package owamp

import (
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
	"time"
)

// DelayType перечисляет наборы задержек, о которых сообщает twping.
type DelayType int

const (
	DelayRTT  DelayType = iota // лучшая оценка сетевого кругового обхода
	DelayFwd                   // клиент -> отражатель
	DelayBck                   // отражатель -> клиент
	DelayProc                  // время обработки на отражателе

	// В статистике погрешностей и джиттера участвуют только RTT, Fwd и Bck.
	numDelayTypes         = 3
	numDelayTypesWithProc = 4
)

// machineSuffix возвращает суффикс имени поля для машинного вывода (-M).
// Имена полей намеренно оставлены в исходном виде: это машинный формат,
// который разбирают внешние инструменты.
func (d DelayType) machineSuffix() string {
	switch d {
	case DelayRTT:
		return ""
	case DelayFwd:
		return "_FWD"
	case DelayBck:
		return "_BCK"
	case DelayProc:
		return "_PROC"
	}
	return "_UNKNOWN"
}

// describe возвращает название набора задержек для отчёта.
func (d DelayType) describe() string {
	switch d {
	case DelayRTT:
		return "время кругового обхода"
	case DelayFwd:
		return "время до отражателя"
	case DelayBck:
		return "время от отражателя"
	case DelayProc:
		return "время обработки на отражателе"
	}
	return ""
}

// TTLType перечисляет два счёта хопов двустороннего теста.
type TTLType int

const (
	TTLFwd TTLType = iota
	TTLBck
	numTTLTypes
)

// ScaleFactor возвращает множитель и сокращённое обозначение единицы измерения
// для селектора 'n', 'u', 'm' или 's'.
func ScaleFactor(unit byte) (float64, string, error) {
	switch unit {
	case 'n', 'N':
		return 1e9, "нс", nil
	case 'u', 'U':
		return 1e6, "мкс", nil
	case 'm', 'M':
		return 1e3, "мс", nil
	case 's', 'S':
		return 1, "с", nil
	default:
		return 0, "", fmt.Errorf("недопустимая единица %q: ожидается одна из n, u, m, s", string(unit))
	}
}

// StatsConfig задаёт параметры сбора статистики.
type StatsConfig struct {
	FromHost, FromServ string
	ToHost, ToServ     string
	SID                [sidLen]byte

	Unit        byte
	BucketWidth float64

	NPackets    uint32
	Padding     uint32
	TypeP       uint32
	LossTimeout Num64

	// RecordOutput, если не nil, получает построчный вывод по каждому пакету.
	RecordOutput io.Writer
	// RecordLimit ограничивает число печатаемых строк (0 — без ограничения).
	RecordLimit uint64
	// UnixTimestamps переключает построчный вывод в формат -U.
	UnixTimestamps bool
}

type packetInfo struct {
	seen          uint32
	lost          bool
	associatedSeq uint32
	hasAssoc      bool
}

// Stats накапливает сводку по двусторонней сессии.
type Stats struct {
	cfg StatsConfig

	scale float64
	abrv  string

	fwd map[uint32]*packetInfo
	bck map[uint32]*packetInfo

	// Корзины гистограммы по каждому набору задержек; ключ —
	// floor(задержка/BucketWidth).
	buckets [numDelayTypes]map[int64]uint32

	minDelay [numDelayTypesWithProc]float64
	maxDelay [numDelayTypesWithProc]float64
	maxErr   [numDelayTypes]float64

	ttlCount [numTTLTypes][256]uint32

	sent      uint32
	lost      uint32
	dupsFwd   uint32
	dupsBck   uint32
	syncCount uint32

	clocksOffset bool
	finished     bool

	startTime Num64
	endTime   Num64
	haveRange bool

	first, last uint32
	haveFirst   bool

	printed uint64
}

const infDelay = math.MaxFloat64 / 4

// NewStats создаёт пустой накопитель статистики.
func NewStats(cfg StatsConfig) (*Stats, error) {
	scale, abrv, err := ScaleFactor(cfg.Unit)
	if err != nil {
		return nil, err
	}
	if cfg.BucketWidth <= 0 {
		return nil, fmt.Errorf("ширина корзины гистограммы должна быть положительной")
	}
	s := &Stats{
		cfg:   cfg,
		scale: scale,
		abrv:  abrv,
		fwd:   make(map[uint32]*packetInfo, cfg.NPackets),
		bck:   make(map[uint32]*packetInfo, cfg.NPackets),
	}
	for i := range s.buckets {
		s.buckets[i] = make(map[int64]uint32, 1024)
	}
	for i := range s.minDelay {
		s.minDelay[i] = infDelay
		s.maxDelay[i] = -infDelay
	}
	return s, nil
}

// SetFinished фиксирует, дошла ли сессия до конца.
func (s *Stats) SetFinished(v bool) { s.finished = v }

func (s *Stats) node(m map[uint32]*packetInfo, seq uint32) *packetInfo {
	if p, ok := m[seq]; ok {
		return p
	}
	p := &packetInfo{}
	m[seq] = p
	return p
}

// Add включает одну запись в статистику. Записи должны поступать в порядке
// завершения — именно в таком виде их выдаёт Session.Run.
func (s *Stats) Add(rec *TWDataRec) error {
	if !s.haveFirst {
		s.first = rec.Sent.SeqNo
		s.startTime = rec.Sent.Send.Time
		s.haveFirst = true
	}
	s.last = rec.Sent.SeqNo + 1
	if rec.Reflected.Recv.Time > s.endTime {
		s.endTime = rec.Reflected.Recv.Time
	}
	if rec.Sent.Send.Time < s.startTime {
		s.startTime = rec.Sent.Send.Time
	}

	fwdNode := s.node(s.fwd, rec.Sent.SeqNo)

	if rec.Lost {
		if fwdNode.lost {
			return fmt.Errorf("повторная запись о потере для номера %d", rec.Sent.SeqNo)
		}
		fwdNode.lost = true
		s.sent++
		s.lost++
		derr := rec.Sent.Recv.ErrEstimate()
		for i := range s.maxErr {
			s.maxErr[i] = math.Max(s.maxErr[i], derr)
		}
		if s.cfg.RecordOutput != nil && s.mayPrint() {
			fmt.Fprintf(s.cfg.RecordOutput, "seq_no=%-10d *ПОТЕРЯН*\n", rec.Sent.SeqNo)
		}
		return nil
	}

	if fwdNode.lost {
		// Ответ пришёл после того, как мы уже признали пакет потерянным:
		// игнорируем его, чтобы не испортить счёт потерь.
		return nil
	}

	bckNode := s.node(s.bck, rec.Reflected.SeqNo)
	if bckNode.seen == 0 {
		bckNode.associatedSeq = rec.Sent.SeqNo
		bckNode.hasAssoc = true
	} else if bckNode.associatedSeq != rec.Sent.SeqNo {
		return fmt.Errorf("номер отражения %d связан с номерами отправки %d и %d",
			rec.Reflected.SeqNo, bckNode.associatedSeq, rec.Sent.SeqNo)
	}
	bckNode.seen++

	isDupFwd := false
	isDupBck := false
	if fwdNode.seen == 0 {
		s.sent++
		fwdNode.seen++
		fwdNode.associatedSeq = rec.Reflected.SeqNo
		fwdNode.hasAssoc = true
	} else if fwdNode.associatedSeq != rec.Reflected.SeqNo && bckNode.seen == 1 {
		// Отличающийся отражённый пакет для уже учтённого номера: значит,
		// пакет клиента был размножен в сети.
		fwdNode.seen++
		isDupFwd = true
	} else {
		isDupBck = true
	}

	if isDupFwd {
		s.dupsFwd++
	}
	if isDupBck {
		s.dupsBck++
	}

	var delay [numDelayTypesWithProc]float64
	delay[DelayProc] = Delay(rec.Sent.Recv, rec.Reflected.Send)
	delay[DelayRTT] = Delay(rec.Sent.Send, rec.Reflected.Recv) - delay[DelayProc]
	delay[DelayFwd] = Delay(rec.Sent.Send, rec.Sent.Recv)
	delay[DelayBck] = Delay(rec.Reflected.Send, rec.Reflected.Recv)

	var delayErr [numDelayTypes]float64
	delayErr[DelayRTT] = rec.Sent.Send.ErrEstimate() + rec.Reflected.Recv.ErrEstimate() +
		rec.Reflected.Send.ErrEstimate() + rec.Sent.Recv.ErrEstimate()
	delayErr[DelayFwd] = rec.Sent.Send.ErrEstimate() + rec.Sent.Recv.ErrEstimate()
	delayErr[DelayBck] = rec.Reflected.Send.ErrEstimate() + rec.Reflected.Recv.ErrEstimate()

	if delay[DelayFwd] < 0 || delay[DelayBck] < 0 {
		s.clocksOffset = true
	}

	if rec.Sent.Send.Sync && rec.Sent.Recv.Sync &&
		rec.Reflected.Send.Sync && rec.Reflected.Recv.Sync {
		s.syncCount++
	}

	s.printRecord(rec, &delay, &delayErr)

	for i := 0; i < numDelayTypesWithProc; i++ {
		s.minDelay[i] = math.Min(s.minDelay[i], delay[i])
		s.maxDelay[i] = math.Max(s.maxDelay[i], delay[i])
	}
	for i := 0; i < numDelayTypes; i++ {
		s.maxErr[i] = math.Max(s.maxErr[i], delayErr[i])
	}

	// Гистограмма и статистика TTL дубликаты не учитывают.
	if isDupFwd || isDupBck {
		return nil
	}
	for i := 0; i < numDelayTypes; i++ {
		b := int64(math.Floor(delay[i] / s.cfg.BucketWidth))
		s.buckets[i][b]++
	}
	s.ttlCount[TTLFwd][rec.Sent.TTL]++
	s.ttlCount[TTLBck][rec.Reflected.TTL]++
	return nil
}

func (s *Stats) mayPrint() bool {
	if s.cfg.RecordOutput == nil {
		return false
	}
	if s.cfg.RecordLimit > 0 && s.printed >= s.cfg.RecordLimit {
		return false
	}
	s.printed++
	return true
}

// printRecord печатает строку по одному пакету для режима -v. Имена полей
// (seq_no, fwd_delay и прочие) сохранены в исходном виде как идентификаторы
// формата.
func (s *Stats) printRecord(rec *TWDataRec, delay *[numDelayTypesWithProc]float64, delayErr *[numDelayTypes]float64) {
	if !s.mayPrint() {
		return
	}
	out := s.cfg.RecordOutput
	if s.cfg.UnixTimestamps {
		const epochDiff = float64(JAN1970)
		fmt.Fprintf(out,
			"seq_no=%d fwd_delay=%e %s bck_delay=%e %s delay=%e %s proc_delay=%e %s (err=%.3g %s) sent=%f recv=%f reflected=%f recv=%f\n",
			rec.Sent.SeqNo,
			delay[DelayFwd]*s.scale, s.abrv,
			delay[DelayBck]*s.scale, s.abrv,
			delay[DelayRTT]*s.scale, s.abrv,
			delay[DelayProc]*s.scale, s.abrv,
			delayErr[DelayRTT]*s.scale, s.abrv,
			rec.Sent.Send.Time.Float()-epochDiff,
			rec.Sent.Recv.Time.Float()-epochDiff,
			rec.Reflected.Send.Time.Float()-epochDiff,
			rec.Reflected.Recv.Time.Float()-epochDiff)
		return
	}
	fmt.Fprintf(out,
		"seq_no=%-10d fwd_delay=%.3g %s bck_delay=%.3g %s delay=%.3g %s proc_delay=%.3g %s\t(err=%.3g %s)\n",
		rec.Sent.SeqNo,
		delay[DelayFwd]*s.scale, s.abrv,
		delay[DelayBck]*s.scale, s.abrv,
		delay[DelayRTT]*s.scale, s.abrv,
		delay[DelayProc]*s.scale, s.abrv,
		delayErr[DelayRTT]*s.scale, s.abrv)
}

// percentile вычисляет квантиль уровня alpha для набора задержек по
// гистограмме, беря середину выбранной корзины.
func (s *Stats) percentile(alpha float64, t DelayType) (float64, bool) {
	if t == DelayProc {
		return 0, false // в гистограмме не отслеживается
	}
	hist := s.buckets[t]
	if len(hist) == 0 {
		return 0, false
	}
	keys := make([]int64, 0, len(hist))
	var total uint32
	for k, c := range hist {
		keys = append(keys, k)
		total += c
	}
	if total == 0 {
		return 0, false
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })

	target := alpha * float64(total)
	var sum float64
	for _, k := range keys {
		sum += float64(hist[k])
		if sum >= target {
			return (float64(k) + 0.5) * s.cfg.BucketWidth, true
		}
	}
	last := keys[len(keys)-1]
	return (float64(last) + 0.5) * s.cfg.BucketWidth, true
}

func (s *Stats) jitter(t DelayType) (float64, bool) {
	p95, ok95 := s.percentile(0.95, t)
	p50, ok50 := s.percentile(0.5, t)
	if !ok95 || !ok50 {
		return 0, false
	}
	return p95 - p50, true
}

func (s *Stats) fmtScaled(v float64, ok bool) string {
	if !ok {
		return "nan"
	}
	return fmt.Sprintf("%.3g", v*s.scale)
}

func (s *Stats) minStr(t DelayType) string {
	return s.fmtScaled(s.minDelay[t], s.minDelay[t] < infDelay)
}

func (s *Stats) maxStr(t DelayType) string {
	return s.fmtScaled(s.maxDelay[t], s.maxDelay[t] > -infDelay)
}

func (s *Stats) ttlRange(t TTLType) (values int, minTTL, maxTTL uint8) {
	minTTL, maxTTL = 255, 0
	for i := 0; i < 256; i++ {
		if s.ttlCount[t][i] == 0 {
			continue
		}
		values++
		if uint8(i) < minTTL {
			minTTL = uint8(i)
		}
		if uint8(i) > maxTTL {
			maxTTL = uint8(i)
		}
	}
	return
}

// PrintSummary печатает человекочитаемую сводку с той же структурой, что и
// у twping.
func (s *Stats) PrintSummary(w io.Writer, percentiles []float64) {
	if s.clocksOffset {
		fmt.Fprintf(w, "\nОднонаправленные задержки могут быть неточны: часы не синхронизированы!\n")
	}

	fmt.Fprintf(w, "\n--- статистика twping от [%s]:%s к [%s]:%s ---\n",
		s.cfg.FromHost, s.cfg.FromServ, s.cfg.ToHost, s.cfg.ToServ)
	fmt.Fprintf(w, "SID:\t%x\n", s.cfg.SID)

	first := s.startTime.AbsTime()
	last := s.endTime.AbsTime()
	fmt.Fprintf(w, "первый:\t%s.%03d\nпоследний:\t%s.%03d\n",
		first.Format("2006-01-02T15:04:05"), first.Nanosecond()/1e6,
		last.Format("2006-01-02T15:04:05"), last.Nanosecond()/1e6)

	lossPct := 0.0
	if s.sent > 0 {
		lossPct = float64(s.lost) / float64(s.sent)
	}
	fmt.Fprintf(w, "отправлено %d, потеряно %d (%.3f%%), ", s.sent, s.lost, 100*lossPct)
	fmt.Fprintf(w, "дубликатов при отправке %d, при отражении %d\n", s.dupsFwd, s.dupsBck)

	for _, t := range []DelayType{DelayRTT, DelayFwd, DelayBck} {
		med, ok := s.percentile(0.5, t)
		fmt.Fprintf(w, "%s мин/медиана/макс = %s/%s/%s %s, ",
			t.describe(), s.minStr(t), s.fmtScaled(med, ok), s.maxStr(t), s.abrv)
		if s.syncCount > 0 {
			fmt.Fprintf(w, "(погрешность=%.3g %s)\n", s.maxErr[t]*s.scale, s.abrv)
		} else {
			fmt.Fprintf(w, "(без синхронизации)\n")
		}
	}
	fmt.Fprintf(w, "%s мин/макс = %s/%s %s\n",
		DelayProc.describe(), s.minStr(DelayProc), s.maxStr(DelayProc), s.abrv)

	for _, t := range []DelayType{DelayRTT, DelayFwd, DelayBck} {
		j, ok := s.jitter(t)
		desc := map[DelayType]string{
			DelayRTT: "двусторонний",
			DelayFwd: "до отражателя",
			DelayBck: "от отражателя",
		}[t]
		fmt.Fprintf(w, "джиттер (%s) = %s %s (P95-P50)\n", desc, s.fmtScaled(j, ok), s.abrv)
	}

	if len(percentiles) > 0 {
		fmt.Fprintf(w, "Процентили:\n")
		for _, p := range percentiles {
			v, ok := s.percentile(p/100.0, DelayRTT)
			fmt.Fprintf(w, "\t%.1f: %s %s\n", p, s.fmtScaled(v, ok), s.abrv)
		}
	}

	for _, t := range []TTLType{TTLFwd, TTLBck} {
		desc := "до отражателя"
		if t == TTLBck {
			desc = "от отражателя"
		}
		n, minTTL, maxTTL := s.ttlRange(t)
		switch {
		case n < 1:
			fmt.Fprintf(w, "TTL (%s) не сообщается\n", desc)
		case n == 1:
			fmt.Fprintf(w, "число хопов (%s) = %d (неизменно)\n", desc, 255-int(minTTL))
		default:
			fmt.Fprintf(w, "число хопов (%s) принимает %d значений; минимум %d, максимум %d\n",
				desc, n, 255-int(maxTTL), 255-int(minTTL))
		}
	}

	fmt.Fprintf(w, "\n")
}

// PrintMachine печатает машинную сводку, соответствующую twping -M. Имена полей
// оставлены в исходном виде: этот формат разбирают внешние инструменты.
func (s *Stats) PrintMachine(w io.Writer) {
	fmt.Fprintf(w, "SUMMARY\t3.00\n")
	fmt.Fprintf(w, "SID\t%x\n", s.cfg.SID)
	fmt.Fprintf(w, "FROM_HOST\t%s\n", s.cfg.FromHost)
	fmt.Fprintf(w, "FROM_ADDR\t%s\n", s.cfg.FromHost)
	fmt.Fprintf(w, "FROM_PORT\t%s\n", s.cfg.FromServ)
	fmt.Fprintf(w, "TO_HOST\t%s\n", s.cfg.ToHost)
	fmt.Fprintf(w, "TO_ADDR\t%s\n", s.cfg.ToHost)
	fmt.Fprintf(w, "TO_PORT\t%s\n", s.cfg.ToServ)
	fmt.Fprintf(w, "START_TIME\t%d\n", uint64(s.startTime))
	fmt.Fprintf(w, "END_TIME\t%d\n", uint64(s.endTime))
	if s.cfg.TypeP&^0x3F000000 == 0 {
		fmt.Fprintf(w, "DSCP\t0x%2.2x\n", s.cfg.TypeP>>24)
	}
	fmt.Fprintf(w, "LOSS_TIMEOUT\t%d\n", uint64(s.cfg.LossTimeout))
	fmt.Fprintf(w, "PACKET_PADDING\t%d\n", s.cfg.Padding)
	fmt.Fprintf(w, "SESSION_PACKET_COUNT\t%d\n", s.cfg.NPackets)
	fmt.Fprintf(w, "SAMPLE_PACKET_COUNT\t%d\n", s.last-s.first)
	fmt.Fprintf(w, "BUCKET_WIDTH\t%g\n", s.cfg.BucketWidth)
	fmt.Fprintf(w, "SESSION_FINISHED\t%d\n", b2i(s.finished))

	fmt.Fprintf(w, "SENT\t%d\n", s.sent)
	fmt.Fprintf(w, "SYNC\t%d\n", s.syncCount)
	fmt.Fprintf(w, "MAXERR\t%.6g\n", s.maxErr[DelayRTT])
	fmt.Fprintf(w, "MAXERR_FWD\t%.6g\n", s.maxErr[DelayFwd])
	fmt.Fprintf(w, "MAXERR_BCK\t%.6g\n", s.maxErr[DelayBck])
	fmt.Fprintf(w, "DUPS_FWD\t%d\n", s.dupsFwd)
	fmt.Fprintf(w, "DUPS_BCK\t%d\n", s.dupsBck)
	fmt.Fprintf(w, "LOST\t%d\n", s.lost)

	for _, t := range []DelayType{DelayRTT, DelayFwd, DelayBck, DelayProc} {
		if s.minDelay[t] < infDelay {
			fmt.Fprintf(w, "MIN%s\t%.6g\n", t.machineSuffix(), s.minDelay[t])
		}
	}
	for _, t := range []DelayType{DelayRTT, DelayFwd, DelayBck} {
		if v, ok := s.percentile(0.5, t); ok {
			fmt.Fprintf(w, "MEDIAN%s\t%.6g\n", t.machineSuffix(), v)
		}
	}
	for _, t := range []DelayType{DelayRTT, DelayFwd, DelayBck, DelayProc} {
		if s.maxDelay[t] > -infDelay {
			fmt.Fprintf(w, "MAX%s\t%.6g\n", t.machineSuffix(), s.maxDelay[t])
		}
	}
	for _, t := range []DelayType{DelayRTT, DelayFwd, DelayBck} {
		if v, ok := s.jitter(t); ok {
			fmt.Fprintf(w, "PDV%s\t%.6g\n", t.machineSuffix(), v)
		}
	}

	if s.sent > s.lost {
		fmt.Fprintf(w, "<BUCKETS>\n")
		keys := make([]int64, 0, len(s.buckets[DelayRTT]))
		for k := range s.buckets[DelayRTT] {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
		for _, k := range keys {
			fmt.Fprintf(w, "\t%d\t%d\t%d\t%d\n", k,
				s.buckets[DelayRTT][k], s.buckets[DelayFwd][k], s.buckets[DelayBck][k])
		}
		fmt.Fprintf(w, "</BUCKETS>\n")
	}

	for _, t := range []TTLType{TTLFwd, TTLBck} {
		suffix := "_FWD"
		if t == TTLBck {
			suffix = "_BCK"
		}
		if n, minTTL, maxTTL := s.ttlRange(t); n > 0 {
			fmt.Fprintf(w, "MINTTL%s\t%d\n", suffix, minTTL)
			fmt.Fprintf(w, "MAXTTL%s\t%d\n", suffix, maxTTL)
		}
	}

	fmt.Fprintf(w, "<TTLBUCKETS>\n")
	for i := 0; i < 256; i++ {
		if s.ttlCount[TTLFwd][i] > 0 || s.ttlCount[TTLBck][i] > 0 {
			fmt.Fprintf(w, "\t%d\t%d\t%d\n", i, s.ttlCount[TTLFwd][i], s.ttlCount[TTLBck][i])
		}
	}
	fmt.Fprintf(w, "</TTLBUCKETS>\n")
	fmt.Fprintf(w, "\n")
}

// ParsePercentiles разбирает аргумент -a, заданный списком через запятую.
func ParsePercentiles(arg string) ([]float64, error) {
	var out []float64
	for _, f := range strings.Split(arg, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		var v float64
		if _, err := fmt.Sscanf(f, "%g", &v); err != nil {
			return nil, fmt.Errorf("недопустимый процентиль %q", f)
		}
		if v < 0 || v > 100 {
			return nil, fmt.Errorf("процентиль %g вне диапазона 0-100", v)
		}
		out = append(out, v)
	}
	sort.Float64s(out)
	return out, nil
}

// EstimateDuration возвращает ожидаемую длительность сессии с заданными
// параметрами, включая завершающий таймаут потери и один круговой обход
// управляющего соединения.
func EstimateDuration(spec TestSpec, rttBound Num64) time.Duration {
	rate := PacketRate(spec.Slots)
	var d float64
	if rate > 0 {
		d = float64(spec.NPackets) / rate
	}
	d += spec.LossTimeout.Float()
	d += rttBound.Float()
	return time.Duration(d * float64(time.Second))
}
