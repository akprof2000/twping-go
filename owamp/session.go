package owamp

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"net"
	"runtime"
	"sync/atomic"
	"time"
)

// PortRange — включительный диапазон UDP-портов для локального
// тестового сокета.
type PortRange struct {
	Low, High uint16
}

// TestSpec задаёт параметры двусторонней тестовой сессии.
type TestSpec struct {
	NPackets    uint32
	Slots       []Slot
	StartTime   Num64
	LossTimeout Num64
	Padding     uint32
	TypeP       uint32
}

// SessionConfig настраивает клиентскую сторону двусторонней
// тестовой сессии.
type SessionConfig struct {
	// Reflector — адрес тестового узла.
	Reflector *net.UDPAddr
	// LocalIP при необходимости закрепляет локальный адрес тестового
	// сокета.
	LocalIP net.IP
	// Ports ограничивает выбор локального UDP-порта.
	Ports PortRange
	// DSCP применяется к тестовому сокету, если отличен от нуля.
	DSCP uint8
	// Clock поставляет метки времени и утверждение о
	// синхронизации.
	Clock Clock
	// SpinMargin — за какое время до запланированной отправки
	// отправитель переходит от сна к активному ожиданию.
	// Ноль отключает активное ожидание.
	SpinMargin time.Duration
	// SendBufSize и RecvBufSize задают размеры буферов сокета,
	// если отличны от нуля.
	SendBufSize int
	RecvBufSize int
}

// Session — двусторонняя тестовая сессия со стороны клиента.
type Session struct {
	conn *net.UDPConn
	cfg  SessionConfig
	mode uint32

	sendPayload uint32
	recvPayload uint32

	// Криптография тестовых пакетов (только режимы с
	// аутентификацией и шифрованием).
	aesBlock cipher.Block
	hmacKey  []byte

	haveTTL bool

	// Счётчики для диагностики.
	sentCount atomic.Uint32
	recvCount atomic.Uint32
}

// LocalAddr возвращает адрес, к которому привязан тестовый сокет.
func (s *Session) LocalAddr() *net.UDPAddr { return s.conn.LocalAddr().(*net.UDPAddr) }

// NewSession открывает локальный тестовый UDP-сокет. Его нужно
// вызывать до Control.RequestTWSession, поскольку запрос содержит
// локальный порт.
func NewSession(cfg SessionConfig, mode uint32, padding uint32) (*Session, error) {
	s := &Session{cfg: cfg, mode: mode}
	s.sendPayload = TestPayloadSize(mode, padding)
	s.recvPayload = TestTWPayloadSize(mode, 0)

	network := "udp4"
	if cfg.Reflector.IP.To4() == nil {
		network = "udp6"
	}

	conn, err := listenTestSocket(network, cfg.LocalIP, cfg.Ports, cfg.DSCP)
	if err != nil {
		return nil, err
	}
	s.conn = conn

	if cfg.RecvBufSize > 0 {
		_ = conn.SetReadBuffer(cfg.RecvBufSize)
	}
	if cfg.SendBufSize > 0 {
		_ = conn.SetWriteBuffer(cfg.SendBufSize)
	}
	// RFC 4656 сохраняет принятый TTL, чтобы вторая сторона могла
	// вычислить число хопов. Это работает только если
	// отправитель выставляет 255, поэтому задаём его явно.
	setSendTTL(conn, 255)

	s.haveTTL = enableRecvTTL(conn)
	return s, nil
}

func listenTestSocket(network string, ip net.IP, ports PortRange, dscp uint8) (*net.UDPConn, error) {
	var lc net.ListenConfig
	if dscp != 0 {
		tos := int(dscp) << 2
		lc.Control = func(_, _ string, rc syscallRawConn) error {
			setTOS(rc, tos)
			return nil
		}
	}

	try := func(port int) (*net.UDPConn, error) {
		addr := &net.UDPAddr{IP: ip, Port: port}
		pc, err := lc.ListenPacket(context.Background(), network, addr.String())
		if err != nil {
			return nil, err
		}
		return pc.(*net.UDPConn), nil
	}

	if ports.Low == 0 && ports.High == 0 {
		return try(0)
	}
	if ports.High < ports.Low {
		return nil, fmt.Errorf("недопустимый диапазон портов %d-%d", ports.Low, ports.High)
	}
	// Начинаем со случайного смещения, чтобы повторные запуски
	// не сталкивались всегда на первом порту диапазона.
	span := int(ports.High) - int(ports.Low) + 1
	var seed [2]byte
	_, _ = rand.Read(seed[:])
	offset := int(binary.BigEndian.Uint16(seed[:])) % span
	var lastErr error
	for i := 0; i < span; i++ {
		port := int(ports.Low) + (offset+i)%span
		conn, err := try(port)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("нет свободного порта в диапазоне %d-%d: %w", ports.Low, ports.High, lastErr)
}

// SetKeys устанавливает ключи тестовых пакетов данной сессии,
// выработанные из SID.
func (s *Session) SetKeys(aesKey, hmacKey []byte) error {
	if s.mode&ModeDoCipherTest == 0 {
		return nil
	}
	if len(aesKey) != blockSize {
		return errors.New("owamp: неверная длина тестового ключа AES")
	}
	blk, err := aes.NewCipher(aesKey)
	if err != nil {
		return err
	}
	s.aesBlock = blk
	s.hmacKey = hmacKey
	return nil
}

// Close освобождает тестовый сокет.
func (s *Session) Close() error { return s.conn.Close() }

// RecordSink принимает записи по мере того, как они становятся
// окончательными.
type RecordSink func(*TWDataRec) error

type pktState struct {
	when time.Time // запланированный момент отправки
	// hit означает, что пакету не нужна запись о потере: пришёл ответ либо
	// отправитель пропустил его как безнадёжно опоздавший. Поле атомарное,
	// потому что его ставят обе горутины — приёма и отправки.
	hit atomic.Bool
	// closed помечает пакет, у которого истёк таймаут потери;
	// пришедшие позже ответы на него отбрасываются, а не
	// считаются дубликатами.
	closed bool
}

// Run выполняет тестовую сессию: отправляет NPackets пакетов по
// расписанию и собирает отражённые пакеты, передавая в sink по
// одной записи на каждый отправленный пакет (плюс по
// дополнительной записи на каждый дубликат) в порядке их
// завершения.
//
// Run возвращает управление после истечения таймаута потери
// последнего пакета.
func (s *Session) Run(spec TestSpec, sid [sidLen]byte, sink RecordSink) error {
	if spec.NPackets == 0 {
		return errors.New("owamp: нет пакетов для отправки")
	}
	sched, err := NewSchedule(sid[:], spec.Slots)
	if err != nil {
		return err
	}

	startWall := spec.StartTime.AbsTime()
	timeout := spec.LossTimeout.Duration()

	pkts := make([]pktState, spec.NPackets)
	cum := Num64(0)
	for i := range pkts {
		cum += sched.NextDelta()
		pkts[i].when = startWall.Add(cum.Duration())
	}
	lastSend := pkts[len(pkts)-1].when

	// Приём работает в отдельной горутине, чтобы ответ никогда не
	// ждал очередного решения планировщика отправки.
	rx := make(chan rxItem, 1024)
	stopRx := make(chan struct{})

	go s.receive(rx, stopRx)

	defer func() {
		close(stopRx)
		// Разблокируем висящий вызов ReadMsgUDP.
		_ = s.conn.SetReadDeadline(time.Now())
	}()

	sendErr := make(chan error, 1)
	go func() { sendErr <- s.send(spec, pkts) }()

	// resolved — наименьший порядковый номер, ещё не учтённый в потоке
	// записей. Пакет остаётся в окне приёма до истечения своего
	// таймаута потери, даже после прихода первого ответа, чтобы
	// сетевые дубликаты тоже попадали в статистику.
	resolved := uint32(0)
	deadline := lastSend.Add(timeout)

	// flush выдаёт в порядке номеров запись о потере для каждого
	// пакета, чей таймаут истёк без ответа, пропуская уже
	// отвеченные.
	flush := func(now time.Time) error {
		for resolved < spec.NPackets {
			p := &pkts[resolved]
			if now.Before(p.when.Add(timeout)) {
				return nil
			}
			if !p.hit.Load() {
				if err := sink(lostRecord(resolved, p.when.Add(timeout), s.cfg.Clock)); err != nil {
					return err
				}
			}
			p.closed = true
			resolved++
		}
		return nil
	}

	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	var sendFailure error
	sendDone := false

	for resolved < spec.NPackets {
		select {
		case item := <-rx:
			if item.err != nil {
				// Некорректный или не прошедший
				// аутентификацию пакет игнорируется,
				// как это делает owamp; ошибка сокета
				// завершает сессию.
				if !isFatalRx(item.err) {
					continue
				}
				if err := flushAll(pkts, timeout, &resolved, sink, s.cfg.Clock); err != nil {
					return err
				}
				return sendFailure
			}
			seq := item.rec.Sent.SeqNo
			if seq >= spec.NPackets || pkts[seq].closed {
				continue // вне окна приёма либо мусор
			}
			pkts[seq].hit.Store(true)
			rec := item.rec
			if err := sink(&rec); err != nil {
				return err
			}
			if err := flush(time.Now()); err != nil {
				return err
			}

		case err := <-sendErr:
			sendDone = true
			sendErr = nil
			if err != nil {
				sendFailure = err
			}

		case now := <-ticker.C:
			if err := flush(now); err != nil {
				return err
			}
			if sendDone && now.After(deadline) {
				// Всё, что ещё могло прийти, уже просрочено.
				if err := flushAll(pkts, timeout, &resolved, sink, s.cfg.Clock); err != nil {
					return err
				}
			}
			if sendFailure != nil && sendDone {
				return sendFailure
			}
		}
	}

	if sendErr != nil {
		if err := <-sendErr; err != nil && sendFailure == nil {
			sendFailure = err
		}
	}
	return sendFailure
}

// lostRecord формирует синтетическую запись, которую owamp пишет
// для пакета, так и не вернувшегося обратно.
func lostRecord(seq uint32, at time.Time, clk Clock) *TWDataRec {
	stamp := clk.StampAt(at)
	rec := &TWDataRec{Lost: true}
	rec.Sent.SeqNo = seq
	rec.Sent.Send = stamp
	rec.Sent.Recv = stamp
	rec.Sent.TTL = 255
	rec.Reflected.SeqNo = 0
	rec.Reflected.Send = stamp
	rec.Reflected.Recv = stamp
	rec.Reflected.TTL = 255
	return rec
}

func flushAll(pkts []pktState, timeout time.Duration, resolved *uint32, sink RecordSink, clk Clock) error {
	for *resolved < uint32(len(pkts)) {
		p := &pkts[*resolved]
		if !p.hit.Load() {
			if err := sink(lostRecord(*resolved, p.when.Add(timeout), clk)); err != nil {
				return err
			}
		}
		p.closed = true
		*resolved++
	}
	return nil
}

func isFatalRx(err error) bool {
	var nerr net.Error
	if errors.As(err, &nerr) && nerr.Timeout() {
		return false
	}
	return errors.Is(err, net.ErrClosed) || errors.Is(err, errRxClosed)
}

var errRxClosed = errors.New("owamp: приём остановлен")

// send отправляет пакеты по расписанию. Это горячий путь:
// внутри цикла нет ни одного выделения памяти.
func (s *Session) send(spec TestSpec, pkts []pktState) error {
	payload := make([]byte, s.sendPayload)
	clear16 := make([]byte, 32) // буфер открытого текста для шифрующих режимов
	iv := make([]byte, blockSize)
	var mac hash.Hash
	if s.mode&ModeDoCipherTest != 0 {
		mac = hmac.New(sha1.New, s.hmacKey)
	}

	// Заполнение случайное — как в сборке owamp по умолчанию.
	if s.sendPayload > TestPayloadSize(s.mode, 0) {
		if _, err := rand.Read(payload[TestPayloadSize(s.mode, 0):]); err != nil {
			return err
		}
	}

	timeout := spec.LossTimeout.Duration()
	maxSpin := s.cfg.SpinMargin

	prev := time.Time{}
	for i := range pkts {
		seq := uint32(i)
		p := &pkts[i]

		// Активное ожидание повышает точность метки времени,
		// но занимает ядро. Никогда не крутимся дольше
		// четверти интервала до предыдущего пакета, чтобы
		// расход процессора оставался ограниченным при
		// росте скорости.
		spin := maxSpin
		if !prev.IsZero() {
			if gap := p.when.Sub(prev) / 4; gap < spin {
				spin = gap
			}
		}
		prev = p.when

		sleepUntil(p.when, spin)

		now := time.Now()
		if now.After(p.when.Add(timeout)) {
			// Слишком поздно, чтобы это имело смысл; считаем пакет
			// отправленным и отвеченным, чтобы поток записей
			// не застрял.
			p.hit.Store(true)
			continue
		}

		ts := s.cfg.Clock.StampAt(now)

		switch s.mode {
		case ModeOpen, ModeMixed:
			binary.BigEndian.PutUint32(payload[0:4], seq)
			ts.EncodeTime(payload[4:12])
			if !ts.EncodeErrEstimate(payload[12:14]) {
				payload[12], payload[13] = 0x3F, 0xFF
			}

		case ModeAuth:
			// Нулевой блок (порядковый номер) шифруется
			// AES-ECB; блок с меткой времени передаётся
			// открытым текстом.
			for j := range clear16[:16] {
				clear16[j] = 0
			}
			binary.BigEndian.PutUint32(clear16[0:4], seq)
			mac.Reset()
			mac.Write(clear16[0:16])
			s.aesBlock.Encrypt(payload[0:16], clear16[0:16])
			ts.EncodeTime(payload[16:24])
			if !ts.EncodeErrEstimate(payload[24:26]) {
				payload[24], payload[25] = 0x3F, 0xFF
			}
			for j := 26; j < 32; j++ {
				payload[j] = 0
			}
			copy(payload[32:48], mac.Sum(nil)[:blockSize])

		case ModeEncrypted:
			for j := range clear16 {
				clear16[j] = 0
			}
			binary.BigEndian.PutUint32(clear16[0:4], seq)
			ts.EncodeTime(clear16[16:24])
			if !ts.EncodeErrEstimate(clear16[24:26]) {
				clear16[24], clear16[25] = 0x3F, 0xFF
			}
			mac.Reset()
			mac.Write(clear16[0:32])
			for j := range iv {
				iv[j] = 0
			}
			cipher.NewCBCEncrypter(s.aesBlock, iv).CryptBlocks(payload[0:32], clear16[0:32])
			copy(payload[32:48], mac.Sum(nil)[:blockSize])

		default:
			return fmt.Errorf("owamp: неподдерживаемый режим 0x%x", s.mode)
		}

		if _, err := s.conn.WriteToUDP(payload, s.cfg.Reflector); err != nil {
			// Разовый сбой отправки не должен прерывать весь тест.
			var nerr net.Error
			if errors.As(err, &nerr) && nerr.Timeout() {
				continue
			}
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			continue
		}
		s.sentCount.Add(1)
	}
	return nil
}

// sleepUntil ждёт наступления заданного момента: спит до момента
// за spin до цели, а затем переходит к активному ожиданию. Это
// сохраняет точность расписания отправки на системах с грубым
// таймером (в первую очередь Windows) при ограниченном расходе
// процессора.
func sleepUntil(t time.Time, spin time.Duration) {
	for {
		d := time.Until(t)
		if d <= 0 {
			return
		}
		if spin <= 0 {
			time.Sleep(d)
			continue
		}
		if d > spin {
			time.Sleep(d - spin)
			continue
		}
		for time.Until(t) > 0 {
			runtime.Gosched()
		}
		return
	}
}

// rxItem — один элемент, произведённый горутиной приёма.
type rxItem struct {
	rec TWDataRec
	err error
}

// receive читает отражённые пакеты до конца сессии.
func (s *Session) receive(out chan<- rxItem, stop <-chan struct{}) {
	buf := make([]byte, 65536)
	oob := make([]byte, oobBufSize)
	iv := make([]byte, blockSize)
	var mac hash.Hash
	if s.mode&ModeDoCipherTest != 0 {
		mac = hmac.New(sha1.New, s.hmacKey)
	}

	for {
		select {
		case <-stop:
			return
		default:
		}

		n, ttl, _, err := readTTLFrom(s.conn, buf, oob)
		if err != nil {
			select {
			case <-stop:
				return
			default:
			}
			var nerr net.Error
			if errors.As(err, &nerr) && nerr.Timeout() {
				continue
			}
			// Run мог уже завершиться: без select с stop горутина
			// зависла бы навсегда на полном канале.
			select {
			case out <- rxItem{err: err}:
			case <-stop:
			}
			return
		}
		recvAt := time.Now()

		if uint32(n) < s.recvPayload {
			continue
		}

		pkt := buf[:n]
		if s.mode&ModeDoCipherTest != 0 {
			if !s.decryptReply(pkt, iv, mac) {
				continue
			}
		}

		rec, ok := s.parseReply(pkt, ttl, recvAt)
		if !ok {
			continue
		}
		s.recvCount.Add(1)
		select {
		case out <- rxItem{rec: rec}:
		case <-stop:
			return
		}
	}
}

// decryptReply расшифровывает и аутентифицирует отражённый
// пакет на месте.
func (s *Session) decryptReply(pkt []byte, iv []byte, mac hash.Hash) bool {
	for j := range iv {
		iv[j] = 0
	}
	mac.Reset()

	// Первый блок всегда шифруется AES-ECB (что для одного блока
	// совпадает с CBC при нулевом IV); IV остаётся готовым для
	// последующих блоков.
	dec := cipher.NewCBCDecrypter(s.aesBlock, iv)
	dec.CryptBlocks(pkt[0:16], pkt[0:16])
	mac.Write(pkt[0:16])

	if s.mode&ModeEncrypted != 0 {
		dec.CryptBlocks(pkt[16:96], pkt[16:96])
		mac.Write(pkt[16:96])
	}

	return subtle.ConstantTimeCompare(mac.Sum(nil)[:blockSize], pkt[96:112]) == 1
}

// parseReply разбирает отражённый тестовый пакет.
func (s *Session) parseReply(pkt []byte, ttl uint8, recvAt time.Time) (TWDataRec, bool) {
	var rec TWDataRec

	var rSeq, sSeq uint32
	var rSend, rErr, sRecv, sSend, sErr []byte
	var sTTL uint8

	switch s.mode {
	case ModeOpen, ModeMixed:
		rSeq = binary.BigEndian.Uint32(pkt[0:4])
		rSend, rErr = pkt[4:12], pkt[12:14]
		sRecv = pkt[16:24]
		sSeq = binary.BigEndian.Uint32(pkt[24:28])
		sSend, sErr = pkt[28:36], pkt[36:38]
		sTTL = pkt[40]
	case ModeAuth, ModeEncrypted:
		rSeq = binary.BigEndian.Uint32(pkt[0:4])
		rSend, rErr = pkt[16:24], pkt[24:26]
		sRecv = pkt[32:40]
		sSeq = binary.BigEndian.Uint32(pkt[48:52])
		sSend, sErr = pkt[64:72], pkt[72:74]
		sTTL = pkt[80]
	default:
		return rec, false
	}

	sentSend, ok := DecodeTimestamp(sSend, sErr)
	if !ok {
		return rec, false
	}
	// Отражатель сообщает одну оценку погрешности; она
	// относится к обеим снятым им меткам времени.
	sentRecv, ok := DecodeTimestamp(sRecv, rErr)
	if !ok {
		return rec, false
	}
	reflSend, ok := DecodeTimestamp(rSend, rErr)
	if !ok {
		return rec, false
	}

	rec.Sent = DataRec{SeqNo: sSeq, Send: sentSend, Recv: sentRecv, TTL: sTTL}
	rec.Reflected = DataRec{SeqNo: rSeq, Send: reflSend, Recv: s.cfg.Clock.StampAt(recvAt)}
	if s.haveTTL && ttl != 0 {
		rec.Reflected.TTL = ttl
	} else {
		rec.Reflected.TTL = 255
	}
	return rec, true
}

// HaveReflectedTTL сообщает, удалось ли измерить число хопов
// обратного пути.
func (s *Session) HaveReflectedTTL() bool { return s.haveTTL }
