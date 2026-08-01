// Пакет twping измеряет двусторонние задержки до сервера TWAMP (RFC 5357).
//
// Это реализация на Go клиента twping из состава perfSONAR owamp;
// сведения об авторстве оригинала — в файле NOTICE.
//
// Пакет содержит всю работу клиента целиком — разбор аргументов командной
// строки и печать статистики в том же виде, что и оригинальная утилита.
// Точка входа cmd/twping — тонкая обёртка над Run, поэтому вызов из чужой
// программы даёт ровно тот же вывод, что и запуск утилиты.
package twping

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/akprof2000/twping-go/owamp"
)

const progName = "twping"

var version = "1.0.0"

type options struct {
	// Параметры теста
	count       uint
	dscp        string
	saveFile    string
	interval    float64
	lossTimeout float64
	portRange   string
	padding     int
	delayStart  float64

	// Параметры соединения
	authMode  string
	pfFile    string
	srcAddr   string
	iface     string
	zeroAddr  bool
	identity  string
	v4only    bool
	v6only    bool
	spinUsec  uint
	syncClock bool
	errUsec   uint

	// Параметры вывода
	percentiles string
	bucketWidth float64
	machine     bool
	units       string
	subCount    uint
	quiet       bool
	raw         bool
	verbose     string
	unixTS      bool

	help bool
}

// usage печатает справку в переданный поток.
func usage(out io.Writer) {
	fmt.Fprintf(out, "использование: %s [аргументы] тест-адрес [адрес-сервера]\n", progName)
	fmt.Fprintf(out, "[аргументы] перечислены ниже:\n\n")
	fmt.Fprintf(out, "   -h             показать эту справку и выйти\n\n")

	fmt.Fprintf(out, "              [Параметры теста]\n\n")
	fmt.Fprintf(out, "   -c число       количество тестовых пакетов\n")
	fmt.Fprintf(out, "   -D DSCP        значение DSCP для байта TOS в стиле RFC 2474\n")
	fmt.Fprintf(out, "   -F файл        сохранить результаты в файл (поток сырых записей)\n")
	fmt.Fprintf(out, "   -i интервал    среднее время между пакетами (секунды)\n")
	fmt.Fprintf(out, "   -L таймаут     сколько ждать пакет, прежде чем считать его потерянным (секунды)\n")
	fmt.Fprintf(out, "   -P диапазон    диапазон портов для использования во время теста\n")
	fmt.Fprintf(out, "   -s заполнение  размер заполнения, добавляемого к каждому пакету (байты)\n")
	fmt.Fprintf(out, "   -z задержка    сколько ждать перед началом теста (секунды)\n\n")

	fmt.Fprintf(out, "              [Параметры соединения]\n\n")
	fmt.Fprintf(out, "   -A режимы      запрашиваемые режимы: [A] с аутентификацией, [E] шифрованный, [M] смешанный, [O] открытый\n")
	fmt.Fprintf(out, "   -k файл-пароля файл с парольной фразой для режимов A, E и M\n")
	fmt.Fprintf(out, "   -S адрес       локальный адрес для управляющего соединения и тестов\n")
	fmt.Fprintf(out, "   -B интерфейс   интерфейс для управляющего соединения и тестов\n")
	fmt.Fprintf(out, "   -Z             не указывать IP-адреса для тестовых пакетов (прохождение NAT)\n")
	fmt.Fprintf(out, "   -u имя         имя пользователя для режимов A, E и M\n")
	fmt.Fprintf(out, "   -4             использовать только адреса IPv4\n")
	fmt.Fprintf(out, "   -6             использовать только адреса IPv6\n\n")

	fmt.Fprintf(out, "              [Параметры вывода]\n\n")
	fmt.Fprintf(out, "   -a уровни      дополнительные уровни процентилей для задержек (через запятую)\n")
	fmt.Fprintf(out, "   -b ширина      размер корзины для расчёта гистограммы\n")
	fmt.Fprintf(out, "   -M             вывести машиночитаемую (perl) сводку\n")
	fmt.Fprintf(out, "   -n единицы     'n', 'u', 'm' или 's'\n")
	fmt.Fprintf(out, "   -Q             выполнить тест и выйти, не выводя статистику\n")
	fmt.Fprintf(out, "   -R             вывести сырые данные: \"SSEQ STIME SS SERR SRTIME SRS SRERR STTL RSEQ RSTIME RSS RSERR RTIME RS RERR RTTL\"\n")
	fmt.Fprintf(out, "   -v[=N]         печатать задержки по каждому пакету; N ограничивает вывод первыми N пакетами\n")
	fmt.Fprintf(out, "   -U             добавлять метки времени UNIX при печати задержек по пакетам\n\n")

	fmt.Fprintf(out, "              [Дополнения порта на Go]\n\n")
	fmt.Fprintf(out, "   --spin мкс     окно активного ожидания перед каждой отправкой по расписанию\n")
	fmt.Fprintf(out, "   --sync         считать локальные часы синхронизированными\n")
	fmt.Fprintf(out, "   --esterror мкс оценка погрешности локальных часов в микросекундах (при значении > 0 включает --sync)\n\n")

	fmt.Fprintf(out, "Версия: %s\n\n", version)
}

// Run выполняет замер по аргументам командной строки twping (без имени
// программы) и пишет результат в out, а диагностику — в errOut.
//
// Сводка печатается подписями оригинального twping из perfSONAR: на них
// рассчитаны инструменты, которые разбирают отчёт. Русский вариант выбирается
// через RunLang — его использует сама утилита.
//
// Отмена ctx прерывает идущую сессию: так вызывающая программа останавливает
// замер, не убивая процесс. Своих обработчиков сигналов пакет не ставит — это
// дело программы, а не библиотеки.
func Run(ctx context.Context, args []string, out, errOut io.Writer) error {
	return RunLang(ctx, args, out, errOut, owamp.English)
}

// RunLang делает то же, что Run, но позволяет выбрать язык подписей в сводке.
func RunLang(ctx context.Context, args []string, out, errOut io.Writer, lang owamp.Language) error {
	if ctx == nil {
		ctx = context.Background()
	}
	var o options
	fs := flag.NewFlagSet(progName, flag.ContinueOnError)
	fs.SetOutput(errOut)
	fs.Usage = func() { usage(errOut) }

	fs.UintVar(&o.count, "c", 100, "количество тестовых пакетов")
	fs.StringVar(&o.dscp, "D", "", "значение DSCP для байта TOS")
	fs.StringVar(&o.saveFile, "F", "", "сохранять сырые записи в файл")
	fs.Float64Var(&o.interval, "i", 0.1, "среднее время между пакетами (секунды)")
	fs.Float64Var(&o.lossTimeout, "L", 0, "порог потери (секунды)")
	fs.StringVar(&o.portRange, "P", "", "диапазон локальных UDP-портов, нижний-верхний")
	fs.IntVar(&o.padding, "s", -1, "октетов заполнения на пакет")
	fs.Float64Var(&o.delayStart, "z", 0, "задержка перед началом теста (секунды)")

	fs.StringVar(&o.authMode, "A", "", "запрашиваемые режимы: A, E, M, O")
	fs.StringVar(&o.pfFile, "k", "", "файл с парольной фразой")
	fs.StringVar(&o.srcAddr, "S", "", "локальный адрес")
	fs.StringVar(&o.iface, "B", "", "локальный интерфейс")
	fs.BoolVar(&o.zeroAddr, "Z", false, "обнулить адреса в запросе сессии")
	fs.StringVar(&o.identity, "u", "", "имя пользователя (KeyID)")
	fs.BoolVar(&o.v4only, "4", false, "только IPv4")
	fs.BoolVar(&o.v6only, "6", false, "только IPv6")

	fs.StringVar(&o.percentiles, "a", "", "дополнительные уровни процентилей")
	fs.Float64Var(&o.bucketWidth, "b", 0.0001, "ширина корзины гистограммы (секунды)")
	fs.BoolVar(&o.machine, "M", false, "машиночитаемая сводка")
	fs.StringVar(&o.units, "n", "m", "единицы измерения: n, u, m или s")
	fs.UintVar(&o.subCount, "N", 0, "пакетов на одну подсводку сессии")
	fs.BoolVar(&o.quiet, "Q", false, "не выводить статистику")
	fs.BoolVar(&o.raw, "R", false, "печатать сырые записи")
	fs.StringVar(&o.verbose, "v", "", "печатать задержки по каждому пакету (можно -v=N)")
	fs.BoolVar(&o.unixTS, "U", false, "метки времени UNIX в задержках по пакетам")

	fs.UintVar(&o.spinUsec, "spin", defaultSpinUsec,
		"максимальное окно активного ожидания перед отправкой по расписанию (мкс, 0 отключает)")
	fs.BoolVar(&o.syncClock, "sync", false, "считать локальные часы синхронизированными")
	fs.UintVar(&o.errUsec, "esterror", 0, "оценка погрешности локальных часов (мкс)")

	fs.BoolVar(&o.help, "h", false, "показать эту справку и выйти")

	// Поддерживаем как одиночный "-v", так и "-v=N".
	if err := fs.Parse(normalizeVerbose(args)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usage(errOut)
			return nil
		}
		return err
	}
	if o.help {
		usage(errOut)
		return nil
	}

	rest := fs.Args()
	if len(rest) < 1 || len(rest) > 2 {
		usage(errOut)
		return errors.New("ожидается тест-адрес [адрес-сервера]")
	}
	remoteTest := rest[0]
	remoteServ := remoteTest
	if len(rest) > 1 {
		remoteServ = rest[1]
	}

	if o.count == 0 {
		return errors.New("значение -c должно быть больше нуля")
	}
	if o.interval <= 0 {
		return errors.New("значение -i должно быть больше нуля")
	}
	if o.bucketWidth <= 0 {
		return errors.New("значение -b должно быть больше нуля")
	}
	if o.v4only && o.v6only {
		return errors.New("параметры -4 и -6 несовместимы")
	}

	units := byte('m')
	if o.units != "" {
		units = o.units[0]
	}
	if _, _, err := owamp.ScaleFactor(units); err != nil {
		return err
	}

	percentiles, err := owamp.ParsePercentiles(o.percentiles)
	if err != nil {
		return err
	}

	var dscp uint8
	if o.dscp != "" {
		dscp, err = parseDSCP(o.dscp)
		if err != nil {
			return err
		}
	}
	typeP := uint32(dscp) << 24

	ports, err := parsePortRange(o.portRange)
	if err != nil {
		return err
	}

	modes, err := parseAuthMode(o.authMode, o.identity)
	if err != nil {
		return err
	}

	var passphrase []byte
	if modes&owamp.ModeDoCipherControl != 0 {
		passphrase, err = readPassphrase(o.pfFile, o.identity)
		if err != nil {
			return err
		}
	}

	srcAddr := o.srcAddr
	if srcAddr == "" && o.iface != "" {
		srcAddr, err = addrForInterface(o.iface, o.v6only)
		if err != nil {
			return err
		}
	}

	network := "tcp"
	switch {
	case o.v4only:
		network = "tcp4"
	case o.v6only:
		network = "tcp6"
	}

	// --- Управляющее соединение ---------------------------------------
	cntrl, err := owamp.OpenControlContext(ctx, owamp.ControlConfig{
		Server:       remoteServ,
		LocalAddr:    srcAddr,
		Network:      network,
		OfferedModes: modes,
		Identity:     o.identity,
		Passphrase:   passphrase,
		Timeout:      30 * time.Second,
		DSCP:         dscp,
	})
	if err != nil {
		return fmt.Errorf("не удалось открыть управляющее соединение с %s: %w", remoteServ, err)
	}
	defer cntrl.Close()

	rttBound := cntrl.RTTBound()
	lossTimeout := o.lossTimeout
	if lossTimeout <= 0 {
		lossTimeout = rttBound.Float() + 2.0
	}
	if lossTimeout < o.bucketWidth {
		return fmt.Errorf("недопустимые параметры теста: порог потери '-L' (%f) меньше ширины корзины '-b' (%f)",
			lossTimeout, o.bucketWidth)
	}

	mode := cntrl.Mode()

	padding := uint32(0)
	if o.padding < 0 {
		// По умолчанию дополняем пакет отправителя так, чтобы ответ
		// отражателя получился того же размера — так делает twping.
		padding = owamp.TestTWPayloadSize(mode, 0) - owamp.TestPayloadSize(mode, 0)
	} else {
		padding = uint32(o.padding)
	}
	if padding > owamp.MaxPaddingSize {
		padding = owamp.MaxPaddingSize
	}

	// --- Разрешение имени тестового узла ------------------------------
	udpNetwork := "udp"
	switch {
	case o.v4only:
		udpNetwork = "udp4"
	case o.v6only:
		udpNetwork = "udp6"
	}
	testHost, testPortStr := splitHostPortDefault(remoteTest, "0")
	reflector, err := net.ResolveUDPAddr(udpNetwork, net.JoinHostPort(testHost, testPortStr))
	if err != nil {
		return fmt.Errorf("не удалось разрешить тестовый адрес %q: %w", remoteTest, err)
	}
	if reflector.IP == nil {
		return fmt.Errorf("не удалось разрешить тестовый адрес %q", remoteTest)
	}

	var localIP net.IP
	if srcAddr != "" {
		localIP = net.ParseIP(srcAddr)
		if localIP == nil {
			if ips, err := net.LookupIP(srcAddr); err == nil && len(ips) > 0 {
				localIP = ips[0]
			}
		}
	}
	if localIP == nil {
		// Берём локальный адрес управляющего соединения — так делает owamp.
		localIP = cntrl.LocalAddr().IP
	}

	clock := owamp.Clock{Sync: o.syncClock || o.errUsec > 0, ErrUsec: uint32(o.errUsec)}
	if clock.ErrUsec == 0 && clock.Sync {
		clock.ErrUsec = 1
	}

	sess, err := owamp.NewSession(owamp.SessionConfig{
		Reflector:   reflector,
		LocalIP:     localIP,
		Ports:       ports,
		DSCP:        dscp,
		Clock:       clock,
		SpinMargin:  time.Duration(o.spinUsec) * time.Microsecond,
		RecvBufSize: 4 << 20,
		SendBufSize: 1 << 20,
	}, mode, padding)
	if err != nil {
		return fmt.Errorf("не удалось открыть тестовый сокет: %w", err)
	}
	defer sess.Close()

	local := sess.LocalAddr()

	// --- Запрос сессии ------------------------------------------------
	startDelay := owamp.Num64FromUint32(1) + rttBound.Mul(owamp.Num64FromUint32(2))
	if d := owamp.Num64FromFloat(o.delayStart); d > startDelay {
		startDelay = d
	}
	startTime := owamp.Num64FromTime(time.Now()) + startDelay

	spec := owamp.TestSpec{
		NPackets:    uint32(o.count),
		Slots:       []owamp.Slot{{Type: owamp.SlotRandExp, Mean: owamp.Num64FromFloat(o.interval)}},
		StartTime:   startTime,
		LossTimeout: owamp.Num64FromFloat(lossTimeout),
		Padding:     padding,
		TypeP:       typeP,
	}

	sid, reflectorPort, err := cntrl.RequestTWSession(owamp.TWSessionRequest{
		Sender:      &net.UDPAddr{IP: localIP, Port: local.Port},
		Receiver:    reflector,
		ZeroAddr:    o.zeroAddr,
		StartTime:   spec.StartTime,
		LossTimeout: spec.LossTimeout,
		TypeP:       spec.TypeP,
		Padding:     spec.Padding,
	})
	if err != nil {
		return fmt.Errorf("сессия не состоялась: %w", err)
	}
	reflector.Port = int(reflectorPort)

	aesKey, hmacKey, err := cntrl.TestKeys(sid)
	if err != nil {
		return err
	}
	if err := sess.SetKeys(aesKey, hmacKey); err != nil {
		return err
	}

	if err := cntrl.StartSessions(); err != nil {
		return fmt.Errorf("session failed: %w", err)
	}

	if !o.quiet {
		eta := owamp.EstimateDuration(spec, rttBound)
		remaining := time.Until(spec.StartTime.AbsTime()) + eta
		// Строка попадает в тот же поток, что и сводка, поэтому подчиняется
		// её языку: иначе английский отчёт начинался бы русской фразой.
		if lang == owamp.Russian {
			fmt.Fprintf(out, "Результаты будут доступны примерно через %.1f с\n", remaining.Seconds())
		} else {
			fmt.Fprintf(out, "Approximately %.1f seconds until results available\n", remaining.Seconds())
		}
	}

	// --- Подготовка вывода --------------------------------------------
	stdout := bufio.NewWriter(out)
	defer stdout.Flush()

	var saveFile *os.File
	if o.saveFile != "" {
		saveFile, err = os.Create(o.saveFile)
		if err != nil {
			return err
		}
		defer saveFile.Close()
	}
	var saveWriter *bufio.Writer
	if saveFile != nil {
		saveWriter = bufio.NewWriter(saveFile)
		defer saveWriter.Flush()
	}

	statsCfg := owamp.StatsConfig{
		FromHost:    local.IP.String(),
		FromServ:    strconv.Itoa(local.Port),
		ToHost:      reflector.IP.String(),
		ToServ:      strconv.Itoa(reflector.Port),
		SID:         sid,
		Unit:        units,
		BucketWidth: o.bucketWidth,
		NPackets:    spec.NPackets,
		Padding:     spec.Padding,
		TypeP:       spec.TypeP,
		LossTimeout: spec.LossTimeout,
	}
	if verboseOn, limit := parseVerbose(o.verbose); verboseOn && !o.quiet && !o.raw {
		statsCfg.RecordOutput = stdout
		statsCfg.RecordLimit = limit
		statsCfg.UnixTimestamps = o.unixTS
	}

	stats, err := owamp.NewStats(statsCfg)
	if err != nil {
		return err
	}

	sink := func(rec *owamp.TWDataRec) error {
		if saveWriter != nil {
			if err := rec.WriteRaw(saveWriter); err != nil {
				return err
			}
		}
		if o.raw {
			return rec.WriteRaw(stdout)
		}
		if o.quiet {
			return nil
		}
		return stats.Add(rec)
	}

	// --- Запуск теста -------------------------------------------------
	// Прерывание приходит через контекст: в утилите его снимает обработчик
	// Ctrl+C, в чужой программе — её собственная логика отмены.
	interrupted := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			close(interrupted)
			sess.Close()
		case <-interrupted:
		}
	}()

	runErr := sess.Run(spec, sid, sink)

	select {
	case <-interrupted:
		return errors.New("прервано")
	default:
		close(interrupted)
	}

	accept := owamp.AcceptOK
	if runErr != nil {
		accept = owamp.AcceptFailure
	}
	if err := cntrl.StopSessions(accept, 1); err != nil {
		fmt.Fprintf(errOut, "%s: %v\n", progName, err)
	}
	if runErr != nil {
		return fmt.Errorf("тестовая сессия завершилась с ошибкой: %w", runErr)
	}

	stats.SetFinished(true)
	if o.quiet || o.raw {
		return nil
	}
	if o.machine {
		stats.PrintMachine(stdout)
	} else {
		stats.PrintSummaryLang(stdout, percentiles, lang)
	}
	return nil
}

// normalizeVerbose переписывает одиночный "-v" в "-v=on", чтобы пакет flag
// воспринимал -v как флаг с необязательным аргументом, как это делает twping.
func normalizeVerbose(args []string) []string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		switch {
		case a == "-v" || a == "--v":
			out = append(out, "-v=on")
		case strings.HasPrefix(a, "-v") && !strings.HasPrefix(a, "-v=") && len(a) > 2:
			// Форма "-v10".
			out = append(out, "-v="+a[2:])
		default:
			out = append(out, a)
		}
	}
	return out
}

func parseVerbose(v string) (bool, uint64) {
	switch v {
	case "":
		return false, 0
	case "on":
		return true, 0
	}
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		return true, 0
	}
	return true, n
}

func parseDSCP(s string) (uint8, error) {
	base := 10
	t := s
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		base, t = 16, s[2:]
	}
	v, err := strconv.ParseUint(t, base, 32)
	if err != nil {
		return 0, fmt.Errorf("недопустимое значение DSCP %q", s)
	}
	if v > 0x3F {
		return 0, fmt.Errorf("значение DSCP %q вне диапазона 0-63", s)
	}
	return uint8(v), nil
}

func parsePortRange(s string) (owamp.PortRange, error) {
	var pr owamp.PortRange
	if s == "" {
		return pr, nil
	}
	lo, hi, found := strings.Cut(s, "-")
	l, err := strconv.ParseUint(strings.TrimSpace(lo), 10, 16)
	if err != nil {
		return pr, fmt.Errorf("недопустимый диапазон портов %q", s)
	}
	pr.Low = uint16(l)
	pr.High = pr.Low
	if found {
		h, err := strconv.ParseUint(strings.TrimSpace(hi), 10, 16)
		if err != nil {
			return pr, fmt.Errorf("invalid port range %q", s)
		}
		pr.High = uint16(h)
	}
	if pr.High < pr.Low {
		return pr, fmt.Errorf("недопустимый диапазон портов %q: верхний меньше нижнего", s)
	}
	return pr, nil
}

func parseAuthMode(s, identity string) (uint32, error) {
	if s == "" {
		// Предлагать шифрующий режим осмысленно только при наличии KeyID,
		// поэтому без -u клиент запрашивает лишь открытый режим.
		if identity == "" {
			return owamp.ModeOpen, nil
		}
		return owamp.TWPDefaultOfferedMode, nil
	}
	var modes uint32
	for _, c := range strings.ToUpper(s) {
		switch c {
		case 'A':
			modes |= owamp.ModeAuth
		case 'E':
			modes |= owamp.ModeEncrypted
		case 'M':
			modes |= owamp.ModeMixed
		case 'O':
			modes |= owamp.ModeOpen
		default:
			return 0, fmt.Errorf("недопустимый режим -A %q: ожидается A, E, M или O", string(c))
		}
	}
	return modes, nil
}

func readPassphrase(file, identity string) ([]byte, error) {
	if file == "" {
		return nil, fmt.Errorf("режимы с аутентификацией, шифрованием и смешанный требуют -k с файлом парольной фразы")
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	// Формат файла парольных фраз owamp — по строке вида
	// "идентификатор<пробел>парольная фраза"; файл из одной строки без
	// идентификатора тоже принимается.
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, pass, found := strings.Cut(line, " ")
		if !found {
			if identity == "" {
				return []byte(strings.TrimSpace(line)), nil
			}
			continue
		}
		if name == identity {
			return []byte(strings.TrimSpace(pass)), nil
		}
	}
	return nil, fmt.Errorf("в %s нет парольной фразы для идентификатора %q", file, identity)
}

func addrForInterface(name string, wantV6 bool) (string, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return "", err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return "", err
	}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		isV4 := ipn.IP.To4() != nil
		if wantV6 == isV4 {
			continue
		}
		if ipn.IP.IsLinkLocalUnicast() {
			continue
		}
		return ipn.IP.String(), nil
	}
	return "", fmt.Errorf("у интерфейса %s нет пригодного адреса", name)
}

func splitHostPortDefault(addr, defPort string) (host, port string) {
	if h, p, err := net.SplitHostPort(addr); err == nil {
		return h, p
	}
	return addr, defPort
}
