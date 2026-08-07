package owamp

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"time"
)

// ControlConfig описывает параметры открытия управляющего соединения TWAMP.
type ControlConfig struct {
	// Server — "хост" или "хост:порт" управляющей службы twampd.
	Server string
	// LocalAddr при необходимости закрепляет локальный адрес управляющего
	// соединения и тестовой сессии.
	LocalAddr string
	// Network ограничивает семейство адресов: "tcp", "tcp4" или "tcp6".
	Network string
	// OfferedModes — битовая маска режимов, которые готов использовать клиент.
	OfferedModes uint32
	// Identity — KeyID для режимов с аутентификацией, шифрованием и смешанного.
	Identity string
	// Passphrase — общий секрет для тех же режимов.
	Passphrase []byte
	// Timeout ограничивает время установления TCP-соединения.
	Timeout time.Duration
	// ExchangeTimeout ограничивает каждый обмен по управляющему каналу:
	// приветствие сервера, согласование режима, запрос и старт сессии.
	//
	// Без него клиент беззащитен перед сервером, который принял соединение и
	// замолчал: чтение висит бесконечно, и остановить его нечем — ни отменой,
	// ни таймаутом вызывающей программы. На пробе, ведущей тысячи замеров,
	// такие «висяки» копятся и держат порты, пока не кончится пул.
	//
	// Ноль означает значение по умолчанию (defaultExchangeTimeout).
	// Отрицательное — «без ограничения», прежнее поведение.
	ExchangeTimeout time.Duration
	// DSCP, если отличен от нуля, применяется к сокету управляющего соединения.
	DSCP uint8
}

// defaultExchangeTimeout — сколько ждать ответа сервера на каждом шаге
// управляющего обмена, если ExchangeTimeout не задан.
//
// Тридцать секунд — тот же порядок, что и таймаут подключения: шаги короткие
// (сервер отвечает сразу), поэтому ожидание такой длины означает, что ответа
// уже не будет.
const defaultExchangeTimeout = 30 * time.Second

// Control — открытое управляющее соединение TWAMP.
type Control struct {
	conn net.Conn

	// exchangeTimeout применяется к каждому чтению и записи управляющего канала.
	exchangeTimeout time.Duration

	// watchdog закрывает соединение при отмене контекста: чтение, уже начатое,
	// иначе не прервать — дедлайн спасает от молчания, а это от отмены.
	watchdogDone chan struct{}

	mode uint32

	sessionKey []byte
	hmacKey    []byte

	encrypt cipher.BlockMode
	decrypt cipher.BlockMode

	sendHMAC hash.Hash
	recvHMAC hash.Hash

	// rttBound — наименьшее время кругового обхода управляющего соединения,
	// замеренное при установлении связи. Используется для выбора времени
	// старта и порога потери по умолчанию.
	rttBound Num64

	uptime Num64

	msg [testRequestLen]byte
}

// Mode возвращает согласованный режим сессии.
func (c *Control) Mode() uint32 { return c.mode }

// RTTBound возвращает замеренное время кругового обхода управляющего
// соединения.
func (c *Control) RTTBound() Num64 { return c.rttBound }

// LocalAddr возвращает локальный адрес управляющего соединения.
func (c *Control) LocalAddr() *net.TCPAddr { return c.conn.LocalAddr().(*net.TCPAddr) }

// RemoteAddr возвращает удалённый адрес управляющего соединения.
func (c *Control) RemoteAddr() *net.TCPAddr { return c.conn.RemoteAddr().(*net.TCPAddr) }

// Close закрывает управляющее соединение и снимает сторож контекста.
func (c *Control) Close() error {
	if c.watchdogDone != nil {
		select {
		case <-c.watchdogDone:
		default:
			close(c.watchdogDone)
		}
	}
	return c.conn.Close()
}

// OpenControl выполняет установление связи TWAMP-Control.
func OpenControl(cfg ControlConfig) (*Control, error) {
	return OpenControlContext(context.Background(), cfg)
}

// OpenControlContext делает то же, что OpenControl, но прерывает подключение
// по отмене контекста.
//
// Без этого отмена не действует на стадии установления TCP-соединения:
// недоступный сервер держит вызывающего до истечения Timeout (а без него —
// до системного таймаута примерно в полминуты). Программам, которые
// останавливают замер по своей причине — например, потому что задачу удалили, —
// такое ожидание не нужно.
func OpenControlContext(ctx context.Context, cfg ControlConfig) (*Control, error) {
	network := cfg.Network
	if network == "" {
		network = "tcp"
	}
	server := cfg.Server
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(server, "862")
	}

	d := net.Dialer{Timeout: cfg.Timeout}
	if cfg.LocalAddr != "" {
		la, err := net.ResolveTCPAddr(network, net.JoinHostPort(cfg.LocalAddr, "0"))
		if err != nil {
			return nil, fmt.Errorf("не удалось разрешить локальный адрес %q: %w", cfg.LocalAddr, err)
		}
		d.LocalAddr = la
	}
	if cfg.DSCP != 0 {
		tos := int(cfg.DSCP) << 2
		d.Control = func(_, _ string, rc syscallRawConn) error {
			setTOS(rc, tos)
			return nil
		}
	}

	conn, err := d.DialContext(ctx, network, server)
	if err != nil {
		return nil, err
	}
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
	}

	c := &Control{conn: conn, exchangeTimeout: cfg.ExchangeTimeout}
	if c.exchangeTimeout == 0 {
		c.exchangeTimeout = defaultExchangeTimeout
	}
	c.watchContext(ctx)

	if err := c.setup(cfg); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// watchContext закрывает соединение, когда контекст отменяют.
//
// Дедлайнов для этого мало: они спасают от молчащего сервера, но не от отмены
// посреди уже начатого чтения. Закрытие сокета прерывает и его — вызывающая
// программа получает ошибку сразу, а не через полминуты.
func (c *Control) watchContext(ctx context.Context) {
	if ctx == nil || ctx.Done() == nil {
		return // контекст без отмены — сторожить нечего
	}

	c.watchdogDone = make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			c.conn.Close()
		case <-c.watchdogDone:
		}
	}()
}

// deadline готовит соединение к очередному шагу обмена.
func (c *Control) deadline() {
	if c.exchangeTimeout <= 0 {
		return // «без ограничения» — так просили явно
	}
	_ = c.conn.SetDeadline(time.Now().Add(c.exchangeTimeout))
}

func (c *Control) setup(cfg ControlConfig) error {
	// --- Server-Greeting (64 октета, без шифрования) --------------------
	var greeting [greetingLen]byte
	start := time.Now()
	c.deadline()
	if _, err := io.ReadFull(c.conn, greeting[:]); err != nil {
		return fmt.Errorf("чтение Server-Greeting: %w", err)
	}
	// Приветствие приходит только после того, как сервер принял
	// TCP-соединение, поэтому это верхняя оценка одного кругового обхода.
	c.rttBound = Num64FromDuration(time.Since(start))

	availModes := binary.BigEndian.Uint32(greeting[12:16])
	challenge := greeting[16:32]
	salt := greeting[32:48]
	count := binary.BigEndian.Uint32(greeting[48:52])

	if availModes == 0 {
		return errors.New("сервер не предлагает ни одного режима (занят или завершает работу)")
	}

	offered := cfg.OfferedModes
	if offered == 0 {
		offered = TWPDefaultOfferedMode
	}
	mode, err := selectMode(availModes, offered)
	if err != nil {
		return err
	}
	c.mode = mode

	// --- Set-Up-Response (164 октета, без шифрования) -------------------
	var resp [setupResponseLen]byte
	binary.BigEndian.PutUint32(resp[0:4], mode)

	if mode&ModeDoCipherControl != 0 {
		if len(cfg.Passphrase) == 0 {
			return fmt.Errorf("режим %s требует парольной фразы", ModeString(mode))
		}
		if count == 0 {
			count = defaultPBKDF2Count
		}
		if len(cfg.Identity) > 80 {
			return errors.New("идентификатор длиннее 80 октетов")
		}

		c.sessionKey = make([]byte, 16)
		c.hmacKey = make([]byte, 32)
		if _, err := rand.Read(c.sessionKey); err != nil {
			return err
		}
		if _, err := rand.Read(c.hmacKey); err != nil {
			return err
		}

		clientIV := make([]byte, blockSize)
		if _, err := rand.Read(clientIV); err != nil {
			return err
		}

		// Token = AES-CBC(pbkdf2(парольная фраза, salt, count),
		//                 challenge || ключ сессии || ключ HMAC)
		var plain [tokenLen]byte
		copy(plain[0:16], challenge)
		copy(plain[16:32], c.sessionKey)
		copy(plain[32:64], c.hmacKey)

		dk, err := pbkdf2.Key(sha1.New, string(cfg.Passphrase), salt, int(count), blockSize)
		if err != nil {
			return fmt.Errorf("выработка ключа: %w", err)
		}
		tokenBlock, err := aes.NewCipher(dk)
		if err != nil {
			return err
		}
		var token [tokenLen]byte
		cipher.NewCBCEncrypter(tokenBlock, make([]byte, blockSize)).
			CryptBlocks(token[:], plain[:])

		copy(resp[4:84], []byte(cfg.Identity))
		copy(resp[84:148], token[:])
		copy(resp[148:164], clientIV)

		sessionBlock, err := aes.NewCipher(c.sessionKey)
		if err != nil {
			return err
		}
		c.encrypt = cipher.NewCBCEncrypter(sessionBlock, clientIV)
		c.sendHMAC = hmac.New(sha1.New, c.hmacKey)
		c.recvHMAC = hmac.New(sha1.New, c.hmacKey)
	}

	c.deadline()
	if _, err := c.conn.Write(resp[:]); err != nil {
		return fmt.Errorf("запись Set-Up-Response: %w", err)
	}

	// --- Server-Start (48 октетов, последний блок шифруется) ------------
	var ss [serverStartLen]byte
	start = time.Now()
	c.deadline()
	if _, err := io.ReadFull(c.conn, ss[:32]); err != nil {
		return fmt.Errorf("чтение Server-Start: %w", err)
	}
	if rtt := Num64FromDuration(time.Since(start)); rtt > 0 && rtt < c.rttBound {
		c.rttBound = rtt
	}

	accept, err := validAccept(ss[15])
	if err != nil {
		return err
	}
	if accept != AcceptOK {
		return fmt.Errorf("сервер отклонил управляющее соединение: %s", accept)
	}

	if c.mode&ModeDoCipherControl != 0 {
		serverIV := ss[16:32]
		sessionBlock, err := aes.NewCipher(c.sessionKey)
		if err != nil {
			return err
		}
		c.decrypt = cipher.NewCBCDecrypter(sessionBlock, serverIV)
	}

	c.deadline()
	if _, err := io.ReadFull(c.conn, ss[32:48]); err != nil {
		return fmt.Errorf("чтение поля uptime в Server-Start: %w", err)
	}
	if c.decrypt != nil {
		c.decrypt.CryptBlocks(ss[32:48], ss[32:48])
		// У этого блока нет собственного поля с дайджестом; он входит в
		// текст, покрываемый HMAC следующего сообщения.
		c.recvHMAC.Write(ss[32:48])
	}
	ts, _ := DecodeTimestamp(ss[32:40], ss[40:42])
	c.uptime = ts.Time

	if c.rttBound == 0 {
		c.rttBound = Num64FromDuration(time.Millisecond)
	}
	return nil
}

func selectMode(avail, offered uint32) (uint32, error) {
	// Сначала самые сильные режимы — тот же порядок предпочтения, что у twping.
	for _, m := range []uint32{ModeEncrypted, ModeAuth, ModeMixed, ModeOpen} {
		if avail&offered&m != 0 {
			return m, nil
		}
	}
	return 0, fmt.Errorf("нет общего поддерживаемого режима (сервер предлагает 0x%x, клиент 0x%x)",
		avail, offered)
}

// sendBlocks шифрует, если нужно, и записывает целые блоки по 16 октетов.
func (c *Control) sendBlocks(buf []byte) error {
	if len(buf)%blockSize != 0 {
		return fmt.Errorf("owamp: %d октетов не составляют целое число блоков", len(buf))
	}
	if c.encrypt != nil {
		c.encrypt.CryptBlocks(buf, buf)
	}
	c.deadline()
	_, err := c.conn.Write(buf)
	return err
}

// recvBlocks читает и расшифровывает целые блоки по 16 октетов.
func (c *Control) recvBlocks(buf []byte) error {
	c.deadline()
	if _, err := io.ReadFull(c.conn, buf); err != nil {
		return err
	}
	if c.decrypt != nil {
		c.decrypt.CryptBlocks(buf, buf)
	}
	return nil
}

// sendDigest добавляет текст к накапливаемому HMAC отправки, записывает
// усечённый дайджест в out и сбрасывает HMAC перед следующим сообщением.
func (c *Control) sendDigest(text, out []byte) {
	if c.sendHMAC == nil {
		for i := range out {
			out[i] = 0
		}
		return
	}
	c.sendHMAC.Write(text)
	sum := c.sendHMAC.Sum(nil)
	copy(out, sum[:blockSize])
	c.sendHMAC.Reset()
}

// checkDigest добавляет текст к накапливаемому HMAC приёма, проверяет усечённый
// дайджест и сбрасывает HMAC перед следующим сообщением.
func (c *Control) checkDigest(text, digest []byte) error {
	if c.recvHMAC == nil {
		return nil
	}
	c.recvHMAC.Write(text)
	sum := c.recvHMAC.Sum(nil)
	c.recvHMAC.Reset()
	if subtle.ConstantTimeCompare(sum[:blockSize], digest[:blockSize]) != 1 {
		return errors.New("неверный HMAC управляющего сообщения")
	}
	return nil
}

// TWSessionRequest описывает запрашиваемую двустороннюю тестовую сессию.
type TWSessionRequest struct {
	// Sender — локальный адрес и порт, с которых клиент будет отправлять.
	Sender *net.UDPAddr
	// Receiver — адрес отражателя.
	Receiver *net.UDPAddr
	// ZeroAddr обнуляет IP-адреса в запросе для прохождения через NAT.
	ZeroAddr bool
	// StartTime — абсолютное время начала сессии.
	StartTime Num64
	// LossTimeout — сколько ждать ответа, прежде чем считать пакет потерянным.
	LossTimeout Num64
	// TypeP передаёт запрос DSCP (раздел 3.5 RFC 4656).
	TypeP uint32
	// Padding — число октетов заполнения, добавляемых к каждому пакету
	// отправителя.
	Padding uint32
}

// RequestTWSession отправляет Request-TW-Session и читает ответ Accept-Session.
// Возвращает SID и UDP-порт, на котором слушает отражатель.
func (c *Control) RequestTWSession(req TWSessionRequest) (sid [sidLen]byte, port uint16, err error) {
	buf := c.msg[:testRequestLen]
	for i := range buf {
		buf[i] = 0
	}

	sender4 := req.Sender.IP.To4()
	recv4 := req.Receiver.IP.To4()
	if (sender4 == nil) != (recv4 == nil) {
		return sid, 0, errors.New("семейства адресов отправителя и получателя не совпадают")
	}

	buf[0] = ReqTestTW
	if sender4 != nil {
		buf[1] = 4
	} else {
		buf[1] = 6
	}
	// Для двусторонних сессий Conf-Sender и Conf-Receiver всегда равны нулю,
	// как и число слотов и число пакетов (смещения 4 и 8).

	binary.BigEndian.PutUint16(buf[12:14], uint16(req.Sender.Port))
	binary.BigEndian.PutUint16(buf[14:16], uint16(req.Receiver.Port))
	if !req.ZeroAddr {
		if sender4 != nil {
			copy(buf[16:20], sender4)
			copy(buf[32:36], recv4)
		} else {
			copy(buf[16:32], req.Sender.IP.To16())
			copy(buf[32:48], req.Receiver.IP.To16())
		}
	}
	// SID в 48..64 оставляем нулевым: его назначает сервер.
	binary.BigEndian.PutUint32(buf[64:68], req.Padding)
	Timestamp{Time: req.StartTime}.EncodeTime(buf[68:76])
	Timestamp{Time: req.LossTimeout}.EncodeTime(buf[76:84])
	binary.BigEndian.PutUint32(buf[84:88], req.TypeP)
	// 88..96 — MBZ, 96..112 — HMAC.

	c.sendDigest(buf[0:96], buf[96:112])
	if err := c.sendBlocks(buf); err != nil {
		return sid, 0, fmt.Errorf("запись Request-TW-Session: %w", err)
	}

	var acc [acceptSessionLen]byte
	if err := c.recvBlocks(acc[:]); err != nil {
		return sid, 0, fmt.Errorf("чтение Accept-Session: %w", err)
	}
	if err := c.checkDigest(acc[0:32], acc[32:48]); err != nil {
		return sid, 0, err
	}

	accept, err := validAccept(acc[0])
	if err != nil {
		return sid, 0, err
	}
	if accept != AcceptOK {
		return sid, 0, fmt.Errorf("запрос сессии отклонён: %s", accept)
	}

	port = binary.BigEndian.Uint16(acc[2:4])
	copy(sid[:], acc[4:20])
	if port == 0 {
		return sid, 0, errors.New("сервер принял сессию, но вернул порт 0")
	}
	return sid, port, nil
}

// StartSessions отправляет Start-Sessions и ожидает Start-Ack.
func (c *Control) StartSessions() error {
	var buf [startSessionsLen]byte
	buf[0] = ReqStartSessions
	c.sendDigest(buf[0:16], buf[16:32])
	if err := c.sendBlocks(buf[:]); err != nil {
		return fmt.Errorf("запись Start-Sessions: %w", err)
	}

	var ack [startAckLen]byte
	if err := c.recvBlocks(ack[:]); err != nil {
		return fmt.Errorf("чтение Start-Ack: %w", err)
	}
	if err := c.checkDigest(ack[0:16], ack[16:32]); err != nil {
		return err
	}
	accept, err := validAccept(ack[0])
	if err != nil {
		return err
	}
	if accept != AcceptOK {
		return fmt.Errorf("сервер отказался начинать сессии: %s", accept)
	}
	return nil
}

// StopSessions отправляет Stop-Sessions для numSessions двусторонних сессий.
// Двусторонний клиент не читает Stop-Sessions в ответ от отражателя.
func (c *Control) StopSessions(accept AcceptType, numSessions uint32) error {
	var buf [stopSessionsLen]byte
	buf[0] = ReqStopSessions
	buf[1] = byte(accept)
	binary.BigEndian.PutUint32(buf[4:8], numSessions)
	c.sendDigest(buf[0:16], buf[16:32])
	if err := c.sendBlocks(buf[:]); err != nil {
		return fmt.Errorf("запись Stop-Sessions: %w", err)
	}
	return nil
}

// TestKeys вырабатывает ключи AES и HMAC для шифрованных тестовых пакетов
// данной сессии согласно разделу 4.1 RFC 4656.
func (c *Control) TestKeys(sid [sidLen]byte) (aesKey, hmacKey []byte, err error) {
	if c.mode&ModeDoCipherTest == 0 {
		return nil, nil, nil
	}
	sidBlock, err := aes.NewCipher(sid[:])
	if err != nil {
		return nil, nil, err
	}
	aesKey = make([]byte, blockSize)
	sidBlock.Encrypt(aesKey, c.sessionKey)

	hmacKey = make([]byte, len(c.hmacKey))
	cipher.NewCBCEncrypter(sidBlock, make([]byte, blockSize)).
		CryptBlocks(hmacKey, c.hmacKey)
	return aesKey, hmacKey, nil
}

// SessionKeyFingerprint предназначен только для диагностики.
func (c *Control) SessionKeyFingerprint() string {
	if c.sessionKey == nil {
		return ""
	}
	sum := sha1.Sum(c.sessionKey)
	return fmt.Sprintf("%x", sum[:4])
}
