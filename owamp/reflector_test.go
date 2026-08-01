package owamp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// testReflector — минимальный сервер TWAMP (управляющая часть плюс отражатель
// сессии) для сквозной проверки клиента. Он реализует только то, что нужно
// клиенту.
type testReflector struct {
	t          *testing.T
	ln         net.Listener
	passphrase []byte
	identity   string
	// availModes ограничивает набор режимов, предлагаемых сервером.
	availModes uint32
	// dropEvery заставляет отражатель отбрасывать каждый N-й пакет
	// (0 — не отбрасывать).
	dropEvery uint32
	// dupEvery заставляет отражатель посылать вторую копию каждого N-го пакета.
	dupEvery uint32
	// procDelay — задержка, вносимая между приёмом и отражением.
	procDelay time.Duration

	wg   sync.WaitGroup
	done chan struct{}
}

func newTestReflector(t *testing.T, availModes uint32) *testReflector {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &testReflector{t: t, ln: ln, availModes: availModes, done: make(chan struct{})}
	r.wg.Add(1)
	go r.serve()
	t.Cleanup(r.Close)
	return r
}

func (r *testReflector) Addr() string { return r.ln.Addr().String() }

func (r *testReflector) Close() {
	select {
	case <-r.done:
		return
	default:
	}
	close(r.done)
	r.ln.Close()
	r.wg.Wait()
}

func (r *testReflector) serve() {
	defer r.wg.Done()
	conn, err := r.ln.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	if err := r.handle(conn); err != nil {
		select {
		case <-r.done:
		default:
			r.t.Logf("reflector: %v", err)
		}
	}
}

func (r *testReflector) handle(conn net.Conn) error {
	// --- ServerGreeting ------------------------------------------------
	var greeting [greetingLen]byte
	binary.BigEndian.PutUint32(greeting[12:16], r.availModes)
	challenge := greeting[16:32]
	salt := greeting[32:48]
	if _, err := rand.Read(challenge); err != nil {
		return err
	}
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	binary.BigEndian.PutUint32(greeting[48:52], defaultPBKDF2Count)
	if _, err := conn.Write(greeting[:]); err != nil {
		return err
	}
	challengeCopy := append([]byte(nil), challenge...)
	saltCopy := append([]byte(nil), salt...)

	// --- SetUpResponse -------------------------------------------------
	var resp [setupResponseLen]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		return err
	}
	mode := binary.BigEndian.Uint32(resp[0:4])

	var encrypt, decrypt cipher.BlockMode
	var sendH, recvH *hmacWrapper
	var sessionKey, hmacKey []byte

	if mode&ModeDoCipherControl != 0 {
		token := resp[84:148]
		clientIV := resp[148:164]

		dk, err := pbkdf2.Key(sha1.New, string(r.passphrase), saltCopy, defaultPBKDF2Count, blockSize)
		if err != nil {
			return err
		}
		blk, err := aes.NewCipher(dk)
		if err != nil {
			return err
		}
		plain := make([]byte, tokenLen)
		cipher.NewCBCDecrypter(blk, make([]byte, blockSize)).CryptBlocks(plain, token)
		if subtle.ConstantTimeCompare(plain[0:16], challengeCopy) != 1 {
			return fmt.Errorf("challenge не совпал: неверная парольная фраза")
		}
		sessionKey = plain[16:32]
		hmacKey = plain[32:64]

		sk, err := aes.NewCipher(sessionKey)
		if err != nil {
			return err
		}
		decrypt = cipher.NewCBCDecrypter(sk, clientIV)

		serverIV := make([]byte, blockSize)
		if _, err := rand.Read(serverIV); err != nil {
			return err
		}
		encrypt = cipher.NewCBCEncrypter(sk, serverIV)

		sendH = newHMACWrapper(hmacKey)
		recvH = newHMACWrapper(hmacKey)

		// --- ServerStart -------------------------------------------
		var ss [serverStartLen]byte
		ss[15] = byte(AcceptOK)
		copy(ss[16:32], serverIV)
		Timestamp{Time: Num64FromTime(time.Now())}.EncodeTime(ss[32:40])
		sendH.h.Write(ss[32:48])
		encrypt.CryptBlocks(ss[32:48], ss[32:48])
		if _, err := conn.Write(ss[:]); err != nil {
			return err
		}
	} else {
		var ss [serverStartLen]byte
		ss[15] = byte(AcceptOK)
		Timestamp{Time: Num64FromTime(time.Now())}.EncodeTime(ss[32:40])
		if _, err := conn.Write(ss[:]); err != nil {
			return err
		}
	}

	recvBlocks := func(buf []byte) error {
		if _, err := io.ReadFull(conn, buf); err != nil {
			return err
		}
		if decrypt != nil {
			decrypt.CryptBlocks(buf, buf)
		}
		return nil
	}
	sendBlocks := func(buf []byte) error {
		if encrypt != nil {
			encrypt.CryptBlocks(buf, buf)
		}
		_, err := conn.Write(buf)
		return err
	}
	checkRecv := func(text, digest []byte) error {
		if recvH == nil {
			return nil
		}
		recvH.h.Write(text)
		sum := recvH.h.Sum(nil)
		recvH.h.Reset()
		if subtle.ConstantTimeCompare(sum[:blockSize], digest) != 1 {
			return fmt.Errorf("bad client HMAC")
		}
		return nil
	}
	putSend := func(text, out []byte) {
		if sendH == nil {
			return
		}
		sendH.h.Write(text)
		copy(out, sendH.h.Sum(nil)[:blockSize])
		sendH.h.Reset()
	}

	// --- Request-TW-Session --------------------------------------------
	var req [testRequestLen]byte
	if err := recvBlocks(req[:]); err != nil {
		return err
	}
	if err := checkRecv(req[0:96], req[96:112]); err != nil {
		return err
	}
	if req[0] != ReqTestTW {
		return fmt.Errorf("ожидалось Request-TW-Session, получена команда %d", req[0])
	}
	senderPort := binary.BigEndian.Uint16(req[12:14])
	padding := binary.BigEndian.Uint32(req[64:68])
	startTS, _ := DecodeTimestamp(req[68:76], []byte{0x3F, 0xFF})
	_ = startTS

	// Привязываем UDP-сокет отражателя.
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return err
	}
	defer udp.Close()
	localPort := udp.LocalAddr().(*net.UDPAddr).Port

	var sid [sidLen]byte
	if _, err := rand.Read(sid[:]); err != nil {
		return err
	}

	var acc [acceptSessionLen]byte
	acc[0] = byte(AcceptOK)
	binary.BigEndian.PutUint16(acc[2:4], uint16(localPort))
	copy(acc[4:20], sid[:])
	putSend(acc[0:32], acc[32:48])
	if err := sendBlocks(acc[:]); err != nil {
		return err
	}

	// --- Start-Sessions -------------------------------------------------
	var start [startSessionsLen]byte
	if err := recvBlocks(start[:]); err != nil {
		return err
	}
	if err := checkRecv(start[0:16], start[16:32]); err != nil {
		return err
	}
	if start[0] != ReqStartSessions {
		return fmt.Errorf("ожидалось Start-Sessions, получено %d", start[0])
	}

	var ack [startAckLen]byte
	ack[0] = byte(AcceptOK)
	putSend(ack[0:16], ack[16:32])
	if err := sendBlocks(ack[:]); err != nil {
		return err
	}

	// --- Reflect test packets ------------------------------------------
	reflectDone := make(chan struct{})
	go func() {
		defer close(reflectDone)
		r.reflect(udp, mode, sessionKey, hmacKey, sid, padding, int(senderPort))
	}()

	// --- Stop-Sessions --------------------------------------------------
	var stop [stopSessionsLen]byte
	if err := recvBlocks(stop[:]); err != nil {
		udp.Close()
		<-reflectDone
		return err
	}
	if err := checkRecv(stop[0:16], stop[16:32]); err != nil {
		udp.Close()
		<-reflectDone
		return err
	}
	if stop[0] != ReqStopSessions {
		udp.Close()
		<-reflectDone
		return fmt.Errorf("ожидалось Stop-Sessions, получено %d", stop[0])
	}
	udp.Close()
	<-reflectDone
	return nil
}

// hmacWrapper хранит накапливаемый HMAC управляющего канала для
// текущего сообщения.
type hmacWrapper struct{ h hash.Hash }

func newHMACWrapper(key []byte) *hmacWrapper {
	return &hmacWrapper{h: hmac.New(sha1.New, key)}
}

// reflect реализует роль отражателя сессии TWAMP (Session-Reflector).
func (r *testReflector) reflect(udp *net.UDPConn, mode uint32, sessionKey, controlHMACKey []byte,
	sid [sidLen]byte, padding uint32, senderPort int) {

	var aesBlock cipher.Block
	var testHMACKey []byte
	if mode&ModeDoCipherTest != 0 {
		sidBlk, err := aes.NewCipher(sid[:])
		if err != nil {
			r.t.Logf("reflector: %v", err)
			return
		}
		key := make([]byte, blockSize)
		sidBlk.Encrypt(key, sessionKey)
		aesBlock, err = aes.NewCipher(key)
		if err != nil {
			r.t.Logf("reflector: %v", err)
			return
		}
		testHMACKey = make([]byte, len(controlHMACKey))
		cipher.NewCBCEncrypter(sidBlk, make([]byte, blockSize)).
			CryptBlocks(testHMACKey, controlHMACKey)
	}

	clock := Clock{Sync: true, ErrUsec: 100}
	inBuf := make([]byte, 65536)
	replySize := TestTWPayloadSize(mode, 0)
	reply := make([]byte, replySize)
	clear96 := make([]byte, 96)
	iv := make([]byte, blockSize)

	var mac hash.Hash
	if testHMACKey != nil {
		mac = hmac.New(sha1.New, testHMACKey)
	}

	var reflSeq uint32
	var received uint32

	for {
		n, from, err := udp.ReadFromUDP(inBuf)
		if err != nil {
			return
		}
		recvTS := clock.StampAt(time.Now())
		if uint32(n) < TestPayloadSize(mode, 0) {
			continue
		}
		received++

		pkt := inBuf[:n]

		// Расшифровываем и аутентифицируем пакет клиента.
		if mode&ModeDoCipherTest != 0 {
			for j := range iv {
				iv[j] = 0
			}
			dec := cipher.NewCBCDecrypter(aesBlock, iv)
			dec.CryptBlocks(pkt[0:16], pkt[0:16])
			mac.Reset()
			mac.Write(pkt[0:16])
			if mode&ModeEncrypted != 0 {
				dec.CryptBlocks(pkt[16:32], pkt[16:32])
				mac.Write(pkt[16:32])
			}
			if subtle.ConstantTimeCompare(mac.Sum(nil)[:blockSize], pkt[32:48]) != 1 {
				continue
			}
		}

		var senderSeq uint32
		var sendTime, sendErr []byte
		switch mode {
		case ModeOpen, ModeMixed:
			senderSeq = binary.BigEndian.Uint32(pkt[0:4])
			sendTime, sendErr = pkt[4:12], pkt[12:14]
		default:
			senderSeq = binary.BigEndian.Uint32(pkt[0:4])
			sendTime, sendErr = pkt[16:24], pkt[24:26]
		}

		if r.dropEvery > 0 && (senderSeq+1)%r.dropEvery == 0 {
			continue
		}
		if r.procDelay > 0 {
			time.Sleep(r.procDelay)
		}

		copies := 1
		if r.dupEvery > 0 && (senderSeq+1)%r.dupEvery == 0 {
			copies = 2
		}

		for c := 0; c < copies; c++ {
			sendTS, _ := clock.Now()
			for j := range reply {
				reply[j] = 0
			}

			switch mode {
			case ModeOpen, ModeMixed:
				binary.BigEndian.PutUint32(reply[0:4], reflSeq)
				sendTS.EncodeTime(reply[4:12])
				sendTS.EncodeErrEstimate(reply[12:14])
				recvTS.EncodeTime(reply[16:24])
				binary.BigEndian.PutUint32(reply[24:28], senderSeq)
				copy(reply[28:36], sendTime)
				copy(reply[36:38], sendErr)
				reply[40] = 64 // TTL отправителя, каким его увидел отражатель
			default:
				for j := range clear96 {
					clear96[j] = 0
				}
				binary.BigEndian.PutUint32(clear96[0:4], reflSeq)
				sendTS.EncodeTime(clear96[16:24])
				sendTS.EncodeErrEstimate(clear96[24:26])
				recvTS.EncodeTime(clear96[32:40])
				binary.BigEndian.PutUint32(clear96[48:52], senderSeq)
				copy(clear96[64:72], sendTime)
				copy(clear96[72:74], sendErr)
				clear96[80] = 64

				mac.Reset()
				for j := range iv {
					iv[j] = 0
				}
				enc := cipher.NewCBCEncrypter(aesBlock, iv)
				enc.CryptBlocks(reply[0:16], clear96[0:16])
				mac.Write(clear96[0:16])
				if mode&ModeEncrypted != 0 {
					enc.CryptBlocks(reply[16:96], clear96[16:96])
					mac.Write(clear96[16:96])
				} else {
					copy(reply[16:96], clear96[16:96])
				}
				copy(reply[96:112], mac.Sum(nil)[:blockSize])
			}

			reflSeq++
			if _, err := udp.WriteToUDP(reply, from); err != nil {
				return
			}
		}
	}
}
