package owamp

import (
	"bytes"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// runSession полностью проводит клиентскую сессию против тестового
// отражателя и возвращает собранные записи.
func runSession(t *testing.T, r *testReflector, offered uint32, npackets uint32,
	interval float64) ([]TWDataRec, *Control, *Session) {
	t.Helper()
	return runSessionSlots(t, r, offered, npackets,
		[]Slot{{Type: SlotRandExp, Mean: Num64FromFloat(interval)}})
}

// runSessionSlots — то же, что runSession, но с явно заданным расписанием.
func runSessionSlots(t *testing.T, r *testReflector, offered uint32, npackets uint32,
	slots []Slot) ([]TWDataRec, *Control, *Session) {
	t.Helper()

	cfg := ControlConfig{
		Server:       r.Addr(),
		Network:      "tcp4",
		OfferedModes: offered,
		Identity:     r.identity,
		Passphrase:   r.passphrase,
		Timeout:      5 * time.Second,
	}
	cntrl, err := OpenControl(cfg)
	if err != nil {
		t.Fatalf("OpenControl: %v", err)
	}
	t.Cleanup(func() { cntrl.Close() })

	mode := cntrl.Mode()
	padding := TestTWPayloadSize(mode, 0) - TestPayloadSize(mode, 0)

	reflector := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	sess, err := NewSession(SessionConfig{
		Reflector:  reflector,
		LocalIP:    net.IPv4(127, 0, 0, 1),
		Clock:      Clock{Sync: true, ErrUsec: 100},
		SpinMargin: time.Millisecond,
	}, mode, padding)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	t.Cleanup(func() { sess.Close() })

	spec := TestSpec{
		NPackets:    npackets,
		Slots:       slots,
		StartTime:   Num64FromTime(time.Now().Add(200 * time.Millisecond)),
		LossTimeout: Num64FromFloat(0.75),
		Padding:     padding,
	}

	sid, port, err := cntrl.RequestTWSession(TWSessionRequest{
		Sender:      sess.LocalAddr(),
		Receiver:    reflector,
		StartTime:   spec.StartTime,
		LossTimeout: spec.LossTimeout,
		Padding:     spec.Padding,
	})
	if err != nil {
		t.Fatalf("RequestTWSession: %v", err)
	}
	reflector.Port = int(port)

	aesKey, hmacKey, err := cntrl.TestKeys(sid)
	if err != nil {
		t.Fatalf("TestKeys: %v", err)
	}
	if err := sess.SetKeys(aesKey, hmacKey); err != nil {
		t.Fatalf("SetKeys: %v", err)
	}
	if err := cntrl.StartSessions(); err != nil {
		t.Fatalf("StartSessions: %v", err)
	}

	var recs []TWDataRec
	err = sess.Run(spec, sid, func(rec *TWDataRec) error {
		recs = append(recs, *rec)
		return nil
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if err := cntrl.StopSessions(AcceptOK, 1); err != nil {
		t.Fatalf("StopSessions: %v", err)
	}
	return recs, cntrl, sess
}

func TestEndToEndOpenMode(t *testing.T) {
	r := newTestReflector(t, ModeOpen)
	recs, cntrl, _ := runSession(t, r, ModeOpen, 10, 0.01)

	if cntrl.Mode() != ModeOpen {
		t.Fatalf("согласован режим %s, ожидался открытый", ModeString(cntrl.Mode()))
	}
	if len(recs) != 10 {
		t.Fatalf("получено %d записей, ожидалось 10", len(recs))
	}
	for i, rec := range recs {
		if rec.Lost {
			t.Errorf("запись %d неожиданно помечена как потерянная", i)
			continue
		}
		if rec.Sent.SeqNo != uint32(i) {
			t.Errorf("у записи %d порядковый номер %d", i, rec.Sent.SeqNo)
		}
		rtt := Delay(rec.Sent.Send, rec.Reflected.Recv) - Delay(rec.Sent.Recv, rec.Reflected.Send)
		if rtt < 0 || rtt > 1 {
			t.Errorf("у записи %d неправдоподобное RTT: %v с", i, rtt)
		}
		if rec.Sent.TTL != 64 {
			t.Errorf("запись %d сообщает TTL отправителя %d, ожидалось 64", i, rec.Sent.TTL)
		}
	}
}

func TestEndToEndEncryptedModes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		modes uint32
		want  uint32
	}{
		{"encrypted", ModeEncrypted, ModeEncrypted},
		{"authenticated", ModeAuth, ModeAuth},
		{"mixed", ModeMixed, ModeMixed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newTestReflector(t, tc.modes)
			r.passphrase = []byte("correct horse battery staple")
			r.identity = "tester"

			recs, cntrl, _ := runSession(t, r, tc.modes, 8, 0.01)
			if cntrl.Mode() != tc.want {
				t.Fatalf("согласован режим %s, ожидался %s", ModeString(cntrl.Mode()), ModeString(tc.want))
			}
			if len(recs) != 8 {
				t.Fatalf("получено %d записей, ожидалось 8", len(recs))
			}
			lost := 0
			for _, rec := range recs {
				if rec.Lost {
					lost++
				}
			}
			if lost > 0 {
				t.Errorf("потеряно %d из %d пакетов на loopback в режиме %s", lost, len(recs), tc.name)
			}
		})
	}
}

func TestEndToEndLossAccounting(t *testing.T) {
	r := newTestReflector(t, ModeOpen)
	r.dropEvery = 3 // отбрасывать номера 2, 5, 8, ...

	recs, _, _ := runSession(t, r, ModeOpen, 9, 0.01)
	if len(recs) != 9 {
		t.Fatalf("получено %d записей, ожидалось 9", len(recs))
	}

	stats := newTestStats(t, 9)
	for i := range recs {
		if err := stats.Add(&recs[i]); err != nil {
			t.Fatalf("stats.Add: %v", err)
		}
	}
	if stats.sent != 9 {
		t.Errorf("отправлено = %d, ожидалось 9", stats.sent)
	}
	if stats.lost != 3 {
		t.Errorf("потеряно = %d, ожидалось 3", stats.lost)
	}

	// Записи выдаются в порядке завершения, поэтому ищем нужный порядковый
	// номер, а не обращаемся по индексу.
	lostSeqs := map[uint32]bool{}
	for _, rec := range recs {
		if rec.Lost {
			lostSeqs[rec.Sent.SeqNo] = true
		}
	}
	for _, seq := range []uint32{2, 5, 8} {
		if !lostSeqs[seq] {
			t.Errorf("номер %d должен быть помечен потерянным, набор потерь: %v", seq, lostSeqs)
		}
	}
}

func TestEndToEndDuplicateAccounting(t *testing.T) {
	r := newTestReflector(t, ModeOpen)
	r.dupEvery = 4 // отражать номера 3 и 7 дважды

	recs, _, _ := runSession(t, r, ModeOpen, 8, 0.01)

	stats := newTestStats(t, 8)
	for i := range recs {
		if err := stats.Add(&recs[i]); err != nil {
			t.Fatalf("stats.Add: %v", err)
		}
	}
	if stats.sent != 8 {
		t.Errorf("отправлено = %d, ожидалось 8", stats.sent)
	}
	if stats.lost != 0 {
		t.Errorf("потеряно = %d, ожидалось 0", stats.lost)
	}
	if total := stats.dupsFwd + stats.dupsBck; total != 2 {
		t.Errorf("подсчитано %d дубликатов, ожидалось 2 (fwd=%d bck=%d)",
			total, stats.dupsFwd, stats.dupsBck)
	}
}

func TestEndToEndProcessingDelay(t *testing.T) {
	r := newTestReflector(t, ModeOpen)
	r.procDelay = 20 * time.Millisecond

	// Отражатель обрабатывает пакеты последовательно, поэтому берём
	// фиксированный интервал, заметно превышающий procDelay. При
	// пуассоновском расписании короткие промежутки скапливались бы в
	// сокете отражателя и проявлялись бы как задержка до отражателя.
	recs, _, _ := runSessionSlots(t, r, ModeOpen, 5,
		[]Slot{{Type: SlotLiteral, Mean: Num64FromFloat(0.05)}})

	stats := newTestStats(t, 5)
	for i := range recs {
		if err := stats.Add(&recs[i]); err != nil {
			t.Fatalf("stats.Add: %v", err)
		}
	}
	// Собственная задержка отражателя должна попасть в набор задержек
	// обработки и быть вычтена из оценки кругового обхода.
	if got := stats.minDelay[DelayProc]; got < 0.015 || got > 0.1 {
		t.Errorf("минимальная задержка обработки = %v с, ожидалось ~0.02", got)
	}
	if got := stats.maxDelay[DelayRTT]; got > 0.015 {
		t.Errorf("RTT %v с всё ещё включает задержку обработки на отражателе", got)
	}
	if got := stats.maxDelay[DelayFwd]; got > 0.015 {
		t.Errorf("задержка до отражателя %v с указывает на постановку пакетов в очередь", got)
	}
}

func TestSummaryOutput(t *testing.T) {
	r := newTestReflector(t, ModeOpen)
	recs, _, _ := runSession(t, r, ModeOpen, 6, 0.01)

	stats := newTestStats(t, 6)
	for i := range recs {
		if err := stats.Add(&recs[i]); err != nil {
			t.Fatal(err)
		}
	}
	stats.SetFinished(true)

	// По умолчанию сводка печатается подписями оригинального twping: на них
	// рассчитаны инструменты, которые её разбирают.
	var human bytes.Buffer
	stats.PrintSummary(&human, []float64{95})
	out := human.String()
	for _, want := range []string{
		"--- twping statistics from",
		"SID:",
		"6 sent, 0 lost (0.000%)",
		"round-trip time min/median/max",
		"send time min/median/max",
		"reflect time min/median/max",
		"reflector processing time min/max",
		"two-way jitter",
		"Percentiles:",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("в английской сводке отсутствует %q\n---\n%s", want, out)
		}
	}

	// Русский вариант выбирается явно — его печатает сама утилита.
	var russian bytes.Buffer
	stats.PrintSummaryLang(&russian, []float64{95}, Russian)
	rout := russian.String()
	for _, want := range []string{
		"--- статистика twping от",
		"отправлено 6, потеряно 0 (0.000%)",
		"время кругового обхода мин/медиана/макс",
		"время до отражателя мин/медиана/макс",
		"время от отражателя мин/медиана/макс",
		"время обработки на отражателе мин/макс",
		"джиттер (двусторонний)",
		"Процентили:",
	} {
		if !strings.Contains(rout, want) {
			t.Errorf("в русской сводке отсутствует %q\n---\n%s", want, rout)
		}
	}

	var machine bytes.Buffer
	stats.PrintMachine(&machine)
	mout := machine.String()
	for _, want := range []string{
		"SUMMARY\t3.0", "SENT\t6", "LOST\t0", "SESSION_FINISHED\t1",
		"MIN\t", "MIN_FWD\t", "MIN_BCK\t", "MIN_PROC\t",
		"<BUCKETS>", "</BUCKETS>", "<TTLBUCKETS>",
	} {
		if !strings.Contains(mout, want) {
			t.Errorf("в машинной сводке отсутствует %q\n---\n%s", want, mout)
		}
	}
}

func TestRawRecordFormat(t *testing.T) {
	rec := TWDataRec{
		Sent: DataRec{
			SeqNo: 7,
			Send:  Timestamp{Time: Num64FromFloat(100), Sync: true, Scale: 8, Multiplier: 4},
			Recv:  Timestamp{Time: Num64FromFloat(100.1), Sync: true, Scale: 8, Multiplier: 4},
			TTL:   64,
		},
		Reflected: DataRec{
			SeqNo: 7,
			Send:  Timestamp{Time: Num64FromFloat(100.2), Sync: true, Scale: 8, Multiplier: 4},
			Recv:  Timestamp{Time: Num64FromFloat(100.3), Sync: true, Scale: 8, Multiplier: 4},
			TTL:   63,
		},
	}
	var buf bytes.Buffer
	if err := rec.WriteRaw(&buf); err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(strings.TrimSpace(buf.String()))
	if len(fields) != 16 {
		t.Fatalf("в сырой строке %d полей, ожидалось 16: %q", len(fields), buf.String())
	}
	if fields[0] != "7" || fields[8] != "7" {
		t.Errorf("sequence numbers not in fields 0 and 8: %v", fields)
	}
	if fields[7] != "64" || fields[15] != "63" {
		t.Errorf("TTLs not in fields 7 and 15: %v", fields)
	}
	if _, err := strconv.ParseUint(fields[1], 10, 64); err != nil {
		t.Errorf("field 1 is not a timestamp: %q", fields[1])
	}
}

func newTestStats(t *testing.T, npackets uint32) *Stats {
	t.Helper()
	s, err := NewStats(StatsConfig{
		FromHost: "127.0.0.1", FromServ: "1234",
		ToHost: "127.0.0.1", ToServ: "5678",
		Unit: 'm', BucketWidth: 0.0001, NPackets: npackets,
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestBadPassphraseIsRejected(t *testing.T) {
	r := newTestReflector(t, ModeEncrypted)
	r.passphrase = []byte("the real secret")

	_, err := OpenControl(ControlConfig{
		Server:       r.Addr(),
		Network:      "tcp4",
		OfferedModes: ModeEncrypted,
		Identity:     "tester",
		Passphrase:   []byte("the wrong secret"),
		Timeout:      5 * time.Second,
	})
	// Сервер закрывает соединение, как только проверка challenge не
	// проходит, поэтому клиент падает либо на ServerStart, либо на первом
	// запросе.
	if err == nil {
		t.Error("ожидался отказ при установлении связи с неверной парольной фразой")
	}
}

func TestNoMutualMode(t *testing.T) {
	r := newTestReflector(t, ModeOpen)
	_, err := OpenControl(ControlConfig{
		Server:       r.Addr(),
		Network:      "tcp4",
		OfferedModes: ModeEncrypted,
		Timeout:      5 * time.Second,
	})
	if err == nil {
		t.Fatal("ожидался сбой согласования режима")
	}
	if !strings.Contains(err.Error(), "нет общего поддерживаемого режима") {
		t.Errorf("неожиданная ошибка: %v", err)
	}
}
