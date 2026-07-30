package owamp

import (
	"math"
	"testing"
)

func TestScheduleDeterministic(t *testing.T) {
	sid := []byte("0123456789abcdef")
	a, err := NewSchedule(sid, []Slot{{Type: SlotRandExp, Mean: Num64FromFloat(0.1)}})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := NewSchedule(sid, []Slot{{Type: SlotRandExp, Mean: Num64FromFloat(0.1)}})

	for i := 0; i < 100; i++ {
		if x, y := a.NextDelta(), b.NextDelta(); x != y {
			t.Fatalf("delta %d differs between identically seeded schedules: %d vs %d", i, x, y)
		}
	}
}

func TestScheduleDiffersBySID(t *testing.T) {
	slots := []Slot{{Type: SlotRandExp, Mean: Num64FromFloat(0.1)}}
	a, _ := NewSchedule([]byte("0123456789abcdef"), slots)
	b, _ := NewSchedule([]byte("fedcba9876543210"), slots)
	same := 0
	for i := 0; i < 20; i++ {
		if a.NextDelta() == b.NextDelta() {
			same++
		}
	}
	if same > 2 {
		t.Errorf("%d/20 deltas identical across different SIDs", same)
	}
}

// Порождаемые интервалы должны быть распределены экспоненциально с заданным
// средним: именно на это свойство опирается пуассоновская выборка TWAMP.
func TestScheduleExponentialMean(t *testing.T) {
	const mean = 0.1
	const n = 200000
	s, err := NewSchedule([]byte("seed-for-exp-1234"[:16]),
		[]Slot{{Type: SlotRandExp, Mean: Num64FromFloat(mean)}})
	if err != nil {
		t.Fatal(err)
	}

	var sum, sumSq float64
	for i := 0; i < n; i++ {
		d := s.NextDelta().Float()
		if d < 0 {
			t.Fatalf("negative delta %v", d)
		}
		sum += d
		sumSq += d * d
	}
	got := sum / n
	if math.Abs(got-mean)/mean > 0.02 {
		t.Errorf("выборочное среднее %v отличается от %v более чем на 2%%", got, mean)
	}
	// У экспоненциального распределения стандартное отклонение равно среднему.
	sd := math.Sqrt(sumSq/n - got*got)
	if math.Abs(sd-mean)/mean > 0.05 {
		t.Errorf("sample sd %v differs from %v by more than 5%%", sd, mean)
	}
}

func TestScheduleLiteralSlots(t *testing.T) {
	s, err := NewSchedule([]byte("0123456789abcdef"), []Slot{
		{Type: SlotLiteral, Mean: Num64FromFloat(0.25)},
		{Type: SlotLiteral, Mean: Num64FromFloat(0.75)},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []float64{0.25, 0.75, 0.25, 0.75}
	for i, w := range want {
		if got := s.NextDelta().Float(); math.Abs(got-w) > 1e-9 {
			t.Errorf("интервал %d = %v, ожидалось %v", i, got, w)
		}
	}
}

func TestPacketRate(t *testing.T) {
	if got := PacketRate([]Slot{{Mean: Num64FromFloat(0.1)}}); math.Abs(got-10) > 1e-6 {
		t.Errorf("PacketRate = %v, ожидалось 10", got)
	}
}

func TestPayloadSizes(t *testing.T) {
	cases := []struct {
		mode       uint32
		send, refl uint32
	}{
		{ModeOpen, 14, 41},
		{ModeMixed, 14, 41},
		{ModeAuth, 48, 112},
		{ModeEncrypted, 48, 112},
	}
	for _, c := range cases {
		if got := TestPayloadSize(c.mode, 0); got != c.send {
			t.Errorf("TestPayloadSize(%s) = %d, ожидалось %d", ModeString(c.mode), got, c.send)
		}
		if got := TestTWPayloadSize(c.mode, 0); got != c.refl {
			t.Errorf("TestTWPayloadSize(%s) = %d, ожидалось %d", ModeString(c.mode), got, c.refl)
		}
	}
}

func TestSelectModePrefersStrongest(t *testing.T) {
	m, err := selectMode(ModeOpen|ModeAuth|ModeEncrypted|ModeMixed, TWPDefaultOfferedMode)
	if err != nil {
		t.Fatal(err)
	}
	if m != ModeEncrypted {
		t.Errorf("выбран режим %s, ожидался шифрованный", ModeString(m))
	}

	if m, err = selectMode(ModeOpen, ModeOpen); err != nil || m != ModeOpen {
		t.Errorf("selectMode(open, open) = %s, %v", ModeString(m), err)
	}
	if _, err = selectMode(ModeOpen, ModeEncrypted); err == nil {
		t.Error("ожидалась ошибка при отсутствии общего поддерживаемого режима")
	}
}
