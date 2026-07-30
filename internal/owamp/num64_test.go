package owamp

import (
	"math"
	"testing"
	"time"
)

func TestNum64RoundTrip(t *testing.T) {
	for _, d := range []float64{0.0001, 0.1, 1, 1.5, 2.25, 100.125} {
		n := Num64FromFloat(d)
		if got := n.Float(); math.Abs(got-d) > 1e-9 {
			t.Errorf("Num64FromFloat(%v).Float() = %v", d, got)
		}
	}
}

func TestNum64Mul(t *testing.T) {
	// 1.5 * 2 == 3
	got := Num64FromFloat(1.5).Mul(Num64FromUint32(2)).Float()
	if math.Abs(got-3) > 1e-9 {
		t.Errorf("1.5*2 = %v, ожидалось 3", got)
	}
	// ln2 * 1 == ln2
	got = ln2.Mul(Num64FromUint32(1)).Float()
	if math.Abs(got-math.Ln2) > 1e-9 {
		t.Errorf("ln2 = %v, ожидалось %v", got, math.Ln2)
	}
}

func TestNum64Duration(t *testing.T) {
	n := Num64FromDuration(1500 * time.Millisecond)
	if d := n.Duration(); math.Abs(d.Seconds()-1.5) > 1e-6 {
		t.Errorf("round trip 1.5s -> %v", d)
	}
}

func TestNum64TimeRoundTrip(t *testing.T) {
	now := time.Now()
	got := Num64FromTime(now).AbsTime()
	if diff := got.Sub(now); diff > time.Microsecond || diff < -time.Microsecond {
		t.Errorf("time round trip drifted by %v", diff)
	}
}

func TestTimestampErrEstimate(t *testing.T) {
	var ts Timestamp
	ts.SetErrEstimate(1000) // 1 ms
	err := ts.ErrEstimate()
	if err < 1e-3 || err > 2e-3 {
		t.Errorf("оценка погрешности 1 мс закодирована как %v с", err)
	}

	var buf [2]byte
	ts.Sync = true
	if !ts.EncodeErrEstimate(buf[:]) {
		t.Fatal("EncodeErrEstimate отклонил корректную оценку")
	}
	var tbuf [8]byte
	ts.Time = Num64FromFloat(12.5)
	ts.EncodeTime(tbuf[:])

	got, ok := DecodeTimestamp(tbuf[:], buf[:])
	if !ok {
		t.Fatal("DecodeTimestamp rejected a valid estimate")
	}
	if got.Time != ts.Time || !got.Sync || got.Scale != ts.Scale || got.Multiplier != ts.Multiplier {
		t.Errorf("метка времени не совпала после кодирования и разбора: %+v против %+v", got, ts)
	}
}

func TestTimestampInvalidErrEstimate(t *testing.T) {
	var ts Timestamp // multiplier 0
	var buf [2]byte
	if ts.EncodeErrEstimate(buf[:]) {
		t.Error("закодирована недопустимая оценка с нулевым множителем")
	}
	if _, ok := DecodeTimestamp(make([]byte, 8), []byte{0x80, 0}); ok {
		t.Error("accepted a zero multiplier on decode")
	}
}

func TestDelaySignedness(t *testing.T) {
	a := Timestamp{Time: Num64FromFloat(10)}
	b := Timestamp{Time: Num64FromFloat(11)}
	if d := Delay(a, b); math.Abs(d-1) > 1e-9 {
		t.Errorf("Delay(a,b) = %v, ожидалось 1", d)
	}
	if d := Delay(b, a); math.Abs(d+1) > 1e-9 {
		t.Errorf("Delay(b,a) = %v, ожидалось -1", d)
	}
}
