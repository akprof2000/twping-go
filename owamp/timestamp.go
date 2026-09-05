package owamp

import (
	"encoding/binary"
	"time"
)

// Timestamp — метка времени OWAMP вместе с оценкой её погрешности.
type Timestamp struct {
	Time       Num64
	Sync       bool
	Scale      uint8 // 6 бит
	Multiplier uint8
}

// EncodeTime записывает 8-октетное поле метки времени.
func (t Timestamp) EncodeTime(buf []byte) {
	binary.BigEndian.PutUint32(buf[0:4], uint32(t.Time>>32))
	binary.BigEndian.PutUint32(buf[4:8], uint32(t.Time&0xFFFFFFFF))
}

// EncodeErrEstimate записывает 2-октетное поле оценки погрешности. Возвращает
// false, если оценка недопустима (нулевой множитель): так же, как реализация на
// C, мы отказываемся кодировать такое значение.
func (t Timestamp) EncodeErrEstimate(buf []byte) bool {
	if t.Multiplier == 0 {
		return false
	}
	buf[0] = t.Scale & 0x3F
	if t.Sync {
		buf[0] |= 0x80
	}
	buf[1] = t.Multiplier
	return true
}

// DecodeTimestamp читает 8-октетную метку времени и 2-октетную оценку
// погрешности. Возвращает false, если оценка погрешности недопустима.
func DecodeTimestamp(tbuf, ebuf []byte) (Timestamp, bool) {
	var t Timestamp
	t.Time = Num64(uint64(binary.BigEndian.Uint32(tbuf[0:4]))<<32 |
		uint64(binary.BigEndian.Uint32(tbuf[4:8])))

	b0, b1 := ebuf[0], ebuf[1]
	if b1 == 0 {
		b0 = 0
	}
	t.Sync = b0&0x80 != 0
	t.Scale = b0 & 0x3F
	t.Multiplier = b1
	return t, b1 != 0
}

// ErrEstimate возвращает закодированную оценку погрешности в секундах.
func (t Timestamp) ErrEstimate() float64 {
	err := Num64(t.Multiplier) << (t.Scale & 0x3F)
	return err.Float()
}

// SetErrEstimate кодирует errUsec (микросекунды) в поля scale и multiplier тем
// же циклом сдвигов с округлением, что и owamp.
func (t *Timestamp) SetErrEstimate(errUsec uint32) {
	if errUsec == 0 {
		t.Sync = false
		t.Scale = 64 & 0x3F
		t.Multiplier = 1
		return
	}
	err := uint64(Num64FromUsec(errUsec))
	t.Scale = 0
	for err >= 0xFF {
		err >>= 1
		t.Scale++
	}
	err++ // округление: учитывает сдвинутые за границу биты
	t.Multiplier = uint8(err & 0xFF)
}

// Delay возвращает задержку в секундах между двумя метками времени; значение
// может быть отрицательным.
func Delay(from, to Timestamp) float64 {
	if to.Time >= from.Time {
		return (to.Time - from.Time).Float()
	}
	return -(from.Time - to.Time).Float()
}

// Clock читает локальные часы и формирует метки времени OWAMP. Утверждение о
// синхронизации задаёт вызывающая сторона: в Go нет переносимого способа
// узнать оценку погрешности у локального демона NTP.
type Clock struct {
	Sync    bool
	ErrUsec uint32
}

// Now возвращает текущее время как Timestamp.
func (c Clock) Now() (Timestamp, time.Time) {
	wall := time.Now()
	return c.StampAt(wall), wall
}

// StampAt формирует Timestamp для уже снятого значения настенных часов.
// Нулевая оценка погрешности означает несинхронизированные часы: SetErrEstimate
// сам снимает признак Sync.
func (c Clock) StampAt(wall time.Time) Timestamp {
	ts := Timestamp{Time: Num64FromTime(wall), Sync: c.Sync}
	ts.SetErrEstimate(c.ErrUsec)
	return ts
}
