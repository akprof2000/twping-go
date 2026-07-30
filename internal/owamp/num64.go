package owamp

import "time"

// Num64 — представление времени с фиксированной точкой из OWAMP/TWAMP:
// старшие 32 бита хранят секунды, младшие 32 бита — дробную часть секунды
// с разрешением 2^-32 с.
type Num64 uint64

// JAN1970 — число секунд между эпохой NTP (1900-01-01) и эпохой UNIX
// (1970-01-01).
const JAN1970 = 2208988800

// Num64FromUint32 помещает целое число секунд в Num64.
func Num64FromUint32(v uint32) Num64 { return Num64(uint64(v) << 32) }

// Num64FromFloat преобразует секунды, заданные числом с плавающей точкой,
// в Num64.
func Num64FromFloat(d float64) Num64 {
	if d <= 0 {
		return 0
	}
	sec := uint64(d)
	frac := uint64((d - float64(sec)) * (1 << 32))
	return Num64(sec<<32 | (frac & 0xFFFFFFFF))
}

// Float возвращает значение Num64 в секундах.
func (n Num64) Float() float64 {
	return float64(n>>32) + float64(n&0xFFFFFFFF)/(1<<32)
}

// Duration преобразует *относительное* значение Num64 в time.Duration.
func (n Num64) Duration() time.Duration {
	sec := time.Duration(n>>32) * time.Second
	// (frac * 1e9) >> 32 — вычисляется в 64 битах без переполнения,
	// поскольку frac < 2^32.
	nsec := time.Duration((uint64(n&0xFFFFFFFF) * 1e9) >> 32)
	return sec + nsec
}

// Num64FromDuration преобразует относительный интервал в Num64.
func Num64FromDuration(d time.Duration) Num64 {
	if d < 0 {
		return 0
	}
	sec := uint64(d / time.Second)
	nsec := uint64(d % time.Second)
	return Num64(sec<<32 | ((nsec << 32) / 1e9))
}

// Num64FromUsec преобразует микросекунды в Num64.
func Num64FromUsec(usec uint32) Num64 {
	sec := uint64(usec) / 1e6
	rem := uint64(usec) % 1e6
	return Num64(sec<<32 | ((rem << 32) / 1e6))
}

// Mul умножает два значения Num64, сохраняя выравнивание 32.32. Реализация
// повторяет алгоритм 4.3.1.M Кнута (том 2), используемый в owamp, поэтому
// сформированные здесь расписания побитово совпадают с расписаниями
// реализации на C.
func (n Num64) Mul(y Num64) Num64 {
	var w [4]uint64
	x0 := uint64(n) & 0xFFFFFFFF
	x1 := uint64(n>>32) & 0xFFFFFFFF
	y0 := uint64(y) & 0xFFFFFFFF
	y1 := uint64(y>>32) & 0xFFFFFFFF

	xd := [2]uint64{x0, x1}
	yd := [2]uint64{y0, y1}

	for j := 0; j < 2; j++ {
		var k uint64
		for i := 0; i < 2; i++ {
			t := k + xd[i]*yd[j] + w[i+j]
			w[i+j] = t & 0xFFFFFFFF
			k = t >> 32
		}
		w[j+2] = k
	}

	return Num64(w[2]<<32 | w[1])
}

// AbsTime преобразует абсолютное значение Num64 (эпоха NTP) во время Go.
func (n Num64) AbsTime() time.Time {
	sec := int64(n>>32) - JAN1970
	nsec := int64((uint64(n&0xFFFFFFFF) * 1e9) >> 32)
	return time.Unix(sec, nsec)
}

// Num64FromTime преобразует время настенных часов в абсолютное значение Num64
// (эпоха NTP).
func Num64FromTime(t time.Time) Num64 {
	sec := uint64(t.Unix() + JAN1970)
	nsec := uint64(t.Nanosecond())
	return Num64(sec<<32 | ((nsec << 32) / 1e9))
}
