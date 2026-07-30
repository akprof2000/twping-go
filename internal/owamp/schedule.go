package owamp

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// SlotType задаёт распределение слота расписания.
type SlotType uint8

const (
	SlotRandExp SlotType = 0
	SlotLiteral SlotType = 1
)

// Slot — одна запись расписания отправки TWAMP/OWAMP.
type Slot struct {
	Type SlotType
	// Mean — средний интервал между пакетами для SlotRandExp и фиксированное
	// смещение для SlotLiteral.
	Mean Num64
}

// Q[k] = сумма по i от 1 до k величин (ln2)^i / i!, умноженная на 2^32 и
// округлённая. Используется алгоритмом Кнута 3.4.1.S для генерации
// экспоненциально распределённых значений.
var expQ = [...]Num64{
	0, // заполнитель, чтобы индексы совпадали с алгоритмом
	0xB17217F8,
	0xEEF193F7,
	0xFD271862,
	0xFF9D6DD0,
	0xFFF4CFD0,
	0xFFFEE819,
	0xFFFFE7FF,
	0xFFFFFE2B,
	0xFFFFFFE0,
	0xFFFFFFFE,
	0xFFFFFFFF,
}

const ln2 = Num64(0xB17217F8)

// expRand — источник равномерных случайных чисел на AES в режиме счётчика,
// описанный в разделе 11.9 RFC 4656. Один блок AES даёт четыре 32-битных
// равномерно распределённых значения.
type expRand struct {
	block   cipher.Block
	counter [16]byte
	out     [16]byte
}

func newExpRand(seed []byte) (*expRand, error) {
	if len(seed) != 16 {
		return nil, fmt.Errorf("owamp: начальное значение расписания должно быть 16 байт, получено %d", len(seed))
	}
	b, err := aes.NewCipher(seed)
	if err != nil {
		return nil, err
	}
	return &expRand{block: b}, nil
}

// uniform возвращает 32-битную равномерно распределённую двоичную дробь
// в младшей половине Num64.
func (r *expRand) uniform() Num64 {
	quarter := r.counter[15] & 3
	if quarter == 0 {
		r.block.Encrypt(r.out[:], r.counter[:])
	}

	// Увеличиваем 128-битный счётчик в сетевом порядке байтов.
	for j := 15; j >= 0; j-- {
		r.counter[j]++
		if r.counter[j] != 0 {
			break
		}
	}

	buf := r.out[4*quarter : 4*quarter+4]
	var ret Num64
	for _, b := range buf {
		ret = ret<<8 + Num64(b)
	}
	return ret
}

// next возвращает экспоненциально распределённое значение с единичным средним
// (в единицах Num64).
func (r *expRand) next() Num64 {
	// S1: получаем U и сдвигаем, отбрасывая ведущие единицы вместе с первым
	// нулевым битом.
	u := r.uniform()
	j := uint32(0)
	for u&0x80000000 != 0 && j < 32 {
		u <<= 1
		j++
	}
	u <<= 1 // отбрасываем сам нулевой бит
	u &= 0xFFFFFFFF

	// S2: немедленное принятие.
	if u < ln2 {
		return Num64FromUint32(j).Mul(ln2) + u
	}

	// S3: минимизация.
	k := 2
	for ; k < len(expQ); k++ {
		if u < expQ[k] {
			break
		}
	}
	v := r.uniform()
	for i := 2; i <= k; i++ {
		if t := r.uniform(); t < v {
			v = t
		}
	}

	// S4: результат (j+V)*ln2.
	return (Num64FromUint32(j) + v).Mul(ln2)
}

// Schedule формирует последовательность интервалов между пакетами тестовой
// сессии.
type Schedule struct {
	rand  *expRand
	slots []Slot
	i     uint64
}

// NewSchedule создаёт расписание, инициализированное идентификатором сессии
// ровно так, как это делает owamp, поэтому обе стороны получают одну и ту же
// последовательность.
func NewSchedule(sid []byte, slots []Slot) (*Schedule, error) {
	if len(slots) == 0 {
		return nil, fmt.Errorf("owamp: расписанию нужен хотя бы один слот")
	}
	for _, s := range slots {
		if s.Type != SlotRandExp && s.Type != SlotLiteral {
			return nil, fmt.Errorf("owamp: недопустимый тип слота %d", s.Type)
		}
	}
	r, err := newExpRand(sid)
	if err != nil {
		return nil, err
	}
	return &Schedule{rand: r, slots: slots}, nil
}

// NextDelta возвращает задержку между предыдущим и следующим пакетом.
func (s *Schedule) NextDelta() Num64 {
	slot := s.slots[s.i%uint64(len(s.slots))]
	s.i++
	switch slot.Type {
	case SlotLiteral:
		return slot.Mean
	default:
		return s.rand.next().Mul(slot.Mean)
	}
}

// PacketRate возвращает среднее число пакетов в секунду, задаваемое слотами.
func PacketRate(slots []Slot) float64 {
	var total Num64
	for _, s := range slots {
		total += s.Mean
	}
	if total == 0 {
		return 0
	}
	return float64(len(slots)) / total.Float()
}
