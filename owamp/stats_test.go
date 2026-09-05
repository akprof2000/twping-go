package owamp

import (
	"bytes"
	"strings"
	"testing"
)

// mkRec собирает запись об отвеченном пакете с заданными номерами и TTL.
func mkRec(seq uint32, reflTTL uint8) *TWDataRec {
	ts := func(sec float64) Timestamp {
		return Timestamp{Time: Num64FromFloat(sec), Sync: true, Scale: 8, Multiplier: 4}
	}
	base := 100 + float64(seq)*0.01
	return &TWDataRec{
		Sent:      DataRec{SeqNo: seq, Send: ts(base), Recv: ts(base + 0.001), TTL: 64},
		Reflected: DataRec{SeqNo: seq, Send: ts(base + 0.002), Recv: ts(base + 0.003), TTL: reflTTL},
	}
}

func mkLost(seq uint32) *TWDataRec {
	return lostRecord(seq, Num64FromFloat(100+float64(seq)*0.01+0.75).AbsTime(), Clock{})
}

// Записи приходят в порядке завершения: потерянный пакет попадает в поток
// позже отвеченных за ним. Диапазон номеров от этого зависеть не должен.
func TestStatsSeqRangeIgnoresArrivalOrder(t *testing.T) {
	s := newTestStats(t, 4)
	for _, rec := range []*TWDataRec{mkRec(1, 63), mkRec(3, 63), mkLost(2), mkLost(0)} {
		if err := s.Add(rec); err != nil {
			t.Fatal(err)
		}
	}
	if s.first != 0 || s.last != 4 {
		t.Errorf("диапазон номеров [%d, %d), ожидалось [0, 4)", s.first, s.last)
	}
	var out bytes.Buffer
	s.PrintMachine(&out)
	if !strings.Contains(out.String(), "SAMPLE_PACKET_COUNT\t4\n") {
		t.Errorf("SAMPLE_PACKET_COUNT должен быть 4:\n%s", out.String())
	}
}

func TestStatsNoReflectedTTL(t *testing.T) {
	cfg := StatsConfig{
		FromHost: "a", FromServ: "1", ToHost: "b", ToServ: "2",
		Unit: 'm', BucketWidth: 0.0001, NPackets: 2,
		NoReflectedTTL: true,
	}
	s, err := NewStats(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Без чтения принятого TTL сессия подставляет 255.
	for _, rec := range []*TWDataRec{mkRec(0, 255), mkRec(1, 255)} {
		if err := s.Add(rec); err != nil {
			t.Fatal(err)
		}
	}
	var out bytes.Buffer
	s.PrintSummary(&out, nil)
	got := out.String()
	if !strings.Contains(got, "reflect TTL not reported") {
		t.Errorf("при недоступном TTL ожидалось «reflect TTL not reported»:\n%s", got)
	}
	if !strings.Contains(got, "send hops = 191 (consistently)") {
		t.Errorf("число хопов до отражателя должно считаться по-прежнему:\n%s", got)
	}
}

func TestStatsRecordOutputLanguage(t *testing.T) {
	for _, tc := range []struct {
		lang      Language
		unit, los string
	}{
		{English, " ms ", "*LOST*"},
		{Russian, " мс ", "*ПОТЕРЯН*"},
	} {
		var lines bytes.Buffer
		s, err := NewStats(StatsConfig{
			FromHost: "a", FromServ: "1", ToHost: "b", ToServ: "2",
			Unit: 'm', BucketWidth: 0.0001, NPackets: 2,
			RecordOutput: &lines, Language: tc.lang,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Add(mkRec(0, 63)); err != nil {
			t.Fatal(err)
		}
		if err := s.Add(mkLost(1)); err != nil {
			t.Fatal(err)
		}
		got := lines.String()
		if !strings.Contains(got, tc.unit) || !strings.Contains(got, tc.los) {
			t.Errorf("язык %d: в построчном выводе нет %q или %q:\n%s", tc.lang, tc.unit, tc.los, got)
		}
	}
}

func TestParsePercentiles(t *testing.T) {
	got, err := ParsePercentiles("99, 50,95.5")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0] != 50 || got[1] != 95.5 || got[2] != 99 {
		t.Errorf("ParsePercentiles = %v, ожидалось [50 95.5 99]", got)
	}
	for _, bad := range []string{"95abc", "101", "-1", "nan"} {
		if _, err := ParsePercentiles(bad); err == nil {
			t.Errorf("ParsePercentiles(%q) принял недопустимое значение", bad)
		}
	}
}
