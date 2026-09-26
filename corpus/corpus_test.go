package corpus

import (
	"encoding/json"
	"os"
	"testing"
)

func load(t *testing.T) Corpus {
	t.Helper()
	data, err := os.ReadFile("testdata/fixtures.json")
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	var c Corpus
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatalf("parse corpus: %v", err)
	}
	return c
}

func TestFixtureMetrics(t *testing.T) {
	got := Score(load(t), FixtureMonitor())
	want := map[string]Metrics{
		"budget-spike":           {Signature: "budget-spike", Attacks: 3, Benign: 3, TP: 3, FP: 0, Recall: 1.0, FPRate: 0.0},
		"tool-definition-change": {Signature: "tool-definition-change", Attacks: 3, Benign: 3, TP: 3, FP: 0, Recall: 1.0, FPRate: 0.0},
		"write-then-exec":        {Signature: "write-then-exec", Attacks: 3, Benign: 6, TP: 3, FP: 3, Recall: 1.0, FPRate: 0.5},
	}
	if len(got) != len(want) {
		t.Fatalf("want %d signatures, got %d", len(want), len(got))
	}
	for _, m := range got {
		w, ok := want[m.Signature]
		if !ok {
			t.Fatalf("unexpected signature %s", m.Signature)
		}
		if m != w {
			t.Fatalf("%s: want %+v, got %+v", m.Signature, w, m)
		}
	}
}
