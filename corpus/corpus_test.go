package corpus

import (
	"encoding/json"
	"math"
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
		"lookup-then-contact":    {Signature: "lookup-then-contact", Attacks: 3, Benign: 3, TP: 3, FP: 1, Recall: 1.0, FPRate: 1.0 / 3.0},
		"manufactured-consensus": {Signature: "manufactured-consensus", Attacks: 3, Benign: 4, TP: 3, FP: 1, Recall: 1.0, FPRate: 0.25},
		"ingest-then-deviate":    {Signature: "ingest-then-deviate", Attacks: 3, Benign: 4, TP: 3, FP: 3, Recall: 1.0, FPRate: 0.75},
		"tool-definition-change": {Signature: "tool-definition-change", Attacks: 3, Benign: 3, TP: 3, FP: 0, Recall: 1.0, FPRate: 0.0},
		"tool-shadowing":         {Signature: "tool-shadowing", Attacks: 3, Benign: 3, TP: 3, FP: 0, Recall: 1.0, FPRate: 0.0},
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
		if m.Attacks != w.Attacks || m.Benign != w.Benign || m.TP != w.TP || m.FP != w.FP {
			t.Fatalf("%s counts: want %+v, got %+v", m.Signature, w, m)
		}
		if math.Abs(m.Recall-w.Recall) > 1e-9 || math.Abs(m.FPRate-w.FPRate) > 1e-9 {
			t.Fatalf("%s rates: want recall %.4f fp %.4f, got recall %.4f fp %.4f", m.Signature, w.Recall, w.FPRate, m.Recall, m.FPRate)
		}
	}
}
