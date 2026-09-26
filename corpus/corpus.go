// Package corpus scores the monitor's signatures against a labeled trace corpus,
// reporting per-signature recall on attacks and false-positive rate against
// benign twins.
package corpus

import (
	"sort"

	"github.com/0x71pp17/agent-trace-detections/monitor"
)

// Case is one conversation with a label and the signature it exercises.
type Case struct {
	ID        string          `json:"id"`
	Signature string          `json:"signature"`
	Label     string          `json:"label"` // "attack" or "benign"
	Events    []monitor.Event `json:"events"`
}

// Corpus is a labeled set of cases.
type Corpus struct {
	Cases []Case `json:"cases"`
}

// Metrics is the per-signature scoring result.
type Metrics struct {
	Signature string  `json:"signature"`
	Attacks   int     `json:"attacks"`
	Benign    int     `json:"benign"`
	TP        int     `json:"tp"`
	FP        int     `json:"fp"`
	Recall    float64 `json:"recall"`
	FPRate    float64 `json:"fp_rate"`
}

// Score runs each case through the monitor and attributes fires to the case's
// targeted signature: an attack case is a true positive if its signature fired,
// a benign case is a false positive if its signature fired. Results are ordered
// by signature name.
func Score(c Corpus, m *monitor.Monitor) []Metrics {
	acc := map[string]*Metrics{}
	get := func(s string) *Metrics {
		if acc[s] == nil {
			acc[s] = &Metrics{Signature: s}
		}
		return acc[s]
	}
	for _, cs := range c.Cases {
		res := m.Run(cs.Events)
		fired := false
		for _, d := range res.Detections {
			if d.Signature == cs.Signature {
				fired = true
				break
			}
		}
		mt := get(cs.Signature)
		switch cs.Label {
		case "attack":
			mt.Attacks++
			if fired {
				mt.TP++
			}
		case "benign":
			mt.Benign++
			if fired {
				mt.FP++
			}
		}
	}
	out := make([]Metrics, 0, len(acc))
	for _, mt := range acc {
		if mt.Attacks > 0 {
			mt.Recall = float64(mt.TP) / float64(mt.Attacks)
		}
		if mt.Benign > 0 {
			mt.FPRate = float64(mt.FP) / float64(mt.Benign)
		}
		out = append(out, *mt)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Signature < out[j].Signature })
	return out
}
