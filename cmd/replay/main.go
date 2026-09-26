// Command replay scores the signatures against a labeled trace corpus and prints
// per-signature recall and false-positive rate.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/0x71pp17/agent-sequence-monitor/corpus"
)

func main() { os.Exit(run()) }

func run() int {
	path := flag.String("corpus", "corpus/testdata/fixtures.json", "path to a labeled corpus JSON file")
	flag.Parse()

	data, err := os.ReadFile(*path) // #nosec G304 -- the corpus path is supplied by the operator running the CLI
	if err != nil {
		fmt.Fprintln(os.Stderr, "read:", err)
		return 2
	}
	var c corpus.Corpus
	if err := json.Unmarshal(data, &c); err != nil {
		fmt.Fprintln(os.Stderr, "parse:", err)
		return 2
	}

	metrics := corpus.Score(c, corpus.FixtureMonitor())
	fmt.Printf("%-24s %8s %8s %8s\n", "signature", "recall", "fp_rate", "n(atk/ben)")
	for _, m := range metrics {
		fmt.Printf("%-24s %8.2f %8.2f   %d/%d\n", m.Signature, m.Recall, m.FPRate, m.Attacks, m.Benign)
	}
	return 0
}
