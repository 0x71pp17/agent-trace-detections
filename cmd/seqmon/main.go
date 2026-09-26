// Command seqmon reads agent-trace events as JSON and reports detections. It
// exits non-zero when it finds any, so it can gate a pipeline.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/0x71pp17/agent-trace-detections/monitor"
)

func main() { os.Exit(run()) }

func run() int {
	in := flag.String("in", "-", "input file of JSON events, or - for stdin")
	flag.Parse()

	var r io.Reader = os.Stdin
	if *in != "-" {
		f, err := os.Open(*in) // #nosec G304 -- the input path is supplied by the operator running the CLI
		if err != nil {
			fmt.Fprintln(os.Stderr, "open:", err)
			return 2
		}
		defer func() { _ = f.Close() }()
		r = f
	}

	data, err := io.ReadAll(r)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read:", err)
		return 2
	}

	var events []monitor.Event
	if err := json.Unmarshal(data, &events); err != nil {
		fmt.Fprintln(os.Stderr, "parse:", err)
		return 2
	}

	res := monitor.New(monitor.NewWriteThenExec, monitor.NewLookupThenContact, monitor.NewIngestThenDeviate, monitor.NewProvenanceLaundering).
		WithCrossSession(monitor.NewMemoryPersistThenActivate).
		Run(events)
	out, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "encode:", err)
		return 2
	}
	fmt.Println(string(out))
	if len(res.Detections) > 0 {
		return 1
	}
	return 0
}
