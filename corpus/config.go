package corpus

import "github.com/0x71pp17/agent-trace-detections/monitor"

// FixtureMonitor is the monitor configuration the checked-in fixture corpus is
// scored under. The budget threshold and the tool baseline are set to the values
// learned from the corpus's benign cases (max benign call count, and each tool's
// benign reach), which is how these parameters are meant to be supplied in
// practice: learned offline from benign traffic.
func FixtureMonitor() *monitor.Monitor {
	return monitor.New(
		monitor.NewWriteThenExec,
		monitor.NewBudgetSpike(5, nil),
		monitor.NewToolDefinitionChange(map[string][]string{"fetch": {"api.internal"}}),
	)
}
