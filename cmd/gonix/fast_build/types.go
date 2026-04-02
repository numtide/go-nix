package fast_build

type EvalJob struct {
	Attr    string            `json:"attr"`
	DrvPath string            `json:"drvPath,omitempty"`
	Name    string            `json:"name,omitempty"`
	Outputs map[string]string `json:"outputs,omitempty"`
	System  string            `json:"system,omitempty"`
	Error   string            `json:"error,omitempty"`
}

type BuildOutput struct {
	Attr      string            `json:"attr"`
	DrvPath   string            `json:"drvPath"`
	Status    string            `json:"status"`
	Error     string            `json:"error,omitempty"`
	StartTime uint64            `json:"startTime,omitempty"`
	StopTime  uint64            `json:"stopTime,omitempty"`
	Outputs   map[string]string `json:"outputs,omitempty"`
}
