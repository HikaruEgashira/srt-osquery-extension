package collector

import "time"

// Violation represents a sandbox violation event
type Violation struct {
	Timestamp   time.Time
	ProcessName string
	ProcessID   string
	Operation   string
	TargetPath  string
	DenyCode    string
	RawLine     string
}
