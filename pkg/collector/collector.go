package collector

import "time"

// Collector is the interface for collecting sandbox violations
type Collector interface {
	CollectViolations(since time.Duration) ([]Violation, error)
}
