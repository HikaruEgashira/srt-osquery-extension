//go:build darwin

package collector

import (
	"bufio"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

var (
	// Example log line:
	// 2025-11-03 16:25:43.448666+0900  localhost kernel[0]: (Sandbox) Sandbox: cat(13276) deny(1) file-read-data /Users/hikae/.ssh/config
	sandboxPattern   = regexp.MustCompile(`Sandbox:\s+(\w+)\((\d+)\)\s+deny\((\d+)\)\s+([\w-]+)\s+(.+)$`)
	timestampPattern = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+[+-]\d{4})`)
)

type DarwinCollector struct{}

func NewCollector() Collector {
	return &DarwinCollector{}
}

// CollectViolations collects sandbox violations from macOS unified logging system
func (c *DarwinCollector) CollectViolations(since time.Duration) ([]Violation, error) {
	// Convert duration to a format log show understands
	sinceStr := fmt.Sprintf("%.0fm", since.Minutes())

	// Use log show to get past logs
	// Predicate filters for sandbox violations
	cmd := exec.Command("log", "show",
		"--predicate", `eventMessage CONTAINS "Sandbox:" AND eventMessage CONTAINS "deny"`,
		"--style", "syslog",
		"--last", sinceStr,
	)

	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to execute log show: %w", err)
	}

	return parseLogOutput(string(output))
}

func parseLogOutput(output string) ([]Violation, error) {
	var violations []Violation
	scanner := bufio.NewScanner(strings.NewReader(output))

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "Sandbox:") {
			continue
		}

		violation := parseViolation(line)
		if violation != nil {
			violations = append(violations, *violation)
		}
	}

	if err := scanner.Err(); err != nil {
		return violations, fmt.Errorf("error scanning log output: %w", err)
	}

	return violations, nil
}

// parseViolation parses a macOS sandbox violation log line
func parseViolation(line string) *Violation {
	// Extract timestamp
	var timestamp time.Time
	if tsMatch := timestampPattern.FindStringSubmatch(line); len(tsMatch) > 1 {
		// Try to parse the timestamp
		t, err := time.Parse("2006-01-02 15:04:05.999999-0700", tsMatch[1])
		if err == nil {
			timestamp = t
		}
	}

	// If timestamp parsing failed, use current time
	if timestamp.IsZero() {
		timestamp = time.Now()
	}

	// Extract sandbox violation details
	matches := sandboxPattern.FindStringSubmatch(line)
	if len(matches) != 6 {
		return nil // Not a sandbox violation line
	}

	return &Violation{
		Timestamp:   timestamp,
		ProcessName: matches[1],
		ProcessID:   matches[2],
		DenyCode:    matches[3],
		Operation:   matches[4],
		TargetPath:  strings.TrimSpace(matches[5]),
		RawLine:     line,
	}
}
