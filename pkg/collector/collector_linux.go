//go:build linux

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
	// Example journalctl line with bubblewrap error:
	// Nov 03 16:25:43 hostname bwrap[12345]: Permission denied: /path/to/file
	journalPattern = regexp.MustCompile(`^(\w+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+(\w+)\[(\d+)\]:\s+(.+)$`)
	bwrapPattern   = regexp.MustCompile(`(?i)(permission denied|eperm|access denied|denied).*?([/\w\-\.]+)`)
)

type LinuxCollector struct{}

func NewCollector() Collector {
	return &LinuxCollector{}
}

// CollectViolations collects sandbox violations from journalctl
func (c *LinuxCollector) CollectViolations(since time.Duration) ([]Violation, error) {
	// Format: "1 hour ago", "30 minutes ago", etc.
	sinceStr := formatDuration(since)

	// Use journalctl to get logs related to bubblewrap
	cmd := exec.Command("journalctl",
		"--since", sinceStr,
		"--no-pager",
		"-o", "short",
	)

	output, err := cmd.Output()
	if err != nil {
		// journalctl might not be available or require permissions
		// Try dmesg as fallback
		return c.collectFromDmesg()
	}

	return parseJournalOutput(string(output))
}

func (c *LinuxCollector) collectFromDmesg() ([]Violation, error) {
	cmd := exec.Command("dmesg", "-T")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to execute dmesg: %w", err)
	}

	return parseJournalOutput(string(output))
}

func parseJournalOutput(output string) ([]Violation, error) {
	var violations []Violation
	scanner := bufio.NewScanner(strings.NewReader(output))
	currentYear := time.Now().Year()

	for scanner.Scan() {
		line := scanner.Text()

		// Filter for bubblewrap-related lines
		lineLower := strings.ToLower(line)
		if !strings.Contains(lineLower, "bwrap") &&
			!strings.Contains(lineLower, "bubblewrap") &&
			!strings.Contains(lineLower, "permission denied") {
			continue
		}

		violation := parseViolation(line, currentYear)
		if violation != nil {
			violations = append(violations, *violation)
		}
	}

	if err := scanner.Err(); err != nil {
		return violations, fmt.Errorf("error scanning journal output: %w", err)
	}

	return violations, nil
}

// parseViolation parses a Linux bubblewrap violation log line
func parseViolation(line string, year int) *Violation {
	// Match journalctl format
	matches := journalPattern.FindStringSubmatch(line)
	if len(matches) != 5 {
		return nil // Not a valid journal line
	}

	timestampStr := matches[1]
	processName := matches[2]
	processID := matches[3]
	message := matches[4]

	// Check if this is related to bubblewrap or sandbox
	if !strings.Contains(strings.ToLower(processName), "bwrap") &&
		!strings.Contains(strings.ToLower(message), "bubblewrap") {
		return nil
	}

	// Parse timestamp (add current year since journalctl doesn't include it)
	timestamp, err := time.Parse("Jan 02 15:04:05", timestampStr)
	if err != nil {
		timestamp = time.Now()
	} else {
		// Add year
		timestamp = time.Date(year, timestamp.Month(), timestamp.Day(),
			timestamp.Hour(), timestamp.Minute(), timestamp.Second(), 0, time.Local)
	}

	// Extract operation and path from message
	operation := "unknown"
	targetPath := ""

	if bwrapMatches := bwrapPattern.FindStringSubmatch(message); len(bwrapMatches) > 2 {
		operation = bwrapMatches[1]
		targetPath = bwrapMatches[2]
	}

	return &Violation{
		Timestamp:   timestamp,
		ProcessName: processName,
		ProcessID:   processID,
		Operation:   operation,
		TargetPath:  targetPath,
		DenyCode:    "EPERM",
		RawLine:     line,
	}
}

func formatDuration(d time.Duration) string {
	if d.Hours() >= 1 {
		return fmt.Sprintf("%.0f hours ago", d.Hours())
	}
	return fmt.Sprintf("%.0f minutes ago", d.Minutes())
}
