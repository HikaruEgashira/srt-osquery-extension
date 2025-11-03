package main

import (
	"fmt"
	"time"
	"github.com/HikaruEgashira/sandboxes/srt-osquery-extension/pkg/collector"
)

func main() {
	col := collector.NewCollector()
	
	fmt.Println("Collecting sandbox violations from the last hour...")
	violations, err := col.CollectViolations(1 * time.Hour)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	
	fmt.Printf("\nFound %d violations:\n\n", len(violations))
	
	for i, v := range violations {
		if i >= 5 {
			fmt.Printf("... and %d more\n", len(violations)-5)
			break
		}
		fmt.Printf("=== Violation #%d ===\n", i+1)
		fmt.Printf("Timestamp:    %s\n", v.Timestamp.Format(time.RFC3339))
		fmt.Printf("Process:      %s (PID: %s)\n", v.ProcessName, v.ProcessID)
		fmt.Printf("Operation:    %s\n", v.Operation)
		fmt.Printf("Target Path:  %s\n", v.TargetPath)
		fmt.Printf("Deny Code:    %s\n", v.DenyCode)
		fmt.Printf("Raw Line:     %s\n\n", v.RawLine[:min(len(v.RawLine), 100)])
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
