package main

import (
	"context"
	"flag"
	"log"
	"os"
	"time"

	"github.com/HikaruEgashira/sandboxes/srt-osquery-extension/pkg/collector"
	"github.com/osquery/osquery-go"
	"github.com/osquery/osquery-go/plugin/table"
)

func main() {
	var (
		socket   = flag.String("socket", "", "Path to osquery socket")
		timeout  = flag.Int("timeout", 3, "Timeout in seconds")
		interval = flag.Int("interval", 3, "Interval in seconds")
		since    = flag.Duration("since", 1*time.Hour, "How far back to look for violations")
		verbose  = flag.Bool("verbose", false, "Enable verbose logging")
	)
	flag.Parse()

	if *verbose {
		log.Printf("Debug: Args=%v, OSQUERY_SOCKET=%s, socket flag=%s",
			flag.Args(), os.Getenv("OSQUERY_SOCKET"), *socket)
	}

	if *socket == "" {
		if envSocket := os.Getenv("OSQUERY_SOCKET"); envSocket != "" {
			*socket = envSocket
			if *verbose {
				log.Printf("Using socket from OSQUERY_SOCKET: %s", *socket)
			}
		}
	}

	if *socket == "" && len(flag.Args()) > 0 {
		*socket = flag.Args()[0]
		if *verbose {
			log.Printf("Using socket from positional arg: %s", *socket)
		}
	}

	if *socket == "" {
		log.Fatalln("Usage: srt_osquery_extension --socket <path>")
	}

	if *verbose {
		log.Printf("Using socket: %s", *socket)
		log.Printf("Violations lookback period: %v", *since)
	}

	if *verbose {
		log.Printf("Creating extension manager server...")
	}
	server, err := osquery.NewExtensionManagerServer(
		"srt_osquery_extension",
		*socket,
		osquery.ServerTimeout(time.Duration(*timeout)*time.Second),
		osquery.ServerPingInterval(time.Duration(*interval)*time.Second),
	)
	if err != nil {
		log.Fatalf("Error creating extension: %v", err)
	}
	if *verbose {
		log.Printf("Extension manager server created successfully")
	}

	// Create collector
	col := collector.NewCollector()

	// Define table columns
	columns := []table.ColumnDefinition{
		table.TextColumn("timestamp"),
		table.TextColumn("process_name"),
		table.TextColumn("process_id"),
		table.TextColumn("operation"),
		table.TextColumn("target_path"),
		table.TextColumn("deny_code"),
		table.TextColumn("raw_line"),
	}

	if *verbose {
		log.Printf("Registering table plugin: sandbox_violations")
	}

	server.RegisterPlugin(table.NewPlugin("sandbox_violations", columns,
		func(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
			if *verbose {
				log.Printf("Table query called for sandbox_violations")
			}

			violations, err := col.CollectViolations(*since)
			if err != nil {
				log.Printf("Error collecting violations: %v", err)
				return []map[string]string{}, nil
			}

			if *verbose {
				log.Printf("Found %d violations", len(violations))
			}

			var results []map[string]string
			for _, v := range violations {
				results = append(results, map[string]string{
					"timestamp":    v.Timestamp.Format(time.RFC3339),
					"process_name": v.ProcessName,
					"process_id":   v.ProcessID,
					"operation":    v.Operation,
					"target_path":  v.TargetPath,
					"deny_code":    v.DenyCode,
					"raw_line":     v.RawLine,
				})
			}

			return results, nil
		}))

	if *verbose {
		log.Printf("Table plugin registered successfully")
	}

	log.Printf("Starting srt_osquery_extension on socket: %s", *socket)
	log.Printf("Registered table: sandbox_violations")
	if err := server.Run(); err != nil {
		log.Fatalf("Error running extension: %v", err)
	}
	log.Printf("Extension stopped")
}
