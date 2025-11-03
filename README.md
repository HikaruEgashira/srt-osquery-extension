# srt-osquery-extension

osquery extension for collecting sandbox violation logs from [sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime).

## Features

- 🍎 **macOS**: Collects `sandbox-exec` violations from unified logging system
- 🐧 **Linux**: Collects `bubblewrap` violations from journalctl/dmesg
- 📊 Query-driven: Violations are collected on-demand when queried (no background monitoring)
- 🔍 SQL interface: Use familiar SQL queries to analyze sandbox violations

## Installation

### Build from source

```bash
git clone https://github.com/HikaruEgashira/sandboxes.git
cd sandboxes/srt-osquery-extension
go build -o srt_osquery_extension
```

### macOS specific requirements

- No additional requirements (uses built-in `log show` command)

### Linux specific requirements

- `journalctl` (systemd) or `dmesg` available
- May require root permissions depending on system configuration

## Usage

### With osqueryi (interactive mode)

```bash
osqueryi --extension /path/to/srt_osquery_extension
```

### With osqueryd (daemon mode)

Add to osquery flags:
```
--extension /path/to/srt_osquery_extension
```

Or add to osquery configuration file:
```json
{
  "extensions_autoload": "/path/to/extensions",
  "extensions": [
    "/path/to/srt_osquery_extension"
  ]
}
```

### Command-line options

```bash
./srt_osquery_extension --socket /path/to/osquery.sock --since 2h --verbose
```

Options:
- `--socket`: Path to osquery socket (auto-detected if launched by osquery)
- `--since`: How far back to look for violations (default: 1h)
- `--timeout`: Connection timeout in seconds (default: 3)
- `--interval`: Ping interval in seconds (default: 3)
- `--verbose`: Enable verbose logging

## Table Schema

### `sandbox_violations`

| Column | Type | Description |
|--------|------|-------------|
| `timestamp` | TEXT | Violation timestamp (RFC3339 format) |
| `process_name` | TEXT | Name of the process that violated sandbox policy |
| `process_id` | TEXT | Process ID (PID) |
| `operation` | TEXT | Operation that was denied (e.g., "file-read-data", "file-write") |
| `target_path` | TEXT | Path or resource that was accessed |
| `deny_code` | TEXT | Denial code from sandbox system |
| `raw_line` | TEXT | Raw log line for debugging |

## Example Queries

See [example_queries.sql](./example_queries.sql) for more examples.

### List recent violations

```sql
SELECT timestamp, process_name, operation, target_path
FROM sandbox_violations
ORDER BY timestamp DESC
LIMIT 20;
```

### Count violations by process

```sql
SELECT process_name, COUNT(*) as violation_count
FROM sandbox_violations
GROUP BY process_name
ORDER BY violation_count DESC;
```

### Find violations accessing sensitive paths

```sql
SELECT timestamp, process_name, operation, target_path
FROM sandbox_violations
WHERE target_path LIKE '%/.ssh/%'
   OR target_path LIKE '%/private/%'
ORDER BY timestamp DESC;
```

## Platform-specific Notes

### macOS

The extension uses `log show` to query the unified logging system. Violations are collected based on the `--since` flag (default: 1 hour).

**Example log format:**
```
2025-11-03 16:25:43.448666+0900  localhost kernel[0]: (Sandbox) Sandbox: cat(13276) deny(1) file-read-data /Users/user/.ssh/config
```

### Linux

The extension tries `journalctl` first, falling back to `dmesg` if journalctl is not available. Violations are filtered for bubblewrap-related entries.

**Note:** Linux violation detection is best-effort. For comprehensive monitoring, consider using `strace` with bubblewrap:

```bash
strace -f -e trace=all bwrap ... 2>&1 | grep EPERM
```

## Development

### Project structure

```
srt-osquery-extension/
├── main.go                          # Entry point & osquery integration
├── pkg/
│   ├── collector/
│   │   ├── collector.go             # Common interface
│   │   ├── collector_darwin.go      # macOS implementation
│   │   ├── collector_linux.go       # Linux implementation
│   │   └── violation.go             # Violation type definition
│   └── parser/
│       ├── parser_darwin.go         # macOS log parser
│       └── parser_linux.go          # Linux log parser
└── go.mod
```

### Build for specific platform

```bash
# macOS
GOOS=darwin GOARCH=amd64 go build -o srt_osquery_extension_darwin

# Linux
GOOS=linux GOARCH=amd64 go build -o srt_osquery_extension_linux
```

### Testing

```bash
go test ./...
```

## Troubleshooting

### macOS: No violations appearing

- Check that sandbox-exec is actually being used
- Try increasing the `--since` duration
- Run with `--verbose` to see debug logs
- Verify violations are in system logs: `log show --predicate 'eventMessage CONTAINS "Sandbox:"' --last 1h`

### Linux: Permission denied

- `journalctl` may require sudo: `sudo osqueryi --extension ./srt_osquery_extension`
- Or add user to `systemd-journal` group: `sudo usermod -a -G systemd-journal $USER`

### Extension not loading

- Check socket path is correct
- Verify osquery version compatibility
- Run with `--verbose` to see detailed errors

## License

MIT

## Related Projects

- [sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime) - Secure sandbox execution environment
- [osquery](https://osquery.io/) - SQL powered operating system instrumentation
- [node-packages-osquery-extension](../node-packages-osquery-extension/) - Reference implementation
