# srt-osquery-extension

osquery extension for collecting sandbox violation logs from [sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime).

## Installation

```bash
# Build from source
go build -o srt_osquery_extension

# Linux
sudo chown root:root ./srt_osquery_extension
sudo chmod 755 ./srt_osquery_extension

# macOS
sudo chown root:wheel ./srt_osquery_extension
sudo chmod 755 ./srt_osquery_extension
```

For other installation methods, see the [releases page](https://github.com/HikaruEgashira/srt-osquery-extension/releases).

## Quick Start

![Demo](assets/demo.gif)

```bash
osqueryi --extension ./srt_osquery_extension
> SELECT * FROM sandbox_violations LIMIT 10;
```

## Features

| Platform | Sandbox System | Log Source | Supported |
|----------|---------------|------------|-----------|
| macOS    | sandbox-exec  | unified logging (`log show`) | Yes |
| Linux    | bubblewrap    | journalctl / dmesg | Yes |

**Key Features:**
- 🔍 Query-driven: Violations collected on-demand (no background monitoring)
- 🚀 Fast: Pre-filtered by log commands
- 📊 Structured: Parsed into queryable columns
- 🔒 Security-focused: Track unauthorized access attempts

## Table Schema

```sql
CREATE TABLE sandbox_violations (
    timestamp TEXT,
    process_name TEXT,
    process_id TEXT,
    operation TEXT,
    target_path TEXT,
    deny_code TEXT,
    raw_line TEXT
);
```

- `timestamp`: Violation timestamp (RFC3339 format)
- `process_name`: Name of the process that violated sandbox policy
- `process_id`: Process ID (PID)
- `operation`: Operation that was denied (e.g., `file-read-data`, `mach-lookup`)
- `target_path`: Path or resource that was accessed
- `deny_code`: Denial code from sandbox system
- `raw_line`: Raw log line for debugging

## Query Examples

### Recent violations

![Recent violations](assets/demo-recent.gif)

```sql
SELECT timestamp, process_name, operation, target_path
FROM sandbox_violations
ORDER BY timestamp DESC
LIMIT 10;
```

### Count by process

![Count by process](assets/demo-count.gif)

```sql
SELECT process_name, COUNT(*) as count
FROM sandbox_violations
GROUP BY process_name
ORDER BY count DESC;
```

### Security-sensitive paths

![Security paths](assets/demo-security.gif)

```sql
SELECT * FROM sandbox_violations
WHERE target_path LIKE '%/.ssh/%'
   OR target_path LIKE '%/credentials%';
```

### Violations by operation type

![By operation](assets/demo-operation.gif)

```sql
SELECT operation, COUNT(*) as count
FROM sandbox_violations
GROUP BY operation
ORDER BY count DESC;
```

### Recent violations (last hour)

![Time filter](assets/demo-time.gif)

```sql
SELECT COUNT(*) as violations
FROM sandbox_violations
WHERE timestamp > datetime('now', '-1 hour');
```

See [example_queries.sql](example_queries.sql) for more SQL query examples.

## Command-line Options

```bash
./srt_osquery_extension [options]
```

Options:
- `--socket`: Path to osquery socket (auto-detected if launched by osquery)
- `--since`: How far back to look for violations (default: 1h)
- `--timeout`: Connection timeout in seconds (default: 3)
- `--interval`: Ping interval in seconds (default: 3)
- `--verbose`: Enable verbose logging

## Platform-specific Notes

### macOS

Uses `log show` to query the unified logging system:
```bash
log show --predicate 'eventMessage CONTAINS "Sandbox:" AND eventMessage CONTAINS "deny"' --last 1h
```

**Example violation:**
```
2025-11-03 16:25:43.448666+0900  localhost kernel[0]: (Sandbox) Sandbox: cat(13276) deny(1) file-read-data /Users/hikae/.ssh/config
```

### Linux

Tries `journalctl` first, falling back to `dmesg`:
```bash
journalctl --since "1 hour ago" | grep -i bubblewrap
```

**Note:** Linux violation detection is best-effort. For comprehensive monitoring, consider using `strace`:
```bash
strace -f -e trace=all bwrap ... 2>&1 | grep EPERM
```

## Use Cases

### Security Monitoring
```sql
-- Alert on SSH key access attempts
SELECT * FROM sandbox_violations
WHERE target_path LIKE '%/.ssh/%';
```

### Process Behavior Analysis
```sql
-- Identify noisy processes
SELECT process_name, COUNT(*) as violations
FROM sandbox_violations
GROUP BY process_name
HAVING violations > 10;
```

### Compliance Auditing
```sql
-- Track unauthorized file access
SELECT timestamp, process_name, target_path
FROM sandbox_violations
WHERE operation LIKE '%file%'
ORDER BY timestamp DESC;
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

## License

MIT
