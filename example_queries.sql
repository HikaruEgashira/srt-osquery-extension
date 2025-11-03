-- Example queries for sandbox_violations table

-- ==============================================================================
-- Basic Queries
-- ==============================================================================

-- List all recent violations (last 20)
SELECT
    timestamp,
    process_name,
    operation,
    target_path
FROM sandbox_violations
ORDER BY timestamp DESC
LIMIT 20;

-- Show all available columns
SELECT * FROM sandbox_violations LIMIT 10;

-- ==============================================================================
-- Filtering and Analysis
-- ==============================================================================

-- Count total violations
SELECT COUNT(*) as total_violations
FROM sandbox_violations;

-- Count violations by process
SELECT
    process_name,
    COUNT(*) as violation_count
FROM sandbox_violations
GROUP BY process_name
ORDER BY violation_count DESC;

-- Count violations by operation type
SELECT
    operation,
    COUNT(*) as count
FROM sandbox_violations
GROUP BY operation
ORDER BY count DESC;

-- ==============================================================================
-- Security Analysis
-- ==============================================================================

-- Find violations accessing sensitive SSH files
SELECT
    timestamp,
    process_name,
    operation,
    target_path
FROM sandbox_violations
WHERE target_path LIKE '%/.ssh/%'
ORDER BY timestamp DESC;

-- Find violations accessing home directory
SELECT
    timestamp,
    process_name,
    operation,
    target_path
FROM sandbox_violations
WHERE target_path LIKE '/Users/%'
   OR target_path LIKE '/home/%'
ORDER BY timestamp DESC;

-- Find file write violations
SELECT
    timestamp,
    process_name,
    target_path
FROM sandbox_violations
WHERE operation LIKE '%write%'
ORDER BY timestamp DESC;

-- Find network-related violations
SELECT
    timestamp,
    process_name,
    operation,
    target_path
FROM sandbox_violations
WHERE operation LIKE '%network%'
ORDER BY timestamp DESC;

-- ==============================================================================
-- Process-specific Queries
-- ==============================================================================

-- Violations by specific process (replace 'cat' with process name)
SELECT
    timestamp,
    operation,
    target_path,
    deny_code
FROM sandbox_violations
WHERE process_name = 'cat'
ORDER BY timestamp DESC;

-- Unique processes that violated sandbox
SELECT DISTINCT process_name
FROM sandbox_violations
ORDER BY process_name;

-- Process with their unique target paths
SELECT
    process_name,
    COUNT(DISTINCT target_path) as unique_paths_accessed
FROM sandbox_violations
GROUP BY process_name
ORDER BY unique_paths_accessed DESC;

-- ==============================================================================
-- Path Analysis
-- ==============================================================================

-- Most frequently blocked paths
SELECT
    target_path,
    COUNT(*) as block_count
FROM sandbox_violations
GROUP BY target_path
ORDER BY block_count DESC
LIMIT 20;

-- Violations accessing /etc directory
SELECT
    timestamp,
    process_name,
    operation,
    target_path
FROM sandbox_violations
WHERE target_path LIKE '/etc/%'
ORDER BY timestamp DESC;

-- Violations accessing temporary directories
SELECT
    timestamp,
    process_name,
    operation,
    target_path
FROM sandbox_violations
WHERE target_path LIKE '/tmp/%'
   OR target_path LIKE '/var/tmp/%'
ORDER BY timestamp DESC;

-- ==============================================================================
-- Advanced Analysis
-- ==============================================================================

-- Violations by hour (timestamp distribution)
SELECT
    strftime('%Y-%m-%d %H:00', timestamp) as hour,
    COUNT(*) as violations
FROM sandbox_violations
GROUP BY hour
ORDER BY hour DESC
LIMIT 24;

-- Process and operation combinations
SELECT
    process_name,
    operation,
    COUNT(*) as count
FROM sandbox_violations
GROUP BY process_name, operation
ORDER BY count DESC
LIMIT 20;

-- Violations with raw log for debugging
SELECT
    timestamp,
    process_name,
    process_id,
    raw_line
FROM sandbox_violations
ORDER BY timestamp DESC
LIMIT 10;

-- ==============================================================================
-- Join with other osquery tables
-- ==============================================================================

-- Join with processes table to get more process info (macOS/Linux)
-- Note: This may not match if process has already exited
SELECT
    sv.timestamp,
    sv.process_name,
    sv.process_id,
    sv.operation,
    sv.target_path,
    p.cmdline,
    p.parent
FROM sandbox_violations sv
LEFT JOIN processes p ON CAST(sv.process_id AS INTEGER) = p.pid
ORDER BY sv.timestamp DESC
LIMIT 20;

-- Find violations from processes with specific parent
SELECT
    sv.timestamp,
    sv.process_name,
    sv.operation,
    sv.target_path,
    p.parent
FROM sandbox_violations sv
JOIN processes p ON CAST(sv.process_id AS INTEGER) = p.pid
WHERE p.parent IN (1, 0)  -- init or launchd
ORDER BY sv.timestamp DESC;

-- ==============================================================================
-- Monitoring Queries
-- ==============================================================================

-- Check if there are any new violations (run periodically)
SELECT COUNT(*) as recent_violations
FROM sandbox_violations
WHERE timestamp > datetime('now', '-5 minutes');

-- Alert on violations to critical paths
SELECT
    timestamp,
    process_name,
    operation,
    target_path
FROM sandbox_violations
WHERE target_path IN (
    '/etc/passwd',
    '/etc/shadow',
    '/private/etc/master.passwd',
    '~/.ssh/id_rsa',
    '~/.aws/credentials'
)
ORDER BY timestamp DESC;
