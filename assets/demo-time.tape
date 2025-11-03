Output assets/demo-time.gif

Set FontSize 14
Set Width 1200
Set Height 600
Set Theme "Catppuccin Mocha"

Type "osqueryi --extension ./srt_osquery_extension"
Enter
Sleep 2s

Type "SELECT COUNT(*) as violations"
Enter
Type "FROM sandbox_violations"
Enter
Type "WHERE timestamp > datetime('now', '-1 hour');"
Enter
Sleep 3s

Ctrl+D
Sleep 1s
