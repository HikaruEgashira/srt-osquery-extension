Output assets/demo-recent.gif

Set FontSize 14
Set Width 1200
Set Height 600
Set Theme "Catppuccin Mocha"

Type "osqueryi --extension ./srt_osquery_extension"
Enter
Sleep 2s

Type "SELECT timestamp, process_name, operation, target_path"
Enter
Type "FROM sandbox_violations"
Enter
Type "ORDER BY timestamp DESC"
Enter
Type "LIMIT 10;"
Enter
Sleep 3s

Ctrl+D
Sleep 1s
