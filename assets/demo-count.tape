Output assets/demo-count.gif

Set FontSize 14
Set Width 1200
Set Height 600
Set Theme "Catppuccin Mocha"

Type "osqueryi --extension ./srt_osquery_extension"
Enter
Sleep 2s

Type "SELECT process_name, COUNT(*) as count"
Enter
Type "FROM sandbox_violations"
Enter
Type "GROUP BY process_name"
Enter
Type "ORDER BY count DESC;"
Enter
Sleep 3s

Ctrl+D
Sleep 1s
