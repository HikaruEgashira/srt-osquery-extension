# Contributing to srt-osquery-extension

Thank you for considering contributing to this project! This document provides guidelines for contributing.

## How to Contribute

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass (`go test ./...`)
6. Commit your changes with conventional commits
7. Push to your fork (`git push origin feature/amazing-feature`)
8. Open a Pull Request

## Development Setup

### Prerequisites

- Go 1.21 or higher
- osquery installed on your system
- macOS 10.15+ or Linux with systemd (for testing)

### Build and Test

```bash
# Install dependencies
go mod download

# Build the extension
go build -o srt_osquery_extension .

# Run tests
go test -v ./...

# Run tests with coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html

# Format code
go fmt ./...

# Lint code (if golangci-lint is installed)
golangci-lint run
```

### Testing the Extension

```bash
# Test with osquery
osqueryi --extension ./srt_osquery_extension

# Test collector directly
go run test_collector.go

# Verbose mode
./srt_osquery_extension --verbose --socket /path/to/socket
```

### Project Structure

```
.
├── main.go                      # Extension entry point & osquery integration
├── pkg/
│   └── collector/
│       ├── collector.go         # Common interface
│       ├── collector_darwin.go  # macOS implementation
│       ├── collector_linux.go   # Linux implementation
│       └── violation.go         # Violation type definition
├── example_queries.sql          # Example SQL queries
├── go.mod
└── README.md
```

## Code Guidelines

### Performance Requirements

**CRITICAL: Log Collection Efficiency**

- Avoid scanning entire log history
- Use predicates/filters to limit log queries
- Be mindful of `--since` parameter impact
- Test with realistic time ranges (1h, 24h)

**Rationale:**
- Unified logging and journalctl can contain millions of entries
- Unfiltered queries can take minutes or timeout
- Poor performance degrades user experience

**Best Practices:**
- Use `log show --predicate` on macOS to filter at source
- Use `journalctl --since` on Linux for time-bounded queries
- Default to reasonable time ranges (1 hour)
- Document performance characteristics

### Platform-Specific Code

- Use build tags: `//go:build darwin` or `//go:build linux`
- Keep platform-specific code in separate files
- Maintain consistent interfaces across platforms
- Document platform differences in code comments

### Code Quality

- Write clear, idiomatic Go code
- Add unit tests for new functionality
- Maintain test coverage above 70%
- Use meaningful variable and function names
- Add comments for complex logic
- Handle errors appropriately

### Testing Requirements

All contributions must include:
- Unit tests for new functions
- Platform-specific tests where applicable
- Test coverage should not decrease significantly
- Test with actual sandbox violations when possible

## Adding Platform Support

To add support for a new platform:

1. Create platform-specific collector file:
```go
//go:build newplatform

package collector

func NewCollector() Collector {
    return &NewPlatformCollector{}
}

func (c *NewPlatformCollector) CollectViolations(since time.Duration) ([]Violation, error) {
    // Implementation
}
```

2. Implement violation parsing logic

3. Add tests in platform-specific test file

4. Update README.md with platform information

## Improving Violation Parsing

To improve log parsing:

1. Add test cases with real log examples in comments
2. Use regex patterns that are maintainable
3. Handle edge cases (missing fields, malformed logs)
4. Return `nil` for non-violation lines (don't error)
5. Preserve raw_line for debugging

Example:
```go
// Example log line:
// 2025-11-03 16:25:43.448666+0900  localhost kernel[0]: (Sandbox) Sandbox: cat(13276) deny(1) file-read-data /path
var sandboxPattern = regexp.MustCompile(`Sandbox:\s+(\w+)\((\d+)\)\s+deny\((\d+)\)\s+([\w-]+)\s+(.+)$`)
```

## Code Review Process

All submissions require review. We use GitHub pull requests for this purpose. The review process includes:

- Code quality and style check
- Test coverage verification
- Performance impact assessment
- Platform compatibility check
- Documentation completeness
- Security considerations

## Commit Message Guidelines

Use conventional commits format:

- `feat: add Linux bubblewrap support`
- `fix: correct timestamp parsing on macOS`
- `docs: update installation instructions`
- `test: add tests for edge cases`
- `refactor: improve error handling`
- `perf: optimize log collection query`

## Security Considerations

When working on this project:

- Never log sensitive information from violations
- Be careful with file path handling
- Validate all input from log parsing
- Consider privacy implications of violation data
- Document any security-relevant changes

## Documentation

When adding features:

- Update README.md with examples
- Add queries to example_queries.sql
- Update CONTRIBUTING.md if development process changes
- Add inline code comments for complex logic
- Update table schema documentation if columns change

## Questions or Issues?

- Open an issue for bugs or feature requests
- Use discussions for questions and ideas
- Check existing issues before creating new ones
- Tag issues appropriately (bug, enhancement, question, etc.)

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
