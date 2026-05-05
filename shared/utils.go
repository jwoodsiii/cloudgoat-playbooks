package shared

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// start.txt parsing
// ---------------------------------------------------------------------------

// StartConfig holds the key/value pairs parsed from a CloudGoat start.txt.
// Keys are lowercased with the "cloudgoat_output_" prefix stripped, so
// callers get clean names like "aws_account_id" or "target_role_arn".
type StartConfig map[string]string

// Get returns the value for key, and whether it was present.
func (s StartConfig) Get(key string) (string, bool) {
	v, ok := s[strings.ToLower(key)]
	return v, ok
}

// MustGet returns the value for key or exits with an error message if absent.
// Use for values the script cannot proceed without.
func (s StartConfig) MustGet(key string) string {
	v, ok := s.Get(key)
	if !ok {
		Error(fmt.Sprintf("required key %q not found in start.txt", key), true)
	}
	return v
}

// LoadStart parses a CloudGoat start.txt file.
//
// CloudGoat writes start.txt in the format:
//
//	cloudgoat_output_aws_account_id = 123456789012
//	cloudgoat_output_target_role_arn = arn:aws:iam::...
//
// The "cloudgoat_output_" prefix is stripped from keys automatically.
func LoadStart(path string) (StartConfig, error) {
	if path == "" {
		path = "start.txt"
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening start.txt at %s: %w", path, err)
	}
	defer f.Close()

	result := make(StartConfig)
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		key = strings.ToLower(key)
		key = strings.TrimPrefix(key, "cloudgoat_output_")

		value := strings.TrimSpace(parts[1])
		result[key] = value
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading start.txt: %w", err)
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("no key=value pairs found in %s", path)
	}

	return result, nil
}

// ---------------------------------------------------------------------------
// Step narration
// ---------------------------------------------------------------------------

func ts() string {
	return time.Now().UTC().Format("15:04:05")
}

// Step prints a timestamped step banner to stdout.
func Step(msg string) {
	fmt.Printf("\n[%s] >>> %s\n", ts(), msg)
}

// Info prints an indented info line.
func Info(msg string) {
	fmt.Printf("    %s\n", msg)
}

// Finding prints a highlighted finding line.
func Finding(msg string) {
	fmt.Printf("    [FINDING] %s\n", msg)
}

// Error prints an error to stderr. If fatal is true, exits with code 1.
func Error(msg string, fatal bool) {
	fmt.Fprintf(os.Stderr, "    [ERROR] %s\n", msg)
	if fatal {
		os.Exit(1)
	}
}

// ---------------------------------------------------------------------------
// Findings persistence
// ---------------------------------------------------------------------------

// FindingEntry represents a single exploitable condition discovered during
// the attack playbook.
type FindingEntry struct {
	Title    string `json:"title"`
	Detail   string `json:"detail"`   // what was found
	Resource string `json:"resource"` // ARN or resource identifier
	Severity string `json:"severity"` // "critical" | "high" | "medium" | "low"
}

// FindingsReport is the top-level structure written to findings.json.
type FindingsReport struct {
	Scenario     string         `json:"scenario"`
	GeneratedAt  time.Time      `json:"generated_at"`
	FindingCount int            `json:"finding_count"`
	Findings     []FindingEntry `json:"findings"`
}

// WriteFindings serializes findings to a JSON file at path.
// Prints a step line on success.
func WriteFindings(findings []FindingEntry, scenario, path string) error {
	if path == "" {
		path = "findings.json"
	}

	report := FindingsReport{
		Scenario:     scenario,
		GeneratedAt:  time.Now().UTC(),
		FindingCount: len(findings),
		Findings:     findings,
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling findings: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("writing findings to %s: %w", path, err)
	}

	Step(fmt.Sprintf("Wrote %d finding(s) to %s", len(findings), path))
	return nil
}
