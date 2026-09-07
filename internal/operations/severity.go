package operations

import (
	"fmt"
	"strconv"
	"strings"
)

var severityCodes = map[string]string{
	"critical": "0",
	"high":     "1",
	"medium":   "2",
	"low":      "3",
	"info":     "4",
}

// SeverityCode translates a CLI-friendly severity name into the integer code
// the API expects. Numeric input is accepted unchanged (0..4).
func SeverityCode(value string) (string, error) {
	if code, ok := severityCodes[strings.ToLower(value)]; ok {
		return code, nil
	}
	if n, err := strconv.Atoi(value); err == nil && n >= 0 && n <= 4 {
		return value, nil
	}
	return "", fmt.Errorf("invalid severity %q (expected: critical|high|medium|low|info)", value)
}
