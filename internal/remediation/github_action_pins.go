package remediation

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

type GitHubActionPins map[string]string

func LoadGitHubActionPins(path string) (GitHubActionPins, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("github action pins file cannot be read")
	}
	var decoded any
	if err := json.Unmarshal(data, &decoded); err != nil {
		return nil, fmt.Errorf("github action pins file is not valid JSON")
	}
	raw, ok := decoded.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("github action pins file must be a JSON object")
	}
	pins := make(GitHubActionPins, len(raw))
	keys := make([]string, 0, len(raw))
	for key := range raw {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if !isStaticGitHubActionRef(key) {
			return nil, fmt.Errorf("github action pins file contains an invalid action ref key")
		}
		sha, ok := raw[key].(string)
		if !ok {
			return nil, fmt.Errorf("github action pins file contains an invalid commit SHA")
		}
		if !isFullCommitSHA(sha) {
			return nil, fmt.Errorf("github action pins file contains an invalid commit SHA")
		}
		pins[key] = sha
	}
	return pins, nil
}

func (pins GitHubActionPins) SHAFor(actionRef string) (string, bool) {
	if len(pins) == 0 {
		return "", false
	}
	sha, ok := pins[actionRef]
	return sha, ok
}

func isStaticGitHubActionRef(value string) bool {
	target, ref, ok := strings.Cut(value, "@")
	if !ok || target == "" || ref == "" {
		return false
	}
	if strings.Contains(value, "${{") || strings.Contains(value, "}}") {
		return false
	}
	if strings.HasPrefix(value, "./") || strings.HasPrefix(value, "docker://") {
		return false
	}
	parts := strings.Split(target, "/")
	if len(parts) < 2 {
		return false
	}
	for _, part := range parts {
		if part == "" || strings.ContainsAny(part, " \t\r\n:") || containsControl(part) {
			return false
		}
	}
	if strings.ContainsAny(ref, " \t\r\n@") || containsControl(ref) {
		return false
	}
	return true
}

func isFullCommitSHA(value string) bool {
	if len(value) != 40 {
		return false
	}
	for _, r := range value {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		case r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}

func containsControl(value string) bool {
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}
