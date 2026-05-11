package intercept

import (
	"embed"
	"fmt"
)

//go:embed shells/zsh.sh shells/bash.sh shells/fish.sh
var shellsFS embed.FS

// SupportedShells lists the shells we can integrate with.
var SupportedShells = []string{"zsh", "bash", "fish"}

// ShellScript returns the init script for the given shell.
// Returns an error if the shell isn't supported.
func ShellScript(shell string) (string, error) {
	var filename string
	switch shell {
	case "zsh":
		filename = "shells/zsh.sh"
	case "bash":
		filename = "shells/bash.sh"
	case "fish":
		filename = "shells/fish.sh"
	default:
		return "", fmt.Errorf("unsupported shell: %q (supported: %v)", shell, SupportedShells)
	}

	data, err := shellsFS.ReadFile(filename)
	if err != nil {
		return "", fmt.Errorf("read embedded script: %w", err)
	}
	return string(data), nil
}