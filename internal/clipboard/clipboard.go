// Package clipboard copies the generated link using platform clipboard tools.
package clipboard

import (
	"fmt"
	"os/exec"
	"runtime"
)

// Write copies text without invoking a shell.
func Write(value string) error {
	var candidates [][]string
	switch runtime.GOOS {
	case "darwin":
		candidates = [][]string{{"pbcopy"}}
	case "linux":
		candidates = [][]string{{"wl-copy"}, {"xclip", "-selection", "clipboard"}, {"xsel", "--clipboard", "--input"}}
	default:
		return fmt.Errorf("clipboard is not supported on %s", runtime.GOOS)
	}
	for _, candidate := range candidates {
		path, err := exec.LookPath(candidate[0])
		if err != nil {
			continue
		}
		command := exec.Command(path, candidate[1:]...)
		stdin, err := command.StdinPipe()
		if err != nil {
			return fmt.Errorf("open clipboard input: %w", err)
		}
		if err := command.Start(); err != nil {
			return fmt.Errorf("start clipboard command: %w", err)
		}
		if _, err := stdin.Write([]byte(value)); err != nil {
			_ = stdin.Close()
			_ = command.Wait()
			return fmt.Errorf("write clipboard: %w", err)
		}
		if err := stdin.Close(); err != nil {
			_ = command.Wait()
			return fmt.Errorf("close clipboard input: %w", err)
		}
		if err := command.Wait(); err != nil {
			return fmt.Errorf("copy to clipboard: %w", err)
		}
		return nil
	}
	return fmt.Errorf("no supported clipboard command found")
}
