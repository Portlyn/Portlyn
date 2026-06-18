package selfupdate

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

func AssetName(prefix string) string {
	ext := ""
	if runtime.GOOS == "windows" {
		ext = ".exe"
	}
	return fmt.Sprintf("%s-%s-%s%s", prefix, runtime.GOOS, runtime.GOARCH, ext)
}

func RequireWritable(path string) error {
	dir := filepath.Dir(path)
	probe := filepath.Join(dir, ".portlyn-writable-probe")
	f, err := os.OpenFile(probe, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("cannot write into %s (rerun with sudo?): %w", dir, err)
	}
	f.Close()
	_ = os.Remove(probe)
	return nil
}

func AtomicSwap(currentPath string, payload io.Reader, mode os.FileMode) (string, error) {
	dir := filepath.Dir(currentPath)
	tmp, err := os.CreateTemp(dir, filepath.Base(currentPath)+".new-*")
	if err != nil {
		return "", fmt.Errorf("create temp: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = os.Remove(tmpPath)
	}()
	if _, err := io.Copy(tmp, payload); err != nil {
		tmp.Close()
		return "", fmt.Errorf("write new binary: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("close new binary: %w", err)
	}
	if err := os.Chmod(tmpPath, mode); err != nil {
		return "", fmt.Errorf("chmod new binary: %w", err)
	}
	backupPath := currentPath + ".bak"
	if _, err := os.Stat(currentPath); err == nil {
		if err := os.Rename(currentPath, backupPath); err != nil {
			return "", fmt.Errorf("backup current: %w", err)
		}
	}
	if err := os.Rename(tmpPath, currentPath); err != nil {
		_ = os.Rename(backupPath, currentPath)
		return "", fmt.Errorf("atomic rename: %w", err)
	}
	_ = os.Chmod(backupPath, 0o600)
	return backupPath, nil
}

func RestartSystemd(ctx context.Context, unit string) error {
	bin, err := exec.LookPath("systemctl")
	if err != nil {
		return fmt.Errorf("systemctl not found: %w", err)
	}
	cmd := exec.CommandContext(ctx, bin, "restart", unit)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl restart %s: %w: %s", unit, err, string(out))
	}
	return nil
}
