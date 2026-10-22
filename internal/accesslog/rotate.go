package accesslog

import (
	"fmt"
	"os"
	"path/filepath"
)

type rotatingFile struct {
	path     string
	maxBytes int64
	maxFiles int
	file     *os.File
	size     int64
}

func openRotatingFile(path string, maxBytes int64, maxFiles int) (*rotatingFile, error) {
	if maxBytes <= 0 {
		maxBytes = 100 << 20
	}
	if maxFiles < 1 {
		maxFiles = 5
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("create access log directory: %w", err)
	}
	f := &rotatingFile{path: path, maxBytes: maxBytes, maxFiles: maxFiles}
	if err := f.open(); err != nil {
		return nil, err
	}
	return f, nil
}

func (f *rotatingFile) open() error {
	file, err := os.OpenFile(f.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return fmt.Errorf("open access log: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return fmt.Errorf("stat access log: %w", err)
	}
	f.file = file
	f.size = info.Size()
	return nil
}

func (f *rotatingFile) WriteLine(line []byte) error {
	if f.size > 0 && f.size+int64(len(line))+1 > f.maxBytes {
		if err := f.rotate(); err != nil {
			return err
		}
	}
	n, err := f.file.Write(append(line, '\n'))
	f.size += int64(n)
	return err
}

func (f *rotatingFile) rotate() error {
	if err := f.file.Close(); err != nil {
		return err
	}
	_ = os.Remove(fmt.Sprintf("%s.%d", f.path, f.maxFiles))
	for i := f.maxFiles - 1; i >= 1; i-- {
		_ = os.Rename(fmt.Sprintf("%s.%d", f.path, i), fmt.Sprintf("%s.%d", f.path, i+1))
	}
	if err := os.Rename(f.path, f.path+".1"); err != nil {
		return err
	}
	return f.open()
}

func (f *rotatingFile) Close() error {
	if f.file == nil {
		return nil
	}
	return f.file.Close()
}
