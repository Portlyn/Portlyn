package accesslog

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestRecorderKeepsNewestEntriesFirst(t *testing.T) {
	rec, err := New(Options{Capacity: 3})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	base := time.Now()
	for i := 1; i <= 5; i++ {
		rec.Record(Entry{Time: base.Add(time.Duration(i) * time.Second), Path: "/" + strconv.Itoa(i), Status: 200})
	}
	got := rec.List(Filter{}, 10)
	if len(got) != 3 || got[0].Path != "/5" || got[2].Path != "/3" {
		t.Fatalf("unexpected entries %+v", got)
	}
}

func TestRecorderFilters(t *testing.T) {
	rec, _ := New(Options{Capacity: 10})
	now := time.Now()
	rec.Record(Entry{Time: now, Host: "test.example.com", Path: "/admin", Status: 403, RemoteAddr: "77.67.9.200", Outcome: "denied", ServiceID: 1})
	rec.Record(Entry{Time: now, Host: "blog.example.com", Path: "/", Status: 200, RemoteAddr: "10.0.0.5", Outcome: "proxied", ServiceID: 2, UserAgent: "curl/8.5.0"})

	cases := []struct {
		filter Filter
		want   int
	}{
		{Filter{}, 2},
		{Filter{Status: "4xx"}, 1},
		{Filter{Status: "200"}, 1},
		{Filter{Host: "TEST"}, 1},
		{Filter{IP: "77.67."}, 1},
		{Filter{ServiceID: 2}, 1},
		{Filter{Query: "curl"}, 1},
		{Filter{Outcome: "denied"}, 1},
		{Filter{Before: now}, 0},
	}
	for _, tc := range cases {
		if got := len(rec.List(tc.filter, 10)); got != tc.want {
			t.Errorf("filter %+v: expected %d, got %d", tc.filter, tc.want, got)
		}
	}
}

func TestRecorderWritesAndRotatesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "logs", "access.log")
	rec, err := New(Options{Capacity: 10, FilePath: path, MaxFileBytes: 300, MaxFiles: 2})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	for i := 0; i < 10; i++ {
		rec.Record(Entry{Time: time.Now(), Host: "app.example.com", Path: "/" + strconv.Itoa(i), Status: 200})
	}
	rec.Close()

	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open log: %v", err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	lines := 0
	for scanner.Scan() {
		var entry Entry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			t.Fatalf("line is not json: %q", scanner.Text())
		}
		lines++
	}
	if lines == 0 {
		t.Fatal("expected entries in the current log file")
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatalf("expected a rotated file: %v", err)
	}
	if _, err := os.Stat(path + ".3"); !os.IsNotExist(err) {
		t.Fatal("expected at most two rotated files")
	}
}
