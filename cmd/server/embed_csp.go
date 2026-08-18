package main

import (
	"crypto/sha256"
	"encoding/base64"
	"io/fs"
	"regexp"
	"sort"
	"strings"
)

var inlineScriptPattern = regexp.MustCompile(`(?is)<script(?:\s[^>]*)?>(.*?)</script>`)
var scriptSrcPattern = regexp.MustCompile(`(?is)^<script[^>]*\ssrc\s*=`)

// Hashes the inline scripts of the embedded UI so the CSP can list them instead
// of allowing 'unsafe-inline'.
func embeddedScriptHashes() []string {
	sub, err := fs.Sub(embeddedFrontend, "frontend_dist")
	if err != nil {
		return nil
	}

	seen := make(map[string]struct{})
	_ = fs.WalkDir(sub, ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() || !strings.HasSuffix(name, ".html") {
			return nil
		}
		content, readErr := fs.ReadFile(sub, name)
		if readErr != nil {
			return nil
		}
		for _, match := range inlineScriptPattern.FindAllSubmatch(content, -1) {
			if scriptSrcPattern.Match(match[0]) {
				continue
			}
			body := match[1]
			if len(body) == 0 {
				continue
			}
			sum := sha256.Sum256(body)
			seen["'sha256-"+base64.StdEncoding.EncodeToString(sum[:])+"'"] = struct{}{}
		}
		return nil
	})

	hashes := make([]string, 0, len(seen))
	for hash := range seen {
		hashes = append(hashes, hash)
	}
	sort.Strings(hashes)
	return hashes
}
