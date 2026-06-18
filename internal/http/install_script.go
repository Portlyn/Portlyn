package http

import (
	_ "embed"
	stdhttp "net/http"
	"os"
	"strings"
)

//go:embed assets/install-node.sh
var installNodeScript string

const defaultNodeAgentDownloadBase = "https://github.com/portlyn/portlyn/releases"

func (s *Server) nodeAgentDownloadBase() string {
	if v := strings.TrimSpace(os.Getenv("PORTLYN_NODEAGENT_DOWNLOAD_BASE")); v != "" {
		return strings.TrimRight(v, "/")
	}
	return defaultNodeAgentDownloadBase
}

func (s *Server) handleInstallScript(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	script := installNodeScript
	script = strings.ReplaceAll(script, "__API_BASE__", s.nodeAgentAPIBaseHint())
	script = strings.ReplaceAll(script, "__DOWNLOAD_BASE__", s.nodeAgentDownloadBase())
	script = strings.ReplaceAll(script, "__VERSION__", "latest")
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(script))
}
