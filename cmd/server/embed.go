package main

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed all:frontend_dist
var embeddedFrontend embed.FS

func embeddedFrontendHandler() http.Handler {
	sub, err := fs.Sub(embeddedFrontend, "frontend_dist")
	if err != nil {
		return nil
	}
	if _, err := fs.Stat(sub, "index.html"); err != nil {
		return nil
	}
	fileServer := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clean := strings.TrimPrefix(r.URL.Path, "/")
		if clean == "" {
			fileServer.ServeHTTP(w, r)
			return
		}
		if strings.HasSuffix(clean, "/") {
			candidate := clean + "index.html"
			if _, err := fs.Stat(sub, candidate); err == nil {
				r2 := r.Clone(r.Context())
				r2.URL.Path = "/" + candidate
				fileServer.ServeHTTP(w, r2)
				return
			}
		}
		if info, err := fs.Stat(sub, clean); err == nil {
			if info.IsDir() {
				candidate := clean + "/index.html"
				if _, err := fs.Stat(sub, candidate); err == nil {
					r2 := r.Clone(r.Context())
					r2.URL.Path = "/" + candidate
					fileServer.ServeHTTP(w, r2)
					return
				}
			} else {
				fileServer.ServeHTTP(w, r)
				return
			}
		}
		trimmed := strings.TrimSuffix(clean, "/")
		if _, err := fs.Stat(sub, trimmed+".html"); err == nil {
			r2 := r.Clone(r.Context())
			r2.URL.Path = "/" + trimmed + ".html"
			fileServer.ServeHTTP(w, r2)
			return
		}
		if _, err := fs.Stat(sub, trimmed+"/index.html"); err == nil {
			r2 := r.Clone(r.Context())
			r2.URL.Path = "/" + trimmed + "/index.html"
			fileServer.ServeHTTP(w, r2)
			return
		}
		index, err := embeddedFrontend.ReadFile("frontend_dist/index.html")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(index)
	})
}
