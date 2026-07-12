package api

import (
	webassets "github.com/cortalabs/cortasentry/web"
	"io/fs"
	"net/http"
	"strings"
)

func (s *Server) EnableWeb() {
	dist, err := fs.Sub(webassets.Dist, "dist")
	if err != nil {
		return
	}
	files := http.FileServer(http.FS(dist))
	s.mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}
		if _, err := fs.Stat(dist, strings.TrimPrefix(r.URL.Path, "/")); err != nil {
			r.URL.Path = "/"
		}
		files.ServeHTTP(w, r)
	})
}
