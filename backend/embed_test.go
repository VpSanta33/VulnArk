package webui

import (
	"io/fs"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestEmbeddedSPARoutesFromAnotherWorkingDirectory(t *testing.T) {
	t.Chdir(t.TempDir())
	gin.SetMode(gin.TestMode)
	r := gin.New()
	Register(r)
	for _, path := range []string{"/", "/vulnerabilities", "/settings/security"} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		require.Equal(t, 200, w.Code, path)
		require.Contains(t, w.Body.String(), "<html")
	}
	for _, path := range []string{"/assets/missing.js", "/api/v1/missing", "/uploads/private.png", "/missing.js"} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		require.Equal(t, 404, w.Code, path)
	}
	entries, err := fs.ReadDir(content, "web/assets")
	require.NoError(t, err)
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".js") {
			continue
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("GET", "/assets/"+entry.Name(), nil))
		require.Equal(t, 200, w.Code)
		require.Contains(t, w.Header().Get("Cache-Control"), "immutable")
		require.NotEmpty(t, w.Body.Bytes())
		return
	}
	t.Fatal("built JavaScript asset is missing")
}
