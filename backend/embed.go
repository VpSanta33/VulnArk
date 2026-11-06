package webui

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"

	"github.com/gin-gonic/gin"
)

//go:embed web
var content embed.FS

// Register serves the bundled application independently of the working directory.
func Register(r *gin.Engine) {
	files, err := fs.Sub(content, "web")
	if err != nil {
		panic(err)
	}
	r.GET("/assets/*filepath", func(c *gin.Context) {
		name := "assets/" + strings.TrimPrefix(c.Param("filepath"), "/")
		if strings.Contains(name, "..") {
			c.Status(http.StatusNotFound)
			return
		}
		if _, err := fs.Stat(files, name); err != nil {
			c.Status(http.StatusNotFound)
			return
		}
		c.Header("Cache-Control", "public, max-age=31536000, immutable")
		c.FileFromFS("/"+name, http.FS(files))
	})
	r.GET("/vite.svg", func(c *gin.Context) {
		c.FileFromFS("/vite.svg", http.FS(files))
	})
	index, err := fs.ReadFile(files, "index.html")
	if err != nil {
		panic(err)
	}
	r.NoRoute(func(c *gin.Context) {
		if c.Request.Method != http.MethodGet && c.Request.Method != http.MethodHead {
			c.Status(http.StatusNotFound)
			return
		}
		if strings.HasPrefix(c.Request.URL.Path, "/api") ||
			strings.HasPrefix(c.Request.URL.Path, "/uploads") ||
			path.Ext(c.Request.URL.Path) != "" {
			c.JSON(http.StatusNotFound, gin.H{"code": 404, "message": "Route not found"})
			return
		}
		c.Header("Cache-Control", "no-cache")
		c.Data(http.StatusOK, "text/html; charset=utf-8", index)
	})
}
