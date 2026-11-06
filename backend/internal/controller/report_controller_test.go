package controller

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"vulnark/internal/model"
	"vulnark/internal/service"
)

type streamReportService struct {
	service.ReportService
	path string
}

func (s streamReportService) OpenReportFile(id uint) (*model.Report, *os.File, error) {
	file, err := os.Open(s.path)
	return &model.Report{ID: id, FileName: "审计报告.pdf"}, file, err
}

func TestReportDownloadStreamsOriginalFileAndRanges(t *testing.T) {
	gin.SetMode(gin.TestMode)
	path := filepath.Join(t.TempDir(), "original.pdf")
	require.NoError(t, os.WriteFile(path, []byte("%PDF-1.7\noriginal report bytes"), 0600))
	router := gin.New()
	router.GET("/reports/:id/download", NewReportController(streamReportService{path: path}).DownloadReport)
	for _, test := range []struct {
		name       string
		rangeValue string
		status     int
		body       string
	}{
		{"full", "", http.StatusOK, "%PDF-1.7\noriginal report bytes"},
		{"range", "bytes=0-3", http.StatusPartialContent, "%PDF"},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/reports/1/download", nil)
			if test.rangeValue != "" {
				request.Header.Set("Range", test.rangeValue)
			}
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, request)
			require.Equal(t, test.status, recorder.Code)
			require.Equal(t, test.body, recorder.Body.String())
			require.Contains(t, recorder.Header().Get("Content-Disposition"), "attachment;")
			require.Equal(t, "nosniff", recorder.Header().Get("X-Content-Type-Options"))
		})
	}
}
