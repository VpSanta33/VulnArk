package model

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReportResponsesHidePrivateStoragePaths(t *testing.T) {
	for _, value := range []interface{}{
		Report{FilePath: "reports/private/report.pdf", FileName: "report.pdf"},
		ReportInfo{FilePath: "reports/private/report.pdf", FileName: "report.pdf"},
		FileAttachment{FilePath: "reports/private/report.pdf", Filename: "report.pdf"},
	} {
		encoded, err := json.Marshal(value)
		require.NoError(t, err)
		require.NotContains(t, string(encoded), "file_path")
		require.NotContains(t, string(encoded), "reports/private/")
		require.Contains(t, string(encoded), "report.pdf")
	}
}
