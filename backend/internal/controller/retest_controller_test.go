package controller

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"vulnark/internal/config"
	"vulnark/internal/model"
	"vulnark/internal/repository"
	"vulnark/internal/service"
	"vulnark/pkg/storage"
	"vulnark/pkg/testutil"
)

type retestControllerPermissions struct{ service.PermissionService }

func (p *retestControllerPermissions) CheckUserPermission(id uint, permission string) (bool, error) {
	return (id > 0 && permission == "vuln:read") || ((id == 1 || id == 3) && permission == "vuln:verify"), nil
}

func retestControllerSetup(t *testing.T, wrap ...func(storage.StorageService) storage.StorageService) (*gin.Engine, *gorm.DB, uint, string) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	previous := config.AppConfig
	base := t.TempDir()
	config.AppConfig = &config.Config{Storage: config.StorageConfig{LocalPath: base}}
	t.Cleanup(func() { config.AppConfig = previous })
	db := testutil.NewTestDB(t)
	require.NoError(t, db.AutoMigrate(&model.VulnerabilityRetest{}, &model.VulnerabilityTimeline{}, &model.FileCleanupTask{}, &model.Notification{}, &model.NotificationSettings{}))
	for i := 1; i <= 3; i++ {
		require.NoError(t, db.Create(&model.User{ID: uint(i), Username: fmt.Sprintf("retest%d", i), Email: fmt.Sprintf("retest%d@test.test", i), RealName: "Tester", PasswordHash: "hash", RoleID: 1}).Error)
	}
	tester := uint(1)
	require.NoError(t, db.Create(&model.Asset{ID: 1, Name: "retest asset", Type: model.AssetTypeApplication, OwnerID: &tester}).Error)
	assignee := uint(2)
	v := &model.Vulnerability{Title: "fixed", AssetID: 1, SeverityLevel: 2, Status: model.StatusFixed, AssigneeID: &assignee}
	require.NoError(t, db.Create(v).Error)
	svc := service.NewRetestService(repository.NewRetestRepository(db), repository.NewVulnerabilityRepository(db), &retestControllerPermissions{})
	store := storage.NewStorageService()
	for _, wrapper := range wrap {
		store = wrapper(store)
	}
	c := NewRetestController(svc, store)
	router := gin.New()
	router.Use(func(ctx *gin.Context) {
		if id, err := strconv.ParseUint(ctx.GetHeader("X-Test-User"), 10, 32); err == nil && id != 0 {
			ctx.Set("user_id", uint(id))
		}
	})
	router.POST("/vulnerabilities/:id/retest", c.CreateRetest)
	router.GET("/vulnerabilities/:id/retests", c.ListRetests)
	router.GET("/vulnerabilities/:id/retests/:retest_id/evidence/:index/download", c.DownloadEvidence)
	return router, db, v.ID, base
}

func retestMultipart(t *testing.T, data string, files ...[]byte) (*bytes.Buffer, string) {
	t.Helper()
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	require.NoError(t, writer.WriteField("data", data))
	for _, file := range files {
		part, err := writer.CreateFormFile("evidence", "proof.png")
		require.NoError(t, err)
		_, err = part.Write(file)
		require.NoError(t, err)
	}
	require.NoError(t, writer.Close())
	return body, writer.FormDataContentType()
}

func retestHTTP(router *gin.Engine, method, path, contentType string, body io.Reader, user uint) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, body)
	request.Header.Set("Content-Type", contentType)
	if user != 0 {
		request.Header.Set("X-Test-User", strconv.FormatUint(uint64(user), 10))
	}
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

func TestRetestMultipartPrivateEvidenceAndAuthorizedDownload(t *testing.T) {
	router, db, id, _ := retestControllerSetup(t)
	body, contentType := retestMultipart(t, `{"result":"pass","summary":"validated"}`, pngAttachment(t))
	response := retestHTTP(router, http.MethodPost, fmt.Sprintf("/vulnerabilities/%d/retest", id), contentType, body, 1)
	require.Equal(t, http.StatusCreated, response.Code, response.Body.String())
	var envelope struct {
		Data model.VulnerabilityRetestInfo `json:"data"`
	}
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &envelope))
	require.Len(t, envelope.Data.EvidenceAttachments, 1)
	require.NotContains(t, response.Body.String(), `"path"`)
	require.NotContains(t, response.Body.String(), "attachments/")
	var saved model.VulnerabilityRetest
	require.NoError(t, db.First(&saved, envelope.Data.ID).Error)
	require.NotEmpty(t, saved.EvidenceAttachments[0].FilePath)
	for _, user := range []uint{1, 2} {
		list := retestHTTP(router, http.MethodGet, fmt.Sprintf("/vulnerabilities/%d/retests", id), "", nil, user)
		require.Equal(t, http.StatusOK, list.Code, list.Body.String())
		require.NotContains(t, list.Body.String(), saved.EvidenceAttachments[0].FilePath)
	}
	downloadURL := fmt.Sprintf("/vulnerabilities/%d/retests/%d/evidence/0/download", id, saved.ID)
	download := retestHTTP(router, http.MethodGet, downloadURL, "", nil, 2)
	require.Equal(t, http.StatusOK, download.Code)
	require.Equal(t, "application/octet-stream", download.Header().Get("Content-Type"))
	require.Contains(t, download.Header().Get("Content-Disposition"), "attachment")
	require.Contains(t, download.Header().Get("Content-Disposition"), "proof.png")
	require.Equal(t, "private, no-store", download.Header().Get("Cache-Control"))
	require.NotEmpty(t, download.Body.Bytes())
	denied := retestHTTP(router, http.MethodGet, downloadURL, "", nil, 3)
	require.Equal(t, http.StatusForbidden, denied.Code)
	forgedParticipation := retestHTTP(router, http.MethodPost, fmt.Sprintf("/vulnerabilities/%d/retest", id), "application/json", strings.NewReader(`{"result":"fail","summary":"unrelated verifier"}`), 3)
	require.Equal(t, http.StatusForbidden, forgedParticipation.Code)
	denied = retestHTTP(router, http.MethodGet, downloadURL, "", nil, 3)
	require.Equal(t, http.StatusForbidden, denied.Code)
	unauthenticated := retestHTTP(router, http.MethodGet, downloadURL, "", nil, 0)
	require.Equal(t, http.StatusUnauthorized, unauthenticated.Code)
	wrongID := retestHTTP(router, http.MethodGet, strings.Replace(downloadURL, "/evidence/0/", "/evidence/1/", 1), "", nil, 2)
	require.Equal(t, http.StatusNotFound, wrongID.Code)
}

func TestRetestRejectsForgedEvidencePathsAndOversizedBody(t *testing.T) {
	router, _, id, _ := retestControllerSetup(t)
	path := fmt.Sprintf("/vulnerabilities/%d/retest", id)
	for _, payload := range []string{
		`{"result":"pass","summary":"test","evidence_attachments":[{"path":"attachments/other-user.png"}]}`,
		`{"result":"pass","summary":"test","tester_id":2}`,
		`{"result":"pass","summary":"test"}{}`,
	} {
		response := retestHTTP(router, http.MethodPost, path, "application/json", strings.NewReader(payload), 1)
		require.Equal(t, http.StatusBadRequest, response.Code, response.Body.String())
	}
	config.AppConfig.Storage.MaxRequestSize = 512
	for _, unknownLength := range []bool{false, true} {
		body, contentType := retestMultipart(t, `{"result":"pass","summary":"test"}`, bytes.Repeat([]byte("x"), 1024))
		request := httptest.NewRequest(http.MethodPost, path, body)
		request.Header.Set("Content-Type", contentType)
		request.Header.Set("X-Test-User", "1")
		if unknownLength {
			request.ContentLength = -1
		}
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		require.Equal(t, http.StatusRequestEntityTooLarge, response.Code, response.Body.String())
	}
}

func TestRetestUploadRollbackCompensatesAndQueuesFailedCleanup(t *testing.T) {
	for _, failedCleanup := range []bool{false, true} {
		t.Run(fmt.Sprint(failedCleanup), func(t *testing.T) {
			var wrappers []func(storage.StorageService) storage.StorageService
			if failedCleanup {
				wrappers = append(wrappers, func(store storage.StorageService) storage.StorageService { return &failingAttachmentDelete{store} })
			}
			router, db, id, base := retestControllerSetup(t, wrappers...)
			require.NoError(t, db.Callback().Create().Before("gorm:create").Register("test:fail-retest", func(tx *gorm.DB) {
				if tx.Statement.Table == "vulnerability_timeline" {
					tx.AddError(errors.New("injected failure"))
				}
			}))
			body, contentType := retestMultipart(t, `{"result":"pass","summary":"test"}`, pngAttachment(t))
			response := retestHTTP(router, http.MethodPost, fmt.Sprintf("/vulnerabilities/%d/retest", id), contentType, body, 1)
			require.NotEqual(t, http.StatusCreated, response.Code)
			var count int64
			require.NoError(t, db.Model(&model.VulnerabilityRetest{}).Count(&count).Error)
			require.Zero(t, count)
			require.NoError(t, db.Model(&model.FileCleanupTask{}).Count(&count).Error)
			if failedCleanup {
				require.EqualValues(t, 1, count)
			} else {
				require.Zero(t, count)
				require.NoError(t, filepath.WalkDir(base, func(_ string, entry os.DirEntry, err error) error {
					require.NoError(t, err)
					require.True(t, entry.IsDir(), "orphan evidence file remains")
					return nil
				}))
			}
		})
	}
}
