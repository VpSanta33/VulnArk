package controller

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"vulnark/internal/model"
	"vulnark/internal/repository"
	"vulnark/internal/service"
)

type aiConflictService struct {
	service.AIService
	err error
}

func (s aiConflictService) SendMessageContext(ctx context.Context, userID uint, request *model.AIChatRequest) (*model.AIChatResponse, error) {
	return nil, s.err
}

func TestAIControllerLeaseConflictsReturn409(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, conflict := range []error{repository.ErrAIConversationBusy, repository.ErrAILeaseLost, repository.ErrAIConversationInactive} {
		t.Run(conflict.Error(), func(t *testing.T) {
			router := gin.New()
			router.POST("/chat", func(ctx *gin.Context) {
				ctx.Set("user_id", uint(7))
				NewAIController(aiConflictService{err: conflict}).SendMessage(ctx)
			})
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, "/chat", strings.NewReader(`{"session_id":"test","message":"hello"}`))
			request.Header.Set("Content-Type", "application/json")
			router.ServeHTTP(recorder, request)
			require.Equal(t, http.StatusConflict, recorder.Code)
		})
	}
}

type aiConfigurationService struct{ service.AIService }

func (aiConfigurationService) GetAIConfiguration(uint) (*model.AIConfiguration, error) {
	return &model.AIConfiguration{APIKey: "hidden-secret", Enabled: true}, nil
}
func TestAIConfigurationResponseReportsStoredKeyWithoutLeakingIt(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/config", func(ctx *gin.Context) {
		ctx.Set("user_id", uint(7))
		NewAIController(aiConfigurationService{}).GetAIConfiguration(ctx)
	})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest("GET", "/config", nil))
	require.Equal(t, 200, response.Code)
	require.Contains(t, response.Body.String(), `"has_api_key":true`)
	require.NotContains(t, response.Body.String(), "hidden-secret")
	require.NotContains(t, response.Body.String(), `"api_key":`)
}
