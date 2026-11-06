package controller

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"vulnark/internal/middleware"
	"vulnark/internal/model"
	"vulnark/internal/repository"
	"vulnark/internal/service"
	"vulnark/pkg/storage"
	"vulnark/pkg/utils"
)

// VulnerabilityRetestController exposes independent vulnerability verification
// endpoints. Routes should also install middleware.RequirePermission("vuln:verify", ...);
// the service repeats the check so direct handler use fails closed.
type VulnerabilityRetestController struct {
	service service.VulnerabilityRetestService
	storage storage.StorageService
}

func NewVulnerabilityRetestController(retestService service.VulnerabilityRetestService, storageServices ...storage.StorageService) *VulnerabilityRetestController {
	var fileStorage storage.StorageService
	if len(storageServices) > 0 {
		fileStorage = storageServices[0]
	}
	return &VulnerabilityRetestController{service: retestService, storage: fileStorage}
}

// NewRetestController is a short constructor alias for route wiring.
func NewRetestController(retestService service.VulnerabilityRetestService, storageServices ...storage.StorageService) *VulnerabilityRetestController {
	return NewVulnerabilityRetestController(retestService, storageServices...)
}

// ListRetests 获取漏洞复测记录
// @Summary 获取漏洞复测记录
// @Description 需要 vuln:read 权限及目标漏洞访问权限。返回独立复测记录和证据显示信息，不返回私有存储路径。
// @Tags 漏洞复测
// @Produce json
// @Security ApiKeyAuth
// @Param id path int true "漏洞ID" minimum(1)
// @Success 200 {object} model.Response{data=[]model.VulnerabilityRetestInfo}
// @Failure 400 {object} model.Response "漏洞ID无效"
// @Failure 401 {object} model.Response "未认证"
// @Failure 403 {object} model.Response "缺少读取权限或无权访问漏洞"
// @Failure 404 {object} model.Response "漏洞不存在"
// @Failure 500 {object} model.Response "复测服务不可用或处理失败"
// @Router /api/v1/vulnerabilities/{id}/retests [get]
func (c *VulnerabilityRetestController) ListRetests(ctx *gin.Context) {
	id, ok := parseRetestVulnerabilityID(ctx)
	if !ok {
		return
	}
	requesterID, exists := middleware.GetCurrentUserID(ctx)
	if !exists || requesterID == 0 {
		utils.UnauthorizedResponse(ctx, "")
		return
	}
	if c == nil || c.service == nil {
		utils.ServerErrorResponse(ctx, "复测服务不可用")
		return
	}
	items, err := c.service.GetRetests(id, requesterID)
	if err != nil {
		writeRetestError(ctx, err)
		return
	}
	utils.SuccessResponse(ctx, items)
}

// CreateRetest 创建独立漏洞复测
// @Summary 创建独立漏洞复测
// @Description 需要 vuln:read 和 vuln:verify 权限及漏洞参与范围或管理/审计权限；当前修复负责人不能复测自己的修复。pass 仅允许 fixed 转为 verified，fail 可将 fixed、verified 或 closed 转回 processing。multipart/form-data 使用唯一的 data 字段传入 JSON（如 {"result":"pass","summary":"修复已验证"}），证据文件使用重复的 evidence 字段；也可使用 application/json 直接提交同样的 result/summary 对象且不带证据。result 必须为 pass 或 fail，summary 为 1-10000 字符；不接受客户端提供的存储路径或证据元数据。证据每个最多 5 MiB、最多 5 个、合计最多 20 MiB，部署配置可进一步收紧大小和数量。
// @Tags 漏洞复测
// @Accept mpfd,json
// @Produce json
// @Security ApiKeyAuth
// @Param id path int true "漏洞ID" minimum(1)
// @Param data formData string true "JSON对象，包含result（pass/fail）和summary（1-10000字符）"
// @Param evidence formData file false "可重复提交的证据文件；无证据时可省略"
// @Success 201 {object} model.Response{data=model.VulnerabilityRetestInfo} "复测已创建"
// @Failure 400 {object} model.Response "请求格式、复测内容或证据无效"
// @Failure 401 {object} model.Response "未认证"
// @Failure 403 {object} model.Response "缺少读取或复测权限，或复测者为当前修复负责人"
// @Failure 404 {object} model.Response "漏洞不存在"
// @Failure 409 {object} model.Response "漏洞不是fixed状态、已验证或并发复测冲突"
// @Failure 413 {object} model.Response "复测请求超过大小限制"
// @Failure 429 {object} model.Response "上传请求过于频繁"
// @Failure 500 {object} model.Response "复测服务、存储不可用或处理失败"
// @Router /api/v1/vulnerabilities/{id}/retest [post]
func (c *VulnerabilityRetestController) CreateRetest(ctx *gin.Context) {
	id, ok := parseRetestVulnerabilityID(ctx)
	if !ok {
		return
	}
	testerID, exists := middleware.GetCurrentUserID(ctx)
	if !exists || testerID == 0 {
		utils.UnauthorizedResponse(ctx, "")
		return
	}
	if c == nil || c.service == nil {
		utils.ServerErrorResponse(ctx, "复测服务不可用")
		return
	}
	maxSize, maxFiles, maxRequest := storage.UploadLimits()
	ctx.Request.Body = http.MaxBytesReader(ctx.Writer, ctx.Request.Body, maxRequest)
	defer func() {
		if ctx.Request.MultipartForm != nil {
			_ = ctx.Request.MultipartForm.RemoveAll()
		}
	}()
	if ctx.Request.ContentLength > maxRequest {
		utils.ErrorResponse(ctx, http.StatusRequestEntityTooLarge, "复测请求超过大小限制")
		return
	}
	var req model.VulnerabilityRetestRequest
	files, err := decodeRetestRequest(ctx.Request, &req)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			utils.ErrorResponse(ctx, http.StatusRequestEntityTooLarge, "复测请求超过大小限制")
		} else {
			utils.BadRequestResponse(ctx, "复测请求格式错误")
		}
		return
	}
	if len(files) > maxFiles {
		utils.BadRequestResponse(ctx, "复测证据数量超过限制")
		return
	}
	if len(files) > 0 && c.storage == nil {
		utils.ServerErrorResponse(ctx, "复测存储服务不可用")
		return
	}
	var total int64
	for _, file := range files {
		if file == nil || file.Size <= 0 || file.Size > maxSize {
			utils.BadRequestResponse(ctx, "复测证据为空或超过大小限制")
			return
		}
		total += file.Size
	}
	if total > storage.MaxScreenshotTotalSize {
		utils.BadRequestResponse(ctx, "复测证据总大小超过限制")
		return
	}
	var uploaded []*storage.FileInfo
	committed := false
	defer func() {
		if committed {
			return
		}
		var failed []string
		for _, info := range uploaded {
			if info != nil && info.FilePath != "" {
				if err := c.storage.DeleteFile(info.FilePath); err != nil {
					failed = append(failed, info.FilePath)
				}
			}
		}
		if len(failed) > 0 {
			if err := c.service.QueueFileCleanup(failed); err != nil {
				logrus.Error("无法持久化复测证据清理任务")
			}
		}
	}()
	for _, file := range files {
		if file == nil || file.Size <= 0 || file.Size > maxSize {
			utils.BadRequestResponse(ctx, "复测证据为空或超过大小限制")
			return
		}
		info, uploadErr := c.storage.UploadFile(file, "attachments")
		if uploadErr != nil {
			var cleanup *storage.CleanupError
			if errors.As(uploadErr, &cleanup) {
				uploaded = append(uploaded, &storage.FileInfo{FilePath: cleanup.FilePath})
			}
			utils.BadRequestResponse(ctx, "复测证据上传失败")
			return
		}
		if info == nil {
			utils.ServerErrorResponse(ctx, "复测证据上传失败")
			return
		}
		uploaded = append(uploaded, info)
		req.EvidenceAttachments = append(req.EvidenceAttachments, model.VulnerabilityRetestEvidenceRequest{
			Filename: info.Filename, OriginalName: info.OriginalName, Path: info.FilePath,
			FileSize: info.FileSize, FileType: info.FileType, MimeType: info.MimeType,
		})
	}
	result, err := c.service.CreateRetest(id, testerID, &req)
	if err != nil {
		writeRetestError(ctx, err)
		return
	}
	committed = true
	ctx.JSON(http.StatusCreated, model.NewSuccessResponse(result))
}

func decodeRetestRequest(request *http.Request, req *model.VulnerabilityRetestRequest) ([]*multipart.FileHeader, error) {
	contentType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil {
		return nil, err
	}
	var reader io.Reader = request.Body
	var files []*multipart.FileHeader
	if contentType == "multipart/form-data" {
		if err := request.ParseMultipartForm(1 << 20); err != nil {
			return nil, err
		}
		form := request.MultipartForm
		if form == nil || len(form.Value["data"]) != 1 || len(form.Value) != 1 {
			return nil, errors.New("缺少复测数据")
		}
		reader = strings.NewReader(form.Value["data"][0])
		files = form.File["evidence"]
		for key := range form.File {
			if key != "evidence" {
				return nil, errors.New("未知证据字段")
			}
		}
	} else if contentType != "application/json" {
		return nil, errors.New("不支持的请求格式")
	}
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(req); err != nil {
		return nil, err
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, errors.New("包含多余数据")
	}
	if len(req.EvidenceAttachments) > 0 {
		return nil, errors.New("证据必须通过multipart文件上传")
	}
	return files, nil
}

// DownloadEvidence 下载复测证据
// @Summary 下载复测证据
// @Description 需要 vuln:read 权限及目标复测记录访问权限。index 为证据数组的零基索引；成功返回受保护的附件文件流，私有存储路径不对客户端公开。
// @Tags 漏洞复测
// @Produce octet-stream,json
// @Security ApiKeyAuth
// @Param id path int true "漏洞ID" minimum(1)
// @Param retest_id path int true "复测记录ID" minimum(1)
// @Param index path int true "证据数组索引（从0开始）" minimum(0)
// @Success 200 {file} file "复测证据文件"
// @Header 200 {string} Content-Disposition "attachment; filename=..."
// @Header 200 {string} Cache-Control "private, no-store"
// @Failure 400 {object} model.Response "漏洞、复测ID或证据索引无效"
// @Failure 401 {object} model.Response "未认证"
// @Failure 403 {object} model.Response "缺少读取权限或无权访问复测记录"
// @Failure 404 {object} model.Response "漏洞、复测记录或证据文件不存在"
// @Failure 500 {object} model.Response "复测服务或存储不可用"
// @Router /api/v1/vulnerabilities/{id}/retests/{retest_id}/evidence/{index}/download [get]
func (c *VulnerabilityRetestController) DownloadEvidence(ctx *gin.Context) {
	id, ok := parseRetestVulnerabilityID(ctx)
	if !ok {
		return
	}
	userID, exists := middleware.GetCurrentUserID(ctx)
	if !exists || userID == 0 {
		utils.UnauthorizedResponse(ctx, "")
		return
	}
	retestID, err := strconv.ParseUint(ctx.Param("retest_id"), 10, 32)
	index, indexErr := strconv.Atoi(ctx.Param("index"))
	if err != nil || retestID == 0 || indexErr != nil || index < 0 {
		utils.BadRequestResponse(ctx, "无效的复测证据ID")
		return
	}
	if c == nil || c.service == nil || c.storage == nil {
		utils.ServerErrorResponse(ctx, "复测服务不可用")
		return
	}
	evidence, err := c.service.GetRetestEvidence(id, uint(retestID), index, userID)
	if err != nil {
		writeRetestError(ctx, err)
		return
	}
	if evidence == nil {
		utils.NotFoundResponse(ctx, "复测证据不存在")
		return
	}
	file, err := c.storage.OpenFile(evidence.FilePath)
	if err != nil {
		utils.NotFoundResponse(ctx, "复测证据不存在")
		return
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		utils.NotFoundResponse(ctx, "复测证据不存在")
		return
	}
	name := evidence.OriginalName
	if name == "" {
		name = "evidence"
	}
	ctx.Header("Content-Type", "application/octet-stream")
	ctx.Header("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name}))
	ctx.Header("Cache-Control", "private, no-store")
	ctx.Header("X-Content-Type-Options", "nosniff")
	ctx.Header("Content-Security-Policy", "default-src 'none'; sandbox")
	http.ServeContent(ctx.Writer, ctx.Request, name, stat.ModTime(), file)
}

func parseRetestVulnerabilityID(ctx *gin.Context) (uint, bool) {
	id, err := strconv.ParseUint(ctx.Param("id"), 10, 32)
	if err != nil || id == 0 {
		utils.BadRequestResponse(ctx, "无效的漏洞ID")
		return 0, false
	}
	return uint(id), true
}

func writeRetestError(ctx *gin.Context, err error) {
	switch {
	case errors.Is(err, service.ErrRetestPermissionDenied), errors.Is(err, service.ErrRetestAccessDenied), errors.Is(err, repository.ErrRetestTesterAssignee), errors.Is(err, repository.ErrRetestScopeDenied):
		utils.ForbiddenResponse(ctx, err.Error())
	case errors.Is(err, repository.ErrRetestNotFound):
		utils.NotFoundResponse(ctx, "复测证据不存在")
	case errors.Is(err, repository.ErrRetestAlreadyVerified), errors.Is(err, repository.ErrRetestConflict):
		utils.ErrorResponse(ctx, http.StatusConflict, err.Error())
	case errors.Is(err, repository.ErrRetestInvalidStatus):
		utils.ErrorResponse(ctx, http.StatusConflict, err.Error())
	case errors.Is(err, service.ErrRetestValidation):
		utils.BadRequestResponse(ctx, err.Error())
	case err != nil && err.Error() == "漏洞不存在":
		utils.NotFoundResponse(ctx, err.Error())
	default:
		utils.ServerErrorResponse(ctx, "复测处理失败")
	}
}
