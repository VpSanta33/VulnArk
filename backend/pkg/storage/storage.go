package storage

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"image"
	"image/gif"
	"image/jpeg"
	"image/png"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"vulnark/internal/config"
)

const (
	DefaultMaxScreenshotSize    int64 = 5 << 20
	DefaultMaxScreenshots             = 5
	MaxScreenshotTotalSize      int64 = 20 << 20
	DefaultMaxUploadRequestSize int64 = 21 << 20
	MaxImageDimension                 = 8192
	MaxImagePixels                    = 20_000_000
)

// UploadLimits applies safe defaults, including when configuration is absent.
func UploadLimits() (fileSize int64, files int, requestSize int64) {
	fileSize, files, requestSize = DefaultMaxScreenshotSize, DefaultMaxScreenshots, DefaultMaxUploadRequestSize
	if config.AppConfig != nil {
		cfg := config.AppConfig.Storage
		if cfg.MaxFileSize > 0 && cfg.MaxFileSize < fileSize {
			fileSize = cfg.MaxFileSize
		}
		if cfg.MaxFiles > 0 && cfg.MaxFiles < files {
			files = cfg.MaxFiles
		}
		if cfg.MaxRequestSize > 0 && cfg.MaxRequestSize < requestSize {
			requestSize = cfg.MaxRequestSize
		}
	}
	return
}

type StorageService interface {
	UploadFile(file *multipart.FileHeader, folder string) (*FileInfo, error)
	UploadFromReader(reader io.Reader, filename, folder string, size int64) (*FileInfo, error)
	DeleteFile(filePath string) error
	OpenFile(filePath string) (*os.File, error)
	GetFileURL(filePath string) string
	GetFileInfo(filePath string) (*FileInfo, error)
	GeneratePresignedURL(filePath string, expiration time.Duration) (string, error)
}

// CleanupError identifies a failed partial write whose removal also failed.
// Callers must enqueue FilePath for persistent retry before returning the error.
type CleanupError struct {
	FilePath string
	Err      error
}

func (e *CleanupError) Error() string { return "存储写入及清理失败" }
func (e *CleanupError) Unwrap() error { return e.Err }

type FileInfo struct {
	Filename     string `json:"filename"`
	OriginalName string `json:"original_name"`
	FilePath     string `json:"-"`
	FileSize     int64  `json:"file_size"`
	FileType     string `json:"file_type"`
	MimeType     string `json:"mime_type"`
	DownloadURL  string `json:"download_url,omitempty"`
}

type LocalStorageService struct{ basePath string }

func NewLocalStorageService() StorageService {
	basePath := "./uploads"
	if config.AppConfig != nil && config.AppConfig.Storage.LocalPath != "" {
		basePath = config.AppConfig.Storage.LocalPath
	}
	return &LocalStorageService{basePath: basePath}
}

func sanitizeFilename(filename string) (string, error) {
	if filename == "" || filename == "." || filename == ".." || len(filename) > 255 || strings.ContainsAny(filename, "/\\") || strings.IndexFunc(filename, unicode.IsControl) >= 0 {
		return "", errors.New("无效的文件名")
	}
	return filename, nil
}

func sanitizeFolderPath(folder string) (string, error) {
	if !filepath.IsLocal(folder) || strings.Contains(folder, "\\") {
		return "", errors.New("无效的目录")
	}
	for _, part := range strings.Split(folder, "/") {
		if part == "" || part == "." || part == ".." {
			return "", errors.New("无效的目录")
		}
	}
	first := strings.Split(folder, "/")[0]
	switch first {
	case "reports", "attachments", "avatars", "temp", "uploads":
		return folder, nil
	}
	return "", errors.New("不允许的目录")
}

// os.Root confines every operation even if a path component is replaced while
// the request runs. Explicit Lstat checks also reject pre-existing symlinks.
func (s *LocalStorageService) openDirectory(relative string, create bool) (*os.Root, error) {
	if create {
		if err := os.MkdirAll(s.basePath, 0700); err != nil {
			return nil, err
		}
	}
	stat, err := os.Lstat(s.basePath)
	if err != nil {
		return nil, err
	}
	if !stat.IsDir() || stat.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("无效的存储根目录")
	}
	base, err := os.OpenRoot(s.basePath)
	if err != nil {
		return nil, err
	}
	current := base
	prefix := ""
	for _, part := range strings.Split(filepath.ToSlash(relative), "/") {
		if part == "" || part == "." || part == ".." {
			if current != base {
				current.Close()
			}
			base.Close()
			return nil, errors.New("无效的存储路径")
		}
		prefix = filepath.Join(prefix, part)
		stat, statErr := base.Lstat(prefix)
		if errors.Is(statErr, os.ErrNotExist) && create {
			statErr = current.Mkdir(part, 0700)
			if statErr == nil || errors.Is(statErr, os.ErrExist) {
				stat, statErr = base.Lstat(prefix)
			}
		}
		if statErr != nil || stat == nil || !stat.IsDir() || stat.Mode()&os.ModeSymlink != 0 {
			if current != base {
				current.Close()
			}
			base.Close()
			if statErr != nil {
				return nil, statErr
			}
			return nil, errors.New("存储目录不允许符号链接")
		}
		next, openErr := current.OpenRoot(part)
		if current != base {
			current.Close()
		}
		if openErr != nil {
			base.Close()
			return nil, openErr
		}
		current = next
	}
	if current != base {
		base.Close()
	}
	return current, nil
}

func (s *LocalStorageService) validateFilePath(filePath string) (string, error) {
	if !filepath.IsLocal(filePath) || strings.Contains(filePath, "\\") {
		return "", errors.New("无效的存储路径")
	}
	for _, part := range strings.Split(filePath, "/") {
		if part == "" || part == "." || part == ".." {
			return "", errors.New("无效的存储路径")
		}
	}
	if _, err := sanitizeFolderPath(path.Dir(filePath)); err != nil {
		return "", err
	}
	return filePath, nil
}

func (s *LocalStorageService) UploadFile(file *multipart.FileHeader, folder string) (*FileInfo, error) {
	if file == nil {
		return nil, errors.New("缺少上传文件")
	}
	if _, err := sanitizeFilename(file.Filename); err != nil {
		return nil, err
	}
	src, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer src.Close()
	return s.UploadFromReader(src, file.Filename, folder, file.Size)
}

// normalizeScreenshot decodes real images under bounded dimensions and rewrites
// them, stripping appended payloads and untrusted metadata. Animated GIFs become
// a single screenshot frame.
func normalizeScreenshot(reader io.Reader, limit int64) ([]byte, string, string, error) {
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, "", "", err
	}
	if len(data) == 0 || int64(len(data)) > limit {
		return nil, "", "", errors.New("截图为空或超过单文件大小限制")
	}
	cfg, format, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil || (format != "png" && format != "jpeg" && format != "gif") {
		return nil, "", "", errors.New("截图必须为有效的PNG、JPEG或GIF图像")
	}
	if cfg.Width <= 0 || cfg.Height <= 0 || cfg.Width > MaxImageDimension || cfg.Height > MaxImageDimension || int64(cfg.Width)*int64(cfg.Height) > MaxImagePixels {
		return nil, "", "", errors.New("截图尺寸或像素总量超过限制")
	}
	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, "", "", errors.New("截图内容损坏")
	}
	var out bytes.Buffer
	writer := &limitedImageWriter{buf: &out, remaining: limit}
	ext, mime := ".png", "image/png"
	switch format {
	case "jpeg":
		ext, mime = ".jpg", "image/jpeg"
		err = jpeg.Encode(writer, img, &jpeg.Options{Quality: 90})
	case "gif":
		ext, mime = ".gif", "image/gif"
		err = gif.Encode(writer, img, nil)
	default:
		err = png.Encode(writer, img)
	}
	if err != nil {
		return nil, "", "", errors.New("截图编码失败或超过大小限制")
	}
	return out.Bytes(), ext, mime, nil
}

type limitedImageWriter struct {
	buf       *bytes.Buffer
	remaining int64
}

func (w *limitedImageWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > w.remaining {
		return 0, errors.New("图像超过大小限制")
	}
	n, err := w.buf.Write(p)
	w.remaining -= int64(n)
	return n, err
}

func (s *LocalStorageService) UploadFromReader(reader io.Reader, filename, folder string, size int64) (result *FileInfo, resultErr error) {
	if reader == nil {
		return nil, errors.New("缺少上传内容")
	}
	cleanFolder, err := sanitizeFolderPath(folder)
	if err != nil {
		return nil, err
	}
	cleanName, err := sanitizeFilename(filename)
	if err != nil {
		return nil, err
	}
	ext := strings.ToLower(filepath.Ext(cleanName))
	maxSize := GetMaxReportSize()
	mimeType := s.getMimeType(ext)
	if strings.Split(cleanFolder, "/")[0] == "attachments" {
		maxSize, _, _ = UploadLimits()
		if size > maxSize {
			return nil, errors.New("截图超过单文件大小限制")
		}
		data, actualExt, actualMime, err := normalizeScreenshot(reader, maxSize)
		if err != nil {
			return nil, err
		}
		reader, size, ext, mimeType = bytes.NewReader(data), int64(len(data)), actualExt, actualMime
	}
	if size < 0 || size > maxSize {
		return nil, errors.New("文件大小超过限制")
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return nil, err
	}
	uniqueName := hex.EncodeToString(random) + ext
	directory := path.Join(cleanFolder, time.Now().Format("2006/01/02"))
	dir, err := s.openDirectory(directory, true)
	if err != nil {
		return nil, fmt.Errorf("创建存储目录失败: %w", err)
	}
	defer dir.Close()
	dst, err := dir.OpenFile(uniqueName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	committed := false
	defer func() {
		dst.Close()
		if !committed {
			if cleanupErr := dir.Remove(uniqueName); cleanupErr != nil && !errors.Is(cleanupErr, os.ErrNotExist) {
				resultErr = &CleanupError{FilePath: path.Join(directory, uniqueName), Err: errors.Join(resultErr, cleanupErr)}
			}
		}
	}()
	written, err := io.Copy(dst, io.LimitReader(reader, maxSize+1))
	if err != nil {
		return nil, fmt.Errorf("写入文件失败: %w", err)
	}
	if written > maxSize || (size > 0 && written != size) {
		return nil, errors.New("文件大小超过限制或与声明不一致")
	}
	if err := dst.Sync(); err != nil {
		return nil, err
	}
	if err := dst.Close(); err != nil {
		return nil, err
	}
	committed = true
	return &FileInfo{Filename: uniqueName, OriginalName: cleanName, FilePath: filepath.ToSlash(filepath.Join(directory, uniqueName)), FileSize: written, FileType: s.getFileType(ext), MimeType: mimeType}, nil
}

func (s *LocalStorageService) OpenFile(filePath string) (*os.File, error) {
	relative, err := s.validateFilePath(filePath)
	if err != nil {
		return nil, err
	}
	dir, err := s.openDirectory(filepath.Dir(relative), false)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	before, err := dir.Lstat(filepath.Base(relative))
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, errors.New("存储内容不是普通文件")
	}
	file, err := dir.Open(filepath.Base(relative))
	if err != nil {
		return nil, err
	}
	stat, err := file.Stat()
	if err != nil || !stat.Mode().IsRegular() || !os.SameFile(before, stat) {
		file.Close()
		return nil, errors.New("存储内容不是普通文件")
	}
	return file, nil
}

func (s *LocalStorageService) DeleteFile(filePath string) error {
	relative, err := s.validateFilePath(filePath)
	if err != nil {
		return err
	}
	dir, err := s.openDirectory(filepath.Dir(relative), false)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer dir.Close()
	// Remove unlinks a final symlink itself without following its target.
	err = dir.Remove(filepath.Base(relative))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// Storage paths are private. Callers must use an authenticated resource endpoint.
func (s *LocalStorageService) GetFileURL(string) string { return "" }
func (s *LocalStorageService) GeneratePresignedURL(string, time.Duration) (string, error) {
	return "", errors.New("本地私有存储不支持公开链接")
}
func (s *LocalStorageService) GetFileInfo(filePath string) (*FileInfo, error) {
	file, err := s.OpenFile(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		return nil, err
	}
	header := make([]byte, 512)
	n, err := file.Read(header)
	if err != nil && err != io.EOF {
		return nil, err
	}
	name, ext := filepath.Base(filePath), filepath.Ext(filePath)
	return &FileInfo{Filename: name, OriginalName: name, FilePath: filePath, FileSize: stat.Size(), FileType: s.getFileType(ext), MimeType: http.DetectContentType(header[:n])}, nil
}

func (s *LocalStorageService) getFileType(ext string) string {
	switch strings.ToLower(ext) {
	case ".jpg", ".jpeg", ".png", ".gif":
		return "image"
	case ".pdf":
		return "pdf"
	case ".doc", ".docx":
		return "document"
	default:
		return "other"
	}
}
func (s *LocalStorageService) getMimeType(ext string) string {
	switch strings.ToLower(ext) {
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".png":
		return "image/png"
	case ".gif":
		return "image/gif"
	case ".pdf":
		return "application/pdf"
	case ".doc":
		return "application/msword"
	case ".docx":
		return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
	default:
		return "application/octet-stream"
	}
}
func NewStorageService() StorageService { return NewLocalStorageService() }
func ValidateFileType(filename string, allowedTypes []string) bool {
	if len(allowedTypes) == 0 {
		return true
	}
	for _, allowed := range allowedTypes {
		if strings.EqualFold(filepath.Ext(filename), allowed) {
			return true
		}
	}
	return false
}
func ValidateFileSize(size, maxSize int64) bool {
	return size >= 0 && (maxSize <= 0 || size <= maxSize)
}
func GetAllowedReportTypes() []string { return []string{".pdf", ".doc", ".docx"} }
func GetMaxReportSize() int64         { return 100 << 20 }
