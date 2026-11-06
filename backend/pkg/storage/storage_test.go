package storage

import (
	"bytes"
	"errors"
	"image"
	"image/color"
	"image/png"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func screenshotPNG(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 3, 2))
	img.Set(1, 1, color.RGBA{R: 255, A: 255})
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestScreenshotValidationAndNormalization(t *testing.T) {
	s := &LocalStorageService{basePath: t.TempDir()}
	data := append(screenshotPNG(t), []byte("<script>payload</script>")...)
	info, err := s.UploadFromReader(bytes.NewReader(data), "not-an-image.html", "attachments", int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if info.MimeType != "image/png" || filepath.Ext(info.Filename) != ".png" {
		t.Fatalf("unexpected metadata: %+v", info)
	}
	file, err := s.OpenFile(info.FilePath)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := io.ReadAll(file)
	file.Close()
	if err != nil || bytes.Contains(stored, []byte("<script>")) {
		t.Fatalf("payload not stripped: %v", err)
	}
	if _, _, err := image.Decode(bytes.NewReader(stored)); err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{"", "<svg><script>alert(1)</script></svg>", "GIF89a broken", "\x89PNG\r\n\x1a\ninvalid"} {
		if _, err := s.UploadFromReader(strings.NewReader(input), "image.png", "attachments", int64(len(input))); err == nil {
			t.Errorf("accepted invalid image %q", input)
		}
	}
	if s.GetFileURL(info.FilePath) != "" {
		t.Fatal("private file has public URL")
	}
	if _, err := s.GeneratePresignedURL(info.FilePath, 0); err == nil {
		t.Fatal("private file has unsigned URL")
	}
}

func TestImageDimensionLimit(t *testing.T) {
	var buf bytes.Buffer
	if err := png.Encode(&buf, image.NewGray(image.Rect(0, 0, MaxImageDimension+1, 1))); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := normalizeScreenshot(&buf, DefaultMaxScreenshotSize); err == nil {
		t.Fatal("accepted overlong image")
	}
	if _, _, _, err := normalizeScreenshot(strings.NewReader(strings.Repeat("a", 32)), 16); err == nil {
		t.Fatal("accepted oversized content")
	}
}

func TestStorageTraversalAndSymlinks(t *testing.T) {
	base, outside := t.TempDir(), t.TempDir()
	s := &LocalStorageService{basePath: base}
	secret := filepath.Join(outside, "secret")
	if err := os.WriteFile(secret, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"../secret", outside + "/secret", "attachments/../../secret", "attachments\\secret", "attachments/../secret"} {
		if _, err := s.OpenFile(path); err == nil {
			t.Errorf("opened traversal %q", path)
		}
		if err := s.DeleteFile(path); err == nil {
			t.Errorf("deleted traversal %q", path)
		}
	}
	if err := os.Symlink(outside, filepath.Join(base, "attachments")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.OpenFile("attachments/secret"); err == nil {
		t.Fatal("followed directory symlink")
	}
	if err := s.DeleteFile("attachments/secret"); err == nil {
		t.Fatal("deleted through directory symlink")
	}
	data := screenshotPNG(t)
	if _, err := s.UploadFromReader(bytes.NewReader(data), "image.png", "attachments", int64(len(data))); err == nil {
		t.Fatal("uploaded through directory symlink")
	}
	if err := os.Remove(filepath.Join(base, "attachments")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(base, "attachments"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(base, "attachments", "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.OpenFile("attachments/link"); err == nil {
		t.Fatal("followed final symlink")
	}
	if err := s.DeleteFile("attachments/link"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(secret); err != nil {
		t.Fatal("deleted symlink target")
	}
	if err := s.DeleteFile("attachments/missing"); err != nil {
		t.Fatal("delete must be idempotent", err)
	}
	if _, err := s.UploadFromReader(bytes.NewReader(data), "image.png", "attachments-evil", int64(len(data))); err == nil {
		t.Fatal("accepted prefix directory")
	}
}

type failingReader struct{ done bool }

func (r *failingReader) Read(p []byte) (int, error) {
	if !r.done {
		r.done = true
		return copy(p, "partial"), nil
	}
	return 0, errors.New("injected read error")
}

func TestFailedWriteRemovesPartialFile(t *testing.T) {
	s := &LocalStorageService{basePath: t.TempDir()}
	if _, err := s.UploadFromReader(&failingReader{}, "report.pdf", "reports", 100); err == nil {
		t.Fatal("expected read failure")
	}
	count := 0
	if err := filepath.WalkDir(s.basePath, func(_ string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			count++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("partial file retained")
	}
	if _, err := s.UploadFromReader(strings.NewReader("short"), "report.pdf", "reports", 100); err == nil {
		t.Fatal("accepted size mismatch")
	}
}
