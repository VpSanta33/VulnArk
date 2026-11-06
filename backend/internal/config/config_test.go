package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const testJWT = "config-test-only-jwt-value-with-more-than-32-bytes"
const testMFA = "config-test-only-aes-key-bytes!!"
const testDatabasePassword = "config-test-only-db-password"

func isolatedConfigEnvironment(t *testing.T) {
	t.Helper()
	var clearFields func(reflect.Type, string)
	clearFields = func(typ reflect.Type, prefix string) {
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			key := prefix + field.Tag.Get("mapstructure")
			if field.Type.Kind() == reflect.Struct {
				clearFields(field.Type, key+".")
				continue
			}
			name := strings.ToUpper(strings.ReplaceAll(key, ".", "_"))
			t.Setenv(name, "")
			if err := os.Unsetenv(name); err != nil {
				t.Fatal(err)
			}
		}
	}
	clearFields(reflect.TypeOf(Config{}), "")
}

func privateConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "private.yaml")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VULNARK_CONFIG", path)
	return path
}

func validConfigYAML() string {
	return "database:\n  password: " + testDatabasePassword + "\njwt:\n  secret: " + testJWT + "\nsecurity:\n  mfa_encryption_key: " + testMFA + "\n"
}

func TestReadConfigPrivateFileAndDefaults(t *testing.T) {
	isolatedConfigEnvironment(t)
	privateConfig(t, validConfigYAML())
	before := AppConfig
	cfg, err := ReadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if AppConfig != before {
		t.Fatal("ReadConfig changed global AppConfig")
	}
	if cfg.JWT.Secret != testJWT || cfg.Security.MFAEncryptionKey != testMFA {
		t.Fatal("private configuration not loaded")
	}
	if cfg.Server.Host != "127.0.0.1" || len(cfg.Server.TrustedProxies) != 0 {
		t.Fatal("unsafe server defaults")
	}
	if cfg.Storage.MaxFileSize != 10<<20 || cfg.Storage.MaxFiles != 5 || cfg.Storage.MaxRequestSize != 50<<20 {
		t.Fatalf("unexpected storage defaults: %+v", cfg.Storage)
	}
	if cfg.CORS.AllowCredentials || len(cfg.CORS.AllowedOrigins) == 0 {
		t.Fatal("unsafe CORS defaults")
	}
	for _, origin := range cfg.CORS.AllowedOrigins {
		if strings.Contains(origin, "*") {
			t.Fatal("wildcard CORS default")
		}
	}
}

func TestReadConfigExplicitEnvironmentKeysAbsentFromYAML(t *testing.T) {
	isolatedConfigEnvironment(t)
	privateConfig(t, "server:\n  port: '9090'\n")
	t.Setenv("JWT_SECRET", testJWT)
	t.Setenv("SECURITY_MFA_ENCRYPTION_KEY", testMFA)
	t.Setenv("DATABASE_PASSWORD", testDatabasePassword)
	t.Setenv("STORAGE_MAX_FILE_SIZE", "2048")
	t.Setenv("STORAGE_MAX_FILES", "2")
	t.Setenv("STORAGE_MAX_REQUEST_SIZE", "8192")
	t.Setenv("SERVER_TRUSTED_PROXIES", "127.0.0.1,10.0.0.0/8")
	cfg, err := ReadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.JWT.Secret != testJWT || cfg.Security.MFAEncryptionKey != testMFA || cfg.Database.Password != testDatabasePassword {
		t.Fatal("explicit secret environment binding failed")
	}
	if cfg.Storage.MaxFileSize != 2048 || cfg.Storage.MaxFiles != 2 || cfg.Storage.MaxRequestSize != 8192 {
		t.Fatal("storage environment overrides failed")
	}
	if len(cfg.Server.TrustedProxies) != 2 {
		t.Fatalf("proxy environment override failed: %v", cfg.Server.TrustedProxies)
	}
}

func TestReadConfigEnvironmentOverridesAndEmptyFailsClosed(t *testing.T) {
	isolatedConfigEnvironment(t)
	privateConfig(t, validConfigYAML())
	t.Setenv("JWT_SECRET", "override-test-only-jwt-value-more-than-32-bytes")
	cfg, err := ReadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(cfg.JWT.Secret, "override-") {
		t.Fatal("environment did not override YAML")
	}
	t.Setenv("JWT_SECRET", "")
	if _, err := ReadConfig(); err == nil {
		t.Fatal("empty JWT_SECRET fell back to file")
	}
}

func TestReadConfigDoesNotReusePriorViperState(t *testing.T) {
	isolatedConfigEnvironment(t)
	privateConfig(t, validConfigYAML())
	if _, err := ReadConfig(); err != nil {
		t.Fatal(err)
	}
	privateConfig(t, "server:\n  mode: release\n")
	if _, err := ReadConfig(); err == nil {
		t.Fatal("secrets leaked from an earlier read")
	}
}

func TestReadConfigMissingPrivateFileNeverFallsBack(t *testing.T) {
	isolatedConfigEnvironment(t)
	t.Setenv("VULNARK_CONFIG", filepath.Join(t.TempDir(), "missing.yaml"))
	if _, err := ReadConfig(); err == nil {
		t.Fatal("missing private config accepted")
	}
	t.Setenv("VULNARK_CONFIG", "")
	if _, err := ReadConfig(); err == nil {
		t.Fatal("empty private config selector accepted")
	}
}

func TestReadConfigErrorsDoNotEchoSecrets(t *testing.T) {
	isolatedConfigEnvironment(t)
	const secret = "do-not-expose-secret-value"
	for _, content := range []string{
		"jwt:\n  secret: [" + secret,
		validConfigYAML() + "storage:\n  max_file_size: " + secret + "\n",
	} {
		privateConfig(t, content)
		_, err := ReadConfig()
		if err == nil {
			t.Fatal("invalid configuration accepted")
		}
		if strings.Contains(err.Error(), secret) {
			t.Fatal("secret included in parse/decode error")
		}
	}
}

func TestValidateRejectsUnsafeConfiguration(t *testing.T) {
	isolatedConfigEnvironment(t)
	privateConfig(t, validConfigYAML())
	valid, err := ReadConfig()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		change func(*Config)
	}{
		{"short JWT", func(c *Config) { c.JWT.Secret = "short" }},
		{"published JWT", func(c *Config) { c.JWT.Secret = "ky6oJtR8MlYpMzJxhaVjWI1O4yeVUbkIJkJdGBzUt89lWifjWuZ1VDgqi68ciRKU" }},
		{"placeholder JWT", func(c *Config) { c.JWT.Secret = "your-jwt-secret-key-at-least-32-characters-long-for-security" }},
		{"missing MFA", func(c *Config) { c.Security.MFAEncryptionKey = "" }},
		{"invalid AES length", func(c *Config) { c.Security.MFAEncryptionKey = "123456789012345678901234" }},
		{"shared MFA and JWT", func(c *Config) { c.JWT.Secret = testMFA; c.Security.MFAEncryptionKey = testMFA }},
		{"weak database password", func(c *Config) { c.Database.Password = "123456" }},
		{"placeholder database password", func(c *Config) { c.Database.Password = "your-secure-database-password-here" }},
		{"wildcard CORS", func(c *Config) { c.CORS.AllowedOrigins = []string{"*"}; c.CORS.AllowCredentials = true }},
		{"wildcard subdomain", func(c *Config) { c.CORS.AllowedOrigins = []string{"https://*.example.com"} }},
		{"CORS URL credentials", func(c *Config) { c.CORS.AllowedOrigins = []string{"https://user:password@example.com"} }},
		{"CORS path", func(c *Config) { c.CORS.AllowedOrigins = []string{"https://example.com/path"} }},
		{"missing CORS origins", func(c *Config) { c.CORS.AllowedOrigins = nil }},
		{"invalid trusted proxy", func(c *Config) { c.Server.TrustedProxies = []string{"*"} }},
		{"negative file size", func(c *Config) { c.Storage.MaxFileSize = -1 }},
		{"request smaller than file", func(c *Config) { c.Storage.MaxRequestSize = c.Storage.MaxFileSize - 1 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := *valid
			tc.change(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("unsafe configuration accepted")
			}
		})
	}
}

func TestPublicConfigurationsContainNoCredentials(t *testing.T) {
	isolatedConfigEnvironment(t)
	for _, name := range []string{"config.yaml", "config.example.yaml"} {
		path, err := filepath.Abs(filepath.Join("..", "..", "configs", name))
		if err != nil {
			t.Fatal(err)
		}
		t.Setenv("VULNARK_CONFIG", path)
		if _, err := ReadConfig(); err == nil {
			t.Fatalf("%s contains usable credentials", name)
		}
		t.Setenv("JWT_SECRET", testJWT)
		t.Setenv("SECURITY_MFA_ENCRYPTION_KEY", testMFA)
		t.Setenv("DATABASE_PASSWORD", testDatabasePassword)
		if _, err := ReadConfig(); err != nil {
			t.Fatalf("%s cannot be configured by environment: %v", name, err)
		}
		for _, key := range []string{"JWT_SECRET", "SECURITY_MFA_ENCRYPTION_KEY", "DATABASE_PASSWORD"} {
			if err := os.Unsetenv(key); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestReadConfigPrivateOutboundOrigins(t *testing.T) {
	isolatedConfigEnvironment(t)
	privateConfig(t, validConfigYAML())
	t.Setenv("SECURITY_OUTBOUND_PRIVATE_ORIGINS", "http://127.0.0.1:11434,https://ai.internal:8443")
	cfg, err := ReadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Security.OutboundPrivateOrigins) != 2 {
		t.Fatalf("origin env decode failed: %v", cfg.Security.OutboundPrivateOrigins)
	}
	t.Setenv("SECURITY_OUTBOUND_PRIVATE_ORIGINS", "http://*.internal")
	if _, err := ReadConfig(); err == nil {
		t.Fatal("wildcard private origin accepted")
	}
}
