package config

import (
	"errors"
	"log"
	"net"
	"net/url"
	"os"
	"reflect"
	"strings"

	"github.com/spf13/viper"
	"vulnark/pkg/outbound"
)

// Config 应用配置结构。
type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	Database DatabaseConfig `mapstructure:"database"`
	JWT      JWTConfig      `mapstructure:"jwt"`
	Security SecurityConfig `mapstructure:"security"`
	OSS      OSSConfig      `mapstructure:"oss"`
	Storage  StorageConfig  `mapstructure:"storage"`
	Email    EmailConfig    `mapstructure:"email"`
	Log      LogConfig      `mapstructure:"log"`
	CORS     CORSConfig     `mapstructure:"cors"`
}

type ServerConfig struct {
	Host           string   `mapstructure:"host"`
	Port           string   `mapstructure:"port"`
	Mode           string   `mapstructure:"mode"`
	ReadTimeout    int      `mapstructure:"read_timeout"`
	WriteTimeout   int      `mapstructure:"write_timeout"`
	TrustedProxies []string `mapstructure:"trusted_proxies"`
}

type DatabaseConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
	Database string `mapstructure:"database"`
	Charset  string `mapstructure:"charset"`
}

type JWTConfig struct {
	Secret     string `mapstructure:"secret"`
	ExpireTime int    `mapstructure:"expire_time"`
}

// SecurityConfig 的MFA密钥是原始32字节AES-256密钥，不从JWT密钥派生。
type SecurityConfig struct {
	MFAEncryptionKey       string   `mapstructure:"mfa_encryption_key"`
	OutboundPrivateOrigins []string `mapstructure:"outbound_private_origins"`
}

type OSSConfig struct {
	Provider        string `mapstructure:"provider"`
	AccessKeyID     string `mapstructure:"access_key_id"`
	AccessKeySecret string `mapstructure:"access_key_secret"`
	Bucket          string `mapstructure:"bucket"`
	Endpoint        string `mapstructure:"endpoint"`
	Region          string `mapstructure:"region"`
}

type StorageConfig struct {
	Type           string `mapstructure:"type"`
	LocalPath      string `mapstructure:"local_path"`
	BaseURL        string `mapstructure:"base_url"`
	MaxFileSize    int64  `mapstructure:"max_file_size"`
	MaxFiles       int    `mapstructure:"max_files"`
	MaxRequestSize int64  `mapstructure:"max_request_size"`
}

type EmailConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
	From     string `mapstructure:"from"`
}

type LogConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
	Output string `mapstructure:"output"`
}

type CORSConfig struct {
	Enabled          bool     `mapstructure:"enabled"`
	AllowedOrigins   []string `mapstructure:"allowed_origins"`
	AllowedMethods   []string `mapstructure:"allowed_methods"`
	AllowedHeaders   []string `mapstructure:"allowed_headers"`
	ExposedHeaders   []string `mapstructure:"exposed_headers"`
	AllowCredentials bool     `mapstructure:"allow_credentials"`
	MaxAge           int      `mapstructure:"max_age"`
}

var AppConfig *Config

// ReadConfig 加载独立配置实例，不修改AppConfig或Viper全局状态。
// VULNARK_CONFIG指定私有配置文件；选定文件不可读时绝不回退到示例配置。
// 所有字段支持大写下划线环境变量，包括JWT_SECRET、
// SECURITY_MFA_ENCRYPTION_KEY、DATABASE_PASSWORD，显式空值也会覆盖文件值。
func ReadConfig() (*Config, error) {
	v := viper.New()
	v.SetConfigType("yaml")
	if path, exists := os.LookupEnv("VULNARK_CONFIG"); exists {
		if strings.TrimSpace(path) == "" {
			return nil, errors.New("VULNARK_CONFIG must name a configuration file")
		}
		v.SetConfigFile(path)
	} else {
		v.SetConfigName("config")
		v.AddConfigPath("./configs")
		v.AddConfigPath("../configs")
		v.AddConfigPath(".")
	}

	setDefaults(v)
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AllowEmptyEnv(true)
	v.AutomaticEnv()
	bindConfigEnvironment(v, reflect.TypeOf(Config{}), "")

	if err := v.ReadInConfig(); err != nil {
		// YAML and decode errors can contain supplied secrets; never echo them.
		return nil, errors.New("configuration file could not be read or parsed; check VULNARK_CONFIG and YAML syntax")
	}
	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, errors.New("configuration contains invalid field types")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// LoadConfig 保留主程序入口；测试和可恢复调用使用ReadConfig。
func LoadConfig() {
	cfg, err := ReadConfig()
	if err != nil {
		log.Fatalf("配置加载失败: %v", err)
	}
	AppConfig = cfg
	log.Println("配置加载成功")
}

func bindConfigEnvironment(v *viper.Viper, typ reflect.Type, prefix string) {
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		key := prefix + field.Tag.Get("mapstructure")
		if field.Type.Kind() == reflect.Struct {
			bindConfigEnvironment(v, field.Type, key+".")
			continue
		}
		// Explicit binding lets Unmarshal see environment-only keys absent in YAML.
		_ = v.BindEnv(key, strings.ToUpper(strings.ReplaceAll(key, ".", "_")))
	}
}

func setDefaults(v *viper.Viper) {
	defaults := map[string]interface{}{
		"server.host": "127.0.0.1", "server.port": "8080", "server.mode": "release",
		"server.read_timeout": 120, "server.write_timeout": 120,
		"server.trusted_proxies": []string{},
		"database.host":          "localhost", "database.port": 3306,
		"database.username": "vulnark", "database.database": "vulnark", "database.charset": "utf8mb4",
		"jwt.expire_time": 3600, "oss.provider": "local",
		"storage.type": "local", "storage.local_path": "./uploads", "storage.base_url": "/uploads",
		"storage.max_file_size": int64(10 << 20), "storage.max_files": 5,
		"storage.max_request_size": int64(50 << 20),
		"cors.enabled":             true, "cors.allowed_origins": []string{"http://localhost:8080", "http://127.0.0.1:8080"},
		"cors.allowed_methods":   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"},
		"cors.allowed_headers":   []string{"Origin", "Content-Length", "Content-Type", "Authorization", "X-Requested-With", "Accept"},
		"cors.exposed_headers":   []string{"Content-Length", "Content-Type"},
		"cors.allow_credentials": false, "cors.max_age": 43200,
		"log.level": "info", "log.format": "json", "log.output": "stdout",
	}
	for key, value := range defaults {
		v.SetDefault(key, value)
	}
}

// Validate 只返回字段名及约束，不在错误中输出配置值。
func (cfg *Config) Validate() error {
	if cfg == nil {
		return errors.New("configuration is missing")
	}
	jwt := cfg.JWT.Secret
	if len(jwt) < 32 || jwt != strings.TrimSpace(jwt) || insecureSecret(jwt) {
		return errors.New("JWT_SECRET / jwt.secret must be at least 32 bytes and must not use a published or placeholder key")
	}
	mfa := cfg.Security.MFAEncryptionKey
	if len(mfa) != 32 || mfa != strings.TrimSpace(mfa) || insecureSecret(mfa) {
		return errors.New("SECURITY_MFA_ENCRYPTION_KEY / security.mfa_encryption_key must be an independent raw 32-byte AES-256 key")
	}
	if mfa == jwt {
		return errors.New("security.mfa_encryption_key must differ from jwt.secret")
	}
	if err := outbound.ValidatePrivateOrigins(cfg.Security.OutboundPrivateOrigins); err != nil {
		return err
	}
	password := cfg.Database.Password
	if len(password) < 12 || insecureSecret(password) {
		return errors.New("DATABASE_PASSWORD / database.password must be at least 12 bytes and must not use a placeholder password")
	}
	if cfg.JWT.ExpireTime <= 0 {
		return errors.New("jwt.expire_time must be positive")
	}
	switch cfg.Server.Mode {
	case "debug", "release", "test":
	default:
		return errors.New("server.mode must be debug, release, or test")
	}
	for _, proxy := range cfg.Server.TrustedProxies {
		if net.ParseIP(proxy) == nil {
			if _, _, err := net.ParseCIDR(proxy); err != nil {
				return errors.New("server.trusted_proxies must contain IP addresses or CIDR ranges")
			}
		}
	}
	if cfg.Storage.MaxFileSize <= 0 || cfg.Storage.MaxFiles <= 0 || cfg.Storage.MaxRequestSize < cfg.Storage.MaxFileSize {
		return errors.New("storage limits must be positive and max_request_size must be at least max_file_size")
	}
	if cfg.CORS.Enabled {
		if len(cfg.CORS.AllowedOrigins) == 0 {
			return errors.New("cors.allowed_origins must list explicit trusted HTTP origins")
		}
		for _, origin := range cfg.CORS.AllowedOrigins {
			u, err := url.Parse(origin)
			if err != nil || strings.Contains(origin, "*") || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || u.Opaque != "" {
				return errors.New("cors.allowed_origins must list explicit HTTP origins without wildcards, paths, or credentials")
			}
		}
	}
	if cfg.Email.Username != "" && cfg.Email.Password == "" {
		return errors.New("email.password is required when email.username is set")
	}
	if cfg.OSS.Provider != "" && cfg.OSS.Provider != "local" {
		if cfg.OSS.AccessKeyID == "" || cfg.OSS.AccessKeySecret == "" {
			return errors.New("oss.access_key_id and oss.access_key_secret are required for cloud storage")
		}
	}
	return nil
}

func insecureSecret(value string) bool {
	// Previously published application key must never become valid again.
	if value == "ky6oJtR8MlYpMzJxhaVjWI1O4yeVUbkIJkJdGBzUt89lWifjWuZ1VDgqi68ciRKU" {
		return true
	}
	lower := strings.ToLower(value)
	for _, marker := range []string{"your-jwt-secret", "your-secure-database-password", "change-me", "changeme", "replace-me", "replace_me", "placeholder", "example-secret"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func validateConfig() error { return AppConfig.Validate() }

func GetEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
