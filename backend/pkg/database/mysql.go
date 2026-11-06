package database

import (
	"context"
	"fmt"
	"log"
	"net"
	"strconv"
	"time"

	mysqlDriver "github.com/go-sql-driver/mysql"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"vulnark/internal/config"
)

var DB *gorm.DB

// InitDatabase connects to an already provisioned database. Schema changes are
// deliberately separate: the application account does not need CREATE DATABASE.
func InitDatabase() error {
	if config.AppConfig == nil {
		return fmt.Errorf("数据库配置未初始化")
	}
	db, err := openDatabase(config.AppConfig.Database)
	if err != nil {
		return err
	}
	DB = db
	return nil
}

func databaseDSN(cfg config.DatabaseConfig) (string, error) {
	if cfg.Database == "" {
		return "", fmt.Errorf("数据库名称不能为空，请先创建数据库")
	}
	port := cfg.Port
	if port == 0 {
		port = 3306
	}
	charset := cfg.Charset
	if charset == "" {
		charset = "utf8mb4"
	}
	dsn := mysqlDriver.NewConfig()
	dsn.User = cfg.Username
	dsn.Passwd = cfg.Password
	dsn.Net = "tcp"
	dsn.Addr = net.JoinHostPort(cfg.Host, strconv.Itoa(port))
	dsn.DBName = cfg.Database
	dsn.ParseTime = true
	dsn.Loc = time.Local
	dsn.Params = map[string]string{"charset": charset}
	dsn.Timeout = 10 * time.Second
	dsn.ReadTimeout = 30 * time.Second
	dsn.WriteTimeout = 30 * time.Second
	return dsn.FormatDSN(), nil
}

func openDatabase(cfg config.DatabaseConfig) (*gorm.DB, error) {
	dsn, err := databaseDSN(cfg)
	if err != nil {
		return nil, err
	}
	// Disable GORM's automatic ping so every post-open failure can close the pool.
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{
		DisableAutomaticPing: true,
		Logger:               logger.Default.LogMode(logger.Warn),
		NowFunc:              func() time.Time { return time.Now().Local() },
	})
	if err != nil {
		if db != nil {
			if pool, poolErr := db.DB(); poolErr == nil {
				_ = pool.Close()
			}
		}
		return nil, fmt.Errorf("连接已配置数据库失败: %w", err)
	}
	pool, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("获取数据库连接池失败: %w", err)
	}
	pool.SetMaxOpenConns(25)
	pool.SetMaxIdleConns(5)
	pool.SetConnMaxLifetime(30 * time.Minute)
	pool.SetConnMaxIdleTime(5 * time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := pool.PingContext(ctx); err != nil {
		_ = pool.Close()
		return nil, fmt.Errorf("数据库连接测试失败: %w", err)
	}
	return db, nil
}

// AutoMigrate is retained for callers explicitly requesting a migration.
func AutoMigrate() error { return RunMigrations() }

func GetDB() *gorm.DB { return DB }

func CloseDatabase() {
	if DB == nil {
		return
	}
	pool, err := DB.DB()
	if err != nil {
		log.Printf("获取数据库连接池失败: %v", err)
		return
	}
	if err := pool.Close(); err != nil {
		log.Printf("关闭数据库连接失败: %v", err)
	}
	DB = nil
}
