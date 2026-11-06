package main

import (
	"context"
	"flag"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	webui "vulnark"
	_ "vulnark/docs"
	"vulnark/internal/config"
	"vulnark/internal/container"
	"vulnark/internal/middleware"
	"vulnark/internal/repository"
	"vulnark/internal/router"
	"vulnark/internal/service"
	"vulnark/pkg/database"
	"vulnark/pkg/logger"
)

// @title VulnArk API
// @version 1.1.0
// @description VulnArk 漏洞管理系统。创建漏洞同时支持 JSON 和 multipart；敏感文件必须携带 Bearer token 下载。
// @license.name MIT
// @license.url https://opensource.org/licenses/MIT
// @BasePath /
// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name Authorization
func main() {
	migrate := flag.Bool("migrate", false, "apply versioned database migrations and exit")
	flag.Parse()
	config.LoadConfig()
	logger.InitLogger()
	if err := database.InitDatabase(); err != nil {
		logger.Fatalf("数据库连接失败: %v", err)
	}
	defer database.CloseDatabase()
	if *migrate {
		if err := database.RunMigrations(); err != nil {
			logger.Fatalf("数据库迁移失败: %v", err)
		}
		logger.Info("数据库迁移完成")
		return
	}
	if err := database.CheckMigrations(); err != nil {
		logger.Fatalf("数据库版本检查失败，请先执行 -migrate: %v", err)
	}
	app := container.NewContainer()
	gin.SetMode(config.AppConfig.Server.Mode)
	r := gin.New()
	if err := r.SetTrustedProxies(config.AppConfig.Server.TrustedProxies); err != nil {
		logger.Fatalf("可信代理配置无效: %v", err)
	}
	r.Use(middleware.RecoveryMiddleware(), middleware.RequestLoggerMiddleware(), middleware.CORSMiddleware(), middleware.AuditMiddleware(app.AuditLogService))
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "version": "1.1.0"})
	})
	router.SetupRoutes(r, app)
	webui.Register(r)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	middleware.StartCleanupRoutine(ctx)
	worker := service.NewFileCleanupWorker(repository.NewFileCleanupRepository(app.DB), app.StorageService,
		service.FileCleanupWorkerOptions{OnError: func(err error) { logger.Error("文件清理暂未完成，将自动重试") }})
	maintenanceDone := make(chan struct{})
	auditCleanupDone := make(chan struct{})
	go func() {
		defer close(auditCleanupDone)
		ticker := time.NewTicker(6 * time.Hour)
		defer ticker.Stop()
		for {
			cleanup, done := context.WithTimeout(ctx, 30*time.Second)
			err := service.CleanupAuditLogs(cleanup, app.DB, time.Now())
			done()
			if err != nil && ctx.Err() == nil {
				logger.Warn("审计日志清理未完成，将在下个周期重试")
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	go func() {
		defer close(maintenanceDone)
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			cleanup, done := context.WithTimeout(ctx, 3*time.Second)
			_, err := app.UserRepo.CleanupMFAChallenges(cleanup, time.Now(), 100)
			done()
			if err != nil && ctx.Err() == nil {
				logger.Warn("过期认证挑战将在下次周期继续清理")
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	slaDone := make(chan struct{})
	go func() {
		defer close(slaDone)
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			scan, stop := context.WithTimeout(ctx, 20*time.Second)
			_, err := app.SLAService.ScanOverdue(scan, time.Now(), 200)
			stop()
			if err != nil && ctx.Err() == nil {
				logger.Warn("SLA提醒扫描未完成，将在下个周期重试")
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		if err := worker.Run(ctx); err != nil && ctx.Err() == nil {
			logger.Error("文件清理任务停止")
		}
	}()
	srv := &http.Server{
		Addr:              config.AppConfig.Server.Host + ":" + config.AppConfig.Server.Port,
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       time.Duration(config.AppConfig.Server.ReadTimeout) * time.Second,
		WriteTimeout:      time.Duration(config.AppConfig.Server.WriteTimeout) * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	serverErrors := make(chan error, 1)
	go func() { serverErrors <- srv.ListenAndServe() }()
	select {
	case err := <-serverErrors:
		if err != nil && err != http.ErrServerClosed {
			logger.Errorf("HTTP服务停止: %v", err)
		}
		cancel()
	case <-ctx.Done():
	}
	shutdown, stop := context.WithTimeout(context.Background(), 10*time.Second)
	defer stop()
	if err := srv.Shutdown(shutdown); err != nil {
		logger.Errorf("关闭HTTP服务失败: %v", err)
	}
	select {
	case <-workerDone:
	case <-shutdown.Done():
		logger.Warn("文件清理将在下次启动时继续")
	}
	select {
	case <-maintenanceDone:
	case <-shutdown.Done():
	}
	select {
	case <-slaDone:
	case <-shutdown.Done():
	}
	select {
	case <-auditCleanupDone:
	case <-shutdown.Done():
	}
}
