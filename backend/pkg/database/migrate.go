package database

import (
	"sync"

	"gorm.io/gorm/schema"
)

// AutoMigrateModels is the legacy startup entry point. Startup now checks only;
// deployments must explicitly invoke RunMigrations (the -migrate command).
func AutoMigrateModels() error { return CheckMigrations() }

func getTableName(value interface{}) string {
	parsed, err := schema.Parse(value, &sync.Map{}, schema.NamingStrategy{})
	if err != nil {
		return ""
	}
	return parsed.Table
}
