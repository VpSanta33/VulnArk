package database

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	mysqlDriver "github.com/go-sql-driver/mysql"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"vulnark/internal/config"
	"vulnark/internal/model"
)

func TestDatabaseDSNRoundTrip(t *testing.T) {
	cfg := config.DatabaseConfig{Host: "::1", Port: 3307, Username: "app_user", Password: "p@ss:/?#&=word", Database: "vulnark-test", Charset: "utf8mb4"}
	dsn, err := databaseDSN(cfg)
	require.NoError(t, err)
	parsed, err := mysqlDriver.ParseDSN(dsn)
	require.NoError(t, err)
	require.Equal(t, cfg.Username, parsed.User)
	require.Equal(t, cfg.Password, parsed.Passwd)
	require.Equal(t, cfg.Database, parsed.DBName)
	require.Equal(t, "[::1]:3307", parsed.Addr)
	require.True(t, parsed.ParseTime)
	require.Equal(t, time.Local, parsed.Loc)
	require.Equal(t, "utf8mb4", parsed.Params["charset"])
	require.False(t, parsed.MultiStatements)
	_, err = databaseDSN(config.DatabaseConfig{})
	require.Error(t, err)
}

// Integration tests never use application config or a default DSN. The caller
// must provision a dedicated, EMPTY *_test database with no production tables.
// The resulting test schema is retained for inspection; no tables are dropped.
func TestMySQLMigrationsExplicitIsolatedDatabase(t *testing.T) {
	dsn := os.Getenv("VULNARK_MYSQL_TEST_DSN")
	if dsn == "" {
		t.Skip("set VULNARK_MYSQL_TEST_DSN to an empty dedicated *_test database")
	}
	parsed, err := mysqlDriver.ParseDSN(dsn)
	require.NoError(t, err)
	require.True(t, strings.HasSuffix(parsed.DBName, "_test"), "integration DSN database must end in _test")
	require.False(t, parsed.MultiStatements, "integration DSN must not enable multiStatements")
	parsed.ParseTime = true
	parsed.Timeout = 10 * time.Second
	parsed.ReadTimeout = 30 * time.Second
	parsed.WriteTimeout = 30 * time.Second
	db, err := gorm.Open(mysql.Open(parsed.FormatDSN()), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	require.NoError(t, err)
	pool, err := db.DB()
	require.NoError(t, err)
	pool.SetMaxOpenConns(5)
	pool.SetMaxIdleConns(2)
	t.Cleanup(func() { require.NoError(t, pool.Close()) })
	var count int64
	require.NoError(t, db.Raw("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE()").Scan(&count).Error)
	require.Zero(t, count, "refusing to touch a nonempty database, even with a _test suffix")
	m := &MigrationManager{db: db, credentialsPath: filepath.Join(t.TempDir(), adminCredentialsFile)}
	// Check the legacy-upgrade path with both old and newly named unique indexes.
	require.NoError(t, db.Exec("CREATE TABLE roles (id bigint unsigned NOT NULL AUTO_INCREMENT PRIMARY KEY, name varchar(50) NOT NULL, UNIQUE KEY uni_roles_name(name))").Error)
	require.NoError(t, db.Exec("CREATE TABLE users (id bigint unsigned NOT NULL AUTO_INCREMENT PRIMARY KEY, username varchar(50) NOT NULL, email varchar(100) NOT NULL, UNIQUE KEY uni_users_username(username), UNIQUE KEY uni_users_email(email))").Error)
	// Legacy tag data includes collation-equivalent names, duplicate pairs and
	// orphan links. No foreign keys existed in this historical schema.
	require.NoError(t, db.Exec("CREATE TABLE knowledge_bases (id bigint unsigned PRIMARY KEY, title varchar(255) NOT NULL, content longtext NOT NULL, category varchar(50) NOT NULL, type varchar(50) NOT NULL, author_id bigint unsigned NOT NULL, tags text)").Error)
	require.NoError(t, db.Exec("INSERT INTO knowledge_bases VALUES (1, 'legacy', 'body', 'security', 'article', 1, ' alpha,ALPHA,beta,beta ')").Error)
	require.NoError(t, db.Exec("CREATE TABLE tags (id bigint unsigned NOT NULL AUTO_INCREMENT PRIMARY KEY, name varchar(50) NOT NULL, display_name varchar(100) NOT NULL, creator_id bigint unsigned NOT NULL, usage_count int DEFAULT 0)").Error)
	require.NoError(t, db.Exec("INSERT INTO tags(id,name,display_name,creator_id,usage_count) VALUES (1,' alpha ','alpha',1,99),(2,'ALPHA','ALPHA',1,99),(3,'related','related',1,99)").Error)
	require.NoError(t, db.Exec("CREATE TABLE knowledge_tags (id bigint unsigned NOT NULL AUTO_INCREMENT PRIMARY KEY, knowledge_id bigint unsigned NOT NULL, tag_id bigint unsigned NOT NULL)").Error)
	require.NoError(t, db.Exec("INSERT INTO knowledge_tags(knowledge_id,tag_id) VALUES (1,1),(1,2),(1,3),(1,3),(999,3),(1,999)").Error)
	require.NoError(t, m.RunMigrations())
	require.NoError(t, m.RunMigrations())
	require.NoError(t, m.CheckMigrations())
	require.EqualValues(t, 1, migrationCount(t, db, &model.User{}))
	require.EqualValues(t, 3, migrationCount(t, db, &model.KnowledgeTag{}))
	var text string
	require.NoError(t, db.Model(&model.KnowledgeBase{}).Select("tags").Where("id = 1").Scan(&text).Error)
	require.Equal(t, "alpha,beta,related", text)
	var tags []model.Tag
	require.NoError(t, db.Order("id").Find(&tags).Error)
	require.Len(t, tags, 3)
	for _, tag := range tags {
		require.Equal(t, 1, tag.UsageCount)
	}
	for _, index := range []string{"uni_users_username", "uni_users_email", "idx_user_username", "idx_user_email"} {
		require.True(t, db.Migrator().HasIndex(&model.User{}, index))
	}
	require.True(t, db.Migrator().HasIndex(&model.Role{}, "uni_roles_name"))
	require.Error(t, db.Exec("INSERT INTO users(username,email,password_hash,real_name,role_id) SELECT username,email,password_hash,real_name,role_id FROM users LIMIT 1").Error)
}
