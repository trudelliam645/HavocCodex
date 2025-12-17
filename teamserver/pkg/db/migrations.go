package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const (
	currentSchemaVersion = 1
)

// applyMigrations ensures the SQLite schema contains the latest RBAC tables.
// It is safe to call repeatedly and will backfill the meta/version table if
// the database pre-dates migration support.
func (db *DB) applyMigrations() error {
	if err := db.createMetaTable(); err != nil {
		return err
	}

	version, err := db.schemaVersion()
	if err != nil {
		return err
	}

	if version >= currentSchemaVersion {
		return nil
	}

	for step := version + 1; step <= currentSchemaVersion; step++ {
		switch step {
		case 1:
			if err := db.migrationAddRBAC(); err != nil {
				return err
			}
		}

		if err := db.setSchemaVersion(step); err != nil {
			return err
		}
	}

	return nil
}

func (db *DB) createMetaTable() error {
	_, err := db.db.Exec(`CREATE TABLE IF NOT EXISTS "TS_Meta" ("Key" text PRIMARY KEY, "Value" text);`)
	return err
}

func (db *DB) schemaVersion() (int, error) {
	row := db.db.QueryRow(`SELECT Value FROM TS_Meta WHERE Key = 'SchemaVersion'`)
	var value string
	if err := row.Scan(&value); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, nil
		}
		return 0, err
	}

	var version int
	if _, err := fmt.Sscanf(value, "%d", &version); err != nil {
		return 0, err
	}

	return version, nil
}

func (db *DB) setSchemaVersion(version int) error {
	_, err := db.db.Exec(`INSERT OR REPLACE INTO TS_Meta (Key, Value) VALUES ('SchemaVersion', ?)`, version)
	return err
}

func (db *DB) migrationAddRBAC() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS "TS_Users" ("ID" integer PRIMARY KEY AUTOINCREMENT, "Username" text UNIQUE, "PasswordHash" text, "SSOToken" text, "CreatedAt" text);`,
		`CREATE TABLE IF NOT EXISTS "TS_Roles" ("Name" text PRIMARY KEY, "Permissions" text);`,
		`CREATE TABLE IF NOT EXISTS "TS_Workspaces" ("ID" integer PRIMARY KEY AUTOINCREMENT, "Name" text UNIQUE, "Active" integer DEFAULT 1, "CreatedAt" text);`,
		`CREATE TABLE IF NOT EXISTS "TS_UserRoles" ("UserID" integer, "RoleName" text, "WorkspaceID" integer, PRIMARY KEY ("UserID", "RoleName", "WorkspaceID"));`,
		`CREATE TABLE IF NOT EXISTS "TS_AuditEvents" ("ID" integer PRIMARY KEY AUTOINCREMENT, "UserID" integer, "WorkspaceID" integer, "Action" text, "Target" text, "Metadata" text, "CreatedAt" text);`,
		`CREATE TABLE IF NOT EXISTS "TS_Sessions" ("ID" text PRIMARY KEY, "UserID" integer, "WorkspaceID" integer, "CreatedAt" text, "ExpiresAt" text);`,
	}

	for _, stmt := range stmts {
		if _, err := db.db.Exec(stmt); err != nil {
			return err
		}
	}

	// ensure a default workspace exists
	_, err := db.EnsureWorkspace("default")
	return err
}

func (db *DB) upsertRole(name string, permissions []string) error {
	encoded, err := json.Marshal(permissions)
	if err != nil {
		return err
	}

	_, err = db.db.Exec(`INSERT INTO TS_Roles (Name, Permissions) VALUES (?, ?) ON CONFLICT(Name) DO UPDATE SET Permissions=excluded.Permissions`, name, string(encoded))
	return err
}

// EnsureWorkspace returns the workspace ID, creating it if missing.
func (db *DB) EnsureWorkspace(name string) (int64, error) {
	var (
		id  int64
		err error
		now = time.Now().Format(time.RFC3339)
		row = db.db.QueryRow(`SELECT ID FROM TS_Workspaces WHERE Name = ?`, name)
	)

	if err = row.Scan(&id); err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return 0, err
		}

		res, err := db.db.Exec(`INSERT INTO TS_Workspaces (Name, Active, CreatedAt) VALUES (?, 1, ?)`, name, now)
		if err != nil {
			return 0, err
		}

		return res.LastInsertId()
	}

	return id, nil
}
