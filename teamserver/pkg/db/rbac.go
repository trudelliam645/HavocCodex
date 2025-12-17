package db

import (
	"database/sql"
	"encoding/json"
	"time"
)

type User struct {
	ID           int64
	Username     string
	PasswordHash string
	SSOToken     sql.NullString
	CreatedAt    string
}

type AuditEvent struct {
	ID          int64
	UserID      int64
	WorkspaceID int64
	Action      string
	Target      string
	Metadata    map[string]any
	CreatedAt   string
}

// UpsertRole ensures a role exists with the provided permissions list.
func (db *DB) UpsertRole(name string, permissions []string) error {
	return db.upsertRole(name, permissions)
}

// SaveUser inserts or updates a user. When updating, the password hash is left
// unchanged if an empty string is provided.
func (db *DB) SaveUser(username, passwordHash, ssoToken string) (*User, error) {
	var (
		now   = time.Now().Format(time.RFC3339)
		token sql.NullString
	)

	if ssoToken != "" {
		token = sql.NullString{String: ssoToken, Valid: true}
	}

	if passwordHash != "" {
		_, err := db.db.Exec(`INSERT INTO TS_Users (Username, PasswordHash, SSOToken, CreatedAt) VALUES (?, ?, ?, ?)
			ON CONFLICT(Username) DO UPDATE SET PasswordHash=excluded.PasswordHash, SSOToken=excluded.SSOToken`, username, passwordHash, token, now)
		if err != nil {
			return nil, err
		}
	} else {
		_, err := db.db.Exec(`INSERT OR IGNORE INTO TS_Users (Username, PasswordHash, SSOToken, CreatedAt) VALUES (?, '', ?, ?)`, username, token, now)
		if err != nil {
			return nil, err
		}
	}

	return db.GetUser(username)
}

func (db *DB) GetUser(username string) (*User, error) {
	row := db.db.QueryRow(`SELECT ID, Username, PasswordHash, SSOToken, CreatedAt FROM TS_Users WHERE Username = ?`, username)
	var user User
	if err := row.Scan(&user.ID, &user.Username, &user.PasswordHash, &user.SSOToken, &user.CreatedAt); err != nil {
		return nil, err
	}

	return &user, nil
}

// AssignRole links a user to a role within a workspace.
func (db *DB) AssignRole(userID int64, roleName string, workspaceID int64) error {
	_, err := db.db.Exec(`INSERT OR IGNORE INTO TS_UserRoles (UserID, RoleName, WorkspaceID) VALUES (?, ?, ?)`, userID, roleName, workspaceID)
	return err
}

func (db *DB) UserRoles(userID, workspaceID int64) ([]string, error) {
	rows, err := db.db.Query(`SELECT RoleName FROM TS_UserRoles WHERE UserID = ? AND WorkspaceID = ?`, userID, workspaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var roles []string
	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}

	return roles, nil
}

// AddAuditEvent stores an action log for a user/workspace pair.
func (db *DB) AddAuditEvent(userID, workspaceID int64, action, target string, metadata map[string]any) error {
	meta := "{}"
	if metadata != nil {
		if encoded, err := json.Marshal(metadata); err == nil {
			meta = string(encoded)
		}
	}

	_, err := db.db.Exec(`INSERT INTO TS_AuditEvents (UserID, WorkspaceID, Action, Target, Metadata, CreatedAt) VALUES (?, ?, ?, ?, ?, ?)`,
		userID, workspaceID, action, target, meta, time.Now().Format(time.RFC3339))
	return err
}

// SessionSave persists a short-lived session token for the client UI to
// consume in future API calls.
func (db *DB) SessionSave(id string, userID, workspaceID int64, expiresAt time.Time) error {
	_, err := db.db.Exec(`INSERT OR REPLACE INTO TS_Sessions (ID, UserID, WorkspaceID, CreatedAt, ExpiresAt) VALUES (?, ?, ?, ?, ?)`,
		id, userID, workspaceID, time.Now().Format(time.RFC3339), expiresAt.Format(time.RFC3339))
	return err
}

// ResolveSession returns the associated user for a session token.
func (db *DB) ResolveSession(id string) (*User, int64, error) {
	row := db.db.QueryRow(`SELECT s.UserID, s.WorkspaceID, u.Username, u.PasswordHash, u.SSOToken, u.CreatedAt FROM TS_Sessions s JOIN TS_Users u ON u.ID = s.UserID WHERE s.ID = ?`, id)
	var (
		user      User
		workspace int64
		err       error
	)

	if err = row.Scan(&user.ID, &workspace, &user.Username, &user.PasswordHash, &user.SSOToken, &user.CreatedAt); err != nil {
		return nil, 0, err
	}

	return &user, workspace, nil
}

// DeleteSession removes a stored session token.
func (db *DB) DeleteSession(id string) error {
	_, err := db.db.Exec(`DELETE FROM TS_Sessions WHERE ID = ?`, id)
	return err
}

// ListAuditEvents fetches a limited audit trail for clients.
func (db *DB) ListAuditEvents(workspaceID int64, limit int) ([]AuditEvent, error) {
	rows, err := db.db.Query(`SELECT ID, UserID, WorkspaceID, Action, Target, Metadata, CreatedAt FROM TS_AuditEvents WHERE WorkspaceID = ? ORDER BY ID DESC LIMIT ?`, workspaceID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []AuditEvent
	for rows.Next() {
		var (
			a    AuditEvent
			meta string
		)
		if err := rows.Scan(&a.ID, &a.UserID, &a.WorkspaceID, &a.Action, &a.Target, &meta, &a.CreatedAt); err != nil {
			return nil, err
		}
		if meta != "" {
			_ = json.Unmarshal([]byte(meta), &a.Metadata)
		}
		events = append(events, a)
	}

	return events, nil
}

// DeleteStaleSessions removes expired session tokens. It is invoked lazily by
// authentication middleware.
func (db *DB) DeleteStaleSessions(now time.Time) error {
	_, err := db.db.Exec(`DELETE FROM TS_Sessions WHERE ExpiresAt <= ?`, now.Format(time.RFC3339))
	return err
}
