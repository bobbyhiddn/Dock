package main

import (
	"database/sql"
	"fmt"
	"os"

	_ "modernc.org/sqlite"
)

// User represents a Dock user account.
type User struct {
	ID           int64
	Username     string
	Email        string
	PasswordHash string // bcrypt hash; empty for OIDC-only users
	Provider     string // 'github', 'google', '' for local
	ProviderID   string
	IsAdmin      bool
	CreatedAt    string
}

// UserStore is a SQLite-backed store for Dock user accounts.
type UserStore struct {
	db *sql.DB
}

// NewUserStore opens (or creates) the SQLite database at dbPath and runs migrations.
func NewUserStore(dbPath string) (*UserStore, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open sqlite %q: %w", dbPath, err)
	}
	// Enable WAL for better concurrent read performance.
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		return nil, fmt.Errorf("enable WAL: %w", err)
	}
	if err := migrate(db); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &UserStore{db: db}, nil
}

func migrate(db *sql.DB) error {
	_, err := db.Exec(`
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    email         TEXT,
    password_hash TEXT,
    provider      TEXT DEFAULT '',
    provider_id   TEXT DEFAULT '',
    is_admin      INTEGER DEFAULT 0,
    created_at    TEXT DEFAULT (datetime('now'))
);`)
	return err
}

// userStoreDBPath returns the SQLite path from env (DOCK_DB_PATH) or default.
func userStoreDBPath() string {
	if p := os.Getenv("DOCK_DB_PATH"); p != "" {
		return p
	}
	return "./dock.db"
}

// CreateUser inserts a new user into the database.
func (s *UserStore) CreateUser(username, email, passwordHash, provider, providerID string) error {
	_, err := s.db.Exec(
		`INSERT INTO users (username, email, password_hash, provider, provider_id)
		 VALUES (?, ?, ?, ?, ?)`,
		username, email, passwordHash, provider, providerID,
	)
	if err != nil {
		return fmt.Errorf("create user %q: %w", username, err)
	}
	return nil
}

// GetByUsername looks up a user by their username.
func (s *UserStore) GetByUsername(username string) (*User, error) {
	row := s.db.QueryRow(
		`SELECT id, username, email, COALESCE(password_hash,''), provider, provider_id, is_admin, created_at
		 FROM users WHERE username = ?`, username)
	return scanUser(row)
}

// GetByProvider looks up a user by their OAuth provider + provider user ID.
func (s *UserStore) GetByProvider(provider, providerID string) (*User, error) {
	row := s.db.QueryRow(
		`SELECT id, username, email, COALESCE(password_hash,''), provider, provider_id, is_admin, created_at
		 FROM users WHERE provider = ? AND provider_id = ?`, provider, providerID)
	return scanUser(row)
}

// SetAdmin grants admin privileges to a user.
func (s *UserStore) SetAdmin(username string) error {
	_, err := s.db.Exec(`UPDATE users SET is_admin = 1 WHERE username = ?`, username)
	return err
}

// ListUsers returns all users.
func (s *UserStore) ListUsers() ([]User, error) {
	rows, err := s.db.Query(
		`SELECT id, username, email, COALESCE(password_hash,''), provider, provider_id, is_admin, created_at
		 FROM users ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []User
	for rows.Next() {
		var u User
		var isAdmin int
		if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash,
			&u.Provider, &u.ProviderID, &isAdmin, &u.CreatedAt); err != nil {
			return nil, err
		}
		u.IsAdmin = isAdmin == 1
		users = append(users, u)
	}
	return users, rows.Err()
}

// CountUsers returns the total number of registered users.
func (s *UserStore) CountUsers() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// scanUser scans a single user row.
func scanUser(row *sql.Row) (*User, error) {
	var u User
	var isAdmin int
	err := row.Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash,
		&u.Provider, &u.ProviderID, &isAdmin, &u.CreatedAt)
	if err != nil {
		return nil, err
	}
	u.IsAdmin = isAdmin == 1
	return &u, nil
}
