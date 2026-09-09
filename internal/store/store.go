package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create data directory: %w", err)
	}
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate(ctx context.Context) error {
	const schema = `
CREATE TABLE IF NOT EXISTS schema_migrations (
	version INTEGER PRIMARY KEY,
	applied_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS repositories (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL UNIQUE,
	remote_url TEXT NOT NULL,
	auth_type TEXT NOT NULL,
	auth_secret TEXT NOT NULL DEFAULT '',
	status TEXT NOT NULL,
	status_message TEXT NOT NULL DEFAULT '',
	default_branch TEXT NOT NULL DEFAULT '',
	mail_username TEXT NOT NULL UNIQUE,
	mail_password_hash TEXT NOT NULL,
	mail_password_cipher TEXT NOT NULL,
	ssh_host_fingerprint TEXT NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL,
	last_fetch_at INTEGER
);
CREATE TABLE IF NOT EXISTS mailboxes (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	repository_id TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
	branch TEXT NOT NULL,
	name TEXT NOT NULL,
	uid_validity INTEGER NOT NULL,
	next_uid INTEGER NOT NULL DEFAULT 1,
	head_oid TEXT NOT NULL DEFAULT '',
	UNIQUE(repository_id, branch),
	UNIQUE(repository_id, name)
);
CREATE TABLE IF NOT EXISTS messages (
	mailbox_id INTEGER NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
	uid INTEGER NOT NULL,
	commit_oid TEXT NOT NULL,
	subject TEXT NOT NULL,
	author_name TEXT NOT NULL,
	author_email TEXT NOT NULL,
	authored_at INTEGER NOT NULL,
	size INTEGER NOT NULL DEFAULT 0,
	cache_path TEXT NOT NULL DEFAULT '',
	PRIMARY KEY(mailbox_id, uid),
	UNIQUE(mailbox_id, commit_oid)
);
CREATE TABLE IF NOT EXISTS admin_sessions (
	id_hash TEXT PRIMARY KEY,
	csrf_token TEXT NOT NULL,
	expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS messages_mailbox_uid ON messages(mailbox_id, uid);
CREATE INDEX IF NOT EXISTS sessions_expiry ON admin_sessions(expires_at);
INSERT OR IGNORE INTO schema_migrations(version,applied_at) VALUES(1,unixepoch());`
	if _, err := s.db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("apply schema: %w", err)
	}
	return nil
}

func (s *Store) CreateRepository(ctx context.Context, repo Repository) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO repositories (
	id,name,remote_url,auth_type,auth_secret,status,status_message,default_branch,
	mail_username,mail_password_hash,mail_password_cipher,ssh_host_fingerprint,
	created_at,updated_at,last_fetch_at
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL)`,
		repo.ID, repo.Name, repo.RemoteURL, repo.AuthType, repo.AuthSecret, repo.Status,
		repo.StatusMessage, repo.DefaultBranch, repo.MailUsername, repo.MailPasswordHash,
		repo.MailPasswordCipher, repo.SSHHostFingerprint, repo.CreatedAt.Unix(),
		repo.UpdatedAt.Unix())
	if err != nil {
		return fmt.Errorf("create repository: %w", err)
	}
	return nil
}

func (s *Store) ListRepositories(ctx context.Context) ([]Repository, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,remote_url,auth_type,auth_secret,status,status_message,
default_branch,mail_username,mail_password_hash,mail_password_cipher,ssh_host_fingerprint,
created_at,updated_at,last_fetch_at FROM repositories ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var repos []Repository
	for rows.Next() {
		repo, err := scanRepository(rows)
		if err != nil {
			return nil, err
		}
		repos = append(repos, repo)
	}
	return repos, rows.Err()
}

func (s *Store) Repository(ctx context.Context, id string) (Repository, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id,name,remote_url,auth_type,auth_secret,status,status_message,
default_branch,mail_username,mail_password_hash,mail_password_cipher,ssh_host_fingerprint,
created_at,updated_at,last_fetch_at FROM repositories WHERE id=?`, id)
	return scanRepository(row)
}

func (s *Store) RepositoryByUsername(ctx context.Context, username string) (Repository, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id,name,remote_url,auth_type,auth_secret,status,status_message,
default_branch,mail_username,mail_password_hash,mail_password_cipher,ssh_host_fingerprint,
created_at,updated_at,last_fetch_at FROM repositories WHERE mail_username=? AND status != 'deleting'`, username)
	return scanRepository(row)
}

type scanner interface {
	Scan(dest ...any) error
}

func scanRepository(row scanner) (Repository, error) {
	var r Repository
	var created, updated int64
	var last sql.NullInt64
	err := row.Scan(&r.ID, &r.Name, &r.RemoteURL, &r.AuthType, &r.AuthSecret, &r.Status,
		&r.StatusMessage, &r.DefaultBranch, &r.MailUsername, &r.MailPasswordHash,
		&r.MailPasswordCipher, &r.SSHHostFingerprint, &created, &updated, &last)
	if err != nil {
		return r, err
	}
	r.CreatedAt = time.Unix(created, 0)
	r.UpdatedAt = time.Unix(updated, 0)
	if last.Valid {
		value := time.Unix(last.Int64, 0)
		r.LastFetchAt = &value
	}
	return r, nil
}

func (s *Store) UpdateRepositoryStatus(ctx context.Context, id, status, message, defaultBranch, fingerprint string, fetched bool) error {
	now := time.Now().UTC().Unix()
	var result sql.Result
	var err error
	if fetched {
		result, err = s.db.ExecContext(ctx, `UPDATE repositories SET status=?,status_message=?,default_branch=?,
ssh_host_fingerprint=?,updated_at=?,last_fetch_at=? WHERE id=?`,
			status, message, defaultBranch, fingerprint, now, now, id)
	} else {
		result, err = s.db.ExecContext(ctx, `UPDATE repositories SET status=?,status_message=?,
default_branch=?,ssh_host_fingerprint=?,updated_at=? WHERE id=?`,
			status, message, defaultBranch, fingerprint, now, id)
	}
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) UpdateMailCredential(ctx context.Context, id, hash, cipher string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE repositories SET mail_password_hash=?,mail_password_cipher=?,updated_at=? WHERE id=?`,
		hash, cipher, time.Now().UTC().Unix(), id)
	return err
}

func (s *Store) DeleteRepository(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM repositories WHERE id=?`, id)
	return err
}

func (s *Store) SetDeleting(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE repositories SET status='deleting',updated_at=? WHERE id=?`, time.Now().UTC().Unix(), id)
	return err
}

func (s *Store) ReplaceMailboxes(ctx context.Context, repoID, defaultBranch string, branches []BranchSnapshot) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	existing, err := loadMailboxState(ctx, tx, repoID)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE mailboxes SET name='__updating__/' || id WHERE repository_id=?`, repoID); err != nil {
		return err
	}
	seen := make(map[string]bool, len(branches))
	for _, branch := range branches {
		seen[branch.Name] = true
		name := "Branches/" + branch.Name
		if branch.Name == defaultBranch {
			name = "INBOX"
		}
		old, ok := existing[branch.Name]
		rebuild := !ok || old.Name != name || old.HeadOID == "" || !branch.FastForward
		if !ok {
			result, err := tx.ExecContext(ctx, `INSERT INTO mailboxes(repository_id,branch,name,uid_validity,next_uid,head_oid)
VALUES(?,?,?,?,1,?)`, repoID, branch.Name, name, uint32(time.Now().Unix()), branch.HeadOID)
			if err != nil {
				return err
			}
			id, _ := result.LastInsertId()
			old = Mailbox{ID: id, RepositoryID: repoID, Branch: branch.Name, Name: name, UIDValidity: uint32(time.Now().Unix()), NextUID: 1}
			rebuild = true
		}
		if rebuild {
			uidValidity := old.UIDValidity
			if ok {
				uidValidity++
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM messages WHERE mailbox_id=?`, old.ID); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE mailboxes SET name=?,uid_validity=?,next_uid=1,head_oid=? WHERE id=?`,
				name, uidValidity, branch.HeadOID, old.ID); err != nil {
				return err
			}
			old.NextUID = 1
		}
		next := old.NextUID
		for _, commit := range branch.NewCommits {
			if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO messages(
mailbox_id,uid,commit_oid,subject,author_name,author_email,authored_at) VALUES(?,?,?,?,?,?,?)`,
				old.ID, next, commit.OID, commit.Subject, commit.AuthorName, commit.AuthorEmail, commit.AuthoredAt.Unix()); err != nil {
				return err
			}
			next++
		}
		if _, err := tx.ExecContext(ctx, `UPDATE mailboxes SET name=?,next_uid=?,head_oid=? WHERE id=?`,
			name, next, branch.HeadOID, old.ID); err != nil {
			return err
		}
	}
	for branch, mailbox := range existing {
		if !seen[branch] {
			if _, err := tx.ExecContext(ctx, `DELETE FROM mailboxes WHERE id=?`, mailbox.ID); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

type CommitSnapshot struct {
	OID         string
	Subject     string
	AuthorName  string
	AuthorEmail string
	AuthoredAt  time.Time
}

type BranchSnapshot struct {
	Name        string
	HeadOID     string
	FastForward bool
	NewCommits  []CommitSnapshot
}

func loadMailboxState(ctx context.Context, tx *sql.Tx, repoID string) (map[string]Mailbox, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id,repository_id,branch,name,uid_validity,next_uid,head_oid FROM mailboxes WHERE repository_id=?`, repoID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[string]Mailbox)
	for rows.Next() {
		var m Mailbox
		if err := rows.Scan(&m.ID, &m.RepositoryID, &m.Branch, &m.Name, &m.UIDValidity, &m.NextUID, &m.HeadOID); err != nil {
			return nil, err
		}
		result[m.Branch] = m
	}
	return result, rows.Err()
}

func (s *Store) Mailboxes(ctx context.Context, repoID string) ([]Mailbox, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,repository_id,branch,name,uid_validity,next_uid,head_oid
FROM mailboxes WHERE repository_id=? ORDER BY CASE WHEN name='INBOX' THEN 0 ELSE 1 END,name`, repoID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []Mailbox
	for rows.Next() {
		var m Mailbox
		if err := rows.Scan(&m.ID, &m.RepositoryID, &m.Branch, &m.Name, &m.UIDValidity, &m.NextUID, &m.HeadOID); err != nil {
			return nil, err
		}
		result = append(result, m)
	}
	return result, rows.Err()
}

func (s *Store) MailboxByName(ctx context.Context, repoID, name string) (Mailbox, error) {
	var m Mailbox
	err := s.db.QueryRowContext(ctx, `SELECT id,repository_id,branch,name,uid_validity,next_uid,head_oid
FROM mailboxes WHERE repository_id=? AND name=?`, repoID, name).
		Scan(&m.ID, &m.RepositoryID, &m.Branch, &m.Name, &m.UIDValidity, &m.NextUID, &m.HeadOID)
	return m, err
}

func (s *Store) Messages(ctx context.Context, mailboxID int64) ([]Message, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT mailbox_id,uid,commit_oid,subject,author_name,author_email,
authored_at,size,cache_path FROM messages WHERE mailbox_id=? ORDER BY uid`, mailboxID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []Message
	for rows.Next() {
		var m Message
		var authored int64
		if err := rows.Scan(&m.MailboxID, &m.UID, &m.CommitOID, &m.Subject, &m.AuthorName,
			&m.AuthorEmail, &authored, &m.Size, &m.CachePath); err != nil {
			return nil, err
		}
		m.AuthoredAt = time.Unix(authored, 0)
		result = append(result, m)
	}
	return result, rows.Err()
}

func (s *Store) UpdateMessageCache(ctx context.Context, mailboxID int64, uid uint32, size int64, path string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE messages SET size=?,cache_path=? WHERE mailbox_id=? AND uid=?`,
		size, path, mailboxID, uid)
	return err
}

func (s *Store) CreateSession(ctx context.Context, idHash, csrf string, expires time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO admin_sessions(id_hash,csrf_token,expires_at) VALUES(?,?,?)`,
		idHash, csrf, expires.Unix())
	return err
}

func (s *Store) Session(ctx context.Context, idHash string) (Session, error) {
	var sess Session
	var expires int64
	err := s.db.QueryRowContext(ctx, `SELECT id_hash,csrf_token,expires_at FROM admin_sessions
WHERE id_hash=? AND expires_at>?`, idHash, time.Now().UTC().Unix()).Scan(&sess.ID, &sess.CSRFToken, &expires)
	sess.ExpiresAt = time.Unix(expires, 0)
	return sess, err
}

func (s *Store) DeleteSession(ctx context.Context, idHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM admin_sessions WHERE id_hash=?`, idHash)
	return err
}

func (s *Store) PurgeExpiredSessions(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM admin_sessions WHERE expires_at<=?`, time.Now().UTC().Unix())
	return err
}

func IsNotFound(err error) bool { return errors.Is(err, sql.ErrNoRows) }
