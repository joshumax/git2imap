package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"git2imap/internal/gitbackend"
	"git2imap/internal/secure"
	"git2imap/internal/store"
)

type AddRepositoryInput struct {
	Name       string
	RemoteURL  string
	AuthType   string
	Username   string
	Password   string
	PrivateKey string
	Passphrase string
}

type RepositoryService struct {
	store    *store.Store
	box      *secure.Box
	git      *gitbackend.Backend
	cacheDir string
	host     string
	logger   *slog.Logger

	mu         sync.Mutex
	identityMu sync.Mutex
	running    map[string]*refreshCall
}

type refreshCall struct {
	done   chan struct{}
	cancel context.CancelFunc
	err    error
}

func NewRepositoryService(st *store.Store, box *secure.Box, git *gitbackend.Backend, cacheDir, host string, logger *slog.Logger) *RepositoryService {
	return &RepositoryService{
		store: st, box: box, git: git, cacheDir: cacheDir, host: host, logger: logger,
		running: make(map[string]*refreshCall),
	}
}

func (s *RepositoryService) AddRepository(ctx context.Context, input AddRepositoryInput) (store.Repository, string, error) {
	input.Name = strings.TrimSpace(input.Name)
	input.RemoteURL = strings.TrimSpace(input.RemoteURL)
	if input.Name == "" {
		return store.Repository{}, "", errors.New("repository name is required")
	}
	if strings.ContainsAny(input.Name, "\r\n\x00/\\") {
		return store.Repository{}, "", errors.New("repository name contains unsupported characters")
	}
	if err := gitbackend.ValidateRemote(input.RemoteURL); err != nil {
		return store.Repository{}, "", err
	}
	switch input.AuthType {
	case "", "none":
		input.AuthType = "none"
	case "http":
		if input.Password == "" {
			return store.Repository{}, "", errors.New("HTTP password or token is required")
		}
	case "ssh":
		if input.PrivateKey == "" {
			return store.Repository{}, "", errors.New("SSH private key is required")
		}
	default:
		return store.Repository{}, "", errors.New("authentication type must be none, http, or ssh")
	}

	authJSON, err := gitbackend.EncodeAuth(gitbackend.Auth{
		Username: input.Username, Password: input.Password,
		PrivateKey: input.PrivateKey, Passphrase: input.Passphrase,
	})
	if err != nil {
		return store.Repository{}, "", err
	}
	authCipher, err := s.box.Encrypt(authJSON)
	if err != nil {
		return store.Repository{}, "", err
	}
	password, err := secure.RandomToken(24)
	if err != nil {
		return store.Repository{}, "", err
	}
	passwordHash, err := secure.HashPassword(password)
	if err != nil {
		return store.Repository{}, "", err
	}
	passwordCipher, err := s.box.Encrypt([]byte(password))
	if err != nil {
		return store.Repository{}, "", err
	}
	id := uuid.NewString()
	s.identityMu.Lock()
	defer s.identityMu.Unlock()
	username, err := s.availableMailAddress(ctx, input.Name, id)
	if err != nil {
		return store.Repository{}, "", err
	}
	now := time.Now().UTC()
	repo := store.Repository{
		ID: id, Name: input.Name, RemoteURL: input.RemoteURL, AuthType: input.AuthType,
		AuthSecret: authCipher, Status: "pending", MailUsername: username,
		MailPasswordHash: passwordHash, MailPasswordCipher: passwordCipher,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := s.store.CreateRepository(ctx, repo); err != nil {
		return store.Repository{}, "", err
	}
	go func() {
		if err := s.RefreshRepository(context.Background(), id); err != nil {
			s.logger.Error("initial repository clone failed", "repository_id", id, "error", err)
		}
	}()
	return repo, password, nil
}

func projectSlug(name string) string {
	var b strings.Builder
	lastDash := false
	for _, r := range strings.ToLower(name) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastDash = false
		} else if b.Len() > 0 && !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	base := strings.Trim(b.String(), "-")
	if base == "" {
		base = "repo"
	}
	if len(base) > 48 {
		base = base[:48]
	}
	return strings.Trim(base, "-")
}

func (s *RepositoryService) availableMailAddress(ctx context.Context, name, id string) (string, error) {
	host := strings.ToLower(s.host)
	slug := projectSlug(name)
	address := "git2imap+" + slug + "@" + host
	repositories, err := s.store.ListRepositories(ctx)
	if err != nil {
		return "", err
	}
	for _, repo := range repositories {
		if strings.EqualFold(repo.MailUsername, address) {
			suffix := "-" + strings.ReplaceAll(id[:8], "-", "")
			maxSlug := 64 - len("git2imap+") - len(suffix)
			if len(slug) > maxSlug {
				slug = slug[:maxSlug]
			}
			return "git2imap+" + slug + suffix + "@" + host, nil
		}
	}
	return address, nil
}

func (s *RepositoryService) PurgeLegacyRepositories(ctx context.Context) (int, error) {
	repositories, err := s.store.ListRepositories(ctx)
	if err != nil {
		return 0, err
	}
	deleted := 0
	for _, repo := range repositories {
		if strings.HasPrefix(strings.ToLower(repo.MailUsername), "git2imap+") &&
			strings.Contains(repo.MailUsername, "@") {
			continue
		}
		if err := s.DeleteRepository(ctx, repo.ID); err != nil {
			return deleted, err
		}
		deleted++
	}
	return deleted, nil
}

func (s *RepositoryService) ListRepositories(ctx context.Context) ([]store.Repository, error) {
	return s.store.ListRepositories(ctx)
}

func (s *RepositoryService) Repository(ctx context.Context, id string) (store.Repository, error) {
	return s.store.Repository(ctx, id)
}

func (s *RepositoryService) Authenticate(ctx context.Context, username, password string) (store.Repository, bool) {
	repo, err := s.store.RepositoryByUsername(ctx, username)
	if err != nil || !secure.VerifyPassword(repo.MailPasswordHash, password) {
		return store.Repository{}, false
	}
	return repo, true
}

func (s *RepositoryService) RevealMailCredential(ctx context.Context, id string) (string, error) {
	repo, err := s.store.Repository(ctx, id)
	if err != nil {
		return "", err
	}
	password, err := s.box.Decrypt(repo.MailPasswordCipher)
	return string(password), err
}

func (s *RepositoryService) RotateMailCredential(ctx context.Context, id string) (string, error) {
	password, err := secure.RandomToken(24)
	if err != nil {
		return "", err
	}
	hash, err := secure.HashPassword(password)
	if err != nil {
		return "", err
	}
	cipher, err := s.box.Encrypt([]byte(password))
	if err != nil {
		return "", err
	}
	if err := s.store.UpdateMailCredential(ctx, id, hash, cipher); err != nil {
		return "", err
	}
	return password, nil
}

func (s *RepositoryService) RetryClone(ctx context.Context, id string) error {
	return s.RefreshRepository(ctx, id)
}

func (s *RepositoryService) RefreshRepository(ctx context.Context, id string) error {
	s.mu.Lock()
	if call := s.running[id]; call != nil {
		s.mu.Unlock()
		select {
		case <-call.done:
			return call.err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	workCtx, cancel := context.WithCancel(ctx)
	call := &refreshCall{done: make(chan struct{}), cancel: cancel}
	s.running[id] = call
	s.mu.Unlock()

	call.err = s.refresh(workCtx, id)
	cancel()
	close(call.done)
	s.mu.Lock()
	delete(s.running, id)
	s.mu.Unlock()
	return call.err
}

func (s *RepositoryService) refresh(ctx context.Context, id string) error {
	repo, err := s.store.Repository(ctx, id)
	if err != nil {
		return err
	}
	if repo.Status == "deleting" {
		return errors.New("repository is being deleted")
	}
	authBytes, err := s.box.Decrypt(repo.AuthSecret)
	if err != nil {
		return err
	}
	auth, err := gitbackend.DecodeAuth(authBytes)
	if err != nil {
		return err
	}
	path := s.RepositoryPath(id)
	status := "fetching"
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		status = "cloning"
	}
	_ = s.store.UpdateRepositoryStatus(ctx, id, status, "", repo.DefaultBranch, repo.SSHHostFingerprint, false)

	fingerprint := repo.SSHHostFingerprint
	if status == "cloning" {
		fingerprint, err = s.git.Clone(ctx, repo.RemoteURL, path, repo.AuthType, auth)
	} else {
		fingerprint, err = s.git.Fetch(ctx, repo.RemoteURL, path, repo.AuthType, auth)
	}
	if err != nil {
		_ = s.store.UpdateRepositoryStatus(context.Background(), id, "error", err.Error(), repo.DefaultBranch, fingerprint, false)
		return err
	}
	defaultBranch, err := s.git.DefaultBranch(ctx, repo.RemoteURL, path, repo.AuthType, auth)
	if err != nil {
		_ = s.store.UpdateRepositoryStatus(context.Background(), id, "error", err.Error(), repo.DefaultBranch, fingerprint, false)
		return err
	}
	branches, err := s.git.Branches(ctx, path)
	if err != nil {
		return s.recordRefreshError(id, repo, fingerprint, err)
	}
	oldMailboxes, err := s.store.Mailboxes(ctx, id)
	if err != nil {
		return s.recordRefreshError(id, repo, fingerprint, err)
	}
	oldByBranch := make(map[string]store.Mailbox, len(oldMailboxes))
	for _, mailbox := range oldMailboxes {
		oldByBranch[mailbox.Branch] = mailbox
	}
	snapshots := make([]store.BranchSnapshot, 0, len(branches))
	for _, branch := range branches {
		old, exists := oldByBranch[branch.Name]
		fastForward := exists && (old.HeadOID == branch.OID || s.git.IsAncestor(ctx, path, old.HeadOID, branch.OID))
		defaultMappingChanged := repo.DefaultBranch != "" && repo.DefaultBranch != defaultBranch &&
			(branch.Name == repo.DefaultBranch || branch.Name == defaultBranch)
		revision := branch.OID
		if fastForward && !defaultMappingChanged {
			if old.HeadOID == branch.OID {
				revision = ""
			} else {
				revision = old.HeadOID + ".." + branch.OID
			}
		} else {
			fastForward = false
		}
		var commits []gitbackend.Commit
		if revision != "" {
			commits, err = s.git.Commits(ctx, path, revision)
			if err != nil {
				return s.recordRefreshError(id, repo, fingerprint, err)
			}
		}
		snapshot := store.BranchSnapshot{Name: branch.Name, HeadOID: branch.OID, FastForward: fastForward}
		for _, commit := range commits {
			snapshot.NewCommits = append(snapshot.NewCommits, store.CommitSnapshot{
				OID: commit.OID, Subject: commit.Subject, AuthorName: commit.AuthorName,
				AuthorEmail: commit.AuthorEmail, AuthoredAt: commit.AuthoredAt,
			})
		}
		snapshots = append(snapshots, snapshot)
	}
	if err := s.store.ReplaceMailboxes(ctx, id, defaultBranch, snapshots); err != nil {
		return s.recordRefreshError(id, repo, fingerprint, err)
	}
	return s.store.UpdateRepositoryStatus(ctx, id, "ready", "", defaultBranch, fingerprint, true)
}

func (s *RepositoryService) recordRefreshError(id string, repo store.Repository, fingerprint string, err error) error {
	_ = s.store.UpdateRepositoryStatus(context.Background(), id, "error", err.Error(), repo.DefaultBranch, fingerprint, false)
	return err
}

func (s *RepositoryService) DeleteRepository(ctx context.Context, id string) error {
	if err := s.store.SetDeleting(ctx, id); err != nil {
		return err
	}
	s.mu.Lock()
	if call := s.running[id]; call != nil {
		call.cancel()
		s.mu.Unlock()
		select {
		case <-call.done:
		case <-ctx.Done():
			return ctx.Err()
		}
	} else {
		s.mu.Unlock()
	}
	if err := os.RemoveAll(s.RepositoryPath(id)); err != nil {
		return err
	}
	if err := os.RemoveAll(filepath.Join(s.cacheDir, "messages", id)); err != nil {
		return err
	}
	return s.store.DeleteRepository(ctx, id)
}

func (s *RepositoryService) RepositoryPath(id string) string {
	return filepath.Join(s.cacheDir, id+".git")
}

func (s *RepositoryService) EnsureAll(ctx context.Context) {
	repos, err := s.store.ListRepositories(ctx)
	if err != nil {
		s.logger.Error("list repositories for recovery", "error", err)
		return
	}
	for _, repo := range repos {
		if repo.Status == "deleting" {
			_ = s.DeleteRepository(ctx, repo.ID)
			continue
		}
		if _, err := os.Stat(s.RepositoryPath(repo.ID)); errors.Is(err, os.ErrNotExist) {
			go func(id string) {
				if err := s.RefreshRepository(context.Background(), id); err != nil {
					s.logger.Error("recover missing repository cache", "repository_id", id, "error", err)
				}
			}(repo.ID)
		}
	}
}

func (s *RepositoryService) Mailboxes(ctx context.Context, repoID string) ([]store.Mailbox, error) {
	return s.store.Mailboxes(ctx, repoID)
}

func (s *RepositoryService) Mailbox(ctx context.Context, repoID, name string) (store.Mailbox, error) {
	return s.store.MailboxByName(ctx, repoID, name)
}

func (s *RepositoryService) Messages(ctx context.Context, mailboxID int64) ([]store.Message, error) {
	return s.store.Messages(ctx, mailboxID)
}

func (s *RepositoryService) RenderMessage(ctx context.Context, repo store.Repository, mailbox store.Mailbox, msg store.Message) ([]byte, error) {
	if msg.CachePath != "" {
		if data, err := os.ReadFile(msg.CachePath); err == nil {
			return data, nil
		}
	}
	patch, err := s.git.RenderCommit(ctx, s.RepositoryPath(repo.ID), msg.CommitOID)
	if err != nil {
		return nil, err
	}
	data := buildMessage(repo, mailbox, msg, patch)
	branchHash := sha256.Sum256([]byte(mailbox.Branch))
	dir := filepath.Join(s.cacheDir, "messages", repo.ID, hex.EncodeToString(branchHash[:8]))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, msg.CommitOID+".eml")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return nil, err
	}
	_ = s.store.UpdateMessageCache(ctx, mailbox.ID, msg.UID, int64(len(data)), path)
	return data, nil
}

func buildMessage(repo store.Repository, mailbox store.Mailbox, msg store.Message, patch []byte) []byte {
	safe := func(value string) string {
		return strings.ReplaceAll(strings.ReplaceAll(value, "\r", " "), "\n", " ")
	}
	subject := mime.QEncoding.Encode("utf-8", safe(msg.Subject))
	fromName := mime.QEncoding.Encode("utf-8", safe(msg.AuthorName))
	messageIDBranch := sha256.Sum256([]byte(mailbox.Branch))
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s <%s>\r\n", fromName, safe(msg.AuthorEmail))
	fmt.Fprintf(&b, "To: %s\r\n", safe(repo.MailUsername))
	fmt.Fprintf(&b, "Subject: %s\r\n", subject)
	fmt.Fprintf(&b, "Date: %s\r\n", msg.AuthoredAt.Format(time.RFC1123Z))
	fmt.Fprintf(&b, "Message-ID: <%s.%x.%s@git2imap>\r\n", msg.CommitOID, messageIDBranch[:6], repo.ID)
	fmt.Fprintf(&b, "X-Git-Repository: %s\r\n", safe(repo.Name))
	fmt.Fprintf(&b, "X-Git-Branch: %s\r\n", safe(mailbox.Branch))
	fmt.Fprintf(&b, "X-Git-Commit: %s\r\n", msg.CommitOID)
	b.WriteString("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n")
	body := strings.ReplaceAll(string(patch), "\r\n", "\n")
	body = strings.ReplaceAll(body, "\n", "\r\n")
	b.WriteString(body)
	if !strings.HasSuffix(body, "\r\n") {
		b.WriteString("\r\n")
	}
	return []byte(b.String())
}
