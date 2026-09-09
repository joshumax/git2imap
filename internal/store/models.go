package store

import "time"

type Repository struct {
	ID                 string
	Name               string
	RemoteURL          string
	AuthType           string
	AuthSecret         string
	Status             string
	StatusMessage      string
	DefaultBranch      string
	MailUsername       string
	MailPasswordHash   string
	MailPasswordCipher string
	SSHHostFingerprint string
	CreatedAt          time.Time
	UpdatedAt          time.Time
	LastFetchAt        *time.Time
}

type Mailbox struct {
	ID           int64
	RepositoryID string
	Branch       string
	Name         string
	UIDValidity  uint32
	NextUID      uint32
	HeadOID      string
}

type Message struct {
	MailboxID   int64
	UID         uint32
	CommitOID   string
	Subject     string
	AuthorName  string
	AuthorEmail string
	AuthoredAt  time.Time
	Size        int64
	CachePath   string
}

type Session struct {
	ID        string
	CSRFToken string
	ExpiresAt time.Time
}
