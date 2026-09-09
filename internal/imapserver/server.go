package imapserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-imap/v2"
	base "github.com/emersion/go-imap/v2/imapserver"

	"git2imap/internal/config"
	"git2imap/internal/service"
	"git2imap/internal/store"
)

type Server struct {
	plain *base.Server
	tls   *base.Server
	cfg   config.IMAPConfig
	log   *slog.Logger
}

func New(cfg config.IMAPConfig, repositories *service.RepositoryService, log *slog.Logger) (*Server, error) {
	tlsConfig, err := loadTLSConfig(cfg.TLSCert, cfg.TLSKey)
	if err != nil {
		return nil, err
	}
	newSession := func(conn *base.Conn) (base.Session, *base.GreetingData, error) {
		return &session{
			repositories: repositories,
			idleInterval: cfg.IdleFetchInterval,
		}, &base.GreetingData{}, nil
	}
	options := &base.Options{
		NewSession:   newSession,
		Caps:         imap.CapSet{imap.CapIMAP4rev1: {}},
		TLSConfig:    tlsConfig,
		InsecureAuth: cfg.AllowInsecureAuth || (tlsConfig == nil && isLoopbackAddress(cfg.Addr)),
		Logger:       printfLogger{log.With("server", "imap")},
	}
	return &Server{
		plain: base.New(options),
		tls: base.New(&base.Options{
			NewSession: newSession,
			Caps:       imap.CapSet{imap.CapIMAP4rev1: {}},
			TLSConfig:  tlsConfig,
			Logger:     printfLogger{log.With("server", "imaps")},
		}),
		cfg: cfg,
		log: log,
	}, nil
}

func (s *Server) Serve(ctx context.Context, report func(string, error)) {
	if s.cfg.Addr != "" {
		go func() { report("imap", s.plain.ListenAndServe(s.cfg.Addr)) }()
	}
	if s.cfg.TLSAddr != "" && s.cfg.TLSCert != "" {
		go func() { report("imaps", s.tls.ListenAndServeTLS(s.cfg.TLSAddr)) }()
	}
	go func() {
		<-ctx.Done()
		_ = s.plain.Close()
		_ = s.tls.Close()
	}()
}

func loadTLSConfig(certPath, keyPath string) (*tls.Config, error) {
	if certPath == "" && keyPath == "" {
		return nil, nil
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load TLS certificate: %w", err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
}

func isLoopbackAddress(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return host == "localhost" || (ip != nil && ip.IsLoopback())
}

type printfLogger struct{ log *slog.Logger }

func (l printfLogger) Printf(format string, args ...interface{}) {
	l.log.Error("protocol error", "detail", fmt.Sprintf(format, args...))
}

type session struct {
	repositories *service.RepositoryService
	idleInterval time.Duration

	repo     store.Repository
	selected *store.Mailbox
	messages []store.Message
	mu       sync.Mutex
}

func (s *session) Close() error { return nil }

func (s *session) Login(username, password string) error {
	repo, ok := s.repositories.Authenticate(context.Background(), username, password)
	if !ok {
		return base.ErrAuthFailed
	}
	s.repo = repo
	return nil
}

func (s *session) Select(name string, options *imap.SelectOptions) (*imap.SelectData, error) {
	_ = s.repositories.RefreshRepository(context.Background(), s.repo.ID)
	mailbox, err := s.repositories.Mailbox(context.Background(), s.repo.ID, name)
	if err != nil {
		return nil, noSuchMailbox()
	}
	messages, err := s.repositories.Messages(context.Background(), mailbox.ID)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.selected = &mailbox
	s.messages = messages
	s.mu.Unlock()
	firstUnseen := uint32(0)
	if len(messages) > 0 {
		firstUnseen = 1
	}
	return &imap.SelectData{
		Flags:             nil,
		PermanentFlags:    nil,
		NumMessages:       uint32(len(messages)),
		FirstUnseenSeqNum: firstUnseen,
		NumRecent:         0,
		UIDNext:           imap.UID(mailbox.NextUID),
		UIDValidity:       mailbox.UIDValidity,
	}, nil
}

func (s *session) Create(string, *imap.CreateOptions) error         { return readOnly() }
func (s *session) Delete(string) error                              { return readOnly() }
func (s *session) Rename(string, string, *imap.RenameOptions) error { return readOnly() }
func (s *session) Subscribe(string) error                           { return readOnly() }
func (s *session) Unsubscribe(string) error                         { return readOnly() }
func (s *session) Append(string, imap.LiteralReader, *imap.AppendOptions) (*imap.AppendData, error) {
	return nil, readOnly()
}

func (s *session) List(w *base.ListWriter, ref string, patterns []string, options *imap.ListOptions) error {
	_ = s.repositories.RefreshRepository(context.Background(), s.repo.ID)
	mailboxes, err := s.repositories.Mailboxes(context.Background(), s.repo.ID)
	if err != nil {
		return err
	}
	if len(patterns) == 0 {
		return w.WriteList(&imap.ListData{Attrs: []imap.MailboxAttr{imap.MailboxAttrNoSelect}, Delim: '/'})
	}
	wroteParent := false
	for _, mailbox := range mailboxes {
		if !matchesList(mailbox.Name, ref, patterns) {
			continue
		}
		data := &imap.ListData{
			Attrs:   []imap.MailboxAttr{imap.MailboxAttrHasNoChildren, imap.MailboxAttrSubscribed},
			Delim:   '/',
			Mailbox: mailbox.Name,
		}
		if options != nil && options.ReturnStatus != nil {
			status, err := s.status(mailbox, options.ReturnStatus)
			if err != nil {
				return err
			}
			data.Status = status
		}
		if err := w.WriteList(data); err != nil {
			return err
		}
		if strings.HasPrefix(mailbox.Name, "Branches/") {
			wroteParent = true
		}
	}
	if wroteParent && matchesList("Branches", ref, patterns) {
		return w.WriteList(&imap.ListData{
			Attrs: []imap.MailboxAttr{imap.MailboxAttrNoSelect, imap.MailboxAttrHasChildren},
			Delim: '/', Mailbox: "Branches",
		})
	}
	return nil
}

func matchesList(name, ref string, patterns []string) bool {
	for _, pattern := range patterns {
		if base.MatchList(name, '/', ref, pattern) {
			return true
		}
	}
	return false
}

func (s *session) Status(name string, options *imap.StatusOptions) (*imap.StatusData, error) {
	_ = s.repositories.RefreshRepository(context.Background(), s.repo.ID)
	mailbox, err := s.repositories.Mailbox(context.Background(), s.repo.ID, name)
	if err != nil {
		return nil, noSuchMailbox()
	}
	return s.status(mailbox, options)
}

func (s *session) status(mailbox store.Mailbox, options *imap.StatusOptions) (*imap.StatusData, error) {
	messages, err := s.repositories.Messages(context.Background(), mailbox.ID)
	if err != nil {
		return nil, err
	}
	data := &imap.StatusData{Mailbox: mailbox.Name, UIDNext: imap.UID(mailbox.NextUID), UIDValidity: mailbox.UIDValidity}
	if options == nil {
		return data, nil
	}
	count := uint32(len(messages))
	zero := uint32(0)
	if options.NumMessages {
		data.NumMessages = &count
	}
	if options.NumUnseen {
		data.NumUnseen = &count
	}
	if options.NumRecent {
		data.NumRecent = &zero
	}
	if options.NumDeleted {
		data.NumDeleted = &zero
	}
	if options.Size {
		var total int64
		for _, message := range messages {
			size := message.Size
			if size == 0 {
				raw, err := s.repositories.RenderMessage(context.Background(), s.repo, mailbox, message)
				if err != nil {
					return nil, err
				}
				size = int64(len(raw))
			}
			total += size
		}
		data.Size = &total
	}
	return data, nil
}

func (s *session) Poll(w *base.UpdateWriter, allowExpunge bool) error {
	return s.refreshSelected(w)
}

func (s *session) Idle(w *base.UpdateWriter, stop <-chan struct{}) error {
	interval := s.idleInterval
	if interval <= 0 {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return nil
		case <-ticker.C:
			if err := s.refreshSelected(w); err != nil {
				return err
			}
		}
	}
}

func (s *session) refreshSelected(w *base.UpdateWriter) error {
	s.mu.Lock()
	selected := s.selected
	oldCount := len(s.messages)
	s.mu.Unlock()
	if err := s.repositories.RefreshRepository(context.Background(), s.repo.ID); err != nil {
		return nil
	}
	if selected == nil {
		return nil
	}
	current, err := s.repositories.Mailbox(context.Background(), s.repo.ID, selected.Name)
	if err != nil {
		return &imap.Error{Type: imap.StatusResponseTypeNo, Text: "selected mailbox no longer exists"}
	}
	if current.UIDValidity != selected.UIDValidity {
		return &imap.Error{Type: imap.StatusResponseTypeNo, Text: "mailbox history changed; reselect mailbox"}
	}
	messages, err := s.repositories.Messages(context.Background(), current.ID)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.selected = &current
	s.messages = messages
	s.mu.Unlock()
	if len(messages) != oldCount {
		return w.WriteNumMessages(uint32(len(messages)))
	}
	return nil
}

func (s *session) Unselect() error {
	s.mu.Lock()
	s.selected = nil
	s.messages = nil
	s.mu.Unlock()
	return nil
}

func (s *session) Expunge(*base.ExpungeWriter, *imap.UIDSet) error { return readOnly() }
func (s *session) Store(*base.FetchWriter, imap.NumSet, *imap.StoreFlags, *imap.StoreOptions) error {
	return readOnly()
}
func (s *session) Copy(imap.NumSet, string) (*imap.CopyData, error) { return nil, readOnly() }

func (s *session) Fetch(w *base.FetchWriter, numSet imap.NumSet, options *imap.FetchOptions) error {
	s.mu.Lock()
	mailbox := s.selected
	messages := append([]store.Message(nil), s.messages...)
	s.mu.Unlock()
	if mailbox == nil {
		return errors.New("no mailbox selected")
	}
	maxUID := uint32(0)
	if len(messages) > 0 {
		maxUID = messages[len(messages)-1].UID
	}
	for i, message := range messages {
		seq := uint32(i + 1)
		if !numSetContains(numSet, seq, message.UID, uint32(len(messages)), maxUID) {
			continue
		}
		response := w.CreateMessage(seq)
		response.WriteUID(imap.UID(message.UID))
		if options.Flags {
			response.WriteFlags(nil)
		}
		if options.InternalDate {
			response.WriteInternalDate(message.AuthoredAt)
		}
		needsBody := options.RFC822Size || options.Envelope || options.BodyStructure != nil ||
			len(options.BodySection) > 0 || len(options.BinarySection) > 0 || len(options.BinarySectionSize) > 0
		var raw []byte
		var err error
		if needsBody {
			raw, err = s.repositories.RenderMessage(context.Background(), s.repo, *mailbox, message)
			if err != nil {
				return err
			}
		}
		if options.RFC822Size {
			response.WriteRFC822Size(int64(len(raw)))
		}
		if options.Envelope {
			response.WriteEnvelope(messageEnvelope(s.repo, *mailbox, message))
		}
		if options.BodyStructure != nil {
			response.WriteBodyStructure(base.ExtractBodyStructure(bytes.NewReader(raw)))
		}
		for _, section := range options.BodySection {
			value := base.ExtractBodySection(bytes.NewReader(raw), section)
			writer := response.WriteBodySection(section, int64(len(value)))
			if _, err := writer.Write(value); err != nil {
				return err
			}
			if err := writer.Close(); err != nil {
				return err
			}
		}
		for _, section := range options.BinarySection {
			value := base.ExtractBinarySection(bytes.NewReader(raw), section)
			writer := response.WriteBinarySection(section, int64(len(value)))
			if _, err := writer.Write(value); err != nil {
				return err
			}
			if err := writer.Close(); err != nil {
				return err
			}
		}
		for _, section := range options.BinarySectionSize {
			response.WriteBinarySectionSize(section, base.ExtractBinarySectionSize(bytes.NewReader(raw), section))
		}
		if err := response.Close(); err != nil {
			return err
		}
	}
	return nil
}

func messageEnvelope(repo store.Repository, mailbox store.Mailbox, message store.Message) *imap.Envelope {
	fromMailbox, fromHost := splitAddress(message.AuthorEmail)
	branchHash := sha256.Sum256([]byte(mailbox.Branch))
	return &imap.Envelope{
		Date: message.AuthoredAt, Subject: message.Subject,
		From:      []imap.Address{{Name: message.AuthorName, Mailbox: fromMailbox, Host: fromHost}},
		Sender:    []imap.Address{{Name: message.AuthorName, Mailbox: fromMailbox, Host: fromHost}},
		ReplyTo:   []imap.Address{{Name: message.AuthorName, Mailbox: fromMailbox, Host: fromHost}},
		To:        []imap.Address{imapAddress(repo.MailUsername)},
		MessageID: fmt.Sprintf("%s.%x.%s@git2imap", message.CommitOID, branchHash[:6], repo.ID),
	}
}

func imapAddress(address string) imap.Address {
	mailbox, host := splitAddress(address)
	return imap.Address{Mailbox: mailbox, Host: host}
}

func splitAddress(address string) (string, string) {
	parts := strings.SplitN(address, "@", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return address, "localhost"
}

func (s *session) Search(kind base.NumKind, criteria *imap.SearchCriteria, options *imap.SearchOptions) (*imap.SearchData, error) {
	s.mu.Lock()
	mailbox := s.selected
	messages := append([]store.Message(nil), s.messages...)
	s.mu.Unlock()
	if mailbox == nil {
		return nil, errors.New("no mailbox selected")
	}
	var seqSet imap.SeqSet
	var uidSet imap.UIDSet
	var data imap.SearchData
	maxUID := uint32(0)
	if len(messages) > 0 {
		maxUID = messages[len(messages)-1].UID
	}
	for i, message := range messages {
		seq := uint32(i + 1)
		match, err := s.matches(message, *mailbox, seq, uint32(len(messages)), maxUID, criteria)
		if err != nil {
			return nil, err
		}
		if !match {
			continue
		}
		var number uint32
		if kind == base.NumKindUID {
			uidSet.AddNum(imap.UID(message.UID))
			number = message.UID
		} else {
			seqSet.AddNum(seq)
			number = seq
		}
		data.Count++
		if data.Min == 0 || number < data.Min {
			data.Min = number
		}
		if number > data.Max {
			data.Max = number
		}
	}
	if kind == base.NumKindUID {
		data.All = uidSet
	} else {
		data.All = seqSet
	}
	return &data, nil
}

func (s *session) matches(message store.Message, mailbox store.Mailbox, seq, maxSeq, maxUID uint32, criteria *imap.SearchCriteria) (bool, error) {
	for _, set := range criteria.SeqNum {
		if !seqSetContains(set, seq, maxSeq) {
			return false, nil
		}
	}
	for _, set := range criteria.UID {
		if !uidSetContains(set, message.UID, maxUID) {
			return false, nil
		}
	}
	if !dateMatches(message.AuthoredAt, criteria.Since, criteria.Before) ||
		!dateMatches(message.AuthoredAt, criteria.SentSince, criteria.SentBefore) {
		return false, nil
	}
	for _, flag := range criteria.Flag {
		if flag != "" {
			return false, nil
		}
	}
	for _, flag := range criteria.NotFlag {
		if flag == "" {
			return false, nil
		}
	}
	needsRaw := len(criteria.Header) > 0 || len(criteria.Body) > 0 || len(criteria.Text) > 0 ||
		criteria.Larger != 0 || criteria.Smaller != 0
	var raw []byte
	var err error
	if needsRaw {
		raw, err = s.repositories.RenderMessage(context.Background(), s.repo, mailbox, message)
		if err != nil {
			return false, err
		}
	}
	if criteria.Larger != 0 && int64(len(raw)) <= criteria.Larger {
		return false, nil
	}
	if criteria.Smaller != 0 && int64(len(raw)) >= criteria.Smaller {
		return false, nil
	}
	lower := strings.ToLower(string(raw))
	for _, field := range criteria.Header {
		needle := strings.ToLower(field.Value)
		key := strings.ToLower(field.Key) + ":"
		if !strings.Contains(lower, key) || (needle != "" && !strings.Contains(lower, needle)) {
			return false, nil
		}
	}
	for _, value := range append(append([]string{}, criteria.Body...), criteria.Text...) {
		if !strings.Contains(lower, strings.ToLower(value)) {
			return false, nil
		}
	}
	for _, not := range criteria.Not {
		ok, err := s.matches(message, mailbox, seq, maxSeq, maxUID, &not)
		if err != nil || ok {
			return false, err
		}
	}
	for _, pair := range criteria.Or {
		left, err := s.matches(message, mailbox, seq, maxSeq, maxUID, &pair[0])
		if err != nil {
			return false, err
		}
		right, err := s.matches(message, mailbox, seq, maxSeq, maxUID, &pair[1])
		if err != nil || (!left && !right) {
			return false, err
		}
	}
	return true, nil
}

func dateMatches(value, since, before time.Time) bool {
	day := time.Date(value.Year(), value.Month(), value.Day(), 0, 0, 0, 0, time.UTC)
	return (since.IsZero() || !day.Before(since)) && (before.IsZero() || day.Before(before))
}

func numSetContains(set imap.NumSet, seq, uid, maxSeq, maxUID uint32) bool {
	switch value := set.(type) {
	case imap.SeqSet:
		return seqSetContains(value, seq, maxSeq)
	case imap.UIDSet:
		return uidSetContains(value, uid, maxUID)
	default:
		return false
	}
}

func seqSetContains(set imap.SeqSet, value, max uint32) bool {
	for _, item := range set {
		start, stop := item.Start, item.Stop
		if start == 0 {
			start = max
		}
		if stop == 0 {
			stop = max
		}
		if start > stop {
			start, stop = stop, start
		}
		if value >= start && value <= stop {
			return true
		}
	}
	return false
}

func uidSetContains(set imap.UIDSet, value, max uint32) bool {
	for _, item := range set {
		start, stop := uint32(item.Start), uint32(item.Stop)
		if start == 0 {
			start = max
		}
		if stop == 0 {
			stop = max
		}
		if start > stop {
			start, stop = stop, start
		}
		if value >= start && value <= stop {
			return true
		}
	}
	return false
}

func readOnly() error {
	return &imap.Error{Type: imap.StatusResponseTypeNo, Text: "repository mailboxes are read-only"}
}

func noSuchMailbox() error {
	return &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeNonExistent, Text: "no such mailbox"}
}

var _ base.Session = (*session)(nil)
var _ io.Closer = (*session)(nil)
