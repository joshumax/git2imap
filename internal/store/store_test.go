package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestReplaceMailboxesPreservesAndResetsUIDs(t *testing.T) {
	ctx := context.Background()
	st, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Now().UTC()
	repo := Repository{
		ID: "repo", Name: "repo", RemoteURL: "https://example.test/repo.git",
		AuthType: "none", Status: "ready", MailUsername: "repo-user",
		MailPasswordHash: "hash", MailPasswordCipher: "cipher", CreatedAt: now, UpdatedAt: now,
	}
	if err := st.CreateRepository(ctx, repo); err != nil {
		t.Fatal(err)
	}
	commit := func(oid, subject string) CommitSnapshot {
		return CommitSnapshot{OID: oid, Subject: subject, AuthorName: "A", AuthorEmail: "a@example.com", AuthoredAt: now}
	}
	if err := st.ReplaceMailboxes(ctx, repo.ID, "main", []BranchSnapshot{
		{Name: "main", HeadOID: "a", NewCommits: []CommitSnapshot{commit("a", "one")}},
		{Name: "next", HeadOID: "b", NewCommits: []CommitSnapshot{commit("b", "next")}},
	}); err != nil {
		t.Fatal(err)
	}
	mainBox, err := st.MailboxByName(ctx, repo.ID, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	initialValidity := mainBox.UIDValidity
	if err := st.ReplaceMailboxes(ctx, repo.ID, "main", []BranchSnapshot{
		{Name: "main", HeadOID: "c", FastForward: true, NewCommits: []CommitSnapshot{commit("c", "two")}},
		{Name: "next", HeadOID: "b", FastForward: true},
	}); err != nil {
		t.Fatal(err)
	}
	mainBox, _ = st.MailboxByName(ctx, repo.ID, "INBOX")
	messages, _ := st.Messages(ctx, mainBox.ID)
	if len(messages) != 2 || messages[0].UID != 1 || messages[1].UID != 2 {
		t.Fatalf("fast-forward messages = %#v", messages)
	}
	if mainBox.UIDValidity != initialValidity {
		t.Fatal("fast-forward changed UIDVALIDITY")
	}
	if err := st.ReplaceMailboxes(ctx, repo.ID, "next", []BranchSnapshot{
		{Name: "main", HeadOID: "d", NewCommits: []CommitSnapshot{commit("d", "rewritten")}},
		{Name: "next", HeadOID: "b", NewCommits: []CommitSnapshot{commit("b", "next")}},
	}); err != nil {
		t.Fatal(err)
	}
	newInbox, err := st.MailboxByName(ctx, repo.ID, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	if newInbox.Branch != "next" {
		t.Fatalf("INBOX branch = %q", newInbox.Branch)
	}
	oldMain, err := st.MailboxByName(ctx, repo.ID, "Branches/main")
	if err != nil {
		t.Fatal(err)
	}
	if oldMain.UIDValidity == initialValidity {
		t.Fatal("rewrite did not change UIDVALIDITY")
	}
}
