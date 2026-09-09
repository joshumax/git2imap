package secure

import (
	"bytes"
	"testing"
)

func TestBoxRoundTrip(t *testing.T) {
	box, err := NewBox(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := box.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if encrypted == "secret" {
		t.Fatal("ciphertext exposed plaintext")
	}
	plain, err := box.Decrypt(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != "secret" {
		t.Fatalf("got %q", plain)
	}
}

func TestPasswordHash(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword(hash, "correct horse battery staple") {
		t.Fatal("correct password was rejected")
	}
	if VerifyPassword(hash, "wrong") {
		t.Fatal("wrong password was accepted")
	}
}
