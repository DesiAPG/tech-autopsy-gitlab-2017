package approval

import (
	"errors"
	"strings"
	"testing"
	"time"
)

const cmd = "sudo rm -rf /var/opt/gitlab/postgresql/data"

var now = time.Date(2017, 1, 31, 23, 0, 0, 0, time.UTC)

func TestRoundTrip(t *testing.T) {
	tok, err := Sign("secret", cmd, "alice", 15*time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	c, err := Verify("secret", tok, "sudo  rm -rf   /var/opt/gitlab/postgresql/data", "bob", false, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if c.Approver != "alice" {
		t.Errorf("approver = %q", c.Approver)
	}
}

func TestRejections(t *testing.T) {
	tok, _ := Sign("secret", cmd, "alice", 15*time.Minute, now)
	tests := []struct {
		name               string
		secret, token, cmd string
		user               string
		at                 time.Time
		want               error
	}{
		{"expired", "secret", tok, cmd, "bob", now.Add(16 * time.Minute), ErrExpired},
		{"other command", "secret", tok, "sudo rm -rf /var/opt/gitlab", "bob", now, ErrWrongCommand},
		{"wrong secret", "other", tok, cmd, "bob", now, ErrSignature},
		{"self approval", "secret", tok, cmd, "alice", now, ErrSelfApproval},
		{"garbage", "secret", "nope", cmd, "bob", now, ErrMalformed},
		{"no secret", "", tok, cmd, "bob", now, ErrNoSecret},
	}
	for _, tt := range tests {
		if _, err := Verify(tt.secret, tt.token, tt.cmd, tt.user, false, tt.at); !errors.Is(err, tt.want) {
			t.Errorf("%s: err = %v, want %v", tt.name, err, tt.want)
		}
	}
}

func TestTamperedPayload(t *testing.T) {
	tok, _ := Sign("secret", cmd, "alice", time.Minute, now)
	parts := strings.Split(tok, ".")
	forged, _ := Sign("attacker", cmd, "mallory", time.Hour, now)
	parts[1] = strings.Split(forged, ".")[1]
	if _, err := Verify("secret", strings.Join(parts, "."), cmd, "bob", false, now); !errors.Is(err, ErrSignature) {
		t.Errorf("tampered payload accepted: %v", err)
	}
}

func TestSelfApprovalAllowedByConfig(t *testing.T) {
	tok, _ := Sign("secret", cmd, "alice", time.Minute, now)
	if _, err := Verify("secret", tok, cmd, "alice", true, now); err != nil {
		t.Errorf("allowSelf: %v", err)
	}
}

func TestSignValidation(t *testing.T) {
	if _, err := Sign("", cmd, "alice", time.Minute, now); !errors.Is(err, ErrNoSecret) {
		t.Error("empty secret must fail")
	}
	if _, err := Sign("s", cmd, "alice", 48*time.Hour, now); err == nil {
		t.Error("TTL over 24h must fail")
	}
}
