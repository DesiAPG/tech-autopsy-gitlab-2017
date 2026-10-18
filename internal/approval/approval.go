// Package approval implements the "second pair of eyes" for destructive
// commands: a short-lived token, signed by an approver, that authorises one
// exact command line.
//
// Tokens are HMAC-SHA256 over {command hash, approver, expiry} with a shared
// secret (GO_GUARD_SECRET). That keeps the tool dependency-free and offline;
// in a real organisation the secret lives in your secrets manager and the
// approve step runs behind your chat-ops / change-request tooling.
package approval

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const prefix = "gg1"

// Claims is what a token asserts.
type Claims struct {
	CommandSHA string `json:"c"`
	Approver   string `json:"by"`
	Expires    int64  `json:"exp"`
}

var (
	ErrNoSecret     = errors.New("GO_GUARD_SECRET no está definido")
	ErrMalformed    = errors.New("token de aprobación mal formado")
	ErrSignature    = errors.New("firma del token inválida")
	ErrExpired      = errors.New("el token de aprobación expiró")
	ErrWrongCommand = errors.New("el token aprueba otro comando")
	ErrSelfApproval = errors.New("no puedes aprobar tu propio comando (regla de cuatro ojos)")
)

// Normalize collapses whitespace so cosmetic spacing does not change the hash.
func Normalize(cmd string) string {
	return strings.Join(strings.Fields(cmd), " ")
}

// Hash returns the hex SHA-256 of the normalized command.
func Hash(cmd string) string {
	sum := sha256.Sum256([]byte(Normalize(cmd)))
	return hex.EncodeToString(sum[:])
}

// Sign issues a token for cmd, approved by approver, valid for ttl.
func Sign(secret, cmd, approver string, ttl time.Duration, now time.Time) (string, error) {
	if secret == "" {
		return "", ErrNoSecret
	}
	if approver == "" {
		return "", errors.New("falta el nombre de quien aprueba")
	}
	if ttl <= 0 || ttl > 24*time.Hour {
		return "", errors.New("el TTL debe estar entre 1s y 24h")
	}
	body, err := json.Marshal(Claims{CommandSHA: Hash(cmd), Approver: approver, Expires: now.Add(ttl).Unix()})
	if err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(body)
	return prefix + "." + payload + "." + sign(secret, payload), nil
}

// Verify checks a token against the command the requester is about to run.
// requester is the local user; unless allowSelf, it must differ from the
// approver.
func Verify(secret, token, cmd, requester string, allowSelf bool, now time.Time) (Claims, error) {
	var c Claims
	if secret == "" {
		return c, ErrNoSecret
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != prefix {
		return c, ErrMalformed
	}
	if !hmac.Equal([]byte(sign(secret, parts[1])), []byte(parts[2])) {
		return c, ErrSignature
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return c, ErrMalformed
	}
	if err := json.Unmarshal(body, &c); err != nil {
		return c, ErrMalformed
	}
	if now.Unix() >= c.Expires {
		return c, ErrExpired
	}
	if c.CommandSHA != Hash(cmd) {
		return c, ErrWrongCommand
	}
	if !allowSelf && strings.EqualFold(c.Approver, requester) {
		return c, ErrSelfApproval
	}
	return c, nil
}

func sign(secret, payload string) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(prefix + "." + payload))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// String renders claims for humans.
func (c Claims) String() string {
	return fmt.Sprintf("aprobado por %s hasta %s", c.Approver, time.Unix(c.Expires, 0).Format(time.RFC3339))
}
