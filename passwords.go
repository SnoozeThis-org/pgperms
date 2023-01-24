package pgperms

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"regexp"
	"strconv"

	"github.com/jackc/pgx/v4"
	"github.com/xdg-go/pbkdf2"
	"github.com/xdg-go/scram"
)

var (
	md5Re   = regexp.MustCompile(`^md5[0-9a-f]{32}$`)
	scramRe = regexp.MustCompile(`^SCRAM-(SHA-1|SHA-256|SHA-512)\$(\d+):([^$]+)\$([^:]+):(.+)$`)
)

// verifyPassword returns whether the hashed password belongs to the given user and password.
func verifyPassword(hashed, username, plain string) bool {
	if hashed == plain {
		return true
	}
	if md5Re.MatchString(hashed) {
		return hashed == MD5Password(username, plain)
	}
	if m := scramRe.FindStringSubmatch(hashed); m != nil {
		hgf := getScramHash(m[1])
		if hgf == nil {
			return false
		}
		iters, err := strconv.ParseInt(m[2], 10, 64)
		if err != nil {
			return false
		}
		salt, err := base64.StdEncoding.DecodeString(m[3])
		if err != nil {
			return false
		}
		storedKey, err := base64.StdEncoding.DecodeString(m[4])
		if err != nil {
			return false
		}
		serverKey, err := base64.StdEncoding.DecodeString(m[5])
		if err != nil {
			return false
		}
		digestKey := pbkdf2.Key([]byte(plain), salt, int(iters), 32, hgf)
		clientKey := getHMACSum(hgf, digestKey, []byte("Client Key"))
		if !bytes.Equal(storedKey, getSum(hgf, clientKey)) {
			return false
		}
		if !bytes.Equal(serverKey, getHMACSum(hgf, digestKey, []byte("Server Key"))) {
			return false
		}
		return true
		/*
			s, err := hgf.NewServer(func(user string) (scram.StoredCredentials, error) {
				return scram.StoredCredentials{
					KeyFactors: scram.KeyFactors{
						Salt:  string(salt),
						Iters: int(iters),
					},
					StoredKey: storedKey,
					ServerKey: serverKey,
				}, nil
			})
			if err != nil {
				return false
			}
			c, err := scram.SHA1.NewClient(username, plain, "")
			if err != nil {
				return false
			}
			clConv := c.NewConversation()
			seConv := s.NewConversation()
			var serverMsg string
			for {
				log.Printf("server -> client: %q", serverMsg)
				clMsg, err := clConv.Step(serverMsg)
				if err != nil {
					log.Printf("Client reject: %q %v", clMsg, err)
					return false
				}
				log.Printf("client -> server: %q", clMsg)
				if clConv.Done() {
					log.Printf("Client is done. Valid: %v", clConv.Valid())
					log.Printf("Server done? %v; Server valid? %v", seConv.Done(), seConv.Valid())
					return clConv.Valid()
				}
				serverMsg, err = seConv.Step(clMsg)
				if err != nil {
					log.Printf("Server reject: %q %v", serverMsg, err)
					return false
				}
			}
		*/
	}
	return false
}

func getScramHash(name string) scram.HashGeneratorFcn {
	switch name {
	case "SHA-1":
		return scram.SHA1
	case "SHA-256":
		return scram.SHA256
	case "SHA-512":
		return scram.SHA512
	default:
		return nil
	}
}

func getHMACSum(hgf scram.HashGeneratorFcn, key, msg []byte) []byte {
	h := hmac.New(hgf, key)
	_, _ = h.Write(msg)
	return h.Sum(nil)
}

func getSum(hgf scram.HashGeneratorFcn, key []byte) []byte {
	h := hgf()
	_, _ = h.Write(key)
	return h.Sum(nil)
}

type PasswordHasher func(username, password string) (string, error)

func SelectPasswordHasher(ctx context.Context, conn *pgx.Conn) (PasswordHasher, error) {
	var method string
	if err := conn.QueryRow(ctx, "SELECT setting FROM pg_settings WHERE name='password_encryption'").Scan(&method); err != nil {
		return nil, err
	}
	switch method {
	case "scram-sha-256":
		return func(username, password string) (string, error) {
			return ScramSha256Password(password)
		}, nil
	case "md5":
		return func(username, password string) (string, error) {
			return MD5Password(username, password), nil
		}, nil
	default:
		return nil, fmt.Errorf("unknown password_encryption %q. File a feature request at https://github.com/SnoozeThis-org/pgperms/issues or don't use plaintext passwords in the config file", method)
	}
}

func MD5Password(username, password string) string {
	b := md5.Sum([]byte(password + username))
	return "md5" + hex.EncodeToString(b[:])
}

func ScramSha256Password(password string) (string, error) {
	const iterationCnt = 4096
	const keyLen = 32
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}
	digestKey := pbkdf2.Key([]byte(password), salt, iterationCnt, keyLen, sha256.New)
	clientKey := getHMACSum(scram.SHA256, digestKey, []byte("Client Key"))
	storedKey := getSum(scram.SHA256, clientKey)
	serverKey := getHMACSum(scram.SHA256, digestKey, []byte("Server Key"))

	return fmt.Sprintf("SCRAM-SHA-256$%d:%s$%s:%s",
		iterationCnt,
		base64.StdEncoding.EncodeToString(salt),
		base64.StdEncoding.EncodeToString(storedKey),
		base64.StdEncoding.EncodeToString(serverKey),
	), nil
}

func encryptPasswordsInConfig(ctx context.Context, conn *pgx.Conn, roles map[string]RoleAttributes) error {
	var hasher PasswordHasher
	for r, ra := range roles {
		if ra.Password == nil || md5Re.MatchString(*ra.Password) || scramRe.MatchString(*ra.Password) {
			continue
		}
		if hasher == nil {
			var err error
			hasher, err = SelectPasswordHasher(ctx, conn)
			if err != nil {
				return err
			}
		}
		hash, err := hasher(r, *ra.Password)
		if err != nil {
			return err
		}
		ra.hashedPassword = hash
		roles[r] = ra
	}
	return nil
}
