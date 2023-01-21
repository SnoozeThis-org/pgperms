package pgperms

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"strconv"
	"strings"

	"github.com/xdg-go/pbkdf2"
	"github.com/xdg-go/scram"
)

// TODO: Use `SELECT setting FROM pg_settings WHERE name='password_encryption'` and only send encrypted passwords.

var scramRe = regexp.MustCompile(`^SCRAM-(SHA-1|SHA-256|SHA-512)\$(\d+):([^$]+)\$([^:]+):(.+)$`)

func verifyPassword(hashed, username, plain string) bool {
	if hashed == plain {
		return true
	}
	if strings.HasPrefix(hashed, "md5") {
		b := md5.Sum([]byte(plain + username))
		h := hex.EncodeToString(b[:])
		return h == hashed[3:]
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
