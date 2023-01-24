package pgperms

import (
	"fmt"
	"testing"
)

func TestPasswords(t *testing.T) {
	tests := []struct {
		username string
		plain    string
		hashed   string
		want     bool
	}{
		{
			username: "quis",
			plain:    "md5abc",
			hashed:   "md5abc",
			want:     true,
		},
		{
			username: "someuser",
			plain:    "somepassword",
			hashed:   "md5036f87626dc9bdf7b4b353ecca2556d0",
			want:     true,
		},
		{
			username: "quis",
			plain:    "SCRAM-SHA-256$4096:R1uviLmvs+9Ap6DAS1WOnQ==$mxR4jEPmRr3wePTVxZYB98KyS+mfZ9Jv0AMXbTDBTmk=:SXj6NmnPJFTuN5HLoGowDacCwKj4XmemeQYXEcsPye4=",
			hashed:   "SCRAM-SHA-256$4096:R1uviLmvs+9Ap6DAS1WOnQ==$mxR4jEPmRr3wePTVxZYB98KyS+mfZ9Jv0AMXbTDBTmk=:SXj6NmnPJFTuN5HLoGowDacCwKj4XmemeQYXEcsPye4=",
			want:     true,
		},
		{
			username: "quis",
			plain:    "helloscram",
			hashed:   "SCRAM-SHA-256$4096:Gb8MkMMMLH1J/9FVgyuZMsDF98cFTZNq$arOSLpGFM6pjdnl2iSK5jpxtFbVggzDuNEuRAJGA/Lc=:BUC644LE0O4bBhsP3p6vxptLEjniEc14ccdKgySEtrA=",
			want:     true,
		},
		{
			username: "quis",
			plain:    "helloscram",
			hashed:   "SCRAM-SHA-256$4096:R1uviLmvs+9Ap6DAS1WOnQ==$mxR4jEPmRr3wePTVxZYB98KyS+mfZ9Jv0AMXbTDBTmk=:SXj6NmnPJFTuN5HLoGowDacCwKj4XmemeQYXEcsPye4=",
			want:     true,
		},
		{
			username: "quis",
			plain:    "wrong",
			hashed:   "SCRAM-SHA-256$4096:R1uviLmvs+9Ap6DAS1WOnQ==$mxR4jEPmRr3wePTVxZYB98KyS+mfZ9Jv0AMXbTDBTmk=:SXj6NmnPJFTuN5HLoGowDacCwKj4XmemeQYXEcsPye4=",
			want:     false,
		},
		{
			username: "quis",
			plain:    "helloscram",
			hashed:   "SCRAM-SHA-256$4096:hello$world:today",
			want:     false,
		},
	}
	for _, tc := range tests {
		c := "=="
		if !tc.want {
			c = "!="
		}
		t.Run(fmt.Sprintf("%s:%s %s %s", tc.username, tc.plain, c, tc.hashed), func(t *testing.T) {
			got := verifyPassword(tc.hashed, tc.username, tc.plain)
			if got != tc.want {
				t.Errorf("verifyPassword(%q, %q, %q): %v; want %v", tc.hashed, tc.username, tc.plain, got, tc.want)
			}
		})
	}
}

func TestScramEncryption(t *testing.T) {
	hash, err := ScramSha256Password("hackme")
	if err != nil {
		t.Fatalf("Failed to encrypt password: %v", err)
	}
	if !verifyPassword(hash, "username", "hackme") {
		t.Fatalf("Encrypted password didn't verify: %v", err)
	}
}
