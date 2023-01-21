package pgperms

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/jackc/pgx/v4"
	"github.com/samber/lo"
)

// TODO: A config setting to manage all users (and thus not need to tombstone them) would be nice.

type RoleAttributes struct {
	Superuser       bool       `yaml:"superuser,omitempty"`
	CreateDB        bool       `yaml:"createdb,omitempty"`
	CreateRole      bool       `yaml:"createrole,omitempty"`
	Inherit         *bool      `yaml:"inherit,omitempty"`
	Login           *bool      `yaml:"login,omitempty"`
	Replication     bool       `yaml:"replication,omitempty"`
	BypassRLS       bool       `yaml:"bypassrls,omitempty"`
	ConnectionLimit *int       `yaml:"connectionlimit,omitempty"`
	Password        *string    `yaml:"password,omitempty"`
	ValidUntil      *time.Time `yaml:"validuntil,omitempty"`
	MemberOf        []string   `yaml:"member_of,omitempty"`
}

func (r RoleAttributes) GetInherit() bool {
	return r.Inherit == nil || *r.Inherit
}

func (r RoleAttributes) GetLogin() bool {
	return r.Login == nil || *r.Login
}

func (r RoleAttributes) GetConnectionLimit() int {
	if r.ConnectionLimit == nil {
		return -1
	}
	return *r.ConnectionLimit
}

func (r RoleAttributes) GetValidUntil() time.Time {
	if r.ValidUntil == nil {
		return time.Time{}
	}
	return *r.ValidUntil
}

func (r RoleAttributes) CreateSQL(username string) string {
	q := "CREATE ROLE " + username
	if r.Superuser {
		q += " SUPERUSER"
	}
	if r.CreateDB {
		q += " CREATEDB"
	}
	if r.CreateRole {
		q += " CREATEROLE"
	}
	if !r.GetInherit() {
		q += " NOINHERIT"
	}
	if r.GetLogin() {
		q += " LOGIN"
	}
	if r.Replication {
		q += " REPLICATION"
	}
	if r.BypassRLS {
		q += " BYPASSRLS"
	}
	if r.ConnectionLimit != nil {
		q += fmt.Sprintf(" CONNECTION LIMIT %d", *r.ConnectionLimit)
	}
	if r.Password != nil && *r.Password != "" {
		q += " PASSWORD " + Escape(*r.Password)
	}
	if r.ValidUntil != nil {
		q += " VALID UNTIL " + Escape(r.ValidUntil.Format("2006-01-02T15:04:05Z"))
	}
	return q
}

func FetchRoles(ctx context.Context, conn *pgx.Conn) (map[string]RoleAttributes, error) {
	rows, err := conn.Query(ctx, "SELECT rolname, rolpassword, rolsuper, rolinherit, rolcreaterole, rolcreatedb, rolcanlogin, rolreplication, rolbypassrls, rolconnlimit, rolvaliduntil FROM pg_catalog.pg_authid WHERE rolname NOT LIKE 'pg_%'")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ret := map[string]RoleAttributes{}
	for rows.Next() {
		var rolpassword sql.NullString
		var rolname string
		var attr RoleAttributes
		if err := rows.Scan(&rolname, &rolpassword, &attr.Superuser, &attr.Inherit, &attr.CreateRole, &attr.CreateDB, &attr.Login, &attr.Replication, &attr.BypassRLS, &attr.ConnectionLimit, &attr.ValidUntil); err != nil {
			return nil, err
		}
		if rolpassword.Valid {
			attr.Password = lo.ToPtr(rolpassword.String)
		} else {
			attr.Password = new(string)
		}
		if attr.Login != nil && *attr.Login {
			attr.Login = nil
		}
		if attr.Inherit != nil && *attr.Inherit {
			attr.Inherit = nil
		}
		if attr.ConnectionLimit != nil && *attr.ConnectionLimit == -1 {
			attr.ConnectionLimit = nil
		}
		ret[rolname] = attr
	}
	rows.Close()
	rows, err = conn.Query(ctx, "SELECT pg_get_userbyid(roleid), pg_get_userbyid(member) FROM pg_catalog.pg_auth_members")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var p, c string
		if err := rows.Scan(&p, &c); err != nil {
			return nil, err
		}
		if a, ok := ret[c]; ok {
			a.MemberOf = append(a.MemberOf, p)
			ret[c] = a
		}
	}
	return ret, nil
}

func alterRole(ss SyncSink, username string, o, n RoleAttributes) {
	q := ""
	if n.Password != nil {
		if *n.Password == "" {
			if *o.Password != "" {
				q += " PASSWORD NULL"
			}
		} else {
			if !verifyPassword(*o.Password, username, *n.Password) {
				q += " PASSWORD " + Escape(*n.Password)
			}
		}
	}
	if o.GetConnectionLimit() != n.GetConnectionLimit() {
		q += fmt.Sprintf(" CONNECTION LIMIT %d", n.GetConnectionLimit())
	}
	if !o.GetValidUntil().Equal(n.GetValidUntil()) {
		if n.GetValidUntil().IsZero() {
			q += " VALID UNTIL 'infinity'"
		} else {
			q += " VALID UNTIL " + Escape(n.GetValidUntil().Format("2006-01-02T15:04:05Z"))
		}
	}
	type actualDesiredPriv struct {
		name    string
		actual  bool
		desired bool
	}
	adps := []actualDesiredPriv{
		{"SUPERUSER", o.Superuser, n.Superuser},
		{"INHERIT", o.GetInherit(), n.GetInherit()},
		{"CREATEROLE", o.CreateRole, n.CreateRole},
		{"CREATEDB", o.CreateDB, n.CreateDB},
		{"LOGIN", o.GetLogin(), n.GetLogin()},
		{"REPLICATION", o.Replication, n.Replication},
		{"BYPASSRLS", o.BypassRLS, n.BypassRLS},
	}
	for _, adp := range adps {
		if adp.actual == adp.desired {
			continue
		}
		if adp.desired {
			q += " " + adp.name
		} else {
			q += " NO" + adp.name
		}
	}
	if q != "" {
		ss.Query("", "ALTER ROLE "+username+q)
	}
}

func SyncRoles(ss SyncSink, oldRoles, newRoles map[string]RoleAttributes, tombstoned []string) {
	for _, t := range tombstoned {
		if _, found := oldRoles[t]; found {
			ss.Query("", "DROP ROLE "+t)
		}
	}
	for username, n := range newRoles {
		if o, found := oldRoles[username]; found {
			alterRole(ss, username, o, n)
		} else {
			ss.Query("", n.CreateSQL(username))
		}
	}
	ss.AddBarrier()
	for username, n := range newRoles {
		o := oldRoles[username]
		toRemove, toAdd := lo.Difference(o.MemberOf, n.MemberOf)
		for _, parent := range toAdd {
			ss.Query("", "GRANT "+parent+" TO "+username)
		}
		for _, parent := range toRemove {
			if lo.Contains(tombstoned, parent) {
				continue
			}
			ss.Query("", "REVOKE "+parent+" FROM "+username)
		}
	}
}
