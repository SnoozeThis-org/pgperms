package pgperms

// TODO: Better handling of superusers.
// TODO: Handle default privileges?

import (
	"context"
	"fmt"
	"strings"

	"github.com/iancoleman/strcase"
	"github.com/jackc/pgx/v4"
	"github.com/samber/lo"
	"golang.org/x/exp/slices"
)

var validPrivileges = map[string][]string{
	"databases":           []string{"CREATE", "TEMPORARY", "CONNECT"},
	"domains":             []string{"USAGE"},
	"routines":            []string{"EXECUTE"},
	"foreignDataWrappers": []string{"USAGE"},
	"foreignServers":      []string{"USAGE"},
	"languages":           []string{"USAGE"},
	"largeObjects":        []string{"SELECT", "UPDATE"},
	"schemas":             []string{"USAGE", "CREATE"},
	"sequences":           []string{"SELECT", "UPDATE", "USAGE"},
	"tables":              []string{"SELECT", "UPDATE", "INSERT", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"},
	"columns":             []string{"SELECT", "UPDATE", "INSERT", "DELETE"},
	"tablespaces":         []string{"CREATE"},
	"types":               []string{"USAGE"},
}
var allPrivs = []string{"SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER", "CREATE", "CONNECT", "TEMPORARY", "EXECUTE", "USAGE"}

var shortPrivs = map[string]string{
	"SELECT":     "r",
	"INSERT":     "a",
	"UPDATE":     "w",
	"DELETE":     "d",
	"TRUNCATE":   "D",
	"REFERENCES": "x",
	"TRIGGER":    "t",
	"CREATE":     "C",
	"CONNECT":    "c",
	"TEMPORARY":  "T",
	"EXECUTE":    "X",
	"USAGE":      "U",
}

// GenericPrivilege is a set of privileges for a set of roles on a set of targets.
type GenericPrivilege struct {
	Roles      []string `yaml:"roles,flow"`
	Privileges []string `yaml:"privileges,flow"`
	Grantable  bool     `yaml:"grantable,omitempty"`

	// One of:

	Tables              []string `yaml:"tables,omitempty"`
	Columns             []string `yaml:"columns,omitempty"`
	Sequences           []string `yaml:"sequences,omitempty"`
	Databases           []string `yaml:"databases,omitempty"`
	Domains             []string `yaml:"domains,omitempty"`
	ForeignDataWrappers []string `yaml:"foreign_data_wrappers,omitempty"`
	ForeignServers      []string `yaml:"foreign_servers,omitempty"`
	Routines            []string `yaml:"routines,omitempty"`
	Languages           []string `yaml:"languages,omitempty"`
	LargeObjects        []string `yaml:"large_objects,omitempty"`
	Schemas             []string `yaml:"schemas,omitempty"`
	Tablespaces         []string `yaml:"tablespaces,omitempty"`
	Types               []string `yaml:"types,omitempty"`
}

func (gp GenericPrivilege) targets() []string {
	var ret []string
	if len(gp.Tables) != 0 {
		ret = append(ret, "tables")
	}
	if len(gp.Columns) != 0 {
		ret = append(ret, "columns")
	}
	if len(gp.Sequences) != 0 {
		ret = append(ret, "sequences")
	}
	if len(gp.Databases) != 0 {
		ret = append(ret, "databases")
	}
	if len(gp.Domains) != 0 {
		ret = append(ret, "domains")
	}
	if len(gp.ForeignDataWrappers) != 0 {
		ret = append(ret, "foreignDataWrappers")
	}
	if len(gp.ForeignServers) != 0 {
		ret = append(ret, "foreignServers")
	}
	if len(gp.Routines) != 0 {
		ret = append(ret, "routines")
	}
	if len(gp.Languages) != 0 {
		ret = append(ret, "languages")
	}
	if len(gp.LargeObjects) != 0 {
		ret = append(ret, "largeObjects")
	}
	if len(gp.Schemas) != 0 {
		ret = append(ret, "schemas")
	}
	if len(gp.Tablespaces) != 0 {
		ret = append(ret, "tablespaces")
	}
	if len(gp.Types) != 0 {
		ret = append(ret, "types")
	}
	return ret
}

func (gp GenericPrivilege) untypedTargets() []string {
	for _, l := range [][]string{gp.Tables, gp.Columns, gp.Sequences, gp.Databases, gp.Domains, gp.ForeignDataWrappers, gp.ForeignServers, gp.Routines, gp.Languages, gp.LargeObjects, gp.Schemas, gp.Tablespaces, gp.Types} {
		if len(l) > 0 {
			return l
		}
	}
	return nil
}

func (gp GenericPrivilege) expandPrivileges() []string {
	if slices.Contains(gp.Privileges, "ALL PRIVILEGES") {
		return validPrivileges[gp.targets()[0]]
	}
	return gp.Privileges
}

func (gp *GenericPrivilege) set(what string, v []string) {
	switch what {
	case "tables":
		gp.Tables = v
	case "columns":
		gp.Columns = v
	case "sequences":
		gp.Sequences = v
	case "databases":
		gp.Databases = v
	case "domains":
		gp.Domains = v
	case "foreignDataWrappers":
		gp.ForeignDataWrappers = v
	case "foreignServers":
		gp.ForeignServers = v
	case "routines":
		gp.Routines = v
	case "languages":
		gp.Languages = v
	case "largeObjects":
		gp.LargeObjects = v
	case "schemas":
		gp.Schemas = v
	case "tablespaces":
		gp.Tablespaces = v
	case "types":
		gp.Types = v
	default:
		panic(fmt.Errorf("GenericPrivilege.set(): invalid what %q", what))
	}
}

func fetchTablePrivileges(ctx context.Context, conn *pgx.Conn, database string, interestingUsers []string) ([]GenericPrivilege, []GenericPrivilege, error) {
	rows, err := conn.Query(ctx, "SELECT pg_get_userbyid(grantee) AS grantee, nspname, relname, relkind, privilege_type, is_grantable FROM pg_catalog.pg_class, pg_namespace, aclexplode(relacl) WHERE pg_namespace.oid = relnamespace AND pg_get_userbyid(grantee) = ANY($1) AND nspname NOT IN ('pg_catalog', 'information_schema')", interestingUsers)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	grouped := map[string]map[string]map[bool]privilegeSet{}
	classTypes := map[string]byte{}
	for rows.Next() {
		var grantee, schema, table, privilege string
		var grantable bool
		var kind byte
		if err := rows.Scan(&grantee, &schema, &table, &kind, &privilege, &grantable); err != nil {
			return nil, nil, err
		}
		fqtn := joinTableName(database, schema, table)
		classTypes[fqtn] = kind
		if grouped[grantee][fqtn] == nil {
			if grouped[grantee] == nil {
				grouped[grantee] = map[string]map[bool]privilegeSet{}
			}
			grouped[grantee][fqtn] = map[bool]privilegeSet{}
		}
		ps := grouped[grantee][fqtn][grantable]
		ps.Add(privilege)
		grouped[grantee][fqtn][grantable] = ps
	}
	var tables, sequences []GenericPrivilege
	for grantee, tmp1 := range grouped {
		for fqtn, tmp2 := range tmp1 {
			for grantable, ps := range tmp2 {
				switch classTypes[fqtn] {
				case 'r', 'v', 'm', 'f':
					tables = append(tables, GenericPrivilege{
						Roles:      []string{grantee},
						Tables:     []string{fqtn},
						Privileges: ps.ListOrAll("tables"),
						Grantable:  grantable,
					})
				case 'S':
					sequences = append(sequences, GenericPrivilege{
						Roles:      []string{grantee},
						Sequences:  []string{fqtn},
						Privileges: ps.ListOrAll("sequences"),
						Grantable:  grantable,
					})
				}
			}
		}
	}
	return tables, sequences, nil
}

func fetchDatabasesPrivileges(ctx context.Context, conn *pgx.Conn, interestingUsers, interestingDatabases []string) ([]GenericPrivilege, error) {
	rows, err := conn.Query(ctx, "SELECT datname, pg_get_userbyid(grantee) AS grantee, privilege_type, is_grantable FROM pg_catalog.pg_database, aclexplode(datacl) WHERE datallowconn AND datname = ANY($1) AND pg_get_userbyid(grantee) = ANY($2)", interestingDatabases, interestingUsers)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	grouped := map[string]map[string]map[bool]privilegeSet{}
	for rows.Next() {
		var database, grantee, privilege string
		var grantable bool
		if err := rows.Scan(&database, &grantee, &privilege, &grantable); err != nil {
			return nil, err
		}
		if grouped[grantee][database] == nil {
			if grouped[grantee] == nil {
				grouped[grantee] = map[string]map[bool]privilegeSet{}
			}
			grouped[grantee][database] = map[bool]privilegeSet{}
		}
		ps := grouped[grantee][database][grantable]
		ps.Add(privilege)
		grouped[grantee][database][grantable] = ps
	}
	var privs []GenericPrivilege
	for grantee, tmp1 := range grouped {
		for database, tmp2 := range tmp1 {
			for grantable, ps := range tmp2 {
				privs = append(privs, GenericPrivilege{
					Roles:      []string{grantee},
					Databases:  []string{database},
					Privileges: ps.ListOrAll("databases"),
					Grantable:  grantable,
				})
			}
		}
	}
	return privs, nil
}

func fetchSchemasPrivileges(ctx context.Context, conn *pgx.Conn, database string, interestingUsers []string) ([]GenericPrivilege, error) {
	rows, err := conn.Query(ctx, "SELECT nspname, pg_get_userbyid(grantee) AS grantee, privilege_type, is_grantable FROM pg_catalog.pg_namespace, aclexplode(nspacl) WHERE nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast') AND pg_get_userbyid(grantee) = ANY($1)", interestingUsers)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	grouped := map[string]map[string]map[bool]privilegeSet{}
	for rows.Next() {
		var schema, grantee, privilege string
		var grantable bool
		if err := rows.Scan(&schema, &grantee, &privilege, &grantable); err != nil {
			return nil, err
		}
		fqsn := joinSchemaName(database, schema)
		if grouped[grantee][fqsn] == nil {
			if grouped[grantee] == nil {
				grouped[grantee] = map[string]map[bool]privilegeSet{}
			}
			grouped[grantee][fqsn] = map[bool]privilegeSet{}
		}
		ps := grouped[grantee][fqsn][grantable]
		ps.Add(privilege)
		grouped[grantee][fqsn][grantable] = ps
	}
	var privs []GenericPrivilege
	for grantee, tmp1 := range grouped {
		for fqsn, tmp2 := range tmp1 {
			for grantable, ps := range tmp2 {
				privs = append(privs, GenericPrivilege{
					Roles:      []string{grantee},
					Schemas:    []string{fqsn},
					Privileges: ps.ListOrAll("schemas"),
					Grantable:  grantable,
				})
			}
		}
	}
	return privs, nil
}

func fetchTypePrivileges(ctx context.Context, conn *pgx.Conn, database string, interestingUsers []string) ([]GenericPrivilege, error) {
	rows, err := conn.Query(ctx, "SELECT nspname, typname, pg_get_userbyid(grantee) AS grantee, privilege_type, is_grantable FROM pg_catalog.pg_type, pg_namespace, aclexplode(typacl) WHERE pg_namespace.oid = typnamespace AND nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast') AND pg_get_userbyid(grantee) = ANY($1)", interestingUsers)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	grouped := map[string]map[string]map[bool]privilegeSet{}
	for rows.Next() {
		var schema, typ, grantee, privilege string
		var grantable bool
		if err := rows.Scan(&schema, &typ, &grantee, &privilege, &grantable); err != nil {
			return nil, err
		}
		fqtn := joinTableName(database, schema, typ)
		if grouped[grantee][fqtn] == nil {
			if grouped[grantee] == nil {
				grouped[grantee] = map[string]map[bool]privilegeSet{}
			}
			grouped[grantee][fqtn] = map[bool]privilegeSet{}
		}
		ps := grouped[grantee][fqtn][grantable]
		ps.Add(privilege)
		grouped[grantee][fqtn][grantable] = ps
	}
	var privs []GenericPrivilege
	for grantee, tmp1 := range grouped {
		for fqtn, tmp2 := range tmp1 {
			for grantable, ps := range tmp2 {
				privs = append(privs, GenericPrivilege{
					Roles:      []string{grantee},
					Types:      []string{fqtn},
					Privileges: ps.ListOrAll("types"),
					Grantable:  grantable,
				})
			}
		}
	}
	return privs, nil
}

type privilegeSet int

func (ps *privilegeSet) Add(priv string) {
	i := lo.IndexOf(allPrivs, priv)
	if i == -1 {
		panic(fmt.Errorf("BUG: Unknown privilege %q", priv))
	}
	*ps = (*ps) | (1 << i)
}

func (ps privilegeSet) String() string {
	var ret string
	for i, p := range allPrivs {
		if ps&(1<<i) > 0 {
			ret += shortPrivs[p]
		}
	}
	return ret
}

func (ps privilegeSet) List() []string {
	var ret []string
	for i, p := range allPrivs {
		if ps&(1<<i) > 0 {
			ret = append(ret, p)
		}
	}
	return ret
}

func (ps privilegeSet) ListOrAll(objectType string) []string {
	l := ps.List()
	if len(l) > 1 && lo.Every(l, validPrivileges[objectType]) {
		return []string{"ALL PRIVILEGES"}
	}
	return l
}

// diffPrivileges returns one set of privileges that should be granted and one that should be granted WITH GRANT OPTION.
// It can also be called to calculate privileges to be revoked.
func diffPrivileges(oldPrivs, newPrivs []GenericPrivilege) ([]GenericPrivilege, []GenericPrivilege) {
	existing := map[string]map[string]map[string]bool{}
	for _, o := range oldPrivs {
		for _, target := range o.untypedTargets() {
			if existing[target] == nil {
				existing[target] = map[string]map[string]bool{}
			}
			for _, grantee := range o.Roles {
				if existing[target][grantee] == nil {
					existing[target][grantee] = map[string]bool{}
				}
				for _, priv := range o.expandPrivileges() {
					existing[target][grantee][priv] = o.Grantable
				}
			}
		}
	}
	var privs, grantPrivs []GenericPrivilege
	for _, n := range newPrivs {
		for _, target := range n.untypedTargets() {
			for _, grantee := range n.Roles {
				for _, priv := range n.expandPrivileges() {
					withGrant, found := existing[target][grantee][priv]
					if found && (withGrant || !n.Grantable) {
						continue
					}
					gp := GenericPrivilege{
						Privileges: []string{priv},
						Grantable:  n.Grantable,
						Roles:      []string{grantee},
					}
					gp.set(n.targets()[0], []string{target})
					if found {
						grantPrivs = append(grantPrivs, gp)
					} else {
						privs = append(privs, gp)
					}
				}
			}
		}
	}
	return privs, grantPrivs
}

// applyPrivileges tells the SyncSink which queries should be executed to grant/revoke the given privileges.
func applyPrivileges(ss SyncSink, database string, granting, justPrivs bool, diff []GenericPrivilege) {
	if len(diff) == 0 {
		return
	}
	t := strings.ReplaceAll(strcase.ToScreamingSnake(strings.TrimSuffix(diff[0].targets()[0], "s")), "_", " ")
	for _, n := range mergePrivileges(diff) {
		var targets []string
		for _, target := range n.untypedTargets() {
			db, tgt := splitObjectName(target)
			if db != database {
				continue
			}
			targets = append(targets, tgt)
		}
		if len(targets) == 0 {
			continue
		}
		if granting {
			q := "GRANT " + strings.Join(n.Privileges, ", ") + " ON " + t + " " + strings.Join(targets, ", ") + " TO " + strings.Join(n.Roles, ", ")
			if n.Grantable {
				q += " WITH GRANT OPTION"
			}
			ss.Query(database, q)
		} else {
			q := "REVOKE "
			if justPrivs {
				q += "GRANT OPTION FOR "
			}
			q += strings.Join(n.Privileges, ", ") + " ON " + t + " " + strings.Join(targets, ", ") + " FROM " + strings.Join(n.Roles, ", ")
			ss.Query(database, q)
		}
	}
}

// SyncPrivileges tells the SyncSink which queries to execute to get towards the desired privileges.
func SyncPrivileges(ss SyncSink, databases []string, actual, desired []GenericPrivilege) {
	grant, grantPrivs := diffPrivileges(actual, desired)
	grant = append(grant, grantPrivs...)
	revoke, revokePrivs := diffPrivileges(desired, actual)
	for _, db := range databases {
		// 1. Grant new privileges (possibly WITH GRANT OPTION)
		applyPrivileges(ss, db, true, false, grant)
		// 2. Revoke privileges
		applyPrivileges(ss, db, false, false, revoke)
		// 3. Revoke GRANT OPTION FOR privileges
		applyPrivileges(ss, db, false, true, revokePrivs)
	}
}
