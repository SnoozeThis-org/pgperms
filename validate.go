package pgperms

import (
	"fmt"
	"strings"

	"github.com/samber/lo"
	"gogen.quis.cx/stringlib"
)

// TODO: Do we want to raise warnings for likely incorrect configurations? (RoleAttributes.Replication without RoleAttributes.Login etc)

type validator struct {
	tombstonedRoles     []string
	definedRoles        []string
	tombstonedDatabases []string
	definedDatabases    []string
	tombstonedSchemas   []string
	definedSchemas      []string

	errors []string
}

func ValidateConfig(c *Config) error {
	v := validator{
		tombstonedRoles:     c.TombstonedRoles,
		definedRoles:        lo.Keys(c.Roles),
		tombstonedDatabases: c.TombstonedDatabases,
		definedDatabases:    c.Databases,
		tombstonedSchemas:   c.TombstonedSchemas,
		definedSchemas:      c.Schemas,
	}
	for name, r := range c.Roles {
		if lo.Contains(v.tombstonedRoles, name) {
			v.addErrorf("Role %s is both tombstoned and defined", name)
		}
		v.validateRole(name, r)
	}
	v.validateDatabases(c.Databases)
	v.validateSchemas(c.Schemas)
	v.validatePrivileges("databases", c.DatabasePrivileges)
	v.validatePrivileges("schemas", c.SchemaPrivileges)
	v.validatePrivileges("tables", c.TablePrivileges)
	v.validatePrivileges("sequences", c.SequencePrivileges)

	switch len(v.errors) {
	case 0:
		return nil
	case 1:
		return fmt.Errorf("Config is invalid: %s", v.errors[0])
	default:
		return fmt.Errorf("Config is invalid:\n* %s", strings.Join(v.errors, "\n* "))
	}
}

func (v *validator) addError(msg string) {
	v.errors = append(v.errors, msg)
}

func (v *validator) addErrorf(f string, args ...interface{}) {
	v.errors = append(v.errors, fmt.Sprintf(f, args...))
}

func (v *validator) checkRole(source, name string) {
	if lo.Contains(v.tombstonedRoles, name) {
		v.addErrorf("%s: Role %s is tombstoned and shouldn't be used", source, name)
	}
}

func (v *validator) validateRole(name string, r RoleAttributes) {
}

func (v *validator) validateDatabases(names []string) {
	for _, n := range names {
		if !safeCharactersRe.MatchString(n) {
			v.addErrorf("Database %q would need its name escaped, which isn't properly supported by this tool yet", n)
		}
		if lo.Contains(v.tombstonedDatabases, n) {
			v.addErrorf("Database %s is both tombstoned and defined", n)
		}
	}
	if dupes := lo.FindDuplicates(names); len(dupes) > 0 {
		for _, d := range dupes {
			v.addErrorf("Database %s is defined multiple times", d)
		}
	}
}

func (v *validator) validateSchemas(names []string) {
	// TODO: Implement
}

func (v *validator) validatePrivileges(what string, privs []GenericPrivilege) {
	for i, p := range privs {
		src := fmt.Sprintf("%s_privileges[%d]", strings.TrimSuffix(what, "s"), i+1)
		t := p.targets()
		if len(t) == 0 {
			v.addErrorf("%s: privilege is missing %s field", src, what)
		} else if len(t) > 1 {
			v.addErrorf("%s: privilege has invalid fields: %v", src, stringlib.Diff(t, []string{what}))
		}
		if what != t[0] {
			v.addErrorf("%s: privilege has wrong target field (want %q, got %q)", src, what, t[0])
		}
		if unknown := stringlib.Diff(p.Privileges, validPrivileges[what]); len(unknown) > 0 {
			v.addErrorf("%s: privilege has invalid privileges %v for %s_privileges", src, unknown, what[:len(what)-1])
		}
		for _, tgt := range p.untypedTargets() {
			db, remaining := splitObjectName(tgt)
			if db != "" && !lo.Contains(v.definedDatabases, db) {
				v.addErrorf("%s: privilege specified for unmanaged database %q", src, db)
			}
			schema, remaining := splitObjectName(remaining)
			if schema == "" {
				schema = remaining
			}
			fullSchema := joinSchemaName(db, schema)
			if schema != "" && !lo.Contains(v.definedSchemas, fullSchema) {
				v.addErrorf("%s: privilege specified for unmanaged schema %q", src, fullSchema)
			}
		}
		for _, r := range p.Roles {
			v.checkRole(src, r)
		}
	}
}
