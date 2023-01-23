package pgperms

import (
	"bytes"
	"context"

	"github.com/Jille/dfr"
	"github.com/samber/lo"
	"gopkg.in/yaml.v3"
)

// Dump all permissions from a running cluster and return a config yaml.
func Dump(ctx context.Context, conns *Connections) (string, error) {
	c, err := Gather(ctx, conns, nil, nil)
	if err != nil {
		return "", err
	}
	c.TablePrivileges = mergePrivileges(c.TablePrivileges)
	c.SequencePrivileges = mergePrivileges(c.SequencePrivileges)
	c.DatabasePrivileges = mergePrivileges(c.DatabasePrivileges)
	c.SchemaPrivileges = mergePrivileges(c.SchemaPrivileges)
	b, err := yaml.Marshal(c)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// Gather all permissions from a running cluster.
func Gather(ctx context.Context, conns *Connections, interestingRoles, interestingDatabases []string) (*Config, error) {
	var d dfr.D
	defer d.Run(nil)
	var ret Config
	roles, err := FetchRoles(ctx, conns.primary)
	if err != nil {
		return nil, err
	}
	ret.Roles = roles
	if len(interestingRoles) == 0 {
		interestingRoles = lo.Keys(roles)
	}
	ret.Databases, err = fetchDatabases(ctx, conns.primary)
	if err != nil {
		return nil, err
	}
	if len(interestingDatabases) == 0 {
		interestingDatabases = ret.Databases
	}
	ret.DatabasePrivileges, err = fetchDatabasesPrivileges(ctx, conns.primary, interestingRoles, interestingDatabases)
	if err != nil {
		return nil, err
	}
	for _, dbname := range lo.Intersect(interestingDatabases, ret.Databases) {
		dbconn, deref, err := conns.Get(dbname)
		if err != nil {
			return nil, err
		}
		derefNow := d.Add(deref)

		schemas, err := fetchSchemas(ctx, dbconn, dbname)
		if err != nil {
			return nil, err
		}
		ret.Schemas = append(ret.Schemas, schemas...)
		schPrivs, err := fetchSchemasPrivileges(ctx, dbconn, dbname, interestingRoles)
		if err != nil {
			return nil, err
		}
		ret.SchemaPrivileges = append(ret.SchemaPrivileges, schPrivs...)

		tblPrivs, seqPrivs, err := fetchTablePrivileges(ctx, dbconn, dbname, interestingRoles)
		if err != nil {
			return nil, err
		}
		ret.TablePrivileges = append(ret.TablePrivileges, tblPrivs...)
		ret.SequencePrivileges = append(ret.SequencePrivileges, seqPrivs...)

		derefNow(true)
	}
	return &ret, nil
}

// Sync the desired configuration to a running cluster.
// Queries to be executed are sent to the SyncSink, not executed on the given connections.
func Sync(ctx context.Context, conns *Connections, desired []byte, ss SyncSink) error {
	dec := yaml.NewDecoder(bytes.NewReader(desired))
	dec.KnownFields(true)
	var d Config
	if err := dec.Decode(&d); err != nil {
		return err
	}
	if err := ValidateConfig(&d); err != nil {
		return err
	}
	actual, err := Gather(ctx, conns, lo.Keys(d.Roles), d.Databases)
	if err != nil {
		return err
	}
	d.TablePrivileges, err = expandTables(ctx, conns, d.TablePrivileges, actual.Databases)
	if err != nil {
		return err
	}
	d.SequencePrivileges, err = expandSequences(ctx, conns, d.SequencePrivileges, actual.Databases)
	if err != nil {
		return err
	}

	SyncDatabases(ss, d.Databases, d.TombstonedDatabases, actual.Databases)
	ss.AddBarrier()
	SyncRoles(ss, actual.Roles, d.Roles, d.TombstonedRoles)
	ss.AddBarrier()
	SyncPrivileges(ss, []string{""}, actual.DatabasePrivileges, d.DatabasePrivileges)
	ss.AddBarrier()
	SyncSchemas(ss, d.Schemas, d.TombstonedSchemas, actual.Schemas)
	ss.AddBarrier()
	SyncPrivileges(ss, d.Databases, actual.SchemaPrivileges, d.SchemaPrivileges)
	ss.AddBarrier()
	SyncPrivileges(ss, d.Databases, actual.TablePrivileges, d.TablePrivileges)
	ss.AddBarrier()
	SyncPrivileges(ss, d.Databases, actual.SequencePrivileges, d.SequencePrivileges)
	return nil
}
