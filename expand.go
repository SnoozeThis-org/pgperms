package pgperms

import (
	"context"
	"strings"

	"github.com/Jille/dfr"
	"github.com/samber/lo"
)

func expandTables(ctx context.Context, conns *Connections, privs []GenericPrivilege, existingDatabases []string) ([]GenericPrivilege, error) {
	return expandTablesOrSequences(ctx, conns, privs, existingDatabases, false)
}

func expandSequences(ctx context.Context, conns *Connections, privs []GenericPrivilege, existingDatabases []string) ([]GenericPrivilege, error) {
	return expandTablesOrSequences(ctx, conns, privs, existingDatabases, true)
}

// expandTablesOrSequences resolves all permissions for .* to an actual list of tables.
func expandTablesOrSequences(ctx context.Context, conns *Connections, privs []GenericPrivilege, existingDatabases []string, sequences bool) ([]GenericPrivilege, error) {
	var d dfr.D
	defer d.Run(nil)
	interestingSchemas := map[string]map[string]struct{}{}
	for _, p := range privs {
		for _, t := range p.untypedTargets() {
			if !strings.HasSuffix(t, ".*") {
				continue
			}
			dbname, tgt := splitObjectName(t)
			if interestingSchemas[dbname] == nil {
				interestingSchemas[dbname] = map[string]struct{}{}
			}
			interestingSchemas[dbname][strings.TrimSuffix(tgt, ".*")] = struct{}{}
		}
	}
	types := []string{"S"}
	if !sequences {
		types = []string{"r", "v", "m", "f"}
	}
	names := map[string]map[string][]string{}
	for dbname, schemas := range interestingSchemas {
		if !lo.Contains(existingDatabases, dbname) {
			continue
		}
		conn, deref, err := conns.Get(dbname)
		if err != nil {
			return nil, err
		}
		derefNow := d.Add(deref)
		names[dbname] = map[string][]string{}
		rows, err := conn.Query(ctx, "SELECT nspname, relname FROM pg_catalog.pg_class, pg_catalog.pg_namespace WHERE pg_class.relnamespace = pg_namespace.oid AND nspname = ANY($1) AND relkind = ANY($2)", lo.Keys(schemas), types)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		for rows.Next() {
			var schema, name string
			if err := rows.Scan(&schema, &name); err != nil {
				return nil, err
			}
			names[dbname][schema] = append(names[dbname][schema], joinTableName(dbname, schema, name))
		}
		derefNow(true)
	}
	for i, p := range privs {
		var newTargets []string
		for _, t := range p.untypedTargets() {
			if !strings.HasSuffix(t, ".*") {
				newTargets = append(newTargets, t)
				continue
			}
			dbname, tgt := splitObjectName(t)
			schema := strings.TrimSuffix(tgt, ".*")
			newTargets = append(newTargets, names[dbname][schema]...)
		}
		if sequences {
			p.Sequences = newTargets
		} else {
			p.Tables = newTargets
		}
		privs[i] = p
	}
	return privs, nil
}
