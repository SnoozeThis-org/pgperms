package pgperms

import (
	"context"

	"github.com/jackc/pgx/v4"
)

func fetchDatabases(ctx context.Context, conn *pgx.Conn) ([]string, error) {
	rows, err := conn.Query(ctx, "SELECT datname FROM pg_catalog.pg_database WHERE datallowconn")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var database string
		if err := rows.Scan(&database); err != nil {
			return nil, err
		}
		names = append(names, database)
	}
	return names, nil
}

func fetchSchemas(ctx context.Context, conn *pgx.Conn, database string) ([]string, error) {
	rows, err := conn.Query(ctx, "SELECT nspname FROM pg_catalog.pg_namespace WHERE nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast') AND nspname NOT LIKE 'pg_temp_%' AND nspname NOT LIKE 'pg_toast_temp_%'")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var schema string
		if err := rows.Scan(&schema); err != nil {
			return nil, err
		}
		names = append(names, joinSchemaName(database, schema))
	}
	return names, nil
}

func joinSchemaName(database, schema string) string {
	return database + "." + safeIdentifier(schema)
}

func SyncDatabases(ss SyncSink, wanted, tombstoned, actual []string) {
	a := map[string]struct{}{}
	for _, d := range actual {
		a[d] = struct{}{}
	}
	for _, d := range wanted {
		if _, exists := a[d]; exists {
			continue
		}
		ss.Query("", "CREATE DATABASE "+safeIdentifier(d))
	}
	for _, d := range tombstoned {
		if _, exists := a[d]; !exists {
			continue
		}
		ss.Query("", "DROP DATABASE "+safeIdentifier(d))
	}
}

func SyncSchemas(ss SyncSink, wanted, tombstoned, actual []string) {
	a := map[string]struct{}{}
	for _, s := range actual {
		a[s] = struct{}{}
	}
	for _, s := range wanted {
		if _, exists := a[s]; exists {
			continue
		}
		db, schema := splitObjectName(s)
		ss.Query(db, "CREATE SCHEMA "+safeIdentifier(schema))
	}
	for _, s := range tombstoned {
		if _, exists := a[s]; !exists {
			continue
		}
		db, schema := splitObjectName(s)
		ss.Query(db, "DROP SCHEMA "+safeIdentifier(schema))
	}
}
