package pgperms_test

import (
	"context"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/SnoozeThis-org/pgperms"
	"github.com/google/go-cmp/cmp"
	"github.com/jackc/pgx/v4"
	"gopkg.in/yaml.v3"
)

type TestCase struct {
	Preparation []string        `yaml:"preparation"`
	Config      *pgperms.Config `yaml:"config"`
	Expected    []string        `yaml:"expected"`
	NoSecondRun bool            `yaml:"no_second_run"`
}

func TestEndToEnd(t *testing.T) {
	dsn := os.Getenv("TESTING_DSN")
	if dsn == "" {
		t.Fatal("TESTING_DSN is not set")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("Failed to connect to PostgreSQL at %q: %v", dsn, err)
	}
	tests, err := filepath.Glob("testdata/*.yaml")
	if err != nil {
		t.Fatalf("Failed to glob tests: %v", err)
	}
	if len(tests) == 0 {
		t.Fatal("No tests matched testdata/*.yaml")
	}
	for _, fn := range tests {
		t.Run(filepath.Base(fn), func(t *testing.T) {
			b, err := ioutil.ReadFile(fn)
			if err != nil {
				t.Fatalf("Failed to read test case: %v", err)
			}
			var tc TestCase
			if err := yaml.Unmarshal(b, &tc); err != nil {
				t.Fatalf("Failed to parse test case: %v", err)
			}

			// 0. Check database emptiness
			checkClusterIsEmpty(ctx, t, conn)
			t.Cleanup(func() {
				purgeCluster(ctx, t, conn)
			})

			// 1. Preparation queries
			for _, q := range tc.Preparation {
				if _, err := conn.Exec(ctx, q); err != nil {
					t.Fatalf("Preparation query %q failed: %v", q, err)
				}
			}

			// 2. Run pgperms (and compare output)
			encoded, err := yaml.Marshal(tc.Config)
			if err != nil {
				t.Fatalf("Failed to reencode the config: %v", err)
			}
			conns := pgperms.NewConnections(ctx, conn)
			t.Cleanup(conns.Close)
			rec := pgperms.NewRecorder()
			if err := pgperms.Sync(ctx, conns, encoded, rec); err != nil {
				t.Fatalf("pgperms.Sync() failed: %v", err)
			}
			queries := rec.Get()
			if diff := cmp.Diff(tc.Expected, queries); diff != "" {
				t.Errorf("Got (+) different queries than expected (-): %s", diff)
			}

			// 3. Execute the pgperms queries
			for _, db := range tc.Config.TombstonedDatabases {
				// Disconnect so we can drop the database.
				conns.DropCachedConnection(db)
			}
			for _, q := range queries {
				if _, err := conn.Exec(ctx, q); err != nil {
					t.Fatalf("Returned query %q failed: %v", q, err)
				}
			}

			if tc.NoSecondRun {
				return
			}

			// 4. Run pgperms again to see if the diff is empty
			rec = pgperms.NewRecorder()
			if err := pgperms.Sync(ctx, conns, encoded, rec); err != nil {
				t.Fatalf("pgperms.Sync() failed the second time: %v", err)
			}
			for _, q := range rec.Get() {
				t.Errorf("A second sync yielded another query to be done: %s", q)
			}
		})
	}
}

func checkClusterIsEmpty(ctx context.Context, t *testing.T, conn *pgx.Conn) {
	checkNoResults(ctx, t, conn, "SELECT datname FROM pg_catalog.pg_database WHERE datname NOT IN ('postgres', 'template0', 'template1')", "Database is not empty: found catalog %s")
	checkNoResults(ctx, t, conn, "SELECT nspname FROM pg_catalog.pg_namespace WHERE nspname NOT IN ('public', 'pg_catalog', 'information_schema', 'pg_toast') AND nspname NOT LIKE 'pg_temp_%' AND nspname NOT LIKE 'pg_toast_temp_%'", "Database is not empty: found schema %s")
	checkNoResults(ctx, t, conn, "SELECT rolname FROM pg_catalog.pg_authid WHERE rolname NOT LIKE 'pg_%' AND rolname!='postgres'", "Database is not empty: found user %s")
	checkNoResults(ctx, t, conn, "SELECT relname FROM pg_catalog.pg_class WHERE relnamespace NOT IN (SELECT oid FROM pg_catalog.pg_namespace WHERE nspname IN ('pg_catalog', 'information_schema', 'pg_toast'))", "Database is not empty: found table %s")
	if t.Failed() {
		t.FailNow()
	}
}

func checkNoResults(ctx context.Context, t *testing.T, conn *pgx.Conn, query, errfmt string) {
	rows, err := conn.Query(ctx, query)
	if err != nil {
		t.Fatalf("Failed to check database emptiness: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("Failed to check database emptiness: %v", err)
		}
		t.Errorf(errfmt, name)
	}
}

func purgeCluster(ctx context.Context, t *testing.T, conn *pgx.Conn) {
	findAndDrop(ctx, t, conn, "SELECT relname FROM pg_catalog.pg_class WHERE relkind != 'S' AND relnamespace NOT IN (SELECT oid FROM pg_catalog.pg_namespace WHERE nspname IN ('pg_catalog', 'information_schema', 'pg_toast'))", "TABLE")
	findAndDrop(ctx, t, conn, "SELECT relname FROM pg_catalog.pg_class WHERE relkind = 'S' AND relnamespace NOT IN (SELECT oid FROM pg_catalog.pg_namespace WHERE nspname IN ('pg_catalog', 'information_schema', 'pg_toast'))", "SEQUENCE")
	findAndDrop(ctx, t, conn, "SELECT nspname FROM pg_catalog.pg_namespace WHERE nspname NOT IN ('public', 'pg_catalog', 'information_schema', 'pg_toast') AND nspname NOT LIKE 'pg_temp_%' AND nspname NOT LIKE 'pg_toast_temp_%'", "SCHEMA")
	findAndDrop(ctx, t, conn, "SELECT datname FROM pg_catalog.pg_database WHERE datname NOT IN ('postgres', 'template0', 'template1')", "DATABASE")
	findAndDrop(ctx, t, conn, "SELECT rolname FROM pg_catalog.pg_authid WHERE rolname NOT LIKE 'pg_%' AND rolname!='postgres'", "USER")
}

func findAndDrop(ctx context.Context, t *testing.T, conn *pgx.Conn, query, objectType string) {
	rows, err := conn.Query(ctx, query)
	if err != nil {
		t.Fatalf("Failed to purge database: %v", err)
	}
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("Failed to purge database: %v", err)
		}
		names = append(names, name)
	}
	rows.Close()
	for _, n := range names {
		if _, err := conn.Exec(ctx, "DROP "+objectType+" "+n); err != nil {
			t.Errorf("Failed to purge database: DROP %s %s: %v", objectType, n, err)
		}
	}
}
