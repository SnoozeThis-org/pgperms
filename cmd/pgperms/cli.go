package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/SnoozeThis-org/pgperms"
	"github.com/creachadair/getpass"
	"github.com/jackc/pgx/v4"
	"github.com/spf13/pflag"
)

var (
	defaultConfig, _ = pgx.ParseConfig("")

	config      = pflag.StringP("config", "c", "pgperms.yaml", "Path to the pgperms yaml config file")
	dump        = pflag.Bool("dump", false, "Whether to dump the current permissions")
	apply       = pflag.Bool("apply", false, "Whether to actually apply the needed queries")
	showVersion = pflag.Bool("version", false, "Dump the version and exit")
	host        = pflag.StringP("host", "h", defaultConfig.Host, "database server host or socket directory")
	port        = pflag.IntP("port", "P", int(defaultConfig.Port), "database server port")
	username    = pflag.StringP("username", "U", defaultConfig.User, "database user name")
	askPassword = pflag.BoolP("password", "W", false, "prompt for password")
	database    = pflag.StringP("database", "d", "postgres", "database name for initial connection")

	// Injected by releaser
	version string
)

func main() {
	pflag.Parse()
	if *showVersion {
		if version != "" {
			fmt.Fprintf(os.Stderr, "pgperms version %s\n", version)
		} else {
			fmt.Fprintf(os.Stderr, "pgperms built without versioning information\n")
		}
		return
	}
	ctx := context.Background()
	dsn := fmt.Sprintf("host=%s port=%d user=%s dbname=%s", escapeDSNString(*host), *port, escapeDSNString(*username), escapeDSNString(*database))
	if *askPassword {
		pass, err := getpass.Prompt("Password: ")
		if err != nil {
			log.Fatalf("Failed to read password from prompt: %v", err)
		}
		dsn += " password=" + escapeDSNString(pass)
	}
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	if *dump {
		ret, err := pgperms.Dump(ctx, pgperms.NewConnections(ctx, conn))
		if err != nil {
			log.Fatalf("Failed to dump privileges to a config file: %v", err)
		}
		fmt.Println(ret)
		return
	}
	if *config == "" {
		log.Fatalf("Unless --dump is specified, --config must be set")
	}
	desired, err := ioutil.ReadFile(*config)
	if err != nil {
		log.Fatalf("Failed to read from config file %q: %v", *config, err)
	}
	conns := pgperms.NewConnections(ctx, conn)
	rec := pgperms.NewRecorder()
	if err := pgperms.Sync(ctx, conns, desired, rec); err != nil {
		log.Fatalf("Failed to calculate queries needed to sync: %v", err)
	}
	if !*apply {
		qs := rec.Get()
		if len(qs) == 0 {
			return // Exit 0
		}
		for _, q := range qs {
			fmt.Println(q.String())
		}
		os.Exit(9)
	}
	for _, q := range rec.Get() {
		db, _, err := conns.Get(q.Database)
		if err != nil {
			log.Fatalf("Failed to connect to database %q: %v", q.Database, err)
		}
		if _, err := db.Exec(ctx, q.Query); err != nil {
			log.Fatalf("Query %q on database %q failed: %v", q.Query, q.Database, err)
		}
	}
	conns.Close()
}

func escapeDSNString(s string) string {
	return "'" + strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `'`, `\'`) + "'"
}
