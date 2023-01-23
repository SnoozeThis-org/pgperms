package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/SnoozeThis-org/pgperms"
	"github.com/jackc/pgx/v4"
	"github.com/spf13/pflag"
)

var (
	dump = pflag.Bool("dump", false, "Whether to dump the current permissions")
	showVersion = pflag.Bool("version", false, "Dump the version and exit")

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
	conn, err := pgx.Connect(ctx, os.Getenv("DSN"))
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
	desired, err := ioutil.ReadFile(pflag.Arg(0))
	if err != nil {
		log.Fatalf("Failed to read from config file %q: %v", pflag.Arg(0), err)
	}
	rec := pgperms.NewRecorder()
	if err := pgperms.Sync(ctx, pgperms.NewConnections(ctx, conn), desired, rec); err != nil {
		log.Fatalf("Failed to calculate queries needed to sync: %v", err)
	}
	for _, q := range rec.Get() {
		fmt.Println(q)
	}
}
