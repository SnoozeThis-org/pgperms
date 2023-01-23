package pgperms

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v4"
)

// Connections is a set of connections to the same cluster, but connected to different databases.
type Connections struct {
	ctx         context.Context
	primary     *pgx.Conn
	perDatabase map[string]*pgx.Conn
	refcounts   map[string]int
}

// NewConnections creates a new set of connections, starting with given connection as the primary connection.
// Other connections will be made based on its config.
func NewConnections(ctx context.Context, primary *pgx.Conn) *Connections {
	c := primary.Config()
	return &Connections{
		ctx:     ctx,
		primary: primary,
		perDatabase: map[string]*pgx.Conn{
			c.Database: primary,
		},
		refcounts: map[string]int{},
	}
}

// Get (or create) a connection to a specific database.
// You need to call the returned function when done with the connection.
func (c *Connections) Get(database string) (*pgx.Conn, func(), error) {
	if database == "" {
		return c.primary, func() {}, nil
	}
	deref := func() {
		c.refcounts[database]--
		if c.refcounts[database] == 0 && (database == "template0" || database == "template1") {
			// We want to drop connections to the template databases as soon as possible, because it blocks new databases from being created based on them.
			c.DropCachedConnection(database)
		}
	}
	if conn, ok := c.perDatabase[database]; ok {
		c.refcounts[database]++
		return conn, deref, nil
	}
	cc := c.primary.Config()
	cc.Database = database
	dbconn, err := pgx.ConnectConfig(c.ctx, cc)
	if err != nil {
		return nil, nil, err
	}
	c.perDatabase[database] = dbconn
	c.refcounts[database]++
	return dbconn, deref, nil
}

// DropCachedConnection disconnects from the given database name if needed.
func (c *Connections) DropCachedConnection(database string) {
	conn, ok := c.perDatabase[database]
	if !ok {
		return
	}
	if c.refcounts[database] > 0 {
		panic(fmt.Errorf("Connection to database %q is still in use", database))
	}
	_ = conn.Close(c.ctx)
	delete(c.perDatabase, database)
	delete(c.refcounts, database)
}

// Close all connections except for the primary.
func (c *Connections) Close() {
	for name, conn := range c.perDatabase {
		if c.primary == conn {
			continue
		}
		c.DropCachedConnection(name)
	}
}
