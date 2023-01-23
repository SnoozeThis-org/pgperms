package pgperms

import (
	"context"
	"fmt"
	"sort"
)

// SyncSink will be called for every query that should be executed to get to the desired state.
type SyncSink interface {
	// Query is called when a query should be executed (in the given database) to get to the desired state.
	// Query can also be called with database "", indicating it can be run on any database.
	Query(database, query string)

	// AddBarrier is called between queries to indicate they can't be reordered across the barrier.
	// Implementations can safely ignore calls to AddBarrier, unless stable output is required (like the tests).
	AddBarrier()
}

func NewRecorder() *Recorder {
	return &Recorder{}
}

// Recorder is a SyncSink that simply records all the queries.
type Recorder struct {
	queries []QueryForDatabase
	barrier int
}

type QueryForDatabase struct {
	Database string
	Query    string
}

func (q QueryForDatabase) String() string {
	return fmt.Sprintf("/* %24s */ %s", q.Database, q.Query)
}

var _ SyncSink = &Recorder{}

// Query records that a query should happen.
func (r *Recorder) Query(database, query string) {
	r.queries = append(r.queries, QueryForDatabase{database, query})
}

func (r *Recorder) AddBarrier() {
	s := r.queries[r.barrier:]
	sort.Slice(s, func(i, j int) bool {
		return s[i].Query < s[j].Query
	})
	r.barrier = len(r.queries)
}

// Get returns all queries recorded by this Recorder.
func (r *Recorder) Get() []QueryForDatabase {
	r.AddBarrier()
	return r.queries
}

func (r *Recorder) Apply(ctx context.Context, conns *Connections) error {
	for _, q := range r.Get() {
		db, deref, err := conns.Get(q.Database)
		if err != nil {
			return fmt.Errorf("failed to connect to database %q: %v", q.Database, err)
		}
		// We'll defer dereferencing until we're done with all queries. Otherwise we might reconnect repeatedly.
		defer deref()
		if _, err := db.Exec(ctx, q.Query); err != nil {
			return fmt.Errorf("query %q on database %q failed: %v", q.Query, q.Database, err)
		}
	}
	return nil
}
