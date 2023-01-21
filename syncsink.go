package pgperms

import (
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

// TODO: Separate streams for databases

func NewRecorder() *Recorder {
	return &Recorder{}
}

type Recorder struct {
	queries []string
	barrier int
}

var _ SyncSink = &Recorder{}

func (r *Recorder) Query(database, query string) {
	r.queries = append(r.queries, fmt.Sprintf("/* %24s */ %s", database, query))
}

func (r *Recorder) AddBarrier() {
	sort.Strings(r.queries[r.barrier:])
	r.barrier = len(r.queries)
}

func (r *Recorder) Get() []string {
	sort.Strings(r.queries[r.barrier:])
	return r.queries
}
