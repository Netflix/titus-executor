package logging

import (
	"context"
	"sync"

	log "github.com/sirupsen/logrus"
)

type concurrentFields struct {
	sync.Mutex
	fields log.Fields
}

type contextKey string

const (
	cfKey contextKey = "cf"
)

// WithConcurrentFields returns an initialized fields entry in the context given.
func WithConcurrentFields(parentCtx context.Context) context.Context {
	c := &concurrentFields{
		fields: make(map[string]interface{}),
	}

	return context.WithValue(parentCtx, cfKey, c)
}

// AddField adds a field in-place
func AddField(ctx context.Context, key string, value interface{}) {
	cf, ok := ctx.Value(cfKey).(*concurrentFields)
	if !ok {
		panic("context has no associated CF")
	}
	defer cf.Unlock()
	cf.Lock()
	cf.fields[key] = value
}

// AddFields adds a field in-place
func AddFields(ctx context.Context, fields log.Fields) {
	cf, ok := ctx.Value(cfKey).(*concurrentFields)
	if !ok {
		return
	}
	defer cf.Unlock()
	cf.Lock()
	for key, value := range fields {
		cf.fields[key] = value
	}
}

// Entry finalizes the fields that have been set
func Entry(ctx context.Context) log.Fields {
	cf, ok := ctx.Value(cfKey).(*concurrentFields)
	if !ok {
		panic("context has no associated CF")
	}
	defer cf.Unlock()
	cf.Lock()
	return cf.fields
}
