package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/pkg/errors"

	"github.com/sirupsen/logrus"
)

var (
	_ error = (*PreResolveError)(nil)
	_ error = (*PostResolveError)(nil)
)

type ResolverError interface {
	Cause() error
}

// PreResolveError represents an error from the underlying resolver
type PreResolveError struct {
	underlyingError error
	reason          string
}

func (pre PreResolveError) Cause() error {
	return pre.underlyingError
}

func (pre PreResolveError) Error() string {
	if pre.reason == "" {
		return fmt.Sprintf("Pre-resolve error: %s", pre.underlyingError.Error())
	}
	return fmt.Sprintf("Pre-resolve error (%s): %s", pre.reason, pre.underlyingError.Error())
}

type PostResolveError struct {
	underlyingError error
	reason          string
}

func (pre PostResolveError) Cause() error {
	return pre.underlyingError
}

func (pre PostResolveError) Error() string {
	if pre.reason == "" {
		return fmt.Sprintf("Post-resolve error: %s", pre.underlyingError.Error())
	}
	return fmt.Sprintf("Post-resolve error (%s): %s", pre.reason, pre.underlyingError.Error())
}

type KeyResolver func(ctx context.Context, key string, v interface{}) error
type Cache interface {
	Resolve(ctx context.Context, key string, v interface{}) error
	ResolveSplitErrors(ctx context.Context, key string, v interface{}) (ResolverError, error)
}

// Returns a new cache object
func NewCache(dir string, ttl *time.Duration, resolver KeyResolver) (Cache, error) {
	err := os.MkdirAll(dir, 0700)
	if err != nil {
		return nil, errors.Wrapf(err, "Cannot create state directory %s", dir)
	}

	return &cache{
		dir:      dir,
		ttl:      ttl,
		resolver: resolver,
	}, nil
}

type cache struct {
	dir      string
	ttl      *time.Duration
	resolver KeyResolver
}

func (c cache) ResolveSplitErrors(ctx context.Context, key string, v interface{}) (ResolverError, error) {
	switch v := c.Resolve(ctx, key, v).(type) {
	case PreResolveError:
		return v, nil
	// Don't return post resolve errors
	case PostResolveError:
		return v, nil
	default:
		return nil, v
	}
}

func (c cache) Resolve(ctx context.Context, key string, v interface{}) error {
	vType := reflect.TypeOf(v)
	if vType.Kind() != reflect.Ptr {
		panic("v must point to pointer")
	}

	path := filepath.Join(c.dir, fmt.Sprintf("entry-%s.json", key))
	file, err := os.Open(path)
	// Errors can happen because this is the first hit
	if err != nil {
		if os.IsNotExist(err) {
			return c.fetchValueAndCache(ctx, key, path, v)
		}
		return PreResolveError{underlyingError: err}
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return PreResolveError{underlyingError: err}
	}

	// Is this value expired?
	if c.ttl != nil && (time.Since(stat.ModTime()) > *c.ttl) {
		// Delete it
		err = os.Remove(path)
		if err != nil && !os.IsNotExist(err) {
			return PreResolveError{underlyingError: err}
		}

		// And fetch and store the new value
		return c.fetchValueAndCache(ctx, key, path, v)
	}

	// Let's go ahead and deserialize the value
	err = json.NewDecoder(file).Decode(v)
	if err != nil {
		return PreResolveError{underlyingError: err}
	}

	return nil
}

func (c cache) fetchValueAndCache(ctx context.Context, key, path string, v interface{}) error {
	err := c.resolver(ctx, key, v)
	if err != nil {
		return err
	}

	// TODO: Do the rename dance
	data, err := json.Marshal(v)
	if err != nil {
		return PostResolveError{underlyingError: err}
	}
	l := logrus.WithField("path", path).WithField("data", string(data))
	err = atomicWriteOnce(path, data, 0700)
	if err != nil {
		l.WithError(err).Error("Failed to write once")
		return PostResolveError{underlyingError: err}
	}
	l.WithError(err).Debug("Wrote once")

	return nil
}

func Duration(d time.Duration) *time.Duration {
	return &d
}
