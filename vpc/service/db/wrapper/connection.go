package wrapper

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/Netflix/titus-executor/vpc/tracehelpers"

	"github.com/Netflix/titus-executor/logger"
	"go.opencensus.io/trace"
)

const (
	skipLevel     = 5
	callerProject = "github.com/Netflix/titus-executor"
)

var (
	_ connectionInterface       = (*connectionWrapper)(nil)
	_ driver.ConnPrepareContext = (*connectionWrapper)(nil)
)

var LogTransactions bool

type connectionInterface interface {
	driver.Conn
	driver.Execer // nolint:staticcheck
	driver.ExecerContext
	driver.Pinger
	driver.Queryer // nolint:staticcheck
	driver.QueryerContext
	driver.ConnBeginTx
	// pq doesn't implement:
	// - driver.ConnPrepareContext
}

type connectionWrapper struct {
	realConn connectionInterface
	wrapper  *wrapper
	pid      int64
}

func (c *connectionWrapper) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	timeFunc, query := c.enhanceQuery(ctx, query)
	res, err := c.realConn.Prepare(query)
	timeFunc(err)
	return res, err
}

func (c *connectionWrapper) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	ctx, span := trace.StartSpan(ctx, "BeginTx")
	defer span.End()
	span.AddAttributes(
		trace.StringAttribute("isolationLevel", sql.IsolationLevel(opts.Isolation).String()),
		trace.Int64Attribute("pg_backend_pid", c.pid),
	)

	isSerial := (sql.IsolationLevel(opts.Isolation) == sql.LevelSerializable)
	if isSerial {
		err := c.wrapper.serializedConnectionSemaphore.Acquire(ctx, 1)
		if err != nil {
			err = errors.Wrap(err, "Could not acquire serializedConnectionSemaphore")
			tracehelpers.SetStatus(err, span)
			return nil, err
		}
	}

	tx, err := c.realConn.BeginTx(ctx, opts)
	if err != nil {
		if isSerial {
			c.wrapper.serializedConnectionSemaphore.Release(1)
		}
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	// TODO: Somehow figure out how to link this to all of the things.
	_, txSpan := trace.StartSpan(ctx, "tx")
	txSpan.AddAttributes(
		trace.Int64Attribute("pg_backend_pid", c.pid),
	)
	return &txWrapper{
		span:     txSpan,
		isSerial: isSerial,
		wrapper:  c.wrapper,
		realTx:   tx,
	}, nil
}

func (c *connectionWrapper) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	timeFunc, query := c.enhanceQuery(ctx, query)
	res, err := c.realConn.QueryContext(ctx, query, args)
	timeFunc(err)
	return res, err
}

func (c *connectionWrapper) Query(query string, args []driver.Value) (driver.Rows, error) {
	timeFunc, query := c.enhanceQuery(context.TODO(), query)
	res, err := c.realConn.Query(query, args)
	timeFunc(err)
	return res, err
}

func (c *connectionWrapper) Ping(ctx context.Context) error {
	return c.realConn.Ping(ctx)
}

func (c *connectionWrapper) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	timeFunc, query := c.enhanceQuery(ctx, query)
	res, err := c.realConn.ExecContext(ctx, query, args)
	timeFunc(err)
	return res, err
}

func (c *connectionWrapper) Exec(query string, args []driver.Value) (driver.Result, error) {
	timeFunc, query := c.enhanceQuery(context.TODO(), query)
	res, err := c.realConn.Exec(query, args)
	timeFunc(err)
	return res, err
}

func (c *connectionWrapper) Prepare(query string) (driver.Stmt, error) {
	return c.realConn.Prepare(query)
}

func (c *connectionWrapper) Close() error {
	return c.realConn.Close()
}

func (c *connectionWrapper) Begin() (driver.Tx, error) {
	tx, err := c.realConn.Begin() // nolint:staticcheck
	if err != nil {
		return nil, err
	}
	return &txWrapper{
		wrapper: c.wrapper,
		realTx:  tx,
	}, nil
}

func (c *connectionWrapper) enhanceQuery(ctx context.Context, query string) (func(error), string) {
	md := QueryMetadata{}

	callsite := ":0"
	callers := make([]uintptr, 10)
	runtime.Callers(skipLevel, callers)
	frames := runtime.CallersFrames(callers)
	frame, more := frames.Next()
	for more {
		// Function is the package path-qualified function name of
		// this call frame.
		if strings.HasPrefix(frame.Function, callerProject) {
			callsite = fmt.Sprintf("%s:%d", filepath.Base(frame.File), frame.Line)
			break
		}
		frame, more = frames.Next()
	}
	timeFunction := func(error) {}
	if span := trace.FromContext(ctx); span != nil {
		span.AddAttributes(trace.Int64Attribute("pg_backend_pid", c.pid))
		spanContext := span.SpanContext()
		md.SpanID = spanContext.SpanID.String()
		now := time.Now()
		timeFunction = func(e error) {
			queryTime := time.Since(now)
			span.AddAttributes(trace.Int64Attribute(callsite+"#queryTimeMs", queryTime.Milliseconds()))
			if e != nil {
				span.AddAttributes(trace.StringAttribute(callsite+"#error", e.Error()))
			}
		}
		if LogTransactions {
			span.AddAttributes(trace.StringAttribute("query", query))
		}
	} else {
		md.Hostname = c.wrapper.hostname
	}
	data, err := json.Marshal(md)
	if err != nil {
		logger.G(ctx).WithError(err).Error("Unable to serialize JSON to enhance query")
		return timeFunction, query
	}
	return timeFunction, fmt.Sprintf("/* md: %s */\n", string(data)) + query
}

type QueryMetadata struct {
	SpanID   string `json:"spanID,omitempty"`
	Hostname string `json:"hostname,omitempty"`
}
