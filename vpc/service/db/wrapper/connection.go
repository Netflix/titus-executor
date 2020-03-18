package wrapper

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"fmt"

	"github.com/pkg/errors"

	"github.com/Netflix/titus-executor/vpc/tracehelpers"

	"github.com/Netflix/titus-executor/logger"
	"go.opencensus.io/trace"
)

var (
	_ connectionInterface       = (*connectionWrapper)(nil)
	_ driver.ConnPrepareContext = (*connectionWrapper)(nil)
)

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
}

func (c *connectionWrapper) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	query = c.enhanceQuery(ctx, query)
	return c.realConn.Prepare(query)
}

func (c *connectionWrapper) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	ctx, span := trace.StartSpan(ctx, "BeginTx")
	defer span.End()
	span.AddAttributes(trace.StringAttribute("isolationLevel", sql.IsolationLevel(opts.Isolation).String()))

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
	return &txWrapper{
		span:     txSpan,
		isSerial: isSerial,
		wrapper:  c.wrapper,
		realTx:   tx,
	}, nil
}

func (c *connectionWrapper) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	query = c.enhanceQuery(ctx, query)
	return c.realConn.QueryContext(ctx, query, args)
}

func (c *connectionWrapper) Query(query string, args []driver.Value) (driver.Rows, error) {
	query = c.enhanceQuery(context.Background(), query)
	return c.realConn.Query(query, args)
}

func (c *connectionWrapper) Ping(ctx context.Context) error {
	return c.realConn.Ping(ctx)
}

func (c *connectionWrapper) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	query = c.enhanceQuery(ctx, query)
	return c.realConn.ExecContext(ctx, query, args)
}

func (c *connectionWrapper) Exec(query string, args []driver.Value) (driver.Result, error) {
	query = c.enhanceQuery(context.Background(), query)
	return c.realConn.Exec(query, args)
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

func (c connectionWrapper) enhanceQuery(ctx context.Context, query string) string {
	md := QueryMetadata{}

	if span := trace.FromContext(ctx); span != nil {
		spanContext := span.SpanContext()
		md.SpanID = spanContext.SpanID.String()
	} else {
		md.Hostname = c.wrapper.hostname
	}
	data, err := json.Marshal(md)
	if err != nil {
		logger.G(ctx).WithError(err).Error("Unable to serialize JSON to enhance query")
		return query
	}
	return fmt.Sprintf("/* md: %s */\n", string(data)) + query
}

type QueryMetadata struct {
	SpanID   string `json:"spanID,omitempty"`
	Hostname string `json:"hostname,omitempty"`
}
