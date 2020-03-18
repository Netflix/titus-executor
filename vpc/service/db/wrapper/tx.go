package wrapper

import (
	"database/sql/driver"

	"github.com/Netflix/titus-executor/vpc/tracehelpers"
	"go.opencensus.io/trace"
)

var _ driver.Tx = (*txWrapper)(nil)

type txWrapper struct {
	span     *trace.Span
	isSerial bool
	wrapper  *wrapper
	realTx   driver.Tx
	done     bool
}

func (t *txWrapper) Commit() error {
	err := t.realTx.Commit()
	if !t.done {
		if t.isSerial {
			t.wrapper.serializedConnectionSemaphore.Release(1)
		}
		if t.span != nil {
			t.span.AddAttributes(trace.StringAttribute("result", "committed"))
			tracehelpers.SetStatus(err, t.span)
			t.span.End()
		}
	}
	t.done = true
	return err
}

func (t *txWrapper) Rollback() error {
	err := t.realTx.Rollback()
	if !t.done {
		if t.isSerial {
			t.wrapper.serializedConnectionSemaphore.Release(1)
		}
		if t.span != nil {
			t.span.AddAttributes(trace.StringAttribute("result", "rollback"))
			tracehelpers.SetStatus(err, t.span)
			t.span.End()
		}
	}
	t.done = true
	return err
}
