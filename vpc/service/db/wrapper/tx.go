package wrapper

import "database/sql/driver"

var _ driver.Tx = (*txWrapper)(nil)

type txWrapper struct {
	wrapper *wrapper
	realTx  driver.Tx
}

func (t *txWrapper) Commit() error {
	return t.realTx.Commit()
}

func (t *txWrapper) Rollback() error {
	return t.realTx.Rollback()
}
