package service

type concurrencyError struct {
	err error
}

func (c *concurrencyError) Unwrap() error {
	return c.err
}

func (c *concurrencyError) Error() string {
	return c.err.Error()
}

func (c *concurrencyError) Is(target error) bool {
	_, ok := target.(*concurrencyError)
	return ok
}
