package logger

import (
	"context"

	"github.com/sirupsen/logrus"
)

var G = GetLogger

type loggerKey struct{}

// WithLogger returns a new context with the provided logger. Use in
// combination with logger.WithField(s) for great effect.
func WithLogger(ctx context.Context, logger logrus.FieldLogger) context.Context {
	return context.WithValue(ctx, loggerKey{}, logger)
}

// GetLogger retrieves the current logger from the context. If no logger is
// available, the default logger is returned.
func GetLogger(ctx context.Context) logrus.FieldLogger {
	logger := ctx.Value(loggerKey{})

	if logger == nil {
		return logrus.StandardLogger()
	}

	return logger.(logrus.FieldLogger)
}

func WithField(ctx context.Context, key string, value interface{}) context.Context {
	return WithLogger(ctx, GetLogger(ctx).WithField(key, value))
}

func WithFields(ctx context.Context, fields map[string]interface{}) context.Context {
	return WithLogger(ctx, GetLogger(ctx).WithFields(fields))
}
