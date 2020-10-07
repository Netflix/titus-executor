package logger

import (
	"context"
	"encoding/json"
	"fmt"

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
		l := logrus.StandardLogger()
		l.SetFormatter(&logrus.TextFormatter{
			DisableQuote: true,
		})
		return l
	}

	return logger.(logrus.FieldLogger)
}

func WithField(ctx context.Context, key string, value interface{}) context.Context {
	return WithLogger(ctx, GetLogger(ctx).WithField(key, value))
}

func WithFields(ctx context.Context, fields map[string]interface{}) context.Context {
	return WithLogger(ctx, GetLogger(ctx).WithFields(fields))
}

// ShouldJSON returns JSON'd version of object, and if it cannot, it will log the error, and returns the "%+v" formatted
// version
func ShouldJSON(ctx context.Context, o interface{}) string {
	data, err := json.Marshal(o)
	if err != nil {
		GetLogger(ctx).WithError(err).Error("Could not serialize value")
		return fmt.Sprintf("%+v", o)
	}
	return string(data)
}
