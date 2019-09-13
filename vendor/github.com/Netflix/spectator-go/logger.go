package spectator

import (
	"log"
	"os"
)

type Logger interface {
	Debugf(format string, v ...interface{})
	Infof(format string, v ...interface{})
	Errorf(format string, v ...interface{})
}

type DefaultLogger struct {
	debug *log.Logger
	info  *log.Logger
	error *log.Logger
}

func defaultLogger() *DefaultLogger {
	flags := log.LstdFlags

	debug := log.New(os.Stdout, "DEBUG: ", flags)
	info := log.New(os.Stdout, "INFO: ", flags)
	err := log.New(os.Stdout, "ERROR: ", flags)

	return &DefaultLogger{
		debug,
		info,
		err,
	}
}

func (l *DefaultLogger) Debugf(format string, v ...interface{}) {
	l.debug.Printf(format, v...)
}

func (l *DefaultLogger) Infof(format string, v ...interface{}) {
	l.info.Printf(format, v...)
}

func (l *DefaultLogger) Errorf(format string, v ...interface{}) {
	l.error.Printf(format, v...)
}
