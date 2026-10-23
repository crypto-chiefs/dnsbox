package logger

import (
	"log"
	"os"
	"sync/atomic"
)

type LogLevel int

const (
	INFO LogLevel = iota
	DEBUG
)

var (
	currentLevel  atomic.Int32
	infoLogger    *log.Logger
	errorLogger   *log.Logger
	warningLogger *log.Logger
)

func init() {
	infoLogger = log.New(os.Stdout, "[dnsbox] ", log.LstdFlags)
	warningLogger = log.New(os.Stdout, "[dnsbox] ", log.LstdFlags)
	errorLogger = log.New(os.Stderr, "[dnsbox] ", log.LstdFlags)
}

// SetDebugMode enables or disables debug logging.
func SetDebugMode(enabled bool) {
	if enabled {
		currentLevel.Store(int32(DEBUG))
	} else {
		currentLevel.Store(int32(INFO))
	}
}

// SetLogLevel explicitly sets the log level.
func SetLogLevel(level LogLevel) {
	currentLevel.Store(int32(level))
}

func Debug(format string, v ...any) {
	if currentLevel.Load() >= int32(DEBUG) {
		infoLogger.Printf("[DEBUG] "+format, v...)
	}
}

func Info(format string, v ...any) {
	if currentLevel.Load() >= int32(INFO) {
		infoLogger.Printf("[INFO] "+format, v...)
	}
}

func Warn(format string, v ...any) {
	warningLogger.Printf("[WARN] "+format, v...)
}

func Error(format string, v ...any) {
	errorLogger.Printf("[ERROR] "+format, v...)
}

func Fatal(format string, v ...any) {
	errorLogger.Printf("[FATAL] "+format, v...)
	os.Exit(1)
}
