package logger

import (
	"log"
	"os"
)

type LogLevel int

const (
	INFO LogLevel = iota
	DEBUG
)

var (
	currentLevel  LogLevel = INFO
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
		currentLevel = DEBUG
	}
}

// SetLogLevel explicitly sets the log level.
func SetLogLevel(level LogLevel) {
	currentLevel = level
}

func Debug(format string, v ...any) {
	if currentLevel >= DEBUG {
		infoLogger.Printf("[DEBUG] "+format, v...)
	}
}

func Info(format string, v ...any) {
	if currentLevel >= INFO {
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
