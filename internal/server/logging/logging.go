package logging

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"toshell/internal/common/types"
	"toshell/internal/server/database"
)

type Level int

const (
	DEBUG Level = iota
	INFO
	WARN
	ERROR
	FATAL
)

var (
	logger       *Logger
	levelStrMap  = map[Level]string{
		DEBUG: "debug",
		INFO:  "info",
		WARN:  "warning",
		ERROR: "error",
		FATAL: "fatal",
	}
)

type Logger struct {
	output   io.Writer
	file     *os.File
	level    Level
	format   string
	db       *database.Database
	mu       sync.Mutex
}

func New(output string, level string, format string) (*Logger, error) {
	logger := &Logger{
		level:  parseLevel(level),
		format: format,
	}

	switch output {
	case "stdout":
		logger.output = os.Stdout
	case "stderr":
		logger.output = os.Stderr
	default:
		dir := filepath.Dir(output)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, err
		}

		f, err := os.OpenFile(output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, err
		}
		logger.output = f
		logger.file = f
	}

	logger.db = database.Get()

	return logger, nil
}

func Get() *Logger {
	if logger == nil {
		logger, _ = New("stdout", "info", "json")
	}
	return logger
}

func parseLevel(level string) Level {
	switch level {
	case "debug":
		return DEBUG
	case "info":
		return INFO
	case "warn", "warning":
		return WARN
	case "error":
		return ERROR
	case "fatal":
		return FATAL
	default:
		return INFO
	}
}

func (l *Logger) SetLevel(level string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = parseLevel(level)
}

func (l *Logger) log(level Level, component string, format string, args ...interface{}) {
	if level < l.level {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	levelStr := levelStrMap[level]
	message := fmt.Sprintf(format, args...)

	logEntry := &types.LogEntry{
		Timestamp: time.Now(),
		Level:     levelStr,
		Component: component,
		Message:   message,
	}

	if l.format == "json" {
		logLine := fmt.Sprintf(`{"timestamp":"%s","level":"%s","component":"%s","message":"%s"}`, timestamp, levelStr, component, message)
		fmt.Fprintln(l.output, logLine)
	} else {
		logLine := fmt.Sprintf("[%s] [%s] [%s] %s", timestamp, levelStr, component, message)
		fmt.Fprintln(l.output, logLine)
	}

	if l.db != nil {
		l.db.CreateLog(logEntry)
	}
}

func (l *Logger) Debug(component string, format string, args ...interface{}) {
	l.log(DEBUG, component, format, args...)
}

func (l *Logger) Info(component string, format string, args ...interface{}) {
	l.log(INFO, component, format, args...)
}

func (l *Logger) Warn(component string, format string, args ...interface{}) {
	l.log(WARN, component, format, args...)
}

func (l *Logger) Error(component string, format string, args ...interface{}) {
	l.log(ERROR, component, format, args...)
}

func (l *Logger) Fatal(component string, format string, args ...interface{}) {
	l.log(FATAL, component, format, args...)
	os.Exit(1)
}

func (l *Logger) Close() error {
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

func Debug(component string, format string, args ...interface{}) {
	if logger != nil {
		logger.Debug(component, format, args...)
	} else {
		log.Printf("[DEBUG] ["+component+"] "+format, args...)
	}
}

func Info(component string, format string, args ...interface{}) {
	if logger != nil {
		logger.Info(component, format, args...)
	} else {
		log.Printf("[INFO] ["+component+"] "+format, args...)
	}
}

func Warn(component string, format string, args ...interface{}) {
	if logger != nil {
		logger.Warn(component, format, args...)
	} else {
		log.Printf("[WARN] ["+component+"] "+format, args...)
	}
}

func Error(component string, format string, args ...interface{}) {
	if logger != nil {
		logger.Error(component, format, args...)
	} else {
		log.Printf("[ERROR] ["+component+"] "+format, args...)
	}
}

func Fatal(component string, format string, args ...interface{}) {
	if logger != nil {
		logger.Fatal(component, format, args...)
	} else {
		log.Printf("[FATAL] ["+component+"] "+format, args...)
		os.Exit(1)
	}
}

func WithSession(sessionID string) *SessionLogger {
	return &SessionLogger{
		sessionID: sessionID,
	}
}

type SessionLogger struct {
	sessionID string
}

func (l *SessionLogger) Debug(format string, args ...interface{}) {
	Debug("session", format, args...)
}

func (l *SessionLogger) Info(format string, args ...interface{}) {
	Info("session", format, args...)
}

func (l *SessionLogger) Warn(format string, args ...interface{}) {
	Warn("session", format, args...)
}

func (l *SessionLogger) Error(format string, args ...interface{}) {
	Error("session", format, args...)
}
