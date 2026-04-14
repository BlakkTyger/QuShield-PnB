// Package logger provides structured JSON logging matching the Python logger format.
package logger

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Entry represents a single log entry in the QuShield format.
type Entry struct {
	Timestamp string                 `json:"timestamp"`
	Level     string                 `json:"level"`
	Service   string                 `json:"service"`
	Function  string                 `json:"function"`
	Message   string                 `json:"message"`
	Extra     map[string]interface{} `json:"extra,omitempty"`
}

// Logger writes structured JSON logs to stdout and a JSONL file.
type Logger struct {
	service string
	logFile *os.File
	mu      sync.Mutex
}

// New creates a new Logger for the given service name.
func New(service string, logDir string) *Logger {
	// Create log directory
	dir := filepath.Join(logDir, service)
	os.MkdirAll(dir, 0755)

	// Open log file
	date := time.Now().Format("2006-01-02")
	filePath := filepath.Join(dir, date+".jsonl")
	f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: cannot open log file %s: %v\n", filePath, err)
	}

	return &Logger{
		service: service,
		logFile: f,
	}
}

func (l *Logger) log(level, function, message string, extra map[string]interface{}) {
	entry := Entry{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Level:     level,
		Service:   l.service,
		Function:  function,
		Message:   message,
		Extra:     extra,
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return
	}

	// Write to stdout
	fmt.Println(string(data))

	// Write to file
	if l.logFile != nil {
		l.mu.Lock()
		l.logFile.Write(data)
		l.logFile.Write([]byte("\n"))
		l.mu.Unlock()
	}
}

// Info logs at INFO level.
func (l *Logger) Info(function, message string, extra ...map[string]interface{}) {
	var e map[string]interface{}
	if len(extra) > 0 {
		e = extra[0]
	}
	l.log("INFO", function, message, e)
}

// Debug logs at DEBUG level.
func (l *Logger) Debug(function, message string, extra ...map[string]interface{}) {
	var e map[string]interface{}
	if len(extra) > 0 {
		e = extra[0]
	}
	l.log("DEBUG", function, message, e)
}

// Warn logs at WARNING level.
func (l *Logger) Warn(function, message string, extra ...map[string]interface{}) {
	var e map[string]interface{}
	if len(extra) > 0 {
		e = extra[0]
	}
	l.log("WARNING", function, message, e)
}

// Error logs at ERROR level.
func (l *Logger) Error(function, message string, extra ...map[string]interface{}) {
	var e map[string]interface{}
	if len(extra) > 0 {
		e = extra[0]
	}
	l.log("ERROR", function, message, e)
}

// Close closes the log file.
func (l *Logger) Close() {
	if l.logFile != nil {
		l.logFile.Close()
	}
}
