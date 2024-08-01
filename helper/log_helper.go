package helper

import (
	"log"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

const (
	LOGGING = "logging"
	GENERAL = "general"
)

func logMessage(level, path, message string, context map[string]interface{}) {
	now := time.Now()
	filePath := filepath.Join("logs", path, now.Format("2006-01-02_15")+".log")
	dir := filepath.Dir(filePath)

	// Ensure the directory exists
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Println("Error creating directories for log file:", err)
		return
	}

	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Println("Error opening log file:", err)
		return
	}
	defer file.Close()

	logger := log.New(file, level+" ", log.LstdFlags|log.Lshortfile)
	_, fileName, line, _ := runtime.Caller(2)
	logContext := map[string]interface{}{
		"trace_file": fileName,
		"trace_line": line,
	}
	for k, v := range context {
		logContext[k] = v
	}

	logger.Printf("%s %v", message, logContext)
}

func Info(path, message string, context map[string]interface{}) {
	logMessage("INFO", path, message, context)
}

func Error(path, message string, context map[string]interface{}) {
	logMessage("ERROR", path, message, context)
}

func Warning(path, message string, context map[string]interface{}) {
	logMessage("WARNING", path, message, context)
}

func Critical(path, message string, context map[string]interface{}) {
	logMessage("CRITICAL", path, message, context)
}

func Emergency(path, message string, context map[string]interface{}) {
	logMessage("EMERGENCY", path, message, context)
}
