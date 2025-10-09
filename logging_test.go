package heroku

import (
	"bytes"
	"log"
	"os"
	"strings"
	"testing"
)

func TestLogLevelParsing(t *testing.T) {
	tests := []struct {
		input    string
		expected int
	}{
		// String inputs (case-insensitive)
		{"OFF", LogLevelOff},
		{"off", LogLevelOff},
		{"ERROR", LogLevelError},
		{"error", LogLevelError},
		{"WARN", LogLevelWarn},
		{"warn", LogLevelWarn},
		{"WARNING", LogLevelWarn},
		{"warning", LogLevelWarn},
		{"INFO", LogLevelInfo},
		{"info", LogLevelInfo},
		{"DEBUG", LogLevelDebug},
		{"debug", LogLevelDebug},

		// Integer inputs
		{"0", LogLevelOff},
		{"1", LogLevelError},
		{"2", LogLevelWarn},
		{"3", LogLevelInfo},
		{"4", LogLevelDebug},

		// Invalid inputs
		{"", -1},
		{"INVALID", -1},
		{"5", -1},
		{"-1", -1},
		{"abc", -1},
	}

	for _, test := range tests {
		result := parseLogLevel(test.input)
		if result != test.expected {
			t.Errorf("parseLogLevel(%q) = %d, expected %d", test.input, result, test.expected)
		}
	}
}

func TestGetLogLevel(t *testing.T) {
	// Test default behavior (no env vars set)
	os.Unsetenv("HEROKU_OAUTH_LOG_LEVEL")
	os.Unsetenv("DYNO_PROXY_LOG_LEVEL")
	if level := getLogLevel(); level != LogLevelWarn {
		t.Errorf("getLogLevel() with no env vars = %d, expected %d", level, LogLevelWarn)
	}

	// Test HEROKU_OAUTH_LOG_LEVEL priority
	os.Setenv("HEROKU_OAUTH_LOG_LEVEL", "DEBUG")
	os.Setenv("DYNO_PROXY_LOG_LEVEL", "ERROR")
	if level := getLogLevel(); level != LogLevelDebug {
		t.Errorf("getLogLevel() with HEROKU_OAUTH_LOG_LEVEL=DEBUG = %d, expected %d", level, LogLevelDebug)
	}

	// Test DYNO_PROXY_LOG_LEVEL fallback
	os.Unsetenv("HEROKU_OAUTH_LOG_LEVEL")
	os.Setenv("DYNO_PROXY_LOG_LEVEL", "INFO")
	if level := getLogLevel(); level != LogLevelInfo {
		t.Errorf("getLogLevel() with DYNO_PROXY_LOG_LEVEL=INFO = %d, expected %d", level, LogLevelInfo)
	}

	// Test case-insensitive parsing
	os.Setenv("HEROKU_OAUTH_LOG_LEVEL", "debug")
	if level := getLogLevel(); level != LogLevelDebug {
		t.Errorf("getLogLevel() with HEROKU_OAUTH_LOG_LEVEL=debug = %d, expected %d", level, LogLevelDebug)
	}

	// Test integer parsing
	os.Setenv("HEROKU_OAUTH_LOG_LEVEL", "3")
	if level := getLogLevel(); level != LogLevelInfo {
		t.Errorf("getLogLevel() with HEROKU_OAUTH_LOG_LEVEL=3 = %d, expected %d", level, LogLevelInfo)
	}

	// Clean up
	os.Unsetenv("HEROKU_OAUTH_LOG_LEVEL")
	os.Unsetenv("DYNO_PROXY_LOG_LEVEL")
}

func TestLoggingFunctions(t *testing.T) {
	// Helper function to capture log output
	captureLogOutput := func(fn func()) string {
		var buf bytes.Buffer
		oldOutput := log.Writer()
		log.SetOutput(&buf)
		defer log.SetOutput(oldOutput)

		fn()
		return buf.String()
	}

	t.Run("logError with different levels", func(t *testing.T) {
		// Test ERROR level
		os.Setenv("HEROKU_OAUTH_LOG_LEVEL", "1")
		output := captureLogOutput(func() {
			logError("Test error message")
		})
		if !strings.Contains(output, "ERROR Test error message") {
			t.Errorf("Expected ERROR log message, got: %s", output)
		}

		// Test WARN level (should include ERROR)
		os.Setenv("HEROKU_OAUTH_LOG_LEVEL", "2")
		output = captureLogOutput(func() {
			logError("Test error message")
		})
		if !strings.Contains(output, "ERROR Test error message") {
			t.Errorf("Expected ERROR log message, got: %s", output)
		}

		// Test OFF level (should not log)
		os.Setenv("HEROKU_OAUTH_LOG_LEVEL", "0")
		output = captureLogOutput(func() {
			logError("Test error message")
		})
		if output != "" {
			t.Errorf("Expected no output, got: %s", output)
		}
	})

	t.Run("logWarn with different levels", func(t *testing.T) {
		// Test WARN level
		os.Setenv("HEROKU_OAUTH_LOG_LEVEL", "2")
		output := captureLogOutput(func() {
			logWarn("Test warning message")
		})
		if !strings.Contains(output, "WARN Test warning message") {
			t.Errorf("Expected WARN log message, got: %s", output)
		}

		// Test INFO level (should include WARN)
		os.Setenv("HEROKU_OAUTH_LOG_LEVEL", "3")
		output = captureLogOutput(func() {
			logWarn("Test warning message")
		})
		if !strings.Contains(output, "WARN Test warning message") {
			t.Errorf("Expected WARN log message, got: %s", output)
		}

		// Test ERROR level (should not include WARN)
		os.Setenv("HEROKU_OAUTH_LOG_LEVEL", "1")
		output = captureLogOutput(func() {
			logWarn("Test warning message")
		})
		if output != "" {
			t.Errorf("Expected no output, got: %s", output)
		}
	})

	t.Run("logInfo with different levels", func(t *testing.T) {
		// Test INFO level
		os.Setenv("HEROKU_OAUTH_LOG_LEVEL", "3")
		output := captureLogOutput(func() {
			logInfo("Test info message")
		})
		if !strings.Contains(output, "Test info message") {
			t.Errorf("Expected INFO log message, got: %s", output)
		}

		// Test DEBUG level (should include INFO)
		os.Setenv("HEROKU_OAUTH_LOG_LEVEL", "4")
		output = captureLogOutput(func() {
			logInfo("Test info message")
		})
		if !strings.Contains(output, "Test info message") {
			t.Errorf("Expected INFO log message, got: %s", output)
		}

		// Test WARN level (should not include INFO)
		os.Setenv("HEROKU_OAUTH_LOG_LEVEL", "2")
		output = captureLogOutput(func() {
			logInfo("Test info message")
		})
		if output != "" {
			t.Errorf("Expected no output, got: %s", output)
		}
	})

	t.Run("logDebug with different levels", func(t *testing.T) {
		// Test DEBUG level
		os.Setenv("HEROKU_OAUTH_LOG_LEVEL", "4")
		output := captureLogOutput(func() {
			logDebug("Test debug message")
		})
		if !strings.Contains(output, "DEBUG Test debug message") {
			t.Errorf("Expected DEBUG log message, got: %s", output)
		}

		// Test INFO level (should not include DEBUG)
		os.Setenv("HEROKU_OAUTH_LOG_LEVEL", "3")
		output = captureLogOutput(func() {
			logDebug("Test debug message")
		})
		if output != "" {
			t.Errorf("Expected no output, got: %s", output)
		}
	})

	t.Run("logTraefikStyle with different levels", func(t *testing.T) {
		// Test INFO level
		os.Setenv("HEROKU_OAUTH_LOG_LEVEL", "3")
		output := captureLogOutput(func() {
			logTraefikStyle("INFO", "LOGIN user_email=test@example.com")
		})
		if !strings.Contains(output, "INFO LOGIN user_email=test@example.com") {
			t.Errorf("Expected Traefik-style log message, got: %s", output)
		}

		// Test WARN level (should not include INFO)
		os.Setenv("HEROKU_OAUTH_LOG_LEVEL", "2")
		output = captureLogOutput(func() {
			logTraefikStyle("INFO", "LOGIN user_email=test@example.com")
		})
		if output != "" {
			t.Errorf("Expected no output, got: %s", output)
		}
	})

	// Clean up
	os.Unsetenv("HEROKU_OAUTH_LOG_LEVEL")
}

func TestLogLevelInheritance(t *testing.T) {
	// Helper function to capture log output
	captureLogOutput := func(fn func()) string {
		var buf bytes.Buffer
		oldOutput := log.Writer()
		log.SetOutput(&buf)
		defer log.SetOutput(oldOutput)

		fn()
		return buf.String()
	}

	t.Run("DEBUG level includes all messages", func(t *testing.T) {
		os.Setenv("HEROKU_OAUTH_LOG_LEVEL", "4")

		output := captureLogOutput(func() {
			logError("error message")
			logWarn("warning message")
			logInfo("info message")
			logDebug("debug message")
		})

		if !strings.Contains(output, "ERROR error message") {
			t.Error("DEBUG level should include ERROR messages")
		}
		if !strings.Contains(output, "WARN warning message") {
			t.Error("DEBUG level should include WARN messages")
		}
		if !strings.Contains(output, "info message") {
			t.Error("DEBUG level should include INFO messages")
		}
		if !strings.Contains(output, "DEBUG debug message") {
			t.Error("DEBUG level should include DEBUG messages")
		}
	})

	t.Run("INFO level includes INFO, WARN, ERROR", func(t *testing.T) {
		os.Setenv("HEROKU_OAUTH_LOG_LEVEL", "3")

		output := captureLogOutput(func() {
			logError("error message")
			logWarn("warning message")
			logInfo("info message")
			logDebug("debug message")
		})

		if !strings.Contains(output, "ERROR error message") {
			t.Error("INFO level should include ERROR messages")
		}
		if !strings.Contains(output, "WARN warning message") {
			t.Error("INFO level should include WARN messages")
		}
		if !strings.Contains(output, "info message") {
			t.Error("INFO level should include INFO messages")
		}
		if strings.Contains(output, "DEBUG debug message") {
			t.Error("INFO level should not include DEBUG messages")
		}
	})

	t.Run("WARN level includes WARN, ERROR", func(t *testing.T) {
		os.Setenv("HEROKU_OAUTH_LOG_LEVEL", "2")

		output := captureLogOutput(func() {
			logError("error message")
			logWarn("warning message")
			logInfo("info message")
			logDebug("debug message")
		})

		if !strings.Contains(output, "ERROR error message") {
			t.Error("WARN level should include ERROR messages")
		}
		if !strings.Contains(output, "WARN warning message") {
			t.Error("WARN level should include WARN messages")
		}
		if strings.Contains(output, "info message") {
			t.Error("WARN level should not include INFO messages")
		}
		if strings.Contains(output, "DEBUG debug message") {
			t.Error("WARN level should not include DEBUG messages")
		}
	})

	t.Run("ERROR level includes only ERROR", func(t *testing.T) {
		os.Setenv("HEROKU_OAUTH_LOG_LEVEL", "1")

		output := captureLogOutput(func() {
			logError("error message")
			logWarn("warning message")
			logInfo("info message")
			logDebug("debug message")
		})

		if !strings.Contains(output, "ERROR error message") {
			t.Error("ERROR level should include ERROR messages")
		}
		if strings.Contains(output, "WARN warning message") {
			t.Error("ERROR level should not include WARN messages")
		}
		if strings.Contains(output, "info message") {
			t.Error("ERROR level should not include INFO messages")
		}
		if strings.Contains(output, "DEBUG debug message") {
			t.Error("ERROR level should not include DEBUG messages")
		}
	})

	t.Run("OFF level includes no messages", func(t *testing.T) {
		os.Setenv("HEROKU_OAUTH_LOG_LEVEL", "0")

		output := captureLogOutput(func() {
			logError("error message")
			logWarn("warning message")
			logInfo("info message")
			logDebug("debug message")
		})

		if output != "" {
			t.Errorf("OFF level should include no messages, got: %s", output)
		}
	})

	// Clean up
	os.Unsetenv("HEROKU_OAUTH_LOG_LEVEL")
}

func TestLogFormatting(t *testing.T) {
	// Helper function to capture log output
	captureLogOutput := func(fn func()) string {
		var buf bytes.Buffer
		oldOutput := log.Writer()
		log.SetOutput(&buf)
		defer log.SetOutput(oldOutput)

		fn()
		return buf.String()
	}

	t.Run("timestamp format", func(t *testing.T) {
		os.Setenv("HEROKU_OAUTH_LOG_LEVEL", "1")

		output := captureLogOutput(func() {
			logError("test message")
		})

		// Check for ISO 8601 timestamp format (YYYY-MM-DDTHH:MM:SS.sssZ)
		if !strings.Contains(output, "T") || !strings.Contains(output, "Z") {
			t.Errorf("Expected ISO 8601 timestamp format, got: %s", output)
		}
	})

	t.Run("log level format", func(t *testing.T) {
		os.Setenv("HEROKU_OAUTH_LOG_LEVEL", "4")

		output := captureLogOutput(func() {
			logError("error message")
			logWarn("warning message")
			logInfo("info message")
			logDebug("debug message")
		})

		if !strings.Contains(output, "ERROR error message") {
			t.Error("Expected ERROR level in output")
		}
		if !strings.Contains(output, "WARN warning message") {
			t.Error("Expected WARN level in output")
		}
		if !strings.Contains(output, "info message") {
			t.Error("Expected INFO level in output")
		}
		if !strings.Contains(output, "DEBUG debug message") {
			t.Error("Expected DEBUG level in output")
		}
	})

	// Clean up
	os.Unsetenv("HEROKU_OAUTH_LOG_LEVEL")
}

func TestEnvironmentVariableFallback(t *testing.T) {
	// Test that DYNO_PROXY_LOG_LEVEL is used when HEROKU_OAUTH_LOG_LEVEL is not set
	os.Unsetenv("HEROKU_OAUTH_LOG_LEVEL")
	os.Setenv("DYNO_PROXY_LOG_LEVEL", "3")

	if level := getLogLevel(); level != LogLevelInfo {
		t.Errorf("Expected LogLevelInfo when DYNO_PROXY_LOG_LEVEL=3, got %d", level)
	}

	// Test that HEROKU_OAUTH_LOG_LEVEL takes precedence
	os.Setenv("HEROKU_OAUTH_LOG_LEVEL", "1")
	os.Setenv("DYNO_PROXY_LOG_LEVEL", "3")

	if level := getLogLevel(); level != LogLevelError {
		t.Errorf("Expected LogLevelError when HEROKU_OAUTH_LOG_LEVEL=1, got %d", level)
	}

	// Clean up
	os.Unsetenv("HEROKU_OAUTH_LOG_LEVEL")
	os.Unsetenv("DYNO_PROXY_LOG_LEVEL")
}
