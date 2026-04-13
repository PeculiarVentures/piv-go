package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config stores CLI-layer defaults only.
type Config struct {
	DefaultReader string       `yaml:"default-reader,omitempty"`
	Adapter       string       `yaml:"adapter,omitempty"`
	Timeout       string       `yaml:"timeout,omitempty"`
	Trace         string       `yaml:"trace,omitempty"`
	Color         string       `yaml:"color,omitempty"`
	Export        ExportConfig `yaml:"export,omitempty"`
}

// ExportConfig stores default serialization preferences.
type ExportConfig struct {
	CertFormat   string `yaml:"cert-format,omitempty"`
	PublicFormat string `yaml:"public-key-format,omitempty"`
}

// ConfigStore manages the CLI configuration file.
type ConfigStore struct {
	path string
}

// NewConfigStore creates a config store using the default path when empty.
func NewConfigStore(path string) (*ConfigStore, error) {
	if path == "" {
		resolved, err := defaultConfigPath()
		if err != nil {
			return nil, err
		}
		path = resolved
	}
	return &ConfigStore{path: path}, nil
}

// Path returns the filesystem path used by the store.
func (s *ConfigStore) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

// Load reads the config file. A missing file returns an empty config.
func (s *ConfigStore) Load() (Config, error) {
	if s == nil {
		return Config{}, InternalError("configuration store is not initialized", "retry the command", nil)
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return Config{}, nil
		}
		return Config{}, IOError(fmt.Sprintf("unable to read %s", s.path), "check the config file path and permissions", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, IOError(fmt.Sprintf("unable to parse %s", s.path), "fix the YAML syntax or remove the invalid config file", err)
	}
	if err := validateConfig(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Save writes the config file atomically.
func (s *ConfigStore) Save(cfg Config) error {
	if s == nil {
		return InternalError("configuration store is not initialized", "retry the command", nil)
	}
	if err := validateConfig(cfg); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return IOError(fmt.Sprintf("unable to create %s", filepath.Dir(s.path)), "check filesystem permissions", err)
	}
	data, err := yaml.Marshal(&cfg)
	if err != nil {
		return InternalError("unable to serialize configuration", "retry the command", err)
	}
	if err := os.WriteFile(s.path, data, 0o644); err != nil {
		return IOError(fmt.Sprintf("unable to write %s", s.path), "check filesystem permissions", err)
	}
	return nil
}

// Set updates one supported configuration key.
func (s *ConfigStore) Set(key string, value string) error {
	cfg, err := s.Load()
	if err != nil {
		return err
	}
	if err := applyConfigValue(&cfg, key, value); err != nil {
		return err
	}
	return s.Save(cfg)
}

// Unset clears one supported configuration key.
func (s *ConfigStore) Unset(key string) error {
	cfg, err := s.Load()
	if err != nil {
		return err
	}
	if err := clearConfigValue(&cfg, key); err != nil {
		return err
	}
	return s.Save(cfg)
}

// ConfigValues renders the persisted configuration as a stable key/value list.
func ConfigValues(cfg Config) []ConfigValueView {
	values := []ConfigValueView{
		{Key: "adapter", Value: cfg.Adapter},
		{Key: "color", Value: cfg.Color},
		{Key: "default-reader", Value: cfg.DefaultReader},
		{Key: "export.cert-format", Value: cfg.Export.CertFormat},
		{Key: "export.public-key-format", Value: cfg.Export.PublicFormat},
		{Key: "timeout", Value: cfg.Timeout},
		{Key: "trace", Value: cfg.Trace},
	}
	filtered := make([]ConfigValueView, 0, len(values))
	for _, value := range values {
		if value.Value == "" {
			continue
		}
		filtered = append(filtered, value)
	}
	return sortedConfigValues(filtered)
}

// ResolveStringSetting resolves one flag/env/config setting and reports the origin.
func ResolveStringSetting(flagSet bool, flagValue string, envValue string, configValue string, fallback string) (string, string) {
	if flagSet {
		return strings.TrimSpace(flagValue), "flag"
	}
	if value := strings.TrimSpace(envValue); value != "" {
		return value, "env"
	}
	if value := strings.TrimSpace(configValue); value != "" {
		return value, "config"
	}
	if value := strings.TrimSpace(fallback); value != "" {
		return value, "auto"
	}
	return "", ""
}

// ResolveDurationSetting resolves and parses a duration setting.
func ResolveDurationSetting(flagSet bool, flagValue string, envValue string, configValue string, fallback time.Duration) (time.Duration, string, error) {
	value, origin := ResolveStringSetting(flagSet, flagValue, envValue, configValue, "")
	if value == "" {
		if fallback > 0 {
			return fallback, "auto", nil
		}
		return 0, "", nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		return 0, "", UsageError(fmt.Sprintf("invalid timeout %q", value), "use a Go duration such as 5s, 15s, or 1m")
	}
	return duration, origin, nil
}

// ResolveTraceSetting validates a trace setting value.
func ResolveTraceSetting(flagSet bool, flagValue string, envValue string, configValue string, fallback TraceLevel) (TraceLevel, string, error) {
	value, origin := ResolveStringSetting(flagSet, flagValue, envValue, configValue, string(fallback))
	if value == "" {
		return TraceOff, "", nil
	}
	trace, err := ParseTraceLevel(value)
	if err != nil {
		return TraceOff, "", err
	}
	return trace, origin, nil
}

// ParseTraceLevel validates the textual trace policy.
func ParseTraceLevel(value string) (TraceLevel, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "off":
		return TraceOff, nil
	case "apdu":
		return TraceAPDU, nil
	case "ops":
		return TraceOps, nil
	case "all":
		return TraceAll, nil
	default:
		return TraceOff, UsageError(fmt.Sprintf("unsupported trace level %q", value), "use off, apdu, ops, or all")
	}
}

func defaultConfigPath() (string, error) {
	directory, err := os.UserConfigDir()
	if err != nil {
		return "", IOError("unable to resolve the user config directory", "set a writable HOME directory and retry", err)
	}
	return filepath.Join(directory, "piv", "config.yaml"), nil
}

func validateConfig(cfg Config) error {
	if cfg.Adapter != "" {
		switch strings.ToLower(cfg.Adapter) {
		case "auto", "standard", "safenet", "yubikey":
		default:
			return UsageError(fmt.Sprintf("invalid config value adapter=%q", cfg.Adapter), "supported adapters are auto, standard, safenet, and yubikey")
		}
	}
	if cfg.Trace != "" {
		if _, err := ParseTraceLevel(cfg.Trace); err != nil {
			return UsageError(fmt.Sprintf("invalid config value trace=%q", cfg.Trace), "supported trace levels are off, apdu, ops, and all")
		}
	}
	if cfg.Timeout != "" {
		if _, err := time.ParseDuration(cfg.Timeout); err != nil {
			return UsageError(fmt.Sprintf("invalid config value timeout=%q", cfg.Timeout), "use a Go duration such as 5s, 15s, or 1m")
		}
	}
	if cfg.Color != "" {
		switch strings.ToLower(cfg.Color) {
		case "auto", "always", "never":
		default:
			return UsageError(fmt.Sprintf("invalid config value color=%q", cfg.Color), "supported color policies are auto, always, and never")
		}
	}
	if cfg.Export.CertFormat != "" {
		switch strings.ToLower(cfg.Export.CertFormat) {
		case "pem", "der":
		default:
			return UsageError(fmt.Sprintf("invalid config value export.cert-format=%q", cfg.Export.CertFormat), "supported certificate formats are pem and der")
		}
	}
	if cfg.Export.PublicFormat != "" {
		switch strings.ToLower(cfg.Export.PublicFormat) {
		case "pem", "der":
		default:
			return UsageError(fmt.Sprintf("invalid config value export.public-key-format=%q", cfg.Export.PublicFormat), "supported public key formats are pem and der")
		}
	}
	return nil
}

func applyConfigValue(cfg *Config, key string, value string) error {
	if cfg == nil {
		return InternalError("configuration store is not initialized", "retry the command", nil)
	}
	value = strings.TrimSpace(value)
	switch key {
	case "default-reader":
		cfg.DefaultReader = value
	case "adapter":
		cfg.Adapter = value
	case "timeout":
		cfg.Timeout = value
	case "trace":
		cfg.Trace = value
	case "color":
		cfg.Color = value
	case "export.cert-format":
		cfg.Export.CertFormat = value
	case "export.public-key-format":
		cfg.Export.PublicFormat = value
	default:
		return UsageError(fmt.Sprintf("unsupported config key %q", key), "use one of default-reader, adapter, timeout, trace, color, export.cert-format, or export.public-key-format")
	}
	return validateConfig(*cfg)
}

func clearConfigValue(cfg *Config, key string) error {
	return applyConfigValue(cfg, key, "")
}
