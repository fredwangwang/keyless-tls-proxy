package kspclient

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/fredwangwang/keyless-tls-proxy/internal/kspcommon"
)

type Config struct {
	Addr string `json:"addr"`
	CA   string `json:"ca"`
	Cert string `json:"cert"`
	Key  string `json:"key"`
}

func LoadConfig(path string) (*Config, error) {
	if path == "" {
		path = kspcommon.ConfigPath()
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if cfg.Addr == "" {
		return nil, os.ErrInvalid
	}
	return &cfg, nil
}

// LoadConfigFromEnv builds a Config from the KSP11_ADDR / KSP11_CA /
// KSP11_CERT / KSP11_KEY environment variables. Returns nil when KSP11_ADDR
// is unset. Used by the Linux PKCS#11 bridge.
func LoadConfigFromEnv() *Config {
	addr := os.Getenv("KSP11_ADDR")
	if addr == "" {
		return nil
	}
	return &Config{
		Addr: addr,
		CA:   os.Getenv("KSP11_CA"),
		Cert: os.Getenv("KSP11_CERT"),
		Key:  os.Getenv("KSP11_KEY"),
	}
}

func SaveConfig(cfg *Config, path string) error {
	if path == "" {
		path = kspcommon.ConfigPath()
	}
	if err := os.MkdirAll(kspcommon.DataDir(), 0o755); err != nil {
		return err
	}
	if cfg.CA != "" {
		if abs, err := filepath.Abs(cfg.CA); err == nil {
			cfg.CA = abs
		} else {
			return err
		}
	}
	if cfg.Cert != "" {
		if abs, err := filepath.Abs(cfg.Cert); err == nil {
			cfg.Cert = abs
		} else {
			return err
		}
	}
	if cfg.Key != "" {
		if abs, err := filepath.Abs(cfg.Key); err == nil {
			cfg.Key = abs
		} else {
			return err
		}
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

