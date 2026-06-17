package kspclient

import (
	"encoding/json"
	"os"

	"tpm-cert-proxy/internal/kspcommon"
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

func SaveConfig(cfg *Config, path string) error {
	if path == "" {
		path = kspcommon.ConfigPath()
	}
	if err := os.MkdirAll(kspcommon.DataDir(), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
