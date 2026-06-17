package kspmanifest

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"tpm-cert-proxy/internal/kspcommon"
)

var ErrNotInstalled = errors.New("thumbprint not in installed manifest")

type Entry struct {
	Thumbprint  string    `json:"thumbprint"`
	Subject     string    `json:"subject,omitempty"`
	InstalledAt time.Time `json:"installed_at"`
}

type Manifest struct {
	Keys []Entry `json:"keys"`
}

func Load() (*Manifest, error) {
	path := kspcommon.ManifestPath()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Manifest{}, nil
		}
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func Save(m *Manifest) error {
	if m == nil {
		m = &Manifest{}
	}
	if err := os.MkdirAll(kspcommon.DataDir(), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	path := kspcommon.ManifestPath()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func NormalizeThumbprint(tp string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(tp), " ", ""))
}

func (m *Manifest) Contains(thumbprint string) bool {
	tp := NormalizeThumbprint(thumbprint)
	for _, e := range m.Keys {
		if NormalizeThumbprint(e.Thumbprint) == tp {
			return true
		}
	}
	return false
}

func Add(thumbprint, subject string) error {
	m, err := Load()
	if err != nil {
		return err
	}
	tp := NormalizeThumbprint(thumbprint)
	for i, e := range m.Keys {
		if NormalizeThumbprint(e.Thumbprint) == tp {
			m.Keys[i].Subject = subject
			return Save(m)
		}
	}
	m.Keys = append(m.Keys, Entry{
		Thumbprint:  tp,
		Subject:     subject,
		InstalledAt: time.Now().UTC(),
	})
	return Save(m)
}

func Remove(thumbprint string) error {
	m, err := Load()
	if err != nil {
		return err
	}
	tp := NormalizeThumbprint(thumbprint)
	out := m.Keys[:0]
	found := false
	for _, e := range m.Keys {
		if NormalizeThumbprint(e.Thumbprint) == tp {
			found = true
			continue
		}
		out = append(out, e)
	}
	if !found {
		return ErrNotInstalled
	}
	m.Keys = out
	return Save(m)
}

func InstalledThumbprints() ([]string, error) {
	m, err := Load()
	if err != nil {
		return nil, err
	}
	out := make([]string, len(m.Keys))
	for i, e := range m.Keys {
		out[i] = NormalizeThumbprint(e.Thumbprint)
	}
	return out, nil
}

func EnsureDir() error {
	return os.MkdirAll(filepath.Dir(kspcommon.ManifestPath()), 0o755)
}
