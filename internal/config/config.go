// Package config loads and validates botguard's runtime configuration.
package config

import (
	"errors"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the top-level YAML config.
type Config struct {
	Log struct {
		Path         string `yaml:"path"`          // path to Caddy access log (JSON lines)
		PollInterval string `yaml:"poll_interval"` // fallback poll if fsnotify is unavailable, e.g. "200ms"
	} `yaml:"log"`

	Cache struct {
		Path string `yaml:"path"` // path to SQLite db file
		TTL  struct {
			Allow    string `yaml:"allow"`
			Deny     string `yaml:"deny"`
			Neutral  string `yaml:"neutral"`
			NXDomain string `yaml:"nxdomain"`
			Error    string `yaml:"error"`
		} `yaml:"ttl"`
		BlockRetention string `yaml:"block_retention"` // how long an IP stays in blocked.caddy
	} `yaml:"cache"`

	Resolver struct {
		Workers     int      `yaml:"workers"`
		Timeout     string   `yaml:"timeout"`
		Servers     []string `yaml:"servers"` // optional explicit DNS servers ("1.1.1.1:53")
		MaxInFlight int      `yaml:"max_in_flight"`
	} `yaml:"resolver"`

	Caddy struct {
		AdminURL       string `yaml:"admin_url"`    // e.g. http://caddy:2019
		Caddyfile      string `yaml:"caddyfile"`    // path inside container
		SnippetPath    string `yaml:"snippet_path"` // path of generated blocked.caddy
		ReloadDebounce string `yaml:"reload_debounce"`
		ReloadCommand  string `yaml:"reload_command"` // optional shell cmd, default "caddy reload"
		// ConfigPath, when set, switches the reload to PATCH /config/<path>
		// with the current IP list as a JSON array, replacing only that node
		// in the running config instead of re-loading the whole Caddyfile.
		// Example: "/id/botguard_blocked/match/0/remote_ip/ranges".
		ConfigPath string `yaml:"config_path"`
	} `yaml:"caddy"`

	Server struct {
		Listen    string `yaml:"listen"` // e.g. :8088 (empty disables)
		BasicAuth struct {
			User string `yaml:"user"`
			Pass string `yaml:"pass"`
		} `yaml:"basic_auth"`
	} `yaml:"server"`

	Rules struct {
		Path string `yaml:"path"` // path to rules.yaml
	} `yaml:"rules"`
}

// Durations carries parsed durations next to a Config (lazy fill).
type Durations struct {
	PollInterval    time.Duration
	TTLAllow        time.Duration
	TTLDeny         time.Duration
	TTLNeutral      time.Duration
	TTLNXDomain     time.Duration
	TTLError        time.Duration
	BlockRetention  time.Duration
	ResolverTimeout time.Duration
	ReloadDebounce  time.Duration
}

// Defaults returns a Config populated with reasonable defaults.
func Defaults() *Config {
	c := &Config{}
	c.Log.Path = "/var/log/caddy/access.log"
	c.Log.PollInterval = "250ms"

	c.Cache.Path = "/var/lib/botguard/botguard.db"
	c.Cache.TTL.Allow = "168h" // 7 days
	c.Cache.TTL.Deny = "720h"  // 30 days
	c.Cache.TTL.Neutral = "168h"
	c.Cache.TTL.NXDomain = "1h"
	c.Cache.TTL.Error = "5m"
	c.Cache.BlockRetention = "2160h" // 90 days

	c.Resolver.Workers = 8
	c.Resolver.Timeout = "3s"
	c.Resolver.MaxInFlight = 64

	c.Caddy.AdminURL = "http://caddy:2019"
	c.Caddy.Caddyfile = "/etc/caddy/Caddyfile"
	c.Caddy.SnippetPath = "/etc/caddy/dynamic/blocked.caddy"
	c.Caddy.ReloadDebounce = "30s"
	c.Caddy.ReloadCommand = ""

	c.Rules.Path = "/etc/botguard/rules.yaml"
	c.Server.Listen = ""
	return c
}

// Load merges defaults with values from path (if it exists).
func Load(path string) (*Config, *Durations, error) {
	cfg := Defaults()
	if path != "" {
		raw, err := os.ReadFile(path)
		if err == nil {
			if err := yaml.Unmarshal(raw, cfg); err != nil {
				return nil, nil, fmt.Errorf("parse %s: %w", path, err)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, nil, fmt.Errorf("read %s: %w", path, err)
		}
	}
	d, err := parseDurations(cfg)
	if err != nil {
		return nil, nil, err
	}
	return cfg, d, nil
}

func parseDurations(c *Config) (*Durations, error) {
	parse := func(name, v string) (time.Duration, error) {
		if v == "" {
			return 0, nil
		}
		d, err := time.ParseDuration(v)
		if err != nil {
			return 0, fmt.Errorf("invalid duration %s=%q: %w", name, v, err)
		}
		return d, nil
	}
	d := &Durations{}
	var err error
	if d.PollInterval, err = parse("log.poll_interval", c.Log.PollInterval); err != nil {
		return nil, err
	}
	if d.TTLAllow, err = parse("cache.ttl.allow", c.Cache.TTL.Allow); err != nil {
		return nil, err
	}
	if d.TTLDeny, err = parse("cache.ttl.deny", c.Cache.TTL.Deny); err != nil {
		return nil, err
	}
	if d.TTLNeutral, err = parse("cache.ttl.neutral", c.Cache.TTL.Neutral); err != nil {
		return nil, err
	}
	if d.TTLNXDomain, err = parse("cache.ttl.nxdomain", c.Cache.TTL.NXDomain); err != nil {
		return nil, err
	}
	if d.TTLError, err = parse("cache.ttl.error", c.Cache.TTL.Error); err != nil {
		return nil, err
	}
	if d.BlockRetention, err = parse("cache.block_retention", c.Cache.BlockRetention); err != nil {
		return nil, err
	}
	if d.ResolverTimeout, err = parse("resolver.timeout", c.Resolver.Timeout); err != nil {
		return nil, err
	}
	if d.ReloadDebounce, err = parse("caddy.reload_debounce", c.Caddy.ReloadDebounce); err != nil {
		return nil, err
	}
	return d, nil
}
