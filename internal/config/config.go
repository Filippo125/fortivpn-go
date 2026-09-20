// Package config loads and resolves the user-facing fortivpn configuration.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const maxConfigSize = 1 << 20

// Config is the effective configuration after resolving global, group and
// instance settings. Command-line flags may override these values afterwards.
type Config struct {
	Gateway   string
	Port      int
	Realm     string
	Username  string
	Password  string
	PSK       string
	SAML      bool
	IPMode    string
	Browser   string
	Timeout   time.Duration
	Insecure  bool
	Protocol  string
	RemoteID  string
	Transport string
	TCPPort   int
	Socket    string
}

// File is the structured representation used by JSON and YAML files.
type File struct {
	Globals   Globals          `json:"globals,omitempty" yaml:"globals,omitempty"`
	Groups    map[string]Group `json:"groups,omitempty" yaml:"groups,omitempty"`
	Instances []Instance       `json:"instances" yaml:"instances"`
}

type Globals struct {
	Insecure  *bool     `json:"insecure,omitempty" yaml:"insecure,omitempty"`
	IPMode    *string   `json:"ip_mode,omitempty" yaml:"ip_mode,omitempty"`
	Timeout   *Duration `json:"timeout,omitempty" yaml:"timeout,omitempty"`
	Browser   *string   `json:"browser,omitempty" yaml:"browser,omitempty"`
	Username  *string   `json:"username,omitempty" yaml:"username,omitempty"`
	Password  *string   `json:"password,omitempty" yaml:"password,omitempty"`
	PSK       *string   `json:"psk,omitempty" yaml:"psk,omitempty"`
	Protocol  *string   `json:"protocol,omitempty" yaml:"protocol,omitempty"`
	RemoteID  *string   `json:"remote_id,omitempty" yaml:"remote_id,omitempty"`
	Transport *string   `json:"transport,omitempty" yaml:"transport,omitempty"`
	TCPPort   *int      `json:"tcp_port,omitempty" yaml:"tcp_port,omitempty"`
	Socket    *string   `json:"socket,omitempty" yaml:"socket,omitempty"`
}

type Group struct {
	Globals `json:",inline" yaml:",inline"`
	SAML    *bool `json:"saml,omitempty" yaml:"saml,omitempty"`
}

type Instance struct {
	Name          string `json:"name" yaml:"name"`
	Group         string `json:"group,omitempty" yaml:"group,omitempty"`
	Gateway       string `json:"gateway" yaml:"gateway"`
	Port          *int   `json:"port,omitempty" yaml:"port,omitempty"`
	Realm         string `json:"realm,omitempty" yaml:"realm,omitempty"`
	GroupSettings `json:",inline" yaml:",inline"`
}

type GroupSettings struct {
	Globals `json:",inline" yaml:",inline"`
	SAML    *bool `json:"saml,omitempty" yaml:"saml,omitempty"`
}

// Duration accepts Go duration strings such as "30s" and "5m".
type Duration time.Duration

func (d *Duration) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return fmt.Errorf("must be a duration string: %w", err)
	}
	return d.parse(value)
}

func (d *Duration) UnmarshalYAML(value *yaml.Node) error { return d.parse(value.Value) }

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

func (d Duration) MarshalYAML() (any, error) {
	return time.Duration(d).String(), nil
}

func (d *Duration) parse(value string) error {
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed <= 0 {
		return fmt.Errorf("must be a duration greater than zero")
	}
	*d = Duration(parsed)
	return nil
}

// Load resolves a JSON or YAML configuration. instance uses the canonical
// "group/instance" form. A single instance is selected automatically.
func Load(path string, instance ...string) (Config, error) {
	file, info, err := loadFile(path)
	if err != nil {
		return Config{}, err
	}
	selected := ""
	if len(instance) > 0 {
		selected = instance[0]
	}

	return resolve(path, info, file, selected)
}

// InstanceSelectors returns the canonical selectors available in path. It is
// used by shell completion and deliberately returns no configuration values.
func InstanceSelectors(path string) ([]string, error) {
	file, info, err := loadFile(path)
	if err != nil {
		return nil, err
	}
	if err := validateFile(path, info, file); err != nil {
		return nil, err
	}
	selectors := make([]string, 0, len(file.Instances))
	for _, instance := range file.Instances {
		selectors = append(selectors, selector(instance.Group, instance.Name))
	}
	sort.Strings(selectors)
	return selectors, nil
}

// AddInstance validates and atomically appends an instance to path. The file
// remains in its original JSON or YAML format.
func AddInstance(path string, instance Instance) error {
	file, info, err := loadFile(path)
	if err != nil {
		return err
	}
	if hasSecrets(file) && info.Mode().Perm()&0o077 != 0 {
		return passwordPermissionsError(path)
	}
	file.Instances = append(file.Instances, instance)
	if err := validateStructure(path, file); err != nil {
		return err
	}

	var data []byte
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		data, err = json.MarshalIndent(file, "", "  ")
	case ".yaml", ".yml":
		data, err = yaml.Marshal(file)
	}
	if err != nil {
		return fmt.Errorf("encode config %q: %w", path, err)
	}
	data = append(bytes.TrimRight(data, "\n"), '\n')
	mode := info.Mode().Perm()
	if hasSecrets(file) {
		mode = 0o600
	}
	return atomicWrite(path, data, mode)
}

// ParseInstanceSelector splits the canonical "group/instance" selector.
// A selector without a slash represents an ungrouped instance.
func ParseInstanceSelector(value string) (group, instance string, err error) {
	if strings.Count(value, "/") > 1 {
		return "", "", fmt.Errorf("invalid instance selector %q: use group/instance", value)
	}
	group, instance, qualified := strings.Cut(value, "/")
	if !qualified {
		instance = group
		group = ""
	}
	if strings.TrimSpace(instance) == "" || qualified && strings.TrimSpace(group) == "" {
		return "", "", fmt.Errorf("invalid instance selector %q: use group/instance", value)
	}
	return group, instance, nil
}

func loadFile(path string) (File, os.FileInfo, error) {
	data, info, err := read(path)
	if err != nil {
		return File{}, nil, err
	}
	var file File
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&file); err != nil {
			return File{}, nil, fmt.Errorf("parse config %q as JSON: %w", path, err)
		}
		if err := ensureJSONEOF(decoder); err != nil {
			return File{}, nil, fmt.Errorf("parse config %q as JSON: %w", path, err)
		}
	case ".yaml", ".yml":
		decoder := yaml.NewDecoder(bytes.NewReader(data))
		decoder.KnownFields(true)
		if err := decoder.Decode(&file); err != nil {
			return File{}, nil, fmt.Errorf("parse config %q as YAML: %w", path, err)
		}
	default:
		return File{}, nil, fmt.Errorf("unsupported config format %q: use .json, .yaml, or .yml", filepath.Ext(path))
	}
	return file, info, nil
}

func read(path string) ([]byte, os.FileInfo, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open config %q: %w", path, err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxConfigSize+1))
	if err != nil {
		return nil, nil, fmt.Errorf("read config %q: %w", path, err)
	}
	if len(data) > maxConfigSize {
		return nil, nil, fmt.Errorf("config %q exceeds %d bytes", path, maxConfigSize)
	}
	info, err := file.Stat()
	if err != nil {
		return nil, nil, fmt.Errorf("stat config %q: %w", path, err)
	}
	return data, info, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("contains more than one JSON value")
		}
		return err
	}
	return nil
}

func resolve(path string, info os.FileInfo, file File, selected string) (Config, error) {
	if err := validateFile(path, info, file); err != nil {
		return Config{}, err
	}
	if selected == "" {
		if len(file.Instances) != 1 {
			return Config{}, fmt.Errorf("config %q contains multiple instances; select one with --instance", path)
		}
		selected = selector(file.Instances[0].Group, file.Instances[0].Name)
	}
	current, found := findInstance(file.Instances, selected)
	if !found {
		return Config{}, fmt.Errorf("config %q has no instance %q", path, selected)
	}

	var cfg Config
	applyGlobals(&cfg, file.Globals)
	if current.Group != "" {
		group, ok := file.Groups[current.Group]
		if !ok {
			return Config{}, fmt.Errorf("instance %q references unknown group %q", current.Name, current.Group)
		}
		applyGlobals(&cfg, group.Globals)
		applyBool(&cfg.SAML, group.SAML)
	}
	applyGlobals(&cfg, current.Globals)
	applyBool(&cfg.SAML, current.SAML)
	cfg.Gateway = current.Gateway
	cfg.Realm = current.Realm
	if current.Port != nil {
		cfg.Port = *current.Port
		if cfg.Port < 1 || cfg.Port > 65535 {
			return Config{}, fmt.Errorf("instance %q port must be between 1 and 65535", current.Name)
		}
	}
	if err := validateIPMode(cfg.IPMode); err != nil {
		return Config{}, fmt.Errorf("instance %q: %w", current.Name, err)
	}
	if cfg.Protocol != "" && cfg.Protocol != "sslvpn" && cfg.Protocol != "ipsec" {
		return Config{}, fmt.Errorf("instance %q: protocol %q must be sslvpn or ipsec", current.Name, cfg.Protocol)
	}
	if cfg.Transport != "" && cfg.Transport != "udp" && cfg.Transport != "tcp" {
		return Config{}, fmt.Errorf("instance %q: transport %q must be udp or tcp", current.Name, cfg.Transport)
	}
	if cfg.TCPPort != 0 && cfg.Transport != "tcp" {
		return Config{}, fmt.Errorf("instance %q: tcp_port requires transport tcp", current.Name)
	}
	return cfg, nil
}

func validateFile(path string, info os.FileInfo, file File) error {
	if hasSecrets(file) && info.Mode().Perm()&0o077 != 0 {
		return passwordPermissionsError(path)
	}
	return validateStructure(path, file)
}

func validateStructure(path string, file File) error {
	if len(file.Instances) == 0 {
		return fmt.Errorf("config %q must contain at least one instance", path)
	}
	if file.Globals.IPMode != nil {
		if err := validateIPMode(*file.Globals.IPMode); err != nil {
			return fmt.Errorf("globals: %w", err)
		}
	}
	if file.Globals.Timeout != nil && time.Duration(*file.Globals.Timeout) <= 0 {
		return fmt.Errorf("globals: timeout must be greater than zero")
	}
	if err := validateConnectionSettings("globals", file.Globals); err != nil {
		return err
	}
	for name, group := range file.Groups {
		if strings.TrimSpace(name) == "" || strings.Contains(name, "/") {
			return fmt.Errorf("group names must be non-empty and must not contain a slash")
		}
		if group.IPMode != nil {
			if err := validateIPMode(*group.IPMode); err != nil {
				return fmt.Errorf("group %q: %w", name, err)
			}
		}
		if group.Timeout != nil && time.Duration(*group.Timeout) <= 0 {
			return fmt.Errorf("group %q: timeout must be greater than zero", name)
		}
		if err := validateConnectionSettings(fmt.Sprintf("group %q", name), group.Globals); err != nil {
			return err
		}
	}
	seen := make(map[string]struct{}, len(file.Instances))
	for _, current := range file.Instances {
		if strings.TrimSpace(current.Name) == "" {
			return fmt.Errorf("config %q contains an instance without a name", path)
		}
		if strings.Contains(current.Name, "/") || strings.Contains(current.Group, "/") {
			return fmt.Errorf("instance and group names must not contain a slash")
		}
		if current.Group != "" {
			if _, ok := file.Groups[current.Group]; !ok {
				return fmt.Errorf("instance %q references unknown group %q", current.Name, current.Group)
			}
		}
		key := selector(current.Group, current.Name)
		if _, exists := seen[key]; exists {
			return fmt.Errorf("config %q contains duplicate instance %q", path, key)
		}
		seen[key] = struct{}{}
		if current.Port != nil && (*current.Port < 1 || *current.Port > 65535) {
			return fmt.Errorf("instance %q port must be between 1 and 65535", key)
		}
		if current.IPMode != nil {
			if err := validateIPMode(*current.IPMode); err != nil {
				return fmt.Errorf("instance %q: %w", key, err)
			}
		}
		if current.Timeout != nil && time.Duration(*current.Timeout) <= 0 {
			return fmt.Errorf("instance %q: timeout must be greater than zero", key)
		}
		if err := validateConnectionSettings(fmt.Sprintf("instance %q", key), current.Globals); err != nil {
			return err
		}
	}
	return nil
}

func atomicWrite(path string, data []byte, mode os.FileMode) (err error) {
	linkInfo, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect config %q: %w", path, err)
	}
	if linkInfo.Mode()&os.ModeSymlink != 0 || !linkInfo.Mode().IsRegular() {
		return fmt.Errorf("config %q must be a regular file", path)
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".fortivpn-config-*")
	if err != nil {
		return fmt.Errorf("create temporary config beside %q: %w", path, err)
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		if err != nil {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err = temporary.Chmod(mode); err != nil {
		return fmt.Errorf("set temporary config permissions: %w", err)
	}
	if _, err = temporary.Write(data); err != nil {
		return fmt.Errorf("write temporary config: %w", err)
	}
	if err = temporary.Sync(); err != nil {
		return fmt.Errorf("sync temporary config: %w", err)
	}
	if err = temporary.Close(); err != nil {
		return fmt.Errorf("close temporary config: %w", err)
	}
	if err = os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace config %q: %w", path, err)
	}
	return nil
}

func findInstance(instances []Instance, selected string) (Instance, bool) {
	for _, current := range instances {
		if selector(current.Group, current.Name) == selected {
			return current, true
		}
	}
	return Instance{}, false
}

func selector(group, instance string) string {
	if group == "" {
		return instance
	}
	return group + "/" + instance
}

func hasSecrets(file File) bool {
	if containsSecret(file.Globals) {
		return true
	}
	for _, group := range file.Groups {
		if containsSecret(group.Globals) {
			return true
		}
	}
	for _, instance := range file.Instances {
		if containsSecret(instance.Globals) {
			return true
		}
	}
	return false
}

func containsSecret(values Globals) bool {
	return values.Password != nil && *values.Password != "" || values.PSK != nil && *values.PSK != ""
}

func applyGlobals(cfg *Config, values Globals) {
	applyBool(&cfg.Insecure, values.Insecure)
	if values.IPMode != nil {
		cfg.IPMode = *values.IPMode
	}
	if values.Timeout != nil {
		cfg.Timeout = time.Duration(*values.Timeout)
	}
	if values.Browser != nil {
		cfg.Browser = *values.Browser
	}
	if values.Username != nil {
		cfg.Username = *values.Username
	}
	if values.Password != nil {
		cfg.Password = *values.Password
	}
	if values.PSK != nil {
		cfg.PSK = *values.PSK
	}
	if values.Protocol != nil {
		cfg.Protocol = strings.ToLower(strings.TrimSpace(*values.Protocol))
	}
	if values.RemoteID != nil {
		cfg.RemoteID = *values.RemoteID
	}
	if values.Transport != nil {
		cfg.Transport = strings.ToLower(strings.TrimSpace(*values.Transport))
	}
	if values.TCPPort != nil {
		cfg.TCPPort = *values.TCPPort
	}
	if values.Socket != nil {
		cfg.Socket = *values.Socket
	}
}

func applyBool(target *bool, value *bool) {
	if value != nil {
		*target = *value
	}
}

func validateIPMode(value string) error {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "auto", "ipv4", "ipv6", "dual", "dual-stack", "dualstack":
		return nil
	default:
		return fmt.Errorf("ip_mode %q must be auto, ipv4, ipv6, or dual", value)
	}
}

func validateConnectionSettings(scope string, values Globals) error {
	if values.Protocol != nil {
		protocol := strings.ToLower(strings.TrimSpace(*values.Protocol))
		if protocol != "" && protocol != "sslvpn" && protocol != "ipsec" {
			return fmt.Errorf("%s: protocol %q must be sslvpn or ipsec", scope, *values.Protocol)
		}
	}
	if values.Transport != nil {
		transport := strings.ToLower(strings.TrimSpace(*values.Transport))
		if transport != "" && transport != "udp" && transport != "tcp" {
			return fmt.Errorf("%s: transport %q must be udp or tcp", scope, *values.Transport)
		}
	}
	if values.TCPPort != nil && (*values.TCPPort < 1 || *values.TCPPort > 65535) {
		return fmt.Errorf("%s: tcp_port must be between 1 and 65535", scope)
	}
	if values.Socket != nil && *values.Socket != "" && !filepath.IsAbs(*values.Socket) {
		return fmt.Errorf("%s: socket must be an absolute path", scope)
	}
	return nil
}

func passwordPermissionsError(path string) error {
	return fmt.Errorf("config %q contains a password or PSK and must not be readable by group or others (run chmod 600)", path)
}
