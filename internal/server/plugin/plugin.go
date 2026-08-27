package plugin

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type PluginType string

const (
	PluginTypeEXE      PluginType = "exe"
	PluginTypeDLL      PluginType = "dll"
	PluginTypeShellcode PluginType = "shellcode"
	PluginTypeBOF      PluginType = "bof"
)

type Plugin struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Type        PluginType `json:"type"`
	Size        int64      `json:"size"`
	Path        string     `json:"path"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

type Manager struct {
	pluginDir string
	plugins   map[string]*Plugin
	mu        sync.RWMutex
}

var (
	manager *Manager
	once    sync.Once
)

func Init(pluginDir string) (*Manager, error) {
	var initErr error
	once.Do(func() {
		if err := os.MkdirAll(pluginDir, 0755); err != nil {
			initErr = fmt.Errorf("failed to create plugin directory: %w", err)
			return
		}
		manager = &Manager{
			pluginDir: pluginDir,
			plugins:   make(map[string]*Plugin),
		}
		initErr = manager.scanPlugins()
	})
	return manager, initErr
}

func GetManager() *Manager {
	return manager
}

func (m *Manager) scanPlugins() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	entries, err := os.ReadDir(m.pluginDir)
	if err != nil {
		return fmt.Errorf("failed to read plugin directory: %w", err)
	}

	m.plugins = make(map[string]*Plugin)

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		pluginType := m.detectPluginType(entry.Name())
		if pluginType == "" {
			continue
		}

		plugin := &Plugin{
			ID:        entry.Name(),
			Name:      entry.Name(),
			Type:      pluginType,
			Size:      info.Size(),
			Path:      filepath.Join(m.pluginDir, entry.Name()),
			CreatedAt: info.ModTime(),
			UpdatedAt: info.ModTime(),
		}

		m.plugins[plugin.ID] = plugin
	}

	return nil
}

func (m *Manager) detectPluginType(filename string) PluginType {
	ext := strings.ToLower(filepath.Ext(filename))
	switch ext {
	case ".exe":
		return PluginTypeEXE
	case ".dll":
		return PluginTypeDLL
	case ".bin", ".raw", ".sc":
		return PluginTypeShellcode
	case ".o", ".obj":
		return PluginTypeBOF
	default:
		return ""
	}
}

func (m *Manager) List() []*Plugin {
	m.mu.RLock()
	defer m.mu.RUnlock()

	plugins := make([]*Plugin, 0, len(m.plugins))
	for _, p := range m.plugins {
		plugins = append(plugins, p)
	}
	return plugins
}

func (m *Manager) Get(id string) (*Plugin, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	plugin, ok := m.plugins[id]
	if !ok {
		return nil, fmt.Errorf("plugin not found: %s", id)
	}
	return plugin, nil
}

func (m *Manager) Add(name string, data []byte, description string) (*Plugin, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	pluginType := m.detectPluginType(name)
	if pluginType == "" {
		return nil, fmt.Errorf("unsupported plugin type: %s", filepath.Ext(name))
	}

	pluginPath := filepath.Join(m.pluginDir, name)
	if err := os.WriteFile(pluginPath, data, 0644); err != nil {
		return nil, fmt.Errorf("failed to write plugin file: %w", err)
	}

	id := strings.TrimSuffix(name, filepath.Ext(name))
	plugin := &Plugin{
		ID:          id,
		Name:        name,
		Description: description,
		Type:        pluginType,
		Size:        int64(len(data)),
		Path:        pluginPath,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	m.plugins[id] = plugin
	return plugin, nil
}

func (m *Manager) Delete(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	plugin, ok := m.plugins[id]
	if !ok {
		return fmt.Errorf("plugin not found: %s", id)
	}

	// If file was already removed manually, just clean up the in-memory entry
	if err := os.Remove(plugin.Path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete plugin file: %w", err)
	}

	delete(m.plugins, id)
	return nil
}

func (m *Manager) ReadPluginData(id string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	plugin, ok := m.plugins[id]
	if !ok {
		return nil, fmt.Errorf("plugin not found: %s", id)
	}

	data, err := os.ReadFile(plugin.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to read plugin file: %w", err)
	}

	return data, nil
}

func (m *Manager) Refresh() error {
	return m.scanPlugins()
}

func (p *Plugin) ToJSON() string {
	data, _ := json.Marshal(p)
	return string(data)
}

func IsValidPluginType(filename string) bool {
	ext := strings.ToLower(filepath.Ext(filename))
	validTypes := []string{".exe", ".dll", ".bin", ".raw", ".sc", ".o", ".obj"}
	for _, t := range validTypes {
		if ext == t {
			return true
		}
	}
	return false
}

func GetPluginTypes() []string {
	return []string{"exe", "dll", "shellcode", "bof"}
}

func (m *Manager) GetPluginInfo() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	counts := make(map[PluginType]int)
	for _, p := range m.plugins {
		counts[p.Type]++
	}

	return map[string]interface{}{
		"total":   len(m.plugins),
		"counts":  counts,
		"types":   GetPluginTypes(),
		"dir":     m.pluginDir,
	}
}

func (m *Manager) WalkPlugins(fn func(path string, d fs.DirEntry, err error) error) error {
	return filepath.WalkDir(m.pluginDir, fn)
}
