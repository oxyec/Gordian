package state

import (
	"encoding/json"
	"os"
)

// SaveProfile saves the current ScanConfig to a JSON file.
func (s *AppState) SaveProfile(filepath string) error {
	s.mu.RLock()
	configCopy := s.ScanConfig
	s.mu.RUnlock()

	data, err := json.MarshalIndent(configCopy, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath, data, 0644)
}

// LoadProfile loads the ScanConfig from a JSON file.
func (s *AppState) LoadProfile(filepath string) error {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return err
	}

	config := defaultScanConfig()
	if err := json.Unmarshal(data, &config); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.ScanConfig = config
	return nil
}
