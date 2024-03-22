package config

import (
	"errors"
	"sync"

	comm_cfg "github.com/mr-shifu/mpc-lib/pkg/mpc/common/config"
)

type SignConfigManager struct {
	lock    sync.RWMutex
	configs map[string]*SignConfig
}

func NewSignConfigManager() comm_cfg.SignConfigManager {
	return &SignConfigManager{
		configs: make(map[string]*SignConfig),
	}
}

func (scm *SignConfigManager) ImportConfig(config comm_cfg.SignConfig) error {
	scm.lock.Lock()
	defer scm.lock.Unlock()

	cfg, ok := config.(*SignConfig)
	if !ok {
		return errors.New("invalid config type")
	}

	scm.configs[config.ID()] = cfg
	return nil
}

func (scm *SignConfigManager) GetConfig(id string) comm_cfg.SignConfig {
	scm.lock.RLock()
	defer scm.lock.RUnlock()

	return scm.configs[id]
}
