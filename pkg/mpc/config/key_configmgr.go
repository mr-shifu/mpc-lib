package config

import (
	"errors"

	comm_cfg "github.com/mr-shifu/mpc-lib/pkg/mpc/common/config"
)

type KeyConfigManager struct {
	store comm_cfg.ConfigStore
}

func NewKeyConfigManager(store comm_cfg.ConfigStore) comm_cfg.KeyConfigManager {
	return &KeyConfigManager{
		store: store,
	}
}

func (mgr *KeyConfigManager) ImportConfig(config comm_cfg.KeyConfig) error {
	cfg, ok := config.(*KeyConfig)
	if !ok {
		return errors.New("invalid config type")
	}

	return mgr.store.Import(config.ID(), cfg)
}

func (mgr *KeyConfigManager) GetConfig(ID string) (comm_cfg.KeyConfig, error) {
	cfg, err := mgr.store.Get(ID)
	if err != nil {
		return nil, err
	}

	kcfg, ok := cfg.(*KeyConfig)
	if !ok {
		return nil, errors.New("invalid config type")
	}

	return kcfg, nil
}
