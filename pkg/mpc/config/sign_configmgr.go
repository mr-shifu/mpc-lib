package config

import (
	"errors"

	comm_cfg "github.com/mr-shifu/mpc-lib/pkg/mpc/common/config"
)

type SignConfigManager struct {
	store comm_cfg.ConfigStore
}

func NewSignConfigManager(store comm_cfg.ConfigStore) comm_cfg.SignConfigManager {
	return &SignConfigManager{
		store: store,
	}
}

func (mgr *SignConfigManager) ImportConfig(config comm_cfg.SignConfig) error {
	cfg, ok := config.(*SignConfig)
	if !ok {
		return errors.New("invalid config type")
	}

	return mgr.store.Import(config.ID(), cfg)
}

func (mgr *SignConfigManager) GetConfig(ID string) (comm_cfg.SignConfig, error) {
	cfg, err := mgr.store.Get(ID)
	if err != nil {
		return nil, err
	}

	kcfg, ok := cfg.(*SignConfig)
	if !ok {
		return nil, errors.New("invalid config type")
	}

	return kcfg, nil
}
