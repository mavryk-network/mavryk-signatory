package ledger

import (
	"encoding/hex"

	"github.com/mavryk-network/mavryk-signatory/pkg/mavryk"
	"github.com/mavryk-network/mavryk-signatory/pkg/vault/ledger/mavrykapp"
)

// Utility functions used by CLI

func SetupBaking(id, keyID, chainID string, mainHWM, testHWM uint32) (pkh string, err error) {
	var hwm mavrykapp.HWM
	if chainID != "" {
		hwm.ChainID, err = mavryk.DecodeChainID(chainID)
		if err != nil {
			return
		}
	}
	key, err := parseKeyID(keyID)
	if err != nil {
		return
	}
	dev, err := deviceScanner.open(id)
	if err != nil {
		return
	}
	defer dev.Close()

	pub, err := dev.SetupBaking(&hwm, key.dt, key.path)
	if err != nil {
		return
	}
	pkh, err = mavryk.EncodePublicKeyHash(pub)
	if err != nil {
		return
	}

	return pkh, nil
}

func DeauthorizeBaking(id string) error {
	dev, err := deviceScanner.open(id)
	if err != nil {
		return err
	}
	defer dev.Close()
	err = dev.DeauthorizeBaking()
	if err != nil {
		return err
	}
	return nil
}

func SetHighWatermark(id string, hwm uint32) error {
	dev, err := deviceScanner.open(id)
	if err != nil {
		return err
	}
	defer dev.Close()
	return dev.SetHighWatermark(hwm)
}

func GetHighWatermark(id string) (hwm uint32, err error) {
	dev, err := deviceScanner.open(id)
	if err != nil {
		return
	}
	defer dev.Close()
	return dev.GetHighWatermark()
}

func GetHighWatermarks(id string) (mainHWM, testHWM uint32, chainID string, err error) {
	dev, err := deviceScanner.open(id)
	if err != nil {
		return
	}
	defer dev.Close()
	hwm, err := dev.GetHighWatermarks()
	if err != nil {
		return
	}
	return hwm.Main, hwm.Test, hex.EncodeToString(hwm.ChainID[:]), nil
}
