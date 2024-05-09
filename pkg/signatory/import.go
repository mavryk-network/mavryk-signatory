package signatory

import (
	"context"
	"fmt"

	"github.com/mavryk-network/mavryk-signatory/pkg/mavryk"
	"github.com/mavryk-network/mavryk-signatory/pkg/utils"
	"github.com/mavryk-network/mavryk-signatory/pkg/vault"
	log "github.com/sirupsen/logrus"
)

// Import a keyPair inside the vault
func (s *Signatory) Import(ctx context.Context, importerName string, secretKey string, passCB mavryk.PassphraseFunc, opt utils.Options) (*PublicKey, error) {
	v, ok := s.vaults[importerName]
	if !ok {
		return nil, fmt.Errorf("import: vault %s is not found", importerName)
	}

	importer, ok := v.(vault.Importer)
	if !ok {
		return nil, fmt.Errorf("import: vault %s doesn't support import operation", importerName)
	}

	pk, err := mavryk.ParsePrivateKey(secretKey, passCB)
	if err != nil {
		return nil, err
	}

	pub := pk.Public()

	hash, err := mavryk.EncodePublicKeyHash(pub)
	if err != nil {
		return nil, err
	}

	l := s.logger().WithFields(log.Fields{
		logPKH:   hash,
		logVault: importer.Name(),
	})
	if n, ok := importer.(vault.VaultNamer); ok {
		l = l.WithField(logVaultName, n.VaultName())
	} else {
		l = l.WithField(logVaultName, importerName)
	}

	l.Info("Requesting import operation")

	stored, err := importer.Import(ctx, pk, opt)
	if err != nil {
		return nil, err
	}

	s.cache.push(hash, &keyVaultPair{key: stored, vault: importer})

	l.WithField(logKeyID, stored.ID()).Info("Successfully imported")

	enc, err := mavryk.EncodePublicKey(pub)
	if err != nil {
		return nil, err
	}

	return &PublicKey{
		PublicKey:     enc,
		PublicKeyHash: hash,
		VaultName:     importer.Name(),
		ID:            stored.ID(),
		Policy:        s.fetchPolicyOrDefault(hash),
	}, nil
}
