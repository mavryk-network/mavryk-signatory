package integrationtest

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAWSVault(t *testing.T) {

	mv2 := os.Getenv("VAULT_AWS_MV2")
	mv3 := os.Getenv("VAULT_AWS_MV3")
	tz3pk := os.Getenv("VAULT_AWS_MV3_PK")
	user := os.Getenv("VAULT_AWS_USER")
	key := os.Getenv("VAULT_AWS_KEY")
	secret := os.Getenv("VAULT_AWS_SECRET")
	region := os.Getenv("VAULT_AWS_REGION")

	tz2alias := "awstz2"
	tz3alias := "awstz3"

	//config
	var c Config
	c.Read()
	var v VaultConfig
	v.Driver = "awskms"
	v.Conf = map[string]interface{}{"user_name": &user, "access_key_id": &key, "secret_access_key": &secret, "region": &region}
	c.Vaults["aws"] = &v
	var p MavrykPolicy
	p.LogPayloads = true
	p.Allow = map[string][]string{"generic": {"reveal", "transaction"}}
	c.Mavryk[mv2] = &p
	c.Mavryk[mv3] = &p
	backup_then_update_config(c)
	defer restore_config()
	restart_signatory()

	//setup
	out, err := MavkitClient("import", "secret", "key", tz2alias, "http://signatory:6732/"+mv2)
	assert.NoError(t, err)
	assert.Contains(t, string(out), "Mavryk address added: "+mv2)
	defer MavkitClient("forget", "address", tz2alias, "--force")

	out, err = MavkitClient("import", "secret", "key", tz3alias, "http://signatory:6732/"+mv3)
	assert.NoError(t, err)
	assert.Contains(t, string(out), "Mavryk address added: "+mv3)
	defer MavkitClient("forget", "address", tz3alias, "--force")

	out, err = MavkitClient("transfer", "100", "from", "alice", "to", tz2alias, "--burn-cap", "0.06425")
	assert.NoError(t, err)
	require.Contains(t, string(out), "Operation successfully injected in the node")

	out, err = MavkitClient("transfer", "100", "from", "alice", "to", tz3alias, "--burn-cap", "0.06425")
	assert.NoError(t, err)
	require.Contains(t, string(out), "Operation successfully injected in the node")

	//test
	//TODO: resolve issue #364 and enable the mv2 test
	//out, err = MavkitClient("transfer", "1", "from", tz2alias, "to", "alice", "--burn-cap", "0.06425")
	//assert.NoError(t, err)
	//require.Contains(t, string(out), "Operation successfully injected in the node")

	out, err = MavkitClient("transfer", "1", "from", tz3alias, "to", "alice", "--burn-cap", "0.06425")
	assert.NoError(t, err)
	require.Contains(t, string(out), "Operation successfully injected in the node")

	require.Equal(t, tz3pk, GetPublicKey(mv3))
}
