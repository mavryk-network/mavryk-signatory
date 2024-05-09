//go:build !integration

package mavryk

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTZKey(t *testing.T) {
	type testCase struct {
		priv string
		pub  string
		hash string
		pass string
	}

	cases := []testCase{
		// p256 unencrypted
		{
			priv: "p2sk35q9MJHLN1SBHNhKq7oho1vnZL28bYfsSKDUrDn2e4XVcp6ohZ",
			pub:  "p2pk64zMPtYav6yiaHV2DhSQ65gbKMr3gkLQtK7TTQCpJEVUhxxEnxo",
			hash: "mv3HZmYPLDjLYmRxv99GyRNHcAmCeVNVMgDR",
		},
		// ed25519 unencrypted
		{
			priv: "edsk4FTF78Qf1m2rykGpHqostAiq5gYW4YZEoGUSWBTJr2njsDHSnd",
			pub:  "edpkv45regue1bWtuHnCgLU8xWKLwa9qRqv4gimgJKro4LSc3C5VjV",
			hash: "mv1949pcbqwGsHfUCaVmNVRu21Cd4SnbpvpP",
		},
		// secp256k1 unencrypted
		{
			priv: "spsk2oTAhiaSywh9ctt8yZLRxL3bo8Mayd3hKFi5iBaoqj2R8bx7ow",
			pub:  "sppk7auhfZa5wAcR8hk3WCw47kHgG3Pp8zaP3ctdAqdDd2dBAeZBof1",
			hash: "mv2h5E4ioj7VJVaQZcKxx4jZGH8wK45EEUxc",
		},
		// p256 encrypted
		{
			priv: "p2esk27ocLPLp1JkTWfxByXysGyB7MBDURYJAzAGJLR3XSEV9Nq8wFFdDVXVTwvCwR7Ne2dcUveamjXbvZf3on6T",
			pub:  "p2pk66vAYU7rN1ckJMp38Z9pXCrkiZCVyi6KyeMwhY69h5WDPHdMecH",
			hash: "mv3CwX4KpwPXcoU9hw4VFtNUpkcadtynsrxB",
			pass: "foo",
		},
		// ed25519 encrypted
		{
			priv: "edesk1uiM6BaysskGto8pRtzKQqFqsy1sea1QRjTzaQYuBxYNhuN6eqEU78TGRXZocsVRJYcN7AaU9JDykwUd8KW",
			pub:  "edpkttVn1coEZNjcjjAF36jDXDB377imNiKCHqjdXSt85eVN779jfX",
			hash: "mv19gsGLshxzWJnZUSZZJuGaPpqFhbqZb755",
			pass: "foo",
		},
		// secp256k1 encrypted
		{
			priv: "spesk246GnDVaqGoYZvKbjrWM1g6xUXnyETXtwZgEYFnP8BQXcaS4rfQQco7C94D1yBmcL1v46Sqy8fXrhBSM7TW",
			pub:  "sppk7aSJpAzeXNTaobig65si221WTqgPh8mJsCJSAiZU7asJkWBVGyx",
			hash: "mv2M7pzvxfyC5mJEr8gVJUG44Aq5HtG6mUQV",
			pass: "foo",
		},
	}

	as := assert.New(t)

	for i, tst := range cases {
		pk, err := ParsePrivateKey(tst.priv, func() ([]byte, error) { return []byte(tst.pass), nil })
		if !as.NoError(err, i) {
			continue
		}

		_, err = ParsePublicKey(tst.pub)
		if !as.NoError(err, i) {
			continue
		}

		pub := pk.Public()
		hash, err := EncodePublicKeyHash(pub)
		if !as.NoError(err) {
			continue
		}

		encPub, err := EncodePublicKey(pub)
		if !as.NoError(err) {
			continue
		}

		as.Equal(encPub, tst.pub)
		as.Equal(hash, tst.hash)
	}
}
