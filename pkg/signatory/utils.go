package signatory

import "github.com/mavryk-network/mavryk-signatory/pkg/mavryk"

func SignRequestAuthenticatedBytes(req *SignRequest) ([]byte, error) {
	keyHashBytes, err := mavryk.EncodeBinaryPublicKeyHash(req.PublicKeyHash)
	if err != nil {
		return nil, err
	}
	data := make([]byte, 2+len(req.Message)+len(keyHashBytes))
	data[0] = 4
	data[1] = 1
	copy(data[2:], keyHashBytes)
	copy(data[2+len(keyHashBytes):], req.Message)
	return data, nil
}
