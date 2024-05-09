package signatory

import (
	"github.com/mavryk-network/mavryk-signatory/pkg/mavryk"
)

// Watermark tests level against stored high watermark
type Watermark interface {
	IsSafeToSign(pkh string, hash []byte, msg mavryk.UnsignedMessage) error
}

// IgnoreWatermark watermark that do not validation and return true
type IgnoreWatermark struct{}

// IsSafeToSign always return true
func (w IgnoreWatermark) IsSafeToSign(pkh string, hash []byte, msg mavryk.UnsignedMessage) error {
	return nil
}

var _ Watermark = (*IgnoreWatermark)(nil)
