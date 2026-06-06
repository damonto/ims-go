package tunnel

import "fmt"

const (
	ikeNonceMinLen = 16
	ikeNonceMaxLen = 256
)

func validateNonceData(data []byte) error {
	if len(data) < ikeNonceMinLen || len(data) > ikeNonceMaxLen {
		return fmt.Errorf("invalid nonce length %d", len(data))
	}
	return nil
}
