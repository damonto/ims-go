package tunnel

import "fmt"

const (
	ikeNonceMinLen = 16
	ikeNonceMaxLen = 256
)

func validateNonceData(action string, data []byte) error {
	if len(data) < ikeNonceMinLen || len(data) > ikeNonceMaxLen {
		return fmt.Errorf("%s: invalid nonce length %d", action, len(data))
	}
	return nil
}
