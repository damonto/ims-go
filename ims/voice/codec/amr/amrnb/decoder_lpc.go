package amrnb

import "fmt"

func (s *decoderCoreState) decodeMR122LPC(params []int16, badFrame bool) (int, error) {
	var decoded decodedPLSF5
	if badFrame {
		decoded = s.lsfState.conceal5()
	} else {
		if len(params) < 5 {
			return 0, fmt.Errorf("AMR-NB MR122 LPC parameter count %d, want at least 5", len(params))
		}
		var err error
		decoded, err = s.lsfState.decode5(params[:5])
		if err != nil {
			return 0, err
		}
	}

	s.az = interpolateLPC1And3(s.lspOld[:], decoded.lsp1[:], decoded.lsp2[:])
	s.lspOld = decoded.lsp2
	return 5, nil
}

func (s *decoderCoreState) decodeLPC3(mode Mode, params []int16, badFrame bool) (int, error) {
	var lspNew [lpcOrder]int16
	var err error
	if badFrame {
		lspNew, err = s.lsfState.conceal3(mode)
	} else {
		if len(params) < 3 {
			return 0, fmt.Errorf("AMR-NB LPC parameter count %d, want at least 3", len(params))
		}
		lspNew, err = s.lsfState.decode3(mode, params[:3])
	}
	if err != nil {
		return 0, err
	}

	s.az = interpolateLPC1To3(s.lspOld[:], lspNew[:])
	s.lspOld = lspNew
	return 3, nil
}
