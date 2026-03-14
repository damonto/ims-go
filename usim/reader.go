package usim

import usimreader "github.com/damonto/ims-client/usim/reader"

// Keep Reader in the root package so existing callers of usim.Load keep compiling.
type Reader = usimreader.Reader
