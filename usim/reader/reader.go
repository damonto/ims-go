package reader

import "context"

type Application struct {
	AID   []byte
	Label string
}

type FileRef struct {
	AID  []byte
	Path []byte
}

type FileAttributes struct {
	FileStructure byte
	FileType      byte
	RecordSize    uint16
	RecordCount   uint16
	FileSize      uint16
}

type TransparentRead struct {
	File   FileRef
	Offset uint16
	Length uint16
}

type RecordRead struct {
	File   FileRef
	Record uint16
	Length uint16
}

type AuthenticateRequest struct {
	AID    []byte
	Rand   []byte
	AUTN   []byte
	EAPAKA bool
}

type SMSPPDownloadRequest struct {
	ServiceCenterAddress string
	TPDU                 []byte
}

type SMSPPDownloadResponse struct {
	SW1  byte
	SW2  byte
	Data []byte
}

type Transmitter interface {
	Transmit(ctx context.Context, req []byte) ([]byte, error)
	Close() error
}

type Reader interface {
	ListApplications(ctx context.Context) ([]Application, error)
	FileAttributes(ctx context.Context, file FileRef) (FileAttributes, error)
	ReadTransparent(ctx context.Context, req TransparentRead) ([]byte, error)
	ReadRecord(ctx context.Context, req RecordRead) ([]byte, error)
	Authenticate3G(ctx context.Context, req AuthenticateRequest) ([]byte, error)
	SMSPPDownload(ctx context.Context, req SMSPPDownloadRequest) (SMSPPDownloadResponse, error)
	Close() error
}
