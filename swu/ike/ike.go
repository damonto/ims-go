package ike

const (
	Version20                 byte   = ikeVersion20
	ExchangeTypeIKESAInit     byte   = exchangeTypeIKESAInit
	ExchangeTypeIKEAuth       byte   = exchangeTypeIKEAuth
	ExchangeTypeInformational byte   = exchangeTypeInformational
	FlagInitiator             byte   = flagInitiator
	FlagResponse              byte   = flagResponse
	TransformENCRAESCBC       uint16 = transformENCRAESCBC
	TransformPRFHMACMD5       uint16 = transformPRFHMACMD5
	TransformPRFHMACSHA1      uint16 = transformPRFHMACSHA1
	TransformPRFHMACSHA256    uint16 = transformPRFHMACSHA256
	TransformINTEGHMACMD596   uint16 = transformINTEGHMACMD596
	TransformINTEGHMACSHA196  uint16 = transformINTEGHMACSHA196
	TransformINTEGHMACSHA256  uint16 = transformINTEGHMACSHA256
	TransformDH1024MODP       uint16 = transformDH1024MODP
	TransformDH2048MODP       uint16 = transformDH2048MODP
)
