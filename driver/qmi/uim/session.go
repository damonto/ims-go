package uim

type Session uint8

const (
	SessionPrimaryGWProvisioning Session = 0

	SessionNonProvisioningSlot1 Session = 4
	SessionNonProvisioningSlot2 Session = 5
	SessionCardSlot1            Session = 6
	SessionCardSlot2            Session = 7

	SessionNonProvisioningSlot3 Session = 16
	SessionNonProvisioningSlot4 Session = 17
	SessionNonProvisioningSlot5 Session = 18
	SessionCardSlot3            Session = 19
	SessionCardSlot4            Session = 20
	SessionCardSlot5            Session = 21
)
