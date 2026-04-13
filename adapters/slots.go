package adapters

import "github.com/PeculiarVentures/piv-go/piv"

// SlotDescription summarizes the observable state of a PIV slot.
type SlotDescription struct {
	KeyPresent   bool
	KeyAlgorithm string
	CertPresent  bool
	CertLabel    string
}

// SlotInspector defines adapter-specific slot inspection behavior.
type SlotInspector interface {
	// DescribeSlot returns the current state of the specified slot.
	DescribeSlot(session *Session, slot piv.Slot) (SlotDescription, error)
}
