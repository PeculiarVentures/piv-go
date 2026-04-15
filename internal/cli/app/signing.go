package app

import "github.com/PeculiarVentures/piv-go/adapters"

func shouldPromptPINForSign(policy adapters.SignAuthorization, explicitPIN bool) bool {
	if explicitPIN {
		return true
	}
	if !policy.IsKnown() {
		return true
	}
	return policy.RequiresPIN()
}
