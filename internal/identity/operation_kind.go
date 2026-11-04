package identity

// Kind names the server-held identity operation family. Each kind has its own
// operation IDs and its own status and cancel actions.
type Kind string

const (
	Selection Kind = "selection"
	KeysOnly  Kind = "keys-only"
	Lifecycle Kind = "lifecycle"
)

func (v Kind) Validate() error {
	if v != Selection && v != KeysOnly && v != Lifecycle {
		return ErrIdentityValue
	}
	return nil
}

// Action names one identity control call. Status actions only read the server.
type Action string

const (
	SelectionApplyAction  Action = "selection-apply"
	KeysReplaceAction     Action = "keys-replace"
	SelectionCancelAction Action = "selection-cancel"
	KeysCancelAction      Action = "keys-cancel"
	LifecycleApplyAction  Action = "lifecycle-apply"
	LifecycleResumeAction Action = "lifecycle-resume"
	SelectionStatusAction Action = "selection-status"
	KeysStatusAction      Action = "keys-status"
	LifecycleStatusAction Action = "lifecycle-status"
)

// Kind is the operation family of the action, or an empty Kind for an unknown action.
func (v Action) Kind() Kind {
	switch v {
	case SelectionApplyAction, SelectionStatusAction, SelectionCancelAction:
		return Selection
	case KeysReplaceAction, KeysStatusAction, KeysCancelAction:
		return KeysOnly
	case LifecycleApplyAction, LifecycleStatusAction, LifecycleResumeAction:
		return Lifecycle
	}
	return ""
}

// Status reports whether the action only reads the server.
func (v Action) Status() bool {
	return v == SelectionStatusAction || v == KeysStatusAction || v == LifecycleStatusAction
}

// Cancel reports whether the action cancels a selection or keys-only operation.
func (v Action) Cancel() bool {
	return v == SelectionCancelAction || v == KeysCancelAction
}
