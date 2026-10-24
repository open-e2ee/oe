package identityattempt

import "errors"

// Failure contains a fixed code and no input, native cause, path, or retained value.
type Failure struct{ code string }

func (e *Failure) Code() string { return e.code }
func (e *Failure) Error() string {
	switch e.code {
	case "STORE_LOCATION":
		return "The selected configuration directory is unavailable. Create its missing parent directories with private ownership and permissions before identity-store first use."
	case "STORE_FIRST_USE_REQUIRED":
		return "Explicit identity store first use is required."
	case "STORE_ALREADY_INITIALIZED":
		return "The identity store already has first-use evidence."
	case "STORE_UNCERTAIN":
		return "The identity store has uncertain retained state. Preserve the state."
	case "STORE_UNSAFE":
		return "The identity store security checks failed."
	case "STORE_FORMAT":
		return "The identity store record format is invalid."
	case "STORE_TOO_LARGE":
		return "The identity store record exceeds its storage representation."
	case "STORE_BUSY":
		return "The identity store is busy."
	case "STORE_TIMEOUT":
		return "The identity store operation deadline expired."
	case "STORE_CHANGED":
		return "The retained identity attempt changed."
	case "STORE_REVISION_EXHAUSTED":
		return "The identity store revision cannot advance."
	case "STORE_PERSISTENCE":
		return "The identity store persistence checks failed. Preserve the state."
	case "STORE_RECEIPT_MISMATCH":
		return "The identity receipt does not match the retained attempt."
	case "STORE_RELEASE":
		return "The identity store resource release failed."
	case "IDENTITY_OPERATION_ID_UNRETAINED":
		return "The supplied operation ID has no retained identity context."
	case "IDENTITY_OPERATION_ID_MISMATCH":
		return "The supplied operation ID does not match the retained identity action."
	case "IDENTITY_CONTINUATION_UNSUPPORTED":
		return "The retained identity operation cannot use this continuation."
	default:
		return "The identity store operation failed."
	}
}

var (
	ErrLocation                = &Failure{"STORE_LOCATION"}
	ErrFirstUseRequired        = &Failure{"STORE_FIRST_USE_REQUIRED"}
	ErrAlreadyInitialized      = &Failure{"STORE_ALREADY_INITIALIZED"}
	ErrUncertain               = &Failure{"STORE_UNCERTAIN"}
	ErrUnsafe                  = &Failure{"STORE_UNSAFE"}
	ErrFormat                  = &Failure{"STORE_FORMAT"}
	ErrTooLarge                = &Failure{"STORE_TOO_LARGE"}
	ErrBusy                    = &Failure{"STORE_BUSY"}
	ErrTimeout                 = &Failure{"STORE_TIMEOUT"}
	ErrChanged                 = &Failure{"STORE_CHANGED"}
	ErrRevisionExhausted       = &Failure{"STORE_REVISION_EXHAUSTED"}
	ErrPersistence             = &Failure{"STORE_PERSISTENCE"}
	ErrReceiptMismatch         = &Failure{"STORE_RECEIPT_MISMATCH"}
	ErrRelease                 = &Failure{"STORE_RELEASE"}
	ErrOperationIDUnretained   = &Failure{"IDENTITY_OPERATION_ID_UNRETAINED"}
	ErrOperationIDMismatch     = &Failure{"IDENTITY_OPERATION_ID_MISMATCH"}
	ErrContinuationUnsupported = &Failure{"IDENTITY_CONTINUATION_UNSUPPORTED"}
	errMissing                 = errors.New("private store object absent")
	errExists                  = errors.New("private store object exists")
)

func releaseFile(f closeable) error {
	if f == nil {
		return nil
	}
	if f.Close() != nil {
		return ErrRelease
	}
	return nil
}

type closeable interface{ Close() error }

// A sole absence can become an absence observation. A joined release failure cannot.
func soleMissing(err error) bool { return err == errMissing }

func combine(primary, release error) error {
	if primary == nil {
		return release
	}
	if release == nil {
		return primary
	}
	return errors.Join(primary, release)
}
