package identityattempt

import (
	"context"
	"os"
	"time"

	"github.com/open-e2ee/oe/internal/identity"
)

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

type Resolution struct {
	disposition identity.ReceiptDisposition
	envelope    Envelope
}

func (v Resolution) Disposition() identity.ReceiptDisposition { return v.disposition }
func (v Resolution) Envelope() (Envelope, error)              { return v.envelope.Clone() }

type permitState struct {
	expected                      Envelope
	action                        Action
	preparation, consumed, joined bool
	callContext                   context.Context
	cancel                        context.CancelFunc
	stopLease                     func() bool
}

// Permits contain no serializable or independently consumable authority.
// Consumption state belongs to the lease, so a copied permit cannot repeat it.
type DispatchPermit struct {
	lease *Lease
	token uint64
}
type PreparationPermit struct {
	lease *Lease
	token uint64
}
type DispatchCall struct {
	lease *Lease
	token uint64
}
type PreparationCall struct {
	lease *Lease
	token uint64
}

func (*DispatchPermit) MarshalJSON() ([]byte, error)    { return nil, ErrChanged }
func (*PreparationPermit) MarshalJSON() ([]byte, error) { return nil, ErrChanged }
func (*DispatchCall) MarshalJSON() ([]byte, error)      { return nil, ErrChanged }
func (*PreparationCall) MarshalJSON() ([]byte, error)   { return nil, ErrChanged }

func (l *Lease) guard() error {
	if l == nil || l.closed {
		return ErrChanged
	}
	if l.active {
		return ErrBusy
	}
	if l.ctx.Err() != nil || l.operationContext != nil && l.operationContext.Err() != nil || !time.Now().Before(l.deadline) {
		return ErrTimeout
	}
	return nil
}

func (l *Lease) ioContext() context.Context {
	if l.operationContext != nil {
		return l.operationContext
	}
	return l.ctx
}

func (l *Lease) activateCaller(ctx context.Context) (func(), error) {
	if err := boundedContext(ctx); err != nil {
		return nil, err
	}
	if err := l.guard(); err != nil {
		return nil, err
	}
	operation, cancel := context.WithDeadline(ctx, l.deadline)
	stopLease := context.AfterFunc(l.ctx, cancel)
	l.operationContext = operation
	return func() { stopLease(); cancel(); l.operationContext = nil }, nil
}

func (l *Lease) Read(ctx context.Context) (Envelope, error) {
	if l == nil {
		return Envelope{}, ErrChanged
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	stopOperation, err := l.activateCaller(ctx)
	if err != nil {
		return Envelope{}, err
	}
	defer stopOperation()
	return l.read()
}

func (l *Lease) expected(expected Envelope) (Envelope, error) {
	current, err := l.read()
	if err != nil {
		return Envelope{}, err
	}
	if !current.Equal(expected) {
		return Envelope{}, ErrChanged
	}
	return current, nil
}

func nextRevision(value Envelope) (identity.SafeInteger, error) {
	if value.Validate() != nil {
		return 0, ErrFormat
	}
	if uint64(value.Revision()) >= identity.MaximumSafeInteger {
		return 0, ErrRevisionExhausted
	}
	return value.Revision() + 1, nil
}

func (l *Lease) Retain(ctx context.Context, expected Envelope, attempt Attempt) (Envelope, error) {
	if l == nil {
		return Envelope{}, ErrChanged
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	stopOperation, err := l.activateCaller(ctx)
	if err != nil {
		return Envelope{}, err
	}
	defer stopOperation()
	if l.occupiedCallUsed {
		return Envelope{}, ErrChanged
	}
	current, err := l.expected(expected)
	if err != nil {
		return Envelope{}, err
	}
	old, err := current.RetainedAttempt()
	if err != nil || old != nil {
		return Envelope{}, ErrChanged
	}
	if os.Getenv("OE_OPERATION_ID") != "" {
		return Envelope{}, ErrOperationIDUnretained
	}
	if attempt.Validate() != nil || attempt.Kind() != l.slot.Kind() {
		return Envelope{}, ErrFormat
	}
	if attempt.Kind() == Lifecycle {
		command, _ := attempt.LifecycleCommand()
		if !l.preparationJoined || identity.ValidatePreparedOperationID(command.OperationID) != nil {
			return Envelope{}, ErrContinuationUnsupported
		}
	}
	revision, err := nextRevision(current)
	if err != nil {
		return Envelope{}, err
	}
	value, err := NewOccupiedEnvelope(l.slot, revision, attempt)
	if err != nil {
		return Envelope{}, ErrFormat
	}
	if err := l.commit(value); err != nil {
		return Envelope{}, err
	}
	return value.Clone()
}

func (l *Lease) AppendCancellation(ctx context.Context, expected Envelope, id identity.CancellationOperationID) (Envelope, error) {
	if l == nil {
		return Envelope{}, ErrChanged
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	stopOperation, err := l.activateCaller(ctx)
	if err != nil {
		return Envelope{}, err
	}
	defer stopOperation()
	if l.occupiedCallUsed {
		return Envelope{}, ErrChanged
	}
	current, err := l.expected(expected)
	if err != nil {
		return Envelope{}, err
	}
	attempt, err := current.RetainedAttempt()
	if err != nil || attempt == nil || attempt.Kind() == Lifecycle || id.Validate() != nil {
		return Envelope{}, ErrChanged
	}
	if existing, present := attempt.CancellationID(); present {
		if existing != id {
			return Envelope{}, ErrChanged
		}
		if value := os.Getenv("OE_OPERATION_ID"); value != "" && value != string(existing) {
			return Envelope{}, ErrOperationIDMismatch
		}
		return current.Clone()
	}
	if os.Getenv("OE_OPERATION_ID") != "" {
		return Envelope{}, ErrOperationIDUnretained
	}
	enriched, err := attempt.WithCancellation(id)
	if err != nil {
		return Envelope{}, ErrFormat
	}
	revision, err := nextRevision(current)
	if err != nil {
		return Envelope{}, err
	}
	value, err := NewOccupiedEnvelope(l.slot, revision, enriched)
	if err != nil {
		return Envelope{}, ErrFormat
	}
	if err := l.commit(value); err != nil {
		return Envelope{}, err
	}
	return value.Clone()
}

func actionMatches(action Action, attempt Attempt) bool {
	_, cancellation := attempt.CancellationID()
	switch action {
	case SelectionApplyAction:
		return attempt.Kind() == Selection && !cancellation
	case KeysReplaceAction:
		return attempt.Kind() == KeysOnly && !cancellation
	case SelectionCancelAction:
		return attempt.Kind() == Selection && cancellation
	case KeysCancelAction:
		return attempt.Kind() == KeysOnly && cancellation
	case SelectionStatusAction:
		return attempt.Kind() == Selection
	case KeysStatusAction:
		return attempt.Kind() == KeysOnly
	case LifecycleApplyAction, LifecycleResumeAction, LifecycleStatusAction:
		return attempt.Kind() == Lifecycle
	}
	return false
}

func checkOperationEnvironment(attempt Attempt, action Action) error {
	value := os.Getenv("OE_OPERATION_ID")
	if value == "" {
		return nil
	}
	if action == SelectionCancelAction || action == KeysCancelAction {
		id, present := attempt.CancellationID()
		if !present {
			return ErrOperationIDUnretained
		}
		if value != string(id) {
			return ErrOperationIDMismatch
		}
		return nil
	}
	var original string
	switch attempt.Kind() {
	case Selection:
		command, _ := attempt.SelectionCommand()
		original = string(command.OperationID)
	case KeysOnly:
		command, _ := attempt.KeysCommand()
		original = string(command.OperationID)
	case Lifecycle:
		command, _ := attempt.LifecycleCommand()
		text, scalar := command.OperationID.ScalarString()
		if !scalar {
			return ErrOperationIDMismatch
		}
		original = text
	}
	if original != value {
		return ErrOperationIDMismatch
	}
	return nil
}

func (l *Lease) newPermit(expected Envelope, action Action, preparation bool) (uint64, error) {
	if l.permitSequence == ^uint64(0) {
		return 0, ErrChanged
	}
	l.permitSequence++
	copy, err := expected.Clone()
	if err != nil {
		return 0, ErrFormat
	}
	l.permits[l.permitSequence] = permitState{expected: copy, action: action, preparation: preparation}
	return l.permitSequence, nil
}

func (l *Lease) Confirm(ctx context.Context, expected Envelope, action Action) (*DispatchPermit, error) {
	if l == nil {
		return nil, ErrChanged
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	stopOperation, err := l.activateCaller(ctx)
	if err != nil {
		return nil, err
	}
	defer stopOperation()
	if l.occupiedCallUsed {
		return nil, ErrChanged
	}
	current, err := l.expected(expected)
	if err != nil {
		return nil, err
	}
	attempt, err := current.RetainedAttempt()
	if err != nil || attempt == nil || !actionMatches(action, *attempt) {
		return nil, ErrChanged
	}
	if err := checkOperationEnvironment(*attempt, action); err != nil {
		return nil, err
	}
	if action == LifecycleResumeAction {
		command, _ := attempt.LifecycleCommand()
		if identity.ValidateResumeOperationID(command.OperationID) != nil {
			return nil, ErrContinuationUnsupported
		}
	}
	// Reinstall identical bytes to repeat the complete platform commit barrier.
	// The revision and every original/cancellation field remain unchanged.
	if err := l.namespace.qualifyReady(l.ioContext(), l.observer); err != nil {
		return nil, err
	}
	if err := l.commit(current); err != nil {
		return nil, err
	}
	if err := phase(l.ioContext()); err != nil {
		return nil, err
	}
	token, err := l.newPermit(current, action, false)
	if err != nil {
		return nil, err
	}
	return &DispatchPermit{l, token}, nil
}

func (l *Lease) ConfirmPreparation(ctx context.Context, expected Envelope) (*PreparationPermit, error) {
	if l == nil {
		return nil, ErrChanged
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	stopOperation, err := l.activateCaller(ctx)
	if err != nil {
		return nil, err
	}
	defer stopOperation()
	if l.prepared || l.occupiedCallUsed || l.slot.Kind() != Lifecycle {
		return nil, ErrChanged
	}
	current, err := l.expected(expected)
	if err != nil {
		return nil, err
	}
	attempt, err := current.RetainedAttempt()
	if err != nil || attempt != nil {
		return nil, ErrChanged
	}
	if os.Getenv("OE_OPERATION_ID") != "" {
		return nil, ErrOperationIDUnretained
	}
	if err := l.namespace.qualifyReady(l.ioContext(), l.observer); err != nil {
		return nil, err
	}
	if err := l.commit(current); err != nil {
		return nil, err
	}
	if err := phase(l.ioContext()); err != nil {
		return nil, err
	}
	token, err := l.newPermit(current, "", true)
	if err != nil {
		return nil, err
	}
	l.prepared = true
	return &PreparationPermit{l, token}, nil
}

func (p *DispatchPermit) Begin(ctx context.Context, action Action) (*DispatchCall, error) {
	if p == nil || p.lease == nil {
		return nil, ErrChanged
	}
	if err := p.lease.beginCall(ctx, p.token, action, false); err != nil {
		return nil, err
	}
	return &DispatchCall{p.lease, p.token}, nil
}
func (p *PreparationPermit) Begin(ctx context.Context) (*PreparationCall, error) {
	if p == nil || p.lease == nil {
		return nil, ErrChanged
	}
	if err := p.lease.beginCall(ctx, p.token, "", true); err != nil {
		return nil, err
	}
	return &PreparationCall{p.lease, p.token}, nil
}

func (l *Lease) beginCall(ctx context.Context, token uint64, action Action, preparation bool) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	stopOperation, err := l.activateCaller(ctx)
	if err != nil {
		return err
	}
	defer stopOperation()
	permit, present := l.permits[token]
	if !present || permit.consumed || permit.preparation != preparation || permit.action != action || l.occupiedCallUsed && !preparation {
		return ErrChanged
	}
	current, err := l.expected(permit.expected)
	if err != nil {
		return err
	}
	if !preparation {
		attempt, _ := current.RetainedAttempt()
		if attempt == nil || !actionMatches(action, *attempt) {
			return ErrChanged
		}
		if err := checkOperationEnvironment(*attempt, action); err != nil {
			return err
		}
	} else if os.Getenv("OE_OPERATION_ID") != "" {
		return ErrOperationIDUnretained
	}
	if err := phase(l.ioContext()); err != nil {
		return err
	}
	deadline, _ := ctx.Deadline()
	deadline = minTime(deadline, minTime(l.deadline, time.Now().Add(callLimit)))
	permit.callContext, permit.cancel = context.WithDeadline(ctx, deadline)
	permit.stopLease = context.AfterFunc(l.ctx, permit.cancel)
	permit.consumed = true
	l.permits[token] = permit
	l.active, l.activeToken = true, token
	if !preparation {
		l.occupiedCallUsed = true
	}
	return nil
}

func (l *Lease) callSnapshot(token uint64) (permitState, bool) {
	if l == nil {
		return permitState{}, false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	permit, present := l.permits[token]
	return permit, present && permit.consumed
}

func canceledCallContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}
func (c *DispatchCall) Context() context.Context {
	if c != nil {
		if state, ok := c.lease.callSnapshot(c.token); ok {
			return state.callContext
		}
	}
	return canceledCallContext()
}
func (c *PreparationCall) Context() context.Context {
	if c != nil {
		if state, ok := c.lease.callSnapshot(c.token); ok {
			return state.callContext
		}
	}
	return canceledCallContext()
}
func (c *DispatchCall) Slot() Slot {
	if c != nil {
		if state, ok := c.lease.callSnapshot(c.token); ok {
			return state.expected.Slot()
		}
	}
	return Slot{}
}
func (c *PreparationCall) Slot() Slot {
	if c != nil {
		if state, ok := c.lease.callSnapshot(c.token); ok {
			return state.expected.Slot()
		}
	}
	return Slot{}
}
func (c *DispatchCall) Action() Action {
	if c != nil {
		if state, ok := c.lease.callSnapshot(c.token); ok {
			return state.action
		}
	}
	return ""
}
func (c *DispatchCall) Attempt() (Attempt, error) {
	if c != nil {
		if state, ok := c.lease.callSnapshot(c.token); ok {
			attempt, err := state.expected.RetainedAttempt()
			if err == nil && attempt != nil {
				return attempt.Clone()
			}
		}
	}
	return Attempt{}, ErrChanged
}
func (c *DispatchCall) Join() error {
	if c == nil || c.lease == nil {
		return ErrChanged
	}
	return c.lease.joinCall(c.token)
}
func (c *PreparationCall) Join() error {
	if c == nil || c.lease == nil {
		return ErrChanged
	}
	return c.lease.joinCall(c.token)
}

func (l *Lease) joinCall(token uint64) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	state, present := l.permits[token]
	if !present || !state.consumed {
		return ErrChanged
	}
	if state.joined {
		return nil
	}
	if !l.active || l.activeToken != token {
		return ErrChanged
	}
	callErr := phase(state.callContext)
	state.stopLease()
	state.cancel()
	state.joined = true
	l.permits[token] = state
	l.active = false
	if state.preparation {
		l.preparationJoined = callErr == nil
	}
	if callErr != nil {
		return ErrTimeout
	}
	return nil
}

func cancellationPointer(attempt Attempt) *identity.CancellationOperationID {
	if id, present := attempt.CancellationID(); present {
		return new(id)
	}
	return nil
}

func (l *Lease) resolve(current Envelope, disposition identity.ReceiptDisposition) (Resolution, error) {
	if disposition == identity.ReceiptMismatch {
		return Resolution{}, ErrReceiptMismatch
	}
	if disposition != identity.ReceiptSettled {
		return Resolution{disposition, current}, nil
	}
	revision, err := nextRevision(current)
	if err != nil {
		return Resolution{}, err
	}
	vacant, err := NewVacantEnvelope(l.slot, revision)
	if err != nil {
		return Resolution{}, ErrFormat
	}
	if err := l.commit(vacant); err != nil {
		return Resolution{}, err
	}
	l.occupiedCallUsed = true
	return Resolution{disposition, vacant}, nil
}

func (l *Lease) ResolveSelection(ctx context.Context, expected Envelope, receipt identity.SelectionReceipt) (Resolution, error) {
	if l == nil {
		return Resolution{}, ErrChanged
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	stopOperation, err := l.activateCaller(ctx)
	if err != nil {
		return Resolution{}, err
	}
	defer stopOperation()
	current, err := l.expected(expected)
	if err != nil {
		return Resolution{}, err
	}
	attempt, err := current.RetainedAttempt()
	if err != nil || attempt == nil {
		return Resolution{}, ErrReceiptMismatch
	}
	command, err := attempt.SelectionCommand()
	if err != nil {
		return Resolution{}, ErrReceiptMismatch
	}
	return l.resolve(current, identity.ClassifySelectionReceipt(command, cancellationPointer(*attempt), receipt))
}
func (l *Lease) ResolveKeys(ctx context.Context, expected Envelope, receipt identity.KeysReceipt) (Resolution, error) {
	if l == nil {
		return Resolution{}, ErrChanged
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	stopOperation, err := l.activateCaller(ctx)
	if err != nil {
		return Resolution{}, err
	}
	defer stopOperation()
	current, err := l.expected(expected)
	if err != nil {
		return Resolution{}, err
	}
	attempt, err := current.RetainedAttempt()
	if err != nil || attempt == nil {
		return Resolution{}, ErrReceiptMismatch
	}
	command, err := attempt.KeysCommand()
	if err != nil {
		return Resolution{}, ErrReceiptMismatch
	}
	return l.resolve(current, identity.ClassifyKeysReceipt(command, cancellationPointer(*attempt), receipt))
}
func (l *Lease) ResolveLifecycle(ctx context.Context, expected Envelope, scope identity.Scope, receipt identity.LifecycleReceipt) (Resolution, error) {
	if l == nil {
		return Resolution{}, ErrChanged
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	stopOperation, err := l.activateCaller(ctx)
	if err != nil {
		return Resolution{}, err
	}
	defer stopOperation()
	current, err := l.expected(expected)
	if err != nil {
		return Resolution{}, err
	}
	attempt, err := current.RetainedAttempt()
	if err != nil || attempt == nil {
		return Resolution{}, ErrReceiptMismatch
	}
	command, err := attempt.LifecycleCommand()
	if err != nil {
		return Resolution{}, ErrReceiptMismatch
	}
	if scope.Validate() != nil || scope.EnvironmentKind != l.slot.Environment() {
		return Resolution{}, ErrReceiptMismatch
	}
	return l.resolve(current, identity.ClassifyLifecycleReceipt(command, scope, receipt))
}
