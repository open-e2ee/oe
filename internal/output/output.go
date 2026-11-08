package output

import (
	"encoding/json"
	"fmt"
	"io"
)

type Mode string

const (
	Text       Mode = "text"
	JSON       Mode = "json"
	JSONStream Mode = "json-stream"
)

type Event struct {
	Status  string         `json:"status"`
	Command string         `json:"command"`
	Message string         `json:"message,omitempty"`
	Data    map[string]any `json:"data,omitempty"`
	Error   string         `json:"error,omitempty"`
	Code    string         `json:"code,omitempty"`
	Next    string         `json:"next,omitempty"`
	Action  Action         `json:"action,omitzero"`
}

// Problem is a failed command. Code is stable for a caller to switch on, and
// Next names the command that moves the caller forward.
type Problem struct {
	Message string
	Code    string
	Next    string
	Action  Action
	Data    map[string]any
}

// Action is a step that a person must take outside the CLI. Kind is the
// place of the step, such as browser, and Reason is why, such as login.
type Action struct {
	Kind   string `json:"kind,omitempty"`
	URL    string `json:"url"`
	Reason string `json:"reason,omitempty"`
}

type Writer struct {
	mode   Mode
	out    io.Writer
	errOut io.Writer
}

// New writes results to out. A JSON mode also writes failures to out, so each
// run emits parseable documents on one stream. Text mode writes failures to
// errOut.
func New(mode Mode, out, errOut io.Writer) *Writer {
	return &Writer{mode: mode, out: out, errOut: errOut}
}

func (w *Writer) Mode() Mode { return w.mode }

func (w *Writer) Progress(command, message string, data map[string]any) error {
	if w.mode == Text {
		_, err := fmt.Fprintln(w.out, message)
		return err
	}
	if w.mode != JSONStream {
		return nil
	}
	return w.writeJSON(Event{Status: "progress", Command: command, Message: message, Data: data})
}

// Pending writes a step that waits for a person, before the final result.
// Both JSON modes write it to out, so a caller can hand the action to the
// person while the command waits.
func (w *Writer) Pending(command, message string, action Action, data map[string]any) error {
	if w.mode == Text {
		_, err := fmt.Fprintln(w.out, message)
		return err
	}
	return w.writeJSON(Event{Status: "pending", Command: command, Message: message, Data: data, Action: action})
}

// PendingNext writes a pending step that is the result of the run: a person
// must act, and next is the command that continues after the person acts.
// Text mode prints the message, the action URL, and next.
func (w *Writer) PendingNext(command, message, next string, action Action, data map[string]any) error {
	if w.mode == Text {
		if _, err := fmt.Fprintln(w.out, message); err != nil {
			return err
		}
		if action.URL != "" {
			if _, err := fmt.Fprintf(w.out, "action: open %s\n", action.URL); err != nil {
				return err
			}
		}
		if next != "" {
			_, err := fmt.Fprintf(w.out, "next: %s\n", next)
			return err
		}
		return nil
	}
	return w.writeJSON(Event{Status: "pending", Command: command, Message: message, Data: data, Next: next, Action: action})
}

func (w *Writer) Success(command, message string, data map[string]any) error {
	return w.SuccessNext(command, message, "", data)
}

// SuccessNext writes a success whose next names the command that moves the
// caller forward.
func (w *Writer) SuccessNext(command, message, next string, data map[string]any) error {
	if w.mode == Text {
		if _, err := fmt.Fprintln(w.out, message); err != nil {
			return err
		}
		if next != "" {
			_, err := fmt.Fprintf(w.out, "next: %s\n", next)
			return err
		}
		return nil
	}
	return w.writeJSON(Event{Status: "ok", Command: command, Message: message, Data: data, Next: next})
}

func (w *Writer) Failure(command string, problem Problem) error {
	if w.mode == Text {
		if _, err := fmt.Fprintf(w.errOut, "error: %s\n", problem.Message); err != nil {
			return err
		}
		if problem.Action.URL != "" {
			if _, err := fmt.Fprintf(w.errOut, "action: open %s\n", problem.Action.URL); err != nil {
				return err
			}
		}
		if problem.Next != "" {
			_, err := fmt.Fprintf(w.errOut, "next: %s\n", problem.Next)
			return err
		}
		return nil
	}
	return w.writeJSON(Event{
		Status: "error", Command: command, Error: problem.Message,
		Code: problem.Code, Next: problem.Next, Data: problem.Data, Action: problem.Action,
	})
}

func (w *Writer) writeJSON(value Event) error {
	encoder := json.NewEncoder(w.out)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}
