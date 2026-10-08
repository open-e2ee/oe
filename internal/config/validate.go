package config

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/santhosh-tekuri/jsonschema/v6/kind"
	"golang.org/x/text/language"
	"golang.org/x/text/message"

	"github.com/open-e2ee/oe/schema"
)

var configSchema = func() *jsonschema.Schema {
	document, err := jsonschema.UnmarshalJSON(bytes.NewReader(schema.ConfigV2))
	if err != nil {
		panic(err)
	}
	compiler := jsonschema.NewCompiler()
	const url = "config-v2.json"
	if err := compiler.AddResource(url, document); err != nil {
		panic(err)
	}
	return compiler.MustCompile(url)
}()

// managedMaximum is the longest retention that each environment allows.
var managedMaximum = map[string]string{"sandbox": "7d", "production": "30d"}

// validate checks value against schema/config-v2.json and the managed
// maximums, and returns it as a Config.
func validate(value any) (Config, error) {
	var fields []FieldError
	if err := configSchema.Validate(value); err != nil {
		failure, ok := errors.AsType[*jsonschema.ValidationError](err)
		if !ok {
			return Config{}, err
		}
		fields = schemaErrors(failure, message.NewPrinter(language.English))
	}
	// A shared policy that leaves out relayReceipts keeps Relay delivery
	// receipts on.
	result := Config{Relay: RelayPolicy{RelayReceipts: true}}
	if len(fields) == 0 {
		encoded, err := json.Marshal(value)
		if err != nil {
			return Config{}, err
		}
		if err := json.Unmarshal(encoded, &result); err != nil {
			return Config{}, err
		}
		for _, environment := range []string{"sandbox", "production"} {
			policy, err := result.RelayPolicyFor(environment)
			if err != nil {
				continue
			}
			maximum := managedMaximum[environment]
			for _, field := range []struct{ name, value string }{
				{"deliveryRetention", policy.DeliveryRetention},
				{"attachmentRetention", policy.AttachmentRetention},
			} {
				if retentionSeconds[field.value] > retentionSeconds[maximum] {
					fields = append(fields, FieldError{
						Path:    "environments." + environment + ".relay." + field.name,
						Message: fmt.Sprintf("is %s, longer than the %s maximum of %s", field.value, environment, maximum),
					})
				}
			}
		}
	}
	if len(fields) == 0 {
		return result, nil
	}
	slices.SortFunc(fields, func(a, b FieldError) int {
		return cmp.Or(strings.Compare(a.Path, b.Path), strings.Compare(a.Message, b.Message))
	})
	details := make([]string, len(fields))
	for index, field := range fields {
		details[index] = cmp.Or(field.Path, "the default export") + " " + field.Message
	}
	return Config{}, &Error{
		Code:    "CONFIG_INVALID",
		Message: fmt.Sprintf("%s is not valid: %s", Filename, strings.Join(details, "; ")),
		Data:    map[string]any{"errors": fields},
	}
}

// schemaErrors returns one FieldError for each leaf of the validation error.
// A missing or unknown property is reported at its own path, not at the
// object that holds it.
func schemaErrors(failure *jsonschema.ValidationError, printer *message.Printer) []FieldError {
	if len(failure.Causes) > 0 {
		var fields []FieldError
		for _, cause := range failure.Causes {
			fields = append(fields, schemaErrors(cause, printer)...)
		}
		return fields
	}
	location := strings.Join(failure.InstanceLocation, ".")
	child := func(name string) string {
		if location == "" {
			return name
		}
		return location + "." + name
	}
	switch reason := failure.ErrorKind.(type) {
	case *kind.Required:
		fields := make([]FieldError, len(reason.Missing))
		for index, name := range reason.Missing {
			fields[index] = FieldError{Path: child(name), Message: "is required"}
		}
		return fields
	case *kind.AdditionalProperties:
		fields := make([]FieldError, len(reason.Properties))
		for index, name := range reason.Properties {
			fields[index] = FieldError{Path: child(name), Message: "is not allowed"}
		}
		return fields
	}
	return []FieldError{{Path: location, Message: "is not valid: " + failure.ErrorKind.LocalizedString(printer)}}
}
