// Package manifest canonicalizes pre-admission Kubernetes object intents.
package manifest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

var (
	ErrNonCanonicalSet = errors.New("manifest set is not canonical")
	ErrDuplicateField  = errors.New("duplicate JSON field")
	ErrDuplicateObject = errors.New("duplicate Kubernetes object identity")
	ErrGeneratedName   = errors.New("generateName is not supported")
	ErrMissingIdentity = errors.New("Kubernetes object identity is incomplete")
	ErrNonJSONObject   = errors.New("manifest must be a JSON object")
	ErrNoManifests     = errors.New("manifest set is empty")
)

type object struct {
	identity  string
	canonical []byte
}

// CanonicalizeSet returns a JSON array containing each input object in stable
// Kubernetes identity order. Inputs are strict JSON, not YAML. The output
// represents client intent before API defaulting or mutating admission.
func CanonicalizeSet(documents ...[]byte) ([]byte, error) {
	if len(documents) == 0 {
		return nil, ErrNoManifests
	}

	objects := make([]object, 0, len(documents))
	seen := make(map[string]struct{}, len(documents))
	for i, document := range documents {
		value, err := decodeStrict(document)
		if err != nil {
			return nil, fmt.Errorf("manifest %d: %w", i, err)
		}
		mapping, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("manifest %d: %w", i, ErrNonJSONObject)
		}

		identity, err := objectIdentity(mapping)
		if err != nil {
			return nil, fmt.Errorf("manifest %d: %w", i, err)
		}
		if _, ok := seen[identity]; ok {
			return nil, fmt.Errorf("manifest %d: %w: %s", i, ErrDuplicateObject, printableIdentity(identity))
		}
		seen[identity] = struct{}{}

		canonical, err := json.Marshal(mapping)
		if err != nil {
			return nil, fmt.Errorf("manifest %d: canonical JSON: %w", i, err)
		}
		objects = append(objects, object{identity: identity, canonical: canonical})
	}

	sort.Slice(objects, func(i, j int) bool { return objects[i].identity < objects[j].identity })
	var output bytes.Buffer
	output.WriteByte('[')
	for i, object := range objects {
		if i > 0 {
			output.WriteByte(',')
		}
		output.Write(object.canonical)
	}
	output.WriteByte(']')
	return output.Bytes(), nil
}

// ValidateCanonicalSet rejects bytes that are merely valid JSON but are not the
// exact output of CanonicalizeSet. Verifiers use this before interpreting
// security-relevant fields so the signed digest has one byte representation.
func ValidateCanonicalSet(canonical []byte) error {
	var documents []json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	if err := decoder.Decode(&documents); err != nil {
		return fmt.Errorf("%w: %v", ErrNonCanonicalSet, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("%w: multiple JSON values", ErrNonCanonicalSet)
		}
		return fmt.Errorf("%w: %v", ErrNonCanonicalSet, err)
	}

	inputs := make([][]byte, len(documents))
	for i := range documents {
		inputs[i] = documents[i]
	}
	reencoded, err := CanonicalizeSet(inputs...)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNonCanonicalSet, err)
	}
	if !bytes.Equal(canonical, reencoded) {
		return ErrNonCanonicalSet
	}
	return nil
}

func decodeStrict(document []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.UseNumber()
	value, err := decodeValue(decoder)
	if err != nil {
		return nil, err
	}
	if token, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, fmt.Errorf("unexpected trailing token %v", token)
		}
		return nil, err
	}
	return value, nil
}

func decodeValue(decoder *json.Decoder) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return token, nil
	}

	switch delimiter {
	case '{':
		mapping := make(map[string]any)
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, errors.New("JSON object key is not a string")
			}
			if _, exists := mapping[key]; exists {
				return nil, fmt.Errorf("%w: %q", ErrDuplicateField, key)
			}
			value, err := decodeValue(decoder)
			if err != nil {
				return nil, err
			}
			mapping[key] = value
		}
		if _, err := decoder.Token(); err != nil {
			return nil, err
		}
		return mapping, nil
	case '[':
		var sequence []any
		for decoder.More() {
			value, err := decodeValue(decoder)
			if err != nil {
				return nil, err
			}
			sequence = append(sequence, value)
		}
		if _, err := decoder.Token(); err != nil {
			return nil, err
		}
		return sequence, nil
	default:
		return nil, fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
}

func objectIdentity(mapping map[string]any) (string, error) {
	apiVersion, ok := nonEmptyString(mapping["apiVersion"])
	if !ok {
		return "", ErrMissingIdentity
	}
	kind, ok := nonEmptyString(mapping["kind"])
	if !ok {
		return "", ErrMissingIdentity
	}
	metadata, ok := mapping["metadata"].(map[string]any)
	if !ok {
		return "", ErrMissingIdentity
	}
	if generateName, ok := nonEmptyString(metadata["generateName"]); ok && generateName != "" {
		return "", ErrGeneratedName
	}
	name, ok := nonEmptyString(metadata["name"])
	if !ok {
		return "", ErrMissingIdentity
	}
	namespace := ""
	if rawNamespace, present := metadata["namespace"]; present {
		var valid bool
		namespace, valid = nonEmptyString(rawNamespace)
		if !valid {
			return "", ErrMissingIdentity
		}
	}
	return strings.Join([]string{apiVersion, kind, namespace, name}, "\x00"), nil
}

func nonEmptyString(value any) (string, bool) {
	text, ok := value.(string)
	return text, ok && strings.TrimSpace(text) != ""
}

func printableIdentity(identity string) string {
	return strings.ReplaceAll(identity, "\x00", "/")
}
