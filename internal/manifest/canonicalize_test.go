package manifest

import (
	"bytes"
	"errors"
	"testing"
)

func TestCanonicalizeSetIsIndependentOfFieldAndDocumentOrder(t *testing.T) {
	deploymentA := []byte(`{"kind":"Deployment","apiVersion":"apps/v1","metadata":{"namespace":"payments","name":"api"},"spec":{"replicas":2}}`)
	deploymentB := []byte(`{
		"spec": {"replicas": 2},
		"metadata": {"name": "api", "namespace": "payments"},
		"apiVersion": "apps/v1",
		"kind": "Deployment"
	}`)
	service := []byte(`{"apiVersion":"v1","kind":"Service","metadata":{"name":"api","namespace":"payments"},"spec":{"ports":[{"port":443}]}}`)

	first, err := CanonicalizeSet(deploymentA, service)
	if err != nil {
		t.Fatal(err)
	}
	second, err := CanonicalizeSet(service, deploymentB)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("canonical sets differ:\n%s\n%s", first, second)
	}
}

func TestCanonicalizeSetPreservesArrayOrder(t *testing.T) {
	first, err := CanonicalizeSet([]byte(`{"apiVersion":"v1","kind":"Pod","metadata":{"name":"api"},"spec":{"containers":[{"name":"a"},{"name":"b"}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	second, err := CanonicalizeSet([]byte(`{"apiVersion":"v1","kind":"Pod","metadata":{"name":"api"},"spec":{"containers":[{"name":"b"},{"name":"a"}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("array reordering must change canonical intent")
	}
}

func TestCanonicalizeSetRejectsAmbiguousOrUnboundInput(t *testing.T) {
	tests := []struct {
		name      string
		documents [][]byte
		want      error
	}{
		{name: "empty set", want: ErrNoManifests},
		{name: "YAML", documents: [][]byte{[]byte("apiVersion: v1\nkind: ConfigMap")}},
		{name: "duplicate field", documents: [][]byte{[]byte(`{"apiVersion":"v1","kind":"ConfigMap","kind":"Secret","metadata":{"name":"x"}}`)}, want: ErrDuplicateField},
		{name: "trailing value", documents: [][]byte{[]byte(`{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"x"}} {}`)}},
		{name: "array root", documents: [][]byte{[]byte(`[]`)}, want: ErrNonJSONObject},
		{name: "missing name", documents: [][]byte{[]byte(`{"apiVersion":"v1","kind":"ConfigMap","metadata":{}}`)}, want: ErrMissingIdentity},
		{name: "generateName", documents: [][]byte{[]byte(`{"apiVersion":"v1","kind":"Job","metadata":{"generateName":"job-"}}`)}, want: ErrGeneratedName},
		{name: "invalid namespace", documents: [][]byte{[]byte(`{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"x","namespace":7}}`)}, want: ErrMissingIdentity},
		{name: "duplicate identity", documents: [][]byte{
			[]byte(`{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"x"}}`),
			[]byte(`{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"x"},"data":{"a":"b"}}`),
		}, want: ErrDuplicateObject},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := CanonicalizeSet(test.documents...)
			if err == nil {
				t.Fatal("expected an error")
			}
			if test.want != nil && !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
		})
	}
}

func TestCanonicalizeSetRejectsNestedDuplicateField(t *testing.T) {
	_, err := CanonicalizeSet([]byte(`{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"x"},"data":{"key":"a","key":"b"}}`))
	if !errors.Is(err, ErrDuplicateField) {
		t.Fatalf("got %v, want %v", err, ErrDuplicateField)
	}
}

func TestValidateCanonicalSet(t *testing.T) {
	canonical, err := CanonicalizeSet(
		[]byte(`{"apiVersion":"v1","kind":"Service","metadata":{"name":"api","namespace":"payments"}}`),
		[]byte(`{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"api","namespace":"payments"}}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateCanonicalSet(canonical); err != nil {
		t.Fatalf("ValidateCanonicalSet() error = %v", err)
	}

	for name, input := range map[string][]byte{
		"whitespace":       append([]byte(" "), canonical...),
		"object order":     []byte(`[{"apiVersion":"v1","kind":"Service","metadata":{"name":"api","namespace":"payments"}},{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"api","namespace":"payments"}}]`),
		"not an array":     []byte(`{"apiVersion":"v1","kind":"Service","metadata":{"name":"api"}}`),
		"trailing content": append(append([]byte(nil), canonical...), []byte(` true`)...),
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateCanonicalSet(input); !errors.Is(err, ErrNonCanonicalSet) {
				t.Fatalf("ValidateCanonicalSet() error = %v, want ErrNonCanonicalSet", err)
			}
		})
	}
}
