package artifact

import (
	"errors"
	"reflect"
	"testing"

	"github.com/EdwinJdevops/kube-release-envelope/internal/manifest"
)

const (
	apiImage   = "registry.example.com/payments/api@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	initImage  = "registry.example.com/platform/migrate@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	debugImage = "registry.example.com/platform/debug@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

func canonical(t *testing.T, documents ...string) []byte {
	t.Helper()
	inputs := make([][]byte, len(documents))
	for i := range documents {
		inputs[i] = []byte(documents[i])
	}
	result, err := manifest.CanonicalizeSet(inputs...)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestExtractPinnedReferencesCoversAllContainerClasses(t *testing.T) {
	set := canonical(t,
		`{"apiVersion":"v1","kind":"Service","metadata":{"name":"api","namespace":"payments"},"spec":{"selector":{"app":"api"}}}`,
		`{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"api","namespace":"payments"},"spec":{"template":{"spec":{"containers":[{"name":"api","image":"`+apiImage+`"},{"name":"sidecar","image":"`+apiImage+`"}],"initContainers":[{"name":"migrate","image":"`+initImage+`"}],"ephemeralContainers":[{"name":"debug","image":"`+debugImage+`"}]}}}}`,
	)
	want := []string{apiImage, debugImage, initImage}
	references, err := ExtractPinnedReferences(set)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(references, want) {
		t.Fatalf("ExtractPinnedReferences() = %#v, want %#v", references, want)
	}
}

func TestExtractPinnedReferencesSupportsWorkloadPaths(t *testing.T) {
	for _, test := range []struct {
		name, document string
	}{
		{"pod", `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"api"},"spec":{"containers":[{"name":"api","image":"` + apiImage + `"}]}}`},
		{"deployment", `{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"api"},"spec":{"template":{"spec":{"containers":[{"name":"api","image":"` + apiImage + `"}]}}}}`},
		{"statefulset", `{"apiVersion":"apps/v1","kind":"StatefulSet","metadata":{"name":"api"},"spec":{"template":{"spec":{"containers":[{"name":"api","image":"` + apiImage + `"}]}}}}`},
		{"daemonset", `{"apiVersion":"apps/v1","kind":"DaemonSet","metadata":{"name":"api"},"spec":{"template":{"spec":{"containers":[{"name":"api","image":"` + apiImage + `"}]}}}}`},
		{"replicaset", `{"apiVersion":"apps/v1","kind":"ReplicaSet","metadata":{"name":"api"},"spec":{"template":{"spec":{"containers":[{"name":"api","image":"` + apiImage + `"}]}}}}`},
		{"job", `{"apiVersion":"batch/v1","kind":"Job","metadata":{"name":"api"},"spec":{"template":{"spec":{"containers":[{"name":"api","image":"` + apiImage + `"}]}}}}`},
		{"cronjob", `{"apiVersion":"batch/v1","kind":"CronJob","metadata":{"name":"api"},"spec":{"jobTemplate":{"spec":{"template":{"spec":{"containers":[{"name":"api","image":"` + apiImage + `"}]}}}}}}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			references, err := ExtractPinnedReferences(canonical(t, test.document))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(references, []string{apiImage}) {
				t.Fatalf("got %#v", references)
			}
		})
	}
}

func TestValidatePinnedReferenceRejectsAmbiguousOrMutableForms(t *testing.T) {
	for _, reference := range []string{
		"busybox", "busybox:latest", "busybox@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"registry.example.com/app:stable@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"registry.example.com/App@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"registry.example.com/app@sha512:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"registry.example.com/app@sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	} {
		if err := ValidatePinnedReference(reference); !errors.Is(err, ErrInvalidReference) {
			t.Errorf("ValidatePinnedReference(%q) error = %v", reference, err)
		}
	}
}

func TestExtractPinnedReferencesFailsClosed(t *testing.T) {
	tests := []struct {
		name, document string
		want           error
	}{
		{"mutable tag", `{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"api"},"spec":{"template":{"spec":{"containers":[{"name":"api","image":"registry.example.com/payments/api:latest"}]}}}}`, ErrInvalidReference},
		{"missing sidecar image", `{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"api"},"spec":{"template":{"spec":{"containers":[{"name":"api","image":"` + apiImage + `"},{"name":"sidecar"}]}}}}`, ErrInvalidWorkload},
		{"unknown custom workload", `{"apiVersion":"example.com/v1","kind":"Worker","metadata":{"name":"api"},"spec":{"image":"` + apiImage + `"}}`, ErrUnsupportedKind},
		{"malformed workload", `{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"api"},"spec":{}}`, ErrInvalidWorkload},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ExtractPinnedReferences(canonical(t, test.document))
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}
