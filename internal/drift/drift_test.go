package drift

import (
	"reflect"
	"testing"
)

func TestCompare(t *testing.T) {
	image := []Package{
		{Name: "bash", Version: "5.2", Type: "deb"},
		{Name: "openssl", Version: "3.0.1", Type: "deb"},
		{Name: "curl", Version: "8.0", Type: "deb"},
		{Name: "pip", Version: "25.0.1", Type: "python"},
	}
	runtime := []Package{
		{Name: "bash", Version: "5.2", Type: "deb"},
		{Name: "openssl", Version: "3.0.2", Type: "deb"},
		{Name: "pip", Version: "25.0.1", Type: "python"},
		{Name: "requests", Version: "2.34.2", Type: "python"},
		{Name: "urllib3", Version: "2.8.0", Type: "python"},
	}

	got := Compare(image, runtime)

	want := Report{
		Added: []Package{
			{Name: "requests", Version: "2.34.2", Type: "python"},
			{Name: "urllib3", Version: "2.8.0", Type: "python"},
		},
		Removed: []Package{{Name: "curl", Version: "8.0", Type: "deb"}},
		Changed: []Change{{Name: "openssl", Type: "deb", FromVersion: "3.0.1", ToVersion: "3.0.2"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
}

func TestCompareIdentical(t *testing.T) {
	ps := []Package{{Name: "bash", Version: "5.2", Type: "deb"}}
	if r := Compare(ps, ps); !r.Empty() {
		t.Fatalf("expected no drift, got %+v", r)
	}
}
