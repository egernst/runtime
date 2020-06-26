package ccgroups

import (
	"os"
	"testing"
)

func TestIsSystemd(t *testing.T) {

	tests := []struct {
		name           string
		path           string
		expectedResult bool
	}{
		{
			"empty, should be false",
			"",
			false,
		},
		{
			"Invalid slice",
			"audrey/wants/a/pizza/slice",
			false,
		},
		{
			"Valid slice",
			"../../../thing.slice",
			true,
		},
		{
			"cgroupfs, not a valid slice",
			"/docker/kata_foobar",
			false,
		},
	}
	for _, tt := range tests {
		res := isSystemd(tt.path)
		if res != tt.expectedResult {
			t.Errorf("test %s failed: result = %v, expected %v", tt.name, res, tt.expectedResult)
		}
	}
}

func Test_DeleteCgroup(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Test intended for non-root tests only")
	}
	tests := []struct {
		name        string
		path        string
		expectedErr bool
	}{
		{
			"try to remove somethign that wasn't there",
			"/docker/kata_foobar",
			true,
		},
	}

	for _, tt := range tests {
		err := DeleteCgroup(tt.path)
		if err != nil && !tt.expectedErr {
			t.Errorf("Test %s failed. Unexpected error: %v", tt.name, err)
		}
	}

}

func TestNew_noroot(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("Test intended for non-root tests only")
	}
	tests := []struct {
		name      string
		path      string
		expectErr bool
	}{
		{
			"cgroupfs: should get permission denied",
			"/docker/kata_foobar",
			true,
		},
		{
			"systemd: should get permission denied",
			"kata.slice",
			true,
		},
	}
	for _, tt := range tests {
		err := New(tt.path)
		if err != nil && !tt.expectErr {
			t.Errorf("Test: %s: Unexpected error: %v", tt.name, err)
		}
		if err == nil && tt.expectErr {
			t.Errorf("Test: %s: Error expected", tt.name)
		}
	}
}

func TestNew(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Test must be run as root - skipping")
	}
	tests := []struct {
		name      string
		path      string
		expectErr bool
	}{
		{
			"cgroupfs: should get permission denied",
			"/docker/kata_foobar",
			false,
		},
		{
			"systemd: should get permission denied",
			"kata.slice",
			false,
		},
	}
	for _, tt := range tests {
		err := New(tt.path)
		if err != nil && !tt.expectErr {
			t.Errorf("Test: %s: Unexpected error: %v", tt.name, err)
		}
		if err == nil && tt.expectErr {
			t.Errorf("Test: %s: Error expected", tt.name)
		}

		// successfully created. Let's clean up after ourselves. This is expected to pass.
		// If it does not, someone needs to get the mop out and cleanup
		err = DeleteCgroup(tt.path)
		if err != nil {
			t.Errorf("Deletion of %s failed! Cleanup necessary", tt.path)
		}
	}
}
