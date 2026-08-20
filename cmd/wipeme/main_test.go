package main

import "testing"

func TestDevelopmentVersionTracksNextRelease(t *testing.T) {
	if version != "0.3.0-alpha.3-dev" {
		t.Fatalf("unexpected development version %q", version)
	}
}
