package main

import "testing"

func TestDevelopmentVersionTracksNextRelease(t *testing.T) {
	if version != "0.2.3-alpha.1-dev" {
		t.Fatalf("unexpected development version %q", version)
	}
}
