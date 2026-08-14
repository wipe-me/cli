package terminalqr

import (
	"bytes"
	"strings"
	"testing"
)

func TestWriteProducesCompactANSIQRCode(t *testing.T) {
	var normal, inverted bytes.Buffer
	const link = "https://wipe.me/1K7-mQ2-xR8#7YW-HMf-k9J-CB7"
	if err := Write(&normal, link, false); err != nil {
		t.Fatal(err)
	}
	if err := Write(&inverted, link, true); err != nil {
		t.Fatal(err)
	}
	if normal.Len() == 0 || !strings.Contains(normal.String(), "\x1b[") || !strings.Contains(normal.String(), "▀") {
		t.Fatalf("expected ANSI half-block QR output, got %q", normal.String())
	}
	if normal.String() == inverted.String() {
		t.Fatal("inverted QR output matches normal output")
	}
	if lines := strings.Count(normal.String(), "\n"); lines < 10 || lines > 30 {
		t.Fatalf("expected compact terminal output, got %d lines", lines)
	}
}

func TestCellCoversEveryModulePair(t *testing.T) {
	tests := []struct {
		top, bottom  bool
		style, glyph string
	}{
		{true, true, darkPair, " "},
		{false, false, lightPair, " "},
		{true, false, darkOverLight, "▀"},
		{false, true, lightOverDark, "▀"},
	}
	for _, test := range tests {
		style, glyph := cell(test.top, test.bottom)
		if style != test.style || glyph != test.glyph {
			t.Fatalf("cell(%v, %v) = %q, %q", test.top, test.bottom, style, glyph)
		}
	}
}
