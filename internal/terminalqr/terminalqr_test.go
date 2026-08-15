package terminalqr

import (
	"bytes"
	"image"
	"image/color"
	"strings"
	"testing"

	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
)

func TestWriteProducesCompactQRCodeWithoutForcedANSIColors(t *testing.T) {
	var normal, inverted bytes.Buffer
	const link = "https://wipe.me/1K7-mQ2-xR8#7YW-HMf-k9J-CB7"
	if err := Write(&normal, link, false); err != nil {
		t.Fatal(err)
	}
	if err := Write(&inverted, link, true); err != nil {
		t.Fatal(err)
	}
	if normal.Len() == 0 || !strings.ContainsAny(normal.String(), "█▀▄") {
		t.Fatalf("expected half-block QR output, got %q", normal.String())
	}
	if strings.Contains(normal.String(), "\x1b[") || strings.Contains(inverted.String(), "\x1b[") {
		t.Fatal("terminal QR output forces ANSI colors")
	}
	if normal.String() == inverted.String() {
		t.Fatal("inverted QR output matches normal output")
	}
	if lines := strings.Count(normal.String(), "\n"); lines < 10 || lines > 30 {
		t.Fatalf("expected compact terminal output, got %d lines", lines)
	}
}

func TestWriteIncludesFourModuleQuietZone(t *testing.T) {
	var output bytes.Buffer
	if err := Write(&output, "https://wipe.me/123-456-789#abc-def-ghi-jkm", false); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(output.String(), "\n"), "\n")
	if len(lines) < 5 {
		t.Fatalf("QR output has only %d lines", len(lines))
	}
	blank := strings.Repeat("█", len([]rune(lines[0])))
	if lines[0] != blank || lines[1] != blank {
		t.Fatalf("QR output does not begin with a four-module quiet zone: %q", lines[:2])
	}
}

func TestWriteRoundTripsThroughIndependentDecoder(t *testing.T) {
	const link = "https://wipe.me/1K7-mQ2-xR8#7YW-HMf-k9J-CB7"
	var output bytes.Buffer
	if err := Write(&output, link, false); err != nil {
		t.Fatal(err)
	}

	bitmap, err := gozxing.NewBinaryBitmapFromImage(renderHalfBlocks(t, output.String()))
	if err != nil {
		t.Fatal(err)
	}
	result, err := qrcode.NewQRCodeReader().DecodeWithoutHints(bitmap)
	if err != nil {
		t.Fatalf("decode terminal QR: %v", err)
	}
	if got := result.GetText(); got != link {
		t.Fatalf("decoded %q, want %q", got, link)
	}
}

func renderHalfBlocks(t *testing.T, terminal string) image.Image {
	t.Helper()
	lines := strings.Split(strings.TrimSuffix(terminal, "\n"), "\n")
	width := len([]rune(lines[0]))
	const scale = 8
	img := image.NewGray(image.Rect(0, 0, width*scale, len(lines)*2*scale))
	for i := range img.Pix {
		img.Pix[i] = 0xff
	}
	for y, line := range lines {
		if len([]rune(line)) != width {
			t.Fatalf("QR row %d has inconsistent width", y)
		}
		for x, cell := range []rune(line) {
			var topDark, bottomDark bool
			switch cell {
			case ' ':
				topDark, bottomDark = true, true
			case '█':
			case '▄':
				topDark = true
			case '▀':
				bottomDark = true
			default:
				t.Fatalf("unexpected terminal QR glyph %q", cell)
			}
			for moduleY, dark := range []bool{topDark, bottomDark} {
				if !dark {
					continue
				}
				for py := 0; py < scale; py++ {
					for px := 0; px < scale; px++ {
						img.SetGray(x*scale+px, (y*2+moduleY)*scale+py, color.Gray{})
					}
				}
			}
		}
	}
	return img
}
