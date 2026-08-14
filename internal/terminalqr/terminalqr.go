// Package terminalqr renders private links as compact terminal QR codes.
package terminalqr

import (
	"fmt"
	"io"

	qrcode "github.com/skip2/go-qrcode"
)

const quietZone = 4

const (
	reset         = "\x1b[0m"
	darkPair      = "\x1b[40m"
	lightPair     = "\x1b[107m"
	darkOverLight = "\x1b[30;107m"
	lightOverDark = "\x1b[97;40m"
)

// Write prints value as a compact QR code using two vertical modules per cell.
// Inverted output uses light modules on a dark background.
func Write(writer io.Writer, value string, inverted bool) error {
	code, err := qrcode.New(value, qrcode.Medium)
	if err != nil {
		return fmt.Errorf("generate QR code: %w", err)
	}
	code.DisableBorder = true
	bitmap := code.Bitmap()
	if len(bitmap) == 0 {
		return fmt.Errorf("generate QR code: empty bitmap")
	}

	size := len(bitmap) + 2*quietZone
	for y := 0; y < size; y += 2 {
		lastStyle := ""
		for x := 0; x < size; x++ {
			top := module(bitmap, x-quietZone, y-quietZone, inverted)
			bottom := module(bitmap, x-quietZone, y+1-quietZone, inverted)
			style, glyph := cell(top, bottom)
			if style != lastStyle {
				if _, err := io.WriteString(writer, style); err != nil {
					return err
				}
				lastStyle = style
			}
			if _, err := io.WriteString(writer, glyph); err != nil {
				return err
			}
		}
		if _, err := io.WriteString(writer, reset+"\n"); err != nil {
			return err
		}
	}
	return nil
}

func module(bitmap [][]bool, x, y int, inverted bool) bool {
	dark := y >= 0 && y < len(bitmap) && x >= 0 && x < len(bitmap[y]) && bitmap[y][x]
	if inverted {
		return !dark
	}
	return dark
}

func cell(top, bottom bool) (style, glyph string) {
	switch {
	case top && bottom:
		return darkPair, " "
	case !top && !bottom:
		return lightPair, " "
	case top:
		return darkOverLight, "▀"
	default:
		return lightOverDark, "▀"
	}
}
