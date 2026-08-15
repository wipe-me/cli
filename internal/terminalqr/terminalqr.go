// Package terminalqr renders private links as compact terminal QR codes.
package terminalqr

import (
	"io"

	qrterminal "github.com/mdp/qrterminal/v3"
)

// Write prints value as a compact QR code using two vertical modules per cell.
// The renderer deliberately uses the terminal's foreground and background
// colors instead of forcing an ANSI palette. Inverted output swaps the module
// glyphs for terminals with the opposite background color.
func Write(writer io.Writer, value string, inverted bool) error {
	config := qrterminal.Config{
		Level:      qrterminal.M,
		Writer:     writer,
		HalfBlocks: true,
		QuietZone:  qrterminal.QUIET_ZONE,
	}
	if inverted {
		config.BlackChar = qrterminal.WHITE_WHITE
		config.BlackWhiteChar = qrterminal.WHITE_BLACK
		config.WhiteChar = qrterminal.BLACK_BLACK
		config.WhiteBlackChar = qrterminal.BLACK_WHITE
	}
	qrterminal.GenerateWithConfig(value, config)
	return nil
}

// WriteBig prints value using qrterminal's full-size two-column module renderer.
func WriteBig(writer io.Writer, value string, inverted bool) error {
	config := qrterminal.Config{
		Level:     qrterminal.M,
		Writer:    writer,
		BlackChar: qrterminal.BLACK,
		WhiteChar: qrterminal.WHITE,
		QuietZone: qrterminal.QUIET_ZONE,
	}
	if inverted {
		config.BlackChar = qrterminal.WHITE
		config.WhiteChar = qrterminal.BLACK
	}
	qrterminal.GenerateWithConfig(value, config)
	return nil
}
