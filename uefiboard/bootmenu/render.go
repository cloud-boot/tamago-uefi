// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Renderer for the boot menu (M9.1).
//
// Renders a *BootConfig as an ASCII-framed interactive menu over a
// byte-stream sink — either a virtio-console (M9.1 production path)
// or a UEFI ConOut io.Writer wrapper (the M9.1 ConOut fallback when
// no virtio-console device is present, e.g. on a runner that didn't
// add `-device virtio-serial-pci -device virtconsole`).
//
// Each call to Render is self-contained: it issues an ANSI cursor-home
// + erase-screen prologue so re-invocations replace the previous
// drawing in place rather than scrolling. The countdown line at the
// bottom updates per-tick (the M9.2 menu loop calls Render once per
// 100 ms while the countdown burns down or the user hits a key).
//
// ASCII-only framing: every UEFI ConOut backend we target renders
// 7-bit ASCII reliably (CHAR16 = UCS-2; ASCII is the trivial first-128
// subset). We intentionally do NOT emit U+2500-range box-drawing
// characters because (a) the UEFI-stub firmware's narrow font often
// lacks them — they render as missing-glyph blocks; (b) the
// virtio-console path goes straight to the host's terminal which
// usually has them, but consistency across both sinks beats prettiness
// on the path that does. The framing uses '+' / '-' / '|' / '>' which
// is universally rendered correctly.
package bootmenu

import (
	"io"
	"strconv"
)

// Renderer renders a BootConfig as an interactive menu over a
// byte-stream sink. Construct one per session; reuse it for every
// Render call so the cursor-home prologue keeps the redraws in place
// rather than scrolling.
type Renderer struct {
	// Out is the byte sink. Typically a *console.VirtioConsole (which
	// satisfies io.Writer via its Write method) when virtio-console is
	// available, or a ConOut wrapper (uefiboard.ConOutWriter) when it
	// isn't.
	Out io.Writer

	// Width is the target line width in columns. Lines longer than
	// Width-4 (leaving room for left + right frame chars) are
	// truncated with a trailing "...". Zero = 80 (the default).
	Width int

	// AsciiOnly forces 7-bit ASCII framing even when AsciiOnly == false
	// could otherwise have used box-drawing characters. We DEFAULT to
	// ASCII (true) for the reasons in the file docstring; the flag is
	// retained so a future tweak (e.g. enable UTF-8 box-drawing on the
	// virtio-console path only) is a one-field change.
	AsciiOnly bool

	// painted is set true after the first Render call. Every frame
	// (including the first) emits the cursor-home + erase-screen
	// prologue so the in-place redraw works on a real terminal AND
	// the menu lands on a clean canvas at first paint.
	painted bool
}

// defaultWidth is the column count we lay the menu out at when
// Renderer.Width is zero. 80 is the universal terminal default and the
// UEFI ConOut narrowest typical mode (80x25).
const defaultWidth = 80

// minWidth is the smallest Width we'll honour without overriding to
// defaultWidth. Below this the truncation logic produces unusable
// output (the trailing "..." consumes more than the available room).
const minWidth = 20

// Render draws the menu state. Re-issuing Render replaces the previous
// drawing in place via ANSI cursor-home + erase-screen.
//
// Layout (Width = 80, ASCII framing):
//
//	+--------------------------------------------------------+
//	| cloud-boot menu                                        |
//	+--------------------------------------------------------+
//	|   alpine-latest                                        |
//	| > rescue                                               |
//	+--------------------------------------------------------+
//	| Auto-boot in 3s -- press any key to stay               |
//	+--------------------------------------------------------+
//
// The selected line is prefixed with "> " (asciiCursor); non-selected
// lines are prefixed with "  ". countdown values <= 0 suppress the
// countdown line entirely (the menu is then in "user-driven; no
// auto-boot" mode — the M9.2 loop sets the deadline 24h ahead on the
// first keystroke).
func (r *Renderer) Render(cfg *BootConfig, selected int, countdown int) error {
	w := r.Width
	if w < minWidth {
		w = defaultWidth
	}
	out := r.Out
	if out == nil {
		return ErrNoSink
	}

	// Compose into a single buffer + one Write call. Keeps the ANSI
	// home/erase + frame atomic on the wire so a slow consumer doesn't
	// observe a half-painted frame (virtio-console chunks per page; a
	// single ~2 KiB menu typically fits in one chunk anyway).
	buf := make([]byte, 0, w*8)

	// ANSI cursor home + erase-in-display (entire screen).
	// "\x1b[H" → cursor to row 1 col 1; "\x1b[2J" → clear screen.
	// Issued on EVERY frame so each Render lands on a clean canvas
	// — the in-place redraw is what makes the countdown tick visibly
	// update without scrolling.
	buf = append(buf, '\x1b', '[', 'H')
	buf = append(buf, '\x1b', '[', '2', 'J')
	if !r.painted {
		// Hide the cursor while we paint so the blinking caret
		// doesn't flicker across the labels. The host TTY restores it
		// on its own at process exit; the UEFI ConOut path ignores the
		// sequence entirely (no functional impact). Only emitted on
		// the very first frame so a reattached terminal doesn't get
		// blasted with hide-cursor sequences.
		buf = append(buf, '\x1b', '[', '?', '2', '5', 'l')
		r.painted = true
	}

	// Resolve title — empty title falls back to the menu's purpose so
	// the user always has a header even if the publisher omitted one.
	title := cfg.Title
	if title == "" {
		title = "cloud-boot"
	}

	buf = appendBorder(buf, w)
	buf = appendTextLine(buf, w, title)
	buf = appendBorder(buf, w)

	// Entries — clamp selected into [0, len-1] defensively so a stale
	// caller value never indexes past the slice.
	sel := selected
	if sel < 0 {
		sel = 0
	}
	if sel >= len(cfg.Entries) {
		sel = len(cfg.Entries) - 1
	}
	for i, e := range cfg.Entries {
		var prefix string
		if i == sel {
			prefix = "> "
		} else {
			prefix = "  "
		}
		buf = appendTextLine(buf, w, prefix+e.Label)
	}

	buf = appendBorder(buf, w)
	if countdown > 0 {
		line := "Auto-boot in " + strconv.Itoa(countdown) + "s -- press any key to stay"
		buf = appendTextLine(buf, w, line)
	} else {
		buf = appendTextLine(buf, w, "Use Up/Down to select; Enter to boot; ESC to halt")
	}
	buf = appendBorder(buf, w)

	if _, err := out.Write(buf); err != nil {
		return err
	}
	return nil
}

// appendBorder appends "+----...----+\n" of `width` columns.
func appendBorder(dst []byte, width int) []byte {
	dst = append(dst, '+')
	for i := 0; i < width-2; i++ {
		dst = append(dst, '-')
	}
	dst = append(dst, '+', '\n')
	return dst
}

// appendTextLine appends "| <text padded to width-4> |\n". Lines
// longer than the inner width are truncated with a "..." trailer.
func appendTextLine(dst []byte, width int, text string) []byte {
	inner := width - 4 // "| " + " |"
	if inner < 4 {
		inner = 4
	}
	if len(text) > inner {
		text = text[:inner-3] + "..."
	}
	dst = append(dst, '|', ' ')
	dst = append(dst, []byte(text)...)
	for i := len(text); i < inner; i++ {
		dst = append(dst, ' ')
	}
	dst = append(dst, ' ', '|', '\n')
	return dst
}

// ErrNoSink is returned by Render when the Renderer.Out field is nil.
// Caller wired the renderer without giving it a sink — a programming
// error rather than a recoverable runtime condition, but surfaced as
// an error so the M9.2 menu loop doesn't panic.
var ErrNoSink = renderErr("bootmenu: Renderer.Out is nil")

// renderErr is the package's tiny sentinel-error type so render.go
// doesn't pull errors into its build closure for one constant.
type renderErr string

// Error implements the error interface.
func (e renderErr) Error() string { return string(e) }
