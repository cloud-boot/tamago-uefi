// Stub for `runNetstackPingProbe` when the
// `phase2_netstack_ping` build tag is NOT set or the binary
// is not built for tamago.
//
// Matches the shape of the M2 / M1.6 / M1.5 stubs: a no-op
// function the dispatcher (phase2_dispatch.go) can call
// unconditionally. Avoids `#ifdef`-style call-site noise.
//
// The `phase2_dispatch.go` file's build constraint includes
// `phase2_netstack_ping`, so this stub is the resolution when
// some OTHER probe tag (e.g. `phase2_blkprintk`) is on but
// `phase2_netstack_ping` is off.

//go:build !phase2_netstack_ping || !tamago

package main

// runNetstackPingProbe is a no-op in any build that doesn't
// have `phase2_netstack_ping` set (or isn't a tamago build).
func runNetstackPingProbe() {}
