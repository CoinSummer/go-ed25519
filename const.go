/**
 * Created by Goland.
 * Description:
 * User: kailee
 * Date: 2021/5/10 12:38 PM
 */
package ed25519

import "errors"

var (
	ErrUnhardenedElement = errors.New("elements must be hardened")
	hardenedOffset       = uint32(0x80000000)
	EmptyPath            = errors.New("empty derivation path")
	AmbiguousPath        = errors.New("ambiguous path: use 'm/' prefix for absolute paths, or no leading '/' for relative ones")
	PathLenOut           = errors.New("path element cannot be larger than 4294967295")
)

const (
	PublicKeyLength = 32
	MaxSeedLength   = 32
	MaxSeed         = 16
	MaxPathLen      = 4294967295
)
