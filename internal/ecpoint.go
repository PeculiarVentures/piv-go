package internal

import (
	"crypto/elliptic"
	"fmt"
	"math/big"
)

// EncodeUncompressedPoint encodes an elliptic curve point using the standard
// uncompressed SEC 1 representation.
func EncodeUncompressedPoint(curve elliptic.Curve, x *big.Int, y *big.Int) ([]byte, error) {
	if curve == nil || x == nil || y == nil {
		return nil, fmt.Errorf("internal: curve and point coordinates are required")
	}
	if !curve.IsOnCurve(x, y) {
		return nil, fmt.Errorf("internal: point is not on curve")
	}

	coordinateSize := curveCoordinateSize(curve)
	xBytes := x.Bytes()
	yBytes := y.Bytes()
	if len(xBytes) > coordinateSize || len(yBytes) > coordinateSize {
		return nil, fmt.Errorf("internal: point coordinate exceeds curve size")
	}

	point := make([]byte, 1+2*coordinateSize)
	point[0] = 0x04
	copy(point[1+coordinateSize-len(xBytes):1+coordinateSize], xBytes)
	copy(point[1+2*coordinateSize-len(yBytes):], yBytes)
	return point, nil
}

// MustEncodeUncompressedPoint encodes a fixed elliptic curve point and panics
// if it is invalid.
func MustEncodeUncompressedPoint(curve elliptic.Curve, x *big.Int, y *big.Int) []byte {
	point, err := EncodeUncompressedPoint(curve, x, y)
	if err != nil {
		panic(err)
	}
	return point
}

// DecodeUncompressedPoint decodes an elliptic curve point from the standard
// uncompressed SEC 1 representation.
func DecodeUncompressedPoint(curve elliptic.Curve, point []byte) (*big.Int, *big.Int, error) {
	if curve == nil {
		return nil, nil, fmt.Errorf("internal: curve is required")
	}

	coordinateSize := curveCoordinateSize(curve)
	if len(point) != 1+2*coordinateSize {
		return nil, nil, fmt.Errorf("internal: unexpected point length %d", len(point))
	}
	if point[0] != 0x04 {
		return nil, nil, fmt.Errorf("internal: unsupported EC point format 0x%02X", point[0])
	}

	x := new(big.Int).SetBytes(point[1 : 1+coordinateSize])
	y := new(big.Int).SetBytes(point[1+coordinateSize:])
	if !curve.IsOnCurve(x, y) {
		return nil, nil, fmt.Errorf("internal: point is not on curve")
	}
	return x, y, nil
}

func curveCoordinateSize(curve elliptic.Curve) int {
	return (curve.Params().BitSize + 7) / 8
}
