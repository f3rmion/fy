# Frosty (fy) - FROST implementation on BabyJubJub elliptic curve

fy is a Go library implementing the FROST (Flexible round-optimized Schnorr threshold) signature scheme with a curve-agnostic design. It includes a BabyJubJub elliptic curve example implementation. 

# Structure

Top-level packages are entry points to public APIs that become importable.

```bash
fy/
├── group/        # Interface definition (Curve, Point, Scalar interfaces)
├── bjj/          # BabyJubJub implementation of group.Group interface
├── frost/        # FROST protocol (depends on group.Group)
├── internal/     # Private helpers
├── go.mod
└── go.sum
```

`group/` defines interfaces:
- `Group` - group operations, generator, order
- `Point` - add, scalar mult, serialize
- `Scalar` - field arithmetic, serialize

`bjj/` adapter: `gnark-crypto` -> `group.Group`

`frost/` accepts a `group.Group` in its constructor, never imports implementation directly.

`internal/` used for private helper functions.

