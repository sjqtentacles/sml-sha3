# sml-sha3

Keccak-f[1600] sponge, SHA3-224/256/384/512, SHAKE128/SHAKE256 XOF, and KMAC in pure Standard ML

## Installation

```
smlpkg add github.com/sjqtentacles/sml-sha3
smlpkg sync
```

## Usage

```sml
(* SHA3-256 digest *)
val hex = Sha3.hex256 "hello"
(* => "3338be694f50c5f338814986cdf0686453a888b84f424d792af4b9202398f392" *)

val raw = Sha3.digest256 "hello"   (* 32-byte binary string *)

(* Other variants *)
val h224 = Sha3.hex224 "abc"
val h384 = Sha3.hex384 "abc"
val h512 = Sha3.hex512 "abc"

(* SHAKE XOF — variable output length *)
val out32 = Shake128.xof "data" 32   (* 32 bytes *)
val out64 = Shake256.xof "data" 64   (* 64 bytes *)

(* KMAC (keyed MAC, SP 800-185) *)
val mac = Kmac128.mac {key = "secret", data = "msg", out = 32, custom = ""}
```

## Testing

```
make test       # MLton
make test-poly  # Poly/ML
```

## License

MIT
