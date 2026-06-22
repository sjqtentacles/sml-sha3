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

(* Hex codec — inverse of the hex*/​*Hex output (round-trips with toHex). *)
val raw' = Hex.fromHex (Sha3.hex256 "abc")   (* SOME (Sha3.digest256 "abc") *)
val same = Hex.toHex (Sha3.digest256 "abc")  (* = Sha3.hex256 "abc"         *)
```

## Example

`make example` builds and runs [`examples/demo.sml`](examples/demo.sml), which
hashes fixed FIPS 202 / SP 800-185 inputs with the SHA-3 family, SHAKE XOFs, and
KMAC, printing lowercase hex digests:

```
$ make example
SHA-3 digests of "abc" (FIPS 202):
  SHA3-224 = e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf
  SHA3-256 = 3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532
  SHA3-384 = ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25
  SHA3-512 = b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0

SHA3-256 of the empty string (FIPS 202):
  SHA3-256("") = a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a

SHAKE XOF output of "abc" (32 bytes):
  SHAKE128 = 5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8
  SHAKE256 = 483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739

KMAC128 (NIST SP 800-185 Sample #1):
  mac = e5780b0d3ea6f7d3a429c5706aa43a00fadbd7d49628839e3187243f456ee14e
```

## Testing

```
make test       # MLton
make test-poly  # Poly/ML
make example    # build + run the demo
```

## License

MIT
