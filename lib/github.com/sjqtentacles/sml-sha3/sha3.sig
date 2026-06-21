(* sha3.sig
   SHA-3 family signatures: Keccak-f[1600] sponge, SHA3-{224,256,384,512},
   SHAKE128/SHAKE256 (XOF), and KMAC (NIST SP 800-185).

   All `digest*` functions return raw bytes (a string of that many chars).
   All `hex*` functions return lowercase hex. *)

signature SHA3 =
sig
  val digest224 : string -> string
  val hex224    : string -> string
  val digest256 : string -> string
  val hex256    : string -> string
  val digest384 : string -> string
  val hex384    : string -> string
  val digest512 : string -> string
  val hex512    : string -> string
end

signature SHAKE =
sig
  val hash    : int -> string -> string
  val hashHex : int -> string -> string
end

signature KMAC =
sig
  val mac    : string -> string -> int -> string -> string
  val macHex : string -> string -> int -> string -> string
end
