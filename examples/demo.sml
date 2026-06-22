(* demo.sml - hash fixed inputs with the SHA-3 family, SHAKE XOFs, and KMAC,
   printing lowercase hex digests. Values are FIPS 202 / SP 800-185 test
   vectors. Deterministic: same digests on every run and compiler. *)

fun hex s =
  let val d = "0123456789abcdef"
  in String.concat (List.map
       (fn c => let val b = Char.ord c
                in String.implode [String.sub (d, b div 16), String.sub (d, b mod 16)] end)
       (String.explode s))
  end

val () = print "SHA-3 digests of \"abc\" (FIPS 202):\n"
val () = print ("  SHA3-224 = " ^ Sha3.hex224 "abc" ^ "\n")
val () = print ("  SHA3-256 = " ^ Sha3.hex256 "abc" ^ "\n")
val () = print ("  SHA3-384 = " ^ Sha3.hex384 "abc" ^ "\n")
val () = print ("  SHA3-512 = " ^ Sha3.hex512 "abc" ^ "\n")

val () = print "\nSHA3-256 of the empty string (FIPS 202):\n"
val () = print ("  SHA3-256(\"\") = " ^ hex (Sha3.digest256 "") ^ "\n")

val () = print "\nSHAKE XOF output of \"abc\" (32 bytes):\n"
val () = print ("  SHAKE128 = " ^ Shake128.hashHex 32 "abc" ^ "\n")
val () = print ("  SHAKE256 = " ^ Shake256.hashHex 32 "abc" ^ "\n")

(* KMAC128 NIST SP 800-185 Sample #1: key 0x40..0x5f, data 00010203, L=32 *)
val key  = String.implode (List.tabulate (32, fn i => Char.chr (i + 64)))
val data = String.implode [Char.chr 0, Char.chr 1, Char.chr 2, Char.chr 3]
val () = print "\nKMAC128 (NIST SP 800-185 Sample #1):\n"
val () = print ("  mac = " ^ Kmac128.macHex key "" 32 data ^ "\n")
