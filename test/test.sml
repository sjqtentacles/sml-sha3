(* test.sml — SHA-3 test suite.
   Expected values are from the NIST FIPS 202 and SP 800-185 published test vectors. *)

structure Sha3Tests =
struct
  open Harness

  fun runSha3_256 () =
    let
      val () = section "SHA3-256"
      val () = checkString "empty string"
        ( "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        , Sha3.hex256 "" )
      val () = checkString "abc"
        ( "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        , Sha3.hex256 "abc" )
      val () = checkString "448-bit NIST vector"
        ( "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376"
        , Sha3.hex256
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" )
      val () = check "digest256 length = 32"
        (String.size (Sha3.digest256 "") = 32)
      val () = check "hex256 length = 64"
        (String.size (Sha3.hex256 "") = 64)
      val () = check "deterministic"
        (Sha3.hex256 "hello" = Sha3.hex256 "hello")
      val () = check "collision-free on single-char inputs"
        (Sha3.hex256 "a" <> Sha3.hex256 "b")
    in () end

  fun runSha3_224 () =
    let
      val () = section "SHA3-224"
      val () = checkString "empty string"
        ( "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
        , Sha3.hex224 "" )
      val () = checkString "abc"
        ( "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf"
        , Sha3.hex224 "abc" )
      val () = check "digest224 length = 28"
        (String.size (Sha3.digest224 "") = 28)
      val () = check "hex224 length = 56"
        (String.size (Sha3.hex224 "") = 56)
    in () end

  fun runSha3_384 () =
    let
      val () = section "SHA3-384"
      val () = checkString "empty string"
        ( "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
        , Sha3.hex384 "" )
      val () = checkString "abc"
        ( "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25"
        , Sha3.hex384 "abc" )
      val () = check "digest384 length = 48"
        (String.size (Sha3.digest384 "") = 48)
      val () = check "hex384 length = 96"
        (String.size (Sha3.hex384 "") = 96)
    in () end

  fun runSha3_512 () =
    let
      val () = section "SHA3-512"
      val () = checkString "empty string"
        ( "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
        , Sha3.hex512 "" )
      val () = checkString "abc"
        ( "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
        , Sha3.hex512 "abc" )
      val () = check "digest512 length = 64"
        (String.size (Sha3.digest512 "") = 64)
      val () = check "hex512 length = 128"
        (String.size (Sha3.hex512 "") = 128)
    in () end

  fun runShake128 () =
    let
      val () = section "SHAKE128"
      val () = checkString "empty, 32 bytes"
        ( "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"
        , Shake128.hashHex 32 "" )
      val () = checkString "abc, 32 bytes"
        ( "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8"
        , Shake128.hashHex 32 "abc" )
      val () = check "output length 16"
        (String.size (Shake128.hash 16 "") = 16)
      val () = check "output length 100"
        (String.size (Shake128.hash 100 "") = 100)
      val () = check "XOF prefix property: first 32 of 64 = standalone 32"
        (String.substring (Shake128.hash 64 "", 0, 32) =
         Shake128.hash 32 "")
    in () end

  fun runShake256 () =
    let
      val () = section "SHAKE256"
      val () = checkString "empty, 32 bytes"
        ( "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
        , Shake256.hashHex 32 "" )
      val () = check "output length 64"
        (String.size (Shake256.hash 64 "") = 64)
    in () end

  fun runKmac () =
    let
      val () = section "KMAC128"
      (* NIST SP 800-185 Sample #1:
         Key  = 404142...5f (32 bytes)
         Data = 00010203
         S    = "" (empty customization string)
         L    = 32 bytes *)
      (* Build key as a string of bytes 0x40..0x5f *)
      val key  = String.implode
        (List.tabulate (32, fn i => Char.chr (i + 64)))
      (* 64 decimal = 0x40 *)
      val data = String.implode [Char.chr 0, Char.chr 1, Char.chr 2, Char.chr 3]
      val () = checkString "KMAC128 sample #1 (empty S)"
        ( "e5780b0d3ea6f7d3a429c5706aa43a00fadbd7d49628839e3187243f456ee14e"
        , Kmac128.macHex key "" 32 data )

      val () = section "KMAC256"
      (* NIST SP 800-185 KMAC256 Sample #3:
         Key  = same 32-byte key (0x40..0x5f)
         Data = 00010203
         S    = "My Tagged Application"
         L    = 64 bytes *)
      val () = checkString "KMAC256 sample #3"
        ( "20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f" ^
          "7f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27773a8dd"
        , Kmac256.macHex key "My Tagged Application" 64 data )
    in () end

  fun run () =
    ( runSha3_256 ()
    ; runSha3_224 ()
    ; runSha3_384 ()
    ; runSha3_512 ()
    ; runShake128 ()
    ; runShake256 ()
    ; runKmac () )
end
