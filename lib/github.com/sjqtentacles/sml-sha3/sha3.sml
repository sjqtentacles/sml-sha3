(* sha3.sml
   Keccak-f[1600] sponge construction and the SHA-3 / SHAKE / KMAC family.
   Reference: FIPS 202, NIST SP 800-185. *)

(* ------------------------------------------------------------------ *)
(* Hex encoding helper                                                  *)
(* ------------------------------------------------------------------ *)

local
  val hexDigits = "0123456789abcdef"
  fun nibble n = String.sub (hexDigits, n)
in
  fun bytesToHex (s : string) : string =
    let
      fun f i acc =
        if i < 0 then acc
        else
          let val w = Char.ord (String.sub (s, i))
          in f (i-1) (String.str (nibble (w div 16)) ^
                      String.str (nibble (w mod 16)) ^ acc)
          end
    in f (String.size s - 1) "" end
end

(* Hex codec: `toHex` is the same lowercase encoding used by every `hex*` /
   `*Hex` function below (it reuses `bytesToHex`); `fromHex` is its inverse. *)
structure Hex : HEX =
struct
  fun toHex s = bytesToHex s

  fun hexVal c =
    if c >= #"0" andalso c <= #"9" then SOME (Char.ord c - Char.ord #"0")
    else if c >= #"a" andalso c <= #"f" then SOME (Char.ord c - Char.ord #"a" + 10)
    else if c >= #"A" andalso c <= #"F" then SOME (Char.ord c - Char.ord #"A" + 10)
    else NONE

  fun fromHex s =
    let
      val n = String.size s
    in
      if n mod 2 <> 0 then NONE
      else
        let
          fun loop (i, acc) =
            if i >= n then SOME (String.implode (List.rev acc))
            else
              case (hexVal (String.sub (s, i)), hexVal (String.sub (s, i + 1))) of
                  (SOME hi, SOME lo) => loop (i + 2, Char.chr (hi * 16 + lo) :: acc)
                | _ => NONE
        in
          loop (0, [])
        end
    end
end

(* ------------------------------------------------------------------ *)
(* Keccak-f[1600]                                                       *)
(* ------------------------------------------------------------------ *)

structure Keccak =
struct
  (* Round constants *)
  val rc : Word64.word array = Array.fromList
    [ 0wx0000000000000001, 0wx0000000000008082
    , 0wx800000000000808A, 0wx8000000080008000
    , 0wx000000000000808B, 0wx0000000080000001
    , 0wx8000000080008081, 0wx8000000000008009
    , 0wx000000000000008A, 0wx0000000000000088
    , 0wx0000000080008009, 0wx000000008000000A
    , 0wx000000008000808B, 0wx800000000000008B
    , 0wx8000000000008089, 0wx8000000000008003
    , 0wx8000000000008002, 0wx8000000000000080
    , 0wx000000000000800A, 0wx800000008000000A
    , 0wx8000000080008081, 0wx8000000000008080
    , 0wx0000000080000001, 0wx8000000080008008 ]

  (* Rotation offsets indexed by (x + 5*y) lane index *)
  val rho : int array = Array.fromList
    [  0,  1, 62, 28, 27
    , 36, 44,  6, 55, 20
    ,  3, 10, 43, 25, 39
    , 41, 45, 15, 21,  8
    , 18,  2, 61, 56, 14 ]

  (* Pi permutation: index i maps to piPerm[i] *)
  val piPerm : int array =
    let
      val a = Array.array (25, 0)
      fun set x y =
        Array.update (a, x + 5*y, y + 5*((2*x + 3*y) mod 5))
    in
      List.app (fn x => List.app (fn y => set x y) [0,1,2,3,4]) [0,1,2,3,4];
      a
    end

  fun rotl64 (x : Word64.word, n : int) : Word64.word =
    if n = 0 then x
    else Word64.orb (Word64.<< (x, Word.fromInt n),
                     Word64.>> (x, Word.fromInt (64 - n)))

  fun permute (s : Word64.word array) : unit =
    let
      val c = Array.array (5, 0w0 : Word64.word)
      val d = Array.array (5, 0w0 : Word64.word)
      val b = Array.array (25, 0w0 : Word64.word)

      fun doRound r =
        let
          (* theta: compute column parities *)
          val () = List.app (fn x =>
              Array.update (c, x,
                Word64.xorb (Word64.xorb (Word64.xorb (Word64.xorb
                  (Array.sub (s, x),
                   Array.sub (s, x+5)),
                   Array.sub (s, x+10)),
                   Array.sub (s, x+15)),
                   Array.sub (s, x+20))))
            [0,1,2,3,4]
          val () = List.app (fn x =>
              Array.update (d, x,
                Word64.xorb (Array.sub (c, (x+4) mod 5),
                             rotl64 (Array.sub (c, (x+1) mod 5), 1))))
            [0,1,2,3,4]
          val () = List.app (fn i =>
              Array.update (s, i,
                Word64.xorb (Array.sub (s, i),
                             Array.sub (d, i mod 5))))
            (List.tabulate (25, fn i => i))

          (* rho + pi *)
          val () = List.app (fn i =>
              Array.update (b, Array.sub (piPerm, i),
                rotl64 (Array.sub (s, i), Array.sub (rho, i))))
            (List.tabulate (25, fn i => i))

          (* chi *)
          val () = List.app (fn i =>
              let val row = (i div 5) * 5
              in Array.update (s, i,
                   Word64.xorb (Array.sub (b, i),
                     Word64.andb (
                       Word64.notb (Array.sub (b, row + (i mod 5 + 1) mod 5)),
                       Array.sub (b, row + (i mod 5 + 2) mod 5))))
              end)
            (List.tabulate (25, fn i => i))

          (* iota *)
          val () = Array.update (s, 0,
              Word64.xorb (Array.sub (s, 0), Array.sub (rc, r)))
        in () end
    in
      List.app doRound (List.tabulate (24, fn i => i))
    end

  (* Absorb `rate` bytes from `msg` at offset `off` into state `s`. *)
  fun absorbBlock (s : Word64.word array) (msg : string) (off : int) (rate : int) : unit =
    let
      fun getByte i =
        if off + i < String.size msg
        then Word64.fromInt (Char.ord (String.sub (msg, off + i)))
        else 0w0
      fun lane i =
        let fun sh b k = Word64.<< (getByte (i*8+b), Word.fromInt (k*8))
        in Word64.orb (Word64.orb (Word64.orb (Word64.orb
             (Word64.orb (Word64.orb (Word64.orb
               (getByte (i*8), sh 1 1), sh 2 2), sh 3 3),
               sh 4 4), sh 5 5), sh 6 6), sh 7 7)
        end
      val laneCount = rate div 8
    in
      List.app (fn i =>
        Array.update (s, i, Word64.xorb (Array.sub (s, i), lane i)))
        (List.tabulate (laneCount, fn i => i))
    end

  (* Squeeze `outLen` bytes from the current state. *)
  fun squeeze (s : Word64.word array) (outLen : int) : string =
    let
      fun extractByte i =
        let val w = Array.sub (s, i div 8)
            val sh = Word.fromInt ((i mod 8) * 8)
        in Char.chr (Word64.toInt (Word64.andb (Word64.>> (w, sh), 0w255)))
        end
    in
      String.implode (List.tabulate (outLen, extractByte))
    end

  (* Full Keccak sponge: absorb `msg` with padding then squeeze `outLen` bytes.
     rate   : bytes per block (1600 bits - capacity) / 8
     dsbyte : domain separation suffix byte (0x06 = SHA-3, 0x1F = SHAKE, 0x04 = cSHAKE) *)
  fun sponge (rate : int) (dsbyte : int) (outLen : int) (msg : string) : string =
    let
      val s    = Array.array (25, 0w0 : Word64.word)
      val mlen = String.size msg

      (* Absorb full blocks *)
      val fullBlocks = mlen div rate
      val () = List.app (fn b =>
          (absorbBlock s msg (b * rate) rate; permute s))
        (List.tabulate (fullBlocks, fn i => i))

      (* Build the final padded block as a mutable buffer *)
      val pad = Array.array (rate, 0)
      val off = fullBlocks * rate
      val rem = mlen - off
      val () = List.app (fn i =>
          Array.update (pad, i, Char.ord (String.sub (msg, off + i))))
        (List.tabulate (rem, fn i => i))
      (* Append domain suffix byte *)
      val () = Array.update (pad, rem,
          Word8.toInt (Word8.orb (Word8.fromInt (Array.sub (pad, rem)),
                                  Word8.fromInt dsbyte)))
      (* Set top bit of last byte *)
      val () = Array.update (pad, rate - 1,
          Word8.toInt (Word8.orb (Word8.fromInt (Array.sub (pad, rate - 1)),
                                  0wx80)))
      val padStr = String.implode (List.tabulate (rate, fn i =>
        Char.chr (Array.sub (pad, i))))
      val () = absorbBlock s padStr 0 rate
      val () = permute s

      (* Squeeze output (loop if outLen > rate) *)
      fun squeezeAll acc needed =
        if needed <= 0 then acc
        else
          let val take = Int.min (rate, needed)
              val chunk = squeeze s take
          in if needed > rate then (permute s; squeezeAll (acc ^ chunk) (needed - take))
             else acc ^ chunk
          end
    in
      squeezeAll "" outLen
    end

  (* ---- NIST SP 800-185 helpers ---- *)

  fun encodeLeft (x : int) : string =
    let
      fun bytes 0 acc n = (n, acc)
        | bytes x acc n = bytes (x div 256) (Char.chr (x mod 256) :: acc) (n + 1)
      val (n, bs) = if x = 0 then (1, [#"\000"]) else bytes x [] 0
    in
      String.str (Char.chr n) ^ String.implode bs
    end

  fun rightEncode (x : int) : string =
    let
      fun bytes 0 acc n = (n, acc)
        | bytes x acc n = bytes (x div 256) (Char.chr (x mod 256) :: acc) (n + 1)
      val (n, bs) = if x = 0 then (1, [#"\000"]) else bytes x [] 0
    in
      String.implode bs ^ String.str (Char.chr n)
    end

  fun encodeString (s : string) : string =
    encodeLeft (String.size s * 8) ^ s

  fun bytePad (x : string) (w : int) : string =
    let
      val enc  = encodeLeft w
      val body = enc ^ x
      val len  = String.size body
      val pad  = (w - len mod w) mod w
    in
      body ^ String.implode (List.tabulate (pad, fn _ => #"\000"))
    end
end

(* ------------------------------------------------------------------ *)
(* SHA-3 fixed-output hash functions                                    *)
(* ------------------------------------------------------------------ *)

structure Sha3 : SHA3 =
struct
  fun digest224 msg = Keccak.sponge 144 0x06 28 msg
  fun digest256 msg = Keccak.sponge 136 0x06 32 msg
  fun digest384 msg = Keccak.sponge 104 0x06 48 msg
  fun digest512 msg = Keccak.sponge  72 0x06 64 msg

  fun hex224 msg = bytesToHex (digest224 msg)
  fun hex256 msg = bytesToHex (digest256 msg)
  fun hex384 msg = bytesToHex (digest384 msg)
  fun hex512 msg = bytesToHex (digest512 msg)
end

(* ------------------------------------------------------------------ *)
(* SHAKE extendable-output functions                                    *)
(* ------------------------------------------------------------------ *)

structure Shake128 : SHAKE =
struct
  fun hash outLen msg = Keccak.sponge 168 0x1F outLen msg
  fun hashHex outLen msg = bytesToHex (hash outLen msg)
end

structure Shake256 : SHAKE =
struct
  fun hash outLen msg = Keccak.sponge 136 0x1F outLen msg
  fun hashHex outLen msg = bytesToHex (hash outLen msg)
end

(* ------------------------------------------------------------------ *)
(* cSHAKE (NIST SP 800-185 §3) — building block for KMAC             *)
(* ------------------------------------------------------------------ *)

local
  fun cshake rate outLen funcName custom msg =
    if funcName = "" andalso custom = "" then
      Keccak.sponge rate 0x1F outLen msg
    else
      let
        val prefix = Keccak.bytePad
          (Keccak.encodeString funcName ^ Keccak.encodeString custom) rate
      in
        Keccak.sponge rate 0x04 outLen (prefix ^ msg)
      end
in

(* ------------------------------------------------------------------ *)
(* KMAC128 / KMAC256                                                    *)
(* ------------------------------------------------------------------ *)

  structure Kmac128 : KMAC =
  struct
    fun mac key custom outLen msg =
      let
        val paddedKey = Keccak.bytePad (Keccak.encodeString key) 168
        (* SP 800-185 §4: right_encode(L) where L is output length in *bits* *)
        val input     = paddedKey ^ msg ^ Keccak.rightEncode (outLen * 8)
      in
        cshake 168 outLen "KMAC" custom input
      end
    fun macHex key custom outLen msg = bytesToHex (mac key custom outLen msg)
  end

  structure Kmac256 : KMAC =
  struct
    fun mac key custom outLen msg =
      let
        val paddedKey = Keccak.bytePad (Keccak.encodeString key) 136
        val input     = paddedKey ^ msg ^ Keccak.rightEncode (outLen * 8)
      in
        cshake 136 outLen "KMAC" custom input
      end
    fun macHex key custom outLen msg = bytesToHex (mac key custom outLen msg)
  end

end
