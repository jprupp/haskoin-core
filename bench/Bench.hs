{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedStrings #-}

-- |
-- Module      : Main
-- Description : Benchmarks of the hot paths of a server
-- Copyright   : No rights reserved
-- License     : MIT
-- Maintainer  : jprupp@protonmail.ch
--
-- A server that indexes the block chain writes hex, addresses and JSON for
-- every input and output that it shows, so those few functions decide how
-- fast it answers. Releases 1.6.3 and 1.6.4 rewrote them for speed. Some of
-- the rewrites were slower than what they replaced, and some of the figures
-- quoted for them held only at @-O2@, or not at all. The package had no
-- benchmark to check them with. This suite is here so that a claim about
-- speed can be checked by anyone, and so that the next rewrite is measured
-- before it is released.
--
-- Wherever it is possible, a function of the library is measured next to the
-- same work done the way haskoin-core 1.6.0 did it, copied into this file as
-- a reference. The reference is the benchmark named @as in 1.6.0@, and the
-- function of the library is the one named @now@, printed with the ratio
-- between the two: below 1 the library is faster than the reference. A
-- reference is a copy compiled here, not the old library, so it shows what
-- the old method costs, not exactly what the old release cost.
--
-- Run it at both levels of optimisation. The package is built with @-O1@
-- unless the user asks otherwise, and code that is only fast with @-O2@ is
-- not fast for most users:
--
-- > stack bench
-- > stack bench --ghc-options -O2
--
-- The README says how to run a part of it and how to compare two runs.
module Main (main) where

import Control.Monad (unless, (<=<))
import Data.Aeson (ToJSON (toEncoding))
import Data.Aeson.Encoding (Encoding, encodingToLazyByteString, unsafeToEncoding)
import Data.Base16.Types (extractBase16)
import Data.Bits (shiftR, xor)
import Data.ByteString (ByteString)
import Data.ByteString qualified as B
import Data.ByteString.Base16 (encodeBase16)
import Data.ByteString.Builder (Builder, char7, lazyByteStringHex, toLazyByteString, word8)
import Data.ByteString.Lazy qualified as L
import Data.ByteString.Lazy.Base16 qualified as L16
import Data.Bytes.Get (isEmpty, runGetS)
import Data.Bytes.Put (runPutL, runPutS)
import Data.Bytes.Serial (Serial (deserialize, serialize))
import Data.Char (chr)
import Data.List (intercalate)
import Data.Maybe (fromMaybe)
import Data.Text (Text)
import Data.Text qualified as T
import Data.Text.Lazy qualified as LT
import Data.Word (Word64)
import Haskoin
import Numeric (showIntAtBase)
import Test.Tasty.Bench

main :: IO ()
main =
  defaultMain
    [ bgroup "hex" hexBenchmarks,
      bgroup "address" addressBenchmarks,
      bgroup "json" jsonBenchmarks,
      bgroup "base58" base58Benchmarks
    ]

-- | The benchmark of a function of the library, named @now@, after the same
-- work done as haskoin-core 1.6.0 did it, named @as in 1.6.0@. The first
-- argument is the names of the groups that the pair is in, outermost first:
-- tasty-bench finds the reference by its full name, to print how many times
-- as long as the reference the library takes.
versus :: [String] -> String -> Benchmarkable -> Benchmarkable -> Benchmark
versus groups name old new =
  bgroup
    name
    [ bench reference old,
      bcompare (intercalate " && " (zipWith field [0 :: Int ..] path)) (bench "now" new)
    ]
  where
    reference = "as in 1.6.0"
    path = reference : name : reverse groups
    field 0 s = "$NF == \"" <> s <> "\""
    field i s = "$(NF-" <> show i <> ") == \"" <> s <> "\""

-- Input

-- | Bytes that look random and are the same in every run: the output of a
-- SplitMix64 generator. Hex and Base58 read their input a byte at a time, so
-- bytes that are all alike would flatter a table lookup.
bytes :: Word64 -> Int -> ByteString
bytes seed n = fst (B.unfoldrN n (Just . next) seed)
  where
    next s =
      let s' = s + 0x9e3779b97f4a7c15
          a = (s' `xor` (s' `shiftR` 30)) * 0xbf58476d1ce4e5b9
          b = (a `xor` (a `shiftR` 27)) * 0x94d049bb133111eb
       in (fromIntegral (b `xor` (b `shiftR` 31)), s')

-- | Bytes from their hex. The input of this file is written by hand, so hex
-- that does not decode is a mistake here, not a case to handle.
hex :: Text -> ByteString
hex = fromMaybe (error "Bench: bad hex") . decodeHex

-- | The sizes that hex is measured on: a hash, a transaction of ordinary
-- size, a large script, and a block.
sizes :: [(String, Int)]
sizes = [("32 B", 32), ("250 B", 250), ("1 kB", 1000), ("1 MB", 1000000)]

-- | A megabyte in the chunks that serializing a block gives: the same bytes
-- written through a builder, as 'runPutL' does, which fills a first chunk of
-- about 4 kB and then chunks of about 32 kB.
megabyteSerialized :: L.ByteString
megabyteSerialized = toLazyByteString (B.foldr (\w b -> word8 w <> b) mempty (bytes 4 1000000))

-- | A megabyte in chunks of 100 bytes, as a list of scripts joined together
-- would be. haskoin-core 1.6.4 treated chunks under 256 bytes differently
-- from longer ones, so both sides of that line are measured.
megabyteSmallChunks :: L.ByteString
megabyteSmallChunks = L.fromChunks (pieces (bytes 5 1000000))
  where
    pieces b
      | B.null b = []
      | otherwise = let (h, t) = B.splitAt 100 b in h : pieces t

-- Hex

hexBenchmarks :: [Benchmark]
hexBenchmarks =
  [ bgroup "hexBuilder" $
      [ versus ["hex", "hexBuilder"] name (nf (toLazyByteString . hexBuilder160) input) $
          nf (toLazyByteString . hexBuilder) input
      | (name, input) <- lazyInputs
      ],
    bgroup "hexEncoding" $
      [ versus ["hex", "hexEncoding"] name (nf (encodingToLazyByteString . hexEncoding160) input) $
          nf (encodingToLazyByteString . hexEncoding) input
      | (name, input) <- lazyInputs
      ],
    bgroup "encodeHex" $
      [ versus ["hex", "encodeHex"] name (nf encodeHex160 input) (nf encodeHex input)
      | (name, size) <- sizes,
        let input = bytes 1 size
      ],
    bgroup "encodeHexLazy" $
      [ versus ["hex", "encodeHexLazy"] name (nf encodeHexLazy160 input) (nf encodeHexLazy input)
      | (name, input) <- lazyInputs
      ],
    bgroup "hash" $
      [ versus ["hex", "hash"] "txHashToHex" (nf txHashToHex160 txid) (nf txHashToHex txid),
        versus ["hex", "hash"] "blockHashToHex" (nf blockHashToHex160 blockid) (nf blockHashToHex blockid)
      ]
  ]
  where
    lazyInputs =
      [(name, L.fromStrict (bytes 2 size)) | (name, size) <- sizes]
        <> [ ("1 MB as serialized", megabyteSerialized),
             ("1 MB in chunks of 100 B", megabyteSmallChunks)
           ]

-- | 'hexBuilder' of haskoin-core 1.6.0: the hex of the builder of bytestring.
hexBuilder160 :: L.ByteString -> Builder
hexBuilder160 = lazyByteStringHex

-- | 'hexEncoding' of haskoin-core 1.6.0.
hexEncoding160 :: L.ByteString -> Encoding
hexEncoding160 b = unsafeToEncoding (char7 '"' <> hexBuilder160 b <> char7 '"')

-- | 'encodeHex' of haskoin-core 1.6.0: the encoder of the base16 package.
encodeHex160 :: ByteString -> Text
encodeHex160 = extractBase16 . encodeBase16

-- | 'encodeHexLazy' of haskoin-core 1.6.0.
encodeHexLazy160 :: L.ByteString -> LT.Text
encodeHexLazy160 = extractBase16 . L16.encodeBase16

-- | 'txHashToHex' of haskoin-core 1.6.0: serialize the hash, reverse it and
-- write its hex.
txHashToHex160 :: TxHash -> Text
txHashToHex160 (TxHash h) = encodeHex160 (B.reverse (runPutS (serialize h)))

-- | 'blockHashToHex' of haskoin-core 1.6.0.
blockHashToHex160 :: BlockHash -> Text
blockHashToHex160 (BlockHash h) = encodeHex160 (B.reverse (runPutS (serialize h)))

txid :: TxHash
txid = TxHash (doubleSHA256 (bytes 6 250))

blockid :: BlockHash
blockid = BlockHash (doubleSHA256 (bytes 7 80))

-- Addresses

-- | The scripts of outputs that a server reads the address of. The first
-- four are the kinds that 'scriptToAddressBS' tells by their bytes. The
-- others are read by the script parser: Taproot and data carriers are a large
-- share of the outputs of Bitcoin today, so they are not a corner case.
scripts :: [(String, Network, ByteString)]
scripts =
  [ ("P2PKH", btc, hex "76a914" <> bytes 10 20 <> hex "88ac"),
    ("P2SH", btc, hex "a914" <> bytes 11 20 <> hex "87"),
    ("P2WPKH", btc, hex "0014" <> bytes 12 20),
    ("P2WSH", btc, hex "0020" <> bytes 13 32),
    ("Taproot", btc, hex "5120" <> bytes 14 32),
    ("witness version 2 with 20 bytes", btc, hex "5214" <> bytes 15 20),
    ("OP_RETURN with 20 bytes", btc, hex "6a14" <> bytes 16 20),
    ("OP_RETURN with 80 bytes", btc, hex "6a4c50" <> bytes 17 80),
    ("pay to public key", btc, hex "21" <> key1 <> hex "ac"),
    ("multisig 2 of 3", btc, multisig),
    ("empty script", btc, B.empty),
    ("non-standard script", btc, hex "76a914" <> bytes 18 20 <> hex "88ad51"),
    ("P2SH32 on Bitcoin Cash", bch, hex "aa20" <> bytes 19 32 <> hex "87"),
    ("P2PKH on Bitcoin Cash", bch, hex "76a914" <> bytes 20 20 <> hex "88ac"),
    ("P2WPKH on Bitcoin Cash", bch, hex "0014" <> bytes 21 20)
  ]
  where
    multisig = hex "5221" <> key1 <> hex "21" <> key2 <> hex "21" <> key3 <> hex "53ae"
    -- the generator of secp256k1, twice it and three times it
    key1 = hex "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    key2 = hex "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
    key3 = hex "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"

-- | Results are forced whole, so a script that has no address is timed with
-- the text of its error. A caller that throws the error away pays less than
-- this for a script that fails to parse.
addressBenchmarks :: [Benchmark]
addressBenchmarks =
  [ bgroup "scriptToAddressBS" $
      [ versus ["address", "scriptToAddressBS"] name (nf (scriptToAddressBS160 net) script) $
          nf (scriptToAddressBS net) script
      | (name, net, script) <- scripts
      ],
    -- the text of an address, which a server writes after reading it
    bgroup "addrToText" $
      [ bench name (nf (addrToText net) address)
      | (name, net, script) <- scripts,
        Right address <- [scriptToAddressBS net script]
      ]
  ]

-- | 'scriptToAddressBS' of haskoin-core 1.6.0: parse the script whatever it
-- is, then decode the output, then find its address.
scriptToAddressBS160 :: Network -> ByteString -> Either String Address
scriptToAddressBS160 net =
  maybeToEither "Could not decode address" . outputAddress net <=< unmarshal160

-- | What @unmarshal@ did for a 'ScriptOutput' in haskoin-core 1.6.0: run a
-- parser that is written for any monad, through the dictionary of its
-- class. The library called it that way, and that is why parsing a script of
-- 34 bytes took most of a microsecond. The pragma keeps GHC from making a
-- copy of this function for the one type it is used at here, which would
-- measure a parser that 1.6.0 did not have. With it, this reference takes
-- as long as @scriptToAddressBS@ of 1.6.0 built from its tag, or up to a
-- tenth less.
unmarshal160 :: (Serial a) => ByteString -> Either String a
unmarshal160 = runGetS $ do
  value <- deserialize
  done <- isEmpty
  unless done $ fail "unmarshal: bytes left over after the value"
  return value
{-# OPAQUE unmarshal160 #-}

-- JSON

-- | Transactions with scripts of the usual shapes and sizes. The bytes of
-- the scripts are made up: writing JSON does not parse them.
transactions :: [(String, Tx)]
transactions =
  [ ( "legacy transaction, 2 inputs and 2 outputs",
      Tx 1 [input 30 (bytes 31 107), input 32 (bytes 33 107)] outputs [] 0
    ),
    ( "SegWit transaction, 2 inputs and 2 outputs",
      Tx 2 [input 34 B.empty, input 35 B.empty] outputs [witness 36, witness 37] 0
    ),
    ( "transaction with 2 multisig inputs of 254 and 296 bytes",
      Tx 1 [input 38 (bytes 39 254), input 40 (bytes 41 296)] outputs [] 0
    ),
    ( "transaction with 100 inputs and 100 outputs",
      Tx 1 [input k (bytes (k + 1000) 107) | k <- [100 .. 199]] (concat (replicate 50 outputs)) [] 0
    )
  ]
  where
    input seed script = TxIn (OutPoint (TxHash (doubleSHA256 (bytes seed 32))) 1) script 0xffffffff
    outputs =
      [ TxOut 5000000000 (hex "76a914" <> bytes 42 20 <> hex "88ac"),
        TxOut 123456 (hex "0020" <> bytes 43 32)
      ]
    -- a signature and a public key
    witness seed = [bytes seed 72, bytes (seed + 100) 33]

jsonBenchmarks :: [Benchmark]
jsonBenchmarks =
  [ bgroup "toEncoding" $
      [bench name (nf encoded tx) | (name, tx) <- transactions]
        <> [ versus ["json", "toEncoding"] "TxHash" (nf (encodingToLazyByteString . txHashEncoding160) txid) $
               nf encoded txid,
             bench "BlockHash" (nf encoded blockid),
             bench "BlockHeader" (nf encoded header)
           ]
  ]
  where
    encoded :: (ToJSON a) => a -> L.ByteString
    encoded = encodingToLazyByteString . toEncoding
    header = BlockHeader 1 blockid (doubleSHA256 (bytes 50 64)) 1231006505 0x1d00ffff 2083236893

-- | The JSON encoding of 'TxHash' of haskoin-core 1.6.0.
txHashEncoding160 :: TxHash -> Encoding
txHashEncoding160 = hexEncoding160 . L.reverse . runPutL . serialize

-- Base58

base58Benchmarks :: [Benchmark]
base58Benchmarks =
  [ bgroup "encodeBase58" $
      [ versus ["base58", "encodeBase58"] name (nf encodeBase58160 input) (nf encodeBase58 input)
      | (name, size) <- lengths,
        let input = bytes 60 size
      ],
    bench "encodeBase58Check of 21 B" (nf encodeBase58Check (bytes 61 21)),
    bench "decodeBase58Check of an address" (nf decodeBase58Check (encodeBase58Check (bytes 62 21)))
  ]
  where
    -- an address with its checksum, an extended key with its checksum, and
    -- lengths that nothing in Bitcoin has, where the cost grows with the
    -- square of the length
    lengths = [("25 B", 25), ("82 B", 82), ("2 kB", 2000), ("20 kB", 20000)]

-- | 'encodeBase58' of haskoin-core 1.6.0: the bytes as one 'Integer',
-- divided by 58 a digit at a time into a list of characters.
encodeBase58160 :: ByteString -> Text
encodeBase58160 bs = T.replicate (B.length zeros) "1" <> digits
  where
    (zeros, rest) = B.span (== 0) bs
    digits
      | B.null rest = T.empty
      | otherwise = T.pack (showIntAtBase 58 (chr . fromIntegral . B.index alphabet) (bsToInteger rest) "")
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
