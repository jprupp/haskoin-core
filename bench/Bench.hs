{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

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
-- The group @serial@ is about the other half of such a server: the bytes
-- that it keeps. It reads a transaction from its database for every one that
-- it returns, and writes and hashes every transaction of a block that it
-- imports. That group has no reference from 1.6.0: it measures each type
-- through every way to its bytes, with the memory that each allocates, and
-- is compared with a run of the release before.
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

import Control.DeepSeq (NFData)
import Control.Monad (unless, (<=<))
import Control.Monad.State.Strict (State, runState)
import Data.Aeson (ToJSON (toEncoding))
import Data.Aeson.Encoding (Encoding, encodingToLazyByteString, unsafeToEncoding)
import Data.Base16.Types (extractBase16)
import Data.Binary qualified as Binary
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
import Data.List (foldl', intercalate)
import Data.Maybe (fromMaybe)
import Data.Serialize qualified as Cereal
import Data.Text (Text)
import Data.Text qualified as T
import Data.Text.Lazy qualified as LT
import Data.Word (Word32, Word64)
import Haskoin
import Numeric (showIntAtBase)
import Test.Tasty.Bench

main :: IO ()
main =
  defaultMain
    [ bgroup "hex" hexBenchmarks,
      bgroup "address" addressBenchmarks,
      bgroup "json" jsonBenchmarks,
      bgroup "base58" base58Benchmarks,
      bgroup "serial" serialBenchmarks,
      bgroup "headers" headerBenchmarks
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
    header = blockHeader

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

-- Binary encoding

-- | The binary form of the types that a server reads and writes most. A
-- server that indexes the chain decodes every transaction it returns from
-- its database, writes a key of a hash or an outpoint for every input and
-- output of a block that it imports, and hashes every transaction of that
-- block. The time and the memory of these few encoders decide how fast it
-- imports a block.
--
-- Each type is measured through the entry points that such a server calls:
-- @encode@ and @decode@ of cereal, and 'runPutS' with 'serialize' and
-- 'runGetS' with 'deserialize' of the bytes package. They give the same
-- bytes, but they reach the code of the library by different doors, and one
-- may be fast while the other is not. A transaction is measured through
-- binary too.
--
-- Run these with @+RTS -T@ to see the memory allocated by each: the time
-- of an encoder of a few bytes is mostly the time that it takes to allocate.
serialBenchmarks :: [Benchmark]
serialBenchmarks =
  [ codec "TxHash" txid,
    codec "BlockHash" blockid,
    codec "Hash256" (doubleSHA256 (bytes 70 32)),
    codec "Hash160" (addressHash (bytes 71 33)),
    codec "VarInt of 1 byte" (VarInt 107),
    codec "VarInt of 3 bytes" (VarInt 3000),
    codec "OutPoint" outpoint,
    codec "TxOut" (TxOut 123456 (hex "0020" <> bytes 43 32)),
    codec "TxIn" (TxIn outpoint (bytes 72 107) 0xffffffff),
    codec "BlockHeader" blockHeader,
    codec "Address, P2PKH" (PubKeyAddress (addressHash (bytes 73 33))),
    codec "Address, P2WSH" (WitnessScriptAddress (sha256 (bytes 74 33))),
    bgroup "Tx" $
      [ bgroup name (codecs tx <> binaryCodecs tx)
      | (name, tx) <- take 2 transactions
      ],
    codec ("Block of " <> show blockSize <> " transactions") block,
    -- a block as a node gets it from a peer and sends it to one; half of
    -- the time is the checksum of the payload
    bgroup
      ("Message with a block of " <> show blockSize <> " transactions")
      [ bench "putMessage" (nf (runPutS . putMessage btc) (MBlock block)),
        bench "getMessage" (nf (runGetS (getMessage btc)) (runPutS (putMessage btc (MBlock block))))
      ],
    bgroup "hash" $
      [ bgroup
          name
          [ bench "txHash" (nf txHash tx),
            bench "txWitnessHash" (nf txWitnessHash tx),
            bench "txWeight" (nf txWeight tx),
            -- what is left of the two above once the bytes are written
            bench "doubleSHA256 of its bytes" (nf doubleSHA256 (runPutS (serialize tx)))
          ]
      | (name, tx) <- take 2 transactions
      ]
        <> [ bench "headerHash" (nf headerHash blockHeader),
             bench ("txHash of " <> show blockSize <> " transactions") (nf (map txHash) blockTransactions)
           ]
  ]
  where
    outpoint = OutPoint txid 1

-- | A value written and read through cereal and through the bytes package.
codec :: (Serial a, Cereal.Serialize a, NFData a) => String -> a -> Benchmark
codec name x = bgroup name (codecs x)
{-# INLINE codec #-}

-- | The benchmarks of 'codec'. The pragma makes a copy of them for every
-- type that they are used at, so that each one calls the library as a
-- program that names the type does, not through a dictionary that only this
-- file would have.
codecs :: forall a. (Serial a, Cereal.Serialize a, NFData a) => a -> [Benchmark]
codecs x =
  [ bench "cereal encode" (nf Cereal.encode x),
    bench "cereal decode" (nf (Cereal.decode :: ByteString -> Either String a) encoded),
    bench "runPutS serialize" (nf (runPutS . serialize) x),
    bench "runGetS deserialize" (nf (runGetS deserialize :: ByteString -> Either String a) encoded),
    bench "encodeSerial" (nf encodeSerial x),
    bench "decodeSerial" (nf (decodeSerial :: ByteString -> Either String a) encoded)
  ]
  where
    encoded = runPutS (serialize x)
{-# INLINE codecs #-}

-- | A value written and read through binary, which works on lazy bytes.
binaryCodecs :: forall a. (Binary.Binary a, NFData a) => a -> [Benchmark]
binaryCodecs x =
  [ bench "binary encode" (nf Binary.encode x),
    bench "binary decode" (nf (Binary.decode :: L.ByteString -> a) (Binary.encode x))
  ]
{-# INLINE binaryCodecs #-}

blockHeader :: BlockHeader
blockHeader = BlockHeader 1 blockid (doubleSHA256 (bytes 50 64)) 1231006505 0x1d00ffff 2083236893

-- | The number of transactions of 'block': about as many as a full block of
-- Bitcoin has.
blockSize :: Int
blockSize = 3000

-- | A block of about 1.1 MB, of transactions that differ in their bytes, in
-- their numbers of inputs and outputs, and in whether they have a witness:
-- two in three do, as in a block of Bitcoin today.
block :: Block
block = Block blockHeader blockTransactions

-- | The transactions of 'block'.
blockTransactions :: [Tx]
blockTransactions = map transaction [1 .. fromIntegral blockSize]
  where
    transaction :: Word64 -> Tx
    transaction k
      | k `mod` 3 == 0 = Tx 1 (map (input 107) (seeds k)) (outputs k) [] 0
      | otherwise = Tx 2 (map (input 0) (seeds k)) (outputs k) (map witness (seeds k)) (fromIntegral k)
    -- one to three seeds, all different from those of every other transaction
    seeds k = [1000 * k + i | i <- [1 .. 1 + k `mod` 3]]
    input size seed =
      TxIn (OutPoint (TxHash (doubleSHA256 (bytes seed 32))) (index seed)) (bytes (seed + 500) size) 0xfffffffd
    index :: Word64 -> Word32
    index seed = fromIntegral (seed `mod` 4)
    outputs k = concat (replicate (fromIntegral (1 + k `mod` 2)) (pair k))
    pair k =
      [ TxOut (1000 + k) (hex "0014" <> bytes (k + 1) 20),
        TxOut (5000000 + k) (hex "5120" <> bytes (k + 2) 32)
      ]
    witness seed = [bytes (seed + 600) 72, bytes (seed + 700) 33]

-- | Connecting a batch of 2,000 headers, the most a peer sends in one
-- @headers@ message, on top of a chain of 100,000 headers that already uses
-- the aserti3-2d difficulty algorithm of Bitcoin Cash. That algorithm needs
-- the anchor block of the chain, which is far below the tip, and a node
-- syncing headers spends its time here. The headers are mined at the easiest
-- target of a test network, so that the chain can be built in a moment, and
-- kept in the memory store of the library, so that the figure is the cost of
-- the validation and not of a database.
--
-- The network is regtest, which has no 'asertAnchorBlock', so 'connectBlocks'
-- searches for the anchor once. 'connectBlock' of a single header is timed
-- twice: on that network, where it searches, and with the anchor set as on
-- mainnet, where it walks to it.
--
-- Each case is run once before it is timed, and the suite stops if its headers
-- do not connect: a failure that came early would otherwise look fast.
headerBenchmarks :: [Benchmark]
headerBenchmarks =
  [ env (checked (connectBlocks net now batch) (length batch)) $ \ ~(mem, hs) ->
      bench "connectBlocks 2000 at 100000" $
        nf (\hs' -> fst (runState (connectBlocks net now hs') mem)) hs,
    env (checked (fmap pure <$> connectBlock net now next) 1) $ \ ~(mem, _) ->
      bench "connectBlock 1 at 100000, anchor searched" $
        nf (\h -> fst (runState (connectBlock net now h) mem)) next,
    env (checked (fmap pure <$> connectBlock anchorNet now next) 1) $ \ ~(mem, _) ->
      bench "connectBlock 1 at 100000, anchor known" $
        nf (\h -> fst (runState (connectBlock anchorNet now h) mem)) next
  ]
  where
    base = 100000
    (old, batch) = splitAt base (appendBlocks net 0 net.genesisHeader (base + 2000))
    next = case batch of
      h : _ -> h
      [] -> error "Bench: no header to connect"
    now = net.genesisHeader.timestamp + 600 * fromIntegral (base + 3000)
    net =
      bchRegTest
        { powNoRetarget = False,
          minDiffBlocks = False,
          edaHeight = Nothing,
          daaHeight = Nothing,
          asertActivationTime = Just (net.genesisHeader.timestamp + 600 * 20),
          checkpoints = []
        }
    -- The same network with the anchor of this chain set, as on mainnet.
    anchorNet = (net :: Network) {asertAnchorBlock = Just (anchor.height, headerHash anchor.header)}
    anchor = fromMaybe (error "Bench: no anchor") (fst (runState (asertAnchor net chain.best) chain))
    -- The store and the batch, once the given connection gave the number of
    -- headers expected.
    checked :: State HeaderMemory (Either String [BlockNode]) -> Int -> IO (HeaderMemory, [BlockHeader])
    checked run n = case fst (runState run chain) of
      Right nodes
        | length nodes == n -> return (chain, batch)
        | otherwise -> fail ("Bench: connected " <> show (length nodes) <> " headers instead of " <> show n)
      Left err -> fail ("Bench: the headers do not connect: " <> err)
    -- The store holding the first headers, built directly, without
    -- validation, so that building it is quick.
    chain = foldl' add (initialChain net) old
    add :: HeaderMemory -> BlockHeader -> HeaderMemory
    add mem bh =
      let par = mem.best
          h = par.height + 1
          sk = fromMaybe (error "no skip") (fst (runState (getAncestor (skipHeight h) par) mem))
          node = BlockNode bh h (par.work + headerWork bh) (headerHash sk.header)
       in snd (runState (addBlockHeader node >> setBestBlockHeader node) mem)
