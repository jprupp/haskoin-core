{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NoFieldSelectors #-}

module Haskoin.NetworkSpec (spec) where

import Control.Exception (evaluate)
import Control.Monad (forM_)
import Data.ByteString (ByteString)
import Data.ByteString qualified as B
import Data.Bytes.Get
import Data.Bytes.Put
import Data.Bytes.Serial
import Data.Default (def)
import Data.List (isInfixOf, nub)
import Data.Maybe (fromJust)
import Data.Sequence qualified as S
import Data.Text (Text)
import Data.Text qualified as T
import Data.Word (Word32)
import Haskoin.Address
import Haskoin.Block
import Haskoin.Crypto
import Haskoin.Network
import Haskoin.Script
import Haskoin.Transaction
import Haskoin.Util
import Haskoin.Util.Arbitrary
import Network.Socket (SockAddr (..), tupleToHostAddress)
import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck

-- Helpers -------------------------------------------------------------------

-- | Bytes of a hex string.
hex :: Text -> ByteString
hex = fromJust . decodeHex

-- | Hex of the serialization of a value.
hexOf :: (Serial a) => a -> Text
hexOf = encodeHex . runPutS . serialize

-- | Parse bytes as a value.
parse :: (Serial a) => ByteString -> Either String a
parse = runGetS deserialize

-- | The parse must fail and the error must mention the given words.
failsWith :: (Show a) => Either String a -> String -> Expectation
failsWith result msg =
  case result of
    Left e | msg `isInfixOf` e -> return ()
    _ ->
      expectationFailure $
        "expected a failure mentioning " ++ show msg ++ ", got " ++ show result

-- Hashes whose hex is the same read in either direction, so their bytes on
-- the wire are the hex below whether or not the type reverses them.
h1, h2, h3 :: Hash256
h1 = fromString' (T.replicate 32 "11")
h2 = fromString' (T.replicate 32 "22")
h3 = fromString' (T.replicate 32 "33")

fromString' :: Text -> Hash256
fromString' = either error id . runGetS deserialize . hex

h1Hex, h2Hex, h3Hex :: Text
h1Hex = T.replicate 32 "11"
h2Hex = T.replicate 32 "22"
h3Hex = T.replicate 32 "33"

bh1 :: BlockHash
bh1 = "1111111111111111111111111111111111111111111111111111111111111111"

bh1Hex :: Text
bh1Hex = T.replicate 32 "11"

-- | 10.0.0.1 port 8333 as an IPv4-mapped IPv6 address.
ipv4Host :: HostAddress
ipv4Host = sockToHostAddress (SockAddrInet 8333 (tupleToHostAddress (10, 0, 0, 1)))

-- | Ten zero bytes, two 0xff bytes, the four address bytes, then the port in
-- network byte order.
ipv4Bytes :: Text
ipv4Bytes = "00000000000000000000ffff0a000001208d"

-- | 2001:db8::1 port 8333.
ipv6Host :: HostAddress
ipv6Host = sockToHostAddress (SockAddrInet6 8333 0 (0x20010db8, 0, 0, 1) 0)

ipv6Bytes :: Text
ipv6Bytes = "20010db8000000000000000000000001208d"

-- | 0.0.0.0 port 0, the address of the documentation's version message.
zeroHost :: HostAddress
zeroHost = sockToHostAddress (SockAddrInet 0 (tupleToHostAddress (0, 0, 0, 0)))

-- | The sample version message of the Bitcoin wiki protocol documentation,
-- sent with protocol 60002, before the relay flag existed.
versionPayloadHex :: Text
versionPayloadHex =
  "62ea0000" -- protocol 60002
    <> "0100000000000000" -- services NODE_NETWORK
    <> "11b2d05000000000" -- timestamp 1355854353
    <> "010000000000000000000000000000000000ffff000000000000" -- addr_recv
    <> "010000000000000000000000000000000000ffff000000000000" -- addr_from
    <> "3b2eb35d8ce61765" -- nonce
    <> "0f2f5361746f7368693a302e372e322f" -- "/Satoshi:0.7.2/"
    <> "c03e0300" -- start height 212672

versionMessageHex :: Text
versionMessageHex =
  "f9beb4d9" -- mainnet magic
    <> "76657273696f6e0000000000" -- "version"
    <> "64000000" -- 100 payload bytes
    <> "3b648d5a" -- checksum
    <> versionPayloadHex

wikiVersion :: Version
wikiVersion =
  Version
    { version = 60002,
      services = 1,
      timestamp = 1355854353,
      addrRecv = NetworkAddress 1 zeroHost,
      addrSend = NetworkAddress 1 zeroHost,
      nonce = 7284544412836900411, -- 0x6517e68c5db32e3b
      userAgent = VarString "/Satoshi:0.7.2/",
      startHeight = 212672,
      relay = True
    }

-- | The sample addr message of the Bitcoin wiki protocol documentation:
-- one entry, seen at 1292899810, services NODE_NETWORK, 10.0.0.1:8333.
addrMessageHex :: Text
addrMessageHex =
  "f9beb4d9"
    <> "61646472" <> "0000000000000000" -- "addr"
    <> "1f000000" -- 31 payload bytes
    <> "ed52399b" -- checksum
    <> "01" -- one entry
    <> "e215104d" -- time 1292899810
    <> "0100000000000000" -- services
    <> ipv4Bytes

-- | A ping with nonce 1. The checksum is the first four bytes of the double
-- SHA-256 of the eight payload bytes.
pingMessageHex :: Text
pingMessageHex =
  "f9beb4d9"
    <> "70696e670000000000000000" -- "ping"
    <> "08000000"
    <> "08533f6b"
    <> "0100000000000000"

-- | A verack. The checksum of an empty payload is 5df6e0e2.
verackMessageHex :: Text
verackMessageHex = "f9beb4d9" <> "76657261636b000000000000" <> "00000000" <> "5df6e0e2"

-- | Pay-to-pubkey-hash output script for the hash
-- 03f47604ea2736334151081e13265b4fe38e6fa8.
p2pkhHash :: ByteString
p2pkhHash = hex "03f47604ea2736334151081e13265b4fe38e6fa8"

p2pkhScript :: ByteString
p2pkhScript = hex "76a914" <> p2pkhHash <> hex "88ac"

-- | A transaction with one input and the given output scripts, each paying
-- 1000 satoshi.
txPaying :: [ByteString] -> Tx
txPaying scripts =
  Tx
    { version = 1,
      inputs =
        [ TxIn
            { outpoint = OutPoint "35fe9017b7e3af592920b56fa06ac02faf0c52cdb19dcb416129ac71c95d060e" 1,
              script = B.empty,
              sequence = 0xffffffff
            }
        ],
      outputs = [TxOut {value = 1000, script = s} | s <- scripts],
      witness = [],
      locktime = 0
    }

-- | The bytes of the outpoint of an output of a transaction, as inserted in
-- a bloom filter.
outpointBytes :: Tx -> Word32 -> ByteString
outpointBytes tx i = runPutS $ serialize $ OutPoint (txHash tx) i


-- | 'txPaying' [p2pkhScript] serialized: version, one input (outpoint hash
-- in internal byte order, index 1, empty script, sequence), one output
-- (1000 satoshi, 25-byte script), lock time.
oneInputTxHex :: Text
oneInputTxHex =
  "01000000"
    <> "01"
    <> "0e065dc971ac296141cb9db1cd520caf2fc06aa06fb5202959afe3b71790fe35"
    <> "01000000"
    <> "00"
    <> "ffffffff"
    <> "01"
    <> "e803000000000000"
    <> "19"
    <> "76a91403f47604ea2736334151081e13265b4fe38e6fa888ac"
    <> "00000000"

genesisHeaderHex :: Text
genesisHeaderHex =
  "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c"

knownCommands :: [MessageCommand]
knownCommands =
  [ MCVersion,
    MCVerAck,
    MCAddr,
    MCAddrV2,
    MCSendAddrV2,
    MCInv,
    MCGetData,
    MCNotFound,
    MCGetBlocks,
    MCGetHeaders,
    MCTx,
    MCBlock,
    MCMerkleBlock,
    MCHeaders,
    MCGetAddr,
    MCFilterLoad,
    MCFilterAdd,
    MCFilterClear,
    MCPing,
    MCPong,
    MCAlert,
    MCMempool,
    MCReject,
    MCSendHeaders,
    MCFeeFilter,
    MCSendCmpct,
    MCCmpctBlock,
    MCGetBlockTxn,
    MCBlockTxn,
    MCGetCFilters,
    MCCFilter,
    MCGetCFHeaders,
    MCCFHeaders,
    MCGetCFCheckpt,
    MCCFCheckpt,
    MCWtxidRelay,
    MCSendTxRcncl
  ]

-- Identity tests --------------------------------------------------------------

identityTests :: IdentityTests
identityTests =
  def
    { readTests =
        [ ReadBox arbitraryVarInt,
          ReadBox arbitraryVarString,
          ReadBox arbitraryAddressNetwork,
          ReadBox arbitraryNetworkAddressV2,
          ReadBox arbitraryInvType,
          ReadBox arbitraryAlert,
          ReadBox arbitraryFeeFilter,
          ReadBox arbitrarySendTxRcncl,
          ReadBox arbitraryReject,
          ReadBox arbitraryRejectCode,
          ReadBox arbitraryPing,
          ReadBox arbitraryPong,
          ReadBox arbitraryMessageCommand,
          ReadBox arbitraryBloomFlags,
          ReadBox arbitraryBloomFilter,
          ReadBox arbitraryFilterLoad,
          ReadBox arbitraryFilterAdd,
          ReadBox arbitrarySendCompact
        ],
      serialTests =
        [ SerialBox arbitraryVarInt,
          SerialBox arbitraryVarString,
          SerialBox arbitraryNetworkAddress,
          SerialBox arbitraryNetworkAddressV2,
          SerialBox arbitraryAddrV2,
          SerialBox arbitraryInvType,
          SerialBox arbitraryInvVector,
          SerialBox arbitraryInv1,
          SerialBox arbitraryVersion,
          SerialBox arbitraryAddr1,
          SerialBox arbitraryAlert,
          SerialBox arbitraryFeeFilter,
          SerialBox arbitrarySendTxRcncl,
          SerialBox arbitraryReject,
          SerialBox arbitraryRejectCode,
          SerialBox arbitraryGetData,
          SerialBox arbitraryNotFound,
          SerialBox arbitraryPing,
          SerialBox arbitraryPong,
          SerialBox arbitraryMessageCommand,
          SerialBox arbitraryMessageHeader,
          SerialBox arbitraryBloomFlags,
          SerialBox arbitraryBloomFilter,
          SerialBox arbitraryFilterLoad,
          SerialBox arbitraryFilterAdd,
          SerialBox arbitrarySendCompact,
          SerialBox arbitraryGetBlockTxn,
          SerialBox arbitraryGetCFilters,
          SerialBox arbitraryCFilter,
          SerialBox arbitraryGetCFHeaders,
          SerialBox arbitraryCFHeaders,
          SerialBox arbitraryGetCFCheckpt,
          SerialBox arbitraryCFCheckpt
        ]
    }

spec :: Spec
spec = prepareContext $ \ctx -> do
  testIdentity identityTests
  describe "Custom identity tests" $ do
    prop "Data.Serialize Encoding for type Message" $
      forAll arbitraryNetwork $ \net ->
        forAll (arbitraryMessage net ctx) $
          customCerealID (getMessage net) (putMessage net)
    prop "Binary encoding/decoding identity for CompactBlock" $
      forAll arbitraryNetwork $ \net ->
        forAll (arbitraryCompactBlock net ctx) $ \c ->
          parse (runPutS (serialize c)) == Right c
    prop "Binary encoding/decoding identity for BlockTxn" $
      forAll arbitraryNetwork $ \net ->
        forAll (arbitraryBlockTxn net ctx) $ \b ->
          parse (runPutS (serialize b)) == Right b
    prop "msgType is the command a message is sent with" $
      forAll arbitraryNetwork $ \net ->
        forAll (arbitraryMessage net ctx) $ \m ->
          fmap (.cmd) (parse (runPutS (putMessage net m)) :: Either String MessageHeader)
            == Right (msgType m)
  varIntSpec
  listSpec
  commandSpec
  inventorySpec
  addressSpec
  addrV2Spec
  versionSpec
  smallMessagesSpec
  rejectSpec
  framingSpec
  bloomSpec ctx
  compactBlockSpec
  blockFilterSpec
  constantsSpec

-- VarInt ----------------------------------------------------------------------

varIntSpec :: Spec
varIntSpec = describe "VarInt" $ do
  it "writes the shortest encoding at every boundary" $ do
    hexOf (VarInt 0) `shouldBe` "00"
    hexOf (VarInt 0xfc) `shouldBe` "fc"
    hexOf (VarInt 0xfd) `shouldBe` "fdfd00"
    hexOf (VarInt 0xffff) `shouldBe` "fdffff"
    hexOf (VarInt 0x10000) `shouldBe` "fe00000100"
    hexOf (VarInt 0xffffffff) `shouldBe` "feffffffff"
    hexOf (VarInt 0x100000000) `shouldBe` "ff0000000001000000"
    hexOf (VarInt 0xffffffffffffffff) `shouldBe` "ffffffffffffffffff"
  it "reads each encoding back" $ do
    parse (hex "00") `shouldBe` Right (VarInt 0)
    parse (hex "fc") `shouldBe` Right (VarInt 0xfc)
    parse (hex "fdfd00") `shouldBe` Right (VarInt 0xfd)
    parse (hex "fdffff") `shouldBe` Right (VarInt 0xffff)
    parse (hex "fe00000100") `shouldBe` Right (VarInt 0x10000)
    parse (hex "feffffffff") `shouldBe` Right (VarInt 0xffffffff)
    parse (hex "ff0000000001000000") `shouldBe` Right (VarInt 0x100000000)
    parse (hex "ffffffffffffffffff") `shouldBe` Right (VarInt 0xffffffffffffffff)
  it "refuses a three-byte encoding of a value below 253" $
    (parse (hex "fd0100") :: Either String VarInt) `failsWith` "non-canonical"
  it "refuses a five-byte encoding of a value below 0x10000" $
    (parse (hex "fe01000000") :: Either String VarInt) `failsWith` "non-canonical"
  it "refuses a nine-byte encoding of a value below 0x100000000" $
    (parse (hex "ff0100000000000000") :: Either String VarInt) `failsWith` "non-canonical"
  it "writes an Int with putVarInt like a VarInt" $
    encodeHex (runPutS (putVarInt (300 :: Int))) `shouldBe` "fd2c01"

-- Lists and byte strings -----------------------------------------------------

listSpec :: Spec
listSpec = describe "lists and byte strings" $ do
  it "limits counts to the MAX_SIZE of Bitcoin Core" $
    maxListSize `shouldBe` 33554432
  it "writes a byte string with its length in front" $ do
    hexOf (VarString "abc") `shouldBe` "03616263"
    hexOf (VarString "") `shouldBe` "00"
  it "reads a byte string" $
    parse (hex "03616263") `shouldBe` Right (VarString "abc")
  it "refuses a byte count above the limit" $
    -- 0x02000001 is one above the limit
    (parse (hex "fe01000002") :: Either String VarString) `failsWith` "Byte count too large"
  it "writes bytes with their count" $
    encodeHex (runPutS (putVarIntBytes "abc")) `shouldBe` "03616263"
  it "reads a list with its count" $
    runGetS (getVarIntList getWord8) (hex "020102") `shouldBe` Right [1, 2]
  it "writes a list with its count" $
    encodeHex (runPutS (putVarIntList putWord8 [1, 2])) `shouldBe` "020102"
  it "refuses a list count above the limit" $
    runGetS (getVarIntList getWord8) (hex "fe01000002") `failsWith` "List count too large"

-- Message commands -----------------------------------------------------------

commandSpec :: Spec
commandSpec = describe "message commands" $ do
  it "names every known command as Bitcoin Core does" $
    map commandToString knownCommands
      `shouldBe` [ "version",
                   "verack",
                   "addr",
                   "addrv2",
                   "sendaddrv2",
                   "inv",
                   "getdata",
                   "notfound",
                   "getblocks",
                   "getheaders",
                   "tx",
                   "block",
                   "merkleblock",
                   "headers",
                   "getaddr",
                   "filterload",
                   "filteradd",
                   "filterclear",
                   "ping",
                   "pong",
                   "alert",
                   "mempool",
                   "reject",
                   "sendheaders",
                   "feefilter",
                   "sendcmpct",
                   "cmpctblock",
                   "getblocktxn",
                   "blocktxn",
                   "getcfilters",
                   "cfilter",
                   "getcfheaders",
                   "cfheaders",
                   "getcfcheckpt",
                   "cfcheckpt",
                   "wtxidrelay",
                   "sendtxrcncl"
                 ]
  it "reads every known name back to its command" $
    forM_ knownCommands $ \c ->
      stringToCommand (commandToString c) `shouldBe` c
  it "reads an unknown name as an unknown command" $
    stringToCommand "foo" `shouldBe` MCOther "foo"
  it "pads a name with NUL bytes to twelve" $ do
    hexOf MCVersion `shouldBe` "76657273696f6e0000000000"
    hexOf MCPing `shouldBe` "70696e670000000000000000"
    hexOf MCSendTxRcncl `shouldBe` "73656e64747872636e636c00"
    hexOf (MCOther "foo") `shouldBe` "666f6f000000000000000000"
  it "reads a padded name" $ do
    parse (hex "76657273696f6e0000000000") `shouldBe` Right MCVersion
    parse (hex "666f6f000000000000000000") `shouldBe` Right (MCOther "foo")
  it "reads twelve NUL bytes as an empty unknown command" $
    parse (hex "000000000000000000000000") `shouldBe` Right (MCOther "")
  it "refuses a byte after the NUL terminator" $
    (parse "ping\0garbage" :: Either String MessageCommand) `failsWith` "after its NUL terminator"
  it "refuses a name with a byte outside printable ASCII" $
    -- "ping" followed by a line feed
    (parse (hex "70696e670a00000000000000") :: Either String MessageCommand) `failsWith` "printable ASCII"
  it "refuses to serialize a name longer than twelve bytes" $
    evaluate (runPutS (serialize (MCOther "averyverylongcommand"))) `shouldThrow` anyErrorCall
  it "refuses to serialize a name with a byte outside printable ASCII" $
    evaluate (runPutS (serialize (MCOther "ping\n"))) `shouldThrow` anyErrorCall
  it "shows and reads a command as its name" $ do
    show MCPing `shouldBe` "\"ping\""
    read "\"ping\"" `shouldBe` MCPing
    read "\"foo\"" `shouldBe` MCOther "foo"
    ("ping" :: MessageCommand) `shouldBe` MCPing

-- Inventory ------------------------------------------------------------------

inventorySpec :: Spec
inventorySpec = describe "inventory" $ do
  it "numbers every inventory type as Bitcoin Core does" $ do
    hexOf InvError `shouldBe` "00000000"
    hexOf InvTx `shouldBe` "01000000"
    hexOf InvBlock `shouldBe` "02000000"
    hexOf InvMerkleBlock `shouldBe` "03000000"
    hexOf InvCompactBlock `shouldBe` "04000000"
    hexOf InvWTx `shouldBe` "05000000"
    -- MSG_WITNESS_FLAG is 1 << 30, so 0x40000001 little-endian
    hexOf InvWitnessTx `shouldBe` "01000040"
    hexOf InvWitnessBlock `shouldBe` "02000040"
    hexOf InvWitnessMerkleBlock `shouldBe` "03000040"
    hexOf (InvType 7) `shouldBe` "07000000"
  it "reads every inventory type" $ do
    parse (hex "01000000") `shouldBe` Right InvTx
    parse (hex "05000000") `shouldBe` Right InvWTx
    parse (hex "02000040") `shouldBe` Right InvWitnessBlock
  it "reads an unknown inventory type as a number" $
    parse (hex "06000000") `shouldBe` Right (InvType 6)
  it "writes an inventory vector as its type then its hash" $
    hexOf (InvVector InvTx h1) `shouldBe` "01000000" <> h1Hex
  it "writes inv, getdata and notfound as a counted list of vectors" $ do
    hexOf (Inv [InvVector InvTx h1, InvVector InvBlock h2])
      `shouldBe` "02" <> "01000000" <> h1Hex <> "02000000" <> h2Hex
    hexOf (GetData [InvVector InvWitnessTx h1]) `shouldBe` "01" <> "01000040" <> h1Hex
    hexOf (NotFound [InvVector InvTx h1]) `shouldBe` "01" <> "01000000" <> h1Hex
  it "reads inv, getdata and notfound" $ do
    parse (hex ("01" <> "01000000" <> h1Hex)) `shouldBe` Right (Inv [InvVector InvTx h1])
    parse (hex ("01" <> "02000000" <> h1Hex)) `shouldBe` Right (GetData [InvVector InvBlock h1])
    parse (hex ("00")) `shouldBe` Right (NotFound [])

-- Network addresses ----------------------------------------------------------

addressSpec :: Spec
addressSpec = describe "network addresses" $ do
  it "maps an IPv4 address into IPv6 with the port in network byte order" $
    hexOf ipv4Host `shouldBe` ipv4Bytes
  it "reads an IPv4-mapped address back as an IPv4 socket address" $
    fmap hostToSockAddr (parse (hex ipv4Bytes))
      `shouldBe` Right (SockAddrInet 8333 (tupleToHostAddress (10, 0, 0, 1)))
  it "writes an IPv6 address as sixteen bytes then the port" $
    hexOf ipv6Host `shouldBe` ipv6Bytes
  it "reads an IPv6 address back" $
    fmap hostToSockAddr (parse (hex ipv6Bytes))
      `shouldBe` Right (SockAddrInet6 8333 0 (0x20010db8, 0, 0, 1) 0)
  it "refuses an address shorter than 18 bytes" $
    (parse (hex "00000000000000000000ffff0a000001") :: Either String HostAddress)
      `failsWith` "too few bytes"
  it "writes the services before the address" $
    hexOf (NetworkAddress 1 ipv4Host) `shouldBe` "0100000000000000" <> ipv4Bytes
  it "writes an addr entry with its time first" $
    hexOf (Addr [(1292899810, NetworkAddress 1 ipv4Host)])
      `shouldBe` "01" <> "e215104d" <> "0100000000000000" <> ipv4Bytes
  it "reads an addr message" $
    parse (hex ("01" <> "e215104d" <> "0100000000000000" <> ipv4Bytes))
      `shouldBe` Right (Addr [(1292899810, NetworkAddress 1 ipv4Host)])

-- addrv2 ----------------------------------------------------------------------

addrV2Spec :: Spec
addrV2Spec = describe "addrv2" $ do
  let ipv4Entry = NetworkAddressV2 1292899810 1 AddrIPv4 (hex "0a000001") 8333
      ipv4EntryHex = "e215104d" <> "01" <> "01" <> "04" <> "0a000001" <> "208d"
  it "numbers the networks as BIP 155 does" $
    map addressNetworkId [AddrIPv4, AddrIPv6, AddrTorV2, AddrTorV3, AddrI2P, AddrCJDNS, AddrYggdrasil, AddrUnknown 9]
      `shouldBe` [1, 2, 3, 4, 5, 6, 7, 9]
  it "knows the address length of every network" $
    map addressNetworkLength [AddrIPv4, AddrIPv6, AddrTorV2, AddrTorV3, AddrI2P, AddrCJDNS, AddrYggdrasil, AddrUnknown 9]
      `shouldBe` [Just 4, Just 16, Just 10, Just 32, Just 32, Just 16, Just 16, Nothing]
  it "limits an address to 512 bytes" $
    maxAddrV2Size `shouldBe` 512
  it "writes an IPv4 entry with time, services as a VarInt, network, address and port" $
    hexOf ipv4Entry `shouldBe` ipv4EntryHex
  it "writes services of more than one byte as a VarInt" $
    -- 1024 is NODE_NETWORK_LIMITED
    hexOf (NetworkAddressV2 0 1024 AddrIPv6 (B.replicate 16 0) 0)
      `shouldBe` "00000000" <> "fd0004" <> "02" <> "10" <> T.replicate 32 "0" <> "0000"
  it "writes a Tor v3 entry with 32 address bytes and no port" $
    hexOf (NetworkAddressV2 0 0 AddrTorV3 (B.replicate 32 0xab) 0)
      `shouldBe` "00000000" <> "00" <> "04" <> "20" <> T.replicate 32 "ab" <> "0000"
  it "reads an entry" $
    parse (hex ipv4EntryHex) `shouldBe` Right ipv4Entry
  it "refuses an IPv4 entry whose address is not four bytes" $
    (parse (hex ("00000000" <> "00" <> "01" <> "05" <> "0a00000102" <> "208d")) :: Either String NetworkAddressV2)
      `failsWith` "should be 4"
  it "keeps an entry of an unknown network with its bytes" $
    parse (hex ("00000000" <> "00" <> "c8" <> "03" <> "aabbcc" <> "0000"))
      `shouldBe` Right (NetworkAddressV2 0 0 (AddrUnknown 200) (hex "aabbcc") 0)
  it "accepts an address of 512 bytes" $
    parse (hex ("00000000" <> "00" <> "c8" <> "fd0002") <> B.replicate 512 0x11 <> hex "0000")
      `shouldBe` Right (NetworkAddressV2 0 0 (AddrUnknown 200) (B.replicate 512 0x11) 0)
  it "refuses an address of 513 bytes" $
    (parse (hex ("00000000" <> "00" <> "c8" <> "fd0102") <> B.replicate 513 0x11 <> hex "0000") :: Either String NetworkAddressV2)
      `failsWith` "too long"
  it "writes an addrv2 message as a counted list of entries" $
    hexOf (AddrV2 [ipv4Entry, ipv4Entry]) `shouldBe` "02" <> ipv4EntryHex <> ipv4EntryHex
  it "turns an addr entry into an addrv2 entry" $
    toNetworkAddressV2 (1292899810, NetworkAddress 1 ipv4Host) `shouldBe` ipv4Entry
  it "keeps an IPv6 entry as sixteen bytes" $
    toNetworkAddressV2 (0, NetworkAddress 0 ipv6Host)
      `shouldBe` NetworkAddressV2 0 0 AddrIPv6 (hex "20010db8000000000000000000000001") 8333
  it "turns an addrv2 entry back into an addr entry" $ do
    fromNetworkAddressV2 ipv4Entry `shouldBe` Just (1292899810, NetworkAddress 1 ipv4Host)
    fromNetworkAddressV2 (NetworkAddressV2 0 0 AddrIPv6 (hex "20010db8000000000000000000000001") 8333)
      `shouldBe` Just (0, NetworkAddress 0 ipv6Host)
  it "has no addr form for a Tor address" $
    fromNetworkAddressV2 (NetworkAddressV2 0 0 AddrTorV3 (B.replicate 32 0) 0) `shouldBe` Nothing

-- Version ---------------------------------------------------------------------

versionSpec :: Spec
versionSpec = describe "version" $ do
  it "reads the version message of the protocol documentation" $
    (parse (hex versionPayloadHex) :: Either String Version) `shouldBe` Right wikiVersion
  it "reads the relay flag" $ do
    parse (hex (versionPayloadHex <> "00")) `shouldBe` Right wikiVersion {relay = False}
    parse (hex (versionPayloadHex <> "01")) `shouldBe` Right wikiVersion
  it "treats any other relay byte as true, as Bitcoin Core does" $
    parse (hex (versionPayloadHex <> "07")) `shouldBe` Right wikiVersion
  it "writes the relay flag after the start height" $
    hexOf wikiVersion `shouldBe` versionPayloadHex <> "01"
  it "limits the user agent to 256 bytes" $
    maxUserAgentLength `shouldBe` 256
  it "accepts a user agent of 256 bytes" $
    -- the 80 bytes before the user agent, then a 256-byte agent of "A"s
    let ua = hex "fd0001" <> B.replicate 256 0x41
        payload = hex (T.take 160 versionPayloadHex) <> ua <> hex "c03e030001"
     in fmap (\v -> B.length v.userAgent.get) (parse payload :: Either String Version)
          `shouldBe` Right 256
  it "refuses a user agent of 257 bytes" $
    let ua = hex "fd0101" <> B.replicate 257 0x41
        payload = hex (T.take 160 versionPayloadHex) <> ua <> hex "c03e030001"
     in (parse payload :: Either String Version) `failsWith` "too long"

-- Ping, pong, feefilter, sendtxrcncl, alert ----------------------------------

smallMessagesSpec :: Spec
smallMessagesSpec = describe "small messages" $ do
  it "writes ping and pong as a little-endian nonce" $ do
    hexOf (Ping 1) `shouldBe` "0100000000000000"
    hexOf (Pong 0x0102030405060708) `shouldBe` "0807060504030201"
  it "reads ping and pong" $ do
    parse (hex "0100000000000000") `shouldBe` Right (Ping 1)
    parse (hex "0807060504030201") `shouldBe` Right (Pong 0x0102030405060708)
  it "writes feefilter as a little-endian fee rate" $
    hexOf (FeeFilter 1000) `shouldBe` "e803000000000000"
  it "reads feefilter" $
    parse (hex "e803000000000000") `shouldBe` Right (FeeFilter 1000)
  it "writes sendtxrcncl as version then salt" $
    hexOf (SendTxRcncl 1 0x0102030405060708) `shouldBe` "01000000" <> "0807060504030201"
  it "reads sendtxrcncl" $
    parse (hex ("01000000" <> "0807060504030201")) `shouldBe` Right (SendTxRcncl 1 0x0102030405060708)
  it "writes an alert as two byte strings" $
    hexOf (Alert (VarString "ab") (VarString "c")) `shouldBe` "026162" <> "0163"
  it "reads an alert" $
    parse (hex ("026162" <> "0163")) `shouldBe` Right (Alert (VarString "ab") (VarString "c"))

-- Reject ----------------------------------------------------------------------

rejectSpec :: Spec
rejectSpec = describe "reject" $ do
  it "uses the code bytes of BIP 61" $
    map hexOf [RejectMalformed, RejectInvalid, RejectObsolete, RejectDuplicate, RejectNonStandard, RejectDust, RejectInsufficientFee, RejectCheckpoint]
      `shouldBe` ["01", "10", "11", "12", "40", "41", "42", "43"]
  it "reads every code" $
    forM_ [RejectMalformed, RejectInvalid, RejectObsolete, RejectDuplicate, RejectNonStandard, RejectDust, RejectInsufficientFee, RejectCheckpoint] $ \c ->
      parse (runPutS (serialize c)) `shouldBe` Right c
  it "refuses an unknown code" $
    (parse (hex "02") :: Either String RejectCode) `failsWith` "Invalid code"
  it "builds a reject without a hash" $
    (reject MCTx RejectDust "dust").extra `shouldBe` Nothing
  it "writes the command, code and reason, and no hash when there is none" $
    hexOf (reject MCTx RejectInvalid "bad") `shouldBe` "027478" <> "10" <> "03626164"
  it "writes the hash after the reason" $
    hexOf (Reject MCBlock RejectCheckpoint (VarString "") (Just h1))
      `shouldBe` "05626c6f636b" <> "43" <> "00" <> h1Hex
  it "reads a reject without a hash" $
    parse (hex ("027478" <> "10" <> "03626164")) `shouldBe` Right (reject MCTx RejectInvalid "bad")
  it "reads a reject with a hash" $
    parse (hex ("05626c6f636b" <> "43" <> "00" <> h1Hex))
      `shouldBe` Right (Reject MCBlock RejectCheckpoint (VarString "") (Just h1))
  it "refuses extra data that is not a hash" $
    (parse (hex ("027478" <> "10" <> "00" <> "0102030405")) :: Either String Reject) `failsWith` "too few bytes"

-- Message framing -------------------------------------------------------------

framingSpec :: Spec
framingSpec = describe "message framing" $ do
  it "writes a header as big-endian magic, padded command, little-endian length and checksum" $
    encodeHex (runPutS (putMessage btc MVerAck)) `shouldBe` verackMessageHex
  it "writes the payload after the header" $
    encodeHex (runPutS (putMessage btc (MPing (Ping 1)))) `shouldBe` pingMessageHex
  it "uses the magic of the network" $
    T.take 8 (encodeHex (runPutS (putMessage bch MVerAck))) `shouldBe` "e3e1f3e8"
  it "reads a header" $
    fmap (\h -> (h.magic, h.cmd, h.size)) (parse (hex verackMessageHex) :: Either String MessageHeader)
      `shouldBe` Right (0xf9beb4d9, MCVerAck, 0)
  it "writes a header back as it was" $
    fmap hexOf (parse (hex verackMessageHex) :: Either String MessageHeader) `shouldBe` Right verackMessageHex
  it "reads the verack message of the protocol documentation" $
    runGetS (getMessage btc) (hex verackMessageHex) `shouldBe` Right MVerAck
  it "reads the version message of the protocol documentation" $
    runGetS (getMessage btc) (hex versionMessageHex) `shouldBe` Right (MVersion wikiVersion)
  it "reads the addr message of the protocol documentation" $
    runGetS (getMessage btc) (hex addrMessageHex)
      `shouldBe` Right (MAddr (Addr [(1292899810, NetworkAddress 1 ipv4Host)]))
  it "refuses a message of another network" $
    runGetS (getMessage btcTest) (hex pingMessageHex) `failsWith` "Invalid network magic"
  it "refuses a message whose checksum does not match its payload" $
    runGetS (getMessage btc) (B.take 24 (hex pingMessageHex) <> hex "0200000000000000")
      `failsWith` "Invalid message checksum"
  it "refuses a length above maxMessageSize before reading the payload" $
    -- 4000001 is one above the limit of btc, written little-endian
    runGetS (getMessage btc) (hex ("f9beb4d9" <> "70696e670000000000000000" <> "01093d00" <> "5df6e0e2"))
      `failsWith` "larger than the limit"
  it "reads one message and leaves the next one in the stream" $
    runGetS ((,) <$> getMessage btc <*> getMessage btc) (hex (pingMessageHex <> verackMessageHex))
      `shouldBe` Right (MPing (Ping 1), MVerAck)
  it "hands the payload parser only the declared bytes" $
    -- a ping declared as 4 bytes, followed by 4 bytes that belong to nothing
    let payload = hex "01000000"
        msg = hex ("f9beb4d9" <> "70696e670000000000000000" <> "04000000") <> runPutS (serialize (checkSum32 payload)) <> payload <> hex "deadbeef"
     in runGetS (getMessage btc) msg `failsWith` "too few bytes"
  it "accepts a payload on a message type that carries none" $
    let payload = hex "00"
        msg = hex ("f9beb4d9" <> "76657261636b000000000000" <> "01000000") <> runPutS (serialize (checkSum32 payload)) <> payload
     in runGetS (getMessage btc) msg `shouldBe` Right MVerAck
  it "refuses a message type that needs a payload without one" $
    runGetS (getMessage btc) (hex ("f9beb4d9" <> "70696e670000000000000000" <> "00000000" <> "5df6e0e2"))
      `failsWith` "too few bytes"
  it "keeps the command and payload of an unknown message" $
    let payload = hex "616263"
        msg = hex ("f9beb4d9" <> "666f6f000000000000000000" <> "03000000") <> runPutS (serialize (checkSum32 payload)) <> payload
     in do
          runGetS (getMessage btc) msg `shouldBe` Right (MOther "foo" "abc")
          runPutS (putMessage btc (MOther "foo" "abc")) `shouldBe` msg
  it "gives each message its command" $ do
    msgType MVerAck `shouldBe` MCVerAck
    msgType (MPing (Ping 1)) `shouldBe` MCPing
    msgType MWtxidRelay `shouldBe` MCWtxidRelay
    msgType MSendAddrV2 `shouldBe` MCSendAddrV2
    msgType (MOther "foo" "") `shouldBe` MCOther "foo"

-- Bloom filters ---------------------------------------------------------------

bloomSpec :: Ctx -> Spec
bloomSpec ctx = describe "bloom filters" $ do
  describe "test vectors of Bitcoin Core" $ do
    it "bloom filter vector 1" bloomFilter1
    it "bloom filter vector 2" bloomFilter2
    it "bloom filter vector 3" $ bloomFilter3 ctx
  describe "bloomCreate" $ do
    it "sizes the filter for the elements and false positive rate" $ do
      -- 3 elements at 1%: 3 bytes and 5 hash functions, as in the vectors
      let f = bloomCreate 3 0.01 0 BloomUpdateAll
      S.length f.array `shouldBe` 3
      f.functions `shouldBe` 5
      -- 20000 elements at 0.1%: 20000 * 6.9078 / 0.48045 = 287552 bits,
      -- 35943 bytes; 35943 * 8 / 20000 * 0.6931 = 9.97, so 9 functions
      let g = bloomCreate 20000 0.001 0 BloomUpdateAll
      S.length g.array `shouldBe` 35943
      g.functions `shouldBe` 9
    it "caps the size at 36000 bytes and the hash functions at 50" $ do
      let f = bloomCreate 100000 0.01 0 BloomUpdateAll
      S.length f.array `shouldBe` 36000
      -- 36000 * 8 / 100000 * 0.6931 = 1.99, so 1 function
      f.functions `shouldBe` 1
      -- 1 element at 1e-20: 46.05 / 0.48045 = 95.85 bits, 11 bytes;
      -- 11 * 8 * 0.6931 = 60.99, capped at 50 functions
      let g = bloomCreate 1 1e-20 0 BloomUpdateAll
      S.length g.array `shouldBe` 11
      g.functions `shouldBe` 50
    it "gives zero hash functions when the elements outnumber the capped size" $
      -- 36000 * 8 / 1000000 * 0.6931 = 0.19
      (bloomCreate 1000000 0.01 0 BloomUpdateAll).functions `shouldBe` 0
    it "makes an empty filter for zero elements" $ do
      let f = bloomCreate 0 0.01 0 BloomUpdateAll
      S.length f.array `shouldBe` 0
      f.functions `shouldBe` 0
    it "keeps the tweak and flags" $ do
      let f = bloomCreate 3 0.01 7 BloomUpdateP2PubKeyOnly
      f.tweak `shouldBe` 7
      f.flags `shouldBe` BloomUpdateP2PubKeyOnly
  describe "bloomContains and bloomInsert" $ do
    it "does not match data that was not inserted" $
      bloomContains (bloomCreate 3 0.01 0 BloomUpdateAll) "abc" `shouldBe` False
    it "matches everything with no hash functions" $
      bloomContains (BloomFilter (S.replicate 10 0xaa) 0 0 BloomUpdateAll) "abc" `shouldBe` True
    it "changes nothing when inserting with no hash functions" $
      bloomInsert (BloomFilter (S.replicate 2 0) 0 0 BloomUpdateAll) "abc"
        `shouldBe` BloomFilter (S.replicate 2 0) 0 0 BloomUpdateAll
    it "matches everything with an empty filter" $
      bloomContains (BloomFilter S.empty 5 0 BloomUpdateAll) "abc" `shouldBe` True
    it "changes nothing when inserting into an empty filter" $
      bloomInsert (BloomFilter S.empty 5 0 BloomUpdateAll) "abc"
        `shouldBe` BloomFilter S.empty 5 0 BloomUpdateAll
    it "matches everything when every bit is set" $
      bloomContains (BloomFilter (S.replicate 3 0xff) 5 0 BloomUpdateAll) "abc" `shouldBe` True
  describe "serialization" $ do
    it "writes the bytes with their count, then functions, tweak and flags" $
      -- the first vector of Bitcoin Core after inserting its three elements
      hexOf (BloomFilter (S.fromList [0x61, 0x4e, 0x9b]) 5 0 BloomUpdateAll)
        `shouldBe` "03614e9b" <> "05000000" <> "00000000" <> "01"
    it "reads a filter" $
      parse (hex ("03614e9b" <> "05000000" <> "00000000" <> "01"))
        `shouldBe` Right (BloomFilter (S.fromList [0x61, 0x4e, 0x9b]) 5 0 BloomUpdateAll)
    it "writes the flags as one byte" $
      map hexOf [BloomUpdateNone, BloomUpdateAll, BloomUpdateP2PubKeyOnly] `shouldBe` ["00", "01", "02"]
    it "reads only the two low bits of the flags, as Bitcoin Core does" $ do
      parse (hex "03") `shouldBe` Right BloomUpdateNone
      parse (hex "81") `shouldBe` Right BloomUpdateAll
      parse (hex "82") `shouldBe` Right BloomUpdateP2PubKeyOnly
    it "accepts the largest filter a peer may load" $
      let f = BloomFilter (S.replicate 36000 0x55) 50 0 BloomUpdateAll
       in parse (runPutS (serialize f)) `shouldBe` Right f
    it "refuses a filter of 36001 bytes" $
      (parse (runPutS (serialize (BloomFilter (S.replicate 36001 0) 1 0 BloomUpdateAll))) :: Either String BloomFilter)
        `failsWith` "too large"
    it "refuses a filter with 51 hash functions" $
      (parse (runPutS (serialize (BloomFilter (S.replicate 1 0) 51 0 BloomUpdateAll))) :: Either String BloomFilter)
        `failsWith` "too many"
    it "refuses a byte count that does not fit the input" $
      -- 2^64 - 1 bytes announced
      (parse (hex ("ffffffffffffffffff" <> "01000000" <> "00000000" <> "01")) :: Either String BloomFilter)
        `failsWith` "too large"
    it "writes filterload as the filter" $
      hexOf (FilterLoad (BloomFilter (S.fromList [0x61]) 1 0 BloomUpdateNone)) `shouldBe` "0161" <> "01000000" <> "00000000" <> "00"
    it "writes filteradd as the element with its length" $
      hexOf (FilterAdd "abc") `shouldBe` "03616263"
    it "accepts a filteradd element of 520 bytes" $
      parse (hex "fd0802" <> B.replicate 520 0x11) `shouldBe` Right (FilterAdd (B.replicate 520 0x11))
    it "refuses a filteradd element of 521 bytes" $
      (parse (hex "fd0902" <> B.replicate 521 0x11) :: Either String FilterAdd) `failsWith` "too long"
  describe "limits" $ do
    it "knows the limits of BIP 37" $ do
      maxBloomSize `shouldBe` 36000
      maxHashFuncs `shouldBe` 50
      maxFilterAddSize `shouldBe` 520
    it "isBloomValid accepts the limits and refuses one more" $ do
      isBloomValid (BloomFilter (S.replicate 36000 0) 50 0 BloomUpdateAll) `shouldBe` True
      isBloomValid (BloomFilter (S.replicate 36001 0) 50 0 BloomUpdateAll) `shouldBe` False
      isBloomValid (BloomFilter (S.replicate 36000 0) 51 0 BloomUpdateAll) `shouldBe` False
    it "isBloomEmpty is true for all-zero bytes" $ do
      isBloomEmpty (BloomFilter (S.fromList [0, 0]) 1 0 BloomUpdateAll) `shouldBe` True
      isBloomEmpty (BloomFilter (S.fromList [0, 1]) 1 0 BloomUpdateAll) `shouldBe` False
    it "isBloomFull is true for all-0xff bytes" $ do
      isBloomFull (BloomFilter (S.fromList [0xff, 0xff]) 1 0 BloomUpdateAll) `shouldBe` True
      isBloomFull (BloomFilter (S.fromList [0xff, 0xfe]) 1 0 BloomUpdateAll) `shouldBe` False
    it "acceptsFilters looks at the NODE_BLOOM bit" $ do
      acceptsFilters 4 `shouldBe` True
      acceptsFilters 5 `shouldBe` True
      acceptsFilters 1 `shouldBe` False
      acceptsFilters 0 `shouldBe` False
  describe "scriptPushData" $ do
    it "lists the data pushed by a pay-to-pubkey-hash script" $
      scriptPushData p2pkhScript `shouldBe` [p2pkhHash]
    it "lists nothing for a script without pushes" $
      scriptPushData (hex "51") `shouldBe` []
    it "lists every push of an OP_RETURN script" $
      scriptPushData (hex "6a" <> hex "0111" <> hex "022233") `shouldBe` [hex "11", hex "2233"]
    it "leaves out empty pushes" $
      scriptPushData (hex "00" <> hex "0111") `shouldBe` [hex "11"]
    it "keeps the pushes before a truncated one" $
      -- a two-byte push, then OP_PUSHDATA1 with no length byte
      scriptPushData (hex "02aabb" <> hex "4c") `shouldBe` [hex "aabb"]
  describe "bloomRelevantUpdate" $ do
    it "inserts the outpoint of a matching output under BloomUpdateAll" relevantOutputUpdated
    it "gives Nothing for a transaction with no matching output" irrelevantOutputNotUpdated
    it "leaves the filter as it is for a matching pay-to-pubkey-hash output under BloomUpdateP2PubKeyOnly" $ do
      let bf = bloomInsert (bloomCreate 10 0.000001 0 BloomUpdateP2PubKeyOnly) p2pkhHash
      bloomRelevantUpdate ctx bf (txPaying [p2pkhScript]) `shouldBe` Just bf
    it "inserts the outpoint of a matching pay-to-pubkey output under BloomUpdateP2PubKeyOnly" $ do
      let k = fromJust $ fromWif btc "5Kg1gnAjaLfKiwhhPpGS3QfRg2m6awQvaj98JCZBZQ5SuS2F15C"
          p = derivePublicKey ctx k
          bf = bloomInsert (bloomCreate 10 0.000001 0 BloomUpdateP2PubKeyOnly) (marshal ctx p)
          tx = txPaying [marshal ctx (PayPK p)]
      fmap (`bloomContains` outpointBytes tx 0) (bloomRelevantUpdate ctx bf tx) `shouldBe` Just True
    it "leaves the filter as it is under BloomUpdateNone" $ do
      let bf = bloomInsert (bloomCreate 10 0.000001 0 BloomUpdateNone) p2pkhHash
      bloomRelevantUpdate ctx bf (txPaying [p2pkhScript]) `shouldBe` Just bf
    it "scans a non-standard output script without failing" $ do
      let bf = bloomInsert (bloomCreate 10 0.000001 0 BloomUpdateAll) p2pkhHash
      bloomRelevantUpdate ctx bf (txPaying [hex "51"]) `shouldBe` Nothing
    it "matches a push inside a non-standard output script" $ do
      let bf = bloomInsert (bloomCreate 10 0.000001 0 BloomUpdateAll) p2pkhHash
          -- push the hash, drop it, then OP_TRUE
          tx = txPaying [hex "14" <> p2pkhHash <> hex "7551"]
      fmap (`bloomContains` outpointBytes tx 0) (bloomRelevantUpdate ctx bf tx) `shouldBe` Just True
    it "still finds the matching output next to a non-standard one" $ do
      let bf = bloomInsert (bloomCreate 10 0.000001 0 BloomUpdateAll) p2pkhHash
          tx = txPaying [hex "51", p2pkhScript]
      fmap (`bloomContains` outpointBytes tx 1) (bloomRelevantUpdate ctx bf tx) `shouldBe` Just True
    it "matches every output with an empty filter and changes nothing" $ do
      let bf = BloomFilter S.empty 0 0 BloomUpdateAll
      bloomRelevantUpdate ctx bf (txPaying [hex "51"]) `shouldBe` Just bf
    it "does not insert the outpoint of an output that does not match" $ do
      let bf = bloomInsert (bloomCreate 10 0.000001 0 BloomUpdateAll) p2pkhHash
          tx = txPaying [p2pkhScript, hex "76a914" <> B.replicate 20 0x42 <> hex "88ac"]
      fmap (`bloomContains` outpointBytes tx 1) (bloomRelevantUpdate ctx bf tx) `shouldBe` Just False

bloomFilter :: Word32 -> Text -> Expectation
bloomFilter n x = do
  bloomContains f1 v1 `shouldBe` True
  bloomContains f1 v2 `shouldBe` False
  bloomContains f3 v3 `shouldBe` True
  bloomContains f4 v4 `shouldBe` True
  runPutS (serialize f4) `shouldBe` bs
  where
    f0 = bloomCreate 3 0.01 n BloomUpdateAll
    f1 = bloomInsert f0 v1
    f3 = bloomInsert f1 v3
    f4 = bloomInsert f3 v4
    v1 = hex "99108ad8ed9bb6274d3980bab5a85c048f0950c8"
    v2 = hex "19108ad8ed9bb6274d3980bab5a85c048f0950c8"
    v3 = hex "b5a2c786d9ef4658287ced5914b37a1b4aa32eee"
    v4 = hex "b9300670b4c5366e95b2699e8b18bc75e5f729c5"
    bs = hex x

bloomFilter1 :: Expectation
bloomFilter1 = bloomFilter 0 "03614e9b050000000000000001"

bloomFilter2 :: Expectation
bloomFilter2 = bloomFilter 2147483649 "03ce4299050000000100008001"

bloomFilter3 :: Ctx -> Expectation
bloomFilter3 ctx =
  runPutS (serialize f2) `shouldBe` bs
  where
    f0 = bloomCreate 2 0.001 0 BloomUpdateAll
    f1 = bloomInsert f0 $ marshal ctx p
    f2 = bloomInsert f1 $ runPutS $ serialize $ fromJust $ addressHash160 $ pubKeyAddr ctx p
    k = fromJust $ fromWif btc "5Kg1gnAjaLfKiwhhPpGS3QfRg2m6awQvaj98JCZBZQ5SuS2F15C"
    p = derivePublicKey ctx k
    bs = hex "038fc16b080000000000000001"

-- | The first output of 'relevantTx' pays the hash in the filter. Its
-- outpoint, which 'spendRelevantTx' spends with its first input, must be in
-- the updated filter. The second output pays somewhere else and its outpoint
-- must not be.
relevantOutputUpdated :: Expectation
relevantOutputUpdated = do
  bloomContains bf2 (outpoint <> hex "00000000") `shouldBe` True
  bloomContains bf2 (outpoint <> hex "01000000") `shouldBe` False
  where
    bf0 = bloomCreate 10 0.000001 0 BloomUpdateAll
    bf1 = bloomInsert bf0 p2pkhHash
    bf2 = fromJust $ bloomRelevantUpdate undefined' bf1 relevantTx
    -- txid 57dc904f32ad4daab7b321dd469e8791ad09df784cdd273a73985150a4f225e9
    -- in internal byte order
    outpoint = hex "e925f2a4505198733a27dd4c78df09ad91879e46dd21b3b7aa4dad324f90dc57"
    undefined' = error "bloomRelevantUpdate must not need the context for pay-to-pubkey-hash under BloomUpdateAll"

irrelevantOutputNotUpdated :: Expectation
irrelevantOutputNotUpdated = bloomRelevantUpdate undefined' bf1 unrelatedTx `shouldBe` Nothing
  where
    bf0 = bloomCreate 10 0.000001 0 BloomUpdateAll
    bf1 = bloomInsert bf0 p2pkhHash
    undefined' = error "bloomRelevantUpdate must not need the context when nothing matches"

-- Random transaction (57dc904f32ad4daab7b321dd469e8791ad09df784cdd273a73985150a4f225e9)
relevantTx :: Tx
relevantTx =
  Tx
    { version = 1,
      inputs =
        [ TxIn
            { outpoint = OutPoint "35fe9017b7e3af592920b56fa06ac02faf0c52cdb19dcb416129ac71c95d060e" 1,
              script = fromJust $ decodeHex "473044022032fc8eef299b7e94b9a986a6aa2dcb9733ab804bef80df995e443b9c1f8c604202203335df7a2e2b4789451cdb4b2b05a786a81c51519eb6a567fd6fe8cd7b2d33fe014104272502dc63a512dad1473cb82a71be9baf4f4303abd1ff6028fc8a78e1f3aec1218907119dec14f07354850758ff0948e88a904fa411c4df7d5444414ec64ad6",
              sequence = 4294967295
            }
        ],
      outputs =
        [ TxOut {value = 100000000, script = fromJust $ decodeHex "76a91403f47604ea2736334151081e13265b4fe38e6fa888ac"},
          TxOut {value = 107980000, script = fromJust $ decodeHex "76a91481cc186a2f4a69f633ed4bf10ef4a78be13effdd88ac"}
        ],
      witness = [],
      locktime = 0
    }

-- This random transaction is unrelated to the others
unrelatedTx :: Tx
unrelatedTx =
  Tx
    { version = 1,
      inputs =
        [ TxIn
            { outpoint = OutPoint "3ec3a71431c68e5d978a5fb4a0a1081d8bee8384d8aa4c06b1fbaf9413e2214f" 20,
              script = fromJust $ decodeHex "483045022100ec9c202c9d3140b973aca9d7f21a82138aa4cfa43fddc5419098ac5e26a6f152022010848fd688f290ae010fb5cb493410caa03145fc12445900ec1ad2bde33aecd9012102c7445e72d723f99a0064526c28269d07f47c8fd81531a94a8d3bf5ebd5e23ef1",
              sequence = 4294967295
            }
        ],
      outputs =
        [ TxOut {value = 12600000, script = fromJust $ decodeHex "76a9148fef3b7051de8cc44e966159e7ea37f4520187e888ac"}
        ],
      witness = [],
      locktime = 0
    }

-- Compact blocks --------------------------------------------------------------

compactBlockSpec :: Spec
compactBlockSpec = describe "compact blocks" $ do
  it "writes sendcmpct as a flag byte and a little-endian version" $
    hexOf (SendCompact True 2) `shouldBe` "01" <> "0200000000000000"
  it "reads sendcmpct" $
    parse (hex ("00" <> "0100000000000000")) `shouldBe` Right (SendCompact False 1)
  it "limits short ids to six bytes" $
    maxShortId `shouldBe` 0xffffffffffff
  it "writes getblocktxn positions as the distance from the previous one minus one" $
    hexOf (GetBlockTxn bh1 [0, 1, 5]) `shouldBe` bh1Hex <> "03" <> "00" <> "00" <> "03"
  it "reads getblocktxn positions" $
    parse (hex (bh1Hex <> "03" <> "00" <> "00" <> "03")) `shouldBe` Right (GetBlockTxn bh1 [0, 1, 5])
  it "reads a first position that is not zero" $
    parse (hex (bh1Hex <> "02" <> "07" <> "00")) `shouldBe` Right (GetBlockTxn bh1 [7, 8])
  it "refuses positions that do not increase" $
    evaluate (runPutS (serialize (GetBlockTxn bh1 [1, 1]))) `shouldThrow` anyErrorCall
  it "refuses a position beyond 32 bits" $
    -- 0 then a distance of 0xffffffff, which lands on 2^32
    (parse (hex (bh1Hex <> "02" <> "00" <> "feffffffff")) :: Either String GetBlockTxn)
      `failsWith` "does not fit 32 bits"
  it "writes a compact block as header, nonce, short ids and prefilled transactions" $
    hexOf (CompactBlock btc.genesisHeader 0x0102030405060708 [1, maxShortId] [PrefilledTx 0 (txPaying [p2pkhScript])])
      `shouldBe` genesisHeaderHex
        <> "0807060504030201"
        <> "02"
        <> "010000000000"
        <> "ffffffffffff"
        <> "01"
        <> "00"
        <> oneInputTxHex
  it "reads a compact block" $
    parse (hex (genesisHeaderHex <> "0807060504030201" <> "02" <> "010000000000" <> "ffffffffffff" <> "01" <> "00" <> oneInputTxHex))
      `shouldBe` Right (CompactBlock btc.genesisHeader 0x0102030405060708 [1, maxShortId] [PrefilledTx 0 (txPaying [p2pkhScript])])
  it "writes prefilled positions as distances too" $
    let tx = txPaying [p2pkhScript]
     in hexOf (CompactBlock btc.genesisHeader 0 [] [PrefilledTx 0 tx, PrefilledTx 2 tx])
          `shouldBe` genesisHeaderHex <> "0000000000000000" <> "00" <> "02" <> "00" <> oneInputTxHex <> "01" <> oneInputTxHex
  it "refuses a short id wider than six bytes" $
    evaluate (runPutS (serialize (CompactBlock btc.genesisHeader 0 [maxShortId + 1] []))) `shouldThrow` anyErrorCall
  it "writes blocktxn as the block hash and the transactions" $
    hexOf (BlockTxn bh1 [txPaying [p2pkhScript]]) `shouldBe` bh1Hex <> "01" <> oneInputTxHex
  it "reads blocktxn" $
    parse (hex (bh1Hex <> "01" <> oneInputTxHex)) `shouldBe` Right (BlockTxn bh1 [txPaying [p2pkhScript]])

-- Block filters ---------------------------------------------------------------

blockFilterSpec :: Spec
blockFilterSpec = describe "block filters" $ do
  it "numbers the basic filter type zero" $
    basicFilterType `shouldBe` 0
  it "writes getcfilters as type, little-endian start height and stop hash" $
    hexOf (GetCFilters 0 1000 bh1) `shouldBe` "00" <> "e8030000" <> bh1Hex
  it "reads getcfilters" $
    parse (hex ("00" <> "e8030000" <> bh1Hex)) `shouldBe` Right (GetCFilters 0 1000 bh1)
  it "writes cfilter as type, block hash and the filter with its length" $
    hexOf (CFilter 0 bh1 (hex "abcd")) `shouldBe` "00" <> bh1Hex <> "02abcd"
  it "reads cfilter" $
    parse (hex ("00" <> bh1Hex <> "02abcd")) `shouldBe` Right (CFilter 0 bh1 (hex "abcd"))
  it "writes getcfheaders like getcfilters" $
    hexOf (GetCFHeaders basicFilterType 2000 bh1) `shouldBe` "00" <> "d0070000" <> bh1Hex
  it "reads getcfheaders" $
    parse (hex ("00" <> "d0070000" <> bh1Hex)) `shouldBe` Right (GetCFHeaders 0 2000 bh1)
  it "writes cfheaders as type, stop hash, previous header and the counted hashes" $
    hexOf (CFHeaders 0 bh1 h1 [h2, h3]) `shouldBe` "00" <> bh1Hex <> h1Hex <> "02" <> h2Hex <> h3Hex
  it "reads cfheaders" $
    parse (hex ("00" <> bh1Hex <> h1Hex <> "02" <> h2Hex <> h3Hex)) `shouldBe` Right (CFHeaders 0 bh1 h1 [h2, h3])
  it "writes getcfcheckpt as type and stop hash" $
    hexOf (GetCFCheckpt 0 bh1) `shouldBe` "00" <> bh1Hex
  it "reads getcfcheckpt" $
    parse (hex ("00" <> bh1Hex)) `shouldBe` Right (GetCFCheckpt 0 bh1)
  it "writes cfcheckpt as type, stop hash and the counted headers" $
    hexOf (CFCheckpt 0 bh1 [h1]) `shouldBe` "00" <> bh1Hex <> "01" <> h1Hex
  it "reads cfcheckpt" $
    parse (hex ("00" <> bh1Hex <> "01" <> h1Hex)) `shouldBe` Right (CFCheckpt 0 bh1 [h1])

-- Constants -------------------------------------------------------------------

constantsSpec :: Spec
constantsSpec = describe "network constants" $ do
  it "lists eight networks with distinct names and magics" $ do
    map (.name) allNets `shouldBe` ["btc", "bch", "btctest", "btctest4", "bchtest4", "bchtest", "btcreg", "bchreg"]
    length (nub (map (.magic) allNets)) `shouldBe` 8
  it "finds every network by name" $
    forM_ allNets $ \n -> netByName n.name `shouldBe` Just n
  it "finds nothing for an unknown name" $
    netByName "ltc" `shouldBe` Nothing
  it "uses the magic bytes of each network" $
    map (.magic) [btc, btcTest, btcTest4, btcRegTest, bch, bchTest, bchTest4, bchRegTest]
      `shouldBe` [0xf9beb4d9, 0x0b110907, 0x1c163f28, 0xfabfb5da, 0xe3e1f3e8, 0xf4e5f3f4, 0xe2b7daaf, 0xdab5bffa]
  it "uses the default port of each network" $
    map (.defaultPort) [btc, btcTest, btcTest4, btcRegTest, bch, bchTest, bchTest4, bchRegTest]
      `shouldBe` [8333, 18333, 48333, 18444, 8333, 18333, 28333, 18444]
  it "has the genesis block of each network" $
    map (headerHash . (.genesisHeader)) [btc, btcTest, btcTest4, btcRegTest, bch, bchTest, bchTest4, bchRegTest]
      `shouldBe` [ "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
                   "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943",
                   "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043",
                   "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
                   "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
                   "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943",
                   "000000001dd410c49a788668ce26751718cc797474d3152a5fc073dd44fd9f7b",
                   "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
                 ]
  it "limits messages to 4 MB on bitcoin and twice the block size on bitcoin cash" $
    map (.maxMessageSize) [btc, btcTest, btcTest4, btcRegTest, bch, bchTest, bchTest4, bchRegTest]
      `shouldBe` [4000000, 4000000, 4000000, 4000000, 64000000, 64000000, 4000000, 64000000]
  it "knows the block size of each network" $
    map (.maxBlockSize) [btc, bch, bchTest, bchTest4, bchRegTest]
      `shouldBe` [1000000, 32000000, 32000000, 2000000, 32000000]
  it "activates BIP34, BIP65 and BIP66 at height 1 on bitcoin regtest, as Bitcoin Core does" $ do
    btcRegTest.bip34Height `shouldBe` 1
    btcRegTest.bip34Hash `shouldBe` Nothing
    btcRegTest.bip65Height `shouldBe` 1
    btcRegTest.bip66Height `shouldBe` 1
  it "keeps the activation heights of Bitcoin Cash Node on bitcoin cash regtest" $ do
    bchRegTest.bip34Height `shouldBe` 100000000
    bchRegTest.bip34Hash `shouldBe` Nothing
    bchRegTest.bip65Height `shouldBe` 1351
    bchRegTest.bip66Height `shouldBe` 1251
  it "pins the BIP34 block on mainnet" $ do
    btc.bip34Height `shouldBe` 227931
    btc.bip34Hash `shouldBe` Just "000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8"
    btc.bip65Height `shouldBe` 388381
    btc.bip66Height `shouldBe` 363725
  it "pins block 1 of testnet4" $ do
    btcTest4.bip34Height `shouldBe` 1
    btcTest4.bip34Hash `shouldBe` Just "0000000012982b6d5f621229286b880e909984df669c2afabb102ce311b13f28"
  it "uses the BIP44 coin type of each network" $
    map (.bip44Coin) [btc, btcTest, btcTest4, btcRegTest, bch, bchTest, bchTest4, bchRegTest]
      `shouldBe` [0, 1, 1, 1, 145, 1, 1, 1]
  it "lists the Bitcoin Forks seed for bitcoin cash" $
    bch.seeds `shouldSatisfy` elem "seed-bch.bitcoinforks.org"
  it "numbers the service bits as Bitcoin Core does" $ do
    nodeNone `shouldBe` 0
    nodeNetwork `shouldBe` 1
    nodeGetUTXO `shouldBe` 2
    nodeBloom `shouldBe` 4
    nodeWitness `shouldBe` 8
    nodeXThin `shouldBe` 16
    nodeCompactFilters `shouldBe` 64
    nodeNetworkLimited `shouldBe` 1024
    nodeP2PV2 `shouldBe` 2048
