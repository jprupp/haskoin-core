{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Haskoin.BlockSpec
  ( spec,
  )
where

import Control.Exception (evaluate)
import Control.Monad
import Control.Monad.State.Strict
import Data.Aeson (Value, decode, encode, object, toJSON, (.=))
import qualified Data.ByteString as B
import Data.Bytes.Get (runGetS)
import Data.Bytes.Put (runPutS)
import Data.Bytes.Serial (deserialize, serialize)
import Data.Default (def)
import Data.Either (isLeft)
import Data.Hashable (hash)
import Data.List (isInfixOf, isPrefixOf)
import Data.Maybe (fromJust)
import Data.String (fromString)
import Data.String.Conversions (cs)
import Data.Text (Text)
import qualified Data.Text as T
import Data.Word (Word32)
import Haskoin.Block
import Haskoin.Crypto
import Haskoin.Network.Constants
import Haskoin.Network.Data
import Haskoin.Transaction
import Haskoin.Util
import Haskoin.Util.Arbitrary
import Test.HUnit hiding (State)
import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck
import Text.Printf (printf)

identityTests :: Ctx -> IdentityTests
identityTests ctx =
  def
    { readTests =
        [ ReadBox (flip arbitraryBlock ctx =<< arbitraryNetwork),
          ReadBox arbitraryBlockHash,
          ReadBox arbitraryBlockHeader,
          ReadBox arbitraryGetBlocks,
          ReadBox arbitraryGetHeaders,
          ReadBox arbitraryHeaders,
          ReadBox arbitraryMerkleBlock,
          ReadBox arbitraryBlockNode,
          ReadBox arbitraryHeaderMemory
        ],
      jsonTests =
        [ JsonBox (flip arbitraryBlock ctx =<< arbitraryNetwork),
          JsonBox arbitraryBlockHash,
          JsonBox arbitraryBlockHeader
        ],
      serialTests =
        [ SerialBox (flip arbitraryBlock ctx =<< arbitraryNetwork),
          SerialBox arbitraryBlockHash,
          SerialBox arbitraryBlockHeader,
          SerialBox arbitraryGetBlocks,
          SerialBox arbitraryGetHeaders,
          SerialBox arbitraryHeaders,
          SerialBox arbitraryMerkleBlock,
          SerialBox arbitraryBlockNode
        ]
    }

-- | Current time given to the validation functions. It is years after the
-- regtest genesis block, so the two-hour rule never interferes with the test
-- chains unless a test passes its own time.
myTime :: Timestamp
myTime = 1499083075

withChain :: Network -> State HeaderMemory a -> a
withChain net f = evalState f (initialChain net)

chain :: (BlockHeaders m) => Network -> BlockHeader -> Int -> m ()
chain net bh i = do
  bnsE <- connectBlocks net myTime bhs
  either error (const $ return ()) bnsE
  where
    bhs = appendBlocks net 6 bh i

-- | Regtest with a retarget every ten blocks and no min-difficulty rule, so
-- that retargets can be tested on short chains.
retargetNet :: Network
retargetNet =
  (btcRegTest :: Network)
    { powNoRetarget = False,
      minDiffBlocks = False,
      targetTimespan = 10 * 600
    }

-- | Regtest with the BIP94 rules, the min-difficulty rule and a retarget every
-- ten blocks.
bip94Net :: Network
bip94Net =
  (btcRegTest :: Network)
    { bip94 = True,
      powNoRetarget = False,
      targetTimespan = 10 * 600
    }

-- | The same network without the BIP94 rules.
noBip94Net :: Network
noBip94Net = (bip94Net :: Network) {bip94 = False}

-- | Bitcoin Cash regtest that retargets, with no Bitcoin Cash algorithm
-- enabled and no checkpoint on its genesis block. Each test enables the
-- algorithm it needs.
cashNet :: Network
cashNet =
  (bchRegTest :: Network)
    { powNoRetarget = False,
      minDiffBlocks = False,
      edaHeight = Nothing,
      daaHeight = Nothing,
      asertActivationTime = Nothing,
      checkpoints = []
    }

edaNet :: Network
edaNet = (cashNet :: Network) {edaHeight = Just 1}

daaNet :: Network
daaNet = (cashNet :: Network) {daaHeight = Just 1}

-- | ASERT activates when the median time past reaches the genesis time plus
-- 6000 seconds. With one block every 600 seconds that is the median time past
-- of block 15.
asertActivation :: Timestamp
asertActivation = cashNet.genesisHeader.timestamp + 6000

asertNet :: Network
asertNet =
  (cashNet :: Network)
    { asertActivationTime = Just asertActivation,
      asertHalfLife = 2 * 24 * 60 * 60
    }

-- | A version 4 header on top of the parent with the given timestamp and
-- bits, and a zero nonce. Version 4 passes the BIP34, BIP65 and BIP66 version
-- rules at any height, which regtest applies from height 1 like Bitcoin Core.
headerOn :: BlockHeader -> Timestamp -> Word32 -> BlockHeader
headerOn parent time bits =
  (parent :: BlockHeader) {version = 4, prev = headerHash parent, timestamp = time, bits = bits, nonce = 0}

-- | Mine a header on top of the parent with the given timestamp and bits.
mineOn :: Network -> BlockHeader -> Timestamp -> Word32 -> BlockHeader
mineOn net parent time bits = mineBlock net 0 (headerOn parent time bits)

-- | The same header with another version number.
headerWithVersion :: Word32 -> BlockHeader -> BlockHeader
headerWithVersion v (BlockHeader _ p m t b n) = BlockHeader v p m t b n

-- | Mine a chain of headers with the given timestamps and bits.
mineChain :: Network -> BlockHeader -> [(Timestamp, Word32)] -> [BlockHeader]
mineChain net parent = drop 1 . scanl (\p (time, bits) -> mineOn net p time bits) parent

-- | Put a chain of unvalidated headers in the store on top of the best block,
-- one per (timestamp, bits) pair. Heights, work and skip pointers are filled
-- in the way 'connectBlocks' does, but there is no proof of work and no rule
-- check, so difficulty tests can use any bits without mining. Returns the new
-- nodes, oldest first, and leaves the last one as the best block.
storeChain :: [(Timestamp, Word32)] -> State HeaderMemory [BlockNode]
storeChain specs = do
  start <- getBestBlockHeader
  go start specs
  where
    go _ [] = return []
    go par ((time, bits) : rest) = do
      let hdr = headerOn par.header time bits
          h = par.height + 1
      skipNode <- fromJust <$> getAncestor (skipHeight h) par
      let node =
            BlockNode
              { header = hdr,
                height = h,
                work = par.work + headerWork hdr,
                skip = headerHash skipNode.header
              }
      addBlockHeader node
      setBestBlockHeader node
      (node :) <$> go node rest

-- | Timestamps and bits of a chain of evenly spaced blocks after genesis.
evenlySpaced :: Network -> Word32 -> Int -> Word32 -> [(Timestamp, Word32)]
evenlySpaced net spacing n bits =
  [(net.genesisHeader.timestamp + spacing * fromIntegral i, bits) | i <- [1 .. n]]

-- | The work required for a block with the given timestamp on top of the
-- stored chain.
requiredAfter :: Network -> Timestamp -> State HeaderMemory Word32
requiredAfter net time = do
  par <- getBestBlockHeader
  nextWorkRequired net par (headerOn par.header time par.header.bits)

connectHeight :: Network -> Timestamp -> BlockHeader -> State HeaderMemory (Either String BlockHeight)
connectHeight net t h = fmap (.height) <$> connectBlock net t h

connectAll :: Network -> [BlockHeader] -> State HeaderMemory ()
connectAll net hs = connectBlocks net myTime hs >>= either error (const (return ()))

genesisHash :: BlockHash
genesisHash = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"

-- Three distinct transaction hashes for Merkle tree tests.
txA, txB, txC :: TxHash
txA = TxHash (sha256 ("a" :: B.ByteString))
txB = TxHash (sha256 ("b" :: B.ByteString))
txC = TxHash (sha256 ("c" :: B.ByteString))

readBlock :: FilePath -> IO Block
readBlock path = do
  hex <- T.strip . cs <$> B.readFile path
  either error return $ runGetS deserialize $ fromJust $ decodeHex hex

displayTxHash :: Text -> TxHash
displayTxHash = fromJust . hexToTxHash

spec :: Spec
spec = prepareContext $ \ctx -> do
  testIdentity $ identityTests ctx
  blockHashSpec
  blockHeaderSpec
  compactSpec
  serializationLimitSpec
  proofOfWorkSpec
  genesisSpec
  headerStoreSpec
  validationSpec
  medianTimeSpec
  bitcoinDifficultySpec
  cashDifficultySpec
  asertSpec
  checkpointSpec
  merkleSpec
  versionRuleSpec
  knownHeaderSpec
  merkleLimitSpec
  chainConstantsSpec
  activationSpec
  minimumWorkSpec
  coreProofSpec
  describe "block subsidy" $ do
    it "computes bitcoin block subsidy correctly" (testSubsidy btc)
    it "computes regtest block subsidy correctly" (testSubsidy btcRegTest)

blockHashSpec :: Spec
blockHashSpec = describe "block hash" $ do
  prop "encodes and decodes block hash" $
    forAll arbitraryBlockHash $ \h ->
      hexToBlockHash (blockHashToHex h) == Just h
  prop "from string block hash" $
    forAll arbitraryBlockHash $ \h ->
      fromString (cs $ blockHashToHex h) == h
  it "hashes the genesis header" $
    headerHash btc.genesisHeader `shouldBe` genesisHash
  it "shows a block hash in display order" $
    blockHashToHex genesisHash
      `shouldBe` "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
  it "serializes a block hash in internal byte order" $
    encodeHex (runPutS (serialize genesisHash))
      `shouldBe` "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000"
  it "encodes a block hash to JSON in display order" $
    encode genesisHash
      `shouldBe` "\"000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f\""
  it "rejects hex that is not 32 bytes" $ do
    hexToBlockHash (T.replicate 31 "00") `shouldBe` Nothing
    hexToBlockHash (T.replicate 33 "00") `shouldBe` Nothing
    hexToBlockHash ("ff" <> T.replicate 32 "00") `shouldBe` Nothing
    hexToBlockHash (T.replicate 32 "zz") `shouldBe` Nothing
    hexToBlockHash "" `shouldBe` Nothing

blockHeaderSpec :: Spec
blockHeaderSpec = describe "block header" $ do
  it "serializes the genesis header" $
    encodeHex (runPutS (serialize btc.genesisHeader))
      `shouldBe` "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c"
  it "encodes the genesis header to JSON like the getblockheader RPC" $
    toJSON btc.genesisHeader `shouldBe` genesisHeaderJson
  it "encodes the same JSON with the streaming encoder" $
    decode (encode btc.genesisHeader) `shouldBe` Just genesisHeaderJson
  it "decodes the genesis header from JSON" $
    decode (encode genesisHeaderJson) `shouldBe` Just btc.genesisHeader
  it "rejects a merkle root that is not 32 bytes in JSON" $
    (decode (encode (object [("version", toJSON (1 :: Int)), ("prevblock", toJSON (T.replicate 64 "0")), ("merkleroot", toJSON (T.replicate 66 "0")), ("timestamp", toJSON (0 :: Int)), ("bits", toJSON (0 :: Int)), ("nonce", toJSON (0 :: Int))])) :: Maybe BlockHeader)
      `shouldBe` Nothing
  it "serializes a getheaders message" $
    -- version 70015 = 0x0001117f, one locator hash, stop hash of zeroes
    encodeHex (runPutS (serialize (GetHeaders 70015 [genesisHash] "0000000000000000000000000000000000000000000000000000000000000000")))
      `shouldBe` "7f110100016fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d61900000000000000000000000000000000000000000000000000000000000000000000000000"
  where
    genesisHeaderJson :: Value
    genesisHeaderJson =
      object
        [ "version" .= (1 :: Int),
          "prevblock" .= ("0000000000000000000000000000000000000000000000000000000000000000" :: Text),
          "merkleroot" .= ("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b" :: Text),
          "timestamp" .= (1231006505 :: Int),
          "bits" .= (486604799 :: Int),
          "nonce" .= (2083236893 :: Int)
        ]

compactSpec :: Spec
compactSpec = describe "compact number" $ do
  it "compact number local vectors" testCompact
  it "compact number imported vectors" testCompactBitcoinCore
  it "refuses a number wider than 255 bytes" $
    evaluate (encodeCompact (2 ^ (2048 :: Int))) `shouldThrow` anyErrorCall
  it "refuses the largest 255-byte number" $
    -- 255 bytes of 0xff: the top byte has the sign bit set, so the mantissa
    -- shifts down one byte and the exponent becomes 256, which cannot be
    -- represented either
    evaluate (encodeCompact (2 ^ (2040 :: Int) - 1)) `shouldThrow` anyErrorCall

serializationLimitSpec :: Spec
serializationLimitSpec = describe "serialization limits" $ do
  it "refuses a block whose transaction count wraps around" $
    -- count 0xffffffffffffffff would become -1 as an Int and read as no transactions
    (runGetS deserialize (genesisHeaderBytes <> B.pack (0xff : replicate 8 0xff)) :: Either String Block)
      `shouldSatisfy` isLeft
  it "refuses a headers message that announces 2001 headers, before it reads them" $
    -- the count 2001 = 0x07d1 as a three-byte compact size, and no header.
    -- MAX_HEADERS_RESULTS is 2000 in Bitcoin Core and Bitcoin Cash Node.
    (runGetS deserialize (B.pack [0xfd, 0xd1, 0x07]) :: Either String Headers)
      `leftWith` "too many"
  it "accepts the count of a headers message of 2000 headers" $
    -- the count is accepted, and the parse then fails on the missing headers
    (runGetS deserialize (B.pack [0xfd, 0xd0, 0x07]) :: Either String Headers)
      `leftWith` "too few bytes"
  it "refuses a merkle block whose hash count wraps around" $
    (runGetS deserialize (genesisHeaderBytes <> B.pack [1, 0, 0, 0] <> B.pack (0xff : replicate 8 0xff)) :: Either String MerkleBlock)
      `shouldSatisfy` isLeft
  it "reads a block with no transactions when the count is zero" $
    (runGetS deserialize (genesisHeaderBytes <> B.pack [0]) :: Either String Block)
      `shouldBe` Right (Block btc.genesisHeader [])
  where
    genesisHeaderBytes = runPutS (serialize btc.genesisHeader)

proofOfWorkSpec :: Spec
proofOfWorkSpec = describe "proof of work" $ do
  it "accepts the genesis header" $
    isValidPOW btc btc.genesisHeader `shouldBe` True
  it "rejects a header whose hash is above its target" $
    -- a 32-bit nonce change leaves a hash with 32 leading zero bits with probability 2^-32
    isValidPOW btc (btc.genesisHeader :: BlockHeader) {nonce = 0} `shouldBe` False
  it "rejects a target above the proof of work limit" $
    -- exponent 0x1e makes the target 256 times the limit
    isValidPOW btc (btc.genesisHeader :: BlockHeader) {bits = 0x1e00ffff} `shouldBe` False
  it "rejects a negative target" $
    isValidPOW btc (btc.genesisHeader :: BlockHeader) {bits = 0x03800001} `shouldBe` False
  it "rejects an overflowing target" $
    isValidPOW btc (btc.genesisHeader :: BlockHeader) {bits = 0xff123456} `shouldBe` False
  it "rejects a zero target" $
    isValidPOW btc (btc.genesisHeader :: BlockHeader) {bits = 0} `shouldBe` False
  it "reads the hash as a number" $
    blockPOW genesisHash `shouldBe` 0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
  it "counts the work of the genesis header" $
    -- 2^256 / (0xffff * 2^208 + 1) = 4295032833, Bitcoin Core's 0x0000000100010001
    headerWork btc.genesisHeader `shouldBe` 4295032833
  it "counts the work of a regtest header" $
    -- 2^256 / (0x7fffff * 2^232 + 1) = 2
    headerWork btcRegTest.genesisHeader `shouldBe` 2
  it "gives no work to a negative target" $
    headerWork (btc.genesisHeader :: BlockHeader) {bits = 0x03800001} `shouldBe` 0
  it "gives no work to an overflowing target" $
    headerWork (btc.genesisHeader :: BlockHeader) {bits = 0xff123456} `shouldBe` 0
  it "gives no work to a zero target" $
    headerWork (btc.genesisHeader :: BlockHeader) {bits = 0} `shouldBe` 0
  it "mines a regtest header by changing only the nonce" $ do
    let hdr = headerOn btcRegTest.genesisHeader (btcRegTest.genesisHeader.timestamp + 600) 0x207fffff
        mined = mineBlock btcRegTest 7 hdr
    isValidPOW btcRegTest mined `shouldBe` True
    (mined :: BlockHeader) {nonce = 0} `shouldBe` hdr
    mined.nonce `shouldSatisfy` (>= 7)
  it "appends mined blocks one target spacing apart" $ do
    let hs = appendBlocks btcRegTest 1 btcRegTest.genesisHeader 3
    map (.timestamp) hs `shouldBe` [1296689202, 1296689802, 1296690402]
    map (.prev) hs `shouldBe` headerHash btcRegTest.genesisHeader : map headerHash (take 2 hs)
    all (isValidPOW btcRegTest) hs `shouldBe` True

genesisSpec :: Spec
genesisSpec = describe "genesis blocks" $ do
  it "has the BIP94 genesis block" $
    headerHash btcTest4.genesisHeader
      `shouldBe` "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043"
  it "has the Bitcoin Cash testnet4 genesis block" $
    headerHash bchTest4.genesisHeader
      `shouldBe` "000000001dd410c49a788668ce26751718cc797474d3152a5fc073dd44fd9f7b"
  it "serializes the mainnet coinbase" $
    encodeHex (runPutS (serialize mainnetGenesisTx))
      `shouldBe` "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000"
  it "serializes the testnet4 coinbase" $
    encodeHex (runPutS (serialize testnet4GenesisTx))
      `shouldBe` "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff5504ffff001d01044c4c30332f4d61792f323032342030303030303030303030303030303030303030303165626435386332343439373062336161396437383362623030313031316662653865613865393865303065ffffffff0100f2052a010000002321000000000000000000000000000000000000000000000000000000000000000000ac00000000"
  it "hashes the testnet4 coinbase to its merkle root" $
    txHashToHex (txHash testnet4GenesisTx)
      `shouldBe` "7aa0a7ae1e223414cb807e40cd57e667b718e42aaf9306db9102fe28912b7b4e"
  it "pairs every network's genesis header with its coinbase" $
    forM_ allNets $ \net ->
      (net.name, (txHash net.genesisTx).get) `shouldBe` (net.name, net.genesisHeader.merkle)
  it "builds the genesis block of every network" $
    forM_ allNets $ \net ->
      genesisBlock net `shouldBe` Block net.genesisHeader [net.genesisTx]
  it "builds the genesis node" $ do
    let node = genesisNode btc
    node.height `shouldBe` 0
    node.work `shouldBe` 4295032833
    node.skip `shouldBe` genesisHash
    isGenesis node `shouldBe` True

headerStoreSpec :: Spec
headerStoreSpec = describe "header store" $ do
  it "starts with genesis as the best block" $
    withChain btc getBestBlockHeader `shouldBe` genesisNode btc
  it "finds genesis by hash" $
    withChain btc (getBlockHeader genesisHash) `shouldBe` Just (genesisNode btc)
  it "finds nothing for an unknown hash" $
    withChain btc (getBlockHeader "0000000000000000000000000000000000000000000000000000000000000001") `shouldBe` Nothing
  it "finds nothing for a hash that only shares its first eight bytes with a block" $
    -- the last eight bytes of this display form are those of the genesis hash
    withChain btc (getBlockHeader "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa72b3f1b60a8ce26f") `shouldBe` Nothing
  it "reads a stored node whose chain work fits 256 bits, and no other" $ do
    -- chain work is a 256-bit unsigned number in Bitcoin Core
    let stored w = runPutS (serialize (genesisNode btc :: BlockNode) {work = w})
        readWork w = fmap (.work) (runGetS deserialize (stored w) :: Either String BlockNode)
    readWork (2 ^ (256 :: Int) - 1)
      `shouldBe` Right 115792089237316195423570985008687907853269984665640564039457584007913129639935
    readWork (2 ^ (256 :: Int)) `leftWith` "chain work out of range"
    readWork (-1) `leftWith` "chain work out of range"
  it "hashes two nodes with the same header to the same value, as they are equal" $ do
    let a = (genesisNode btc :: BlockNode) {work = 1}
        b = (genesisNode btc :: BlockNode) {work = 2}
    a == b `shouldBe` True
    hash a == hash b `shouldBe` True
  it "finds an added node by hash" $
    withChain btcRegTest (storeChain (evenlySpaced btcRegTest 600 3 0x207fffff) >>= \ns -> getBlockHeader (headerHash (last ns).header))
      `shouldSatisfy` maybe False ((== 3) . (.height))
  it "takes the short hash from the high-entropy end of the hash" $
    -- the first eight bytes of the internal order, as a big-endian number
    shortBlockHash genesisHash `shouldBe` 0x6fe28c0ab6f1b372
  it "gets best block on bchRegTest" $
    let net = bchRegTest
        bb =
          withChain net $ do
            chain net net.genesisHeader 100
            getBestBlockHeader
     in bb.height `shouldBe` 100
  it "computes skip heights like Bitcoin Core" $
    map skipHeight [0 .. 12] `shouldBe` [0, 0, 0, 1, 0, 1, 4, 1, 0, 1, 8, 1, 8]
  it "gets ancestors at any height" $
    let heights =
          withChain btcRegTest $ do
            chain btcRegTest btcRegTest.genesisHeader 100
            bb <- getBestBlockHeader
            forM [0, 1, 37, 64, 99, 100] $ \h -> fmap (.height) <$> getAncestor h bb
     in heights `shouldBe` map Just [0, 1, 37, 64, 99, 100]
  it "has no ancestor above the block" $
    withChain btcRegTest (chain btcRegTest btcRegTest.genesisHeader 5 >> getBestBlockHeader >>= getAncestor 6)
      `shouldBe` Nothing
  it "finds the parent of a block" $
    let hdr = mineOn btcRegTest btcRegTest.genesisHeader (btcRegTest.genesisHeader.timestamp + 600) 0x207fffff
     in withChain btcRegTest (parentBlock hdr) `shouldBe` Just (genesisNode btcRegTest)
  it "lists parents from the nearest, stopping at genesis" $
    let heights = withChain btcRegTest $ do
          chain btcRegTest btcRegTest.genesisHeader 5
          bb <- getBestBlockHeader
          map (.height) <$> getParents 10 bb
     in heights `shouldBe` [4, 3, 2, 1, 0]
  it "lists the requested number of parents" $
    let heights = withChain btcRegTest $ do
          chain btcRegTest btcRegTest.genesisHeader 20
          bb <- getBestBlockHeader
          map (.height) <$> getParents 3 bb
     in heights `shouldBe` [19, 18, 17]
  it "builds a block locator like Bitcoin Core" $
    -- ten single steps below the tip, then steps of 2, 4, 8, ... and genesis
    locatorHeights 100 `shouldBe` [100, 99, 98, 97, 96, 95, 94, 93, 92, 91, 90, 89, 87, 83, 75, 59, 27, 0]
  it "ends the block locator at genesis once" $
    locatorHeights 12 `shouldBe` [12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
  it "builds a block locator of a short chain" $
    locatorHeights 3 `shouldBe` [3, 2, 1, 0]
  it "builds a block locator of hashes" $
    let (hashes, nodes) = withChain btcRegTest $ do
          chain btcRegTest btcRegTest.genesisHeader 20
          bb <- getBestBlockHeader
          (,) <$> blockLocator bb <*> blockLocatorNodes bb
     in hashes `shouldBe` map (headerHash . (.header)) nodes
  it "follows split chains on bchRegTest" $
    let net = bchRegTest
        bb = withChain net $ splitChain net >> getBestBlockHeader
     in bb.height `shouldBe` 4035
  it "prefers the block with more work" $ do
    let node w h = (genesisNode btc :: BlockNode) {work = w, height = h}
    chooseBest (node 10 1) (node 20 1) `shouldBe` node 20 1
    chooseBest (node 20 1) (node 10 5) `shouldBe` node 20 1
  it "keeps the first block on equal work, whatever the heights" $ do
    -- CBlockIndexWorkComparator in Bitcoin Core compares the chain work and
    -- then the order of arrival. Height is not part of the rule.
    let node w h = (genesisNode btc :: BlockNode) {work = w, height = h}
    (chooseBest (node 10 1) (node 10 2)).height `shouldBe` 1
    (chooseBest (node 10 2) (node 10 1)).height `shouldBe` 2
  it "keeps the first block on equal work and height" $ do
    let node w h hdr = (genesisNode btc :: BlockNode) {work = w, height = h, header = hdr}
        first = node 10 1 btc.genesisHeader
        second = node 10 1 (btc.genesisHeader :: BlockHeader) {nonce = 1}
    chooseBest first second `shouldBe` first
    chooseBest second first `shouldBe` second
  it "orders nodes by height and then by header" $ do
    let node h hdr = (genesisNode btc :: BlockNode) {height = h, header = hdr}
        a = node 1 btc.genesisHeader
        b = node 1 (btc.genesisHeader :: BlockHeader) {nonce = 4294967295}
        c = node 2 btc.genesisHeader
    compare a b `shouldBe` LT
    compare a c `shouldBe` LT
    compare a a `shouldBe` EQ
  it "searches the chain for the first block at or above a height" $
    searchHeights `shouldBe` (Just 7, Just 7, Nothing, Just 20, Just 0, Nothing)
  where
    locatorHeights n = withChain btcRegTest $ do
      chain btcRegTest btcRegTest.genesisHeader n
      bb <- getBestBlockHeader
      map (.height) <$> blockLocatorNodes bb
    searchHeights = withChain btcRegTest $ do
      _ <- storeChain (evenlySpaced btcRegTest 600 20 0x207fffff)
      let byHeight :: BlockHeight -> BlockNode -> State HeaderMemory Ordering
          byHeight h bn = return (compare bn.height h)
          allBelow, allAbove :: BlockNode -> State HeaderMemory Ordering
          allBelow bn = return (compare bn.height 100)
          allAbove bn = return (compare (bn.height + 100) 50)
      a <- fmap (.height) <$> firstGreaterOrEqual btcRegTest (byHeight 7)
      b <- fmap (.height) <$> lastSmallerOrEqual btcRegTest (byHeight 7)
      c <- fmap (.height) <$> firstGreaterOrEqual btcRegTest allBelow
      d <- fmap (.height) <$> lastSmallerOrEqual btcRegTest allBelow
      e <- fmap (.height) <$> firstGreaterOrEqual btcRegTest allAbove
      f <- fmap (.height) <$> lastSmallerOrEqual btcRegTest allAbove
      return (a, b, c, d, e, f)

validationSpec :: Spec
validationSpec = describe "header validation" $ do
  let net = btcRegTest
      t0 = net.genesisHeader.timestamp
      b1 = mineOn net net.genesisHeader (t0 + 600) 0x207fffff
      b2 = mineOn net b1 (t0 + 1200) 0x207fffff
      b3 = mineOn net b2 (t0 + 1800) 0x207fffff
  it "connects a chain and returns the newest node first" $
    let heights = withChain net $ do
          r <- connectBlocks net myTime [b1, b2, b3]
          return (map (.height) <$> r)
     in heights `shouldBe` Right [3, 2, 1]
  it "connects headers one at a time" $
    withChain net (mapM (connectHeight net myTime) [b1, b2, b3]) `shouldBe` [Right 1, Right 2, Right 3]
  it "makes the connected chain the best block" $
    withChain net (connectAll net [b1, b2, b3] >> getBestBlockHeader) `shouldSatisfy` (== 3) . (.height)
  it "accepts a header it already has" $
    withChain net (connectAll net [b1] >> connectHeight net myTime b1) `shouldBe` Right 1
  it "rejects a header whose parent is unknown" $
    withChain net (connectHeight net myTime b2) `shouldBe` Left "Could not get parent block"
  it "rejects a list of headers that is not a chain" $
    withChain net (connectBlocks net myTime [b1, b3]) `shouldBe` Left "Blocks to connect do not form a chain"
  it "keeps the headers before a bad one and the best block among them" $
    let bad = mineOn net b2 (t0 + 1800) 0x1f7fffff
        (result, best, stored) = withChain net $ do
          r <- connectBlocks net myTime [b1, b2, bad]
          bb <- getBestBlockHeader
          s <- getBlockHeader (headerHash b2)
          return (map (.height) <$> r, bb.height, (.height) <$> s)
     in (result, best, stored)
          `shouldBe` (Left "Incorrect difficulty bits: 0x1f7fffff, expected 0x207fffff", 2, Just 2)
  it "rejects a header whose proof of work fails" $
    -- a nonce of zero on top of the mainnet genesis block has 32 leading zero bits with probability 2^-32
    withChain btc (connectBlock btc myTime (headerOn btc.genesisHeader (btc.genesisHeader.timestamp + 600) 0x1d00ffff))
      `shouldSatisfy` either ("Proof of work failed: " `isPrefixOf`) (const False)
  it "rejects a header whose bits differ from the required difficulty" $
    -- regtest requires 0x207fffff; the header is mined at a harder target
    withChain net (connectHeight net myTime (mineOn net net.genesisHeader (t0 + 600) 0x1f7fffff))
      `shouldBe` Left "Incorrect difficulty bits: 0x1f7fffff, expected 0x207fffff"
  it "rejects a timestamp more than two hours in the future" $
    -- current time 1296700000, header at 1296707201 is 7201 seconds ahead
    withChain net (connectHeight net 1296700000 (mineOn net net.genesisHeader 1296707201 0x207fffff))
      `shouldBe` Left "Invalid header timestamp: 1296707201"
  it "accepts a timestamp exactly two hours in the future" $
    withChain net (connectHeight net 1296700000 (mineOn net net.genesisHeader 1296707200 0x207fffff))
      `shouldBe` Right 1
  it "rejects a timestamp equal to the median time past" $
    -- the median of genesis (1296688602) and block 1 (1296689202) is 1296689202
    withChain net (connectAll net [b1] >> connectHeight net myTime (mineOn net b1 (t0 + 600) 0x207fffff))
      `shouldBe` Left "Block timestamp too early: 1296689202"
  it "accepts a timestamp one second above the median time past" $
    withChain net (connectAll net [b1] >> connectHeight net myTime (mineOn net b1 (t0 + 601) 0x207fffff))
      `shouldBe` Right 2
  it "rejects a block that does not match a checkpoint" $
    let cpNet = (net :: Network) {checkpoints = [(2, headerHash b3)]}
     in withChain cpNet (connectAll cpNet [b1] >> connectHeight cpNet myTime b2)
          `shouldBe` Left "Rejected checkpoint: 2"
  it "accepts a block that matches a checkpoint" $
    let cpNet = (net :: Network) {checkpoints = [(2, headerHash b2)]}
     in withChain cpNet (connectAll cpNet [b1] >> connectHeight cpNet myTime b2)
          `shouldBe` Right 2
  it "rejects a fork below the last checkpoint reached" $
    let cpNet = (net :: Network) {checkpoints = [(2, headerHash b2)]}
        fork2 = mineOn net b1 (t0 + 1201) 0x207fffff
     in withChain cpNet (connectAll cpNet [b1, b2, b3] >> connectHeight cpNet myTime fork2)
          `shouldBe` Left "Rewriting pre-checkpoint chain: 2"
  it "accepts a fork above the last checkpoint reached" $
    let cpNet = (net :: Network) {checkpoints = [(2, headerHash b2)]}
        fork3 = mineOn net b2 (t0 + 1801) 0x207fffff
     in withChain cpNet (connectAll cpNet [b1, b2, b3] >> connectHeight cpNet myTime fork3)
          `shouldBe` Right 3
  it "rejects the BIP34 activation block with the wrong hash" $
    let bipNet = (net :: Network) {bip34Height = 2, bip34Hash = Just (headerHash b3)}
     in withChain bipNet (connectAll bipNet [b1] >> connectHeight bipNet myTime b2)
          `shouldSatisfy` either ("Rejected BIP-34 block: " `isPrefixOf`) (const False)
  it "accepts the BIP34 activation block with the right hash" $
    let bipNet = (net :: Network) {bip34Height = 2, bip34Hash = Just (headerHash b2)}
     in withChain bipNet (connectAll bipNet [b1] >> connectHeight bipNet myTime b2)
          `shouldBe` Right 2
  it "accepts any block at the BIP34 height when no hash is pinned" $
    let bipNet = (net :: Network) {bip34Height = 2, bip34Hash = Nothing}
     in withChain bipNet (connectAll bipNet [b1] >> connectHeight bipNet myTime b2)
          `shouldBe` Right 2
  it "rejects version 1 once BIP34 is active" $
    let bipNet = (net :: Network) {bip34Height = 0, bip34Hash = Nothing}
        hdr = mineBlock net 0 (headerWithVersion 1 (headerOn net.genesisHeader (t0 + 600) 0x207fffff))
     in withChain bipNet (connectHeight bipNet myTime hdr) `shouldBe` Left "Invalid block version: 1"
  it "rejects a negative version once BIP34 is active" $
    let bipNet = (net :: Network) {bip34Height = 0, bip34Hash = Nothing}
        hdr = mineBlock net 0 (headerWithVersion 0xffffffff (headerOn net.genesisHeader (t0 + 600) 0x207fffff))
     in withChain bipNet (connectHeight bipNet myTime hdr) `shouldBe` Left "Invalid block version: 4294967295"
  it "rejects version 2 once BIP66 is active" $
    let bipNet = (net :: Network) {bip34Height = 0, bip34Hash = Nothing, bip66Height = 1}
        hdr = mineBlock net 0 (headerWithVersion 2 (headerOn net.genesisHeader (t0 + 600) 0x207fffff))
     in withChain bipNet (connectHeight bipNet myTime hdr) `shouldBe` Left "Invalid block version: 2"
  it "accepts version 4 everywhere" $
    let bipNet = (net :: Network) {bip34Height = 0, bip34Hash = Nothing, bip66Height = 1, bip65Height = 1}
        hdr = mineBlock net 0 (headerWithVersion 4 (headerOn net.genesisHeader (t0 + 600) 0x207fffff))
     in withChain bipNet (connectHeight bipNet myTime hdr) `shouldBe` Right 1
  it "keeps the first block seen on equal work and height" $
    let c1 = mineOn net net.genesisHeader (t0 + 601) 0x207fffff
        tips = withChain net $ do
          connectAll net [b1]
          _ <- connectBlock net myTime c1
          s1 <- getBestBlockHeader
          connectAll net [c1]
          s2 <- getBestBlockHeader
          connectAll net [b1]
          s3 <- getBestBlockHeader
          return [s1, s2, s3]
     in map (headerHash . (.header)) tips `shouldBe` replicate 3 (headerHash b1)
  it "moves the best block to the fork with more work" $
    let c1 = mineOn net net.genesisHeader (t0 + 601) 0x207fffff
        c2 = mineOn net c1 (t0 + 1201) 0x207fffff
        tips = withChain net $ do
          connectAll net [b1]
          connectAll net [c1, c2]
          s1 <- getBestBlockHeader
          connectAll net [b2, b3]
          s2 <- getBestBlockHeader
          return [s1, s2]
     in map (headerHash . (.header)) tips `shouldBe` [headerHash c2, headerHash b3]
  describe "BIP94" $ do
    it "rejects the first block of a retarget period when it is too early" $ do
      -- Blocks 1 to 8 are ten minutes apart; block 9 jumps two hours ahead.
      let t = bip94Net.genesisHeader.timestamp
          hs =
            mineChain bip94Net bip94Net.genesisHeader $
              [(t + 600 * i, 0x207fffff) | i <- [1 .. 8]] ++ [(t + 12000, 0x207fffff)]
          par = last hs
          b10 = mineOn bip94Net par (t + 11400) 0x207fffff
          connect net' chain' h = withChain net' $ do
            connectBlocks net' myTime chain' >>= either error (const (return ()))
            connectHeight net' myTime h
      -- Block 10 starts a retarget period, so it may be at most 600 seconds
      -- earlier than block 9.
      connect bip94Net hs (mineOn bip94Net par (t + 11399) 0x207fffff)
        `shouldBe` Left "Block timestamp too early for retarget: 1296700001"
      connect bip94Net hs b10 `shouldBe` Right 10
      -- Block 11 does not start a period.
      connect bip94Net (hs ++ [b10]) (mineOn bip94Net b10 (t + 10799) 0x207fffff)
        `shouldBe` Right 11
      connect noBip94Net hs (mineOn noBip94Net par (t + 11399) 0x207fffff)
        `shouldBe` Right 10
    it "allows the first block of a period 600 seconds before its parent" $ do
      validTimeWarp bip94Net 10 10000 9400 `shouldBe` True
      validTimeWarp bip94Net 10 10000 9399 `shouldBe` False
      validTimeWarp bip94Net 11 10000 0 `shouldBe` True
      validTimeWarp noBip94Net 10 10000 0 `shouldBe` True

medianTimeSpec :: Spec
medianTimeSpec = describe "median time past" $ do
  it "takes the middle of an odd count" $
    medianTime [5, 1, 3] `shouldBe` 3
  it "takes the upper middle of an even count" $
    medianTime [4, 1, 3, 2] `shouldBe` 3
  it "takes the only element" $
    medianTime [7] `shouldBe` 7
  it "is the genesis timestamp for genesis" $
    withChain btcRegTest (getBestBlockHeader >>= mtp) `shouldBe` 1296688602
  it "covers the block and its ten ancestors" $
    -- blocks 10 to 20 are 600 seconds apart, the median is block 15
    withChain btcRegTest (storeChain (evenlySpaced btcRegTest 600 20 0x207fffff) >>= mtp . last)
      `shouldBe` 1296688602 + 600 * 15
  it "covers fewer blocks near genesis" $
    -- genesis and blocks 1 to 3: the upper middle of four is block 2
    withChain btcRegTest (storeChain (evenlySpaced btcRegTest 600 3 0x207fffff) >>= mtp . last)
      `shouldBe` 1296688602 + 600 * 2

bitcoinDifficultySpec :: Spec
bitcoinDifficultySpec = describe "bitcoin difficulty" $ do
  let t0 = retargetNet.genesisHeader.timestamp
      mainnetHeader = (btc.genesisHeader :: BlockHeader) {bits = 0x1703a30c, timestamp = 20000000}
  it "has a retarget interval of 2016 blocks" $ do
    diffInterval btc `shouldBe` 2016
    diffInterval retargetNet `shouldBe` 10
  it "keeps the target when the period took the target timespan" $
    -- 1209600 seconds is two weeks
    calcNextWork btc mainnetHeader (20000000 - 1209600) `shouldBe` 0x1703a30c
  it "raises the target at most four times" $
    -- 0x03a30c * 4 = 0x0e8c30
    calcNextWork btc mainnetHeader (20000000 - 10 * 1209600) `shouldBe` 0x170e8c30
  it "lowers the target at most to a quarter" $
    -- 0x03a30c / 4 = 0x00e8c3
    calcNextWork btc mainnetHeader (20000000 - 1) `shouldBe` 0x1700e8c3
  it "treats a period that ends before it starts as a short one" $
    calcNextWork btc mainnetHeader (20000000 + 1) `shouldBe` 0x1700e8c3
  it "does not raise the target above the limit" $
    calcNextWork btc (btc.genesisHeader :: BlockHeader) {timestamp = 20000000} (20000000 - 2 * 1209600) `shouldBe` 0x1d00ffff
  it "keeps the bits when the network does not retarget" $
    calcNextWork btcRegTest mainnetHeader (20000000 - 10 * 1209600) `shouldBe` 0x1703a30c
  it "requires the parent's bits inside a period" $
    requiredOn retargetNet (evenlySpaced retargetNet 600 5 0x1f400000) (t0 + 600 * 6) `shouldBe` 0x1f400000
  it "keeps the target when the first period took the target timespan" $
    -- block 9 is 6000 seconds after genesis
    requiredOn retargetNet (nineBlocks (t0 + 6000)) (t0 + 6600) `shouldBe` 0x1f400000
  it "lowers the target in proportion to a fast period" $
    -- 5400 of 6000 seconds: 0x400000 * 0.9 = 0x399999.9
    requiredOn retargetNet (nineBlocks (t0 + 5400)) (t0 + 6000) `shouldBe` 0x1f399999
  it "doubles the target for a period that took twice as long" $
    -- 2^246 * 2 = 2^247 = 0x80 * 2^240, whose sign bit moves the mantissa down one byte
    requiredOn retargetNet (nineBlocks (t0 + 12000)) (t0 + 12600) `shouldBe` 0x20008000
  it "raises the target at most four times over a period" $
    -- 30000 of 6000 seconds is clamped to 24000: 2^246 * 4 = 2^248
    requiredOn retargetNet (nineBlocks (t0 + 30000)) (t0 + 30600) `shouldBe` 0x20010000
  it "lowers the target at most to a quarter over a period" $
    -- 600 of 6000 seconds is clamped to 1500: 2^246 / 4 = 2^244
    requiredOn retargetNet (nineBlocks (t0 + 600)) (t0 + 1200) `shouldBe` 0x1f100000
  it "treats a period that ends before it starts as a short one" $
    requiredOn retargetNet (nineBlocks (t0 - 100)) (t0 + 600) `shouldBe` 0x1f100000
  it "does not raise the target above the limit over a period" $
    requiredOn retargetNet (map (\(t, _) -> (t, 0x207fffff)) (nineBlocks (t0 + 12000))) (t0 + 12600) `shouldBe` 0x207fffff
  describe "min-difficulty rule" $ do
    let minNet = (retargetNet :: Network) {minDiffBlocks = True}
        -- blocks 1 to 5 at the normal target, block 6 at the minimum after a long gap
        withMinDiffBlock = evenlySpaced minNet 600 5 0x1f400000 ++ [(t0 + 600 * 5 + 1300, 0x207fffff)]
    it "allows the minimum difficulty after twice the target spacing" $
      requiredOn minNet (evenlySpaced minNet 600 5 0x1f400000) (t0 + 600 * 5 + 1201) `shouldBe` 0x207fffff
    it "requires the normal difficulty at exactly twice the target spacing" $
      requiredOn minNet (evenlySpaced minNet 600 5 0x1f400000) (t0 + 600 * 5 + 1200) `shouldBe` 0x1f400000
    it "requires the last normal difficulty after a minimum-difficulty block" $
      requiredOn minNet withMinDiffBlock (t0 + 600 * 5 + 1300 + 600) `shouldBe` 0x1f400000
    it "does not apply on networks without the rule" $
      requiredOn retargetNet (evenlySpaced retargetNet 600 5 0x1f400000) (t0 + 600 * 5 + 1201) `shouldBe` 0x1f400000
    it "finds the last block without minimum difficulty" $
      let heights = withChain minNet $ do
            nodes <- storeChain withMinDiffBlock
            forM [nodes !! 5, nodes !! 4, nodes !! 0] $ fmap (.height) . lastNoMinDiff minNet
       in heights `shouldBe` [5, 5, 1]
    it "stops at the first block of a period" $
      -- block 10 starts a period, so it is never a special block
      withChain minNet (storeChain (evenlySpaced minNet 600 10 0x207fffff) >>= fmap (.height) . lastNoMinDiff minNet . last)
        `shouldBe` 10
    it "stops at genesis" $
      withChain minNet (getBestBlockHeader >>= fmap (.height) . lastNoMinDiff minNet) `shouldBe` 0
  describe "BIP94 retarget" $ do
    let bip94MinNet = (retargetNet :: Network) {bip94 = True, minDiffBlocks = True}
        noBip94MinNet = (retargetNet :: Network) {minDiffBlocks = True}
        -- blocks 1 to 9 take exactly one target timespan; blocks 10 to 19 take
        -- four, and block 19 is a minimum-difficulty block
        twoPeriods =
          [(t0 + 600 * i, 0x1f400000) | i <- [1 .. 8]]
            ++ [(t0 + 6000, 0x1f400000)]
            ++ [(t0 + 6600 + 600 * i, 0x1f400000) | i <- [0 .. 8]]
            ++ [(t0 + 30600, 0x207fffff)]
    it "bases the retarget on the first block of the period" $
      -- four times the target of block 10: 2^246 * 4 = 2^248
      requiredOn bip94MinNet twoPeriods (t0 + 31200) `shouldBe` 0x20010000
    it "bases the retarget on the last block without BIP94" $
      -- four times the minimum difficulty is clamped to the limit
      requiredOn noBip94MinNet twoPeriods (t0 + 31200) `shouldBe` 0x207fffff
  where
    nineBlocks lastTime = evenlySpaced retargetNet 600 8 0x1f400000 ++ [(lastTime, 0x1f400000)]
    requiredOn net specs time = withChain net (storeChain specs >> requiredAfter net time)

cashDifficultySpec :: Spec
cashDifficultySpec = describe "bitcoin cash difficulty" $ do
  let t0 = cashNet.genesisHeader.timestamp
  describe "regtest" $
    it "never retargets" $
      -- a regtest chain at a harder target with an hour-long gap
      withChain bchRegTest (storeChain (evenlySpaced bchRegTest 600 5 0x1f400000) >> requiredAfter bchRegTest (t0 + 3000 + 3600))
        `shouldBe` 0x1f400000
  describe "emergency difficulty adjustment" $ do
    it "keeps the target when the last six blocks took less than twelve hours" $
      requiredOn edaNet (evenlySpaced edaNet 600 20 0x1f400000) (t0 + 600 * 21) `shouldBe` 0x1f400000
    it "keeps the target just below twelve hours" $
      -- 6 * 7199 = 43194 seconds between the two median times
      requiredOn edaNet (evenlySpaced edaNet 7199 20 0x1f400000) (t0 + 7199 * 21) `shouldBe` 0x1f400000
    it "raises the target by a quarter when the last six blocks took twelve hours" $
      -- 0x400000 + 0x100000 = 0x500000
      requiredOn edaNet (evenlySpaced edaNet 7200 20 0x1f400000) (t0 + 7200 * 21) `shouldBe` 0x1f500000
    it "does not raise the target above the limit" $
      requiredOn edaNet (evenlySpaced edaNet 7200 20 0x207fffff) (t0 + 7200 * 21) `shouldBe` 0x207fffff
    it "retargets normally at the end of a period" $
      -- 5400 of 6000 seconds: 0x400000 * 0.9 = 0x399999.9
      let shortNet = (edaNet :: Network) {targetTimespan = 10 * 600}
       in requiredOn shortNet (evenlySpaced shortNet 600 9 0x1f400000) (t0 + 6000) `shouldBe` 0x1f399999
    it "ignores the gap to the parent on mainnet" $
      requiredOn edaNet (evenlySpaced edaNet 600 20 0x1f400000) (t0 + 600 * 20 + 1201) `shouldBe` 0x1f400000
    describe "on test networks" $ do
      let testNet = (edaNet :: Network) {minDiffBlocks = True}
          withMinDiffBlock = evenlySpaced testNet 600 5 0x1f400000 ++ [(t0 + 600 * 5 + 1300, 0x207fffff)]
      it "allows the minimum difficulty after twice the target spacing" $
        requiredOn testNet (evenlySpaced testNet 600 20 0x1f400000) (t0 + 600 * 20 + 1201) `shouldBe` 0x207fffff
      it "requires the last normal difficulty after a minimum-difficulty block" $
        requiredOn testNet withMinDiffBlock (t0 + 600 * 5 + 1300 + 600) `shouldBe` 0x1f400000
      it "does not use the twelve-hour rule" $
        -- the last six blocks took twelve hours, the new block follows its parent closely
        requiredOn testNet (evenlySpaced testNet 7200 20 0x1f400000) (t0 + 7200 * 20 + 600) `shouldBe` 0x1f400000
  describe "difficulty adjustment algorithm" $ do
    -- The window runs from the suitable block before block 2056 to the one
    -- before block 2200: 144 blocks of work at 0x1f7fffff, which is 512 each.
    let window spacing = evenlySpaced daaNet spacing 2200 0x1f7fffff
    it "keeps the target when blocks come every ten minutes" $
      -- (2^256 - 512) / 512 = 2^247 - 1
      requiredOn daaNet (window 600) (t0 + 600 * 2201) `shouldBe` 0x1f7fffff
    it "halves the target when blocks come every five minutes" $
      -- (2^256 - 1024) / 1024 = 2^246 - 1
      requiredOn daaNet (window 300) (t0 + 300 * 2201) `shouldBe` 0x1f3fffff
    it "doubles the target when blocks come every twenty minutes" $
      -- (2^256 - 256) / 256 = 2^248 - 1, whose top byte has the sign bit set
      requiredOn daaNet (window 1200) (t0 + 1200 * 2201) `shouldBe` 0x2000ffff
    it "halves the target at most over a window" $
      -- 144 * 150 = 21600 seconds is clamped to 72 * 600 = 43200
      requiredOn daaNet (window 150) (t0 + 150 * 2201) `shouldBe` 0x1f3fffff
    it "doubles the target at most over a window" $
      -- 144 * 2400 = 345600 seconds is clamped to 288 * 600 = 172800
      requiredOn daaNet (window 2400) (t0 + 2400 * 2201) `shouldBe` 0x2000ffff
    it "ignores the gap to the parent on mainnet" $
      requiredOn daaNet (window 600) (t0 + 600 * 2200 + 1201) `shouldBe` 0x1f7fffff
    it "allows the minimum difficulty after twice the target spacing on test networks" $
      let testNet = (daaNet :: Network) {minDiffBlocks = True}
       in requiredOn testNet (window 600) (t0 + 600 * 2200 + 1201) `shouldBe` 0x207fffff
    it "computes the target from the work and time of a window" $ do
      -- 144 * 2^200 work over 144 * 600 seconds is 2^200 work per 600 seconds:
      -- (2^256 - 2^200) / 2^200 = 2^56 - 1
      computeTarget bch (node 0 1000000) (node (144 * 2 ^ (200 :: Int)) (1000000 + 86400)) `shouldBe` 72057594037927935
      -- one second is clamped to 43200: 2^201 work per 600 seconds gives 2^55 - 1
      computeTarget bch (node 0 1000000) (node (144 * 2 ^ (200 :: Int)) 1000001) `shouldBe` 36028797018963967
      -- a window that ends before it starts is clamped the same way
      computeTarget bch (node 0 1000000) (node (144 * 2 ^ (200 :: Int)) 999999) `shouldBe` 36028797018963967
      -- a million seconds is clamped to 172800: 2^199 work per 600 seconds gives 2^57 - 1
      computeTarget bch (node 0 1000000) (node (144 * 2 ^ (200 :: Int)) 2000000) `shouldBe` 144115188075855871
    it "picks the block with the median timestamp as suitable" $ do
      suitableHeight [600, 1200, 1800] `shouldBe` 2
      suitableHeight [600, 9000, 1200] `shouldBe` 3
      suitableHeight [9000, 600, 1200] `shouldBe` 3
    it "picks the same block as Bitcoin Cash Node on equal timestamps" $ do
      suitableHeight [600, 1200, 1200] `shouldBe` 2
      suitableHeight [1200, 600, 1200] `shouldBe` 1
      suitableHeight [1200, 1200, 600] `shouldBe` 2
      suitableHeight [600, 600, 600] `shouldBe` 2
  where
    requiredOn net specs time = withChain net (storeChain specs >> requiredAfter net time)
    node w t = (genesisNode bch :: BlockNode) {work = w, header = (bch.genesisHeader :: BlockHeader) {timestamp = t}}
    suitableHeight offsets = withChain cashNet $ do
      nodes <- storeChain [(cashNet.genesisHeader.timestamp + o, 0x207fffff) | o <- offsets]
      (.height) <$> getSuitableBlock (last nodes)

asertSpec :: Spec
asertSpec = describe "asert" $ do
  let t0 = asertNet.genesisHeader.timestamp
      halfLife = 2 * 24 * 60 * 60
      regtestLimit = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
      mainnetLimit = 0x00000000ffff0000000000000000000000000000000000000000000000000000
      -- thirty blocks ten minutes apart; block 15 is the first whose median
      -- time past reaches the activation time
      steady = evenlySpaced asertNet 600 30 0x1f400000
      requiredOn net specs time = withChain net (storeChain specs >> requiredAfter net time)
  it "finds the first block whose median time past reaches the activation time" $
    anchorHeights `shouldBe` [Nothing, Just 15, Just 15, Just 15]
  it "has no anchor without an activation time" $
    withChain cashNet (storeChain steady >>= asertAnchor cashNet . last) `shouldBe` Nothing
  it "keeps the target when the chain is on schedule" $
    requiredOn asertNet (take 15 steady) (t0 + 600 * 16) `shouldBe` 0x1f400000
  it "keeps the target later on the schedule" $
    requiredOn asertNet steady (t0 + 600 * 31) `shouldBe` 0x1f400000
  it "ignores the timestamp of the block itself" $ do
    -- The chain up to the parent is on schedule. A block that is a half-life
    -- late or early still carries the unchanged bits; only its children see
    -- the delay.
    requiredOn asertNet steady (t0 + 600 * 31 + halfLife) `shouldBe` 0x1f400000
    requiredOn asertNet steady (t0 + 600 * 31 - halfLife) `shouldBe` 0x1f400000
  it "connects a block that is not exactly ten minutes after its parent" $
    -- Block 31 comes 428 seconds after block 30, as mainnet block 975899
    -- came after its parent, with the unchanged bits of the chain.
    withChain asertNet (storeChain steady >>= connectLate) `shouldBe` Right 31
  it "doubles the target after a parent that is a half-life late" $
    -- Block 16 is 172800 seconds late. From the anchor's parent, block 14,
    -- to block 16 the chain took 1200 + 172800 seconds for two blocks, one
    -- half-life behind schedule. 2^246 * 2 = 2^247 = 0x80 * 2^240, whose sign
    -- bit moves the mantissa down one byte.
    let late = (t0 + 600 * 16 + halfLife, 0x1f400000)
     in requiredOn asertNet (take 15 steady ++ [late]) (t0 + 600 * 17 + halfLife) `shouldBe` 0x20008000
  it "halves the target after a chain that is a half-life ahead" $
    -- 300 blocks 24 seconds apart follow the anchor, block 15. From the
    -- anchor's parent to block 315 the chain took 600 + 300 * 24 = 7800
    -- seconds for 301 blocks instead of 301 * 600 = 180600, which is one
    -- half-life (172800 seconds) ahead of schedule.
    let fast = [(t0 + 600 * 15 + 24 * i, 0x1f400000) | i <- [1 .. 300]]
     in requiredOn asertNet (take 15 steady ++ fast) (t0 + 600 * 15 + 24 * 301) `shouldBe` 0x1f200000
  it "allows the minimum difficulty after twice the target spacing on test networks" $
    let testNet = (asertNet :: Network) {minDiffBlocks = True}
     in requiredOn testNet steady (t0 + 600 * 31 + halfLife) `shouldBe` 0x207fffff
  it "uses the previous algorithm before activation" $
    -- block 14 has not reached the activation time, so block 15 keeps its parent's bits
    requiredOn asertNet (take 14 steady) (t0 + 600 * 15 + halfLife) `shouldBe` 0x1f400000
  it "computes the formula on the anchor" $ do
    -- one block and 1200 seconds after the anchor's parent is on schedule;
    -- the half-life is 172800 seconds
    computeAsertBits regtestLimit 172800 0x1f400000 1200 1 `shouldBe` 0x1f400000
    computeAsertBits regtestLimit 172800 0x1f400000 (1200 + 172800) 1 `shouldBe` 0x20008000
    computeAsertBits regtestLimit 172800 0x1f400000 (1200 - 172800) 1 `shouldBe` 0x1f200000
  it "does not raise the target above the limit" $
    computeAsertBits (2 ^ (246 :: Int)) 172800 0x1f400000 (1200 + 172800) 1 `shouldBe` 0x1f400000
  it "does not lower the target below one" $
    -- a target of one halved ten times
    computeAsertBits regtestLimit 172800 0x01010000 (1200 - 10 * 172800) 1 `shouldBe` 0x01010000
  it "computes the bits of Bitcoin Cash mainnet block 975899" $
    -- The anchor is block 661647 with bits 0x1804dafe and its parent is dated
    -- 1605447844. Block 975898, the parent of 975899, is dated 1793800487:
    -- 1793800487 - 1605447844 = 188352643 seconds and 975898 - 661647 =
    -- 314251 blocks after the anchor.
    computeAsertBits mainnetLimit 172800 0x1804dafe 188352643 314251 `shouldBe` 0x1802308e
  describe "aserti3-2d test vectors" $
    mapM_
      ( \x ->
          asertTests $
            "test_vectors_aserti3-2d_run" ++ printf "%02d" x ++ ".txt"
      )
      [(1 :: Int) .. 12]
  where
    -- Mine block 31 with the chain's bits 428 seconds after block 30 and
    -- connect it with every rule checked.
    connectLate :: [BlockNode] -> State HeaderMemory (Either String BlockHeight)
    connectLate nodes =
      let parent = (last nodes).header
          t0 = asertNet.genesisHeader.timestamp
       in connectHeight asertNet myTime (mineOn asertNet parent (t0 + 600 * 30 + 428) 0x1f400000)
    anchorHeights = withChain asertNet $ do
      nodes <- storeChain (evenlySpaced asertNet 600 30 0x1f400000)
      forM [nodes !! 13, nodes !! 14, nodes !! 19, last nodes] $ \n ->
        fmap (.height) <$> asertAnchor asertNet n

checkpointSpec :: Spec
checkpointSpec = describe "checkpoints and versions" $ do
  it "accepts the checkpoint hash at its height" $
    validCP btc 11111 "0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d" `shouldBe` True
  it "rejects another hash at a checkpoint height" $
    validCP btc 11111 genesisHash `shouldBe` False
  it "accepts any hash where there is no checkpoint" $
    validCP btc 11112 genesisHash `shouldBe` True
  it "requires new blocks above the last checkpoint reached" $ do
    -- the checkpoints at or below height 50000 are 11111 and 33333
    afterLastCP btc 50000 33334 `shouldBe` True
    afterLastCP btc 50000 33333 `shouldBe` False
    afterLastCP btc 50000 11112 `shouldBe` False
    afterLastCP btc 10000 1 `shouldBe` True
    afterLastCP btcRegTest 10000 1 `shouldBe` True
  it "checks the BIP34 activation block" $ do
    bip34 btc 227931 "000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8" `shouldBe` True
    bip34 btc 227931 genesisHash `shouldBe` False
    bip34 btc 227932 genesisHash `shouldBe` True
    -- regtest pins no hash, so any block passes at its BIP34 height
    bip34 btcRegTest 1 genesisHash `shouldBe` True
    bip34 btcRegTest 5 genesisHash `shouldBe` True
    bip34 bchRegTest 100000000 genesisHash `shouldBe` True
  it "requires block versions by height" $ do
    validVersion btc 227930 1 `shouldBe` True
    validVersion btc 227931 1 `shouldBe` False
    validVersion btc 363724 2 `shouldBe` True
    validVersion btc 363725 2 `shouldBe` False
    validVersion btc 388380 3 `shouldBe` True
    validVersion btc 388381 3 `shouldBe` False
    validVersion btc 388381 4 `shouldBe` True
    validVersion btc 800000 0x20000000 `shouldBe` True
  it "treats a version with the top bit set as negative" $ do
    validVersion btc 800000 0xffffffff `shouldBe` False
    validVersion btc 800000 0x80000004 `shouldBe` False
    validVersion btc 0 0xffffffff `shouldBe` True

merkleSpec :: Spec
merkleSpec = describe "merkle trees" $ do
  prop "builds tree of right width at height 1" testTreeWidth
  prop "builds tree of right width at height 0" testBaseWidth
  prop "builds and extracts partial merkle tree" $
    forAll arbitraryNetwork $ \net ->
      forAll
        (listOf1 ((,) <$> arbitraryTxHash <*> arbitrary))
        (buildExtractTree net)
  it "merkle root test vectors" $ mapM_ runMerkleVector merkleVectors
  it "computes tree heights" $
    map calcTreeHeight [0, 1, 2, 3, 4, 5, 8, 9, 1000] `shouldBe` [0, 0, 1, 2, 2, 3, 3, 4, 10]
  it "computes tree widths" $ do
    map (calcTreeWidth 5) [0, 1, 2, 3] `shouldBe` [5, 3, 2, 1]
    map (calcTreeWidth 4) [0, 1, 2] `shouldBe` [4, 2, 1]
  it "refuses to build a root without transactions" $
    buildMerkleRoot [] `shouldBe` Left "buildMerkleRoot: a block needs at least one transaction"
  it "refuses a mutated tree with duplicate siblings" $ do
    buildMerkleRoot [txA, txA] `shouldBe` Left "buildMerkleRoot: duplicate transaction hashes (mutated tree)"
    buildMerkleRoot [txA, txB, txC, txC] `shouldBe` Left "buildMerkleRoot: duplicate transaction hashes (mutated tree)"
  it "pairs the last odd transaction with itself without counting it as a duplicate" $
    buildMerkleRoot [txA, txB, txC] `shouldSatisfy` either (const False) (const True)
  it "uses the transaction hash as the root of a single transaction" $
    buildMerkleRoot [txA] `shouldBe` Right txA.get
  it "unpacks flag bits from the least significant bit" $ do
    decodeMerkleFlags [0xaa] `shouldBe` [False, True, False, True, False, True, False, True]
    decodeMerkleFlags [0x01, 0x80] `shouldBe` [True, False, False, False, False, False, False, False, False, False, False, False, False, False, False, True]
    decodeMerkleFlags [] `shouldBe` []
  it "packs flag bits and pads the last byte" $ do
    encodeMerkleFlags [True, True, False, True, True] `shouldBe` [0x1b]
    encodeMerkleFlags (replicate 8 False ++ [True]) `shouldBe` [0x00, 0x01]
    encodeMerkleFlags [] `shouldBe` []
  it "splits a list in chunks" $
    splitIn 3 [1 .. 7 :: Int] `shouldBe` [[1, 2, 3], [4, 5, 6], [7]]
  it "gives the whole list as one chunk for a chunk length below one" $ do
    splitIn 0 [1, 2, 3 :: Int] `shouldBe` [[1, 2, 3]]
    splitIn (-1) [1, 2, 3 :: Int] `shouldBe` [[1, 2, 3]]
    splitIn 0 ([] :: [Int]) `shouldBe` []
  it "packs bools in a byte" $ do
    boolsToWord8 [] `shouldBe` 0
    boolsToWord8 [True] `shouldBe` 1
    boolsToWord8 [False, False, False, False, False, False, False, True] `shouldBe` 128
  describe "block 100000" $ do
    let txids =
          map
            displayTxHash
            [ "8c14f0db3df150123e6f3dbbf30f8b955a8249b62ac1d1ff16284aefa3d06d87",
              "fff2525b8931402dd09222c50775608f75787bd2b87e56995a7bdd30f79702c4",
              "6359f0868171b1d194cbee1af2f16ea598ae8fad666d9b012c8ed2b79a236ec4",
              "e9a66845e05d5abc0ad04ec80f774a7e585c6e8db975962d069a522137b80c1d"
            ]
        root = (displayTxHash "f3e94742aca4b5ef85488dc37c06c3282295ffec960994b2c0d5ac2a25a95766").get
        rightNode = (displayTxHash "8e30899078ca1813be036a073bbf80b86cdddde1c96e9e9c99e9e3782df4ae49").get
    it "parses the block" $ do
      blk <- readBlock "data/block_100000.hex"
      headerHash blk.header `shouldBe` "000000000003ba27aa200b1cecaad478d2b00432346c3f1f3986da1afd33e506"
      map txHash blk.txs `shouldBe` txids
      blk.header.merkle `shouldBe` root
    it "builds its merkle root" $
      buildMerkleRoot txids `shouldBe` Right root
    it "hashes a pair of nodes" $
      hash2 (txids !! 2).get (txids !! 3).get `shouldBe` rightNode
    it "computes single nodes" $ do
      calcHash 0 2 txids `shouldBe` Just (txids !! 2).get
      calcHash 1 1 txids `shouldBe` Just rightNode
      calcHash 2 0 txids `shouldBe` Just root
    it "has no node outside the tree" $ do
      -- four transactions: levels of 4, 2 and 1 nodes
      calcHash 0 4 txids `shouldBe` Nothing
      calcHash 3 0 txids `shouldBe` Nothing
      calcHash (-1) 0 txids `shouldBe` Nothing
      calcHash 0 (-1) txids `shouldBe` Nothing
      calcHash 0 0 [] `shouldBe` Nothing
    it "gives the position of each match, as Bitcoin Core does" $ do
      extractIndexedMatches btc [True, True, False, True, False, False, False, False] [(txids !! 0).get, (txids !! 1).get, rightNode] 4
        `shouldBe` Right (root, [(1, txids !! 1)])
      -- every transaction matches: positions 0 to 3
      fmap (map fst . snd) (extractIndexedMatches btc (replicate 7 True ++ [False]) (map (.get) txids) 4)
        `shouldBe` Right [0, 1, 2, 3]
    it "builds a partial tree for the second transaction" $
      -- root and left node have a match below (1), the first transaction
      -- does not (0), the second does (1), the right node does not (0)
      buildPartialMerkle (zip txids [False, True, False, False])
        `shouldBe` ([True, True, False, True, False], [(txids !! 0).get, (txids !! 1).get, rightNode])
    it "extracts the second transaction from its partial tree" $
      extractMatches btc [True, True, False, True, False, False, False, False] [(txids !! 0).get, (txids !! 1).get, rightNode] 4
        `shouldBe` Right (root, [txids !! 1])
    it "builds a partial tree with no matches" $
      buildPartialMerkle (zip txids (repeat False)) `shouldBe` ([False], [root])
    it "builds a partial tree with every match" $
      buildPartialMerkle (zip txids (repeat True))
        `shouldBe` ([True, True, True, True, True, True, True], map (.get) txids)
  describe "merkle block" $ do
    -- Bitcoin Core's merkle_block_3_and_serialize test: a block with one
    -- transaction, which matches.
    let bytes = fromJust $ decodeHex "0100000079cda856b143d9db2c1caff01d1aecc8630d30625d10e8b4b8b0000000000000b50cc069d6a3e33e3ff84a5c41d9d3febe7c770fdcc96b2c3ff60abe184f196367291b4d4c86041b8fa45d630100000001b50cc069d6a3e33e3ff84a5c41d9d3febe7c770fdcc96b2c3ff60abe184f19630101"
        merkleBlock = either error id $ runGetS deserialize bytes
    it "parses Bitcoin Core's merkle block" $ do
      headerHash merkleBlock.header `shouldBe` "000000000000dab0130bbcc991d3d7ae6b81aa6f50a798888dfe62337458dc45"
      merkleBlock.txn `shouldBe` 1
      length merkleBlock.hashes `shouldBe` 1
      merkleBlock.flags `shouldBe` [True, False, False, False, False, False, False, False]
    it "serializes back to the same bytes" $
      runPutS (serialize merkleBlock) `shouldBe` bytes
    it "extracts the matching transaction" $
      merkleBlockTxs btc merkleBlock `shouldBe` Right [displayTxHash "63194f18be0af63f2c6bc9dc0f777cbefed3d9415c4af83f3ee3a3d669c00cb5"]
    it "accepts the merkle root" $
      testMerkleRoot btc merkleBlock `shouldBe` True
    it "rejects a changed merkle root" $
      merkleBlockTxs btc (MerkleBlock (merkleBlock.header :: BlockHeader) {merkle = txA.get} merkleBlock.txn merkleBlock.hashes merkleBlock.flags)
        `shouldBe` Left "merkleBlockTxs: Merkle root incorrect"
    it "rejects a changed transaction count" $
      testMerkleRoot btc (merkleBlock :: MerkleBlock) {txn = 2} `shouldBe` False
  describe "malformed partial trees" $ do
    it "rejects a block without transactions" $
      extractMatches btc [True] [txA.get] 0 `shouldBe` Left "extractMatches: number of transactions can not be 0"
    it "rejects too many transactions" $
      -- 1000000 bytes / 60 bytes per transaction is 16666
      extractMatches btc [True] [txA.get] 16667 `shouldBe` Left "extractMatches: number of transactions excessively high"
    it "rejects more hashes than transactions" $
      extractMatches btc [True] [txA.get, txB.get] 1 `shouldBe` Left "extractMatches: More hashes provided than the number of transactions"
    it "rejects fewer flags than hashes" $
      extractMatches btc [True] [txA.get, txB.get] 2 `shouldBe` Left "extractMatches: At least one bit per node and one bit per hash"
    it "rejects a tree that runs out of flags" $
      extractMatches btc [True, True] [txA.get, txB.get] 2 `shouldBe` Left "extractMatches: ran out of flag bits"
    it "rejects a tree that runs out of hashes" $
      extractMatches btc [True, True, True] [txA.get] 2 `shouldBe` Left "extractMatches: ran out of hashes"
    it "rejects identical left and right branches" $
      -- a mutated tree: the four leaves [a, b, c, c] have the root of [a, b, c]
      extractMatches btc [True, True, True, True, True, True, True, False] (map (.get) [txA, txB, txC, txC]) 4
        `shouldBe` Left "extractMatches: identical left and right branches (mutated tree)"
    it "rejects unused hashes" $
      extractMatches btc (False : replicate 7 False) [txA.get, txB.get] 2 `shouldBe` Left "extractMatches: All hashes were not consumed"
    it "rejects unused flags beyond the last byte" $
      extractMatches btc (True : replicate 8 False) [txA.get] 1 `shouldBe` Left "extractMatches: All bits were not consumed"
    it "accepts unused flags within the last byte" $
      extractMatches btc (True : replicate 7 False) [txA.get] 1 `shouldBe` Right (txA.get, [txA])

-- 0 → → 2015 → → → → → → → 4031
--       ↓
--       → → 2035 → → → → → → 4035*
--           ↓
--           → → 2185
splitChain :: Network -> State HeaderMemory ()
splitChain net = do
  start <- go 1 net.genesisHeader 2015
  e 2015 start
  tail1 <- go 2 start.header 2016
  e 4031 tail1
  tail2 <- go 3 start.header 20
  e 2035 tail2
  tail3 <- go 4 tail2.header 2000
  e 4035 tail3
  tail4 <- go 5 tail2.header 150
  e 2185 tail4
  sp1 <- splitPoint tail1 tail3
  unless (sp1 == start) $
    error $
      "Split point wrong between blocks 4031 and 4035: "
        ++ show sp1.height
  sp2 <- splitPoint tail4 tail3
  unless (sp2 == tail2) $
    error $
      "Split point wrong between blocks 2185 and 4035: "
        ++ show sp2.height
  where
    e n bn@BlockNode {} =
      unless (bn.height == n) $
        error $
          "Node height "
            ++ show bn.height
            ++ " of first chunk should be "
            ++ show n
    -- mine and connect n blocks on top of the start header, returning the tip
    go seed start n = do
      let bhs = appendBlocks net seed start n
      bnE <- connectBlocks net myTime bhs
      case bnE of
        Right (tip : _) -> return tip
        Right [] -> error "No blocks were connected"
        Left ex -> error ex

{- Merkle Trees -}

testTreeWidth :: Int -> Property
testTreeWidth i = i /= 0 ==> calcTreeWidth (abs i) (calcTreeHeight $ abs i) == 1

testBaseWidth :: Int -> Property
testBaseWidth i = i /= 0 ==> calcTreeWidth (abs i) 0 == abs i

buildExtractTree :: Network -> [(TxHash, Bool)] -> Bool
buildExtractTree net txs =
  Right r == buildMerkleRoot (map fst txs) && m == map fst (filter snd txs)
  where
    (f, h) = buildPartialMerkle txs
    (r, m) =
      either error id $
        extractMatches net f h (length txs)

testCompact :: Assertion
testCompact = do
  assertEqual "vector 1" 0x05123456 (encodeCompact 0x1234560000)
  assertEqual "vector 2" (0x1234560000, False) (decodeCompact 0x05123456)
  assertEqual "vector 3" 0x0600c0de (encodeCompact 0xc0de000000)
  assertEqual "vector 4" (0xc0de000000, False) (decodeCompact 0x0600c0de)
  assertEqual "vector 5" 0x05c0de00 (encodeCompact (-0x40de000000))
  assertEqual "vector 6" (-0x40de000000, False) (decodeCompact 0x05c0de00)

testCompactBitcoinCore :: Assertion
testCompactBitcoinCore = do
  assertEqual "zero" (0, False) (decodeCompact 0x00000000)
  assertEqual
    "zero (encode · decode)"
    0x00000000
    (encodeCompact . fst $ decodeCompact 0x00000000)
  assertEqual "rounds to zero" (0, False) (decodeCompact 0x00123456)
  assertEqual "rounds to zero" (0, False) (decodeCompact 0x01003456)
  assertEqual "rounds to zero" (0, False) (decodeCompact 0x02000056)
  assertEqual "rounds to zero" (0, False) (decodeCompact 0x03000000)
  assertEqual "rounds to zero" (0, False) (decodeCompact 0x04000000)
  assertEqual "rounds to zero" (0, False) (decodeCompact 0x00923456)
  assertEqual "rounds to zero" (0, False) (decodeCompact 0x01803456)
  assertEqual "rounds to zero" (0, False) (decodeCompact 0x02800056)
  assertEqual "rounds to zero" (0, False) (decodeCompact 0x03800000)
  assertEqual "rounds to zero" (0, False) (decodeCompact 0x04800000)
  assertEqual "vector 1 (decode)" (0x12, False) (decodeCompact 0x01123456)
  assertEqual
    "vector 1 (encode · decode)"
    0x01120000
    (encodeCompact . fst $ decodeCompact 0x01123456)
  assertEqual "0x80 bit set" 0x02008000 (encodeCompact 0x80)
  assertEqual
    "vector 2 (negative) (decode)"
    (-0x7e, False)
    (decodeCompact 0x01fedcba)
  assertEqual
    "vector 2 (negative) (encode · decode)"
    0x01fe0000
    (encodeCompact . fst $ decodeCompact 0x01fedcba)
  assertEqual "vector 3 (decode)" (0x1234, False) (decodeCompact 0x02123456)
  assertEqual
    "vector 3 (encode · decode)"
    0x02123400
    (encodeCompact . fst $ decodeCompact 0x02123456)
  assertEqual "vector 4 (decode)" (0x123456, False) (decodeCompact 0x03123456)
  assertEqual
    "vector 4 (encode · decode)"
    0x03123456
    (encodeCompact . fst $ decodeCompact 0x03123456)
  assertEqual
    "vector 5 (decode)"
    (0x12345600, False)
    (decodeCompact 0x04123456)
  assertEqual
    "vector 5 (encode · decode)"
    0x04123456
    (encodeCompact . fst $ decodeCompact 0x04123456)
  assertEqual
    "vector 6 (decode)"
    (-0x12345600, False)
    (decodeCompact 0x04923456)
  assertEqual
    "vector 6 (encode · decode)"
    0x04923456
    (encodeCompact . fst $ decodeCompact 0x04923456)
  assertEqual
    "vector 7 (decode)"
    (0x92340000, False)
    (decodeCompact 0x05009234)
  assertEqual
    "vector 7 (encode · decode)"
    0x05009234
    (encodeCompact . fst $ decodeCompact 0x05009234)
  assertEqual
    "vector 8 (decode)"
    ( 0x1234560000000000000000000000000000000000000000000000000000000000,
      False
    )
    (decodeCompact 0x20123456)
  assertEqual
    "vector 8 (encode · decode)"
    0x20123456
    (encodeCompact . fst $ decodeCompact 0x20123456)
  assertBool "vector 9 (decode) (overflow)" (snd $ decodeCompact 0xff123456)
  assertBool
    "vector 9 (decode) (positive)"
    ((> 0) . fst $ decodeCompact 0xff123456)

runMerkleVector :: (Text, [Text]) -> Assertion
runMerkleVector (r, hs) =
  assertEqual "merkle vector" (Right (f r).get) (buildMerkleRoot (map f hs))
  where
    f = fromJust . hexToTxHash

merkleVectors :: [(Text, [Text])]
merkleVectors =
  -- Block 000000000000cd7e8cf6510303dde76121a1a791c15dba0be4be7022b07cf9e1
  [ ( "fb6698ac95b754256c5e71b4fbe07638cb6ca83ee67f44e181b91727f09f4b1f",
      [ "dd96fdcfaec994bf583af650ff6022980ee0ba1686d84d0a3a2d24eabf34bc52",
        "1bc216f786a564378710ae589916fc8e092ddfb9f24fe6c47b733550d476d5d9",
        "a1db0b0194426064b067899ff2d975fb277fd52dbb1a38370800c76dd6503d41",
        "d69f7fb0e668fbd437d1bf5211cc34d7eb8746f50cfddf705fe10bc2f8f7035f",
        "5b4057cd80be7df5ed2ac42b776897ed3c26e3a01e4072075b8129c587094ef6",
        "ed6dabcfba0ef43c50d89a8a0e4b236b1bc6585d4c3bbf49728b55f44312d6bc",
        "056aaa9a3c635909c794e9b0acc7dccb0456c59a84c6b08417335bee4515e3d3",
        "05bae5f1d1c874171692e1fc06f664e63eb143d3f096601ef938e4a9012eee66",
        "b5e48e94e3f2fba197b3f591e01f47e185d7834d669529d44078e41c671aab0f",
        "3b56aeadfc0c5484fd507bc89f13f2e5f61c42e0a4ae9062eda9a9aeef7db6a4",
        "2affa187e1ebb94a2a86578b9f64951e854ff3d346fef259acfb6d0f5212e0d3"
      ]
    ),
    -- Block 00000000000007cc4b6f07bfed72bccc1ed8dd031a93969a4c22211f784457d4

    ( "886fea311d2dc64c315519f2d647e43998d780d2170f77e53dc0d85bf2ee680c",
      [ "c9c9e5211512629fd111cc071d745b8c79bf486b4ea95489eb5de08b5d786b8e",
        "20beb0ee30dfd323ade790ce9a46ae7a174f9ea44ce22a17c4d4eb23b7016f51",
        "d4cb7dd741e78a8f57e12f6c8ddb0361ff2a5bf9365bd7d7df761060847daf9a",
        "ddbfa6fdd29d4b47aeaadf82a4bf0a93d58cd7d8401fabf860a1ae8eeb51f42e",
        "9d82bafe44abee248b968c86f165051c8413482c232659795335c52922dab471",
        "86035372d31b53efd848cea7231aa9738c209aff64d3c59b1619341afb5b6ba3",
        "11e7a7393d9658813dfaebc04fa6d4b73bac8d641bffa7067da879523d43d030",
        "2f676b9aa5bc0ebf3395032c84c466e40cac29f80434cd1138e31c2d0fcc5c13",
        "37567d559fbfae07fda9a90de0ce30b202128bc8ebdfef5ad2b53e865a3478c2",
        "0b8e6c1200c454361e94e261738429e9c9b8dcffd85ec8511bbf5dc7e2e0ada8"
      ]
    ),
    -- Block 00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048

    ( "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098",
      ["0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098"]
    ),
    -- Block 000000000004d160ac1f7b775d7c1823345aeadd5fcb29ca2ad2403bb7babd4c

    ( "aae018650f513fc42d55b2210ec3ceeeb194fb1261d37989de07451fc0cbac5c",
      [ "a4454f22831acd7904a9902c5070a3ee4bf4c2b13bc6b2dc66735dd3c4414028",
        "45297f334278885108dd38a0b689ed95a4373dd3f7e4413e6aebdc2654fb771b"
      ]
    ),
    -- Block 000000000001d1b13a7e86ddb20da178f20d6da5cd037a29c2a15b8b84cc774e

    ( "ca3580505feb87544760ac14a5859659e23be05f765bbed9f86a3c9aad1a5d0c",
      [ "60702384c6e9d34ff03c2b3e726bdc649befe603216815bd0a2974921d0d9549",
        "11f40f58941d2a81a1616a3b84b7dd8b9d07e68750827de488c11a18f54220bb",
        "d78e82527aa8cf16e375010bc666362c0258d3c0da1885a1871121706da8b633"
      ]
    ),
    -- Block 0000000000000630a4e2266a31776e952a19b7c99a6387917d9de9032f608021

    ( "dcce8be0a9a41e7bb726c5b49d957d90b5308e3dc5dce070ccbc8996e265a6c2",
      [ "c0f58ff12cd1023b05f8f7035cc62bf50958ddb216a4e0eb5471deb7ef25fe81",
        "24e5bbf9008641b8fcf3d076fef66c28c695362ba9f6a6042f8275a98414ee92",
        "e8e1f72abad5e34dabc0f6de46a484b17a9af857d1c41de19482fadf6f7f4b27",
        "540e4d34d9fd9e5ec02853054be7ad9260379bc23388489049cca1b0f7cf518a",
        "324444835c5fe0545f98c4240011b75e6ea1bb76f41829e4cfbe7f75b6cee924",
        "e7d31437ac21bceb0c222a82b2723e2b8a7654147e33397679f041537022a4b2",
        "a8b5768d8b33525ee89d546a6a6897f8e42ba9d56a2c5e871a5d2ab40258dc95",
        "7ba712b31bae8d45810a5cda3838c7e7fb9abd6e88bb4b3ee79be9ea2f714bb4",
        "2ae1c4d927b06edaa626b230976ad8062bbae24da9378d1de2409da5ab08a26d",
        "3c417dc8087d6878003624b74431e17fec9ca761389034b1b1e0f32cbfb11f4f",
        "de6de7beae8d8c98c7d46b4409d5460e58e3204d8b4caed256c7471998595909",
        "c7c3c211402b7c4379f7b01fadc67260ee58d11e8d0bcce3d68cb45f3467e99d",
        "77aa2717e727a096d81074bd46ae59462692d20a1acc1a01b2535518ae5aeb53",
        "4859a710bb673aca46208bbd59d1000ae990dafff5f70b56f0853aeeaea3948b",
        "38deca6991988e461b83aa0d49ffef0f304c4b760371682d152eeb8c56a48174",
        "648f4f50dada3574e2dfe2dc68956b01dd97d543859a3540bbe1ef5418d0e494",
        "9cd7be42c2f0cd8bf38738c162cd05108e213ec7958bf2571cb627872963f5c4",
        "6740e0dd8b97e23864af41839fc197238d2f0dbefce9a82c657556be65c465fa",
        "f75c2e4b70db4b0aabc44b77af1ae75d305340fcf6e7b5f806ddcba4aa42b55d",
        "e125c488636749da68e6696b97525a77146c0777c7946927e37afd513d74a4e6",
        "c20526f119aea10880af631eba7f0b60385a22e0b0c402fe8508d41952e58be9",
        "6456c023c7e245f5c57a168633a23f57f4fadb651115f807694a6bed14ae3b55",
        "98b26e364e2888c9f264e4b5e13103c89608609774eb07ce933d8a2a45d19776",
        "2efaa4f167bb65ba5684f8076cd9279fd67fd9c67388c8862809bab5542e637d",
        "ec44eeb84d8d976d77079a822710b4dfdb11a2d9a03d8cc00bab0ae424e84666",
        "410730d9f807d81ac48b8eafac6f1d36642c1c370241b367a35f0bac6ac7c05f",
        "e95a7d0d477fd3db22756a3fd390a50c7bc48dc9e946fea9d24bd0866b3bb0e9",
        "a72fec99d14939216628aaf7a0afc4c017113bcae964e777e6b508864eeaacc4",
        "8548433310fcf75dbbc042121e8318c678e0a017534786dd322a91cebe8d213f"
      ]
    )
  ]

testSubsidy :: Network -> Assertion
testSubsidy net = go (2 * 50 * 100 * 1000 * 1000) 0
  where
    go previous_subsidy halvings = do
      let height = halvings * net.halvingInterval
          subsidy = computeSubsidy net height
      if halvings >= 64
        then subsidy `shouldBe` 0
        else do
          subsidy `shouldBe` (previous_subsidy `div` 2)
          go subsidy (halvings + 1)

data AsertBlock = AsertBlock Int Integer Integer Word32

data AsertVector = AsertVector String Integer Integer Word32 [AsertBlock]

readAsertVector :: FilePath -> IO AsertVector
readAsertVector p = do
  (d : ah : apt : ab : _ : _ : _ : _ : xs) <- lines <$> readFile ("data/" ++ p)
  let desc = drop 16 d
      anchor_height = read (words ah !! 3)
      anchor_parent_time = read (words apt !! 4)
      anchor_nbits = read (words ab !! 3)
      blocks = map (f . words) (init xs)
  return $
    AsertVector
      desc
      anchor_height
      anchor_parent_time
      anchor_nbits
      blocks
  where
    f [i, h, t, g] = AsertBlock (read i) (read h) (read t) (read g)
    f _ = undefined

asertTests :: FilePath -> SpecWith ()
asertTests file = do
  v@(AsertVector d _ _ _ _) <- runIO $ readAsertVector file
  it d $ testAsertBits v

-- | The vectors use the mainnet proof-of-work limit and a two-day half-life.
testAsertBits :: AsertVector -> Assertion
testAsertBits (AsertVector _ anchor_height anchor_parent_time anchor_bits blocks) =
  forM_ blocks $ \(AsertBlock _ h t g) ->
    computeAsertBits
      0x00000000ffff0000000000000000000000000000000000000000000000000000
      (2 * 24 * 60 * 60)
      anchor_bits
      (t - anchor_parent_time)
      (h - anchor_height)
      `shouldBe` g

-- | The result must be a failure whose message holds the given words.
leftWith :: Either String a -> String -> Expectation
leftWith result msg =
  case result of
    Left e | msg `isInfixOf` e -> return ()
    Left e -> expectationFailure ("expected a failure mentioning " ++ show msg ++ ", got " ++ show e)
    Right _ -> expectationFailure ("expected a failure mentioning " ++ show msg ++ ", got a value")

versionRuleSpec :: Spec
versionRuleSpec = describe "block version rule, three independent conditions" $ do
  -- ContextualCheckBlockHeader in Bitcoin Core and Bitcoin Cash Node rejects
  -- when (version < 2 and height >= BIP34) or (version < 3 and height >=
  -- BIP66) or (version < 4 and height >= BIP65).
  it "refuses version 1 from the BIP66 height of bitcoin cash regtest, 1251" $ do
    -- BIP34 is at 100000000 there, far above BIP66 at 1251 and BIP65 at 1351
    validVersion bchRegTest 1250 1 `shouldBe` True
    validVersion bchRegTest 1251 1 `shouldBe` False
    validVersion bchRegTest 1251 2 `shouldBe` False
    validVersion bchRegTest 1251 3 `shouldBe` True
  it "refuses version 3 from the BIP65 height of bitcoin cash regtest, 1351" $ do
    validVersion bchRegTest 1350 3 `shouldBe` True
    validVersion bchRegTest 1351 3 `shouldBe` False
    validVersion bchRegTest 1351 4 `shouldBe` True
  it "refuses a negative version from the BIP66 height of bitcoin cash regtest" $
    validVersion bchRegTest 1251 0xffffffff `shouldBe` False
  it "refuses versions 2 and 3 at height 3 of bitcoin cash testnet4, where BIP65 comes before BIP66" $ do
    -- BIP34 at 2, BIP65 at 3, BIP66 at 4
    validVersion bchTest4 1 1 `shouldBe` True
    validVersion bchTest4 2 1 `shouldBe` False
    validVersion bchTest4 2 2 `shouldBe` True
    validVersion bchTest4 3 2 `shouldBe` False
    validVersion bchTest4 3 3 `shouldBe` False
    validVersion bchTest4 3 4 `shouldBe` True
  it "refuses a version 1 header at height 1252 of bitcoin cash regtest through connectBlock" $
    let net = bchRegTest
        result = withChain net $ do
          chain net net.genesisHeader 1251
          best <- getBestBlockHeader
          let hdr = mineBlock net 0 (headerWithVersion 1 (headerOn best.header (best.header.timestamp + 600) 0x207fffff))
          connectHeight net (best.header.timestamp + 1200) hdr
     in result `shouldBe` Left "Invalid block version: 1"

knownHeaderSpec :: Spec
knownHeaderSpec = describe "headers that are already in the store" $ do
  -- AcceptBlockHeader in Bitcoin Core returns the block index it already has
  -- for a known header, before any other check.
  let base = btcRegTest
      t0 = base.genesisHeader.timestamp
      b1 = mineOn base base.genesisHeader (t0 + 600) 0x207fffff
      b2 = mineOn base b1 (t0 + 1200) 0x207fffff
      b3 = mineOn base b2 (t0 + 1800) 0x207fffff
      -- regtest with a checkpoint on block 2
      net = (base :: Network) {checkpoints = [(2, headerHash b2)]}
  it "returns the stored node for a known header at or below a checkpoint that was reached" $
    withChain net (connectAll net [b1, b2, b3] >> connectHeight net myTime b1) `shouldBe` Right 1
  it "returns the stored nodes for a known batch, and keeps the best block" $
    let (heights, best) = withChain net $ do
          connectAll net [b1, b2, b3]
          r <- connectBlocks net myTime [b1, b2]
          bb <- getBestBlockHeader
          return (fmap (map (.height)) r, bb.height)
     in (heights, best) `shouldBe` (Right [2, 1], 3)
  it "still refuses another header at the height of a checkpoint that was reached" $
    let other = mineBlock base 1 (headerOn b1 (t0 + 1260) 0x207fffff)
     in withChain net (connectAll net [b1, b2, b3] >> connectHeight net myTime other)
          `shouldBe` Left "Rewriting pre-checkpoint chain: 2"

merkleLimitSpec :: Spec
merkleLimitSpec = describe "merkle block size limits" $ do
  -- A proof visits at most one tree node per flag bit. Every node it visits
  -- lies above a stored hash, so it uses at most (height + 1) bits per hash,
  -- and no more bits than the tree has nodes. CPartialMerkleTree in Bitcoin
  -- Core refuses more hashes than transactions and unused flag bytes.
  let header = runPutS (serialize btc.genesisHeader)
      hashA = runPutS (serialize txA.get)
      one = B.pack [1, 0, 0, 0]
      parseMerkle bytes = runGetS deserialize bytes :: Either String MerkleBlock
  it "refuses a merkle block of one transaction with 1000 flag bytes" $
    -- 0xfde803 is the count 1000
    parseMerkle (header <> one <> B.pack [1] <> hashA <> B.pack [0xfd, 0xe8, 0x03] <> B.replicate 1000 1)
      `leftWith` "flag"
  it "refuses a merkle block of one transaction with two flag bytes" $
    -- one transaction is one node, one flag bit, one byte
    parseMerkle (header <> one <> B.pack [1] <> hashA <> B.pack [2, 1, 0]) `leftWith` "flag"
  it "reads a merkle block of one transaction with one flag byte" $
    fmap (\m -> (m.txn, length m.hashes, length m.flags)) (parseMerkle (header <> one <> B.pack [1] <> hashA <> B.pack [1, 1]))
      `shouldBe` Right (1, 1, 8)
  it "refuses a merkle block with more hashes than transactions" $
    parseMerkle (header <> one <> B.pack [2] <> hashA <> hashA <> B.pack [1, 1]) `leftWith` "hashes"
  it "reads the proof of the second transaction of block 100000" $
    -- four transactions, three hashes, the five flag bits 1 1 0 1 0 in one byte: 0x0b
    let hashes =
          map
            (runPutS . serialize . (.get) . displayTxHash)
            [ "8c14f0db3df150123e6f3dbbf30f8b955a8249b62ac1d1ff16284aefa3d06d87",
              "fff2525b8931402dd09222c50775608f75787bd2b87e56995a7bdd30f79702c4",
              "8e30899078ca1813be036a073bbf80b86cdddde1c96e9e9c99e9e3782df4ae49"
            ]
        bytes = header <> B.pack [4, 0, 0, 0] <> B.pack [3] <> B.concat hashes <> B.pack [1, 0x0b]
     in fmap (\m -> extractMatches btc m.flags m.hashes (fromIntegral m.txn)) (parseMerkle bytes)
          `shouldBe` Right
            ( Right
                ( (displayTxHash "f3e94742aca4b5ef85488dc37c06c3282295ffec960994b2c0d5ac2a25a95766").get,
                  [displayTxHash "fff2525b8931402dd09222c50775608f75787bd2b87e56995a7bdd30f79702c4"]
                )
            )
  it "refuses a proof of four transactions and three hashes with two flag bytes" $
    -- three hashes under a tree of height 2 use at most 3 * 3 = 9 bits, but
    -- the tree has only 7 nodes: one byte
    let bytes = header <> B.pack [4, 0, 0, 0] <> B.pack [3] <> B.concat (replicate 3 hashA) <> B.pack [2, 0x0b, 0]
     in parseMerkle bytes `leftWith` "flag"
  it "refuses a proof of one hash with three flag bytes under a tree of 1000 transactions" $
    -- 1000 transactions make a tree of height 10. One hash lies under at
    -- most 11 nodes, so it uses at most 11 flag bits: two bytes.
    let thousand = B.pack [0xe8, 0x03, 0, 0]
     in do
          parseMerkle (header <> thousand <> B.pack [1] <> hashA <> B.pack [3, 0, 0, 0]) `leftWith` "flag"
          fmap (\m -> length m.flags) (parseMerkle (header <> thousand <> B.pack [1] <> hashA <> B.pack [2, 0, 0]))
            `shouldBe` Right 16
  it "allows 33 flag bits per hash at most, and no more bits than the tree has nodes" $ do
    -- 7 transactions: widths 7, 4, 2, 1, so 14 nodes and a height of 3
    maxMerkleFlagBits 7 1 `shouldBe` 4
    maxMerkleFlagBits 7 3 `shouldBe` 12
    maxMerkleFlagBits 7 4 `shouldBe` 14
    maxMerkleFlagBits 7 7 `shouldBe` 14
    maxMerkleFlagBits 1 1 `shouldBe` 1
    maxMerkleFlagBits 0 0 `shouldBe` 0
    -- 2^32 - 1 transactions make a tree of height 32
    maxMerkleFlagBits 4294967295 2 `shouldBe` 66
  it "accepts a proof over 16666 transactions and refuses 16667 on bitcoin" $ do
    -- 1000000 bytes of block / 60 bytes per transaction = 16666
    extractMatches btc [False] [txA.get] 16666 `shouldBe` Right (txA.get, [])
    extractMatches btc [False] [txA.get] 16667 `shouldBe` Left "extractMatches: number of transactions excessively high"

chainConstantsSpec :: Spec
chainConstantsSpec = describe "chain parameters of the reference nodes" $ do
  it "retargets every 144 blocks on bitcoin regtest, where the timespan is one day" $ do
    -- kernel/chainparams.cpp of Bitcoin Core: nPowTargetTimespan = 24 * 60 * 60
    btcRegTest.targetTimespan `shouldBe` 86400
    diffInterval btcRegTest `shouldBe` 144
  it "retargets every 2016 blocks on the other networks" $
    map diffInterval [btc, btcTest, btcTest4, bch, bchTest, bchTest4, bchRegTest] `shouldBe` replicate 7 2016
  it "starts the EDA and the DAA one block after the heights of Bitcoin Cash Node" $ do
    -- chainparams.cpp of Bitcoin Cash Node: uahfHeight 478558, daaHeight
    -- 504031 on mainnet; 1155875 and 1188697 on testnet3; 6 and 3000 on testnet4
    (bch.edaHeight, bch.daaHeight) `shouldBe` (Just 478559, Just 504032)
    (bchTest.edaHeight, bchTest.daaHeight) `shouldBe` (Just 1155876, Just 1188698)
    (bchTest4.edaHeight, bchTest4.daaHeight) `shouldBe` (Just 7, Just 3001)
  it "activates ASERT at the time of Bitcoin Cash Node, with its half-lives" $ do
    -- axionActivationTime = 1605441600; nASERTHalfLife is two days on
    -- mainnet (172800 seconds) and one hour on the test networks (3600)
    map (.asertActivationTime) [bch, bchTest, bchTest4, bchRegTest] `shouldBe` replicate 4 (Just 1605441600)
    map (.asertHalfLife) [bch, bchTest, bchTest4, bchRegTest] `shouldBe` [172800, 3600, 3600, 172800]
  it "halves the subsidy every 210000 blocks, and every 150 on regtest" $ do
    map (.halvingInterval) [btc, btcTest, btcTest4, bch, bchTest, bchTest4] `shouldBe` replicate 6 210000
    map (.halvingInterval) [btcRegTest, bchRegTest] `shouldBe` [150, 150]
  it "pays 50 coins before block 210000 and 25 from it" $ do
    computeSubsidy btc 209999 `shouldBe` 5000000000
    computeSubsidy btc 210000 `shouldBe` 2500000000
    computeSubsidy btc 420000 `shouldBe` 1250000000
    computeSubsidy btcRegTest 149 `shouldBe` 5000000000
    computeSubsidy btcRegTest 150 `shouldBe` 2500000000
  it "pays one satoshi until block 6929999 and nothing from block 6930000" $ do
    -- 33 halvings: 5000000000 shifted right by 32 is 1, by 33 is 0
    computeSubsidy btc 6929999 `shouldBe` 1
    computeSubsidy btc 6930000 `shouldBe` 0
  it "has the checkpoint of block 33333 on bitcoin" $ do
    validCP btc 33333 "000000002dd5588a74784eaa7ab0507a18ad16a236e7b1ce69f00d7ddfb5d0a6" `shouldBe` True
    validCP btc 33333 "000000002dd5588a74784eaa7ab0507a18ad16a236e7b1ce69f00d7ddfb5d0a7" `shouldBe` False
  it "enforces BIP94 on bitcoin testnet4 only" $ do
    map (.bip94) [btc, btcTest, btcTest4, btcRegTest, bch, bchTest, bchTest4, bchRegTest]
      `shouldBe` [False, False, True, False, False, False, False, False]
    -- the first block of a period may be at most 600 seconds before its parent
    validTimeWarp btcTest4 2016 10000 9400 `shouldBe` True
    validTimeWarp btcTest4 2016 10000 9399 `shouldBe` False
    validTimeWarp btc 2016 10000 9399 `shouldBe` True
  it "computes the four retargets of the pow_tests of Bitcoin Core" $ do
    let next lastTime lastBits firstTime =
          calcNextWork btc (btc.genesisHeader :: BlockHeader) {timestamp = lastTime, bits = lastBits} firstTime
    -- blocks 30240 to 32255, the first difficulty change
    next 1262152739 0x1d00ffff 1261130161 `shouldBe` 0x1d00d86a
    -- blocks 0 to 2015, capped at the proof-of-work limit
    next 1233061996 0x1d00ffff 1231006505 `shouldBe` 0x1d00ffff
    -- blocks 66528 to 68543, limited to a quarter of the timespan
    next 1279297671 0x1c05a3f4 1279008237 `shouldBe` 0x1c0168fd
    -- limited to four times the timespan
    next 1269211443 0x1c387f6f 1263163443 `shouldBe` 0x1d00e1fd
  it "computes the retarget of bitcoin testnet4 block 157248" $
    -- first block of the period: bits 0x19037e43, time 1791203299. Last
    -- block: time 1792638187. 1434888 s of 1209600 s is a factor of 1.18625,
    -- and 0x037e43 * 1.18625 = 0x0424d1.
    calcNextWork btcTest4 (btcTest4.genesisHeader :: BlockHeader) {timestamp = 1792638187, bits = 0x19037e43} 1791203299
      `shouldBe` 0x190424d1
  it "counts 2^255 hashes of work for a target of one" $
    -- 2^256 / (1 + 1)
    headerWork (btc.genesisHeader :: BlockHeader) {bits = 0x01010000}
      `shouldBe` 57896044618658097711785492504343953926634992332820282019728792003956564819968

activationSpec :: Spec
activationSpec = describe "first block of each Bitcoin Cash difficulty rule" $ do
  -- Expected bits come from a Python port of GetNextEDAWorkRequired and
  -- GetNextCashWorkRequired of Bitcoin Cash Node.
  it "uses the DAA for the block at the DAA height, and not for the block before" $ do
    -- DAA from block 150. Blocks every 300 seconds at bits 0x1f00ffff.
    -- Block 149 keeps the bits of its parent. Block 150 gets the DAA: 144
    -- blocks of work in 43200 seconds, twice the rate, so half the target.
    -- The DAA needs a parent at or above the retarget interval, as in
    -- Bitcoin Cash Node, so the interval is 144 blocks here.
    let net = (cashNet :: Network) {daaHeight = Just 150, targetTimespan = 144 * 600}
        required n = withChain net (storeChain (evenlySpaced net 300 n 0x1f00ffff) >> requiredAfter net (net.genesisHeader.timestamp + 300 * (fromIntegral n + 1)))
    required 148 `shouldBe` 0x1f00ffff
    required 149 `shouldBe` 0x1e7fff80
  it "uses the EDA for the block at the EDA height, and not for the block before" $ do
    -- EDA from block 20. Blocks every three hours at bits 0x1f00ffff, so the
    -- median time past moves 18 hours in six blocks, more than 12. Block 19
    -- keeps the bits of its parent. Block 20 gets a target a quarter higher:
    -- 0x00ffff + 0x003fff = 0x013ffe.
    let net = (cashNet :: Network) {edaHeight = Just 20}
        required n = withChain net (storeChain (evenlySpaced net 10800 n 0x1f00ffff) >> requiredAfter net (net.genesisHeader.timestamp + 10800 * (fromIntegral n + 1)))
    required 18 `shouldBe` 0x1f00ffff
    required 19 `shouldBe` 0x1f013ffe

minimumWorkSpec :: Spec
minimumWorkSpec = describe "minimum chain work" $ do
  -- A regtest header at bits 0x207fffff has a target of 0x7fffff * 2^232,
  -- so its work is 2^256 / (target + 1) = 2. Genesis has 2, block 1 has 4,
  -- block 2 has 6, block 3 has 8 and so on.
  let base = btcRegTest
      t0 = base.genesisHeader.timestamp
      b1 = mineOn base base.genesisHeader (t0 + 600) 0x207fffff
      b2 = mineOn base b1 (t0 + 1200) 0x207fffff
      b3 = mineOn base b2 (t0 + 1800) 0x207fffff
      b4 = mineOn base b3 (t0 + 2400) 0x207fffff
      -- other blocks on top of genesis, block 1 and block 2
      fork0 = mineBlock base 1 (headerOn base.genesisHeader (t0 + 660) 0x207fffff)
      fork1 = mineBlock base 1 (headerOn b1 (t0 + 1260) 0x207fffff)
      fork2 = mineBlock base 1 (headerOn b2 (t0 + 1860) 0x207fffff)
      -- the chain is known to have a work of 8, which block 3 reaches
      net = (base :: Network) {minimumChainWork = 8}
  it "has the work the test assumes" $
    map headerWork [base.genesisHeader, b1] `shouldBe` [2, 2]
  it "accepts a fork below the minimum chain work while the best block is below it too" $
    withChain net (connectAll net [b1, b2] >> connectHeight net myTime fork0) `shouldBe` Right 1
  it "refuses a fork whose chain has less than the minimum chain work once the best block has it" $ do
    -- best block 3 with a work of 8. A second block 1 would have 4, a second block 2 would have 6.
    withChain net (connectAll net [b1, b2, b3] >> connectHeight net myTime fork0)
      `shouldBe` Left "Header chain has less work than the minimum chain work: 1"
    withChain net (connectAll net [b1, b2, b3] >> connectHeight net myTime fork1)
      `shouldBe` Left "Header chain has less work than the minimum chain work: 2"
  it "accepts a fork whose chain has exactly the minimum chain work" $
    -- a second block 3 has a work of 8
    withChain net (connectAll net [b1, b2, b3] >> connectHeight net myTime fork2) `shouldBe` Right 3
  it "accepts the next block of the best chain" $
    withChain net (connectAll net [b1, b2, b3] >> connectHeight net myTime b4) `shouldBe` Right 4
  it "applies no minimum on regtest, where it is zero" $
    withChain base (connectAll base [b1, b2, b3] >> connectHeight base myTime fork0) `shouldBe` Right 1
  it "has the minimum chain work of Bitcoin Core 32.1 and Bitcoin Cash Node on each network" $ do
    -- nMinimumChainWork in kernel/chainparams.cpp of Bitcoin Core v32.1
    btc.minimumChainWork `shouldBe` 0x0000000000000000000000000000000000000000145ec036acc5ba740052af1a0
    btcTest.minimumChainWork `shouldBe` 0x0000000000000000000000000000000000000000000017f49f702147f10c0eb6
    btcTest4.minimumChainWork `shouldBe` 0x000000000000000000000000000000000000000000000e346a558455ade8eca9
    btcRegTest.minimumChainWork `shouldBe` 0
    -- chainparamsconstants.h of Bitcoin Cash Node at 3d13ce8
    bch.minimumChainWork `shouldBe` 0x0000000000000000000000000000000000000000030fd678912166474fe93f14
    bchTest.minimumChainWork `shouldBe` 0x00000000000000000000000000000000000000000000011fdbbe582349040762
    bchTest4.minimumChainWork `shouldBe` 0x000000000000000000000000000000000000000000000000bd5a1b5bda45b5da
    bchRegTest.minimumChainWork `shouldBe` 0

coreProofSpec :: Spec
coreProofSpec = describe "merkle proofs made by Bitcoin Core 32.1" $ do
  -- Output of gettxoutproof on a regtest block of seven transactions,
  -- 307105bce8534c8829f50dbee4a0f5d5f702327443d7078853d0003b19099718. The
  -- result of that call is a serialized merkle block.
  let proofOfOne = fromJust $ decodeHex "00000020890b601aa1dcb84e3647ac08bba63d1b2f4c20f493fa83c81c96e113775e525996ec6f2e21c4e47055a7977fefa3567adcf9618591645e1aa004a366a7bd60d5ace5ec6affff7f2000000000070000000431094d2f5d072ffc7cee499023fb27b7910b7c0579f43d6ef46ae4a5ee78d21bacda1c3873e5bc3343400027c94c3ee281134ada869cbc15533593ededf6bd85ccac70b301ce3c55ba6c315c05dd255396d7c76add7ce5fd0780c741353d02c1d444e4de84cf6931a28901c210ad7d81a63e8e9c66ab239e00a0dceb06cb2fa3012b"
      proofOfTwo = fromJust $ decodeHex "00000020890b601aa1dcb84e3647ac08bba63d1b2f4c20f493fa83c81c96e113775e525996ec6f2e21c4e47055a7977fefa3567adcf9618591645e1aa004a366a7bd60d5ace5ec6affff7f2000000000070000000631094d2f5d072ffc7cee499023fb27b7910b7c0579f43d6ef46ae4a5ee78d21bacda1c3873e5bc3343400027c94c3ee281134ada869cbc15533593ededf6bd85ccac70b301ce3c55ba6c315c05dd255396d7c76add7ce5fd0780c741353d02c1406b3b9a3292f7e0efcd4d4a63197c97d4ab4a7109e8e8ece3dfbd25db25fcece9cc6977b0609eb4c3a5bb98dc6e113a87136a2c2d75320d367ddaa32a20a0d680edfad428b72d1713a241614633c4f0ec6109b7c57cd8a42e6b4c6bd0d736cc02eb02"
      tx3 = displayTxHash "c1023d3541c78007fde57cdd6ac7d7965325dd055c316cba553cce01b370accc"
      tx5 = displayTxHash "d6a0202aa3da7d360d32752d2c6a13873a116edc98bba5c3b49e60b07769cce9"
      parseMerkle bytes = runGetS deserialize bytes :: Either String MerkleBlock
  it "reads the proof of the transaction at position 3" $ do
    fmap (\m -> (headerHash m.header, m.txn)) (parseMerkle proofOfOne)
      `shouldBe` Right ("307105bce8534c8829f50dbee4a0f5d5f702327443d7078853d0003b19099718", 7)
    fmap (merkleBlockIndexedTxs btcRegTest) (parseMerkle proofOfOne) `shouldBe` Right (Right [(3, tx3)])
  it "reads the proof of the transactions at positions 3 and 5" $
    fmap (merkleBlockIndexedTxs btcRegTest) (parseMerkle proofOfTwo) `shouldBe` Right (Right [(3, tx3), (5, tx5)])
  it "writes both proofs back to the same bytes" $ do
    fmap (runPutS . serialize) (parseMerkle proofOfOne) `shouldBe` Right proofOfOne
    fmap (runPutS . serialize) (parseMerkle proofOfTwo) `shouldBe` Right proofOfTwo
