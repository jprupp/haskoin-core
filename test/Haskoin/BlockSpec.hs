{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}

module Haskoin.BlockSpec
  ( spec,
  )
where

import Control.Monad
import Control.Monad.State.Strict
import Data.Default (def)
import Data.Either (fromRight)
import Data.Maybe (fromJust)
import Data.String (fromString)
import Data.String.Conversions (cs)
import Data.Text (Text)
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

-- | Regtest with the BIP94 rules and a retarget every ten blocks.
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

-- | Mine a header on top of the parent with the given timestamp and bits.
mineOn :: Network -> BlockHeader -> Timestamp -> Word32 -> BlockHeader
mineOn net parent time bits =
  mineBlock net 0 (parent :: BlockHeader) {prev = headerHash parent, timestamp = time, bits = bits}

-- | Mine a chain of headers with the given timestamps and bits.
mineChain :: Network -> BlockHeader -> [(Timestamp, Word32)] -> [BlockHeader]
mineChain net parent = drop 1 . scanl (\p (time, bits) -> mineOn net p time bits) parent

spec :: Spec
spec = prepareContext $ \ctx -> do
  testIdentity $ identityTests ctx
  describe "blockchain headers" $ do
    it "gets best block on bchRegTest" $
      let net = bchRegTest
          bb =
            withChain net $ do
              chain net net.genesisHeader 100
              getBestBlockHeader
       in bb.height `shouldBe` 100
    it "builds a block locator on bchRegTest" $
      let net = bchRegTest
          loc =
            withChain net $ do
              chain net net.genesisHeader 100
              bb <- getBestBlockHeader
              blockLocatorNodes bb
          heights = map (.height) loc
       in heights `shouldBe` [100, 99 .. 90] <> [88, 84, 76, 60, 28, 0]
    it "follows split chains on bchRegTest" $
      let net = bchRegTest
          bb = withChain net $ splitChain net >> getBestBlockHeader
       in bb.height `shouldBe` 4035
  describe "testnet4" $ do
    it "has the BIP94 genesis block" $
      headerHash btcTest4.genesisHeader
        `shouldBe` "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043"
    it "rejects the first block of a retarget period when it is too early" $ do
      -- Blocks 1 to 8 are ten minutes apart; block 9 jumps two hours ahead.
      let t = bip94Net.genesisHeader.timestamp
          hs =
            mineChain bip94Net bip94Net.genesisHeader $
              [(t + 600 * i, 0x207fffff) | i <- [1 .. 8]] ++ [(t + 12000, 0x207fffff)]
          par = last hs
          b10 = mineOn bip94Net par (t + 11400) 0x207fffff
          connect net chain' h = withChain net $ do
            connectBlocks net myTime chain' >>= either error (const (return ()))
            fmap (.height) <$> connectBlock net myTime h
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
    it "bases the retarget on the first block of the period" $ do
      -- Blocks 10 to 19 form a retarget period that takes four times the
      -- target timespan. Its last block uses the min-difficulty exception.
      let t = bip94Net.genesisHeader.timestamp
          hs =
            mineChain bip94Net bip94Net.genesisHeader $
              [(t + 600 * i, 0x207fffff) | i <- [1 .. 9]]
                ++ [(t + 6000 + 600 * i, 0x1f7fffff) | i <- [0 .. 8]]
                ++ [(t + 30000, 0x207fffff)]
          next net = withChain net $ do
            connectBlocks net myTime hs >>= either error (const (return ()))
            par <- getBestBlockHeader
            let bh = (par.header :: BlockHeader) {prev = headerHash par.header, timestamp = t + 30600}
            nextWorkRequired net par bh
      -- Four times the difficulty of block 10.
      next bip94Net `shouldBe` 0x2001ffff
      -- Without BIP94, block 19 drags the next period down to min difficulty.
      next noBip94Net `shouldBe` 0x207fffff
  describe "emergency difficulty adjustment" $
    it "retargets at the end of a period" $ do
      -- Blocks 10 to 19 form a retarget period that takes four times the
      -- target timespan.
      let net = (noBip94Net :: Network) {edaHeight = Just 1}
          t = net.genesisHeader.timestamp
          hs =
            mineChain net net.genesisHeader $
              [(t + 600 * i, 0x207fffff) | i <- [1 .. 9]]
                ++ [(t + 6000 + 600 * i, 0x1f7fffff) | i <- [0 .. 8]]
                ++ [(t + 30000, 0x1f7fffff)]
          next = withChain net $ do
            connectBlocks net myTime hs >>= either error (const (return ()))
            par <- getBestBlockHeader
            let bh = (par.header :: BlockHeader) {prev = headerHash par.header, timestamp = t + 30600}
            nextWorkRequired net par bh
      next `shouldBe` 0x2001ffff
  describe "block hash" $ do
    prop "encodes and decodes block hash" $
      forAll arbitraryBlockHash $ \h ->
        hexToBlockHash (blockHashToHex h) == Just h
    prop "from string block hash" $
      forAll arbitraryBlockHash $ \h ->
        fromString (cs $ blockHashToHex h) == h
  describe "merkle trees" $ do
    prop "builds tree of right width at height 1" testTreeWidth
    prop "builds tree of right width at height 0" testBaseWidth
    prop "builds and extracts partial merkle tree" $
      forAll arbitraryNetwork $ \net ->
        forAll
          (listOf1 ((,) <$> arbitraryTxHash <*> arbitrary))
          (buildExtractTree net)
    it "merkle root test vectors" $ mapM_ runMerkleVector merkleVectors
  describe "compact number" $ do
    it "compact number local vectors" testCompact
    it "compact number imported vectors" testCompactBitcoinCore
  describe "asert" $
    mapM_
      ( \x ->
          asertTests $
            "test_vectors_aserti3-2d_run" ++ printf "%02d" x ++ ".txt"
      )
      [(1 :: Int) .. 12]
  describe "helper functions" $ do
    it "computes bitcoin block subsidy correctly" (testSubsidy btc)
    it "computes regtest block subsidy correctly" (testSubsidy btcRegTest)

-- 0 → → 2015 → → → → → → → 4031
--       ↓
--       → → 2035 → → → → → → 4035*
--           ↓
--           → → 2185
splitChain :: Network -> State HeaderMemory ()
splitChain net = do
  start <- go 1 net.genesisHeader 2015
  e 2015 (head start)
  tail1 <- go 2 (head start).header 2016
  e 4031 (head tail1)
  tail2 <- go 3 (head start).header 20
  e 2035 (head tail2)
  tail3 <- go 4 (head tail2).header 2000
  e 4035 (head tail3)
  tail4 <- go 5 (head tail2).header 150
  e 2185 (head tail4)
  sp1 <- splitPoint (head tail1) (head tail3)
  unless (sp1 == head start) $
    error $
      "Split point wrong between blocks 4031 and 4035: "
        ++ show sp1.height
  sp2 <- splitPoint (head tail4) (head tail3)
  unless (sp2 == head tail2) $
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
    go seed start n = do
      let bhs = appendBlocks net seed start n
      bnE <- connectBlocks net myTime bhs
      case bnE of
        Right bn -> return bn
        Left ex -> error ex

{- Merkle Trees -}

testTreeWidth :: Int -> Property
testTreeWidth i = i /= 0 ==> calcTreeWidth (abs i) (calcTreeHeight $ abs i) == 1

testBaseWidth :: Int -> Property
testBaseWidth i = i /= 0 ==> calcTreeWidth (abs i) 0 == abs i

buildExtractTree :: Network -> [(TxHash, Bool)] -> Bool
buildExtractTree net txs =
  r == buildMerkleRoot (map fst txs) && m == map fst (filter snd txs)
  where
    (f, h) = buildPartialMerkle txs
    (r, m) =
      fromRight (error "Could not extract matches from Merkle tree") $
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
  assertBool "merkle vector" $
    buildMerkleRoot (map f hs) == (f r).get
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

testAsertBits :: AsertVector -> Assertion
testAsertBits (AsertVector _ anchor_height anchor_parent_time anchor_bits blocks) =
  forM_ blocks $ \(AsertBlock _ h t g) ->
    computeAsertBits
      (2 * 24 * 60 * 60)
      anchor_bits
      (t - anchor_parent_time)
      (h - anchor_height)
      `shouldBe` g
