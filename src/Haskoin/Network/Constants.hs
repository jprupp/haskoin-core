{-# LANGUAGE CPP #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NoFieldSelectors #-}

-- |
-- Module      : Haskoin.Constants
-- Copyright   : No rights reserved
-- License     : MIT
-- Maintainer  : jprupp@protonmail.ch
-- Stability   : experimental
-- Portability : POSIX
--
-- Network constants for various networks, including Bitcoin SegWit (BTC), Bitcoin
-- Cash (BCH), and corresponding public test and private regression test networks.
module Haskoin.Network.Constants
  ( -- * Constants
    btc,
    btcTest,
    btcTest4,
    btcRegTest,
    bch,
    bchTest3,
    bchTest4,
    bchRegTest,
    allNets,
    netByName,
  )
where

import Control.DeepSeq
import Data.Binary (Binary (..))
import Data.ByteString (ByteString)
import Data.Bytes.Get
import Data.Bytes.Put
import Data.Bytes.Serial
import Data.List
import Data.Maybe
import Data.Serialize (Serialize (..))
import Data.String
import Data.Text (Text)
import Data.Word (Word32, Word64, Word8)
import GHC.Generics (Generic)
import Haskoin.Block
import Haskoin.Network.Common
import Haskoin.Network.Data
import Haskoin.Transaction
import Text.Read

-- | Version of Haskoin Core package.
versionString :: (IsString a) => a

#ifdef CURRENT_PACKAGE_VERSION
versionString = CURRENT_PACKAGE_VERSION
#else
versionString = "Unavailable"
#endif

-- | Query known networks by name.
netByName :: String -> Maybe Network
netByName str = find ((== str) . (.name)) allNets

-- | Bitcoin SegWit network. Symbol: BTC.
btc :: Network
btc =
  Network
    { name = "btc",
      addrPrefix = 0,
      scriptPrefix = 5,
      secretPrefix = 128,
      xPubPrefix = 0x0488b21e,
      xPrvPrefix = 0x0488ade4,
      magic = 0xf9beb4d9,
      genesisHeader =
        BlockHeader
          0x01
          "0000000000000000000000000000000000000000000000000000000000000000"
          "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"
          1231006505
          0x1d00ffff
          2083236893,
      -- Hash 000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
      genesisTx = mainnetGenesisTx,
      maxBlockSize = 1000000,
      maxMessageSize = 4000000,
      maxProtocolMessageSize = 4000000,
      maxCompactBlockIndex = 0xffff,
      maxSatoshi = 2100000000000000,
      userAgent =
        "/haskoin-btc:" <> versionString <> "/",
      defaultPort = 8333,
      minDiffBlocks = False,
      powNoRetarget = False,
      bip94 = False,
      powLimit =
        0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff,
      bip34Height = 227931,
      bip34Hash = Just "000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8",
      bip65Height = 388381,
      bip66Height = 363725,
      targetTimespan = 14 * 24 * 60 * 60,
      minimumChainWork = 0x0145ec036acc5ba740052af1a0,
      targetSpacing = 10 * 60,
      -- Bitcoin Core 32.1 has no checkpoints: its minimum chain work and the
      -- low-work headers sync protect the sync instead.
      checkpoints = [],
      seeds =
        [ "dnsseed.bluematt.me", -- Matt Corallo
          "seed.bitcoin.jonasschnelli.ch", -- Jonas Schnelli
          "seed.btc.petertodd.net", -- Peter Todd
          "seed.bitcoin.sprovoost.nl", -- Sjors Provoost
          "dnsseed.emzy.de", -- Stephan Oeste
          "seed.bitcoin.wiz.biz", -- Jason Maurice
          "seed.mainnet.achownodes.xyz" -- Ava Chow
        ],
      bip44Coin = 0,
      sigHashForkId = Nothing,
      edaHeight = Nothing,
      daaHeight = Nothing,
      asertActivationTime = Nothing,
      asertHalfLife = 0,
      asertAnchorBlock = Nothing,
      segWit = True,
      cashAddrPrefix = Nothing,
      bech32Prefix = Just "bc",
      replaceByFee = True,
      halvingInterval = 210000
    }

-- | Testnet3 for Bitcoin SegWit network. Deprecated: use 'btcTest4'.
--
-- Bitcoin Core has deprecated testnet3 in favour of testnet4, whose BIP94
-- rules stop the storms of minimum-difficulty blocks that made testnet3 hard
-- to use. This value stays, still in 'allNets' and found by 'netByName', so
-- that code reading old testnet3 data keeps working, and will be removed in a
-- later major version.
btcTest :: Network
btcTest =
  Network
    { name = "btctest",
      addrPrefix = 111,
      scriptPrefix = 196,
      secretPrefix = 239,
      xPubPrefix = 0x043587cf,
      xPrvPrefix = 0x04358394,
      magic = 0x0b110907,
      genesisHeader =
        BlockHeader
          0x01
          "0000000000000000000000000000000000000000000000000000000000000000"
          "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"
          1296688602
          486604799
          414098458,
      -- Hash 000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943
      genesisTx = mainnetGenesisTx,
      maxBlockSize = 1000000,
      maxMessageSize = 4000000,
      maxProtocolMessageSize = 4000000,
      maxCompactBlockIndex = 0xffff,
      maxSatoshi = 2100000000000000,
      userAgent = "/haskoin-btc-test:" <> versionString <> "/",
      defaultPort = 18333,
      minDiffBlocks = True,
      powNoRetarget = False,
      bip94 = False,
      powLimit =
        0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff,
      bip34Height = 21111,
      bip34Hash = Just "0000000023b3a96d3484e5abb3755c413e7d41500f8e2a5c3f0dd01299cd8ef8",
      bip65Height = 581885,
      bip66Height = 330776,
      targetTimespan = 14 * 24 * 60 * 60,
      minimumChainWork = 0x17f49f702147f10c0eb6,
      targetSpacing = 10 * 60,
      -- Bitcoin Core 32.1 has no checkpoints: its minimum chain work and the
      -- low-work headers sync protect the sync instead.
      checkpoints = [],
      seeds =
        [ "testnet-seed.bitcoin.jonasschnelli.ch", -- Jonas Schnelli
          "seed.tbtc.petertodd.net", -- Peter Todd
          "testnet-seed.bluematt.me", -- Matt Corallo
          "seed.testnet.achownodes.xyz" -- Ava Chow
        ],
      bip44Coin = 1,
      sigHashForkId = Nothing,
      edaHeight = Nothing,
      daaHeight = Nothing,
      asertActivationTime = Nothing,
      asertHalfLife = 0,
      asertAnchorBlock = Nothing,
      segWit = True,
      cashAddrPrefix = Nothing,
      bech32Prefix = Just "tb",
      replaceByFee = True,
      halvingInterval = 210000
    }

-- | Testnet4 for Bitcoin SegWit network (BIP94).
btcTest4 :: Network
btcTest4 =
  Network
    { name = "btctest4",
      addrPrefix = 111,
      scriptPrefix = 196,
      secretPrefix = 239,
      xPubPrefix = 0x043587cf,
      xPrvPrefix = 0x04358394,
      magic = 0x1c163f28,
      genesisHeader =
        BlockHeader
          0x01
          "0000000000000000000000000000000000000000000000000000000000000000"
          "4e7b2b9128fe0291db0693af2ae418b767e657cd407e80cb1434221eaea7a07a"
          1714777860
          0x1d00ffff
          393743547,
      -- Hash 00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043
      genesisTx = testnet4GenesisTx,
      maxBlockSize = 1000000,
      maxMessageSize = 4000000,
      maxProtocolMessageSize = 4000000,
      maxCompactBlockIndex = 0xffff,
      maxSatoshi = 2100000000000000,
      userAgent = "/haskoin-btc-test4:" <> versionString <> "/",
      defaultPort = 48333,
      minDiffBlocks = True,
      powNoRetarget = False,
      bip94 = True,
      powLimit =
        0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff,
      bip34Height = 1,
      -- Bitcoin Core pins no block here: BIP34Hash is uint256{} on testnet4
      bip34Hash = Nothing,
      bip65Height = 1,
      bip66Height = 1,
      targetTimespan = 14 * 24 * 60 * 60,
      minimumChainWork = 0x0e346a558455ade8eca9,
      targetSpacing = 10 * 60,
      checkpoints = [],
      seeds =
        [ "seed.testnet4.bitcoin.sprovoost.nl", -- Sjors Provoost
          "seed.testnet4.wiz.biz" -- Jason Maurice
        ],
      bip44Coin = 1,
      sigHashForkId = Nothing,
      edaHeight = Nothing,
      daaHeight = Nothing,
      asertActivationTime = Nothing,
      asertHalfLife = 0,
      asertAnchorBlock = Nothing,
      segWit = True,
      cashAddrPrefix = Nothing,
      bech32Prefix = Just "tb",
      replaceByFee = True,
      halvingInterval = 210000
    }

-- | RegTest for Bitcoin SegWit network.
btcRegTest :: Network
btcRegTest =
  Network
    { name = "btcreg",
      addrPrefix = 111,
      scriptPrefix = 196,
      secretPrefix = 239,
      xPubPrefix = 0x043587cf,
      xPrvPrefix = 0x04358394,
      magic = 0xfabfb5da,
      genesisHeader =
        BlockHeader
          -- 0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206
          0x01
          "0000000000000000000000000000000000000000000000000000000000000000"
          "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"
          1296688602
          0x207fffff
          2,
      genesisTx = mainnetGenesisTx,
      maxBlockSize = 1000000,
      maxMessageSize = 4000000,
      maxProtocolMessageSize = 4000000,
      maxCompactBlockIndex = 0xffff,
      maxSatoshi = 2100000000000000,
      userAgent = "/haskoin-btc-regtest:" <> versionString <> "/",
      defaultPort = 18444,
      minDiffBlocks = True,
      powNoRetarget = True,
      bip94 = False,
      powLimit =
        0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,
      bip34Height = 1,
      bip34Hash = Nothing,
      bip65Height = 1,
      bip66Height = 1,
      -- one day, as in Bitcoin Core (kernel/chainparams.cpp, CRegTestParams)
      targetTimespan = 24 * 60 * 60,
      minimumChainWork = 0,
      targetSpacing = 10 * 60,
      checkpoints = [],
      -- the placeholder of Bitcoin Core, which never resolves
      seeds = ["dummySeed.invalid"],
      bip44Coin = 1,
      sigHashForkId = Nothing,
      edaHeight = Nothing,
      daaHeight = Nothing,
      asertActivationTime = Nothing,
      asertHalfLife = 0,
      asertAnchorBlock = Nothing,
      segWit = True,
      cashAddrPrefix = Nothing,
      bech32Prefix = Just "bcrt",
      replaceByFee = True,
      halvingInterval = 150
    }

-- | Bitcoin Cash network. Symbol: BCH.
bch :: Network
bch =
  Network
    { name = "bch",
      addrPrefix = 0,
      scriptPrefix = 5,
      secretPrefix = 128,
      xPubPrefix = 0x0488b21e,
      xPrvPrefix = 0x0488ade4,
      magic = 0xe3e1f3e8,
      genesisHeader =
        BlockHeader
          0x01
          "0000000000000000000000000000000000000000000000000000000000000000"
          "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"
          1231006505
          0x1d00ffff
          2083236893,
      -- Hash 000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
      genesisTx = mainnetGenesisTx,
      maxBlockSize = 32000000,
      maxMessageSize = 64000000,
      maxProtocolMessageSize = 2097152,
      maxCompactBlockIndex = 0xffffffff,
      maxSatoshi = 2100000000000000,
      userAgent = "/haskoin-bch:" <> versionString <> "/",
      defaultPort = 8333,
      minDiffBlocks = False,
      powNoRetarget = False,
      bip94 = False,
      powLimit =
        0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff,
      bip34Height = 227931,
      bip34Hash = Just "000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8",
      bip65Height = 388381,
      bip66Height = 363725,
      targetTimespan = 14 * 24 * 60 * 60,
      minimumChainWork = 0x030fd678912166474fe93f14,
      targetSpacing = 10 * 60,
      -- mapCheckpoints of Bitcoin Cash Node 29.2.0, src/chainparams.cpp
      checkpoints =
        [ ( 11111,
            "0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d"
          ),
          ( 33333,
            "000000002dd5588a74784eaa7ab0507a18ad16a236e7b1ce69f00d7ddfb5d0a6"
          ),
          ( 74000,
            "0000000000573993a3c9e41ce34471c079dcf5f52a0e824a81e7f953b8661a20"
          ),
          ( 105000,
            "00000000000291ce28027faea320c8d2b054b2e0fe44a773f3eefb151d6bdc97"
          ),
          ( 134444,
            "00000000000005b12ffd4cd315cd34ffd4a594f430ac814c91184a0d42d2b0fe"
          ),
          ( 168000,
            "000000000000099e61ea72015e79632f216fe6cb33d7899acb35b75c8303b763"
          ),
          ( 193000,
            "000000000000059f452a5f7340de6682a977387c17010ff6e6c3bd83ca8b1317"
          ),
          ( 210000,
            "000000000000048b95347e83192f69cf0366076336c639f9b7228e9ba171342e"
          ),
          ( 216116,
            "00000000000001b4f4b433e81ee46494af945cf96014816a4e2370f11b23df4e"
          ),
          ( 225430,
            "00000000000001c108384350f74090433e7fcf79a606b8e797f065b130575932"
          ),
          ( 250000,
            "000000000000003887df1f29024b06fc2200b55f8af8f35453d7be294df2d214"
          ),
          ( 279000,
            "0000000000000001ae8c72a0b0c301f67e3afca10e819efa9041e458e9bd7e40"
          ),
          ( 295000,
            "00000000000000004d9b4ef50f0f9d686fd69db2e03af35a100370c64632a983"
          ),
          ( 478559,
            "000000000000000000651ef99cb9fcbe0dadde1d424bd9f15ff20136191a5eec"
          ),
          ( 504032,
            "00000000000000000343e9875012f2062554c8752929892c82a0c0743ac7dcfd"
          ),
          ( 530359,
            "0000000000000000011ada8bd08f46074f44a8f155396f43e38acf9501c49103"
          ),
          ( 556767,
            "0000000000000000004626ff6e3b936941d341c5932ece4357eeccac44e6d56c"
          ),
          ( 582680,
            "000000000000000001b4b8e36aec7d4f9671a47872cb9a74dc16ca398c7dcc18"
          ),
          ( 609136,
            "000000000000000000b48bb207faac5ac655c313e41ac909322eaa694f5bc5b1"
          ),
          ( 635259,
            "00000000000000000033dfef1fc2d6a5d5520b078c55193a9bf498c5b27530f7"
          ),
          ( 661648,
            "0000000000000000029e471c41818d24b8b74c911071c4ef0b4a0509f9b5a8ce"
          ),
          ( 682900,
            "0000000000000000018b0a60a00ca53b69b213a8515e5eedbf8a207f0355fe42"
          ),
          ( 699484,
            "0000000000000000030192242425926218184a609a63efee615b7586d7f3972b"
          ),
          ( 714881,
            "000000000000000004cd628ee64c058183e780bc31143ff00680ea8af51fa0ff"
          ),
          ( 740238,
            "000000000000000002afc6fbd302f01f8cf4533f4b45207abc61d9f4297bf969"
          ),
          ( 741245,
            "000000000000000001c46d1d0f35df726bfb3e84cdc396d9edd9e2f8414191cd"
          ),
          ( 768220,
            "0000000000000000012f9d67fc9304253bdf204b65782816cbbc64913398e25b"
          ),
          ( 773784,
            "0000000000000000045cc0dbdd5cbbb86f7f63596e699ac5a11b2d41c65c6993"
          ),
          ( 792773,
            "000000000000000002fc0cdadaef1857bbd2936d37ea94f80ba3db4a5e8353e8"
          ),
          ( 845891,
            "0000000000000000017012058e7b67032926f1f20f96d1a2cd66abff9aaf8244"
          ),
          ( 853417,
            "000000000000000001c97a4c91c7a85d5f56a7ecd119f21abffdc6987a1be792"
          ),
          ( 873239,
            "000000000000000000e28c75f4b398b3ac410755d18ef9314b770c3d08cb130e"
          ),
          ( 878660,
            "000000000000000000c166d5661c13195722ae6fbee90f0ab2407ae60b71c2e6"
          ),
          ( 898374,
            "00000000000000000157a0a3dcdc80f1acd809648d238c1e893b26247091b3b4"
          ),
          ( 901000,
            "000000000000000001eda4b93cfe9bc790906f2358fc5643ff335da5e7bbae5d"
          ),
          ( 932228,
            "0000000000000000005a48a20e13f038be389952014373478b6a6a90d40e4680"
          ),
          ( 951145,
            "000000000000000000f64dbed68370486f945097ba90b17e30d7bf5c43df7a60"
          ),
          ( 960710,
            "00000000000000000275ee55c04aa109347c9ee0b5bb4617837df3044f7e1be5"
          ),
          ( 970892,
            "000000000000000000e76270e57f4ebbd2b282db46a1695984935126c0a68cd8"
          )
        ],
      seeds =
        [ "seed.flowee.cash", -- Flowee
          "seed-bch.bitcoinforks.org", -- Bitcoin Forks
          "btccash-seeder.bitcoinunlimited.info", -- Bitcoin Unlimited
          "seed.bchd.cash", -- BCHD
          "seed.bch.loping.net", -- Loping.net
          "bchseed.c3-soft.com", -- C3 Soft
          "bch.bitjson.com" -- Jason Dreyzehner
        ],
      bip44Coin = 145,
      sigHashForkId = Just 0,
      edaHeight = Just 478559,
      daaHeight = Just 504032,
      asertActivationTime = Just 1605441600,
      asertHalfLife = 2 * 24 * 60 * 60,
      -- Block 661647, as asertAnchorParams of Bitcoin Cash Node.
      asertAnchorBlock =
        Just (661647, "00000000000000000083ed4b7a780d59e3983513215518ad75654bb02deee62f"),
      segWit = False,
      cashAddrPrefix = Just "bitcoincash",
      bech32Prefix = Nothing,
      replaceByFee = False,
      halvingInterval = 210000
    }

-- | Testnet4 for Bitcoin Cash network.
bchTest4 :: Network
bchTest4 =
  Network
    { name = "bchtest4",
      addrPrefix = 111,
      scriptPrefix = 196,
      secretPrefix = 239,
      xPubPrefix = 0x043587cf,
      xPrvPrefix = 0x04358394,
      magic = 0xe2b7daaf,
      genesisHeader =
        BlockHeader
          0x01
          "0000000000000000000000000000000000000000000000000000000000000000"
          "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"
          1597811185
          0x1d00ffff
          114152193,
      -- Hash 000000001dd410c49a788668ce26751718cc797474d3152a5fc073dd44fd9f7b
      genesisTx = mainnetGenesisTx,
      maxBlockSize = 2000000,
      maxMessageSize = 4000000,
      maxProtocolMessageSize = 2097152,
      maxCompactBlockIndex = 0xffffffff,
      maxSatoshi = 2100000000000000,
      userAgent = "/haskoin-bch-test4:" <> versionString <> "/",
      defaultPort = 28333,
      minDiffBlocks = True,
      powNoRetarget = False,
      bip94 = False,
      powLimit =
        0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff,
      bip34Height = 2,
      bip34Hash = Just "00000000b0c65b1e03baace7d5c093db0d6aac224df01484985ffd5e86a1a20c",
      bip65Height = 3,
      bip66Height = 4,
      targetTimespan = 14 * 24 * 60 * 60,
      minimumChainWork = 0xbd5a1b5bda45b5da,
      targetSpacing = 10 * 60,
      -- mapCheckpoints of Bitcoin Cash Node 29.2.0, src/chainparams.cpp
      checkpoints =
        [ ( 5000,
            "000000009f092d074574a216faec682040a853c4f079c33dfd2c3ef1fd8108c4"
          ),
          ( 16845,
            "00000000fb325b8f34fe80c96a5f708a08699a68bbab82dba4474d86bd743077"
          ),
          ( 38000,
            "000000000015197537e59f339e3b1bbf81a66f691bd3d7aa08560fc7bf5113fb"
          ),
          ( 54700,
            "00000000009af4379d87f17d0f172ee4769b48839a5a3a3e81d69da4322518b8"
          ),
          ( 68117,
            "0000000000a2c2fc11a3b72adbd10a3f02a1f8745da55a85321523043639829a"
          ),
          ( 95465,
            "00000000a77206a2265cabc47cc2c34706ba1c5e5a5743ac6681b83d43c91a01"
          ),
          ( 115252,
            "00000000ae25e85d9e22cd6c8d72c2f5d4b0222289d801b7f633aeae3f8c6367"
          ),
          ( 121428,
            "00000000002cf277337c504f7ce708cce851d5d20cad2936fedf3be95a9ca5eb"
          ),
          ( 128070,
            "00000000044f34642fa3d91e34678737cc10a821a4696f50c187091c3df480c2"
          ),
          ( 148044,
            "0000000008d96c4423ac92aa200af82819339435251736b08babde1ecaf8a5b6"
          ),
          ( 200741,
            "0000000007d8ccbb767c269551dd81c520463066bec8654a18f4106aa53dc816"
          ),
          ( 206379,
            "000000001d44ca6c351af579f81703c0a175d1d4554db70ae7b7f7df2919eaf9"
          ),
          ( 226116,
            "000000008416a726dd957835add86d7166ef331b74f2f2ca38928dcd56484f8e"
          ),
          ( 232000,
            "0000000018ef632fc8a77dd4ff6a6e29ad2c7af405af63247c6f28a051b1b817"
          ),
          ( 253319,
            "00000000004605937a919cf6f636b68e8137b5cb0226ddbc9e00f386ef02999b"
          ),
          ( 277407,
            "00000000fd6af07e5c4618de0cc36796f9470620eb4610584d9011b9f41d3400"
          ),
          ( 305848,
            "00000000601bf68f9927154cf55557b1c08245b4d415658d1cbcd1eb4502dabc"
          ),
          ( 313651,
            "000000005c58d20403191a778c51206eca7552629c1e390313e786d2c388d0fb"
          ),
          ( 325709,
            "00000000000097a6ca206aa88b45a2158eea1a9ab8a49aed8f4b193d558e74b4"
          )
        ],
      seeds =
        [ "testnet4-seed-bch.toom.im", -- Jonathan Toomim
          "seed.tbch4.loping.net", -- Loping.net
          "testnet4-seed.flowee.cash", -- Flowee
          "testnet4.bitjson.com" -- Jason Dreyzehner
        ],
      bip44Coin = 1,
      sigHashForkId = Just 0,
      edaHeight = Just 7,
      daaHeight = Just 3001,
      asertActivationTime = Just 1605441600,
      asertHalfLife = 60 * 60,
      -- Block 16844, as asertAnchorParams of Bitcoin Cash Node.
      asertAnchorBlock =
        Just (16844, "00000000602570ee2b66c1d3f75d404c234f8aacdcc784da97e65838a2daf0fc"),
      segWit = False,
      cashAddrPrefix = Just "bchtest",
      bech32Prefix = Nothing,
      replaceByFee = False,
      halvingInterval = 210000
    }

-- | Testnet3 for Bitcoin Cash network.
--
-- Bitcoin Cash Node 29.2.0 supports testnet3 without a deprecation notice,
-- unlike Bitcoin Core, so this network is not deprecated. 'bchTest4' is the
-- smaller test network, with blocks of 2 MB.
--
-- The value and its 'name', @bchtest3@, carry the number of the testnet, as
-- those of 'bchTest4' do, so that neither looks like the default test network
-- of Bitcoin Cash. They were @bchTest@ and @bchtest@ before 3.0.0. The
-- CashAddr prefix stays @bchtest@: Bitcoin Cash Node gives it to every test
-- network.
bchTest3 :: Network
bchTest3 =
  Network
    { name = "bchtest3",
      addrPrefix = 111,
      scriptPrefix = 196,
      secretPrefix = 239,
      xPubPrefix = 0x043587cf,
      xPrvPrefix = 0x04358394,
      magic = 0xf4e5f3f4,
      genesisHeader =
        BlockHeader
          0x01
          "0000000000000000000000000000000000000000000000000000000000000000"
          "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"
          1296688602
          486604799
          414098458,
      -- Hash 000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943
      genesisTx = mainnetGenesisTx,
      maxBlockSize = 32000000,
      maxMessageSize = 64000000,
      maxProtocolMessageSize = 2097152,
      maxCompactBlockIndex = 0xffffffff,
      maxSatoshi = 2100000000000000,
      userAgent = "/haskoin-bch-test:" <> versionString <> "/",
      defaultPort = 18333,
      minDiffBlocks = True,
      powNoRetarget = False,
      bip94 = False,
      powLimit =
        0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff,
      bip34Height = 21111,
      bip34Hash = Just "0000000023b3a96d3484e5abb3755c413e7d41500f8e2a5c3f0dd01299cd8ef8",
      bip65Height = 581885,
      bip66Height = 330776,
      targetTimespan = 14 * 24 * 60 * 60,
      minimumChainWork = 0x011fdbbe582349040762,
      targetSpacing = 10 * 60,
      -- mapCheckpoints of Bitcoin Cash Node 29.2.0, src/chainparams.cpp
      checkpoints =
        [ ( 546,
            "000000002a936ca763904c3c35fce2f3556c559c0214345d31b1bcebf76acb70"
          ),
          ( 1155876,
            "00000000000e38fef93ed9582a7df43815d5c2ba9fd37ef70c9a0ea4a285b8f5"
          ),
          ( 1188698,
            "0000000000051b450faa75bb8e1ea30bc18c4b9736e765d2794259a53bc83f99"
          ),
          ( 1303885,
            "00000000000000479138892ef0e4fa478ccc938fb94df862ef5bde7e8dee23d3"
          ),
          ( 1341712,
            "00000000fffc44ea2e202bd905a9fbbb9491ef9e9d5a9eed4039079229afa35b"
          ),
          ( 1500206,
            "000000000000360769353e933530c40d3f00565a4e7731ff56027e23fa74a8ef"
          ),
          ( 1526155,
            "0000000057fa336560212f0ff351ca6b2008c6c48032bc305e5b4663e837953f"
          ),
          ( 1532821,
            "00000000000000e2e476a806171758c75e6fd4c28d1435a56701df87874ddd2f"
          ),
          ( 1552788,
            "000000007bc92323648b95ea8401a2247e977b653b13adb9e40748ce06b30a5e"
          ),
          ( 1582896,
            "000000000000088ef4d908ed35dc511b97fe4df78d5e37ab1e1aea4084d19506"
          ),
          ( 1605521,
            "000000000000007d4c561056e9bcb3ab7591d024b18fff4bc27cca4d51d4780e"
          ),
          ( 1610899,
            "00000000e2f5dde96179ea278285118ad69e5d94b9269fef63c604b3d551a5d0"
          ),
          ( 1630783,
            "000000002e0058b88b1857bbf2ca3edaaade318e54bbb9226ca53b3ae5528f90"
          ),
          ( 1636000,
            "0000000000001af6a0fb0ec4f079858b6add6d070381f94157be80fdb4809c65"
          ),
          ( 1658050,
            "0000000015d90bbd6deeb63cf86dc1f794d76c697d2ea86a42158c8003da8c5e"
          ),
          ( 1689348,
            "000000001935f758281aa60414a1218dcd09b4dc6b7ad0be2a3cddbcd38ff265"
          ),
          ( 1710483,
            "00000000078fe0c74ffa0c5221081c34774aa7d17a3c14c36f952f829463f120"
          ),
          ( 1718198,
            "00000000fb70d93bc600b9189f2bb13383b0e44d96a4547615b3c194680e6308"
          ),
          ( 1730264,
            "000000000001ce982fa29717a4ed233b0e5a7a8b9936a17fdeeccc5c1d0af795"
          )
        ],
      seeds =
        [ "testnet-seed.bchd.cash", -- BCHD
          "seed.tbch.loping.net", -- Loping.net
          "testnet-seed.bitcoinunlimited.info" -- Bitcoin Unlimited
        ],
      bip44Coin = 1,
      sigHashForkId = Just 0,
      edaHeight = Just 1155876,
      daaHeight = Just 1188698,
      asertActivationTime = Just 1605441600,
      asertHalfLife = 60 * 60,
      asertAnchorBlock = Nothing,
      segWit = False,
      cashAddrPrefix = Just "bchtest",
      bech32Prefix = Nothing,
      replaceByFee = False,
      halvingInterval = 210000
    }

-- | RegTest for Bitcoin Cash network.
bchRegTest :: Network
bchRegTest =
  Network
    { name = "bchreg",
      addrPrefix = 111,
      scriptPrefix = 196,
      secretPrefix = 239,
      xPubPrefix = 0x043587cf,
      xPrvPrefix = 0x04358394,
      magic = 0xdab5bffa,
      genesisHeader =
        BlockHeader
          -- 0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206
          0x01
          "0000000000000000000000000000000000000000000000000000000000000000"
          "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"
          1296688602
          0x207fffff
          2,
      genesisTx = mainnetGenesisTx,
      maxBlockSize = 32000000,
      maxMessageSize = 64000000,
      maxProtocolMessageSize = 2097152,
      maxCompactBlockIndex = 0xffffffff,
      maxSatoshi = 2100000000000000,
      userAgent = "/haskoin-bch-regtest:" <> versionString <> "/",
      defaultPort = 18444,
      minDiffBlocks = True,
      powNoRetarget = True,
      bip94 = False,
      powLimit =
        0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,
      bip34Height = 100000000,
      bip34Hash = Nothing,
      bip65Height = 1351,
      bip66Height = 1251,
      targetTimespan = 14 * 24 * 60 * 60,
      minimumChainWork = 0,
      targetSpacing = 10 * 60,
      -- mapCheckpoints of Bitcoin Cash Node 29.2.0, src/chainparams.cpp
      checkpoints =
        [ ( 0,
            "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
          )
        ],
      -- Bitcoin Cash Node has no seeds on regtest.
      seeds = [],
      bip44Coin = 1,
      sigHashForkId = Just 0,
      -- uahfHeight and daaHeight are 0 in Bitcoin Cash Node, so both rules
      -- apply from block 1. No-retargeting comes first on regtest, so they
      -- change no difficulty.
      edaHeight = Just 1,
      daaHeight = Just 1,
      asertActivationTime = Just 1605441600,
      asertHalfLife = 2 * 24 * 60 * 60,
      asertAnchorBlock = Nothing,
      segWit = False,
      cashAddrPrefix = Just "bchreg",
      bech32Prefix = Nothing,
      replaceByFee = False,
      halvingInterval = 150
    }

{-# DEPRECATED btcTest "Testnet3 is deprecated: use btcTest4" #-}

-- | List of all networks supported by this library, the deprecated 'btcTest'
-- included.
allNets :: [Network]
allNets = [btc, bch, btcTest, btcTest4, bchTest4, bchTest3, btcRegTest, bchRegTest]
