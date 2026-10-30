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
    bchTest,
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
      maxBlockSize = 1000000,
      maxSatoshi = 2100000000000000,
      userAgent =
        "/haskoin-btc:" <> versionString <> "/",
      defaultPort = 8333,
      minDiffBlocks = False,
      powNoRetarget = False,
      bip94 = False,
      powLimit =
        0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff,
      bip34Block =
        ( 227931,
          "000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8"
        ),
      bip65Height = 388381,
      bip66Height = 363725,
      targetTimespan = 14 * 24 * 60 * 60,
      targetSpacing = 10 * 60,
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
          )
        ],
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
      segWit = True,
      cashAddrPrefix = Nothing,
      bech32Prefix = Just "bc",
      replaceByFee = True,
      halvingInterval = 210000
    }

-- | Testnet for Bitcoin SegWit network.
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
      maxBlockSize = 1000000,
      maxSatoshi = 2100000000000000,
      userAgent = "/haskoin-btc-test:" <> versionString <> "/",
      defaultPort = 18333,
      minDiffBlocks = True,
      powNoRetarget = False,
      bip94 = False,
      powLimit =
        0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff,
      bip34Block =
        ( 21111,
          "0000000023b3a96d3484e5abb3755c413e7d41500f8e2a5c3f0dd01299cd8ef8"
        ),
      bip65Height = 581885,
      bip66Height = 330776,
      targetTimespan = 14 * 24 * 60 * 60,
      targetSpacing = 10 * 60,
      checkpoints =
        [ ( 546,
            "000000002a936ca763904c3c35fce2f3556c559c0214345d31b1bcebf76acb70"
          )
        ],
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
      maxBlockSize = 1000000,
      maxSatoshi = 2100000000000000,
      userAgent = "/haskoin-btc-test4:" <> versionString <> "/",
      defaultPort = 48333,
      minDiffBlocks = True,
      powNoRetarget = False,
      bip94 = True,
      powLimit =
        0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff,
      bip34Block =
        ( 1,
          "0000000012982b6d5f621229286b880e909984df669c2afabb102ce311b13f28"
        ),
      bip65Height = 1,
      bip66Height = 1,
      targetTimespan = 14 * 24 * 60 * 60,
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
      maxBlockSize = 1000000,
      maxSatoshi = 2100000000000000,
      userAgent = "/haskoin-btc-regtest:" <> versionString <> "/",
      defaultPort = 18444,
      minDiffBlocks = True,
      powNoRetarget = True,
      bip94 = False,
      powLimit =
        0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,
      bip34Block =
        ( 100000000,
          "0000000000000000000000000000000000000000000000000000000000000000"
        ),
      bip65Height = 1351,
      bip66Height = 1251,
      targetTimespan = 14 * 24 * 60 * 60,
      targetSpacing = 10 * 60,
      checkpoints = [],
      seeds = ["localhost"],
      bip44Coin = 1,
      sigHashForkId = Nothing,
      edaHeight = Nothing,
      daaHeight = Nothing,
      asertActivationTime = Nothing,
      asertHalfLife = 0,
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
      maxBlockSize = 32000000,
      maxSatoshi = 2100000000000000,
      userAgent = "/haskoin-bch:" <> versionString <> "/",
      defaultPort = 8333,
      minDiffBlocks = False,
      powNoRetarget = False,
      bip94 = False,
      powLimit =
        0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff,
      bip34Block =
        ( 227931,
          "000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8"
        ),
      bip65Height = 388381,
      bip66Height = 363725,
      targetTimespan = 14 * 24 * 60 * 60,
      targetSpacing = 10 * 60,
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
          -- UAHF fork block.

          ( 478559,
            "000000000000000000651ef99cb9fcbe0dadde1d424bd9f15ff20136191a5eec"
          ),
          -- Nov, 13 DAA activation block.

          ( 504031,
            "0000000000000000011ebf65b60d0a3de80b8175be709d653b4c1a1beeb6ab9c"
          )
        ],
      seeds =
        [ "seed.flowee.cash", -- Flowee
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
      maxBlockSize = 2000000,
      maxSatoshi = 2100000000000000,
      userAgent = "/haskoin-bch-test4:" <> versionString <> "/",
      defaultPort = 28333,
      minDiffBlocks = True,
      powNoRetarget = False,
      bip94 = False,
      powLimit =
        0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff,
      bip34Block =
        ( 2,
          "00000000b0c65b1e03baace7d5c093db0d6aac224df01484985ffd5e86a1a20c"
        ),
      bip65Height = 3,
      bip66Height = 4,
      targetTimespan = 14 * 24 * 60 * 60,
      targetSpacing = 10 * 60,
      checkpoints =
        [ ( 5000,
            "000000009f092d074574a216faec682040a853c4f079c33dfd2c3ef1fd8108c4"
          ),
          -- Axion activation

          ( 16845,
            "00000000fb325b8f34fe80c96a5f708a08699a68bbab82dba4474d86bd743077"
          ),
          ( 38000,
            "000000000015197537e59f339e3b1bbf81a66f691bd3d7aa08560fc7bf5113fb"
          ),
          ( 54700,
            "00000000009af4379d87f17d0f172ee4769b48839a5a3a3e81d69da4322518b8"
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
      segWit = False,
      cashAddrPrefix = Just "bchtest",
      bech32Prefix = Nothing,
      replaceByFee = False,
      halvingInterval = 210000
    }

-- | Testnet for Bitcoin Cash network.
bchTest :: Network
bchTest =
  Network
    { name = "bchtest",
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
      maxBlockSize = 32000000,
      maxSatoshi = 2100000000000000,
      userAgent = "/haskoin-bch-test:" <> versionString <> "/",
      defaultPort = 18333,
      minDiffBlocks = True,
      powNoRetarget = False,
      bip94 = False,
      powLimit =
        0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff,
      bip34Block =
        ( 21111,
          "0000000023b3a96d3484e5abb3755c413e7d41500f8e2a5c3f0dd01299cd8ef8"
        ),
      bip65Height = 581885,
      bip66Height = 330776,
      targetTimespan = 14 * 24 * 60 * 60,
      targetSpacing = 10 * 60,
      checkpoints =
        [ ( 546,
            "000000002a936ca763904c3c35fce2f3556c559c0214345d31b1bcebf76acb70"
          ),
          -- UAHF fork block.

          ( 1155876,
            "00000000000e38fef93ed9582a7df43815d5c2ba9fd37ef70c9a0ea4a285b8f5"
          ),
          -- Nov, 13. DAA activation block.

          ( 1188697,
            "0000000000170ed0918077bde7b4d36cc4c91be69fa09211f748240dabe047fb"
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
      maxBlockSize = 1000000,
      maxSatoshi = 2100000000000000,
      userAgent = "/haskoin-bch-regtest:" <> versionString <> "/",
      defaultPort = 18444,
      minDiffBlocks = True,
      powNoRetarget = True,
      bip94 = False,
      powLimit =
        0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,
      bip34Block =
        ( 100000000,
          "0000000000000000000000000000000000000000000000000000000000000000"
        ),
      bip65Height = 1351,
      bip66Height = 1251,
      targetTimespan = 14 * 24 * 60 * 60,
      targetSpacing = 10 * 60,
      checkpoints =
        [ ( 0,
            "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
          )
        ],
      seeds = ["localhost"],
      bip44Coin = 1,
      sigHashForkId = Just 0,
      edaHeight = Nothing,
      daaHeight = Just 0,
      asertActivationTime = Just 1605441600,
      asertHalfLife = 2 * 24 * 60 * 60,
      segWit = False,
      cashAddrPrefix = Just "bchreg",
      bech32Prefix = Nothing,
      replaceByFee = False,
      halvingInterval = 150
    }

-- | List of all networks supported by this library.
allNets :: [Network]
allNets = [btc, bch, btcTest, btcTest4, bchTest4, bchTest, btcRegTest, bchRegTest]
