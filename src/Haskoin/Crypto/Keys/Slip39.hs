{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NoFieldSelectors #-}

-- |
-- Module      : Haskoin.Crypto.Keys.Slip39
-- Copyright   : No rights reserved
-- License     : MIT
-- Maintainer  : jprupp@protonmail.ch
-- Stability   : experimental
-- Portability : POSIX
--
-- Shamir's secret-sharing for mnemonic codes, SLIP-0039. A master secret is
-- encrypted with a passphrase and split into shares, of which a chosen
-- number rebuild it. Each share is a mnemonic of the SLIP-0039 word list,
-- with a checksum that catches any three wrong words. The split has two
-- levels: the encrypted master secret is shared among groups, and each
-- group's share among its members. A plain T-of-N split is one group with
-- a member threshold of T and N members.
--
-- The specification is at
-- <https://github.com/satoshilabs/slips/blob/master/slip-0039.md>. This
-- module follows it section by section: the field GF(256), the Lagrange
-- interpolation, the splitting and recovery of a secret with its digest,
-- the format of a share mnemonic, the RS1024 checksum, the encryption of
-- the master secret with the passphrase, and the generation and combination
-- of the shares.
--
-- The master secret of a BIP-0032 wallet is its seed, the bytes fed to
-- HMAC-SHA512 to derive the master key. A SLIP-0039 share is not a BIP-0039
-- mnemonic and cannot be converted into one.
module Haskoin.Crypto.Keys.Slip39
  ( -- * Shares
    Share (..),
    encodeShare,
    decodeShare,

    -- * Generating shares
    Scheme (..),
    generateMnemonics,
    generateShares,
    generateSharesWith,
    SplitRandom (..),
    splitRandomSizes,

    -- * Combining shares
    combineMnemonics,
    combineShares,
    EncryptedMasterSecret (..),

    -- * The passphrase
    encryptMasterSecret,
    decryptMasterSecret,

    -- * Shamir's secret sharing
    splitSecret,
    recoverSecret,
    interpolate,
    secretIndex,
    digestIndex,

    -- * The field GF(256)
    gfMul,
    gfInv,
    gfDiv,

    -- * The checksum
    rs1024Polymod,
    rs1024Checksum,
    rs1024Verify,
    customizationString,

    -- * The word list
    slip39WordList,
    slip39WordListMap,
    mnemonicToIndices,
    indicesToMnemonic,
  )
where

import Control.Monad (foldM, forM, forM_, replicateM, unless, when)
import Crypto.Hash (SHA256)
import Crypto.KDF.PBKDF2 (Parameters (..), fastPBKDF2_SHA256)
import Crypto.MAC.HMAC (HMAC, hmac)
import Crypto.Random (MonadRandom, getRandomBytes)
import Data.Array.Unboxed (UArray, listArray, (!))
import Data.Bits (shiftL, shiftR, testBit, xor, (.&.), (.|.))
import Data.ByteArray qualified as BA
import Data.ByteString (ByteString)
import Data.ByteString qualified as B
import Data.Char (ord)
import Data.List (nub, transpose)
import Data.Map.Strict (Map)
import Data.Map.Strict qualified as M
import Data.Text (Text)
import Data.Text qualified as T
import Data.Text.Encoding qualified as E
import Data.Vector (Vector)
import Data.Vector qualified as V
import Data.Word (Word8)

{- Shares -}

-- | A share, as its mnemonic carries it. The identifier is a random 15-bit
-- value, the same on every share of a split. The iteration exponent sets
-- the PBKDF2 iterations of the passphrase to 10000 times 2 to its power.
-- The indices are the x values of the share at each level, 0 to 15, and the
-- thresholds and the group count are the actual numbers, 1 to 16, not the
-- values the mnemonic encodes, which are one less.
data Share = Share
  { identifier :: !Int,
    extendable :: !Bool,
    iterationExponent :: !Int,
    groupIndex :: !Int,
    groupThreshold :: !Int,
    groupCount :: !Int,
    memberIndex :: !Int,
    memberThreshold :: !Int,
    -- | The share value: f(x) of each byte of the secret shared
    value :: !ByteString
  }
  deriving (Eq, Ord)

-- | The value of a share is secret, so it is not shown.
instance Show Share where
  showsPrec d s =
    showParen (d > 10) $
      showString "Share {identifier = "
        . shows s.identifier
        . showString ", extendable = "
        . shows s.extendable
        . showString ", iterationExponent = "
        . shows s.iterationExponent
        . showString ", groupIndex = "
        . shows s.groupIndex
        . showString ", groupThreshold = "
        . shows s.groupThreshold
        . showString ", groupCount = "
        . shows s.groupCount
        . showString ", memberIndex = "
        . shows s.memberIndex
        . showString ", memberThreshold = "
        . shows s.memberThreshold
        . showString ", value = <redacted>}"

-- | The master secret encrypted with its passphrase, with what its
-- decryption needs besides the passphrase. This is what the shares share.
data EncryptedMasterSecret = EncryptedMasterSecret
  { identifier :: !Int,
    extendable :: !Bool,
    iterationExponent :: !Int,
    ciphertext :: !ByteString
  }
  deriving (Eq)

-- | The ciphertext is secret, so it is not shown.
instance Show EncryptedMasterSecret where
  showsPrec d e =
    showParen (d > 10) $
      showString "EncryptedMasterSecret {identifier = "
        . shows e.identifier
        . showString ", extendable = "
        . shows e.extendable
        . showString ", iterationExponent = "
        . shows e.iterationExponent
        . showString ", ciphertext = <redacted>}"

-- | How a master secret is split: how many groups are needed to rebuild
-- it, and, for each group, how many of its members are needed and how many
-- members it has. A plain T-of-N split is @Scheme 1 [(T, N)]@.
data Scheme = Scheme
  { groupThreshold :: !Int,
    groups :: ![(Int, Int)]
  }
  deriving (Eq, Show)

{- Constants of the format -}

-- | The index at which the shared secret is stored, f(255).
secretIndex :: Word8
secretIndex = 255

-- | The index at which the digest of the shared secret is stored, f(254).
digestIndex :: Word8
digestIndex = 254

-- | The bytes of the digest at the head of the digest share.
digestBytes :: Int
digestBytes = 4

-- | The most shares a secret can be split into, and the most groups: the
-- indices have four bits.
maxShares :: Int
maxShares = 16

-- | The fewest bytes of a master secret: 128 bits.
minSecretBytes :: Int
minSecretBytes = 16

-- | The words of a mnemonic that are not share value: four of header and
-- three of checksum.
metadataWords :: Int
metadataWords = 7

-- | The header words of a mnemonic: the identifier, the flag, the exponent,
-- the indices, the thresholds and the group count, 40 bits in all.
headerWords :: Int
headerWords = 4

-- | The fewest words of a mnemonic: the metadata and 13 words of value for
-- a secret of 128 bits.
minMnemonicWords :: Int
minMnemonicWords = 20

{- The field GF(256) -}

-- | The powers of the generator x + 1, the byte 3, in the field of the AES
-- cipher: bytes as polynomials modulo x^8 + x^4 + x^3 + x + 1. The table
-- holds 3^i for i from 0 to 254.
expTable :: UArray Int Word8
expTable = listArray (0, 254) (map fromIntegral (take 255 (iterate timesGenerator (1 :: Int))))
  where
    -- Multiply by x + 1, then reduce by the polynomial, 0x11B
    timesGenerator p =
      let q = (p `shiftL` 1) `xor` p
       in if testBit q 8 then q `xor` 0x11B else q

-- | The logarithm of each non-zero byte to the base 3: the inverse of
-- 'expTable'. The entry of zero, which has no logarithm, is unused.
logTable :: UArray Word8 Int
logTable = listArray (0, 255) [M.findWithDefault 0 b logs | b <- [0 .. 255]]
  where
    logs = M.fromList [(expTable ! i, i) | i <- [0 .. 254]]

-- | The product of two bytes in GF(256).
gfMul :: Word8 -> Word8 -> Word8
gfMul a b
  | a == 0 || b == 0 = 0
  | otherwise = expTable ! ((logTable ! a + logTable ! b) `mod` 255)

-- | The inverse of a byte in GF(256); zero has none.
gfInv :: Word8 -> Maybe Word8
gfInv 0 = Nothing
gfInv a = Just (expTable ! ((255 - logTable ! a) `mod` 255))

-- | The quotient of two bytes in GF(256); nothing when dividing by zero.
gfDiv :: Word8 -> Word8 -> Maybe Word8
gfDiv a b = gfMul a <$> gfInv b

{- Shamir's secret sharing -}

-- | The value at the index x of the polynomials through the points given,
-- one polynomial per byte of the values, by Lagrange interpolation. The
-- points must have distinct indices and values of one length.
interpolate :: Word8 -> [(Word8, ByteString)] -> Either String ByteString
interpolate x points = do
  when (null points) $ Left "There are no shares to interpolate"
  when (length (nub indices) /= length indices) $ Left "The shares do not have distinct indices"
  when (length (nub (map (B.length . snd) points)) /= 1) $ Left "The shares do not have the same length"
  weights <- mapM basis indices
  -- Each byte of the result is the sum over the points of the point's byte
  -- times its basis polynomial at x; the sum of the field is xor
  return $ B.pack [foldl' xor 0 (zipWith gfMul weights column) | column <- transpose (map (B.unpack . snd) points)]
  where
    indices = map fst points
    -- The Lagrange basis polynomial of the point at xi, evaluated at x: the
    -- product over the other points of (x - xj) / (xi - xj), where the
    -- difference of the field is xor. The indices are distinct, so no
    -- division is by zero.
    basis xi = foldM (factor xi) 1 [xj | xj <- indices, xj /= xi]
    factor xi acc xj =
      maybe (Left "The shares do not have distinct indices") (Right . gfMul acc) $
        gfDiv (x `xor` xj) (xi `xor` xj)

-- | The random values a split draws: the T - 2 random shares, each as long
-- as the secret, and the random part of the digest share, four bytes
-- shorter. A split with a threshold of 1 draws none.
data SplitRandom = SplitRandom
  { randomShares :: ![ByteString],
    digestRandom :: !ByteString
  }
  deriving (Eq, Show)

-- | The sizes of the random values a split of a secret of the given length
-- draws at the given threshold: how many random shares, their length, and
-- the length of the random part of the digest share.
splitRandomSizes :: Int -> Int -> (Int, Int, Int)
splitRandomSizes threshold secretLength
  | threshold <= 1 = (0, secretLength, 0)
  | otherwise = (threshold - 2, secretLength, secretLength - digestBytes)

-- | The first four bytes of HMAC-SHA256 keyed with the random part of the
-- digest share, of the shared secret.
digestOf :: ByteString -> ByteString -> ByteString
digestOf randomPart secret = B.take digestBytes (hmacSha256 randomPart secret)

hmacSha256 :: ByteString -> ByteString -> ByteString
hmacSha256 key msg = BA.convert (hmac key msg :: HMAC SHA256)

-- | SplitSecret of the specification: the shares of a secret at the given
-- threshold and count, with their indices from 0, computed from the random
-- values given. With a threshold of 1 every share is the secret itself.
-- Otherwise the random shares take the first indices, the digest share
-- sits at 254 and the secret at 255, and the remaining shares are the
-- polynomials through those points.
splitSecret :: Int -> Int -> ByteString -> SplitRandom -> Either String [(Word8, ByteString)]
splitSecret threshold count secret random = do
  when (threshold < 1) $ Left "The threshold must be at least 1"
  when (threshold > count) $ Left "The threshold is greater than the number of shares"
  when (count > maxShares) $ Left ("The number of shares is greater than " <> show maxShares)
  checkSecretLength "secret" secret
  let (randomCount, _, randomPartLength) = splitRandomSizes threshold (B.length secret)
  unless (length random.randomShares == randomCount) $
    Left ("A split with a threshold of " <> show threshold <> " takes " <> show randomCount <> " random shares")
  unless (all ((== B.length secret) . B.length) random.randomShares) $
    Left "A random share must be as long as the secret"
  unless (B.length random.digestRandom == randomPartLength) $
    Left ("The random part of the digest share must have " <> show randomPartLength <> " bytes")
  if threshold == 1
    then return [(i, secret) | i <- indicesUpTo count]
    else do
      let digestShare = digestOf random.digestRandom secret <> random.digestRandom
          randomPoints = zip (indicesUpTo randomCount) random.randomShares
          basePoints = randomPoints ++ [(digestIndex, digestShare), (secretIndex, secret)]
      computed <- forM (drop randomCount (indicesUpTo count)) $ \i -> (,) i <$> interpolate i basePoints
      return (randomPoints ++ computed)
  where
    indicesUpTo n = take n [0 ..]

-- | RecoverSecret of the specification: the secret the shares were split
-- from at the given threshold. With a threshold of 1 it is the first share.
-- Otherwise the secret and the digest share are interpolated at their
-- indices, and the digest must match the secret.
recoverSecret :: Int -> [(Word8, ByteString)] -> Either String ByteString
recoverSecret threshold shares =
  case shares of
    [] -> Left "There are no shares to recover the secret from"
    (_, first) : _
      | threshold == 1 -> Right first
      | otherwise -> do
          secret <- interpolate secretIndex shares
          digestShare <- interpolate digestIndex shares
          let (digest, randomPart) = B.splitAt digestBytes digestShare
          unless (digest == digestOf randomPart secret) $ Left "The digest of the secret does not match"
          return secret

{- The checksum -}

-- | The polymod of the RS1024 code over the values given, each a word of
-- the mnemonic as its 10-bit index, after the characters of the
-- customization string.
rs1024Polymod :: [Int] -> Int
rs1024Polymod = foldl' step 1
  where
    step chk v =
      let top = chk `shiftR` 20
          shifted = ((chk .&. 0xfffff) `shiftL` 10) `xor` v
       in foldl' (\c (i, g) -> if testBit top i then c `xor` g else c) shifted (zip [0 ..] generator)
    generator =
      [ 0xe0e040,
        0x1c1c080,
        0x3838100,
        0x7070200,
        0xe0e0009,
        0x1c0c2412,
        0x38086c24,
        0x3090fc48,
        0x21b1f890,
        0x3f3f120
      ]

-- | The customization string of the checksum, fed to the polymod before
-- the data: "shamir", or "shamir_extendable" when the extendable flag is
-- set.
customizationString :: Bool -> [Int]
customizationString ext = map ord (if ext then "shamir_extendable" else "shamir")

-- | The three checksum words of the data words given, under the
-- customization string.
rs1024Checksum :: [Int] -> [Int] -> [Int]
rs1024Checksum cs values = [(polymod `shiftR` (10 * (2 - i))) .&. 1023 | i <- [0 .. 2]]
  where
    polymod = rs1024Polymod (cs ++ values ++ [0, 0, 0]) `xor` 1

-- | Whether the words given, the data words and their checksum, check out
-- under the customization string.
rs1024Verify :: [Int] -> [Int] -> Bool
rs1024Verify cs values = rs1024Polymod (cs ++ values) == 1

{- Share mnemonics -}

-- | The mnemonic of a share: its header, its value padded to whole words,
-- and the checksum, as words of the list. A share whose fields are out of
-- range is refused.
encodeShare :: Share -> Either String Text
encodeShare share = do
  checkShare share
  let dataWords = headerOf share ++ valueWords share.value
      checksum = rs1024Checksum (customizationString share.extendable) dataWords
  return $ indicesToMnemonic (dataWords ++ checksum)

-- | The share a mnemonic carries. The words are looked up in lower case.
-- The mnemonic must have at least 20 words, a length that leaves at most 8
-- bits of padding, a valid checksum, zero padding bits, and a group
-- threshold no greater than its group count.
decodeShare :: Text -> Either String Share
decodeShare mnemonic = do
  indices <- mnemonicToIndices mnemonic
  let count = length indices
      valueWordCount = count - metadataWords
      -- The padded value is a whole number of 10-bit words; its length
      -- modulo 16 is the padding, since the value has a multiple of 16 bits
      padding = (10 * valueWordCount) `mod` 16
  when (count < minMnemonicWords) $
    Left ("The mnemonic has " <> show count <> " words, but a share has at least " <> show minMnemonicWords)
  when (padding > 8) $
    Left ("The mnemonic has " <> show count <> " words, which is not a valid share length")
  let (header, rest) = splitAt headerWords indices
      (valueIndices, checksum) = splitAt valueWordCount rest
      headerInt = indicesToInteger header
      ext = testBit headerInt 24
  unless (rs1024Verify (customizationString ext) (header ++ valueIndices ++ checksum)) $
    Left "The checksum of the mnemonic is invalid"
  let share =
        Share
          { identifier = field 25 32767,
            extendable = ext,
            iterationExponent = field 20 15,
            groupIndex = field 16 15,
            groupThreshold = field 12 15 + 1,
            groupCount = field 8 15 + 1,
            memberIndex = field 4 15,
            memberThreshold = field 0 15 + 1,
            value = B.empty
          }
      field offset mask = fromIntegral ((headerInt `shiftR` offset) .&. mask)
  when (share.groupThreshold > share.groupCount) $
    Left "The group threshold is greater than the group count"
  let valueBytes = (10 * valueWordCount - padding) `div` 8
      valueInt = indicesToInteger valueIndices
  when (valueInt >= 2 ^ (8 * valueBytes)) $
    Left "The padding bits of the share value are not zero"
  return share {value = integerToBytes valueBytes valueInt}

-- | The header of a share as four words: the identifier, the flag, the
-- exponent, the group index, the group threshold less one, the group count
-- less one, the member index and the member threshold less one, 40 bits.
headerOf :: Share -> [Int]
headerOf share = integerToIndices headerWords headerInt
  where
    headerInt =
      (toInteger share.identifier `shiftL` 25)
        .|. (if share.extendable then 1 `shiftL` 24 else 0)
        .|. (toInteger share.iterationExponent `shiftL` 20)
        .|. (toInteger share.groupIndex `shiftL` 16)
        .|. (toInteger (share.groupThreshold - 1) `shiftL` 12)
        .|. (toInteger (share.groupCount - 1) `shiftL` 8)
        .|. (toInteger share.memberIndex `shiftL` 4)
        .|. toInteger (share.memberThreshold - 1)

-- | A share value as words: its bits, left-padded with zeros to a multiple
-- of ten.
valueWords :: ByteString -> [Int]
valueWords bytes = integerToIndices wordCount (bytesToInteger bytes)
  where
    wordCount = (8 * B.length bytes + 9) `div` 10

-- | Every field of a share checked against its range, so that an encoded
-- share is a valid mnemonic and a combined set is one the format allows.
checkShare :: Share -> Either String ()
checkShare share = do
  checkRange "identifier" 0 32767 share.identifier
  checkRange "iteration exponent" 0 15 share.iterationExponent
  checkRange "group index" 0 (maxShares - 1) share.groupIndex
  checkRange "group threshold" 1 maxShares share.groupThreshold
  checkRange "group count" 1 maxShares share.groupCount
  when (share.groupThreshold > share.groupCount) $
    Left "The group threshold is greater than the group count"
  checkRange "member index" 0 (maxShares - 1) share.memberIndex
  checkRange "member threshold" 1 maxShares share.memberThreshold
  checkSecretLength "share value" share.value

-- | A count with its noun: "1 share", "2 shares".
counted :: Int -> String -> String
counted n noun = show n <> " " <> noun <> (if n == 1 then "" else "s")

checkRange :: String -> Int -> Int -> Int -> Either String ()
checkRange what lo hi v =
  unless (v >= lo && v <= hi) $
    Left ("The " <> what <> " must be between " <> show lo <> " and " <> show hi <> ", not " <> show v)

-- | A secret, or a share of one, has at least 128 bits and a multiple of
-- 16 bits.
checkSecretLength :: String -> ByteString -> Either String ()
checkSecretLength what bytes = do
  when (B.length bytes < minSecretBytes) $
    Left ("The " <> what <> " must have at least " <> show minSecretBytes <> " bytes, not " <> show (B.length bytes))
  when (odd (B.length bytes)) $
    Left ("The " <> what <> " must have an even number of bytes, not " <> show (B.length bytes))

{- The passphrase -}

-- | The master secret encrypted with the passphrase under the identifier,
-- the extendable flag and the iteration exponent given, by the four-round
-- Feistel network of the specification. The passphrase must be printable
-- ASCII, code points 32 to 126; use the empty passphrase for none.
encryptMasterSecret :: Int -> Bool -> Int -> Text -> ByteString -> Either String EncryptedMasterSecret
encryptMasterSecret identifier ext iterExponent passphrase secret = do
  checkRange "identifier" 0 32767 identifier
  checkRange "iteration exponent" 0 15 iterExponent
  checkSecretLength "master secret" secret
  unless (T.all printableAscii passphrase) $
    Left "The passphrase must contain only printable ASCII characters, code points 32 to 126"
  return
    EncryptedMasterSecret
      { identifier = identifier,
        extendable = ext,
        iterationExponent = iterExponent,
        ciphertext = feistel [0, 1, 2, 3] identifier ext iterExponent passphrase secret
      }
  where
    printableAscii c = ord c >= 32 && ord c <= 126

-- | The master secret of an encrypted one under a passphrase: the Feistel
-- rounds in reverse. Any passphrase gives a master secret, so a wrong one
-- is not detected, as the specification intends. The passphrase is not
-- checked for printable ASCII here, so that shares made by an
-- implementation that allowed other characters can still be recovered; it
-- is encoded as UTF-8, as the reference implementation does.
decryptMasterSecret :: Text -> EncryptedMasterSecret -> Either String ByteString
decryptMasterSecret passphrase ems = do
  checkRange "identifier" 0 32767 ems.identifier
  checkRange "iteration exponent" 0 15 ems.iterationExponent
  checkSecretLength "encrypted master secret" ems.ciphertext
  return $ feistel [3, 2, 1, 0] ems.identifier ems.extendable ems.iterationExponent passphrase ems.ciphertext

-- | The Feistel network of the specification over the rounds given, in
-- that order: the halves L and R become (R, L xor F(i, R)) each round, and
-- the result is R || L. The round function is PBKDF2-HMAC-SHA256 of the
-- round number followed by the passphrase, salted with the salt prefix
-- and R, with 2500 times 2 to the exponent iterations.
feistel :: [Word8] -> Int -> Bool -> Int -> Text -> ByteString -> ByteString
feistel rounds identifier ext iterExponent passphrase secret = right <> left
  where
    half = B.length secret `div` 2
    (left, right) = foldl' step (B.take half secret, B.drop half secret) rounds
    step (l, r) i = (r, B.pack (B.zipWith xor l (roundFunction i r)))
    roundFunction i r =
      fastPBKDF2_SHA256
        Parameters {iterCounts = 2500 `shiftL` iterExponent, outputLength = half}
        (B.cons i (E.encodeUtf8 passphrase))
        (saltPrefix <> r)
    -- Without the extendable flag the identifier salts the passphrase, so
    -- another split of the same secret gives another master secret
    saltPrefix
      | ext = B.empty
      | otherwise = "shamir" <> integerToBytes 2 (toInteger identifier)

{- Generating shares -}

-- | The shares of a master secret under a scheme, with the random values
-- given: the identifier, then one 'SplitRandom' for the split among the
-- groups and one for each group's split among its members, in that order.
-- GenerateShares of the specification, with the identifier and the
-- extendable flag as arguments. The shares come as one list per group.
generateSharesWith :: Scheme -> Int -> Bool -> Int -> Text -> ByteString -> [SplitRandom] -> Either String [[Share]]
generateSharesWith scheme identifier ext iterExponent passphrase secret randoms = do
  checkScheme scheme
  ems <- encryptMasterSecret identifier ext iterExponent passphrase secret
  (groupRandom, memberRandoms) <- case randoms of
    (g : ms) | length ms == groupCount -> Right (g, ms)
    _ ->
      Left $
        "A scheme of " <> show groupCount <> " groups takes " <> show (groupCount + 1)
          <> " sets of random values: one for the split among the groups, then one per group"
  groupShares <- splitSecret scheme.groupThreshold groupCount ems.ciphertext groupRandom
  forM (zip3 scheme.groups groupShares memberRandoms) $ \((threshold, members), (gi, groupSecret), random) -> do
    memberShares <- splitSecret threshold members groupSecret random
    return
      [ Share
          { identifier = identifier,
            extendable = ext,
            iterationExponent = iterExponent,
            groupIndex = fromIntegral gi,
            groupThreshold = scheme.groupThreshold,
            groupCount = groupCount,
            memberIndex = fromIntegral mi,
            memberThreshold = threshold,
            value = v
          }
        | (mi, v) <- memberShares
      ]
  where
    groupCount = length scheme.groups

-- | A scheme has 1 to 16 groups, a group threshold within them, and in each
-- group a member threshold within 1 to 16 members. A group whose member
-- threshold is 1 has one member: more would differ only in their index and
-- give no security, so the specification refuses them.
checkScheme :: Scheme -> Either String ()
checkScheme scheme = do
  when (null scheme.groups) $ Left "A scheme has at least one group"
  when (length scheme.groups > maxShares) $ Left ("A scheme has at most " <> show maxShares <> " groups")
  checkRange "group threshold" 1 (length scheme.groups) scheme.groupThreshold
  forM_ (zip [1 :: Int ..] scheme.groups) $ \(i, (threshold, members)) -> do
    let group = "group " <> show i
    checkRange ("member count of " <> group) 1 maxShares members
    checkRange ("member threshold of " <> group) 1 members threshold
    when (threshold == 1 && members > 1) $
      Left ("A group with a member threshold of 1 has one member, but " <> group <> " has " <> show members)

-- | The thresholds of the splits of a scheme, in the order the random
-- values are drawn: the groups first, then the members of each group.
schemeThresholds :: Scheme -> [Int]
schemeThresholds scheme = scheme.groupThreshold : map fst scheme.groups

-- | The shares of a master secret under a scheme, with a random identifier
-- and random values from the monad. The scheme and the secret are checked
-- before anything is drawn. The random source must be fit for keys.
generateShares :: (MonadRandom m) => Scheme -> Bool -> Int -> Text -> ByteString -> m (Either String [[Share]])
generateShares scheme ext iterExponent passphrase secret =
  case checkScheme scheme >> checkSecretLength "master secret" secret of
    Left err -> return (Left err)
    Right () -> do
      idBytes <- getRandomBytes 2
      let identifier = fromIntegral (bytesToInteger idBytes .&. 0x7fff)
      randoms <- mapM (drawSplitRandom (B.length secret)) (schemeThresholds scheme)
      return $ generateSharesWith scheme identifier ext iterExponent passphrase secret randoms

-- | The random values of one split: the random shares, then the random
-- part of the digest share.
drawSplitRandom :: (MonadRandom m) => Int -> Int -> m SplitRandom
drawSplitRandom secretLength threshold = do
  let (count, shareLength, randomPartLength) = splitRandomSizes threshold secretLength
  shares <- replicateM count (getRandomBytes shareLength)
  randomPart <- getRandomBytes randomPartLength
  return SplitRandom {randomShares = shares, digestRandom = randomPart}

-- | The share mnemonics of a master secret under a scheme, one list per
-- group: 'generateShares' encoded.
generateMnemonics :: (MonadRandom m) => Scheme -> Bool -> Int -> Text -> ByteString -> m (Either String [[Text]])
generateMnemonics scheme ext iterExponent passphrase secret =
  (>>= traverse (traverse encodeShare)) <$> generateShares scheme ext iterExponent passphrase secret

{- Combining shares -}

-- | The encrypted master secret the shares rebuild. The shares must agree
-- on the identifier, the flag, the exponent, the group threshold, the group
-- count and the length of their values; they must come from exactly as
-- many groups as the group threshold; and in each group they must agree on
-- the member threshold, have distinct member indices and be exactly as many
-- as that threshold. Each group's secret is recovered from its members,
-- then the master secret from the groups.
combineShares :: [Share] -> Either String EncryptedMasterSecret
combineShares [] = Left "There are no shares to combine"
combineShares shares@(first : _) = do
  mapM_ checkShare shares
  agree "identifier" (.identifier)
  agree "extendable flag" (.extendable)
  agree "iteration exponent" (.iterationExponent)
  agree "group threshold" (.groupThreshold)
  agree "group count" (.groupCount)
  agree "length of their values" (B.length . (.value))
  let groups = M.toList (M.fromListWith (flip (++)) [(s.groupIndex, [s]) | s <- shares])
  unless (length groups == first.groupThreshold) $
    Left ("The shares come from " <> counted (length groups) "group" <> ", but the group threshold is " <> show first.groupThreshold)
  groupSecrets <- forM groups $ \(gi, members) -> do
    threshold <- case members of
      m : _ -> Right m.memberThreshold
      [] -> Left ("Group " <> show gi <> " has no shares") -- cannot happen: a group holds the share it was made for
    unless (all ((== threshold) . (.memberThreshold)) members) $
      Left ("The shares of group " <> show gi <> " do not have the same member threshold")
    forM_ (duplicates (map (.memberIndex) members)) $ \mi ->
      Left ("Group " <> show gi <> " has two shares with the member index " <> show mi)
    unless (length members == threshold) $
      Left ("Group " <> show gi <> " has " <> counted (length members) "share" <> ", but its member threshold is " <> show threshold)
    secret <- recoverSecret threshold [(fromIntegral m.memberIndex, m.value) | m <- members]
    return (fromIntegral gi, secret)
  ciphertext <- recoverSecret first.groupThreshold groupSecrets
  return
    EncryptedMasterSecret
      { identifier = first.identifier,
        extendable = first.extendable,
        iterationExponent = first.iterationExponent,
        ciphertext = ciphertext
      }
  where
    agree :: (Eq a) => String -> (Share -> a) -> Either String ()
    agree what field =
      unless (all ((== field first) . field) shares) $
        Left ("The shares do not have the same " <> what)
    duplicates xs = nub [x | (i, x) <- zip [0 :: Int ..] xs, x `elem` take i xs]

-- | The master secret the mnemonics rebuild, decrypted with the passphrase.
combineMnemonics :: Text -> [Text] -> Either String ByteString
combineMnemonics passphrase mnemonics = do
  shares <- mapM decodeShare mnemonics
  ems <- combineShares shares
  decryptMasterSecret passphrase ems

{- Words and bits -}

-- | The indices of the words of a mnemonic in the list. The words are
-- matched in lower case, as the reference implementation matches them.
mnemonicToIndices :: Text -> Either String [Int]
mnemonicToIndices mnemonic = forM (T.words (T.toLower mnemonic)) $ \w ->
  maybe (Left ("The word " <> show w <> " is not in the SLIP-39 word list")) Right (M.lookup w slip39WordListMap)

-- | The mnemonic of word indices, the words separated by single spaces.
-- An index outside the list is an error of the caller.
indicesToMnemonic :: [Int] -> Text
indicesToMnemonic = T.unwords . map (slip39WordList V.!)

-- | The big-endian number of a list of 10-bit indices.
indicesToInteger :: [Int] -> Integer
indicesToInteger = foldl' (\acc i -> (acc `shiftL` 10) .|. toInteger i) 0

-- | A number as the given count of 10-bit indices, big-endian.
integerToIndices :: Int -> Integer -> [Int]
integerToIndices count n = [fromIntegral ((n `shiftR` (10 * i)) .&. 1023) | i <- reverse [0 .. count - 1]]

-- | The big-endian number of a byte string.
bytesToInteger :: ByteString -> Integer
bytesToInteger = B.foldl' (\acc b -> (acc `shiftL` 8) .|. toInteger b) 0

-- | A number as the given count of bytes, big-endian.
integerToBytes :: Int -> Integer -> ByteString
integerToBytes count n = B.pack [fromIntegral ((n `shiftR` (8 * i)) .&. 255) | i <- reverse [0 .. count - 1]]

-- | The index of each word of the list.
slip39WordListMap :: Map Text Int
slip39WordListMap = M.fromList (zip (V.toList slip39WordList) [0 ..])

-- | The 1024 words of SLIP-0039, in order. The list is alphabetical, its
-- words have 4 to 8 letters and distinct first four letters.
slip39WordList :: Vector Text
slip39WordList =
  V.fromListN
    1024
    [ "academic",
      "acid",
      "acne",
      "acquire",
      "acrobat",
      "activity",
      "actress",
      "adapt",
      "adequate",
      "adjust",
      "admit",
      "adorn",
      "adult",
      "advance",
      "advocate",
      "afraid",
      "again",
      "agency",
      "agree",
      "aide",
      "aircraft",
      "airline",
      "airport",
      "ajar",
      "alarm",
      "album",
      "alcohol",
      "alien",
      "alive",
      "alpha",
      "already",
      "alto",
      "aluminum",
      "always",
      "amazing",
      "ambition",
      "amount",
      "amuse",
      "analysis",
      "anatomy",
      "ancestor",
      "ancient",
      "angel",
      "angry",
      "animal",
      "answer",
      "antenna",
      "anxiety",
      "apart",
      "aquatic",
      "arcade",
      "arena",
      "argue",
      "armed",
      "artist",
      "artwork",
      "aspect",
      "auction",
      "august",
      "aunt",
      "average",
      "aviation",
      "avoid",
      "award",
      "away",
      "axis",
      "axle",
      "beam",
      "beard",
      "beaver",
      "become",
      "bedroom",
      "behavior",
      "being",
      "believe",
      "belong",
      "benefit",
      "best",
      "beyond",
      "bike",
      "biology",
      "birthday",
      "bishop",
      "black",
      "blanket",
      "blessing",
      "blimp",
      "blind",
      "blue",
      "body",
      "bolt",
      "boring",
      "born",
      "both",
      "boundary",
      "bracelet",
      "branch",
      "brave",
      "breathe",
      "briefing",
      "broken",
      "brother",
      "browser",
      "bucket",
      "budget",
      "building",
      "bulb",
      "bulge",
      "bumpy",
      "bundle",
      "burden",
      "burning",
      "busy",
      "buyer",
      "cage",
      "calcium",
      "camera",
      "campus",
      "canyon",
      "capacity",
      "capital",
      "capture",
      "carbon",
      "cards",
      "careful",
      "cargo",
      "carpet",
      "carve",
      "category",
      "cause",
      "ceiling",
      "center",
      "ceramic",
      "champion",
      "change",
      "charity",
      "check",
      "chemical",
      "chest",
      "chew",
      "chubby",
      "cinema",
      "civil",
      "class",
      "clay",
      "cleanup",
      "client",
      "climate",
      "clinic",
      "clock",
      "clogs",
      "closet",
      "clothes",
      "club",
      "cluster",
      "coal",
      "coastal",
      "coding",
      "column",
      "company",
      "corner",
      "costume",
      "counter",
      "course",
      "cover",
      "cowboy",
      "cradle",
      "craft",
      "crazy",
      "credit",
      "cricket",
      "criminal",
      "crisis",
      "critical",
      "crowd",
      "crucial",
      "crunch",
      "crush",
      "crystal",
      "cubic",
      "cultural",
      "curious",
      "curly",
      "custody",
      "cylinder",
      "daisy",
      "damage",
      "dance",
      "darkness",
      "database",
      "daughter",
      "deadline",
      "deal",
      "debris",
      "debut",
      "decent",
      "decision",
      "declare",
      "decorate",
      "decrease",
      "deliver",
      "demand",
      "density",
      "deny",
      "depart",
      "depend",
      "depict",
      "deploy",
      "describe",
      "desert",
      "desire",
      "desktop",
      "destroy",
      "detailed",
      "detect",
      "device",
      "devote",
      "diagnose",
      "dictate",
      "diet",
      "dilemma",
      "diminish",
      "dining",
      "diploma",
      "disaster",
      "discuss",
      "disease",
      "dish",
      "dismiss",
      "display",
      "distance",
      "dive",
      "divorce",
      "document",
      "domain",
      "domestic",
      "dominant",
      "dough",
      "downtown",
      "dragon",
      "dramatic",
      "dream",
      "dress",
      "drift",
      "drink",
      "drove",
      "drug",
      "dryer",
      "duckling",
      "duke",
      "duration",
      "dwarf",
      "dynamic",
      "early",
      "earth",
      "easel",
      "easy",
      "echo",
      "eclipse",
      "ecology",
      "edge",
      "editor",
      "educate",
      "either",
      "elbow",
      "elder",
      "election",
      "elegant",
      "element",
      "elephant",
      "elevator",
      "elite",
      "else",
      "email",
      "emerald",
      "emission",
      "emperor",
      "emphasis",
      "employer",
      "empty",
      "ending",
      "endless",
      "endorse",
      "enemy",
      "energy",
      "enforce",
      "engage",
      "enjoy",
      "enlarge",
      "entrance",
      "envelope",
      "envy",
      "epidemic",
      "episode",
      "equation",
      "equip",
      "eraser",
      "erode",
      "escape",
      "estate",
      "estimate",
      "evaluate",
      "evening",
      "evidence",
      "evil",
      "evoke",
      "exact",
      "example",
      "exceed",
      "exchange",
      "exclude",
      "excuse",
      "execute",
      "exercise",
      "exhaust",
      "exotic",
      "expand",
      "expect",
      "explain",
      "express",
      "extend",
      "extra",
      "eyebrow",
      "facility",
      "fact",
      "failure",
      "faint",
      "fake",
      "false",
      "family",
      "famous",
      "fancy",
      "fangs",
      "fantasy",
      "fatal",
      "fatigue",
      "favorite",
      "fawn",
      "fiber",
      "fiction",
      "filter",
      "finance",
      "findings",
      "finger",
      "firefly",
      "firm",
      "fiscal",
      "fishing",
      "fitness",
      "flame",
      "flash",
      "flavor",
      "flea",
      "flexible",
      "flip",
      "float",
      "floral",
      "fluff",
      "focus",
      "forbid",
      "force",
      "forecast",
      "forget",
      "formal",
      "fortune",
      "forward",
      "founder",
      "fraction",
      "fragment",
      "frequent",
      "freshman",
      "friar",
      "fridge",
      "friendly",
      "frost",
      "froth",
      "frozen",
      "fumes",
      "funding",
      "furl",
      "fused",
      "galaxy",
      "game",
      "garbage",
      "garden",
      "garlic",
      "gasoline",
      "gather",
      "general",
      "genius",
      "genre",
      "genuine",
      "geology",
      "gesture",
      "glad",
      "glance",
      "glasses",
      "glen",
      "glimpse",
      "goat",
      "golden",
      "graduate",
      "grant",
      "grasp",
      "gravity",
      "gray",
      "greatest",
      "grief",
      "grill",
      "grin",
      "grocery",
      "gross",
      "group",
      "grownup",
      "grumpy",
      "guard",
      "guest",
      "guilt",
      "guitar",
      "gums",
      "hairy",
      "hamster",
      "hand",
      "hanger",
      "harvest",
      "have",
      "havoc",
      "hawk",
      "hazard",
      "headset",
      "health",
      "hearing",
      "heat",
      "helpful",
      "herald",
      "herd",
      "hesitate",
      "hobo",
      "holiday",
      "holy",
      "home",
      "hormone",
      "hospital",
      "hour",
      "huge",
      "human",
      "humidity",
      "hunting",
      "husband",
      "hush",
      "husky",
      "hybrid",
      "idea",
      "identify",
      "idle",
      "image",
      "impact",
      "imply",
      "improve",
      "impulse",
      "include",
      "income",
      "increase",
      "index",
      "indicate",
      "industry",
      "infant",
      "inform",
      "inherit",
      "injury",
      "inmate",
      "insect",
      "inside",
      "install",
      "intend",
      "intimate",
      "invasion",
      "involve",
      "iris",
      "island",
      "isolate",
      "item",
      "ivory",
      "jacket",
      "jerky",
      "jewelry",
      "join",
      "judicial",
      "juice",
      "jump",
      "junction",
      "junior",
      "junk",
      "jury",
      "justice",
      "kernel",
      "keyboard",
      "kidney",
      "kind",
      "kitchen",
      "knife",
      "knit",
      "laden",
      "ladle",
      "ladybug",
      "lair",
      "lamp",
      "language",
      "large",
      "laser",
      "laundry",
      "lawsuit",
      "leader",
      "leaf",
      "learn",
      "leaves",
      "lecture",
      "legal",
      "legend",
      "legs",
      "lend",
      "length",
      "level",
      "liberty",
      "library",
      "license",
      "lift",
      "likely",
      "lilac",
      "lily",
      "lips",
      "liquid",
      "listen",
      "literary",
      "living",
      "lizard",
      "loan",
      "lobe",
      "location",
      "losing",
      "loud",
      "loyalty",
      "luck",
      "lunar",
      "lunch",
      "lungs",
      "luxury",
      "lying",
      "lyrics",
      "machine",
      "magazine",
      "maiden",
      "mailman",
      "main",
      "makeup",
      "making",
      "mama",
      "manager",
      "mandate",
      "mansion",
      "manual",
      "marathon",
      "march",
      "market",
      "marvel",
      "mason",
      "material",
      "math",
      "maximum",
      "mayor",
      "meaning",
      "medal",
      "medical",
      "member",
      "memory",
      "mental",
      "merchant",
      "merit",
      "method",
      "metric",
      "midst",
      "mild",
      "military",
      "mineral",
      "minister",
      "miracle",
      "mixed",
      "mixture",
      "mobile",
      "modern",
      "modify",
      "moisture",
      "moment",
      "morning",
      "mortgage",
      "mother",
      "mountain",
      "mouse",
      "move",
      "much",
      "mule",
      "multiple",
      "muscle",
      "museum",
      "music",
      "mustang",
      "nail",
      "national",
      "necklace",
      "negative",
      "nervous",
      "network",
      "news",
      "nuclear",
      "numb",
      "numerous",
      "nylon",
      "oasis",
      "obesity",
      "object",
      "observe",
      "obtain",
      "ocean",
      "often",
      "olympic",
      "omit",
      "oral",
      "orange",
      "orbit",
      "order",
      "ordinary",
      "organize",
      "ounce",
      "oven",
      "overall",
      "owner",
      "paces",
      "pacific",
      "package",
      "paid",
      "painting",
      "pajamas",
      "pancake",
      "pants",
      "papa",
      "paper",
      "parcel",
      "parking",
      "party",
      "patent",
      "patrol",
      "payment",
      "payroll",
      "peaceful",
      "peanut",
      "peasant",
      "pecan",
      "penalty",
      "pencil",
      "percent",
      "perfect",
      "permit",
      "petition",
      "phantom",
      "pharmacy",
      "photo",
      "phrase",
      "physics",
      "pickup",
      "picture",
      "piece",
      "pile",
      "pink",
      "pipeline",
      "pistol",
      "pitch",
      "plains",
      "plan",
      "plastic",
      "platform",
      "playoff",
      "pleasure",
      "plot",
      "plunge",
      "practice",
      "prayer",
      "preach",
      "predator",
      "pregnant",
      "premium",
      "prepare",
      "presence",
      "prevent",
      "priest",
      "primary",
      "priority",
      "prisoner",
      "privacy",
      "prize",
      "problem",
      "process",
      "profile",
      "program",
      "promise",
      "prospect",
      "provide",
      "prune",
      "public",
      "pulse",
      "pumps",
      "punish",
      "puny",
      "pupal",
      "purchase",
      "purple",
      "python",
      "quantity",
      "quarter",
      "quick",
      "quiet",
      "race",
      "racism",
      "radar",
      "railroad",
      "rainbow",
      "raisin",
      "random",
      "ranked",
      "rapids",
      "raspy",
      "reaction",
      "realize",
      "rebound",
      "rebuild",
      "recall",
      "receiver",
      "recover",
      "regret",
      "regular",
      "reject",
      "relate",
      "remember",
      "remind",
      "remove",
      "render",
      "repair",
      "repeat",
      "replace",
      "require",
      "rescue",
      "research",
      "resident",
      "response",
      "result",
      "retailer",
      "retreat",
      "reunion",
      "revenue",
      "review",
      "reward",
      "rhyme",
      "rhythm",
      "rich",
      "rival",
      "river",
      "robin",
      "rocky",
      "romantic",
      "romp",
      "roster",
      "round",
      "royal",
      "ruin",
      "ruler",
      "rumor",
      "sack",
      "safari",
      "salary",
      "salon",
      "salt",
      "satisfy",
      "satoshi",
      "saver",
      "says",
      "scandal",
      "scared",
      "scatter",
      "scene",
      "scholar",
      "science",
      "scout",
      "scramble",
      "screw",
      "script",
      "scroll",
      "seafood",
      "season",
      "secret",
      "security",
      "segment",
      "senior",
      "shadow",
      "shaft",
      "shame",
      "shaped",
      "sharp",
      "shelter",
      "sheriff",
      "short",
      "should",
      "shrimp",
      "sidewalk",
      "silent",
      "silver",
      "similar",
      "simple",
      "single",
      "sister",
      "skin",
      "skunk",
      "slap",
      "slavery",
      "sled",
      "slice",
      "slim",
      "slow",
      "slush",
      "smart",
      "smear",
      "smell",
      "smirk",
      "smith",
      "smoking",
      "smug",
      "snake",
      "snapshot",
      "sniff",
      "society",
      "software",
      "soldier",
      "solution",
      "soul",
      "source",
      "space",
      "spark",
      "speak",
      "species",
      "spelling",
      "spend",
      "spew",
      "spider",
      "spill",
      "spine",
      "spirit",
      "spit",
      "spray",
      "sprinkle",
      "square",
      "squeeze",
      "stadium",
      "staff",
      "standard",
      "starting",
      "station",
      "stay",
      "steady",
      "step",
      "stick",
      "stilt",
      "story",
      "strategy",
      "strike",
      "style",
      "subject",
      "submit",
      "sugar",
      "suitable",
      "sunlight",
      "superior",
      "surface",
      "surprise",
      "survive",
      "sweater",
      "swimming",
      "swing",
      "switch",
      "symbolic",
      "sympathy",
      "syndrome",
      "system",
      "tackle",
      "tactics",
      "tadpole",
      "talent",
      "task",
      "taste",
      "taught",
      "taxi",
      "teacher",
      "teammate",
      "teaspoon",
      "temple",
      "tenant",
      "tendency",
      "tension",
      "terminal",
      "testify",
      "texture",
      "thank",
      "that",
      "theater",
      "theory",
      "therapy",
      "thorn",
      "threaten",
      "thumb",
      "thunder",
      "ticket",
      "tidy",
      "timber",
      "timely",
      "ting",
      "tofu",
      "together",
      "tolerate",
      "total",
      "toxic",
      "tracks",
      "traffic",
      "training",
      "transfer",
      "trash",
      "traveler",
      "treat",
      "trend",
      "trial",
      "tricycle",
      "trip",
      "triumph",
      "trouble",
      "true",
      "trust",
      "twice",
      "twin",
      "type",
      "typical",
      "ugly",
      "ultimate",
      "umbrella",
      "uncover",
      "undergo",
      "unfair",
      "unfold",
      "unhappy",
      "union",
      "universe",
      "unkind",
      "unknown",
      "unusual",
      "unwrap",
      "upgrade",
      "upstairs",
      "username",
      "usher",
      "usual",
      "valid",
      "valuable",
      "vampire",
      "vanish",
      "various",
      "vegan",
      "velvet",
      "venture",
      "verdict",
      "verify",
      "very",
      "veteran",
      "vexed",
      "victim",
      "video",
      "view",
      "vintage",
      "violence",
      "viral",
      "visitor",
      "visual",
      "vitamins",
      "vocal",
      "voice",
      "volume",
      "voter",
      "voting",
      "walnut",
      "warmth",
      "warn",
      "watch",
      "wavy",
      "wealthy",
      "weapon",
      "webcam",
      "welcome",
      "welfare",
      "western",
      "width",
      "wildlife",
      "window",
      "wine",
      "wireless",
      "wisdom",
      "withdraw",
      "wits",
      "wolf",
      "woman",
      "work",
      "worthy",
      "wrap",
      "wrist",
      "writing",
      "wrote",
      "year",
      "yelp",
      "yield",
      "yoga",
      "zero"
    ]
