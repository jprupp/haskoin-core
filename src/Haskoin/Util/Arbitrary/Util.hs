{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}

-- |
-- Module      : Haskoin.Test.Util
-- Copyright   : No rights reserved
-- License     : MIT
-- Maintainer  : jprupp@protonmail.ch
-- Stability   : experimental
-- Portability : POSIX
module Haskoin.Util.Arbitrary.Util
  ( arbitraryBS,
    arbitraryBS1,
    arbitraryBSn,
    arbitraryBSS,
    arbitraryBSS1,
    arbitraryBSSn,
    arbitraryMaybe,
    arbitraryNetwork,
    arbitraryUTCTime,
    ReadBox (..),
    JsonBox (..),
    MarshalJsonBox (..),
    SerialBox (..),
    MarshalBox (..),
    IdentityTests (..),
    testIdentity,
    testSerial,
    testRead,
    testJson,
  )
where

import Control.Monad (forM_, (<=<))
import qualified Data.Aeson as A
import qualified Data.Aeson.Encoding as A
import qualified Data.Aeson.Types as A
import Data.ByteString (ByteString, pack)
import Data.ByteString.Lazy (fromStrict, toStrict)
import qualified Data.ByteString.Short as BSS
import Data.Bytes.Get
import Data.Bytes.Put
import Data.Bytes.Serial
import Data.Default
import qualified Data.Map.Strict as Map
import Data.Proxy
import Data.Time.Clock (UTCTime (..))
import Data.Time.Clock.POSIX (posixSecondsToUTCTime)
import qualified Data.Typeable as T
import Data.Word (Word32)
import Haskoin.Crypto (Ctx)
import Haskoin.Network.Constants
import Haskoin.Network.Data
import Haskoin.Util
import Test.Hspec (Spec, describe, shouldBe, shouldSatisfy)
import Test.Hspec.QuickCheck (prop)
import Test.QuickCheck

-- | Arbitrary strict 'ByteString'.
arbitraryBS :: Gen ByteString
arbitraryBS = pack <$> arbitrary

-- | Arbitrary non-empty strict 'ByteString'
arbitraryBS1 :: Gen ByteString
arbitraryBS1 = pack <$> listOf1 arbitrary

-- | Arbitrary strict 'ByteString' of a given length
arbitraryBSn :: Int -> Gen ByteString
arbitraryBSn n = pack <$> vectorOf n arbitrary

-- | Arbitrary 'ShortByteString'.
arbitraryBSS :: Gen BSS.ShortByteString
arbitraryBSS = BSS.pack <$> arbitrary

-- | Arbitrary non-empty 'ShortByteString'
arbitraryBSS1 :: Gen BSS.ShortByteString
arbitraryBSS1 = BSS.pack <$> listOf1 arbitrary

-- | Arbitrary 'ShortByteString' of a given length
arbitraryBSSn :: Int -> Gen BSS.ShortByteString
arbitraryBSSn n = BSS.pack <$> vectorOf n arbitrary

-- | Arbitrary UTCTime that generates dates after 01 Jan 1970 01:00:00 CET
arbitraryUTCTime :: Gen UTCTime
arbitraryUTCTime = do
  w <- arbitrary :: Gen Word32
  return $ posixSecondsToUTCTime $ realToFrac w

-- | Generate a Maybe from a Gen a
arbitraryMaybe :: Gen a -> Gen (Maybe a)
arbitraryMaybe g =
  frequency
    [ (1, return Nothing),
      (5, Just <$> g)
    ]

-- | Generate an Network
arbitraryNetwork :: Gen Network
arbitraryNetwork = elements allNets

-- Helpers for creating Serial and JSON Identity tests

instance Show Ctx where
  show _ = "Ctx"

data ReadBox
  = forall a.
    (Read a, Show a, Eq a, T.Typeable a) =>
    ReadBox (Gen a)

data JsonBox
  = forall a.
    (Show a, Eq a, T.Typeable a, A.ToJSON a, A.FromJSON a) =>
    JsonBox (Gen a)

data MarshalJsonBox
  = forall s a.
    (Show a, Show s, Eq a, T.Typeable a, MarshalJSON s a) =>
    MarshalJsonBox (Gen (s, a))

data SerialBox
  = forall a.
    (Show a, Eq a, T.Typeable a, Serial a) =>
    SerialBox (Gen a)

data MarshalBox
  = forall s a.
    (Show a, Show s, Eq a, T.Typeable a, Marshal s a) =>
    MarshalBox (Gen (s, a))

data IdentityTests = IdentityTests
  { readTests :: [ReadBox],
    jsonTests :: [JsonBox],
    marshalJsonTests :: [MarshalJsonBox],
    serialTests :: [SerialBox],
    marshalTests :: [MarshalBox]
  }

instance Default IdentityTests where
  def =
    IdentityTests
      { readTests = [],
        jsonTests = [],
        marshalJsonTests = [],
        serialTests = [],
        marshalTests = []
      }

testIdentity :: IdentityTests -> Spec
testIdentity t = do
  describe "Read/Show Encoding" $
    forM_ t.readTests $
      \(ReadBox g) -> testRead g
  describe "Data.Aeson Encoding" $
    forM_ t.jsonTests $
      \(JsonBox g) -> testJson g
  describe "MarshalJSON Encoding" $
    forM_ t.marshalJsonTests $
      \(MarshalJsonBox g) -> testMarshalJson g
  describe "Binary Encoding" $
    forM_ t.serialTests $
      \(SerialBox g) -> testSerial g
  describe "Marshal Encoding" $
    forM_ t.marshalTests $
      \(MarshalBox g) -> testMarshal g

-- | Generate Read/Show identity tests
testRead ::
  (Eq a, Read a, Show a, T.Typeable a) => Gen a -> Spec
testRead gen =
  prop ("read/show identity for " <> name) $
    forAll gen $
      \x -> (read . show) x `shouldBe` x
  where
    name = show $ T.typeRep $ proxy gen
    proxy :: Gen a -> Proxy a
    proxy = const Proxy

-- | Generate binary identity tests
testSerial ::
  (Eq a, Show a, T.Typeable a, Serial a) => Gen a -> Spec
testSerial gen =
  prop ("Binary encoding/decoding identity for " <> name) $
    forAll gen $ \x -> do
      (runGetL deserialize . runPutL . serialize) x `shouldBe` x
      (runGetL deserialize . fromStrict . runPutS . serialize) x `shouldBe` x
      (runGetS deserialize . runPutS . serialize) x `shouldBe` Right x
      (runGetS deserialize . toStrict . runPutL . serialize) x `shouldBe` Right x
  where
    name = show $ T.typeRep $ proxy gen
    proxy :: Gen a -> Proxy a
    proxy = const Proxy

-- | Generate Marshal identity tests
testMarshal ::
  (Eq a, Show a, Show s, T.Typeable a, Marshal s a) =>
  Gen (s, a) ->
  Spec
testMarshal gen = do
  prop ("Marshal marshalPut/marshalGet identity for " <> name) $
    forAll gen $ \(s, a) -> do
      (unmarshal s . marshal s) a `shouldBe` Right a
      (unmarshalLazy s . marshalLazy s) a `shouldBe` a
  where
    name = show $ T.typeRep $ proxy gen
    proxy :: Gen (s, a) -> Proxy a
    proxy = const Proxy

-- | Generate Data.Aeson identity tests
testJson ::
  (Eq a, Show a, T.Typeable a, A.ToJSON a, A.FromJSON a) => Gen a -> Spec
testJson gen = do
  prop ("Data.Aeson toJSON/fromJSON identity for " <> name) $
    forAll gen (`shouldSatisfy` jsonID)
  prop ("Data.Aeson toEncoding/fromJSON identity for " <> name) $
    forAll gen (`shouldSatisfy` encodingID)
  where
    name = show $ T.typeRep $ proxy gen
    proxy :: Gen a -> Proxy a
    proxy = const Proxy
    jsonID x = (A.fromJSON . A.toJSON) (toMap x) == A.Success (toMap x)
    encodingID x =
      (A.decode . A.encodingToLazyByteString . A.toEncoding) (toMap x)
        == Just (toMap x)

-- | Generate MarshalJSON identity tests
testMarshalJson ::
  (Eq a, Show a, Show s, T.Typeable a, MarshalJSON s a) =>
  Gen (s, a) ->
  Spec
testMarshalJson gen = do
  prop ("MarshalJSON marshalValue/unmarshalValue identity for " <> name) $
    forAll gen $
      \(s, a) -> val s a `shouldBe` Just a
  prop ("MarshalJSON marshalEncoding/unmarshalValue identity for " <> name) $
    forAll gen $
      \(s, a) -> enc s a `shouldBe` Just a
  where
    name = show $ T.typeRep $ proxy gen
    proxy :: Gen (s, a) -> Proxy a
    proxy = const Proxy
    val s a = A.parseMaybe (unmarshalValue s) (marshalValue s a)
    enc s a = unmarshalJSON s (marshalJSON s a)

toMap :: a -> Map.Map String a
toMap = Map.singleton "object"

toMapE :: A.Encoding -> A.Encoding
toMapE = A.pairs . A.pair "object"

fromMap :: Map.Map String a -> a
fromMap = (Map.! "object")
