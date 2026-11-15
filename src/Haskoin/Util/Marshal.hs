{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE ImportQualifiedPost #-}

-- |
-- Module      : Haskoin.Util.Marshal
-- Description : Encodings that depend on the network
--
-- Most types of this library are written the same way everywhere, and have
-- 'Serial', 'Data.Aeson.ToJSON' and 'Data.Aeson.FromJSON' instances. A few are
-- not: an extended key starts with version bytes that differ from one network
-- to the next, an address has a prefix, and a transaction signature may carry
-- a fork id. Those types cannot have the ordinary instances, since an instance
-- has nowhere to take the network from. They have 'Marshal' and 'MarshalJSON'
-- instances instead, whose functions take a parameter first, a @Network@
-- in every instance of this library.
--
-- Up to version 1.6 the parameter was also used to pass a secp256k1 context
-- to the types that hold a public key or a signature. The context is global
-- since 2.0.0, so those types went back to the ordinary classes, and
-- 'encodeSerial' and 'decodeSerial' stand in for 'marshal' and 'unmarshal'
-- on them.
module Haskoin.Util.Marshal where

import Control.Monad
import Data.Aeson
import Data.Aeson.Encoding
import Data.Aeson.Types
import Data.ByteString
import Data.ByteString.Builder
import Data.ByteString.Lazy qualified as Lazy
import Data.Bytes.Get
import Data.Bytes.Put
import Data.Bytes.Serial

class Marshal s a | a -> s where
  marshalPut :: (MonadPut m) => s -> a -> m ()
  marshalGet :: (MonadGet m) => s -> m a

marshal :: (Marshal s a) => s -> a -> ByteString
marshal s = runPutS . marshalPut s

marshalLazy :: (Marshal s a) => s -> a -> Lazy.ByteString
marshalLazy s = runPutL . marshalPut s

-- | Read a value from bytes that hold the value and nothing else. Bytes left
-- over after the value are an error, so that two different byte strings never
-- read as the same value. To read a value from the start of a longer stream,
-- run 'marshalGet' yourself.
unmarshal :: (Marshal s a) => s -> ByteString -> Either String a
unmarshal s = runGetS (marshalGetAll s)

-- | Like 'unmarshal', for lazy bytes.
unmarshalLazy :: (Marshal s a) => s -> Lazy.ByteString -> Either String a
unmarshalLazy s = runGetS (marshalGetAll s) . Lazy.toStrict

-- | Read a value and require that the input ends there.
marshalGetAll :: (Marshal s a, MonadGet m) => s -> m a
marshalGetAll s = do
  value <- marshalGet s
  done <- isEmpty
  unless done $ fail "unmarshal: bytes left over after the value"
  return value

-- | Write a value of an ordinary 'Serial' type to bytes. It is the
-- counterpart of 'marshal' for the types that need nothing to be read or
-- written, such as public keys, signatures and output scripts, and is only a
-- shorter way to write @'runPutS' . 'serialize'@.
encodeSerial :: (Serial a) => a -> ByteString
encodeSerial = runPutS . serialize

-- | Read a value of an ordinary 'Serial' type from bytes that hold the value
-- and nothing else. It is the counterpart of 'unmarshal' for the types that
-- need nothing to be read, and it keeps the same rule: bytes left over after
-- the value are an error. @'runGetS' 'deserialize'@ does not have that rule
-- and accepts a value followed by junk, so use it only to read from the start
-- of a longer stream.
--
-- The function is inlined where it is called, on purpose. A parser of this
-- library is written for any monad of the 'MonadGet' class. Called from
-- here, behind the 'Serial' dictionary of a type not yet known, it would run
-- every step through the dictionary of the monad. Inlined at a call that
-- names the type, it becomes the parser that GHC compiled for that type and
-- for the one monad used here. For an output script of 34 bytes that is the
-- difference between about 900 ns and about 150 ns, which
-- 'Haskoin.Address.scriptToAddressBS' pays for every script it parses.
decodeSerial :: (Serial a) => ByteString -> Either String a
decodeSerial = runGetS $ do
  value <- deserialize
  done <- isEmpty
  unless done $ fail "decodeSerial: bytes left over after the value"
  return value
{-# INLINE decodeSerial #-}

class MarshalJSON s a | a -> s where
  marshalValue :: s -> a -> Value
  marshalEncoding :: s -> a -> Encoding
  marshalEncoding x = value . marshalValue x
  unmarshalValue :: s -> Value -> Parser a

marshalJSON :: (MarshalJSON s a) => s -> a -> Lazy.ByteString
marshalJSON s = toLazyByteString . fromEncoding . marshalEncoding s

unmarshalJSON :: (MarshalJSON s a) => s -> Lazy.ByteString -> Maybe a
unmarshalJSON s = parseMaybe (unmarshalValue s) <=< decode
