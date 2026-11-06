{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE ImportQualifiedPost #-}

module Haskoin.Util.Marshal where

import Control.Monad
import Crypto.Secp256k1
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

class MarshalJSON s a | a -> s where
  marshalValue :: s -> a -> Value
  marshalEncoding :: s -> a -> Encoding
  marshalEncoding x = value . marshalValue x
  unmarshalValue :: s -> Value -> Parser a

marshalJSON :: (MarshalJSON s a) => s -> a -> Lazy.ByteString
marshalJSON s = toLazyByteString . fromEncoding . marshalEncoding s

unmarshalJSON :: (MarshalJSON s a) => s -> Lazy.ByteString -> Maybe a
unmarshalJSON s = parseMaybe (unmarshalValue s) <=< decode
