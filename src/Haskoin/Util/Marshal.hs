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

unmarshal :: (Marshal s a) => s -> ByteString -> Either String a
unmarshal = runGetS . marshalGet

unmarshalLazy :: (Marshal s a) => s -> Lazy.ByteString -> Either String a
unmarshalLazy s = runGetS (marshalGet s) . Lazy.toStrict

class MarshalJSON s a | a -> s where
  marshalValue :: s -> a -> Value
  marshalEncoding :: s -> a -> Encoding
  marshalEncoding x = value . marshalValue x
  unmarshalValue :: s -> Value -> Parser a

marshalJSON :: (MarshalJSON s a) => s -> a -> Lazy.ByteString
marshalJSON s = toLazyByteString . fromEncoding . marshalEncoding s

unmarshalJSON :: (MarshalJSON s a) => s -> Lazy.ByteString -> Maybe a
unmarshalJSON s = parseMaybe (unmarshalValue s) <=< decode
