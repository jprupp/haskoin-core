{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}

-- | Helper program of the PSBT shell scripts. It works on regtest only.
--
-- > PsbtSignTest key SECRET
--
-- SECRET is a secret key of 64 hexadecimal digits. The program prints the
-- private key in the wallet import format, a space, and the compressed
-- public key in hexadecimal.
--
-- > PsbtSignTest sign WIF
--
-- The program reads a PSBT in Base64 from the standard input. It signs every
-- input the key can sign and prints the PSBT in Base64.
module Main (main) where

import Crypto.Secp256k1 (secKey)
import qualified Data.ByteString.Char8 as C
import Data.Text (pack)
import qualified Data.Text.IO as T
import Haskoin
import System.Environment (getArgs)
import System.Exit (die)

main :: IO ()
main = withContext $ \ctx -> do
  args <- getArgs
  case args of
    ["key", secretHex] -> do
      secret <-
        maybe (die "The secret is not a valid secret key in hexadecimal") return $
          secKey =<< decodeHex (pack secretHex)
      let private = wrapSecKey True secret
          public = derivePublicKey ctx private
      T.putStrLn (toWif btcRegTest private <> " " <> encodeHex (marshal ctx public))
    ["sign", wif] -> do
      private <-
        maybe (die "The key is not a regtest private key") return $
          fromWif btcRegTest (pack wif)
      text <- C.getContents
      -- The signer is the default one. It wants the previous transaction of
      -- a SegWit version 0 coin, which Bitcoin Core puts into its PSBTs.
      let signed = signPsbt btcRegTest ctx (keySigner ctx private.key) =<< decodePsbtBase64 text
      either die (C.putStrLn . encodePsbtBase64) signed
    _ -> die "Usage: PsbtSignTest key SECRET | PsbtSignTest sign WIF"
