{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}

-- | A regtest node of Bitcoin Core for the tests that check the library
-- against it: Bitcoin Core makes and checks what the library signs, and
-- the library must combine and finalize what Bitcoin Core does, as Bitcoin
-- Core does.
--
-- The node runs in a rootless Podman container of
-- [podman-test](https://github.com/jprupp/podman-test), for as long as the
-- tests of a group: each group of tests that needs a node gets one of its
-- own, so test processes that run at once never share a node, a port or a
-- folder. Its RPC port is bridged to a Unix socket of its pod, and the pod
-- has no network, so the node can reach no peer and nothing else can reach
-- it.
--
-- Without Podman the tests are pending, and say why. Set @PODMAN_TEST_SKIP@
-- to leave them out on purpose.
--
-- This module is part of the test suite only, not of the library: the
-- library must not depend on podman-test.
module BitcoinCore
  ( -- * Running a node
    Node,
    aroundNode,
    coreVersion,

    -- * Calls
    RpcError (..),
    rpc,
    walletRpc,
    at,
    textAt,
  )
where

import Control.Exception (Exception, SomeException, bracket, throwIO, try)
import Control.Lens ((^?))
import Data.Aeson (Value (..), eitherDecodeStrict, encode, object, (.=))
import Data.Aeson.Key qualified as Key
import Data.Aeson.Lens (key)
import Data.ByteString (ByteString)
import Data.ByteString qualified as B
import Data.ByteString.Char8 qualified as C
import Data.ByteString.Lazy qualified as BL
import Data.Text (Text)
import Data.Text qualified as T
import Data.Text.Encoding (encodeUtf8)
import Network.Socket (Socket, close)
import Network.Socket.ByteString (recv, sendAll)
import Test.Hspec (Spec, SpecWith, around, aroundAll, pendingWith, runIO)
import Test.Podman

-- | A node that runs, and the address of its RPC interface.
newtype Node = Node Address

-- | Release of Bitcoin Core in the image.
coreVersion :: String
coreVersion = "32.1"

-- | Run a group of tests with a node of its own, after a setup that gives
-- the tests what they need: the node itself, or what the setup made with
-- it. The node is started before the first test of the group and removed
-- after the last, however they end. Without Podman, each test is pending,
-- and says why. Whether Podman can run is asked once, as the tree of tests
-- is built, which takes a tenth of a second.
--
-- The first run on a machine builds the image, which downloads Ubuntu and
-- Bitcoin Core and takes a minute or two; later runs start a node in a few
-- seconds.
aroundNode :: (Node -> IO a) -> SpecWith a -> Spec
aroundNode setup tests = do
  usable <- runIO podmanUsable
  case usable of
    Left why -> around (\_ -> pendingWith ("Bitcoin Core needs Podman: " <> why)) tests
    Right () -> aroundAll (\test -> withPod nodePod $ \p -> setup (Node (address p "rpc")) >>= test) tests

-- | The pod of a node: ready once the RPC answers, which Bitcoin Core does
-- only after it has loaded its chain, some seconds after its port opens.
nodePod :: PodSpec
nodePod =
  (pod "bitcoin-core" [nodeContainer])
    { ready = [Accepts "rpc", Probe "Bitcoin Core answers RPC calls" answers],
      readyWithin = 120
    }
  where
    answers p = do
      r <- try @SomeException (rpc (Node (address p "rpc")) "getblockchaininfo" [])
      return (either (const False) (const True) r)

-- | The container of a node. Its chain is in memory, it talks to no peer,
-- and its caches and mempool are small, as a test needs.
nodeContainer :: ContainerSpec
nodeContainer =
  (container "bitcoind" image)
    { entrypoint = Just "/opt/bitcoin-core/bin/bitcoind",
      memory = Just "1g",
      tmpfs = [("/chain", "512m")],
      command =
        [ "-regtest",
          "-datadir=/chain",
          "-printtoconsole",
          "-server",
          "-rpcuser=test",
          "-rpcpassword=test",
          "-rpcbind=0.0.0.0",
          "-rpcallowip=0.0.0.0/0",
          "-listen=0",
          "-txindex=1",
          "-fallbackfee=0.0001",
          "-dbcache=4",
          "-maxmempool=5",
          "-par=1",
          "-rpcthreads=2"
        ],
      endpoints = [Bridged "rpc" 18443]
    }

-- | The image of the node, built from pinned and checked sources only.
--
-- It starts from the official Ubuntu 26.04 image, pinned by the digest of
-- its index, installs curl from the Ubuntu archive at a fixed snapshot date,
-- and downloads the release of Bitcoin Core from bitcoincore.org, checked
-- against the SHA-256 hash pinned here: a tarball that does not match stops
-- the build. The hashes are those of the @SHA256SUMS@ of the release, whose
-- signatures by the builders of Bitcoin Core were checked when they were
-- pinned for the tests of haskoin-store, which use the same base image and
-- release.
--
-- podman-test tags the image with a hash of this recipe, so a new release
-- or hash builds a new image. To move to a new release, change
-- 'coreVersion' and the two hashes after checking them the same way.
image :: Image
image =
  Built
    ImageSpec
      { name = "haskoin-core-bitcoind",
        containerfile = C.pack (unlines recipe),
        files = []
      }
  where
    base =
      "docker.io/library/ubuntu\
      \@sha256:6a06111c3b0a8600feadb270aec771dc239bf407b25625f93f44ab00e11f4d3c"
    snapshot = "20261101T000000Z"
    amd64 = "61545c17c3120fb7412f896d248b11993af04ec8817aad3649c55b2afb044963"
    arm64 = "7ed37c7373eb6aa3e3f72842596a1afeba1b223717033cade9842b25773e1922"
    url =
      "https://bitcoincore.org/bin/bitcoin-core-"
        <> coreVersion
        <> "/bitcoin-"
        <> coreVersion
        <> "-$a-linux-gnu.tar.gz"
    -- The snapshot archive is served over HTTPS only, so its certificates
    -- come first from the regular archive, whose packages apt checks by
    -- their signatures.
    recipe =
      [ "FROM " <> base,
        "ARG TARGETARCH",
        "RUN apt-get update --error-on=any \\",
        " && apt-get install -y --no-install-recommends ca-certificates \\",
        " && apt-get update --error-on=any --snapshot " <> snapshot <> " \\",
        " && apt-get install -y --no-install-recommends --snapshot " <> snapshot <> " ca-certificates curl \\",
        " && rm -rf /var/lib/apt/lists/*",
        "RUN set -eu; \\",
        " case \"$TARGETARCH\" in \\",
        "  amd64) a=x86_64; h=" <> amd64 <> ";; \\",
        "  arm64) a=aarch64; h=" <> arm64 <> ";; \\",
        "  *) echo \"unsupported architecture $TARGETARCH\"; exit 1;; \\",
        " esac; \\",
        " curl -fsSL -o /tmp/release.tar.gz \"" <> url <> "\"; \\",
        " echo \"$h  /tmp/release.tar.gz\" | sha256sum -c -; \\",
        " mkdir -p /opt/bitcoin-core; \\",
        " tar -xzf /tmp/release.tar.gz -C /opt/bitcoin-core --strip-components=1; \\",
        " rm /tmp/release.tar.gz"
      ]

-- | An error that the node gave for a call: the method, and the error.
data RpcError = RpcError !Text !Value
  deriving (Show)

instance Exception RpcError

-- | Call a method of the node, and give its result.
rpc :: Node -> Text -> [Value] -> IO Value
rpc node = call node "/"

-- | Call a method of a wallet of the node, and give its result.
walletRpc :: Node -> Text -> Text -> [Value] -> IO Value
walletRpc node wallet = call node ("/wallet/" <> wallet)

-- | One JSON-RPC call, as one request of HTTP 1.0 on a connection of its
-- own: the node answers with the whole body and closes the connection, so
-- the answer is all that comes back. That is all the HTTP the tests need,
-- and it needs no client library. The node answers an error with a status
-- that is not 200 and the error in the body, so only the body is read.
call :: Node -> Text -> Text -> [Value] -> IO Value
call (Node addr) path method params = do
  answer <- bracket (connectTo addr) close $ \s -> do
    sendAll s request
    receiveAll s
  let body = B.drop 4 (snd (B.breakSubstring "\r\n\r\n" answer))
  case eitherDecodeStrict @Value body of
    Left e -> fail ("Bitcoin Core gave no JSON for " <> T.unpack method <> ": " <> e)
    Right v -> case (v ^? key "error", v ^? key "result") of
      (Just Null, Just r) -> return r
      (Just e, _) -> throwIO (RpcError method e)
      _ -> fail ("Bitcoin Core gave no result for " <> T.unpack method)
  where
    payload =
      BL.toStrict . encode $
        object ["jsonrpc" .= ("1.0" :: Text), "id" .= ("test" :: Text), "method" .= method, "params" .= params]
    request =
      mconcat
        [ "POST " <> encodeUtf8 path <> " HTTP/1.0\r\n",
          -- test:test, the user and password of the node
          "Authorization: Basic dGVzdDp0ZXN0\r\n",
          "Content-Type: application/json\r\n",
          "Content-Length: " <> C.pack (show (B.length payload)) <> "\r\n",
          "\r\n",
          payload
        ]

-- | All that comes on a connection until the node closes it.
receiveAll :: Socket -> IO ByteString
receiveAll s = B.concat <$> go
  where
    go =
      recv s 65536 >>= \case
        "" -> return []
        chunk -> (chunk :) <$> go

-- | The field of an object that a call gave, or a failure that names it.
at :: Text -> Value -> IO Value
at k v = maybe (fail ("No field " <> T.unpack k <> " in " <> show v)) return (v ^? key (Key.fromText k))

-- | The text field of an object that a call gave.
textAt :: Text -> Value -> IO Text
textAt k v =
  at k v >>= \case
    String t -> return t
    other -> fail ("The field " <> T.unpack k <> " is not text: " <> show other)
