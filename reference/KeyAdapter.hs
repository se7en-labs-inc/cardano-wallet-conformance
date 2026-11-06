{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}
-- Thin pinned-source oracle; expected fixture values are never read here.
module Main (main) where
import Prelude
import Cardano.Mnemonic (mkSomeMnemonic)
import Control.Monad (foldM, unless)
import Data.Aeson (Value, Object, eitherDecode, encode, object, withObject, (.:), (.=))
import Data.Aeson.Types (Parser, parseEither)
import Data.ByteString (ByteString)
import Data.Text (Text)
import Data.Word (Word32)
import System.Exit (exitFailure)
import qualified Cardano.Address.Derivation as A
import qualified Cardano.Crypto.Wallet as CC
import qualified Cardano.Wallet.Address.Derivation.Shelley as Shelley
import qualified Cardano.Wallet.Address.Derivation.Shared as Shared
import qualified Cardano.Wallet.Address.Derivation.Icarus as Icarus
import qualified Cardano.Wallet.Address.Derivation.Byron as Byron
import qualified Cardano.Wallet.Primitive.Passphrase as P
import qualified Data.ByteArray as BA
import qualified Data.ByteArray.Encoding as Base
import qualified Data.Aeson.Key as Key
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL
import qualified Data.Text as T
import qualified Data.Text.Encoding as T

hex :: ByteString -> Text
hex = T.decodeUtf8 . Base.convertToBase Base.Base16
bytes :: Object -> Text -> Parser ByteString
bytes input field = do
    text <- input .: Key.fromText field
    either (const $ fail "invalid_input") pure $ Base.convertFromBase Base.Base16 (T.encodeUtf8 text)

scheme :: Text -> Parser A.DerivationScheme
scheme "Byron" = pure A.DerivationScheme1
scheme style | style `elem` ["Shelley", "Shared", "Icarus"] = pure A.DerivationScheme2
scheme _ = fail "invalid_input"

root :: Object -> Text -> Parser A.XPrv
root input style = do
    sentence <- input .: "mnemonic"
    mnemonic <- either (const $ fail "invalid_input") pure $ mkSomeMnemonic @'[12,15,18,21,24] (T.words sentence)
    factor <- bytes input "second_factor_hex"
    unless (BS.null factor) $ fail "unsupported_profile"
    key <- case style of
        "Shelley" -> pure $ Shelley.getKey $ Shelley.generateKeyFromSeed (mnemonic, Nothing) mempty
        "Shared" -> pure $ Shared.getKey $ Shared.generateKeyFromSeed (mnemonic, Nothing) mempty
        "Icarus" -> pure $ Icarus.getKey $ Icarus.generateKeyFromSeed mnemonic mempty
        "Byron" -> pure $ Byron.getKey $ Byron.generateKeyFromSeed mnemonic mempty
        _ -> fail "invalid_input"
    let legacy = CC.unXPrv key
    maybe (fail "invalid_input") pure $ A.xprvFromBytes (BS.take 64 legacy <> BS.drop 96 legacy)

validPath :: Text -> [Word32] -> Bool
validPath _ [] = True
validPath "Byron" [_, _] = True
validPath style path = case path of
    [purpose, coin, account] -> prefix purpose coin account
    [purpose, coin, account, role, index] -> prefix purpose coin account && role <= 2 && index < hard
    _ -> False
  where
    hard = 2147483648
    prefix purpose coin account = purpose == hard + (if style == "Shared" then 1854 else if style == "Icarus" then 44 else 1852) && coin == hard + 1815 && account >= hard

run :: Text -> Value -> Parser Value
run operation = withObject "input" $ \input -> case operation of
    "byron.generate-root" -> do
        words' <- input .: "mnemonic"
        mnemonic <- either (const $ fail "invalid_input") pure $ mkSomeMnemonic @'[12,15,18,21,24] words'
        password <- bytes input "encryption_passphrase_hex"
        let key = Byron.getKey $ Byron.generateKeyFromSeed mnemonic (P.Passphrase $ BA.convert password)
        pure $ object ["xprv_hex" .= hex (CC.unXPrv key)]
    "keys.derive" -> do
        style <- input .: "style"
        derivation <- scheme style
        path <- input .: "path"
        unless (validPath style path) $ fail "invalid_input"
        parent <- root input style
        let child = foldl (\key index -> A.deriveXPrv derivation key (A.wholeDomainIndex index)) parent path
        pure $ object ["xprv_hex" .= hex (A.xprvToBytes child), "xpub_hex" .= hex (A.xpubToBytes $ A.toXPub child)]
    "keys.derive-public" -> do
        style <- input .: "style"
        derivation <- scheme style
        raw <- bytes input "parent_xpub_hex"
        parent <- maybe (fail "invalid_input") pure $ A.xpubFromBytes raw
        path <- input .: "path" :: Parser [Word32]
        unless (length path <= 5 && all (< 2147483648) path) $ fail "invalid_input"
        child <- foldM (\key index -> maybe (fail "invalid_input") pure $ A.deriveXPub derivation key (A.wholeDomainIndex index)) parent path
        pure $ object ["xpub_hex" .= hex (A.xpubToBytes child)]
    "keys.sign-extended" -> do
        raw <- bytes input "xprv_hex"
        key <- maybe (fail "invalid_input") pure $ A.xprvFromBytes raw
        message <- bytes input "message_hex"
        pure $ object ["public_key_hex" .= hex (A.xpubPublicKey $ A.toXPub key), "signature_hex" .= hex (CC.unXSignature $ A.sign key message)]
    _ -> fail "unsupported_operation"

main :: IO ()
main = do
    raw <- BL.take 1048577 <$> BL.getContents
    unless (BL.length raw <= 1048576) exitFailure
    request <- either (const exitFailure) pure $ eitherDecode raw
    (ident, operation, input) <- either (const exitFailure) pure $ parseEither parseRequest request
    let envelope field value = object ["protocol_version" .= (1 :: Int),"id" .= ident,field .= value]
    BL.putStr $ encode $ case parseEither (run operation) input of
        Left message -> envelope "error" $ object ["code" .= (if "unsupported_profile" `T.isInfixOf` T.pack message then "unsupported_profile" else "invalid_input" :: Text)]
        Right value -> envelope "result" value
  where
    parseRequest = withObject "request" $ \value -> do
        version <- value .: "protocol_version" :: Parser Int
        unless (version == 1) $ fail "invalid protocol"
        (,,) <$> (value .: "id" :: Parser Text) <*> value .: "operation" <*> value .: "input"
