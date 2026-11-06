{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
-- Pinned source component profiles; no expected answers are read here.
module Main (main) where
import Prelude
import Control.Monad (unless)
import Data.Aeson (Value, Object, eitherDecode, encode, object, withObject, (.:), (.=))
import Data.Aeson.Types (Parser, parseEither)
import Data.ByteString (ByteString)
import Data.String (fromString)
import Data.Text (Text)
import Data.Word (Word32)
import System.Exit (exitFailure)
import qualified Cardano.Address as Address
import qualified Cardano.Address.Derivation as A
import qualified Cardano.Address.Style.Icarus as CI
import qualified Cardano.Address.Style.Shelley as CS
import qualified Cardano.Crypto.Wallet as CC
import qualified Cardano.Mnemonic as M
import qualified Cardano.Wallet.Address.Derivation.Shelley as Shelley
import qualified Cardano.Wallet.Address.Derivation.Shared as Shared
import qualified Cardano.Wallet.Address.Derivation.Icarus as Icarus
import qualified Cardano.Wallet.Primitive.Passphrase as P
import qualified Crypto.Encoding.BIP39 as B
import qualified Crypto.Encoding.BIP39.English as English
import qualified Data.Aeson.Key as Key
import qualified Data.ByteArray as BA
import qualified Data.ByteArray.Encoding as Base
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL
import qualified Data.Text as T
import qualified Data.Text.Encoding as T

hex :: BA.ByteArrayAccess a => a -> Text
hex = T.decodeUtf8 . Base.convertToBase Base.Base16
bytes :: Object -> Text -> Parser ByteString
bytes input field = do
    text <- input .: Key.fromText field
    either (const $ fail "invalid_input") pure $ Base.convertFromBase Base.Base16 (T.encodeUtf8 text)

entropyMnemonic :: ByteString -> Parser M.SomeMnemonic
entropyMnemonic raw = case BS.length raw of
    16 -> M.SomeMnemonic . M.entropyToMnemonic <$> checked (M.mkEntropy @128 $ BA.convert raw)
    20 -> M.SomeMnemonic . M.entropyToMnemonic <$> checked (M.mkEntropy @160 $ BA.convert raw)
    24 -> M.SomeMnemonic . M.entropyToMnemonic <$> checked (M.mkEntropy @192 $ BA.convert raw)
    28 -> M.SomeMnemonic . M.entropyToMnemonic <$> checked (M.mkEntropy @224 $ BA.convert raw)
    32 -> M.SomeMnemonic . M.entropyToMnemonic <$> checked (M.mkEntropy @256 $ BA.convert raw)
    _ -> fail "invalid_input"
  where checked = either (const $ fail "invalid_input") pure

seed :: forall n. B.ValidMnemonicSentence n => [Text] -> Text -> Parser ByteString
seed words' password = do
    phrase <- either (const $ fail "invalid_input") pure $ B.mnemonicPhrase @n (map (fromString . T.unpack) words')
    pure $ BA.convert $ B.phraseToSeed phrase English.english (fromString $ T.unpack password)

rawSeed :: [Text] -> Text -> Parser ByteString
rawSeed words' password = do
    _ <- either (const $ fail "invalid_input") pure $ M.mkSomeMnemonic @'[12,15,18,21,24] words'
    case length words' of
        12 -> seed @12 words' password
        15 -> seed @15 words' password
        18 -> seed @18 words' password
        21 -> seed @21 words' password
        24 -> seed @24 words' password
        _ -> fail "invalid_input"

rootProfile :: Object -> Parser Value
rootProfile input = do
    style <- input .: "style" :: Parser Text
    sentence <- input .: "mnemonic"
    mnemonic <- either (const $ fail "invalid_input") pure $ M.mkSomeMnemonic @'[12,15,18,21,24] (T.words sentence)
    factor <- bytes input "second_factor_hex"
    password <- input .: "encryption_passphrase_utf8"
    let pwd = P.Passphrase (BA.convert $ T.encodeUtf8 password)
        fromAddress key = let raw = A.xprvToBytes key
            in either (const $ fail "invalid_input") pure $ CC.xprv (BS.take 64 raw <> A.xpubPublicKey (A.toXPub key) <> BS.drop 64 raw)
    encrypted <- case style of
        "Ledger" -> do
            unless (BS.null factor) $ fail "unsupported_profile"
            pure $ Icarus.getKey $ Icarus.generateKeyFromHardwareLedger mnemonic pwd
        "Icarus" -> if BS.null factor
            then pure $ Icarus.getKey $ Icarus.generateKeyFromSeed mnemonic pwd
            else do
                plain <- fromAddress $ CI.getKey $ CI.genMasterKeyFromMnemonic mnemonic (BA.convert factor)
                pure $ CC.xPrvChangePass (mempty :: ByteString) pwd plain
        "Trezor" -> if BS.null factor
            then pure $ Icarus.getKey $ Icarus.generateKeyFromSeed mnemonic pwd
            else do
                plain <- fromAddress $ CI.getKey $ CI.genMasterKeyFromMnemonic mnemonic (BA.convert factor)
                pure $ CC.xPrvChangePass (mempty :: ByteString) pwd plain
        "Shelley" -> do
            second <- if BS.null factor then pure Nothing else Just <$> entropyMnemonic factor
            pure $ Shelley.getKey $ Shelley.generateKeyFromSeed (mnemonic, second) pwd
        "Shared" -> do
            second <- if BS.null factor then pure Nothing else Just <$> entropyMnemonic factor
            pure $ Shared.getKey $ Shared.generateKeyFromSeed (mnemonic, second) pwd
        _ -> fail "invalid_input"
    let plain128 = CC.unXPrv $ CC.xPrvChangePass pwd (mempty :: ByteString) encrypted
    plain <- maybe (fail "invalid_input") pure $ A.xprvFromBytes (BS.take 64 plain128 <> BS.drop 96 plain128)
    path <- input .: "path" :: Parser [Word32]
    message <- bytes input "message_hex"
    unless (length path <= 5) $ fail "invalid_input"
    let child = foldl (\key index -> A.deriveXPrv A.DerivationScheme2 key (A.wholeDomainIndex index)) plain path
    pure $ object ["xprv_hex" .= hex (A.xprvToBytes child),"xpub_hex" .= hex (A.xpubToBytes $ A.toXPub child),"encrypted_xprv_hex" .= hex (CC.unXPrv encrypted),"signature_hex" .= hex (CC.unXSignature $ A.sign child message)]

run :: Text -> Value -> Parser Value
run operation = withObject "input" $ \input -> case operation of
    "bip39.entropy-to-mnemonic" -> do
        raw <- bytes input "entropy_hex"
        mnemonic <- entropyMnemonic raw
        case mnemonic of M.SomeMnemonic words' -> pure $ object ["mnemonic" .= T.unwords (M.mnemonicToText words')]
    seedOperation | seedOperation `elem` ["bip39.wallet-seed", "bip39.to-seed"] -> do
        sentence <- input .: "mnemonic"
        password <- input .: "passphrase"
        unless (seedOperation == "bip39.wallet-seed" || T.all (< '\x80') password) $ fail "unsupported_profile"
        result <- rawSeed (T.words sentence) password
        pure $ object ["seed_hex" .= hex result]
    "keys.generate-root-profile" -> rootProfile input
    "address.enterprise" -> do
        public <- bytes input "public_key_hex"
        unless (BS.length public == 32) $ fail "invalid_input"
        extended <- maybe (fail "invalid_input") pure $ A.xpubFromBytes (public <> BS.replicate 32 0)
        network <- input .: "network_tag" :: Parser Integer
        discriminant <- either (const $ fail "invalid_input") pure $ CS.mkNetworkDiscriminant network
        let address = CS.paymentAddress discriminant $ CS.PaymentFromKey $ CS.liftPub $ A.xpubToPub extended
        pure $ object ["address" .= Address.bech32 address,"address_hex" .= hex (Address.unAddress address)]
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
