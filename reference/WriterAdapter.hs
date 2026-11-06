{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
module Main (main) where
import Prelude
import Cardano.Crypto.Libsodium (sodiumInit)
import Control.Exception (ErrorCall, displayException, evaluate, try)
import Control.Lens ((&), (.~), (^.))
import Control.Monad (unless)
import Data.Aeson (Value, Object, eitherDecode, encode, object, withObject, (.:), (.:?), (.!=), (.=))
import Data.Aeson.Types (Parser, parseEither)
import Data.ByteString (ByteString)
import Data.Text (Text)
import Data.Word (Word32, Word64)
import System.Exit (exitFailure)
import qualified Cardano.Address.Derivation as A
import qualified Cardano.Address.KeyHash as Key
import qualified Cardano.Address.Script as Script
import qualified Cardano.Api as Api
import qualified Cardano.Balance.Tx.Eras as Era
import qualified Cardano.Balance.Tx.Tx as Balance
import qualified Cardano.Crypto.Wallet as Crypto
import qualified Cardano.Crypto.Hash.Class as Hash
import qualified Cardano.Ledger.Api as Ledger
import qualified Cardano.Ledger.Alonzo.Scripts as Alonzo
import qualified Cardano.Ledger.Binary as Binary
import qualified Cardano.Ledger.Core as Core
import qualified Cardano.Ledger.Hashes as Hashes
import qualified Cardano.Read.Ledger.Tx.CBOR as CBOR
import qualified Cardano.Wallet.Address.Derivation as Derivation
import qualified Cardano.Wallet.Address.Derivation.Byron as Byron
import qualified Cardano.Wallet.Address.Derivation.Shelley as Shelley
import qualified Cardano.Wallet.Flavor as Flavor
import qualified Cardano.Wallet.Primitive.Ledger.Convert as Convert
import qualified Cardano.Wallet.Primitive.Passphrase as Pass
import qualified Cardano.Wallet.Primitive.Types.Address as Address
import qualified Cardano.Wallet.Primitive.Types.Coin as Coin
import qualified Cardano.Wallet.Primitive.Types.DRep as DRep
import qualified Cardano.Wallet.Primitive.Types.Pool as Pool
import qualified Cardano.Wallet.Read.Eras as Read
import qualified Cardano.Wallet.Read.Tx as Read
import qualified Cardano.Wallet.Shelley.Transaction as Wallet
import qualified Cardano.Wallet.Shelley.Transaction.Ledger as Writer
import qualified Cardano.Wallet.Transaction as Transaction
import qualified Data.Aeson.Key as JsonKey
import qualified Data.ByteArray as BA
import qualified Data.ByteArray.Encoding as Hex
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL
import qualified Data.Map.Strict as Map
import qualified Data.Text as T
import qualified Data.Text.Encoding as T

hex :: ByteString -> Text
hex = T.decodeUtf8 . Hex.convertToBase Hex.Base16
bytes :: Object -> Text -> Parser ByteString
bytes input field = do
    raw <- input .: JsonKey.fromText field
    either (const $ fail "invalid_input") pure $ Hex.convertFromBase Hex.Base16 (T.encodeUtf8 raw)
sized :: Int -> ByteString -> Parser ByteString
sized size raw = do
    unless (BS.length raw == size) $ fail "invalid_input"
    pure raw
present :: Maybe a -> Parser a
present = maybe (fail "invalid_input") pure
transaction :: Object -> Parser (Balance.Tx Read.Conway)
transaction input = do
    raw <- bytes input "transaction_cbor_hex"
    parsed <- either (const $ fail "decode_failed") pure (CBOR.deserializeTx $ BL.fromStrict raw :: Either Binary.DecoderError (Read.Tx Read.Conway))
    pure $ Read.unTx parsed
native :: ByteString -> Script.Script Key.KeyHash
native raw = Script.RequireSignatureOf $ Key.KeyHash Key.Payment raw
certificates :: Object -> Parser Value
certificates input = do
    era <- input .: "era" :: Parser Text
    stake <- bytes input "stake_xpub_hex" >>= present . A.xpubFromBytes
    script <- input .:? "stake_script"
    credential <- case script of
        Nothing -> pure $ Left stake
        Just raw -> Right . native <$> (bytes raw "key_hash_hex" >>= sized 28)
    deposit <- fmap (Coin.Coin . fromIntegral) <$> (input .:? "deposit" :: Parser (Maybe Word64))
    action <- input .: "action" :: Parser Text
    let withEra :: forall era. Era.IsRecentEra era => Era.RecentEra era -> Parser Value
        withEra recent = do
            certs <- case action of
                "join" -> do
                    pool <- Pool.PoolId <$> (bytes input "pool_hex" >>= sized 28)
                    pure $ Writer.certificateFromDelegationActionLedger recent credential deposit $ Transaction.Join pool
                "join-registering" -> do
                    pool <- Pool.PoolId <$> (bytes input "pool_hex" >>= sized 28)
                    pure $ Writer.certificateFromDelegationActionLedger recent credential deposit $ Transaction.JoinRegisteringKey pool
                "quit" -> pure $ Writer.certificateFromDelegationActionLedger recent credential deposit Transaction.Quit
                "vote" -> Writer.certificateFromVotingActionLedger recent credential deposit . Transaction.Vote <$> drep input
                "vote-registering" -> Writer.certificateFromVotingActionLedger recent credential deposit . Transaction.VoteRegisteringKey <$> drep input
                _ -> fail "invalid_input"
            pure $ object ["certificates_cbor_hex" .= map (hex . Binary.serialize' (Ledger.eraProtVerLow @era)) certs]
    case era of
        "conway" -> withEra Era.RecentEraConway
        "dijkstra" -> withEra Era.RecentEraDijkstra
        _ -> fail "invalid_input"
  where
    drep payload = do
        value <- payload .: "drep"
        kind <- value .: "type" :: Parser Text
        case kind of
            "abstain" -> pure DRep.Abstain
            "no-confidence" -> pure DRep.NoConfidence
            "key" -> DRep.FromDRepID . DRep.DRepFromKeyHash . DRep.DRepKeyHash <$> (bytes value "hash_hex" >>= sized 28)
            "script" -> DRep.FromDRepID . DRep.DRepFromScriptHash . DRep.DRepScriptHash <$> (bytes value "hash_hex" >>= sized 28)
            _ -> fail "invalid_input"
run :: Text -> Value -> Parser Value
run operation = withObject "input" $ \input -> case operation of
    "wallet.certificates" -> certificates input
    "witness.script" -> do
        raw <- bytes input "script_key_hash_hex" >>= sized 28
        let script = Alonzo.NativeScript (Convert.toLedgerTimelockScript $ native raw) :: Ledger.Script Read.Conway
            scriptHash = Core.hashScript @Read.Conway script
            witnesses = (Ledger.mkBasicTxWits :: Ledger.TxWits Read.Conway) & Ledger.scriptTxWitsL .~ Map.singleton scriptHash script
        let Hashes.ScriptHash rawHash = scriptHash
        pure $ object ["witnesses_cbor_hex" .= hex (Binary.serialize' (Ledger.eraProtVerLow @Read.Conway) witnesses),"script_hash_hex" .= hex (Hash.hashToBytes rawHash)]
    _ | operation `elem` ["witness.build","witness.sign"] -> do
        tx <- transaction input
        rawKey <- bytes input "xprv_hex" >>= sized 128
        key <- either (const $ fail "invalid_input") pure $ Crypto.xprv rawKey
        password <- bytes input "passphrase_hex"
        let passphrase = Pass.Passphrase $ BA.convert password
        style <- input .: "style" :: Parser Text
        address <- Address.Address <$> bytes input "address_hex"
        magic <- input .:? "network_magic" :: Parser (Maybe Word32)
        resolve <- input .:? "resolve_inputs" .!= True
        let network = maybe Api.Mainnet (Api.Testnet . Api.NetworkMagic) magic
            body = tx ^. Ledger.bodyTxL
        if operation == "witness.build" then do
            witness <- case style of
                "Shelley" -> pure $ Binary.serialize' (Ledger.eraProtVerLow @Read.Conway) $ Writer.mkShelleyWitnessLedger Era.RecentEraConway body (key,passphrase)
                "Byron" -> pure $ Binary.serialize' (Ledger.eraProtVerLow @Read.Conway) $ Writer.mkByronWitnessLedger Era.RecentEraConway body network address (key,passphrase)
                _ -> fail "invalid_input"
            pure $ object ["witness_cbor_hex" .= hex witness]
        else do
            let sign :: forall k depth. Flavor.KeyFlavorS k -> (Address.Address -> Maybe (k depth A.XPrv, Pass.Passphrase "encryption")) -> Balance.Tx Read.Conway
                sign flavor addressResolver = Wallet.signTransaction flavor network Transaction.AnyWitnessCountCtx (const Nothing) (const Nothing) Nothing (const Nothing) addressResolver (const $ if resolve then Just address else Nothing) tx
            signed <- case style of
                "Shelley" -> pure $ sign Flavor.ShelleyKeyS $ const $ Just (Shelley.ShelleyKey key,passphrase)
                "Byron" -> pure $ sign Flavor.ByronKeyS $ const $ Just (Byron.ByronKey key () mempty :: Byron.ByronKey 'Derivation.RootK A.XPrv,passphrase)
                _ -> fail "invalid_input"
            pure $ object ["transaction_cbor_hex" .= hex (BL.toStrict $ CBOR.serializeTx (Read.Tx signed :: Read.Tx Read.Conway))]
    _ -> fail "invalid_input"
main :: IO ()
main = do
    sodiumInit
    raw <- BL.take 1048577 <$> BL.getContents
    unless (BL.length raw <= 1048576) exitFailure
    request <- either (const exitFailure) pure $ eitherDecode raw
    (ident,operation,input) <- either (const exitFailure) pure $ parseEither parseRequest request
    let envelope field value = object ["protocol_version" .= (1 :: Int),"id" .= ident,field .= value]
        output = case parseEither (run operation) input of
            Left message -> envelope "error" $ object ["code" .= (if "decode_failed" `T.isInfixOf` T.pack message then "decode_failed" else "invalid_input" :: Text)]
            Right value -> envelope "result" value
        encoded = encode output
    forced <- try @ErrorCall $ evaluate $ BL.length encoded
    case forced of
        Right _ -> BL.putStr encoded
        Left err -> do
            let message = T.pack $ displayException err
            code <- if operation == "wallet.certificates" && "Dijkstra not yet supported" `T.isInfixOf` message then pure ("unsupported_era" :: Text)
                else if operation == "wallet.certificates" && "deposit required" `T.isInfixOf` message then pure "deposit_required"
                else exitFailure
            BL.putStr $ encode $ envelope "error" $ object ["code" .= code]
  where
    parseRequest = withObject "request" $ \value -> do
        version <- value .: "protocol_version" :: Parser Int
        unless (version == 1) $ fail "invalid_input"
        (,,) <$> (value .: "id" :: Parser Text) <*> value .: "operation" <*> value .: "input"
