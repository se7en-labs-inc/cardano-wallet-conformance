{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
module Main (main) where
import Prelude
import Cardano.Crypto.Libsodium (sodiumInit)
import Control.Monad (unless)
import Control.Lens ((&), (.~))
import Data.Aeson (Value, Object, eitherDecode, encode, object, withObject, (.:), (.=))
import Data.Aeson.Types (Parser, parseEither)
import Data.ByteString (ByteString)
import Data.Either (isRight)
import Data.List.NonEmpty (NonEmpty (..))
import Data.Text (Text)
import Data.Word (Word64)
import System.Exit (exitFailure)
import qualified Cardano.Crypto.DSIGN.Class as DSIGN
import qualified Cardano.Crypto.DSIGN.Ed25519 as Ed
import qualified Cardano.Binary.FixedSizeCodec as Fixed
import qualified Cardano.Ledger.Binary as Binary
import qualified Cardano.Ledger.Api as Ledger
import qualified Cardano.Ledger.Core as Core
import qualified Cardano.Ledger.Coin as Coin
import qualified Cardano.Ledger.Mary.Value as Mary
import qualified Cardano.Wallet.Read.Eras as E
import qualified Cardano.Wallet.Read.Hash as Hash
import qualified Cardano.Wallet.Read.Tx as Tx
import qualified Cardano.Wallet.Read.Tx.CBOR as CBOR
import qualified Cardano.Wallet.Read.Tx.Gen as Gen
import qualified Cardano.Wallet.Read.Tx.Gen.TxParameters as Parameters
import qualified Cardano.Wallet.Read.Tx as Id
import qualified Cardano.Wallet.Primitive.Types.Tx.TxMetadata as Metadata
import qualified Data.Aeson.Key as Key
import qualified Data.ByteArray as BA
import qualified Data.ByteArray.Encoding as Base
import qualified Data.ByteString.Lazy as BL
import qualified Data.Map.Strict as Map
import qualified Data.Foldable as Foldable
import qualified Data.Sequence.Strict as Sequence
import qualified Data.Set as Set
import qualified Data.Text as T
import qualified Data.Text.Encoding as T

hex :: BA.ByteArrayAccess a => a -> Text
hex = T.decodeUtf8 . Base.convertToBase Base.Base16
bytes :: Object -> Text -> Parser ByteString
bytes input field = do
    text <- input .: Key.fromText field
    either (const $ fail "invalid_input") pure $ Base.convertFromBase Base.Base16 (T.encodeUtf8 text)
present :: Maybe a -> Parser a
present = maybe (fail "invalid_input") pure

cborFor :: Text -> BL.ByteString -> Parser CBOR.TxCBOR
cborFor era raw = case era of
    "byron" -> pure $ E.EraValue (E.K raw :: E.K BL.ByteString E.Byron)
    "shelley" -> pure $ E.EraValue (E.K raw :: E.K BL.ByteString E.Shelley)
    "allegra" -> pure $ E.EraValue (E.K raw :: E.K BL.ByteString E.Allegra)
    "mary" -> pure $ E.EraValue (E.K raw :: E.K BL.ByteString E.Mary)
    "alonzo" -> pure $ E.EraValue (E.K raw :: E.K BL.ByteString E.Alonzo)
    "babbage" -> pure $ E.EraValue (E.K raw :: E.K BL.ByteString E.Babbage)
    "conway" -> pure $ E.EraValue (E.K raw :: E.K BL.ByteString E.Conway)
    "dijkstra" -> pure $ E.EraValue (E.K raw :: E.K BL.ByteString E.Dijkstra)
    _ -> fail "invalid_input"
fixtureFor :: Text -> Parameters.TxParameters -> Parser (E.EraValue Tx.Tx)
fixtureFor era parameters = case era of
    "byron" -> pure $ E.EraValue $ Gen.mkTxEra @E.Byron parameters
    "shelley" -> pure $ E.EraValue $ Gen.mkTxEra @E.Shelley parameters
    "allegra" -> pure $ E.EraValue $ Gen.mkTxEra @E.Allegra parameters
    "mary" -> pure $ E.EraValue $ Gen.mkTxEra @E.Mary parameters
    "alonzo" -> pure $ E.EraValue $ Gen.mkTxEra @E.Alonzo parameters
    "babbage" -> pure $ E.EraValue $ Gen.mkTxEra @E.Babbage parameters
    "conway" -> pure $ E.EraValue $ Gen.mkTxEra @E.Conway parameters
    "dijkstra" -> do
        -- Capture-only fixture: the pinned wallet generator throws a TODO.
        -- Use actual ledger constructors; the wallet decoder remains the oracle.
        outputs <- traverse (\(address,Parameters.Lovelace coin) -> do
            rawAddress <- case address of
                Parameters.ByronAddress raw -> pure raw
                Parameters.ShelleyAddress raw -> pure raw
            decoded <- present $ Ledger.decodeAddr rawAddress
            pure $ Core.mkBasicTxOut decoded (Mary.MaryValue (Coin.Coin coin) mempty)
            ) $ Foldable.toList $ Parameters.txOutputs parameters
        let inputs = Set.fromList [Tx.TxIn txid (Tx.TxIx $ fromIntegral index) | (Parameters.Index index,txid) <- Foldable.toList $ Parameters.txInputs parameters]
            body = (Core.mkBasicTxBody :: Core.TxBody Core.TopTx E.Dijkstra)
                & Ledger.inputsTxBodyL .~ inputs
                & Ledger.outputsTxBodyL .~ Sequence.fromList outputs
        pure $ E.EraValue (Tx.Tx $ Core.mkBasicTx body :: Tx.Tx E.Dijkstra)
    _ -> fail "invalid_input"
render :: E.EraValue Tx.Tx -> Value
render transaction = case CBOR.renderTxToCBOR transaction of
    E.EraValue (E.K encoded) -> case transaction of
        E.EraValue tx -> object ["cbor_hex" .= hex (BL.toStrict encoded),"transaction_id" .= hex (Hash.hashToBytes $ Id.hashFromTxId $ Id.getTxId tx)]

metadatum :: Int -> Value -> Parser Metadata.TxMetadataValue
metadatum depth = withObject "metadata value" $ \input -> do
    unless (depth <= 8) $ fail "invalid_input"
    kind <- input .: "type" :: Parser Text
    case kind of
        "number" -> Metadata.TxMetaNumber <$> input .: "value"
        "text" -> Metadata.TxMetaText <$> input .: "value"
        "bytes" -> Metadata.TxMetaBytes <$> bytes input "hex"
        "list" -> do
            items <- input .: "items"
            unless (length items <= 32) $ fail "invalid_input"
            Metadata.TxMetaList <$> traverse (metadatum $ depth + 1) items
        "map" -> do
            entries <- input .: "entries"
            unless (length entries <= 32) $ fail "invalid_input"
            Metadata.TxMetaMap <$> traverse (withObject "metadata pair" $ \pair -> (,) <$> (pair .: "key" >>= metadatum (depth + 1)) <*> (pair .: "value" >>= metadatum (depth + 1))) entries
        _ -> fail "invalid_input"
rangeError :: (Word64, Metadata.TxMetadataRangeError) -> Value
rangeError (label,err) = case err of
    Metadata.TxMetadataNumberOutOfRange n -> object ["label" .= label,"code" .= ("number_out_of_range" :: Text),"actual" .= n]
    Metadata.TxMetadataBytesTooLong n -> object ["label" .= label,"code" .= ("bytes_too_long" :: Text),"actual" .= n]
    Metadata.TxMetadataTextTooLong n -> object ["label" .= label,"code" .= ("text_too_long" :: Text),"actual" .= n]

run :: Text -> Value -> Parser Value
run operation = withObject "input" $ \input -> case operation of
    "fixture.transaction" -> do
        era <- input .: "era"
        rawAddress <- bytes input "address_hex"
        inputHash <- bytes input "input_txid_hex" >>= present . Hash.hashFromBytes
        index <- input .: "input_index" :: Parser Word64
        unless (index <= 65535) $ fail "invalid_input"
        coin <- input .: "output_coin" :: Parser Word64
        let parameters = Parameters.TxParameters ((Parameters.Index (fromIntegral index),Id.txIdFromHash inputHash) :| []) ((Parameters.ByronAddress rawAddress,Parameters.Lovelace $ fromIntegral coin) :| [])
        render <$> fixtureFor era parameters
    "transaction.roundtrip" -> do
        era <- input .: "era"
        raw <- bytes input "cbor_hex"
        encoded <- cborFor era $ BL.fromStrict raw
        case CBOR.parseTxFromCBOR encoded of
            Left _ -> fail "decode_failed"
            Right transaction -> pure $ render transaction
    "metadata.encode" -> do
        version <- input .: "ledger_version" :: Parser Word64
        ledgerVersion <- Binary.mkVersion version
        entries <- input .: "entries"
        unless (length entries <= 32) $ fail "invalid_input"
        pairs <- traverse (withObject "metadata entry" $ \entry -> (,) <$> entry .: "label" <*> (entry .: "value" >>= metadatum 0)) entries
        let metadata = Metadata.TxMetadata $ Map.fromList pairs
        case Metadata.validateTxMetadata metadata of
            Left errors -> pure $ object ["valid" .= False,"errors" .= map rangeError errors]
            Right () -> pure $ object ["valid" .= True,"cbor_hex" .= hex (Binary.serialize' ledgerVersion $ Metadata.toShelleyMetadata $ Metadata.unTxMetadata metadata)]
    "ledger.ed25519.verify" -> do
        public <- bytes input "public_key_hex"
        signature <- bytes input "signature_hex"
        message <- bytes input "message_hex"
        let valid = case (Fixed.rawDecodeFixedSized public :: Maybe (DSIGN.VerKeyDSIGN Ed.Ed25519DSIGN), Fixed.rawDecodeFixedSized signature :: Maybe (DSIGN.SigDSIGN Ed.Ed25519DSIGN)) of
                (Just key, Just signed) -> isRight $ DSIGN.verifyDSIGN () key message signed
                _ -> False
        pure $ object ["valid" .= valid]
    _ -> fail "invalid_input"

main :: IO ()
main = do
    sodiumInit
    raw <- BL.take 1048577 <$> BL.getContents
    unless (BL.length raw <= 1048576) exitFailure
    request <- either (const exitFailure) pure $ eitherDecode raw
    (ident, operation, input) <- either (const exitFailure) pure $ parseEither parseRequest request
    let envelope field value = object ["protocol_version" .= (1 :: Int),"id" .= ident,field .= value]
    BL.putStr $ encode $ case parseEither (run operation) input of
        Left message -> envelope "error" $ object ["code" .= (if "decode_failed" `T.isInfixOf` T.pack message then "decode_failed" else "invalid_input" :: Text)]
        Right value -> envelope "result" value
  where
    parseRequest = withObject "request" $ \value -> do
        version <- value .: "protocol_version" :: Parser Int
        unless (version == 1) $ fail "invalid protocol"
        (,,) <$> (value .: "id" :: Parser Text) <*> value .: "operation" <*> value .: "input"
