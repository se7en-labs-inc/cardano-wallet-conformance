{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}
module Main (main) where
import Prelude
import Cardano.Crypto.Libsodium (sodiumInit)
import Control.Lens ((&), (.~), (^.))
import Control.Monad (unless)
import Data.Aeson (Value, Object, eitherDecode, encode, object, withObject, (.:), (.=))
import Data.Aeson.Types (Parser, parseEither)
import Data.Text (Text)
import Data.Word (Word64)
import System.Exit (exitFailure)
import qualified Cardano.Balance.Tx.Sign as Sign
import qualified Cardano.Balance.Tx.SizeEstimation as Size
import qualified Cardano.Balance.Tx.Primitive as Primitive
import qualified Cardano.Ledger.Api as Ledger
import qualified Cardano.Ledger.BaseTypes as Base
import qualified Cardano.Ledger.Binary as Binary
import qualified Cardano.Ledger.Core as Core
import qualified Cardano.Read.Ledger.Tx.CBOR as CBOR
import qualified Cardano.Wallet.Read.Eras as Read
import qualified Cardano.Wallet.Read.Hash as Hash
import qualified Cardano.Wallet.Read.Tx as Read
import qualified Data.ByteArray.Encoding as Hex
import qualified Data.ByteString.Lazy as BL
import qualified Data.Text as T
import qualified Data.Text.Encoding as T

run :: Object -> Parser Value
run input = do
    encoded <- input .: "transaction_cbor_hex"
    raw <- either (const $ fail "invalid_input") pure $ Hex.convertFromBase Hex.Base16 $ T.encodeUtf8 encoded
    parsed <- either (const $ fail "decode_failed") pure
        (CBOR.deserializeTx $ BL.fromStrict raw :: Either Binary.DecoderError (Read.Tx Read.Conway))
    keys <- input .: "vkey_witnesses" :: Parser Word64
    boots <- input .: "bootstrap_witnesses" :: Parser Word64
    maximumSize <- input .: "maximum_transaction_bytes" :: Parser Word64
    major <- input .: "protocol_major" :: Parser Word64
    unless (keys <= 65536 && boots <= 65536 && maximumSize <= 4294967295 && major >= 9 && major <= 12) $
        fail "invalid_input"
    version <- Binary.mkVersion major
    let pp = (Core.emptyPParams :: Ledger.PParams Read.Conway)
            & Ledger.ppProtocolVersionL .~ Base.ProtVer version 0
            & Ledger.ppMaxTxSizeL .~ fromIntegral maximumSize
        tx = Read.unTx parsed
        Primitive.TxSize estimated = Sign.estimateSignedTxSize pp
            (Sign.KeyWitnessCounts (fromIntegral keys) (fromIntegral boots)) tx
        Primitive.TxSize bootstrapBytes = Size.sizeOf_BootstrapWitnesses $ fromIntegral boots
    pure $ object
        [ "estimated_bytes" .= estimated
        , "original_ledger_bytes" .= (tx ^. Ledger.sizeTxF)
        , "bootstrap_bytes" .= bootstrapBytes
        , "within_size_limit" .= (estimated <= fromIntegral (pp ^. Ledger.ppMaxTxSizeL))
        , "transaction_id" .= (T.decodeUtf8 $ Hex.convertToBase Hex.Base16 $ Hash.hashToBytes $ Read.hashFromTxId $ Read.getTxId parsed)
        ]
main :: IO ()
main = do
    sodiumInit
    raw <- BL.take 1048577 <$> BL.getContents
    unless (BL.length raw <= 1048576) exitFailure
    request <- either (const exitFailure) pure $ eitherDecode raw
    (ident,operation,input) <- either (const exitFailure) pure $ parseEither parseRequest request
    let envelope field value = object ["protocol_version" .= (1 :: Int),"id" .= ident,field .= value]
    BL.putStr $ encode $ case parseEither (withObject "input" $ \value ->
            if operation == "transaction.size-estimate" then run value else fail "invalid_input") input of
        Left message -> envelope "error" $ object ["code" .=
            (if "decode_failed" `T.isInfixOf` T.pack message then "decode_failed" else "invalid_input" :: Text)]
        Right value -> envelope "result" value
  where
    parseRequest = withObject "request" $ \value -> do
        version <- value .: "protocol_version" :: Parser Int
        unless (version == 1) $ fail "invalid_input"
        (,,) <$> (value .: "id" :: Parser Text) <*> (value .: "operation" :: Parser Text) <*> value .: "input"
