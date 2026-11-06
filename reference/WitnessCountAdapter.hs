{-# LANGUAGE OverloadedStrings #-}
module Main (main) where
import Prelude
import Cardano.Crypto.Libsodium (sodiumInit)
import Control.Lens ((^.), to)
import Control.Monad (unless)
import Data.Aeson (Value, eitherDecode, encode, object, withObject, (.:), (.=))
import Data.Aeson.Types (Parser, parseEither)
import Data.Text (Text)
import System.Exit (exitFailure)
import qualified Cardano.Balance.Tx.Sign as Sign
import qualified Cardano.Balance.Tx.Tx as Balance
import qualified Cardano.Ledger.Api as Ledger
import qualified Cardano.Ledger.Binary as Binary
import qualified Cardano.Read.Ledger.Tx.CBOR as CBOR
import qualified Cardano.Wallet.Read.Eras as Read
import qualified Cardano.Wallet.Read.Tx as Read
import qualified Data.ByteArray.Encoding as Hex
import qualified Data.ByteString.Lazy as BL
import qualified Data.Foldable as F
import qualified Data.Map.Strict as Map
import qualified Data.Text.Encoding as T

run :: Value -> Parser Value
run = withObject "input" $ \input -> do
    encoded <- input .: "transaction_cbor_hex"
    raw <- either (const $ fail "invalid_input") pure $ Hex.convertFromBase Hex.Base16 $ T.encodeUtf8 encoded
    parsed <- either (const $ fail "decode_failed") pure
        (CBOR.deserializeTx $ BL.fromStrict raw :: Either Binary.DecoderError (Read.Tx Read.Conway))
    let tx = Read.unTx parsed
        body = tx ^. Ledger.bodyTxL
        inputs = body ^. Ledger.inputsTxBodyL
        outputs = body ^. Ledger.outputsTxBodyL . to F.toList
    output <- case outputs of
        first:_ -> pure first
        [] -> fail "invalid_input"
    let utxo = Balance.UTxO $ Map.fromSet (const output) inputs
        counts = Sign.estimateKeyWitnessCounts utxo tx mempty
    pure $ object ["vkey_witnesses" .= Sign.nKeyWits counts,
        "bootstrap_witnesses" .= Sign.nBootstrapWits counts]
main :: IO ()
main = do
    sodiumInit
    raw <- BL.take 1048577 <$> BL.getContents
    unless (BL.length raw <= 1048576) exitFailure
    request <- either (const exitFailure) pure $ eitherDecode raw
    (ident,operation,input) <- either (const exitFailure) pure $ parseEither
        (withObject "request" $ \value -> do
            version <- value .: "protocol_version" :: Parser Int
            unless (version == 1) $ fail "invalid_input"
            (,,) <$> (value .: "id" :: Parser Text) <*> (value .: "operation" :: Parser Text) <*> value .: "input") request
    unless (operation == "transaction.input-witness-count") exitFailure
    let envelope field value = object ["protocol_version" .= (1 :: Int), "id" .= ident, field .= value]
    BL.putStr $ encode $ case parseEither run input of
        Left _ -> envelope "error" $ object ["code" .= ("invalid_input" :: Text)]
        Right value -> envelope "result" value
