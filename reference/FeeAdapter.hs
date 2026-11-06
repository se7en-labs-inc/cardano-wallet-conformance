{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}
module Main (main) where
import Prelude
import Cardano.Crypto.Libsodium (sodiumInit)
import Control.Lens ((&), (.~), (^.))
import Control.Monad (unless)
import Data.Aeson (Value, Object, eitherDecode, encode, object, withObject, (.:), (.=))
import Data.Aeson.Types (Parser, parseEither)
import Data.ByteString (ByteString)
import Data.Ratio ((%), numerator, denominator)
import Data.Text (Text)
import Data.Word (Word32, Word64)
import System.Exit (exitFailure)
import qualified Cardano.Ledger.Api as Ledger
import qualified Cardano.Ledger.Alonzo.TxWits as Witnesses
import qualified Cardano.Ledger.BaseTypes as Base
import qualified Cardano.Ledger.Binary as Binary
import qualified Cardano.Ledger.Coin as Coin
import qualified Cardano.Ledger.Compactible as Compact
import qualified Cardano.Ledger.Conway.PParams as Parameters
import qualified Cardano.Ledger.Conway.Scripts as Purpose
import qualified Cardano.Ledger.Conway.Tx as Conway
import qualified Cardano.Ledger.Core as Core
import qualified Cardano.Ledger.Plutus.Data as Data
import qualified Cardano.Ledger.Plutus.ExUnits as Ex
import qualified Cardano.Read.Ledger.Tx.CBOR as CBOR
import qualified Cardano.Wallet.Read.Eras as Read
import qualified Cardano.Wallet.Read.Tx as Read
import qualified PlutusLedgerApi.V1 as Plutus
import qualified Data.ByteArray.Encoding as Hex
import qualified Data.ByteString.Lazy as BL
import qualified Data.Map.Strict as Map
import qualified Data.Text as T
import qualified Data.Text.Encoding as T

hex :: ByteString -> Text
hex = T.decodeUtf8 . Hex.convertToBase Hex.Base16
price :: Value -> Parser Base.NonNegativeInterval
price = withObject "price" $ \input -> do
    n <- input .: "numerator" :: Parser Word64
    d <- input .: "denominator" :: Parser Word64
    unless (d > 0) $ fail "invalid_input"
    maybe (fail "invalid_input") pure $ Base.boundRational $ toInteger n % toInteger d
run :: Object -> Parser Value
run input = do
    encoded <- input .: "transaction_cbor_hex"
    raw <- either (const $ fail "invalid_input") pure $ Hex.convertFromBase Hex.Base16 $ T.encodeUtf8 encoded
    parsed <- either (const $ fail "decode_failed") pure (CBOR.deserializeTx $ BL.fromStrict raw :: Either Binary.DecoderError (Read.Tx Read.Conway))
    coefficient <- input .: "coefficient" :: Parser Word64
    constant <- input .: "constant" :: Parser Word64
    compact <- maybe (fail "invalid_input") pure $ Compact.toCompact $ Coin.Coin $ toInteger coefficient
    memoryPrice <- input .: "memory_price" >>= price
    stepPrice <- input .: "step_price" >>= price
    referencePrice <- input .: "reference_script_price" >>= price
    referenceBytes <- input .: "reference_script_bytes" :: Parser Word64
    unless (referenceBytes <= 200000) $ fail "invalid_input"
    units <- input .: "execution_units" >>= traverse (withObject "execution units" $ \u -> do
        memory <- u .: "memory" :: Parser Word64
        steps <- u .: "steps" :: Parser Word64
        pure $ Ex.ExUnits (fromIntegral memory) (fromIntegral steps))
    unless (length units <= 16) $ fail "invalid_input"
    let prices = Ex.Prices memoryPrice stepPrice
        pp = (Core.emptyPParams :: Ledger.PParams Read.Conway)
            & Ledger.ppTxFeePerByteL .~ Ledger.CoinPerByte compact
            & Ledger.ppTxFeeFixedL .~ Coin.Coin (toInteger constant)
            & Ledger.ppPricesL .~ prices
            & Ledger.ppProtocolVersionL .~ Base.ProtVer (Ledger.eraProtVerLow @Read.Conway) 0
            & Parameters.ppMinFeeRefScriptCostPerByteL .~ referencePrice
        original = Read.unTx parsed
        redeemers = Witnesses.Redeemers $ Map.fromList
            [(Purpose.ConwaySpending $ Ledger.AsIx index,(Data.Data $ Plutus.I 0,ex)) | (index,ex) <- zip [0 :: Word32 ..] units]
        tx = if null units then original else original & Ledger.witsTxL . Ledger.rdmrsTxWitsL .~ redeemers
        Coin.Coin minimumFee = Ledger.getMinFeeTx pp tx $ fromIntegral referenceBytes
        actualUnits = foldMap snd $ Ledger.unRedeemers $ tx ^. Ledger.witsTxL . Ledger.rdmrsTxWitsL
        Coin.Coin executionFee = Ex.txscriptfee prices actualUnits
        stride = Base.unNonZero $ pp ^. Parameters.ppRefScriptCostStrideG
        multiplier = Base.unboundRational $ pp ^. Parameters.ppRefScriptCostMultiplierG
        Coin.Coin referenceFee = Conway.tierRefScriptFee multiplier (fromIntegral stride) (Base.unboundRational referencePrice) $ fromIntegral referenceBytes
    pure $ object
        [ "minimum_fee" .= minimumFee
        , "execution_fee" .= executionFee
        , "reference_script_fee" .= referenceFee
        , "ledger_size" .= (tx ^. Ledger.sizeTxF)
        , "transaction_cbor_hex" .= hex (BL.toStrict $ CBOR.serializeTx (Read.Tx tx :: Read.Tx Read.Conway))
        , "reference_stride" .= stride
        , "reference_multiplier" .= object ["numerator" .= numerator multiplier,"denominator" .= denominator multiplier]
        ]
main :: IO ()
main = do
    sodiumInit
    raw <- BL.take 1048577 <$> BL.getContents
    unless (BL.length raw <= 1048576) exitFailure
    request <- either (const exitFailure) pure $ eitherDecode raw
    (ident,operation,input) <- either (const exitFailure) pure $ parseEither parseRequest request
    let envelope field value = object ["protocol_version" .= (1 :: Int),"id" .= ident,field .= value]
    BL.putStr $ encode $ case parseEither (withObject "input" $ \value -> if operation == "transaction.minimum-fee" then run value else fail "invalid_input") input of
        Left message -> envelope "error" $ object ["code" .= (if "decode_failed" `T.isInfixOf` T.pack message then "decode_failed" else "invalid_input" :: Text)]
        Right value -> envelope "result" value
  where
    parseRequest = withObject "request" $ \value -> do
        version <- value .: "protocol_version" :: Parser Int
        unless (version == 1) $ fail "invalid_input"
        (,,) <$> (value .: "id" :: Parser Text) <*> (value .: "operation" :: Parser Text) <*> value .: "input"
