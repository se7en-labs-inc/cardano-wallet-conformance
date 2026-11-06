{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}
module Main (main) where
import Prelude
import Control.Lens ((&), (.~), (^.))
import Control.Monad (unless)
import Data.Aeson (Value, Object, eitherDecode, encode, object, withObject, (.:), (.=))
import Data.Aeson.Types (Parser, parseEither)
import Data.ByteString (ByteString)
import Data.Ratio ((%))
import Data.Text (Text)
import Data.Word (Word64)
import System.Exit (exitFailure)
import qualified Cardano.Balance.Tx.Tx as Balance
import qualified Cardano.Balance.Tx.SizeEstimation as Size
import qualified Cardano.Balance.Tx.Primitive as Primitive
import qualified Cardano.Ledger.Api as Ledger
import qualified Cardano.Ledger.BaseTypes as Base
import qualified Cardano.Ledger.Binary as Binary
import qualified Cardano.Ledger.Compactible as Compact
import qualified Cardano.Ledger.Conway as Conway
import qualified Cardano.Ledger.Core as Core
import qualified Cardano.Ledger.Plutus.ExUnits as Ex
import qualified Data.ByteArray.Encoding as Hex
import qualified Data.ByteString.Lazy as BL
import qualified Data.Text as T
import qualified Data.Text.Encoding as T

bytes :: Object -> Parser ByteString
bytes input = do
    raw <- input .: "output_cbor_hex"
    either (const $ fail "invalid_input") pure $ Hex.convertFromBase Hex.Base16 (T.encodeUtf8 raw)
hex :: ByteString -> Text
hex = T.decodeUtf8 . Hex.convertToBase Hex.Base16
price :: Value -> Parser Base.NonNegativeInterval
price = withObject "price" $ \input -> do
    numerator <- input .: "numerator" :: Parser Word64
    denominator <- input .: "denominator" :: Parser Word64
    unless (denominator > 0) $ fail "invalid_input"
    maybe (fail "invalid_input") pure $ Base.boundRational (toInteger numerator % toInteger denominator)
coinPerByte :: Word64 -> Parser Ledger.CoinPerByte
coinPerByte n = maybe (fail "invalid_input") (pure . Ledger.CoinPerByte) $ Compact.toCompact $ Balance.Coin $ toInteger n
run :: Text -> Value -> Parser Value
run operation = withObject "input" $ \input -> case operation of
    "fee.components" -> do
        size <- input .: "transaction_bytes" :: Parser Word64
        vkeys <- input .: "vkey_witnesses" :: Parser Word64
        boots <- input .: "bootstrap_witnesses" :: Parser Word64
        coefficient <- input .: "coefficient" :: Parser Word64
        constant <- input .: "constant" :: Parser Word64
        maximumSize <- input .: "maximum_transaction_bytes" :: Parser Word64
        unless (maximumSize <= 4294967295 && vkeys <= 65536 && boots <= 65536) $ fail "invalid_input"
        memory <- input .: "execution_memory" :: Parser Word64
        steps <- input .: "execution_steps" :: Parser Word64
        memoryPrice <- input .: "memory_price" >>= price
        stepPrice <- input .: "step_price" >>= price
        let pp = (Core.emptyPParams :: Ledger.PParams Conway.ConwayEra)
                & Ledger.ppPricesL .~ Ex.Prices memoryPrice stepPrice
                & Ledger.ppMaxTxExUnitsL .~ Ex.ExUnits (fromIntegral memory) (fromIntegral steps)
                & Ledger.ppMaxTxSizeL .~ fromIntegral maximumSize
            Primitive.TxSize vkeyBytes = Size.sizeOf_VKeyWitnesses $ fromIntegral vkeys
            Primitive.TxSize bootstrapBytes = Size.sizeOf_BootstrapWitnesses $ fromIntegral boots
            estimated = fromIntegral size + vkeyBytes + bootstrapBytes
            Balance.Coin linear = Balance.feeOfBytes (Balance.FeePerByte $ fromIntegral coefficient) estimated
            Balance.Coin execution = Balance.maxScriptExecutionCost pp
        pure $ object ["vkey_witness_bytes" .= vkeyBytes,"bootstrap_witness_bytes" .= bootstrapBytes,"estimated_bytes" .= estimated,"linear_fee" .= linear,"execution_fee" .= execution,"total_fee" .= (toInteger constant + linear + execution),"within_size_limit" .= (estimated <= fromIntegral (pp ^. Ledger.ppMaxTxSizeL))]
    "minimum-utxo" -> do
        raw <- bytes input
        cost <- input .: "coins_per_byte" >>= coinPerByte
        out <- either (const $ fail "decode_failed") pure $ Binary.decodeFull' (Ledger.eraProtVerLow @Conway.ConwayEra) raw
        let pp = (Core.emptyPParams :: Ledger.PParams Conway.ConwayEra) & Ledger.ppCoinsPerUTxOByteL .~ cost
            actual = out :: Ledger.TxOut Conway.ConwayEra
            conservative = actual & Ledger.coinTxOutL .~ Balance.Coin 45000000000000000
            Balance.Coin minimumCoin = Ledger.getMinCoinTxOut pp actual
            Balance.Coin walletMinimum = Balance.computeMinimumCoinForTxOut pp actual
            encodeOut = hex . Binary.serialize' (Ledger.eraProtVerLow @Conway.ConwayEra)
        pure $ object ["minimum_coin" .= minimumCoin,"wallet_minimum_coin" .= walletMinimum,"below_minimum" .= Balance.isBelowMinimumCoinForTxOut pp actual,"output_cbor_hex" .= encodeOut actual,"wallet_output_cbor_hex" .= encodeOut conservative]
    _ -> fail "invalid_input"
main :: IO ()
main = do
    raw <- BL.take 1048577 <$> BL.getContents
    unless (BL.length raw <= 1048576) exitFailure
    request <- either (const exitFailure) pure $ eitherDecode raw
    (ident,operation,input) <- either (const exitFailure) pure $ parseEither parseRequest request
    let envelope field value = object ["protocol_version" .= (1 :: Int),"id" .= ident,field .= value]
    BL.putStr $ encode $ case parseEither (run operation) input of
        Left message -> envelope "error" $ object ["code" .= (if "decode_failed" `T.isInfixOf` T.pack message then "decode_failed" else "invalid_input" :: Text)]
        Right value -> envelope "result" value
  where
    parseRequest = withObject "request" $ \value -> do
        version <- value .: "protocol_version" :: Parser Int
        unless (version == 1) $ fail "invalid_input"
        (,,) <$> (value .: "id" :: Parser Text) <*> value .: "operation" <*> value .: "input"
