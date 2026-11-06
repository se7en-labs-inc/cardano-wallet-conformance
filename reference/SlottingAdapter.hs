{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedStrings #-}
module Main (main) where
import Prelude
import Cardano.Slotting.Slot (SlotNo(..))
import qualified Cardano.Wallet.Primitive.Slotting as S
import Cardano.Wallet.Primitive.Types.SlottingParameters (SlottingParameters(..), SlotLength(..), EpochLength(..), ActiveSlotCoefficient(..))
import Control.Monad (unless)
import Data.Aeson (Value, eitherDecode, encode, object, withObject, (.:), (.=))
import Data.Aeson.Types (Parser, parseEither)
import Data.Functor.Identity (runIdentity)
import Data.Quantity (Quantity(..))
import Data.Ratio ((%))
import Data.Text (Text)
import Data.Time (UTCTime(..), fromGregorian, addUTCTime, diffUTCTime)
import System.Exit (exitFailure)
import qualified Data.ByteString.Lazy as BL

run :: Text -> Value -> Parser Value
run operation = withObject "input" $ \input -> do
    unless (operation == "time.slot-boundary") $ fail "invalid_input"
    slot <- input .: "slot_length_picos" :: Parser Integer
    elapsed <- input .: "elapsed_picos" :: Parser Integer
    epoch <- input .: "epoch_length" :: Parser Integer
    unless (slot > 0 && slot <= 10^(15::Int) && elapsed >= 0 && elapsed <= 18446744073709551615 && epoch > 0 && epoch <= 4294967295) $ fail "invalid_input"
    unless (elapsed `div` slot < 18446744073709551615) $ fail "invalid_input"
    let startUTC = UTCTime (fromGregorian 2000 1 1) 0
        start = S.StartTime startUTC
        params = SlottingParameters (SlotLength $ fromRational $ slot % 10^(12::Int)) (EpochLength $ fromInteger epoch) (ActiveSlotCoefficient 1) (Quantity 1)
        interpreter = S.mkSingleEraInterpreter start params
        utc = addUTCTime (fromRational $ elapsed % 10^(12::Int)) startUTC
    relative <- maybe (fail "invalid_input") pure $ S.toRelativeTime start utc
    let SlotNo floorSlot = runIdentity $ S.interpretQuery interpreter $ S.ongoingSlotAt relative
        SlotNo ceilingSlot = runIdentity $ S.interpretQuery interpreter $ S.ceilingSlotAt relative
        floorUTC = runIdentity $ S.interpretQuery interpreter $ S.slotToUTCTime $ SlotNo floorSlot
        floorPicos = round (toRational (diffUTCTime floorUTC startUTC) * 10^(12::Int)) :: Integer
    pure $ object ["floor_slot" .= floorSlot,"ceiling_slot" .= ceilingSlot,"floor_time_picos" .= floorPicos]
main :: IO ()
main = do
    raw <- BL.take 1048577 <$> BL.getContents
    unless (BL.length raw <= 1048576) exitFailure
    request <- either (const exitFailure) pure $ eitherDecode raw
    (ident,operation,input) <- either (const exitFailure) pure $ parseEither parseRequest request
    let envelope field value = object ["protocol_version" .= (1::Int),"id" .= ident,field .= value]
    BL.putStr $ encode $ case parseEither (run operation) input of
        Left _ -> envelope "error" $ object ["code" .= ("invalid_input"::Text)]
        Right value -> envelope "result" value
  where
    parseRequest = withObject "request" $ \value -> do
        version <- value .: "protocol_version" :: Parser Int
        unless (version == 1) $ fail "invalid_input"
        (,,) <$> (value .: "id" :: Parser Text) <*> value .: "operation" <*> value .: "input"
