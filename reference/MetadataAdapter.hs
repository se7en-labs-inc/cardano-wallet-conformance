{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}
module Main (main) where
import Prelude
import Control.Exception (ErrorCall, displayException, evaluate, try)
import Control.Monad (unless)
import Data.Aeson (Value, Object, eitherDecode, encode, object, withObject, (.:), (.=))
import Data.Aeson.Types (Parser, parseEither)
import Data.Text (Text)
import System.Exit (exitFailure)
import qualified Cardano.Wallet.Primitive.Types.Tx.TxMetadata as M
import qualified Cardano.Wallet.Primitive.Types.MetadataEncryption as C
import qualified Data.Aeson.Key as K
import qualified Data.ByteArray.Encoding as H
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
import qualified Data.Map.Strict as Map
import qualified Data.Text as T
import qualified Data.Text.Encoding as T

bytes :: Object -> Text -> Parser B.ByteString
bytes o key = do
    raw <- o .: K.fromText key
    either (const $ fail "invalid_input") pure $ H.convertFromBase H.Base16 (T.encodeUtf8 raw)
value :: Int -> Value -> Parser M.TxMetadataValue
value depth = withObject "metadatum" $ \o -> do
    unless (depth <= 8) $ fail "invalid_input"
    kind <- o .: "type" :: Parser Text
    case kind of
        "number" -> M.TxMetaNumber <$> o .: "value"
        "text" -> M.TxMetaText <$> o .: "value"
        "bytes" -> M.TxMetaBytes <$> bytes o "hex"
        "list" -> do
            xs <- o .: "items"
            unless (length xs <= 32) $ fail "invalid_input"
            M.TxMetaList <$> traverse (value $ depth+1) xs
        "map" -> do
            xs <- o .: "entries"
            unless (length xs <= 32) $ fail "invalid_input"
            M.TxMetaMap <$> traverse (withObject "pair" $ \p -> (,) <$> (p .: "key" >>= value (depth+1)) <*> (p .: "value" >>= value (depth+1))) xs
        _ -> fail "invalid_input"
render :: M.TxMetadataValue -> Value
render v = case v of
    M.TxMetaNumber n -> object ["type" .= ("number"::Text), "value" .= n]
    M.TxMetaText t -> object ["type" .= ("text"::Text), "value" .= t]
    M.TxMetaBytes b -> object ["type" .= ("bytes"::Text), "hex" .= T.decodeUtf8 (H.convertToBase H.Base16 b)]
    M.TxMetaList xs -> object ["type" .= ("list"::Text), "items" .= map render xs]
    M.TxMetaMap xs -> object ["type" .= ("map"::Text), "entries" .= map (\(k,x) -> object ["key" .= render k,"value" .= render x]) xs]
run :: Text -> Value -> Parser (Either Value Value)
run operation = withObject "input" $ \o -> do
    pwd <- bytes o "passphrase_hex"
    entries <- o .: "entries"
    unless (length entries <= 32) $ fail "invalid_input"
    pairs <- traverse (withObject "entry" $ \e -> (,) <$> e .: "label" <*> (e .: "value" >>= value 0)) entries
    unless (Map.size (Map.fromList pairs) == length pairs) $ fail "invalid_input"
    let metadata = M.TxMetadata $ Map.fromList pairs
        rendered (M.TxMetadata m) = object ["entries" .= map (\(label,x) -> object ["label" .= label,"value" .= render x]) (Map.toAscList m)]
    either (const $ fail "invalid_input") pure $ M.validateTxMetadata metadata
    case operation of
        "metadata.encrypt" -> do
            salt <- bytes o "salt_hex"
            unless (B.length salt == 8) $ fail "invalid_input"
            pure $ either (Left . object . pure . ("code" .=) . show) (Right . rendered) $ C.toMetadataEncrypted pwd metadata (Just salt)
        "metadata.decrypt" -> pure $ either (Left . object . pure . ("code" .=) . show) (Right . rendered) $ C.fromMetadataEncrypted pwd metadata
        _ -> fail "invalid_input"
main :: IO ()
main = do
    raw <- BL.take 1048577 <$> BL.getContents
    unless (BL.length raw <= 1048576) exitFailure
    request <- either (const exitFailure) pure $ eitherDecode raw
    (ident,operation,input) <- either (const exitFailure) pure $ parseEither parseRequest request
    let envelope field x = object ["protocol_version" .= (1::Int),"id" .= ident,field .= x]
        response = case parseEither (run operation) input of
            Left _ -> envelope "error" $ object ["code" .= ("invalid_input"::Text)]
            Right (Left e) -> envelope "error" e
            Right (Right x) -> envelope "result" x
        encoded = encode response
    forced <- try @ErrorCall $ evaluate $ BL.length encoded
    case forced of
        Right _ -> BL.putStr encoded
        Left err -> do
            let message = T.takeWhile (/= '\n') $ T.pack $ displayException err
            unless (operation == "metadata.decrypt" && message == "we have checked already in composePayload that there is enough elements in decrypedList") exitFailure
            BL.putStr $ encode $ envelope "error" $ object ["code" .= ("haskell_error_call"::Text),"class" .= ("ErrorCall"::Text),"message" .= message]
  where
    parseRequest = withObject "request" $ \o -> do
        version <- o .: "protocol_version" :: Parser Int
        unless (version == 1) $ fail "invalid_input"
        (,,) <$> (o .: "id" :: Parser Text) <*> o .: "operation" <*> o .: "input"
