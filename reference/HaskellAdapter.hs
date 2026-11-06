{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PackageImports #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE DuplicateRecordFields #-}

-- Thin development oracle. Calls Haskell libraries; never imports Rust/Pallas
-- or manufactures expected answers. Build/runtime provenance is recorded separately.
module Main (main) where

import Prelude
import Control.Exception (SomeException, evaluate, try)
import Control.Monad (foldM, forM, unless)
import Control.Monad.Random.Strict (evalRand)
import "cryptonite" Crypto.Error (CryptoFailable (..))
import "cryptonite" Crypto.Hash (Digest, hash)
import "cryptonite" Crypto.Hash.Algorithms (Blake2b_160, Blake2b_224, Blake2b_256, Blake2b_512, SHA256, SHA512)
import Data.Aeson (Key, Object, Value (..), eitherDecode, encode, object, withObject, (.:), (.:?), (.!=), (.=))
import Data.Aeson.Types (Parser, parseEither)
import Data.ByteString (ByteString)
import Data.Either (isRight)
import Data.List (isSuffixOf)
import Data.Text (Text)
import Data.Word (Word32, Word64)
import Data.Bits (finiteBitSize)
import System.Random (mkStdGen)
import GHC.Records (getField)
import System.Exit (exitFailure)
import qualified Cardano.Wallet.Primitive.Passphrase as P
import qualified Cardano.Wallet.Primitive.Passphrase.Current as Current
import qualified Cardano.Crypto.Wallet as CC
import Cardano.Crypto.Libsodium (sodiumInit)
import qualified Cardano.Crypto.WalletHD.Encrypted as Encrypted
import Cardano.CoinSelection.Context (SelectionContext (..))
import Cardano.CoinSelection.Size (TokenBundleSizeAssessor (..), TokenBundleSizeAssessment (..))
import Cardano.CoinSelection.Types.AssetId (AssetId (..))
import Cardano.CoinSelection.Types.AssetName (AssetName (..))
import Cardano.CoinSelection.Types.Coin (Coin (..))
import Cardano.CoinSelection.Types.Hash (Hash (..))
import Cardano.CoinSelection.Types.TokenPolicyId (TokenPolicyId (..))
import Cardano.CoinSelection.Types.TokenQuantity (TokenQuantity (..))
import qualified Cardano.CoinSelection.Balance as Balance
import qualified Cardano.CoinSelection.Types.TokenBundle as TB
import qualified Cardano.CoinSelection.UTxOIndex as Index
import qualified Cardano.CoinSelection.UTxOSelection as Selection
import qualified "cryptonite" Crypto.PubKey.Ed25519 as Ed
import qualified Data.ByteArray as BA
import qualified Data.ByteArray.Encoding as Base
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString as BS
import qualified Data.List.NonEmpty as NE
import qualified Data.Map.Strict as Map
import qualified Data.Set as Set
import qualified Data.Text as Text
import qualified Data.Text.Encoding as T

hex :: BA.ByteArrayAccess a => a -> Text
hex value = T.decodeUtf8 (Base.convertToBase Base.Base16 value :: ByteString)

bytes :: Object -> Key -> Parser ByteString
bytes input key = do
    text <- input .: key
    either (const $ fail "invalid_input") pure
        (Base.convertFromBase Base.Base16 (T.encodeUtf8 text))

crypto :: CryptoFailable a -> Parser a
crypto (CryptoPassed value) = pure value
crypto (CryptoFailed _) = fail "invalid_input"

run :: Text -> Value -> Parser Value
run operation = withObject "input" $ \input -> case operation of
    "sha256" -> do
        message <- bytes input "message_hex"
        pure $ object ["hex" .= hex (hash message :: Digest SHA256)]
    "sha512" -> do
        message <- bytes input "message_hex"
        pure $ object ["hex" .= hex (hash message :: Digest SHA512)]
    "blake2b" -> do
        message <- bytes input "message_hex"
        lengthBytes <- input .: "output_bytes" :: Parser Int
        digest <- case lengthBytes of
            20 -> pure $ hex (hash message :: Digest Blake2b_160)
            28 -> pure $ hex (hash message :: Digest Blake2b_224)
            32 -> pure $ hex (hash message :: Digest Blake2b_256)
            64 -> pure $ hex (hash message :: Digest Blake2b_512)
            n | n > 0 && n <= 64 -> fail "unsupported_operation"
            _ -> fail "invalid_input"
        pure $ object ["hex" .= digest]
    "ed25519.sign" -> do
        secret <- bytes input "seed_hex" >>= crypto . Ed.secretKey
        message <- bytes input "message_hex"
        let public = Ed.toPublic secret
        pure $ object ["public_key_hex" .= hex public, "signature_hex" .= hex (Ed.sign secret public message)]
    "ed25519.verify" -> do
        public <- bytes input "public_key_hex" >>= crypto . Ed.publicKey
        signature <- bytes input "signature_hex" >>= crypto . Ed.signature
        message <- bytes input "message_hex"
        pure $ object ["valid" .= Ed.verify public message signature]
    "keys.verify-extended" -> do
        public <- bytes input "xpub_hex" >>= either (const $ fail "invalid_input") pure . CC.xpub
        signature <- bytes input "signature_hex" >>= either (const $ fail "invalid_input") pure . CC.xsignature
        message <- bytes input "message_hex"
        pure $ object ["valid" .= CC.verify public message signature]
    "passphrase.hash-pbkdf2" -> do
        passphrase <- input .: "passphrase_utf8"
        salt <- bytes input "salt_hex"
        let encrypted = Current.encryptPassphrase
                (P.Passphrase $ BA.convert $ T.encodeUtf8 passphrase)
                (P.Passphrase @"salt" $ BA.convert salt)
        pure $ object ["hash_hex" .= hex encrypted]
    "passphrase.check-pbkdf2" -> checkPassphrase P.EncryptWithPBKDF2 input
    "passphrase.check-scrypt" -> checkPassphrase P.EncryptWithScrypt input
    _ -> fail "unsupported_operation"

checkPassphrase :: P.PassphraseScheme -> Object -> Parser Value
checkPassphrase scheme input = do
    passphrase <- input .: "passphrase_utf8"
    stored <- bytes input "hash_hex"
    let valid = isRight $ P.checkPassphrase scheme
            (P.Passphrase $ BA.convert $ T.encodeUtf8 passphrase)
            (P.PassphraseHash $ BA.convert stored)
    pure $ object ["valid" .= valid]

request :: Value -> Parser (Value, Text, Value)
request = withObject "request" $ \value -> do
    version <- value .: "protocol_version" :: Parser Int
    unless (version == 1) $ fail "unsupported protocol version"
    (,,) <$> value .: "id" <*> value .: "operation" <*> value .: "input"

dispatch :: Text -> Value -> Parser (Either Value Value)
dispatch "coin-selection.select" = select True
dispatch "coin-selection.haskell" = select False
dispatch operation = fmap Right . run operation

dispatchIO :: Text -> Value -> Parser (IO (Either Value Value))
dispatchIO operation
    | "root-key." `Text.isPrefixOf` operation = encryptedRoot operation
    | otherwise = fmap pure . dispatch operation

rootFailure :: Encrypted.XPrvError -> Value
rootFailure err = object ["code" .= show err]

renderRoot :: Encrypted.EncryptedKey -> Value
renderRoot key = object
    [ "format" .= (case Encrypted.encryptedKeyFormat key of
        Encrypted.LegacyV1 -> "v1" :: Text
        Encrypted.EnvelopeV2 -> "v2")
    , "key_hex" .= hex (Encrypted.unEncryptedKey key)
    , "xpub_hex" .= rootPublic key
    ]

rootPublic :: Encrypted.EncryptedKey -> Text
rootPublic key = hex $ Encrypted.publicKeyByteString (Encrypted.encryptedPublic key)
    <> Encrypted.chainCodeByteString (Encrypted.encryptedChainCode key)

counterRandomness :: Object -> Parser ()
counterRandomness input = do
    profile <- input .: "randomness" :: Parser Text
    unless (profile == "counter-v1") $ fail "invalid_input"

encryptedRoot :: Text -> Value -> Parser (IO (Either Value Value))
encryptedRoot operation = withObject "encrypted root" $ \input -> do
    if operation == "root-key.create-v2" then do
        master <- bytes input "master_key_hex"
        passphrase <- bytes input "passphrase_hex"
        counterRandomness input
        pure $ Encrypted.withDeterministicRandomnessForTesting $
            fmap (either (Left . rootFailure) (Right . renderRoot)) $
                Encrypted.encryptedCreateDirectWithTweak master passphrase
    else do
        rawKey <- bytes input "key_hex"
        case Encrypted.mkEncryptedKey rawKey of
            Left err -> pure $ pure $ Left $ rootFailure err
            Right key -> case operation of
                "root-key.parse" -> pure $ pure $ Right $ object
                    [ "format" .= (case Encrypted.encryptedKeyFormat key of
                        Encrypted.LegacyV1 -> "v1" :: Text
                        Encrypted.EnvelopeV2 -> "v2")
                    , "xpub_hex" .= rootPublic key
                    ]
                "root-key.check-v2" -> do
                    passphrase <- bytes input "passphrase_hex"
                    pure $ fmap (either (Left . rootFailure) (const $ Right $ object ["valid" .= True])) $
                        Encrypted.encryptedValidatePassphrase key passphrase
                "root-key.sign-v2" -> do
                    passphrase <- bytes input "passphrase_hex"
                    message <- bytes input "message_hex"
                    pure $ fmap (either (Left . rootFailure) (\(Encrypted.Signature signature) -> Right $ object
                        ["signature_hex" .= hex signature, "xpub_hex" .= rootPublic key])) $
                        Encrypted.encryptedSign key passphrase message
                "root-key.change-v2" -> do
                    oldPassphrase <- bytes input "old_passphrase_hex"
                    newPassphrase <- bytes input "new_passphrase_hex"
                    counterRandomness input
                    pure $ Encrypted.withDeterministicRandomnessForTesting $
                        fmap (either (Left . rootFailure) (Right . renderRoot)) $
                            Encrypted.encryptedChangePassphrase oldPassphrase newPassphrase key
                "root-key.derive-v2" -> do
                    passphrase <- bytes input "passphrase_hex"
                    path <- input .: "path" :: Parser [Word32]
                    counterRandomness input
                    pure $ Encrypted.withDeterministicRandomnessForTesting $ do
                        derived <- foldM (\parent index -> case parent of
                            Left err -> pure $ Left err
                            Right parentKey -> Encrypted.encryptedDerivePrivate Encrypted.DerivationScheme2 parentKey passphrase index) (Right key) path
                        pure $ either (Left . rootFailure) (Right . renderRoot) derived
                _ -> fail "unsupported_operation"

main :: IO ()
main = do
    sodiumInit
    input <- BL.take 1048577 <$> BL.getContents
    unless (BL.length input <= 1048576) exitFailure
    value <- either (const exitFailure) pure $ eitherDecode input
    (ident, operation, payload) <- either (const exitFailure) pure $ parseEither request value
    let envelope field item = object ["protocol_version" .= (1 :: Int), "id" .= ident, field .= item]
        action = case parseEither (dispatchIO operation) payload of
            Right execute -> fmap (either (envelope "error") (envelope "result")) execute
            Left message -> pure $ envelope "error" $ object ["code" .=
                (if "unsupported_operation" `isSuffixOf` message then "unsupported_operation" else "invalid_input" :: Text)]
    evaluated <- try @SomeException $ do
        encoded <- encode <$> action
        _ <- evaluate $ BL.length encoded
        pure encoded
    case evaluated of
        Left _ -> BL.putStr $ encode $ envelope "error" $ object ["code" .= ("internal_error" :: Text)]
        Right encoded -> BL.putStr encoded

-- This context is only an adapter representation of the generic library's
-- identifier/address types. The selection algorithm is imported unchanged.
data ConformanceSelection
instance SelectionContext ConformanceSelection where
    type Address ConformanceSelection = Text
    type UTxO ConformanceSelection = Text

parseHex :: Text -> Parser ByteString
parseHex value = either (const $ fail "invalid_input") pure
    (Base.convertFromBase Base.Base16 (T.encodeUtf8 value))

parseAsset :: Text -> Parser AssetId
parseAsset value = case Text.splitOn "." value of
    [policyText, nameText] -> do
        policy <- parseHex policyText
        name <- parseHex nameText
        unless (BS.length policy == 28 && BS.length name <= 32) $ fail "invalid_input"
        pure $ AssetId (UnsafeTokenPolicyId $ Hash policy) (UnsafeAssetName name)
    _ -> fail "invalid_input"

parseBundle :: Value -> Parser TB.TokenBundle
parseBundle = withObject "bundle" $ \value -> do
    coin <- value .: "coin" :: Parser Word64
    assets <- value .:? "assets" .!= Map.empty :: Parser (Map.Map Text Word64)
    tokens <- forM (Map.toList assets) $ \(name, quantity) -> do
        asset <- parseAsset name
        pure (asset, TokenQuantity $ fromIntegral quantity)
    pure $ TB.fromFlatList (Coin $ fromIntegral coin) tokens

assetText :: AssetId -> Text
assetText (AssetId (UnsafeTokenPolicyId (Hash policy)) (UnsafeAssetName name)) =
    hex policy <> "." <> hex name

renderBundle :: TB.TokenBundle -> Value
renderBundle bundle = object ["coin" .= coin, "assets" .= Map.fromList
    [(assetText asset, quantity) | (asset, TokenQuantity quantity) <- assets]]
  where
    (Coin coin, assets) = TB.toFlatList bundle

select :: Bool -> Value -> Parser (Either Value Value)
select fixedContract = withObject "selection input" $ \input -> do
    seed <- input .: "seed" :: Parser Word64
    unless (finiteBitSize (0 :: Int) == 64) $ fail "unsupported_operation"
    minimumFee <- input .: (if fixedContract then "fee" else "minimum_fee") :: Parser Word64
    minimumChange <- input .: "minimum_change_coin" :: Parser Word64
    maximumCoin <- input .:? "maximum_output_coin" .!= 45000000000000000 :: Parser Word64
    maximumQuantity <- input .:? "maximum_output_token_quantity" .!= 9223372036854775807 :: Parser Word64
    maximumAssets <- input .:? "maximum_assets_per_bundle" .!= 32 :: Parser Int
    maximumInputs <- input .:? "maximum_inputs" .!= maxBound :: Parser Word64
    unless (maximumCoin > 0 && maximumCoin >= minimumChange && maximumQuantity > 0 && maximumAssets > 0) $
        fail "invalid_input"
    strategyName <- input .:? "strategy" .!= ("optimal" :: Text)
    strategy <- case strategyName of
        "minimal" -> pure Balance.SelectionStrategyMinimal
        "optimal" -> pure Balance.SelectionStrategyOptimal
        _ -> fail "invalid_input"
    inputValues <- input .: "utxos" :: Parser [Value]
    utxos <- forM inputValues $ withObject "utxo" $ \value -> do
        ident <- value .: "id" :: Parser Text
        bundle <- value .: "value" >>= parseBundle
        eligible <- value .: "eligible"
        pure (ident, bundle, eligible)
    unless (Set.size (Set.fromList [ident | (ident,_,_) <- utxos]) == length utxos) $ fail "invalid_input"
    let eligibleCoin = sum [toInteger coin | (_, bundle, True) <- utxos, let Coin coin = TB.getCoin bundle]
    unless (eligibleCoin <= toInteger maximumCoin) $ fail "invalid_input"
    outputValues <- input .: "outputs" :: Parser [Value]
    outputs <- mapM parseBundle outputValues
    let minimumCoin = Coin $ fromIntegral minimumChange
        fee = Coin $ fromIntegral minimumFee
        sizeAssessment bundle = if length (snd $ TB.toFlatList bundle) <= maximumAssets
            then TokenBundleSizeWithinLimit else TokenBundleSizeExceedsLimit
        constraints :: Balance.SelectionConstraints ConformanceSelection
        constraints = Balance.SelectionConstraints
            { Balance.tokenBundleSizeAssessor = TokenBundleSizeAssessor sizeAssessment
            , Balance.computeMinimumAdaQuantity = \_ _ -> minimumCoin
            , Balance.computeMinimumCost = const fee
            , Balance.maximumLengthChangeAddress = "change"
            , Balance.nullAddress = ""
            , Balance.maximumOutputAdaQuantity = Coin $ fromIntegral maximumCoin
            , Balance.maximumOutputTokenQuantity = TokenQuantity $ fromIntegral maximumQuantity
            }
        params :: Balance.SelectionParams ConformanceSelection
        params = Balance.SelectionParams
            { Balance.outputsToCover = zipWith (\index bundle -> (Text.pack $ show index, bundle)) [0 :: Int ..] outputs
            , Balance.utxoAvailable = Selection.fromIndex $ Index.fromMap $ Map.fromList
                [(ident, bundle) | (ident,bundle,True) <- utxos]
            , Balance.extraCoinSource = Coin 0
            , Balance.extraCoinSink = Coin 0
            , Balance.assetsToMint = mempty
            , Balance.assetsToBurn = mempty
            , Balance.selectionStrategy = strategy
            }
        result = evalRand (Balance.performSelection constraints params) (mkStdGen $ fromIntegral seed)
        coinValue bundle = let Coin coin = TB.getCoin bundle in toInteger coin
        validOutput bundle =
            let (Coin coin, tokens) = TB.toFlatList bundle
            in coin >= fromIntegral minimumChange && coin <= fromIntegral maximumCoin
                && length tokens <= maximumAssets
                && all (\(_, TokenQuantity quantity) -> quantity <= fromIntegral maximumQuantity) tokens
    unless (all validOutput outputs) $ fail "invalid_input"
    pure $ case result of
        Left failure -> Left $ selectionError fixedContract failure
        Right selection ->
            let chosen = NE.toList $ Balance.inputsSelected selection
                change = Balance.changeGenerated selection
                actualFee = sum (map (coinValue . snd) chosen) - sum (map coinValue outputs) - sum (map coinValue change)
            in if actualFee < 0 then Left $ object ["code" .= ("internal_error" :: Text)]
               else if fixedContract && (actualFee /= toInteger minimumFee || fromIntegral (length chosen) > maximumInputs)
                    then Left $ object ["code" .= ("not_enough_money" :: Text)]
               else Right $ object ["inputs" .= map fst chosen, "change" .= map renderBundle change, "fee" .= actualFee]

selectionError :: Bool -> Balance.SelectionBalanceError ConformanceSelection -> Value
selectionError True _ = object ["code" .= ("not_enough_money" :: Text)]
selectionError False failure = case failure of
    Balance.EmptyUTxO -> object ["code" .= ("empty_utxo" :: Text)]
    Balance.BalanceInsufficient info -> object
        [ "code" .= ("balance_insufficient" :: Text)
        , "available" .= renderBundle (Balance.utxoBalanceAvailable info)
        , "required" .= renderBundle (Balance.utxoBalanceRequired info)
        , "shortfall" .= renderBundle (Balance.utxoBalanceShortfall info)
        ]
    Balance.UnableToConstructChange info ->
        let Coin required = getField @"requiredCost" info
            Coin shortfall = Balance.shortfall info
        in object ["code" .= ("unable_to_construct_change" :: Text), "required_cost" .= required, "shortfall" .= shortfall]
