{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedStrings #-}
module Main (main) where
import Prelude
import Control.Monad (forM, unless)
import Control.Monad.Random (evalRand)
import Control.Monad.Trans.Except (runExceptT)
import Data.Aeson (Value, Object, eitherDecode, encode, object, withObject, (.:), (.=))
import Data.Aeson.Types (Parser, parseEither)
import Data.Text (Text)
import Data.Word (Word32, Word64)
import System.Exit (exitFailure)
import System.Random (mkStdGen)
import qualified Cardano.Balance.Tx.Balance.CoinSelection as Selection
import qualified Cardano.Balance.Tx.Primitive as W
import qualified Cardano.CoinSelection.Size as Size
import qualified Cardano.CoinSelection.UTxOIndex as Index
import qualified Cardano.CoinSelection.UTxOSelection as UTxO
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL
import qualified Data.List.NonEmpty as NE
import qualified Data.Map.Strict as Map
import qualified Data.Set as Set

asset :: W.AssetId
asset = W.AssetId (W.UnsafeTokenPolicyId $ W.Hash $ BS.replicate 28 0x11) (W.UnsafeAssetName $ BS.singleton 0)
bundle :: Word64 -> Word64 -> W.TokenBundle
bundle coin quantity = W.TokenBundle (W.Coin $ fromIntegral coin) $ if quantity == 0 then mempty else W.fromFlatList [(asset,W.TokenQuantity $ fromIntegral quantity)]
parseBundle :: Value -> Parser W.TokenBundle
parseBundle = withObject "bundle" $ \input -> bundle <$> input .: "coin" <*> input .: "asset_quantity"
render :: W.TokenBundle -> Value
render (W.TokenBundle (W.Coin coin) tokens) = object ["coin" .= coin,"asset_quantity" .= sum [q | (_,W.TokenQuantity q) <- W.toFlatList tokens]]
coinOf :: W.TokenBundle -> Integer
coinOf (W.TokenBundle (W.Coin n) _) = toInteger n
run :: Object -> Parser Value
run input = do
    raw <- input .: "utxos" :: Parser [Value]
    unless (length raw <= 64) $ fail "invalid_input"
    let address = W.Address $ BS.cons 0x60 $ BS.replicate 28 0x22
    entries <- forM raw $ withObject "utxo" $ \entry -> do
        ident <- entry .: "id" :: Parser Word32
        value <- bundle <$> entry .: "coin" <*> entry .: "asset_quantity"
        ordinary <- entry .: "inputs"
        collateral <- entry .: "collateral"
        let txin = W.TxIn (BS.replicate 32 0) ident
        pure (ident,txin,Selection.WalletUTxO txin address,value,ordinary,collateral)
    unless (Set.size (Set.fromList [i | (i,_,_,_,_,_) <- entries]) == length entries) $ fail "invalid_input"
    outputs <- input .: "outputs" >>= traverse parseBundle
    unless (length outputs <= 16) $ fail "invalid_input"
    fee <- input .: "minimum_fee" :: Parser Word64
    minimumChange <- input .: "minimum_change_coin" :: Parser Word64
    cap <- input .: "maximum_collateral_inputs" :: Parser Word64
    unless (cap <= 64) $ fail "invalid_input"
    percentage <- input .: "collateral_percentage" :: Parser Word64
    required <- input .: "collateral_required"
    mint <- input .: "mint_quantity" :: Parser Word64
    burn <- input .: "burn_quantity" :: Parser Word64
    seed <- input .: "seed" :: Parser Word64
    strategyName <- input .: "strategy" :: Parser Text
    strategy <- case strategyName of
        "minimal" -> pure Selection.SelectionStrategyMinimal
        "optimal" -> pure Selection.SelectionStrategyOptimal
        _ -> fail "invalid_input"
    let constraints = Selection.SelectionConstraints
            { Selection.tokenBundleSizeAssessor = Size.TokenBundleSizeAssessor $ const Size.TokenBundleSizeWithinLimit
            , Selection.computeMinimumAdaQuantity = \_ _ -> W.Coin $ fromIntegral minimumChange
            , Selection.isBelowMinimumAdaQuantity = \_ b -> coinOf b < toInteger minimumChange
            , Selection.computeMinimumCost = const $ W.Coin $ fromIntegral fee
            , Selection.maximumCollateralInputCount = fromIntegral cap
            , Selection.minimumCollateralPercentage = fromIntegral percentage
            , Selection.maximumLengthChangeAddress = address
            }
        params = Selection.SelectionParams
            { Selection.extraValueIn = bundle 0 mint
            , Selection.extraValueOut = bundle 0 burn
            , Selection.outputsToCover = map (W.TxOut address) outputs
            , Selection.collateralRequirement = if required then Selection.SelectionCollateralRequired else Selection.SelectionCollateralNotRequired
            , Selection.utxoAvailableForCollateral = Map.fromList [(u,b) | (_,_,u,b,_,True) <- entries]
            , Selection.utxoAvailableForInputs = UTxO.fromIndex $ Index.fromMap $ Map.fromList [(u,Selection.toCSTokenBundle b) | (_,_,u,b,True,_) <- entries]
            , Selection.selectionStrategy = strategy
            }
        lookupId = Map.fromList [(txin,ident) | (ident,txin,_,_,_,_) <- entries]
        identOf txin = lookupId Map.! txin
        result = evalRand (runExceptT $ Selection.performSelection constraints params) (mkStdGen $ fromIntegral seed)
        errorResult code = object ["error" .= object ["code" .= (code :: Text)]]
    pure $ case result of
        Left (Selection.SelectionCollateralErrorOf failure) ->
            let W.Coin minimumCollateral = Selection.fromCSCoin $ Selection.minimumSelectionAmount failure
            in object ["error" .= object ["code" .= ("insufficient_collateral" :: Text),"minimum_collateral" .= minimumCollateral,"largest_available" .= [identOf txin | Selection.WalletUTxO txin _ <- Map.keys $ Selection.largestCombinationAvailable failure]]]
        Left (Selection.SelectionBalanceErrorOf failure) -> case failure of
            Selection.EmptyUTxO -> errorResult "empty_utxo"
            Selection.BalanceInsufficient _ -> errorResult "balance_insufficient"
            Selection.UnableToConstructChange _ -> errorResult "unable_to_construct_change"
        Right selection ->
            let selected = NE.toList $ Selection.inputs selection
                changes = Selection.change selection
                feeActual = sum [coinOf b | (_,W.TxOut _ b) <- selected] - sum (map coinOf outputs) - sum (map coinOf changes)
            in if feeActual < 0 then errorResult "internal_error" else object
                [ "inputs" .= map (identOf . fst) selected
                , "collateral" .= map (identOf . fst) (Selection.collateral selection)
                , "change" .= map render changes
                , "outputs" .= map (\(W.TxOut _ b) -> render b) (Selection.outputs selection)
                , "fee" .= feeActual
                ]

main :: IO ()
main = do
    raw <- BL.take 1048577 <$> BL.getContents
    unless (BL.length raw <= 1048576) exitFailure
    request <- either (const exitFailure) pure $ eitherDecode raw
    (ident,operation,input) <- either (const exitFailure) pure $ parseEither parseRequest request
    let envelope field value = object ["protocol_version" .= (1 :: Int),"id" .= ident,field .= value]
    BL.putStr $ encode $ case parseEither (withObject "input" $ \value -> if operation == "selection.wallet" then run value else fail "invalid_input") input of
        Left _ -> envelope "error" $ object ["code" .= ("invalid_input" :: Text)]
        Right value -> valueEnvelope envelope value
  where
    valueEnvelope envelope value = case parseEither (withObject "result" $ \v -> v .: "error") value of
        Right err -> envelope "error" (err :: Value)
        Left _ -> envelope "result" value
    parseRequest = withObject "request" $ \value -> do
        version <- value .: "protocol_version" :: Parser Int
        unless (version == 1) $ fail "invalid_input"
        (,,) <$> (value .: "id" :: Parser Text) <*> (value .: "operation" :: Parser Text) <*> value .: "input"
