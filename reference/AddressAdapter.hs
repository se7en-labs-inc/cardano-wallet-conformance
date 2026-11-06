{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
module Main (main) where
import Prelude
import Control.Monad (unless)
import Data.Aeson (Value, Object, eitherDecode, encode, object, withObject, (.:), (.:?), (.=))
import Data.Aeson.Types (Parser, parseEither)
import Data.ByteString (ByteString)
import Data.Either (isRight)
import Data.Text (Text)
import Data.Word (Word8, Word32, Word64)
import System.Exit (exitFailure)
import Cardano.Ledger.Allegra (AllegraEra)
import Cardano.Slotting.Slot (SlotNo (..))
import Data.Maybe.Strict (StrictMaybe (..))
import qualified Cardano.Address as Address
import qualified Cardano.Address.Derivation as A
import qualified Cardano.Address.KeyHash as KH
import qualified Cardano.Address.Script as S
import qualified Cardano.Address.Style.Shelley as CS
import qualified Cardano.Address.Style.Byron as CB
import qualified Cardano.Address.Style.Icarus as CI
import qualified Cardano.Codec.Cbor as Cbor
import qualified Cardano.Mnemonic as M
import qualified Cardano.Crypto.Hash.Class as Hash
import qualified Cardano.Ledger.Hashes as Ledger
import qualified Cardano.Ledger.Keys as LedgerKeys
import qualified Cardano.Ledger.Allegra.Scripts as L
import qualified Cardano.Wallet.Primitive.Types.TokenFingerprint as Fingerprint
import qualified Cardano.Wallet.Primitive.Types.TokenPolicyId as Policy
import qualified Cardano.Wallet.Primitive.Types.AssetName as Asset
import qualified Cardano.Wallet.Primitive.Types.Hash as WalletHash
import qualified Codec.Binary.Bech32 as Bech32
import qualified Data.Aeson.Key as Key
import qualified Data.ByteArray as BA
import qualified Data.ByteArray.Encoding as Base
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base58 as Base58
import qualified Data.ByteString.Lazy as BL
import qualified Data.Sequence.Strict as Seq
import qualified Data.Set as Set
import qualified Data.Text as T
import qualified Data.Text.Encoding as T

hex :: BA.ByteArrayAccess a => a -> Text
hex = T.decodeUtf8 . Base.convertToBase Base.Base16
bytes :: Object -> Text -> Parser ByteString
bytes input field = do
    value <- input .: Key.fromText field
    either (const $ fail "invalid_input") pure $ Base.convertFromBase Base.Base16 (T.encodeUtf8 value)
checked :: Either e a -> Parser a
checked = either (const $ fail "invalid_input") pure
present :: Maybe a -> Parser a
present = maybe (fail "invalid_input") pure
keyHash :: KH.KeyRole -> ByteString -> Parser KH.KeyHash
keyHash role raw = present $ KH.keyHashFromBytes (role, raw)
ledgerHash :: ByteString -> Parser (Ledger.KeyHash LedgerKeys.Witness)
ledgerHash raw = Ledger.KeyHash <$> present (Hash.hashFromBytes raw)

script :: Int -> Value -> Parser (S.Script KH.KeyHash, L.Timelock AllegraEra)
script depth = withObject "script" $ \input -> do
    unless (depth <= 8) $ fail "invalid_input"
    kind <- input .: "type" :: Parser Text
    case kind of
        "signature" -> do
            raw <- bytes input "key_hash_hex"
            key <- keyHash KH.Payment raw
            ledger <- ledgerHash raw
            pure (S.RequireSignatureOf key, L.mkRequireSignatureTimelock ledger)
        "all" -> do
            children <- childScripts input
            pure (S.RequireAllOf $ map fst children, L.mkRequireAllOfTimelock $ Seq.fromList $ map snd children)
        "any" -> do
            children <- childScripts input
            pure (S.RequireAnyOf $ map fst children, L.mkRequireAnyOfTimelock $ Seq.fromList $ map snd children)
        "at_least" -> do
            required <- input .: "required" :: Parser Word8
            children <- childScripts input
            pure (S.RequireSomeOf required $ map fst children, L.mkRequireMOfTimelock (fromIntegral required) $ Seq.fromList $ map snd children)
        "before" -> do
            slot <- input .: "slot" :: Parser Word64
            pure (S.ActiveUntilSlot $ fromIntegral slot, L.mkTimeExpireTimelock $ SlotNo slot)
        "after" -> do
            slot <- input .: "slot" :: Parser Word64
            pure (S.ActiveFromSlot $ fromIntegral slot, L.mkTimeStartTimelock $ SlotNo slot)
        _ -> fail "invalid_input"
  where
    childScripts input = do
        children <- input .: "scripts"
        unless (length children <= 16) $ fail "invalid_input"
        traverse (script $ depth + 1) children

payment :: Value -> Parser (CS.Credential 'A.PaymentK)
payment = withObject "payment credential" $ \input -> do
    kind <- input .: "type" :: Parser Text
    case kind of
        "key" -> CS.PaymentFromKeyHash <$> (bytes input "hash_hex" >>= keyHash KH.Payment)
        "script" -> CS.PaymentFromScript . fst <$> (input .: "script" >>= script 0)
        _ -> fail "invalid_input"
stake :: Value -> Parser (CS.Credential 'A.DelegationK)
stake = withObject "stake credential" $ \input -> do
    kind <- input .: "type" :: Parser Text
    case kind of
        "key" -> CS.DelegationFromKeyHash <$> (bytes input "hash_hex" >>= keyHash KH.Delegation)
        "script" -> CS.DelegationFromScript . fst <$> (input .: "script" >>= script 0)
        _ -> fail "invalid_input"
renderAddress :: Address.Address -> Value
renderAddress address = object ["address" .= encoded,"address_hex" .= hex raw]
  where
    raw = Address.unAddress address
    encoded
        | not (BS.null raw) && BS.head raw >= 224 =
            let name = if BS.head raw `mod` 16 == 1 then "stake" else "stake_test"
            in case Bech32.humanReadablePartFromText name of
                Left _ -> error "constant reward HRP is invalid"
                Right hrp -> Bech32.encodeLenient hrp (Bech32.dataPartFromBytes raw)
        | otherwise = Address.bech32 address

run :: Text -> Value -> Parser Value
run operation = withObject "input" $ \input -> case operation of
    "native.script" -> do
        (native, ledger) <- input .: "script" >>= script 0
        signerHex <- input .: "signers" :: Parser [Text]
        signers <- traverse (\text -> checked (Base.convertFromBase Base.Base16 $ T.encodeUtf8 text) >>= ledgerHash) signerHex
        lo <- input .:? "invalid_before" :: Parser (Maybe Word64)
        hi <- input .:? "invalid_hereafter" :: Parser (Maybe Word64)
        let bound = maybe SNothing (SJust . SlotNo)
            interval = L.ValidityInterval (bound lo) (bound hi)
        pure $ object ["cbor_hex" .= hex (S.serializeScript native),"hash_hex" .= hex (S.unScriptHash $ S.toScriptHash native),"valid" .= isRight (S.validateScript S.RequiredValidation native),"satisfied" .= L.evalTimelock (Set.fromList signers) interval ledger]
    "address.build" -> do
        network <- input .: "network_tag"
        discriminant <- checked $ CS.mkNetworkDiscriminant network
        kind <- input .: "kind" :: Parser Text
        case kind of
            "enterprise" -> renderAddress . CS.paymentAddress discriminant <$> (input .: "payment" >>= payment)
            "base" -> do
                p <- input .: "payment" >>= payment
                s <- input .: "stake" >>= stake
                pure $ renderAddress $ CS.delegationAddress discriminant p s
            "reward" -> do
                s <- input .: "stake" >>= stake
                renderAddress <$> checked (CS.stakeAddress discriminant s)
            "pointer" -> do
                p <- input .: "payment" >>= payment
                slot <- input .: "slot" :: Parser Word64
                transaction <- input .: "transaction_index" :: Parser Word64
                output <- input .: "output_index" :: Parser Word64
                pure $ renderAddress $ CS.pointerAddress discriminant p (Address.ChainPointer (fromIntegral slot) (fromIntegral transaction) (fromIntegral output))
            _ -> fail "invalid_input"
    "address.byron" -> do
        style <- input .: "style" :: Parser Text
        sentence <- input .: "mnemonic"
        mnemonic <- checked $ M.mkSomeMnemonic @'[12,15,18,21,24] (T.words sentence)
        network <- input .: "network" :: Parser Text
        unless (network `elem` ["mainnet", "preprod"]) $ fail "invalid_input"
        account <- input .: "account_index" :: Parser Word32
        index <- input .: "address_index" :: Parser Word32
        address <- case style of
            "Byron" -> do
                let root = CB.genMasterKeyFromMnemonic mnemonic
                    accountKey = CB.deriveAccountPrivateKey root (A.wholeDomainIndex account)
                    child = CB.deriveAddressPrivateKey accountKey (A.wholeDomainIndex index)
                    public = CB.liftXPub (A.toXPub $ CB.getKey root) (A.wholeDomainIndex account,A.wholeDomainIndex index) (A.toXPub $ CB.getKey child)
                pure $ CB.paymentAddress (if network == "mainnet" then CB.byronMainnet else CB.byronPreprod) public
            "Icarus" -> do
                unless (account >= 2147483648 && index < 2147483648) $ fail "invalid_input"
                let root = CI.genMasterKeyFromMnemonic mnemonic mempty
                    accountKey = CI.deriveAccountPrivateKey root (A.unsafeMkIndex account)
                    child = CI.deriveAddressPrivateKey accountKey CI.UTxOExternal (A.unsafeMkIndex index)
                pure $ CI.paymentAddress (if network == "mainnet" then CI.icarusMainnet else CI.icarusPreprod) (CI.liftXPub $ A.toXPub $ CI.getKey child)
            _ -> fail "invalid_input"
        pure $ object ["address" .= Address.base58 address,"address_hex" .= hex (Address.unAddress address)]
    "address.inspect-byron" -> do
        raw <- bytes input "address_hex"
        style <- input .: "style" :: Parser Text
        case style of
            "Byron" -> do
                _ <- checked $ CB.eitherInspectAddress Nothing (Address.unsafeMkAddress raw)
                pure $ object ["valid" .= True]
            "Icarus" -> do
                _ <- checked $ CI.eitherInspectAddress (Address.unsafeMkAddress raw)
                pure $ object ["valid" .= True]
            _ -> fail "invalid_input"
    "byron.path-encrypt" -> do
        password <- bytes input "passphrase_hex"
        unless (BS.length password == 32) $ fail "invalid_input"
        account <- input .: "account_index"
        index <- input .: "address_index"
        let attributes = Cbor.toStrictByteString $ Cbor.encodeAttributes [Cbor.encodeDerivationPathAttr (BA.convert password) account index]
        pure $ object ["attributes_hex" .= hex attributes]
    "byron.path-decrypt" -> do
        password <- bytes input "passphrase_hex"
        unless (BS.length password == 32) $ fail "invalid_input"
        raw <- bytes input "attributes_hex"
        result <- checked $ Cbor.deserialiseCbor (Cbor.decodeAllAttributes >>= Cbor.decodeDerivationPathAttr (BA.convert password)) raw
        pure $ object ["path" .= fmap (\(account,index) -> [account,index]) result]
    "encoding.bech32" -> do
        action <- input .: "action" :: Parser Text
        case action of
            "encode" -> do
                hrp <- input .: "hrp" >>= checked . Bech32.humanReadablePartFromText
                raw <- bytes input "bytes_hex"
                pure $ object ["text" .= Bech32.encodeLenient hrp (Bech32.dataPartFromBytes raw)]
            "decode" -> do
                (hrp,part) <- input .: "text" >>= checked . Bech32.decodeLenient
                raw <- present $ Bech32.dataPartToBytes part
                pure $ object ["hrp" .= Bech32.humanReadablePartToText hrp,"bytes_hex" .= hex raw]
            _ -> fail "invalid_input"
    "encoding.base58" -> do
        action <- input .: "action" :: Parser Text
        case action of
            "encode" -> do
                raw <- bytes input "bytes_hex"
                pure $ object ["text" .= T.decodeUtf8 (Base58.encodeBase58 Base58.bitcoinAlphabet raw)]
            "decode" -> do
                text <- input .: "text"
                raw <- present $ Base58.decodeBase58 Base58.bitcoinAlphabet (T.encodeUtf8 text)
                pure $ object ["bytes_hex" .= hex raw]
            _ -> fail "invalid_input"
    "governance.identifier" -> do
        action <- input .: "action" :: Parser Text
        kind <- input .: "kind" :: Parser Text
        role <- input .: "role" :: Parser Text
        keyRole <- case role of
            "drep" -> pure KH.Representative
            "committee_hot" -> pure KH.CommitteeHot
            "committee_cold" -> pure KH.CommitteeCold
            _ -> fail "invalid_input"
        case (action,kind) of
            ("encode","key") -> do
                digest <- bytes input "hash_hex" >>= keyHash keyRole
                pure $ object ["text" .= KH.keyHashToText digest KH.CIP0129]
            ("encode","script") -> do
                digest <- bytes input "hash_hex" >>= present . S.scriptHashFromBytes
                pure $ object ["text" .= S.scriptHashToText digest keyRole (Just KH.CIP0129)]
            ("decode","key") -> do
                digest <- input .: "text" >>= checked . KH.keyHashFromText
                pure $ object ["hash_hex" .= hex (KH.digest digest)]
            ("decode","script") -> do
                digest <- input .: "text" >>= checked . S.scriptHashFromText
                pure $ object ["hash_hex" .= hex (S.unScriptHash digest)]
            _ -> fail "invalid_input"
    "key.hash" -> do
        public <- bytes input "public_key_hex"
        unless (BS.length public == 32) $ fail "invalid_input"
        pure $ object ["hash_hex" .= hex (A.hashCredential public)]
    "asset.fingerprint" -> do
        policy <- bytes input "policy_hex"
        asset <- bytes input "asset_name_hex"
        unless (BS.length policy == 28 && BS.length asset <= 32) $ fail "invalid_input"
        let fingerprint = Fingerprint.mkTokenFingerprint (Policy.UnsafeTokenPolicyId $ WalletHash.Hash policy) (Asset.UnsafeAssetName asset)
        case fingerprint of Fingerprint.UnsafeTokenFingerprint text -> pure $ object ["fingerprint" .= text]
    _ -> fail "invalid_input"

main :: IO ()
main = do
    raw <- BL.take 1048577 <$> BL.getContents
    unless (BL.length raw <= 1048576) exitFailure
    request <- either (const exitFailure) pure $ eitherDecode raw
    (ident, operation, input) <- either (const exitFailure) pure $ parseEither parseRequest request
    let envelope field value = object ["protocol_version" .= (1 :: Int),"id" .= ident,field .= value]
    BL.putStr $ encode $ case parseEither (run operation) input of
        Left _ -> envelope "error" $ object ["code" .= ("invalid_input" :: Text)]
        Right value -> envelope "result" value
  where
    parseRequest = withObject "request" $ \value -> do
        version <- value .: "protocol_version" :: Parser Int
        unless (version == 1) $ fail "invalid protocol"
        (,,) <$> (value .: "id" :: Parser Text) <*> value .: "operation" <*> value .: "input"
