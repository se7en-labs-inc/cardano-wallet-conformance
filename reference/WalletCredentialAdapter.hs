{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

-- Test fixtures around actual wallet/database functions. No migration algorithm
-- is implemented here. Compile against the pinned Nix-built wallet library.
module Main (main) where

import Prelude
import Cardano.Address.Script (Cosigner (..), Script (..), ScriptTemplate (..))
import Cardano.Mnemonic (SomeMnemonic, mkSomeMnemonic)
import Cardano.Crypto.Libsodium (sodiumInit)
import Cardano.Wallet.Address.Derivation (Depth (..), DerivationPrefix (..), HardDerivation (..))
import Cardano.Wallet.Address.Discovery (ChangeAddressMode (..), IsOurs, coinTypeAda)
import Cardano.Wallet.Address.Discovery.Random (mkRndState)
import Cardano.Wallet.Address.Discovery.Sequential (mkSeqStateFromAccountXPub, defaultAddressPoolGap, purposeCIP1852)
import Cardano.Wallet.Address.Discovery.Shared (SharedState (..), Readiness (..))
import Cardano.Wallet.Address.Keys.WalletKey (getRawKey)
import Cardano.Wallet.DB (DBLayer (..))
import Cardano.Wallet.DB.Layer (PersistAddressBook, withBootDBLayerInMemory)
import Cardano.Wallet.DummyTarget.Primitive.Types (block0, dummyNetworkParameters, dummyTimeInterpreter)
import Cardano.Wallet.Flavor (WalletFlavor, WalletFlavorS (..), KeyOf, keyFlavorFromState)
import Cardano.Wallet.Network.RestorationMode (RestorationPoint (..))
import Cardano.Wallet.Primitive.NetworkId (NetworkDiscriminant (..))
import Cardano.Wallet.Primitive.Types (WalletId (..), WalletName (..), WalletMetadata (..))
import Cardano.Wallet.Primitive.Types.Address (Address)
import Cardano.Wallet.Primitive.Types.Credentials (HashedCredentials (..))
import Cardano.Wallet.Primitive.Types.RewardAccount (RewardAccount)
import Control.Exception (SomeException, evaluate, try)
import Control.Monad (forM, unless, when)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.Except (runExceptT, throwE)
import Control.Tracer (mkTracer, nullTracer)
import Cryptography.Hash.Core (hash)
import Data.Aeson (Value (..), eitherDecode, encode, object, withObject, (.:), (.:?), (.!=), (.=))
import Data.Aeson.Types (Parser, parseEither)
import Data.ByteString (ByteString)
import Data.Either (isRight)
import Data.IORef (newIORef, readIORef, writeIORef, modifyIORef')
import Data.Word (Word64)
import Data.Text (Text)
import System.Exit (exitFailure)
import qualified Cardano.Crypto.Wallet as CC
import qualified Cardano.Crypto.WalletHD.Encrypted as E
import qualified Cardano.Wallet as W
import qualified Cardano.Wallet.Address.Derivation.Shelley as Shelley
import qualified Cardano.Wallet.Address.Derivation.Shared as Shared
import qualified Cardano.Wallet.Address.Derivation.Byron as Byron
import qualified Cardano.Wallet.Address.Derivation.Icarus as Icarus
import qualified Cardano.Wallet.Primitive.Passphrase as P
import qualified Cardano.Wallet.Primitive.Passphrase.Current as Current
import qualified Cardano.Wallet.Primitive.Passphrase.Legacy as Legacy
import qualified Data.ByteArray as BA
import qualified Data.ByteArray.Encoding as Base
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL
import qualified Data.Map.Strict as Map
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.Text.Encoding as T

hex :: BA.ByteArrayAccess a => a -> Text
hex value = T.decodeUtf8 (Base.convertToBase Base.Base16 value :: ByteString)

userPassword :: Text -> P.Passphrase "user"
userPassword = P.Passphrase . BA.convert . T.encodeUtf8

foreign import ccall unsafe "conformance_arm_argon2_failure"
    armArgonFailure :: IO ()
foreign import ccall unsafe "conformance_argon2_failures"
    argonFailures :: IO Word64
foreign import ccall unsafe "conformance_argon2_bad_parameters"
    argonBadParameters :: IO Word64

data Action = Unlock Text Bool Bool | Change Text Text

data Input = Input
    { flavor :: Text
    , mnemonic :: SomeMnemonic
    , scheme :: P.PassphraseScheme
    , initialFormat :: Text
    , password :: P.Passphrase "user"
    , probes :: [Text]
    , message :: ByteString
    , actions :: [Action]
    }

parseAction :: Value -> Parser Action
parseAction = withObject "action" $ \value -> do
    operation <- value .: "type" :: Parser Text
    case operation of
        "unlock" -> Unlock <$> value .: "passphrase_utf8" <*> value .:? "callback_error" .!= False <*> value .:? "fail_migration" .!= False
        "change" -> Change <$> value .: "old_passphrase_utf8" <*> value .: "new_passphrase_utf8"
        _ -> fail "invalid_input"

parseInput :: Value -> Parser Input
parseInput = withObject "credentials" $ \value -> do
    flavor <- value .: "flavor"
    words' <- value .: "mnemonic"
    mnemonic <- either (const $ fail "invalid_input") pure $ mkSomeMnemonic @'[12,15,18,21,24] words'
    requestedScheme <- value .: "scheme" :: Parser Text
    scheme <- case requestedScheme of
        "pbkdf2" -> pure P.EncryptWithPBKDF2
        "scrypt" -> pure P.EncryptWithScrypt
        _ -> fail "invalid_input"
    initialFormat <- value .: "initial_format"
    unless (initialFormat `elem` ["v1", "new", "none"] && (initialFormat /= "new" || scheme == P.EncryptWithPBKDF2)) $ fail "invalid_input"
    password <- userPassword <$> value .: "passphrase_utf8"
    probes <- value .: "password_probes"
    messageText <- value .: "message_hex"
    message <- either (const $ fail "invalid_input") pure $ Base.convertFromBase Base.Base16 (T.encodeUtf8 messageText)
    randomness <- value .: "randomness" :: Parser Text
    unless (randomness == "counter-v1") $ fail "invalid_input"
    actions <- value .: "actions" >>= traverse parseAction
    pure $ Input flavor mnemonic scheme initialFormat password probes message actions

schemeName :: P.PassphraseScheme -> Text
schemeName P.EncryptWithPBKDF2 = "pbkdf2"
schemeName P.EncryptWithScrypt = "scrypt"
schemeName P.EncryptWithArgon2idV2 = "argon2id"

rootError :: W.ErrWithRootKey -> Text
rootError (W.ErrWithRootKeyNoRootKey _) = "no_root_key"
rootError (W.ErrWithRootKeyWrongPassphrase _ _) = "wrong_passphrase"
rootError (W.ErrWithRootKeyWrongMnemonic _) = "wrong_mnemonic"

rootPublic :: E.EncryptedKey -> Text
rootPublic key = hex $ E.publicKeyByteString (E.encryptedPublic key)
    <> E.chainCodeByteString (E.encryptedChainCode key)

snapshot :: forall s. WalletFlavor s => DBLayer IO s -> [Text] -> IO Value
snapshot DBLayer{atomically=transaction,walletState=store} candidates = do
    creds <- transaction $ W.readPrivateKey store
    meta <- transaction $ W.readWalletMeta store
    let storedScheme = P.passphraseScheme <$> passphraseInfo meta
        (format, bytes, public, hashPresent) = case creds of
            Nothing -> ("none" :: Text, Nothing, Nothing, False)
            Just (HashedCredentialsV1 key _) ->
                let raw = getRawKey (keyFlavorFromState @s) key
                in ("v1", Just $ hex $ CC.unXPrv raw, Just $ hex $ CC.unXPub $ CC.toXPub raw, True)
            Just (HashedCredentialsV2 key _) -> ("v2", Just $ hex $ E.unEncryptedKey key, Just $ rootPublic key, False)
    checks <- forM candidates $ \candidate -> case (creds, storedScheme) of
        (Just (HashedCredentialsV1 _ hpwd), Just passScheme) -> pure $ isRight $ P.checkPassphrase passScheme (userPassword candidate) hpwd
        (Just (HashedCredentialsV2 key _), _) -> isRight <$> E.encryptedValidatePassphrase key (userPassword candidate)
        _ -> pure False
    pure $ object ["format" .= format,"scheme" .= fmap schemeName storedScheme,"key_hex" .= bytes,"xpub_hex" .= public,"password_hash_present" .= hashPresent,"password_checks" .= checks]

fixture
    :: forall s. (WalletFlavor s, PersistAddressBook s, IsOurs s Address, IsOurs s RewardAccount)
    => WalletFlavorS s -> s -> KeyOf s 'RootK CC.XPrv -> Input -> IO Value
fixture walletFlavor state key input = do
    let wid = WalletId $ hash @ByteString "wallet-conformance-credential-profile"
        initial = W.InitialState state block0 RestorationPointAtGenesis
    params <- W.createWallet dummyNetworkParameters wid (WalletName "Conformance credentials") initial
    withBootDBLayerInMemory walletFlavor nullTracer dummyTimeInterpreter wid params $ \db@DBLayer{atomically=transaction,walletState=store} -> do
        let wl = W.WalletLayer nullTracer (block0, dummyNetworkParameters)
                (error "unexpected network use in credential fixture")
                (error "unexpected transaction-layer use in credential fixture") db
            prepared = P.preparePassphrase (scheme input) (password input)
            salt n = P.Passphrase @"salt" $ BA.convert $ BS.replicate n 0x42
            hpwd = case scheme input of
                P.EncryptWithScrypt -> Legacy.encryptPassphraseTestingOnly 64 prepared (salt 32)
                _ -> Current.encryptPassphrase prepared (salt 16)
        case initialFormat input of
            "none" -> pure ()
            "new" -> W.attachPrivateKeyFromPwd wl (key, password input)
            _ -> case scheme input of
                P.EncryptWithScrypt -> W.attachPrivateKeyFromPwdHashByron wl (key, hpwd)
                _ -> W.attachPrivateKeyFromPwdHashShelley wl (key, hpwd)
        first <- snapshot db (probes input)
        steps <- forM (actions input) $ \action -> do
            before <- transaction $ W.readPrivateKey store
            beforeMeta <- transaction $ W.readWalletMeta store
            previous <- snapshot db []
            callback <- newIORef Null
            warnings <- newIORef (0 :: Word64)
            let migrationTracer = mkTracer $ \event -> case event of
                    W.MsgV2MigrationFailed _ -> modifyIORef' warnings (+1)
                    _ -> pure ()
            outcome <- case action of
                Unlock candidate failCallback injectFailure -> do
                    when injectFailure armArgonFailure
                    result <- runExceptT $ W.withRootKey migrationTracer db wid (userPassword candidate) rootError $ \access -> do
                        let accessFormat = case access of W.RootKeyAccessV1{} -> "v1" :: Text; W.RootKeyAccessV2{} -> "v2"
                        liftIO $ writeIORef callback $ object ["access" .= accessFormat]
                        when failCallback $ throwE "action_failed"
                        signed <- liftIO $ case access of
                            W.RootKeyAccessV1 root passScheme -> do
                                let raw = getRawKey (keyFlavorFromState @s) root
                                    sig = CC.sign (P.preparePassphrase passScheme $ userPassword candidate) raw (message input)
                                pure $ object ["access" .= accessFormat,"signature_hex" .= hex (CC.unXSignature sig),"xpub_hex" .= hex (CC.unXPub $ CC.toXPub raw)]
                            W.RootKeyAccessV2 encrypted _ pwd -> do
                                sig <- E.encryptedSign encrypted pwd (message input)
                                case sig of
                                    Left _ -> error "validated root signing failed"
                                    Right (E.Signature signature) -> pure $ object ["access" .= accessFormat,"signature_hex" .= hex signature,"xpub_hex" .= rootPublic encrypted]
                        liftIO $ writeIORef callback signed
                    pure $ either id (const "success") result
                Change old new -> do
                    result <- runExceptT $ W.updateWalletPassphraseWithOldPassphrase walletFlavor wl wid (userPassword old, userPassword new)
                    pure $ case result of
                        Right () -> "success"
                        Left (W.ErrUpdatePassphraseWithRootKey err) -> rootError err
            after <- transaction $ W.readPrivateKey store
            afterMeta <- transaction $ W.readWalletMeta store
            current <- snapshot db (probes input)
            observedCallback <- readIORef callback
            faultFields <- case action of
                Unlock _ _ True -> do
                    faults <- argonFailures
                    badParameters <- argonBadParameters
                    warningCount <- readIORef warnings
                    unless (faults == 1 && warningCount == 1 && badParameters == 0) $ error "requested migration fault was not observed under production parameters"
                    pure ["migration_faults_consumed" .= faults,"migration_warnings" .= warningCount,"production_kdf_parameters" .= (badParameters == 0)]
                _ -> pure []
            let timestamp meta = P.lastUpdatedAt <$> passphraseInfo meta
                keyBytes value = case value of Object fields -> KeyMap.lookup "key_hex" fields; _ -> Nothing
                identity creds = case creds of
                    Nothing -> Nothing
                    Just (HashedCredentialsV1 root hpwd') -> Just ("v1" :: Text, CC.unXPrv $ getRawKey (keyFlavorFromState @s) root, Just $ hex hpwd')
                    Just (HashedCredentialsV2 root payload) -> Just ("v2", E.unEncryptedKey root, fmap hex payload)
            pure $ object $ ["outcome" .= outcome,"callback" .= observedCallback,"after" .= current,
                "credentials_unchanged" .= (identity before == identity after),
                "metadata_unchanged" .= (beforeMeta == afterMeta),
                "timestamp_unchanged" .= (timestamp beforeMeta == timestamp afterMeta),
                "key_bytes_unchanged" .= (keyBytes previous == keyBytes current)] <> faultFields
        pure $ object ["initial" .= first,"steps" .= steps]

execute :: Input -> IO Value
execute input = E.withDeterministicRandomnessForTesting $ do
    let prepared = P.preparePassphrase (scheme input) (password input)
        mn = mnemonic input
        sequential account purpose = mkSeqStateFromAccountXPub @'Mainnet account Nothing purpose defaultAddressPoolGap IncreasingChangeAddresses
    case flavor input of
        "shelley" -> do
            let key = Shelley.generateKeyFromSeed (mn, Nothing) prepared
                account = Shelley.ShelleyKey $ CC.toXPub $ Shelley.getKey $ deriveAccountPrivateKey prepared key minBound
            fixture ShelleyWallet (sequential account purposeCIP1852) key input
        "icarus" -> do
            let key = Icarus.generateKeyFromSeed mn prepared
                account = Icarus.IcarusKey $ CC.toXPub $ Icarus.getKey $ deriveAccountPrivateKey prepared key minBound
            fixture IcarusWallet (sequential account purposeCIP1852) key input
        "byron" -> do
            let key = Byron.generateKeyFromSeed mn prepared
            fixture (ByronWallet @'Mainnet) (mkRndState key 0) key input
        "shared" -> do
            let key = Shared.generateKeyFromSeed (mn, Nothing) prepared
                accountPub = CC.toXPub $ Shared.getKey $ deriveAccountPrivateKey prepared key minBound
                template = ScriptTemplate (Map.singleton (Cosigner 0) accountPub) (RequireAllOf [RequireSignatureOf (Cosigner 0),RequireSignatureOf (Cosigner 1)])
                state = SharedState (DerivationPrefix (Shared.purposeCIP1854,coinTypeAda,minBound)) (Shared.SharedKey accountPub) template Nothing Nothing defaultAddressPoolGap IncreasingChangeAddresses Pending
            fixture (SharedWallet @'Mainnet) state key input
        _ -> error "invalid flavor"

main :: IO ()
main = do
    sodiumInit
    bytes <- BL.take 1048577 <$> BL.getContents
    unless (BL.length bytes <= 1048576) exitFailure
    value <- either (const exitFailure) pure $ eitherDecode bytes
    (ident, input) <- either (const exitFailure) pure $ parseEither parseRequest value
    let envelope field result = object ["protocol_version" .= (1 :: Int),"id" .= ident,field .= result]
    result <- try @SomeException $ do
        encoded <- encode . envelope "result" <$> execute input
        _ <- evaluate $ BL.length encoded
        pure encoded
    BL.putStr $ either (const $ encode $ envelope "error" $ object ["code" .= ("internal_error" :: Text)]) id result
  where
    parseRequest :: Value -> Parser (Value, Input)
    parseRequest = withObject "request" $ \value -> do
        version <- value .: "protocol_version" :: Parser Int
        operation <- value .: "operation" :: Parser Text
        unless (version == 1 && operation == "wallet.credentials") $ fail "invalid request"
        (,) <$> value .: "id" <*> (value .: "input" >>= parseInput)
