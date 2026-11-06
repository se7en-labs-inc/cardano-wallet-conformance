{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE OverloadedStrings #-}
module Main (main) where

-- Diagnostic only: call the actual pinned submission implementation. No
-- submission algorithm or expected transition is implemented in this helper.
import Prelude
import Control.Monad (unless)
import Data.Aeson (Value, eitherDecode, encode, object, withObject, (.:), (.=))
import Data.Aeson.Types (Parser, parseEither)
import Data.ByteString (ByteString)
import Data.Delta (Delta (apply))
import Data.Quantity (Quantity (..))
import Data.Text (Text)
import Data.Word (Word64)
import Cardano.Wallet.Primitive.Types (SlotNo (..))
import Cardano.Wallet.Primitive.Types.Coin (Coin (..))
import Cardano.Wallet.Primitive.Types.Hash (Hash (..))
import Cardano.Wallet.Primitive.Types.Tx.TxMeta (Direction (Outgoing))
import Cardano.Wallet.DB.Store.Submissions.Operations (SubmissionMeta (..))
import Cardano.Wallet.Submissions.Submissions (TxStatusMeta (..))
import qualified Cardano.Wallet.DB.Sqlite.Types as DB
import qualified PatchedSubmissionLayer as Layer
import qualified Cardano.Wallet.Submissions.Operations as Operations
import qualified Cardano.Wallet.Submissions.TxStatus as Status
import qualified Cardano.Wallet.Primitive.Types.Tx as Wallet
import qualified Cardano.Wallet.Read.Eras as Era
import qualified Cardano.Wallet.Read.Hash as ReadHash
import qualified Cardano.Wallet.Read.Tx as ReadTx
import qualified Data.ByteArray.Encoding as Base
import qualified Data.ByteString.Lazy as BL
import qualified Data.Text.Encoding as Text

decodeHex :: Text -> Parser ByteString
decodeHex = either (const $ fail "invalid hex") pure . Base.convertFromBase Base.Base16 . Text.encodeUtf8

statusName :: Status.TxStatus slot tx -> Text
statusName Status.InSubmission{} = "pending"
statusName Status.InLedger{} = "in_ledger"
statusName Status.Expired{} = "expired"
statusName Status.Unknown = "unknown"

probe :: Value -> Parser Value
probe = withObject "submission race diagnostic" $ \input -> do
    raw <- input .: "cbor_hex" >>= decodeHex
    claimed <- input .: "transaction_id" >>= decodeHex
    expiry <- input .: "expiry" :: Parser Word64
    acceptance <- input .: "acceptance" :: Parser Word64
    tip <- input .: "tip" :: Parser Word64
    retry <- input .: "retry_slot" :: Parser Word64
    unless (BL.length (BL.fromStrict raw) <= 1024 * 1024 && acceptance > 0 && acceptance <= tip && tip < expiry && retry < expiry) $ fail "invalid bounds"
    sealed <- either (const $ fail "invalid signed transaction") pure $ Wallet.sealedTxFromBytes raw
    let actual = case Wallet.unsafeReadTx sealed of
            Era.EraValue tx -> ReadHash.hashToBytes $ ReadTx.hashFromTxId $ ReadTx.getTxId tx
    unless (actual == claimed) $ fail "transaction hash differs"
    let transactionId = Hash actual
        databaseId = DB.TxId transactionId
        meta = SubmissionMeta (SlotNo 0) (Quantity 0) (Coin 0) Outgoing (SlotNo 0)
        pending = Operations.applyOperations
            (Operations.AddSubmission (SlotNo expiry) (databaseId, sealed) meta)
            Layer.emptyTxSubmissions
        confirmed = apply (Layer.rollForwardTxSubmissions (SlotNo tip) [(SlotNo acceptance, transactionId)]) pending
        delayed = Layer.resubmitTx transactionId (SlotNo retry) confirmed
        after = apply delayed confirmed
        ordinary = apply (Layer.resubmitTx transactionId (SlotNo retry) pending) pending
        describe state = maybe "unknown" (statusName . _txStatus) $ Layer.getInSubmissionTransaction transactionId state
    pure $ object
        [ "counts_as_conformance_evidence" .= False
        , "transaction_id" .= (Text.decodeUtf8 $ Base.convertToBase Base.Base16 actual)
        , "before_delayed_bookkeeping" .= describe confirmed
        , "after_delayed_bookkeeping" .= describe after
        , "pending_control_after_bookkeeping" .= describe ordinary
        , "delayed_bookkeeping_operations" .= length delayed
        ]

main :: IO ()
main = do
    input <- BL.getContents
    unless (BL.length input <= 3 * 1024 * 1024) $ fail "input too large"
    value <- either fail pure $ eitherDecode input
    result <- either fail pure $ parseEither probe value
    BL.putStr $ encode result
