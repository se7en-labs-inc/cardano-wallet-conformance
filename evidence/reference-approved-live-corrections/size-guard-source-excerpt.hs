      where
        guardTxSize
            :: KeyWitnessCounts
            -> Tx era
            -> ExceptT (ErrBalanceTx era) m (Tx era)
        guardTxSize witCount tx = do
            let maxSize = W.TxSize $ intCast (pp ^. ppMaxTxSizeL)
            let size = estimateSignedTxSize pp witCount tx
            when (size > maxSize) $
                throwE ErrBalanceTxMaxSizeLimitExceeded{size, maxSize}
            pure tx

        guardTxBalanced
            :: Tx era
            -> ExceptT (ErrBalanceTx era) m (Tx era)
        guardTxBalanced tx = do
            let bal = txBalance tx
            if bal == mempty
                then pure tx
                else
                    throwE
                        $ ErrBalanceTxInternalError
                        $ ErrFailedBalancing bal

        txBalance :: Tx era -> Value
        txBalance =
            evaluateTransactionBalance
                pp
                (lookupStakeKeyDeposit keyDeposits pp)
                utxoReference
                . view bodyTxL

        balanceAfterSettingMinFee
            :: Tx era
            -> ExceptT (ErrBalanceTx era) m (Value, Coin, KeyWitnessCounts)
        balanceAfterSettingMinFee tx = ExceptT . pure $ do
            let witCount =
                    estimateKeyWitnessCounts
                        utxoReference
                        tx
                        timelockKeyWitnessCounts
                minfee =
                    Convert.fromLedgerCoin $
                        estimateSignedTxMinFee pp utxoReference tx witCount
                update =
                    TxUpdate
                        { extraInputs = mempty
                        , extraCollateral = mempty
                        , extraOutputs = []
                        , extraInputScripts = []
                        , feeUpdate = UseNewTxFee minfee
                        }
