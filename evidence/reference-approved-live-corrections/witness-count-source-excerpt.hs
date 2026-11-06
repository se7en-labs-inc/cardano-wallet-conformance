FIXME [ADP-1515] Improve estimation

NOTE: Similar to 'estimateTransactionKeyWitnessCount' from cardano-api, which
we cannot use because it requires a 'TxBodyContent BuildTx era'.
-}
estimateKeyWitnessCounts
    :: forall era
     . (IsRecentEra era)
    => UTxO era
    {- ^ Must contain all inputs from the 'TxBody' or
    'estimateKeyWitnessCounts will 'error'.
    -}
    -> Tx era
    -> TimelockKeyWitnessCounts
    {- ^ Specifying the intended number of timelock script key witnesses may
    save space and fees when constructing a transaction.

    Timelock scripts without entries in this map will have their key witness
    counts estimated according to 'estimateMaxWitnessRequiredPerInput'.
    -}
    -> KeyWitnessCounts
estimateKeyWitnessCounts utxo tx timelockKeyWitCounts =
    nonInputWits <> inputWits
  where
    txBody = tx ^. bodyTxL
    allInputs =
        Set.toList (txBody ^. inputsTxBodyL)
            <> Set.toList
                (txBody ^. collateralInputsTxBodyL)
    vkInsUnique =
        L.nub $
            filter (not . hasScriptCred utxo) allInputs
    nExtraKeyWits =
        Set.size (txBody ^. Alonzo.reqSignerHashesTxBodyG)
    Withdrawals wdrlMap =
        txBody ^. withdrawalsTxBodyL
    nKeyWithdrawals =
        length
            $ filter isKeyHashWithdrawal
            $ Map.keys wdrlMap
    certs = F.toList (txBody ^. certsTxBodyL)
    nCertWits =
        sumVia estimateDelegSigningKeys certs
    nonInputWits =
        numberOfShelleyWitnesses
            $ fromIntegral
            $ nExtraKeyWits
                + nKeyWithdrawals
                + fromIntegral nCertWits
                + fromIntegral timelockTotalWitCount
    inputWits =
        KeyWitnessCounts
            { nKeyWits =
                fromIntegral
                    . length
                    $ filter
                        (not . hasBootstrapAddr utxo)
                        vkInsUnique
            , nBootstrapWits =
                fromIntegral
