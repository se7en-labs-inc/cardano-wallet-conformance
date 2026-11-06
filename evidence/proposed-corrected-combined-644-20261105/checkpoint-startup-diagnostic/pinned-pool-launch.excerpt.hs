                        $ MsgDebug "waiting for stake pools to register"
                    replicateM poolCount (readChan waitGroup)

            let onException :: SomeException -> ClusterM ()
                onException e = do
                    traceClusterLog
                        $ MsgDebug
                        $ "exception while starting pool: "
                            <> T.pack (show e)
                    writeChan waitGroup (Left e)

            let mkConfig (port, peers) =
                    NodeParams
                        genesisFiles
                        cfgLastHardFork
                        (port, peers)
                        cfgNodeLogging
                        cfgNodeOutputFile
                        NothingK
            asyncs <- forM (zip (NE.toList configuredPools) ports)
                $ \(configuredPool, (port, peers)) -> do
                    async $ handle onException $ do
                        let cfg = mkConfig (port, peers)
                        operatePool configuredPool cfg
                            $ do
                                writeChan waitGroup $ Right ()
                                readChan doneGroup
            mapM_ link asyncs
            let cancelAll = do
                    traceWith cfgTracer $ MsgDebug "Stopping all stake pools"
                    replicateM_ poolCount (writeChan doneGroup ())
                    mapM_ wait asyncs
                    traceWith cfgTracer $ MsgDebug "All stake pools are down"

            traceClusterLog $ MsgRegisteringStakePools poolCount
            group <- waitAll
            if length (filter isRight group) /= poolCount
                then do
                    liftIO cancelAll
                    let errors = show (filter isLeft group)
