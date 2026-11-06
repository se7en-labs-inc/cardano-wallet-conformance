                    $ randomUnusedTCPPorts (length cfgStakePools + 1)

            let pool0port :| poolPorts = NE.fromList (rotate poolsTcpPorts)
            let pool0 :| otherPools = configuredPools

            contT_
                $ operatePool pool0
                $ NodeParams
                    genesisFiles
                    cfgLastHardFork
                    pool0port
                    cfgNodeLogging
                    cfgNodeOutputFile
                    NothingK

            let relayNodeParams =
                    NodeParams
                        { nodeGenesisFiles = genesisFiles
                        , nodeHardForks = cfgLastHardFork
                        , nodePeers = (extraPort, poolsTcpPorts)
                        , nodeLogConfig =
                            LogFileConfig
                                { minSeverityTerminal = Info
                                , extraLogDir = Nothing
                                , minSeverityFile = Info
                                }
                        , nodeParamsOutputFile =
                            cfgNodeOutputFile
                        , nodeSocket = JustK cfgNodeToClientSocket
                        }
            relayNode <-
                ContT $ withRelayNode relayNodeParams cfgRelayNodePath
            lift $ extraClusterSetupUsingNode configuredPools relayNode

            case NE.nonEmpty otherPools of
                Nothing -> liftIO $ onClusterStart relayNode
                Just others -> do
                    ContT $ \k -> do
                        debug "Starting pools"
                        r <-
                            launchPools
                                others
                                genesisFiles
                                poolPorts
                                $ k ()
                        debug "Pools are down"
