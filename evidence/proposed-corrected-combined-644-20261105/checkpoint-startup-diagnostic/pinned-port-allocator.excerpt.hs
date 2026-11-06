
-- | Get a list of random TCPv4 ports that currently do not have any servers
-- listening on them. It may return less than the requested number of ports.
--
-- Note that this method of allocating ports is subject to race
-- conditions. Production code should use better methods such as passing a
-- listening socket to the child process.
randomUnusedTCPPorts :: Int -> IO [Int]
randomUnusedTCPPorts count = do
    usablePorts <- shuffleM [1024 .. 49151]
    sort <$> filterM unused (take count usablePorts)
  where
    unused =
        fmap not . isPortOpen . simpleSockAddr (127, 0, 0, 1) . fromIntegral
