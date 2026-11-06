defaultPoolConfigs :: NonEmpty PoolRecipe
defaultPoolConfigs =
    NE.zipWith (\i p -> p{index = i}) (1 :| [2 ..])
        $
        -- This pool should never retire:
        PoolRecipe
            { pledgeAmt = 150 * millionAda
            , retirementEpoch = Nothing
            , poolMetadata =
                Aeson.object
                    [ "name" .= Aeson.String "Genesis Pool A"
                    , "ticker" .= Aeson.String "GPA"
                    , "description" .= Aeson.Null
                    , "homepage" .= Aeson.String "https://iohk.io"
                    ]
