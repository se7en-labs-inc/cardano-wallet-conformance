{
  walletFlake,
  system ? "x86_64-linux",
}: let
  wallet = builtins.getFlake walletFlake;
  project = wallet.legacyPackages.${system};
in
  assert (wallet.rev or null) == "2fc5c383c94bb907deaa0cd27b1b407f86224b6c";
    project.ghcWithPackages (packages: [
      packages.cardano-wallet
      packages.cardano-wallet-unit.components.sublibs.test-common
    ])
