{inputs, ...}: {
  perSystem = {
    inputs',
    system,
    config,
    lib,
    pkgs,
    ...
  }: let
    toolchain = with inputs'.fenix.packages;
      combine [
        stable.rustc
        stable.cargo
        stable.clippy
        stable.rustfmt
      ];

    craneLib = (inputs.crane.mkLib pkgs).overrideToolchain toolchain;

    src = lib.fileset.toSource {
      root = ./..;
      fileset = lib.fileset.unions [
        ../Cargo.lock
        ../Cargo.toml
        ../src
        ../fixtures
        ../tests
        ../reference/HaskellAdapter.hs
        ../reference/WalletCredentialAdapter.hs
        ../reference/credential-faults.rs
        ../reference/KeyAdapter.hs
        ../reference/MnemonicAdapter.hs
        ../reference/AddressAdapter.hs
        ../reference/LedgerAdapter.hs
        ../reference/BalanceAdapter.hs
        ../reference/SlottingAdapter.hs
        ../reference/FeeAdapter.hs
        ../reference/SizeAdapter.hs
        ../reference/WitnessCountAdapter.hs
        ../reference/WriterAdapter.hs
        ../reference/MetadataAdapter.hs
        ../reference/SelectionAdapter.hs
        ../reference/wallet-toolchain.nix
        ../docs/adapter.md
        ../docs/live-contracts.md
      ];
    };

    # Extract pname and version from Cargo.toml
    crateInfo = craneLib.crateNameFromCargoToml {cargoToml = ../Cargo.toml;};

    commonArgs = {
      inherit src;
      inherit (crateInfo) pname version;
      strictDeps = true;

      nativeBuildInputs = with pkgs; [
        pkg-config
      ];

      meta = {
        mainProgram = crateInfo.pname;
        maintainers = with lib.maintainers; [
          disassembler
        ];
        license = with lib.licenses; [
          asl20
        ];
      };
    };

    # Build dependencies separately for better caching
    cargoArtifacts = craneLib.buildDepsOnly commonArgs;
  in {
    checks = {
      credential-faults =
        pkgs.runCommand "credential-fault-tests" {
          nativeBuildInputs = [toolchain pkgs.stdenv.cc];
          src = ../reference/credential-faults.rs;
        } ''
          rustc --edition=2021 --crate-name credential_faults --crate-type=staticlib -C panic=abort -O -D warnings "$src" -o libcredential_faults.a
          rustc --edition=2021 --crate-name credential_faults --test -D warnings "$src" -o credential-fault-tests
          ./credential-fault-tests
          touch "$out"
        '';
      clippy = craneLib.cargoClippy (commonArgs
        // {
          inherit cargoArtifacts;
          cargoClippyExtraArgs = "--all-targets -- --deny warnings";
        });

      fmt = craneLib.cargoFmt {inherit src;};
    };

    packages = {
      default = config.packages.${crateInfo.pname};

      ${crateInfo.pname} = craneLib.buildPackage (commonArgs
        // {
          inherit cargoArtifacts;
          doCheck = true;
        });
    };
  };
}
