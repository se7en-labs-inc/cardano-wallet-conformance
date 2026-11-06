{
  description = "Independent Cardano wallet conformance tests";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    flake-parts.url = "github:hercules-ci/flake-parts";
    crane.url = "github:ipetkov/crane";
    fenix.url = "github:nix-community/fenix";
    fenix.inputs.nixpkgs.follows = "nixpkgs";
    treefmt-nix.url = "github:numtide/treefmt-nix";
    treefmt-nix.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = {flake-parts, ...} @ inputs:
    flake-parts.lib.mkFlake {inherit inputs;} {
      # Explicit imports avoid recursive directory enumeration in the store.
      imports = [
        ./perSystem/devShells.nix
        ./perSystem/formatter.nix
        ./perSystem/packages.nix
        inputs.treefmt-nix.flakeModule
      ];
      systems = ["x86_64-linux"];
    };
}
