{
  perSystem = {
    config,
    inputs',
    pkgs,
    ...
  }: {
    treefmt = {
      projectRootFile = "flake.nix";

      programs.alejandra.enable = true;
      programs.rustfmt = {
        enable = true;
        edition = "2021";
        package = inputs'.fenix.packages.stable.rustfmt;
      };
      programs.taplo.enable = true;

      settings.global.excludes = [
        "*.lock"
        "*.patch"
        ".gitattributes"
        ".gitignore"
        ".gitmodules"
        "LICENSE"
      ];
    };

    formatter = config.treefmt.build.wrapper;
  };
}
