{
  description = "rawgrep";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    crane.url = "github:ipetkov/crane";
  };

  outputs = {
    nixpkgs,
      crane,
      flake-utils,
      ...
  }:
    flake-utils.lib.eachDefaultSystem (system: let
      pkgs = nixpkgs.legacyPackages.${system};
      craneLib = crane.mkLib pkgs;

      src = craneLib.cleanCargoSource ./.;

      commonArgs = {
        inherit src;
        strictDeps = true;

        nativeBuildInputs = [
          pkgs.capnproto
        ];

        buildInputs = [];
      };

      cargoArtifacts = craneLib.buildDepsOnly commonArgs;

      rawgrep = craneLib.buildPackage (commonArgs // {
        inherit cargoArtifacts;

        meta = with pkgs.lib; {
          description = "The fastest grep in the world";
          homepage = "https://github.com/rakivo/rawgrep";
          license = licenses.mit;
          maintainers = [];
        };
      });
    in {
      packages.default = rawgrep;

      apps.default = {
        type = "app";
        program = "${rawgrep}/bin/rawgrep";
        meta.description = "Run rawgrep";
      };

      devShells.default = pkgs.mkShell {
        inputsFrom = [rawgrep];

        buildInputs = with pkgs; [
          rustc
          cargo
          rust-analyzer
          rustfmt
          clippy
        ];
      };
    });
}
