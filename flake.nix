{
  description = "rawgrep";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    crane.url = "github:ipetkov/crane";
  };

  outputs = {
    nixpkgs,
    crane,
    ...
  }: let
    supportedSystems = [ "x86_64-linux" "aarch64-linux" ];
    forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
    pkgsFor = system: nixpkgs.legacyPackages.${system};

    mkRawgrep = system: let
      pkgs = pkgsFor system;
      craneLib = crane.mkLib pkgs;
      src = craneLib.cleanCargoSource ./.;
      commonArgs = {
        inherit src;
        strictDeps = true;
        nativeBuildInputs = [ pkgs.capnproto ];
        buildInputs = [];
      };
      cargoArtifacts = craneLib.buildDepsOnly commonArgs;
    in craneLib.buildPackage (commonArgs // {
      inherit cargoArtifacts;
      meta = with pkgs.lib; {
        description = "The fastest grep in the world";
        homepage = "https://github.com/rakivo/rawgrep";
        license = licenses.mit;
        maintainers = [];
      };
    });
  in {
    packages = forAllSystems (system: {
      default = mkRawgrep system;
    });

    apps = forAllSystems (system: {
      default = {
        type = "app";
        program = "${mkRawgrep system}/bin/rawgrep";
        meta.description = "Run rawgrep";
      };
    });

    devShells = forAllSystems (system: let
      pkgs = pkgsFor system;
    in {
      default = pkgs.mkShell {
        inputsFrom = [ (mkRawgrep system) ];
        buildInputs = with pkgs; [
          rustc
          cargo
          rust-analyzer
          rustfmt
          clippy
        ];
      };
    });
  };
}
