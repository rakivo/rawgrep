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
    mkRawgrep = system: let
      pkgs = nixpkgs.legacyPackages.${system};
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
    packages.x86_64-linux.default = mkRawgrep "x86_64-linux";
    packages.aarch64-linux.default = mkRawgrep "aarch64-linux";

    apps.x86_64-linux.default = {
      type = "app";
      program = "${mkRawgrep "x86_64-linux"}/bin/rawgrep";
      meta.description = "Run rawgrep";
    };
    apps.aarch64-linux.default = {
      type = "app";
      program = "${mkRawgrep "aarch64-linux"}/bin/rawgrep";
      meta.description = "Run rawgrep";
    };

    devShells.x86_64-linux.default = let
      pkgs = nixpkgs.legacyPackages.x86_64-linux;
    in pkgs.mkShell {
      inputsFrom = [ (mkRawgrep "x86_64-linux") ];
      buildInputs = with pkgs; [
        rustc
        cargo
        rust-analyzer
        rustfmt
        clippy
      ];
    };
    devShells.aarch64-linux.default = let
      pkgs = nixpkgs.legacyPackages.aarch64-linux;
    in pkgs.mkShell {
      inputsFrom = [ (mkRawgrep "aarch64-linux") ];
      buildInputs = with pkgs; [
        rustc
        cargo
        rust-analyzer
        rustfmt
        clippy
      ];
    };
  };
}
