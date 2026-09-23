{inputs, ...}: {
  perSystem = {system, ...}: let
    pkgs = import inputs.nixpkgs {
      inherit system;
      overlays = [inputs.rust-overlay.overlays.default];
    };

    rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ../rust-toolchain.toml;

    craneLib = (inputs.crane.mkLib pkgs).overrideToolchain (_: rustToolchain);

    # Force rustc onto wild (Linux/ELF only). rustc defaults to self-contained
    # lld; disable it and point gcc at wild's `ld` via -B (gcc 15 rejects
    # -fuse-ld=wild). Proof: `readelf -p .comment result/bin/cli` -> "Linker: Wild".
    # When nixpkgs' default gcc reaches 16, collapse to "-C link-arg=-fuse-ld=wild".
    wildRustflags =
      if pkgs.stdenv.hostPlatform.isLinux
      then "-C linker-features=-lld -C link-self-contained=-linker -C link-arg=-B${pkgs.wild}/bin"
      else "";
  in {
    _module.args = {
      inherit pkgs rustToolchain craneLib wildRustflags;
    };
  };
}
