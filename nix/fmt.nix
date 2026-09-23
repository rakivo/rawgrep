{...}: {
  perSystem = {...}: {
    treefmt.config = {
      projectRootFile = "flake.nix";

      # Nix only: rustfmt.toml opts out of Rust formatting, and Cargo.toml is hand-aligned.
      programs.alejandra.enable = true;
    };
  };
}
