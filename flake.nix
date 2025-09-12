{
  description = "A devShell example";

  inputs = {
    nixpkgs.url      = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url  = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };

	# Read the toolchain definition from the local toml file
        toolchainFileContents = builtins.fromTOML (builtins.readFile ./rust-toolchain.toml);

        # Extract the toolchain configuration section
        toolchainConfig = toolchainFileContents.toolchain;

        # Get the list of components specified in the file, or an empty list if none.
        baseComponents = toolchainConfig.components or [];

        # Extend the list of components to include rust-analyzer and its dependency, rust-src.
        # This ensures your LSP is from the same toolchain as your compiler, which is crucial for stability.
        extendedComponents = baseComponents ++ [ "rust-analyzer" "rust-src" ];

        # Build the final rust toolchain using the configuration from the file,
        # but with our extended list of components. The `fromRustupToolchain`
        # function is a powerful part of rust-overlay that handles this perfectly.
        rustToolchain = pkgs.rust-bin.fromRustupToolchain {
          channel = toolchainConfig.channel;
          components = extendedComponents;
          # Pass along targets if they are specified in the file
          targets = toolchainConfig.targets or [];
        };
      in
      {
        devShells.default = with pkgs; mkShell {
          buildInputs = [
            openssl
            pkg-config
            eza
            fd
            rustToolchain
          ];

          shellHook = ''
            alias ls=eza
            alias find=fd
          '';
        };
      }
    );
}
