{
  description = "Read Apple Passwords on Linux";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      eachSystem = f:
        nixpkgs.lib.genAttrs systems
          (system: f nixpkgs.legacyPackages.${system});

      version = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).package.version;

      apw = pkgs: pkgs.rustPlatform.buildRustPackage {
        pname = "apw";
        inherit version;

        src = ./.;

        cargoLock.lockFile = ./Cargo.lock;

        meta = {
          description = "Read Apple Passwords on Linux";
          homepage = "https://github.com/win0na/apw";
          license = pkgs.lib.licenses.gpl3Only;
          mainProgram = "apw";
          platforms = [ "x86_64-linux" "aarch64-linux" ];
        };
      };
    in
    {
      packages = eachSystem (pkgs: {
        default = apw pkgs;
        apw = apw pkgs;
      });

      apps = eachSystem (pkgs: {
        default = {
          type = "app";
          program = "${apw pkgs}/bin/apw";
        };
      });

      devShells = eachSystem (pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [
            cargo
            rustc
            rustfmt
            clippy
          ];
        };
      });
    };
}
