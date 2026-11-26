{
  description = "Read Apple Passwords on Linux";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  # Flake sources drop git submodules, so fetch the pinned OpenTUI tree and
  # place it back before Cargo builds the native library.
  inputs.opentui = {
    url = "git+https://github.com/anomalyco/opentui?rev=4ea9c4035286e6d6eb75784ed21c52a9375c7035";
    flake = false;
  };

  outputs = { self, nixpkgs, opentui }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      eachSystem = f:
        nixpkgs.lib.genAttrs systems
          (system: f nixpkgs.legacyPackages.${system});

      version = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).package.version;

      anisette-server = pkgs: pkgs.callPackage ./packaging/nix/anisette-server.nix { };

      apw = pkgs: pkgs.rustPlatform.buildRustPackage {
        pname = "apw";
        inherit version;

        src = pkgs.runCommandLocal "apw-src-${version}" { } ''
          cp -r ${./.} $out
          chmod -R u+w $out
          rm -rf $out/opentui
          cp -r ${opentui} $out/opentui
        '';

        cargoLock.lockFile = ./Cargo.lock;

        # nixpkgs asks aws-lc-sys to link a system AWS-LC that this closure
        # does not provide. Build it from source instead.
        AWS_LC_SYS_USE_SYSTEM = "0";
        nativeBuildInputs = with pkgs; [ cmake perl pkg-config zig ];
        buildInputs = with pkgs; [ dbus ];
        preBuild = ''
          export AWS_LC_SYS_USE_SYSTEM=0
          # Zig needs a writable HOME for its global cache; the build sandbox
          # runs with HOME=/homeless-shelter, which is not writable.
          export HOME=$TMPDIR
          export ZIG_GLOBAL_CACHE_DIR=$TMPDIR/zig-global-cache
        '';

        # The CLI tests need a CA store, which the build sandbox does not have.
        # CI runs them on a normal runner.
        doCheck = false;

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
        anisette-server = anisette-server pkgs;
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
            cmake
            perl
            pkg-config
            dbus
            zig
          ];
        };
      });
    };
}
