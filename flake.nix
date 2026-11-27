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

        nativeBuildInputs = with pkgs; [ patchelf pkg-config zig ];
        buildInputs = with pkgs; [ dbus ];
        # The nixpkgs Zig hook claims buildPhase and runs `zig build` at the
        # source root. apw has no root build.zig; its build script drives Zig.
        dontUseZigBuild = true;
        dontUseZigCheck = true;
        dontUseZigInstall = true;
        dontUseZigConfigure = true;
        preBuild = ''
          # Zig needs a writable HOME for its global cache; the build sandbox
          # runs with HOME=/homeless-shelter, which is not writable.
          export HOME=$TMPDIR
          export ZIG_GLOBAL_CACHE_DIR=$TMPDIR/zig-global-cache
        '';

        # The CLI tests need a CA store, which the build sandbox does not have.
        # CI runs them on a normal runner.
        doCheck = false;

        postInstall = ''
          lib=$(find . -path '*/opentui/packages/native/lib/*/libopentui.so' -print -quit)
          if [ -z "$lib" ]; then
            echo "libopentui.so was not built" >&2
            exit 1
          fi
          install -Dm755 "$lib" "$out/lib/apw/libopentui.so"
          # The cargo install hook also copies the build-tree library here.
          rm -f "$out/lib/libopentui.so"
          strip --strip-unneeded "$out/bin/apw" "$out/lib/apw/libopentui.so"
        '';

        # Nix's fixup strip keeps the symbol table. Strip fully here, then put
        # the relative runpath back after the fixup shrinks it away.
        dontStrip = true;
        postFixup = ''
          rpath=$(patchelf --print-rpath "$out/bin/apw")
          case ":$rpath:" in
            *':$ORIGIN/../lib/apw:'*) ;;
            *) patchelf --add-rpath '$ORIGIN/../lib/apw' "$out/bin/apw" ;;
          esac
        '';

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
            pkg-config
            dbus
            zig
          ];
        };
      });
    };
}
