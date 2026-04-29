{
  description = "zig-crypto — Portable cryptographic primitives in Zig";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
  };

  outputs = inputs @ { flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" ];

      perSystem = { pkgs, system, ... }:
        let
          zigVersion = "0.15.2";
          zigTargets = {
            aarch64-darwin = {
              name = "aarch64-macos";
              hash = "sha256-PMK6s2fhhc37J1AcSzCxsGU8KNn3PfjckUiOZuzl+ms=";
            };
            aarch64-linux = {
              name = "aarch64-linux";
              hash = "sha256-lY7X0eANDqdlkNJ2Zu+/epMigbPXugxrAbD/JkmPZn8=";
            };
            x86_64-linux = {
              name = "x86_64-linux";
              hash = "sha256-AqonDxg9onbltZILHaxEpj8aSeVQUOveOuzJ64L5Mjk=";
            };
          };
          zigTarget = zigTargets.${system} or (throw "zig-crypto flake does not provide Zig ${zigVersion} for ${system}");
          zig = pkgs.stdenv.mkDerivation {
            pname = "zig";
            version = zigVersion;
            src = pkgs.fetchurl {
              url = "https://ziglang.org/download/${zigVersion}/zig-${zigTarget.name}-${zigVersion}.tar.xz";
              hash = zigTarget.hash;
            };
            nativeBuildInputs = [ pkgs.gnutar pkgs.xz ];
            dontConfigure = true;
            dontBuild = true;
            installPhase = ''
              mkdir -p $out/bin $out/lib/zig
              tar -xJf $src --strip-components=1 -C $out/lib/zig
              ln -s $out/lib/zig/zig $out/bin/zig
            '';
          };
        in
        {
          devShells.default = pkgs.mkShell {
            packages = [
              zig
              pkgs.just
              pkgs.python3Packages.detect-secrets
              pkgs.pre-commit
            ];

            shellHook = ''
              echo "zig-crypto dev shell — zig $(zig version 2>/dev/null || echo 'not found')"
            '';
          };

          packages.default = pkgs.stdenv.mkDerivation {
            pname = "zig-crypto";
            version = "0.1.0";
            src = ./.;

            nativeBuildInputs = [ zig ];

            dontConfigure = true;

            buildPhase = ''
              export XDG_CACHE_HOME="$TMPDIR/zig-cache"
              zig build -Doptimize=ReleaseFast --prefix $out
            '';

            installPhase = ''
              mkdir -p $out/include
              cp include/zig_crypto.h $out/include/
            '';
          };
        };
    };
}
