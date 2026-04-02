{
  pkgs,
  flake,
  pname,
  perSystem,
  ...
}:
let
  inherit (pkgs) lib;
  fs = lib.fileset;
in
pkgs.buildGo126Module (final: {
  inherit pname;

  # there's no good way of tying in the version to a git tag or branch
  # so for simplicity's sake we set the version as the commit revision hash
  # we remove the `-dirty` suffix to avoid a lot of unnecessary rebuilds in local dev
  version = lib.removeSuffix "-dirty" (flake.shortRev or flake.dirtyShortRev);

  src = fs.toSource {
    root = ../.;
    fileset = fs.unions [
      ../cmd
      ../pkg
      ../test
      ../.golangci.yml
      ../go.mod
      ../go.sum
    ];
  };

  vendorHash = "sha256-FT0ckssWx7aIhqvoMGVi4au9EEg0xfU1xMHhbJ2f7sA=";

  env.GOTOOLCHAIN = "local";

  ldflags = [
    "-s"
    "-w"
  ];

  passthru = {
    no-vendor-hash = final.overrideAttrs {
      vendorHash = "";
    };

    update-vendor-hash = pkgs.writeShellApplication {
      name = "update-vendor-hash";
      runtimeInputs = with pkgs; [
        nix
        coreutils
        gnused
        gawk
      ];
      text = ''
        ROOT_DIR=''${1:-.}

        FAILED_BUILD=$(nix build .#${pname}.no-vendor-hash 2>&1 || true)
        echo "$FAILED_BUILD"
        CHECKSUM=$(echo "$FAILED_BUILD" | awk '/got:.*sha256/ { print $2 }')

        # only replace the first entry in the file so we don't break no-vendor-hash
        sed -i -e "0,/vendorHash = \".*\"/s|vendorHash = \".*\"|vendorHash = \"$CHECKSUM\"|" "$ROOT_DIR/packages/gonix.nix"
      '';
    };

    tests = {
      benchmark = final.overrideAttrs (_old: {
        checkFlags = [
          "-race"
          "-bench=.+"
        ];

      });
      integration = final.overrideAttrs (old: {
        nativeBuildInputs = old.nativeBuildInputs ++ [ perSystem.self.nix-test-daemons ];

        buildPhase = ''
          go test -tags integration ./...
        '';

        installPhase = ''
          touch $out
        '';
      });
      golangci-lint = final.overrideAttrs (old: {
        nativeBuildInputs = old.nativeBuildInputs ++ [ pkgs.golangci-lint ];
        buildPhase = ''
          HOME=$TMPDIR
          golangci-lint run
        '';
        installPhase = ''
          touch $out
        '';
      });
    };
  };

  meta = with lib; {
    description = "gonix: elements of nix re-implemented as Go Libraries";
    homepage = "https://github.com/numtide/go-nix";
    license = licenses.asl20;
    mainProgram = "gonix";
  };
})
