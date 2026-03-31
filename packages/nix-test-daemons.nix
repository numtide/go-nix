# Builds a directory of versioned Nix daemon binaries for integration testing.
#
# Output structure:
#   $out/nix-<version>/bin/nix -> /nix/store/...-nix-<version>/bin/nix
#
# Each subdirectory contains a single nix binary, allowing the Go test harness
# to discover and iterate over multiple daemon versions.
{
  pkgs,
  pname,
  inputs,
  system,
}:
let
  pkgs-24-05 = import inputs.nixpkgs-24-05 { inherit system; };

  # collect all nix_2_* versions from a package set, skipping removed packages.
  # the regex requires >= 2 digits in the minor version, which excludes nix 2.3
  # through 2.9 — all of which predate the `nix daemon` subcommand.
  collectVersions =
    nixVersions:
    let
      names = builtins.filter (n: builtins.match "nix_2_[0-9][0-9]+" n != null) (
        builtins.attrNames nixVersions
      );
      tryPkg =
        n:
        let
          v = builtins.tryEval nixVersions.${n};
        in
        if v.success then [ v.value ] else [ ];
    in
    builtins.concatMap tryPkg names;

  allPkgs = collectVersions pkgs-24-05.nixVersions ++ collectVersions pkgs.nixVersions;

  # deduplicate by version string
  seen = builtins.foldl' (
    acc: pkg: if builtins.hasAttr pkg.version acc then acc else acc // { ${pkg.version} = pkg; }
  ) { } allPkgs;

  versions = map (version: {
    name = "nix-${version}";
    pkg = seen.${version};
  }) (builtins.sort builtins.lessThan (builtins.attrNames seen));
in
pkgs.runCommand pname { } (
  builtins.concatStringsSep "\n" (
    map (v: ''
      mkdir -p $out/${v.name}/bin
      ln -s ${v.pkg}/bin/nix $out/${v.name}/bin/nix
    '') versions
  )
  + ''
    mkdir -p $out/nix-support
    cat > $out/nix-support/setup-hook <<EOF
    export NIX_TEST_DAEMONS_DIR=$out
    EOF
  ''
)
