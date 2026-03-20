{
  perSystem,
  pkgs,
  ...
}:
pkgs.mkShell {
  env.GOROOT = "${pkgs.go}/share/go";

  packages =
    (with pkgs; [
      delve
      go
      golangci-lint
      gotools
      lazysql
      pprof
      sqlc
    ])
    ++ (with perSystem; [
      gomod2nix.default
    ]);
}
