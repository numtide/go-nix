{
  perSystem,
  pkgs,
  ...
}:
perSystem.self.gonix.overrideAttrs (old: {
  doCheck = false;

  env = old.env // {
    GOROOT = "${old.passthru.go}/share/go";
  };

  nativeBuildInputs =
    old.nativeBuildInputs
    ++ [
      perSystem.self.nix-test-daemons
    ]
    ++ (with pkgs; [
      delve
      golangci-lint
      gotools
      lazysql
      pprof
      sqlc
      nix-eval-jobs
    ]);

  shellHook = ''
    # these are only needed for hermetic builds
    unset GO_NO_VENDOR_CHECKS GOSUMDB GOPROXY GOFLAGS
  '';
})
