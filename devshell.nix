{
  perSystem,
  pkgs,
  ...
}:
perSystem.self.gonix.passthru.tests.integration.overrideAttrs (old: {
  doCheck = false;

  env = old.env // {
    GOROOT = "${old.passthru.go}/share/go";
  };

  nativeBuildInputs =
    old.nativeBuildInputs
    ++ (with pkgs; [
      delve
      golangci-lint
      gotools
      lazysql
      pprof
      sqlc
    ]);

  shellHook = ''
    # these are only needed for hermetic builds
    unset GO_NO_VENDOR_CHECKS GOSUMDB GOPROXY GOFLAGS
  '';
})
