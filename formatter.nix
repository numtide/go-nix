{
  pkgs,
  inputs,
  ...
}:
inputs.treefmt-nix.lib.mkWrapper pkgs {
  projectRootFile = ".git/config";

  programs = {
    # nix
    nixfmt.enable = true;
    deadnix.enable = true;
    statix.enable = true;

    # go
    gofumpt.enable = true;

    # shell
    shellcheck.enable = true;
    shfmt.enable = true;

    # yaml
    yamlfmt.enable = true;
    yamlfmt.settings.formatter = {
      type = "basic";
      indent = 2;
      retain_line_breaks = true;
    };
  };

  settings = {
    global.excludes = [
      "LICENSE"
      ".gitattributes"
      "test/testdata/*"
      # unsupported extensions
      "*.{gif,png,svg,tape,mts,lock,mod,sum,toml,env,envrc,gitignore,sql}"
    ];

    formatter = {
      # nix
      deadnix.pipeline = "nix";
      deadnix.priority = 1;
      statix.pipeline = "nix";
      statix.priority = 2;
      nixfmt.pipeline = "nix";
      nixfmt.priority = 3;

      # shell
      shellcheck.pipeline = "shell";
      shellcheck.includes = [
        "*.sh"
        "*.bash"
        "*.envrc"
        "*.envrc.*"
        "bin/*"
      ];
      shellcheck.options = [
        "-e"
        "SC2155" # Disable check for declare and assign in same command
      ];
      shellcheck.priority = 1;
      shfmt.pipeline = "shell";
      shfmt.includes = [
        "*.sh"
        "*.bash"
        "*.envrc"
        "*.envrc.*"
        "bin/*"
      ];
      shfmt.priority = 2;

      # yaml
      yamlfmt.pipeline = "yaml";
      yamlfmt.priority = 1;
    };
  };
}
