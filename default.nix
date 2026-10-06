{
  pkgs ? import <nixpkgs> { },
}:
let
  pyobjc-framework-SystemConfiguration =
    pkgs.python3Packages.callPackage ./nix/pyobjc-framework-SystemConfiguration { };
in
{
  inherit pyobjc-framework-SystemConfiguration;

  pymacdns = pkgs.python3Packages.callPackage ./pymacdns {
    inherit pyobjc-framework-SystemConfiguration;
  };

  shell = pkgs.mkShell {
    packages = [
      (pkgs.python3.withPackages (ps: [
        ps.anyio
        ps.dnspython
        # dnspython gates DoH on importlib.metadata: httpx, httpcore and
        # h2 must all be importable with distributions, not just modules.
        ps.h2
        ps.httpx
        ps.pydantic
        ps.pydantic-settings
        ps.pytest
        ps.trustme
        pyobjc-framework-SystemConfiguration
      ]))
      pkgs.ruff
    ];
  };
}
