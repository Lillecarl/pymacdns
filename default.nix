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
        ps.pydantic
        ps.pydantic-settings
        pyobjc-framework-SystemConfiguration
      ]))
      pkgs.ruff
    ];
  };
}
