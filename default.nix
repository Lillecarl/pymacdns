{
  pkgs ? import <nixpkgs> { },
}:
{
  pymacdns = pkgs.python3Packages.callPackage ./pymacdns { };

  shell = pkgs.mkShell {
    packages = [
      (pkgs.python3.withPackages (ps: [
        ps.anyio
        ps.dnspython
      ]))
      pkgs.ruff
    ];
  };
}
