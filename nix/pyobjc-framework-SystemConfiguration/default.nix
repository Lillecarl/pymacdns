{
  buildPythonPackage,
  darwin,
  lib,
  pyobjc-core,
  pyobjc-framework-Cocoa,
  setuptools,
}:

buildPythonPackage rec {
  pname = "pyobjc-framework-SystemConfiguration";
  pyproject = true;

  inherit (pyobjc-core) version src;

  sourceRoot = "${src.name}/pyobjc-framework-SystemConfiguration";

  build-system = [ setuptools ];

  buildInputs = [
    darwin.libffi
  ];

  nativeBuildInputs = [
    darwin.DarwinTools # sw_vers
  ];

  # Same sw_vers/xcrun path fix as the other pyobjc-framework packages.
  postPatch = ''
    substituteInPlace pyobjc_setup.py \
      --replace-fail "-buildversion" "-buildVersion" \
      --replace-fail "-productversion" "-productVersion" \
      --replace-fail "/usr/bin/sw_vers" "sw_vers" \
      --replace-fail "/usr/bin/xcrun" "xcrun"
  '';

  dependencies = [
    pyobjc-core
    pyobjc-framework-Cocoa
  ];

  env.NIX_CFLAGS_COMPILE = toString [
    "-I${darwin.libffi.dev}/include"
    "-Wno-error=unused-command-line-argument"
  ];

  pythonImportsCheck = [ "SystemConfiguration" ];

  meta = {
    description = "PyObjC wrapper for the SystemConfiguration framework on macOS";
    homepage = "https://github.com/ronaldoussoren/pyobjc/tree/main/pyobjc-framework-SystemConfiguration";
    license = lib.licenses.mit;
    platforms = lib.platforms.darwin;
  };
}
