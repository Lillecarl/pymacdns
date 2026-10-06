{ lib, buildPythonPackage, setuptools, anyio, dnspython, pyobjc-framework-SystemConfiguration }:

buildPythonPackage {
  pname = "pymacdns";
  version = "0.1.0";
  src = ../.;
  pyproject = true;
  build-system = [ setuptools ];
  dependencies = [ anyio dnspython pyobjc-framework-SystemConfiguration ];
  pythonImportsCheck = [ "pymacdns" ];
  meta = {
    description = "macOS DNS forwarder respecting DHCP upstreams";
    license = lib.licenses.mit;
  };
}
