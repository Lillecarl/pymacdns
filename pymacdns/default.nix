{ lib, buildPythonPackage, setuptools, anyio, dnspython }:

buildPythonPackage {
  pname = "pymacdns";
  version = "0.1.0";
  src = ../.;
  pyproject = true;
  build-system = [ setuptools ];
  dependencies = [ anyio dnspython ];
  pythonImportsCheck = [ "pymacdns" ];
  meta = {
    description = "macOS DNS forwarder respecting DHCP upstreams";
    license = lib.licenses.mit;
  };
}
