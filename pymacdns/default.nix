{ lib, buildPythonPackage, setuptools, anyio, dnspython, pydantic, pydantic-settings, pyobjc-framework-SystemConfiguration }:

buildPythonPackage {
  pname = "pymacdns";
  version = "0.1.0";
  src = ../.;
  pyproject = true;
  build-system = [ setuptools ];
  dependencies = [ anyio dnspython pydantic pydantic-settings pyobjc-framework-SystemConfiguration ];
  pythonImportsCheck = [ "pymacdns" ];
  meta = {
    description = "macOS DNS forwarder respecting DHCP upstreams";
    license = lib.licenses.mit;
    mainProgram = "pymacdns";
  };
}
