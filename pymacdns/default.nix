{ lib, buildPythonPackage, setuptools, anyio, dnspython, h2, httpx, pydantic, pydantic-settings, pyobjc-framework-SystemConfiguration }:

buildPythonPackage {
  pname = "pymacdns";
  version = "0.1.0";
  src = ../.;
  pyproject = true;
  build-system = [ setuptools ];
  dependencies = [ anyio dnspython h2 httpx pydantic pydantic-settings pyobjc-framework-SystemConfiguration ];
  pythonImportsCheck = [ "pymacdns" ];
  meta = {
    description = "macOS DNS forwarder respecting DHCP upstreams";
    license = lib.licenses.asl20;
    mainProgram = "pymacdns";
  };
}
