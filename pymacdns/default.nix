{ lib, buildPythonPackage, setuptools, anyio, dnspython, h2, httpx, pydantic, pydantic-settings, pyobjc-framework-SystemConfiguration, pytestCheckHook, trustme }:

buildPythonPackage {
  pname = "pymacdns";
  version = "0.1.0";
  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../pyproject.toml
      ../README.md
      ../src
      ../tests
    ];
  };
  pyproject = true;
  build-system = [ setuptools ];
  dependencies = [ anyio dnspython h2 httpx pydantic pydantic-settings pyobjc-framework-SystemConfiguration ];
  pythonImportsCheck = [ "pymacdns" ];
  # The suite runs the real daemon on loopback high ports, so a daemon
  # that crashes under load fails the build instead of reaching launchd.
  nativeCheckInputs = [ pytestCheckHook trustme ];
  __darwinAllowLocalNetworking = true;
  meta = {
    description = "macOS DNS forwarder respecting DHCP upstreams";
    license = lib.licenses.asl20;
    mainProgram = "pymacdns";
  };
}
