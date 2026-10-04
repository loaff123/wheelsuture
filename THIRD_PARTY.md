# Third-party notices

WheelSuture original code, fixtures and documentation are MIT licensed. No pip, installer or packaging implementation is vendored in runtime code.

- Runtime: packaging 26.3, Apache-2.0 OR BSD-2-Clause. License texts are in licenses/packaging-LICENSE, packaging-LICENSE.APACHE and packaging-LICENSE.BSD. Official source: https://github.com/pypa/packaging
- Development mapping oracle: PyPA installer 0.7.0, MIT. Official source: https://github.com/pypa/installer. Its pinned downloaded wheel and license receipt remain in separate qualification evidence, not the installed WheelSuture package
- Real installer oracle: official pip 26.2.1 / CPython 3.12.14, used only on original inert generated fixtures. These implementations are not copied into WheelSuture
- Build/test tooling: setuptools, wheel, build, pyproject-hooks, jsonschema and Python unittest; none is a runtime WheelSuture dependency

Downloaded official build-tool wheel hashes are recorded in qualification/package-toolchain-sha256.json. Package contents do not include disposable environments, downloaded third-party wheels, caches, secrets, or external package payloads.
