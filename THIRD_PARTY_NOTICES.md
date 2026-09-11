# Third-party notices

This project distributes the runtime dependency set recorded in `requirements-runtime.lock`. The lock file, the installed package metadata, and each dependency's upstream license file are authoritative for the exact release.

| Package | Locked version | License / notice | Upstream |
| --- | --- | --- | --- |
| cryptography | 50.0.1 | Apache-2.0 OR BSD-3-Clause | https://github.com/pyca/cryptography |
| cffi | 2.1.1 | MIT | https://github.com/python-cffi/cffi |
| pycparser | 2.21 | BSD-3-Clause | https://github.com/eliben/pycparser |

`requirements-build.lock` and `requirements-ci.lock` contain development and CI tools. They are not runtime package dependencies; their exact licenses remain discoverable from the pinned distributions and are not copied into the application runtime.

No third-party image, font, model weight, prompt collection, or client dataset is bundled by this repository. GitHub Action references are pinned to immutable commits in the workflow files.
