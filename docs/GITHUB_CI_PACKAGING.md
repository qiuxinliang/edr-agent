# GitHub CI and Windows Packaging

This repository is intended to be uploaded with `edr-agent` as the GitHub
repository root. The workflows under `.github/workflows` therefore use `cmake
-S .`, not `cmake -S edr-agent`.

## Why package builds disable gRPC

The Windows installer job builds the production installer and should be fast and
repeatable. It explicitly disables optional heavy dependencies:

- `EDR_WITH_GRPC=OFF`
- `EDR_WITH_YARA=OFF`
- `EDR_WITH_ONNXRUNTIME=OFF`
- `EDR_WITH_FL_TRAINER=OFF`

This keeps the package job on the native HTTPS/REST transport and builtin
fallback detectors. gRPC is still supported, but it is validated in the separate
`gRPC Smoke` workflow on Ubuntu using packaged system dependencies. That
workflow sets `EDR_REQUIRE_GRPC=ON`, so it fails if CMake cannot find the real
`gRPC::grpc++` target. Avoid using Windows vcpkg gRPC in the installer workflow
because building gRPC and its dependency graph from source can take hours on
GitHub-hosted runners.

## CMake project declaration

When a project declares `VERSION`, `DESCRIPTION`, or `HOMEPAGE_URL`, CMake
requires language names to appear after the `LANGUAGES` keyword:

```cmake
project(edr_agent
  VERSION 0.1.0
  DESCRIPTION "EDR endpoint agent"
  LANGUAGES C CXX
)
```

The invalid form is:

```cmake
project(edr_agent VERSION 0.1.0 C CXX)
```

That invalid form causes the GitHub error:

```text
project with VERSION, DESCRIPTION or HOMEPAGE_URL must use LANGUAGES before language names.
```

## Recommended workflow split

- `Agent CI`: fast Linux/macOS/Windows build and tests without gRPC.
- `gRPC Smoke`: manual and weekly Ubuntu gRPC build using `apt` packages.
- `Publish Windows Setup EXE`: Windows installer only, no gRPC/vcpkg.

If a Windows gRPC artifact is required later, create a separate manual workflow
with vcpkg binary cache enabled. Do not add it to the installer path.
