# GitHub CI and Windows Packaging

This repository is intended to be uploaded with `edr-agent` as the GitHub
repository root. The workflows under `.github/workflows` therefore use `cmake
-S .`, not `cmake -S edr-agent`.

## Why package builds disable gRPC

The Windows installer job builds the production installer and should be fast and
repeatable. It explicitly disables legacy/heavy optional components while keeping
the endpoint detection stack intact:

- `EDR_WITH_GRPC=OFF`
- `EDR_WITH_YARA=ON`
- `EDR_REQUIRE_YARA=ON`
- `VCPKG_MANIFEST_FEATURES=yara`
- `EDR_WITH_FL_TRAINER=OFF`

This keeps the package job on the native HTTPS/REST transport while requiring
real libyara-backed scanning. The package must include both the vcpkg YARA
runtime/static package artifacts and the rule directories: `rules/forensic`,
`rules/shellcode`, and `rules/webshell`. gRPC is no longer part of the standard
Windows endpoint package path; avoid adding Windows vcpkg gRPC to the installer
workflow because building gRPC and its dependency graph from source can take
hours on GitHub-hosted runners.

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
- `Publish Windows Setup EXE`: Windows installer only, no gRPC.

The default Windows package now emits both:

- `edr-agent-<tag>-windows-amd64-exe.zip`: raw executable payload, runtime DLLs,
  scripts, encrypted P0 bundle, sensor interest manifest, `VERSION`, and
  `edr_agent_setup.exe` inside the zip.
- `edr-agent-<tag>-windows-amd64-setup.exe`: the same Inno Setup installer as a
  direct release asset for operator download.

If a Windows gRPC artifact is required later, create a separate manual workflow
with vcpkg binary cache enabled. Do not add it to the installer path.
