"""Verify the updater's embedded installer owner. No endpoint-side compiler is used.

Run without options for the offline source/payload consistency check. For a
byte-for-byte rebuild, pass --dotnet-root pointing to a .NET installation with
the SDK pinned in global.json. Pass the build/.NETFramework/v4.6.2 folder from
Microsoft.NETFramework.ReferenceAssemblies.net462 1.0.3 as --references. Add --write to
regenerate after editing InstallerJob.cs.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import zlib

HERE = Path(__file__).resolve().parent
UPDATER = HERE.parent / "edr_agent_inplace_update.ps1"
REFERENCES = {
    "mscorlib.dll": "f8b1e8838944f96ea36b670b32a54c0eb0eca3743946363acc676d1d7ef893b0",
    "System.dll": "19359fe1fdef82d265afdd0f1ba15e978795ea483a63e6f2881f993bd20bbd65",
}
FIELDS = (
    r"(# InstallerJob\.cs SHA-256: )([0-9a-f]{64})",
    r"(\$packed = \[Convert\]::FromBase64String\(')([A-Za-z0-9+/=]+)",
    r"(if \(\$actual -cne ')([0-9a-f]{64})",
    r"(\$image = \[byte\[\]\]::new\()([0-9]+)",
)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def build(dotnet_root, refs, source):
    version = json.loads((HERE.parents[1] / "global.json").read_text())["sdk"]["version"]
    compiler = dotnet_root / "sdk" / version / "Roslyn/bincore/csc.dll"
    dotnet = dotnet_root / ("dotnet.exe" if os.name == "nt" else "dotnet")
    with tempfile.TemporaryDirectory() as directory:
        tmp = Path(directory)
        (tmp / "InstallerJob.cs").write_bytes(source)
        for name, expected in REFERENCES.items():
            data = (refs / name).read_bytes()
            if digest(data) != expected:
                raise ValueError(f"Unexpected .NET Framework reference: {name}")
            (tmp / name).write_bytes(data)
        subprocess.run([
            str(dotnet), str(compiler), "/nologo", "/noconfig", "/nostdlib+",
            "/reference:mscorlib.dll,System.dll", "/target:library", "/platform:anycpu",
            "/optimize+", "/debug-", "/deterministic+", "/langversion:5",
            f"/pathmap:{tmp}=/_", "/out:FDSecurity.InstallerJob.dll", "InstallerJob.cs",
        ], cwd=tmp, check=True, timeout=60)
        return (tmp / "FDSecurity.InstallerJob.dll").read_bytes()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dotnet-root", type=Path)
    parser.add_argument("--references", type=Path)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    if bool(args.dotnet_root) != bool(args.references) or (args.write and not args.dotnet_root):
        parser.error("rebuilding requires both --dotnet-root and --references")
    source = (HERE / "InstallerJob.cs").read_text(encoding="utf-8").encode("utf-8")
    # Replace only the generated fields, preserving all other bytes and EOLs.
    script = UPDATER.read_bytes().decode("utf-8")
    lo = script.index("function Initialize-InstallerJobType {")
    hi = script.index("function Get-InstallerUptimeMilliseconds {", lo)
    loader = script[lo:hi]
    fields = []
    for pattern in FIELDS:
        matches = list(re.finditer(pattern, loader))
        if len(matches) != 1:
            raise ValueError("Missing or ambiguous installer owner field")
        fields.append(matches[0])
    packed = base64.b64decode(fields[1][2], validate=True)
    decoder = zlib.decompressobj(-15)
    image = decoder.decompress(packed, 65537)
    if not decoder.eof or decoder.unused_data or not 0 < len(image) <= 65536:
        raise ValueError("Invalid packed installer owner")
    if args.dotnet_root:
        rebuilt = build(args.dotnet_root.resolve(), args.references.resolve(), source)
        if not 0 < len(rebuilt) <= 65536:
            raise ValueError("Installer owner exceeds its generation bound")
        if rebuilt != image:
            if not args.write:
                raise ValueError("Embedded installer owner differs from the rebuilt assembly")
            encoder = zlib.compressobj(9, zlib.DEFLATED, -15)
            image = rebuilt
            packed = encoder.compress(image) + encoder.flush()
    values = (digest(source), base64.b64encode(packed).decode("ascii"), digest(packed), str(len(image)))
    for match, expected in reversed(list(zip(fields, values))):
        if not args.write and match[2] != expected:
            raise ValueError("InstallerJob.cs, embedded image or digest is stale")
        start, end = match.span(2)
        loader = loader[:start] + expected + loader[end:]
    if args.write:
        UPDATER.write_bytes((script[:lo] + loader + script[hi:]).encode("utf-8"))


if __name__ == "__main__":
    main()
