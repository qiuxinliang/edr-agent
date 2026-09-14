"""Resolve release signing once, before any draft or native build is created."""
import argparse
from pathlib import Path


def resolve_mode(event: str, requested: str = "", configured: str = "") -> str:
    if event not in {"push", "workflow_dispatch"}:
        raise ValueError("Only release tags and explicit workflow dispatch are supported")
    # Missing repository configuration must never disable signing.
    mode = (requested if event == "workflow_dispatch" and requested else configured) or "usb"
    if mode not in {"usb", "signed", "unsigned"}:
        raise ValueError("Release signing mode must be usb, signed or unsigned")
    if mode == "unsigned" and (event != "workflow_dispatch" or requested != "unsigned"):
        raise ValueError("Unsigned releases require an explicit manual selection; tag releases cannot bypass signing")
    return mode


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--event", required=True)
    parser.add_argument("--requested", default="")
    parser.add_argument("--configured", default="")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    mode = resolve_mode(args.event, args.requested, args.configured)
    with Path(args.output).open("a", encoding="utf-8") as output:
        output.write(f"mode={mode}\n")
    print(f"Resolved release mode: {mode}; unsigned is never an automatic fallback")


if __name__ == "__main__":
    main()
