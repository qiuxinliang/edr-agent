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
    parser.add_argument("--purpose", choices=("candidate", "release"))
    args = parser.parse_args()
    if args.purpose == "candidate":
        if args.event not in {"push", "workflow_dispatch"}:
            raise ValueError("Unsupported candidate event")
        mode = "unsigned"
    else:
        mode = resolve_mode(args.event, args.requested, args.configured)
        if args.purpose == "release" and mode == "unsigned":
            raise ValueError("Unsigned output is candidate-only; releases require signing")
    with Path(args.output).open("a", encoding="utf-8") as output:
        output.write(f"mode={mode}\n")
        if args.purpose:
            output.write(f"purpose={args.purpose}\n")
    print(f"Resolved purpose: {args.purpose or 'legacy explicit mode'}; signing: {mode}")


if __name__ == "__main__":
    main()
