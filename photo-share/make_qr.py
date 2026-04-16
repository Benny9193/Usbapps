#!/usr/bin/env python3
"""
General-purpose QR code maker.

Give it any URL (or any text) and it spits out:
  <name>.png       - high-resolution PNG, great for texting/emailing
  <name>.svg       - vector version, perfect for printing at any size
  <name>-card.html - a printable "scan me" card with the QR embedded

Examples
--------
  python3 make_qr.py https://example.com
  python3 make_qr.py https://example.com --name website
  python3 make_qr.py https://youtu.be/dQw4w9WgXcQ --name rick --title "Click me"
  python3 make_qr.py "Happy birthday!" --name bday --title "A note for you"

Requires segno:  pip install segno
"""

import argparse
import base64
import sys
from pathlib import Path

try:
    import segno
except ImportError:
    sys.stderr.write(
        "[-] segno is not installed. Run:  pip install segno\n"
    )
    sys.exit(1)


def build_card_html(png_b64: str, title: str, subtitle: str) -> str:
    """Return a self-contained printable HTML card with the QR embedded."""
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
  @page {{ margin: 0.5in; }}
  html, body {{ margin: 0; padding: 0; background: #f4f1ec; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI",
                 Helvetica, Arial, sans-serif;
    color: #2d2420;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 32px 16px;
    box-sizing: border-box;
  }}
  .card {{
    width: 420px;
    max-width: 100%;
    background: #ffffff;
    border-radius: 18px;
    box-shadow: 0 8px 40px rgba(60, 40, 20, 0.12);
    padding: 40px 36px 32px 36px;
    text-align: center;
    border: 1px solid #efe6db;
  }}
  .eyebrow {{
    font-size: 12px;
    letter-spacing: 2.5px;
    text-transform: uppercase;
    color: #a8673d;
    font-weight: 700;
    margin-bottom: 12px;
  }}
  h1 {{
    margin: 0 0 10px 0;
    font-size: 28px;
    font-weight: 700;
    line-height: 1.2;
  }}
  p.sub {{
    margin: 0 0 26px 0;
    font-size: 15px;
    color: #6b5b4e;
    line-height: 1.5;
  }}
  .qr-wrap {{
    display: inline-block;
    padding: 18px;
    background: #fff;
    border: 1px solid #efe6db;
    border-radius: 12px;
  }}
  .qr-wrap img {{
    display: block;
    width: 260px;
    height: 260px;
  }}
  .hint {{
    margin: 22px 0 0 0;
    font-size: 13px;
    color: #a89687;
    line-height: 1.5;
  }}
  @media print {{
    body {{ background: #ffffff; }}
    .card {{ box-shadow: none; border: none; }}
  }}
</style>
</head>
<body>
  <div class="card">
    <div class="eyebrow">Scan me</div>
    <h1>{title}</h1>
    <p class="sub">{subtitle}</p>
    <div class="qr-wrap">
      <img src="data:image/png;base64,{png_b64}" alt="QR code">
    </div>
    <p class="hint">
      Point your phone camera at the code, then tap the notification that pops up.
    </p>
  </div>
</body>
</html>
"""


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate a QR code for any URL or text.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 make_qr.py https://example.com\n"
            "  python3 make_qr.py https://example.com --name website\n"
            "  python3 make_qr.py \"Happy birthday!\" --name bday "
            "--title \"A note for you\"\n"
        ),
    )
    parser.add_argument(
        "payload",
        help="The URL or text to encode into the QR code.",
    )
    parser.add_argument(
        "--name",
        default="qr",
        help="Base filename for outputs (default: qr).",
    )
    parser.add_argument(
        "--title",
        default="Scan me",
        help='Headline shown on the printable card (default: "Scan me").',
    )
    parser.add_argument(
        "--subtitle",
        default="Point your phone camera here.",
        help="Smaller line of text on the card.",
    )
    parser.add_argument(
        "--out-dir",
        default=".",
        help="Directory to write output files into (default: current dir).",
    )
    parser.add_argument(
        "--dark",
        default="#2d2420",
        help="Dark (foreground) color, as hex (default: #2d2420).",
    )
    parser.add_argument(
        "--light",
        default="#ffffff",
        help="Light (background) color, as hex (default: #ffffff).",
    )
    parser.add_argument(
        "--scale",
        type=int,
        default=16,
        help="Pixels per QR module in the PNG (default: 16).",
    )
    parser.add_argument(
        "--error",
        choices=["l", "m", "q", "h"],
        default="h",
        help=(
            "Error correction level: l(~7%%), m(~15%%), q(~25%%), h(~30%%). "
            "Higher = more robust but denser. Default: h."
        ),
    )
    parser.add_argument(
        "--no-svg",
        action="store_true",
        help="Skip the SVG output.",
    )
    parser.add_argument(
        "--no-card",
        action="store_true",
        help="Skip the printable HTML card output.",
    )
    args = parser.parse_args()

    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    png_path = out_dir / f"{args.name}.png"
    svg_path = out_dir / f"{args.name}.svg"
    card_path = out_dir / f"{args.name}-card.html"

    qr = segno.make(args.payload, error=args.error)

    qr.save(
        str(png_path),
        scale=args.scale,
        border=4,
        dark=args.dark,
        light=args.light,
    )
    print(f"[+] Wrote {png_path.name}  ({png_path.stat().st_size} bytes)")

    if not args.no_svg:
        qr.save(
            str(svg_path),
            scale=max(8, args.scale // 2),
            border=4,
            dark=args.dark,
            light=args.light,
        )
        print(f"[+] Wrote {svg_path.name}  ({svg_path.stat().st_size} bytes)")

    if not args.no_card:
        png_b64 = base64.b64encode(png_path.read_bytes()).decode("ascii")
        card_path.write_text(
            build_card_html(png_b64, args.title, args.subtitle),
            encoding="utf-8",
        )
        print(f"[+] Wrote {card_path.name} ({card_path.stat().st_size} bytes)")

    preview = args.payload if len(args.payload) <= 70 else args.payload[:67] + "..."
    print(f"[+] QR encodes: {preview}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
