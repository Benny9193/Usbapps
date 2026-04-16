#!/usr/bin/env python3
"""
Generate a QR code that opens a Google Photos share link when scanned.

Usage:
    python3 generate_qr.py

Produces:
    qr-code.png    - A high-resolution PNG of the QR code (great for texting,
                     emailing, or dropping into a document).
    qr-code.svg    - A vector version (scales perfectly for print - use this
                     one if you want to print it big on a card or poster).
    qr-card.html   - A self-contained printable card with the QR code plus a
                     short note. Open it in a browser, then File > Print.

To change the photo, just edit PHOTO_URL below and re-run the script.
"""

import base64
from pathlib import Path

import segno

PHOTO_URL = "https://photos.app.goo.gl/7x4LxoZjX67xCTqd6"

HERE = Path(__file__).resolve().parent
PNG_PATH = HERE / "qr-code.png"
SVG_PATH = HERE / "qr-code.svg"
CARD_PATH = HERE / "qr-card.html"

# Use high error correction so the QR still scans if the image is
# slightly damaged, printed small, or snapped at an angle.
qr = segno.make(PHOTO_URL, error="h")

# --- PNG: big, crisp, black-on-white, with a generous quiet zone ---
qr.save(
    str(PNG_PATH),
    scale=16,      # 16 px per QR module = plenty of resolution
    border=4,      # quiet zone (required for reliable scanning)
    dark="#2d2420",
    light="#ffffff",
)

# --- SVG: vector, infinite zoom, tiny file ---
qr.save(
    str(SVG_PATH),
    scale=10,
    border=4,
    dark="#2d2420",
    light="#ffffff",
)

# --- Printable HTML card with the QR embedded as base64 ---
png_bytes = PNG_PATH.read_bytes()
png_b64 = base64.b64encode(png_bytes).decode("ascii")

card_html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>A little surprise</title>
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
  .heart {{ color: #c44545; }}
  @media print {{
    body {{ background: #ffffff; }}
    .card {{ box-shadow: none; border: none; }}
  }}
</style>
</head>
<body>
  <div class="card">
    <div class="eyebrow">For you</div>
    <h1>Scan me <span class="heart">&#9825;</span></h1>
    <p class="sub">Point your phone camera here.</p>
    <div class="qr-wrap">
      <img src="data:image/png;base64,{png_b64}" alt="QR code">
    </div>
    <p class="hint">
      Tap the notification that pops up to open the surprise.
    </p>
  </div>
</body>
</html>
"""

CARD_PATH.write_text(card_html, encoding="utf-8")

print(f"[+] Wrote {PNG_PATH.relative_to(HERE)}  ({PNG_PATH.stat().st_size} bytes)")
print(f"[+] Wrote {SVG_PATH.relative_to(HERE)}  ({SVG_PATH.stat().st_size} bytes)")
print(f"[+] Wrote {CARD_PATH.relative_to(HERE)} ({CARD_PATH.stat().st_size} bytes)")
print(f"[+] QR encodes: {PHOTO_URL}")
