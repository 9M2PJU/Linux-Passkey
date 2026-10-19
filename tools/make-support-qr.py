#!/usr/bin/python3
"""Draw the donation QR codes in docs/support with a logo in the centre.

Needs the qrcode and Pillow packages. The codes use error correction level
H (30% may be covered), and the logo covers well under that, so they scan
as plain QR codes.
"""

import os
import sys

import qrcode
from PIL import Image, ImageDraw, ImageFont

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "docs", "support")
BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"

CODES = {
    "upi": ("upi://pay?pa=akileswar2002@oksbi&pn=Linux%20Passkey&cu=INR", "UPI", "#097939", "#ffffff"),
    "bitcoin": ("bitcoin:13pu8fvcNt6Rx8tXJGfFDVWf59uhZuaFEp", "B", "#f7931a", "#ffffff"),
}


def badge(size, text, fill, ink):
    """A round badge with white margin, drawn at 4x and scaled down."""
    big = size * 4
    img = Image.new("RGBA", (big, big), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    draw.ellipse((0, 0, big - 1, big - 1), fill="white")
    pad = big // 12
    draw.ellipse((pad, pad, big - 1 - pad, big - 1 - pad), fill=fill)
    if text == "B":
        # The Bitcoin sign: fonts rarely have U+20BF, so draw a B with the two
        # strokes through its top and bottom, tilted as in the Bitcoin logo.
        glyph = Image.new("RGBA", (big, big), (0, 0, 0, 0))
        g = ImageDraw.Draw(glyph)
        font = ImageFont.truetype(BOLD, int(big * 0.5))
        g.text((big / 2, big / 2), "B", font=font, fill=ink, anchor="mm")
        left, top, right, bottom = g.textbbox((big / 2, big / 2), "B", font=font, anchor="mm")
        bar = max(2, (right - left) // 7)
        for x in (left + (right - left) * 0.3, left + (right - left) * 0.58):
            g.rectangle((x, top - big * 0.07, x + bar, top + bar), fill=ink)
            g.rectangle((x, bottom - bar, x + bar, bottom + big * 0.07), fill=ink)
        img.alpha_composite(glyph.rotate(-14, resample=Image.BICUBIC))
    else:
        font = ImageFont.truetype(BOLD, int(big * 0.3))
        draw.text((big / 2, big / 2), text, font=font, fill=ink, anchor="mm")
    return img.resize((size, size), Image.LANCZOS)


def main():
    for name, (payload, text, fill, ink) in CODES.items():
        qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_H, box_size=10, border=2)
        qr.add_data(payload)
        img = qr.make_image(fill_color="black", back_color="white").convert("RGBA")
        size = int(img.size[0] * 0.24)
        logo = badge(size, text, fill, ink)
        img.alpha_composite(logo, ((img.size[0] - size) // 2, (img.size[1] - size) // 2))
        path = os.path.join(OUT, name + ".png")
        img.convert("RGB").save(path, optimize=True)
        print("wrote %s (%s)" % (path, payload))
    return 0


if __name__ == "__main__":
    sys.exit(main())
