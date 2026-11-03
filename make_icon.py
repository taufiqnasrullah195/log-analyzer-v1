"""make_icon.py — generate assets/icon.ico for LogAnalyzer.
Same Editorial Light motif as TheWiseAudit: white rounded card, terracotta
border, serif monogram 'LA'."""
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

SIZES = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128),
         (256, 256)]
PAPER = (247, 246, 243, 255)
TERRA = (169, 79, 28, 255)
INK = (22, 23, 26, 255)


def _font(size: int):
    for name in ("georgiab.ttf", "georgia.ttf", "times.ttf"):
        try:
            return ImageFont.truetype(f"C:/Windows/Fonts/{name}",
                                      size=int(size * 0.60))
        except OSError:
            continue
    return ImageFont.load_default()


def _draw(size: int) -> Image.Image:
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    r = max(2, size // 6)
    d.rounded_rectangle([0, 0, size - 1, size - 1], radius=r,
                        fill=PAPER, outline=TERRA,
                        width=max(1, size // 16))
    f = _font(size)
    bbox = d.textbbox((0, 0), "LA", font=f)
    w, h = bbox[2] - bbox[0], bbox[3] - bbox[1]
    d.text(((size - w) / 2 - bbox[0], (size - h) / 2 - bbox[1]), "LA",
           font=f, fill=INK)
    return img


if __name__ == "__main__":
    out = Path("assets/icon.ico")
    out.parent.mkdir(exist_ok=True)
    frames = [_draw(s) for s, _ in SIZES]
    frames[-1].save(out, format="ICO", sizes=[s for s in SIZES])
    print(f"ICON OK → {out} ({out.stat().st_size} bytes, "
          f"{len(SIZES)} sizes)")
