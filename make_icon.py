"""
Converts src/resources/logo.png → src/resources/logo.ico
Run once after placing the logo:  python make_icon.py
Requires Pillow:  pip install Pillow
"""
from pathlib import Path

SRC = Path(__file__).parent / "src" / "resources"
png = SRC / "logo.png"
ico = SRC / "logo.ico"

if not png.exists():
    raise FileNotFoundError(f"Logo not found: {png}\nPlace your logo.png there first.")

from PIL import Image

img = Image.open(png).convert("RGBA")
sizes = [(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (16, 16)]
img.save(ico, format="ICO", sizes=sizes)
print(f"Saved {ico}")
