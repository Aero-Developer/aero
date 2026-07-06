"""Generate the Aero app icons from the source logo (real-transparency PNG).

Crops to the logo's opaque bounding box, scales it to fill the canvas edge-to-edge (touching top &
bottom), centers it on a 1080x1080 transparent master, and emits the app PNG sizes + a
multi-resolution .ico with PNG-compressed frames (so every size keeps a real alpha channel).
"""
from PIL import Image

SRC = r"C:\Users\Administrator\Downloads\Gemini_Generated_Image_epl6raepl6raepl6 (2).png"
MASTER = r"C:\Users\Administrator\Downloads\aero_logo_1080.png"
APPICONS = r"C:\Users\Administrator\Desktop\ethereum\frontend\gui\assets\images\appicons"
FEATHER = r"C:\Users\Administrator\Desktop\ethereum\frontend\gui\assets\images\feather.png"

img = Image.open(SRC).convert("RGBA")

# Crop to the actual logo (trim transparent borders).
bbox = img.getbbox()
if bbox:
    img = img.crop(bbox)

# Fill the canvas: longest side spans it edge-to-edge, centered.
CANVAS = 1080
lw, lh = img.size
scale = CANVAS / max(lw, lh)
nw, nh = max(1, round(lw * scale)), max(1, round(lh * scale))
logo = img.resize((nw, nh), Image.LANCZOS)
master = Image.new("RGBA", (CANVAS, CANVAS), (0, 0, 0, 0))
master.paste(logo, ((CANVAS - nw) // 2, (CANVAS - nh) // 2), logo)
master.save(MASTER)
print("wrote", MASTER, master.size, "logo px", (nw, nh))

# App PNG sizes (bundled via assets.qrc; drive the window/taskbar/tray icon).
for s in (16, 24, 32, 48, 64, 96, 128, 256, 512):
    master.resize((s, s), Image.LANCZOS).save(f"{APPICONS}\\{s}x{s}.png")
    print("wrote", f"{s}x{s}.png")

# Legacy standalone feather logo (kept in sync).
master.resize((256, 256), Image.LANCZOS).save(FEATHER)

# Multi-resolution .ico for the Windows executable (PNG frames keep alpha in every shell context).
ico_sizes = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
try:
    master.save(f"{APPICONS}\\appicon.ico", format="ICO", sizes=ico_sizes, bitmap_format="png")
except TypeError:
    master.save(f"{APPICONS}\\appicon.ico", format="ICO", sizes=ico_sizes)
print("wrote appicon.ico", ico_sizes)
