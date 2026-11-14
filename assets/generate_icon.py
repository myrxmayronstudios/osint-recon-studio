"""Programmatic Windows Multi-Resolution .ico Generator.

Draws a sleek, modern cybersecurity radar/shield emblem in a dark navy and
neon emerald/cyan aesthetic, generating multi-size Windows icons (16x16 to 256x256).
"""

from __future__ import annotations

import math
from pathlib import Path
from PIL import Image, ImageDraw


def generate_app_icon(output_ico_path: Path, output_png_path: Path | None = None) -> None:
    output_ico_path.parent.mkdir(parents=True, exist_ok=True)

    # Super-sampled canvas for crisp vector-like anti-aliasing (1024x1024 downscaled)
    size = 1024
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    center_x, center_y = size // 2, size // 2

    # 1. Dark Navy Shield Body with Rounded Polygonal Path
    shield_points = [
        (200, 160),
        (824, 160),
        (824, 520),
        (512, 900),
        (200, 520),
    ]

    # Gradient-like layered fills
    # Deep navy-indigo base
    draw.polygon(shield_points, fill=(15, 20, 36, 255))

    # Inner shield accent border
    inner_points = [
        (230, 190),
        (794, 190),
        (794, 500),
        (512, 850),
        (230, 500),
    ]
    draw.polygon(inner_points, fill=(24, 30, 52, 255))

    # 2. Glowing Shield Outer Border (Neon Emerald / Cyan)
    border_width = 24
    for i in range(border_width, 0, -4):
        alpha = int(255 * (1.0 - (i / border_width) * 0.4))
        draw.polygon(shield_points, outline=(0, 229, 163, alpha))

    # 3. Radar Display Concentric Circles & Grid
    radar_center = (512, 450)
    radii = [280, 200, 120, 50]

    for r in radii:
        bbox = (radar_center[0] - r, radar_center[1] - r, radar_center[0] + r, radar_center[1] + r)
        draw.ellipse(bbox, outline=(0, 229, 163, 90), width=6)

    # Crosshair grid lines
    draw.line(
        [(radar_center[0] - 280, radar_center[1]), (radar_center[0] + 280, radar_center[1])],
        fill=(0, 229, 163, 100),
        width=5,
    )
    draw.line(
        [(radar_center[0], radar_center[1] - 280), (radar_center[0], radar_center[1] + 280)],
        fill=(0, 229, 163, 100),
        width=5,
    )

    # 4. Stylized Radar Sweep Sector
    sweep_r = 270
    sweep_bbox = (
        radar_center[0] - sweep_r,
        radar_center[1] - sweep_r,
        radar_center[0] + sweep_r,
        radar_center[1] + sweep_r,
    )
    # Wedge angle -45 to 15
    draw.pieslice(sweep_bbox, start=300, end=350, fill=(0, 229, 163, 60), outline=(0, 255, 180, 180), width=4)

    # 5. Glowing Target / Blip Nodes
    targets = [
        (radar_center[0] + 130, radar_center[1] - 110, 16, (0, 255, 180, 255)),
        (radar_center[0] - 140, radar_center[1] + 90, 12, (116, 199, 236, 255)),
        (radar_center[0] + 60, radar_center[1] + 160, 10, (243, 139, 168, 255)),
        (radar_center[0], radar_center[1], 18, (255, 255, 255, 255)),
    ]

    for tx, ty, tr, col in targets:
        # Glow halo
        draw.ellipse((tx - tr * 2, ty - tr * 2, tx + tr * 2, ty + tr * 2), fill=(col[0], col[1], col[2], 50))
        # Solid center
        draw.ellipse((tx - tr, ty - tr, tx + tr, ty + tr), fill=col)

    # Downsample cleanly with LANCZOS for optimal sharpness
    img_256 = img.resize((256, 256), Image.Resampling.LANCZOS)

    # Generate multi-size icons for Windows desktop, taskbar, Alt+Tab, and Explorer
    sizes = [(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]

    # Save multi-resolution .ico directly using Pillow's native multi-size ICO encoder
    img_256.save(
        output_ico_path,
        format="ICO",
        sizes=sizes,
    )
    print(f"[+] Successfully generated Windows icon: {output_ico_path}")

    if output_png_path:
        img_256.save(output_png_path, format="PNG")
        print(f"[+] Successfully generated PNG preview: {output_png_path}")


if __name__ == "__main__":
    base_dir = Path(__file__).resolve().parent.parent
    ico_dest = base_dir / "assets" / "app_icon.ico"
    png_dest = base_dir / "assets" / "app_icon.png"
    generate_app_icon(ico_dest, png_dest)
