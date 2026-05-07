"""Generate high-quality PNG and ICO icons from SVG design.

Uses Pillow with GaussianBlur for glow effects and per-pixel gradients.
Much closer to the SVG source than basic rendering.

Usage: python generate_icons.py
"""

import math
import struct
from io import BytesIO
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter

ICONS_DIR = Path(__file__).parent
SVG_PATH = ICONS_DIR / "icon.svg"

TARGET_SIZES = [16, 32, 48, 64, 128, 256, 512]

# --- Color palette ---
BG_OUTER = (6, 13, 26)
BG_INNER = (15, 40, 71)
CORE_CYAN = (0, 229, 255)
LIGHT_CYAN = (178, 235, 242)
ELECTRON = (0, 188, 212)
ELECTRON_HI = (224, 247, 250)
ORBIT_COLORS = [
    (0, 229, 255),
    (38, 198, 218),
    (77, 208, 225),
]
GRID_COLOR = (77, 208, 225)
NODE_COLOR = (0, 131, 143)
EDGE_COLOR = (0, 172, 193)
ACCENT_COLOR = (0, 172, 193)


def lerp(a, b, t):
    return a + (b - a) * t


def lerp_color(c1, c2, t):
    return tuple(int(lerp(c1[i], c2[i], t)) for i in range(len(c1)))


def rounded_rect_mask(size, radius):
    """Create a mask for a rounded rectangle."""
    mask = Image.new("L", (size, size), 0)
    draw = ImageDraw.Draw(mask)
    draw.rounded_rectangle([0, 0, size - 1, size - 1], radius=radius, fill=255)
    return mask


def draw_bg_gradient(size, radius):
    """Draw the background with a radial gradient."""
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    mask = rounded_rect_mask(size, radius)

    cx, cy = size * 0.5, size * 0.45
    max_dist = size * 0.55

    for y in range(size):
        for x in range(size):
            if mask.getpixel((x, y)) == 0:
                continue
            dx, dy = x - cx, y - cy
            dist = math.sqrt(dx * dx + dy * dy)
            t = min(dist / max_dist, 1.0)
            r = int(lerp(BG_INNER[0], BG_OUTER[0], t))
            g = int(lerp(BG_INNER[1], BG_OUTER[1], t))
            b = int(lerp(BG_INNER[2], BG_OUTER[2], t))
            img.putpixel((x, y), (r, g, b, 255))

    return img


def draw_bg_gradient_fast(size, radius):
    """Fast background gradient using downscale-upscale trick."""
    small = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    mask = rounded_rect_mask(size, radius)

    # Create gradient at reduced resolution, then resize up
    step = max(1, size // 128)
    small_size = size // step
    grad = Image.new("RGBA", (small_size, small_size), BG_OUTER + (255,))
    cx, cy = small_size * 0.5, small_size * 0.45
    max_dist = small_size * 0.55
    for y in range(small_size):
        for x in range(small_size):
            dx, dy = x - cx, y - cy
            dist = math.sqrt(dx * dx + dy * dy)
            t = min(dist / max_dist, 1.0)
            c = lerp_color(BG_INNER, BG_OUTER, t)
            grad.putpixel((x, y), c + (255,))

    grad = grad.resize((size, size), Image.BILINEAR)
    grad.putalpha(mask)
    return grad


def draw_grid(draw, s):
    """Draw subtle grid lines."""
    alpha = int(255 * 0.06)
    c = GRID_COLOR + (alpha,)
    positions = [128, 192, 256, 320, 384]
    w = max(1, round(0.7 * s))
    for p in positions:
        p_ = int(p * s)
        draw.line([(int(40 * s), p_), (int(472 * s), p_)], fill=c, width=w)
        draw.line([(p_, int(40 * s)), (p_, int(472 * s))], fill=c, width=w)


def draw_network(draw, s):
    """Draw P2P network nodes and edges."""
    nodes = [
        (130, 130, 5), (382, 130, 5), (130, 382, 5), (382, 382, 5),
        (90, 256, 4), (422, 256, 4), (256, 90, 4), (256, 422, 4),
    ]
    center = (256, 256)

    # Edges from center
    edge_alpha = int(255 * 0.25)
    ec = EDGE_COLOR + (edge_alpha,)
    ew = max(1, round(1.2 * s))
    for nx, ny, _ in nodes:
        draw.line(
            [(int(center[0] * s), int(center[1] * s)),
             (int(nx * s), int(ny * s))],
            fill=ec, width=ew
        )
    # Cross connections
    for i in range(4):
        for j in range(i + 1, 4):
            n1, n2 = nodes[i], nodes[j]
            draw.line(
                [(int(n1[0] * s), int(n1[1] * s)),
                 (int(n2[0] * s), int(n2[1] * s))],
                fill=ec, width=ew
            )

    # Node dots
    node_alpha = int(255 * 0.55)
    nc = NODE_COLOR + (node_alpha,)
    for nx, ny, nr in nodes:
        r = max(2, int(nr * s))
        draw.ellipse(
            [int(nx * s - r), int(ny * s - r), int(nx * s + r), int(ny * s + r)],
            fill=nc
        )


def draw_glow_circle(img, cx, cy, radius, color, intensity=1.0):
    """Draw a soft glow circle by overlaying a blurred circle."""
    glow = Image.new("RGBA", img.size, (0, 0, 0, 0))
    gdraw = ImageDraw.Draw(glow)
    for i in range(3):
        r = int(radius * (1.0 + i * 0.3))
        alpha = int(255 * intensity * (0.4 - i * 0.12))
        alpha = max(0, min(255, alpha))
        c = color + (alpha,)
        gdraw.ellipse([cx - r, cy - r, cx + r, cy + r], fill=c)
    glow = glow.filter(ImageFilter.GaussianBlur(radius=radius * 0.4))
    img.paste(Image.alpha_composite(img, glow), (0, 0))


def draw_orbit(draw, cx, cy, angle_deg, rx, ry, color, width):
    """Draw a tilted elliptical orbit."""
    angle = math.radians(angle_deg)
    cos_a, sin_a = math.cos(angle), math.sin(angle)
    n_points = max(60, int(180 * (rx / 110)))
    points = []
    for i in range(n_points):
        theta = 2 * math.pi * i / n_points
        px = rx * math.cos(theta)
        py = ry * math.sin(theta)
        rpx = px * cos_a - py * sin_a
        rpy = px * sin_a + py * cos_a
        points.append((int(cx + rpx), int(cy + rpy)))
    points.append(points[0])
    draw.line(points, fill=color, width=width)


def draw_electron(img, ex, ey, radius, s):
    """Draw an electron with highlight."""
    draw = ImageDraw.Draw(img)
    r = max(2, int(radius * s))
    # Glow
    glow = Image.new("RGBA", img.size, (0, 0, 0, 0))
    gdraw = ImageDraw.Draw(glow)
    gdraw.ellipse([ex - r * 2, ey - r * 2, ex + r * 2, ey + r * 2],
                  fill=ELECTRON + (60,))
    glow = glow.filter(ImageFilter.GaussianBlur(radius=r))
    img.paste(Image.alpha_composite(img, glow), (0, 0))
    draw = ImageDraw.Draw(img)
    # Body
    draw.ellipse([ex - r, ey - r, ex + r, ey + r], fill=ELECTRON + (255,))
    # Highlight
    hr = max(1, int(2.5 * s))
    hx, hy = ex - max(1, int(1.5 * s)), ey - max(1, int(1.5 * s))
    draw.ellipse([hx - hr, hy - hr, hx + hr, hy + hr],
                 fill=ELECTRON_HI + (200,))


def draw_corner_accents(draw, size, s):
    """Draw corner bracket accents."""
    alpha = int(255 * 0.12)
    c = ACCENT_COLOR + (alpha,)
    w = max(1, round(1.2 * s))
    m = int(30 * s)
    l = int(30 * s)
    # Top-left
    draw.line([(m, m + l), (m, m)], fill=c, width=w)
    draw.line([(m, m), (m + l, m)], fill=c, width=w)
    # Top-right
    draw.line([(size - m - l, m), (size - m, m)], fill=c, width=w)
    draw.line([(size - m, m), (size - m, m + l)], fill=c, width=w)
    # Bottom-right
    draw.line([(size - m, size - m - l), (size - m, size - m)], fill=c, width=w)
    draw.line([(size - m, size - m), (size - m - l, size - m)], fill=c, width=w)
    # Bottom-left
    draw.line([(m + l, size - m), (m, size - m)], fill=c, width=w)
    draw.line([(m, size - m), (m, size - m - l)], fill=c, width=w)


def render_icon(size):
    """Render the PQNodium icon at the given pixel size."""
    s = size / 512.0
    cx, cy = size // 2, size // 2
    radius = int(96 * s)

    # 1. Background gradient
    img = draw_bg_gradient_fast(size, radius)

    draw = ImageDraw.Draw(img)

    # 2. Grid
    draw_grid(draw, s)

    # 3. P2P Network
    draw_network(draw, s)

    # 4. Orbits with glow
    orbits = [
        (-30, 110, 38, ORBIT_COLORS[0], 0.7),
        (30, 110, 38, ORBIT_COLORS[1], 0.6),
        (90, 38, 110, ORBIT_COLORS[2], 0.5),
    ]
    for angle_deg, rx, ry, color, opacity in orbits:
        alpha = int(255 * opacity)
        c = color + (alpha,)
        w = max(1, round(2 * s))
        draw_orbit(draw, cx, cy, angle_deg, rx * s, ry * s, c, w)

    # Orbit glow layer (blurred duplicate for glow effect)
    orbit_glow = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    odraw = ImageDraw.Draw(orbit_glow)
    for angle_deg, rx, ry, color, opacity in orbits:
        alpha = int(255 * opacity * 0.4)
        c = color + (alpha,)
        w = max(2, round(4 * s))
        draw_orbit(odraw, cx, cy, angle_deg, rx * s, ry * s, c, w)
    blur_r = max(2, int(4 * s))
    orbit_glow = orbit_glow.filter(ImageFilter.GaussianBlur(radius=blur_r))
    img.paste(Image.alpha_composite(img, orbit_glow), (0, 0))

    draw = ImageDraw.Draw(img)

    # 5. Nucleus glow
    draw_glow_circle(img, cx, cy, int(30 * s), CORE_CYAN, intensity=0.5)

    draw = ImageDraw.Draw(img)

    # 6. Nucleus core
    nr = max(2, int(16 * s))
    draw.ellipse([cx - nr, cy - nr, cx + nr, cy + nr],
                 fill=CORE_CYAN + (240,))
    nr2 = max(1, int(10 * s))
    draw.ellipse([cx - nr2, cy - nr2, cx + nr2, cy + nr2],
                 fill=LIGHT_CYAN + (180,))

    # 7. Electrons
    electrons = [
        (-30, 85, -35, 8),
        (30, -75, 50, 8),
        (0, 15, -90, 7),
    ]
    for angle_deg, ex, ey, er in electrons:
        angle = math.radians(angle_deg)
        cos_a, sin_a = math.cos(angle), math.sin(angle)
        rpx = ex * cos_a - ey * sin_a
        rpy = ex * sin_a + ey * cos_a
        epx, epy = int(cx + rpx * s), int(cy + rpy * s)
        draw_electron(img, epx, epy, er, s)

    # 8. Corner accents
    draw_corner_accents(ImageDraw.Draw(img), size, s)

    return img


def create_ico(png_images, output_path):
    """Create a Windows ICO file from multiple PNG images."""
    num_images = len(png_images)
    header_size = 6
    dir_entry_size = 16
    dir_size = dir_entry_size * num_images
    data_offset = header_size + dir_size

    with open(output_path, "wb") as f:
        f.write(struct.pack("<HHH", 0, 1, num_images))

        entries = []
        data_parts = []
        current_offset = data_offset

        for img_png in png_images:
            w, h = img_png.size
            w_byte = 0 if w >= 256 else w
            h_byte = 0 if h >= 256 else h

            buf = BytesIO()
            img_png.save(buf, format="PNG")
            png_data = buf.getvalue()

            entry = struct.pack("<BBBBHHII",
                                w_byte, h_byte, 0, 0, 1, 32,
                                len(png_data), current_offset)
            entries.append(entry)
            data_parts.append(png_data)
            current_offset += len(png_data)

        for entry in entries:
            f.write(entry)
        for data in data_parts:
            f.write(data)


def main():
    print("Generating PQNodium icons...")
    png_images = []

    for size in TARGET_SIZES:
        print(f"  Rendering {size}x{size}...")
        img = render_icon(size)
        png_path = ICONS_DIR / f"icon_{size}x{size}.png"
        img.save(png_path, "PNG")
        png_images.append(img)

    # Standard names
    render_icon(256).save(ICONS_DIR / "icon.png", "PNG")
    render_icon(32).save(ICONS_DIR / "32x32.png", "PNG")
    render_icon(128).save(ICONS_DIR / "128x128.png", "PNG")
    render_icon(256).save(ICONS_DIR / "128x128@2x.png", "PNG")

    # ICO
    ico_sizes = [16, 32, 48, 64, 128, 256]
    ico_images = [render_icon(sz) for sz in ico_sizes]
    ico_path = ICONS_DIR / "icon.ico"
    create_ico(ico_images, ico_path)

    print(f"\nDone! Files in {ICONS_DIR}:")
    for f in sorted(ICONS_DIR.iterdir()):
        if f.suffix in (".png", ".ico", ".svg"):
            sz = f.stat().st_size
            print(f"  {f.name:30s} {sz:>8,} bytes")


if __name__ == "__main__":
    main()
