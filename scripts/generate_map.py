"""Generate a minimal schematic map for AeroNix Guard."""

from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "assets" / "pisa_viareggio_map.png"

W, H = 1400, 780
LON_MIN, LON_MAX = 10.18, 10.47
LAT_MIN, LAT_MAX = 43.68, 43.91

LAND = "#EDF3E9"
SEA = "#DCEEF5"
COAST = "#A9CFD9"
PARK = "#E2EFD9"
LAKE = "#D5EAF1"
TEXT = "#50687C"


def get_font(size: int, bold: bool = False):
    candidates = (
        [
            "/usr/share/fonts/TTF/DejaVuSans-Bold.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        ]
        if bold else [
            "/usr/share/fonts/TTF/DejaVuSans.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        ]
    )
    for candidate in candidates:
        try:
            return ImageFont.truetype(candidate, size)
        except OSError:
            pass
    return ImageFont.load_default()


def xy(lat: float, lon: float) -> tuple[int, int]:
    x = (lon - LON_MIN) / (LON_MAX - LON_MIN) * (W - 1)
    y = (LAT_MAX - lat) / (LAT_MAX - LAT_MIN) * (H - 1)
    return int(x), int(y)


def main():
    image = Image.new("RGB", (W, H), LAND)
    draw = ImageDraw.Draw(image)

    # Minimal coastline, sea, wetlands and green areas.
    coast = [
        (255, 0),
        (245, 90),
        (260, 180),
        (250, 270),
        (275, 360),
        (265, 450),
        (285, 550),
        (280, 650),
        (310, H),
    ]

    draw.polygon([(0, 0), *coast, (0, H)], fill=SEA)
    draw.line(coast, fill=COAST, width=3)

    draw.polygon(
        [(590, 245), (745, 220), (815, 295), (775, 370), (630, 355)],
        fill=PARK,
    )
    draw.polygon(
        [(665, 400), (760, 385), (815, 430), (785, 475), (700, 465)],
        fill=LAKE,
    )
    draw.polygon(
        [(845, 510), (930, 492), (980, 535), (952, 574), (875, 570)],
        fill=LAKE,
    )

    # No road grid, diagonal road network or dense labels:
    # the live aircraft route must remain the dominant line on the map.
    draw.text(
        (48, 42), "MAR TIRRENO",
        font=get_font(23), fill="#7399AB",
    )
    draw.text(
        (W - 270, 38), "TOSCANA · MAPPA SCHEMATICA",
        font=get_font(15), fill="#89999C",
    )

    # City labels align with the same coordinate bounds used by the app.
    viareggio = xy(43.8657, 10.2513)
    pisa = xy(43.7228, 10.4017)

    for (x, y), name, offset in (
        (viareggio, "Viareggio (LU)", (18, -34)),
        (pisa, "Pisa", (-65, 17)),
    ):
        draw.text(
            (x + offset[0], y + offset[1]),
            name,
            font=get_font(25, True),
            fill=TEXT,
            stroke_width=3,
            stroke_fill=LAND,
        )

    image.save(OUT, format="PNG", optimize=True)
    print(f"Mappa minimalista creata: {OUT}")
    print(f"Dimensioni: {W} x {H} px")


if __name__ == "__main__":
    main()
