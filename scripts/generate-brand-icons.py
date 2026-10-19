#!/usr/bin/env python3
"""Rasterize the existing linked-N vector into consistent Windows/Linux assets."""
from pathlib import Path
import xml.etree.ElementTree as ET
from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parents[1]
BRAND = ROOT / 'brand'
svg = ET.parse(BRAND / 'icon.svg').getroot()
def render(size):
    scale = size * 4 / 512
    image = Image.new('RGBA', (size * 4, size * 4))
    draw = ImageDraw.Draw(image)
    for element in svg:
        kind = element.tag.rsplit('}', 1)[-1]
        a = element.attrib
        if kind == 'rect':
            x, y, w, h = (float(a[k]) * scale for k in ('x', 'y', 'width', 'height'))
            draw.rounded_rectangle((x, y, x + w, y + h), radius=float(a['rx']) * scale, fill=a['fill'])
        elif kind in ('polyline', 'line'):
            if kind == 'polyline':
                points = [tuple(float(v) * scale for v in p.split(',')) for p in a['points'].split()]
            else:
                points = [(float(a[x]) * scale, float(a[y]) * scale) for x, y in [('x1', 'y1'), ('x2', 'y2')]]
            width = round(float(a['stroke-width']) * scale)
            draw.line(points, fill=a['stroke'], width=width, joint='curve')
            radius = width / 2
            for x, y in points:
                draw.ellipse((x-radius, y-radius, x+radius, y+radius), fill=a['stroke'])
    return image.resize((size, size), Image.Resampling.LANCZOS)

render(256).save(BRAND / 'nestlink.png')
render(256).save(BRAND / 'nestlink.ico', sizes=[(n, n) for n in (16, 20, 24, 32, 40, 48, 64, 128, 256)])
for name, size, icon_size in [('wizard-small.bmp', (55, 55), 44), ('wizard-large.bmp', (164, 314), 112)]:
    canvas = Image.new('RGB', size, '#EEE8F8')
    icon = render(icon_size)
    canvas.paste(icon, ((size[0]-icon_size)//2, 24 if size[1]>100 else (size[1]-icon_size)//2), icon)
    canvas.save(BRAND / name)
print('Generated ICO, PNG and installer artwork from brand/icon.svg')
