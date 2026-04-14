from PIL import Image, ImageDraw, ImageFont

SANS_PATH = "/usr/share/fonts/truetype/msttcorefonts/Arial.ttf"
BOLD_PATH = "/usr/share/fonts/truetype/msttcorefonts/Arial_Bold.ttf"

SCALE       = 2          # render at 2x then downsample for crisp text
FONT_SIZE   = 13 * SCALE
BOLD_SIZE   = 13 * SCALE

# Yotsuba (red) board theme
BG          = "#F0E0D6"   # classic salmon board background
ANON_GREEN  = "#117743"
ID_COLOR    = "#000000"
DATE_COLOR  = "#000000"
NO_COLOR    = "#800000"
REPLY_COLOR = "#0000EE"
BODY_COLOR  = "#000000"

PAD_X    = 10 * SCALE
PAD_Y    = 8  * SCALE
HEAD_GAP = 4  * SCALE     # gap between header and body (tight, like 4chan)
CHECKBOX_SIZE = 13 * SCALE  # small checkbox before Anonymous

body_lines = [
    "apology for poor english",
    "",
    "when were you when rsa dies?",
    "",
    "i was sat at home eating sandwich in park",
    "",
    "when mythos ring",
    "",
    "'rsa is kill'",
    "",
    "'no'",
]

sans = ImageFont.truetype(SANS_PATH, FONT_SIZE)
bold = ImageFont.truetype(BOLD_PATH, BOLD_SIZE)

header_parts = [
    ("Anonymous", ANON_GREEN, bold),
    (" 04/14/26(Tue)11:37:12 ", DATE_COLOR, sans),
    ("No.", NO_COLOR, sans),
    ("998244353", NO_COLOR, sans),
    ("  [Reply]", REPLY_COLOR, sans),
]

CHECKBOX_GAP = 4 * SCALE   # gap between checkbox and "Anonymous"

dummy = Image.new("RGB", (1, 1))
d     = ImageDraw.Draw(dummy)

def tw(text, font):
    bb = d.textbbox((0, 0), text, font=font)
    return bb[2] - bb[0]

def th(text, font):
    bb = d.textbbox((0, 0), text, font=font)
    return bb[3] - bb[1]

line_h   = th("Ag", sans)
header_h = max(th(t, f) for t, _, f in header_parts)
header_w = CHECKBOX_SIZE + CHECKBOX_GAP + sum(tw(t, f) for t, _, f in header_parts)

body_w = max((tw(l, sans) if l else 0) for l in body_lines)

total_w = max(header_w, body_w) + PAD_X * 2
total_h = PAD_Y + header_h + HEAD_GAP + line_h * len(body_lines) + PAD_Y

img  = Image.new("RGB", (total_w, total_h), BG)
draw = ImageDraw.Draw(img)

# checkbox
cb_x = PAD_X
cb_y = PAD_Y + (header_h - CHECKBOX_SIZE) // 2
draw.rectangle(
    [cb_x, cb_y, cb_x + CHECKBOX_SIZE, cb_y + CHECKBOX_SIZE],
    outline="#888888", width=max(1, SCALE // 2)
)

# header row
x = PAD_X + CHECKBOX_SIZE + CHECKBOX_GAP
y = PAD_Y
for text, color, font in header_parts:
    draw.text((x, y), text, font=font, fill=color)
    x += tw(text, font)

# body lines (empty strings = blank lines = double spacing)
# body indented past the checkbox to align with header text
body_x = PAD_X + CHECKBOX_SIZE + CHECKBOX_GAP
y = PAD_Y + header_h + HEAD_GAP
for line in body_lines:
    if line:
        draw.text((body_x, y), line, font=sans, fill=BODY_COLOR)
    y += line_h

# downsample to 1x
out = img.resize((total_w // SCALE, total_h // SCALE), Image.LANCZOS)
out.save("meme.png")
print(f"saved meme.png ({out.width}x{out.height})")
