#!/usr/bin/env python3
"""Build the local desk memo. Its password is read from macOS Keychain.

The memo contains the password and must never be committed or published.
The QR contains only the public website URL.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
from pathlib import Path

from PIL import Image, ImageDraw
from reportlab.graphics.barcode.qrencoder import QRCode, QRErrorCorrectLevel
from reportlab.lib.colors import HexColor, white
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_URL = "https://munozmelanie.github.io/"
DEFAULT_OUTPUT = ROOT.parents[1] / "output" / "Espace remplaçant"
INK, GREEN, MUTED, PAPER, LINE = "#233e38", "#285c4d", "#66746d", "#fafaf5", "#dde3d9"


def password_from_keychain(helper: Path) -> str:
    result = subprocess.run([str(helper), "get", "relais-cm1-reader", "munozmelanie.github.io"], capture_output=True)
    if result.returncode:
        raise RuntimeError("Le mot de passe du Relais est indisponible dans le trousseau.")
    password = result.stdout.decode("ascii")
    if not 16 <= len(password) <= 80 or not re.fullmatch(r"[a-z0-9-]+", password):
        raise ValueError("Le mot de passe ne correspond pas au format lisible du mémo.")
    return password


def fonts() -> tuple[str, str, str]:
    directory = Path("/System/Library/Fonts/Supplemental")
    entries = (("RelaySans", "Arial.ttf"), ("RelayBold", "Arial Bold.ttf"), ("RelaySerif", "Georgia.ttf"))
    if all((directory / file).exists() for _, file in entries):
        for name, file in entries:
            pdfmetrics.registerFont(TTFont(name, str(directory / file)))
        return "RelaySans", "RelayBold", "RelaySerif"
    return "Helvetica", "Helvetica-Bold", "Times-Roman"


def build(url: str, output: Path, helper: Path) -> dict:
    if url != DEFAULT_URL:
        raise ValueError("Utiliser l’adresse permanente validée du Relais.")
    password = password_from_keychain(helper)
    output.mkdir(parents=True, exist_ok=True)
    private = ROOT / ".private" / "qr-memo"
    private.mkdir(parents=True, exist_ok=True)
    backup = private / "backup-before-github"
    backup.mkdir(exist_ok=True)
    pdf_path = output / "QR code remplaçant CM1.pdf"
    png_path = output / "QR code remplaçant CM1.png"
    for existing in (pdf_path, png_path):
        if existing.exists() and not (backup / existing.name).exists():
            shutil.copy2(existing, backup / existing.name)

    qr = QRCode(None, QRErrorCorrectLevel.M)
    qr.addData(url)
    qr.make()
    quiet, scale = 4, 24
    units = qr.moduleCount + quiet * 2
    bitmap = Image.new("RGB", (units * scale, units * scale), "white")
    draw = ImageDraw.Draw(bitmap)
    for row in range(qr.moduleCount):
        for col in range(qr.moduleCount):
            if qr.isDark(row, col):
                x, y = (col + quiet) * scale, (row + quiet) * scale
                draw.rectangle((x, y, x + scale - 1, y + scale - 1), fill="#183f32")
    bitmap.save(private / "qr-only.png", dpi=(300, 300))

    sans, bold, serif = fonts()
    width, height = A4
    c = canvas.Canvas(str(pdf_path), pagesize=A4, pageCompression=1)
    c.setTitle("Le relais - Accès remplaçant CM1")
    c.setAuthor("Mme Munoz")
    c.setSubject("Mémo à poser sur le bureau : adresse, QR code et mot de passe")
    c.setFillColor(HexColor(PAPER)); c.rect(0, 0, width, height, fill=1, stroke=0)
    c.setStrokeColor(HexColor(LINE)); c.setLineWidth(0.8)
    c.roundRect(30, 30, width - 60, height - 60, 16, fill=0, stroke=1)

    def centered(text: str, y: float, font: str, size: float, color: str = INK):
        c.setFillColor(HexColor(color)); c.setFont(font, size)
        c.drawCentredString(width / 2, y, text)

    c.setFillColor(HexColor(GREEN)); c.roundRect(55, 755, 29, 31, 7, fill=1, stroke=0)
    c.setStrokeColor(white); c.setLineWidth(1.1)
    p = c.beginPath()
    p.moveTo(60, 777); p.curveTo(64, 778, 68, 776, 69.5, 775)
    p.curveTo(73, 777, 76, 778, 79, 777)
    p.lineTo(79, 765); p.curveTo(75, 766, 72, 765, 69.5, 763)
    p.curveTo(67, 765, 63, 766, 60, 765); p.close()
    c.drawPath(p, fill=0, stroke=1); c.line(69.5, 775, 69.5, 763)
    c.setFillColor(HexColor(INK)); c.setFont(bold, 24); c.drawString(95, 768, "Le relais")
    dot_x = 95 + pdfmetrics.stringWidth("Le relais", bold, 24)
    c.setFillColor(HexColor("#cc8c37")); c.drawString(dot_x, 768, ".")
    c.setFillColor(HexColor(MUTED)); c.setFont(sans, 8); c.drawString(96, 755, "L’ESPACE DE REMPLACEMENT")
    c.setStrokeColor(HexColor(LINE)); c.line(55, 735, width - 55, 735)

    centered("Vous prenez le relais ?", 687, serif, 29)
    centered("Retrouvez la journée de CM1", 655, sans, 13, MUTED)
    centered("Programme · Diaporama · Photocopies", 630, bold, 11, GREEN)

    address_x, address_y, address_w, address_h = 55, 518, width - 110, 94
    c.setFillColor(HexColor(GREEN)); c.roundRect(address_x, address_y, address_w, address_h, 13, fill=1, stroke=0)
    centered("À taper dans le navigateur", 583, sans, 12, "#ffffff")
    visible_url = url.removeprefix("https://").rstrip("/")
    url_size = 27
    assert pdfmetrics.stringWidth(visible_url, bold, url_size) <= address_w - 36
    centered(visible_url, 545, bold, url_size, "#ffffff")
    c.linkURL(url, (address_x, address_y, address_x + address_w, address_y + address_h), relative=0, thickness=0)
    centered("Ou scannez ce QR code", 493, sans, 12, MUTED)

    box, by = 230, 250
    bx = (width - box) / 2
    c.setFillColor(white); c.setStrokeColor(HexColor(LINE))
    c.roundRect(bx, by, box, box, 13, fill=1, stroke=1)
    qr_side = 72 * mm
    qr_x, qr_y = (width - qr_side) / 2, by + (box - qr_side) / 2
    unit = qr_side / units
    c.setFillColor(HexColor("#183f32"))
    for row in range(qr.moduleCount):
        for col in range(qr.moduleCount):
            if qr.isDark(row, col):
                c.rect(qr_x + (col + quiet) * unit, qr_y + (units - row - quiet - 1) * unit, unit, unit, fill=1, stroke=0)

    c.setFillColor(HexColor("#e9f0e8")); c.setStrokeColor(HexColor("#c8d7c6"))
    c.roundRect(55, 139, width - 110, 92, 12, fill=1, stroke=1)
    centered("MOT DE PASSE", 207, bold, 10, GREEN)
    password_size = 18
    while pdfmetrics.stringWidth(password, bold, password_size) > width - 150:
        password_size -= 0.25
    if password_size < 15:
        raise ValueError("Le mot de passe est trop long pour une lecture confortable sur le mémo.")
    centered(password, 178, bold, password_size, INK)
    centered("Tout en minuscules, sans accents, avec les tirets.", 157, sans, 10, MUTED)

    centered("Aucun compte à créer", 114, bold, 11, GREEN)
    c.setStrokeColor(HexColor(LINE)); c.line(75, 95, width - 75, 95)
    centered("Mme Munoz · CM1 · 2026-2027", 73, bold, 11)
    centered("Le même lien pour retrouver les documents du jour.", 52, sans, 9.5, MUTED)
    c.showPage(); c.save()

    renderer = shutil.which("pdftoppm")
    if not renderer:
        raise RuntimeError("pdftoppm est nécessaire pour générer et vérifier le mémo PNG.")
    subprocess.run([renderer, "-singlefile", "-png", "-r", "144", str(pdf_path), str(png_path.with_suffix(''))], check=True, capture_output=True)
    # Return only non-secret metadata.
    return {"url": url, "pdf": str(pdf_path), "png": str(png_path), "qrModules": qr.moduleCount,
            "quietZoneModules": quiet, "passwordPrinted": True, "passwordFontSize": password_size,
            "passwordIncludedInQr": False, "privateBackup": str(backup)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=DEFAULT_URL)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--keychain-helper", type=Path, default=ROOT / ".private/keychain-helper")
    args = parser.parse_args()
    print(json.dumps(build(args.url, args.output_dir, args.keychain_helper), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
