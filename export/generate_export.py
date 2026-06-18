#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Portable monthly leave PDF export generator.

Expected CSV columns:
    meno,oddelenie,narok,cerpane_mesiac,cerpane_rok,terminy

The script computes `zostatok` as `narok - cerpane_rok` and renders the PDF
report in the approved company layout.
"""

from __future__ import annotations

import argparse
import csv
import sys
from datetime import datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import HRFlowable, Image, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

SCRIPT_DIR = Path(__file__).resolve().parent

pdfmetrics.registerFont(TTFont("DejaVuSans", str(SCRIPT_DIR / "DejaVuSans.ttf")))
pdfmetrics.registerFont(TTFont("DejaVuSans-Bold", str(SCRIPT_DIR / "DejaVuSans-Bold.ttf")))
pdfmetrics.registerFont(TTFont("DejaVuSans-Oblique", str(SCRIPT_DIR / "DejaVuSans-Oblique.ttf")))

FONT = "DejaVuSans"
FONT_B = "DejaVuSans-Bold"
FONT_I = "DejaVuSans-Oblique"

NAVY = colors.HexColor("#1F3864")
ACCENT_BG = colors.HexColor("#EAF1FB")
ROW_ALT = colors.HexColor("#F4F6F9")
GRID_GRAY = colors.HexColor("#D5DAE1")
TEXT_GRAY = colors.HexColor("#5B6470")
TOTAL_BG = colors.HexColor("#DCE7F6")
NBH = "\u2011"

SLOVAK_MONTHS = {
    1: "Január",
    2: "Február",
    3: "Marec",
    4: "April",
    5: "Maj",
    6: "Jún",
    7: "Júl",
    8: "August",
    9: "September",
    10: "Oktober",
    11: "November",
    12: "December",
}

DEFAULT_COMPANY = {
    "name": "CellQoS, a.s.",
    "address": "Koniarekova 19, 917 01 Trnava",
    "ico": "36817864",
    "dic": "2022424173",
}

PAGE_W, PAGE_H = A4
L_MARGIN = R_MARGIN = 1.3 * cm
T_MARGIN = 2.1 * cm
B_MARGIN = 1.8 * cm
CONTENT_W = PAGE_W - L_MARGIN - R_MARGIN

style_title = ParagraphStyle("title", fontName=FONT_B, fontSize=17, leading=20, textColor=NAVY)
style_subtitle = ParagraphStyle("subtitle", fontName=FONT, fontSize=9.5, leading=13, textColor=TEXT_GRAY)
style_company = ParagraphStyle("company", fontName=FONT_B, fontSize=10.5, leading=13, textColor=NAVY)
style_company_sub = ParagraphStyle("company_sub", fontName=FONT, fontSize=8, leading=11, textColor=TEXT_GRAY)
style_label = ParagraphStyle("label", fontName=FONT_B, fontSize=7, leading=9, textColor=TEXT_GRAY)
style_value = ParagraphStyle("value", fontName=FONT_B, fontSize=10.8, leading=13, textColor=NAVY)
style_section = ParagraphStyle("section", fontName=FONT_B, fontSize=10.5, leading=13, textColor=NAVY, spaceBefore=2, spaceAfter=4)
style_th = ParagraphStyle("th", fontName=FONT_B, fontSize=7.6, leading=9.3, textColor=colors.white, alignment=TA_CENTER)
style_th_left = ParagraphStyle("th_left", fontName=FONT_B, fontSize=7.6, leading=9.3, textColor=colors.white, alignment=TA_LEFT)
style_td = ParagraphStyle("td", fontName=FONT, fontSize=8.3, leading=10.5, textColor=colors.HexColor("#222831"), alignment=TA_CENTER)
style_td_left = ParagraphStyle("td_left", fontName=FONT, fontSize=8.3, leading=10.5, textColor=colors.HexColor("#222831"), alignment=TA_LEFT)
style_total = ParagraphStyle("total", fontName=FONT_B, fontSize=8.4, leading=10.5, textColor=NAVY, alignment=TA_CENTER)
style_total_left = ParagraphStyle("total_left", fontName=FONT_B, fontSize=8.4, leading=10.5, textColor=NAVY, alignment=TA_LEFT)
style_legend = ParagraphStyle("legend", fontName=FONT_I, fontSize=7.3, leading=10, textColor=TEXT_GRAY)
style_sig_label = ParagraphStyle("sig_label", fontName=FONT_B, fontSize=8.6, leading=11, textColor=NAVY)
style_sig_line = ParagraphStyle("sig_line", fontName=FONT, fontSize=8.3, leading=15, textColor=colors.HexColor("#222831"))
style_logo_placeholder = ParagraphStyle("logo_ph", fontName=FONT_B, fontSize=9, textColor=colors.HexColor("#9AA5B1"), alignment=TA_CENTER)


def previous_month(today: datetime | None = None) -> tuple[int, int]:
    today = today or datetime.now()
    month = today.month - 1
    year = today.year
    if month == 0:
        return 12, year - 1
    return month, year


def parse_number(raw: str, line_no: int, column_name: str) -> Decimal:
    normalized = raw.strip().replace(",", ".")
    if not normalized:
        raise ValueError(f"Riadok {line_no}: stlpec {column_name} nesmie byt prazdny.")
    try:
        return Decimal(normalized)
    except InvalidOperation as exc:
        raise ValueError(f"Riadok {line_no}: stlpec {column_name} musi byt cislo.") from exc


def format_number(value: Decimal | float | int) -> str:
    decimal_value = value if isinstance(value, Decimal) else Decimal(str(value))
    normalized = decimal_value.quantize(Decimal("0.01")).normalize()
    text = format(normalized, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text or "0"


def format_terms_for_pdf(value: object) -> str:
    raw = str(value).strip()
    if not raw or raw == "\u2013":
        return escape(raw or "\u2013")

    terms = []
    for part in raw.split(";"):
        term = part.strip()
        if not term:
            continue
        if " - " in term:
            start, end = term.split(" - ", 1)
            term = f"{start}&nbsp;-&nbsp;{end}"
        terms.append(escape(term).replace("&amp;nbsp;", "&nbsp;"))

    return "<br/>".join(terms) if terms else "\u2013"


def read_employees(csv_path: str) -> list[dict[str, object]]:
    required = ["meno", "oddelenie", "narok", "cerpane_mesiac", "cerpane_rok"]
    with open(csv_path, newline="", encoding="utf-8-sig") as handle:
        reader = csv.reader(handle)
        try:
            header = next(reader)
        except StopIteration as exc:
            raise ValueError("Vstupny CSV je prazdny.") from exc

        normalized_header = [column.strip().lower() for column in header]
        missing = [column for column in required if column not in normalized_header]
        if missing:
            raise ValueError(
                "Vstupny CSV nema povinne stlpce: "
                + ", ".join(missing)
                + "\nOcakavane stlpce: "
                + ", ".join(required)
                + ", terminy (nepovinne)"
            )

        indexes = {name: index for index, name in enumerate(normalized_header)}

        def get(raw_row: list[str], column: str, default: str = "") -> str:
            index = indexes.get(column)
            if index is None or index >= len(raw_row):
                return default
            return raw_row[index].strip()

        rows: list[dict[str, object]] = []
        for line_no, raw_row in enumerate(reader, start=2):
            if not raw_row or all(not cell.strip() for cell in raw_row):
                continue

            meno = get(raw_row, "meno")
            if not meno:
                raise ValueError(f"Riadok {line_no}: chyba meno zamestnanca.")

            narok = parse_number(get(raw_row, "narok"), line_no, "narok")
            cerpane_mesiac = parse_number(get(raw_row, "cerpane_mesiac"), line_no, "cerpane_mesiac")
            cerpane_rok = parse_number(get(raw_row, "cerpane_rok"), line_no, "cerpane_rok")

            rows.append(
                {
                    "meno": meno,
                    "oddelenie": get(raw_row, "oddelenie"),
                    "narok": narok,
                    "cerpane_mesiac": cerpane_mesiac,
                    "cerpane_rok": cerpane_rok,
                    "zostatok": narok - cerpane_rok,
                    "terminy": get(raw_row, "terminy") or "\u2013",
                }
            )

    if not rows:
        raise ValueError("Vstupny CSV neobsahuje ziadne pouzitelne riadky so zamestnancami.")

    return rows


def build_logo_cell(logo_path: str | None):
    max_w, max_h = 2.6 * cm, 1.7 * cm
    if logo_path:
        logo = Path(logo_path)
        if logo.exists():
            try:
                from PIL import Image as PILImage

                with PILImage.open(logo) as image:
                    width, height = image.size
                scale = min(max_w / width, max_h / height)
                img = Image(str(logo), width=width * scale, height=height * scale)
                wrapper = Table([[img]], colWidths=[max_w], rowHeights=[max_h])
                wrapper.setStyle(
                    TableStyle(
                        [
                            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                        ]
                    )
                )
                return wrapper
            except Exception as exc:  # pragma: no cover - best effort fallback
                print(f"[VAROVANIE] Logo sa nepodarilo nacitat ({exc}), pouzivam placeholder.", file=sys.stderr)
        else:
            print(f"[VAROVANIE] Logo '{logo_path}' nebolo najdene, pouzivam placeholder.", file=sys.stderr)

    placeholder = Table([[Paragraph("LOGO", style_logo_placeholder)]], colWidths=[max_w], rowHeights=[max_h])
    placeholder.setStyle(
        TableStyle(
            [
                ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor("#C7CDD6")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ]
        )
    )
    return placeholder


def build_pdf(rows: list[dict[str, object]], output_path: Path, logo_path: str | None, month: int, year: int, export_seq: int, company: dict[str, str]) -> None:
    story = []

    logo_cell = build_logo_cell(logo_path)
    company_block = [
        Paragraph(company["name"], style_company),
        Paragraph(company["address"], style_company_sub),
        Paragraph(f"IČO: {company.get('ico', '')} · DIČ: {company.get('dic', '')}", style_company_sub),
    ]
    left_header = Table([[logo_cell, company_block]], colWidths=[2.9 * cm, 7.4 * cm])
    left_header.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ]
        )
    )

    right_header_block = [
        Paragraph("MESAČNÝ EXPORT DOVOLENIEK", style_title),
        Spacer(1, 2),
        Paragraph("Automatický generovaný report z dovolenkového systému", style_subtitle),
    ]

    header_table = Table([[left_header, right_header_block]], colWidths=[10.3 * cm, CONTENT_W - 10.3 * cm])
    header_table.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("ALIGN", (1, 0), (1, 0), "RIGHT"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ]
        )
    )
    story.append(header_table)
    story.append(Spacer(1, 8))
    story.append(HRFlowable(width="100%", thickness=1.4, color=NAVY, spaceAfter=8))

    def info_cell(label: str, value: str):
        return [Paragraph(label.upper(), style_label), Paragraph(value, style_value)]

    export_id = f"DOV{NBH}{year}{NBH}{month:02d}{NBH}{export_seq:03d}"
    info_data = [[
        info_cell("Obdobie exportu", f"{SLOVAK_MONTHS[month]} {year}"),
        info_cell("Export ID", export_id),
        info_cell("Vygenerované", datetime.now().strftime("%d.%m.%Y %H:%M")),
    ]]
    cell_width = CONTENT_W / 3
    info_table = Table(info_data, colWidths=[cell_width] * 3)
    info_table.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BACKGROUND", (0, 0), (-1, -1), ACCENT_BG),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("LINEAFTER", (0, 0), (-2, -1), 0.7, colors.white),
            ]
        )
    )
    story.append(info_table)
    story.append(Spacer(1, 16))

    story.append(Paragraph("Prehľad čerpania dovolenky podľa zamestnancov", style_section))

    headers = [
        Paragraph("Č.", style_th),
        Paragraph("Meno a priezvisko", style_th_left),
        Paragraph("Oddelenie", style_th_left),
        Paragraph("Nárok<br/>(dni/rok)", style_th),
        Paragraph("Čerpané v<br/>mesiaci", style_th),
        Paragraph("Čerpané<br/>celkom (rok)", style_th),
        Paragraph("Zostatok<br/>(dni)", style_th),
        Paragraph("Termín čerpania v mesiaci", style_th_left),
    ]
    table_data = [headers]

    for index, row in enumerate(rows, start=1):
        table_data.append(
            [
                Paragraph(str(index), style_td),
                Paragraph(str(row["meno"]), style_td_left),
                Paragraph(str(row["oddelenie"]), style_td_left),
                Paragraph(format_number(row["narok"]), style_td),
                Paragraph(format_number(row["cerpane_mesiac"]), style_td),
                Paragraph(format_number(row["cerpane_rok"]), style_td),
                Paragraph(format_number(row["zostatok"]), style_td),
                Paragraph(format_terms_for_pdf(row["terminy"]), style_td_left),
            ]
        )

    sum_narok = sum((row["narok"] for row in rows), Decimal("0"))
    sum_mesiac = sum((row["cerpane_mesiac"] for row in rows), Decimal("0"))
    sum_rok = sum((row["cerpane_rok"] for row in rows), Decimal("0"))
    sum_zostatok = sum((row["zostatok"] for row in rows), Decimal("0"))
    table_data.append(
        [
            Paragraph("", style_total),
            Paragraph("SPOLU", style_total_left),
            Paragraph("–", style_total_left),
            Paragraph(format_number(sum_narok), style_total),
            Paragraph(format_number(sum_mesiac), style_total),
            Paragraph(format_number(sum_rok), style_total),
            Paragraph(format_number(sum_zostatok), style_total),
            Paragraph("–", style_total_left),
        ]
    )

    col_fracs = [0.040, 0.200, 0.180, 0.100, 0.110, 0.090, 0.100, 0.18]
    col_widths = [fraction * CONTENT_W for fraction in col_fracs]
    main_table = Table(table_data, colWidths=col_widths, repeatRows=1)

    table_style = [
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, 0), 7),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 7),
        ("TOPPADDING", (0, 1), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 1), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("GRID", (0, 0), (-1, -1), 0.6, GRID_GRAY),
        ("LINEBELOW", (0, 0), (-1, 0), 1.2, NAVY),
        ("BACKGROUND", (0, -1), (-1, -1), TOTAL_BG),
        ("LINEABOVE", (0, -1), (-1, -1), 1.0, NAVY),
    ]
    for row_index in range(1, len(rows) + 1):
        if row_index % 2 == 0:
            table_style.append(("BACKGROUND", (0, row_index), (-1, row_index), ROW_ALT))
    main_table.setStyle(TableStyle(table_style))
    story.append(main_table)
    story.append(Spacer(1, 8))

    story.append(
        Paragraph(
            "* \"Čerpané v mesiaci\" = dni dovolenky čerpané v rámci aktuálne reportovaného mesiaca. "
            "\"Čerpané celkom (rok)\" = kumulatívny súčet od začiatku kalendárneho roka. "
            "\"Zostatok\" = Nárok na dovolenku - Čerpané celkom (rok).",
            style_legend,
        )
    )
    story.append(
        Paragraph("* Tento report je automatický generovaný mesačný export z dovolenkového systemu.", style_legend)
    )
    story.append(Spacer(1, 18))

    def sign_block(role: str):
        return [
            Paragraph(role, style_sig_label),
            Spacer(1, 10),
            Paragraph("Meno a priezvisko: " + "." * 32, style_sig_line),
            Paragraph("Dátum: " + "." * 40, style_sig_line),
            Paragraph("Podpis: " + "." * 40, style_sig_line),
        ]

    sig_table = Table([[sign_block("Schválil")]], colWidths=[CONTENT_W])
    sig_table.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("TOPPADDING", (0, 0), (-1, -1), 10),
                ("LINEABOVE", (0, 0), (-1, 0), 0.8, GRID_GRAY),
            ]
        )
    )
    story.append(sig_table)

    def page_decoration(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(NAVY)
        canvas.rect(0, PAGE_H - 0.32 * cm, PAGE_W, 0.32 * cm, stroke=0, fill=1)
        canvas.setStrokeColor(GRID_GRAY)
        canvas.setLineWidth(0.6)
        canvas.line(L_MARGIN, B_MARGIN - 0.5 * cm, PAGE_W - R_MARGIN, B_MARGIN - 0.5 * cm)
        canvas.setFont(FONT, 7.3)
        canvas.setFillColor(TEXT_GRAY)
        canvas.drawString(
            L_MARGIN,
            B_MARGIN - 0.95 * cm,
            f"Vygenerované automaticky · Dovolenkový systém · {company['name']}",
        )
        canvas.drawRightString(PAGE_W - R_MARGIN, B_MARGIN - 0.95 * cm, f"Strana {doc.page}")
        canvas.restoreState()

    document = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        leftMargin=L_MARGIN,
        rightMargin=R_MARGIN,
        topMargin=T_MARGIN,
        bottomMargin=B_MARGIN,
        title=f"Mesacny export dovoleniek {month:02d}/{year}",
    )
    document.build(story, onFirstPage=page_decoration, onLaterPages=page_decoration)


def main() -> None:
    parser = argparse.ArgumentParser(description="Automaticky generator mesacneho PDF exportu dovoleniek.")
    parser.add_argument("--input", required=True, help="Cesta k vstupnemu CSV so zaznamami o dovolenke")
    parser.add_argument("--logo", default=str(SCRIPT_DIR / "output-onlinepngtools.png"), help="Cesta k logu spolocnosti (PNG)")
    parser.add_argument("--output", default=None, help="Cesta k vystupnemu PDF (default: Export_dovoleniek_MM_YYYY.pdf)")
    parser.add_argument("--month", type=int, default=None, choices=range(1, 13), metavar="1-12", help="Mesiac exportu")
    parser.add_argument("--year", type=int, default=None, help="Rok exportu")
    parser.add_argument("--export-seq", type=int, default=1, help="Poradove cislo exportu v danom mesiaci")
    parser.add_argument("--company-name", default=DEFAULT_COMPANY["name"])
    parser.add_argument("--company-address", default=DEFAULT_COMPANY["address"])
    parser.add_argument("--ico", default=DEFAULT_COMPANY["ico"])
    parser.add_argument("--dic", default=DEFAULT_COMPANY["dic"])
    args = parser.parse_args()

    if args.month is None or args.year is None:
        default_month, default_year = previous_month()
        month = args.month or default_month
        year = args.year or default_year
    else:
        month, year = args.month, args.year

    try:
        rows = read_employees(args.input)
    except (ValueError, FileNotFoundError) as exc:
        print(f"CHYBA: {exc}", file=sys.stderr)
        sys.exit(1)

    output_path = Path(args.output) if args.output else Path(f"Export_dovoleniek_{month:02d}_{year}.pdf")
    company = {
        "name": args.company_name,
        "address": args.company_address,
        "ico": args.ico,
        "dic": args.dic,
    }

    build_pdf(rows, output_path, args.logo, month, year, args.export_seq, company)
    print(f"Hotovo -> {output_path} ({len(rows)} zamestnancov)")


if __name__ == "__main__":
    main()
