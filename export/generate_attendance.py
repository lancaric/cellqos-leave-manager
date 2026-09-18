#!/usr/bin/env python3
import argparse, json
from pathlib import Path
from xml.sax.saxutils import escape
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak

ROOT = Path(__file__).resolve().parent
pdfmetrics.registerFont(TTFont("DejaVu", str(ROOT / "DejaVuSans.ttf")))
pdfmetrics.registerFont(TTFont("DejaVuBold", str(ROOT / "DejaVuSans-Bold.ttf")))
BASE = ParagraphStyle("base", fontName="DejaVu", fontSize=9, leading=12)
TITLE = ParagraphStyle("title", fontName="DejaVuBold", fontSize=17, leading=22, textColor=colors.HexColor("#1F3864"))
HEAD = ParagraphStyle("head", fontName="DejaVuBold", fontSize=8, textColor=colors.white)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True); parser.add_argument("--output", required=True)
    args = parser.parse_args()
    data = json.loads(Path(args.input).read_text(encoding="utf-8"))
    interns = data.get("interns") or ([data["intern"]] if data.get("intern") else [])
    doc=SimpleDocTemplate(args.output,pagesize=A4,leftMargin=1.5*cm,rightMargin=1.5*cm,topMargin=1.5*cm,bottomMargin=1.5*cm)
    story=[]
    for index, intern in enumerate(interns):
        if index:
            story.append(PageBreak())
        intern_records = [row for row in data["records"] if row.get("internId") == intern.get("id")]
        story += [Paragraph("Evidencia dochádzky praktikanta",TITLE),Spacer(1,8),
          Paragraph(f"<b>Praktikant:</b> {escape(intern['name'])}",BASE),
          Paragraph(f"<b>Obdobie:</b> {data['from']} – {data['to']}",BASE),Spacer(1,12)]
        rows=[[Paragraph(x,HEAD) for x in ["Dátum","Dochádzka","Dôvod neprítomnosti"]]]
        for row in intern_records:
            status={"PRESENT":"Prítomný","ABSENT":"Neprítomný"}.get(row.get("status"),"Nezaevidované")
            reason=row.get("reason") or (row.get("internReason") if row.get("internReasonConfirmed") else "") or "–"
            rows.append([Paragraph(escape(row["date"]),BASE),Paragraph(status,BASE),Paragraph(escape(reason),BASE)])
        table=Table(rows,colWidths=[3.2*cm,4*cm,9*cm],repeatRows=1)
        table.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#1F3864")),("GRID",(0,0),(-1,-1),.5,colors.HexColor("#CDD5DF")),("VALIGN",(0,0),(-1,-1),"TOP"),("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,colors.HexColor("#F4F6F9")]),("LEFTPADDING",(0,0),(-1,-1),6),("RIGHTPADDING",(0,0),(-1,-1),6),("TOPPADDING",(0,0),(-1,-1),6),("BOTTOMPADDING",(0,0),(-1,-1),6)]))
        story += [table,Spacer(1,28),Paragraph(f"Poverený zamestnanec: {escape(intern.get('supervisorName') or '–')}",BASE),Spacer(1,24),Paragraph("Vlastnoručný podpis: __________________________________",BASE)]
    doc.build(story)

if __name__ == "__main__": main()
