package report

import (
	"strings"
	"time"

	"github.com/go-pdf/fpdf"
	"github.com/hasia17/arbiter/internal/checks"
)

// truncateLines wraps text to fit a cell of the given width and keeps at most
// maxLines lines, ending the last one with "..." if anything was cut off.
//
// text must already be converted to cp1252 (see tr in WritePDF). We don't use
// fpdf's SplitText: it expects UTF-8 and panics on characters above U+00FF.
func truncateLines(pdf *fpdf.Fpdf, text string, width float64, maxLines int) []string {
	if maxLines < 1 {
		return nil
	}
	// CellFormat pads text with the cell margin on both sides.
	avail := width - 2*pdf.GetCellMargin()

	lines := wrapText(pdf, text, avail)
	if len(lines) == 0 {
		return []string{""}
	}
	if len(lines) <= maxLines {
		return lines
	}

	lines = lines[:maxLines]
	last := lines[maxLines-1]
	for len(last) > 0 && pdf.GetStringWidth(last+"...") > avail {
		last = last[:len(last)-1]
	}
	lines[maxLines-1] = last + "..."
	return lines
}

// wrapText splits text into lines no wider than width, breaking at spaces.
// A single word wider than a whole line is broken wherever it overflows.
// It slices by bytes, which is safe because cp1252 uses one byte per character.
func wrapText(pdf *fpdf.Fpdf, text string, width float64) []string {
	var lines []string
	line := ""
	for _, word := range strings.Fields(text) {
		candidate := word
		if line != "" {
			candidate = line + " " + word
		}
		if pdf.GetStringWidth(candidate) <= width {
			line = candidate
			continue
		}

		if line != "" {
			lines = append(lines, line)
		}
		for len(word) > 1 && pdf.GetStringWidth(word) > width {
			n := 1
			for n < len(word) && pdf.GetStringWidth(word[:n+1]) <= width {
				n++
			}
			lines = append(lines, word[:n])
			word = word[n:]
		}
		line = word
	}
	if line != "" {
		lines = append(lines, line)
	}
	return lines
}

func WritePDF(url string, results []checks.CheckResult, path string) error {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.AddPage()

	// The built-in fonts only support the cp1252 encoding, while Go strings are
	// UTF-8. tr converts text so that non-ASCII characters don't come out garbled.
	// Characters outside cp1252 (e.g. Polish ś, ż, ł) become ".".
	tr := pdf.UnicodeTranslatorFromDescriptor("")

	const (
		pageWidth     = 210.0
		headerWidth   = pageWidth - 2*10 // fpdf's default 10mm margins
		marginX       = 15.0
		barWidth      = 1.5
		textIndent    = 4.0
		textWidth     = pageWidth - 2*marginX - textIndent
		statusWidth   = 20.0
		nameWidth     = textWidth - statusWidth
		nameHeight    = 6.0
		valueLineH    = 5.0
		descLineH     = 4.0
		cardPadding   = 4.0
		maxValueLines = 3
		maxDescLines  = 2
		pageBottom    = 282.0
	)

	pdf.SetFont("Arial", "B", 20)
	pdf.SetTextColor(20, 20, 20)
	pdf.Cell(0, 10, "Arbiter Security Report")

	pdf.Ln(9)
	pdf.SetFont("Arial", "", 11)
	pdf.SetTextColor(90, 90, 90)
	pdf.Cell(0, 6, truncateLines(pdf, tr("Target: "+url), headerWidth, 1)[0])

	pdf.Ln(6)
	pdf.Cell(0, 6, "Generated: "+time.Now().Format("2006-01-02 15:04"))

	pdf.Ln(10)
	pdf.SetDrawColor(200, 200, 200)
	pdf.SetLineWidth(0.3)
	x, y := pdf.GetX(), pdf.GetY()
	pdf.Line(x, y, pageWidth-x, y)

	pdf.Ln(8)
	pdf.SetAutoPageBreak(false, 0)

	green := [3]int{46, 160, 67}
	red := [3]int{209, 50, 47}

	for _, r := range results {
		// SplitText measures with the current font, so set it before splitting.
		pdf.SetFont("Arial", "B", 11)
		name := truncateLines(pdf, tr(r.Name), nameWidth, 1)[0]

		pdf.SetFont("Arial", "", 9)
		valueLines := truncateLines(pdf, tr(r.Value), textWidth, maxValueLines)

		var descLines []string
		if r.Description != "" {
			pdf.SetFont("Arial", "I", 8)
			descLines = truncateLines(pdf, tr(r.Description), textWidth, maxDescLines)
		}

		cardH := nameHeight +
			float64(len(valueLines))*valueLineH +
			float64(len(descLines))*descLineH +
			cardPadding

		if pdf.GetY()+cardH > pageBottom {
			pdf.AddPage()
		}

		x, y := marginX, pdf.GetY()

		color := red
		status := "FAIL"
		if r.Pass {
			color = green
			status = "PASS"
		}

		pdf.SetFillColor(color[0], color[1], color[2])
		pdf.Rect(x, y, barWidth, cardH-cardPadding, "F")

		pdf.SetXY(x+textIndent, y)
		pdf.SetFont("Arial", "B", 11)
		pdf.SetTextColor(20, 20, 20)
		pdf.CellFormat(nameWidth, nameHeight, name, "", 0, "L", false, 0, "")

		pdf.SetTextColor(color[0], color[1], color[2])
		pdf.CellFormat(statusWidth, nameHeight, status, "", 1, "R", false, 0, "")

		lineY := y + nameHeight
		pdf.SetFont("Arial", "", 9)
		pdf.SetTextColor(110, 110, 110)
		for _, line := range valueLines {
			pdf.SetXY(x+textIndent, lineY)
			pdf.CellFormat(textWidth, valueLineH, line, "", 0, "L", false, 0, "")
			lineY += valueLineH
		}

		pdf.SetFont("Arial", "I", 8)
		pdf.SetTextColor(140, 140, 140)
		for _, line := range descLines {
			pdf.SetXY(x+textIndent, lineY)
			pdf.CellFormat(textWidth, descLineH, line, "", 0, "L", false, 0, "")
			lineY += descLineH
		}

		pdf.SetY(y + cardH)
	}

	return pdf.OutputFileAndClose(path)
}
