package report

import (
	"time"

	"github.com/go-pdf/fpdf"
	"github.com/hasia17/arbiter/internal/checks"
)

var checkDescriptions = map[string]string{
	"Strict-Transport-Security": "Forces browsers to always use HTTPS for this site, preventing downgrade attacks.",
	"X-Content-Type-Options":    "Stops browsers from guessing file types, which can prevent some attacks.",
}

func checkDescription(name string) string {
	desc, ok := checkDescriptions[name]
	if !ok {
		return ""
	}
	return desc
}

func WritePDF(url string, results []checks.CheckResult, path string) error {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.AddPage()

	pdf.SetFont("Arial", "B", 20)
	pdf.SetTextColor(20, 20, 20)
	pdf.Cell(0, 10, "Arbiter Security Report")

	pdf.Ln(9)
	pdf.SetFont("Arial", "", 11)
	pdf.SetTextColor(90, 90, 90)
	pdf.Cell(0, 6, "Target: "+url)

	pdf.Ln(6)
	pdf.Cell(0, 6, "Generated: "+time.Now().Format("2006-01-02 15:04"))

	pdf.Ln(10)
	pdf.SetDrawColor(200, 200, 200)
	pdf.SetLineWidth(0.3)
	x, y := pdf.GetX(), pdf.GetY()
	pdf.Line(x, y, 210-x, y)

	pdf.Ln(8)
	pdf.SetAutoPageBreak(false, 0)

	const (
		marginX    = 15.0
		barWidth   = 1.5
		cardHeight = 15.0
		pageBottom = 282.0
	)

	green := [3]int{46, 160, 67}
	red := [3]int{209, 50, 47}

	for _, r := range results {
		desc := checkDescription(r.Name)
		cardH := cardHeight
		if desc != "" {
			cardH += 5
		}

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
		pdf.Rect(x, y, barWidth, cardH-4, "F")

		pdf.SetXY(x+4, y)
		pdf.SetFont("Arial", "B", 11)
		pdf.SetTextColor(20, 20, 20)
		pdf.CellFormat(140, 6, r.Name, "", 0, "L", false, 0, "")

		pdf.SetTextColor(color[0], color[1], color[2])
		pdf.CellFormat(0, 6, status, "", 1, "R", false, 0, "")

		pdf.SetXY(x+4, y+6)
		pdf.SetFont("Arial", "", 9)
		pdf.SetTextColor(110, 110, 110)
		pdf.CellFormat(180, 5, r.Value, "", 1, "L", false, 0, "")

		if desc != "" {
			pdf.SetXY(x+4, y+11)
			pdf.SetFont("Arial", "I", 8)
			pdf.SetTextColor(140, 140, 140)
			pdf.CellFormat(180, 5, desc, "", 1, "L", false, 0, "")
		}

		pdf.SetY(y + cardH)
	}

	return pdf.OutputFileAndClose(path)
}
