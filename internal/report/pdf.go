package report

import (
	"github.com/go-pdf/fpdf"
	"github.com/hasia17/arbiter/internal/checks"
)

func WritePDF(url string, results []checks.CheckResult, path string) error {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.AddPage()

	pdf.SetFont("Arial", "B", 16)
	pdf.Cell(0, 10, "Arbiter security report")

	pdf.Ln(12)
	pdf.SetFont("Arial", "", 12)
	pdf.Cell(0, 10, "Target: "+url)

	pdf.Ln(12)
	for _, r := range results {
		pdf.Cell(0, 8, r.Name+": "+r.Value)
		pdf.Ln(8)
	}

	return pdf.OutputFileAndClose(path)
}
