package helper

import (
	"fmt"
)

// FormatRupiah formats a number as Indonesian Rupiah currency without "Rp" and thousands separators
func FormatRupiah(amount float64) string {
	// Format without commas as thousand separators and append ",00" for cents
	formattedAmount := fmt.Sprintf("%.0f,00", amount)
	return formattedAmount
}
