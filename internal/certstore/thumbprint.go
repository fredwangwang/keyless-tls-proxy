package certstore

import "strings"

// NormalizeThumbprint normalizes a thumbprint by removing separators (colons, spaces, dashes)
// and converting to uppercase, so "aa:bb", "aa bb", "aa-bb" and "AABB" all produce "AABB".
func NormalizeThumbprint(tp string) string {
	tp = strings.ToUpper(strings.TrimSpace(tp))
	tp = strings.ReplaceAll(tp, ":", "")
	tp = strings.ReplaceAll(tp, " ", "")
	tp = strings.ReplaceAll(tp, "-", "")
	return tp
}

func cleanThumbprint(tp string) string {
	return NormalizeThumbprint(tp)
}
