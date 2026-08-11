package certstore

import "strings"

// cleanThumbprint normalizes a thumbprint by removing separators and
// upper-casing, so "aa:bb", "aa bb", "aa-bb" and "AABB" all match.
func cleanThumbprint(tp string) string {
	tp = strings.ToUpper(strings.TrimSpace(tp))
	tp = strings.ReplaceAll(tp, ":", "")
	tp = strings.ReplaceAll(tp, " ", "")
	tp = strings.ReplaceAll(tp, "-", "")
	return tp
}
