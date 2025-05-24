package keycloak

import "strings"

func join(parts ...string) string {
	if len(parts) == 0 {
		return ""
	}
	var url = ""
	var v string
	for i, item := range parts {
		if i == 0 {
			url = strings.Trim(item, "/")
			continue
		}
		v = strings.Trim(item, "/")
		if v == "" {
			continue
		}
		url += "/" + v
	}
	return url
}
