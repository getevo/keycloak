package keycloak

import "strings"

func join(parts ...string) string {
	if len(parts) == 0 {
		return ""
	}
	var url = ""
	for i, item := range parts {
		if i == 0 {
			url = strings.Trim(item, "/")
			continue
		}
		url += "/" + strings.Trim(item, "/")
	}
	return url
}
