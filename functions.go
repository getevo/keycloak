package keycloak

import "strings"

func join(parts ...string) string {
	if len(parts) == 0 {
		return ""
	}
	var url = ""
	for _, item := range parts {
		url += "/" + strings.Trim(item, "/")
	}
	if parts[0][0] != '/' {
		url = strings.TrimRight(url, "/")
	}
	return url
}
