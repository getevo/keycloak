package keycloak

import (
	"github.com/getevo/evo/v2/lib/curl"
	"github.com/getevo/evo/v2/lib/log"
)

func getClient() {
	post, err := conn.Get("/admin", "/clients", curl.Header{
		"Authorization": "Bearer " + conn.Admin.AccessToken,
	})
	if err != nil {
		log.Errorf("Failed to create or update Keycloak client: %v", err)
		return
	}

	var clients []Client
	err = post.ToJSON(&clients)
	if err != nil {
		log.Errorf("Failed to parse Keycloak client response: %v", err)
		return
	}

	for _, c := range clients {
		if c.ClientID == conn.Settings.Client {
			client = c
			break
		}
	}
}
