package keycloak

import (
	"github.com/getevo/evo/v2/lib/db/schema"
	"github.com/getevo/evo/v2/lib/log"
)

type App struct{}

var client Client
var userModel *schema.Model

func (a App) Register() error {

	return nil
}

func (a App) Router() error {
	return nil
}

func (a App) WhenReady() error {
	var _, err = Connect()
	if err != nil {
		log.Errorf("failed to connect to Keycloak server: %v", err)
	}
	getClient()
	go migrate()

	return err
}

func (a App) Name() string {
	return "keycloak"
}
