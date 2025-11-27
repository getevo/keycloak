package keycloak

import (
	"fmt"
	"github.com/getevo/evo/v2/lib/curl"
)

// Put sends a PUT request to the specified endpoint with the provided query strings and data. It returns a curl.Resp and an error.
// Parameters:
// - endpoint: The endpoint path to send the request to.
// - query: The query string to be appended to the endpoint URL.
// - data: Optional data to be included in the request body.
// Returns:
// - *curl.Resp: The response from the PUT request.
// - error: Any error that occurred during the request.
func (connection *Connection) Put(endpoint string, query string, data ...interface{}) (*curl.Resp, error) {
	data = connection.PrepareRequest(data)
	var url = join(connection.Settings.Server, connection.Settings.BasePath, endpoint, "realms", connection.Settings.Realm, query)
	resp, err := curl.Put(url, data...)
	if err != nil {
		return nil, err
	}
	if connection.Settings.Debug {
		fmt.Println(resp.Dump())
	}
	resp, err = handleRedirect(resp)
	if err != nil {
		return nil, err
	}
	if resp.Response().StatusCode == 204 {
		return resp, nil
	}
	return resp, nil
}

func (connection *Connection) Delete(endpoint string, query string, data ...interface{}) (*curl.Resp, error) {
	data = connection.PrepareRequest(data)
	var url = join(connection.Settings.Server, connection.Settings.BasePath, endpoint, "realms", connection.Settings.Realm, query)
	resp, err := curl.Delete(url, data...)
	if err != nil {
		return nil, err
	}
	if connection.Settings.Debug {
		fmt.Println(resp.Dump())
	}
	resp, err = handleRedirect(resp)
	if err != nil {
		return nil, err
	}
	if resp.Response().StatusCode == 204 {
		return resp, nil
	}
	return resp, nil
}

// Post sends a POST request to the specified endpoint with optional query parameters and data. It returns the response and an error if any.
func (connection *Connection) Post(endpoint string, query string, data ...interface{}) (*curl.Resp, error) {
	data = connection.PrepareRequest(data)
	var url = join(connection.Settings.Server, connection.Settings.BasePath, endpoint, "realms", connection.Settings.Realm, query)
	resp, err := curl.Post(url, data...)
	if err != nil {
		return nil, err
	}
	if connection.Settings.Debug {
		fmt.Println(resp.Dump())
	}
	/*resp, err = handleRedirect(resp)
	if resp.Response().StatusCode == 204 {
		return resp, nil
	}*/
	return resp, nil
}

// Get method sends a GET request to the specified endpoint with optional query parameters and data.
//
// Parameters:
// - endpoint: the endpoint URL string to send the request to.
// - query: the query string to include in the request URL.
// - data: optional variadic parameter to include data in the request body.
//
// Returns:
// - *curl.Resp: the response object containing the HTTP response information.
// - error: any error that occurred during the request.
func (connection *Connection) Get(endpoint string, query string, data ...interface{}) (*curl.Resp, error) {
	data = connection.PrepareRequest(data)
	var url = join(connection.Settings.Server, connection.Settings.BasePath, endpoint, "realms", connection.Settings.Realm, query)
	resp, err := curl.Get(url, data...)
	if err != nil {
		return nil, err
	}
	if connection.Settings.Debug {
		fmt.Println(resp.Dump())
	}
	resp, err = handleRedirect(resp)
	return resp, nil
}

// handleRedirect redirects the response to the location specified in the "location" header, if present.
// It uses the curl.Get function to make a new request to the location. If there is an error during the request, it returns nil and the error.
// If there is no "location" header or there is no error, it returns the original response and nil error.
func handleRedirect(resp *curl.Resp) (*curl.Resp, error) {
	var err error
	if resp.Response().Header.Get("location") != "" {
		resp, err = curl.Get(resp.Response().Header.Get("location"), resp.Request().Header)
		if err != nil {
			return nil, err
		}
	}
	return resp, nil
}
