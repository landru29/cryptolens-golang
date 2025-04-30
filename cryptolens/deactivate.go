package cryptolens

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
)

func (c Client) KeyDeactivate(token string, key LicenseKey, floating bool) error {
	var http http.Client

	data := url.Values{}
	data.Set("token", token)
	data.Set("ProductId", strconv.Itoa(key.ProductId))
	data.Set("Floating", map[bool]string{true: "true", false: "false"}[floating])

	response, err := http.PostForm(c.buildURL("api/key/Deactivate").String(), data)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	dec := json.NewDecoder(response.Body)
	var r baseResponse
	err = dec.Decode(&r)
	if err != nil {
		return err
	}

	if r.Result != 0 {
		return errors.New(r.Message)
	}

	return nil
}
