package cryptolens

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
)

func (c Client) GetKey(token string, args GetKeyArguments) (LicenseKey, error) {
	activateResponse, err := c.makeGetKeyRequest(token, args)
	if err != nil {
		return LicenseKey{}, err
	}

	licenseKeyBytes, signatureBytes, err := parseGetKeyResponse(activateResponse)
	if err != nil {
		return LicenseKey{}, err
	}

	return buildLicenseKey(licenseKeyBytes, signatureBytes)
}

func (c Client) makeGetKeyRequest(token string, args GetKeyArguments) (*getKeyResponse, error) {
	var http http.Client

	// From KeyActivateArguments struct
	data := url.Values{}
	data.Set("token", token)
	data.Set("ProductId", strconv.Itoa(args.ProductId))
	data.Set("Key", args.Key)
	data.Set("FieldsToReturn", strconv.Itoa(args.FieldsToReturn))
	data.Set("FloatingTimeInterval", strconv.Itoa(args.FloatingTimeInterval))

	// Hardcoded by the library
	data.Set("Sign", "true")
	data.Set("SignMethod", "1")

	response, err := http.PostForm(c.buildURL("api/key/GetKey").String(), data)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	dec := json.NewDecoder(response.Body)
	var r getKeyResponse
	err = dec.Decode(&r)
	if err != nil {
		return nil, err
	}

	return &r, nil
}

func parseGetKeyResponse(response *getKeyResponse) ([]byte, []byte, error) {
	licenseKeyBytes, err := base64.StdEncoding.DecodeString(response.LicenseKey)
	if err != nil {
		return []byte{}, []byte{}, err
	}

	signatureBytes, err := base64.StdEncoding.DecodeString(response.Signature)
	if err != nil {
		return []byte{}, []byte{}, err
	}

	return licenseKeyBytes, signatureBytes, nil
}

type getKeyResponse struct {
	baseResponse
	LicenseKey string         `json:"licenseKey"`
	Metadata   map[string]any `json:"Metadata"`
	Signature  string         `json:"signature"`
}

type GetKeyArguments struct {
	ProductId            int
	Key                  string
	FieldsToReturn       int
	FloatingTimeInterval int
}
