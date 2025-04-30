package cryptolens

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
)

func (c Client) KeyActivate(token string, args KeyActivateArguments) (LicenseKey, error) {
	activateResponse, err := c.makeActivateRequest(token, args)
	if err != nil {
		return LicenseKey{}, err
	}

	licenseKeyBytes, signatureBytes, err := parseActivateResponse(activateResponse)
	if err != nil {
		return LicenseKey{}, err
	}

	return buildLicenseKey(licenseKeyBytes, signatureBytes)
}

func (c Client) makeActivateRequest(token string, args KeyActivateArguments) (*activateResponse, error) {
	var http http.Client

	// From KeyActivateArguments struct
	data := url.Values{}
	data.Set("token", token)
	data.Set("ProductId", strconv.Itoa(args.ProductId))
	data.Set("Key", args.Key)
	data.Set("MachineCode", args.MachineCode)
	data.Set("FieldsToReturn", strconv.Itoa(args.FieldsToReturn))
	data.Set("FloatingTimeInterval", strconv.Itoa(args.FloatingTimeInterval))
	data.Set("MaxOverdraft", strconv.Itoa(args.MaxOverdraft))

	// Hardcoded by the library
	data.Set("Sign", "true")
	data.Set("SignMethod", "1")

	response, err := http.PostForm(c.buildURL("api/key/Activate").String(), data)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	dec := json.NewDecoder(response.Body)
	var r activateResponse
	err = dec.Decode(&r)
	if err != nil {
		return nil, err
	}

	return &r, nil
}

func parseActivateResponse(response *activateResponse) ([]byte, []byte, error) {
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

type KeyActivateArguments struct {
	ProductId            int
	Key                  string
	MachineCode          string
	FieldsToReturn       int
	FloatingTimeInterval int
	MaxOverdraft         int
}

type activateResponse struct {
	baseResponse
	LicenseKey string `json:"licenseKey"`
	Signature  string `json:"signature"`
}
