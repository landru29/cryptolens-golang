package cryptolens

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"math/big"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/landru29/cryptolens-golang/internal/hardware"
)

const (
	baseURL = "https://app.cryptolens.io"
)

type Client struct {
	baseURL *url.URL
}

type configurator func(*Client) error

func NewClient(opts ...configurator) (*Client, error) {
	cloudURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}

	output := Client{
		baseURL: cloudURL,
	}

	for _, opt := range opts {
		if err := opt(&output); err != nil {
			return nil, err
		}
	}

	return &output, nil
}

func ClientWithURL(customURL string) configurator {
	return func(c *Client) error {
		userURL, err := url.Parse(customURL)
		if err != nil {
			return err
		}

		c.baseURL = userURL

		return nil
	}
}

func (c Client) buildURL(apiPath string) *url.URL {
	output := *c.baseURL

	output.Path = path.Join(output.Path, apiPath)

	return &output
}

type LicenseKey struct {
	ProductId         int              `json:"ProductId"`
	Id                int              `json:"Id"`
	Key               string           `json:"Key"`
	Created           Timestamp        `json:"Created"`
	Expires           Timestamp        `json:"Expires"`
	Period            int              `json:"Period"`
	F1                bool             `json:"F1"`
	F2                bool             `json:"F2"`
	F3                bool             `json:"F3"`
	F4                bool             `json:"F4"`
	F5                bool             `json:"F5"`
	F6                bool             `json:"F6"`
	F7                bool             `json:"F7"`
	F8                bool             `json:"F8"`
	Notes             string           `json:"Notes"`
	Block             bool             `json:"Block"`
	GlobalId          int64            `json:"GlobalId"`
	Customer          Customer         `json:"Customer"`
	ActivatedMachines []ActivationData `json:"ActivatedMachines"`
	TrialActivation   bool             `json:"TrialActivation"`
	MaxNoOfMachines   int              `json:"MaxNoOfMachines"`
	AllowedMachines   StringList       `json:"AllowedMachines"`
	DataObjects       []DataObject     `json:"DataObjects"`
	SignDate          Timestamp        `json:"SignDate"`

	licenseKeyBytes []byte `json:"-"`
	signatureBytes  []byte `json:"-"`
}

func (l LicenseKey) HasExpired() bool {
	return time.Now().After(time.Time(l.Expires))
}

// IsOnRightMachine is the golang version of https://github.com/Cryptolens/cryptolens-python/blob/master/licensing/methods.py#L1455
func (l LicenseKey) IsOnRightMachine(isFloatingLicense bool, allowOverdraft bool, customMachineCode *string) bool {
	currentMid := ""

	if customMachineCode != nil {
		currentMid = *customMachineCode
	} else {
		code, err := hardware.GetMachineCode()
		if err != nil {
			return false
		}

		currentMid = code
	}

	if isFloatingLicense {
		for _, activationData := range l.ActivatedMachines {
			if activationData.Mid[9:] == currentMid || (allowOverdraft && activationData.Mid[19:] == currentMid) {
				return true
			}
		}

		return false
	}

	for _, activationData := range l.ActivatedMachines {
		if activationData.Mid == currentMid {
			return true
		}
	}

	return false
}

type Customer struct {
	Id          int
	Name        string
	Email       string
	CompanyName string
	Created     time.Time
}

type ActivationData struct {
	Mid  string
	IP   string
	Time time.Time
}

type DataObject struct {
	Id          int
	Name        string
	StringValue string
	IntValue    int
}

func (licenseKey *LicenseKey) HasValidSignature(publicKey string) bool {
	type RSAKeyValue struct {
		Modulus  string
		Exponent string
	}
	var k RSAKeyValue
	err := xml.Unmarshal([]byte(publicKey), &k)
	if err != nil {
		return false
	}

	modulusBytes, err := base64.StdEncoding.DecodeString(k.Modulus)
	if err != nil {
		return false
	}

	exponentBytes, err := base64.StdEncoding.DecodeString(k.Exponent)
	if err != nil {
		return false
	}

	modulus := big.NewInt(0).SetBytes(modulusBytes)
	exponent := big.NewInt(0).SetBytes(exponentBytes)

	if !exponent.IsInt64() {
		return false
	}
	key := rsa.PublicKey{N: modulus, E: int(exponent.Int64())}

	hashed := sha256.Sum256(licenseKey.licenseKeyBytes)
	err = rsa.VerifyPKCS1v15(&key, crypto.SHA256, hashed[:], licenseKey.signatureBytes)

	return err == nil
}

func (licenseKey *LicenseKey) ToBytes() ([]byte, error) {
	temp := activateResponse{
		LicenseKey: base64.StdEncoding.EncodeToString(licenseKey.licenseKeyBytes),
		Signature:  base64.StdEncoding.EncodeToString(licenseKey.signatureBytes),
		baseResponse: baseResponse{
			Result:  0,
			Message: "",
		},
	}

	return json.Marshal(temp)
}

func (customer *Customer) UnmarshalJSON(b []byte) error {
	var temp struct {
		Id          int
		Name        string
		Email       string
		CompanyName string
		Created     int64
	}

	err := json.Unmarshal(b, &temp)
	if err != nil {
		return err
	}

	customer.Id = temp.Id
	customer.Name = temp.Name
	customer.Email = temp.Email
	customer.CompanyName = temp.CompanyName
	customer.Created = time.Unix(temp.Created, 0)

	return nil
}

func (activationData *ActivationData) UnmarshalJSON(b []byte) error {
	var temp struct {
		Mid  string
		IP   string
		Time int64
	}

	err := json.Unmarshal(b, &temp)
	if err != nil {
		return err
	}

	activationData.Mid = temp.Mid
	activationData.IP = temp.IP
	activationData.Time = time.Unix(temp.Time, 0)

	return nil
}

func KeyFromBytes(b []byte) (LicenseKey, error) {
	var r activateResponse
	err := json.Unmarshal(b, &r)
	if err != nil {
		return LicenseKey{}, err
	}

	licenseKeyBytes, signatureBytes, err := parseActivateResponse(&r)
	if err != nil {
		return LicenseKey{}, err
	}

	return buildLicenseKey(licenseKeyBytes, signatureBytes)
}

func buildLicenseKey(licenseKeyBytes []byte, signatureBytes []byte) (LicenseKey, error) {
	var k LicenseKey
	err := json.Unmarshal(licenseKeyBytes, &k)
	if err != nil {
		return LicenseKey{}, err
	}

	k.licenseKeyBytes = licenseKeyBytes
	k.signatureBytes = signatureBytes

	return k, nil
}

type Timestamp time.Time

func (t *Timestamp) UnmarshalJSON(data []byte) error {
	var seconds int64

	if err := json.Unmarshal(data, &seconds); err != nil {
		return err
	}

	*t = Timestamp(time.Unix(seconds, 0))

	return nil
}

type StringList []string

func (s *StringList) UnmarshalJSON(data []byte) error {
	var list []string

	if err := json.Unmarshal(data, &list); err == nil {
		*s = StringList(list)

		return nil
	}

	var element string

	if err := json.Unmarshal(data, &element); err != nil {
		return err
	}

	if element != "" {
		*s = StringList(strings.Split(element, "\n"))
	}

	return nil
}

type baseResponse struct {
	Result  int    `json:"result"`
	Message string `json:"message"`
}

func GetMachineCode() (string, error) {
	return hardware.GetMachineCode()
}

func MustGetMachineCode() string {
	code, err := hardware.GetMachineCode()
	if err != nil {
		panic(err)
	}

	return code
}
