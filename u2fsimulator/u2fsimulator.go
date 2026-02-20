package u2fsimulator

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

const (
	DefaultKeyHandle = `U2fSimulatorKey`

	// Using this instead of rand.Reader, in order to have consistent
	//  private and public keys, which allows for comparison when tests fail
	BigStrNotRandom1 = "11111111111111111111111111111111111111111"

	// The authenticatorData value includes bytes that refer to these flags.
	// Multiple flags can be combined through addition. For example,
	// including the UserPresent (UP) and AttestedCredentialData (AT) flags would be done
	// by using the value 65.
	// AT(64) + UP(1) = 65
	AttObjFlagUserPresent_UP      = 1
	AttObjFlagUserVerified_UV     = 2
	AttObjFlagAttestedCredData_AT = 64
	AttObjFlagExtensionData_ED    = 128
)

// Internal type for ASN1 coercion
type DsaSignature struct {
	R, S *big.Int
}

// ClientData as defined by the FIDO U2F Raw Message Formats specification.
type ClientData struct {
	Typ          string          `json:"type"`
	Challenge    string          `json:"challenge"`
	Origin       string          `json:"origin"`
	CIDPublicKey json.RawMessage `json:"cid_pubkey"`
}

func fixStringEncoding(content string) string {
	content = strings.ReplaceAll(content, "+", "-")
	content = strings.ReplaceAll(content, "/", "_")
	content = strings.ReplaceAll(content, "=", "")
	return content
}

func jsonResponse(w http.ResponseWriter, body any, status int) {
	var data any
	switch b := body.(type) {
	case error:
		data = struct {
			Error string `json:"error"`
		}{Error: b.Error()}
	default:
		data = body
	}

	var jBody []byte
	var err error
	if data != nil {
		jBody, err = json.Marshal(data)
		if err != nil {
			log.Printf("failed to marshal response body to json: %s", err)
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("failed to marshal response body to json"))
			return
		}
	}

	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	_, err = w.Write(jBody)
	if err != nil {
		log.Printf("failed to write response in jsonResponse: %s", err)
	}
}

func GetClientDataJson(ceremonyType, challenge, rpOrigin string) (string, []byte) {
	if ceremonyType != "webauthn.create" && ceremonyType != "webauthn.get" {
		panic(`ceremonyType must be "webauthn.create" or "webauthn.get"`)
	}

	cd := ClientData{
		Typ:       ceremonyType,
		Origin:    rpOrigin,
		Challenge: challenge,
	}

	cdJson, _ := json.Marshal(cd)

	clientData := base64.URLEncoding.EncodeToString(cdJson)
	return clientData, cdJson
}

// getPrivateKey returns a newly generated ecdsa private key without using any kind of randomizing
func getPrivateKey() *ecdsa.PrivateKey {
	curve := elliptic.P256()
	notRandomReader := strings.NewReader(BigStrNotRandom1)
	privateKey, err := ecdsa.GenerateKey(curve, notRandomReader)
	if err != nil {
		panic("error generating privateKey: " + err.Error())
	}

	return privateKey
}

// GetAuthDataAndPrivateKey return the authentication data as a string and as a byte slice
// and also returns the private key
func GetAuthDataAndPrivateKey(rpID, keyHandle string) (authDataStr string, authData []byte, privateKey *ecdsa.PrivateKey) {
	// Add in the RP ID Hash (32 bytes)
	hash := sha256.Sum256([]byte(rpID))
	for _, r := range hash {
		authData = append(authData, r)
	}

	authData = append(authData, byte(AttObjFlagAttestedCredData_AT+AttObjFlagUserPresent_UP)) // AT & UP flags

	// Add 4 bytes for counter = 0 (for now, just make it 0)
	authData = append(authData, []byte{byte(0), byte(0), byte(0), byte(0)}...)

	// Add 16 bytes for (zero) AAGUID
	aaguid := make([]byte, 16)
	authData = append(authData, aaguid...)

	credID := []byte(keyHandle)

	kHLen := len(keyHandle)
	if kHLen >= 256 {
		panic("the length of the keyHandle must be less than 256")
	}
	idLen := []byte{byte(0), byte(kHLen)}

	authData = append(authData, idLen...)
	authData = append(authData, credID...)

	privateKey = getPrivateKey()
	publicKey := privateKey.PublicKey

	pubKeyData := webauthncose.EC2PublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{
			Algorithm: int64(webauthncose.AlgES256),
			KeyType:   int64(webauthncose.EllipticKey),
		},
		XCoord: publicKey.X.Bytes(),
		YCoord: publicKey.Y.Bytes(),
	}

	// Get the CBOR-encoded representation of the OKPPublicKeyData
	pubKeyBytes, err := webauthncbor.Marshal(pubKeyData)
	if err != nil {
		panic("error Marshaling publicKeyData: " + err.Error())
	}

	authData = append(authData, pubKeyBytes...)
	authDataStr = base64.RawURLEncoding.EncodeToString(authData)
	return authDataStr, authData, privateKey
}

// getCertBytes generates an x509 certificate without using any kind of randomization
// Most of this was borrowed from https://github.com/ryankurte/go-u2f
func getCertBytes(privateKey *ecdsa.PrivateKey, serialNumber *big.Int, certReaderStr string) []byte {
	template := x509.Certificate{}

	template.SerialNumber = serialNumber
	template.KeyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign

	template.NotBefore = time.Date(2022, 1, 1, 1, 1, 1, 1, time.UTC)
	template.NotAfter = time.Date(2122, 1, 1, 1, 1, 1, 1, time.UTC) // 100 years

	template.SignatureAlgorithm = x509.ECDSAWithSHA256

	newReader := strings.NewReader(certReaderStr)

	certBytes, err := x509.CreateCertificate(newReader, &template, &template, &(privateKey.PublicKey), privateKey)
	if err != nil {
		panic("error creating x509 certificate " + err.Error())
	}

	return certBytes
}

// GetASN1Signature signs a hash (which should be the result of hashing a larger message)
// using the private key.
func GetASN1Signature(notRandom io.Reader, privateKey *ecdsa.PrivateKey, sha256Digest []byte) (DsaSignature, []byte) {
	r, s, err := ecdsa.Sign(notRandom, privateKey, sha256Digest[:])
	if err != nil {
		panic("error generating signature: " + err.Error())
	}

	dsaSig := DsaSignature{R: r, S: s}

	asnSig, err := asn1.Marshal(dsaSig)
	if err != nil {
		panic("error encoding signature: " + err.Error())
	}

	return dsaSig, asnSig
}

// getSignatureForAttObject starts with byte(0) and appends the sha256 sum of the rpOrigin and of the clientData
// and then appends the keyHandle and an elliptic Marshalled version of the public key. It does a sha256 sum of
// that and creates a dsa signature of it with the private key and without using any randomizing.
func getSignatureForAttObject(notRandom io.Reader, clientData []byte, keyHandle string, privateKey *ecdsa.PrivateKey, rpOrigin string) []byte {
	appParam := sha256.Sum256([]byte(rpOrigin))
	challenge := sha256.Sum256(clientData)

	publicKey := privateKey.PublicKey

	buf := []byte{0}
	buf = append(buf, appParam[:]...)
	buf = append(buf, challenge[:]...)
	buf = append(buf, keyHandle...)
	pk := elliptic.Marshal(publicKey.Curve, publicKey.X, publicKey.Y)
	buf = append(buf, pk...)

	digest := sha256.Sum256(buf)
	_, asnSig := GetASN1Signature(notRandom, privateKey, digest[:])
	return asnSig
}

// GetAttestationObject builds an attestation object for a webauth registration.
func GetAttestationObject(authDataBytes, clientData []byte, keyHandle string, privateKey *ecdsa.PrivateKey, rpOrigin string) string {
	bigNumStr := "123456789012345678901234567890123456789012345678901234567890123456789012345678"
	bigNum := new(big.Int)
	bigNum, ok := bigNum.SetString(bigNumStr, 10)
	if !ok {
		panic("failed to set bigNumber to string")
	}
	attestationCertBytes := getCertBytes(privateKey, bigNum, BigStrNotRandom1)

	notRandomReader := strings.NewReader(BigStrNotRandom1)
	signature := getSignatureForAttObject(notRandomReader, clientData, keyHandle, privateKey, rpOrigin)

	attObj := protocol.AttestationObject{
		Format: "fido-u2f",

		RawAuthData: authDataBytes,
		AttStatement: map[string]any{
			`x5c`: []any{attestationCertBytes},
			`sig`: signature,
		},
	}

	marshalledAttObj, err := webauthncbor.Marshal(&attObj)
	if err != nil {
		panic("error marshalling AttestationObject: " + err.Error())
	}

	b64RawURL := base64.RawURLEncoding.EncodeToString(marshalledAttObj)
	return b64RawURL
}

type AttObjectClientData struct {
	AuthenticatorData string `json:"authenticatorData"`
	AttestationObject string `json:"attestationObject"`
	ClientDataJSON    string `json:"clientDataJSON"`
}

type U2fRegistrationResponse struct {
	ID                     string              `json:"id"`
	RawID                  string              `json:"rawId"`
	Response               AttObjectClientData `json:"response"`
	ClientExtensionResults map[string]string   `json:"clientExtensionResults"`
	Type                   string              `json:"type"`
	Transports             []string            `json:"transports"`
}

// U2fRegistration is intended to assist with automated testing by
// returning to an api server something similar to what a client
// would return following a registration ceremony with a U2F key
//
// It expects a POST call with the following elements in the body/form
//
//	"challenge"
//	"keyHandle" (optional)
//
// (Although the api server wouldn't normally deal with a challenge and keyHandle,
// including them here allows for more predictability with the test results.)
//
// It also expects the following headers to be set on the request
//
//	"x-mfa-RPID"
//	"x-mfa-RPOrigin"
//	"x-mfa-UserUUID"
func U2fRegistration(w http.ResponseWriter, r *http.Request) {
	reqBody, err := io.ReadAll(r.Body)
	if err != nil {
		panic(err)
	}

	var reqParams map[string]string
	if err := json.Unmarshal(reqBody, &reqParams); err != nil {
		panic(err)
	}
	log.Printf("U2fRegistration httpRequest: %v", reqParams)

	challenge := reqParams["challenge"]
	if challenge == "" {
		panic("'challenge' POST param is required.")
	}
	challenge = fixStringEncoding(challenge)

	keyHandle := reqParams["keyHandle"]
	if keyHandle == "" {
		keyHandle = DefaultKeyHandle
	}
	rpID := r.Header.Get("x-mfa-RPID")
	rpOrigin := r.Header.Get("x-mfa-RPOrigin")
	id := r.Header.Get("x-mfa-UserUUID")

	required := map[string]string{
		"x-mfa-RPID":     rpID,
		"x-mfa-RPOrigin": rpOrigin,
		"x-mfa-UserUUID": id,
	}
	for key, value := range required {
		if value == "" {
			panic(fmt.Sprintf("'%s' header is required.", key))
		}
	}

	clientDataStr, clientData := GetClientDataJson("webauthn.create", challenge, rpOrigin)
	authDataStr, authDataBytes, privateKey := GetAuthDataAndPrivateKey(rpID, keyHandle)

	attestationObject := GetAttestationObject(authDataBytes, clientData, keyHandle, privateKey, rpOrigin)

	resp := U2fRegistrationResponse{
		ID:    id,
		RawID: id,
		Response: AttObjectClientData{
			AuthenticatorData: authDataStr,
			AttestationObject: attestationObject,
			ClientDataJSON:    clientDataStr,
		},
		ClientExtensionResults: map[string]string{},
		Type:                   "public-key",
		Transports:             []string{"usb"},
	}

	jsonResponse(w, resp, http.StatusOK)
}
