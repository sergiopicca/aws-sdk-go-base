package rolesanywhere

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

func CreateSession(req CreateSessionInput, region string, signingCert string, privateKey *rsa.PrivateKey) (*CreateSessionOutput, error) {
	now := time.Now().UTC()

	_, canonicalHeaders, signedHeaders := defaultHeaders(region, signingCert, now)
	hashedCanonicalReq, err := createHashedCanonicalRequest(req, canonicalHeaders, signedHeaders)
	if err != nil {
		return nil, fmt.Errorf("failed to create canonical request: %w", err)
	}

	signature, err := sign(region, *hashedCanonicalReq, privateKey, now)
	if err != nil {
		return nil, fmt.Errorf("failed to sign request: %w", err)
	}

	// TODO: Complete the HTTP request with the signature and call the API
	_ = signature

	return nil, nil
}

func sign(region string, hashedCanonicalReq string, privateKey *rsa.PrivateKey, now time.Time) (*string, error) {
	dateTime := now.Format("20060102T150405Z")
	date := now.Format("20060102")

	// TODO: extend support to different algorithm and validate
	stringToSign := "AWS4-X509-RSA-SHA256\n"
	stringToSign += dateTime + "\n"
	stringToSign += date + "/" + region + "/rolesanywhere/aws4_request\n"
	stringToSign += hashedCanonicalReq

	// AWS4-X509-RSA-SHA256 requires signing the raw string-to-sign bytes with
	// RSA-PKCS1v15. Passing crypto.Hash(0) tells SignPKCS1v15 to skip any
	// internal pre-hashing and sign the message bytes directly.
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.Hash(0), []byte(stringToSign))
	if err != nil {
		return nil, fmt.Errorf("failed to sign with private key: %w", err)
	}

	hexSignature := hex.EncodeToString(signature)
	return &hexSignature, nil
}

func createHashedCanonicalRequest(req CreateSessionInput, canonicalHeaders string, signedHeaders string) (*string, error) {
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	canonicalRequest := "POST\n"                                            // HTTP Method
	canonicalRequest += "/session\n"                                        // URI
	canonicalRequest += "\n"                                                // Query Parameters
	canonicalRequest += fmt.Sprintf("%s\n", canonicalHeaders)               // Canonical Headers
	canonicalRequest += fmt.Sprintf("%s\n", signedHeaders)                  // Signed Headers
	canonicalRequest += fmt.Sprintf("%s\n", canonicalHash(string(payload))) // Request Payload

	hashedCanonicalReq := canonicalHash(canonicalRequest)

	return &hashedCanonicalReq, nil
}

// TODO: If the client is providing the chain of intermediate certificates,
// the X-Amz-X509-Chain MUST be added to the request as well.
func defaultHeaders(region string, signingCert string, now time.Time) (http.Header, string, string) {
	var canonicalHeaders string
	var signedHeaders string

	headers := make(http.Header)
	headers.Add("content-type", "application/json")
	headers.Add("host", fmt.Sprintf("rolesanywhere.%s.amazonaws.com", region))
	headers.Add("x-amz-date", now.Format("20060102T150405Z"))
	headers.Add("x-amz-x509", signingCert)

	for k, v := range headers {
		signedHeaders += fmt.Sprintf("%s;", k)
		canonicalHeaders += fmt.Sprintf("%s:%s\n", strings.ToLower(k), strings.TrimSpace(v[0]))
	}
	signedHeaders = strings.TrimSuffix(signedHeaders, ";")

	return headers, canonicalHeaders, signedHeaders
}

func canonicalHash(msg string) string {
	digest := sha256.Sum256([]byte(msg))
	return strings.ToLower(hex.EncodeToString(digest[:]))
}
