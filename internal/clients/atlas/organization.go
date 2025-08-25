// Package organization for the mongodb client
package organization

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/icholy/digest"
	"github.com/pkg/errors"
)

const (
	errJSON           = "unable to parse JSON"
	errStatusCode     = "unexpected Status Code %d"
	errRequest        = "request failed with status code %d and reason: %s"
	errValidation     = "validation error: %s"
	errUnprocessable  = "unprocessable request: %s"
	errProfileExists  = "profile already exists %s"
	errUnknownWithErr = "unknown error %s"
	errUnknown        = "unknown error"
)

const (
	getOrganizationURL    = "https://cloud.mongodb.com/api/atlas/v1.0/orgs/%s" // orgID
	createOrganizationURL = "https://cloud.mongodb.com/api/atlas/v1.0/orgs"
	deleteOrganizationURL = "https://cloud.mongodb.com/api/atlas/v1.0/orgs/%s" // orgID
)

// Client model for atlas
type Client struct {
	rootCredentials Credentials
	orgCredentials  *Credentials
}

func (c *Client) getRootClient() *http.Client {
	return &http.Client{
		Transport: &digest.Transport{
			Username: c.rootCredentials.PublicKey,
			Password: c.rootCredentials.PrivateKey,
		},
	}
}

func (c *Client) getOrgClient() *http.Client {
	return &http.Client{
		Transport: &digest.Transport{
			Username: c.orgCredentials.PublicKey,
			Password: c.orgCredentials.PrivateKey,
		},
	}
}

// Credentials model for Ingress Registration API credentials
type Credentials struct {
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
}

// NewAtlasClient creates an atlas client
func NewAtlasClient(rootCredentials Credentials, orgCredentials *Credentials) (*Client, error) {
	return &Client{
		rootCredentials: rootCredentials,
		orgCredentials:  orgCredentials,
	}, nil
}

// GetOrgResponse object represents the successful response of the get organization api
type GetOrgResponse struct {
	IsDeleted bool   `json:"isDeleted"`
	Name      string `json:"name"`
}

// ErrorResponse allows to deserialize
type ErrorResponse struct {
	Reason string `json:"reason"`
	Detail string `json:"detail"`
}

// ErrNotFound is an error representing a 404 http response
var ErrNotFound = errors.New("not found")

// GetOrganization function to check the status of the organization
func (c *Client) GetOrganization(ctx context.Context, orgID string) (GetOrgResponse, error) {

	if c.orgCredentials == nil {
		return GetOrgResponse{}, errors.New("missing org credentials to get organization")
	}

	requestURL := fmt.Sprintf(getOrganizationURL, orgID)

	request, err := http.NewRequestWithContext(ctx, "GET", requestURL, nil)
	if err != nil {
		return GetOrgResponse{}, err
	}
	res, err := c.getOrgClient().Do(request)
	if err != nil {
		return GetOrgResponse{}, err
	}
	defer res.Body.Close() //nolint:errcheck // ignoring response body error

	resBody, err := io.ReadAll(res.Body)

	if err != nil {
		return GetOrgResponse{}, err
	}

	if res.StatusCode == 200 {
		var org GetOrgResponse
		err := json.Unmarshal(resBody, &org)
		if err != nil {
			return GetOrgResponse{}, err
		}
		return org, nil
	}

	if res.StatusCode == 404 {
		return GetOrgResponse{}, err
	}

	// error status code
	var errResp ErrorResponse

	if err = json.Unmarshal(resBody, &errResp); err != nil {
		return GetOrgResponse{}, err
	}
	return GetOrgResponse{}, fmt.Errorf(errRequest, res.StatusCode, resBody)
}

// APIKey describes an api key for the creation payload
type APIKey struct {
	Description string   `json:"desc"`
	Roles       []string `json:"roles"`
}

// CreateOrgPayload allows to serialize the request data
type CreateOrgPayload struct {
	Name       string `json:"name"`
	OrgOwnerID string `json:"orgOwnerId"`
	APIKey     APIKey `json:"apiKey"`
}

// CreateOrgResponse contains data returned from create-org-request
type CreateOrgResponse struct {
	APIKey struct {
		ID         string `json:"id"`
		PrivateKey string `json:"privateKey"`
		PublicKey  string `json:"publicKey"`
	} `json:"apiKey"`
	Organization struct {
		ID        string `json:"id"`
		IsDeleted bool   `json:"isDeleted"`
	} `json:"organization"`
}

// CreateOrganization function to create a new organization
func (c *Client) CreateOrganization(ctx context.Context, name string, apiKey APIKey, ownerID string) (CreateOrgResponse, error) {
	payload := CreateOrgPayload{
		Name:       name,
		OrgOwnerID: ownerID,
		APIKey:     apiKey,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return CreateOrgResponse{}, err
	}

	bodyReader := bytes.NewReader(payloadBytes)

	request, err := http.NewRequestWithContext(ctx, "POST", createOrganizationURL, bodyReader)
	if err != nil {
		return CreateOrgResponse{}, err
	}

	request.Header.Set("Content-Type", "application/json")

	res, err := c.getRootClient().Do(request)
	if err != nil {
		return CreateOrgResponse{}, err
	}

	defer res.Body.Close() //nolint:errcheck // ignoring response body error

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return CreateOrgResponse{}, err
	}

	if res.StatusCode == 201 {
		var org CreateOrgResponse
		err := json.Unmarshal(resBody, &org)
		if err != nil {
			return CreateOrgResponse{}, err
		}
		return org, nil
	}

	if res.StatusCode == 404 {
		return CreateOrgResponse{}, fmt.Errorf("not found: %s", resBody)
	}

	// error status code
	var errResp ErrorResponse

	if err = json.Unmarshal(resBody, &errResp); err != nil {
		return CreateOrgResponse{}, err
	}
	return CreateOrgResponse{}, fmt.Errorf(errRequest, res.StatusCode, errResp.Detail)
}

// DeleteOrganization function to delete an existing organization
func (c *Client) DeleteOrganization(ctx context.Context, orgID string) error {
	requestURL := fmt.Sprintf(deleteOrganizationURL, orgID)

	request, err := http.NewRequestWithContext(ctx, "POST", requestURL, nil)
	if err != nil {
		return err
	}

	request.Header.Set("Content-Type", "application/json")

	res, err := c.getOrgClient().Do(request)
	if err != nil {
		return err
	}

	defer res.Body.Close() //nolint:errcheck // ignoring response body error

	if res.StatusCode == 204 {
		return nil
	}

	if res.StatusCode == 404 {
		return ErrNotFound
	}

	// error status code
	var errResp ErrorResponse

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}

	if err = json.Unmarshal(resBody, &errResp); err != nil {
		return err
	}
	return fmt.Errorf(errRequest, res.StatusCode, errResp.Reason)
}
