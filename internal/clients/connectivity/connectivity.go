// Package organization for the mongodb client
package organization

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

const (
	errorCodeNotFound = "InvalidVpcEndpointId.NotFound"
)

// ErrNotFound is a sentinel for a 404 error
var ErrNotFound = errors.New("not found")

// Client model for vpc endpoint lambdas
type Client struct {
	BaseURL string
	APIKey  string
}

// Credentials model that describes configuration options for the client
type Credentials struct {
	BaseURL string `json:"endpointURL"`
	APIKey  string `json:"endpointSecret"`
}

func (c *Client) getCreateURL() (string, error) {
	return url.JoinPath(c.BaseURL, "vpcendpoint")
}

func (c *Client) getStatusURL() (string, error) {
	return url.JoinPath(c.BaseURL, "vpcendpoint")
}

// NewConnectivityClient creates a client to configure connectivity components of MongoDBAtlas
func NewConnectivityClient(baseURL string, apiKey string) (*Client, error) {
	return &Client{
		BaseURL: baseURL,
		APIKey:  apiKey,
	}, nil
}

type getVPCEndpointBody struct {
	VpcEndpointIDs []string `json:"vpcEndpointIds"`
}

// VPCEndpointStatusResponse decodes a successful response from the VPC endpoint status endpoint
type VPCEndpointStatusResponse struct {
	VpcEndpoints []ResponseVPCEndpoint `json:"VpcEndpoints"`
}

// LambdaErrorResponse decodes a lambda response if it is an error
type LambdaErrorResponse struct {
	Error ErrorResponse `json:"Error"`
}

// ParseLambdaErrorResponse parses a response from the Lambda API as an error
func ParseLambdaErrorResponse(in []byte) (*LambdaErrorResponse, error) {
	// parse error
	responseError := LambdaErrorResponse{}
	err := json.Unmarshal(in, &responseError)
	if err != nil {
		return &LambdaErrorResponse{}, err
	}

	return &responseError, nil
}

// ErrorResponse is the error description part of a LambdaErrorResponse
type ErrorResponse struct {
	Code    string `json:"Code"`
	Message string `json:"Message"`
}

// VPCEndpointStatus is the return type of GetVPCEndpointStatus
type VPCEndpointStatus struct {
	State string
}

func (c *Client) requestVPCEndpointStatus(ctx context.Context, accountID string, vpcEndpointID string, region string) ([]byte, int, error) {
	statusURL, err := c.getStatusURL()
	if err != nil {
		return []byte{}, 0, err
	}

	body := getVPCEndpointBody{
		VpcEndpointIDs: []string{vpcEndpointID},
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return []byte{}, 0, err
	}

	bodyReader := bytes.NewReader(jsonBody)

	request, err := http.NewRequestWithContext(ctx, "GET", statusURL, bodyReader)
	if err != nil {
		return []byte{}, 0, err
	}

	request.Header.Set("X-API-KEY", c.APIKey)
	request.Header.Set("x-account-id", accountID)
	request.Header.Set("x-region", region)

	res, err := http.DefaultClient.Do(request)
	if err != nil {
		return []byte{}, 0, err
	}

	defer res.Body.Close() //nolint:errcheck // ignoring response body error

	resBody, err := io.ReadAll(res.Body)
	return resBody, res.StatusCode, err
}

// GetVPCEndpointStatus returns whether the VPC endpoint resource already exists
func (c *Client) GetVPCEndpointStatus(ctx context.Context, accountID string, vpcEndpointID string, region string) (VPCEndpointStatus, error) {
	resBody, statusCode, err := c.requestVPCEndpointStatus(ctx, accountID, vpcEndpointID, region)
	if err != nil {
		return VPCEndpointStatus{}, err
	}

	if statusCode != 200 {
		responseError, err := ParseLambdaErrorResponse(resBody)
		if err != nil {
			return VPCEndpointStatus{}, fmt.Errorf("unable to parse error with status code %d: %w", statusCode, err)
		}

		if responseError.Error.Code == errorCodeNotFound {
			return VPCEndpointStatus{}, fmt.Errorf("%w: %s", ErrNotFound, responseError.Error.Message)
		}
		return VPCEndpointStatus{}, fmt.Errorf("unexpected status code %d with error message %s", statusCode, responseError.Error.Message)
	}

	statusResponse := VPCEndpointStatusResponse{}
	err = json.Unmarshal(resBody, &statusResponse)
	if err != nil {
		return VPCEndpointStatus{}, fmt.Errorf("unable to parse status response: %w", err)
	}

	if len(statusResponse.VpcEndpoints) == 0 {
		return VPCEndpointStatus{}, fmt.Errorf("%w: empty list of vpcEndpoints", ErrNotFound)
	}

	return VPCEndpointStatus{
		State: statusResponse.VpcEndpoints[0].State,
	}, nil
}

// VPCEndpointResponse contains all information available about a VPC endpoint resource
type VPCEndpointResponse struct {
	VpcEndpoint ResponseVPCEndpoint `json:"VpcEndpoint"`
}

// ResponseVPCEndpoint is the VpcEndpoint section of a VPC endpoint response
type ResponseVPCEndpoint struct {
	VpcEndpointID string `json:"VpcEndpointId"`
	State         string `json:"State"`
}

type createVPCEndpointBody struct {
	VpcID            string   `json:"vpcId"`
	ServiceName      string   `json:"serviceName"`
	SubnetIDs        []string `json:"subnetIds"`
	SecurityGroupIDs []string `json:"securityGroupIds"`
	VpcEndpointType  string   `json:"vpcEndpointType"`
	IPAddressType    string   `json:"ipAddressType"`
}

// CreateVPCEndpointParams is the parameter struct for VPC endpoint creation
type CreateVPCEndpointParams struct {
	VpcID            string
	ServiceName      string
	SubnetIDs        []string
	SecurityGroupIDs []string
	VpcEndpointType  string
	IPAddressType    string
	AccountID        string
	Region           string
}

// CreateVPCEndpoint function creates a new VPC endpoint resource
func (c *Client) CreateVPCEndpoint(ctx context.Context, params CreateVPCEndpointParams) (VPCEndpointResponse, error) {
	createURL, err := c.getCreateURL()
	if err != nil {
		return VPCEndpointResponse{}, err
	}

	body := createVPCEndpointBody{
		VpcID:            params.VpcID,
		ServiceName:      params.ServiceName,
		SubnetIDs:        params.SubnetIDs,
		SecurityGroupIDs: params.SecurityGroupIDs,
		VpcEndpointType:  params.VpcEndpointType,
		IPAddressType:    params.IPAddressType,
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return VPCEndpointResponse{}, err
	}
	bodyReader := bytes.NewReader(jsonBody)

	request, err := http.NewRequestWithContext(ctx, "POST", createURL, bodyReader)
	if err != nil {
		return VPCEndpointResponse{}, err
	}

	request.Header.Set("X-API-KEY", c.APIKey)
	request.Header.Set("x-account-id", params.AccountID)
	request.Header.Set("x-region", params.Region)

	res, err := http.DefaultClient.Do(request)
	if err != nil {
		return VPCEndpointResponse{}, err
	}
	defer res.Body.Close() //nolint:errcheck // ignoring response body error

	resBody, err := io.ReadAll(res.Body)

	if err != nil {
		return VPCEndpointResponse{}, err
	}

	if res.StatusCode != 200 {
		responseError, err := ParseLambdaErrorResponse(resBody)
		if err != nil {
			return VPCEndpointResponse{}, fmt.Errorf("unable to parse error with status code %d: %w", res.StatusCode, err)
		}
		return VPCEndpointResponse{}, fmt.Errorf("unexpected status code %d with error message %s", res.StatusCode, responseError.Error.Message)
	}

	var vpcEndpoint VPCEndpointResponse
	err = json.Unmarshal(resBody, &vpcEndpoint)
	if err != nil {
		return VPCEndpointResponse{}, err
	}

	return vpcEndpoint, nil
}
