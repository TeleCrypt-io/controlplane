// Package synapseadmin is a client for Synapse's admin API user_type mutations — the call
// cashier uses to unlock/relock accounts. Mirrors tc-verify.sh's Synapse half only (PUT
// user_type verified/null); rate-limit overrides are intentionally outside this client.
package synapseadmin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	homeserverURL string
	adminToken    string
	httpClient    *http.Client
}

// UserExists confirms an MXID is a local Synapse account before cashier lets it consume a seat.
func (c *Client) UserExists(ctx context.Context, mxid string) (bool, error) {
	endpoint := fmt.Sprintf("%s/_synapse/admin/v2/users/%s", c.homeserverURL, url.PathEscape(mxid))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+c.adminToken)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("synapse admin get user: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("synapse admin get user: unexpected status %d", resp.StatusCode)
	}
	return true, nil
}

func NewClient(homeserverURL, adminToken string) *Client {
	return &Client{
		homeserverURL: strings.TrimRight(homeserverURL, "/"),
		adminToken:    adminToken,
		httpClient:    &http.Client{Timeout: 15 * time.Second},
	}
}

func (c *Client) SetUserTypeVerified(ctx context.Context, mxid string) error {
	v := "verified"
	return c.setUserType(ctx, mxid, &v)
}

func (c *Client) ClearUserType(ctx context.Context, mxid string) error {
	return c.setUserType(ctx, mxid, nil)
}

func (c *Client) setUserType(ctx context.Context, mxid string, userType *string) error {
	var body any
	if userType == nil {
		body = map[string]any{"user_type": nil}
	} else {
		body = map[string]string{"user_type": *userType}
	}
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}

	endpoint := fmt.Sprintf("%s/_synapse/admin/v2/users/%s", c.homeserverURL, url.PathEscape(mxid))
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.adminToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("synapse admin set user_type: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("synapse admin set user_type: unexpected status %d", resp.StatusCode)
	}
	return nil
}
