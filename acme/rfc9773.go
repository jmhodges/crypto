// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package acme

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// RenewalInfo holds an ACME Renewal Information (ARI) response, as defined in
// RFC 9773. It tells the client when the CA suggests renewing a previously
// issued certificate.
type RenewalInfo struct {
	// SuggestedWindow is the time window during which the CA recommends that
	// the client renew the certificate. The client should select a uniformly
	// random time within the window.
	SuggestedWindow RenewalWindow

	// ExplanationURL is an optional URL pointing to a page explaining why the
	// suggested window has its current value. It may be empty.
	ExplanationURL string

	// retryAfter is the parsed Retry-After response header.
	// retryAfterSet reports whether the header was present at all,
	// disambiguating an absent header from a zero duration.
	retryAfter    time.Duration
	retryAfterSet bool
}

// NextFetch reports how long the client should wait before fetching renewal
// information for the certificate again, as advised by the server via the
// Retry-After response header described in RFC 9773 Section 4.2. NextFetch
// describes only when to poll this endpoint again; it is not the time to
// renew the certificate, which is given by SuggestedWindow.
//
// The boolean is false if the server did not include a Retry-After header,
// in which case clients should fall back to fetching again at
// SuggestedWindow.Start.
func (r *RenewalInfo) NextFetch() (time.Duration, bool) {
	return r.retryAfter, r.retryAfterSet
}

// RenewalWindow is a time window suggested by the CA for certificate renewal,
// as defined in RFC 9773 Section 4.2.
type RenewalWindow struct {
	Start time.Time
	End   time.Time
}

// certID returns the ARI certificate identifier for the given certificate, as
// defined in RFC 9773 Section 4.1: the base64url-encoded Authority Key
// Identifier (AKI) value, a period, and the base64url-encoded Serial Number
// bytes.
//
// It returns an error if the certificate does not contain an Authority Key
// Identifier extension or if its serial number is missing.
func certID(cert *x509.Certificate) (string, error) {
	if cert == nil {
		return "", errors.New("acme: nil certificate")
	}
	if len(cert.AuthorityKeyId) == 0 {
		return "", errors.New("acme: certificate has no Authority Key Identifier extension")
	}
	if cert.SerialNumber == nil {
		return "", errors.New("acme: certificate has no serial number")
	}
	akid := base64.RawURLEncoding.EncodeToString(cert.AuthorityKeyId)
	serial := base64.RawURLEncoding.EncodeToString(cert.SerialNumber.Bytes())
	return akid + "." + serial, nil
}

// FetchRenewalInfo retrieves the ACME Renewal Information for the given
// certificate, as defined in RFC 9773.
//
// If the CA does not advertise a renewal information endpoint, FetchRenewalInfo
// returns ErrRenewalInfoNotSupported.
func (c *Client) FetchRenewalInfo(ctx context.Context, cert *x509.Certificate) (*RenewalInfo, error) {
	dir, err := c.Discover(ctx)
	if err != nil {
		return nil, err
	}
	if dir.RenewalInfoURL == "" {
		return nil, ErrRenewalInfoNotSupported
	}
	id, err := certID(cert)
	if err != nil {
		return nil, err
	}
	url := strings.TrimRight(dir.RenewalInfoURL, "/") + "/" + id
	res, err := c.get(ctx, url, wantStatus(http.StatusOK))
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	var v struct {
		SuggestedWindow struct {
			Start time.Time `json:"start"`
			End   time.Time `json:"end"`
		} `json:"suggestedWindow"`
		ExplanationURL string `json:"explanationURL"`
	}
	if err := json.NewDecoder(res.Body).Decode(&v); err != nil {
		return nil, fmt.Errorf("acme: invalid renewal info response: %v", err)
	}
	info := &RenewalInfo{
		SuggestedWindow: RenewalWindow{
			Start: v.SuggestedWindow.Start,
			End:   v.SuggestedWindow.End,
		},
		ExplanationURL: v.ExplanationURL,
	}
	if h := res.Header.Get("Retry-After"); h != "" {
		info.retryAfter = retryAfter(h)
		info.retryAfterSet = true
	}
	return info, nil
}
