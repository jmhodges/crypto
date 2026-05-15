// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package acme

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRFC9773_certID(t *testing.T) {
	cert := &x509.Certificate{
		AuthorityKeyId: []byte{0x69, 0x88, 0x5b, 0x6b, 0x87, 0x46, 0x40, 0x41, 0xe1, 0xb3,
			0x7b, 0x84, 0x7b, 0xa0, 0xae, 0x2c, 0xde, 0x01, 0xc8, 0xd4},
		SerialNumber: big.NewInt(0x87654321),
	}
	got, err := certID(cert)
	if err != nil {
		t.Fatalf("certID: %v", err)
	}
	wantAKI := base64.RawURLEncoding.EncodeToString(cert.AuthorityKeyId)
	wantSerial := base64.RawURLEncoding.EncodeToString(cert.SerialNumber.Bytes())
	want := wantAKI + "." + wantSerial
	if got != want {
		t.Errorf("certID = %q; want %q", got, want)
	}
	// Sanity: the components must contain no '=' padding and a '.' separator.
	if strings.ContainsRune(got, '=') {
		t.Errorf("certID %q contains base64 padding", got)
	}
	if strings.Count(got, ".") != 1 {
		t.Errorf("certID %q must contain exactly one '.'", got)
	}
}

func TestRFC9773_certID_Errors(t *testing.T) {
	cases := []struct {
		name string
		cert *x509.Certificate
	}{
		{"nil cert", nil},
		{"missing AKI", &x509.Certificate{SerialNumber: big.NewInt(1)}},
		{"missing serial", &x509.Certificate{AuthorityKeyId: []byte{1, 2, 3}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := certID(tc.cert); err == nil {
				t.Errorf("certID returned nil error")
			}
		})
	}
}

func TestRFC9773_Discover_RenewalInfo(t *testing.T) {
	const renewal = "https://example.com/acme/renewal-info"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
			"newNonce": "https://example.com/acme/new-nonce",
			"newAccount": "https://example.com/acme/new-acct",
			"newOrder": "https://example.com/acme/new-order",
			"revokeCert": "https://example.com/acme/revoke-cert",
			"keyChange": "https://example.com/acme/key-change",
			"renewalInfo": %q
		}`, renewal)
	}))
	defer ts.Close()
	c := &Client{DirectoryURL: ts.URL}
	dir, err := c.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if dir.RenewalInfoURL != renewal {
		t.Errorf("dir.RenewalInfoURL = %q; want %q", dir.RenewalInfoURL, renewal)
	}
}

func TestRFC9773_FetchRenewalInfo_NotSupported(t *testing.T) {
	s := newACMEServer()
	s.start()
	defer s.close()

	cl := &Client{Key: testKeyEC, DirectoryURL: s.url("/")}
	cert := &x509.Certificate{
		AuthorityKeyId: []byte{1, 2, 3, 4},
		SerialNumber:   big.NewInt(42),
	}
	_, err := cl.FetchRenewalInfo(context.Background(), cert)
	if !errors.Is(err, ErrRenewalInfoNotSupported) {
		t.Errorf("FetchRenewalInfo error = %v; want ErrRenewalInfoNotSupported", err)
	}
}

func TestRFC9773_FetchRenewalInfo(t *testing.T) {
	cert := &x509.Certificate{
		AuthorityKeyId: []byte{0x69, 0x88, 0x5b, 0x6b, 0x87, 0x46, 0x40, 0x41, 0xe1, 0xb3,
			0x7b, 0x84, 0x7b, 0xa0, 0xae, 0x2c, 0xde, 0x01, 0xc8, 0xd4},
		SerialNumber: big.NewInt(0x87654321),
	}
	wantID, err := certID(cert)
	if err != nil {
		t.Fatal(err)
	}

	start := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	end := time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)

	mux := http.NewServeMux()
	var directoryURL string
	mux.HandleFunc("/directory", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
			"newNonce": %q,
			"newAccount": %q,
			"newOrder": %q,
			"revokeCert": %q,
			"keyChange": %q,
			"renewalInfo": %q
		}`,
			directoryURL+"/new-nonce",
			directoryURL+"/new-account",
			directoryURL+"/new-order",
			directoryURL+"/revoke-cert",
			directoryURL+"/key-change",
			directoryURL+"/renewal-info",
		)
	})
	mux.HandleFunc("/renewal-info/", func(w http.ResponseWriter, r *http.Request) {
		gotID := strings.TrimPrefix(r.URL.Path, "/renewal-info/")
		if gotID != wantID {
			t.Errorf("server got certID %q; want %q", gotID, wantID)
		}
		if r.Method != "GET" {
			t.Errorf("server got method %q; want GET", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", "21600")
		fmt.Fprintf(w, `{
			"suggestedWindow": {"start": %q, "end": %q},
			"explanationURL": "https://example.com/why"
		}`, start.Format(time.RFC3339), end.Format(time.RFC3339))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()
	directoryURL = ts.URL

	cl := &Client{Key: testKeyEC, DirectoryURL: ts.URL + "/directory"}
	info, err := cl.FetchRenewalInfo(context.Background(), cert)
	if err != nil {
		t.Fatalf("FetchRenewalInfo: %v", err)
	}
	if !info.SuggestedWindow.Start.Equal(start) {
		t.Errorf("Start = %v; want %v", info.SuggestedWindow.Start, start)
	}
	if !info.SuggestedWindow.End.Equal(end) {
		t.Errorf("End = %v; want %v", info.SuggestedWindow.End, end)
	}
	if info.ExplanationURL != "https://example.com/why" {
		t.Errorf("ExplanationURL = %q; want %q", info.ExplanationURL, "https://example.com/why")
	}
	d, ok := info.NextFetch()
	if !ok {
		t.Errorf("info.NextFetch ok = false; want true")
	}
	if d != 6*time.Hour {
		t.Errorf("info.NextFetch = %v; want %v", d, 6*time.Hour)
	}
}

func TestRFC9773_FetchRenewalInfo_NoRetryAfter(t *testing.T) {
	cert := &x509.Certificate{
		AuthorityKeyId: []byte{1, 2, 3, 4},
		SerialNumber:   big.NewInt(42),
	}

	mux := http.NewServeMux()
	var directoryURL string
	mux.HandleFunc("/directory", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
			"newNonce": %q,
			"newAccount": %q,
			"newOrder": %q,
			"revokeCert": %q,
			"keyChange": %q,
			"renewalInfo": %q
		}`,
			directoryURL+"/new-nonce",
			directoryURL+"/new-account",
			directoryURL+"/new-order",
			directoryURL+"/revoke-cert",
			directoryURL+"/key-change",
			directoryURL+"/renewal-info",
		)
	})
	mux.HandleFunc("/renewal-info/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"suggestedWindow": {"start": %q, "end": %q}}`,
			time.Now().Format(time.RFC3339),
			time.Now().Add(time.Hour).Format(time.RFC3339))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()
	directoryURL = ts.URL

	cl := &Client{Key: testKeyEC, DirectoryURL: ts.URL + "/directory"}
	info, err := cl.FetchRenewalInfo(context.Background(), cert)
	if err != nil {
		t.Fatalf("FetchRenewalInfo: %v", err)
	}
	if _, ok := info.NextFetch(); ok {
		t.Errorf("info.NextFetch ok = true; want false (Retry-After absent)")
	}
}

func TestRFC9773_AuthorizeOrder_Replaces(t *testing.T) {
	cert := &x509.Certificate{
		AuthorityKeyId: []byte{0x69, 0x88, 0x5b, 0x6b, 0x87, 0x46, 0x40, 0x41, 0xe1, 0xb3,
			0x7b, 0x84, 0x7b, 0xa0, 0xae, 0x2c, 0xde, 0x01, 0xc8, 0xd4},
		SerialNumber: big.NewInt(0x87654321),
	}
	wantReplaces, err := certID(cert)
	if err != nil {
		t.Fatal(err)
	}

	s := newACMEServer()
	s.handle("/acme/new-account", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", s.url("/accounts/1"))
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "valid"}`))
	})
	s.handle("/acme/new-order", func(w http.ResponseWriter, r *http.Request) {
		body, _ := readBodyJWSPayload(r)
		if !bytes.Contains(body, []byte(`"replaces":"`+wantReplaces+`"`)) {
			t.Errorf("new-order request body missing replaces=%q; got %s", wantReplaces, body)
		}
		w.Header().Set("Location", s.url("/orders/1"))
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{
			"status": "pending",
			"identifiers": [{"type":"dns", "value":"example.org"}],
			"authorizations": [%q],
			"replaces": %q
		}`, s.url("/authz/1"), wantReplaces)
	})
	s.start()
	defer s.close()

	cl := &Client{Key: testKeyEC, DirectoryURL: s.url("/")}
	o, err := cl.AuthorizeOrder(context.Background(), DomainIDs("example.org"),
		WithOrderReplaces(cert),
	)
	if err != nil {
		t.Fatalf("AuthorizeOrder: %v", err)
	}
	if o.Replaces != wantReplaces {
		t.Errorf("o.Replaces = %q; want %q", o.Replaces, wantReplaces)
	}
}

func TestRFC9773_AuthorizeOrder_AlreadyReplaced(t *testing.T) {
	s := newACMEServer()
	s.handle("/acme/new-account", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", s.url("/accounts/1"))
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "valid"}`))
	})
	s.handle("/acme/new-order", func(w http.ResponseWriter, r *http.Request) {
		s.error(w, &wireError{
			Status: http.StatusConflict,
			Type:   "urn:ietf:params:acme:error:alreadyReplaced",
			Detail: "certificate has already been replaced",
		})
	})
	s.start()
	defer s.close()

	cert := &x509.Certificate{
		AuthorityKeyId: []byte{1, 2, 3, 4},
		SerialNumber:   big.NewInt(42),
	}
	cl := &Client{Key: testKeyEC, DirectoryURL: s.url("/")}
	_, err := cl.AuthorizeOrder(context.Background(), DomainIDs("example.org"),
		WithOrderReplaces(cert),
	)
	if !errors.Is(err, ErrAlreadyReplaced) {
		t.Errorf("AuthorizeOrder error = %v; want ErrAlreadyReplaced", err)
	}
}

// readBodyJWSPayload parses the JWS request body and returns the decoded payload bytes.
func readBodyJWSPayload(r *http.Request) ([]byte, error) {
	var jws struct {
		Payload string `json:"payload"`
	}
	if err := decodeJSONBody(r, &jws); err != nil {
		return nil, err
	}
	return base64.RawURLEncoding.DecodeString(jws.Payload)
}

func decodeJSONBody(r *http.Request, v interface{}) error {
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	return dec.Decode(v)
}
