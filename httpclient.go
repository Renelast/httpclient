package httpclient

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/pkg/errors"
)

// HTTPClient embeds an http.Client
// The HTTPClients adds some convenience methods to set various aspects of
// an http.Client like Root CA's, Proxy or Client certificates
type HTTPClient struct {
	http.Client
}

// New returns a HTTPClient with some sensible defaults
func New(opts ...func(*HTTPClient) error) (*HTTPClient, error) {
	dialer := net.Dialer{
		Timeout: 30 * time.Second,
	}

	tlsConf := &tls.Config{
		InsecureSkipVerify: false,
	}

	transport := &http.Transport{
		Dial:                  dialer.Dial,
		TLSClientConfig:       tlsConf,
		TLSHandshakeTimeout:   5 * time.Second,
		IdleConnTimeout:       30 * time.Second,
		ResponseHeaderTimeout: 120 * time.Second,
	}

	c := http.Client{
		Transport: transport,
	}
	client := &HTTPClient{c}

	for _, opt := range opts {
		err := opt(client)
		if err != nil {
			return nil, err
		}
	}

	return client, nil
}

// Insecure set the InsecureSkipVerify option to true in the client
// this diabled verification of any server certificates
// This is an option and should be passed to the New() function
func Insecure() func(*HTTPClient) error {
	return func(h *HTTPClient) error {
		return h.Insecure()
	}
}

// ClientCert adds an client key and certificate to the client
// This is an option and should be passed to the New() function
func ClientCert(clientCert, clientKey string) func(*HTTPClient) error {
	return func(h *HTTPClient) error {
		return h.ClientCert(clientCert, clientKey)
	}
}

// RootCA Adds a root certificate to the client
// This certificate is used to verify certificates provided by the server
// This is an option and should be passed to the New() function
func RootCA(CACertFile string) func(*HTTPClient) error {
	return func(h *HTTPClient) error {
		return h.RootCA(CACertFile)
	}
}

// Proxy sets a proxy for the client
// This is an option and should be passed to the New() function
func Proxy(proxyURL string) func(*HTTPClient) error {
	return func(h *HTTPClient) error {
		return h.Proxy(proxyURL)
	}
}

func (h *HTTPClient) transport() (*http.Transport, error) {
	t, ok := h.Transport.(*http.Transport)
	if !ok {
		return nil, errors.New("could not get transport from client")
	}
	return t, nil
}

// Insecure set the InsecureSkipVerify option to true in the client
// this diabled verification of any server certificates
func (h *HTTPClient) Insecure() error {
	t, err := h.transport()
	if err != nil {
		return err
	}

	t.TLSClientConfig.InsecureSkipVerify = true
	h.Transport = t
	return nil
}

// ClientCert adds an client key and certificate to the client
func (h *HTTPClient) ClientCert(clientCert, clientKey string) error {
	cert, err := tls.LoadX509KeyPair(clientCert, clientKey)
	if err != nil {
		return fmt.Errorf("could not load client certificate or key: %v", err)
	}

	t, err := h.transport()
	if err != nil {
		return err
	}

	var certs []tls.Certificate
	if t.TLSClientConfig.Certificates == nil {
		certs = []tls.Certificate{}
	}
	certs = append(certs, cert)

	t.TLSClientConfig.Certificates = certs
	h.Transport = t

	return nil
}

// RootCA Adds a root certificate to the client
// This certificate is used to verify certificates provided by the server
func (h *HTTPClient) RootCA(CACertFile string) error {
	caBytes, err := ioutil.ReadFile(CACertFile)
	if err != nil {
		return fmt.Errorf("could not read CA certificate file: %v", err)
	}

	t, err := h.transport()
	if err != nil {
		return err
	}

	p := x509.NewCertPool()
	if t.TLSClientConfig.RootCAs != nil {
		p = t.TLSClientConfig.RootCAs
	}

	ok := p.AppendCertsFromPEM(caBytes)
	if !ok {
		return errors.New("could not add ca cert to certpool")
	}
	t.TLSClientConfig.RootCAs = p

	h.Transport = t
	return nil
}

// Proxy sets a proxy for the client
func (h *HTTPClient) Proxy(proxyURL string) error {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return fmt.Errorf("could not parse proxy url: %v", err)
	}
	t, err := h.transport()
	if err != nil {
		return err
	}

	t.Proxy = http.ProxyURL(u)
	h.Transport = t
	return nil
}

// GetClient returns the embedded http.Client
// This can be used to pass a configured client to a function requiring an http.Client
func (h *HTTPClient) GetClient() http.Client {
	return h.Client
}
