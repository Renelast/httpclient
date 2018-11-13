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

type Option func(*http.Client) error

// New returns a HTTPClient with some sensible defaults
func New(opts ...Option) (*http.Client, error) {
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

	client := &http.Client{
		Transport: transport,
	}

	for _, opt := range opts {
		err := opt(client)
		if err != nil {
			return nil, err
		}
	}

	return client, nil
}

// Insecure set the InsecureSkipVerify Option to true in the client
// this diabled verification of any server certificates
// This is an Option and should be passed to the New() function
func Insecure() Option {
	return func(c *http.Client) error {
		return SetInsecure(c)
	}
}

// SetInsecure set the InsecureSkipVerify Option to true in the client
// this diabled verification of any server certificates
func SetInsecure(c *http.Client) error {
	t, err := transport(c)
	if err != nil {
		return err
	}
	t.TLSClientConfig.InsecureSkipVerify = true
	c.Transport = t
	return nil
}

// ClientCert adds an client key and certificate to the client
// This is an Option and should be passed to the New() function
func ClientCert(clientCert, clientKey string) Option {
	return func(c *http.Client) error {
		return WithClientCert(c, clientCert, clientKey)
	}
}

// ClientCert adds an client key and certificate to the client
func WithClientCert(c *http.Client, clientCert, clientKey string) error {
	cert, err := tls.LoadX509KeyPair(clientCert, clientKey)
	if err != nil {
		return fmt.Errorf("could not load client certificate or key: %v", err)
	}

	t, err := transport(c)
	if err != nil {
		return err
	}

	var certs []tls.Certificate
	if t.TLSClientConfig.Certificates == nil {
		certs = []tls.Certificate{}
	}
	certs = append(certs, cert)

	t.TLSClientConfig.Certificates = certs
	c.Transport = t

	return nil
}

// RootCA Adds a root certificate to the client
// This certificate is used to verify certificates provided by the server
// This is an Option and should be passed to the New() function
func RootCA(CACertFile string) Option {
	return func(c *http.Client) error {
		return WithRootCA(c, CACertFile)
	}
}

// RootCA Adds a root certificate to the client
// This certificate is used to verify certificates provided by the server
func WithRootCA(c *http.Client, CACertFile string) error {
	caBytes, err := ioutil.ReadFile(CACertFile)
	if err != nil {
		return fmt.Errorf("could not read CA certificate file: %v", err)
	}

	t, err := transport(c)
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

	c.Transport = t
	return nil
}

// Proxy sets a proxy for the client
// This is an Option and should be passed to the New() function
func Proxy(proxyURL string) Option {
	return func(c *http.Client) error {
		return WithProxy(c, proxyURL)
	}
}

// Proxy sets a proxy for the client
func WithProxy(c *http.Client, proxyURL string) error {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return fmt.Errorf("could not parse proxy url: %v", err)
	}
	t, err := transport(c)
	if err != nil {
		return err
	}

	t.Proxy = http.ProxyURL(u)
	c.Transport = t
	return nil
}

func transport(c *http.Client) (*http.Transport, error) {
	t, ok := c.Transport.(*http.Transport)
	if !ok {
		return nil, errors.New("could not get transport from client")
	}
	return t, nil
}
