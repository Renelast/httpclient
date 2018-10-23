package httpclient

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"os"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Fatalf("expected new to return an httpclient; got error %v", err)
	}

	_, err = c.transport()
	if err != nil {
		t.Fatal(err)
	}
}

func TestTransport(t *testing.T) {
	cert, key, cleanup := CertAndKey(t)
	defer cleanup()

	c := &HTTPClient{}

	_, err := c.transport()
	if err == nil {
		t.Fatal("expected an error message; Got nil")
	}
	if err.Error() != "could not get transport from client" {
		t.Fatalf("got unexpected error message: %v", err)
	}

	err = c.Insecure()
	if err == nil {
		t.Fatal("expected an error message; Got nil")
	}
	if err.Error() != "could not get transport from client" {
		t.Fatalf("got unexpected error message: %v", err)
	}

	err = c.Proxy("proxy")
	if err == nil {
		t.Fatal("expected an error message; Got nil")
	}
	if err.Error() != "could not get transport from client" {
		t.Fatalf("got unexpected error message: %v", err)
	}

	err = c.RootCA(cert)
	if err == nil {
		t.Fatal("expected an error message; Got nil")
	}
	if err.Error() != "could not get transport from client" {
		t.Fatalf("got unexpected error message: %v", err)
	}

	err = c.ClientCert(cert, key)
	if err == nil {
		t.Fatal("expected an error message; Got nil")
	}
	if err.Error() != "could not get transport from client" {
		t.Fatalf("got unexpected error message: %v", err)
	}

}

func TestGetClient(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Fatalf("expected new to return an httpclient; got error %v", err)
	}
	var cl interface{}
	cl = c.GetClient()
	client, ok := cl.(http.Client)
	if !ok {
		t.Fatalf("expected GetClient() to return an http.Client; got %T", client)
	}
}

func TestInsecureOption(t *testing.T) {
	c, err := New(Insecure())
	if err != nil {
		t.Fatalf("expected new to return an httpclient; got error %v", err)
	}
	transport, err := c.transport()
	if err != nil {
		t.Fatal(err)
	}
	if transport.TLSClientConfig.InsecureSkipVerify != true {
		t.Fatalf("expected InsecureSkipVerify to be true; got %v", transport.TLSClientConfig.InsecureSkipVerify)
	}
}

func TestProxyOption(t *testing.T) {
	tt := []struct {
		Name       string
		Proxy      string
		ShouldFail bool
	}{
		{"ValidProxyURL", "http://my.proxy:3128", false},
		{"InValidProxyURL", ":proxy", true},
	}

	for _, test := range tt {
		t.Run(test.Name, func(t *testing.T) {
			c, err := New(Proxy(test.Proxy))
			if err != nil && test.ShouldFail == false {
				t.Fatalf("expected new to return an httpclient; got error %v", err)
			} else if err == nil && test.ShouldFail == true {
				t.Fatal("expected an error; got nil")
			}

			if test.ShouldFail == false {
				transport, err := c.transport()
				if err != nil {
					t.Fatal(err)
				}

				u, _ := transport.Proxy(nil)
				if u.String() != test.Proxy {
					t.Fatalf("expected Proxy url to be set to %s; got %s", test.Proxy, u.String())
				}
			}
		})
	}

}
func TestRootCAOption(t *testing.T) {
	cert, key, cleanup := CertAndKey(t)
	defer cleanup()

	t.Run("Empty parameter", func(t *testing.T) {
		_, err := New(RootCA(""))
		if err == nil {
			t.Fatal("expected an error; Got nil")
		}
	})

	t.Run("Valid cert", func(t *testing.T) {
		c, err := New(RootCA(cert))
		if err != nil {
			t.Fatalf("expected new to return an httpclient; got error %v", err)
		}

		transport, err := c.transport()
		if err != nil {
			t.Fatal(err)
		}

		if transport.TLSClientConfig.RootCAs == nil {
			t.Fatal("transport.TLSClientConfig.RootCAs was nil after adding a CA cert")
		}
		pool := transport.TLSClientConfig.RootCAs
		no := len(pool.Subjects())
		if no != 1 {
			t.Fatalf("expected certpool to contain 1 cert; got %d", no)
		}
	})

	t.Run("Extra valid cert", func(t *testing.T) {
		cert2, _, cleanup := CertAndKey(t)
		defer cleanup()

		c, err := New(RootCA(cert))
		if err != nil {
			t.Fatalf("expected new to return an httpclient; got error %v", err)
		}
		err = c.RootCA(cert2)

		if err != nil {
			t.Fatalf("error adding second root CA cert: %v", err)
		}
		transport, err := c.transport()
		if err != nil {
			t.Fatal(err)
		}

		if transport.TLSClientConfig.RootCAs == nil {
			t.Fatal("transport.TLSClientConfig.RootCAs was nil after adding a CA cert")
		}
		pool := transport.TLSClientConfig.RootCAs
		no := len(pool.Subjects())
		if no != 2 {
			t.Fatalf("expected certpool to contain 2 certs; got %d", no)
		}
	})

	t.Run("Invalid cert", func(t *testing.T) {
		_, err := New(RootCA(key))
		if err == nil {
			t.Fatal("expected an error adding an invalid ca cert")
		}
	})

}

func TestClientCertsOption(t *testing.T) {
	cert, key, cleanup := CertAndKey(t)
	defer cleanup()

	tt := []struct {
		Name string
		Key  string
		Cert string
	}{
		{"Empty Key", "", cert},
		{"Empty Cert", key, ""},
		{"Invalid Cert", key, key},
		{"Invalid Key", cert, cert},
	}

	for _, test := range tt {
		t.Run(test.Name, func(t *testing.T) {
			_, err := New(ClientCert(test.Cert, test.Key))
			if err == nil {
				t.Fatal("expected an error; Got nil")
			}
		})
	}

	c, err := New(ClientCert(cert, key))
	if err != nil {
		t.Fatalf("expected new to return an httpclient; got error %v", err)
	}

	transport, err := c.transport()
	if err != nil {
		t.Fatal(err)
	}

	if transport.TLSClientConfig.Certificates == nil {
		t.Fatal("transport.TLSClientConfig.Certificates was nil after adding a client cert and key")
	}
	no := len(transport.TLSClientConfig.Certificates)
	if no != 1 {
		t.Fatalf("expected certificates to contain 1 cert; got %d", no)
	}
}

func CertAndKey(t *testing.T) (string, string, func()) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		t.Fatalf("failed to generate serial number: %s", err)
	}

	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("could not generate a private key for testing: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{fmt.Sprintf("%s", serialNumber)},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(30 * time.Minute),
		IsCA:      true,
		KeyUsage:  x509.KeyUsageCertSign,
	}

	tmpCert, err := ioutil.TempFile("", "")
	if err != nil {
		t.Fatal("could not create temporary file for certificate")
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		log.Fatalf("Failed to create certificate for testing: %s", err)
	}
	if err := pem.Encode(tmpCert, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		t.Fatalf("failed to write data to cert.pem: %s", err)
	}
	if err := tmpCert.Close(); err != nil {
		t.Fatalf("error closing cert.pem: %s", err)
	}

	tmpKey, err := ioutil.TempFile("", "")
	if err != nil {
		t.Fatalf("could not create temporary file for key")
	}
	if err := pem.Encode(tmpKey, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		t.Fatalf("failed to write data to key.pem: %s", err)
	}
	if err := tmpKey.Close(); err != nil {
		t.Fatalf("error closing key.pem: %s", err)
	}

	return tmpCert.Name(), tmpKey.Name(), func() {
		os.Remove(tmpCert.Name())
		os.Remove(tmpKey.Name())
	}
}
