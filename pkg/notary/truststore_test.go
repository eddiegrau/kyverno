package notary

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"github.com/notaryproject/notation-go/verifier/truststore"
	"github.com/stretchr/testify/assert"
)

func TestSimpleTrustStore(t *testing.T) {
	cert := &x509.Certificate{Subject: pkix.Name{CommonName: "test"}}
	certs := []*x509.Certificate{cert}

	ts := NewTrustStore("kyverno", certs)

	// Test getting certificates with correct type and name
	result, err := ts.GetCertificates(context.Background(), truststore.TypeCA, "kyverno")
	assert.NoError(t, err)
	assert.Equal(t, certs, result)

	// Test getting certificates with wrong type
	_, err = ts.GetCertificates(context.Background(), truststore.TypeTSA, "kyverno")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid truststore type")

	// Test getting certificates with wrong name
	_, err = ts.GetCertificates(context.Background(), truststore.TypeCA, "other")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid truststore name")
}

func TestMultiTrustStore(t *testing.T) {
	caCert := &x509.Certificate{Subject: pkix.Name{CommonName: "ca"}}
	tsaCert := &x509.Certificate{Subject: pkix.Name{CommonName: "tsa"}}

	caCerts := []*x509.Certificate{caCert}
	tsaCerts := []*x509.Certificate{tsaCert}

	ts := NewMultiTrustStore()
	ts.AddStore(truststore.TypeCA, "kyverno", caCerts)
	ts.AddStore(truststore.TypeTSA, "kyverno", tsaCerts)

	// Test getting CA certificates
	result, err := ts.GetCertificates(context.Background(), truststore.TypeCA, "kyverno")
	assert.NoError(t, err)
	assert.Equal(t, caCerts, result)

	// Test getting TSA certificates
	result, err = ts.GetCertificates(context.Background(), truststore.TypeTSA, "kyverno")
	assert.NoError(t, err)
	assert.Equal(t, tsaCerts, result)

	// Test getting non-existent type
	_, err = ts.GetCertificates(context.Background(), truststore.TypeSigningAuthority, "kyverno")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "trust store type")

	// Test getting non-existent name
	_, err = ts.GetCertificates(context.Background(), truststore.TypeCA, "other")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestMultiTrustStoreEmpty(t *testing.T) {
	ts := NewMultiTrustStore()

	// Test getting from empty store
	_, err := ts.GetCertificates(context.Background(), truststore.TypeCA, "kyverno")
	assert.Error(t, err)
}
