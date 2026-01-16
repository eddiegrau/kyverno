package notary

import (
	"context"
	"crypto/x509"

	"github.com/notaryproject/notation-go/verifier/truststore"
	"github.com/pkg/errors"
)

type simpleTrustStore struct {
	name      string
	storeType truststore.Type
	certs     []*x509.Certificate
}

func NewTrustStore(name string, certs []*x509.Certificate) truststore.X509TrustStore {
	return &simpleTrustStore{
		name:      name,
		storeType: truststore.TypeCA,
		certs:     certs,
	}
}

func (ts *simpleTrustStore) GetCertificates(ctx context.Context, storeType truststore.Type, name string) ([]*x509.Certificate, error) {
	if storeType != ts.storeType {
		return nil, errors.Errorf("invalid truststore type")
	}

	if name != ts.name {
		return nil, errors.Errorf("invalid truststore name")
	}

	return ts.certs, nil
}

// multiTrustStore supports multiple trust store types (CA and TSA) for Notary verification
type multiTrustStore struct {
	// stores maps store type -> store name -> certificates
	stores map[truststore.Type]map[string][]*x509.Certificate
}

func NewMultiTrustStore() *multiTrustStore {
	return &multiTrustStore{
		stores: make(map[truststore.Type]map[string][]*x509.Certificate),
	}
}

// AddStore adds certificates to a named store of a specific type
func (ts *multiTrustStore) AddStore(storeType truststore.Type, name string, certs []*x509.Certificate) {
	if ts.stores[storeType] == nil {
		ts.stores[storeType] = make(map[string][]*x509.Certificate)
	}
	ts.stores[storeType][name] = certs
}

func (ts *multiTrustStore) GetCertificates(ctx context.Context, storeType truststore.Type, name string) ([]*x509.Certificate, error) {
	typeStores, ok := ts.stores[storeType]
	if !ok {
		return nil, errors.Errorf("trust store type %q not found", storeType)
	}

	certs, ok := typeStores[name]
	if !ok {
		return nil, errors.Errorf("trust store %q of type %q not found", name, storeType)
	}

	return certs, nil
}
