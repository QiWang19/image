package signature

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"

	"github.com/containers/image/v5/signature/internal"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

type pkiTrustRoot struct {
	caRootsCertificates         *x509.CertPool
	caIntermediatesCertificates *x509.CertPool
	subjectEmail                string
	subjectHostname             string
}

func (p *pkiTrustRoot) validate() error {
	if p.subjectEmail == "" && p.subjectHostname == "" {
		return errors.New("Internal inconsistency: PKI use set up without subject email or subject hostname")
	}
	return nil
}

func verifyPKI(pkiTrustRoot *pkiTrustRoot, untrustedCertificateBytes []byte, untrustedIntermediateChainBytes []byte) (crypto.PublicKey, error) {

	untrustedLeafCerts, err := cryptoutils.UnmarshalCertificatesFromPEM(untrustedCertificateBytes)
	if err != nil {
		return nil, internal.NewInvalidSignatureError(fmt.Sprintf("parsing leaf certificate: %v", err))
	}
	switch len(untrustedLeafCerts) {
	case 0:
		return nil, internal.NewInvalidSignatureError("no certificate found in signature certificate data")
	case 1:
		break // OK
	default:
		return nil, internal.NewInvalidSignatureError("unexpected multiple certificates present in signature certificate data")
	}
	untrustedCertificate := untrustedLeafCerts[0]

	if pkiTrustRoot.subjectEmail != "" {
		if !slices.Contains(untrustedCertificate.EmailAddresses, pkiTrustRoot.subjectEmail) {
			return nil, internal.NewInvalidSignatureError(fmt.Sprintf("Required email %q not found (got %q)",
				pkiTrustRoot.subjectEmail,
				untrustedCertificate.EmailAddresses))
		}
	}

	if pkiTrustRoot.subjectHostname != "" {
		if err = untrustedCertificate.VerifyHostname(pkiTrustRoot.subjectHostname); err != nil {
			return nil, internal.NewInvalidSignatureError(fmt.Sprintf("Unexpected subject hostname: %v", err))
		}
	}

	untrustedIntermediatePool := x509.NewCertPool()
	if pkiTrustRoot.caIntermediatesCertificates != nil {
		untrustedIntermediatePool = pkiTrustRoot.caIntermediatesCertificates
	}
	if len(untrustedIntermediateChainBytes) > 0 {
		untrustedIntermediateChain, err := cryptoutils.UnmarshalCertificatesFromPEM(untrustedIntermediateChainBytes)
		if err != nil {
			return nil, internal.NewInvalidSignatureError(fmt.Sprintf("loading certificate chain: %v", err))
		}
		if len(untrustedIntermediateChain) > 1 {
			for _, untrustedIntermediateCert := range untrustedIntermediateChain {
				untrustedIntermediatePool.AddCert(untrustedIntermediateCert)
			}
		}
	}

	if _, err := untrustedCertificate.Verify(x509.VerifyOptions{
		Intermediates: untrustedIntermediatePool,
		Roots:         pkiTrustRoot.caRootsCertificates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}); err != nil {
		return nil, internal.NewInvalidSignatureError(fmt.Sprintf("veryfing leaf certificate failed: %v", err))
	}

	return untrustedCertificate.PublicKey, nil
}