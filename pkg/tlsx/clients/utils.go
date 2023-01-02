package clients

import (
	"crypto/x509"
)

func Convertx509toResponse(hostname string, cert *x509.Certificate, showcert bool) *CertificateResponse {
	response := &CertificateResponse{
		SubjectAN:    cert.DNSNames,
		Emails:       cert.EmailAddresses,
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		Expired:      IsExpired(cert.NotAfter),
		SelfSigned:   IsSelfSigned(cert.AuthorityKeyId, cert.SubjectKeyId),
		MisMatched:   IsMisMatchedCert(hostname, append(cert.DNSNames, cert.Subject.CommonName)),
		Revoked:      IsTLSRevoked(cert),
		WildCardCert: IsWildCardCert(append(cert.DNSNames, cert.Subject.CommonName)),
		IssuerCN:     cert.Issuer.CommonName,
		IssuerOrg:    cert.Issuer.Organization,
		SubjectCN:    cert.Subject.CommonName,
		SubjectOrg:   cert.Subject.Organization,
		FingerprintHash: CertificateResponseFingerprintHash{
			MD5:    MD5Fingerprint(cert.Raw),
			SHA1:   SHA1Fingerprint(cert.Raw),
			SHA256: SHA256Fingerprint(cert.Raw),
		},
	}
	response.IssuerDN = ParseASN1DNSequenceWithZpkixOrDefault(cert.RawIssuer, cert.Issuer.String())
	response.SubjectDN = ParseASN1DNSequenceWithZpkixOrDefault(cert.RawSubject, cert.Subject.String())
	if showcert {
		response.Certificate = PemEncode(cert.Raw)
	}
	return response
}
