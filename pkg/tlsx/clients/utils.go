package clients

import (
	"context"
	"crypto/x509"
	"net"

	errorutil "github.com/projectdiscovery/utils/errors"
	iputil "github.com/projectdiscovery/utils/ip"
)

func Convertx509toResponse(options *Options, hostname string, cert *x509.Certificate, showcert bool) *CertificateResponse {
	response := &CertificateResponse{
		SubjectAN:    cert.DNSNames,
		Emails:       cert.EmailAddresses,
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		Expired:      IsExpired(cert.NotAfter),
		SelfSigned:   IsSelfSigned(cert.AuthorityKeyId, cert.SubjectKeyId),
		MisMatched:   IsMisMatchedCert(hostname, append(cert.DNSNames, cert.Subject.CommonName)),
		Revoked:      IsTLSRevoked(options, cert),
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

// IntersectStringSlices returns intersection of two string slices
func IntersectStringSlices(s1 []string, s2 []string) []string {
	res := []string{}
	slicemap := map[string]struct{}{}
	var rangeslice []string

	// create a map of small slice and iterate over larger slice
	if len(s1) < len(s2) {
		for _, v := range s1 {
			slicemap[v] = struct{}{}
		}
		rangeslice = s2
	} else {
		for _, v := range s2 {
			slicemap[v] = struct{}{}
		}
		rangeslice = s1
	}
	for _, v := range rangeslice {
		if _, ok := slicemap[v]; ok {
			res = append(res, v)
		}
	}
	return res
}

// GetAddress return address string from user input
func GetConn(ctx context.Context, hostname, ip, port string, inputOpts *Options) (net.Conn, error) {
	var address string
	if iputil.IsIP(ip) && (inputOpts.ScanAllIPs || len(inputOpts.IPVersion) > 0) {
		address = net.JoinHostPort(ip, port)
	} else {
		address = net.JoinHostPort(hostname, port)
	}
	//validation
	if (hostname == "" && ip == "") || port == "" {
		return nil, errorutil.New("client requires valid address got port=%v,hostname=%v,ip=%v", port, hostname, ip)
	}
	rawConn, err := inputOpts.Fastdialer.Dial(ctx, "tcp", address)
	if err != nil {
		return nil, errorutil.New("could not dial address").Wrap(err)
	}
	if rawConn == nil {
		return nil, errorutil.New("could not connect to %s", address)
	}
	return rawConn, nil
}
