package output

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"

	jsoniter "github.com/json-iterator/go"
	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
	errorutil "github.com/projectdiscovery/utils/errors"
	"golang.org/x/exp/maps"
)

// Writer is an interface which writes output to somewhere for katana events.
type Writer interface {
	// Close closes the output writer interface
	Close() error
	// Write writes the event to file and/or screen.
	Write(*clients.Response) error
}

var decolorizerRegex = regexp.MustCompile(`\x1B\[[0-9;]*[a-zA-Z]`)

// StandardWriter is an standard output writer structure
type StandardWriter struct {
	json        bool
	aurora      aurora.Aurora
	outputFile  *fileWriter
	outputMutex *sync.Mutex

	options *clients.Options
}

// New returns a new output writer instance
func New(options *clients.Options) (Writer, error) {
	var outputFile *fileWriter
	if options.OutputFile != "" {
		output, err := newFileOutputWriter(options.OutputFile)
		if err != nil {
			return nil, errorutil.NewWithErr(err).Msgf("could not create output file")
		}
		outputFile = output
	}
	writer := &StandardWriter{
		json:        options.JSON,
		aurora:      aurora.NewAurora(!options.NoColor),
		outputFile:  outputFile,
		outputMutex: &sync.Mutex{},
		options:     options,
	}
	return writer, nil
}

// Write writes the event to file and/or screen.
func (w *StandardWriter) Write(event *clients.Response) error {
	var data []byte
	var err error

	if w.json {
		data, err = w.formatJSON(event)
	} else {
		data, err = w.formatStandard(event)
	}
	if err != nil {
		return errorutil.NewWithErr(err).Msgf("could not format output")
	}
	data = bytes.TrimSuffix(data, []byte("\n")) // remove last newline

	w.outputMutex.Lock()
	defer w.outputMutex.Unlock()
	_, _ = os.Stdout.Write(data)
	_, _ = os.Stdout.Write([]byte("\n"))
	if w.outputFile != nil {
		if !w.json {
			data = decolorizerRegex.ReplaceAll(data, []byte(""))
		}
		if writeErr := w.outputFile.Write(data); writeErr != nil {
			return errorutil.NewWithErr(err).Msgf("could not write to output")
		}
	}
	return nil
}

// Close closes the output writer
func (w *StandardWriter) Close() error {
	var err error
	if w.outputFile != nil {
		err = w.outputFile.Close()
	}
	return err
}

// formatJSON formats the output for json based formatting
func (w *StandardWriter) formatJSON(output *clients.Response) ([]byte, error) {
	return jsoniter.Marshal(output)
}

// formatStandard formats the output for standard client formatting
func (w *StandardWriter) formatStandard(output *clients.Response) ([]byte, error) {
	if output == nil {
		return nil, errorutil.New("empty certificate response")
	}

	if output.CertificateResponse == nil {
		return nil, errorutil.New("empty leaf certificate")
	}

	builder := &bytes.Buffer{}

	if !w.options.RespOnly {
		builder.WriteString(output.Host)
		builder.WriteString(":")
		builder.WriteString(output.Port)
		if (w.options.ScanAllIPs || len(w.options.IPVersion) > 0) && output.IP != "" {
			builder.WriteString(" (")
			builder.WriteString(output.IP)
			builder.WriteString(")")
		}
	}
	outputPrefix := builder.String()
	builder.Reset()

	cert := output.CertificateResponse

	var names []string
	if w.options.SAN {
		names = append(names, cert.SubjectAN...)
	}
	if w.options.CN {
		names = append(names, cert.SubjectCN)
	}
	uniqueNames := uniqueNormalizeCertNames(names)
	if len(uniqueNames) > 0 {
		for _, name := range uniqueNames {
			if w.options.RespOnly {
				builder.WriteString(name)
				builder.WriteString("\n")
			} else {
				builder.WriteString(outputPrefix)
				builder.WriteString(" [")
				builder.WriteString(w.aurora.Cyan(name).String())
				builder.WriteString("]\n")
			}
		}
	}

	if !w.options.SAN && !w.options.CN && !w.options.TlsCiphersEnum {
		builder.WriteString(outputPrefix)
	}
	if !output.ProbeStatus {
		builder.WriteString(" [")
		builder.WriteString(w.aurora.Red("failed").String())
		builder.WriteString("]")
	}
	if w.options.ProbeStatus && output.ProbeStatus {
		builder.WriteString(" [")
		builder.WriteString(w.aurora.Green("success").String())
		builder.WriteString("]")
	}
	if w.options.ServerName != nil {
		builder.WriteString(" [")
		builder.WriteString(w.aurora.Blue(output.ServerName).String())
		builder.WriteString("]")
	}
	if w.options.SO && len(cert.SubjectOrg) > 0 {
		builder.WriteString(" [")
		builder.WriteString(w.aurora.BrightYellow(strings.Join(cert.SubjectOrg, ",")).String())
		builder.WriteString("]")
	}
	if w.options.TLSVersion {
		builder.WriteString(" [")
		builder.WriteString(w.aurora.Blue(strings.ToUpper(output.Version)).String())
		builder.WriteString("]")
	}
	if w.options.Cipher {
		builder.WriteString(" [")
		builder.WriteString(w.aurora.Green(output.Cipher).String())
		builder.WriteString("]")
	}
	if w.options.Expired && cert.Expired {
		builder.WriteString(" [")
		builder.WriteString(w.aurora.Red("expired").String())
		builder.WriteString("]")
	}
	if w.options.SelfSigned && cert.SelfSigned {
		builder.WriteString(" [")
		builder.WriteString(w.aurora.Yellow("self-signed").String())
		builder.WriteString("]")
	}
	if w.options.MisMatched && cert.MisMatched {
		builder.WriteString(" [")
		builder.WriteString(w.aurora.Yellow("mismatched").String())
		builder.WriteString("]")
	}
	if w.options.Revoked && cert.Revoked {
		builder.WriteString(" [")
		builder.WriteString(w.aurora.Red("revoked").String())
		builder.WriteString("]")
	}
	if w.options.Untrusted && cert.Untrusted {
		builder.WriteString(" [")
		builder.WriteString(w.aurora.Yellow("untrusted").String())
		builder.WriteString("]")
	}
	if w.options.WildcardCertCheck && cert.WildCardCert {
		builder.WriteString(" [")
		builder.WriteString(w.aurora.Yellow("wildcard").String())
		builder.WriteString("]")
	}
	if w.options.Serial {
		builder.WriteString(" [")
		builder.WriteString(w.aurora.BrightCyan(cert.Serial).String())
		builder.WriteString("]")
	}
	if w.options.Hash != "" {
		hashOpts := strings.Split(w.options.Hash, ",")

		for _, hash := range hashOpts {
			var value string
			builder.WriteString(" [")
			switch hash {
			case "md5":
				value = cert.FingerprintHash.MD5
			case "sha1":
				value = cert.FingerprintHash.SHA1
			case "sha256":
				value = cert.FingerprintHash.SHA256
			}
			builder.WriteString(w.aurora.BrightMagenta(value).String())
			builder.WriteString("]")
		}
	}
	if w.options.Jarm && output.JarmHash != "" {
		builder.WriteString(" [")
		builder.WriteString(w.aurora.Magenta(output.JarmHash).String())
		builder.WriteString("]")
	}

	if w.options.Ja3 && output.Ja3Hash != "" {
		builder.WriteString(" [")
		builder.WriteString(w.aurora.Magenta(output.Ja3Hash).String())
		builder.WriteString("]")
	}

	if w.options.TlsCiphersEnum {
		for _, v := range output.TlsCiphers {
			ct := v.Ciphers.ColorCode(w.aurora)
			all := []string{}
			all = append(all, ct.Insecure...)
			all = append(all, ct.Weak...)
			all = append(all, ct.Secure...)
			all = append(all, ct.Unknown...)
			if len(all) > 0 {
				builder.WriteString(outputPrefix)
				builder.WriteString(fmt.Sprintf(" [%v] [%v]\n", w.aurora.Magenta(v.Version), strings.Join(all, ",")))
			}
		}
	} else if w.options.TlsVersionsEnum {
		builder.WriteString(" [")
		builder.WriteString(w.aurora.Magenta(strings.Join(output.VersionEnum, ",")).String())
		builder.WriteString("]")
	}

	outputdata := builder.Bytes()
	return outputdata, nil
}

// uniqueNormalizeCertNames removes *. wildcards from cert alternative
// names and uniques them returning a final list.
func uniqueNormalizeCertNames(names []string) []string {
	unique := make(map[string]struct{})
	for _, value := range names {
		replaced := strings.Replace(value, "*.", "", -1)
		unique[replaced] = struct{}{}
	}
	return maps.Keys(unique)
}
