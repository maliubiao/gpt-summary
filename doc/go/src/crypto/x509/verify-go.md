Response:
The user wants to understand the functionality of the provided Go code snippet, which is part of the `crypto/x509` package in Go, specifically the `verify.go` file.

Here's a breakdown of the thought process to answer the request:

1. **Identify the core purpose:** The file name `verify.go` strongly suggests that the primary function of this code is related to verifying X.509 certificates.

2. **Analyze the top-level declarations:**
    * **Constants:**  `InvalidReason` enum and its values clearly define various reasons why a certificate might be invalid. This points towards error handling during verification.
    * **Types:** `CertificateInvalidError`, `HostnameError`, `UnknownAuthorityError`, and `SystemRootsError` are all specific error types related to certificate verification failures. `VerifyOptions` is a struct that holds parameters for the verification process. This structure helps in customizing the verification process.
    * **Functions:**  The provided snippet defines several functions. Focus on those that seem most central to verification: `isValid`, `Verify`, `buildChains`, and the various `match...Constraint` functions.

3. **Infer functionality from error types:**  The error types provide clues about the verification steps. For instance:
    * `HostnameError` suggests hostname validation.
    * `UnknownAuthorityError` implies checking the issuer of the certificate.
    * `CertificateInvalidError` with various `InvalidReason` values outlines different types of validation failures (expiration, key usage, name constraints, etc.).

4. **Examine the `VerifyOptions` struct:**  The fields in this struct reveal the customizable aspects of the verification process:
    * `DNSName`:  Verification against a specific hostname.
    * `Intermediates`, `Roots`: Handling certificate chains.
    * `CurrentTime`:  Validity period checks.
    * `KeyUsages`: Allowed key usages.
    * `MaxConstraintComparisions`: Limits for name constraint checks.
    * `CertificatePolicies`: Policy validation.

5. **Analyze key functions:**
    * **`isValid`:**  This function seems to perform basic validity checks on a certificate, such as expiration and name constraints.
    * **`Verify`:**  This appears to be the main entry point for certificate verification. It takes `VerifyOptions` and attempts to build and validate a chain of certificates. The logic for using system verifiers on some platforms is also present.
    * **`buildChains`:** This function likely handles the process of building possible certificate chains from the given certificate to a trusted root.
    * **`match...Constraint` functions:** These functions seem responsible for comparing names (email, DNS, URI, IP) against name constraints specified in certificates.

6. **Identify supporting functions:** Functions like `parseRFC2821Mailbox`, `domainToReverseLabels`, and `appendToFreshChain` support the core verification logic by handling specific data formats or operations.

7. **Synthesize the functionality:** Based on the analysis, the primary function of this code is to implement X.509 certificate path validation. This involves:
    * Building certificate chains.
    * Checking certificate validity periods.
    * Verifying signatures in the chain.
    * Enforcing key usage and extended key usage restrictions.
    * Validating name constraints.
    * Handling different types of errors encountered during verification.
    * Potentially using platform-specific verification mechanisms.

8. **Formulate the answer:** Structure the answer by listing the identified functionalities, providing a concise summary, and highlighting key aspects like chain building, validity checks, and name constraint validation.

This methodical approach helps to understand the complex logic within the code snippet and provide a comprehensive and accurate answer to the user's request.
这段 Go 语言代码是 `crypto/x509` 包中 `verify.go` 文件的一部分，其核心功能是 **实现 X.509 证书的路径验证（Path Validation）过程**。

**主要功能归纳如下：**

1. **定义了证书验证过程中可能出现的各种错误类型：**
   - `InvalidReason` 枚举了证书无效的各种原因，例如未授权签名、过期、名称约束不符、路径长度限制等。
   - `CertificateInvalidError` 结构体用于表示由于上述原因导致的证书无效错误。
   - `HostnameError` 结构体用于表示主机名与证书中的授权名称不匹配的错误。
   - `UnknownAuthorityError` 结构体用于表示证书的签发者未知（不在信任列表中）的错误。
   - `SystemRootsError` 结构体用于表示加载系统根证书失败的错误。

2. **定义了证书验证的选项参数：**
   - `VerifyOptions` 结构体封装了证书验证过程中的各种配置选项，例如要验证的 DNS 名称、中间证书池、根证书池、当前时间、可接受的密钥用途、最大约束比较次数、可接受的证书策略等。

3. **实现了证书基本属性的验证：**
   - `isValid` 函数用于检查单个证书的基本有效性，例如：
     - 是否有未处理的关键扩展。
     - 颁发者和主题是否匹配（在链式验证中）。
     - 证书的有效期是否在当前时间范围内。
     - 根据证书类型（中间或根证书）检查 `BasicConstraints` 扩展。

4. **实现了名称约束（Name Constraints）的检查：**
   - `checkNameConstraints` 函数用于检查证书是否允许子证书声明给定的名称（例如域名、邮箱、URI、IP 地址）。
   - `matchEmailConstraint`, `matchDomainConstraint`, `matchURIConstraint`, `matchIPConstraint` 等函数用于具体执行各种类型名称与约束的匹配。
   - 这些函数会解析不同类型的名称（例如邮箱地址），并将其与证书中定义的允许和排除的名称约束进行比较。

5. **实现了证书链的构建和验证：**
   - `Verify` 函数是主要的验证入口点，它会尝试构建从目标证书到可信根证书的有效证书链。
   - `buildChains` 函数递归地搜索可能的父证书，并检查签名是否有效，以及父证书是否满足 `isValid` 的要求。

6. **实现了主机名验证：**
   - `HostnameError` 及其相关逻辑用于验证证书是否对特定的主机名有效。这部分代码在其他地方，但 `verify.go` 中定义了相关的错误类型。

7. **支持扩展密钥用途（Extended Key Usage）的验证：**
   - `Verify` 函数会检查构建的证书链是否满足 `VerifyOptions` 中指定的 `KeyUsages`。

**代码示例（基于推理）：**

假设我们要验证一个服务器证书 `leafCert`，并指定需要验证的主机名为 `example.com`。我们有一个可信的根证书 `rootCert` 和一个中间证书 `intermediateCert`。

```go
package main

import (
	"crypto/x509"
	"fmt"
	"time"
)

func main() {
	// 假设 leafCert, intermediateCert, rootCert 已经通过某种方式加载
	leafCert, err := x509.ParseCertificate(leafCertBytes)
	if err != nil {
		fmt.Println("解析叶子证书失败:", err)
		return
	}
	intermediateCert, err := x509.ParseCertificate(intermediateCertBytes)
	if err != nil {
		fmt.Println("解析中间证书失败:", err)
		return
	}
	rootCert, err := x509.ParseCertificate(rootCertBytes)
	if err != nil {
		fmt.Println("解析根证书失败:", err)
		return
	}

	// 创建证书池
	roots := x509.NewCertPool()
	roots.AddCert(rootCert)

	intermediates := x509.NewCertPool()
	intermediates.AddCert(intermediateCert)

	// 设置验证选项
	opts := x509.VerifyOptions{
		DNSName:       "example.com",
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   time.Now(), // 使用当前时间
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	// 进行验证
	chains, err := leafCert.Verify(opts)
	if err != nil {
		fmt.Println("证书验证失败:", err)
		return
	}

	fmt.Println("证书验证成功，找到以下证书链:")
	for _, chain := range chains {
		fmt.Println("  证书链:")
		for _, cert := range chain {
			fmt.Printf("    主体: %s, 颁发者: %s\n", cert.Subject.CommonName, cert.Issuer.CommonName)
		}
	}
}
```

**假设的输入与输出：**

**输入：**

- `leafCertBytes`:  一个服务器证书的字节数组，其主题包含 `example.com`。
- `intermediateCertBytes`:  一个中间 CA 证书的字节数组，其颁发者与 `rootCert` 的主题相同，主题与 `leafCert` 的颁发者相同。
- `rootCertBytes`:  一个根 CA 证书的字节数组。

**输出（如果验证成功）：**

```
证书验证成功，找到以下证书链:
  证书链:
    主体: example.com, 颁发者: intermediate CA
    主体: intermediate CA, 颁发者: Root CA
    主体: Root CA, 颁发者: Root CA
```

**命令行参数处理：**

这段代码本身并没有直接处理命令行参数。证书的加载和 `VerifyOptions` 的配置通常是在程序代码中完成的。如果涉及到命令行参数，那通常是在调用这个代码的外部程序中处理的，例如通过 `flag` 包来解析用户提供的证书文件路径或主机名等信息。

**功能归纳 (第 1 部分)：**

这段 `verify.go` 代码的主要功能是 **定义了 X.509 证书验证过程中的错误类型和验证选项，并实现了证书的基本属性验证和名称约束检查的逻辑，为构建和验证证书链奠定了基础。**  它定义了在验证过程中可能出现的各种情况和如何处理这些情况，是 Go 语言 `crypto/x509` 包中证书路径验证的核心组成部分。

### 提示词
```
这是路径为go/src/crypto/x509/verify.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"bytes"
	"crypto"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"iter"
	"maps"
	"net"
	"net/url"
	"reflect"
	"runtime"
	"strings"
	"time"
	"unicode/utf8"
)

type InvalidReason int

const (
	// NotAuthorizedToSign results when a certificate is signed by another
	// which isn't marked as a CA certificate.
	NotAuthorizedToSign InvalidReason = iota
	// Expired results when a certificate has expired, based on the time
	// given in the VerifyOptions.
	Expired
	// CANotAuthorizedForThisName results when an intermediate or root
	// certificate has a name constraint which doesn't permit a DNS or
	// other name (including IP address) in the leaf certificate.
	CANotAuthorizedForThisName
	// TooManyIntermediates results when a path length constraint is
	// violated.
	TooManyIntermediates
	// IncompatibleUsage results when the certificate's key usage indicates
	// that it may only be used for a different purpose.
	IncompatibleUsage
	// NameMismatch results when the subject name of a parent certificate
	// does not match the issuer name in the child.
	NameMismatch
	// NameConstraintsWithoutSANs is a legacy error and is no longer returned.
	NameConstraintsWithoutSANs
	// UnconstrainedName results when a CA certificate contains permitted
	// name constraints, but leaf certificate contains a name of an
	// unsupported or unconstrained type.
	UnconstrainedName
	// TooManyConstraints results when the number of comparison operations
	// needed to check a certificate exceeds the limit set by
	// VerifyOptions.MaxConstraintComparisions. This limit exists to
	// prevent pathological certificates can consuming excessive amounts of
	// CPU time to verify.
	TooManyConstraints
	// CANotAuthorizedForExtKeyUsage results when an intermediate or root
	// certificate does not permit a requested extended key usage.
	CANotAuthorizedForExtKeyUsage
	// NoValidChains results when there are no valid chains to return.
	NoValidChains
)

// CertificateInvalidError results when an odd error occurs. Users of this
// library probably want to handle all these errors uniformly.
type CertificateInvalidError struct {
	Cert   *Certificate
	Reason InvalidReason
	Detail string
}

func (e CertificateInvalidError) Error() string {
	switch e.Reason {
	case NotAuthorizedToSign:
		return "x509: certificate is not authorized to sign other certificates"
	case Expired:
		return "x509: certificate has expired or is not yet valid: " + e.Detail
	case CANotAuthorizedForThisName:
		return "x509: a root or intermediate certificate is not authorized to sign for this name: " + e.Detail
	case CANotAuthorizedForExtKeyUsage:
		return "x509: a root or intermediate certificate is not authorized for an extended key usage: " + e.Detail
	case TooManyIntermediates:
		return "x509: too many intermediates for path length constraint"
	case IncompatibleUsage:
		return "x509: certificate specifies an incompatible key usage"
	case NameMismatch:
		return "x509: issuer name does not match subject from issuing certificate"
	case NameConstraintsWithoutSANs:
		return "x509: issuer has name constraints but leaf doesn't have a SAN extension"
	case UnconstrainedName:
		return "x509: issuer has name constraints but leaf contains unknown or unconstrained name: " + e.Detail
	case NoValidChains:
		s := "x509: no valid chains built"
		if e.Detail != "" {
			s = fmt.Sprintf("%s: %s", s, e.Detail)
		}
		return s
	}
	return "x509: unknown error"
}

// HostnameError results when the set of authorized names doesn't match the
// requested name.
type HostnameError struct {
	Certificate *Certificate
	Host        string
}

func (h HostnameError) Error() string {
	c := h.Certificate

	if !c.hasSANExtension() && matchHostnames(c.Subject.CommonName, h.Host) {
		return "x509: certificate relies on legacy Common Name field, use SANs instead"
	}

	var valid string
	if ip := net.ParseIP(h.Host); ip != nil {
		// Trying to validate an IP
		if len(c.IPAddresses) == 0 {
			return "x509: cannot validate certificate for " + h.Host + " because it doesn't contain any IP SANs"
		}
		for _, san := range c.IPAddresses {
			if len(valid) > 0 {
				valid += ", "
			}
			valid += san.String()
		}
	} else {
		valid = strings.Join(c.DNSNames, ", ")
	}

	if len(valid) == 0 {
		return "x509: certificate is not valid for any names, but wanted to match " + h.Host
	}
	return "x509: certificate is valid for " + valid + ", not " + h.Host
}

// UnknownAuthorityError results when the certificate issuer is unknown
type UnknownAuthorityError struct {
	Cert *Certificate
	// hintErr contains an error that may be helpful in determining why an
	// authority wasn't found.
	hintErr error
	// hintCert contains a possible authority certificate that was rejected
	// because of the error in hintErr.
	hintCert *Certificate
}

func (e UnknownAuthorityError) Error() string {
	s := "x509: certificate signed by unknown authority"
	if e.hintErr != nil {
		certName := e.hintCert.Subject.CommonName
		if len(certName) == 0 {
			if len(e.hintCert.Subject.Organization) > 0 {
				certName = e.hintCert.Subject.Organization[0]
			} else {
				certName = "serial:" + e.hintCert.SerialNumber.String()
			}
		}
		s += fmt.Sprintf(" (possibly because of %q while trying to verify candidate authority certificate %q)", e.hintErr, certName)
	}
	return s
}

// SystemRootsError results when we fail to load the system root certificates.
type SystemRootsError struct {
	Err error
}

func (se SystemRootsError) Error() string {
	msg := "x509: failed to load system roots and no roots provided"
	if se.Err != nil {
		return msg + "; " + se.Err.Error()
	}
	return msg
}

func (se SystemRootsError) Unwrap() error { return se.Err }

// errNotParsed is returned when a certificate without ASN.1 contents is
// verified. Platform-specific verification needs the ASN.1 contents.
var errNotParsed = errors.New("x509: missing ASN.1 contents; use ParseCertificate")

// VerifyOptions contains parameters for Certificate.Verify.
type VerifyOptions struct {
	// DNSName, if set, is checked against the leaf certificate with
	// Certificate.VerifyHostname or the platform verifier.
	DNSName string

	// Intermediates is an optional pool of certificates that are not trust
	// anchors, but can be used to form a chain from the leaf certificate to a
	// root certificate.
	Intermediates *CertPool
	// Roots is the set of trusted root certificates the leaf certificate needs
	// to chain up to. If nil, the system roots or the platform verifier are used.
	Roots *CertPool

	// CurrentTime is used to check the validity of all certificates in the
	// chain. If zero, the current time is used.
	CurrentTime time.Time

	// KeyUsages specifies which Extended Key Usage values are acceptable. A
	// chain is accepted if it allows any of the listed values. An empty list
	// means ExtKeyUsageServerAuth. To accept any key usage, include ExtKeyUsageAny.
	KeyUsages []ExtKeyUsage

	// MaxConstraintComparisions is the maximum number of comparisons to
	// perform when checking a given certificate's name constraints. If
	// zero, a sensible default is used. This limit prevents pathological
	// certificates from consuming excessive amounts of CPU time when
	// validating. It does not apply to the platform verifier.
	MaxConstraintComparisions int

	// CertificatePolicies specifies which certificate policy OIDs are
	// acceptable during policy validation. An empty CertificatePolices
	// field implies any valid policy is acceptable.
	CertificatePolicies []OID

	// The following policy fields are unexported, because we do not expect
	// users to actually need to use them, but are useful for testing the
	// policy validation code.

	// inhibitPolicyMapping indicates if policy mapping should be allowed
	// during path validation.
	inhibitPolicyMapping bool

	// requireExplicitPolicy indidicates if explicit policies must be present
	// for each certificate being validated.
	requireExplicitPolicy bool

	// inhibitAnyPolicy indicates if the anyPolicy policy should be
	// processed if present in a certificate being validated.
	inhibitAnyPolicy bool
}

const (
	leafCertificate = iota
	intermediateCertificate
	rootCertificate
)

// rfc2821Mailbox represents a “mailbox” (which is an email address to most
// people) by breaking it into the “local” (i.e. before the '@') and “domain”
// parts.
type rfc2821Mailbox struct {
	local, domain string
}

// parseRFC2821Mailbox parses an email address into local and domain parts,
// based on the ABNF for a “Mailbox” from RFC 2821. According to RFC 5280,
// Section 4.2.1.6 that's correct for an rfc822Name from a certificate: “The
// format of an rfc822Name is a "Mailbox" as defined in RFC 2821, Section 4.1.2”.
func parseRFC2821Mailbox(in string) (mailbox rfc2821Mailbox, ok bool) {
	if len(in) == 0 {
		return mailbox, false
	}

	localPartBytes := make([]byte, 0, len(in)/2)

	if in[0] == '"' {
		// Quoted-string = DQUOTE *qcontent DQUOTE
		// non-whitespace-control = %d1-8 / %d11 / %d12 / %d14-31 / %d127
		// qcontent = qtext / quoted-pair
		// qtext = non-whitespace-control /
		//         %d33 / %d35-91 / %d93-126
		// quoted-pair = ("\" text) / obs-qp
		// text = %d1-9 / %d11 / %d12 / %d14-127 / obs-text
		//
		// (Names beginning with “obs-” are the obsolete syntax from RFC 2822,
		// Section 4. Since it has been 16 years, we no longer accept that.)
		in = in[1:]
	QuotedString:
		for {
			if len(in) == 0 {
				return mailbox, false
			}
			c := in[0]
			in = in[1:]

			switch {
			case c == '"':
				break QuotedString

			case c == '\\':
				// quoted-pair
				if len(in) == 0 {
					return mailbox, false
				}
				if in[0] == 11 ||
					in[0] == 12 ||
					(1 <= in[0] && in[0] <= 9) ||
					(14 <= in[0] && in[0] <= 127) {
					localPartBytes = append(localPartBytes, in[0])
					in = in[1:]
				} else {
					return mailbox, false
				}

			case c == 11 ||
				c == 12 ||
				// Space (char 32) is not allowed based on the
				// BNF, but RFC 3696 gives an example that
				// assumes that it is. Several “verified”
				// errata continue to argue about this point.
				// We choose to accept it.
				c == 32 ||
				c == 33 ||
				c == 127 ||
				(1 <= c && c <= 8) ||
				(14 <= c && c <= 31) ||
				(35 <= c && c <= 91) ||
				(93 <= c && c <= 126):
				// qtext
				localPartBytes = append(localPartBytes, c)

			default:
				return mailbox, false
			}
		}
	} else {
		// Atom ("." Atom)*
	NextChar:
		for len(in) > 0 {
			// atext from RFC 2822, Section 3.2.4
			c := in[0]

			switch {
			case c == '\\':
				// Examples given in RFC 3696 suggest that
				// escaped characters can appear outside of a
				// quoted string. Several “verified” errata
				// continue to argue the point. We choose to
				// accept it.
				in = in[1:]
				if len(in) == 0 {
					return mailbox, false
				}
				fallthrough

			case ('0' <= c && c <= '9') ||
				('a' <= c && c <= 'z') ||
				('A' <= c && c <= 'Z') ||
				c == '!' || c == '#' || c == '$' || c == '%' ||
				c == '&' || c == '\'' || c == '*' || c == '+' ||
				c == '-' || c == '/' || c == '=' || c == '?' ||
				c == '^' || c == '_' || c == '`' || c == '{' ||
				c == '|' || c == '}' || c == '~' || c == '.':
				localPartBytes = append(localPartBytes, in[0])
				in = in[1:]

			default:
				break NextChar
			}
		}

		if len(localPartBytes) == 0 {
			return mailbox, false
		}

		// From RFC 3696, Section 3:
		// “period (".") may also appear, but may not be used to start
		// or end the local part, nor may two or more consecutive
		// periods appear.”
		twoDots := []byte{'.', '.'}
		if localPartBytes[0] == '.' ||
			localPartBytes[len(localPartBytes)-1] == '.' ||
			bytes.Contains(localPartBytes, twoDots) {
			return mailbox, false
		}
	}

	if len(in) == 0 || in[0] != '@' {
		return mailbox, false
	}
	in = in[1:]

	// The RFC species a format for domains, but that's known to be
	// violated in practice so we accept that anything after an '@' is the
	// domain part.
	if _, ok := domainToReverseLabels(in); !ok {
		return mailbox, false
	}

	mailbox.local = string(localPartBytes)
	mailbox.domain = in
	return mailbox, true
}

// domainToReverseLabels converts a textual domain name like foo.example.com to
// the list of labels in reverse order, e.g. ["com", "example", "foo"].
func domainToReverseLabels(domain string) (reverseLabels []string, ok bool) {
	for len(domain) > 0 {
		if i := strings.LastIndexByte(domain, '.'); i == -1 {
			reverseLabels = append(reverseLabels, domain)
			domain = ""
		} else {
			reverseLabels = append(reverseLabels, domain[i+1:])
			domain = domain[:i]
			if i == 0 { // domain == ""
				// domain is prefixed with an empty label, append an empty
				// string to reverseLabels to indicate this.
				reverseLabels = append(reverseLabels, "")
			}
		}
	}

	if len(reverseLabels) > 0 && len(reverseLabels[0]) == 0 {
		// An empty label at the end indicates an absolute value.
		return nil, false
	}

	for _, label := range reverseLabels {
		if len(label) == 0 {
			// Empty labels are otherwise invalid.
			return nil, false
		}

		for _, c := range label {
			if c < 33 || c > 126 {
				// Invalid character.
				return nil, false
			}
		}
	}

	return reverseLabels, true
}

func matchEmailConstraint(mailbox rfc2821Mailbox, constraint string) (bool, error) {
	// If the constraint contains an @, then it specifies an exact mailbox
	// name.
	if strings.Contains(constraint, "@") {
		constraintMailbox, ok := parseRFC2821Mailbox(constraint)
		if !ok {
			return false, fmt.Errorf("x509: internal error: cannot parse constraint %q", constraint)
		}
		return mailbox.local == constraintMailbox.local && strings.EqualFold(mailbox.domain, constraintMailbox.domain), nil
	}

	// Otherwise the constraint is like a DNS constraint of the domain part
	// of the mailbox.
	return matchDomainConstraint(mailbox.domain, constraint)
}

func matchURIConstraint(uri *url.URL, constraint string) (bool, error) {
	// From RFC 5280, Section 4.2.1.10:
	// “a uniformResourceIdentifier that does not include an authority
	// component with a host name specified as a fully qualified domain
	// name (e.g., if the URI either does not include an authority
	// component or includes an authority component in which the host name
	// is specified as an IP address), then the application MUST reject the
	// certificate.”

	host := uri.Host
	if len(host) == 0 {
		return false, fmt.Errorf("URI with empty host (%q) cannot be matched against constraints", uri.String())
	}

	if strings.Contains(host, ":") && !strings.HasSuffix(host, "]") {
		var err error
		host, _, err = net.SplitHostPort(uri.Host)
		if err != nil {
			return false, err
		}
	}

	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") ||
		net.ParseIP(host) != nil {
		return false, fmt.Errorf("URI with IP (%q) cannot be matched against constraints", uri.String())
	}

	return matchDomainConstraint(host, constraint)
}

func matchIPConstraint(ip net.IP, constraint *net.IPNet) (bool, error) {
	if len(ip) != len(constraint.IP) {
		return false, nil
	}

	for i := range ip {
		if mask := constraint.Mask[i]; ip[i]&mask != constraint.IP[i]&mask {
			return false, nil
		}
	}

	return true, nil
}

func matchDomainConstraint(domain, constraint string) (bool, error) {
	// The meaning of zero length constraints is not specified, but this
	// code follows NSS and accepts them as matching everything.
	if len(constraint) == 0 {
		return true, nil
	}

	domainLabels, ok := domainToReverseLabels(domain)
	if !ok {
		return false, fmt.Errorf("x509: internal error: cannot parse domain %q", domain)
	}

	// RFC 5280 says that a leading period in a domain name means that at
	// least one label must be prepended, but only for URI and email
	// constraints, not DNS constraints. The code also supports that
	// behaviour for DNS constraints.

	mustHaveSubdomains := false
	if constraint[0] == '.' {
		mustHaveSubdomains = true
		constraint = constraint[1:]
	}

	constraintLabels, ok := domainToReverseLabels(constraint)
	if !ok {
		return false, fmt.Errorf("x509: internal error: cannot parse domain %q", constraint)
	}

	if len(domainLabels) < len(constraintLabels) ||
		(mustHaveSubdomains && len(domainLabels) == len(constraintLabels)) {
		return false, nil
	}

	for i, constraintLabel := range constraintLabels {
		if !strings.EqualFold(constraintLabel, domainLabels[i]) {
			return false, nil
		}
	}

	return true, nil
}

// checkNameConstraints checks that c permits a child certificate to claim the
// given name, of type nameType. The argument parsedName contains the parsed
// form of name, suitable for passing to the match function. The total number
// of comparisons is tracked in the given count and should not exceed the given
// limit.
func (c *Certificate) checkNameConstraints(count *int,
	maxConstraintComparisons int,
	nameType string,
	name string,
	parsedName any,
	match func(parsedName, constraint any) (match bool, err error),
	permitted, excluded any) error {

	excludedValue := reflect.ValueOf(excluded)

	*count += excludedValue.Len()
	if *count > maxConstraintComparisons {
		return CertificateInvalidError{c, TooManyConstraints, ""}
	}

	for i := 0; i < excludedValue.Len(); i++ {
		constraint := excludedValue.Index(i).Interface()
		match, err := match(parsedName, constraint)
		if err != nil {
			return CertificateInvalidError{c, CANotAuthorizedForThisName, err.Error()}
		}

		if match {
			return CertificateInvalidError{c, CANotAuthorizedForThisName, fmt.Sprintf("%s %q is excluded by constraint %q", nameType, name, constraint)}
		}
	}

	permittedValue := reflect.ValueOf(permitted)

	*count += permittedValue.Len()
	if *count > maxConstraintComparisons {
		return CertificateInvalidError{c, TooManyConstraints, ""}
	}

	ok := true
	for i := 0; i < permittedValue.Len(); i++ {
		constraint := permittedValue.Index(i).Interface()

		var err error
		if ok, err = match(parsedName, constraint); err != nil {
			return CertificateInvalidError{c, CANotAuthorizedForThisName, err.Error()}
		}

		if ok {
			break
		}
	}

	if !ok {
		return CertificateInvalidError{c, CANotAuthorizedForThisName, fmt.Sprintf("%s %q is not permitted by any constraint", nameType, name)}
	}

	return nil
}

// isValid performs validity checks on c given that it is a candidate to append
// to the chain in currentChain.
func (c *Certificate) isValid(certType int, currentChain []*Certificate, opts *VerifyOptions) error {
	if len(c.UnhandledCriticalExtensions) > 0 {
		return UnhandledCriticalExtension{}
	}

	if len(currentChain) > 0 {
		child := currentChain[len(currentChain)-1]
		if !bytes.Equal(child.RawIssuer, c.RawSubject) {
			return CertificateInvalidError{c, NameMismatch, ""}
		}
	}

	now := opts.CurrentTime
	if now.IsZero() {
		now = time.Now()
	}
	if now.Before(c.NotBefore) {
		return CertificateInvalidError{
			Cert:   c,
			Reason: Expired,
			Detail: fmt.Sprintf("current time %s is before %s", now.Format(time.RFC3339), c.NotBefore.Format(time.RFC3339)),
		}
	} else if now.After(c.NotAfter) {
		return CertificateInvalidError{
			Cert:   c,
			Reason: Expired,
			Detail: fmt.Sprintf("current time %s is after %s", now.Format(time.RFC3339), c.NotAfter.Format(time.RFC3339)),
		}
	}

	maxConstraintComparisons := opts.MaxConstraintComparisions
	if maxConstraintComparisons == 0 {
		maxConstraintComparisons = 250000
	}
	comparisonCount := 0

	if certType == intermediateCertificate || certType == rootCertificate {
		if len(currentChain) == 0 {
			return errors.New("x509: internal error: empty chain when appending CA cert")
		}
	}

	if (certType == intermediateCertificate || certType == rootCertificate) &&
		c.hasNameConstraints() {
		toCheck := []*Certificate{}
		for _, c := range currentChain {
			if c.hasSANExtension() {
				toCheck = append(toCheck, c)
			}
		}
		for _, sanCert := range toCheck {
			err := forEachSAN(sanCert.getSANExtension(), func(tag int, data []byte) error {
				switch tag {
				case nameTypeEmail:
					name := string(data)
					mailbox, ok := parseRFC2821Mailbox(name)
					if !ok {
						return fmt.Errorf("x509: cannot parse rfc822Name %q", mailbox)
					}

					if err := c.checkNameConstraints(&comparisonCount, maxConstraintComparisons, "email address", name, mailbox,
						func(parsedName, constraint any) (bool, error) {
							return matchEmailConstraint(parsedName.(rfc2821Mailbox), constraint.(string))
						}, c.PermittedEmailAddresses, c.ExcludedEmailAddresses); err != nil {
						return err
					}

				case nameTypeDNS:
					name := string(data)
					if _, ok := domainToReverseLabels(name); !ok {
						return fmt.Errorf("x509: cannot parse dnsName %q", name)
					}

					if err := c.checkNameConstraints(&comparisonCount, maxConstraintComparisons, "DNS name", name, name,
						func(parsedName, constraint any) (bool, error) {
							return matchDomainConstraint(parsedName.(string), constraint.(string))
						}, c.PermittedDNSDomains, c.ExcludedDNSDomains); err != nil {
						return err
					}

				case nameTypeURI:
					name := string(data)
					uri, err := url.Parse(name)
					if err != nil {
						return fmt.Errorf("x509: internal error: URI SAN %q failed to parse", name)
					}

					if err := c.checkNameConstraints(&comparisonCount, maxConstraintComparisons, "URI", name, uri,
						func(parsedName, constraint any) (bool, error) {
							return matchURIConstraint(parsedName.(*url.URL), constraint.(string))
						}, c.PermittedURIDomains, c.ExcludedURIDomains); err != nil {
						return err
					}

				case nameTypeIP:
					ip := net.IP(data)
					if l := len(ip); l != net.IPv4len && l != net.IPv6len {
						return fmt.Errorf("x509: internal error: IP SAN %x failed to parse", data)
					}

					if err := c.checkNameConstraints(&comparisonCount, maxConstraintComparisons, "IP address", ip.String(), ip,
						func(parsedName, constraint any) (bool, error) {
							return matchIPConstraint(parsedName.(net.IP), constraint.(*net.IPNet))
						}, c.PermittedIPRanges, c.ExcludedIPRanges); err != nil {
						return err
					}

				default:
					// Unknown SAN types are ignored.
				}

				return nil
			})

			if err != nil {
				return err
			}
		}
	}

	// KeyUsage status flags are ignored. From Engineering Security, Peter
	// Gutmann: A European government CA marked its signing certificates as
	// being valid for encryption only, but no-one noticed. Another
	// European CA marked its signature keys as not being valid for
	// signatures. A different CA marked its own trusted root certificate
	// as being invalid for certificate signing. Another national CA
	// distributed a certificate to be used to encrypt data for the
	// country’s tax authority that was marked as only being usable for
	// digital signatures but not for encryption. Yet another CA reversed
	// the order of the bit flags in the keyUsage due to confusion over
	// encoding endianness, essentially setting a random keyUsage in
	// certificates that it issued. Another CA created a self-invalidating
	// certificate by adding a certificate policy statement stipulating
	// that the certificate had to be used strictly as specified in the
	// keyUsage, and a keyUsage containing a flag indicating that the RSA
	// encryption key could only be used for Diffie-Hellman key agreement.

	if certType == intermediateCertificate && (!c.BasicConstraintsValid || !c.IsCA) {
		return CertificateInvalidError{c, NotAuthorizedToSign, ""}
	}

	if c.BasicConstraintsValid && c.MaxPathLen >= 0 {
		numIntermediates := len(currentChain) - 1
		if numIntermediates > c.MaxPathLen {
			return CertificateInvalidError{c, TooManyIntermediates, ""}
		}
	}

	return nil
}

// Verify attempts to verify c by building one or more chains from c to a
// certificate in opts.Roots, using certificates in opts.Intermediates if
// needed. If successful, it returns one or more chains where the first
// element of the chain is c and the last element is from opts.Roots.
//
// If opts.Roots is nil, the platform verifier might be used, and
// verification details might differ from what is described below. If system
// roots are unavailable the returned error will be of type SystemRootsError.
//
// Name constraints in the intermediates will be applied to all names claimed
// in the chain, not just opts.DNSName. Thus it is invalid for a leaf to claim
// example.com if an intermediate doesn't permit it, even if example.com is not
// the name being validated. Note that DirectoryName constraints are not
// supported.
//
// Name constraint validation follows the rules from RFC 5280, with the
// addition that DNS name constraints may use the leading period format
// defined for emails and URIs. When a constraint has a leading period
// it indicates that at least one additional label must be prepended to
// the constrained name to be considered valid.
//
// Extended Key Usage values are enforced nested down a chain, so an intermediate
// or root that enumerates EKUs prevents a leaf from asserting an EKU not in that
// list. (While this is not specified, it is common practice in order to limit
// the types of certificates a CA can issue.)
//
// Certificates that use SHA1WithRSA and ECDSAWithSHA1 signatures are not supported,
// and will not be used to build chains.
//
// Certificates other than c in the returned chains should not be modified.
//
// WARNING: this function doesn't do any revocation checking.
func (c *Certificate) Verify(opts VerifyOptions) (chains [][]*Certificate, err error) {
	// Platform-specific verification needs the ASN.1 contents so
	// this makes the behavior consistent across platforms.
	if len(c.Raw) == 0 {
		return nil, errNotParsed
	}
	for i := 0; i < opts.Intermediates.len(); i++ {
		c, _, err := opts.Intermediates.cert(i)
		if err != nil {
			return nil, fmt.Errorf("crypto/x509: error fetching intermediate: %w", err)
		}
		if len(c.Raw) == 0 {
			return nil, errNotParsed
		}
	}

	// Use platform verifiers, where available, if Roots is from SystemCertPool.
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" || runtime.GOOS == "ios" {
		// Don't use the system verifier if the system pool was replaced with a non-system pool,
		// i.e. if SetFallbackRoots was called with x509usefallbackroots=1.
		systemPool := systemRootsPool()
		if opts.Roots == nil && (systemPool == nil || systemPool.systemPool) {
			return c.systemVerify(&opts)
		}
		if opts.Roots != nil && opts.Roots.systemPool {
			platformChains, err := c.systemVerify(&opts)
			// If the platform verifier succeeded, or there are no additional
			// roots, return the platform verifier result. Otherwise, continue
			// with the Go verifier.
			if err == nil || opts.Roots.len() == 0 {
				return platformChains, err
			}
		}
	}

	if opts.Roots == nil {
		opts.Roots = systemRootsPool()
		if opts.Roots == nil {
			return nil, SystemRootsError{systemRootsErr}
		}
	}

	err = c.isValid(leafCertificate, nil, &opts)
	if err != nil {
		return
	}

	if len(opts.DNSName) > 0 {
		err = c.VerifyHostname(opts.DNSName)
		if err != nil {
			return
		}
	}

	var candidateChains [][]*Certificate
	if opts.Roots.contains(c) {
		candidateChains = [][]*Certificate{{c}}
	} else {
		candidateChains, err = c.buildChains([]*Certificate{c}, nil, &opts)
		if err != nil {
			return nil, err
		}
	}

	if len(opts.KeyUsages) == 0 {
		opts.KeyUsages = []ExtKeyUsage{ExtKeyUsageServerAuth}
	}

	for _, eku := range opts.KeyUsages {
		if eku == ExtKeyUsageAny {
			// If any key usage is acceptable, no need to check the chain for
			// key usages.
			return candidateChains, nil
		}
	}

	chains = make([][]*Certificate, 0, len(candidateChains))
	var incompatibleKeyUsageChains, invalidPoliciesChains int
	for _, candidate := range candidateChains {
		if !checkChainForKeyUsage(candidate, opts.KeyUsages) {
			incompatibleKeyUsageChains++
			continue
		}
		if !policiesValid(candidate, opts) {
			invalidPoliciesChains++
			continue
		}
		chains = append(chains, candidate)
	}
	if len(chains) == 0 {
		var details []string
		if incompatibleKeyUsageChains > 0 {
			if invalidPoliciesChains == 0 {
				return nil, CertificateInvalidError{c, IncompatibleUsage, ""}
			}
			details = append(details, fmt.Sprintf("%d chains with incompatible key usage", incompatibleKeyUsageChains))
		}
		if invalidPoliciesChains > 0 {
			details = append(details, fmt.Sprintf("%d chains with invalid policies", invalidPoliciesChains))
		}
		err = CertificateInvalidError{c, NoValidChains, strings.Join(details, ", ")}
		return nil, err
	}

	return chains, nil
}

func appendToFreshChain(chain []*Certificate, cert *Certificate) []*Certificate {
	n := make([]*Certificate, len(chain)+1)
	copy(n, chain)
	n[len(chain)] = cert
	return n
}

// alreadyInChain checks whether a candidate certificate is present in a chain.
// Rather than doing a direct byte for byte equivalency check, we check if the
// subject, public key, and SAN, if present, are equal. This prevents loops that
// are created by mutual cross-signatures, or other cross-signature bridge
// oddities.
func alreadyInChain(candidate *Certificate, chain []*Certificate) bool {
	type pubKeyEqual interface {
		Equal(crypto.PublicKey) bool
	}

	var candidateSAN *pkix.Extension
	for _, ext := range candidate.Extensions {
		if ext.Id.Equal(oidExtensionSubjectAltName) {
			candidateSAN = &ext
			break
		}
	}

	for _, cert := range chain {
		if !bytes.Equal(candidate.RawSubject, cert.RawSubject) {
			continue
		}
		if !candidate.PublicKey.(pubKeyEqual).Equal(cert.PublicKey) {
			continue
		}
		var certSAN *pkix.Extension
		for _, ext := range cert.Extensions {
			if ext.Id.Equal(oidExtensionSubjectAltName) {
				certSAN = &ext
				break
			}
		}
		if candidateSAN == nil && certSAN == nil {
			return true
		} else if candidateSAN == nil || certSAN == nil {
			return false
		}
		if bytes.Equal(candidateSAN.Value, certSAN.Value) {
			return true
		}
	}
	return false
}

// maxChainSignatureChecks is the maximum number of CheckSignatureFrom calls
// that an invocation of buildChains will (transitively) make. Most chains are
// less than 15 certificates long, so this leaves space for multiple chains and
// for failed checks due to different intermediates having the same Subject.
const maxChainSignatureChecks = 100

func (c *Certificate) buildChains(currentChain []*Certificate, sigChecks *int, opts *VerifyOptions) (chains [][]*Certificate, err error) {
	var (
		hintErr  error
		hintCert *Certificate
	)

	considerCandidate := func(certType int, candidate potentialParent) {
		if candidate.cert.PublicKey == nil || alreadyInChain(candidate.cert, currentChain) {
			return
		}

		if sigChecks == nil {
			sigChecks = new(int)
		}
		*sigChecks++
		if *sigChecks > maxChainSignatureChecks {
			err = errors.New("x509: signature check attempts limit reached while verifying certificate chain")
			return
		}

		if err := c.CheckSignatureFrom(candidate.cert); err != nil {
			if hintErr == nil {
				hintErr = err
				hintCert = candidate.cert
			}
			return
		}

		err = candidate.cert.isValid(certType, currentChain, opts)
		if err != nil {
			if hintErr == nil {
				hintErr = err
				hintCert = candidate.cert
			}
			return
		}

		if candidate.constraint != nil {
			if err := candidate.constraint(currentChain); err != nil {
				if hintErr == nil {
					hintErr = err
					hintCert = candidate.cert
				}
				return
			}
		}

		switch certType {
		case rootCertificate:
			chains = append(chains, appendToFreshChain(currentChain, candidate.cert))
		case intermediateCertificate:
			var childChains [][]*Certificate
			childChains, err = candidate.cert.buildChains(appendToFreshChain(currentChain, candidate.cert), sigChecks, opts)
			chains = append(chains, childChains...)
		}
	}

	for _, root := range opts.Roots.findPotentialParents(c) {
		considerCandidate(rootCertificate, root)
	}
	for _, intermediate := range opts.Intermediates.findPotentialParents(c) {
		considerCandidate(intermediateCertificate, intermediate)
	}

	if len(chains) > 0 {
		err = nil
	}
	if len(chains) == 0 && err == nil {
		err = UnknownAuthorityError{c, hintErr, hintCert}
	}

	return
}

func validHostnamePattern(host string) bool { return validHostname(host, true) }
func validHostnameInput(host string) bool   { return validHostname(host, false) }

// validHostname reports whether host is a valid hostname that can be matched or
// matched against according to RFC 6125 2.2, with some leniency to accommodate
// legacy values.
func validHostname(host string, isPattern bool) bool {
	if !isPattern {
		host = strings.TrimSuffix(host, ".")
	}
	if len(host) == 0 {
		return false
	}
	if host == "*" {
		// Bare wildcards are not allowed, they are not valid DNS names,
		// no
```