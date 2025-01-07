Response:
The user wants a summary of the Go code provided, which is the second part of a file related to X.509 certificate verification. I need to analyze the functions and data structures in this snippet and synthesize their collective purpose. The request emphasizes functionality, possible Go features implemented, code examples with assumptions, handling of command-line arguments (if applicable), and common mistakes (if any).

Based on the code, it seems to be handling the following aspects of certificate verification:

1. **Hostname matching:** Functions like `validHostnameInput`, `validHostnamePattern`, `matchExactly`, `matchHostnames`, and `VerifyHostname` deal with verifying if a certificate is valid for a given hostname. This involves handling wildcards and case-insensitivity.
2. **Extended Key Usage:** The `checkChainForKeyUsage` function seems to verify if a certificate chain supports the required extended key usages.
3. **Certificate Policy Processing:** The code defines data structures (`policyGraphNode`, `policyGraph`) and functions (`newPolicyGraph`, `insert`, `prune`, `policiesValid`) related to processing and validating certificate policies according to RFC specifications. This is a complex part dealing with policy OIDs, mapping, and constraints.

Since this is the second part of the file, it likely builds upon concepts defined in the first part.

Let's break down the required elements for the response:

*   **Functionality Listing:** Enumerate the main tasks performed by this code.
*   **Go Feature Implementation:**  Identify key Go language features demonstrated in the code (e.g., structs, methods, slices, maps, string manipulation).
*   **Code Example:** Provide a concrete Go example showcasing one of the functionalities (hostname verification seems suitable). I'll need to invent some certificate data for this.
*   **Command-line Arguments:**  This part of the code doesn't appear to directly handle command-line arguments. I should state this explicitly.
*   **Common Mistakes:**  Think about potential pitfalls for users when dealing with hostname matching and certificate policy. Incorrect wildcard usage or misunderstanding policy constraints are potential areas.
*   **Overall Function Summary:** Provide a concise summary of the code's purpose.
这是 `go/src/crypto/x509/verify.go` 文件的一部分，专注于 X.509 证书验证过程中的主机名验证和证书策略处理。

**功能列举:**

1. **主机名验证相关:**
    *   `validHostnameInput(host string) bool`: 检查输入的主机名是否符合基本的有效性规则。
    *   `validHostnamePattern(host string) bool`: 检查给定的字符串是否是有效的主机名模式（可以包含通配符 `*`）。
    *   `matchExactly(hostA, hostB string) bool`: 比较两个主机名是否完全匹配（忽略大小写）。
    *   `matchHostnames(pattern, host string) bool`:  根据模式匹配主机名，支持左侧的通配符。
    *   `toLowerCaseASCII(in string) string`: 将字符串转换为小写 ASCII 形式。
    *   `(*Certificate) VerifyHostname(h string) error`: 验证证书是否对给定的主机名有效。它会检查证书的 `IPAddresses` 和 `DNSNames` 字段，并处理 IP 地址和带有通配符的主机名。

2. **扩展密钥用途 (Extended Key Usage) 检查:**
    *   `checkChainForKeyUsage(chain []*Certificate, keyUsages []ExtKeyUsage) bool`: 检查证书链中的证书是否支持所需的扩展密钥用途。

3. **证书策略 (Certificate Policy) 处理:**
    *   定义了 `policyGraphNode` 和 `policyGraph` 结构体，用于表示证书策略的图结构。
    *   `newPolicyGraph() *policyGraph`: 创建一个新的策略图。
    *   `(*policyGraph) insert(n *policyGraphNode)`: 向策略图中插入一个节点。
    *   `(*policyGraph) parentsWithExpected(expected OID) []*policyGraphNode`:  在策略图中查找具有指定期望策略的父节点。
    *   `(*policyGraph) parentWithAnyPolicy() *policyGraphNode`: 在策略图中查找具有 `anyPolicyOID` 的父节点。
    *   `(*policyGraph) parents() iter.Seq[*policyGraphNode]`: 获取策略图当前层的所有父节点。
    *   `(*policyGraph) leaves() map[string]*policyGraphNode`: 获取策略图当前层的所有叶子节点。
    *   `(*policyGraph) leafWithPolicy(policy OID) *policyGraphNode`:  在策略图中查找具有指定策略的叶子节点。
    *   `(*policyGraph) deleteLeaf(policy OID)`: 从策略图中删除指定的叶子节点。
    *   `(*policyGraph) validPolicyNodes() []*policyGraphNode`: 获取策略图中有效的策略节点。
    *   `(*policyGraph) prune()`:  修剪策略图中没有子节点的中间节点。
    *   `(*policyGraph) incrDepth()`: 增加策略图的深度。
    *   `policiesValid(chain []*Certificate, opts VerifyOptions) bool`:  根据 RFC 5280 和 RFC 9618 的规定，验证证书链的策略是否有效。

**Go 语言功能实现举例:**

这个代码片段大量使用了 Go 语言的以下特性：

*   **结构体 (struct):**  `Certificate`, `HostnameError`, `policyGraphNode`, `policyGraph` 等用于组织数据。
*   **方法 (method):**  例如 `(*Certificate) VerifyHostname(h string) error` 定义了 `Certificate` 结构体的方法。
*   **切片 (slice):**  例如 `[]*Certificate` 用于表示证书链，`[]string` 用于存储主机名列表。
*   **映射 (map):**  例如 `map[string]*policyGraphNode` 用于在策略图中存储节点，`map[string]bool` 用于表示策略集合。
*   **字符串操作:** 使用 `strings` 包进行字符串分割、比较和转换。
*   **循环和条件语句:**  用于实现各种验证逻辑。
*   **错误处理:** 使用 `error` 接口返回验证错误。

**代码推理举例 (Hostname 验证):**

假设我们有以下输入：

```go
import (
	"crypto/x509"
	"fmt"
)

func main() {
	cert := &x509.Certificate{
		DNSNames: []string{"example.com", "*.test.com"},
		IPAddresses: nil,
	}

	testCases := []string{"example.com", "www.example.com", "a.test.com", "b.test.com", "invalid_host"}

	for _, host := range testCases {
		err := cert.VerifyHostname(host)
		if err != nil {
			fmt.Printf("主机名 '%s' 验证失败: %v\n", host, err)
		} else {
			fmt.Printf("主机名 '%s' 验证成功\n", host)
		}
	}
}
```

**假设的输出:**

```
主机名 'example.com' 验证成功
主机名 'www.example.com' 验证失败: x509: certificate is valid for example.com, *.test.com, not www.example.com
主机名 'a.test.com' 验证成功
主机名 'b.test.com' 验证成功
主机名 'invalid_host' 验证失败: x509: certificate is valid for example.com, *.test.com, not invalid_host
```

**代码推理 (策略验证):**

由于策略验证的代码非常复杂，涉及到多个 RFC 规范，直接通过简单的输入输出进行推理比较困难。  其核心逻辑在于构建和维护一个策略图，并根据证书链中的策略信息和各种约束（例如 `inhibitAnyPolicy`，`requireExplicitPolicy`，`policyMapping`）来判断策略是否有效。

**命令行参数处理:**

这个代码片段本身不直接处理命令行参数。与 X.509 证书验证相关的命令行工具（例如 `openssl` 或 Go 标准库中可能存在的其他工具）可能会使用这些函数，但具体的命令行参数处理逻辑不在这个代码片段中。

**使用者易犯错的点 (Hostname 验证):**

1. **通配符的理解错误:** 用户可能会认为 `*.example.com` 可以匹配 `sub.sub.example.com`，但实际上，这种通配符只匹配最左侧的一个标签。
    *   **错误示例:**  证书的 `DNSNames` 包含 `*.example.com`，用户认为可以访问 `a.b.example.com`，但实际上这是不匹配的。

2. **大小写敏感性混淆:**  虽然 `VerifyHostname` 内部会将主机名转换为小写进行比较，但用户可能会错误地认为需要完全匹配大小写。
    *   **错误示例:**  证书的 `DNSNames` 包含 `Example.com`，用户尝试使用 `example.com` 进行连接，可能会疑惑为什么可以连接，而没有意识到内部的转换。

3. **忽略尾部的点:**  `matchHostnames` 函数会去除主机名尾部的点，用户可能没有意识到这一点。

**功能归纳:**

这段代码实现了 Go 语言中 X.509 证书验证的核心功能，特别是：

*   **安全地验证证书是否适用于特定的主机名或 IP 地址，** 遵循 RFC 6125 等相关标准，并处理通配符。
*   **检查证书链是否满足所需的扩展密钥用途，** 这对于确保证书被用于其预期的目的至关重要。
*   **根据 RFC 5280 和 RFC 9618 的规定，进行复杂的证书策略验证，**  这涉及到处理证书中的策略信息，以及各种策略约束，以确保证书链的策略有效性。

总的来说，这段代码是 Go 语言进行安全通信的基础组成部分，确保了客户端和服务端能够信任彼此的身份。

Prompt: 
```
这是路径为go/src/crypto/x509/verify.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""
r are they allowed per RFC 6125.
		return false
	}

	for i, part := range strings.Split(host, ".") {
		if part == "" {
			// Empty label.
			return false
		}
		if isPattern && i == 0 && part == "*" {
			// Only allow full left-most wildcards, as those are the only ones
			// we match, and matching literal '*' characters is probably never
			// the expected behavior.
			continue
		}
		for j, c := range part {
			if 'a' <= c && c <= 'z' {
				continue
			}
			if '0' <= c && c <= '9' {
				continue
			}
			if 'A' <= c && c <= 'Z' {
				continue
			}
			if c == '-' && j != 0 {
				continue
			}
			if c == '_' {
				// Not a valid character in hostnames, but commonly
				// found in deployments outside the WebPKI.
				continue
			}
			return false
		}
	}

	return true
}

func matchExactly(hostA, hostB string) bool {
	if hostA == "" || hostA == "." || hostB == "" || hostB == "." {
		return false
	}
	return toLowerCaseASCII(hostA) == toLowerCaseASCII(hostB)
}

func matchHostnames(pattern, host string) bool {
	pattern = toLowerCaseASCII(pattern)
	host = toLowerCaseASCII(strings.TrimSuffix(host, "."))

	if len(pattern) == 0 || len(host) == 0 {
		return false
	}

	patternParts := strings.Split(pattern, ".")
	hostParts := strings.Split(host, ".")

	if len(patternParts) != len(hostParts) {
		return false
	}

	for i, patternPart := range patternParts {
		if i == 0 && patternPart == "*" {
			continue
		}
		if patternPart != hostParts[i] {
			return false
		}
	}

	return true
}

// toLowerCaseASCII returns a lower-case version of in. See RFC 6125 6.4.1. We use
// an explicitly ASCII function to avoid any sharp corners resulting from
// performing Unicode operations on DNS labels.
func toLowerCaseASCII(in string) string {
	// If the string is already lower-case then there's nothing to do.
	isAlreadyLowerCase := true
	for _, c := range in {
		if c == utf8.RuneError {
			// If we get a UTF-8 error then there might be
			// upper-case ASCII bytes in the invalid sequence.
			isAlreadyLowerCase = false
			break
		}
		if 'A' <= c && c <= 'Z' {
			isAlreadyLowerCase = false
			break
		}
	}

	if isAlreadyLowerCase {
		return in
	}

	out := []byte(in)
	for i, c := range out {
		if 'A' <= c && c <= 'Z' {
			out[i] += 'a' - 'A'
		}
	}
	return string(out)
}

// VerifyHostname returns nil if c is a valid certificate for the named host.
// Otherwise it returns an error describing the mismatch.
//
// IP addresses can be optionally enclosed in square brackets and are checked
// against the IPAddresses field. Other names are checked case insensitively
// against the DNSNames field. If the names are valid hostnames, the certificate
// fields can have a wildcard as the complete left-most label (e.g. *.example.com).
//
// Note that the legacy Common Name field is ignored.
func (c *Certificate) VerifyHostname(h string) error {
	// IP addresses may be written in [ ].
	candidateIP := h
	if len(h) >= 3 && h[0] == '[' && h[len(h)-1] == ']' {
		candidateIP = h[1 : len(h)-1]
	}
	if ip := net.ParseIP(candidateIP); ip != nil {
		// We only match IP addresses against IP SANs.
		// See RFC 6125, Appendix B.2.
		for _, candidate := range c.IPAddresses {
			if ip.Equal(candidate) {
				return nil
			}
		}
		return HostnameError{c, candidateIP}
	}

	candidateName := toLowerCaseASCII(h) // Save allocations inside the loop.
	validCandidateName := validHostnameInput(candidateName)

	for _, match := range c.DNSNames {
		// Ideally, we'd only match valid hostnames according to RFC 6125 like
		// browsers (more or less) do, but in practice Go is used in a wider
		// array of contexts and can't even assume DNS resolution. Instead,
		// always allow perfect matches, and only apply wildcard and trailing
		// dot processing to valid hostnames.
		if validCandidateName && validHostnamePattern(match) {
			if matchHostnames(match, candidateName) {
				return nil
			}
		} else {
			if matchExactly(match, candidateName) {
				return nil
			}
		}
	}

	return HostnameError{c, h}
}

func checkChainForKeyUsage(chain []*Certificate, keyUsages []ExtKeyUsage) bool {
	usages := make([]ExtKeyUsage, len(keyUsages))
	copy(usages, keyUsages)

	if len(chain) == 0 {
		return false
	}

	usagesRemaining := len(usages)

	// We walk down the list and cross out any usages that aren't supported
	// by each certificate. If we cross out all the usages, then the chain
	// is unacceptable.

NextCert:
	for i := len(chain) - 1; i >= 0; i-- {
		cert := chain[i]
		if len(cert.ExtKeyUsage) == 0 && len(cert.UnknownExtKeyUsage) == 0 {
			// The certificate doesn't have any extended key usage specified.
			continue
		}

		for _, usage := range cert.ExtKeyUsage {
			if usage == ExtKeyUsageAny {
				// The certificate is explicitly good for any usage.
				continue NextCert
			}
		}

		const invalidUsage ExtKeyUsage = -1

	NextRequestedUsage:
		for i, requestedUsage := range usages {
			if requestedUsage == invalidUsage {
				continue
			}

			for _, usage := range cert.ExtKeyUsage {
				if requestedUsage == usage {
					continue NextRequestedUsage
				}
			}

			usages[i] = invalidUsage
			usagesRemaining--
			if usagesRemaining == 0 {
				return false
			}
		}
	}

	return true
}

func mustNewOIDFromInts(ints []uint64) OID {
	oid, err := OIDFromInts(ints)
	if err != nil {
		panic(fmt.Sprintf("OIDFromInts(%v) unexpected error: %v", ints, err))
	}
	return oid
}

type policyGraphNode struct {
	validPolicy       OID
	expectedPolicySet []OID
	// we do not implement qualifiers, so we don't track qualifier_set

	parents  map[*policyGraphNode]bool
	children map[*policyGraphNode]bool
}

func newPolicyGraphNode(valid OID, parents []*policyGraphNode) *policyGraphNode {
	n := &policyGraphNode{
		validPolicy:       valid,
		expectedPolicySet: []OID{valid},
		children:          map[*policyGraphNode]bool{},
		parents:           map[*policyGraphNode]bool{},
	}
	for _, p := range parents {
		p.children[n] = true
		n.parents[p] = true
	}
	return n
}

type policyGraph struct {
	strata []map[string]*policyGraphNode
	// map of OID -> nodes at strata[depth-1] with OID in their expectedPolicySet
	parentIndex map[string][]*policyGraphNode
	depth       int
}

var anyPolicyOID = mustNewOIDFromInts([]uint64{2, 5, 29, 32, 0})

func newPolicyGraph() *policyGraph {
	root := policyGraphNode{
		validPolicy:       anyPolicyOID,
		expectedPolicySet: []OID{anyPolicyOID},
		children:          map[*policyGraphNode]bool{},
		parents:           map[*policyGraphNode]bool{},
	}
	return &policyGraph{
		depth:  0,
		strata: []map[string]*policyGraphNode{{string(anyPolicyOID.der): &root}},
	}
}

func (pg *policyGraph) insert(n *policyGraphNode) {
	pg.strata[pg.depth][string(n.validPolicy.der)] = n
}

func (pg *policyGraph) parentsWithExpected(expected OID) []*policyGraphNode {
	if pg.depth == 0 {
		return nil
	}
	return pg.parentIndex[string(expected.der)]
}

func (pg *policyGraph) parentWithAnyPolicy() *policyGraphNode {
	if pg.depth == 0 {
		return nil
	}
	return pg.strata[pg.depth-1][string(anyPolicyOID.der)]
}

func (pg *policyGraph) parents() iter.Seq[*policyGraphNode] {
	if pg.depth == 0 {
		return nil
	}
	return maps.Values(pg.strata[pg.depth-1])
}

func (pg *policyGraph) leaves() map[string]*policyGraphNode {
	return pg.strata[pg.depth]
}

func (pg *policyGraph) leafWithPolicy(policy OID) *policyGraphNode {
	return pg.strata[pg.depth][string(policy.der)]
}

func (pg *policyGraph) deleteLeaf(policy OID) {
	n := pg.strata[pg.depth][string(policy.der)]
	if n == nil {
		return
	}
	for p := range n.parents {
		delete(p.children, n)
	}
	for c := range n.children {
		delete(c.parents, n)
	}
	delete(pg.strata[pg.depth], string(policy.der))
}

func (pg *policyGraph) validPolicyNodes() []*policyGraphNode {
	var validNodes []*policyGraphNode
	for i := pg.depth; i >= 0; i-- {
		for _, n := range pg.strata[i] {
			if n.validPolicy.Equal(anyPolicyOID) {
				continue
			}

			if len(n.parents) == 1 {
				for p := range n.parents {
					if p.validPolicy.Equal(anyPolicyOID) {
						validNodes = append(validNodes, n)
					}
				}
			}
		}
	}
	return validNodes
}

func (pg *policyGraph) prune() {
	for i := pg.depth - 1; i > 0; i-- {
		for _, n := range pg.strata[i] {
			if len(n.children) == 0 {
				for p := range n.parents {
					delete(p.children, n)
				}
				delete(pg.strata[i], string(n.validPolicy.der))
			}
		}
	}
}

func (pg *policyGraph) incrDepth() {
	pg.parentIndex = map[string][]*policyGraphNode{}
	for _, n := range pg.strata[pg.depth] {
		for _, e := range n.expectedPolicySet {
			pg.parentIndex[string(e.der)] = append(pg.parentIndex[string(e.der)], n)
		}
	}

	pg.depth++
	pg.strata = append(pg.strata, map[string]*policyGraphNode{})
}

func policiesValid(chain []*Certificate, opts VerifyOptions) bool {
	// The following code implements the policy verification algorithm as
	// specified in RFC 5280 and updated by RFC 9618. In particular the
	// following sections are replaced by RFC 9618:
	//	* 6.1.2 (a)
	//	* 6.1.3 (d)
	//	* 6.1.3 (e)
	//	* 6.1.3 (f)
	//	* 6.1.4 (b)
	//	* 6.1.5 (g)

	if len(chain) == 1 {
		return true
	}

	// n is the length of the chain minus the trust anchor
	n := len(chain) - 1

	pg := newPolicyGraph()
	var inhibitAnyPolicy, explicitPolicy, policyMapping int
	if !opts.inhibitAnyPolicy {
		inhibitAnyPolicy = n + 1
	}
	if !opts.requireExplicitPolicy {
		explicitPolicy = n + 1
	}
	if !opts.inhibitPolicyMapping {
		policyMapping = n + 1
	}

	initialUserPolicySet := map[string]bool{}
	for _, p := range opts.CertificatePolicies {
		initialUserPolicySet[string(p.der)] = true
	}
	// If the user does not pass any policies, we consider
	// that equivalent to passing anyPolicyOID.
	if len(initialUserPolicySet) == 0 {
		initialUserPolicySet[string(anyPolicyOID.der)] = true
	}

	for i := n - 1; i >= 0; i-- {
		cert := chain[i]

		isSelfSigned := bytes.Equal(cert.RawIssuer, cert.RawSubject)

		// 6.1.3 (e) -- as updated by RFC 9618
		if len(cert.Policies) == 0 {
			pg = nil
		}

		// 6.1.3 (f) -- as updated by RFC 9618
		if explicitPolicy == 0 && pg == nil {
			return false
		}

		if pg != nil {
			pg.incrDepth()

			policies := map[string]bool{}

			// 6.1.3 (d) (1) -- as updated by RFC 9618
			for _, policy := range cert.Policies {
				policies[string(policy.der)] = true

				if policy.Equal(anyPolicyOID) {
					continue
				}

				// 6.1.3 (d) (1) (i) -- as updated by RFC 9618
				parents := pg.parentsWithExpected(policy)
				if len(parents) == 0 {
					// 6.1.3 (d) (1) (ii) -- as updated by RFC 9618
					if anyParent := pg.parentWithAnyPolicy(); anyParent != nil {
						parents = []*policyGraphNode{anyParent}
					}
				}
				if len(parents) > 0 {
					pg.insert(newPolicyGraphNode(policy, parents))
				}
			}

			// 6.1.3 (d) (2) -- as updated by RFC 9618
			// NOTE: in the check "n-i < n" our i is different from the i in the specification.
			// In the specification chains go from the trust anchor to the leaf, whereas our
			// chains go from the leaf to the trust anchor, so our i's our inverted. Our
			// check here matches the check "i < n" in the specification.
			if policies[string(anyPolicyOID.der)] && (inhibitAnyPolicy > 0 || (n-i < n && isSelfSigned)) {
				missing := map[string][]*policyGraphNode{}
				leaves := pg.leaves()
				for p := range pg.parents() {
					for _, expected := range p.expectedPolicySet {
						if leaves[string(expected.der)] == nil {
							missing[string(expected.der)] = append(missing[string(expected.der)], p)
						}
					}
				}

				for oidStr, parents := range missing {
					pg.insert(newPolicyGraphNode(OID{der: []byte(oidStr)}, parents))
				}
			}

			// 6.1.3 (d) (3) -- as updated by RFC 9618
			pg.prune()

			if i != 0 {
				// 6.1.4 (b) -- as updated by RFC 9618
				if len(cert.PolicyMappings) > 0 {
					// collect map of issuer -> []subject
					mappings := map[string][]OID{}

					for _, mapping := range cert.PolicyMappings {
						if policyMapping > 0 {
							if mapping.IssuerDomainPolicy.Equal(anyPolicyOID) || mapping.SubjectDomainPolicy.Equal(anyPolicyOID) {
								// Invalid mapping
								return false
							}
							mappings[string(mapping.IssuerDomainPolicy.der)] = append(mappings[string(mapping.IssuerDomainPolicy.der)], mapping.SubjectDomainPolicy)
						} else {
							// 6.1.4 (b) (3) (i) -- as updated by RFC 9618
							pg.deleteLeaf(mapping.IssuerDomainPolicy)

							// 6.1.4 (b) (3) (ii) -- as updated by RFC 9618
							pg.prune()
						}
					}

					for issuerStr, subjectPolicies := range mappings {
						// 6.1.4 (b) (1) -- as updated by RFC 9618
						if matching := pg.leafWithPolicy(OID{der: []byte(issuerStr)}); matching != nil {
							matching.expectedPolicySet = subjectPolicies
						} else if matching := pg.leafWithPolicy(anyPolicyOID); matching != nil {
							// 6.1.4 (b) (2) -- as updated by RFC 9618
							n := newPolicyGraphNode(OID{der: []byte(issuerStr)}, []*policyGraphNode{matching})
							n.expectedPolicySet = subjectPolicies
							pg.insert(n)
						}
					}
				}
			}
		}

		if i != 0 {
			// 6.1.4 (h)
			if !isSelfSigned {
				if explicitPolicy > 0 {
					explicitPolicy--
				}
				if policyMapping > 0 {
					policyMapping--
				}
				if inhibitAnyPolicy > 0 {
					inhibitAnyPolicy--
				}
			}

			// 6.1.4 (i)
			if (cert.RequireExplicitPolicy > 0 || cert.RequireExplicitPolicyZero) && cert.RequireExplicitPolicy < explicitPolicy {
				explicitPolicy = cert.RequireExplicitPolicy
			}
			if (cert.InhibitPolicyMapping > 0 || cert.InhibitPolicyMappingZero) && cert.InhibitPolicyMapping < policyMapping {
				policyMapping = cert.InhibitPolicyMapping
			}
			// 6.1.4 (j)
			if (cert.InhibitAnyPolicy > 0 || cert.InhibitAnyPolicyZero) && cert.InhibitAnyPolicy < inhibitAnyPolicy {
				inhibitAnyPolicy = cert.InhibitAnyPolicy
			}
		}
	}

	// 6.1.5 (a)
	if explicitPolicy > 0 {
		explicitPolicy--
	}

	// 6.1.5 (b)
	if chain[0].RequireExplicitPolicyZero {
		explicitPolicy = 0
	}

	// 6.1.5 (g) (1) -- as updated by RFC 9618
	var validPolicyNodeSet []*policyGraphNode
	// 6.1.5 (g) (2) -- as updated by RFC 9618
	if pg != nil {
		validPolicyNodeSet = pg.validPolicyNodes()
		// 6.1.5 (g) (3) -- as updated by RFC 9618
		if currentAny := pg.leafWithPolicy(anyPolicyOID); currentAny != nil {
			validPolicyNodeSet = append(validPolicyNodeSet, currentAny)
		}
	}

	// 6.1.5 (g) (4) -- as updated by RFC 9618
	authorityConstrainedPolicySet := map[string]bool{}
	for _, n := range validPolicyNodeSet {
		authorityConstrainedPolicySet[string(n.validPolicy.der)] = true
	}
	// 6.1.5 (g) (5) -- as updated by RFC 9618
	userConstrainedPolicySet := maps.Clone(authorityConstrainedPolicySet)
	// 6.1.5 (g) (6) -- as updated by RFC 9618
	if len(initialUserPolicySet) != 1 || !initialUserPolicySet[string(anyPolicyOID.der)] {
		// 6.1.5 (g) (6) (i) -- as updated by RFC 9618
		for p := range userConstrainedPolicySet {
			if !initialUserPolicySet[p] {
				delete(userConstrainedPolicySet, p)
			}
		}
		// 6.1.5 (g) (6) (ii) -- as updated by RFC 9618
		if authorityConstrainedPolicySet[string(anyPolicyOID.der)] {
			for policy := range initialUserPolicySet {
				userConstrainedPolicySet[policy] = true
			}
		}
	}

	if explicitPolicy == 0 && len(userConstrainedPolicySet) == 0 {
		return false
	}

	return true
}

"""




```