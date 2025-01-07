Response:
My goal is to analyze the provided Go code snippet and summarize its functionality, identify the Go features it demonstrates, provide illustrative code examples, and highlight potential pitfalls for users. Since this is part 1 of 2, I need to keep the summary concise and focused on the functionality presented in this specific excerpt.

Here's my thought process:

1. **High-Level Overview:**  The code is a test file (`lookup_test.go`) within the `net` package in Go. Test files typically verify the correct behavior of the code they accompany. Therefore, this file is likely testing the DNS lookup functionalities of the `net` package.

2. **Key Functions and Data Structures:** I'll scan the code for prominent functions and data structures:
    * `goResolver`:  A `Resolver` with `PreferGo: true`, indicating a preference for the Go-native DNS resolver.
    * `lookupLocalhost`: A custom function to handle lookups for "localhost". This suggests testing of local hostname resolution.
    * Various `lookup...Tests` variables (e.g., `lookupGoogleSRVTests`, `lookupGmailMXTests`): These appear to be test case definitions, likely used to drive the testing of different lookup types (SRV, MX, NS, TXT, etc.).
    * Test functions like `TestLookupGoogleSRV`, `TestLookupGmailMX`, `TestLookupCNAME`, etc.: These are standard Go test functions, indicating the specific DNS lookup functions being tested.
    * `backoffDuration`: An array of `time.Duration`, suggesting a retry mechanism with increasing delays for potentially flaky network tests.
    * `reverseaddr`: A function likely responsible for converting IP addresses to reverse DNS lookup format.
    * `TestReverseAddress`: Tests the `reverseaddr` function.
    * `TestDNSFlood`:  A test designed to simulate a high volume of DNS queries, potentially testing concurrency and resilience.
    * `TestLookupDotsWithLocalSource`, `TestLookupDotsWithRemoteSource`, `testDots`:  These tests likely focus on how DNS lookups handle domain names with and without trailing dots.
    * `TestLookupPort`, `TestLookupProtocol_Minimal`:  Tests for looking up port numbers and protocol numbers by name.
    * `TestLookupNonLDH`: Tests handling of non-standard domain names.
    * `TestLookupContextCancel`:  Tests how DNS lookups behave with canceled contexts.
    * `TestNilResolverLookup`:  Tests the behavior of lookups with a `nil` `Resolver`.
    * `TestLookupHostCancel`: Tests lookups after multiple cancellations.
    * `TestConcurrentPreferGoResolversDial`: Tests concurrent use of `PreferGo` resolvers.
    * `TestIPVersion`: Tests a helper function for determining IP version from network type.
    * `TestLookupIPAddrPreservesContextValues`:  Tests if context values are preserved during lookups.
    * `TestLookupIPAddrConcurrentCallsForNetworks`: Tests concurrent lookups for different network types.
    * `TestResolverLookupIPWithEmptyHost`: Tests error handling for empty hostnames.
    * `TestWithUnexpiredValuesPreserved`: Tests context value preservation.
    * `TestLookupNullByte`: Tests handling of null bytes in hostnames.

3. **Identifying Go Features:** Based on the functions and structures, I can identify several Go features in use:
    * **Standard Testing (`testing` package):** The core of the file is built using Go's testing framework.
    * **Contexts (`context` package):** Used for managing timeouts and cancellations in DNS lookups.
    * **Error Handling (`error` interface):** DNS lookup errors are checked and handled.
    * **String Manipulation (`strings` package):** Functions like `HasSuffixFold`, `ToLower`, and `Contains` are used for string comparisons and manipulations in test assertions.
    * **Time Management (`time` package):** Used for implementing backoff delays and timeouts.
    * **Concurrency (`sync` and `sync/atomic` packages):**  Used for managing concurrent DNS queries in the `TestDNSFlood` and `TestConcurrentPreferGoResolversDial` tests, as well as for atomic counters.
    * **Reflection (`reflect` package):** Used for deep comparison of data structures in tests.
    * **Slices (`slices` package):** Used for comparing slices of strings.
    * **Network Programming (`net` and `net/netip` packages):** The core functionality being tested revolves around network and IP address lookups.
    * **Runtime Information (`runtime` package):** Used to conditionally skip tests based on the operating system.
    * **Internal Testing (`internal/testenv`):** Used for skipping tests based on environment conditions (e.g., external network availability).

4. **Illustrative Code Examples (Mental Note for the next step):**  I'll need to provide concise examples demonstrating functions like `LookupHost`, `LookupIP`, `LookupMX`, etc. These examples should be simple and easy to understand.

5. **Command-Line Arguments (Mental Note):**  The code references `*testIPv4` and `*testIPv6`. These are likely boolean flags controlled via command-line arguments during testing. I'll need to explain how these flags are used.

6. **Common Pitfalls (Mental Note):**  A potential pitfall is assuming DNS lookups are always instantaneous and synchronous. The retry logic and context usage suggest that network issues and delays are expected. Another potential issue could be incorrect handling of domain names with or without trailing dots.

7. **Concise Summary (For this part):** I need to summarize the core purpose of the provided code, which is testing various DNS lookup functionalities within the Go `net` package.

By following these steps, I can systematically analyze the code and generate the required comprehensive response. The constraint of it being "part 1" means I should focus on the functionality evident in this snippet and avoid speculating too much about what might be in the subsequent part.
这个 `go/src/net/lookup_test.go` 文件的第一部分主要**测试了 Go 语言 `net` 包中域名解析（DNS lookup）相关的各种功能**。

具体来说，它测试了以下功能：

* **基础的域名解析函数：**  测试了 `LookupHost`, `LookupIP`, `LookupIPAddr`, `LookupCNAME`, `LookupMX`, `LookupNS`, `LookupTXT`, `LookupSRV`, `LookupAddr` 这些用于查询不同类型 DNS 记录的函数。
* **对特定域名（如 google.com, gmail.com）的解析结果的正确性：**  通过预定义的测试用例，验证了针对这些域名的解析结果是否符合预期，例如 `LookupMX` 是否返回包含 `google.com.` 的主机名。
* **对 localhost 的特殊处理：**  `lookupLocalhost` 函数表明测试了对本地主机名 "localhost" 的解析，确保能正确返回 IPv4 和 IPv6 的环回地址。
* **反向地址解析 (`LookupAddr`) 的正确性：**  `TestReverseAddress` 函数测试了 `reverseaddr` 函数，该函数用于将 IP 地址转换为反向 DNS 查询的格式。
* **处理带有点号的域名：** `TestLookupDotsWithLocalSource` 和 `TestLookupDotsWithRemoteSource` 测试了域名末尾带点和不带点的情况，以及本地解析源和远程解析源的不同表现。
* **高并发 DNS 查询的稳定性：** `TestDNSFlood` 模拟了大量的并发 DNS 查询，以测试在高负载下 DNS 解析的稳定性和错误处理。
* **查询服务端口号：** `TestLookupPort` 测试了 `LookupPort` 函数，该函数用于根据服务名和协议查询对应的端口号。
* **查询协议号：** `TestLookupProtocol_Minimal` 测试了 `lookupProtocol` 函数，根据协议名查询协议号。
* **处理非标准域名：** `TestLookupNonLDH` 测试了对包含特殊字符的非法域名的处理，预期会返回 "host not found" 的错误。
* **Context 的取消机制：** `TestLookupContextCancel` 测试了当 `context.Context` 被取消时，DNS 查询是否能够正确终止并返回相应的错误。
* **`nil` Resolver 的安全性：** `TestNilResolverLookup` 确保在使用 `nil` 的 `Resolver` 进行 DNS 查询时不会发生 panic。
* **高并发取消查询后的正常查询：** `TestLookupHostCancel` 测试了在大量被取消的 DNS 查询后，后续的正常查询是否能够正常工作。
* **并发使用 `PreferGo` Resolver 的正确性：** `TestConcurrentPreferGoResolversDial` 确保并发使用配置了 `PreferGo: true` 的 Resolver 时能够正确发起 DNS 查询。
* **IP 版本判断：** `TestIPVersion` 测试了 `ipVersion` 函数，该函数用于根据网络类型判断 IP 协议版本。
* **保持 Context 的值：** `TestLookupIPAddrPreservesContextValues` 验证了在 DNS 查询过程中，传入的 `context.Context` 中的值是否被保留。
* **针对不同网络类型的并发查询：** `TestLookupIPAddrConcurrentCallsForNetworks` 确保针对不同网络类型（如 "udp"，"udp4"，"udp6"）的 DNS 查询能够并发执行。
* **空主机名的错误处理：** `TestResolverLookupIPWithEmptyHost` 测试了当 `LookupIP` 函数传入空主机名时，是否会返回预期的错误。
* **保持未过期 Context 的值：** `TestWithUnexpiredValuesPreserved` 测试了在特定情况下 Context 中的值是否能够被正确保留。
* **处理域名中的空字节：** `TestLookupNullByte` 测试了当域名中包含空字节时，是否会发生 panic。

**这是 Go 语言 `net` 包中关于域名解析功能实现的一部分测试代码，旨在验证其功能的正确性和健壮性。**

Prompt: 
```
这是路径为go/src/net/lookup_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package net

import (
	"context"
	"errors"
	"fmt"
	"internal/testenv"
	"net/netip"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var goResolver = Resolver{PreferGo: true}

func hasSuffixFold(s, suffix string) bool {
	return strings.HasSuffix(strings.ToLower(s), strings.ToLower(suffix))
}

func lookupLocalhost(ctx context.Context, fn func(context.Context, string, string) ([]IPAddr, error), network, host string) ([]IPAddr, error) {
	switch host {
	case "localhost":
		return []IPAddr{
			{IP: IPv4(127, 0, 0, 1)},
			{IP: IPv6loopback},
		}, nil
	default:
		return fn(ctx, network, host)
	}
}

// The Lookup APIs use various sources such as local database, DNS or
// mDNS, and may use platform-dependent DNS stub resolver if possible.
// The APIs accept any of forms for a query; host name in various
// encodings, UTF-8 encoded net name, domain name, FQDN or absolute
// FQDN, but the result would be one of the forms and it depends on
// the circumstances.

var lookupGoogleSRVTests = []struct {
	service, proto, name string
	cname, target        string
}{
	{
		"ldap", "tcp", "google.com",
		"google.com.", "google.com.",
	},
	{
		"ldap", "tcp", "google.com.",
		"google.com.", "google.com.",
	},

	// non-standard back door
	{
		"", "", "_ldap._tcp.google.com",
		"google.com.", "google.com.",
	},
	{
		"", "", "_ldap._tcp.google.com.",
		"google.com.", "google.com.",
	},
}

var backoffDuration = [...]time.Duration{time.Second, 5 * time.Second, 30 * time.Second}

func TestLookupGoogleSRV(t *testing.T) {
	t.Parallel()
	mustHaveExternalNetwork(t)

	if runtime.GOOS == "ios" {
		t.Skip("no resolv.conf on iOS")
	}

	if !supportsIPv4() || !*testIPv4 {
		t.Skip("IPv4 is required")
	}

	attempts := 0
	for i := 0; i < len(lookupGoogleSRVTests); i++ {
		tt := lookupGoogleSRVTests[i]
		cname, srvs, err := LookupSRV(tt.service, tt.proto, tt.name)
		if err != nil {
			testenv.SkipFlakyNet(t)
			if attempts < len(backoffDuration) {
				dur := backoffDuration[attempts]
				t.Logf("backoff %v after failure %v\n", dur, err)
				time.Sleep(dur)
				attempts++
				i--
				continue
			}
			t.Fatal(err)
		}
		if len(srvs) == 0 {
			t.Error("got no record")
		}
		if !hasSuffixFold(cname, tt.cname) {
			t.Errorf("got %s; want %s", cname, tt.cname)
		}
		for _, srv := range srvs {
			if !hasSuffixFold(srv.Target, tt.target) {
				t.Errorf("got %v; want a record containing %s", srv, tt.target)
			}
		}
	}
}

var lookupGmailMXTests = []struct {
	name, host string
}{
	{"gmail.com", "google.com."},
	{"gmail.com.", "google.com."},
}

func TestLookupGmailMX(t *testing.T) {
	t.Parallel()
	mustHaveExternalNetwork(t)

	if runtime.GOOS == "ios" {
		t.Skip("no resolv.conf on iOS")
	}

	if !supportsIPv4() || !*testIPv4 {
		t.Skip("IPv4 is required")
	}

	attempts := 0
	for i := 0; i < len(lookupGmailMXTests); i++ {
		tt := lookupGmailMXTests[i]
		mxs, err := LookupMX(tt.name)
		if err != nil {
			testenv.SkipFlakyNet(t)
			if attempts < len(backoffDuration) {
				dur := backoffDuration[attempts]
				t.Logf("backoff %v after failure %v\n", dur, err)
				time.Sleep(dur)
				attempts++
				i--
				continue
			}
			t.Fatal(err)
		}
		if len(mxs) == 0 {
			t.Error("got no record")
		}
		for _, mx := range mxs {
			if !hasSuffixFold(mx.Host, tt.host) {
				t.Errorf("got %v; want a record containing %s", mx, tt.host)
			}
		}
	}
}

var lookupGmailNSTests = []struct {
	name, host string
}{
	{"gmail.com", "google.com."},
	{"gmail.com.", "google.com."},
}

func TestLookupGmailNS(t *testing.T) {
	t.Parallel()
	mustHaveExternalNetwork(t)

	if runtime.GOOS == "ios" {
		t.Skip("no resolv.conf on iOS")
	}

	if !supportsIPv4() || !*testIPv4 {
		t.Skip("IPv4 is required")
	}

	attempts := 0
	for i := 0; i < len(lookupGmailNSTests); i++ {
		tt := lookupGmailNSTests[i]
		nss, err := LookupNS(tt.name)
		if err != nil {
			testenv.SkipFlakyNet(t)
			if attempts < len(backoffDuration) {
				dur := backoffDuration[attempts]
				t.Logf("backoff %v after failure %v\n", dur, err)
				time.Sleep(dur)
				attempts++
				i--
				continue
			}
			t.Fatal(err)
		}
		if len(nss) == 0 {
			t.Error("got no record")
		}
		for _, ns := range nss {
			if !hasSuffixFold(ns.Host, tt.host) {
				t.Errorf("got %v; want a record containing %s", ns, tt.host)
			}
		}
	}
}

var lookupGmailTXTTests = []struct {
	name, txt, host string
}{
	{"gmail.com", "spf", "google.com"},
	{"gmail.com.", "spf", "google.com"},
}

func TestLookupGmailTXT(t *testing.T) {
	if runtime.GOOS == "plan9" {
		t.Skip("skipping on plan9; see https://golang.org/issue/29722")
	}
	t.Parallel()
	mustHaveExternalNetwork(t)

	if runtime.GOOS == "ios" {
		t.Skip("no resolv.conf on iOS")
	}

	if !supportsIPv4() || !*testIPv4 {
		t.Skip("IPv4 is required")
	}

	attempts := 0
	for i := 0; i < len(lookupGmailTXTTests); i++ {
		tt := lookupGmailTXTTests[i]
		txts, err := LookupTXT(tt.name)
		if err != nil {
			testenv.SkipFlakyNet(t)
			if attempts < len(backoffDuration) {
				dur := backoffDuration[attempts]
				t.Logf("backoff %v after failure %v\n", dur, err)
				time.Sleep(dur)
				attempts++
				i--
				continue
			}
			t.Fatal(err)
		}
		if len(txts) == 0 {
			t.Error("got no record")
		}

		if !slices.ContainsFunc(txts, func(txt string) bool {
			return strings.Contains(txt, tt.txt) && (strings.HasSuffix(txt, tt.host) || strings.HasSuffix(txt, tt.host+"."))
		}) {
			t.Errorf("got %v; want a record containing %s, %s", txts, tt.txt, tt.host)
		}
	}
}

var lookupGooglePublicDNSAddrTests = []string{
	"8.8.8.8",
	"8.8.4.4",
	"2001:4860:4860::8888",
	"2001:4860:4860::8844",
}

func TestLookupGooglePublicDNSAddr(t *testing.T) {
	mustHaveExternalNetwork(t)

	if !supportsIPv4() || !supportsIPv6() || !*testIPv4 || !*testIPv6 {
		t.Skip("both IPv4 and IPv6 are required")
	}

	defer dnsWaitGroup.Wait()

	for _, ip := range lookupGooglePublicDNSAddrTests {
		names, err := LookupAddr(ip)
		if err != nil {
			t.Fatal(err)
		}
		if len(names) == 0 {
			t.Error("got no record")
		}
		for _, name := range names {
			if !hasSuffixFold(name, ".google.com.") && !hasSuffixFold(name, ".google.") {
				t.Errorf("got %q; want a record ending in .google.com. or .google.", name)
			}
		}
	}
}

func TestLookupIPv6LinkLocalAddr(t *testing.T) {
	if !supportsIPv6() || !*testIPv6 {
		t.Skip("IPv6 is required")
	}

	defer dnsWaitGroup.Wait()

	addrs, err := LookupHost("localhost")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(addrs, "fe80::1%lo0") {
		t.Skipf("not supported on %s", runtime.GOOS)
	}
	if _, err := LookupAddr("fe80::1%lo0"); err != nil {
		t.Error(err)
	}
}

func TestLookupIPv6LinkLocalAddrWithZone(t *testing.T) {
	if !supportsIPv6() || !*testIPv6 {
		t.Skip("IPv6 is required")
	}

	ipaddrs, err := DefaultResolver.LookupIPAddr(context.Background(), "fe80::1%lo0")
	if err != nil {
		t.Error(err)
	}
	for _, addr := range ipaddrs {
		if e, a := "lo0", addr.Zone; e != a {
			t.Errorf("wrong zone: want %q, got %q", e, a)
		}
	}

	addrs, err := DefaultResolver.LookupHost(context.Background(), "fe80::1%lo0")
	if err != nil {
		t.Error(err)
	}
	for _, addr := range addrs {
		if e, a := "fe80::1%lo0", addr; e != a {
			t.Errorf("wrong host: want %q got %q", e, a)
		}
	}
}

var lookupCNAMETests = []struct {
	name, cname string
}{
	{"www.iana.org", "icann.org."},
	{"www.iana.org.", "icann.org."},
	{"www.google.com", "google.com."},
	{"google.com", "google.com."},
	{"cname-to-txt.go4.org", "test-txt-record.go4.org."},
}

func TestLookupCNAME(t *testing.T) {
	mustHaveExternalNetwork(t)
	testenv.SkipFlakyNet(t)

	if !supportsIPv4() || !*testIPv4 {
		t.Skip("IPv4 is required")
	}

	defer dnsWaitGroup.Wait()

	attempts := 0
	for i := 0; i < len(lookupCNAMETests); i++ {
		tt := lookupCNAMETests[i]
		cname, err := LookupCNAME(tt.name)
		if err != nil {
			testenv.SkipFlakyNet(t)
			if attempts < len(backoffDuration) {
				dur := backoffDuration[attempts]
				t.Logf("backoff %v after failure %v\n", dur, err)
				time.Sleep(dur)
				attempts++
				i--
				continue
			}
			t.Fatal(err)
		}
		if !hasSuffixFold(cname, tt.cname) {
			t.Errorf("got %s; want a record containing %s", cname, tt.cname)
		}
	}
}

var lookupGoogleHostTests = []struct {
	name string
}{
	{"google.com"},
	{"google.com."},
}

func TestLookupGoogleHost(t *testing.T) {
	mustHaveExternalNetwork(t)
	testenv.SkipFlakyNet(t)

	if !supportsIPv4() || !*testIPv4 {
		t.Skip("IPv4 is required")
	}

	defer dnsWaitGroup.Wait()

	for _, tt := range lookupGoogleHostTests {
		addrs, err := LookupHost(tt.name)
		if err != nil {
			t.Fatal(err)
		}
		if len(addrs) == 0 {
			t.Error("got no record")
		}
		for _, addr := range addrs {
			if ParseIP(addr) == nil {
				t.Errorf("got %q; want a literal IP address", addr)
			}
		}
	}
}

func TestLookupLongTXT(t *testing.T) {
	testenv.SkipFlaky(t, 22857)
	mustHaveExternalNetwork(t)

	defer dnsWaitGroup.Wait()

	txts, err := LookupTXT("golang.rsc.io")
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(txts)
	want := []string{
		strings.Repeat("abcdefghijklmnopqrstuvwxyABCDEFGHJIKLMNOPQRSTUVWXY", 10),
		"gophers rule",
	}
	if !slices.Equal(txts, want) {
		t.Fatalf("LookupTXT golang.rsc.io incorrect\nhave %q\nwant %q", txts, want)
	}
}

var lookupGoogleIPTests = []struct {
	name string
}{
	{"google.com"},
	{"google.com."},
}

func TestLookupGoogleIP(t *testing.T) {
	mustHaveExternalNetwork(t)
	testenv.SkipFlakyNet(t)

	if !supportsIPv4() || !*testIPv4 {
		t.Skip("IPv4 is required")
	}

	defer dnsWaitGroup.Wait()

	for _, tt := range lookupGoogleIPTests {
		ips, err := LookupIP(tt.name)
		if err != nil {
			t.Fatal(err)
		}
		if len(ips) == 0 {
			t.Error("got no record")
		}
		for _, ip := range ips {
			if ip.To4() == nil && ip.To16() == nil {
				t.Errorf("got %v; want an IP address", ip)
			}
		}
	}
}

var revAddrTests = []struct {
	Addr      string
	Reverse   string
	ErrPrefix string
}{
	{"1.2.3.4", "4.3.2.1.in-addr.arpa.", ""},
	{"245.110.36.114", "114.36.110.245.in-addr.arpa.", ""},
	{"::ffff:12.34.56.78", "78.56.34.12.in-addr.arpa.", ""},
	{"::1", "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.", ""},
	{"1::", "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.0.ip6.arpa.", ""},
	{"1234:567::89a:bcde", "e.d.c.b.a.9.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.7.6.5.0.4.3.2.1.ip6.arpa.", ""},
	{"1234:567:fefe:bcbc:adad:9e4a:89a:bcde", "e.d.c.b.a.9.8.0.a.4.e.9.d.a.d.a.c.b.c.b.e.f.e.f.7.6.5.0.4.3.2.1.ip6.arpa.", ""},
	{"1.2.3", "", "unrecognized address"},
	{"1.2.3.4.5", "", "unrecognized address"},
	{"1234:567:bcbca::89a:bcde", "", "unrecognized address"},
	{"1234:567::bcbc:adad::89a:bcde", "", "unrecognized address"},
}

func TestReverseAddress(t *testing.T) {
	defer dnsWaitGroup.Wait()
	for i, tt := range revAddrTests {
		a, err := reverseaddr(tt.Addr)
		if len(tt.ErrPrefix) > 0 && err == nil {
			t.Errorf("#%d: expected %q, got <nil> (error)", i, tt.ErrPrefix)
			continue
		}
		if len(tt.ErrPrefix) == 0 && err != nil {
			t.Errorf("#%d: expected <nil>, got %q (error)", i, err)
		}
		if err != nil && err.(*DNSError).Err != tt.ErrPrefix {
			t.Errorf("#%d: expected %q, got %q (mismatched error)", i, tt.ErrPrefix, err.(*DNSError).Err)
		}
		if a != tt.Reverse {
			t.Errorf("#%d: expected %q, got %q (reverse address)", i, tt.Reverse, a)
		}
	}
}

func TestDNSFlood(t *testing.T) {
	if !*testDNSFlood {
		t.Skip("test disabled; use -dnsflood to enable")
	}

	defer dnsWaitGroup.Wait()

	var N = 5000
	if runtime.GOOS == "darwin" || runtime.GOOS == "ios" {
		// On Darwin this test consumes kernel threads much
		// than other platforms for some reason.
		// When we monitor the number of allocated Ms by
		// observing on runtime.newm calls, we can see that it
		// easily reaches the per process ceiling
		// kern.num_threads when CGO_ENABLED=1 and
		// GODEBUG=netdns=go.
		N = 500
	}

	const timeout = 3 * time.Second
	ctxHalfTimeout, cancel := context.WithTimeout(context.Background(), timeout/2)
	defer cancel()
	ctxTimeout, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	c := make(chan error, 2*N)
	for i := 0; i < N; i++ {
		name := fmt.Sprintf("%d.net-test.golang.org", i)
		go func() {
			_, err := DefaultResolver.LookupIPAddr(ctxHalfTimeout, name)
			c <- err
		}()
		go func() {
			_, err := DefaultResolver.LookupIPAddr(ctxTimeout, name)
			c <- err
		}()
	}
	qstats := struct {
		succeeded, failed         int
		timeout, temporary, other int
		unknown                   int
	}{}
	deadline := time.After(timeout + time.Second)
	for i := 0; i < 2*N; i++ {
		select {
		case <-deadline:
			t.Fatal("deadline exceeded")
		case err := <-c:
			switch err := err.(type) {
			case nil:
				qstats.succeeded++
			case Error:
				qstats.failed++
				if err.Timeout() {
					qstats.timeout++
				}
				if err.Temporary() {
					qstats.temporary++
				}
				if !err.Timeout() && !err.Temporary() {
					qstats.other++
				}
			default:
				qstats.failed++
				qstats.unknown++
			}
		}
	}

	// A high volume of DNS queries for sub-domain of golang.org
	// would be coordinated by authoritative or recursive server,
	// or stub resolver which implements query-response rate
	// limitation, so we can expect some query successes and more
	// failures including timeout, temporary and other here.
	// As a rule, unknown must not be shown but it might possibly
	// happen due to issue 4856 for now.
	t.Logf("%v succeeded, %v failed (%v timeout, %v temporary, %v other, %v unknown)", qstats.succeeded, qstats.failed, qstats.timeout, qstats.temporary, qstats.other, qstats.unknown)
}

func TestLookupDotsWithLocalSource(t *testing.T) {
	if !supportsIPv4() || !*testIPv4 {
		t.Skip("IPv4 is required")
	}

	mustHaveExternalNetwork(t)

	defer dnsWaitGroup.Wait()

	for i, fn := range []func() func(){forceGoDNS, forceCgoDNS} {
		fixup := fn()
		if fixup == nil {
			continue
		}
		names, err := LookupAddr("127.0.0.1")
		fixup()
		if err != nil {
			t.Logf("#%d: %v", i, err)
			continue
		}
		mode := "netgo"
		if i == 1 {
			mode = "netcgo"
		}
	loop:
		for i, name := range names {
			if strings.Index(name, ".") == len(name)-1 { // "localhost" not "localhost."
				for j := range names {
					if j == i {
						continue
					}
					if names[j] == name[:len(name)-1] {
						// It's OK if we find the name without the dot,
						// as some systems say 127.0.0.1 localhost localhost.
						continue loop
					}
				}
				t.Errorf("%s: got %s; want %s", mode, name, name[:len(name)-1])
			} else if strings.Contains(name, ".") && !strings.HasSuffix(name, ".") { // "localhost.localdomain." not "localhost.localdomain"
				t.Errorf("%s: got %s; want name ending with trailing dot", mode, name)
			}
		}
	}
}

func TestLookupDotsWithRemoteSource(t *testing.T) {
	if runtime.GOOS == "darwin" || runtime.GOOS == "ios" {
		testenv.SkipFlaky(t, 27992)
	}
	mustHaveExternalNetwork(t)
	testenv.SkipFlakyNet(t)

	if !supportsIPv4() || !*testIPv4 {
		t.Skip("IPv4 is required")
	}

	if runtime.GOOS == "ios" {
		t.Skip("no resolv.conf on iOS")
	}

	defer dnsWaitGroup.Wait()

	if fixup := forceGoDNS(); fixup != nil {
		testDots(t, "go")
		fixup()
	}
	if fixup := forceCgoDNS(); fixup != nil {
		testDots(t, "cgo")
		fixup()
	}
}

func testDots(t *testing.T, mode string) {
	names, err := LookupAddr("8.8.8.8") // Google dns server
	if err != nil {
		t.Errorf("LookupAddr(8.8.8.8): %v (mode=%v)", err, mode)
	} else {
		for _, name := range names {
			if !hasSuffixFold(name, ".google.com.") && !hasSuffixFold(name, ".google.") {
				t.Errorf("LookupAddr(8.8.8.8) = %v, want names ending in .google.com or .google with trailing dot (mode=%v)", names, mode)
				break
			}
		}
	}

	cname, err := LookupCNAME("www.mit.edu")
	if err != nil {
		t.Errorf("LookupCNAME(www.mit.edu, mode=%v): %v", mode, err)
	} else if !strings.HasSuffix(cname, ".") {
		t.Errorf("LookupCNAME(www.mit.edu) = %v, want cname ending in . with trailing dot (mode=%v)", cname, mode)
	}

	mxs, err := LookupMX("google.com")
	if err != nil {
		t.Errorf("LookupMX(google.com): %v (mode=%v)", err, mode)
	} else {
		for _, mx := range mxs {
			if !hasSuffixFold(mx.Host, ".google.com.") {
				t.Errorf("LookupMX(google.com) = %v, want names ending in .google.com. with trailing dot (mode=%v)", mxString(mxs), mode)
				break
			}
		}
	}

	nss, err := LookupNS("google.com")
	if err != nil {
		t.Errorf("LookupNS(google.com): %v (mode=%v)", err, mode)
	} else {
		for _, ns := range nss {
			if !hasSuffixFold(ns.Host, ".google.com.") {
				t.Errorf("LookupNS(google.com) = %v, want names ending in .google.com. with trailing dot (mode=%v)", nsString(nss), mode)
				break
			}
		}
	}

	cname, srvs, err := LookupSRV("ldap", "tcp", "google.com")
	if err != nil {
		t.Errorf("LookupSRV(ldap, tcp, google.com): %v (mode=%v)", err, mode)
	} else {
		if !hasSuffixFold(cname, ".google.com.") {
			t.Errorf("LookupSRV(ldap, tcp, google.com) returned cname=%v, want name ending in .google.com. with trailing dot (mode=%v)", cname, mode)
		}
		for _, srv := range srvs {
			if !hasSuffixFold(srv.Target, ".google.com.") {
				t.Errorf("LookupSRV(ldap, tcp, google.com) returned addrs=%v, want names ending in .google.com. with trailing dot (mode=%v)", srvString(srvs), mode)
				break
			}
		}
	}
}

func mxString(mxs []*MX) string {
	var buf strings.Builder
	sep := ""
	fmt.Fprintf(&buf, "[")
	for _, mx := range mxs {
		fmt.Fprintf(&buf, "%s%s:%d", sep, mx.Host, mx.Pref)
		sep = " "
	}
	fmt.Fprintf(&buf, "]")
	return buf.String()
}

func nsString(nss []*NS) string {
	var buf strings.Builder
	sep := ""
	fmt.Fprintf(&buf, "[")
	for _, ns := range nss {
		fmt.Fprintf(&buf, "%s%s", sep, ns.Host)
		sep = " "
	}
	fmt.Fprintf(&buf, "]")
	return buf.String()
}

func srvString(srvs []*SRV) string {
	var buf strings.Builder
	sep := ""
	fmt.Fprintf(&buf, "[")
	for _, srv := range srvs {
		fmt.Fprintf(&buf, "%s%s:%d:%d:%d", sep, srv.Target, srv.Port, srv.Priority, srv.Weight)
		sep = " "
	}
	fmt.Fprintf(&buf, "]")
	return buf.String()
}

func TestLookupPort(t *testing.T) {
	// See https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml
	//
	// Please be careful about adding new test cases.
	// There are platforms which have incomplete mappings for
	// restricted resource access and security reasons.
	type test struct {
		network string
		name    string
		port    int
		ok      bool
	}
	var tests = []test{
		{"tcp", "0", 0, true},
		{"udp", "0", 0, true},
		{"udp", "domain", 53, true},

		{"--badnet--", "zzz", 0, false},
		{"tcp", "--badport--", 0, false},
		{"tcp", "-1", 0, false},
		{"tcp", "65536", 0, false},
		{"udp", "-1", 0, false},
		{"udp", "65536", 0, false},
		{"tcp", "123456789", 0, false},

		// Issue 13610: LookupPort("tcp", "")
		{"tcp", "", 0, true},
		{"tcp4", "", 0, true},
		{"tcp6", "", 0, true},
		{"udp", "", 0, true},
		{"udp4", "", 0, true},
		{"udp6", "", 0, true},
	}

	switch runtime.GOOS {
	case "android":
		if netGoBuildTag {
			t.Skipf("not supported on %s without cgo; see golang.org/issues/14576", runtime.GOOS)
		}
	default:
		tests = append(tests, test{"tcp", "http", 80, true})
	}

	for _, tt := range tests {
		port, err := LookupPort(tt.network, tt.name)
		if port != tt.port || (err == nil) != tt.ok {
			t.Errorf("LookupPort(%q, %q) = %d, %v; want %d, error=%t", tt.network, tt.name, port, err, tt.port, !tt.ok)
		}
		if err != nil {
			if perr := parseLookupPortError(err); perr != nil {
				t.Error(perr)
			}
		}
	}
}

// Like TestLookupPort but with minimal tests that should always pass
// because the answers are baked-in to the net package.
func TestLookupPort_Minimal(t *testing.T) {
	type test struct {
		network string
		name    string
		port    int
	}
	var tests = []test{
		{"tcp", "http", 80},
		{"tcp", "HTTP", 80}, // case shouldn't matter
		{"tcp", "https", 443},
		{"tcp", "ssh", 22},
		{"tcp", "gopher", 70},
		{"tcp4", "http", 80},
		{"tcp6", "http", 80},
	}

	for _, tt := range tests {
		port, err := LookupPort(tt.network, tt.name)
		if port != tt.port || err != nil {
			t.Errorf("LookupPort(%q, %q) = %d, %v; want %d, error=nil", tt.network, tt.name, port, err, tt.port)
		}
	}
}

func TestLookupProtocol_Minimal(t *testing.T) {
	type test struct {
		name string
		want int
	}
	var tests = []test{
		{"tcp", 6},
		{"TcP", 6}, // case shouldn't matter
		{"icmp", 1},
		{"igmp", 2},
		{"udp", 17},
		{"ipv6-icmp", 58},
	}

	for _, tt := range tests {
		got, err := lookupProtocol(context.Background(), tt.name)
		if got != tt.want || err != nil {
			t.Errorf("LookupProtocol(%q) = %d, %v; want %d, error=nil", tt.name, got, err, tt.want)
		}
	}

}

func TestLookupNonLDH(t *testing.T) {
	defer dnsWaitGroup.Wait()

	if fixup := forceGoDNS(); fixup != nil {
		defer fixup()
	}

	// "LDH" stands for letters, digits, and hyphens and is the usual
	// description of standard DNS names.
	// This test is checking that other kinds of names are reported
	// as not found, not reported as invalid names.
	addrs, err := LookupHost("!!!.###.bogus..domain.")
	if err == nil {
		t.Fatalf("lookup succeeded: %v", addrs)
	}
	if !strings.HasSuffix(err.Error(), errNoSuchHost.Error()) {
		t.Fatalf("lookup error = %v, want %v", err, errNoSuchHost)
	}
	if !err.(*DNSError).IsNotFound {
		t.Fatalf("lookup error = %v, want true", err.(*DNSError).IsNotFound)
	}
}

func TestLookupContextCancel(t *testing.T) {
	mustHaveExternalNetwork(t)
	testenv.SkipFlakyNet(t)

	origTestHookLookupIP := testHookLookupIP
	defer func() {
		dnsWaitGroup.Wait()
		testHookLookupIP = origTestHookLookupIP
	}()

	lookupCtx, cancelLookup := context.WithCancel(context.Background())
	unblockLookup := make(chan struct{})

	// Set testHookLookupIP to start a new, concurrent call to LookupIPAddr
	// and cancel the original one, then block until the canceled call has returned
	// (ensuring that it has performed any synchronous cleanup).
	testHookLookupIP = func(
		ctx context.Context,
		fn func(context.Context, string, string) ([]IPAddr, error),
		network string,
		host string,
	) ([]IPAddr, error) {
		select {
		case <-unblockLookup:
		default:
			// Start a concurrent LookupIPAddr for the same host while the caller is
			// still blocked, and sleep a little to give it time to be deduplicated
			// before we cancel (and unblock) the caller.
			// (If the timing doesn't quite work out, we'll end up testing sequential
			// calls instead of concurrent ones, but the test should still pass.)
			t.Logf("starting concurrent LookupIPAddr")
			dnsWaitGroup.Add(1)
			go func() {
				defer dnsWaitGroup.Done()
				_, err := DefaultResolver.LookupIPAddr(context.Background(), host)
				if err != nil {
					t.Error(err)
				}
			}()
			time.Sleep(1 * time.Millisecond)
		}

		cancelLookup()
		<-unblockLookup
		// If the concurrent lookup above is deduplicated to this one
		// (as we expect to happen most of the time), it is important
		// that the original call does not cancel the shared Context.
		// (See https://go.dev/issue/22724.) Explicitly check for
		// cancellation now, just in case fn itself doesn't notice it.
		if err := ctx.Err(); err != nil {
			t.Logf("testHookLookupIP canceled")
			return nil, err
		}
		t.Logf("testHookLookupIP performing lookup")
		return fn(ctx, network, host)
	}

	_, err := DefaultResolver.LookupIPAddr(lookupCtx, "google.com")
	if dnsErr, ok := err.(*DNSError); !ok || dnsErr.Err != errCanceled.Error() {
		t.Errorf("unexpected error from canceled, blocked LookupIPAddr: %v", err)
	}
	close(unblockLookup)
}

// Issue 24330: treat the nil *Resolver like a zero value. Verify nothing
// crashes if nil is used.
func TestNilResolverLookup(t *testing.T) {
	mustHaveExternalNetwork(t)
	var r *Resolver = nil
	ctx := context.Background()

	// Don't care about the results, just that nothing panics:
	r.LookupAddr(ctx, "8.8.8.8")
	r.LookupCNAME(ctx, "google.com")
	r.LookupHost(ctx, "google.com")
	r.LookupIPAddr(ctx, "google.com")
	r.LookupIP(ctx, "ip", "google.com")
	r.LookupMX(ctx, "gmail.com")
	r.LookupNS(ctx, "google.com")
	r.LookupPort(ctx, "tcp", "smtp")
	r.LookupSRV(ctx, "service", "proto", "name")
	r.LookupTXT(ctx, "gmail.com")
}

// TestLookupHostCancel verifies that lookup works even after many
// canceled lookups (see golang.org/issue/24178 for details).
func TestLookupHostCancel(t *testing.T) {
	mustHaveExternalNetwork(t)
	testenv.SkipFlakyNet(t)
	t.Parallel() // Executes 600ms worth of sequential sleeps.

	const (
		google        = "www.google.com"
		invalidDomain = "invalid.invalid" // RFC 2606 reserves .invalid
		n             = 600               // this needs to be larger than threadLimit size
	)

	_, err := LookupHost(google)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for i := 0; i < n; i++ {
		addr, err := DefaultResolver.LookupHost(ctx, invalidDomain)
		if err == nil {
			t.Fatalf("LookupHost(%q): returns %v, but should fail", invalidDomain, addr)
		}

		// Don't verify what the actual error is.
		// We know that it must be non-nil because the domain is invalid,
		// but we don't have any guarantee that LookupHost actually bothers
		// to check for cancellation on the fast path.
		// (For example, it could use a local cache to avoid blocking entirely.)

		// The lookup may deduplicate in-flight requests, so give it time to settle
		// in between.
		time.Sleep(time.Millisecond * 1)
	}

	_, err = LookupHost(google)
	if err != nil {
		t.Fatal(err)
	}
}

type lookupCustomResolver struct {
	*Resolver
	mu     sync.RWMutex
	dialed bool
}

func (lcr *lookupCustomResolver) dial() func(ctx context.Context, network, address string) (Conn, error) {
	return func(ctx context.Context, network, address string) (Conn, error) {
		lcr.mu.Lock()
		lcr.dialed = true
		lcr.mu.Unlock()
		return Dial(network, address)
	}
}

// TestConcurrentPreferGoResolversDial tests that multiple resolvers with the
// PreferGo option used concurrently are all dialed properly.
func TestConcurrentPreferGoResolversDial(t *testing.T) {
	switch runtime.GOOS {
	case "plan9":
		// TODO: plan9 implementation of the resolver uses the Dial function since
		// https://go.dev/cl/409234, this test could probably be reenabled.
		t.Skipf("skip on %v", runtime.GOOS)
	}

	testenv.MustHaveExternalNetwork(t)
	testenv.SkipFlakyNet(t)

	defer dnsWaitGroup.Wait()

	resolvers := make([]*lookupCustomResolver, 2)
	for i := range resolvers {
		cs := lookupCustomResolver{Resolver: &Resolver{PreferGo: true}}
		cs.Dial = cs.dial()
		resolvers[i] = &cs
	}

	var wg sync.WaitGroup
	wg.Add(len(resolvers))
	for i, resolver := range resolvers {
		go func(r *Resolver, index int) {
			defer wg.Done()
			_, err := r.LookupIPAddr(context.Background(), "google.com")
			if err != nil {
				t.Errorf("lookup failed for resolver %d: %q", index, err)
			}
		}(resolver.Resolver, i)
	}
	wg.Wait()

	if t.Failed() {
		t.FailNow()
	}

	for i, resolver := range resolvers {
		if !resolver.dialed {
			t.Errorf("custom resolver %d not dialed during lookup", i)
		}
	}
}

var ipVersionTests = []struct {
	network string
	version byte
}{
	{"tcp", 0},
	{"tcp4", '4'},
	{"tcp6", '6'},
	{"udp", 0},
	{"udp4", '4'},
	{"udp6", '6'},
	{"ip", 0},
	{"ip4", '4'},
	{"ip6", '6'},
	{"ip7", 0},
	{"", 0},
}

func TestIPVersion(t *testing.T) {
	for _, tt := range ipVersionTests {
		if version := ipVersion(tt.network); version != tt.version {
			t.Errorf("Family for: %s. Expected: %s, Got: %s", tt.network,
				string(tt.version), string(version))
		}
	}
}

// Issue 28600: The context that is used to lookup ips should always
// preserve the values from the context that was passed into LookupIPAddr.
func TestLookupIPAddrPreservesContextValues(t *testing.T) {
	origTestHookLookupIP := testHookLookupIP
	defer func() { testHookLookupIP = origTestHookLookupIP }()

	keyValues := []struct {
		key, value any
	}{
		{"key-1", 12},
		{384, "value2"},
		{new(float64), 137},
	}
	ctx := context.Background()
	for _, kv := range keyValues {
		ctx = context.WithValue(ctx, kv.key, kv.value)
	}

	wantIPs := []IPAddr{
		{IP: IPv4(127, 0, 0, 1)},
		{IP: IPv6loopback},
	}

	checkCtxValues := func(ctx_ context.Context, fn func(context.Context, string, string) ([]IPAddr, error), network, host string) ([]IPAddr, error) {
		for _, kv := range keyValues {
			g, w := ctx_.Value(kv.key), kv.value
			if !reflect.DeepEqual(g, w) {
				t.Errorf("Value lookup:\n\tGot:  %v\n\tWant: %v", g, w)
			}
		}
		return wantIPs, nil
	}
	testHookLookupIP = checkCtxValues

	resolvers := []*Resolver{
		nil,
		new(Resolver),
	}

	for i, resolver := range resolvers {
		gotIPs, err := resolver.LookupIPAddr(ctx, "golang.org")
		if err != nil {
			t.Errorf("Resolver #%d: unexpected error: %v", i, err)
		}
		if !reflect.DeepEqual(gotIPs, wantIPs) {
			t.Errorf("#%d: mismatched IPAddr results\n\tGot: %v\n\tWant: %v", i, gotIPs, wantIPs)
		}
	}
}

// Issue 30521: The lookup group should call the resolver for each network.
func TestLookupIPAddrConcurrentCallsForNetworks(t *testing.T) {
	origTestHookLookupIP := testHookLookupIP
	defer func() { testHookLookupIP = origTestHookLookupIP }()

	queries := [][]string{
		{"udp", "golang.org"},
		{"udp4", "golang.org"},
		{"udp6", "golang.org"},
		{"udp", "golang.org"},
		{"udp", "golang.org"},
	}
	results := map[[2]string][]IPAddr{
		{"udp", "golang.org"}: {
			{IP: IPv4(127, 0, 0, 1)},
			{IP: IPv6loopback},
		},
		{"udp4", "golang.org"}: {
			{IP: IPv4(127, 0, 0, 1)},
		},
		{"udp6", "golang.org"}: {
			{IP: IPv6loopback},
		},
	}
	calls := int32(0)
	waitCh := make(chan struct{})
	testHookLookupIP = func(ctx context.Context, fn func(context.Context, string, string) ([]IPAddr, error), network, host string) ([]IPAddr, error) {
		// We'll block until this is called one time for each different
		// expected result. This will ensure that the lookup group would wait
		// for the existing call if it was to be reused.
		if atomic.AddInt32(&calls, 1) == int32(len(results)) {
			close(waitCh)
		}
		select {
		case <-waitCh:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return results[[2]string{network, host}], nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	wg := sync.WaitGroup{}
	for _, q := range queries {
		network := q[0]
		host := q[1]
		wg.Add(1)
		go func() {
			defer wg.Done()
			gotIPs, err := DefaultResolver.lookupIPAddr(ctx, network, host)
			if err != nil {
				t.Errorf("lookupIPAddr(%v, %v): unexpected error: %v", network, host, err)
			}
			wantIPs := results[[2]string{network, host}]
			if !reflect.DeepEqual(gotIPs, wantIPs) {
				t.Errorf("lookupIPAddr(%v, %v): mismatched IPAddr results\n\tGot: %v\n\tWant: %v", network, host, gotIPs, wantIPs)
			}
		}()
	}
	wg.Wait()
}

// Issue 53995: Resolver.LookupIP should return error for empty host name.
func TestResolverLookupIPWithEmptyHost(t *testing.T) {
	_, err := DefaultResolver.LookupIP(context.Background(), "ip", "")
	if err == nil {
		t.Fatal("DefaultResolver.LookupIP for empty host success, want no host error")
	}
	if !strings.HasSuffix(err.Error(), errNoSuchHost.Error()) {
		t.Fatalf("lookup error = %v, want %v", err, errNoSuchHost)
	}
}

func TestWithUnexpiredValuesPreserved(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	// Insert a value into it.
	key, value := "key-1", 2
	ctx = context.WithValue(ctx, key, value)

	// Now use the "values preserving context" like
	// we would for LookupIPAddr. See Issue 28600.
	ctx = withUnexpiredValuesPreserved(ctx)

	// Lookup before expiry.
	if g, w := ctx.Value(key), value; g != w {
		t.Errorf("Lookup before expiry: Got %v Want %v", g, w)
	}

	// Cancel the context.
	cancel()

	// Lookup after expiry should return nil
	if g := ctx.Value(key); g != nil {
		t.Errorf("Lookup after expiry: Got %v want nil", g)
	}
}

// Issue 31597: don't panic on null byte in name
func TestLookupNullByte(t *testing.T) {
	testenv.MustHaveExternalNetwork(t)
	testenv.SkipFlakyNet(t)
	LookupHost("foo\x00bar") // check that it doesn't panic; it used to on Windows
}

func TestResolverLookupIP(t *testing.T) {
	testenv.MustHaveExternalNetwork(t)

	v4Ok := supportsIPv4() && *testIPv4
	v6Ok := supportsIPv6() && *testIPv6

	defer dnsWaitGroup.Wait()

	for _, impl := range []struct {
		name string
		fn   func() func()
	}{
		{"go", forceGoDNS},
		{"cgo", forceCgoDNS},
	} {
		t.Run("implementation: "+impl.name, func(t *testing.T) {
			fixup := impl.fn()
			if fixup == nil {
				t.Skip("not supported")
			}
			defer fixup()

			for _, network := range []string{"ip", "ip4", "ip6"} {
				t.Run("network: "+network, func(t *testing.T) {
					switch {
					case network == "ip4" && !v4Ok:
						t.Skip("IPv4 is not supported")
					
"""




```