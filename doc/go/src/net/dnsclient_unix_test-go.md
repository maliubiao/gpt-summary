Response:
My goal is to understand the functionality of the provided Go code snippet, explain it in Chinese, and potentially illustrate its usage with examples. Here's my thinking process:

1. **Initial Scan for Keywords and Purpose:** I first scanned the code for keywords like `test`, `dns`, `resolve`, `fallback`, `specialDomainName`, `avoidDNS`, `resolvConf`, `lookupIP`, `timeout`, `rotate`, `StrictErrors`, etc. This gives me a high-level understanding that the code is related to testing DNS client functionality in a Unix environment. The file name `dnsclient_unix_test.go` reinforces this.

2. **Identifying Key Test Functions:** I then looked for functions starting with `Test`. These are the main test cases that reveal the code's purpose. I identified several important test functions:
    * `TestDNSTransportFallback`: This suggests testing how the DNS client falls back between UDP and TCP.
    * `TestDNSTransportNoFallbackOnTCP`: This likely tests scenarios where fallback to UDP is prevented when TCP is already used.
    * `TestSpecialDomainName`:  Indicates testing how the client handles special domain names (like `localhost`, `invalid`).
    * `TestAvoidDNSName`: Focuses on preventing DNS lookups for certain names (like `.onion`).
    * `TestLookupTorOnion`: A specific test for `.onion` domains.
    * `TestUpdateResolvConf`: Tests how the client reacts to changes in the `resolv.conf` file.
    * `TestGoLookupIPWithResolverConfig`:  Tests `LookupIPAddr` with different `resolv.conf` configurations.
    * `TestGoLookupIPOrderFallbackToFile`: Tests fallback to the `/etc/hosts` file.
    * `TestErrorForOriginalNameWhenSearching`: Tests error handling during DNS search domain resolution.
    * `TestIgnoreLameReferrals`: Tests the client's behavior when encountering "lame" DNS referrals.
    * `TestRetryTimeout`: Tests how the client retries after timeouts.
    * `TestRotate`:  Tests the `rotate` option in `resolv.conf`.
    * `TestStrictErrorsLookupIP`: Tests the `StrictErrors` resolver option.
    * `TestIgnoreDNSForgeries`: Tests handling of invalid DNS responses.

3. **Analyzing Test Structures:** I examined the structure of the test functions. Most of them follow a pattern:
    * **Setup:**  Often involves creating a `fakeDNSServer` to simulate DNS responses. Some tests also manipulate `resolv.conf` using `newResolvConfTest`.
    * **Execution:** Calls functions from the `net` package (like `r.exchange`, `r.LookupIPAddr`, `r.LookupIP`).
    * **Assertions:** Uses `t.Error`, `t.Errorf`, `t.Fatalf` to check if the actual behavior matches the expected behavior.

4. **Understanding `fakeDNSServer`:** The `fakeDNSServer` struct is crucial. It allows the tests to control the DNS responses, simulating various scenarios (successful responses, timeouts, errors, etc.). The `rh` field (response handler function) defines how the fake server reacts to different queries.

5. **Inferring Functionality:** Based on the test names and the behavior of the `fakeDNSServer`, I could infer the functionality being tested:
    * **Transport Fallback:** The code checks if the client automatically switches from UDP to TCP when a UDP response is truncated.
    * **Special Domain Name Handling:**  The tests verify that the client doesn't send DNS queries for special domain names.
    * **`.onion` Domain Handling:** The tests ensure that `.onion` domains are not resolved via DNS.
    * **`resolv.conf` Parsing and Updates:** The tests check if the client correctly parses `resolv.conf` and updates its DNS server list when the file changes.
    * **Error Handling:** The tests cover different DNS error scenarios (NXDOMAIN, timeouts, server failures) and how the client reports them.
    * **Search Domains:** The code tests how the client uses search domains defined in `resolv.conf`.
    * **Lame Referrals:**  The tests verify that the client ignores lame referral responses and tries other servers.
    * **Timeouts and Retries:** The tests ensure that the client retries queries with increasing timeouts.
    * **`rotate` Option:** The tests check if the client rotates through the configured DNS servers when the `rotate` option is set in `resolv.conf`.
    * **`StrictErrors` Option:** The tests verify that the `StrictErrors` option prevents returning partial results when temporary errors occur.
    * **Handling Invalid Responses:** The tests check that the client ignores malformed DNS responses.

6. **Identifying Go Language Features:**  I recognized the following Go features in use:
    * **Testing (`testing` package):** The code uses the `testing` package for writing unit tests.
    * **Context (`context` package):**  Contexts are used for managing timeouts and cancellations.
    * **Error Handling (`error` interface):** The code uses the standard Go error handling mechanism.
    * **Concurrency (`sync` and `sync/atomic` packages):**  Synchronization primitives are used for managing concurrent operations, especially around `resolv.conf` updates.
    * **Time (`time` package):** Timeouts and delays are handled using the `time` package.
    * **DNS Message Parsing (`golang.org/x/net/dns/dnsmessage`):** The code uses this package to construct and parse DNS messages.
    * **File System Operations (`os` package):**  Used for creating temporary directories and files for `resolv.conf` testing.

7. **Formulating the Summary in Chinese:**  Finally, I synthesized my understanding into a concise summary in Chinese, focusing on the core functionality of the tested code. I avoided going into too much detail in the summary, as the later parts of the prompt ask for more specific explanations.

This systematic approach allowed me to break down the code, understand its purpose, and generate the requested summary. The key was to focus on the test cases and the simulated DNS server behavior.
这是对 Go 语言标准库 `net` 包中与 DNS 客户端相关的、在 Unix 系统上的特定功能进行测试的代码。主要涵盖了以下功能点的测试：

**功能归纳:**

这段代码主要测试了 Go 语言在 Unix 系统下进行 DNS 查询时的一些特定行为和配置处理，包括：

1. **DNS 传输协议回退 (Fallback)：**  测试当使用 UDP 查询 DNS 服务器时，如果响应被截断 (Truncated)，客户端是否能正确地回退到 TCP 进行重试。
2. **禁用 TCP 上的回退：** 测试当已经使用 TCP 进行 DNS 查询时，即使收到截断的响应，客户端也不会再尝试 UDP。
3. **特殊域名处理：** 测试 Go 语言如何处理 RFC 6761 中定义的特殊域名 (如 `localhost`, `invalid`)，确保不会向 DNS 服务器发送这些查询。
4. **避免对特定名称进行 DNS 查询：** 测试 Go 语言如何避免对某些特定的域名 (如 `.onion`) 进行 DNS 查询。
5. **`resolv.conf` 文件解析和更新：** 测试 Go 语言如何读取和解析 `/etc/resolv.conf` 文件中的 DNS 服务器配置，以及当文件内容发生变化时如何更新配置。
6. **使用 `resolv.conf` 进行 IP 地址查找：** 测试在指定 `resolv.conf` 配置的情况下，`LookupIPAddr` 函数的行为，包括超时、域名不存在等情况。
7. **DNS 查询顺序回退到 hosts 文件：** 测试当 DNS 服务器不可用时，`LookupIPAddr` 是否会回退到读取 `/etc/hosts` 文件来解析主机名。
8. **搜索域名的错误处理：** 测试当配置了搜索域名时，如果查询原始域名失败，是否会返回原始域名的错误，而不是搜索后生成的域名的错误。
9. **忽略错误的 DNS 引用 (Lame Referrals)：** 测试当 DNS 服务器返回错误的引用信息时，客户端是否会忽略并尝试下一个配置的 DNS 服务器。
10. **处理 DNS 查询超时：** 测试当 DNS 查询超时时，客户端是否会重试下一个配置的 DNS 服务器。
11. **DNS 服务器轮询 (Rotate)：** 测试 `resolv.conf` 中 `options rotate` 的配置，即是否会轮流使用配置的 DNS 服务器。
12. **严格错误模式 (Strict Errors)：** 测试当启用严格错误模式时，如果 DNS 查询过程中遇到临时错误，`LookupIP` 是否会返回错误，而不是返回部分结果。
13. **忽略伪造的 DNS 响应：** 测试客户端是否能识别并忽略具有错误 ID 或其他不一致性的 DNS 响应。

简单来说，这段代码是用来确保 Go 语言在 Unix 系统下能够正确、健壮地进行 DNS 客户端操作，并能正确处理各种网络状况和 DNS 服务器的响应。

### 提示词
```
这是路径为go/src/net/dnsclient_unix_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```go
// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build unix

package net

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Test address from 192.0.2.0/24 block, reserved by RFC 5737 for documentation.
var TestAddr = [4]byte{0xc0, 0x00, 0x02, 0x01}

// Test address from 2001:db8::/32 block, reserved by RFC 3849 for documentation.
var TestAddr6 = [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}

func mustNewName(name string) dnsmessage.Name {
	nn, err := dnsmessage.NewName(name)
	if err != nil {
		panic(fmt.Sprint("creating name: ", err))
	}
	return nn
}

func mustQuestion(name string, qtype dnsmessage.Type, class dnsmessage.Class) dnsmessage.Question {
	return dnsmessage.Question{
		Name:  mustNewName(name),
		Type:  qtype,
		Class: class,
	}
}

var dnsTransportFallbackTests = []struct {
	server   string
	question dnsmessage.Question
	timeout  int
	rcode    dnsmessage.RCode
}{
	// Querying "com." with qtype=255 usually makes an answer
	// which requires more than 512 bytes.
	{"8.8.8.8:53", mustQuestion("com.", dnsmessage.TypeALL, dnsmessage.ClassINET), 2, dnsmessage.RCodeSuccess},
	{"8.8.4.4:53", mustQuestion("com.", dnsmessage.TypeALL, dnsmessage.ClassINET), 4, dnsmessage.RCodeSuccess},
}

func TestDNSTransportFallback(t *testing.T) {
	fake := fakeDNSServer{
		rh: func(n, _ string, q dnsmessage.Message, _ time.Time) (dnsmessage.Message, error) {
			r := dnsmessage.Message{
				Header: dnsmessage.Header{
					ID:       q.Header.ID,
					Response: true,
					RCode:    dnsmessage.RCodeSuccess,
				},
				Questions: q.Questions,
			}
			if n == "udp" {
				r.Header.Truncated = true
			}
			return r, nil
		},
	}
	r := Resolver{PreferGo: true, Dial: fake.DialContext}
	for _, tt := range dnsTransportFallbackTests {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		_, h, err := r.exchange(ctx, tt.server, tt.question, time.Second, useUDPOrTCP, false)
		if err != nil {
			t.Error(err)
			continue
		}
		if h.RCode != tt.rcode {
			t.Errorf("got %v from %v; want %v", h.RCode, tt.server, tt.rcode)
			continue
		}
	}
}

func TestDNSTransportNoFallbackOnTCP(t *testing.T) {
	fake := fakeDNSServer{
		rh: func(n, _ string, q dnsmessage.Message, _ time.Time) (dnsmessage.Message, error) {
			r := dnsmessage.Message{
				Header: dnsmessage.Header{
					ID:        q.Header.ID,
					Response:  true,
					RCode:     dnsmessage.RCodeSuccess,
					Truncated: true,
				},
				Questions: q.Questions,
			}
			if n == "tcp" {
				r.Answers = []dnsmessage.Resource{
					{
						Header: dnsmessage.ResourceHeader{
							Name:   q.Questions[0].Name,
							Type:   dnsmessage.TypeA,
							Class:  dnsmessage.ClassINET,
							Length: 4,
						},
						Body: &dnsmessage.AResource{
							A: TestAddr,
						},
					},
				}
			}
			return r, nil
		},
	}
	r := Resolver{PreferGo: true, Dial: fake.DialContext}
	for _, tt := range dnsTransportFallbackTests {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		p, h, err := r.exchange(ctx, tt.server, tt.question, time.Second, useUDPOrTCP, false)
		if err != nil {
			t.Error(err)
			continue
		}
		if h.RCode != tt.rcode {
			t.Errorf("got %v from %v; want %v", h.RCode, tt.server, tt.rcode)
			continue
		}
		a, err := p.AllAnswers()
		if err != nil {
			t.Errorf("unexpected error %v getting all answers from %v", err, tt.server)
			continue
		}
		if len(a) != 1 {
			t.Errorf("got %d answers from %v; want 1", len(a), tt.server)
			continue
		}
	}
}

// See RFC 6761 for further information about the reserved, pseudo
// domain names.
var specialDomainNameTests = []struct {
	question dnsmessage.Question
	rcode    dnsmessage.RCode
}{
	// Name resolution APIs and libraries should not recognize the
	// followings as special.
	{mustQuestion("1.0.168.192.in-addr.arpa.", dnsmessage.TypePTR, dnsmessage.ClassINET), dnsmessage.RCodeNameError},
	{mustQuestion("test.", dnsmessage.TypeALL, dnsmessage.ClassINET), dnsmessage.RCodeNameError},
	{mustQuestion("example.com.", dnsmessage.TypeALL, dnsmessage.ClassINET), dnsmessage.RCodeSuccess},

	// Name resolution APIs and libraries should recognize the
	// followings as special and should not send any queries.
	// Though, we test those names here for verifying negative
	// answers at DNS query-response interaction level.
	{mustQuestion("localhost.", dnsmessage.TypeALL, dnsmessage.ClassINET), dnsmessage.RCodeNameError},
	{mustQuestion("invalid.", dnsmessage.TypeALL, dnsmessage.ClassINET), dnsmessage.RCodeNameError},
}

func TestSpecialDomainName(t *testing.T) {
	fake := fakeDNSServer{rh: func(_, _ string, q dnsmessage.Message, _ time.Time) (dnsmessage.Message, error) {
		r := dnsmessage.Message{
			Header: dnsmessage.Header{
				ID:       q.ID,
				Response: true,
			},
			Questions: q.Questions,
		}

		switch q.Questions[0].Name.String() {
		case "example.com.":
			r.Header.RCode = dnsmessage.RCodeSuccess
		default:
			r.Header.RCode = dnsmessage.RCodeNameError
		}

		return r, nil
	}}
	r := Resolver{PreferGo: true, Dial: fake.DialContext}
	server := "8.8.8.8:53"
	for _, tt := range specialDomainNameTests {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		_, h, err := r.exchange(ctx, server, tt.question, 3*time.Second, useUDPOrTCP, false)
		if err != nil {
			t.Error(err)
			continue
		}
		if h.RCode != tt.rcode {
			t.Errorf("got %v from %v; want %v", h.RCode, server, tt.rcode)
			continue
		}
	}
}

// Issue 13705: don't try to resolve onion addresses, etc
func TestAvoidDNSName(t *testing.T) {
	tests := []struct {
		name  string
		avoid bool
	}{
		{"foo.com", false},
		{"foo.com.", false},

		{"foo.onion.", true},
		{"foo.onion", true},
		{"foo.ONION", true},
		{"foo.ONION.", true},

		// But do resolve *.local address; Issue 16739
		{"foo.local.", false},
		{"foo.local", false},
		{"foo.LOCAL", false},
		{"foo.LOCAL.", false},

		{"", true}, // will be rejected earlier too

		// Without stuff before onion/local, they're fine to
		// use DNS. With a search path,
		// "onion.vegetables.com" can use DNS. Without a
		// search path (or with a trailing dot), the queries
		// are just kinda useless, but don't reveal anything
		// private.
		{"local", false},
		{"onion", false},
		{"local.", false},
		{"onion.", false},
	}
	for _, tt := range tests {
		got := avoidDNS(tt.name)
		if got != tt.avoid {
			t.Errorf("avoidDNS(%q) = %v; want %v", tt.name, got, tt.avoid)
		}
	}
}

func TestNameListAvoidDNS(t *testing.T) {
	c := &dnsConfig{search: []string{"go.dev.", "onion."}}
	got := c.nameList("www")
	if !slices.Equal(got, []string{"www.", "www.go.dev."}) {
		t.Fatalf(`nameList("www") = %v, want "www.", "www.go.dev."`, got)
	}

	got = c.nameList("www.onion")
	if !slices.Equal(got, []string{"www.onion.go.dev."}) {
		t.Fatalf(`nameList("www.onion") = %v, want "www.onion.go.dev."`, got)
	}
}

var fakeDNSServerSuccessful = fakeDNSServer{rh: func(_, _ string, q dnsmessage.Message, _ time.Time) (dnsmessage.Message, error) {
	r := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:       q.ID,
			Response: true,
		},
		Questions: q.Questions,
	}
	if len(q.Questions) == 1 && q.Questions[0].Type == dnsmessage.TypeA {
		r.Answers = []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{
					Name:   q.Questions[0].Name,
					Type:   dnsmessage.TypeA,
					Class:  dnsmessage.ClassINET,
					Length: 4,
				},
				Body: &dnsmessage.AResource{
					A: TestAddr,
				},
			},
		}
	}
	return r, nil
}}

// Issue 13705: don't try to resolve onion addresses, etc
func TestLookupTorOnion(t *testing.T) {
	defer dnsWaitGroup.Wait()
	r := Resolver{PreferGo: true, Dial: fakeDNSServerSuccessful.DialContext}
	addrs, err := r.LookupIPAddr(context.Background(), "foo.onion.")
	if err != nil {
		t.Fatalf("lookup = %v; want nil", err)
	}
	if len(addrs) > 0 {
		t.Errorf("unexpected addresses: %v", addrs)
	}
}

type resolvConfTest struct {
	dir  string
	path string
	*resolverConfig
}

func newResolvConfTest() (*resolvConfTest, error) {
	dir, err := os.MkdirTemp("", "go-resolvconftest")
	if err != nil {
		return nil, err
	}
	conf := &resolvConfTest{
		dir:            dir,
		path:           path.Join(dir, "resolv.conf"),
		resolverConfig: &resolvConf,
	}
	conf.initOnce.Do(conf.init)
	return conf, nil
}

func (conf *resolvConfTest) write(lines []string) error {
	f, err := os.OpenFile(conf.path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(strings.Join(lines, "\n")); err != nil {
		f.Close()
		return err
	}
	f.Close()
	return nil
}

func (conf *resolvConfTest) writeAndUpdate(lines []string) error {
	return conf.writeAndUpdateWithLastCheckedTime(lines, time.Now().Add(time.Hour))
}

func (conf *resolvConfTest) writeAndUpdateWithLastCheckedTime(lines []string, lastChecked time.Time) error {
	if err := conf.write(lines); err != nil {
		return err
	}
	return conf.forceUpdate(conf.path, lastChecked)
}

func (conf *resolvConfTest) forceUpdate(name string, lastChecked time.Time) error {
	dnsConf := dnsReadConfig(name)
	if !conf.forceUpdateConf(dnsConf, lastChecked) {
		return fmt.Errorf("tryAcquireSema for %s failed", name)
	}
	return nil
}

func (conf *resolvConfTest) forceUpdateConf(c *dnsConfig, lastChecked time.Time) bool {
	conf.dnsConfig.Store(c)
	for i := 0; i < 5; i++ {
		if conf.tryAcquireSema() {
			conf.lastChecked = lastChecked
			conf.releaseSema()
			return true
		}
	}
	return false
}

func (conf *resolvConfTest) servers() []string {
	return conf.dnsConfig.Load().servers
}

func (conf *resolvConfTest) teardown() error {
	err := conf.forceUpdate("/etc/resolv.conf", time.Time{})
	os.RemoveAll(conf.dir)
	return err
}

var updateResolvConfTests = []struct {
	name    string   // query name
	lines   []string // resolver configuration lines
	servers []string // expected name servers
}{
	{
		name:    "golang.org",
		lines:   []string{"nameserver 8.8.8.8"},
		servers: []string{"8.8.8.8:53"},
	},
	{
		name:    "",
		lines:   nil, // an empty resolv.conf should use defaultNS as name servers
		servers: defaultNS,
	},
	{
		name:    "www.example.com",
		lines:   []string{"nameserver 8.8.4.4"},
		servers: []string{"8.8.4.4:53"},
	},
}

func TestUpdateResolvConf(t *testing.T) {
	defer dnsWaitGroup.Wait()

	r := Resolver{PreferGo: true, Dial: fakeDNSServerSuccessful.DialContext}

	conf, err := newResolvConfTest()
	if err != nil {
		t.Fatal(err)
	}
	defer conf.teardown()

	for i, tt := range updateResolvConfTests {
		if err := conf.writeAndUpdate(tt.lines); err != nil {
			t.Error(err)
			continue
		}
		if tt.name != "" {
			var wg sync.WaitGroup
			const N = 10
			wg.Add(N)
			for j := 0; j < N; j++ {
				go func(name string) {
					defer wg.Done()
					ips, err := r.LookupIPAddr(context.Background(), name)
					if err != nil {
						t.Error(err)
						return
					}
					if len(ips) == 0 {
						t.Errorf("no records for %s", name)
						return
					}
				}(tt.name)
			}
			wg.Wait()
		}
		servers := conf.servers()
		if !slices.Equal(servers, tt.servers) {
			t.Errorf("#%d: got %v; want %v", i, servers, tt.servers)
			continue
		}
	}
}

var goLookupIPWithResolverConfigTests = []struct {
	name  string
	lines []string // resolver configuration lines
	error
	a, aaaa bool // whether response contains A, AAAA-record
}{
	// no records, transport timeout
	{
		"jgahvsekduiv9bw4b3qhn4ykdfgj0493iohkrjfhdvhjiu4j",
		[]string{
			"options timeout:1 attempts:1",
			"nameserver 255.255.255.255", // please forgive us for abuse of limited broadcast address
		},
		&DNSError{Name: "jgahvsekduiv9bw4b3qhn4ykdfgj0493iohkrjfhdvhjiu4j", Server: "255.255.255.255:53", IsTimeout: true},
		false, false,
	},

	// no records, non-existent domain
	{
		"jgahvsekduiv9bw4b3qhn4ykdfgj0493iohkrjfhdvhjiu4j",
		[]string{
			"options timeout:3 attempts:1",
			"nameserver 8.8.8.8",
		},
		&DNSError{Name: "jgahvsekduiv9bw4b3qhn4ykdfgj0493iohkrjfhdvhjiu4j", Server: "8.8.8.8:53", IsTimeout: false},
		false, false,
	},

	// a few A records, no AAAA records
	{
		"ipv4.google.com.",
		[]string{
			"nameserver 8.8.8.8",
			"nameserver 2001:4860:4860::8888",
		},
		nil,
		true, false,
	},
	{
		"ipv4.google.com",
		[]string{
			"domain golang.org",
			"nameserver 2001:4860:4860::8888",
			"nameserver 8.8.8.8",
		},
		nil,
		true, false,
	},
	{
		"ipv4.google.com",
		[]string{
			"search x.golang.org y.golang.org",
			"nameserver 2001:4860:4860::8888",
			"nameserver 8.8.8.8",
		},
		nil,
		true, false,
	},

	// no A records, a few AAAA records
	{
		"ipv6.google.com.",
		[]string{
			"nameserver 2001:4860:4860::8888",
			"nameserver 8.8.8.8",
		},
		nil,
		false, true,
	},
	{
		"ipv6.google.com",
		[]string{
			"domain golang.org",
			"nameserver 8.8.8.8",
			"nameserver 2001:4860:4860::8888",
		},
		nil,
		false, true,
	},
	{
		"ipv6.google.com",
		[]string{
			"search x.golang.org y.golang.org",
			"nameserver 8.8.8.8",
			"nameserver 2001:4860:4860::8888",
		},
		nil,
		false, true,
	},

	// both A and AAAA records
	{
		"hostname.as112.net", // see RFC 7534
		[]string{
			"domain golang.org",
			"nameserver 2001:4860:4860::8888",
			"nameserver 8.8.8.8",
		},
		nil,
		true, true,
	},
	{
		"hostname.as112.net", // see RFC 7534
		[]string{
			"search x.golang.org y.golang.org",
			"nameserver 2001:4860:4860::8888",
			"nameserver 8.8.8.8",
		},
		nil,
		true, true,
	},
}

func TestGoLookupIPWithResolverConfig(t *testing.T) {
	defer dnsWaitGroup.Wait()
	fake := fakeDNSServer{rh: func(n, s string, q dnsmessage.Message, _ time.Time) (dnsmessage.Message, error) {
		switch s {
		case "[2001:4860:4860::8888]:53", "8.8.8.8:53":
			break
		default:
			time.Sleep(10 * time.Millisecond)
			return dnsmessage.Message{}, os.ErrDeadlineExceeded
		}
		r := dnsmessage.Message{
			Header: dnsmessage.Header{
				ID:       q.ID,
				Response: true,
			},
			Questions: q.Questions,
		}
		for _, question := range q.Questions {
			switch question.Type {
			case dnsmessage.TypeA:
				switch question.Name.String() {
				case "hostname.as112.net.":
					break
				case "ipv4.google.com.":
					r.Answers = append(r.Answers, dnsmessage.Resource{
						Header: dnsmessage.ResourceHeader{
							Name:   q.Questions[0].Name,
							Type:   dnsmessage.TypeA,
							Class:  dnsmessage.ClassINET,
							Length: 4,
						},
						Body: &dnsmessage.AResource{
							A: TestAddr,
						},
					})
				default:

				}
			case dnsmessage.TypeAAAA:
				switch question.Name.String() {
				case "hostname.as112.net.":
					break
				case "ipv6.google.com.":
					r.Answers = append(r.Answers, dnsmessage.Resource{
						Header: dnsmessage.ResourceHeader{
							Name:   q.Questions[0].Name,
							Type:   dnsmessage.TypeAAAA,
							Class:  dnsmessage.ClassINET,
							Length: 16,
						},
						Body: &dnsmessage.AAAAResource{
							AAAA: TestAddr6,
						},
					})
				}
			}
		}
		return r, nil
	}}
	r := Resolver{PreferGo: true, Dial: fake.DialContext}

	conf, err := newResolvConfTest()
	if err != nil {
		t.Fatal(err)
	}
	defer conf.teardown()

	for _, tt := range goLookupIPWithResolverConfigTests {
		if err := conf.writeAndUpdate(tt.lines); err != nil {
			t.Error(err)
			continue
		}
		addrs, err := r.LookupIPAddr(context.Background(), tt.name)
		if err != nil {
			if err, ok := err.(*DNSError); !ok || tt.error != nil && (err.Name != tt.error.(*DNSError).Name || err.Server != tt.error.(*DNSError).Server || err.IsTimeout != tt.error.(*DNSError).IsTimeout) {
				t.Errorf("got %v; want %v", err, tt.error)
			}
			continue
		}
		if len(addrs) == 0 {
			t.Errorf("no records for %s", tt.name)
		}
		if !tt.a && !tt.aaaa && len(addrs) > 0 {
			t.Errorf("unexpected %v for %s", addrs, tt.name)
		}
		for _, addr := range addrs {
			if !tt.a && addr.IP.To4() != nil {
				t.Errorf("got %v; must not be IPv4 address", addr)
			}
			if !tt.aaaa && addr.IP.To16() != nil && addr.IP.To4() == nil {
				t.Errorf("got %v; must not be IPv6 address", addr)
			}
		}
	}
}

// Test that goLookupIPOrder falls back to the host file when no DNS servers are available.
func TestGoLookupIPOrderFallbackToFile(t *testing.T) {
	defer dnsWaitGroup.Wait()

	fake := fakeDNSServer{rh: func(n, s string, q dnsmessage.Message, tm time.Time) (dnsmessage.Message, error) {
		r := dnsmessage.Message{
			Header: dnsmessage.Header{
				ID:       q.ID,
				Response: true,
			},
			Questions: q.Questions,
		}
		return r, nil
	}}
	r := Resolver{PreferGo: true, Dial: fake.DialContext}

	// Add a config that simulates no dns servers being available.
	conf, err := newResolvConfTest()
	if err != nil {
		t.Fatal(err)
	}
	defer conf.teardown()

	if err := conf.writeAndUpdate([]string{}); err != nil {
		t.Fatal(err)
	}
	// Redirect host file lookups.
	defer func(orig string) { hostsFilePath = orig }(hostsFilePath)
	hostsFilePath = "testdata/hosts"

	for _, order := range []hostLookupOrder{hostLookupFilesDNS, hostLookupDNSFiles} {
		name := fmt.Sprintf("order %v", order)
		// First ensure that we get an error when contacting a non-existent host.
		_, _, err := r.goLookupIPCNAMEOrder(context.Background(), "ip", "notarealhost", order, nil)
		if err == nil {
			t.Errorf("%s: expected error while looking up name not in hosts file", name)
			continue
		}

		// Now check that we get an address when the name appears in the hosts file.
		addrs, _, err := r.goLookupIPCNAMEOrder(context.Background(), "ip", "thor", order, nil) // entry is in "testdata/hosts"
		if err != nil {
			t.Errorf("%s: expected to successfully lookup host entry", name)
			continue
		}
		if len(addrs) != 1 {
			t.Errorf("%s: expected exactly one result, but got %v", name, addrs)
			continue
		}
		if got, want := addrs[0].String(), "127.1.1.1"; got != want {
			t.Errorf("%s: address doesn't match expectation. got %v, want %v", name, got, want)
		}
	}
}

// Issue 12712.
// When using search domains, return the error encountered
// querying the original name instead of an error encountered
// querying a generated name.
func TestErrorForOriginalNameWhenSearching(t *testing.T) {
	defer dnsWaitGroup.Wait()

	const fqdn = "doesnotexist.domain"

	conf, err := newResolvConfTest()
	if err != nil {
		t.Fatal(err)
	}
	defer conf.teardown()

	if err := conf.writeAndUpdate([]string{"search servfail"}); err != nil {
		t.Fatal(err)
	}

	fake := fakeDNSServer{rh: func(_, _ string, q dnsmessage.Message, _ time.Time) (dnsmessage.Message, error) {
		r := dnsmessage.Message{
			Header: dnsmessage.Header{
				ID:       q.ID,
				Response: true,
			},
			Questions: q.Questions,
		}

		switch q.Questions[0].Name.String() {
		case fqdn + ".servfail.":
			r.Header.RCode = dnsmessage.RCodeServerFailure
		default:
			r.Header.RCode = dnsmessage.RCodeNameError
		}

		return r, nil
	}}

	cases := []struct {
		strictErrors bool
		wantErr      *DNSError
	}{
		{true, &DNSError{Name: fqdn, Err: "server misbehaving", IsTemporary: true}},
		{false, &DNSError{Name: fqdn, Err: errNoSuchHost.Error(), IsNotFound: true}},
	}
	for _, tt := range cases {
		r := Resolver{PreferGo: true, StrictErrors: tt.strictErrors, Dial: fake.DialContext}
		_, err = r.LookupIPAddr(context.Background(), fqdn)
		if err == nil {
			t.Fatal("expected an error")
		}

		want := tt.wantErr
		if err, ok := err.(*DNSError); !ok || err.Name != want.Name || err.Err != want.Err || err.IsTemporary != want.IsTemporary {
			t.Errorf("got %v; want %v", err, want)
		}
	}
}

// Issue 15434. If a name server gives a lame referral, continue to the next.
func TestIgnoreLameReferrals(t *testing.T) {
	defer dnsWaitGroup.Wait()

	conf, err := newResolvConfTest()
	if err != nil {
		t.Fatal(err)
	}
	defer conf.teardown()

	if err := conf.writeAndUpdate([]string{"nameserver 192.0.2.1", // the one that will give a lame referral
		"nameserver 192.0.2.2"}); err != nil {
		t.Fatal(err)
	}

	fake := fakeDNSServer{rh: func(_, s string, q dnsmessage.Message, _ time.Time) (dnsmessage.Message, error) {
		t.Log(s, q)
		r := dnsmessage.Message{
			Header: dnsmessage.Header{
				ID:       q.ID,
				Response: true,
			},
			Questions: q.Questions,
		}

		if s == "192.0.2.2:53" {
			r.Header.RecursionAvailable = true
			if q.Questions[0].Type == dnsmessage.TypeA {
				r.Answers = []dnsmessage.Resource{
					{
						Header: dnsmessage.ResourceHeader{
							Name:   q.Questions[0].Name,
							Type:   dnsmessage.TypeA,
							Class:  dnsmessage.ClassINET,
							Length: 4,
						},
						Body: &dnsmessage.AResource{
							A: TestAddr,
						},
					},
				}
			}
		} else if s == "192.0.2.1:53" {
			if q.Questions[0].Type == dnsmessage.TypeA && strings.HasPrefix(q.Questions[0].Name.String(), "empty.com.") {
				var edns0Hdr dnsmessage.ResourceHeader
				edns0Hdr.SetEDNS0(maxDNSPacketSize, dnsmessage.RCodeSuccess, false)

				r.Additionals = []dnsmessage.Resource{
					{
						Header: edns0Hdr,
						Body:   &dnsmessage.OPTResource{},
					},
				}
			}
		}

		return r, nil
	}}
	r := Resolver{PreferGo: true, Dial: fake.DialContext}

	addrs, err := r.LookupIP(context.Background(), "ip4", "www.golang.org")
	if err != nil {
		t.Fatal(err)
	}

	if got := len(addrs); got != 1 {
		t.Fatalf("got %d addresses, want 1", got)
	}

	if got, want := addrs[0].String(), "192.0.2.1"; got != want {
		t.Fatalf("got address %v, want %v", got, want)
	}

	_, err = r.LookupIP(context.Background(), "ip4", "empty.com")
	de, ok := err.(*DNSError)
	if !ok {
		t.Fatalf("err = %#v; wanted a *net.DNSError", err)
	}
	if de.Err != errNoSuchHost.Error() {
		t.Fatalf("Err = %#v; wanted %q", de.Err, errNoSuchHost.Error())
	}
}

func BenchmarkGoLookupIP(b *testing.B) {
	testHookUninstaller.Do(uninstallTestHooks)
	ctx := context.Background()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		goResolver.LookupIPAddr(ctx, "www.example.com")
	}
}

func BenchmarkGoLookupIPNoSuchHost(b *testing.B) {
	testHookUninstaller.Do(uninstallTestHooks)
	ctx := context.Background()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		goResolver.LookupIPAddr(ctx, "some.nonexistent")
	}
}

func BenchmarkGoLookupIPWithBrokenNameServer(b *testing.B) {
	testHookUninstaller.Do(uninstallTestHooks)

	conf, err := newResolvConfTest()
	if err != nil {
		b.Fatal(err)
	}
	defer conf.teardown()

	lines := []string{
		"nameserver 203.0.113.254", // use TEST-NET-3 block, see RFC 5737
		"nameserver 8.8.8.8",
	}
	if err := conf.writeAndUpdate(lines); err != nil {
		b.Fatal(err)
	}
	ctx := context.Background()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		goResolver.LookupIPAddr(ctx, "www.example.com")
	}
}

type fakeDNSServer struct {
	rh        func(n, s string, q dnsmessage.Message, t time.Time) (dnsmessage.Message, error)
	alwaysTCP bool
}

func (server *fakeDNSServer) DialContext(_ context.Context, n, s string) (Conn, error) {
	if server.alwaysTCP || n == "tcp" || n == "tcp4" || n == "tcp6" {
		return &fakeDNSConn{tcp: true, server: server, n: n, s: s}, nil
	}
	return &fakeDNSPacketConn{fakeDNSConn: fakeDNSConn{tcp: false, server: server, n: n, s: s}}, nil
}

type fakeDNSConn struct {
	Conn
	tcp    bool
	server *fakeDNSServer
	n      string
	s      string
	q      dnsmessage.Message
	t      time.Time
	buf    []byte
}

func (f *fakeDNSConn) Close() error {
	return nil
}

func (f *fakeDNSConn) Read(b []byte) (int, error) {
	if len(f.buf) > 0 {
		n := copy(b, f.buf)
		f.buf = f.buf[n:]
		return n, nil
	}

	resp, err := f.server.rh(f.n, f.s, f.q, f.t)
	if err != nil {
		return 0, err
	}

	bb := make([]byte, 2, 514)
	bb, err = resp.AppendPack(bb)
	if err != nil {
		return 0, fmt.Errorf("cannot marshal DNS message: %v", err)
	}

	if f.tcp {
		l := len(bb) - 2
		bb[0] = byte(l >> 8)
		bb[1] = byte(l)
		f.buf = bb
		return f.Read(b)
	}

	bb = bb[2:]
	if len(b) < len(bb) {
		return 0, errors.New("read would fragment DNS message")
	}

	copy(b, bb)
	return len(bb), nil
}

func (f *fakeDNSConn) Write(b []byte) (int, error) {
	if f.tcp && len(b) >= 2 {
		b = b[2:]
	}
	if f.q.Unpack(b) != nil {
		return 0, fmt.Errorf("cannot unmarshal DNS message fake %s (%d)", f.n, len(b))
	}
	return len(b), nil
}

func (f *fakeDNSConn) SetDeadline(t time.Time) error {
	f.t = t
	return nil
}

type fakeDNSPacketConn struct {
	PacketConn
	fakeDNSConn
}

func (f *fakeDNSPacketConn) SetDeadline(t time.Time) error {
	return f.fakeDNSConn.SetDeadline(t)
}

func (f *fakeDNSPacketConn) Close() error {
	return f.fakeDNSConn.Close()
}

// UDP round-tripper algorithm should ignore invalid DNS responses (issue 13281).
func TestIgnoreDNSForgeries(t *testing.T) {
	c, s := Pipe()
	go func() {
		b := make([]byte, maxDNSPacketSize)
		n, err := s.Read(b)
		if err != nil {
			t.Error(err)
			return
		}

		var msg dnsmessage.Message
		if msg.Unpack(b[:n]) != nil {
			t.Error("invalid DNS query:", err)
			return
		}

		s.Write([]byte("garbage DNS response packet"))

		msg.Header.Response = true
		msg.Header.ID++ // make invalid ID

		if b, err = msg.Pack(); err != nil {
			t.Error("failed to pack DNS response:", err)
			return
		}
		s.Write(b)

		msg.Header.ID-- // restore original ID
		msg.Answers = []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{
					Name:   mustNewName("www.example.com."),
					Type:   dnsmessage.TypeA,
					Class:  dnsmessage.ClassINET,
					Length: 4,
				},
				Body: &dnsmessage.AResource{
					A: TestAddr,
				},
			},
		}

		b, err = msg.Pack()
		if err != nil {
			t.Error("failed to pack DNS response:", err)
			return
		}
		s.Write(b)
	}()

	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID: 42,
		},
		Questions: []dnsmessage.Question{
			{
				Name:  mustNewName("www.example.com."),
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
			},
		},
	}

	b, err := msg.Pack()
	if err != nil {
		t.Fatal("Pack failed:", err)
	}

	p, _, err := dnsPacketRoundTrip(c, 42, msg.Questions[0], b)
	if err != nil {
		t.Fatalf("dnsPacketRoundTrip failed: %v", err)
	}

	p.SkipAllQuestions()
	as, err := p.AllAnswers()
	if err != nil {
		t.Fatal("AllAnswers failed:", err)
	}
	if got := as[0].Body.(*dnsmessage.AResource).A; got != TestAddr {
		t.Errorf("got address %v, want %v", got, TestAddr)
	}
}

// Issue 16865. If a name server times out, continue to the next.
func TestRetryTimeout(t *testing.T) {
	defer dnsWaitGroup.Wait()

	conf, err := newResolvConfTest()
	if err != nil {
		t.Fatal(err)
	}
	defer conf.teardown()

	testConf := []string{
		"nameserver 192.0.2.1", // the one that will timeout
		"nameserver 192.0.2.2",
	}
	if err := conf.writeAndUpdate(testConf); err != nil {
		t.Fatal(err)
	}

	var deadline0 time.Time

	fake := fakeDNSServer{rh: func(_, s string, q dnsmessage.Message, deadline time.Time) (dnsmessage.Message, error) {
		t.Log(s, q, deadline)

		if deadline.IsZero() {
			t.Error("zero deadline")
		}

		if s == "192.0.2.1:53" {
			deadline0 = deadline
			time.Sleep(10 * time.Millisecond)
			return dnsmessage.Message{}, os.ErrDeadlineExceeded
		}

		if deadline.Equal(deadline0) {
			t.Error("deadline didn't change")
		}

		return mockTXTResponse(q), nil
	}}
	r := &Resolver{PreferGo: true, Dial: fake.DialContext}

	_, err = r.LookupTXT(context.Background(), "www.golang.org")
	if err != nil {
		t.Fatal(err)
	}

	if deadline0.IsZero() {
		t.Error("deadline0 still zero", deadline0)
	}
}

func TestRotate(t *testing.T) {
	// without rotation, always uses the first server
	testRotate(t, false, []string{"192.0.2.1", "192.0.2.2"}, []string{"192.0.2.1:53", "192.0.2.1:53", "192.0.2.1:53"})

	// with rotation, rotates through back to first
	testRotate(t, true, []string{"192.0.2.1", "192.0.2.2"}, []string{"192.0.2.1:53", "192.0.2.2:53", "192.0.2.1:53"})
}

func testRotate(t *testing.T, rotate bool, nameservers, wantServers []string) {
	defer dnsWaitGroup.Wait()

	conf, err := newResolvConfTest()
	if err != nil {
		t.Fatal(err)
	}
	defer conf.teardown()

	var confLines []string
	for _, ns := range nameservers {
		confLines = append(confLines, "nameserver "+ns)
	}
	if rotate {
		confLines = append(confLines, "options rotate")
	}

	if err := conf.writeAndUpdate(confLines); err != nil {
		t.Fatal(err)
	}

	var usedServers []string
	fake := fakeDNSServer{rh: func(_, s string, q dnsmessage.Message, deadline time.Time) (dnsmessage.Message, error) {
		usedServers = append(usedServers, s)
		return mockTXTResponse(q), nil
	}}
	r := Resolver{PreferGo: true, Dial: fake.DialContext}

	// len(nameservers) + 1 to allow rotation to get back to start
	for i := 0; i < len(nameservers)+1; i++ {
		if _, err := r.LookupTXT(context.Background(), "www.golang.org"); err != nil {
			t.Fatal(err)
		}
	}

	if !slices.Equal(usedServers, wantServers) {
		t.Errorf("rotate=%t got used servers:\n%v\nwant:\n%v", rotate, usedServers, wantServers)
	}
}

func mockTXTResponse(q dnsmessage.Message) dnsmessage.Message {
	r := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 q.ID,
			Response:           true,
			RecursionAvailable: true,
		},
		Questions: q.Questions,
		Answers: []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{
					Name:  q.Questions[0].Name,
					Type:  dnsmessage.TypeTXT,
					Class: dnsmessage.ClassINET,
				},
				Body: &dnsmessage.TXTResource{
					TXT: []string{"ok"},
				},
			},
		},
	}

	return r
}

// Issue 17448. With StrictErrors enabled, temporary errors should make
// LookupIP fail rather than return a partial result.
func TestStrictErrorsLookupIP(t *testing.T) {
	defer dnsWaitGroup.Wait()

	conf, err := newResolvConfTest()
	if err != nil {
		t.Fatal(err)
	}
	defer conf.teardown()

	confData := []string{
		"nameserver 192.0.2.53",
		"search x.golang.org y.golang.org",
	}
	if err := conf.writeAndUpdate(confData); err != nil {
		t.Fatal(err)
	}

	const name = "test-issue19592"
	const server = "192.0.2.53:53"
	const searchX = "test-issue19592.x.golang.org."
	const searchY = "test-issue19592.y.golang.org."
	const ip4 = "192.0.2.1"
	const ip6 = "2001:db8::1"

	type resolveWhichEnum int
	const (
		resolveOK resolveWhichEnum = iota
		resolveOpError
		resolveServfail
		resolveTimeout
	)

	makeTempError := func(err string) error {
		return &DNSError{
			Err:         err,
			Name:        name,
			Server:      server,
			IsTemporary: true,
		}
	}
	makeTimeout := func() error {
		return &DNSError{
			Err:         os.ErrDeadlineExceeded.Error(),
			Name:        name,
			Server:      server,
			IsTimeout:   true,
			IsTemporary: true,
		}
	}
	makeNxDomain := func() error {
		return &DNSError{
			Err:        errNoSuchHost.Error(),
			Name:       name,
			Server:     server,
			IsNotFound: true,
		}
	}

	cases := []struct {
		desc          string
		resolveWhich  func(quest dnsmessage.Question) resolveWhichEnum
		wantStrictErr error
		wantLaxErr    error
		wantIPs       []string
	}{
		{
			desc: "No errors",
			resolveWhich: func(quest dnsmessage.Question) resolveWhichEnum {
				return resolveOK
			},
			wantIPs: []string{ip4, ip6},
		},
		{
			desc: "searchX error fails in strict mode",
			resolveWhich: func(quest dnsmessage.Question) resolveWhichEnum {
				if quest.Name.String() == searchX {
					return resolveTimeout
				}
				return resolveOK
			},
			wantStrictErr: makeTimeout(),
			wantIPs:       []string{ip4, ip6},
		},
		{
			desc: "searchX IPv4-only timeout fails in strict mode",
			resolveWhich: func(quest dnsmessage.Question) resolveWhichEnum {
				if quest.Name.String() == searchX && quest.Type == dnsmessage.TypeA {
					return resolveTimeout
				}
				return resolveOK
			},
			wantStrictErr: makeTimeout(),
			wantIPs:       []string{ip4, ip6},
		},
		{
			desc: "searchX IPv6-only servfail fails in strict mode",
			resolveWhich: func(quest dnsmessage.Question) resolveWhichEnum {
				if quest.Name.String() == searchX && quest.Type == dnsmessage.TypeAAAA {
					return resolveServfail
				}
				return resolveOK
			},
			wantStrictErr: makeTempError("server misbehaving"),
			wantIPs:       []string{ip4, ip6},
		},
		{
			desc: "searchY error always fails",
			resolveWhich: func(quest dnsmessage.Question) resolveWhichEnum {
				if quest.Name.String() == searchY {
					return resolveTimeout
				}
				return resolveOK
			},
			wantStrictErr: makeTimeout(),
			wantLaxErr:    makeNxDomain(), // This one reaches the "test." FQDN.
		},
		{
			desc: "searchY IPv4-only socket error fails in strict mode",
			resolveWhich: func(quest dnsmessage.Question) resolveWhichEnum {
				if quest.Name.String() == searchY && quest.Type == dnsmessage.TypeA {
					return resolveOpError
				}
				return resolveOK
			},
			wantStrictErr: makeTempError("write: socket on fire"),
			wantIPs:       []string{ip6},
		},
		{
			desc: "searchY IPv6-only timeout fails in strict mode",
			re
```