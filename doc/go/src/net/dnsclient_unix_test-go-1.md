Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Understand the Goal:** The overarching goal is to understand the functionality of the provided Go code, which is a part of `dnsclient_unix_test.go`. This involves identifying what specific DNS-related features are being tested and how.

2. **Identify the Core Structure:**  The code is primarily a series of test functions (functions starting with `Test`). Each test function focuses on a particular aspect of DNS resolution. The main building blocks within these tests are:
    * **`fakeDNSServer`:** A custom type simulating a DNS server. This is crucial for controlled testing.
    * **`Resolver`:**  The core component being tested – the DNS resolver.
    * **Test Cases:**  Many tests use a structured `cases` slice to run the same logic with different inputs and expected outputs.
    * **Assertions:**  `t.Errorf`, `t.Fatalf`, etc., are used to verify the actual behavior against the expected behavior.

3. **Analyze Individual Test Functions:** Go through each `Test` function and decipher its purpose.

    * **`TestLookupIPAddrSearchListStrictErrors`:** The name strongly suggests it's testing `LookupIPAddr`'s interaction with the search list when `StrictErrors` is enabled. The `resolveWhich` function within the `fakeDNSServer` is the key to understanding the different scenarios being simulated (timeout, error, success).

    * **`TestStrictErrorsLookupTXT`:** Similar to the previous one, but focusing on `LookupTXT` and how `StrictErrors` affects search list traversal when temporary errors occur.

    * **`TestDNSGoroutineRace`:** The name hints at testing for race conditions, specifically between uninstalling test hooks and closing sockets. The `time.Sleep` in the fake server is likely designed to introduce a delay to trigger the race.

    * **`TestIssue8434`:** This indicates a specific bug fix being verified. The core of the test is checking if a `SERVFAIL` response is correctly identified as a temporary error.

    * **`TestIssueNoSuchHostExists`:**  Another bug fix test, focusing on verifying that `RCodeNameError` is correctly identified as a "not found" error.

    * **`TestNoSuchHost`:**  A more comprehensive test for non-existent domains, covering different scenarios like `NXDOMAIN` and empty answers. The test verifies the "fail fast" behavior.

    * **`TestDNSDialTCP`:** Checks if the resolver correctly handles TCP even when UDP is requested, based on the underlying connection type.

    * **`TestTXTRecordTwoStrings`:** Focuses on how TXT records with multiple strings are handled (concatenation).

    * **`TestSingleRequestLookup`:**  Tests the `single-request` resolv.conf option, ensuring that A and AAAA queries are sent sequentially.

    * **`TestDNSUseTCP`:** Verifies the functionality to force TCP-only DNS requests.

    * **`TestDNSUseTCPTruncated`:** Checks how truncated responses over TCP are handled.

    * **`TestPTRandNonPTR`:**  Tests the behavior of `lookupAddr` when a PTR response includes non-PTR records.

    * **`TestCVE202133195`:** Clearly a test for a specific security vulnerability. It checks how the resolver handles malformed DNS records of various types (CNAME, SRV, MX, NS, PTR) to prevent potential exploits.

    * **`TestNullMX`:** Tests how the resolver handles an MX record with a value of ".".

    * **`TestRootNS`:** Tests the lookup of NS records for the root domain.

    * **`TestGoLookupIPCNAMEOrderHostsAliasesFilesOnlyMode`, `TestGoLookupIPCNAMEOrderHostsAliasesFilesDNSMode`, `TestGoLookupIPCNAMEOrderHostsAliasesDNSFilesMode`:** These test different modes of host lookup involving `/etc/hosts` and aliases. They verify the order in which different sources are consulted.

    * **`TestDNSPacketSize`:** Checks if the resolver correctly advertises support for larger DNS packet sizes using EDNS.

    * **`TestLongDNSNames`:** Tests how the resolver handles very long DNS names.

4. **Identify Key Concepts and Patterns:**  Recognize recurring patterns like:
    * The use of `fakeDNSServer` for mocking.
    * The use of `Resolver` for testing the resolution logic.
    * The focus on error handling (especially with `StrictErrors`).
    * The testing of specific DNS record types (A, AAAA, TXT, SRV, MX, NS, PTR, CNAME).
    * The testing of configuration options (like `single-request`, forcing TCP).

5. **Infer Functionality from Tests:** Based on the tests, deduce the broader functionality being implemented in the `net/dnsclient_unix_test.go` file. This involves:
    * Resolving IP addresses (`LookupIPAddr`).
    * Looking up TXT records (`LookupTXT`).
    * Handling search lists.
    * Managing errors (strict vs. lax).
    * Handling different DNS response codes (NXDOMAIN, SERVFAIL).
    * Using both UDP and TCP for DNS queries.
    * Supporting different resolv.conf options.
    * Handling various DNS record types.
    * Protecting against malformed DNS records.
    * Handling `/etc/hosts` and alias files.
    * Supporting larger DNS packet sizes.
    * Handling long DNS names.

6. **Synthesize the Summary:** Combine the insights from analyzing individual tests and identifying key concepts to create a concise summary of the code's functionality. The summary should highlight the major areas of DNS resolution being tested.

7. **Self-Correction/Refinement:** Review the initial summary. Is it accurate? Is it comprehensive enough without being overly verbose?  For example, initially, I might have just said "tests DNS resolution." But by looking at the individual tests, I can be much more specific about *what aspects* of DNS resolution are being tested. Similarly, noting the focus on error handling and specific record types adds valuable detail.
这是Go语言标准库 `net` 包中 `dnsclient_unix_test.go` 文件的一部分，它主要用于测试在 Unix 系统下 DNS 客户端的特定功能。根据提供的代码片段，可以归纳出以下功能：

**主要功能归纳:**

这段代码主要测试了 `net` 包中 DNS 解析器在处理特定场景下的行为，特别是涉及到以下方面：

1. **严格错误模式 (`StrictErrors`) 对 DNS 解析的影响:** 测试了当启用 `StrictErrors` 时，DNS 解析器在遇到错误（如超时）时是否会停止搜索列表，以及返回的错误类型是否符合预期。

2. **针对特定 DNS 查询的模拟响应:** 使用 `fakeDNSServer` 模拟不同的 DNS 服务器响应，包括成功响应、操作错误、服务器失败（SERVFAIL）、超时等，以此来测试 DNS 解析器在接收到这些响应时的处理逻辑。

3. **搜索列表 (`search list`) 的行为:**  测试了 DNS 解析器在使用搜索列表进行域名解析时的行为，包括在找到结果或遇到特定错误时是否会继续尝试搜索列表中的其他域名后缀。

4. **临时性错误的处理:**  测试了 DNS 解析器是否能正确识别并处理临时性错误，例如超时错误。

5. **“域名不存在” (NXDOMAIN) 的处理:** 测试了 DNS 解析器在接收到 NXDOMAIN 响应时的行为，以及是否能快速失败。

6. **处理 Truncated (截断) 的 TCP 响应:**  测试了当 DNS 服务器使用 TCP 发送截断的响应时，DNS 解析器是否能够正确处理。

7. **忽略非 PTR 记录:** 测试了当进行 PTR 查询时，如果响应中包含非 PTR 类型的记录，DNS 解析器是否会正确忽略这些记录。

8. **处理包含恶意内容的 DNS 响应 (CVE-2021-33195 相关):**  测试了 DNS 解析器在接收到包含潜在恶意内容（例如 CNAME 指向 HTML 标签）的 DNS 响应时的安全性，防止出现诸如注入攻击的风险。

9. **处理特殊的 MX 和 NS 记录:** 测试了对于 MX 记录值为 "." 和 NS 记录值为根域名 "." 的处理。

10. **主机名查找顺序 (涉及 `/etc/hosts` 和别名文件):**  测试了在不同的主机名查找模式下，DNS 解析器如何使用 `/etc/hosts` 文件和别名文件进行解析。

11. **支持更大的 DNS 数据包大小 (EDNS):** 测试了 DNS 解析器是否能够发送和处理携带 EDNS 信息的 DNS 查询，以便支持更大的 UDP 数据包。

12. **处理过长的 DNS 域名:**  测试了 DNS 解析器对于超长域名的处理能力。

**结合第1部分和第2部分，可以更全面地理解这段测试代码的目的。** 第一部分可能包含了测试框架的搭建、辅助函数的定义以及一些基础的测试用例。而第二部分则深入到更具体的 DNS 解析场景和错误处理逻辑的测试。

总而言之，这段代码是 Go 语言 `net` 包中 DNS 客户端实现的关键测试部分，它确保了 DNS 解析器在各种复杂和异常情况下都能按照预期工作，并且能够防御潜在的安全风险。

Prompt: 
```
这是路径为go/src/net/dnsclient_unix_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共3部分，请归纳一下它的功能

"""
solveWhich: func(quest dnsmessage.Question) resolveWhichEnum {
				if quest.Name.String() == searchY && quest.Type == dnsmessage.TypeAAAA {
					return resolveTimeout
				}
				return resolveOK
			},
			wantStrictErr: makeTimeout(),
			wantIPs:       []string{ip4},
		},
	}

	for i, tt := range cases {
		fake := fakeDNSServer{rh: func(_, s string, q dnsmessage.Message, deadline time.Time) (dnsmessage.Message, error) {
			t.Log(s, q)

			switch tt.resolveWhich(q.Questions[0]) {
			case resolveOK:
				// Handle below.
			case resolveOpError:
				return dnsmessage.Message{}, &OpError{Op: "write", Err: fmt.Errorf("socket on fire")}
			case resolveServfail:
				return dnsmessage.Message{
					Header: dnsmessage.Header{
						ID:       q.ID,
						Response: true,
						RCode:    dnsmessage.RCodeServerFailure,
					},
					Questions: q.Questions,
				}, nil
			case resolveTimeout:
				return dnsmessage.Message{}, os.ErrDeadlineExceeded
			default:
				t.Fatal("Impossible resolveWhich")
			}

			switch q.Questions[0].Name.String() {
			case searchX, name + ".":
				// Return NXDOMAIN to utilize the search list.
				return dnsmessage.Message{
					Header: dnsmessage.Header{
						ID:       q.ID,
						Response: true,
						RCode:    dnsmessage.RCodeNameError,
					},
					Questions: q.Questions,
				}, nil
			case searchY:
				// Return records below.
			default:
				return dnsmessage.Message{}, fmt.Errorf("Unexpected Name: %v", q.Questions[0].Name)
			}

			r := dnsmessage.Message{
				Header: dnsmessage.Header{
					ID:       q.ID,
					Response: true,
				},
				Questions: q.Questions,
			}
			switch q.Questions[0].Type {
			case dnsmessage.TypeA:
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
			case dnsmessage.TypeAAAA:
				r.Answers = []dnsmessage.Resource{
					{
						Header: dnsmessage.ResourceHeader{
							Name:   q.Questions[0].Name,
							Type:   dnsmessage.TypeAAAA,
							Class:  dnsmessage.ClassINET,
							Length: 16,
						},
						Body: &dnsmessage.AAAAResource{
							AAAA: TestAddr6,
						},
					},
				}
			default:
				return dnsmessage.Message{}, fmt.Errorf("Unexpected Type: %v", q.Questions[0].Type)
			}
			return r, nil
		}}

		for _, strict := range []bool{true, false} {
			r := Resolver{PreferGo: true, StrictErrors: strict, Dial: fake.DialContext}
			ips, err := r.LookupIPAddr(context.Background(), name)

			var wantErr error
			if strict {
				wantErr = tt.wantStrictErr
			} else {
				wantErr = tt.wantLaxErr
			}
			if !reflect.DeepEqual(err, wantErr) {
				t.Errorf("#%d (%s) strict=%v: got err %#v; want %#v", i, tt.desc, strict, err, wantErr)
			}

			gotIPs := map[string]struct{}{}
			for _, ip := range ips {
				gotIPs[ip.String()] = struct{}{}
			}
			wantIPs := map[string]struct{}{}
			if wantErr == nil {
				for _, ip := range tt.wantIPs {
					wantIPs[ip] = struct{}{}
				}
			}
			if !maps.Equal(gotIPs, wantIPs) {
				t.Errorf("#%d (%s) strict=%v: got ips %v; want %v", i, tt.desc, strict, gotIPs, wantIPs)
			}
		}
	}
}

// Issue 17448. With StrictErrors enabled, temporary errors should make
// LookupTXT stop walking the search list.
func TestStrictErrorsLookupTXT(t *testing.T) {
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

	const name = "test"
	const server = "192.0.2.53:53"
	const searchX = "test.x.golang.org."
	const searchY = "test.y.golang.org."
	const txt = "Hello World"

	fake := fakeDNSServer{rh: func(_, s string, q dnsmessage.Message, deadline time.Time) (dnsmessage.Message, error) {
		t.Log(s, q)

		switch q.Questions[0].Name.String() {
		case searchX:
			return dnsmessage.Message{}, os.ErrDeadlineExceeded
		case searchY:
			return mockTXTResponse(q), nil
		default:
			return dnsmessage.Message{}, fmt.Errorf("Unexpected Name: %v", q.Questions[0].Name)
		}
	}}

	for _, strict := range []bool{true, false} {
		r := Resolver{StrictErrors: strict, Dial: fake.DialContext}
		p, _, err := r.lookup(context.Background(), name, dnsmessage.TypeTXT, nil)
		var wantErr error
		var wantRRs int
		if strict {
			wantErr = &DNSError{
				Err:         os.ErrDeadlineExceeded.Error(),
				Name:        name,
				Server:      server,
				IsTimeout:   true,
				IsTemporary: true,
			}
		} else {
			wantRRs = 1
		}
		if !reflect.DeepEqual(err, wantErr) {
			t.Errorf("strict=%v: got err %#v; want %#v", strict, err, wantErr)
		}
		a, err := p.AllAnswers()
		if err != nil {
			a = nil
		}
		if len(a) != wantRRs {
			t.Errorf("strict=%v: got %v; want %v", strict, len(a), wantRRs)
		}
	}
}

// Test for a race between uninstalling the test hooks and closing a
// socket connection. This used to fail when testing with -race.
func TestDNSGoroutineRace(t *testing.T) {
	defer dnsWaitGroup.Wait()

	fake := fakeDNSServer{rh: func(n, s string, q dnsmessage.Message, t time.Time) (dnsmessage.Message, error) {
		time.Sleep(10 * time.Microsecond)
		return dnsmessage.Message{}, os.ErrDeadlineExceeded
	}}
	r := Resolver{PreferGo: true, Dial: fake.DialContext}

	// The timeout here is less than the timeout used by the server,
	// so the goroutine started to query the (fake) server will hang
	// around after this test is done if we don't call dnsWaitGroup.Wait.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Microsecond)
	defer cancel()
	_, err := r.LookupIPAddr(ctx, "where.are.they.now")
	if err == nil {
		t.Fatal("fake DNS lookup unexpectedly succeeded")
	}
}

func lookupWithFake(fake fakeDNSServer, name string, typ dnsmessage.Type) error {
	r := Resolver{PreferGo: true, Dial: fake.DialContext}

	conf := getSystemDNSConfig()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_, _, err := r.tryOneName(ctx, conf, name, typ)
	return err
}

// Issue 8434: verify that Temporary returns true on an error when rcode
// is SERVFAIL
func TestIssue8434(t *testing.T) {
	err := lookupWithFake(fakeDNSServer{
		rh: func(n, _ string, q dnsmessage.Message, _ time.Time) (dnsmessage.Message, error) {
			return dnsmessage.Message{
				Header: dnsmessage.Header{
					ID:       q.ID,
					Response: true,
					RCode:    dnsmessage.RCodeServerFailure,
				},
				Questions: q.Questions,
			}, nil
		},
	}, "golang.org.", dnsmessage.TypeALL)
	if err == nil {
		t.Fatal("expected an error")
	}
	if ne, ok := err.(Error); !ok {
		t.Fatalf("err = %#v; wanted something supporting net.Error", err)
	} else if !ne.Temporary() {
		t.Fatalf("Temporary = false for err = %#v; want Temporary == true", err)
	}
	if de, ok := err.(*DNSError); !ok {
		t.Fatalf("err = %#v; wanted a *net.DNSError", err)
	} else if !de.IsTemporary {
		t.Fatalf("IsTemporary = false for err = %#v; want IsTemporary == true", err)
	}
}

func TestIssueNoSuchHostExists(t *testing.T) {
	err := lookupWithFake(fakeDNSServer{
		rh: func(n, _ string, q dnsmessage.Message, _ time.Time) (dnsmessage.Message, error) {
			return dnsmessage.Message{
				Header: dnsmessage.Header{
					ID:       q.ID,
					Response: true,
					RCode:    dnsmessage.RCodeNameError,
				},
				Questions: q.Questions,
			}, nil
		},
	}, "golang.org.", dnsmessage.TypeALL)
	if err == nil {
		t.Fatal("expected an error")
	}
	if _, ok := err.(Error); !ok {
		t.Fatalf("err = %#v; wanted something supporting net.Error", err)
	}
	if de, ok := err.(*DNSError); !ok {
		t.Fatalf("err = %#v; wanted a *net.DNSError", err)
	} else if !de.IsNotFound {
		t.Fatalf("IsNotFound = false for err = %#v; want IsNotFound == true", err)
	}
}

// TestNoSuchHost verifies that tryOneName works correctly when the domain does
// not exist.
//
// Issue 12778: verify that NXDOMAIN without RA bit errors as "no such host"
// and not "server misbehaving"
//
// Issue 25336: verify that NXDOMAIN errors fail fast.
//
// Issue 27525: verify that empty answers fail fast.
func TestNoSuchHost(t *testing.T) {
	tests := []struct {
		name string
		f    func(string, string, dnsmessage.Message, time.Time) (dnsmessage.Message, error)
	}{
		{
			"NXDOMAIN",
			func(n, _ string, q dnsmessage.Message, _ time.Time) (dnsmessage.Message, error) {
				return dnsmessage.Message{
					Header: dnsmessage.Header{
						ID:                 q.ID,
						Response:           true,
						RCode:              dnsmessage.RCodeNameError,
						RecursionAvailable: false,
					},
					Questions: q.Questions,
				}, nil
			},
		},
		{
			"no answers",
			func(n, _ string, q dnsmessage.Message, _ time.Time) (dnsmessage.Message, error) {
				return dnsmessage.Message{
					Header: dnsmessage.Header{
						ID:                 q.ID,
						Response:           true,
						RCode:              dnsmessage.RCodeSuccess,
						RecursionAvailable: false,
						Authoritative:      true,
					},
					Questions: q.Questions,
				}, nil
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			lookups := 0
			err := lookupWithFake(fakeDNSServer{
				rh: func(n, s string, q dnsmessage.Message, d time.Time) (dnsmessage.Message, error) {
					lookups++
					return test.f(n, s, q, d)
				},
			}, ".", dnsmessage.TypeALL)

			if lookups != 1 {
				t.Errorf("got %d lookups, wanted 1", lookups)
			}

			if err == nil {
				t.Fatal("expected an error")
			}
			de, ok := err.(*DNSError)
			if !ok {
				t.Fatalf("err = %#v; wanted a *net.DNSError", err)
			}
			if de.Err != errNoSuchHost.Error() {
				t.Fatalf("Err = %#v; wanted %q", de.Err, errNoSuchHost.Error())
			}
			if !de.IsNotFound {
				t.Fatalf("IsNotFound = %v wanted true", de.IsNotFound)
			}
		})
	}
}

// Issue 26573: verify that Conns that don't implement PacketConn are treated
// as streams even when udp was requested.
func TestDNSDialTCP(t *testing.T) {
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
			return r, nil
		},
		alwaysTCP: true,
	}
	r := Resolver{PreferGo: true, Dial: fake.DialContext}
	ctx := context.Background()
	_, _, err := r.exchange(ctx, "0.0.0.0", mustQuestion("com.", dnsmessage.TypeALL, dnsmessage.ClassINET), time.Second, useUDPOrTCP, false)
	if err != nil {
		t.Fatal("exchange failed:", err)
	}
}

// Issue 27763: verify that two strings in one TXT record are concatenated.
func TestTXTRecordTwoStrings(t *testing.T) {
	fake := fakeDNSServer{
		rh: func(n, _ string, q dnsmessage.Message, _ time.Time) (dnsmessage.Message, error) {
			r := dnsmessage.Message{
				Header: dnsmessage.Header{
					ID:       q.Header.ID,
					Response: true,
					RCode:    dnsmessage.RCodeSuccess,
				},
				Questions: q.Questions,
				Answers: []dnsmessage.Resource{
					{
						Header: dnsmessage.ResourceHeader{
							Name:  q.Questions[0].Name,
							Type:  dnsmessage.TypeA,
							Class: dnsmessage.ClassINET,
						},
						Body: &dnsmessage.TXTResource{
							TXT: []string{"string1 ", "string2"},
						},
					},
					{
						Header: dnsmessage.ResourceHeader{
							Name:  q.Questions[0].Name,
							Type:  dnsmessage.TypeA,
							Class: dnsmessage.ClassINET,
						},
						Body: &dnsmessage.TXTResource{
							TXT: []string{"onestring"},
						},
					},
				},
			}
			return r, nil
		},
	}
	r := Resolver{PreferGo: true, Dial: fake.DialContext}
	txt, err := r.lookupTXT(context.Background(), "golang.org")
	if err != nil {
		t.Fatal("LookupTXT failed:", err)
	}
	if want := 2; len(txt) != want {
		t.Fatalf("len(txt), got %d, want %d", len(txt), want)
	}
	if want := "string1 string2"; txt[0] != want {
		t.Errorf("txt[0], got %q, want %q", txt[0], want)
	}
	if want := "onestring"; txt[1] != want {
		t.Errorf("txt[1], got %q, want %q", txt[1], want)
	}
}

// Issue 29644: support single-request resolv.conf option in pure Go resolver.
// The A and AAAA queries will be sent sequentially, not in parallel.
func TestSingleRequestLookup(t *testing.T) {
	defer dnsWaitGroup.Wait()
	var (
		firstcalled int32
		ipv4        int32 = 1
		ipv6        int32 = 2
	)
	fake := fakeDNSServer{rh: func(n, s string, q dnsmessage.Message, _ time.Time) (dnsmessage.Message, error) {
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
				if question.Name.String() == "slowipv4.example.net." {
					time.Sleep(10 * time.Millisecond)
				}
				if !atomic.CompareAndSwapInt32(&firstcalled, 0, ipv4) {
					t.Errorf("the A query was received after the AAAA query !")
				}
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
			case dnsmessage.TypeAAAA:
				atomic.CompareAndSwapInt32(&firstcalled, 0, ipv6)
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
		return r, nil
	}}
	r := Resolver{PreferGo: true, Dial: fake.DialContext}

	conf, err := newResolvConfTest()
	if err != nil {
		t.Fatal(err)
	}
	defer conf.teardown()
	if err := conf.writeAndUpdate([]string{"options single-request"}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"hostname.example.net", "slowipv4.example.net"} {
		firstcalled = 0
		_, err := r.LookupIPAddr(context.Background(), name)
		if err != nil {
			t.Error(err)
		}
	}
}

// Issue 29358. Add configuration knob to force TCP-only DNS requests in the pure Go resolver.
func TestDNSUseTCP(t *testing.T) {
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
				t.Fatal("udp protocol was used instead of tcp")
			}
			return r, nil
		},
	}
	r := Resolver{PreferGo: true, Dial: fake.DialContext}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, _, err := r.exchange(ctx, "0.0.0.0", mustQuestion("com.", dnsmessage.TypeALL, dnsmessage.ClassINET), time.Second, useTCPOnly, false)
	if err != nil {
		t.Fatal("exchange failed:", err)
	}
}

func TestDNSUseTCPTruncated(t *testing.T) {
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
				Answers: []dnsmessage.Resource{
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
				},
			}
			if n == "udp" {
				t.Fatal("udp protocol was used instead of tcp")
			}
			return r, nil
		},
	}
	r := Resolver{PreferGo: true, Dial: fake.DialContext}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p, _, err := r.exchange(ctx, "0.0.0.0", mustQuestion("com.", dnsmessage.TypeALL, dnsmessage.ClassINET), time.Second, useTCPOnly, false)
	if err != nil {
		t.Fatal("exchange failed:", err)
	}
	a, err := p.AllAnswers()
	if err != nil {
		t.Fatalf("unexpected error %v getting all answers", err)
	}
	if len(a) != 1 {
		t.Fatalf("got %d answers; want 1", len(a))
	}
}

// Issue 34660: PTR response with non-PTR answers should ignore non-PTR
func TestPTRandNonPTR(t *testing.T) {
	fake := fakeDNSServer{
		rh: func(n, _ string, q dnsmessage.Message, _ time.Time) (dnsmessage.Message, error) {
			r := dnsmessage.Message{
				Header: dnsmessage.Header{
					ID:       q.Header.ID,
					Response: true,
					RCode:    dnsmessage.RCodeSuccess,
				},
				Questions: q.Questions,
				Answers: []dnsmessage.Resource{
					{
						Header: dnsmessage.ResourceHeader{
							Name:  q.Questions[0].Name,
							Type:  dnsmessage.TypePTR,
							Class: dnsmessage.ClassINET,
						},
						Body: &dnsmessage.PTRResource{
							PTR: dnsmessage.MustNewName("golang.org."),
						},
					},
					{
						Header: dnsmessage.ResourceHeader{
							Name:  q.Questions[0].Name,
							Type:  dnsmessage.TypeTXT,
							Class: dnsmessage.ClassINET,
						},
						Body: &dnsmessage.TXTResource{
							TXT: []string{"PTR 8 6 60 ..."}, // fake RRSIG
						},
					},
				},
			}
			return r, nil
		},
	}
	r := Resolver{PreferGo: true, Dial: fake.DialContext}
	names, err := r.lookupAddr(context.Background(), "192.0.2.123")
	if err != nil {
		t.Fatalf("LookupAddr: %v", err)
	}
	if want := []string{"golang.org."}; !slices.Equal(names, want) {
		t.Errorf("names = %q; want %q", names, want)
	}
}

func TestCVE202133195(t *testing.T) {
	fake := fakeDNSServer{
		rh: func(n, _ string, q dnsmessage.Message, _ time.Time) (dnsmessage.Message, error) {
			r := dnsmessage.Message{
				Header: dnsmessage.Header{
					ID:                 q.Header.ID,
					Response:           true,
					RCode:              dnsmessage.RCodeSuccess,
					RecursionAvailable: true,
				},
				Questions: q.Questions,
			}
			switch q.Questions[0].Type {
			case dnsmessage.TypeCNAME:
				r.Answers = []dnsmessage.Resource{}
			case dnsmessage.TypeA: // CNAME lookup uses a A/AAAA as a proxy
				r.Answers = append(r.Answers,
					dnsmessage.Resource{
						Header: dnsmessage.ResourceHeader{
							Name:   dnsmessage.MustNewName("<html>.golang.org."),
							Type:   dnsmessage.TypeA,
							Class:  dnsmessage.ClassINET,
							Length: 4,
						},
						Body: &dnsmessage.AResource{
							A: TestAddr,
						},
					},
				)
			case dnsmessage.TypeSRV:
				n := q.Questions[0].Name
				if n.String() == "_hdr._tcp.golang.org." {
					n = dnsmessage.MustNewName("<html>.golang.org.")
				}
				r.Answers = append(r.Answers,
					dnsmessage.Resource{
						Header: dnsmessage.ResourceHeader{
							Name:   n,
							Type:   dnsmessage.TypeSRV,
							Class:  dnsmessage.ClassINET,
							Length: 4,
						},
						Body: &dnsmessage.SRVResource{
							Target: dnsmessage.MustNewName("<html>.golang.org."),
						},
					},
					dnsmessage.Resource{
						Header: dnsmessage.ResourceHeader{
							Name:   n,
							Type:   dnsmessage.TypeSRV,
							Class:  dnsmessage.ClassINET,
							Length: 4,
						},
						Body: &dnsmessage.SRVResource{
							Target: dnsmessage.MustNewName("good.golang.org."),
						},
					},
				)
			case dnsmessage.TypeMX:
				r.Answers = append(r.Answers,
					dnsmessage.Resource{
						Header: dnsmessage.ResourceHeader{
							Name:   dnsmessage.MustNewName("<html>.golang.org."),
							Type:   dnsmessage.TypeMX,
							Class:  dnsmessage.ClassINET,
							Length: 4,
						},
						Body: &dnsmessage.MXResource{
							MX: dnsmessage.MustNewName("<html>.golang.org."),
						},
					},
					dnsmessage.Resource{
						Header: dnsmessage.ResourceHeader{
							Name:   dnsmessage.MustNewName("good.golang.org."),
							Type:   dnsmessage.TypeMX,
							Class:  dnsmessage.ClassINET,
							Length: 4,
						},
						Body: &dnsmessage.MXResource{
							MX: dnsmessage.MustNewName("good.golang.org."),
						},
					},
				)
			case dnsmessage.TypeNS:
				r.Answers = append(r.Answers,
					dnsmessage.Resource{
						Header: dnsmessage.ResourceHeader{
							Name:   dnsmessage.MustNewName("<html>.golang.org."),
							Type:   dnsmessage.TypeNS,
							Class:  dnsmessage.ClassINET,
							Length: 4,
						},
						Body: &dnsmessage.NSResource{
							NS: dnsmessage.MustNewName("<html>.golang.org."),
						},
					},
					dnsmessage.Resource{
						Header: dnsmessage.ResourceHeader{
							Name:   dnsmessage.MustNewName("good.golang.org."),
							Type:   dnsmessage.TypeNS,
							Class:  dnsmessage.ClassINET,
							Length: 4,
						},
						Body: &dnsmessage.NSResource{
							NS: dnsmessage.MustNewName("good.golang.org."),
						},
					},
				)
			case dnsmessage.TypePTR:
				r.Answers = append(r.Answers,
					dnsmessage.Resource{
						Header: dnsmessage.ResourceHeader{
							Name:   dnsmessage.MustNewName("<html>.golang.org."),
							Type:   dnsmessage.TypePTR,
							Class:  dnsmessage.ClassINET,
							Length: 4,
						},
						Body: &dnsmessage.PTRResource{
							PTR: dnsmessage.MustNewName("<html>.golang.org."),
						},
					},
					dnsmessage.Resource{
						Header: dnsmessage.ResourceHeader{
							Name:   dnsmessage.MustNewName("good.golang.org."),
							Type:   dnsmessage.TypePTR,
							Class:  dnsmessage.ClassINET,
							Length: 4,
						},
						Body: &dnsmessage.PTRResource{
							PTR: dnsmessage.MustNewName("good.golang.org."),
						},
					},
				)
			}
			return r, nil
		},
	}

	r := Resolver{PreferGo: true, Dial: fake.DialContext}
	// Change the default resolver to match our manipulated resolver
	originalDefault := DefaultResolver
	DefaultResolver = &r
	defer func() { DefaultResolver = originalDefault }()
	// Redirect host file lookups.
	defer func(orig string) { hostsFilePath = orig }(hostsFilePath)
	hostsFilePath = "testdata/hosts"

	tests := []struct {
		name string
		f    func(*testing.T)
	}{
		{
			name: "CNAME",
			f: func(t *testing.T) {
				expectedErr := &DNSError{Err: errMalformedDNSRecordsDetail, Name: "golang.org"}
				_, err := r.LookupCNAME(context.Background(), "golang.org")
				if err.Error() != expectedErr.Error() {
					t.Fatalf("unexpected error: %s", err)
				}
				_, err = LookupCNAME("golang.org")
				if err.Error() != expectedErr.Error() {
					t.Fatalf("unexpected error: %s", err)
				}
			},
		},
		{
			name: "SRV (bad record)",
			f: func(t *testing.T) {
				expected := []*SRV{
					{
						Target: "good.golang.org.",
					},
				}
				expectedErr := &DNSError{Err: errMalformedDNSRecordsDetail, Name: "golang.org"}
				_, records, err := r.LookupSRV(context.Background(), "target", "tcp", "golang.org")
				if err.Error() != expectedErr.Error() {
					t.Fatalf("unexpected error: %s", err)
				}
				if !reflect.DeepEqual(records, expected) {
					t.Error("Unexpected record set")
				}
				_, records, err = LookupSRV("target", "tcp", "golang.org")
				if err.Error() != expectedErr.Error() {
					t.Errorf("unexpected error: %s", err)
				}
				if !reflect.DeepEqual(records, expected) {
					t.Error("Unexpected record set")
				}
			},
		},
		{
			name: "SRV (bad header)",
			f: func(t *testing.T) {
				_, _, err := r.LookupSRV(context.Background(), "hdr", "tcp", "golang.org.")
				if expected := "lookup golang.org.: SRV header name is invalid"; err == nil || err.Error() != expected {
					t.Errorf("Resolver.LookupSRV returned unexpected error, got %q, want %q", err, expected)
				}
				_, _, err = LookupSRV("hdr", "tcp", "golang.org.")
				if expected := "lookup golang.org.: SRV header name is invalid"; err == nil || err.Error() != expected {
					t.Errorf("LookupSRV returned unexpected error, got %q, want %q", err, expected)
				}
			},
		},
		{
			name: "MX",
			f: func(t *testing.T) {
				expected := []*MX{
					{
						Host: "good.golang.org.",
					},
				}
				expectedErr := &DNSError{Err: errMalformedDNSRecordsDetail, Name: "golang.org"}
				records, err := r.LookupMX(context.Background(), "golang.org")
				if err.Error() != expectedErr.Error() {
					t.Fatalf("unexpected error: %s", err)
				}
				if !reflect.DeepEqual(records, expected) {
					t.Error("Unexpected record set")
				}
				records, err = LookupMX("golang.org")
				if err.Error() != expectedErr.Error() {
					t.Fatalf("unexpected error: %s", err)
				}
				if !reflect.DeepEqual(records, expected) {
					t.Error("Unexpected record set")
				}
			},
		},
		{
			name: "NS",
			f: func(t *testing.T) {
				expected := []*NS{
					{
						Host: "good.golang.org.",
					},
				}
				expectedErr := &DNSError{Err: errMalformedDNSRecordsDetail, Name: "golang.org"}
				records, err := r.LookupNS(context.Background(), "golang.org")
				if err.Error() != expectedErr.Error() {
					t.Fatalf("unexpected error: %s", err)
				}
				if !reflect.DeepEqual(records, expected) {
					t.Error("Unexpected record set")
				}
				records, err = LookupNS("golang.org")
				if err.Error() != expectedErr.Error() {
					t.Fatalf("unexpected error: %s", err)
				}
				if !reflect.DeepEqual(records, expected) {
					t.Error("Unexpected record set")
				}
			},
		},
		{
			name: "Addr",
			f: func(t *testing.T) {
				expected := []string{"good.golang.org."}
				expectedErr := &DNSError{Err: errMalformedDNSRecordsDetail, Name: "192.0.2.42"}
				records, err := r.LookupAddr(context.Background(), "192.0.2.42")
				if err.Error() != expectedErr.Error() {
					t.Fatalf("unexpected error: %s", err)
				}
				if !slices.Equal(records, expected) {
					t.Error("Unexpected record set")
				}
				records, err = LookupAddr("192.0.2.42")
				if err.Error() != expectedErr.Error() {
					t.Fatalf("unexpected error: %s", err)
				}
				if !slices.Equal(records, expected) {
					t.Error("Unexpected record set")
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, tc.f)
	}

}

func TestNullMX(t *testing.T) {
	fake := fakeDNSServer{
		rh: func(n, _ string, q dnsmessage.Message, _ time.Time) (dnsmessage.Message, error) {
			r := dnsmessage.Message{
				Header: dnsmessage.Header{
					ID:       q.Header.ID,
					Response: true,
					RCode:    dnsmessage.RCodeSuccess,
				},
				Questions: q.Questions,
				Answers: []dnsmessage.Resource{
					{
						Header: dnsmessage.ResourceHeader{
							Name:  q.Questions[0].Name,
							Type:  dnsmessage.TypeMX,
							Class: dnsmessage.ClassINET,
						},
						Body: &dnsmessage.MXResource{
							MX: dnsmessage.MustNewName("."),
						},
					},
				},
			}
			return r, nil
		},
	}
	r := Resolver{PreferGo: true, Dial: fake.DialContext}
	rrset, err := r.LookupMX(context.Background(), "golang.org")
	if err != nil {
		t.Fatalf("LookupMX: %v", err)
	}
	if want := []*MX{&MX{Host: "."}}; !reflect.DeepEqual(rrset, want) {
		records := []string{}
		for _, rr := range rrset {
			records = append(records, fmt.Sprintf("%v", rr))
		}
		t.Errorf("records = [%v]; want [%v]", strings.Join(records, " "), want[0])
	}
}

func TestRootNS(t *testing.T) {
	// See https://golang.org/issue/45715.
	fake := fakeDNSServer{
		rh: func(n, _ string, q dnsmessage.Message, _ time.Time) (dnsmessage.Message, error) {
			r := dnsmessage.Message{
				Header: dnsmessage.Header{
					ID:       q.Header.ID,
					Response: true,
					RCode:    dnsmessage.RCodeSuccess,
				},
				Questions: q.Questions,
				Answers: []dnsmessage.Resource{
					{
						Header: dnsmessage.ResourceHeader{
							Name:  q.Questions[0].Name,
							Type:  dnsmessage.TypeNS,
							Class: dnsmessage.ClassINET,
						},
						Body: &dnsmessage.NSResource{
							NS: dnsmessage.MustNewName("i.root-servers.net."),
						},
					},
				},
			}
			return r, nil
		},
	}
	r := Resolver{PreferGo: true, Dial: fake.DialContext}
	rrset, err := r.LookupNS(context.Background(), ".")
	if err != nil {
		t.Fatalf("LookupNS: %v", err)
	}
	if want := []*NS{&NS{Host: "i.root-servers.net."}}; !reflect.DeepEqual(rrset, want) {
		records := []string{}
		for _, rr := range rrset {
			records = append(records, fmt.Sprintf("%v", rr))
		}
		t.Errorf("records = [%v]; want [%v]", strings.Join(records, " "), want[0])
	}
}

func TestGoLookupIPCNAMEOrderHostsAliasesFilesOnlyMode(t *testing.T) {
	defer func(orig string) { hostsFilePath = orig }(hostsFilePath)
	hostsFilePath = "testdata/aliases"
	mode := hostLookupFiles

	for _, v := range lookupStaticHostAliasesTest {
		testGoLookupIPCNAMEOrderHostsAliases(t, mode, v.lookup, absDomainName(v.res))
	}
}

func TestGoLookupIPCNAMEOrderHostsAliasesFilesDNSMode(t *testing.T) {
	defer func(orig string) { hostsFilePath = orig }(hostsFilePath)
	hostsFilePath = "testdata/aliases"
	mode := hostLookupFilesDNS

	for _, v := range lookupStaticHostAliasesTest {
		testGoLookupIPCNAMEOrderHostsAliases(t, mode, v.lookup, absDomainName(v.res))
	}
}

var goLookupIPCNAMEOrderDNSFilesModeTests = []struct {
	lookup, res string
}{
	// 127.0.1.1
	{"invalid.invalid", "invalid.test"},
}

func TestGoLookupIPCNAMEOrderHostsAliasesDNSFilesMode(t *testing.T) {
	defer func(orig string) { hostsFilePath = orig }(hostsFilePath)
	hostsFilePath = "testdata/aliases"
	mode := hostLookupDNSFiles

	for _, v := range goLookupIPCNAMEOrderDNSFilesModeTests {
		testGoLookupIPCNAMEOrderHostsAliases(t, mode, v.lookup, absDomainName(v.res))
	}
}

func testGoLookupIPCNAMEOrderHostsAliases(t *testing.T, mode hostLookupOrder, lookup, lookupRes string) {
	fake := fakeDNSServer{
		rh: func(_, _ string, q dnsmessage.Message, _ time.Time) (dnsmessage.Message, error) {
			var answers []dnsmessage.Resource

			if mode != hostLookupDNSFiles {
				t.Fatal("received unexpected DNS query")
			}

			return dnsmessage.Message{
				Header: dnsmessage.Header{
					ID:       q.Header.ID,
					Response: true,
				},
				Questions: []dnsmessage.Question{q.Questions[0]},
				Answers:   answers,
			}, nil
		},
	}

	r := Resolver{PreferGo: true, Dial: fake.DialContext}
	ins := []string{lookup, absDomainName(lookup), strings.ToLower(lookup), strings.ToUpper(lookup)}
	for _, in := range ins {
		_, res, err := r.goLookupIPCNAMEOrder(context.Background(), "ip", in, mode, nil)
		if err != nil {
			t.Errorf("expected err == nil, but got error: %v", err)
		}
		if res.String() != lookupRes {
			t.Errorf("goLookupIPCNAMEOrder(%v): got %v, want %v", in, res, lookupRes)
		}
	}
}

// Test that we advertise support for a larger DNS packet size.
// This isn't a great test as it just tests the dnsmessage package
// against itself.
func TestDNSPacketSize(t *testing.T) {
	t.Run("enabled", func(t *testing.T) {
		testDNSPacketSize(t, false)
	})
	t.Run("disabled", func(t *testing.T) {
		testDNSPacketSize(t, true)
	})
}

func testDNSPacketSize(t *testing.T, disable bool) {
	fake := fakeDNSServer{
		rh: func(_, _ string, q dnsmessage.Message, _ time.Time) (dnsmessage.Message, error) {
			if disable {
				if len(q.Additionals) > 0 {
					t.Error("unexpected additional record")
				}
			} else {
				if len(q.Additionals) == 0 {
					t.Error("missing EDNS record")
				} else if opt, ok := q.Additionals[0].Body.(*dnsmessage.OPTResource); !ok {
					t.Errorf("additional record type %T, expected OPTResource", q.Additionals[0])
				} else if len(opt.Options) != 0 {
					t.Errorf("found %d Options, expected none", len(opt.Options))
				} else {
					got := int(q.Additionals[0].Header.Class)
					t.Logf("EDNS packet size == %d", got)
					if got != maxDNSPacketSize {
						t.Errorf("EDNS packet size == %d, want %d", got, maxDNSPacketSize)
					}
				}
			}

			// Hand back a dummy answer to verify that
			// LookupIPAddr completes.
			r := dnsmessage.Message{
				Header: dnsmessage.Header{
					ID:       q.Header.ID,
					Response: true,
					RCode:    dnsmessage.RCodeSuccess,
				},
				Questions: q.Questions,
			}
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
			return r, nil
		},
	}

	if disable {
		t.Setenv("GODEBUG", "netedns0=0")
	}

	r := &Resolver{PreferGo: true, Dial: fake.DialContext}
	if _, err := r.LookupIPAddr(context.Background(), "go.dev"); err != nil {
		t.Errorf("lookup failed: %v", err)
	}
}

func TestLongDNSNames(t *testing.T) {
	const longDNSsuffix = ".go.dev."
	const longDNSsuffixNoEndingDot = ".go.dev"

	var longDNSPrefix = strings.Repeat("verylongdomainlabel.", 20)

	var longDNSNamesTests = []struct {
		req  string
		fail bool
	}{
		{req: longDNSPrefix[:255-len(longDNSsuffix)] + longDNSsuffix, fail: true},
		{req: longDNSPrefix[:254-len(longDNSsuffix)] + longDNSsuffix},
		{req: longDNSPrefix[:253-len(longDNSs
"""




```