Response:
The user wants me to summarize the functionality of the provided Go code snippet, which is part of the `lookup_test.go` file in the `net` package.

This part of the code focuses on testing the `LookupIP` function with different network types, handling DNS timeouts, testing scenarios where no data is found for a domain, testing the `LookupPort` function, and testing scenarios where a host is not found.

I need to go through each test function and extract its purpose.
这是 `go/src/net/lookup_test.go` 文件的一部分，主要用于测试 Go 语言网络库中域名解析相关的功能。这是第二部分，延续了第一部分对 DNS 查询功能的测试。

**归纳一下它的功能:**

这部分代码主要测试了以下 `net` 包中的 DNS 查询功能：

1. **`TestLookupIP` 函数:**
   - 验证 `LookupIP` 函数在指定网络类型 ("ip", "ip4", "ip6") 下是否能正确解析域名，并返回期望的 IP 地址类型 (IPv4 或 IPv6)。
   - 测试了在不支持 IPv6 的环境下，`LookupIP` 对于 "ip6" 网络的处理（会跳过测试）。
   - 使用 `DefaultResolver` 进行测试，确保默认的解析器工作正常。

2. **`TestDNSTimeout` 函数:**
   - 模拟 DNS 查询超时的情况，验证在超时后是否返回了正确的 `DNSError` 类型错误，并且该错误的 `IsTimeout` 属性为 `true`。
   - 测试了单个和并发的 DNS 查询超时场景。
   - 测试了带有 `context.Context` 的 DNS 查询超时。

3. **`TestLookupNoData` 和 `testLookupNoData` 函数:**
   - 测试当查询的域名没有对应的 A 或 AAAA 记录，但存在其他记录（例如 TXT 记录）时，`LookupHost` 函数是否会返回 `DNSError`，并且 `IsNotFound` 属性为 `true`，错误信息为 "no such host"。
   - 使用了不同的解析器 (default, forced go, forced cgo) 进行测试。
   - 包含了对查询失败进行退避重试的逻辑。

4. **`TestLookupPortNotFound` 函数:**
   - 测试 `LookupPort` 函数在给定的网络协议下查询不存在的服务名称时，是否会返回 `DNSError`，并且 `IsNotFound` 属性为 `true`。

5. **`TestLookupPortDifferentNetwork` 函数:**
   - 测试 `LookupPort` 函数在指定与服务实际协议不符的网络协议时（例如，查询仅支持 TCP 的 "submissions" 服务时使用 UDP），是否会返回 `DNSError`，并且 `IsNotFound` 属性为 `true`。

6. **`TestLookupPortEmptyNetworkString` 和 `TestLookupPortIPNetworkString` 函数:**
   - 测试 `LookupPort` 函数在网络协议参数为空字符串或 "ip" 时是否能正常工作。

7. **`TestLookupNoSuchHost` 函数:**
   - 测试各种 DNS 查询函数（如 `LookupCNAME`, `LookupHost`, `LookupMX`, `LookupNS`, `LookupSRV`, `LookupTXT`）在查询不存在的域名 (NXDOMAIN) 或存在域名但没有请求类型的记录 (NODATA) 时，是否会返回 `DNSError`，并且 `IsNotFound` 属性为 `true`，错误信息为 "no such host"。
   - 使用了不同的解析器进行测试，并包含了对查询失败进行退避重试的逻辑。

8. **`TestDNSErrorUnwrap` 函数:**
   - 测试 `DNSError` 是否正确实现了 `Unwrap` 方法，以便可以使用 `errors.Is` 函数来检查底层的错误，例如 `context.DeadlineExceeded` 或 `context.Canceled`。

总的来说，这部分代码通过大量的测试用例，覆盖了 `net` 包中各种 DNS 查询函数在不同场景下的行为，包括成功的解析、超时、找不到记录、找不到主机等各种异常情况，确保了 DNS 解析功能的健壮性和可靠性。

### 提示词
```
这是路径为go/src/net/lookup_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
case network == "ip6" && !v6Ok:
						t.Skip("IPv6 is not supported")
					}

					// google.com has both A and AAAA records.
					const host = "google.com"
					ips, err := DefaultResolver.LookupIP(context.Background(), network, host)
					if err != nil {
						testenv.SkipFlakyNet(t)
						t.Fatalf("DefaultResolver.LookupIP(%q, %q): failed with unexpected error: %v", network, host, err)
					}

					var v4Addrs []netip.Addr
					var v6Addrs []netip.Addr
					for _, ip := range ips {
						if addr, ok := netip.AddrFromSlice(ip); ok {
							if addr.Is4() {
								v4Addrs = append(v4Addrs, addr)
							} else {
								v6Addrs = append(v6Addrs, addr)
							}
						} else {
							t.Fatalf("IP=%q is neither IPv4 nor IPv6", ip)
						}
					}

					// Check that we got the expected addresses.
					if network == "ip4" || network == "ip" && v4Ok {
						if len(v4Addrs) == 0 {
							t.Errorf("DefaultResolver.LookupIP(%q, %q): no IPv4 addresses", network, host)
						}
					}
					if network == "ip6" || network == "ip" && v6Ok {
						if len(v6Addrs) == 0 {
							t.Errorf("DefaultResolver.LookupIP(%q, %q): no IPv6 addresses", network, host)
						}
					}

					// Check that we didn't get any unexpected addresses.
					if network == "ip6" && len(v4Addrs) > 0 {
						t.Errorf("DefaultResolver.LookupIP(%q, %q): unexpected IPv4 addresses: %v", network, host, v4Addrs)
					}
					if network == "ip4" && len(v6Addrs) > 0 {
						t.Errorf("DefaultResolver.LookupIP(%q, %q): unexpected IPv6 or IPv4-mapped IPv6 addresses: %v", network, host, v6Addrs)
					}
				})
			}
		})
	}
}

// A context timeout should still return a DNSError.
func TestDNSTimeout(t *testing.T) {
	origTestHookLookupIP := testHookLookupIP
	defer func() { testHookLookupIP = origTestHookLookupIP }()
	defer dnsWaitGroup.Wait()

	timeoutHookGo := make(chan bool, 1)
	timeoutHook := func(ctx context.Context, fn func(context.Context, string, string) ([]IPAddr, error), network, host string) ([]IPAddr, error) {
		<-timeoutHookGo
		return nil, context.DeadlineExceeded
	}
	testHookLookupIP = timeoutHook

	checkErr := func(err error) {
		t.Helper()
		if err == nil {
			t.Error("expected an error")
		} else if dnserr, ok := err.(*DNSError); !ok {
			t.Errorf("got error type %T, want %T", err, (*DNSError)(nil))
		} else if !dnserr.IsTimeout {
			t.Errorf("got error %#v, want IsTimeout == true", dnserr)
		} else if isTimeout := dnserr.Timeout(); !isTimeout {
			t.Errorf("got err.Timeout() == %t, want true", isTimeout)
		}
	}

	// Single lookup.
	timeoutHookGo <- true
	_, err := LookupIP("golang.org")
	checkErr(err)

	// Double lookup.
	var err1, err2 error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err1 = LookupIP("golang1.org")
	}()
	go func() {
		defer wg.Done()
		_, err2 = LookupIP("golang1.org")
	}()
	close(timeoutHookGo)
	wg.Wait()
	checkErr(err1)
	checkErr(err2)

	// Double lookup with context.
	timeoutHookGo = make(chan bool)
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err1 = DefaultResolver.LookupIPAddr(ctx, "golang2.org")
	}()
	go func() {
		defer wg.Done()
		_, err2 = DefaultResolver.LookupIPAddr(ctx, "golang2.org")
	}()
	time.Sleep(10 * time.Nanosecond)
	close(timeoutHookGo)
	wg.Wait()
	checkErr(err1)
	checkErr(err2)
	cancel()
}

func TestLookupNoData(t *testing.T) {
	if runtime.GOOS == "plan9" {
		t.Skip("not supported on plan9")
	}

	mustHaveExternalNetwork(t)

	testLookupNoData(t, "default resolver")

	func() {
		defer forceGoDNS()()
		testLookupNoData(t, "forced go resolver")
	}()

	func() {
		defer forceCgoDNS()()
		testLookupNoData(t, "forced cgo resolver")
	}()
}

func testLookupNoData(t *testing.T, prefix string) {
	attempts := 0
	for {
		// Domain that doesn't have any A/AAAA RRs, but has different one (in this case a TXT),
		// so that it returns an empty response without any error codes (NXDOMAIN).
		_, err := LookupHost("golang.rsc.io.")
		if err == nil {
			t.Errorf("%v: unexpected success", prefix)
			return
		}

		var dnsErr *DNSError
		if errors.As(err, &dnsErr) {
			succeeded := true
			if !dnsErr.IsNotFound {
				succeeded = false
				t.Logf("%v: IsNotFound is set to false", prefix)
			}

			if dnsErr.Err != errNoSuchHost.Error() {
				succeeded = false
				t.Logf("%v: error message is not equal to: %v", prefix, errNoSuchHost.Error())
			}

			if succeeded {
				return
			}
		}

		testenv.SkipFlakyNet(t)
		if attempts < len(backoffDuration) {
			dur := backoffDuration[attempts]
			t.Logf("%v: backoff %v after failure %v\n", prefix, dur, err)
			time.Sleep(dur)
			attempts++
			continue
		}

		t.Errorf("%v: unexpected error: %v", prefix, err)
		return
	}
}

func TestLookupPortNotFound(t *testing.T) {
	allResolvers(t, func(t *testing.T) {
		_, err := LookupPort("udp", "_-unknown-service-")
		var dnsErr *DNSError
		if !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

// submissions service is only available through a tcp network, see:
// https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml?search=submissions
var tcpOnlyService = func() string {
	// plan9 does not have submissions service defined in the service database.
	if runtime.GOOS == "plan9" {
		return "https"
	}
	return "submissions"
}()

func TestLookupPortDifferentNetwork(t *testing.T) {
	allResolvers(t, func(t *testing.T) {
		_, err := LookupPort("udp", tcpOnlyService)
		var dnsErr *DNSError
		if !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestLookupPortEmptyNetworkString(t *testing.T) {
	allResolvers(t, func(t *testing.T) {
		_, err := LookupPort("", tcpOnlyService)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestLookupPortIPNetworkString(t *testing.T) {
	allResolvers(t, func(t *testing.T) {
		_, err := LookupPort("ip", tcpOnlyService)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestLookupNoSuchHost(t *testing.T) {
	mustHaveExternalNetwork(t)

	const testNXDOMAIN = "invalid.invalid."
	const testNODATA = "_ldap._tcp.google.com."

	tests := []struct {
		name  string
		query func() error
	}{
		{
			name: "LookupCNAME NXDOMAIN",
			query: func() error {
				_, err := LookupCNAME(testNXDOMAIN)
				return err
			},
		},
		{
			name: "LookupHost NXDOMAIN",
			query: func() error {
				_, err := LookupHost(testNXDOMAIN)
				return err
			},
		},
		{
			name: "LookupHost NODATA",
			query: func() error {
				_, err := LookupHost(testNODATA)
				return err
			},
		},
		{
			name: "LookupMX NXDOMAIN",
			query: func() error {
				_, err := LookupMX(testNXDOMAIN)
				return err
			},
		},
		{
			name: "LookupMX NODATA",
			query: func() error {
				_, err := LookupMX(testNODATA)
				return err
			},
		},
		{
			name: "LookupNS NXDOMAIN",
			query: func() error {
				_, err := LookupNS(testNXDOMAIN)
				return err
			},
		},
		{
			name: "LookupNS NODATA",
			query: func() error {
				_, err := LookupNS(testNODATA)
				return err
			},
		},
		{
			name: "LookupSRV NXDOMAIN",
			query: func() error {
				_, _, err := LookupSRV("unknown", "tcp", testNXDOMAIN)
				return err
			},
		},
		{
			name: "LookupTXT NXDOMAIN",
			query: func() error {
				_, err := LookupTXT(testNXDOMAIN)
				return err
			},
		},
		{
			name: "LookupTXT NODATA",
			query: func() error {
				_, err := LookupTXT(testNODATA)
				return err
			},
		},
	}

	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			allResolvers(t, func(t *testing.T) {
				attempts := 0
				for {
					err := v.query()
					if err == nil {
						t.Errorf("unexpected success")
						return
					}
					if dnsErr, ok := err.(*DNSError); ok {
						succeeded := true
						if !dnsErr.IsNotFound {
							succeeded = false
							t.Log("IsNotFound is set to false")
						}
						if dnsErr.Err != errNoSuchHost.Error() {
							succeeded = false
							t.Logf("error message is not equal to: %v", errNoSuchHost.Error())
						}
						if succeeded {
							return
						}
					}
					testenv.SkipFlakyNet(t)
					if attempts < len(backoffDuration) {
						dur := backoffDuration[attempts]
						t.Logf("backoff %v after failure %v\n", dur, err)
						time.Sleep(dur)
						attempts++
						continue
					}
					t.Errorf("unexpected error: %v", err)
					return
				}
			})
		})
	}
}

func TestDNSErrorUnwrap(t *testing.T) {
	if runtime.GOOS == "plan9" {
		// The Plan 9 implementation of the resolver doesn't use the Dial function yet. See https://go.dev/cl/409234
		t.Skip("skipping on plan9")
	}
	rDeadlineExcceeded := &Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (Conn, error) {
		return nil, context.DeadlineExceeded
	}}
	rCancelled := &Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (Conn, error) {
		return nil, context.Canceled
	}}

	_, err := rDeadlineExcceeded.LookupHost(context.Background(), "test.go.dev")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("errors.Is(err, context.DeadlineExceeded) = false; want = true")
	}

	_, err = rCancelled.LookupHost(context.Background(), "test.go.dev")
	if !errors.Is(err, context.Canceled) {
		t.Errorf("errors.Is(err, context.Canceled) = false; want = true")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = goResolver.LookupHost(ctx, "text.go.dev")
	if !errors.Is(err, context.Canceled) {
		t.Errorf("errors.Is(err, context.Canceled) = false; want = true")
	}
}
```