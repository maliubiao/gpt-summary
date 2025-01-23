Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Understanding of the Goal:**

The request asks for the functionality of the provided Go code, examples of its usage, potential errors, and inferences about the Go feature it implements. The file path `go/src/net/netip/netip_pkg_test.go` strongly suggests this is a test file for a `netip` package.

**2. Identifying Key Structures and Functions:**

Scanning the code immediately reveals key types and functions:

* **`Prefix`:**  Represents an IP address and a prefix length (e.g., "192.168.1.0/24").
* **`Addr`:** Represents an IP address.
* **`AddrPort`:** Represents an IP address and a port number.
* **`mustPrefix`, `mustIP`:** Helper functions for parsing prefixes and IPs, likely panicking on errors (as they are used in test setup).
* **`TestPrefixValid`:**  Clearly tests the validity of `Prefix` values based on the address and prefix length.
* **`TestIPNextPrev`:**  Tests functions to get the next and previous IP addresses.
* **`BenchmarkIPNextPrev`:** Benchmarks the `Next` and `Prev` functions.
* **`TestIPBitLen`:** Tests getting the bit length of an IP address (32 for IPv4, 128 for IPv6).
* **`TestPrefixContains`:** Tests if an IP address is contained within a given prefix.
* **`TestParseIPError`:** Tests error handling when parsing invalid IP address strings.
* **`TestParseAddrPort`:** Tests parsing strings into `AddrPort` values.
* **`TestAddrPortMarshalUnmarshal`:** Tests JSON marshaling and unmarshaling of `AddrPort`.
* **`testAppendToMarshal`:** A helper function to compare `AppendTo` and `MarshalText` output.
* **`TestIPv6Accessor`:**  Tests accessing individual bytes of an IPv6 address.

**3. Deductive Reasoning about the `netip` Package:**

Based on the tested functions and types, we can infer that the `netip` package provides:

* **Basic IP Address Representation:** The `Addr` type is central to this.
* **Prefix Representation:** The `Prefix` type allows representing IP networks or subnets.
* **Address and Port Combinations:**  The `AddrPort` type is for network endpoints.
* **IP Address Manipulation:**  Functions like `Next` and `Prev` suggest basic IP address arithmetic.
* **IP Address Metadata:**  The `BitLen` function indicates access to information about the IP address type (IPv4 or IPv6).
* **Network Containment Checks:** The `Contains` function on `Prefix` allows determining if an IP belongs to a network.
* **Parsing from Strings:** Functions like `ParseAddr` and `ParseAddrPort` are essential for converting string representations to the internal types.
* **String Conversion:** The existence of `String()` methods (implicitly tested) is likely.
* **Serialization:** The tests for JSON marshaling (`json.Marshal`, `json.Unmarshal`) and `encoding.TextMarshaler` imply support for serializing these types.

**4. Formulating Examples and Explanations:**

With the understanding of the functionality, the next step is to create illustrative examples:

* **`Prefix` Validity:** Show cases of valid and invalid prefix lengths for IPv4 and IPv6.
* **Next/Previous IP:** Demonstrate the behavior for common IP transitions.
* **`Contains`:**  Show examples of an IP being inside and outside a prefix.
* **Parsing Errors:**  Illustrate common mistakes when providing IP strings.
* **`AddrPort`:**  Demonstrate parsing and the string representation.

**5. Identifying Potential User Errors:**

Based on the tests, some common mistakes become apparent:

* **Invalid Prefix Lengths:** Providing a prefix length outside the valid range (0-32 for IPv4, 0-128 for IPv6).
* **Incorrect IP String Formats:** Errors in syntax, invalid characters, or out-of-range values.
* **Zone Handling:** While the tests mention ignoring zones, it's worth noting that users might expect zone information to be fully handled. (Though the tests show it's deliberately ignored in `Contains` for now).
* **Port Number Range:**  Incorrect port numbers (too large or negative).

**6. Structuring the Answer:**

Finally, the information needs to be organized logically, following the prompt's requirements:

* Start with a summary of the file's purpose (testing the `netip` package).
* List the key functionalities as identified.
* Provide Go code examples for each functionality.
* Explain the code examples, including assumptions and outputs.
* Discuss potential user errors with examples.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Focus solely on the individual test functions.
* **Correction:** Realize the need to synthesize the information to understand the overall purpose and features of the *underlying* `netip` package being tested.
* **Initial thought:** Just list the test cases as functionalities.
* **Correction:** Group related tests into higher-level functionalities (e.g., the `TestPrefixValid` tests are related to the broader concept of prefix validity).
* **Initial thought:** Directly translate test names into functionality descriptions.
* **Correction:** Rephrase descriptions to be more user-friendly and explanatory. For example, "Tests IP bit length" becomes "确定IP地址的位数".

By following this thought process, breaking down the code, deducing the package's purpose, and structuring the information clearly, we can arrive at a comprehensive and accurate answer to the prompt.
这段代码是 Go 语言标准库 `netip` 包的一部分，它的主要功能是测试 `netip` 包中关于 IP 地址和网络前缀（Prefix）的功能。更具体地说，这个测试文件 `netip_pkg_test.go` 针对的是 `Prefix` 和 `Addr` 这两个核心类型及其相关方法。

下面我将列举其主要功能，并尝试推理出它测试的 Go 语言功能，并给出相应的代码示例。

**主要功能:**

1. **测试 `Prefix` 的有效性 (`TestPrefixValid`)**:
   - 验证创建的 `Prefix` 结构的有效性，主要检查 prefix length 是否在合法范围内 (IPv4: 0-32, IPv6: 0-128)。
   - 验证对于无效的 prefix length，`IsValid()` 方法返回 `false`。
   - 验证对于同一个 IP 地址，只有一个无效的 `Prefix` 表示形式（prefix length 为 -1）。

2. **测试 IP 地址的 `Next()` 和 `Prev()` 方法 (`TestIPNextPrev`)**:
   - 验证获取 IP 地址的下一个和上一个 IP 地址的功能。
   - 边界情况测试，例如 IPv4 的 `0.0.0.0` 的上一个和 `255.255.255.255` 的下一个，以及 IPv6 的 `::` 和 `ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff` 的情况。

3. **性能基准测试 `Next()` 和 `Prev()` 方法 (`BenchmarkIPNextPrev`)**:
   - 用于评估 `Next()` 和 `Prev()` 方法的性能。

4. **测试获取 IP 地址的位数 (`TestIPBitLen`)**:
   - 验证 `BitLen()` 方法能够正确返回 IPv4 (32) 和 IPv6 (128) 地址的位数。

5. **测试前缀包含 IP 地址的功能 (`TestPrefixContains`)**:
   - 验证 `Prefix` 的 `Contains()` 方法能够正确判断给定的 IP 地址是否属于该前缀。
   - 包括各种边界情况和错误情况的测试，例如无效的 Prefix、不同 IP 地址族之间的包含关系等。

6. **测试解析 IP 地址字符串时的错误处理 (`TestParseIPError`)**:
   - 验证 `ParseAddr()` 函数在解析无效 IP 地址字符串时能够返回正确的错误类型和错误信息。

7. **测试解析带端口的 IP 地址字符串 (`TestParseAddrPort`)**:
   - 验证 `ParseAddrPort()` 函数能够正确解析 "IP:端口" 格式的字符串，并创建 `AddrPort` 结构。
   - 测试了合法的 IPv4 和 IPv6 地址以及端口号。
   - 同时测试了 `AddrPort` 结构的 `String()` 方法，以及 JSON 序列化和反序列化的功能。

8. **测试 `AddrPort` 结构的 JSON 序列化和反序列化 (`TestAddrPortMarshalUnmarshal`)**:
   - 进一步测试 `AddrPort` 结构的 JSON 序列化和反序列化，包括空字符串的情况。

9. **测试 `AppendTo` 和 `MarshalText` 方法的一致性 (`testAppendToMarshal`)**:
   - 这是一个辅助测试函数，用于确保实现了 `encoding.TextMarshaler` 接口的类型的 `AppendTo` 方法和 `MarshalText` 方法返回相同的结果。

10. **测试访问 IPv6 地址的单个字节 (`TestIPv6Accessor`)**:
    - 验证通过 `v6()` 方法可以访问 IPv6 地址的特定字节。

**推理 `netip` 包实现的 Go 语言功能:**

根据测试内容，可以推断出 `netip` 包旨在提供一种更高效、更轻量级的 IP 地址和网络前缀的表示和操作方式。它可能旨在替代或补充标准库 `net` 包中的 `net.IP` 和 `net.IPNet` 类型，尤其是在对性能有较高要求的场景下。

**Go 代码示例:**

```go
package main

import (
	"fmt"
	"net/netip"
)

func main() {
	// 演示 Prefix 的有效性
	prefix := netip.MustParsePrefix("192.168.1.0/24")
	fmt.Println("Prefix:", prefix, "IsValid:", prefix.IsValid()) // Output: Prefix: 192.168.1.0/24 IsValid: true

	invalidPrefix := netip.PrefixFrom(netip.MustParseAddr("192.168.1.1"), 33)
	fmt.Println("Invalid Prefix:", invalidPrefix, "IsValid:", invalidPrefix.IsValid()) // Output: Invalid Prefix: 192.168.1.1/-1 IsValid: false

	// 演示 IP 地址的 Next 和 Prev
	ip := netip.MustParseAddr("192.168.1.10")
	nextIP := ip.Next()
	prevIP := ip.Prev()
	fmt.Println("IP:", ip, "Next:", nextIP, "Prev:", prevIP) // Output: IP: 192.168.1.10 Next: 192.168.1.11 Prev: 192.168.1.9

	// 演示 Prefix 的 Contains 方法
	ipToCheck := netip.MustParseAddr("192.168.1.20")
	contains := prefix.Contains(ipToCheck)
	fmt.Println("Prefix:", prefix, "Contains:", ipToCheck, ":", contains) // Output: Prefix: 192.168.1.0/24 Contains: 192.168.1.20 : true

	outsideIP := netip.MustParseAddr("192.168.2.1")
	containsOutside := prefix.Contains(outsideIP)
	fmt.Println("Prefix:", prefix, "Contains:", outsideIP, ":", containsOutside) // Output: Prefix: 192.168.1.0/24 Contains: 192.168.2.1 : false

	// 演示 ParseAddrPort
	addrPort, err := netip.ParseAddrPort("10.0.0.1:8080")
	if err != nil {
		fmt.Println("Error parsing AddrPort:", err)
	} else {
		fmt.Println("AddrPort:", addrPort) // Output: AddrPort: 10.0.0.1:8080
	}
}
```

**假设的输入与输出 (针对代码推理部分):**

* **`TestPrefixValid`**:
    * **输入:** `PrefixFrom(mustIP("192.168.1.1"), 24)`
    * **输出:** `IsValid()` 返回 `true`
    * **输入:** `PrefixFrom(mustIP("2001:db8::1"), 129)`
    * **输出:** `IsValid()` 返回 `false`

* **`TestIPNextPrev`**:
    * **输入:** `mustIP("192.168.1.255")`
    * **调用:** `Next()`
    * **输出:** `192.168.2.0`
    * **输入:** `mustIP("0.0.0.1")`
    * **调用:** `Prev()`
    * **输出:** `0.0.0.0`

* **`TestPrefixContains`**:
    * **输入:** `mustPrefix("10.0.0.0/8")`, `mustIP("10.1.2.3")`
    * **输出:** `Contains()` 返回 `true`
    * **输入:** `mustPrefix("fe80::/10")`, `mustIP("fe80::1234")`
    * **输出:** `Contains()` 返回 `true`
    * **输入:** `mustPrefix("192.168.1.0/24")`, `mustIP("192.168.2.1")`
    * **输出:** `Contains()` 返回 `false`

**命令行参数的具体处理:**

这段代码本身是测试代码，不涉及命令行参数的处理。`netip` 包作为库，其功能通常通过 Go 代码调用来使用，而不是通过命令行参数。

**使用者易犯错的点:**

1. **错误的 Prefix Length:**  使用 `PrefixFrom` 创建 `Prefix` 时，容易提供超出 IP 地址族范围的 prefix length。例如，为 IPv4 地址设置大于 32 的 prefix length，或者为 IPv6 地址设置大于 128 的 prefix length。

   ```go
   // 错误示例
   invalidPrefixV4 := netip.PrefixFrom(netip.MustParseAddr("10.0.0.1"), 33)
   invalidPrefixV6 := netip.PrefixFrom(netip.MustParseAddr("::1"), 129)
   ```

2. **解析 IP 地址字符串的格式错误:** `ParseAddr` 和 `ParseAddrPort` 函数对输入字符串的格式有严格要求。不符合要求的字符串会导致解析失败。

   ```go
   // 错误示例
   _, err := netip.ParseAddr("192.168.1") // 缺少最后的段
   if err != nil {
       fmt.Println("解析错误:", err)
   }

   _, err = netip.ParseAddrPort("10.0.0.1:65536") // 端口号超出范围
   if err != nil {
       fmt.Println("解析错误:", err)
   }
   ```

3. **混淆 `Addr` 和 `Prefix` 类型:**  `Contains` 方法是 `Prefix` 类型的方法，不能直接在 `Addr` 类型上调用。

   ```go
   ip := netip.MustParseAddr("192.168.1.1")
   // 错误示例：Cannot call method Contains on type netip.Addr
   // ip.Contains(netip.MustParseAddr("192.168.1.2"))
   ```

这段测试代码覆盖了 `netip` 包中关于 IP 地址和网络前缀的核心功能，旨在确保这些功能的正确性和健壮性。通过阅读测试代码，可以更好地理解 `netip` 包的使用方式和潜在的错误场景。

### 提示词
```
这是路径为go/src/net/netip/netip_pkg_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2020 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package netip

import (
	"bytes"
	"encoding"
	"encoding/json"
	"strings"
	"testing"
)

var (
	mustPrefix = MustParsePrefix
	mustIP     = MustParseAddr
)

func TestPrefixValid(t *testing.T) {
	v4 := MustParseAddr("1.2.3.4")
	v6 := MustParseAddr("::1")
	tests := []struct {
		ipp  Prefix
		want bool
	}{
		{PrefixFrom(v4, -2), false},
		{PrefixFrom(v4, -1), false},
		{PrefixFrom(v4, 0), true},
		{PrefixFrom(v4, 32), true},
		{PrefixFrom(v4, 33), false},

		{PrefixFrom(v6, -2), false},
		{PrefixFrom(v6, -1), false},
		{PrefixFrom(v6, 0), true},
		{PrefixFrom(v6, 32), true},
		{PrefixFrom(v6, 128), true},
		{PrefixFrom(v6, 129), false},

		{PrefixFrom(Addr{}, -2), false},
		{PrefixFrom(Addr{}, -1), false},
		{PrefixFrom(Addr{}, 0), false},
		{PrefixFrom(Addr{}, 32), false},
		{PrefixFrom(Addr{}, 128), false},
	}
	for _, tt := range tests {
		got := tt.ipp.IsValid()
		if got != tt.want {
			t.Errorf("(%v).IsValid() = %v want %v", tt.ipp, got, tt.want)
		}

		// Test that there is only one invalid Prefix representation per Addr.
		invalid := PrefixFrom(tt.ipp.Addr(), -1)
		if !got && tt.ipp != invalid {
			t.Errorf("(%v == %v) = false, want true", tt.ipp, invalid)
		}
	}
}

var nextPrevTests = []struct {
	ip   Addr
	next Addr
	prev Addr
}{
	{mustIP("10.0.0.1"), mustIP("10.0.0.2"), mustIP("10.0.0.0")},
	{mustIP("10.0.0.255"), mustIP("10.0.1.0"), mustIP("10.0.0.254")},
	{mustIP("127.0.0.1"), mustIP("127.0.0.2"), mustIP("127.0.0.0")},
	{mustIP("254.255.255.255"), mustIP("255.0.0.0"), mustIP("254.255.255.254")},
	{mustIP("255.255.255.255"), Addr{}, mustIP("255.255.255.254")},
	{mustIP("0.0.0.0"), mustIP("0.0.0.1"), Addr{}},
	{mustIP("::"), mustIP("::1"), Addr{}},
	{mustIP("::%x"), mustIP("::1%x"), Addr{}},
	{mustIP("::1"), mustIP("::2"), mustIP("::")},
	{mustIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), Addr{}, mustIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe")},
}

func TestIPNextPrev(t *testing.T) {
	doNextPrev(t)

	for _, ip := range []Addr{
		mustIP("0.0.0.0"),
		mustIP("::"),
	} {
		got := ip.Prev()
		if !got.isZero() {
			t.Errorf("IP(%v).Prev = %v; want zero", ip, got)
		}
	}

	var allFF [16]byte
	for i := range allFF {
		allFF[i] = 0xff
	}

	for _, ip := range []Addr{
		mustIP("255.255.255.255"),
		AddrFrom16(allFF),
	} {
		got := ip.Next()
		if !got.isZero() {
			t.Errorf("IP(%v).Next = %v; want zero", ip, got)
		}
	}
}

func BenchmarkIPNextPrev(b *testing.B) {
	for i := 0; i < b.N; i++ {
		doNextPrev(b)
	}
}

func doNextPrev(t testing.TB) {
	for _, tt := range nextPrevTests {
		gnext, gprev := tt.ip.Next(), tt.ip.Prev()
		if gnext != tt.next {
			t.Errorf("IP(%v).Next = %v; want %v", tt.ip, gnext, tt.next)
		}
		if gprev != tt.prev {
			t.Errorf("IP(%v).Prev = %v; want %v", tt.ip, gprev, tt.prev)
		}
		if !tt.ip.Next().isZero() && tt.ip.Next().Prev() != tt.ip {
			t.Errorf("IP(%v).Next.Prev = %v; want %v", tt.ip, tt.ip.Next().Prev(), tt.ip)
		}
		if !tt.ip.Prev().isZero() && tt.ip.Prev().Next() != tt.ip {
			t.Errorf("IP(%v).Prev.Next = %v; want %v", tt.ip, tt.ip.Prev().Next(), tt.ip)
		}
	}
}

func TestIPBitLen(t *testing.T) {
	tests := []struct {
		ip   Addr
		want int
	}{
		{Addr{}, 0},
		{mustIP("0.0.0.0"), 32},
		{mustIP("10.0.0.1"), 32},
		{mustIP("::"), 128},
		{mustIP("fed0::1"), 128},
		{mustIP("::ffff:10.0.0.1"), 128},
	}
	for _, tt := range tests {
		got := tt.ip.BitLen()
		if got != tt.want {
			t.Errorf("BitLen(%v) = %d; want %d", tt.ip, got, tt.want)
		}
	}
}

func TestPrefixContains(t *testing.T) {
	tests := []struct {
		ipp  Prefix
		ip   Addr
		want bool
	}{
		{mustPrefix("9.8.7.6/0"), mustIP("9.8.7.6"), true},
		{mustPrefix("9.8.7.6/16"), mustIP("9.8.7.6"), true},
		{mustPrefix("9.8.7.6/16"), mustIP("9.8.6.4"), true},
		{mustPrefix("9.8.7.6/16"), mustIP("9.9.7.6"), false},
		{mustPrefix("9.8.7.6/32"), mustIP("9.8.7.6"), true},
		{mustPrefix("9.8.7.6/32"), mustIP("9.8.7.7"), false},
		{mustPrefix("9.8.7.6/32"), mustIP("9.8.7.7"), false},
		{mustPrefix("::1/0"), mustIP("::1"), true},
		{mustPrefix("::1/0"), mustIP("::2"), true},
		{mustPrefix("::1/127"), mustIP("::1"), true},
		{mustPrefix("::1/127"), mustIP("::2"), false},
		{mustPrefix("::1/128"), mustIP("::1"), true},
		{mustPrefix("::1/127"), mustIP("::2"), false},
		// Zones ignored: https://go.dev/issue/51899
		{Prefix{mustIP("1.2.3.4").WithZone("a"), 32}, mustIP("1.2.3.4"), true},
		{Prefix{mustIP("::1").WithZone("a"), 128}, mustIP("::1"), true},
		// invalid IP
		{mustPrefix("::1/0"), Addr{}, false},
		{mustPrefix("1.2.3.4/0"), Addr{}, false},
		// invalid Prefix
		{PrefixFrom(mustIP("::1"), 129), mustIP("::1"), false},
		{PrefixFrom(mustIP("1.2.3.4"), 33), mustIP("1.2.3.4"), false},
		{PrefixFrom(Addr{}, 0), mustIP("1.2.3.4"), false},
		{PrefixFrom(Addr{}, 32), mustIP("1.2.3.4"), false},
		{PrefixFrom(Addr{}, 128), mustIP("::1"), false},
		// wrong IP family
		{mustPrefix("::1/0"), mustIP("1.2.3.4"), false},
		{mustPrefix("1.2.3.4/0"), mustIP("::1"), false},
	}
	for _, tt := range tests {
		got := tt.ipp.Contains(tt.ip)
		if got != tt.want {
			t.Errorf("(%v).Contains(%v) = %v want %v", tt.ipp, tt.ip, got, tt.want)
		}
	}
}

func TestParseIPError(t *testing.T) {
	tests := []struct {
		ip     string
		errstr string
	}{
		{
			ip: "localhost",
		},
		{
			ip:     "500.0.0.1",
			errstr: "field has value >255",
		},
		{
			ip:     "::gggg%eth0",
			errstr: "must have at least one digit",
		},
		{
			ip:     "fe80::1cc0:3e8c:119f:c2e1%",
			errstr: "zone must be a non-empty string",
		},
		{
			ip:     "%eth0",
			errstr: "missing IPv6 address",
		},
	}
	for _, test := range tests {
		t.Run(test.ip, func(t *testing.T) {
			_, err := ParseAddr(test.ip)
			if err == nil {
				t.Fatal("no error")
			}
			if _, ok := err.(parseAddrError); !ok {
				t.Errorf("error type is %T, want parseIPError", err)
			}
			if test.errstr == "" {
				test.errstr = "unable to parse IP"
			}
			if got := err.Error(); !strings.Contains(got, test.errstr) {
				t.Errorf("error is missing substring %q: %s", test.errstr, got)
			}
		})
	}
}

func TestParseAddrPort(t *testing.T) {
	tests := []struct {
		in      string
		want    AddrPort
		wantErr bool
	}{
		{in: "1.2.3.4:1234", want: AddrPort{mustIP("1.2.3.4"), 1234}},
		{in: "1.1.1.1:123456", wantErr: true},
		{in: "1.1.1.1:-123", wantErr: true},
		{in: "[::1]:1234", want: AddrPort{mustIP("::1"), 1234}},
		{in: "[1.2.3.4]:1234", wantErr: true},
		{in: "fe80::1:1234", wantErr: true},
		{in: ":0", wantErr: true}, // if we need to parse this form, there should be a separate function that explicitly allows it
	}
	for _, test := range tests {
		t.Run(test.in, func(t *testing.T) {
			got, err := ParseAddrPort(test.in)
			if err != nil {
				if test.wantErr {
					return
				}
				t.Fatal(err)
			}
			if got != test.want {
				t.Errorf("got %v; want %v", got, test.want)
			}
			if got.String() != test.in {
				t.Errorf("String = %q; want %q", got.String(), test.in)
			}
		})

		t.Run(test.in+"/AppendTo", func(t *testing.T) {
			got, err := ParseAddrPort(test.in)
			if err == nil {
				testAppendToMarshal(t, got)
			}
		})

		// TextMarshal and TextUnmarshal mostly behave like
		// ParseAddrPort and String. Divergent behavior are handled in
		// TestAddrPortMarshalUnmarshal.
		t.Run(test.in+"/Marshal", func(t *testing.T) {
			var got AddrPort
			jsin := `"` + test.in + `"`
			err := json.Unmarshal([]byte(jsin), &got)
			if err != nil {
				if test.wantErr {
					return
				}
				t.Fatal(err)
			}
			if got != test.want {
				t.Errorf("got %v; want %v", got, test.want)
			}
			gotb, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			if string(gotb) != jsin {
				t.Errorf("Marshal = %q; want %q", string(gotb), jsin)
			}
		})
	}
}

func TestAddrPortMarshalUnmarshal(t *testing.T) {
	tests := []struct {
		in   string
		want AddrPort
	}{
		{"", AddrPort{}},
	}

	for _, test := range tests {
		t.Run(test.in, func(t *testing.T) {
			orig := `"` + test.in + `"`

			var ipp AddrPort
			if err := json.Unmarshal([]byte(orig), &ipp); err != nil {
				t.Fatalf("failed to unmarshal: %v", err)
			}

			ippb, err := json.Marshal(ipp)
			if err != nil {
				t.Fatalf("failed to marshal: %v", err)
			}

			back := string(ippb)
			if orig != back {
				t.Errorf("Marshal = %q; want %q", back, orig)
			}

			testAppendToMarshal(t, ipp)
		})
	}
}

type appendMarshaler interface {
	encoding.TextMarshaler
	AppendTo([]byte) []byte
}

// testAppendToMarshal tests that x's AppendTo and MarshalText methods yield the same results.
// x's MarshalText method must not return an error.
func testAppendToMarshal(t *testing.T, x appendMarshaler) {
	t.Helper()
	m, err := x.MarshalText()
	if err != nil {
		t.Fatalf("(%v).MarshalText: %v", x, err)
	}
	a := make([]byte, 0, len(m))
	a = x.AppendTo(a)
	if !bytes.Equal(m, a) {
		t.Errorf("(%v).MarshalText = %q, (%v).AppendTo = %q", x, m, x, a)
	}
}

func TestIPv6Accessor(t *testing.T) {
	var a [16]byte
	for i := range a {
		a[i] = uint8(i) + 1
	}
	ip := AddrFrom16(a)
	for i := range a {
		if got, want := ip.v6(uint8(i)), uint8(i)+1; got != want {
			t.Errorf("v6(%v) = %v; want %v", i, got, want)
		}
	}
}
```