Response:
Let's break down the thought process to arrive at the explanation of the provided Go code.

1. **Identify the Core Purpose:** The filename `fuzz_test.go` and the function name `FuzzParse` immediately suggest that this code is related to fuzzing. Fuzzing is a technique for testing software by providing it with a large amount of random, unexpected, or invalid input and observing its behavior for crashes or errors.

2. **Understand the Context:** The `package netip_test` and the import of `net/netip` indicate that this fuzzing is specifically targeting the `netip` package in the Go standard library. The `netip` package is likely involved in handling IP addresses and related concepts.

3. **Analyze the `corpus` Variable:** The `corpus` variable is a slice of strings. A quick scan reveals a variety of IP address formats, both valid and invalid, including:
    * Basic IPv4 and IPv6 addresses.
    * Addresses with leading zeros.
    * IPv6 addresses with elided parts (`::`).
    * IPv6 addresses with embedded IPv4 (`::ffff:192.168.140.255`).
    * Addresses with zone specifiers (`%eth0`).
    * Invalid IP address formats (`bad`, `1234`, `1.2.3.`).
    * AddrPort strings (`1.2.3.4:51820`).
    * Prefix strings (`1.2.3.4/24`).

    This confirms the suspicion that the code is about parsing and handling IP addresses. The inclusion of invalid formats reinforces the fuzzing aspect. The `corpus` acts as a seed set for the fuzzer.

4. **Examine the `FuzzParse` Function:**

    * **Seeding the Fuzzer:** The first part of `FuzzParse` iterates through the `corpus` and uses `f.Add(seed)` to add these strings as initial inputs to the fuzzer. This ensures the fuzzer starts with a known set of interesting inputs.

    * **The Fuzzing Loop:** `f.Fuzz(func(t *testing.T, s string) { ... })` is the core of the fuzzing. The fuzzer will generate various mutations of the seed inputs (and potentially completely new inputs) and pass them as the `s` string to the anonymous function.

    * **Parsing Functions:** Inside the fuzzing loop, the code calls `ParseAddr(s)`, `ParseAddrPort(s)`, and `ParsePrefix(s)`. These strongly suggest that the `netip` package provides functions to parse IP addresses, IP addresses with ports, and IP prefixes (IP addresses with subnet masks).

    * **Round Trip Checks:** The code uses `checkStringParseRoundTrip`. This function likely takes a value and a parsing function, converts the value to a string, parses the string back into a value, and checks if the original and parsed values are equal. This verifies that the string representation and parsing are consistent.

    * **Encoding Checks:** The code calls `checkEncoding`. This function likely checks the `encoding.TextMarshaler` and `encoding.BinaryMarshaler` interfaces. These interfaces are standard Go interfaces for converting data to and from text and binary representations. This verifies the serialization and deserialization mechanisms of the `netip` types.

    * **Comparison with `net` Package:** The code compares the results of `netip.ParseAddr` with `net.ParseIP` from the standard `net` package (excluding cases with zones). This is to ensure that the new `netip` package behaves consistently with the older `net` package, where applicable. It checks for agreement in parsing validity, string representations, and various IP address properties (IsGlobalUnicast, IsLoopback, etc.).

    * **`Next()` and `Prev()` Checks:**  The code checks the `Next()` and `Prev()` methods of the `Addr` type. This suggests that `netip.Addr` has methods to get the next and previous IP address in the sequence. The fuzz test verifies that `ip.Next().Prev()` and `ip.Prev().Next()` correctly round trip back to the original IP.

5. **Analyze Helper Functions:** The code includes several helper functions like `checkTextMarshaler`, `checkBinaryMarshaler`, `checkTextMarshalMatchesString`, `checkTextMarshalMatchesAppendTo`, and `checkStringParseRoundTrip`. These are common patterns in Go testing to reduce code duplication and make tests more readable. By looking at their names and what they do (marshal/unmarshal, string conversions), we can infer their purpose in verifying the encoding and string representation of the `netip` types.

6. **Infer Functionality:** Based on the analysis above, we can conclude that `fuzz_test.go` is part of the testing infrastructure for the `netip` package. It uses fuzzing to test the parsing and handling of various IP address, address-port, and prefix string formats, including invalid ones. It also verifies the consistency of string representations, encoding/decoding, and comparisons with the standard `net` package.

7. **Construct the Explanation:** Finally, organize the findings into a clear and structured explanation, covering the main functionalities, code examples, potential areas of confusion, and specifically addressing the prompt's requirements. Provide concrete examples to illustrate the functionality and how it might be used.

This systematic approach, starting with identifying the core purpose and gradually analyzing the code elements, leads to a comprehensive understanding of the provided Go code snippet.
这段Go语言代码是 `net/netip` 包的一部分，专门用于进行模糊测试 (`fuzz testing`)。模糊测试是一种软件测试技术，它向程序提供大量的随机或意外的输入数据，以发现潜在的错误、崩溃或漏洞。

以下是这段代码的主要功能：

1. **模糊测试 `netip` 包的解析功能:**  `FuzzParse` 函数是模糊测试的核心。它利用 Go 的 `testing` 包提供的模糊测试能力，对 `netip` 包中用于解析 IP 地址、带端口的地址以及 IP 前缀的函数进行测试。

2. **测试多种 IP 地址格式的解析:** `corpus` 变量定义了一个包含各种格式 IP 地址、带端口地址和前缀的字符串切片。这些字符串既包含了有效的 IP 地址（IPv4 和 IPv6 的各种形式），也包含了无效的 IP 地址格式（例如，格式错误、超出范围的值等）。这个 `corpus` 作为模糊测试的种子输入。

3. **验证解析函数的正确性:**  `FuzzParse` 函数内部调用了 `netip` 包中的 `ParseAddr`、`ParseAddrPort` 和 `ParsePrefix` 函数，并将模糊测试生成的字符串作为输入。它会检查解析结果是否符合预期。

4. **与 `net` 包的 `net.ParseIP` 进行对比:** 对于不包含 zone 的 IP 地址字符串，代码会将 `netip.ParseAddr` 的结果与标准库 `net` 包中的 `net.ParseIP` 的结果进行对比，以确保 `netip` 包的行为与标准库一致。这包括检查解析是否成功、字符串表示是否相同以及一些 IP 地址属性（如是否是全局单播地址、是否是环回地址等）是否一致。

5. **测试 `Next()` 和 `Prev()` 方法:**  对于解析成功的 IP 地址，代码会测试 `ip.Next()` 和 `ip.Prev()` 方法，以验证获取下一个和上一个 IP 地址的功能是否正常。它会检查 `ip.Next().Prev()` 和 `ip.Prev().Next()` 是否能返回原始的 IP 地址。

6. **验证编码和解码的正确性:**  `checkEncoding` 函数及其调用的辅助函数（如 `checkTextMarshaler`、`checkBinaryMarshaler`）用于验证 `netip` 包中的类型是否正确地实现了 `encoding.TextMarshaler` 和 `encoding.BinaryMarshaler` 接口，即可以正确地进行文本和二进制的序列化和反序列化。

**推理 `netip` 包的 Go 语言功能实现：**

从这段模糊测试代码来看，可以推断出 `netip` 包主要实现了以下 Go 语言功能：

* **IP 地址表示和操作:** 提供了 `Addr` 类型来表示 IP 地址，并提供了例如 `IsValid()`、`Next()`、`Prev()`、`Is4In6()`、`IsGlobalUnicast()` 等方法来检查和操作 IP 地址。
* **带端口的地址表示和操作:** 提供了 `AddrPort` 类型来表示带有端口号的 IP 地址，并可能提供了相应的解析和格式化方法。
* **IP 前缀表示和操作:** 提供了 `Prefix` 类型来表示 IP 地址前缀（IP 地址加上子网掩码长度），并可能提供了相应的解析和格式化方法。
* **字符串解析:** 提供了 `ParseAddr`、`ParseAddrPort` 和 `ParsePrefix` 等函数，用于将字符串解析为对应的 `Addr`、`AddrPort` 和 `Prefix` 类型。
* **文本和二进制编码/解码:**  实现了 `encoding.TextMarshaler` 和 `encoding.BinaryMarshaler` 接口，允许将 `Addr`、`AddrPort` 和 `Prefix` 类型转换为文本和二进制表示，并能从文本和二进制表示恢复。

**Go 代码示例：**

以下是一些基于代码推断的 `netip` 包的使用示例：

```go
package main

import (
	"fmt"
	"net/netip"
)

func main() {
	// 解析 IP 地址
	ip, err := netip.ParseAddr("192.168.1.1")
	if err != nil {
		fmt.Println("解析 IP 地址失败:", err)
		return
	}
	fmt.Println("解析的 IP 地址:", ip) // 输出: 解析的 IP 地址: 192.168.1.1

	// 检查 IP 地址是否有效
	fmt.Println("IP 地址是否有效:", ip.IsValid()) // 输出: IP 地址是否有效: true

	// 获取下一个 IP 地址
	nextIP := ip.Next()
	fmt.Println("下一个 IP 地址:", nextIP) // 输出: 下一个 IP 地址: 192.168.1.2

	// 解析带端口的地址
	addrPort, err := netip.ParseAddrPort("10.0.0.1:8080")
	if err != nil {
		fmt.Println("解析带端口的地址失败:", err)
		return
	}
	fmt.Println("解析的带端口的地址:", addrPort) // 输出: 解析的带端口的地址: 10.0.0.1:8080

	// 解析 IP 前缀
	prefix, err := netip.ParsePrefix("2001:db8::/32")
	if err != nil {
		fmt.Println("解析 IP 前缀失败:", err)
		return
	}
	fmt.Println("解析的 IP 前缀:", prefix) // 输出: 解析的 IP 前缀: 2001:db8::/32

	// 将 IP 地址转换为字符串
	ipStr := ip.String()
	fmt.Println("IP 地址的字符串表示:", ipStr) // 输出: IP 地址的字符串表示: 192.168.1.1
}
```

**假设的输入与输出（基于 `checkStringParseRoundTrip` 函数）：**

假设输入字符串 `s` 为 `"192.168.1.1"`, 并且调用 `checkStringParseRoundTrip` 函数时， `parse` 参数是 `netip.ParseAddr`。

**输入:** `s = "192.168.1.1"`

**过程:**

1. `ip, _ := ParseAddr(s)`:  `netip.ParseAddr("192.168.1.1")` 将会成功解析字符串，返回一个 `netip.Addr` 类型的 IP 地址对象，假设为 `ip1`。
2. `checkStringParseRoundTrip(t, ip1, ParseAddr)`:
   - `s := ip1.String()`: `ip1.String()` 将返回字符串 `"192.168.1.1"`。
   - `y, err := parse(s)`: `netip.ParseAddr("192.168.1.1")` 再次解析字符串，返回一个新的 `netip.Addr` 类型的 IP 地址对象，假设为 `ip2`。`err` 应该为 `nil`。
   - `if x != y`:  会比较 `ip1` 和 `ip2` 的值。由于解析的是同一个有效的 IP 地址，它们应该相等。
   - `s2 := y.String()`: `ip2.String()` 将返回字符串 `"192.168.1.1"`。
   - `if s != s2`: 会比较原始字符串 `s` 和解析后再转换回字符串的 `s2`。它们应该相等。

**输出:**  如果一切正常，`checkStringParseRoundTrip` 函数不会报错，因为 IP 地址的字符串表示和解析过程是可逆的。

**命令行参数的具体处理：**

这段代码本身是一个测试文件，通常不会直接通过命令行运行并接收参数。Go 的模糊测试工具 `go test` 会负责运行这些测试。

当使用 `go test -fuzz=FuzzParse` 命令运行模糊测试时，Go 的模糊测试引擎会：

1. **使用 `corpus` 中的种子输入作为初始测试用例。**
2. **生成新的、变异的输入数据。**  模糊测试引擎会尝试修改种子输入，例如插入、删除或替换字符，以探索不同的输入空间。
3. **将生成的输入传递给 `FuzzParse` 函数。**
4. **监控程序的运行状态，查找崩溃、panic 或其他错误。**

**使用者易犯错的点：**

从提供的代码中，我们可以推断出一些使用 `netip` 包时可能遇到的错误点：

1. **IP 地址字符串格式不正确:**  `ParseAddr` 等函数对 IP 地址字符串的格式有严格的要求。例如，IPv4 地址的每个部分必须是 0-255 的十进制数，不能有多余的前导零（除非像 Windows 那样的特殊格式），IPv6 地址的格式也需要符合规范。

   **示例：**
   ```go
   _, err := netip.ParseAddr("192.168.1.256") // 错误：256 超出范围
   if err != nil {
       fmt.Println(err) // 输出: parse "192.168.1.256": invalid IPv4 address
   }
   ```

2. **带端口地址缺少或格式错误的端口号:** `ParseAddrPort` 需要一个有效的端口号（0-65535）。

   **示例：**
   ```go
   _, err := netip.ParseAddrPort("192.168.1.1:") // 错误：缺少端口号
   if err != nil {
       fmt.Println(err) // 输出: parse "192.168.1.1:": missing port in address
   }

   _, err = netip.ParseAddrPort("192.168.1.1:65536") // 错误：端口号超出范围
   if err != nil {
       fmt.Println(err) // 输出: parse "192.168.1.1:65536": invalid port "65536"
   }
   ```

3. **IP 前缀格式不正确:** `ParsePrefix` 需要一个合法的 IP 地址加上一个斜杠 `/` 和一个表示子网掩码长度的数字。

   **示例：**
   ```go
   _, err := netip.ParsePrefix("192.168.1.1/") // 错误：缺少前缀长度
   if err != nil {
       fmt.Println(err) // 输出: parse "192.168.1.1/": missing prefix length
   }

   _, err = netip.ParsePrefix("192.168.1.1/33") // 错误：IPv4 前缀长度超出范围
   if err != nil {
       fmt.Println(err) // 输出: parse "192.168.1.1/33": invalid IPv4 prefix length: 33
   }
   ```

总之，这段代码是 `netip` 包进行自我测试的重要组成部分，它通过模糊测试来确保 IP 地址相关功能的健壮性和正确性。理解这段代码有助于我们了解 `netip` 包的设计和使用方式。

### 提示词
```
这是路径为go/src/net/netip/fuzz_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package netip_test

import (
	"bytes"
	"encoding"
	"fmt"
	"net"
	. "net/netip"
	"reflect"
	"strings"
	"testing"
)

var corpus = []string{
	// Basic zero IPv4 address.
	"0.0.0.0",
	// Basic non-zero IPv4 address.
	"192.168.140.255",
	// IPv4 address in windows-style "print all the digits" form.
	"010.000.015.001",
	// IPv4 address with a silly amount of leading zeros.
	"000001.00000002.00000003.000000004",
	// 4-in-6 with octet with leading zero
	"::ffff:1.2.03.4",
	// Basic zero IPv6 address.
	"::",
	// Localhost IPv6.
	"::1",
	// Fully expanded IPv6 address.
	"fd7a:115c:a1e0:ab12:4843:cd96:626b:430b",
	// IPv6 with elided fields in the middle.
	"fd7a:115c::626b:430b",
	// IPv6 with elided fields at the end.
	"fd7a:115c:a1e0:ab12:4843:cd96::",
	// IPv6 with single elided field at the end.
	"fd7a:115c:a1e0:ab12:4843:cd96:626b::",
	"fd7a:115c:a1e0:ab12:4843:cd96:626b:0",
	// IPv6 with single elided field in the middle.
	"fd7a:115c:a1e0::4843:cd96:626b:430b",
	"fd7a:115c:a1e0:0:4843:cd96:626b:430b",
	// IPv6 with the trailing 32 bits written as IPv4 dotted decimal. (4in6)
	"::ffff:192.168.140.255",
	"::ffff:192.168.140.255",
	// IPv6 with a zone specifier.
	"fd7a:115c:a1e0:ab12:4843:cd96:626b:430b%eth0",
	// IPv6 with dotted decimal and zone specifier.
	"1:2::ffff:192.168.140.255%eth1",
	"1:2::ffff:c0a8:8cff%eth1",
	// IPv6 with capital letters.
	"FD9E:1A04:F01D::1",
	"fd9e:1a04:f01d::1",
	// Empty string.
	"",
	// Garbage non-IP.
	"bad",
	// Single number. Some parsers accept this as an IPv4 address in
	// big-endian uint32 form, but we don't.
	"1234",
	// IPv4 with a zone specifier.
	"1.2.3.4%eth0",
	// IPv4 field must have at least one digit.
	".1.2.3",
	"1.2.3.",
	"1..2.3",
	// IPv4 address too long.
	"1.2.3.4.5",
	// IPv4 in dotted octal form.
	"0300.0250.0214.0377",
	// IPv4 in dotted hex form.
	"0xc0.0xa8.0x8c.0xff",
	// IPv4 in class B form.
	"192.168.12345",
	// IPv4 in class B form, with a small enough number to be
	// parseable as a regular dotted decimal field.
	"127.0.1",
	// IPv4 in class A form.
	"192.1234567",
	// IPv4 in class A form, with a small enough number to be
	// parseable as a regular dotted decimal field.
	"127.1",
	// IPv4 field has value >255.
	"192.168.300.1",
	// IPv4 with too many fields.
	"192.168.0.1.5.6",
	// IPv6 with not enough fields.
	"1:2:3:4:5:6:7",
	// IPv6 with too many fields.
	"1:2:3:4:5:6:7:8:9",
	// IPv6 with 8 fields and a :: expander.
	"1:2:3:4::5:6:7:8",
	// IPv6 with a field bigger than 2b.
	"fe801::1",
	// IPv6 with non-hex values in field.
	"fe80:tail:scal:e::",
	// IPv6 with a zone delimiter but no zone.
	"fe80::1%",
	// IPv6 with a zone specifier of zero.
	"::ffff:0:0%0",
	// IPv6 (without ellipsis) with too many fields for trailing embedded IPv4.
	"ffff:ffff:ffff:ffff:ffff:ffff:ffff:192.168.140.255",
	// IPv6 (with ellipsis) with too many fields for trailing embedded IPv4.
	"ffff::ffff:ffff:ffff:ffff:ffff:ffff:192.168.140.255",
	// IPv6 with invalid embedded IPv4.
	"::ffff:192.168.140.bad",
	// IPv6 with multiple ellipsis ::.
	"fe80::1::1",
	// IPv6 with invalid non hex/colon character.
	"fe80:1?:1",
	// IPv6 with truncated bytes after single colon.
	"fe80:",
	// AddrPort strings.
	"1.2.3.4:51820",
	"[fd7a:115c:a1e0:ab12:4843:cd96:626b:430b]:80",
	"[::ffff:c000:0280]:65535",
	"[::ffff:c000:0280%eth0]:1",
	// Prefix strings.
	"1.2.3.4/24",
	"fd7a:115c:a1e0:ab12:4843:cd96:626b:430b/118",
	"::ffff:c000:0280/96",
	"::ffff:c000:0280%eth0/37",
}

func FuzzParse(f *testing.F) {
	for _, seed := range corpus {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, s string) {
		ip, _ := ParseAddr(s)
		checkStringParseRoundTrip(t, ip, ParseAddr)
		checkEncoding(t, ip)

		// Check that we match the net's IP parser, modulo zones.
		if !strings.Contains(s, "%") {
			stdip := net.ParseIP(s)
			if !ip.IsValid() != (stdip == nil) {
				t.Errorf("ParseAddr zero != net.ParseIP nil: ip=%q stdip=%q", ip, stdip)
			}

			if ip.IsValid() && !ip.Is4In6() {
				buf, err := ip.MarshalText()
				if err != nil {
					t.Fatal(err)
				}
				buf2, err := stdip.MarshalText()
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(buf, buf2) {
					t.Errorf("Addr.MarshalText() != net.IP.MarshalText(): ip=%q stdip=%q", ip, stdip)
				}
				if ip.String() != stdip.String() {
					t.Errorf("Addr.String() != net.IP.String(): ip=%q stdip=%q", ip, stdip)
				}
				if ip.IsGlobalUnicast() != stdip.IsGlobalUnicast() {
					t.Errorf("Addr.IsGlobalUnicast() != net.IP.IsGlobalUnicast(): ip=%q stdip=%q", ip, stdip)
				}
				if ip.IsInterfaceLocalMulticast() != stdip.IsInterfaceLocalMulticast() {
					t.Errorf("Addr.IsInterfaceLocalMulticast() != net.IP.IsInterfaceLocalMulticast(): ip=%q stdip=%q", ip, stdip)
				}
				if ip.IsLinkLocalMulticast() != stdip.IsLinkLocalMulticast() {
					t.Errorf("Addr.IsLinkLocalMulticast() != net.IP.IsLinkLocalMulticast(): ip=%q stdip=%q", ip, stdip)
				}
				if ip.IsLinkLocalUnicast() != stdip.IsLinkLocalUnicast() {
					t.Errorf("Addr.IsLinkLocalUnicast() != net.IP.IsLinkLocalUnicast(): ip=%q stdip=%q", ip, stdip)
				}
				if ip.IsLoopback() != stdip.IsLoopback() {
					t.Errorf("Addr.IsLoopback() != net.IP.IsLoopback(): ip=%q stdip=%q", ip, stdip)
				}
				if ip.IsMulticast() != stdip.IsMulticast() {
					t.Errorf("Addr.IsMulticast() != net.IP.IsMulticast(): ip=%q stdip=%q", ip, stdip)
				}
				if ip.IsPrivate() != stdip.IsPrivate() {
					t.Errorf("Addr.IsPrivate() != net.IP.IsPrivate(): ip=%q stdip=%q", ip, stdip)
				}
				if ip.IsUnspecified() != stdip.IsUnspecified() {
					t.Errorf("Addr.IsUnspecified() != net.IP.IsUnspecified(): ip=%q stdip=%q", ip, stdip)
				}
			}
		}

		// Check that .Next().Prev() and .Prev().Next() preserve the IP.
		if ip.IsValid() && ip.Next().IsValid() && ip.Next().Prev() != ip {
			t.Errorf(".Next.Prev did not round trip: ip=%q .next=%q .next.prev=%q", ip, ip.Next(), ip.Next().Prev())
		}
		if ip.IsValid() && ip.Prev().IsValid() && ip.Prev().Next() != ip {
			t.Errorf(".Prev.Next did not round trip: ip=%q .prev=%q .prev.next=%q", ip, ip.Prev(), ip.Prev().Next())
		}

		port, err := ParseAddrPort(s)
		if err == nil {
			checkStringParseRoundTrip(t, port, ParseAddrPort)
			checkEncoding(t, port)
		}
		port = AddrPortFrom(ip, 80)
		checkStringParseRoundTrip(t, port, ParseAddrPort)
		checkEncoding(t, port)

		ipp, err := ParsePrefix(s)
		if err == nil {
			checkStringParseRoundTrip(t, ipp, ParsePrefix)
			checkEncoding(t, ipp)
		}
		ipp = PrefixFrom(ip, 8)
		checkStringParseRoundTrip(t, ipp, ParsePrefix)
		checkEncoding(t, ipp)
	})
}

// checkTextMarshaler checks that x's MarshalText and UnmarshalText functions round trip correctly.
func checkTextMarshaler(t *testing.T, x encoding.TextMarshaler) {
	buf, err := x.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	y := reflect.New(reflect.TypeOf(x)).Interface().(encoding.TextUnmarshaler)
	err = y.UnmarshalText(buf)
	if err != nil {
		t.Logf("(%v).MarshalText() = %q", x, buf)
		t.Fatalf("(%T).UnmarshalText(%q) = %v", y, buf, err)
	}
	e := reflect.ValueOf(y).Elem().Interface()
	if !reflect.DeepEqual(x, e) {
		t.Logf("(%v).MarshalText() = %q", x, buf)
		t.Logf("(%T).UnmarshalText(%q) = %v", y, buf, y)
		t.Fatalf("MarshalText/UnmarshalText failed to round trip: %#v != %#v", x, e)
	}
	buf2, err := y.(encoding.TextMarshaler).MarshalText()
	if err != nil {
		t.Logf("(%v).MarshalText() = %q", x, buf)
		t.Logf("(%T).UnmarshalText(%q) = %v", y, buf, y)
		t.Fatalf("failed to MarshalText a second time: %v", err)
	}
	if !bytes.Equal(buf, buf2) {
		t.Logf("(%v).MarshalText() = %q", x, buf)
		t.Logf("(%T).UnmarshalText(%q) = %v", y, buf, y)
		t.Logf("(%v).MarshalText() = %q", y, buf2)
		t.Fatalf("second MarshalText differs from first: %q != %q", buf, buf2)
	}
}

// checkBinaryMarshaler checks that x's MarshalText and UnmarshalText functions round trip correctly.
func checkBinaryMarshaler(t *testing.T, x encoding.BinaryMarshaler) {
	buf, err := x.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	y := reflect.New(reflect.TypeOf(x)).Interface().(encoding.BinaryUnmarshaler)
	err = y.UnmarshalBinary(buf)
	if err != nil {
		t.Logf("(%v).MarshalBinary() = %q", x, buf)
		t.Fatalf("(%T).UnmarshalBinary(%q) = %v", y, buf, err)
	}
	e := reflect.ValueOf(y).Elem().Interface()
	if !reflect.DeepEqual(x, e) {
		t.Logf("(%v).MarshalBinary() = %q", x, buf)
		t.Logf("(%T).UnmarshalBinary(%q) = %v", y, buf, y)
		t.Fatalf("MarshalBinary/UnmarshalBinary failed to round trip: %#v != %#v", x, e)
	}
	buf2, err := y.(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil {
		t.Logf("(%v).MarshalBinary() = %q", x, buf)
		t.Logf("(%T).UnmarshalBinary(%q) = %v", y, buf, y)
		t.Fatalf("failed to MarshalBinary a second time: %v", err)
	}
	if !bytes.Equal(buf, buf2) {
		t.Logf("(%v).MarshalBinary() = %q", x, buf)
		t.Logf("(%T).UnmarshalBinary(%q) = %v", y, buf, y)
		t.Logf("(%v).MarshalBinary() = %q", y, buf2)
		t.Fatalf("second MarshalBinary differs from first: %q != %q", buf, buf2)
	}
}

func checkTextMarshalMatchesString(t *testing.T, x netipType) {
	buf, err := x.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	str := x.String()
	if string(buf) != str {
		t.Fatalf("%v: MarshalText = %q, String = %q", x, buf, str)
	}
}

type appendMarshaler interface {
	encoding.TextMarshaler
	AppendTo([]byte) []byte
}

// checkTextMarshalMatchesAppendTo checks that x's MarshalText matches x's AppendTo.
func checkTextMarshalMatchesAppendTo(t *testing.T, x appendMarshaler) {
	buf, err := x.MarshalText()
	if err != nil {
		t.Fatal(err)
	}

	buf2 := make([]byte, 0, len(buf))
	buf2 = x.AppendTo(buf2)
	if !bytes.Equal(buf, buf2) {
		t.Fatalf("%v: MarshalText = %q, AppendTo = %q", x, buf, buf2)
	}
}

type netipType interface {
	encoding.BinaryMarshaler
	encoding.TextMarshaler
	fmt.Stringer
	IsValid() bool
}

type netipTypeCmp interface {
	comparable
	netipType
}

// checkStringParseRoundTrip checks that x's String method and the provided parse function can round trip correctly.
func checkStringParseRoundTrip[P netipTypeCmp](t *testing.T, x P, parse func(string) (P, error)) {
	if !x.IsValid() {
		// Ignore invalid values.
		return
	}

	s := x.String()
	y, err := parse(s)
	if err != nil {
		t.Fatalf("s=%q err=%v", s, err)
	}
	if x != y {
		t.Fatalf("%T round trip identity failure: s=%q x=%#v y=%#v", x, s, x, y)
	}
	s2 := y.String()
	if s != s2 {
		t.Fatalf("%T String round trip identity failure: s=%#v s2=%#v", x, s, s2)
	}
}

func checkEncoding(t *testing.T, x netipType) {
	if x.IsValid() {
		checkTextMarshaler(t, x)
		checkBinaryMarshaler(t, x)
		checkTextMarshalMatchesString(t, x)
	}

	if am, ok := x.(appendMarshaler); ok {
		checkTextMarshalMatchesAppendTo(t, am)
	}
}
```