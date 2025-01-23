Response:
The user wants to understand the functionality of the provided Go code snippet. The code is a test file (`netip_test.go`) for the `netip` package in Go's standard library.

Here's a breakdown of the thought process:

1. **Identify the core purpose:** The file name and the package declaration (`package netip_test`) clearly indicate that this is a test file for the `netip` package. Test files are used to verify the correctness of the code in the corresponding package.

2. **Analyze the imports:** The imported packages (`bytes`, `encoding/json`, `flag`, `fmt`, `internal/asan`, `internal/testenv`, `net`, `. "net/netip"`, `reflect`, `slices`, `strings`, `testing`, `unique`) provide clues about the functionalities being tested. Specifically, `net/netip` (imported with a dot, meaning its exported members are directly accessible) is the package under test. Other imports suggest operations like JSON encoding/decoding, command-line flags, string manipulation, reflection, and testing utilities.

3. **Examine the global variables:**
    - `long`: A boolean flag, likely used to control the execution of longer, more exhaustive tests.
    - `uint128`: A type alias, probably related to representing IPv6 addresses internally.
    - `mustPrefix`, `mustIP`, `mustIPPort`: Helper functions (likely wrappers around `MustParsePrefix`, `MustParseAddr`, `MustParseAddrPort`) to simplify creating valid `Prefix`, `Addr`, and `AddrPort` values in tests, panicking on error.

4. **Go through the test functions:**  The naming convention `TestXxx` indicates these are test functions. Analyze what each test function is doing:
    - `TestParseAddr`: This test focuses on the `ParseAddr` function, checking its ability to correctly parse various valid and invalid IP address strings. It also verifies the `String()` method and JSON marshaling/unmarshaling.
    - `TestAddrFromSlice`: Tests the `AddrFromSlice` function, which creates an `Addr` from a byte slice.
    - `TestIPv4Constructors`: Tests constructors related to IPv4 addresses.
    - `TestAddrAppendText`: Tests the `AppendText` method for formatting IP addresses into a byte slice.
    - `TestAddrMarshalUnmarshalBinary`: Tests the binary marshaling and unmarshaling of `Addr` values.
    - `TestAddrPortMarshalTextString`: Tests the text marshaling and string representation of `AddrPort` values.
    - `TestAddrPortMarshalUnmarshalBinary`: Tests the binary marshaling and unmarshaling of `AddrPort` values.
    - `TestPrefixMarshalTextString`: Tests the text marshaling and string representation of `Prefix` values.
    - `TestPrefixMarshalUnmarshalBinary`: Tests the binary marshaling and unmarshaling of `Prefix` values.
    - `TestAddrMarshalUnmarshal`: Specifically tests JSON marshaling/unmarshaling of the zero `Addr` value, highlighting differences from `ParseAddr`/`String`.
    - `TestAddrFrom16`: Tests the `AddrFrom16` function, creating an `Addr` from a 16-byte array.
    - `TestIPProperties`: Tests various property checking methods on `Addr`, such as `IsGlobalUnicast`, `IsMulticast`, etc.
    - `TestAddrWellKnown`: Tests the correctness of predefined "well-known" IP addresses.
    - `TestAddrLessCompare`: Tests the `Less` and `Compare` methods for `Addr`, ensuring correct ordering. It also checks for consistency with `reflect.DeepEqual`.
    - `TestAddrPortCompare`: Tests the `Compare` method for `AddrPort`.
    - `TestPrefixCompare`: Tests the `Compare` method for `Prefix`.
    - `TestIPStringExpanded`: Tests the `StringExpanded` method for a more verbose string representation of IP addresses.
    - `TestPrefixMasking`:  This test (truncated in the provided snippet) likely focuses on the functionality of creating prefixes from IP addresses and applying masks.

5. **Identify the tested Go features:** Based on the test functions, the code appears to be testing the following functionalities related to IP addresses and network prefixes:
    - Parsing IP address strings (IPv4 and IPv6, with and without zones).
    - Formatting IP addresses into strings (standard and expanded forms).
    - Creating IP addresses from byte slices and 16-byte arrays.
    - Binary and text marshaling and unmarshaling of IP addresses, IP address-port combinations, and network prefixes.
    - Comparing IP addresses, IP address-port combinations, and network prefixes.
    - Checking various properties of IP addresses (unicast, multicast, loopback, private, etc.).
    - Working with well-known IP addresses.
    - Creating and manipulating network prefixes (likely involving masking).

6. **Synthesize the summary:** Combine the observations from the above steps to create a concise summary of the code's functionality. Emphasize the core purpose of testing the `netip` package.
这个go语言代码文件 `go/src/net/netip/netip_test.go` 的主要功能是 **测试 `net/netip` 包中的 IP 地址和网络前缀相关的功能**。

具体来说，它包含了一系列以 `Test` 开头的测试函数，用于验证 `net/netip` 包中定义的类型（如 `Addr`, `AddrPort`, `Prefix`）及其相关方法的正确性。

以下是该代码文件测试的主要功能点归纳：

1. **IP 地址解析 (`ParseAddr`)**:
   - 测试将字符串解析为 `Addr` 类型的 IP 地址，包括 IPv4 和 IPv6 地址，以及带 Zone 的 IPv6 地址。
   - 测试解析有效和无效的 IP 地址字符串，并验证是否返回预期的错误。
   - 验证 `ParseAddr` 函数的纯粹性（多次调用相同输入应得到相同结果）。
   - 验证 `ParseAddr(ip.String())` 是否为恒等函数。
   - 使用一个较慢但可读性更高的解析函数 `parseIPSlow` 对比结果。
   - 验证解析后的 IP 地址使用 `String()` 方法格式化后的字符串是否符合预期。
   - 验证 IP 地址的 JSON 序列化和反序列化 (`MarshalText`, `UnmarshalText`) 功能。

2. **从切片创建 IP 地址 (`AddrFromSlice`)**:
   - 测试从 `[]byte` 切片创建 `Addr` 类型 IP 地址的功能。
   - 验证对于合法和非法的切片长度是否返回预期的结果。

3. **IPv4 地址构造函数 (`TestIPv4Constructors`)**:
   - 测试使用 `AddrFrom4` 函数从 `[4]byte` 数组创建 IPv4 地址的功能。

4. **IP 地址文本追加 (`AddrAppendText`)**:
   - 测试将 `Addr` 类型 IP 地址追加到 byte 切片的功能，并验证输出的文本格式。

5. **IP 地址二进制序列化和反序列化 (`AddrMarshalUnmarshalBinary`)**:
   - 测试将 `Addr` 类型 IP 地址序列化为二进制数据的功能。
   - 测试从二进制数据反序列化为 `Addr` 类型 IP 地址的功能。
   - 验证序列化后的数据长度是否符合预期。
   - 测试将 `Addr` 追加到二进制切片的功能。
   - 测试从长度不符合预期的二进制数据反序列化是否会报错。

6. **IP 地址和端口的文本序列化和字符串表示 (`AddrPortMarshalTextString`)**:
   - 测试 `AddrPort` 类型的文本序列化 (`MarshalText`) 功能。
   - 测试 `AddrPort` 类型的字符串表示 (`String`) 功能。
   - 测试将 `AddrPort` 追加到文本切片的功能。

7. **IP 地址和端口的二进制序列化和反序列化 (`AddrPortMarshalUnmarshalBinary`)**:
   - 测试 `AddrPort` 类型的二进制序列化 (`MarshalBinary`) 功能。
   - 测试从二进制数据反序列化为 `AddrPort` 类型的功能。
   - 验证序列化后的数据长度是否符合预期。
   - 测试将 `AddrPort` 追加到二进制切片的功能。
   - 测试从长度不符合预期的二进制数据反序列化是否会报错。

8. **网络前缀的文本序列化和字符串表示 (`PrefixMarshalTextString`)**:
   - 测试 `Prefix` 类型的文本序列化 (`MarshalText`) 功能。
   - 测试 `Prefix` 类型的字符串表示 (`String`) 功能。
   - 测试将 `Prefix` 追加到文本切片的功能。
   - 验证带有 Zone 的 IP 地址创建的 Prefix 在序列化时 Zone 是否被移除。

9. **网络前缀的二进制序列化和反序列化 (`PrefixMarshalUnmarshalBinary`)**:
   - 测试 `Prefix` 类型的二进制序列化 (`MarshalBinary`) 功能。
   - 测试从二进制数据反序列化为 `Prefix` 类型的功能。
   - 验证序列化后的数据长度是否符合预期。
   - 测试将 `Prefix` 追加到二进制切片的功能。
   - 测试从长度不符合预期的二进制数据反序列化是否会报错。
   - 验证对于超过 IP 地址长度的掩码位数的处理。

10. **IP 地址的 JSON 序列化和反序列化 (特殊情况) (`AddrMarshalUnmarshal`)**:
    - 专门测试空字符串反序列化为 `Addr` 的行为，与 `ParseAddr("")` 的行为有所不同。

11. **从 16 字节数组创建 IP 地址 (`AddrFrom16`)**:
    - 测试从 `[16]byte` 数组创建 `Addr` 类型 IP 地址的功能，包括 IPv4 和 IPv6 的表示。

12. **IP 地址属性判断 (`TestIPProperties`)**:
    - 测试 `Addr` 类型的一系列方法，用于判断 IP 地址的属性，例如是否为全局单播地址、接口本地多播地址、链路本地单播地址、环回地址、组播地址、私有地址、未指定地址等。

13. **预定义的 IP 地址常量 (`TestAddrWellKnown`)**:
    - 测试 `net/netip` 包中预定义的常用 IP 地址常量，并与 `net` 包中的对应常量进行比较。

14. **IP 地址的比较 (`TestAddrLessCompare`)**:
    - 测试 `Addr` 类型的 `Less` 和 `Compare` 方法，用于比较两个 IP 地址的大小。
    - 验证比较结果的正确性，包括 IPv4 和 IPv6 地址，以及带 Zone 的地址。
    - 验证 `Less` 和 `Compare` 方法的一致性。
    - 使用 `slices.SortFunc` 对 IP 地址切片进行排序并验证结果。
    - 验证 `Compare` 方法与 `reflect.DeepEqual` 在比较 IP 地址时的行为一致性。

15. **IP 地址和端口的比较 (`TestAddrPortCompare`)**:
    - 测试 `AddrPort` 类型的 `Compare` 方法，用于比较两个 IP 地址和端口的组合。
    - 使用 `slices.SortFunc` 对 `AddrPort` 切片进行排序并验证结果。

16. **网络前缀的比较 (`TestPrefixCompare`)**:
    - 测试 `Prefix` 类型的 `Compare` 方法，用于比较两个网络前缀的大小。
    - 使用 `slices.SortFunc` 对 `Prefix` 切片进行排序并验证结果。

17. **IP 地址的展开字符串表示 (`TestIPStringExpanded`)**:
    - 测试 `Addr` 类型的 `StringExpanded` 方法，用于获取 IP 地址的完整展开形式的字符串表示。

18. **网络前缀的掩码操作 (`TestPrefixMasking`)**:
    - (代码片段未完整展示，但推测) 测试使用指定的掩码位数创建 `Prefix` 的功能，验证掩码操作的正确性。

总而言之，这个测试文件覆盖了 `net/netip` 包中 IP 地址和网络前缀的核心功能，确保这些功能能够按照预期工作，并且能够正确处理各种边界情况和异常输入。

### 提示词
```
这是路径为go/src/net/netip/netip_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
// Copyright 2020 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package netip_test

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"internal/asan"
	"internal/testenv"
	"net"
	. "net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
	"unique"
)

var long = flag.Bool("long", false, "run long tests")

type uint128 = Uint128

var (
	mustPrefix = MustParsePrefix
	mustIP     = MustParseAddr
	mustIPPort = MustParseAddrPort
)

func TestParseAddr(t *testing.T) {
	var validIPs = []struct {
		in      string
		ip      Addr   // output of ParseAddr()
		str     string // output of String(). If "", use in.
		wantErr string
	}{
		// Basic zero IPv4 address.
		{
			in: "0.0.0.0",
			ip: MkAddr(Mk128(0, 0xffff00000000), Z4),
		},
		// Basic non-zero IPv4 address.
		{
			in: "192.168.140.255",
			ip: MkAddr(Mk128(0, 0xffffc0a88cff), Z4),
		},
		// IPv4 address in windows-style "print all the digits" form.
		{
			in:      "010.000.015.001",
			wantErr: `ParseAddr("010.000.015.001"): IPv4 field has octet with leading zero`,
		},
		// IPv4 address with a silly amount of leading zeros.
		{
			in:      "000001.00000002.00000003.000000004",
			wantErr: `ParseAddr("000001.00000002.00000003.000000004"): IPv4 field has octet with leading zero`,
		},
		// 4-in-6 with octet with leading zero
		{
			in:      "::ffff:1.2.03.4",
			wantErr: `ParseAddr("::ffff:1.2.03.4"): IPv4 field has octet with leading zero`,
		},
		// 4-in-6 with octet with unexpected character
		{
			in:      "::ffff:1.2.3.z",
			wantErr: `ParseAddr("::ffff:1.2.3.z"): unexpected character (at "z")`,
		},
		// Basic zero IPv6 address.
		{
			in: "::",
			ip: MkAddr(Mk128(0, 0), Z6noz),
		},
		// Localhost IPv6.
		{
			in: "::1",
			ip: MkAddr(Mk128(0, 1), Z6noz),
		},
		// Fully expanded IPv6 address.
		{
			in: "fd7a:115c:a1e0:ab12:4843:cd96:626b:430b",
			ip: MkAddr(Mk128(0xfd7a115ca1e0ab12, 0x4843cd96626b430b), Z6noz),
		},
		// IPv6 with elided fields in the middle.
		{
			in: "fd7a:115c::626b:430b",
			ip: MkAddr(Mk128(0xfd7a115c00000000, 0x00000000626b430b), Z6noz),
		},
		// IPv6 with elided fields at the end.
		{
			in: "fd7a:115c:a1e0:ab12:4843:cd96::",
			ip: MkAddr(Mk128(0xfd7a115ca1e0ab12, 0x4843cd9600000000), Z6noz),
		},
		// IPv6 with single elided field at the end.
		{
			in:  "fd7a:115c:a1e0:ab12:4843:cd96:626b::",
			ip:  MkAddr(Mk128(0xfd7a115ca1e0ab12, 0x4843cd96626b0000), Z6noz),
			str: "fd7a:115c:a1e0:ab12:4843:cd96:626b:0",
		},
		// IPv6 with single elided field in the middle.
		{
			in:  "fd7a:115c:a1e0::4843:cd96:626b:430b",
			ip:  MkAddr(Mk128(0xfd7a115ca1e00000, 0x4843cd96626b430b), Z6noz),
			str: "fd7a:115c:a1e0:0:4843:cd96:626b:430b",
		},
		// IPv6 with the trailing 32 bits written as IPv4 dotted decimal. (4in6)
		{
			in:  "::ffff:192.168.140.255",
			ip:  MkAddr(Mk128(0, 0x0000ffffc0a88cff), Z6noz),
			str: "::ffff:192.168.140.255",
		},
		// IPv6 with a zone specifier.
		{
			in: "fd7a:115c:a1e0:ab12:4843:cd96:626b:430b%eth0",
			ip: MkAddr(Mk128(0xfd7a115ca1e0ab12, 0x4843cd96626b430b), unique.Make(MakeAddrDetail(true, "eth0"))),
		},
		// IPv6 with dotted decimal and zone specifier.
		{
			in:  "1:2::ffff:192.168.140.255%eth1",
			ip:  MkAddr(Mk128(0x0001000200000000, 0x0000ffffc0a88cff), unique.Make(MakeAddrDetail(true, "eth1"))),
			str: "1:2::ffff:c0a8:8cff%eth1",
		},
		// 4-in-6 with zone
		{
			in:  "::ffff:192.168.140.255%eth1",
			ip:  MkAddr(Mk128(0, 0x0000ffffc0a88cff), unique.Make(MakeAddrDetail(true, "eth1"))),
			str: "::ffff:192.168.140.255%eth1",
		},
		// IPv6 with capital letters.
		{
			in:  "FD9E:1A04:F01D::1",
			ip:  MkAddr(Mk128(0xfd9e1a04f01d0000, 0x1), Z6noz),
			str: "fd9e:1a04:f01d::1",
		},
	}

	for _, test := range validIPs {
		t.Run(test.in, func(t *testing.T) {
			got, err := ParseAddr(test.in)
			if err != nil {
				if err.Error() == test.wantErr {
					return
				}
				t.Fatal(err)
			}
			if test.wantErr != "" {
				t.Fatalf("wanted error %q; got none", test.wantErr)
			}
			if got != test.ip {
				t.Errorf("got %#v, want %#v", got, test.ip)
			}

			// Check that ParseAddr is a pure function.
			got2, err := ParseAddr(test.in)
			if err != nil {
				t.Fatal(err)
			}
			if got != got2 {
				t.Errorf("ParseAddr(%q) got 2 different results: %#v, %#v", test.in, got, got2)
			}

			// Check that ParseAddr(ip.String()) is the identity function.
			s := got.String()
			got3, err := ParseAddr(s)
			if err != nil {
				t.Fatal(err)
			}
			if got != got3 {
				t.Errorf("ParseAddr(%q) != ParseAddr(ParseIP(%q).String()). Got %#v, want %#v", test.in, test.in, got3, got)
			}

			// Check that the slow-but-readable parser produces the same result.
			slow, err := parseIPSlow(test.in)
			if err != nil {
				t.Fatal(err)
			}
			if got != slow {
				t.Errorf("ParseAddr(%q) = %#v, parseIPSlow(%q) = %#v", test.in, got, test.in, slow)
			}

			// Check that the parsed IP formats as expected.
			s = got.String()
			wants := test.str
			if wants == "" {
				wants = test.in
			}
			if s != wants {
				t.Errorf("ParseAddr(%q).String() got %q, want %q", test.in, s, wants)
			}

			// Check that AppendTo matches MarshalText.
			TestAppendToMarshal(t, got)

			// Check that MarshalText/UnmarshalText work similarly to
			// ParseAddr/String (see TestIPMarshalUnmarshal for
			// marshal-specific behavior that's not common with
			// ParseAddr/String).
			js := `"` + test.in + `"`
			var jsgot Addr
			if err := json.Unmarshal([]byte(js), &jsgot); err != nil {
				t.Fatal(err)
			}
			if jsgot != got {
				t.Errorf("json.Unmarshal(%q) = %#v, want %#v", test.in, jsgot, got)
			}
			jsb, err := json.Marshal(jsgot)
			if err != nil {
				t.Fatal(err)
			}
			jswant := `"` + wants + `"`
			jsback := string(jsb)
			if jsback != jswant {
				t.Errorf("Marshal(Unmarshal(%q)) = %s, want %s", test.in, jsback, jswant)
			}
		})
	}

	var invalidIPs = []string{
		// Empty string
		"",
		// Garbage non-IP
		"bad",
		// Single number. Some parsers accept this as an IPv4 address in
		// big-endian uint32 form, but we don't.
		"1234",
		// IPv4 with a zone specifier
		"1.2.3.4%eth0",
		// IPv4 field must have at least one digit
		".1.2.3",
		"1.2.3.",
		"1..2.3",
		// IPv4 address too long
		"1.2.3.4.5",
		// IPv4 in dotted octal form
		"0300.0250.0214.0377",
		// IPv4 in dotted hex form
		"0xc0.0xa8.0x8c.0xff",
		// IPv4 in class B form
		"192.168.12345",
		// IPv4 in class B form, with a small enough number to be
		// parseable as a regular dotted decimal field.
		"127.0.1",
		// IPv4 in class A form
		"192.1234567",
		// IPv4 in class A form, with a small enough number to be
		// parseable as a regular dotted decimal field.
		"127.1",
		// IPv4 field has value >255
		"192.168.300.1",
		// IPv4 with too many fields
		"192.168.0.1.5.6",
		// IPv6 with not enough fields
		"1:2:3:4:5:6:7",
		// IPv6 with too many fields
		"1:2:3:4:5:6:7:8:9",
		// IPv6 with 8 fields and a :: expander
		"1:2:3:4::5:6:7:8",
		// IPv6 with a field bigger than 2b
		"fe801::1",
		// IPv6 with non-hex values in field
		"fe80:tail:scal:e::",
		// IPv6 with a zone delimiter but no zone.
		"fe80::1%",
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
		// IPv6 with 5 zeros in last group
		"0:0:0:0:0:ffff:0:00000",
		// IPv6 with 5 zeros in one group and embedded IPv4
		"0:0:0:0:00000:ffff:127.1.2.3",
	}

	for _, s := range invalidIPs {
		t.Run(s, func(t *testing.T) {
			got, err := ParseAddr(s)
			if err == nil {
				t.Errorf("ParseAddr(%q) = %#v, want error", s, got)
			}

			slow, err := parseIPSlow(s)
			if err == nil {
				t.Errorf("parseIPSlow(%q) = %#v, want error", s, slow)
			}

			std := net.ParseIP(s)
			if std != nil {
				t.Errorf("net.ParseIP(%q) = %#v, want error", s, std)
			}

			if s == "" {
				// Don't test unmarshaling of "" here, do it in
				// IPMarshalUnmarshal.
				return
			}
			var jsgot Addr
			js := []byte(`"` + s + `"`)
			if err := json.Unmarshal(js, &jsgot); err == nil {
				t.Errorf("json.Unmarshal(%q) = %#v, want error", s, jsgot)
			}
		})
	}
}

func TestAddrFromSlice(t *testing.T) {
	tests := []struct {
		ip       []byte
		wantAddr Addr
		wantOK   bool
	}{
		{
			ip:       []byte{10, 0, 0, 1},
			wantAddr: mustIP("10.0.0.1"),
			wantOK:   true,
		},
		{
			ip:       []byte{0xfe, 0x80, 15: 0x01},
			wantAddr: mustIP("fe80::01"),
			wantOK:   true,
		},
		{
			ip:       []byte{0, 1, 2},
			wantAddr: Addr{},
			wantOK:   false,
		},
		{
			ip:       nil,
			wantAddr: Addr{},
			wantOK:   false,
		},
	}
	for _, tt := range tests {
		addr, ok := AddrFromSlice(tt.ip)
		if ok != tt.wantOK || addr != tt.wantAddr {
			t.Errorf("AddrFromSlice(%#v) = %#v, %v, want %#v, %v", tt.ip, addr, ok, tt.wantAddr, tt.wantOK)
		}
	}
}

func TestIPv4Constructors(t *testing.T) {
	if AddrFrom4([4]byte{1, 2, 3, 4}) != MustParseAddr("1.2.3.4") {
		t.Errorf("don't match")
	}
}

func TestAddrAppendText(t *testing.T) {
	tests := []struct {
		ip   Addr
		want string
	}{
		{Addr{}, ""}, // zero IP
		{mustIP("1.2.3.4"), "1.2.3.4"},
		{mustIP("fd7a:115c:a1e0:ab12:4843:cd96:626b:430b"), "fd7a:115c:a1e0:ab12:4843:cd96:626b:430b"},
		{mustIP("::ffff:192.168.140.255"), "::ffff:192.168.140.255"},
		{mustIP("::ffff:192.168.140.255%en0"), "::ffff:192.168.140.255%en0"},
	}
	for i, tc := range tests {
		ip := tc.ip

		mtAppend := make([]byte, 4, 32)
		mtAppend, err := ip.AppendText(mtAppend)
		mtAppend = mtAppend[4:]
		if err != nil {
			t.Fatal(err)
		}
		if string(mtAppend) != tc.want {
			t.Errorf("%d. for (%v) AppendText = %q; want %q", i, ip, mtAppend, tc.want)
		}
	}
}

func TestAddrMarshalUnmarshalBinary(t *testing.T) {
	tests := []struct {
		ip       string
		wantSize int
	}{
		{"", 0}, // zero IP
		{"1.2.3.4", 4},
		{"fd7a:115c:a1e0:ab12:4843:cd96:626b:430b", 16},
		{"::ffff:c000:0280", 16},
		{"::ffff:c000:0280%eth0", 20},
	}
	for _, tc := range tests {
		var ip Addr
		if len(tc.ip) > 0 {
			ip = mustIP(tc.ip)
		}
		b, err := ip.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if len(b) != tc.wantSize {
			t.Fatalf("%q encoded to size %d; want %d", tc.ip, len(b), tc.wantSize)
		}
		var ip2 Addr
		if err := ip2.UnmarshalBinary(b); err != nil {
			t.Fatal(err)
		}
		if ip != ip2 {
			t.Fatalf("got %v; want %v", ip2, ip)
		}

		bAppend := make([]byte, 4, 32)
		bAppend, err = ip.AppendBinary(bAppend)
		bAppend = bAppend[4:]
		if err != nil {
			t.Fatal(err)
		}
		if len(bAppend) != tc.wantSize {
			t.Fatalf("%q encoded to size %d; want %d", tc.ip, len(bAppend), tc.wantSize)
		}
		var ip3 Addr
		if err := ip3.UnmarshalBinary(bAppend); err != nil {
			t.Fatal(err)
		}
		if ip != ip3 {
			t.Fatalf("got %v; want %v", ip3, ip)
		}
	}

	// Cannot unmarshal from unexpected IP length.
	for _, n := range []int{3, 5} {
		var ip2 Addr
		if err := ip2.UnmarshalBinary(bytes.Repeat([]byte{1}, n)); err == nil {
			t.Fatalf("unmarshaled from unexpected IP length %d", n)
		}
	}
}

func TestAddrPortMarshalTextString(t *testing.T) {
	tests := []struct {
		in   AddrPort
		want string
	}{
		{mustIPPort("1.2.3.4:80"), "1.2.3.4:80"},
		{mustIPPort("[::]:80"), "[::]:80"},
		{mustIPPort("[1::CAFE]:80"), "[1::cafe]:80"},
		{mustIPPort("[1::CAFE%en0]:80"), "[1::cafe%en0]:80"},
		{mustIPPort("[::FFFF:192.168.140.255]:80"), "[::ffff:192.168.140.255]:80"},
		{mustIPPort("[::FFFF:192.168.140.255%en0]:80"), "[::ffff:192.168.140.255%en0]:80"},
	}
	for i, tt := range tests {
		if got := tt.in.String(); got != tt.want {
			t.Errorf("%d. for (%v, %v) String = %q; want %q", i, tt.in.Addr(), tt.in.Port(), got, tt.want)
		}
		mt, err := tt.in.MarshalText()
		if err != nil {
			t.Errorf("%d. for (%v, %v) MarshalText error: %v", i, tt.in.Addr(), tt.in.Port(), err)
			continue
		}
		if string(mt) != tt.want {
			t.Errorf("%d. for (%v, %v) MarshalText = %q; want %q", i, tt.in.Addr(), tt.in.Port(), mt, tt.want)
		}

		mtAppend := make([]byte, 4, 32)
		mtAppend, err = tt.in.AppendText(mtAppend)
		mtAppend = mtAppend[4:]
		if err != nil {
			t.Errorf("%d. for (%v, %v) AppendText error: %v", i, tt.in.Addr(), tt.in.Port(), err)
			continue
		}
		if string(mtAppend) != tt.want {
			t.Errorf("%d. for (%v, %v) AppendText = %q; want %q", i, tt.in.Addr(), tt.in.Port(), mtAppend, tt.want)
		}
	}
}

func TestAddrPortMarshalUnmarshalBinary(t *testing.T) {
	tests := []struct {
		ipport   string
		wantSize int
	}{
		{"1.2.3.4:51820", 4 + 2},
		{"[fd7a:115c:a1e0:ab12:4843:cd96:626b:430b]:80", 16 + 2},
		{"[::ffff:c000:0280]:65535", 16 + 2},
		{"[::ffff:c000:0280%eth0]:1", 20 + 2},
	}
	for _, tc := range tests {
		var ipport AddrPort
		if len(tc.ipport) > 0 {
			ipport = mustIPPort(tc.ipport)
		}
		b, err := ipport.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if len(b) != tc.wantSize {
			t.Fatalf("%q encoded to size %d; want %d", tc.ipport, len(b), tc.wantSize)
		}
		var ipport2 AddrPort
		if err := ipport2.UnmarshalBinary(b); err != nil {
			t.Fatal(err)
		}
		if ipport != ipport2 {
			t.Fatalf("got %v; want %v", ipport2, ipport)
		}

		bAppend := make([]byte, 4, 32)
		bAppend, err = ipport.AppendBinary(bAppend)
		bAppend = bAppend[4:]
		if err != nil {
			t.Fatal(err)
		}
		if len(bAppend) != tc.wantSize {
			t.Fatalf("%q encoded to size %d; want %d", tc.ipport, len(bAppend), tc.wantSize)
		}
		var ipport3 AddrPort
		if err := ipport3.UnmarshalBinary(bAppend); err != nil {
			t.Fatal(err)
		}
		if ipport != ipport3 {
			t.Fatalf("got %v; want %v", ipport3, ipport)
		}
	}

	// Cannot unmarshal from unexpected lengths.
	for _, n := range []int{3, 7} {
		var ipport2 AddrPort
		if err := ipport2.UnmarshalBinary(bytes.Repeat([]byte{1}, n)); err == nil {
			t.Fatalf("unmarshaled from unexpected length %d", n)
		}
	}
}

func TestPrefixMarshalTextString(t *testing.T) {
	tests := []struct {
		in   Prefix
		want string
	}{
		{mustPrefix("1.2.3.4/24"), "1.2.3.4/24"},
		{mustPrefix("fd7a:115c:a1e0:ab12:4843:cd96:626b:430b/118"), "fd7a:115c:a1e0:ab12:4843:cd96:626b:430b/118"},
		{mustPrefix("::ffff:c000:0280/96"), "::ffff:192.0.2.128/96"},
		{mustPrefix("::ffff:192.168.140.255/8"), "::ffff:192.168.140.255/8"},
		{PrefixFrom(mustIP("::ffff:c000:0280").WithZone("eth0"), 37), "::ffff:192.0.2.128/37"}, // Zone should be stripped
	}
	for i, tt := range tests {
		if got := tt.in.String(); got != tt.want {
			t.Errorf("%d. for %v String = %q; want %q", i, tt.in, got, tt.want)
		}
		mt, err := tt.in.MarshalText()
		if err != nil {
			t.Errorf("%d. for %v MarshalText error: %v", i, tt.in, err)
			continue
		}
		if string(mt) != tt.want {
			t.Errorf("%d. for %v MarshalText = %q; want %q", i, tt.in, mt, tt.want)
		}

		mtAppend := make([]byte, 4, 64)
		mtAppend, err = tt.in.AppendText(mtAppend)
		mtAppend = mtAppend[4:]
		if err != nil {
			t.Errorf("%d. for %v AppendText error: %v", i, tt.in, err)
			continue
		}
		if string(mtAppend) != tt.want {
			t.Errorf("%d. for %v AppendText = %q; want %q", i, tt.in, mtAppend, tt.want)
		}
	}
}

func TestPrefixMarshalUnmarshalBinary(t *testing.T) {
	type testCase struct {
		prefix   Prefix
		wantSize int
	}
	tests := []testCase{
		{mustPrefix("1.2.3.4/24"), 4 + 1},
		{mustPrefix("fd7a:115c:a1e0:ab12:4843:cd96:626b:430b/118"), 16 + 1},
		{mustPrefix("::ffff:c000:0280/96"), 16 + 1},
		{PrefixFrom(mustIP("::ffff:c000:0280").WithZone("eth0"), 37), 16 + 1}, // Zone should be stripped
	}
	tests = append(tests,
		testCase{PrefixFrom(tests[0].prefix.Addr(), 33), tests[0].wantSize},
		testCase{PrefixFrom(tests[1].prefix.Addr(), 129), tests[1].wantSize})
	for _, tc := range tests {
		prefix := tc.prefix
		b, err := prefix.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if len(b) != tc.wantSize {
			t.Fatalf("%q encoded to size %d; want %d", tc.prefix, len(b), tc.wantSize)
		}
		var prefix2 Prefix
		if err := prefix2.UnmarshalBinary(b); err != nil {
			t.Fatal(err)
		}
		if prefix != prefix2 {
			t.Fatalf("got %v; want %v", prefix2, prefix)
		}

		bAppend := make([]byte, 4, 32)
		bAppend, err = prefix.AppendBinary(bAppend)
		bAppend = bAppend[4:]
		if err != nil {
			t.Fatal(err)
		}
		if len(bAppend) != tc.wantSize {
			t.Fatalf("%q encoded to size %d; want %d", tc.prefix, len(bAppend), tc.wantSize)
		}
		var prefix3 Prefix
		if err := prefix3.UnmarshalBinary(bAppend); err != nil {
			t.Fatal(err)
		}
		if prefix != prefix3 {
			t.Fatalf("got %v; want %v", prefix3, prefix)
		}
	}

	// Cannot unmarshal from unexpected lengths.
	for _, n := range []int{3, 6} {
		var prefix2 Prefix
		if err := prefix2.UnmarshalBinary(bytes.Repeat([]byte{1}, n)); err == nil {
			t.Fatalf("unmarshaled from unexpected length %d", n)
		}
	}
}

func TestAddrMarshalUnmarshal(t *testing.T) {
	// This only tests the cases where Marshal/Unmarshal diverges from
	// the behavior of ParseAddr/String. For the rest of the test cases,
	// see TestParseAddr above.
	orig := `""`
	var ip Addr
	if err := json.Unmarshal([]byte(orig), &ip); err != nil {
		t.Fatalf("Unmarshal(%q) got error %v", orig, err)
	}
	if ip != (Addr{}) {
		t.Errorf("Unmarshal(%q) is not the zero Addr", orig)
	}

	jsb, err := json.Marshal(ip)
	if err != nil {
		t.Fatalf("Marshal(%v) got error %v", ip, err)
	}
	back := string(jsb)
	if back != orig {
		t.Errorf("Marshal(Unmarshal(%q)) got %q, want %q", orig, back, orig)
	}
}

func TestAddrFrom16(t *testing.T) {
	tests := []struct {
		name string
		in   [16]byte
		want Addr
	}{
		{
			name: "v6-raw",
			in:   [...]byte{15: 1},
			want: MkAddr(Mk128(0, 1), Z6noz),
		},
		{
			name: "v4-raw",
			in:   [...]byte{10: 0xff, 11: 0xff, 12: 1, 13: 2, 14: 3, 15: 4},
			want: MkAddr(Mk128(0, 0xffff01020304), Z6noz),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AddrFrom16(tt.in)
			if got != tt.want {
				t.Errorf("got %#v; want %#v", got, tt.want)
			}
		})
	}
}

func TestIPProperties(t *testing.T) {
	var (
		nilIP Addr

		unicast4           = mustIP("192.0.2.1")
		unicast6           = mustIP("2001:db8::1")
		unicastZone6       = mustIP("2001:db8::1%eth0")
		unicast6Unassigned = mustIP("4000::1") // not in 2000::/3.

		multicast4     = mustIP("224.0.0.1")
		multicast6     = mustIP("ff02::1")
		multicastZone6 = mustIP("ff02::1%eth0")

		llu4     = mustIP("169.254.0.1")
		llu6     = mustIP("fe80::1")
		llu6Last = mustIP("febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
		lluZone6 = mustIP("fe80::1%eth0")

		loopback4 = mustIP("127.0.0.1")

		ilm6     = mustIP("ff01::1")
		ilmZone6 = mustIP("ff01::1%eth0")

		private4a        = mustIP("10.0.0.1")
		private4b        = mustIP("172.16.0.1")
		private4c        = mustIP("192.168.1.1")
		private6         = mustIP("fd00::1")
		private6mapped4a = mustIP("::ffff:10.0.0.1")
		private6mapped4b = mustIP("::ffff:172.16.0.1")
		private6mapped4c = mustIP("::ffff:192.168.1.1")
	)

	tests := []struct {
		name                    string
		ip                      Addr
		globalUnicast           bool
		interfaceLocalMulticast bool
		linkLocalMulticast      bool
		linkLocalUnicast        bool
		loopback                bool
		multicast               bool
		private                 bool
		unspecified             bool
	}{
		{
			name: "nil",
			ip:   nilIP,
		},
		{
			name:          "unicast v4Addr",
			ip:            unicast4,
			globalUnicast: true,
		},
		{
			name:          "unicast v6 mapped v4Addr",
			ip:            AddrFrom16(unicast4.As16()),
			globalUnicast: true,
		},
		{
			name:          "unicast v6Addr",
			ip:            unicast6,
			globalUnicast: true,
		},
		{
			name:          "unicast v6AddrZone",
			ip:            unicastZone6,
			globalUnicast: true,
		},
		{
			name:          "unicast v6Addr unassigned",
			ip:            unicast6Unassigned,
			globalUnicast: true,
		},
		{
			name:               "multicast v4Addr",
			ip:                 multicast4,
			linkLocalMulticast: true,
			multicast:          true,
		},
		{
			name:               "multicast v6 mapped v4Addr",
			ip:                 AddrFrom16(multicast4.As16()),
			linkLocalMulticast: true,
			multicast:          true,
		},
		{
			name:               "multicast v6Addr",
			ip:                 multicast6,
			linkLocalMulticast: true,
			multicast:          true,
		},
		{
			name:               "multicast v6AddrZone",
			ip:                 multicastZone6,
			linkLocalMulticast: true,
			multicast:          true,
		},
		{
			name:             "link-local unicast v4Addr",
			ip:               llu4,
			linkLocalUnicast: true,
		},
		{
			name:             "link-local unicast v6 mapped v4Addr",
			ip:               AddrFrom16(llu4.As16()),
			linkLocalUnicast: true,
		},
		{
			name:             "link-local unicast v6Addr",
			ip:               llu6,
			linkLocalUnicast: true,
		},
		{
			name:             "link-local unicast v6Addr upper bound",
			ip:               llu6Last,
			linkLocalUnicast: true,
		},
		{
			name:             "link-local unicast v6AddrZone",
			ip:               lluZone6,
			linkLocalUnicast: true,
		},
		{
			name:     "loopback v4Addr",
			ip:       loopback4,
			loopback: true,
		},
		{
			name:     "loopback v6Addr",
			ip:       IPv6Loopback(),
			loopback: true,
		},
		{
			name:     "loopback v6 mapped v4Addr",
			ip:       AddrFrom16(IPv6Loopback().As16()),
			loopback: true,
		},
		{
			name:                    "interface-local multicast v6Addr",
			ip:                      ilm6,
			interfaceLocalMulticast: true,
			multicast:               true,
		},
		{
			name:                    "interface-local multicast v6AddrZone",
			ip:                      ilmZone6,
			interfaceLocalMulticast: true,
			multicast:               true,
		},
		{
			name:          "private v4Addr 10/8",
			ip:            private4a,
			globalUnicast: true,
			private:       true,
		},
		{
			name:          "private v4Addr 172.16/12",
			ip:            private4b,
			globalUnicast: true,
			private:       true,
		},
		{
			name:          "private v4Addr 192.168/16",
			ip:            private4c,
			globalUnicast: true,
			private:       true,
		},
		{
			name:          "private v6Addr",
			ip:            private6,
			globalUnicast: true,
			private:       true,
		},
		{
			name:          "private v6 mapped v4Addr 10/8",
			ip:            private6mapped4a,
			globalUnicast: true,
			private:       true,
		},
		{
			name:          "private v6 mapped v4Addr 172.16/12",
			ip:            private6mapped4b,
			globalUnicast: true,
			private:       true,
		},
		{
			name:          "private v6 mapped v4Addr 192.168/16",
			ip:            private6mapped4c,
			globalUnicast: true,
			private:       true,
		},
		{
			name:        "unspecified v4Addr",
			ip:          IPv4Unspecified(),
			unspecified: true,
		},
		{
			name:        "unspecified v6Addr",
			ip:          IPv6Unspecified(),
			unspecified: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gu := tt.ip.IsGlobalUnicast()
			if gu != tt.globalUnicast {
				t.Errorf("IsGlobalUnicast(%v) = %v; want %v", tt.ip, gu, tt.globalUnicast)
			}

			ilm := tt.ip.IsInterfaceLocalMulticast()
			if ilm != tt.interfaceLocalMulticast {
				t.Errorf("IsInterfaceLocalMulticast(%v) = %v; want %v", tt.ip, ilm, tt.interfaceLocalMulticast)
			}

			llu := tt.ip.IsLinkLocalUnicast()
			if llu != tt.linkLocalUnicast {
				t.Errorf("IsLinkLocalUnicast(%v) = %v; want %v", tt.ip, llu, tt.linkLocalUnicast)
			}

			llm := tt.ip.IsLinkLocalMulticast()
			if llm != tt.linkLocalMulticast {
				t.Errorf("IsLinkLocalMulticast(%v) = %v; want %v", tt.ip, llm, tt.linkLocalMulticast)
			}

			lo := tt.ip.IsLoopback()
			if lo != tt.loopback {
				t.Errorf("IsLoopback(%v) = %v; want %v", tt.ip, lo, tt.loopback)
			}

			multicast := tt.ip.IsMulticast()
			if multicast != tt.multicast {
				t.Errorf("IsMulticast(%v) = %v; want %v", tt.ip, multicast, tt.multicast)
			}

			private := tt.ip.IsPrivate()
			if private != tt.private {
				t.Errorf("IsPrivate(%v) = %v; want %v", tt.ip, private, tt.private)
			}

			unspecified := tt.ip.IsUnspecified()
			if unspecified != tt.unspecified {
				t.Errorf("IsUnspecified(%v) = %v; want %v", tt.ip, unspecified, tt.unspecified)
			}
		})
	}
}

func TestAddrWellKnown(t *testing.T) {
	tests := []struct {
		name string
		ip   Addr
		std  net.IP
	}{
		{
			name: "IPv4 unspecified",
			ip:   IPv4Unspecified(),
			std:  net.IPv4zero,
		},
		{
			name: "IPv6 link-local all nodes",
			ip:   IPv6LinkLocalAllNodes(),
			std:  net.IPv6linklocalallnodes,
		},
		{
			name: "IPv6 link-local all routers",
			ip:   IPv6LinkLocalAllRouters(),
			std:  net.IPv6linklocalallrouters,
		},
		{
			name: "IPv6 loopback",
			ip:   IPv6Loopback(),
			std:  net.IPv6loopback,
		},
		{
			name: "IPv6 unspecified",
			ip:   IPv6Unspecified(),
			std:  net.IPv6unspecified,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := tt.std.String()
			got := tt.ip.String()

			if got != want {
				t.Fatalf("got %s, want %s", got, want)
			}
		})
	}
}

func TestAddrLessCompare(t *testing.T) {
	tests := []struct {
		a, b Addr
		want bool
	}{
		{Addr{}, Addr{}, false},
		{Addr{}, mustIP("1.2.3.4"), true},
		{mustIP("1.2.3.4"), Addr{}, false},

		{mustIP("1.2.3.4"), mustIP("0102:0304::0"), true},
		{mustIP("0102:0304::0"), mustIP("1.2.3.4"), false},
		{mustIP("1.2.3.4"), mustIP("1.2.3.4"), false},

		{mustIP("::1"), mustIP("::2"), true},
		{mustIP("::1"), mustIP("::1%foo"), true},
		{mustIP("::1%foo"), mustIP("::2"), true},
		{mustIP("::2"), mustIP("::3"), true},

		{mustIP("::"), mustIP("0.0.0.0"), false},
		{mustIP("0.0.0.0"), mustIP("::"), true},

		{mustIP("::1%a"), mustIP("::1%b"), true},
		{mustIP("::1%a"), mustIP("::1%a"), false},
		{mustIP("::1%b"), mustIP("::1%a"), false},

		// For Issue 68113, verify that an IPv4 address and a
		// v4-mapped-IPv6 address differing only in their zone
		// pointer are unequal via all three of
		// ==/Compare/reflect.DeepEqual. In Go 1.22 and
		// earlier, these were accidentally equal via
		// DeepEqual due to their zone pointers (z) differing
		// but pointing to identical structures.
		{mustIP("::ffff:11.1.1.12"), mustIP("11.1.1.12"), false},
	}
	for _, tt := range tests {
		got := tt.a.Less(tt.b)
		if got != tt.want {
			t.Errorf("Less(%q, %q) = %v; want %v", tt.a, tt.b, got, tt.want)
		}
		cmp := tt.a.Compare(tt.b)
		if got && cmp != -1 {
			t.Errorf("Less(%q, %q) = true, but Compare = %v (not -1)", tt.a, tt.b, cmp)
		}
		if cmp < -1 || cmp > 1 {
			t.Errorf("bogus Compare return value %v", cmp)
		}
		if cmp == 0 && tt.a != tt.b {
			t.Errorf("Compare(%q, %q) = 0; but not equal", tt.a, tt.b)
		}
		if cmp == 1 && !tt.b.Less(tt.a) {
			t.Errorf("Compare(%q, %q) = 1; but b.Less(a) isn't true", tt.a, tt.b)
		}

		// Also check inverse.
		if got == tt.want && got {
			got2 := tt.b.Less(tt.a)
			if got2 {
				t.Errorf("Less(%q, %q) was correctly %v, but so was Less(%q, %q)", tt.a, tt.b, got, tt.b, tt.a)
			}
		}

		// Also check reflect.DeepEqual. See issue 68113.
		deepEq := reflect.DeepEqual(tt.a, tt.b)
		if (cmp == 0) != deepEq {
			t.Errorf("%q and %q differ in == (%v) vs reflect.DeepEqual (%v)", tt.a, tt.b, cmp == 0, deepEq)
		}
	}

	// And just sort.
	values := []Addr{
		mustIP("::1"),
		mustIP("::2"),
		Addr{},
		mustIP("1.2.3.4"),
		mustIP("8.8.8.8"),
		mustIP("::1%foo"),
	}
	slices.SortFunc(values, Addr.Compare)
	got := fmt.Sprintf("%s", values)
	want := `[invalid IP 1.2.3.4 8.8.8.8 ::1 ::1%foo ::2]`
	if got != want {
		t.Errorf("unexpected sort\n got: %s\nwant: %s\n", got, want)
	}
}

func TestAddrPortCompare(t *testing.T) {
	tests := []struct {
		a, b AddrPort
		want int
	}{
		{AddrPort{}, AddrPort{}, 0},
		{AddrPort{}, mustIPPort("1.2.3.4:80"), -1},

		{mustIPPort("1.2.3.4:80"), mustIPPort("1.2.3.4:80"), 0},
		{mustIPPort("[::1]:80"), mustIPPort("[::1]:80"), 0},

		{mustIPPort("1.2.3.4:80"), mustIPPort("2.3.4.5:22"), -1},
		{mustIPPort("[::1]:80"), mustIPPort("[::2]:22"), -1},

		{mustIPPort("1.2.3.4:80"), mustIPPort("1.2.3.4:443"), -1},
		{mustIPPort("[::1]:80"), mustIPPort("[::1]:443"), -1},

		{mustIPPort("1.2.3.4:80"), mustIPPort("[0102:0304::0]:80"), -1},
	}
	for _, tt := range tests {
		got := tt.a.Compare(tt.b)
		if got != tt.want {
			t.Errorf("Compare(%q, %q) = %v; want %v", tt.a, tt.b, got, tt.want)
		}

		// Also check inverse.
		if got == tt.want {
			got2 := tt.b.Compare(tt.a)
			if want2 := -1 * tt.want; got2 != want2 {
				t.Errorf("Compare(%q, %q) was correctly %v, but Compare(%q, %q) was %v", tt.a, tt.b, got, tt.b, tt.a, got2)
			}
		}
	}

	// And just sort.
	values := []AddrPort{
		mustIPPort("[::1]:80"),
		mustIPPort("[::2]:80"),
		AddrPort{},
		mustIPPort("1.2.3.4:443"),
		mustIPPort("8.8.8.8:8080"),
		mustIPPort("[::1%foo]:1024"),
	}
	slices.SortFunc(values, AddrPort.Compare)
	got := fmt.Sprintf("%s", values)
	want := `[invalid AddrPort 1.2.3.4:443 8.8.8.8:8080 [::1]:80 [::1%foo]:1024 [::2]:80]`
	if got != want {
		t.Errorf("unexpected sort\n got: %s\nwant: %s\n", got, want)
	}
}

func TestPrefixCompare(t *testing.T) {
	tests := []struct {
		a, b Prefix
		want int
	}{
		{Prefix{}, Prefix{}, 0},
		{Prefix{}, mustPrefix("1.2.3.0/24"), -1},

		{mustPrefix("1.2.3.0/24"), mustPrefix("1.2.3.0/24"), 0},
		{mustPrefix("fe80::/64"), mustPrefix("fe80::/64"), 0},

		{mustPrefix("1.2.3.0/24"), mustPrefix("1.2.4.0/24"), -1},
		{mustPrefix("fe80::/64"), mustPrefix("fe90::/64"), -1},

		{mustPrefix("1.2.0.0/16"), mustPrefix("1.2.0.0/24"), -1},
		{mustPrefix("fe80::/48"), mustPrefix("fe80::/64"), -1},

		{mustPrefix("1.2.3.0/24"), mustPrefix("fe80::/8"), -1},
	}
	for _, tt := range tests {
		got := tt.a.Compare(tt.b)
		if got != tt.want {
			t.Errorf("Compare(%q, %q) = %v; want %v", tt.a, tt.b, got, tt.want)
		}

		// Also check inverse.
		if got == tt.want {
			got2 := tt.b.Compare(tt.a)
			if want2 := -1 * tt.want; got2 != want2 {
				t.Errorf("Compare(%q, %q) was correctly %v, but Compare(%q, %q) was %v", tt.a, tt.b, got, tt.b, tt.a, got2)
			}
		}
	}

	// And just sort.
	values := []Prefix{
		mustPrefix("1.2.3.0/24"),
		mustPrefix("fe90::/64"),
		mustPrefix("fe80::/64"),
		mustPrefix("1.2.0.0/16"),
		Prefix{},
		mustPrefix("fe80::/48"),
		mustPrefix("1.2.0.0/24"),
	}
	slices.SortFunc(values, Prefix.Compare)
	got := fmt.Sprintf("%s", values)
	want := `[invalid Prefix 1.2.0.0/16 1.2.0.0/24 1.2.3.0/24 fe80::/48 fe80::/64 fe90::/64]`
	if got != want {
		t.Errorf("unexpected sort\n got: %s\nwant: %s\n", got, want)
	}
}

func TestIPStringExpanded(t *testing.T) {
	tests := []struct {
		ip Addr
		s  string
	}{
		{
			ip: Addr{},
			s:  "invalid IP",
		},
		{
			ip: mustIP("192.0.2.1"),
			s:  "192.0.2.1",
		},
		{
			ip: mustIP("::ffff:192.0.2.1"),
			s:  "0000:0000:0000:0000:0000:ffff:c000:0201",
		},
		{
			ip: mustIP("2001:db8::1"),
			s:  "2001:0db8:0000:0000:0000:0000:0000:0001",
		},
		{
			ip: mustIP("2001:db8::1%eth0"),
			s:  "2001:0db8:0000:0000:0000:0000:0000:0001%eth0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.ip.String(), func(t *testing.T) {
			want := tt.s
			got := tt.ip.StringExpanded()

			if got != want {
				t.Fatalf("got %s, want %s", got, want)
			}
		})
	}
}

func TestPrefixMasking(t *testing.T) {
	type subtest struct {
		ip   Addr
		bits uint8
		p    Prefix
		ok   bool
	}

	// makeIPv6 produces a set of IPv6 subtests with an optional zone identifier.
	makeIPv6 := func(zone string) []subtest {
		if zone != "" {
			zone = "%" + zone
		}

		return []subtest{
			{
				ip:   mustIP(fmt.Sprintf("2001:db8::1%s", zone)),
				bits: 255,
			},
			{
				ip:   mustIP(fmt.Sprintf("2001:db8::1%s", zone)),
				bits: 32,
				p:    mustPrefix("2001:db8::/32"),
				ok:   true,
			},
			{
				ip:   mustIP(fmt.Sprintf("fe80::dead:beef:dead:beef%s", zone)),
				bits: 96,
				p:    mustPrefix("fe80::dead:beef:0:0/96"),
				ok:   true,
			},
			{
				ip:   mustIP(fmt.Sprintf("aaaa::%s", zone)),
				bits: 4,
				p:    mustPrefix("a000::/4"),
				ok:   true,
			},
			{
				ip:   mustIP(fmt.Sprintf("::%s", zone)),
				bits: 63,
				p:    mustPrefix("::/63"),
				ok:   true,
			},
		}
	}

	tests := []struct {
		family   string
		subtests []subtest
	}{
		{
			family: "nil",
			subtests: []subtest{
				{
					bits: 255,
					ok:   true,
				},
				{
					bits: 16,
					ok:   true,
				},
			},
		},
		{
			family: "IPv4",
			subtests: []subtest{
				{
					ip:   mustIP("192.0.2.0"),
					bits: 255,
				},
				{
					ip:   mustIP("192.0.2.0"),
					bits: 16,
					p:    mustPrefix("192.0.0.0/16"),
					ok:   true,
				},
				{
					ip:   must
```