Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Scan and Understanding the Purpose:**

The first step is to quickly scan the code to understand its overall purpose. Keywords like `test`, `parseIPTests`, `Benchmark`, `MarshalText`, `IPMask`, `CIDR`, `LookupIP`, `SplitHostPort`, `JoinHostPort`, and function names like `TestParseIP`, `TestIPString`, etc., immediately suggest that this code is a set of unit tests and benchmarks for IP address related functionalities in the `net` package of Go. The file path `go/src/net/ip_test.go` confirms this.

**2. Identifying Key Functionality Areas:**

Next, I look for distinct sections within the code that test different aspects of IP address handling. I mentally group the tests based on the types of operations they perform:

* **Parsing IP Addresses:** `parseIPTests`, `TestParseIP`, `BenchmarkParseIP`, `BenchmarkParseIPValidIPv4`, `BenchmarkParseIPValidIPv6`. These clearly relate to converting strings to `net.IP` objects.
* **String Representation of IP Addresses:** `ipStringTests`, `TestIPString`, `TestIPAppendTextNoAllocs`, `BenchmarkIPMarshalText`, `BenchmarkIPString`. This section focuses on converting `net.IP` objects back to string representations.
* **IP Masks:** `ipMaskTests`, `TestIPMask`, `ipMaskStringTests`, `TestIPMaskString`, `BenchmarkIPMaskString`. These tests involve creating and manipulating IP masks (`net.IPMask`).
* **CIDR Notation:** `parseCIDRTests`, `TestParseCIDR`. This section deals with parsing and validating CIDR (Classless Inter-Domain Routing) notation.
* **IP Network (`IPNet`) Operations:** `ipNetContainsTests`, `TestIPNetContains`, `ipNetStringTests`, `TestIPNetString`, `cidrMaskTests`, `TestCIDRMask`, `networkNumberAndMaskTests`, `TestNetworkNumberAndMask`. These tests are related to working with IP networks, including checking if an IP belongs to a network.
* **Host and Port Manipulation:** `TestSplitHostPort`, `TestJoinHostPort`. These tests involve splitting and joining host and port strings.
* **IP Address Properties (Family, Scope):** `ipAddrFamilyTests`, `TestIPAddrFamily`, `ipAddrScopeTests`, `TestIPAddrScope`. These tests check various properties of IP addresses, such as whether they are IPv4 or IPv6, loopback, multicast, etc.
* **Lookup Functionality:** `TestLookupWithIP`. This tests if `LookupIP` and `LookupHost` work correctly with IP address strings.
* **Benchmarking `Equal` Method:** `BenchmarkIPEqual`. This benchmarks the performance of comparing IP addresses.
* **Error Handling:**  The tests often include checks for `err != nil` or comparing the error type.

**3. Deep Dive into Specific Test Structures:**

For each functional area, I examine the test structures (`struct` definitions like `parseIPTests`, `ipStringTests`, etc.). This reveals the input data, expected output, and error conditions being tested. For example, `parseIPTests` shows various valid and invalid IP address strings and their expected `net.IP` representations (or `nil` for invalid cases).

**4. Identifying Go Language Features:**

Based on the identified functional areas and test structures, I can deduce the Go language features being tested:

* **`net.ParseIP`:** Parsing IP address strings.
* **`IP.String()` and `IP.MarshalText()`/`IP.UnmarshalText()`/`IP.AppendText()`:**  String conversion of `net.IP`.
* **`net.IPv4` and `net.IPv6`:**  Creating `net.IP` objects for IPv4 and IPv6 addresses.
* **`net.IPv4Mask` and `net.IPMask`:** Creating and representing IP masks.
* **`IP.Mask()`:**  Applying an IP mask to an IP address.
* **`net.ParseCIDR`:** Parsing CIDR notation.
* **`net.IPNet`:** Representing IP networks.
* **`IPNet.Contains()`:** Checking if an IP address belongs to a network.
* **`IPNet.String()`:**  String representation of `net.IPNet`.
* **`net.CIDRMask()`:** Creating `net.IPMask` from a CIDR prefix length.
* **`IP.Equal()`:**  Comparing two IP addresses.
* **`net.LookupIP` and `net.LookupHost`:**  Looking up IP addresses and hostnames.
* **`net.SplitHostPort` and `net.JoinHostPort`:** Manipulating host and port strings.
* **IP address classification methods (`IsUnspecified`, `IsLoopback`, etc.).**

**5. Inferring Implementation Details (Reasoning and Examples):**

For each Go feature, I try to infer how it might be implemented and create example usage:

* **`ParseIP`:**  Likely involves string splitting, validation of numeric ranges for IPv4, and handling different IPv6 formats (compressed, IPv4-mapped).
* **`String()`/`MarshalText()`:**  Needs logic to format IPv4 addresses with dots and IPv6 addresses with colons, handling compression.
* **`Mask()`:**  Bitwise AND operation between the IP address and the mask.
* **`ParseCIDR`:**  Splitting the string by `/`, parsing the IP address, and creating the mask based on the prefix length.
* **`Contains()`:**  Applying the network mask to both the network address and the tested IP address and comparing the results.
* **`SplitHostPort`:**  Looking for the last colon, handling IPv6 addresses enclosed in square brackets.
* **`JoinHostPort`:**  Adding a colon, enclosing IPv6 addresses in square brackets.

**6. Identifying Potential Pitfalls:**

Based on the test cases and my understanding, I consider potential errors users might make:

* **Incorrect IP Address Formats:** Leading zeros, out-of-range values, extra or missing separators.
* **Invalid CIDR Notation:** Incorrect prefix length, using a mask instead of a prefix length.
* **Misunderstanding IPv6 Compression:** Not realizing that `::` can only be used once.
* **Forgetting Square Brackets for IPv6 in Host:Port:**  Causing issues with `SplitHostPort`.

**7. Structuring the Answer:**

Finally, I organize the information into a clear and structured answer, addressing each part of the prompt:

* **功能列表 (List of Functions):**  List the key Go functions being tested.
* **Go 语言功能实现 (Go Language Feature Implementation):** For each key feature, provide a brief explanation and a code example with input and expected output.
* **代码推理 (Code Reasoning):**  Explain the likely implementation logic behind certain functions, like `ParseIP` and `Contains`.
* **命令行参数处理 (Command Line Arguments):**  Note that this code is primarily for testing and doesn't involve direct command-line argument processing.
* **易犯错的点 (Common Mistakes):**  List the potential pitfalls identified earlier.

This systematic approach ensures a comprehensive and accurate analysis of the provided Go code snippet.
这个`go/src/net/ip_test.go` 文件是 Go 语言标准库 `net` 包中关于 IP 地址处理功能的**单元测试**代码。它的主要功能是验证 `net` 包中与 IP 地址相关的各种函数和方法的正确性。

更具体地说，这个文件测试了以下 Go 语言功能的实现：

1. **IP 地址的解析 (`ParseIP`)**:
   - 功能：将字符串形式的 IP 地址（包括 IPv4 和 IPv6）解析为 `net.IP` 类型。
   - Go 代码示例：
     ```go
     package main

     import (
         "fmt"
         "net"
     )

     func main() {
         ipStr := "192.168.1.1"
         ip := net.ParseIP(ipStr)
         if ip != nil {
             fmt.Println("解析成功:", ip) // 输出: 解析成功: 192.168.1.1
         } else {
             fmt.Println("解析失败")
         }

         ipStr2 := "2001:db8::1"
         ip2 := net.ParseIP(ipStr2)
         if ip2 != nil {
             fmt.Println("解析成功:", ip2) // 输出: 解析成功: 2001:db8::1
         } else {
             fmt.Println("解析失败")
         }

         invalidIP := "192.168.1.256"
         ip3 := net.ParseIP(invalidIP)
         if ip3 == nil {
             fmt.Println("解析失败，预期行为") // 输出: 解析失败，预期行为
         }
     }
     ```
   - 假设输入：`"192.168.1.1"`, `"2001:db8::1"`, `"192.168.1.256"`
   - 预期输出：对于前两个输入，解析成功并返回对应的 `net.IP` 对象。对于第三个输入，解析失败并返回 `nil`。

2. **IP 地址的字符串表示 (`String`, `MarshalText`, `UnmarshalText`, `AppendText`)**:
   - 功能：将 `net.IP` 类型转换为字符串形式，以及从字符串形式解析回 `net.IP` 类型。
   - Go 代码示例：
     ```go
     package main

     import (
         "fmt"
         "net"
     )

     func main() {
         ip := net.ParseIP("192.168.1.1")
         ipStr := ip.String()
         fmt.Println("IP 地址的字符串表示:", ipStr) // 输出: IP 地址的字符串表示: 192.168.1.1

         ip2 := net.ParseIP("2001:db8::1")
         ipStr2 := ip2.String()
         fmt.Println("IPv6 地址的字符串表示:", ipStr2) // 输出: IPv6 地址的字符串表示: 2001:db8::1

         var ip3 net.IP
         err := ip3.UnmarshalText([]byte("127.0.0.1"))
         if err == nil {
             fmt.Println("UnmarshalText 解析成功:", ip3) // 输出: UnmarshalText 解析成功: 127.0.0.1
         }

         buf := make([]byte, 0, 64)
         buf = ip.AppendText(buf)
         fmt.Println("AppendText 结果:", string(buf)) // 输出: AppendText 结果: 192.168.1.1
     }
     ```
   - 假设输入：一个 `net.IP` 对象，例如 `net.ParseIP("192.168.1.1")`。
   - 预期输出：`String()` 方法返回 `"192.168.1.1"`。 `MarshalText()` 返回 `[]byte("192.168.1.1")`。 `UnmarshalText()` 可以从 `[]byte("192.168.1.1")` 成功解析回 `net.IP` 对象。 `AppendText` 将 IP 地址的文本表示追加到提供的字节切片中。

3. **IP 地址查找 (`LookupIP`, `LookupHost`)**:
   - 功能：通过 IP 地址字符串查找对应的 IP 地址列表，以及通过主机名查找对应的 IP 地址列表。这里的测试用例验证了可以直接使用 IP 地址字符串作为参数进行查找。
   - Go 代码示例：
     ```go
     package main

     import (
         "fmt"
         "net"
     )

     func main() {
         ips, err := net.LookupIP("127.0.0.1")
         if err == nil {
             fmt.Println("LookupIP 结果:", ips) // 输出: LookupIP 结果: [127.0.0.1]
         }

         hosts, err := net.LookupHost("127.0.0.1")
         if err == nil {
             fmt.Println("LookupHost 结果:", hosts) // 输出: LookupHost 结果: [127.0.0.1]
         }
     }
     ```
   - 假设输入：IP 地址字符串 `"127.0.0.1"`。
   - 预期输出：`LookupIP` 返回包含 `net.ParseIP("127.0.0.1")` 的 IP 地址切片。 `LookupHost` 返回包含字符串 `"127.0.0.1"` 的主机名切片。

4. **IP 地址掩码 (`IPMask`) 及其操作 (`Mask`, `String`)**:
   - 功能：表示和操作 IP 地址掩码，用于确定网络地址。
   - Go 代码示例：
     ```go
     package main

     import (
         "fmt"
         "net"
     )

     func main() {
         ip := net.ParseIP("192.168.1.127")
         mask := net.IPv4Mask(255, 255, 255, 0)
         network := ip.Mask(mask)
         fmt.Println("网络地址:", network) // 输出: 网络地址: 192.168.1.0

         maskStr := mask.String()
         fmt.Println("掩码的字符串表示:", maskStr) // 输出: 掩码的字符串表示: ffffffff00000000
     }
     ```
   - 假设输入：IP 地址 `net.ParseIP("192.168.1.127")` 和掩码 `net.IPv4Mask(255, 255, 255, 0)`。
   - 预期输出：`Mask` 方法返回网络地址 `192.168.1.0`。 `String()` 方法返回掩码的十六进制字符串表示 `"ffffffff00000000"`。

5. **CIDR 地址解析 (`ParseCIDR`)**:
   - 功能：将 CIDR (Classless Inter-Domain Routing) 格式的字符串解析为 IP 地址和网络地址信息。
   - Go 代码示例：
     ```go
     package main

     import (
         "fmt"
         "net"
     )

     func main() {
         cidrStr := "192.168.1.0/24"
         ip, ipnet, err := net.ParseCIDR(cidrStr)
         if err == nil {
             fmt.Println("IP 地址:", ip)    // 输出: IP 地址: 192.168.1.0
             fmt.Println("网络地址:", ipnet) // 输出: 网络地址: 192.168.1.0/24
         }
     }
     ```
   - 假设输入：CIDR 字符串 `"192.168.1.0/24"`。
   - 预期输出：`ParseCIDR` 返回 IP 地址 `192.168.1.0` 和 `net.IPNet` 对象，其 IP 为 `192.168.1.0`，掩码为 `/24` 对应的掩码。

6. **IP 网络 (`IPNet`) 及其操作 (`Contains`, `String`)**:
   - 功能：表示和操作 IP 网络，例如判断一个 IP 地址是否属于某个网络。
   - Go 代码示例：
     ```go
     package main

     import (
         "fmt"
         "net"
     )

     func main() {
         _, ipnet, _ := net.ParseCIDR("192.168.1.0/24")
         ip := net.ParseIP("192.168.1.100")
         contains := ipnet.Contains(ip)
         fmt.Println("IP 是否在网络中:", contains) // 输出: IP 是否在网络中: true

         netStr := ipnet.String()
         fmt.Println("IPNet 的字符串表示:", netStr) // 输出: IPNet 的字符串表示: 192.168.1.0/24
     }
     ```
   - 假设输入：一个 `net.IPNet` 对象（例如，通过 `net.ParseCIDR` 创建）和一个 `net.IP` 对象。
   - 预期输出：`Contains` 方法返回 `true` 如果 IP 地址在网络内，否则返回 `false`。 `String()` 方法返回 CIDR 格式的字符串表示。

7. **CIDR 掩码创建 (`CIDRMask`)**:
   - 功能：根据前缀长度创建 IP 掩码。
   - Go 代码示例：
     ```go
     package main

     import (
         "fmt"
         "net"
     )

     func main() {
         mask := net.CIDRMask(24, 32)
         fmt.Println("CIDR 掩码:", mask) // 输出: CIDR 掩码: [255 255 255 0]
     }
     ```
   - 假设输入：`ones = 24`, `bits = 32` (表示 IPv4)。
   - 预期输出：返回 `net.IPv4Mask(255, 255, 255, 0)`。

8. **分割主机和端口 (`SplitHostPort`) 和连接主机和端口 (`JoinHostPort`)**:
   - 功能：处理包含主机名（或 IP 地址）和端口号的字符串。
   - Go 代码示例：
     ```go
     package main

     import (
         "fmt"
         "net"
     )

     func main() {
         host, port, err := net.SplitHostPort("localhost:8080")
         if err == nil {
             fmt.Println("主机:", host, "端口:", port) // 输出: 主机: localhost 端口: 8080
         }

         hostPort := net.JoinHostPort("127.0.0.1", "80")
         fmt.Println("连接后的主机和端口:", hostPort) // 输出: 连接后的主机和端口: 127.0.0.1:80
     }
     ```
   - 假设输入：`SplitHostPort("localhost:8080")` 和 `JoinHostPort("127.0.0.1", "80")`。
   - 预期输出：`SplitHostPort` 返回 `"localhost"` 和 `"8080"`。 `JoinHostPort` 返回 `"127.0.0.1:80"`。

9. **IP 地址类型判断 (例如 `IsLoopback`, `IsGlobalUnicast`, `IsPrivate` 等)**:
   - 功能：判断 IP 地址是否属于特定的类型。
   - Go 代码示例：
     ```go
     package main

     import (
         "fmt"
         "net"
     )

     func main() {
         ip := net.ParseIP("127.0.0.1")
         fmt.Println("是否是环回地址:", ip.IsLoopback()) // 输出: 是否是环回地址: true

         ip2 := net.ParseIP("8.8.8.8")
         fmt.Println("是否是全局单播地址:", ip2.IsGlobalUnicast()) // 输出: 是否是全局单播地址: true
     }
     ```
   - 假设输入：不同的 IP 地址，例如 `net.ParseIP("127.0.0.1")` 和 `net.ParseIP("8.8.8.8")`。
   - 预期输出：`IsLoopback()` 对于 `127.0.0.1` 返回 `true`，对于 `8.8.8.8` 返回 `false`。 `IsGlobalUnicast()` 对于 `8.8.8.8` 返回 `true`，对于私有 IP 地址返回 `false`。

**代码推理示例 (`ParseIP`)**:

`ParseIP` 函数的实现可能包含以下步骤：

1. **检查输入字符串的格式**: 判断是否包含点号 (`.`) 或冒号 (`:`), 以初步判断是 IPv4 还是 IPv6。
2. **IPv4 处理**:
   - 如果包含点号，则按点号分割字符串。
   - 验证分割后的四个部分是否都是数字，并且在 `0` 到 `255` 的范围内。
   - 如果验证通过，则创建一个包含四个字节的 `net.IP` 对象。
3. **IPv6 处理**:
   - 如果包含冒号，则按冒号分割字符串。
   - 处理 IPv6 压缩的情况 (`::`)。
   - 将每个十六进制部分转换为数字，并验证是否在正确的范围内。
   - 如果验证通过，则创建一个包含 16 个字节的 `net.IP` 对象。
4. **错误处理**: 如果字符串格式不正确或数字超出范围，则返回 `nil`。

**假设的输入与输出 (`ParseIP`)**:

- **输入**: `"192.168.1.1"`
- **输出**: `net.IP{192, 168, 1, 1}`

- **输入**: `"2001:db8::1"`
- **输出**: `net.IP{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}`

- **输入**: `"invalid-ip"`
- **输出**: `nil`

**命令行参数的具体处理**:

这个测试文件本身不处理命令行参数。它是作为 `go test` 命令的一部分运行的。`go test` 命令会扫描当前目录（或指定的包），查找以 `_test.go` 结尾的文件，并执行其中的测试函数。

**使用者易犯错的点**:

1. **`ParseIP` 解析 IPv4 时的前导零**:  如测试用例所示，`"127.001.002.003"` 会解析失败。Go 的 `ParseIP` 不允许 IPv4 地址的段中带有前导零。
   ```go
   package main

   import (
       "fmt"
       "net"
   )

   func main() {
       ip := net.ParseIP("127.001.0.1")
       if ip == nil {
           fmt.Println("解析失败，不允许前导零") // 输出: 解析失败，不允许前导零
       }
   }
   ```

2. **`ParseCIDR` 期望的是前缀长度，而不是掩码**:  用户可能会错误地将掩码（例如 `"255.255.255.0"`) 放在 `/` 后面。
   ```go
   package main

   import (
       "fmt"
       "net"
   )

   func main() {
       _, _, err := net.ParseCIDR("192.168.1.0/255.255.255.0")
       if err != nil {
           fmt.Println("解析失败，应该使用前缀长度") // 输出: 解析失败，应该使用前缀长度
       }
   }
   ```

3. **`SplitHostPort` 处理 IPv6 地址时需要方括号**: 如果 IPv6 地址没有被方括号 `[]` 包围，`SplitHostPort` 可能会解析错误。
   ```go
   package main

   import (
       "fmt"
       "net"
   )

   func main() {
       host, port, err := net.SplitHostPort("[2001:db8::1]:80")
       if err == nil {
           fmt.Println("IPv6 地址和端口:", host, port) // 输出: IPv6 地址和端口: 2001:db8::1 80
       }

       _, _, err = net.SplitHostPort("2001:db8::1:80")
       if err != nil {
           fmt.Println("解析失败，IPv6 地址需要方括号") // 输出: 解析失败，IPv6 地址需要方括号
       }
   }
   ```

总而言之，`go/src/net/ip_test.go` 是对 Go 语言 `net` 包中 IP 地址处理功能进行全面测试的重要组成部分，确保了这些核心网络功能的稳定性和正确性。

Prompt: 
```
这是路径为go/src/net/ip_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package net

import (
	"bytes"
	"math/rand"
	"reflect"
	"runtime"
	"testing"
)

var parseIPTests = []struct {
	in  string
	out IP
}{
	{"127.0.1.2", IPv4(127, 0, 1, 2)},
	{"127.0.0.1", IPv4(127, 0, 0, 1)},
	{"::ffff:127.1.2.3", IPv4(127, 1, 2, 3)},
	{"::ffff:7f01:0203", IPv4(127, 1, 2, 3)},
	{"0:0:0:0:0000:ffff:127.1.2.3", IPv4(127, 1, 2, 3)},
	{"0:0:0:0::ffff:127.1.2.3", IPv4(127, 1, 2, 3)},

	{"2001:4860:0:2001::68", IP{0x20, 0x01, 0x48, 0x60, 0, 0, 0x20, 0x01, 0, 0, 0, 0, 0, 0, 0x00, 0x68}},
	{"2001:4860:0000:2001:0000:0000:0000:0068", IP{0x20, 0x01, 0x48, 0x60, 0, 0, 0x20, 0x01, 0, 0, 0, 0, 0, 0, 0x00, 0x68}},

	{"-0.0.0.0", nil},
	{"0.-1.0.0", nil},
	{"0.0.-2.0", nil},
	{"0.0.0.-3", nil},
	{"127.0.0.256", nil},
	{"abc", nil},
	{"123:", nil},
	{"fe80::1%lo0", nil},
	{"fe80::1%911", nil},
	{"", nil},
	//6 zeroes in one group
	{"0:0:0:0:000000:ffff:127.1.2.3", nil},
	//5 zeroes in one group edge case
	{"0:0:0:0:00000:ffff:127.1.2.3", nil},
	{"a1:a2:a3:a4::b1:b2:b3:b4", nil}, // Issue 6628
	{"127.001.002.003", nil},
	{"::ffff:127.001.002.003", nil},
	{"123.000.000.000", nil},
	{"1.2..4", nil},
	{"0123.0.0.1", nil},
}

func TestParseIP(t *testing.T) {
	for _, tt := range parseIPTests {
		if out := ParseIP(tt.in); !reflect.DeepEqual(out, tt.out) {
			t.Errorf("ParseIP(%q) = %v, want %v", tt.in, out, tt.out)
		}
		if tt.in == "" {
			// Tested in TestMarshalEmptyIP below.
			continue
		}
		var out IP
		if err := out.UnmarshalText([]byte(tt.in)); !reflect.DeepEqual(out, tt.out) || (tt.out == nil) != (err != nil) {
			t.Errorf("IP.UnmarshalText(%q) = %v, %v, want %v", tt.in, out, err, tt.out)
		}
	}
}

func TestLookupWithIP(t *testing.T) {
	_, err := LookupIP("")
	if err == nil {
		t.Errorf(`LookupIP("") succeeded, should fail`)
	}
	_, err = LookupHost("")
	if err == nil {
		t.Errorf(`LookupIP("") succeeded, should fail`)
	}

	// Test that LookupHost and LookupIP, which normally
	// expect host names, work with IP addresses.
	for _, tt := range parseIPTests {
		if tt.out != nil {
			addrs, err := LookupHost(tt.in)
			if len(addrs) != 1 || addrs[0] != tt.in || err != nil {
				t.Errorf("LookupHost(%q) = %v, %v, want %v, nil", tt.in, addrs, err, []string{tt.in})
			}
		} else if !testing.Short() {
			// We can't control what the host resolver does; if it can resolve, say,
			// 127.0.0.256 or fe80::1%911 or a host named 'abc', who are we to judge?
			// Warn about these discrepancies but don't fail the test.
			addrs, err := LookupHost(tt.in)
			if err == nil {
				t.Logf("warning: LookupHost(%q) = %v, want error", tt.in, addrs)
			}
		}

		if tt.out != nil {
			ips, err := LookupIP(tt.in)
			if len(ips) != 1 || !reflect.DeepEqual(ips[0], tt.out) || err != nil {
				t.Errorf("LookupIP(%q) = %v, %v, want %v, nil", tt.in, ips, err, []IP{tt.out})
			}
		} else if !testing.Short() {
			ips, err := LookupIP(tt.in)
			// We can't control what the host resolver does. See above.
			if err == nil {
				t.Logf("warning: LookupIP(%q) = %v, want error", tt.in, ips)
			}
		}
	}
}

func BenchmarkParseIP(b *testing.B) {
	testHookUninstaller.Do(uninstallTestHooks)

	for i := 0; i < b.N; i++ {
		for _, tt := range parseIPTests {
			ParseIP(tt.in)
		}
	}
}

func BenchmarkParseIPValidIPv4(b *testing.B) {
	testHookUninstaller.Do(uninstallTestHooks)

	for i := 0; i < b.N; i++ {
		ParseIP("192.0.2.1")
	}
}

func BenchmarkParseIPValidIPv6(b *testing.B) {
	testHookUninstaller.Do(uninstallTestHooks)

	for i := 0; i < b.N; i++ {
		ParseIP("2001:DB8::1")
	}
}

// Issue 6339
func TestMarshalEmptyIP(t *testing.T) {
	for _, in := range [][]byte{nil, []byte("")} {
		var out = IP{1, 2, 3, 4}
		if err := out.UnmarshalText(in); err != nil || out != nil {
			t.Errorf("UnmarshalText(%v) = %v, %v; want nil, nil", in, out, err)
		}
	}
	var ip IP
	got, err := ip.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []byte("")) {
		t.Errorf(`got %#v, want []byte("")`, got)
	}

	buf := make([]byte, 4)
	got, err = ip.AppendText(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []byte("\x00\x00\x00\x00")) {
		t.Errorf(`got %#v, want []byte("\x00\x00\x00\x00")`, got)
	}
}

var ipStringTests = []*struct {
	in  IP     // see RFC 791 and RFC 4291
	str string // see RFC 791, RFC 4291 and RFC 5952
	byt []byte
	error
}{
	// IPv4 address
	{
		IP{192, 0, 2, 1},
		"192.0.2.1",
		[]byte("192.0.2.1"),
		nil,
	},
	{
		IP{0, 0, 0, 0},
		"0.0.0.0",
		[]byte("0.0.0.0"),
		nil,
	},

	// IPv4-mapped IPv6 address
	{
		IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 1},
		"192.0.2.1",
		[]byte("192.0.2.1"),
		nil,
	},
	{
		IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0},
		"0.0.0.0",
		[]byte("0.0.0.0"),
		nil,
	},

	// IPv6 address
	{
		IP{0x20, 0x1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0x1, 0x23, 0, 0x12, 0, 0x1},
		"2001:db8::123:12:1",
		[]byte("2001:db8::123:12:1"),
		nil,
	},
	{
		IP{0x20, 0x1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1},
		"2001:db8::1",
		[]byte("2001:db8::1"),
		nil,
	},
	{
		IP{0x20, 0x1, 0xd, 0xb8, 0, 0, 0, 0x1, 0, 0, 0, 0x1, 0, 0, 0, 0x1},
		"2001:db8:0:1:0:1:0:1",
		[]byte("2001:db8:0:1:0:1:0:1"),
		nil,
	},
	{
		IP{0x20, 0x1, 0xd, 0xb8, 0, 0x1, 0, 0, 0, 0x1, 0, 0, 0, 0x1, 0, 0},
		"2001:db8:1:0:1:0:1:0",
		[]byte("2001:db8:1:0:1:0:1:0"),
		nil,
	},
	{
		IP{0x20, 0x1, 0, 0, 0, 0, 0, 0, 0, 0x1, 0, 0, 0, 0, 0, 0x1},
		"2001::1:0:0:1",
		[]byte("2001::1:0:0:1"),
		nil,
	},
	{
		IP{0x20, 0x1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0x1, 0, 0, 0, 0, 0, 0},
		"2001:db8:0:0:1::",
		[]byte("2001:db8:0:0:1::"),
		nil,
	},
	{
		IP{0x20, 0x1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0x1, 0, 0, 0, 0, 0, 0x1},
		"2001:db8::1:0:0:1",
		[]byte("2001:db8::1:0:0:1"),
		nil,
	},
	{
		IP{0x20, 0x1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0xa, 0, 0xb, 0, 0xc, 0, 0xd},
		"2001:db8::a:b:c:d",
		[]byte("2001:db8::a:b:c:d"),
		nil,
	},
	{
		IPv6unspecified,
		"::",
		[]byte("::"),
		nil,
	},

	// IP wildcard equivalent address in Dial/Listen API
	{
		nil,
		"<nil>",
		nil,
		nil,
	},

	// Opaque byte sequence
	{
		IP{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef},
		"?0123456789abcdef",
		nil,
		&AddrError{Err: "invalid IP address", Addr: "0123456789abcdef"},
	},
}

func TestIPString(t *testing.T) {
	for _, tt := range ipStringTests {
		if out := tt.in.String(); out != tt.str {
			t.Errorf("IP.String(%v) = %q, want %q", tt.in, out, tt.str)
		}
		if out, err := tt.in.MarshalText(); !bytes.Equal(out, tt.byt) || !reflect.DeepEqual(err, tt.error) {
			t.Errorf("IP.MarshalText(%v) = %v, %v, want %v, %v", tt.in, out, err, tt.byt, tt.error)
		}
		buf := make([]byte, 4, 32)
		if out, err := tt.in.AppendText(buf); !bytes.Equal(out[4:], tt.byt) || !reflect.DeepEqual(err, tt.error) {
			t.Errorf("IP.AppendText(%v) = %v, %v, want %v, %v", tt.in, out[4:], err, tt.byt, tt.error)
		}
	}
}

func TestIPAppendTextNoAllocs(t *testing.T) {
	// except the invalid IP
	for _, tt := range ipStringTests[:len(ipStringTests)-1] {
		allocs := int(testing.AllocsPerRun(1000, func() {
			buf := make([]byte, 0, 64)
			_, _ = tt.in.AppendText(buf)
		}))
		if allocs != 0 {
			t.Errorf("IP(%q) AppendText allocs: %d times, want 0", tt.in, allocs)
		}
	}
}

func BenchmarkIPMarshalText(b *testing.B) {
	b.Run("IPv4", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		ip := IP{192, 0, 2, 1}
		for range b.N {
			_, _ = ip.MarshalText()
		}
	})
	b.Run("IPv6", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		ip := IP{0x20, 0x1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0xa, 0, 0xb, 0, 0xc, 0, 0xd}
		for range b.N {
			_, _ = ip.MarshalText()
		}
	})
	b.Run("IPv6_long", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		// fd7a:115c:a1e0:ab12:4843:cd96:626b:430b
		ip := IP{253, 122, 17, 92, 161, 224, 171, 18, 72, 67, 205, 150, 98, 107, 67, 11}
		for range b.N {
			_, _ = ip.MarshalText()
		}
	})
}

var sink string

func BenchmarkIPString(b *testing.B) {
	testHookUninstaller.Do(uninstallTestHooks)

	b.Run("IPv4", func(b *testing.B) {
		benchmarkIPString(b, IPv4len)
	})

	b.Run("IPv6", func(b *testing.B) {
		benchmarkIPString(b, IPv6len)
	})
}

func benchmarkIPString(b *testing.B, size int) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, tt := range ipStringTests {
			if tt.in != nil && len(tt.in) == size {
				sink = tt.in.String()
			}
		}
	}
}

var ipMaskTests = []struct {
	in   IP
	mask IPMask
	out  IP
}{
	{IPv4(192, 168, 1, 127), IPv4Mask(255, 255, 255, 128), IPv4(192, 168, 1, 0)},
	{IPv4(192, 168, 1, 127), IPMask(ParseIP("255.255.255.192")), IPv4(192, 168, 1, 64)},
	{IPv4(192, 168, 1, 127), IPMask(ParseIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffe0")), IPv4(192, 168, 1, 96)},
	{IPv4(192, 168, 1, 127), IPv4Mask(255, 0, 255, 0), IPv4(192, 0, 1, 0)},
	{ParseIP("2001:db8::1"), IPMask(ParseIP("ffff:ff80::")), ParseIP("2001:d80::")},
	{ParseIP("2001:db8::1"), IPMask(ParseIP("f0f0:0f0f::")), ParseIP("2000:d08::")},
}

func TestIPMask(t *testing.T) {
	for _, tt := range ipMaskTests {
		if out := tt.in.Mask(tt.mask); out == nil || !tt.out.Equal(out) {
			t.Errorf("IP(%v).Mask(%v) = %v, want %v", tt.in, tt.mask, out, tt.out)
		}
	}
}

var ipMaskStringTests = []struct {
	in  IPMask
	out string
}{
	{IPv4Mask(255, 255, 255, 240), "fffffff0"},
	{IPv4Mask(255, 0, 128, 0), "ff008000"},
	{IPMask(ParseIP("ffff:ff80::")), "ffffff80000000000000000000000000"},
	{IPMask(ParseIP("ef00:ff80::cafe:0")), "ef00ff800000000000000000cafe0000"},
	{nil, "<nil>"},
}

func TestIPMaskString(t *testing.T) {
	for _, tt := range ipMaskStringTests {
		if out := tt.in.String(); out != tt.out {
			t.Errorf("IPMask.String(%v) = %q, want %q", tt.in, out, tt.out)
		}
	}
}

func BenchmarkIPMaskString(b *testing.B) {
	testHookUninstaller.Do(uninstallTestHooks)

	for i := 0; i < b.N; i++ {
		for _, tt := range ipMaskStringTests {
			sink = tt.in.String()
		}
	}
}

var parseCIDRTests = []struct {
	in  string
	ip  IP
	net *IPNet
	err error
}{
	{"135.104.0.0/32", IPv4(135, 104, 0, 0), &IPNet{IP: IPv4(135, 104, 0, 0), Mask: IPv4Mask(255, 255, 255, 255)}, nil},
	{"0.0.0.0/24", IPv4(0, 0, 0, 0), &IPNet{IP: IPv4(0, 0, 0, 0), Mask: IPv4Mask(255, 255, 255, 0)}, nil},
	{"135.104.0.0/24", IPv4(135, 104, 0, 0), &IPNet{IP: IPv4(135, 104, 0, 0), Mask: IPv4Mask(255, 255, 255, 0)}, nil},
	{"135.104.0.1/32", IPv4(135, 104, 0, 1), &IPNet{IP: IPv4(135, 104, 0, 1), Mask: IPv4Mask(255, 255, 255, 255)}, nil},
	{"135.104.0.1/24", IPv4(135, 104, 0, 1), &IPNet{IP: IPv4(135, 104, 0, 0), Mask: IPv4Mask(255, 255, 255, 0)}, nil},
	{"::1/128", ParseIP("::1"), &IPNet{IP: ParseIP("::1"), Mask: IPMask(ParseIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"))}, nil},
	{"abcd:2345::/127", ParseIP("abcd:2345::"), &IPNet{IP: ParseIP("abcd:2345::"), Mask: IPMask(ParseIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe"))}, nil},
	{"abcd:2345::/65", ParseIP("abcd:2345::"), &IPNet{IP: ParseIP("abcd:2345::"), Mask: IPMask(ParseIP("ffff:ffff:ffff:ffff:8000::"))}, nil},
	{"abcd:2345::/64", ParseIP("abcd:2345::"), &IPNet{IP: ParseIP("abcd:2345::"), Mask: IPMask(ParseIP("ffff:ffff:ffff:ffff::"))}, nil},
	{"abcd:2345::/63", ParseIP("abcd:2345::"), &IPNet{IP: ParseIP("abcd:2345::"), Mask: IPMask(ParseIP("ffff:ffff:ffff:fffe::"))}, nil},
	{"abcd:2345::/33", ParseIP("abcd:2345::"), &IPNet{IP: ParseIP("abcd:2345::"), Mask: IPMask(ParseIP("ffff:ffff:8000::"))}, nil},
	{"abcd:2345::/32", ParseIP("abcd:2345::"), &IPNet{IP: ParseIP("abcd:2345::"), Mask: IPMask(ParseIP("ffff:ffff::"))}, nil},
	{"abcd:2344::/31", ParseIP("abcd:2344::"), &IPNet{IP: ParseIP("abcd:2344::"), Mask: IPMask(ParseIP("ffff:fffe::"))}, nil},
	{"abcd:2300::/24", ParseIP("abcd:2300::"), &IPNet{IP: ParseIP("abcd:2300::"), Mask: IPMask(ParseIP("ffff:ff00::"))}, nil},
	{"abcd:2345::/24", ParseIP("abcd:2345::"), &IPNet{IP: ParseIP("abcd:2300::"), Mask: IPMask(ParseIP("ffff:ff00::"))}, nil},
	{"2001:DB8::/48", ParseIP("2001:DB8::"), &IPNet{IP: ParseIP("2001:DB8::"), Mask: IPMask(ParseIP("ffff:ffff:ffff::"))}, nil},
	{"2001:DB8::1/48", ParseIP("2001:DB8::1"), &IPNet{IP: ParseIP("2001:DB8::"), Mask: IPMask(ParseIP("ffff:ffff:ffff::"))}, nil},
	{"192.168.1.1/255.255.255.0", nil, nil, &ParseError{Type: "CIDR address", Text: "192.168.1.1/255.255.255.0"}},
	{"192.168.1.1/35", nil, nil, &ParseError{Type: "CIDR address", Text: "192.168.1.1/35"}},
	{"2001:db8::1/-1", nil, nil, &ParseError{Type: "CIDR address", Text: "2001:db8::1/-1"}},
	{"2001:db8::1/-0", nil, nil, &ParseError{Type: "CIDR address", Text: "2001:db8::1/-0"}},
	{"-0.0.0.0/32", nil, nil, &ParseError{Type: "CIDR address", Text: "-0.0.0.0/32"}},
	{"0.-1.0.0/32", nil, nil, &ParseError{Type: "CIDR address", Text: "0.-1.0.0/32"}},
	{"0.0.-2.0/32", nil, nil, &ParseError{Type: "CIDR address", Text: "0.0.-2.0/32"}},
	{"0.0.0.-3/32", nil, nil, &ParseError{Type: "CIDR address", Text: "0.0.0.-3/32"}},
	{"0.0.0.0/-0", nil, nil, &ParseError{Type: "CIDR address", Text: "0.0.0.0/-0"}},
	{"127.000.000.001/32", nil, nil, &ParseError{Type: "CIDR address", Text: "127.000.000.001/32"}},
	{"", nil, nil, &ParseError{Type: "CIDR address", Text: ""}},
}

func TestParseCIDR(t *testing.T) {
	for _, tt := range parseCIDRTests {
		ip, net, err := ParseCIDR(tt.in)
		if !reflect.DeepEqual(err, tt.err) {
			t.Errorf("ParseCIDR(%q) = %v, %v; want %v, %v", tt.in, ip, net, tt.ip, tt.net)
		}
		if err == nil && (!tt.ip.Equal(ip) || !tt.net.IP.Equal(net.IP) || !reflect.DeepEqual(net.Mask, tt.net.Mask)) {
			t.Errorf("ParseCIDR(%q) = %v, {%v, %v}; want %v, {%v, %v}", tt.in, ip, net.IP, net.Mask, tt.ip, tt.net.IP, tt.net.Mask)
		}
	}
}

var ipNetContainsTests = []struct {
	ip  IP
	net *IPNet
	ok  bool
}{
	{IPv4(172, 16, 1, 1), &IPNet{IP: IPv4(172, 16, 0, 0), Mask: CIDRMask(12, 32)}, true},
	{IPv4(172, 24, 0, 1), &IPNet{IP: IPv4(172, 16, 0, 0), Mask: CIDRMask(13, 32)}, false},
	{IPv4(192, 168, 0, 3), &IPNet{IP: IPv4(192, 168, 0, 0), Mask: IPv4Mask(0, 0, 255, 252)}, true},
	{IPv4(192, 168, 0, 4), &IPNet{IP: IPv4(192, 168, 0, 0), Mask: IPv4Mask(0, 255, 0, 252)}, false},
	{ParseIP("2001:db8:1:2::1"), &IPNet{IP: ParseIP("2001:db8:1::"), Mask: CIDRMask(47, 128)}, true},
	{ParseIP("2001:db8:1:2::1"), &IPNet{IP: ParseIP("2001:db8:2::"), Mask: CIDRMask(47, 128)}, false},
	{ParseIP("2001:db8:1:2::1"), &IPNet{IP: ParseIP("2001:db8:1::"), Mask: IPMask(ParseIP("ffff:0:ffff::"))}, true},
	{ParseIP("2001:db8:1:2::1"), &IPNet{IP: ParseIP("2001:db8:1::"), Mask: IPMask(ParseIP("0:0:0:ffff::"))}, false},
}

func TestIPNetContains(t *testing.T) {
	for _, tt := range ipNetContainsTests {
		if ok := tt.net.Contains(tt.ip); ok != tt.ok {
			t.Errorf("IPNet(%v).Contains(%v) = %v, want %v", tt.net, tt.ip, ok, tt.ok)
		}
	}
}

var ipNetStringTests = []struct {
	in  *IPNet
	out string
}{
	{&IPNet{IP: IPv4(192, 168, 1, 0), Mask: CIDRMask(26, 32)}, "192.168.1.0/26"},
	{&IPNet{IP: IPv4(192, 168, 1, 0), Mask: IPv4Mask(255, 0, 255, 0)}, "192.168.1.0/ff00ff00"},
	{&IPNet{IP: ParseIP("2001:db8::"), Mask: CIDRMask(55, 128)}, "2001:db8::/55"},
	{&IPNet{IP: ParseIP("2001:db8::"), Mask: IPMask(ParseIP("8000:f123:0:cafe::"))}, "2001:db8::/8000f1230000cafe0000000000000000"},
	{nil, "<nil>"},
}

func TestIPNetString(t *testing.T) {
	for _, tt := range ipNetStringTests {
		if out := tt.in.String(); out != tt.out {
			t.Errorf("IPNet.String(%v) = %q, want %q", tt.in, out, tt.out)
		}
	}
}

var cidrMaskTests = []struct {
	ones int
	bits int
	out  IPMask
}{
	{0, 32, IPv4Mask(0, 0, 0, 0)},
	{12, 32, IPv4Mask(255, 240, 0, 0)},
	{24, 32, IPv4Mask(255, 255, 255, 0)},
	{32, 32, IPv4Mask(255, 255, 255, 255)},
	{0, 128, IPMask{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
	{4, 128, IPMask{0xf0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
	{48, 128, IPMask{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
	{128, 128, IPMask{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
	{33, 32, nil},
	{32, 33, nil},
	{-1, 128, nil},
	{128, -1, nil},
}

func TestCIDRMask(t *testing.T) {
	for _, tt := range cidrMaskTests {
		if out := CIDRMask(tt.ones, tt.bits); !reflect.DeepEqual(out, tt.out) {
			t.Errorf("CIDRMask(%v, %v) = %v, want %v", tt.ones, tt.bits, out, tt.out)
		}
	}
}

var (
	v4addr         = IP{192, 168, 0, 1}
	v4mappedv6addr = IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 0, 1}
	v6addr         = IP{0x20, 0x1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0x1, 0x23, 0, 0x12, 0, 0x1}
	v4mask         = IPMask{255, 255, 255, 0}
	v4mappedv6mask = IPMask{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 255, 255, 255, 0}
	v6mask         = IPMask{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0}
	badaddr        = IP{192, 168, 0}
	badmask        = IPMask{255, 255, 0}
	v4maskzero     = IPMask{0, 0, 0, 0}
)

var networkNumberAndMaskTests = []struct {
	in  IPNet
	out IPNet
}{
	{IPNet{IP: v4addr, Mask: v4mask}, IPNet{IP: v4addr, Mask: v4mask}},
	{IPNet{IP: v4addr, Mask: v4mappedv6mask}, IPNet{IP: v4addr, Mask: v4mask}},
	{IPNet{IP: v4mappedv6addr, Mask: v4mappedv6mask}, IPNet{IP: v4addr, Mask: v4mask}},
	{IPNet{IP: v4mappedv6addr, Mask: v6mask}, IPNet{IP: v4addr, Mask: v4maskzero}},
	{IPNet{IP: v4addr, Mask: v6mask}, IPNet{IP: v4addr, Mask: v4maskzero}},
	{IPNet{IP: v6addr, Mask: v6mask}, IPNet{IP: v6addr, Mask: v6mask}},
	{IPNet{IP: v6addr, Mask: v4mappedv6mask}, IPNet{IP: v6addr, Mask: v4mappedv6mask}},
	{in: IPNet{IP: v6addr, Mask: v4mask}},
	{in: IPNet{IP: v4addr, Mask: badmask}},
	{in: IPNet{IP: v4mappedv6addr, Mask: badmask}},
	{in: IPNet{IP: v6addr, Mask: badmask}},
	{in: IPNet{IP: badaddr, Mask: v4mask}},
	{in: IPNet{IP: badaddr, Mask: v4mappedv6mask}},
	{in: IPNet{IP: badaddr, Mask: v6mask}},
	{in: IPNet{IP: badaddr, Mask: badmask}},
}

func TestNetworkNumberAndMask(t *testing.T) {
	for _, tt := range networkNumberAndMaskTests {
		ip, m := networkNumberAndMask(&tt.in)
		out := &IPNet{IP: ip, Mask: m}
		if !reflect.DeepEqual(&tt.out, out) {
			t.Errorf("networkNumberAndMask(%v) = %v, want %v", tt.in, out, &tt.out)
		}
	}
}

func TestSplitHostPort(t *testing.T) {
	for _, tt := range []struct {
		hostPort string
		host     string
		port     string
	}{
		// Host name
		{"localhost:http", "localhost", "http"},
		{"localhost:80", "localhost", "80"},

		// Go-specific host name with zone identifier
		{"localhost%lo0:http", "localhost%lo0", "http"},
		{"localhost%lo0:80", "localhost%lo0", "80"},
		{"[localhost%lo0]:http", "localhost%lo0", "http"}, // Go 1 behavior
		{"[localhost%lo0]:80", "localhost%lo0", "80"},     // Go 1 behavior

		// IP literal
		{"127.0.0.1:http", "127.0.0.1", "http"},
		{"127.0.0.1:80", "127.0.0.1", "80"},
		{"[::1]:http", "::1", "http"},
		{"[::1]:80", "::1", "80"},

		// IP literal with zone identifier
		{"[::1%lo0]:http", "::1%lo0", "http"},
		{"[::1%lo0]:80", "::1%lo0", "80"},

		// Go-specific wildcard for host name
		{":http", "", "http"}, // Go 1 behavior
		{":80", "", "80"},     // Go 1 behavior

		// Go-specific wildcard for service name or transport port number
		{"golang.org:", "golang.org", ""}, // Go 1 behavior
		{"127.0.0.1:", "127.0.0.1", ""},   // Go 1 behavior
		{"[::1]:", "::1", ""},             // Go 1 behavior

		// Opaque service name
		{"golang.org:https%foo", "golang.org", "https%foo"}, // Go 1 behavior
	} {
		if host, port, err := SplitHostPort(tt.hostPort); host != tt.host || port != tt.port || err != nil {
			t.Errorf("SplitHostPort(%q) = %q, %q, %v; want %q, %q, nil", tt.hostPort, host, port, err, tt.host, tt.port)
		}
	}

	for _, tt := range []struct {
		hostPort string
		err      string
	}{
		{"golang.org", "missing port in address"},
		{"127.0.0.1", "missing port in address"},
		{"[::1]", "missing port in address"},
		{"[fe80::1%lo0]", "missing port in address"},
		{"[localhost%lo0]", "missing port in address"},
		{"localhost%lo0", "missing port in address"},

		{"::1", "too many colons in address"},
		{"fe80::1%lo0", "too many colons in address"},
		{"fe80::1%lo0:80", "too many colons in address"},

		// Test cases that didn't fail in Go 1

		{"[foo:bar]", "missing port in address"},
		{"[foo:bar]baz", "missing port in address"},
		{"[foo]bar:baz", "missing port in address"},

		{"[foo]:[bar]:baz", "too many colons in address"},

		{"[foo]:[bar]baz", "unexpected '[' in address"},
		{"foo[bar]:baz", "unexpected '[' in address"},

		{"foo]bar:baz", "unexpected ']' in address"},
	} {
		if host, port, err := SplitHostPort(tt.hostPort); err == nil {
			t.Errorf("SplitHostPort(%q) should have failed", tt.hostPort)
		} else {
			e := err.(*AddrError)
			if e.Err != tt.err {
				t.Errorf("SplitHostPort(%q) = _, _, %q; want %q", tt.hostPort, e.Err, tt.err)
			}
			if host != "" || port != "" {
				t.Errorf("SplitHostPort(%q) = %q, %q, err; want %q, %q, err on failure", tt.hostPort, host, port, "", "")
			}
		}
	}
}

func TestJoinHostPort(t *testing.T) {
	for _, tt := range []struct {
		host     string
		port     string
		hostPort string
	}{
		// Host name
		{"localhost", "http", "localhost:http"},
		{"localhost", "80", "localhost:80"},

		// Go-specific host name with zone identifier
		{"localhost%lo0", "http", "localhost%lo0:http"},
		{"localhost%lo0", "80", "localhost%lo0:80"},

		// IP literal
		{"127.0.0.1", "http", "127.0.0.1:http"},
		{"127.0.0.1", "80", "127.0.0.1:80"},
		{"::1", "http", "[::1]:http"},
		{"::1", "80", "[::1]:80"},

		// IP literal with zone identifier
		{"::1%lo0", "http", "[::1%lo0]:http"},
		{"::1%lo0", "80", "[::1%lo0]:80"},

		// Go-specific wildcard for host name
		{"", "http", ":http"}, // Go 1 behavior
		{"", "80", ":80"},     // Go 1 behavior

		// Go-specific wildcard for service name or transport port number
		{"golang.org", "", "golang.org:"}, // Go 1 behavior
		{"127.0.0.1", "", "127.0.0.1:"},   // Go 1 behavior
		{"::1", "", "[::1]:"},             // Go 1 behavior

		// Opaque service name
		{"golang.org", "https%foo", "golang.org:https%foo"}, // Go 1 behavior
	} {
		if hostPort := JoinHostPort(tt.host, tt.port); hostPort != tt.hostPort {
			t.Errorf("JoinHostPort(%q, %q) = %q; want %q", tt.host, tt.port, hostPort, tt.hostPort)
		}
	}
}

var ipAddrFamilyTests = []struct {
	in  IP
	af4 bool
	af6 bool
}{
	{IPv4bcast, true, false},
	{IPv4allsys, true, false},
	{IPv4allrouter, true, false},
	{IPv4zero, true, false},
	{IPv4(224, 0, 0, 1), true, false},
	{IPv4(127, 0, 0, 1), true, false},
	{IPv4(240, 0, 0, 1), true, false},
	{IPv6unspecified, false, true},
	{IPv6loopback, false, true},
	{IPv6interfacelocalallnodes, false, true},
	{IPv6linklocalallnodes, false, true},
	{IPv6linklocalallrouters, false, true},
	{ParseIP("ff05::a:b:c:d"), false, true},
	{ParseIP("fe80::1:2:3:4"), false, true},
	{ParseIP("2001:db8::123:12:1"), false, true},
}

func TestIPAddrFamily(t *testing.T) {
	for _, tt := range ipAddrFamilyTests {
		if af := tt.in.To4() != nil; af != tt.af4 {
			t.Errorf("verifying IPv4 address family for %q = %v, want %v", tt.in, af, tt.af4)
		}
		if af := len(tt.in) == IPv6len && tt.in.To4() == nil; af != tt.af6 {
			t.Errorf("verifying IPv6 address family for %q = %v, want %v", tt.in, af, tt.af6)
		}
	}
}

var ipAddrScopeTests = []struct {
	scope func(IP) bool
	in    IP
	ok    bool
}{
	{IP.IsUnspecified, IPv4zero, true},
	{IP.IsUnspecified, IPv4(127, 0, 0, 1), false},
	{IP.IsUnspecified, IPv6unspecified, true},
	{IP.IsUnspecified, IPv6interfacelocalallnodes, false},
	{IP.IsUnspecified, nil, false},
	{IP.IsLoopback, IPv4(127, 0, 0, 1), true},
	{IP.IsLoopback, IPv4(127, 255, 255, 254), true},
	{IP.IsLoopback, IPv4(128, 1, 2, 3), false},
	{IP.IsLoopback, IPv6loopback, true},
	{IP.IsLoopback, IPv6linklocalallrouters, false},
	{IP.IsLoopback, nil, false},
	{IP.IsMulticast, IPv4(224, 0, 0, 0), true},
	{IP.IsMulticast, IPv4(239, 0, 0, 0), true},
	{IP.IsMulticast, IPv4(240, 0, 0, 0), false},
	{IP.IsMulticast, IPv6linklocalallnodes, true},
	{IP.IsMulticast, IP{0xff, 0x05, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, true},
	{IP.IsMulticast, IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, false},
	{IP.IsMulticast, nil, false},
	{IP.IsInterfaceLocalMulticast, IPv4(224, 0, 0, 0), false},
	{IP.IsInterfaceLocalMulticast, IPv4(0xff, 0x01, 0, 0), false},
	{IP.IsInterfaceLocalMulticast, IPv6interfacelocalallnodes, true},
	{IP.IsInterfaceLocalMulticast, nil, false},
	{IP.IsLinkLocalMulticast, IPv4(224, 0, 0, 0), true},
	{IP.IsLinkLocalMulticast, IPv4(239, 0, 0, 0), false},
	{IP.IsLinkLocalMulticast, IPv4(0xff, 0x02, 0, 0), false},
	{IP.IsLinkLocalMulticast, IPv6linklocalallrouters, true},
	{IP.IsLinkLocalMulticast, IP{0xff, 0x05, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, false},
	{IP.IsLinkLocalMulticast, nil, false},
	{IP.IsLinkLocalUnicast, IPv4(169, 254, 0, 0), true},
	{IP.IsLinkLocalUnicast, IPv4(169, 255, 0, 0), false},
	{IP.IsLinkLocalUnicast, IPv4(0xfe, 0x80, 0, 0), false},
	{IP.IsLinkLocalUnicast, IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, true},
	{IP.IsLinkLocalUnicast, IP{0xfe, 0xc0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, false},
	{IP.IsLinkLocalUnicast, nil, false},
	{IP.IsGlobalUnicast, IPv4(240, 0, 0, 0), true},
	{IP.IsGlobalUnicast, IPv4(232, 0, 0, 0), false},
	{IP.IsGlobalUnicast, IPv4(169, 254, 0, 0), false},
	{IP.IsGlobalUnicast, IPv4bcast, false},
	{IP.IsGlobalUnicast, IP{0x20, 0x1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0x1, 0x23, 0, 0x12, 0, 0x1}, true},
	{IP.IsGlobalUnicast, IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, false},
	{IP.IsGlobalUnicast, IP{0xff, 0x05, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, false},
	{IP.IsGlobalUnicast, nil, false},
	{IP.IsPrivate, nil, false},
	{IP.IsPrivate, IPv4(1, 1, 1, 1), false},
	{IP.IsPrivate, IPv4(9, 255, 255, 255), false},
	{IP.IsPrivate, IPv4(10, 0, 0, 0), true},
	{IP.IsPrivate, IPv4(10, 255, 255, 255), true},
	{IP.IsPrivate, IPv4(11, 0, 0, 0), false},
	{IP.IsPrivate, IPv4(172, 15, 255, 255), false},
	{IP.IsPrivate, IPv4(172, 16, 0, 0), true},
	{IP.IsPrivate, IPv4(172, 16, 255, 255), true},
	{IP.IsPrivate, IPv4(172, 23, 18, 255), true},
	{IP.IsPrivate, IPv4(172, 31, 255, 255), true},
	{IP.IsPrivate, IPv4(172, 31, 0, 0), true},
	{IP.IsPrivate, IPv4(172, 32, 0, 0), false},
	{IP.IsPrivate, IPv4(192, 167, 255, 255), false},
	{IP.IsPrivate, IPv4(192, 168, 0, 0), true},
	{IP.IsPrivate, IPv4(192, 168, 255, 255), true},
	{IP.IsPrivate, IPv4(192, 169, 0, 0), false},
	{IP.IsPrivate, IP{0xfb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, false},
	{IP.IsPrivate, IP{0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, true},
	{IP.IsPrivate, IP{0xfc, 0xff, 0x12, 0, 0, 0, 0, 0x44, 0, 0, 0, 0, 0, 0, 0, 0}, true},
	{IP.IsPrivate, IP{0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, true},
	{IP.IsPrivate, IP{0xfe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, false},
}

func name(f any) string {
	return runtime.FuncForPC(reflect.ValueOf(f).Pointer()).Name()
}

func TestIPAddrScope(t *testing.T) {
	for _, tt := range ipAddrScopeTests {
		if ok := tt.scope(tt.in); ok != tt.ok {
			t.Errorf("%s(%q) = %v, want %v", name(tt.scope), tt.in, ok, tt.ok)
		}
		ip := tt.in.To4()
		if ip == nil {
			continue
		}
		if ok := tt.scope(ip); ok != tt.ok {
			t.Errorf("%s(%q) = %v, want %v", name(tt.scope), ip, ok, tt.ok)
		}
	}
}

func BenchmarkIPEqual(b *testing.B) {
	b.Run("IPv4", func(b *testing.B) {
		benchmarkIPEqual(b, IPv4len)
	})
	b.Run("IPv6", func(b *testing.B) {
		benchmarkIPEqual(b, IPv6len)
	})
}

func benchmarkIPEqual(b *testing.B, size int) {
	ips := make([]IP, 1000)
	for i := range ips {
		ips[i] = make(IP, size)
		rand.Read(ips[i])
	}
	// Half of the N are equal.
	for i := 0; i < b.N/2; i++ {
		x := ips[i%len(ips)]
		y := ips[i%len(ips)]
		x.Equal(y)
	}
	// The other half are not equal.
	for i := 0; i < b.N/2; i++ {
		x := ips[i%len(ips)]
		y := ips[(i+1)%len(ips)]
		x.Equal(y)
	}
}

"""



```