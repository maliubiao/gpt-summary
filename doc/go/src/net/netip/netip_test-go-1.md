Response:
Let's break down the thought process for analyzing this Go code snippet and generating the detailed explanation.

1. **Understand the Goal:** The request asks for an analysis of a Go test file (`netip_test.go`). Specifically, it asks for the functionalities tested, the Go features demonstrated, code examples, command-line argument handling (if any), common mistakes, and a summary of the file's purpose. This is the *what* we need to find.

2. **Identify the Core Subject:** The filename and the content clearly point to testing functionalities related to IP addresses and network prefixes. The `netip` package is the subject of these tests.

3. **High-Level Scan and Structure Recognition:** Quickly skim through the code to identify key components:
    * **Test Functions:** Functions starting with `Test...` are the core of the testing. Note the names: `TestPrefix`, `TestAddr`, `TestPrefixMarshalUnmarshal`, etc. This gives a good initial overview of the functionalities being tested.
    * **Helper Functions:** Functions like `mustIP`, `mustPrefix`, `makeIPv6`, `mustIPs` are helper functions to set up test cases. These are important for understanding how the tests are structured.
    * **Test Cases (Structs):**  Look for slices of structs (e.g., `tests := []struct{...}`). These define the individual test scenarios, including inputs, expected outputs, and sometimes flags (like `ok`).
    * **Assertions:**  Lines using `t.Run`, `t.Fatalf`, `t.Errorf` indicate assertions where the actual behavior is compared against the expected behavior.

4. **Detailed Analysis of Key Test Functions:** Now, go through each major test function and understand *what* it's testing.

    * **`TestPrefix`:**  This test seems to be the most comprehensive for the `Prefix` type. It checks:
        * Parsing prefixes from strings.
        * Accessing the IP address and prefix length.
        * Checking if an IP address is contained within a prefix.
        * String representation of a prefix.
        * Marshalling and unmarshalling (using `TestAppendToMarshal`).

    * **`TestAddr_Prefix`:** Focuses specifically on the `Prefix` method of the `Addr` type. It verifies the creation of a prefix from an IP and a number of bits, including error handling for invalid bit counts.

    * **`TestPrefixMarshalUnmarshal`:** Tests the JSON marshalling and unmarshalling of the `Prefix` type, ensuring data integrity during serialization and deserialization.

    * **`TestPrefixUnmarshalTextNonZero`:** Checks how `Prefix` handles unmarshalling from non-empty text.

    * **`TestIs4AndIs6`:**  Verifies the `Is4()` and `Is6()` methods of the `Addr` type.

    * **`TestIs4In6`:** Tests the `Is4In6()` and `Unmap()` methods, related to IPv4-in-IPv6 addresses.

    * **`TestPrefixMasked`:**  Checks the `Masked()` method of `Prefix`, which calculates the network address.

    * **`TestPrefixFromInvalidBits`:**  Specifically tests the behavior of `PrefixFrom` with invalid bit counts.

    * **`TestParsePrefixAllocs`:**  Focuses on memory allocations when parsing prefixes.

    * **`TestParsePrefixError`:**  Verifies error handling during prefix parsing with various invalid inputs.

    * **`TestPrefixIsSingleIP`:**  Tests the `IsSingleIP()` method of `Prefix`.

    * **`TestAs4`:** Checks the `As4()` method of `Addr`, which converts an IPv4 address to a byte array (and handles panics for non-IPv4 addresses).

    * **`TestPrefixOverlaps`:**  Tests the `Overlaps()` method of `Prefix`, which determines if two prefixes have any common IP addresses.

5. **Identify Go Features Demonstrated:** As you analyze the test functions, note the Go features being used:
    * **Testing Framework (`testing` package):**  The structure of test functions, `t.Run`, assertions, benchmarks.
    * **Structs:** Used extensively for organizing test cases.
    * **Slices:**  Used to hold multiple test cases.
    * **Methods on Structs:**  The `Prefix` and `Addr` types have methods being tested.
    * **Error Handling:** Checking for `err != nil`.
    * **JSON Marshalling/Unmarshalling (`encoding/json`):**  Demonstrated in `TestPrefixMarshalUnmarshal`.
    * **String Conversion:** Using `.String()` methods.
    * **Reflection (`reflect` package):** Used for deep equality checks (`reflect.DeepEqual`).
    * **Panics and Recover (`recover()`):** Used in `TestAs4` for testing error conditions.
    * **Benchmarking (`testing` package):** Functions starting with `Benchmark...`.

6. **Code Examples:**  Based on the understanding of the test functions, construct clear and concise code examples demonstrating the functionality. Select representative test cases and adapt them into standalone examples. Focus on showing *how* to use the functions being tested.

7. **Command-Line Arguments:** Carefully examine the code for any use of `os.Args` or the `flag` package. In this specific snippet, there's no explicit handling of command-line arguments.

8. **Common Mistakes:** Think about potential pitfalls users might encounter based on the test cases, especially the error handling tests. For example, providing an invalid number of bits for a prefix or not handling potential errors during parsing.

9. **Summarize the Functionality:**  Combine the findings from the detailed analysis into a concise summary of the file's purpose. Focus on the key functionalities being tested: IP address manipulation, prefix handling, and serialization.

10. **Review and Refine:**  Read through the generated explanation to ensure clarity, accuracy, and completeness. Check for any inconsistencies or areas that could be explained better. Ensure the code examples are correct and easy to understand. Make sure the summary accurately reflects the content of the test file. For instance, initially, I might have missed the nuances of `Is4In6` and `Unmap`, but a closer look at the test function reveals their purpose. Similarly, the benchmarks provide insights into performance considerations.
这是路径为 `go/src/net/netip/netip_test.go` 的 Go 语言实现的一部分，它是该测试文件的**第二部分**。考虑到这是第二部分，我们需要结合第一部分的内容进行归纳。

**结合第一部分的推断，此测试文件（`netip_test.go`）主要目的是测试 `netip` 包中关于 IP 地址 (`Addr`) 和网络前缀 (`Prefix`) 的功能。**

根据提供的代码片段，我们可以归纳出以下功能被测试：

**1. 网络前缀 (Prefix) 的创建和操作:**

* **从 IP 地址和掩码位数创建前缀 (`Prefix`)：**  `TestAddr_Prefix` 测试了 `Addr.Prefix(bits int)` 方法，该方法将 IP 地址与指定的掩码位数结合，生成一个网络前缀。
    * **代码示例：**
      ```go
      package main

      import (
          "fmt"
          "net/netip"
      )

      func main() {
          ip := netip.MustParseAddr("192.168.1.100")
          prefix, err := ip.Prefix(24)
          if err != nil {
              fmt.Println("Error:", err)
              return
          }
          fmt.Println(prefix) // Output: 192.168.1.0/24
      }
      ```
      * **假设输入：** IP 地址 "192.168.1.100"，掩码位数 24。
      * **预期输出：** 网络前缀 "192.168.1.0/24"。

* **前缀的序列化和反序列化 (Marshal/Unmarshal)：** `TestPrefixMarshalUnmarshal` 测试了将 `Prefix` 类型序列化为 JSON 格式以及从 JSON 格式反序列化的功能。这确保了前缀可以方便地存储和传输。
    * **代码示例：**
      ```go
      package main

      import (
          "encoding/json"
          "fmt"
          "net/netip"
      )

      func main() {
          prefix := netip.MustParsePrefix("10.0.0.0/8")
          jsonBytes, err := json.Marshal(prefix)
          if err != nil {
              fmt.Println("Error marshaling:", err)
              return
          }
          fmt.Println("Marshaled:", string(jsonBytes)) // Output: Marshaled: "10.0.0.0/8"

          var newPrefix netip.Prefix
          err = json.Unmarshal(jsonBytes, &newPrefix)
          if err != nil {
              fmt.Println("Error unmarshaling:", err)
              return
          }
          fmt.Println("Unmarshaled:", newPrefix) // Output: Unmarshaled: 10.0.0.0/8
      }
      ```
      * **假设输入：** `Prefix` 对象，例如 "10.0.0.0/8"。
      * **预期输出：**  JSON 字符串 "10.0.0.0/8"，并且反序列化后得到相同的 `Prefix` 对象。

* **处理非零值的文本反序列化：** `TestPrefixUnmarshalTextNonZero` 似乎测试了当尝试将文本反序列化为一个已经有值的 `Prefix` 对象时会发生什么。这可能与确保反序列化操作是覆盖而非合并有关。

* **获取前缀的网络地址 (`Masked`)：** `TestPrefixMasked` 测试了 `Prefix.Masked()` 方法，该方法返回将前缀的 IP 地址部分按照掩码进行屏蔽后的前缀。
    * **代码示例：**
      ```go
      package main

      import (
          "fmt"
          "net/netip"
      )

      func main() {
          prefix := netip.MustParsePrefix("192.168.0.255/24")
          maskedPrefix := prefix.Masked()
          fmt.Println(maskedPrefix) // Output: 192.168.0.0/24
      }
      ```
      * **假设输入：**  前缀 "192.168.0.255/24"。
      * **预期输出：** 前缀 "192.168.0.0/24"。

* **前缀的包含关系 (`Contains`)：** `TestPrefix` 测试了 `Prefix.Contains(Addr)` 方法，用于判断给定的 IP 地址是否属于该网络前缀。
    * **代码示例：**
      ```go
      package main

      import (
          "fmt"
          "net/netip"
      )

      func main() {
          prefix := netip.MustParsePrefix("192.168.1.0/24")
          ip1 := netip.MustParseAddr("192.168.1.100")
          ip2 := netip.MustParseAddr("192.168.2.100")

          fmt.Println(prefix.Contains(ip1)) // Output: true
          fmt.Println(prefix.Contains(ip2)) // Output: false
      }
      ```
      * **假设输入：**  前缀 "192.168.1.0/24"，IP 地址 "192.168.1.100" 和 "192.168.2.100"。
      * **预期输出：** `true` 和 `false`。

* **从字符串解析前缀 (`ParsePrefix`)：** `TestPrefix` 也间接测试了 `ParsePrefix` 函数，用于将字符串解析为 `Prefix` 对象。`TestParsePrefixError` 专门测试了 `ParsePrefix` 函数在遇到错误输入时的行为。
    * **命令行参数处理：**  `ParsePrefix` 函数本身不直接处理命令行参数。它接受一个字符串作为输入。

* **判断前缀是否代表单个 IP 地址 (`IsSingleIP`)：** `TestPrefixIsSingleIP` 测试了 `Prefix.IsSingleIP()` 方法，该方法判断前缀的掩码是否为 /32 (IPv4) 或 /128 (IPv6)，从而确定它是否只包含一个 IP 地址。

* **前缀的重叠判断 (`Overlaps`)：** `TestPrefixOverlaps` 测试了 `Prefix.Overlaps(Prefix)` 方法，用于判断两个前缀是否包含任何相同的 IP 地址。

**2. IP 地址 (Addr) 的属性和操作:**

* **判断 IP 地址的类型 (`Is4`, `Is6`)：** `TestIs4AndIs6` 测试了 `Addr.Is4()` 和 `Addr.Is6()` 方法，用于判断 IP 地址是 IPv4 还是 IPv6。
    * **代码示例：**
      ```go
      package main

      import (
          "fmt"
          "net/netip"
      )

      func main() {
          ipv4 := netip.MustParseAddr("192.168.1.1")
          ipv6 := netip.MustParseAddr("2001:db8::1")

          fmt.Println(ipv4.Is4()) // Output: true
          fmt.Println(ipv4.Is6()) // Output: false
          fmt.Println(ipv6.Is4()) // Output: false
          fmt.Println(ipv6.Is6()) // Output: true
      }
      ```

* **处理 IPv4-in-IPv6 地址 (`Is4In6`, `Unmap`)：** `TestIs4In6` 测试了 `Addr.Is4In6()` 方法，用于判断 IPv6 地址是否是封装了 IPv4 地址，以及 `Addr.Unmap()` 方法，用于将 IPv4-in-IPv6 地址解映射回 IPv4 地址。
    * **代码示例：**
      ```go
      package main

      import (
          "fmt"
          "net/netip"
      )

      func main() {
          ipv4In6 := netip.MustParseAddr("::ffff:192.168.1.1")
          ipv6 := netip.MustParseAddr("2001:db8::1")

          fmt.Println(ipv4In6.Is4In6()) // Output: true
          fmt.Println(ipv6.Is4In6())    // Output: false

          unmapped := ipv4In6.Unmap()
          fmt.Println(unmapped)         // Output: 192.168.1.1
      }
      ```
      * **假设输入：** IPv6 地址 "::ffff:192.168.1.1" 和 "2001:db8::1"。
      * **预期输出：** `true` 和 `false`，以及解映射后的 IPv4 地址 "192.168.1.1"。

* **将 IPv4 地址转换为 `[4]byte` 数组 (`As4`)：** `TestAs4` 测试了 `Addr.As4()` 方法，用于将 IPv4 地址转换为一个包含 4 个字节的数组。对于非 IPv4 地址，此方法会 panic。

**3. 性能测试 (Benchmarks):**

* 文件中包含多个以 `Benchmark` 开头的函数，用于测试不同操作的性能，例如二进制序列化/反序列化 (`BenchmarkBinaryMarshalRoundTrip`)，创建 IP 地址 (`BenchmarkStdIPv4`, `BenchmarkIPv4`, `BenchmarkIPv4_inline`, `BenchmarkStdIPv6`, `BenchmarkIPv6`)，判断包含关系 (`BenchmarkIPv4Contains`, `BenchmarkIPv6Contains`)，解析 IP 地址 (`BenchmarkParseAddr`, `BenchmarkStdParseIP`)，格式化为字符串 (`BenchmarkAddrString`, `BenchmarkIPStringExpanded`)，以及前缀操作 (`BenchmarkPrefixMasking`, `BenchmarkPrefixMarshalText`) 等。

**4. 无内存分配测试 (`TestNoAllocs`)：**

* `TestNoAllocs` 函数使用 `testing.AllocsPerRun` 来检查某些关键操作是否会发生不必要的内存分配。这对于性能至关重要的网络库来说非常重要。

**5. 错误处理测试 (`TestParsePrefixError`)：**

* 该测试用例集合旨在验证 `ParsePrefix` 函数在接收到各种格式错误的输入时，是否能够正确地返回错误，并且错误信息是否包含预期的子字符串。

**使用者易犯错的点（根据测试用例推断）：**

* **解析前缀时缺少斜杠 (`/`) 和掩码位数：**  如 `TestParsePrefixError` 中的 `"192.168.0.0"`。
* **解析前缀时掩码位数格式错误：** 如 `TestParsePrefixError` 中的 `"1.1.1.0/q"`, `"1.1.1.0/-1"`, `"1.1.1.0/+32"`, `"1.1.1.0/032"` 等。
* **解析前缀时掩码位数超出范围：** 如 `TestParsePrefixError` 中的 `"1.1.1.0/33"` (IPv4) 和 `"2001::/129"` (IPv6)。
* **在前缀字符串中包含 Zone 信息：**  虽然 `Addr` 类型可以包含 Zone，但 `Prefix` 类型目前不支持，如 `TestParsePrefixError` 中的 `"1.1.1.0%a/24"` 和 `"2001:db8::%a/32"`。

**总结 `netip_test.go` (第 2 部分) 的功能:**

此部分主要集中测试了 `netip` 包中 `Prefix` 类型的各种功能，包括从 IP 地址创建、序列化与反序列化、获取网络地址、判断 IP 地址是否属于该前缀、字符串解析、判断是否为单个 IP 地址前缀以及前缀的重叠判断。此外，还测试了 `Addr` 类型的一些特定功能，例如判断 IP 类型和处理 IPv4-in-IPv6 地址。  结合第一部分，整个测试文件旨在全面验证 `netip` 包中 IP 地址和网络前缀的核心功能是否正确且高效地实现。  基准测试部分则关注于性能表现，而无内存分配测试则强调了该包在设计上对内存使用的优化。

Prompt: 
```
这是路径为go/src/net/netip/netip_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""
IP("255.255.255.255"),
					bits: 20,
					p:    mustPrefix("255.255.240.0/20"),
					ok:   true,
				},
				{
					// Partially masking one byte that contains both
					// 1s and 0s on either side of the mask limit.
					ip:   mustIP("100.98.156.66"),
					bits: 10,
					p:    mustPrefix("100.64.0.0/10"),
					ok:   true,
				},
			},
		},
		{
			family:   "IPv6",
			subtests: makeIPv6(""),
		},
		{
			family:   "IPv6 zone",
			subtests: makeIPv6("eth0"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.family, func(t *testing.T) {
			for _, st := range tt.subtests {
				t.Run(st.p.String(), func(t *testing.T) {
					// Ensure st.ip is not mutated.
					orig := st.ip.String()

					p, err := st.ip.Prefix(int(st.bits))
					if st.ok && err != nil {
						t.Fatalf("failed to produce prefix: %v", err)
					}
					if !st.ok && err == nil {
						t.Fatal("expected an error, but none occurred")
					}
					if err != nil {
						t.Logf("err: %v", err)
						return
					}

					if !reflect.DeepEqual(p, st.p) {
						t.Errorf("prefix = %q, want %q", p, st.p)
					}

					if got := st.ip.String(); got != orig {
						t.Errorf("IP was mutated: %q, want %q", got, orig)
					}
				})
			}
		})
	}
}

func TestPrefixMarshalUnmarshal(t *testing.T) {
	tests := []string{
		"",
		"1.2.3.4/32",
		"0.0.0.0/0",
		"::/0",
		"::1/128",
		"2001:db8::/32",
	}

	for _, s := range tests {
		t.Run(s, func(t *testing.T) {
			// Ensure that JSON  (and by extension, text) marshaling is
			// sane by entering quoted input.
			orig := `"` + s + `"`

			var p Prefix
			if err := json.Unmarshal([]byte(orig), &p); err != nil {
				t.Fatalf("failed to unmarshal: %v", err)
			}

			pb, err := json.Marshal(p)
			if err != nil {
				t.Fatalf("failed to marshal: %v", err)
			}

			back := string(pb)
			if orig != back {
				t.Errorf("Marshal = %q; want %q", back, orig)
			}
		})
	}
}

func TestPrefixUnmarshalTextNonZero(t *testing.T) {
	ip := mustPrefix("fe80::/64")
	if err := ip.UnmarshalText([]byte("xxx")); err == nil {
		t.Fatal("unmarshaled into non-empty Prefix")
	}
}

func TestIs4AndIs6(t *testing.T) {
	tests := []struct {
		ip  Addr
		is4 bool
		is6 bool
	}{
		{Addr{}, false, false},
		{mustIP("1.2.3.4"), true, false},
		{mustIP("127.0.0.2"), true, false},
		{mustIP("::1"), false, true},
		{mustIP("::ffff:192.0.2.128"), false, true},
		{mustIP("::fffe:c000:0280"), false, true},
		{mustIP("::1%eth0"), false, true},
	}
	for _, tt := range tests {
		got4 := tt.ip.Is4()
		if got4 != tt.is4 {
			t.Errorf("Is4(%q) = %v; want %v", tt.ip, got4, tt.is4)
		}

		got6 := tt.ip.Is6()
		if got6 != tt.is6 {
			t.Errorf("Is6(%q) = %v; want %v", tt.ip, got6, tt.is6)
		}
	}
}

func TestIs4In6(t *testing.T) {
	tests := []struct {
		ip        Addr
		want      bool
		wantUnmap Addr
	}{
		{Addr{}, false, Addr{}},
		{mustIP("::ffff:c000:0280"), true, mustIP("192.0.2.128")},
		{mustIP("::ffff:192.0.2.128"), true, mustIP("192.0.2.128")},
		{mustIP("::ffff:192.0.2.128%eth0"), true, mustIP("192.0.2.128")},
		{mustIP("::fffe:c000:0280"), false, mustIP("::fffe:c000:0280")},
		{mustIP("::ffff:127.1.2.3"), true, mustIP("127.1.2.3")},
		{mustIP("::ffff:7f01:0203"), true, mustIP("127.1.2.3")},
		{mustIP("0:0:0:0:0000:ffff:127.1.2.3"), true, mustIP("127.1.2.3")},
		{mustIP("0:0:0:0::ffff:127.1.2.3"), true, mustIP("127.1.2.3")},
		{mustIP("::1"), false, mustIP("::1")},
		{mustIP("1.2.3.4"), false, mustIP("1.2.3.4")},
	}
	for _, tt := range tests {
		got := tt.ip.Is4In6()
		if got != tt.want {
			t.Errorf("Is4In6(%q) = %v; want %v", tt.ip, got, tt.want)
		}
		u := tt.ip.Unmap()
		if u != tt.wantUnmap {
			t.Errorf("Unmap(%q) = %v; want %v", tt.ip, u, tt.wantUnmap)
		}
	}
}

func TestPrefixMasked(t *testing.T) {
	tests := []struct {
		prefix Prefix
		masked Prefix
	}{
		{
			prefix: mustPrefix("192.168.0.255/24"),
			masked: mustPrefix("192.168.0.0/24"),
		},
		{
			prefix: mustPrefix("2100::/3"),
			masked: mustPrefix("2000::/3"),
		},
		{
			prefix: PrefixFrom(mustIP("2000::"), 129),
			masked: Prefix{},
		},
		{
			prefix: PrefixFrom(mustIP("1.2.3.4"), 33),
			masked: Prefix{},
		},
	}
	for _, test := range tests {
		t.Run(test.prefix.String(), func(t *testing.T) {
			got := test.prefix.Masked()
			if got != test.masked {
				t.Errorf("Masked=%s, want %s", got, test.masked)
			}
		})
	}
}

func TestPrefix(t *testing.T) {
	tests := []struct {
		prefix      string
		ip          Addr
		bits        int
		str         string
		contains    []Addr
		notContains []Addr
	}{
		{
			prefix:      "192.168.0.0/24",
			ip:          mustIP("192.168.0.0"),
			bits:        24,
			contains:    mustIPs("192.168.0.1", "192.168.0.55"),
			notContains: mustIPs("192.168.1.1", "1.1.1.1"),
		},
		{
			prefix:      "192.168.1.1/32",
			ip:          mustIP("192.168.1.1"),
			bits:        32,
			contains:    mustIPs("192.168.1.1"),
			notContains: mustIPs("192.168.1.2"),
		},
		{
			prefix:      "100.64.0.0/10", // CGNAT range; prefix not multiple of 8
			ip:          mustIP("100.64.0.0"),
			bits:        10,
			contains:    mustIPs("100.64.0.0", "100.64.0.1", "100.81.251.94", "100.100.100.100", "100.127.255.254", "100.127.255.255"),
			notContains: mustIPs("100.63.255.255", "100.128.0.0"),
		},
		{
			prefix:      "2001:db8::/96",
			ip:          mustIP("2001:db8::"),
			bits:        96,
			contains:    mustIPs("2001:db8::aaaa:bbbb", "2001:db8::1"),
			notContains: mustIPs("2001:db8::1:aaaa:bbbb", "2001:db9::"),
		},
		{
			prefix:      "0.0.0.0/0",
			ip:          mustIP("0.0.0.0"),
			bits:        0,
			contains:    mustIPs("192.168.0.1", "1.1.1.1"),
			notContains: append(mustIPs("2001:db8::1"), Addr{}),
		},
		{
			prefix:      "::/0",
			ip:          mustIP("::"),
			bits:        0,
			contains:    mustIPs("::1", "2001:db8::1"),
			notContains: mustIPs("192.0.2.1"),
		},
		{
			prefix:      "2000::/3",
			ip:          mustIP("2000::"),
			bits:        3,
			contains:    mustIPs("2001:db8::1"),
			notContains: mustIPs("fe80::1"),
		},
	}
	for _, test := range tests {
		t.Run(test.prefix, func(t *testing.T) {
			prefix, err := ParsePrefix(test.prefix)
			if err != nil {
				t.Fatal(err)
			}
			if prefix.Addr() != test.ip {
				t.Errorf("IP=%s, want %s", prefix.Addr(), test.ip)
			}
			if prefix.Bits() != test.bits {
				t.Errorf("bits=%d, want %d", prefix.Bits(), test.bits)
			}
			for _, ip := range test.contains {
				if !prefix.Contains(ip) {
					t.Errorf("does not contain %s", ip)
				}
			}
			for _, ip := range test.notContains {
				if prefix.Contains(ip) {
					t.Errorf("contains %s", ip)
				}
			}
			want := test.str
			if want == "" {
				want = test.prefix
			}
			if got := prefix.String(); got != want {
				t.Errorf("prefix.String()=%q, want %q", got, want)
			}

			TestAppendToMarshal(t, prefix)
		})
	}
}

func TestPrefixFromInvalidBits(t *testing.T) {
	v4 := MustParseAddr("1.2.3.4")
	v6 := MustParseAddr("66::66")
	tests := []struct {
		ip       Addr
		in, want int
	}{
		{v4, 0, 0},
		{v6, 0, 0},
		{v4, 1, 1},
		{v4, 33, -1},
		{v6, 33, 33},
		{v6, 127, 127},
		{v6, 128, 128},
		{v4, 254, -1},
		{v4, 255, -1},
		{v4, -1, -1},
		{v6, -1, -1},
		{v4, -5, -1},
		{v6, -5, -1},
	}
	for _, tt := range tests {
		p := PrefixFrom(tt.ip, tt.in)
		if got := p.Bits(); got != tt.want {
			t.Errorf("for (%v, %v), Bits out = %v; want %v", tt.ip, tt.in, got, tt.want)
		}
	}
}

func TestParsePrefixAllocs(t *testing.T) {
	tests := []struct {
		ip    string
		slash string
	}{
		{"192.168.1.0", "/24"},
		{"aaaa:bbbb:cccc::", "/24"},
	}
	for _, test := range tests {
		prefix := test.ip + test.slash
		t.Run(prefix, func(t *testing.T) {
			ipAllocs := int(testing.AllocsPerRun(5, func() {
				ParseAddr(test.ip)
			}))
			prefixAllocs := int(testing.AllocsPerRun(5, func() {
				ParsePrefix(prefix)
			}))
			if got := prefixAllocs - ipAllocs; got != 0 {
				t.Errorf("allocs=%d, want 0", got)
			}
		})
	}
}

func TestParsePrefixError(t *testing.T) {
	tests := []struct {
		prefix string
		errstr string
	}{
		{
			prefix: "192.168.0.0",
			errstr: "no '/'",
		},
		{
			prefix: "1.257.1.1/24",
			errstr: "value >255",
		},
		{
			prefix: "1.1.1.0/q",
			errstr: "bad bits",
		},
		{
			prefix: "1.1.1.0/-1",
			errstr: "bad bits",
		},
		{
			prefix: "1.1.1.0/33",
			errstr: "out of range",
		},
		{
			prefix: "2001::/129",
			errstr: "out of range",
		},
		// Zones are not allowed: https://go.dev/issue/51899
		{
			prefix: "1.1.1.0%a/24",
			errstr: "unexpected character",
		},
		{
			prefix: "2001:db8::%a/32",
			errstr: "zones cannot be present",
		},
		{
			prefix: "1.1.1.0/+32",
			errstr: "bad bits",
		},
		{
			prefix: "1.1.1.0/-32",
			errstr: "bad bits",
		},
		{
			prefix: "1.1.1.0/032",
			errstr: "bad bits",
		},
		{
			prefix: "1.1.1.0/0032",
			errstr: "bad bits",
		},
	}
	for _, test := range tests {
		t.Run(test.prefix, func(t *testing.T) {
			_, err := ParsePrefix(test.prefix)
			if err == nil {
				t.Fatal("no error")
			}
			if got := err.Error(); !strings.Contains(got, test.errstr) {
				t.Errorf("error is missing substring %q: %s", test.errstr, got)
			}
		})
	}
}

func TestPrefixIsSingleIP(t *testing.T) {
	tests := []struct {
		ipp  Prefix
		want bool
	}{
		{ipp: mustPrefix("127.0.0.1/32"), want: true},
		{ipp: mustPrefix("127.0.0.1/31"), want: false},
		{ipp: mustPrefix("127.0.0.1/0"), want: false},
		{ipp: mustPrefix("::1/128"), want: true},
		{ipp: mustPrefix("::1/127"), want: false},
		{ipp: mustPrefix("::1/0"), want: false},
		{ipp: Prefix{}, want: false},
	}
	for _, tt := range tests {
		got := tt.ipp.IsSingleIP()
		if got != tt.want {
			t.Errorf("IsSingleIP(%v) = %v want %v", tt.ipp, got, tt.want)
		}
	}
}

func mustIPs(strs ...string) []Addr {
	var res []Addr
	for _, s := range strs {
		res = append(res, mustIP(s))
	}
	return res
}

func BenchmarkBinaryMarshalRoundTrip(b *testing.B) {
	b.ReportAllocs()
	tests := []struct {
		name string
		ip   string
	}{
		{"ipv4", "1.2.3.4"},
		{"ipv6", "2001:db8::1"},
		{"ipv6+zone", "2001:db8::1%eth0"},
	}
	for _, tc := range tests {
		b.Run(tc.name, func(b *testing.B) {
			ip := mustIP(tc.ip)
			for i := 0; i < b.N; i++ {
				bt, err := ip.MarshalBinary()
				if err != nil {
					b.Fatal(err)
				}
				var ip2 Addr
				if err := ip2.UnmarshalBinary(bt); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkStdIPv4(b *testing.B) {
	b.ReportAllocs()
	ips := []net.IP{}
	for i := 0; i < b.N; i++ {
		ip := net.IPv4(8, 8, 8, 8)
		ips = ips[:0]
		for i := 0; i < 100; i++ {
			ips = append(ips, ip)
		}
	}
}

func BenchmarkIPv4(b *testing.B) {
	b.ReportAllocs()
	ips := []Addr{}
	for i := 0; i < b.N; i++ {
		ip := IPv4(8, 8, 8, 8)
		ips = ips[:0]
		for i := 0; i < 100; i++ {
			ips = append(ips, ip)
		}
	}
}

// ip4i was one of the possible representations of IP that came up in
// discussions, inlining IPv4 addresses, but having an "overflow"
// interface for IPv6 or IPv6 + zone. This is here for benchmarking.
type ip4i struct {
	ip4    [4]byte
	flags1 byte
	flags2 byte
	flags3 byte
	flags4 byte
	ipv6   any
}

func newip4i_v4(a, b, c, d byte) ip4i {
	return ip4i{ip4: [4]byte{a, b, c, d}}
}

// BenchmarkIPv4_inline benchmarks the candidate representation, ip4i.
func BenchmarkIPv4_inline(b *testing.B) {
	b.ReportAllocs()
	ips := []ip4i{}
	for i := 0; i < b.N; i++ {
		ip := newip4i_v4(8, 8, 8, 8)
		ips = ips[:0]
		for i := 0; i < 100; i++ {
			ips = append(ips, ip)
		}
	}
}

func BenchmarkStdIPv6(b *testing.B) {
	b.ReportAllocs()
	ips := []net.IP{}
	for i := 0; i < b.N; i++ {
		ip := net.ParseIP("2001:db8::1")
		ips = ips[:0]
		for i := 0; i < 100; i++ {
			ips = append(ips, ip)
		}
	}
}

func BenchmarkIPv6(b *testing.B) {
	b.ReportAllocs()
	ips := []Addr{}
	for i := 0; i < b.N; i++ {
		ip := mustIP("2001:db8::1")
		ips = ips[:0]
		for i := 0; i < 100; i++ {
			ips = append(ips, ip)
		}
	}
}

func BenchmarkIPv4Contains(b *testing.B) {
	b.ReportAllocs()
	prefix := PrefixFrom(IPv4(192, 168, 1, 0), 24)
	ip := IPv4(192, 168, 1, 1)
	for i := 0; i < b.N; i++ {
		prefix.Contains(ip)
	}
}

func BenchmarkIPv6Contains(b *testing.B) {
	b.ReportAllocs()
	prefix := MustParsePrefix("::1/128")
	ip := MustParseAddr("::1")
	for i := 0; i < b.N; i++ {
		prefix.Contains(ip)
	}
}

var parseBenchInputs = []struct {
	name string
	ip   string
}{
	{"v4", "192.168.1.1"},
	{"v6", "fd7a:115c:a1e0:ab12:4843:cd96:626b:430b"},
	{"v6_ellipsis", "fd7a:115c::626b:430b"},
	{"v6_v4", "::ffff:192.168.140.255"},
	{"v6_zone", "1:2::ffff:192.168.140.255%eth1"},
}

func BenchmarkParseAddr(b *testing.B) {
	sinkInternValue = unique.Make(MakeAddrDetail(true, "eth1")) // Pin to not benchmark the intern package
	for _, test := range parseBenchInputs {
		b.Run(test.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				sinkIP, _ = ParseAddr(test.ip)
			}
		})
	}
}

func BenchmarkStdParseIP(b *testing.B) {
	for _, test := range parseBenchInputs {
		b.Run(test.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				sinkStdIP = net.ParseIP(test.ip)
			}
		})
	}
}

func BenchmarkAddrString(b *testing.B) {
	for _, test := range parseBenchInputs {
		ip := MustParseAddr(test.ip)
		b.Run(test.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				sinkString = ip.String()
			}
		})
	}
}

func BenchmarkIPStringExpanded(b *testing.B) {
	for _, test := range parseBenchInputs {
		ip := MustParseAddr(test.ip)
		b.Run(test.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				sinkString = ip.StringExpanded()
			}
		})
	}
}

func BenchmarkAddrMarshalText(b *testing.B) {
	for _, test := range parseBenchInputs {
		ip := MustParseAddr(test.ip)
		b.Run(test.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				sinkBytes, _ = ip.MarshalText()
			}
		})
	}
}

func BenchmarkAddrPortString(b *testing.B) {
	for _, test := range parseBenchInputs {
		ip := MustParseAddr(test.ip)
		ipp := AddrPortFrom(ip, 60000)
		b.Run(test.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				sinkString = ipp.String()
			}
		})
	}
}

func BenchmarkAddrPortMarshalText(b *testing.B) {
	for _, test := range parseBenchInputs {
		ip := MustParseAddr(test.ip)
		ipp := AddrPortFrom(ip, 60000)
		b.Run(test.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				sinkBytes, _ = ipp.MarshalText()
			}
		})
	}
}

func BenchmarkPrefixMasking(b *testing.B) {
	tests := []struct {
		name string
		ip   Addr
		bits int
	}{
		{
			name: "IPv4 /32",
			ip:   IPv4(192, 0, 2, 0),
			bits: 32,
		},
		{
			name: "IPv4 /17",
			ip:   IPv4(192, 0, 2, 0),
			bits: 17,
		},
		{
			name: "IPv4 /0",
			ip:   IPv4(192, 0, 2, 0),
			bits: 0,
		},
		{
			name: "IPv6 /128",
			ip:   mustIP("2001:db8::1"),
			bits: 128,
		},
		{
			name: "IPv6 /65",
			ip:   mustIP("2001:db8::1"),
			bits: 65,
		},
		{
			name: "IPv6 /0",
			ip:   mustIP("2001:db8::1"),
			bits: 0,
		},
		{
			name: "IPv6 zone /128",
			ip:   mustIP("2001:db8::1%eth0"),
			bits: 128,
		},
		{
			name: "IPv6 zone /65",
			ip:   mustIP("2001:db8::1%eth0"),
			bits: 65,
		},
		{
			name: "IPv6 zone /0",
			ip:   mustIP("2001:db8::1%eth0"),
			bits: 0,
		},
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				sinkPrefix, _ = tt.ip.Prefix(tt.bits)
			}
		})
	}
}

func BenchmarkPrefixMarshalText(b *testing.B) {
	b.ReportAllocs()
	ipp := MustParsePrefix("66.55.44.33/22")
	for i := 0; i < b.N; i++ {
		sinkBytes, _ = ipp.MarshalText()
	}
}

func BenchmarkParseAddrPort(b *testing.B) {
	for _, test := range parseBenchInputs {
		var ipp string
		if strings.HasPrefix(test.name, "v6") {
			ipp = fmt.Sprintf("[%s]:1234", test.ip)
		} else {
			ipp = fmt.Sprintf("%s:1234", test.ip)
		}
		b.Run(test.name, func(b *testing.B) {
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				sinkAddrPort, _ = ParseAddrPort(ipp)
			}
		})
	}
}

func TestAs4(t *testing.T) {
	tests := []struct {
		ip        Addr
		want      [4]byte
		wantPanic bool
	}{
		{
			ip:   mustIP("1.2.3.4"),
			want: [4]byte{1, 2, 3, 4},
		},
		{
			ip:   AddrFrom16(mustIP("1.2.3.4").As16()), // IPv4-in-IPv6
			want: [4]byte{1, 2, 3, 4},
		},
		{
			ip:   mustIP("0.0.0.0"),
			want: [4]byte{0, 0, 0, 0},
		},
		{
			ip:        Addr{},
			wantPanic: true,
		},
		{
			ip:        mustIP("::1"),
			wantPanic: true,
		},
	}
	as4 := func(ip Addr) (v [4]byte, gotPanic bool) {
		defer func() {
			if recover() != nil {
				gotPanic = true
				return
			}
		}()
		v = ip.As4()
		return
	}
	for i, tt := range tests {
		got, gotPanic := as4(tt.ip)
		if gotPanic != tt.wantPanic {
			t.Errorf("%d. panic on %v = %v; want %v", i, tt.ip, gotPanic, tt.wantPanic)
			continue
		}
		if got != tt.want {
			t.Errorf("%d. %v = %v; want %v", i, tt.ip, got, tt.want)
		}
	}
}

func TestPrefixOverlaps(t *testing.T) {
	pfx := mustPrefix
	tests := []struct {
		a, b Prefix
		want bool
	}{
		{Prefix{}, pfx("1.2.0.0/16"), false},    // first zero
		{pfx("1.2.0.0/16"), Prefix{}, false},    // second zero
		{pfx("::0/3"), pfx("0.0.0.0/3"), false}, // different families

		{pfx("1.2.0.0/16"), pfx("1.2.0.0/16"), true}, // equal

		{pfx("1.2.0.0/16"), pfx("1.2.3.0/24"), true},
		{pfx("1.2.3.0/24"), pfx("1.2.0.0/16"), true},

		{pfx("1.2.0.0/16"), pfx("1.2.3.0/32"), true},
		{pfx("1.2.3.0/32"), pfx("1.2.0.0/16"), true},

		// Match /0 either order
		{pfx("1.2.3.0/32"), pfx("0.0.0.0/0"), true},
		{pfx("0.0.0.0/0"), pfx("1.2.3.0/32"), true},

		{pfx("1.2.3.0/32"), pfx("5.5.5.5/0"), true}, // normalization not required; /0 means true

		// IPv6 overlapping
		{pfx("5::1/128"), pfx("5::0/8"), true},
		{pfx("5::0/8"), pfx("5::1/128"), true},

		// IPv6 not overlapping
		{pfx("1::1/128"), pfx("2::2/128"), false},
		{pfx("0100::0/8"), pfx("::1/128"), false},

		// IPv4-mapped IPv6 addresses should not overlap with IPv4.
		{PrefixFrom(AddrFrom16(mustIP("1.2.0.0").As16()), 16), pfx("1.2.3.0/24"), false},

		// Invalid prefixes
		{PrefixFrom(mustIP("1.2.3.4"), 33), pfx("1.2.3.0/24"), false},
		{PrefixFrom(mustIP("2000::"), 129), pfx("2000::/64"), false},
	}
	for i, tt := range tests {
		if got := tt.a.Overlaps(tt.b); got != tt.want {
			t.Errorf("%d. (%v).Overlaps(%v) = %v; want %v", i, tt.a, tt.b, got, tt.want)
		}
		// Overlaps is commutative
		if got := tt.b.Overlaps(tt.a); got != tt.want {
			t.Errorf("%d. (%v).Overlaps(%v) = %v; want %v", i, tt.b, tt.a, got, tt.want)
		}
	}
}

// Sink variables are here to force the compiler to not elide
// seemingly useless work in benchmarks and allocation tests. If you
// were to just `_ = foo()` within a test function, the compiler could
// correctly deduce that foo() does nothing and doesn't need to be
// called. By writing results to a global variable, we hide that fact
// from the compiler and force it to keep the code under test.
var (
	sinkIP          Addr
	sinkStdIP       net.IP
	sinkAddrPort    AddrPort
	sinkPrefix      Prefix
	sinkPrefixSlice []Prefix
	sinkInternValue unique.Handle[AddrDetail]
	sinkIP16        [16]byte
	sinkIP4         [4]byte
	sinkBool        bool
	sinkString      string
	sinkBytes       []byte
	sinkUDPAddr     = &net.UDPAddr{IP: make(net.IP, 0, 16)}
)

func TestNoAllocs(t *testing.T) {
	if asan.Enabled {
		t.Skip("test allocates more with -asan; see #70079")
	}

	// Wrappers that panic on error, to prove that our alloc-free
	// methods are returning successfully.
	panicIP := func(ip Addr, err error) Addr {
		if err != nil {
			panic(err)
		}
		return ip
	}
	panicPfx := func(pfx Prefix, err error) Prefix {
		if err != nil {
			panic(err)
		}
		return pfx
	}
	panicIPP := func(ipp AddrPort, err error) AddrPort {
		if err != nil {
			panic(err)
		}
		return ipp
	}
	test := func(name string, f func()) {
		t.Run(name, func(t *testing.T) {
			n := testing.AllocsPerRun(1000, f)
			if n != 0 {
				t.Fatalf("allocs = %d; want 0", int(n))
			}
		})
	}

	// Addr constructors
	test("IPv4", func() { sinkIP = IPv4(1, 2, 3, 4) })
	test("AddrFrom4", func() { sinkIP = AddrFrom4([4]byte{1, 2, 3, 4}) })
	test("AddrFrom16", func() { sinkIP = AddrFrom16([16]byte{}) })
	test("ParseAddr/4", func() { sinkIP = panicIP(ParseAddr("1.2.3.4")) })
	test("ParseAddr/6", func() { sinkIP = panicIP(ParseAddr("::1")) })
	test("MustParseAddr", func() { sinkIP = MustParseAddr("1.2.3.4") })
	test("IPv6LinkLocalAllNodes", func() { sinkIP = IPv6LinkLocalAllNodes() })
	test("IPv6LinkLocalAllRouters", func() { sinkIP = IPv6LinkLocalAllRouters() })
	test("IPv6Loopback", func() { sinkIP = IPv6Loopback() })
	test("IPv6Unspecified", func() { sinkIP = IPv6Unspecified() })

	// Addr methods
	test("Addr.IsZero", func() { sinkBool = MustParseAddr("1.2.3.4").IsZero() })
	test("Addr.BitLen", func() { sinkBool = MustParseAddr("1.2.3.4").BitLen() == 8 })
	test("Addr.Zone/4", func() { sinkBool = MustParseAddr("1.2.3.4").Zone() == "" })
	test("Addr.Zone/6", func() { sinkBool = MustParseAddr("fe80::1").Zone() == "" })
	test("Addr.Zone/6zone", func() { sinkBool = MustParseAddr("fe80::1%zone").Zone() == "" })
	test("Addr.Compare", func() {
		a := MustParseAddr("1.2.3.4")
		b := MustParseAddr("2.3.4.5")
		sinkBool = a.Compare(b) == 0
	})
	test("Addr.Less", func() {
		a := MustParseAddr("1.2.3.4")
		b := MustParseAddr("2.3.4.5")
		sinkBool = a.Less(b)
	})
	test("Addr.Is4", func() { sinkBool = MustParseAddr("1.2.3.4").Is4() })
	test("Addr.Is6", func() { sinkBool = MustParseAddr("fe80::1").Is6() })
	test("Addr.Is4In6", func() { sinkBool = MustParseAddr("fe80::1").Is4In6() })
	test("Addr.Unmap", func() { sinkIP = MustParseAddr("ffff::2.3.4.5").Unmap() })
	test("Addr.WithZone", func() { sinkIP = MustParseAddr("fe80::1").WithZone("") })
	test("Addr.IsGlobalUnicast", func() { sinkBool = MustParseAddr("2001:db8::1").IsGlobalUnicast() })
	test("Addr.IsInterfaceLocalMulticast", func() { sinkBool = MustParseAddr("fe80::1").IsInterfaceLocalMulticast() })
	test("Addr.IsLinkLocalMulticast", func() { sinkBool = MustParseAddr("fe80::1").IsLinkLocalMulticast() })
	test("Addr.IsLinkLocalUnicast", func() { sinkBool = MustParseAddr("fe80::1").IsLinkLocalUnicast() })
	test("Addr.IsLoopback", func() { sinkBool = MustParseAddr("fe80::1").IsLoopback() })
	test("Addr.IsMulticast", func() { sinkBool = MustParseAddr("fe80::1").IsMulticast() })
	test("Addr.IsPrivate", func() { sinkBool = MustParseAddr("fd00::1").IsPrivate() })
	test("Addr.IsUnspecified", func() { sinkBool = IPv6Unspecified().IsUnspecified() })
	test("Addr.Prefix/4", func() { sinkPrefix = panicPfx(MustParseAddr("1.2.3.4").Prefix(20)) })
	test("Addr.Prefix/6", func() { sinkPrefix = panicPfx(MustParseAddr("fe80::1").Prefix(64)) })
	test("Addr.As16", func() { sinkIP16 = MustParseAddr("1.2.3.4").As16() })
	test("Addr.As4", func() { sinkIP4 = MustParseAddr("1.2.3.4").As4() })
	test("Addr.Next", func() { sinkIP = MustParseAddr("1.2.3.4").Next() })
	test("Addr.Prev", func() { sinkIP = MustParseAddr("1.2.3.4").Prev() })

	// AddrPort constructors
	test("AddrPortFrom", func() { sinkAddrPort = AddrPortFrom(IPv4(1, 2, 3, 4), 22) })
	test("ParseAddrPort", func() { sinkAddrPort = panicIPP(ParseAddrPort("[::1]:1234")) })
	test("MustParseAddrPort", func() { sinkAddrPort = MustParseAddrPort("[::1]:1234") })

	// Prefix constructors
	test("PrefixFrom", func() { sinkPrefix = PrefixFrom(IPv4(1, 2, 3, 4), 32) })
	test("ParsePrefix/4", func() { sinkPrefix = panicPfx(ParsePrefix("1.2.3.4/20")) })
	test("ParsePrefix/6", func() { sinkPrefix = panicPfx(ParsePrefix("fe80::1/64")) })
	test("MustParsePrefix", func() { sinkPrefix = MustParsePrefix("1.2.3.4/20") })

	// Prefix methods
	test("Prefix.Contains", func() { sinkBool = MustParsePrefix("1.2.3.0/24").Contains(MustParseAddr("1.2.3.4")) })
	test("Prefix.Overlaps", func() {
		a, b := MustParsePrefix("1.2.3.0/24"), MustParsePrefix("1.2.0.0/16")
		sinkBool = a.Overlaps(b)
	})
	test("Prefix.IsZero", func() { sinkBool = MustParsePrefix("1.2.0.0/16").IsZero() })
	test("Prefix.IsSingleIP", func() { sinkBool = MustParsePrefix("1.2.3.4/32").IsSingleIP() })
	test("Prefix.Masked", func() { sinkPrefix = MustParsePrefix("1.2.3.4/16").Masked() })
}

func TestAddrStringAllocs(t *testing.T) {
	tests := []struct {
		name       string
		ip         Addr
		wantAllocs int
	}{
		{"zero", Addr{}, 0},
		{"ipv4", MustParseAddr("192.168.1.1"), 1},
		{"ipv6", MustParseAddr("2001:db8::1"), 1},
		{"ipv6+zone", MustParseAddr("2001:db8::1%eth0"), 1},
		{"ipv4-in-ipv6", MustParseAddr("::ffff:192.168.1.1"), 1},
		{"ipv4-in-ipv6+zone", MustParseAddr("::ffff:192.168.1.1%eth0"), 1},
	}
	optimizationOff := testenv.OptimizationOff()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if optimizationOff && strings.HasPrefix(tc.name, "ipv4-in-ipv6") {
				// Optimizations are required to remove some allocs.
				t.Skipf("skipping on %v", testenv.Builder())
			}
			allocs := int(testing.AllocsPerRun(1000, func() {
				sinkString = tc.ip.String()
			}))
			if allocs != tc.wantAllocs {
				t.Errorf("allocs=%d, want %d", allocs, tc.wantAllocs)
			}
		})
	}
}

func TestPrefixString(t *testing.T) {
	tests := []struct {
		ipp  Prefix
		want string
	}{
		{Prefix{}, "invalid Prefix"},
		{PrefixFrom(Addr{}, 8), "invalid Prefix"},
		{PrefixFrom(MustParseAddr("1.2.3.4"), 88), "invalid Prefix"},
	}

	for _, tt := range tests {
		if got := tt.ipp.String(); got != tt.want {
			t.Errorf("(%#v).String() = %q want %q", tt.ipp, got, tt.want)
		}
	}
}

func TestAddrPortString(t *testing.T) {
	tests := []struct {
		ipp  AddrPort
		want string
	}{
		{MustParseAddrPort("127.0.0.1:80"), "127.0.0.1:80"},
		{MustParseAddrPort("[0000::0]:8080"), "[::]:8080"},
		{MustParseAddrPort("[FFFF::1]:8080"), "[ffff::1]:8080"},
		{AddrPort{}, "invalid AddrPort"},
		{AddrPortFrom(Addr{}, 80), "invalid AddrPort"},
	}

	for _, tt := range tests {
		if got := tt.ipp.String(); got != tt.want {
			t.Errorf("(%#v).String() = %q want %q", tt.ipp, got, tt.want)
		}
	}
}

func TestAsSlice(t *testing.T) {
	tests := []struct {
		in   Addr
		want []byte
	}{
		{in: Addr{}, want: nil},
		{in: mustIP("1.2.3.4"), want: []byte{1, 2, 3, 4}},
		{in: mustIP("ffff::1"), want: []byte{0xff, 0xff, 15: 1}},
	}

	for _, test := range tests {
		got := test.in.AsSlice()
		if !bytes.Equal(got, test.want) {
			t.Errorf("%v.AsSlice() = %v want %v", test.in, got, test.want)
		}
	}
}

var sink16 [16]byte

func BenchmarkAs16(b *testing.B) {
	addr := MustParseAddr("1::10")
	for i := 0; i < b.N; i++ {
		sink16 = addr.As16()
	}
}

"""




```