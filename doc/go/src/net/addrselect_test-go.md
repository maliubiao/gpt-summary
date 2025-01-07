Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Understanding - The Basics:**

* **File Path:** `go/src/net/addrselect_test.go` immediately suggests this is part of the Go standard library's `net` package and specifically deals with address selection. The `_test.go` suffix signifies it's a test file.
* **Package Declaration:** `package net` confirms the package.
* **Imports:** `net/netip`, `reflect`, and `testing` are standard testing imports and a specific IP address type. This points towards testing functionalities related to IP addresses.
* **`//go:build ...`:**  This is a build constraint, indicating this code is only included on specific operating systems (Darwin, Dragonfly, FreeBSD, Linux, NetBSD, OpenBSD, Solaris). This suggests the functionality being tested might be OS-specific or rely on OS-level networking behaviors.

**2. Examining the Test Functions - Core Functionality:**

* **`TestSortByRFC6724`:** This is the most substantial test function. The name strongly implies it's testing a sorting mechanism based on RFC 6724. RFC 6724 deals with default address selection for IPv6.
    * **Test Cases:** The `tests` variable is a slice of structs, each defining an input (`in`), source addresses (`srcs`), expected output (`want`), and a `reverse` flag. This pattern is typical for table-driven testing in Go.
    * **Input and Output:** The `in` and `want` fields are slices of `IPAddr`. The `srcs` are slices of `netip.Addr`. This hints that the function being tested takes a list of destination IP addresses and a list of potential source IP addresses and sorts the destination addresses according to the RFC.
    * **`sortByRFC6724withSrcs`:** This function is called within the test. Its name makes the purpose very clear – sorting by RFC 6724 considering source addresses.
    * **RFC 6724 Examples:** The comments explicitly mention examples from RFC 6724 section 10.2, confirming the focus on that standard.
    * **`reverse` flag:**  Testing with reversed input suggests a robustness check and ensuring the sorting algorithm is consistent regardless of the initial order.
    * **`reflect.DeepEqual`:**  This is the standard way to compare complex data structures for equality in Go tests.

* **`TestRFC6724PolicyTableOrder`:** This test verifies the order of the `rfc6724policyTable`. It checks if the `Prefix.Bits()` are in descending order. This suggests the policy table likely stores network prefixes with varying levels of specificity, and the order is important for matching.

* **`TestRFC6724PolicyTableContent`:** This test checks the *content* of the `rfc6724policyTable` against an `expectedRfc6724policyTable`. This confirms the specific prefixes, precedences, and labels defined by the RFC are correctly implemented.

* **`TestRFC6724PolicyTableClassify`:**  This test uses the `Classify` method of `rfc6724policyTable`. It takes an IP address and checks if it's correctly classified into a `policyTableEntry`. This confirms the policy table is used to categorize IP addresses based on their properties.

* **`TestRFC6724ClassifyScope`:** This test checks the `classifyScope` function. It maps IP addresses to different scopes (LinkLocal, SiteLocal, Global). This aligns with RFC 6724's concept of scope-based address preference.

* **`TestRFC6724CommonPrefixLength`:** This test checks the `commonPrefixLen` function, calculating the length of the common prefix between two IP addresses. This is likely a helper function used in the sorting logic.

**3. Inferring Functionality and Go Features:**

Based on the tests, the primary functionality is implementing the address selection algorithm defined in RFC 6724. This involves:

* **Sorting destination IP addresses:**  Prioritizing addresses based on factors like scope, precedence, and common prefix length with source addresses.
* **Using a policy table:**  `rfc6724policyTable` stores rules for classifying IP addresses.
* **Classifying IP addresses:** Determining the category of an IP address based on the policy table.
* **Determining IP address scope:** Identifying the network scope of an IP address.
* **Calculating common prefix length:** Comparing IP addresses at the bit level to find shared prefixes.

The Go features used are:

* **Structs:** To represent IP addresses (`IPAddr`), policy table entries (`policyTableEntry`), and test cases.
* **Slices:** To hold lists of IP addresses and policy table entries.
* **Methods:**  Functions associated with structs (e.g., `Classify` on `policyTable`).
* **Table-driven testing:**  Using a slice of structs to define multiple test scenarios.
* **`reflect.DeepEqual`:** For comparing complex data structures.
* **`netip.Addr` and `net.IP`:**  Representing IP addresses (likely the newer `netip` package for efficiency).
* **Build constraints (`//go:build`)**: For OS-specific compilation.

**4. Considering User Mistakes:**

The primary potential mistake would be misunderstanding the sorting criteria defined by RFC 6724. A user might expect a simpler sorting based on IP address values, but RFC 6724 introduces a more nuanced approach.

**5. Structuring the Answer:**

Finally, I organized the information into the requested sections:

* **功能列举:** Listing the key functionalities identified.
* **Go语言功能实现推理及代码举例:**  Providing a concise explanation and illustrative Go code example of how `sortByRFC6724withSrcs` likely works. This involves making assumptions about its internal logic based on the RFC 6724 principles.
* **代码推理，带上假设的输入与输出:**  Providing a concrete example of the sorting function with sample input and the expected output, directly relating to one of the test cases.
* **命令行参数处理:** Noting that the code snippet doesn't involve command-line arguments.
* **使用者易犯错的点:**  Explaining the potential misunderstanding of RFC 6724 sorting.

This systematic approach of analyzing the code structure, test cases, and function names allows for a comprehensive understanding of the code's purpose and the underlying Go features it utilizes.
这个`go/src/net/addrselect_test.go` 文件是 Go 语言标准库 `net` 包中关于地址选择功能的一个测试文件。它的主要功能是测试和验证 Go 语言在进行网络连接时，如何根据 RFC 6724 规范选择合适的本地源 IP 地址和目标 IP 地址。

具体来说，它测试了以下几个方面：

1. **`sortByRFC6724` 函数的正确性:** 这个函数是实现 RFC 6724 地址选择算法的核心。它根据目标地址和可能的源地址列表，对目标地址进行排序，以确定最佳的连接目标。排序的依据包括地址的范围（scope）、优先级（precedence）、标签（label）以及与源地址的匹配程度等。

2. **RFC 6724 策略表 (`rfc6724policyTable`) 的内容和顺序:** RFC 6724 定义了一个策略表，用于给不同的 IP 地址前缀分配优先级和标签。测试用例会验证这个策略表的内容是否符合 RFC 6724 的规定，并且条目的顺序是否正确（按照前缀长度降序排列）。

3. **`Classify` 方法的正确性:** `Classify` 方法用于根据 RFC 6724 策略表对 IP 地址进行分类，确定其对应的优先级和标签。测试用例会验证对于不同的 IP 地址，`Classify` 方法是否返回了正确的策略表条目。

4. **`classifyScope` 函数的正确性:** 这个函数用于判断 IP 地址的范围（scope），例如本地链路（link-local）、站点本地（site-local）或全局（global）。测试用例会验证对于不同的 IP 地址，`classifyScope` 函数是否返回了正确的范围。

5. **`commonPrefixLen` 函数的正确性:** 这个函数用于计算两个 IP 地址之间共同前缀的长度。这是地址选择算法中判断地址匹配程度的重要依据。测试用例会验证对于不同的 IP 地址对，`commonPrefixLen` 函数是否返回了正确的共同前缀长度。

**Go 语言功能实现推理及代码举例:**

这个测试文件主要测试了 Go 语言 `net` 包中与 RFC 6724 地址选择相关的实现。RFC 6724 是一项关于 IPv6 默认地址选择的规范，它定义了一套规则来确定在多个可用地址的情况下，应该优先使用哪个地址进行网络连接。虽然规范主要是针对 IPv6，但 Go 语言的实现也将其应用于 IPv4 地址的选择。

核心的实现逻辑很可能封装在 `sortByRFC6724withSrcs` 函数中。这个函数接收一个目标 IP 地址列表和一个源 IP 地址列表，并根据 RFC 6724 的规则对目标 IP 地址进行排序。

以下是一个简化的 Go 代码示例，展示了 `sortByRFC6724withSrcs` 函数可能的工作方式（这只是一个概念性的例子，实际实现会更复杂）：

```go
package net

import (
	"net"
	"net/netip"
	"sort"
)

// 假设的 sortByRFC6724withSrcs 函数实现
func sortByRFC6724withSrcs(dests []IPAddr, srcs []netip.Addr) {
	sort.Slice(dests, func(i, j int) bool {
		// 规则 1: 优先选择与源地址具有相同范围的地址
		scopeI := classifyScope(dests[i].IP.AsNetIP())
		scopeJ := classifyScope(dests[j].IP.AsNetIP())

		bestSrcForI := findBestSource(dests[i].IP.AsNetIP(), srcs)
		bestSrcForJ := findBestSource(dests[j].IP.AsNetIP(), srcs)

		if bestSrcForI.IsValid() && bestSrcForJ.IsValid() {
			srcScopeI := classifyScope(bestSrcForI)
			srcScopeJ := classifyScope(bestSrcForJ)
			if srcScopeI != srcScopeJ {
				return srcScopeI < srcScopeJ // 假设较小的 scope 更优先
			}
		}

		// 规则 2: 优先选择具有更高优先级的地址 (根据策略表)
		policyI := rfc6724policyTable.Classify(dests[i].IP.AsNetIP())
		policyJ := rfc6724policyTable.Classify(dests[j].IP.AsNetIP())
		if policyI.Precedence != policyJ.Precedence {
			return policyI.Precedence > policyJ.Precedence
		}

		// ... 其他规则，例如比较范围大小，比较标签等 ...

		return false // 默认保持原顺序
	})
}

// 辅助函数：根据目标地址找到最佳匹配的源地址（简化版）
func findBestSource(dest netip.Addr, srcs []netip.Addr) netip.Addr {
	// 这里只是一个简单的示例，实际实现可能更复杂
	for _, src := range srcs {
		if classifyScope(dest) == classifyScope(src) {
			return src
		}
	}
	return netip.Addr{} // 返回无效地址表示没有找到匹配的源地址
}

// 假设的 classifyScope 函数实现 (简化版)
func classifyScope(ip netip.Addr) scope {
	if ip.IsLoopback() {
		return scopeLinkLocal
	}
	// ... 其他范围判断逻辑 ...
	return scopeGlobal
}

// 假设的 rfc6724policyTable
var rfc6724policyTable = policyTable{
	// ... 策略表条目 ...
}

// 假设的 policyTable 和 policyTableEntry 定义
type policyTable []policyTableEntry

func (pt policyTable) Classify(ip netip.Addr) policyTableEntry {
	for _, entry := range pt {
		if entry.Prefix.Contains(ip) {
			return entry
		}
	}
	return policyTableEntry{} // 默认值
}

type policyTableEntry struct {
	Prefix     netip.Prefix
	Precedence int
	Label      int
}

// 假设的 scope 类型定义
type scope int

const (
	scopeLinkLocal scope = iota
	scopeSiteLocal
	scopeGlobal
)
```

**代码推理，带上假设的输入与输出:**

假设我们有以下输入：

```go
in := []IPAddr{
	{IP: net.ParseIP("2001:db8:1::1")},
	{IP: net.ParseIP("198.51.100.121")},
}
srcs := []netip.Addr{
	netip.MustParseAddr("fe80::1"),
	netip.MustParseAddr("198.51.100.117"),
}
```

在这个例子中，`in` 包含了两个目标 IP 地址，一个是 IPv6 地址，一个是 IPv4 地址。`srcs` 包含了两个可能的源 IP 地址，一个是 IPv6 的本地链路地址，一个是 IPv4 的全局地址。

根据 RFC 6724 的规则，`sortByRFC6724withSrcs` 函数会进行以下排序判断：

1. **比较目标地址与源地址的范围:**
   - 目标地址 `2001:db8:1::1` 是一个全局 IPv6 地址。
   - 目标地址 `198.51.100.121` 是一个全局 IPv4 地址。
   - 源地址 `fe80::1` 是一个 IPv6 的本地链路地址。
   - 源地址 `198.51.100.117` 是一个 IPv4 的全局地址。

2. **应用策略表规则:**  根据 `rfc6724policyTable`，不同的 IP 地址前缀会有不同的优先级和标签。

3. **选择最佳匹配:**  在这种情况下，目标地址 `198.51.100.121` 与源地址 `198.51.100.117` 处于相同的全局范围，因此可能会被优先选择。而目标地址 `2001:db8:1::1` 与源地址 `fe80::1` 范围不匹配。

假设 `sortByRFC6724withSrcs` 函数按照 RFC 6724 的 "Prefer matching scope" 原则进行排序，那么输出结果 `want` 应该是：

```go
want := []IPAddr{
	{IP: net.ParseIP("198.51.100.121")},
	{IP: net.ParseIP("2001:db8:1::1")},
}
```

**命令行参数的具体处理:**

这个代码片段是测试代码，本身不涉及命令行参数的处理。命令行参数的处理通常发生在应用程序的主入口 `main` 函数中，而不是测试代码中。测试代码的主要目的是验证特定函数的行为是否符合预期。

**使用者易犯错的点:**

在使用 Go 语言的 `net` 包进行网络编程时，关于地址选择方面，用户容易犯的错误可能包括：

1. **没有理解 RFC 6724 的地址选择规则:**  用户可能期望系统按照简单的 IP 地址大小或类型进行选择，而忽略了 RFC 6724 中定义的复杂规则，例如范围匹配、优先级等。这可能导致连接尝试使用了非最优的本地地址或目标地址。

   **示例:**  在一个多网卡主机上，用户可能期望连接到某个特定的网络，但由于没有正确配置或理解地址选择机制，系统可能使用了另一个网卡的 IP 地址进行连接，导致连接失败或性能下降。

2. **错误地配置或理解网络接口和地址:**  用户可能没有正确配置网络接口的 IP 地址，或者对不同类型的 IP 地址（例如本地链路地址、全局地址）的作用范围理解不足，导致程序在选择地址时出现意外行为。

   **示例:**  用户可能尝试使用一个本地链路 IPv6 地址（`fe80::/10`）连接到 Internet 上的服务器，这显然是不可行的，因为本地链路地址仅在本地网络链路内有效。

3. **假设了简单的地址选择逻辑:**  用户可能假设系统会简单地选择第一个可用的 IP 地址，而忽略了 Go 语言 `net` 包中实现的复杂的地址选择算法。这可能导致在某些网络环境下出现不期望的连接行为。

总而言之，`go/src/net/addrselect_test.go` 这个文件是 Go 语言 `net` 包中地址选择功能的重要组成部分，它通过一系列测试用例来确保 Go 语言在进行网络连接时能够根据 RFC 6724 规范选择合适的 IP 地址，从而提高网络连接的效率和可靠性。理解这部分代码的功能有助于开发者更好地理解 Go 语言的网络编程机制。

Prompt: 
```
这是路径为go/src/net/addrselect_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package net

import (
	"net/netip"
	"reflect"
	"testing"
)

func TestSortByRFC6724(t *testing.T) {
	tests := []struct {
		in      []IPAddr
		srcs    []netip.Addr
		want    []IPAddr
		reverse bool // also test it starting backwards
	}{
		// Examples from RFC 6724 section 10.2:

		// Prefer matching scope.
		{
			in: []IPAddr{
				{IP: ParseIP("2001:db8:1::1")},
				{IP: ParseIP("198.51.100.121")},
			},
			srcs: []netip.Addr{
				netip.MustParseAddr("2001:db8:1::2"),
				netip.MustParseAddr("169.254.13.78"),
			},
			want: []IPAddr{
				{IP: ParseIP("2001:db8:1::1")},
				{IP: ParseIP("198.51.100.121")},
			},
			reverse: true,
		},

		// Prefer matching scope.
		{
			in: []IPAddr{
				{IP: ParseIP("2001:db8:1::1")},
				{IP: ParseIP("198.51.100.121")},
			},
			srcs: []netip.Addr{
				netip.MustParseAddr("fe80::1"),
				netip.MustParseAddr("198.51.100.117"),
			},
			want: []IPAddr{
				{IP: ParseIP("198.51.100.121")},
				{IP: ParseIP("2001:db8:1::1")},
			},
			reverse: true,
		},

		// Prefer higher precedence.
		{
			in: []IPAddr{
				{IP: ParseIP("2001:db8:1::1")},
				{IP: ParseIP("10.1.2.3")},
			},
			srcs: []netip.Addr{
				netip.MustParseAddr("2001:db8:1::2"),
				netip.MustParseAddr("10.1.2.4"),
			},
			want: []IPAddr{
				{IP: ParseIP("2001:db8:1::1")},
				{IP: ParseIP("10.1.2.3")},
			},
			reverse: true,
		},

		// Prefer smaller scope.
		{
			in: []IPAddr{
				{IP: ParseIP("2001:db8:1::1")},
				{IP: ParseIP("fe80::1")},
			},
			srcs: []netip.Addr{
				netip.MustParseAddr("2001:db8:1::2"),
				netip.MustParseAddr("fe80::2"),
			},
			want: []IPAddr{
				{IP: ParseIP("fe80::1")},
				{IP: ParseIP("2001:db8:1::1")},
			},
			reverse: true,
		},

		// Issue 13283.  Having a 10/8 source address does not
		// mean we should prefer 23/8 destination addresses.
		{
			in: []IPAddr{
				{IP: ParseIP("54.83.193.112")},
				{IP: ParseIP("184.72.238.214")},
				{IP: ParseIP("23.23.172.185")},
				{IP: ParseIP("75.101.148.21")},
				{IP: ParseIP("23.23.134.56")},
				{IP: ParseIP("23.21.50.150")},
			},
			srcs: []netip.Addr{
				netip.MustParseAddr("10.2.3.4"),
				netip.MustParseAddr("10.2.3.4"),
				netip.MustParseAddr("10.2.3.4"),
				netip.MustParseAddr("10.2.3.4"),
				netip.MustParseAddr("10.2.3.4"),
				netip.MustParseAddr("10.2.3.4"),
			},
			want: []IPAddr{
				{IP: ParseIP("54.83.193.112")},
				{IP: ParseIP("184.72.238.214")},
				{IP: ParseIP("23.23.172.185")},
				{IP: ParseIP("75.101.148.21")},
				{IP: ParseIP("23.23.134.56")},
				{IP: ParseIP("23.21.50.150")},
			},
			reverse: false,
		},
	}
	for i, tt := range tests {
		inCopy := make([]IPAddr, len(tt.in))
		copy(inCopy, tt.in)
		srcCopy := make([]netip.Addr, len(tt.in))
		copy(srcCopy, tt.srcs)
		sortByRFC6724withSrcs(inCopy, srcCopy)
		if !reflect.DeepEqual(inCopy, tt.want) {
			t.Errorf("test %d:\nin = %s\ngot: %s\nwant: %s\n", i, tt.in, inCopy, tt.want)
		}
		if tt.reverse {
			copy(inCopy, tt.in)
			copy(srcCopy, tt.srcs)
			for j := 0; j < len(inCopy)/2; j++ {
				k := len(inCopy) - j - 1
				inCopy[j], inCopy[k] = inCopy[k], inCopy[j]
				srcCopy[j], srcCopy[k] = srcCopy[k], srcCopy[j]
			}
			sortByRFC6724withSrcs(inCopy, srcCopy)
			if !reflect.DeepEqual(inCopy, tt.want) {
				t.Errorf("test %d, starting backwards:\nin = %s\ngot: %s\nwant: %s\n", i, tt.in, inCopy, tt.want)
			}
		}

	}

}

func TestRFC6724PolicyTableOrder(t *testing.T) {
	for i := 0; i < len(rfc6724policyTable)-1; i++ {
		if !(rfc6724policyTable[i].Prefix.Bits() >= rfc6724policyTable[i+1].Prefix.Bits()) {
			t.Errorf("rfc6724policyTable item number %d sorted in wrong order = %d bits, next item = %d bits;", i, rfc6724policyTable[i].Prefix.Bits(), rfc6724policyTable[i+1].Prefix.Bits())
		}
	}
}

func TestRFC6724PolicyTableContent(t *testing.T) {
	expectedRfc6724policyTable := policyTable{
		{
			Prefix:     netip.MustParsePrefix("::1/128"),
			Precedence: 50,
			Label:      0,
		},
		{
			Prefix:     netip.MustParsePrefix("::ffff:0:0/96"),
			Precedence: 35,
			Label:      4,
		},
		{
			Prefix:     netip.MustParsePrefix("::/96"),
			Precedence: 1,
			Label:      3,
		},
		{
			Prefix:     netip.MustParsePrefix("2001::/32"),
			Precedence: 5,
			Label:      5,
		},
		{
			Prefix:     netip.MustParsePrefix("2002::/16"),
			Precedence: 30,
			Label:      2,
		},
		{
			Prefix:     netip.MustParsePrefix("3ffe::/16"),
			Precedence: 1,
			Label:      12,
		},
		{
			Prefix:     netip.MustParsePrefix("fec0::/10"),
			Precedence: 1,
			Label:      11,
		},
		{
			Prefix:     netip.MustParsePrefix("fc00::/7"),
			Precedence: 3,
			Label:      13,
		},
		{
			Prefix:     netip.MustParsePrefix("::/0"),
			Precedence: 40,
			Label:      1,
		},
	}
	if !reflect.DeepEqual(rfc6724policyTable, expectedRfc6724policyTable) {
		t.Errorf("rfc6724policyTable has wrong contend = %v; want %v", rfc6724policyTable, expectedRfc6724policyTable)
	}
}

func TestRFC6724PolicyTableClassify(t *testing.T) {
	tests := []struct {
		ip   netip.Addr
		want policyTableEntry
	}{
		{
			ip: netip.MustParseAddr("127.0.0.1"),
			want: policyTableEntry{
				Prefix:     netip.MustParsePrefix("::ffff:0:0/96"),
				Precedence: 35,
				Label:      4,
			},
		},
		{
			ip: netip.MustParseAddr("2601:645:8002:a500:986f:1db8:c836:bd65"),
			want: policyTableEntry{
				Prefix:     netip.MustParsePrefix("::/0"),
				Precedence: 40,
				Label:      1,
			},
		},
		{
			ip: netip.MustParseAddr("::1"),
			want: policyTableEntry{
				Prefix:     netip.MustParsePrefix("::1/128"),
				Precedence: 50,
				Label:      0,
			},
		},
		{
			ip: netip.MustParseAddr("2002::ab12"),
			want: policyTableEntry{
				Prefix:     netip.MustParsePrefix("2002::/16"),
				Precedence: 30,
				Label:      2,
			},
		},
	}
	for i, tt := range tests {
		got := rfc6724policyTable.Classify(tt.ip)
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%d. Classify(%s) = %v; want %v", i, tt.ip, got, tt.want)
		}
	}
}

func TestRFC6724ClassifyScope(t *testing.T) {
	tests := []struct {
		ip   netip.Addr
		want scope
	}{
		{netip.MustParseAddr("127.0.0.1"), scopeLinkLocal},   // rfc6724#section-3.2
		{netip.MustParseAddr("::1"), scopeLinkLocal},         // rfc4007#section-4
		{netip.MustParseAddr("169.254.1.2"), scopeLinkLocal}, // rfc6724#section-3.2
		{netip.MustParseAddr("fec0::1"), scopeSiteLocal},
		{netip.MustParseAddr("8.8.8.8"), scopeGlobal},

		{netip.MustParseAddr("ff02::"), scopeLinkLocal},  // IPv6 multicast
		{netip.MustParseAddr("ff05::"), scopeSiteLocal},  // IPv6 multicast
		{netip.MustParseAddr("ff04::"), scopeAdminLocal}, // IPv6 multicast
		{netip.MustParseAddr("ff0e::"), scopeGlobal},     // IPv6 multicast

		{netip.AddrFrom16([16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xe0, 0, 0, 0}), scopeGlobal}, // IPv4 link-local multicast as 16 bytes
		{netip.AddrFrom16([16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xe0, 2, 2, 2}), scopeGlobal}, // IPv4 global multicast as 16 bytes
		{netip.AddrFrom4([4]byte{0xe0, 0, 0, 0}), scopeGlobal},                                       // IPv4 link-local multicast as 4 bytes
		{netip.AddrFrom4([4]byte{0xe0, 2, 2, 2}), scopeGlobal},                                       // IPv4 global multicast as 4 bytes
	}
	for i, tt := range tests {
		got := classifyScope(tt.ip)
		if got != tt.want {
			t.Errorf("%d. classifyScope(%s) = %x; want %x", i, tt.ip, got, tt.want)
		}
	}
}

func TestRFC6724CommonPrefixLength(t *testing.T) {
	tests := []struct {
		a    netip.Addr
		b    IP
		want int
	}{
		{netip.MustParseAddr("fe80::1"), ParseIP("fe80::2"), 64},
		{netip.MustParseAddr("fe81::1"), ParseIP("fe80::2"), 15},
		{netip.MustParseAddr("127.0.0.1"), ParseIP("fe80::1"), 0}, // diff size
		{netip.AddrFrom4([4]byte{1, 2, 3, 4}), IP{1, 2, 3, 4}, 32},
		{netip.AddrFrom4([4]byte{1, 2, 255, 255}), IP{1, 2, 0, 0}, 16},
		{netip.AddrFrom4([4]byte{1, 2, 127, 255}), IP{1, 2, 0, 0}, 17},
		{netip.AddrFrom4([4]byte{1, 2, 63, 255}), IP{1, 2, 0, 0}, 18},
		{netip.AddrFrom4([4]byte{1, 2, 31, 255}), IP{1, 2, 0, 0}, 19},
		{netip.AddrFrom4([4]byte{1, 2, 15, 255}), IP{1, 2, 0, 0}, 20},
		{netip.AddrFrom4([4]byte{1, 2, 7, 255}), IP{1, 2, 0, 0}, 21},
		{netip.AddrFrom4([4]byte{1, 2, 3, 255}), IP{1, 2, 0, 0}, 22},
		{netip.AddrFrom4([4]byte{1, 2, 1, 255}), IP{1, 2, 0, 0}, 23},
		{netip.AddrFrom4([4]byte{1, 2, 0, 255}), IP{1, 2, 0, 0}, 24},
	}
	for i, tt := range tests {
		got := commonPrefixLen(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("%d. commonPrefixLen(%s, %s) = %d; want %d", i, tt.a, tt.b, got, tt.want)
		}
	}

}

"""



```