Response:
Let's break down the thought process to analyze the provided Go code and generate the Chinese explanation.

1. **Understand the Goal:** The request asks for a functional description of the Go code snippet, to infer its purpose within the `net` package, provide illustrative examples, and point out potential pitfalls.

2. **Initial Code Scan (Keywords and Structure):**  Quickly scan the code for familiar Go constructs and keywords related to networking:
    * `package net`:  Confirms it's part of the standard networking library.
    * `import`:  Uses `fmt`, `reflect`, `runtime`, and `testing`, suggesting testing and some reflection or OS-specific logic.
    * Function names like `loopbackInterface`, `ipv6LinkLocalUnicastAddr`, `TestInterfaces`, `TestInterfaceAddrs`, `TestInterfaceUnicastAddrs`, `TestInterfaceMulticastAddrs`, `Benchmark...`:  Strong indication of testing and benchmarking related to network interfaces and addresses.
    * Structs like `Interface`, `IPNet`, `IPAddr`:  These are fundamental to the `net` package and represent network interface information and IP addresses/networks.
    * Constants like `FlagLoopback`, `FlagUp`: Flags associated with network interfaces.

3. **Analyze Individual Functions:**  Go through each function and understand its specific role:
    * `loopbackInterface()`:  Iterates through interfaces and returns the first one that is a loopback interface and is up.
    * `ipv6LinkLocalUnicastAddr(ifi *Interface)`:  Takes an interface, gets its addresses, and returns the first IPv6 link-local unicast address.
    * `TestInterfaces(t *testing.T)`: This is clearly a test function. It calls `Interfaces()` to get all interfaces, then uses `InterfaceByIndex` and `InterfaceByName` to verify that retrieving interfaces by index and name works correctly. It also logs interface details.
    * `TestInterfaceAddrs(t *testing.T)`: Another test. It gets all interfaces and their addresses, then uses helper functions (`interfaceStats`, `validateInterfaceUnicastAddrs`, `checkUnicastStats`) to validate the addresses.
    * `TestInterfaceUnicastAddrs(t *testing.T)`: Similar to `TestInterfaceAddrs`, but focuses specifically on unicast addresses obtained through iterating over each interface.
    * `TestInterfaceMulticastAddrs(t *testing.T)`: Tests retrieval and validation of *multicast* addresses for each interface.
    * `interfaceStats(ift []Interface)`:  Counts the number of up loopback and other interfaces. This is a helper for the tests.
    * `routeStats`:  A struct to hold counts of IPv4 and IPv6 routes (unicast/multicast).
    * `validateInterfaceUnicastAddrs(ifat []Addr)`:  Examines a list of addresses, ensuring they are valid unicast addresses (either `IPNet` or `IPAddr`), and counts IPv4 and IPv6 unicast addresses. Includes checks for prefix lengths.
    * `validateInterfaceMulticastAddrs(ifat []Addr)`:  Similar to the unicast version, but validates and counts multicast addresses.
    * `checkUnicastStats(ifStats *ifStats, uniStats *routeStats)`:  Performs assertions based on the counts of interfaces and unicast addresses. Checks if IPv4/IPv6 unicast routes exist when expected.
    * `checkMulticastStats(ifStats *ifStats, uniStats, multiStats *routeStats)`:  Performs assertions based on interface, unicast, and multicast address counts, with some platform-specific exceptions.
    * `Benchmark...`:  These functions are for performance testing (benchmarking) the various interface-related functions.

4. **Infer the Go Feature:**  Based on the function names and the types being manipulated, the core functionality being tested is clearly **network interface management** in Go. This includes:
    * Listing network interfaces (`Interfaces`).
    * Retrieving interfaces by index (`InterfaceByIndex`) and name (`InterfaceByName`).
    * Getting the addresses associated with an interface (`ifi.Addrs()`).
    * Specifically getting multicast addresses (`ifi.MulticastAddrs()`).

5. **Illustrative Go Code Example:**  Create a simple example demonstrating the use of the key functions like `Interfaces`, `InterfaceByIndex`, `InterfaceByName`, and retrieving addresses. This should showcase the typical usage.

6. **Code Reasoning (Hypothetical Inputs and Outputs):** Choose a simple scenario (e.g., a system with a loopback interface and a single Ethernet interface with an IP address). Trace the execution of the test functions conceptually, outlining what inputs they'd receive (the interface data) and what outputs (success or failure from the `t.Fatal`/`t.Errorf` calls) would be expected. Focus on how the validation functions work.

7. **Command-Line Arguments:** Since the code is purely testing and doesn't have a `main` function or parse command-line arguments directly, state that it doesn't involve command-line processing. Mentioning that the `go test` command is used to run these tests is helpful context.

8. **Common Mistakes:** Think about typical errors developers might make when working with network interfaces:
    * Not checking for errors when calling functions like `Interfaces()`.
    * Assuming an interface with a specific name or index exists.
    * Incorrectly interpreting the flags of an interface.
    * Not handling cases where no interfaces or specific types of addresses are found.

9. **Structure and Language:** Organize the findings logically, starting with the overall functionality, then going into details of each part. Use clear and concise Chinese. Use appropriate technical terminology.

10. **Review and Refine:** Read through the generated explanation to ensure accuracy, clarity, and completeness. Check that the Go code examples are correct and easy to understand. Make sure the common mistakes section is relevant and helpful. Ensure the language is natural and flows well.

**(Self-Correction Example During the Process):**

*Initially, I might have focused too much on the low-level details of the `validateInterfaceUnicastAddrs` function. I would then realize that the core functionality is about *accessing* and *listing* interfaces and their addresses. The validation is secondary, being part of the *testing* process. So, I'd re-prioritize the explanation to emphasize the primary functions first.*

*I might also initially forget to include an example. Realizing this omission, I'd add a simple `main` function demonstrating the basic usage.*

By following this structured approach, systematically analyzing the code, and thinking from a user's perspective, we can generate a comprehensive and helpful explanation like the example provided in the initial prompt.
这段代码是 Go 语言标准库 `net` 包中 `interface_test.go` 文件的一部分，它的主要功能是 **测试和验证网络接口相关的功能**。

更具体地说，它测试了 `net` 包中用于获取和操作网络接口信息的函数，例如：

1. **`Interfaces()` 函数:**  用于获取主机上所有网络接口的列表。
2. **`InterfaceByIndex(index int)` 函数:**  根据索引获取指定的网络接口。
3. **`InterfaceByName(name string)` 函数:**  根据名称获取指定的网络接口。
4. **`(*Interface).Addrs()` 方法:**  获取指定网络接口的所有地址（包括 IPv4 和 IPv6 的单播地址）。
5. **`(*Interface).MulticastAddrs()` 方法:** 获取指定网络接口的所有组播地址。

**代码功能分解:**

* **`loopbackInterface()` 函数:**  这个辅助函数用于查找并返回一个可用的环回网络接口（例如 `lo` 或 `lo0`）。它遍历所有接口，检查 `FlagLoopback` 和 `FlagUp` 标志，以确定是否为活动的环回接口。
* **`ipv6LinkLocalUnicastAddr(ifi *Interface)` 函数:** 这个辅助函数用于在给定的网络接口上查找并返回一个 IPv6 的链路本地单播地址。它遍历接口的所有地址，检查是否为 IPv6 地址且属于链路本地单播地址范围。
* **`TestInterfaces(t *testing.T)` 函数:**  这是一个测试函数，用于验证 `Interfaces()`, `InterfaceByIndex()`, 和 `InterfaceByName()` 函数的功能。它获取所有接口，然后尝试通过索引和名称重新获取每个接口，并比较结果是否一致。同时，它还会打印每个接口的一些基本信息。
* **`TestInterfaceAddrs(t *testing.T)` 函数:**  这是一个测试函数，用于验证 `InterfaceAddrs()` 函数的功能。它获取所有接口的地址，并使用辅助函数 `validateInterfaceUnicastAddrs` 和 `checkUnicastStats` 来验证返回的地址信息是否正确。
* **`TestInterfaceUnicastAddrs(t *testing.T)` 函数:**  这个测试函数更细致地验证了获取每个接口的单播地址的功能，并同样使用辅助函数进行验证。
* **`TestInterfaceMulticastAddrs(t *testing.T)` 函数:**  这是一个测试函数，用于验证 `MulticastAddrs()` 方法的功能。它获取每个接口的组播地址，并使用辅助函数 `validateInterfaceMulticastAddrs` 和 `checkMulticastStats` 进行验证。
* **`interfaceStats(ift []Interface)` 函数:**  这是一个辅助函数，用于统计给定接口列表中活动的环回接口和其他接口的数量。
* **`routeStats` 结构体:**  用于存储 IPv4 和 IPv6 路由的统计信息。
* **`validateInterfaceUnicastAddrs(ifat []Addr)` 函数:**  这是一个辅助函数，用于验证给定的地址列表是否为有效的单播地址，并统计 IPv4 和 IPv6 地址的数量。它会检查地址的类型、IP 地址的有效性、以及前缀长度等。
* **`validateInterfaceMulticastAddrs(ifat []Addr)` 函数:**  这是一个辅助函数，用于验证给定的地址列表是否为有效的组播地址，并统计 IPv4 和 IPv6 地址的数量。
* **`checkUnicastStats(ifStats *ifStats, uniStats *routeStats)` 函数:**  这是一个辅助函数，用于根据接口统计信息和单播地址统计信息进行断言，验证单播路由的存在性。
* **`checkMulticastStats(ifStats *ifStats, uniStats, multiStats *routeStats)` 函数:**  这是一个辅助函数，用于根据接口统计信息、单播地址统计信息和组播地址统计信息进行断言，验证组播路由的存在性。
* **`BenchmarkInterfaces(b *testing.B)` 等 `Benchmark...` 函数:**  这些是基准测试函数，用于评估 `Interfaces()`, `InterfaceByIndex()`, `InterfaceByName()`, `InterfaceAddrs()`, 和 `MulticastAddrs()` 等函数的性能。

**推理 `net` 包中网络接口功能的实现:**

这段测试代码暗示了 `net` 包提供了访问操作系统底层网络接口信息的能力。通过 `Interfaces()` 函数，Go 程序可以获取到系统中所有网络接口的详细信息，包括接口名称、索引、标志（如是否为环回接口、是否启用等）、MTU (最大传输单元)、硬件地址（MAC 地址）以及关联的 IP 地址。

**Go 代码示例说明:**

假设我们想获取本地所有的网络接口并打印它们的名称和 IP 地址。可以使用以下代码：

```go
package main

import (
	"fmt"
	"net"
)

func main() {
	interfaces, err := net.Interfaces()
	if err != nil {
		fmt.Println("Error getting interfaces:", err)
		return
	}

	for _, iface := range interfaces {
		fmt.Printf("Interface Name: %s\n", iface.Name)
		addrs, err := iface.Addrs()
		if err != nil {
			fmt.Printf("  Error getting addresses for %s: %v\n", iface.Name, err)
			continue
		}
		for _, addr := range addrs {
			fmt.Printf("  Address: %s\n", addr.String())
		}
		fmt.Println("---")
	}
}
```

**假设的输入与输出:**

假设你的系统有一个名为 `eth0` 的以太网接口，IP 地址为 `192.168.1.100/24` 和一个名为 `lo` 的环回接口，IP 地址为 `127.0.0.1/8` 和 `::1/128`。

**运行上述代码的输出可能如下：**

```
Interface Name: eth0
  Address: 192.168.1.100/24
  Address: fe80::a00:27ff:fe94:1234%eth0
---
Interface Name: lo
  Address: 127.0.0.1/8
  Address: ::1/128
---
```

**命令行参数处理:**

这段代码本身是测试代码，并不直接处理命令行参数。但是，当使用 `go test` 命令运行这些测试时，可以使用一些标准的 `go test` 命令行参数，例如：

* **`-v`:**  显示更详细的测试输出。
* **`-run <regexp>`:**  只运行名称匹配正则表达式的测试函数。例如，`go test -v -run TestInterfaces` 只会运行 `TestInterfaces` 函数。
* **`-bench <regexp>`:** 只运行名称匹配正则表达式的基准测试函数。例如，`go test -bench BenchmarkInterfaces` 只会运行 `BenchmarkInterfaces` 函数。

**使用者易犯错的点:**

1. **假设接口名称或索引固定:**  网络接口的名称和索引在不同的操作系统或配置下可能不同。直接硬编码接口名称或索引可能会导致程序在其他环境下运行失败。应该通过 `Interfaces()` 获取接口列表，然后根据需要查找目标接口。

   **错误示例:**

   ```go
   iface, err := net.InterfaceByName("eth0") // 假设接口名为 eth0
   if err != nil {
       fmt.Println("Error:", err) // 如果没有 eth0 接口就会出错
       return
   }
   // ... 使用 iface
   ```

   **正确做法:**

   ```go
   interfaces, err := net.Interfaces()
   if err != nil {
       fmt.Println("Error:", err)
       return
   }
   for _, iface := range interfaces {
       if iface.Name == "eth0" { // 查找名为 eth0 的接口
           // ... 使用 iface
           break
       }
   }
   ```

2. **忽略错误处理:**  在调用 `net` 包中的函数时，应该始终检查返回的错误。例如，如果网络接口不存在或权限不足，`InterfaceByName` 和 `InterfaceByIndex` 可能会返回错误。

   **错误示例:**

   ```go
   iface, _ := net.InterfaceByName("nonexistent") // 忽略了错误
   fmt.Println(iface.Name) // 可能导致 panic 或不确定的行为
   ```

   **正确做法:**

   ```go
   iface, err := net.InterfaceByName("nonexistent")
   if err != nil {
       fmt.Println("Error:", err)
       return
   }
   fmt.Println(iface.Name)
   ```

3. **不理解接口的 Flags:**  `Interface` 结构体包含一个 `Flags` 字段，它是一个位掩码，表示接口的状态和属性，例如是否启用、是否为环回接口等。使用者可能错误地假设接口处于某种状态，而没有检查 `Flags`。

   **错误示例:**

   ```go
   iface, err := net.InterfaceByName("eth0")
   // ...
   if iface.Flags & net.FlagUp == 0 { // 错误地假设接口已启动
       fmt.Println("Interface is down")
   }
   ```

   **应该查阅 `net` 包的文档，了解各种 `Flag` 的含义，并根据需要进行检查。**

总而言之，`go/src/net/interface_test.go` 这段代码是 `net` 包中网络接口功能的测试代码，它通过各种测试用例验证了获取和操作网络接口信息的相关函数的正确性。 通过阅读这段代码，可以了解 `net` 包提供的网络接口功能以及如何正确使用它们。

### 提示词
```
这是路径为go/src/net/interface_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package net

import (
	"fmt"
	"reflect"
	"runtime"
	"testing"
)

// loopbackInterface returns an available logical network interface
// for loopback tests. It returns nil if no suitable interface is
// found.
func loopbackInterface() *Interface {
	ift, err := Interfaces()
	if err != nil {
		return nil
	}
	for _, ifi := range ift {
		if ifi.Flags&FlagLoopback != 0 && ifi.Flags&FlagUp != 0 {
			return &ifi
		}
	}
	return nil
}

// ipv6LinkLocalUnicastAddr returns an IPv6 link-local unicast address
// on the given network interface for tests. It returns "" if no
// suitable address is found.
func ipv6LinkLocalUnicastAddr(ifi *Interface) string {
	if ifi == nil {
		return ""
	}
	ifat, err := ifi.Addrs()
	if err != nil {
		return ""
	}
	for _, ifa := range ifat {
		if ifa, ok := ifa.(*IPNet); ok {
			if ifa.IP.To4() == nil && ifa.IP.IsLinkLocalUnicast() {
				return ifa.IP.String()
			}
		}
	}
	return ""
}

func TestInterfaces(t *testing.T) {
	ift, err := Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, ifi := range ift {
		ifxi, err := InterfaceByIndex(ifi.Index)
		if err != nil {
			t.Fatal(err)
		}
		switch runtime.GOOS {
		case "solaris", "illumos":
			if ifxi.Index != ifi.Index {
				t.Errorf("got %v; want %v", ifxi, ifi)
			}
		default:
			if !reflect.DeepEqual(ifxi, &ifi) {
				t.Errorf("got %v; want %v", ifxi, ifi)
			}
		}
		ifxn, err := InterfaceByName(ifi.Name)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(ifxn, &ifi) {
			t.Errorf("got %v; want %v", ifxn, ifi)
		}
		t.Logf("%s: flags=%v index=%d mtu=%d hwaddr=%v", ifi.Name, ifi.Flags, ifi.Index, ifi.MTU, ifi.HardwareAddr)
	}
}

func TestInterfaceAddrs(t *testing.T) {
	ift, err := Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	ifStats := interfaceStats(ift)
	ifat, err := InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	uniStats, err := validateInterfaceUnicastAddrs(ifat)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkUnicastStats(ifStats, uniStats); err != nil {
		t.Fatal(err)
	}
}

func TestInterfaceUnicastAddrs(t *testing.T) {
	ift, err := Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	ifStats := interfaceStats(ift)
	if err != nil {
		t.Fatal(err)
	}
	var uniStats routeStats
	for _, ifi := range ift {
		ifat, err := ifi.Addrs()
		if err != nil {
			t.Fatal(ifi, err)
		}
		stats, err := validateInterfaceUnicastAddrs(ifat)
		if err != nil {
			t.Fatal(ifi, err)
		}
		uniStats.ipv4 += stats.ipv4
		uniStats.ipv6 += stats.ipv6
	}
	if err := checkUnicastStats(ifStats, &uniStats); err != nil {
		t.Fatal(err)
	}
}

func TestInterfaceMulticastAddrs(t *testing.T) {
	ift, err := Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	ifStats := interfaceStats(ift)
	ifat, err := InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	uniStats, err := validateInterfaceUnicastAddrs(ifat)
	if err != nil {
		t.Fatal(err)
	}
	var multiStats routeStats
	for _, ifi := range ift {
		ifmat, err := ifi.MulticastAddrs()
		if err != nil {
			t.Fatal(ifi, err)
		}
		stats, err := validateInterfaceMulticastAddrs(ifmat)
		if err != nil {
			t.Fatal(ifi, err)
		}
		multiStats.ipv4 += stats.ipv4
		multiStats.ipv6 += stats.ipv6
	}
	if err := checkMulticastStats(ifStats, uniStats, &multiStats); err != nil {
		t.Fatal(err)
	}
}

type ifStats struct {
	loop  int // # of active loopback interfaces
	other int // # of active other interfaces
}

func interfaceStats(ift []Interface) *ifStats {
	var stats ifStats
	for _, ifi := range ift {
		if ifi.Flags&FlagUp != 0 {
			if ifi.Flags&FlagLoopback != 0 {
				stats.loop++
			} else {
				stats.other++
			}
		}
	}
	return &stats
}

type routeStats struct {
	ipv4, ipv6 int // # of active connected unicast, anycast or multicast routes
}

func validateInterfaceUnicastAddrs(ifat []Addr) (*routeStats, error) {
	// Note: BSD variants allow assigning any IPv4/IPv6 address
	// prefix to IP interface. For example,
	//   - 0.0.0.0/0 through 255.255.255.255/32
	//   - ::/0 through ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128
	// In other words, there is no tightly-coupled combination of
	// interface address prefixes and connected routes.
	stats := new(routeStats)
	for _, ifa := range ifat {
		switch ifa := ifa.(type) {
		case *IPNet:
			if ifa == nil || ifa.IP == nil || ifa.IP.IsMulticast() || ifa.Mask == nil {
				return nil, fmt.Errorf("unexpected value: %#v", ifa)
			}
			if len(ifa.IP) != IPv6len {
				return nil, fmt.Errorf("should be internal representation either IPv6 or IPv4-mapped IPv6 address: %#v", ifa)
			}
			prefixLen, maxPrefixLen := ifa.Mask.Size()
			if ifa.IP.To4() != nil {
				if 0 >= prefixLen || prefixLen > 8*IPv4len || maxPrefixLen != 8*IPv4len {
					return nil, fmt.Errorf("unexpected prefix length: %d/%d for %#v", prefixLen, maxPrefixLen, ifa)
				}
				if ifa.IP.IsLoopback() && prefixLen < 8 { // see RFC 1122
					return nil, fmt.Errorf("unexpected prefix length: %d/%d for %#v", prefixLen, maxPrefixLen, ifa)
				}
				stats.ipv4++
			}
			if ifa.IP.To16() != nil && ifa.IP.To4() == nil {
				if 0 >= prefixLen || prefixLen > 8*IPv6len || maxPrefixLen != 8*IPv6len {
					return nil, fmt.Errorf("unexpected prefix length: %d/%d for %#v", prefixLen, maxPrefixLen, ifa)
				}
				if ifa.IP.IsLoopback() && prefixLen != 8*IPv6len { // see RFC 4291
					return nil, fmt.Errorf("unexpected prefix length: %d/%d for %#v", prefixLen, maxPrefixLen, ifa)
				}
				stats.ipv6++
			}
		case *IPAddr:
			if ifa == nil || ifa.IP == nil || ifa.IP.IsMulticast() {
				return nil, fmt.Errorf("unexpected value: %#v", ifa)
			}
			if len(ifa.IP) != IPv6len {
				return nil, fmt.Errorf("should be internal representation either IPv6 or IPv4-mapped IPv6 address: %#v", ifa)
			}
			if ifa.IP.To4() != nil {
				stats.ipv4++
			}
			if ifa.IP.To16() != nil && ifa.IP.To4() == nil {
				stats.ipv6++
			}
		default:
			return nil, fmt.Errorf("unexpected type: %T", ifa)
		}
	}
	return stats, nil
}

func validateInterfaceMulticastAddrs(ifat []Addr) (*routeStats, error) {
	stats := new(routeStats)
	for _, ifa := range ifat {
		switch ifa := ifa.(type) {
		case *IPAddr:
			if ifa == nil || ifa.IP == nil || ifa.IP.IsUnspecified() || !ifa.IP.IsMulticast() {
				return nil, fmt.Errorf("unexpected value: %#v", ifa)
			}
			if len(ifa.IP) != IPv6len {
				return nil, fmt.Errorf("should be internal representation either IPv6 or IPv4-mapped IPv6 address: %#v", ifa)
			}
			if ifa.IP.To4() != nil {
				stats.ipv4++
			}
			if ifa.IP.To16() != nil && ifa.IP.To4() == nil {
				stats.ipv6++
			}
		default:
			return nil, fmt.Errorf("unexpected type: %T", ifa)
		}
	}
	return stats, nil
}

func checkUnicastStats(ifStats *ifStats, uniStats *routeStats) error {
	// Test the existence of connected unicast routes for IPv4.
	if supportsIPv4() && ifStats.loop+ifStats.other > 0 && uniStats.ipv4 == 0 {
		return fmt.Errorf("num IPv4 unicast routes = 0; want >0; summary: %+v, %+v", ifStats, uniStats)
	}
	// Test the existence of connected unicast routes for IPv6.
	// We can assume the existence of ::1/128 when at least one
	// loopback interface is installed.
	if supportsIPv6() && ifStats.loop > 0 && uniStats.ipv6 == 0 {
		return fmt.Errorf("num IPv6 unicast routes = 0; want >0; summary: %+v, %+v", ifStats, uniStats)
	}
	return nil
}

func checkMulticastStats(ifStats *ifStats, uniStats, multiStats *routeStats) error {
	switch runtime.GOOS {
	case "aix", "dragonfly", "netbsd", "openbsd", "plan9", "solaris", "illumos":
	default:
		// Test the existence of connected multicast route
		// clones for IPv4. Unlike IPv6, IPv4 multicast
		// capability is not a mandatory feature, and so IPv4
		// multicast validation is ignored and we only check
		// IPv6 below.
		//
		// Test the existence of connected multicast route
		// clones for IPv6. Some platform never uses loopback
		// interface as the nexthop for multicast routing.
		// We can assume the existence of connected multicast
		// route clones when at least two connected unicast
		// routes, ::1/128 and other, are installed.
		if supportsIPv6() && ifStats.loop > 0 && uniStats.ipv6 > 1 && multiStats.ipv6 == 0 {
			return fmt.Errorf("num IPv6 multicast route clones = 0; want >0; summary: %+v, %+v, %+v", ifStats, uniStats, multiStats)
		}
	}
	return nil
}

func BenchmarkInterfaces(b *testing.B) {
	b.ReportAllocs()
	testHookUninstaller.Do(uninstallTestHooks)

	for i := 0; i < b.N; i++ {
		if _, err := Interfaces(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkInterfaceByIndex(b *testing.B) {
	b.ReportAllocs()
	testHookUninstaller.Do(uninstallTestHooks)

	ifi := loopbackInterface()
	if ifi == nil {
		b.Skip("loopback interface not found")
	}
	for i := 0; i < b.N; i++ {
		if _, err := InterfaceByIndex(ifi.Index); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkInterfaceByName(b *testing.B) {
	b.ReportAllocs()
	testHookUninstaller.Do(uninstallTestHooks)

	ifi := loopbackInterface()
	if ifi == nil {
		b.Skip("loopback interface not found")
	}
	for i := 0; i < b.N; i++ {
		if _, err := InterfaceByName(ifi.Name); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkInterfaceAddrs(b *testing.B) {
	b.ReportAllocs()
	testHookUninstaller.Do(uninstallTestHooks)

	for i := 0; i < b.N; i++ {
		if _, err := InterfaceAddrs(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkInterfacesAndAddrs(b *testing.B) {
	b.ReportAllocs()
	testHookUninstaller.Do(uninstallTestHooks)

	ifi := loopbackInterface()
	if ifi == nil {
		b.Skip("loopback interface not found")
	}
	for i := 0; i < b.N; i++ {
		if _, err := ifi.Addrs(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkInterfacesAndMulticastAddrs(b *testing.B) {
	b.ReportAllocs()
	testHookUninstaller.Do(uninstallTestHooks)

	ifi := loopbackInterface()
	if ifi == nil {
		b.Skip("loopback interface not found")
	}
	for i := 0; i < b.N; i++ {
		if _, err := ifi.MulticastAddrs(); err != nil {
			b.Fatal(err)
		}
	}
}
```