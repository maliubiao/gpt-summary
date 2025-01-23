Response:
Let's break down the thought process for analyzing the provided Go code.

1. **Understand the Goal:** The request asks for the functionality of the `conf_test.go` file within the `net` package. It specifically probes for its purpose, related Go features, code examples, command-line argument handling (if any), and potential pitfalls for users.

2. **Identify the Core Functionality:** The file name `conf_test.go` strongly suggests it's testing configuration-related aspects of the `net` package. Scanning the code confirms this. It focuses on how the system resolves hostnames and IP addresses, particularly the order in which different sources are consulted (files, DNS, mDNS, etc.).

3. **Locate Key Structures and Functions:**
    * **`nssHostTest` struct:** This clearly defines test cases for hostname lookups, including the host to look up, the local hostname, and the expected lookup order (`hostLookupOrder`).
    * **`nssStr` function:** This is a helper function to create temporary `nssConf` objects from string representations. This hints at the file interacting with `nsswitch.conf` or similar system configurations.
    * **`defaultResolvConf` variable:**  Represents the default DNS configuration when a `resolv.conf` file is absent.
    * **`TestConfHostLookupOrder` function:** This is the main testing function for hostname lookup order. It iterates through various test cases.
    * **`TestAddrLookupOrder` function:**  Tests the order for looking up addresses (reverse lookups).
    * **`setSystemNSS` function:**  This function seems to simulate or mock the system's NSS (Name Service Switch) configuration. This is a crucial piece of information.
    * **`TestSystemConf` function:** A simple test that likely triggers the loading of system configuration.
    * **`hostLookupOrder` type and its constants (`hostLookupCgo`, `hostLookupDNSFiles`, etc.):** These represent the different resolution methods and their orderings.

4. **Analyze Test Cases in `TestConfHostLookupOrder`:**  Each test case in `TestConfHostLookupOrder` provides valuable insights:
    * **`force`:**  Tests forcing the use of CGO for resolution.
    * **`netgo_dns_before_files` and `netgo_fallback_on_cgo`:**  Relate to the `netgo` build tag and its impact on lookup order.
    * **Platform-specific tests (e.g., `ubuntu_trusty_avahi`, `freebsdlinux_no_resolv_conf`, `openbsd_no_resolv_conf`):** These demonstrate how the code handles different operating system defaults and configurations. The presence of `goos` in the `conf` struct within these tests is a strong indicator.
    * **Tests involving `resolv.conf` and `nsswitch.conf`:** These highlight the code's parsing and interpretation of these configuration files. The use of `nssStr` is key here.
    * **Tests with different `lookup` values in `resolv.conf` (OpenBSD):**  Shows how specific settings in `resolv.conf` influence lookup order.
    * **Tests with "myhostname":** Illustrates how the system handles lookups for the local hostname.
    * **Tests with `mdnsTest`:** Indicates support for Multicast DNS (mDNS).
    * **Tests involving `Resolver.PreferGo`:**  Shows how the `Resolver` type can override default behavior.

5. **Infer the Purpose and Related Go Features:** Based on the analysis, the file's primary function is to test the logic that determines the order in which the Go `net` package attempts to resolve hostnames and IP addresses. This involves:
    * **Operating System Configuration:** Reading and interpreting system files like `nsswitch.conf` (or its equivalents) and `resolv.conf`.
    * **CGO:** Testing the interaction with the system's native resolver when CGO is available.
    * **Go's Internal Resolver (netgo):** Testing the behavior when using Go's pure Go resolver.
    * **Build Tags:** Observing the use of `//go:build unix` and the checks for `netGoBuildTag` and `cgoAvailable`.
    * **Testing Framework:** Utilizing the `testing` package for unit tests.
    * **File System Interaction:** Creating and managing temporary files for simulating configuration files.

6. **Construct Code Examples:**  Based on the tests, it's possible to create illustrative Go code demonstrating how to influence the lookup order, even though the test file itself doesn't *directly* expose these mechanisms for end-users. The examples should focus on the concepts being tested.

7. **Consider Command-Line Arguments:**  Review the code for any explicit parsing of command-line arguments. In this case, the test file itself doesn't directly process command-line arguments. However, the *behavior* being tested is influenced by system configuration, which *could* be affected by command-line tools or environment variables *outside* the Go code. This nuance is important.

8. **Identify Potential Pitfalls:**  Think about common mistakes developers might make when working with hostname resolution:
    * **Assuming a specific lookup order:**  The order can vary by OS and configuration.
    * **Not considering `netgo` vs. CGO:** The behavior can differ significantly.
    * **Ignoring system configuration:** Changes to `nsswitch.conf` or `resolv.conf` will affect Go's resolver.
    * **Platform differences:** Code that works on one OS might not work the same way on another.

9. **Structure the Answer:** Organize the findings into logical sections (Functionality, Go Feature Implementation, Code Examples, etc.) as requested. Use clear and concise language, providing context and explanations.

10. **Review and Refine:** Read through the generated answer to ensure accuracy, clarity, and completeness. Check for any inconsistencies or areas that could be explained better. For example, explicitly mentioning that the test code *simulates* system configuration instead of directly manipulating it is important.
这个 `go/src/net/conf_test.go` 文件是 Go 语言 `net` 包的一部分，专门用于测试网络配置相关的逻辑，特别是 **主机名查找顺序** 和 **地址查找顺序**。  它模拟了各种系统配置情况，并验证在这些情况下 Go 的网络库会如何进行主机名和 IP 地址的解析。

以下是其主要功能点的详细解释：

**1. 测试主机名查找顺序 (Host Lookup Order):**

   - **核心功能:**  测试在不同的系统配置下，当 Go 程序尝试解析主机名时，会按照什么样的顺序查找不同的信息来源（例如：本地 `hosts` 文件、DNS 服务器等）。这个查找顺序受到操作系统配置（如 `nsswitch.conf` 文件）和 `resolv.conf` 文件的影响。
   - **测试方法:**  `TestConfHostLookupOrder` 函数是这个功能的核心。它通过以下步骤进行测试：
     - **模拟系统配置:**  使用 `nssStr` 函数创建临时的 `nsswitch.conf` 文件的内容，并使用 `defaultResolvConf` 或自定义的 `dnsConfig` 模拟 `resolv.conf` 的内容。
     - **定义测试用例:**  `tests` 变量包含了多个测试用例，每个用例定义了：
       - `name`: 测试用例的名称。
       - `c`:  一个 `conf` 结构体，用于模拟不同的 Go 内部配置，例如是否强制使用 CGO 解析器 (`preferCgo`, `netCgo`)，是否使用纯 Go 解析器 (`netGo`)，以及模拟 mDNS 的存在状态 (`mdnsTest`)。
       - `nss`:  模拟的 `nsswitch.conf` 配置。
       - `resolver`:  可以指定一个 `Resolver` 结构体来测试特定的解析器配置，例如 `PreferGo: true`。
       - `resolv`: 模拟的 `resolv.conf` 配置。
       - `hostTests`:  一个包含 `nssHostTest` 结构体的切片，每个结构体定义了一个待测试的主机名 (`host`)，模拟的本地主机名 (`localhost`)，以及期望的查找顺序 (`want`)。
     - **执行测试:**  对于每个测试用例，它会设置模拟的系统配置和本地主机名，然后调用 `c.hostLookupOrder(tt.resolver, ht.host)` 来获取实际的查找顺序，并与期望的顺序进行比较。
   - **涉及的 Go 语言功能:**
     - **`testing` 包:** 用于编写和运行测试。
     - **`io/fs` 包:** 用于处理文件系统相关的错误。
     - **`os` 包:** 用于创建临时文件。
     - **结构体和方法:**  定义了 `nssHostTest` 和 `nssConf` 等结构体，以及 `parseNSSConfFile` 和 `hostLookupOrder` 等方法。
     - **条件编译 (`//go:build unix`):**  表明这个测试文件主要用于 Unix 系统。
     - **Build Tag (`netGoBuildTag`):**  用于判断 `net` 包是否使用 `netgo` build tag 构建。
     - **CGO (`cgoAvailable`):**  用于判断 CGO 是否可用。

**2. 测试地址查找顺序 (Address Lookup Order):**

   - **核心功能:**  测试在不同的系统配置下，当 Go 程序尝试通过 IP 地址反向查找主机名时，会按照什么样的顺序查找信息来源。
   - **测试方法:** `TestAddrLookupOrder` 函数执行此测试。它也使用了 `setSystemNSS` 来模拟 `nsswitch.conf` 的配置，并调用 `cnf.addrLookupOrder(nil, "192.0.2.1")` 来获取实际的查找顺序。
   - **与主机名查找的联系:** 地址查找顺序的配置也通常在 `nsswitch.conf` 文件中定义。

**3. `nssStr` 函数:**

   - **功能:**  这是一个辅助函数，用于在测试中动态创建包含指定内容的临时文件，模拟 `nsswitch.conf` 文件的内容。
   - **代码示例:**
     ```go
     func TestExampleNssStr(t *testing.T) {
         nss := nssStr(t, "hosts: files dns")
         defer os.Remove(nss.path) // 确保清理临时文件
         // 此时 nss.path 指向一个包含 "hosts: files dns" 内容的临时文件
         // 后续测试代码可以使用 nss.path 来模拟系统配置
     }
     ```
   - **假设的输入与输出:**
     - **输入:** `t *testing.T`, `s string = "hosts: files dns"`
     - **输出:**  返回一个 `*nssConf` 结构体，其 `path` 字段指向一个新创建的临时文件，该文件的内容为 "hosts: files dns"。如果创建文件失败，测试会直接 `Fatal` 退出。

**4. `defaultResolvConf` 变量:**

   - **功能:**  定义了一个 `dnsConfig` 结构体，表示当系统上不存在 `resolv.conf` 文件时，Go 语言网络库使用的默认 DNS 配置。
   - **重要字段:**
     - `servers`:  默认的 DNS 服务器地址 (`defaultNS`)。
     - `ndots`:  解析为绝对域名所需的点数量。
     - `timeout`:  DNS 查询超时时间。
     - `attempts`:  DNS 查询尝试次数。
     - `err`:  设置为 `fs.ErrNotExist`，表示模拟 `resolv.conf` 文件不存在的情况。

**5. `setSystemNSS` 函数:**

   - **功能:**  这是一个测试辅助函数，用于模拟设置系统的 NSS (Name Service Switch) 配置。它通过修改全局的 `nssConfig` 变量来达到目的。
   - **参数:**
     - `nss *nssConf`:  要设置的 NSS 配置。
     - `addDur time.Duration`:  一个时间段，用于设置 `nssConfig.lastChecked` 的值，模拟配置的更新时间。

**6. `TestSystemConf` 函数:**

   - **功能:**  这个函数调用了 `systemConf()` 函数，这个函数在 `net` 包的其他地方定义，负责加载系统的网络配置。`TestSystemConf` 的作用可能是触发和测试这个加载过程，确保没有错误发生。

**代码推理示例:**

假设我们运行一个使用 `net` 包进行主机名解析的 Go 程序，并且系统的 `nsswitch.conf` 文件包含以下内容：

```
hosts: files dns
```

并且 `resolv.conf` 文件不存在。

根据 `TestConfHostLookupOrder` 中的 `files_dns` 测试用例：

```go
{
    name:   "files_dns",
    c:      &conf{},
    resolv: defaultResolvConf,
    nss:    nssStr(t, "hosts: files dns"),
    hostTests: []nssHostTest{
        {"x.com", "myhostname", hostLookupFilesDNS},
        {"x", "myhostname", hostLookupFilesDNS},
        {"x.local", "myhostname", hostLookupFilesDNS},
    },
},
```

**假设的输入与输出:**

如果我们的 Go 程序尝试解析主机名 "x.com"，并且本地 `hosts` 文件中没有该条目，那么根据 "files_dns" 测试用例的预期，Go 的 `net` 包会首先查找本地 `hosts` 文件 (`hostLookupFiles`)，如果没有找到，则会查找 DNS 服务器 (`hostLookupDNS`)。  因此，期望的 `hostLookupOrder` 是 `hostLookupFilesDNS`。

**命令行参数处理:**

这个测试文件本身并不直接处理命令行参数。它主要通过模拟系统配置文件来测试 Go 网络库的行为。然而，实际运行 Go 程序时，可能会受到以下因素影响，这些因素可以通过命令行或环境变量进行配置：

- **`GODEBUG=netdns=go` 或 `GODEBUG=netdns=cgo`:**  这两个环境变量可以强制 Go 的 `net` 包使用纯 Go 解析器 (`netdns=go`) 或 CGO 解析器 (`netdns=cgo`)，这会影响主机名解析的行为。  虽然测试代码中使用了 `preferCgo` 和 `netGo` 来模拟这些情况，但实际运行中可以通过环境变量覆盖。

**使用者易犯错的点:**

- **假设固定的主机名查找顺序:**  开发者可能会错误地假设主机名总是按照 `files` -> `dns` 的顺序查找，但实际顺序取决于操作系统配置（`nsswitch.conf`）。不同的操作系统或配置可能导致不同的查找顺序。例如，某些系统可能先查找 DNS。
  ```go
  // 错误的做法：假设总是先查本地文件
  func resolveHostMyWay(host string) (net.IP, error) {
      // 开发者可能认为这里总是先尝试读取本地 hosts 文件
      ips, err := net.LookupIP(host)
      // ...
      return ips[0], err
  }
  ```
- **忽略 `netgo` build tag 的影响:**  如果程序使用 `netgo` build tag 构建，则会使用纯 Go 实现的 DNS 解析器，其行为可能与使用 CGO 解析器略有不同。测试用例 `netgo_dns_before_files` 和 `netgo_fallback_on_cgo` 就是为了测试这种情况。
- **没有考虑到 mDNS 的存在:** 某些系统可能会配置使用 mDNS (Multicast DNS) 来解析本地网络的主机名。如果开发者没有考虑到这一点，可能会在解析本地 `.local` 域名时遇到意外行为。测试用例 `ubuntu_trusty_avahi` 和 `files_mdns_dns` 就是为了测试 mDNS 的影响。
- **依赖于特定的 `resolv.conf` 内容:**  开发者不应该硬编码依赖于特定的 `resolv.conf` 配置，因为不同环境的 `resolv.conf` 文件内容可能不同。测试用例中通过模拟不同的 `resolv.conf` 内容来验证 Go 网络库的兼容性。

总而言之，`go/src/net/conf_test.go` 是一个非常重要的测试文件，它确保了 Go 语言的 `net` 包在各种不同的系统配置下都能正确地进行主机名和 IP 地址的解析，保证了网络编程的可靠性。

### 提示词
```
这是路径为go/src/net/conf_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build unix

package net

import (
	"io/fs"
	"os"
	"testing"
	"time"
)

type nssHostTest struct {
	host      string
	localhost string
	want      hostLookupOrder
}

func nssStr(t *testing.T, s string) *nssConf {
	f, err := os.CreateTemp(t.TempDir(), "nss")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return parseNSSConfFile(f.Name())
}

// represents a dnsConfig returned by parsing a nonexistent resolv.conf
var defaultResolvConf = &dnsConfig{
	servers:  defaultNS,
	ndots:    1,
	timeout:  5,
	attempts: 2,
	err:      fs.ErrNotExist,
}

func TestConfHostLookupOrder(t *testing.T) {
	// These tests are written for a system with cgo available,
	// without using the netgo tag.
	if netGoBuildTag {
		t.Skip("skipping test because net package built with netgo tag")
	}
	if !cgoAvailable {
		t.Skip("skipping test because cgo resolver not available")
	}

	tests := []struct {
		name      string
		c         *conf
		nss       *nssConf
		resolver  *Resolver
		resolv    *dnsConfig
		hostTests []nssHostTest
	}{
		{
			name: "force",
			c: &conf{
				preferCgo: true,
				netCgo:    true,
			},
			resolv: defaultResolvConf,
			nss:    nssStr(t, "foo: bar"),
			hostTests: []nssHostTest{
				{"foo.local", "myhostname", hostLookupCgo},
				{"google.com", "myhostname", hostLookupCgo},
			},
		},
		{
			name: "netgo_dns_before_files",
			c: &conf{
				netGo: true,
			},
			resolv: defaultResolvConf,
			nss:    nssStr(t, "hosts: dns files"),
			hostTests: []nssHostTest{
				{"x.com", "myhostname", hostLookupDNSFiles},
			},
		},
		{
			name: "netgo_fallback_on_cgo",
			c: &conf{
				netGo: true,
			},
			resolv: defaultResolvConf,
			nss:    nssStr(t, "hosts: dns files something_custom"),
			hostTests: []nssHostTest{
				{"x.com", "myhostname", hostLookupDNSFiles},
			},
		},
		{
			name: "ubuntu_trusty_avahi",
			c: &conf{
				mdnsTest: mdnsAssumeDoesNotExist,
			},
			resolv: defaultResolvConf,
			nss:    nssStr(t, "hosts: files mdns4_minimal [NOTFOUND=return] dns mdns4"),
			hostTests: []nssHostTest{
				{"foo.local", "myhostname", hostLookupCgo},
				{"foo.local.", "myhostname", hostLookupCgo},
				{"foo.LOCAL", "myhostname", hostLookupCgo},
				{"foo.LOCAL.", "myhostname", hostLookupCgo},
				{"google.com", "myhostname", hostLookupFilesDNS},
			},
		},
		{
			name: "freebsdlinux_no_resolv_conf",
			c: &conf{
				goos: "freebsd",
			},
			resolv:    defaultResolvConf,
			nss:       nssStr(t, "foo: bar"),
			hostTests: []nssHostTest{{"google.com", "myhostname", hostLookupFilesDNS}},
		},
		// On OpenBSD, no resolv.conf means no DNS.
		{
			name: "openbsd_no_resolv_conf",
			c: &conf{
				goos: "openbsd",
			},
			resolv:    defaultResolvConf,
			hostTests: []nssHostTest{{"google.com", "myhostname", hostLookupFiles}},
		},
		{
			name: "solaris_no_nsswitch",
			c: &conf{
				goos: "solaris",
			},
			resolv:    defaultResolvConf,
			nss:       &nssConf{err: fs.ErrNotExist},
			hostTests: []nssHostTest{{"google.com", "myhostname", hostLookupCgo}},
		},
		{
			name: "openbsd_lookup_bind_file",
			c: &conf{
				goos: "openbsd",
			},
			resolv: &dnsConfig{lookup: []string{"bind", "file"}},
			hostTests: []nssHostTest{
				{"google.com", "myhostname", hostLookupDNSFiles},
				{"foo.local", "myhostname", hostLookupDNSFiles},
			},
		},
		{
			name: "openbsd_lookup_file_bind",
			c: &conf{
				goos: "openbsd",
			},
			resolv:    &dnsConfig{lookup: []string{"file", "bind"}},
			hostTests: []nssHostTest{{"google.com", "myhostname", hostLookupFilesDNS}},
		},
		{
			name: "openbsd_lookup_bind",
			c: &conf{
				goos: "openbsd",
			},
			resolv:    &dnsConfig{lookup: []string{"bind"}},
			hostTests: []nssHostTest{{"google.com", "myhostname", hostLookupDNS}},
		},
		{
			name: "openbsd_lookup_file",
			c: &conf{
				goos: "openbsd",
			},
			resolv:    &dnsConfig{lookup: []string{"file"}},
			hostTests: []nssHostTest{{"google.com", "myhostname", hostLookupFiles}},
		},
		{
			name: "openbsd_lookup_yp",
			c: &conf{
				goos: "openbsd",
			},
			resolv:    &dnsConfig{lookup: []string{"file", "bind", "yp"}},
			hostTests: []nssHostTest{{"google.com", "myhostname", hostLookupCgo}},
		},
		{
			name: "openbsd_lookup_two",
			c: &conf{
				goos: "openbsd",
			},
			resolv:    &dnsConfig{lookup: []string{"file", "foo"}},
			hostTests: []nssHostTest{{"google.com", "myhostname", hostLookupCgo}},
		},
		{
			name: "openbsd_lookup_empty",
			c: &conf{
				goos: "openbsd",
			},
			resolv:    &dnsConfig{lookup: nil},
			hostTests: []nssHostTest{{"google.com", "myhostname", hostLookupDNSFiles}},
		},
		{
			name: "linux_no_nsswitch.conf",
			c: &conf{
				goos: "linux",
			},
			resolv:    defaultResolvConf,
			nss:       &nssConf{err: fs.ErrNotExist},
			hostTests: []nssHostTest{{"google.com", "myhostname", hostLookupFilesDNS}},
		},
		{
			name: "linux_empty_nsswitch.conf",
			c: &conf{
				goos: "linux",
			},
			resolv:    defaultResolvConf,
			nss:       nssStr(t, ""),
			hostTests: []nssHostTest{{"google.com", "myhostname", hostLookupFilesDNS}},
		},
		{
			name: "files_mdns_dns",
			c: &conf{
				mdnsTest: mdnsAssumeDoesNotExist,
			},
			resolv: defaultResolvConf,
			nss:    nssStr(t, "hosts: files mdns dns"),
			hostTests: []nssHostTest{
				{"x.com", "myhostname", hostLookupFilesDNS},
				{"x.local", "myhostname", hostLookupCgo},
			},
		},
		{
			name:   "dns_special_hostnames",
			c:      &conf{},
			resolv: defaultResolvConf,
			nss:    nssStr(t, "hosts: dns"),
			hostTests: []nssHostTest{
				{"x.com", "myhostname", hostLookupDNS},
				{"x\\.com", "myhostname", hostLookupCgo},     // punt on weird glibc escape
				{"foo.com%en0", "myhostname", hostLookupCgo}, // and IPv6 zones
			},
		},
		{
			name: "mdns_allow",
			c: &conf{
				mdnsTest: mdnsAssumeExists,
			},
			resolv: defaultResolvConf,
			nss:    nssStr(t, "hosts: files mdns dns"),
			hostTests: []nssHostTest{
				{"x.com", "myhostname", hostLookupCgo},
				{"x.local", "myhostname", hostLookupCgo},
			},
		},
		{
			name:   "files_dns",
			c:      &conf{},
			resolv: defaultResolvConf,
			nss:    nssStr(t, "hosts: files dns"),
			hostTests: []nssHostTest{
				{"x.com", "myhostname", hostLookupFilesDNS},
				{"x", "myhostname", hostLookupFilesDNS},
				{"x.local", "myhostname", hostLookupFilesDNS},
			},
		},
		{
			name:   "dns_files",
			c:      &conf{},
			resolv: defaultResolvConf,
			nss:    nssStr(t, "hosts: dns files"),
			hostTests: []nssHostTest{
				{"x.com", "myhostname", hostLookupDNSFiles},
				{"x", "myhostname", hostLookupDNSFiles},
				{"x.local", "myhostname", hostLookupDNSFiles},
			},
		},
		{
			name:   "something_custom",
			c:      &conf{},
			resolv: defaultResolvConf,
			nss:    nssStr(t, "hosts: dns files something_custom"),
			hostTests: []nssHostTest{
				{"x.com", "myhostname", hostLookupCgo},
			},
		},
		{
			name:   "myhostname",
			c:      &conf{},
			resolv: defaultResolvConf,
			nss:    nssStr(t, "hosts: files dns myhostname"),
			hostTests: []nssHostTest{
				{"x.com", "myhostname", hostLookupFilesDNS},
				{"myhostname", "myhostname", hostLookupCgo},
				{"myHostname", "myhostname", hostLookupCgo},
				{"myhostname.dot", "myhostname.dot", hostLookupCgo},
				{"myHostname.dot", "myhostname.dot", hostLookupCgo},
				{"_gateway", "myhostname", hostLookupCgo},
				{"_Gateway", "myhostname", hostLookupCgo},
				{"_outbound", "myhostname", hostLookupCgo},
				{"_Outbound", "myhostname", hostLookupCgo},
				{"localhost", "myhostname", hostLookupCgo},
				{"Localhost", "myhostname", hostLookupCgo},
				{"anything.localhost", "myhostname", hostLookupCgo},
				{"Anything.localhost", "myhostname", hostLookupCgo},
				{"localhost.localdomain", "myhostname", hostLookupCgo},
				{"Localhost.Localdomain", "myhostname", hostLookupCgo},
				{"anything.localhost.localdomain", "myhostname", hostLookupCgo},
				{"Anything.Localhost.Localdomain", "myhostname", hostLookupCgo},
				{"somehostname", "myhostname", hostLookupFilesDNS},
			},
		},
		{
			name: "ubuntu14.04.02",
			c: &conf{
				mdnsTest: mdnsAssumeDoesNotExist,
			},
			resolv: defaultResolvConf,
			nss:    nssStr(t, "hosts: files myhostname mdns4_minimal [NOTFOUND=return] dns mdns4"),
			hostTests: []nssHostTest{
				{"x.com", "myhostname", hostLookupFilesDNS},
				{"somehostname", "myhostname", hostLookupFilesDNS},
				{"myhostname", "myhostname", hostLookupCgo},
			},
		},
		// Debian Squeeze is just "dns,files", but lists all
		// the default criteria for dns, but then has a
		// non-standard but redundant notfound=return for the
		// files.
		{
			name:   "debian_squeeze",
			c:      &conf{},
			resolv: defaultResolvConf,
			nss:    nssStr(t, "hosts: dns [success=return notfound=continue unavail=continue tryagain=continue] files [notfound=return]"),
			hostTests: []nssHostTest{
				{"x.com", "myhostname", hostLookupDNSFiles},
				{"somehostname", "myhostname", hostLookupDNSFiles},
			},
		},
		{
			name:      "resolv.conf-unknown",
			c:         &conf{},
			resolv:    &dnsConfig{servers: defaultNS, ndots: 1, timeout: 5, attempts: 2, unknownOpt: true},
			nss:       nssStr(t, "foo: bar"),
			hostTests: []nssHostTest{{"google.com", "myhostname", hostLookupCgo}},
		},
		// Issue 24393: make sure "Resolver.PreferGo = true" acts like netgo.
		{
			name:     "resolver-prefergo",
			resolver: &Resolver{PreferGo: true},
			c: &conf{
				preferCgo: true,
				netCgo:    true,
			},
			resolv: defaultResolvConf,
			nss:    nssStr(t, ""),
			hostTests: []nssHostTest{
				{"localhost", "myhostname", hostLookupFilesDNS},
			},
		},
		{
			name:     "unknown-source",
			resolver: &Resolver{PreferGo: true},
			c:        &conf{},
			resolv:   defaultResolvConf,
			nss:      nssStr(t, "hosts: resolve files"),
			hostTests: []nssHostTest{
				{"x.com", "myhostname", hostLookupDNSFiles},
			},
		},
		{
			name:     "dns-among-unknown-sources",
			resolver: &Resolver{PreferGo: true},
			c:        &conf{},
			resolv:   defaultResolvConf,
			nss:      nssStr(t, "hosts: mymachines files dns"),
			hostTests: []nssHostTest{
				{"x.com", "myhostname", hostLookupFilesDNS},
			},
		},
		{
			name:     "dns-among-unknown-sources-2",
			resolver: &Resolver{PreferGo: true},
			c:        &conf{},
			resolv:   defaultResolvConf,
			nss:      nssStr(t, "hosts: dns mymachines files"),
			hostTests: []nssHostTest{
				{"x.com", "myhostname", hostLookupDNSFiles},
			},
		},
	}

	origGetHostname := getHostname
	defer func() { getHostname = origGetHostname }()
	defer setSystemNSS(getSystemNSS(), 0)
	conf, err := newResolvConfTest()
	if err != nil {
		t.Fatal(err)
	}
	defer conf.teardown()

	for _, tt := range tests {
		if !conf.forceUpdateConf(tt.resolv, time.Now().Add(time.Hour)) {
			t.Errorf("%s: failed to change resolv config", tt.name)
		}
		for _, ht := range tt.hostTests {
			getHostname = func() (string, error) { return ht.localhost, nil }
			setSystemNSS(tt.nss, time.Hour)

			gotOrder, _ := tt.c.hostLookupOrder(tt.resolver, ht.host)
			if gotOrder != ht.want {
				t.Errorf("%s: hostLookupOrder(%q) = %v; want %v", tt.name, ht.host, gotOrder, ht.want)
			}
		}
	}
}

func TestAddrLookupOrder(t *testing.T) {
	// This test is written for a system with cgo available,
	// without using the netgo tag.
	if netGoBuildTag {
		t.Skip("skipping test because net package built with netgo tag")
	}
	if !cgoAvailable {
		t.Skip("skipping test because cgo resolver not available")
	}

	defer setSystemNSS(getSystemNSS(), 0)
	c, err := newResolvConfTest()
	if err != nil {
		t.Fatal(err)
	}
	defer c.teardown()

	if !c.forceUpdateConf(defaultResolvConf, time.Now().Add(time.Hour)) {
		t.Fatal("failed to change resolv config")
	}

	setSystemNSS(nssStr(t, "hosts: files myhostname dns"), time.Hour)
	cnf := &conf{}
	order, _ := cnf.addrLookupOrder(nil, "192.0.2.1")
	if order != hostLookupCgo {
		t.Errorf("addrLookupOrder returned: %v, want cgo", order)
	}

	setSystemNSS(nssStr(t, "hosts: files mdns4 dns"), time.Hour)
	order, _ = cnf.addrLookupOrder(nil, "192.0.2.1")
	if order != hostLookupCgo {
		t.Errorf("addrLookupOrder returned: %v, want cgo", order)
	}

}

func setSystemNSS(nss *nssConf, addDur time.Duration) {
	nssConfig.mu.Lock()
	nssConfig.nssConf = nss
	nssConfig.mu.Unlock()
	nssConfig.acquireSema()
	nssConfig.lastChecked = time.Now().Add(addDur)
	nssConfig.releaseSema()
}

func TestSystemConf(t *testing.T) {
	systemConf()
}
```