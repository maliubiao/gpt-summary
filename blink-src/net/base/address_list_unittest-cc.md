Response:
Let's break down the thought process for analyzing the C++ unittest file.

**1. Initial Understanding: The Big Picture**

The first step is to recognize this is a C++ *unittest* file within the Chromium project, specifically for the `net` component. The filename `address_list_unittest.cc` strongly suggests it tests the functionality of the `AddressList` class.

**2. Identifying Key Components and Functionality**

Scanning the `#include` directives is crucial. They reveal the core classes and concepts being tested:

* `"net/base/address_list.h"`: This is the primary header for the class under test.
* `"net/base/ip_address.h"` and `"net/base/sockaddr_storage.h"`:  These indicate that `AddressList` deals with IP addresses and socket address structures.
* `"net/base/sys_addrinfo.h"`:  This suggests interaction with system-level address information (likely from `getaddrinfo`).
* `"testing/gmock/include/gmock/gmock.h"` and `"testing/gtest/include/gtest/gtest.h"`:  Confirms this is a Google Test based unit test file.

Based on these includes and the test names, we can infer the primary responsibilities of `AddressList`:

* Storing a list of network addresses (IP addresses and port numbers).
* Handling canonical hostnames and aliases.
* Creating `AddressList` objects from system structures (`addrinfo`) and lists of IP addresses.
* Removing duplicate entries.

**3. Analyzing Individual Tests**

Now, go through each `TEST` function and decipher its purpose:

* **`Canonical`:** Focuses on setting and retrieving the canonical hostname.
* **`CreateFromAddrinfo`:** Tests the creation of `AddressList` from the `addrinfo` structure (the output of `getaddrinfo`). It checks if the IP addresses and ports are correctly extracted.
* **`CreateFromIPAddressList`:** Tests creating an `AddressList` from a list of `IPAddress` objects and associated DNS aliases.
* **`GetCanonicalNameWhenUnset`:** Verifies that an `AddressList` without an explicitly set canonical name initially has no aliases.
* **`SetDefaultCanonicalNameThenSetDnsAliases`:** Examines the behavior when setting a default canonical name (based on the IP address) and then setting aliases. Crucially, it notes that setting aliases *replaces* the default name.
* **`SetDefaultCanonicalNameThenAppendDnsAliases`:**  Similar to the previous test, but checks if appending aliases *keeps* the default canonical name.
* **`DnsAliases`:** Tests the basic setting, appending, and overwriting of DNS aliases.
* **`DeduplicatesEmptyAddressList`:** Tests the `Deduplicate` method on an empty list.
* **`DeduplicatesSingletonAddressList`:** Tests `Deduplicate` on a list with one element.
* **`DeduplicatesLongerAddressList`:** Tests `Deduplicate` with multiple elements, including duplicates, and verifies the order of the remaining elements.
* **`DeduplicatePreservesOrder`:**  A more exhaustive test of the `Deduplicate` method, using permutations to ensure the order is maintained. This is a more complex test requiring understanding of algorithms and testing methodologies.

**4. Connecting to JavaScript (If Applicable)**

Think about how network information is used in a web browser environment. JavaScript interacts with network resources through APIs like `fetch`, `XMLHttpRequest`, and WebSockets. These APIs internally rely on the browser's networking stack to resolve hostnames and establish connections.

* **Hostname Resolution:**  When JavaScript code uses a hostname (e.g., `fetch('https://www.example.com')`), the browser needs to resolve that hostname to IP addresses. The `AddressList` class is involved in representing the results of this DNS resolution. The canonical name and aliases are directly relevant here.

* **Connection Establishment:**  Once IP addresses are resolved, the browser tries to connect to one of them. The `AddressList` provides the list of potential endpoints to try.

**5. Hypothesizing Inputs and Outputs (Logical Reasoning)**

For functions like `CreateFromAddrinfo` and `Deduplicate`, you can imagine specific inputs and predict the outputs based on the test logic. For instance:

* **`CreateFromAddrinfo` Input:** An `addrinfo` structure containing multiple IPv4 addresses with different ports.
* **`CreateFromAddrinfo` Output:** An `AddressList` where each element corresponds to an entry in `addrinfo`, with the correct IP address and port.

* **`Deduplicate` Input:** An `AddressList` with duplicate `IPEndPoint` entries.
* **`Deduplicate` Output:** An `AddressList` containing only the unique `IPEndPoint` entries, maintaining the order of the first occurrence.

**6. Identifying Common Usage Errors (Especially for Developers)**

Consider how a developer might misuse the `AddressList` class or related networking APIs:

* **Incorrect `addrinfo` Construction:**  Manually creating `addrinfo` structures is error-prone. Developers might get the sizes or pointers wrong.
* **Assuming Order After Deduplication (Without Understanding the Guarantee):** If a developer relies on a specific order after deduplication *without knowing* that the order of first occurrence is preserved, they might encounter unexpected behavior if the input order changes.
* **Not Handling Empty `AddressList`:** If code expects a non-empty `AddressList` and doesn't handle the case where DNS resolution fails, it could lead to crashes or errors.

**7. Tracing User Operations (Debugging Clues)**

Think about the user actions that trigger network requests:

1. **Typing a URL in the address bar:** This initiates a DNS lookup.
2. **Clicking a link:** Similar to typing a URL.
3. **JavaScript making a network request (`fetch`, `XMLHttpRequest`):** This directly involves the browser's networking stack.
4. **A background process (e.g., sync) making a network request.**

To reach the code being tested (the `AddressList` class), the following sequence of events is likely:

1. The user initiates a network request (e.g., types a URL).
2. The browser's networking code performs a DNS lookup for the hostname.
3. The operating system's DNS resolver returns the results (IP addresses and potentially a canonical name and aliases).
4. The Chromium networking stack converts these results into an `addrinfo` structure (or a similar internal representation).
5. The `AddressList::CreateFromAddrinfo` method is called to create an `AddressList` object from the `addrinfo` data.

**Self-Correction/Refinement During Analysis:**

* **Initial thought:** "This just deals with IP addresses."
* **Correction:** "No, it also handles hostnames (canonical names and aliases) which are important for DNS."

* **Initial thought:** "Deduplication just removes duplicates."
* **Refinement:** "The tests specifically check that the *order* of the first occurrences is preserved, which is a crucial detail."

By following this kind of structured analysis, you can effectively understand the purpose and functionality of a complex C++ file like the one provided. The key is to combine code reading with knowledge of networking concepts and the overall architecture of a web browser.
好的，我们来详细分析一下 `net/base/address_list_unittest.cc` 这个 Chromium 网络栈的源代码文件。

**文件功能概述**

`address_list_unittest.cc` 是一个单元测试文件，用于测试 `net/base/address_list.h` 中定义的 `AddressList` 类的功能。`AddressList` 类在 Chromium 的网络栈中扮演着重要的角色，它用于存储和管理一个主机名解析得到的 IP 地址列表以及相关的 DNS 别名（aliases）。

这个测试文件主要验证了 `AddressList` 类的以下功能：

1. **创建 `AddressList` 对象:**
   - 从 `addrinfo` 结构体创建。 `addrinfo` 是 C 语言中用于存储主机信息的结构体，通常由 `getaddrinfo` 函数返回。
   - 从 `IPAddressList` 对象创建。 `IPAddressList` 是一个存储 `IPAddress` 对象的列表。

2. **管理规范主机名 (Canonical Hostname):**
   - 设置和获取规范主机名。
   - 当没有设置规范主机名时的情况。
   - 设置默认的规范主机名（通常是 IP 地址的字符串表示）。
   - 设置和追加 DNS 别名，并验证规范主机名和别名的组合行为。

3. **管理 DNS 别名 (DNS Aliases):**
   - 设置、获取和追加 DNS 别名。
   - 验证别名的存储和管理是否正确。

4. **去除重复 IP 地址 (Deduplication):**
   - 测试 `Deduplicate()` 方法，该方法用于移除 `AddressList` 中重复的 IP 地址。
   - 验证在不同情况下（空列表、单元素列表、多元素列表）去除重复项的行为。
   - 重点测试去除重复项后，列表中剩余 IP 地址的顺序是否得到保留（按照首次出现的顺序）。

**与 JavaScript 的关系**

`AddressList` 类本身是 C++ 的实现，JavaScript 代码并不能直接操作它。然而，`AddressList` 中管理的信息对于 JavaScript 在浏览器中发起网络请求至关重要。

**举例说明:**

当 JavaScript 代码使用 `fetch` API 或 `XMLHttpRequest` 发起一个网络请求时，例如：

```javascript
fetch('https://www.example.com/data');
```

浏览器内核会执行以下步骤（简化）：

1. **域名解析 (DNS Resolution):**  浏览器会查找 `www.example.com` 的 IP 地址。这通常涉及到操作系统底层的 DNS 解析器。
2. **获取地址列表:**  DNS 解析器返回的 IP 地址列表（以及可能的别名和规范主机名）会被 Chromium 的网络栈接收，并存储在 `AddressList` 对象中。
3. **连接尝试:**  浏览器会尝试连接到 `AddressList` 中的一个或多个 IP 地址。如果连接到一个地址失败，可能会尝试连接列表中的下一个地址。

在这个过程中，`AddressList` 就扮演了存储和管理解析结果的角色。虽然 JavaScript 代码看不到 `AddressList` 对象本身，但它发起的网络请求最终会依赖于 `AddressList` 中存储的 IP 地址信息。

**逻辑推理和假设输入/输出**

**测试 `CreateFromAddrinfo`:**

* **假设输入:** 一个 `addrinfo` 链表，包含两个 IPv4 地址：
    - `192.168.1.1:80`
    - `10.0.0.1:8080`
* **预期输出:** 创建的 `AddressList` 对象应该包含两个 `IPEndPoint` 对象，分别对应于输入的两个 IP 地址和端口。

**测试 `Deduplicate`:**

* **假设输入:** 一个 `AddressList` 对象，包含以下 `IPEndPoint` (为了简化，忽略端口)：
    - `192.168.1.1`
    - `10.0.0.1`
    - `192.168.1.1`
    - `172.16.0.1`
* **预期输出:** 调用 `Deduplicate()` 后，`AddressList` 对象应该包含以下 `IPEndPoint`，并且保持原始顺序：
    - `192.168.1.1`
    - `10.0.0.1`
    - `172.16.0.1`

**用户或编程常见的使用错误**

1. **假设 `AddressList` 中的 IP 地址是有序的（除了去重后）：**  在没有明确排序的情况下，不应该假设 `AddressList` 中的 IP 地址顺序。虽然去重会保留首次出现的顺序，但初始顺序可能受到 DNS 解析器返回结果的影响。

   **示例代码错误 (C++):**

   ```c++
   AddressList addr_list = GetAddressListForHost("example.com");
   // 错误假设：第一个地址总是最优的
   ConnectTo(addr_list[0]);
   ```

   正确的做法是考虑尝试连接列表中的多个地址，或者使用更智能的连接策略。

2. **在多线程环境下不安全地访问或修改 `AddressList`：**  `AddressList` 类本身可能不是线程安全的。如果在多个线程中同时访问或修改同一个 `AddressList` 对象，可能会导致数据竞争和未定义的行为。

3. **错误地假设 `AddressList` 总是包含至少一个 IP 地址：**  DNS 解析可能失败，导致 `AddressList` 为空。代码需要处理这种情况，避免访问空列表的元素。

   **示例代码错误 (C++):**

   ```c++
   AddressList addr_list = GetAddressListForHost("nonexistent.example.com");
   // 如果 GetAddressListForHost 返回空的 AddressList，则会导致越界访问
   ConnectTo(addr_list[0]);
   ```

**用户操作如何一步步到达这里 (调试线索)**

作为一个调试线索，了解用户操作如何最终触发对 `AddressList` 的使用是很重要的。以下是一个可能的步骤：

1. **用户在浏览器地址栏输入 URL 并回车，或者点击了一个链接。**  例如，用户输入 `www.google.com`。
2. **浏览器解析 URL，提取主机名 `www.google.com`。**
3. **浏览器的网络栈发起 DNS 查询，请求解析 `www.google.com` 的 IP 地址。** 操作系统或配置的 DNS 服务器会处理这个请求。
4. **DNS 服务器返回一个或多个 IP 地址，以及可能的规范主机名和别名。**
5. **Chromium 网络栈接收 DNS 解析结果。**
6. **网络栈的代码会使用接收到的信息创建一个 `AddressList` 对象。** 这很可能涉及到调用 `AddressList::CreateFromAddrinfo` 或 `AddressList::CreateFromIPAddressList`。
7. **后续的网络连接模块会使用 `AddressList` 中的 IP 地址尝试建立 TCP 连接。**

如果在调试网络连接问题，并且怀疑是 DNS 解析或地址列表处理的问题，可以按照以下步骤进行：

1. **使用浏览器的开发者工具的网络面板，查看请求的状态和时间线。**  这可以帮助确定 DNS 解析是否成功，以及连接尝试是否失败。
2. **启用 Chromium 的网络日志 (net-internals)。**  在 Chrome 浏览器中访问 `chrome://net-internals/#dns` 可以查看 DNS 查询的结果。访问 `chrome://net-internals/#events` 可以查看更详细的网络事件，包括 `AddressList` 的创建和使用。
3. **如果可以本地构建 Chromium，可以在 `net/base/address_list.cc` 和 `net/base/address_list_unittest.cc` 中添加断点或日志输出。**  特别是关注 `CreateFromAddrinfo` 和 `Deduplicate` 等方法。
4. **检查操作系统的 DNS 设置和缓存。**  错误的 DNS 配置或缓存可能导致解析结果不正确。

总而言之，`address_list_unittest.cc` 通过各种测试用例，确保了 `AddressList` 类能够正确地管理和操作 IP 地址列表和 DNS 别名，这对于 Chromium 网络栈的稳定性和可靠性至关重要。虽然 JavaScript 代码不直接操作这个类，但它的功能是 JavaScript 发起网络请求的基础。

Prompt: 
```
这是目录为net/base/address_list_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/base/address_list.h"

#include <algorithm>

#include "base/strings/string_util.h"
#include "base/sys_byteorder.h"
#include "net/base/ip_address.h"
#include "net/base/sockaddr_storage.h"
#include "net/base/sys_addrinfo.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using ::testing::ElementsAre;
using ::testing::UnorderedElementsAre;

namespace net {
namespace {

const char kCanonicalHostname[] = "canonical.bar.com";

TEST(AddressListTest, Canonical) {
  // Create an addrinfo with a canonical name.
  struct sockaddr_in address;
  // The contents of address do not matter for this test,
  // so just zero-ing them out for consistency.
  memset(&address, 0x0, sizeof(address));
  // But we need to set the family.
  address.sin_family = AF_INET;
  struct addrinfo ai;
  memset(&ai, 0x0, sizeof(ai));
  ai.ai_family = AF_INET;
  ai.ai_socktype = SOCK_STREAM;
  ai.ai_addrlen = sizeof(address);
  ai.ai_addr = reinterpret_cast<sockaddr*>(&address);
  ai.ai_canonname = const_cast<char *>(kCanonicalHostname);

  // Copy the addrinfo struct into an AddressList object and
  // make sure it seems correct.
  AddressList addrlist1 = AddressList::CreateFromAddrinfo(&ai);
  EXPECT_THAT(addrlist1.dns_aliases(),
              UnorderedElementsAre("canonical.bar.com"));

  // Copy the AddressList to another one.
  AddressList addrlist2 = addrlist1;
  EXPECT_THAT(addrlist2.dns_aliases(),
              UnorderedElementsAre("canonical.bar.com"));
}

TEST(AddressListTest, CreateFromAddrinfo) {
  // Create an 4-element addrinfo.
  const unsigned kNumElements = 4;
  SockaddrStorage storage[kNumElements];
  struct addrinfo ai[kNumElements];
  for (unsigned i = 0; i < kNumElements; ++i) {
    struct sockaddr_in* addr =
        reinterpret_cast<struct sockaddr_in*>(storage[i].addr);
    storage[i].addr_len = sizeof(struct sockaddr_in);
    // Populating the address with { i, i, i, i }.
    memset(&addr->sin_addr, i, IPAddress::kIPv4AddressSize);
    addr->sin_family = AF_INET;
    // Set port to i << 2;
    addr->sin_port = base::HostToNet16(static_cast<uint16_t>(i << 2));
    memset(&ai[i], 0x0, sizeof(ai[i]));
    ai[i].ai_family = addr->sin_family;
    ai[i].ai_socktype = SOCK_STREAM;
    ai[i].ai_addrlen = storage[i].addr_len;
    ai[i].ai_addr = storage[i].addr;
    if (i + 1 < kNumElements)
      ai[i].ai_next = &ai[i + 1];
  }

  AddressList list = AddressList::CreateFromAddrinfo(&ai[0]);

  ASSERT_EQ(kNumElements, list.size());
  for (size_t i = 0; i < list.size(); ++i) {
    EXPECT_EQ(ADDRESS_FAMILY_IPV4, list[i].GetFamily());
    // Only check the first byte of the address.
    EXPECT_EQ(i, list[i].address().bytes()[0]);
    EXPECT_EQ(static_cast<int>(i << 2), list[i].port());
  }

  // Check if operator= works.
  AddressList copy;
  copy = list;
  ASSERT_EQ(kNumElements, copy.size());

  // Check if copy is independent.
  copy[1] = IPEndPoint(copy[2].address(), 0xBEEF);
  // Original should be unchanged.
  EXPECT_EQ(1u, list[1].address().bytes()[0]);
  EXPECT_EQ(1 << 2, list[1].port());
}

TEST(AddressListTest, CreateFromIPAddressList) {
  struct TestData {
    std::string ip_address;
    const char* in_addr;
    int ai_family;
    size_t ai_addrlen;
    size_t in_addr_offset;
    size_t in_addr_size;
  } tests[] = {
    { "127.0.0.1",
      "\x7f\x00\x00\x01",
      AF_INET,
      sizeof(struct sockaddr_in),
      offsetof(struct sockaddr_in, sin_addr),
      sizeof(struct in_addr),
    },
    { "2001:db8:0::42",
      "\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x42",
      AF_INET6,
      sizeof(struct sockaddr_in6),
      offsetof(struct sockaddr_in6, sin6_addr),
      sizeof(struct in6_addr),
    },
    { "192.168.1.1",
      "\xc0\xa8\x01\x01",
      AF_INET,
      sizeof(struct sockaddr_in),
      offsetof(struct sockaddr_in, sin_addr),
      sizeof(struct in_addr),
    },
  };
  const std::string kCanonicalName = "canonical.example.com";

  // Construct a list of ip addresses.
  IPAddressList ip_list;
  for (const auto& test : tests) {
    IPAddress ip_address;
    ASSERT_TRUE(ip_address.AssignFromIPLiteral(test.ip_address));
    ip_list.push_back(ip_address);
  }

  // Wrap the canonical name in an alias vector.
  std::vector<std::string> aliases({kCanonicalName});

  AddressList test_list =
      AddressList::CreateFromIPAddressList(ip_list, std::move(aliases));
  std::string canonical_name;
  EXPECT_THAT(test_list.dns_aliases(), UnorderedElementsAre(kCanonicalName));
  EXPECT_EQ(std::size(tests), test_list.size());
}

TEST(AddressListTest, GetCanonicalNameWhenUnset) {
  const IPAddress kAddress(1, 2, 3, 4);
  const IPEndPoint kEndpoint(kAddress, 0);
  AddressList addrlist(kEndpoint);

  EXPECT_TRUE(addrlist.dns_aliases().empty());
}

TEST(AddressListTest, SetDefaultCanonicalNameThenSetDnsAliases) {
  const IPAddress kAddress(1, 2, 3, 4);
  const IPEndPoint kEndpoint(kAddress, 0);
  AddressList addrlist(kEndpoint);

  addrlist.SetDefaultCanonicalName();

  EXPECT_THAT(addrlist.dns_aliases(), UnorderedElementsAre("1.2.3.4"));

  std::vector<std::string> aliases({"alias1", "alias2", "alias3"});
  addrlist.SetDnsAliases(std::move(aliases));

  // Setting the aliases after setting the default canonical name
  // replaces the default canonical name.
  EXPECT_THAT(addrlist.dns_aliases(),
              UnorderedElementsAre("alias1", "alias2", "alias3"));
}

TEST(AddressListTest, SetDefaultCanonicalNameThenAppendDnsAliases) {
  const IPAddress kAddress(1, 2, 3, 4);
  const IPEndPoint kEndpoint(kAddress, 0);
  AddressList addrlist(kEndpoint);

  addrlist.SetDefaultCanonicalName();

  EXPECT_THAT(addrlist.dns_aliases(), UnorderedElementsAre("1.2.3.4"));

  std::vector<std::string> aliases({"alias1", "alias2", "alias3"});
  addrlist.AppendDnsAliases(std::move(aliases));

  // Appending the aliases after setting the default canonical name
  // does not replace the default canonical name.
  EXPECT_THAT(addrlist.dns_aliases(),
              UnorderedElementsAre("1.2.3.4", "alias1", "alias2", "alias3"));
}

TEST(AddressListTest, DnsAliases) {
  const IPAddress kAddress(1, 2, 3, 4);
  const IPEndPoint kEndpoint(kAddress, 0);
  std::vector<std::string> aliases({"alias1", "alias2", "alias3"});
  AddressList addrlist(kEndpoint, std::move(aliases));

  EXPECT_THAT(addrlist.dns_aliases(),
              UnorderedElementsAre("alias1", "alias2", "alias3"));

  std::vector<std::string> more_aliases({"alias4", "alias5", "alias6"});
  addrlist.AppendDnsAliases(std::move(more_aliases));

  EXPECT_THAT(addrlist.dns_aliases(),
              UnorderedElementsAre("alias1", "alias2", "alias3", "alias4",
                                   "alias5", "alias6"));

  std::vector<std::string> new_aliases({"alias7", "alias8", "alias9"});
  addrlist.SetDnsAliases(std::move(new_aliases));

  EXPECT_THAT(addrlist.dns_aliases(),
              UnorderedElementsAre("alias7", "alias8", "alias9"));
}

TEST(AddressListTest, DeduplicatesEmptyAddressList) {
  AddressList empty;
  empty.Deduplicate();
  EXPECT_EQ(empty.size(), 0u);
}

TEST(AddressListTest, DeduplicatesSingletonAddressList) {
  AddressList singleton;
  singleton.push_back(IPEndPoint());
  singleton.Deduplicate();
  EXPECT_THAT(singleton.endpoints(), ElementsAre(IPEndPoint()));
}

TEST(AddressListTest, DeduplicatesLongerAddressList) {
  AddressList several;
  several.endpoints() = {IPEndPoint(IPAddress(0, 0, 0, 1), 0),
                         IPEndPoint(IPAddress(0, 0, 0, 2), 0),
                         IPEndPoint(IPAddress(0, 0, 0, 2), 0),
                         IPEndPoint(IPAddress(0, 0, 0, 3), 0),
                         IPEndPoint(IPAddress(0, 0, 0, 2), 0),
                         IPEndPoint(IPAddress(0, 0, 0, 1), 0),
                         IPEndPoint(IPAddress(0, 0, 0, 2), 0),
                         IPEndPoint(IPAddress(0, 0, 0, 3), 0),
                         IPEndPoint(IPAddress(0, 0, 0, 2), 0)};
  several.Deduplicate();

  // Deduplication should preserve the order of the first instances
  // of the unique addresses.
  EXPECT_THAT(several.endpoints(),
              ElementsAre(IPEndPoint(IPAddress(0, 0, 0, 1), 0),
                          IPEndPoint(IPAddress(0, 0, 0, 2), 0),
                          IPEndPoint(IPAddress(0, 0, 0, 3), 0)));
}

// Test that, for every permutation of a list of endpoints, deduplication
// produces the same results as a naive reference implementation.
TEST(AddressListTest, DeduplicatePreservesOrder) {
  std::vector<IPEndPoint> permutation = {IPEndPoint(IPAddress(0, 0, 0, 1), 0),
                                         IPEndPoint(IPAddress(0, 0, 0, 1), 0),
                                         IPEndPoint(IPAddress(0, 0, 0, 2), 0),
                                         IPEndPoint(IPAddress(0, 0, 0, 2), 0),
                                         IPEndPoint(IPAddress(0, 0, 0, 3), 0)};
  ASSERT_TRUE(std::is_sorted(permutation.begin(), permutation.end()));

  do {
    std::vector<IPEndPoint> expected;
    std::set<IPEndPoint> set;
    for (const IPEndPoint& endpoint : permutation) {
      if (set.insert(endpoint).second)
        expected.push_back(endpoint);
    }
    EXPECT_EQ(expected.size(), 3u);

    AddressList address_list;
    address_list.endpoints() = permutation;
    address_list.Deduplicate();
    EXPECT_EQ(address_list.endpoints(), expected);
  } while (std::next_permutation(permutation.begin(), permutation.end()));
}

}  // namespace
}  // namespace net

"""

```