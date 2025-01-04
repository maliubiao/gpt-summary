Response:
Let's break down the thought process for analyzing this C++ unit test file.

**1. Initial Understanding - The Big Picture:**

* **File Path:** `net/base/network_interfaces_win_unittest.cc` immediately tells me this is a unit test file for something related to network interfaces on Windows within the Chromium project. The `_unittest.cc` suffix is a strong convention.
* **Copyright & License:** Standard Chromium copyright and BSD license notice, confirming it's part of the open-source project.
* **Includes:** These are crucial. They reveal the dependencies and what the code interacts with:
    * `<objbase.h>` and `<iphlpapi.h>`:  Windows-specific headers for COM (Component Object Model) and IP Helper API. This reinforces the Windows focus. `iphlpapi.h` is a key indicator that network interface information is being retrieved directly from the operating system.
    * Standard C++ headers (`<ostream>`, `<string>`, `<unordered_set>`).
    * Chromium base libraries (`base/logging.h`, `base/strings/utf_string_conversions.h`).
    * `build/build_config.h`:  Indicates platform-specific compilation logic might be involved.
    * `net/base/ip_endpoint.h`:  Deals with IP addresses and ports.
    * `testing/gtest/include/gtest/gtest.h`:  Confirms this is a Google Test-based unit test.
    * The header being tested:  `net/base/network_interfaces_win.h` (implicitly included through the `.cc` file).

* **Namespace:**  `namespace net { namespace { ... } }` is standard C++ practice for organizing code and limiting scope.

**2. Analyzing the Test Cases (Functions starting with `TEST`):**

* **`NetworkListTrimmingWindows`:** This name strongly suggests testing the logic for filtering or excluding certain network interfaces from a list. Looking at the code inside:
    * It creates `IP_ADAPTER_ADDRESSES` structures, which are Windows API structures for representing network adapter information.
    * It uses a helper function `FillAdapterAddress` to populate these structures with test data.
    * It calls `internal::GetNetworkListImpl`. The `internal::` namespace suggests this is an implementation detail of the `network_interfaces_win.h` code.
    * It makes assertions (`EXPECT_EQ`, `ASSERT_TRUE`) about the size and content of the `NetworkInterfaceList` after calling `GetNetworkListImpl`.
    * The tests cover scenarios like: offline interfaces, loopback interfaces, VMware interfaces (and the ability to exclude them), incomplete DAD (Duplicate Address Detection), and interface attributes like "temporary" and "deprecated".

* **`NetworkListExtractMacAddress`:**  Clearly focuses on verifying the extraction of MAC addresses. It sets up an `IP_ADAPTER_ADDRESSES` structure and checks if the extracted MAC address matches the expected value.

* **`NetworkListExtractMacAddressInvalidLength`:** Tests the case where the MAC address length in the Windows API data is invalid (not EUI-48), confirming that the MAC address is not extracted in such cases.

* **`MAYBE_SetWifiOptions` (and related functions):** This section is different. It interacts with Wi-Fi specific settings.
    * `GetWifiOptions`:  Seems to query current Wi-Fi adapter options using the Windows WLAN API.
    * `TryChangeWifiOptions`: A helper to test setting and resetting Wi-Fi options.
    * `SetWifiOptions`:  The function being tested (likely in `network_interfaces_win.h`). It's wrapped in a `ScopedWifiOptions`, suggesting RAII (Resource Acquisition Is Initialization) for managing changes.
    * The `MAYBE_` prefix and the `#if` block point to a test that might be flaky or have issues on specific platforms (Win ARM64 in this case).

**3. Identifying Key Functionality:**

Based on the test cases, the main functionality of `network_interfaces_win.cc` (or at least the parts being tested) includes:

* **Retrieving Network Interface Information:** Using Windows API functions like those related to `IP_ADAPTER_ADDRESSES`.
* **Filtering Network Interfaces:**  Based on criteria like operational status, interface type (loopback), and potentially user-defined policies (excluding virtual interfaces).
* **Extracting Network Interface Details:**  IP addresses, interface names, MAC addresses, prefix lengths, and interface attributes.
* **Managing Wi-Fi Adapter Options:**  Specifically, disabling background scans and enabling media streaming mode.

**4. Relating to JavaScript (if applicable):**

* **No direct JavaScript code:** This is a C++ file within the Chromium codebase. It doesn't directly contain JavaScript.
* **Indirect relationship through the browser:**  Chromium's network stack (where this code resides) is responsible for handling network requests made by the browser, including those initiated by JavaScript code.
* **Example:** If a web page running JavaScript uses `navigator.connection` to get network information, the underlying implementation on Windows would involve code like this to retrieve the interface details. Or if JavaScript uses WebSockets, the connection setup and management rely on the network stack.

**5. Logic Inference, Assumptions, and Errors:**

* The tests make assumptions about how the Windows API behaves and the structure of the data it returns.
* Common user errors could involve misconfiguring network settings in the operating system, which would be reflected in the data this code retrieves. For example, a user might disable a network adapter, which would cause it to be filtered out by the `NetworkListTrimmingWindows` tests.

**6. Debugging Clues:**

* The test cases themselves serve as debugging clues. If a test fails, it indicates a problem in the corresponding logic within `network_interfaces_win.cc`.
* The `LOG(FATAL)` in `read_int_or_bool` indicates a serious, unexpected error if the data size is not 1 or 4 bytes. This could happen if the Windows API returns malformed data.

**Self-Correction/Refinement during the Process:**

* Initially, I might just see a bunch of C++ code. But by focusing on the `TEST` macros and the function names, the purpose becomes much clearer.
* Recognizing the Windows API structures (`IP_ADAPTER_ADDRESSES`) is key to understanding the data source.
* The `internal::` namespace is a clue to distinguish between public interface and implementation details.
* The Wi-Fi option tests are a bit of a detour, highlighting another related but distinct piece of functionality within the same file.

By following this systematic approach, breaking down the code into smaller parts, and leveraging the information provided by the test structure and included headers, it's possible to gain a comprehensive understanding of the functionality of this unit test file.
这个文件 `net/base/network_interfaces_win_unittest.cc` 是 Chromium 项目中网络栈的一部分，专门用于测试 Windows 平台上获取和处理网络接口信息的代码。它针对的是 `net/base/network_interfaces_win.h` 中定义的与 Windows 系统相关的网络接口功能。

以下是该文件的功能列表：

1. **测试网络接口列表的修剪逻辑 (Network List Trimming):**  验证在获取网络接口列表时，代码是否正确地排除了某些不应包含的接口。例如：
    * **离线的接口 (Offline Links):**  测试当网络接口处于断开状态时，是否会被排除在结果列表之外。
    * **环回接口 (Loopback Interfaces):** 测试本地环回接口是否被正确排除。
    * **虚拟机接口 (Virtual Machine Interfaces):** 测试是否能够根据策略包含或排除虚拟机创建的网络接口（例如 VMware 的接口）。
    * **不完整的 DAD 状态的地址 (Incomplete DAD):** 测试处于“尝试中” (Tentative) 的重复地址检测 (DAD) 状态的 IP 地址是否会被忽略。
    * **特定的 IP 地址属性:** 测试具有特定属性（如临时地址、废弃地址）的 IP 地址是否被正确处理。

2. **测试 MAC 地址的提取 (MAC Address Extraction):** 验证代码是否能正确地从网络接口信息中提取 MAC 地址。
    * **有效长度的 MAC 地址:** 测试当物理地址长度为标准的 6 字节 (EUI-48) 时，MAC 地址能否被正确提取。
    * **无效长度的 MAC 地址:** 测试当物理地址长度不是 6 字节时，MAC 地址是否会被忽略。

3. **测试 Wi-Fi 选项的设置和获取 (Set and Get Wi-Fi Options):**  测试与 Wi-Fi 适配器相关的设置功能。
    * **获取 Wi-Fi 选项:** 测试代码能否正确获取 Wi-Fi 适配器的当前选项，例如是否禁用了后台扫描，是否启用了媒体流模式。
    * **设置 Wi-Fi 选项:** 测试代码能否正确地设置 Wi-Fi 适配器的选项，并通过 `ScopedWifiOptions` 确保设置在测试后能够恢复。

**与 Javascript 的关系:**

虽然这个 C++ 文件本身不包含 Javascript 代码，但它测试的网络功能是 Web 浏览器与网络交互的基础。当 Javascript 代码通过浏览器进行网络请求时，底层的 Chromium 网络栈（包括这里测试的代码）负责处理这些请求。

**举例说明:**

假设一个网页中的 Javascript 代码想要获取用户的网络连接信息，它可能会使用 `navigator.connection` API。在 Windows 平台上，Chromium 浏览器会调用 `net/base/network_interfaces_win.h` 中定义的函数来获取网络接口列表。而 `net/base/network_interfaces_win_unittest.cc` 中测试的逻辑就保证了这些函数能够正确地返回过滤后的、包含正确信息的网络接口列表，例如排除了本地环回地址，并正确提取了 MAC 地址。

例如，Javascript 可以通过以下方式获取 IP 地址信息（简化示例）：

```javascript
navigator.connection.getNetworkInterfaces()
  .then(interfaces => {
    interfaces.forEach(iface => {
      console.log(`Interface Name: ${iface.name}`);
      iface.addressList.forEach(addr => {
        console.log(`  IP Address: ${addr.address}`);
      });
    });
  });
```

当这段 Javascript 代码在 Windows 上的 Chrome 浏览器中执行时，`net/base/network_interfaces_win.cc` 中的代码（受到 `network_interfaces_win_unittest.cc` 的测试）会负责获取底层的网络接口信息，并将其转换为 Javascript 可以理解的数据结构。

**逻辑推理，假设输入与输出:**

**测试场景：`NetworkListTrimmingWindows` - 测试排除离线接口**

* **假设输入 (模拟 Windows API 返回的数据):**
    * 一个 `IP_ADAPTER_ADDRESSES` 结构体，其 `OperStatus` 字段设置为 `IfOperStatusDown`，表示接口已断开。
    * 其他字段包含有效的接口信息，例如接口名称 "em1" 和一个 IPv6 地址。

* **预期输出 (测试断言):**
    * 调用 `internal::GetNetworkListImpl` 后，返回的 `NetworkInterfaceList` 应该是空的 (`results.size() == 0`)。

**测试场景：`NetworkListExtractMacAddress` - 测试提取有效 MAC 地址**

* **假设输入 (模拟 Windows API 返回的数据):**
    * 一个 `IP_ADAPTER_ADDRESSES` 结构体，其 `PhysicalAddressLength` 字段设置为 6。
    * `PhysicalAddress` 数组包含 6 个字节的 MAC 地址数据：`{0x6, 0x5, 0x4, 0x3, 0x2, 0x1}`。

* **预期输出 (测试断言):**
    * 调用 `internal::GetNetworkListImpl` 后，返回的 `NetworkInterfaceList` 中包含一个元素。
    * 该元素的 `mac_address` 字段的值应该是一个包含 `{0x6, 0x5, 0x4, 0x3, 0x2, 0x1}` 的 `Eui48MacAddress` 对象。

**用户或编程常见的使用错误:**

1. **假设网络接口总是存在:** 开发者可能会在没有检查网络接口是否存在的情况下就尝试获取其信息，导致程序崩溃或产生未定义的行为。这个测试文件确保了当没有有效的网络接口时，代码能够正确处理。

2. **错误地处理虚拟接口:** 用户可能不希望在某些操作中包含虚拟机创建的虚拟网络接口。如果代码没有提供排除这些接口的机制，可能会导致意外的结果。`NetworkListTrimmingWindows` 测试了这种排除逻辑。

3. **假设 MAC 地址总是有效且为 EUI-48 格式:** 开发者可能会假设所有网络接口都有一个 6 字节的 MAC 地址。但实际上，某些虚拟接口或特殊类型的接口可能没有有效的 MAC 地址或具有不同的长度。`NetworkListExtractMacAddressInvalidLength` 测试了这种情况。

4. **不正确地管理 Wi-Fi 适配器选项:**  错误地设置 Wi-Fi 适配器选项可能会影响设备的网络连接和性能。`MAYBE_SetWifiOptions` 测试了设置和恢复 Wi-Fi 选项的功能，确保这些操作是可控的。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设用户在使用 Chrome 浏览器时遇到了与网络连接相关的问题，例如无法连接到特定的网站，或者网络速度异常。作为开发者，在调试时可能会追踪以下步骤，最终可能涉及到 `network_interfaces_win_unittest.cc` 中测试的代码：

1. **用户报告网络问题:** 用户反馈无法访问某个网站或网络速度慢。

2. **浏览器网络栈分析:** 开发者开始分析 Chrome 浏览器的网络栈，查看请求是否发送成功，DNS 解析是否正常，TCP 连接是否建立等。

3. **网络接口信息获取:** 在某些情况下，问题可能与本地网络接口的配置有关。例如，浏览器可能需要获取本地的 IP 地址、MAC 地址或网络接口的状态。

4. **调用 `GetNetworkList` 或相关函数:** Chrome 浏览器会调用 `net/base/network_interfaces_win.h` 中定义的 `GetNetworkList` 或其他相关函数来获取 Windows 系统上的网络接口信息。

5. **执行 `net/base/network_interfaces_win.cc` 中的代码:** 这些函数的实现在 `net/base/network_interfaces_win.cc` 中，它们会调用 Windows API (如 `GetAdaptersAddresses`) 来获取原始的网络接口数据。

6. **数据处理和过滤:** 获取到的原始数据会被进行处理和过滤，例如排除断开的接口、环回接口等，这部分逻辑正是 `network_interfaces_win_unittest.cc` 中 `NetworkListTrimmingWindows` 测试的内容。

7. **MAC 地址提取:** 如果需要获取 MAC 地址，则会执行提取 MAC 地址的逻辑，这部分是 `NetworkListExtractMacAddress` 测试的内容。

8. **Wi-Fi 选项检查:** 如果问题可能与 Wi-Fi 连接有关，可能会涉及到检查或修改 Wi-Fi 适配器的选项，这部分与 `MAYBE_SetWifiOptions` 测试相关。

**调试线索:**

* **如果用户报告某些网络接口没有被识别到:** 可以查看 `NetworkListTrimmingWindows` 的测试用例，确认是否有相关的过滤逻辑导致了该接口被排除。
* **如果涉及到 MAC 地址的问题 (例如，用于设备识别):** 可以查看 `NetworkListExtractMacAddress` 的测试用例，确认 MAC 地址是否被正确提取，以及是否正确处理了无效的 MAC 地址长度。
* **如果用户在使用 Wi-Fi 连接时遇到问题:** 可以查看 `MAYBE_SetWifiOptions` 的测试用例，了解 Wi-Fi 选项的设置和获取是否正常。

因此，`network_interfaces_win_unittest.cc` 中的测试用例可以作为调试的起点，帮助开发者理解在 Windows 平台上获取网络接口信息的过程中可能出现的问题，并验证相关的代码是否按预期工作。

Prompt: 
```
这是目录为net/base/network_interfaces_win_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/base/network_interfaces_win.h"

#include <objbase.h>

#include <iphlpapi.h>

#include <ostream>
#include <string>
#include <unordered_set>

#include "base/logging.h"
#include "base/strings/utf_string_conversions.h"
#include "build/build_config.h"
#include "net/base/ip_endpoint.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

static const char kIfnameEm1[] = "em1";
static const char kIfnameVmnet[] = "VMnet";

static const unsigned char kIPv6LocalAddr[] = {0, 0, 0, 0, 0, 0, 0, 0,
                                               0, 0, 0, 0, 0, 0, 0, 1};

static const unsigned char kIPv6Addr[] = {0x24, 0x01, 0xfa, 0x00, 0x00, 0x04,
                                          0x10, 0x00, 0xbe, 0x30, 0x5b, 0xff,
                                          0xfe, 0xe5, 0x00, 0xc3};
static const unsigned char kIPv6AddrPrefix[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

// Helper function to create a valid IP_ADAPTER_ADDRESSES with reasonable
// default value. The output is the |adapter_address|. All the rests are input
// to fill the |adapter_address|. |sock_addrs| are temporary storage used by
// |adapter_address| once the function is returned.
bool FillAdapterAddress(IP_ADAPTER_ADDRESSES* adapter_address,
                        const char* ifname,
                        const IPAddress& ip_address,
                        const IPAddress& ip_netmask,
                        sockaddr_storage sock_addrs[2]) {
  adapter_address->AdapterName = const_cast<char*>(ifname);
  adapter_address->FriendlyName = const_cast<PWCHAR>(L"interface");
  adapter_address->IfType = IF_TYPE_ETHERNET_CSMACD;
  adapter_address->OperStatus = IfOperStatusUp;
  adapter_address->FirstUnicastAddress->DadState = IpDadStatePreferred;
  adapter_address->FirstUnicastAddress->PrefixOrigin = IpPrefixOriginOther;
  adapter_address->FirstUnicastAddress->SuffixOrigin = IpSuffixOriginOther;
  adapter_address->FirstUnicastAddress->PreferredLifetime = 100;
  adapter_address->FirstUnicastAddress->ValidLifetime = 1000;

  DCHECK(sizeof(adapter_address->PhysicalAddress) > 5);
  // Generate 06:05:04:03:02:01
  adapter_address->PhysicalAddressLength = 6;
  for (unsigned long i = 0; i < adapter_address->PhysicalAddressLength; i++) {
    adapter_address->PhysicalAddress[i] =
        adapter_address->PhysicalAddressLength - i;
  }

  socklen_t sock_len = sizeof(sockaddr_storage);

  // Convert to sockaddr for next check.
  if (!IPEndPoint(ip_address, 0)
           .ToSockAddr(reinterpret_cast<sockaddr*>(&sock_addrs[0]),
                       &sock_len)) {
    return false;
  }
  adapter_address->FirstUnicastAddress->Address.lpSockaddr =
      reinterpret_cast<sockaddr*>(&sock_addrs[0]);
  adapter_address->FirstUnicastAddress->Address.iSockaddrLength = sock_len;
  adapter_address->FirstUnicastAddress->OnLinkPrefixLength = 1;

  sock_len = sizeof(sockaddr_storage);
  if (!IPEndPoint(ip_netmask, 0)
           .ToSockAddr(reinterpret_cast<sockaddr*>(&sock_addrs[1]),
                       &sock_len)) {
    return false;
  }
  adapter_address->FirstPrefix->Address.lpSockaddr =
      reinterpret_cast<sockaddr*>(&sock_addrs[1]);
  adapter_address->FirstPrefix->Address.iSockaddrLength = sock_len;
  adapter_address->FirstPrefix->PrefixLength = 1;

  DCHECK_EQ(sock_addrs[0].ss_family, sock_addrs[1].ss_family);
  if (sock_addrs[0].ss_family == AF_INET6) {
    adapter_address->Ipv6IfIndex = 0;
  } else {
    DCHECK_EQ(sock_addrs[0].ss_family, AF_INET);
    adapter_address->IfIndex = 0;
  }

  return true;
}

TEST(NetworkInterfacesTest, NetworkListTrimmingWindows) {
  IPAddress ipv6_local_address(kIPv6LocalAddr);
  IPAddress ipv6_address(kIPv6Addr);
  IPAddress ipv6_prefix(kIPv6AddrPrefix);

  NetworkInterfaceList results;
  sockaddr_storage addresses[2];
  IP_ADAPTER_ADDRESSES adapter_address = {};
  IP_ADAPTER_UNICAST_ADDRESS address = {};
  IP_ADAPTER_PREFIX adapter_prefix = {};
  adapter_address.FirstUnicastAddress = &address;
  adapter_address.FirstPrefix = &adapter_prefix;

  // Address of offline links should be ignored.
  ASSERT_TRUE(FillAdapterAddress(&adapter_address, kIfnameEm1, ipv6_address,
                                 ipv6_prefix, addresses));
  adapter_address.OperStatus = IfOperStatusDown;

  EXPECT_TRUE(internal::GetNetworkListImpl(
      &results, INCLUDE_HOST_SCOPE_VIRTUAL_INTERFACES, &adapter_address));

  EXPECT_EQ(results.size(), 0ul);

  // Address on loopback interface should be trimmed out.
  ASSERT_TRUE(FillAdapterAddress(
      &adapter_address /* adapter_address */, kIfnameEm1 /* ifname */,
      ipv6_local_address /* ip_address */, ipv6_prefix /* ip_netmask */,
      addresses /* sock_addrs */));
  adapter_address.IfType = IF_TYPE_SOFTWARE_LOOPBACK;

  EXPECT_TRUE(internal::GetNetworkListImpl(
      &results, INCLUDE_HOST_SCOPE_VIRTUAL_INTERFACES, &adapter_address));
  EXPECT_EQ(results.size(), 0ul);

  // vmware address should return by default.
  ASSERT_TRUE(FillAdapterAddress(&adapter_address, kIfnameVmnet, ipv6_address,
                                 ipv6_prefix, addresses));
  EXPECT_TRUE(internal::GetNetworkListImpl(
      &results, INCLUDE_HOST_SCOPE_VIRTUAL_INTERFACES, &adapter_address));
  EXPECT_EQ(results.size(), 1ul);
  EXPECT_EQ(results[0].name, kIfnameVmnet);
  EXPECT_EQ(results[0].prefix_length, 1ul);
  EXPECT_EQ(results[0].address, ipv6_address);
  EXPECT_EQ(results[0].ip_address_attributes, IP_ADDRESS_ATTRIBUTE_NONE);
  results.clear();

  // vmware address should be trimmed out if policy specified so.
  ASSERT_TRUE(FillAdapterAddress(&adapter_address, kIfnameVmnet, ipv6_address,
                                 ipv6_prefix, addresses));
  EXPECT_TRUE(internal::GetNetworkListImpl(
      &results, EXCLUDE_HOST_SCOPE_VIRTUAL_INTERFACES, &adapter_address));
  EXPECT_EQ(results.size(), 0ul);
  results.clear();

  // Addresses with incomplete DAD should be ignored.
  ASSERT_TRUE(FillAdapterAddress(&adapter_address, kIfnameEm1, ipv6_address,
                                 ipv6_prefix, addresses));
  adapter_address.FirstUnicastAddress->DadState = IpDadStateTentative;

  EXPECT_TRUE(internal::GetNetworkListImpl(
      &results, INCLUDE_HOST_SCOPE_VIRTUAL_INTERFACES, &adapter_address));
  EXPECT_EQ(results.size(), 0ul);
  results.clear();

  // Addresses with allowed attribute IpSuffixOriginRandom should be returned
  // and attributes should be translated correctly to
  // IP_ADDRESS_ATTRIBUTE_TEMPORARY.
  ASSERT_TRUE(FillAdapterAddress(&adapter_address, kIfnameEm1, ipv6_address,
                                 ipv6_prefix, addresses));
  adapter_address.FirstUnicastAddress->PrefixOrigin =
      IpPrefixOriginRouterAdvertisement;
  adapter_address.FirstUnicastAddress->SuffixOrigin = IpSuffixOriginRandom;

  EXPECT_TRUE(internal::GetNetworkListImpl(
      &results, INCLUDE_HOST_SCOPE_VIRTUAL_INTERFACES, &adapter_address));
  EXPECT_EQ(results.size(), 1ul);
  EXPECT_EQ(results[0].name, kIfnameEm1);
  EXPECT_EQ(results[0].prefix_length, 1ul);
  EXPECT_EQ(results[0].address, ipv6_address);
  EXPECT_EQ(results[0].ip_address_attributes, IP_ADDRESS_ATTRIBUTE_TEMPORARY);
  results.clear();

  // Addresses with preferred lifetime 0 should be returned and
  // attributes should be translated correctly to
  // IP_ADDRESS_ATTRIBUTE_DEPRECATED.
  ASSERT_TRUE(FillAdapterAddress(&adapter_address, kIfnameEm1, ipv6_address,
                                 ipv6_prefix, addresses));
  adapter_address.FirstUnicastAddress->PreferredLifetime = 0;
  adapter_address.FriendlyName = const_cast<PWCHAR>(L"FriendlyInterfaceName");
  EXPECT_TRUE(internal::GetNetworkListImpl(
      &results, INCLUDE_HOST_SCOPE_VIRTUAL_INTERFACES, &adapter_address));
  EXPECT_EQ(results.size(), 1ul);
  EXPECT_EQ(results[0].friendly_name, "FriendlyInterfaceName");
  EXPECT_EQ(results[0].name, kIfnameEm1);
  EXPECT_EQ(results[0].prefix_length, 1ul);
  EXPECT_EQ(results[0].address, ipv6_address);
  EXPECT_EQ(results[0].ip_address_attributes, IP_ADDRESS_ATTRIBUTE_DEPRECATED);
  results.clear();
}

TEST(NetworkInterfacesTest, NetworkListExtractMacAddress) {
  IPAddress ipv6_local_address(kIPv6LocalAddr);
  IPAddress ipv6_address(kIPv6Addr);
  IPAddress ipv6_prefix(kIPv6AddrPrefix);

  NetworkInterfaceList results;
  sockaddr_storage addresses[2];
  IP_ADAPTER_ADDRESSES adapter_address = {};
  IP_ADAPTER_UNICAST_ADDRESS address = {};
  IP_ADAPTER_PREFIX adapter_prefix = {};
  adapter_address.FirstUnicastAddress = &address;
  adapter_address.FirstPrefix = &adapter_prefix;

  ASSERT_TRUE(FillAdapterAddress(&adapter_address, kIfnameEm1, ipv6_address,
                                 ipv6_prefix, addresses));

  Eui48MacAddress expected_mac_address = {0x6, 0x5, 0x4, 0x3, 0x2, 0x1};

  EXPECT_TRUE(internal::GetNetworkListImpl(
      &results, INCLUDE_HOST_SCOPE_VIRTUAL_INTERFACES, &adapter_address));
  ASSERT_EQ(results.size(), 1ul);
  ASSERT_EQ(results[0].mac_address, expected_mac_address);
}

TEST(NetworkInterfacesTest, NetworkListExtractMacAddressInvalidLength) {
  IPAddress ipv6_local_address(kIPv6LocalAddr);
  IPAddress ipv6_address(kIPv6Addr);
  IPAddress ipv6_prefix(kIPv6AddrPrefix);

  NetworkInterfaceList results;
  sockaddr_storage addresses[2];
  IP_ADAPTER_ADDRESSES adapter_address = {};
  IP_ADAPTER_UNICAST_ADDRESS address = {};
  IP_ADAPTER_PREFIX adapter_prefix = {};
  adapter_address.FirstUnicastAddress = &address;
  adapter_address.FirstPrefix = &adapter_prefix;

  ASSERT_TRUE(FillAdapterAddress(&adapter_address, kIfnameEm1, ipv6_address,
                                 ipv6_prefix, addresses));
  // Not EUI-48 Mac address, so it is not extracted.
  adapter_address.PhysicalAddressLength = 8;

  EXPECT_TRUE(internal::GetNetworkListImpl(
      &results, INCLUDE_HOST_SCOPE_VIRTUAL_INTERFACES, &adapter_address));
  ASSERT_EQ(results.size(), 1ul);
  EXPECT_FALSE(results[0].mac_address.has_value());
}

bool read_int_or_bool(DWORD data_size, PVOID data) {
  switch (data_size) {
    case 1:
      return !!*reinterpret_cast<uint8_t*>(data);
    case 4:
      return !!*reinterpret_cast<uint32_t*>(data);
    default:
      LOG(FATAL) << "That is not a type I know!";
  }
}

int GetWifiOptions() {
  const internal::WlanApi& wlanapi = internal::WlanApi::GetInstance();
  if (!wlanapi.initialized)
    return -1;

  internal::WlanHandle client;
  DWORD cur_version = 0;
  const DWORD kMaxClientVersion = 2;
  DWORD result = wlanapi.OpenHandle(kMaxClientVersion, &cur_version, &client);
  if (result != ERROR_SUCCESS)
    return -1;

  WLAN_INTERFACE_INFO_LIST* interface_list_ptr = nullptr;
  result =
      wlanapi.enum_interfaces_func(client.Get(), nullptr, &interface_list_ptr);
  if (result != ERROR_SUCCESS)
    return -1;
  std::unique_ptr<WLAN_INTERFACE_INFO_LIST, internal::WlanApiDeleter>
      interface_list(interface_list_ptr);

  for (unsigned i = 0; i < interface_list->dwNumberOfItems; ++i) {
    WLAN_INTERFACE_INFO* info = &interface_list->InterfaceInfo[i];
    DWORD data_size;
    PVOID data;
    int options = 0;
    result =
        wlanapi.query_interface_func(client.Get(), &info->InterfaceGuid,
                                     wlan_intf_opcode_background_scan_enabled,
                                     nullptr, &data_size, &data, nullptr);
    if (result != ERROR_SUCCESS)
      continue;
    if (!read_int_or_bool(data_size, data)) {
      options |= WIFI_OPTIONS_DISABLE_SCAN;
    }
    internal::WlanApi::GetInstance().free_memory_func(data);

    result = wlanapi.query_interface_func(client.Get(), &info->InterfaceGuid,
                                          wlan_intf_opcode_media_streaming_mode,
                                          nullptr, &data_size, &data, nullptr);
    if (result != ERROR_SUCCESS)
      continue;
    if (read_int_or_bool(data_size, data)) {
      options |= WIFI_OPTIONS_MEDIA_STREAMING_MODE;
    }
    internal::WlanApi::GetInstance().free_memory_func(data);

    // Just the the options from the first succesful
    // interface.
    return options;
  }

  // No wifi interface found.
  return -1;
}

void TryChangeWifiOptions(int options) {
  int previous_options = GetWifiOptions();
  std::unique_ptr<ScopedWifiOptions> scoped_options = SetWifiOptions(options);
  EXPECT_EQ(previous_options | options, GetWifiOptions());
  scoped_options.reset();
  EXPECT_EQ(previous_options, GetWifiOptions());
}

// Test fails on Win Arm64 bots. TODO(crbug.com/40260910): Fix on bot.
#if BUILDFLAG(IS_WIN) && defined(ARCH_CPU_ARM64)
#define MAYBE_SetWifiOptions DISABLED_SetWifiOptions
#else
#define MAYBE_SetWifiOptions SetWifiOptions
#endif
// Test SetWifiOptions().
TEST(NetworkInterfacesTest, MAYBE_SetWifiOptions) {
  TryChangeWifiOptions(0);
  TryChangeWifiOptions(WIFI_OPTIONS_DISABLE_SCAN);
  TryChangeWifiOptions(WIFI_OPTIONS_MEDIA_STREAMING_MODE);
  TryChangeWifiOptions(WIFI_OPTIONS_DISABLE_SCAN |
                       WIFI_OPTIONS_MEDIA_STREAMING_MODE);
}

}  // namespace

}  // namespace net

"""

```