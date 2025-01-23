Response:
Let's break down the thought process for analyzing this C++ code and addressing the user's request.

**1. Understanding the Core Functionality:**

The first step is to read the code and identify its primary purpose. The filename `network_interfaces_getifaddrs.cc` and the presence of `#include <ifaddrs.h>` strongly suggest it's related to retrieving network interface information using the `getifaddrs()` system call.

Skimming through the code confirms this. The main function seems to be `GetNetworkList`, which calls `getifaddrs`, iterates through the results, and populates a `NetworkInterfaceList`. The `IfaddrsToNetworkInterfaceList` function is the core processing loop.

**2. Identifying Platform-Specific Logic:**

The `#if BUILDFLAG(...)` preprocessor directives are crucial. They indicate platform-specific implementations. We see special handling for:

* **macOS (`IS_MAC`):**  The `IPAttributesGetterMac` class uses `ioctl` to get more detailed IP address attributes and network interface types.
* **Android (`IS_ANDROID`):** There's a conditional compilation block related to Android versions and potentially using a different `getifaddrs` implementation.

This platform-specific logic needs to be highlighted in the analysis.

**3. Analyzing Key Functions and Data Structures:**

* **`getifaddrs()` and `freeifaddrs()`:**  These are standard POSIX functions for retrieving and freeing network interface address information. Their purpose is central.
* **`struct ifaddrs`:** This structure, defined in `<ifaddrs.h>`, is the fundamental data unit returned by `getifaddrs()`. Understanding its members (like `ifa_name`, `ifa_addr`, `ifa_netmask`, `ifa_flags`, `ifa_next`) is key.
* **`NetworkInterfaceList`:** This is the output data structure. We need to infer what information it likely holds (interface name, IP address, netmask, connection type, etc.). The code confirms this in the `IfaddrsToNetworkInterfaceList` function.
* **`IPAttributesGetter` (and its macOS implementation):** This abstract class and its concrete implementation show how platform-specific attributes are retrieved. The use of `ioctl` on macOS is a significant detail.

**4. Addressing the User's Specific Questions:**

Now, we tackle each part of the user's request:

* **Functionality:**  Summarize the core purpose: retrieving network interface information. Mention the key steps: calling `getifaddrs`, iterating, filtering, and populating the `NetworkInterfaceList`.
* **Relationship to JavaScript:** This requires recognizing how this low-level C++ code could be exposed to JavaScript in a browser environment. The most likely scenario is through a browser API. The Network Information API immediately comes to mind. Connect the concepts of interface names, IP addresses, connection types, etc., to properties of objects returned by this API. Provide a concrete example.
* **Logical Deduction (Assumptions and Outputs):** This involves tracing the logic in `IfaddrsToNetworkInterfaceList`. Identify key filtering conditions (interface up, running, not loopback, not ignored). Create hypothetical input (a simplified `ifaddrs` structure) and predict the output based on the filtering. This demonstrates an understanding of the code's behavior.
* **Common User/Programming Errors:** Think about common mistakes when dealing with network information or this kind of API. Permissions issues, misinterpreting interface flags, and assuming availability on all platforms are good examples. Explain *why* these are errors.
* **User Steps to Reach the Code (Debugging Clues):**  Focus on the higher-level user actions that would trigger the need for this information. Opening a webpage, a PWA, or a network settings page are good starting points. Then, trace down to the underlying browser components and the potential use of the Network Information API. Explain how a developer debugging network issues might encounter this code (e.g., inspecting browser internals).

**5. Structuring the Answer:**

Organize the information clearly, using headings and bullet points for readability. Present the functionality first, then address each of the user's specific points in order.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe this code directly handles network requests. **Correction:**  Realize it's more about *information gathering* about the network interfaces, not necessarily the request handling itself.
* **Initial thought:** Focus heavily on the `getifaddrs` system call. **Refinement:** Recognize the importance of the platform-specific logic and give it due attention.
* **Initial thought:**  Only consider direct JavaScript interaction. **Refinement:** Consider the broader context of how this information might be used internally by the browser, even if not directly exposed via an API. However, stick to the most likely and clear connection, which is the Network Information API for the JavaScript part.
* **Initial thought:** Overly technical explanation of `ifaddrs` structure. **Refinement:** Keep the explanation concise and focused on the relevant fields for the user's understanding.

By following this structured approach, breaking down the code, considering the user's questions, and performing self-correction, we can arrive at a comprehensive and accurate answer.
这个文件 `net/base/network_interfaces_getifaddrs.cc` 是 Chromium 网络栈的一部分，其主要功能是 **获取系统网络接口的信息**。它使用了 POSIX 系统调用 `getifaddrs()` 来实现这个目标。

以下是详细的功能分解和与 JavaScript 的关系，以及其他方面的说明：

**功能列举:**

1. **调用 `getifaddrs()` 系统调用:**  这是核心功能。`getifaddrs()` 会填充一个链表，其中包含系统中每个网络接口的地址信息，例如接口名称、IP 地址、子网掩码、广播地址等。
2. **遍历网络接口列表:**  代码会遍历 `getifaddrs()` 返回的 `ifaddrs` 结构体链表。
3. **过滤不需要的接口:**  根据一定的规则过滤掉不需要的网络接口。常见的过滤条件包括：
    * **接口状态:** 只考虑 `IFF_UP` 和 `IFF_RUNNING` 的接口（即已启用且正在运行的接口）。
    * **环回接口:** 排除 `IFF_LOOPBACK` 接口 (例如 `lo` 或 `lo0`)。
    * **无地址接口:** 排除没有配置 IP 地址的接口。
    * **特定名称接口:**  根据策略（`policy` 参数）排除某些特定名称的接口，例如 VMware 的 `vmnet1` 和 `vmnet8`。
    * **特定属性的 IPv6 地址 (macOS):** 在 macOS 上，会使用 `ioctl` 获取 IPv6 地址的属性，并排除具有 `ANYCAST`、`DUPLICATED`、`TENTATIVE` 和 `DETACHED` 属性的地址，因为这些地址可能正在进行重复地址检测（DAD）或不适合单播通信。
4. **获取接口类型 (macOS):** 在 macOS 上，使用 `ioctl` 调用 `SIOCGIFMEDIA` 来判断接口的物理连接类型，例如 Wi-Fi (`IFM_IEEE80211`) 或以太网 (`IFM_ETHER`)。
5. **将 `ifaddrs` 结构体信息转换为 `NetworkInterfaceList`:**  将 `ifaddrs` 结构体中的信息提取出来，并填充到 Chromium 自定义的 `NetworkInterfaceList` 数据结构中。这个结构体通常包含接口名称、IP 地址、前缀长度、连接类型等信息.
6. **处理不同平台:**  使用了条件编译 (`#if BUILDFLAG(...)`) 来处理不同操作系统之间的差异，例如 macOS 和 Android。
    * **macOS:** 使用 `IPAttributesGetterMac` 类，通过 `ioctl` 系统调用获取更详细的 IP 地址属性和网络接口类型。
    * **Android:**  在 Android N+ 版本上直接使用系统提供的 `getifaddrs` 和 `freeifaddrs`。对于旧版本，Chromium 可能有自己的实现 (虽然这个文件本身看起来并没有包含旧版本的实现)。
7. **处理 IPv6 地址属性 (macOS):**  在 macOS 上，会获取 IPv6 地址的特定标志（例如 `IN6_IFF_TEMPORARY`, `IN6_IFF_DEPRECATED` 等），并将这些标志转换为 Chromium 定义的 IP 地址属性。

**与 JavaScript 的关系:**

这个 C++ 代码本身并不能直接被 JavaScript 调用。然而，它获取的网络接口信息最终可能会通过 Chromium 的内部机制暴露给 JavaScript，最常见的场景是通过 **Network Information API**。

**举例说明:**

假设一个网页想要知道用户的网络连接类型和 IP 地址，它可以使用 JavaScript 的 Network Information API：

```javascript
if ('connection' in navigator) {
  const connection = navigator.connection;
  console.log('Connection type:', connection.effectiveType); // 可能输出 "wifi", "ethernet", "cellular", "none", "unknown"

  // 获取所有网络接口信息（这是一个提案中的 API，并非所有浏览器都支持）
  navigator.getNetworkInterfaces().then(interfaces => {
    interfaces.forEach(iface => {
      console.log('Interface name:', iface.name);
      iface.addressList.forEach(addr => {
        console.log('IP Address:', addr.address);
        console.log('Prefix Length:', addr.prefixLength);
      });
      console.log('Connection Type (approximate):', iface.connectionType);
    });
  });
}
```

在这个例子中，当 JavaScript 代码调用 `navigator.connection.effectiveType` 或 `navigator.getNetworkInterfaces()` (如果浏览器支持)，Chromium 内部就需要获取系统的网络接口信息。`net/base/network_interfaces_getifaddrs.cc` 中实现的 `GetNetworkList` 函数很可能就是这个过程中的一部分。它负责从操作系统层面获取原始的网络接口信息，然后 Chromium 会将这些信息处理和格式化，最终通过 JavaScript API 提供给网页。

**逻辑推理 (假设输入与输出):**

**假设输入:**

假设系统有以下两个网络接口：

1. **以太网接口 `eth0`:**
   * 状态: UP, RUNNING
   * IP 地址: 192.168.1.100
   * 子网掩码: 255.255.255.0
2. **Wi-Fi 接口 `wlan0`:**
   * 状态: UP, RUNNING
   * IP 地址: 10.0.0.50
   * 子网掩码: 255.255.255.0
3. **环回接口 `lo`:**
   * 状态: UP, RUNNING
   * IP 地址: 127.0.0.1
   * 子网掩码: 255.0.0.0

假设 `policy` 参数没有排除任何接口。

**预期输出:**

`GetNetworkList` 函数可能会返回一个 `NetworkInterfaceList`，其中包含两个 `NetworkInterface` 对象（环回接口会被过滤掉）：

1. **针对 `eth0` 的 `NetworkInterface` 对象:**
   * `name`: "eth0"
   * `friendly_name`: "eth0" (通常与 `name` 相同)
   * `index`:  (与接口索引对应)
   * `connection_type`: `NetworkChangeNotifier::CONNECTION_ETHERNET`
   * `address`:  `192.168.1.100`
   * `prefix_length`: 24
   * `ip_attributes`: `IP_ADDRESS_ATTRIBUTE_NONE`

2. **针对 `wlan0` 的 `NetworkInterface` 对象:**
   * `name`: "wlan0"
   * `friendly_name`: "wlan0"
   * `index`:  (与接口索引对应)
   * `connection_type`: `NetworkChangeNotifier::CONNECTION_WIFI` (如果 macOS，否则可能为 `UNKNOWN`)
   * `address`: `10.0.0.50`
   * `prefix_length`: 24
   * `ip_attributes`: `IP_ADDRESS_ATTRIBUTE_NONE`

**涉及用户或编程常见的使用错误:**

1. **权限不足:**  在某些系统上，调用 `getifaddrs()` 可能需要特定的权限。如果 Chromium 进程没有足够的权限，`getifaddrs()` 可能会返回错误，导致网络信息获取失败。
2. **假设所有平台行为一致:**  开发者可能会错误地假设不同操作系统上的网络接口命名规则和行为完全一致。例如，macOS 上获取连接类型需要额外的 `ioctl` 调用，而其他系统可能没有直接的方法。
3. **错误地解析接口标志:**  `ifa_flags` 字段包含了很多关于接口状态的信息。开发者可能会错误地理解或使用这些标志，导致过滤逻辑错误。例如，错误地判断接口是否可用。
4. **内存泄漏:** 虽然代码中使用了 `freeifaddrs()` 来释放 `getifaddrs()` 分配的内存，但在某些错误处理路径下，可能会忘记释放内存，导致内存泄漏。
5. **竞争条件:**  在多线程环境中，如果多个线程同时尝试获取网络接口信息，可能会出现竞争条件，导致数据不一致。虽然在这个特定的文件中可能不太明显，但在 Chromium 的更广泛的网络栈中需要考虑。

**用户操作是如何一步步的到达这里，作为调试线索:**

以下是一个典型的用户操作路径，最终可能涉及到这个代码文件：

1. **用户打开一个网页或 PWA (Progressive Web App):** 用户在浏览器中输入网址或点击书签打开一个网页。
2. **网页上的 JavaScript 代码尝试获取网络信息:** 网页上的 JavaScript 代码可能使用了 Network Information API (`navigator.connection`, `navigator.getNetworkInterfaces()`) 来获取用户的网络连接状态、类型或具体的网络接口信息。
3. **浏览器内核处理 JavaScript API 请求:**  Chromium 的渲染进程（Renderer Process）中的 JavaScript 引擎接收到这些 API 调用。
4. **请求被传递到浏览器进程 (Browser Process):**  获取网络接口信息通常涉及到系统级别的操作，因此渲染进程会将请求传递给拥有更高权限的浏览器进程。
5. **浏览器进程的网络服务 (Network Service) 介入:**  浏览器进程中的网络服务组件负责处理网络相关的操作。
6. **调用 `GetNetworkList` 或相关函数:**  网络服务中的某个模块会调用 `net::GetNetworkList` 函数，而这个函数在内部会调用 `net::internal::GetNetworkListUsingGetifaddrs` (在 Android N+ 上) 或 `net::internal::GetNetworkList`，最终执行到 `getifaddrs()` 系统调用。
7. **系统调用 `getifaddrs()` 执行:** 操作系统执行 `getifaddrs()`，收集网络接口信息。
8. **信息被处理和转换:** `net/base/network_interfaces_getifaddrs.cc` 中的代码会将 `getifaddrs()` 返回的原始信息进行过滤、处理和转换成 Chromium 内部的数据结构。
9. **信息通过 IPC 返回:**  处理后的网络接口信息会通过进程间通信 (IPC) 返回给渲染进程。
10. **JavaScript API 回调被触发:**  渲染进程接收到网络信息后，会触发 JavaScript 中相应的 API 回调函数，将信息传递给网页。

**作为调试线索:**

当开发者在调试与网络信息相关的 Bug 时，例如：

* **网页无法正确判断网络连接类型。**
* **PWA 在离线状态下行为异常。**
* **需要获取用户 IP 地址或网络接口信息的功能出现问题。**

他们可能会：

1. **查看浏览器控制台的 Network Information API 输出:**  检查 `navigator.connection` 和 `navigator.getNetworkInterfaces()` 返回的值是否正确。
2. **使用 `chrome://network-internals/#ifaces` 查看 Chromium 内部的网络接口信息:**  这个页面显示了 Chromium 感知到的网络接口信息，可以帮助开发者验证 `GetNetworkList` 的输出是否正确。
3. **设置断点在 `net/base/network_interfaces_getifaddrs.cc` 中的关键函数:**  如果怀疑问题出在获取网络接口信息的阶段，开发者可能会在 `GetNetworkList` 或 `IfaddrsToNetworkInterfaceList` 函数中设置断点，逐步跟踪代码执行，查看 `ifaddrs` 结构体的内容，以及过滤和转换的过程。
4. **检查 `getifaddrs()` 的返回值:**  确认 `getifaddrs()` 是否成功执行，并检查其返回值和 `errno` 的值，以排查系统调用层面的问题。
5. **比较不同平台上的行为:**  如果 Bug 只在特定操作系统上出现，开发者可能会比较不同平台上的 `getifaddrs()` 返回结果和 Chromium 的处理逻辑。

总而言之，`net/base/network_interfaces_getifaddrs.cc` 是 Chromium 获取底层网络接口信息的核心组件，虽然它不能直接被 JavaScript 调用，但其功能是实现 JavaScript Network Information API 的基础。理解其功能对于调试网络相关的 Bug 和理解 Chromium 的网络架构至关重要。

### 提示词
```
这是目录为net/base/network_interfaces_getifaddrs.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/network_interfaces_getifaddrs.h"

#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/types.h>

#include <memory>
#include <set>

#include "base/files/file_path.h"
#include "base/logging.h"
#include "base/posix/eintr_wrapper.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_tokenizer.h"
#include "base/strings/string_util.h"
#include "base/threading/scoped_blocking_call.h"
#include "build/build_config.h"
#include "net/base/ip_endpoint.h"
#include "net/base/net_errors.h"
#include "net/base/network_interfaces_posix.h"

#if BUILDFLAG(IS_MAC)
#include <net/if_media.h>
#include <netinet/in_var.h>
#include <sys/ioctl.h>
#endif

#if BUILDFLAG(IS_ANDROID)
#include "base/android/build_info.h"
#include "net/base/network_interfaces_getifaddrs_android.h"
// Declare getifaddrs() and freeifaddrs() weakly as they're only available
// on Android N+.
extern "C" {
int getifaddrs(struct ifaddrs** __list_ptr) __attribute__((weak_import));
void freeifaddrs(struct ifaddrs* __ptr) __attribute__((weak_import));
}
#endif  // BUILDFLAG(IS_ANDROID)

namespace net {
namespace internal {

#if BUILDFLAG(IS_MAC)

// MacOSX implementation of IPAttributesGetter which calls ioctl() on socket to
// retrieve IP attributes.
class IPAttributesGetterMac : public internal::IPAttributesGetter {
 public:
  IPAttributesGetterMac();
  ~IPAttributesGetterMac() override;
  bool IsInitialized() const override;
  bool GetAddressAttributes(const ifaddrs* if_addr, int* attributes) override;
  NetworkChangeNotifier::ConnectionType GetNetworkInterfaceType(
      const ifaddrs* if_addr) override;

 private:
  int ioctl_socket_;
};

IPAttributesGetterMac::IPAttributesGetterMac()
    : ioctl_socket_(socket(AF_INET6, SOCK_DGRAM, 0)) {
  DCHECK_GE(ioctl_socket_, 0);
}

IPAttributesGetterMac::~IPAttributesGetterMac() {
  if (IsInitialized()) {
    PCHECK(IGNORE_EINTR(close(ioctl_socket_)) == 0);
  }
}

bool IPAttributesGetterMac::IsInitialized() const {
  return ioctl_socket_ >= 0;
}

int AddressFlagsToNetAddressAttributes(int flags) {
  int result = 0;
  if (flags & IN6_IFF_TEMPORARY) {
    result |= IP_ADDRESS_ATTRIBUTE_TEMPORARY;
  }
  if (flags & IN6_IFF_DEPRECATED) {
    result |= IP_ADDRESS_ATTRIBUTE_DEPRECATED;
  }
  if (flags & IN6_IFF_ANYCAST) {
    result |= IP_ADDRESS_ATTRIBUTE_ANYCAST;
  }
  if (flags & IN6_IFF_TENTATIVE) {
    result |= IP_ADDRESS_ATTRIBUTE_TENTATIVE;
  }
  if (flags & IN6_IFF_DUPLICATED) {
    result |= IP_ADDRESS_ATTRIBUTE_DUPLICATED;
  }
  if (flags & IN6_IFF_DETACHED) {
    result |= IP_ADDRESS_ATTRIBUTE_DETACHED;
  }
  return result;
}

bool IPAttributesGetterMac::GetAddressAttributes(const ifaddrs* if_addr,
                                                 int* attributes) {
  struct in6_ifreq ifr = {};
  strncpy(ifr.ifr_name, if_addr->ifa_name, sizeof(ifr.ifr_name) - 1);
  memcpy(&ifr.ifr_ifru.ifru_addr, if_addr->ifa_addr, if_addr->ifa_addr->sa_len);
  int rv = ioctl(ioctl_socket_, SIOCGIFAFLAG_IN6, &ifr);
  if (rv >= 0) {
    *attributes = AddressFlagsToNetAddressAttributes(ifr.ifr_ifru.ifru_flags);
  }
  return (rv >= 0);
}

NetworkChangeNotifier::ConnectionType
IPAttributesGetterMac::GetNetworkInterfaceType(const ifaddrs* if_addr) {
  if (!IsInitialized())
    return NetworkChangeNotifier::CONNECTION_UNKNOWN;

  struct ifmediareq ifmr = {};
  strncpy(ifmr.ifm_name, if_addr->ifa_name, sizeof(ifmr.ifm_name) - 1);

  if (ioctl(ioctl_socket_, SIOCGIFMEDIA, &ifmr) != -1) {
    if (ifmr.ifm_current & IFM_IEEE80211) {
      return NetworkChangeNotifier::CONNECTION_WIFI;
    }
    if (ifmr.ifm_current & IFM_ETHER) {
      return NetworkChangeNotifier::CONNECTION_ETHERNET;
    }
  }

  return NetworkChangeNotifier::CONNECTION_UNKNOWN;
}

#endif  // BUILDFLAG(IS_MAC)

bool IfaddrsToNetworkInterfaceList(int policy,
                                   const ifaddrs* interfaces,
                                   IPAttributesGetter* ip_attributes_getter,
                                   NetworkInterfaceList* networks) {
  // Enumerate the addresses assigned to network interfaces which are up.
  for (const ifaddrs* interface = interfaces; interface != nullptr;
       interface = interface->ifa_next) {
    // Skip loopback interfaces, and ones which are down.
    if (!(IFF_UP & interface->ifa_flags)) {
      continue;
    }
    if (!(IFF_RUNNING & interface->ifa_flags))
      continue;
    if (IFF_LOOPBACK & interface->ifa_flags)
      continue;
    // Skip interfaces with no address configured.
    struct sockaddr* addr = interface->ifa_addr;
    if (!addr)
      continue;

    // Skip unspecified addresses (i.e. made of zeroes) and loopback addresses
    // configured on non-loopback interfaces.
    if (IsLoopbackOrUnspecifiedAddress(addr))
      continue;

    std::string name = interface->ifa_name;
    // Filter out VMware interfaces, typically named vmnet1 and vmnet8.
    if (ShouldIgnoreInterface(name, policy)) {
      continue;
    }

    NetworkChangeNotifier::ConnectionType connection_type =
        NetworkChangeNotifier::CONNECTION_UNKNOWN;

    int ip_attributes = IP_ADDRESS_ATTRIBUTE_NONE;

    // Retrieve native ip attributes and convert to net version if a getter is
    // given.
    if (ip_attributes_getter && ip_attributes_getter->IsInitialized()) {
      if (addr->sa_family == AF_INET6 &&
          ip_attributes_getter->GetAddressAttributes(interface,
                                                     &ip_attributes)) {
        // Disallow addresses with attributes ANYCASE, DUPLICATED, TENTATIVE,
        // and DETACHED as these are still progressing through duplicated
        // address detection (DAD) or are not suitable to be used in an
        // one-to-one communication and shouldn't be used by the application
        // layer.
        if (ip_attributes &
            (IP_ADDRESS_ATTRIBUTE_ANYCAST | IP_ADDRESS_ATTRIBUTE_DUPLICATED |
             IP_ADDRESS_ATTRIBUTE_TENTATIVE | IP_ADDRESS_ATTRIBUTE_DETACHED)) {
          continue;
        }
      }

      connection_type =
          ip_attributes_getter->GetNetworkInterfaceType(interface);
    }

    IPEndPoint address;

    int addr_size = 0;
    if (addr->sa_family == AF_INET6) {
      addr_size = sizeof(sockaddr_in6);
    } else if (addr->sa_family == AF_INET) {
      addr_size = sizeof(sockaddr_in);
    }

    if (address.FromSockAddr(addr, addr_size)) {
      uint8_t prefix_length = 0;
      if (interface->ifa_netmask) {
        // If not otherwise set, assume the same sa_family as ifa_addr.
        if (interface->ifa_netmask->sa_family == 0) {
          interface->ifa_netmask->sa_family = addr->sa_family;
        }
        IPEndPoint netmask;
        if (netmask.FromSockAddr(interface->ifa_netmask, addr_size)) {
          prefix_length = MaskPrefixLength(netmask.address());
        }
      }
      networks->push_back(NetworkInterface(
          name, name, if_nametoindex(name.c_str()), connection_type,
          address.address(), prefix_length, ip_attributes));
    }
  }

  return true;
}

}  // namespace internal

// This version of GetNetworkList() can only be called on Android N+, so give it
// a different and internal name so it isn't invoked mistakenly.
#if BUILDFLAG(IS_ANDROID)
namespace internal {
bool GetNetworkListUsingGetifaddrs(NetworkInterfaceList* networks,
                                   int policy,
                                   bool use_alternative_getifaddrs) {
  DCHECK_GE(base::android::BuildInfo::GetInstance()->sdk_int(),
            base::android::SDK_VERSION_NOUGAT);
  DCHECK(getifaddrs);
  DCHECK(freeifaddrs);
#else
bool GetNetworkList(NetworkInterfaceList* networks, int policy) {
  constexpr bool use_alternative_getifaddrs = false;
#endif
  if (networks == nullptr)
    return false;

  // getifaddrs() may require IO operations.
  base::ScopedBlockingCall scoped_blocking_call(FROM_HERE,
                                                base::BlockingType::MAY_BLOCK);

  ifaddrs* interfaces;
  int getifaddrs_result;
  if (use_alternative_getifaddrs) {
#if BUILDFLAG(IS_ANDROID)
    // Chromium ships its own implementation of getifaddrs()
    // under the name Getifaddrs.
    getifaddrs_result = Getifaddrs(&interfaces);
#else
    NOTREACHED();
#endif
  } else {
    getifaddrs_result = getifaddrs(&interfaces);
  }
  if (getifaddrs_result < 0) {
    PLOG(ERROR) << "getifaddrs";
    return false;
  }

  std::unique_ptr<internal::IPAttributesGetter> ip_attributes_getter;

#if BUILDFLAG(IS_MAC)
  ip_attributes_getter = std::make_unique<internal::IPAttributesGetterMac>();
#endif

  bool result = internal::IfaddrsToNetworkInterfaceList(
      policy, interfaces, ip_attributes_getter.get(), networks);

  if (use_alternative_getifaddrs) {
#if BUILDFLAG(IS_ANDROID)
    Freeifaddrs(interfaces);
#else
    NOTREACHED();
#endif
  } else {
    freeifaddrs(interfaces);
  }
  return result;
}

#if BUILDFLAG(IS_ANDROID)
}  // namespace internal
// For Android use GetWifiSSID() impl in network_interfaces_linux.cc.
#else
std::string GetWifiSSID() {
  NOTIMPLEMENTED();
  return std::string();
}
#endif

}  // namespace net
```