Response:
Let's break down the request and plan the response step-by-step.

**1. Understanding the Core Request:**

The primary goal is to analyze the `network_interfaces_win.cc` file and describe its functionality. The request also asks for specific connections to JavaScript, logical reasoning examples, common user/programming errors, and debugging clues.

**2. Initial Analysis of the Code:**

I need to scan the code for key functionalities. Keywords like `GetNetworkList`, `WLAN`, `IP_ADAPTER_ADDRESSES`, and function names like `GetNetworkInterfaceType`, `GetConnectionAttributes`, `SetWifiOptions`, and `GetWifiSSID` are important. The file clearly deals with retrieving and potentially manipulating network interface information on Windows.

**3. Deconstructing the Sub-Requests:**

*   **Functionality:** This is the most straightforward part. I need to summarize what the code does in high-level terms.
*   **Relationship with JavaScript:** This requires understanding how network information retrieved by this C++ code might be exposed to JavaScript in a browser context. I need to think about the browser's rendering process, networking APIs, and potential data flow.
*   **Logical Reasoning:** This requires identifying a function where the output depends on the input and providing concrete examples. `GetNetworkInterfaceType` or `GetNetworkListImpl` seem like good candidates.
*   **User/Programming Errors:** This involves considering common mistakes developers or users might make when dealing with network configurations or when interacting with APIs that rely on this underlying code.
*   **User Operations & Debugging:** This requires thinking about the user actions that could trigger the execution of this code and how developers could use this code (or information derived from it) during debugging.

**4. Planning Specific Examples and Details:**

*   **Functionality:** List the key functions and their purposes.
*   **JavaScript Connection:** Focus on `navigator.connection` API or how website content might adapt based on network information.
*   **Logical Reasoning (GetNetworkInterfaceType):** Define input as a `DWORD` representing `ifType` and output as a `ConnectionType` enum. Provide examples for `IF_TYPE_ETHERNET_CSMACD` and `IF_TYPE_IEEE80211`.
*   **Logical Reasoning (GetNetworkListImpl):** Consider filtering based on `policy` (e.g., `EXCLUDE_HOST_SCOPE_VIRTUAL_INTERFACES`) and how it affects the output `NetworkInterfaceList`. Provide a simplified example.
*   **User/Programming Errors:** Think about incorrect permissions, network driver issues, or assumptions about network status.
*   **User Operations:** Browser navigation, accessing network settings, connecting/disconnecting from Wi-Fi are relevant examples.
*   **Debugging:**  Explain how developers could use browser DevTools (Network tab, potentially `chrome://network-internals`) and the information retrieved by this code.

**5. Structuring the Response:**

I'll organize the response into clear sections for each part of the request, using headings and bullet points for better readability.

**6. Refinement and Review:**

After drafting the initial response, I'll review it to ensure:

*   Accuracy of the technical details.
*   Clarity and conciseness.
*   Specific and relevant examples.
*   Address all parts of the original request.

**Self-Correction during Planning:**

Initially, I considered focusing heavily on the Windows API details. However, the request also specifically asks about JavaScript interaction and user scenarios. So, I need to broaden the scope and connect the low-level C++ code to higher-level browser functionalities. I also need to ensure the logical reasoning examples are simple and easy to understand. I'll avoid overly complex network configurations in the examples. For the user operation, I should think from a user's perspective, not just a developer's. Similarly, for debugging, I need to consider tools available to developers.

By following this structured thinking process, I can generate a comprehensive and accurate answer that addresses all aspects of the user's request.
This C++ source code file, `net/base/network_interfaces_win.cc`, within the Chromium project's networking stack, is responsible for **retrieving information about the network interfaces** present on a Windows system. It provides functions to enumerate and detail these interfaces, including their type, IP addresses, MAC addresses, and other relevant network configuration.

Here's a breakdown of its functionalities:

**1. Enumerating Network Interfaces:**

*   **`GetNetworkList(NetworkInterfaceList* networks, int policy)`:** This is the main function that populates the `networks` list with information about each network interface.
*   It uses the Windows API function `GetAdaptersAddresses` to retrieve a list of network adapters and their associated IP addresses.
*   It handles potential errors during the API call, including buffer overflow and no data.
*   The `policy` parameter allows filtering of network interfaces based on certain criteria (e.g., excluding host-scoped virtual interfaces).

**2. Gathering Interface Details:**

*   **Iterates through IP Adapters:** The code iterates through the list of network adapters obtained from `GetAdaptersAddresses`.
*   **Filters Interfaces:** It filters out loopback interfaces and interfaces that are not in an "up" state. It can also filter out host-scoped virtual interfaces based on the `policy`.
*   **Extracts MAC Address:** It retrieves the MAC address of the interface.
*   **Extracts IP Addresses:** It iterates through the unicast IP addresses associated with each adapter, supporting both IPv4 and IPv6.
*   **Determines IP Address Attributes:** For IPv6 addresses, it checks if the address is temporary or deprecated.
*   **Maps Windows Types to Chromium Types:** The `GetNetworkInterfaceType(DWORD ifType)` function converts Windows-specific interface types (like `IF_TYPE_ETHERNET_CSMACD` and `IF_TYPE_IEEE80211`) to Chromium's `NetworkChangeNotifier::ConnectionType` enum (e.g., `CONNECTION_ETHERNET`, `CONNECTION_WIFI`).

**3. Handling Wi-Fi Specific Information:**

*   **`GetWifiSSID()`:** This function retrieves the Service Set Identifier (SSID) of the currently connected Wi-Fi network.
*   It uses the Windows WLAN API to get information about the current Wi-Fi connection.
*   **`SetWifiOptions(int options)` and `WifiOptionSetter`:** These are used to temporarily modify Wi-Fi adapter settings. For example, they can disable background scanning or enable media streaming mode. These options are automatically reset when the `ScopedWifiOptions` object goes out of scope.
*   **`GetConnectionAttributes()`:** This helper function uses the WLAN API to retrieve detailed connection attributes of the currently connected Wi-Fi network.

**Relationship with JavaScript:**

This C++ code directly interacts with the Windows operating system to gather network information. This information is then made available to higher layers within the Chromium browser, which can eventually be exposed to JavaScript through browser APIs. Here's how it connects:

*   **`navigator.connection` API:**  JavaScript code running in a web page can use the `navigator.connection` API to get information about the user's network connection. This API provides properties like `type` (e.g., "ethernet", "wifi", "none"), `effectiveType` (e.g., "4g", "3g", "slow-2g"), and `rtt` (round-trip time). The underlying implementation of this API on Windows would likely utilize the information gathered by `network_interfaces_win.cc`. For example, the `type` property might be derived from the `NetworkChangeNotifier::ConnectionType` determined by `GetNetworkInterfaceType`.

    **Example:**
    ```javascript
    if (navigator.connection) {
      console.log("Connection type:", navigator.connection.type);
      if (navigator.connection.type === 'wifi') {
        console.log("User is on Wi-Fi.");
        // Potentially load higher-quality assets.
      }
    }
    ```

*   **Network Information for Resource Loading:** The browser's networking stack uses the information gathered by this code to make decisions about how to load resources. For instance, it might prioritize certain network interfaces or adjust connection parameters based on the network type. This indirectly affects the performance and behavior experienced by JavaScript applications.

*   **Permissions and Security:**  While JavaScript doesn't directly call functions in this C++ file, the browser's permission model ensures that web pages can only access network information through controlled APIs, preventing malicious scripts from directly probing network interfaces.

**Logical Reasoning Examples:**

**Example 1: `GetNetworkInterfaceType`**

*   **Assumption:** The function correctly maps Windows interface types to Chromium's `ConnectionType`.
*   **Input:** `ifType = IF_TYPE_ETHERNET_CSMACD` (a Windows constant representing Ethernet).
*   **Output:** `NetworkChangeNotifier::CONNECTION_ETHERNET`.
*   **Reasoning:** The `if` condition `if (ifType == IF_TYPE_ETHERNET_CSMACD)` will be true, and the function will assign `NetworkChangeNotifier::CONNECTION_ETHERNET` to the `type` variable.

*   **Input:** `ifType = IF_TYPE_IEEE80211` (a Windows constant representing 802.11 wireless).
*   **Output:** `NetworkChangeNotifier::CONNECTION_WIFI`.
*   **Reasoning:** The `else if` condition `else if (ifType == IF_TYPE_IEEE80211)` will be true, and the function will assign `NetworkChangeNotifier::CONNECTION_WIFI` to the `type` variable.

*   **Input:** `ifType = some_unknown_type` (a Windows constant not explicitly handled).
*   **Output:** `NetworkChangeNotifier::CONNECTION_UNKNOWN`.
*   **Reasoning:** Neither the `if` nor the `else if` conditions will be true, so the initial value of `type`, which is `NetworkChangeNotifier::CONNECTION_UNKNOWN`, will be returned.

**Example 2: `GetNetworkListImpl` with `EXCLUDE_HOST_SCOPE_VIRTUAL_INTERFACES` Policy**

*   **Assumption:** The `policy` flag `EXCLUDE_HOST_SCOPE_VIRTUAL_INTERFACES` correctly filters out VMware host adapters.
*   **Input:** `policy` has the `EXCLUDE_HOST_SCOPE_VIRTUAL_INTERFACES` bit set. The `adapters` list contains a VMware adapter with `adapter->AdapterName` containing "VMnet" and a regular Ethernet adapter.
*   **Output:** The `networks` list will contain information about the regular Ethernet adapter but **not** the VMware adapter.
*   **Reasoning:**  When the code iterates through the adapters, for the VMware adapter, the condition `(policy & EXCLUDE_HOST_SCOPE_VIRTUAL_INTERFACES) && strstr(adapter->AdapterName, "VMnet") != nullptr` will be true. This will cause the `continue` statement to be executed, skipping the processing of this VMware adapter and preventing it from being added to the `networks` list. The regular Ethernet adapter will not match this condition and will be processed and added.

**User or Programming Common Usage Errors:**

1. **Insufficient Permissions:** If the Chromium process doesn't have sufficient privileges to call `GetAdaptersAddresses` or the WLAN API functions, these calls might fail, and `GetNetworkList` or `GetWifiSSID` might return incomplete or incorrect information. This is more of a system-level configuration issue.

    *   **Example:** A user running Chromium in a restricted environment might not be able to retrieve all network interface details.

2. **Network Driver Issues:**  Faulty or outdated network drivers can lead to incorrect information being reported by the Windows APIs. This would propagate through this code, resulting in inaccurate data.

    *   **Example:** If a Wi-Fi driver is malfunctioning, `GetWifiSSID` might return an empty string even when the user is connected to Wi-Fi.

3. **Incorrect `policy` Usage:**  A programmer using the `GetNetworkList` function might pass an incorrect `policy` value, unintentionally filtering out necessary network interfaces.

    *   **Example:** If a developer mistakenly sets `policy` to `EXCLUDE_HOST_SCOPE_VIRTUAL_INTERFACES` when they actually need to include these interfaces, their application logic relying on the `networks` list will behave incorrectly.

4. **Assuming Network State:**  Code relying on the output of these functions might make assumptions about the network state that are not always true.

    *   **Example:** A program might assume that if `GetWifiSSID` returns a non-empty string, the internet connection is active and stable. However, the user might be connected to a local Wi-Fi network without internet access.

**User Operations Leading to this Code:**

This code is executed internally by the Chromium browser when it needs to gather information about the network environment. Here are some user actions that indirectly trigger this code:

1. **Opening a Web Page:** When a user navigates to a website, the browser needs to determine the network connection to establish communication with the server. This involves querying the available network interfaces.

2. **Checking Network Status:**  Users can view their network status through the operating system's network settings. Chromium might use this information to display relevant details in its own internal pages (like `chrome://network-internals`).

3. **Using Web Features that Rely on Network Information:** Features like WebRTC (for video conferencing), location services, or network quality estimation rely on the underlying network information. When a user uses these features, the browser might need to refresh its knowledge of the network interfaces.

4. **Connecting to or Disconnecting from a Network:** When a user connects to a new Wi-Fi network or disconnects from the internet, the operating system will signal these changes. Chromium will then likely re-enumerate the network interfaces to reflect the updated state.

5. **Troubleshooting Network Issues:** When a user experiences network problems, they might use Chromium's built-in tools or extensions that display network information. These tools would ultimately rely on the data gathered by this code.

**Debugging Clues:**

If you suspect issues related to network interface detection in Chromium, you can look for clues in the following places:

1. **`chrome://network-internals/#ifconfig`:** This Chromium internal page displays the list of network interfaces as detected by the browser. Compare this with the network interfaces shown by the Windows operating system (`ipconfig` in Command Prompt). Discrepancies might indicate a problem in this code.

2. **Chromium Logs:**  Enable verbose logging in Chromium (e.g., using the `--vmodule` flag) and look for messages related to `net::GetNetworkList` or `net::network_interfaces_win`. Error messages or unexpected values could point to issues.

3. **Windows Event Logs:** Check the Windows system event logs for errors related to network interface drivers or the WLAN service. These errors might indicate problems that are preventing Chromium from correctly retrieving network information.

4. **Debugger:** If you are a Chromium developer, you can set breakpoints in `net/base/network_interfaces_win.cc` to step through the code and inspect the values of variables like `adapters`, `address`, and the `networks` list. This allows you to observe the data being retrieved from the Windows API and identify where things might be going wrong.

5. **Wireshark or Network Monitoring Tools:**  While not directly related to this code, using network monitoring tools like Wireshark can help understand the network traffic and identify if the expected network interfaces are being used.

By understanding the functionality of `net/base/network_interfaces_win.cc` and how it interacts with the underlying operating system, developers and users can better diagnose and troubleshoot network-related issues within the Chromium browser.

Prompt: 
```
这是目录为net/base/network_interfaces_win.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
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

#include "net/base/network_interfaces_win.h"

#include <algorithm>
#include <memory>
#include <string_view>

#include "base/containers/heap_array.h"
#include "base/files/file_path.h"
#include "base/lazy_instance.h"
#include "base/strings/escape.h"
#include "base/strings/string_util.h"
#include "base/strings/sys_string_conversions.h"
#include "base/strings/utf_string_conversions.h"
#include "base/threading/scoped_blocking_call.h"
#include "base/threading/scoped_thread_priority.h"
#include "base/win/scoped_handle.h"
#include "net/base/ip_endpoint.h"
#include "net/base/net_errors.h"
#include "url/gurl.h"

namespace net {

namespace {

// Converts Windows defined types to NetworkInterfaceType.
NetworkChangeNotifier::ConnectionType GetNetworkInterfaceType(DWORD ifType) {
  NetworkChangeNotifier::ConnectionType type =
      NetworkChangeNotifier::CONNECTION_UNKNOWN;
  if (ifType == IF_TYPE_ETHERNET_CSMACD) {
    type = NetworkChangeNotifier::CONNECTION_ETHERNET;
  } else if (ifType == IF_TYPE_IEEE80211) {
    type = NetworkChangeNotifier::CONNECTION_WIFI;
  }
  // TODO(mallinath) - Cellular?
  return type;
}

// Returns scoped_ptr to WLAN_CONNECTION_ATTRIBUTES. The scoped_ptr may hold a
// NULL pointer if WLAN_CONNECTION_ATTRIBUTES is unavailable.
std::unique_ptr<WLAN_CONNECTION_ATTRIBUTES, internal::WlanApiDeleter>
GetConnectionAttributes() {
  const internal::WlanApi& wlanapi = internal::WlanApi::GetInstance();
  std::unique_ptr<WLAN_CONNECTION_ATTRIBUTES, internal::WlanApiDeleter>
      wlan_connection_attributes;
  if (!wlanapi.initialized)
    return wlan_connection_attributes;

  internal::WlanHandle client;
  DWORD cur_version = 0;
  const DWORD kMaxClientVersion = 2;
  DWORD result = wlanapi.OpenHandle(kMaxClientVersion, &cur_version, &client);
  if (result != ERROR_SUCCESS)
    return wlan_connection_attributes;

  WLAN_INTERFACE_INFO_LIST* interface_list_ptr = nullptr;
  result =
      wlanapi.enum_interfaces_func(client.Get(), nullptr, &interface_list_ptr);
  if (result != ERROR_SUCCESS)
    return wlan_connection_attributes;
  std::unique_ptr<WLAN_INTERFACE_INFO_LIST, internal::WlanApiDeleter>
      interface_list(interface_list_ptr);

  // Assume at most one connected wifi interface.
  WLAN_INTERFACE_INFO* info = nullptr;
  for (unsigned i = 0; i < interface_list->dwNumberOfItems; ++i) {
    if (interface_list->InterfaceInfo[i].isState ==
        wlan_interface_state_connected) {
      info = &interface_list->InterfaceInfo[i];
      break;
    }
  }

  if (info == nullptr)
    return wlan_connection_attributes;

  WLAN_CONNECTION_ATTRIBUTES* conn_info_ptr = nullptr;
  DWORD conn_info_size = 0;
  WLAN_OPCODE_VALUE_TYPE op_code;
  result = wlanapi.query_interface_func(
      client.Get(), &info->InterfaceGuid, wlan_intf_opcode_current_connection,
      nullptr, &conn_info_size, reinterpret_cast<VOID**>(&conn_info_ptr),
      &op_code);
  wlan_connection_attributes.reset(conn_info_ptr);
  if (result == ERROR_SUCCESS)
    DCHECK(conn_info_ptr);
  else
    wlan_connection_attributes.reset();
  return wlan_connection_attributes;
}

}  // namespace

namespace internal {

base::LazyInstance<WlanApi>::Leaky lazy_wlanapi =
  LAZY_INSTANCE_INITIALIZER;

WlanApi& WlanApi::GetInstance() {
  return lazy_wlanapi.Get();
}

WlanApi::WlanApi() : initialized(false) {
  // Mitigate the issues caused by loading DLLs on a background thread
  // (http://crbug/973868).
  SCOPED_MAY_LOAD_LIBRARY_AT_BACKGROUND_PRIORITY();

  HMODULE module =
      ::LoadLibraryEx(L"wlanapi.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
  if (!module)
    return;

  open_handle_func = reinterpret_cast<WlanOpenHandleFunc>(
      ::GetProcAddress(module, "WlanOpenHandle"));
  enum_interfaces_func = reinterpret_cast<WlanEnumInterfacesFunc>(
      ::GetProcAddress(module, "WlanEnumInterfaces"));
  query_interface_func = reinterpret_cast<WlanQueryInterfaceFunc>(
      ::GetProcAddress(module, "WlanQueryInterface"));
  set_interface_func = reinterpret_cast<WlanSetInterfaceFunc>(
      ::GetProcAddress(module, "WlanSetInterface"));
  free_memory_func = reinterpret_cast<WlanFreeMemoryFunc>(
      ::GetProcAddress(module, "WlanFreeMemory"));
  close_handle_func = reinterpret_cast<WlanCloseHandleFunc>(
      ::GetProcAddress(module, "WlanCloseHandle"));
  initialized = open_handle_func && enum_interfaces_func &&
      query_interface_func && set_interface_func &&
      free_memory_func && close_handle_func;
}

bool GetNetworkListImpl(NetworkInterfaceList* networks,
                        int policy,
                        const IP_ADAPTER_ADDRESSES* adapters) {
  for (const IP_ADAPTER_ADDRESSES* adapter = adapters; adapter != nullptr;
       adapter = adapter->Next) {
    // Ignore the loopback device.
    if (adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK) {
      continue;
    }

    if (adapter->OperStatus != IfOperStatusUp) {
      continue;
    }

    // Ignore any HOST side vmware adapters with a description like:
    // VMware Virtual Ethernet Adapter for VMnet1
    // but don't ignore any GUEST side adapters with a description like:
    // VMware Accelerated AMD PCNet Adapter #2
    if ((policy & EXCLUDE_HOST_SCOPE_VIRTUAL_INTERFACES) &&
        strstr(adapter->AdapterName, "VMnet") != nullptr) {
      continue;
    }

    std::optional<Eui48MacAddress> mac_address;
    mac_address.emplace();
    if (adapter->PhysicalAddressLength == mac_address->size()) {
      std::copy_n(reinterpret_cast<const uint8_t*>(adapter->PhysicalAddress),
                  mac_address->size(), mac_address->begin());
    } else {
      mac_address.reset();
    }

    for (IP_ADAPTER_UNICAST_ADDRESS* address = adapter->FirstUnicastAddress;
         address; address = address->Next) {
      int family = address->Address.lpSockaddr->sa_family;
      if (family == AF_INET || family == AF_INET6) {
        IPEndPoint endpoint;
        if (endpoint.FromSockAddr(address->Address.lpSockaddr,
                                  address->Address.iSockaddrLength)) {
          size_t prefix_length = address->OnLinkPrefixLength;

          // If the duplicate address detection (DAD) state is not changed to
          // Preferred, skip this address.
          if (address->DadState != IpDadStatePreferred) {
            continue;
          }

          uint32_t index =
              (family == AF_INET) ? adapter->IfIndex : adapter->Ipv6IfIndex;

          // From http://technet.microsoft.com/en-us/ff568768(v=vs.60).aspx, the
          // way to identify a temporary IPv6 Address is to check if
          // PrefixOrigin is equal to IpPrefixOriginRouterAdvertisement and
          // SuffixOrigin equal to IpSuffixOriginRandom.
          int ip_address_attributes = IP_ADDRESS_ATTRIBUTE_NONE;
          if (family == AF_INET6) {
            if (address->PrefixOrigin == IpPrefixOriginRouterAdvertisement &&
                address->SuffixOrigin == IpSuffixOriginRandom) {
              ip_address_attributes |= IP_ADDRESS_ATTRIBUTE_TEMPORARY;
            }
            if (address->PreferredLifetime == 0) {
              ip_address_attributes |= IP_ADDRESS_ATTRIBUTE_DEPRECATED;
            }
          }
          networks->push_back(NetworkInterface(
              adapter->AdapterName,
              base::SysWideToNativeMB(adapter->FriendlyName), index,
              GetNetworkInterfaceType(adapter->IfType), endpoint.address(),
              prefix_length, ip_address_attributes, mac_address));
        }
      }
    }
  }
  return true;
}

}  // namespace internal

bool GetNetworkList(NetworkInterfaceList* networks, int policy) {
  // Max number of times to retry GetAdaptersAddresses due to
  // ERROR_BUFFER_OVERFLOW. If GetAdaptersAddresses returns this indefinitely
  // due to an unforseen reason, we don't want to be stuck in an endless loop.
  static constexpr int MAX_GETADAPTERSADDRESSES_TRIES = 10;
  // Use an initial buffer size of 15KB, as recommended by MSDN. See:
  // https://msdn.microsoft.com/en-us/library/windows/desktop/aa365915(v=vs.85).aspx
  static constexpr int INITIAL_BUFFER_SIZE = 15000;

  ULONG len = INITIAL_BUFFER_SIZE;
  ULONG flags = 0;
  // Initial buffer allocated on stack.
  char initial_buf[INITIAL_BUFFER_SIZE];
  // Dynamic buffer in case initial buffer isn't large enough.
  base::HeapArray<char> buf;

  IP_ADAPTER_ADDRESSES* adapters = nullptr;
  {
    // GetAdaptersAddresses() may require IO operations.
    base::ScopedBlockingCall scoped_blocking_call(
        FROM_HERE, base::BlockingType::MAY_BLOCK);

    adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(&initial_buf);
    ULONG result =
        GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, adapters, &len);

    // If we get ERROR_BUFFER_OVERFLOW, call GetAdaptersAddresses in a loop,
    // because the required size may increase between successive calls,
    // resulting in ERROR_BUFFER_OVERFLOW multiple times.
    for (int tries = 1; result == ERROR_BUFFER_OVERFLOW &&
                        tries < MAX_GETADAPTERSADDRESSES_TRIES;
         ++tries) {
      buf = base::HeapArray<char>::Uninit(len);
      adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());
      result = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, adapters, &len);
    }

    if (result == ERROR_NO_DATA) {
      // There are 0 networks.
      return true;
    } else if (result != NO_ERROR) {
      LOG(ERROR) << "GetAdaptersAddresses failed: " << result;
      return false;
    }
  }

  return internal::GetNetworkListImpl(networks, policy, adapters);
}

// Note: There is no need to explicitly set the options back
// as the OS will automatically set them back when the WlanHandle
// is closed.
class WifiOptionSetter : public ScopedWifiOptions {
 public:
  WifiOptionSetter(int options) {
    const internal::WlanApi& wlanapi = internal::WlanApi::GetInstance();
    if (!wlanapi.initialized)
      return;

    DWORD cur_version = 0;
    const DWORD kMaxClientVersion = 2;
    DWORD result = wlanapi.OpenHandle(
        kMaxClientVersion, &cur_version, &client_);
    if (result != ERROR_SUCCESS)
      return;

    WLAN_INTERFACE_INFO_LIST* interface_list_ptr = nullptr;
    result = wlanapi.enum_interfaces_func(client_.Get(), nullptr,
                                          &interface_list_ptr);
    if (result != ERROR_SUCCESS)
      return;
    std::unique_ptr<WLAN_INTERFACE_INFO_LIST, internal::WlanApiDeleter>
        interface_list(interface_list_ptr);

    for (unsigned i = 0; i < interface_list->dwNumberOfItems; ++i) {
      WLAN_INTERFACE_INFO* info = &interface_list->InterfaceInfo[i];
      if (options & WIFI_OPTIONS_DISABLE_SCAN) {
        BOOL data = false;
        wlanapi.set_interface_func(client_.Get(), &info->InterfaceGuid,
                                   wlan_intf_opcode_background_scan_enabled,
                                   sizeof(data), &data, nullptr);
      }
      if (options & WIFI_OPTIONS_MEDIA_STREAMING_MODE) {
        BOOL data = true;
        wlanapi.set_interface_func(client_.Get(), &info->InterfaceGuid,
                                   wlan_intf_opcode_media_streaming_mode,
                                   sizeof(data), &data, nullptr);
      }
    }
  }

 private:
  internal::WlanHandle client_;
};

std::unique_ptr<ScopedWifiOptions> SetWifiOptions(int options) {
  return std::make_unique<WifiOptionSetter>(options);
}

std::string GetWifiSSID() {
  auto conn_info = GetConnectionAttributes();

  if (!conn_info.get())
    return "";

  const DOT11_SSID dot11_ssid = conn_info->wlanAssociationAttributes.dot11Ssid;
  return std::string(reinterpret_cast<const char*>(dot11_ssid.ucSSID),
                     dot11_ssid.uSSIDLength);
}

}  // namespace net

"""

```