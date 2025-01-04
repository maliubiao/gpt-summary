Response:
Let's break down the thought process to analyze this C code for frida.

1. **Understand the Goal:** The primary goal is to analyze the provided C source code (`device-monitor-windows.c`) and explain its functionality, its relation to reverse engineering, its use of low-level OS concepts, any logical inferences, potential user errors, and how a user might reach this code.

2. **Initial Code Scan and High-Level Understanding:**  Start by skimming the code to get a general idea of its purpose. Look for keywords, function names, and data structures. I see:
    * Includes like `<devguid.h>`, `<iphlpapi.h>`, `<setupapi.h>`, `<windns.h>` – immediately suggests interaction with Windows device management and network functionalities.
    * Data structures like `FridaMobileDeviceInfo`, `FridaImageDeviceInfo`, `FridaDeviceInfo` –  strongly indicates the code is about detecting and managing devices.
    * Functions like `frida_foreach_usb_device`, `find_mobile_device_by_udid`, `find_image_device_by_location` – points to device enumeration and identification.
    * The presence of "pairing browser" in function names like `_frida_fruity_windows_pairing_browser_enumerate_network_interfaces` hints at network device discovery for pairing.

3. **Deconstructing Functionality - Top Down and Bottom Up:**
    * **Entry Points:** Look for functions that are likely to be called from outside the file. Functions starting with `_frida_fruity_windows_pairing_browser_` seem to be public interfaces. Focus on `_frida_fruity_windows_pairing_browser_enumerate_network_interfaces`, `_frida_fruity_windows_pairing_browser_monitor_create_backend`, and `_frida_fruity_windows_pairing_browser_monitor_destroy_backend`. These appear to handle network interface enumeration and starting/stopping a monitor.
    * **Core Logic:** Identify the central algorithms. `frida_foreach_usb_device` is clearly a core function for iterating through USB devices. The `find_mobile_device_by_udid` and `find_image_device_by_location` functions are key to identifying specific device types.
    * **Helper Functions:** Recognize utility functions like `frida_read_device_registry_string_property`, `frida_read_registry_string`, `frida_read_registry_multi_string`, `frida_try_get_dns_api`. These provide lower-level functionalities.
    * **Data Flow:**  Trace how data moves between functions. For example, how does the UDID get from the `_frida_fruity_usbmux_backend_extract_details_for_device` function to the device matching logic?

4. **Relating to Reverse Engineering:**
    * **Device Detection:**  Frida needs to know *what* devices are available to instrument. This code provides that foundational capability on Windows.
    * **Device Identification:**  Knowing the UDID and other device properties is crucial for targeting specific devices during reverse engineering tasks.
    * **System API Interaction:**  The code heavily uses Windows APIs (`SetupDi...`, `GetAdaptersAddresses`, `DnsServiceBrowse`, Registry functions). Understanding how Frida interacts with these APIs is relevant to reverse engineering Frida itself.

5. **Identifying Low-Level Concepts:**
    * **Windows APIs:**  List the key Windows APIs and what they do (Device Manager, Network interfaces, DNS, Registry).
    * **GUIDs:** Explain the role of GUIDs in identifying device classes.
    * **Handles:** Explain the use of `HDEVINFO`, `HKEY`, and `DNS_SERVICE_CANCEL`.
    * **Pointers and Memory Management:** Note the use of `g_malloc`, `g_free`, `g_new`, `g_slice_new0`, and how memory is allocated and deallocated, particularly with wide characters (`WCHAR`).
    * **Unicode:** The usage of `WCHAR` and functions like `g_utf8_to_utf16` highlights the importance of handling Unicode in Windows.
    * **Networking Concepts:**  Mention IP addresses, network interfaces, and DNS-SD.

6. **Logical Inference and Assumptions:**
    * **Input/Output:** Consider the inputs to key functions (e.g., UDID to `find_mobile_device_by_udid`) and what they output (pointers to device info structures). What happens if a device isn't found?
    * **Assumptions:** The code assumes certain device properties exist in the registry. It assumes the presence of the `dnsapi.dll`.

7. **User and Programming Errors:**
    * **Memory Leaks:**  If `g_free` is missed, especially in error paths.
    * **Incorrect API Usage:**  Calling Windows APIs with incorrect parameters.
    * **Unicode Handling:** Mishandling UTF-8 to UTF-16 conversions.
    * **Error Handling:**  The code checks return values, but are all error conditions handled gracefully?
    * **Permissions:** Accessing device information or the registry might require specific permissions.

8. **User Operations Leading to This Code:**  Think about the user's perspective:
    * Starting Frida.
    * Connecting to a device (especially an iOS device over USB or network).
    * Listing available devices.
    * The pairing process itself.

9. **Structuring the Answer:** Organize the findings into clear sections based on the prompt's requirements: functionality, relation to reverse engineering, low-level details, logical inferences, user errors, and user path. Use bullet points and examples for clarity.

10. **Refinement and Review:**  Read through the analysis to ensure accuracy, completeness, and clarity. Are the examples relevant and easy to understand? Is the language precise?  Are there any missing pieces or areas that could be explained better?  For example, initially, I might not have emphasized the DNS-SD aspect as much, but seeing the `DnsServiceBrowse` function calls, I would revisit and add more detail about network-based device discovery.

This iterative process of scanning, deconstructing, relating, identifying, inferring, and refining helps in building a comprehensive analysis of the code.
这个 C 源代码文件 `device-monitor-windows.c` 是 Frida 工具中用于监控 Windows 系统上设备连接和断开的模块，特别是针对 iOS 设备的 USB 连接和网络配对服务发现。它利用 Windows API 来枚举设备，读取设备信息，并监听网络上的配对服务。

**功能列表:**

1. **枚举 USB 设备:** 使用 Windows 的 `SetupDiGetClassDevsW` 和相关的 SetupAPI 函数来查找特定 GUID 对应的设备，例如 Apple Mobile USB Driver (`GUID_APPLE_USB`) 和图像设备 (`GUID_DEVCLASS_IMAGE`)。
2. **读取设备属性:**  通过 `SetupDiGetDeviceRegistryPropertyW` 读取设备的注册表属性，如设备路径、实例 ID、友好名称和位置信息。
3. **查找特定 UDID 的移动设备:**  `find_mobile_device_by_udid` 函数通过枚举 USB 设备，比较设备的实例 ID 或设备路径中是否包含指定的 UDID 来查找特定的 iOS 设备。
4. **查找特定位置的图像设备:** `find_image_device_by_location` 函数通过枚举图像设备，比较设备的位置信息来查找匹配的设备。
5. **提取设备详细信息:** `_frida_fruity_usbmux_backend_extract_details_for_device` 函数根据产品 ID 和 UDID，尝试查找移动设备和相关的图像设备，从而获取设备的名称和图标。如果找到关联的图像设备，则使用其友好名称和图标。
6. **监控网络配对服务:**  使用 DNS-SD (DNS Service Discovery) 技术，通过调用 `DnsServiceBrowse` 函数来监听网络上广播的 Frida 配对服务。
7. **获取网络接口信息:** `_frida_fruity_windows_pairing_browser_enumerate_network_interfaces` 函数使用 `GetAdaptersAddresses` 获取系统网络接口的信息，用于后续的网络服务监听。
8. **创建和销毁网络监控后端:** `_frida_fruity_windows_pairing_browser_monitor_create_backend` 和 `_frida_fruity_windows_pairing_browser_monitor_destroy_backend` 函数负责启动和停止 DNS-SD 的监听。
9. **回调机制:** 使用回调函数 (`FridaFruityWindowsPairingBrowserResultCallback`, `FridaFruityWindowsPairingBrowserNetifFoundFunc`) 将发现的设备信息或网络接口信息传递给 Frida 的其他模块。

**与逆向方法的关系及举例说明:**

这个文件是 Frida 用于发现目标设备的关键部分，这对于动态 instrumentation 来说至关重要。逆向工程师通常需要连接到特定的设备进行分析和修改，这个文件提供的功能就是实现这一点的基础。

* **设备识别:** 在逆向 iOS 应用时，需要连接到目标 iOS 设备。这个文件中的 `find_mobile_device_by_udid` 函数允许 Frida 根据设备的 UDID 精确地找到目标设备。例如，逆向工程师在 USB 连接设备后，Frida 可以通过这个函数找到该设备的句柄，从而进行后续的内存读取、函数 hook 等操作。
* **获取设备信息:**  `_frida_fruity_usbmux_backend_extract_details_for_device` 可以获取设备的名称和图标，这有助于用户在多个连接设备中快速识别目标。在 Frida 的 UI 或命令行界面中，会显示这些信息，方便用户选择要连接的设备进行逆向分析。
* **网络配对:** 对于无法通过 USB 连接的设备，例如虚拟机或远程设备，可以通过网络配对连接。这个文件中的 DNS-SD 功能允许 Frida 自动发现网络上的 Frida 服务，简化了连接过程。逆向工程师不需要手动输入 IP 地址和端口，Frida 可以自动找到可用的目标。

**涉及的二进制底层、Linux、Android 内核及框架的知识及举例说明:**

虽然这个文件是 Windows 平台的代码，但它与跨平台的设备连接和发现概念是相关的。

* **二进制底层 (Windows):**
    * **Windows API:** 大量使用了 Windows API，例如 SetupAPI 用于设备管理，Iphlpapi 用于网络接口管理，Windns 用于 DNS 操作。这些 API 都是与操作系统内核交互的底层接口。例如，`SetupDiGetClassDevsW` 最终会调用内核驱动程序来枚举设备。
    * **注册表操作:** 使用 `SetupDiOpenDevRegKey` 和 `RegQueryValueExW` 等函数读取设备相关的注册表信息。注册表是 Windows 系统配置的核心，理解其结构和访问方式对于理解设备管理至关重要。
    * **GUID (Globally Unique Identifier):** 使用 GUID 来标识设备类，这是 Windows 设备驱动模型的基础。例如，`GUID_APPLE_USB` 用于查找 Apple 的 USB 设备。

* **Linux/Android 内核及框架 (概念关联):**
    * **设备枚举:**  尽管实现方式不同，但 Linux 和 Android 也有类似的设备枚举机制，例如使用 `udev` 或 Android 的 `ServiceManager` 和 HAL (Hardware Abstraction Layer)。Frida 在 Linux 和 Android 平台上也有相应的代码来实现设备发现。
    * **USB 通信:**  虽然这个文件没有直接涉及 USB 通信的细节，但它为后续的 USB 通信奠定了基础。在 Linux 和 Android 上，需要使用 libusb 或 Android 的 USB Host API 进行 USB 通信。
    * **网络服务发现:** DNS-SD 是一种跨平台的网络服务发现协议，在 macOS、Linux 和 Android 上也有应用。虽然具体的 API 调用不同，但基本原理相同。在 Linux 上可以使用 Avahi，在 Android 上可以使用 NsdManager。

**逻辑推理、假设输入与输出:**

* **假设输入 (针对 `find_mobile_device_by_udid`):**
    * `udid`: 一个表示 iOS 设备唯一标识符的宽字符串，例如 `E66BDF77-026A-4968-B62E-1D55E29131A1`。
* **输出:**
    * 如果找到匹配的设备，返回一个指向 `FridaMobileDeviceInfo` 结构的指针，其中 `location` 成员包含了设备的路径信息。
    * 如果未找到匹配的设备，返回 `NULL`。
* **逻辑推理:**
    1. 函数遍历所有属于 `GUID_APPLE_USB` 设备类的设备。
    2. 对于每个设备，尝试从其 `instance_id` 或 `device_path` 中提取可能的 UDID 部分。
    3. 将提取出的 UDID 与输入的 `udid` 进行比较（忽略大小写）。
    4. 如果匹配，则分配内存创建一个 `FridaMobileDeviceInfo` 结构，复制设备的 `location` 信息，并返回该结构的指针。
    5. 如果遍历完所有设备都没有匹配，则返回 `NULL`。

**用户或编程常见的使用错误及举例说明:**

* **权限问题:** 用户运行 Frida 的进程没有足够的权限来枚举设备或访问注册表。例如，在某些环境下可能需要管理员权限才能访问设备信息。
    * **错误信息:**  `SetupDiGetClassDevsW` 返回 `INVALID_HANDLE_VALUE`，`GetLastError()` 返回 `ERROR_ACCESS_DENIED`。
    * **解决方法:** 尝试以管理员身份运行 Frida。
* **驱动未安装:**  目标设备的驱动程序没有正确安装，导致 Windows 无法识别该设备。
    * **错误现象:**  即使设备已连接，Frida 也无法找到该设备。
    * **解决方法:** 确保目标设备的驱动程序已正确安装。对于 iOS 设备，需要安装 iTunes 或 Apple Mobile Device USB Driver。
* **UDID 错误:** 用户提供的 UDID 不正确或包含格式错误。
    * **错误现象:** `find_mobile_device_by_udid` 函数始终返回 `NULL`。
    * **解决方法:** 仔细检查提供的 UDID 是否与目标设备的实际 UDID 一致。
* **网络配置问题:**  网络配对服务发现失败，可能是由于防火墙阻止了 UDP 广播，或者设备和主机不在同一个网络中。
    * **错误现象:** Frida 无法通过网络发现目标设备。
    * **解决方法:** 检查防火墙设置，确保允许 DNS-SD 相关的 UDP 端口通信。确保主机和目标设备在同一个局域网内。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户启动 Frida:**  用户在命令行或通过脚本启动 Frida 工具。
2. **Frida 尝试连接到设备:**  用户可能通过指定设备 UDID (`frida -U <udid> ...`) 或让 Frida 自动发现设备 (`frida-ls-devices`) 来尝试连接。
3. **设备枚举和识别:**
    * 如果是通过 USB 连接，Frida 会调用 `_frida_fruity_usbmux_backend_extract_details_for_device` 函数，该函数会间接调用 `find_mobile_device_by_udid` 来查找 USB 连接的 iOS 设备。
    * 如果是尝试通过网络连接，Frida 会调用 `_frida_fruity_windows_pairing_browser_enumerate_network_interfaces` 获取网络接口信息，然后调用 `_frida_fruity_windows_pairing_browser_monitor_create_backend` 启动 DNS-SD 监听。
4. **`frida_foreach_usb_device` 的调用:**  无论是查找特定 UDID 的设备还是枚举所有 USB 设备，`frida_foreach_usb_device` 函数都会被调用，它使用 SetupAPI 函数来遍历系统中的 USB 设备。
5. **读取设备信息:** 在 `frida_foreach_usb_device` 的循环中，会调用 `SetupDiGetDeviceInterfaceDetailW` 获取设备接口详细信息，并调用 `frida_read_device_registry_string_property` 读取设备的友好名称和位置信息。
6. **匹配和返回:** `compare_udid_and_create_mobile_device_info_if_matching` 或 `compare_location_and_create_image_device_info_if_matching` 函数会被作为回调传递给 `frida_foreach_usb_device`，用于比较设备信息并创建相应的设备信息结构。
7. **网络服务发现回调:** 如果是网络配对，当网络上广播了 Frida 服务时，`frida_fruity_windows_pairing_browser_on_browse_results` 函数会被调用，将发现的服务信息传递给 Frida。

**作为调试线索:**

* **设备未找到:** 如果 Frida 无法连接到设备，可以检查 `find_mobile_device_by_udid` 函数是否返回 `NULL`，以及 `GetLastError()` 的值，来判断是 UDID 错误、驱动问题还是权限问题。
* **网络配对失败:**  可以检查 `_frida_fruity_windows_pairing_browser_monitor_create_backend` 的返回值是否为 `NULL`，以及 `DnsServiceBrowse` 的返回值，来判断 DNS-SD 监听是否启动成功。可以使用网络抓包工具（如 Wireshark）来查看是否有 DNS-SD 查询和响应。
* **设备信息不正确:**  如果 Frida 显示的设备名称或图标不正确，可以检查 `_frida_fruity_usbmux_backend_extract_details_for_device` 函数中读取注册表信息的部分，看是否能正确读取到 FriendlyName 和 Icons。

总而言之，`device-monitor-windows.c` 是 Frida 在 Windows 平台上进行设备发现和监控的核心模块，它利用了 Windows 提供的设备管理和网络 API，为 Frida 的动态 instrumentation 功能提供了基础。理解这个文件的功能和实现细节，有助于理解 Frida 的工作原理，并能帮助定位设备连接和发现过程中出现的问题。

Prompt: 
```
这是目录为frida/subprojects/frida-core/src/fruity/device-monitor-windows.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
#include "frida-core.h"

#include "../windows/icon-helpers.h"

#include <devguid.h>
#include <iphlpapi.h>
#include <setupapi.h>
#include <windns.h>

typedef struct _FridaPairingBrowserBackend FridaPairingBrowserBackend;

typedef struct _FridaMobileDeviceInfo FridaMobileDeviceInfo;
typedef struct _FridaImageDeviceInfo FridaImageDeviceInfo;

typedef struct _FridaFindMobileDeviceContext FridaFindMobileDeviceContext;
typedef struct _FridaFindImageDeviceContext FridaFindImageDeviceContext;

typedef struct _FridaDeviceInfo FridaDeviceInfo;

typedef struct _FridaDnsApi FridaDnsApi;

typedef gboolean (* FridaEnumerateDeviceFunc) (const FridaDeviceInfo * device_info, gpointer user_data);

struct _FridaPairingBrowserBackend
{
  FridaFruityWindowsPairingBrowserResultCallback callback;
  gpointer callback_target;

  DNS_SERVICE_CANCEL browse_handle;
};

struct _FridaMobileDeviceInfo
{
  WCHAR * location;
};

struct _FridaImageDeviceInfo
{
  WCHAR * friendly_name;
  WCHAR * icon_url;
};

struct _FridaFindMobileDeviceContext
{
  const WCHAR * udid;
  FridaMobileDeviceInfo * mobile_device;
};

struct _FridaFindImageDeviceContext
{
  const WCHAR * location;
  FridaImageDeviceInfo * image_device;
};

struct _FridaDeviceInfo
{
  WCHAR * device_path;
  WCHAR * instance_id;
  WCHAR * friendly_name;
  WCHAR * location;

  HDEVINFO device_info_set;
  PSP_DEVINFO_DATA device_info_data;
};

struct _FridaDnsApi
{
  DNS_STATUS (WINAPI * browse) (DNS_SERVICE_BROWSE_REQUEST * request, DNS_SERVICE_CANCEL * cancel);
  DNS_STATUS (WINAPI * browse_cancel) (DNS_SERVICE_CANCEL * cancel_handle);
};

static void WINAPI frida_fruity_windows_pairing_browser_on_browse_results (void * query_context, DNS_QUERY_RESULT * query_results);

static FridaMobileDeviceInfo * find_mobile_device_by_udid (const WCHAR * udid);
static FridaImageDeviceInfo * find_image_device_by_location (const WCHAR * location);

static gboolean compare_udid_and_create_mobile_device_info_if_matching (const FridaDeviceInfo * device_info, gpointer user_data);
static gboolean compare_location_and_create_image_device_info_if_matching (const FridaDeviceInfo * device_info, gpointer user_data);

FridaMobileDeviceInfo * frida_mobile_device_info_new (WCHAR * location);
void frida_mobile_device_info_free (FridaMobileDeviceInfo * mdev);

FridaImageDeviceInfo * frida_image_device_info_new (WCHAR * friendly_name, WCHAR * icon_url);
void frida_image_device_info_free (FridaImageDeviceInfo * idev);

static void frida_foreach_usb_device (const GUID * guid, FridaEnumerateDeviceFunc func, gpointer user_data);

static WCHAR * frida_read_device_registry_string_property (HANDLE info_set, SP_DEVINFO_DATA * info_data, DWORD prop_id);
static WCHAR * frida_read_registry_string (HKEY key, WCHAR * value_name);
static WCHAR * frida_read_registry_multi_string (HKEY key, WCHAR * value_name);
static gpointer frida_read_registry_value (HKEY key, WCHAR * value_name, DWORD expected_type);

static FridaDnsApi * frida_try_get_dns_api (void);

static GUID GUID_APPLE_USB = { 0xF0B32BE3, 0x6678, 0x4879, { 0x92, 0x30, 0x0E4, 0x38, 0x45, 0xD8, 0x05, 0xEE } };

void
_frida_fruity_windows_pairing_browser_enumerate_network_interfaces (FridaFruityWindowsPairingBrowserNetifFoundFunc func,
    gpointer func_target)
{
  IP_ADAPTER_ADDRESSES * adapters;
  ULONG buffer_size, result;
  IP_ADAPTER_ADDRESSES_LH * adapter;

  if (frida_try_get_dns_api () == NULL)
    return;

  buffer_size = 32768;
  adapters = g_malloc (buffer_size);

  do
  {
    result = GetAdaptersAddresses (AF_INET6, 0, NULL, adapters, &buffer_size);
    if (result != ERROR_BUFFER_OVERFLOW)
      break;
    adapters = g_realloc (adapters, buffer_size);
  }
  while (result == ERROR_BUFFER_OVERFLOW);
  if (result != ERROR_SUCCESS)
    goto beach;

  for (adapter = adapters; adapter != NULL; adapter = adapter->Next)
  {
    SOCKET_ADDRESS * raw_addr;
    GInetSocketAddress * addr;

    if (adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
      continue;

    if (adapter->FirstUnicastAddress == NULL)
      continue;

    raw_addr = &adapter->FirstUnicastAddress->Address;
    addr = G_INET_SOCKET_ADDRESS (g_socket_address_new_from_native (raw_addr->lpSockaddr, raw_addr->iSockaddrLength));

    func (adapter->IfIndex, adapter->AdapterName, addr, func_target);
  }

beach:
  g_free (adapters);
}

void *
_frida_fruity_windows_pairing_browser_monitor_create_backend (gulong interface_index,
    FridaFruityWindowsPairingBrowserResultCallback callback, gpointer callback_target)
{
  FridaPairingBrowserBackend * backend;
  FridaDnsApi * api;
  DNS_SERVICE_BROWSE_REQUEST r = { 0, };

  api = frida_try_get_dns_api ();
  if (api == NULL)
    return NULL;

  backend = g_slice_new0 (FridaPairingBrowserBackend);
  backend->callback = callback;
  backend->callback_target = callback_target;

  r.Version = DNS_QUERY_REQUEST_VERSION2;
  r.InterfaceIndex = interface_index;
  r.QueryName = G_PASTE (L, FRIDA_FRUITY_PAIRING_SERVICE_DNS_SD_NAME);
  r.pBrowseCallbackV2 = frida_fruity_windows_pairing_browser_on_browse_results;
  r.pQueryContext = backend;

  if (api->browse (&r, &backend->browse_handle) != DNS_REQUEST_PENDING)
  {
    g_slice_free (FridaPairingBrowserBackend, backend);
    return NULL;
  }

  return backend;
}

void
_frida_fruity_windows_pairing_browser_monitor_destroy_backend (void * opaque_backend)
{
  FridaPairingBrowserBackend * backend = opaque_backend;

  if (backend == NULL)
    return;

  frida_try_get_dns_api ()->browse_cancel (&backend->browse_handle);

  g_slice_free (FridaPairingBrowserBackend, backend);
}

static void WINAPI
frida_fruity_windows_pairing_browser_on_browse_results (void * query_context, DNS_QUERY_RESULT * query_results)
{
  FridaPairingBrowserBackend * backend = query_context;

  backend->callback (query_results, backend->callback_target);
}

void
_frida_fruity_usbmux_backend_extract_details_for_device (gint product_id, const char * udid, char ** name, GVariant ** icon,
    GError ** error)
{
  gboolean result = FALSE;
  GString * udid_plain;
  const gchar * cursor;
  WCHAR * udid_utf16 = NULL;
  FridaMobileDeviceInfo * mdev = NULL;
  FridaImageDeviceInfo * idev = NULL;
  GVariant * idev_icon = NULL;

  udid_plain = g_string_sized_new (40);
  for (cursor = udid; *cursor != '\0'; cursor++)
  {
    gchar ch = *cursor;
    if (ch != '-')
      g_string_append_c (udid_plain, ch);
  }

  udid_utf16 = (WCHAR *) g_utf8_to_utf16 (udid_plain->str, udid_plain->len, NULL, NULL, NULL);

  mdev = find_mobile_device_by_udid (udid_utf16);
  if (mdev == NULL)
    goto beach;

  idev = find_image_device_by_location (mdev->location);
  if (idev != NULL)
  {
    idev_icon = _frida_icon_from_resource_url (idev->icon_url, FRIDA_ICON_SMALL);
  }

  if (idev_icon != NULL)
  {
    *name = g_utf16_to_utf8 ((gunichar2 *) idev->friendly_name, -1, NULL, NULL, NULL);
    *icon = idev_icon;
  }
  else
  {
    /* TODO: grab metadata from iTunes instead of relying on having an image device */
    *name = g_strdup ("iOS Device");
    *icon = NULL;
  }
  result = TRUE;

beach:
  if (!result)
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_NOT_SUPPORTED,
        "Unable to extract details for device by UDID '%s'", udid);
  }

  frida_image_device_info_free (idev);
  frida_mobile_device_info_free (mdev);
  g_free (udid_utf16);
  g_string_free (udid_plain, TRUE);
}

static FridaMobileDeviceInfo *
find_mobile_device_by_udid (const WCHAR * udid)
{
  FridaFindMobileDeviceContext ctx;

  ctx.udid = udid;
  ctx.mobile_device = NULL;

  frida_foreach_usb_device (&GUID_APPLE_USB, compare_udid_and_create_mobile_device_info_if_matching, &ctx);

  return ctx.mobile_device;
}

static FridaImageDeviceInfo *
find_image_device_by_location (const WCHAR * location)
{
  FridaFindImageDeviceContext ctx;

  ctx.location = location;
  ctx.image_device = NULL;

  frida_foreach_usb_device (&GUID_DEVCLASS_IMAGE, compare_location_and_create_image_device_info_if_matching, &ctx);

  return ctx.image_device;
}

static gboolean
compare_udid_and_create_mobile_device_info_if_matching (const FridaDeviceInfo * device_info, gpointer user_data)
{
  FridaFindMobileDeviceContext * ctx = (FridaFindMobileDeviceContext *) user_data;
  WCHAR * udid, * location;
  size_t udid_len;

  udid = wcsrchr (device_info->instance_id, L'\\');
  if (udid == NULL)
    goto try_device_path;
  udid++;

  if (_wcsicmp (udid, ctx->udid) == 0)
    goto match;

try_device_path:
  udid = device_info->device_path;
  if (udid == NULL)
    goto keep_looking;

  udid_len = wcslen (ctx->udid);
  while (*udid != L'\0')
  {
    if (_wcsnicmp (udid, ctx->udid, udid_len) == 0)
      goto match;
    udid++;
  }

  goto keep_looking;

match:
  location = (WCHAR *) g_memdup2 (device_info->location, ((guint) wcslen (device_info->location) + 1) * sizeof (WCHAR));
  ctx->mobile_device = frida_mobile_device_info_new (location);

  return FALSE;

keep_looking:
  return TRUE;
}

static gboolean
compare_location_and_create_image_device_info_if_matching (const FridaDeviceInfo * device_info, gpointer user_data)
{
  FridaFindImageDeviceContext * ctx = (FridaFindImageDeviceContext *) user_data;
  HKEY devkey = (HKEY) INVALID_HANDLE_VALUE;
  WCHAR * friendly_name = NULL;
  WCHAR * icon_url = NULL;

  if (_wcsicmp (device_info->location, ctx->location) != 0)
    goto keep_looking;

  devkey = SetupDiOpenDevRegKey (device_info->device_info_set, device_info->device_info_data, DICS_FLAG_GLOBAL, 0, DIREG_DEV, KEY_READ);
  if (devkey == INVALID_HANDLE_VALUE)
    goto keep_looking;

  friendly_name = frida_read_registry_string (devkey, L"FriendlyName");
  if (friendly_name == NULL)
  {
    friendly_name = frida_read_registry_string (devkey, L"Label");
    if (friendly_name == NULL)
      goto keep_looking;
  }

  icon_url = frida_read_registry_multi_string (devkey, L"Icons");
  if (icon_url == NULL)
    goto keep_looking;

  ctx->image_device = frida_image_device_info_new (friendly_name, icon_url);

  RegCloseKey (devkey);
  return FALSE;

keep_looking:
  g_free (icon_url);
  g_free (friendly_name);
  if (devkey != INVALID_HANDLE_VALUE)
    RegCloseKey (devkey);
  return TRUE;
}

FridaMobileDeviceInfo *
frida_mobile_device_info_new (WCHAR * location)
{
  FridaMobileDeviceInfo * mdev;

  mdev = g_new (FridaMobileDeviceInfo, 1);
  mdev->location = location;

  return mdev;
}

void
frida_mobile_device_info_free (FridaMobileDeviceInfo * mdev)
{
  if (mdev == NULL)
    return;

  g_free (mdev->location);
  g_free (mdev);
}

FridaImageDeviceInfo *
frida_image_device_info_new (WCHAR * friendly_name, WCHAR * icon_url)
{
  FridaImageDeviceInfo * idev;

  idev = g_new (FridaImageDeviceInfo, 1);
  idev->friendly_name = friendly_name;
  idev->icon_url = icon_url;

  return idev;
}

void
frida_image_device_info_free (FridaImageDeviceInfo * idev)
{
  if (idev == NULL)
    return;

  g_free (idev->icon_url);
  g_free (idev->friendly_name);
  g_free (idev);
}

static void
frida_foreach_usb_device (const GUID * guid, FridaEnumerateDeviceFunc func, gpointer user_data)
{
  HANDLE info_set;
  gboolean carry_on = TRUE;
  guint member_index;

  info_set = SetupDiGetClassDevsW (guid, NULL, NULL, DIGCF_DEVICEINTERFACE | DIGCF_PRESENT);
  if (info_set == INVALID_HANDLE_VALUE)
    goto beach;

  for (member_index = 0; carry_on; member_index++)
  {
    SP_DEVICE_INTERFACE_DATA iface_data = { 0, };
    SP_DEVINFO_DATA info_data = { 0, };
    DWORD detail_size;
    SP_DEVICE_INTERFACE_DETAIL_DATA_W * detail_data = NULL;
    BOOL success;
    FridaDeviceInfo device_info = { 0, };
    DWORD instance_id_size;

    iface_data.cbSize = sizeof (iface_data);
    if (!SetupDiEnumDeviceInterfaces (info_set, NULL, guid, member_index, &iface_data))
      break;

    info_data.cbSize = sizeof (info_data);
    success = SetupDiGetDeviceInterfaceDetailW (info_set, &iface_data, NULL, 0, &detail_size, &info_data);
    if (!success && GetLastError () != ERROR_INSUFFICIENT_BUFFER)
      goto skip_device;

    detail_data = (SP_DEVICE_INTERFACE_DETAIL_DATA_W *) g_malloc (detail_size);
    detail_data->cbSize = sizeof (SP_DEVICE_INTERFACE_DETAIL_DATA_W);
    success = SetupDiGetDeviceInterfaceDetailW (info_set, &iface_data, detail_data, detail_size, NULL, &info_data);
    if (!success)
      goto skip_device;

    device_info.device_path = detail_data->DevicePath;

    success = SetupDiGetDeviceInstanceIdW (info_set, &info_data, NULL, 0, &instance_id_size);
    if (!success && GetLastError () != ERROR_INSUFFICIENT_BUFFER)
      goto skip_device;

    device_info.instance_id = (WCHAR *) g_malloc (instance_id_size * sizeof (WCHAR));
    success = SetupDiGetDeviceInstanceIdW (info_set, &info_data, device_info.instance_id, instance_id_size, NULL);
    if (!success)
      goto skip_device;

    device_info.friendly_name = frida_read_device_registry_string_property (info_set, &info_data, SPDRP_FRIENDLYNAME);

    device_info.location = frida_read_device_registry_string_property (info_set, &info_data, SPDRP_LOCATION_INFORMATION);
    if (device_info.location == NULL)
      goto skip_device;

    device_info.device_info_set = info_set;
    device_info.device_info_data = &info_data;

    carry_on = func (&device_info, user_data);

skip_device:
    g_free (device_info.location);
    g_free (device_info.friendly_name);
    g_free (device_info.instance_id);

    g_free (detail_data);
  }

beach:
  if (info_set != INVALID_HANDLE_VALUE)
    SetupDiDestroyDeviceInfoList (info_set);
}

static WCHAR *
frida_read_device_registry_string_property (HANDLE info_set, SP_DEVINFO_DATA * info_data, DWORD prop_id)
{
  gboolean success = FALSE;
  WCHAR * value_buffer = NULL;
  DWORD value_size;
  BOOL ret;

  ret = SetupDiGetDeviceRegistryPropertyW (info_set, info_data, prop_id, NULL, NULL, 0, &value_size);
  if (!ret && GetLastError () != ERROR_INSUFFICIENT_BUFFER)
    goto beach;

  value_buffer = (WCHAR *) g_malloc (value_size);
  if (!SetupDiGetDeviceRegistryPropertyW (info_set, info_data, prop_id, NULL, (PBYTE) value_buffer, value_size, NULL))
    goto beach;

  success = TRUE;

beach:
  if (!success)
  {
    g_free (value_buffer);
    value_buffer = NULL;
  }

  return value_buffer;
}

static WCHAR *
frida_read_registry_string (HKEY key, WCHAR * value_name)
{
  return (WCHAR *) frida_read_registry_value (key, value_name, REG_SZ);
}

static WCHAR *
frida_read_registry_multi_string (HKEY key, WCHAR * value_name)
{
  return (WCHAR *) frida_read_registry_value (key, value_name, REG_MULTI_SZ);
}

static gpointer
frida_read_registry_value (HKEY key, WCHAR * value_name, DWORD expected_type)
{
  gboolean success = FALSE;
  DWORD type;
  WCHAR * buffer = NULL;
  DWORD base_size = 0, real_size;
  LONG ret;

  ret = RegQueryValueExW (key, value_name, NULL, &type, NULL, &base_size);
  if (ret != ERROR_SUCCESS || type != expected_type)
    goto beach;

  if (type == REG_SZ)
    real_size = base_size + sizeof (WCHAR);
  else if (type == REG_MULTI_SZ)
    real_size = base_size + 2 * sizeof (WCHAR);
  else
    real_size = base_size;
  buffer = (WCHAR *) g_malloc0 (real_size);
  ret = RegQueryValueExW (key, value_name, NULL, &type, (LPBYTE) buffer, &base_size);
  if (ret != ERROR_SUCCESS || type != expected_type)
    goto beach;

  success = TRUE;

beach:
  if (!success)
  {
    g_free (buffer);
    buffer = NULL;
  }

  return buffer;
}

static FridaDnsApi *
frida_try_get_dns_api (void)
{
  static gsize api_value = 0;

  if (g_once_init_enter (&api_value))
  {
    HMODULE mod;
    FARPROC browse;
    FridaDnsApi * api = NULL;

    mod = GetModuleHandleW (L"dnsapi.dll");

    browse = GetProcAddress (mod, "DnsServiceBrowse");
    if (browse != NULL)
    {
      api = g_slice_new (FridaDnsApi);
      api->browse = (gpointer) browse;
      api->browse_cancel = (gpointer) GetProcAddress (mod, "DnsServiceBrowseCancel");
    }

    g_once_init_leave (&api_value, GPOINTER_TO_SIZE (api) + 1);
  }

  return GSIZE_TO_POINTER (api_value - 1);
}

"""

```