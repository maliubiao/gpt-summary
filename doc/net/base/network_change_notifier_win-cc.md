Response:
Let's break down the thought process for analyzing the `network_change_notifier_win.cc` file and generating the response.

**1. Understanding the Core Purpose:**

The filename and initial comments clearly point to this file's role: monitoring network changes on Windows. The `#include "net/base/network_change_notifier_win.h"` is the primary indicator of this.

**2. Identifying Key Components and Functionality:**

* **Windows-Specific:** The "Win" suffix and inclusion of `<winsock2.h>` and `<iphlpapi.h>` immediately signal that this is a Windows-specific implementation.
* **Event Handling:**  The use of `WSACreateEvent`, `NotifyAddrChange`, and the `addr_overlapped_` structure suggests an event-driven approach to detecting network changes. The `OnObjectSignaled` method confirms this.
* **Asynchronous Operations:** The use of `base::ThreadPool::CreateSequencedTaskRunner` and `PostTaskAndReplyWithResult` indicates asynchronous operations, likely to avoid blocking the main thread.
* **Connection Type and Cost:** The methods `RecomputeCurrentConnectionType`, `GetCurrentConnectionType`, `GetCurrentConnectionCost`, and `OnCostChanged` highlight the focus on determining the network's connection type (e.g., Wi-Fi, Ethernet, None) and cost (e.g., metered, unmetered).
* **Observer Pattern:** The `NotifyObserversOf...` methods clearly indicate the implementation of an observer pattern to inform other parts of Chromium about network changes.
* **Retry Mechanism:** The `WatchForAddressChange` function and the `kWatchForAddressChangeRetryIntervalMs` constant suggest a retry mechanism for handling potential failures in the Windows API calls.
* **Modern API Consideration:** The `RecomputeCurrentConnectionTypeModern` function and the feature flag check demonstrate an effort to use newer Windows APIs for improved functionality.

**3. Analyzing Specific Methods and Logic:**

* **`RecomputeCurrentConnectionType`:** This is a critical function. The comments comparing different approaches (InternetGetConnectedState, adapter enumeration, namespace providers) were very helpful in understanding the chosen method and its rationale. The newer `RecomputeCurrentConnectionTypeModern` using `GetNetworkConnectivityHint` is also important.
* **`WatchForAddressChange`:**  The retry logic and the handling of `sequential_failures_` are key aspects to note.
* **`NotifyObservers` and related methods:**  Understanding the flow of notifications, the use of timers (`timer_`), and the `offline_polls_` counter is crucial.

**4. Considering the Relationship with JavaScript:**

* **Indirect Interaction:**  Network changes detected by this code ultimately affect what JavaScript running in a web page can do. For example, if the network goes offline, JavaScript fetch requests will fail. If the connection is metered, the browser might throttle resource loading, impacting JavaScript performance.
* **No Direct API:**  There's no direct JavaScript API that directly calls into this C++ code. Instead, the changes are communicated internally within Chromium and eventually reflected in the Network Information API available to JavaScript.

**5. Thinking About Logic and Potential Issues:**

* **Assumptions:** The `RecomputeCurrentConnectionType` method relies on certain assumptions about the presence of network providers indicating an online state. This is not foolproof.
* **Error Handling:** The code includes error logging for failed Windows API calls, but there's still a possibility of transient issues or edge cases.
* **Timing:** The delays in notifications are based on experimentation and might not be optimal in all scenarios.
* **User Errors:**  Misconfigured network settings are the most common user-related issues that would trigger the detection mechanisms in this code.

**6. Constructing the Response:**

* **Organize by Functionality:** Group related methods and concepts together to make the explanation clear.
* **Use Clear and Concise Language:** Avoid overly technical jargon where possible.
* **Provide Concrete Examples:**  The JavaScript examples illustrate the *indirect* relationship.
* **Explain the "Why":**  Don't just describe what the code does, but also *why* it does it (e.g., the rationale behind the chosen `RecomputeCurrentConnectionType` approach).
* **Address All Prompts:**  Ensure all parts of the original request are addressed (functionality, JavaScript relationship, logic/assumptions, user errors, debugging).
* **Review and Refine:**  Read through the generated response to ensure accuracy and clarity. For instance, initially, I might have overstated the direct relationship with JavaScript and needed to correct it to be more nuanced.

**Self-Correction Example During Thought Process:**

Initially, I might have thought, "This code directly provides network status to JavaScript."  However, upon closer inspection, I'd realize there's no direct function call from JavaScript into this C++ file. Instead, this C++ code updates internal Chromium state, which is then exposed to the renderer process (where JavaScript runs) through APIs like the Network Information API. This correction leads to a more accurate explanation of the relationship.
好的，让我们来分析一下 `net/base/network_change_notifier_win.cc` 这个 Chromium 网络栈的源代码文件。

**功能列举:**

该文件的主要功能是监听和报告 Windows 操作系统上的网络连接状态变化。更具体地说，它负责：

1. **检测 IP 地址变化:** 使用 Windows API `NotifyAddrChange` 监听本地计算机 IP 地址的改变。当 IP 地址发生变化时（例如，连接或断开 Wi-Fi，插入或拔出网线），它会收到通知。
2. **检测网络连接类型变化 (Online/Offline):**  通过 `RecomputeCurrentConnectionType` 方法来判断当前的网络连接状态是 "在线" (CONNECTION_UNKNOWN 或更具体的类型) 还是 "离线" (CONNECTION_NONE)。 这个判断基于枚举网络命名空间提供者 (`WSALookupServiceBegin`/`WSALookupServiceNext`)，或者使用更现代的 Windows API `GetNetworkConnectivityHint` (在 Windows 10 20H1 及以上版本)。
3. **检测网络连接成本变化 (Metered/Unmetered):**  通过 `NetworkCostChangeNotifierWin` 来监听网络连接的成本变化。这对于判断当前连接是否是按流量计费的非常重要。
4. **通知观察者:**  当检测到网络状态发生变化时，它会通知注册到 `NetworkChangeNotifier` 的观察者。这些观察者可能是 Chromium 的其他网络组件，甚至是渲染进程（用于通知网页）。
5. **处理瞬时离线状态:**  通过一定的延迟和多次轮询来处理网络连接的短暂中断，避免过于频繁地发出状态变化通知。
6. **使用异步操作:**  一些耗时的操作（如重新计算连接类型）会在独立的线程池中执行，以避免阻塞主线程。
7. **提供当前网络状态信息:**  提供方法 `GetCurrentConnectionType` 和 `GetCurrentConnectionCost` 来获取当前的网络连接类型和成本。

**与 JavaScript 功能的关系及举例说明:**

虽然这个 C++ 文件本身不直接包含 JavaScript 代码，但它所检测到的网络状态变化会影响到在 Chromium 浏览器中运行的 JavaScript 代码的功能。  JavaScript 可以通过 **Network Information API** 来获取当前的网络状态信息，而 `NetworkChangeNotifierWin` 的工作正是为这个 API 提供底层数据。

**举例说明:**

假设一个网页应用需要根据用户的网络连接类型来决定加载资源的策略：

* **假设输入:** 用户从连接到 Wi-Fi 的状态切换到断开网络的状态。
* **`NetworkChangeNotifierWin` 的处理:**
    1. `NotifyAddrChange` 会收到通知，表明 IP 地址发生了变化。
    2. `RecomputeCurrentConnectionType` 会被调用，检测到当前网络状态为 `CONNECTION_NONE` (离线)。
    3. `NetworkChangeNotifierWin` 会通知其观察者，其中包括负责将网络状态更新到渲染进程的组件。
* **Network Information API 的体现:**
    1. 渲染进程接收到网络状态变化的通知。
    2. 网页中的 JavaScript 代码可以使用 `navigator.connection.type` 属性来获取当前的网络连接类型。此时，该属性的值会反映出 "none"。
    3. 网页应用中的 JavaScript 代码可以根据 `navigator.connection.type` 的变化来执行相应的逻辑，例如：
        ```javascript
        if (navigator.connection.type === 'none') {
          console.log('网络已断开，请检查网络连接。');
          // 显示离线提示信息
          document.getElementById('offline-message').style.display = 'block';
        } else {
          console.log('网络已连接，连接类型为：' + navigator.connection.type);
          // 恢复在线功能
          document.getElementById('offline-message').style.display = 'none';
        }
        ```

**逻辑推理、假设输入与输出:**

**场景 1:  连接到新的 Wi-Fi 网络**

* **假设输入:** 用户计算机从没有网络连接的状态，成功连接到一个新的 Wi-Fi 网络。
* **`NetworkChangeNotifierWin` 的处理:**
    1. `NotifyAddrChange` 会收到通知，因为分配了新的 IP 地址。
    2. `RecomputeCurrentConnectionType` 会被调用，并可能检测到连接类型为 `WIFI` 或 `UNKNOWN` (如果无法更精确判断)。
    3. `NetworkChangeNotifierWin` 会通知观察者，表明网络状态从 `CONNECTION_NONE` 变为 `WIFI` 或 `UNKNOWN`。
* **输出:**
    * `GetCurrentConnectionType()` 的返回值会更新为 `WIFI` 或 `UNKNOWN`。
    * 注册的观察者会收到网络连接类型变化的通知。
    * 使用 Network Information API 的 JavaScript 代码会反映出新的连接类型。

**场景 2:  从 Wi-Fi 切换到以太网**

* **假设输入:** 用户计算机从连接到 Wi-Fi 的状态，插入网线连接到以太网。
* **`NetworkChangeNotifierWin` 的处理:**
    1. `NotifyAddrChange` 会收到通知，因为 IP 地址可能发生了变化。
    2. `RecomputeCurrentConnectionType` 会被调用，并可能检测到连接类型从 `WIFI` 变为 `ETHERNET` 或 `UNKNOWN`。
    3. `NetworkCostChangeNotifierWin` 可能会检测到连接成本的变化 (例如，从 "按流量计费" 到 "非按流量计费")。
    4. `NetworkChangeNotifierWin` 会通知观察者，表明网络连接类型和成本可能都发生了变化。
* **输出:**
    * `GetCurrentConnectionType()` 的返回值会更新为 `ETHERNET` 或 `UNKNOWN`。
    * `GetCurrentConnectionCost()` 的返回值可能会更新。
    * 注册的观察者会收到网络连接类型和成本变化的通知。
    * 使用 Network Information API 的 JavaScript 代码会反映出新的连接类型和成本信息（如果 API 支持）。

**涉及用户或编程常见的使用错误及举例说明:**

1. **用户网络配置错误:**
   * **错误:** 用户手动配置了错误的静态 IP 地址、子网掩码或网关。
   * **`NetworkChangeNotifierWin` 的行为:**  虽然连接可能存在问题，但 `NotifyAddrChange` 仍然可能会在 IP 地址发生变化时触发。 `RecomputeCurrentConnectionType` 可能会报告 "在线" 状态，即使实际的网络通信存在问题。
   * **调试线索:**  如果应用程序报告网络已连接，但无法访问互联网，则可能是用户网络配置错误。

2. **驱动程序问题:**
   * **错误:**  网卡驱动程序过时、损坏或不兼容。
   * **`NetworkChangeNotifierWin` 的行为:**  可能无法正确接收网络状态变化的通知，或者接收到的信息不准确。
   * **调试线索:**  网络状态频繁切换，或者 `NetworkChangeNotifierWin` 的日志中出现与 Windows API 调用相关的错误。

3. **防火墙或安全软件阻止:**
   * **错误:**  防火墙或安全软件阻止了 Chromium 访问必要的网络信息或接收网络状态变化通知。
   * **`NetworkChangeNotifierWin` 的行为:**  可能无法正常工作，导致无法检测到网络状态变化。
   * **调试线索:**  在禁用防火墙或安全软件后，问题消失。

4. **编程错误 (在 Chromium 代码中):**
   * **错误:**  在 `NetworkChangeNotifierWin` 的使用或观察者注册过程中存在逻辑错误，导致无法正确处理网络状态变化。
   * **`NetworkChangeNotifierWin` 的行为:**  即使网络状态发生变化，观察者也可能没有收到通知或处理不正确。
   * **调试线索:**  需要仔细检查调用 `NetworkChangeNotifier::AddObserver` 和相关通知处理的代码。

**用户操作如何一步步到达这里，作为调试线索:**

以下是一些用户操作可能触发 `NetworkChangeNotifierWin` 工作流程的步骤，可以作为调试线索：

1. **连接或断开网络连接:**
   * 用户点击任务栏的网络图标，选择连接或断开 Wi-Fi 网络。
   * 用户插入或拔出以太网线缆。
   * 用户启用了飞行模式或禁用了网络适配器。
   * **调试线索:**  在执行这些操作前后，观察 `NetworkChangeNotifierWin` 的日志输出，看是否触发了 `NotifyAddrChange` 或 `RecomputeCurrentConnectionType`。

2. **网络配置更改:**
   * 用户在 Windows 设置中更改了 IP 地址、DNS 服务器等网络配置。
   * **调试线索:**  这些操作通常会导致 IP 地址变化，从而触发 `NotifyAddrChange`。

3. **网络适配器状态变化:**
   * 用户启用了或禁用了虚拟网络适配器 (例如，VPN 客户端)。
   * 系统检测到物理网卡的连接状态变化 (例如，链路丢失)。
   * **调试线索:**  这些状态变化可能会影响 `RecomputeCurrentConnectionType` 的判断结果。

4. **系统启动或休眠/唤醒:**
   * 在系统启动时，`NetworkChangeNotifierWin` 会初始化并开始监听网络状态变化。
   * 在系统从休眠或睡眠状态唤醒时，网络连接状态可能会发生变化。
   * **调试线索:**  观察系统启动和唤醒过程中的日志，看 `NetworkChangeNotifierWin` 是否正常启动和检测到初始网络状态。

5. **网络成本变化 (仅限支持的 Windows 版本):**
   * Windows 检测到网络连接的成本发生变化 (例如，从非按流量计费的网络切换到移动热点)。
   * **调试线索:**  观察 `NetworkCostChangeNotifierWin` 是否触发了 `OnCostChanged` 回调。

**总而言之，`net/base/network_change_notifier_win.cc` 是 Chromium 在 Windows 平台上感知网络世界变化的关键组件。它的稳定性和准确性直接影响到浏览器中各种网络功能的正常运行，以及网页开发者通过 Network Information API 获取到的网络信息。**

### 提示词
```
这是目录为net/base/network_change_notifier_win.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/network_change_notifier_win.h"

#include <winsock2.h>

#include <iphlpapi.h>

#include <utility>

#include "base/feature_list.h"
#include "base/functional/bind.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/metrics/histogram_macros.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/single_thread_task_runner.h"
#include "base/task/task_traits.h"
#include "base/task/thread_pool.h"
#include "base/threading/thread.h"
#include "base/time/time.h"
#include "base/win/windows_version.h"
#include "net/base/features.h"
#include "net/base/network_cost_change_notifier_win.h"
#include "net/base/winsock_init.h"
#include "net/base/winsock_util.h"

namespace net {

namespace {

// Time between NotifyAddrChange retries, on failure.
const int kWatchForAddressChangeRetryIntervalMs = 500;

}  // namespace

NetworkChangeNotifierWin::NetworkChangeNotifierWin()
    : NetworkChangeNotifier(NetworkChangeCalculatorParamsWin()),
      blocking_task_runner_(
          base::ThreadPool::CreateSequencedTaskRunner({base::MayBlock()})),
      last_computed_connection_type_(RecomputeCurrentConnectionType()),
      last_announced_offline_(last_computed_connection_type_ ==
                              CONNECTION_NONE),
      sequence_runner_for_registration_(
          base::SequencedTaskRunner::GetCurrentDefault()) {
  memset(&addr_overlapped_, 0, sizeof addr_overlapped_);
  addr_overlapped_.hEvent = WSACreateEvent();

  cost_change_notifier_ = NetworkCostChangeNotifierWin::CreateInstance(
      base::BindRepeating(&NetworkChangeNotifierWin::OnCostChanged,
                          weak_factory_.GetWeakPtr()));
}

NetworkChangeNotifierWin::~NetworkChangeNotifierWin() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  ClearGlobalPointer();
  if (is_watching_) {
    CancelIPChangeNotify(&addr_overlapped_);
    addr_watcher_.StopWatching();
  }
  WSACloseEvent(addr_overlapped_.hEvent);
}

// static
NetworkChangeNotifier::NetworkChangeCalculatorParams
NetworkChangeNotifierWin::NetworkChangeCalculatorParamsWin() {
  NetworkChangeCalculatorParams params;
  // Delay values arrived at by simple experimentation and adjusted so as to
  // produce a single signal when switching between network connections.
  params.ip_address_offline_delay_ = base::Milliseconds(1500);
  params.ip_address_online_delay_ = base::Milliseconds(1500);
  params.connection_type_offline_delay_ = base::Milliseconds(1500);
  params.connection_type_online_delay_ = base::Milliseconds(500);
  return params;
}

// static
NetworkChangeNotifier::ConnectionType
NetworkChangeNotifierWin::RecomputeCurrentConnectionTypeModern() {
  using GetNetworkConnectivityHintType =
      decltype(&::GetNetworkConnectivityHint);

  // This API is only available on Windows 10 Build 19041. However, it works
  // inside the Network Service Sandbox, so is preferred. See
  GetNetworkConnectivityHintType get_network_connectivity_hint =
      reinterpret_cast<GetNetworkConnectivityHintType>(::GetProcAddress(
          ::GetModuleHandleA("iphlpapi.dll"), "GetNetworkConnectivityHint"));
  if (!get_network_connectivity_hint) {
    return NetworkChangeNotifier::CONNECTION_UNKNOWN;
  }
  NL_NETWORK_CONNECTIVITY_HINT hint;
  // https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getnetworkconnectivityhint.
  auto ret = get_network_connectivity_hint(&hint);
  if (ret != NO_ERROR) {
    return NetworkChangeNotifier::CONNECTION_UNKNOWN;
  }

  switch (hint.ConnectivityLevel) {
    case NetworkConnectivityLevelHintUnknown:
      return NetworkChangeNotifier::CONNECTION_UNKNOWN;
    case NetworkConnectivityLevelHintNone:
    case NetworkConnectivityLevelHintHidden:
      return NetworkChangeNotifier::CONNECTION_NONE;
    case NetworkConnectivityLevelHintLocalAccess:
    case NetworkConnectivityLevelHintInternetAccess:
    case NetworkConnectivityLevelHintConstrainedInternetAccess:
      // TODO(droger): Return something more detailed than CONNECTION_UNKNOWN.
      return ConnectionTypeFromInterfaces();
  }

  NOTREACHED();
}

// This implementation does not return the actual connection type but merely
// determines if the user is "online" (in which case it returns
// CONNECTION_UNKNOWN) or "offline" (and then it returns CONNECTION_NONE).
// This is challenging since the only thing we can test with certainty is
// whether a *particular* host is reachable.
//
// While we can't conclusively determine when a user is "online", we can at
// least reliably recognize some of the situtations when they are clearly
// "offline". For example, if the user's laptop is not plugged into an ethernet
// network and is not connected to any wireless networks, it must be offline.
//
// There are a number of different ways to implement this on Windows, each with
// their pros and cons. Here is a comparison of various techniques considered:
//
// (1) Use InternetGetConnectedState (wininet.dll). This function is really easy
// to use (literally a one-liner), and runs quickly. The drawback is it adds a
// dependency on the wininet DLL.
//
// (2) Enumerate all of the network interfaces using GetAdaptersAddresses
// (iphlpapi.dll), and assume we are "online" if there is at least one interface
// that is connected, and that interface is not a loopback or tunnel.
//
// Safari on Windows has a fairly simple implementation that does this:
// http://trac.webkit.org/browser/trunk/WebCore/platform/network/win/NetworkStateNotifierWin.cpp.
//
// Mozilla similarly uses this approach:
// http://mxr.mozilla.org/mozilla1.9.2/source/netwerk/system/win32/nsNotifyAddrListener.cpp
//
// The biggest drawback to this approach is it is quite complicated.
// WebKit's implementation for example doesn't seem to test for ICS gateways
// (internet connection sharing), whereas Mozilla's implementation has extra
// code to guess that.
//
// (3) The method used in this file comes from google talk, and is similar to
// method (2). The main difference is it enumerates the winsock namespace
// providers rather than the actual adapters.
//
// I ran some benchmarks comparing the performance of each on my Windows 7
// workstation. Here is what I found:
//   * Approach (1) was pretty much zero-cost after the initial call.
//   * Approach (2) took an average of 3.25 milliseconds to enumerate the
//     adapters.
//   * Approach (3) took an average of 0.8 ms to enumerate the providers.
//
// In terms of correctness, all three approaches were comparable for the simple
// experiments I ran... However none of them correctly returned "offline" when
// executing 'ipconfig /release'.
//
// static
NetworkChangeNotifier::ConnectionType
NetworkChangeNotifierWin::RecomputeCurrentConnectionType() {
  if (base::win::GetVersion() >= base::win::Version::WIN10_20H1 &&
      base::FeatureList::IsEnabled(
          features::kEnableGetNetworkConnectivityHintAPI)) {
    return RecomputeCurrentConnectionTypeModern();
  }

  EnsureWinsockInit();

  // The following code was adapted from:
  // http://src.chromium.org/viewvc/chrome/trunk/src/chrome/common/net/notifier/base/win/async_network_alive_win32.cc?view=markup&pathrev=47343
  // The main difference is we only call WSALookupServiceNext once, whereas
  // the earlier code would traverse the entire list and pass LUP_FLUSHPREVIOUS
  // to skip past the large results.

  HANDLE ws_handle;
  WSAQUERYSET query_set = {0};
  query_set.dwSize = sizeof(WSAQUERYSET);
  query_set.dwNameSpace = NS_NLA;
  // Initiate a client query to iterate through the
  // currently connected networks.
  if (0 != WSALookupServiceBegin(&query_set, LUP_RETURN_ALL, &ws_handle)) {
    LOG(ERROR) << "WSALookupServiceBegin failed with: " << WSAGetLastError();
    return NetworkChangeNotifier::CONNECTION_UNKNOWN;
  }

  bool found_connection = false;

  // Retrieve the first available network. In this function, we only
  // need to know whether or not there is network connection.
  // Allocate 256 bytes for name, it should be enough for most cases.
  // If the name is longer, it is OK as we will check the code returned and
  // set correct network status.
  char result_buffer[sizeof(WSAQUERYSET) + 256] = {0};
  DWORD length = sizeof(result_buffer);
  reinterpret_cast<WSAQUERYSET*>(&result_buffer[0])->dwSize =
      sizeof(WSAQUERYSET);
  int result =
      WSALookupServiceNext(ws_handle, LUP_RETURN_NAME, &length,
                           reinterpret_cast<WSAQUERYSET*>(&result_buffer[0]));

  if (result == 0) {
    // Found a connection!
    found_connection = true;
  } else {
    DCHECK_EQ(SOCKET_ERROR, result);
    result = WSAGetLastError();

    // Error code WSAEFAULT means there is a network connection but the
    // result_buffer size is too small to contain the results. The
    // variable "length" returned from WSALookupServiceNext is the minimum
    // number of bytes required. We do not need to retrieve detail info,
    // it is enough knowing there was a connection.
    if (result == WSAEFAULT) {
      found_connection = true;
    } else if (result == WSA_E_NO_MORE || result == WSAENOMORE) {
      // There was nothing to iterate over!
    } else {
      LOG(WARNING) << "WSALookupServiceNext() failed with:" << result;
    }
  }

  result = WSALookupServiceEnd(ws_handle);
  LOG_IF(ERROR, result != 0) << "WSALookupServiceEnd() failed with: " << result;

  // TODO(droger): Return something more detailed than CONNECTION_UNKNOWN.
  return found_connection ? ConnectionTypeFromInterfaces()
                          : NetworkChangeNotifier::CONNECTION_NONE;
}

void NetworkChangeNotifierWin::RecomputeCurrentConnectionTypeOnBlockingSequence(
    base::OnceCallback<void(ConnectionType)> reply_callback) const {
  // Unretained is safe in this call because this object owns the thread and the
  // thread is stopped in this object's destructor.
  blocking_task_runner_->PostTaskAndReplyWithResult(
      FROM_HERE,
      base::BindOnce(&NetworkChangeNotifierWin::RecomputeCurrentConnectionType),
      std::move(reply_callback));
}

NetworkChangeNotifier::ConnectionCost
NetworkChangeNotifierWin::GetCurrentConnectionCost() {
  if (last_computed_connection_cost_ ==
      ConnectionCost::CONNECTION_COST_UNKNOWN) {
    // Use the default logic when the Windows OS APIs do not have a cost for the
    // current connection.
    return NetworkChangeNotifier::GetCurrentConnectionCost();
  }
  return last_computed_connection_cost_;
}

void NetworkChangeNotifierWin::OnCostChanged(
    NetworkChangeNotifier::ConnectionCost new_cost) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  // Only notify if there's actually a change.
  if (last_computed_connection_cost_ != new_cost) {
    last_computed_connection_cost_ = new_cost;
    NotifyObserversOfConnectionCostChange();
  }
}

NetworkChangeNotifier::ConnectionType
NetworkChangeNotifierWin::GetCurrentConnectionType() const {
  base::AutoLock auto_lock(last_computed_connection_type_lock_);
  return last_computed_connection_type_;
}

void NetworkChangeNotifierWin::SetCurrentConnectionType(
    ConnectionType connection_type) {
  base::AutoLock auto_lock(last_computed_connection_type_lock_);
  last_computed_connection_type_ = connection_type;
}

void NetworkChangeNotifierWin::OnObjectSignaled(HANDLE object) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK(is_watching_);
  is_watching_ = false;

  // Start watching for the next address change.
  WatchForAddressChange();

  RecomputeCurrentConnectionTypeOnBlockingSequence(base::BindOnce(
      &NetworkChangeNotifierWin::NotifyObservers, weak_factory_.GetWeakPtr()));
}

void NetworkChangeNotifierWin::NotifyObservers(ConnectionType connection_type) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  SetCurrentConnectionType(connection_type);
  NotifyObserversOfIPAddressChange();

  // Calling GetConnectionType() at this very moment is likely to give
  // the wrong result, so we delay that until a little bit later.
  //
  // The one second delay chosen here was determined experimentally
  // by adamk on Windows 7.
  // If after one second we determine we are still offline, we will
  // delay again.
  offline_polls_ = 0;
  timer_.Start(FROM_HERE, base::Seconds(1), this,
               &NetworkChangeNotifierWin::NotifyParentOfConnectionTypeChange);
}

void NetworkChangeNotifierWin::WatchForAddressChange() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK(!is_watching_);

  // NotifyAddrChange occasionally fails with ERROR_OPEN_FAILED for unknown
  // reasons.  More rarely, it's also been observed failing with
  // ERROR_NO_SYSTEM_RESOURCES.  When either of these happens, we retry later.
  if (!WatchForAddressChangeInternal()) {
    ++sequential_failures_;

    base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
        FROM_HERE,
        base::BindOnce(&NetworkChangeNotifierWin::WatchForAddressChange,
                       weak_factory_.GetWeakPtr()),
        base::Milliseconds(kWatchForAddressChangeRetryIntervalMs));
    return;
  }

  // Treat the transition from NotifyAddrChange failing to succeeding as a
  // network change event, since network changes were not being observed in
  // that interval.
  if (sequential_failures_ > 0) {
    RecomputeCurrentConnectionTypeOnBlockingSequence(
        base::BindOnce(&NetworkChangeNotifierWin::NotifyObservers,
                       weak_factory_.GetWeakPtr()));
  }

  is_watching_ = true;
  sequential_failures_ = 0;
}

bool NetworkChangeNotifierWin::WatchForAddressChangeInternal() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  ResetEventIfSignaled(addr_overlapped_.hEvent);
  HANDLE handle = nullptr;
  DWORD ret = NotifyAddrChange(&handle, &addr_overlapped_);
  if (ret != ERROR_IO_PENDING)
    return false;

  addr_watcher_.StartWatchingOnce(addr_overlapped_.hEvent, this);
  return true;
}

void NetworkChangeNotifierWin::NotifyParentOfConnectionTypeChange() {
  RecomputeCurrentConnectionTypeOnBlockingSequence(base::BindOnce(
      &NetworkChangeNotifierWin::NotifyParentOfConnectionTypeChangeImpl,
      weak_factory_.GetWeakPtr()));
}

void NetworkChangeNotifierWin::NotifyParentOfConnectionTypeChangeImpl(
    ConnectionType connection_type) {
  SetCurrentConnectionType(connection_type);
  bool current_offline = IsOffline();
  offline_polls_++;
  // If we continue to appear offline, delay sending out the notification in
  // case we appear to go online within 20 seconds.  UMA histogram data shows
  // we may not detect the transition to online state after 1 second but within
  // 20 seconds we generally do.
  if (last_announced_offline_ && current_offline && offline_polls_ <= 20) {
    timer_.Start(FROM_HERE, base::Seconds(1), this,
                 &NetworkChangeNotifierWin::NotifyParentOfConnectionTypeChange);
    return;
  }
  if (last_announced_offline_)
    UMA_HISTOGRAM_CUSTOM_COUNTS("NCN.OfflinePolls", offline_polls_, 1, 50, 50);
  last_announced_offline_ = current_offline;

  NotifyObserversOfConnectionTypeChange();
  double max_bandwidth_mbps = 0.0;
  ConnectionType max_connection_type = CONNECTION_NONE;
  GetCurrentMaxBandwidthAndConnectionType(&max_bandwidth_mbps,
                                          &max_connection_type);
  NotifyObserversOfMaxBandwidthChange(max_bandwidth_mbps, max_connection_type);
}

}  // namespace net
```