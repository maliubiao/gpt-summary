Response:
Let's break down the thought process for analyzing this C++ code and answering the prompt.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of `QuicConnectivityMonitor` in the Chromium networking stack. The request also asks to identify relationships with JavaScript, explain logical reasoning, highlight potential user/programming errors, and describe how a user might reach this code.

**2. Initial Code Scan and Keyword Identification:**

The first step is a quick scan of the code, looking for key terms and structures:

* **Class Name:** `QuicConnectivityMonitor` - This is the central entity.
* **Includes:** `base/metrics/histogram_functions.h`, `base/metrics/histogram_macros.h` -  Indicates the class is involved in recording metrics.
* **Namespace:** `net` -  Confirms it's part of the networking stack.
* **Member Variables:** `default_network_`, `active_sessions_`, `degrading_sessions_`, `write_error_map_`, `quic_error_map_`, `num_all_degraded_sessions_`, `num_sessions_active_during_current_speculative_connectivity_failure_` - These are the state of the monitor and hint at its purpose.
* **Methods:** `RecordConnectivityStatsToHistograms`, `GetNumDegradingSessions`, `GetCountForWriteErrorCode`, `SetInitialDefaultNetwork`, `OnSessionPathDegrading`, `OnSessionResumedPostPathDegrading`, `OnSessionEncounteringWriteError`, `OnSessionClosedAfterHandshake`, `OnSessionRegistered`, `OnSessionRemoved`, `OnDefaultNetworkUpdated`, `OnIPAddressChanged`, `OnSessionGoingAwayOnIPAddressChange` - These are the actions the monitor can perform or react to.
* **Histograms:**  Mentions of `UMA_HISTOGRAM_*` clearly show the class is about collecting and reporting statistics.
* **Error Codes:**  References to `ERR_ADDRESS_UNREACHABLE`, `ERR_ACCESS_DENIED`, `ERR_INTERNET_DISCONNECTED`, `quic::QUIC_PACKET_WRITE_ERROR`, `quic::QUIC_TOO_MANY_RTOS`, `quic::QUIC_PUBLIC_RESET`. This points to monitoring network connectivity issues.
* **"Degrading Sessions":**  This term appears frequently, suggesting a key aspect of the monitoring.
* **"Default Network":**  Another recurring concept, highlighting the importance of the current active network.

**3. Deeper Dive into Functionality - Method by Method:**

Now, analyze each method to understand its specific role:

* **Constructor/Destructor:**  Initialization and cleanup. The constructor takes the initial default network.
* **`RecordConnectivityStatsToHistograms`:**  The core of metrics reporting. It gathers data about active and degrading sessions and logs it to histograms based on network notifications.
* **`GetNumDegradingSessions` and `GetCountForWriteErrorCode`:** Simple accessors to internal state.
* **`SetInitialDefaultNetwork`:**  Allows setting the initial default network (likely done early on).
* **`OnSessionPathDegrading`:**  Called when a QUIC session's path starts experiencing degradation. Crucially, it checks if the network matches the default and tracks the session.
* **`OnSessionResumedPostPathDegrading`:**  Called when a degraded session recovers.
* **`OnSessionEncounteringWriteError`:**  Called when a QUIC session encounters a write error. It checks for previous degradation and tracks error codes.
* **`OnSessionClosedAfterHandshake`:** Called when a QUIC session closes after the handshake. It specifically looks for errors indicative of connectivity issues (like `QUIC_PUBLIC_RESET`, `QUIC_PACKET_WRITE_ERROR`, `QUIC_TOO_MANY_RTOS`).
* **`OnSessionRegistered` and `OnSessionRemoved`:**  Manage the set of active QUIC sessions.
* **`OnDefaultNetworkUpdated`:**  Called when the default network changes. This triggers a reset of the monitor's state.
* **`OnIPAddressChanged`:**  Called when the IP address changes. Similar to `OnDefaultNetworkUpdated` in its implications, especially when network handles aren't supported.
* **`OnSessionGoingAwayOnIPAddressChange`:**  A cleanup method called when a session is affected by an IP address change.

**4. Identifying Core Functionality:**

Based on the method analysis, the core functions of `QuicConnectivityMonitor` are:

* **Monitoring QUIC session health:** Tracking active and degrading sessions.
* **Detecting network connectivity issues:** Observing write errors, connection closures with specific error codes, and network changes.
* **Collecting metrics:**  Recording statistics about session degradation, error occurrences, and network changes using histograms.
* **Reacting to network changes:**  Updating its internal state when the default network or IP address changes.

**5. Relationship with JavaScript:**

Consider how network information is exposed to JavaScript in a browser:

* **`navigator.connection` API:**  This API provides information about the network connection (type, effective type, downlink speed, etc.). While this C++ code doesn't directly interact with this API, the *information* it gathers (like network changes and degradation) could *inform* the data provided by this API.
* **`fetch` API errors:** When a `fetch` request fails due to network issues, the error object might contain information that originated from the kind of monitoring done by this class.
* **WebSockets:** Similar to `fetch`, WebSocket connections can be affected by network issues, and the events/errors in JavaScript might reflect the underlying problems detected by `QuicConnectivityMonitor`.

**6. Logical Reasoning and Examples:**

Focus on the `OnSessionPathDegrading` and `OnSessionEncounteringWriteError` methods to demonstrate logical flow. Think about the state changes and histogram recordings.

**7. User/Programming Errors:**

Consider how developers using the Chromium networking stack might misuse this component or encounter issues related to its behavior.

**8. User Operations and Debugging:**

Trace a user action (like browsing a website) and think about how the network requests would go through the QUIC implementation and potentially trigger the methods in `QuicConnectivityMonitor`. This helps illustrate the call flow.

**9. Structuring the Answer:**

Finally, organize the findings into the requested sections: Functionality, JavaScript relationship, logical reasoning, errors, and debugging. Use clear and concise language. Provide specific examples where possible.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Focusing too much on individual lines of code.
* **Correction:** Shift to understanding the overall purpose and the interaction between different methods.
* **Initial thought:**  Overlooking the importance of histograms.
* **Correction:** Recognize that metric collection is a primary function.
* **Initial thought:**  Struggling to connect to JavaScript.
* **Correction:**  Think about the *information* this class gathers and how that information could be reflected in browser APIs or error messages.

By following these steps, and iterating through the analysis, a comprehensive and accurate answer can be constructed.
好的，让我们详细分析一下 `net/quic/quic_connectivity_monitor.cc` 文件的功能。

**文件功能概述**

`QuicConnectivityMonitor` 类在 Chromium 的 QUIC (Quick UDP Internet Connections) 实现中扮演着监控网络连接状态的关键角色。它的主要功能是：

1. **跟踪 QUIC 会话的网络连接质量：**  它会记录哪些 QUIC 会话正在经历网络路径降级（例如，延迟增加、丢包率上升）或遇到网络写入错误。
2. **监控默认网络的变化：** 当设备的默认网络发生改变时（例如，从 Wi-Fi 切换到移动数据），`QuicConnectivityMonitor` 会收到通知并更新其状态。
3. **收集网络连接统计信息并记录到直方图：**  它会收集关于活动 QUIC 会话数量、降级会话数量、特定网络错误发生次数等信息，并将这些数据记录到 Chromium 的 UMA (User Metrics Analysis) 直方图中。这些直方图用于分析网络连接的稳定性和 QUIC 的性能。
4. **辅助进行网络连接相关的诊断：** 通过监控网络事件和会话状态，它可以帮助识别潜在的网络连接问题，例如间歇性断网、地址不可达等。

**与 JavaScript 功能的关系**

`QuicConnectivityMonitor` 本身是用 C++ 实现的，直接在浏览器的网络层运行，不直接与 JavaScript 代码交互。但是，它收集的统计信息和它对网络状态的监控可以间接地影响 JavaScript 的行为和开发者可以通过 JavaScript 获取的信息：

* **`navigator.connection` API:**  JavaScript 中的 `navigator.connection` API 提供了一些关于用户网络连接的信息，例如网络类型（wifi, cellular 等）、有效连接类型（slow-2g, 2g, 3g, 4g 等）。虽然 `QuicConnectivityMonitor` 不直接操作这个 API，但它监控到的网络降级事件和网络变化可以作为浏览器更新 `navigator.connection` API 中相关信息的依据之一。例如，如果 `QuicConnectivityMonitor` 检测到连接质量下降，浏览器可能会在 `navigator.connection.effectiveType` 中反映出来。

   **举例说明：**

   * **假设输入（`QuicConnectivityMonitor` 的内部状态）：**  `QuicConnectivityMonitor` 检测到多个 QUIC 会话在当前默认网络上经历持续的丢包和延迟增加。
   * **逻辑推理：**  `QuicConnectivityMonitor` 将这些信息记录到直方图，并可能触发一些内部机制来通知网络栈其他部分网络状况不佳。
   * **输出（对 JavaScript 的间接影响）：**  浏览器可能会根据这些信息更新 `navigator.connection.effectiveType` 为 "slow-2g" 或 "2g"，即使物理网络连接仍然是 Wi-Fi。
   * **JavaScript 代码示例：**
     ```javascript
     if (navigator.connection && navigator.connection.effectiveType === 'slow-2g') {
       console.warn("网络连接缓慢，可能需要优化资源加载。");
       // 可以采取一些优化措施，例如加载低分辨率图片
     }
     ```

* **`fetch` API 和错误处理：** 当 JavaScript 使用 `fetch` API 发起网络请求时，如果底层 QUIC 连接遇到问题（例如，被 `QuicConnectivityMonitor` 监控到的写入错误或连接关闭），`fetch` 请求可能会失败。开发者可以通过 `fetch` 的 `catch` 块捕获这些错误。虽然错误信息本身不直接包含 `QuicConnectivityMonitor` 的细节，但错误发生的原因可能与 `QuicConnectivityMonitor` 监控到的网络问题有关。

   **举例说明：**

   * **假设输入（`QuicConnectivityMonitor` 的内部状态）：** `QuicConnectivityMonitor` 检测到由于网络不稳定，多个 QUIC 会话遇到了 `ERR_INTERNET_DISCONNECTED` 错误。
   * **逻辑推理：** 这些错误会导致对应的 QUIC 连接关闭。
   * **输出（对 JavaScript 的间接影响）：**  使用这些 QUIC 连接的 `fetch` 请求将会失败，并抛出类似 "NetworkError" 的错误。
   * **JavaScript 代码示例：**
     ```javascript
     fetch('https://example.com/data')
       .then(response => response.json())
       .then(data => console.log(data))
       .catch(error => {
         console.error("网络请求失败:", error);
         if (error.message === 'Failed to fetch') {
           // 用户可能遇到了网络连接问题
           alert("网络连接似乎有问题，请检查您的网络。");
         }
       });
     ```

* **WebSocket API 和错误事件：** 类似于 `fetch`，当 WebSocket 连接建立在 QUIC 之上时，`QuicConnectivityMonitor` 监控到的网络问题也可能导致 WebSocket 连接中断或出错，触发 WebSocket 对象的 `onerror` 事件。

**逻辑推理的假设输入与输出**

让我们以 `OnSessionPathDegrading` 方法为例进行逻辑推理：

* **假设输入：**
    * `session`: 一个指向 `QuicChromiumClientSession` 对象的指针，代表一个正在经历路径降级的 QUIC 会话。
    * `network`: 一个 `handles::NetworkHandle` 值，表示该会话正在使用的网络。假设 `network` 的值与 `default_network_` 相同（当前默认网络）。

* **逻辑推理过程：**
    1. `if (network != default_network_) return;`: 由于假设 `network` 与 `default_network_` 相同，所以条件不成立，代码继续执行。
    2. `degrading_sessions_.insert(session);`: 将该 `session` 添加到 `degrading_sessions_` 集合中，表示该会话正在降级。
    3. `num_all_degraded_sessions_++;`: 增加所有降级会话的计数器。
    4. `active_sessions_.insert(session);`: 将该 `session` 添加到 `active_sessions_` 集合中（确保被跟踪）。
    5. `if (!num_sessions_active_during_current_speculative_connectivity_failure_)`: 检查 `num_sessions_active_during_current_speculative_connectivity_failure_` 是否为空。
       * **假设第一次遇到路径降级：**  `num_sessions_active_during_current_speculative_connectivity_failure_` 为空，条件成立。
       * `num_sessions_active_during_current_speculative_connectivity_failure_ = active_sessions_.size();`: 将当前活跃会话的数量赋值给 `num_sessions_active_during_current_speculative_connectivity_failure_`，表示在开始推测性连接失败时的活跃会话数量。
       * **假设之前已经观察到写入错误：** `num_sessions_active_during_current_speculative_connectivity_failure_` 不为空，条件不成立，执行 `else` 块。
       * `UMA_HISTOGRAM_COUNTS_100(...)`: 记录在观察到路径降级之前，`QUIC_PACKET_WRITE_ERROR` 发生的次数。

* **预期输出（内部状态变化）：**
    * `degrading_sessions_` 集合将包含传入的 `session`。
    * `num_all_degraded_sessions_` 的值会增加 1。
    * `active_sessions_` 集合将包含传入的 `session`。
    * 如果是第一次遇到路径降级，`num_sessions_active_during_current_speculative_connectivity_failure_` 将被设置为当前活跃会话的数量。

**用户或编程常见的使用错误**

虽然用户不直接与 `QuicConnectivityMonitor` 交互，但编程错误可能会导致其功能异常或信息不准确：

1. **未正确注册会话：** 如果 QUIC 会话在创建后没有通过 `OnSessionRegistered` 方法注册到 `QuicConnectivityMonitor`，那么该会话的网络状态将不会被监控，导致统计信息不完整。
   * **示例：**  在创建 `QuicChromiumClientSession` 对象后，忘记调用 `connectivity_monitor_->OnSessionRegistered(session, network_handle);`。

2. **在不正确的时机调用方法：**  例如，在会话尚未建立连接就调用 `OnSessionPathDegrading` 可能会导致逻辑错误或未定义的行为。
   * **示例：**  在握手完成之前，错误地认为会话路径已经开始降级。

3. **网络句柄管理错误：**  如果传递给 `QuicConnectivityMonitor` 的 `handles::NetworkHandle` 值不正确或过时，可能导致监控的网络对象错误。
   * **示例：**  在一个网络连接已经断开后，仍然使用旧的网络句柄调用相关方法。

4. **直方图命名冲突：**  虽然不太可能，但如果在 Chromium 的其他部分使用了相同的直方图名称，可能会导致数据记录冲突。

**用户操作如何一步步到达这里（调试线索）**

要理解用户操作如何最终触发 `QuicConnectivityMonitor` 中的代码，我们需要跟踪一个典型的网络请求流程：

1. **用户在浏览器中输入 URL 或点击链接：**  这将触发一个导航请求。
2. **浏览器解析 URL 并确定协议：** 如果目标网站支持 QUIC，浏览器可能会尝试使用 QUIC 连接。
3. **建立 QUIC 连接：**  浏览器会与服务器进行 QUIC 握手。
4. **`QuicConnectivityMonitor::OnSessionRegistered` 被调用：** 当一个新的 QUIC 会话成功建立并准备好发送数据时，`OnSessionRegistered` 方法会被调用，将该会话添加到 `active_sessions_` 中。
5. **网络传输过程：**
   * **网络状况良好：** 数据包顺利传输。
   * **网络出现波动或降级：**
     * **延迟增加或丢包：** QUIC 层可能会检测到路径质量下降，并调用 `OnSessionPathDegrading` 方法。
     * **遇到网络写入错误：**  当尝试发送数据包时遇到操作系统级别的网络错误（如 `ERR_ADDRESS_UNREACHABLE`）时，`OnSessionEncounteringWriteError` 方法会被调用。
6. **网络切换：**
   * **用户从 Wi-Fi 切换到移动数据，或反之：** 操作系统会通知 Chromium 网络状态变化。
   * **`QuicConnectivityMonitor::OnDefaultNetworkUpdated` 被调用：**  `QuicConnectivityMonitor` 会收到通知，更新其 `default_network_`，并清除之前的会话状态，因为连接可能会迁移到新的网络。
7. **连接关闭：**
   * **正常关闭：**  当请求完成或连接空闲一段时间后，QUIC 连接可能会正常关闭。
   * **异常关闭：**
     * **网络错误导致连接中断：** 例如，遇到 `QUIC_PACKET_WRITE_ERROR` 或 `QUIC_TOO_MANY_RTOS` (重传超时次数过多)，会调用 `OnSessionClosedAfterHandshake` 方法记录这些错误。
     * **服务器发送 PUBLIC_RESET：** 这通常表示网络地址发生了变化（例如，NAT 重绑定），也会通过 `OnSessionClosedAfterHandshake` 记录。
8. **用户浏览其他网页或关闭标签页：** 当 QUIC 会话不再需要时，`OnSessionRemoved` 方法会被调用，从 `active_sessions_` 和 `degrading_sessions_` 中移除该会话。
9. **IP 地址变化：** 如果用户的 IP 地址发生变化（例如，由于网络配置更新），`OnIPAddressChanged` 方法会被调用，通知 `QuicConnectivityMonitor`。

**调试线索：**

如果在调试与网络连接相关的问题时需要查看 `QuicConnectivityMonitor` 的行为，可以采取以下步骤：

* **设置断点：** 在 `QuicConnectivityMonitor.cc` 文件的关键方法（例如，`OnSessionPathDegrading`, `OnSessionEncounteringWriteError`, `OnDefaultNetworkUpdated`）设置断点。
* **使用 Chromium 的网络日志 (net-internals)：**  在浏览器中访问 `chrome://net-internals/#quic` 可以查看 QUIC 连接的详细信息，包括错误信息和状态变化，这些信息与 `QuicConnectivityMonitor` 收集的统计数据相关。
* **查看 UMA 直方图：**  Chromium 的 UMA 系统会记录 `QuicConnectivityMonitor` 收集的统计信息。在本地构建的 Chromium 版本中，可以查看这些直方图的值来分析网络连接的趋势和问题。
* **模拟网络条件：**  可以使用 Chromium 提供的网络节流工具或外部工具来模拟不同的网络条件（例如，高延迟、丢包）来观察 `QuicConnectivityMonitor` 的反应。

总而言之，`QuicConnectivityMonitor` 是 Chromium QUIC 实现中一个重要的组件，它负责监控网络连接状态，收集统计信息，并为网络连接问题的诊断提供线索。虽然 JavaScript 代码不直接调用它，但它的行为和收集的信息可以间接地影响 JavaScript 的网络 API 和错误处理。

Prompt: 
```
这是目录为net/quic/quic_connectivity_monitor.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_connectivity_monitor.h"

#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_macros.h"

namespace net {

namespace {

bool IsErrorRelatedToConnectivity(int error_code) {
  return (error_code == ERR_ADDRESS_UNREACHABLE ||
          error_code == ERR_ACCESS_DENIED ||
          error_code == ERR_INTERNET_DISCONNECTED);
}

}  // namespace

QuicConnectivityMonitor::QuicConnectivityMonitor(
    handles::NetworkHandle default_network)
    : default_network_(default_network) {}

QuicConnectivityMonitor::~QuicConnectivityMonitor() = default;

void QuicConnectivityMonitor::RecordConnectivityStatsToHistograms(
    const std::string& notification,
    handles::NetworkHandle affected_network) const {
  if (notification == "OnNetworkSoonToDisconnect" ||
      notification == "OnNetworkDisconnected") {
    // If the disconnected network is not the default network, ignore
    // stats collections.
    if (affected_network != default_network_)
      return;
  }

  base::ClampedNumeric<int> num_degrading_sessions = GetNumDegradingSessions();

  if (num_sessions_active_during_current_speculative_connectivity_failure_) {
    UMA_HISTOGRAM_COUNTS_100(
        "Net.QuicConnectivityMonitor.NumSessionsTrackedSinceSpeculativeError",
        num_sessions_active_during_current_speculative_connectivity_failure_
            .value());
  }

  UMA_HISTOGRAM_COUNTS_100(
      "Net.QuicConnectivityMonitor.NumActiveQuicSessionsAtNetworkChange",
      active_sessions_.size());

  int percentage = 0;
  if (num_sessions_active_during_current_speculative_connectivity_failure_ &&
      num_sessions_active_during_current_speculative_connectivity_failure_
              .value() > 0) {
    percentage = base::saturated_cast<int>(
        num_all_degraded_sessions_ * 100.0 /
        num_sessions_active_during_current_speculative_connectivity_failure_
            .value());
  }

  UMA_HISTOGRAM_COUNTS_100(
      "Net.QuicConnectivityMonitor.NumAllSessionsDegradedAtNetworkChange",
      num_all_degraded_sessions_);

  const std::string raw_histogram_name1 =
      "Net.QuicConnectivityMonitor.NumAllDegradedSessions." + notification;
  base::UmaHistogramCustomCounts(raw_histogram_name1,
                                 num_all_degraded_sessions_, 1, 100, 50);

  const std::string percentage_histogram_name1 =
      "Net.QuicConnectivityMonitor.PercentageAllDegradedSessions." +
      notification;

  base::UmaHistogramPercentageObsoleteDoNotUse(percentage_histogram_name1,
                                               percentage);

  // Skip degrading session collection if there are less than two sessions.
  if (active_sessions_.size() < 2u)
    return;

  const std::string raw_histogram_name =
      "Net.QuicConnectivityMonitor.NumActiveDegradingSessions." + notification;

  base::UmaHistogramCustomCounts(raw_histogram_name, num_degrading_sessions, 1,
                                 100, 50);

  percentage = base::saturated_cast<double>(num_degrading_sessions * 100.0 /
                                            active_sessions_.size());

  const std::string percentage_histogram_name =
      "Net.QuicConnectivityMonitor.PercentageActiveDegradingSessions." +
      notification;
  base::UmaHistogramPercentageObsoleteDoNotUse(percentage_histogram_name,
                                               percentage);
}

size_t QuicConnectivityMonitor::GetNumDegradingSessions() const {
  return degrading_sessions_.size();
}

size_t QuicConnectivityMonitor::GetCountForWriteErrorCode(
    int write_error_code) const {
  auto it = write_error_map_.find(write_error_code);
  return it == write_error_map_.end() ? 0u : it->second;
}

void QuicConnectivityMonitor::SetInitialDefaultNetwork(
    handles::NetworkHandle default_network) {
  default_network_ = default_network;
}

void QuicConnectivityMonitor::OnSessionPathDegrading(
    QuicChromiumClientSession* session,
    handles::NetworkHandle network) {
  if (network != default_network_)
    return;

  degrading_sessions_.insert(session);
  num_all_degraded_sessions_++;
  // If the degrading session used to be on the previous default network, it is
  // possible that the session is no longer tracked in |active_sessions_| due
  // to the recent default network change.
  active_sessions_.insert(session);

  if (!num_sessions_active_during_current_speculative_connectivity_failure_) {
    num_sessions_active_during_current_speculative_connectivity_failure_ =
        active_sessions_.size();
  } else {
    // Before seeing session degrading, PACKET_WRITE_ERROR has been observed.
    UMA_HISTOGRAM_COUNTS_100(
        "Net.QuicConnectivityMonitor.NumWriteErrorsSeenBeforeDegradation",
        quic_error_map_[quic::QUIC_PACKET_WRITE_ERROR]);
  }
}

void QuicConnectivityMonitor::OnSessionResumedPostPathDegrading(
    QuicChromiumClientSession* session,
    handles::NetworkHandle network) {
  if (network != default_network_)
    return;

  degrading_sessions_.erase(session);

  // If the resumed session used to be on the previous default network, it is
  // possible that the session is no longer tracked in |active_sessions_| due
  // to the recent default network change.
  active_sessions_.insert(session);

  num_all_degraded_sessions_ = 0u;
  num_sessions_active_during_current_speculative_connectivity_failure_ =
      std::nullopt;
}

void QuicConnectivityMonitor::OnSessionEncounteringWriteError(
    QuicChromiumClientSession* session,
    handles::NetworkHandle network,
    int error_code) {
  if (network != default_network_)
    return;

  // If the session used to be on the previous default network, it is
  // possible that the session is no longer tracked in |active_sessions_| due
  // to the recent default network change.
  active_sessions_.insert(session);

  ++write_error_map_[error_code];

  bool is_session_degraded =
      degrading_sessions_.find(session) != degrading_sessions_.end();

  UMA_HISTOGRAM_BOOLEAN(
      "Net.QuicConnectivityMonitor.SessionDegradedBeforeWriteError",
      is_session_degraded);

  if (!num_sessions_active_during_current_speculative_connectivity_failure_ &&
      IsErrorRelatedToConnectivity(error_code)) {
    num_sessions_active_during_current_speculative_connectivity_failure_ =
        active_sessions_.size();
  }
}

void QuicConnectivityMonitor::OnSessionClosedAfterHandshake(
    QuicChromiumClientSession* session,
    handles::NetworkHandle network,
    quic::ConnectionCloseSource source,
    quic::QuicErrorCode error_code) {
  if (network != default_network_)
    return;

  if (source == quic::ConnectionCloseSource::FROM_PEER) {
    // Connection closed by the peer post handshake with PUBLIC RESET
    // is most likely a NAT rebinding issue.
    if (error_code == quic::QUIC_PUBLIC_RESET)
      quic_error_map_[error_code]++;
    return;
  }

  if (error_code == quic::QUIC_PACKET_WRITE_ERROR ||
      error_code == quic::QUIC_TOO_MANY_RTOS) {
    // Connection close by self with PACKET_WRITE_ERROR or TOO_MANY_RTOS
    // is likely a connectivity issue.
    quic_error_map_[error_code]++;
  }
}

void QuicConnectivityMonitor::OnSessionRegistered(
    QuicChromiumClientSession* session,
    handles::NetworkHandle network) {
  if (network != default_network_)
    return;

  active_sessions_.insert(session);
  if (num_sessions_active_during_current_speculative_connectivity_failure_) {
    num_sessions_active_during_current_speculative_connectivity_failure_
        .value()++;
  }
}

void QuicConnectivityMonitor::OnSessionRemoved(
    QuicChromiumClientSession* session) {
  degrading_sessions_.erase(session);
  active_sessions_.erase(session);
}

void QuicConnectivityMonitor::OnDefaultNetworkUpdated(
    handles::NetworkHandle default_network) {
  default_network_ = default_network;
  active_sessions_.clear();
  degrading_sessions_.clear();
  num_sessions_active_during_current_speculative_connectivity_failure_ =
      std::nullopt;
  write_error_map_.clear();
  quic_error_map_.clear();
}

void QuicConnectivityMonitor::OnIPAddressChanged() {
  // If handles::NetworkHandle is supported, connectivity monitor will receive
  // notifications via OnDefaultNetworkUpdated.
  if (NetworkChangeNotifier::AreNetworkHandlesSupported())
    return;

  DCHECK_EQ(default_network_, handles::kInvalidNetworkHandle);
  degrading_sessions_.clear();
  write_error_map_.clear();
}

void QuicConnectivityMonitor::OnSessionGoingAwayOnIPAddressChange(
    QuicChromiumClientSession* session) {
  // This should only be called after ConnectivityMonitor gets notified via
  // OnIPAddressChanged().
  DCHECK(degrading_sessions_.empty());
  // |session| that encounters IP address change will lose track which network
  // it is bound to. Future connectivity monitoring may be misleading.
  session->RemoveConnectivityObserver(this);
}

}  // namespace net

"""

```