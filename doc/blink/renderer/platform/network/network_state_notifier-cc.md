Response:
Let's break down the thought process for analyzing the provided C++ code.

1. **Understand the Goal:** The request asks for the functionality of the `NetworkStateNotifier.cc` file in the Chromium Blink engine, its relation to web technologies (JS, HTML, CSS), logical reasoning examples, and common usage errors.

2. **Initial Scan and Identification of Key Class:**  The first step is to quickly scan the code and identify the core class: `NetworkStateNotifier`. This class name itself suggests its primary purpose: notifying about network state changes.

3. **Core Functionality - What does it *do*?:**  Read through the class methods and data members. Look for actions and state. Key observations:
    * **State Tracking:**  The `NetworkState` struct holds information like `on_line`, `type`, `max_bandwidth_mbps`, `effective_type`, `http_rtt`, `save_data`, etc. This confirms the "network state tracking" aspect.
    * **Observers:** The `AddConnectionObserver` and `AddOnLineObserver` methods, along with the `connection_observers_` and `on_line_state_observers_` data members, strongly suggest a "publish-subscribe" pattern where other parts of the browser can be notified of network changes.
    * **Setters:** Methods like `SetOnLine`, `SetWebConnection`, `SetNetworkQuality`, and `SetSaveDataEnabled` are clearly for updating the tracked network state.
    * **Overrides:** The `SetNetworkConnectionInfoOverride` and related methods indicate a mechanism to temporarily or manually set the network state, potentially for testing or specific scenarios.
    * **Randomization:** The `GetRandomMultiplier`, `RoundRtt`, and `RoundMbps` methods hint at a privacy mechanism to prevent precise network fingerprinting.

4. **Relating to Web Technologies (JS, HTML, CSS):** This is where the "why does this matter to web developers?" question comes in. Consider how network state can influence web page behavior:
    * **JavaScript `navigator.onLine`:** The `SetOnLine` method directly relates to the JavaScript `navigator.onLine` property.
    * **JavaScript Network Information API (`navigator.connection`):** The various `Set` methods, especially those related to connection type, effective type, RTT, and downlink speed, directly correspond to the information exposed by the Network Information API. Think about how JavaScript could use this information for:
        * **Adaptive loading:** Serving different image sizes or content based on connection speed.
        * **Offline experiences:** Caching data or showing different UI when offline.
        * **Real-time feedback:** Indicating connection quality to the user.
    * **Client Hints (HTML `Accept-CH`):**  The code includes `<client_hints.h>` and references to `WebEffectiveConnectionType`. This connects to the Client Hints mechanism where the browser informs the server about network conditions to optimize resource delivery.
    * **CSS Media Queries (indirect):** While not directly linked in the code, understand that the underlying network state *influences* decisions made in JavaScript, which *could* then dynamically change CSS classes or styles. For example, a script might add a class like `.slow-network` to the `body` element, and CSS could target that class.

5. **Logical Reasoning (Input/Output):**  Focus on specific methods and their effects. Choose straightforward examples:
    * **`SetOnLine(true)` ->  Observers are notified of `onLine: true`.**
    * **`SetWebConnection(WIFI, 10)` -> Observers are notified with `connectionType: 'wifi'`, `maxBandwidth: 10`.**
    * **Overrides are interesting:**  Show how setting an override changes the reported state compared to the underlying system state.

6. **Common Usage Errors:** Think about how developers might interact with or misunderstand the implications of this code *from the JavaScript side*.
    * **Relying *only* on `navigator.onLine`:**  Explain that `onLine` is a simple boolean and doesn't capture nuanced network quality.
    * **Ignoring the asynchronous nature of network changes:** Emphasize that network state can change at any time, and developers need to listen for events rather than assuming a static state.
    * **Over-reliance on specific connection types:** Highlight that network conditions are dynamic, and relying too heavily on assumptions about "wifi" vs. "cellular" might be problematic.

7. **Structure and Refine:** Organize the findings into logical sections (Functionality, Relation to Web Tech, Logical Reasoning, Usage Errors). Use clear language and provide concrete examples. Review the code again to ensure nothing important was missed.

8. **Self-Correction/Refinement During Analysis:**
    * **Initial thought:** "This is just about network status."
    * **Correction:**  Realize the observer pattern is crucial for understanding how this information is distributed within the browser.
    * **Initial thought:** "It's only for internal use."
    * **Correction:**  Recognize the direct connection to web APIs like `navigator.onLine` and the Network Information API, making it relevant to web developers.
    * **Initial thought:**  Focus only on the `Set` methods.
    * **Correction:**  Analyze the `Get` methods (like the holdback methods) and the randomization logic to gain a more complete picture.

By following these steps, combining careful code reading with knowledge of web technologies, and thinking about potential developer interactions, you can arrive at a comprehensive explanation of the `NetworkStateNotifier.cc` file's functionality and its significance.
这个文件 `blink/renderer/platform/network/network_state_notifier.cc` 的主要功能是 **在 Chromium Blink 渲染引擎中管理和通知网络状态的变化**。它充当一个中心化的状态管理器，负责跟踪设备的网络连接状态和质量，并向感兴趣的组件（观察者）广播这些变化。

以下是其更详细的功能列表：

**核心功能：**

1. **跟踪网络连接状态:**
   - 维护当前的网络连接类型 (例如：WiFi, 蜂窝数据, 以太网, 未知)。
   - 跟踪最大带宽 (max_bandwidth_mbps)。
   - 跟踪设备是否在线 (on_line)。
   - 跟踪数据节省模式是否启用 (save_data)。

2. **跟踪网络质量信息:**
   - 维护估计的有效连接类型 (EffectiveConnectionType，例如：4G, 3G, 2G, Slow 2G)。
   - 跟踪 HTTP 往返时延 (HTTP RTT)。
   - 跟踪传输层往返时延 (Transport RTT)。
   - 跟踪下行吞吐量 (downlink_throughput_mbps)。
   - 支持网络质量 Web Holdback，允许暂时性地模拟较差的网络连接质量。

3. **观察者模式:**
   - 允许其他 Blink 组件注册为观察者，以便在网络状态发生变化时接收通知。
   - 提供两种类型的观察者：
     - `ConnectionObserver`: 接收连接类型、带宽、有效连接类型、RTT、吞吐量和数据节省模式的变化通知。
     - `OnLineObserver`: 接收设备在线状态的变化通知。

4. **状态更新机制:**
   - 提供方法 (`SetOnLine`, `SetWebConnection`, `SetNetworkQuality`, `SetSaveDataEnabled`) 来更新内部维护的网络状态。
   - 使用 `ScopedNotifier` 类确保在状态更新前后比较状态，并在发生实际变化时才通知观察者。

5. **覆盖 (Override) 机制:**
   - 允许设置临时的网络连接信息覆盖 (`SetNetworkConnectionInfoOverride`, `SetSaveDataEnabledOverride`)，用于测试或其他特定场景。
   - 提供清除覆盖的方法 (`ClearOverride`)。

6. **隐私保护机制:**
   - 引入随机化机制 (`GetRandomMultiplier`, `RoundRtt`, `RoundMbps`) 来模糊化报告的 RTT 和吞吐量信息，以减少跨域指纹追踪。这个随机因子基于主机名和一个随机盐值。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

`NetworkStateNotifier` 的功能直接或间接地影响 Web 内容的加载和渲染，并且其状态可以通过 JavaScript API 暴露给 Web 开发者。

* **JavaScript `navigator.onLine` 属性:**
    - **功能关系:** `NetworkStateNotifier` 的 `SetOnLine` 方法更新了设备的在线状态，这个状态会同步到 JavaScript 的 `navigator.onLine` 属性。
    - **举例说明:**
        - **假设输入:**  `NetworkStateNotifier::SetOnLine(true)` 被调用。
        - **输出:**  在浏览器中运行的 JavaScript 代码访问 `navigator.onLine` 将返回 `true`。
        - **Web 开发应用:** JavaScript 可以监听 `online` 和 `offline` 事件，根据 `navigator.onLine` 的值来调整应用的行为，例如在离线时显示提示信息或启用离线缓存。

* **JavaScript Network Information API (`navigator.connection`):**
    - **功能关系:**  `NetworkStateNotifier` 维护的连接类型、有效连接类型、RTT 和吞吐量等信息，与 JavaScript 的 Network Information API 提供的属性（例如 `effectiveType`, `rtt`, `downlink`) 相对应。
    - **举例说明:**
        - **假设输入:**  `NetworkStateNotifier::SetNetworkQuality(WebEffectiveConnectionType::kType4G, base::Milliseconds(100), base::Milliseconds(50), 1000)` 被调用。
        - **输出:**  在支持 Network Information API 的浏览器中，JavaScript 代码访问 `navigator.connection.effectiveType` 可能返回 `"4g"`，`navigator.connection.rtt` 可能返回一个接近 100 的值， `navigator.connection.downlink` 可能返回一个接近 1 的值 (Mbps)。
        - **Web 开发应用:**  JavaScript 可以使用 Network Information API 来优化资源加载，例如在低速网络下加载低分辨率图片或延迟加载非关键资源。

* **HTML Client Hints (`Accept-CH` 头部):**
    - **功能关系:**  `NetworkStateNotifier` 维护的有效连接类型等信息可以用于生成 Client Hints 请求头部，告知服务器客户端的网络状况。
    - **举例说明:**
        - **假设输入:** `NetworkStateNotifier` 检测到当前网络有效连接类型为 `WebEffectiveConnectionType::kTypeSlow2G`。
        - **输出:**  浏览器在发送 HTTP 请求时，可能会包含类似 `Accept-CH: ECT` 的头部，并且在后续的请求中发送 `ECT: slow-2g` 头部。
        - **Web 开发应用:**  服务器可以根据 Client Hints 头部信息，为不同网络状况的用户提供不同的资源或内容优化，例如提供更小的图片、更简化的 CSS 或 JavaScript。

* **CSS Media Queries (间接影响):**
    - **功能关系:** 虽然 `NetworkStateNotifier` 不直接操作 CSS，但其提供的网络状态信息可以通过 JavaScript 传递给 CSS，或者影响浏览器的渲染行为，从而间接影响 CSS 的应用。
    - **举例说明:**
        - **假设输入:**  `NetworkStateNotifier` 检测到网络连接速度较慢。
        - **输出:** JavaScript 可能会根据 Network Information API 的信息，给 `<body>` 元素添加一个特定的 class (例如 `slow-network`)。
        - **Web 开发应用:**  CSS 可以定义针对该 class 的样式，例如隐藏动画或加载指示器，以改善在慢速网络下的用户体验。

**逻辑推理的假设输入与输出:**

* **场景 1: 网络从离线变为在线**
    - **假设输入:**  初始状态 `state_.on_line = false`，调用 `NetworkStateNotifier::SetOnLine(true)`。
    - **输出:** 所有注册的 `OnLineObserver` 会收到 `OnLineStateChange(true)` 的回调。JavaScript 的 `navigator.onLine` 属性变为 `true`，触发 `window.ononline` 事件。

* **场景 2: 网络连接类型变化**
    - **假设输入:** 初始状态 `state_.type = WebConnectionType::kWifi`，调用 `NetworkStateNotifier::SetWebConnection(WebConnectionType::kCellular, 0.5)`。
    - **输出:** 所有注册的 `ConnectionObserver` 会收到 `ConnectionChange(WebConnectionType::kCellular, 0.5, ...)` 的回调。JavaScript 的 `navigator.connection.type` 可能会更新为 `"cellular"`。

* **场景 3: 设置网络质量覆盖**
    - **假设输入:** 调用 `NetworkStateNotifier::SetNetworkConnectionInfoOverride(false, WebConnectionType::kNone, WebEffectiveConnectionType::kType2G, 1000, 0.1)`。
    - **输出:**  之后查询网络状态的组件将看到覆盖后的状态：`on_line = false`, `type = WebConnectionType::kNone`, `effective_type = WebEffectiveConnectionType::kType2G`, `http_rtt` 接近 1000ms, `max_bandwidth_mbps = 0.1`。  JavaScript 的 Network Information API 将反映这些覆盖后的值。

**用户或编程常见的使用错误举例说明：**

1. **过度依赖 `navigator.onLine` 进行精细化网络判断:**
   - **错误:** 开发者只检查 `navigator.onLine` 来判断网络状况，并据此决定是否加载某些资源。
   - **问题:** `navigator.onLine` 只是一个简单的布尔值，指示浏览器是否可以访问局域网或互联网。即使 `navigator.onLine` 为 `true`，网络连接可能仍然很慢或不稳定。
   - **正确做法:**  结合使用 Network Information API 来获取更详细的网络质量信息，例如 `effectiveType`, `rtt`, `downlink`，以便做出更精细的决策。

2. **没有正确监听网络状态变化事件:**
   - **错误:**  开发者在页面加载时获取一次 `navigator.connection` 的值，并假设网络状态保持不变。
   - **问题:** 网络状态是动态变化的。如果连接类型或质量在用户浏览过程中发生变化，应用可能无法做出相应的调整。
   - **正确做法:**  监听 `navigator.connection` 上的 `change` 事件，以便在网络状态变化时更新应用的行为。

3. **在不必要的情况下使用网络状态覆盖:**
   - **错误:**  开发者为了某种临时的需求或调试，设置了网络状态覆盖，但忘记及时清除覆盖。
   - **问题:**  这会导致浏览器的网络行为与实际情况不符，影响用户体验，甚至可能导致一些功能异常。
   - **正确做法:**  谨慎使用网络状态覆盖，并在使用完毕后立即调用 `ClearOverride` 清除覆盖。

4. **假设所有浏览器都支持 Network Information API:**
   - **错误:**  开发者直接使用 Network Information API 的属性，没有进行特性检测。
   - **问题:**  Network Information API 的支持程度在不同浏览器之间可能存在差异。在不支持该 API 的浏览器中，访问相关属性可能会导致错误。
   - **正确做法:**  在使用 Network Information API 之前，先进行特性检测，例如检查 `navigator.connection` 是否存在。

总而言之，`blink/renderer/platform/network/network_state_notifier.cc` 是 Blink 引擎中一个至关重要的组件，它集中管理网络状态信息，并将这些信息传递给浏览器内部的各个部分以及通过 JavaScript API 暴露给 Web 开发者，从而使 Web 应用能够感知并适应不同的网络环境。

Prompt: 
```
这是目录为blink/renderer/platform/network/network_state_notifier.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
/*
 * Copyright (C) 2008 Apple Inc. All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/network/network_state_notifier.h"

#include <memory>

#include "base/containers/contains.h"
#include "base/synchronization/lock.h"
#include "base/task/single_thread_task_runner.h"
#include "net/nqe/effective_connection_type.h"
#include "net/nqe/network_quality_estimator_params.h"
#include "services/network/public/cpp/client_hints.h"
#include "third_party/blink/public/common/client_hints/client_hints.h"
#include "third_party/blink/public/mojom/webpreferences/web_preferences.mojom-blink.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_base.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/string_hash.h"
#include "third_party/blink/renderer/platform/wtf/threading.h"
#include "third_party/blink/renderer/platform/wtf/wtf.h"

namespace blink {

using mojom::blink::EffectiveConnectionType;

namespace {

// Typical HTTP RTT value corresponding to a given WebEffectiveConnectionType
// value. Taken from
// https://cs.chromium.org/chromium/src/net/nqe/network_quality_estimator_params.cc.
const base::TimeDelta kTypicalHttpRttEffectiveConnectionType
    [static_cast<size_t>(WebEffectiveConnectionType::kMaxValue) + 1] = {
        base::Milliseconds(0),    base::Milliseconds(0),
        base::Milliseconds(3600), base::Milliseconds(1800),
        base::Milliseconds(450),  base::Milliseconds(175)};

// Typical downlink throughput (in Mbps) value corresponding to a given
// WebEffectiveConnectionType value. Taken from
// https://cs.chromium.org/chromium/src/net/nqe/network_quality_estimator_params.cc.
const double kTypicalDownlinkMbpsEffectiveConnectionType
    [static_cast<size_t>(WebEffectiveConnectionType::kMaxValue) + 1] = {
        0, 0, 0.040, 0.075, 0.400, 1.600};

}  // namespace

NetworkStateNotifier& GetNetworkStateNotifier() {
  DEFINE_THREAD_SAFE_STATIC_LOCAL(NetworkStateNotifier, network_state_notifier,
                                  ());
  return network_state_notifier;
}

NetworkStateNotifier::ScopedNotifier::ScopedNotifier(
    NetworkStateNotifier& notifier)
    : notifier_(notifier) {
  DCHECK(IsMainThread());
  before_ = notifier_.has_override_ ? notifier_.override_ : notifier_.state_;
}

NetworkStateNotifier::ScopedNotifier::~ScopedNotifier() {
  DCHECK(IsMainThread());
  const NetworkState& after =
      notifier_.has_override_ ? notifier_.override_ : notifier_.state_;
  if ((after.type != before_.type ||
       after.max_bandwidth_mbps != before_.max_bandwidth_mbps ||
       after.effective_type != before_.effective_type ||
       after.http_rtt != before_.http_rtt ||
       after.transport_rtt != before_.transport_rtt ||
       after.downlink_throughput_mbps != before_.downlink_throughput_mbps ||
       after.save_data != before_.save_data) &&
      before_.connection_initialized) {
    notifier_.NotifyObservers(notifier_.connection_observers_,
                              ObserverType::kConnectionType, after);
  }
  if (after.on_line != before_.on_line && before_.on_line_initialized) {
    notifier_.NotifyObservers(notifier_.on_line_state_observers_,
                              ObserverType::kOnLineState, after);
  }
}

NetworkStateNotifier::NetworkStateObserverHandle::NetworkStateObserverHandle(
    NetworkStateNotifier* notifier,
    NetworkStateNotifier::ObserverType type,
    NetworkStateNotifier::NetworkStateObserver* observer,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner)
    : notifier_(notifier),
      type_(type),
      observer_(observer),
      task_runner_(std::move(task_runner)) {}

NetworkStateNotifier::NetworkStateObserverHandle::
    ~NetworkStateObserverHandle() {
  notifier_->RemoveObserver(type_, observer_, std::move(task_runner_));
}

void NetworkStateNotifier::SetOnLine(bool on_line) {
  DCHECK(IsMainThread());
  ScopedNotifier notifier(*this);
  {
    base::AutoLock locker(lock_);
    state_.on_line_initialized = true;
    state_.on_line = on_line;
  }
}

void NetworkStateNotifier::SetWebConnection(WebConnectionType type,
                                            double max_bandwidth_mbps) {
  DCHECK(IsMainThread());
  ScopedNotifier notifier(*this);
  {
    base::AutoLock locker(lock_);
    state_.connection_initialized = true;
    state_.type = type;
    state_.max_bandwidth_mbps = max_bandwidth_mbps;
  }
}

void NetworkStateNotifier::SetNetworkQuality(WebEffectiveConnectionType type,
                                             base::TimeDelta http_rtt,
                                             base::TimeDelta transport_rtt,
                                             int downlink_throughput_kbps) {
  DCHECK(IsMainThread());
  ScopedNotifier notifier(*this);
  {
    base::AutoLock locker(lock_);

    state_.effective_type = type;
    state_.http_rtt = std::nullopt;
    state_.transport_rtt = std::nullopt;
    state_.downlink_throughput_mbps = std::nullopt;

    if (http_rtt.InMilliseconds() >= 0)
      state_.http_rtt = http_rtt;

    if (transport_rtt.InMilliseconds() >= 0)
      state_.transport_rtt = transport_rtt;

    if (downlink_throughput_kbps >= 0) {
      state_.downlink_throughput_mbps =
          static_cast<double>(downlink_throughput_kbps) / 1000;
    }
  }
}

void NetworkStateNotifier::SetNetworkQualityWebHoldback(
    WebEffectiveConnectionType type) {
  DCHECK(IsMainThread());
  if (type == WebEffectiveConnectionType::kTypeUnknown)
    return;
  ScopedNotifier notifier(*this);
  {
    base::AutoLock locker(lock_);

    state_.network_quality_web_holdback = type;
  }
}

std::unique_ptr<NetworkStateNotifier::NetworkStateObserverHandle>
NetworkStateNotifier::AddConnectionObserver(
    NetworkStateObserver* observer,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner) {
  AddObserverToMap(connection_observers_, observer, task_runner);
  return std::make_unique<NetworkStateNotifier::NetworkStateObserverHandle>(
      this, ObserverType::kConnectionType, observer, task_runner);
}

void NetworkStateNotifier::SetSaveDataEnabled(bool enabled) {
  DCHECK(IsMainThread());
  ScopedNotifier notifier(*this);
  {
    base::AutoLock locker(lock_);
    state_.save_data = enabled;
  }
}

std::unique_ptr<NetworkStateNotifier::NetworkStateObserverHandle>
NetworkStateNotifier::AddOnLineObserver(
    NetworkStateObserver* observer,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner) {
  AddObserverToMap(on_line_state_observers_, observer, task_runner);
  return std::make_unique<NetworkStateNotifier::NetworkStateObserverHandle>(
      this, ObserverType::kOnLineState, observer, task_runner);
}

void NetworkStateNotifier::SetNetworkConnectionInfoOverride(
    bool on_line,
    WebConnectionType type,
    std::optional<WebEffectiveConnectionType> effective_type,
    int64_t http_rtt_msec,
    double max_bandwidth_mbps) {
  DCHECK(IsMainThread());
  ScopedNotifier notifier(*this);
  {
    base::AutoLock locker(lock_);
    has_override_ = true;
    override_.on_line_initialized = true;
    override_.on_line = on_line;
    override_.connection_initialized = true;
    override_.type = type;
    override_.max_bandwidth_mbps = max_bandwidth_mbps;

    if (!effective_type && http_rtt_msec > 0) {
      base::TimeDelta http_rtt(base::Milliseconds(http_rtt_msec));
      // Threshold values taken from
      // net/nqe/network_quality_estimator_params.cc.
      if (http_rtt >=
          net::kHttpRttEffectiveConnectionTypeThresholds[static_cast<int>(
              EffectiveConnectionType::kEffectiveConnectionSlow2GType)]) {
        effective_type = WebEffectiveConnectionType::kTypeSlow2G;
      } else if (http_rtt >=
                 net::kHttpRttEffectiveConnectionTypeThresholds[static_cast<
                     int>(
                     EffectiveConnectionType::kEffectiveConnection2GType)]) {
        effective_type = WebEffectiveConnectionType::kType2G;
      } else if (http_rtt >=
                 net::kHttpRttEffectiveConnectionTypeThresholds[static_cast<
                     int>(
                     EffectiveConnectionType::kEffectiveConnection3GType)]) {
        effective_type = WebEffectiveConnectionType::kType3G;
      } else {
        effective_type = WebEffectiveConnectionType::kType4G;
      }
    }
    override_.effective_type = effective_type
                                   ? effective_type.value()
                                   : WebEffectiveConnectionType::kTypeUnknown;
    override_.http_rtt = base::Milliseconds(http_rtt_msec);
    override_.downlink_throughput_mbps = max_bandwidth_mbps;
  }
}

void NetworkStateNotifier::SetSaveDataEnabledOverride(bool enabled) {
  DCHECK(IsMainThread());
  ScopedNotifier notifier(*this);
  {
    base::AutoLock locker(lock_);
    has_override_ = true;
    override_.on_line_initialized = true;
    override_.connection_initialized = true;
    override_.save_data = enabled;
  }
}

void NetworkStateNotifier::ClearOverride() {
  DCHECK(IsMainThread());
  ScopedNotifier notifier(*this);
  {
    base::AutoLock locker(lock_);
    has_override_ = false;
  }
}

void NetworkStateNotifier::NotifyObservers(ObserverListMap& map,
                                           ObserverType type,
                                           const NetworkState& state) {
  DCHECK(IsMainThread());
  base::AutoLock locker(lock_);
  for (const auto& entry : map) {
    entry.value->PostTask(
        FROM_HERE,
        base::BindOnce(&NetworkStateNotifier::NotifyObserverOnTaskRunner,
                       base::Unretained(this), base::UnsafeDangling(entry.key),
                       type, state));
  }
}

void NetworkStateNotifier::NotifyObserverOnTaskRunner(
    MayBeDangling<NetworkStateObserver> observer,
    ObserverType type,
    const NetworkState& state) {
  {
    base::AutoLock locker(lock_);
    ObserverListMap& map = GetObserverMapFor(type);
    // It's safe to pass a MayBeDangling pointer to find().
    ObserverListMap::iterator it = map.find(observer);
    if (map.end() == it) {
      return;
    }
    DCHECK(it->value->RunsTasksInCurrentSequence());
  }

  switch (type) {
    case ObserverType::kOnLineState:
      observer->OnLineStateChange(state.on_line);
      return;
    case ObserverType::kConnectionType:
      observer->ConnectionChange(
          state.type, state.max_bandwidth_mbps, state.effective_type,
          state.http_rtt, state.transport_rtt, state.downlink_throughput_mbps,
          state.save_data);
      return;
    default:
      NOTREACHED();
  }
}

NetworkStateNotifier::ObserverListMap& NetworkStateNotifier::GetObserverMapFor(
    ObserverType type) {
  switch (type) {
    case ObserverType::kConnectionType:
      return connection_observers_;
    case ObserverType::kOnLineState:
      return on_line_state_observers_;
    default:
      NOTREACHED();
  }
}

void NetworkStateNotifier::AddObserverToMap(
    ObserverListMap& map,
    NetworkStateObserver* observer,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner) {
  DCHECK(task_runner->RunsTasksInCurrentSequence());
  DCHECK(observer);

  base::AutoLock locker(lock_);
  ObserverListMap::AddResult result =
      map.insert(observer, std::move(task_runner));
  DCHECK(result.is_new_entry);
}

void NetworkStateNotifier::RemoveObserver(
    ObserverType type,
    NetworkStateObserver* observer,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner) {
  DCHECK(task_runner->RunsTasksInCurrentSequence());
  DCHECK(observer);

  base::AutoLock locker(lock_);
  ObserverListMap& map = GetObserverMapFor(type);
  DCHECK(base::Contains(map, observer));
  map.erase(observer);
}

// static
String NetworkStateNotifier::EffectiveConnectionTypeToString(
    WebEffectiveConnectionType type) {
  return network::kWebEffectiveConnectionTypeMapping.at(
      static_cast<size_t>(type));
}

double NetworkStateNotifier::GetRandomMultiplier(const String& host) const {
  // The random number should be a function of the hostname to reduce
  // cross-origin fingerprinting. The random number should also be a function
  // of randomized salt which is known only to the device. This prevents
  // origin from removing noise from the estimates.
  if (!host)
    return 1.0;

  unsigned hash = WTF::GetHash(host) + RandomizationSalt();
  double random_multiplier = 0.9 + static_cast<double>((hash % 21)) * 0.01;
  DCHECK_LE(0.90, random_multiplier);
  DCHECK_GE(1.10, random_multiplier);
  return random_multiplier;
}

uint32_t NetworkStateNotifier::RoundRtt(
    const String& host,
    const std::optional<base::TimeDelta>& rtt) const {
  if (!rtt.has_value()) {
    // RTT is unavailable. So, return the fastest value.
    return 0;
  }

  // Limit the maximum reported value and the granularity to reduce
  // fingerprinting.
  constexpr auto kMaxRtt = base::Seconds(3);
  constexpr auto kGranularity = base::Milliseconds(50);

  const base::TimeDelta modified_rtt =
      std::min(rtt.value() * GetRandomMultiplier(host), kMaxRtt);
  DCHECK_GE(modified_rtt, base::TimeDelta());
  return static_cast<uint32_t>(
      modified_rtt.RoundToMultiple(kGranularity).InMilliseconds());
}

double NetworkStateNotifier::RoundMbps(
    const String& host,
    const std::optional<double>& downlink_mbps) const {
  // Limit the size of the buckets and the maximum reported value to reduce
  // fingerprinting.
  static const size_t kBucketSize = 50;
  static const double kMaxDownlinkKbps = 10.0 * 1000;

  double downlink_kbps = 0;
  if (!downlink_mbps.has_value()) {
    // Throughput is unavailable. So, return the fastest value.
    downlink_kbps = kMaxDownlinkKbps;
  } else {
    downlink_kbps = downlink_mbps.value() * 1000;
  }
  downlink_kbps *= GetRandomMultiplier(host);

  downlink_kbps = std::min(downlink_kbps, kMaxDownlinkKbps);

  DCHECK_LE(0, downlink_kbps);
  DCHECK_GE(kMaxDownlinkKbps, downlink_kbps);
  // Round down to the nearest kBucketSize kbps value.
  double downlink_kbps_rounded =
      std::round(downlink_kbps / kBucketSize) * kBucketSize;

  // Convert from Kbps to Mbps.
  return downlink_kbps_rounded / 1000;
}

std::optional<WebEffectiveConnectionType>
NetworkStateNotifier::GetWebHoldbackEffectiveType() const {
  base::AutoLock locker(lock_);

  const NetworkState& state = has_override_ ? override_ : state_;
  // TODO (tbansal): Add a DCHECK to check that |state.on_line_initialized| is
  // true once https://crbug.com/728771 is fixed.
  return state.network_quality_web_holdback;
}

std::optional<base::TimeDelta> NetworkStateNotifier::GetWebHoldbackHttpRtt()
    const {
  std::optional<WebEffectiveConnectionType> override_ect =
      GetWebHoldbackEffectiveType();

  if (override_ect) {
    return kTypicalHttpRttEffectiveConnectionType[static_cast<size_t>(
        override_ect.value())];
  }
  return std::nullopt;
}

std::optional<double>
NetworkStateNotifier::GetWebHoldbackDownlinkThroughputMbps() const {
  std::optional<WebEffectiveConnectionType> override_ect =
      GetWebHoldbackEffectiveType();

  if (override_ect) {
    return kTypicalDownlinkMbpsEffectiveConnectionType[static_cast<size_t>(
        override_ect.value())];
  }
  return std::nullopt;
}

void NetworkStateNotifier::GetMetricsWithWebHoldback(
    WebConnectionType* type,
    double* downlink_max_mbps,
    WebEffectiveConnectionType* effective_type,
    std::optional<base::TimeDelta>* http_rtt,
    std::optional<double>* downlink_mbps,
    bool* save_data) const {
  base::AutoLock locker(lock_);
  const NetworkState& state = has_override_ ? override_ : state_;

  *type = state.type;
  *downlink_max_mbps = state.max_bandwidth_mbps;

  std::optional<WebEffectiveConnectionType> override_ect =
      state.network_quality_web_holdback;
  if (override_ect) {
    *effective_type = override_ect.value();
    *http_rtt = kTypicalHttpRttEffectiveConnectionType[static_cast<size_t>(
        override_ect.value())];
    *downlink_mbps =
        kTypicalDownlinkMbpsEffectiveConnectionType[static_cast<size_t>(
            override_ect.value())];
  } else {
    *effective_type = state.effective_type;
    *http_rtt = state.http_rtt;
    *downlink_mbps = state.downlink_throughput_mbps;
  }
  *save_data = state.save_data;
}

}  // namespace blink

"""

```