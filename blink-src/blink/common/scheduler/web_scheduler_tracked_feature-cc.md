Response: Let's break down the thought process for analyzing this C++ code.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of the `web_scheduler_tracked_feature.cc` file within the Chromium Blink engine. This involves identifying what it does, how it relates to web technologies (JavaScript, HTML, CSS), and potential usage scenarios, including errors.

**2. Initial Code Scan - Identifying Key Elements:**

I started by quickly scanning the code, looking for keywords and structures that provide clues:

* **Includes:**  `third_party/blink/public/common/scheduler/web_scheduler_tracked_feature.h`, `<atomic>`, `<map>`, `<vector>`, `third_party/blink/public/common/features.h`. These suggest it deals with scheduling, feature tracking, and potentially feature flags.
* **Namespaces:** `blink::scheduler`. This confirms it's related to the Blink rendering engine's scheduling mechanisms.
* **Global Variables:** `disable_align_wake_ups` (atomic boolean), which hints at controlling wake-up alignment.
* **Structures:** `FeatureNames` (short and human-readable names for features).
* **Functions:**  A large `switch` statement inside `FeatureToNames`, functions like `FeatureToHumanReadableString`, `FeatureToShortString`, `StringToFeature`, `IsRemovedFeature`, `IsFeatureSticky`, `StickyFeatures`, `DisableAlignWakeUpsForProcess`, `IsAlignWakeUpsDisabledForProcess`. These are the core actions the file performs.
* **Enums (implicit):** The use of `WebSchedulerTrackedFeature::kSomething` strongly suggests an enum called `WebSchedulerTrackedFeature`.

**3. Deeper Dive into Core Functionality:**

* **`WebSchedulerTrackedFeature` Enum (Inferred):** The `switch` statement in `FeatureToNames` is the heart of the file. It maps enum values (like `kWebSocket`, `kDocumentLoaded`) to their string representations. This tells me the file is about tracking different web-related features or states.
* **Feature Naming:** The `FeatureNames` struct and the `FeatureToNames` function are about providing both short (likely for internal use) and human-readable names for these tracked features.
* **String Conversion:** `FeatureToHumanReadableString`, `FeatureToShortString`, and `StringToFeature` are clearly for converting between the enum values and their string representations. This is common for serialization, logging, and configuration.
* **"Sticky" Features:** `IsFeatureSticky` and `StickyFeatures` suggest some features are considered "sticky," meaning once they occur, they remain active or tracked for a longer duration. The list in `StickyFeatures` provides concrete examples.
* **Removed Features:** `IsRemovedFeature` indicates a way to identify features that are no longer actively tracked or supported, likely for compatibility or migration purposes.
* **Wake-up Alignment:** `DisableAlignWakeUpsForProcess` and `IsAlignWakeUpsDisabledForProcess` are about a specific optimization related to scheduling wake-ups. Disabling alignment might be for performance tuning in certain scenarios.

**4. Connecting to Web Technologies (JavaScript, HTML, CSS):**

Now, I looked at the specific `WebSchedulerTrackedFeature` values and considered their relation to web technologies:

* **Directly Related:**
    * `kWebSocket`, `kWebTransport`, `kWebRTC`: These are direct JavaScript APIs for real-time communication.
    * `kContainsPlugins`: Directly related to `<embed>` or `<object>` tags in HTML.
    * `kDocumentLoaded`: A key event in the HTML lifecycle.
    * `kSharedWorker`, `kBroadcastChannel`: JavaScript APIs for inter-script communication.
    * Network requests (`kOutstandingNetworkRequestFetch`, `kOutstandingNetworkRequestXHR`, etc.):  Initiated by JavaScript (e.g., `fetch()`, `XMLHttpRequest`).
    * Permissions (`kRequestedMIDIPermission`, etc.):  Requested by JavaScript APIs.
    * `kWebXR`, `kWebLocks`, `kWebHID`, `kWebShare`, `kWebNfc`: Modern JavaScript APIs for accessing device features.
    * `kPrinting`: Initiated via JavaScript (`window.print()`).
    * `kPictureInPicture`, `kSpeechRecognizer`, `kIdleManager`, `kPaymentManager`, `kKeyboardLock`, `kWebOTPService`, `kWebSerial`, `kSmartCard`:  More JavaScript APIs.
    * `kInjectedJavascript`, `kInjectedStyleSheet`:  Relate to dynamically adding `<script>` and `<style>` tags, often via JavaScript.
    * `kUnloadHandler`:  JavaScript event handler (`window.onunload`).
* **Indirectly Related (Through HTTP Headers):**
    * `kMainResourceHasCacheControlNoCache/NoStore`, `kSubresourceHasCacheControlNoCache/NoStore`, `kKeepaliveRequest`: These track HTTP headers sent by the server, influencing how the browser caches and manages resources requested by HTML, CSS, or JavaScript.
* **Parser:**
    * `kParserAborted`:  Relates to the HTML parsing process.

**5. Logical Reasoning, Assumptions, Inputs, and Outputs:**

For logical reasoning, I focused on how the functions would operate:

* **`FeatureToNames`:**  *Input:* a `WebSchedulerTrackedFeature` enum value. *Output:* A `FeatureNames` struct containing the short and human-readable string representations.
* **`StringToFeature`:** *Input:* a string. *Output:* An `std::optional<WebSchedulerTrackedFeature>` which contains the corresponding enum value if found, or `std::nullopt` otherwise.
* **`IsFeatureSticky`:** *Input:* a `WebSchedulerTrackedFeature` enum value. *Output:* `true` if it's in the `StickyFeatures` list, `false` otherwise.

**6. User/Programming Errors:**

I thought about common mistakes developers might make related to the tracked features:

* **Incorrect String Input:**  Using a misspelled or incorrect string with `StringToFeature` would result in `std::nullopt`.
* **Misunderstanding "Sticky" Features:** Developers might not realize that certain actions (like setting `Cache-Control: no-store`) have lasting implications on the scheduler.
* **Not Handling Permissions:**  Trying to use features like WebRTC or Web MIDI without requesting and getting the necessary permissions would trigger the tracking but the feature itself might fail.

**7. Structuring the Output:**

Finally, I organized the findings into the requested categories:

* **Functionality:**  A high-level overview.
* **Relationship to Web Technologies:** Specific examples linking features to JavaScript, HTML, and CSS.
* **Logical Reasoning:**  Describing the behavior of key functions with hypothetical inputs and outputs.
* **User/Programming Errors:** Concrete examples of common mistakes.

This structured approach, starting with a broad overview and then drilling down into specific details, allowed for a comprehensive understanding of the code's purpose and its connections to the broader web development landscape.这个文件 `blink/common/scheduler/web_scheduler_tracked_feature.cc` 的主要功能是定义和管理 Blink 渲染引擎中**被追踪的特性 (Tracked Features)**。这些特性代表了当前页面或渲染进程中正在使用的某些功能或状态。Scheduler（调度器）可以利用这些信息来优化任务调度和资源分配，以提高性能和响应速度。

**具体功能如下:**

1. **定义可追踪的特性枚举 (`WebSchedulerTrackedFeature`)**:  虽然枚举的定义在对应的头文件 `.h` 中，但这个 `.cc` 文件列举了所有可能的追踪特性，并通过 `switch` 语句将每个特性映射到人类可读的名称和简短的名称。

2. **提供特性名称的转换**:
   - `FeatureToHumanReadableString(WebSchedulerTrackedFeature feature)`: 将追踪特性枚举值转换为更易于理解的字符串，例如将 `WebSchedulerTrackedFeature::kWebSocket` 转换为 `"WebSocket live connection"`。
   - `FeatureToShortString(WebSchedulerTrackedFeature feature)`: 将追踪特性枚举值转换为简短的字符串，例如将 `WebSchedulerTrackedFeature::kWebSocket` 转换为 `"websocket"`。这些短字符串通常用于内部标记或统计。
   - `StringToFeature(const std::string& str)`:  尝试将一个短字符串转换回对应的 `WebSchedulerTrackedFeature` 枚举值。如果找不到匹配的特性，则返回 `std::nullopt`。

3. **判断特性是否是 "粘性的" (Sticky)**:
   - `IsFeatureSticky(WebSchedulerTrackedFeature feature)`: 判断一个特性是否是粘性的。粘性特性意味着一旦页面或渲染进程使用了该特性，即使该特性不再活跃，该标记也会保持一段时间。这可以帮助调度器避免过早地进行某些优化，因为用户可能很快又会用到该特性。
   - `StickyFeatures()`: 返回一个包含所有粘性特性的列表。

4. **记录已移除的特性**:
   - `IsRemovedFeature(const std::string& feature)`:  用于判断给定的字符串是否对应于一个已经被移除的追踪特性。这通常用于处理配置或参数解析，以忽略不再使用的特性。

5. **控制 wake-up 对齐 (Wake-up Alignment)**:
   - `DisableAlignWakeUpsForProcess()`: 设置一个全局标志，指示禁用当前进程的 wake-up 对齐优化。
   - `IsAlignWakeUpsDisabledForProcess()`:  检查当前进程是否禁用了 wake-up 对齐优化。Wake-up 对齐是一种调度优化技术，旨在将多个延迟的任务安排在同一时间唤醒，以减少 CPU 唤醒次数并节省电量。

**与 JavaScript, HTML, CSS 功能的关系及举例说明:**

这些追踪的特性通常与 Web 标准提供的 API 和浏览器行为直接相关。它们反映了页面正在使用哪些 JavaScript API，渲染了哪些 HTML 结构，或者遇到了哪些 CSS 相关的场景。

* **JavaScript API:**
    * `WebSchedulerTrackedFeature::kWebSocket`:  当页面使用 `WebSocket` API 创建持久连接时，该特性会被标记。
        * **例子 (JavaScript):** `const socket = new WebSocket('ws://example.com');`
    * `WebSchedulerTrackedFeature::kWebTransport`:  当页面使用 `WebTransport` API 进行双向数据传输时。
        * **例子 (JavaScript):** `const transport = new WebTransport('https://example.com/wt');`
    * `WebSchedulerTrackedFeature::kWebRTC`: 当页面使用 WebRTC API (例如 `getUserMedia`, `RTCPeerConnection`) 进行实时通信时。
        * **例子 (JavaScript):** `navigator.mediaDevices.getUserMedia({ video: true, audio: true });`
    * `WebSchedulerTrackedFeature::kSharedWorker`:  当页面使用了共享 Worker。
        * **例子 (JavaScript):** `const worker = new SharedWorker('worker.js');`
    * `WebSchedulerTrackedFeature::kBroadcastChannel`: 当页面使用了广播频道 API。
        * **例子 (JavaScript):** `const bc = new BroadcastChannel('my_channel');`
    * `WebSchedulerTrackedFeature::kWebLocks`: 当页面使用了 Web Locks API 来协调资源的访问。
        * **例子 (JavaScript):** `navigator.locks.request('my_resource', { mode: 'exclusive' }, () => { ... });`
    * 其他如 `kWebHID`, `kWebShare`, `kWebNfc`, `kPictureInPicture`, `kSpeechRecognizer`, `kIdleManager`, `kPaymentManager`, `kKeyboardLock`, `kWebOTPService`, `kWebSerial`, `kSmartCard` 等都对应着相应的 JavaScript API 的使用。

* **HTML 结构和加载过程:**
    * `WebSchedulerTrackedFeature::kContainsPlugins`: 当页面包含插件 (例如通过 `<embed>` 或 `<object>`) 时。
        * **例子 (HTML):** `<embed src="plugin.swf">`
    * `WebSchedulerTrackedFeature::kDocumentLoaded`: 当页面的主要文档加载完成时。
    * `WebSchedulerTrackedFeature::kUnloadHandler`: 当页面定义了 `unload` 事件处理函数时。
        * **例子 (JavaScript):** `window.addEventListener('unload', function(event) { ... });`

* **CSS 和资源加载:**
    * `WebSchedulerTrackedFeature::kMainResourceHasCacheControlNoCache`, `kMainResourceHasCacheControlNoStore`, `kSubresourceHasCacheControlNoCache`, `kSubresourceHasCacheControlNoStore`:  当主资源或子资源的 HTTP 响应头中包含 `Cache-Control: no-cache` 或 `Cache-Control: no-store` 时。这会影响浏览器的缓存策略。
        * **例子 (HTTP Response Header):** `Cache-Control: no-cache`
    * `WebSchedulerTrackedFeature::kInjectedJavascript`, `kInjectedStyleSheet`: 当页面动态注入了 JavaScript 代码或 CSS 样式表时，这通常是通过 JavaScript 实现的。
        * **例子 (JavaScript):**
            ```javascript
            const script = document.createElement('script');
            script.src = 'external.js';
            document.body.appendChild(script);
            ```
            ```javascript
            const style = document.createElement('style');
            style.innerHTML = '.my-class { color: red; }';
            document.head.appendChild(style);
            ```

* **网络请求:**
    * `WebSchedulerTrackedFeature::kOutstandingNetworkRequestFetch`, `kOutstandingNetworkRequestXHR`, `kOutstandingNetworkRequestOthers`, `kOutstandingNetworkRequestDirectSocket`:  当页面发起网络请求时，根据请求的类型（Fetch API, XMLHttpRequest, 其他, Direct Socket）进行标记。
        * **例子 (JavaScript):**
            ```javascript
            fetch('https://example.com/data');
            const xhr = new XMLHttpRequest();
            xhr.open('GET', 'https://example.com/data');
            xhr.send();
            ```

* **权限请求:**
    * `WebSchedulerTrackedFeature::kRequestedMIDIPermission`, `kRequestedAudioCapturePermission`, `kRequestedVideoCapturePermission`, `kRequestedBackForwardCacheBlockedSensors`, `kRequestedBackgroundWorkPermission`, `kRequestedStorageAccessGrant`: 当页面请求了某些敏感权限时。
        * **例子 (JavaScript):** `navigator.mediaDevices.getUserMedia({ audio: true });` (会触发音频捕获权限请求)

**逻辑推理、假设输入与输出:**

假设我们调用 `StringToFeature` 函数：

* **假设输入:** `"websocket"`
* **输出:** `std::optional<WebSchedulerTrackedFeature>` 包含 `WebSchedulerTrackedFeature::kWebSocket`。

* **假设输入:** `"unknown-feature"`
* **输出:** `std::nullopt` (因为 "unknown-feature" 不是一个已知的追踪特性)。

假设我们调用 `FeatureToHumanReadableString` 函数：

* **假设输入:** `WebSchedulerTrackedFeature::kDocumentLoaded`
* **输出:** `"document loaded"`

假设我们调用 `IsFeatureSticky` 函数：

* **假设输入:** `WebSchedulerTrackedFeature::kWebSocket`
* **输出:** `false` (根据 `StickyFeatures()` 的定义，WebSocket 不是粘性的)

* **假设输入:** `WebSchedulerTrackedFeature::kContainsPlugins`
* **输出:** `true` (根据 `StickyFeatures()` 的定义，包含插件是粘性的)

**用户或编程常见的使用错误:**

1. **在需要 `WebSchedulerTrackedFeature` 枚举值的地方使用了错误的字符串**:
   - **错误示例:**  某个函数期望接收 `WebSchedulerTrackedFeature`，但开发者错误地传递了字符串 `"websoket"` (拼写错误)。
   - **后果:** 该函数可能无法正确识别要追踪的特性，导致调度行为异常或统计数据不准确。

2. **假设某些特性是粘性的，但实际上并非如此 (或反之)**:
   - **错误示例:** 开发者错误地假设只要页面使用过 WebSocket，调度器就会一直保持某种状态。但实际上，WebSocket 的粘性由 `kWebSocketSticky` 控制，而 `kWebSocket` 本身可能在连接关闭后就不再被追踪。
   - **后果:** 可能导致不必要的资源消耗或过早地进行优化，最终影响性能。

3. **在解析配置或参数时，没有正确处理 `StringToFeature` 返回的 `std::nullopt`**:
   - **错误示例:**  代码尝试将一个字符串转换为 `WebSchedulerTrackedFeature`，但没有检查 `StringToFeature` 是否返回了有效值。
   - **后果:**  如果输入的字符串不是有效的追踪特性，可能会导致程序崩溃或出现未定义的行为。

4. **错误地理解粘性特性的生命周期**:
   - **错误示例:**  开发者认为只要页面加载了包含 `Cache-Control: no-store` 的资源，这个特性就会永远被标记，即使之后加载了其他页面。
   - **后果:**  可能导致不正确的性能分析或调度决策。粘性特性通常与特定的渲染进程或页面生命周期相关。

总而言之，`web_scheduler_tracked_feature.cc` 文件定义了一个关键的枚举和相关的辅助函数，用于跟踪 Blink 引擎中各种与 Web 标准相关的特性和状态，这些信息对于调度器进行智能的资源管理和优化至关重要。理解这些追踪特性的含义和生命周期对于开发和调试 Blink 引擎的相关功能非常重要。

Prompt: 
```
这是目录为blink/common/scheduler/web_scheduler_tracked_feature.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/public/common/scheduler/web_scheduler_tracked_feature.h"

#include <atomic>
#include <map>
#include <vector>

#include "third_party/blink/public/common/features.h"

namespace blink {
namespace scheduler {

namespace {

std::atomic_bool disable_align_wake_ups{false};

struct FeatureNames {
  std::string short_name;
  std::string human_readable;
};

FeatureNames FeatureToNames(WebSchedulerTrackedFeature feature) {
  switch (feature) {
    case WebSchedulerTrackedFeature::kWebSocket:
      return {"websocket", "WebSocket live connection"};
    case WebSchedulerTrackedFeature::kWebSocketSticky:
      return {"websocket", "WebSocket used"};
    case WebSchedulerTrackedFeature::kWebTransport:
      return {"webtransport", "WebTransport live connection"};
    case WebSchedulerTrackedFeature::kWebTransportSticky:
      return {"webtransport", "WebTransport used"};
    case WebSchedulerTrackedFeature::kWebRTC:
      return {"rtc", "WebRTC live connection"};
    case WebSchedulerTrackedFeature::kWebRTCSticky:
      return {"rtc", "WebRTC used"};
    case WebSchedulerTrackedFeature::kMainResourceHasCacheControlNoCache:
      return {"response-cache-control-no-cache",
              "main resource has Cache-Control: No-Cache"};
    case WebSchedulerTrackedFeature::kMainResourceHasCacheControlNoStore:
      return {"response-cache-control-no-store",
              "main resource has Cache-Control: No-Store"};
    case WebSchedulerTrackedFeature::kSubresourceHasCacheControlNoCache:
      return {"response-cache-control-no-cache",
              "subresource has Cache-Control: No-Cache"};
    case WebSchedulerTrackedFeature::kSubresourceHasCacheControlNoStore:
      return {"response-cache-control-no-store",
              "subresource has Cache-Control: No-Store"};
    case WebSchedulerTrackedFeature::kContainsPlugins:
      return {"plugins", "page contains plugins"};
    case WebSchedulerTrackedFeature::kDocumentLoaded:
      return {"document-loaded", "document loaded"};
    case WebSchedulerTrackedFeature::kSharedWorker:
      return {"sharedworker", "Shared worker present"};
    case WebSchedulerTrackedFeature::kOutstandingNetworkRequestFetch:
      return {"fetch", "outstanding network request (fetch)"};
    case WebSchedulerTrackedFeature::kOutstandingNetworkRequestXHR:
      return {"outstanding-network-request",
              "outstanding network request (XHR)"};
    case WebSchedulerTrackedFeature::kOutstandingNetworkRequestOthers:
      return {"outstanding-network-request",
              "outstanding network request (others)"};
    case WebSchedulerTrackedFeature::kRequestedMIDIPermission:
      return {"midi", "requested midi permission"};
    case WebSchedulerTrackedFeature::kRequestedAudioCapturePermission:
      return {"audio-capture", "requested audio capture permission"};
    case WebSchedulerTrackedFeature::kRequestedVideoCapturePermission:
      return {"video-capture", "requested video capture permission"};
    case WebSchedulerTrackedFeature::kRequestedBackForwardCacheBlockedSensors:
      return {"sensors", "requested sensors permission"};
    case WebSchedulerTrackedFeature::kRequestedBackgroundWorkPermission:
      return {"background-work", "requested background work permission"};
    case WebSchedulerTrackedFeature::kBroadcastChannel:
      return {"broadcastchannel", "requested broadcast channel permission"};
    case WebSchedulerTrackedFeature::kWebXR:
      return {"webxrdevice", "WebXR"};
    case WebSchedulerTrackedFeature::kWebLocks:
      return {"lock", "WebLocks"};
    case WebSchedulerTrackedFeature::kWebHID:
      return {"webhid", "WebHID"};
    case WebSchedulerTrackedFeature::kWebShare:
      return {"webshare", "WebShare"};
    case WebSchedulerTrackedFeature::kRequestedStorageAccessGrant:
      return {"storageaccess", "requested storage access permission"};
    case WebSchedulerTrackedFeature::kWebNfc:
      return {"webnfc", "WebNfc"};
    case WebSchedulerTrackedFeature::kPrinting:
      return {base::FeatureList::IsEnabled(
                  features::kBackForwardCacheUpdateNotRestoredReasonsName)
                  ? "masked"
                  : "printing",
              "Printing"};
    case WebSchedulerTrackedFeature::kWebDatabase:
      return {base::FeatureList::IsEnabled(
                  features::kBackForwardCacheUpdateNotRestoredReasonsName)
                  ? "masked"
                  : "web-database",
              "WebDatabase"};
    case WebSchedulerTrackedFeature::kPictureInPicture:
      return {"pictureinpicturewindow", "PictureInPicture"};
    case WebSchedulerTrackedFeature::kSpeechRecognizer:
      return {"speechrecognition", "SpeechRecognizer"};
    case WebSchedulerTrackedFeature::kIdleManager:
      return {"idledetector", "IdleManager"};
    case WebSchedulerTrackedFeature::kPaymentManager:
      return {"paymentrequest", "PaymentManager"};
    case WebSchedulerTrackedFeature::kKeyboardLock:
      return {"keyboardlock", "KeyboardLock"};
    case WebSchedulerTrackedFeature::kWebOTPService:
      return {"otpcredential", "SMSService"};
    case WebSchedulerTrackedFeature::kOutstandingNetworkRequestDirectSocket:
      return {"outstanding-network-request",
              "outstanding network request (direct socket)"};
    case WebSchedulerTrackedFeature::kInjectedJavascript:
      return {base::FeatureList::IsEnabled(
                  features::kBackForwardCacheUpdateNotRestoredReasonsName)
                  ? "masked"
                  : "injected-javascript",
              "External javascript injected"};
    case WebSchedulerTrackedFeature::kInjectedStyleSheet:
      return {base::FeatureList::IsEnabled(
                  features::kBackForwardCacheUpdateNotRestoredReasonsName)
                  ? "masked"
                  : "injected-stylesheet",
              "External stylesheet injected"};
    case WebSchedulerTrackedFeature::kKeepaliveRequest:
      return {"response-keep-alive", "requests with keepalive set"};
    case WebSchedulerTrackedFeature::kDummy:
      return {"Dummy", "Dummy for testing"};
    case WebSchedulerTrackedFeature::
        kJsNetworkRequestReceivedCacheControlNoStoreResource:
      return {"response-cache-control-no-store",
              "JavaScript network request received Cache-Control: no-store "
              "resource"};
    case WebSchedulerTrackedFeature::kIndexedDBEvent:
      return {"idbversionchangeevent", "IndexedDB event is pending"};
    case WebSchedulerTrackedFeature::kWebSerial:
      return {"webserial", "Serial port open"};
    case WebSchedulerTrackedFeature::kSmartCard:
      return {"smartcardconnection", "SmartCardContext used"};
    case WebSchedulerTrackedFeature::kLiveMediaStreamTrack:
      return {"mediastream", "page has live MediaStreamTrack"};
    case WebSchedulerTrackedFeature::kUnloadHandler:
      return {base::FeatureList::IsEnabled(
                  features::kBackForwardCacheUpdateNotRestoredReasonsName)
                  ? "unload-handler"
                  : "unload-listener",
              "page contains unload handler"};
    case WebSchedulerTrackedFeature::kParserAborted:
      return {"parser-aborted", "parser was aborted"};
  }
  return {};
}

std::map<std::string, WebSchedulerTrackedFeature> MakeShortNameToFeature() {
  std::map<std::string, WebSchedulerTrackedFeature> short_name_to_feature;
  for (int i = 0; i <= static_cast<int>(WebSchedulerTrackedFeature::kMaxValue);
       i++) {
    WebSchedulerTrackedFeature feature =
        static_cast<WebSchedulerTrackedFeature>(i);
    FeatureNames strs = FeatureToNames(feature);
    if (strs.short_name.size())
      short_name_to_feature[strs.short_name] = feature;
  }
  return short_name_to_feature;
}

const std::map<std::string, WebSchedulerTrackedFeature>&
ShortStringToFeatureMap() {
  static const std::map<std::string, WebSchedulerTrackedFeature>
      short_name_to_feature = MakeShortNameToFeature();
  return short_name_to_feature;
}

}  // namespace

std::string FeatureToHumanReadableString(WebSchedulerTrackedFeature feature) {
  return FeatureToNames(feature).human_readable;
}

std::string FeatureToShortString(WebSchedulerTrackedFeature feature) {
  return FeatureToNames(feature).short_name;
}

std::optional<WebSchedulerTrackedFeature> StringToFeature(
    const std::string& str) {
  auto map = ShortStringToFeatureMap();
  auto it = map.find(str);
  if (it == map.end()) {
    return std::nullopt;
  }
  return it->second;
}

bool IsRemovedFeature(const std::string& feature) {
  // This is an incomplete list. It only contains features that were
  // BFCache-enabled via finch. It does not contain all those that were removed.
  // This function is simple, not efficient because it is called once during
  // finch param parsing.
  const char* removed_features[] = {"MediaSessionImplOnServiceCreated"};
  for (const char* removed_feature : removed_features) {
    if (feature == removed_feature) {
      return true;
    }
  }
  return false;
}

bool IsFeatureSticky(WebSchedulerTrackedFeature feature) {
  return StickyFeatures().Has(feature);
}

WebSchedulerTrackedFeatures StickyFeatures() {
  return {WebSchedulerTrackedFeature::kMainResourceHasCacheControlNoStore,
          WebSchedulerTrackedFeature::kMainResourceHasCacheControlNoCache,
          WebSchedulerTrackedFeature::kSubresourceHasCacheControlNoStore,
          WebSchedulerTrackedFeature::kSubresourceHasCacheControlNoCache,
          WebSchedulerTrackedFeature::kContainsPlugins,
          WebSchedulerTrackedFeature::kDocumentLoaded,
          WebSchedulerTrackedFeature::kRequestedMIDIPermission,
          WebSchedulerTrackedFeature::kRequestedAudioCapturePermission,
          WebSchedulerTrackedFeature::kRequestedVideoCapturePermission,
          WebSchedulerTrackedFeature::kRequestedBackForwardCacheBlockedSensors,
          WebSchedulerTrackedFeature::kRequestedBackgroundWorkPermission,
          WebSchedulerTrackedFeature::kWebLocks,
          WebSchedulerTrackedFeature::kRequestedStorageAccessGrant,
          WebSchedulerTrackedFeature::kWebNfc,
          WebSchedulerTrackedFeature::kPrinting,
          WebSchedulerTrackedFeature::kPictureInPicture,
          WebSchedulerTrackedFeature::kIdleManager,
          WebSchedulerTrackedFeature::kPaymentManager,
          WebSchedulerTrackedFeature::kWebOTPService,
          WebSchedulerTrackedFeature::kInjectedJavascript,
          WebSchedulerTrackedFeature::kInjectedStyleSheet,
          WebSchedulerTrackedFeature::kKeepaliveRequest,
          WebSchedulerTrackedFeature::kDummy,
          WebSchedulerTrackedFeature::
              kJsNetworkRequestReceivedCacheControlNoStoreResource,
          WebSchedulerTrackedFeature::kWebRTCSticky,
          WebSchedulerTrackedFeature::kWebSocketSticky,
          WebSchedulerTrackedFeature::kWebTransportSticky,
          WebSchedulerTrackedFeature::kParserAborted};
}

// static
void DisableAlignWakeUpsForProcess() {
  disable_align_wake_ups.store(true, std::memory_order_relaxed);
}

// static
bool IsAlignWakeUpsDisabledForProcess() {
  return disable_align_wake_ups.load(std::memory_order_relaxed);
}

}  // namespace scheduler
}  // namespace blink

"""

```