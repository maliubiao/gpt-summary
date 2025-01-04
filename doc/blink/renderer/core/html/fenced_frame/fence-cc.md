Response:
Let's break down the thought process to analyze the provided `fence.cc` file.

**1. Initial Scan and Keyword Identification:**

The first step is a quick scan of the code, looking for recurring keywords and familiar patterns. Keywords like `Fence`, `reportEvent`, `setReportEventDataForAutomaticBeacons`, `getNestedConfigs`, `disableUntrustedNetwork`, `reportPrivateAggregationEvent`, `notifyEvent`, and class names like `FenceEvent`, `FencedFrameConfig` jump out. Include files like `<optional>`, "base/feature_list.h", "third_party/blink/public/common/features.h",  "third_party/blink/public/mojom/fenced_frame/fenced_frame.mojom-blink.h", and  "third_party/blink/renderer/bindings/core/v8/..."  give hints about the file's purpose within the Blink rendering engine.

**2. Class Name and Core Purpose:**

The file name `fence.cc` and the class name `Fence` strongly suggest this file implements the functionality for the `<fencedframe>` element. The comments at the top confirm this.

**3. Function-by-Function Analysis:**

Now, go through each function systematically. For each function, ask:

* **What does it do?**  (High-level description)
* **What are its inputs?** (Parameters)
* **What are its outputs or side effects?** (Return values, sending IPC messages, throwing exceptions, logging to the console)
* **Are there any conditional checks or feature flags involved?** (Using `base::FeatureList`)
* **Does it interact with other Blink components (like the DOM, Frame, Loader)?**
* **Does it relate to JavaScript, HTML, or CSS?**  (Specifically look for interactions with V8 bindings, DOM elements, or styling concerns.)

**Example - `reportEvent` function:**

* **Overload 1 (taking `V8UnionFenceEventOrString`):**  This looks like a dispatcher, handling either a string (for private aggregation) or a `FenceEvent` object.
* **Overload 2 (taking `FenceEvent*`):**
    * **Does:** Reports an event from inside the fenced frame.
    * **Inputs:** A `FenceEvent` object.
    * **Side Effects:**  Sends a reporting beacon via IPC (either to predefined destinations or a custom URL). Throws exceptions for security or type errors. Logs console messages for errors or informational purposes.
    * **Conditions/Features:** Checks if the document is active, checks for reserved event prefixes, uses feature flags like `kAdAuctionReportingWithMacroApi`.
    * **Interactions:** Accesses `DomWindow`, `LocalFrame`, `DocumentLoader`, `FencedFrameProperties`, `LocalFrameHostRemote`.
    * **Relation to JS/HTML/CSS:** Directly interacts with JavaScript through the `FenceEvent` object, which is likely constructed in JS. The reporting mechanism is tied to the fenced frame element in the HTML. CSS isn't directly involved in the *reporting* logic itself.

**4. Identifying Relationships with Web Technologies:**

As you analyze each function, specifically think about how it connects to the web platform:

* **JavaScript:** Look for interactions with V8 types (like `ScriptPromise`, `ExceptionState`, V8 object wrappers), event handling, and the overall asynchronous nature of web APIs.
* **HTML:** The `<fencedframe>` element is the central point. The functionality manages reporting *from within* this element. Consider attributes or APIs exposed on the element.
* **CSS:** While less direct, think about how CSS might be affected by fenced frames (isolation, styling boundaries). The provided code doesn't directly manipulate CSS, but it's worth noting the isolation aspect.

**5. Inferring Logic and Providing Examples:**

When the code has conditional logic (like checking for feature flags or required properties),  create hypothetical input scenarios and predict the output. For example, with `reportEventToDestinationEnum`, imagine a `FenceEvent` object missing the `destination` property – the code explicitly throws a `TypeError`.

**6. Spotting Potential User/Programming Errors:**

Think about how a developer might misuse the API. Common errors include:

* Providing invalid input (e.g., missing required properties in `FenceEvent`).
* Exceeding limits (e.g., the maximum beacon length).
* Calling methods at the wrong time (e.g., on an inactive document).
* Not understanding the security restrictions and feature flags.

**7. Structuring the Answer:**

Organize the information logically. Start with a high-level summary of the file's purpose. Then, detail the functionality of each important method. Use clear headings and bullet points. Provide concrete examples for JavaScript, HTML, CSS relationships, logical inferences, and common errors.

**Self-Correction/Refinement During Analysis:**

* **Initial Misinterpretations:**  You might initially misunderstand the purpose of a function. As you read more of the surrounding code and comments, your understanding will refine. For example, initially, you might think `disableUntrustedNetwork` directly disables network access globally. Reading the surrounding code clarifies it's specific to the fenced frame.
* **Missing Connections:** You might miss a connection between a function and a web technology initially. Revisiting the function's purpose and the surrounding context can help you make these connections. For example, you might initially focus only on the C++ implementation and forget the JavaScript API that triggers these functions.

By following this systematic and iterative process, you can effectively analyze and explain the functionality of complex source code files like the one provided.
这个文件 `fence.cc` 是 Chromium Blink 渲染引擎中关于 `<fencedframe>` 元素的一个关键组成部分，它定义了与 fenced frame 相关的 `Fence` 类的功能。`Fence` 类主要负责提供 JavaScript API，允许 fenced frame 内的内容与外部环境进行受限的交互，特别是关于事件报告和配置管理。

以下是 `fence.cc` 的主要功能：

**1. 提供 JavaScript API `window.fence` 对象的功能：**

   - `Fence` 类实例关联到 fenced frame 的 `window` 对象上，通过 `window.fence` 属性暴露给 JavaScript 代码。
   - 这个 API 提供了一系列方法，允许 fenced frame 内的 JavaScript 代码执行特定的受限操作。

**2. 事件报告 (Reporting Events)：**

   - **`reportEvent(event)` 和 `reportEvent(eventType, eventData, destination)`:**  允许 fenced frame 向指定的报告目标（Buyer, Seller, Component Seller, Direct Seller）发送事件报告。
   - 可以通过 `FenceEvent` 对象或分别指定 `eventType` 和 `eventData` 参数来报告事件。
   - 支持跨域事件报告，但需要满足特定的条件，例如启用对应的 feature flag (`kFencedFramesCrossOriginEventReportingUnlabeledTraffic` 或 `kFencedFramesCrossOriginEventReportingAllTraffic`) 以及在调用 `reportEvent` 时设置 `crossOriginExposed` 为 true。
   - 实现了对报告数据大小的限制 (`kFencedFrameMaxBeaconLength`)，防止发送过大的报告。
   - 提供了向自定义 URL 报告事件的功能 (`reportEventToDestinationURL`)，允许将事件发送到指定的 HTTPS 端点。

   **与 JavaScript, HTML, CSS 的关系举例：**

   * **JavaScript:** fenced frame 内的 JavaScript 代码可以使用 `window.fence.reportEvent()` 方法发送事件。例如：
     ```javascript
     window.fence.reportEvent({
       eventType: 'impression',
       eventData: 'user clicked on ad',
       destination: ['buyer', 'seller']
     });
     ```
   * **HTML:** `<fencedframe>` 元素本身触发了 `Fence` 对象的创建和关联。
   * **CSS:**  CSS 本身不直接与事件报告功能交互，但 fenced frame 的隔离特性会影响报告事件时的上下文。

   **逻辑推理 (假设输入与输出):**

   * **假设输入:**  在 fenced frame 内的 JavaScript 代码调用 `window.fence.reportEvent({ eventType: 'click', destination: ['buyer'] })`。
   * **输出:**  Blink 引擎会通过 IPC 消息将一个包含 `eventType: 'click'` 和目标 `buyer` 的报告发送到浏览器进程，最终可能到达广告购买方。

**3. 设置自动信标报告数据 (Setting Report Event Data for Automatic Beacons):**

   - **`setReportEventDataForAutomaticBeacons(event)`:**  允许 fenced frame 为特定的自动信标事件类型（例如，导航开始或提交）设置报告数据和目标。
   - 自动信标是在特定生命周期事件发生时自动发送的报告。
   - 限制了只有注册了报告元数据的文档才能设置自动信标数据。

   **与 JavaScript, HTML, CSS 的关系举例：**

   * **JavaScript:**  使用 `window.fence.setReportEventDataForAutomaticBeacons()` 方法设置数据。例如：
     ```javascript
     window.fence.setReportEventDataForAutomaticBeacons({
       eventType: 'fencedframe-top-navigation-commit',
       eventData: 'navigation to product page',
       destination: ['seller'],
       once: true
     });
     ```

**4. 获取嵌套配置 (Getting Nested Configurations):**

   - **`getNestedConfigs()`:** 允许 fenced frame 获取其嵌套 fenced frame 的配置信息。
   - 这提供了对嵌套 fenced frame 的受限访问，主要用于获取其渲染所需的配置数据。

   **与 JavaScript, HTML, CSS 的关系举例：**

   * **JavaScript:**  使用 `window.fence.getNestedConfigs()` 方法获取配置。例如：
     ```javascript
     const nestedConfigs = window.fence.getNestedConfigs();
     console.log(nestedConfigs);
     ```
   * **HTML:**  与嵌套的 `<fencedframe>` 元素相关，允许父 fenced frame 获取子 fenced frame 的信息。

   **逻辑推理 (假设输入与输出):**

   * **假设输入:** 一个包含嵌套 `<fencedframe>` 的父 fenced frame 调用 `window.fence.getNestedConfigs()`。
   * **输出:**  一个包含子 fenced frame 配置信息的数组，例如子 fenced frame 的 URN 或其他相关属性。

**5. 禁用非信任网络 (Disabling Untrusted Network):**

   - **`disableUntrustedNetwork()`:**  允许 fenced frame 禁用其内部的非信任网络请求。
   - 这是一种安全机制，用于防止 fenced frame 内加载可能存在风险的资源。
   - 只有具有特定权限的 fenced frame 才能调用此方法。

   **与 JavaScript, HTML, CSS 的关系举例：**

   * **JavaScript:**  使用 `window.fence.disableUntrustedNetwork()` 方法禁用网络。例如：
     ```javascript
     window.fence.disableUntrustedNetwork().then(() => {
       console.log('Untrusted network disabled.');
     });
     ```

**6. 私有聚合事件报告 (Reporting Private Aggregation Events):**

   - **`reportPrivateAggregationEvent(event)`:** 允许 fenced frame 向私有聚合服务发送事件报告。
   - 这用于在保护用户隐私的前提下进行数据聚合和分析。
   - 此功能依赖于特定的 feature flags 和 FLEDGE 扩展。

   **与 JavaScript, HTML, CSS 的关系举例：**

   * **JavaScript:** 使用 `window.fence.reportPrivateAggregationEvent()` 方法发送报告。例如：
     ```javascript
     window.fence.reportPrivateAggregationEvent('auction_win');
     ```

**7. 通知事件 (Notifying Events):**

   - **`notifyEvent(triggeringEvent)`:** 允许顶级 fenced frame 将一个受信任的用户交互事件转发给嵌入器（例如，包含该 fenced frame 的页面）。
   - 这允许 fenced frame 与外部环境进行有限的交互，例如响应用户的点击事件。
   - 只能在顶级 fenced frame 中调用，且 `triggeringEvent` 必须是受信任的事件。

   **与 JavaScript, HTML, CSS 的关系举例：**

   * **JavaScript:** 使用 `window.fence.notifyEvent()` 方法通知事件。例如：
     ```javascript
     document.addEventListener('click', (event) => {
       window.fence.notifyEvent(event);
     });
     ```

   **逻辑推理 (假设输入与输出):**

   * **假设输入:** 在顶级 fenced frame 内，用户点击了一个元素，触发了一个 `click` 事件。JavaScript 代码调用 `window.fence.notifyEvent(event)`。
   * **输出:**  Blink 引擎会将 `click` 事件类型通过 IPC 消息转发给浏览器进程，浏览器进程可能会将该事件传递给包含该 fenced frame 的页面。

**用户或编程常见的使用错误举例：**

1. **在非 fenced frame 环境中使用 `window.fence`:**  `window.fence` 对象只在 fenced frame 环境下存在，如果在普通页面或 iframe 中尝试访问，会导致错误。
   ```javascript
   // 错误示例 (在普通页面中)
   window.fence.reportEvent({ eventType: 'test' }); // TypeError: Cannot read properties of undefined (reading 'reportEvent')
   ```

2. **`reportEvent` 缺少必要的参数:**  如果调用 `reportEvent` 时缺少 `destination` 或 `eventType`，会导致类型错误。
   ```javascript
   // 错误示例
   window.fence.reportEvent({ eventData: 'some data' }); // TypeError: Missing required 'destination' property.
   ```

3. **报告数据超过最大长度:**  尝试发送超过 `kFencedFrameMaxBeaconLength` 限制的数据会导致安全错误。
   ```javascript
   // 错误示例
   const longData = 'a'.repeat(65 * 1024); // 超过 64KB
   window.fence.reportEvent({ eventType: 'long', eventData: longData, destination: ['buyer'] }); // SecurityError: The data provided to reportEvent() exceeds the maximum length...
   ```

4. **在跨域 fenced frame 中报告事件但未设置 `crossOriginExposed` 或未启用 Feature Flag:** 在跨域情况下报告事件需要显式设置 `crossOriginExposed: true` 并且可能需要启用对应的 Feature Flag。
   ```javascript
   // 错误示例 (跨域 fenced frame，未设置 crossOriginExposed)
   window.fence.reportEvent({ eventType: 'cross-origin', destination: ['buyer'] }); // TypeError: 'crossOriginExposed' is not supported with reportEvent().
   ```

5. **在非顶级 fenced frame 中调用 `notifyEvent`:** `notifyEvent` 只能在顶级 fenced frame 中调用。
   ```javascript
   // 错误示例 (在嵌套的 fenced frame 中)
   document.addEventListener('click', (event) => {
     window.fence.notifyEvent(event); // SecurityError: notifyEvent is only available in fenced frame roots.
   });
   ```

总而言之，`fence.cc` 文件定义了 fenced frame 与外部世界进行受限且安全交互的关键 API，主要集中在事件报告、配置管理和安全控制方面。它通过 `window.fence` 对象暴露给 JavaScript，使得 fenced frame 能够执行一些特定的、受控的操作。

Prompt: 
```
这是目录为blink/renderer/core/html/fenced_frame/fence.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/html/fenced_frame/fence.h"

#include <optional>

#include "base/feature_list.h"
#include "base/ranges/algorithm.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/fenced_frame/fenced_frame_utils.h"
#include "third_party/blink/public/common/frame/frame_policy.h"
#include "third_party/blink/public/mojom/fenced_frame/fenced_frame.mojom-blink.h"
#include "third_party/blink/public/mojom/frame/frame.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_fence_event.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_fenceevent_string.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/frame/frame_owner.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {

namespace {

blink::FencedFrame::ReportingDestination ToPublicDestination(
    const V8FenceReportingDestination& destination) {
  switch (destination.AsEnum()) {
    case V8FenceReportingDestination::Enum::kBuyer:
      return blink::FencedFrame::ReportingDestination::kBuyer;
    case V8FenceReportingDestination::Enum::kSeller:
      return blink::FencedFrame::ReportingDestination::kSeller;
    case V8FenceReportingDestination::Enum::kComponentSeller:
      return blink::FencedFrame::ReportingDestination::kComponentSeller;
    case V8FenceReportingDestination::Enum::kDirectSeller:
      return blink::FencedFrame::ReportingDestination::kDirectSeller;
    case V8FenceReportingDestination::Enum::kSharedStorageSelectUrl:
      return blink::FencedFrame::ReportingDestination::kSharedStorageSelectUrl;
  }
}

std::optional<mojom::blink::AutomaticBeaconType> GetAutomaticBeaconType(
    const WTF::String& input) {
  if (input == blink::kDeprecatedFencedFrameTopNavigationBeaconType) {
    return mojom::blink::AutomaticBeaconType::kDeprecatedTopNavigation;
  }
  if (input == blink::kFencedFrameTopNavigationStartBeaconType) {
    return mojom::blink::AutomaticBeaconType::kTopNavigationStart;
  }
  if (input == blink::kFencedFrameTopNavigationCommitBeaconType) {
    return mojom::blink::AutomaticBeaconType::kTopNavigationCommit;
  }
  return std::nullopt;
}

}  // namespace

Fence::Fence(LocalDOMWindow& window) : ExecutionContextClient(&window) {}

void Fence::Trace(Visitor* visitor) const {
  ScriptWrappable::Trace(visitor);
  ExecutionContextClient::Trace(visitor);
}

void Fence::reportEvent(const V8UnionFenceEventOrString* event,
                        ExceptionState& exception_state) {
  switch (event->GetContentType()) {
    case V8UnionFenceEventOrString::ContentType::kString:
      reportPrivateAggregationEvent(event->GetAsString(), exception_state);
      return;
    case V8UnionFenceEventOrString::ContentType::kFenceEvent:
      reportEvent(event->GetAsFenceEvent(), exception_state);
      return;
  }
}

void Fence::reportEvent(const FenceEvent* event,
                        ExceptionState& exception_state) {
  if (!DomWindow()) {
    exception_state.ThrowSecurityError(
        "May not use a Fence object associated with a Document that is not "
        "fully active.");
    return;
  }

  if (event->getEventTypeOr("").StartsWith(
          blink::kFencedFrameReservedPAEventPrefix)) {
    AddConsoleMessage("Reserved events cannot be triggered manually.");
    return;
  }

  if (event->hasDestinationURL() &&
      base::FeatureList::IsEnabled(
          blink::features::kAdAuctionReportingWithMacroApi)) {
    reportEventToDestinationURL(event, exception_state);
  } else {
    reportEventToDestinationEnum(event, exception_state);
  }
}

void Fence::reportEventToDestinationEnum(const FenceEvent* event,
                                         ExceptionState& exception_state) {
  if (!event->hasDestination()) {
    exception_state.ThrowTypeError("Missing required 'destination' property.");
    return;
  }
  if (!event->hasEventType()) {
    exception_state.ThrowTypeError("Missing required 'eventType' property.");
    return;
  }
  if (event->crossOriginExposed() &&
      !base::FeatureList::IsEnabled(
          blink::features::
              kFencedFramesCrossOriginEventReportingUnlabeledTraffic) &&
      !base::FeatureList::IsEnabled(
          blink::features::kFencedFramesCrossOriginEventReportingAllTraffic)) {
    exception_state.ThrowTypeError(
        "'crossOriginExposed' is not supported with reportEvent().");
    return;
  }

  if (event->hasEventData() &&
      event->eventData().length() > blink::kFencedFrameMaxBeaconLength) {
    exception_state.ThrowSecurityError(
        "The data provided to reportEvent() exceeds the maximum length, which "
        "is 64KB.");
    return;
  }

  LocalFrame* frame = DomWindow()->GetFrame();
  DCHECK(frame->GetDocument());

  const auto& properties =
      frame->GetDocument()->Loader()->FencedFrameProperties();
  if (!properties.has_value() || !properties->has_fenced_frame_reporting()) {
    AddConsoleMessage("This frame did not register reporting metadata.");
    return;
  }

  if (properties->is_cross_origin_content()) {
    if (!properties->allow_cross_origin_event_reporting()) {
      AddConsoleMessage(
          "This document is cross-origin to the document that contains "
          "reporting metadata, but the fenced frame's document was not served "
          "with the 'Allow-Cross-Origin-Event-Reporting' header.");
      return;
    }
    if (!event->crossOriginExposed()) {
      AddConsoleMessage(
          "This document is cross-origin to the document that contains "
          "reporting metadata, but reportEvent() was not called with "
          "crossOriginExposed=true.");
      return;
    }
  }

  WTF::Vector<blink::FencedFrame::ReportingDestination> destinations;
  destinations.reserve(event->destination().size());
  base::ranges::transform(event->destination(),
                          std::back_inserter(destinations),
                          ToPublicDestination);

  frame->GetLocalFrameHostRemote().SendFencedFrameReportingBeacon(
      event->getEventDataOr(String{""}), event->eventType(), destinations,
      event->crossOriginExposed());
}

void Fence::reportEventToDestinationURL(const FenceEvent* event,
                                        ExceptionState& exception_state) {
  if (event->hasEventType()) {
    exception_state.ThrowTypeError(
        "When reporting to a custom destination URL, 'eventType' is not "
        "allowed.");
    return;
  }
  if (event->hasEventData()) {
    exception_state.ThrowTypeError(
        "When reporting to a custom destination URL, 'eventData' is not "
        "allowed.");
    return;
  }
  if (event->hasDestination()) {
    exception_state.ThrowTypeError(
        "When reporting to a custom destination URL, 'destination' is not "
        "allowed.");
    return;
  }
  if (event->crossOriginExposed() &&
      !base::FeatureList::IsEnabled(
          blink::features::
              kFencedFramesCrossOriginEventReportingUnlabeledTraffic) &&
      !base::FeatureList::IsEnabled(
          blink::features::kFencedFramesCrossOriginEventReportingAllTraffic)) {
    exception_state.ThrowTypeError(
        "'crossOriginExposed' is not supported with reportEvent().");
    return;
  }
  if (event->destinationURL().length() > blink::kFencedFrameMaxBeaconLength) {
    exception_state.ThrowSecurityError(
        "The destination URL provided to reportEvent() exceeds the maximum "
        "length, which is 64KB.");
    return;
  }

  KURL destinationURL(event->destinationURL());
  if (!destinationURL.IsValid()) {
    exception_state.ThrowTypeError(
        "The destination URL provided to reportEvent() is not a valid URL.");
    return;
  }
  if (!destinationURL.ProtocolIs(url::kHttpsScheme)) {
    exception_state.ThrowTypeError(
        "The destination URL provided to reportEvent() does not have the "
        "required scheme (https).");
    return;
  }

  LocalFrame* frame = DomWindow()->GetFrame();
  DCHECK(frame->GetDocument());

  const auto& properties =
      frame->GetDocument()->Loader()->FencedFrameProperties();
  if (!properties.has_value() || !properties->has_fenced_frame_reporting()) {
    AddConsoleMessage("This frame did not register reporting metadata.");
    return;
  }

  if (properties->is_cross_origin_content()) {
    if (!properties->allow_cross_origin_event_reporting()) {
      AddConsoleMessage(
          "This document is cross-origin to the document that contains "
          "reporting metadata, but the fenced frame's document was not served "
          "with the 'Allow-Cross-Origin-Event-Reporting' header.");
      return;
    }
    if (!event->crossOriginExposed()) {
      AddConsoleMessage(
          "This document is cross-origin to the document that contains "
          "reporting metadata, but reportEvent() was not called with "
          "crossOriginExposed=true.");
      return;
    }
  }

  frame->GetLocalFrameHostRemote().SendFencedFrameReportingBeaconToCustomURL(
      destinationURL, event->crossOriginExposed());
}

void Fence::setReportEventDataForAutomaticBeacons(
    const FenceEvent* event,
    ExceptionState& exception_state) {
  if (!DomWindow()) {
    exception_state.ThrowSecurityError(
        "May not use a Fence object associated with a Document that is not "
        "fully active.");
    return;
  }
  if (!event->hasDestination()) {
    exception_state.ThrowTypeError("Missing required 'destination' property.");
    return;
  }
  if (!event->hasEventType()) {
    exception_state.ThrowTypeError("Missing required 'eventType' property.");
    return;
  }
  std::optional<mojom::blink::AutomaticBeaconType> beacon_type =
      GetAutomaticBeaconType(event->eventType());
  if (!beacon_type.has_value()) {
    AddConsoleMessage(event->eventType() +
                      " is not a valid automatic beacon event type.");
    return;
  }
  if (event->hasEventData() &&
      event->eventData().length() > blink::kFencedFrameMaxBeaconLength) {
    exception_state.ThrowSecurityError(
        "The data provided to setReportEventDataForAutomaticBeacons() exceeds "
        "the maximum length, which is 64KB.");
    return;
  }
  if (event->eventType() ==
      blink::kDeprecatedFencedFrameTopNavigationBeaconType) {
    AddConsoleMessage(event->eventType() + " is deprecated in favor of " +
                          kFencedFrameTopNavigationCommitBeaconType + ".",
                      mojom::blink::ConsoleMessageLevel::kWarning);
  }
  LocalFrame* frame = DomWindow()->GetFrame();
  DCHECK(frame->GetDocument());

  const auto& properties =
      frame->GetDocument()->Loader()->FencedFrameProperties();
  if (!properties.has_value() || !properties->has_fenced_frame_reporting()) {
    AddConsoleMessage("This frame did not register reporting metadata.");
    return;
  }

  if (properties->is_cross_origin_content()) {
    AddConsoleMessage(
        "Automatic beacon data can only be set from documents that registered "
        "reporting metadata.");
    return;
  }

  WTF::Vector<blink::FencedFrame::ReportingDestination> destinations;
  destinations.reserve(event->destination().size());
  base::ranges::transform(event->destination(),
                          std::back_inserter(destinations),
                          ToPublicDestination);

  frame->GetLocalFrameHostRemote().SetFencedFrameAutomaticBeaconReportEventData(
      beacon_type.value(), event->getEventDataOr(String{""}), destinations,
      event->once(), event->crossOriginExposed());
}

HeapVector<Member<FencedFrameConfig>> Fence::getNestedConfigs(
    ExceptionState& exception_state) {
  HeapVector<Member<FencedFrameConfig>> out;
  const std::optional<FencedFrame::RedactedFencedFrameProperties>&
      fenced_frame_properties =
          DomWindow()->document()->Loader()->FencedFrameProperties();
  if (fenced_frame_properties.has_value() &&
      fenced_frame_properties.value().nested_urn_config_pairs() &&
      fenced_frame_properties.value()
          .nested_urn_config_pairs()
          ->potentially_opaque_value) {
    for (const std::pair<GURL, FencedFrame::RedactedFencedFrameConfig>&
             config_pair : fenced_frame_properties.value()
                               .nested_urn_config_pairs()
                               ->potentially_opaque_value.value()) {
      FencedFrame::RedactedFencedFrameConfig config = config_pair.second;
      out.push_back(FencedFrameConfig::From(config));
    }
  }
  return out;
}

ScriptPromise<IDLUndefined> Fence::disableUntrustedNetwork(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  if (!DomWindow()) {
    exception_state.ThrowSecurityError(
        "May not use a Fence object associated with a Document that is not "
        "fully active.");
    return EmptyPromise();
  }
  LocalFrame* frame = DomWindow()->GetFrame();
  DCHECK(frame->GetDocument());
  CHECK(frame->GetDocument()->Loader()->FencedFrameProperties().has_value());
  bool can_disable_untrusted_network = frame->GetDocument()
                                           ->Loader()
                                           ->FencedFrameProperties()
                                           ->can_disable_untrusted_network();
  if (!can_disable_untrusted_network) {
    exception_state.ThrowTypeError(
        "This frame is not allowed to disable untrusted network.");
    return EmptyPromise();
  }

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();
  frame->GetLocalFrameHostRemote().DisableUntrustedNetworkInFencedFrame(
      WTF::BindOnce(
          [](ScriptPromiseResolver<IDLUndefined>* resolver) {
            resolver->Resolve();
          },
          WrapPersistent(resolver)));
  return promise;
}

void Fence::reportPrivateAggregationEvent(const String& event,
                                          ExceptionState& exception_state) {
  if (!base::FeatureList::IsEnabled(blink::features::kPrivateAggregationApi) ||
      !blink::features::kPrivateAggregationApiEnabledInProtectedAudience
           .Get() ||
      !blink::features::kPrivateAggregationApiProtectedAudienceExtensionsEnabled
           .Get()) {
    exception_state.ThrowSecurityError(
        "FLEDGE extensions must be enabled to use reportEvent() for private "
        "aggregation events.");
    return;
  }
  if (!DomWindow()) {
    exception_state.ThrowSecurityError(
        "May not use a Fence object associated with a Document that is not "
        "fully active.");
    return;
  }

  if (event.StartsWith(blink::kFencedFrameReservedPAEventPrefix)) {
    AddConsoleMessage("Reserved events cannot be triggered manually.");
    return;
  }

  LocalFrame* frame = DomWindow()->GetFrame();
  DCHECK(frame->GetDocument());

  const auto& properties =
      frame->GetDocument()->Loader()->FencedFrameProperties();
  if (!properties.has_value() || !properties->has_fenced_frame_reporting()) {
    AddConsoleMessage("This frame did not register reporting metadata.");
    return;
  }

  frame->GetLocalFrameHostRemote()
      .SendPrivateAggregationRequestsForFencedFrameEvent(event);
}

void Fence::notifyEvent(const Event* triggering_event,
                        ExceptionState& exception_state) {
  if (!DomWindow()) {
    exception_state.ThrowSecurityError(
        "May not use a Fence object associated with a Document that is not "
        "fully active.");
    return;
  }

  LocalFrame* frame = DomWindow()->GetFrame();
  CHECK(frame);
  // notifyEvent is not allowed in iframes.
  if (!frame->IsFencedFrameRoot()) {
    exception_state.ThrowSecurityError(
        "notifyEvent is only available in fenced frame "
        "roots.");
    return;
  }

  if (!triggering_event || !triggering_event->isTrusted() ||
      !triggering_event->IsBeingDispatched()) {
    exception_state.ThrowSecurityError(
        "The triggering_event object is in an invalid "
        "state.");
    return;
  }

  if (!CanNotifyEventTypeAcrossFence(triggering_event->type().Ascii())) {
    exception_state.ThrowSecurityError(
        "notifyEvent called with an unsupported event type.");
    return;
  }

  frame->GetLocalFrameHostRemote()
      .ForwardFencedFrameEventAndUserActivationToEmbedder(
          triggering_event->type());

  // The browser process checks and consumes user activation as part of the
  // above IPC, so this just needs to update the renderer's state.
  LocalFrame::ConsumeTransientUserActivation(
      frame, UserActivationUpdateSource::kBrowser);
}

void Fence::AddConsoleMessage(const String& message,
                              mojom::blink::ConsoleMessageLevel level) {
  DCHECK(DomWindow());
  DomWindow()->AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
      mojom::blink::ConsoleMessageSource::kJavaScript, level, message));
}

}  // namespace blink

"""

```