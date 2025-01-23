Response:
The user wants to understand the functionality of the `xr_system.cc` file in the Chromium Blink engine. I need to go through the provided code snippet and identify its main responsibilities. I should also highlight any interactions with JavaScript, HTML, and CSS, provide examples of logical reasoning based on the code, point out potential user/programming errors, explain how a user interaction could lead to this code being executed, and finally, summarize the functionality of this specific part of the file.

**Plan:**

1. **Identify Key Classes and Data Structures:** Look for the main classes defined or used in the code, focusing on `XRSystem`, `PendingSupportsSessionQuery`, and `PendingRequestSessionQuery`.
2. **Analyze Function Signatures and Logic:**  Examine the methods within these classes and understand their purpose based on their names, parameters, and return types. Pay attention to interactions with other Blink components and external services.
3. **Trace Interactions with Web Technologies:** Look for mentions of JavaScript concepts (like Promises), HTML elements (like `domOverlay`), and CSS implications (though less direct in this file).
4. **Infer Logical Reasoning:**  Identify conditional logic or data transformations that suggest a decision-making process within the code.
5. **Identify Potential Errors:**  Look for error handling, assertions, or checks that indicate common misuse or potential problems.
6. **Construct a User Flow:**  Imagine the steps a user might take in a web browser that would trigger the execution of this code.
7. **Summarize the Functionality:**  Condense the findings into a concise overview of what the code does.
```
这是目录为blink/renderer/modules/xr/xr_system.cc的chromium blink引擎源代码文件， 请列举一下它的功能,
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能
```

**blink/renderer/modules/xr/xr_system.cc 的功能 (第 1 部分归纳):**

这份代码是 Chromium Blink 引擎中 `XRSystem` 类的实现，该类是 WebXR API 的核心入口点，负责处理与 XR (扩展现实，包括 VR 和 AR) 功能相关的各种操作。  主要功能集中在处理会话请求和支持查询上。

更具体地说，第 1 部分主要负责以下功能：

1. **提供 `navigator.xr` 对象:** `XRSystem` 类作为 `Navigator` 对象的 supplement，通过 `navigator.xr` 属性暴露给 JavaScript。这是 Web 开发者访问 WebXR API 的起点。
2. **处理 `supportsSession()` 查询:**  实现了 `supportsSession()` 方法的逻辑，允许网页查询浏览器是否支持特定的 XR 会话模式 (例如 `inline`, `immersive-vr`, `immersive-ar`)。这涉及到创建 `PendingSupportsSessionQuery` 对象来异步处理查询。
3. **处理 `requestSession()` 请求:** 实现了 `requestSession()` 方法的逻辑，允许网页请求创建一个 XR 会话。这涉及到：
    *   验证会话请求的合法性，例如是否需要用户激活、是否在可见页面中。
    *   检查 Permissions Policy 是否允许访问 "xr" 功能。
    *   创建 `PendingRequestSessionQuery` 对象来管理会话请求。
    *   解析会话请求中的 requiredFeatures 和 optionalFeatures，并进行验证。
    *   与浏览器进程中的 XR 服务进行通信，以创建实际的 XR 会话。
4. **管理待处理的查询:** 使用 `PendingSupportsSessionQuery` 和 `PendingRequestSessionQuery` 类来异步处理 `supportsSession()` 和 `requestSession()` 的请求。
5. **定义和处理 XR 会话的特性 (Features):**  定义了各种 XR 会话特性（例如 `viewer`, `local`, `local-floor`, `dom-overlay`, `hit-test` 等），并提供了检查这些特性是否有效、是否需要特定权限策略的函数。
6. **数据转换和验证:**  提供了在 JavaScript API 中使用的枚举类型 (例如 `XRSessionMode`, `XRDepthUsage`, `XRDepthDataFormat`) 和内部 Mojo 接口之间进行转换的函数。
7. **指标上报 (Metrics Reporting):**  在会话请求成功或失败时，会收集和上报相关的指标数据 (通过 UKM)。

**与 JavaScript, HTML, CSS 的关系:**

*   **JavaScript:**
    *   `navigator.xr`:  `XRSystem` 实例通过 `navigator.xr` 属性暴露给 JavaScript，使得 JavaScript 代码可以调用 `supportsSession()` 和 `requestSession()` 等方法来使用 WebXR API。
    *   **示例:** JavaScript 代码可以使用 `navigator.xr.requestSession('immersive-vr')` 来请求一个沉浸式 VR 会话。
    *   Promise:  `supportsSession()` 和 `requestSession()` 方法返回 Promise 对象，用于处理异步操作的结果。`PendingSupportsSessionQuery` 和 `PendingRequestSessionQuery` 负责解析或拒绝这些 Promise。
    *   枚举类型: 代码中使用了 `V8XRSessionMode::Enum` 等枚举类型，这些类型对应于 JavaScript 中定义的枚举值，例如 `XRSessionMode` 的 `'inline'`, `'immersive-vr'`, `'immersive-ar'`。
*   **HTML:**
    *   **DOM Overlay (`dom-overlay` feature):**  如果请求的会话包含 `dom-overlay` 特性，代码会检查 `XRSessionInit` 中是否指定了有效的 `domOverlay.root` 元素，该元素必须是 HTML 中的一个元素。
    *   **示例:**  JavaScript 可以请求一个带有 DOM Overlay 的 AR 会话，并将 HTML 中的一个 `<div>` 元素指定为 overlay 的根元素。
*   **CSS:**
    *   虽然这份代码本身不直接操作 CSS，但 DOM Overlay 功能最终会影响页面的 CSS 布局和渲染，因为指定的 HTML 元素会被渲染到 XR 场景中。

**逻辑推理 (假设输入与输出):**

**假设输入:**

*   **用户操作:** 用户在支持 WebXR 的浏览器中访问了一个网页。
*   **JavaScript 代码:**  网页的 JavaScript 代码执行了以下操作：
    ```javascript
    navigator.xr.supportsSession('immersive-vr').then(supported => {
      if (supported) {
        console.log('支持 immersive-vr 会话');
      } else {
        console.log('不支持 immersive-vr 会话');
      }
    });
    ```

**逻辑推理:**

1. `navigator.xr.supportsSession('immersive-vr')` 被调用。
2. `XRSystem::supportsSession()` 方法被执行。
3. 创建一个 `PendingSupportsSessionQuery` 对象，用于处理 `'immersive-vr'` 模式的支持查询。
4. Blink 引擎会与底层的 XR 服务进行通信，查询是否支持 `'immersive-vr'` 会话模式。
5. XR 服务返回结果 (假设支持)。
6. `PendingSupportsSessionQuery::Resolve(true, ...)` 被调用。
7. `supportsSession()` 返回的 Promise 被 resolve，并将 `true` 传递给 `then()` 方法的回调函数。

**输出:**

*   控制台输出: "支持 immersive-vr 会话"

**用户或编程常见的使用错误:**

*   **在非用户激活的情况下请求沉浸式会话:**
    *   **错误示例:**  在页面加载时立即调用 `navigator.xr.requestSession('immersive-vr')`。
    *   **代码中的体现:**  `CheckImmersiveSessionRequestAllowed()` 函数会检查 `LocalFrame::HasTransientUserActivation()`，如果返回 `false`，则会返回 `kRequestRequiresUserActivation` 错误信息。
    *   **用户看到的错误:**  控制台会输出类似 "The requested session requires user activation." 的错误信息，并且会话请求会被拒绝。
*   **请求 Feature Policy 禁止的特性:**
    *   **错误示例:**  页面没有通过 Feature Policy 授权访问 WebXR，但仍然尝试请求 XR 会话。
    *   **代码中的体现:** `HasRequiredPermissionsPolicy()` 函数会检查 Permissions Policy 是否允许特定的 XR 特性，如果被禁止，则会拒绝会话请求。
    *   **用户看到的错误:** 控制台会输出类似 "Access to the feature \"xr\" is disallowed by permissions policy." 的错误信息，并且会话请求会被拒绝。
*   **在已经存在沉浸式会话时请求新的沉浸式会话:**
    *   **错误示例:**  在已经存在一个 `immersive-vr` 会话的情况下，再次调用 `navigator.xr.requestSession('immersive-ar')`。
    *   **代码中的体现:**  代码会检查是否存在活动的沉浸式会话，如果存在，则会返回 `kActiveImmersiveSession` 错误信息。
    *   **用户看到的错误:** 控制台会输出类似 "There is already an active, immersive XRSession." 的错误信息，并且新的会话请求会被拒绝。
*   **为 `dom-overlay` 特性提供无效的根元素:**
    *   **错误示例:** 请求包含 `dom-overlay` 特性的会话，但 `XRSessionInit` 中 `domOverlay.root` 指定的元素不存在或无效。
    *   **代码中的体现:** `IsFeatureValidForMode()` 函数会检查 `session_init->hasDomOverlay()` 以及根元素是否有效，如果无效会添加控制台错误消息。
    *   **用户看到的错误:** 控制台会输出类似 "Must specify a valid domOverlay.root element in XRSessionInit" 的错误信息，并且会话请求可能会被拒绝。

**用户操作到达此处的步骤 (调试线索):**

1. **用户打开一个网页:** 用户在浏览器中输入网址或点击链接，打开了一个包含 WebXR 代码的网页。
2. **网页加载并执行 JavaScript:** 浏览器加载网页的 HTML、CSS 和 JavaScript 代码。
3. **JavaScript 代码调用 `navigator.xr` 的方法:**  网页的 JavaScript 代码调用了 `navigator.xr.supportsSession()` 或 `navigator.xr.requestSession()` 方法。
4. **Blink 引擎执行 `XRSystem` 中的相应方法:**  浏览器引擎接收到 JavaScript 的调用，并路由到 `blink/renderer/modules/xr/xr_system.cc` 文件中 `XRSystem` 类的相应方法 (`supportsSession()` 或 `requestSession()`)。
5. **根据用户操作和代码逻辑进行处理:**  `XRSystem` 中的代码会根据调用的方法、传入的参数、浏览器的状态和权限等进行相应的处理，例如查询设备支持情况、验证参数、请求权限等。

**总结 (第 1 部分功能):**

`blink/renderer/modules/xr/xr_system.cc` 的第 1 部分主要负责实现 WebXR API 的入口点，处理查询浏览器对特定 XR 会话模式的支持情况以及处理创建 XR 会话的请求。它涉及到对用户操作的验证、权限策略的检查、与底层 XR 服务的通信以及对异步操作的管理。 这部分代码是 Web 开发者使用 WebXR 功能的关键桥梁。

### 提示词
```
这是目录为blink/renderer/modules/xr/xr_system.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/xr/xr_system.h"

#include <memory>
#include <utility>

#include "base/containers/contains.h"
#include "base/ranges/algorithm.h"
#include "base/trace_event/trace_id_helper.h"
#include "base/trace_event/typed_macros.h"
#include "build/build_config.h"
#include "device/vr/public/mojom/vr_service.mojom-blink.h"
#include "services/metrics/public/cpp/ukm_builders.h"
#include "third_party/blink/public/mojom/permissions_policy/permissions_policy.mojom-blink.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_xr_depth_state_init.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_xr_reference_space_type.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_xr_session_mode.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_xr_tracked_image_init.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/navigator.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/viewport_data.h"
#include "third_party/blink/renderer/core/fullscreen/fullscreen.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/imagebitmap/image_bitmap.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/modules/event_modules.h"
#include "third_party/blink/renderer/modules/event_target_modules.h"
#include "third_party/blink/renderer/modules/xr/xr_enter_fullscreen_observer.h"
#include "third_party/blink/renderer/modules/xr/xr_exit_fullscreen_observer.h"
#include "third_party/blink/renderer/modules/xr/xr_frame_provider.h"
#include "third_party/blink/renderer/modules/xr/xr_session.h"
#include "third_party/blink/renderer/modules/xr/xr_session_viewport_scaler.h"
#include "third_party/blink/renderer/modules/xr/xr_utils.h"
#include "third_party/blink/renderer/platform/bindings/v8_throw_exception.h"
#include "third_party/blink/renderer/platform/graphics/static_bitmap_image.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/text/string_view.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

namespace {

constexpr uint64_t kInvalidTraceId = -1;

const char kNavigatorDetachedError[] =
    "The navigator.xr object is no longer associated with a document.";

const char kPageNotVisible[] = "The page is not visible";

const char kFeaturePolicyBlocked[] =
    "Access to the feature \"xr\" is disallowed by permissions policy.";

const char kActiveImmersiveSession[] =
    "There is already an active, immersive XRSession.";

const char kRequestRequiresUserActivation[] =
    "The requested session requires user activation.";

const char kSessionNotSupported[] =
    "The specified session configuration is not supported.";

const char kInvalidRequiredFeatures[] =
    "The session request contains invalid requiredFeatures and could not be "
    "fullfilled.";

const char kNoDevicesMessage[] = "No XR hardware found.";

const char kImmersiveArModeNotValid[] =
    "Failed to execute '%s' on 'XRSystem': The provided value 'immersive-ar' "
    "is not a valid enum value of type XRSessionMode.";

const char kTrackedImageWidthInvalid[] =
    "trackedImages[%d].widthInMeters invalid, must be a positive number.";

constexpr device::mojom::XRSessionFeature kDefaultImmersiveVrFeatures[] = {
    device::mojom::XRSessionFeature::REF_SPACE_VIEWER,
    device::mojom::XRSessionFeature::REF_SPACE_LOCAL,
};

constexpr device::mojom::XRSessionFeature kDefaultImmersiveArFeatures[] = {
    device::mojom::XRSessionFeature::REF_SPACE_VIEWER,
    device::mojom::XRSessionFeature::REF_SPACE_LOCAL,
};

constexpr device::mojom::XRSessionFeature kDefaultInlineFeatures[] = {
    device::mojom::XRSessionFeature::REF_SPACE_VIEWER,
};

device::mojom::blink::XRSessionMode V8EnumToSessionMode(
    V8XRSessionMode::Enum mode) {
  switch (mode) {
    case V8XRSessionMode::Enum::kInline:
      return device::mojom::blink::XRSessionMode::kInline;
    case V8XRSessionMode::Enum::kImmersiveVr:
      return device::mojom::blink::XRSessionMode::kImmersiveVr;
    case V8XRSessionMode::Enum::kImmersiveAr:
      return device::mojom::blink::XRSessionMode::kImmersiveAr;
  }
}

const char* SessionModeToString(device::mojom::blink::XRSessionMode mode) {
  switch (mode) {
    case device::mojom::blink::XRSessionMode::kInline:
      return "inline";
    case device::mojom::blink::XRSessionMode::kImmersiveVr:
      return "immersive-vr";
    case device::mojom::blink::XRSessionMode::kImmersiveAr:
      return "immersive-ar";
  }
}

device::mojom::XRDepthUsage ParseDepthUsage(const V8XRDepthUsage& usage) {
  switch (usage.AsEnum()) {
    case V8XRDepthUsage::Enum::kCpuOptimized:
      return device::mojom::XRDepthUsage::kCPUOptimized;
    case V8XRDepthUsage::Enum::kGpuOptimized:
      return device::mojom::XRDepthUsage::kGPUOptimized;
  }
}

Vector<device::mojom::XRDepthUsage> ParseDepthUsages(
    const Vector<V8XRDepthUsage>& usages) {
  Vector<device::mojom::XRDepthUsage> result;

  base::ranges::transform(usages, std::back_inserter(result), ParseDepthUsage);

  return result;
}

device::mojom::XRDepthDataFormat ParseDepthFormat(
    const V8XRDepthDataFormat& format) {
  switch (format.AsEnum()) {
    case V8XRDepthDataFormat::Enum::kLuminanceAlpha:
      return device::mojom::XRDepthDataFormat::kLuminanceAlpha;
    case V8XRDepthDataFormat::Enum::kFloat32:
      return device::mojom::XRDepthDataFormat::kFloat32;
    case V8XRDepthDataFormat::Enum::kUnsignedShort:
      return device::mojom::XRDepthDataFormat::kUnsignedShort;
  }
}

Vector<device::mojom::XRDepthDataFormat> ParseDepthFormats(
    const Vector<V8XRDepthDataFormat>& formats) {
  Vector<device::mojom::XRDepthDataFormat> result;

  base::ranges::transform(formats, std::back_inserter(result),
                          ParseDepthFormat);

  return result;
}

bool IsFeatureValidForMode(device::mojom::XRSessionFeature feature,
                           device::mojom::blink::XRSessionMode mode,
                           XRSessionInit* session_init,
                           ExecutionContext* execution_context,
                           mojom::blink::ConsoleMessageLevel error_level) {
  switch (feature) {
    case device::mojom::XRSessionFeature::REF_SPACE_VIEWER:
    case device::mojom::XRSessionFeature::REF_SPACE_LOCAL:
    case device::mojom::XRSessionFeature::REF_SPACE_LOCAL_FLOOR:
      return true;
    case device::mojom::XRSessionFeature::REF_SPACE_BOUNDED_FLOOR:
    case device::mojom::XRSessionFeature::REF_SPACE_UNBOUNDED:
    case device::mojom::XRSessionFeature::HIT_TEST:
    case device::mojom::XRSessionFeature::ANCHORS:
    case device::mojom::XRSessionFeature::HAND_INPUT:
    case device::mojom::XRSessionFeature::SECONDARY_VIEWS:
    case device::mojom::XRSessionFeature::LAYERS:
    case device::mojom::XRSessionFeature::WEBGPU:
      return mode == device::mojom::blink::XRSessionMode::kImmersiveVr ||
             mode == device::mojom::blink::XRSessionMode::kImmersiveAr;
    case device::mojom::XRSessionFeature::DOM_OVERLAY:
      if (mode != device::mojom::blink::XRSessionMode::kImmersiveAr)
        return false;
      if (!session_init->hasDomOverlay()) {
        execution_context->AddConsoleMessage(MakeGarbageCollected<
                                             ConsoleMessage>(
            mojom::blink::ConsoleMessageSource::kJavaScript, error_level,
            "Must specify a valid domOverlay.root element in XRSessionInit"));
        return false;
      }
      return true;
    case device::mojom::XRSessionFeature::IMAGE_TRACKING:
      if (mode != device::mojom::blink::XRSessionMode::kImmersiveAr)
        return false;
      if (!session_init->hasTrackedImages()) {
        execution_context->AddConsoleMessage(
            MakeGarbageCollected<ConsoleMessage>(
                mojom::blink::ConsoleMessageSource::kJavaScript, error_level,
                "Must specify trackedImages in XRSessionInit"));
        return false;
      }
      return true;
    case device::mojom::XRSessionFeature::LIGHT_ESTIMATION:
    case device::mojom::XRSessionFeature::CAMERA_ACCESS:
    case device::mojom::XRSessionFeature::PLANE_DETECTION:
    case device::mojom::XRSessionFeature::FRONT_FACING:
      return mode == device::mojom::blink::XRSessionMode::kImmersiveAr;
    case device::mojom::XRSessionFeature::DEPTH:
      if (!session_init->hasDepthSensing()) {
        execution_context->AddConsoleMessage(
            MakeGarbageCollected<ConsoleMessage>(
                mojom::blink::ConsoleMessageSource::kJavaScript, error_level,
                "Must provide a depthSensing dictionary in XRSessionInit"));
        return false;
      }
      return mode == device::mojom::blink::XRSessionMode::kImmersiveAr;
  }
}

bool HasRequiredPermissionsPolicy(ExecutionContext* context,
                                  device::mojom::XRSessionFeature feature) {
  if (!context)
    return false;

  switch (feature) {
    case device::mojom::XRSessionFeature::REF_SPACE_VIEWER:
      return true;
    case device::mojom::XRSessionFeature::REF_SPACE_LOCAL:
    case device::mojom::XRSessionFeature::REF_SPACE_LOCAL_FLOOR:
    case device::mojom::XRSessionFeature::REF_SPACE_BOUNDED_FLOOR:
    case device::mojom::XRSessionFeature::REF_SPACE_UNBOUNDED:
    case device::mojom::XRSessionFeature::DOM_OVERLAY:
    case device::mojom::XRSessionFeature::HIT_TEST:
    case device::mojom::XRSessionFeature::LIGHT_ESTIMATION:
    case device::mojom::XRSessionFeature::ANCHORS:
    case device::mojom::XRSessionFeature::PLANE_DETECTION:
    case device::mojom::XRSessionFeature::DEPTH:
    case device::mojom::XRSessionFeature::IMAGE_TRACKING:
    case device::mojom::XRSessionFeature::HAND_INPUT:
    case device::mojom::XRSessionFeature::SECONDARY_VIEWS:
    case device::mojom::XRSessionFeature::LAYERS:
    case device::mojom::XRSessionFeature::FRONT_FACING:
    case device::mojom::XRSessionFeature::WEBGPU:
      return context->IsFeatureEnabled(
          mojom::blink::PermissionsPolicyFeature::kWebXr,
          ReportOptions::kReportOnFailure);
    case device::mojom::XRSessionFeature::CAMERA_ACCESS:
      return context->IsFeatureEnabled(
                 mojom::blink::PermissionsPolicyFeature::kWebXr,
                 ReportOptions::kReportOnFailure) &&
             context->IsFeatureEnabled(
                 mojom::blink::PermissionsPolicyFeature::kCamera,
                 ReportOptions::kReportOnFailure);
  }
}

// Ensure that the immersive session request is allowed, if not
// return which security error occurred.
// https://immersive-web.github.io/webxr/#immersive-session-request-is-allowed
const char* CheckImmersiveSessionRequestAllowed(LocalDOMWindow* window) {
  // Ensure that the session was initiated by a user gesture
  if (!LocalFrame::HasTransientUserActivation(window->GetFrame())) {
    return kRequestRequiresUserActivation;
  }

  // Check that the document is "trustworthy"
  // https://immersive-web.github.io/webxr/#trustworthy
  if (!window->document()->IsPageVisible()) {
    return kPageNotVisible;
  }

  // Consent occurs in the Browser process.

  return nullptr;
}

// Helper method to convert the mojom error code into text for displaying in the
// console. The console message will have the format of:
// "Could not create a session because: <this value>"
const char* GetConsoleMessage(device::mojom::RequestSessionError error) {
  switch (error) {
    case device::mojom::RequestSessionError::EXISTING_IMMERSIVE_SESSION:
      return "There is already an existing immersive session";
    case device::mojom::RequestSessionError::INVALID_CLIENT:
      return "An error occurred while querying for runtime support";
    case device::mojom::RequestSessionError::USER_DENIED_CONSENT:
      return "The user denied some part of the requested configuration";
    case device::mojom::RequestSessionError::NO_RUNTIME_FOUND:
      return "No runtimes supported the requested configuration";
    case device::mojom::RequestSessionError::UNKNOWN_RUNTIME_ERROR:
      return "Something went wrong initializing the session in the runtime";
    case device::mojom::RequestSessionError::RUNTIME_INSTALL_FAILURE:
      return "The runtime for this configuration could not be installed";
    case device::mojom::RequestSessionError::RUNTIMES_CHANGED:
      return "The supported runtimes changed while initializing the session";
    case device::mojom::RequestSessionError::FULLSCREEN_ERROR:
      return "An error occurred while initializing fullscreen support";
    case device::mojom::RequestSessionError::UNKNOWN_FAILURE:
      return "An unknown error occurred";
  }
}

bool IsFeatureRequested(
    device::mojom::XRSessionFeatureRequestStatus requestStatus) {
  switch (requestStatus) {
    case device::mojom::XRSessionFeatureRequestStatus::kOptionalAccepted:
    case device::mojom::XRSessionFeatureRequestStatus::kRequired:
      return true;
    case device::mojom::XRSessionFeatureRequestStatus::kNotRequested:
    case device::mojom::XRSessionFeatureRequestStatus::kOptionalRejected:
      return false;
  }
}

bool IsImmersiveArAllowedBySettings(LocalDOMWindow* window) {
  // If we're unable to get the settings for any reason, we'll treat the AR as
  // enabled.
  if (!window->GetFrame()) {
    return true;
  }

  return window->GetFrame()->GetSettings()->GetWebXRImmersiveArAllowed();
}

}  // namespace

// Ensure that the inline session request is allowed, if not
// return which security error occurred.
// https://immersive-web.github.io/webxr/#inline-session-request-is-allowed
const char* XRSystem::CheckInlineSessionRequestAllowed(
    LocalFrame* frame,
    const PendingRequestSessionQuery& query) {
  // Without user activation, we must reject the session if *any* features
  // (optional or required) were present, whether or not they were recognized.
  // The only exception to this is the 'viewer' feature.
  if (!LocalFrame::HasTransientUserActivation(frame)) {
    if (query.InvalidOptionalFeatures() || query.InvalidRequiredFeatures()) {
      return kRequestRequiresUserActivation;
    }

    // If any required features (besides 'viewer') were requested, reject.
    for (auto feature : query.RequiredFeatures()) {
      if (feature != device::mojom::XRSessionFeature::REF_SPACE_VIEWER) {
        return kRequestRequiresUserActivation;
      }
    }

    // If any optional features (besides 'viewer') were requested, reject.
    for (auto feature : query.OptionalFeatures()) {
      if (feature != device::mojom::XRSessionFeature::REF_SPACE_VIEWER) {
        return kRequestRequiresUserActivation;
      }
    }
  }

  return nullptr;
}

XRSystem::PendingSupportsSessionQuery::PendingSupportsSessionQuery(
    ScriptPromiseResolverBase* resolver,
    device::mojom::blink::XRSessionMode session_mode,
    bool throw_on_unsupported)
    : resolver_(resolver),
      mode_(session_mode),
      trace_id_(base::trace_event::GetNextGlobalTraceId()),
      throw_on_unsupported_(throw_on_unsupported) {
  TRACE_EVENT("xr", "PendingSupportsSessionQuery::PendingSupportsSessionQuery",
              "session_mode", session_mode, perfetto::Flow::Global(trace_id_));
}

void XRSystem::PendingSupportsSessionQuery::Trace(Visitor* visitor) const {
  visitor->Trace(resolver_);
}

void XRSystem::PendingSupportsSessionQuery::Resolve(
    bool supported,
    ExceptionState* exception_state) {
  TRACE_EVENT("xr", "PendingSupportsSessionQuery::Resolve", "supported",
              supported, perfetto::TerminatingFlow::Global(trace_id_));

  if (throw_on_unsupported_) {
    if (supported) {
      resolver_->DowncastTo<IDLUndefined>()->Resolve();
    } else {
      DVLOG(2) << __func__ << ": session is unsupported - throwing exception";
      RejectWithDOMException(DOMExceptionCode::kNotSupportedError,
                             kSessionNotSupported, exception_state);
    }
  } else {
    static_cast<ScriptPromiseResolver<IDLBoolean>*>(resolver_.Get())
        ->Resolve(supported);
  }
}

void XRSystem::PendingSupportsSessionQuery::RejectWithDOMException(
    DOMExceptionCode exception_code,
    const String& message,
    ExceptionState* exception_state) {
  DCHECK_NE(exception_code, DOMExceptionCode::kSecurityError);

  TRACE_EVENT("xr", "PendingSupportsSessionQuery::RejectWithDOMException",
              "exception_code", exception_code, "message", message,
              perfetto::TerminatingFlow::Global(trace_id_));

  if (exception_state) {
    // The generated bindings will reject the returned promise for us.
    // Detaching the resolver prevents it from thinking we abandoned
    // the promise.
    exception_state->ThrowDOMException(exception_code, message);
    resolver_->Detach();
  } else {
    resolver_->Reject(
        MakeGarbageCollected<DOMException>(exception_code, message));
  }
}

void XRSystem::PendingSupportsSessionQuery::RejectWithSecurityError(
    const String& message,
    ExceptionState* exception_state) {
  TRACE_EVENT("xr", "PendingSupportsSessionQuery::RejectWithSecurityError",
              "message", message, perfetto::TerminatingFlow::Global(trace_id_));

  if (exception_state) {
    // The generated V8 bindings will reject the returned promise for us.
    // Detaching the resolver prevents it from thinking we abandoned
    // the promise.
    exception_state->ThrowSecurityError(message);
    resolver_->Detach();
  } else {
    resolver_->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kSecurityError, message));
  }
}

void XRSystem::PendingSupportsSessionQuery::RejectWithTypeError(
    const String& message,
    ExceptionState* exception_state) {
  TRACE_EVENT("xr", "PendingSupportsSessionQuery::RejectWithTypeError",
              "message", message, perfetto::TerminatingFlow::Global(trace_id_));

  if (exception_state) {
    // The generated bindings will reject the returned promise for us.
    // Detaching the resolver prevents it from thinking we abandoned
    // the promise.
    exception_state->ThrowTypeError(message);
    resolver_->Detach();
  } else {
    resolver_->Reject(V8ThrowException::CreateTypeError(
        resolver_->GetScriptState()->GetIsolate(), message));
  }
}

device::mojom::blink::XRSessionMode
XRSystem::PendingSupportsSessionQuery::mode() const {
  return mode_;
}

XRSystem::PendingRequestSessionQuery::PendingRequestSessionQuery(
    int64_t ukm_source_id,
    ScriptPromiseResolver<XRSession>* resolver,
    device::mojom::blink::XRSessionMode session_mode,
    RequestedXRSessionFeatureSet required_features,
    RequestedXRSessionFeatureSet optional_features)
    : resolver_(resolver),
      mode_(session_mode),
      required_features_(std::move(required_features)),
      optional_features_(std::move(optional_features)),
      ukm_source_id_(ukm_source_id),
      trace_id_(base::trace_event::GetNextGlobalTraceId()) {
  TRACE_EVENT("xr", "PendingRequestSessionQuery::PendingRequestSessionQuery",
              "Session mode", session_mode, perfetto::Flow::Global(trace_id_));

  ParseSensorRequirement();
}

void XRSystem::PendingRequestSessionQuery::Resolve(
    XRSession* session,
    mojo::PendingRemote<device::mojom::blink::XRSessionMetricsRecorder>
        metrics_recorder) {
  TRACE_EVENT("xr", "PendingRequestSessionQuery::Resolve",
              perfetto::TerminatingFlow::Global(trace_id_));

  resolver_->Resolve(session);
  ReportRequestSessionResult(SessionRequestStatus::kSuccess, session,
                             std::move(metrics_recorder));
}

void XRSystem::PendingRequestSessionQuery::RejectWithDOMException(
    DOMExceptionCode exception_code,
    const String& message,
    ExceptionState* exception_state) {
  DCHECK_NE(exception_code, DOMExceptionCode::kSecurityError);

  TRACE_EVENT("xr", "PendingRequestSessionQuery::RejectWithDOMException",
              "exception_code", exception_code, "message", message,
              perfetto::TerminatingFlow::Global(trace_id_));

  if (exception_state) {
    exception_state->ThrowDOMException(exception_code, message);
    resolver_->Detach();
  } else {
    resolver_->Reject(
        MakeGarbageCollected<DOMException>(exception_code, message));
  }

  ReportRequestSessionResult(SessionRequestStatus::kOtherError);
}

void XRSystem::PendingRequestSessionQuery::RejectWithSecurityError(
    const String& message,
    ExceptionState* exception_state) {
  TRACE_EVENT("xr", "PendingRequestSessionQuery::RejectWithSecurityError",
              "message", message, perfetto::TerminatingFlow::Global(trace_id_));

  if (exception_state) {
    exception_state->ThrowSecurityError(message);
    resolver_->Detach();
  } else {
    resolver_->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kSecurityError, message));
  }

  ReportRequestSessionResult(SessionRequestStatus::kOtherError);
}

void XRSystem::PendingRequestSessionQuery::RejectWithTypeError(
    const String& message,
    ExceptionState* exception_state) {
  TRACE_EVENT("xr", "PendingRequestSessionQuery::RejectWithTypeError",
              "message", message, perfetto::TerminatingFlow::Global(trace_id_));

  if (exception_state) {
    exception_state->ThrowTypeError(message);
    resolver_->Detach();
  } else {
    resolver_->Reject(V8ThrowException::CreateTypeError(
        GetScriptState()->GetIsolate(), message));
  }

  ReportRequestSessionResult(SessionRequestStatus::kOtherError);
}

device::mojom::XRSessionFeatureRequestStatus
XRSystem::PendingRequestSessionQuery::GetFeatureRequestStatus(
    device::mojom::XRSessionFeature feature,
    const XRSession* session) const {
  using device::mojom::XRSessionFeatureRequestStatus;

  if (RequiredFeatures().Contains(feature)) {
    // In the case of required features, accepted/rejected state is
    // the same as the entire session.
    return XRSessionFeatureRequestStatus::kRequired;
  }

  if (OptionalFeatures().Contains(feature)) {
    if (!session || !session->IsFeatureEnabled(feature)) {
      return XRSessionFeatureRequestStatus::kOptionalRejected;
    }

    return XRSessionFeatureRequestStatus::kOptionalAccepted;
  }

  return XRSessionFeatureRequestStatus::kNotRequested;
}

void XRSystem::PendingRequestSessionQuery::ReportRequestSessionResult(
    SessionRequestStatus status,
    XRSession* session,
    mojo::PendingRemote<device::mojom::blink::XRSessionMetricsRecorder>
        metrics_recorder) {
  using device::mojom::XRSessionFeature;
  auto* execution_context = resolver_->GetExecutionContext();
  if (!execution_context) {
    return;
  }

  auto feature_request_viewer =
      GetFeatureRequestStatus(XRSessionFeature::REF_SPACE_VIEWER, session);
  auto feature_request_local =
      GetFeatureRequestStatus(XRSessionFeature::REF_SPACE_LOCAL, session);
  auto feature_request_local_floor =
      GetFeatureRequestStatus(XRSessionFeature::REF_SPACE_LOCAL_FLOOR, session);
  auto feature_request_bounded_floor = GetFeatureRequestStatus(
      XRSessionFeature::REF_SPACE_BOUNDED_FLOOR, session);
  auto feature_request_unbounded =
      GetFeatureRequestStatus(XRSessionFeature::REF_SPACE_UNBOUNDED, session);
  auto feature_request_dom_overlay =
      GetFeatureRequestStatus(XRSessionFeature::DOM_OVERLAY, session);
  auto feature_request_depth_sensing =
      GetFeatureRequestStatus(XRSessionFeature::DEPTH, session);
  auto feature_request_plane_detection =
      GetFeatureRequestStatus(XRSessionFeature::PLANE_DETECTION, session);
  auto feature_request_image_tracking =
      GetFeatureRequestStatus(XRSessionFeature::IMAGE_TRACKING, session);

  ukm::builders::XR_WebXR_SessionRequest(ukm_source_id_)
      .SetMode(static_cast<int64_t>(mode_))
      .SetStatus(static_cast<int64_t>(status))
      .SetFeature_Viewer(static_cast<int64_t>(feature_request_viewer))
      .SetFeature_Local(static_cast<int64_t>(feature_request_local))
      .SetFeature_LocalFloor(static_cast<int64_t>(feature_request_local_floor))
      .SetFeature_BoundedFloor(
          static_cast<int64_t>(feature_request_bounded_floor))
      .SetFeature_Unbounded(static_cast<int64_t>(feature_request_unbounded))
      .Record(execution_context->UkmRecorder());

  // If the session was successfully created and DOM overlay was requested,
  // count this as a use of the DOM overlay feature.
  if (session && status == SessionRequestStatus::kSuccess &&
      IsFeatureRequested(feature_request_dom_overlay)) {
    DVLOG(2) << __func__ << ": DOM overlay was requested, logging a UseCounter";
    UseCounter::Count(session->GetExecutionContext(),
                      WebFeature::kXRDOMOverlay);
  }

  // If the session was successfully created and depth-sensing was requested,
  // count this as a use of depth sensing feature.
  if (session && status == SessionRequestStatus::kSuccess &&
      IsFeatureRequested(feature_request_depth_sensing)) {
    DVLOG(2) << __func__
             << ": depth sensing was requested, logging a UseCounter";
    UseCounter::Count(session->GetExecutionContext(),
                      WebFeature::kXRDepthSensing);
  }

  if (session && status == SessionRequestStatus::kSuccess &&
      IsFeatureRequested(feature_request_plane_detection)) {
    DVLOG(2) << __func__
             << ": plane detection was requested, logging a UseCounter";
    UseCounter::Count(session->GetExecutionContext(),
                      WebFeature::kXRPlaneDetection);
  }

  if (session && status == SessionRequestStatus::kSuccess &&
      IsFeatureRequested(feature_request_image_tracking)) {
    DVLOG(2) << __func__
             << ": image tracking was requested, logging a UseCounter";
    UseCounter::Count(session->GetExecutionContext(),
                      WebFeature::kXRImageTracking);
  }

  if (session && metrics_recorder) {
    mojo::Remote<device::mojom::blink::XRSessionMetricsRecorder> recorder(
        std::move(metrics_recorder));
    session->SetMetricsReporter(
        std::make_unique<XRSession::MetricsReporter>(std::move(recorder)));
  }
}

device::mojom::blink::XRSessionMode XRSystem::PendingRequestSessionQuery::mode()
    const {
  return mode_;
}

const XRSessionFeatureSet&
XRSystem::PendingRequestSessionQuery::RequiredFeatures() const {
  return required_features_.valid_features;
}

const XRSessionFeatureSet&
XRSystem::PendingRequestSessionQuery::OptionalFeatures() const {
  return optional_features_.valid_features;
}

bool XRSystem::PendingRequestSessionQuery::HasFeature(
    device::mojom::XRSessionFeature feature) const {
  return RequiredFeatures().Contains(feature) ||
         OptionalFeatures().Contains(feature);
}

bool XRSystem::PendingRequestSessionQuery::InvalidRequiredFeatures() const {
  return required_features_.invalid_features;
}

bool XRSystem::PendingRequestSessionQuery::InvalidOptionalFeatures() const {
  return optional_features_.invalid_features;
}

ScriptState* XRSystem::PendingRequestSessionQuery::GetScriptState() const {
  return resolver_->GetScriptState();
}

void XRSystem::PendingRequestSessionQuery::ParseSensorRequirement() {
  // All modes other than inline require sensors.
  if (mode_ != device::mojom::blink::XRSessionMode::kInline) {
    sensor_requirement_ = SensorRequirement::kRequired;
    return;
  }

  // If any required features require sensors, then sensors are required.
  for (const auto& feature : RequiredFeatures()) {
    if (feature != device::mojom::XRSessionFeature::REF_SPACE_VIEWER) {
      sensor_requirement_ = SensorRequirement::kRequired;
      return;
    }
  }

  // If any optional features require sensors, then sensors are optional.
  for (const auto& feature : OptionalFeatures()) {
    if (feature != device::mojom::XRSessionFeature::REF_SPACE_VIEWER) {
      sensor_requirement_ = SensorRequirement::kOptional;
      return;
    }
  }

  // By this point any situation that requires sensors should have returned.
  sensor_requirement_ = kNone;
}

void XRSystem::PendingRequestSessionQuery::Trace(Visitor* visitor) const {
  visitor->Trace(resolver_);
  visitor->Trace(dom_overlay_element_);
}

device::mojom::blink::XRSessionOptionsPtr XRSystem::XRSessionOptionsFromQuery(
    const PendingRequestSessionQuery& query) {
  device::mojom::blink::XRSessionOptionsPtr session_options =
      device::mojom::blink::XRSessionOptions::New();
  session_options->mode = query.mode();

  session_options->required_features.assign(query.RequiredFeatures());
  session_options->optional_features.assign(query.OptionalFeatures());

  session_options->tracked_images.resize(query.TrackedImages().size());
  for (unsigned i = 0; i < query.TrackedImages().size(); ++i) {
    session_options->tracked_images[i] =
        device::mojom::blink::XRTrackedImage::New();
    *session_options->tracked_images[i] = query.TrackedImages()[i];
  }

  if (query.HasFeature(device::mojom::XRSessionFeature::DEPTH)) {
    session_options->depth_options =
        device::mojom::blink::XRDepthOptions::New();
    session_options->depth_options->usage_preferences = query.PreferredUsage();
    session_options->depth_options->data_format_preferences =
        query.PreferredFormat();
  }

  session_options->trace_id = query.TraceId();

  return session_options;
}

const char XRSystem::kSupplementName[] = "XRSystem";

XRSystem* XRSystem::FromIfExists(Document& document) {
  if (!document.domWindow())
    return nullptr;
  return Supplement<Navigator>::From<XRSystem>(
      document.domWindow()->navigator());
}

XRSystem* XRSystem::From(Document& document) {
  DVLOG(2) << __func__;

  return document.domWindow() ? xr(*document.domWindow()->navigator())
                              : nullptr;
}

XRSystem* XRSystem::xr(Navigator& navigator) {
  DVLOG(2) << __func__;

  LocalDOMWindow* window = navigator.DomWindow();
  if (!window)
    return nullptr;

  XRSystem* xr = Supplement<Navigator>::From<XRSystem>(navigator);
  if (!xr) {
    xr = MakeGarbageCollected<XRSystem>(navigator);
    ProvideTo(navigator, xr);

    ukm::builders::XR_WebXR(window->UkmSourceID())
        .SetDidUseNavigatorXR(1)
        .Record(window->UkmRecorder());
  }
  return xr;
}

XRSystem::XRSystem(Navigator& navigator)
    : Supplement<Navigator>(navigator),
      ExecutionContextLifecycleObserver(navigator.DomWindow()),
      FocusChangedObserver(navigator.DomWindow()->GetFrame()->GetPage()),
      service_(navigator.DomWindow()),
      environment_provider_(navigator.DomWindow()),
      receiver_(this, navigator.DomWindow()),
      navigation_start_(navigator.DomWindow()
                            ->document()
                            ->Loader()
                            ->GetTiming()
                            .NavigationStart()),
      feature_handle_for_scheduler_(
          navigator.DomWindow()
              ->GetFrame()
              ->GetFrameScheduler()
              ->RegisterFeature(SchedulingPolicy::Feature::kWebXR,
                                {SchedulingPolicy::DisableBackForwardCache()})),
      webxr_internals_renderer_listener_(GetExecutionContext()) {}

void XRSystem::FocusedFrameChanged() {
  // Tell all sessions that focus changed.
  // Since this eventually dispatches an event to the page, the page could
  // create a new session which would invalidate our iterators; so iterate over
  // a copy of the session map.
  HeapHashSet<WeakMember<XRSession>> processing_sessions = sessions_;
  for (const auto& session : processing_sessions) {
    session->OnFocusChanged();
  }

  if (frame_provider_)
    frame_provider_->OnFocusChanged();
}

bool XRSystem::IsFrameFocused() {
  return FocusChangedObserver::IsFrameFocused(
      DomWindow() ? DomWindow()->GetFrame() : nullptr);
}

ExecutionContext* XRSystem::GetExecutionContext() const {
  return ExecutionContextLifecycleObserver::GetExecutionContext();
}

const AtomicString& XRSystem::InterfaceName() const {
  return event_target_names::kXR;
}

XRFrameProvider* XRSystem::frameP
```