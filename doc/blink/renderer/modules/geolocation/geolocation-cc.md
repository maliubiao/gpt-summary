Response:
Let's break down the thought process to analyze the `geolocation.cc` file and address the prompt's requirements.

**1. Understanding the Core Functionality:**

The immediate clue is the file path: `blink/renderer/modules/geolocation/geolocation.cc`. This strongly suggests the file implements the core logic for the Web Geolocation API within the Blink rendering engine. Reading the initial copyright notices confirms this, mentioning Apple and Android, key players in web browser development and adoption of web standards.

**2. Identifying Key Classes and Data Structures:**

Skimming through the `#include` statements and the class definition (`class Geolocation`) reveals the main components:

* **`Geolocation`:** The central class, managing geolocation requests and state.
* **`GeolocationCoordinates`:**  Represents the geographic coordinates (latitude, longitude, etc.).
* **`GeolocationPositionError`:**  Represents errors that occur during geolocation.
* **`GeoNotifier`:**  Likely a helper class to manage individual geolocation requests (one-shot or watch). The names `one_shots_` and `watchers_` reinforce this.
* **`GeolocationWatchers`:** A container for `GeoNotifier` instances associated with `watchPosition`.
* **`device::mojom::blink::Geoposition` and `device::mojom::blink::GeopositionError`:**  These come from the `services/device` component, indicating an interaction with a lower-level service responsible for actually fetching geolocation data. The `mojom` suffix suggests they are part of a Mojo interface definition.

**3. Tracing the Workflow of `getCurrentPosition` and `watchPosition`:**

By examining the `getCurrentPosition` and `watchPosition` methods, I can deduce the following flow:

* A JavaScript call to `navigator.geolocation.getCurrentPosition()` or `navigator.geolocation.watchPosition()` initiates the process.
* Blink's JavaScript binding layer routes this call to the corresponding methods in the `Geolocation` class.
* A `GeoNotifier` object is created to track the request.
* Permissions are checked (secure context, feature policy).
* Caching is considered (`HaveSuitableCachedPosition`).
* If a fresh location is needed, `StartUpdating` is called.
* `StartUpdating` interacts with the lower-level geolocation service via Mojo (`geolocation_service_`).

**4. Connecting to JavaScript, HTML, and CSS:**

The connection to JavaScript is direct through the `navigator.geolocation` API. HTML triggers the JavaScript which then uses the `Geolocation` API. CSS has no *direct* connection to the core logic in `geolocation.cc`. However, CSS *could* be used to visually indicate loading states or error messages related to geolocation (e.g., displaying a spinner while waiting for a position, showing an error message if permission is denied).

**5. Logical Reasoning and Input/Output Examples:**

Consider `ValidateGeoposition`. The code checks for valid latitude, longitude, accuracy, and timestamp. I can create hypothetical inputs and outputs:

* **Input:** `latitude = 91`, `longitude = 10`, `accuracy = 5`, `timestamp = valid`
* **Output:** `false` (latitude is out of range)

* **Input:** `latitude = 45`, `longitude = 190`, `accuracy = 5`, `timestamp = valid`
* **Output:** `false` (longitude is out of range)

* **Input:** `latitude = 30`, `longitude = 60`, `accuracy = -1`, `timestamp = valid`
* **Output:** `false` (accuracy cannot be negative)

**6. Identifying Potential User and Programming Errors:**

* **User Denial:** The code explicitly handles the "User denied Geolocation" scenario.
* **Insecure Context:**  The code checks for secure contexts and flags insecure usage as deprecated or blocked.
* **Feature Policy:**  The code checks for and handles cases where geolocation is disabled by feature policy.
* **Missing Error Handling in JavaScript:** A common JS error is failing to provide an error callback to `getCurrentPosition` or `watchPosition`. While `geolocation.cc` handles the error, the JS code might not gracefully handle it.

**7. Tracing User Operations to Reach the Code (Debugging Clues):**

This requires working backward from the code:

1. A user interacts with a webpage.
2. The webpage's JavaScript calls `navigator.geolocation.getCurrentPosition()` or `navigator.geolocation.watchPosition()`.
3. The browser's JavaScript engine (V8 in Chromium) executes this code.
4. Blink's bindings layer intercepts the geolocation API call.
5. The call is routed to the corresponding methods (`getCurrentPosition`, `watchPosition`) in `geolocation.cc`.

Therefore, to reach this code during debugging, a developer would:

* Set breakpoints in the JavaScript code calling the geolocation API.
* Set breakpoints in the `geolocation.cc` file, particularly at the entry points of `getCurrentPosition` and `watchPosition`.
* Step through the code execution to observe the flow and the values of relevant variables.

**Self-Correction/Refinement during the Process:**

* Initially, I might just focus on the core methods. Then, realizing the prompt asks about broader connections, I'd expand to consider the interaction with JavaScript, HTML, and CSS, even if indirect.
* I might initially overlook the `GeoNotifier` class's significance. Further analysis of how it's used in `one_shots_` and `watchers_` would reveal its role in managing individual requests.
* The Mojo interfaces (`device::mojom::blink::*`) are crucial for understanding the communication with the lower-level system. Recognizing the `mojom` convention is important.

By following these steps, combining code analysis with knowledge of web technologies and the Chromium architecture, I can generate a comprehensive answer that addresses all aspects of the prompt.
好的，让我们详细分析一下 `blink/renderer/modules/geolocation/geolocation.cc` 这个文件。

**功能概述**

`geolocation.cc` 文件实现了 Chromium Blink 引擎中 Web Geolocation API 的核心功能。它负责处理网页发起的获取地理位置信息的请求，并与底层操作系统或设备提供的定位服务进行交互。主要功能包括：

1. **暴露 JavaScript API:**  它实现了 `navigator.geolocation` 对象，使得 JavaScript 代码可以调用 `getCurrentPosition()` 和 `watchPosition()` 方法来获取设备的位置信息。
2. **权限管理:**  处理用户对地理位置权限的授予和拒绝。
3. **请求管理:**  管理来自网页的地理位置请求，包括一次性请求 (`getCurrentPosition`) 和持续监听请求 (`watchPosition`)。
4. **与底层定位服务交互:**  通过 Mojo 接口 (`device::mojom::blink::Geolocation`) 与 Chromium 的设备服务进行通信，以获取实际的地理位置数据。
5. **数据处理和转换:**  将底层定位服务返回的原始数据转换为 JavaScript 可以理解的 `GeolocationCoordinates` 和 `GeolocationPositionError` 对象。
6. **缓存机制:**  可选地使用缓存的位置信息来响应请求，以提高效率。
7. **错误处理:**  处理定位过程中可能出现的各种错误，例如用户拒绝权限、定位服务不可用等。
8. **Feature Policy 支持:**  遵守 Feature Policy 的限制，如果 Feature Policy 禁止了地理位置功能，则拒绝请求。
9. **安全上下文检查:**  要求在安全上下文（HTTPS）下才能使用地理位置 API，除非特定配置允许。
10. **性能监控:**  记录地理位置 API 的使用情况，用于性能分析。

**与 JavaScript, HTML, CSS 的关系**

* **JavaScript:**  `geolocation.cc` 提供的核心功能通过 `navigator.geolocation` 对象暴露给 JavaScript。开发者可以使用 JavaScript 调用 `getCurrentPosition()` 获取一次性位置信息，或者调用 `watchPosition()` 注册一个监听器，当位置发生变化时接收通知。

   **举例：**

   ```javascript
   navigator.geolocation.getCurrentPosition(
     function(position) {
       console.log("纬度: " + position.coords.latitude);
       console.log("经度: " + position.coords.longitude);
     },
     function(error) {
       console.error("获取地理位置失败: " + error.message);
     }
   );

   let watchId = navigator.geolocation.watchPosition(
     function(position) {
       console.log("位置更新: " + position.coords.latitude + ", " + position.coords.longitude);
     },
     function(error) {
       console.error("监听地理位置失败: " + error.message);
     }
   );

   // 稍后停止监听
   // navigator.geolocation.clearWatch(watchId);
   ```

* **HTML:**  HTML 本身不直接涉及地理位置的处理，但用户与网页的交互（例如点击按钮触发 JavaScript 代码调用地理位置 API）是使用地理位置功能的起点。此外，一些权限提示可能会作为 HTML 的一部分展示。

   **举例：**  一个按钮，点击后触发 JavaScript 代码请求地理位置。

   ```html
   <button onclick="getLocation()">获取我的位置</button>
   <script>
     function getLocation() {
       if (navigator.geolocation) {
         navigator.geolocation.getCurrentPosition(showPosition, showError);
       
### 提示词
```
这是目录为blink/renderer/modules/geolocation/geolocation.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2008, 2009, 2010, 2011 Apple Inc. All Rights Reserved.
 * Copyright (C) 2009 Torch Mobile, Inc.
 * Copyright 2010, The Android Open Source Project
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

#include "third_party/blink/renderer/modules/geolocation/geolocation.h"

#include <optional>

#include "base/notreached.h"
#include "base/task/single_thread_task_runner.h"
#include "services/device/public/mojom/geoposition.mojom-blink.h"
#include "third_party/blink/public/mojom/permissions_policy/permissions_policy.mojom-blink.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/core/frame/deprecation/deprecation.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/navigator.h"
#include "third_party/blink/renderer/core/frame/performance_monitor.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/core/timing/epoch_time_stamp.h"
#include "third_party/blink/renderer/modules/geolocation/geolocation_coordinates.h"
#include "third_party/blink/renderer/modules/geolocation/geolocation_error.h"
#include "third_party/blink/renderer/platform/bindings/source_location.h"

namespace blink {
namespace {

const char kPermissionDeniedErrorMessage[] = "User denied Geolocation";
const char kFeaturePolicyErrorMessage[] =
    "Geolocation has been disabled in this document by permissions policy.";
const char kFeaturePolicyConsoleWarning[] =
    "Geolocation access has been blocked because of a permissions policy "
    "applied to the current document. See https://goo.gl/EuHzyv for more "
    "details.";

Geoposition* CreateGeoposition(
    const device::mojom::blink::Geoposition& position) {
  auto* coordinates = MakeGarbageCollected<GeolocationCoordinates>(
      position.latitude, position.longitude,
      // Lowest point on land is at approximately -400 meters.
      position.altitude > -10000. ? std::make_optional(position.altitude)
                                  : std::nullopt,
      position.accuracy,
      position.altitude_accuracy >= 0.
          ? std::make_optional(position.altitude_accuracy)
          : std::nullopt,
      position.heading >= 0. && position.heading <= 360.
          ? std::make_optional(position.heading)
          : std::nullopt,
      position.speed >= 0. ? std::optional(position.speed) : std::nullopt);
  return MakeGarbageCollected<Geoposition>(
      coordinates, ConvertTimeToEpochTimeStamp(position.timestamp));
}

GeolocationPositionError* CreatePositionError(
    const device::mojom::blink::GeopositionError& error) {
  GeolocationPositionError::ErrorCode error_code =
      GeolocationPositionError::kPositionUnavailable;
  switch (error.error_code) {
    case device::mojom::blink::GeopositionErrorCode::kPermissionDenied:
      error_code = GeolocationPositionError::kPermissionDenied;
      break;
    case device::mojom::blink::GeopositionErrorCode::kPositionUnavailable:
      error_code = GeolocationPositionError::kPositionUnavailable;
      break;
    default:
      // On the Blink side, it should only handle W3C-defined error codes. If it
      // reaches here, that means a platform-specific error type is being
      // propagated to Blink. We will now just use kPositionUnavailable until
      // more explicit error codes are defined in the W3C spec.
      error_code = GeolocationPositionError::kPositionUnavailable;
      break;
  }
  return MakeGarbageCollected<GeolocationPositionError>(error_code,
                                                        error.error_message);
}

static void ReportGeolocationViolation(LocalDOMWindow* window) {
  // TODO(dcheng): |doc| probably can't be null here.
  if (!LocalFrame::HasTransientUserActivation(window ? window->GetFrame()
                                                     : nullptr)) {
    PerformanceMonitor::ReportGenericViolation(
        window, PerformanceMonitor::kDiscouragedAPIUse,
        "Only request geolocation information in response to a user gesture.",
        base::TimeDelta(), nullptr);
  }
}

bool ValidateGeoposition(const device::mojom::blink::Geoposition& position) {
  return position.latitude >= -90. && position.latitude <= 90. &&
         position.longitude >= -180. && position.longitude <= 180. &&
         position.accuracy >= 0. && !position.timestamp.is_null();
}

}  // namespace

// static
const char Geolocation::kSupplementName[] = "Geolocation";

// static
Geolocation* Geolocation::geolocation(Navigator& navigator) {
  if (!navigator.DomWindow())
    return nullptr;

  Geolocation* supplement = Supplement<Navigator>::From<Geolocation>(navigator);
  if (!supplement) {
    supplement = MakeGarbageCollected<Geolocation>(navigator);
    ProvideTo(navigator, supplement);
  }
  return supplement;
}

Geolocation::Geolocation(Navigator& navigator)
    : ActiveScriptWrappable<Geolocation>({}),
      Supplement<Navigator>(navigator),
      ExecutionContextLifecycleObserver(navigator.DomWindow()),
      PageVisibilityObserver(navigator.DomWindow()->GetFrame()->GetPage()),
      one_shots_(MakeGarbageCollected<GeoNotifierSet>()),
      watchers_(MakeGarbageCollected<GeolocationWatchers>()),
      one_shots_being_invoked_(MakeGarbageCollected<GeoNotifierSet>()),
      geolocation_(navigator.DomWindow()),
      geolocation_service_(navigator.DomWindow()) {}

Geolocation::~Geolocation() = default;

void Geolocation::Trace(Visitor* visitor) const {
  visitor->Trace(one_shots_);
  visitor->Trace(watchers_);
  visitor->Trace(one_shots_being_invoked_);
  visitor->Trace(watchers_being_invoked_);
  visitor->Trace(last_position_);
  visitor->Trace(geolocation_);
  visitor->Trace(geolocation_service_);
  ScriptWrappable::Trace(visitor);
  Supplement<Navigator>::Trace(visitor);
  ExecutionContextLifecycleObserver::Trace(visitor);
  PageVisibilityObserver::Trace(visitor);
}

LocalFrame* Geolocation::GetFrame() const {
  return DomWindow() ? DomWindow()->GetFrame() : nullptr;
}

void Geolocation::ContextDestroyed() {
  StopTimers();
  one_shots_->clear();
  watchers_->Clear();

  StopUpdating();

  last_position_ = nullptr;
}

void Geolocation::RecordOriginTypeAccess() const {
  DCHECK(GetFrame());

  LocalDOMWindow* window = DomWindow();

  // It is required by isSecureContext() but isn't actually used. This could be
  // used later if a warning is shown in the developer console.
  String insecure_origin_msg;
  if (window->IsSecureContext(insecure_origin_msg)) {
    UseCounter::Count(window, WebFeature::kGeolocationSecureOrigin);
    window->CountUseOnlyInCrossOriginIframe(
        WebFeature::kGeolocationSecureOriginIframe);
  } else if (GetFrame()
                 ->GetSettings()
                 ->GetAllowGeolocationOnInsecureOrigins()) {
    // Android WebView allows geolocation in secure contexts for legacy apps.
    // See https://crbug.com/603574 for details.
    Deprecation::CountDeprecation(
        window, WebFeature::kGeolocationInsecureOriginDeprecatedNotRemoved);
    Deprecation::CountDeprecationCrossOriginIframe(
        window,
        WebFeature::kGeolocationInsecureOriginIframeDeprecatedNotRemoved);
  } else {
    Deprecation::CountDeprecation(window,
                                  WebFeature::kGeolocationInsecureOrigin);
    Deprecation::CountDeprecationCrossOriginIframe(
        window, WebFeature::kGeolocationInsecureOriginIframe);
  }
}

void Geolocation::getCurrentPosition(V8PositionCallback* success_callback,
                                     V8PositionErrorCallback* error_callback,
                                     const PositionOptions* options) {
  if (!GetFrame())
    return;

  probe::BreakableLocation(GetExecutionContext(),
                           "Geolocation.getCurrentPosition");

  auto* notifier = MakeGarbageCollected<GeoNotifier>(this, success_callback,
                                                     error_callback, options);

  one_shots_->insert(notifier);

  StartRequest(notifier);
}

int Geolocation::watchPosition(V8PositionCallback* success_callback,
                               V8PositionErrorCallback* error_callback,
                               const PositionOptions* options) {
  if (!GetFrame())
    return 0;

  probe::BreakableLocation(GetExecutionContext(), "Geolocation.watchPosition");

  auto* notifier = MakeGarbageCollected<GeoNotifier>(this, success_callback,
                                                     error_callback, options);

  int watch_id;
  // Keep asking for the next id until we're given one that we don't already
  // have.
  do {
    watch_id = GetExecutionContext()->CircularSequentialID();
  } while (!watchers_->Add(watch_id, notifier));

  StartRequest(notifier);

  return watch_id;
}

void Geolocation::StartRequest(GeoNotifier* notifier) {
  RecordOriginTypeAccess();
  String error_message;
  if (!GetFrame()->GetSettings()->GetAllowGeolocationOnInsecureOrigins() &&
      !GetExecutionContext()->IsSecureContext(error_message)) {
    notifier->SetFatalError(MakeGarbageCollected<GeolocationPositionError>(
        GeolocationPositionError::kPermissionDenied, error_message));
    return;
  }

  if (!GetExecutionContext()->IsFeatureEnabled(
          mojom::blink::PermissionsPolicyFeature::kGeolocation,
          ReportOptions::kReportOnFailure, kFeaturePolicyConsoleWarning)) {
    UseCounter::Count(GetExecutionContext(),
                      WebFeature::kGeolocationDisabledByFeaturePolicy);
    notifier->SetFatalError(MakeGarbageCollected<GeolocationPositionError>(
        GeolocationPositionError::kPermissionDenied,
        kFeaturePolicyErrorMessage));
    return;
  }

  ReportGeolocationViolation(DomWindow());

  if (HaveSuitableCachedPosition(notifier->Options())) {
    notifier->SetUseCachedPosition();
  } else {
    StartUpdating(notifier);
  }
}

void Geolocation::FatalErrorOccurred(GeoNotifier* notifier) {
  DCHECK(!notifier->IsTimerActive());

  // This request has failed fatally. Remove it from our lists.
  one_shots_->erase(notifier);
  watchers_->Remove(notifier);

  if (!HasListeners())
    StopUpdating();
}

void Geolocation::RequestUsesCachedPosition(GeoNotifier* notifier) {
  DCHECK(!notifier->IsTimerActive());

  notifier->RunSuccessCallback(last_position_);

  // If this is a one-shot request, stop it. Otherwise, if the watch still
  // exists, start the service to get updates.
  if (one_shots_->Contains(notifier)) {
    one_shots_->erase(notifier);
  } else if (watchers_->Contains(notifier)) {
    StartUpdating(notifier);
  }

  if (!HasListeners())
    StopUpdating();
}

void Geolocation::RequestTimedOut(GeoNotifier* notifier) {
  DCHECK(!notifier->IsTimerActive());

  // If this is a one-shot request, stop it.
  one_shots_->erase(notifier);

  if (!HasListeners())
    StopUpdating();
}

bool Geolocation::DoesOwnNotifier(GeoNotifier* notifier) const {
  return one_shots_->Contains(notifier) ||
         one_shots_being_invoked_->Contains(notifier) ||
         watchers_->Contains(notifier) ||
         watchers_being_invoked_.Contains(notifier);
}

bool Geolocation::HaveSuitableCachedPosition(const PositionOptions* options) {
  if (!last_position_)
    return false;
  if (!options->maximumAge())
    return false;
  EpochTimeStamp current_time_millis =
      ConvertTimeToEpochTimeStamp(base::Time::Now());
  return last_position_->timestamp() >
         current_time_millis - options->maximumAge();
}

void Geolocation::clearWatch(int watch_id) {
  if (watch_id <= 0)
    return;

  GeoNotifier* notifier = watchers_->Find(watch_id);
  if (!notifier)
    return;

  notifier->StopTimer();
  watchers_->Remove(watch_id);

  if (!HasListeners())
    StopUpdating();
}

void Geolocation::StopTimers() {
  for (const auto& notifier : *one_shots_) {
    notifier->StopTimer();
  }

  for (const auto& notifier : watchers_->Notifiers()) {
    notifier->StopTimer();
  }
}

void Geolocation::HandleError(GeolocationPositionError* error) {
  DCHECK(error);

  DCHECK(one_shots_being_invoked_->IsEmpty());
  DCHECK(watchers_being_invoked_.empty());

  if (error->IsFatal()) {
    // Stop the timers of |one_shots_| and |watchers_| before swapping/copying
    // them.
    StopTimers();
  }

  // Set |one_shots_being_invoked_| and |watchers_being_invoked_| to the
  // callbacks to be invoked, which must not change during invocation of
  // the callbacks. Note that |one_shots_| and |watchers_| might be changed
  // by a callback through getCurrentPosition, watchPosition, and/or
  // clearWatch.
  swap(one_shots_, one_shots_being_invoked_);
  watchers_->CopyNotifiersToVector(watchers_being_invoked_);

  if (error->IsFatal()) {
    // Clear the watchers before invoking the callbacks.
    watchers_->Clear();
  }

  // Invoke the callbacks. Do not send a non-fatal error to the notifiers
  // that only need a cached position. Let them receive a cached position
  // later.
  //
  // A notifier may call |clearWatch|, and in that case, that watcher notifier
  // already scheduled must be immediately cancelled according to the spec. But
  // the current implementation doesn't support such case.
  // TODO(mattreynolds): Support watcher cancellation inside notifier callbacks.
  for (auto& notifier : *one_shots_being_invoked_) {
    if (error->IsFatal() || !notifier->UseCachedPosition())
      notifier->RunErrorCallback(error);
  }
  for (auto& notifier : watchers_being_invoked_) {
    if (error->IsFatal() || !notifier->UseCachedPosition())
      notifier->RunErrorCallback(error);
  }

  // |HasListeners| doesn't distinguish those notifiers which require a fresh
  // position from those which are okay with a cached position. Perform the
  // check before adding the latter back to |one_shots_|.
  if (!HasListeners())
    StopUpdating();

  if (!error->IsFatal()) {
    // Keep the notifiers that are okay with a cached position in |one_shots_|.
    for (const auto& notifier : *one_shots_being_invoked_) {
      if (notifier->UseCachedPosition())
        one_shots_->InsertWithoutTimerCheck(notifier.Get());
      else
        notifier->StopTimer();
    }
    one_shots_being_invoked_->ClearWithoutTimerCheck();
  }

  one_shots_being_invoked_->clear();
  watchers_being_invoked_.clear();
}

void Geolocation::MakeSuccessCallbacks() {
  DCHECK(last_position_);

  DCHECK(one_shots_being_invoked_->IsEmpty());
  DCHECK(watchers_being_invoked_.empty());

  // Set |one_shots_being_invoked_| and |watchers_being_invoked_| to the
  // callbacks to be invoked, which must not change during invocation of
  // the callbacks. Note that |one_shots_| and |watchers_| might be changed
  // by a callback through getCurrentPosition, watchPosition, and/or
  // clearWatch.
  swap(one_shots_, one_shots_being_invoked_);
  watchers_->CopyNotifiersToVector(watchers_being_invoked_);

  // Invoke the callbacks.
  //
  // A notifier may call |clearWatch|, and in that case, that watcher notifier
  // already scheduled must be immediately cancelled according to the spec. But
  // the current implementation doesn't support such case.
  // TODO(mattreynolds): Support watcher cancellation inside notifier callbacks.
  for (auto& notifier : *one_shots_being_invoked_)
    notifier->RunSuccessCallback(last_position_);
  for (auto& notifier : watchers_being_invoked_)
    notifier->RunSuccessCallback(last_position_);

  if (!HasListeners())
    StopUpdating();

  one_shots_being_invoked_->clear();
  watchers_being_invoked_.clear();
}

void Geolocation::PositionChanged() {
  // Stop all currently running timers.
  StopTimers();

  MakeSuccessCallbacks();
}

void Geolocation::StartUpdating(GeoNotifier* notifier) {
  updating_ = true;
  if (notifier->Options()->enableHighAccuracy() && !enable_high_accuracy_) {
    enable_high_accuracy_ = true;
    if (geolocation_.is_bound())
      geolocation_->SetHighAccuracy(true);
  }
  UpdateGeolocationConnection(notifier);
}

void Geolocation::StopUpdating() {
  updating_ = false;
  UpdateGeolocationConnection(nullptr);
  enable_high_accuracy_ = false;
}

void Geolocation::UpdateGeolocationConnection(GeoNotifier* notifier) {
  if (!GetExecutionContext() || !GetPage() || !GetPage()->IsPageVisible() ||
      !updating_) {
    geolocation_.reset();
    geolocation_service_.reset();
    disconnected_geolocation_ = true;
    return;
  }
  if (geolocation_.is_bound()) {
    if (notifier)
      notifier->StartTimer();
    return;
  }

  // See https://bit.ly/2S0zRAS for task types.
  scoped_refptr<base::SingleThreadTaskRunner> task_runner =
      GetExecutionContext()->GetTaskRunner(TaskType::kMiscPlatformAPI);
  GetFrame()->GetBrowserInterfaceBroker().GetInterface(
      geolocation_service_.BindNewPipeAndPassReceiver(task_runner));
  geolocation_service_->CreateGeolocation(
      geolocation_.BindNewPipeAndPassReceiver(std::move(task_runner)),
      LocalFrame::HasTransientUserActivation(GetFrame()),
      WTF::BindOnce(&Geolocation::OnGeolocationPermissionStatusUpdated,
                    WrapWeakPersistent(this), WrapWeakPersistent(notifier)));

  geolocation_.set_disconnect_handler(WTF::BindOnce(
      &Geolocation::OnGeolocationConnectionError, WrapWeakPersistent(this)));
  if (enable_high_accuracy_)
    geolocation_->SetHighAccuracy(true);
  QueryNextPosition();
}

void Geolocation::QueryNextPosition() {
  geolocation_->QueryNextPosition(
      WTF::BindOnce(&Geolocation::OnPositionUpdated, WrapPersistent(this)));
}

void Geolocation::OnPositionUpdated(
    device::mojom::blink::GeopositionResultPtr result) {
  disconnected_geolocation_ = false;
  if (result->is_position()) {
    if (!ValidateGeoposition(*result->get_position())) {
      return;
    }
    last_position_ = CreateGeoposition(*result->get_position());
    PositionChanged();
  } else {
    DCHECK(result->is_error());
    const auto& geoposition_error = *result->get_error();
    GeolocationPositionError* position_error =
        CreatePositionError(geoposition_error);

    auto* context = GetExecutionContext();
    DCHECK(context);
    if (!geoposition_error.error_technical.empty()) {
      context->AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
          mojom::blink::ConsoleMessageSource::kNetwork,
          mojom::blink::ConsoleMessageLevel::kError,
          geoposition_error.error_technical));
    }

    if (position_error->code() == GeolocationPositionError::kPermissionDenied) {
      position_error->SetIsFatal(true);
    }
    HandleError(position_error);
  }
  if (!disconnected_geolocation_)
    QueryNextPosition();
}

void Geolocation::PageVisibilityChanged() {
  for (auto& notifier : *one_shots_)
    UpdateGeolocationConnection(notifier);

  HeapVector<Member<GeoNotifier>> watchers;
  watchers_->CopyNotifiersToVector(watchers);
  for (auto& notifier : watchers)
    UpdateGeolocationConnection(notifier);
}

bool Geolocation::HasPendingActivity() const {
  return !one_shots_->IsEmpty() || !one_shots_being_invoked_->IsEmpty() ||
         !watchers_->IsEmpty() || !watchers_being_invoked_.empty();
}

void Geolocation::OnGeolocationConnectionError() {
  StopUpdating();
  // The only reason that we would fail to get a ConnectionError is if we lack
  // sufficient permission.
  auto* error = MakeGarbageCollected<GeolocationPositionError>(
      GeolocationPositionError::kPermissionDenied,
      kPermissionDeniedErrorMessage);
  error->SetIsFatal(true);
  HandleError(error);
}

void Geolocation::OnGeolocationPermissionStatusUpdated(
    GeoNotifier* notifier,
    mojom::PermissionStatus status) {
  if (notifier && status == mojom::PermissionStatus::GRANTED) {
    // Avoid starting the notifier timer if the notifier has already been
    // removed.
    if (DoesOwnNotifier(notifier))
      notifier->StartTimer();
  }
}

}  // namespace blink
```