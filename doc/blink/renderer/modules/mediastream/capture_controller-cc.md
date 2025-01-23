Response:
Let's break down the thought process for analyzing the `capture_controller.cc` file.

**1. Initial Reading and Identifying Key Areas:**

The first step is to read through the code to get a general understanding. I'd look for:

* **Includes:** These tell you the dependencies and what functionalities are likely being used (e.g., `mediastream`, `dom`, `events`, `bindings`, `platform`).
* **Class Definition:** The main class is `CaptureController`. This is the core of the functionality.
* **Methods:**  Scanning the public methods reveals the main actions the class performs (`setFocusBehavior`, `sendWheel`, `captureWheel`, `getZoomLevel`, `setZoomLevel`).
* **Helper Functions:**  The anonymous namespace contains utility functions (`IsCaptureType`, `ScaleCoordinates`, etc.). These often handle specific, smaller tasks.
* **Platform Checks:** The `#if !BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_IOS)` blocks indicate platform-specific behavior. This is important to note.
* **Asynchronous Operations:** The use of `ScriptPromise` strongly suggests asynchronous operations, likely interacting with the browser process.

**2. Dissecting Functionality - Core Tasks:**

Now, focus on understanding the purpose of each key method:

* **`setFocusBehavior`:**  This clearly deals with setting the focus behavior related to the captured surface. The checks for `focus_decision_finalized_` and the track state are important for understanding the lifecycle and constraints.
* **`sendWheel`:**  The name suggests sending wheel events. The code scales the coordinates and uses a `MediaStreamDispatcherHost`, indicating communication with the browser process. The platform-specific handling is a key observation.
* **`captureWheel`:** This seems to enable/disable the capturing of wheel events on a specific HTML element. The interaction with `WheelEventListener` is crucial here. Again, the platform divergence is noted.
* **`getZoomLevel` and `setZoomLevel`:** These are about controlling the zoom level of the captured surface. The constraints and the interaction with the browser process via `MediaStreamDispatcherHost` are essential.

**3. Identifying Relationships with Web Technologies (JavaScript, HTML, CSS):**

With an understanding of the core functionalities, consider how they connect to web technologies:

* **JavaScript:** The presence of `ScriptPromise` and the use of V8 types (`V8CaptureStartFocusBehavior`, `V8CapturedWheelAction`) strongly point to JavaScript API exposure. Think about how a JavaScript developer would use these methods.
* **HTML:** The `captureWheel` method takes an `HTMLElement*` as input. This directly links to HTML elements and event handling within the DOM.
* **CSS:** While not directly manipulating CSS properties, the zooming functionality conceptually affects how the rendered content (potentially captured from the browser or a window) appears, which indirectly relates to how CSS would style that content. The scaling of coordinates in `sendWheel` is also relevant in the context of how the browser renders elements.

**4. Logical Reasoning and Examples:**

For each function, consider potential scenarios and how they would work:

* **`setFocusBehavior`:**  Imagine a user granting screen sharing permissions. This method determines whether the focus shifts to the shared window/tab or stays with the sharing application.
* **`sendWheel`:**  Think of a user scrolling within a captured browser tab. This function takes the coordinates of the scroll event on the *capturing* application's side and sends them to the browser process to be interpreted in the context of the *captured* content.
* **`captureWheel`:** Envision a web application wanting to intercept scroll events from a specific element within a captured tab.
* **`getZoomLevel`/`setZoomLevel`:**  A web application providing controls to zoom in or out on the captured content.

**5. Common User/Programming Errors:**

Think about how developers might misuse the API:

* Calling methods in the wrong order (e.g., trying to control zoom before starting capture).
* Providing invalid arguments (e.g., zoom levels outside the supported range).
* Not handling promise rejections properly.
* Platform-specific assumptions in their code.

**6. Debugging Clues and User Operations:**

Trace the path a user might take to reach the code:

1. User interacts with a web page that uses the `getDisplayMedia` API.
2. The browser prompts the user to select a screen, window, or tab to share.
3. The user grants permission.
4. The JavaScript code then might call methods on the `CaptureController` instance (e.g., `setFocusBehavior`, `captureWheel`, `setZoomLevel`).
5. This triggers the execution of the C++ code in `capture_controller.cc`.

**7. Platform-Specific Considerations:**

Pay close attention to the `#if` blocks. Understand *why* certain functionality might be disabled on Android and iOS. This often relates to OS-level API differences or platform-specific design choices.

**8. Review and Refine:**

After the initial analysis, go back and review your findings. Ensure clarity and accuracy. Check for any missing pieces or areas that need further explanation. For example, explicitly mention the role of `MediaStreamDispatcherHost` as a bridge to the browser process.

By following these steps systematically, you can effectively analyze complex C++ code like the `capture_controller.cc` file and understand its role in the Chromium rendering engine and its interaction with web technologies.
这个文件是 Chromium Blink 引擎中 `blink/renderer/modules/mediastream/capture_controller.cc`，它主要负责**控制媒体流捕获的行为和属性**，特别是当使用 `getDisplayMedia()` API 捕获屏幕、窗口或标签页时。

以下是其功能的详细列表：

**核心功能：**

1. **管理捕获会话:**  与一个特定的媒体流轨道（通常是视频轨道）关联，该轨道代表正在进行的屏幕/窗口/标签页捕获会话。
2. **设置捕获焦点行为 (`setFocusBehavior`):** 允许网页控制在捕获开始时是否应该将焦点转移到被捕获的表面（例如，被捕获的窗口或标签页）。这只适用于捕获浏览器或窗口。
3. **发送鼠标滚轮事件到被捕获表面 (`sendWheel`):**  允许捕获页面将鼠标滚轮事件转发到被捕获的窗口或标签页。这使得捕获页面可以模拟用户在被捕获内容上的滚动操作。
4. **捕获特定元素的鼠标滚轮事件 (`captureWheel`):** 允许捕获页面监听特定 HTML 元素上的鼠标滚轮事件，并将这些事件转发到被捕获的表面。这可以用于交互式地控制被捕获的内容，例如在演示文稿中翻页。
5. **获取支持的缩放级别 (`getSupportedZoomLevels`):**  返回被捕获表面支持的缩放级别列表。
6. **获取当前的缩放级别 (`getZoomLevel`):**  返回被捕获表面的当前缩放级别。
7. **设置缩放级别 (`setZoomLevel`):**  允许捕获页面更改被捕获表面的缩放级别。

**与 JavaScript, HTML, CSS 的关系：**

这个文件是 Blink 引擎的 C++ 代码，它为 Web API 提供了底层实现。它直接与以下 Web 技术相关：

* **JavaScript:**
    * **`getDisplayMedia()` API:**  `CaptureController` 的生命周期通常与通过 `getDisplayMedia()` 获取的媒体流轨道相关联。
    * **`MediaStreamTrack` 接口:**  `CaptureController` 与表示捕获的 `MediaStreamTrack` 对象交互。
    * **`CapturedWheelAction` 接口:** JavaScript 可以创建 `CapturedWheelAction` 对象，用于指定要发送到被捕获表面的滚轮事件的参数（例如，坐标和滚动增量）。
    * **`CaptureController` 接口:**  JavaScript 可以通过 `MediaStreamTrack` 对象访问 `CaptureController` 实例，并调用其方法（例如 `setFocusBehavior`, `sendWheel`, `captureWheel`, `getZoomLevel`, `setZoomLevel`）。
    * **Promise:**  许多方法（如 `sendWheel`, `captureWheel`, `setZoomLevel`) 返回 JavaScript `Promise` 对象，以便异步处理操作结果。
    * **事件:**  `CaptureController` 可以派发事件，例如 `capturedzoomlevelchange`，通知 JavaScript 缩放级别发生了变化。

    **示例：**

    ```javascript
    navigator.mediaDevices.getDisplayMedia({ video: true })
      .then(stream => {
        const videoTrack = stream.getVideoTracks()[0];
        const captureController = videoTrack.getCaptureController();

        // 设置焦点行为
        captureController.setFocusBehavior('focus-captured-surface');

        // 发送滚轮事件
        const elementToScroll = document.getElementById('scrollable-area');
        elementToScroll.addEventListener('wheel', event => {
          captureController.sendWheel({
            x: event.clientX,
            y: event.clientY,
            wheelDeltaX: event.deltaX,
            wheelDeltaY: event.deltaY
          });
        });

        // 捕获特定元素的滚轮事件
        const captureTarget = document.getElementById('capture-target');
        captureController.captureWheel(captureTarget);

        // 获取和设置缩放级别
        const supportedZoomLevels = captureController.getSupportedZoomLevels();
        captureController.getZoomLevel().then(currentZoom => console.log('Current zoom:', currentZoom));
        captureController.setZoomLevel(150);
      });
    ```

* **HTML:**
    * `captureWheel` 方法接受一个 `HTMLElement` 对象作为参数，这意味着 JavaScript 可以指定监听哪个 HTML 元素的滚轮事件。

    **示例：**

    ```html
    <!DOCTYPE html>
    <html>
    <head>
      <title>Capture Example</title>
    </head>
    <body>
      <div id="capture-target" style="width: 200px; height: 200px; background-color: lightblue;">
        Target for Wheel Capture
      </div>
      <script src="script.js"></script>
    </body>
    </html>
    ```

* **CSS:**
    * 虽然 `CaptureController` 不直接操作 CSS，但其 `setZoomLevel` 功能会影响被捕获内容的渲染方式，最终用户在屏幕上看到的效果会受到 CSS 的影响。例如，被捕获的网页的布局和元素大小会随着缩放级别的变化而改变。

**逻辑推理和假设输入与输出：**

**假设输入 (对于 `sendWheel` 方法):**

* `MediaStreamTrack` 对象 `videoTrack`，表示一个正在进行的屏幕捕获会话。
* `CapturedWheelAction` 对象 `action`，包含以下属性：
    * `x`: 100 (鼠标事件的 X 坐标)
    * `y`: 50 (鼠标事件的 Y 坐标)
    * `wheelDeltaX`: 0 (水平滚动增量)
    * `wheelDeltaY`: -100 (垂直滚动增量，负数表示向下滚动)

**假设输出:**

* `sendWheel` 方法会尝试将模拟的滚轮事件发送到与 `videoTrack` 关联的被捕获表面。
* 如果成功，`sendWheel` 返回的 `Promise` 会 resolve。
* 如果失败（例如，捕获会话已结束，没有权限），`Promise` 会 reject 并抛出一个 `DOMException`。

**假设输入 (对于 `getZoomLevel` 方法):**

* `MediaStreamTrack` 对象 `videoTrack`，表示一个正在进行的屏幕捕获会话。

**假设输出:**

* `getZoomLevel` 方法返回一个 `Promise`。
* 如果成功，`Promise` 会 resolve 并返回一个整数，表示当前的缩放级别 (例如，100 表示 100%)。
* 如果失败（例如，捕获会话尚未开始），`Promise` 会 reject 并抛出一个 `DOMException`。

**用户或编程常见的使用错误：**

1. **在捕获会话开始之前调用方法：**  用户或开发者可能会尝试在 `getDisplayMedia()` 成功并获取到 `MediaStreamTrack` 之后，并且 `CaptureController` 被关联之前调用 `sendWheel` 或 `setZoomLevel` 等方法。这会导致 `DOMException: InvalidStateError`，因为没有活动的捕获会话。
   * **示例代码 (错误):**
     ```javascript
     let captureController;
     navigator.mediaDevices.getDisplayMedia({ video: true })
       .then(stream => {
         const videoTrack = stream.getVideoTracks()[0];
         // 错误：过早调用，captureController 可能还未初始化
         captureController.setZoomLevel(120);
         captureController = videoTrack.getCaptureController();
       });
     ```
2. **发送超出范围的缩放级别：**  用户或开发者可能会尝试使用 `setZoomLevel` 设置一个不在 `getSupportedZoomLevels()` 返回列表中的缩放级别。这会导致 `DOMException: InvalidStateError`。
   * **示例代码 (错误):**
     ```javascript
     captureController.setZoomLevel(110); // 假设 110 不在支持的列表中
     ```
3. **在不支持的捕获类型上调用方法：** 某些方法（例如 `sendWheel`，`setZoomLevel`）可能只在特定的捕获类型（例如标签页捕获）上受支持。如果在不支持的捕获类型（例如屏幕捕获）上调用这些方法，可能会导致 `DOMException: NotSupportedError`。
4. **在 Track 结束后调用方法:** 如果捕获的 `MediaStreamTrack` 已经结束 (readyState 为 "ended")，尝试调用 `CaptureController` 的方法也会导致 `DOMException: InvalidStateError`。

**用户操作如何一步步的到达这里，作为调试线索：**

1. **用户访问一个网页，该网页使用了 `getDisplayMedia()` API。**
2. **网页的 JavaScript 代码调用 `navigator.mediaDevices.getDisplayMedia({ video: true })` 请求屏幕共享、窗口共享或标签页共享。**
3. **浏览器显示一个提示框，让用户选择要共享的内容。**
4. **用户选择一个屏幕、窗口或标签页并点击“共享”。**
5. **`getDisplayMedia()` 返回一个 `MediaStream` 对象。**
6. **网页的 JavaScript 代码获取 `MediaStream` 中的视频轨道：`const videoTrack = stream.getVideoTracks()[0];`。**
7. **网页的 JavaScript 代码调用 `videoTrack.getCaptureController()` 获取 `CaptureController` 的实例。**
8. **网页的 JavaScript 代码调用 `CaptureController` 的方法，例如 `setFocusBehavior()`, `sendWheel()`, `captureWheel()`, `getZoomLevel()`, `setZoomLevel()`。**

**调试线索：**

* **断点:** 在 `capture_controller.cc` 的关键方法（例如 `setFocusBehavior`, `SendWheel`, `OnCaptureWheelPermissionResult`, `SetZoomLevel`) 设置断点，可以观察这些方法何时被调用，以及传入的参数值。
* **日志:**  在 `capture_controller.cc` 中添加日志输出，记录关键状态的变化和方法调用，例如：
    * 何时创建 `CaptureController` 实例。
    * `setFocusBehavior` 被调用的时间和传入的参数。
    * `SendWheel` 被调用时接收到的坐标和滚动增量。
    * `SetZoomLevel` 被调用时接收到的缩放级别。
    * 捕获会话的状态（例如，轨道是否已结束）。
* **检查 `MediaStreamTrack` 的状态:** 确保在调用 `CaptureController` 的方法时，关联的 `MediaStreamTrack` 处于 "live" 状态。
* **检查捕获类型:** 确认正在使用的捕获类型（屏幕、窗口或标签页）是否支持正在调用的 `CaptureController` 方法。
* **查看 JavaScript 控制台错误:**  如果操作失败，通常会在 JavaScript 控制台中抛出 `DOMException`，可以查看错误消息来了解问题所在。
* **使用 Chromium 的内部页面:**  可以使用 `chrome://webrtc-internals` 查看 WebRTC 的内部状态，包括媒体流和轨道的信息，这有助于了解捕获会话的状态。

总而言之，`blink/renderer/modules/mediastream/capture_controller.cc` 是 Chromium 中负责实现 Web API 规范中关于控制屏幕捕获行为的关键组件，它连接了 JavaScript API 和底层的媒体流处理逻辑。理解其功能对于调试 WebRTC 屏幕共享相关的问题至关重要。

### 提示词
```
这是目录为blink/renderer/modules/mediastream/capture_controller.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/mediastream/capture_controller.h"

#include <cmath>
#include <optional>

#include "base/numerics/safe_conversions.h"
#include "base/ranges/algorithm.h"
#include "base/types/expected.h"
#include "base/unguessable_token.h"
#include "build/build_config.h"
#include "third_party/blink/public/common/page/page_zoom.h"
#include "third_party/blink/renderer/bindings/core/v8/idl_types.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_captured_wheel_action.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_media_stream_track_state.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/dom/events/native_event_listener.h"
#include "third_party/blink/renderer/core/event_type_names.h"
#include "third_party/blink/renderer/core/events/wheel_event.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/geometry/dom_rect.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_track.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_video_track.h"
#include "third_party/blink/renderer/modules/mediastream/user_media_client.h"
#include "third_party/blink/renderer/platform/bindings/exception_code.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_component.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_source.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

using ::blink::mojom::blink::CapturedSurfaceControlResult;

namespace blink {

namespace {

using SurfaceType = media::mojom::DisplayCaptureSurfaceType;

bool IsCaptureType(const MediaStreamTrack* track,
                   const std::vector<SurfaceType>& types) {
  DCHECK(track);

  const MediaStreamVideoTrack* video_track =
      MediaStreamVideoTrack::From(track->Component());
  if (!video_track) {
    return false;
  }

  MediaStreamTrackPlatform::Settings settings;
  video_track->GetSettings(settings);
  const std::optional<SurfaceType> display_surface = settings.display_surface;
  return base::ranges::any_of(
      types, [display_surface](SurfaceType t) { return t == display_surface; });
}

#if !BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_IOS)
struct ScaledCoordinates {
  ScaledCoordinates(double relative_x, double relative_y)
      : relative_x(relative_x), relative_y(relative_y) {
    CHECK(0.0 <= relative_x && relative_x < 1.0);
    CHECK(0.0 <= relative_y && relative_y < 1.0);
  }

  const double relative_x;
  const double relative_y;
};

// Attempt to scale the coordinates to relative coordinates based on the last
// frame emitted for the given track.
base::expected<ScaledCoordinates, String> ScaleCoordinates(
    MediaStreamTrack* track,
    CapturedWheelAction* action) {
  CHECK(track);  // Validated by ValidateCapturedSurfaceControlCall().

  MediaStreamComponent* const component = track->Component();
  if (!component) {
    return base::unexpected("Unexpected error - no component.");
  }

  MediaStreamVideoTrack* const video_track =
      MediaStreamVideoTrack::From(component);
  if (!video_track) {
    return base::unexpected("Unexpected error - no video track.");
  }

  // Determine the size of the last video frame observed by the app for this
  // capture session.
  const gfx::Size last_frame_size = video_track->GetVideoSize();

  // Validate (x, y) prior to scaling.
  if (last_frame_size.width() <= 0 || last_frame_size.height() <= 0) {
    return base::unexpected("No frames observed yet.");
  }
  if (action->x() < 0 || action->x() >= last_frame_size.width() ||
      action->y() < 0 || action->y() >= last_frame_size.height()) {
    return base::unexpected("Coordinates out of bounds.");
  }

  // Scale (x, y) to reflect their position relative to the video size.
  // This allows the browser process to scale these coordinates to
  // the coordinate space of the captured surface, which is unknown
  // to the capturer.
  const double relative_x =
      static_cast<double>(action->x()) / last_frame_size.width();
  const double relative_y =
      static_cast<double>(action->y()) / last_frame_size.height();
  return ScaledCoordinates(relative_x, relative_y);
}

bool ShouldFocusCapturedSurface(V8CaptureStartFocusBehavior focus_behavior) {
  switch (focus_behavior.AsEnum()) {
    case V8CaptureStartFocusBehavior::Enum::kFocusCapturedSurface:
      return true;
    case V8CaptureStartFocusBehavior::Enum::kFocusCapturingApplication:
    case V8CaptureStartFocusBehavior::Enum::kNoFocusChange:
      return false;
  }
  NOTREACHED();
}

std::optional<int> GetInitialZoomLevel(MediaStreamTrack* video_track) {
  const MediaStreamVideoSource* native_source =
      MediaStreamVideoSource::GetVideoSource(
          video_track->Component()->Source());
  if (!native_source) {
    return std::nullopt;
  }

  const media::mojom::DisplayMediaInformationPtr& display_media_info =
      native_source->device().display_media_info;
  if (!display_media_info) {
    return std::nullopt;
  }

  return display_media_info->initial_zoom_level;
}

std::optional<base::UnguessableToken> GetCaptureSessionId(
    MediaStreamTrack* track) {
  if (!track) {
    return std::nullopt;
  }
  MediaStreamComponent* component = track->Component();
  if (!component) {
    return std::nullopt;
  }
  MediaStreamSource* source = component->Source();
  if (!source) {
    return std::nullopt;
  }
  WebPlatformMediaStreamSource* platform_source = source->GetPlatformSource();
  if (!platform_source) {
    return std::nullopt;
  }
  return platform_source->device().serializable_session_id();
}

DOMException* CscResultToDOMException(CapturedSurfaceControlResult result) {
  switch (result) {
    case CapturedSurfaceControlResult::kSuccess:
      return nullptr;
    case CapturedSurfaceControlResult::kUnknownError:
      return MakeGarbageCollected<DOMException>(DOMExceptionCode::kUnknownError,
                                                "Unknown error.");
    case CapturedSurfaceControlResult::kNoPermissionError:
      return MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kNotAllowedError, "No permission.");
    case CapturedSurfaceControlResult::kCapturerNotFoundError:
      return MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kNotFoundError, "Capturer not found.");
    case CapturedSurfaceControlResult::kCapturedSurfaceNotFoundError:
      return MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kNotFoundError, "Captured surface not found.");
    case CapturedSurfaceControlResult::kDisallowedForSelfCaptureError:
      return MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kInvalidStateError,
          "API not supported for self-capture.");
    case CapturedSurfaceControlResult::kCapturerNotFocusedError:
      return MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kInvalidStateError,
          "Capturing application not focused.");
  }
  NOTREACHED();
}

void OnCapturedSurfaceControlResult(
    ScriptPromiseResolver<IDLUndefined>* resolver,
    CapturedSurfaceControlResult result) {
  if (auto* exception = CscResultToDOMException(result)) {
    resolver->Reject(exception);
  } else {
    resolver->Resolve();
  }
}
#endif  // !BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_IOS)

}  // namespace

#if !BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_IOS)
class CaptureController::WheelEventListener : public NativeEventListener {
 public:
  WheelEventListener(ScriptState* script_state, CaptureController* controller)
      : script_state_(script_state), controller_(controller) {}

  void ListenTo(HTMLElement* element) {
    if (element_) {
      element_->removeEventListener(event_type_names::kWheel, this,
                                    /*use_capture=*/false);
    }
    element_ = element;
    if (element_) {
      element_->addEventListener(event_type_names::kWheel, this);
    }
  }

  void StopListening() { ListenTo(nullptr); }

  // NativeEventListener
  void Invoke(ExecutionContext* context, Event* event) override {
    CHECK(element_);
    CHECK(controller_);
    WheelEvent* wheel_event = DynamicTo<WheelEvent>(event);
    if (!wheel_event || !wheel_event->isTrusted()) {
      return;
    }

    DOMRect* element_rect = element_->GetBoundingClientRect();
    double relative_x =
        static_cast<double>(wheel_event->offsetX()) / element_rect->width();
    double relative_y =
        static_cast<double>(wheel_event->offsetY()) / element_rect->height();

    controller_->SendWheel(relative_x, relative_y, -wheel_event->deltaX(),
                           -wheel_event->deltaY());
  }

  void Trace(Visitor* visitor) const override {
    NativeEventListener::Trace(visitor);
    visitor->Trace(script_state_);
    visitor->Trace(controller_);
    visitor->Trace(element_);
  }

 private:
  Member<ScriptState> script_state_;
  Member<CaptureController> controller_;
  Member<HTMLElement> element_;
};
#endif  // !BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_IOS)

CaptureController::ValidationResult::ValidationResult(DOMExceptionCode code,
                                                      String message)
    : code(code), message(message) {}

CaptureController* CaptureController::Create(ExecutionContext* context) {
  return MakeGarbageCollected<CaptureController>(context);
}

CaptureController::CaptureController(ExecutionContext* context)
    : ExecutionContextClient(context)
#if !BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_IOS)
      ,
      media_stream_dispatcher_host_(context)
#endif
{
}

void CaptureController::setFocusBehavior(
    V8CaptureStartFocusBehavior focus_behavior,
    ExceptionState& exception_state) {
  DCHECK(IsMainThread());

  if (!GetExecutionContext()) {
    return;
  }

  if (focus_decision_finalized_) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "The window of opportunity for focus-decision is closed.");
    return;
  }

  if (!video_track_) {
    focus_behavior_ = focus_behavior;
    return;
  }

  if (video_track_->readyState() != V8MediaStreamTrackState::Enum::kLive) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "The video track must be live.");
    return;
  }

  if (!IsCaptureType(video_track_,
                     {SurfaceType::BROWSER, SurfaceType::WINDOW})) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "The captured display surface must be either a tab or a window.");
    return;
  }

  focus_behavior_ = focus_behavior;
  FinalizeFocusDecision();
}

ScriptPromise<IDLUndefined> CaptureController::sendWheel(
    ScriptState* script_state,
    CapturedWheelAction* action) {
  DCHECK(IsMainThread());
  CHECK(action);
  CHECK(action->hasX());
  CHECK(action->hasY());
  CHECK(action->hasWheelDeltaX());
  CHECK(action->hasWheelDeltaY());

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);

  const auto promise = resolver->Promise();
#if BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_IOS)
  resolver->RejectWithDOMException(DOMExceptionCode::kNotSupportedError,
                                   "Unsupported.");
  return promise;
#else
  ValidationResult validation_result = ValidateCapturedSurfaceControlCall();
  if (validation_result.code != DOMExceptionCode::kNoError) {
    resolver->RejectWithDOMException(validation_result.code,
                                     validation_result.message);
    return promise;
  }

  const base::expected<ScaledCoordinates, String> scaled_coordinates =
      ScaleCoordinates(video_track_, action);
  if (!scaled_coordinates.has_value()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     scaled_coordinates.error());
    return promise;
  }

  const std::optional<base::UnguessableToken>& session_id =
      GetCaptureSessionId(video_track_);
  if (!session_id.has_value()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kUnknownError,
                                     "Invalid capture");
    return promise;
  }

  GetMediaStreamDispatcherHost()->SendWheel(
      *session_id,
      blink::mojom::blink::CapturedWheelAction::New(
          scaled_coordinates->relative_x, scaled_coordinates->relative_y,
          action->wheelDeltaX(), action->wheelDeltaY()),
      WTF::BindOnce(&OnCapturedSurfaceControlResult, WrapPersistent(resolver)));

  return promise;
#endif  // BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_IOS)
}

ScriptPromise<IDLUndefined> CaptureController::captureWheel(
    ScriptState* script_state,
    HTMLElement* element) {
  DCHECK(IsMainThread());
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  const auto promise = resolver->Promise();
#if BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_IOS)
  resolver->RejectWithDOMException(DOMExceptionCode::kNotSupportedError,
                                   "Unsupported.");
  return promise;
#else
  if (!element) {
    if (wheel_listener_) {
      wheel_listener_->StopListening();
    }
    resolver->Resolve();
    return promise;
  }

  std::optional<base::UnguessableToken> session_id =
      GetCaptureSessionId(video_track_);
  if (!session_id.has_value()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "Invalid capture.");
    return promise;
  }

  ValidationResult validation_result = ValidateCapturedSurfaceControlCall();
  if (validation_result.code != DOMExceptionCode::kNoError) {
    resolver->RejectWithDOMException(validation_result.code,
                                     validation_result.message);
    return promise;
  }

  GetMediaStreamDispatcherHost()->RequestCapturedSurfaceControlPermission(
      *session_id,
      WTF::BindOnce(&CaptureController::OnCaptureWheelPermissionResult,
                    WrapWeakPersistent(this), WrapPersistent(resolver),
                    WrapWeakPersistent(element)));
  return promise;
#endif  // BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_IOS)
}

Vector<int> CaptureController::getSupportedZoomLevels() {
  const wtf_size_t kSize =
      static_cast<wtf_size_t>(kPresetBrowserZoomFactors.size());
  // If later developers modify `kPresetBrowserZoomFactors` to include many more
  // entries than original intended, they should consider modifying this
  // Web-exposed API to either:
  // * Allow the Web application provide the max levels it wishes to receive.
  // * Do some UA-determined trimming.
  CHECK_LE(kSize, 100u) << "Excessive zoom levels.";
  CHECK_EQ(kMinimumBrowserZoomFactor, kPresetBrowserZoomFactors.front());
  CHECK_EQ(kMaximumBrowserZoomFactor, kPresetBrowserZoomFactors.back());

  Vector<int> result(kSize);
  if (kSize == 0) {
    return result;
  }

  result[0] = base::ClampCeil(100 * kPresetBrowserZoomFactors[0]);
  for (wtf_size_t i = 1; i < kSize; ++i) {
    result[i] = base::ClampFloor(100 * kPresetBrowserZoomFactors[i]);
    CHECK_LT(result[i - 1], result[i]) << "Must be monotonically increasing.";
  }

  return result;
}

int CaptureController::getZoomLevel(ExceptionState& exception_state) {
  DCHECK(IsMainThread());

#if BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_IOS)
  exception_state.ThrowDOMException(DOMExceptionCode::kNotSupportedError,
                                    "Unsupported.");
  return 100;
#else
  ValidationResult validation_result = ValidateCapturedSurfaceControlCall();
  if (validation_result.code != DOMExceptionCode::kNoError) {
    exception_state.ThrowDOMException(validation_result.code,
                                      validation_result.message);
    return 100;
  }

  if (!zoom_level_) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "The zoom level is not yet known.");
    return 100;
  }

  return *zoom_level_;
#endif  // BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_IOS)
}

ScriptPromise<IDLUndefined> CaptureController::setZoomLevel(
    ScriptState* script_state,
    int zoom_level) {
  DCHECK(IsMainThread());

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);

  const auto promise = resolver->Promise();
#if BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_IOS)
  resolver->RejectWithDOMException(DOMExceptionCode::kNotSupportedError,
                                   "Unsupported.");
  return promise;
#else
  ValidationResult validation_result = ValidateCapturedSurfaceControlCall();
  if (validation_result.code != DOMExceptionCode::kNoError) {
    resolver->RejectWithDOMException(validation_result.code,
                                     validation_result.message);
    return promise;
  }

  if (!getSupportedZoomLevels().Contains(zoom_level)) {
    resolver->RejectWithDOMException(
        DOMExceptionCode::kInvalidStateError,
        "Only values returned by getSupportedZoomLevels() are valid.");
    return promise;
  }

  const std::optional<base::UnguessableToken>& session_id =
      GetCaptureSessionId(video_track_);
  if (!session_id.has_value()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kUnknownError,
                                     "Invalid capture");
    return promise;
  }

  GetMediaStreamDispatcherHost()->SetZoomLevel(
      session_id.value(), zoom_level,
      WTF::BindOnce(&OnCapturedSurfaceControlResult, WrapPersistent(resolver)));
  return promise;
#endif  // BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_IOS)
}

void CaptureController::SetVideoTrack(MediaStreamTrack* video_track,
                                      std::string descriptor_id) {
  DCHECK(IsMainThread());
  DCHECK(video_track);
  DCHECK(!video_track_);
  DCHECK(!descriptor_id.empty());
  DCHECK(descriptor_id_.empty());

  video_track_ = video_track;
  // The CaptureController-Source mapping cannot change after having been set
  // up, and the observer remains until either object is garbage collected. No
  // explicit deregistration of the observer is necessary.
  video_track_->Component()->AddSourceObserver(this);
  descriptor_id_ = std::move(descriptor_id);
#if !BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_IOS)
  zoom_level_ = GetInitialZoomLevel(video_track_);
#endif
}

const AtomicString& CaptureController::InterfaceName() const {
  return event_target_names::kCaptureController;
}

ExecutionContext* CaptureController::GetExecutionContext() const {
  return ExecutionContextClient::GetExecutionContext();
}

void CaptureController::FinalizeFocusDecision() {
  DCHECK(IsMainThread());

  if (focus_decision_finalized_) {
    return;
  }

  focus_decision_finalized_ = true;

  if (!video_track_ || !IsCaptureType(video_track_, {SurfaceType::BROWSER,
                                                     SurfaceType::WINDOW})) {
    return;
  }

  UserMediaClient* client = UserMediaClient::From(DomWindow());
  if (!client) {
    return;
  }

  if (!focus_behavior_) {
    return;
  }

#if !BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_IOS)
  client->FocusCapturedSurface(
      String(descriptor_id_),
      ShouldFocusCapturedSurface(focus_behavior_.value()));
#endif
}

#if !BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_IOS)
void CaptureController::SourceChangedZoomLevel(int zoom_level) {
  DCHECK(IsMainThread());

  if (zoom_level_ == zoom_level) {
    return;
  }

  zoom_level_ = zoom_level;

  if (!video_track_ || video_track_->Ended()) {
    return;
  }

  DispatchEvent(*Event::Create(event_type_names::kCapturedzoomlevelchange));
}

void CaptureController::OnCaptureWheelPermissionResult(
    ScriptPromiseResolver<IDLUndefined>* resolver,
    HTMLElement* element,
    CapturedSurfaceControlResult result) {
  DCHECK(IsMainThread());
  DOMException* exception = CscResultToDOMException(result);
  if (exception) {
    resolver->Reject(exception);
    return;
  }

  if (!wheel_listener_) {
    wheel_listener_ = MakeGarbageCollected<WheelEventListener>(
        resolver->GetScriptState(), this);
  }
  wheel_listener_->ListenTo(element);
  resolver->Resolve();
}

void CaptureController::SendWheel(double relative_x,
                                  double relative_y,
                                  int32_t wheel_delta_x,
                                  int32_t wheel_delta_y) {
  const std::optional<base::UnguessableToken>& session_id =
      GetCaptureSessionId(video_track_);
  if (!session_id.has_value()) {
    return;
  }

  GetMediaStreamDispatcherHost()->SendWheel(
      *session_id,
      blink::mojom::blink::CapturedWheelAction::New(
          relative_x, relative_y, wheel_delta_x, wheel_delta_y),
      WTF::BindOnce([](CapturedSurfaceControlResult) {}));
}

mojom::blink::MediaStreamDispatcherHost*
CaptureController::GetMediaStreamDispatcherHost() {
  DCHECK(IsMainThread());
  CHECK(GetExecutionContext());
  if (!media_stream_dispatcher_host_.is_bound()) {
    GetExecutionContext()->GetBrowserInterfaceBroker().GetInterface(
        media_stream_dispatcher_host_.BindNewPipeAndPassReceiver(
            GetExecutionContext()->GetTaskRunner(
                TaskType::kInternalMediaRealTime)));
  }

  return media_stream_dispatcher_host_.get();
}

void CaptureController::SetMediaStreamDispatcherHostForTesting(
    mojo::PendingRemote<mojom::blink::MediaStreamDispatcherHost> host) {
  media_stream_dispatcher_host_.Bind(
      std::move(host),
      GetExecutionContext()->GetTaskRunner(TaskType::kInternalMediaRealTime));
}
#endif

void CaptureController::Trace(Visitor* visitor) const {
  visitor->Trace(video_track_);
#if !BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_IOS)
  visitor->Trace(wheel_listener_);
  visitor->Trace(media_stream_dispatcher_host_);
#endif
  EventTarget::Trace(visitor);
  ExecutionContextClient::Trace(visitor);
}

CaptureController::ValidationResult
CaptureController::ValidateCapturedSurfaceControlCall() const {
  if (!is_bound_) {
    return ValidationResult(DOMExceptionCode::kInvalidStateError,
                            "getDisplayMedia() not called yet.");
  }

  if (!video_track_) {
    return ValidationResult(DOMExceptionCode::kInvalidStateError,
                            "Capture-session not started.");
  }

  if (video_track_->readyState() == V8MediaStreamTrackState::Enum::kEnded) {
    return ValidationResult(DOMExceptionCode::kInvalidStateError,
                            "Video track ended.");
  }

  if (!IsCaptureType(video_track_, {SurfaceType::BROWSER})) {
    return ValidationResult(DOMExceptionCode::kNotSupportedError,
                            "Action only supported for tab-capture.");
  }
  return ValidationResult(DOMExceptionCode::kNoError, "");
}

}  // namespace blink
```