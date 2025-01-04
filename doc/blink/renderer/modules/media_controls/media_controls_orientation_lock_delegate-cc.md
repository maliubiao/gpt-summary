Response:
Let's break down the thought process for analyzing this C++ code. The request is comprehensive, asking for functionality, relationships to web technologies, logic analysis, potential errors, and user journey. Here’s a step-by-step approach:

1. **Initial Skim for Keywords and Structure:**  The first thing I'd do is quickly read through the code, looking for obvious keywords and the general structure. I'd notice things like `#include`, namespaces (`blink`), class definition (`MediaControlsOrientationLockDelegate`), member variables (`video_element_`, `state_`, etc.), and methods (`Attach`, `Detach`, `MaybeLockOrientation`, etc.). The comments, especially the copyright notice and the initial description, are valuable.

2. **Identify the Core Purpose:**  The class name itself is very telling: `MediaControlsOrientationLockDelegate`. This immediately suggests its primary function is related to locking screen orientation, specifically in the context of media controls. The includes further reinforce this: `ScreenOrientationController`, `ScreenOrientation`, `DeviceOrientationEvent`.

3. **Analyze Key Methods (Verb-Driven Approach):** I'd then focus on the methods, paying attention to their names. Verbs often indicate actions or functionalities.

    * **`Attach()` and `Detach()`:** These are standard lifecycle methods for hooking up and unhooking event listeners. The events being listened for (`fullscreenchange`, `webkitfullscreenchange`, `loadedmetadata`) are strong clues about when this delegate is active.

    * **`MaybeLockOrientation()`:** The "Maybe" prefix suggests conditional logic. The code checks `VideoElement().getReadyState()` and interacts with `ScreenOrientationController` to potentially lock the orientation. The call to `ComputeOrientationLock()` tells us *how* the orientation is determined.

    * **`ChangeLockToAnyOrientation()`:**  This indicates a modification of an existing lock, specifically to allow any orientation.

    * **`MaybeUnlockOrientation()`:**  The counterpart to `MaybeLockOrientation()`, responsible for releasing the orientation lock.

    * **`MaybeListenToDeviceOrientation()`:**  This method introduces the concept of responding to device orientation changes. The `RuntimeEnabledFeatures::VideoRotateToFullscreenEnabled()` check reveals a feature flag controlling this behavior. The Android-specific code with `IsAutoRotateEnabledByUser` is important.

    * **`GotIsAutoRotateEnabledByUser()`:** This is a callback function, handling the result of the asynchronous check for user-level auto-rotate settings.

    * **`ComputeOrientationLock()`:**  This is crucial for understanding *what* orientation is being locked. The logic based on video dimensions (`videoWidth`, `videoHeight`) is key.

    * **`ComputeDeviceOrientation()`:** This delves into the logic of interpreting raw device orientation data (`beta`, `gamma`). The trigonometric calculations are noteworthy.

    * **`MaybeLockToAnyIfDeviceOrientationMatchesVideo()`:** This ties device orientation back to the locked video orientation, potentially unlocking if they match. The `kLockToAnyDelay` introduces a timing aspect.

    * **`Invoke()`:** This is the event handler, dispatching logic based on the event type.

4. **Identify Relationships to Web Technologies:**  As I analyze the methods, I would explicitly note the connections to web technologies:

    * **JavaScript Events:**  `fullscreenchange`, `webkitfullscreenchange`, `loadedmetadata`, `deviceorientation` are all standard JavaScript events.
    * **HTML Elements:** `HTMLVideoElement` is the core element this code interacts with.
    * **CSS (Indirectly):** Fullscreen mode is often styled using CSS. While this code doesn't directly manipulate CSS, it triggers state changes that CSS might respond to.
    * **Screen Orientation API:** The use of `ScreenOrientationController`, `ScreenOrientation`, and related classes directly links to the browser's Screen Orientation API.

5. **Perform Logical Reasoning and Create Scenarios:**  Now, I would think about the flow of execution and create hypothetical scenarios:

    * **Scenario 1: Video enters fullscreen.**  The `fullscreenchange` event would trigger `MaybeLockOrientation()`. If metadata is loaded, it would lock to landscape/portrait based on video dimensions.
    * **Scenario 2: User rotates the device.** If `VideoRotateToFullscreenEnabled()` is true and auto-rotate is enabled, `deviceorientation` events would be listened for. `MaybeLockToAnyIfDeviceOrientationMatchesVideo()` would be invoked.
    * **Scenario 3: Video metadata loads before fullscreen.** The `loadedmetadata` event would trigger `MaybeLockOrientation()`.
    * **Scenario 4: User exits fullscreen.** The `fullscreenchange` event would trigger `MaybeUnlockOrientation()`.

6. **Consider Potential Errors and User Mistakes:** Based on the code's logic, I'd think about potential issues:

    * **User has locked OS-level orientation:** The code checks for this on Android and adjusts behavior, but it's a potential conflict.
    * **Feature flag disabled:** If `VideoRotateToFullscreenEnabled()` is off, the device orientation logic is skipped.
    * **Rapid fullscreen toggling:**  The state machine (`state_`) and the `lock_to_any_task_` help manage this, but there could still be edge cases.
    * **Square videos:** The fallback logic for square videos could be unexpected.
    * **Permissions:**  The Device Orientation API requires user permission. If permission is denied, this code might not function as expected.

7. **Trace the User Journey (Debugging Perspective):**  Finally, I'd outline how a user's actions lead to this code being executed:

    * **User interaction:**  Clicking the fullscreen button on a video player.
    * **Browser event:** The browser dispatches a `fullscreenchange` event.
    * **Event listener:** The `MediaControlsOrientationLockDelegate` is registered as a listener for this event.
    * **Code execution:** The `Invoke()` method is called, leading to `MaybeLockOrientation()` or `MaybeUnlockOrientation()`.
    * **Further actions:** Depending on the state, this could involve calls to the Screen Orientation API or starting to listen for `deviceorientation` events.

8. **Structure the Answer:**  Organize the findings into clear sections as requested by the prompt: Functionality, Relationships to Web Technologies, Logical Reasoning (with input/output examples), Common Errors, and User Journey (Debugging). Use clear and concise language.

9. **Review and Refine:**  Read through the entire answer, checking for accuracy, clarity, and completeness. Ensure the examples are relevant and easy to understand. For instance, the initial draft of the logical reasoning might be too abstract. Adding specific input and output (or expected actions) makes it much clearer. Similarly, the debugging section needs to be a step-by-step narrative.
这个C++源代码文件 `media_controls_orientation_lock_delegate.cc` 属于 Chromium Blink 引擎，它专门负责在视频全屏播放时管理屏幕方向锁定。 它的主要功能是根据视频的宽高比以及用户的设备方向，来请求锁定或解锁屏幕方向，以提供更好的全屏观看体验。

以下是该文件的详细功能列表以及与 web 技术的关系：

**主要功能:**

1. **根据视频宽高比自动锁定屏幕方向:**
   - 当视频进入全屏模式时，如果启用了相关特性（`RuntimeEnabledFeatures::VideoRotateToFullscreenEnabled()`），该代码会根据视频的宽高比（大于高则锁定为横屏，大于宽则锁定为竖屏）自动请求锁定屏幕方向。
   - 对于宽高相等的视频，它会尝试锁定到当前屏幕方向，如果无法获取则默认为横屏。

2. **处理全屏状态变化:**
   - 监听 `fullscreenchange` 和 `webkitfullscreenchange` 事件，当视频进入全屏时尝试锁定屏幕方向，当退出全屏时解锁屏幕方向。

3. **处理视频元数据加载完成事件:**
   - 监听 `loadedmetadata` 事件，在视频元数据加载完成后，如果当前正准备进入全屏，则尝试锁定屏幕方向。这是为了确保在视频尺寸已知后才进行方向锁定。

4. **监听设备方向变化 (可选):**
   - 如果 `VideoRotateToFullscreenEnabled()` 特性启用，并且用户没有在操作系统层面锁定屏幕方向，则会监听 `deviceorientation` 事件。
   - 这允许在用户将设备旋转到与视频方向一致时，临时解锁屏幕方向，以便用户可以通过再次旋转设备退出全屏。

5. **延迟解锁机制:**
   - 在用户旋转设备到与视频方向一致时，会延迟一段时间再解锁屏幕方向。这是为了解决某些 Android 设备上屏幕方向变化检测的延迟问题，避免在用户旋转过程中屏幕方向反复横竖切换。

6. **与 Screen Orientation API 交互:**
   - 使用 `ScreenOrientationController` 来请求锁定和解锁屏幕方向。这是一个浏览器提供的 Web API，允许网页控制屏幕的显示方向。

**与 JavaScript, HTML, CSS 的关系:**

* **JavaScript:**
    - **事件监听:**  该 C++ 代码通过 Blink 引擎的事件系统监听 JavaScript 触发的 `fullscreenchange`、`webkitfullscreenchange`、`loadedmetadata` 和 `deviceorientation` 事件。
    - **Screen Orientation API:**  该代码内部使用了 Blink 引擎对 Screen Orientation API 的 C++ 实现。JavaScript 可以通过 `window.screen.orientation` 对象来访问和控制屏幕方向。
        ```javascript
        // JavaScript 可以请求锁定屏幕方向
        screen.orientation.lock('landscape');

        // 监听屏幕方向变化
        screen.orientation.addEventListener('change', () => {
          console.log('屏幕方向已更改为：', screen.orientation.type);
        });
        ```
    - **Fullscreen API:**  该代码响应 JavaScript 的 Fullscreen API 调用，例如 `videoElement.requestFullscreen()`。
        ```javascript
        const video = document.querySelector('video');
        video.requestFullscreen();

        document.addEventListener('fullscreenchange', () => {
          if (document.fullscreenElement) {
            console.log('进入全屏');
          } else {
            console.log('退出全屏');
          }
        });
        ```
    - **Device Orientation API:** 该代码利用 Device Orientation API 获取设备的物理方向信息。
        ```javascript
        window.addEventListener('deviceorientation', (event) => {
          console.log('Beta:', event.beta);
          console.log('Gamma:', event.gamma);
        });
        ```

* **HTML:**
    - **`<video>` 元素:** 该代码的核心是处理 `<video>` 元素的播放行为，特别是全屏播放。
    - **全屏状态:**  HTML 元素进入或退出全屏状态会触发 `fullscreenchange` 和 `webkitfullscreenchange` 事件，该 C++ 代码会监听这些事件。

* **CSS:**
    - **全屏样式:**  虽然该 C++ 代码不直接操作 CSS，但全屏状态的改变通常会触发浏览器对元素的 CSS 样式进行调整，例如使用 `:fullscreen` 伪类来应用特定的全屏样式。
        ```css
        video:fullscreen {
          /* 全屏时的样式 */
          width: 100%;
          height: 100%;
        }
        ```

**逻辑推理 (假设输入与输出):**

**假设输入 1:** 用户在一个竖屏的移动设备上，点击播放一个横向视频的“全屏”按钮。`RuntimeEnabledFeatures::VideoRotateToFullscreenEnabled()` 为 true，且用户未锁定设备方向。

**输出 1:**
1. `fullscreenchange` 事件触发。
2. `MediaControlsOrientationLockDelegate` 接收到事件。
3. `MaybeLockOrientation()` 被调用。
4. 检查视频元数据，如果已加载，则计算视频宽高比（宽 > 高，为横向）。
5. 调用 `ScreenOrientationController::lock(LANDSCAPE, ...)` 请求将屏幕锁定为横屏方向。
6. 开始监听 `deviceorientation` 事件。

**假设输入 2:** 用户在全屏播放横向视频时，将设备旋转到竖屏方向。

**输出 2:**
1. `deviceorientation` 事件不断触发。
2. `MediaControlsOrientationLockDelegate` 接收到事件。
3. `MaybeLockToAnyIfDeviceOrientationMatchesVideo()` 被调用。
4. `ComputeDeviceOrientation()` 计算出设备当前为竖屏方向。
5. 由于设备方向与视频方向不匹配，不执行任何操作。

**假设输入 3:** 用户在全屏播放横向视频时，将设备旋转到横屏方向。

**输出 3:**
1. `deviceorientation` 事件触发。
2. `MediaControlsOrientationLockDelegate` 接收到事件。
3. `MaybeLockToAnyIfDeviceOrientationMatchesVideo()` 被调用。
4. `ComputeDeviceOrientation()` 计算出设备当前为横屏方向。
5. 设备方向与视频方向匹配。
6. 延迟一段时间后，调用 `ChangeLockToAnyOrientation()`，请求将屏幕方向锁定更改为 `ANY`，允许自由旋转。

**假设输入 4:** 用户在全屏播放视频后，点击“退出全屏”按钮。

**输出 4:**
1. `fullscreenchange` 事件触发。
2. `MediaControlsOrientationLockDelegate` 接收到事件。
3. `MaybeUnlockOrientation()` 被调用。
4. 调用 `ScreenOrientationController::unlock()` 请求解锁屏幕方向。
5. 停止监听 `deviceorientation` 事件。

**用户或编程常见的使用错误:**

1. **在不支持全屏 API 的环境中尝试全屏:**  如果 JavaScript 代码尝试调用 `requestFullscreen()` 但浏览器或设备不支持，则不会触发 `fullscreenchange` 事件，导致该 C++ 代码不会执行任何方向锁定的逻辑。
2. **在视频元数据加载完成前进入全屏:** 虽然代码会监听 `loadedmetadata` 事件，但如果在视频元数据加载完成前就进入全屏，可能会导致方向锁定不及时或错误。开发者应该确保在视频信息可用后再进行全屏操作。
3. **用户操作系统层面锁定了屏幕方向:**  即使网页请求锁定方向，如果用户在操作系统层面锁定了屏幕方向，浏览器的请求也会被忽略。该代码在 Android 平台上会检测用户的系统设置，并相应地调整行为。
4. **不正确处理 `deviceorientation` 权限:**  访问设备方向信息需要用户授权。如果用户拒绝授权，`deviceorientation` 事件不会触发，依赖该事件的解锁逻辑将无法执行。开发者需要在 JavaScript 中正确处理权限请求和错误情况。
5. **误用 `webkitfullscreenchange` 事件:**  虽然 `webkitfullscreenchange` 仍然被监听，但它是一个带有浏览器引擎前缀的事件，应该优先使用标准的 `fullscreenchange` 事件。

**用户操作如何一步步的到达这里 (调试线索):**

假设用户在一个支持全屏 API 的浏览器中观看一个嵌入了 `<video>` 元素的网页。

1. **用户交互:** 用户点击视频播放器上的全屏按钮。
2. **JavaScript 调用:** 视频播放器的 JavaScript 代码通常会调用 `videoElement.requestFullscreen()` 方法来请求进入全屏模式。
3. **浏览器事件触发:** 浏览器接收到全屏请求，开始进入全屏模式，并触发 `fullscreenchange` 事件。
4. **Blink 引擎事件分发:** Blink 引擎的事件系统会将 `fullscreenchange` 事件分发到注册了该事件监听器的对象。
5. **`MediaControlsOrientationLockDelegate::Invoke()` 调用:**  `MediaControlsOrientationLockDelegate` 对象通过 `Attach()` 方法注册了对 `fullscreenchange` 事件的监听，因此其 `Invoke()` 方法会被调用。
6. **状态判断与逻辑执行:**  在 `Invoke()` 方法中，会判断事件类型，如果是 `fullscreenchange`，则会根据当前全屏状态和内部状态，调用 `MaybeLockOrientation()` 或 `MaybeUnlockOrientation()`。
7. **方向锁定/解锁操作:** `MaybeLockOrientation()` 会计算视频方向并调用 `ScreenOrientationController` 的 `lock()` 方法请求锁定屏幕方向。`MaybeUnlockOrientation()` 则会调用 `unlock()` 方法。
8. **设备方向监听 (如果启用):** 如果 `VideoRotateToFullscreenEnabled()` 为 true，并且是进入全屏，`MaybeLockOrientation()` 还会调用相关逻辑开始监听 `deviceorientation` 事件。

**作为调试线索:**

* **断点:** 在 `MediaControlsOrientationLockDelegate::Invoke()` 方法中设置断点，可以观察到 `fullscreenchange` 事件是否被正确触发以及何时触发。
* **状态跟踪:** 观察 `state_` 成员变量的值变化，可以了解方向锁定委托的内部状态流转。
* **日志输出:** 在关键的逻辑分支（例如计算视频方向、请求锁定/解锁）添加 `DLOG` 或 `DVLOG` 输出，可以帮助了解代码的执行路径和参数。
* **Screen Orientation API 调用跟踪:**  检查 `ScreenOrientationController` 的 `lock()` 和 `unlock()` 方法是否被调用，以及传入的参数是否正确。
* **Device Orientation 事件检查:**  如果启用了设备方向监听，可以在 `MaybeLockToAnyIfDeviceOrientationMatchesVideo()` 方法中设置断点，观察 `deviceorientation` 事件的数据。
* **Feature Flag 检查:** 确认 `RuntimeEnabledFeatures::VideoRotateToFullscreenEnabled()` 的值是否符合预期，这会影响设备方向监听的逻辑。

通过以上分析，可以深入理解 `media_controls_orientation_lock_delegate.cc` 文件的功能及其在 Chromium Blink 引擎中处理视频全屏方向锁定的作用。

Prompt: 
```
这是目录为blink/renderer/modules/media_controls/media_controls_orientation_lock_delegate.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/media_controls/media_controls_orientation_lock_delegate.h"

#include <memory>

#include "base/time/time.h"
#include "build/build_config.h"
#include "third_party/blink/public/common/thread_safe_browser_interface_broker_proxy.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/screen.h"
#include "third_party/blink/renderer/core/html/media/html_video_element.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/modules/device_orientation/device_orientation_data.h"
#include "third_party/blink/renderer/modules/device_orientation/device_orientation_event.h"
#include "third_party/blink/renderer/modules/screen_orientation/screen_orientation.h"
#include "third_party/blink/renderer/modules/screen_orientation/screen_orientation_controller.h"
#include "third_party/blink/renderer/modules/screen_orientation/screen_screen_orientation.h"
#include "third_party/blink/renderer/modules/screen_orientation/web_lock_orientation_callback.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/math_extras.h"
#include "ui/display/screen_info.h"

#if BUILDFLAG(IS_ANDROID)
#include "third_party/blink/public/platform/platform.h"
#endif  // BUILDFLAG(IS_ANDROID)

#undef atan2  // to use std::atan2 instead of wtf_atan2
#undef fmod   // to use std::fmod instead of wtf_fmod
#include <cmath>

namespace blink {

namespace {

// WebLockOrientationCallback implementation that will not react to a success
// nor a failure.
class DummyScreenOrientationCallback : public WebLockOrientationCallback {
 public:
  void OnSuccess() override {}
  void OnError(WebLockOrientationError) override {}
};

}  // anonymous namespace

constexpr base::TimeDelta MediaControlsOrientationLockDelegate::kLockToAnyDelay;

MediaControlsOrientationLockDelegate::MediaControlsOrientationLockDelegate(
    HTMLVideoElement& video)
    : monitor_(video.GetExecutionContext()), video_element_(video) {
  if (VideoElement().isConnected())
    Attach();
}

void MediaControlsOrientationLockDelegate::Attach() {
  DCHECK(VideoElement().isConnected());

  GetDocument().addEventListener(event_type_names::kFullscreenchange, this,
                                 true);
  VideoElement().addEventListener(event_type_names::kWebkitfullscreenchange,
                                  this, true);
  VideoElement().addEventListener(event_type_names::kLoadedmetadata, this,
                                  true);
}

void MediaControlsOrientationLockDelegate::Detach() {
  DCHECK(!VideoElement().isConnected());

  GetDocument().removeEventListener(event_type_names::kFullscreenchange, this,
                                    true);
  VideoElement().removeEventListener(event_type_names::kWebkitfullscreenchange,
                                     this, true);
  VideoElement().removeEventListener(event_type_names::kLoadedmetadata, this,
                                     true);
}

void MediaControlsOrientationLockDelegate::MaybeLockOrientation() {
  DCHECK(state_ != State::kMaybeLockedFullscreen);

  if (VideoElement().getReadyState() == HTMLMediaElement::kHaveNothing) {
    state_ = State::kPendingMetadata;
    return;
  }

  state_ = State::kMaybeLockedFullscreen;

  if (!GetDocument().domWindow())
    return;

  auto* controller =
      ScreenOrientationController::From(*GetDocument().domWindow());
  if (controller->MaybeHasActiveLock())
    return;

  locked_orientation_ = ComputeOrientationLock();
  DCHECK_NE(locked_orientation_,
            device::mojom::blink::ScreenOrientationLockType::DEFAULT);
  controller->lock(locked_orientation_,
                   std::make_unique<DummyScreenOrientationCallback>());

  MaybeListenToDeviceOrientation();
}

void MediaControlsOrientationLockDelegate::ChangeLockToAnyOrientation() {
  // Must already be locked.
  DCHECK_EQ(state_, State::kMaybeLockedFullscreen);
  DCHECK_NE(locked_orientation_,
            device::mojom::blink::ScreenOrientationLockType::DEFAULT);

  locked_orientation_ = device::mojom::blink::ScreenOrientationLockType::ANY;

  // The document could have been detached from the frame.
  if (LocalDOMWindow* window = GetDocument().domWindow()) {
    ScreenOrientationController::From(*window)->lock(
        locked_orientation_,
        std::make_unique<DummyScreenOrientationCallback>());
  }
}

void MediaControlsOrientationLockDelegate::MaybeUnlockOrientation() {
  DCHECK(state_ != State::kPendingFullscreen);

  state_ = State::kPendingFullscreen;

  if (locked_orientation_ ==
      device::mojom::blink::ScreenOrientationLockType::DEFAULT /* unlocked */)
    return;

  monitor_.reset();  // Cancel any GotIsAutoRotateEnabledByUser Mojo callback.
  LocalDOMWindow* dom_window = GetDocument().domWindow();
  dom_window->removeEventListener(event_type_names::kDeviceorientation, this,
                                  false);
  ScreenOrientationController::From(*dom_window)->unlock();
  locked_orientation_ =
      device::mojom::blink::ScreenOrientationLockType::DEFAULT /* unlocked */;

  lock_to_any_task_.Cancel();
}

void MediaControlsOrientationLockDelegate::MaybeListenToDeviceOrientation() {
  DCHECK_EQ(state_, State::kMaybeLockedFullscreen);
  DCHECK_NE(locked_orientation_,
            device::mojom::blink::ScreenOrientationLockType::DEFAULT);

  // If the rotate-to-fullscreen feature is also enabled, then start listening
  // to deviceorientation events so the orientation can be unlocked once the
  // user rotates the device to match the video's orientation (allowing the user
  // to then exit fullscreen by rotating their device back to the opposite
  // orientation). Otherwise, don't listen for deviceorientation events and just
  // hold the orientation lock until the user exits fullscreen (which prevents
  // the user rotating to the wrong fullscreen orientation).
  if (!RuntimeEnabledFeatures::VideoRotateToFullscreenEnabled())
    return;

  if (is_auto_rotate_enabled_by_user_override_for_testing_ != std::nullopt) {
    GotIsAutoRotateEnabledByUser(
        is_auto_rotate_enabled_by_user_override_for_testing_.value());
    return;
  }

// Check whether the user locked screen orientation at the OS level.
#if BUILDFLAG(IS_ANDROID)
  DCHECK(!monitor_.is_bound());
  Platform::Current()->GetBrowserInterfaceBroker()->GetInterface(
      monitor_.BindNewPipeAndPassReceiver(
          GetDocument().GetTaskRunner(TaskType::kMediaElementEvent)));
  monitor_->IsAutoRotateEnabledByUser(WTF::BindOnce(
      &MediaControlsOrientationLockDelegate::GotIsAutoRotateEnabledByUser,
      WrapPersistent(this)));
#else
  GotIsAutoRotateEnabledByUser(true);  // Assume always enabled on other OSes.
#endif  // BUILDFLAG(IS_ANDROID)
}

void MediaControlsOrientationLockDelegate::GotIsAutoRotateEnabledByUser(
    bool enabled) {
  monitor_.reset();

  if (!enabled) {
    // Since the user has locked their screen orientation, prevent
    // MediaControlsRotateToFullscreenDelegate from exiting fullscreen by not
    // listening for deviceorientation events and instead continuing to hold the
    // orientation lock until the user exits fullscreen. This enables users to
    // watch videos in bed with their head facing sideways (which requires a
    // landscape screen orientation when the device is portrait and vice versa).
    // TODO(johnme): Ideally we would start listening for deviceorientation
    // events and allow rotating to exit if a user enables screen auto rotation
    // after we have locked to landscape. That would require listening for
    // changes to the auto rotate setting, rather than only checking it once.
    return;
  }

  if (LocalDOMWindow* dom_window = GetDocument().domWindow()) {
    dom_window->addEventListener(event_type_names::kDeviceorientation, this,
                                 false);
  }
}

HTMLVideoElement& MediaControlsOrientationLockDelegate::VideoElement() const {
  return *video_element_;
}

Document& MediaControlsOrientationLockDelegate::GetDocument() const {
  return VideoElement().GetDocument();
}

void MediaControlsOrientationLockDelegate::Invoke(
    ExecutionContext* execution_context,
    Event* event) {
  if (event->type() == event_type_names::kFullscreenchange ||
      event->type() == event_type_names::kWebkitfullscreenchange) {
    if (VideoElement().IsFullscreen()) {
      if (state_ == State::kPendingFullscreen)
        MaybeLockOrientation();
    } else {
      if (state_ != State::kPendingFullscreen)
        MaybeUnlockOrientation();
    }

    return;
  }

  if (event->type() == event_type_names::kLoadedmetadata) {
    if (state_ == State::kPendingMetadata)
      MaybeLockOrientation();

    return;
  }

  if (event->type() == event_type_names::kDeviceorientation) {
    if (event->isTrusted() &&
        event->InterfaceName() ==
            event_interface_names::kDeviceOrientationEvent) {
      MaybeLockToAnyIfDeviceOrientationMatchesVideo(
          To<DeviceOrientationEvent>(event));
    }

    return;
  }

  NOTREACHED();
}

device::mojom::blink::ScreenOrientationLockType
MediaControlsOrientationLockDelegate::ComputeOrientationLock() const {
  DCHECK(VideoElement().getReadyState() != HTMLMediaElement::kHaveNothing);

  const unsigned width = VideoElement().videoWidth();
  const unsigned height = VideoElement().videoHeight();

  if (width > height)
    return device::mojom::blink::ScreenOrientationLockType::LANDSCAPE;

  if (height > width)
    return device::mojom::blink::ScreenOrientationLockType::PORTRAIT;

  // For square videos, try to lock to the current screen orientation for
  // consistency. Use device::mojom::blink::ScreenOrientationLockType::LANDSCAPE
  // as a fallback value.
  // TODO(mlamouri): we could improve this by having direct access to
  // `window.screen.orientation.type`.
  LocalFrame* frame = GetDocument().GetFrame();
  if (!frame)
    return device::mojom::blink::ScreenOrientationLockType::LANDSCAPE;

  ChromeClient& chrome_client = frame->GetChromeClient();
  switch (chrome_client.GetScreenInfo(*frame).orientation_type) {
    case display::mojom::blink::ScreenOrientation::kPortraitPrimary:
    case display::mojom::blink::ScreenOrientation::kPortraitSecondary:
      return device::mojom::blink::ScreenOrientationLockType::PORTRAIT;
    case display::mojom::blink::ScreenOrientation::kLandscapePrimary:
    case display::mojom::blink::ScreenOrientation::kLandscapeSecondary:
      return device::mojom::blink::ScreenOrientationLockType::LANDSCAPE;
    case display::mojom::blink::ScreenOrientation::kUndefined:
      return device::mojom::blink::ScreenOrientationLockType::LANDSCAPE;
  }

  NOTREACHED();
}

MediaControlsOrientationLockDelegate::DeviceOrientationType
MediaControlsOrientationLockDelegate::ComputeDeviceOrientation(
    DeviceOrientationData* data) const {
  LocalDOMWindow* dom_window = GetDocument().domWindow();
  if (!dom_window)
    return DeviceOrientationType::kUnknown;

  if (!data->CanProvideBeta() || !data->CanProvideGamma())
    return DeviceOrientationType::kUnknown;
  double beta = data->Beta();
  double gamma = data->Gamma();

  // Calculate the projection of the up vector (normal to the earth's surface)
  // onto the device's screen in its natural orientation. (x,y) will lie within
  // the unit circle centered on (0,0), e.g. if the top of the device is
  // pointing upwards (x,y) will be (0,-1).
  double x = -std::sin(Deg2rad(gamma)) * std::cos(Deg2rad(beta));
  double y = -std::sin(Deg2rad(beta));

  // Convert (x,y) to polar coordinates: 0 <= device_orientation_angle < 360 and
  // 0 <= r <= 1, such that device_orientation_angle is the clockwise angle in
  // degrees between the current physical orientation of the device and the
  // natural physical orientation of the device (ignoring the screen
  // orientation). Thus snapping device_orientation_angle to the nearest
  // multiple of 90 gives the value screen.orientation.angle would have if the
  // screen orientation was allowed to rotate freely to match the device
  // orientation. Note that we want device_orientation_angle==0 when the top of
  // the device is pointing upwards, but atan2's zero angle points to the right,
  // so we pass y=x and x=-y to atan2 to rotate by 90 degrees.
  double r = std::sqrt(x * x + y * y);
  double device_orientation_angle =
      std::fmod(Rad2deg(std::atan2(/* y= */ x, /* x= */ -y)) + 360, 360);

  // If angle between device's screen and the horizontal plane is less than
  // kMinElevationAngle (chosen to approximately match Android's behavior), then
  // device is too flat to reliably determine orientation.
  constexpr double kMinElevationAngle = 24;  // degrees from horizontal plane
  if (r < std::sin(Deg2rad(kMinElevationAngle)))
    return DeviceOrientationType::kFlat;

  // device_orientation_angle snapped to nearest multiple of 90.
  int device_orientation_angle90 =
      static_cast<int>(std::lround(device_orientation_angle / 90) * 90);

  // To be considered portrait or landscape, allow the device to be rotated 23
  // degrees (chosen to approximately match Android's behavior) to either side
  // of those orientations. In the remaining 90 - 2*23 = 44 degree hysteresis
  // zones, consider the device to be diagonal. These hysteresis zones prevent
  // the computed orientation from oscillating rapidly between portrait and
  // landscape when the device is in between the two orientations.
  if (std::abs(device_orientation_angle - device_orientation_angle90) > 23)
    return DeviceOrientationType::kDiagonal;

  // screen.orientation.angle is the standardized replacement for
  // window.orientation. They are equal, except -90 was replaced by 270.
  int screen_orientation_angle =
      ScreenScreenOrientation::orientation(*dom_window->screen())->angle();

  // This is equivalent to screen.orientation.type.startsWith('landscape').
  bool screen_orientation_is_portrait =
      dom_window->screen()->width() <= dom_window->screen()->height();

  // The natural orientation of the device could either be portrait (almost
  // all phones, and some tablets like Nexus 7) or landscape (other tablets
  // like Pixel C). Detect this by comparing angle to orientation.
  // TODO(johnme): This might get confused on square screens.
  bool screen_orientation_is_natural_or_flipped_natural =
      screen_orientation_angle % 180 == 0;
  bool natural_orientation_is_portrait =
      screen_orientation_is_portrait ==
      screen_orientation_is_natural_or_flipped_natural;

  // If natural_orientation_is_portrait_, then angles 0 and 180 are portrait,
  // otherwise angles 90 and 270 are portrait.
  int portrait_angle_mod_180 = natural_orientation_is_portrait ? 0 : 90;
  return device_orientation_angle90 % 180 == portrait_angle_mod_180
             ? DeviceOrientationType::kPortrait
             : DeviceOrientationType::kLandscape;
}

void MediaControlsOrientationLockDelegate::
    MaybeLockToAnyIfDeviceOrientationMatchesVideo(
        DeviceOrientationEvent* event) {
  DCHECK_EQ(state_, State::kMaybeLockedFullscreen);
  DCHECK(locked_orientation_ ==
             device::mojom::blink::ScreenOrientationLockType::PORTRAIT ||
         locked_orientation_ ==
             device::mojom::blink::ScreenOrientationLockType::LANDSCAPE);

  DeviceOrientationType device_orientation =
      ComputeDeviceOrientation(event->Orientation());

  DeviceOrientationType video_orientation =
      locked_orientation_ ==
              device::mojom::blink::ScreenOrientationLockType::PORTRAIT
          ? DeviceOrientationType::kPortrait
          : DeviceOrientationType::kLandscape;

  if (device_orientation != video_orientation)
    return;

  // Job done: the user rotated their device to match the orientation of the
  // video that we locked to, so now we can stop listening.
  if (LocalDOMWindow* dom_window = GetDocument().domWindow()) {
    dom_window->removeEventListener(event_type_names::kDeviceorientation, this,
                                    false);
  }
  // Delay before changing lock, as a workaround for the case where the device
  // is initially portrait-primary, then fullscreen orientation lock locks it to
  // landscape and the screen orientation changes to landscape-primary, but the
  // user actually rotates the device to landscape-secondary. In that case, if
  // this delegate unlocks the orientation before Android has detected the
  // rotation to landscape-secondary (which is slow due to low-pass filtering),
  // Android would change the screen orientation back to portrait-primary. This
  // is avoided by delaying unlocking long enough to ensure that Android has
  // detected the orientation change.
  lock_to_any_task_ = PostDelayedCancellableTask(
      *GetDocument().GetTaskRunner(TaskType::kMediaElementEvent), FROM_HERE,
      // Conceptually, this callback will unlock the screen orientation,
      // so that the user can now rotate their device to the opposite
      // orientation in order to exit fullscreen. But unlocking
      // corresponds to
      // device::mojom::blink::ScreenOrientationLockType::DEFAULT, which is
      // sometimes a specific orientation. For example in a webapp added to
      // homescreen that has set its orientation to portrait using the manifest,
      // unlocking actually locks to portrait, which would immediately exit
      // fullscreen if we're watching a landscape video in landscape
      // orientation! So instead, this locks to
      // device::mojom::blink::ScreenOrientationLockType::ANY which will
      // auto-rotate according to the accelerometer, and only exit
      // fullscreen once the user actually rotates their device. We only
      // fully unlock to
      // device::mojom::blink::ScreenOrientationLockType::DEFAULT once
      // fullscreen is exited.
      WTF::BindOnce(
          &MediaControlsOrientationLockDelegate::ChangeLockToAnyOrientation,
          WrapPersistent(this)),
      kLockToAnyDelay);
}

void MediaControlsOrientationLockDelegate::Trace(Visitor* visitor) const {
  NativeEventListener::Trace(visitor);
  visitor->Trace(monitor_);
  visitor->Trace(video_element_);
}

}  // namespace blink

"""

```