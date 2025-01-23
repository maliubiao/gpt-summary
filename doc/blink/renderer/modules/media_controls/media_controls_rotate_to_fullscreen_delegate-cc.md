Response:
Let's break down the thought process for analyzing this C++ file.

1. **Understand the Goal:** The request asks for the functionality of the file, its relation to web technologies (JavaScript, HTML, CSS), examples of logic, potential user errors, and debugging steps.

2. **Identify the Core Class:** The filename `media_controls_rotate_to_fullscreen_delegate.cc` and the code itself clearly point to the central class: `MediaControlsRotateToFullscreenDelegate`. This is the main focus of the analysis.

3. **Analyze the Class Purpose:** The name strongly suggests the class is responsible for handling the automatic switching to fullscreen when the device is rotated while a video is playing. The "delegate" suffix hints that this class assists another component (likely `MediaControlsImpl`).

4. **Examine Key Methods:**  Start with the constructor and destructor (implicitly through Attach/Detach). Then, look for methods triggered by events or state changes.

    * **Constructor (`MediaControlsRotateToFullscreenDelegate`):** Takes an `HTMLVideoElement` as input. This confirms its association with video elements.
    * **`Attach()`:** Sets up event listeners for `play`, `pause`, `fullscreenchange`, `webkitfullscreenchange`, `orientationchange`, and `deviceorientation`. This is where the logic begins.
    * **`Detach()`:** Removes the event listeners, cleaning up resources. It also handles disconnecting the `IntersectionObserver`.
    * **`Invoke()`:** The central event handler, dispatching based on the event type. This links directly to the event listeners set up in `Attach()`.
    * **`OnStateChange()`:**  Handles `play`, `pause`, and fullscreen changes. It manages the `IntersectionObserver` based on the video's playing state and fullscreen status. This is a crucial part for determining visibility.
    * **`OnIntersectionChange()`:**  Called by the `IntersectionObserver`. Updates the `is_visible_` flag based on the video's visibility.
    * **`OnDeviceOrientationAvailable()`:** Handles the `deviceorientation` event. Crucially, it checks if the device can provide beta and gamma values, which are needed for unlocking the orientation later.
    * **`OnScreenOrientationChange()`:** The core logic for handling screen rotation. This method contains many checks and conditions for deciding whether to enter or exit fullscreen.
    * **`ComputeVideoOrientation()`:** Determines if the video is landscape or portrait based on its dimensions.
    * **`ComputeScreenOrientation()`:**  Gets the current screen orientation.

5. **Trace the Logic Flow (Mental Simulation):** Imagine a user playing a video and rotating their device. Follow the likely sequence of events:

    * Video starts playing (`kPlay` event). `OnStateChange` sets up the `IntersectionObserver`.
    * The `IntersectionObserver` reports the video is visible (`OnIntersectionChange`).
    * The device is rotated (`orientationchange` event). `OnScreenOrientationChange` is called.
    * `OnScreenOrientationChange` checks video state, visibility, orientation, and decides whether to toggle fullscreen.

6. **Identify Connections to Web Technologies:**

    * **HTML:**  The code directly interacts with `HTMLVideoElement`. The automatic fullscreen behavior is a feature that modifies how the video is displayed in the HTML document. The `controlsList` attribute is also checked.
    * **JavaScript:**  JavaScript events (`play`, `pause`, `fullscreenchange`, `orientationchange`, `deviceorientation`) are the triggers for the C++ logic. The `IntersectionObserver` is a JavaScript API whose functionality is implemented here. The fullscreen API itself is often controlled via JavaScript.
    * **CSS:** While not directly manipulating CSS, the act of entering and exiting fullscreen significantly changes the visual layout, often involving CSS rules for the fullscreen element.

7. **Construct Examples:**  Based on the code analysis, create concrete examples for each connection:

    * **JavaScript:**  Show how JavaScript can trigger play/pause, enter/exit fullscreen, and how the `deviceorientation` event is dispatched.
    * **HTML:** Demonstrate the `controlsList` attribute and the basic `<video>` tag.
    * **CSS:** Mention how CSS handles fullscreen styling.

8. **Infer Logical Reasoning and Create Input/Output Examples:**

    * **Assumption:** The core logic is to match video orientation to screen orientation.
    * **Input:** Video playing, visible, device rotated to landscape matching video.
    * **Output:** Video enters fullscreen.
    * **Input:** Video playing, visible, in landscape fullscreen, device rotated to portrait.
    * **Output:** Video exits fullscreen.

9. **Pinpoint Potential User/Programming Errors:**

    * **User:** Disabling controls, playing inline.
    * **Programming:** Not handling permissions, incorrect event listeners.

10. **Outline Debugging Steps:**  Think about how a developer would investigate issues with this feature.

    * Breakpoints in key methods.
    * Logging relevant variables.
    * Checking event listeners.
    * Simulating device rotation.

11. **Structure the Answer:** Organize the findings logically, starting with the core functionality and then addressing the other points in the request. Use clear headings and bullet points for readability.

12. **Review and Refine:** Read through the generated answer to ensure accuracy, clarity, and completeness. Check for any logical inconsistencies or missing information. For instance, double-check the conditions for entering/exiting fullscreen in `OnScreenOrientationChange`.

This iterative process of code analysis, mental simulation, and connecting the code to broader concepts allows for a comprehensive understanding and the generation of a detailed and helpful answer.
这个C++源代码文件 `media_controls_rotate_to_fullscreen_delegate.cc` 的主要功能是**实现视频在移动设备上，当用户旋转屏幕时自动进入或退出全屏模式的逻辑**。 它作为 Chromium Blink 渲染引擎中媒体控制模块的一部分，专门处理视频元素的全屏切换行为，以提升移动设备上的用户体验。

更具体地说，它做了以下几件事：

**核心功能:**

1. **监听关键事件:**
   - **`play` 和 `pause` 事件:**  当视频开始播放或暂停时，会触发相应的逻辑。
   - **`fullscreenchange` 和 `webkitfullscreenchange` 事件:** 监听浏览器原生全屏事件，以跟踪视频是否已进入或退出全屏。
   - **`orientationchange` 事件:**  当设备的屏幕方向发生变化时触发。
   - **`deviceorientation` 事件:** 提供设备的物理方向信息，用于判断设备是横向还是纵向。

2. **使用 Intersection Observer 判断视频可见性:**
   - 当视频开始播放但未进入全屏时，它会创建一个 `IntersectionObserver` 来监听视频元素是否在视口中可见，并且可见比例是否超过一定的阈值 (`kIntersectionThreshold`，默认为 0.75)。
   - 只有当视频可见时，旋转屏幕自动全屏的功能才会生效。

3. **根据设备方向和视频方向自动切换全屏:**
   - 当 `orientationchange` 事件触发时，它会比较当前的屏幕方向和视频的固有方向（横向或纵向）。
   - 如果当前屏幕方向与视频方向一致，并且视频可见且正在播放，则会尝试进入全屏。
   - 如果当前屏幕方向与视频方向不一致，且视频当前处于全屏状态，则会尝试退出全屏。

4. **处理设备方向 API 的支持情况:**
   - 它会监听 `deviceorientation` 事件，并检查设备是否支持提供 `beta` 和 `gamma` 值。这些值对于 `MediaControlsOrientationLockDelegate` 在旋转回原始方向时自动解锁屏幕方向和退出全屏非常重要。

5. **考虑各种限制条件:**
   - **画中画模式:** 如果视频处于画中画模式，则不启用自动旋转全屏功能。
   - **自定义媒体控件:** 只有在使用浏览器原生媒体控件时才启用此功能。
   - **`controlsList="nofullscreen"`:** 如果视频元素的 `controlsList` 属性包含了 `nofullscreen`，则不启用此功能。
   - **其他元素已全屏:** 如果页面上的其他元素已经进入全屏，则不进行自动全屏操作。
   - **视频尺寸限制:** 只有当视频的宽度和高度都大于等于 `kMinVideoSize` (200像素) 时才启用此功能。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **JavaScript:**
    - **事件监听:**  该 C++ 文件通过 `addEventListener` 监听了 HTML 元素 (`HTMLVideoElement` 和 `Document`) 上的 JavaScript 事件，例如 `play`, `pause`, `fullscreenchange`, `orientationchange`, `deviceorientation`。 这些事件是由 JavaScript 在浏览器中触发的。
    - **Intersection Observer API:**  该文件使用了 Intersection Observer API，这是一个 JavaScript API，用于异步监听目标元素与其祖先元素或 viewport 交叉情况的变化。
    - **调用 Media Controls 的方法:**  当需要进入或退出全屏时，它会调用 `MediaControlsImpl` 提供的 `EnterFullscreen()` 和 `ExitFullscreen()` 方法，这些方法最终可能会涉及到 JavaScript 的全屏 API 调用。
    - **用户操作触发:** 用户在页面上与视频元素进行交互（例如点击播放按钮），或者旋转设备，这些操作都会触发 JavaScript 事件，进而触发此 C++ 文件中的逻辑。

    **举例:**
    ```html
    <video id="myVideo" controls width="640" height="360" src="myvideo.mp4"></video>
    <script>
      const video = document.getElementById('myVideo');
      video.play(); // JavaScript 触发 'play' 事件
    </script>
    ```
    当上述 JavaScript 代码执行 `video.play()` 时，`MediaControlsRotateToFullscreenDelegate` 会监听到 `play` 事件，并开始判断是否需要启用自动旋转全屏功能。

* **HTML:**
    - **`HTMLVideoElement`:**  这个 C++ 文件直接操作 `HTMLVideoElement` 对象，获取视频的属性（例如 `paused`, `IsFullscreen`, `videoWidth`, `videoHeight`, `controlsList`），并监听其事件。
    - **`<video>` 标签属性:**  HTML 中 `<video>` 标签的属性，例如 `controls`, `width`, `height`, `controlsList` 等，会影响该 C++ 文件的行为。例如，如果 `controls` 属性不存在，则不会使用原生媒体控件，自动旋转全屏功能可能不会生效。如果设置了 `controlsList="nofullscreen"`，则会明确禁用全屏功能，自动旋转全屏也会被阻止。

    **举例:**
    ```html
    <video controls width="480" height="640" src="vertical_video.mp4"></video>
    ```
    如果 `vertical_video.mp4` 是一个纵向视频，并且用户在支持自动旋转全屏的移动设备上横屏观看，`MediaControlsRotateToFullscreenDelegate` 会检测到屏幕方向与视频方向不一致，可能会触发退出全屏的操作（如果当前处于全屏）。

* **CSS:**
    - **全屏样式:** 虽然该 C++ 文件不直接操作 CSS，但进入和退出全屏会触发浏览器的全屏 API，这通常会涉及到应用一些默认的全屏 CSS 样式，或者开发者自定义的全屏样式。
    - **影响布局:** 进入全屏会改变视频元素的显示方式和页面布局，这与 CSS 的渲染密切相关。

    **举例:**
    开发者可能会使用 CSS 来定制全屏状态下视频控件的样式：
    ```css
    video:-webkit-full-screen {
      background-color: black;
    }
    video:-moz-full-screen {
      background-color: black;
    }
    video:full-screen {
      background-color: black;
    }
    ```
    当 `MediaControlsRotateToFullscreenDelegate` 调用 `EnterFullscreen()` 使视频进入全屏时，这些 CSS 规则会被应用。

**逻辑推理的假设输入与输出:**

**假设输入:**

1. **场景 1:**
   - 用户在移动设备上打开一个包含竖屏视频的网页。
   - 视频正在播放，并且在视口中可见（Intersection Ratio > 0.75）。
   - 设备当前为竖屏方向。
   - 用户将设备旋转到横屏方向。

   **输出:** 视频进入全屏模式。

2. **场景 2:**
   - 用户正在横屏全屏观看一个横屏视频。
   - 用户将设备旋转回竖屏方向。

   **输出:** 视频退出全屏模式。

3. **场景 3:**
   - 用户在移动设备上打开一个包含横屏视频的网页。
   - 视频正在播放，但只有一部分在视口中可见 (Intersection Ratio < 0.75)。
   - 用户将设备旋转到横屏方向。

   **输出:** 视频不会进入全屏模式，因为视频不可见或可见比例不足。

4. **场景 4:**
   - 用户正在播放一个视频，但该视频的 HTML 标签设置了 `controlsList="nofullscreen"`。
   - 用户旋转设备。

   **输出:** 视频不会进入或退出全屏模式，因为全屏功能被禁用。

**用户或编程常见的使用错误:**

1. **用户错误:**
   - **禁用了浏览器对设备方向的权限:** 如果用户禁用了网站访问设备方向信息的权限，`orientationchange` 和 `deviceorientation` 事件不会触发，自动旋转全屏功能将无法工作。
   - **误操作导致频繁旋转:** 用户可能无意中频繁旋转设备，导致视频频繁地进入和退出全屏，这可能会带来不好的用户体验。

2. **编程错误:**
   - **错误的 Intersection Threshold 设置:**  如果 `kIntersectionThreshold` 设置得过高，即使视频大部分可见，也可能因为达不到阈值而无法触发自动全屏。
   - **没有正确处理全屏事件:**  如果相关的全屏事件处理逻辑存在错误，可能导致进入或退出全屏的状态与预期不符。
   - **假设所有设备都支持 Device Orientation API:** 代码中检查了设备是否支持提供 `beta` 和 `gamma` 值，但如果没有充分考虑各种设备的兼容性问题，可能会在某些设备上出现异常行为。
   - **在不应该启用时启用了功能:** 例如，在桌面环境下或在画中画模式下，如果错误地触发了自动旋转全屏的逻辑，会导致不期望的行为。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设用户在移动设备上观看一个视频，并观察到旋转屏幕时视频自动进入或退出全屏的行为，以下是可能的操作步骤和调试线索：

1. **用户打开网页并加载包含 `<video>` 元素的页面。**
   - **调试线索:** 检查网络请求，确认视频资源已成功加载。查看 `<video>` 元素的属性，确认 `controls` 属性存在，且 `controlsList` 没有包含 `nofullscreen`。

2. **用户点击视频的播放按钮开始播放视频。**
   - **调试线索:**  在浏览器的开发者工具中监听 `play` 事件是否被触发。在 `MediaControlsRotateToFullscreenDelegate::Attach()` 方法中设置断点，确认事件监听器已成功注册。

3. **当视频开始播放，并且视频在视口中可见时，`MediaControlsRotateToFullscreenDelegate` 会创建并启动 `IntersectionObserver`。**
   - **调试线索:** 在 `MediaControlsRotateToFullscreenDelegate::OnStateChange()` 方法中检查 `intersection_observer_` 是否被创建。可以通过 Intersection Observer API 的调试工具查看其状态。

4. **用户旋转移动设备，例如从竖屏旋转到横屏。**
   - **调试线索:** 浏览器的开发者工具中的 "Sensors" 面板可以模拟设备旋转，触发 `orientationchange` 和 `deviceorientation` 事件。在 `MediaControlsRotateToFullscreenDelegate::Invoke()` 方法中，检查是否接收到了这些事件。

5. **`MediaControlsRotateToFullscreenDelegate::OnScreenOrientationChange()` 方法被调用。**
   - **调试线索:** 在此方法中设置断点，查看 `previous_screen_orientation_` 和 `current_screen_orientation_` 的值，确认屏幕方向已发生改变。

6. **在该方法中，会进行一系列的条件判断，例如视频是否正在播放、是否可见、是否设置了 `controlsList="nofullscreen"` 等。**
   - **调试线索:** 逐步调试，检查每个条件判断的结果，确认是否符合进入或退出全屏的条件。

7. **如果条件满足，并且当前屏幕方向与视频方向一致，`MediaControlsRotateToFullscreenDelegate` 会调用 `media_controls.EnterFullscreen()`。**
   - **调试线索:**  在 `MediaControlsImpl::EnterFullscreen()` 方法中设置断点，确认全屏请求已发出。监听 `fullscreenchange` 事件，查看视频元素是否进入全屏状态。

8. **如果条件满足，并且当前屏幕方向与视频方向不一致，且视频当前处于全屏状态，`MediaControlsRotateToFullscreenDelegate` 会调用 `media_controls.ExitFullscreen()`。**
   - **调试线索:** 在 `MediaControlsImpl::ExitFullscreen()` 方法中设置断点，确认退出全屏请求已发出。监听 `fullscreenchange` 事件，查看视频元素是否退出全屏状态。

通过以上步骤，可以逐步追踪用户操作如何触发相关的代码逻辑，并使用调试工具和断点来定位问题。 重点关注事件监听、条件判断以及状态变化，可以有效地诊断自动旋转全屏功能是否按预期工作。

### 提示词
```
这是目录为blink/renderer/modules/media_controls/media_controls_rotate_to_fullscreen_delegate.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/media_controls/media_controls_rotate_to_fullscreen_delegate.h"

#include "third_party/blink/public/mojom/frame/user_activation_notification_type.mojom-blink.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/user_metrics_action.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/fullscreen/fullscreen.h"
#include "third_party/blink/renderer/core/html/media/html_media_element_controls_list.h"
#include "third_party/blink/renderer/core/html/media/html_video_element.h"
#include "third_party/blink/renderer/core/intersection_observer/intersection_observer.h"
#include "third_party/blink/renderer/core/intersection_observer/intersection_observer_entry.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/modules/device_orientation/device_orientation_data.h"
#include "third_party/blink/renderer/modules/device_orientation/device_orientation_event.h"
#include "third_party/blink/renderer/modules/media_controls/media_controls_impl.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "ui/display/mojom/screen_orientation.mojom-blink.h"
#include "ui/display/screen_info.h"

namespace blink {

namespace {

// Videos must be at least this big in both dimensions to qualify.
constexpr unsigned kMinVideoSize = 200;

// At least this fraction of the video must be visible.
constexpr float kIntersectionThreshold = 0.75;

}  // anonymous namespace

MediaControlsRotateToFullscreenDelegate::
    MediaControlsRotateToFullscreenDelegate(HTMLVideoElement& video)
    : video_element_(video) {}

void MediaControlsRotateToFullscreenDelegate::Attach() {
  DCHECK(video_element_->isConnected());

  LocalDOMWindow* dom_window = video_element_->GetDocument().domWindow();
  if (!dom_window)
    return;

  video_element_->addEventListener(event_type_names::kPlay, this, true);
  video_element_->addEventListener(event_type_names::kPause, this, true);

  // Listen to two different fullscreen events in order to make sure the new and
  // old APIs are handled.
  video_element_->addEventListener(event_type_names::kWebkitfullscreenchange,
                                   this, true);
  video_element_->GetDocument().addEventListener(
      event_type_names::kFullscreenchange, this, true);

  current_screen_orientation_ = ComputeScreenOrientation();
  // TODO(johnme): Check this is battery efficient (note that this doesn't need
  // to receive events for 180 deg rotations).
  dom_window->addEventListener(event_type_names::kOrientationchange, this,
                               false);
  dom_window->addEventListener(event_type_names::kDeviceorientation, this,
                               false);
}

void MediaControlsRotateToFullscreenDelegate::Detach() {
  DCHECK(!video_element_->isConnected());

  if (intersection_observer_) {
    // TODO(johnme): Should I also call disconnect in a prefinalizer?
    intersection_observer_->disconnect();
    intersection_observer_ = nullptr;
    is_visible_ = false;
  }

  video_element_->removeEventListener(event_type_names::kPlay, this, true);
  video_element_->removeEventListener(event_type_names::kPause, this, true);

  video_element_->removeEventListener(event_type_names::kWebkitfullscreenchange,
                                      this, true);
  video_element_->GetDocument().removeEventListener(
      event_type_names::kFullscreenchange, this, true);

  LocalDOMWindow* dom_window = video_element_->GetDocument().domWindow();
  if (!dom_window)
    return;
  dom_window->removeEventListener(event_type_names::kOrientationchange, this,
                                  false);
  dom_window->removeEventListener(event_type_names::kDeviceorientation, this,
                                  false);
}

void MediaControlsRotateToFullscreenDelegate::Invoke(
    ExecutionContext* execution_context,
    Event* event) {
  if (event->type() == event_type_names::kPlay ||
      event->type() == event_type_names::kPause ||
      event->type() == event_type_names::kFullscreenchange ||
      event->type() == event_type_names::kWebkitfullscreenchange) {
    OnStateChange();
    return;
  }
  if (event->type() == event_type_names::kDeviceorientation) {
    if (event->isTrusted() &&
        event->InterfaceName() ==
            event_interface_names::kDeviceOrientationEvent) {
      OnDeviceOrientationAvailable(To<DeviceOrientationEvent>(event));
    }
    return;
  }
  if (event->type() == event_type_names::kOrientationchange) {
    OnScreenOrientationChange();
    return;
  }

  NOTREACHED();
}

void MediaControlsRotateToFullscreenDelegate::OnStateChange() {
  // TODO(johnme): Check this aggressive disabling doesn't lead to race
  // conditions where we briefly don't know if the video is visible.
  bool needs_intersection_observer =
      !video_element_->paused() && !video_element_->IsFullscreen();
  DVLOG(3) << __func__ << " " << !!intersection_observer_ << " -> "
           << needs_intersection_observer;

  if (needs_intersection_observer && !intersection_observer_) {
    intersection_observer_ = IntersectionObserver::Create(
        video_element_->GetDocument(),
        WTF::BindRepeating(
            &MediaControlsRotateToFullscreenDelegate::OnIntersectionChange,
            WrapWeakPersistent(this)),
        LocalFrameUkmAggregator::kMediaIntersectionObserver,
        IntersectionObserver::Params{.thresholds = {kIntersectionThreshold}});
    intersection_observer_->observe(video_element_);
  } else if (!needs_intersection_observer && intersection_observer_) {
    intersection_observer_->disconnect();
    intersection_observer_ = nullptr;
    is_visible_ = false;
  }
}

void MediaControlsRotateToFullscreenDelegate::OnIntersectionChange(
    const HeapVector<Member<IntersectionObserverEntry>>& entries) {
  bool is_visible =
      (entries.back()->intersectionRatio() > kIntersectionThreshold);
  DVLOG(3) << __func__ << " " << is_visible_ << " -> " << is_visible;
  is_visible_ = is_visible;
}

void MediaControlsRotateToFullscreenDelegate::OnDeviceOrientationAvailable(
    DeviceOrientationEvent* event) {
  LocalDOMWindow* dom_window = video_element_->GetDocument().domWindow();
  if (!dom_window)
    return;
  // Stop listening after the first event. Just need to know if it's available.
  dom_window->removeEventListener(event_type_names::kDeviceorientation, this,
                                  false);

  // MediaControlsOrientationLockDelegate needs Device Orientation events with
  // beta and gamma in order to unlock screen orientation and exit fullscreen
  // when the device is rotated. Some devices cannot provide beta and/or gamma
  // values and must be excluded. Unfortunately, some other devices incorrectly
  // return true for both CanProvideBeta() and CanProvideGamma() but their
  // Beta() and Gamma() values are permanently stuck on zero (crbug/760737); so
  // we have to also exclude devices where both of these values are exactly
  // zero, even though that's a valid (albeit unlikely) device orientation.
  DeviceOrientationData* data = event->Orientation();
  device_orientation_supported_ =
      std::make_optional(data->CanProvideBeta() && data->CanProvideGamma() &&
                         (data->Beta() != 0.0 || data->Gamma() != 0.0));
}

void MediaControlsRotateToFullscreenDelegate::OnScreenOrientationChange() {
  SimpleOrientation previous_screen_orientation = current_screen_orientation_;
  current_screen_orientation_ = ComputeScreenOrientation();
  DVLOG(3) << __func__ << " " << static_cast<int>(previous_screen_orientation)
           << " -> " << static_cast<int>(current_screen_orientation_);

  // Do not enable if video is in Picture-in-Picture.
  if (video_element_->GetDisplayType() == DisplayType::kPictureInPicture)
    return;

  // Only enable if native media controls are used.
  if (!video_element_->ShouldShowControls())
    return;

  // Do not enable if controlsList=nofullscreen is used.
  if (video_element_->ControlsListInternal()->ShouldHideFullscreen())
    return;

  // Only enable if the Device Orientation API can provide beta and gamma values
  // that will be needed for MediaControlsOrientationLockDelegate to
  // automatically unlock, such that it will be possible to exit fullscreen by
  // rotating back to the previous orientation.
  if (!device_orientation_supported_.value_or(false))
    return;

  // Don't enter/exit fullscreen if some other element is fullscreen.
  Element* fullscreen_element =
      Fullscreen::FullscreenElementFrom(video_element_->GetDocument());
  if (fullscreen_element && fullscreen_element != video_element_)
    return;

  // To enter fullscreen, video must be visible and playing.
  // TODO(johnme): If orientation changes whilst this tab is in the background,
  // we'll get an orientationchange event when this tab next becomes active.
  // Check that those events don't trigger rotate-to-fullscreen.
  if (!video_element_->IsFullscreen() &&
      (!is_visible_ || video_element_->paused())) {
    return;
  }

  // Ignore (unexpected) events where we have incomplete information.
  if (previous_screen_orientation == SimpleOrientation::kUnknown ||
      current_screen_orientation_ == SimpleOrientation::kUnknown) {
    return;
  }

  // Ignore 180 degree rotations between PortraitPrimary and PortraitSecondary,
  // or between LandscapePrimary and LandscapeSecondary.
  if (previous_screen_orientation == current_screen_orientation_)
    return;

  SimpleOrientation video_orientation = ComputeVideoOrientation();

  // Ignore videos that are too small or of unknown size.
  if (video_orientation == SimpleOrientation::kUnknown)
    return;

  MediaControlsImpl& media_controls =
      *static_cast<MediaControlsImpl*>(video_element_->GetMediaControls());

  {
    LocalFrame::NotifyUserActivation(
        video_element_->GetDocument().GetFrame(),
        mojom::blink::UserActivationNotificationType::kInteraction);

    bool should_be_fullscreen =
        current_screen_orientation_ == video_orientation;
    if (should_be_fullscreen && !video_element_->IsFullscreen()) {
      Platform::Current()->RecordAction(
          UserMetricsAction("Media.Video.RotateToFullscreen.Enter"));
      media_controls.EnterFullscreen();
    } else if (!should_be_fullscreen && video_element_->IsFullscreen()) {
      Platform::Current()->RecordAction(
          UserMetricsAction("Media.Video.RotateToFullscreen.Exit"));
      media_controls.ExitFullscreen();
    }
  }
}

MediaControlsRotateToFullscreenDelegate::SimpleOrientation
MediaControlsRotateToFullscreenDelegate::ComputeVideoOrientation() const {
  if (video_element_->getReadyState() == HTMLMediaElement::kHaveNothing)
    return SimpleOrientation::kUnknown;

  const unsigned width = video_element_->videoWidth();
  const unsigned height = video_element_->videoHeight();

  if (width < kMinVideoSize || height < kMinVideoSize)
    return SimpleOrientation::kUnknown;  // Too small, ignore this video.

  if (width >= height)
    return SimpleOrientation::kLandscape;  // Includes square videos.
  return SimpleOrientation::kPortrait;
}

MediaControlsRotateToFullscreenDelegate::SimpleOrientation
MediaControlsRotateToFullscreenDelegate::ComputeScreenOrientation() const {
  LocalFrame* frame = video_element_->GetDocument().GetFrame();
  if (!frame)
    return SimpleOrientation::kUnknown;

  ChromeClient& chrome_client = frame->GetChromeClient();
  const display::ScreenInfo& screen_info = chrome_client.GetScreenInfo(*frame);
  switch (screen_info.orientation_type) {
    case display::mojom::blink::ScreenOrientation::kPortraitPrimary:
    case display::mojom::blink::ScreenOrientation::kPortraitSecondary:
      return SimpleOrientation::kPortrait;
    case display::mojom::blink::ScreenOrientation::kLandscapePrimary:
    case display::mojom::blink::ScreenOrientation::kLandscapeSecondary:
      return SimpleOrientation::kLandscape;
    case display::mojom::blink::ScreenOrientation::kUndefined:
      return SimpleOrientation::kUnknown;
  }

  NOTREACHED();
}

void MediaControlsRotateToFullscreenDelegate::Trace(Visitor* visitor) const {
  NativeEventListener::Trace(visitor);
  visitor->Trace(video_element_);
  visitor->Trace(intersection_observer_);
}

}  // namespace blink
```