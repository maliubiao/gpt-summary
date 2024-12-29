Response:
Let's break down the thought process for analyzing the given C++ test file.

**1. Understanding the Goal:**

The primary goal is to understand the *purpose* of the C++ file `media_controls_rotate_to_fullscreen_delegate_test.cc` within the Chromium Blink rendering engine. This involves identifying its functionalities, its relationships with web technologies (JavaScript, HTML, CSS), how it handles different scenarios, and its role in debugging.

**2. Initial Scan and Identification of Key Components:**

The first step is a quick read-through to identify the major elements and keywords:

* **Includes:**  Headers like `media_controls_rotate_to_fullscreen_delegate.h`,  `gtest/gtest.h`, and various `blink` and `mojo` headers immediately indicate this is a unit test file for a specific delegate related to media controls and fullscreen behavior. The inclusion of `HTMLVideoElement` and `HTMLAudioElement` hints at testing media element interactions. Headers related to `ScreenOrientation` are crucial.
* **Namespaces:** The `blink` namespace is a clear indicator of Blink engine code.
* **Test Fixture:**  `MediaControlsRotateToFullscreenDelegateTest` inheriting from `PageTestBase` strongly suggests this is an integration test simulating web page scenarios. The private inheritance of `ScopedVideoFullscreenOrientationLockForTest` and `ScopedVideoRotateToFullscreenForTest` indicates feature flag control for testing.
* **Mock Classes:** The presence of `MockVideoWebMediaPlayer` and `MockChromeClient` tells us the tests are using mock objects to control and verify interactions with external components.
* **`TEST_F` Macros:** These are the core test cases, and their names (e.g., `DelegateRequiresFlag`, `ComputeVideoOrientation`, `EnterSuccessPortraitToLandscape`) provide valuable clues about the features being tested.
* **Assertions:**  `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_EQ` are standard Google Test assertions, showing the expected outcomes of the tests.
* **Methods like `InitScreenAndVideo`, `PlayVideo`, `RotateTo`:** These are helper functions to set up test scenarios.

**3. Deeper Dive into Functionality:**

Now, let's examine the purpose of the main class and its methods:

* **`MediaControlsRotateToFullscreenDelegate`:** The name itself suggests its responsibility is managing the transition to fullscreen triggered by device rotation, specifically within the media controls context.
* **`ComputeVideoOrientation()`:**  This clearly determines if a video is considered landscape or portrait based on its dimensions.
* **The various `EnterSuccess...` and `EnterFail...` test cases:** These systematically test the conditions under which the video should or should not enter fullscreen when the screen is rotated. The naming convention is very helpful.
* **The `ExitSuccess...` and `ExitFail...` test cases:**  These cover the scenarios for exiting fullscreen upon rotation.
* **Visibility Observation:**  The tests involving `IsObservingVisibility()` and `ObservedVisibility()` highlight the delegate's dependency on the video's visibility.

**4. Connecting to Web Technologies (JavaScript, HTML, CSS):**

Based on the included headers and test scenarios, we can establish these connections:

* **HTML:** The tests directly manipulate `HTMLVideoElement` and its attributes (`controls`, `controlslist`). The setup involves appending the video element to the document body.
* **JavaScript:** While the *test* is in C++, the *feature being tested* is triggered by browser behavior that is often initiated or influenced by JavaScript. The tests simulate user activation (`LocalFrame::NotifyUserActivation`), which is a JavaScript concept. The fullscreen API itself is accessible via JavaScript.
* **CSS:** The test `EnterFailHidden` manipulates CSS (`style()->setProperty`) to simulate the video being off-screen, demonstrating the delegate's sensitivity to CSS-driven visibility changes.

**5. Logical Reasoning and Scenarios:**

The test cases themselves represent logical reasoning and cover various scenarios:

* **Input:** Initial screen orientation, video dimensions, whether the video is playing, visibility, device orientation support, and whether other elements are in fullscreen.
* **Output:** Whether the video enters or exits fullscreen.

The tests explore edge cases and different combinations of these inputs. For example, the "EnterFail" tests demonstrate conditions that prevent the automatic rotation to fullscreen.

**6. Identifying Common Usage Errors:**

By analyzing the "EnterFail" scenarios, we can deduce potential user or programming errors:

* **Assuming rotation to fullscreen always works:** The tests highlight that factors like `controlslist="nofullscreen"`, being in Picture-in-Picture, or the video being hidden can prevent this behavior.
* **Not considering device orientation support:** The tests show that the feature relies on device orientation data.

**7. Debugging Clues and User Actions:**

The tests offer debugging clues by isolating specific conditions. Understanding the test setup helps trace user actions:

* **User plays a video on a mobile device.**
* **The device's screen orientation is different from the video's aspect ratio.**
* **The user rotates the device.**
* **The browser checks if the conditions for automatic fullscreen are met (as tested in this file).**

If a user reports unexpected fullscreen behavior on rotation, examining these test cases can provide insights into which conditions might be causing the issue. For instance, if rotation to fullscreen isn't happening, checking if `controlslist="nofullscreen"` is set or if the video is hidden might be a starting point.

**8. Iterative Refinement:**

Throughout the analysis, it's essential to revisit and refine understanding. For example, initially, I might just see "screen orientation." But then, digging deeper, I'd realize the tests differentiate between different screen orientation *types* (primary, secondary, portrait, landscape) and also consider device orientation events.

By following these steps, we can systematically deconstruct the C++ test file and gain a comprehensive understanding of its purpose and its relevance to the broader web development context.
这个C++文件 `media_controls_rotate_to_fullscreen_delegate_test.cc` 是 Chromium Blink 引擎中的一个单元测试文件。它的主要功能是 **测试 `MediaControlsRotateToFullscreenDelegate` 类的行为和逻辑**。这个 delegate 负责处理当用户在移动设备上播放视频时旋转屏幕，自动将视频切换到全屏模式的逻辑。

更具体地说，这个测试文件旨在验证以下方面：

**1. 核心功能测试:**

*   **根据屏幕旋转进入全屏:**  测试当设备从竖屏旋转到横屏（或反之），且视频的宽高比与旋转后的屏幕方向匹配时，delegate 是否能够正确触发视频进入全屏。
*   **根据屏幕旋转退出全屏:** 测试当视频处于全屏状态，设备旋转到与视频宽高比不匹配的方向时，delegate 是否能够正确触发视频退出全屏。
*   **不同视频宽高比的处理:** 测试 delegate 如何处理横屏视频、竖屏视频以及宽高相近（正方形）的视频在不同屏幕旋转下的全屏切换行为。
*   **各种失败场景:**  测试在哪些情况下旋转屏幕不应该触发全屏切换，例如：
    *   视频控件被禁用 (`controls` 属性不存在)。
    *   设备不支持设备方向 API。
    *   设备方向 API 返回无效或零值。
    *   视频未播放或已暂停。
    *   视频不可见。
    *   发生了 180 度旋转 (例如从一个横屏方向旋转到另一个横屏方向)。
    *   视频尺寸太小。
    *   当前文档已经处于全屏状态（但不是视频本身）。
    *   `controlslist` 属性设置为 `nofullscreen`。
    *   视频处于画中画模式。

**2. 依赖项和条件测试:**

*   **功能开关 (Feature Flag):**  测试 `MediaControlsRotateToFullscreenDelegate` 的功能是否由一个特定的 Feature Flag 控制。
*   **是否为视频元素:**  测试 delegate 只对 `HTMLVideoElement` 生效，而对 `HTMLAudioElement` 等其他元素无效。
*   **可见性观察:** 测试 delegate 是否仅在视频播放时才开始观察其可见性，并且根据可见性状态决定是否触发全屏切换。

**3. 内部状态和计算:**

*   **计算视频方向:** 测试 delegate 是否能正确判断视频是横屏还是竖屏。
*   **观察屏幕方向:** 测试 delegate 是否能正确获取和跟踪当前的屏幕方向。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

虽然这个文件是 C++ 代码，但它测试的功能直接关联到 Web 开发者可以通过 JavaScript, HTML, CSS 控制的行为：

*   **HTML:**
    *   `<video>` 标签的 `controls` 属性：测试中通过设置和移除 `controls` 属性来模拟用户是否显示默认的视频控件。如果 `controls` 属性不存在，旋转屏幕不应触发全屏。
        ```html
        <video src="myvideo.mp4" controls></video>
        <video src="myvideo.mp4"></video>
        ```
    *   `<video>` 标签的 `controlslist` 属性：测试中设置 `controlslist="nofullscreen"` 来模拟禁用全屏按钮的情况。
        ```html
        <video src="myvideo.mp4" controls controlslist="nofullscreen"></video>
        ```
*   **JavaScript:**
    *   `video.play()` 和 `video.pause()`: 测试中通过调用这些方法来模拟视频的播放和暂停状态，验证只有在播放状态下旋转屏幕才会触发全屏。
    *   Fullscreen API (`requestFullscreen()`, `exitFullscreen()`): 虽然测试代码本身不直接调用这些 API (它通过模拟 Blink 内部的事件和状态变化)，但 `MediaControlsRotateToFullscreenDelegate` 的最终目的是响应屏幕旋转并触发这些 API 的调用。开发者可以使用 JavaScript 来监听全屏状态的变化。
    *   Device Orientation API (`DeviceOrientationEvent`):  测试中模拟了设备方向事件的触发，以测试 delegate 如何根据设备方向变化做出反应。虽然测试代码直接设置了 Device Orientation 数据，但在实际场景中，浏览器会捕获设备的物理传感器数据并触发 `deviceorientation` 事件，开发者可以使用 JavaScript 监听这些事件。
        ```javascript
        window.addEventListener('deviceorientation', function(event) {
          console.log(event.beta, event.gamma);
        });
        ```
*   **CSS:**
    *   测试中通过修改 CSS 的 `margin-top` 属性来模拟视频元素是否可见。这说明 delegate 会考虑 CSS 的影响，只有当视频可见时才会响应屏幕旋转。
        ```javascript
        document.querySelector('video').style.marginTop = '-999px'; // 模拟视频不可见
        ```

**逻辑推理、假设输入与输出:**

以下是一些测试用例的逻辑推理和假设输入输出示例：

*   **假设输入:**
    *   屏幕方向: 竖屏 (Portrait)
    *   视频宽高: 640x480 (横屏)
    *   视频状态: 播放中
    *   用户操作: 将设备旋转到横屏 (Landscape)
    *   `controls` 属性: 存在
*   **预期输出:** 视频进入全屏模式。

*   **假设输入:**
    *   屏幕方向: 横屏 (Landscape)
    *   视频宽高: 480x640 (竖屏)
    *   视频状态: 播放中
    *   用户操作: 将设备旋转到竖屏 (Portrait)
    *   `controls` 属性: 存在
*   **预期输出:** 视频进入全屏模式。

*   **假设输入:**
    *   屏幕方向: 竖屏 (Portrait)
    *   视频宽高: 640x480 (横屏)
    *   视频状态: 暂停
    *   用户操作: 将设备旋转到横屏 (Landscape)
    *   `controls` 属性: 存在
*   **预期输出:** 视频 **不** 进入全屏模式。

**用户或编程常见的使用错误举例说明:**

*   **错误地认为所有旋转都会触发全屏:**  开发者或用户可能会认为只要旋转设备，视频就会自动全屏。但测试用例表明，多种因素会阻止这种情况，例如视频未播放、控件被禁用、或设置了 `controlslist="nofullscreen"`。
*   **没有考虑设备方向 API 的可用性:**  依赖于自动旋转全屏功能的开发者需要意识到，如果设备不支持 Device Orientation API，或者用户禁用了相关权限，该功能将无法工作。
*   **在文档全屏时尝试视频旋转全屏:**  如果网页已经处于全屏状态（例如用户请求了 document.body 的全屏），那么视频的自动旋转全屏功能通常不会生效。
*   **错误地禁用了控件:**  如果开发者为了自定义 UI 而移除了 `controls` 属性，他们也禁用了自动旋转全屏的功能，可能需要自己实现类似逻辑。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在移动设备上浏览网页，网页中包含一个 `<video>` 元素。**
2. **用户点击播放按钮开始播放视频。**  此时 `MediaControlsRotateToFullscreenDelegate` 开始观察视频的状态和屏幕方向。
3. **用户握持设备处于某个方向，例如竖屏。**  `MediaControlsRotateToFullscreenDelegate` 记录当前的屏幕方向。
4. **用户旋转设备，例如从竖屏旋转到横屏。**  操作系统会触发 `orientationchange` 事件，浏览器接收到该事件。
5. **Blink 引擎的 `ScreenOrientationController` 组件接收到 `orientationchange` 事件，并更新屏幕方向的信息。**
6. **`MediaControlsRotateToFullscreenDelegate` 观察到屏幕方向发生了变化。**
7. **Delegate 检查一系列条件：**
    *   视频是否正在播放？
    *   视频控件是否显示？
    *   设备方向 API 是否可用？
    *   旋转后的屏幕方向是否与视频的宽高比匹配？
    *   当前文档是否已处于全屏状态？
    *   `controlslist` 属性是否阻止全屏？
    *   视频是否可见？
    *   等等。
8. **如果所有条件都满足，`MediaControlsRotateToFullscreenDelegate` 会请求视频元素进入全屏模式。**  这通常会通过调用 Blink 内部的 Fullscreen API 实现。
9. **如果条件不满足，旋转操作将被忽略，视频保持当前状态。**

**作为调试线索：**

当用户报告视频在旋转屏幕时没有自动进入全屏，或者在不应该全屏的时候进入了全屏，开发者可以参考 `media_controls_rotate_to_fullscreen_delegate_test.cc` 中的测试用例来排查问题：

*   **检查 HTML 代码：** 确认 `<video>` 标签是否包含 `controls` 属性，以及 `controlslist` 属性的设置。
*   **检查 JavaScript 代码：**  确认是否有 JavaScript 代码阻止了默认的全屏行为，或者是否有代码主动请求了其他元素的全屏。
*   **检查 CSS 代码：**  确认视频元素是否可见，没有被 `display: none` 或其他样式隐藏。
*   **考虑设备特性：**  确认用户设备是否支持 Device Orientation API，以及用户是否授予了相关权限。
*   **重现测试场景：**  尝试按照测试用例中的步骤操作，看是否能重现问题。例如，先暂停视频再旋转屏幕，或者在网页已经处于全屏状态下旋转屏幕。

总而言之，`media_controls_rotate_to_fullscreen_delegate_test.cc` 是一个重要的测试文件，它确保了 Chromium Blink 引擎能够正确处理视频在屏幕旋转时的全屏切换逻辑，同时也为开发者提供了理解该功能行为和排查相关问题的线索。

Prompt: 
```
这是目录为blink/renderer/modules/media_controls/media_controls_rotate_to_fullscreen_delegate_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/media_controls/media_controls_rotate_to_fullscreen_delegate.h"

#include <tuple>

#include "mojo/public/cpp/bindings/associated_remote.h"
#include "services/device/public/mojom/screen_orientation.mojom-blink.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/css/css_style_declaration.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/fullscreen/fullscreen.h"
#include "third_party/blink/renderer/core/html/media/html_audio_element.h"
#include "third_party/blink/renderer/core/html/media/html_video_element.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/loader/empty_clients.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/modules/device_orientation/device_orientation_controller.h"
#include "third_party/blink/renderer/modules/device_orientation/device_orientation_data.h"
#include "third_party/blink/renderer/modules/media_controls/media_controls_impl.h"
#include "third_party/blink/renderer/modules/screen_orientation/screen_orientation_controller.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/testing/empty_web_media_player.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"
#include "ui/display/mojom/screen_orientation.mojom-blink.h"

namespace blink {

namespace {

class MockVideoWebMediaPlayer : public EmptyWebMediaPlayer {
 public:
  ~MockVideoWebMediaPlayer() override = default;

  // EmptyWebMediaPlayer overrides:
  bool HasVideo() const override { return true; }
  gfx::Size NaturalSize() const override { return mock_natural_size_; }

  gfx::Size& MockNaturalSize() { return mock_natural_size_; }

 private:
  gfx::Size mock_natural_size_ = {};
};

class MockChromeClient : public EmptyChromeClient {
 public:
  // ChromeClient overrides:
  void InstallSupplements(LocalFrame& frame) override {
    EmptyChromeClient::InstallSupplements(frame);
    HeapMojoAssociatedRemote<device::mojom::blink::ScreenOrientation>
        screen_orientation(frame.DomWindow());
    std::ignore = screen_orientation.BindNewEndpointAndPassDedicatedReceiver();
    ScreenOrientationController::From(*frame.DomWindow())
        ->SetScreenOrientationAssociatedRemoteForTests(
            std::move(screen_orientation));
  }
  void EnterFullscreen(LocalFrame& frame,
                       const FullscreenOptions*,
                       FullscreenRequestType) override {
    Fullscreen::DidResolveEnterFullscreenRequest(*frame.GetDocument(),
                                                 true /* granted */);
  }
  void ExitFullscreen(LocalFrame& frame) override {
    Fullscreen::DidExitFullscreen(*frame.GetDocument());
  }

  const display::ScreenInfo& GetScreenInfo(LocalFrame&) const override {
    return mock_screen_info_;
  }

  display::ScreenInfo& MockScreenInfo() { return mock_screen_info_; }

 private:
  display::ScreenInfo mock_screen_info_ = {};
};

class StubLocalFrameClient : public EmptyLocalFrameClient {
 public:
  std::unique_ptr<WebMediaPlayer> CreateWebMediaPlayer(
      HTMLMediaElement&,
      const WebMediaPlayerSource&,
      WebMediaPlayerClient*) override {
    return std::make_unique<MockVideoWebMediaPlayer>();
  }
};

}  // anonymous namespace

class MediaControlsRotateToFullscreenDelegateTest
    : public PageTestBase,
      private ScopedVideoFullscreenOrientationLockForTest,
      private ScopedVideoRotateToFullscreenForTest {
 public:
  MediaControlsRotateToFullscreenDelegateTest()
      : ScopedVideoFullscreenOrientationLockForTest(true),
        ScopedVideoRotateToFullscreenForTest(true) {}

 protected:
  using SimpleOrientation =
      MediaControlsRotateToFullscreenDelegate::SimpleOrientation;

  void SetUp() override {
    chrome_client_ = MakeGarbageCollected<MockChromeClient>();
    SetupPageWithClients(chrome_client_,
                         MakeGarbageCollected<StubLocalFrameClient>());
    video_ = MakeGarbageCollected<HTMLVideoElement>(GetDocument());
    GetVideo().setAttribute(html_names::kControlsAttr, g_empty_atom);
    // Most tests should call GetDocument().body()->AppendChild(&GetVideo());
    // This is not done automatically, so that tests control timing of `Attach`.
  }

  static bool HasDelegate(const MediaControls& media_controls) {
    return !!static_cast<const MediaControlsImpl*>(&media_controls)
                 ->rotate_to_fullscreen_delegate_;
  }

  void SimulateVideoReadyState(HTMLMediaElement::ReadyState state) {
    GetVideo().SetReadyState(state);
  }

  SimpleOrientation ObservedScreenOrientation() const {
    return GetMediaControls()
        .rotate_to_fullscreen_delegate_->current_screen_orientation_;
  }

  SimpleOrientation ComputeVideoOrientation() const {
    return GetMediaControls()
        .rotate_to_fullscreen_delegate_->ComputeVideoOrientation();
  }

  bool IsObservingVisibility() const {
    return GetMediaControls()
               .rotate_to_fullscreen_delegate_->intersection_observer_ !=
           nullptr;
  }

  bool ObservedVisibility() const {
    return GetMediaControls().rotate_to_fullscreen_delegate_->is_visible_;
  }

  void DisableControls() {
    // If scripts are not enabled, controls will always be shown.
    GetFrame().GetSettings()->SetScriptEnabled(true);

    GetVideo().removeAttribute(html_names::kControlsAttr);
  }

  void DispatchEvent(EventTarget& target, const AtomicString& type) {
    target.DispatchEvent(*Event::Create(type));
  }

  void InitScreenAndVideo(
      display::mojom::blink::ScreenOrientation initial_screen_orientation,
      gfx::Size video_size,
      bool with_device_orientation = true);

  void PlayVideo();

  void UpdateVisibilityObserver() {
    // Let IntersectionObserver update.
    UpdateAllLifecyclePhasesForTest();
    test::RunPendingTasks();
  }

  void RotateTo(
      display::mojom::blink::ScreenOrientation new_screen_orientation);

  MockChromeClient& GetChromeClient() const { return *chrome_client_; }
  LocalDOMWindow& GetWindow() const { return *GetDocument().domWindow(); }
  HTMLVideoElement& GetVideo() const { return *video_; }
  MediaControlsImpl& GetMediaControls() const {
    return *static_cast<MediaControlsImpl*>(GetVideo().GetMediaControls());
  }
  MockVideoWebMediaPlayer& GetWebMediaPlayer() const {
    return *static_cast<MockVideoWebMediaPlayer*>(
        GetVideo().GetWebMediaPlayer());
  }

 private:
  Persistent<MockChromeClient> chrome_client_;
  Persistent<HTMLVideoElement> video_;
};

void MediaControlsRotateToFullscreenDelegateTest::InitScreenAndVideo(
    display::mojom::blink::ScreenOrientation initial_screen_orientation,
    gfx::Size video_size,
    bool with_device_orientation /* = true */) {
  // Set initial screen orientation (called by `Attach` during `AppendChild`).
  GetChromeClient().MockScreenInfo().orientation_type =
      initial_screen_orientation;

  // Set up the WebMediaPlayer instance.
  GetDocument().body()->AppendChild(&GetVideo());
  GetVideo().SetSrc(AtomicString("https://example.com"));
  test::RunPendingTasks();
  SimulateVideoReadyState(HTMLMediaElement::kHaveMetadata);

  // Set video size.
  GetWebMediaPlayer().MockNaturalSize() = video_size;

  if (with_device_orientation) {
    // Dispatch an arbitrary Device Orientation event to satisfy
    // MediaControlsRotateToFullscreenDelegate's requirement that the device
    // supports the API and can provide beta and gamma values. The orientation
    // will be ignored.
    DeviceOrientationController::From(GetWindow())
        .SetOverride(DeviceOrientationData::Create(
            0.0 /* alpha */, 90.0 /* beta */, 0.0 /* gamma */,
            false /* absolute */));
    test::RunPendingTasks();
  }
}

void MediaControlsRotateToFullscreenDelegateTest::PlayVideo() {
  LocalFrame::NotifyUserActivation(
      GetDocument().GetFrame(), mojom::UserActivationNotificationType::kTest);
  GetVideo().Play();
  test::RunPendingTasks();
}

void MediaControlsRotateToFullscreenDelegateTest::RotateTo(
    display::mojom::blink::ScreenOrientation new_screen_orientation) {
  GetChromeClient().MockScreenInfo().orientation_type = new_screen_orientation;
  DispatchEvent(GetWindow(), event_type_names::kOrientationchange);
  test::RunPendingTasks();
}

TEST_F(MediaControlsRotateToFullscreenDelegateTest, DelegateRequiresFlag) {
  // SetUp turns the flag on by default.
  GetDocument().body()->AppendChild(&GetVideo());
  EXPECT_TRUE(HasDelegate(GetMediaControls()));

  // No delegate when flag is off.
  ScopedVideoRotateToFullscreenForTest video_rotate_to_fullscreen(false);
  auto* video = MakeGarbageCollected<HTMLVideoElement>(GetDocument());
  GetDocument().body()->AppendChild(video);
  EXPECT_FALSE(HasDelegate(*video->GetMediaControls()));
}

TEST_F(MediaControlsRotateToFullscreenDelegateTest, DelegateRequiresVideo) {
  auto* audio = MakeGarbageCollected<HTMLAudioElement>(GetDocument());
  GetDocument().body()->AppendChild(audio);
  EXPECT_FALSE(HasDelegate(*audio->GetMediaControls()));
}

TEST_F(MediaControlsRotateToFullscreenDelegateTest, ComputeVideoOrientation) {
  // Set up the WebMediaPlayer instance.
  GetDocument().body()->AppendChild(&GetVideo());
  GetVideo().SetSrc(AtomicString("https://example.com"));
  test::RunPendingTasks();

  // Video is not yet ready.
  EXPECT_EQ(SimpleOrientation::kUnknown, ComputeVideoOrientation());

  SimulateVideoReadyState(HTMLMediaElement::kHaveMetadata);

  // 400x400 is square, which is currently treated as landscape.
  GetWebMediaPlayer().MockNaturalSize() = gfx::Size(400, 400);
  EXPECT_EQ(SimpleOrientation::kLandscape, ComputeVideoOrientation());
  // 300x200 is landscape.
  GetWebMediaPlayer().MockNaturalSize() = gfx::Size(300, 200);
  EXPECT_EQ(SimpleOrientation::kLandscape, ComputeVideoOrientation());
  // 200x300 is portrait.
  GetWebMediaPlayer().MockNaturalSize() = gfx::Size(200, 300);
  EXPECT_EQ(SimpleOrientation::kPortrait, ComputeVideoOrientation());
  // 300x199 is too small.
  GetWebMediaPlayer().MockNaturalSize() = gfx::Size(300, 199);
  EXPECT_EQ(SimpleOrientation::kUnknown, ComputeVideoOrientation());
  // 199x300 is too small.
  GetWebMediaPlayer().MockNaturalSize() = gfx::Size(199, 300);
  EXPECT_EQ(SimpleOrientation::kUnknown, ComputeVideoOrientation());
  // 0x0 is empty.
  GetWebMediaPlayer().MockNaturalSize() = gfx::Size(0, 0);
  EXPECT_EQ(SimpleOrientation::kUnknown, ComputeVideoOrientation());
}

TEST_F(MediaControlsRotateToFullscreenDelegateTest,
       OnlyObserveVisibilityWhenPlaying) {
  // Should not initially be observing visibility.
  GetDocument().body()->AppendChild(&GetVideo());
  EXPECT_FALSE(IsObservingVisibility());

  // Should start observing visibility when played.
  LocalFrame::NotifyUserActivation(
      GetDocument().GetFrame(), mojom::UserActivationNotificationType::kTest);
  GetVideo().Play();
  test::RunPendingTasks();
  EXPECT_TRUE(IsObservingVisibility());
  EXPECT_FALSE(ObservedVisibility());

  // Should have observed visibility once compositor updates.
  UpdateAllLifecyclePhasesForTest();
  test::RunPendingTasks();
  EXPECT_TRUE(ObservedVisibility());

  // Should stop observing visibility when paused.
  GetVideo().pause();
  test::RunPendingTasks();
  EXPECT_FALSE(IsObservingVisibility());
  EXPECT_FALSE(ObservedVisibility());

  // Should resume observing visibility when playback resumes.
  LocalFrame::NotifyUserActivation(
      GetDocument().GetFrame(), mojom::UserActivationNotificationType::kTest);
  GetVideo().Play();
  test::RunPendingTasks();
  EXPECT_TRUE(IsObservingVisibility());
  EXPECT_FALSE(ObservedVisibility());

  // Should have observed visibility once compositor updates.
  UpdateAllLifecyclePhasesForTest();
  test::RunPendingTasks();
  EXPECT_TRUE(ObservedVisibility());
}

TEST_F(MediaControlsRotateToFullscreenDelegateTest,
       EnterSuccessPortraitToLandscape) {
  // Portrait screen, landscape video.
  InitScreenAndVideo(display::mojom::blink::ScreenOrientation::kPortraitPrimary,
                     gfx::Size(640, 480));
  EXPECT_EQ(SimpleOrientation::kPortrait, ObservedScreenOrientation());
  EXPECT_EQ(SimpleOrientation::kLandscape, ComputeVideoOrientation());

  // Play video.
  PlayVideo();
  UpdateVisibilityObserver();

  EXPECT_TRUE(ObservedVisibility());
  EXPECT_FALSE(GetVideo().IsFullscreen());

  // Rotate screen to landscape.
  RotateTo(display::mojom::blink::ScreenOrientation::kLandscapePrimary);

  // Should enter fullscreen.
  EXPECT_TRUE(GetVideo().IsFullscreen());
}

TEST_F(MediaControlsRotateToFullscreenDelegateTest,
       EnterSuccessLandscapeToPortrait) {
  // Landscape screen, portrait video.
  InitScreenAndVideo(
      display::mojom::blink::ScreenOrientation::kLandscapePrimary,
      gfx::Size(480, 640));
  EXPECT_EQ(SimpleOrientation::kLandscape, ObservedScreenOrientation());
  EXPECT_EQ(SimpleOrientation::kPortrait, ComputeVideoOrientation());

  // Play video.
  PlayVideo();
  UpdateVisibilityObserver();

  EXPECT_TRUE(ObservedVisibility());
  EXPECT_FALSE(GetVideo().IsFullscreen());

  // Rotate screen to portrait.
  RotateTo(display::mojom::blink::ScreenOrientation::kPortraitPrimary);

  // Should enter fullscreen.
  EXPECT_TRUE(GetVideo().IsFullscreen());
}

TEST_F(MediaControlsRotateToFullscreenDelegateTest,
       EnterSuccessSquarePortraitToLandscape) {
  // Portrait screen, square video.
  InitScreenAndVideo(display::mojom::blink::ScreenOrientation::kPortraitPrimary,
                     gfx::Size(400, 400));
  EXPECT_EQ(SimpleOrientation::kPortrait, ObservedScreenOrientation());
  EXPECT_EQ(SimpleOrientation::kLandscape, ComputeVideoOrientation());

  // Play video.
  PlayVideo();
  UpdateVisibilityObserver();

  EXPECT_TRUE(ObservedVisibility());
  EXPECT_FALSE(GetVideo().IsFullscreen());

  // Rotate screen to landscape.
  RotateTo(display::mojom::blink::ScreenOrientation::kLandscapePrimary);

  // Should enter fullscreen, since square videos are currently treated the same
  // as landscape videos.
  EXPECT_TRUE(GetVideo().IsFullscreen());
}

TEST_F(MediaControlsRotateToFullscreenDelegateTest, EnterFailWrongOrientation) {
  // Landscape screen, landscape video.
  InitScreenAndVideo(
      display::mojom::blink::ScreenOrientation::kLandscapePrimary,
      gfx::Size(640, 480));
  EXPECT_EQ(SimpleOrientation::kLandscape, ObservedScreenOrientation());
  EXPECT_EQ(SimpleOrientation::kLandscape, ComputeVideoOrientation());

  // Play video.
  PlayVideo();
  UpdateVisibilityObserver();

  EXPECT_TRUE(ObservedVisibility());

  // Rotate screen to portrait.
  RotateTo(display::mojom::blink::ScreenOrientation::kPortraitPrimary);

  // Should not enter fullscreen since the orientation that the device was
  // rotated to does not match the orientation of the video.
  EXPECT_FALSE(GetVideo().IsFullscreen());
}

TEST_F(MediaControlsRotateToFullscreenDelegateTest,
       EnterFailSquareWrongOrientation) {
  // Landscape screen, square video.
  InitScreenAndVideo(
      display::mojom::blink::ScreenOrientation::kLandscapePrimary,
      gfx::Size(400, 400));
  EXPECT_EQ(SimpleOrientation::kLandscape, ObservedScreenOrientation());
  EXPECT_EQ(SimpleOrientation::kLandscape, ComputeVideoOrientation());

  // Play video.
  PlayVideo();
  UpdateVisibilityObserver();

  EXPECT_TRUE(ObservedVisibility());

  // Rotate screen to portrait.
  RotateTo(display::mojom::blink::ScreenOrientation::kPortraitPrimary);

  // Should not enter fullscreen since square videos are treated as landscape,
  // so rotating to portrait does not match the orientation of the video.
  EXPECT_FALSE(GetVideo().IsFullscreen());
}

TEST_F(MediaControlsRotateToFullscreenDelegateTest, EnterFailNoControls) {
  DisableControls();

  // Portrait screen, landscape video.
  InitScreenAndVideo(display::mojom::blink::ScreenOrientation::kPortraitPrimary,
                     gfx::Size(640, 480));
  EXPECT_EQ(SimpleOrientation::kPortrait, ObservedScreenOrientation());
  EXPECT_EQ(SimpleOrientation::kLandscape, ComputeVideoOrientation());

  // Play video.
  PlayVideo();
  UpdateVisibilityObserver();

  EXPECT_TRUE(ObservedVisibility());

  // Rotate screen to landscape.
  RotateTo(display::mojom::blink::ScreenOrientation::kLandscapePrimary);

  // Should not enter fullscreen since video has no controls.
  EXPECT_FALSE(GetVideo().IsFullscreen());
}

TEST_F(MediaControlsRotateToFullscreenDelegateTest,
       EnterFailNoDeviceOrientation) {
  // Portrait screen, landscape video.
  InitScreenAndVideo(display::mojom::blink::ScreenOrientation::kPortraitPrimary,
                     gfx::Size(640, 480), false /* with_device_orientation */);
  EXPECT_EQ(SimpleOrientation::kPortrait, ObservedScreenOrientation());
  EXPECT_EQ(SimpleOrientation::kLandscape, ComputeVideoOrientation());

  // Dispatch an null Device Orientation event, as happens when the device lacks
  // the necessary hardware to support the Device Orientation API.
  DeviceOrientationController::From(GetWindow())
      .SetOverride(DeviceOrientationData::Create());
  test::RunPendingTasks();

  // Play video.
  PlayVideo();
  UpdateVisibilityObserver();

  EXPECT_TRUE(ObservedVisibility());

  // Rotate screen to landscape.
  RotateTo(display::mojom::blink::ScreenOrientation::kLandscapePrimary);

  // Should not enter fullscreen since Device Orientation is not available.
  EXPECT_FALSE(GetVideo().IsFullscreen());
}

TEST_F(MediaControlsRotateToFullscreenDelegateTest,
       EnterFailZeroDeviceOrientation) {
  // Portrait screen, landscape video.
  InitScreenAndVideo(display::mojom::blink::ScreenOrientation::kPortraitPrimary,
                     gfx::Size(640, 480), false /* with_device_orientation */);
  EXPECT_EQ(SimpleOrientation::kPortrait, ObservedScreenOrientation());
  EXPECT_EQ(SimpleOrientation::kLandscape, ComputeVideoOrientation());

  // Dispatch a Device Orientation event where all values are zero, as happens
  // on poorly configured devices that lack the necessary hardware to support
  // the Device Orientation API, but don't properly expose that lack.
  DeviceOrientationController::From(GetWindow())
      .SetOverride(
          DeviceOrientationData::Create(0.0 /* alpha */, 0.0 /* beta */,
                                        0.0 /* gamma */, false /* absolute */));
  test::RunPendingTasks();

  // Play video.
  PlayVideo();
  UpdateVisibilityObserver();

  EXPECT_TRUE(ObservedVisibility());

  // Rotate screen to landscape.
  RotateTo(display::mojom::blink::ScreenOrientation::kLandscapePrimary);

  // Should not enter fullscreen since Device Orientation is not available.
  EXPECT_FALSE(GetVideo().IsFullscreen());
}

TEST_F(MediaControlsRotateToFullscreenDelegateTest, EnterFailPaused) {
  // Portrait screen, landscape video.
  InitScreenAndVideo(display::mojom::blink::ScreenOrientation::kPortraitPrimary,
                     gfx::Size(640, 480));
  EXPECT_EQ(SimpleOrientation::kPortrait, ObservedScreenOrientation());
  EXPECT_EQ(SimpleOrientation::kLandscape, ComputeVideoOrientation());

  EXPECT_FALSE(ObservedVisibility());

  UpdateVisibilityObserver();

  EXPECT_FALSE(ObservedVisibility());

  // Rotate screen to landscape.
  RotateTo(display::mojom::blink::ScreenOrientation::kLandscapePrimary);

  // Should not enter fullscreen since video is paused.
  EXPECT_FALSE(GetVideo().IsFullscreen());
}

TEST_F(MediaControlsRotateToFullscreenDelegateTest, EnterFailHidden) {
  // Portrait screen, landscape video.
  InitScreenAndVideo(display::mojom::blink::ScreenOrientation::kPortraitPrimary,
                     gfx::Size(640, 480));
  EXPECT_EQ(SimpleOrientation::kPortrait, ObservedScreenOrientation());
  EXPECT_EQ(SimpleOrientation::kLandscape, ComputeVideoOrientation());

  // Play video.
  PlayVideo();
  UpdateVisibilityObserver();

  EXPECT_TRUE(ObservedVisibility());

  // Move video offscreen.
  GetDocument().body()->style()->setProperty(
      GetDocument().GetExecutionContext(), "margin-top", "-999px", "",
      ASSERT_NO_EXCEPTION);

  UpdateVisibilityObserver();

  EXPECT_FALSE(ObservedVisibility());

  // Rotate screen to landscape.
  RotateTo(display::mojom::blink::ScreenOrientation::kLandscapePrimary);

  // Should not enter fullscreen since video is not visible.
  EXPECT_FALSE(GetVideo().IsFullscreen());
}

TEST_F(MediaControlsRotateToFullscreenDelegateTest,
       EnterFail180DegreeRotation) {
  // Landscape screen, landscape video.
  InitScreenAndVideo(
      display::mojom::blink::ScreenOrientation::kLandscapeSecondary,
      gfx::Size(640, 480));
  EXPECT_EQ(SimpleOrientation::kLandscape, ObservedScreenOrientation());
  EXPECT_EQ(SimpleOrientation::kLandscape, ComputeVideoOrientation());

  // Play video.
  PlayVideo();
  UpdateVisibilityObserver();

  EXPECT_TRUE(ObservedVisibility());

  // Rotate screen 180 degrees to the opposite landscape (without passing via a
  // portrait orientation).
  RotateTo(display::mojom::blink::ScreenOrientation::kLandscapePrimary);

  // Should not enter fullscreen since this is a 180 degree orientation.
  EXPECT_FALSE(GetVideo().IsFullscreen());
}

TEST_F(MediaControlsRotateToFullscreenDelegateTest, EnterFailSmall) {
  // Portrait screen, small landscape video.
  InitScreenAndVideo(display::mojom::blink::ScreenOrientation::kPortraitPrimary,
                     gfx::Size(300, 199));
  EXPECT_EQ(SimpleOrientation::kPortrait, ObservedScreenOrientation());
  EXPECT_EQ(SimpleOrientation::kUnknown, ComputeVideoOrientation());

  // Play video.
  PlayVideo();
  UpdateVisibilityObserver();

  EXPECT_TRUE(ObservedVisibility());

  // Rotate screen to landscape.
  RotateTo(display::mojom::blink::ScreenOrientation::kLandscapePrimary);

  // Should not enter fullscreen since video is too small.
  EXPECT_FALSE(GetVideo().IsFullscreen());
}

TEST_F(MediaControlsRotateToFullscreenDelegateTest,
       EnterFailDocumentFullscreen) {
  // Portrait screen, landscape video.
  InitScreenAndVideo(display::mojom::blink::ScreenOrientation::kPortraitPrimary,
                     gfx::Size(640, 480));
  EXPECT_EQ(SimpleOrientation::kPortrait, ObservedScreenOrientation());
  EXPECT_EQ(SimpleOrientation::kLandscape, ComputeVideoOrientation());

  // Simulate the webpage requesting fullscreen on some other element than the
  // video (in this case document.body).
  LocalFrame::NotifyUserActivation(
      GetDocument().GetFrame(), mojom::UserActivationNotificationType::kTest);
  Fullscreen::RequestFullscreen(*GetDocument().body());
  test::RunPendingTasks();
  EXPECT_TRUE(Fullscreen::IsFullscreenElement(*GetDocument().body()));
  EXPECT_FALSE(GetVideo().IsFullscreen());

  // Play video.
  PlayVideo();
  UpdateVisibilityObserver();

  EXPECT_TRUE(ObservedVisibility());

  // Rotate screen to landscape.
  RotateTo(display::mojom::blink::ScreenOrientation::kLandscapePrimary);

  // Should not enter fullscreen on video, since document is already fullscreen.
  EXPECT_TRUE(Fullscreen::IsFullscreenElement(*GetDocument().body()));
  EXPECT_FALSE(GetVideo().IsFullscreen());
}

TEST_F(MediaControlsRotateToFullscreenDelegateTest,
       ExitSuccessLandscapeFullscreenToPortraitInline) {
  // Landscape screen, landscape video.
  InitScreenAndVideo(
      display::mojom::blink::ScreenOrientation::kLandscapePrimary,
      gfx::Size(640, 480));
  EXPECT_EQ(SimpleOrientation::kLandscape, ObservedScreenOrientation());
  EXPECT_EQ(SimpleOrientation::kLandscape, ComputeVideoOrientation());

  // Start in fullscreen.
  LocalFrame::NotifyUserActivation(
      GetDocument().GetFrame(), mojom::UserActivationNotificationType::kTest);
  GetMediaControls().EnterFullscreen();
  // n.b. omit to call Fullscreen::From(GetDocument()).DidEnterFullscreen() so
  // that MediaControlsOrientationLockDelegate doesn't trigger, which avoids
  // having to create deviceorientation events here to unlock it again.
  test::RunPendingTasks();
  EXPECT_TRUE(GetVideo().IsFullscreen());

  // Leave video paused (playing is not a requirement to exit fullscreen).
  EXPECT_TRUE(GetVideo().paused());
  EXPECT_FALSE(ObservedVisibility());

  // Rotate screen to portrait. This relies on the screen orientation not being
  // locked by MediaControlsOrientationLockDelegate (which has its own tests).
  RotateTo(display::mojom::blink::ScreenOrientation::kPortraitPrimary);

  // Should exit fullscreen.
  EXPECT_FALSE(GetVideo().IsFullscreen());
}

TEST_F(MediaControlsRotateToFullscreenDelegateTest,
       ExitSuccessPortraitFullscreenToLandscapeInline) {
  // Portrait screen, portrait video.
  InitScreenAndVideo(display::mojom::blink::ScreenOrientation::kPortraitPrimary,
                     gfx::Size(480, 640));
  EXPECT_EQ(SimpleOrientation::kPortrait, ObservedScreenOrientation());
  EXPECT_EQ(SimpleOrientation::kPortrait, ComputeVideoOrientation());

  // Start in fullscreen.
  LocalFrame::NotifyUserActivation(
      GetDocument().GetFrame(), mojom::UserActivationNotificationType::kTest);
  GetMediaControls().EnterFullscreen();
  // n.b. omit to call Fullscreen::From(GetDocument()).DidEnterFullscreen() so
  // that MediaControlsOrientationLockDelegate doesn't trigger, which avoids
  // having to create deviceorientation events here to unlock it again.
  test::RunPendingTasks();
  EXPECT_TRUE(GetVideo().IsFullscreen());

  // Leave video paused (playing is not a requirement to exit fullscreen).
  EXPECT_TRUE(GetVideo().paused());
  EXPECT_FALSE(ObservedVisibility());

  // Rotate screen to landscape. This relies on the screen orientation not being
  // locked by MediaControlsOrientationLockDelegate (which has its own tests).
  RotateTo(display::mojom::blink::ScreenOrientation::kLandscapePrimary);

  // Should exit fullscreen.
  EXPECT_FALSE(GetVideo().IsFullscreen());
}

TEST_F(MediaControlsRotateToFullscreenDelegateTest,
       ExitFailDocumentFullscreen) {
  // Landscape screen, landscape video.
  InitScreenAndVideo(
      display::mojom::blink::ScreenOrientation::kLandscapePrimary,
      gfx::Size(640, 480));
  EXPECT_EQ(SimpleOrientation::kLandscape, ObservedScreenOrientation());
  EXPECT_EQ(SimpleOrientation::kLandscape, ComputeVideoOrientation());

  // Simulate the webpage requesting fullscreen on some other element than the
  // video (in this case document.body).
  LocalFrame::NotifyUserActivation(
      GetDocument().GetFrame(), mojom::UserActivationNotificationType::kTest);
  Fullscreen::RequestFullscreen(*GetDocument().body());
  test::RunPendingTasks();
  EXPECT_TRUE(Fullscreen::IsFullscreenElement(*GetDocument().body()));
  EXPECT_FALSE(GetVideo().IsFullscreen());

  // Leave video paused (playing is not a requirement to exit fullscreen).
  EXPECT_TRUE(GetVideo().paused());
  EXPECT_FALSE(ObservedVisibility());

  // Rotate screen to portrait.
  RotateTo(display::mojom::blink::ScreenOrientation::kPortraitPrimary);

  // Should not exit fullscreen, since video was not the fullscreen element.
  EXPECT_TRUE(Fullscreen::IsFullscreenElement(*GetDocument().body()));
  EXPECT_FALSE(GetVideo().IsFullscreen());
}

TEST_F(MediaControlsRotateToFullscreenDelegateTest,
       EnterFailControlsListNoFullscreen) {
  // Portrait screen, landscape video.
  InitScreenAndVideo(display::mojom::blink::ScreenOrientation::kPortraitPrimary,
                     gfx::Size(640, 480));
  EXPECT_EQ(SimpleOrientation::kPortrait, ObservedScreenOrientation());
  EXPECT_EQ(SimpleOrientation::kLandscape, ComputeVideoOrientation());

  EXPECT_FALSE(ObservedVisibility());

  GetVideo().setAttribute(AtomicString("controlslist"),
                          AtomicString("nofullscreen"));

  PlayVideo();
  UpdateVisibilityObserver();

  EXPECT_TRUE(ObservedVisibility());

  // Rotate screen to landscape.
  RotateTo(display::mojom::blink::ScreenOrientation::kLandscapePrimary);

  // Should not enter fullscreen when controlsList=nofullscreen.
  EXPECT_FALSE(GetVideo().IsFullscreen());
}

TEST_F(MediaControlsRotateToFullscreenDelegateTest, EnterFailPictureInPicture) {
  // Portrait screen, landscape video.
  InitScreenAndVideo(display::mojom::blink::ScreenOrientation::kPortraitPrimary,
                     gfx::Size(640, 480));
  EXPECT_EQ(SimpleOrientation::kPortrait, ObservedScreenOrientation());
  EXPECT_EQ(SimpleOrientation::kLandscape, ComputeVideoOrientation());

  EXPECT_FALSE(ObservedVisibility());

  PlayVideo();
  UpdateVisibilityObserver();

  EXPECT_TRUE(ObservedVisibility());

  // Simulate Picture-in-Picture.
  GetVideo().SetPersistentState(true);

  // Rotate screen to landscape.
  RotateTo(display::mojom::blink::ScreenOrientation::kLandscapePrimary);

  // Should not enter fullscreen when Picture-in-Picture.
  EXPECT_FALSE(GetVideo().IsFullscreen());
}

TEST_F(MediaControlsRotateToFullscreenDelegateTest,
       EnterSuccessControlsListNoDownload) {
  // Portrait screen, landscape video.
  InitScreenAndVideo(display::mojom::blink::ScreenOrientation::kPortraitPrimary,
                     gfx::Size(640, 480));
  EXPECT_EQ(SimpleOrientation::kPortrait, ObservedScreenOrientation());
  EXPECT_EQ(SimpleOrientation::kLandscape, ComputeVideoOrientation());

  EXPECT_FALSE(ObservedVisibility());

  GetVideo().setAttribute(AtomicString("controlslist"),
                          AtomicString("nodownload"));

  PlayVideo();
  UpdateVisibilityObserver();

  EXPECT_TRUE(ObservedVisibility());

  // Rotate screen to landscape.
  RotateTo(display::mojom::blink::ScreenOrientation::kLandscapePrimary);

  // Should enter fullscreen when controlsList is not set to nofullscreen.
  EXPECT_TRUE(GetVideo().IsFullscreen());
}

}  // namespace blink

"""

```