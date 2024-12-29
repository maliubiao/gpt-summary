Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Identify the Core Purpose:** The filename `media_controls_display_cutout_delegate_test.cc` immediately suggests this code is testing the `MediaControlsDisplayCutoutDelegate` class. The `_test.cc` suffix is a strong convention for unit tests in Chromium. The "display cutout" part hints at its role in handling how media controls interact with screen notches or cutouts.

2. **Scan the Includes:** The included headers provide valuable context:
    * `media_controls_display_cutout_delegate.h`: This is the class being tested.
    * `core/page/page_animator.h`, `mojom/page/display_cutout.mojom-blink.h`, `core/dom/scripted_animation_controller.h`: These point to interactions with the page's animation system and data structures related to display cutouts.
    * `core/events/touch_event.h`, `core/frame/local_frame.h`, `core/frame/viewport_data.h`:  Indicates handling of touch events and interaction with the frame's viewport.
    * `core/fullscreen/fullscreen.h`:  Crucial, as the tests extensively involve entering and exiting fullscreen.
    * `core/html/media/html_video_element.h`: The tests operate on video elements.
    * `core/input/touch.h`, `core/input/touch_list.h`:  More evidence of touch event handling.
    * `core/testing/page_test_base.h`:  The base class for these integration tests.
    * `modules/media_controls/media_controls_impl.h`:  The delegate is part of the media controls implementation.
    * `platform/instrumentation/use_counter.h`:  Indicates tracking of feature usage.
    * `platform/testing/...`: Standard Blink testing utilities.

3. **Examine the Test Fixture:** The `MediaControlsDisplayCutoutDelegateTest` class inherits from `PageTestBase`. This means it sets up a minimal rendering environment for testing. The private inheritance of `ScopedDisplayCutoutAPIForTest` and `ScopedMediaControlsExpandGestureForTest` suggests these are test-specific helpers to enable/disable features related to display cutouts and expand gestures. The `SetUp()` method initializes the test environment, creating a video element.

4. **Analyze Helper Methods:** The test fixture includes several helper methods starting with `Simulate...`. These are crucial for driving the tests:
    * `SimulateEnterFullscreen()` and `SimulateExitFullscreen()`:  Directly manipulate the fullscreen state.
    * `SimulateContractingGesture()` and `SimulateExpandingGesture()`:  Mimic touch events to simulate pinch gestures. The creation of `TouchList` objects with specific coordinates is key.
    * `SimulateSingleTouchGesture()`: Simulates a single touch.
    * `HasGestureState()`, `DirectionIsExpanding()`, `DirectionIsUnknown()`:  Inspect the internal state of the `MediaControlsDisplayCutoutDelegate`.
    * `SimulateEvent()`:  Dispatches a given `TouchEvent` to the video element.
    * `CreateTouchListWithOnePoint()`, `CreateTouchListWithTwoPoints()`, `CreateTouchEventWithList()`, `CreateTouchAtPoint()`:  Utilities for easily creating touch event data.
    * `CurrentViewportFit()`:  Retrieves the current viewport fit mode.
    * `GetDelegate()` and `GetVideoElement()`: Provide access to the objects under test.

5. **Scrutinize the Test Cases:** Each `TEST_F` function focuses on a specific scenario:
    * `CombinedGesture`: Tests a sequence of expanding then contracting gestures.
    * `ContractingGesture`: Tests a contracting gesture after an expanding one.
    * `ContractingGesture_Noop`: Tests a contracting gesture without a prior expanding one.
    * `ExpandingGesture`: Tests an expanding gesture and its effect on viewport fit.
    * `ExpandingGesture_DoubleNoop`: Tests two consecutive expanding gestures.
    * `IncompleteGestureClearsState`:  Ensures that if a gesture isn't completed, its state is cleared.
    * `MetricsNoop`: Checks that no metrics are recorded if no relevant gestures occur.
    * `NoFullscreen_Noop`: Verifies that gestures have no effect outside of fullscreen.
    * `SingleTouchGesture_Noop`: Checks that single-touch gestures are ignored.
    * `TouchCancelShouldClearState`: Tests the effect of a `touchcancel` event.
    * `TouchEndShouldClearState`: Tests the effect of a `touchend` event when not completing a gesture that changes the viewport-fit.
    * `DefaultExpand`: Checks the default viewport fit in fullscreen.

6. **Connect to Web Technologies (JavaScript, HTML, CSS):**
    * **JavaScript:** The touch events simulated in the tests are the same events JavaScript code can listen for (`touchstart`, `touchmove`, `touchend`, `touchcancel`). The changes to `viewport-fit` are observable and controllable by JavaScript using the Visual Viewport API.
    * **HTML:** The tests create a `<video>` element. The presence of the `id="video"` attribute is significant for selecting the element in the tests.
    * **CSS:** While not directly tested here, the `viewport-fit` property is a CSS property. The test verifies that the underlying mechanism for controlling this property is working correctly.

7. **Infer Logic and Assumptions:** The tests make assumptions about how pinch gestures should be interpreted and how they affect the `viewport-fit` property in fullscreen for video elements. The logic seems to be that an expanding pinch in fullscreen video triggers `viewport-fit: cover` (or the equivalent `kCoverForcedByUserAgent`), while a subsequent contracting pinch reverts it to `auto`.

8. **Identify Potential Errors:** The tests reveal potential user or programming errors:
    * **User Error:**  The user might perform an expanding gesture unintentionally. The system should handle this gracefully and allow them to revert with a contracting gesture.
    * **Programming Error:** The `MediaControlsDisplayCutoutDelegate` needs to correctly interpret touch events and manage its internal state to avoid unexpected behavior or incorrect `viewport-fit` settings.

9. **Trace User Actions (Debugging Clues):**  To reach the code being tested, a user would typically:
    1. Open a webpage containing a `<video>` element.
    2. Enter fullscreen mode on the video.
    3. Perform a two-finger pinch gesture (expanding or contracting) on the video.

By following these steps, we can systematically analyze the C++ test file and understand its functionality, relationships to web technologies, underlying logic, potential errors, and how user actions lead to this code being executed.
这个文件是 Chromium Blink 引擎中 `media_controls_display_cutout_delegate_test.cc` 的源代码，它是一个**单元测试文件**，专门用于测试 `MediaControlsDisplayCutoutDelegate` 类的功能。  `MediaControlsDisplayCutoutDelegate` 的主要职责是**处理当视频全屏播放时，用户通过手势与屏幕刘海（display cutout）区域的交互，并根据这些交互调整视频的显示模式**。

以下是该文件的功能分解：

**1. 测试 `MediaControlsDisplayCutoutDelegate` 的核心逻辑：**

   - **手势识别:** 测试当用户在全屏视频上进行双指捏合（pinch）手势时，`MediaControlsDisplayCutoutDelegate` 是否能正确识别是放大（expanding）还是缩小（contracting）的手势。
   - **`viewport-fit` 属性的控制:** 测试当识别到放大手势时，`MediaControlsDisplayCutoutDelegate` 是否会相应地将视频的 `viewport-fit` 属性设置为 `cover` (或者 Chromium 内部的等价表示 `kCoverForcedByUserAgent`)，以确保视频内容填充整个屏幕，包括刘海区域。 当识别到缩小手势时，是否会将 `viewport-fit` 恢复为 `auto`。
   - **状态管理:** 测试 `MediaControlsDisplayCutoutDelegate` 是否正确地管理手势的状态，例如在手势开始、移动和结束时更新状态。
   - **边界情况处理:** 测试在没有进入全屏、只有一个手指触摸、或者手势未完成时，`MediaControlsDisplayCutoutDelegate` 是否能正确处理，不进行不必要的操作。

**2. 与 JavaScript, HTML, CSS 的关系：**

   - **JavaScript:**
     - **事件模拟:** 测试代码通过模拟 `touchstart`, `touchmove`, `touchend`, `touchcancel` 等触摸事件来触发 `MediaControlsDisplayCutoutDelegate` 的逻辑。这些事件是 JavaScript 中用于处理触摸交互的基础事件。
     - **Visual Viewport API:** 虽然测试代码本身不直接操作 JavaScript API，但 `MediaControlsDisplayCutoutDelegate` 的最终目标是影响视频的 `viewport-fit` 属性，这个属性可以通过 JavaScript 的 Visual Viewport API 进行访问和修改。例如，开发者可以使用 JavaScript 监听 `resize` 事件，并根据当前的 `viewport-fit` 值调整页面布局。
     - **`Fullscreen API`:** 测试代码使用 `Fullscreen::RequestFullscreen` 和 `Fullscreen::FullyExitFullscreen` 等方法来模拟进入和退出全屏的操作，这与 Web 开发者在 JavaScript 中使用的 `requestFullscreen()` 和 `exitFullscreen()` API 相对应。

   - **HTML:**
     - **`<video>` 元素:** 测试代码首先在 HTML 文档中创建了一个 `<video id=video>` 元素，所有的测试操作都是针对这个视频元素进行的。`MediaControlsDisplayCutoutDelegate` 的作用对象就是 HTML 中的视频元素。

   - **CSS:**
     - **`viewport-fit` 属性:** `MediaControlsDisplayCutoutDelegate` 的核心功能就是控制视频元素的 `viewport-fit` CSS 属性。当用户进行放大手势时，该 delegate 会使得浏览器内部将该属性设置为 `cover`，让视频填充整个视口，包括刘海区域。当缩小手势时，会恢复为默认的 `auto` 值。

   **举例说明:**

   - **用户操作:** 用户在一个包含 `<video>` 元素的网页上，点击全屏按钮，然后用两个手指在视频上做一个放大的捏合手势。
   - **内部机制:** 浏览器捕获到 `touchstart` 和 `touchmove` 事件，`MediaControlsDisplayCutoutDelegate` 分析触摸点的变化，判断这是一个放大手势。
   - **结果:** `MediaControlsDisplayCutoutDelegate` 通知浏览器将视频的 `viewport-fit` 设置为 `cover`。 这相当于浏览器内部应用了类似 `video { viewport-fit: cover; }` 的 CSS 规则。

**3. 逻辑推理 (假设输入与输出):**

   **假设输入：**

   - 用户已进入视频全屏模式。
   - 用户在视频上进行了双指触摸，初始触摸点分别为 (1, 1) 和 (-1, -1)。
   - 用户移动手指，新的触摸点分别为 (4, 4) 和 (-4, -4)。
   - 用户抬起手指。

   **输出：**

   - `MediaControlsDisplayCutoutDelegate` 判断这是一个放大手势 (`DirectionIsExpanding()` 返回 true)。
   - 视频的 `viewport-fit` 属性被设置为 `kCoverForcedByUserAgent` (`CurrentViewportFit()` 返回 `mojom::ViewportFit::kCoverForcedByUserAgent`)。
   - Chromium 的 UseCounter 记录了 `WebFeature::kMediaControlsDisplayCutoutGesture` 的使用。

   **假设输入（反例）：**

   - 用户未进入视频全屏模式。
   - 用户在视频上进行了相同的放大手势。

   **输出：**

   - `MediaControlsDisplayCutoutDelegate` 不会进行任何操作。
   - 视频的 `viewport-fit` 属性保持不变 (`CurrentViewportFit()` 返回 `mojom::ViewportFit::kAuto`)。
   - Chromium 的 UseCounter 不会记录 `WebFeature::kMediaControlsDisplayCutoutGesture` 的使用。

**4. 用户或编程常见的使用错误：**

   - **用户错误:**
     - **误触:** 用户可能在观看全屏视频时不小心进行了双指捏合手势，导致视频的显示模式意外改变。例如，本来只想滑动切换控制栏，结果误操作触发了 `viewport-fit` 的改变。
     - **不理解手势:** 用户可能不清楚这个手势的作用，导致对视频显示效果的困惑。

   - **编程错误 (如果 `MediaControlsDisplayCutoutDelegate` 实现不正确):**
     - **手势方向判断错误:**  Delegate 可能错误地将缩小手势识别为放大手势，反之亦然。 这会导致 `viewport-fit` 设置错误。
     - **状态管理错误:** Delegate 可能在手势未完成时就错误地更新了状态，或者在手势结束后没有正确清理状态，导致后续手势判断异常。
     - **边界情况处理不足:**  Delegate 可能在非全屏模式下或者单指触摸时错误地执行了操作。

**5. 用户操作是如何一步步的到达这里，作为调试线索：**

   1. **加载包含视频的网页:** 用户在浏览器中打开一个包含 `<video>` 标签的网页。
   2. **进入全屏:** 用户点击视频播放器上的全屏按钮（通常由浏览器或网页自定义实现）。这将调用浏览器的全屏 API。
   3. **触摸事件发生:** 用户用两个手指触摸视频画面。浏览器会捕获 `touchstart` 事件。
   4. **手指移动:** 用户移动两个手指，进行捏合操作。浏览器会不断捕获 `touchmove` 事件。
   5. **`MediaControlsDisplayCutoutDelegate` 介入:**
      - 在 `HTMLVideoElement` 处理触摸事件的过程中，相关的逻辑会调用到 `MediaControlsImpl`，而 `MediaControlsImpl` 中会持有 `MediaControlsDisplayCutoutDelegate` 的实例。
      - `MediaControlsDisplayCutoutDelegate` 会监听这些触摸事件，并根据触摸点的变化计算手势的方向和幅度。
   6. **判断手势类型:** `MediaControlsDisplayCutoutDelegate` 根据触摸点的距离变化判断是放大还是缩小手势。
   7. **修改 `viewport-fit`:** 如果判断是放大手势，且当前处于全屏模式，`MediaControlsDisplayCutoutDelegate` 会通知渲染引擎修改视频元素的 `viewport-fit` 属性，使其填充整个屏幕。 这通常涉及到调用 Blink 内部的布局和渲染相关的接口。
   8. **手指抬起:** 用户抬起手指。浏览器会捕获 `touchend` 事件，`MediaControlsDisplayCutoutDelegate` 会清理手势状态。

   **调试线索:**

   - 如果在调试过程中发现全屏视频的 `viewport-fit` 行为异常，可以设置断点在 `MediaControlsDisplayCutoutDelegate` 的触摸事件处理函数中，例如 `HandleTouchStartEvent`, `HandleTouchMoveEvent`, `HandleTouchEndEvent` 等。
   - 可以查看 `previous_` 成员变量，了解 Delegate 是否记录了上次的手势状态。
   - 可以检查 `CurrentViewportFit()` 的返回值，确认 `viewport-fit` 是否被正确设置。
   - 可以检查 UseCounter 的记录，确认手势事件是否被正确统计。
   - 可以使用 Chromium 的 DevTools 中的 "Event Listeners" 面板，查看视频元素上注册的触摸事件监听器，以及事件触发的顺序。

总而言之，`media_controls_display_cutout_delegate_test.cc` 这个测试文件确保了 Chromium 引擎能够正确处理用户在全屏视频上的双指捏合手势，并根据这些手势动态调整视频的显示方式，以更好地适应有屏幕刘海的设备。它涵盖了手势识别、状态管理、以及与 CSS `viewport-fit` 属性的交互等关键功能。

Prompt: 
```
这是目录为blink/renderer/modules/media_controls/media_controls_display_cutout_delegate_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/media_controls/media_controls_display_cutout_delegate.h"
#include "third_party/blink/renderer/core/page/page_animator.h"

#include "third_party/blink/public/mojom/page/display_cutout.mojom-blink.h"
#include "third_party/blink/renderer/core/dom/scripted_animation_controller.h"
#include "third_party/blink/renderer/core/events/touch_event.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/viewport_data.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/fullscreen/fullscreen.h"
#include "third_party/blink/renderer/core/html/media/html_video_element.h"
#include "third_party/blink/renderer/core/input/touch.h"
#include "third_party/blink/renderer/core/input/touch_list.h"
#include "third_party/blink/renderer/core/loader/empty_clients.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/modules/media_controls/media_controls_impl.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"

namespace blink {

namespace {

class DisplayCutoutMockChromeClient : public EmptyChromeClient {
 public:
  // ChromeClient overrides:
  void EnterFullscreen(LocalFrame& frame,
                       const FullscreenOptions*,
                       FullscreenRequestType) override {
    Fullscreen::DidResolveEnterFullscreenRequest(*frame.GetDocument(),
                                                 true /* granted */);
  }
  void ExitFullscreen(LocalFrame& frame) override {
    Fullscreen::DidExitFullscreen(*frame.GetDocument());
  }
};

}  // namespace

class MediaControlsDisplayCutoutDelegateTest
    : public PageTestBase,
      private ScopedDisplayCutoutAPIForTest,
      private ScopedMediaControlsExpandGestureForTest {
 public:
  MediaControlsDisplayCutoutDelegateTest()
      : ScopedDisplayCutoutAPIForTest(true),
        ScopedMediaControlsExpandGestureForTest(true) {}
  void SetUp() override {
    chrome_client_ = MakeGarbageCollected<DisplayCutoutMockChromeClient>();
    SetupPageWithClients(chrome_client_,
                         MakeGarbageCollected<EmptyLocalFrameClient>());
    GetDocument().write("<body><video id=video></body>");
  }

  void SimulateEnterFullscreen() {
    {
      LocalFrame::NotifyUserActivation(
          GetDocument().GetFrame(),
          mojom::UserActivationNotificationType::kTest);
      Fullscreen::RequestFullscreen(GetVideoElement());
    }

    test::RunPendingTasks();
    PageAnimator::ServiceScriptedAnimations(
        base::TimeTicks(),
        {{GetDocument().GetScriptedAnimationController(), false}});

    EXPECT_TRUE(GetVideoElement().IsFullscreen());
  }

  void SimulateExitFullscreen() {
    Fullscreen::FullyExitFullscreen(GetDocument());

    PageAnimator::ServiceScriptedAnimations(
        base::TimeTicks(),
        {{GetDocument().GetScriptedAnimationController(), false}});

    EXPECT_FALSE(GetVideoElement().IsFullscreen());
  }

  void SimulateContractingGesture() {
    TouchList* list = CreateTouchListWithTwoPoints(5, 5, -5, -5);
    SimulateEvent(
        CreateTouchEventWithList(event_type_names::kTouchstart, list));

    list = CreateTouchListWithTwoPoints(4, 4, -4, -4);
    SimulateEvent(CreateTouchEventWithList(event_type_names::kTouchmove, list));

    list = CreateTouchListWithTwoPoints(0, 0, 0, 0);
    SimulateEvent(CreateTouchEventWithList(event_type_names::kTouchend, list));
  }

  void SimulateExpandingGesture() {
    TouchList* list = CreateTouchListWithTwoPoints(1, 1, -1, -1);
    SimulateEvent(
        CreateTouchEventWithList(event_type_names::kTouchstart, list));

    list = CreateTouchListWithTwoPoints(4, 4, -4, -4);
    SimulateEvent(CreateTouchEventWithList(event_type_names::kTouchmove, list));

    list = CreateTouchListWithTwoPoints(5, 5, -5, -5);
    SimulateEvent(CreateTouchEventWithList(event_type_names::kTouchend, list));
  }

  void SimulateSingleTouchGesture() {
    TouchList* list = CreateTouchListWithOnePoint(1, 1);
    SimulateEvent(
        CreateTouchEventWithList(event_type_names::kTouchstart, list));

    list = CreateTouchListWithOnePoint(4, 4);
    SimulateEvent(CreateTouchEventWithList(event_type_names::kTouchmove, list));

    list = CreateTouchListWithOnePoint(5, 5);
    SimulateEvent(CreateTouchEventWithList(event_type_names::kTouchend, list));
  }

  bool HasGestureState() { return GetDelegate().previous_.has_value(); }

  bool DirectionIsExpanding() {
    return GetDelegate().previous_->second ==
           MediaControlsDisplayCutoutDelegate::Direction::kExpanding;
  }

  bool DirectionIsUnknown() {
    return GetDelegate().previous_->second ==
           MediaControlsDisplayCutoutDelegate::Direction::kUnknown;
  }

  void SimulateEvent(TouchEvent* event) {
    DCHECK(event);
    GetVideoElement().FireEventListeners(*event);
  }

  TouchList* CreateTouchListWithOnePoint(int x, int y) {
    TouchList* list = TouchList::Create();
    list->Append(CreateTouchAtPoint(x, y));
    return list;
  }

  TouchList* CreateTouchListWithTwoPoints(int x1, int y1, int x2, int y2) {
    TouchList* list = TouchList::Create();
    list->Append(CreateTouchAtPoint(x1, y1));
    list->Append(CreateTouchAtPoint(x2, y2));
    return list;
  }

  TouchEvent* CreateTouchEventWithList(const AtomicString& type,
                                       TouchList* list) {
    TouchEvent* event = TouchEvent::Create();
    event->initEvent(type, true, false);
    event->SetTouches(list);
    return event;
  }

  Touch* CreateTouchAtPoint(int x, int y) {
    return Touch::Create(GetDocument().GetFrame(), &GetVideoElement(),
                         1 /* identifier */, gfx::PointF(x, y),
                         gfx::PointF(x, y), gfx::SizeF(1, 1), 90, 0);
  }

  mojom::ViewportFit CurrentViewportFit() const {
    return GetDocument().GetViewportData().GetCurrentViewportFitForTests();
  }

 private:
  MediaControlsDisplayCutoutDelegate& GetDelegate() {
    MediaControlsImpl* controls =
        static_cast<MediaControlsImpl*>(GetVideoElement().GetMediaControls());
    return *controls->display_cutout_delegate_;
  }

  HTMLVideoElement& GetVideoElement() {
    return *To<HTMLVideoElement>(
        GetDocument().getElementById(AtomicString("video")));
  }

  Persistent<DisplayCutoutMockChromeClient> chrome_client_;
};

TEST_F(MediaControlsDisplayCutoutDelegateTest, CombinedGesture) {
  SimulateEnterFullscreen();

  // Simulate the an expanding gesture but do not finish it.
  TouchList* list = CreateTouchListWithTwoPoints(1, 1, -1, -1);
  SimulateEvent(CreateTouchEventWithList(event_type_names::kTouchstart, list));
  list = CreateTouchListWithTwoPoints(4, 4, -4, -4);
  SimulateEvent(CreateTouchEventWithList(event_type_names::kTouchmove, list));

  // Check the viewport fit value has been correctly set.
  EXPECT_EQ(mojom::ViewportFit::kCoverForcedByUserAgent, CurrentViewportFit());

  // Finish the gesture by contracting.
  list = CreateTouchListWithTwoPoints(0, 0, 0, 0);
  SimulateEvent(CreateTouchEventWithList(event_type_names::kTouchend, list));

  // Check the viewport fit value has been correctly set.
  EXPECT_EQ(mojom::ViewportFit::kAuto, CurrentViewportFit());

  // Make sure we recorded a UseCounter metric.
  EXPECT_TRUE(GetDocument().IsUseCounted(
      WebFeature::kMediaControlsDisplayCutoutGesture));
}

TEST_F(MediaControlsDisplayCutoutDelegateTest, ContractingGesture) {
  // Go fullscreen and simulate an expanding gesture.
  SimulateEnterFullscreen();
  SimulateExpandingGesture();

  // Check the viewport fit value has been correctly set.
  EXPECT_EQ(mojom::ViewportFit::kCoverForcedByUserAgent, CurrentViewportFit());

  // Simulate a contracting gesture and check the value has been restored.
  SimulateContractingGesture();
  EXPECT_EQ(mojom::ViewportFit::kAuto, CurrentViewportFit());

  // Make sure we recorded a UseCounter metric.
  EXPECT_TRUE(GetDocument().IsUseCounted(
      WebFeature::kMediaControlsDisplayCutoutGesture));
}

TEST_F(MediaControlsDisplayCutoutDelegateTest, ContractingGesture_Noop) {
  // Go fullscreen and simulate a contracting gesture.
  SimulateEnterFullscreen();
  SimulateContractingGesture();

  // Check that the value did not change.
  EXPECT_EQ(mojom::ViewportFit::kAuto, CurrentViewportFit());
}

TEST_F(MediaControlsDisplayCutoutDelegateTest, ExpandingGesture) {
  // Go fullscreen and simulate an expanding gesture.
  SimulateEnterFullscreen();
  SimulateExpandingGesture();

  // Check the viewport fit value has been correctly set.
  EXPECT_EQ(mojom::ViewportFit::kCoverForcedByUserAgent, CurrentViewportFit());

  // Exit fullscreen and check the value has been restored.
  SimulateExitFullscreen();
  EXPECT_EQ(mojom::ViewportFit::kAuto, CurrentViewportFit());

  // Make sure we recorded a UseCounter metric.
  EXPECT_TRUE(GetDocument().IsUseCounted(
      WebFeature::kMediaControlsDisplayCutoutGesture));
}

TEST_F(MediaControlsDisplayCutoutDelegateTest, ExpandingGesture_DoubleNoop) {
  // Go fullscreen and simulate an expanding gesture.
  SimulateEnterFullscreen();
  SimulateExpandingGesture();

  // Check the viewport fit value has been correctly set.
  EXPECT_EQ(mojom::ViewportFit::kCoverForcedByUserAgent, CurrentViewportFit());

  // Simulate another expanding gesture and make sure nothing changed.
  SimulateExpandingGesture();
  EXPECT_EQ(mojom::ViewportFit::kCoverForcedByUserAgent, CurrentViewportFit());
}

TEST_F(MediaControlsDisplayCutoutDelegateTest, IncompleteGestureClearsState) {
  SimulateEnterFullscreen();

  // Simulate a gesture and check we have state.
  TouchList* list = CreateTouchListWithTwoPoints(1, 1, -1, -1);
  SimulateEvent(CreateTouchEventWithList(event_type_names::kTouchstart, list));

  list = CreateTouchListWithTwoPoints(2, 2, -2, -2);
  SimulateEvent(CreateTouchEventWithList(event_type_names::kTouchmove, list));
  EXPECT_TRUE(DirectionIsExpanding());

  // Simulate another start gesture and make sure we do not have a direction.
  list = CreateTouchListWithTwoPoints(3, 3, -3, -3);
  SimulateEvent(CreateTouchEventWithList(event_type_names::kTouchstart, list));
  EXPECT_TRUE(DirectionIsUnknown());
}

TEST_F(MediaControlsDisplayCutoutDelegateTest, MetricsNoop) {
  EXPECT_FALSE(GetDocument().IsUseCounted(
      WebFeature::kMediaControlsDisplayCutoutGesture));
}

TEST_F(MediaControlsDisplayCutoutDelegateTest, NoFullscreen_Noop) {
  // Simulate an expanding gesture and make sure it had no effect.
  SimulateExpandingGesture();
  EXPECT_EQ(mojom::ViewportFit::kAuto, CurrentViewportFit());
}

TEST_F(MediaControlsDisplayCutoutDelegateTest, SingleTouchGesture_Noop) {
  // Simulate a single touch gesture and make sure it had no effect.
  SimulateEnterFullscreen();
  SimulateSingleTouchGesture();
  EXPECT_EQ(mojom::ViewportFit::kCoverForcedByUserAgent, CurrentViewportFit());
}

TEST_F(MediaControlsDisplayCutoutDelegateTest, TouchCancelShouldClearState) {
  SimulateEnterFullscreen();

  // Simulate a gesture and check we have state.
  TouchList* list = CreateTouchListWithTwoPoints(1, 1, -1, -1);
  SimulateEvent(CreateTouchEventWithList(event_type_names::kTouchstart, list));
  EXPECT_TRUE(HasGestureState());

  // Simulate a touchcancel gesture and check that clears the state.
  list = CreateTouchListWithTwoPoints(1, 1, -1, -1);
  SimulateEvent(CreateTouchEventWithList(event_type_names::kTouchcancel, list));
  EXPECT_FALSE(HasGestureState());
  EXPECT_EQ(mojom::ViewportFit::kCoverForcedByUserAgent, CurrentViewportFit());
}

TEST_F(MediaControlsDisplayCutoutDelegateTest, TouchEndShouldClearState) {
  SimulateEnterFullscreen();

  // Simulate a gesture and check we have state.
  TouchList* list = CreateTouchListWithTwoPoints(1, 1, -1, -1);
  SimulateEvent(CreateTouchEventWithList(event_type_names::kTouchstart, list));
  EXPECT_TRUE(HasGestureState());

  // Simulate a touchend gesture and check that clears the state.
  list = CreateTouchListWithTwoPoints(1, 1, -1, -1);
  SimulateEvent(CreateTouchEventWithList(event_type_names::kTouchend, list));
  EXPECT_FALSE(HasGestureState());
  EXPECT_EQ(mojom::ViewportFit::kCoverForcedByUserAgent, CurrentViewportFit());
}

TEST_F(MediaControlsDisplayCutoutDelegateTest, DefaultExpand) {
  SimulateEnterFullscreen();
  EXPECT_EQ(mojom::ViewportFit::kCoverForcedByUserAgent, CurrentViewportFit());
}

}  // namespace blink

"""

```