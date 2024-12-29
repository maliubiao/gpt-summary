Response:
Let's break down the thought process for analyzing this code snippet and generating the response.

**1. Understanding the Goal:**

The request asks for an analysis of a specific Chromium source file (`media_controls_orientation_lock_delegate_test.cc`). The key requirements are to identify its functionality, its relation to web technologies (JavaScript, HTML, CSS), provide examples, explain logical reasoning with hypothetical inputs/outputs, highlight common usage errors, describe user interaction leading to this code, and finally, summarize its purpose. The "part 1 of 2" indicates this is an initial analysis focusing on the first part of the file.

**2. Initial Code Scan and Keyword Identification:**

The first step is to quickly scan the code for keywords and structures. This helps to get a general idea of the file's purpose. Key observations from the initial scan:

* **`_test.cc` suffix:**  This immediately signals that this is a test file. It's not the actual implementation code.
* **Includes:** The included headers provide valuable clues. We see:
    * `media_controls_orientation_lock_delegate.h`:  This tells us the code is testing a class named `MediaControlsOrientationLockDelegate`.
    * `testing/gmock/include/gmock/gmock.h`, `testing/gtest/include/gtest/gtest.h`:  Indicates the use of Google Mock and Google Test frameworks for unit testing.
    * Headers related to `mojo`, `device/public/mojom/screen_orientation.mojom-blink.h`: Suggests interaction with system-level orientation services via Mojo.
    * `core/dom/document.h`, `core/frame/...`, `core/html/media/...`:  Shows interaction with the Blink rendering engine's DOM, frames, and media elements.
    * `modules/screen_orientation/...`:  Points to the involvement of the Screen Orientation API.
* **Class names:** `DummyScreenOrientationCallback`, `MockWebMediaPlayerForOrientationLockDelegate`, `MockScreenOrientation`, `MockChromeClientForOrientationLockDelegate`, `StubLocalFrameClientForOrientationLockDelegate`, `MediaControlsOrientationLockDelegateTest`, `MediaControlsOrientationLockAndRotateToFullscreenDelegateTest`:  The "Mock" prefix strongly suggests these are mock objects used for testing.
* **Test functions:** `TEST_F(...)`:  Confirms this is a test file. The names of the test functions (e.g., `DelegateRequiresFlag`, `InitialState`, `EnterFullscreenNoMetadata`) hint at the specific aspects being tested.

**3. Deduce the Core Functionality:**

Based on the includes and class names, it becomes clear that this test file is specifically designed to test the `MediaControlsOrientationLockDelegate` class. This delegate seems to be responsible for managing screen orientation locking behavior when media (specifically video) is in fullscreen mode. The presence of `MockScreenOrientation` suggests that the delegate interacts with the system's screen orientation capabilities.

**4. Identify Connections to Web Technologies:**

* **HTML:** The inclusion of `HTMLVideoElement` and the use of `GetDocument().write("<video>")` clearly show a connection to HTML. The tests manipulate video elements.
* **JavaScript:** While no direct JavaScript code is in this C++ file, the tested functionality is exposed to JavaScript via the Screen Orientation API. The tests implicitly cover how JavaScript interactions would trigger the delegate's logic. The `ScreenOrientationController` is a bridge between JavaScript and the underlying platform.
* **CSS:** While not directly manipulated, CSS is relevant because fullscreen mode can involve CSS changes. The tests indirectly assess how the orientation lock interacts with the visual presentation in fullscreen.

**5. Logical Reasoning and Examples:**

The test names themselves provide good starting points for constructing hypothetical input/output scenarios.

* **`EnterFullscreenNoMetadata`:**  *Input:* A video element enters fullscreen before metadata is loaded. *Output:*  No screen orientation lock is attempted.
* **`EnterFullscreenWithMetadata`:** *Input:* A video element enters fullscreen after metadata is loaded. *Output:* A screen orientation lock based on the video's aspect ratio is requested.
* **`LeaveFullscreenWithMetadata`:** *Input:* A video is in fullscreen with a screen lock, then exits fullscreen. *Output:* The screen orientation lock is released.

**6. Common Usage Errors:**

Think about how a developer might misuse the related APIs.

* **Forgetting User Activation:** The tests use `LocalFrame::NotifyUserActivation`. A common error would be trying to enter fullscreen or lock orientation without proper user interaction, which would be blocked by browsers.
* **Incorrectly Handling Promises (though not directly shown):** While not explicitly in this file, the Screen Orientation API involves Promises in JavaScript. Incorrect error handling or chaining of these promises would be a common mistake.

**7. User Interaction and Debugging Clues:**

Trace the user's actions:

1. User opens a web page containing a video.
2. User interacts with the video (e.g., clicks the fullscreen button).
3. The browser's rendering engine (Blink) processes this request.
4. The `MediaControlsOrientationLockDelegate` (the code being tested) is involved in deciding whether and how to lock the screen orientation during fullscreen.

Debugging clues: If screen orientation locking isn't working as expected for a video in fullscreen, this test file provides insights into the logic that might be failing. A developer might look at the conditions under which the delegate requests or releases a screen lock.

**8. Summarization:**

Combine the key findings to provide a concise summary of the file's purpose. It's a unit test file for the `MediaControlsOrientationLockDelegate`, which manages screen orientation locking during video fullscreen in Chromium.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe this file directly manipulates the screen orientation.
* **Correction:**  The use of `MockScreenOrientation` reveals it *tests* the interaction with the screen orientation service, rather than implementing it directly.
* **Initial thought:** Focus only on the explicitly mentioned JavaScript, HTML, and CSS.
* **Refinement:**  Recognize that even though the code is C++, it's testing functionality directly related to these web technologies and how they interact with the browser's media controls.

By following these steps, systematically examining the code, and considering the broader context of web development and browser functionality, we can arrive at a comprehensive and accurate analysis like the example provided in the initial prompt.好的，这是对 `blink/renderer/modules/media_controls/media_controls_orientation_lock_delegate_test.cc` 文件功能的归纳：

**功能归纳:**

该C++测试文件 `media_controls_orientation_lock_delegate_test.cc` 的主要功能是 **测试 `MediaControlsOrientationLockDelegate` 类的行为和逻辑**。  `MediaControlsOrientationLockDelegate` 类的核心职责是 **管理在视频进入全屏模式时，是否以及如何锁定屏幕方向**。

具体来说，该测试文件通过以下方式验证 `MediaControlsOrientationLockDelegate` 的功能：

1. **模拟不同的场景和状态:**  例如，视频是否已加载元数据，是否已经进入或退出全屏，页面是否已经锁定了屏幕方向等等。
2. **使用 Mock 对象:**  创建和使用模拟（Mock）对象，例如 `MockScreenOrientation` (模拟屏幕方向服务)，`MockWebMediaPlayerForOrientationLockDelegate` (模拟 WebMediaPlayer)，`MockChromeClientForOrientationLockDelegate` (模拟 Chrome 客户端)，以便隔离被测试单元，并精确控制依赖项的行为。
3. **断言预期行为:**  使用 Google Test 和 Google Mock 框架提供的断言机制 (`EXPECT_CALL`, `EXPECT_TRUE`, `EXPECT_EQ` 等) 来验证 `MediaControlsOrientationLockDelegate` 在不同场景下是否执行了预期的操作，例如：
    * 是否调用了 `ScreenOrientation` 接口的 `LockOrientation` 和 `UnlockOrientation` 方法。
    * 锁定的屏幕方向是否符合预期 (例如，根据视频的宽高比)。
    * 内部状态 (例如 `state_`, `locked_orientation_`) 的变化是否符合预期。
4. **测试在有和没有 "视频全屏方向锁定" 功能标志的情况下的行为。**
5. **测试在有和没有 "视频旋转至全屏" 功能标志的情况下的行为，并涉及到设备方向的计算。**

**与 Javascript, HTML, CSS 的关系 (间接但重要):**

尽管此文件是 C++ 代码，但它测试的功能直接关系到 Web 开发者可以使用 JavaScript API (`Screen Orientation API`) 以及 HTML `<video>` 元素来实现的功能。

* **JavaScript (Screen Orientation API):**  `MediaControlsOrientationLockDelegate` 的目标是自动化和优化在视频全屏时使用 `Screen Orientation API` 的过程。例如，当用户将一个横向视频切换到全屏时，浏览器可能会自动锁定屏幕方向为横向。测试会验证这个自动化过程是否按预期工作。
    * **举例说明:** JavaScript 代码可以使用 `screen.orientation.lock('landscape')` 来锁定屏幕方向。 `MediaControlsOrientationLockDelegate` 的功能是 *在用户没有显式调用这个 API 的情况下*，根据视频内容和状态，*自动* 执行类似的操作。
* **HTML (`<video>` 元素):** 该测试文件围绕 `<video>` 元素展开。全屏操作通常由用户与视频播放器的控件交互触发。测试模拟了视频进入和退出全屏的状态变化。
    * **举例说明:** 用户点击视频播放器的全屏按钮，这个用户操作最终会导致浏览器调用 `Fullscreen::RequestFullscreen(Video())`，而 `MediaControlsOrientationLockDelegate` 会监听这个事件并采取相应的操作。
* **CSS (间接关系):**  全屏模式通常伴随着 CSS 样式的改变，以使视频占据整个屏幕。虽然此测试文件不直接测试 CSS，但屏幕方向的锁定是为了提供更好的全屏观看体验，这与 CSS 的目标是一致的。

**逻辑推理、假设输入与输出 (部分在 `MediaControlsOrientationLockAndRotateToFullscreenDelegateTest` 中体现):**

* **假设输入 (针对 `ComputeOrientationLock` 测试):**
    * 视频已加载元数据。
    * 视频的自然尺寸为 100x50 (宽 > 高)。
    * 用户将视频切换到全屏。
* **预期输出:**
    * `ComputeOrientationLock()` 方法应该返回 `device::mojom::ScreenOrientationLockType::LANDSCAPE`，因为视频是横向的。
    * 测试会断言 `ScreenOrientationClient().LockOrientation()` 方法被调用，并且传入的参数是 `device::mojom::ScreenOrientationLockType::LANDSCAPE`。

* **假设输入 (针对 `ComputeDeviceOrientation` 测试):**
    * 设备自然方向是竖屏。
    * 设备当前屏幕方向是横屏 (角度 90 度)。
    * 设备传感器报告 Beta=0, Gamma=-90 (对应物理上的横向握持)。
* **预期输出:**
    * `ComputeDeviceOrientation()` 方法应该返回 `MediaControlsOrientationLockDelegate::DeviceOrientationType::kLandscape`。

**用户或编程常见的使用错误 (虽然测试文件不直接体现，但其目的是预防这些错误):**

* **尝试在没有用户激活的情况下锁定屏幕方向:**  浏览器通常要求锁定屏幕方向的操作必须由用户主动触发（例如，点击按钮）。如果 `MediaControlsOrientationLockDelegate` 的实现不正确，可能会在不应该锁定的时候尝试锁定，导致操作被浏览器阻止。
* **在不合适的时机解锁屏幕方向:** 例如，在视频仍然处于全屏状态时过早解锁屏幕方向，可能会导致用户体验不佳。
* **没有考虑到设备的自然方向和当前屏幕方向:**  在计算应该锁定的方向时，需要考虑设备的物理特性和用户当前的屏幕方向设置。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户访问包含 `<video>` 元素的网页。**
2. **视频元素加载并准备播放。**
3. **用户点击视频播放器提供的全屏按钮 (或使用浏览器快捷键进入全屏)。**
4. **浏览器接收到全屏请求。**
5. **Blink 渲染引擎处理全屏请求。**
6. **`MediaControlsImpl` (视频播放器的控制逻辑) 创建或获取 `MediaControlsOrientationLockDelegate` 的实例。**
7. **`MediaControlsOrientationLockDelegate` 监听全屏事件以及视频状态变化事件 (例如，元数据加载完成)。**
8. **根据当前状态 (是否全屏，是否加载元数据，视频宽高比等)，`MediaControlsOrientationLockDelegate` 决定是否需要请求锁定屏幕方向。**
9. **如果需要锁定，`MediaControlsOrientationLockDelegate` 通过 Mojo 接口与屏幕方向服务进行通信，请求锁定到特定的方向。**

**作为调试线索:** 如果开发者发现他们的网页在视频进入全屏时，屏幕方向的锁定行为不符合预期 (例如，应该锁定为横向但没有锁定)，他们可能会查看 `MediaControlsOrientationLockDelegate` 的代码和相关的测试文件，以理解浏览器的内部逻辑是如何工作的，并找到他们代码中可能导致问题的部分。 `media_controls_orientation_lock_delegate_test.cc` 提供了各种场景的测试用例，可以帮助开发者理解在哪些情况下浏览器会锁定屏幕方向，以及预期的锁定方向是什么。

**总结一下它的功能 (第1部分):**

`media_controls_orientation_lock_delegate_test.cc` 文件的主要功能是 **作为 `MediaControlsOrientationLockDelegate` 类的单元测试**。它通过模拟各种用户操作和视频状态，验证 `MediaControlsOrientationLockDelegate` 是否能够正确地判断在视频进入全屏时是否需要锁定屏幕方向，以及应该锁定到哪个方向，从而确保 Chromium 浏览器在处理视频全屏时的屏幕方向锁定功能能够按预期工作。

Prompt: 
```
这是目录为blink/renderer/modules/media_controls/media_controls_orientation_lock_delegate_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/media_controls/media_controls_orientation_lock_delegate.h"

#include <memory>

#include "mojo/public/cpp/bindings/associated_remote.h"
#include "mojo/public/cpp/bindings/pending_associated_receiver.h"
#include "services/device/public/mojom/screen_orientation.mojom-blink.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/scripted_animation_controller.h"
#include "third_party/blink/renderer/core/frame/frame_view.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/fullscreen/fullscreen.h"
#include "third_party/blink/renderer/core/html/media/html_audio_element.h"
#include "third_party/blink/renderer/core/html/media/html_video_element.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/loader/empty_clients.h"
#include "third_party/blink/renderer/core/page/page_animator.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/modules/device_orientation/device_orientation_controller.h"
#include "third_party/blink/renderer/modules/device_orientation/device_orientation_data.h"
#include "third_party/blink/renderer/modules/media_controls/media_controls_impl.h"
#include "third_party/blink/renderer/modules/screen_orientation/screen_orientation_controller.h"
#include "third_party/blink/renderer/modules/screen_orientation/web_lock_orientation_callback.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/mojo/heap_mojo_associated_receiver.h"
#include "third_party/blink/renderer/platform/testing/empty_web_media_player.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/web_test_support.h"
#include "third_party/blink/renderer/platform/wtf/gc_plugin.h"
#include "ui/display/mojom/screen_orientation.mojom-blink.h"
#include "ui/gfx/geometry/rect.h"

using testing::_;

namespace blink {

namespace {

// WebLockOrientationCallback implementation that will not react to a success
// nor a failure.
class DummyScreenOrientationCallback final : public WebLockOrientationCallback {
 public:
  void OnSuccess() override {}
  void OnError(WebLockOrientationError) override {}
};

class MockWebMediaPlayerForOrientationLockDelegate final
    : public EmptyWebMediaPlayer {
 public:
  ~MockWebMediaPlayerForOrientationLockDelegate() override = default;

  // EmptyWebMediaPlayer overrides:
  bool HasVideo() const override { return true; }
  gfx::Size NaturalSize() const override { return mock_natural_size_; }

  gfx::Size& MockNaturalSize() { return mock_natural_size_; }

 private:
  gfx::Size mock_natural_size_ = {};
};

class MockScreenOrientation final
    : public GarbageCollected<MockScreenOrientation>,
      public device::mojom::blink::ScreenOrientation {
 public:
  MockScreenOrientation() = default;

  // device::mojom::blink::ScreenOrientation overrides:
  void LockOrientation(device::mojom::ScreenOrientationLockType type,
                       LockOrientationCallback callback) override {
    std::move(callback).Run(device::mojom::ScreenOrientationLockResult::
                                SCREEN_ORIENTATION_LOCK_RESULT_SUCCESS);
    LockOrientation(type);
  }
  MOCK_METHOD(void, UnlockOrientation, (), (override));

  void BindPendingReceiver(
      mojo::PendingAssociatedReceiver<device::mojom::blink::ScreenOrientation>
          pending_receiver,
      scoped_refptr<base::SequencedTaskRunner> task_runner) {
    receiver_.Bind(std::move(pending_receiver), task_runner);
  }

  void Close() { receiver_.reset(); }

  void Trace(Visitor* visitor) const { visitor->Trace(receiver_); }

  MOCK_METHOD(void,
              LockOrientation,
              (device::mojom::ScreenOrientationLockType));

 private:
  // MockScreenOrientation is not tied to ExecutionContext.
  HeapMojoAssociatedReceiver<device::mojom::blink::ScreenOrientation,
                             MockScreenOrientation>
      receiver_{this, nullptr};
};

void DidEnterFullscreen(Document* document) {
  DCHECK(document);
  Fullscreen::DidResolveEnterFullscreenRequest(*document, true /* granted */);
  PageAnimator::ServiceScriptedAnimations(
      base::TimeTicks::Now(),
      {{document->GetScriptedAnimationController(), false}});
}

void DidExitFullscreen(Document* document) {
  DCHECK(document);
  Fullscreen::DidExitFullscreen(*document);
  PageAnimator::ServiceScriptedAnimations(
      base::TimeTicks::Now(),
      {{document->GetScriptedAnimationController(), false}});
}

class MockChromeClientForOrientationLockDelegate final
    : public EmptyChromeClient {
 public:
  MockChromeClientForOrientationLockDelegate()
      : mock_screen_orientation_(
            MakeGarbageCollected<MockScreenOrientation>()) {}

  // ChromeClient overrides:
  void InstallSupplements(LocalFrame& frame) override {
    EmptyChromeClient::InstallSupplements(frame);
    HeapMojoAssociatedRemote<device::mojom::blink::ScreenOrientation>
        screen_orientation(frame.DomWindow());
    ScreenOrientationClient().BindPendingReceiver(
        screen_orientation.BindNewEndpointAndPassDedicatedReceiver(),
        frame.GetTaskRunner(TaskType::kInternalNavigationAssociated));
    ScreenOrientationController::From(*frame.DomWindow())
        ->SetScreenOrientationAssociatedRemoteForTests(
            std::move(screen_orientation));
  }
  // The real ChromeClient::EnterFullscreen/ExitFullscreen implementation is
  // async due to IPC, emulate that by posting tasks:
  void EnterFullscreen(LocalFrame& frame,
                       const FullscreenOptions*,
                       FullscreenRequestType) override {
    frame.GetTaskRunner(TaskType::kInternalNavigationAssociated)
        ->PostTask(FROM_HERE,
                   WTF::BindOnce(DidEnterFullscreen,
                                 WrapPersistent(frame.GetDocument())));
  }
  void ExitFullscreen(LocalFrame& frame) override {
    frame.GetTaskRunner(TaskType::kInternalNavigationAssociated)
        ->PostTask(FROM_HERE,
                   WTF::BindOnce(DidExitFullscreen,
                                 WrapPersistent(frame.GetDocument())));
  }

  const display::ScreenInfo& GetScreenInfo(LocalFrame&) const override {
    // This dcheck is for the assumption that MockScreenInfo gets the
    // correct (and only) screen info to modify.
    DCHECK_EQ(mock_screen_infos_.screen_infos.size(), 1u);
    return mock_screen_infos_.current();
  }
  const display::ScreenInfos& GetScreenInfos(LocalFrame&) const override {
    DCHECK_EQ(mock_screen_infos_.screen_infos.size(), 1u);
    return mock_screen_infos_;
  }

  display::ScreenInfo& MockScreenInfo() {
    return mock_screen_infos_.mutable_current();
  }

  MockScreenOrientation& ScreenOrientationClient() {
    return *mock_screen_orientation_;
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(mock_screen_orientation_);
    EmptyChromeClient::Trace(visitor);
  }

 private:
  Member<MockScreenOrientation> mock_screen_orientation_;
  display::ScreenInfos mock_screen_infos_ =
      display::ScreenInfos(display::ScreenInfo());
};

class StubLocalFrameClientForOrientationLockDelegate final
    : public EmptyLocalFrameClient {
 public:
  std::unique_ptr<WebMediaPlayer> CreateWebMediaPlayer(
      HTMLMediaElement&,
      const WebMediaPlayerSource&,
      WebMediaPlayerClient*) override {
    return std::make_unique<MockWebMediaPlayerForOrientationLockDelegate>();
  }
};

}  // anonymous namespace

class MediaControlsOrientationLockDelegateTest
    : public PageTestBase,
      private ScopedVideoFullscreenOrientationLockForTest,
      private ScopedVideoRotateToFullscreenForTest {
 public:
  MediaControlsOrientationLockDelegateTest()
      : ScopedVideoFullscreenOrientationLockForTest(true),
        ScopedVideoRotateToFullscreenForTest(false) {}

  explicit MediaControlsOrientationLockDelegateTest(
      bool video_rotate_to_fullscreen)
      : ScopedVideoFullscreenOrientationLockForTest(true),
        ScopedVideoRotateToFullscreenForTest(video_rotate_to_fullscreen) {}

 protected:
  using DeviceOrientationType =
      MediaControlsOrientationLockDelegate::DeviceOrientationType;

  static constexpr base::TimeDelta GetUnlockDelay() {
    return MediaControlsOrientationLockDelegate::kLockToAnyDelay;
  }

  void SetUp() override {
    chrome_client_ =
        MakeGarbageCollected<MockChromeClientForOrientationLockDelegate>();
    SetupPageWithClients(
        chrome_client_,
        MakeGarbageCollected<StubLocalFrameClientForOrientationLockDelegate>());
    previous_orientation_event_value_ =
        RuntimeEnabledFeatures::OrientationEventEnabled();

    GetDocument().write("<body><video></body>");
    video_ = To<HTMLVideoElement>(
        *GetDocument().QuerySelector(AtomicString("video")));
  }

  void TearDown() override {
    testing::Mock::VerifyAndClear(&ScreenOrientationClient());
    ScreenOrientationClient().Close();
    PageTestBase::TearDown();
  }

  static bool HasDelegate(const MediaControls& media_controls) {
    return !!static_cast<const MediaControlsImpl*>(&media_controls)
                 ->orientation_lock_delegate_;
  }

  void SimulateEnterFullscreen() {
    LocalFrame::NotifyUserActivation(
        GetDocument().GetFrame(), mojom::UserActivationNotificationType::kTest);
    Fullscreen::RequestFullscreen(Video());
    test::RunPendingTasks();
  }

  void SimulateExitFullscreen() {
    Fullscreen::ExitFullscreen(GetDocument());
    test::RunPendingTasks();
  }

  void SimulateOrientationLock() {
    ScreenOrientationController* controller =
        ScreenOrientationController::From(*GetDocument().domWindow());
    controller->lock(device::mojom::ScreenOrientationLockType::LANDSCAPE,
                     std::make_unique<DummyScreenOrientationCallback>());
    EXPECT_TRUE(controller->MaybeHasActiveLock());
  }

  void SimulateVideoReadyState(HTMLMediaElement::ReadyState state) {
    Video().SetReadyState(state);
  }

  void SimulateVideoNetworkState(HTMLMediaElement::NetworkState state) {
    Video().SetNetworkState(state);
  }

  MediaControlsImpl* MediaControls() const {
    return static_cast<MediaControlsImpl*>(video_->GetMediaControls());
  }

  void CheckStatePendingFullscreen() const {
    EXPECT_EQ(MediaControlsOrientationLockDelegate::State::kPendingFullscreen,
              MediaControls()->orientation_lock_delegate_->state_);
  }

  void CheckStatePendingMetadata() const {
    EXPECT_EQ(MediaControlsOrientationLockDelegate::State::kPendingMetadata,
              MediaControls()->orientation_lock_delegate_->state_);
  }

  void CheckStateMaybeLockedFullscreen() const {
    EXPECT_EQ(
        MediaControlsOrientationLockDelegate::State::kMaybeLockedFullscreen,
        MediaControls()->orientation_lock_delegate_->state_);
  }

  bool DelegateWillUnlockFullscreen() const {
    return DelegateOrientationLock() !=
           device::mojom::ScreenOrientationLockType::DEFAULT /* unlocked */;
  }

  device::mojom::ScreenOrientationLockType DelegateOrientationLock() const {
    return MediaControls()->orientation_lock_delegate_->locked_orientation_;
  }

  device::mojom::ScreenOrientationLockType ComputeOrientationLock() const {
    return MediaControls()
        ->orientation_lock_delegate_->ComputeOrientationLock();
  }

  MockChromeClientForOrientationLockDelegate& ChromeClient() const {
    return *chrome_client_;
  }

  HTMLVideoElement& Video() const { return *video_; }
  MockScreenOrientation& ScreenOrientationClient() const {
    return ChromeClient().ScreenOrientationClient();
  }
  MockWebMediaPlayerForOrientationLockDelegate& MockWebMediaPlayer() const {
    return *static_cast<MockWebMediaPlayerForOrientationLockDelegate*>(
        Video().GetWebMediaPlayer());
  }

 protected:
  Persistent<MockChromeClientForOrientationLockDelegate> chrome_client_;

 private:
  friend class MediaControlsOrientationLockAndRotateToFullscreenDelegateTest;

  bool previous_orientation_event_value_;
  Persistent<HTMLVideoElement> video_;
};

class MediaControlsOrientationLockAndRotateToFullscreenDelegateTest
    : public MediaControlsOrientationLockDelegateTest,
      private ScopedOrientationEventForTest {
 public:
  MediaControlsOrientationLockAndRotateToFullscreenDelegateTest()
      : MediaControlsOrientationLockDelegateTest(true),
        ScopedOrientationEventForTest(true) {}

 protected:
  enum DeviceNaturalOrientation { kNaturalIsPortrait, kNaturalIsLandscape };

  void SetUp() override {
    MediaControlsOrientationLockDelegateTest::SetUp();

    // Reset the <video> element now we've enabled the runtime feature.
    video_->parentElement()->RemoveChild(video_);
    video_ = MakeGarbageCollected<HTMLVideoElement>(GetDocument());
    video_->setAttribute(html_names::kControlsAttr, g_empty_atom);
    // Most tests should call GetDocument().body()->AppendChild(&Video());
    // This is not done automatically, so that tests control timing of `Attach`,
    // which is important for MediaControlsRotateToFullscreenDelegate since
    // that's when it reads the initial screen orientation.
  }

  void TearDown() override {
    MediaControlsOrientationLockDelegateTest::TearDown();
  }

  void SetIsAutoRotateEnabledByUser(bool enabled) {
    MediaControls()
        ->orientation_lock_delegate_
        ->is_auto_rotate_enabled_by_user_override_for_testing_ = enabled;
  }

  gfx::Rect ScreenRectFromAngle(uint16_t screen_orientation_angle) {
    uint16_t portrait_angle_mod_180 = natural_orientation_is_portrait_ ? 0 : 90;
    bool screen_rect_is_portrait =
        screen_orientation_angle % 180 == portrait_angle_mod_180;
    return screen_rect_is_portrait ? gfx::Rect(0, 0, 1080, 1920)
                                   : gfx::Rect(0, 0, 1920, 1080);
  }

  void RotateDeviceTo(uint16_t new_device_orientation_angle) {
    // Pick one of the many (beta,gamma) pairs that should map to each angle.
    switch (new_device_orientation_angle) {
      case 0:
        RotateDeviceTo(90, 0);
        break;
      case 90:
        RotateDeviceTo(0, -90);
        break;
      case 180:
        RotateDeviceTo(-90, 0);
        break;
      case 270:
        RotateDeviceTo(0, 90);
        break;
      default:
        NOTREACHED();
    }
  }
  void RotateDeviceTo(double beta, double gamma) {
    DeviceOrientationController::From(*GetFrame().DomWindow())
        .SetOverride(DeviceOrientationData::Create(0.0 /* alpha */, beta, gamma,
                                                   false /* absolute */));
    test::RunPendingTasks();
  }

  // Calls must be wrapped in ASSERT_NO_FATAL_FAILURE.
  void RotateScreenTo(
      display::mojom::blink::ScreenOrientation screen_orientation_type,
      uint16_t screen_orientation_angle) {
    auto rect = ScreenRectFromAngle(screen_orientation_angle);
    ASSERT_TRUE(screen_orientation_type ==
                ScreenOrientationController::ComputeOrientation(
                    rect, screen_orientation_angle));
    ChromeClient().MockScreenInfo().orientation_type = screen_orientation_type;
    ChromeClient().MockScreenInfo().orientation_angle =
        screen_orientation_angle;
    ChromeClient().MockScreenInfo().rect = rect;

    // Screen Orientation API
    ScreenOrientationController::From(*GetDocument().domWindow())
        ->NotifyOrientationChanged();

    // Legacy window.orientation API
    GetDocument().domWindow()->SendOrientationChangeEvent();

    test::RunPendingTasks();
  }

  void InitVideo(int video_width, int video_height) {
    // Set up the WebMediaPlayer instance.
    GetDocument().body()->AppendChild(&Video());
    Video().SetSrc(AtomicString("https://example.com"));
    test::RunPendingTasks();
    SimulateVideoReadyState(HTMLMediaElement::kHaveMetadata);

    // Set video size.
    MockWebMediaPlayer().MockNaturalSize() =
        gfx::Size(video_width, video_height);

    // Dispatch an arbitrary Device Orientation event to satisfy
    // MediaControlsRotateToFullscreenDelegate's requirement that the device
    // supports the API and can provide beta and gamma values. The orientation
    // will be ignored.
    RotateDeviceTo(0);
  }

  void PlayVideo() {
    LocalFrame::NotifyUserActivation(
        GetDocument().GetFrame(), mojom::UserActivationNotificationType::kTest);
    Video().Play();
    test::RunPendingTasks();
  }

  void UpdateVisibilityObserver() {
    // Let IntersectionObserver update.
    UpdateAllLifecyclePhasesForTest();
    test::RunPendingTasks();
  }

  DeviceOrientationType ComputeDeviceOrientation(
      DeviceOrientationData* data) const {
    return MediaControls()
        ->orientation_lock_delegate_->ComputeDeviceOrientation(data);
  }

  // Disable web test mode to fix
  // ScreenOrientationController::ComputeOrientation.
  // TODO(mlamouri): Refactor to avoid this (crbug.com/726817).
  ScopedWebTestMode web_test_mode_{false};

  bool natural_orientation_is_portrait_ = true;
};

TEST_F(MediaControlsOrientationLockDelegateTest, DelegateRequiresFlag) {
  // Flag on by default.
  EXPECT_TRUE(HasDelegate(*Video().GetMediaControls()));

  // Same with flag off.
  ScopedVideoFullscreenOrientationLockForTest video_fullscreen_orientation_lock(
      false);
  auto* video = MakeGarbageCollected<HTMLVideoElement>(GetDocument());
  GetDocument().body()->AppendChild(video);
  EXPECT_FALSE(HasDelegate(*video->GetMediaControls()));
}

TEST_F(MediaControlsOrientationLockDelegateTest, DelegateRequiresVideo) {
  auto* audio = MakeGarbageCollected<HTMLAudioElement>(GetDocument());
  GetDocument().body()->AppendChild(audio);
  EXPECT_FALSE(HasDelegate(*audio->GetMediaControls()));
}

TEST_F(MediaControlsOrientationLockDelegateTest, InitialState) {
  CheckStatePendingFullscreen();
}

TEST_F(MediaControlsOrientationLockDelegateTest, EnterFullscreenNoMetadata) {
  EXPECT_CALL(ScreenOrientationClient(), LockOrientation(_)).Times(0);

  SimulateEnterFullscreen();

  CheckStatePendingMetadata();
}

TEST_F(MediaControlsOrientationLockDelegateTest, LeaveFullscreenNoMetadata) {
  EXPECT_CALL(ScreenOrientationClient(), LockOrientation(_)).Times(0);
  EXPECT_CALL(ScreenOrientationClient(), UnlockOrientation()).Times(0);

  SimulateEnterFullscreen();
  // State set to PendingMetadata.
  SimulateExitFullscreen();

  CheckStatePendingFullscreen();
}

TEST_F(MediaControlsOrientationLockDelegateTest, EnterFullscreenWithMetadata) {
  SimulateVideoReadyState(HTMLMediaElement::kHaveMetadata);

  EXPECT_CALL(ScreenOrientationClient(), LockOrientation(_)).Times(1);
  EXPECT_FALSE(DelegateWillUnlockFullscreen());

  SimulateEnterFullscreen();

  EXPECT_TRUE(DelegateWillUnlockFullscreen());
  CheckStateMaybeLockedFullscreen();
}

TEST_F(MediaControlsOrientationLockDelegateTest, LeaveFullscreenWithMetadata) {
  SimulateVideoReadyState(HTMLMediaElement::kHaveMetadata);

  EXPECT_CALL(ScreenOrientationClient(), LockOrientation(_)).Times(1);
  EXPECT_CALL(ScreenOrientationClient(), UnlockOrientation()).Times(1);

  SimulateEnterFullscreen();
  // State set to MaybeLockedFullscreen.
  SimulateExitFullscreen();

  EXPECT_FALSE(DelegateWillUnlockFullscreen());
  CheckStatePendingFullscreen();
}

TEST_F(MediaControlsOrientationLockDelegateTest, EnterFullscreenAfterPageLock) {
  SimulateVideoReadyState(HTMLMediaElement::kHaveMetadata);
  SimulateOrientationLock();
  test::RunPendingTasks();

  EXPECT_FALSE(DelegateWillUnlockFullscreen());
  EXPECT_CALL(ScreenOrientationClient(), LockOrientation(_)).Times(0);

  SimulateEnterFullscreen();

  EXPECT_FALSE(DelegateWillUnlockFullscreen());
  CheckStateMaybeLockedFullscreen();
}

TEST_F(MediaControlsOrientationLockDelegateTest, LeaveFullscreenAfterPageLock) {
  SimulateVideoReadyState(HTMLMediaElement::kHaveMetadata);
  SimulateOrientationLock();
  test::RunPendingTasks();

  EXPECT_CALL(ScreenOrientationClient(), LockOrientation(_)).Times(0);
  EXPECT_CALL(ScreenOrientationClient(), UnlockOrientation()).Times(0);

  SimulateEnterFullscreen();
  // State set to MaybeLockedFullscreen.
  SimulateExitFullscreen();

  EXPECT_FALSE(DelegateWillUnlockFullscreen());
  CheckStatePendingFullscreen();
}

TEST_F(MediaControlsOrientationLockDelegateTest,
       ReceivedMetadataAfterExitingFullscreen) {
  EXPECT_CALL(ScreenOrientationClient(), LockOrientation(_)).Times(1);

  SimulateEnterFullscreen();
  // State set to PendingMetadata.

  // Set up the WebMediaPlayer instance.
  Video().SetSrc(AtomicString("http://example.com"));
  test::RunPendingTasks();

  SimulateVideoNetworkState(HTMLMediaElement::kNetworkIdle);
  SimulateVideoReadyState(HTMLMediaElement::kHaveMetadata);
  test::RunPendingTasks();

  CheckStateMaybeLockedFullscreen();
}

TEST_F(MediaControlsOrientationLockDelegateTest, ReceivedMetadataLater) {
  EXPECT_CALL(ScreenOrientationClient(), LockOrientation(_)).Times(0);
  EXPECT_CALL(ScreenOrientationClient(), UnlockOrientation()).Times(0);

  SimulateEnterFullscreen();
  // State set to PendingMetadata.
  SimulateExitFullscreen();

  // Set up the WebMediaPlayer instance.
  Video().SetSrc(AtomicString("http://example.com"));
  test::RunPendingTasks();

  SimulateVideoNetworkState(HTMLMediaElement::kNetworkIdle);
  SimulateVideoReadyState(HTMLMediaElement::kHaveMetadata);
  test::RunPendingTasks();

  CheckStatePendingFullscreen();
}

TEST_F(MediaControlsOrientationLockDelegateTest, ComputeOrientationLock) {
  // Set up the WebMediaPlayer instance.
  Video().SetSrc(AtomicString("http://example.com"));
  test::RunPendingTasks();

  SimulateVideoNetworkState(HTMLMediaElement::kNetworkIdle);
  SimulateVideoReadyState(HTMLMediaElement::kHaveMetadata);

  // 100x50
  MockWebMediaPlayer().MockNaturalSize() = gfx::Size(100, 50);
  EXPECT_EQ(device::mojom::ScreenOrientationLockType::LANDSCAPE,
            ComputeOrientationLock());

  // 50x100
  MockWebMediaPlayer().MockNaturalSize() = gfx::Size(50, 100);
  EXPECT_EQ(device::mojom::ScreenOrientationLockType::PORTRAIT,
            ComputeOrientationLock());

  // 100x100 has more subtilities, it depends on the current screen orientation.
  MockWebMediaPlayer().MockNaturalSize() = gfx::Size(100, 100);
  ChromeClient().MockScreenInfo().orientation_type =
      display::mojom::blink::ScreenOrientation::kUndefined;
  EXPECT_EQ(device::mojom::ScreenOrientationLockType::LANDSCAPE,
            ComputeOrientationLock());

  ChromeClient().MockScreenInfo().orientation_type =
      display::mojom::blink::ScreenOrientation::kPortraitPrimary;
  EXPECT_EQ(device::mojom::ScreenOrientationLockType::PORTRAIT,
            ComputeOrientationLock());

  ChromeClient().MockScreenInfo().orientation_type =
      display::mojom::blink::ScreenOrientation::kPortraitPrimary;
  EXPECT_EQ(device::mojom::ScreenOrientationLockType::PORTRAIT,
            ComputeOrientationLock());

  ChromeClient().MockScreenInfo().orientation_type =
      display::mojom::blink::ScreenOrientation::kLandscapePrimary;
  EXPECT_EQ(device::mojom::ScreenOrientationLockType::LANDSCAPE,
            ComputeOrientationLock());

  ChromeClient().MockScreenInfo().orientation_type =
      display::mojom::blink::ScreenOrientation::kLandscapeSecondary;
  EXPECT_EQ(device::mojom::ScreenOrientationLockType::LANDSCAPE,
            ComputeOrientationLock());
}

TEST_F(MediaControlsOrientationLockAndRotateToFullscreenDelegateTest,
       ComputeDeviceOrientation) {
  InitVideo(400, 400);

  // Repeat test with natural_orientation_is_portrait_ = false then true.
  for (int n_o_i_p = 0; n_o_i_p <= 1; n_o_i_p++) {
    natural_orientation_is_portrait_ = static_cast<bool>(n_o_i_p);
    SCOPED_TRACE(testing::Message() << "natural_orientation_is_portrait_="
                                    << natural_orientation_is_portrait_);

    DeviceOrientationType natural_orientation =
        natural_orientation_is_portrait_ ? DeviceOrientationType::kPortrait
                                         : DeviceOrientationType::kLandscape;
    DeviceOrientationType perpendicular_to_natural_orientation =
        natural_orientation_is_portrait_ ? DeviceOrientationType::kLandscape
                                         : DeviceOrientationType::kPortrait;

    // There are four valid combinations of orientation type and orientation
    // angle for a naturally portrait device, and they should all calculate the
    // same device orientation (since this doesn't depend on the screen
    // orientation, it only depends on whether the device is naturally portrait
    // or naturally landscape). Similarly for a naturally landscape device.
    for (int screen_angle = 0; screen_angle < 360; screen_angle += 90) {
      SCOPED_TRACE(testing::Message() << "screen_angle=" << screen_angle);
      display::mojom::blink::ScreenOrientation screen_type =
          display::mojom::blink::ScreenOrientation::kUndefined;
      switch (screen_angle) {
        case 0:
          screen_type =
              natural_orientation_is_portrait_
                  ? display::mojom::blink::ScreenOrientation::kPortraitPrimary
                  : display::mojom::blink::ScreenOrientation::kLandscapePrimary;
          break;
        case 90:
          screen_type =
              natural_orientation_is_portrait_
                  ? display::mojom::blink::ScreenOrientation::kLandscapePrimary
                  : display::mojom::blink::ScreenOrientation::
                        kPortraitSecondary;
          break;
        case 180:
          screen_type =
              natural_orientation_is_portrait_
                  ? display::mojom::blink::ScreenOrientation::kPortraitSecondary
                  : display::mojom::blink::ScreenOrientation::
                        kLandscapeSecondary;
          break;
        case 270:
          screen_type =
              natural_orientation_is_portrait_
                  ? display::mojom::blink::ScreenOrientation::
                        kLandscapeSecondary
                  : display::mojom::blink::ScreenOrientation::kPortraitPrimary;
          break;
      }
      ASSERT_NO_FATAL_FAILURE(RotateScreenTo(screen_type, screen_angle));

      // Compass heading is irrelevant to this calculation.
      double alpha = 0.0;
      bool absolute = false;

      // These beta and gamma values should all map to r < sin(24 degrees), so
      // orientation == kFlat, irrespective of their device_orientation_angle.
      EXPECT_EQ(DeviceOrientationType::kFlat,  // face up
                ComputeDeviceOrientation(DeviceOrientationData::Create(
                    alpha, 0. /* beta */, 0. /* gamma */, absolute)));
      EXPECT_EQ(DeviceOrientationType::kFlat,  // face down
                ComputeDeviceOrientation(DeviceOrientationData::Create(
                    alpha, 180. /* beta */, 0. /* gamma */, absolute)));
      EXPECT_EQ(DeviceOrientationType::kFlat,  // face down
                ComputeDeviceOrientation(DeviceOrientationData::Create(
                    alpha, -180. /* beta */, 0. /* gamma */, absolute)));
      EXPECT_EQ(DeviceOrientationType::kFlat,  // face up, angle=0
                ComputeDeviceOrientation(DeviceOrientationData::Create(
                    alpha, 20. /* beta */, 0. /* gamma */, absolute)));
      EXPECT_EQ(DeviceOrientationType::kFlat,  // face up, angle=90
                ComputeDeviceOrientation(DeviceOrientationData::Create(
                    alpha, 0. /* beta */, -20. /* gamma */, absolute)));
      EXPECT_EQ(DeviceOrientationType::kFlat,  // face up, angle=180
                ComputeDeviceOrientation(DeviceOrientationData::Create(
                    alpha, -20. /* beta */, 0. /* gamma */, absolute)));
      EXPECT_EQ(DeviceOrientationType::kFlat,  // face up, angle=270
                ComputeDeviceOrientation(DeviceOrientationData::Create(
                    alpha, 0. /* beta */, 20. /* gamma */, absolute)));

      // These beta and gamma values should all map to r ~= 1 and
      // device_orientation_angle % 90 ~= 45, hence orientation == kDiagonal.
      EXPECT_EQ(DeviceOrientationType::kDiagonal,  // angle=45
                ComputeDeviceOrientation(DeviceOrientationData::Create(
                    alpha, 135. /* beta */, 90. /* gamma */, absolute)));
      EXPECT_EQ(DeviceOrientationType::kDiagonal,  // angle=45
                ComputeDeviceOrientation(DeviceOrientationData::Create(
                    alpha, 45. /* beta */, -90. /* gamma */, absolute)));
      EXPECT_EQ(DeviceOrientationType::kDiagonal,  // angle=135
                ComputeDeviceOrientation(DeviceOrientationData::Create(
                    alpha, -135. /* beta */, 90. /* gamma */, absolute)));
      EXPECT_EQ(DeviceOrientationType::kDiagonal,  // angle=135
                ComputeDeviceOrientation(DeviceOrientationData::Create(
                    alpha, -45. /* beta */, -90. /* gamma */, absolute)));
      EXPECT_EQ(DeviceOrientationType::kDiagonal,  // angle=225
                ComputeDeviceOrientation(DeviceOrientationData::Create(
                    alpha, -45. /* beta */, 90. /* gamma */, absolute)));
      EXPECT_EQ(DeviceOrientationType::kDiagonal,  // angle=225
                ComputeDeviceOrientation(DeviceOrientationData::Create(
                    alpha, -135. /* beta */, -90. /* gamma */, absolute)));
      EXPECT_EQ(DeviceOrientationType::kDiagonal,  // angle=315
                ComputeDeviceOrientation(DeviceOrientationData::Create(
                    alpha, 45. /* beta */, 90. /* gamma */, absolute)));
      EXPECT_EQ(DeviceOrientationType::kDiagonal,  // angle=315
                ComputeDeviceOrientation(DeviceOrientationData::Create(
                    alpha, 135. /* beta */, -90. /* gamma */, absolute)));

      // These beta and gamma values should all map to r ~= 1 and
      // device_orientation_angle ~= 0, hence orientation == kPortrait.
      EXPECT_EQ(natural_orientation,
                ComputeDeviceOrientation(DeviceOrientationData::Create(
                    alpha, 90. /* beta */, 0. /* gamma */, absolute)));
      EXPECT_EQ(natural_orientation,
                ComputeDeviceOrientation(DeviceOrientationData::Create(
                    alpha, 90. /* beta */, 90. /* gamma */, absolute)));
      EXPECT_EQ(natural_orientation,
                ComputeDeviceOrientation(DeviceOrientationData::Create(
                    alpha, 90. /* beta */, -90. /* gamma */, absolute)));
      EXPECT_EQ(natural_orientation,
                ComputeDeviceOrientation(DeviceOrientationData::Create(
                    alpha, 85. /* beta */, 90. /* gamma */, absolute)));
      EXPECT_EQ(natural_orientation,
                ComputeDeviceOrientation(DeviceOrientationData::Create(
                    alpha, 85. /* beta */, -90. /* gamma */, absolute)));
      EXPECT_EQ(natural_orientation,
                ComputeDeviceOrientation(DeviceOrientationData::Create(
                    alpha, 95. /* beta */, 90. /* gamma */, absolute)));
      EXPECT_EQ(natural_orientation,
                ComputeDeviceOrientation(DeviceOrientationData::Create(
                    alpha, 95. /* beta */, -90. /* gamma */, absolute)));

      // These beta and gamma values should all map to r == 1 and
      // device_orientation_angle == 90, hence orientation == kLandscape.
      EXPECT_EQ(perpendicular_to_natural_orientation,
                ComputeDeviceOrientation(DeviceOrientationData::Create(
                    alpha, 0. /* beta */, -90. /* gamma */, absolute)));
      EXPECT_EQ(perpendicular_to_natural_orientation,
                ComputeDeviceOrientation(DeviceOrientationData::Create(
                    alpha, 180. /* beta */, 90. /* gamma */, absolute)));
      EXPECT_EQ(perpendicular_to_natural_orientation,
                ComputeDeviceOrientation(DeviceOrientationData::Create(
                    alpha, -180. /* beta */, 90. /* gamma */, absolute)));

      // These beta and gamma values should all map to r ~= 1 and
      // device_orientation_angle ~= 180, hence orientation == kPortrait.
      EXPECT_EQ(natural_orientation,
                ComputeDeviceOrientation(DeviceOrientationData::Create(
                    alpha, -90. /* beta */, 0. /* gamma */, absolute)));
      EXPECT_EQ(natural_orientation,
                ComputeDeviceOrientation(DeviceOrien
"""


```