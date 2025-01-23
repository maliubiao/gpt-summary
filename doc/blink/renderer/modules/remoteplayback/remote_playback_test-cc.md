Response:
Let's break down the thought process for analyzing the `remote_playback_test.cc` file.

1. **Identify the Core Purpose:** The filename `remote_playback_test.cc` immediately signals that this is a unit test file. It's designed to test the functionality of something related to "remote playback".

2. **Look at Includes:**  The `#include` directives provide crucial context:
    * `remote_playback.h`:  This is the main file being tested. It defines the `RemotePlayback` class.
    * `testing/gmock/include/gmock/gmock.h` and `testing/gtest/include/gtest/gtest.h`:  These are the core Google Test and Google Mock libraries, confirming it's a unit test.
    * `mojom/frame/user_activation_notification_type.mojom-blink.h`: This suggests interaction with user activation concepts, likely related to preventing unauthorized remote playback initiation.
    * `bindings/...`:  Files in the `bindings` directory relate to JavaScript interaction. Seeing `ScriptFunction`, `ScriptPromiseTester`, and `V8RemotePlaybackAvailabilityCallback` indicates this code has a JavaScript API.
    * `core/dom/...`, `core/frame/...`, `core/html/media/...`: These headers point to the DOM, frame structure, and media element interactions. `HTMLVideoElement` and `HTMLMediaElement` are key players.
    * `modules/presentation/presentation_controller.h`: This reveals a connection to the Presentation API, used for casting content to other screens.
    * `modules/remoteplayback/html_media_element_remote_playback.h`: This likely manages the remote playback aspects specifically within media elements.
    * `platform/testing/...`: These headers are for Blink's internal testing utilities.

3. **Examine the Test Fixture (`RemotePlaybackTest`):**
    * Inheritance from `testing::Test` and `ScopedRemotePlaybackBackendForTest`: Confirms it's a standard Google Test setup, and that there's a testing-specific backend for remote playback.
    * `SetUp()` method:  This initializes the test environment. Creating a `DummyPageHolder` and an `HTMLVideoElement` are crucial for simulating a web page context.
    * Helper methods (`CancelPrompt`, `SetState`, `IsListening`, etc.): These methods provide controlled ways to interact with the `RemotePlayback` object under test, isolating specific behaviors.

4. **Analyze Individual Tests (the `TEST_F` blocks):**  Each `TEST_F` focuses on a specific aspect of `RemotePlayback` functionality. Look for:
    * **Test Name:**  Provides a concise description of what's being tested (e.g., `PromptCancelledRejectsWithNotAllowedError`).
    * **Setup:** How the test environment is prepared (e.g., notifying user activation).
    * **Action:** The primary operation being tested (e.g., calling `remote_playback.prompt()`).
    * **Assertion:** How the outcome is verified (e.g., `EXPECT_TRUE(promise_tester.IsRejected())`).
    * **Mocking (`MOCK_METHOD`):**  Identify where mock objects are used to simulate dependencies (like `MockPresentationController` or `MockEventListenerForRemotePlayback`). This helps isolate the unit being tested.

5. **Identify Relationships with Web Technologies:**
    * **JavaScript:** The presence of `ScriptPromiseTester`, `V8RemotePlaybackAvailabilityCallback`, and the `prompt()` and `watchAvailability()` methods clearly indicate a JavaScript API. The tests often use `scope.GetScriptState()` to interact with the V8 JavaScript engine.
    * **HTML:** The tests create `HTMLVideoElement` instances. The `disableremoteplayback` attribute is tested, directly linking to HTML media element attributes.
    * **CSS:** While not directly tested in *this specific file*, the functionality being tested (remote playback) often has UI elements that might be styled with CSS. This file focuses on the *logic*, not the visual presentation.

6. **Infer Logic and Scenarios:**  Based on the test names and actions, deduce the intended behavior of the `RemotePlayback` class:
    * Handling prompt cancellations.
    * Managing connection states (connecting, connected, closed, terminated).
    * Firing events (`connecting`, `connect`, `disconnect`).
    * Handling the `disableremoteplayback` attribute.
    * Implementing availability callbacks for when remote playback is possible.
    * Interaction with the Presentation API.
    * Handling cases where the backend is disabled.

7. **Consider User and Programming Errors:** Think about how a developer might misuse the API or how a user's actions could lead to certain states:
    * Calling `prompt()` without user activation.
    * Not handling the promise returned by `prompt()`.
    * Expecting remote playback to work when the `disableremoteplayback` attribute is set.
    * Misunderstanding the timing of availability callbacks.

8. **Trace User Actions (Debugging Clues):** Imagine a user trying to cast a video:
    * User clicks a "cast" button (initiates user activation).
    * JavaScript calls `videoElement.remotePlayback.prompt()`.
    * The browser checks for available remote playback devices.
    * The user might cancel the prompt.
    * A connection might be established or fail.
    * The remote playback might start and later be disconnected.
    * The `watchAvailability()` API could be used to show/hide the cast button.

9. **Structure the Answer:** Organize the findings into logical sections: Functionality, Relationship to Web Technologies, Logic and I/O, Common Errors, and Debugging Clues. Use examples to illustrate the points.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This just tests the `prompt()` method."  *Correction:*  Realize it tests much more, including state changes, events, and availability.
* **Focus too narrowly on code details:**  *Correction:* Step back and think about the broader purpose and how it relates to user interactions and web standards.
* **Missing the JavaScript connection:** *Correction:* Pay closer attention to the `bindings` includes and the use of `ScriptPromiseTester` – this is a key aspect.
* **Not explaining the "why":** *Correction:*  Don't just list features; explain *why* these tests are important and what aspects of remote playback they verify.

By following this kind of structured analysis, and iteratively refining understanding, it's possible to generate a comprehensive and accurate description of the `remote_playback_test.cc` file.
这个文件 `blink/renderer/modules/remoteplayback/remote_playback_test.cc` 是 Chromium Blink 引擎中用于测试 `RemotePlayback` 接口功能的单元测试文件。`RemotePlayback` 接口允许网页上的媒体元素（例如 `<video>`）将其播放控制权转移到远程设备，例如 Chromecast 或 Miracast 设备。

以下是该文件的主要功能点：

**1. 测试 `RemotePlayback` 接口的核心功能:**

* **`prompt()` 方法测试:**
    * 测试当用户取消远程播放提示时，`prompt()` 方法返回的 Promise 是否会被拒绝，并带有 `NotAllowedError`。
    * 测试当远程播放连接已建立，但之后被取消时，`prompt()` 返回的 Promise 是否会被拒绝。
    * 测试当远程播放连接已建立，但之后断开连接时，`prompt()` 返回的 Promise 是否会成功 resolve。
    * 测试在禁用远程播放属性 (`disableremoteplayback`) 后调用 `prompt()` 是否会抛出 `InvalidStateError`。
    * 测试当 RemotePlayback 后端被禁用时调用 `prompt()` 是否会抛出异常。
* **状态变化事件测试 (`connecting`, `connect`, `disconnect`):**
    * 测试当远程播放连接状态发生变化时，是否会触发相应的事件。
    * 验证事件触发的顺序和次数是否正确，例如连接时触发 `connecting` 和 `connect`，断开时触发 `disconnect`。
* **`watchAvailability()` 和 `cancelWatchAvailability()` 方法测试:**
    * 测试 `watchAvailability()` 方法是否能成功注册回调函数，以便在远程播放可用性发生变化时被调用。
    * 测试 `cancelWatchAvailability()` 方法是否能成功取消注册的回调函数。
    * 测试在 `disableremoteplayback` 属性设置后，之前注册的可用性回调是否会被取消。
    * 测试在可用性回调函数中调用 `watchAvailability()` 是否能正确处理。
    * 测试当 RemotePlayback 后端被禁用时调用 `watchAvailability()` 是否仍然能成功完成（Promise resolve）。
* **`is_listening_` 内部状态测试:**
    * 测试 `RemotePlayback` 对象是否根据媒体资源的 URL 和时长开始或停止监听远程播放设备的可用性。
    * 验证在不同情况下（例如，URL 改变、时长改变、手动调用 `watchAvailability` 和 `cancelWatchAvailability`） `is_listening_` 状态是否正确。
* **`AvailabilityChangedForTesting()` 方法测试:**
    * 用于模拟远程播放设备的可用性变化，以触发注册的回调函数。
* **`SourceChanged()` 和 `MediaMetadataChanged()` 方法测试:**
    * 测试当媒体资源的 URL 或元数据（音频/视频编解码器）发生变化时，生成的远程播放可用性 URL 是否正确。

**2. 与 JavaScript, HTML, CSS 的关系:**

* **JavaScript:** 该测试文件直接测试了 `RemotePlayback` 接口提供的 JavaScript API，例如 `prompt()` 和 `watchAvailability()` 方法。测试用例模拟了 JavaScript 代码调用这些方法，并验证其行为和返回的 Promise 状态。
    * **举例:** 测试用例中使用了 `ScriptPromiseTester` 来处理 `prompt()` 和 `watchAvailability()` 返回的 Promise，并断言 Promise 是否被 resolve 或 reject。
    * **假设输入与输出:** 假设 JavaScript 代码调用 `videoElement.remotePlayback.prompt()`，如果用户在浏览器弹出的远程播放设备选择框中点击“取消”，则测试用例会断言 `prompt()` 返回的 Promise 被 reject，并且错误类型是 `NotAllowedError`。
* **HTML:**  测试用例中创建了 `HTMLVideoElement` 对象，并使用 `HTMLMediaElementRemotePlayback::SetBooleanAttribute` 方法来设置 `disableremoteplayback` 属性。这模拟了 HTML 元素上设置属性对 `RemotePlayback` 行为的影响。
    * **举例:**  `<video disableremoteplayback src="video.mp4"></video>`。当 HTML 中设置了 `disableremoteplayback` 属性后，调用 `remotePlayback.prompt()` 应该会失败。
* **CSS:**  该测试文件本身不直接涉及 CSS 的功能测试。然而，`RemotePlayback` 的用户界面（例如，选择远程播放设备的弹窗）可能会使用 CSS 进行样式设置。该测试文件关注的是 `RemotePlayback` 接口的逻辑行为，而不是用户界面的渲染。

**3. 逻辑推理与假设输入输出:**

* **假设输入:**  用户在网页上点击了一个视频的播放按钮，并且该视频元素支持远程播放。JavaScript 代码调用了 `videoElement.remotePlayback.prompt()`。
* **逻辑推理:**  浏览器会尝试发现可用的远程播放设备。如果找到了设备，浏览器会弹出一个提示框，让用户选择要连接的设备。
* **输出 (取决于用户操作):**
    * **用户选择了一个设备:** `prompt()` 返回的 Promise 会在连接建立后 resolve。如果连接之后断开，Promise 仍然会 resolve。
    * **用户取消了提示:** `prompt()` 返回的 Promise 会被 reject，并带有 `NotAllowedError`。
    * **没有找到可用的设备:**  `prompt()` 返回的 Promise 可能会立即 reject，或者在超时后 reject (具体行为可能取决于实现细节，但此测试主要关注用户取消的情况)。

**4. 用户或编程常见的使用错误:**

* **在没有用户激活的情况下调用 `prompt()`:**  浏览器通常会阻止在没有用户交互的情况下自动弹出远程播放提示。测试用例中使用了 `NotifyUserActivationTest()` 来模拟用户激活，确保测试的正确性。开发者如果忘记用户激活，`prompt()` 调用可能会失败。
* **假设输入:** JavaScript 代码在页面加载完成后立即调用 `videoElement.remotePlayback.prompt()`。
* **预期错误:**  浏览器会阻止此操作，`prompt()` 返回的 Promise 会被 reject，或者根本不会触发任何操作。
* **不处理 `prompt()` 返回的 Promise:**  开发者如果忘记处理 `prompt()` 返回的 Promise 的 resolve 或 reject 情况，可能无法正确处理远程播放连接的成功或失败。
* **错误地认为设置了 `disableremoteplayback` 属性后仍然可以调用 `prompt()`:**  `disableremoteplayback` 属性明确禁用了远程播放功能，调用 `prompt()` 会导致错误。
* **假设输入:** HTML 中设置了 `<video disableremoteplayback>`，但 JavaScript 代码仍然调用了 `videoElement.remotePlayback.prompt()`。
* **预期错误:** `prompt()` 方法会抛出 `InvalidStateError` 异常，或者返回的 Promise 会被 reject 并带有该错误。

**5. 用户操作到达此处的调试线索:**

1. **用户尝试在网页上播放视频。**
2. **该网页使用了支持远程播放的 `<video>` 元素。**
3. **网页的 JavaScript 代码可能会调用 `videoElement.remotePlayback.prompt()` 来启动远程播放。** 这通常发生在用户点击了视频上的“投屏”或类似的按钮时。
4. **如果用户调用了 `watchAvailability()`，则在视频资源加载或其 URL 发生变化时，浏览器会尝试检测可用的远程播放设备。**
5. **开发者可能在遇到远程播放功能问题时，会查看 Blink 引擎的源代码，并可能定位到 `remote_playback_test.cc` 文件，以了解该功能的测试方式和预期行为。**
6. **通过阅读测试用例，开发者可以理解 `RemotePlayback` API 的各种场景和边缘情况，例如用户取消提示、连接状态变化、`disableremoteplayback` 属性的影响等。**
7. **当调试远程播放功能时，开发者可能会在 Chromium 源代码中搜索与 `RemotePlayback` 相关的代码，并最终找到这个测试文件，以帮助理解问题的根源。** 例如，他们可能会搜索 `RemotePlayback::prompt` 或 `RemotePlayback::watchAvailability` 等关键字。

总而言之，`remote_playback_test.cc` 是一个关键的测试文件，用于确保 Chromium Blink 引擎中 `RemotePlayback` 接口的正确性和稳定性。它涵盖了各种正常和异常情况，并为开发者提供了理解该接口工作原理的重要参考。

### 提示词
```
这是目录为blink/renderer/modules/remoteplayback/remote_playback_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/remoteplayback/remote_playback.h"

#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/mojom/frame/user_activation_notification_type.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/script_function.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_tester.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_remote_playback_availability_callback.h"
#include "third_party/blink/renderer/core/dom/events/native_event_listener.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/html/media/html_media_element.h"
#include "third_party/blink/renderer/core/html/media/html_video_element.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"
#include "third_party/blink/renderer/core/testing/mock_function_scope.h"
#include "third_party/blink/renderer/modules/presentation/presentation_controller.h"
#include "third_party/blink/renderer/modules/remoteplayback/html_media_element_remote_playback.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"

namespace blink {

namespace {

class MockFunction : public ScriptFunction {
 public:
  MockFunction() = default;
  MOCK_METHOD2(Call, ScriptValue(ScriptState*, ScriptValue));
};

class MockEventListenerForRemotePlayback : public NativeEventListener {
 public:
  MOCK_METHOD2(Invoke, void(ExecutionContext* executionContext, Event*));
};

class MockPresentationController final : public PresentationController {
 public:
  explicit MockPresentationController(LocalDOMWindow& window)
      : PresentationController(window) {}
  ~MockPresentationController() override = default;

  MOCK_METHOD1(AddAvailabilityObserver,
               void(PresentationAvailabilityObserver*));
  MOCK_METHOD1(RemoveAvailabilityObserver,
               void(PresentationAvailabilityObserver*));
};
}  // namespace

class RemotePlaybackTest : public testing::Test,
                           private ScopedRemotePlaybackBackendForTest {
 public:
  RemotePlaybackTest() : ScopedRemotePlaybackBackendForTest(true) {}

  void SetUp() override {
    page_holder_ = std::make_unique<DummyPageHolder>();
    element_ =
        MakeGarbageCollected<HTMLVideoElement>(page_holder_->GetDocument());
    ChangeMediaElementDuration(60);
  }

 protected:
  void CancelPrompt(RemotePlayback& remote_playback) {
    remote_playback.PromptCancelled();
  }

  void SetState(RemotePlayback& remote_playback,
                mojom::blink::PresentationConnectionState state) {
    remote_playback.StateChanged(state);
  }

  bool IsListening(RemotePlayback& remote_playback) {
    return remote_playback.is_listening_;
  }

  void NotifyUserActivationTest() {
    LocalFrame::NotifyUserActivation(
        &page_holder_->GetFrame(),
        mojom::UserActivationNotificationType::kTest);
  }

  void DisableRemotePlaybackAttr() {
    HTMLMediaElementRemotePlayback::SetBooleanAttribute(
        *element_, html_names::kDisableremoteplaybackAttr, true);
  }

  void ChangeMediaElementDuration(double duration) {
    element_->DurationChanged(duration, false);
  }

  void UpdateAvailabilityUrlsAndStartListening() {
    get_remote_playback().UpdateAvailabilityUrlsAndStartListening();
  }

  RemotePlayback& get_remote_playback() {
    return RemotePlayback::From(*element_);
  }

  DummyPageHolder* page_holder() { return page_holder_.get(); }

 private:
  test::TaskEnvironment task_environment_;
  std::unique_ptr<DummyPageHolder> page_holder_;
  Persistent<HTMLVideoElement> element_ = nullptr;
};

TEST_F(RemotePlaybackTest, PromptCancelledRejectsWithNotAllowedError) {
  V8TestingScope scope;
  RemotePlayback& remote_playback = get_remote_playback();

  NotifyUserActivationTest();
  ScriptPromiseTester promise_tester(
      scope.GetScriptState(),
      remote_playback.prompt(scope.GetScriptState(),
                             scope.GetExceptionState()));
  CancelPrompt(remote_playback);

  // Runs pending promises.
  scope.PerformMicrotaskCheckpoint();
  EXPECT_TRUE(promise_tester.IsRejected());
}

TEST_F(RemotePlaybackTest, PromptConnectedRejectsWhenCancelled) {
  V8TestingScope scope;
  RemotePlayback& remote_playback = get_remote_playback();

  SetState(remote_playback,
           mojom::blink::PresentationConnectionState::CONNECTED);

  NotifyUserActivationTest();
  ScriptPromiseTester promise_tester(
      scope.GetScriptState(),
      remote_playback.prompt(scope.GetScriptState(),
                             scope.GetExceptionState()));
  CancelPrompt(remote_playback);

  // Runs pending promises.
  scope.PerformMicrotaskCheckpoint();
  EXPECT_TRUE(promise_tester.IsRejected());
}

TEST_F(RemotePlaybackTest, PromptConnectedResolvesWhenDisconnected) {
  V8TestingScope scope;
  RemotePlayback& remote_playback = get_remote_playback();

  SetState(remote_playback,
           mojom::blink::PresentationConnectionState::CONNECTED);

  NotifyUserActivationTest();
  ScriptPromiseTester promise_tester(
      scope.GetScriptState(),
      remote_playback.prompt(scope.GetScriptState(),
                             scope.GetExceptionState()));

  SetState(remote_playback, mojom::blink::PresentationConnectionState::CLOSED);

  // Runs pending promises.
  scope.PerformMicrotaskCheckpoint();
  EXPECT_TRUE(promise_tester.IsFulfilled());
}

TEST_F(RemotePlaybackTest, StateChangeEvents) {
  V8TestingScope scope;
  RemotePlayback& remote_playback = get_remote_playback();

  auto* connecting_handler = MakeGarbageCollected<
      testing::StrictMock<MockEventListenerForRemotePlayback>>();
  auto* connect_handler = MakeGarbageCollected<
      testing::StrictMock<MockEventListenerForRemotePlayback>>();
  auto* disconnect_handler = MakeGarbageCollected<
      testing::StrictMock<MockEventListenerForRemotePlayback>>();

  remote_playback.addEventListener(event_type_names::kConnecting,
                                   connecting_handler);
  remote_playback.addEventListener(event_type_names::kConnect, connect_handler);
  remote_playback.addEventListener(event_type_names::kDisconnect,
                                   disconnect_handler);

  // Verify a state changes when a route is connected and closed.
  EXPECT_CALL(*connecting_handler, Invoke(testing::_, testing::_)).Times(1);
  EXPECT_CALL(*connect_handler, Invoke(testing::_, testing::_)).Times(1);
  EXPECT_CALL(*disconnect_handler, Invoke(testing::_, testing::_)).Times(1);

  SetState(remote_playback,
           mojom::blink::PresentationConnectionState::CONNECTING);
  SetState(remote_playback,
           mojom::blink::PresentationConnectionState::CONNECTING);
  SetState(remote_playback,
           mojom::blink::PresentationConnectionState::CONNECTED);
  SetState(remote_playback,
           mojom::blink::PresentationConnectionState::CONNECTED);
  SetState(remote_playback, mojom::blink::PresentationConnectionState::CLOSED);
  SetState(remote_playback, mojom::blink::PresentationConnectionState::CLOSED);

  // Verify mock expectations explicitly as the mock objects are garbage
  // collected.
  testing::Mock::VerifyAndClear(connecting_handler);
  testing::Mock::VerifyAndClear(connect_handler);
  testing::Mock::VerifyAndClear(disconnect_handler);

  // Verify a state changes when a route is connected and terminated.
  EXPECT_CALL(*connecting_handler, Invoke(testing::_, testing::_)).Times(1);
  EXPECT_CALL(*connect_handler, Invoke(testing::_, testing::_)).Times(1);
  EXPECT_CALL(*disconnect_handler, Invoke(testing::_, testing::_)).Times(1);

  SetState(remote_playback,
           mojom::blink::PresentationConnectionState::CONNECTING);
  SetState(remote_playback,
           mojom::blink::PresentationConnectionState::CONNECTED);
  SetState(remote_playback,
           mojom::blink::PresentationConnectionState::TERMINATED);

  // Verify mock expectations explicitly as the mock objects are garbage
  // collected.
  testing::Mock::VerifyAndClear(connecting_handler);
  testing::Mock::VerifyAndClear(connect_handler);
  testing::Mock::VerifyAndClear(disconnect_handler);

  // Verify we can connect after a route termination.
  EXPECT_CALL(*connecting_handler, Invoke(testing::_, testing::_)).Times(1);
  SetState(remote_playback,
           mojom::blink::PresentationConnectionState::CONNECTING);
  testing::Mock::VerifyAndClear(connecting_handler);
}

TEST_F(RemotePlaybackTest,
       DisableRemotePlaybackRejectsPromptWithInvalidStateError) {
  V8TestingScope scope;
  RemotePlayback& remote_playback = get_remote_playback();

  NotifyUserActivationTest();
  ScriptPromiseTester promise_tester(
      scope.GetScriptState(),
      remote_playback.prompt(scope.GetScriptState(),
                             scope.GetExceptionState()));
  DisableRemotePlaybackAttr();

  // Runs pending promises.
  scope.PerformMicrotaskCheckpoint();
  EXPECT_TRUE(promise_tester.IsRejected());
}

TEST_F(RemotePlaybackTest, DisableRemotePlaybackCancelsAvailabilityCallbacks) {
  V8TestingScope scope;
  RemotePlayback& remote_playback = get_remote_playback();
  MockFunctionScope funcs(scope.GetScriptState());

  V8RemotePlaybackAvailabilityCallback* availability_callback =
      V8RemotePlaybackAvailabilityCallback::Create(
          funcs.ExpectNoCall()->ToV8Function(scope.GetScriptState()));

  ScriptPromiseTester promise_tester(
      scope.GetScriptState(), remote_playback.watchAvailability(
                                  scope.GetScriptState(), availability_callback,
                                  scope.GetExceptionState()));

  DisableRemotePlaybackAttr();

  // Runs pending promises.
  scope.PerformMicrotaskCheckpoint();
  EXPECT_TRUE(promise_tester.IsFulfilled());
}

TEST_F(RemotePlaybackTest, CallingWatchAvailabilityFromAvailabilityCallback) {
  V8TestingScope scope;
  RemotePlayback& remote_playback = get_remote_playback();

  MockFunction* callback_function = MakeGarbageCollected<MockFunction>();
  V8RemotePlaybackAvailabilityCallback* availability_callback =
      V8RemotePlaybackAvailabilityCallback::Create(
          callback_function->ToV8Function(scope.GetScriptState()));

  const int kNumberCallbacks = 10;
  for (int i = 0; i < kNumberCallbacks; ++i) {
    remote_playback.watchAvailability(scope.GetScriptState(),
                                      availability_callback,
                                      scope.GetExceptionState());
  }

  auto add_callback_lambda = [&]() {
    remote_playback.watchAvailability(scope.GetScriptState(),
                                      availability_callback,
                                      scope.GetExceptionState());
    return blink::ScriptValue::CreateNull(scope.GetScriptState()->GetIsolate());
  };

  // When the availability changes, we should get exactly kNumberCallbacks
  // calls, due to the kNumberCallbacks initial current callbacks. The extra
  // callbacks we are adding should not be executed.
  EXPECT_CALL(*callback_function, Call(testing::_, testing::_))
      .Times(kNumberCallbacks)
      .WillRepeatedly(testing::InvokeWithoutArgs(add_callback_lambda));

  remote_playback.AvailabilityChangedForTesting(true);

  scope.PerformMicrotaskCheckpoint();
  testing::Mock::VerifyAndClear(callback_function);

  // We now have twice as many callbacks as we started with, and should get
  // twice as many calls, but no more.
  EXPECT_CALL(*callback_function, Call(testing::_, testing::_))
      .Times(kNumberCallbacks * 2)
      .WillRepeatedly(testing::InvokeWithoutArgs(add_callback_lambda));

  remote_playback.AvailabilityChangedForTesting(false);

  scope.PerformMicrotaskCheckpoint();

  // Verify mock expectations explicitly as the mock objects are garbage
  // collected.
  testing::Mock::VerifyAndClear(callback_function);
}

TEST_F(RemotePlaybackTest, PromptThrowsWhenBackendDisabled) {
  ScopedRemotePlaybackBackendForTest remote_playback_backend(false);
  V8TestingScope scope;
  RemotePlayback& remote_playback = get_remote_playback();

  NotifyUserActivationTest();
  remote_playback.prompt(scope.GetScriptState(), scope.GetExceptionState());
  EXPECT_TRUE(scope.GetExceptionState().HadException());
}

TEST_F(RemotePlaybackTest, WatchAvailabilityWorksWhenBackendDisabled) {
  ScopedRemotePlaybackBackendForTest remote_playback_backend(false);
  V8TestingScope scope;
  RemotePlayback& remote_playback = get_remote_playback();

  MockFunctionScope funcs(scope.GetScriptState());

  V8RemotePlaybackAvailabilityCallback* availability_callback =
      V8RemotePlaybackAvailabilityCallback::Create(
          funcs.ExpectNoCall()->ToV8Function(scope.GetScriptState()));

  ScriptPromiseTester promise_tester(
      scope.GetScriptState(), remote_playback.watchAvailability(
                                  scope.GetScriptState(), availability_callback,
                                  scope.GetExceptionState()));

  // Runs pending promises.
  scope.PerformMicrotaskCheckpoint();
  EXPECT_TRUE(promise_tester.IsFulfilled());
}

TEST_F(RemotePlaybackTest, IsListening) {
  V8TestingScope scope;
  RemotePlayback& remote_playback = get_remote_playback();

  LocalDOMWindow& window = *page_holder()->GetFrame().DomWindow();
  MockPresentationController* mock_controller =
      MakeGarbageCollected<MockPresentationController>(window);
  Supplement<LocalDOMWindow>::ProvideTo(
      window, static_cast<PresentationController*>(mock_controller));

  EXPECT_CALL(*mock_controller,
              AddAvailabilityObserver(testing::Eq(&remote_playback)))
      .Times(3);
  EXPECT_CALL(*mock_controller,
              RemoveAvailabilityObserver(testing::Eq(&remote_playback)))
      .Times(3);

  MockFunction* callback_function = MakeGarbageCollected<MockFunction>();
  V8RemotePlaybackAvailabilityCallback* availability_callback =
      V8RemotePlaybackAvailabilityCallback::Create(
          callback_function->ToV8Function(scope.GetScriptState()));

  // The initial call upon registering will not happen as it's posted on the
  // message loop.
  EXPECT_CALL(*callback_function, Call(testing::_, testing::_)).Times(2);

  remote_playback.watchAvailability(
      scope.GetScriptState(), availability_callback, scope.GetExceptionState());

  ASSERT_TRUE(remote_playback.Urls().empty());
  ASSERT_FALSE(IsListening(remote_playback));

  remote_playback.SourceChanged(WebURL(KURL("http://www.example.com")), true);
  ASSERT_EQ((size_t)1, remote_playback.Urls().size());
  ASSERT_TRUE(IsListening(remote_playback));
  remote_playback.AvailabilityChanged(mojom::ScreenAvailability::AVAILABLE);

  remote_playback.cancelWatchAvailability(scope.GetScriptState(),
                                          scope.GetExceptionState());
  ASSERT_EQ((size_t)1, remote_playback.Urls().size());
  ASSERT_FALSE(IsListening(remote_playback));

  remote_playback.watchAvailability(
      scope.GetScriptState(), availability_callback, scope.GetExceptionState());
  ASSERT_EQ((size_t)1, remote_playback.Urls().size());
  ASSERT_TRUE(IsListening(remote_playback));
  remote_playback.AvailabilityChanged(mojom::ScreenAvailability::AVAILABLE);

  // Background monitoring is disabled for short videos.
  ChangeMediaElementDuration(10);
  UpdateAvailabilityUrlsAndStartListening();
  ASSERT_TRUE(remote_playback.Urls().empty());
  ASSERT_FALSE(IsListening(remote_playback));

  ChangeMediaElementDuration(60);
  UpdateAvailabilityUrlsAndStartListening();
  ASSERT_EQ((size_t)1, remote_playback.Urls().size());
  ASSERT_TRUE(IsListening(remote_playback));

  // Background monitoring is disabled for invalid sources.
  remote_playback.SourceChanged(WebURL(), false);
  ASSERT_TRUE(remote_playback.Urls().empty());
  ASSERT_FALSE(IsListening(remote_playback));

  remote_playback.SourceChanged(WebURL(KURL("@$@#@#")), true);
  ASSERT_TRUE(remote_playback.Urls().empty());
  ASSERT_FALSE(IsListening(remote_playback));

  // Runs pending promises.
  scope.PerformMicrotaskCheckpoint();

  // Verify mock expectations explicitly as the mock objects are garbage
  // collected.
  testing::Mock::VerifyAndClear(callback_function);
  testing::Mock::VerifyAndClear(mock_controller);
}

TEST_F(RemotePlaybackTest, NullContextDoesntCrash) {
  RemotePlayback& remote_playback = get_remote_playback();

  remote_playback.SetExecutionContext(nullptr);
  remote_playback.PromptInternal();
}

TEST_F(RemotePlaybackTest, GetAvailabilityUrl) {
  RemotePlayback& remote_playback = get_remote_playback();

  remote_playback.SourceChanged(WebURL(KURL("http://www.example.com")), false);
  EXPECT_TRUE(remote_playback.Urls().empty());

  remote_playback.SourceChanged(WebURL(KURL("")), true);
  EXPECT_TRUE(remote_playback.Urls().empty());

  remote_playback.SourceChanged(WebURL(KURL("http://www.example.com")), true);
  EXPECT_EQ((size_t)1, remote_playback.Urls().size());
  EXPECT_EQ(
      "remote-playback:media-element?source=aHR0cDovL3d3dy5leGFtcGxlLmNvbS8=",
      remote_playback.Urls()[0]);

  remote_playback.MediaMetadataChanged(media::VideoCodec::kVP9,
                                       media::AudioCodec::kMP3);
  EXPECT_EQ(
      "remote-playback:media-element?source=aHR0cDovL3d3dy5leGFtcGxlLmNvbS8=&"
      "video_codec=vp9&audio_codec=mp3",
      remote_playback.Urls()[0]);
}

}  // namespace blink
```