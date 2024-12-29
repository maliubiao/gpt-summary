Response:
The user wants to understand the functionality of the provided C++ code, which is a test file for the `CaptureController` class in the Chromium Blink engine.

Here's a breakdown of the thinking process to generate the response:

1. **Identify the core function:** The filename `capture_controller_test.cc` and the presence of `TEST_F` macros immediately indicate that this is a unit test file. It's designed to test the `CaptureController` class.

2. **Analyze the test categories:** The test names often indicate the specific functionality being tested. Look for patterns in the names. In this case, we see tests related to `SendWheel` and `CaptureWheel`. This suggests the `CaptureController` is responsible for handling wheel events during screen capture.

3. **Examine individual tests for `SendWheel`:**
    * Tests with "Fails" in their name indicate negative test cases, checking for expected errors.
    * Tests with "Success" indicate positive test cases.
    * Look for the actions performed in each test: creating a `CaptureController`, setting a video track, simulating frame arrival, calling `sendWheel`, and then asserting the outcome of the returned promise (fulfilled or rejected) and the potential error message.
    * Pay attention to the differences between the "Fails" and "Success" tests. These differences highlight the conditions under which `sendWheel` should succeed or fail (e.g., no video track, ended video track, capturing window/monitor vs. tab, no frames received yet).
    * Note the `EXPECT_CALL` statements, which mock interactions with other components (like `DispatcherHost`). This reveals that `CaptureController` communicates with a browser process to send wheel events.
    * Look for tests that examine the content of the dispatched data (e.g., `SendWheelScalesCorrectly`).

4. **Examine individual tests for `CaptureWheel`:**
    * Notice the use of `captureWheel` and the association with an HTML element. This suggests that `captureWheel` is a method to start capturing wheel events on a specific element.
    * Observe how the tests simulate wheel events using `element->DispatchEvent`.
    * Pay attention to the handling of trusted vs. untrusted events.
    * Look for tests covering different backend error scenarios and the case where no element is targeted.

5. **Identify relationships to web technologies:**
    * The presence of `HTMLDivElement`, `WheelEvent`, and the interaction with the DOM clearly link this code to HTML.
    * The use of `ScriptPromise` and `ScriptState` indicates interaction with JavaScript.
    * While CSS isn't directly manipulated in these tests, the concept of scrolling and elements on a webpage inherently connects to CSS (which defines layout and appearance).

6. **Infer user actions:** Based on the functionality being tested, deduce how a user might trigger these actions. The tests around `SendWheel` imply programmatic scrolling, while `CaptureWheel` directly relates to user interaction with the mouse wheel on a web page.

7. **Identify potential user errors:** Look for scenarios where the tests check for incorrect usage or state (e.g., trying to send a wheel event before the capture session has started, or when the video track has ended).

8. **Consider debugging:** Think about how these tests can aid in debugging. The specific error messages and the test setup (simulating different conditions) provide valuable clues for developers.

9. **Structure the response:** Organize the findings into logical sections: overall functionality, relationship to web technologies, logical reasoning (input/output), common errors, debugging, and a concise summary. Use clear and descriptive language.

10. **Address the "Part 2" aspect:** Since this is the second part of the analysis, summarize the key functionalities covered in this specific snippet, building on the understanding gained from the previous (unseen) part. Focus on the wheel event handling aspects.
这是对 Chromium Blink 引擎源代码文件 `blink/renderer/modules/mediastream/capture_controller_test.cc` 的第二部分功能归纳。

**总的功能归纳 (基于提供的第二部分代码):**

这部分代码主要专注于测试 `CaptureController` 类处理鼠标滚轮事件 (wheel events) 的功能，具体包括：

* **`sendWheel` 方法的测试:**  测试在不同场景下 `sendWheel` 方法的正确行为，包括成功发送滚轮事件和各种失败情况。
* **`captureWheel` 方法的测试:** 测试 `captureWheel` 方法的流程，包括请求捕获权限、监听指定元素的滚轮事件、将事件发送到浏览器进程以及停止捕获。
* **参数验证:** 测试 `sendWheel` 方法对于滚轮事件坐标参数的验证逻辑。

**与 JavaScript, HTML, CSS 的关系以及举例说明:**

* **JavaScript:**
    * `CaptureController` 类是在 Blink 渲染引擎中实现的，它为 JavaScript 提供了与屏幕捕获相关的 API。
    * `sendWheel` 方法很可能对应着 JavaScript 中用于向捕获目标发送模拟滚轮事件的 API，尽管在 Web API 中直接模拟滚轮事件发送可能有限制，这里更多的是测试内部逻辑。
    * `captureWheel` 方法对应着 JavaScript 中开始捕获指定 HTML 元素上的滚轮事件，这与 `HTMLElement.addEventListener('wheel', ...)` 类似，但多了权限请求和将事件发送到浏览器进程的步骤。

    **举例:**  假设在 JavaScript 中，你可以通过某个 API (可能是 `navigator.mediaDevices.getDisplayMedia` 返回的 `MediaStreamTrack` 对象上的方法) 调用到 `CaptureController` 的 `sendWheel` 或 `captureWheel` 功能。

    ```javascript
    // 假设 streamTrack 是通过屏幕捕获获得的 MediaStreamTrack 对象
    // 假设 captureController 是与 streamTrack 关联的 CaptureController 实例 (内部实现)

    // 模拟发送滚轮事件 (这可能是内部机制，Web API 可能不允许直接这样做)
    captureController.sendWheel({ deltaX: 10, deltaY: 0 });

    // 开始捕获某个 div 元素上的滚轮事件
    const myDiv = document.getElementById('myDiv');
    captureController.captureWheel(myDiv);

    // 用户在 myDiv 上滚动滚轮，事件会被捕获并发送到浏览器进程

    // 停止捕获
    captureController.captureWheel(null);
    ```

* **HTML:**
    * `captureWheel` 方法需要指定一个 HTML 元素作为目标，以便监听其上的滚轮事件。测试代码中使用了 `HTMLDivElement`。

    **举例:**  用户在网页上与一个 `<div>` 元素交互，滚动鼠标滚轮，如果该元素被 `captureWheel` 方法指定，则这些滚轮事件会被捕获。

    ```html
    <div id="myDiv" style="width: 200px; height: 100px; overflow: auto;">
      This is a scrollable div.
    </div>
    ```

* **CSS:**
    * CSS 决定了 HTML 元素的布局和是否可滚动。如果一个元素不可滚动，那么 `captureWheel` 捕获的滚轮事件可能意义不大。测试代码中没有直接涉及 CSS，但元素的 CSS 属性会影响滚轮事件的行为。

    **举例:**  如果一个 `<div>` 元素设置了 `overflow: hidden;`，即使调用了 `captureWheel`，在该元素上滚动滚轮也不会产生视觉上的滚动效果，但事件仍然可以被捕获并发送。

**逻辑推理 (假设输入与输出):**

**`sendWheel` 测试:**

* **假设输入:**
    * `CaptureController` 实例已创建并绑定。
    * 已设置视频轨道 (`MediaStreamTrack`)，并且轨道未结束。
    * 已接收到至少一帧视频帧。
    * 目标是标签页捕获 (SurfaceType::BROWSER)。
    * 滚轮事件的坐标 (x, y) 在视频帧的范围内。
    * 与浏览器进程的通信成功 (模拟的 `DispatcherHost().SendWheel` 返回成功)。
* **预期输出:** `sendWheel` 返回的 Promise 被 resolve (fulfilled)。

* **假设输入 (失败情况):**
    * 没有设置视频轨道。
    * 视频轨道已结束。
    * 目标是窗口或屏幕捕获。
    * 滚轮事件的坐标超出视频帧范围。
    * 与浏览器进程的通信失败 (模拟的 `DispatcherHost().SendWheel` 返回错误)。
    * 在接收到第一帧视频帧之前调用 `sendWheel`。
* **预期输出:** `sendWheel` 返回的 Promise 被 reject，并带有相应的 `DOMException` 错误信息 (例如 "Capture-session not started.", "Video track ended.", "Action only supported for tab-capture.", "Coordinates out of bounds.", "Unknown error.", "No frames observed yet.")。

**`captureWheel` 测试:**

* **假设输入:**
    * `CaptureController` 实例已创建并绑定。
    * 已设置有效的视频轨道。
    * 指定了一个有效的 HTML 元素作为捕获目标。
    * 成功获得捕获滚轮事件的权限。
    * 用户在该元素上触发了滚轮事件。
* **预期输出:**  滚轮事件数据被发送到浏览器进程 (`DispatcherHost().SendWheel` 被调用)。

* **假设输入 (失败情况):**
    * 没有设置视频轨道或轨道已停止。
    * 没有指定捕获目标元素。
    * 请求捕获权限失败。
    * 尝试捕获没有会话 ID 的捕获源的滚轮事件。
* **预期输出:** `captureWheel` 返回的 Promise 被 reject，或者滚轮事件不会被发送到浏览器进程。

**用户或编程常见的使用错误:**

* **在捕获会话开始前尝试发送滚轮事件:**  用户或开发者可能在调用 `captureWheel` 并成功建立连接之前就尝试调用 `sendWheel`。
* **向已结束的视频轨道发送滚轮事件:**  如果视频捕获已经停止，尝试发送滚轮事件会失败。
* **在不支持的捕获类型上发送滚轮事件:**  `sendWheel` 方法可能只支持特定类型的屏幕捕获 (例如标签页捕获)，在窗口或屏幕捕获上调用会出错。
* **忘记调用 `captureWheel(null)` 停止捕获:**  如果持续监听元素的滚轮事件而没有停止，可能会导致不必要的资源消耗或意想不到的行为。
* **尝试捕获没有会话 ID 的捕获源的滚轮事件:** 对于某些捕获场景，可能需要有效的会话 ID。
* **在没有设置有效视频轨道的情况下调用 `captureWheel` 或 `sendWheel`。**

**用户操作如何一步步到达这里 (调试线索):**

1. **用户发起屏幕捕获:** 用户在浏览器中选择共享屏幕或特定窗口/标签页。这通常通过浏览器的 UI 触发 `navigator.mediaDevices.getDisplayMedia` API。
2. **Web 应用程序请求控制捕获表面:** Web 应用程序可能需要模拟用户输入，例如滚动事件，这时可能会调用到 Blink 内部的 `CaptureController`。
3. **JavaScript 调用相关 API:**  Web 应用程序的 JavaScript 代码调用了与 `CaptureController` 功能相关的 API，例如模拟滚轮事件的接口或开始捕获滚轮事件的接口。
4. **Blink 引擎处理请求:**  Blink 引擎接收到 JavaScript 的请求，并创建或使用 `CaptureController` 实例来处理这些操作。
5. **`CaptureController` 执行相应的逻辑:**  `CaptureController` 根据 JavaScript 的调用，执行 `sendWheel` 或 `captureWheel` 方法，与浏览器进程通信，并处理各种错误情况。
6. **测试覆盖了各种场景:** `capture_controller_test.cc` 文件中的测试用例模拟了上述步骤中的各种情况，包括成功的情况和各种错误情况，以确保 `CaptureController` 的行为符合预期。

**第二部分功能归纳:**

这部分测试代码主要关注 `CaptureController` 类中处理鼠标滚轮事件的核心功能：

* **`sendWheel` 方法的详细测试:**  涵盖了 `sendWheel` 在不同状态 (是否有视频轨道、轨道是否结束、是否接收到帧、捕获类型) 下的成功和失败情况，以及参数校验 (坐标范围)。
* **`captureWheel` 方法的功能测试:**  验证了 `captureWheel` 方法启动滚轮事件捕获、将事件发送到浏览器进程、以及停止捕获的流程，并测试了权限请求和错误处理机制。

总的来说，这部分代码深入测试了 `CaptureController` 如何响应和处理与鼠标滚轮事件相关的操作，确保在屏幕共享场景下，模拟或捕获用户的滚动操作能够正确地传递和处理。

Prompt: 
```
这是目录为blink/renderer/modules/mediastream/capture_controller_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
oTrack) {
  V8TestingScope v8_scope;
  CaptureController* controller =
      MakeController(v8_scope.GetExecutionContext());
  controller->SetIsBound(true);
  // Test avoids calling CaptureController::SetVideoTrack().

  const auto promise = controller->sendWheel(v8_scope.GetScriptState(),
                                             CapturedWheelAction::Create());

  ScriptPromiseTester promise_tester(v8_scope.GetScriptState(), promise);
  promise_tester.WaitUntilSettled();
  EXPECT_TRUE(promise_tester.IsRejected());
  EXPECT_TRUE(IsDOMException(v8_scope, promise_tester.Value(),
                             DOMExceptionCode::kInvalidStateError));

  // Avoid false-positives through different error paths terminating in
  // exception with the same code.
  EXPECT_EQ(GetDOMExceptionMessage(v8_scope, promise_tester.Value()),
            "Capture-session not started.");
}

TEST_F(CaptureControllerScrollTest, SendWheelFailsIfVideoTrackEnded) {
  V8TestingScope v8_scope;
  CaptureController* controller =
      MakeController(v8_scope.GetExecutionContext());
  controller->SetIsBound(true);
  MediaStreamTrack* track = MakeTrack(v8_scope, SurfaceType::BROWSER);
  controller->SetVideoTrack(track, "descriptor");
  track->stopTrack(v8_scope.GetExecutionContext());  // Ends the track.

  const auto promise = controller->sendWheel(v8_scope.GetScriptState(),
                                             CapturedWheelAction::Create());

  ScriptPromiseTester promise_tester(v8_scope.GetScriptState(), promise);
  promise_tester.WaitUntilSettled();
  EXPECT_TRUE(promise_tester.IsRejected());
  EXPECT_TRUE(IsDOMException(v8_scope, promise_tester.Value(),
                             DOMExceptionCode::kInvalidStateError));

  // Avoid false-positives through different error paths terminating in
  // exception with the same code.
  EXPECT_EQ(GetDOMExceptionMessage(v8_scope, promise_tester.Value()),
            "Video track ended.");
}

TEST_F(CaptureControllerScrollTest, SendWheelSuccess) {
  V8TestingScope v8_scope;
  CaptureController* controller =
      MakeController(v8_scope.GetExecutionContext());
  controller->SetIsBound(true);
  MediaStreamTrack* track = MakeTrack(v8_scope, SurfaceType::BROWSER);
  controller->SetVideoTrack(track, "descriptor");
  SimulateFrameArrival(track);

  EXPECT_CALL(DispatcherHost(), SendWheel(_, _, _))
      .WillOnce(RunOnceCallback<2>(CscResult::kSuccess));
  const auto promise = controller->sendWheel(v8_scope.GetScriptState(),
                                             CapturedWheelAction::Create());

  ScriptPromiseTester promise_tester(v8_scope.GetScriptState(), promise);
  promise_tester.WaitUntilSettled();
  EXPECT_TRUE(promise_tester.IsFulfilled());
}

// Note that the setup differs from that of SendWheelSuccess only in the
// SurfaceType provided to MakeTrack().
TEST_F(CaptureControllerScrollTest, SendWheelFailsIfCapturingWindow) {
  V8TestingScope v8_scope;
  CaptureController* controller =
      MakeController(v8_scope.GetExecutionContext());
  controller->SetIsBound(true);
  MediaStreamTrack* track = MakeTrack(v8_scope, SurfaceType::WINDOW);
  controller->SetVideoTrack(track, "descriptor");

  const auto promise = controller->sendWheel(v8_scope.GetScriptState(),
                                             CapturedWheelAction::Create());
  ScriptPromiseTester promise_tester(v8_scope.GetScriptState(), promise);
  promise_tester.WaitUntilSettled();
  EXPECT_TRUE(promise_tester.IsRejected());
  EXPECT_TRUE(IsDOMException(v8_scope, promise_tester.Value(),
                             DOMExceptionCode::kNotSupportedError));

  // Avoid false-positives through different error paths terminating in
  // exception with the same code.
  EXPECT_EQ(GetDOMExceptionMessage(v8_scope, promise_tester.Value()),
            "Action only supported for tab-capture.");
}

// Note that the setup differs from that of SendWheelSuccess only in the
// SurfaceType provided to MakeTrack().
TEST_F(CaptureControllerScrollTest, SendWheelFailsIfCapturingMonitor) {
  V8TestingScope v8_scope;
  CaptureController* controller =
      MakeController(v8_scope.GetExecutionContext());
  controller->SetIsBound(true);
  MediaStreamTrack* track = MakeTrack(v8_scope, SurfaceType::MONITOR);
  controller->SetVideoTrack(track, "descriptor");

  const auto promise = controller->sendWheel(v8_scope.GetScriptState(),
                                             CapturedWheelAction::Create());
  ScriptPromiseTester promise_tester(v8_scope.GetScriptState(), promise);
  promise_tester.WaitUntilSettled();
  EXPECT_TRUE(promise_tester.IsRejected());
  EXPECT_TRUE(IsDOMException(v8_scope, promise_tester.Value(),
                             DOMExceptionCode::kNotSupportedError));

  // Avoid false-positives through different error paths terminating in
  // exception with the same code.
  EXPECT_EQ(GetDOMExceptionMessage(v8_scope, promise_tester.Value()),
            "Action only supported for tab-capture.");
}

// Note that the setup differs from that of SendWheelSuccess only in the
// simulated result from the browser process.
TEST_F(CaptureControllerScrollTest, SimulatedFailureFromDispatcherHost) {
  V8TestingScope v8_scope;
  CaptureController* controller =
      MakeController(v8_scope.GetExecutionContext());
  controller->SetIsBound(true);
  MediaStreamTrack* track = MakeTrack(v8_scope, SurfaceType::BROWSER);
  controller->SetVideoTrack(track, "descriptor");
  SimulateFrameArrival(track);

  EXPECT_CALL(DispatcherHost(), SendWheel(_, _, _))
      .WillOnce(RunOnceCallback<2>(CscResult::kUnknownError));
  const auto promise = controller->sendWheel(v8_scope.GetScriptState(),
                                             CapturedWheelAction::Create());

  ScriptPromiseTester promise_tester(v8_scope.GetScriptState(), promise);
  promise_tester.WaitUntilSettled();
  EXPECT_TRUE(promise_tester.IsRejected());
  EXPECT_TRUE(IsDOMException(v8_scope, promise_tester.Value(),
                             DOMExceptionCode::kUnknownError));

  // Avoid false-positives through different error paths terminating in
  // exception with the same code.
  EXPECT_EQ(GetDOMExceptionMessage(v8_scope, promise_tester.Value()),
            "Unknown error.");
}

// Note that the setup differs from that of SendWheelSuccess only in the
// absence of a call to SimulateFrameArrival().
TEST_F(CaptureControllerScrollTest, SendWheelFailsBeforeReceivingFrames) {
  V8TestingScope v8_scope;
  CaptureController* controller =
      MakeController(v8_scope.GetExecutionContext());
  controller->SetIsBound(true);
  MediaStreamTrack* track = MakeTrack(v8_scope, SurfaceType::BROWSER);
  controller->SetVideoTrack(track, "descriptor");
  // Intentionally avoid calling SimulateFrameArrival().

  const auto promise = controller->sendWheel(v8_scope.GetScriptState(),
                                             CapturedWheelAction::Create());
  ScriptPromiseTester promise_tester(v8_scope.GetScriptState(), promise);
  promise_tester.WaitUntilSettled();
  EXPECT_TRUE(promise_tester.IsRejected());
  EXPECT_TRUE(IsDOMException(v8_scope, promise_tester.Value(),
                             DOMExceptionCode::kInvalidStateError));

  // Avoid false-positives through different error paths terminating in
  // exception with the same code.
  EXPECT_EQ(GetDOMExceptionMessage(v8_scope, promise_tester.Value()),
            "No frames observed yet.");
}

// This test:
// * Simulates the arrival of a frame of a given size.
// * Simulates a call to sendWheel() at a specific point.
// * Expects scaling.
TEST_F(CaptureControllerScrollTest, SendWheelScalesCorrectly) {
  V8TestingScope v8_scope;
  CaptureController* controller =
      MakeController(v8_scope.GetExecutionContext());
  controller->SetIsBound(true);
  MediaStreamTrack* track = MakeTrack(v8_scope, SurfaceType::BROWSER);
  controller->SetVideoTrack(track, "descriptor");
  SimulateFrameArrival(track, gfx::Size(200, 4000));

  CapturedWheelAction* const action = CapturedWheelAction::Create();
  action->setX(100);
  action->setY(250);
  action->setWheelDeltaX(111);
  action->setWheelDeltaY(222);

  mojom::blink::CapturedWheelAction dispatcher_action;
  EXPECT_CALL(DispatcherHost(), SendWheel(_, _, _))
      .WillOnce(DoAll(SaveArgPointee<1>(&dispatcher_action),
                      RunOnceCallbackRepeatedly<2>(CscResult::kSuccess)));
  const auto promise = controller->sendWheel(v8_scope.GetScriptState(), action);
  ScriptPromiseTester promise_tester(v8_scope.GetScriptState(), promise);
  promise_tester.WaitUntilSettled();
  EXPECT_TRUE(promise_tester.IsFulfilled());
  EXPECT_EQ(dispatcher_action.relative_x, 100.0 / 200.0);
  EXPECT_EQ(dispatcher_action.relative_y, 250.0 / 4000.0);
  EXPECT_EQ(dispatcher_action.wheel_delta_x, 111);
  EXPECT_EQ(dispatcher_action.wheel_delta_y, 222);
}

TEST_F(CaptureControllerScrollTest, SendWheelFailsWithoutSessionId) {
  V8TestingScope v8_scope;
  CaptureController* controller =
      MakeController(v8_scope.GetExecutionContext());
  controller->SetIsBound(true);
  MediaStreamTrack* track = MakeTrack(
      v8_scope, SurfaceType::BROWSER,
      CaptureController::getSupportedZoomLevels()[0], /*use_session_id=*/false);
  controller->SetVideoTrack(track, "descriptor");
  SimulateFrameArrival(track);

  const auto promise = controller->sendWheel(v8_scope.GetScriptState(),
                                             CapturedWheelAction::Create());
  ScriptPromiseTester promise_tester(v8_scope.GetScriptState(), promise);
  promise_tester.WaitUntilSettled();
  EXPECT_TRUE(promise_tester.IsRejected());
  EXPECT_TRUE(IsDOMException(v8_scope, promise_tester.Value(),
                             DOMExceptionCode::kUnknownError));

  // Avoid false-positives through different error paths terminating in
  // exception with the same code.
  EXPECT_EQ(GetDOMExceptionMessage(v8_scope, promise_tester.Value()),
            "Invalid capture");
}

class CaptureConstrollerCaptureWheelTest : public PageTestBase,
                                           public CaptureControllerTestSupport {
};

TEST_F(CaptureConstrollerCaptureWheelTest, Success) {
  CaptureController* controller =
      MakeController(GetDocument().GetExecutionContext());
  controller->SetIsBound(true);
  MediaStreamTrack* track =
      MakeTrack(GetDocument().GetExecutionContext(), SurfaceType::BROWSER);
  controller->SetVideoTrack(track, "descriptor");

  HTMLDivElement* element = MakeGarbageCollected<HTMLDivElement>(GetDocument());
  ScriptState* script_state = ToScriptStateForMainWorld(&GetFrame());

  ScriptState::Scope scope(script_state);
  EXPECT_CALL(DispatcherHost(), RequestCapturedSurfaceControlPermission(_, _))
      .WillOnce(RunOnceCallback<1>(CscResult::kSuccess));
  auto promise = controller->captureWheel(script_state, element);

  ScriptPromiseTester promise_tester(script_state, promise);
  promise_tester.WaitUntilSettled();
  EXPECT_TRUE(promise_tester.IsFulfilled());

  base::RunLoop run_loop;
  EXPECT_CALL(DispatcherHost(), SendWheel(_, _, _))
      .WillOnce(DoAll(Invoke(&run_loop, &base::RunLoop::Quit),
                      RunOnceCallback<2>(CscResult::kSuccess)));
  element->DispatchEvent(
      *WheelEvent::Create(event_type_names::kWheel, WheelEventInit::Create()));
  run_loop.Run();

  promise = controller->captureWheel(script_state, nullptr);
  ScriptPromiseTester promise_tester2(script_state, promise);
  promise_tester.WaitUntilSettled();
  EXPECT_TRUE(promise_tester.IsFulfilled());

  auto* mock_listener = MakeGarbageCollected<MockEventListener>();
  element->addEventListener(event_type_names::kWheel, mock_listener);
  base::RunLoop run_loop2;
  EXPECT_CALL(DispatcherHost(), SendWheel(_, _, _)).Times(0);
  EXPECT_CALL(*mock_listener, Invoke)
      .WillOnce(Invoke(&run_loop2, &base::RunLoop::Quit));
  element->DispatchEvent(
      *WheelEvent::Create(event_type_names::kWheel, WheelEventInit::Create()));
  run_loop2.Run();
}

TEST_F(CaptureConstrollerCaptureWheelTest, DropUntrustedEvent) {
  CaptureController* controller =
      MakeController(GetDocument().GetExecutionContext());
  controller->SetIsBound(true);
  MediaStreamTrack* track =
      MakeTrack(GetDocument().GetExecutionContext(), SurfaceType::BROWSER);
  controller->SetVideoTrack(track, "descriptor");

  HTMLDivElement* element = MakeGarbageCollected<HTMLDivElement>(GetDocument());
  ScriptState* script_state = ToScriptStateForMainWorld(&GetFrame());

  ScriptState::Scope scope(script_state);
  EXPECT_CALL(DispatcherHost(), RequestCapturedSurfaceControlPermission(_, _))
      .WillOnce(RunOnceCallback<1>(CscResult::kSuccess));
  ScriptPromiseTester(script_state,
                      controller->captureWheel(script_state, element))
      .WaitUntilSettled();

  EXPECT_CALL(DispatcherHost(), SendWheel(_, _, _)).Times(0);
  DummyExceptionStateForTesting exception_state;
  // Events dispatched with dispatchEventForBindings are always untrusted.
  element->dispatchEventForBindings(
      WheelEvent::Create(event_type_names::kWheel, WheelEventInit::Create()),
      exception_state);

  task_environment().RunUntilIdle();
}

TEST_F(CaptureConstrollerCaptureWheelTest, SuccessWithNoElement) {
  CaptureController* controller =
      MakeController(GetDocument().GetExecutionContext());
  controller->SetIsBound(true);
  MediaStreamTrack* track =
      MakeTrack(GetDocument().GetExecutionContext(), SurfaceType::BROWSER);
  controller->SetVideoTrack(track, "descriptor");

  ScriptState* script_state = ToScriptStateForMainWorld(&GetFrame());
  ScriptState::Scope scope(script_state);

  EXPECT_CALL(DispatcherHost(), RequestCapturedSurfaceControlPermission(_, _))
      .Times(0);
  auto promise = controller->captureWheel(script_state, nullptr);
  ScriptPromiseTester promise_tester(script_state, promise);
  promise_tester.WaitUntilSettled();
  EXPECT_TRUE(promise_tester.IsFulfilled());
}

TEST_F(CaptureConstrollerCaptureWheelTest, BackendError) {
  ExecutionContext* execution_context = GetDocument().GetExecutionContext();
  CaptureController* controller = MakeController(execution_context);
  controller->SetIsBound(true);
  MediaStreamTrack* track =
      MakeTrack(GetDocument().GetExecutionContext(), SurfaceType::BROWSER);
  controller->SetVideoTrack(track, "descriptor");

  HTMLDivElement* element = MakeGarbageCollected<HTMLDivElement>(GetDocument());
  ScriptState* script_state = ToScriptStateForMainWorld(&GetFrame());

  EXPECT_CALL(DispatcherHost(), SendWheel(_, _, _)).Times(0);

  ScriptState::Scope scope(script_state);
  for (CscResult csc_error_result :
       {CscResult::kUnknownError, CscResult::kNoPermissionError,
        CscResult::kCapturerNotFoundError,
        CscResult::kCapturedSurfaceNotFoundError,
        CscResult::kDisallowedForSelfCaptureError,
        CscResult::kCapturerNotFocusedError}) {
    EXPECT_CALL(DispatcherHost(), RequestCapturedSurfaceControlPermission(_, _))
        .WillOnce(RunOnceCallback<1>(csc_error_result));
    const auto promise = controller->captureWheel(script_state, element);

    ScriptPromiseTester promise_tester(script_state, promise);
    promise_tester.WaitUntilSettled();
    EXPECT_TRUE(promise_tester.IsRejected());

    auto* mock_listener = MakeGarbageCollected<MockEventListener>();
    element->addEventListener(event_type_names::kWheel, mock_listener);
    base::RunLoop run_loop;

    EXPECT_CALL(*mock_listener, Invoke)
        .WillRepeatedly(Invoke(&run_loop, &base::RunLoop::Quit));
    element->DispatchEvent(*WheelEvent::Create(event_type_names::kWheel,
                                               WheelEventInit::Create()));
    run_loop.Run();
  }
}

TEST_F(CaptureConstrollerCaptureWheelTest, NoSessionId) {
  CaptureController* controller =
      MakeController(GetDocument().GetExecutionContext());
  controller->SetIsBound(true);
  MediaStreamTrack* track =
      MakeTrack(GetDocument().GetExecutionContext(), SurfaceType::BROWSER,
                /*initial_zoom_level=*/100, /*use_session_id=*/false);
  controller->SetVideoTrack(track, "descriptor");

  HTMLDivElement* element = MakeGarbageCollected<HTMLDivElement>(GetDocument());
  ScriptState* script_state = ToScriptStateForMainWorld(&GetFrame());

  ScriptState::Scope scope(script_state);
  auto promise = controller->captureWheel(script_state, element);

  ScriptPromiseTester promise_tester(script_state, promise);
  promise_tester.WaitUntilSettled();
  EXPECT_TRUE(promise_tester.IsRejected());
  EXPECT_TRUE(IsDOMException(script_state, promise_tester.Value(),
                             DOMExceptionCode::kInvalidStateError));
  EXPECT_EQ(GetDOMExceptionMessage(script_state, promise_tester.Value()),
            "Invalid capture.");
}

TEST_F(CaptureConstrollerCaptureWheelTest, NoTrack) {
  CaptureController* controller =
      MakeController(GetDocument().GetExecutionContext());
  controller->SetIsBound(true);
  MediaStreamTrack* track =
      MakeTrack(GetDocument().GetExecutionContext(), SurfaceType::BROWSER,
                /*initial_zoom_level=*/100, /*use_session_id=*/false);
  controller->SetVideoTrack(track, "descriptor");

  HTMLDivElement* element = MakeGarbageCollected<HTMLDivElement>(GetDocument());
  ScriptState* script_state = ToScriptStateForMainWorld(&GetFrame());

  ScriptState::Scope scope(script_state);
  auto promise = controller->captureWheel(script_state, element);

  ScriptPromiseTester promise_tester(script_state, promise);
  promise_tester.WaitUntilSettled();
  EXPECT_TRUE(promise_tester.IsRejected());
  EXPECT_TRUE(IsDOMException(script_state, promise_tester.Value(),
                             DOMExceptionCode::kInvalidStateError));
  EXPECT_EQ(GetDOMExceptionMessage(script_state, promise_tester.Value()),
            "Invalid capture.");
}

TEST_F(CaptureConstrollerCaptureWheelTest, StoppedTrack) {
  CaptureController* controller =
      MakeController(GetDocument().GetExecutionContext());
  controller->SetIsBound(true);
  MediaStreamTrack* track =
      MakeTrack(GetDocument().GetExecutionContext(), SurfaceType::BROWSER,
                /*initial_zoom_level=*/100, /*use_session_id=*/false);
  controller->SetVideoTrack(track, "descriptor");

  HTMLDivElement* element = MakeGarbageCollected<HTMLDivElement>(GetDocument());
  ScriptState* script_state = ToScriptStateForMainWorld(&GetFrame());

  ScriptState::Scope scope(script_state);
  track->stopTrack(GetDocument().GetExecutionContext());
  auto promise = controller->captureWheel(script_state, element);

  ScriptPromiseTester promise_tester(script_state, promise);
  promise_tester.WaitUntilSettled();
  EXPECT_TRUE(promise_tester.IsRejected());
  EXPECT_TRUE(IsDOMException(script_state, promise_tester.Value(),
                             DOMExceptionCode::kInvalidStateError));
  EXPECT_EQ(GetDOMExceptionMessage(script_state, promise_tester.Value()),
            "Invalid capture.");
}

// Test the validation of sendWheel() parameters.
class CaptureControllerScrollParametersValidationTest
    : public CaptureControllerScrollTest,
      public WithParamInterface<
          std::tuple<std::tuple<ScrollDirection, ScrollDirection>,
                     std::tuple<gfx::Point, bool>>> {
 public:
  static constexpr int kWidth = 1000;
  static constexpr int kHeight = 2000;

  CaptureControllerScrollParametersValidationTest()
      : vertical_scroll_direction_(std::get<0>(std::get<0>(GetParam()))),
        horizontal_scroll_direction_(std::get<1>(std::get<0>(GetParam()))),
        scroll_coordinates_(std::get<0>(std::get<1>(GetParam()))),
        expect_success_(std::get<1>(std::get<1>(GetParam()))) {}
  ~CaptureControllerScrollParametersValidationTest() override = default;

  static int GetScrollValue(ScrollDirection direction) {
    switch (direction) {
      case ScrollDirection::kNone:
        return 0;
      case ScrollDirection::kForwards:
        return 10;
      case ScrollDirection::kBackwards:
        return -10;
    }
  }

  int wheel_deltax_x() const {
    return GetScrollValue(horizontal_scroll_direction_);
  }

  int wheel_deltax_y() const {
    return GetScrollValue(vertical_scroll_direction_);
  }

 protected:
  const ScrollDirection vertical_scroll_direction_;
  const ScrollDirection horizontal_scroll_direction_;
  const gfx::Point scroll_coordinates_;
  const bool expect_success_;
};

namespace {
constexpr int kLeftmost = 0;
constexpr int kRightmost =
    CaptureControllerScrollParametersValidationTest::kWidth - 1;
constexpr int kTop = 0;
constexpr int kBottom =
    CaptureControllerScrollParametersValidationTest::kHeight - 1;

INSTANTIATE_TEST_SUITE_P(
    ,
    CaptureControllerScrollParametersValidationTest,
    Combine(
        // Scroll direction.
        Combine(
            // Vertical scroll.
            Values(ScrollDirection::kNone,
                   ScrollDirection::kForwards,
                   ScrollDirection::kBackwards),
            // Horizontal scroll.
            Values(ScrollDirection::kNone,
                   ScrollDirection::kForwards,
                   ScrollDirection::kBackwards)),
        // Scroll coordinates and expectation.
        Values(
            // Corners
            std::make_tuple(gfx::Point(kLeftmost, kTop), true),
            std::make_tuple(gfx::Point(kLeftmost, kBottom), true),
            std::make_tuple(gfx::Point(kRightmost, kTop), true),
            std::make_tuple(gfx::Point(kRightmost, kBottom), true),
            // Just beyond top-left
            std::make_tuple(gfx::Point(kLeftmost - 1, kTop), false),
            std::make_tuple(gfx::Point(kLeftmost, kTop - 1), false),
            // Just beyond bottom-left
            std::make_tuple(gfx::Point(kLeftmost - 1, kBottom), false),
            std::make_tuple(gfx::Point(kLeftmost, kBottom + 1), false),
            // Just beyond top-right
            std::make_tuple(gfx::Point(kRightmost + 1, kTop), false),
            std::make_tuple(gfx::Point(kRightmost, kTop - 1), false),
            // Just beyond bottom-right
            std::make_tuple(gfx::Point(kRightmost + 1, kBottom), false),
            std::make_tuple(gfx::Point(kRightmost, kBottom + 1), false))));
}  // namespace

TEST_P(CaptureControllerScrollParametersValidationTest, ValidateCoordinates) {
  V8TestingScope v8_scope;
  CaptureController* controller =
      MakeController(v8_scope.GetExecutionContext());
  controller->SetIsBound(true);
  MediaStreamTrack* track = MakeTrack(v8_scope, SurfaceType::BROWSER);
  controller->SetVideoTrack(track, "descriptor");
  SimulateFrameArrival(track, gfx::Size(kWidth, kHeight));

  if (expect_success_) {
    EXPECT_CALL(DispatcherHost(), SendWheel(_, _, _))
        .WillOnce(RunOnceCallback<2>(CscResult::kSuccess));
  }
  CapturedWheelAction* const action = CapturedWheelAction::Create();
  action->setX(scroll_coordinates_.x());
  action->setY(scroll_coordinates_.y());
  action->setWheelDeltaX(wheel_deltax_x());
  action->setWheelDeltaY(wheel_deltax_y());
  const auto promise = controller->sendWheel(v8_scope.GetScriptState(), action);

  ScriptPromiseTester promise_tester(v8_scope.GetScriptState(), promise);
  promise_tester.WaitUntilSettled();
  EXPECT_TRUE(expect_success_ ? promise_tester.IsFulfilled()
                              : promise_tester.IsRejected());

  // Avoid false-positives through different error paths terminating in
  // exception with the same code.
  if (!expect_success_) {
    EXPECT_EQ(GetDOMExceptionMessage(v8_scope, promise_tester.Value()),
              "Coordinates out of bounds.");
  }
}

}  // namespace blink

"""


```