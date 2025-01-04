Response:
The user wants me to summarize the functionality of the provided C++ code snippet from a Chromium Blink engine file. This is the second part of a three-part request. I need to focus on the code provided and avoid repeating information from previous parts.

The code snippet primarily contains unit tests for the `InputHandlerProxy` class. These tests cover various aspects of how `InputHandlerProxy` handles different types of input events, especially touch and gesture events.

Here's a breakdown of the functionality demonstrated in the tests:

1. **Touch Event Handling and Hit Testing:** Tests related to how `InputHandlerProxy` determines the target of touch events based on hit testing and the presence of touch event listeners (blocking vs. passive). This involves interactions with the `mock_input_handler_` to simulate the underlying input handling logic.

2. **Multi-Touch Handling:** Tests verifying how `InputHandlerProxy` deals with multiple touch points, including scenarios where some touch points hit interactive regions and others don't.

3. **Touch Sequence Management:** Tests that check how `InputHandlerProxy` tracks the beginning and end of touch sequences, including handling `TouchCancel` events and interruptions by other events like `MouseDown`.

4. **Interaction with `InputHandler` and `InputHandlerProxyClient`:**  The tests extensively use mock objects (`mock_input_handler_` and `mock_client_`) to simulate the behavior of the compositor's input handler and the client interacting with the proxy. This includes verifying calls to methods like `EventListenerTypeForTouchStartOrMoveAt`, `SetAllowedTouchAction`, `SetIsHandlingTouchSequence`, `HitTest`, and `UpdateBrowserControlsState`.

5. **Gesture Event Handling and Main Thread Hit Testing:**  A significant portion of the code focuses on testing the unified scrolling logic and how `InputHandlerProxy` handles gesture scroll events, especially when a main thread hit test is required. This includes testing event queueing, coalescing, and the re-injection of events after the main thread hit test.

6. **Synchronous Input Handling:**  Tests related to how `InputHandlerProxy` interacts with a `SynchronousInputHandler`, including setting it up and calling methods like `UpdateRootLayerStateForSynchronousInputHandler` and `SynchronouslySetRootScrollOffset`.

7. **Event Queueing and VSync Alignment:** Tests that examine how gesture events are queued and dispatched in sync with VSync, including coalescing of events and the use of a simulated tick clock.

8. **Event Attribution:** Tests verifying how `InputHandlerProxy` determines the target frame for input events (attribution).

Based on this, I can now formulate a concise summary of the functionality covered in this code snippet.这段代码是 `blink/renderer/platform/widget/input/input_handler_proxy_unittest.cc` 文件的一部分，主要功能是 **测试 `InputHandlerProxy` 类处理各种触摸事件的逻辑，特别是多点触控和与主线程交互的场景**。

以下是对其功能的归纳，并结合 JavaScript, HTML, CSS 的功能进行说明：

**功能归纳:**

*   **测试多点触摸的命中测试 (Hit Test):**  验证当多个触摸点中部分命中可交互区域（例如，绑定了 `touchstart` 或 `touchmove` 事件的元素）时，`InputHandlerProxy` 如何决定是否将事件发送到主线程处理。
*   **测试被动监听器 (Passive Listener) 的处理:** 验证当触摸事件的监听器是被动时，事件是否会被发送到合成器线程（impl thread）处理。
*   **测试触摸序列的结束 (Touch Sequence Ending):**  验证当触摸序列被 `touchcancel` 事件或其他事件（例如 `mousedown`）中断时，`InputHandlerProxy` 如何处理并重置触摸状态。
*   **测试 `touchstart` 被动但 `touchend` 阻塞的情况:**  验证在这种特殊情况下，为了维持事件目标，`touchstart` 会以非阻塞的方式派发，而中间的 `touchmove` 事件会被丢弃。
*   **测试在被动 `touchstart` 之后添加阻塞的 `touchmove` 监听器的情况:** 验证在这种动态添加监听器的情况下，事件的处理流程。
*   **测试浏览器控件状态的更新:**  验证 `InputHandlerProxy` 是否能正确地更新浏览器控件的状态。
*   **测试统一滚动输入处理 (Unified Scrolling Input Handling):**  这部分着重测试了手势滚动事件的处理流程，包括：
    *   **主线程命中测试 (Main Thread Hit Test):** 验证当需要主线程进行命中测试时，`InputHandlerProxy` 如何暂停事件派发，等待主线程的命中结果，然后继续处理。
    *   **事件队列和合并:**  验证在等待主线程命中测试期间，手势事件如何被队列化和合并。
    *   **主线程命中测试的结果处理:** 验证接收到主线程命中测试结果后，`InputHandlerProxy` 如何更新事件并继续派发。
    *   **手势滚动事件的度量 (Metrics):** 验证在主线程命中测试过程中，手势滚动事件的开始和结束是否被正确记录。
    *   **滚动事件和开始事件在主线程命中测试期间的到达:** 验证在这种复杂情况下事件的处理顺序和逻辑。
    *   **主线程命中测试失败的处理:** 验证当主线程命中测试返回空结果时，`InputHandlerProxy` 如何处理并重置状态。

**与 JavaScript, HTML, CSS 的关系举例:**

*   **多点触摸的命中测试:**  当 HTML 页面中存在绑定了 JavaScript 事件监听器（如 `element.addEventListener('touchstart', handler)`）的元素时，`InputHandlerProxy` 需要判断触摸点是否在该元素上。如果触摸点在该元素上，事件通常需要发送到主线程的 JavaScript 代码进行处理。
*   **被动监听器:**  JavaScript 可以注册被动事件监听器，例如 `element.addEventListener('touchstart', handler, { passive: true })`。这种监听器告诉浏览器该监听器不会调用 `preventDefault()` 来阻止默认行为（如滚动）。`InputHandlerProxy` 会识别这种被动监听器，并可能将事件发送到合成器线程以提高性能，允许滚动等操作在不等待主线程的情况下进行。
*   **触摸序列的结束:** 当用户手指离开屏幕或触摸被系统取消时（例如，来电），会触发 `touchend` 或 `touchcancel` 事件。`InputHandlerProxy` 需要正确处理这些事件，清理触摸状态，防止后续事件处理错误。
*   **`touchstart` 被动但 `touchend` 阻塞的情况:** 某些情况下，开发者可能希望在 `touchend` 时执行一些需要阻止默认行为的操作，但在 `touchstart` 时不需要。这种情况下，`InputHandlerProxy` 会先以非阻塞的方式处理 `touchstart`，以避免滚动卡顿，但会丢弃中间的 `touchmove` 事件，确保 `touchend` 的目标一致性。
*   **主线程命中测试:**  当发生手势滚动时，`InputHandlerProxy` 可能需要询问主线程才能确定滚动的目标元素，特别是当滚动可能发生在 iframe 或其他复杂布局中。这涉及到浏览器渲染引擎的内部机制，但最终会影响 JavaScript 代码中事件的触发和目标元素。

**逻辑推理的假设输入与输出:**

**示例 1: `MultiTouchPointHitTestPositive` 测试**

*   **假设输入:** 一个 `TouchStart` 事件，包含三个触摸点，坐标分别为 (0, 0), (10, 10), 和 (-10, 10)。
*   **假设条件:**  `mock_input_handler_` 的模拟行为是：
    *   坐标为 (0, 0) 的触摸点没有对应的监听器（返回 `kNoHandler`）。
    *   坐标大于 0 的触摸点 (10, 10) 命中一个滚动区域（返回 `kHandlerOnScrollingLayer`）。
    *   对于第三个触摸点，由于已经有一个触摸点命中，所以不会进行命中测试。
*   **预期输出:** `expected_disposition_` 的值应该为 `InputHandlerProxy::DID_NOT_HANDLE_NON_BLOCKING`，表示事件被发送到主线程处理。同时，`mock_client_` 的 `SetAllowedTouchAction` 方法应该被调用，参数为 `cc::TouchAction::kPanY`，表示允许垂直方向的滚动。

**示例 2: `MainThreadHitTestRequired` 测试**

*   **假设输入:** 一个 `GestureScrollBegin` 事件。
*   **假设条件:** `mock_input_handler_` 的 `ScrollBegin` 方法返回 `kRequiresMainThreadHitTestState`。
*   **预期输出:** `InputHandlerProxy` 返回 `InputHandlerProxy::REQUIRES_MAIN_THREAD_HIT_TEST`，并且内部状态 `MainThreadHitTestInProgress()` 为 `true`，表示正在等待主线程的命中测试结果。后续的 `GestureScrollUpdate` 事件会被队列化，不会立即发送到 `mock_input_handler_`。

**用户或编程常见的使用错误举例:**

*   **忘记处理 `touchcancel` 事件:**  开发者可能只关注 `touchstart` 和 `touchend`，但忽略了 `touchcancel` 事件。这可能导致在触摸被打断时，应用程序状态不一致或出现未预期的行为。例如，一个正在进行的拖拽操作可能因为 `touchcancel` 而没有正确结束。
*   **在被动监听器中调用 `preventDefault()`:**  如果在注册了 `passive: true` 的事件监听器中调用 `event.preventDefault()`，浏览器会忽略这个调用，并可能在控制台中发出警告。开发者可能期望阻止默认行为，但实际上并没有生效，导致页面滚动等默认行为发生。
*   **错误地假设所有触摸事件都在主线程处理:**  开发者可能没有意识到被动监听器和合成器线程的存在，错误地假设所有的触摸事件都会立即在主线程的 JavaScript 代码中执行。这可能导致性能问题，因为某些可以由合成器线程处理的事件被不必要地发送到主线程。

总而言之，这段代码通过大量的单元测试，细致地验证了 `InputHandlerProxy` 在处理各种复杂的触摸和手势输入场景下的正确性和效率，确保了 Blink 引擎能够准确、流畅地响应用户的触摸操作。

Prompt: 
```
这是目录为blink/renderer/platform/widget/input/input_handler_proxy_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
dlerProxyTest, MultiTouchPointHitTestPositive) {
  // One of the touch points is on a touch-region. So the event should be sent
  // to the main thread.
  expected_disposition_ = InputHandlerProxy::DID_NOT_HANDLE_NON_BLOCKING;
  VERIFY_AND_RESET_MOCKS();

  EXPECT_CALL(mock_input_handler_,
              EventListenerTypeForTouchStartOrMoveAt(
                  testing::Property(&gfx::Point::x, testing::Eq(0)), _))
      .WillOnce(testing::Invoke([](const gfx::Point&,
                                   cc::TouchAction* touch_action) {
        *touch_action = cc::TouchAction::kAuto;
        return cc::InputHandler::TouchStartOrMoveEventListenerType::kNoHandler;
      }));
  EXPECT_CALL(mock_input_handler_,
              EventListenerTypeForTouchStartOrMoveAt(
                  testing::Property(&gfx::Point::x, testing::Gt(0)), _))
      .WillOnce(
          testing::Invoke([](const gfx::Point&, cc::TouchAction* touch_action) {
            *touch_action = cc::TouchAction::kPanY;
            return cc::InputHandler::TouchStartOrMoveEventListenerType::
                kHandlerOnScrollingLayer;
          }));
  EXPECT_CALL(mock_client_, SetAllowedTouchAction(cc::TouchAction::kPanY))
      .WillOnce(testing::Return());
  EXPECT_CALL(mock_input_handler_, SetIsHandlingTouchSequence(true));
  // Since the second touch point hits a touch-region, there should be no
  // hit-testing for the third touch point.

  WebTouchEvent touch(WebInputEvent::Type::kTouchStart,
                      WebInputEvent::kNoModifiers,
                      WebInputEvent::GetStaticTimeStampForTests());

  touch.unique_touch_event_id = 1;
  touch.touches_length = 3;
  touch.touch_start_or_first_touch_move = true;
  touch.touches[0] =
      CreateWebTouchPoint(WebTouchPoint::State::kStatePressed, 0, 0);
  touch.touches[1] =
      CreateWebTouchPoint(WebTouchPoint::State::kStatePressed, 10, 10);
  touch.touches[2] =
      CreateWebTouchPoint(WebTouchPoint::State::kStatePressed, -10, 10);
  EXPECT_EQ(expected_disposition_,
            HandleInputEventWithLatencyInfo(input_handler_.get(), touch));

  VERIFY_AND_RESET_MOCKS();
}

TEST_P(InputHandlerProxyTest, MultiTouchPointHitTestPassivePositive) {
  // One of the touch points is not on a touch-region. So the event should be
  // sent to the impl thread.
  expected_disposition_ = InputHandlerProxy::DID_NOT_HANDLE_NON_BLOCKING;
  VERIFY_AND_RESET_MOCKS();

  EXPECT_CALL(
      mock_input_handler_,
      GetEventListenerProperties(cc::EventListenerClass::kTouchStartOrMove))
      .WillRepeatedly(testing::Return(cc::EventListenerProperties::kPassive));
  EXPECT_CALL(mock_input_handler_, EventListenerTypeForTouchStartOrMoveAt(_, _))
      .Times(3)
      .WillOnce(testing::Invoke([](const gfx::Point&,
                                   cc::TouchAction* touch_action) {
        *touch_action = cc::TouchAction::kPanRight;
        return cc::InputHandler::TouchStartOrMoveEventListenerType::kNoHandler;
      }))
      .WillRepeatedly(testing::Invoke([](const gfx::Point&,
                                         cc::TouchAction* touch_action) {
        *touch_action = cc::TouchAction::kPanX;
        return cc::InputHandler::TouchStartOrMoveEventListenerType::kNoHandler;
      }));
  EXPECT_CALL(mock_client_, SetAllowedTouchAction(cc::TouchAction::kPanRight))
      .WillOnce(testing::Return());
  EXPECT_CALL(mock_input_handler_, SetIsHandlingTouchSequence(true));

  WebTouchEvent touch(WebInputEvent::Type::kTouchStart,
                      WebInputEvent::kNoModifiers,
                      WebInputEvent::GetStaticTimeStampForTests());

  touch.unique_touch_event_id = 1;
  touch.touches_length = 3;
  touch.touch_start_or_first_touch_move = true;
  touch.touches[0] =
      CreateWebTouchPoint(WebTouchPoint::State::kStatePressed, 0, 0);
  touch.touches[1] =
      CreateWebTouchPoint(WebTouchPoint::State::kStatePressed, 10, 10);
  touch.touches[2] =
      CreateWebTouchPoint(WebTouchPoint::State::kStatePressed, -10, 10);
  EXPECT_EQ(expected_disposition_,
            HandleInputEventWithLatencyInfo(input_handler_.get(), touch));

  VERIFY_AND_RESET_MOCKS();
}

TEST_P(InputHandlerProxyTest, TouchTrackingEndsOnCancel) {
  // One of the touch points is not on a touch-region. So the event should be
  // sent to the impl thread.
  expected_disposition_ = InputHandlerProxy::DID_NOT_HANDLE_NON_BLOCKING;
  VERIFY_AND_RESET_MOCKS();

  EXPECT_CALL(
      mock_input_handler_,
      GetEventListenerProperties(cc::EventListenerClass::kTouchStartOrMove))
      .WillRepeatedly(testing::Return(cc::EventListenerProperties::kPassive));
  EXPECT_CALL(mock_input_handler_, EventListenerTypeForTouchStartOrMoveAt(_, _))
      .Times(1)
      .WillOnce(testing::Invoke([](const gfx::Point&,
                                   cc::TouchAction* touch_action) {
        *touch_action = cc::TouchAction::kPanRight;
        return cc::InputHandler::TouchStartOrMoveEventListenerType::kNoHandler;
      }));
  EXPECT_CALL(mock_client_, SetAllowedTouchAction(cc::TouchAction::kPanRight))
      .WillOnce(testing::Return());
  EXPECT_CALL(mock_input_handler_, SetIsHandlingTouchSequence(true));
  EXPECT_CALL(mock_input_handler_, HitTest(_))
      .WillOnce(testing::Return(cc::PointerResultType::kUnhandled));

  WebTouchEvent touch(WebInputEvent::Type::kTouchStart,
                      WebInputEvent::kNoModifiers,
                      WebInputEvent::GetStaticTimeStampForTests());

  touch.unique_touch_event_id = 1;
  touch.touches_length = 1;
  touch.touch_start_or_first_touch_move = true;
  touch.touches[0] =
      CreateWebTouchPoint(WebTouchPoint::State::kStatePressed, 0, 0);
  EXPECT_EQ(expected_disposition_,
            HandleInputEventWithLatencyInfo(input_handler_.get(), touch));

  VERIFY_AND_RESET_MOCKS();

  expected_disposition_ = InputHandlerProxy::DID_NOT_HANDLE;
  EXPECT_CALL(mock_input_handler_, HitTest(_))
      .WillOnce(testing::Return(cc::PointerResultType::kUnhandled));

  WebMouseEvent mouse_down(WebInputEvent::Type::kMouseDown,
                           WebInputEvent::kNoModifiers,
                           WebInputEvent::GetStaticTimeStampForTests());
  mouse_down.button = WebMouseEvent::Button::kLeft;
  EXPECT_EQ(expected_disposition_,
            HandleInputEventWithLatencyInfo(input_handler_.get(), mouse_down));

  VERIFY_AND_RESET_MOCKS();

  EXPECT_CALL(mock_input_handler_, SetIsHandlingTouchSequence(false));
  WebTouchEvent touch_cancel(WebInputEvent::Type::kTouchCancel,
                             WebInputEvent::kNoModifiers,
                             WebInputEvent::GetStaticTimeStampForTests());

  touch_cancel.unique_touch_event_id = 2;
  EXPECT_EQ(expected_disposition_, HandleInputEventWithLatencyInfo(
                                       input_handler_.get(), touch_cancel));
  VERIFY_AND_RESET_MOCKS();
}

TEST_P(InputHandlerProxyTest, TouchStartPassiveAndTouchEndBlocking) {
  // The touch start is not in a touch-region but there is a touch end handler
  // so to maintain targeting we need to dispatch the touch start as
  // non-blocking but drop all touch moves.
  expected_disposition_ = InputHandlerProxy::DID_NOT_HANDLE_NON_BLOCKING;
  VERIFY_AND_RESET_MOCKS();

  EXPECT_CALL(
      mock_input_handler_,
      GetEventListenerProperties(cc::EventListenerClass::kTouchStartOrMove))
      .WillOnce(testing::Return(cc::EventListenerProperties::kNone));
  EXPECT_CALL(
      mock_input_handler_,
      GetEventListenerProperties(cc::EventListenerClass::kTouchEndOrCancel))
      .WillOnce(testing::Return(cc::EventListenerProperties::kBlocking));
  EXPECT_CALL(mock_input_handler_, EventListenerTypeForTouchStartOrMoveAt(_, _))
      .WillOnce(testing::Invoke([](const gfx::Point&,
                                   cc::TouchAction* touch_action) {
        *touch_action = cc::TouchAction::kNone;
        return cc::InputHandler::TouchStartOrMoveEventListenerType::kNoHandler;
      }));
  EXPECT_CALL(mock_client_, SetAllowedTouchAction(cc::TouchAction::kNone))
      .WillOnce(testing::Return());
  EXPECT_CALL(mock_input_handler_, SetIsHandlingTouchSequence(true));

  WebTouchEvent touch(WebInputEvent::Type::kTouchStart,
                      WebInputEvent::kNoModifiers,
                      WebInputEvent::GetStaticTimeStampForTests());
  touch.unique_touch_event_id = 1;
  touch.touches_length = 1;
  touch.touches[0] =
      CreateWebTouchPoint(WebTouchPoint::State::kStatePressed, 0, 0);
  touch.touch_start_or_first_touch_move = true;
  EXPECT_EQ(expected_disposition_,
            HandleInputEventWithLatencyInfo(input_handler_.get(), touch));

  touch.SetType(WebInputEvent::Type::kTouchMove);
  touch.touches_length = 1;
  touch.touch_start_or_first_touch_move = false;
  touch.touches[0] =
      CreateWebTouchPoint(WebTouchPoint::State::kStatePressed, 10, 10);
  EXPECT_EQ(InputHandlerProxy::DROP_EVENT,
            HandleInputEventWithLatencyInfo(input_handler_.get(), touch));
  VERIFY_AND_RESET_MOCKS();
}

TEST_P(InputHandlerProxyTest, TouchMoveBlockingAddedAfterPassiveTouchStart) {
  // The touch start is not in a touch-region but there is a touch end handler
  // so to maintain targeting we need to dispatch the touch start as
  // non-blocking but drop all touch moves.
  VERIFY_AND_RESET_MOCKS();

  EXPECT_CALL(
      mock_input_handler_,
      GetEventListenerProperties(cc::EventListenerClass::kTouchStartOrMove))
      .WillOnce(testing::Return(cc::EventListenerProperties::kPassive));
  EXPECT_CALL(mock_input_handler_, EventListenerTypeForTouchStartOrMoveAt(_, _))
      .WillOnce(testing::Return(
          cc::InputHandler::TouchStartOrMoveEventListenerType::kNoHandler));
  EXPECT_CALL(mock_client_, SetAllowedTouchAction(_))
      .WillOnce(testing::Return());
  EXPECT_CALL(mock_input_handler_, HitTest(_))
      .WillOnce(testing::Return(cc::PointerResultType::kUnhandled));
  EXPECT_CALL(mock_input_handler_, SetIsHandlingTouchSequence(true));

  WebTouchEvent touch(WebInputEvent::Type::kTouchStart,
                      WebInputEvent::kNoModifiers,
                      WebInputEvent::GetStaticTimeStampForTests());
  touch.touches_length = 1;
  touch.touch_start_or_first_touch_move = true;
  touch.touches[0] =
      CreateWebTouchPoint(WebTouchPoint::State::kStatePressed, 0, 0);
  EXPECT_EQ(InputHandlerProxy::DID_NOT_HANDLE_NON_BLOCKING,
            HandleInputEventWithLatencyInfo(input_handler_.get(), touch));

  EXPECT_CALL(mock_input_handler_, EventListenerTypeForTouchStartOrMoveAt(_, _))
      .WillOnce(testing::Return(
          cc::InputHandler::TouchStartOrMoveEventListenerType::kHandler));
  EXPECT_CALL(mock_client_, SetAllowedTouchAction(_))
      .WillOnce(testing::Return());

  touch.SetType(WebInputEvent::Type::kTouchMove);
  touch.touches_length = 1;
  touch.touch_start_or_first_touch_move = true;
  touch.touches[0] =
      CreateWebTouchPoint(WebTouchPoint::State::kStateMoved, 10, 10);
  EXPECT_EQ(InputHandlerProxy::DID_NOT_HANDLE_NON_BLOCKING,
            HandleInputEventWithLatencyInfo(input_handler_.get(), touch));
  VERIFY_AND_RESET_MOCKS();
}

TEST_P(InputHandlerProxyTest, UpdateBrowserControlsState) {
  VERIFY_AND_RESET_MOCKS();
  EXPECT_CALL(
      mock_input_handler_,
      UpdateBrowserControlsState(cc::BrowserControlsState::kShown,
                                 cc::BrowserControlsState::kBoth, true, _))
      .Times(1);

  input_handler_->UpdateBrowserControlsState(cc::BrowserControlsState::kShown,
                                             cc::BrowserControlsState::kBoth,
                                             true, std::nullopt);
  VERIFY_AND_RESET_MOCKS();
}

class UnifiedScrollingInputHandlerProxyTest : public testing::Test {
 public:
  using ElementId = cc::ElementId;
  using EventDisposition = InputHandlerProxy::EventDisposition;
  using EventDispositionCallback = InputHandlerProxy::EventDispositionCallback;
  using LatencyInfo = ui::LatencyInfo;
  using ScrollGranularity = ui::ScrollGranularity;
  using ScrollState = cc::ScrollState;
  using ReturnedDisposition = std::optional<EventDisposition>;

  UnifiedScrollingInputHandlerProxyTest()
      : input_handler_proxy_(mock_input_handler_, &mock_client_) {}

  std::unique_ptr<WebCoalescedInputEvent> ScrollBegin() {
    auto gsb = std::make_unique<WebGestureEvent>(
        WebInputEvent::Type::kGestureScrollBegin, WebInputEvent::kNoModifiers,
        TimeForInputEvents(), WebGestureDevice::kTouchpad);
    gsb->data.scroll_begin.scrollable_area_element_id = 0;
    gsb->data.scroll_begin.main_thread_hit_tested_reasons =
        cc::MainThreadScrollingReason::kNotScrollingOnMain;
    gsb->data.scroll_begin.delta_x_hint = 0;
    gsb->data.scroll_begin.delta_y_hint = 10;
    gsb->data.scroll_begin.pointer_count = 0;

    LatencyInfo unused;
    return std::make_unique<WebCoalescedInputEvent>(std::move(gsb), unused);
  }

  std::unique_ptr<WebCoalescedInputEvent> ScrollUpdate() {
    auto gsu = std::make_unique<WebGestureEvent>(
        WebInputEvent::Type::kGestureScrollUpdate, WebInputEvent::kNoModifiers,
        TimeForInputEvents(), WebGestureDevice::kTouchpad);
    gsu->data.scroll_update.delta_x = 0;
    gsu->data.scroll_update.delta_y = 10;

    LatencyInfo unused;
    return std::make_unique<WebCoalescedInputEvent>(std::move(gsu), unused);
  }

  std::unique_ptr<WebCoalescedInputEvent> ScrollEnd() {
    auto gse = std::make_unique<WebGestureEvent>(
        WebInputEvent::Type::kGestureScrollEnd, WebInputEvent::kNoModifiers,
        TimeForInputEvents(), WebGestureDevice::kTouchpad);

    LatencyInfo unused;
    return std::make_unique<WebCoalescedInputEvent>(std::move(gse), unused);
  }

  void DispatchEvent(std::unique_ptr<blink::WebCoalescedInputEvent> event,
                     ReturnedDisposition* out_disposition = nullptr) {
    input_handler_proxy_.HandleInputEventWithLatencyInfo(
        std::move(event), nullptr, BindEventHandledCallback(out_disposition));
  }

  void ContinueScrollBeginAfterMainThreadHitTest(
      std::unique_ptr<WebCoalescedInputEvent> event,
      cc::ElementId hit_test_result,
      ReturnedDisposition* out_disposition = nullptr) {
    input_handler_proxy_.ContinueScrollBeginAfterMainThreadHitTest(
        std::move(event), nullptr, BindEventHandledCallback(out_disposition),
        hit_test_result);
  }

  bool MainThreadHitTestInProgress() const {
    return input_handler_proxy_.scroll_begin_main_thread_hit_test_reasons_ !=
           cc::MainThreadScrollingReason::kNotScrollingOnMain;
  }

  void BeginFrame() {
    constexpr base::TimeDelta interval = base::Milliseconds(16);
    base::TimeTicks frame_time =
        TimeForInputEvents() +
        (next_begin_frame_number_ - viz::BeginFrameArgs::kStartingFrameNumber) *
            interval;
    input_handler_proxy_.DeliverInputForBeginFrame(viz::BeginFrameArgs::Create(
        BEGINFRAME_FROM_HERE, 0, next_begin_frame_number_++, frame_time,
        frame_time + interval, interval, viz::BeginFrameArgs::NORMAL));
  }

  cc::InputHandlerScrollResult DidScrollResult() const {
    cc::InputHandlerScrollResult result;
    result.did_scroll = true;
    return result;
  }

 protected:
  base::test::SingleThreadTaskEnvironment task_environment_;
  NiceMock<MockInputHandler> mock_input_handler_;
  NiceMock<MockInputHandlerProxyClient> mock_client_;

 private:
  void EventHandledCallback(
      ReturnedDisposition* out_disposition,
      EventDisposition event_disposition,
      std::unique_ptr<WebCoalescedInputEvent> input_event,
      std::unique_ptr<InputHandlerProxy::DidOverscrollParams> overscroll_params,
      const WebInputEventAttribution& attribution,
      std::unique_ptr<cc::EventMetrics> metrics) {
    if (out_disposition)
      *out_disposition = event_disposition;
  }

  EventDispositionCallback BindEventHandledCallback(
      ReturnedDisposition* out_disposition = nullptr) {
    return base::BindOnce(
        &UnifiedScrollingInputHandlerProxyTest::EventHandledCallback,
        weak_ptr_factory_.GetWeakPtr(), out_disposition);
  }

  base::TimeTicks TimeForInputEvents() const {
    return WebInputEvent::GetStaticTimeStampForTests();
  }

  InputHandlerProxy input_handler_proxy_;
  base::test::ScopedFeatureList scoped_feature_list_;
  base::SimpleTestTickClock tick_clock_;
  uint64_t next_begin_frame_number_ = viz::BeginFrameArgs::kStartingFrameNumber;
  base::WeakPtrFactory<UnifiedScrollingInputHandlerProxyTest> weak_ptr_factory_{
      this};
};

// Test that when a main thread hit test is requested, the InputHandlerProxy
// starts queueing incoming gesture event and the compositor queue is blocked
// until the hit test is satisfied.
TEST_F(UnifiedScrollingInputHandlerProxyTest, MainThreadHitTestRequired) {
  // The hit testing state shouldn't be entered until one is actually requested.
  EXPECT_FALSE(MainThreadHitTestInProgress());

  // Inject a GSB that returns RequiresMainThreadHitTest.
  {
    EXPECT_CALL(mock_input_handler_, ScrollBegin(_, _))
        .WillOnce(Return(kRequiresMainThreadHitTestState));

    ReturnedDisposition disposition;
    DispatchEvent(ScrollBegin(), &disposition);

    EXPECT_TRUE(MainThreadHitTestInProgress());
    EXPECT_EQ(InputHandlerProxy::REQUIRES_MAIN_THREAD_HIT_TEST, *disposition);

    Mock::VerifyAndClearExpectations(&mock_input_handler_);
  }

  ReturnedDisposition gsu1_disposition;
  ReturnedDisposition gsu2_disposition;

  // Now inject a GSU. This should be queued.
  {
    EXPECT_CALL(mock_input_handler_, ScrollUpdate(_, _)).Times(0);

    DispatchEvent(ScrollUpdate(), &gsu1_disposition);
    EXPECT_FALSE(gsu1_disposition);

    // Ensure the queue is blocked; a BeginFrame doesn't cause event dispatch.
    BeginFrame();
    EXPECT_FALSE(gsu1_disposition);

    Mock::VerifyAndClearExpectations(&mock_input_handler_);
  }

  // Inject a second GSU; it should be coalesced and also queued.
  {
    EXPECT_CALL(mock_input_handler_, ScrollUpdate(_, _)).Times(0);

    DispatchEvent(ScrollUpdate(), &gsu2_disposition);
    EXPECT_FALSE(gsu2_disposition);

    // Ensure the queue is blocked.
    BeginFrame();
    EXPECT_FALSE(gsu2_disposition);

    Mock::VerifyAndClearExpectations(&mock_input_handler_);
  }

  EXPECT_TRUE(MainThreadHitTestInProgress());

  // The hit test reply arrives. Ensure we call ScrollBegin and unblock the
  // queue.
  {
    EXPECT_CALL(mock_input_handler_, ScrollBegin(_, _))
        .WillOnce(Return(kImplThreadScrollState));

    // Additionally, the queue should be flushed by
    // ContinueScrollBeginAfterMainThreadHitTest so that the GSUs dispatched
    // earlier will now handled.
    EXPECT_CALL(mock_input_handler_, ScrollUpdate(_, _))
        .WillOnce(Return(DidScrollResult()));

    // Ensure we don't spurriously call ScrollEnd (because we think we're
    // already in a scroll from the first GSB).
    EXPECT_CALL(mock_input_handler_, ScrollEnd(_)).Times(0);

    ReturnedDisposition disposition;
    constexpr ElementId kHitTestResult(12345);
    ContinueScrollBeginAfterMainThreadHitTest(ScrollBegin(), kHitTestResult,
                                              &disposition);

    // The ScrollBegin should have been immediately re-injected and queue
    // flushed.
    EXPECT_FALSE(MainThreadHitTestInProgress());
    EXPECT_EQ(InputHandlerProxy::DID_HANDLE, *disposition);
    EXPECT_EQ(InputHandlerProxy::DID_HANDLE, *gsu1_disposition);
    EXPECT_EQ(InputHandlerProxy::DID_HANDLE, *gsu2_disposition);

    Mock::VerifyAndClearExpectations(&mock_input_handler_);
  }

  // Injecting a new GSU should cause queueing and dispatching as usual.
  {
    EXPECT_CALL(mock_input_handler_, ScrollUpdate(_, _))
        .WillOnce(Return(DidScrollResult()));

    ReturnedDisposition disposition;
    DispatchEvent(ScrollUpdate(), &disposition);
    EXPECT_FALSE(disposition);

    BeginFrame();
    EXPECT_EQ(InputHandlerProxy::DID_HANDLE, *disposition);

    Mock::VerifyAndClearExpectations(&mock_input_handler_);
  }

  // Finish the scroll.
  {
    EXPECT_CALL(mock_input_handler_, ScrollEnd(_)).Times(1);
    ReturnedDisposition disposition;
    DispatchEvent(ScrollEnd(), &disposition);
    EXPECT_EQ(InputHandlerProxy::DID_HANDLE, *disposition);
    Mock::VerifyAndClearExpectations(&mock_input_handler_);
  }

  EXPECT_FALSE(MainThreadHitTestInProgress());
}

// Test to ensure that a main thread hit test sets the correct flags on the
// re-injected GestureScrollBegin.
TEST_F(UnifiedScrollingInputHandlerProxyTest, MainThreadHitTestEvent) {
  // Inject a GSB that returns RequiresMainThreadHitTest.
  {
    // Ensure that by default we don't set a target. The
    // |is_main_thread_hit_tested| property should default to false.
    EXPECT_CALL(
        mock_input_handler_,
        ScrollBegin(
            AllOf(Property(&ScrollState::target_element_id, Eq(ElementId())),
                  Property(
                      &ScrollState::main_thread_hit_tested_reasons,
                      Eq(cc::MainThreadScrollingReason::kNotScrollingOnMain))),
            _))
        .WillOnce(Return(kRequiresMainThreadHitTestState));
    DispatchEvent(ScrollBegin());
    ASSERT_TRUE(MainThreadHitTestInProgress());
    Mock::VerifyAndClearExpectations(&mock_input_handler_);
  }

  // The hit test reply arrives. Ensure we call ScrollBegin with the ElementId
  // from the hit test and the main_thread
  {
    const ElementId kHitTestResult(12345);

    EXPECT_CALL(
        mock_input_handler_,
        ScrollBegin(
            AllOf(Property(&ScrollState::target_element_id, Eq(kHitTestResult)),
                  Property(&ScrollState::main_thread_hit_tested_reasons,
                           Eq(cc::MainThreadScrollingReason::
                                  kMainThreadScrollHitTestRegion))),
            _))
        .Times(1);

    ContinueScrollBeginAfterMainThreadHitTest(ScrollBegin(), kHitTestResult);
    Mock::VerifyAndClearExpectations(&mock_input_handler_);
  }
}

// Test to ensure that a main thread hit test counts the correct number of
// scrolls for metrics.
TEST_F(UnifiedScrollingInputHandlerProxyTest, MainThreadHitTestMetrics) {
  // Inject a GSB that returns RequiresMainThreadHitTest followed by a GSU and
  // a GSE.
  {
    EXPECT_CALL(mock_input_handler_, ScrollBegin(_, _))
        .WillOnce(Return(kRequiresMainThreadHitTestState))
        .WillOnce(Return(kImplThreadScrollState));
    EXPECT_CALL(mock_input_handler_, ScrollUpdate(_, _)).Times(1);
    EXPECT_CALL(mock_input_handler_, ScrollEnd(_)).Times(1);

    // The record begin/end should be called exactly once.
    EXPECT_CALL(mock_input_handler_, RecordScrollBegin(_, _)).Times(1);
    EXPECT_CALL(mock_input_handler_, RecordScrollEnd(_)).Times(1);

    DispatchEvent(ScrollBegin());
    EXPECT_TRUE(MainThreadHitTestInProgress());
    DispatchEvent(ScrollUpdate());
    DispatchEvent(ScrollEnd());

    // Hit test reply.
    constexpr ElementId kHitTestResult(12345);
    ContinueScrollBeginAfterMainThreadHitTest(ScrollBegin(), kHitTestResult);
    Mock::VerifyAndClearExpectations(&mock_input_handler_);
  }

  // Ensure we don't record either a begin or an end if the hit test fails.
  {
    EXPECT_CALL(mock_input_handler_, ScrollBegin(_, _))
        .WillOnce(Return(kRequiresMainThreadHitTestState));
    EXPECT_CALL(mock_input_handler_, ScrollUpdate(_, _)).Times(0);
    EXPECT_CALL(mock_input_handler_, ScrollEnd(_)).Times(0);

    EXPECT_CALL(mock_input_handler_, RecordScrollBegin(_, _)).Times(0);
    EXPECT_CALL(mock_input_handler_, RecordScrollEnd(_)).Times(0);

    DispatchEvent(ScrollBegin());
    EXPECT_TRUE(MainThreadHitTestInProgress());
    DispatchEvent(ScrollUpdate());
    DispatchEvent(ScrollEnd());

    // Hit test reply failed.
    constexpr ElementId kHitTestResult;
    ASSERT_FALSE(kHitTestResult);

    ContinueScrollBeginAfterMainThreadHitTest(ScrollBegin(), kHitTestResult);
    Mock::VerifyAndClearExpectations(&mock_input_handler_);
  }
}

// Test the case where a main thread hit test is in progress on the main thread
// and a GSE and new GSB arrive.
TEST_F(UnifiedScrollingInputHandlerProxyTest,
       ScrollEndAndBeginsDuringMainThreadHitTest) {
  ReturnedDisposition gsb1_disposition;
  ReturnedDisposition gsu1_disposition;
  ReturnedDisposition gse1_disposition;
  ReturnedDisposition gsb2_disposition;
  ReturnedDisposition gsu2_disposition;
  ReturnedDisposition gse2_disposition;

  // Inject a GSB that returns RequiresMainThreadHitTest followed by a GSU and
  // GSE that get queued.
  {
    EXPECT_CALL(mock_input_handler_, ScrollBegin(_, _))
        .WillOnce(Return(kRequiresMainThreadHitTestState));
    DispatchEvent(ScrollBegin(), &gsb1_disposition);
    ASSERT_TRUE(MainThreadHitTestInProgress());
    ASSERT_EQ(InputHandlerProxy::REQUIRES_MAIN_THREAD_HIT_TEST,
              *gsb1_disposition);

    DispatchEvent(ScrollUpdate(), &gsu1_disposition);
    DispatchEvent(ScrollEnd(), &gse1_disposition);

    // The queue is blocked so none of the events should be processed.
    BeginFrame();

    ASSERT_FALSE(gsu1_disposition);
    ASSERT_FALSE(gse1_disposition);
  }

  // Inject another group of GSB, GSU, GSE. They should all be queued.
  {
    DispatchEvent(ScrollBegin(), &gsb2_disposition);
    DispatchEvent(ScrollUpdate(), &gsu2_disposition);
    DispatchEvent(ScrollEnd(), &gse2_disposition);

    // The queue is blocked so none of the events should be processed.
    BeginFrame();

    EXPECT_FALSE(gsb2_disposition);
    EXPECT_FALSE(gsu2_disposition);
    EXPECT_FALSE(gse2_disposition);
  }

  ASSERT_TRUE(MainThreadHitTestInProgress());

  // The hit test reply arrives. Ensure we call ScrollBegin and unblock the
  // queue.
  {
    EXPECT_CALL(mock_input_handler_, ScrollBegin(_, _))
        .Times(2)
        .WillRepeatedly(Return(kImplThreadScrollState));
    EXPECT_CALL(mock_input_handler_, ScrollUpdate(_, _))
        .Times(2)
        .WillRepeatedly(Return(DidScrollResult()));
    EXPECT_CALL(mock_input_handler_, ScrollEnd(_)).Times(2);

    ReturnedDisposition disposition;
    constexpr ElementId kHitTestResult(12345);
    ContinueScrollBeginAfterMainThreadHitTest(ScrollBegin(), kHitTestResult,
                                              &disposition);

    // The ScrollBegin should have been immediately re-injected and queue
    // flushed.
    EXPECT_FALSE(MainThreadHitTestInProgress());
    EXPECT_EQ(InputHandlerProxy::DID_HANDLE, *disposition);
    EXPECT_EQ(InputHandlerProxy::DID_HANDLE, *gsu1_disposition);
    EXPECT_EQ(InputHandlerProxy::DID_HANDLE, *gse1_disposition);

    EXPECT_EQ(InputHandlerProxy::DID_HANDLE, *gsb2_disposition);
    EXPECT_EQ(InputHandlerProxy::DID_HANDLE, *gsu2_disposition);
    EXPECT_EQ(InputHandlerProxy::DID_HANDLE, *gse2_disposition);

    Mock::VerifyAndClearExpectations(&mock_input_handler_);
  }
}

// Test the case where a main thread hit test returns a null element_id. In
// this case we should reset the state and unblock the queue.
TEST_F(UnifiedScrollingInputHandlerProxyTest, MainThreadHitTestFailed) {
  ReturnedDisposition gsu1_disposition;

  // Inject a GSB that returns RequiresMainThreadHitTest.
  {
    EXPECT_CALL(mock_input_handler_, ScrollBegin(_, _))
        .WillOnce(Return(kRequiresMainThreadHitTestState));
    DispatchEvent(ScrollBegin());
    DispatchEvent(ScrollUpdate(), &gsu1_disposition);
    Mock::VerifyAndClearExpectations(&mock_input_handler_);
  }

  // The hit test reply arrives with an invalid ElementId. We shouldn't call
  // ScrollBegin nor ScrollUpdate. Both should be dropped without reaching the
  // input handler.
  {
    EXPECT_CALL(mock_input_handler_, ScrollBegin(_, _)).Times(0);
    EXPECT_CALL(mock_input_handler_, ScrollUpdate(_, _)).Times(0);
    EXPECT_CALL(mock_input_handler_, ScrollEnd(_)).Times(0);

    constexpr ElementId kHitTestResult;
    ASSERT_FALSE(kHitTestResult);

    ReturnedDisposition gsb_disposition;
    ContinueScrollBeginAfterMainThreadHitTest(ScrollBegin(), kHitTestResult,
                                              &gsb_disposition);

    EXPECT_EQ(InputHandlerProxy::DROP_EVENT, *gsb_disposition);
    EXPECT_EQ(InputHandlerProxy::DROP_EVENT, *gsu1_disposition);
    Mock::VerifyAndClearExpectations(&mock_input_handler_);
  }

  // Send a new GSU, ensure it's dropped without queueing since there's no
  // scroll in progress.
  {
    EXPECT_CALL(mock_input_handler_, ScrollUpdate(_, _)).Times(0);

    ReturnedDisposition disposition;
    DispatchEvent(ScrollUpdate(), &disposition);
    EXPECT_EQ(InputHandlerProxy::DROP_EVENT, *disposition);
    Mock::VerifyAndClearExpectations(&mock_input_handler_);
  }

  // Ensure there's no left-over bad state by sending a new GSB+GSU which
  // should be handled by the input handler immediately. A following GSU should
  // be queued and dispatched at BeginFrame.
  {
    EXPECT_CALL(mock_input_handler_, ScrollBegin(_, _))
        .WillOnce(Return(kImplThreadScrollState));
    EXPECT_CALL(mock_input_handler_, ScrollUpdate(_, _))
        .WillOnce(Return(DidScrollResult()))
        .WillOnce(Return(DidScrollResult()));

    // Note: The first GSU after a GSB is dispatched immediately without
    // queueing.
    ReturnedDisposition disposition;
    DispatchEvent(ScrollBegin(), &disposition);
    DispatchEvent(ScrollUpdate());

    EXPECT_EQ(InputHandlerProxy::DID_HANDLE, *disposition);
    disposition = std::nullopt;

    DispatchEvent(ScrollUpdate(), &disposition);
    EXPECT_FALSE(disposition);

    BeginFrame();
    EXPECT_EQ(InputHandlerProxy::DID_HANDLE, *disposition);
    Mock::VerifyAndClearExpectations(&mock_input_handler_);
  }
}

TEST(SynchronousInputHandlerProxyTest, StartupShutdown) {
  base::test::SingleThreadTaskEnvironment task_environment;
  testing::StrictMock<MockInputHandler> mock_input_handler;
  testing::StrictMock<MockInputHandlerProxyClient> mock_client;
  testing::StrictMock<MockSynchronousInputHandler>
      mock_synchronous_input_handler;
  InputHandlerProxy proxy(mock_input_handler, &mock_client);

  // When adding a SynchronousInputHandler, immediately request an
  // UpdateRootLayerStateForSynchronousInputHandler() call.
  EXPECT_CALL(mock_input_handler, RequestUpdateForSynchronousInputHandler())
      .Times(1);
  proxy.SetSynchronousInputHandler(&mock_synchronous_input_handler);

  testing::Mock::VerifyAndClearExpectations(&mock_input_handler);
  testing::Mock::VerifyAndClearExpectations(&mock_client);
  testing::Mock::VerifyAndClearExpectations(&mock_synchronous_input_handler);

  EXPECT_CALL(mock_input_handler, RequestUpdateForSynchronousInputHandler())
      .Times(0);
  proxy.SetSynchronousInputHandler(nullptr);

  testing::Mock::VerifyAndClearExpectations(&mock_input_handler);
  testing::Mock::VerifyAndClearExpectations(&mock_client);
  testing::Mock::VerifyAndClearExpectations(&mock_synchronous_input_handler);
}

TEST(SynchronousInputHandlerProxyTest, UpdateRootLayerState) {
  base::test::SingleThreadTaskEnvironment task_environment;
  testing::NiceMock<MockInputHandler> mock_input_handler;
  testing::StrictMock<MockInputHandlerProxyClient> mock_client;
  testing::StrictMock<MockSynchronousInputHandler>
      mock_synchronous_input_handler;
  InputHandlerProxy proxy(mock_input_handler, &mock_client);

  proxy.SetSynchronousInputHandler(&mock_synchronous_input_handler);

  // When adding a SynchronousInputHandler, immediately request an
  // UpdateRootLayerStateForSynchronousInputHandler() call.
  EXPECT_CALL(mock_synchronous_input_handler,
              UpdateRootLayerState(gfx::PointF(1, 2), gfx::PointF(3, 4),
                                   gfx::SizeF(5, 6), 7, 8, 9))
      .Times(1);
  proxy.UpdateRootLayerStateForSynchronousInputHandler(
      gfx::PointF(1, 2), gfx::PointF(3, 4), gfx::SizeF(5, 6), 7, 8, 9);

  testing::Mock::VerifyAndClearExpectations(&mock_input_handler);
  testing::Mock::VerifyAndClearExpectations(&mock_client);
  testing::Mock::VerifyAndClearExpectations(&mock_synchronous_input_handler);
}

TEST(SynchronousInputHandlerProxyTest, SetOffset) {
  base::test::SingleThreadTaskEnvironment task_environment;
  testing::NiceMock<MockInputHandler> mock_input_handler;
  testing::StrictMock<MockInputHandlerProxyClient> mock_client;
  testing::StrictMock<MockSynchronousInputHandler>
      mock_synchronous_input_handler;
  InputHandlerProxy proxy(mock_input_handler, &mock_client);

  proxy.SetSynchronousInputHandler(&mock_synchronous_input_handler);

  EXPECT_CALL(mock_input_handler,
              SetSynchronousInputHandlerRootScrollOffset(gfx::PointF(5, 6)));
  proxy.SynchronouslySetRootScrollOffset(gfx::PointF(5, 6));

  testing::Mock::VerifyAndClearExpectations(&mock_input_handler);
  testing::Mock::VerifyAndClearExpectations(&mock_client);
  testing::Mock::VerifyAndClearExpectations(&mock_synchronous_input_handler);
}

TEST_F(InputHandlerProxyEventQueueTest,
       MouseEventOnScrollbarInitiatesGestureScroll) {
  EXPECT_CALL(mock_input_handler_, SetNeedsAnimateInput()).Times(1);
  EXPECT_CALL(mock_input_handler_, FindFrameElementIdAtPoint(_))
      .Times(2)
      .WillRepeatedly(testing::Return(cc::ElementId()));

  // Test mousedown on the scrollbar. Expect to get GSB and GSU.
  cc::InputHandlerPointerResult pointer_down_result;
  pointer_down_result.type = cc::PointerResultType::kScrollbarScroll;
  pointer_down_result.scroll_delta = gfx::Vector2dF(0, 1);
  EXPECT_CALL(mock_input_handler_, HitTest(_))
      .WillOnce(testing::Return(pointer_down_result.type));
  EXPECT_CALL(mock_input_handler_, MouseDown(_, _))
      .WillOnce(testing::Return(pointer_down_result));
  HandleMouseEvent(WebInputEvent::Type::kMouseDown);
  EXPECT_EQ(2ul, event_queue().size());
  EXPECT_EQ(event_queue()[0]->event().GetType(),
            WebInputEvent::Type::kGestureScrollBegin);
  EXPECT_TRUE(static_cast<const WebGestureEvent&>(event_queue()[0]->event())
                  .data.scroll_begin.synthetic);
  EXPECT_EQ(event_queue()[1]->event().GetType(),
            WebInputEvent::Type::kGestureScrollUpdate);
  cc::InputHandlerPointerResult pointer_up_result;
  pointer_up_result.type = cc::PointerResultType::kScrollbarScroll;
  EXPECT_CALL(mock_input_handler_, MouseUp(_))
      .WillOnce(testing::Return(pointer_up_result));
  // Test mouseup on the scrollbar. Expect to get GSE.
  HandleMouseEvent(WebInputEvent::Type::kMouseUp);
  EXPECT_EQ(3ul, event_queue().size());
  EXPECT_EQ(event_queue()[2]->event().GetType(),
            WebInputEvent::Type::kGestureScrollEnd);
}

TEST_F(InputHandlerProxyEventQueueTest, VSyncAlignedGestureScroll) {
  // Handle scroll on compositor.
  cc::InputHandlerScrollResult scroll_result_did_scroll_;
  scroll_result_did_scroll_.did_scroll = true;

  EXPECT_CALL(mock_input_handler_, ScrollBegin(_, _))
      .WillOnce(testing::Return(kImplThreadScrollState));
  EXPECT_CALL(
      mock_input_handler_,
      RecordScrollBegin(_, cc::ScrollBeginThreadState::kScrollingOnCompositor))
      .Times(1);
  EXPECT_CALL(mock_input_handler_, SetNeedsAnimateInput()).Times(1);
  EXPECT_CALL(mock_input_handler_, FindFrameElementIdAtPoint(_))
      .Times(1)
      .WillOnce(testing::Return(cc::ElementId()));

  HandleGestureEvent(WebInputEvent::Type::kGestureScrollBegin);

  // GestureScrollBegin will be processed immediately.
  EXPECT_EQ(0ul, event_queue().size());
  EXPECT_EQ(1ul, event_disposition_recorder_.size());
  EXPECT_EQ(InputHandlerProxy::DID_HANDLE, event_disposition_recorder_[0]);

  HandleGestureEvent(WebInputEvent::Type::kGestureScrollUpdate, -20);

  // GestureScrollUpdate will be queued.
  EXPECT_EQ(1ul, event_queue().size());
  EXPECT_EQ(-20,
            static_cast<const WebGestureEvent&>(event_queue().front()->event())
                .data.scroll_update.delta_y);
  EXPECT_EQ(1ul, event_queue().front()->coalesced_count());
  EXPECT_EQ(1ul, event_disposition_recorder_.size());

  HandleGestureEvent(WebInputEvent::Type::kGestureScrollUpdate, -40);

  // GestureScrollUpdate will be coalesced.
  EXPECT_EQ(1ul, event_queue().size());
  EXPECT_EQ(-60,
            static_cast<const WebGestureEvent&>(event_queue().front()->event())
                .data.scroll_update.delta_y);
  EXPECT_EQ(2ul, event_queue().front()->coalesced_count());
  EXPECT_EQ(1ul, event_disposition_recorder_.size());

  EXPECT_CALL(mock_input_handler_, RecordScrollEnd(_)).Times(0);
  HandleGestureEvent(WebInputEvent::Type::kGestureScrollEnd);

  // GestureScrollEnd will be queued.
  EXPECT_EQ(2ul, event_queue().size());
  EXPECT_EQ(1ul, event_disposition_recorder_.size());
  testing::Mock::VerifyAndClearExpectations(&mock_input_handler_);

  EXPECT_CALL(
      mock_input_handler_,
      ScrollUpdate(testing::Property(&cc::ScrollState::delta_y, testing::Gt(0)),
                   _))
      .WillOnce(testing::Return(scroll_result_did_scroll_));
  EXPECT_CALL(mock_input_handler_, ScrollEnd(true));
  EXPECT_CALL(mock_input_handler_, FindFrameElementIdAtPoint(_))
      .Times(2)
      .WillRepeatedly(testing::Return(cc::ElementId()));

  // Dispatch all queued events.
  EXPECT_CALL(mock_input_handler_, RecordScrollEnd(_)).Times(1);
  DeliverInputForBeginFrame();
  EXPECT_EQ(0ul, event_queue().size());
  // Should run callbacks for every original events.
  EXPECT_EQ(4ul, event_disposition_recorder_.size());
  EXPECT_EQ(InputHandlerProxy::DID_HANDLE, event_disposition_recorder_[1]);
  EXPECT_EQ(InputHandlerProxy::DID_HANDLE, event_disposition_recorder_[2]);
  EXPECT_EQ(InputHandlerProxy::DID_HANDLE, event_disposition_recorder_[3]);
  testing::Mock::VerifyAndClearExpectations(&mock_input_handler_);
}

#if defined(ADDRESS_SANITIZER) || defined(THREAD_SANITIZER) || \
    defined(MEMORY_SANITIZER) || defined(UNDEFINED_SANITIZER)
// Flaky under sanitizers and in other "slow" bot configs:
// https://crbug.com/1029250
#define MAYBE_VSyncAlignedGestureScrollPinchScroll \
  DISABLED_VSyncAlignedGestureScrollPinchScroll
#else
#define MAYBE_VSyncAlignedGestureScrollPinchScroll \
  VSyncAlignedGestureScrollPinchScroll
#endif

TEST_F(InputHandlerProxyEventQueueTest,
       MAYBE_VSyncAlignedGestureScrollPinchScroll) {
  // Handle scroll on compositor.
  cc::InputHandlerScrollResult scroll_result_did_scroll_;
  scroll_result_did_scroll_.did_scroll = true;

  // Start scroll in the first frame.
  EXPECT_CALL(mock_input_handler_, ScrollBegin(_, _))
      .WillOnce(testing::Return(kImplThreadScrollState));
  EXPECT_CALL(
      mock_input_handler_,
      RecordScrollBegin(_, cc::ScrollBeginThreadState::kScrollingOnCompositor))
      .Times(1);
  EXPECT_CALL(
      mock_input_handler_,
      ScrollUpdate(testing::Property(&cc::ScrollState::delta_y, testing::Gt(0)),
                   _))
      .WillOnce(testing::Return(scroll_result_did_scroll_));
  EXPECT_CALL(mock_input_handler_, SetNeedsAnimateInput()).Times(1);
  EXPECT_CALL(mock_input_handler_, FindFrameElementIdAtPoint(_))
      .Times(2)
      .WillRepeatedly(testing::Return(cc::ElementId()));

  HandleGestureEvent(WebInputEvent::Type::kGestureScrollBegin);
  HandleGestureEvent(WebInputEvent::Type::kGestureScrollUpdate, -20);

  EXPECT_EQ(1ul, event_queue().size());
  EXPECT_EQ(1ul, event_disposition_recorder_.size());

  DeliverInputForBeginFrame();

  EXPECT_EQ(0ul, event_queue().size());
  EXPECT_EQ(2ul, event_disposition_recorder_.size());
  testing::Mock::VerifyAndClearExpectations(&mock_input_handler_);

  // Continue scroll in the second frame, pinch, then start another scroll.
  EXPECT_CALL(mock_input_handler_, ScrollBegin(_, _))
      .WillOnce(testing::Return(kImplThreadScrollState));
  EXPECT_CALL(
      mock_input_handler_,
      RecordScrollBegin(_, cc::ScrollBeginThreadState::kScrollingOnCompositor))
      .Times(1);
  EXPECT_CALL(
      mock_input_handler_,
      ScrollUpdate(testing::Property(&cc::ScrollState::delta_y, testing::Gt(0)),
                   _))
      .WillRepeatedly(testing::Return(scroll_result_did_scroll_));
  EXPECT_CALL(mock_input_handler_, ScrollEnd(true)).Times(2);
  EXPECT_CALL(mock_input_handler_, SetNeedsAnimateInput()).Times(1);
  EXPECT_CALL(mock_input_handler_, FindFrameElementIdAtPoint(_))
      .Times(8)
      .WillRepeatedly(testing::Return(cc::ElementId()));
  EXPECT_CALL(mock_input_handler_, PinchGestureBegin(_, _));
  // Two |GesturePinchUpdate| will be coalesced.
  EXPECT_CALL(mock_input_handler_,
              PinchGestureUpdate(0.7f, gfx::Point(13, 17)));
  EXPECT_CALL(mock_input_handler_, PinchGestureEnd(gfx::Point()));
  EXPECT_CALL(mock_input_handler_, RecordScrollEnd(_)).Times(2);

  HandleGestureEvent(WebInputEvent::Type::kGestureScrollUpdate, -30);
  HandleGestureEvent(WebInputEvent::Type::kGestureScrollEnd);
  HandleGestureEvent(WebInputEvent::Type::kGesturePinchBegin);
  HandleGestureEvent(WebInputEvent::Type::kGesturePinchUpdate, 1.4f, 13, 17);
  HandleGestureEvent(WebInputEvent::Type::kGesturePinchUpdate, 0.5f, 13, 17);
  HandleGestureEvent(WebInputEvent::Type::kGesturePinchEnd);
  HandleGestureEvent(WebInputEvent::Type::kGestureScrollBegin);
  HandleGestureEvent(WebInputEvent::Type::kGestureScrollUpdate, -70);
  HandleGestureEvent(WebInputEvent::Type::kGestureScrollUpdate, -5);
  HandleGestureEvent(WebInputEvent::Type::kGestureScrollEnd);

  EXPECT_EQ(8ul, event_queue().size());
  EXPECT_EQ(2ul, event_disposition_recorder_.size());

  DeliverInputForBeginFrame();

  EXPECT_EQ(0ul, event_queue().size());
  EXPECT_EQ(12ul, event_disposition_recorder_.size());
  testing::Mock::VerifyAndClearExpectations(&mock_input_handler_);
}

TEST_F(InputHandlerProxyEventQueueTest, VSyncAlignedQueueingTime) {
  base::SimpleTestTickClock tick_clock;
  tick_clock.SetNowTicks(base::TimeTicks::Now());
  SetInputHandlerProxyTickClockForTesting(&tick_clock);

  // Handle scroll on compositor.
  cc::InputHandlerScrollResult scroll_result_did_scroll_;
  scroll_result_did_scroll_.did_scroll = true;

  EXPECT_CALL(mock_input_handler_, ScrollBegin(_, _))
      .WillOnce(testing::Return(kImplThreadScrollState));
  EXPECT_CALL(
      mock_input_handler_,
      RecordScrollBegin(_, cc::ScrollBeginThreadState::kScrollingOnCompositor))
      .Times(1);
  EXPECT_CALL(mock_input_handler_, SetNeedsAnimateInput()).Times(1);
  EXPECT_CALL(mock_input_handler_, FindFrameElementIdAtPoint(_))
      .Times(3)
      .WillRepeatedly(testing::Return(cc::ElementId()));
  EXPECT_CALL(
      mock_input_handler_,
      ScrollUpdate(testing::Property(&cc::ScrollState::delta_y, testing::Gt(0)),
                   _))
      .WillOnce(testing::Return(scroll_result_did_scroll_));
  EXPECT_CALL(mock_input_handler_, ScrollEnd(true));
  EXPECT_CALL(mock_input_handler_, RecordScrollEnd(_)).Times(1);

  HandleGestureEvent(WebInputEvent::Type::kGestureScrollBegin);
  tick_clock.Advance(base::Microseconds(10));
  HandleGestureEvent(WebInputEvent::Type::kGestureScrollUpdate, -20);
  tick_clock.Advance(base::Microseconds(40));
  HandleGestureEvent(WebInputEvent::Type::kGestureScrollUpdate, -40);
  tick_clock.Advance(base::Microseconds(20));
  HandleGestureEvent(WebInputEvent::Type::kGestureScrollUpdate, -10);
  tick_clock.Advance(base::Microseconds(10));
  HandleGestureEvent(WebInputEvent::Type::kGestureScrollEnd);

  // Dispatch all queued events.
  tick_clock.Advance(base::Microseconds(70));
  DeliverInputForBeginFrame();
  EXPECT_EQ(0ul, event_queue().size());
  EXPECT_EQ(5ul, event_disposition_recorder_.size());
  testing::Mock::VerifyAndClearExpectations(&mock_input_handler_);
}

TEST_F(InputHandlerProxyEventQueueTest, VSyncAlignedCoalesceScrollAndPinch) {
  // Start scroll in the first frame.
  EXPECT_CALL(mock_input_handler_, ScrollBegin(_, _))
      .WillOnce(testing::Return(kImplThreadScrollState));
  EXPECT_CALL(
      mock_input_handler_,
      RecordScrollBegin(_, cc::ScrollBeginThreadState::kScrollingOnCompositor))
      .Times(1);
  EXPECT_CALL(mock_input_handler_, SetNeedsAnimateInput()).Times(1);
  EXPECT_CALL(mock_input_handler_, FindFrameElementIdAtPoint(_))
      .Times(1)
      .WillOnce(testing::Return(cc::ElementId()));

  // GSUs and GPUs in one sequence should be coalesced into 1 GSU and 1 GPU.
  HandleGestureEvent(WebInputEvent::Type::kGestureScrollBegin);
  HandleGestureEvent(WebInputEvent::Type::kGesturePinchBegin);
  HandleGestureEvent(WebInputEvent::Type::kGestureScrollUpdate, -20);
  HandleGestureEvent(WebInputEvent::Type::kGestureScrollUpdate, -7);
  HandleGestureEvent(WebInputEvent::Type::kGesturePinchUpdate, 2.0f, 13, 10);
  HandleGestureEvent(WebInputEvent::Type::kGestureScrollUpdate, -10);
  HandleGestureEvent(WebInputEvent::Type::kGestureScrollUpdate, -6);
  HandleGestureEvent(WebInputEvent::Type::kGesturePinchEnd);
  HandleGestureEvent(WebInputEvent::Type::kGestureScrollEnd);
  HandleGestureEvent(WebInputEvent::Type::kGestureScrollBegin);
  HandleGestureEvent(WebInputEvent::Type::kGesturePinchBegin);
  HandleGestureEvent(WebInputEvent::Type::kGesturePinchUpdate, 0.2f, 2, 20);
  HandleGestureEvent(WebInputEvent::Type::kGesturePinchUpdate, 10.0f, 1, 10);
  HandleGestureEvent(WebInputEvent::Type::kGestureScrollUpdate, -30);
  HandleGestureEvent(WebInputEvent::Type::kGesturePinchUpdate, 0.25f, 3, 30);
  HandleGestureEvent(WebInputEvent::Type::kGestureScrollUpdate, -10);
  HandleGestureEvent(WebInputEvent::Type::kGesturePinchEnd);
  HandleGestureEvent(WebInputEvent::Type::kGestureScrollEnd);

  // Only the first GSB was dispatched.
  EXPECT_EQ(11ul, event_queue().size());
  EXPECT_EQ(1ul, event_disposition_recorder_.size());

  EXPECT_EQ(WebInputEvent::Type::kGesturePinchBegin,
            event_queue()[0]->event().GetType());
  EXPECT_EQ(WebInputEvent::Type::kGestureScrollUpdate,
            event_queue()[1]->event().GetType());
  EXPECT_EQ(-35, static_cast<const WebGestureEvent&>(event_queue()[1]->event())
                     .data.scroll_update.delta_y);
  EXPECT_EQ(WebInputEvent::Type::kGesturePinchUpdate,
            event_queue()[2]->event().GetType());
  EXPECT_EQ(2.0f, static_cast<const WebGestureEvent&>(event_queue()[2]->event())
                      .data.pinch_update.scale);
  EXPECT_EQ(WebInputEvent::Type::kGesturePinchEnd,
            event_queue()[3]->event().GetType());
  EXPECT_EQ(WebInputEvent::Type::kGestureScrollEnd,
            event_queue()[4]->event().GetType());
  EXPECT_EQ(WebInputEvent::Type::kGestureScrollBegin,
            event_queue()[5]->event().GetType());
  EXPECT_EQ(WebInputEvent::Type::kGesturePinchBegin,
            event_queue()[6]->event().GetType());
  EXPECT_EQ(WebInputEvent::Type::kGestureScrollUpdate,
            event_queue()[7]->event().GetType());
  EXPECT_EQ(-85, static_cast<const WebGestureEvent&>(event_queue()[7]->event())
                     .data.scroll_update.delta_y);
  EXPECT_EQ(WebInputEvent::Type::kGesturePinchUpdate,
            event_queue()[8]->event().GetType());
  EXPECT_EQ(0.5f, static_cast<const WebGestureEvent&>(event_queue()[8]->event())
                      .data.pinch_update.scale);
  EXPECT_EQ(WebInputEvent::Type::kGesturePinchEnd,
            event_queue()[9]->event().GetType());
  EXPECT_EQ(WebInputEvent::Type::kGestureScrollEnd,
            event_queue()[10]->event().GetType());
  testing::Mock::VerifyAndClearExpectations(&mock_input_handler_);
}

TEST_F(InputHandlerProxyEventQueueTest, VSyncAlignedCoalesceTouchpadPinch) {
  EXPECT_CALL(mock_input_handler_, PinchGestureBegin(_, _));
  EXPECT_CALL(mock_input_handler_, SetNeedsAnimateInput());
  EXPECT_CALL(mock_input_handler_, FindFrameElementIdAtPoint(_))
      .Times(1)
      .WillOnce(testing::Return(cc::ElementId()));

  HandleGestureEventWithSourceDevice(WebInputEvent::Type::kGesturePinchBegin,
                                     WebGestureDevice::kTouchpad);
  HandleGestureEventWithSourceDevice(WebInputEvent::Type::kGesturePinchUpdate,
                                     WebGestureDevice::kTouchpad, 1.1f, 10, 20);
  // The second update should coalesce with the first.
  HandleGestureEventWithSourceDevice(WebInputEvent::Type::kGesturePinchUpdate,
                                     WebGestureDevice::kTouchpad, 1.1f, 10, 20);
  // The third update has a different anchor so it should not be coalesced.
  HandleGestureEventWithSourceDevice(WebInputEvent::Type::kGesturePinchUpdate,
                                     WebGestureDevice::kTouchpad, 1.1f, 11, 21);
  HandleGestureEventWithSourceDevice(WebInputEvent::Type::kGesturePinchEnd,
                                     WebGestureDevice::kTouchpad);

  // Only the PinchBegin was dispatched.
  EXPECT_EQ(3ul, event_queue().size());
  EXPECT_EQ(1ul, event_disposition_recorder_.size());

  ASSERT_EQ(WebInputEvent::Type::kGesturePinchUpdate,
            event_queue()[0]->event().GetType());
  EXPECT_FLOAT_EQ(1.21f,
                  static_cast<const WebGestureEvent&>(event_queue()[0]->event())
                      .data.pinch_update.scale);
  EXPECT_EQ(WebInputEvent::Type::kGesturePinchUpdate,
            event_queue()[1]->event().GetType());
  EXPECT_EQ(WebInputEvent::Type::kGesturePinchEnd,
            event_queue()[2]->event().GetType());
}

TEST_F(InputHandlerProxyEventQueueTest, OriginalEventsTracing) {
  // Handle scroll on compositor.
  cc::InputHandlerScrollResult scroll_result_did_scroll_;
  scroll_result_did_scroll_.did_scroll = true;

  EXPECT_CALL(mock_input_handler_, ScrollBegin(_, _))
      .WillRepeatedly(testing::Return(kImplThreadScrollState));
  EXPECT_CALL(
      mock_input_handler_,
      RecordScrollBegin(_, cc::ScrollBeginThreadState::kScrollingOnCompositor))
      .Times(2);
  EXPECT_CALL(mock_input_handler_, SetNeedsAnimateInput())
      .Times(::testing::AtLeast(1));
  EXPECT_CALL(mock_input_handler_, FindFrameElementIdAtPoint(_))
      .Times(9)
      .WillRepeatedly(testing::Return(cc::ElementId()));
  EXPECT_CALL(
      mock_input_handler_,
      ScrollUpdate(testing::Property(&cc::ScrollState::delta_y, testing::Gt(0)),
                   _))
      .WillRepeatedly(testing::Return(scroll_result_did_scroll_));
  EXPECT_CALL(mock_input_handler_, ScrollEnd(true))
      .Times(::testing::AtLeast(1));
  EXPECT_CALL(mock_input_handler_, RecordScrollEnd(_)).Times(2);

  EXPECT_CALL(mock_input_handler_, PinchGestureBegin(_, _));
  EXPECT_CALL(mock_input_handler_, PinchGestureUpdate(_, _));
  EXPECT_CALL(mock_input_handler_, PinchGestureEnd(_));

  trace_analyzer::Start("input");
  // Simulate scroll.
  HandleGestureEvent(WebInputEvent::Type::kGestureScrollBegin);
  HandleGestureEvent(WebInputEvent::Type::kGestureScrollUpdate, -20);
  HandleGestureEvent(WebInputEvent::Type::kGestureScrollUpdate, -40);
  HandleGestureEvent(WebInputEvent::Type::kGestureScrollUpdate, -10);
  HandleGestureEvent(WebInputEvent::Type::kGestureScrollEnd);

  // Simulate scroll and pinch.
  HandleGestureEvent(WebInputEvent::Type::kGestureScrollBegin);
  HandleGestureEvent(WebInputEvent::Type::kGesturePinchBegin);
  HandleGestureEvent(WebInputEvent::Type::kGesturePinchUpdate, 10.0f, 1, 10);
  HandleGestureEvent(WebInputEvent::Type::kGestureScrollUpdate, -10);
  HandleGestureEvent(WebInputEvent::Type::kGesturePinchUpdate, 2.0f, 1, 10);
  HandleGestureEvent(WebInputEvent::Type::kGestureScrollUpdate, -30);
  HandleGestureEvent(WebInputEvent::Type::kGesturePinchEnd);
  HandleGestureEvent(WebInputEvent::Type::kGestureScrollEnd);

  // Dispatch all events.
  DeliverInputForBeginFrame();

  // Retrieve tracing data.
  auto analyzer = trace_analyzer::Stop();
  trace_analyzer::TraceEventVector begin_events;
  trace_analyzer::Query begin_query = trace_analyzer::Query::EventPhaseIs(
      TRACE_EVENT_PHASE_NESTABLE_ASYNC_BEGIN);
  analyzer->FindEvents(begin_query, &begin_events);

  trace_analyzer::TraceEventVector end_events;
  trace_analyzer::Query end_query =
      trace_analyzer::Query::EventPhaseIs(TRACE_EVENT_PHASE_NESTABLE_ASYNC_END);
  analyzer->FindEvents(end_query, &end_events);

  EXPECT_EQ(7ul, begin_events.size());
  EXPECT_EQ(7ul, end_events.size());

  // Traces collected through Perfetto tracing backend differ in 2 aspects:
  // 1. Arguments from the corresponding begin and end events are merged and
  //    stored in the begin event.
  // 2. Enum values are converted to strings for better readability.
  // So test expectations differ a bit in the SDK build and non-SDK build.
  EXPECT_EQ("kGestureScrollUpdate",
            begin_events[0]->GetKnownArgAsString("type"));
  EXPECT_EQ(3, begin_events[0]->GetKnownArgAsInt("coalesced_count"));

  EXPECT_EQ("kGestureScrollEnd", begin_events[1]->GetKnownArgAsString("type"));
  EXPECT_EQ("{kGestureScrollBegin, kGestureTypeFirst}",
            begin_events[2]->GetKnownArgAsString("type"));
  EXPECT_EQ("{kGesturePinchBegin, kGesturePinchTypeFirst}",
            begin_events[3]->GetKnownArgAsString("type"));
  // Original scroll and pinch updates will be stored in the coalesced
  // PinchUpdate of the <ScrollUpdate, PinchUpdate> pair.
  // The ScrollUpdate of the pair doesn't carry original events and won't be
  // traced.
  EXPECT_EQ("{kGesturePinchUpdate, kGesturePinchTypeLast}",
            begin_events[4]->GetKnownArgAsString("type"));
  EXPECT_EQ(4, begin_events[4]->GetKnownArgAsInt("coalesced_count"));
  EXPECT_EQ("kGesturePinchEnd", begin_events[5]->GetKnownArgAsString("type"));
  EXPECT_EQ("kGestureScrollEnd", begin_events[6]->GetKnownArgAsString("type"));

  testing::Mock::VerifyAndClearExpectations(&mock_input_handler_);
}

TEST_F(InputHandlerProxyEventQueueTest, TouchpadGestureScrollEndFlushQueue) {
  // Handle scroll on compositor.
  cc::InputHandlerScrollResult scroll_result_did_scroll_;
  scroll_result_did_scroll_.did_scroll = true;

  EXPECT_CALL(mock_input_handler_, ScrollBegin(_, _))
      .WillRepeatedly(testing::Return(kImplThreadScrollState));
  EXPECT_CALL(
      mock_input_handler_,
      RecordScrollBegin(_, cc::ScrollBeginThreadState::kScrollingOnCompositor))
      .Times(2);
  EXPECT_CALL(
      mock_input_handler_,
      ScrollUpdate(testing::Property(&cc::ScrollState::delta_y, testing::Gt(0)),
                   _))
      .WillRepeatedly(testing::Return(scroll_result_did_scroll_));
  EXPECT_CALL(mock_input_handler_, ScrollEnd(true))
      .Times(::testing::AtLeast(1));
  EXPECT_CALL(mock_input_handler_, FindFrameElementIdAtPoint(_))
      .Times(2)
      .WillRepeatedly(testing::Return(cc::ElementId()));

  // Simulate scroll.
  HandleGestureEventWithSourceDevice(WebInputEvent::Type::kGestureScrollBegin,
                                     WebGestureDevice::kTouchpad);
  HandleGestureEventWithSourceDevice(WebInputEvent::Type::kGestureScrollUpdate,
                                     WebGestureDevice::kTouchpad, -20);

  // Both GSB and the first GSU will be dispatched immediately since the first
  // GSU has blocking wheel event source.
  EXPECT_EQ(0ul, event_queue().size());
  EXPECT_EQ(2ul, event_disposition_recorder_.size());

  // The rest of the GSU events will get queued since they have non-blocking
  // wheel event source.
  EXPECT_CALL(mock_input_handler_, SetNeedsAnimateInput())
      .Times(::testing::AtLeast(1));
  EXPECT_CALL(mock_input_handler_, FindFrameElementIdAtPoint(_))
      .Times(4)
      .WillRepeatedly(testing::Return(cc::ElementId()));
  HandleGestureEventWithSourceDevice(WebInputEvent::Type::kGestureScrollUpdate,
                                     WebGestureDevice::kTouchpad, -20);
  EXPECT_EQ(1ul, event_queue().size());
  EXPECT_EQ(2ul, event_disposition_recorder_.size());

  // Touchpad GSE will flush the queue.
  EXPECT_CALL(mock_input_handler_, RecordScrollEnd(_)).Times(1);
  HandleGestureEventWithSourceDevice(WebInputEvent::Type::kGestureScrollEnd,
                                     WebGestureDevice::kTouchpad);

  EXPECT_EQ(0ul, event_queue().size());
  // GSB, GSU(with blocking wheel source), GSU(with non-blocking wheel
  // source), and GSE are the sent events.
  EXPECT_EQ(4ul, event_disposition_recorder_.size());

  EXPECT_FALSE(
      input_handler_proxy_.gesture_scroll_on_impl_thread_for_testing());

  // Starting a new scroll sequence should have the same behavior (namely that
  // the first scroll update is not queued but immediately dispatched).
  HandleGestureEventWithSourceDevice(WebInputEvent::Type::kGestureScrollBegin,
                                     WebGestureDevice::kTouchpad);
  HandleGestureEventWithSourceDevice(WebInputEvent::Type::kGestureScrollUpdate,
                                     WebGestureDevice::kTouchpad, -20);

  // Both GSB and the first GSU must be dispatched immediately since the first
  // GSU has blocking wheel event source.
  EXPECT_EQ(0ul, event_queue().size());
  EXPECT_EQ(6ul, event_disposition_recorder_.size());
}

TEST_F(InputHandlerProxyEventQueueTest, CoalescedLatencyInfo) {
  // Handle scroll on compositor.
  cc::InputHandlerScrollResult scroll_result_did_scroll_;
  scroll_result_did_scroll_.did_scroll = true;

  EXPECT_CALL(mock_input_handler_, ScrollBegin(_, _))
      .WillOnce(testing::Return(kImplThreadScrollState));
  EXPECT_CALL(
      mock_input_handler_,
      RecordScrollBegin(_, cc::ScrollBeginThreadState::kScrollingOnCompositor))
      .Times(1);
  EXPECT_CALL(mock_input_handler_, SetNeedsAnimateInput()).Times(1);
  EXPECT_CALL(mock_input_handler_, FindFrameElementIdAtPoint(_))
      .Times(3)
      .WillRepeatedly(testing::Return(cc::ElementId()));
  EXPECT_CALL(
      mock_input_handler_,
      ScrollUpdate(testing::Property(&cc::ScrollState::delta_y, testing::Gt(0)),
                   _))
      .WillOnce(testing::Return(scroll_result_did_scroll_));
  EXPECT_CALL(mock_input_handler_, RecordScrollEnd(_)).Times(1);
  EXPECT_CALL(mock_input_handler_, ScrollEnd(true));

  HandleGestureEvent(WebInputEvent::Type::kGestureScrollBegin);
  HandleGestureEvent(WebInputEvent::Type::kGestureScrollUpdate, -20);
  HandleGestureEvent(WebInputEvent::Type::kGestureScrollUpdate, -40);
  HandleGestureEvent(WebInputEvent::Type::kGestureScrollUpdate, -30);
  HandleGestureEvent(WebInputEvent::Type::kGestureScrollEnd);
  DeliverInputForBeginFrame();

  EXPECT_EQ(0ul, event_queue().size());
  // Should run callbacks for every original events.
  EXPECT_EQ(5ul, event_disposition_recorder_.size());
  EXPECT_EQ(5ul, latency_info_recorder_.size());
  EXPECT_EQ(false, latency_info_recorder_[1].coalesced());
  // Coalesced events should have latency set to coalesced.
  EXPECT_EQ(true, latency_info_recorder_[2].coalesced());
  EXPECT_EQ(true, latency_info_recorder_[3].coalesced());
  testing::Mock::VerifyAndClearExpectations(&mock_input_handler_);
}

TEST_F(InputHandlerProxyEventQueueTest, ScrollPredictorTest) {
  base::SimpleTestTickClock tick_clock;
  tick_clock.SetNowTicks(base::TimeTicks());
  SetInputHandlerProxyTickClockForTesting(&tick_clock);

  cc::InputHandlerScrollResult scroll_result_did_scroll_;
  scroll_result_did_scroll_.did_scroll = true;
  EXPECT_CALL(mock_input_handler_, ScrollBegin(_, _))
      .WillOnce(testing::Return(kImplThreadScrollState));
  EXPECT_CALL(
      mock_input_handler_,
      RecordScrollBegin(_, cc::ScrollBeginThreadState::kScrollingOnCompositor))
      .Times(1);
  EXPECT_CALL(mock_input_handler_, SetNeedsAnimateInput()).Times(2);
  EXPECT_CALL(mock_input_handler_, FindFrameElementIdAtPoint(_))
      .Times(2)
      .WillRepeatedly(testing::Return(cc::ElementId()));
  EXPECT_CALL(
      mock_input_handler_,
      ScrollUpdate(testing::Property(&cc::ScrollState::delta_y, testing::Gt(0)),
                   _))
      .WillOnce(testing::Return(scroll_result_did_scroll_));

  // No prediction when start with a GSB
  tick_clock.Advance(base::Milliseconds(8));
  HandleGestureEvent(WebInputEvent::Type::kGestureScrollBegin);
  DeliverInputForBeginFrame();
  EXPECT_FALSE(GestureScrollEventPredictionAvailable());

  // Test predictor returns last GSU delta.
  tick_clock.Advance(base::Milliseconds(8));
  HandleGestureEvent(WebInputEvent::Type::kGestureScrollUpdate, -20);
  tick_clock.Advance(base::Milliseconds(8));
  HandleGestureEvent(WebInputEvent::Type::kGestureScrollUpdate, -15);
  DeliverInputForBeginFrame();
  auto result = GestureScrollEventPredictionAvailable();
  EXPECT_TRUE(result);
  EXPECT_NE(0, result->pos.y());
  HandleGestureEvent(WebInputEvent::Type::kGestureScrollEnd);

  testing::Mock::VerifyAndClearExpectations(&mock_input_handler_);

  // Predictor has been reset after a new GSB.
  EXPECT_CALL(mock_input_handler_, SetNeedsAnimateInput()).Times(1);
  EXPECT_CALL(mock_input_handler_, FindFrameElementIdAtPoint(_))
      .Times(2)
      .WillRepeatedly(testing::Return(cc::ElementId()));
  EXPECT_CALL(mock_input_handler_, ScrollBegin(_, _))
      .WillOnce(testing::Return(kImplThreadScrollState));
  EXPECT_CALL(mock_input_handler_, ScrollEnd(_)).Times(1);
  EXPECT_CALL(mock_input_handler_, RecordScrollEnd(_)).Times(1);
  EXPECT_CALL(
      mock_input_handler_,
      RecordScrollBegin(_, cc::ScrollBeginThreadState::kScrollingOnCompositor))
      .Times(1);
  tick_clock.Advance(base::Milliseconds(8));
  HandleGestureEvent(WebInputEvent::Type::kGestureScrollBegin);
  DeliverInputForBeginFrame();
  EXPECT_FALSE(GestureScrollEventPredictionAvailable());
  HandleGestureEvent(WebInputEvent::Type::kGestureScrollEnd);

  testing::Mock::VerifyAndClearExpectations(&mock_input_handler_);
}

// Test deliver input w/o prediction enabled.
TEST_F(InputHandlerProxyEventQueueTest, DeliverInputWithHighLatencyMode) {
  SetScrollPredictionEnabled(false);

  cc::InputHandlerScrollResult scroll_result_did_scroll_;
  scroll_result_did_scroll_.did_scroll = true;
  EXPECT_CALL(mock_input_handler_, ScrollBegin(_, _))
      .WillOnce(testing::Return(kImplThreadScrollState));
  EXPECT_CALL(
      mock_input_handler_,
      RecordScrollBegin(_, cc::ScrollBeginThreadState::kScrollingOnCompositor))
      .Times(1);
  EXPECT_CALL(mock_input_handler_, SetNeedsAnimateInput()).Times(2);
  EXPECT_CALL(mock_input_handler_, FindFrameElementIdAtPoint(_))
      .Times(3)
      .WillRepeatedly(testing::Return(cc::ElementId()));
  EXPECT_CALL(
      mock_input_handler_,
      ScrollUpdate(testing::Property(&cc::ScrollState::delta_y, testing::Gt(0)),
                   _))
      .WillRepeatedly(testing::Return(scroll_result_did_scroll_));

  HandleGestureEvent(WebInputEvent::Type::kGestureScrollBegin);
  HandleGestureEvent(WebInputEvent::Type::kGestureScrollUpdate, -20);
  HandleGestureEvent(WebInputEvent::Type::kGestureScrollUpdate, -10);
  DeliverInputForBeginFrame();
  // 3 queued event be delivered.
  EXPECT_EQ(3ul, event_disposition_recorder_.size());
  EXPECT_EQ(0ul, event_queue().size());
  EXPECT_EQ(InputHandlerProxy::DID_HANDLE, event_disposition_recorder_.back());

  HandleGestureEvent(WebInputEvent::Type::kGestureScrollUpdate, -20);
  HandleGestureEvent(WebInputEvent::Type::kGestureScrollUpdate, -10);
  DeliverInputForHighLatencyMode();
  // 2 queued event be delivered.
  EXPECT_EQ(5ul, event_disposition_recorder_.size());
  EXPECT_EQ(0ul, event_queue().size());
  EXPECT_EQ(InputHandlerProxy::DID_HANDLE, event_disposition_recorder_.back());

  testing::Mock::VerifyAndClearExpectations(&mock_input_handler_);
}

TEST_F(InputHandlerProxyEventQueueTest, KeyEventAttribution) {
  WebKeyboardEvent key(WebInputEvent::Type::kKeyDown,
                       WebInputEvent::kNoModifiers,
                       WebInputEvent::GetStaticTimeStampForTests());

  EXPECT_CALL(mock_input_handler_, FindFrameElementIdAtPoint(_)).Times(0);

  WebInputEventAttribution attribution =
      input_handler_proxy_.PerformEventAttribution(key);
  EXPECT_EQ(attribution.type(), WebInputEventAttribution::kFocusedFrame);
  EXPECT_EQ(attribution.target_frame_id(), cc::ElementId());
  testing::Mock::VerifyAndClearExpectations(&mock_input_handler_);
}

TEST_F(InputHandlerProxyEventQueueTest, MouseEventAttribution) {
  WebMouseEvent mouse_down(WebInputEvent::Type::kMouseDown,
                           WebInputEvent::kNoModifiers,
                           WebInputEvent::GetStaticTimeStampForTests());

  EXPECT_CALL(mock_input_handler_, FindFrameElementIdAtPoint(gfx::PointF(0, 0)))
      .Times(1)
      .WillOnce(testing::Return(cc::ElementId(0xDEADBEEF)));

  WebInputEventAttribution attribution =
      input_handler_proxy_.PerformEventAttribution(mouse_down);
  EXPECT_EQ(attribution.type(), WebInputEventAttribution::kTargetedFrame);
  EXPECT_EQ(attribution.target_frame_id(), cc::ElementId(0xDEADBEEF));
  testing::Mock::VerifyAndClearExpectations(&mock_input_handler_);
}

TEST_F(InputHandlerProxyEventQueueTest, MouseWheelEventAttribution) {
  WebMouseWheelEvent wheel(WebInputEvent::Type::kMouseWheel,
                           WebInputEvent::kNoModifiers,
                           WebInputEvent::GetStaticTimeStampForTests());

  EXPECT_CALL(mock_input_handler_, FindFrameElementIdAtPoint(gfx::PointF(0, 0)))
      .Times(1)
      .WillOnce(testing::Return(cc::ElementId(0xDEADBEEF)));

  WebInputEventAttribution attribution =
      input_handler_proxy_.PerformEventAttribution(wheel);
  EXPECT_EQ(attribution.type(), WebInputEventAttribution::kTargetedFrame);
  EXPECT_EQ(attribution.target_frame_id(), cc::ElementId(0xDEADBEEF));
  testing::Mock::VerifyAndClearExpectations(&mock_input_handler_);
}

// Verify that the first point in a touch event is used for performing event
// attribution.
TEST_F(InputHandlerProxyEventQueueTest, TouchEventAttribution) {
  WebTouchEvent touch(WebInputEvent::Type::kTouchStart,
                      WebInputEvent::kNoModifiers,
                      WebInputEvent::GetStaticTimeStampForTests());

  touch.touches_length = 3;
  touch.touch_start_or_first_touch_move = true;
  touch.touches[0] =
      CreateWebTouchPoint(WebTouchPoint::State::kStatePressed, 0, 0);
  touch.touches[1] =
      CreateWebTouchPoint(WebTouchPoint::State::kStatePressed, 10, 10);
  touch.touches[2] =
 
"""


```