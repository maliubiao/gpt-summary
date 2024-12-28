Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is a part of a unit test file for `InputHandlerProxy` in the Chromium Blink engine. I need to identify the main functionalities being tested in this part of the code. The tests seem to focus on how `InputHandlerProxy` handles and queues different types of input events, especially gesture events like scrolls and pinches, and how it interacts with the `mock_input_handler_`. I also need to look for connections to JavaScript, HTML, and CSS, examples of logical reasoning (input/output), common usage errors, and finally, summarise the functionality.

**Functionality Breakdown:**

1. **Scrollbar Interaction:** Testing how mouse clicks on scrollbars initiate and end gesture scrolls.
2. **VSync Aligned Gesture Scroll:**  Testing the queuing and coalescing of `GestureScrollUpdate` events and their dispatch aligned with VSync.
3. **VSync Aligned Gesture Scroll with Pinch:** Testing the interleaving of scroll and pinch gestures and their queuing/coalescing.
4. **VSync Aligned Queueing Time:**  Testing the timing of event queuing and dispatch.
5. **VSync Aligned Coalescing of Scroll and Pinch:** Testing the coalescing behavior of scroll and pinch updates within the same gesture sequence.
6. **VSync Aligned Coalescing of Touchpad Pinch:** Testing specific coalescing behavior for touchpad pinch gestures.
7. **Original Events Tracing:** Testing if original input events are correctly tracked during tracing.
8. **Touchpad Gesture Scroll End Flushing Queue:** Testing if a touchpad `GestureScrollEnd` event triggers the immediate processing of queued events.
9. **Coalesced Latency Info:** Testing if coalesced events are correctly marked in latency information.
10. **Scroll Predictor:** Testing the scroll prediction mechanism and its reset behavior.
11. **Deliver Input in High Latency Mode:** Testing how events are delivered when scroll prediction is disabled.
12. **Event Attribution:** Testing how the target frame for different input events is determined.

**Connections to JavaScript, HTML, and CSS:**

The functionalities tested here directly relate to how user interactions (mouse clicks, touch gestures, etc.) are translated into browser actions. JavaScript event listeners can react to these events, HTML elements are the targets of these interactions, and CSS can influence scrolling behavior.

**Logical Reasoning (Input/Output):**

The tests use `EXPECT_CALL` to define expected calls to the mock object and `EXPECT_EQ` to verify the state of the event queue and other variables. For instance, a mouse down on a scrollbar should result in `GestureScrollBegin` and `GestureScrollUpdate` events being queued.

**Common Usage Errors:**

While the code itself is a test, the scenarios it covers can highlight potential issues. For example, incorrectly handling or blocking touch events in JavaScript could interfere with the smooth scrolling tested here.

**Summary:**

This part of the test suite focuses on verifying the correct queuing, coalescing, and dispatching of various input events, especially gesture events like scrolls and pinches, within the `InputHandlerProxy`. It also tests features like scroll prediction, event attribution, and tracing.
这是 `blink/renderer/platform/widget/input/input_handler_proxy_unittest.cc` 文件的第 4 部分，主要功能是 **测试 `InputHandlerProxy` 类在处理各种输入事件时的事件队列管理、合并（coalescing）、调度 (dispatching) 机制，以及一些相关的功能特性。**  它关注的是当输入事件发生时，`InputHandlerProxy` 如何将这些事件放入队列，如何将相似的事件合并以优化处理，以及在合适的时机将这些事件传递给底层的输入处理器 `mock_input_handler_`。

以下是该部分测试用例的具体功能归纳，并解释了它们与 JavaScript, HTML, CSS 的关系，逻辑推理的例子，以及可能的用户或编程错误：

**功能归纳:**

1. **`nScrollbarInitiatesGestureScroll`**: 测试当用户在滚动条上按下鼠标（`kMouseDown`）和释放鼠标（`kMouseUp`）时，`InputHandlerProxy` 是否正确地生成 `GestureScrollBegin` 和 `GestureScrollEnd` 事件。
    *   **与 JavaScript, HTML, CSS 的关系:** 用户与滚动条的交互是浏览器用户界面的基本组成部分。JavaScript 可以监听和处理与滚动相关的事件，HTML 结构定义了滚动条的存在，CSS 样式可以影响滚动条的外观。
    *   **逻辑推理 (假设输入与输出):**
        *   **输入:**  `kMouseDown` 事件发生在滚动条区域，然后是 `kMouseUp` 事件。
        *   **输出:**  事件队列中应该先出现一个 `kGestureScrollBegin` 事件，然后是一个 `kGestureScrollUpdate` 事件（由 `MouseDown` 触发），最后是一个 `kGestureScrollEnd` 事件（由 `MouseUp` 触发）。
    *   **用户或编程常见的使用错误:** 开发者可能会错误地阻止或修改滚动条上的默认鼠标事件行为，导致滚动失效。

2. **`VSyncAlignedGestureScroll`**: 测试在合成器线程上处理滚动时，`GestureScrollUpdate` 事件是否被正确地排队和合并，并在 VSync 信号到来时被分发。
    *   **与 JavaScript, HTML, CSS 的关系:**  流畅的滚动体验是用户感知的关键。此测试确保了与动画帧同步的滚动更新，这与 JavaScript 动画和 CSS 过渡效果密切相关。
    *   **逻辑推理 (假设输入与输出):**
        *   **输入:**  一个 `kGestureScrollBegin` 事件，然后是多个 `kGestureScrollUpdate` 事件，最后是 `kGestureScrollEnd` 事件。
        *   **输出:**  `kGestureScrollBegin` 会立即处理。后续的 `kGestureScrollUpdate` 事件会合并到队列中。当 `DeliverInputForBeginFrame()` 被调用时（模拟 VSync），队列中的事件会被分发。
    *   **用户或编程常见的使用错误:** 如果 JavaScript 代码中存在性能瓶颈，或者 CSS 样式导致大量的重绘，可能会影响合成器线程的性能，从而影响滚动的流畅性。

3. **`MAYBE_VSyncAlignedGestureScrollPinchScroll`**: 测试滚动和捏合（pinch）手势的组合处理，验证事件的排队、合并和分发是否正确。
    *   **与 JavaScript, HTML, CSS 的关系:** 捏合缩放是移动设备上常见的交互方式，与 JavaScript 事件处理和 CSS 变换密切相关。
    *   **逻辑推理 (假设输入与输出):**  一系列的 `kGestureScrollBegin`, `kGestureScrollUpdate`, `kGestureScrollEnd`, `kGesturePinchBegin`, `kGesturePinchUpdate`, `kGesturePinchEnd` 事件会按顺序进入。  部分事件会被合并，并在 `DeliverInputForBeginFrame()` 时分发。
    *   **用户或编程常见的使用错误:**  JavaScript 代码中对触摸事件处理不当，可能会干扰捏合缩放的正常进行。

4. **`VSyncAlignedQueueingTime`**: 测试事件进入队列的时间戳是否被正确记录，这对于分析事件处理延迟非常重要。
    *   **与 JavaScript, HTML, CSS 的关系:** 事件处理的延迟直接影响用户交互的响应速度，与 JavaScript 代码的执行效率和浏览器渲染性能有关。
    *   **逻辑推理 (假设输入与输出):** 通过模拟时间流逝，测试不同时间点产生的事件在队列中的顺序和时间信息。

5. **`VSyncAlignedCoalesceScrollAndPinch`**:  测试在同一次交互中混合发生的滚动和捏合手势事件是否能正确合并。
    *   **与 JavaScript, HTML, CSS 的关系:**  用户可能在滚动的同时进行捏合操作，浏览器需要正确处理这种混合输入。
    *   **逻辑推理 (假设输入与输出):**  交错的 `kGestureScrollUpdate` 和 `kGesturePinchUpdate` 事件会被合并成一个 `kGestureScrollUpdate` 和一个 `kGesturePinchUpdate` 事件。

6. **`VSyncAlignedCoalesceTouchpadPinch`**:  专门测试触摸板产生的捏合手势事件的合并行为，特别是关注中心点 (anchor) 不同的情况。
    *   **与 JavaScript, HTML, CSS 的关系:** 触摸板是桌面设备上常见的输入方式，其捏合手势的处理与触摸屏有所不同。
    *   **逻辑推理 (假设输入与输出):**  具有相同中心点的连续 `kGesturePinchUpdate` 事件会被合并，而中心点不同的事件则不会。

7. **`OriginalEventsTracing`**: 测试在进行事件追踪时，原始的输入事件信息是否被正确记录。
    *   **与 JavaScript, HTML, CSS 的关系:**  事件追踪对于调试和性能分析至关重要，可以帮助开发者理解用户交互和浏览器行为。

8. **`TouchpadGestureScrollEndFlushQueue`**: 测试当触摸板产生 `GestureScrollEnd` 事件时，是否会立即清空事件队列，以便快速响应滚动结束。
    *   **与 JavaScript, HTML, CSS 的关系:**  触摸板滚动的特性需要在事件处理上进行特殊优化以提供流畅的体验。

9. **`CoalescedLatencyInfo`**: 测试被合并的事件是否在延迟信息中被正确标记为已合并，这对于分析事件延迟至关重要。

10. **`ScrollPredictorTest`**: 测试滚动预测功能，即浏览器尝试预测用户的滚动意图，以提前进行渲染。
    *   **与 JavaScript, HTML, CSS 的关系:**  滚动预测旨在提高滚动流畅性，尤其是在高延迟情况下，这与 JavaScript 动画和 CSS 滚动行为有关。

11. **`DeliverInputWithHighLatencyMode`**: 测试在禁用滚动预测的情况下，事件的传递方式。

12. **`KeyEventAttribution`**, **`MouseEventAttribution`**, **`MouseWheelEventAttribution`**, **`TouchEventAttribution`**: 测试如何确定不同类型输入事件的目标 frame（`cc::ElementId`），这对于在 iframe 结构中正确分发事件至关重要。
    *   **与 JavaScript, HTML, CSS 的关系:**  复杂的网页可能包含多个 iframe，浏览器需要正确地将事件发送到相应的 iframe 上下文中的 JavaScript 代码和 HTML 元素。

**总结:**

这部分单元测试主要验证了 `InputHandlerProxy` 在处理各种输入事件时，如何有效地管理和调度事件队列，包括对滚动、捏合等复杂手势事件的合并和 VSync 对齐处理，以及事件追踪和目标归属等功能。这些测试确保了 Blink 引擎能够以高性能和正确的方式响应用户的输入，从而为用户提供流畅的交互体验。这与 JavaScript 事件处理、HTML 结构和 CSS 样式共同构成了 Web 页面的交互基础。

Prompt: 
```
这是目录为blink/renderer/platform/widget/input/input_handler_proxy_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第4部分，共5部分，请归纳一下它的功能

"""
nScrollbarInitiatesGestureScroll) {
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