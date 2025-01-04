Response:
The user wants me to summarize the functionality of the provided C++ code snippet from `input_handler_proxy_unittest.cc`. I also need to identify its relationships with web technologies like JavaScript, HTML, and CSS, providing examples if such connections exist. Furthermore, I should illustrate logical reasoning within the code with input/output examples and highlight potential user or programming errors. Finally, as this is the third part of the request, I need to provide a comprehensive summary of the overall functionality based on the provided snippet.

Let's break down the code:

1. **Event Attribution Tests:** The `GestureEventAttribution` and the test using `CreateWebTouchPoint` are about determining which frame (iframe) an input event targets. This is crucial for correct event routing in web pages with multiple frames.
2. **Event Queue and Deadline Tests:** The `QueueInputForLateBeginFrameArgs` test focuses on how the `InputHandlerProxy` manages input events when the compositor's frame rendering is delayed. It tests the queuing behavior and the interaction with `BeginFrame` signals.
3. **Main Thread Scrolling Reason Tests:** The `InputHandlerProxyMainThreadScrollingReasonTest` suite examines the conditions under which scrolling happens on the main thread versus the compositor thread and records the reasons for main thread scrolling. Histograms are used to track these reasons.
4. **Touch Scrollbar Test:** The `InputHandlerProxyTouchScrollbarTest` checks if touch events on a scrollbar are handled directly by the compositor thread.
5. **Test Fixtures and Parameterization:** The code utilizes various test fixtures (`InputHandlerProxyTest`, `InputHandlerProxyEventQueueTest`, `InputHandlerProxyMainThreadScrollingReasonTest`, `InputHandlerProxyTouchScrollbarTest`) and parameterization (`INSTANTIATE_TEST_SUITE_P`) to cover different scenarios and configurations.

Now let's consider the relationships with web technologies:

*   **JavaScript:** Event listeners in JavaScript can influence whether an input event is handled on the main thread or compositor thread. For example, a passive event listener allows compositor thread scrolling, while a blocking listener forces main thread handling.
*   **HTML:**  The structure of the HTML document, particularly the presence of iframes, is directly relevant to the event attribution tests. The presence of scrollable areas and event listeners on those areas is also key to the scrolling reason tests.
*   **CSS:** CSS properties like `touch-action` can influence how touch events are handled. Also, overflow properties can create scrollable areas, which are the focus of the scrollbar tests.

Let's think about logical reasoning and input/output:

*   **Event Attribution:** Input: A `WebTouchEvent` at coordinates (0, 0). Expected Output: `WebInputEventAttribution` with `target_frame_id` set to `0xDEADBEEF`. This assumes that `mock_input_handler_.FindFrameElementIdAtPoint(gfx::PointF(0, 0))` returns `cc::ElementId(0xDEADBEEF)`.
*   **Event Queuing:** Input: A `kGestureScrollUpdate` event arriving after the deadline. Expected Output: The event is added to the `event_queue()`.

Finally, common errors:

*   **Incorrectly assuming compositor thread scrolling:** Developers might assume their scrolling is always smooth and compositor-driven, but blocking JavaScript event listeners can force main thread scrolling, leading to jank.
*   **Not handling events in iframes properly:**  Failing to account for iframe boundaries can result in events not being dispatched to the correct frame.

Given this breakdown, I can now formulate the final response.
这是`blink/renderer/platform/widget/input/input_handler_proxy_unittest.cc`文件的第3部分，延续了对 `InputHandlerProxy` 类的单元测试。基于提供的代码片段，可以归纳出以下功能：

**1. 测试输入事件的归属 (Attribution)：**

*   **触摸事件归属测试 (`GestureEventAttribution`)：** 测试了 `InputHandlerProxy` 如何确定触摸事件的目标元素所在的帧（frame）。它模拟了一个触摸按下事件，并期望 `PerformEventAttribution` 方法返回的归属信息表明该事件的目标是特定的帧，其 `target_frame_id` 为 `0xDEADBEEF`。
    *   **与 HTML 的关系：**  当一个网页包含 `<iframe>` 等内嵌帧时，浏览器需要正确地将输入事件路由到对应的帧。此测试模拟了这种情况，确保在点击某个位置时，能正确识别出该位置所属的帧。
    *   **假设输入与输出：**
        *   **假设输入：** 一个触摸按下事件发生在屏幕坐标 `(-10, 10)`。
        *   **假设输出：** `PerformEventAttribution` 返回一个 `WebInputEventAttribution` 对象，其类型为 `kTargetedFrame`，且 `target_frame_id` 为 `0xDEADBEEF`。

*   **手势事件归属测试 (`GestureEventAttribution`)：**  与触摸事件类似，测试了 `InputHandlerProxy` 如何确定手势事件（例如 `kGestureTap`）的目标帧。
    *   **与 HTML 的关系：**  同样与包含 `<iframe>` 的网页相关，确保手势操作能正确作用于目标帧。
    *   **假设输入与输出：**
        *   **假设输入：** 一个 `kGestureTap` 事件发生在屏幕坐标 `(10, 10)`。
        *   **假设输出：** `PerformEventAttribution` 返回一个 `WebInputEventAttribution` 对象，其类型为 `kTargetedFrame`，且 `target_frame_id` 为 `0xDEADBEEF`。

**2. 测试事件队列和截止时间 (Deadline) 的处理：**

*   **延迟 BeginFrame 参数的输入排队测试 (`QueueInputForLateBeginFrameArgs`)：** 测试了当启用“在截止时间前分发事件”模式时，`InputHandlerProxy` 如何处理在截止时间之后到达的输入事件和 `BeginFrame` 信号。它验证了晚到的输入事件会被放入队列，并且错过的 (`MISSED`) `BeginFrame` 信号不会触发队列中事件的分发。
    *   **与 JavaScript 的关系：**  JavaScript 的动画和 requestAnimationFrame 等机制依赖于 `BeginFrame` 信号。此测试确保了在帧渲染延迟的情况下，输入事件能够被正确地排队和处理，从而避免丢失输入或导致不流畅的动画。
    *   **假设输入与输出：**
        *   **假设输入 1：** 一个 `kGestureScrollUpdate` 事件在 `BeginFrame` 的截止时间之后到达。
        *   **假设输出 1：** 该事件被加入到 `event_queue()` 中。
        *   **假设输入 2：** 一个 `viz::BeginFrameArgs::MISSED` 类型的 `BeginFrame` 信号在截止时间之后到达。
        *   **假设输出 2：** `event_queue()` 中的事件不会被处理。

**3. 测试主线程滚动原因的记录：**

*   **`InputHandlerProxyMainThreadScrollingReasonTest` 测试套件：**  这一系列的测试旨在验证 `InputHandlerProxy` 是否正确记录了导致滚动发生在主线程的原因。这对于性能分析和优化非常重要，因为通常情况下，滚动应该尽可能在合成器线程上进行以提高流畅度。
    *   **与 JavaScript 的关系：** JavaScript 事件监听器可以影响滚动是否发生在主线程。例如，如果一个触摸事件命中了具有阻塞型事件监听器的区域，滚动可能会被阻塞在主线程上。
    *   **与 HTML 的关系：** HTML 元素的结构和属性（例如是否可滚动）会影响滚动行为。
    *   **与 CSS 的关系：** CSS 属性（例如 `touch-action`）可以影响浏览器如何处理触摸事件和滚动。
    *   **示例和逻辑推理：**
        *   **`GestureScrollNotScrollOnMain`：** 测试了当触摸开始事件没有命中任何处理程序时，手势滚动发生在合成器线程。
        *   **`GestureScrollTouchEventHandlerRegion`：** 测试了当触摸事件命中了一个由合成器线程确认处理的触摸事件处理程序时，手势滚动发生在合成器线程。
        *   **`ImplHandled_MainThreadHitTest` 和 `ImplHandled_MainThreadRepaint`：** 测试了在某些情况下（例如，需要主线程进行命中测试或重绘），即使滚动在合成器线程上开始，仍然会记录主线程滚动的原因。
        *   **`WheelScrollHistogram`：** 测试了可以正确记录鼠标滚轮滚动的主线程滚动原因。
        *   **`WheelScrollNotScrollingOnMain` 和 `WheelScrollWheelEventHandlerRegion`：**  分别测试了当鼠标滚轮事件没有阻塞事件处理程序和有阻塞事件处理程序时，滚动的处理方式和主线程滚动原因的记录。
    *   **假设输入与输出（以 `GestureScrollTouchEventHandlerRegion` 为例）：**
        *   **假设输入：** 一个触摸开始事件发生在一个具有触摸事件处理程序的区域，随后发生手势滚动开始和结束事件。
        *   **假设输出：**  `Renderer4.MainThreadGestureScrollReason2` 柱状图会记录一个非主线程滚动的样本 (`base::Bucket(0, 1)`)，表示滚动发生在合成器线程。

**4. 测试触摸滚动条的处理：**

*   **`InputHandlerProxyTouchScrollbarTest` 测试套件：** 测试了当触摸发生在滚动条上时，事件是否由合成器线程处理。
    *   **与 HTML 的关系：**  网页的滚动条是 HTML 结构的一部分。
    *   **假设输入与输出：**
        *   **假设输入：** 一个触摸按下事件发生在滚动条区域，然后发生触摸抬起事件。
        *   **假设输出：**  `InputHandlerProxy` 将识别出触摸发生在滚动条上，并模拟鼠标按下和抬起事件，导致滚动在合成器线程上发生。

**5. 使用参数化测试覆盖不同场景：**

*   **`INSTANTIATE_TEST_SUITE_P`：**  使用了 gtest 的参数化测试功能，通过 `kTestCombinations` 定义了不同的测试参数组合（`ScrollerType` 和 `HandlerType`），并为每个组合生成不同的测试实例，以更全面地测试 `InputHandlerProxy` 的行为。

**常见的使用错误（开发者角度）：**

*   **错误地假设所有滚动都在合成器线程上进行：** 开发者可能会认为所有滚动操作都是平滑的，由合成器线程处理，但 JavaScript 事件监听器或某些渲染因素可能导致滚动阻塞在主线程，造成性能问题。
*   **没有正确处理 iframe 间的事件传递：**  在包含 iframe 的页面中，开发者可能会错误地假设事件会自然地冒泡或捕获到父框架，而没有考虑到跨文档脚本的限制和事件路由的复杂性。`InputHandlerProxy` 的事件归属测试正是为了确保这种场景下事件能被正确处理。
*   **过度使用阻塞型事件监听器：**  为了实现某些交互效果，开发者可能会滥用阻塞型的触摸或鼠标滚轮事件监听器，导致滚动操作被迫在主线程上执行，降低页面性能。

总而言之，这部分代码主要关注 `InputHandlerProxy` 如何正确识别输入事件的目标、如何在帧渲染延迟的情况下管理事件队列，以及如何记录导致滚动发生在主线程的原因。这些功能对于确保 Chromium 浏览器能够流畅、高效地处理用户输入至关重要，尤其是在处理包含 iframe 和复杂交互的网页时。

Prompt: 
```
这是目录为blink/renderer/platform/widget/input/input_handler_proxy_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共3部分，请归纳一下它的功能

"""
     CreateWebTouchPoint(WebTouchPoint::State::kStatePressed, -10, 10);

  EXPECT_CALL(mock_input_handler_, FindFrameElementIdAtPoint(gfx::PointF(0, 0)))
      .Times(1)
      .WillOnce(testing::Return(cc::ElementId(0xDEADBEEF)));

  WebInputEventAttribution attribution =
      input_handler_proxy_.PerformEventAttribution(touch);
  EXPECT_EQ(attribution.type(), WebInputEventAttribution::kTargetedFrame);
  EXPECT_EQ(attribution.target_frame_id(), cc::ElementId(0xDEADBEEF));
  testing::Mock::VerifyAndClearExpectations(&mock_input_handler_);
}

TEST_F(InputHandlerProxyEventQueueTest, GestureEventAttribution) {
  WebGestureEvent gesture(WebInputEvent::Type::kGestureTap,
                          WebInputEvent::kNoModifiers,
                          WebInputEvent::GetStaticTimeStampForTests());
  gesture.SetPositionInWidget(gfx::PointF(10, 10));

  EXPECT_CALL(mock_input_handler_,
              FindFrameElementIdAtPoint(gfx::PointF(10, 10)))
      .Times(1)
      .WillOnce(testing::Return(cc::ElementId(0xDEADBEEF)));
  WebInputEventAttribution attribution =
      input_handler_proxy_.PerformEventAttribution(gesture);
  EXPECT_EQ(attribution.type(), WebInputEventAttribution::kTargetedFrame);
  EXPECT_EQ(attribution.target_frame_id(), cc::ElementId(0xDEADBEEF));
  testing::Mock::VerifyAndClearExpectations(&mock_input_handler_);
}

// Tests that when we are only dispatching events until the deadline, that input
// arriving after the deadline is enqueued. As well any MISSED BeginFrames
// arriving after the deadline do not dispatch any enqueued input events.
TEST_F(InputHandlerProxyEventQueueTest, QueueInputForLateBeginFrameArgs) {
  base::SimpleTestTickClock tick_clock;
  tick_clock.SetNowTicks(base::TimeTicks::Now());
  SetInputHandlerProxyTickClockForTesting(&tick_clock);
  input_handler_proxy_.SetScrollEventDispatchMode(
      cc::InputHandlerClient::ScrollEventDispatchMode::
          kDispatchScrollEventsUntilDeadline,
      0.333);

  // ScrollBegin should idenfity the target element, and the event should be
  // processed immediately without being queued.
  EXPECT_CALL(mock_input_handler_, ScrollBegin(_, _))
      .WillOnce(testing::Return(kImplThreadScrollState));
  EXPECT_CALL(
      mock_input_handler_,
      RecordScrollBegin(ui::ScrollInputType::kTouchscreen,
                        cc::ScrollBeginThreadState::kScrollingOnCompositor))
      .Times(1);
  EXPECT_CALL(mock_input_handler_, FindFrameElementIdAtPoint(_)).Times(1);
  HandleGestureEventWithSourceDevice(WebInputEvent::Type::kGestureScrollBegin,
                                     WebGestureDevice::kTouchscreen);
  EXPECT_EQ(0ul, event_queue().size());
  EXPECT_EQ(1ul, event_disposition_recorder_.size());
  testing::Mock::VerifyAndClearExpectations(&mock_input_handler_);

  // When a BeginFrame is received, if the queue is empty we should dispatch
  // any incoming scroll event immediately. As long as it is before the
  // deadline.
  DeliverInputForBeginFrame(tick_clock.NowTicks());
  EXPECT_CALL(mock_input_handler_, FindFrameElementIdAtPoint(_)).Times(1);
  EXPECT_CALL(mock_input_handler_, ScrollUpdate).Times(1);
  HandleGestureEventWithSourceDevice(WebInputEvent::Type::kGestureScrollUpdate,
                                     WebGestureDevice::kTouchscreen, -20);
  EXPECT_EQ(0ul, event_queue().size());
  testing::Mock::VerifyAndClearExpectations(&mock_input_handler_);

  // When a BeginFrame is received, and the input arrives after the deadline,
  // the event should be enqueued. We should signal that we still require
  // BeginFrames by calling SetNeedsAnimateInput.
  constexpr base::TimeDelta interval = base::Milliseconds(16);
  tick_clock.Advance(interval);
  DeliverInputForBeginFrame(tick_clock.NowTicks());
  EXPECT_CALL(mock_input_handler_, SetNeedsAnimateInput());
  EXPECT_CALL(mock_input_handler_, ScrollUpdate).Times(0);
  constexpr base::TimeDelta after_deadline = interval * 0.4f;
  tick_clock.Advance(after_deadline);
  HandleGestureEventWithSourceDevice(WebInputEvent::Type::kGestureScrollUpdate,
                                     WebGestureDevice::kTouchscreen, -20);
  EXPECT_EQ(1ul, event_queue().size());
  testing::Mock::VerifyAndClearExpectations(&mock_input_handler_);

  // When a BeginFrame is received, that is of viz::BeginFrameArgs::MISSED, and
  // arrives after the deadline. We should not process the queue.
  tick_clock.Advance(interval);
  const base::TimeTicks missed_frame_time = tick_clock.NowTicks();
  tick_clock.Advance(after_deadline);
  EXPECT_CALL(mock_input_handler_, SetNeedsAnimateInput());
  DeliverInputForBeginFrame(missed_frame_time, viz::BeginFrameArgs::MISSED);
  EXPECT_EQ(1ul, event_queue().size());
  testing::Mock::VerifyAndClearExpectations(&mock_input_handler_);

  // When a regular BeginFrame arrives we resume processing the queue.
  EXPECT_CALL(mock_input_handler_, FindFrameElementIdAtPoint(_)).Times(1);
  EXPECT_CALL(mock_input_handler_, ScrollUpdate);
  DeliverInputForBeginFrame(tick_clock.NowTicks());
  EXPECT_EQ(0ul, event_queue().size());
  testing::Mock::VerifyAndClearExpectations(&mock_input_handler_);
}

class InputHandlerProxyMainThreadScrollingReasonTest
    : public InputHandlerProxyTest {
 public:
  enum TestEventType {
    kTouch,
    kMouseWheel,
  };

  InputHandlerProxyMainThreadScrollingReasonTest() : InputHandlerProxyTest() {}
  ~InputHandlerProxyMainThreadScrollingReasonTest() = default;

  void SetupEvents(TestEventType type) {
    touch_start_ = WebTouchEvent(WebInputEvent::Type::kTouchStart,
                                 WebInputEvent::kNoModifiers,
                                 WebInputEvent::GetStaticTimeStampForTests());
    touch_end_ = WebTouchEvent(WebInputEvent::Type::kTouchEnd,
                               WebInputEvent::kNoModifiers,
                               WebInputEvent::GetStaticTimeStampForTests());
    wheel_event_ = WebMouseWheelEvent(
        WebInputEvent::Type::kMouseWheel, WebInputEvent::kControlKey,
        WebInputEvent::GetStaticTimeStampForTests());
    gesture_scroll_begin_ = WebGestureEvent(
        WebInputEvent::Type::kGestureScrollBegin, WebInputEvent::kNoModifiers,
        WebInputEvent::GetStaticTimeStampForTests(),
        type == TestEventType::kMouseWheel ? WebGestureDevice::kTouchpad
                                           : WebGestureDevice::kTouchscreen);
    gesture_scroll_end_ = WebGestureEvent(
        WebInputEvent::Type::kGestureScrollEnd, WebInputEvent::kNoModifiers,
        WebInputEvent::GetStaticTimeStampForTests(),
        type == TestEventType::kMouseWheel ? WebGestureDevice::kTouchpad
                                           : WebGestureDevice::kTouchscreen);
    touch_start_.touches_length = 1;
    touch_start_.touch_start_or_first_touch_move = true;
    touch_start_.touches[0] =
        CreateWebTouchPoint(WebTouchPoint::State::kStatePressed, 10, 10);

    touch_end_.touches_length = 1;
  }

  base::HistogramBase::Sample GetBucketSample(uint32_t reason) {
    uint32_t bucket = 0;
    while (reason >>= 1)
      bucket++;
    DCHECK_NE(bucket, 0u);
    return bucket;
  }

 protected:
  WebTouchEvent touch_start_;
  WebTouchEvent touch_end_;
  WebMouseWheelEvent wheel_event_;
  WebGestureEvent gesture_scroll_begin_;
  WebGestureEvent gesture_scroll_end_;
};

// Bucket 0: non-main-thread scrolls
// Bucket 1: main-thread scrolls for any reason.
#define EXPECT_NON_MAIN_THREAD_GESTURE_SCROLL_SAMPLE()         \
  EXPECT_THAT(histogram_tester().GetAllSamples(                \
                  "Renderer4.MainThreadGestureScrollReason2"), \
              testing::ElementsAre(base::Bucket(0, 1)))
#define EXPECT_NON_MAIN_THREAD_WHEEL_SCROLL_SAMPLE()         \
  EXPECT_THAT(histogram_tester().GetAllSamples(              \
                  "Renderer4.MainThreadWheelScrollReason2"), \
              testing::ElementsAre(base::Bucket(0, 1)))
#define EXPECT_MAIN_THREAD_GESTURE_SCROLL_SAMPLE(reason)       \
  EXPECT_THAT(histogram_tester().GetAllSamples(                \
                  "Renderer4.MainThreadGestureScrollReason2"), \
              testing::ElementsAre(base::Bucket(1, 1),         \
                                   base::Bucket(GetBucketSample(reason), 1)))
#define EXPECT_MAIN_THREAD_WHEEL_SCROLL_SAMPLE(reason)       \
  EXPECT_THAT(histogram_tester().GetAllSamples(              \
                  "Renderer4.MainThreadWheelScrollReason2"), \
              testing::ElementsAre(base::Bucket(1, 1),       \
                                   base::Bucket(GetBucketSample(reason), 1)))
#define EXPECT_MAIN_THREAD_WHEEL_SCROLL_SAMPLE_2(reason1, reason2)            \
  EXPECT_THAT(histogram_tester().GetAllSamples(                               \
                  "Renderer4.MainThreadWheelScrollReason2"),                  \
              testing::ElementsAre(base::Bucket(1, 1),                        \
                                   base::Bucket(GetBucketSample(reason1), 1), \
                                   base::Bucket(GetBucketSample(reason2), 1)))

// Tests GetBucketSample() returns the corresponding values defined in
// enums.xml, to ensure correctness of the tests using the function.
TEST_P(InputHandlerProxyMainThreadScrollingReasonTest, ReasonToBucket) {
  EXPECT_EQ(2, GetBucketSample(kSampleMainThreadScrollingReason));
  EXPECT_EQ(14, GetBucketSample(
                    cc::MainThreadScrollingReason::kTouchEventHandlerRegion));
}

TEST_P(InputHandlerProxyMainThreadScrollingReasonTest,
       GestureScrollNotScrollOnMain) {
  // Touch start with passive event listener.
  SetupEvents(TestEventType::kTouch);

  EXPECT_CALL(mock_input_handler_,
              EventListenerTypeForTouchStartOrMoveAt(
                  testing::Property(&gfx::Point::x, testing::Gt(0)), _))
      .WillOnce(testing::Return(
          cc::InputHandler::TouchStartOrMoveEventListenerType::kNoHandler));
  EXPECT_CALL(
      mock_input_handler_,
      GetEventListenerProperties(cc::EventListenerClass::kTouchStartOrMove))
      .WillOnce(testing::Return(cc::EventListenerProperties::kPassive));
  EXPECT_CALL(mock_client_, SetAllowedTouchAction(_))
      .WillOnce(testing::Return());
  EXPECT_CALL(mock_input_handler_, HitTest(_))
      .WillOnce(testing::Return(cc::PointerResultType::kUnhandled));
  EXPECT_CALL(mock_input_handler_, SetIsHandlingTouchSequence(true));

  expected_disposition_ = InputHandlerProxy::DID_NOT_HANDLE_NON_BLOCKING;
  EXPECT_EQ(expected_disposition_,
            HandleInputEventAndFlushEventQueue(
                mock_input_handler_, input_handler_.get(), touch_start_));

  EXPECT_CALL(mock_input_handler_, ScrollBegin(_, _))
      .WillOnce(testing::Return(kImplThreadScrollState));
  EXPECT_CALL(
      mock_input_handler_,
      RecordScrollBegin(_, cc::ScrollBeginThreadState::kScrollingOnCompositor))
      .Times(1);
  expected_disposition_ = InputHandlerProxy::DID_HANDLE;
  EXPECT_EQ(
      expected_disposition_,
      HandleInputEventAndFlushEventQueue(
          mock_input_handler_, input_handler_.get(), gesture_scroll_begin_));

  EXPECT_NON_MAIN_THREAD_GESTURE_SCROLL_SAMPLE();

  EXPECT_CALL(mock_input_handler_, ScrollEnd(true));
  EXPECT_CALL(mock_input_handler_, RecordScrollEnd(_)).Times(1);
  expected_disposition_ = InputHandlerProxy::DID_HANDLE;
  EXPECT_EQ(
      expected_disposition_,
      HandleInputEventAndFlushEventQueue(
          mock_input_handler_, input_handler_.get(), gesture_scroll_end_));
}

TEST_P(InputHandlerProxyMainThreadScrollingReasonTest,
       GestureScrollTouchEventHandlerRegion) {
  // The touch event hits a touch event handler that is acked from the
  // compositor thread.
  SetupEvents(TestEventType::kTouch);

  EXPECT_CALL(mock_input_handler_,
              EventListenerTypeForTouchStartOrMoveAt(
                  testing::Property(&gfx::Point::x, testing::Gt(0)), _))
      .WillOnce(
          testing::Return(cc::InputHandler::TouchStartOrMoveEventListenerType::
                              kHandlerOnScrollingLayer));
  EXPECT_CALL(mock_client_, SetAllowedTouchAction(_))
      .WillOnce(testing::Return());
  EXPECT_CALL(mock_input_handler_, HitTest(_))
      .WillOnce(testing::Return(cc::PointerResultType::kUnhandled));
  EXPECT_CALL(mock_input_handler_, SetIsHandlingTouchSequence(true));

  expected_disposition_ = InputHandlerProxy::DID_NOT_HANDLE_NON_BLOCKING;
  EXPECT_EQ(expected_disposition_,
            HandleInputEventAndFlushEventQueue(
                mock_input_handler_, input_handler_.get(), touch_start_));

  EXPECT_CALL(mock_input_handler_, ScrollBegin(_, _))
      .WillOnce(testing::Return(kImplThreadScrollState));
  EXPECT_CALL(
      mock_input_handler_,
      RecordScrollBegin(_, cc::ScrollBeginThreadState::kScrollingOnCompositor))
      .Times(1);
  expected_disposition_ = InputHandlerProxy::DID_HANDLE;
  EXPECT_EQ(
      expected_disposition_,
      HandleInputEventAndFlushEventQueue(
          mock_input_handler_, input_handler_.get(), gesture_scroll_begin_));

  EXPECT_NON_MAIN_THREAD_GESTURE_SCROLL_SAMPLE();

  EXPECT_CALL(mock_input_handler_, ScrollEnd(true));
  EXPECT_CALL(mock_input_handler_, RecordScrollEnd(_)).Times(1);
  expected_disposition_ = InputHandlerProxy::DID_HANDLE;
  EXPECT_EQ(
      expected_disposition_,
      HandleInputEventAndFlushEventQueue(
          mock_input_handler_, input_handler_.get(), gesture_scroll_end_));
}

TEST_P(InputHandlerProxyMainThreadScrollingReasonTest,
       ImplHandled_MainThreadHitTest) {
  expected_disposition_ = InputHandlerProxy::DID_HANDLE;
  VERIFY_AND_RESET_MOCKS();

  gesture_.data.scroll_begin.scrollable_area_element_id = 1;
  gesture_.data.scroll_begin.main_thread_hit_tested_reasons =
      cc::MainThreadScrollingReason::kMainThreadScrollHitTestRegion;

  EXPECT_CALL(mock_input_handler_, ScrollBegin(_, _))
      .WillOnce(testing::Return(kImplThreadScrollState));
  EXPECT_CALL(
      mock_input_handler_,
      RecordScrollBegin(
          _, cc::ScrollBeginThreadState::kScrollingOnCompositorBlockedOnMain))
      .Times(1);

  gesture_.SetType(WebInputEvent::Type::kGestureScrollBegin);
  EXPECT_EQ(expected_disposition_,
            HandleInputEventWithLatencyInfo(input_handler_.get(), gesture_));

  VERIFY_AND_RESET_MOCKS();

  EXPECT_MAIN_THREAD_WHEEL_SCROLL_SAMPLE(
      cc::MainThreadScrollingReason::kMainThreadScrollHitTestRegion);
}

TEST_P(InputHandlerProxyMainThreadScrollingReasonTest,
       ImplHandled_MainThreadRepaint) {
  expected_disposition_ = InputHandlerProxy::DID_HANDLE;
  VERIFY_AND_RESET_MOCKS();

  cc::InputHandler::ScrollStatus scroll_status = kImplThreadScrollState;
  scroll_status.main_thread_repaint_reasons =
      cc::MainThreadScrollingReason::kPreferNonCompositedScrolling;

  EXPECT_CALL(mock_input_handler_, ScrollBegin(_, _))
      .WillOnce(testing::Return(scroll_status));
  EXPECT_CALL(
      mock_input_handler_,
      RecordScrollBegin(_, cc::ScrollBeginThreadState::kScrollingOnMain))
      .Times(1);

  gesture_.SetType(WebInputEvent::Type::kGestureScrollBegin);
  EXPECT_EQ(expected_disposition_,
            HandleInputEventWithLatencyInfo(input_handler_.get(), gesture_));

  VERIFY_AND_RESET_MOCKS();

  EXPECT_MAIN_THREAD_WHEEL_SCROLL_SAMPLE(
      cc::MainThreadScrollingReason::kPreferNonCompositedScrolling);
}

TEST_P(InputHandlerProxyMainThreadScrollingReasonTest, WheelScrollHistogram) {
  // Firstly check if input handler can correctly record main thread scrolling
  // reasons.
  EXPECT_CALL(
      mock_input_handler_,
      RecordScrollBegin(_, cc::ScrollBeginThreadState::kScrollingOnMain))
      .Times(1);
  input_handler_->RecordScrollBeginForTest(
      WebGestureDevice::kTouchpad,
      kSampleMainThreadScrollingReason |
          cc::MainThreadScrollingReason::kPreferNonCompositedScrolling);

  EXPECT_MAIN_THREAD_WHEEL_SCROLL_SAMPLE_2(
      kSampleMainThreadScrollingReason,
      cc::MainThreadScrollingReason::kPreferNonCompositedScrolling);
}

TEST_P(InputHandlerProxyMainThreadScrollingReasonTest,
       WheelScrollNotScrollingOnMain) {
  // Even if a scroller is composited, we still need to record its main thread
  // scrolling reason if it is blocked on a main thread event handler.
  SetupEvents(TestEventType::kMouseWheel);

  // We can scroll on impl for an wheel event with passive event listener.
  EXPECT_CALL(mock_input_handler_, HasBlockingWheelEventHandlerAt(_))
      .WillRepeatedly(testing::Return(false));
  EXPECT_CALL(mock_input_handler_,
              GetEventListenerProperties(cc::EventListenerClass::kMouseWheel))
      .WillOnce(testing::Return(cc::EventListenerProperties::kPassive));
  expected_disposition_ = InputHandlerProxy::DID_NOT_HANDLE_NON_BLOCKING;
  EXPECT_EQ(expected_disposition_, HandleInputEventWithLatencyInfo(
                                       input_handler_.get(), wheel_event_));

  EXPECT_CALL(mock_input_handler_, ScrollBegin(_, _))
      .WillOnce(testing::Return(kImplThreadScrollState));
  EXPECT_CALL(
      mock_input_handler_,
      RecordScrollBegin(_, cc::ScrollBeginThreadState::kScrollingOnCompositor))
      .Times(1);
  expected_disposition_ = InputHandlerProxy::DID_HANDLE;
  EXPECT_EQ(expected_disposition_,
            HandleInputEventWithLatencyInfo(input_handler_.get(),
                                            gesture_scroll_begin_));

  EXPECT_NON_MAIN_THREAD_WHEEL_SCROLL_SAMPLE();

  EXPECT_CALL(mock_input_handler_, ScrollEnd(true));
  EXPECT_CALL(mock_input_handler_, RecordScrollEnd(_)).Times(1);
  expected_disposition_ = InputHandlerProxy::DID_HANDLE;
  EXPECT_EQ(expected_disposition_,
            HandleInputEventWithLatencyInfo(input_handler_.get(),
                                            gesture_scroll_end_));
}

TEST_P(InputHandlerProxyMainThreadScrollingReasonTest,
       WheelScrollWheelEventHandlerRegion) {
  // Wheel event with blocking event listener. If there is a wheel event handler
  // at the point, we do not need to call GetEventListenerProperties since it
  // indicates kBlocking.
  SetupEvents(TestEventType::kMouseWheel);
  EXPECT_CALL(mock_input_handler_, HasBlockingWheelEventHandlerAt(_))
      .WillRepeatedly(testing::Return(true));
  expected_disposition_ = InputHandlerProxy::DID_NOT_HANDLE;
  EXPECT_EQ(expected_disposition_, HandleInputEventWithLatencyInfo(
                                       input_handler_.get(), wheel_event_));

  EXPECT_CALL(mock_input_handler_, ScrollBegin(_, _))
      .WillOnce(testing::Return(kImplThreadScrollState));
  EXPECT_CALL(
      mock_input_handler_,
      RecordScrollBegin(
          _, cc::ScrollBeginThreadState::kScrollingOnCompositorBlockedOnMain))
      .Times(1);
  expected_disposition_ = InputHandlerProxy::DID_HANDLE;
  EXPECT_EQ(expected_disposition_,
            HandleInputEventWithLatencyInfo(input_handler_.get(),
                                            gesture_scroll_begin_));

  EXPECT_MAIN_THREAD_WHEEL_SCROLL_SAMPLE(
      cc::MainThreadScrollingReason::kWheelEventHandlerRegion);

  EXPECT_CALL(mock_input_handler_, ScrollEnd(true));
  EXPECT_CALL(mock_input_handler_, RecordScrollEnd(_)).Times(1);
  expected_disposition_ = InputHandlerProxy::DID_HANDLE;
  EXPECT_EQ(expected_disposition_,
            HandleInputEventWithLatencyInfo(input_handler_.get(),
                                            gesture_scroll_end_));
}

class InputHandlerProxyTouchScrollbarTest : public InputHandlerProxyTest {
 public:
  void SetupEvents() {
    touch_start_ = WebTouchEvent(WebInputEvent::Type::kTouchStart,
                                 WebInputEvent::kNoModifiers,
                                 WebInputEvent::GetStaticTimeStampForTests());
    touch_end_ = WebTouchEvent(WebInputEvent::Type::kTouchEnd,
                               WebInputEvent::kNoModifiers,
                               WebInputEvent::GetStaticTimeStampForTests());
    touch_start_.touches_length = 1;
    touch_start_.touch_start_or_first_touch_move = true;
    touch_start_.touches[0] =
        CreateWebTouchPoint(WebTouchPoint::State::kStatePressed, 10, 10);

    touch_end_.touches_length = 1;
  }

 protected:
  WebTouchEvent touch_start_;
  WebTouchEvent touch_end_;
};

TEST_P(InputHandlerProxyTouchScrollbarTest,
       TouchOnScrollbarIsHandledByCompositorThread) {
  // The touch event hits a touch event handler that is acked from the
  // compositor thread.
  SetupEvents();
  cc::InputHandlerPointerResult pointer_down_result;
  pointer_down_result.type = cc::PointerResultType::kScrollbarScroll;
  pointer_down_result.scroll_delta = gfx::Vector2dF(0, 1);
  cc::InputHandlerPointerResult pointer_up_result;
  pointer_up_result.type = cc::PointerResultType::kScrollbarScroll;

  EXPECT_CALL(mock_input_handler_,
              EventListenerTypeForTouchStartOrMoveAt(
                  testing::Property(&gfx::Point::x, testing::Eq(10)), _))
      .WillOnce(testing::Invoke([](const gfx::Point&,
                                   cc::TouchAction* touch_action) {
        *touch_action = cc::TouchAction::kAuto;
        return cc::InputHandler::TouchStartOrMoveEventListenerType::kNoHandler;
      }));
  EXPECT_CALL(
      mock_input_handler_,
      GetEventListenerProperties(cc::EventListenerClass::kTouchStartOrMove))
      .WillOnce(testing::Return(cc::EventListenerProperties::kNone));

  EXPECT_CALL(mock_client_, SetAllowedTouchAction(_))
      .WillOnce(testing::Return());

  EXPECT_CALL(mock_input_handler_, HitTest(_))
      .WillOnce(testing::Return(pointer_down_result.type));
  EXPECT_CALL(mock_input_handler_, MouseDown(_, _))
      .WillOnce(testing::Return(pointer_down_result));
  EXPECT_CALL(mock_input_handler_, SetIsHandlingTouchSequence(true));
  cc::InputHandlerScrollResult scroll_result_did_scroll;
  scroll_result_did_scroll.did_scroll = true;
  expected_disposition_ = InputHandlerProxy::DID_HANDLE;

  EXPECT_CALL(
      mock_input_handler_,
      RecordScrollBegin(ui::ScrollInputType::kScrollbar,
                        cc::ScrollBeginThreadState::kScrollingOnCompositor))
      .Times(1);
  EXPECT_CALL(mock_input_handler_, ScrollBegin(_, _))
      .WillOnce(testing::Return(kImplThreadScrollState));
  EXPECT_CALL(mock_input_handler_, ScrollUpdate(_, _))
      .WillRepeatedly(testing::Return(scroll_result_did_scroll));
  EXPECT_CALL(mock_input_handler_, MouseUp(_))
      .WillOnce(testing::Return(pointer_up_result));

  EXPECT_EQ(expected_disposition_,
            HandleInputEventAndFlushEventQueue(
                mock_input_handler_, input_handler_.get(), touch_start_));

  EXPECT_CALL(mock_input_handler_, ScrollEnd(true));
  EXPECT_CALL(mock_input_handler_, RecordScrollEnd(_)).Times(1);
  expected_disposition_ = InputHandlerProxy::DID_HANDLE;
  EXPECT_EQ(expected_disposition_,
            HandleInputEventAndFlushEventQueue(
                mock_input_handler_, input_handler_.get(), touch_end_));
}

const auto kTestCombinations = testing::Combine(
    testing::Values(ScrollerType::kRoot, ScrollerType::kChild),
    testing::Values(HandlerType::kNormal, HandlerType::kSynchronous));

const auto kSuffixGenerator =
    [](const testing::TestParamInfo<std::tuple<ScrollerType, HandlerType>>&
           info) {
      std::string name = std::get<1>(info.param) == HandlerType::kSynchronous
                             ? "Synchronous"
                             : "";
      name += std::get<0>(info.param) == ScrollerType::kRoot ? "Root" : "Child";
      return name;
    };

INSTANTIATE_TEST_SUITE_P(All,
                         InputHandlerProxyTest,
                         kTestCombinations,
                         kSuffixGenerator);

INSTANTIATE_TEST_SUITE_P(All,
                         InputHandlerProxyMainThreadScrollingReasonTest,
                         kTestCombinations,
                         kSuffixGenerator);

INSTANTIATE_TEST_SUITE_P(All,
                         InputHandlerProxyTouchScrollbarTest,
                         kTestCombinations,
                         kSuffixGenerator);

}  // namespace test
}  // namespace blink

"""


```