Response:
The user wants a summary of the provided C++ code snippet from a Chromium Blink engine file.

The file `window_performance_test.cc` seems to be a unit test file for performance-related functionalities in the Blink rendering engine, specifically focusing on `WindowPerformance`.

The tests likely cover scenarios involving user interactions (keyboard, mouse), page visibility changes, and how these interactions are measured and recorded for performance analysis (using UKM and UMA).

The user wants a summary of the code's functionality, explanation of its relation to web technologies (JavaScript, HTML, CSS), examples of input/output, common usage errors, debugging steps to reach this code, and a general summary.

Here's a breakdown of how to approach each request:

1. **Functionality:** Analyze each `TEST_F` block to understand what it's testing. Look for the sequence of events simulated (e.g., keydown/keyup, pointerdown/pointerup/click), the calls to `Register...Event`, `SimulatePaintAndResolvePresentationPromise`, and the assertions made using `EXPECT_EQ` and `GetUkmRecorder()->ExpectEntryMetric`.

2. **Relation to JavaScript, HTML, CSS:**  Connect the tested events to user actions in a web browser. Keyboard and pointer events directly correspond to user interactions with HTML elements. The timing aspects relate to how quickly the browser responds to these interactions and updates the rendered HTML and CSS.

3. **Input/Output Examples:** Choose a few simple test cases (e.g., `PressSingleKey`) and trace the simulated timestamps. The input would be the sequence of simulated events and their timestamps. The output would be the recorded UKM metrics (max and total event durations) and potentially UMA histograms.

4. **Common Usage Errors:** Since this is a testing file, common "user" errors are less relevant. Instead, focus on potential errors in the *test setup* or assumptions being made in the tests (e.g., incorrect timestamp order, missing event registrations).

5. **User Operation to Reach Here (Debugging):** Think about the chain of events that leads to this code being executed. A user interacts with a webpage (e.g., types in a text field), which triggers events. The browser processes these events, and performance metrics are collected. During development or debugging, engineers might use breakpoints or logging within the event handling code that eventually calls the code being tested here.

6. **Summary of Functionality:** Combine the observations from analyzing the individual test cases to provide a concise overview of the file's purpose.
这是对 `blink/renderer/core/timing/window_performance_test.cc` 文件代码片段的第二部分的功能归纳。

**功能归纳:**

这部分代码主要包含了一系列针对 `WindowPerformance` 类的单元测试，用于验证其在不同用户交互场景下，记录和上报性能指标（通过 UKM 和 UMA）的正确性。  这些测试覆盖了以下几种用户交互类型：

*   **键盘事件 (Keyboard Events):**
    *   测试单个按键按下和释放的场景 (`PressSingleKey`)。
    *   测试连续按下多个按键的场景 (`PressMultipleKeys`)，并验证 UKM 记录是否正确聚合了交互时长。
    *   测试 `keydown` 和 `keyup` 事件处理完成顺序与回调执行顺序不一致的情况 (`KeyupFinishLastButCallbackInvokedFirst`)，模拟了多进程和线程带来的复杂性，并验证了性能指标记录的准确性。

*   **触摸或点击事件 (TapOrClick Events):**
    *   测试完整的 `pointerdown` -> `pointerup` -> `click` 事件序列，验证 UKM 和 UMA 中 `TapOrClick` 交互类型的记录。

*   **页面可见性变化 (Page Visibility Change):**
    *   测试在触摸事件序列中，页面可见性发生变化时，如何影响性能指标的计算和记录，特别是最大事件时长和总事件时长。

*   **拖拽事件 (Drag Events):**
    *   测试通过 `NotifyPotentialDrag` 标记潜在拖拽操作后，事件序列（`pointerdown` -> `pointerup` -> `click`）被归类为 `Drag` 交互类型，并正确记录 UKM 和 UMA。

*   **滚动事件 (Scroll Events):**
    *   测试 `pointerdown` 后立即 `pointercancel` 的情况，验证这类非完整交互不会被记录到 UKM 和 UMA 中。

*   **无点击的触摸事件 (Touches Without Click):**
    *   测试连续的 `pointerdown` 事件，没有后续的 `pointerup` 或 `click`，验证这类非完整交互不会被记录到 UKM 中。

*   **人工合成的指针抬起或点击事件 (Artificial PointerupOrClick - 仅限 macOS):**
    *   针对 macOS 平台，测试人工合成的 `pointerup` 和 `click` 事件，这些事件的发生时间戳可能与 `pointerdown` 相同，验证在这种特殊情况下，性能指标记录是否使用了 `processingEnd` 作为事件结束时间。

*   **性能标记跟踪事件 (Performance Mark Trace Event):**
    *   测试 `performance.mark()` JavaScript API 的调用，验证是否正确生成了 "test\_trace" 的跟踪事件，并包含了必要的元数据，如开始时间和 navigationId。

*   **元素时间跟踪事件 (Element Timing Trace Event):**
    *   测试 `AddElementTiming` 方法，验证是否正确生成了 "PerformanceElementTiming" 的跟踪事件，并包含了元素加载和渲染时间、尺寸、ID、URL 等信息。

*   **事件时间跟踪事件 (Event Timing Trace Events):**
    *   测试多个连续发生的事件（`pointerdown`, `pointerup`, `click`），验证是否生成了 "EventTiming" 的跟踪事件，并包含了交互 ID、事件类型、节点 ID 等信息。

*   **慢交互到下次绘制跟踪事件 (Slow Interaction To Next Paint Trace Events):**
    *   测试一系列键盘事件，包含快速的和耗时较长的，验证只有耗时较长的交互才会被记录为 "InteractionToNextPaint" 相关的跟踪事件。

**总而言之，这部分代码主要专注于验证 `WindowPerformance` 类在处理各种用户交互时，能够准确地记录和上报关键的性能指标，并通过 UKM 和 UMA 进行统计分析，为浏览器性能优化提供数据支持。**

### 提示词
```
这是目录为blink/renderer/core/timing/window_performance_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
tamp(2);
  processing_start_keydown = GetTimeStamp(3);
  processing_end_keydown = GetTimeStamp(5);
  presentation_time_keydown = GetTimeStamp(9);
  RegisterKeyboardEvent(event_type_names::kKeydown, keydown_timestamp,
                        processing_start_keydown, processing_end_keydown,
                        key_code);
  SimulatePaintAndResolvePresentationPromise(presentation_time_keydown);

  // Keyup
  base::TimeTicks keyup_timestamp = GetTimeStamp(3);
  base::TimeTicks processing_start_keyup = GetTimeStamp(5);
  base::TimeTicks processing_end_keyup = GetTimeStamp(6);
  base::TimeTicks presentation_time_keyup = GetTimeStamp(13);
  RegisterKeyboardEvent(event_type_names::kKeyup, keyup_timestamp,
                        processing_start_keyup, processing_end_keyup, key_code);
  SimulatePaintAndResolvePresentationPromise(presentation_time_keyup);

  // Flush UKM logging mojo request.
  RunPendingTasks();

  // Check UKM recording.
  entries = GetUkmRecorder()->GetEntriesByName(
      ukm::builders::Responsiveness_UserInteraction::kEntryName);
  EXPECT_EQ(3u, entries.size());
  std::vector<std::pair<int, int>> expected_durations;
  expected_durations.emplace_back(std::make_pair(5, 5));
  expected_durations.emplace_back(std::make_pair(6, 6));
  expected_durations.emplace_back(std::make_pair(10, 11));
  for (std::size_t i = 0; i < entries.size(); ++i) {
    auto* entry = entries[i].get();
    GetUkmRecorder()->ExpectEntryMetric(
        entry,
        ukm::builders::Responsiveness_UserInteraction::kMaxEventDurationName,
        expected_durations[i].first);
    GetUkmRecorder()->ExpectEntryMetric(
        entry,
        ukm::builders::Responsiveness_UserInteraction::kTotalEventDurationName,
        expected_durations[i].second);
    GetUkmRecorder()->ExpectEntryMetric(
        entry,
        ukm::builders::Responsiveness_UserInteraction::kInteractionTypeName, 0);
  }

  // Check UMA recording.
  GetHistogramTester().ExpectTotalCount(
      "Blink.Responsiveness.UserInteraction.MaxEventDuration.AllTypes", 3);
  GetHistogramTester().ExpectTotalCount(
      "Blink.Responsiveness.UserInteraction.MaxEventDuration.Keyboard", 3);
  GetHistogramTester().ExpectTotalCount(
      "Blink.Responsiveness.UserInteraction.MaxEventDuration.TapOrClick", 0);
  GetHistogramTester().ExpectTotalCount(
      "Blink.Responsiveness.UserInteraction.MaxEventDuration.Drag", 0);
}

TEST_F(WindowPerformanceTest, PressMultipleKeys) {
  auto entries = GetUkmRecorder()->GetEntriesByName(
      ukm::builders::Responsiveness_UserInteraction::kEntryName);
  EXPECT_EQ(0u, entries.size());
  // Press the first key.
  base::TimeTicks keydown_timestamp = GetTimeOrigin();
  base::TimeTicks processing_start_keydown = GetTimeStamp(1);
  base::TimeTicks processing_end_keydown = GetTimeStamp(2);
  base::TimeTicks presentation_time_keydown = GetTimeStamp(5);
  int first_key_code = 2;
  RegisterKeyboardEvent(event_type_names::kKeydown, keydown_timestamp,
                        processing_start_keydown, processing_end_keydown,
                        first_key_code);
  SimulatePaintAndResolvePresentationPromise(presentation_time_keydown);

  // Press the second key.
  processing_start_keydown = GetTimeStamp(2);
  processing_end_keydown = GetTimeStamp(3);
  presentation_time_keydown = GetTimeStamp(7);
  int second_key_code = 4;
  RegisterKeyboardEvent(event_type_names::kKeydown, keydown_timestamp,
                        processing_start_keydown, processing_end_keydown,
                        second_key_code);
  SimulatePaintAndResolvePresentationPromise(presentation_time_keydown);

  // Release the first key.
  base::TimeTicks keyup_timestamp = GetTimeStamp(3);
  base::TimeTicks processing_start_keyup = GetTimeStamp(5);
  base::TimeTicks processing_end_keyup = GetTimeStamp(6);
  base::TimeTicks presentation_time_keyup = GetTimeStamp(13);
  RegisterKeyboardEvent(event_type_names::kKeyup, keyup_timestamp,
                        processing_start_keyup, processing_end_keyup,
                        first_key_code);
  SimulatePaintAndResolvePresentationPromise(presentation_time_keyup);

  // Release the second key.
  keyup_timestamp = GetTimeStamp(5);
  processing_start_keyup = GetTimeStamp(5);
  processing_end_keyup = GetTimeStamp(6);
  presentation_time_keyup = GetTimeStamp(20);
  RegisterKeyboardEvent(event_type_names::kKeyup, keyup_timestamp,
                        processing_start_keyup, processing_end_keyup,
                        second_key_code);
  SimulatePaintAndResolvePresentationPromise(presentation_time_keyup);

  // Flush UKM logging mojo request.
  RunPendingTasks();

  // Check UKM recording.
  entries = GetUkmRecorder()->GetEntriesByName(
      ukm::builders::Responsiveness_UserInteraction::kEntryName);
  EXPECT_EQ(2u, entries.size());
  std::vector<std::pair<int, int>> expected_durations;
  expected_durations.emplace_back(std::make_pair(10, 13));
  expected_durations.emplace_back(std::make_pair(15, 20));
  for (std::size_t i = 0; i < entries.size(); ++i) {
    auto* entry = entries[i].get();
    GetUkmRecorder()->ExpectEntryMetric(
        entry,
        ukm::builders::Responsiveness_UserInteraction::kMaxEventDurationName,
        expected_durations[i].first);
    GetUkmRecorder()->ExpectEntryMetric(
        entry,
        ukm::builders::Responsiveness_UserInteraction::kTotalEventDurationName,
        expected_durations[i].second);
    GetUkmRecorder()->ExpectEntryMetric(
        entry,
        ukm::builders::Responsiveness_UserInteraction::kInteractionTypeName, 0);
  }
}

// Test a real world scenario, where keydown got presented first but its
// callback got invoked later than keyup's due to multi processes & threading
// overhead.
TEST_F(WindowPerformanceTest, KeyupFinishLastButCallbackInvokedFirst) {
  // Arbitrary keycode picked for testing from
  // https://developer.mozilla.org/en-US/docs/Web/API/KeyboardEvent/keyCode#value_of_keycode
  int digit_1_key_code = 0x31;

  // Keydown
  base::TimeTicks keydown_timestamp = GetTimeStamp(0);
  base::TimeTicks processing_start_keydown = GetTimeStamp(1);
  base::TimeTicks processing_end_keydown = GetTimeStamp(5);
  base::TimeTicks presentation_time_keydown = GetTimeStamp(7);
  const uint64_t presentation_index_keydown = RegisterKeyboardEvent(
      event_type_names::kKeydown, keydown_timestamp, processing_start_keydown,
      processing_end_keydown, digit_1_key_code);

  SimulatePaint();

  // Keyup
  base::TimeTicks keyup_timestamp = GetTimeStamp(3);
  base::TimeTicks processing_start_keyup = GetTimeStamp(6);
  base::TimeTicks processing_end_keyup = GetTimeStamp(7);
  base::TimeTicks presentation_promise_break_time_keyup = GetTimeStamp(8);
  const uint64_t presentation_index_keyup = RegisterKeyboardEvent(
      event_type_names::kKeyup, keyup_timestamp, processing_start_keyup,
      processing_end_keyup, digit_1_key_code);

  // keyup resolved without a paint, due to no damage.
  SimulateResolvePresentationPromise(presentation_index_keyup,
                                     presentation_promise_break_time_keyup);
  SimulateResolvePresentationPromise(presentation_index_keydown,
                                     presentation_time_keydown);

  // Flush UKM logging mojo request.
  RunPendingTasks();

  // Check UKM recording.
  auto entries = GetUkmRecorder()->GetEntriesByName(
      ukm::builders::Responsiveness_UserInteraction::kEntryName);
  EXPECT_EQ(1u, entries.size());
  const ukm::mojom::UkmEntry* ukm_entry = entries[0];
  GetUkmRecorder()->ExpectEntryMetric(
      ukm_entry,
      ukm::builders::Responsiveness_UserInteraction::kMaxEventDurationName, 7);
  GetUkmRecorder()->ExpectEntryMetric(
      ukm_entry,
      ukm::builders::Responsiveness_UserInteraction::kTotalEventDurationName,
      8);
  GetUkmRecorder()->ExpectEntryMetric(
      ukm_entry,
      ukm::builders::Responsiveness_UserInteraction::kInteractionTypeName, 0);

  // Check UMA recording.
  GetHistogramTester().ExpectTotalCount(
      "Blink.Responsiveness.UserInteraction.MaxEventDuration.AllTypes", 1);
  GetHistogramTester().ExpectTotalCount(
      "Blink.Responsiveness.UserInteraction.MaxEventDuration.Keyboard", 1);
  GetHistogramTester().ExpectTotalCount(
      "Blink.Responsiveness.UserInteraction.MaxEventDuration.TapOrClick", 0);
  GetHistogramTester().ExpectTotalCount(
      "Blink.Responsiveness.UserInteraction.MaxEventDuration.Drag", 0);
}

TEST_F(WindowPerformanceTest, TapOrClick) {
  // Pointerdown
  base::TimeTicks pointerdown_timestamp = GetTimeOrigin();
  base::TimeTicks processing_start_pointerdown = GetTimeStamp(1);
  base::TimeTicks processing_end_pointerdown = GetTimeStamp(2);
  base::TimeTicks presentation_time_pointerdown = GetTimeStamp(5);
  PointerId pointer_id = 4;
  RegisterPointerEvent(event_type_names::kPointerdown, pointerdown_timestamp,
                       processing_start_pointerdown, processing_end_pointerdown,
                       pointer_id);
  SimulatePaintAndResolvePresentationPromise(presentation_time_pointerdown);
  // Pointerup
  base::TimeTicks pointerup_timestamp = GetTimeStamp(3);
  base::TimeTicks processing_start_pointerup = GetTimeStamp(5);
  base::TimeTicks processing_end_pointerup = GetTimeStamp(6);
  base::TimeTicks presentation_time_pointerup = GetTimeStamp(10);
  RegisterPointerEvent(event_type_names::kPointerup, pointerup_timestamp,
                       processing_start_pointerup, processing_end_pointerup,
                       pointer_id);
  SimulatePaintAndResolvePresentationPromise(presentation_time_pointerup);
  // Click
  base::TimeTicks click_timestamp = GetTimeStamp(13);
  base::TimeTicks processing_start_click = GetTimeStamp(15);
  base::TimeTicks processing_end_click = GetTimeStamp(16);
  base::TimeTicks presentation_time_click = GetTimeStamp(20);
  RegisterPointerEvent(event_type_names::kClick, click_timestamp,
                       processing_start_click, processing_end_click,
                       pointer_id);
  SimulatePaintAndResolvePresentationPromise(presentation_time_click);

  // Flush UKM logging mojo request.
  RunPendingTasks();

  // Check UKM recording.
  auto entries = GetUkmRecorder()->GetEntriesByName(
      ukm::builders::Responsiveness_UserInteraction::kEntryName);
  EXPECT_EQ(1u, entries.size());
  const ukm::mojom::UkmEntry* ukm_entry = entries[0];
  GetUkmRecorder()->ExpectEntryMetric(
      ukm_entry,
      ukm::builders::Responsiveness_UserInteraction::kMaxEventDurationName, 7);
  GetUkmRecorder()->ExpectEntryMetric(
      ukm_entry,
      ukm::builders::Responsiveness_UserInteraction::kTotalEventDurationName,
      17);
  GetUkmRecorder()->ExpectEntryMetric(
      ukm_entry,
      ukm::builders::Responsiveness_UserInteraction::kInteractionTypeName, 1);

  // Check UMA recording.
  GetHistogramTester().ExpectTotalCount(
      "Blink.Responsiveness.UserInteraction.MaxEventDuration.AllTypes", 1);
  GetHistogramTester().ExpectTotalCount(
      "Blink.Responsiveness.UserInteraction.MaxEventDuration.Keyboard", 0);
  GetHistogramTester().ExpectTotalCount(
      "Blink.Responsiveness.UserInteraction.MaxEventDuration.TapOrClick", 1);
  GetHistogramTester().ExpectTotalCount(
      "Blink.Responsiveness.UserInteraction.MaxEventDuration.Drag", 0);
}

TEST_F(WindowPerformanceTest, PageVisibilityChanged) {
  // Pointerdown
  base::TimeTicks pointerdown_timestamp = GetTimeOrigin();
  base::TimeTicks processing_start_pointerdown = GetTimeStamp(1);
  base::TimeTicks processing_end_pointerdown = GetTimeStamp(2);
  base::TimeTicks presentation_time_pointerdown = GetTimeStamp(5);
  PointerId pointer_id = 4;
  RegisterPointerEvent(event_type_names::kPointerdown, pointerdown_timestamp,
                       processing_start_pointerdown, processing_end_pointerdown,
                       pointer_id);
  SimulatePaintAndResolvePresentationPromise(presentation_time_pointerdown);

  // Pointerup
  base::TimeTicks pointerup_timestamp = GetTimeStamp(3);
  base::TimeTicks processing_start_pointerup = GetTimeStamp(5);
  base::TimeTicks processing_end_pointerup = GetTimeStamp(6);
  RegisterPointerEvent(event_type_names::kPointerup, pointerup_timestamp,
                       processing_start_pointerup, processing_end_pointerup,
                       pointer_id);
  // Click
  base::TimeTicks click_timestamp = GetTimeStamp(13);
  base::TimeTicks processing_start_click = GetTimeStamp(15);
  base::TimeTicks processing_end_click = GetTimeStamp(16);
  base::TimeTicks presentation_time_pointerup_and_click = GetTimeStamp(20);
  RegisterPointerEvent(event_type_names::kClick, click_timestamp,
                       processing_start_click, processing_end_click,
                       pointer_id);

  performance_->GetPage()->SetVisibilityState(
      mojom::blink::PageVisibilityState::kHidden, true);
  PageVisibilityChanged(GetTimeStamp(18));

  SimulatePaintAndResolvePresentationPromise(
      presentation_time_pointerup_and_click);

  // Flush UKM logging mojo request.
  RunPendingTasks();

  // Check UKM recording.
  auto entries = GetUkmRecorder()->GetEntriesByName(
      ukm::builders::Responsiveness_UserInteraction::kEntryName);
  EXPECT_EQ(1u, entries.size());
  const ukm::mojom::UkmEntry* ukm_entry = entries[0];
  // The event duration of pointerdown is 5ms, all the way to presentation.
  // The event duration of pointerup is processingEnd 6 - event
  // creation time 3 = 3.
  // The event duration of click is page visibility change time 16 - 13 = 3.
  // So the max duration should be 5 ms.
  GetUkmRecorder()->ExpectEntryMetric(
      ukm_entry,
      ukm::builders::Responsiveness_UserInteraction::kMaxEventDurationName, 5);
  // The total duration should be 9ms, which is the sum of time from time 0 of
  // pointer down creation time to the processingEnd of pointer up 6ms +
  // duration of click which is 16-13 = 3ms.
  GetUkmRecorder()->ExpectEntryMetric(
      ukm_entry,
      ukm::builders::Responsiveness_UserInteraction::kTotalEventDurationName,
      9);
  GetUkmRecorder()->ExpectEntryMetric(
      ukm_entry,
      ukm::builders::Responsiveness_UserInteraction::kInteractionTypeName, 1);

  EXPECT_EQ(1ul, performance_->interactionCount());
}

TEST_F(WindowPerformanceTest, Drag) {
  // Pointerdown
  base::TimeTicks pointerdwon_timestamp = GetTimeOrigin();
  base::TimeTicks processing_start_pointerdown = GetTimeStamp(1);
  base::TimeTicks processing_end_pointerdown = GetTimeStamp(2);
  base::TimeTicks presentation_time_pointerdown = GetTimeStamp(5);
  PointerId pointer_id = 4;
  RegisterPointerEvent(event_type_names::kPointerdown, pointerdwon_timestamp,
                       processing_start_pointerdown, processing_end_pointerdown,
                       pointer_id);
  SimulatePaintAndResolvePresentationPromise(presentation_time_pointerdown);
  // Notify drag.
  performance_->NotifyPotentialDrag(pointer_id);
  // Pointerup
  base::TimeTicks pointerup_timestamp = GetTimeStamp(3);
  base::TimeTicks processing_start_pointerup = GetTimeStamp(5);
  base::TimeTicks processing_end_pointerup = GetTimeStamp(6);
  base::TimeTicks presentation_time_pointerup = GetTimeStamp(10);
  RegisterPointerEvent(event_type_names::kPointerup, pointerup_timestamp,
                       processing_start_pointerup, processing_end_pointerup,
                       pointer_id);
  SimulatePaintAndResolvePresentationPromise(presentation_time_pointerup);
  // Click
  base::TimeTicks click_timestamp = GetTimeStamp(13);
  base::TimeTicks processing_start_click = GetTimeStamp(15);
  base::TimeTicks processing_end_click = GetTimeStamp(16);
  base::TimeTicks presentation_time_click = GetTimeStamp(20);
  RegisterPointerEvent(event_type_names::kClick, click_timestamp,
                       processing_start_click, processing_end_click,
                       pointer_id);
  SimulatePaintAndResolvePresentationPromise(presentation_time_click);

  // Flush UKM logging mojo request.
  RunPendingTasks();

  // Check UKM recording.
  auto entries = GetUkmRecorder()->GetEntriesByName(
      ukm::builders::Responsiveness_UserInteraction::kEntryName);
  EXPECT_EQ(1u, entries.size());
  const ukm::mojom::UkmEntry* ukm_entry = entries[0];
  GetUkmRecorder()->ExpectEntryMetric(
      ukm_entry,
      ukm::builders::Responsiveness_UserInteraction::kMaxEventDurationName, 7);
  GetUkmRecorder()->ExpectEntryMetric(
      ukm_entry,
      ukm::builders::Responsiveness_UserInteraction::kTotalEventDurationName,
      17);
  GetUkmRecorder()->ExpectEntryMetric(
      ukm_entry,
      ukm::builders::Responsiveness_UserInteraction::kInteractionTypeName, 2);

  // Check UMA recording.
  GetHistogramTester().ExpectTotalCount(
      "Blink.Responsiveness.UserInteraction.MaxEventDuration.AllTypes", 1);
  GetHistogramTester().ExpectTotalCount(
      "Blink.Responsiveness.UserInteraction.MaxEventDuration.Keyboard", 0);
  GetHistogramTester().ExpectTotalCount(
      "Blink.Responsiveness.UserInteraction.MaxEventDuration.TapOrClick", 0);
  GetHistogramTester().ExpectTotalCount(
      "Blink.Responsiveness.UserInteraction.MaxEventDuration.Drag", 1);
}

TEST_F(WindowPerformanceTest, Scroll) {
  // Pointerdown
  base::TimeTicks pointerdown_timestamp = GetTimeOrigin();
  base::TimeTicks processing_start_keydown = GetTimeStamp(1);
  base::TimeTicks processing_end_keydown = GetTimeStamp(2);
  base::TimeTicks presentation_time_keydown = GetTimeStamp(5);
  PointerId pointer_id = 5;
  RegisterPointerEvent(event_type_names::kPointerdown, pointerdown_timestamp,
                       processing_start_keydown, processing_end_keydown,
                       pointer_id);
  SimulatePaintAndResolvePresentationPromise(presentation_time_keydown);
  // Pointercancel
  base::TimeTicks pointerup_timestamp = GetTimeStamp(3);
  base::TimeTicks processing_start_keyup = GetTimeStamp(5);
  base::TimeTicks processing_end_keyup = GetTimeStamp(6);
  base::TimeTicks presentation_time_keyup = GetTimeStamp(10);
  RegisterPointerEvent(event_type_names::kPointercancel, pointerup_timestamp,
                       processing_start_keyup, processing_end_keyup,
                       pointer_id);
  SimulatePaintAndResolvePresentationPromise(presentation_time_keyup);

  // Flush UKM logging mojo request.
  RunPendingTasks();

  // Check UKM recording.
  auto entries = GetUkmRecorder()->GetEntriesByName(
      ukm::builders::Responsiveness_UserInteraction::kEntryName);
  EXPECT_EQ(0u, entries.size());

  // Check UMA recording.
  GetHistogramTester().ExpectTotalCount(
      "Blink.Responsiveness.UserInteraction.MaxEventDuration.AllTypes", 0);
  GetHistogramTester().ExpectTotalCount(
      "Blink.Responsiveness.UserInteraction.MaxEventDuration.Keyboard", 0);
  GetHistogramTester().ExpectTotalCount(
      "Blink.Responsiveness.UserInteraction.MaxEventDuration.TapOrClick", 0);
  GetHistogramTester().ExpectTotalCount(
      "Blink.Responsiveness.UserInteraction.MaxEventDuration.Drag", 0);
}

TEST_F(WindowPerformanceTest, TouchesWithoutClick) {
  base::TimeTicks pointerdown_timestamp = GetTimeOrigin();
  // First Pointerdown
  base::TimeTicks processing_start_pointerdown = GetTimeStamp(1);
  base::TimeTicks processing_end_pointerdown = GetTimeStamp(2);
  base::TimeTicks presentation_time_pointerdown = GetTimeStamp(5);
  PointerId pointer_id = 4;
  RegisterPointerEvent(event_type_names::kPointerdown, pointerdown_timestamp,
                       processing_start_pointerdown, processing_end_pointerdown,
                       pointer_id);
  SimulatePaintAndResolvePresentationPromise(presentation_time_pointerdown);

  // Second Pointerdown
  pointerdown_timestamp = GetTimeStamp(6);
  processing_start_pointerdown = GetTimeStamp(7);
  processing_end_pointerdown = GetTimeStamp(8);
  presentation_time_pointerdown = GetTimeStamp(15);
  RegisterPointerEvent(event_type_names::kPointerdown, pointerdown_timestamp,
                       processing_start_pointerdown, processing_end_pointerdown,
                       pointer_id);
  SimulatePaintAndResolvePresentationPromise(presentation_time_pointerdown);

  // Flush UKM logging mojo request.
  RunPendingTasks();

  // Check UKM recording.
  auto entries = GetUkmRecorder()->GetEntriesByName(
      ukm::builders::Responsiveness_UserInteraction::kEntryName);
  EXPECT_EQ(0u, entries.size());
}

#if BUILDFLAG(IS_MAC)
//  Test artificial pointerup and click on MacOS fall back to use processingEnd
//  as event duration ending time.
//  See crbug.com/1321819
TEST_F(WindowPerformanceTest, ArtificialPointerupOrClick) {
  // Arbitrary pointerId picked for testing
  PointerId pointer_id = 4;

  // Pointerdown
  base::TimeTicks pointerdown_timestamp = GetTimeOrigin();
  base::TimeTicks processing_start_pointerdown = GetTimeStamp(1);
  base::TimeTicks processing_end_pointerdown = GetTimeStamp(2);
  base::TimeTicks presentation_time_pointerdown = GetTimeStamp(3);
  RegisterPointerEvent(event_type_names::kPointerdown, pointerdown_timestamp,
                       processing_start_pointerdown, processing_end_pointerdown,
                       pointer_id);
  SimulatePaintAndResolvePresentationPromise(presentation_time_pointerdown);
  // Artificial Pointerup
  base::TimeTicks pointerup_timestamp = pointerdown_timestamp;
  base::TimeTicks processing_start_pointerup = GetTimeStamp(5);
  base::TimeTicks processing_end_pointerup = GetTimeStamp(6);
  base::TimeTicks presentation_time_pointerup = GetTimeStamp(10);
  RegisterPointerEvent(event_type_names::kPointerup, pointerup_timestamp,
                       processing_start_pointerup, processing_end_pointerup,
                       pointer_id);
  SimulatePaintAndResolvePresentationPromise(presentation_time_pointerup);
  // Artificial Click
  base::TimeTicks click_timestamp = pointerup_timestamp;
  base::TimeTicks processing_start_click = GetTimeStamp(11);
  base::TimeTicks processing_end_click = GetTimeStamp(12);
  base::TimeTicks presentation_time_click = GetTimeStamp(20);
  RegisterPointerEvent(event_type_names::kClick, click_timestamp,
                       processing_start_click, processing_end_click,
                       pointer_id);
  SimulatePaintAndResolvePresentationPromise(presentation_time_click);

  // Flush UKM logging mojo request.
  RunPendingTasks();

  // Check UKM recording.
  auto entries = GetUkmRecorder()->GetEntriesByName(
      ukm::builders::Responsiveness_UserInteraction::kEntryName);
  EXPECT_EQ(1u, entries.size());
  const ukm::mojom::UkmEntry* ukm_entry = entries[0];
  GetUkmRecorder()->ExpectEntryMetric(
      ukm_entry,
      ukm::builders::Responsiveness_UserInteraction::kMaxEventDurationName, 12);
  GetUkmRecorder()->ExpectEntryMetric(
      ukm_entry,
      ukm::builders::Responsiveness_UserInteraction::kTotalEventDurationName,
      12);
  GetUkmRecorder()->ExpectEntryMetric(
      ukm_entry,
      ukm::builders::Responsiveness_UserInteraction::kInteractionTypeName, 1);

  // Check UMA recording.
  GetHistogramTester().ExpectTotalCount(
      "Blink.Responsiveness.UserInteraction.MaxEventDuration.AllTypes", 1);
  GetHistogramTester().ExpectTotalCount(
      "Blink.Responsiveness.UserInteraction.MaxEventDuration.Keyboard", 0);
  GetHistogramTester().ExpectTotalCount(
      "Blink.Responsiveness.UserInteraction.MaxEventDuration.TapOrClick", 1);
  GetHistogramTester().ExpectTotalCount(
      "Blink.Responsiveness.UserInteraction.MaxEventDuration.Drag", 0);
}
#endif  // BUILDFLAG(IS_MAC)

// The trace_analyzer does not work on platforms on which the migration of
// tracing into Perfetto has not completed.
TEST_F(WindowPerformanceTest, PerformanceMarkTraceEvent) {
  v8::HandleScope handle_scope(GetScriptState()->GetIsolate());
  v8::Local<v8::Context> context = GetScriptState()->GetContext();
  v8::Context::Scope context_scope(context);
  DummyExceptionStateForTesting exception_state;

  using trace_analyzer::Query;
  trace_analyzer::Start("*");

  performance_->mark(GetScriptState(), AtomicString("test_trace"), nullptr,
                     exception_state);

  auto analyzer = trace_analyzer::Stop();

  trace_analyzer::TraceEventVector events;

  Query q = Query::EventNameIs("test_trace");
  analyzer->FindEvents(q, &events);
  EXPECT_EQ(1u, events.size());

  EXPECT_EQ("blink.user_timing", events[0]->category);

  ASSERT_TRUE(events[0]->HasDictArg("data"));

  base::Value::Dict arg_dict = events[0]->GetKnownArgAsDict("data");

  std::optional<double> start_time = arg_dict.FindDouble("startTime");
  ASSERT_TRUE(start_time.has_value());

  // The navigationId should be recorded if performance.mark is executed by a
  // document.
  std::string* navigation_id = arg_dict.FindString("navigationId");
  ASSERT_TRUE(navigation_id);
}

TEST_F(WindowPerformanceTest, ElementTimingTraceEvent) {
  using trace_analyzer::Query;
  trace_analyzer::Start("*");
  // |element| needs to be non-null to prevent a crash.
  performance_->AddElementTiming(
      AtomicString("image-paint"), "url", gfx::RectF(10, 20, 30, 40),
      GetTimeStamp(2000), GetTimeStamp(1000), AtomicString("identifier"),
      gfx::Size(200, 300), AtomicString("id"),
      /*element*/ page_holder_->GetDocument().documentElement());
  auto analyzer = trace_analyzer::Stop();
  trace_analyzer::TraceEventVector events;
  Query q = Query::EventNameIs("PerformanceElementTiming");
  analyzer->FindEvents(q, &events);
  EXPECT_EQ(1u, events.size());
  EXPECT_EQ("loading", events[0]->category);
  EXPECT_TRUE(events[0]->HasStringArg("frame"));

  ASSERT_TRUE(events[0]->HasDictArg("data"));
  base::Value::Dict arg_dict = events[0]->GetKnownArgAsDict("data");
  std::string* element_type = arg_dict.FindString("elementType");
  ASSERT_TRUE(element_type);
  EXPECT_EQ(*element_type, "image-paint");
  EXPECT_EQ(arg_dict.FindInt("loadTime").value_or(-1), 1000);
  EXPECT_EQ(arg_dict.FindInt("renderTime").value_or(-1), 2000);
  EXPECT_EQ(arg_dict.FindDouble("rectLeft").value_or(-1), 10);
  EXPECT_EQ(arg_dict.FindDouble("rectTop").value_or(-1), 20);
  EXPECT_EQ(arg_dict.FindDouble("rectWidth").value_or(-1), 30);
  EXPECT_EQ(arg_dict.FindDouble("rectHeight").value_or(-1), 40);
  std::string* identifier = arg_dict.FindString("identifier");
  ASSERT_TRUE(identifier);
  EXPECT_EQ(*identifier, "identifier");
  EXPECT_EQ(arg_dict.FindInt("naturalWidth").value_or(-1), 200);
  EXPECT_EQ(arg_dict.FindInt("naturalHeight").value_or(-1), 300);
  std::string* element_id = arg_dict.FindString("elementId");
  ASSERT_TRUE(element_id);
  EXPECT_EQ(*element_id, "id");
  std::string* url = arg_dict.FindString("url");
  ASSERT_TRUE(url);
  EXPECT_EQ(*url, "url");
}

TEST_F(WindowPerformanceTest, EventTimingTraceEvents) {
  using trace_analyzer::Query;
  trace_analyzer::Start("*");
  base::TimeTicks start_time = GetTimeOrigin() + base::Seconds(1);
  base::TimeTicks processing_start = start_time + base::Milliseconds(5);
  base::TimeTicks processing_end = processing_start + base::Milliseconds(10);
  RegisterPointerEvent(event_type_names::kPointerdown, start_time,
                       processing_start, processing_end, 4,
                       GetWindow()->document());

  base::TimeTicks presentation_time = processing_end + base::Milliseconds(10);
  SimulatePaintAndResolvePresentationPromise(presentation_time);

  base::TimeTicks start_time2 = start_time + base::Milliseconds(100);
  base::TimeTicks processing_start2 = start_time2 + base::Milliseconds(5);
  base::TimeTicks processing_end2 = processing_start2 + base::Milliseconds(10);
  RegisterPointerEvent(event_type_names::kPointerup, start_time2,
                       processing_start2, processing_end2, 4,
                       GetWindow()->document());

  base::TimeTicks start_time3 = start_time2;
  base::TimeTicks processing_start3 = processing_end2;
  base::TimeTicks processing_end3 = processing_start3 + base::Milliseconds(10);
  RegisterPointerEvent(event_type_names::kClick, start_time3, processing_start3,
                       processing_end3, 4, GetWindow()->document());

  base::TimeTicks presentation_time2 = processing_end3 + base::Milliseconds(5);
  SimulatePaintAndResolvePresentationPromise(presentation_time2);

  // Only the longer event should have been reported.
  auto analyzer = trace_analyzer::Stop();
  analyzer->AssociateAsyncBeginEndEvents();
  trace_analyzer::TraceEventVector events;
  Query q = Query::EventNameIs("EventTiming") &&
            Query::EventPhaseIs(TRACE_EVENT_PHASE_NESTABLE_ASYNC_BEGIN);
  analyzer->FindEvents(q, &events);
  EXPECT_EQ(3u, events.size());
  for (int i = 0; i < 3; i++) {
    EXPECT_EQ("devtools.timeline", events[i]->category);
  }

  // Items in the trace events list is ordered chronologically, that is -- trace
  // event with smaller timestamp comes earlier.
  //
  // --Timestamps--
  // pointerdown_begin: 1000ms (pointerdown end: 1025ms)
  const trace_analyzer::TraceEvent* pointerdown_begin = events[0];
  // pointerup_begin: 1100ms (pointerup end: 1130ms)
  const trace_analyzer::TraceEvent* pointerup_begin = events[1];
  // click_begin: 1100ms (click end 1130ms)
  const trace_analyzer::TraceEvent* click_begin = events[2];

  // pointerdown
  ASSERT_TRUE(pointerdown_begin->HasDictArg("data"));
  base::Value::Dict arg_dict = pointerdown_begin->GetKnownArgAsDict("data");
  EXPECT_GT(arg_dict.FindInt("interactionId").value_or(-1), 0);
  std::string* event_name = arg_dict.FindString("type");
  ASSERT_TRUE(event_name);
  EXPECT_EQ(*event_name, "pointerdown");
  std::string* frame_trace_value = arg_dict.FindString("frame");
  EXPECT_EQ(String(*frame_trace_value), GetFrameIdForTracing(GetFrame()));
  EXPECT_EQ(arg_dict.FindInt("nodeId"),
            DOMNodeIds::IdForNode(GetWindow()->document()));
  ASSERT_TRUE(pointerdown_begin->has_other_event());
  EXPECT_EQ(base::ClampRound(pointerdown_begin->GetAbsTimeToOtherEvent()),
            25000);
  EXPECT_FALSE(pointerdown_begin->other_event->HasDictArg("data"));

  // pointerup
  ASSERT_TRUE(pointerup_begin->HasDictArg("data"));
  arg_dict = pointerup_begin->GetKnownArgAsDict("data");
  EXPECT_GT(arg_dict.FindInt("interactionId").value_or(-1), 0);
  event_name = arg_dict.FindString("type");
  ASSERT_TRUE(event_name);
  EXPECT_EQ(*event_name, "pointerup");
  frame_trace_value = arg_dict.FindString("frame");
  EXPECT_EQ(String(*frame_trace_value), GetFrameIdForTracing(GetFrame()));
  EXPECT_EQ(arg_dict.FindInt("nodeId"),
            DOMNodeIds::IdForNode(GetWindow()->document()));
  ASSERT_TRUE(pointerup_begin->has_other_event());
  EXPECT_EQ(base::ClampRound(pointerup_begin->GetAbsTimeToOtherEvent()), 30000);
  EXPECT_FALSE(pointerup_begin->other_event->HasDictArg("data"));

  // click
  ASSERT_TRUE(click_begin->HasDictArg("data"));
  arg_dict = click_begin->GetKnownArgAsDict("data");
  EXPECT_GT(arg_dict.FindInt("interactionId").value_or(-1), 0);
  event_name = arg_dict.FindString("type");
  ASSERT_TRUE(event_name);
  EXPECT_EQ(*event_name, "click");
  frame_trace_value = arg_dict.FindString("frame");
  EXPECT_EQ(String(*frame_trace_value), GetFrameIdForTracing(GetFrame()));
  EXPECT_EQ(arg_dict.FindInt("nodeId"),
            DOMNodeIds::IdForNode(GetWindow()->document()));
  ASSERT_TRUE(click_begin->has_other_event());
  EXPECT_EQ(base::ClampRound(click_begin->GetAbsTimeToOtherEvent()), 30000);
  EXPECT_FALSE(click_begin->other_event->HasDictArg("data"));
}

TEST_F(WindowPerformanceTest, SlowInteractionToNextPaintTraceEvents) {
  using trace_analyzer::Query;
  trace_analyzer::Start("*");

  constexpr int kKeyCode = 2;

  // Short, untraced keyboard event.
  {
    // Keydown.
    base::TimeTicks keydown_timestamp = GetTimeStamp(0);
    base::TimeTicks processing_start_keydown = GetTimeStamp(1);
    base::TimeTicks processing_end_keydown = GetTimeStamp(2);
    base::TimeTicks presentation_time_keydown = GetTimeStamp(20);
    RegisterKeyboardEvent(event_type_names::kKeydown, keydown_timestamp,
                          processing_start_keydown, processing_end_keydown,
                          kKeyCode);
    SimulatePaintAndResolvePresentationPromise(presentation_time_keydown);

    // Keyup.
    base::TimeTicks keyup_timestamp = GetTimeStamp(10);
    base::TimeTicks processing_start_keyup = GetTimeStamp(15);
    base::TimeTicks processing_end_keyup = GetTimeStamp(50);
    base::TimeTicks presentation_time_keyup = GetTimeStamp(110);
    RegisterKeyboardEvent(event_type_names::kKeyup, keyup_timestamp,
                          processing_start_keyup, processing_end_keyup,
                          kKeyCode);
    SimulatePaintAndResolvePresentationPromise(presentation_time_keyup);
  }

  // Single long event.
  {
    // Keydown (quick).
    base::TimeTicks keydown_timestamp = GetTimeStamp(200);
    base::TimeTicks processing_start_keydown = GetTimeStamp(201);
    base::TimeTicks processing_end_keydown = GetTimeStamp(202);
    base::TimeTicks pre
```