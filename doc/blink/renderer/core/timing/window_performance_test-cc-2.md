Response:
The user wants a summary of the provided C++ code, which is a test file for the `WindowPerformance` class in the Chromium Blink engine. I need to identify the main functionalities being tested and how they relate to web technologies like JavaScript, HTML, and CSS. I also need to analyze the test cases for any logical assumptions, potential user errors, and debugging information. Finally, I need to synthesize this information into a concise summary.

Here's a breakdown of the content:

1. **SlowInteractionToNextPaint Test:** This test verifies the calculation of the time difference between a user interaction (like keyboard or mouse events) and the next paint operation. It uses trace events to analyze the timing.

2. **InteractionID Test:** This test focuses on assigning and tracking interaction IDs for various user interactions (keyboard input, clicks, drags). It checks if related events receive the same ID and logs these interactions to UKM (User Key Metrics).

3. **InteractionIdTest Class:** This is a test fixture providing helper methods to simulate sequences of events and check the resulting interaction IDs and UKM logs.

4. **Various InteractionId Test Cases:**  These test different scenarios:
    *   Typing (English and Japanese/Chinese input methods)
    *   Handling composition events during text input
    *   Smart suggestions on Android
    *   Tap and click interactions (with and without explicit click events)
    *   Multi-touch interactions
    *   Cases with incorrect pointer IDs.
这是 `blink/renderer/core/timing/window_performance_test.cc` 文件的第三部分，主要功能是**测试用户交互的 Interaction ID 的生成和 UKM (User Key Metrics) 日志记录功能**。

**功能归纳：**

本部分主要测试了 `PerformanceEventTiming` 类中关于用户交互 ID (`interactionId`) 的生成和关联，以及将这些交互数据记录到 UKM 的功能。它涵盖了各种用户输入场景，包括：

*   **键盘输入:** 测试了英文输入、日文/中文输入法下的组合输入（包括 `compositionstart`, `compositionupdate`, `compositionend` 事件），以及 Android 智能提示的情况。
*   **触摸/鼠标事件:** 测试了单击、双击、拖拽等手势操作，以及多点触控的情况。
*   **特殊情况:** 测试了没有 `click` 事件的 `tap` 操作，以及 `click` 事件的 `pointerId` 不正确的情况。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

这些测试直接关联到用户在网页上的交互行为，这些行为通常会触发 JavaScript 事件，并可能导致 HTML 结构的改变和 CSS 样式的更新。

*   **JavaScript 事件:** 测试中模拟的 `keydown`, `keyup`, `input`, `click`, `pointerdown`, `pointerup`, `pointercancel`, `compositionstart`, `compositionupdate`, `compositionend` 等都是 JavaScript 中常见的事件类型。
    *   **举例:**  用户在文本框中输入 "a"，会触发 `keydown` (按下 'a' 键), `input` (文本框内容发生变化), `keyup` (释放 'a' 键) 等事件。这些事件的时间戳和类型会被 `PerformanceEventTiming` 记录下来并用于生成 `interactionId`。
*   **HTML 结构:** 用户交互可能导致 DOM 元素的增删改。例如，输入文本会在文本框中插入字符，点击按钮可能会显示或隐藏某些元素。虽然测试本身不直接操作 HTML，但它模拟的事件和时间与浏览器处理 HTML 更新息息相关。
*   **CSS 样式:**  用户交互可能触发 CSS 伪类（如 `:hover`, `:active`）或 JavaScript 动态修改样式。测试中测量的 "SlowInteractionToNextPaint" 关注的就是交互到页面视觉更新的时间，这与 CSS 的渲染密切相关。

**逻辑推理、假设输入与输出：**

以下是一些测试用例的逻辑推理和假设输入输出示例：

*   **假设输入:**  用户依次按下并释放 'A' 键。
    *   `keydown` 事件时间戳：100
    *   `input` 事件时间戳：120
    *   `keyup` 事件时间戳：130
    *   `keydown` 和 `keyup` 的 presentationTimestamp: 150
*   **逻辑推理:**  `keydown` 和 `keyup` 是同一个用户交互的开始和结束，应该具有相同的 `interactionId`。 `input` 事件是键盘输入的中间状态，其 `interactionId` 应该为 0 或者与 `keydown`/`keyup` 关联（取决于具体实现）。
*   **预期输出:** `keydown` 和 `keyup` 事件的 `interactionId` 大于 0 且相等，`input` 事件的 `interactionId` 为 0。 UKM 会记录一个 `UserInteraction` 事件，其 `max_duration` 可能为 `150 - 100 = 50`，`total_duration` 可能也接近。

*   **假设输入:**  用户在触摸屏上快速点击一个元素。
    *   `pointerdown` 事件时间戳：100
    *   `pointerup` 事件时间戳：120
    *   `click` 事件时间戳：130
    *   所有事件的 presentationTimestamp 可能略有不同。
*   **逻辑推理:**  `pointerdown`, `pointerup`, 和 `click` 是同一次点击操作的不同阶段，应该具有相同的 `interactionId`。
*   **预期输出:** `pointerdown`, `pointerup`, 和 `click` 事件的 `interactionId` 大于 0 且相等。 UKM 会记录一个 `UserInteraction` 事件，其 `max_duration` 和 `total_duration` 会根据这些时间戳计算。

**用户或编程常见的使用错误：**

*   **事件监听错误:**  开发者可能没有正确监听关键的事件（例如，只监听了 `click` 而没有监听 `pointerdown` 或 `pointerup`），导致性能监控数据不完整。
*   **事件处理延迟:**  JavaScript 代码中耗时的操作可能会延迟事件的处理，导致 `processing_start` 和 `processing_end` 时间戳之间的间隔过长，影响用户体验。
*   **非预期的事件顺序或类型:**  某些情况下，浏览器可能会发出非预期的事件顺序或类型（例如，在某些移动端场景下，可能没有 `touchstart` 直接触发 `click`），这需要 `WindowPerformance` 组件能够正确处理。
*   **指针 ID 错误处理:** 在多点触控或某些特殊情况下，开发者可能错误地假设 `click` 事件的 `pointerId` 与之前的 `pointerdown` 或 `pointerup` 事件一致，而测试用例 `ClickIncorrectPointerId` 就模拟了这种情况。

**用户操作如何一步步的到达这里，作为调试线索：**

1. **用户执行交互操作:** 用户在浏览器中进行操作，例如：
    *   **键盘输入:** 在文本框中输入内容。
    *   **鼠标点击/触摸:** 点击按钮、链接或其他可交互元素。
    *   **滑动/拖拽:** 在页面上滑动或拖动元素。
2. **浏览器捕获事件:** 浏览器的渲染引擎 (Blink) 会捕获这些用户产生的事件（例如 `keydown`, `click`, `pointerdown` 等）。
3. **事件传递和处理:**  捕获到的事件会被传递到相应的事件监听器进行处理。
4. **PerformanceEventTiming 记录事件信息:**  `blink/renderer/core/timing/` 目录下的代码，特别是 `PerformanceMonitor` 和 `PerformanceEventTiming` 类，会记录这些事件发生的时间戳 (`event_timestamp`, `processing_start`, `processing_end`, `presentation_timestamp`) 以及事件类型。
5. **生成 Interaction ID:**  根据事件的类型、时间顺序和关联性，`PerformanceEventTiming` 会为相关的事件生成一个唯一的 `interactionId`，用于追踪同一次用户交互。
6. **UKM 日志记录:**  相关的性能数据，包括 `interactionId`、事件持续时间等，会被记录到 UKM 系统，用于性能分析和优化。

**调试线索:**  如果开发者怀疑某个用户交互的性能存在问题，或者 UKM 数据显示异常，他们可能会：

*   **使用 Chrome 的开发者工具:**  查看 Performance 面板或 Timeline 面板，分析事件的触发顺序和时间消耗。
*   **启用跟踪 (Tracing):**  使用 `chrome://tracing` 或命令行参数启动 Chromium 的跟踪功能，可以更详细地查看 Blink 内部的事件处理流程，包括 `SlowInteractionToNextPaint` 等 trace event。
*   **断点调试:**  在 `blink/renderer/core/timing/` 相关的代码中设置断点，例如 `PerformanceEventTiming::SimulateInteractionId` 方法，可以观察 `interactionId` 的生成过程和 UKM 数据的记录。
*   **查看 UKM 数据:**  通过 Chrome 的 `chrome://ukm` 页面或者分析后台收集的 UKM 数据，了解用户交互的性能指标。

总而言之，`window_performance_test.cc` 的这部分代码是用来验证 Blink 引擎正确地追踪和记录用户交互的关键性能指标，为后续的性能分析和优化提供数据基础。

Prompt: 
```
这是目录为blink/renderer/core/timing/window_performance_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共3部分，请归纳一下它的功能

"""
sentation_time_keydown = GetTimeStamp(220);
    RegisterKeyboardEvent(event_type_names::kKeydown, keydown_timestamp,
                          processing_start_keydown, processing_end_keydown,
                          kKeyCode);
    SimulatePaintAndResolvePresentationPromise(presentation_time_keydown);

    // Keyup (start = 210, dur = 101ms).
    base::TimeTicks keyup_timestamp = GetTimeStamp(210);
    base::TimeTicks processing_start_keyup = GetTimeStamp(215);
    base::TimeTicks processing_end_keyup = GetTimeStamp(250);
    base::TimeTicks presentation_time_keyup = GetTimeStamp(311);
    RegisterKeyboardEvent(event_type_names::kKeyup, keyup_timestamp,
                          processing_start_keyup, processing_end_keyup,
                          kKeyCode);
    SimulatePaintAndResolvePresentationPromise(presentation_time_keyup);
  }

  // Overlapping events.
  {
    // Keydown (quick).
    base::TimeTicks keydown_timestamp = GetTimeStamp(1000);
    base::TimeTicks processing_start_keydown = GetTimeStamp(1001);
    base::TimeTicks processing_end_keydown = GetTimeStamp(1002);
    base::TimeTicks presentation_time_keydown = GetTimeStamp(1010);
    RegisterKeyboardEvent(event_type_names::kKeydown, keydown_timestamp,
                          processing_start_keydown, processing_end_keydown,
                          kKeyCode);
    SimulatePaintAndResolvePresentationPromise(presentation_time_keydown);

    // Keyup (start = 1020, dur = 1000ms).
    base::TimeTicks keyup_timestamp = GetTimeStamp(1020);
    base::TimeTicks processing_start_keyup = GetTimeStamp(1030);
    base::TimeTicks processing_end_keyup = GetTimeStamp(1040);
    base::TimeTicks presentation_time_keyup = GetTimeStamp(2020);
    RegisterKeyboardEvent(event_type_names::kKeyup, keyup_timestamp,
                          processing_start_keyup, processing_end_keyup,
                          kKeyCode);
    SimulatePaintAndResolvePresentationPromise(presentation_time_keyup);

    // Keydown (quick).
    base::TimeTicks keydown_timestamp2 = GetTimeStamp(1000);
    base::TimeTicks processing_start_keydown2 = GetTimeStamp(1001);
    base::TimeTicks processing_end_keydown2 = GetTimeStamp(1002);
    base::TimeTicks presentation_time_keydown2 = GetTimeStamp(1010);
    RegisterKeyboardEvent(event_type_names::kKeydown, keydown_timestamp2,
                          processing_start_keydown2, processing_end_keydown2,
                          kKeyCode);
    SimulatePaintAndResolvePresentationPromise(presentation_time_keydown2);

    // Keyup (start = 1800, dur = 600ms).
    base::TimeTicks keyup_timestamp2 = GetTimeStamp(1800);
    base::TimeTicks processing_start_keyup2 = GetTimeStamp(1802);
    base::TimeTicks processing_end_keyup2 = GetTimeStamp(1810);
    base::TimeTicks presentation_time_keyup2 = GetTimeStamp(2400);
    RegisterKeyboardEvent(event_type_names::kKeyup, keyup_timestamp2,
                          processing_start_keyup2, processing_end_keyup2,
                          kKeyCode);
    SimulatePaintAndResolvePresentationPromise(presentation_time_keyup2);
  }

  auto analyzer = trace_analyzer::Stop();
  analyzer->AssociateAsyncBeginEndEvents();

  trace_analyzer::TraceEventVector events;
  Query q = Query::EventNameIs("SlowInteractionToNextPaint") &&
            Query::EventPhaseIs(TRACE_EVENT_PHASE_NESTABLE_ASYNC_BEGIN);
  analyzer->FindEvents(q, &events);

  ASSERT_EQ(3u, events.size());

  ASSERT_TRUE(events[0]->has_other_event());
  EXPECT_EQ(events[0]->category, "latency");
  EXPECT_EQ(base::ClampRound(events[0]->GetAbsTimeToOtherEvent()), 101000);

  ASSERT_TRUE(events[1]->has_other_event());
  EXPECT_EQ(events[1]->category, "latency");
  EXPECT_EQ(base::ClampRound(events[1]->GetAbsTimeToOtherEvent()), 1000000);

  ASSERT_TRUE(events[2]->has_other_event());
  EXPECT_EQ(events[2]->category, "latency");
  EXPECT_EQ(base::ClampRound(events[2]->GetAbsTimeToOtherEvent()), 600000);
}

TEST_F(WindowPerformanceTest, InteractionID) {
  // Keyboard with max duration 25, total duration 40.
  PerformanceEventTiming* keydown_entry =
      CreatePerformanceEventTiming(event_type_names::kKeydown, 1, std::nullopt,
                                   GetTimeStamp(100), GetTimeStamp(120));
  SimulateInteractionId(keydown_entry);
  PerformanceEventTiming* keyup_entry =
      CreatePerformanceEventTiming(event_type_names::kKeyup, 1, std::nullopt,
                                   GetTimeStamp(115), GetTimeStamp(140));
  SimulateInteractionId(keyup_entry);
  EXPECT_EQ(keydown_entry->interactionId(), keyup_entry->interactionId());
  EXPECT_GT(keydown_entry->interactionId(), 0u);

  // Tap or Click with max duration 70, total duration 90.
  PointerId pointer_id_1 = 10;
  PerformanceEventTiming* pointerdown_entry = CreatePerformanceEventTiming(
      event_type_names::kPointerdown, std::nullopt, pointer_id_1,
      GetTimeStamp(100), GetTimeStamp(120));
  SimulateInteractionId(pointerdown_entry);
  PerformanceEventTiming* pointerup_entry = CreatePerformanceEventTiming(
      event_type_names::kPointerup, std::nullopt, pointer_id_1,
      GetTimeStamp(130), GetTimeStamp(150));
  SimulateInteractionId(pointerup_entry);
  PerformanceEventTiming* click_entry = CreatePerformanceEventTiming(
      event_type_names::kClick, std::nullopt, pointer_id_1, GetTimeStamp(130),
      GetTimeStamp(200));
  SimulateInteractionId(click_entry);
  EXPECT_GT(pointerdown_entry->interactionId(), 0u);
  EXPECT_EQ(pointerdown_entry->interactionId(),
            pointerup_entry->interactionId());
  EXPECT_EQ(pointerup_entry->interactionId(), click_entry->interactionId());

  // Drag with max duration 50, total duration 80.
  PointerId pointer_id_2 = 20;
  pointerdown_entry = CreatePerformanceEventTiming(
      event_type_names::kPointerdown, std::nullopt, pointer_id_2,
      GetTimeStamp(150), GetTimeStamp(200));
  SimulateInteractionId(pointerdown_entry);
  performance_->NotifyPotentialDrag(20);
  pointerup_entry = CreatePerformanceEventTiming(
      event_type_names::kPointerup, std::nullopt, pointer_id_2,
      GetTimeStamp(200), GetTimeStamp(230));
  SimulateInteractionId(pointerup_entry);
  EXPECT_GT(pointerdown_entry->interactionId(), 0u);
  EXPECT_EQ(pointerdown_entry->interactionId(),
            pointerup_entry->interactionId());

  // Scroll should not be reported in ukm.
  pointerdown_entry = CreatePerformanceEventTiming(
      event_type_names::kPointerdown, std::nullopt, pointer_id_2,
      GetTimeStamp(300), GetTimeStamp(315));
  SimulateInteractionId(pointerdown_entry);
  PerformanceEventTiming* pointercancel_entry = CreatePerformanceEventTiming(
      event_type_names::kPointercancel, std::nullopt, pointer_id_2,
      GetTimeStamp(310), GetTimeStamp(330));
  SimulateInteractionId(pointercancel_entry);
  EXPECT_EQ(pointerdown_entry->interactionId(), 0u);
  EXPECT_EQ(pointercancel_entry->interactionId(), 0u);

  // Flush UKM logging mojo request.
  RunPendingTasks();

  // Check UKM values.
  struct {
    int max_duration;
    int total_duration;
    UserInteractionType type;
  } expected_ukm[] = {{25, 40, UserInteractionType::kKeyboard},
                      {70, 90, UserInteractionType::kTapOrClick},
                      {50, 80, UserInteractionType::kDrag}};
  auto entries = GetUkmRecorder()->GetEntriesByName(
      ukm::builders::Responsiveness_UserInteraction::kEntryName);
  EXPECT_EQ(3u, entries.size());
  for (size_t i = 0; i < entries.size(); ++i) {
    const ukm::mojom::UkmEntry* ukm_entry = entries[i];
    GetUkmRecorder()->ExpectEntryMetric(
        ukm_entry,
        ukm::builders::Responsiveness_UserInteraction::kMaxEventDurationName,
        expected_ukm[i].max_duration);
    GetUkmRecorder()->ExpectEntryMetric(
        ukm_entry,
        ukm::builders::Responsiveness_UserInteraction::kTotalEventDurationName,
        expected_ukm[i].total_duration);
    GetUkmRecorder()->ExpectEntryMetric(
        ukm_entry,
        ukm::builders::Responsiveness_UserInteraction::kInteractionTypeName,
        static_cast<int>(expected_ukm[i].type));
  }
}

class InteractionIdTest : public WindowPerformanceTest {
 public:
  struct EventForInteraction {
    EventForInteraction(
        const AtomicString& name,
        std::optional<int> key_code,
        std::optional<PointerId> pointer_id,
        base::TimeTicks event_timestamp = base::TimeTicks(),
        base::TimeTicks presentation_timestamp = base::TimeTicks())
        : name_(name),
          key_code_(key_code),
          pointer_id_(pointer_id),
          event_timestamp_(event_timestamp),
          presentation_timestamp_(presentation_timestamp) {}

    AtomicString name_;
    std::optional<int> key_code_;
    std::optional<PointerId> pointer_id_;
    base::TimeTicks event_timestamp_;
    base::TimeTicks presentation_timestamp_;
  };

  struct ExpectedUkmValue {
    int max_duration_;
    int total_duration_;
    UserInteractionType interaction_type_;
  };

  std::vector<uint32_t> SimulateInteractionIds(
      const std::vector<EventForInteraction>& events) {
    // Store the entries first and record interactionIds at the end.
    HeapVector<Member<PerformanceEventTiming>> entries;
    for (const auto& event : events) {
      PerformanceEventTiming* entry = CreatePerformanceEventTiming(
          event.name_, event.key_code_, event.pointer_id_,
          event.event_timestamp_, event.presentation_timestamp_);
      SimulateInteractionId(entry);
      entries.push_back(entry);
    }
    std::vector<uint32_t> interaction_ids;
    for (const auto& entry : entries) {
      interaction_ids.push_back(entry->interactionId());
    }
    return interaction_ids;
  }

  void CheckUKMValues(const std::vector<ExpectedUkmValue>& expected_ukms) {
    // Flush UKM logging mojo request.
    RunPendingTasks();

    auto entries = GetUkmRecorder()->GetEntriesByName(
        ukm::builders::Responsiveness_UserInteraction::kEntryName);
    EXPECT_EQ(expected_ukms.size(), entries.size());
    for (size_t i = 0; i < entries.size(); ++i) {
      const ukm::mojom::UkmEntry* ukm_entry = entries[i];
      GetUkmRecorder()->ExpectEntryMetric(
          ukm_entry,
          ukm::builders::Responsiveness_UserInteraction::kMaxEventDurationName,
          expected_ukms[i].max_duration_);
      GetUkmRecorder()->ExpectEntryMetric(
          ukm_entry,
          ukm::builders::Responsiveness_UserInteraction::
              kTotalEventDurationName,
          expected_ukms[i].total_duration_);
      GetUkmRecorder()->ExpectEntryMetric(
          ukm_entry,
          ukm::builders::Responsiveness_UserInteraction::kInteractionTypeName,
          static_cast<int>(expected_ukms[i].interaction_type_));
    }
  }
};

// Tests English typing.
TEST_F(InteractionIdTest, InputOutsideComposition) {
  // Insert "a" with a max duration of 50 and total of 50.
  std::vector<EventForInteraction> events1 = {
      {event_type_names::kKeydown, 65, std::nullopt, GetTimeStamp(100),
       GetTimeStamp(150)},
      {event_type_names::kInput, std::nullopt, std::nullopt, GetTimeStamp(120),
       GetTimeStamp(220)},
      {event_type_names::kKeyup, 65, std::nullopt, GetTimeStamp(130),
       GetTimeStamp(150)}};
  std::vector<uint32_t> ids1 = SimulateInteractionIds(events1);
  EXPECT_GT(ids1[0], 0u) << "Keydown interactionId was nonzero";
  EXPECT_EQ(ids1[1], 0u) << "Input interactionId was zero";
  EXPECT_EQ(ids1[0], ids1[2]) << "Keydown and keyup interactionId match";

  // Insert "3" with a max duration of 40 and total of 60.
  std::vector<EventForInteraction> events2 = {
      {event_type_names::kKeydown, 53, std::nullopt, GetTimeStamp(200),
       GetTimeStamp(220)},
      {event_type_names::kInput, std::nullopt, std::nullopt, GetTimeStamp(220),
       GetTimeStamp(320)},
      {event_type_names::kKeyup, 53, std::nullopt, GetTimeStamp(250),
       GetTimeStamp(290)}};
  std::vector<uint32_t> ids2 = SimulateInteractionIds(events2);
  EXPECT_GT(ids2[0], 0u) << "Second keydown has nonzero interactionId";
  EXPECT_EQ(ids2[1], 0u) << "Second input interactionId was zero";
  EXPECT_EQ(ids2[0], ids2[2]) << "Second keydown and keyup interactionId match";
  EXPECT_NE(ids1[0], ids2[0])
      << "First and second keydown have different interactionId";

  // Backspace with max duration of 25 and total of 25.
  std::vector<EventForInteraction> events3 = {
      {event_type_names::kKeydown, 8, std::nullopt, GetTimeStamp(300),
       GetTimeStamp(320)},
      {event_type_names::kInput, std::nullopt, std::nullopt, GetTimeStamp(300),
       GetTimeStamp(400)},
      {event_type_names::kKeyup, 8, std::nullopt, GetTimeStamp(300),
       GetTimeStamp(325)}};
  std::vector<uint32_t> ids3 = SimulateInteractionIds(events3);
  EXPECT_GT(ids3[0], 0u) << "Third keydown has nonzero interactionId";
  EXPECT_EQ(ids3[1], 0u) << "Third input interactionId was zero";
  EXPECT_EQ(ids3[0], ids3[2]) << "Third keydown and keyup interactionId match";
  EXPECT_NE(ids1[0], ids3[0])
      << "First and third keydown have different interactionId";
  EXPECT_NE(ids2[0], ids3[0])
      << "Second and third keydown have different interactionId";

  CheckUKMValues({{50, 50, UserInteractionType::kKeyboard},
                  {40, 60, UserInteractionType::kKeyboard},
                  {25, 25, UserInteractionType::kKeyboard}});
}

// Tests Japanese on Mac.
TEST_F(InteractionIdTest, CompositionSingleKeydown) {
  // Insert "a" with a duration of 20.
  std::vector<EventForInteraction> events1 = {
      {event_type_names::kKeydown, 229, std::nullopt, GetTimeStamp(100),
       GetTimeStamp(200)},
      {event_type_names::kCompositionstart, std::nullopt, std::nullopt},
      {event_type_names::kCompositionupdate, std::nullopt, std::nullopt},
      {event_type_names::kInput, std::nullopt, std::nullopt, GetTimeStamp(120),
       GetTimeStamp(140)},
      {event_type_names::kKeyup, 65, std::nullopt, GetTimeStamp(120),
       GetTimeStamp(220)}};
  std::vector<uint32_t> ids1 = SimulateInteractionIds(events1);

  // Insert "b" and finish composition with a duration of 30.
  std::vector<EventForInteraction> events2 = {
      {event_type_names::kKeydown, 229, std::nullopt, GetTimeStamp(200),
       GetTimeStamp(300)},
      {event_type_names::kCompositionupdate, std::nullopt, std::nullopt},
      {event_type_names::kInput, std::nullopt, std::nullopt, GetTimeStamp(230),
       GetTimeStamp(260)},
      {event_type_names::kKeyup, 66, std::nullopt, GetTimeStamp(270),
       GetTimeStamp(370)},
      {event_type_names::kCompositionend, std::nullopt, std::nullopt}};
  std::vector<uint32_t> ids2 = SimulateInteractionIds(events2);

  performance_->GetResponsivenessMetrics().FlushAllEventsForTesting();

  EXPECT_GT(ids1[0], 0u) << "Keydown interactionId was nonzero";
  EXPECT_EQ(ids1[1], 0u) << "Compositionstart interactionId was zero";
  EXPECT_GT(ids1[3], 0u) << "Input interactionId was nonzero";
  EXPECT_GT(ids1[4], 0u) << "Keyup interactionId was nonzero";
  EXPECT_EQ(ids1[0], ids1[3])
      << "Keydown and Input have the same interactionIds";

  EXPECT_GT(ids2[0], 0u) << "Second keydown interactionId was nonzero";
  EXPECT_GT(ids2[2], 0u) << "Second input interactionId was nonzero";
  EXPECT_GT(ids2[3], 0u) << "Second keyup interactionId was non zero";
  EXPECT_EQ(ids2[4], 0u) << "Compositionend interactionId was zero";
  EXPECT_EQ(ids2[0], ids2[2])
      << "Keydown and Input have the same interactionIds";
  EXPECT_NE(ids1[3], ids2[2])
      << "First and second inputs have different interactionIds";

  CheckUKMValues({{100, 120, UserInteractionType::kKeyboard},
                  {100, 170, UserInteractionType::kKeyboard}});
}

// Tests Chinese on Mac. Windows is similar, but has more keyups inside the
// composition.
TEST_F(InteractionIdTest, CompositionToFinalInput) {
  // Insert "a" with a duration of 25.
  std::vector<EventForInteraction> events1 = {
      {event_type_names::kKeydown, 229, std::nullopt, GetTimeStamp(100),
       GetTimeStamp(190)},
      {event_type_names::kCompositionstart, std::nullopt, std::nullopt},
      {event_type_names::kCompositionupdate, std::nullopt, std::nullopt},
      {event_type_names::kInput, std::nullopt, std::nullopt, GetTimeStamp(100),
       GetTimeStamp(125)},
      {event_type_names::kKeyup, 65, std::nullopt, GetTimeStamp(110),
       GetTimeStamp(190)}};
  std::vector<uint32_t> ids1 = SimulateInteractionIds(events1);
  EXPECT_GT(ids1[3], 0u) << "First input nonzero";

  // Insert "b" with a duration of 35.
  std::vector<EventForInteraction> events2 = {
      {event_type_names::kKeydown, 229, std::nullopt, GetTimeStamp(200),
       GetTimeStamp(290)},
      {event_type_names::kCompositionupdate, std::nullopt, std::nullopt},
      {event_type_names::kInput, std::nullopt, std::nullopt, GetTimeStamp(220),
       GetTimeStamp(255)},
      {event_type_names::kKeyup, 66, std::nullopt, GetTimeStamp(210),
       GetTimeStamp(290)}};
  std::vector<uint32_t> ids2 = SimulateInteractionIds(events2);
  EXPECT_GT(ids2[2], 0u) << "Second input nonzero";
  EXPECT_NE(ids1[3], ids2[2])
      << "First and second input have different interactionIds";

  // Select a composed input and finish, with a duration of 140.
  std::vector<EventForInteraction> events3 = {
      {event_type_names::kCompositionupdate, std::nullopt, std::nullopt},
      {event_type_names::kInput, std::nullopt, std::nullopt, GetTimeStamp(300),
       GetTimeStamp(440)},
      {event_type_names::kCompositionend, std::nullopt, std::nullopt}};
  std::vector<uint32_t> ids3 = SimulateInteractionIds(events3);
  EXPECT_EQ(ids3[2], 0u) << "Compositionend has zero interactionId";
  EXPECT_GT(ids3[1], 0u) << "Third input has nonzero interactionId";
  EXPECT_NE(ids1[3], ids3[1])
      << "First and third inputs have different interactionIds";
  EXPECT_NE(ids2[2], ids3[1])
      << "Second and third inputs have different interactionIds";

  performance_->GetResponsivenessMetrics().FlushAllEventsForTesting();

  CheckUKMValues({{90, 90, UserInteractionType::kKeyboard},
                  {90, 90, UserInteractionType::kKeyboard},
                  {140, 140, UserInteractionType::kKeyboard}});
}

// Tests Chinese on Windows.
TEST_F(InteractionIdTest, CompositionToFinalInputMultipleKeyUps) {
  // Insert "a" with a duration of 66.
  std::vector<EventForInteraction> events1 = {
      {event_type_names::kKeydown, 229, std::nullopt, GetTimeStamp(0),
       GetTimeStamp(100)},
      {event_type_names::kCompositionstart, std::nullopt, std::nullopt},
      {event_type_names::kCompositionupdate, std::nullopt, std::nullopt},
      {event_type_names::kInput, std::nullopt, std::nullopt, GetTimeStamp(0),
       GetTimeStamp(66)},
      {event_type_names::kKeyup, 229, std::nullopt, GetTimeStamp(0),
       GetTimeStamp(100)},
      {event_type_names::kKeyup, 65, std::nullopt, GetTimeStamp(0),
       GetTimeStamp(100)}};
  std::vector<uint32_t> ids1 = SimulateInteractionIds(events1);

  // Insert "b" with a duration of 51.
  std::vector<EventForInteraction> events2 = {
      {event_type_names::kKeydown, 229, std::nullopt, GetTimeStamp(200),
       GetTimeStamp(300)},
      {event_type_names::kCompositionupdate, std::nullopt, std::nullopt},
      {event_type_names::kInput, std::nullopt, std::nullopt, GetTimeStamp(200),
       GetTimeStamp(251)},
      {event_type_names::kKeyup, 229, std::nullopt, GetTimeStamp(200),
       GetTimeStamp(300)},
      {event_type_names::kKeyup, 66, std::nullopt, GetTimeStamp(200),
       GetTimeStamp(300)}};
  std::vector<uint32_t> ids2 = SimulateInteractionIds(events2);

  // Select a composed input and finish, with duration of 85.
  std::vector<EventForInteraction> events3 = {
      {event_type_names::kCompositionupdate, std::nullopt, std::nullopt},
      {event_type_names::kInput, std::nullopt, std::nullopt, GetTimeStamp(300),
       GetTimeStamp(385)},
      {event_type_names::kCompositionend, std::nullopt, std::nullopt}};
  std::vector<uint32_t> ids3 = SimulateInteractionIds(events3);

  performance_->GetResponsivenessMetrics().FlushAllEventsForTesting();
  EXPECT_GT(ids1[3], 0u) << "First input nonzero";
  EXPECT_GT(ids1[4], 0u) << "First keyup has nonzero interactionId";
  EXPECT_GT(ids1[5], 0u) << "Second keyup has nonzero interactionId";

  EXPECT_GT(ids2[2], 0u) << "Second input nonzero";
  EXPECT_NE(ids1[3], ids2[2])
      << "First and second input have different interactionIds";
  EXPECT_GT(ids2[3], 0u) << "Third keyup has nonzero interactionId";
  EXPECT_GT(ids2[4], 0u) << "Fourth keyup has nonzero interactionId";

  EXPECT_GT(ids3[1], 0u) << "Third input has nonzero interactionId";
  EXPECT_NE(ids1[3], ids3[1])
      << "First and third inputs have different interactionIds";
  EXPECT_NE(ids2[2], ids3[1])
      << "Second and third inputs have different interactionIds";
  CheckUKMValues({{100, 100, UserInteractionType::kKeyboard},
                  {100, 100, UserInteractionType::kKeyboard},
                  {85, 85, UserInteractionType::kKeyboard}});
}

// Tests Android smart suggestions (similar to Android Chinese).
TEST_F(InteractionIdTest, SmartSuggestion) {
  // Insert "A" with a duration of 9.
  std::vector<EventForInteraction> events1 = {
      {event_type_names::kKeydown, 229, std::nullopt, GetTimeStamp(0),
       GetTimeStamp(16)},
      {event_type_names::kCompositionstart, std::nullopt, std::nullopt},
      {event_type_names::kCompositionupdate, std::nullopt, std::nullopt},
      {event_type_names::kInput, std::nullopt, std::nullopt, GetTimeStamp(0),
       GetTimeStamp(9)},
      {event_type_names::kKeyup, 229, std::nullopt, GetTimeStamp(0),
       GetTimeStamp(16)}};
  std::vector<uint32_t> ids1 = SimulateInteractionIds(events1);

  // Compose to "At" with a duration of 14.
  std::vector<EventForInteraction> events2 = {
      {event_type_names::kCompositionupdate, std::nullopt, std::nullopt},
      {event_type_names::kInput, std::nullopt, std::nullopt, GetTimeStamp(100),
       GetTimeStamp(114)},
      {event_type_names::kCompositionend, std::nullopt, std::nullopt}};
  std::vector<uint32_t> ids2 = SimulateInteractionIds(events2);

  // Add "the". No composition so need to consider the keydown and keyup.
  // Max duration of 43 and total duration of 70
  std::vector<EventForInteraction> events3 = {
      {event_type_names::kKeydown, 229, std::nullopt, GetTimeStamp(200),
       GetTimeStamp(243)},
      {event_type_names::kInput, std::nullopt, std::nullopt, GetTimeStamp(200),
       GetTimeStamp(300)},
      {event_type_names::kKeyup, 229, std::nullopt, GetTimeStamp(235),
       GetTimeStamp(270)}};
  std::vector<uint32_t> ids3 = SimulateInteractionIds(events3);

  performance_->GetResponsivenessMetrics().FlushAllEventsForTesting();
  EXPECT_GT(ids1[3], 0u) << "First input nonzero";
  EXPECT_EQ(ids1[0], ids1[3]) << "Keydown and input have the same id";
  EXPECT_EQ(ids1[0], ids1[3]) << "Keydown and keyup have the same id";

  EXPECT_GT(ids2[1], 0u) << "Second input nonzero";
  EXPECT_NE(ids1[3], ids2[1])
      << "First and second input have different interactionIds";
  EXPECT_GT(ids3[0], 0u) << "Keydown nonzero";
  EXPECT_EQ(ids3[0], ids3[2]) << "Keydown and keyup have some id";
  EXPECT_EQ(ids3[1], 0u) << "Third input has zero id";

  CheckUKMValues({{16, 16, UserInteractionType::kKeyboard},
                  {14, 14, UserInteractionType::kKeyboard},
                  {43, 70, UserInteractionType::kKeyboard}});
}

TEST_F(InteractionIdTest, TapWithoutClick) {
  std::vector<EventForInteraction> events = {
      {event_type_names::kPointerdown, std::nullopt, 1, GetTimeStamp(100),
       GetTimeStamp(140)},
      {event_type_names::kPointerup, std::nullopt, 1, GetTimeStamp(120),
       GetTimeStamp(150)}};
  std::vector<uint32_t> ids = SimulateInteractionIds(events);
  EXPECT_GT(ids[0], 0u) << "Nonzero interaction id";
  EXPECT_EQ(ids[0], ids[1])
      << "Pointerdown and pointerup have same interaction id";
  // No UKM value, since we are waiting for click.
  RunPendingTasks();
  auto entries = GetUkmRecorder()->GetEntriesByName(
      ukm::builders::Responsiveness_UserInteraction::kEntryName);
  EXPECT_EQ(entries.size(), 0u);

  // After a wait, we should see the UKM.
  test::RunDelayedTasks(base::Seconds(1));
  CheckUKMValues({{40, 50, UserInteractionType::kTapOrClick}});
}

TEST_F(InteractionIdTest, PointerupClick) {
  std::vector<EventForInteraction> events = {
      {event_type_names::kPointerup, std::nullopt, 1, GetTimeStamp(100),
       GetTimeStamp(140)},
      {event_type_names::kClick, std::nullopt, 1, GetTimeStamp(120),
       GetTimeStamp(150)}};
  std::vector<uint32_t> ids = SimulateInteractionIds(events);
  EXPECT_EQ(ids[0], 0u) << "Orphan pointerup gets interaction id of zero";
  EXPECT_GT(ids[1], 0u) << "Nonzero interaction id for click";
  // Flush UKM logging mojo request.
  RunPendingTasks();
  CheckUKMValues({{30, 30, UserInteractionType::kTapOrClick}});
}

TEST_F(InteractionIdTest, JustClick) {
  // Hitting enter on a keyboard may cause just a trusted click event.
  std::vector<EventForInteraction> events = {
      {event_type_names::kClick, std::nullopt, 0, GetTimeStamp(120),
       GetTimeStamp(150)}};
  std::vector<uint32_t> ids = SimulateInteractionIds(events);
  EXPECT_GT(ids[0], 0u) << "Nonzero interaction id";
  // Flush UKM logging mojo request.
  RunPendingTasks();
  CheckUKMValues({{30, 30, UserInteractionType::kTapOrClick}});
}

TEST_F(InteractionIdTest, PointerdownClick) {
  // Contextmenus may cause us to only see pointerdown and click (no pointerup).
  std::vector<EventForInteraction> events = {
      {event_type_names::kPointerdown, std::nullopt, 1, GetTimeStamp(100),
       GetTimeStamp(140)},
      {event_type_names::kClick, std::nullopt, 1, GetTimeStamp(120),
       GetTimeStamp(150)}};
  std::vector<uint32_t> ids = SimulateInteractionIds(events);
  EXPECT_GT(ids[0], 0u) << "Nonzero interaction id";
  EXPECT_EQ(ids[0], ids[1]) << "Pointerdown and click have same interaction id";
  // Flush UKM logging mojo request.
  RunPendingTasks();
  CheckUKMValues({{40, 50, UserInteractionType::kTapOrClick}});
}

TEST_F(InteractionIdTest, MultiTouch) {
  // In multitouch, we report an interaction per pointerId. We do not see
  // clicks.
  std::vector<EventForInteraction> events = {
      {event_type_names::kPointerdown, std::nullopt, 1, GetTimeStamp(100),
       GetTimeStamp(110)},
      {event_type_names::kPointerdown, std::nullopt, 2, GetTimeStamp(120),
       GetTimeStamp(140)},
      {event_type_names::kPointerup, std::nullopt, 2, GetTimeStamp(200),
       GetTimeStamp(230)},
      {event_type_names::kPointerup, std::nullopt, 1, GetTimeStamp(200),
       GetTimeStamp(250)}};
  std::vector<uint32_t> ids = SimulateInteractionIds(events);
  for (uint32_t id : ids) {
    EXPECT_GT(id, 0u);
  }
  // Interaction ids should match by PointerId.
  EXPECT_EQ(ids[0], ids[3]);
  EXPECT_EQ(ids[1], ids[2]);
  // After a wait, flush UKM logging mojo request.
  test::RunDelayedTasks(base::Seconds(1));
  CheckUKMValues({{30, 50, UserInteractionType::kTapOrClick},
                  {50, 60, UserInteractionType::kTapOrClick}});
}

TEST_F(InteractionIdTest, ClickIncorrectPointerId) {
  // On mobile, in cases where touchstart is skipped, click does not get the
  // correct pointerId. See crbug.com/1264930 for more details.
  // TODO crbug.com/359679950: remove this test and event timing workaround
  // since crbug.com/1264930 has been fixed.
  std::vector<EventForInteraction> events = {
      {event_type_names::kPointerup, std::nullopt, 1, GetTimeStamp(100),
       GetTimeStamp(130)},
      {event_type_names::kClick, std::nullopt, 0, GetTimeStamp(120),
       GetTimeStamp(160)}};
  std::vector<uint32_t> ids = SimulateInteractionIds(events);
  EXPECT_EQ(ids[0], 0u) << "Orphan pointerup gets interaction id of zero";
  EXPECT_GT(ids[1], 0u) << "Nonzero interaction id for click";
  // Flush UKM logging mojo request.
  RunPendingTasks();
  CheckUKMValues({{40, 40, UserInteractionType::kTapOrClick}});
}

}  // namespace blink

"""


```