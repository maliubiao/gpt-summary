Response:
The user wants a summary of the functionality of the provided C++ code file. I need to identify the main purpose of the file and any relationships it has with web technologies like JavaScript, HTML, and CSS. The user also asked for examples of logical reasoning, common usage errors, and steps to reach this code during debugging. Finally, I need to summarize the file's overall function as the first part of a three-part explanation.

**Plan:**

1. **Identify the core class:** The file name `window_performance_test.cc` and the inclusion of `window_performance.h` suggest the code tests the `WindowPerformance` class.
2. **Analyze the tests:** Look at the `TEST_F` macros to understand the different functionalities being tested. Pay attention to the methods being called on the `performance_` object (which is a `DOMWindowPerformance`).
3. **Relate to web technologies:**  Connect the tested functionalities to browser features accessible through JavaScript's `performance` API. For example, `mark()`, `getEntriesByType()`, and event timing are directly related.
4. **Logical Reasoning (Input/Output):** For specific tests, consider what input would lead to a particular output. Focus on tests that manipulate time and event registration.
5. **Common Usage Errors:** Think about how developers might misuse the JavaScript `performance` API and if these tests cover those scenarios.
6. **Debugging Steps:**  Consider the developer workflow when investigating performance issues. How might they end up looking at this specific test file?
7. **Summarize the functionality:** Concisely describe the purpose of the `window_performance_test.cc` file.
这个 blink 引擎源代码文件 `window_performance_test.cc` 的主要功能是**测试 `blink::WindowPerformance` 类的各项功能**。`WindowPerformance` 类是 Chromium 中用于**收集和管理与浏览器窗口性能相关的指标**的类，它是通过 JavaScript 的 `window.performance` 对象暴露给 web 开发者的。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个测试文件直接测试了 `WindowPerformance` 类，而 `WindowPerformance` 类又是 JavaScript `window.performance` API 的底层实现。因此，该文件与 JavaScript 性能 API 息息相关。

* **JavaScript 的 `performance.mark()` 和 `performance.measure()`:**  测试文件中的 `TEST_F(WindowPerformanceTest, EnsureEntryListOrder)` 测试了 `performance_->mark()` 方法，这模拟了 JavaScript 中调用 `performance.mark()` 来添加时间标记点的行为。通过 `performance_->getEntriesByType(performance_entry_names::kMark)` 来获取这些标记点，并验证它们的顺序和时间戳是否正确。
    * **举例说明:**  在 JavaScript 中，开发者可以使用 `performance.mark('start')` 和 `performance.mark('end')` 标记代码执行的开始和结束，然后使用 `performance.measure('myMeasure', 'start', 'end')` 计算这段代码的执行时间。这个测试文件验证了 Blink 引擎底层实现这些功能的正确性。

* **JavaScript 的 `performance.getEntriesByType('event')` (PerformanceEventTiming API):** 许多测试（例如 `TEST_F(WindowPerformanceTest, EventTimingEntryBuffering)`, `TEST_F(WindowPerformanceTest, Expose100MsEvents)`, `TEST_F(WindowPerformanceTest, EventTimingDuration)` 等）都涉及到模拟浏览器事件的发生（例如 `RegisterPointerEvent`, `RegisterKeyboardEvent`）并验证这些事件是否被正确记录到 `performance_->event_timing_entries_` 中，最终可以通过 JavaScript 的 `performance.getEntriesByType('event')` 获取。
    * **举例说明:** 在 JavaScript 中，开发者可以使用 `performance.getEntriesByType('event')` 获取诸如 `click`, `keydown` 等事件的详细信息，例如事件的开始时间、处理时间、以及呈现时间。这个测试文件模拟了这些事件的触发，并验证了 Blink 引擎正确地记录了这些事件的时序信息。

* **JavaScript 的 `performance.getEntriesByType('first-input')` (First Input Delay - FID):**  测试文件中的 `TEST_F(WindowPerformanceTest, FirstInput)`, `TEST_F(WindowPerformanceTest, FirstInputAfterIgnored)`, `TEST_F(WindowPerformanceTest, FirstPointerUp)` 等测试了对于用户首次交互事件（例如点击、键盘按下）的识别和记录，这对应于 Web 性能指标 First Input Delay (FID)。
    * **举例说明:** 当用户首次与页面进行交互时，浏览器需要一定的时间来响应。FID 指标衡量了用户首次交互到浏览器开始处理事件之间的时间延迟。这个测试文件验证了 Blink 引擎正确地识别和记录了这些首次交互事件。

* **JavaScript 的 `performance.timeOrigin`:** 测试文件中的 `GetTimeOrigin()` 函数和 `performance_->time_origin_` 成员模拟了 `performance.timeOrigin` 的概念，即性能测量的起始时间。

**逻辑推理 (假设输入与输出):**

以 `TEST_F(WindowPerformanceTest, EventTimingDuration)` 为例：

* **假设输入:**
    1. 在 `GetTimeOrigin() + base::Milliseconds(1000)` 时刻注册一个 `click` 事件。
    2. 事件处理开始时间为 `GetTimeOrigin() + base::Milliseconds(1001)`。
    3. 事件处理结束时间为 `GetTimeOrigin() + base::Milliseconds(1002)`。
    4. 第一次呈现时间为 `GetTimeOrigin() + base::Milliseconds(1003)`。
    5. 第二次呈现时间为 `GetTimeOrigin() + base::Milliseconds(2000)`。

* **逻辑推理:**  `PerformanceEventTiming` 只有在事件的持续时间（从创建到呈现）超过一定阈值时才会被记录（通常是 100ms）。第一次呈现时间 (3ms) 使得事件持续时间很短，不应被记录。第二次呈现时间 (1000ms) 使得事件持续时间较长，应该被记录。

* **预期输出:**
    1. 第一次 `SimulatePaintAndResolvePresentationPromise(short_presentation_time)` 后，`performance_->getBufferedEntriesByType(performance_entry_names::kEvent)` 的大小为 0。
    2. 第二次 `SimulatePaintAndResolvePresentationPromise(long_presentation_time)` 后，`performance_->getBufferedEntriesByType(performance_entry_names::kEvent)` 的大小为 1。

**涉及用户或者编程常见的使用错误 (举例说明):**

* **忘记调用 `SimulatePaintAndResolvePresentationPromise`:**  开发者可能在注册事件后，忘记模拟浏览器的渲染和呈现过程，导致事件的呈现时间未被设置，`PerformanceEventTiming` 无法完成，从而无法被正确记录。这对应了测试中需要显式调用 `SimulatePaintAndResolvePresentationPromise` 来模拟呈现完成。

* **误解事件时序:** 开发者可能对事件的触发、处理和呈现之间的关系理解不正确，导致对性能指标的解读出现偏差。例如，他们可能错误地认为事件处理结束就意味着用户看到了结果，而忽略了呈现延迟。测试文件通过精确控制时间点来验证这些时序逻辑。

**用户操作是如何一步步的到达这里，作为调试线索:**

当开发者在分析网页性能问题时，可能会遇到以下情况，从而需要查看 `window_performance_test.cc`：

1. **用户报告页面响应缓慢:** 用户反馈某个网页在进行交互时有明显的卡顿。
2. **开发者使用性能分析工具:** 开发者使用 Chrome DevTools 的 Performance 面板，发现 First Input Delay (FID) 或其他性能指标过高。
3. **怀疑是 Blink 引擎的实现问题:**  如果开发者排除了 JavaScript 代码的性能问题，可能会怀疑是浏览器底层对于事件处理或性能指标计算存在问题。
4. **查找 Blink 引擎相关代码:** 开发者可能会搜索 Blink 引擎中与 `window.performance` 或 `PerformanceEventTiming` 相关的代码，最终定位到 `blink/renderer/core/timing/window_performance.cc` 和其对应的测试文件 `blink/renderer/core/timing/window_performance_test.cc`。
5. **查看测试用例:**  开发者可以通过查看测试用例，例如 `TEST_F(WindowPerformanceTest, FirstInput)`，来理解 Blink 引擎是如何识别和记录首次用户输入的，以及是否存在潜在的 bug 或性能瓶颈。他们还可以通过修改测试用例来复现问题或验证修复方案。

**归纳其功能 (第1部分):**

总而言之，`blink/renderer/core/timing/window_performance_test.cc` 的主要功能是**对 Blink 引擎中负责管理窗口性能指标的 `WindowPerformance` 类进行全面的单元测试**。它通过模拟各种场景，包括 JavaScript API 调用、浏览器事件触发、页面生命周期变化等，来验证 `WindowPerformance` 类及其相关组件（如 `PerformanceTiming`, `PerformanceEventTiming`）的功能是否正确，确保 Blink 引擎能够准确地收集和报告 web 页面的性能数据，为 web 开发者提供可靠的性能分析基础。

### 提示词
```
这是目录为blink/renderer/core/timing/window_performance_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/core/timing/window_performance.h"

#include <cstdint>

#include "base/numerics/safe_conversions.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/test/test_mock_time_task_runner.h"
#include "base/test/trace_event_analyzer.h"
#include "base/time/time.h"
#include "build/build_config.h"
#include "components/viz/common/frame_timing_details.h"
#include "services/metrics/public/cpp/ukm_builders.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/responsiveness_metrics/user_interaction_latency.h"
#include "third_party/blink/public/mojom/page/page_visibility_state.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_keyboard_event_init.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_pointer_event_init.h"
#include "third_party/blink/renderer/core/dom/document_init.h"
#include "third_party/blink/renderer/core/dom/dom_node_ids.h"
#include "third_party/blink/renderer/core/events/input_event.h"
#include "third_party/blink/renderer/core/events/keyboard_event.h"
#include "third_party/blink/renderer/core/events/pointer_event.h"
#include "third_party/blink/renderer/core/execution_context/security_context_init.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/performance_monitor.h"
#include "third_party/blink/renderer/core/loader/document_load_timing.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/performance_entry_names.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"
#include "third_party/blink/renderer/core/testing/mock_policy_container_host.h"
#include "third_party/blink/renderer/core/timing/dom_window_performance.h"
#include "third_party/blink/renderer/core/timing/performance_event_timing.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_vector.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/testing/scoped_fake_ukm_recorder.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/wtf/wtf_size_t.h"

namespace blink {

using test::RunPendingTasks;

namespace {

base::TimeTicks GetTimeOrigin() {
  return base::TimeTicks() + base::Seconds(500);
}

base::TimeTicks GetTimeStamp(int64_t time) {
  return GetTimeOrigin() + base::Milliseconds(time);
}

}  // namespace

class WindowPerformanceTest : public testing::Test {
 protected:
  void SetUp() override {
    test_task_runner_ = base::MakeRefCounted<base::TestMockTimeTaskRunner>();
    ResetPerformance();
  }

  void AddLongTaskObserver() {
    // simulate with filter options.
    performance_->observer_filter_options_ |= PerformanceEntry::kLongTask;
  }

  void RemoveLongTaskObserver() {
    // simulate with filter options.
    performance_->observer_filter_options_ = PerformanceEntry::kInvalid;
  }

  void SimulatePaint() { performance_->OnPaintFinished(); }
  void SimulateResolvePresentationPromise(uint64_t presentation_index,
                                          base::TimeTicks timestamp) {
    viz::FrameTimingDetails presentation_details;
    presentation_details.presentation_feedback.timestamp = timestamp;
    performance_->OnPresentationPromiseResolved(presentation_index,
                                                presentation_details);
  }

  // Only use this function if you don't care about the time difference between
  // paint & frame presented. Otherwise, use SimulatePaint() &
  // SimulateResolvePresentationPromise() separately instead and perform actions
  // in between as needed.
  void SimulatePaintAndResolvePresentationPromise(base::TimeTicks timestamp) {
    uint64_t presentation_promise_index =
        performance_->event_presentation_promise_count_;
    SimulatePaint();
    SimulateResolvePresentationPromise(presentation_promise_index, timestamp);
  }

  void SimulateInteractionId(PerformanceEventTiming* entry) {
    ResponsivenessMetrics::EventTimestamps event_timestamps = {
        entry->GetEventTimingReportingInfo()->creation_time, base::TimeTicks(),
        base::TimeTicks(),
        entry->GetEventTimingReportingInfo()->fallback_time.has_value()
            ? entry->GetEventTimingReportingInfo()->fallback_time.value()
            : entry->GetEventTimingReportingInfo()->presentation_time.value()};
    performance_->SetInteractionIdAndRecordLatency(entry, event_timestamps);
  }

  uint64_t RegisterKeyboardEvent(AtomicString type,
                                 base::TimeTicks start_time,
                                 base::TimeTicks processing_start,
                                 base::TimeTicks processing_end,
                                 int key_code,
                                 EventTarget* target = nullptr) {
    KeyboardEventInit* init = KeyboardEventInit::Create();
    init->setKeyCode(key_code);
    KeyboardEvent* keyboard_event =
        MakeGarbageCollected<KeyboardEvent>(type, init, start_time);
    performance_->EventTimingProcessingStart(*keyboard_event, processing_start,
                                             target);
    keyboard_event->SetTarget(target);
    performance_->EventTimingProcessingEnd(*keyboard_event, processing_end);
    return performance_->event_presentation_promise_count_;
  }

  void RegisterPointerEvent(AtomicString type,
                            base::TimeTicks start_time,
                            base::TimeTicks processing_start,
                            base::TimeTicks processing_end,
                            PointerId pointer_id,
                            EventTarget* target = nullptr) {
    PointerEventInit* init = PointerEventInit::Create();
    init->setPointerId(pointer_id);
    PointerEvent* pointer_event = PointerEvent::Create(type, init, start_time);
    performance_->EventTimingProcessingStart(*pointer_event, processing_start,
                                             target);
    pointer_event->SetTarget(target);
    performance_->EventTimingProcessingEnd(*pointer_event, processing_end);
  }

  PerformanceEventTiming* CreatePerformanceEventTiming(
      const AtomicString& name,
      std::optional<int> key_code,
      std::optional<PointerId> pointer_id,
      base::TimeTicks event_creation_timestamp,
      base::TimeTicks presentation_timestamp) {
    PerformanceEventTiming::EventTimingReportingInfo reporting_info{
        .creation_time = event_creation_timestamp,
        .presentation_time = presentation_timestamp,
        .key_code = key_code,
        .pointer_id = pointer_id};

    return PerformanceEventTiming::Create(
        name, reporting_info, false, nullptr,
        LocalDOMWindow::From(GetScriptState()));
  }

  HeapVector<Member<PerformanceEventTiming>>*
  GetWindowPerformanceEventTimingEntries() {
    return &performance_->event_timing_entries_;
  }

  LocalFrame* GetFrame() const { return &page_holder_->GetFrame(); }

  LocalDOMWindow* GetWindow() const { return GetFrame()->DomWindow(); }

  String SanitizedAttribution(ExecutionContext* context,
                              bool has_multiple_contexts,
                              LocalFrame* observer_frame) {
    return WindowPerformance::SanitizedAttribution(
               context, has_multiple_contexts, observer_frame)
        .first;
  }

  void ResetPerformance() {
    page_holder_ = nullptr;
    page_holder_ = std::make_unique<DummyPageHolder>(gfx::Size(800, 600));
    page_holder_->GetDocument().SetURL(KURL("https://example.com"));

    LocalDOMWindow* window = LocalDOMWindow::From(GetScriptState());
    performance_ = DOMWindowPerformance::performance(*window);
    performance_->SetClocksForTesting(test_task_runner_->GetMockClock(),
                                      test_task_runner_->GetMockTickClock());
    performance_->time_origin_ = GetTimeOrigin();
    // Stop UKM sampling for testing.
    performance_->GetResponsivenessMetrics().StopUkmSamplingForTesting();
  }

  ScriptState* GetScriptState() const {
    return ToScriptStateForMainWorld(page_holder_->GetDocument().GetFrame());
  }

  ukm::TestUkmRecorder* GetUkmRecorder() {
    return scoped_fake_ukm_recorder_.recorder();
  }

  const base::HistogramTester& GetHistogramTester() const {
    return histogram_tester_;
  }

  void PageVisibilityChanged(base::TimeTicks timestamp) {
    performance_->PageVisibilityChangedWithTimestamp(timestamp);
  }

  test::TaskEnvironment task_environment_;
  Persistent<WindowPerformance> performance_;
  std::unique_ptr<DummyPageHolder> page_holder_;
  scoped_refptr<base::TestMockTimeTaskRunner> test_task_runner_;
  ScopedFakeUkmRecorder scoped_fake_ukm_recorder_;
  base::HistogramTester histogram_tester_;
};

TEST_F(WindowPerformanceTest, SanitizedLongTaskName) {
  // Unable to attribute, when no execution contents are available.
  EXPECT_EQ("unknown", SanitizedAttribution(nullptr, false, GetFrame()));

  // Attribute for same context (and same origin).
  EXPECT_EQ("self", SanitizedAttribution(GetWindow(), false, GetFrame()));

  // Unable to attribute, when multiple script execution contents are involved.
  EXPECT_EQ("multiple-contexts",
            SanitizedAttribution(GetWindow(), true, GetFrame()));
}

TEST_F(WindowPerformanceTest, SanitizedLongTaskName_CrossOrigin) {
  // Create another dummy page holder and pretend it is an iframe.
  DummyPageHolder another_page(gfx::Size(400, 300));
  another_page.GetDocument().SetURL(KURL("https://iframed.com/bar"));

  // Unable to attribute, when no execution contents are available.
  EXPECT_EQ("unknown", SanitizedAttribution(nullptr, false, GetFrame()));

  // Attribute for same context (and same origin).
  EXPECT_EQ("cross-origin-unreachable",
            SanitizedAttribution(another_page.GetFrame().DomWindow(), false,
                                 GetFrame()));
}

// https://crbug.com/706798: Checks that after navigation that have replaced the
// window object, calls to not garbage collected yet WindowPerformance belonging
// to the old window do not cause a crash.
TEST_F(WindowPerformanceTest, NavigateAway) {
  AddLongTaskObserver();

  // Simulate navigation commit.
  GetFrame()->DomWindow()->FrameDestroyed();
}

// Checks that WindowPerformance object and its fields (like PerformanceTiming)
// function correctly after transition to another document in the same window.
// This happens when a page opens a new window and it navigates to a same-origin
// document.
TEST(PerformanceLifetimeTest, SurviveContextSwitch) {
  test::TaskEnvironment task_environment;
  auto page_holder = std::make_unique<DummyPageHolder>(gfx::Size(800, 600));
  // Emulate a new window inheriting the origin for its initial empty document
  // from its opener. This is necessary to ensure window reuse below, as that
  // only happens when origins match.
  KURL url("http://example.com");
  page_holder->GetFrame()
      .DomWindow()
      ->GetSecurityContext()
      .SetSecurityOriginForTesting(SecurityOrigin::Create(KURL(url)));

  WindowPerformance* perf =
      DOMWindowPerformance::performance(*page_holder->GetFrame().DomWindow());
  PerformanceTiming* timing = perf->timing();

  auto* document_loader = page_holder->GetFrame().Loader().GetDocumentLoader();
  ASSERT_TRUE(document_loader);
  document_loader->GetTiming().SetNavigationStart(base::TimeTicks::Now());

  EXPECT_EQ(page_holder->GetFrame().DomWindow(), perf->DomWindow());
  EXPECT_EQ(page_holder->GetFrame().DomWindow(), timing->DomWindow());
  auto navigation_start = timing->navigationStart();
  EXPECT_NE(0U, navigation_start);

  // Simulate changing the document while keeping the window.
  std::unique_ptr<WebNavigationParams> params =
      WebNavigationParams::CreateWithEmptyHTMLForTesting(url);
  MockPolicyContainerHost mock_policy_container_host;
  params->policy_container = std::make_unique<WebPolicyContainer>(
      WebPolicyContainerPolicies(),
      mock_policy_container_host.BindNewEndpointAndPassDedicatedRemote());
  page_holder->GetFrame().Loader().CommitNavigation(std::move(params), nullptr);

  EXPECT_EQ(perf, DOMWindowPerformance::performance(
                      *page_holder->GetFrame().DomWindow()));
  EXPECT_EQ(timing, perf->timing());
  EXPECT_EQ(page_holder->GetFrame().DomWindow(), perf->DomWindow());
  EXPECT_EQ(page_holder->GetFrame().DomWindow(), timing->DomWindow());
  EXPECT_LE(navigation_start, timing->navigationStart());
}

// Make sure the output entries with the same timestamps follow the insertion
// order. (http://crbug.com/767560)
TEST_F(WindowPerformanceTest, EnsureEntryListOrder) {
  // Need to have an active V8 context for ScriptValues to operate.
  v8::HandleScope handle_scope(GetScriptState()->GetIsolate());
  v8::Local<v8::Context> context = GetScriptState()->GetContext();
  v8::Context::Scope context_scope(context);
  auto initial_offset =
      test_task_runner_->NowTicks().since_origin().InSecondsF();
  test_task_runner_->FastForwardBy(GetTimeOrigin() - base::TimeTicks());

  DummyExceptionStateForTesting exception_state;
  test_task_runner_->FastForwardBy(base::Seconds(2));
  for (int i = 0; i < 8; i++) {
    performance_->mark(GetScriptState(), AtomicString::Number(i), nullptr,
                       exception_state);
  }
  test_task_runner_->FastForwardBy(base::Seconds(2));
  for (int i = 8; i < 17; i++) {
    performance_->mark(GetScriptState(), AtomicString::Number(i), nullptr,
                       exception_state);
  }
  PerformanceEntryVector entries =
      performance_->getEntriesByType(performance_entry_names::kMark);
  EXPECT_EQ(17U, entries.size());
  for (int i = 0; i < 8; i++) {
    EXPECT_EQ(AtomicString::Number(i), entries[i]->name());
    EXPECT_NEAR(2000, entries[i]->startTime() - initial_offset, 0.005);
  }
  for (int i = 8; i < 17; i++) {
    EXPECT_EQ(AtomicString::Number(i), entries[i]->name());
    EXPECT_NEAR(4000, entries[i]->startTime() - initial_offset, 0.005);
  }
}

TEST_F(WindowPerformanceTest, EventTimingEntryBuffering) {
  EXPECT_TRUE(page_holder_->GetFrame().Loader().GetDocumentLoader());

  base::TimeTicks start_time = GetTimeOrigin() + base::Seconds(1.1);
  base::TimeTicks processing_start = GetTimeOrigin() + base::Seconds(3.3);
  base::TimeTicks processing_end = GetTimeOrigin() + base::Seconds(3.8);
  RegisterPointerEvent(event_type_names::kClick, start_time, processing_start,
                       processing_end, 4);
  base::TimeTicks presentation_time = GetTimeOrigin() + base::Seconds(6.0);
  SimulatePaintAndResolvePresentationPromise(presentation_time);
  EXPECT_EQ(1u, performance_
                    ->getBufferedEntriesByType(performance_entry_names::kEvent)
                    .size());

  page_holder_->GetFrame()
      .Loader()
      .GetDocumentLoader()
      ->GetTiming()
      .MarkLoadEventStart();
  RegisterPointerEvent(event_type_names::kClick, start_time, processing_start,
                       processing_end, 4);
  SimulatePaintAndResolvePresentationPromise(presentation_time);
  EXPECT_EQ(2u, performance_
                    ->getBufferedEntriesByType(performance_entry_names::kEvent)
                    .size());

  EXPECT_TRUE(page_holder_->GetFrame().Loader().GetDocumentLoader());
  GetFrame()->DetachDocument();
  EXPECT_FALSE(page_holder_->GetFrame().Loader().GetDocumentLoader());
  RegisterPointerEvent(event_type_names::kClick, start_time, processing_start,
                       processing_end, 4);
  SimulatePaintAndResolvePresentationPromise(presentation_time);
  EXPECT_EQ(3u, performance_
                    ->getBufferedEntriesByType(performance_entry_names::kEvent)
                    .size());
}

TEST_F(WindowPerformanceTest, Expose100MsEvents) {
  base::TimeTicks start_time = GetTimeOrigin() + base::Seconds(1);
  base::TimeTicks processing_start = start_time + base::Milliseconds(10);
  base::TimeTicks processing_end = processing_start + base::Milliseconds(10);
  RegisterPointerEvent(event_type_names::kMousedown, start_time,
                       processing_start, processing_end, 4);

  base::TimeTicks start_time2 = start_time + base::Microseconds(200);
  RegisterPointerEvent(event_type_names::kClick, start_time2, processing_start,
                       processing_end, 4);

  // The presentation time is 100.1 ms after |start_time| but only 99.9 ms after
  // |start_time2|.
  base::TimeTicks presentation_time = start_time + base::Microseconds(100100);
  SimulatePaintAndResolvePresentationPromise(presentation_time);
  // Only the longer event should have been reported.
  const auto& entries =
      performance_->getBufferedEntriesByType(performance_entry_names::kEvent);
  EXPECT_EQ(1u, entries.size());
  EXPECT_EQ(event_type_names::kMousedown, entries.at(0)->name());
}

TEST_F(WindowPerformanceTest, EventTimingDuration) {
  base::TimeTicks start_time = GetTimeOrigin() + base::Milliseconds(1000);
  base::TimeTicks processing_start = GetTimeOrigin() + base::Milliseconds(1001);
  base::TimeTicks processing_end = GetTimeOrigin() + base::Milliseconds(1002);
  RegisterPointerEvent(event_type_names::kClick, start_time, processing_start,
                       processing_end, 4);
  base::TimeTicks short_presentation_time =
      GetTimeOrigin() + base::Milliseconds(1003);
  SimulatePaintAndResolvePresentationPromise(short_presentation_time);
  EXPECT_EQ(0u, performance_
                    ->getBufferedEntriesByType(performance_entry_names::kEvent)
                    .size());

  RegisterPointerEvent(event_type_names::kClick, start_time, processing_start,
                       processing_end, 4);
  base::TimeTicks long_presentation_time =
      GetTimeOrigin() + base::Milliseconds(2000);
  SimulatePaintAndResolvePresentationPromise(long_presentation_time);
  EXPECT_EQ(1u, performance_
                    ->getBufferedEntriesByType(performance_entry_names::kEvent)
                    .size());

  RegisterPointerEvent(event_type_names::kClick, start_time, processing_start,
                       processing_end, 4);
  SimulatePaintAndResolvePresentationPromise(short_presentation_time);
  RegisterPointerEvent(event_type_names::kClick, start_time, processing_start,
                       processing_end, 4);
  SimulatePaintAndResolvePresentationPromise(long_presentation_time);
  EXPECT_EQ(2u, performance_
                    ->getBufferedEntriesByType(performance_entry_names::kEvent)
                    .size());
}

// Test the case where multiple events are registered and then their
// presentation promise is resolved.
TEST_F(WindowPerformanceTest, MultipleEventsThenPresent) {
  size_t num_events = 10;
  for (size_t i = 0; i < num_events; ++i) {
    base::TimeTicks start_time = GetTimeOrigin() + base::Seconds(i);
    base::TimeTicks processing_start = start_time + base::Milliseconds(100);
    base::TimeTicks processing_end = start_time + base::Milliseconds(200);
    RegisterPointerEvent(event_type_names::kClick, start_time, processing_start,
                         processing_end, 4);
    EXPECT_EQ(
        0u,
        performance_->getBufferedEntriesByType(performance_entry_names::kEvent)
            .size());
  }
  base::TimeTicks presentation_time =
      GetTimeOrigin() + base::Seconds(num_events);
  SimulatePaintAndResolvePresentationPromise(presentation_time);
  EXPECT_EQ(
      num_events,
      performance_->getBufferedEntriesByType(performance_entry_names::kEvent)
          .size());
}

// Test the case where commit finish timestamps are recorded on all pending
// EventTimings.
TEST_F(WindowPerformanceTest,
       CommitFinishTimeRecordedOnAllPendingEventTimings) {
  size_t num_events = 3;
  for (size_t i = 0; i < num_events; ++i) {
    base::TimeTicks start_time = GetTimeOrigin() + base::Seconds(i);
    base::TimeTicks processing_start = start_time + base::Milliseconds(100);
    base::TimeTicks processing_end = start_time + base::Milliseconds(200);
    RegisterPointerEvent(event_type_names::kClick, start_time, processing_start,
                         processing_end, 4);
  }
  auto* event_timing_entries = GetWindowPerformanceEventTimingEntries();
  EXPECT_EQ(event_timing_entries->size(), 3u);
  for (const auto event_data : *event_timing_entries) {
    EXPECT_FALSE(event_data->GetEventTimingReportingInfo()
                     ->commit_finish_time.has_value());
  }
  base::TimeTicks commit_finish_time = GetTimeOrigin() + base::Seconds(2);
  performance_->SetCommitFinishTimeStampForPendingEvents(commit_finish_time);
  for (const auto event_data : *event_timing_entries) {
    EXPECT_TRUE(event_data->GetEventTimingReportingInfo()
                    ->commit_finish_time.has_value());
    EXPECT_EQ(
        event_data->GetEventTimingReportingInfo()->commit_finish_time.value(),
        commit_finish_time);
  }
}

// Test the case where a new commit finish timestamps does not affect previous
// EventTiming who has already seen a commit finish.
TEST_F(WindowPerformanceTest, NewCommitNotOverwritePreviousEventTimings) {
  base::TimeTicks start_time = GetTimeOrigin() + base::Seconds(1);
  base::TimeTicks processing_start = start_time + base::Milliseconds(100);
  base::TimeTicks processing_end = start_time + base::Milliseconds(200);
  RegisterPointerEvent(event_type_names::kClick, start_time, processing_start,
                       processing_end, 4);
  base::TimeTicks commit_finish_time = GetTimeOrigin() + base::Seconds(2);
  performance_->SetCommitFinishTimeStampForPendingEvents(commit_finish_time);
  auto* event_timing_entries = GetWindowPerformanceEventTimingEntries();
  EXPECT_EQ(event_timing_entries->size(), 1u);
  EXPECT_EQ(event_timing_entries->at(0)
                ->GetEventTimingReportingInfo()
                ->commit_finish_time,
            commit_finish_time);
  // Set a new commit finish timestamp.
  base::TimeTicks commit_finish_time_1 = commit_finish_time + base::Seconds(1);
  performance_->SetCommitFinishTimeStampForPendingEvents(commit_finish_time_1);
  EXPECT_EQ(event_timing_entries->at(0)
                ->GetEventTimingReportingInfo()
                ->commit_finish_time,
            commit_finish_time);
  EXPECT_NE(event_timing_entries->at(0)
                ->GetEventTimingReportingInfo()
                ->commit_finish_time,
            commit_finish_time_1);
}

// Test for existence of 'first-input' given different types of first events.
TEST_F(WindowPerformanceTest, FirstInput) {
  struct {
    AtomicString event_type;
    bool should_report;
  } inputs[] = {{event_type_names::kClick, true},
                {event_type_names::kKeydown, true},
                {event_type_names::kKeypress, false},
                {event_type_names::kPointerdown, false},
                {event_type_names::kMousedown, true},
                {event_type_names::kMouseover, false}};
  for (const auto& input : inputs) {
    // first-input does not have a |duration| threshold so use close values.
    if (input.event_type == event_type_names::kKeydown ||
        input.event_type == event_type_names::kKeypress) {
      RegisterKeyboardEvent(input.event_type, GetTimeOrigin(),
                            GetTimeOrigin() + base::Milliseconds(1),
                            GetTimeOrigin() + base::Milliseconds(2), 4);
    } else {
      RegisterPointerEvent(input.event_type, GetTimeOrigin(),
                           GetTimeOrigin() + base::Milliseconds(1),
                           GetTimeOrigin() + base::Milliseconds(2), 4);
    }
    SimulatePaintAndResolvePresentationPromise(GetTimeOrigin() +
                                               base::Milliseconds(3));
    PerformanceEntryVector firstInputs =
        performance_->getEntriesByType(performance_entry_names::kFirstInput);
    EXPECT_GE(1u, firstInputs.size());
    EXPECT_EQ(input.should_report, firstInputs.size() == 1u);
    ResetPerformance();
  }
}

// Test that the 'first-input' is populated after some irrelevant events are
// ignored.
TEST_F(WindowPerformanceTest, FirstInputAfterIgnored) {
  AtomicString several_events[] = {event_type_names::kMouseover,
                                   event_type_names::kMousedown,
                                   event_type_names::kPointerup};
  for (const auto& event : several_events) {
    RegisterPointerEvent(event, GetTimeOrigin(),
                         GetTimeOrigin() + base::Milliseconds(1),
                         GetTimeOrigin() + base::Milliseconds(2), 4);
    SimulatePaintAndResolvePresentationPromise(GetTimeOrigin() +
                                               base::Milliseconds(3));
  }
  ASSERT_EQ(1u,
            performance_->getEntriesByType(performance_entry_names::kFirstInput)
                .size());
  EXPECT_EQ(
      event_type_names::kMousedown,
      performance_->getEntriesByType(performance_entry_names::kFirstInput)[0]
          ->name());
}

// Test that pointerdown followed by pointerup works as a 'firstInput'.
TEST_F(WindowPerformanceTest, FirstPointerUp) {
  base::TimeTicks start_time = GetTimeStamp(0);
  base::TimeTicks processing_start = GetTimeStamp(1);
  base::TimeTicks processing_end = GetTimeStamp(2);
  base::TimeTicks presentation_time = GetTimeStamp(3);
  RegisterPointerEvent(event_type_names::kPointerdown, start_time,
                       processing_start, processing_end, 4);
  SimulatePaintAndResolvePresentationPromise(presentation_time);
  EXPECT_EQ(0u,
            performance_->getEntriesByType(performance_entry_names::kFirstInput)
                .size());
  RegisterPointerEvent(event_type_names::kPointerup, start_time,
                       processing_start, processing_end, 4);
  SimulatePaintAndResolvePresentationPromise(presentation_time);
  EXPECT_EQ(1u,
            performance_->getEntriesByType(performance_entry_names::kFirstInput)
                .size());
  // The name of the entry should be event_type_names::kPointerdown.
  EXPECT_EQ(1u, performance_
                    ->getEntriesByName(event_type_names::kPointerdown,
                                       performance_entry_names::kFirstInput)
                    .size());
}

// When the pointerdown is optimized out, the mousedown works as a
// 'first-input'.
TEST_F(WindowPerformanceTest, PointerdownOptimizedOut) {
  base::TimeTicks start_time = GetTimeStamp(0);
  base::TimeTicks processing_start = GetTimeStamp(1);
  base::TimeTicks processing_end = GetTimeStamp(2);
  base::TimeTicks presentation_time = GetTimeStamp(3);
  RegisterPointerEvent(event_type_names::kMousedown, start_time,
                       processing_start, processing_end, 4);
  SimulatePaintAndResolvePresentationPromise(presentation_time);
  EXPECT_EQ(1u,
            performance_->getEntriesByType(performance_entry_names::kFirstInput)
                .size());
  // The name of the entry should be event_type_names::kMousedown.
  EXPECT_EQ(1u, performance_
                    ->getEntriesByName(event_type_names::kMousedown,
                                       performance_entry_names::kFirstInput)
                    .size());
}

// Test that pointerdown followed by mousedown, pointerup works as a
// 'first-input'.
TEST_F(WindowPerformanceTest, PointerdownOnDesktop) {
  base::TimeTicks start_time = GetTimeStamp(0);
  base::TimeTicks processing_start = GetTimeStamp(1);
  base::TimeTicks processing_end = GetTimeStamp(2);
  base::TimeTicks presentation_time = GetTimeStamp(3);
  RegisterPointerEvent(event_type_names::kPointerdown, start_time,
                       processing_start, processing_end, 4);
  SimulatePaintAndResolvePresentationPromise(presentation_time);
  EXPECT_EQ(0u,
            performance_->getEntriesByType(performance_entry_names::kFirstInput)
                .size());
  RegisterPointerEvent(event_type_names::kMousedown, start_time,
                       processing_start, processing_end, 4);
  SimulatePaintAndResolvePresentationPromise(presentation_time);
  EXPECT_EQ(0u,
            performance_->getEntriesByType(performance_entry_names::kFirstInput)
                .size());
  RegisterPointerEvent(event_type_names::kPointerup, start_time,
                       processing_start, processing_end, 4);
  SimulatePaintAndResolvePresentationPromise(presentation_time);
  EXPECT_EQ(1u,
            performance_->getEntriesByType(performance_entry_names::kFirstInput)
                .size());
  // The name of the entry should be event_type_names::kPointerdown.
  EXPECT_EQ(1u, performance_
                    ->getEntriesByName(event_type_names::kPointerdown,
                                       performance_entry_names::kFirstInput)
                    .size());
}

TEST_F(WindowPerformanceTest, OneKeyboardInteraction) {
  base::TimeTicks keydown_timestamp = GetTimeStamp(0);
  // Keydown
  base::TimeTicks processing_start_keydown = GetTimeStamp(1);
  base::TimeTicks processing_end_keydown = GetTimeStamp(2);
  base::TimeTicks presentation_time_keydown = GetTimeStamp(5);
  int key_code = 2;
  RegisterKeyboardEvent(event_type_names::kKeydown, keydown_timestamp,
                        processing_start_keydown, processing_end_keydown,
                        key_code);
  SimulatePaintAndResolvePresentationPromise(presentation_time_keydown);
  // Keyup
  base::TimeTicks keyup_timestamp = GetTimeStamp(3);
  base::TimeTicks processing_start_keyup = GetTimeStamp(5);
  base::TimeTicks processing_end_keyup = GetTimeStamp(6);
  base::TimeTicks presentation_time_keyup = GetTimeStamp(10);
  RegisterKeyboardEvent(event_type_names::kKeyup, keyup_timestamp,
                        processing_start_keyup, processing_end_keyup, key_code);
  SimulatePaintAndResolvePresentationPromise(presentation_time_keyup);

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
      10);
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

TEST_F(WindowPerformanceTest, HoldingDownAKey) {
  auto entries = GetUkmRecorder()->GetEntriesByName(
      ukm::builders::Responsiveness_UserInteraction::kEntryName);
  EXPECT_EQ(0u, entries.size());
  base::TimeTicks keydown_timestamp = GetTimeOrigin();
  base::TimeTicks processing_start_keydown = GetTimeStamp(1);
  base::TimeTicks processing_end_keydown = GetTimeStamp(2);
  base::TimeTicks presentation_time_keydown = GetTimeStamp(5);
  int key_code = 2;
  RegisterKeyboardEvent(event_type_names::kKeydown, keydown_timestamp,
                        processing_start_keydown, processing_end_keydown,
                        key_code);
  SimulatePaintAndResolvePresentationPromise(presentation_time_keydown);

  // Second Keydown
  keydown_timestamp = GetTimeStamp(1);
  processing_start_keydown = GetTimeStamp(2);
  processing_end_keydown = GetTimeStamp(3);
  presentation_time_keydown = GetTimeStamp(7);
  RegisterKeyboardEvent(event_type_names::kKeydown, keydown_timestamp,
                        processing_start_keydown, processing_end_keydown,
                        key_code);
  SimulatePaintAndResolvePresentationPromise(presentation_time_keydown);

  // Third Keydown
  keydown_timestamp = GetTimeS
```