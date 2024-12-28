Response:
Let's break down the request and the thought process for generating the answer.

**1. Understanding the Core Request:**

The primary goal is to understand the functionality of the `soft_navigation_heuristics_test.cc` file in the Chromium Blink engine. The request specifically asks to:

* **List its functions:** What does this file *do*?
* **Relate to web technologies (JS, HTML, CSS):** How does it interact with these frontend languages?
* **Provide logic examples (input/output):**  Illustrate the behavior with concrete cases.
* **Highlight common user/programming errors:** What mistakes can happen related to this code?
* **Explain user steps leading here (debugging):**  How would a developer end up looking at this file?

**2. Initial Code Analysis (Skimming and Key Elements):**

I started by quickly reading through the code, looking for key indicators:

* **`// Copyright ...`:** Basic licensing information, not directly functional.
* **`#include ...`:**  A list of dependencies. This is crucial for understanding what the code relies on. I noted things like:
    * `SoftNavigationHeuristics.h`:  This is the code being tested!
    * `testing/gtest/include/gtest/gtest.h`:  Indicates this is a unit test file using Google Test.
    * `.../renderer/bindings/core/v8/...`:  Suggests interaction with JavaScript.
    * `.../core/dom/events/...`:  Deals with DOM events.
    * `.../core/html/...`:  Involves HTML elements.
    * `.../core/timing/soft_navigation_context.h`:  Relates to the concept of a soft navigation.
    * `.../platform/scheduler/...`:  Connects to Blink's task scheduling.
* **`namespace blink { ... }`:** The code resides within the `blink` namespace.
* **`class SoftNavigationHeuristicsTest : public testing::Test { ... }`:**  Confirms this is a test fixture.
* **`SetUp()`:** A common setup method in Google Test. It creates a `DummyPageHolder`, which simulates a web page environment.
* **`CreateSoftNavigationHeuristicsForTest()`, `GetScriptStateForTest()`, `GetDocument()`:**  Helper functions to get necessary Blink objects for testing.
* **`IsDocumentTrackingSoftNavigations()`:**  A method to check the state of soft navigation tracking.
* **`KeyboardEventScopeTypeToEventName()`, `CreateEvent()`:** Functions to create synthetic DOM events for testing. This immediately suggests the tests involve simulating user interactions.
* **`TEST_F(SoftNavigationHeuristicsTest, ...)`:**  The individual test cases. Reading the names of these tests provides high-level insights into the tested scenarios (e.g., "EarlyReturnOnInvalidPendingInteractionTimestamp", "ResetHeuristicOnSetBecameEmpty", "NestedEventScopesAreMerged").

**3. Deeper Dive into Functionality (Test Case Analysis):**

I then examined the individual test cases more closely:

* **What each test aims to verify:** I tried to understand the specific behavior each test is checking. For example, `EarlyReturnOnInvalidPendingInteractionTimestamp` tests a specific edge case where a timestamp is missing. `ResetHeuristicOnSetBecameEmpty` checks how the heuristics are reset when there are no longer active contexts.
* **How the tests simulate scenarios:** I looked at how the tests create events, trigger callbacks, and interact with the `SoftNavigationHeuristics` class. The use of `MaybeCreateEventScopeForEvent`, `MaybeCreateTaskScopeForCallback`, `ModifiedDOM`, and `SameDocumentNavigationCommitted` are key actions.
* **The assertions (`ASSERT_TRUE`, `EXPECT_FALSE`, `EXPECT_EQ`):** These tell us what the expected outcome of the test is.

**4. Connecting to Web Technologies:**

Based on the code and test cases, I identified the relationships to JavaScript, HTML, and CSS:

* **JavaScript:** The tests simulate JavaScript event handlers triggering actions that might lead to soft navigations. The interaction with `ScriptState` and the creation of events that JavaScript code would typically handle are direct connections.
* **HTML:** The creation of `HTMLBodyElement` and `HTMLDivElement` as event targets shows the tests are working within the context of a basic HTML structure.
* **CSS:** While not directly manipulated in this *test* file, the concept of soft navigation is relevant to how CSS changes are handled during such navigations (e.g., avoiding full style recalculations).

**5. Developing Examples and Scenarios:**

With a good understanding of the tests, I could create:

* **Input/Output Examples:** I chose scenarios from the tests themselves (like clicking a link or triggering a JavaScript navigation) and described the expected behavior of the `SoftNavigationHeuristics`.
* **Common Errors:** I considered what could go wrong based on the code's logic, such as forgetting to set a timestamp or having unexpected event ordering.
* **Debugging Steps:** I imagined a developer encountering a bug related to soft navigations and how they might step through the code, eventually landing in this test file to understand the heuristics.

**6. Structuring the Answer:**

Finally, I organized the information into the requested categories, providing clear explanations and examples for each point. I aimed for a balance of technical detail and understandable language. I used bullet points and code snippets to make the information easier to digest.

**Self-Correction/Refinement during the process:**

* **Initial Focus on Individual Tests:** I initially focused heavily on explaining each test case in isolation. I realized it was more effective to synthesize the information and extract common themes and functionalities.
* **Clarifying the "Why":** I made sure to explain *why* these heuristics are important (performance, user experience) rather than just describing *what* they do.
* **Improving Examples:** I tried to make the examples more concrete and relatable to common web development scenarios.

By following this process of analysis, connection, and synthesis, I was able to generate a comprehensive answer that addresses all aspects of the original request.
这个文件 `soft_navigation_heuristics_test.cc` 是 Chromium Blink 引擎中的一个 **单元测试文件**。它的主要功能是 **测试 `SoftNavigationHeuristics` 类的各种功能和逻辑**。

`SoftNavigationHeuristics` 类的目的是 **通过一系列的启发式规则来判断当前发生的行为是否属于“软导航”** (soft navigation)。软导航是指在同一个页面内部发生的、类似于页面跳转但不需要重新加载整个页面的行为，例如单页应用 (SPA) 中的路由切换。

下面详细列举一下这个测试文件的功能，并结合 JavaScript、HTML、CSS 的关系进行说明：

**1. 功能概述:**

* **测试软导航的识别逻辑:**  核心功能是验证 `SoftNavigationHeuristics` 类能否正确地识别各种触发软导航的事件和操作。
* **模拟用户交互:** 通过创建和分发各种 DOM 事件 (例如 `click`, `keydown`, `keypress`, `keyup`, `navigate`) 来模拟用户的操作。
* **测试不同场景下的行为:**  涵盖了多种场景，例如：
    * 简单的点击事件触发软导航。
    * 键盘事件触发软导航。
    * `navigate` 事件触发软导航。
    * 嵌套的事件作用域。
    * 在软导航检测之后发生的事件处理。
    * 异步的同文档导航。
* **验证启发式规则的正确性:**  测试各种启发式规则是否按照预期工作，例如：
    * 检查事件是否是可信的 (trusted)。
    * 检查键盘事件的目标元素是否是 `<body>`。
    * 检查是否发生了 DOM 修改 (`ModifiedDOM`)。
    * 检查是否提交了同文档导航 (`SameDocumentNavigationCommitted`)。
* **测试垃圾回收 (GC) 的影响:**  验证在垃圾回收过程中，软导航的检测状态是否保持一致。
* **测试软导航事件的触发次数:**  确保软导航事件只在应该触发的时候触发一次。
* **测试异步同文档导航的启动和提交:**  验证 `AsyncSameDocumentNavigationStarted` 和 `CommitSameDocumentNavigation` 的正确性。

**2. 与 JavaScript, HTML, CSS 的关系及举例说明:**

`SoftNavigationHeuristics` 类的工作直接与 JavaScript 和 HTML 的行为相关，而间接地与 CSS 相关。

* **JavaScript:**
    * **事件监听器:** 用户在网页上的操作（例如点击按钮、输入文本）通常会触发 JavaScript 事件监听器。`SoftNavigationHeuristics` 会监听这些事件来判断是否是软导航的开始。
    * **路由切换:** 在 SPA 中，JavaScript 代码会监听路由变化事件（例如使用 `history.pushState` 或 Hash 路由），然后动态更新页面内容。`SoftNavigationHeuristics` 需要识别这些路由切换是否属于软导航。
    * **异步操作:**  JavaScript 可以执行异步操作来更新页面内容，例如使用 `fetch` API 获取数据并更新 DOM。`SoftNavigationHeuristics` 需要考虑这些异步操作对软导航判断的影响。

    **举例:**  测试用例 `ResetHeuristicOnSetBecameEmpty` 模拟了一个 `click` 事件，这通常对应用户在 HTML 元素上点击，而这个点击事件可能会触发 JavaScript 代码执行，进行页面内容的更新，最终可能被判定为软导航。

* **HTML:**
    * **DOM 结构:** `SoftNavigationHeuristics` 会检查事件的目标元素，例如键盘事件的目标必须是 `<body>` 元素才能被认为是潜在的软导航触发事件。
    * **链接 (<a> 标签):**  点击链接是触发页面导航的常见方式。`SoftNavigationHeuristics` 需要区分传统的页面跳转和同文档的“软”跳转。

    **举例:** 测试用例 `MaybeCreateEventScopeForEvent` 中创建了 `HTMLBodyElement` 和 `HTMLDivElement` 作为事件的目标，用以测试 `SoftNavigationHeuristics` 如何根据事件目标来判断是否需要创建事件作用域。

* **CSS:**
    * **样式变化:** 虽然 `SoftNavigationHeuristics` 不直接操作 CSS，但软导航通常会导致页面样式的变化。引擎需要确保在软导航过程中，CSS 的更新和渲染能够正确执行。

    **间接关系举例:**  一个 SPA 应用程序使用 JavaScript 路由切换来更新页面内容，这可能会涉及到修改 HTML 结构和动态加载不同的 CSS 样式。`SoftNavigationHeuristics` 的正确工作可以帮助引擎更好地处理这些样式变化，例如避免不必要的重绘和重排。

**3. 逻辑推理的假设输入与输出:**

以下是一些测试用例的逻辑推理示例：

* **测试用例: `EarlyReturnOnInvalidPendingInteractionTimestamp`**
    * **假设输入:** 一个没有设置有效时间戳的交互事件 (`kKeypress`)。
    * **预期输出:**  `SoftNavigationHeuristics` 不会因为缺少时间戳而崩溃，而是提前返回。

* **测试用例: `ResetHeuristicOnSetBecameEmpty`**
    * **假设输入:**
        1. 用户点击一个元素 (`kClick`)，触发一个任务作用域。
        2. 在该任务作用域内，可能进行了一些 DOM 操作。
        3. 当所有与该点击事件相关的任务都完成后，并且没有其他活跃的软导航上下文时。
    * **预期输出:** `IsDocumentTrackingSoftNavigations()` 返回 `false`，表明软导航的跟踪状态被重置。

* **测试用例: `NestedEventScopesAreMerged`**
    * **假设输入:**
        1. 一个 `click` 事件触发了一个外部事件作用域。
        2. 在外部事件作用域的处理过程中，又触发了一个 `navigate` 事件，创建了一个内部事件作用域。
    * **预期输出:** 两个事件作用域共享同一个 `SoftNavigationContext` 对象，表明嵌套的事件被合并处理。

**4. 用户或编程常见的使用错误:**

* **错误地配置启发式规则:** 如果 `SoftNavigationHeuristics` 的启发式规则配置不当，可能会导致误判，将非软导航的行为识别为软导航，或者反之。
* **事件监听器的错误处理:**  如果 JavaScript 代码中的事件监听器处理不当，可能会阻止 `SoftNavigationHeuristics` 观察到关键事件，导致软导航检测失败。
* **异步操作的管理不当:**  如果异步操作导致 DOM 的修改和导航的提交没有在同一个任务中发生，可能会影响 `SoftNavigationHeuristics` 的判断。
* **在不需要的时候重置软导航状态:**  开发者可能错误地手动重置了软导航的跟踪状态，导致后续的软导航检测失效。

**5. 用户操作如何一步步到达这里，作为调试线索:**

当开发者在 Chromium 引擎中调试与软导航相关的性能或行为问题时，可能会逐步深入到 `SoftNavigationHeuristics` 的代码中。以下是可能的调试路径：

1. **用户反馈或性能监控:** 用户报告 SPA 应用在某些页面跳转时性能不佳，或者性能监控工具显示某些操作触发了不必要的页面重绘或重排。
2. **分析性能瓶颈:**  开发者使用 Chromium 的开发者工具 (例如 Performance 面板) 分析性能瓶颈，发现问题可能与页面导航处理有关。
3. **查看渲染流水线:**  开发者可能会查看 Chromium 的渲染流水线，了解页面导航的不同阶段，例如输入事件处理、JavaScript 执行、样式计算、布局、绘制等。
4. **定位到软导航相关的代码:**  如果怀疑是软导航的检测或处理有问题，开发者可能会开始查找与“soft navigation”相关的代码。
5. **进入 `SoftNavigationHeuristics`:**  通过代码搜索或调用栈分析，开发者可能会找到 `SoftNavigationHeuristics` 类，这个类负责判断是否是软导航的关键逻辑。
6. **查看测试文件:**  为了更好地理解 `SoftNavigationHeuristics` 的工作原理和各种场景下的行为，开发者会查看其对应的测试文件 `soft_navigation_heuristics_test.cc`。
7. **阅读测试用例:**  通过阅读测试用例，开发者可以了解 `SoftNavigationHeuristics` 如何处理不同的用户交互和事件，以及其预期的行为。
8. **修改和调试代码:**  如果发现 `SoftNavigationHeuristics` 的逻辑有问题，开发者可能会修改代码并运行相关的测试用例进行验证。

总而言之，`soft_navigation_heuristics_test.cc` 是一个至关重要的测试文件，它确保了 Blink 引擎能够正确地识别和处理软导航，从而提升 SPA 应用的性能和用户体验。它通过模拟各种用户操作和场景，验证了 `SoftNavigationHeuristics` 类的启发式规则和逻辑的正确性。

Prompt: 
```
这是目录为blink/renderer/core/timing/soft_navigation_heuristics_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/timing/soft_navigation_heuristics.h"

#include <memory>

#include "base/notreached.h"
#include "base/time/time.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/scheduler/task_attribution_id.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_keyboard_event_init.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_mouse_event_init.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/event_type_names.h"
#include "third_party/blink/renderer/core/events/keyboard_event.h"
#include "third_party/blink/renderer/core/events/mouse_event.h"
#include "third_party/blink/renderer/core/html/html_body_element.h"
#include "third_party/blink/renderer/core/html/html_div_element.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"
#include "third_party/blink/renderer/core/timing/soft_navigation_context.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/heap/thread_state.h"
#include "third_party/blink/renderer/platform/scheduler/public/task_attribution_info.h"
#include "third_party/blink/renderer/platform/scheduler/public/task_attribution_tracker.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"

namespace blink {

using TaskScope = scheduler::TaskAttributionTracker::TaskScope;
using TaskScopeType = scheduler::TaskAttributionTracker::TaskScopeType;

class SoftNavigationHeuristicsTest : public testing::Test {
 protected:
  void SetUp() override {
    page_holder_ = std::make_unique<DummyPageHolder>(gfx::Size(800, 600));
  }

  SoftNavigationHeuristics* CreateSoftNavigationHeuristicsForTest() {
    ScriptState* script_state = GetScriptStateForTest();

    LocalDOMWindow* window = LocalDOMWindow::From(script_state);

    SoftNavigationHeuristics* heuristics =
        SoftNavigationHeuristics::From(*window);

    return heuristics;
  }

  ScriptState* GetScriptStateForTest() {
    return ToScriptStateForMainWorld(page_holder_->GetDocument().GetFrame());
  }

  Document& GetDocument() { return page_holder_->GetDocument(); }

  bool IsDocumentTrackingSoftNavigations() {
    return LocalDOMWindow::From(GetScriptStateForTest())
        ->document()
        ->IsTrackingSoftNavigationHeuristics();
  }

  static WTF::AtomicString KeyboardEventScopeTypeToEventName(
      SoftNavigationHeuristics::EventScope::Type type) {
    switch (type) {
      case SoftNavigationHeuristics::EventScope::Type::kKeydown:
        return event_type_names::kKeydown;
      case SoftNavigationHeuristics::EventScope::Type::kKeypress:
        return event_type_names::kKeypress;
      case SoftNavigationHeuristics::EventScope::Type::kKeyup:
        return event_type_names::kKeyup;
      default:
        NOTREACHED();
    }
  }

  Event* CreateEvent(SoftNavigationHeuristics::EventScope::Type type) {
    Event* event = nullptr;
    switch (type) {
      case SoftNavigationHeuristics::EventScope::Type::kKeydown:
      case SoftNavigationHeuristics::EventScope::Type::kKeypress:
      case SoftNavigationHeuristics::EventScope::Type::kKeyup:
        event = KeyboardEvent::Create(GetScriptStateForTest(),
                                      KeyboardEventScopeTypeToEventName(type),
                                      KeyboardEventInit::Create());
        event->SetTarget(MakeGarbageCollected<HTMLBodyElement>(GetDocument()));
        break;
      case SoftNavigationHeuristics::EventScope::Type::kClick:
        event = MouseEvent::Create(GetScriptStateForTest(),
                                   event_type_names::kClick,
                                   MouseEventInit::Create());
        break;
      case SoftNavigationHeuristics::EventScope::Type::kNavigate:
        event = Event::Create(event_type_names::kNavigate);
        break;
    }
    event->SetTrusted(true);
    return event;
  }

 private:
  test::TaskEnvironment task_environment_;
  std::unique_ptr<DummyPageHolder> page_holder_;
};

// TODO(crbug.com/1503284): This test validates that the renderer does not crash
// when presented with an unset timestamp. Figure out whether it is possible to
// void ever calling InteractionCallbackCalled in that situation instead.
TEST_F(SoftNavigationHeuristicsTest,
       EarlyReturnOnInvalidPendingInteractionTimestamp) {
  auto* test_heuristics = CreateSoftNavigationHeuristicsForTest();
  // A non-new interaction will try to use the pending timestamp, which will
  // never have been set in this case.
  auto* event =
      CreateEvent(SoftNavigationHeuristics::EventScope::Type::kKeypress);
  std::optional<SoftNavigationHeuristics::EventScope> event_scope(
      test_heuristics->MaybeCreateEventScopeForEvent(*event));
  auto* tracker = scheduler::TaskAttributionTracker::From(
      GetScriptStateForTest()->GetIsolate());
  ASSERT_TRUE(tracker);
  {
    // Simulate a top-level event dispatch with no context to propagate.
    std::optional<TaskScope> task_scope =
        tracker->MaybeCreateTaskScopeForCallback(GetScriptStateForTest(),
                                                 nullptr);
  }
  ASSERT_TRUE(test_heuristics->GetInitialInteractionEncounteredForTest());
}

TEST_F(SoftNavigationHeuristicsTest, ResetHeuristicOnSetBecameEmpty) {
  auto* heuristics = CreateSoftNavigationHeuristicsForTest();
  ASSERT_TRUE(heuristics);

  auto* script_state = GetScriptStateForTest();
  auto* tracker =
      scheduler::TaskAttributionTracker::From(script_state->GetIsolate());
  ASSERT_TRUE(tracker);

  Persistent<scheduler::TaskAttributionInfo> root_task = nullptr;
  // Simulate a click.
  {
    EXPECT_FALSE(IsDocumentTrackingSoftNavigations());
    auto* event =
        CreateEvent(SoftNavigationHeuristics::EventScope::Type::kClick);
    std::optional<SoftNavigationHeuristics::EventScope> event_scope(
        heuristics->MaybeCreateEventScopeForEvent(*event));

    // Simulate a top-level event dispatch with no context to propagate.
    std::optional<TaskScope> task_scope =
        tracker->MaybeCreateTaskScopeForCallback(script_state, nullptr);
    // This won't create a new task scope because there's already one on the
    // stack to propagate the soft navigation context, but it should notify
    // `heuristics`.
    EXPECT_FALSE(task_scope);
    root_task = tracker->RunningTask();
  }
  EXPECT_TRUE(root_task);
  EXPECT_TRUE(IsDocumentTrackingSoftNavigations());

  // Simulate a descendant task.
  Persistent<scheduler::TaskAttributionInfo> descendant_task = nullptr;
  {
    TaskScope task_scope = tracker->CreateTaskScope(script_state, root_task,
                                                    TaskScopeType::kCallback);
    descendant_task = tracker->RunningTask();
  }
  EXPECT_TRUE(descendant_task);

  EXPECT_TRUE(IsDocumentTrackingSoftNavigations());
  EXPECT_EQ(root_task.Get(), descendant_task.Get());

  root_task = nullptr;
  ThreadState::Current()->CollectAllGarbageForTesting();
  // The heuristics still should not have been reset since there is a live
  // root task, which is being held onto by its descendant task.
  EXPECT_TRUE(IsDocumentTrackingSoftNavigations());

  // Finally, this should allow the click task to be GCed, which should cause
  // the heuristics to be reset.
  descendant_task = nullptr;
  ThreadState::Current()->CollectAllGarbageForTesting();
  EXPECT_FALSE(IsDocumentTrackingSoftNavigations());
}

TEST_F(SoftNavigationHeuristicsTest, NestedEventScopesAreMerged) {
  auto* heuristics = CreateSoftNavigationHeuristicsForTest();
  auto* script_state = GetScriptStateForTest();

  auto* event = CreateEvent(SoftNavigationHeuristics::EventScope::Type::kClick);
  std::optional<SoftNavigationHeuristics::EventScope> outer_event_scope(
      heuristics->MaybeCreateEventScopeForEvent(*event));
  auto* tracker = scheduler::TaskAttributionTracker::From(
      GetScriptStateForTest()->GetIsolate());
  ASSERT_TRUE(tracker);

  SoftNavigationContext* context1 = nullptr;
  {
    std::optional<TaskScope> task_scope =
        tracker->MaybeCreateTaskScopeForCallback(script_state, nullptr);
    context1 = tracker->RunningTask()->GetSoftNavigationContext();
  }
  EXPECT_TRUE(context1);

  auto* inner_event =
      CreateEvent(SoftNavigationHeuristics::EventScope::Type::kNavigate);
  std::optional<SoftNavigationHeuristics::EventScope> inner_event_scope(
      heuristics->MaybeCreateEventScopeForEvent(*inner_event));

  SoftNavigationContext* context2 = nullptr;
  {
    std::optional<TaskScope> task_scope =
        tracker->MaybeCreateTaskScopeForCallback(script_state, nullptr);
    context2 = tracker->RunningTask()->GetSoftNavigationContext();
  }
  EXPECT_TRUE(context2);

  EXPECT_EQ(context1, context2);
}

TEST_F(SoftNavigationHeuristicsTest, EventAfterSoftNavDetection) {
  auto* heuristics = CreateSoftNavigationHeuristicsForTest();
  auto* script_state = GetScriptStateForTest();

  auto* outer_event =
      CreateEvent(SoftNavigationHeuristics::EventScope::Type::kClick);
  std::optional<SoftNavigationHeuristics::EventScope> outer_event_scope(
      heuristics->MaybeCreateEventScopeForEvent(*outer_event));
  auto* tracker =
      scheduler::TaskAttributionTracker::From(script_state->GetIsolate());
  ASSERT_TRUE(tracker);

  auto* context = tracker->RunningTask()->GetSoftNavigationContext();
  ASSERT_TRUE(context);

  {
    std::optional<TaskScope> task_scope =
        tracker->MaybeCreateTaskScopeForCallback(script_state, nullptr);
    heuristics->ModifiedDOM();
  }

  // Simulate default action link navigation after the click event.
  heuristics->SameDocumentNavigationCommitted("foo", context);
  {
    auto* inner_event =
        CreateEvent(SoftNavigationHeuristics::EventScope::Type::kNavigate);
    std::optional<SoftNavigationHeuristics::EventScope> inner_event_scope(
        heuristics->MaybeCreateEventScopeForEvent(*inner_event));
  }

  // crbug.com/335945346: Some events, e.g. blur, can fire after all of the soft
  // navigation criteria have been met and all of the input event handlers have
  // run, while there's still an EventScope on the stack. Since
  // SoftNavigationHeuristics::OnCreateTaskScope relies on the active context
  // being non-null, emitting a soft navigation entry and resetting the
  // heuristic prematurely would clear the context while it still may be needed.
  // An event firing here, after the criteria have been met, should not cause a
  // crash.
  {
    std::optional<TaskScope> task_scope =
        tracker->MaybeCreateTaskScopeForCallback(script_state, nullptr);
  }
}

TEST_F(SoftNavigationHeuristicsTest,
       HeuristicNotResetDuringGCWithActiveContext) {
  auto* heuristics = CreateSoftNavigationHeuristicsForTest();
  auto* script_state = GetScriptStateForTest();
  auto* tracker =
      scheduler::TaskAttributionTracker::From(script_state->GetIsolate());
  ASSERT_TRUE(tracker);

  {
    auto* event =
        CreateEvent(SoftNavigationHeuristics::EventScope::Type::kClick);
    std::optional<SoftNavigationHeuristics::EventScope> event_scope(
        heuristics->MaybeCreateEventScopeForEvent(*event));
    {
      std::optional<TaskScope> task_scope =
          tracker->MaybeCreateTaskScopeForCallback(script_state, nullptr);
    }
  }
  // At this point there is a single `SoftNavigationContext` being tracked, but
  // it wasn't propagated anywhere, so it is eligible for GC.
  EXPECT_TRUE(IsDocumentTrackingSoftNavigations());

  auto* event = CreateEvent(SoftNavigationHeuristics::EventScope::Type::kClick);
  std::optional<SoftNavigationHeuristics::EventScope> event_scope(
      heuristics->MaybeCreateEventScopeForEvent(*event));

  // If GC occurs here, e.g. during a blink allocation, the heuristic should not
  // be reset, otherwise the `SoftNavigationContext` created above will be
  // cleared.
  ThreadState::Current()->CollectAllGarbageForTesting(
      cppgc::EmbedderStackState::kMayContainHeapPointers);

  std::optional<TaskScope> task_scope =
      tracker->MaybeCreateTaskScopeForCallback(script_state, nullptr);
  EXPECT_TRUE(IsDocumentTrackingSoftNavigations());
}

TEST_F(SoftNavigationHeuristicsTest, SoftNavigationEmittedOnlyOnce) {
  auto* heuristics = CreateSoftNavigationHeuristicsForTest();
  EXPECT_EQ(heuristics->SoftNavigationCount(), 0u);

  auto* tracker = scheduler::TaskAttributionTracker::From(
      GetScriptStateForTest()->GetIsolate());
  ASSERT_TRUE(tracker);

  auto* script_state = GetScriptStateForTest();
  scheduler::TaskAttributionInfo* task_state = nullptr;
  SoftNavigationContext* context = nullptr;

  {
    auto* event =
        CreateEvent(SoftNavigationHeuristics::EventScope::Type::kClick);
    std::optional<SoftNavigationHeuristics::EventScope> event_scope(
        heuristics->MaybeCreateEventScopeForEvent(*event));
    {
      std::optional<TaskScope> task_scope =
          tracker->MaybeCreateTaskScopeForCallback(script_state, nullptr);
      task_state = tracker->RunningTask();
      ASSERT_TRUE(task_state);
      context = task_state->GetSoftNavigationContext();
      ASSERT_TRUE(context);

      heuristics->SameDocumentNavigationCommitted("foo.html", context);
      heuristics->ModifiedDOM();
    }
  }
  EXPECT_EQ(heuristics->SoftNavigationCount(), 1u);

  {
    std::optional<TaskScope> task_scope =
        tracker->MaybeCreateTaskScopeForCallback(script_state, task_state);
    heuristics->SameDocumentNavigationCommitted("bar.html", context);
    heuristics->ModifiedDOM();
  }
  EXPECT_EQ(heuristics->SoftNavigationCount(), 1u);
}

TEST_F(SoftNavigationHeuristicsTest, AsyncSameDocumentNavigation) {
  auto* heuristics = CreateSoftNavigationHeuristicsForTest();
  EXPECT_EQ(heuristics->SoftNavigationCount(), 0u);

  auto* tracker = scheduler::TaskAttributionTracker::From(
      GetScriptStateForTest()->GetIsolate());
  ASSERT_TRUE(tracker);

  auto* script_state = GetScriptStateForTest();
  scheduler::TaskAttributionInfo* task_state = nullptr;
  SoftNavigationContext* context = nullptr;

  {
    auto* event =
        CreateEvent(SoftNavigationHeuristics::EventScope::Type::kClick);
    std::optional<SoftNavigationHeuristics::EventScope> event_scope(
        heuristics->MaybeCreateEventScopeForEvent(*event));
    task_state = tracker->RunningTask();
    ASSERT_TRUE(task_state);
    context = task_state->GetSoftNavigationContext();
    ASSERT_TRUE(context);
  }

  // Simulate starting a same-document navigation in a JavaScript task
  // associated with `context`.
  std::optional<scheduler::TaskAttributionId> navigation_task_id;
  {
    std::optional<TaskScope> task_scope =
        tracker->MaybeCreateTaskScopeForCallback(script_state, task_state);
    navigation_task_id = heuristics->AsyncSameDocumentNavigationStarted();
  }
  ASSERT_TRUE(navigation_task_id);

  // Simulate committing the same-document navigation asynchronously.
  task_state = tracker->CommitSameDocumentNavigation(*navigation_task_id);
  ASSERT_TRUE(task_state);
  EXPECT_EQ(task_state->GetSoftNavigationContext(), context);

  EXPECT_TRUE(context->Url().empty());
  heuristics->SameDocumentNavigationCommitted("foo.html", context);
  EXPECT_FALSE(context->Url().empty());
}

TEST_F(SoftNavigationHeuristicsTest, AsyncSameDocumentNavigationNoContext) {
  auto* heuristics = CreateSoftNavigationHeuristicsForTest();
  EXPECT_EQ(heuristics->SoftNavigationCount(), 0u);

  auto* tracker = scheduler::TaskAttributionTracker::From(
      GetScriptStateForTest()->GetIsolate());
  ASSERT_TRUE(tracker);

  // Simulate starting a same-document navigation in a JavaScript task that
  // isn't associated with a `SoftNavigationContext`
  std::optional<scheduler::TaskAttributionId> navigation_task_id;
  {
    std::optional<TaskScope> task_scope =
        tracker->MaybeCreateTaskScopeForCallback(GetScriptStateForTest(),
                                                 /*task_state=*/nullptr);
    navigation_task_id = heuristics->AsyncSameDocumentNavigationStarted();
  }
  EXPECT_FALSE(navigation_task_id);

  // Simulate committing the same-document navigation asynchronously without a
  // `SoftNavigationContext`. This shouldn't crash.
  heuristics->SameDocumentNavigationCommitted("foo.html", /*context=*/nullptr);
}

TEST_F(SoftNavigationHeuristicsTest, MaybeCreateEventScopeForEvent) {
  auto* heuristics = CreateSoftNavigationHeuristicsForTest();

  for (unsigned type = 0;
       type <=
       static_cast<unsigned>(SoftNavigationHeuristics::EventScope::Type::kLast);
       type++) {
    auto* event = CreateEvent(
        static_cast<SoftNavigationHeuristics::EventScope::Type>(type));
    auto event_scope = heuristics->MaybeCreateEventScopeForEvent(*event);
    EXPECT_TRUE(event_scope);
  }

  // Untrusted events should be ignored.
  Event* event =
      CreateEvent(SoftNavigationHeuristics::EventScope::Type::kClick);
  event->SetTrusted(false);
  std::optional<SoftNavigationHeuristics::EventScope> event_scope =
      heuristics->MaybeCreateEventScopeForEvent(*event);
  EXPECT_FALSE(event_scope);

  // Unrelated events should be ignored.
  event = Event::Create(event_type_names::kDrag);
  event_scope = heuristics->MaybeCreateEventScopeForEvent(*event);
  EXPECT_FALSE(event_scope);

  // Keyboard events without a target or that target a non-body element should
  // be ignored.
  event = Event::Create(event_type_names::kKeydown);
  event_scope = heuristics->MaybeCreateEventScopeForEvent(*event);
  EXPECT_FALSE(event_scope);
  event->SetTarget(MakeGarbageCollected<HTMLDivElement>(GetDocument()));
  event_scope = heuristics->MaybeCreateEventScopeForEvent(*event);
  EXPECT_FALSE(event_scope);
}

}  // namespace blink

"""

```