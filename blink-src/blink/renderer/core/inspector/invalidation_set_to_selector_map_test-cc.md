Response:
The user wants to understand the functionality of the C++ file `invalidation_set_to_selector_map_test.cc` in the Chromium Blink engine. I need to analyze the code and identify its purpose, how it relates to web technologies, and potential usage scenarios including errors.

Here's a breakdown of the code and my thought process:

1. **Overall Purpose:** The file name strongly suggests this is a test file for `InvalidationSetToSelectorMap`. The presence of `PageTestBase` confirms this is an integration test within the Blink rendering engine.

2. **Key Class Under Test:** The central class is `InvalidationSetToSelectorMap`. Based on the name, it likely maps invalidation sets (used in CSS invalidation) to the CSS selectors that caused those invalidations. This is crucial for understanding why certain style recalculations happen.

3. **Testing Scenarios:** The test cases (`TEST_F`) provide concrete examples of how `InvalidationSetToSelectorMap` is expected to behave. I need to analyze each test case individually.

    * `TrackerLifetime`:  Focuses on the creation and destruction of the `InvalidationSetToSelectorMap` instance based on tracing being enabled or disabled. It confirms that the tracker only exists when DevTools invalidation tracking is active.
    * `ClassMatch`: Tests the scenario where a change in an element's class attribute triggers style invalidation, and the map correctly identifies the matching CSS selector.
    * `ClassMatchWithMultipleInvalidations`: Similar to `ClassMatch`, but with multiple elements affected by the same class change, ensuring all invalidations are tracked.
    * `ClassMatchWithCombine`: Tests how the map handles multiple style rules with the same invalidation set, verifying that all relevant selectors are associated.
    * `SelfInvalidation`: Examines the case where a style change directly affects the element it's defined on (e.g., changing the class of an element with a class-based style). This test looks at different trace events related to scheduling and executing style invalidation.
    * `SubtreeInvalidation`: Tests scenarios where a style rule targets descendants of an element, and changes to the parent element's attributes trigger invalidation in the subtree.
    * `InvalidationSetRemoval`: Checks that the map correctly handles the lifecycle of `InvalidationSet` objects, removing associations when the sets are no longer in use.
    * `StartTracingLate`:  Verifies that the map can start tracking even after the initial page load and style parsing, capturing subsequent invalidations.
    * `StartTracingLateWithNestedRules`: Similar to `StartTracingLate`, but with more complex CSS structure (media queries, supports rules) to ensure the map handles nested rules correctly.
    * `StartTracingLateWithSiblingAndDescendantRules`: Focuses on selectors involving siblings and descendants when tracing starts late.
    * `StartTracingLateWithPendingInsertRule`: Tests the scenario where CSS rules are added dynamically after tracing starts.
    * `HandleRebuildAfterRuleSetChange`: A more complex test that simulates a rebuild of the internal CSS rule structures while tracing is active, ensuring the map maintains correct associations.

4. **Relationship to Web Technologies:**

    * **CSS:** The core of the tests revolves around CSS selectors and how changes in HTML elements trigger style recalculations based on these selectors. The tests explicitly use CSS syntax in `<style>` tags.
    * **HTML:** The tests manipulate HTML elements (using `SetBodyInnerHTML`, `GetElementById`, `setAttribute`, `removeAttribute`) to trigger style invalidations.
    * **JavaScript (Indirect):** While no explicit JavaScript code is present in the test file, the functionality being tested is crucial for how JavaScript interacts with the DOM and CSS. When JavaScript modifies the DOM or CSS properties, this system is responsible for efficiently updating the rendered styles. The DevTools timeline, which relies on this tracing, is a common tool for web developers debugging JavaScript-driven style changes.

5. **Logic and Assumptions:** The tests make assumptions about how the Blink rendering engine works, specifically the style invalidation mechanism. The tracing infrastructure is used to observe the internal workings of the engine.

6. **User/Programming Errors:**  Understanding this code helps identify potential issues:

    * **Incorrect Selector Specificity:**  If a developer writes CSS rules with incorrect specificity, the invalidation tracking can help pinpoint which rules are being triggered unexpectedly.
    * **Unintended Style Recalculations:**  Excessive or unnecessary style recalculations can impact performance. This tool helps understand the cause of these recalculations.
    * **Debugging Dynamic Styles:** When JavaScript dynamically modifies styles, this tracking is invaluable for understanding which CSS rules are affected.

7. **Output Format:** I need to present the information in a clear and organized way, following the user's request to list functionalities, explain relationships to web technologies with examples, provide logical reasoning with inputs/outputs, and highlight common errors.

By following these steps, I can generate a comprehensive and accurate explanation of the provided source code.
这个文件 `blink/renderer/core/inspector/invalidation_set_to_selector_map_test.cc` 是 Chromium Blink 引擎中的一个测试文件，它的主要功能是 **测试 `InvalidationSetToSelectorMap` 类的功能**。

`InvalidationSetToSelectorMap` 的作用是将 CSS 样式规则中的失效集（InvalidationSet）映射到对应的 CSS 选择器。失效集是 Blink 引擎用于优化样式计算的一种机制，它记录了哪些类型的属性变化会影响到哪些样式规则。这个测试文件的目的是验证在各种场景下，`InvalidationSetToSelectorMap` 是否能正确地建立和维护这种映射关系，从而为开发者工具（DevTools）提供更详细的样式失效跟踪信息。

下面详细列举其功能，并说明与 JavaScript、HTML、CSS 的关系：

**功能列举:**

1. **测试 `InvalidationSetToSelectorMap` 的生命周期管理:**
   - 验证在启用和禁用跟踪（tracing）的情况下，`InvalidationSetToSelectorMap` 实例的创建和销毁是否符合预期。
   - **例子:** `TEST_F(InvalidationSetToSelectorMapTest, TrackerLifetime)`  测试用例验证了当启用 `devtools.timeline.invalidationTracking` trace 时，实例被创建，禁用时被销毁。

2. **测试类名（class）匹配场景:**
   - 验证当 HTML 元素的 `class` 属性发生变化时，`InvalidationSetToSelectorMap` 是否能正确识别出与之匹配的 CSS 选择器。
   - **例子:** `TEST_F(InvalidationSetToSelectorMapTest, ClassMatch)` 测试用例中，改变父元素的 class，会触发子元素的样式失效，测试会检查 trace 事件中是否记录了 `.b .x` 这个选择器。
   - **假设输入:** HTML 结构包含带有 class 的元素，CSS 中定义了基于 class 的选择器。修改元素的 class 属性。
   - **预期输出:** Trace 事件中会包含 "Invalidation set matched class" 的记录，并且 `selectors` 列表中包含匹配的 CSS 选择器字符串（例如 ".b .x"）。

3. **测试多个失效场景:**
   - 验证当一个 class 属性的变化影响到多个具有相同选择器的元素时，`InvalidationSetToSelectorMap` 是否能正确跟踪所有这些失效。
   - **例子:** `TEST_F(InvalidationSetToSelectorMapTest, ClassMatchWithMultipleInvalidations)` 测试用例中，多个子元素都拥有相同的 class，父元素 class 的改变会影响到所有子元素。

4. **测试组合选择器场景:**
   - 验证 `InvalidationSetToSelectorMap` 是否能处理包含多个 class 或其他组合的选择器。
   - **例子:** `TEST_F(InvalidationSetToSelectorMapTest, ClassMatchWithCombine)` 测试用例中，CSS 中定义了 `.b .x` 和 `.b .w .x` 两个选择器，当父元素的 class 变为 `b` 时，会同时匹配这两个选择器。

5. **测试自失效（Self Invalidation）场景:**
   - 验证当元素自身的属性变化导致自身样式失效时，`InvalidationSetToSelectorMap` 的行为。
   - **例子:** `TEST_F(InvalidationSetToSelectorMapTest, SelfInvalidation)` 测试用例中，改变元素的 class 会触发自身样式的失效。虽然此测试主要关注 `ScheduleStyleInvalidationTracking` 事件，但也验证了 `StyleInvalidatorInvalidationTracking` 事件中记录了 "Invalidation set invalidates self" 的原因。

6. **测试子树失效（Subtree Invalidation）场景:**
   - 验证当元素的属性变化导致其子树中的元素样式失效时，`InvalidationSetToSelectorMap` 是否能正确识别相关的选择器（例如通配符选择器 `*`）。
   - **例子:** `TEST_F(InvalidationSetToSelectorMapTest, SubtreeInvalidation)` 测试用例中，CSS 定义了 `.b *` 这样的选择器，当父元素的 class 变为 `b` 时，子元素的样式也会失效。

7. **测试失效集移除场景:**
   - 验证当不再需要某个失效集时，`InvalidationSetToSelectorMap` 是否能正确地清理相关的映射关系。
   - **例子:** `TEST_F(InvalidationSetToSelectorMapTest, InvalidationSetRemoval)` 测试用例模拟了创建失效集并进行查找，然后在释放失效集后，确认查找结果为空。

8. **测试延迟启动跟踪（tracing）场景:**
   - 验证在页面加载后，如果才开始启用跟踪，`InvalidationSetToSelectorMap` 是否仍然能正确地记录后续的样式失效信息。
   - **例子:** `TEST_F(InvalidationSetToSelectorMapTest, StartTracingLate)` 以及后续几个 `StartTracingLate` 开头的测试用例，覆盖了各种延迟启动跟踪的场景，包括嵌套规则、兄弟选择器、以及在插入新样式规则之后启动跟踪的情况。

9. **测试在规则集更改后处理重建的情况:**
   - 验证当样式规则集发生变化（例如添加或删除样式表）后，`InvalidationSetToSelectorMap` 是否能正确处理失效数据的重建。
   - **例子:** `TEST_F(InvalidationSetToSelectorMapTest, HandleRebuildAfterRuleSetChange)` 测试用例模拟了在跟踪启动后，插入新的样式表，并验证后续的样式失效跟踪是否正确。

**与 JavaScript, HTML, CSS 的关系:**

这个测试文件直接关联到 Web 前端开发的三大核心技术：

* **CSS (Cascading Style Sheets):**  `InvalidationSetToSelectorMap` 核心就是处理 CSS 样式规则的选择器和失效关系。测试用例中大量使用 CSS 选择器，例如 `.a .x`, `.b *` 等。当 CSS 规则发生变化，或者 HTML 结构变化导致需要重新计算样式时，`InvalidationSetToSelectorMap` 负责记录哪些 CSS 选择器因此失效。
    * **例子:**  在 `TEST_F(InvalidationSetToSelectorMapTest, ClassMatch)` 中，CSS 定义了 `.b .x { color: green; }`，当 HTML 中 `<div id=parent class=a>` 的 class 被修改为 `b` 时，`InvalidationSetToSelectorMap` 需要能识别出 `.b .x` 这个选择器导致了子元素的样式失效。

* **HTML (HyperText Markup Language):** HTML 结构和属性的变化是触发样式失效的关键。测试用例通过修改 HTML 元素的属性（例如 `class` 属性）来模拟触发样式失效的场景。
    * **例子:**  在所有的测试用例中，都使用了 `SetBodyInnerHTML` 来设置 HTML 结构，并使用 `GetElementById` 获取元素，然后通过 `setAttribute` 或 `removeAttribute` 来修改元素的属性，从而触发样式的重新计算。

* **JavaScript (通过 DevTools 间接关联):** 虽然这个 C++ 测试文件本身不包含 JavaScript 代码，但它所测试的功能是 DevTools 中 "性能" 面板下 "渲染" 部分的关键组成部分，特别是 "样式和布局" 相关的跟踪信息。开发者可以通过 JavaScript 动态修改 HTML 结构或 CSS 样式，而 `InvalidationSetToSelectorMap` 记录的失效信息，可以帮助开发者理解这些 JavaScript 操作对渲染性能的影响。
    * **例子:**  假设一个 JavaScript 代码动态地修改了一个元素的 `className`，导致大量元素的样式重新计算。通过 DevTools 的样式失效跟踪，结合 `InvalidationSetToSelectorMap` 提供的信息，开发者可以清晰地看到是哪个 CSS 选择器因为这个 `className` 的修改而触发了失效。

**用户或编程常见的使用错误举例:**

虽然这个文件是测试代码，但它揭示了样式失效跟踪的一些机制，可以帮助理解常见错误：

1. **CSS 选择器过于宽泛导致不必要的样式重计算:**
   - **场景:** 开发者使用了类似 `*` 或标签选择器而没有足够的约束，导致 HTML 中大量元素被包含进失效集。
   - **`InvalidationSetToSelectorMap` 的体现:** 在 DevTools 的样式失效跟踪中，会看到这些宽泛的选择器频繁出现，并且关联到大量的元素失效。
   - **错误示例 (CSS):**
     ```css
     * { margin: 0; padding: 0; } /* 过于宽泛 */
     .container * { color: red; } /* 稍微好一点，但仍然可能影响很多元素 */
     ```
   - **假设输入:** HTML 中有大量的元素，CSS 中有像 `*` 这样的全局选择器。
   - **预期输出:**  DevTools 的样式失效跟踪会显示 `*` 选择器导致了大量元素的样式失效。

2. **频繁修改元素的 class 属性导致样式抖动:**
   - **场景:** JavaScript 代码频繁地添加或移除元素的 class，导致样式不断地重新计算。
   - **`InvalidationSetToSelectorMap` 的体现:** DevTools 的样式失效跟踪会显示大量的 "Invalidation set matched class" 事件，并且关联到被频繁修改的 class 选择器。
   - **错误示例 (JavaScript):**
     ```javascript
     const element = document.getElementById('myElement');
     setInterval(() => {
       element.classList.toggle('active');
     }, 100); // 频繁切换 class
     ```
   - **假设输入:**  HTML 中有一个元素，JavaScript 代码以很高的频率切换该元素的 class。
   - **预期输出:** DevTools 的样式失效跟踪会记录到针对与该 class 相关的 CSS 选择器的大量失效事件。

3. **不必要的属性继承失效:**
   - **场景:** 修改了父元素的某个属性，导致子元素继承该属性的样式也需要重新计算，即使子元素的样式并没有直接依赖这个属性。
   - **`InvalidationSetToSelectorMap` 的体现:**  虽然 `InvalidationSetToSelectorMap` 主要关注选择器匹配，但通过分析失效的原因，可以间接发现这种由于继承导致的失效。

总而言之，`blink/renderer/core/inspector/invalidation_set_to_selector_map_test.cc` 是一个关键的测试文件，用于确保 Blink 引擎能够准确地跟踪 CSS 样式失效的原因，并将失效集与触发失效的 CSS 选择器关联起来。这对于开发者理解和优化 Web 页面的渲染性能至关重要，特别是在使用 DevTools 进行性能分析时。

Prompt: 
```
这是目录为blink/renderer/core/inspector/invalidation_set_to_selector_map_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/inspector/invalidation_set_to_selector_map.h"

#include "base/test/trace_event_analyzer.h"
#include "third_party/blink/renderer/core/css/css_test_helpers.h"
#include "third_party/blink/renderer/core/css/invalidation/invalidation_set.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/html/html_style_element.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"

namespace blink {

class InvalidationSetToSelectorMapTest : public PageTestBase {
 protected:
  void SetUp() override {
    PageTestBase::SetUp();
    CHECK(GetInstance() == nullptr);
  }
  void TearDown() override {
    // Ensure we do not carry over an instance from one test to another.
    InvalidationSetToSelectorMap::StartOrStopTrackingIfNeeded(
        GetDocument().GetStyleEngine());
    CHECK(GetInstance() == nullptr);

    PageTestBase::TearDown();
  }

  void StartTracing() {
    trace_analyzer::Start(
        TRACE_DISABLED_BY_DEFAULT("devtools.timeline.invalidationTracking"));
  }
  void StartTracingWithoutInvalidationTracking() {
    trace_analyzer::Start(TRACE_DISABLED_BY_DEFAULT("devtools.timeline"));
  }
  std::unique_ptr<trace_analyzer::TraceAnalyzer> StopTracing() {
    return trace_analyzer::Stop();
  }
  InvalidationSetToSelectorMap* GetInstance() {
    return InvalidationSetToSelectorMap::GetInstanceReference().Get();
  }
};

TEST_F(InvalidationSetToSelectorMapTest, TrackerLifetime) {
  ASSERT_EQ(GetInstance(), nullptr);

  StartTracing();
  SetBodyInnerHTML(R"HTML(<div id=d>D</div>)HTML");
  EXPECT_NE(GetInstance(), nullptr);
  GetElementById("d")->setAttribute(html_names::kStyleAttr,
                                    AtomicString("color: red"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_NE(GetInstance(), nullptr);

  StopTracing();
  GetElementById("d")->setAttribute(html_names::kStyleAttr,
                                    AtomicString("color: green"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(GetInstance(), nullptr);

  StartTracingWithoutInvalidationTracking();
  GetElementById("d")->setAttribute(html_names::kStyleAttr,
                                    AtomicString("color: blue"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(GetInstance(), nullptr);
  StopTracing();
}

TEST_F(InvalidationSetToSelectorMapTest, ClassMatch) {
  StartTracing();
  SetBodyInnerHTML(R"HTML(
    <style>
      .a .x { color: red; }
      .b .x { color: green; }
      .c .x { color: blue; }
    </style>
    <div id=parent class=a>Parent
      <div class=x>Child</div>
    </div>
  )HTML");

  GetElementById("parent")->setAttribute(html_names::kClassAttr,
                                         AtomicString("b"));
  UpdateAllLifecyclePhasesForTest();

  auto analyzer = StopTracing();
  trace_analyzer::TraceEventVector events;
  analyzer->FindEvents(trace_analyzer::Query::EventNameIs(
                           "StyleInvalidatorInvalidationTracking"),
                       &events);
  size_t found_event_count = 0;
  for (auto event : events) {
    ASSERT_TRUE(event->HasDictArg("data"));
    base::Value::Dict data_dict = event->GetKnownArgAsDict("data");
    std::string* reason = data_dict.FindString("reason");
    if (reason != nullptr && *reason == "Invalidation set matched class") {
      base::Value::List* selector_list = data_dict.FindList("selectors");
      if (selector_list != nullptr) {
        EXPECT_EQ(selector_list->size(), 1u);
        EXPECT_EQ((*selector_list)[0], ".b .x");
        found_event_count++;
      }
    }
  }
  EXPECT_EQ(found_event_count, 1u);
}

TEST_F(InvalidationSetToSelectorMapTest, ClassMatchWithMultipleInvalidations) {
  StartTracing();
  SetBodyInnerHTML(R"HTML(
    <style>
      .a .x { color: red; }
      .b .x { color: green; }
      .c .x { color: blue; }
    </style>
    <div id=parent class=a>Parent
      <div class=x>Child</div>
      <div class=x>Child</div>
      <div class=x>Child</div>
    </div>
  )HTML");

  GetElementById("parent")->setAttribute(html_names::kClassAttr,
                                         AtomicString("b"));
  UpdateAllLifecyclePhasesForTest();

  auto analyzer = StopTracing();
  trace_analyzer::TraceEventVector events;
  analyzer->FindEvents(trace_analyzer::Query::EventNameIs(
                           "StyleInvalidatorInvalidationTracking"),
                       &events);
  size_t found_event_count = 0;
  for (auto event : events) {
    ASSERT_TRUE(event->HasDictArg("data"));
    base::Value::Dict data_dict = event->GetKnownArgAsDict("data");
    std::string* reason = data_dict.FindString("reason");
    if (reason != nullptr && *reason == "Invalidation set matched class") {
      base::Value::List* selector_list = data_dict.FindList("selectors");
      if (selector_list != nullptr) {
        EXPECT_EQ(selector_list->size(), 1u);
        EXPECT_EQ((*selector_list)[0], ".b .x");
        found_event_count++;
      }
    }
  }
  EXPECT_EQ(found_event_count, 3u);
}

TEST_F(InvalidationSetToSelectorMapTest, ClassMatchWithCombine) {
  StartTracing();
  SetBodyInnerHTML(R"HTML(
    <style>
      .a .x { color: red; }
      .b .x { color: green; }
      .c .x { color: blue; }
    </style>
    <style>
      .b .w .x { color: black; }
    </style>
    <div id=parent class=a>Parent
      <div class=x>Child</div>
    </div>
  )HTML");

  GetElementById("parent")->setAttribute(html_names::kClassAttr,
                                         AtomicString("b"));
  UpdateAllLifecyclePhasesForTest();

  auto analyzer = StopTracing();
  trace_analyzer::TraceEventVector events;
  analyzer->FindEvents(trace_analyzer::Query::EventNameIs(
                           "StyleInvalidatorInvalidationTracking"),
                       &events);
  size_t found_event_count = 0;
  for (auto event : events) {
    ASSERT_TRUE(event->HasDictArg("data"));
    base::Value::Dict data_dict = event->GetKnownArgAsDict("data");
    std::string* reason = data_dict.FindString("reason");
    if (reason != nullptr && *reason == "Invalidation set matched class") {
      base::Value::List* selector_list = data_dict.FindList("selectors");
      if (selector_list != nullptr) {
        EXPECT_EQ(selector_list->size(), 2u);
        // The map stores selectors in a HeapHashSet; they can be output to the
        // trace event list in either order.
        if ((*selector_list)[0] == ".b .x") {
          EXPECT_EQ((*selector_list)[1], ".b .w .x");
        } else {
          EXPECT_EQ((*selector_list)[0], ".b .w .x");
          EXPECT_EQ((*selector_list)[1], ".b .x");
        }
        found_event_count++;
      }
    }
  }
  EXPECT_EQ(found_event_count, 1u);
}

TEST_F(InvalidationSetToSelectorMapTest, SelfInvalidation) {
  StartTracing();
  SetBodyInnerHTML(R"HTML(
    <style>
      .a { color: red; }
      .b { color: green; }
      .c { color: blue; }
    </style>
    <div id=parent class=a>Parent
      <div class=x>Child</div>
    </div>
  )HTML");

  GetElementById("parent")->setAttribute(html_names::kClassAttr,
                                         AtomicString("b"));
  UpdateAllLifecyclePhasesForTest();

  auto analyzer = StopTracing();
  trace_analyzer::TraceEventVector events;

  analyzer->FindEvents(
      trace_analyzer::Query::EventNameIs("ScheduleStyleInvalidationTracking") ||
          trace_analyzer::Query::EventNameIs(
              "StyleInvalidatorInvalidationTracking"),
      &events);
  ASSERT_EQ(events.size(), 4u);
  EXPECT_EQ(events[0]->name, "ScheduleStyleInvalidationTracking");
  EXPECT_EQ(*(events[0]->GetKnownArgAsDict("data").FindString(
                "invalidatedSelectorId")),
            "class");
  EXPECT_EQ(*(events[0]->GetKnownArgAsDict("data").FindString("changedClass")),
            "b");
  EXPECT_EQ(events[1]->name, "ScheduleStyleInvalidationTracking");
  EXPECT_EQ(*(events[1]->GetKnownArgAsDict("data").FindString(
                "invalidatedSelectorId")),
            "class");
  EXPECT_EQ(*(events[1]->GetKnownArgAsDict("data").FindString("changedClass")),
            "a");
  // Because self invalidations are largely handled via the Bloom filter and/or
  // the singleton SelfInvalidationSet, we don't expect selectors. But the
  // preceding schedule events do give us context for what changed.
  EXPECT_EQ(events[2]->name, "StyleInvalidatorInvalidationTracking");
  EXPECT_EQ(*(events[2]->GetKnownArgAsDict("data").FindString("reason")),
            "Invalidation set invalidates self");
  EXPECT_EQ(events[3]->name, "StyleInvalidatorInvalidationTracking");
  EXPECT_EQ(*(events[3]->GetKnownArgAsDict("data").FindString("reason")),
            "Invalidation set invalidates self");
}

TEST_F(InvalidationSetToSelectorMapTest, SubtreeInvalidation) {
  StartTracing();
  SetBodyInnerHTML(R"HTML(
    <style>
      .a * { color: red; }
      .b * { color: green; }
      .c * { color: blue; }
    </style>
    <div id=parent class=a>Parent
      <div class=x>Child</div>
    </div>
  )HTML");

  GetElementById("parent")->setAttribute(html_names::kClassAttr,
                                         AtomicString("b"));
  UpdateAllLifecyclePhasesForTest();

  auto analyzer = StopTracing();
  trace_analyzer::TraceEventVector events;
  analyzer->FindEvents(trace_analyzer::Query::EventNameIs(
                           "StyleInvalidatorInvalidationTracking"),
                       &events);
  size_t found_event_count = 0;
  for (auto event : events) {
    ASSERT_TRUE(event->HasDictArg("data"));
    base::Value::Dict data_dict = event->GetKnownArgAsDict("data");
    std::string* reason = data_dict.FindString("reason");
    if (reason != nullptr &&
        *reason == "Invalidation set invalidates subtree") {
      base::Value::List* selector_list = data_dict.FindList("selectors");
      if (selector_list != nullptr) {
        EXPECT_EQ(selector_list->size(), 1u);
        EXPECT_EQ((*selector_list)[0], ".b *");
        found_event_count++;
      }
    }
  }
  EXPECT_EQ(found_event_count, 1u);
}

TEST_F(InvalidationSetToSelectorMapTest, InvalidationSetRemoval) {
  StartTracing();
  SetBodyInnerHTML(R"HTML(<div id=d>D</div>)HTML");
  EXPECT_NE(GetInstance(), nullptr);

  StyleRule* style_rule = To<StyleRule>(
      css_test_helpers::ParseRule(GetDocument(), ".a .b { color: red; }"));
  AtomicString class_name("b");

  using SelectorFeatureType = InvalidationSetToSelectorMap::SelectorFeatureType;
  using IndexedSelector = InvalidationSetToSelectorMap::IndexedSelector;
  using IndexedSelectorList = InvalidationSetToSelectorMap::IndexedSelectorList;

  InvalidationSetToSelectorMap::BeginSelector(style_rule, 0);
  InvalidationSet* invalidation_set =
      DescendantInvalidationSet::Create().release();
  InvalidationSetToSelectorMap::RecordInvalidationSetEntry(
      invalidation_set, SelectorFeatureType::kClass, class_name);
  InvalidationSetToSelectorMap::EndSelector();

  const IndexedSelectorList* result = InvalidationSetToSelectorMap::Lookup(
      invalidation_set, SelectorFeatureType::kClass, class_name);
  EXPECT_TRUE(
      result->Contains(MakeGarbageCollected<IndexedSelector>(style_rule, 0)));

  // Release the invalidation set but retain the pointer so we can confirm that
  // looking it up no longer returns any results.
  EXPECT_TRUE(invalidation_set->HasOneRef());
  invalidation_set->Release();

  result = InvalidationSetToSelectorMap::Lookup(
      invalidation_set, SelectorFeatureType::kClass, class_name);
  EXPECT_EQ(result, nullptr);

  StopTracing();
}

TEST_F(InvalidationSetToSelectorMapTest, StartTracingLate) {
  SetBodyInnerHTML(R"HTML(
    <style>
      .a .x { color: red; }
      .b .x { color: green; }
      .c .x { color: blue; }
    </style>
    <div id=parent class=a>Parent
      <div class=x>Child</div>
    </div>
  )HTML");

  StartTracing();

  GetElementById("parent")->setAttribute(html_names::kClassAttr,
                                         AtomicString("b"));
  UpdateAllLifecyclePhasesForTest();

  auto analyzer = StopTracing();
  trace_analyzer::TraceEventVector events;
  analyzer->FindEvents(trace_analyzer::Query::EventNameIs(
                           "StyleInvalidatorInvalidationTracking"),
                       &events);
  size_t found_event_count = 0;
  for (auto event : events) {
    ASSERT_TRUE(event->HasDictArg("data"));
    base::Value::Dict data_dict = event->GetKnownArgAsDict("data");
    std::string* reason = data_dict.FindString("reason");
    if (reason != nullptr && *reason == "Invalidation set matched class") {
      base::Value::List* selector_list = data_dict.FindList("selectors");
      if (selector_list != nullptr) {
        EXPECT_EQ(selector_list->size(), 1u);
        EXPECT_EQ((*selector_list)[0], ".b .x");
        found_event_count++;
      }
    }
  }
  EXPECT_EQ(found_event_count, 1u);
}

TEST_F(InvalidationSetToSelectorMapTest, StartTracingLateWithNestedRules) {
  SetBodyInnerHTML(R"HTML(
    <style>
      @media screen {
        @supports (color: green) {
          .a .x { color: red; }
          .b .x { color: green; }
          .c .x { color: blue; }
        }
      }
    </style>
    <div id=parent class=a>Parent
      <div class=x>Child</div>
    </div>
  )HTML");

  StartTracing();

  GetElementById("parent")->setAttribute(html_names::kClassAttr,
                                         AtomicString("b"));
  UpdateAllLifecyclePhasesForTest();

  auto analyzer = StopTracing();
  trace_analyzer::TraceEventVector events;
  analyzer->FindEvents(trace_analyzer::Query::EventNameIs(
                           "StyleInvalidatorInvalidationTracking"),
                       &events);
  size_t found_event_count = 0;
  for (auto event : events) {
    ASSERT_TRUE(event->HasDictArg("data"));
    base::Value::Dict data_dict = event->GetKnownArgAsDict("data");
    std::string* reason = data_dict.FindString("reason");
    if (reason != nullptr && *reason == "Invalidation set matched class") {
      base::Value::List* selector_list = data_dict.FindList("selectors");
      if (selector_list != nullptr) {
        EXPECT_EQ(selector_list->size(), 1u);
        EXPECT_EQ((*selector_list)[0], ".b .x");
        found_event_count++;
      }
    }
  }
  EXPECT_EQ(found_event_count, 1u);
}

TEST_F(InvalidationSetToSelectorMapTest,
       StartTracingLateWithSiblingAndDescendantRules) {
  SetBodyInnerHTML(R"HTML(
    <style>
      .a ~ .b { color: red; }
      .a .c { color: green; }
    </style>
    <div id=parent class=a>Parent
      <div class=c>Child</div>
    </div>
  )HTML");

  StartTracing();

  GetElementById("parent")->removeAttribute(html_names::kClassAttr);
  UpdateAllLifecyclePhasesForTest();

  auto analyzer = StopTracing();
  trace_analyzer::TraceEventVector events;
  analyzer->FindEvents(trace_analyzer::Query::EventNameIs(
                           "StyleInvalidatorInvalidationTracking"),
                       &events);
  size_t found_event_count = 0;
  for (auto event : events) {
    ASSERT_TRUE(event->HasDictArg("data"));
    base::Value::Dict data_dict = event->GetKnownArgAsDict("data");
    std::string* reason = data_dict.FindString("reason");
    if (reason != nullptr && *reason == "Invalidation set matched class") {
      base::Value::List* selector_list = data_dict.FindList("selectors");
      if (selector_list != nullptr) {
        EXPECT_EQ(selector_list->size(), 1u);
        EXPECT_EQ((*selector_list)[0], ".a .c");
        found_event_count++;
      }
    }
  }
  EXPECT_EQ(found_event_count, 1u);
}

TEST_F(InvalidationSetToSelectorMapTest,
       StartTracingLateWithPendingInsertRule) {
  SetBodyInnerHTML(R"HTML(
    <style id=target>
      .a .b { color: red; }
    </style>
    <div id=parent class=c>Parent
      <div class=d>Child</div>
    </div>
  )HTML");

  StartTracing();

  DummyExceptionStateForTesting exception_state;
  CSSStyleSheet* sheet =
      To<HTMLStyleElement>(GetElementById("target"))->sheet();
  sheet->insertRule(".c .d { color: green; }", 0, exception_state);
  UpdateAllLifecyclePhasesForTest();
  GetElementById("parent")->removeAttribute(html_names::kClassAttr);
  UpdateAllLifecyclePhasesForTest();

  auto analyzer = StopTracing();
  trace_analyzer::TraceEventVector events;
  analyzer->FindEvents(trace_analyzer::Query::EventNameIs(
                           "StyleInvalidatorInvalidationTracking"),
                       &events);
  size_t found_event_count = 0;
  for (auto event : events) {
    ASSERT_TRUE(event->HasDictArg("data"));
    base::Value::Dict data_dict = event->GetKnownArgAsDict("data");
    std::string* reason = data_dict.FindString("reason");
    if (reason != nullptr && *reason == "Invalidation set matched class") {
      base::Value::List* selector_list = data_dict.FindList("selectors");
      if (selector_list != nullptr) {
        EXPECT_EQ(selector_list->size(), 1u);
        EXPECT_EQ((*selector_list)[0], ".c .d");
        found_event_count++;
      }
    }
  }
  EXPECT_EQ(found_event_count, 1u);
}

TEST_F(InvalidationSetToSelectorMapTest, HandleRebuildAfterRuleSetChange) {
  // This test is intended to cover the case that necessitates us walking both
  // global and per-sheet rule sets when revisiting invalidation data on a late
  // attach.
  //
  // The rule we're trying to catch is the `.a .b` rule. The `.a .c` rule is
  // also important, and the fact that it is in a separate sheet is important.
  // Without that separate sheet, when we build the global rule set we would
  // just AddRef the `.a {.b}` invalidation set from the per-sheet rule set.
  // When tracing starts, revisiting the global rule set will associate that
  // `.a {.b}` invalidation set with the `.a .b` selector. If the global rule
  // set needs to be rebuilt, we'd AddRef the same invalidation set again, so
  // the association would remain stable.
  //
  // By contrast, having another sheet with an invalidation set also keyed at
  // `.a` forces a copy-on-write and combine. The combined `.a {.b .c}`
  // invalidation set gets stored in the global rule set, and it's what we find
  // on a revisit. The next time we rebuild the global rule set while tracing is
  // still active, we repeat the copy-on-write and combine, which generates a
  // brand-new `.a {.b .c}` invalidation set. If we hadn't walked the per-sheet
  // rule sets, we wouldn't know that the `.a .b` selector contributed to the
  // `.a {.b}` invalidation set and would not follow that selector through the
  // combine. Then, when an invalidation happens due to the `.b` entry on the
  // new `.a {.b .c}` invalidation set, we wouldn't know what selector put that
  // entry there.
  SetBodyInnerHTML(R"HTML(
    <style>
      .a .b { color: red; }
    </style>
    <style>
      .a .c { color: green; }
    </style>
    <div id=parent class=a>Parent
      <div class=b>Child</div>
    </div>
  )HTML");

  StartTracing();

  // Invalidation data revisit happens on the first lifecycle update following
  // the start of tracing. Perform a simple mutation to cause that to happen.
  GetDocument().body()->appendChild(
      GetDocument().CreateRawElement(html_names::kDivTag));
  UpdateAllLifecyclePhasesForTest();

  // Insert a new stylesheet to cause a rebuild of the global rule set.
  InsertStyleElement("#nobody { color: blue; }");
  UpdateAllLifecyclePhasesForTest();

  // Now perform an invalidation-causing mutation and confirm we can follow the
  // invalidation back to the style rule.
  GetElementById("parent")->removeAttribute(html_names::kClassAttr);
  UpdateAllLifecyclePhasesForTest();

  auto analyzer = StopTracing();
  trace_analyzer::TraceEventVector events;
  analyzer->FindEvents(trace_analyzer::Query::EventNameIs(
                           "StyleInvalidatorInvalidationTracking"),
                       &events);
  size_t found_event_count = 0;
  for (auto event : events) {
    ASSERT_TRUE(event->HasDictArg("data"));
    base::Value::Dict data_dict = event->GetKnownArgAsDict("data");
    std::string* reason = data_dict.FindString("reason");
    if (reason != nullptr && *reason == "Invalidation set matched class") {
      base::Value::List* selector_list = data_dict.FindList("selectors");
      if (selector_list != nullptr) {
        EXPECT_EQ(selector_list->size(), 1u);
        EXPECT_EQ((*selector_list)[0], ".a .b");
        found_event_count++;
      }
    }
  }
  EXPECT_EQ(found_event_count, 1u);
}

}  // namespace blink

"""

```