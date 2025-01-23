Response:
Let's break down the thought process for analyzing this C++ test file and generating the explanation.

1. **Understand the Goal:** The request asks for an explanation of the C++ test file's functionality, its relation to web technologies (JavaScript, HTML, CSS), logical reasoning with examples, and common usage errors.

2. **Initial File Scan (Keywords and Imports):**  Quickly scan the file for keywords and `#include` directives. This gives a high-level idea of the file's purpose. I see:
    * `DisplayLockUtilities` in the filename and `#include`. This strongly suggests the file tests functionalities related to `DisplayLockUtilities`.
    * `#include "third_party/blink/renderer/testing/core_unit_test_helper.h"`, `#include "third_party/blink/renderer/testing/page_test_base.h"`, `#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"`:  These imports indicate it's a unit test within the Blink rendering engine.
    * `#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"`, `#include "third_party/blink/renderer/bindings/core/v8/v8_intersection_observer_init.h"`:  This hints at interaction with the V8 JavaScript engine and specifically the Intersection Observer API.
    * `#include "third_party/blink/renderer/core/display_lock/display_lock_context.h"`, `#include "third_party/blink/renderer/core/display_lock/display_lock_document_state.h"`: Reinforces the focus on display locks.
    * `#include "third_party/blink/renderer/core/dom/shadow_root.h"`:  Suggests tests involving Shadow DOM.

3. **Identify the Test Fixture:** The `DisplayLockUtilitiesTest` class inherits from `RenderingTest`. This means it sets up a basic rendering environment for the tests. The constructor `RenderingTest(MakeGarbageCollected<SingleChildLocalFrameClient>())` indicates it's likely testing within a single-frame context initially.

4. **Analyze Helper Functions:** The `LockElement` and `CommitElement` functions are clearly helpers for setting and unsetting display lock related attributes (`hidden="until-found"` and `content-visibility: hidden`). The `UpdateAllLifecyclePhasesForTest()` call after these operations is crucial for simulating the rendering pipeline updates.

5. **Examine Individual Test Cases (`TEST_F`):**  Go through each test case to understand its specific purpose.

    * **`ShouldIgnoreHiddenUntilFoundChildren`:** Tests if `ShouldIgnoreNodeDueToDisplayLock` correctly identifies nodes hidden with `hidden="until-found"` as ignorable for accessibility reasons. This directly relates to HTML attributes and how they affect accessibility.

    * **`DISABLED_ActivatableLockedInclusiveAncestors`:**  This test is disabled, but its name suggests it's about finding locked ancestor elements when the lock is "activatable" (using `hidden="until-found"`). The HTML structure involves nested divs and a Shadow DOM, and the test manipulates these elements and their lock states. This connects to HTML structure and the Shadow DOM.

    * **`LockedSubtreeCrossingFrames`:** This test deals with iframes and how display locks propagate across frame boundaries. It uses `SetChildFrameHTML` to set up the iframe content. This directly relates to HTML iframes and how content isolation is handled with display locks.

    * **`InteractionWithIntersectionObserver`:**  This test explicitly checks the interaction between display locks and the Intersection Observer API. It sets up an iframe, locks a container, observes an element within the iframe, and verifies that the Intersection Observer callbacks behave correctly under these conditions. This directly links to the JavaScript Intersection Observer API and how display locks influence its behavior.

    * **`ContainerQueryCrash`:** This test is focused on preventing crashes when using container queries (`container-type: size`) in combination with `content-visibility: hidden`. It doesn't explicitly test display lock *utilities* directly, but tests a scenario that might have involved display lock interactions.

6. **Connect to Web Technologies:**  As each test is analyzed, explicitly identify the connection to HTML, CSS, and JavaScript features. For instance:

    * `hidden="until-found"` is an HTML attribute.
    * `content-visibility: hidden` is a CSS property.
    * The Intersection Observer is a JavaScript API.
    * Iframes are an HTML element.
    * Container queries are a CSS feature.

7. **Logical Reasoning and Examples:**  For each test, consider the assumptions and expected outcomes. If a test involves setting attributes and checking conditions, think about the "if...then..." logic. For example:

    * *Assumption:* Setting `hidden="until-found"` on an element should make its descendants ignorable for display lock checks related to accessibility.
    * *Output (Verification):* `EXPECT_TRUE(DisplayLockUtilities::ShouldIgnoreNodeDueToDisplayLock(...))` confirms this.

    For tests with more complex setups (like `ActivatableLockedInclusiveAncestors` or `LockedSubtreeCrossingFrames`), trace the steps of locking and unlocking elements and predict the outcome of the `DisplayLockUtilities` functions.

8. **Common Usage Errors:** Think about how developers might misuse the features being tested.

    * Forgetting to call `UpdateAllLifecyclePhasesForTest()` after modifying element attributes.
    * Incorrectly assuming that display locks in the parent frame *always* block rendering in the child frame without understanding the nuances (activatable locks).
    * Not considering the impact of display locks on JavaScript APIs like Intersection Observer.

9. **Structure the Explanation:**  Organize the information logically. Start with a general overview, then detail each test case, focusing on its functionality, relation to web technologies, logical reasoning, and potential errors.

10. **Refine and Clarify:** Review the explanation for clarity and accuracy. Use precise language and avoid jargon where possible. Ensure the examples are easy to understand. For example, initially, I might have just said "tests interaction with Intersection Observer."  Refining this to "tests how display locks affect the behavior and callbacks of the JavaScript Intersection Observer API, especially when observing elements in iframes that are subject to display locks" is much more informative.

By following these steps, a comprehensive and accurate explanation of the C++ test file can be generated. The key is to understand the code's purpose, identify the web technologies involved, and think about the scenarios being tested from both a technical and a developer usage perspective.
这个C++源代码文件 `display_lock_utilities_test.cc` 是 Chromium Blink 引擎中的一个单元测试文件，专门用于测试 `blink::DisplayLockUtilities` 这个命名空间下的各种实用工具函数的功能。这些工具函数主要与“显示锁”（Display Lock）机制相关。

**功能概述:**

该文件通过编写一系列的测试用例，验证了 `DisplayLockUtilities` 中函数的正确性，这些函数主要用于判断和管理页面元素的显示锁定状态，以及处理显示锁与页面生命周期、跨 frame 交互、以及 JavaScript API 的交互。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`DisplayLockUtilities` 以及这个测试文件所测试的功能，都直接或间接地与 Web 前端技术（JavaScript, HTML, CSS）的功能相关。显示锁机制本身是浏览器为了优化渲染性能和用户体验而引入的一种机制，它允许开发者通过特定的 HTML 属性或 CSS 属性来控制元素的渲染时机。

以下是一些具体的关联和举例：

1. **HTML 属性 (`hidden="until-found"`):**
   - `LockElement` 函数使用了 `element.setAttribute(html_names::kHiddenAttr, AtomicString("until-found"));` 来设置元素的 `hidden` 属性为 `until-found`。
   - `hidden="until-found"` 是一个 HTML 属性，用于指示浏览器在满足特定条件（例如通过 JavaScript 解锁）之前，不要渲染该元素及其内容，但会参与布局计算。这与显示锁的“可激活锁定”概念相关。
   - **举例:**  `TEST_F(DisplayLockUtilitiesTest, ShouldIgnoreHiddenUntilFoundChildren)` 这个测试用例验证了 `ShouldIgnoreNodeDueToDisplayLock` 函数是否能正确地忽略设置了 `hidden="until-found"` 的元素。这表明显示锁机制会考虑这种特殊的 `hidden` 属性。

2. **CSS 属性 (`content-visibility: hidden`):**
   - `LockElement` 函数还使用了 `element.setAttribute(html_names::kStyleAttr, AtomicString("content-visibility: hidden"));` 来设置元素的 CSS 样式 `content-visibility: hidden`。
   - `content-visibility: hidden` 是一个 CSS 属性，可以阻止元素进行任何渲染，并且跳过其内容的渲染，从而提高初始页面加载性能。这也被用于实现显示锁的某些状态。
   - **举例:** 虽然这个测试文件中没有直接针对 `content-visibility: hidden` 的独立测试用例，但 `LockElement` 函数同时使用了这两种方式来设置锁定状态，表明测试覆盖了这两种场景。

3. **Intersection Observer API (JavaScript):**
   - `TEST_F(DisplayLockUtilitiesTest, InteractionWithIntersectionObserver)` 这个测试用例明确测试了显示锁与 JavaScript 的 `IntersectionObserver` API 的交互。
   - `IntersectionObserver` 是一个 JavaScript API，允许开发者异步地监听目标元素与其祖先元素或 viewport 交叉状态的变化。
   - **举例:** 该测试用例创建了一个包含 iframe 的页面，并在父页面上锁定了包含 iframe 的容器。然后，它在子 iframe 中创建了一个目标元素，并使用 `IntersectionObserver` 观察该元素。测试验证了在容器被锁定时，`IntersectionObserver` 的回调行为（例如，交叉状态为不相交，目标矩形和根矩形为空）。解锁容器后，`IntersectionObserver` 的回调会报告正确的交叉状态。这说明显示锁会影响 JavaScript API 的行为。

4. **页面生命周期和渲染流程:**
   - 测试用例中多次调用 `UpdateAllLifecyclePhasesForTest()`。这个函数模拟了 Blink 引擎的页面生命周期更新过程，包括样式计算、布局和绘制等阶段。
   - 显示锁的核心目的就是在特定的时机阻止或延迟某些元素的渲染，因此它与页面的渲染流程紧密相关。测试需要模拟这些流程来验证显示锁的正确性。

5. **iframe 和跨 Frame 交互:**
   - `TEST_F(DisplayLockUtilitiesTest, LockedSubtreeCrossingFrames)` 和 `TEST_F(DisplayLockUtilitiesTest, InteractionWithIntersectionObserver)` 都涉及到了 iframe。
   - 显示锁的状态需要考虑跨 frame 的场景，例如，父 frame 的显示锁可能会影响子 frame 的渲染。测试用例验证了 `IsInLockedSubtreeCrossingFrames` 函数是否能正确判断元素是否位于跨 frame 的锁定子树中。

**逻辑推理和假设输入/输出:**

1. **`TEST_F(DisplayLockUtilitiesTest, ShouldIgnoreHiddenUntilFoundChildren)`:**
   - **假设输入:** 一个包含一个设置了 `hidden="until-found"` 的 div 元素，该 div 内包含一个 id 为 "target" 的 div 元素。`DisplayLockActivationReason::kAccessibility` 作为激活原因。
   - **逻辑推理:**  `hidden="until-found"` 表示该元素在特定条件下才会被显示，出于可访问性的考虑，在未激活前，其子节点应该被显示锁机制忽略。
   - **预期输出:** `DisplayLockUtilities::ShouldIgnoreNodeDueToDisplayLock` 函数返回 `true`。

2. **`TEST_F(DisplayLockUtilitiesTest, DISABLED_ActivatableLockedInclusiveAncestors)`:**
   - **假设输入:** 一个嵌套的 div 结构，其中一些 div 元素被设置为可激活锁定 (`hidden="until-found"`）。
   - **逻辑推理:**  `ActivatableLockedInclusiveAncestors` 函数应该返回所有包含给定元素并且是可激活锁定的祖先元素。
   - **预期输出:** 根据不同的锁定状态和查询的起始元素，函数返回包含相应锁定祖先元素的 `HeapVector<Member<Element>>`。例如，如果只有最外层的 div 被锁定，查询其内部的元素应该只返回最外层的 div。

3. **`TEST_F(DisplayLockUtilitiesTest, LockedSubtreeCrossingFrames)`:**
   - **假设输入:** 一个包含 iframe 的父页面，以及子页面。父页面或子页面中的某些元素被锁定 (`content-visibility: hidden`)。
   - **逻辑推理:** `IsInLockedSubtreeCrossingFrames` 函数应该判断一个元素是否位于跨 frame 的锁定子树中。
   - **预期输出:**
     - 如果子 frame 的一个元素的祖先在子 frame 中被锁定，则该元素返回 `true`。
     - 如果子 frame 的一个元素的祖先在父 frame 中被锁定，则该元素返回 `true`。
     - 如果没有祖先被锁定，则返回 `false`。

4. **`TEST_F(DisplayLockUtilitiesTest, InteractionWithIntersectionObserver)`:**
   - **假设输入:** 一个包含 iframe 的父页面，父页面锁定了包含 iframe 的容器。子 iframe 中有一个被 `IntersectionObserver` 观察的目标元素。
   - **逻辑推理:** 当包含 iframe 的容器被锁定时，子 iframe 的渲染可能会被节流，`IntersectionObserver` 的回调会反映这种状态。解锁后，回调会更新。
   - **预期输出:**  在容器被锁定时，`IntersectionObserver` 的回调指示目标元素不相交，且几何信息为空。解锁后，回调指示目标元素相交，并提供正确的几何信息。

**涉及用户或编程常见的使用错误:**

1. **忘记调用 `UpdateAllLifecyclePhasesForTest()`:** 在修改 DOM 结构或元素属性（特别是与渲染相关的属性）后，如果没有调用 `UpdateAllLifecyclePhasesForTest()`，测试可能无法反映真实的渲染状态，导致测试结果不准确。这是模拟渲染流程的关键步骤。
   - **举例:** 如果在 `LockElement` 或 `CommitElement` 函数调用后忘记调用 `UpdateAllLifecyclePhasesForTest()`，后续的断言可能会基于过时的渲染状态进行判断。

2. **对显示锁机制的误解:**  开发者可能不理解不同类型的显示锁（例如，可激活锁定和非激活锁定）的行为差异，导致在 JavaScript 或 CSS 中使用不当，或者对 `IntersectionObserver` 等 API 的行为产生错误的预期。
   - **举例:** 开发者可能认为只要父元素被 `content-visibility: hidden` 锁定，子元素就永远不会触发 `IntersectionObserver` 的回调，但实际上，某些类型的锁定可能允许在特定条件下触发回调。

3. **跨 Frame 场景下的疏忽:**  在涉及 iframe 的页面中，显示锁的行为可能更加复杂。开发者可能没有考虑到父 frame 的显示锁对子 frame 的影响，或者反之。
   - **举例:**  开发者可能在父 frame 中锁定了某个区域，但期望子 frame 中的元素仍然能够正常触发动画或显示，而实际上由于显示锁的存在，子 frame 的渲染可能被延迟或阻止。

总而言之，`display_lock_utilities_test.cc` 通过各种测试用例，确保了 Blink 引擎中负责处理显示锁的实用工具函数的正确性和健壮性，这些功能直接影响着网页的渲染性能和与前端技术的交互。理解这个测试文件的内容，有助于理解 Chromium 如何实现和测试显示锁机制。

### 提示词
```
这是目录为blink/renderer/core/display_lock/display_lock_utilities_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/display_lock/display_lock_utilities.h"

#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_intersection_observer_init.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_context.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_document_state.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/core/testing/intersection_observer_test_helper.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"

namespace blink {

class DisplayLockUtilitiesTest : public RenderingTest {
 public:
  DisplayLockUtilitiesTest()
      : RenderingTest(MakeGarbageCollected<SingleChildLocalFrameClient>()) {}

  void LockElement(Element& element, bool activatable) {
    if (activatable) {
      element.setAttribute(html_names::kHiddenAttr,
                           AtomicString("until-found"));
    } else {
      element.setAttribute(html_names::kStyleAttr,
                           AtomicString("content-visibility: hidden"));
    }
    UpdateAllLifecyclePhasesForTest();
  }

  void CommitElement(Element& element) {
    element.setAttribute(html_names::kStyleAttr, g_empty_atom);
    UpdateAllLifecyclePhasesForTest();
  }
};

TEST_F(DisplayLockUtilitiesTest, ShouldIgnoreHiddenUntilFoundChildren) {
  SetBodyInnerHTML(R"HTML(
    <div hidden=until-found>
      <div id=target></div>
    </div>
  )HTML");

  Node* target = GetDocument().getElementById(AtomicString("target"));
  EXPECT_TRUE(DisplayLockUtilities::ShouldIgnoreNodeDueToDisplayLock(
      *target, DisplayLockActivationReason::kAccessibility));
}

TEST_F(DisplayLockUtilitiesTest, DISABLED_ActivatableLockedInclusiveAncestors) {
  SetBodyInnerHTML(R"HTML(
    <style>
      div {
        contain: style layout;
      }
    </style>
    <div id='outer'>
      <div id='innerA'>
        <div id='innermost'>text_node</div>
      </div>
      <div id='innerB'></div>
    </div>
  )HTML");

  Element& outer = *GetDocument().getElementById(AtomicString("outer"));
  Element& inner_a = *GetDocument().getElementById(AtomicString("innerA"));
  Element& inner_b = *GetDocument().getElementById(AtomicString("innerB"));
  Element& innermost = *GetDocument().getElementById(AtomicString("innermost"));
  ShadowRoot& shadow_root =
      inner_b.AttachShadowRootForTesting(ShadowRootMode::kOpen);
  shadow_root.setInnerHTML("<div id='shadowDiv'>shadow!</div>");
  Element& shadow_div = *shadow_root.getElementById(AtomicString("shadowDiv"));

  LockElement(outer, true);
  EXPECT_EQ(
      GetDocument().GetDisplayLockDocumentState().LockedDisplayLockCount(), 1);
  EXPECT_EQ(GetDocument()
                .GetDisplayLockDocumentState()
                .DisplayLockBlockingAllActivationCount(),
            0);
  // Querying from every element gives |outer|.
  HeapVector<Member<Element>> result_for_outer =
      DisplayLockUtilities::ActivatableLockedInclusiveAncestors(
          outer, DisplayLockActivationReason::kAny);
  EXPECT_EQ(result_for_outer.size(), 1u);
  EXPECT_EQ(result_for_outer.at(0), outer);

  HeapVector<Member<Element>> result_for_inner_a =
      DisplayLockUtilities::ActivatableLockedInclusiveAncestors(
          inner_a, DisplayLockActivationReason::kAny);
  EXPECT_EQ(result_for_inner_a.size(), 1u);
  EXPECT_EQ(result_for_inner_a.at(0), outer);

  HeapVector<Member<Element>> result_for_innermost =
      DisplayLockUtilities::ActivatableLockedInclusiveAncestors(
          innermost, DisplayLockActivationReason::kAny);
  EXPECT_EQ(result_for_innermost.size(), 1u);
  EXPECT_EQ(result_for_innermost.at(0), outer);

  HeapVector<Member<Element>> result_for_inner_b =
      DisplayLockUtilities::ActivatableLockedInclusiveAncestors(
          inner_b, DisplayLockActivationReason::kAny);
  EXPECT_EQ(result_for_inner_b.size(), 1u);
  EXPECT_EQ(result_for_inner_b.at(0), outer);

  HeapVector<Member<Element>> result_for_shadow_div =
      DisplayLockUtilities::ActivatableLockedInclusiveAncestors(
          shadow_div, DisplayLockActivationReason::kAny);
  EXPECT_EQ(result_for_shadow_div.size(), 1u);
  EXPECT_EQ(result_for_shadow_div.at(0), outer);

  // Lock innermost with activatable flag.
  LockElement(innermost, true);
  EXPECT_EQ(
      GetDocument().GetDisplayLockDocumentState().LockedDisplayLockCount(), 2);
  EXPECT_EQ(GetDocument()
                .GetDisplayLockDocumentState()
                .DisplayLockBlockingAllActivationCount(),
            0);

  result_for_outer = DisplayLockUtilities::ActivatableLockedInclusiveAncestors(
      outer, DisplayLockActivationReason::kAny);
  EXPECT_EQ(result_for_outer.size(), 1u);
  EXPECT_EQ(result_for_outer.at(0), outer);

  result_for_inner_a =
      DisplayLockUtilities::ActivatableLockedInclusiveAncestors(
          inner_a, DisplayLockActivationReason::kAny);
  EXPECT_EQ(result_for_inner_a.size(), 1u);
  EXPECT_EQ(result_for_inner_a.at(0), outer);

  result_for_innermost =
      DisplayLockUtilities::ActivatableLockedInclusiveAncestors(
          innermost, DisplayLockActivationReason::kAny);
  EXPECT_EQ(result_for_innermost.size(), 2u);
  EXPECT_EQ(result_for_innermost.at(0), innermost);
  EXPECT_EQ(result_for_innermost.at(1), outer);

  result_for_inner_b =
      DisplayLockUtilities::ActivatableLockedInclusiveAncestors(
          inner_b, DisplayLockActivationReason::kAny);
  EXPECT_EQ(result_for_inner_b.size(), 1u);
  EXPECT_EQ(result_for_inner_b.at(0), outer);

  result_for_shadow_div =
      DisplayLockUtilities::ActivatableLockedInclusiveAncestors(
          shadow_div, DisplayLockActivationReason::kAny);
  EXPECT_EQ(result_for_shadow_div.size(), 1u);
  EXPECT_EQ(result_for_shadow_div.at(0), outer);

  // Unlock everything.
  CommitElement(innermost);
  CommitElement(outer);
  EXPECT_EQ(
      GetDocument().GetDisplayLockDocumentState().LockedDisplayLockCount(), 0);
  EXPECT_EQ(GetDocument()
                .GetDisplayLockDocumentState()
                .DisplayLockBlockingAllActivationCount(),
            0);

  EXPECT_EQ(DisplayLockUtilities::ActivatableLockedInclusiveAncestors(
                outer, DisplayLockActivationReason::kAny)
                .size(),
            0u);
  EXPECT_EQ(DisplayLockUtilities::ActivatableLockedInclusiveAncestors(
                inner_a, DisplayLockActivationReason::kAny)
                .size(),
            0u);
  EXPECT_EQ(DisplayLockUtilities::ActivatableLockedInclusiveAncestors(
                innermost, DisplayLockActivationReason::kAny)
                .size(),
            0u);
  EXPECT_EQ(DisplayLockUtilities::ActivatableLockedInclusiveAncestors(
                inner_b, DisplayLockActivationReason::kAny)
                .size(),
            0u);
  EXPECT_EQ(DisplayLockUtilities::ActivatableLockedInclusiveAncestors(
                shadow_div, DisplayLockActivationReason::kAny)
                .size(),
            0u);
}

TEST_F(DisplayLockUtilitiesTest, LockedSubtreeCrossingFrames) {
  GetDocument().SetBaseURLOverride(KURL("http://test.com"));
  SetBodyInnerHTML(R"HTML(
    <style>
      div {
        contain: style layout;
      }
    </style>
    <div id="grandparent">
      <iframe id="frame" src="http://test.com"></iframe>
    </div>
  )HTML");
  SetChildFrameHTML(R"HTML(
    <style>
      div {
        contain: style layout;
      }
    </style>
    <div id="parent">
      <div id="child"></div>
    </div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();

  Element* grandparent =
      GetDocument().getElementById(AtomicString("grandparent"));
  Element* parent = ChildDocument().getElementById(AtomicString("parent"));
  Element* child = ChildDocument().getElementById(AtomicString("child"));

  ASSERT_TRUE(grandparent);
  ASSERT_TRUE(parent);
  ASSERT_TRUE(child);

  // Lock parent.
  LockElement(*parent, false);

  EXPECT_EQ(
      GetDocument().GetDisplayLockDocumentState().LockedDisplayLockCount(), 0);
  EXPECT_EQ(
      ChildDocument().GetDisplayLockDocumentState().LockedDisplayLockCount(),
      1);

  EXPECT_FALSE(
      DisplayLockUtilities::IsInLockedSubtreeCrossingFrames(*grandparent));
  EXPECT_FALSE(DisplayLockUtilities::IsInLockedSubtreeCrossingFrames(*parent));
  EXPECT_TRUE(DisplayLockUtilities::IsInLockedSubtreeCrossingFrames(*child));

  // Lock grandparent.
  LockElement(*grandparent, false);

  EXPECT_FALSE(
      DisplayLockUtilities::IsInLockedSubtreeCrossingFrames(*grandparent));
  EXPECT_TRUE(DisplayLockUtilities::IsInLockedSubtreeCrossingFrames(*parent));
  EXPECT_TRUE(DisplayLockUtilities::IsInLockedSubtreeCrossingFrames(*child));

  // Unlock parent.
  CommitElement(*parent);

  EXPECT_FALSE(
      DisplayLockUtilities::IsInLockedSubtreeCrossingFrames(*grandparent));
  EXPECT_TRUE(DisplayLockUtilities::IsInLockedSubtreeCrossingFrames(*parent));
  EXPECT_TRUE(DisplayLockUtilities::IsInLockedSubtreeCrossingFrames(*child));

  // Unlock grandparent.
  CommitElement(*grandparent);

  // CommitElement(*grandparent) ran a lifecycle update, but during that update
  // the iframe document was still throttled, so did not update style. The
  // iframe document should have become unthrottled at the end of that update,
  // so it takes an additional lifecycle update to resolve style in the iframe.
  UpdateAllLifecyclePhasesForTest();

  EXPECT_FALSE(
      DisplayLockUtilities::IsInLockedSubtreeCrossingFrames(*grandparent));
  EXPECT_FALSE(DisplayLockUtilities::IsInLockedSubtreeCrossingFrames(*parent));
  EXPECT_FALSE(DisplayLockUtilities::IsInLockedSubtreeCrossingFrames(*child));
}

TEST_F(DisplayLockUtilitiesTest, InteractionWithIntersectionObserver) {
  SetHtmlInnerHTML(R"HTML(
    <div id="container"><iframe id="frame"></iframe></div>
  )HTML");
  SetChildFrameHTML(R"HTML(
    <div id="target"></target>
  )HTML");

  auto* container = GetDocument().getElementById(AtomicString("container"));
  auto* target = ChildDocument().getElementById(AtomicString("target"));

  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(ChildDocument().View()->ShouldThrottleRenderingForTest());
  LockElement(*container, false);
  EXPECT_TRUE(ChildDocument().View()->ShouldThrottleRenderingForTest());

  target->setInnerHTML("Hello, world!");
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(ChildDocument().View()->ShouldThrottleRenderingForTest());
  EXPECT_TRUE(ChildDocument().Lifecycle().GetState() ==
              DocumentLifecycle::kVisualUpdatePending);

  IntersectionObserverInit* observer_init = IntersectionObserverInit::Create();
  TestIntersectionObserverDelegate* observer_delegate =
      MakeGarbageCollected<TestIntersectionObserverDelegate>(ChildDocument());
  IntersectionObserver* observer = IntersectionObserver::Create(
      observer_init, *observer_delegate,
      LocalFrameUkmAggregator::kDisplayLockIntersectionObserver);
  observer->observe(target);
  UpdateAllLifecyclePhasesForTest();
  test::RunPendingTasks();
  EXPECT_TRUE(ChildDocument().View()->ShouldThrottleRenderingForTest());
  EXPECT_EQ(ChildDocument().Lifecycle().GetState(),
            DocumentLifecycle::kVisualUpdatePending);
  EXPECT_EQ(observer_delegate->CallCount(), 1);
  EXPECT_EQ(observer_delegate->EntryCount(), 1);
  EXPECT_FALSE(observer_delegate->LastEntry()->GetGeometry().IsIntersecting());
  EXPECT_EQ(observer_delegate->LastEntry()->GetGeometry().TargetRect(),
            gfx::RectF());
  EXPECT_EQ(observer_delegate->LastEntry()->GetGeometry().RootRect(),
            gfx::RectF());

  CommitElement(*container);
  test::RunPendingTasks();
  EXPECT_FALSE(ChildDocument().View()->ShouldThrottleRenderingForTest());
  EXPECT_EQ(ChildDocument().Lifecycle().GetState(),
            DocumentLifecycle::kVisualUpdatePending);
  EXPECT_EQ(observer_delegate->CallCount(), 1);

  UpdateAllLifecyclePhasesForTest();
  test::RunPendingTasks();
  EXPECT_FALSE(ChildDocument().View()->ShouldThrottleRenderingForTest());
  EXPECT_FALSE(ChildDocument().View()->NeedsLayout());
  EXPECT_EQ(ChildDocument().Lifecycle().GetState(),
            DocumentLifecycle::kPaintClean);
  EXPECT_EQ(observer_delegate->CallCount(), 2);
  EXPECT_EQ(observer_delegate->EntryCount(), 2);
  EXPECT_TRUE(observer_delegate->LastEntry()->GetGeometry().IsIntersecting());
  EXPECT_NE(observer_delegate->LastEntry()->GetGeometry().TargetRect(),
            gfx::RectF());
  EXPECT_EQ(observer_delegate->LastEntry()->GetGeometry().IntersectionRect(),
            observer_delegate->LastEntry()->GetGeometry().TargetRect());
  EXPECT_NE(observer_delegate->LastEntry()->GetGeometry().RootRect(),
            gfx::RectF());
}

TEST_F(DisplayLockUtilitiesTest, ContainerQueryCrash) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      #container {
        content-visibility: hidden;
        container-type: size;
      }
    </style>
    <div id="container"><div id="child"></div></div>
  )HTML");

  auto* child = DynamicTo<HTMLElement>(
      GetDocument().getElementById(AtomicString("child")));
  ASSERT_TRUE(child);

  // Should not fail DCHECKs or crash.
  child->offsetTopForBinding();
}

}  // namespace blink
```