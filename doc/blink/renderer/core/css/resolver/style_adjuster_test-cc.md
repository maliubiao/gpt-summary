Response:
My thinking process to analyze the `style_adjuster_test.cc` file went something like this:

1. **Understand the Purpose:** The filename `style_adjuster_test.cc` immediately suggests this file contains tests for a component called "StyleAdjuster."  The location within `blink/renderer/core/css/resolver/` further clarifies that this adjuster likely operates during the CSS resolution process. The "test.cc" suffix confirms it's a unit test file.

2. **Identify Core Functionality:** I scanned the test names and the code within each test. The repeated use of `TouchAction` and related keywords like `pan`, `pinch-zoom`, `scroll`, `contenteditable`, `input`, and `textarea` strongly indicates that the `StyleAdjuster` is responsible for adjusting the computed style, specifically the `touch-action` property, based on various factors.

3. **Analyze Individual Tests:** I examined each `TEST_F` block to understand the specific scenarios being tested:
    * **`TouchActionPropagatedAcrossIframes`:**  Checks if the `touch-action` style set on a parent iframe is correctly inherited (or rather, affects the computed style) of elements within the child iframe.
    * **`TouchActionPanningReEnabledByScrollers`:** Investigates how the presence of a scrollable container (`overflow: scroll`) influences the effective `touch-action`, even if an ancestor has a more restrictive `touch-action`.
    * **`TouchActionPropagatedWhenAncestorStyleChanges`:**  Verifies that dynamic changes to an ancestor's `touch-action` or `overflow` style are correctly reflected in the descendant's computed `touch-action`.
    * **`TouchActionRestrictedByLowerAncestor`:**  Confirms that the most restrictive `touch-action` value in the ancestor chain takes precedence.
    * **`TouchActionContentEditableArea`:**  Examines how the `contenteditable` attribute on `div`, `input`, and `textarea` elements affects the computed `touch-action`. It specifically considers the disabling of horizontal panning (`kInternalPanXScrolls`).
    * **`TouchActionNoPanXScrollsWhenNoPanX`:** Checks if `kInternalPanXScrolls` is correctly suppressed when `touch-action: pan-y` is set, even when an element becomes `contenteditable`.
    * **`TouchActionNotWritableReEnabledByScrollers`:** Tests if scrollable containers re-enable the `kInternalNotWritable` flag in `touch-action`, even if an ancestor sets `touch-action: none`.
    * **`TouchActionWritableArea`:**  Similar to `TouchActionContentEditableArea`, but with a focus on the `kInternalNotWritable` flag and different input types (`password`). It also considers the impact of the `SwipeToMoveCursor` feature.
    * **`OverflowClipUseCount`:**  Verifies that the `overflow: clip` CSS property correctly triggers a use counter.
    * **`AdjustForSVGCrash`:**  Seems like a regression test for a specific crash scenario related to SVG, `dominant-baseline`, and `<use>` elements with shadow DOM.

4. **Relate to Web Technologies (HTML, CSS, JavaScript):**
    * **HTML:** The tests heavily utilize HTML elements (`div`, `iframe`, `input`, `textarea`, `svg`, `tref`, `use`) and attributes (`style`, `contenteditable`, `overflow`, `touch-action`, `xlink:href`).
    * **CSS:** The tests involve setting and manipulating CSS properties like `touch-action`, `overflow`, `display`, `margin`, `width`, `height`, and `dominant-baseline`. The `StyleAdjuster`'s job is fundamentally about the *computed* style, which is a result of CSS cascading and specificity.
    * **JavaScript:** While this specific test file doesn't directly execute JavaScript, the scenarios being tested have implications for how JavaScript interactions (like touch events and focus changes) would behave. The `contenteditable` attribute, for example, allows JavaScript to modify the content of an element.

5. **Infer Logic and Hypothesize Inputs/Outputs:** Based on the test names and code, I inferred the core logic of the `StyleAdjuster`: It modifies the computed `touch-action` property based on:
    * **Inheritance and Propagation:**  `touch-action` values propagate down the DOM tree, with more restrictive values potentially overriding less restrictive ones.
    * **Scrollable Containers:** The presence of scrollable containers (elements with `overflow: scroll` or `overflow: auto`) can re-enable certain touch actions like panning.
    * **Content Editability:** Elements that are `contenteditable` or form controls (like `input` and `textarea`) have specific default `touch-action` behaviors to enable text manipulation.
    * **Feature Flags:**  The `SwipeToMoveCursor` feature influences the computed `touch-action` for editable elements.
    * **SVG Specifics:**  The SVG test suggests there's logic to handle specific SVG elements and their styling.

6. **Identify Potential User/Programming Errors:**
    * **Conflicting `touch-action` Values:** Users might set conflicting `touch-action` values on parent and child elements without fully understanding the inheritance and overriding rules. This could lead to unexpected touch behavior.
    * **Forgetting Scroll Containers:** Developers might set `touch-action: none` on a parent, unintentionally preventing scrolling within a child container.
    * **Misunderstanding `contenteditable`:**  Developers might not realize how making an element `contenteditable` can alter its default touch behavior.

7. **Trace User Operations to Reach the Code:** I considered a typical browser interaction flow:
    1. **User interacts with a webpage:**  This could involve loading a page, clicking, scrolling, touching the screen, or focusing on input fields.
    2. **Browser processes the HTML and CSS:** The rendering engine parses the HTML and CSS to build the DOM tree and CSSOM.
    3. **Style resolution:** The `StyleAdjuster` comes into play during the style resolution process, calculating the computed styles for each element, including `touch-action`.
    4. **Layout and Painting:** The computed styles are used to layout and paint the webpage.
    5. **Event Handling:** When the user interacts (e.g., touches the screen), the browser's event handling mechanism uses the computed styles (including the effective `touch-action`) to determine how to respond to the event. For example, if `touch-action: none` is in effect, touch scrolling might be disabled.

By following these steps, I was able to systematically analyze the `style_adjuster_test.cc` file and extract the relevant information about its purpose, functionality, connections to web technologies, underlying logic, potential errors, and how it fits into the broader browser workflow.
这个文件 `blink/renderer/core/css/resolver/style_adjuster_test.cc` 是 Chromium Blink 渲染引擎中的一个单元测试文件，专门用于测试 **StyleAdjuster** 组件的功能。 **StyleAdjuster** 的主要职责是在 CSS 样式解析的后期阶段，根据特定的条件和规则，调整元素的计算样式。

以下是该文件的功能以及与 JavaScript、HTML、CSS 的关系，并附带举例说明：

**功能：**

该文件主要测试 `StyleAdjuster` 在以下方面的调整行为：

1. **`touch-action` 属性的传播和影响:**
   - 测试 `touch-action` 属性在 iframe 之间的传播。
   - 测试滚动容器 (`overflow: scroll` 等) 如何重新启用或修改 `touch-action`。
   - 测试祖先元素 `touch-action` 属性的动态变化如何影响后代元素。
   - 测试祖先元素 `touch-action` 的限制作用。

2. **`touch-action` 属性与可编辑区域的交互:**
   - 测试 `contenteditable` 属性为 `true` 或 `false` 的 `div` 元素，以及可编辑和禁用的 `input` 和 `textarea` 元素，其 `touch-action` 的默认行为和调整。
   - 测试当祖先元素设置了 `touch-action: pan-y` 时，可编辑区域是否会禁用水平滚动 (`kInternalPanXScrolls`)。

3. **`touch-action` 属性与写入区域的交互 (Stylus Handwriting 特性):**
   - 测试在启用手写笔支持的情况下，可编辑和不可编辑元素 (`contenteditable`，`input`，`textarea`) 的 `touch-action` 行为，特别是 `kInternalNotWritable` 标志。

4. **`overflow: clip` 使用计数:**
   - 测试当页面上使用 `overflow: clip` 属性时，是否正确触发了 Web Feature 的使用计数。

5. **SVG 相关样式调整:**
   - 测试一个特定的 SVG 场景，确保在特定的样式和元素组合下不会发生崩溃。

**与 JavaScript, HTML, CSS 的关系：**

`StyleAdjuster` 位于 CSS 样式解析的后端，其工作直接影响着最终应用于 DOM 元素的计算样式，而这些样式决定了页面的渲染和交互行为。

* **HTML:** 该测试文件使用 HTML 结构来创建各种测试场景，例如包含 iframe、不同类型的元素 (div, input, textarea, svg)，以及设置各种属性 (`style`, `contenteditable`, `overflow`). `StyleAdjuster` 的作用是根据这些 HTML 结构和属性来调整样式。
    * **例子:** `<div id='target' style='touch-action: pan-x'></div>`  `StyleAdjuster` 会根据这个 `style` 属性来设置 `target` 元素的 `touch-action` 计算值。

* **CSS:**  测试文件通过内联 CSS 或 `<style>` 标签来设置元素的 CSS 属性，例如 `touch-action`, `overflow`, `dominant-baseline`。`StyleAdjuster` 的目标是根据 CSS 规范和 Blink 特有的规则来调整这些样式。
    * **例子:**  `<style>#ancestor { touch-action: pan-x; }</style>`  `StyleAdjuster` 会考虑这个样式规则，并可能影响其后代元素的 `touch-action` 计算值。

* **JavaScript:** 虽然这个测试文件本身没有直接执行 JavaScript 代码，但 `StyleAdjuster` 的调整行为会影响 JavaScript 与页面的交互。例如，如果一个元素的 `touch-action` 被调整为 `none`，那么 JavaScript 的触摸事件处理可能会受到影响。
    * **例子 (虽然未在测试中直接体现):**  JavaScript 代码可能会监听触摸事件，并根据元素的 `touch-action` 计算值来决定如何处理这些事件 (例如，是否允许滚动或缩放)。

**逻辑推理、假设输入与输出：**

以 `TouchActionPropagatedAcrossIframes` 测试为例：

**假设输入:**

```html
<iframe id='owner' src='http://test.com' style='touch-action: none'>
  <iframe id='child' src='http://test.com'>
    <div id='target' style='touch-action: pinch-zoom'></div>
  </iframe>
</iframe>
```

**逻辑推理:**

1. 父 iframe (`owner`) 设置了 `touch-action: none`。
2. 子 iframe (`child`) 内部的元素 (`target`) 设置了 `touch-action: pinch-zoom`。
3. `StyleAdjuster` 会检查祖先元素的 `touch-action`，并将其应用于后代元素。
4. 由于父 iframe 的 `touch-action: none` 具有更高的限制性，它会覆盖子元素的 `touch-action: pinch-zoom`。

**预期输出:**

`target` 元素的 `EffectiveTouchAction()` 应该返回 `TouchAction::kNone`。

当父 iframe 的样式被修改为 `touch-action: auto` 后：

**假设输入 (修改后):**

```html
<iframe id='owner' src='http://test.com' style='touch-action: auto'>
  <iframe id='child' src='http://test.com'>
    <div id='target' style='touch-action: pinch-zoom'></div>
  </iframe>
</iframe>
```

**逻辑推理:**

1. 父 iframe (`owner`) 的 `touch-action` 被修改为 `auto`，不再限制触摸行为。
2. 子 iframe 内部的元素 (`target`) 设置了 `touch-action: pinch-zoom`。
3. `StyleAdjuster` 会应用元素自身设置的 `touch-action`。

**预期输出 (修改后):**

`target` 元素的 `EffectiveTouchAction()` 应该返回 `TouchAction::kPinchZoom`。

**用户或编程常见的使用错误：**

1. **误解 `touch-action` 的继承和覆盖规则:** 开发者可能在父元素设置了 `touch-action: none`，期望阻止整个子树的触摸行为，但可能没有意识到滚动容器或可编辑区域可能会重新启用某些触摸行为。

   **例子:**

   ```html
   <div style="touch-action: none;">
     <div style="overflow: auto; width: 100px; height: 100px;">
       <div style="width: 200px; height: 200px;"></div>
     </div>
   </div>
   ```

   开发者可能期望内部的 `div` 完全禁用触摸，但由于中间的 `div` 是一个滚动容器，它可能会重新启用滚动行为。`StyleAdjuster` 的测试会验证这种情况下 `touch-action` 的最终计算结果。

2. **未考虑 `contenteditable` 对 `touch-action` 的影响:** 开发者可能没有意识到将一个 `div` 设置为 `contenteditable="true"` 会自动调整其 `touch-action` 以允许文本操作。

   **例子:**

   ```html
   <div contenteditable="true" style="touch-action: pan-y;">
     This is editable text.
   </div>
   ```

   开发者可能期望只允许垂直拖动，但 `StyleAdjuster` 会调整 `touch-action` 以允许文本选择和光标移动，可能包含水平方向的操作。

**用户操作如何一步步到达这里（调试线索）：**

1. **用户加载网页:** 用户在浏览器中打开一个包含复杂 CSS 样式和交互行为的网页。
2. **浏览器解析 HTML 和 CSS:** Blink 引擎解析 HTML 构建 DOM 树，解析 CSS 构建 CSSOM 树。
3. **样式计算:**  在样式计算阶段，`StyleAdjuster` 被调用，根据元素的 CSS 属性、继承关系、以及 Blink 特有的规则（例如，对滚动容器和可编辑区域的处理）来调整元素的计算样式。
4. **用户交互 (触摸屏幕):** 用户在触摸屏设备上与网页进行交互，例如尝试滚动、缩放、或者与可编辑区域进行交互。
5. **触摸事件处理:** 浏览器捕获触摸事件，并根据元素的计算样式（特别是 `touch-action`）来决定如何处理这些事件。
6. **调试线索:** 如果用户发现触摸行为不符合预期（例如，无法滚动某个区域，或者意外触发了缩放），开发者可能会开始检查元素的 CSS 样式，包括 `touch-action` 属性。如果怀疑是 Blink 引擎的样式调整逻辑有问题，他们可能会查看 `blink/renderer/core/css/resolver/style_adjuster_test.cc` 这样的测试文件，了解 `StyleAdjuster` 的工作原理，并尝试复现问题进行调试。他们可能会：
   - 查看相关测试用例，看是否覆盖了类似场景。
   - 运行这些测试用例，验证 `StyleAdjuster` 的行为是否符合预期。
   - 在 Blink 源码中查找 `StyleAdjuster` 的实现，跟踪样式调整的逻辑。
   - 使用开发者工具检查元素的计算样式，看 `touch-action` 的值是否被意外调整。

总而言之，`style_adjuster_test.cc` 文件是 Blink 引擎中一个非常重要的测试文件，它确保了 `StyleAdjuster` 组件能够正确地根据各种因素调整元素的计算样式，特别是 `touch-action` 属性，从而保证了网页的触摸交互行为符合预期。

### 提示词
```
这是目录为blink/renderer/core/css/resolver/style_adjuster_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/test/scoped_feature_list.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/frame/event_handler_registry.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "ui/base/ui_base_features.h"

namespace blink {

class StyleAdjusterTest : public RenderingTest {
 public:
  StyleAdjusterTest()
      : RenderingTest(MakeGarbageCollected<SingleChildLocalFrameClient>()) {}
};

TEST_F(StyleAdjusterTest, TouchActionPropagatedAcrossIframes) {
  GetDocument().SetBaseURLOverride(KURL("http://test.com"));
  SetBodyInnerHTML(R"HTML(
    <style>body { margin: 0; } iframe { display: block; } </style>
    <iframe id='owner' src='http://test.com' width='500' height='500'
    style='touch-action: none'>
    </iframe>
  )HTML");
  SetChildFrameHTML(R"HTML(
    <style>body { margin: 0; } #target { width: 200px; height: 200px; }
    </style>
    <div id='target' style='touch-action: pinch-zoom'></div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  Element* target = ChildDocument().getElementById(AtomicString("target"));
  EXPECT_EQ(TouchAction::kNone,
            target->GetComputedStyle()->EffectiveTouchAction());

  Element* owner = GetDocument().getElementById(AtomicString("owner"));
  owner->setAttribute(html_names::kStyleAttr,
                      AtomicString("touch-action: auto"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(TouchAction::kPinchZoom,
            target->GetComputedStyle()->EffectiveTouchAction());
}

TEST_F(StyleAdjusterTest, TouchActionPanningReEnabledByScrollers) {
  GetDocument().SetBaseURLOverride(KURL("http://test.com"));
  SetBodyInnerHTML(R"HTML(
    <style>#ancestor { margin: 0; touch-action: pinch-zoom; }
    #scroller { overflow: scroll; width: 100px; height: 100px; }
    #target { width: 200px; height: 200px; } </style>
    <div id='ancestor'><div id='scroller'><div id='target'>
    </div></div></div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  Element* target = GetDocument().getElementById(AtomicString("target"));
  EXPECT_EQ(TouchAction::kManipulation | TouchAction::kInternalPanXScrolls |
                TouchAction::kInternalNotWritable,
            target->GetComputedStyle()->EffectiveTouchAction());
}

TEST_F(StyleAdjusterTest, TouchActionPropagatedWhenAncestorStyleChanges) {
  GetDocument().SetBaseURLOverride(KURL("http://test.com"));
  SetBodyInnerHTML(R"HTML(
    <style>#ancestor { margin: 0; touch-action: pan-x; }
    #potential-scroller { width: 100px; height: 100px; overflow: hidden; }
    #target { width: 200px; height: 200px; }</style>
    <div id='ancestor'><div id='potential-scroller'><div id='target'>
    </div></div></div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  Element* target = GetDocument().getElementById(AtomicString("target"));
  EXPECT_EQ(TouchAction::kPanX | TouchAction::kInternalPanXScrolls |
                TouchAction::kInternalNotWritable,
            target->GetComputedStyle()->EffectiveTouchAction());

  Element* ancestor = GetDocument().getElementById(AtomicString("ancestor"));
  ancestor->setAttribute(html_names::kStyleAttr,
                         AtomicString("touch-action: pan-y"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(TouchAction::kPanY | TouchAction::kInternalNotWritable,
            target->GetComputedStyle()->EffectiveTouchAction());

  Element* potential_scroller =
      GetDocument().getElementById(AtomicString("potential-scroller"));
  potential_scroller->setAttribute(html_names::kStyleAttr,
                                   AtomicString("overflow: scroll"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(TouchAction::kPan | TouchAction::kInternalPanXScrolls |
                TouchAction::kInternalNotWritable,
            target->GetComputedStyle()->EffectiveTouchAction());
}

TEST_F(StyleAdjusterTest, TouchActionRestrictedByLowerAncestor) {
  GetDocument().SetBaseURLOverride(KURL("http://test.com"));
  SetBodyInnerHTML(R"HTML(
    <div id='ancestor' style='touch-action: pan'>
    <div id='parent' style='touch-action: pan-right pan-y'>
    <div id='target' style='touch-action: pan-x'>
    </div></div></div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  Element* target = GetDocument().getElementById(AtomicString("target"));
  EXPECT_EQ(TouchAction::kPanRight | TouchAction::kInternalPanXScrolls |
                TouchAction::kInternalNotWritable,
            target->GetComputedStyle()->EffectiveTouchAction());

  Element* parent = GetDocument().getElementById(AtomicString("parent"));
  parent->setAttribute(html_names::kStyleAttr,
                       AtomicString("touch-action: auto"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(TouchAction::kPanX | TouchAction::kInternalPanXScrolls |
                TouchAction::kInternalNotWritable,
            target->GetComputedStyle()->EffectiveTouchAction());
}

TEST_F(StyleAdjusterTest, TouchActionContentEditableArea) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitWithFeatures({::features::kSwipeToMoveCursor}, {});
  if (!::features::IsSwipeToMoveCursorEnabled()) {
    return;
  }

  GetDocument().SetBaseURLOverride(KURL("http://test.com"));
  SetBodyInnerHTML(R"HTML(
    <div id='editable1' contenteditable='false'></div>
    <input type="text" id='input1' disabled>
    <textarea id="textarea1" readonly></textarea>
    <div id='editable2' contenteditable='true'></div>
    <input type="text" id='input2'>
    <textarea id="textarea2"></textarea>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  EXPECT_EQ(TouchAction::kAuto, GetDocument()
                                    .getElementById(AtomicString("editable1"))
                                    ->GetComputedStyle()
                                    ->EffectiveTouchAction());
  EXPECT_EQ(TouchAction::kAuto, GetDocument()
                                    .getElementById(AtomicString("input1"))
                                    ->GetComputedStyle()
                                    ->EffectiveTouchAction());
  EXPECT_EQ(TouchAction::kAuto, GetDocument()
                                    .getElementById(AtomicString("textarea1"))
                                    ->GetComputedStyle()
                                    ->EffectiveTouchAction());
  EXPECT_EQ(TouchAction::kAuto & ~TouchAction::kInternalPanXScrolls,
            GetDocument()
                .getElementById(AtomicString("editable2"))
                ->GetComputedStyle()
                ->EffectiveTouchAction());
  EXPECT_EQ(TouchAction::kAuto & ~TouchAction::kInternalPanXScrolls,
            GetDocument()
                .getElementById(AtomicString("input2"))
                ->GetComputedStyle()
                ->EffectiveTouchAction());
  EXPECT_EQ(TouchAction::kAuto & ~TouchAction::kInternalPanXScrolls,
            GetDocument()
                .getElementById(AtomicString("textarea2"))
                ->GetComputedStyle()
                ->EffectiveTouchAction());

  Element* target = GetDocument().getElementById(AtomicString("editable1"));
  target->setAttribute(html_names::kContenteditableAttr, keywords::kTrue);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(TouchAction::kAuto & ~TouchAction::kInternalPanXScrolls,
            target->GetComputedStyle()->EffectiveTouchAction());
}

TEST_F(StyleAdjusterTest, TouchActionNoPanXScrollsWhenNoPanX) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitWithFeatures({::features::kSwipeToMoveCursor}, {});
  if (!::features::IsSwipeToMoveCursorEnabled()) {
    return;
  }

  GetDocument().SetBaseURLOverride(KURL("http://test.com"));
  SetBodyInnerHTML(R"HTML(
    <div id='target' contenteditable='false' style='touch-action: pan-y'></div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  Element* target = GetDocument().getElementById(AtomicString("target"));
  EXPECT_EQ(TouchAction::kPanY | TouchAction::kInternalNotWritable,
            target->GetComputedStyle()->EffectiveTouchAction());

  target->setAttribute(html_names::kContenteditableAttr, keywords::kTrue);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(TouchAction::kPanY | TouchAction::kInternalNotWritable,
            target->GetComputedStyle()->EffectiveTouchAction());
}

TEST_F(StyleAdjusterTest, TouchActionNotWritableReEnabledByScrollers) {
  base::test::ScopedFeatureList feature_list;
  ScopedStylusHandwritingForTest stylus_handwriting(true);

  GetDocument().SetBaseURLOverride(KURL("http://test.com"));
  SetBodyInnerHTML(R"HTML(
    <style>#ancestor { margin: 0; touch-action: none; }
    #scroller { overflow: auto; width: 100px; height: 100px; }
    #target { width: 200px; height: 200px; } </style>
    <div id='ancestor'><div id='scroller'><div id='target'>
    </div></div></div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  Element* target = GetDocument().getElementById(AtomicString("target"));
  EXPECT_TRUE((target->GetComputedStyle()->EffectiveTouchAction() &
               TouchAction::kInternalNotWritable) != TouchAction::kNone);
}

TEST_F(StyleAdjusterTest, TouchActionWritableArea) {
  base::test::ScopedFeatureList feature_list;
  ScopedStylusHandwritingForTest stylus_handwriting(true);

  GetDocument().SetBaseURLOverride(KURL("http://test.com"));
  SetBodyInnerHTML(R"HTML(
    <div id='editable1' contenteditable='false'></div>
    <input type="text" id='input1' disabled>
    <input type="password" id='password1' disabled>
    <textarea id="textarea1" readonly></textarea>
    <div id='editable2' contenteditable='true'></div>
    <input type="text" id='input2'>
    <input type="password" id='password2'>
    <textarea id="textarea2"></textarea>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  EXPECT_EQ(TouchAction::kAuto, GetDocument()
                                    .getElementById(AtomicString("editable1"))
                                    ->GetComputedStyle()
                                    ->EffectiveTouchAction());
  EXPECT_EQ(TouchAction::kAuto, GetDocument()
                                    .getElementById(AtomicString("input1"))
                                    ->GetComputedStyle()
                                    ->EffectiveTouchAction());
  EXPECT_EQ(TouchAction::kAuto, GetDocument()
                                    .getElementById(AtomicString("password1"))
                                    ->GetComputedStyle()
                                    ->EffectiveTouchAction());
  EXPECT_EQ(TouchAction::kAuto, GetDocument()
                                    .getElementById(AtomicString("textarea1"))
                                    ->GetComputedStyle()
                                    ->EffectiveTouchAction());

  TouchAction expected_input_action =
      (TouchAction::kAuto & ~TouchAction::kInternalNotWritable);
  TouchAction expected_pwd_action = TouchAction::kAuto;
  if (::features::IsSwipeToMoveCursorEnabled()) {
    expected_input_action &= ~TouchAction::kInternalPanXScrolls;
    expected_pwd_action &= ~TouchAction::kInternalPanXScrolls;
  }

  EXPECT_EQ(expected_input_action,
            GetDocument()
                .getElementById(AtomicString("editable2"))
                ->GetComputedStyle()
                ->EffectiveTouchAction());
  EXPECT_EQ(expected_input_action, GetDocument()
                                       .getElementById(AtomicString("input2"))
                                       ->GetComputedStyle()
                                       ->EffectiveTouchAction());
  EXPECT_EQ(expected_pwd_action, GetDocument()
                                     .getElementById(AtomicString("password2"))
                                     ->GetComputedStyle()
                                     ->EffectiveTouchAction());
  EXPECT_EQ(expected_input_action,
            GetDocument()
                .getElementById(AtomicString("textarea2"))
                ->GetComputedStyle()
                ->EffectiveTouchAction());

  Element* target = GetDocument().getElementById(AtomicString("editable1"));
  target->setAttribute(html_names::kContenteditableAttr, keywords::kTrue);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(expected_input_action,
            target->GetComputedStyle()->EffectiveTouchAction());
}

TEST_F(StyleAdjusterTest, OverflowClipUseCount) {
  GetDocument().SetBaseURLOverride(KURL("http://test.com"));
  SetBodyInnerHTML(R"HTML(
    <div></div>
    <div style='overflow: hidden'></div>
    <div style='overflow: scroll'></div>
    <div></div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(
      GetDocument().IsUseCounted(WebFeature::kOverflowClipAlongEitherAxis));

  SetBodyInnerHTML(R"HTML(
    <div style='overflow: clip'></div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(
      GetDocument().IsUseCounted(WebFeature::kOverflowClipAlongEitherAxis));
}

// crbug.com/1216721
TEST_F(StyleAdjusterTest, AdjustForSVGCrash) {
  SetBodyInnerHTML(R"HTML(
<style>
.class1 { dominant-baseline: hanging; }
</style>
<svg>
<tref>
<text id="text5" style="dominant-baseline: no-change;"/>
</svg>
<svg>
<use id="use1" xlink:href="#text5" class="class1" />
  )HTML");
  UpdateAllLifecyclePhasesForTest();
  Element* text = GetDocument()
                      .getElementById(AtomicString("use1"))
                      ->GetShadowRoot()
                      ->getElementById(AtomicString("text5"));
  EXPECT_EQ(EDominantBaseline::kHanging,
            text->GetComputedStyle()->CssDominantBaseline());
}

}  // namespace blink
```