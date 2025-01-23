Response:
Let's break down the thought process for analyzing this C++ test file and generating the comprehensive explanation.

**1. Initial Understanding of the Request:**

The request asks for an analysis of a specific Chromium Blink engine test file (`box_paint_invalidator_test.cc`). The key areas to focus on are:

* **Functionality:** What does this test file *do*?
* **Relationship to Web Technologies:** How does it connect to JavaScript, HTML, and CSS?
* **Logic and Examples:**  Provide concrete examples of the tests, including inputs and expected outputs.
* **User/Developer Errors:**  Identify potential mistakes developers could make that this test helps prevent.
* **Debugging Context:** Explain how a user's actions could lead to this code being executed.

**2. Scanning the Code for Key Indicators:**

The first step is to quickly read through the code, looking for recurring patterns and important class names. This provides a high-level overview.

* **Includes:** The `#include` directives are crucial. They tell us what other parts of the Blink engine this test interacts with. We see names like `PaintInvalidator`, `LayoutBox`, `HTMLFrameOwnerElement`, `LayoutView`, `PaintController`, `RasterInvalidationTracking`. These suggest the test is heavily focused on the painting and layout processes.
* **Class Name:**  `BoxPaintInvalidatorTest` immediately tells us this is a test for the `BoxPaintInvalidator` class (or a closely related concept).
* **Test Macros:** `TEST_P`, `INSTANTIATE_PAINT_TEST_SUITE_P` indicate this is a parameterized test fixture, meaning the same test logic might run with different configurations (likely different rendering pipelines).
* **Helper Functions:**  `ComputePaintInvalidationReason`, `ExpectFullPaintInvalidationOnGeometryChange`, and `SetUpHTML` are custom functions within the test class. These will be central to understanding the test's purpose.
* **Assertions:** `EXPECT_EQ`, `EXPECT_THAT`, `UnorderedElementsAre` are Google Test assertions, showing what the tests are verifying.
* **HTML Snippets:**  The `R"HTML(...)HTML"` blocks contain HTML and CSS, demonstrating the scenarios being tested.
* **Focus on `PaintInvalidationReason`:**  This enum appears frequently, suggesting the test is primarily about determining *why* repainting is necessary.

**3. Deep Dive into Key Components:**

Now, focus on the most important parts identified in the scan.

* **`BoxPaintInvalidator`:** The core subject of the test. The name strongly suggests it's responsible for figuring out when and how to invalidate (mark for repainting) parts of the rendered output when properties of a "box" (HTML elements) change.
* **`ComputePaintInvalidationReason`:**  This function seems to be the primary mechanism for triggering the logic being tested. It takes a `LayoutBox` and its old paint offset as input and returns a `PaintInvalidationReason`. This is the central "act" of the tests.
* **`PaintInvalidationReason`:**  The different values of this enum (e.g., `kNone`, `kIncremental`, `kLayout`, `kStyle`, `kSVGResource`) are the *possible outcomes* of the `BoxPaintInvalidator`'s calculation. Understanding these values is key to understanding the test's goals.
* **`ExpectFullPaintInvalidationOnGeometryChange`:** This helper function clearly tests scenarios where a change in geometry (size, position) should trigger a full repaint rather than an incremental one. This suggests there are optimizations for smaller changes.
* **HTML and CSS:** The HTML and CSS snippets define the specific elements and styles being manipulated in each test case. Analyzing these reveals what kind of changes are being tested (e.g., changing width, adding borders, outlines, masks, filters, etc.).

**4. Connecting to Web Technologies:**

With a better understanding of the code, the connections to web technologies become clearer:

* **HTML:** The tests manipulate HTML elements (divs, potentially others). Changes to attributes like `style` and `class` are the triggers for the invalidation logic.
* **CSS:**  CSS properties like `width`, `border`, `background`, `outline`, `mask`, `filter`, `box-shadow`, `clip-path`, `transform`, and `will-change` are directly involved in causing repaints.
* **JavaScript (Implicit):** While there's no explicit JavaScript in the test file, the test infrastructure simulates how JavaScript might manipulate the DOM and trigger style changes. A real-world scenario would likely involve JavaScript code changing element attributes or styles.

**5. Constructing Examples and Logic:**

Based on the individual test cases, create concrete examples:

* **Input:** Describe the initial HTML/CSS and the specific change being made (e.g., "Initially, a div with a border. Then the border is removed").
* **Expected Output:**  State the expected `PaintInvalidationReason` (e.g., `kIncremental` for a size change without visual overflow, `kLayout` for a size change with visual overflow). Explain *why* that's the expected outcome based on the code's logic.

**6. Identifying User/Developer Errors:**

Think about common mistakes developers make when working with CSS and JavaScript that could lead to unexpected repaints.

* **Unnecessary `will-change`:** Overusing `will-change` can hurt performance. The test indirectly checks scenarios related to compositing and `will-change`.
* **Forgetting About Visual Overflow:** Developers might change sizes without realizing it will cause outlines or shadows to draw outside the original bounds, requiring a larger repaint.
* **Incorrectly Assuming Incremental Repaints:** Developers might assume a small change will always be cheap, but certain property changes (like those tested) might necessitate a full layout or paint.

**7. Tracing User Actions for Debugging:**

Imagine a user interacting with a web page and how that could lead to the execution of this code.

* **Direct Manipulation:**  User clicks a button, triggering JavaScript to change an element's style.
* **Dynamic Content:**  A web application updates data, causing JavaScript to add or remove elements or modify their styles.
* **Animations/Transitions:** CSS animations or transitions inherently cause style changes over time.

**8. Structuring the Explanation:**

Organize the information logically:

* Start with a concise summary of the file's purpose.
* Detail the functionality by explaining the main components and how they work.
* Provide clear examples with inputs and outputs.
* Explain the connections to web technologies.
* Discuss potential errors and how the tests help.
* Describe the debugging context.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  This is just about repainting.
* **Correction:**  It's more specifically about *why* a repaint is needed and distinguishing between different levels of repainting (incremental vs. full layout).
* **Initial thought:** The examples are self-explanatory from the code.
* **Refinement:**  Need to provide clear "input" and "expected output" descriptions for each test scenario to make it easier to understand.
* **Initial thought:** The connection to web technologies is obvious.
* **Refinement:** Need to explicitly list the relevant HTML elements and CSS properties and explain how the tests relate to them.

By following this systematic approach,  breaking down the code into smaller pieces, and connecting it to broader web development concepts, it's possible to generate a comprehensive and informative explanation like the example provided in the prompt.
这个文件 `blink/renderer/core/paint/box_paint_invalidator_test.cc` 是 Chromium Blink 引擎中的一个 C++ 单元测试文件。它的主要功能是**测试 `BoxPaintInvalidator` 类的逻辑，该类负责决定在布局（LayoutBox）的属性发生变化时，需要进行何种程度的重绘（Paint Invalidation）**。

更具体地说，这个测试文件会模拟各种 HTML 元素和 CSS 属性的变化，然后断言 `BoxPaintInvalidator` 类计算出的 `PaintInvalidationReason` 是否符合预期。`PaintInvalidationReason` 是一个枚举类型，表示重绘的原因，例如：

* `kNone`: 不需要重绘。
* `kIncremental`:  只需要增量重绘，即只重绘发生变化的部分。
* `kLayout`: 需要进行布局重绘，因为元素的几何属性发生了变化，影响了其在页面上的位置和大小。
* `kStyle`: 因为样式发生了变化，但没有影响布局。
* 其他更具体的重绘原因。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

这个测试文件直接关系到 HTML 和 CSS 的渲染过程，而 JavaScript 经常用于动态修改 HTML 结构和 CSS 样式，因此也间接地与 JavaScript 有关。

* **HTML:**  测试用例中会创建各种 HTML 元素，例如 `<div>` 元素，并通过 `getElementById` 获取这些元素进行操作。
    * **举例：**  `GetDocument().getElementById(AtomicString("target"))`  这行代码模拟了 JavaScript 中 `document.getElementById("target")` 的功能，用于获取 ID 为 "target" 的 HTML 元素。
* **CSS:** 测试用例会通过修改元素的 `style` 属性或 `class` 属性来改变元素的 CSS 样式。
    * **举例：**
        * `target.setAttribute(html_names::kStyleAttr, AtomicString("width: 200px"));`  模拟了 JavaScript 中设置元素的 `style` 属性，例如 `element.style.width = "200px"`。
        * `target.setAttribute(html_names::kClassAttr, g_empty_atom);` 模拟了移除元素的 CSS 类，可能会导致样式的变化。
* **JavaScript:** 虽然测试文件本身是 C++ 代码，但它模拟了 JavaScript 操作 DOM 导致样式和布局变化的情况。当 JavaScript 代码修改了元素的样式或属性时，Blink 引擎会触发相应的重绘流程，`BoxPaintInvalidator` 就是这个流程中的关键组件。
    * **举例：** 假设一个网页中有以下 JavaScript 代码：
      ```javascript
      const targetElement = document.getElementById('target');
      targetElement.style.backgroundColor = 'red';
      ```
      这段代码会改变 ID 为 "target" 的元素的背景颜色。Blink 引擎在执行这段 JavaScript 代码后，会调用相应的机制来标记需要重绘的区域，`BoxPaintInvalidator` 会参与决定需要进行哪种程度的重绘。

**逻辑推理、假设输入与输出：**

测试用例 `ComputePaintInvalidationReasonBasic` 就是一个逻辑推理的例子。

**假设输入：**

1. 初始 HTML 结构：
    ```html
    <div id='target' class='border' style='background: blue'></div>
    ```
    对应的 CSS 中 `.border` 定义了边框。
2. 初始状态下，`target` 元素的布局盒子的绘制偏移量 `paint_offset` 为 (0, 0)。
3. 第一次变化：修改 `target` 元素的 `style` 属性，添加 `width: 200px;`。

**逻辑推理过程：**

`BoxPaintInvalidator` 会比较元素修改前后的状态，特别是几何属性（如大小、位置）的变化。由于 `width` 属性发生了变化，元素的尺寸会改变，但没有超出其包含块，因此应该进行增量重绘。

**预期输出：**

`ComputePaintInvalidationReason` 函数在第一次变化后，应该返回 `PaintInvalidationReason::kIncremental`。

**假设输入（继续 `ComputePaintInvalidationReasonBasic` 例子）：**

1. 第二次变化：在第一次变化的基础上，添加 `outline: 5px solid red`。

**逻辑推理过程：**

`outline` 属性会产生视觉溢出，即使元素的尺寸没有直接改变，但由于轮廓线会绘制在元素边界之外，需要重新计算需要重绘的区域，这通常会导致布局相关的重绘。

**预期输出：**

`ComputePaintInvalidationReason` 函数在第二次变化后，应该返回 `PaintInvalidationReason::kLayout`。

**用户或编程常见的使用错误及举例说明：**

* **错误地假设小的样式变化不会触发重绘：**  开发者可能会认为只修改一个颜色或简单的样式不会导致性能问题，但实际上，即使是很小的样式变化也可能触发重绘。`BoxPaintInvalidator` 的测试可以帮助理解哪些类型的变化会触发哪种程度的重绘。
    * **例子：** 假设开发者使用 JavaScript 频繁地改变一个元素的 `opacity` 属性来实现动画效果。如果该元素没有被提升为合成层，那么每次 `opacity` 的变化都可能触发重绘，影响性能。理解 `BoxPaintInvalidator` 的工作原理可以帮助开发者选择更优的动画实现方式，例如使用 `transform: opacity()` 或将元素提升为合成层。
* **不理解不同 CSS 属性对重绘的影响：**  某些 CSS 属性的改变比其他属性的改变代价更高。例如，修改布局相关的属性（如 `width`, `height`, `position`）通常比修改颜色更耗费资源。
    * **例子：** 开发者可能在 JavaScript 中使用 `element.style.left` 和 `element.style.top` 来移动元素，而没有意识到这种操作会频繁触发布局重绘。更好的做法可能是使用 `transform: translate()`，因为它通常可以避免布局重绘，只触发合成层的重绘。`BoxPaintInvalidator` 的测试覆盖了各种 CSS 属性，帮助开发者理解其影响。

**用户操作是如何一步步的到达这里，作为调试线索：**

当用户在浏览器中进行操作，导致网页的视觉效果需要更新时，就会触发重绘流程。以下是一个可能的步骤：

1. **用户操作：** 用户点击一个按钮，或者鼠标悬停在一个元素上，或者滚动页面，或者在输入框中输入文字。
2. **JavaScript 执行：**  这些用户操作通常会触发 JavaScript 代码的执行。
3. **DOM 和 CSSOM 修改：**  JavaScript 代码可能会修改 DOM 结构（例如，添加或删除元素）或 CSSOM（CSS 对象模型，例如，修改元素的样式）。
4. **样式计算和布局：**  Blink 引擎会根据 DOM 和 CSSOM 的变化，重新计算元素的样式和布局信息。
5. **`BoxPaintInvalidator` 的调用：**  在布局完成后，如果检测到元素的视觉属性发生了变化，Blink 引擎会使用 `BoxPaintInvalidator` 来确定需要重绘的区域和原因。
    *  `BoxPaintInvalidator` 会接收到发生变化的 `LayoutBox` 对象，以及可能的一些上下文信息（例如，之前的绘制偏移量）。
    *  `BoxPaintInvalidator` 会比较元素修改前后的状态，并根据其内部的逻辑判断应该返回哪种 `PaintInvalidationReason`。
6. **重绘（Painting）：**  根据 `PaintInvalidationReason`，Blink 引擎会执行相应的重绘操作，将更新后的内容绘制到屏幕上。
7. **合成（Compositing）：** 如果使用了硬件加速，重绘的结果会被上传到 GPU 进行合成，最终显示在用户的屏幕上。

**调试线索：**

当开发者遇到页面渲染问题（例如，性能不佳、出现闪烁、元素没有正确更新）时，理解 `BoxPaintInvalidator` 的工作原理可以作为调试的线索：

* **检查重绘原因：**  开发者可以使用浏览器提供的开发者工具（例如 Chrome DevTools 的 Performance 面板）来查看页面重绘的原因。如果看到频繁的 "Layout" 或 "Paint" 事件，可能意味着某些操作触发了不必要的重绘。
* **分析触发重绘的操作：**  通过分析 JavaScript 代码和 CSS 样式，找出哪些操作导致了重绘。
* **利用 `BoxPaintInvalidator` 的测试用例：**  查看 `box_paint_invalidator_test.cc` 中的测试用例，可以帮助理解哪些 CSS 属性的变化会触发哪种类型的重绘。例如，如果发现某个元素的 `outline` 属性变化导致了性能问题，可以参考测试用例 `ComputePaintInvalidationReasonOutline`，了解 `outline` 属性对重绘的影响。
* **优化策略：**  根据对重绘原因的分析，可以采取相应的优化策略，例如：
    *  避免频繁修改布局相关的 CSS 属性。
    *  使用 `transform` 和 `opacity` 来实现动画效果，而不是直接修改 `left`, `top` 等属性。
    *  利用 CSS 的 `will-change` 属性来提前告知浏览器哪些属性可能会发生变化，以便进行优化。
    *  将需要频繁重绘的元素提升为合成层。

总之，`blink/renderer/core/paint/box_paint_invalidator_test.cc` 是一个重要的测试文件，它验证了 Blink 引擎中负责决定重绘策略的核心组件的正确性。理解其功能和相关的概念对于前端开发者进行性能优化和调试渲染问题非常有帮助。

### 提示词
```
这是目录为blink/renderer/core/paint/box_paint_invalidator_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/paint/box_paint_invalidator.h"

#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/html/html_frame_owner_element.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/paint/paint_and_raster_invalidation_test.h"
#include "third_party/blink/renderer/core/paint/paint_controller_paint_test.h"
#include "third_party/blink/renderer/core/paint/paint_invalidator.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/platform/graphics/paint/raster_invalidation_tracking.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"

namespace blink {

using ::testing::UnorderedElementsAre;

class BoxPaintInvalidatorTest : public PaintAndRasterInvalidationTest {
 public:
  BoxPaintInvalidatorTest() = default;

 protected:
  PaintInvalidationReason ComputePaintInvalidationReason(
      LayoutBox& box,
      const PhysicalOffset& old_paint_offset) {
    PaintInvalidatorContext context;
    context.old_paint_offset = old_paint_offset;
    fragment_data_->SetPaintOffset(box.FirstFragment().PaintOffset());
    context.fragment_data = fragment_data_;
    return BoxPaintInvalidator(box, context).ComputePaintInvalidationReason();
  }

  // This applies when the target is set to meet conditions that we should do
  // full paint invalidation instead of incremental invalidation on geometry
  // change.
  void ExpectFullPaintInvalidationOnGeometryChange(const char* test_title) {
    SCOPED_TRACE(test_title);

    UpdateAllLifecyclePhasesForTest();
    auto& target = *GetDocument().getElementById(AtomicString("target"));
    auto& box = *target.GetLayoutBox();
    auto paint_offset = box.FirstFragment().PaintOffset();
    box.SetShouldCheckForPaintInvalidation();

    // No geometry change.
    EXPECT_EQ(PaintInvalidationReason::kNone,
              ComputePaintInvalidationReason(box, paint_offset));

    target.setAttribute(
        html_names::kStyleAttr,
        target.getAttribute(html_names::kStyleAttr) + "; width: 200px");
    GetDocument().View()->UpdateLifecycleToLayoutClean(
        DocumentUpdateReason::kTest);

    EXPECT_EQ(PaintInvalidationReason::kLayout,
              ComputePaintInvalidationReason(box, paint_offset));
  }

  void SetUpHTML() {
    SetBodyInnerHTML(R"HTML(
      <style>
        body {
          margin: 0;
          height: 0;
        }
        ::-webkit-scrollbar { display: none }
        #target {
          width: 50px;
          height: 100px;
          transform-origin: 0 0;
        }
        .background {
          background: blue;
        }
        .border {
          border-width: 20px 10px;
          border-style: solid;
          border-color: red;
        }
      </style>
      <div id='target' class='border'></div>
    )HTML");
  }

 private:
  Persistent<FragmentData> fragment_data_ =
      MakeGarbageCollected<FragmentData>();
};

INSTANTIATE_PAINT_TEST_SUITE_P(BoxPaintInvalidatorTest);

// Paint invalidation for empty content is needed for updating composited layer
// bounds for correct composited hit testing. It won't cause raster invalidation
// (tested in paint_and_raster_invalidation_test.cc).
TEST_P(BoxPaintInvalidatorTest, ComputePaintInvalidationReasonEmptyContent) {
  SetUpHTML();
  auto& target = *GetDocument().getElementById(AtomicString("target"));
  auto& box = *target.GetLayoutBox();
  // Remove border.
  target.setAttribute(html_names::kClassAttr, g_empty_atom);
  UpdateAllLifecyclePhasesForTest();

  box.SetShouldCheckForPaintInvalidation();
  auto paint_offset = box.FirstFragment().PaintOffset();

  // No geometry change.
  EXPECT_EQ(PaintInvalidationReason::kNone,
            ComputePaintInvalidationReason(box, paint_offset));

  // Paint offset change.
  auto old_paint_offset = paint_offset + PhysicalOffset(10, 20);
  EXPECT_EQ(PaintInvalidationReason::kLayout,
            ComputePaintInvalidationReason(box, old_paint_offset));

  // Size change.
  target.setAttribute(html_names::kStyleAttr, AtomicString("width: 200px"));
  GetDocument().View()->UpdateLifecycleToLayoutClean(
      DocumentUpdateReason::kTest);
  EXPECT_EQ(PaintInvalidationReason::kIncremental,
            ComputePaintInvalidationReason(box, paint_offset));
}

TEST_P(BoxPaintInvalidatorTest, ComputePaintInvalidationReasonBasic) {
  SetUpHTML();
  auto& target = *GetDocument().getElementById(AtomicString("target"));
  auto& box = *target.GetLayoutBox();
  // Remove border.
  target.setAttribute(html_names::kClassAttr, g_empty_atom);
  target.setAttribute(html_names::kStyleAttr, AtomicString("background: blue"));
  UpdateAllLifecyclePhasesForTest();

  box.SetShouldCheckForPaintInvalidation();
  auto paint_offset = box.FirstFragment().PaintOffset();
  EXPECT_EQ(PhysicalOffset(), paint_offset);

  // No geometry change.
  EXPECT_EQ(PaintInvalidationReason::kNone,
            ComputePaintInvalidationReason(box, paint_offset));

  // Size change.
  target.setAttribute(html_names::kStyleAttr,
                      AtomicString("background: blue; width: 200px"));
  GetDocument().View()->UpdateLifecycleToLayoutClean(
      DocumentUpdateReason::kTest);
  EXPECT_EQ(PaintInvalidationReason::kIncremental,
            ComputePaintInvalidationReason(box, paint_offset));

  // Add visual overflow.
  target.setAttribute(
      html_names::kStyleAttr,
      AtomicString("background: blue; width: 200px; outline: 5px solid red"));
  UpdateAllLifecyclePhasesForTest();

  // Size change with visual overflow.
  target.setAttribute(
      html_names::kStyleAttr,
      AtomicString("background: blue; width: 100px; outline: 5px solid red"));
  GetDocument().View()->UpdateLifecycleToLayoutClean(
      DocumentUpdateReason::kTest);

  EXPECT_EQ(PaintInvalidationReason::kLayout,
            ComputePaintInvalidationReason(box, paint_offset));

  // Computed kLayout has higher priority than the non-geometry paint
  // invalidation reason on the LayoutBox.
  box.SetShouldDoFullPaintInvalidationWithoutLayoutChange(
      PaintInvalidationReason::kStyle);
  EXPECT_EQ(PaintInvalidationReason::kLayout,
            ComputePaintInvalidationReason(box, paint_offset));

  // If the LayoutBox has a geometry paint invalidation reason, the reason is
  // returned directly without checking geometry change.
  box.SetShouldDoFullPaintInvalidation(PaintInvalidationReason::kSVGResource);
  EXPECT_EQ(PaintInvalidationReason::kSVGResource,
            ComputePaintInvalidationReason(box, paint_offset));
}

TEST_P(BoxPaintInvalidatorTest,
       InvalidateLineBoxHitTestOnCompositingStyleChange) {
  ScopedPaintUnderInvalidationCheckingForTest under_invalidation_checking(true);
  SetBodyInnerHTML(R"HTML(
    <style>
      #target {
        width: 100px;
        height: 100px;
        touch-action: none;
      }
    </style>
    <div id="target" style="will-change: transform;">a<br>b</div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();
  auto& target = *GetDocument().getElementById(AtomicString("target"));
  target.setAttribute(html_names::kStyleAttr, g_empty_atom);
  UpdateAllLifecyclePhasesForTest();
  // This test passes if no underinvalidation occurs.
}

TEST_P(BoxPaintInvalidatorTest, ComputePaintInvalidationReasonOtherCases) {
  SetUpHTML();
  auto& target = *GetDocument().getElementById(AtomicString("target"));

  // The target initially has border.
  ExpectFullPaintInvalidationOnGeometryChange("With border");

  // Clear border, set background.
  target.setAttribute(html_names::kClassAttr, AtomicString("background"));
  target.setAttribute(html_names::kStyleAttr,
                      AtomicString("border-radius: 5px"));
  ExpectFullPaintInvalidationOnGeometryChange("With border-radius");

  target.setAttribute(html_names::kStyleAttr,
                      AtomicString("-webkit-mask: url(#)"));
  ExpectFullPaintInvalidationOnGeometryChange("With mask");

  target.setAttribute(html_names::kStyleAttr,
                      AtomicString("filter: blur(5px)"));
  ExpectFullPaintInvalidationOnGeometryChange("With filter");

  target.setAttribute(html_names::kStyleAttr,
                      AtomicString("box-shadow: inset 3px 2px"));
  ExpectFullPaintInvalidationOnGeometryChange("With box-shadow");

  target.setAttribute(html_names::kStyleAttr,
                      AtomicString("clip-path: circle(50% at 0 50%)"));
  ExpectFullPaintInvalidationOnGeometryChange("With clip-path");
}

TEST_P(BoxPaintInvalidatorTest, ComputePaintInvalidationReasonOutline) {
  SetUpHTML();
  auto& target = *GetDocument().getElementById(AtomicString("target"));
  auto* object = target.GetLayoutObject();

  GetDocument().View()->SetTracksRasterInvalidations(true);
  target.setAttribute(html_names::kStyleAttr,
                      AtomicString("outline: 2px solid blue;"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_THAT(GetRasterInvalidationTracking()->Invalidations(),
              UnorderedElementsAre(RasterInvalidationInfo{
                  object->Id(), object->DebugName(), gfx::Rect(0, 0, 72, 142),
                  PaintInvalidationReason::kLayout}));
  GetDocument().View()->SetTracksRasterInvalidations(false);

  GetDocument().View()->SetTracksRasterInvalidations(true);
  target.setAttribute(html_names::kStyleAttr,
                      AtomicString("outline: 2px solid blue; width: 100px;"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_THAT(GetRasterInvalidationTracking()->Invalidations(),
              UnorderedElementsAre(RasterInvalidationInfo{
                  object->Id(), object->DebugName(), gfx::Rect(0, 0, 122, 142),
                  PaintInvalidationReason::kLayout}));
  GetDocument().View()->SetTracksRasterInvalidations(false);
}

TEST_P(BoxPaintInvalidatorTest, InvalidateHitTestOnCompositingStyleChange) {
  ScopedPaintUnderInvalidationCheckingForTest under_invalidation_checking(true);
  SetBodyInnerHTML(R"HTML(
    <style>
      #target {
        width: 400px;
        height: 300px;
        overflow: hidden;
        touch-action: none;
      }
    </style>
    <div id="target" style="will-change: transform;"></div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();
  auto& target = *GetDocument().getElementById(AtomicString("target"));
  target.setAttribute(html_names::kStyleAttr, g_empty_atom);
  UpdateAllLifecyclePhasesForTest();
  // This test passes if no under-invalidation occurs.
}

}  // namespace blink
```