Response:
The user wants me to summarize the functionality of the provided C++ code snippet. This code is a part of the Chromium Blink engine and specifically tests the `PaintLayer` functionality.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the core subject:** The filename and the content clearly indicate this code tests the `PaintLayer` class.

2. **Recognize the testing framework:** The `TEST_P` macros indicate this is a parameterized test using Google Test. This means different scenarios and configurations are being tested within the same test functions.

3. **Analyze individual test cases:**  Go through each `TEST_P` function and determine its purpose. Look for keywords and the actions being performed. For example:
    * `HitTest`: These tests are verifying the hit-testing logic for different scenarios involving `PaintLayer`s.
    * `SetNeedsRepaint`: This tests the repaint mechanism and how it propagates.
    * `ScrollContainerLayer`:  These tests focus on how `PaintLayer`s determine their containing scroll container.

4. **Group related test cases:**  Notice that many tests are related to `HitTest` but explore different aspects like pseudo-elements, transforms, scrollbars, and overlay resizers. Similarly, several tests focus on `ScrollContainerLayer` under various positioning contexts.

5. **Infer the overall purpose:**  Based on the individual test cases, deduce that the primary goal of this file is to ensure the correct behavior of `PaintLayer` in various rendering scenarios, especially concerning hit-testing and determining scroll containers.

6. **Connect to web technologies:**  Relate the `PaintLayer` concepts to web technologies like HTML, CSS, and JavaScript. Consider how CSS properties (like `opacity`, `float`, `transform`, `position`, `overflow`, `resize`, `clip-path`, `backdrop-filter`) and pseudo-elements (`::before`, `::first-letter`, `::scroll-marker`) influence the creation, behavior, and hit-testing of `PaintLayer`s. Hit-testing is directly related to user interaction (clicks, mouse movements), so this connection should be highlighted.

7. **Identify potential issues and debugging aspects:** Note tests that deal with edge cases or potential bugs, like the `HitTestTinyLayerUnderLargeScale` test, which targets a specific bug fix. The tests themselves provide debugging clues by showing how specific HTML/CSS configurations lead to certain `PaintLayer` behaviors.

8. **Structure the summary:** Organize the findings into logical sections. Start with a general overview, then elaborate on specific functionalities like hit-testing and scroll containers. Include the connections to web technologies, potential errors, and debugging aspects.

9. **Address the "part 3" instruction:**  Since this is the final part, reiterate the overall function of the file based on the accumulated knowledge from previous parts (even though they weren't provided in this prompt, the concept remains).

10. **Review and refine:**  Ensure the summary is clear, concise, and accurately reflects the content of the code. Use appropriate terminology related to web rendering and the Blink engine.

**(Self-Correction during the process):** Initially, I might just list the names of the test cases. However, the prompt asks for *functionality*. Therefore, I need to delve deeper into *what* each test is actually testing and *why* it's important. Also, directly connecting the tests to concrete HTML/CSS examples makes the explanation much more understandable for someone familiar with web development. I also need to explicitly mention the connection to user interaction through hit-testing.
这是 `paint_layer_test.cc` 文件的第三部分，它延续了前两部分的功能，主要集中在测试 `PaintLayer` 类的各种行为和交互。 从提供的代码片段来看，这一部分主要关注以下几个方面：

**功能归纳:**

1. **Hit-testing 功能的各种场景测试:**  本部分延续了前两部分的重点，深入测试了各种复杂的布局和渲染情况下 `PaintLayer` 的 hit-testing (点击测试) 功能。 这包括：
    *   **非自绘制元素下的自绘制子元素:** 检查当父元素是非自绘制时，其自绘制子元素的 hit-testing 是否正确。
    *   **带有 continuation 的伪元素:** 测试带有内容延续的伪元素（如 `::before`）的 hit-testing。
    *   **`::first-letter` 伪元素:** 测试 `::first-letter` 伪元素的 hit-testing，包括在包含块和 `::before` 伪元素中的情况。
    *   **行内盒子容器内的浮动元素:** 测试浮动元素在行内盒子容器中的 hit-testing。
    *   **`display: contents` 的 `::first-letter` 伪元素:**  测试当元素设置 `display: contents` 时，其 `::first-letter` 伪元素的 hit-testing。
    *   **Overlay Resizer (叠加层大小调整器):** 测试不同层叠上下文和 z-index 下 Overlay Resizer 的 hit-testing。
    *   **被裁剪的滚动条:** 测试被父元素裁剪的滚动条的 hit-testing。
    *   **透视和背面隐藏:** 测试在 3D 透视和 `backface-visibility: hidden` 影响下的 hit-testing。
    *   **被遮挡的 Overlay 滚动条:** 测试被其他元素遮挡的 Overlay 滚动条的 hit-testing。
    *   **全局根滚动器 (Global Root Scroller):** 测试应用了 `clip-path`, `background`, `transform` 等样式的根元素的 hit-testing，并考虑页面缩放。
    *   **小尺寸图层在大缩放下的 hit-testing:**  测试在应用大比例缩放的情况下，对非常小的图层进行 hit-testing 的准确性，以防止出现精度问题。
    *   **带有 3D 后代的图层的 hit-testing:** 测试具有 3D 变换子元素的图层的 hit-testing，防止出现崩溃。
    *   **滚动标记伪元素 (`::scroll-marker`):** 测试新的滚动标记伪元素的 hit-testing 和默认事件处理。

2. **`SetNeedsRepaint` 功能测试:** 测试当自绘制元素嵌套在非自绘制元素下时，调用 `SetNeedsRepaint` 是否能正确触发祖先元素的重绘标志。

3. **`ContainingScrollContainerLayer` 功能测试:**  测试 `PaintLayer` 的 `ContainingScrollContainerLayer` 方法在各种复杂的布局场景下的行为，判断元素所属的滚动容器以及是否固定在视口。 这些场景包括：
    *   根滚动器下的各种定位元素 (`position: sticky`, `absolute`, `fixed`, `transform`)。
    *   相对定位滚动容器下的各种定位元素。
    *   嵌套滚动容器下的各种定位元素。
    *   在 `position: fixed` 元素下的滚动容器。
    *   在 `transform` 影响下的 `position: fixed` 元素下的滚动容器。
    *   自身是 `position: fixed` 的滚动容器。
    *   同时具有 `transform` 和 `position: fixed` 的滚动容器。
    *   自身具有 `transform` 的滚动容器。

4. **`HasPaintLayer` 功能测试:** 检查某些 CSS 属性（例如 `backdrop-filter`）是否会导致元素创建 `PaintLayer`。

5. **图层更新相关的测试:** 测试在添加一个需要创建新图层的子元素时，父图层是否正确标记了 `DescendantNeedsRepaint` 和 `DescendantNeedsCullRectUpdate`。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个测试文件直接关联着 HTML 和 CSS 的渲染机制。 每个测试用例都通过设置特定的 HTML 结构和 CSS 样式来触发不同的 `PaintLayer` 创建和渲染行为。

*   **HTML:**  测试用例使用 HTML 元素（如 `div`, `span`, `a`, `map`) 来构建页面结构。例如，`<div id='target'>` 定义了一个可以被 CSS 样式化的元素，并可以通过 JavaScript 获取。

*   **CSS:**  测试用例大量使用 CSS 属性来控制元素的布局、渲染和行为。例如：
    *   `opacity: 0.5`:  用于测试非自绘制元素。
    *   `float: left; overflow: hidden`: 用于创建新的层叠上下文，影响 `PaintLayer` 的创建。
    *   `columns: 2`: 用于创建多列布局。
    *   `position: sticky`, `absolute`, `fixed`:  影响元素的定位和 `PaintLayer` 的所属关系。
    *   `transform: rotate(1deg)`, `transform: translate3d(...)`, `transform: scale(...)`:  创建变换，通常会创建新的 `PaintLayer`。
    *   `backface-visibility: hidden`:  影响 3D 变换元素的背面是否可见。
    *   `overflow: scroll`, `resize: both`:  创建滚动容器和可调整大小的元素。
    *   `clip-path: circle(30%)`: 用于裁剪元素。
    *   `backdrop-filter: invert(1)`:  应用背景滤镜，会导致创建 `PaintLayer`。
    *   `::before`, `::first-letter`, `::scroll-marker`:  伪元素，用于测试对这些特殊渲染盒子的 hit-testing。
    *   `display: contents`:  控制元素的显示方式，会影响 `PaintLayer` 的创建和继承。

*   **JavaScript:** 虽然这个测试文件本身是用 C++ 编写的，用于测试 Blink 引擎的内部机制，但这些测试场景最终会影响到 JavaScript 与页面交互的行为。 例如：
    *   **Hit-testing:** 当用户在页面上点击时，浏览器需要判断点击事件发生在哪个元素上。 `PaintLayer` 的 hit-testing 功能的正确性直接影响到 JavaScript 事件处理程序的触发。 例如，在测试 `HitTestFirstLetterPseudoElement` 时，如果 hit-testing 不正确，点击到 first-letter 伪元素时，可能无法正确触发绑定到父元素的 JavaScript 事件。
    *   **滚动行为:** `ContainingScrollContainerLayer` 功能的正确性关系到 JavaScript 中与滚动相关的 API (如 `scrollTop`, `scrollLeft`) 的行为。 如果 `PaintLayer` 无法正确识别滚动容器，JavaScript 代码可能无法正确获取或设置元素的滚动位置。

**逻辑推理、假设输入与输出:**

*   **假设输入 (以 `SetNeedsRepaintSelfPaintingUnderNonSelfPainting` 为例):**
    *   HTML 结构：包含一个设置了 `opacity` 的 `span` 元素，其内部包含一个设置了 `float` 和 `overflow: hidden` 的 `div`，再内部包含一个设置了 `columns` 的 `div`。
    *   操作：调用浮动 `div` 的 `PaintLayer` 的 `SetNeedsRepaint()` 方法。
*   **预期输出:**
    *   父 `span` 元素的 `PaintLayer` 的 `DescendantNeedsRepaint()` 返回 `true`。
    *   浮动 `div` 元素的 `PaintLayer` 的 `SelfNeedsRepaint()` 返回 `true`。
    *   HTML 根元素的 `PaintLayer` 的 `DescendantNeedsRepaint()` 返回 `true`。

*   **假设输入 (以 `HitTestFirstLetterPseudoElement` 为例):**
    *   HTML 结构：包含一个设置了 `height` 的 `div`，其内部包含一个包含文本的 `span` 元素，并为容器 `div` 设置了 `::first-letter` 的样式 (`font-size: 50px`)。
    *   操作：在 `::first-letter` 伪元素占据的区域内进行 hit-testing。
*   **预期输出:**
    *   `result.InnerNode()` 等于 `span` 元素。
    *   `result.InnerPossiblyPseudoNode()` 等于容器 `div` 的 `::first-letter` 伪元素。

**用户或编程常见的使用错误及举例说明:**

*   **CSS 属性对 `PaintLayer` 创建的误解:** 开发者可能不清楚哪些 CSS 属性会触发新的 `PaintLayer` 的创建。例如，开发者可能认为只有 `position: absolute` 或 `position: fixed` 才会创建新的 `PaintLayer`，而忽略了 `transform`, `opacity`, `filter` 等属性也会创建。这可能导致意想不到的渲染行为和性能问题。
    *   **示例:**  开发者为了实现动画效果，可能会在很多元素上使用 `opacity` 来实现淡入淡出，但如果元素过多，每个元素都创建一个 `PaintLayer` 会导致性能下降。

*   **Z-index 的错误使用:** 开发者可能对 `z-index` 和层叠上下文的理解不够深入，导致元素的层叠顺序不符合预期。 `PaintLayer` 的 hit-testing 功能的测试有助于确保在复杂的层叠上下文中点击事件能正确传递。
    *   **示例:**  开发者可能在一个没有设置 `position: relative/absolute/fixed` 的元素上设置 `z-index`，期望它能覆盖其他元素，但实际上没有效果，因为该元素没有创建新的层叠上下文。

*   **对伪元素 hit-testing 的误解:** 开发者可能不清楚如何对伪元素进行 hit-testing 或绑定事件。 例如，可能尝试直接获取伪元素的引用并绑定事件，但实际上需要通过父元素进行处理。

**用户操作是如何一步步的到达这里，作为调试线索:**

这些测试用例模拟了各种用户与网页交互的情况，以及浏览器渲染引擎在处理这些交互时的内部逻辑。  以下是一些用户操作如何触发到 `PaintLayer` 和 hit-testing 的示例：

1. **页面加载和渲染:**
    *   用户在浏览器中输入网址或点击链接。
    *   浏览器解析 HTML 结构，构建 DOM 树。
    *   浏览器解析 CSS 样式，构建 CSSOM 树。
    *   结合 DOM 和 CSSOM 构建渲染树 (Render Tree)，其中会创建 LayoutObject。
    *   根据 LayoutObject 创建 PaintLayer 树。
    *   进行绘制 (Painting) 阶段，将 PaintLayer 的内容绘制到屏幕上。

2. **用户交互 (例如点击):**
    *   用户在页面上点击鼠标。
    *   浏览器接收到点击事件。
    *   浏览器需要确定点击事件发生在哪个元素上，这会触发 hit-testing 过程。
    *   `PaintLayer` 的 hit-testing 逻辑会被调用，遍历 `PaintLayer` 树，判断点击位置是否在某个 `PaintLayer` 的边界内。
    *   最终确定被点击的元素，并触发该元素绑定的 JavaScript 事件处理程序。

3. **CSS 属性变更或动画:**
    *   JavaScript 代码修改元素的 CSS 属性（例如通过 `element.style.opacity = 0.5`）。
    *   CSS 动画或过渡效果触发样式变化。
    *   这些变化可能导致 `PaintLayer` 的属性更新，甚至创建或销毁 `PaintLayer`。
    *   如果涉及到影响布局或绘制的属性，可能会触发重排 (Layout) 和重绘 (Paint)。
    *   `SetNeedsRepaint` 方法会被调用，标记需要重新绘制的 `PaintLayer`。

4. **滚动:**
    *   用户滚动鼠标滚轮或拖动滚动条。
    *   浏览器需要更新可视区域，并可能需要重新绘制部分内容。
    *   `ContainingScrollContainerLayer` 的逻辑被用来确定哪些元素是滚动容器，以及哪些元素需要随着滚动而移动或保持固定。

作为调试线索，当网页出现渲染错误、点击事件无法正确触发、元素层叠顺序错误或性能问题时，开发者可以通过以下步骤进行调试，并可能最终追溯到 `PaintLayer` 的相关问题：

1. **使用浏览器开发者工具:**
    *   查看 Elements 面板，检查元素的样式和布局信息。
    *   使用 Performance 面板分析页面性能，查看是否有过多的重排和重绘。
    *   使用 Layers 面板查看页面的 `PaintLayer` 结构，了解哪些元素创建了新的 `PaintLayer`。

2. **分析 CSS 样式:** 检查是否有不必要的 CSS 属性导致创建了过多的 `PaintLayer`。

3. **检查 JavaScript 代码:**  查看是否有 JavaScript 代码错误地修改了元素的样式或位置，导致渲染问题。

4. **逐步缩小问题范围:** 通过注释或修改 HTML 和 CSS 代码，逐步排除可能导致问题的元素和样式。

理解 `PaintLayer` 的工作原理和这些测试用例覆盖的场景，可以帮助开发者更好地理解浏览器渲染引擎的行为，并更有效地调试和优化网页性能。

Prompt: 
```
这是目录为blink/renderer/core/paint/paint_layer_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共3部分，请归纳一下它的功能

"""
               svg->GetLayoutObject());
  result = HitTestResult(request, location);
  GetDocument().GetLayoutView()->HitTest(location, result);
  EXPECT_EQ(svg, result.InnerNode());
}

TEST_P(PaintLayerTest, SetNeedsRepaintSelfPaintingUnderNonSelfPainting) {
  SetHtmlInnerHTML(R"HTML(
    <span id='span' style='opacity: 0.5'>
      <div id='floating' style='float: left; overflow: hidden'>
        <div id='multicol' style='columns: 2'>A</div>
      </div>
    </span>
  )HTML");

  auto* html_layer = To<LayoutBoxModelObject>(
                         GetDocument().documentElement()->GetLayoutObject())
                         ->Layer();
  auto* span_layer = GetPaintLayerByElementId("span");
  auto* floating_layer = GetPaintLayerByElementId("floating");

  EXPECT_FALSE(html_layer->SelfNeedsRepaint());
  EXPECT_FALSE(span_layer->SelfNeedsRepaint());
  EXPECT_FALSE(floating_layer->SelfNeedsRepaint());
  EXPECT_FALSE(floating_layer->SelfNeedsRepaint());
  floating_layer->SetNeedsRepaint();
  EXPECT_TRUE(html_layer->DescendantNeedsRepaint());
  EXPECT_TRUE(span_layer->DescendantNeedsRepaint());
  EXPECT_TRUE(floating_layer->SelfNeedsRepaint());
}

TEST_P(PaintLayerTest, HitTestPseudoElementWithContinuation) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin: 0; }
      #target::before {
        content: ' ';
        display: block;
        height: 100px
      }
    </style>
    <span id='target'></span>
  )HTML");
  Element* target = GetDocument().getElementById(AtomicString("target"));
  HitTestRequest request(HitTestRequest::kReadOnly | HitTestRequest::kActive);
  HitTestLocation location(PhysicalOffset(10, 10));
  HitTestResult result(request, location);
  GetDocument().GetLayoutView()->HitTest(location, result);
  EXPECT_EQ(target, result.InnerNode());
  EXPECT_EQ(target->GetPseudoElement(kPseudoIdBefore),
            result.InnerPossiblyPseudoNode());
}

TEST_P(PaintLayerTest, HitTestFirstLetterPseudoElement) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin: 0; }
      #container { height: 100px; }
      #container::first-letter { font-size: 50px; }
    </style>
    <div id='container'>
      <div>
        <span id='target'>First letter</span>
      </div>
    </div>
  )HTML");
  Element* target = GetDocument().getElementById(AtomicString("target"));
  Element* container = GetDocument().getElementById(AtomicString("container"));
  HitTestRequest request(HitTestRequest::kReadOnly | HitTestRequest::kActive);
  HitTestLocation location(PhysicalOffset(10, 10));
  HitTestResult result(request, location);
  GetDocument().GetLayoutView()->HitTest(location, result);
  EXPECT_EQ(target, result.InnerNode());
  EXPECT_EQ(container->GetPseudoElement(kPseudoIdFirstLetter),
            result.InnerPossiblyPseudoNode());
}

TEST_P(PaintLayerTest, HitTestFirstLetterInBeforePseudoElement) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin: 0; }
      #container { height: 100px; }
      #container::first-letter { font-size: 50px; }
      #target::before { content: "First letter"; }
    </style>
    <div id='container'>
      <div>
        <span id='target'></span>
      </div>
    </div>
  )HTML");
  Element* target = GetDocument().getElementById(AtomicString("target"));
  Element* container = GetDocument().getElementById(AtomicString("container"));
  HitTestRequest request(HitTestRequest::kReadOnly | HitTestRequest::kActive);
  HitTestLocation location(PhysicalOffset(10, 10));
  HitTestResult result(request, location);
  GetDocument().GetLayoutView()->HitTest(location, result);
  EXPECT_EQ(target, result.InnerNode());
  EXPECT_EQ(container->GetPseudoElement(kPseudoIdFirstLetter),
            result.InnerPossiblyPseudoNode());
}

TEST_P(PaintLayerTest, HitTestFloatInsideInlineBoxContainer) {
  LoadAhem();
  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin: 0; }
      #container { font: 10px/10px Ahem; width: 70px; }
      #inline-container { border: 1px solid black; }
      #target { float: right; }
    </style>
    <div id='container'>
      <span id='inline-container'>
        <a href='#' id='target'>bar</a>
        foo
      </span>
    </div>
  )HTML");
  Node* target =
      GetDocument().getElementById(AtomicString("target"))->firstChild();
  HitTestRequest request(HitTestRequest::kReadOnly | HitTestRequest::kActive);
  HitTestLocation location(PhysicalOffset(55, 5));  // At the center of "bar"
  HitTestResult result(request, location);
  GetDocument().GetLayoutView()->HitTest(location, result);
  EXPECT_EQ(target, result.InnerNode());
}

TEST_P(PaintLayerTest, HitTestFirstLetterPseudoElementDisplayContents) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin: 0; }
      #container { height: 100px; }
      #container::first-letter { font-size: 50px; }
      #target { display: contents; }
    </style>
    <div id='container'>
      <div>
        <span id='target'>First letter</span>
      </div>
    </div>
  )HTML");
  Element* target = GetDocument().getElementById(AtomicString("target"));
  Element* container = GetDocument().getElementById(AtomicString("container"));
  HitTestRequest request(HitTestRequest::kReadOnly | HitTestRequest::kActive);
  HitTestLocation location(PhysicalOffset(10, 10));
  HitTestResult result(request, location);
  GetDocument().GetLayoutView()->HitTest(location, result);
  EXPECT_EQ(target, result.InnerNode());
  EXPECT_EQ(container->GetPseudoElement(kPseudoIdFirstLetter),
            result.InnerPossiblyPseudoNode());
}

TEST_P(PaintLayerTest, HitTestOverlayResizer) {
  SetBodyInnerHTML(R"HTML(
    <style>
      * {
        margin: 0;
      }
      div {
        width: 200px;
        height: 200px;
      }
      body > div {
        overflow: hidden;
        resize: both;
        display: none;
      }
      #target_0 {
        position: relative;
        z-index: -1;
      }
      #target_2 {
        position: relative;
      }
      #target_3 {
        position: relative;
        z-index: 1;
      }
    </style>
    <!--
      Definitions: Nor(Normal flow paint layer), Pos(Positive paint layer),
      Neg(Negative paint layer)
    -->
    <!--0. Neg+Pos-->
    <div id="target_0" class="resize">
      <div style="position: relative"></div>
    </div>

    <!--1. Nor+Pos-->
    <div id="target_1" class="resize">
      <div style="position: relative"></div>
    </div>

    <!--2. Pos+Pos(siblings)-->
    <div id="target_2" class="resize">
      <div style="position: relative"></div>
    </div>

    <!--3. Pos+Pos(parent-child)-->
    <div id="target_3" class="resize">
      <div style="position: relative"></div>
    </div>

    <!--4. Nor+Pos+Nor-->
    <div id="target_4" class="resize">
      <div style="position: relative; z-index: 1">
        <div style="position: relative"></div>
      </div>
    </div>

    <!--5. Nor+Pos+Neg-->
    <div id="target_5" class="resize">
      <div style="position: relative; z-index: -1">
        <div style="position: relative"></div>
      </div>
    </div>
  )HTML");

  for (int i = 0; i < 6; i++) {
    Element* target_element = GetDocument().getElementById(
        AtomicString(String::Format("target_%d", i)));
    target_element->setAttribute(html_names::kStyleAttr,
                                 AtomicString("display: block"));
    UpdateAllLifecyclePhasesForTest();

    HitTestRequest request(HitTestRequest::kIgnoreClipping);
    HitTestLocation location((gfx::Point(198, 198)));
    HitTestResult result(request, location);
    GetDocument().GetLayoutView()->HitTest(location, result);
    if (i == 0)
      EXPECT_NE(target_element, result.InnerNode());
    else
      EXPECT_EQ(target_element, result.InnerNode());

    target_element->setAttribute(html_names::kStyleAttr,
                                 AtomicString("display: none"));
  }
}

TEST_P(PaintLayerTest, HitTestScrollbarUnderClip) {
  USE_NON_OVERLAY_SCROLLBARS_OR_QUIT();

  SetBodyInnerHTML(R"HTML(
    <style>body { margin: 50px; }</style>
    <div style="overflow: hidden; width: 200px; height: 100px">
      <div id="target" style="width: 200px; height: 200px; overflow: scroll">
        <!-- This relative div triggers crbug.com/1360860. -->
        <div style="position: relative"></div>
      </div>
    </div>
    <div id="below" style="height: 200px"></div>
  )HTML");

  // Hit the visible part of the vertical scrollbar.
  EXPECT_EQ(GetDocument().getElementById(AtomicString("target")),
            HitTest(245, 100));
  // Should not hit the hidden part of the vertical scrollbar, the hidden
  // horizontal scrollbar, or the hidden scroll corner.
  EXPECT_EQ(GetDocument().getElementById(AtomicString("below")),
            HitTest(245, 200));
  EXPECT_EQ(GetDocument().getElementById(AtomicString("below")),
            HitTest(150, 245));
  EXPECT_EQ(GetDocument().getElementById(AtomicString("below")),
            HitTest(245, 245));
}

TEST_P(PaintLayerTest, HitTestPerspectiveBackfaceHiddenNotInverted) {
  SetBodyInnerHTML(R"HTML(
    <style>body { margin: 0 }</style>
    <div style="transform: translate3d(50px, 80px, 200px);
                transform-style: preserve-3d; perspective: 100px;">
      <div id="target" style="width: 100px; height: 100px; background: green;
                              backface-visibility: hidden"></div>
    </div>
  )HTML");

  EXPECT_EQ(GetDocument().body(), HitTest(49, 79));
  EXPECT_EQ(GetDocument().getElementById(AtomicString("target")),
            HitTest(50, 80));
  EXPECT_EQ(GetDocument().getElementById(AtomicString("target")),
            HitTest(149, 179));
  EXPECT_EQ(GetDocument().documentElement(), HitTest(150, 180));
}

TEST_P(PaintLayerTest, HitTestObscuredOverlayScrollbar) {
  SetBodyInnerHTML(R"HTML(
    <div id="scroll" style="position: absolute; width: 200px; height: 200px;
                            top: 0; left: 0; overflow: scroll">
      <div style="position: relative; height: 400px"></div>
    </div>
    <div id="above" style="position: absolute; left: 100px; top: 100px;
                           width: 200px; height: 200px"></div>
  )HTML");

  auto* scroller = GetDocument().getElementById(AtomicString("scroll"));
  scroller->GetLayoutBox()->GetScrollableArea()->SetScrollbarsHiddenForTesting(
      false);
  EXPECT_EQ(scroller, HitTest(199, 1));
  EXPECT_EQ(GetDocument().getElementById(AtomicString("above")),
            HitTest(199, 101));
}

TEST_P(PaintLayerTest, InlineWithBackdropFilterHasPaintLayer) {
  SetBodyInnerHTML(
      "<map id='target' style='backdrop-filter: invert(1);'></map>");
  PaintLayer* paint_layer = GetPaintLayerByElementId("target");
  PaintLayer* root_layer = GetLayoutView().Layer();

  EXPECT_NE(nullptr, root_layer);
  EXPECT_NE(nullptr, paint_layer);
}

TEST_P(PaintLayerTest, GlobalRootScrollerHitTest) {
  SetBodyInnerHTML(R"HTML(
    <style>
      :root {
        clip-path: circle(30%);
        background:blue;
        transform: rotate(30deg);
        transform-style: preserve-3d;
      }
      #perspective {
        perspective:100px;
      }
      #threedee {
        transform: rotate3d(1, 1, 1, 45deg);
        width:100px; height:200px;
      }
    </style>
    <div id="perspective">
      <div id="threedee"></div>
    </div>
  )HTML");
  GetDocument().GetPage()->SetPageScaleFactor(2);
  UpdateAllLifecyclePhasesForTest();

  const HitTestRequest hit_request(HitTestRequest::kActive);
  const HitTestLocation location(gfx::Point(400, 300));
  HitTestResult result;
  GetLayoutView().HitTestNoLifecycleUpdate(location, result);
  EXPECT_EQ(result.InnerNode(), GetDocument().documentElement());
  EXPECT_EQ(result.GetScrollbar(), nullptr);

  if (GetDocument().GetPage()->GetScrollbarTheme().AllowsHitTest()) {
    const HitTestLocation location_scrollbar(gfx::Point(790, 300));
    HitTestResult result_scrollbar;
    EXPECT_EQ(result_scrollbar.InnerNode(), &GetDocument());
    EXPECT_NE(result_scrollbar.GetScrollbar(), nullptr);
  }
}

TEST_P(PaintLayerTest, HitTestTinyLayerUnderLargeScale) {
  SetBodyInnerHTML(R"HTML(
    <div id="target" style="width: 1px; height: 1px;
                            transform: scale(200); transform-origin: 0 0">
    </div>
  )HTML");

  auto* target = GetDocument().getElementById(AtomicString("target"));
  // Before https://crrev.com/c/4250297,
  // HitTestingTransformState::BoundsOfMappedQuadInternal() might "randomly"
  // return an empty rect with some of the following hit test locations.
  // See https://crbug.com/1414042.
  for (float x = 50; x < 50.5; x += 0.001) {
    const HitTestLocation location(gfx::PointF(x, 50));
    HitTestResult result;
    GetLayoutView().HitTest(location, result);
    EXPECT_EQ(target, result.InnerNode()) << " x=" << x;
  }
}

TEST_P(PaintLayerTest, AddLayerNeedsRepaintAndCullRectUpdate) {
  SetBodyInnerHTML(R"HTML(
    <div id="parent" style="opacity: 0.9">
      <div id="child"></div>
  )HTML");

  auto* parent_layer = GetPaintLayerByElementId("parent");
  EXPECT_FALSE(parent_layer->DescendantNeedsRepaint());
  EXPECT_FALSE(parent_layer->DescendantNeedsCullRectUpdate());
  auto* child = GetLayoutBoxByElementId("child");
  EXPECT_FALSE(child->HasLayer());

  GetDocument()
      .getElementById(AtomicString("child"))
      ->setAttribute(html_names::kStyleAttr,
                     AtomicString("position: relative"));
  GetDocument().View()->UpdateLifecycleToLayoutClean(
      DocumentUpdateReason::kTest);
  EXPECT_TRUE(parent_layer->DescendantNeedsRepaint());
  EXPECT_TRUE(parent_layer->DescendantNeedsCullRectUpdate());

  auto* child_layer = child->Layer();
  ASSERT_TRUE(child_layer);
  EXPECT_TRUE(child_layer->SelfNeedsRepaint());
  EXPECT_TRUE(child_layer->NeedsCullRectUpdate());
}

TEST_P(PaintLayerTest, HitTestLayerWith3DDescendantCrash) {
  SetBodyInnerHTML(R"HTML(
    <div id="target" style="transform: translate(0)">
      <div style="transform-style: preserve-3d; transform: rotateY(1deg)"></div>
    </div>
  )HTML");

  auto* target = GetPaintLayerByElementId("target");
  EXPECT_TRUE(target->Has3DTransformedDescendant());
  HitTestRequest request(0);
  HitTestLocation location;
  HitTestResult result(request, location);
  // This should not crash.
  target->HitTest(location, result, PhysicalRect(0, 0, 800, 600));
}

#define TEST_SCROLL_CONTAINER(name, expected_scroll_container,           \
                              expected_is_fixed_to_view)                 \
  do {                                                                   \
    auto* layer = GetPaintLayerByElementId(name);                        \
    bool is_fixed_to_view = false;                                       \
    EXPECT_EQ(expected_scroll_container,                                 \
              layer->ContainingScrollContainerLayer(&is_fixed_to_view)); \
    EXPECT_EQ(expected_is_fixed_to_view, is_fixed_to_view);              \
  } while (false)

TEST_P(PaintLayerTest, ScrollContainerLayerRootScroller) {
  SetBodyInnerHTML(R"HTML(
    <div id="sticky" style="position: sticky"></div>
    <div id="absolute" style="position: absolute"></div>
    <div id="fixed" style="position: fixed">
      <div id="sticky-under-fixed" style="position: sticky"></div>
      <div id="absolute-under-fixed" style="position: absolute"></div>
      <div id="fixed-under-fixed" style="position: fixed">
        <div id="sticky-under-nested-fixed" style="position: sticky"></div>
        <div id="absolute-under-nested-fixed" style="position: absolute"></div>
        <div id="fixed-under-nested-fixed" style="position: fixed"></div>
        <div id="transform-under-nested-fixed" style="transform: rotate(1deg)">
        </div>
      </div>
      <div id="transform-under-fixed" style="transform: rotate(1deg)"></div>
    </div>
    <div id="transform" style="transform: rotate(1deg)">
      <div id="sticky-under-transform" style="position: sticky"></div>
      <div id="absolute-under-transform" style="position: absolute"></div>
      <div id="fixed-under-transform" style="position: fixed"></div>
      <div id="transform-under-transform" style="transform: rotate(1deg)"></div>
    </div>
  )HTML");

  auto* view_layer = GetLayoutView().Layer();
  {
    bool is_fixed_to_view = false;
    EXPECT_EQ(nullptr,
              view_layer->ContainingScrollContainerLayer(&is_fixed_to_view));
    EXPECT_TRUE(is_fixed_to_view);
  }

  TEST_SCROLL_CONTAINER("sticky", view_layer, false);
  TEST_SCROLL_CONTAINER("absolute", view_layer, false);
  TEST_SCROLL_CONTAINER("fixed", view_layer, true);
  TEST_SCROLL_CONTAINER("transform", view_layer, false);

  TEST_SCROLL_CONTAINER("sticky-under-fixed", view_layer, true);
  TEST_SCROLL_CONTAINER("absolute-under-fixed", view_layer, true);
  TEST_SCROLL_CONTAINER("fixed-under-fixed", view_layer, true);
  TEST_SCROLL_CONTAINER("transform-under-fixed", view_layer, true);

  TEST_SCROLL_CONTAINER("sticky-under-nested-fixed", view_layer, true);
  TEST_SCROLL_CONTAINER("absolute-under-nested-fixed", view_layer, true);
  TEST_SCROLL_CONTAINER("fixed-under-nested-fixed", view_layer, true);
  TEST_SCROLL_CONTAINER("transform-under-nested-fixed", view_layer, true);

  TEST_SCROLL_CONTAINER("sticky-under-transform", view_layer, false);
  TEST_SCROLL_CONTAINER("absolute-under-transform", view_layer, false);
  TEST_SCROLL_CONTAINER("fixed-under-transform", view_layer, false);
  TEST_SCROLL_CONTAINER("transform-under-transform", view_layer, false);
}

TEST_P(PaintLayerTest, ScrollContainerLayerRelativeScroller) {
  SetBodyInnerHTML(R"HTML(
    <div id="scroller" style="width: 100px; height: 100px; overflow: scroll;
                              position: relative">
      <div id="sticky" style="position: sticky">
        <div id="sticky-under-sticky" style="position: sticky"></div>
        <div id="absolute-under-sticky" style="position: absolute"></div>
        <div id="fixed-under-sticky" style="position: fixed"></div>
        <div id="transform-under-sticky" style="transform: rotate(1deg)"></div>
      </div>
      <div id="absolute" style="position: absolute">
        <div id="sticky-under-absolute" style="position: sticky"></div>
        <div id="absolute-under-absolute" style="position: absolute"></div>
        <div id="fixed-under-absolute" style="position: fixed"></div>
        <div id="transform-under-absolute" style="transform: rotate(1deg)">
        </div>
      </div>
      <div id="fixed" style="position: fixed">
        <div id="sticky-under-fixed" style="position: sticky"></div>
        <div id="absolute-under-fixed" style="position: absolute"></div>
        <div id="fixed-under-fixed" style="position: fixed"></div>
        <div id="transform-under-fixed" style="transform: rotate(1deg)"></div>
      </div>
      <div id="transform" style="transform: rotate(1deg)">
        <div id="sticky-under-transform" style="position: sticky"></div>
        <div id="absolute-under-transform" style="position: absolute"></div>
        <div id="fixed-under-transform" style="position: fixed"></div>
        <div id="transform-under-transform" style="transform: rotate(1deg)">
        </div>
      </div>
  )HTML");

  auto* view_layer = GetLayoutView().Layer();
  // scroller has relative position so contains absolute but not fixed.
  auto* scroller = GetPaintLayerByElementId("scroller");
  ASSERT_TRUE(scroller->GetLayoutObject().CanContainAbsolutePositionObjects());
  ASSERT_FALSE(scroller->GetLayoutObject().CanContainFixedPositionObjects());
  TEST_SCROLL_CONTAINER("scroller", view_layer, false);

  TEST_SCROLL_CONTAINER("sticky", scroller, false);
  TEST_SCROLL_CONTAINER("sticky-under-sticky", scroller, false);
  TEST_SCROLL_CONTAINER("absolute-under-sticky", scroller, false);
  TEST_SCROLL_CONTAINER("fixed-under-sticky", view_layer, true);
  TEST_SCROLL_CONTAINER("transform-under-sticky", scroller, false);

  TEST_SCROLL_CONTAINER("absolute", scroller, false);
  TEST_SCROLL_CONTAINER("sticky-under-absolute", scroller, false);
  TEST_SCROLL_CONTAINER("absolute-under-absolute", scroller, false);
  TEST_SCROLL_CONTAINER("fixed-under-absolute", view_layer, true);
  TEST_SCROLL_CONTAINER("transform-under-absolute", scroller, false);

  TEST_SCROLL_CONTAINER("fixed", view_layer, true);
  TEST_SCROLL_CONTAINER("sticky-under-fixed", view_layer, true);
  TEST_SCROLL_CONTAINER("absolute-under-fixed", view_layer, true);
  TEST_SCROLL_CONTAINER("fixed-under-fixed", view_layer, true);
  TEST_SCROLL_CONTAINER("transform-under-fixed", view_layer, true);

  TEST_SCROLL_CONTAINER("transform", scroller, false);
  TEST_SCROLL_CONTAINER("sticky-under-transform", scroller, false);
  TEST_SCROLL_CONTAINER("absolute-under-transform", scroller, false);
  TEST_SCROLL_CONTAINER("fixed-under-transform", scroller, false);
  TEST_SCROLL_CONTAINER("transform-under-transform", scroller, false);
}

TEST_P(PaintLayerTest, ScrollContainerLayerNestedScroller) {
  SetBodyInnerHTML(R"HTML(
    <div id="scroller1" style="width: 100px; height: 100px; overflow: scroll;
                               position: relative">
      <div id="scroller2" style="width: 100px; height: 100px; overflow: scroll">
        <div id="sticky" style="position: sticky"></div>
        <div id="absolute" style="position: absolute"></div>
        <div id="fixed" style="position: fixed"></div>
        <div id="transform" style="transform: rotate(1deg"></div>
      </div>
    </div>
  )HTML");

  auto* view_layer = GetLayoutView().Layer();
  // scroller1 has relative position so contains absolute but not fixed.
  // scroller2 is static position so contains neither absolute or fixed.
  auto* scroller1 = GetPaintLayerByElementId("scroller1");
  auto* scroller2 = GetPaintLayerByElementId("scroller2");
  ASSERT_FALSE(
      scroller2->GetLayoutObject().CanContainAbsolutePositionObjects());
  ASSERT_FALSE(scroller2->GetLayoutObject().CanContainFixedPositionObjects());
  TEST_SCROLL_CONTAINER("scroller2", scroller1, false);

  TEST_SCROLL_CONTAINER("sticky", scroller2, false);
  TEST_SCROLL_CONTAINER("absolute", scroller1, false);
  TEST_SCROLL_CONTAINER("fixed", view_layer, true);
  TEST_SCROLL_CONTAINER("transform", scroller2, false);
}

TEST_P(PaintLayerTest, ScrollContainerLayerScrollerUnderRealFixed) {
  SetBodyInnerHTML(R"HTML(
    <div style="position: fixed">
      <div id="scroller" style="width: 100px; height: 100px; overflow: scroll">
        <div id="sticky" style="position: sticky"></div>
        <div id="absolute" style="position: absolute"></div>
        <div id="fixed" style="position: fixed"></div>
        <div id="transform" style="transform: rotate(1deg"></div>
      </div>
    </div>
  )HTML");

  auto* view_layer = GetLayoutView().Layer();
  // scroller is static_position, under real position:fixed.
  auto* scroller = GetPaintLayerByElementId("scroller");
  TEST_SCROLL_CONTAINER("scroller", view_layer, true);
  TEST_SCROLL_CONTAINER("sticky", scroller, false);
  TEST_SCROLL_CONTAINER("absolute", view_layer, true);
  TEST_SCROLL_CONTAINER("fixed", view_layer, true);
  TEST_SCROLL_CONTAINER("transform", scroller, false);
}

TEST_P(PaintLayerTest, ScrollContainerLayerScrollerUnderFakeFixed) {
  SetBodyInnerHTML(R"HTML(
    <div style="transform: rotate(1deg)">
      <div style="position: fixed">
        <div id="scroller"
             style="width: 100px; height: 100px; overflow: scroll">
          <div id="sticky" style="position: sticky"></div>
          <div id="absolute" style="position: absolute"></div>
          <div id="fixed" style="position: fixed"></div>
          <div id="transform" style="transform: rotate(1deg"></div>
        </div>
      </div>
    </div>
  )HTML");

  auto* view_layer = GetLayoutView().Layer();
  // scroller is static position, under fake position:fixed.
  auto* scroller = GetPaintLayerByElementId("scroller");
  TEST_SCROLL_CONTAINER("scroller", view_layer, false);
  TEST_SCROLL_CONTAINER("sticky", scroller, false);
  TEST_SCROLL_CONTAINER("absolute", view_layer, false);
  TEST_SCROLL_CONTAINER("fixed", view_layer, false);
  TEST_SCROLL_CONTAINER("transform", scroller, false);
}

TEST_P(PaintLayerTest, ScrollContainerLayerFixedScroller) {
  SetBodyInnerHTML(R"HTML(
    <div id="scroller"
         style="position: fixed; width: 100px; height: 100px; overflow: scroll">
      <div id="sticky" style="position: sticky"></div>
      <div id="absolute" style="position: absolute"></div>
      <div id="fixed" style="position: fixed"></div>
      <div id="transform" style="transform: rotate(1deg"></div>
    </div>
  )HTML");

  auto* view_layer = GetLayoutView().Layer();
  // scroller itself has real fixed position.
  auto* scroller = GetPaintLayerByElementId("scroller");
  TEST_SCROLL_CONTAINER("scroller", view_layer, true);
  TEST_SCROLL_CONTAINER("sticky", scroller, false);
  TEST_SCROLL_CONTAINER("absolute", scroller, false);
  TEST_SCROLL_CONTAINER("fixed", view_layer, true);
  TEST_SCROLL_CONTAINER("transform", scroller, false);
}

TEST_P(PaintLayerTest, ScrollContainerLayerScrollerUnderTransformAndFixed) {
  SetBodyInnerHTML(R"HTML(
    <div style="transform: rotate(1deg); position: fixed">
      <div id="scroller" style="width: 100px; height: 100px; overflow: scroll">
        <div id="sticky" style="position: sticky"></div>
        <div id="absolute" style="position: absolute"></div>
        <div id="fixed" style="position: fixed"></div>
        <div id="transform" style="transform: rotate(1deg"></div>
      </div>
    </div>
  )HTML");

  auto* view_layer = GetLayoutView().Layer();
  auto* scroller = GetPaintLayerByElementId("scroller");
  TEST_SCROLL_CONTAINER("scroller", view_layer, true);
  TEST_SCROLL_CONTAINER("sticky", scroller, false);
  TEST_SCROLL_CONTAINER("absolute", view_layer, true);
  TEST_SCROLL_CONTAINER("fixed", view_layer, true);
  TEST_SCROLL_CONTAINER("transform", scroller, false);
}

TEST_P(PaintLayerTest, ScrollContainerLayerTransformScroller) {
  SetBodyInnerHTML(R"HTML(
    <div id="scroller" style="transform: rotate(1deg);
                              width: 100px; height: 100px; overflow: scroll">
      <div id="sticky" style="position: sticky"></div>
      <div id="absolute" style="position: absolute"></div>
      <div id="fixed" style="position: fixed"></div>
      <div id="transform" style="transform: rotate(1deg"></div>
    </div>
  )HTML");

  auto* view_layer = GetLayoutView().Layer();
  auto* scroller = GetPaintLayerByElementId("scroller");
  TEST_SCROLL_CONTAINER("scroller", view_layer, false);
  TEST_SCROLL_CONTAINER("sticky", scroller, false);
  TEST_SCROLL_CONTAINER("absolute", scroller, false);
  TEST_SCROLL_CONTAINER("fixed", scroller, false);
  TEST_SCROLL_CONTAINER("transform", scroller, false);
}

TEST_P(PaintLayerTest, HitTestScrollMarkerPseudoElement) {
  GetDocument().body()->setInnerHTML(
      "<style>"
      "#scroller { overflow: scroll; scroll-marker-group: before; width: "
      "100px; height: 100px; }"
      "#scroller::scroll-marker-group { border: 3px solid black; display: "
      "flex; width: 100px; height: 20px; }"
      "#scroller div { width: 100px; height: 100px; background: green; }"
      "#scroller div::scroll-marker { content: ''; display: inline-flex; "
      "width: 10px; height: 10px; background: green; border-radius: 50%; }"
      "</style>"
      "<div id='scroller'>"
      "  <div></div>"
      "  <div id='second_div'></div>"
      "</div>");
  UpdateAllLifecyclePhasesForTest();
  Element* scroller = GetDocument().getElementById(AtomicString("scroller"));
  EXPECT_EQ(scroller->scrollTop(), 0);
  Element* second_div =
      GetDocument().getElementById(AtomicString("second_div"));
  PseudoElement* second_scroll_marker =
      second_div->GetPseudoElement(kPseudoIdScrollMarker);

  HitTestRequest request(HitTestRequest::kReadOnly | HitTestRequest::kActive);
  HitTestLocation location(PhysicalOffset(25, 20));
  HitTestResult result(request, location);
  GetDocument().GetLayoutView()->HitTest(location, result);
  EXPECT_EQ(second_scroll_marker, result.InnerNode());

  MouseEvent& event = *MouseEvent::Create();
  event.SetType(event_type_names::kClick);
  event.SetTarget(second_scroll_marker);
  second_scroll_marker->DefaultEventHandler(event);
  EXPECT_EQ(scroller->scrollTop(), 100);
}

}  // namespace blink

"""


```