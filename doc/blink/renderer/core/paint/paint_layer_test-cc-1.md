Response:
The user has provided a snippet of a C++ file `paint_layer_test.cc` from the Chromium Blink engine. They've asked for a summary of its functionality based on the provided code, given that it's part 2 of a 3-part request.

My goal is to:

1. **Analyze the C++ code:** Identify the core functionalities being tested. Look for patterns in the `TEST_P` blocks and the actions performed within them.
2. **Relate to web technologies:**  Connect the C++ tests to concepts in HTML, CSS, and JavaScript where applicable. Provide concrete examples.
3. **Infer logic and assumptions:**  Understand the test scenarios, the expected inputs (HTML/CSS), and the anticipated outputs (state of paint layers, hit-testing results).
4. **Identify potential user errors:**  Think about how developers using these web technologies might make mistakes that these tests are designed to catch or prevent.
5. **Describe the user journey to this code:**  Explain the steps a developer or even a browser user might take that would lead to the execution of this specific code during rendering.
6. **Summarize the functionality:**  Based on the analysis, provide a concise summary of the purpose of this code snippet.

**Code Analysis - Key Observations:**

* **`TEST_P` with different names:**  The code uses `TEST_P` macros, indicating parameterized tests. The names (e.g., `ReorderOverlayOverflowControlsTest`, `PaintLayerTest`) suggest different categories of tests.
* **HTML/CSS setup:** Each test case starts by setting up an HTML structure and applying CSS styles using `SetBodyInnerHTML` and `SetChildFrameHTML`.
* **`GetPaintLayerByElementId`:** This function is frequently used to retrieve `PaintLayer` objects, which are core to the rendering process.
* **Assertions (`EXPECT_...`)**: The tests use `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_EQ`, `EXPECT_THAT` to verify expected states and behaviors of the paint layers.
* **Lifecycle management:** Functions like `UpdateAllLifecyclePhasesExceptPaint` and `UpdateAllLifecyclePhasesForTest` control the rendering pipeline stages.
* **Focus on specific properties:** Many tests target CSS properties like `position`, `z-index`, `transform`, `opacity`, `overflow`, `clip-path`, `column-span`, etc.
* **Hit-testing:**  Several tests involve `HitTest` operations, checking which element is located at a specific point.
* **Compositing:**  Tests examine the `CompositingContainer` of paint layers.
* **Scrolling:**  Some tests involve scrolling and its impact.

**Connecting to Web Technologies:**

* **HTML:** The structure of the web page is defined using HTML elements.
* **CSS:**  Styling and layout are controlled using CSS properties, which directly influence the creation and behavior of paint layers.
* **JavaScript:** While not directly present in this snippet, JavaScript can dynamically modify HTML and CSS, leading to changes in paint layers.

**Inferring Logic and Assumptions:**

The tests seem to be verifying:

* The correct ordering of paint layers, especially when dealing with overflow and stacking contexts.
* The conditions under which layers support subsequence caching for optimization.
* How changes in CSS properties (like `z-index`, `transform`) affect the structure and properties of paint layers.
* The correct determination of a layer's compositing container.
* The behavior of hit-testing under various conditions, including clipping, transformations, and within complex layouts like tables and multi-column layouts.
* How scrolling interacts with paint layer properties.

**Identifying Potential User Errors:**

* Incorrectly setting `z-index` values, leading to unexpected stacking order.
* Not understanding how `position`, `transform`, and `opacity` can trigger the creation of new stacking contexts and composited layers.
* Issues with hit-testing when elements are clipped or transformed.
* Problems with content not appearing as expected in multi-column layouts.

**Describing the User Journey:**

1. **Developer writes HTML/CSS:** A web developer creates HTML elements and applies CSS styles.
2. **Browser parses HTML/CSS:** The browser's parsing engine processes the HTML and CSS to build the DOM tree and CSSOM.
3. **Layout engine calculates geometry:** The layout engine determines the size and position of each element on the page.
4. **Paint tree creation:** Based on the layout, the browser creates a paint tree, which is a hierarchical representation of how elements should be painted. This is where `PaintLayer` objects come into play.
5. **Compositing (if needed):**  For performance reasons, certain parts of the page might be composited into separate layers. The tests involving `CompositingContainer` are relevant here.
6. **Painting:** The browser draws the content of each paint layer onto the screen.
7. **User interaction (e.g., scrolling, clicking):** When a user interacts with the page, the browser might need to re-render parts of the page. Hit-testing is used to determine which element was interacted with.
8. **Dynamic changes (JavaScript):** JavaScript can modify the DOM and CSSOM, triggering updates to the paint tree and potentially re-painting.

The tests in this file are specifically targeting the logic within the "Paint tree creation" and "Compositing" stages. When developers introduce HTML/CSS that triggers complex layering or compositing scenarios, these tests help ensure the Blink rendering engine behaves correctly.

**Summarizing the Functionality (Part 2):**

This section of `paint_layer_test.cc` focuses on testing the behavior of `PaintLayer` objects in various complex layout scenarios, particularly those involving:

* **Reordering overlay overflow controls:** Ensuring that scrollbars and other overlay controls are correctly ordered with respect to the content.
* **Subsequence caching:** Verifying that layers that can be efficiently cached are correctly identified.
* **Stacking contexts:** Testing how changes in `z-index` affect the stacking order of elements.
* **Visibility and transformations:** Checking how properties like `visibility` and `transform` influence descendant flags.
* **Compositing containers:**  Validating the logic for determining the correct compositing container for elements in different layout contexts (floats, inline elements, multi-column layouts, iframes).
* **Containing blocks:** Testing how containing blocks are established for floated and absolutely positioned elements within inline elements.
* **Hit-testing:** Rigorously testing hit-testing logic in various scenarios, including clipped content, elements with transformations, and within tables and SVG elements.
* **Interaction with page zoom:** Ensuring that features like `clip-path` work correctly when the page is zoomed.
* **Repainting:** Verifying that layers are marked for repaint when their self-painting status or stacking context changes.

In essence, this part of the test file aims to ensure the correctness and robustness of the Blink rendering engine when dealing with sophisticated CSS layouts and user interactions.

这是 `paint_layer_test.cc` 文件的第二部分，主要功能是测试 Blink 渲染引擎中 `PaintLayer` 对象的各种行为和属性，尤其关注在复杂布局场景下的表现。以下是更详细的归纳：

**主要功能归纳：**

1. **测试 overlay overflow controls 的重新排序:** 验证当元素具有 `overflow: auto` 或 `overflow: scroll` 等属性时，滚动条等 overlay 控件的绘制顺序和 hit-test 行为是否正确，尤其是在动态添加或移除子元素时。

2. **测试 subsequence caching (子序列缓存):**  验证在特定的 stacking 上下文和 SVG 结构中，`PaintLayer` 是否正确支持子序列缓存，这是一种优化绘制性能的技术。

3. **测试 z-index 改变的影响:** 验证当元素的 `z-index` 属性从负数变为正数时，`PaintLayer` 的绘制顺序是否正确更新。

4. **测试 `HasVisibleSelfPaintingDescendant`:** 验证 `PaintLayer` 是否能正确判断其后代中是否存在自身绘制的可见图层。

5. **测试 3D 变换相关的属性 (`Has3DTransformedDescendant`):**  验证当元素的后代应用了 3D 变换时，`PaintLayer` 是否能正确标记，并测试动态修改变换属性后的更新情况。

6. **测试 throttled frames (节流帧) 对 descendant dependent flags 的影响:** 验证当 iframe 被节流时，其 `PaintLayer` 的某些依赖后代的标志位是否被正确处理，避免在节流期间发生错误。

7. **测试 `CompositingContainer` 的确定:** 重点测试在各种复杂布局情况下，例如 stacked 元素、浮动元素、inline 元素、column-span 元素等，`PaintLayer` 是否能正确找到其 compositing container。

8. **测试 containing layer 的确定:** 验证在各种布局组合下，`PaintLayer` 的 containing layer 是否被正确识别，特别是涉及到浮动元素和 inline 元素的情况。

9. **测试滚动对 containing layer 的影响:** 验证当 containing layer 是一个可滚动容器时，滚动偏移量如何影响子 `PaintLayer` 的坐标。

10. **测试动画对 `PaintLayer` transform 的影响:** 验证当应用 CSS transform 动画时，`PaintLayer` 的 transform 属性是否被正确更新。

11. **测试自绘制状态改变时的 repaint:** 验证当 `PaintLayer` 的自绘制状态发生变化时，是否会触发必要的 repaint。

12. **测试移除 stacked layer 时的 repaint:** 验证当一个 stacked layer 被移除时，其父容器是否会正确触发 repaint。

13. **测试 FrameView 的内容尺寸:**  简单验证 `FrameView` 的内容尺寸是否符合预期。

14. **测试带有页面缩放的引用 clip-path 的 hit-test:** 验证当页面缩放时，使用 URL 引用 clip-path 的元素，其 hit-test 行为是否仍然正确。

15. **测试 fragmented (分段) 布局的 hit-test:** 验证在多列布局等 fragmented 布局中，`PaintLayer` 的 hit-test 是否能正确找到目标元素。

16. **测试带有 `ignore clipping` 和 `stop node` 的 hit-test:** 验证 hit-test 功能在忽略裁剪和指定停止节点的情况下是否按预期工作。这包括对普通元素、表格和 SVG 元素的测试。

**与 JavaScript, HTML, CSS 的关系举例说明：**

* **HTML 结构定义 `PaintLayer` 的层级关系:**  例如，`<div id='parent'><div id='child'></div></div>` 的 HTML 结构会创建相应的 `PaintLayer` 父子关系。
* **CSS 属性影响 `PaintLayer` 的属性和行为:**
    * `position: relative;` 或 `transform: translateZ(0);` 等属性可能使元素创建新的 `PaintLayer`。
    * `z-index` 影响 `PaintLayer` 的 stacking 上下文和绘制顺序。
    * `overflow: auto;` 触发 overlay scrollbar 的创建，需要测试其绘制顺序。
    * `clip-path` 定义了 `PaintLayer` 的可见区域，影响 hit-test 结果。
    * `column-span: all;` 会影响 `PaintLayer` 的 containing layer。
* **JavaScript 动态修改样式会触发 `PaintLayer` 的更新和 repaint:** 例如，通过 JavaScript 修改元素的 `style.display = 'block'`，可能会导致新的 `PaintLayer` 被创建或现有 `PaintLayer` 的属性发生变化，从而触发 repaint。

**逻辑推理的假设输入与输出:**

以 `TEST_P(ReorderOverlayOverflowControlsTest, AddRemoveChild)` 为例：

* **假设输入:**
    * 初始 HTML 和 CSS 定义了一个父元素 (`#parent`) 具有 `overflow: auto`，一个子元素 (`#child`) 在父元素内部。
    * 使用 `InitOverflowStyle("parent")` 初始化父元素的滚动行为。
* **逻辑:**  测试在父元素拥有 overflow 属性的情况下，添加和移除子元素后，父元素的 `NeedsReorderOverlayOverflowControls()` 状态以及 overlay 控件的绘制顺序是否正确。
* **预期输出:**
    * 添加子元素后，父元素可能需要重新排序 overlay 控件 (`NeedsReorderOverlayOverflowControls()` 为 true)。
    * 使用 `LayersPaintingOverlayOverflowControlsAfter(child)` 检查子元素是否在父元素的 overlay 控件之后绘制。
    * 移除子元素后，父元素不再需要重新排序 overlay 控件。
    * `HitTest(99, 99)` 验证特定坐标上的元素是否符合预期。

**涉及用户或编程常见的使用错误举例说明:**

* **错误的 z-index 使用导致元素遮挡问题:**  开发者可能错误地设置了 `z-index` 值，导致预期的元素被意外遮挡。相关的测试 (`NegativeZIndexChangeToPositive`) 帮助确保引擎能正确处理 `z-index` 的变化。
* **不理解 stacking context 导致 compositing 错误:** 开发者可能不清楚哪些 CSS 属性会创建新的 stacking context，导致元素的 compositing container 不如预期。相关的 `CompositingContainer` 测试覆盖了这些场景。
* **clip-path 或 transform 应用错误导致 hit-test 失效:** 开发者可能错误地使用了 `clip-path` 或 `transform`，导致用户无法点击到预期的元素。`ReferenceClipPathWithPageZoom` 和其他 hit-test 相关的测试旨在防止这种情况。

**用户操作如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器中加载一个网页:**  用户通过地址栏输入网址或点击链接，浏览器开始解析 HTML、CSS 和 JavaScript。
2. **浏览器渲染引擎开始工作:**  Blink 渲染引擎会根据 HTML 和 CSS 构建 DOM 树和 CSSOM 树。
3. **创建 Paint Tree 和 PaintLayer:** 渲染引擎会根据布局信息创建 Paint Tree，并为需要独立绘制的元素创建 `PaintLayer` 对象。这一步会涉及到本文件中测试的各种 `PaintLayer` 属性的计算和设置。
4. **处理复杂的 CSS 属性:**  如果网页使用了复杂的 CSS 属性，例如 `overflow: auto`、`z-index`、`transform`、`clip-path` 等，就会触发本文件中测试的相关逻辑。
5. **用户交互触发重绘或重排:**  用户的滚动、点击、鼠标悬停等操作可能会导致页面需要重新绘制或重新布局，这会再次触发 `PaintLayer` 的更新和绘制过程。
6. **开发者调试渲染问题:** 当开发者遇到页面渲染问题（例如元素遮挡、点击失效等）时，可能会深入到 Blink 渲染引擎的代码中进行调试，`paint_layer_test.cc` 中的测试用例可以帮助理解和定位问题。

**总结：**

总而言之，`paint_layer_test.cc` 的这一部分着重于对 Blink 渲染引擎中 `PaintLayer` 对象的各种复杂行为进行细致的测试，确保在各种高级 CSS 布局和用户交互场景下，渲染结果的正确性和性能。这些测试覆盖了从基本的层叠顺序到复杂的 compositing 策略和 hit-test 行为，旨在防止因渲染引擎的 bug 而导致的用户体验问题。

### 提示词
```
这是目录为blink/renderer/core/paint/paint_layer_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
rflowControls());
  EXPECT_THAT(LayersPaintingOverlayOverflowControlsAfter(child),
              Pointee(ElementsAre(parent)));
  EXPECT_EQ(parent->GetLayoutObject().GetNode(), HitTest(99, 99));

  RemoveOverflowStyle("parent");
  EXPECT_FALSE(parent->GetScrollableArea());
  EXPECT_FALSE(parent->NeedsReorderOverlayOverflowControls());
  EXPECT_FALSE(LayersPaintingOverlayOverflowControlsAfter(child));
  EXPECT_EQ(child->GetLayoutObject().GetNode(), HitTest(99, 99));
}

TEST_P(ReorderOverlayOverflowControlsTest, AddRemoveStackedChild) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin: 0; }
      #parent {
        position: relative;
        width: 100px;
        height: 100px;
      }
      #child {
        position: absolute;
        width: 200px;
        height: 200px;
        display: none;
      }
    </style>
    <div id='parent'>
      <div id='child'></div>
    </div>
  )HTML");

  InitOverflowStyle("parent");
  auto* parent = GetPaintLayerByElementId("parent");
  EXPECT_FALSE(parent->NeedsReorderOverlayOverflowControls());
  EXPECT_EQ(parent->GetLayoutObject().GetNode(), HitTest(99, 99));

  auto* child_element = GetDocument().getElementById(AtomicString("child"));
  child_element->setAttribute(html_names::kStyleAttr,
                              AtomicString("display: block"));
  UpdateAllLifecyclePhasesExceptPaint();
  EXPECT_TRUE(parent->NeedsReorderOverlayOverflowControls());
  EXPECT_THAT(LayersPaintingOverlayOverflowControlsAfter(
                  GetPaintLayerByElementId("child")),
              Pointee(ElementsAre(parent)));
  EXPECT_TRUE(parent->SelfNeedsRepaint());
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(parent->SelfNeedsRepaint());
  EXPECT_EQ(parent->GetLayoutObject().GetNode(), HitTest(99, 99));

  child_element->setAttribute(html_names::kStyleAttr, g_empty_atom);
  UpdateAllLifecyclePhasesExceptPaint();
  EXPECT_FALSE(parent->NeedsReorderOverlayOverflowControls());
  EXPECT_TRUE(parent->SelfNeedsRepaint());
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(parent->SelfNeedsRepaint());
  EXPECT_EQ(parent->GetLayoutObject().GetNode(), HitTest(99, 99));
}

TEST_P(PaintLayerTest, SubsequenceCachingStackedLayers) {
  SetBodyInnerHTML(R"HTML(
    <div id='parent' style='position:relative'>
      <div id='child1' style='position: relative'>
        <div id='grandchild1' style='position: relative'></div>
      </div>
      <div id='child2' style='isolation: isolate'>
        <div id='grandchild2' style='position: relative'></div>
      </div>
    </div>
  )HTML");
  PaintLayer* parent = GetPaintLayerByElementId("parent");
  PaintLayer* child1 = GetPaintLayerByElementId("child1");
  PaintLayer* child2 = GetPaintLayerByElementId("child2");
  PaintLayer* grandchild1 = GetPaintLayerByElementId("grandchild1");
  PaintLayer* grandchild2 = GetPaintLayerByElementId("grandchild2");

  EXPECT_TRUE(parent->SupportsSubsequenceCaching());
  EXPECT_TRUE(child1->SupportsSubsequenceCaching());
  EXPECT_TRUE(child2->SupportsSubsequenceCaching());
  EXPECT_TRUE(grandchild1->SupportsSubsequenceCaching());
  EXPECT_TRUE(grandchild2->SupportsSubsequenceCaching());
}

TEST_P(PaintLayerTest, SubsequenceCachingSVG) {
  SetBodyInnerHTML(R"HTML(
    <svg id='svgroot'>
      <foreignObject id='foreignObject'/>
    </svg>
  )HTML");

  PaintLayer* svgroot = GetPaintLayerByElementId("svgroot");
  PaintLayer* foreign_object = GetPaintLayerByElementId("foreignObject");
  EXPECT_TRUE(svgroot->SupportsSubsequenceCaching());
  EXPECT_TRUE(foreign_object->SupportsSubsequenceCaching());
}

TEST_P(PaintLayerTest, SubsequenceCachingMuticol) {
  SetBodyInnerHTML(R"HTML(
    <div style='columns: 2'>
      <div id='target' style='position: relative; height: 20px;'></div>
    </div>
  )HTML");

  PaintLayer* target = GetPaintLayerByElementId("target");
  EXPECT_FALSE(target->SupportsSubsequenceCaching());
}

TEST_P(PaintLayerTest, NegativeZIndexChangeToPositive) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #child { position: relative; }
    </style>
    <div id='target' style='isolation: isolate'>
      <div id='child' style='z-index: -1'></div>
    </div>
  )HTML");

  PaintLayer* target = GetPaintLayerByElementId("target");

  EXPECT_TRUE(
      PaintLayerPaintOrderIterator(target, kNegativeZOrderChildren).Next());
  EXPECT_FALSE(
      PaintLayerPaintOrderIterator(target, kPositiveZOrderChildren).Next());

  GetDocument()
      .getElementById(AtomicString("child"))
      ->setAttribute(html_names::kStyleAttr, AtomicString("z-index: 1"));
  UpdateAllLifecyclePhasesForTest();

  EXPECT_FALSE(
      PaintLayerPaintOrderIterator(target, kNegativeZOrderChildren).Next());
  EXPECT_TRUE(
      PaintLayerPaintOrderIterator(target, kPositiveZOrderChildren).Next());
}

TEST_P(PaintLayerTest, HasVisibleSelfPaintingDescendant) {
  SetBodyInnerHTML(R"HTML(
    <div id='invisible' style='position:relative'>
      <div id='visible' style='visibility: visible; position: relative'>
      </div>
    </div>
  )HTML");
  PaintLayer* invisible = GetPaintLayerByElementId("invisible");
  PaintLayer* visible = GetPaintLayerByElementId("visible");

  EXPECT_TRUE(invisible->HasVisibleSelfPaintingDescendant());
  EXPECT_FALSE(visible->HasVisibleSelfPaintingDescendant());
  EXPECT_FALSE(invisible->HasNonIsolatedDescendantWithBlendMode());
}

TEST_P(PaintLayerTest, Has3DTransformedDescendant) {
  SetBodyInnerHTML(R"HTML(
    <div id='parent' style='position:relative; z-index: 0'>
      <div id='child' style='transform: translateZ(1px)'>
      </div>
    </div>
  )HTML");
  PaintLayer* parent = GetPaintLayerByElementId("parent");
  PaintLayer* child = GetPaintLayerByElementId("child");

  EXPECT_TRUE(parent->Has3DTransformedDescendant());
  EXPECT_FALSE(child->Has3DTransformedDescendant());
}

TEST_P(PaintLayerTest, Has3DTransformedDescendantChangeStyle) {
  SetBodyInnerHTML(R"HTML(
    <div id='parent' style='position:relative; z-index: 0'>
      <div id='child' style='position:relative '>
      </div>
    </div>
  )HTML");
  PaintLayer* parent = GetPaintLayerByElementId("parent");
  PaintLayer* child = GetPaintLayerByElementId("child");

  EXPECT_FALSE(parent->Has3DTransformedDescendant());
  EXPECT_FALSE(child->Has3DTransformedDescendant());

  GetDocument()
      .getElementById(AtomicString("child"))
      ->setAttribute(html_names::kStyleAttr,
                     AtomicString("transform: translateZ(1px)"));
  UpdateAllLifecyclePhasesForTest();

  EXPECT_TRUE(parent->Has3DTransformedDescendant());
  EXPECT_FALSE(child->Has3DTransformedDescendant());
}

TEST_P(PaintLayerTest, Has3DTransformedDescendantNotStacking) {
  SetBodyInnerHTML(R"HTML(
    <div id='parent' style='position:relative;'>
      <div id='child' style='transform: translateZ(1px)'>
      </div>
    </div>
  )HTML");
  PaintLayer* parent = GetPaintLayerByElementId("parent");
  PaintLayer* child = GetPaintLayerByElementId("child");

  // |child| is not a stacking child of |parent|, so it has no 3D transformed
  // descendant.
  EXPECT_FALSE(parent->Has3DTransformedDescendant());
  EXPECT_FALSE(child->Has3DTransformedDescendant());
}

TEST_P(PaintLayerTest, Has3DTransformedGrandchildWithPreserve3d) {
  SetBodyInnerHTML(R"HTML(
    <div id='parent' style='position:relative; z-index: 0'>
      <div id='child' style='transform-style: preserve-3d'>
        <div id='grandchild' style='transform: translateZ(1px)'>
        </div>
      </div>
    </div>
  )HTML");
  PaintLayer* parent = GetPaintLayerByElementId("parent");
  PaintLayer* child = GetPaintLayerByElementId("child");
  PaintLayer* grandchild = GetPaintLayerByElementId("grandchild");

  EXPECT_TRUE(parent->Has3DTransformedDescendant());
  EXPECT_TRUE(child->Has3DTransformedDescendant());
  EXPECT_FALSE(grandchild->Has3DTransformedDescendant());
}

TEST_P(PaintLayerTest, DescendantDependentFlagsStopsAtThrottledFrames) {
  SetBodyInnerHTML(R"HTML(
    <style>body { margin: 0; }</style>
    <div id='transform' style='transform: translate3d(4px, 5px, 6px);'>
    </div>
    <iframe id='iframe' sandbox></iframe>
  )HTML");
  SetChildFrameHTML(R"HTML(
    <style>body { margin: 0; }</style>
    <div id='iframeTransform'
      style='transform: translate3d(4px, 5px, 6px);'/>
  )HTML");

  // Move the child frame offscreen so it becomes available for throttling.
  auto* iframe = To<HTMLIFrameElement>(
      GetDocument().getElementById(AtomicString("iframe")));
  iframe->setAttribute(html_names::kStyleAttr,
                       AtomicString("transform: translateY(5555px)"));
  UpdateAllLifecyclePhasesForTest();
  // Ensure intersection observer notifications get delivered.
  test::RunPendingTasks();
  EXPECT_FALSE(GetDocument().View()->IsHiddenForThrottling());
  EXPECT_TRUE(ChildDocument().View()->IsHiddenForThrottling());

  EXPECT_FALSE(GetDocument().View()->ShouldThrottleRenderingForTest());
  EXPECT_TRUE(ChildDocument().View()->ShouldThrottleRenderingForTest());

  ChildDocument().View()->GetLayoutView()->Layer()->DirtyVisibleContentStatus();

  EXPECT_TRUE(ChildDocument()
                  .View()
                  ->GetLayoutView()
                  ->Layer()
                  ->needs_descendant_dependent_flags_update_);

  // Also check that the rest of the lifecycle succeeds without crashing due
  // to a stale m_needsDescendantDependentFlagsUpdate.
  UpdateAllLifecyclePhasesForTest();

  // Still dirty, because the frame was throttled.
  EXPECT_TRUE(ChildDocument()
                  .View()
                  ->GetLayoutView()
                  ->Layer()
                  ->needs_descendant_dependent_flags_update_);

  // Do an unthrottled compositing update, this should clear flags;
  GetDocument().View()->UpdateAllLifecyclePhasesExceptPaint(
      DocumentUpdateReason::kTest);
  EXPECT_FALSE(ChildDocument()
                   .View()
                   ->GetLayoutView()
                   ->Layer()
                   ->needs_descendant_dependent_flags_update_);
}

TEST_P(PaintLayerTest, CompositingContainerStackedFloatUnderStackingInline) {
  SetBodyInnerHTML(R"HTML(
    <div id='compositedContainer' style='position: relative;
        will-change: transform'>
      <div id='containingBlock' style='position: relative; z-index: 0'>
        <span id='span' style='opacity: 0.9'>
          <div id='target' style='float: right; position: relative'></div>
        </span>
      </div>
    </div>
  )HTML");

  PaintLayer* target = GetPaintLayerByElementId("target");
  EXPECT_EQ(GetPaintLayerByElementId("span"), target->CompositingContainer());
}

TEST_P(PaintLayerTest, CompositingContainerColumnSpanAll) {
  SetBodyInnerHTML(R"HTML(
    <div>
      <div id='multicol' style='columns: 1; position: relative'>
        <div id='paintContainer' style='position: relative'>
          <div id='columnSpan' style='column-span: all; overflow: hidden'></div>
        </div>
      </div>
    </div>
  )HTML");

  PaintLayer* columnSpan = GetPaintLayerByElementId("columnSpan");
  EXPECT_EQ(GetPaintLayerByElementId("paintContainer"),
            columnSpan->CompositingContainer());
  EXPECT_EQ(GetPaintLayerByElementId("multicol"),
            columnSpan->ContainingLayer());
}

TEST_P(PaintLayerTest,
       CompositingContainerStackedFloatUnderStackingCompositedInline) {
  SetBodyInnerHTML(R"HTML(
    <div id='compositedContainer' style='position: relative;
        will-change: transform'>
      <div id='containingBlock' style='position: relative; z-index: 0'>
        <span id='span' style='opacity: 0.9; will-change: transform'>
          <div id='target' style='float: right; position: relative'></div>
        </span>
      </div>
    </div>
  )HTML");

  PaintLayer* target = GetPaintLayerByElementId("target");
  PaintLayer* span = GetPaintLayerByElementId("span");
  EXPECT_EQ(span, target->CompositingContainer());
}

TEST_P(PaintLayerTest, CompositingContainerNonStackedFloatUnderStackingInline) {
  SetBodyInnerHTML(R"HTML(
    <div id='compositedContainer' style='position: relative;
        will-change: transform'>
      <div id='containingBlock' style='position: relative; z-index: 0'>
        <span id='span' style='opacity: 0.9'>
          <div id='target' style='float: right; overflow: hidden'></div>
        </span>
      </div>
    </div>
  )HTML");

  PaintLayer* target = GetPaintLayerByElementId("target");
  EXPECT_EQ(GetPaintLayerByElementId("span"), target->CompositingContainer());
}

TEST_P(PaintLayerTest,
       CompositingContainerNonStackedFloatUnderStackingCompositedInline) {
  SetBodyInnerHTML(R"HTML(
    <div id='compositedContainer' style='position: relative;
        will-change: transform'>
      <div id='containingBlock' style='position: relative; z-index: 0'>
        <span id='span' style='opacity: 0.9; will-change: transform'>
          <div id='target' style='float: right; overflow: hidden'></div>
        </span>
      </div>
    </div>
  )HTML");

  PaintLayer* target = GetPaintLayerByElementId("target");
  EXPECT_EQ(GetPaintLayerByElementId("span"), target->CompositingContainer());
}

TEST_P(PaintLayerTest,
       CompositingContainerStackedUnderFloatUnderStackingInline) {
  SetBodyInnerHTML(R"HTML(
    <div id='compositedContainer' style='position: relative;
        will-change: transform'>
      <div id='containingBlock' style='position: relative; z-index: 0'>
        <span id='span' style='opacity: 0.9'>
          <div style='float: right'>
            <div id='target' style='position: relative'></div>
          </div>
        </span>
      </div>
    </div>
  )HTML");

  PaintLayer* target = GetPaintLayerByElementId("target");
  EXPECT_EQ(GetPaintLayerByElementId("span"), target->CompositingContainer());
}

TEST_P(PaintLayerTest,
       CompositingContainerStackedUnderFloatUnderStackingCompositedInline) {
  SetBodyInnerHTML(R"HTML(
    <div id='compositedContainer' style='position: relative;
        will-change: transform'>
      <div id='containingBlock' style='position: relative; z-index: 0'>
        <span id='span' style='opacity: 0.9; will-change: transform'>
          <div style='float: right'>
            <div id='target' style='position: relative'></div>
          </div>
        </span>
      </div>
    </div>
  )HTML");

  PaintLayer* target = GetPaintLayerByElementId("target");
  PaintLayer* span = GetPaintLayerByElementId("span");
  EXPECT_EQ(span, target->CompositingContainer());
}

TEST_P(PaintLayerTest,
       CompositingContainerNonStackedUnderFloatUnderStackingInline) {
  SetBodyInnerHTML(R"HTML(
    <div id='compositedContainer' style='position: relative;
        will-change: transform'>
      <div id='containingBlock' style='position: relative; z-index: 0'>
        <span id='span' style='opacity: 0.9'>
          <div style='float: right'>
            <div id='target' style='overflow: hidden'></div>
          </div>
        </span>
      </div>
    </div>
  )HTML");

  PaintLayer* target = GetPaintLayerByElementId("target");
  EXPECT_EQ(GetPaintLayerByElementId("span"), target->CompositingContainer());
}

TEST_P(PaintLayerTest,
       CompositingContainerNonStackedUnderFloatUnderStackingCompositedInline) {
  SetBodyInnerHTML(R"HTML(
    <div id='compositedContainer' style='position: relative;
        will-change: transform'>
      <div id='containingBlock' style='position: relative; z-index: 0'>
        <span id='span' style='opacity: 0.9; will-change: transform'>
          <div style='float: right'>
            <div id='target' style='overflow: hidden'></div>
          </div>
        </span>
      </div>
    </div>
  )HTML");

  PaintLayer* target = GetPaintLayerByElementId("target");
  EXPECT_EQ(GetPaintLayerByElementId("span"), target->CompositingContainer());
}

TEST_P(PaintLayerTest, FloatLayerAndAbsoluteUnderInlineLayer) {
  SetBodyInnerHTML(R"HTML(
    <div id='container' style='position: absolute; top: 20px; left: 20px'>
      <div style='margin: 33px'>
        <span id='span' style='position: relative; top: 100px; left: 100px'>
          <div id='floating'
            style='float: left; position: relative; top: 50px; left: 50px'>
          </div>
          <div id='absolute'
            style='position: absolute; top: 50px; left: 50px'>
          </div>
        </span>
      </div>
    </div>
  )HTML");

  PaintLayer* floating = GetPaintLayerByElementId("floating");
  PaintLayer* absolute = GetPaintLayerByElementId("absolute");
  PaintLayer* span = GetPaintLayerByElementId("span");
  PaintLayer* container = GetPaintLayerByElementId("container");

  EXPECT_EQ(span, floating->Parent());
  EXPECT_EQ(span, floating->ContainingLayer());
  EXPECT_EQ(span, absolute->Parent());
  EXPECT_EQ(span, absolute->ContainingLayer());
  EXPECT_EQ(container, span->Parent());
  EXPECT_EQ(container, span->ContainingLayer());
}

TEST_P(PaintLayerTest, FloatLayerUnderInlineLayerScrolled) {
  SetBodyInnerHTML(R"HTML(
    <div id='container' style='overflow: scroll; width: 50px; height: 50px'>
      <span id='span' style='position: relative; top: 100px; left: 100px'>
        <div id='floating'
          style='float: left; position: relative; top: 50px; left: 50px'>
        </div>
      </span>
      <div style='height: 1000px'></div>
    </div>
  )HTML");

  PaintLayer* floating = GetPaintLayerByElementId("floating");
  PaintLayer* span = GetPaintLayerByElementId("span");
  PaintLayer* container = GetPaintLayerByElementId("container");
  container->GetScrollableArea()->SetScrollOffset(
      ScrollOffset(0, 400), mojom::blink::ScrollType::kProgrammatic);

  EXPECT_EQ(span, floating->Parent());
  EXPECT_EQ(span, floating->ContainingLayer());
  EXPECT_EQ(container, span->Parent());
  EXPECT_EQ(container, span->ContainingLayer());
  EXPECT_EQ(gfx::Vector2d(0, 400),
            span->ContainingLayer()->PixelSnappedScrolledContentOffset());
}

TEST_P(PaintLayerTest, FloatLayerUnderBlockUnderInlineLayer) {
  SetBodyInnerHTML(R"HTML(
    <style>body {margin: 0}</style>
    <span id='span' style='position: relative; top: 100px; left: 100px'>
      <div style='display: inline-block; margin: 33px'>
        <div id='floating'
            style='float: left; position: relative; top: 50px; left: 50px'>
        </div>
      </div>
    </span>
  )HTML");

  PaintLayer* floating = GetPaintLayerByElementId("floating");
  PaintLayer* span = GetPaintLayerByElementId("span");

  EXPECT_EQ(span, floating->Parent());
  EXPECT_EQ(span, floating->ContainingLayer());
}

TEST_P(PaintLayerTest, FloatLayerUnderFloatUnderInlineLayer) {
  SetBodyInnerHTML(R"HTML(
    <style>body {margin: 0}</style>
    <span id='span' style='position: relative; top: 100px; left: 100px'>
      <div style='float: left; margin: 33px'>
        <div id='floating'
            style='float: left; position: relative; top: 50px; left: 50px'>
        </div>
      </div>
    </span>
  )HTML");

  PaintLayer* floating = GetPaintLayerByElementId("floating");
  PaintLayer* span = GetPaintLayerByElementId("span");

  EXPECT_EQ(span, floating->Parent());
  EXPECT_EQ(span, floating->ContainingLayer());
}

TEST_P(PaintLayerTest, FloatLayerUnderFloatLayerUnderInlineLayer) {
  SetBodyInnerHTML(R"HTML(
    <style>body {margin: 0}</style>
    <span id='span' style='position: relative; top: 100px; left: 100px'>
      <div id='floatingParent'
          style='float: left; position: relative; margin: 33px'>
        <div id='floating'
            style='float: left; position: relative; top: 50px; left: 50px'>
        </div>
      </div>
    </span>
  )HTML");

  PaintLayer* floating = GetPaintLayerByElementId("floating");
  PaintLayer* floating_parent = GetPaintLayerByElementId("floatingParent");
  PaintLayer* span = GetPaintLayerByElementId("span");

  EXPECT_EQ(floating_parent, floating->Parent());
  EXPECT_EQ(floating_parent, floating->ContainingLayer());
  EXPECT_EQ(span, floating_parent->Parent());
  EXPECT_EQ(span, floating_parent->ContainingLayer());
}

TEST_P(PaintLayerTest, LayerUnderFloatUnderInlineLayer) {
  SetBodyInnerHTML(R"HTML(
    <style>body {margin: 0}</style>
    <span id='span' style='position: relative; top: 100px; left: 100px'>
      <div style='float: left; margin: 33px'>
        <div>
          <div id='child' style='position: relative; top: 50px; left: 50px'>
          </div>
        </div>
      </div>
    </span>
  )HTML");

  PaintLayer* child = GetPaintLayerByElementId("child");
  PaintLayer* span = GetPaintLayerByElementId("span");

  EXPECT_EQ(span, child->Parent());
  EXPECT_EQ(span, child->ContainingLayer());
}

TEST_P(PaintLayerTest, CompositingContainerFloatingIframe) {
  SetBodyInnerHTML(R"HTML(
    <div id='compositedContainer' style='position: relative;
        will-change: transform'>
      <div id='containingBlock' style='position: relative; z-index: 0'>
        <div style='backface-visibility: hidden'></div>
        <span id='span'
            style='clip-path: polygon(0px 15px, 0px 54px, 100px 0px)'>
          <iframe srcdoc='foo' id='target' style='float: right'></iframe>
        </span>
      </div>
    </div>
  )HTML");

  PaintLayer* target = GetPaintLayerByElementId("target");

  // A non-positioned iframe still gets a PaintLayer because PaintLayers are
  // forced for all LayoutEmbeddedContent objects. However, such PaintLayers are
  // not stacked.
  EXPECT_EQ(GetPaintLayerByElementId("span"), target->CompositingContainer());
}

TEST_P(PaintLayerTest, ColumnSpanLayerUnderExtraLayerScrolled) {
  SetBodyInnerHTML(R"HTML(
    <div id='columns' style='overflow: hidden; width: 80px; height: 80px;
        columns: 2; column-gap: 0'>
      <div id='extraLayer'
          style='position: relative; top: 100px; left: 100px'>
        <div id='spanner' style='column-span: all; position: relative;
            top: 50px; left: 50px'>
        </div>
      </div>
      <div style='height: 1000px'></div>
    </div>
  )HTML");

  PaintLayer* spanner = GetPaintLayerByElementId("spanner");
  PaintLayer* extra_layer = GetPaintLayerByElementId("extraLayer");
  PaintLayer* columns = GetPaintLayerByElementId("columns");
  columns->GetScrollableArea()->SetScrollOffset(
      ScrollOffset(200, 0), mojom::blink::ScrollType::kProgrammatic);

  EXPECT_EQ(extra_layer, spanner->Parent());
  EXPECT_EQ(columns, spanner->ContainingLayer());
  EXPECT_EQ(columns, extra_layer->Parent());
  EXPECT_EQ(columns, extra_layer->ContainingLayer());
  EXPECT_EQ(gfx::Vector2d(200, 0),
            spanner->ContainingLayer()->PixelSnappedScrolledContentOffset());
}

TEST_P(PaintLayerTest, PaintLayerTransformUpdatedOnStyleTransformAnimation) {
  SetBodyInnerHTML("<div id='target' style='will-change: transform'></div>");

  LayoutObject* target_object =
      GetDocument().getElementById(AtomicString("target"))->GetLayoutObject();
  PaintLayer* target_paint_layer =
      To<LayoutBoxModelObject>(target_object)->Layer();
  EXPECT_EQ(nullptr, target_paint_layer->Transform());

  const ComputedStyle* old_style = target_object->Style();
  ComputedStyleBuilder new_style_builder(*old_style);
  new_style_builder.SetHasCurrentTransformAnimation(true);
  target_object->SetStyle(new_style_builder.TakeStyle());

  EXPECT_NE(nullptr, target_paint_layer->Transform());
}

TEST_P(PaintLayerTest, NeedsRepaintOnSelfPaintingStatusChange) {
  SetBodyInnerHTML(R"HTML(
    <span id='span' style='opacity: 0.1'>
      <div id='target' style='overflow: hidden; float: left;
          position: relative;'>
      </div>
    </span>
  )HTML");

  auto* span_layer = GetPaintLayerByElementId("span");
  auto* target_element = GetDocument().getElementById(AtomicString("target"));
  auto* target_object = target_element->GetLayoutObject();
  auto* target_layer = To<LayoutBoxModelObject>(target_object)->Layer();

  // Target layer is self painting because it is relatively positioned.
  EXPECT_TRUE(target_layer->IsSelfPaintingLayer());
  EXPECT_EQ(span_layer, target_layer->CompositingContainer());
  EXPECT_FALSE(target_layer->SelfNeedsRepaint());
  EXPECT_FALSE(span_layer->SelfNeedsRepaint());

  // Removing position:relative makes target layer no longer self-painting,
  // and change its compositing container. The original compositing container
  // span_layer should be marked SelfNeedsRepaint.
  target_element->setAttribute(html_names::kStyleAttr,
                               AtomicString("overflow: hidden; float: left"));

  UpdateAllLifecyclePhasesExceptPaint();
  EXPECT_FALSE(target_layer->IsSelfPaintingLayer());
  EXPECT_EQ(span_layer, target_layer->CompositingContainer());
  EXPECT_TRUE(target_layer->SelfNeedsRepaint());
  EXPECT_TRUE(target_layer->CompositingContainer()->SelfNeedsRepaint());
  EXPECT_TRUE(span_layer->SelfNeedsRepaint());
  UpdateAllLifecyclePhasesForTest();
}

TEST_P(PaintLayerTest, NeedsRepaintOnRemovingStackedLayer) {
  SetBodyInnerHTML(
      "<style>body {margin-top: 200px; backface-visibility: hidden}</style>"
      "<div id='target' style='position: absolute; top: 0'>Text</div>");

  auto* body = GetDocument().body();
  auto* body_layer = body->GetLayoutBox()->Layer();
  auto* target_element = GetDocument().getElementById(AtomicString("target"));
  auto* target_object = target_element->GetLayoutObject();
  auto* target_layer = To<LayoutBoxModelObject>(target_object)->Layer();

  // |container| is not the CompositingContainer of |target| because |target|
  // is stacked but |container| is not a stacking context.
  EXPECT_TRUE(target_layer->GetLayoutObject().IsStacked());
  EXPECT_NE(body_layer, target_layer->CompositingContainer());
  auto* old_compositing_container = target_layer->CompositingContainer();

  body->setAttribute(html_names::kStyleAttr, AtomicString("margin-top: 0"));
  target_element->setAttribute(html_names::kStyleAttr, AtomicString("top: 0"));
  UpdateAllLifecyclePhasesExceptPaint();

  EXPECT_FALSE(target_object->HasLayer());
  EXPECT_TRUE(body_layer->SelfNeedsRepaint());
  EXPECT_TRUE(old_compositing_container->DescendantNeedsRepaint());

  UpdateAllLifecyclePhasesForTest();
}

TEST_P(PaintLayerTest, FrameViewContentSize) {
  SetBodyInnerHTML(
      "<style> body { width: 1200px; height: 900px; margin: 0 } </style>");
  EXPECT_EQ(gfx::Size(800, 600), GetDocument().View()->Size());
}

TEST_P(PaintLayerTest, ReferenceClipPathWithPageZoom) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      body { margin: 0; }
    </style>
    <div style='width: 200px; height: 200px; background-color: blue;
                clip-path: url(#clip)' id='content'></div>
    <svg>
      <clipPath id='clip'>
        <path d='M50,50h100v100h-100z'/>
      </clipPath>
    </svg>
  )HTML");

  auto* content = GetDocument().getElementById(AtomicString("content"));
  auto* body = GetDocument().body();

  // A hit test on the content div within the clip should hit it.
  EXPECT_EQ(content, GetDocument().ElementFromPoint(125, 75));
  EXPECT_EQ(content, GetDocument().ElementFromPoint(75, 125));

  // A hit test on the content div outside the clip should not hit it.
  EXPECT_EQ(body, GetDocument().ElementFromPoint(151, 60));
  EXPECT_EQ(body, GetDocument().ElementFromPoint(60, 151));

  // Zoom the page by 2x,
  GetDocument().GetFrame()->SetLayoutZoomFactor(2);

  // A hit test on the content div within the clip should hit it.
  EXPECT_EQ(content, GetDocument().ElementFromPoint(125, 75));
  EXPECT_EQ(content, GetDocument().ElementFromPoint(75, 125));

  // A hit test on the content div outside the clip should not hit it.
  EXPECT_EQ(body, GetDocument().ElementFromPoint(151, 60));
  EXPECT_EQ(body, GetDocument().ElementFromPoint(60, 151));
}

TEST_P(PaintLayerTest, FragmentedHitTest) {
  SetHtmlInnerHTML(R"HTML(
    <style>
    div {
      break-inside: avoid-column;
      width: 50px;
      height: 50px;
      position: relative;
    }
    </style>
    <ul style="column-count: 4; position: relative">
      <div></div>
      <div id=target style=" position: relative; transform: translateY(0px);">
      </div>
    </ul>
  )HTML");

  auto* target = GetDocument().getElementById(AtomicString("target"));
  EXPECT_EQ(target, GetDocument().ElementFromPoint(280, 30));
}

TEST_P(PaintLayerTest, HitTestWithIgnoreClipping) {
  SetBodyInnerHTML("<div id='hit' style='width: 90px; height: 9000px;'></div>");

  HitTestRequest request(HitTestRequest::kIgnoreClipping);
  // (10, 900) is outside the viewport clip of 800x600.
  HitTestLocation location((gfx::Point(10, 900)));
  HitTestResult result(request, location);
  GetDocument().GetLayoutView()->HitTest(location, result);
  EXPECT_EQ(GetDocument().getElementById(AtomicString("hit")),
            result.InnerNode());
}

TEST_P(PaintLayerTest, HitTestWithStopNode) {
  SetBodyInnerHTML(R"HTML(
    <div id='hit' style='width: 100px; height: 100px;'>
      <div id='child' style='width:100px;height:100px'></div>
    </div>
    <div id='overlap' style='position:relative;top:-50px;width:100px;height:100px'></div>
  )HTML");
  Element* hit = GetDocument().getElementById(AtomicString("hit"));
  Element* child = GetDocument().getElementById(AtomicString("child"));
  Element* overlap = GetDocument().getElementById(AtomicString("overlap"));

  // Regular hit test over 'child'
  HitTestRequest request(HitTestRequest::kReadOnly | HitTestRequest::kActive);
  HitTestLocation location((PhysicalOffset(50, 25)));
  HitTestResult result(request, location);
  GetDocument().GetLayoutView()->HitTest(location, result);
  EXPECT_EQ(child, result.InnerNode());

  // Same hit test, with stop node.
  request = HitTestRequest(HitTestRequest::kReadOnly | HitTestRequest::kActive,
                           hit->GetLayoutObject());
  result = HitTestResult(request, location);
  GetDocument().GetLayoutView()->HitTest(location, result);
  EXPECT_EQ(hit, result.InnerNode());

  // Regular hit test over 'overlap'
  request = HitTestRequest(HitTestRequest::kReadOnly | HitTestRequest::kActive);
  location = HitTestLocation((PhysicalOffset(50, 75)));
  result = HitTestResult(request, location);
  GetDocument().GetLayoutView()->HitTest(location, result);
  EXPECT_EQ(overlap, result.InnerNode());

  // Same hit test, with stop node, should still hit 'overlap' because it's not
  // a descendant of 'hit'.
  request = HitTestRequest(HitTestRequest::kReadOnly | HitTestRequest::kActive,
                           hit->GetLayoutObject());
  result = HitTestResult(request, location);
  GetDocument().GetLayoutView()->HitTest(location, result);
  EXPECT_EQ(overlap, result.InnerNode());

  // List-based hit test with stop node
  request = HitTestRequest(HitTestRequest::kReadOnly | HitTestRequest::kActive |
                               HitTestRequest::kListBased,
                           hit->GetLayoutObject());
  location = HitTestLocation((PhysicalRect(40, 15, 20, 20)));
  result = HitTestResult(request, location);
  GetDocument().GetLayoutView()->HitTest(location, result);
  EXPECT_EQ(1u, result.ListBasedTestResult().size());
  EXPECT_EQ(hit, *result.ListBasedTestResult().begin());
}

TEST_P(PaintLayerTest, HitTestTableWithStopNode) {
  SetBodyInnerHTML(R"HTML(
    <style>
    .cell {
      width: 100px;
      height: 100px;
    }
    </style>
    <table id='table'>
      <tr>
        <td><div id='cell11' class='cell'></td>
        <td><div id='cell12' class='cell'></td>
      </tr>
      <tr>
        <td><div id='cell21' class='cell'></td>
        <td><div id='cell22' class='cell'></td>
      </tr>
    </table>
    )HTML");
  Element* table = GetDocument().getElementById(AtomicString("table"));
  Element* cell11 = GetDocument().getElementById(AtomicString("cell11"));
  HitTestRequest request(HitTestRequest::kReadOnly | HitTestRequest::kActive);
  HitTestLocation location((PhysicalOffset(50, 50)));
  HitTestResult result(request, location);
  GetDocument().GetLayoutView()->HitTest(location, result);
  EXPECT_EQ(cell11, result.InnerNode());

  request = HitTestRequest(HitTestRequest::kReadOnly | HitTestRequest::kActive,
                           table->GetLayoutObject());
  result = HitTestResult(request, location);
  GetDocument().GetLayoutView()->HitTest(location, result);
  EXPECT_EQ(table, result.InnerNode());
}

TEST_P(PaintLayerTest, HitTestSVGWithStopNode) {
  SetBodyInnerHTML(R"HTML(
    <svg id='svg' style='width:100px;height:100px' viewBox='0 0 100 100'>
      <circle id='circle' cx='50' cy='50' r='50' />
    </svg>
    )HTML");
  Element* svg = GetDocument().getElementById(AtomicString("svg"));
  Element* circle = GetDocument().getElementById(AtomicString("circle"));
  HitTestRequest request(HitTestRequest::kReadOnly | HitTestRequest::kActive);
  HitTestLocation location((PhysicalOffset(50, 50)));
  HitTestResult result(request, location);
  GetDocument().GetLayoutView()->HitTest(location, result);
  EXPECT_EQ(circle, result.InnerNode());

  request = HitTestRequest(HitTestRequest::kReadOnly | HitTestRequest::kActive,
```