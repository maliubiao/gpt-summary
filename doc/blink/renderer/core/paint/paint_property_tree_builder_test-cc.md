Response:
The user is asking for a summary of the functionalities present in the provided C++ code snippet from a Chromium Blink engine file. The file is named `paint_property_tree_builder_test.cc` and is located in the `blink/renderer/core/paint/` directory. The user also wants to know the relationships to HTML, CSS, and JavaScript, examples of logical reasoning with inputs and outputs, common user/programming errors, and how user actions lead to this code being executed (as a debugging clue).

Here's a breakdown of the thought process:

1. **Identify the core purpose of the file:** The filename `paint_property_tree_builder_test.cc` strongly suggests that this file contains tests for the `PaintPropertyTreeBuilder`. This class is responsible for constructing the paint property trees, which are crucial for rendering web pages.

2. **Analyze the includes:** The included header files provide valuable clues about the functionalities being tested:
    * `cc/trees/effect_node.h`, `cc/trees/scroll_node.h`, `cc/trees/transform_node.h`: These indicate that the tests involve properties related to effects (like opacity, filters), scrolling, and transformations (translate, rotate, scale).
    * `third_party/blink/renderer/core/frame/*`:  These point to interactions with the frame structure of a web page, including the DOM window and viewport.
    * `third_party/blink/renderer/core/html/html_iframe_element.h`: This suggests testing scenarios involving iframes, which have their own separate rendering contexts.
    * `third_party/blink/renderer/core/layout/*`: These headers are about the layout engine, responsible for positioning and sizing elements. The inclusion of `layout_tree_as_text.h` hints at the ability to represent the layout tree in a textual format, useful for debugging and testing.
    * `third_party/blink/renderer/core/paint/*`: This confirms that the tests are directly related to the painting process, especially the `PaintProperty` system.
    * `third_party/blink/renderer/platform/graphics/compositing/*`: This signals testing of compositing, where parts of the page are rendered independently on the GPU for performance.
    * `third_party/blink/renderer/platform/testing/*`: These are standard testing utilities within Blink.

3. **Examine the `PaintPropertyTreeBuilderTest` class:** The presence of this test class confirms the initial hypothesis. The methods within the class provide further insights:
    * `LoadTestData`: Indicates the tests load HTML content from files.
    * `DocPreTranslation`, `DocScrollTranslation`, `DocContentClip`, `DocScroll`, `DocEffect`: These methods provide access to specific paint property nodes related to the document/viewport, like the initial translation, scroll translation, content clipping, and scroll node.
    * `PaintPropertiesForElement`: This retrieves the paint properties for a specific element by its ID, a common testing pattern.
    * `GetTransformCache`: Accesses the transform cache for optimization.
    * `SetUp`:  Performs initial setup, notably enabling compositing.
    * `CHECK_VISUAL_RECT`, `CHECK_EXACT_VISUAL_RECT`: These are macros used for verifying the visual position of elements, taking into account transformations and scrolling.

4. **Identify relationships with web technologies:**
    * **HTML:** The tests load HTML files, demonstrating the file's connection to the structure of web pages.
    * **CSS:** The tests manipulate CSS properties (e.g., `position: fixed`, `transform`, `overflow`, `perspective`) and verify how these styles affect the paint property tree.
    * **JavaScript:** While not explicitly shown in this snippet, JavaScript can dynamically manipulate styles and trigger layout and paint updates, indirectly affecting the paint property tree. The tests likely simulate these actions.

5. **Consider logical reasoning and examples:** The `CHECK_VISUAL_RECT` macros are examples of logical reasoning. Given the initial layout and paint properties, the tests predict the final visual rectangle of an element after applying transformations, scrolling, etc. Hypothetical inputs would be HTML/CSS, and the expected output would be the verified visual rectangles.

6. **Think about user/programming errors:**  Common mistakes would be incorrect CSS syntax, misunderstanding how different CSS properties interact (e.g., fixed positioning within a scrolled container), or incorrect assumptions about the default values or behaviors of CSS properties.

7. **Trace user actions to code execution:** A user interacts with a web page (e.g., scrolls, resizes the window, hovers over elements triggering animations). These actions can lead to style recalculation, layout updates, and ultimately, the `PaintPropertyTreeBuilder` being invoked to rebuild the paint property trees to reflect the changes for rendering.

8. **Synthesize the information for the "Part 1" summary:** Combine the observations to provide a concise overview of the file's purpose and key functionalities.

Self-Correction/Refinement during the thought process:

* Initially, I might focus too much on the individual header files. Realizing the overall goal is *testing* the `PaintPropertyTreeBuilder` helps prioritize the analysis.
*  It's important to connect the C++ code back to the user-facing web technologies (HTML, CSS, JavaScript). Without these connections, the explanation is less useful.
* When considering user errors, think about *common* mistakes developers make when working with layout and styling, as these are the scenarios the tests are likely designed to cover.
* The debugging clue aspect is crucial. Emphasize how user actions trigger the code, providing context for why this code exists and when it's executed.
这是文件 `blink/renderer/core/paint/paint_property_tree_builder_test.cc` 的第一部分，它是一个 Chromium Blink 引擎的源代码文件，专门用于 **测试 `PaintPropertyTreeBuilder` 的功能**。 `PaintPropertyTreeBuilder` 的核心职责是根据 DOM 树和 CSS 样式信息构建用于绘制的 **Paint Property Trees（绘制属性树）**。

**以下是该文件第一部分的主要功能归纳：**

1. **提供测试基础设施:**  该文件定义了一个测试类 `PaintPropertyTreeBuilderTest`，继承自 `RenderingTest`，这表明它是一个集成测试，需要渲染引擎的完整上下文。 它包含了用于设置测试环境 (`SetUp`) 和加载测试数据 (`LoadTestData`) 的方法。

2. **加载测试用例:**  `LoadTestData` 方法用于从文件中读取 HTML 内容，作为测试用例的输入。这允许测试不同的 HTML 和 CSS 结构对绘制属性树构建的影响。

3. **提供访问绘制属性树节点的方法:**  文件中定义了多个帮助方法，用于方便地访问文档的根元素的各种绘制属性节点，例如：
    * `DocPreTranslation()`: 获取文档预平移变换节点。
    * `DocScrollTranslation()`: 获取文档滚动平移变换节点。
    * `DocContentClip()`: 获取文档内容裁剪节点。
    * `DocScroll()`: 获取文档滚动节点。
    * `DocEffect()`: 获取文档效果节点。

4. **提供访问元素绘制属性的方法:** `PaintPropertiesForElement()` 方法允许根据元素的 ID 获取其对应的 `ObjectPaintProperties`，从而访问该元素的各种绘制属性节点。

5. **提供访问变换缓存的方法:** `GetTransformCache()` 方法用于访问特定变换绘制属性节点的变换缓存，这可能用于测试性能优化相关的逻辑。

6. **定义辅助宏用于视觉位置检查:**  `CHECK_VISUAL_RECT` 和 `CHECK_EXACT_VISUAL_RECT` 宏用于断言元素的实际渲染位置是否与预期一致。这两个宏会考虑几何映射 (GeometryMapper) 的优化路径以及慢路径，以确保测试的全面性。

7. **包含针对特定绘制属性功能的测试用例:**  该部分已经包含了多个针对特定绘制属性功能的测试用例，例如：
    * `FixedPosition`: 测试固定定位元素的绘制属性树构建。
    * `PositionAndScroll`: 测试定位和滚动相关的绘制属性树构建。
    * `OverflowScrollExcludeScrollbars`: 测试带有滚动条的溢出容器的裁剪属性。
    * `OverlapNoPaintOffsetTranslation` 和 `AssumeOverlapNoPaintOffsetTranslation`: 测试在特定重叠情况下是否创建了不必要的 paint offset translation 节点。
    * `OverflowScrollExcludeScrollbarsSubpixel`:  测试亚像素情况下滚动条的排除。
    * `OverflowScrollExcludeCssOverlayScrollbar`: 测试 CSS overlay 滚动条的影响。
    * `OverflowScrollVerticalRL`: 测试垂直方向从右到左书写模式下的滚动容器。
    * `OverflowScrollRTL`: 测试从右到左布局下的滚动容器。
    * `OverflowScrollVerticalRLMulticol`: 测试多列布局下滚动的影响。
    * `DocScrollingTraditional`: 测试文档滚动对绘制属性树的影响。
    * `Perspective`: 测试 `perspective` CSS 属性对绘制属性树的影响。
    * `Transform`: 测试 `transform` CSS 属性对绘制属性树的影响。
    * `Preserve3D3DTransformedDescendant`: 测试 `transform-style: preserve-3d` 对子元素的影响。
    * `Perspective3DTransformedDescendant`: 测试父元素设置 `perspective` 对子元素的影响。
    * `TransformPerspective3DTransformedDescendant`:  测试父元素使用 `transform: perspective()` 对子元素的影响。

**与 JavaScript, HTML, CSS 的关系举例说明：**

* **HTML:** `LoadTestData("fixed-position.html")`  这行代码加载了一个包含 HTML 结构的测试文件。`PaintPropertyTreeBuilder` 的目标就是解析这个 HTML 结构，并结合 CSS 样式来构建绘制属性树。
* **CSS:** 在 `FixedPosition` 测试用例中，测试了 CSS 属性 `position: fixed` 的元素。`PaintPropertyTreeBuilder` 需要正确地将这个 CSS 属性反映到绘制属性树中，例如，固定定位元素通常会挂载到视口下。
* **JavaScript:** 虽然这段代码没有直接的 JavaScript 代码，但 JavaScript 可以动态地修改 HTML 结构和 CSS 样式。 这些修改会触发重新布局和重绘，进而调用 `PaintPropertyTreeBuilder` 来更新绘制属性树。例如，JavaScript 可以通过修改元素的 `style` 属性来改变其 `transform` 值，这将导致 `Transform` 测试用例中的逻辑被执行。

**逻辑推理举例说明：**

**假设输入 (来自 `FixedPosition` 测试用例):**

```html
<div style="position: absolute; overflow: scroll; width: 200px; height: 200px;" id="positionedScroll">
  <div style="width: 300px; height: 300px;">
    <div style="position: fixed; left: 200px; top: 150px; width: 100px; height: 100px;" id="target1"></div>
  </div>
</div>
```

**逻辑推理:**  由于 `target1` 元素设置了 `position: fixed;`，并且它位于一个可滚动的绝对定位元素 `positionedScroll` 内，`PaintPropertyTreeBuilder` 应该将 `target1` 的绘制属性树节点挂载到视口下，以使其不受父元素的滚动影响。

**预期输出:** `target1_properties->OverflowClip()->Parent()` 应该等于 `DocContentClip()`，表示 `target1` 的溢出裁剪的父节点是文档的内容裁剪节点，即视口的裁剪。

**用户或编程常见的使用错误举例说明：**

* **误解 fixed 定位的行为:**  开发者可能会错误地认为固定定位的元素会相对于其最近的定位祖先进行固定，但实际上它是相对于视口固定的。测试用例 `FixedPosition` 可以帮助验证 `PaintPropertyTreeBuilder` 是否正确处理了这种情况。如果 `PaintPropertyTreeBuilder` 没有正确处理，`target1` 的位置可能不会如预期那样固定在视口的位置。

**用户操作如何一步步的到达这里，作为调试线索：**

1. **用户在浏览器中访问一个网页。**
2. **网页的 HTML、CSS 和 JavaScript 代码被加载和解析。**
3. **渲染引擎开始构建 DOM 树和 CSSOM 树。**
4. **布局引擎根据 DOM 树和 CSSOM 树计算出每个元素的位置和大小 (Layout Tree)。**
5. **在布局完成后，`PaintPropertyTreeBuilder` 被调用，遍历 Layout Tree，并根据元素的样式属性（例如 `position`, `transform`, `overflow` 等）以及继承关系，构建出 Paint Property Trees。**
6. **例如，如果用户访问的网页包含一个设置了 `position: fixed` 的元素，并且该元素需要被绘制，那么 `PaintPropertyTreeBuilder` 中处理 `position: fixed` 逻辑的代码会被执行，这部分逻辑正是 `FixedPosition` 测试用例所覆盖的。**
7. **如果开发者怀疑 `position: fixed` 的元素没有按照预期的方式渲染，他们可能会查看与 `PaintPropertyTreeBuilder` 相关的代码和测试用例，例如这个 `paint_property_tree_builder_test.cc` 文件，来理解渲染引擎是如何处理 `position: fixed` 的。**

总而言之，`blink/renderer/core/paint/paint_property_tree_builder_test.cc` 的第一部分定义了测试框架和基础工具，并包含了一系列针对特定绘制属性功能的测试用例，旨在验证 `PaintPropertyTreeBuilder` 是否能正确地根据 HTML 结构和 CSS 样式构建用于绘制的属性树，这直接关系到网页的最终渲染结果。

### 提示词
```
这是目录为blink/renderer/core/paint/paint_property_tree_builder_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共10部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/paint/paint_property_tree_builder_test.h"

#include "cc/test/fake_layer_tree_host_client.h"
#include "cc/trees/effect_node.h"
#include "cc/trees/scroll_node.h"
#include "cc/trees/transform_node.h"
#include "third_party/blink/renderer/core/frame/frame_test_helpers.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/html/html_iframe_element.h"
#include "third_party/blink/renderer/core/layout/layout_flow_thread.h"
#include "third_party/blink/renderer/core/layout/layout_image.h"
#include "third_party/blink/renderer/core/layout/layout_multi_column_flow_thread.h"
#include "third_party/blink/renderer/core/layout/layout_tree_as_text.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_root.h"
#include "third_party/blink/renderer/core/paint/fragment_data_iterator.h"
#include "third_party/blink/renderer/core/paint/object_paint_properties.h"
#include "third_party/blink/renderer/core/paint/paint_property_tree_printer.h"
#include "third_party/blink/renderer/platform/graphics/compositing/paint_artifact_compositor.h"
#include "third_party/blink/renderer/platform/graphics/paint/geometry_mapper.h"
#include "third_party/blink/renderer/platform/testing/layer_tree_host_embedder.h"
#include "third_party/blink/renderer/platform/testing/paint_property_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/testing_platform_support.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "ui/gfx/geometry/test/geometry_util.h"

namespace blink {

void PaintPropertyTreeBuilderTest::LoadTestData(const char* file_name) {
  StringBuilder full_path;
  full_path.Append(test::BlinkRootDir());
  full_path.Append("/renderer/core/paint/test_data/");
  full_path.Append(file_name);
  const Vector<char> input_buffer = *test::ReadFromFile(full_path.ToString());
  SetBodyInnerHTML(String(input_buffer));
}

const TransformPaintPropertyNode*
PaintPropertyTreeBuilderTest::DocPreTranslation(const Document* document) {
  if (!document)
    document = &GetDocument();
  return document->GetLayoutView()
      ->FirstFragment()
      .PaintProperties()
      ->PaintOffsetTranslation();
}

const TransformPaintPropertyNode*
PaintPropertyTreeBuilderTest::DocScrollTranslation(const Document* document) {
  if (!document)
    document = &GetDocument();
  return document->GetLayoutView()
      ->FirstFragment()
      .PaintProperties()
      ->ScrollTranslation();
}

const ClipPaintPropertyNode* PaintPropertyTreeBuilderTest::DocContentClip(
    const Document* document) {
  if (!document)
    document = &GetDocument();
  return document->GetLayoutView()
      ->FirstFragment()
      .PaintProperties()
      ->OverflowClip();
}

const ScrollPaintPropertyNode* PaintPropertyTreeBuilderTest::DocScroll(
    const Document* document) {
  if (!document)
    document = &GetDocument();
  return document->GetLayoutView()->FirstFragment().PaintProperties()->Scroll();
}

const EffectPaintPropertyNode* PaintPropertyTreeBuilderTest::DocEffect(
    const Document* document) {
  if (!document) {
    document = &GetDocument();
  }
  return document->GetLayoutView()
      ->FirstFragment()
      .PaintProperties()
      ->ViewTransitionEffect();
}

const ObjectPaintProperties*
PaintPropertyTreeBuilderTest::PaintPropertiesForElement(const char* name) {
  return GetDocument()
      .getElementById(AtomicString(name))
      ->GetLayoutObject()
      ->FirstFragment()
      .PaintProperties();
}

const GeometryMapperTransformCache&
PaintPropertyTreeBuilderTest::GetTransformCache(
    const TransformPaintPropertyNode& transform) {
  return transform.GetTransformCache();
}

void PaintPropertyTreeBuilderTest::SetUp() {
  EnableCompositing();
  RenderingTest::SetUp();
}

#define CHECK_VISUAL_RECT(expected, source_object, ancestor, slop_factor)      \
  do {                                                                         \
    if ((source_object)->HasLayer() && (ancestor)->HasLayer()) {               \
      auto actual = LocalVisualRect(*(source_object));                         \
      (source_object)                                                          \
          ->MapToVisualRectInAncestorSpace(ancestor, actual,                   \
                                           kUseGeometryMapper);                \
      SCOPED_TRACE("GeometryMapper: ");                                        \
      EXPECT_EQ(expected, actual);                                             \
    }                                                                          \
                                                                               \
    if (slop_factor == LayoutUnit::Max())                                      \
      break;                                                                   \
    auto slow_path_rect = LocalVisualRect(*(source_object));                   \
    (source_object)->MapToVisualRectInAncestorSpace(ancestor, slow_path_rect); \
    if (slop_factor) {                                                         \
      auto inflated_expected = expected;                                       \
      inflated_expected.Inflate(LayoutUnit(slop_factor));                      \
      SCOPED_TRACE(String::Format(                                             \
          "Slow path rect: %s, Expected: %s, Inflated expected: %s",           \
          slow_path_rect.ToString().Ascii().c_str(),                           \
          expected.ToString().Ascii().c_str(),                                 \
          inflated_expected.ToString().Ascii().c_str()));                      \
      EXPECT_TRUE(                                                             \
          PhysicalRect(ToEnclosingRect(slow_path_rect)).Contains(expected));   \
      EXPECT_TRUE(inflated_expected.Contains(slow_path_rect));                 \
    } else {                                                                   \
      SCOPED_TRACE("Slow path: ");                                             \
      EXPECT_EQ(expected, slow_path_rect);                                     \
    }                                                                          \
  } while (0)

#define CHECK_EXACT_VISUAL_RECT(expected, source_object, ancestor) \
  CHECK_VISUAL_RECT(expected, source_object, ancestor, 0)

INSTANTIATE_TEST_SUITE_P(All,
                         PaintPropertyTreeBuilderTest,
                         ::testing::Values(0,
                                           kUnderInvalidationChecking,
                                           kElementCapture));

TEST_P(PaintPropertyTreeBuilderTest, FixedPosition) {
  LoadTestData("fixed-position.html");

  Element* positioned_scroll =
      GetDocument().getElementById(AtomicString("positionedScroll"));
  positioned_scroll->setScrollTop(3);
  Element* transformed_scroll =
      GetDocument().getElementById(AtomicString("transformedScroll"));
  transformed_scroll->setScrollTop(5);

  LocalFrameView* frame_view = GetDocument().View();
  frame_view->UpdateAllLifecyclePhasesForTest();

  // target1 is a fixed-position element inside an absolute-position scrolling
  // element.  It should be attached under the viewport to skip scrolling and
  // offset of the parent.
  Element* target1 = GetDocument().getElementById(AtomicString("target1"));
  const ObjectPaintProperties* target1_properties =
      target1->GetLayoutObject()->FirstFragment().PaintProperties();
  EXPECT_CLIP_RECT(FloatRoundedRect(0, 0, 100, 100),
                   target1_properties->OverflowClip());
  // Likewise, it inherits clip from the viewport, skipping overflow clip of the
  // scroller.
  EXPECT_EQ(DocContentClip(), target1_properties->OverflowClip()->Parent());
  // target1 should not have its own scroll node and instead should inherit
  // positionedScroll's.
  const ObjectPaintProperties* positioned_scroll_properties =
      positioned_scroll->GetLayoutObject()->FirstFragment().PaintProperties();
  auto* positioned_scroll_translation =
      positioned_scroll_properties->ScrollTranslation();
  auto* positioned_scroll_node = positioned_scroll_translation->ScrollNode();
  EXPECT_EQ(DocScroll(), positioned_scroll_node->Parent());
  EXPECT_EQ(gfx::Vector2dF(0, -3),
            positioned_scroll_translation->Get2dTranslation());
  EXPECT_EQ(nullptr, target1_properties->ScrollTranslation());
  CHECK_EXACT_VISUAL_RECT(PhysicalRect(200, 150, 100, 100),
                          target1->GetLayoutObject(),
                          frame_view->GetLayoutView());

  // target2 is a fixed-position element inside a transformed scrolling element.
  // It should be attached under the scrolled box of the transformed element.
  Element* target2 = GetDocument().getElementById(AtomicString("target2"));
  const ObjectPaintProperties* target2_properties =
      target2->GetLayoutObject()->FirstFragment().PaintProperties();
  Element* scroller =
      GetDocument().getElementById(AtomicString("transformedScroll"));
  const ObjectPaintProperties* scroller_properties =
      scroller->GetLayoutObject()->FirstFragment().PaintProperties();
  EXPECT_CLIP_RECT(FloatRoundedRect(200, 150, 100, 100),
                   target2_properties->OverflowClip());
  EXPECT_EQ(scroller_properties->OverflowClip(),
            target2_properties->OverflowClip()->Parent());
  // target2 should not have it's own scroll node and instead should inherit
  // transformedScroll's.
  const ObjectPaintProperties* transformed_scroll_properties =
      transformed_scroll->GetLayoutObject()->FirstFragment().PaintProperties();
  auto* transformed_scroll_translation =
      transformed_scroll_properties->ScrollTranslation();
  auto* transformed_scroll_node = transformed_scroll_translation->ScrollNode();
  EXPECT_EQ(DocScroll(), transformed_scroll_node->Parent());
  EXPECT_EQ(gfx::Vector2dF(0, -5),
            transformed_scroll_translation->Get2dTranslation());
  EXPECT_EQ(nullptr, target2_properties->ScrollTranslation());

  CHECK_EXACT_VISUAL_RECT(PhysicalRect(208, 153, 200, 100),
                          target2->GetLayoutObject(),
                          frame_view->GetLayoutView());
}

TEST_P(PaintPropertyTreeBuilderTest, PositionAndScroll) {
  GetDocument().SetCompatibilityMode(Document::kQuirksMode);
  LoadTestData("position-and-scroll.html");

  Element* scroller = GetDocument().getElementById(AtomicString("scroller"));
  scroller->scrollTo(0, 100);
  LocalFrameView* frame_view = GetDocument().View();
  frame_view->UpdateAllLifecyclePhasesForTest();
  const ObjectPaintProperties* scroller_properties =
      scroller->GetLayoutObject()->FirstFragment().PaintProperties();
  EXPECT_EQ(gfx::Vector2dF(0, -100),
            scroller_properties->ScrollTranslation()->Get2dTranslation());
  EXPECT_EQ(scroller_properties->PaintOffsetTranslation(),
            scroller_properties->ScrollTranslation()->Parent());
  EXPECT_EQ(DocScrollTranslation(),
            scroller_properties->PaintOffsetTranslation()->Parent());
  EXPECT_EQ(scroller_properties->PaintOffsetTranslation(),
            &scroller_properties->OverflowClip()->LocalTransformSpace());
  const auto* scroll = scroller_properties->ScrollTranslation()->ScrollNode();
  EXPECT_EQ(DocScroll(), scroll->Parent());
  EXPECT_EQ(gfx::Rect(0, 0, 413, 317), scroll->ContainerRect());
  EXPECT_EQ(gfx::Rect(0, 0, 660, 10200), scroll->ContentsRect());
  EXPECT_FALSE(scroll->UserScrollableHorizontal());
  EXPECT_TRUE(scroll->UserScrollableVertical());
  EXPECT_EQ(gfx::Vector2dF(120, 340),
            scroller_properties->PaintOffsetTranslation()->Get2dTranslation());
  EXPECT_CLIP_RECT(FloatRoundedRect(0, 0, 413, 317),
                   scroller_properties->OverflowClip());
  EXPECT_EQ(DocContentClip(), scroller_properties->OverflowClip()->Parent());
  CHECK_EXACT_VISUAL_RECT(PhysicalRect(120, 340, 413, 317),
                          scroller->GetLayoutObject(),
                          frame_view->GetLayoutView());

  // The relative-positioned element should have accumulated box offset (exclude
  // scrolling), and should be affected by ancestor scroll transforms.
  Element* rel_pos = GetDocument().getElementById(AtomicString("rel-pos"));
  const ObjectPaintProperties* rel_pos_properties =
      rel_pos->GetLayoutObject()->FirstFragment().PaintProperties();
  EXPECT_EQ(gfx::Vector2dF(560, 780),
            rel_pos_properties->PaintOffsetTranslation()->Get2dTranslation());
  EXPECT_EQ(scroller_properties->ScrollTranslation(),
            rel_pos_properties->PaintOffsetTranslation()->Parent());
  EXPECT_EQ(rel_pos_properties->Transform(),
            &rel_pos_properties->OverflowClip()->LocalTransformSpace());
  EXPECT_CLIP_RECT(FloatRoundedRect(0, 0, 100, 200),
                   rel_pos_properties->OverflowClip());
  EXPECT_EQ(scroller_properties->OverflowClip(),
            rel_pos_properties->OverflowClip()->Parent());
  CHECK_EXACT_VISUAL_RECT(PhysicalRect(), rel_pos->GetLayoutObject(),
                          frame_view->GetLayoutView());

  // The absolute-positioned element should not be affected by non-positioned
  // scroller at all.
  Element* abs_pos = GetDocument().getElementById(AtomicString("abs-pos"));
  const ObjectPaintProperties* abs_pos_properties =
      abs_pos->GetLayoutObject()->FirstFragment().PaintProperties();
  EXPECT_EQ(gfx::Vector2dF(123, 456),
            abs_pos_properties->PaintOffsetTranslation()->Get2dTranslation());
  EXPECT_EQ(DocScrollTranslation(),
            abs_pos_properties->PaintOffsetTranslation()->Parent());
  EXPECT_EQ(abs_pos_properties->Transform(),
            &abs_pos_properties->OverflowClip()->LocalTransformSpace());
  EXPECT_CLIP_RECT(FloatRoundedRect(0, 0, 300, 400),
                   abs_pos_properties->OverflowClip());
  EXPECT_EQ(DocContentClip(), abs_pos_properties->OverflowClip()->Parent());
  CHECK_EXACT_VISUAL_RECT(PhysicalRect(123, 456, 300, 400),
                          abs_pos->GetLayoutObject(),
                          frame_view->GetLayoutView());
}

TEST_P(PaintPropertyTreeBuilderTest, OverflowScrollExcludeScrollbars) {
  SetBodyInnerHTML(R"HTML(
    <div id='scroller'
         style='width: 100px; height: 100px; overflow: scroll;
                 border: 10px solid blue'>
      <div style='width: 400px; height: 400px'></div>
    </div>
  )HTML");
  CHECK(GetDocument().GetPage()->GetScrollbarTheme().UsesOverlayScrollbars());

  const auto* properties = PaintPropertiesForElement("scroller");
  const auto* overflow_clip = properties->OverflowClip();

  EXPECT_EQ(DocContentClip(), overflow_clip->Parent());
  EXPECT_EQ(properties->PaintOffsetTranslation(),
            &overflow_clip->LocalTransformSpace());
  EXPECT_EQ(FloatClipRect(gfx::RectF(10, 10, 100, 100)),
            overflow_clip->LayoutClipRect());

  PaintLayer* paint_layer = GetPaintLayerByElementId("scroller");
  EXPECT_TRUE(paint_layer->GetScrollableArea()
                  ->VerticalScrollbar()
                  ->IsOverlayScrollbar());

  EXPECT_EQ(FloatClipRect(gfx::RectF(10, 10, 93, 93)),
            overflow_clip->LayoutClipRectExcludingOverlayScrollbars());
}

TEST_P(PaintPropertyTreeBuilderTest, OverlapNoPaintOffsetTranslation) {
  SetBodyInnerHTML(R"HTML(
    <style>
      div { width: 100px; height: 100px }
    </style>
    <div style='will-change: transform'></div>
    <div id=target style='margin-top: -50px; position: relative; opacity: 0.5'></div>
  )HTML");
  CHECK(GetDocument().GetPage()->GetScrollbarTheme().UsesOverlayScrollbars());
  const auto* properties = PaintPropertiesForElement("target");
  EXPECT_EQ(nullptr, properties->PaintOffsetTranslation());
}

TEST_P(PaintPropertyTreeBuilderTest, AssumeOverlapNoPaintOffsetTranslation) {
  SetBodyInnerHTML(R"HTML(
    <style>
      div { width: 100px; height: 100px }
    </style>
    <div style='position: fixed'></div>
    <div id=target style='position: relative; opacity: 0.5'></div>
    <div style="height: 1000px"></div>
  )HTML");
  CHECK(GetDocument().GetPage()->GetScrollbarTheme().UsesOverlayScrollbars());
  const auto* properties = PaintPropertiesForElement("target");
  EXPECT_EQ(nullptr, properties->PaintOffsetTranslation());
}

TEST_P(PaintPropertyTreeBuilderTest, OverflowScrollExcludeScrollbarsSubpixel) {
  SetBodyInnerHTML(R"HTML(
    <div id='scroller'
         style='width: 100.5px; height: 100px; overflow: scroll;
                 border: 10px solid blue'>
      <div style='width: 400px; height: 400px'></div>
    </div>
  )HTML");
  CHECK(GetDocument().GetPage()->GetScrollbarTheme().UsesOverlayScrollbars());

  const auto* scroller = GetLayoutObjectByElementId("scroller");
  const auto* properties = scroller->FirstFragment().PaintProperties();
  const auto* overflow_clip = properties->OverflowClip();

  EXPECT_EQ(DocContentClip(), overflow_clip->Parent());
  EXPECT_EQ(properties->PaintOffsetTranslation(),
            &overflow_clip->LocalTransformSpace());
  EXPECT_EQ(FloatClipRect(gfx::RectF(10, 10, 100.5, 100)),
            overflow_clip->LayoutClipRect());
  EXPECT_EQ(FloatRoundedRect(10, 10, 101, 100), overflow_clip->PaintClipRect());

  EXPECT_TRUE(To<LayoutBox>(scroller)
                  ->GetScrollableArea()
                  ->VerticalScrollbar()
                  ->IsOverlayScrollbar());

  EXPECT_EQ(FloatClipRect(gfx::RectF(10, 10, 93.5, 93)),
            overflow_clip->LayoutClipRectExcludingOverlayScrollbars());
}

TEST_P(PaintPropertyTreeBuilderTest, OverflowScrollExcludeCssOverlayScrollbar) {
  SetBodyInnerHTML(R"HTML(
    <style>
    ::-webkit-scrollbar { background-color: transparent; }
    ::-webkit-scrollbar:vertical { width: 200px; }
    ::-webkit-scrollbar-thumb { background: transparent; }
    body {
      margin: 0 30px 0 0;
      background: lightgreen;
      overflow-y: overlay;
      overflow-x: hidden;
    }
    </style>
    <div style="height: 5000px; width: 100%; background: lightblue;"></div>
  )HTML");
  // The document content should not be clipped by the overlay scrollbar because
  // the scrollbar can be transparent and the content needs to paint below.
  EXPECT_CLIP_RECT(FloatRoundedRect(0, 0, 600, 600), DocContentClip());
}

TEST_P(PaintPropertyTreeBuilderTest, OverflowScrollVerticalRL) {
  SetBodyInnerHTML(R"HTML(
    <style>::-webkit-scrollbar {width: 15px; height: 15px}</style>
    <div id='scroller'
         style='width: 100px; height: 100px; overflow: scroll;
                writing-mode: vertical-rl; border: 10px solid blue'>
      <div id="content" style='width: 400px; height: 400px'></div>
    </div>
  )HTML");

  const auto* scroller = GetLayoutBoxByElementId("scroller");
  const auto* content = GetLayoutObjectByElementId("content");
  const auto* properties = scroller->FirstFragment().PaintProperties();
  const auto* overflow_clip = properties->OverflowClip();
  const auto* scroll_translation = properties->ScrollTranslation();
  const auto* scroll = properties->Scroll();

  // -315: container_width (100) - contents_width (400) - scrollber_width
  EXPECT_EQ(gfx::Vector2dF(-315, 0), scroll_translation->Get2dTranslation());
  EXPECT_EQ(scroll, scroll_translation->ScrollNode());
  // 10: border width. 85: container client size (== 100 - scrollbar width).
  EXPECT_EQ(gfx::Rect(10, 10, 85, 85), scroll->ContainerRect());
  EXPECT_EQ(gfx::Rect(10, 10, 400, 400), scroll->ContentsRect());
  EXPECT_EQ(PhysicalOffset(), scroller->FirstFragment().PaintOffset());
  EXPECT_EQ(gfx::Point(315, 0), scroller->ScrollOrigin());
  EXPECT_EQ(PhysicalOffset(10, 10), content->FirstFragment().PaintOffset());

  EXPECT_EQ(DocContentClip(), overflow_clip->Parent());
  EXPECT_EQ(properties->PaintOffsetTranslation(),
            &overflow_clip->LocalTransformSpace());
  EXPECT_CLIP_RECT(FloatRoundedRect(10, 10, 85, 85), overflow_clip);

  scroller->GetScrollableArea()->ScrollBy(ScrollOffset(-100, 0),
                                          mojom::blink::ScrollType::kUser);
  UpdateAllLifecyclePhasesForTest();

  // Only scroll_translation is affected by scrolling.
  EXPECT_EQ(gfx::Vector2dF(-215, 0), scroll_translation->Get2dTranslation());
  // Other properties are the same as before.
  EXPECT_EQ(scroll, scroll_translation->ScrollNode());
  EXPECT_EQ(gfx::Rect(10, 10, 85, 85), scroll->ContainerRect());
  EXPECT_EQ(gfx::Rect(10, 10, 400, 400), scroll->ContentsRect());
  EXPECT_EQ(PhysicalOffset(), scroller->FirstFragment().PaintOffset());
  EXPECT_EQ(gfx::Point(315, 0), scroller->ScrollOrigin());
  EXPECT_EQ(PhysicalOffset(10, 10), content->FirstFragment().PaintOffset());

  EXPECT_EQ(DocContentClip(), overflow_clip->Parent());
  EXPECT_EQ(properties->PaintOffsetTranslation(),
            &overflow_clip->LocalTransformSpace());
  EXPECT_CLIP_RECT(FloatRoundedRect(10, 10, 85, 85), overflow_clip);
}

TEST_P(PaintPropertyTreeBuilderTest, OverflowScrollRTL) {
  SetBodyInnerHTML(R"HTML(
    <style>::-webkit-scrollbar {width: 15px; height: 15px}</style>
    <div id='scroller'
         style='width: 100px; height: 100px; overflow: scroll;
                direction: rtl; border: 10px solid blue'>
      <div id='content' style='width: 400px; height: 400px'></div>
    </div>
  )HTML");

  const auto* scroller = GetLayoutBoxByElementId("scroller");
  const auto* content = GetLayoutObjectByElementId("content");
  const auto* properties = scroller->FirstFragment().PaintProperties();
  const auto* overflow_clip = properties->OverflowClip();
  const auto* scroll_translation = properties->ScrollTranslation();
  const auto* scroll = properties->Scroll();

  // -315: container_width (100) - contents_width (400) - scrollbar width (15).
  EXPECT_EQ(gfx::Vector2dF(-315, 0), scroll_translation->Get2dTranslation());
  EXPECT_EQ(scroll, scroll_translation->ScrollNode());
  // 25: border width (10) + scrollbar (on the left) width (15).
  // 85: container client size (== 100 - scrollbar width).
  EXPECT_EQ(gfx::Rect(25, 10, 85, 85), scroll->ContainerRect());
  EXPECT_EQ(gfx::Rect(25, 10, 400, 400), scroll->ContentsRect());
  EXPECT_EQ(PhysicalOffset(), scroller->FirstFragment().PaintOffset());
  EXPECT_EQ(gfx::Point(315, 0), scroller->ScrollOrigin());
  EXPECT_EQ(PhysicalOffset(25, 10), content->FirstFragment().PaintOffset());

  EXPECT_EQ(DocContentClip(), overflow_clip->Parent());
  EXPECT_EQ(properties->PaintOffsetTranslation(),
            &overflow_clip->LocalTransformSpace());
  EXPECT_CLIP_RECT(FloatRoundedRect(25, 10, 85, 85), overflow_clip);

  scroller->GetScrollableArea()->ScrollBy(ScrollOffset(-100, 0),
                                          mojom::blink::ScrollType::kUser);
  UpdateAllLifecyclePhasesForTest();

  // Only scroll_translation is affected by scrolling.
  EXPECT_EQ(gfx::Vector2dF(-215, 0), scroll_translation->Get2dTranslation());
  // Other properties are the same as before.
  EXPECT_EQ(scroll, scroll_translation->ScrollNode());
  EXPECT_EQ(gfx::Rect(25, 10, 85, 85), scroll->ContainerRect());
  EXPECT_EQ(gfx::Rect(25, 10, 400, 400), scroll->ContentsRect());
  EXPECT_EQ(PhysicalOffset(), scroller->FirstFragment().PaintOffset());
  EXPECT_EQ(gfx::Point(315, 0), scroller->ScrollOrigin());
  EXPECT_EQ(PhysicalOffset(25, 10), content->FirstFragment().PaintOffset());

  EXPECT_EQ(DocContentClip(), overflow_clip->Parent());
  EXPECT_EQ(properties->PaintOffsetTranslation(),
            &overflow_clip->LocalTransformSpace());
  EXPECT_CLIP_RECT(FloatRoundedRect(25, 10, 85, 85), overflow_clip);
}

TEST_P(PaintPropertyTreeBuilderTest, OverflowScrollVerticalRLMulticol) {
  SetBodyInnerHTML(R"HTML(
    <style>::-webkit-scrollbar {width: 15px; height: 15px}</style>
    <div id='scroller'
         style='width: 100px; height: 100px; overflow: scroll;
                writing-mode: vertical-rl; border: 10px solid blue'>
      <div id="multicol"
           style="width: 50px; height: 400px; columns: 2; column-gap: 0">
        <div id="child" style="width: 100px"></div>
      </div>
      <div style='width: 400px; height: 400px'></div>
    </div>
  )HTML");

  auto check_fragments = [this]() {
    const auto* child = GetLayoutObjectByElementId("child");
    ASSERT_EQ(2u, NumFragments(child));
    EXPECT_EQ(PhysicalOffset(410, 10), FragmentAt(child, 0).PaintOffset());
    EXPECT_EQ(PhysicalOffset(410, 210), FragmentAt(child, 1).PaintOffset());
  };
  check_fragments();

  // Fragment geometries are not affected by parent scrolling.
  GetLayoutBoxByElementId("scroller")
      ->GetScrollableArea()
      ->ScrollBy(ScrollOffset(-100, 200), mojom::blink::ScrollType::kUser);
  UpdateAllLifecyclePhasesForTest();
  check_fragments();
}

TEST_P(PaintPropertyTreeBuilderTest, DocScrollingTraditional) {
  SetBodyInnerHTML("<style> body { height: 10000px; } </style>");

  GetDocument().domWindow()->scrollTo(0, 100);

  LocalFrameView* frame_view = GetDocument().View();
  frame_view->UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(DocPreTranslation()->IsIdentity());
  EXPECT_EQ(
      GetDocument().GetPage()->GetVisualViewport().GetScrollTranslationNode(),
      DocPreTranslation()->Parent());
  EXPECT_EQ(gfx::Vector2dF(0, -100),
            DocScrollTranslation()->Get2dTranslation());
  EXPECT_EQ(DocPreTranslation(), DocScrollTranslation()->Parent());
  EXPECT_EQ(DocPreTranslation(), &DocContentClip()->LocalTransformSpace());
  EXPECT_CLIP_RECT(FloatRoundedRect(0, 0, 800, 600), DocContentClip());
  EXPECT_TRUE(DocContentClip()->Parent()->IsRoot());

  CHECK_EXACT_VISUAL_RECT(PhysicalRect(8, 8, 784, 10000),
                          GetDocument().body()->GetLayoutObject(),
                          frame_view->GetLayoutView());
}

TEST_P(PaintPropertyTreeBuilderTest, Perspective) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #perspective {
        position: absolute;
        left: 50px;
        top: 100px;
        width: 400px;
        height: 300px;
        perspective: 100px;
      }
      #inner {
        transform: translateZ(0);
        width: 100px;
        height: 200px;
      }
    </style>
    <div id='perspective'>
      <div id='inner'></div>
    </div>
  )HTML");
  Element* perspective =
      GetDocument().getElementById(AtomicString("perspective"));
  const ObjectPaintProperties* perspective_properties =
      perspective->GetLayoutObject()->FirstFragment().PaintProperties();
  gfx::Transform matrix;
  matrix.ApplyPerspectiveDepth(100);
  EXPECT_EQ(matrix, perspective_properties->Perspective()->Matrix());
  // The perspective origin is the center of the border box plus accumulated
  // paint offset.
  EXPECT_EQ(gfx::Point3F(250, 250, 0),
            perspective_properties->Perspective()->Origin());
  EXPECT_EQ(DocScrollTranslation(),
            perspective_properties->Perspective()->Parent());

  // Adding perspective doesn't clear paint offset. The paint offset will be
  // passed down to children.
  Element* inner = GetDocument().getElementById(AtomicString("inner"));
  const ObjectPaintProperties* inner_properties =
      inner->GetLayoutObject()->FirstFragment().PaintProperties();
  EXPECT_EQ(gfx::Vector2dF(50, 100),
            inner_properties->PaintOffsetTranslation()->Get2dTranslation());
  EXPECT_EQ(perspective_properties->Perspective(),
            inner_properties->PaintOffsetTranslation()->Parent());
  CHECK_EXACT_VISUAL_RECT(PhysicalRect(50, 100, 100, 200),
                          inner->GetLayoutObject(),
                          GetDocument().View()->GetLayoutView());

  perspective->setAttribute(html_names::kStyleAttr,
                            AtomicString("perspective: 200px"));
  UpdateAllLifecyclePhasesForTest();
  gfx::Transform matrix1;
  matrix1.ApplyPerspectiveDepth(200);
  EXPECT_EQ(matrix1, perspective_properties->Perspective()->Matrix());
  EXPECT_EQ(gfx::Point3F(250, 250, 0),
            perspective_properties->Perspective()->Origin());
  EXPECT_EQ(DocScrollTranslation(),
            perspective_properties->Perspective()->Parent());

  perspective->setAttribute(html_names::kStyleAttr,
                            AtomicString("perspective-origin: 5% 20%"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(matrix, perspective_properties->Perspective()->Matrix());
  EXPECT_EQ(gfx::Point3F(70, 160, 0),
            perspective_properties->Perspective()->Origin());
  EXPECT_EQ(DocScrollTranslation(),
            perspective_properties->Perspective()->Parent());
}

TEST_P(PaintPropertyTreeBuilderTest, Transform) {
  SetBodyInnerHTML(R"HTML(
    <style> body { margin: 0 } </style>
    <div id='transform' style='margin-left: 50px; margin-top: 100px;
        width: 400px; height: 300px;
        transform: translate3d(123px, 456px, 789px)'>
    </div>
  )HTML");

  Element* transform = GetDocument().getElementById(AtomicString("transform"));
  const ObjectPaintProperties* transform_properties =
      transform->GetLayoutObject()->FirstFragment().PaintProperties();

  EXPECT_EQ(MakeTranslationMatrix(123, 456, 789),
            transform_properties->Transform()->Matrix());
  EXPECT_EQ(gfx::Point3F(200, 150, 0),
            transform_properties->Transform()->Origin());
  EXPECT_EQ(transform_properties->PaintOffsetTranslation(),
            transform_properties->Transform()->Parent());
  EXPECT_EQ(gfx::Vector2dF(50, 100),
            transform_properties->PaintOffsetTranslation()->Get2dTranslation());
  EXPECT_EQ(DocScrollTranslation(),
            transform_properties->PaintOffsetTranslation()->Parent());
  EXPECT_TRUE(transform_properties->Transform()->HasDirectCompositingReasons());

  CHECK_EXACT_VISUAL_RECT(PhysicalRect(173, 556, 400, 300),
                          transform->GetLayoutObject(),
                          GetDocument().View()->GetLayoutView());

  transform->setAttribute(html_names::kStyleAttr,
                          AtomicString("margin-left: 50px; margin-top: 100px; "
                                       "width: 400px; height: 300px;"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(nullptr,
            transform->GetLayoutObject()->FirstFragment().PaintProperties());

  transform->setAttribute(
      html_names::kStyleAttr,
      AtomicString(
          "margin-left: 50px; margin-top: 100px; width: 400px; height: 300px; "
          "transform: translate3d(123px, 456px, 789px)"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(MakeTranslationMatrix(123, 456, 789), transform->GetLayoutObject()
                                                      ->FirstFragment()
                                                      .PaintProperties()
                                                      ->Transform()
                                                      ->Matrix());
}

TEST_P(PaintPropertyTreeBuilderTest, Preserve3D3DTransformedDescendant) {
  SetBodyInnerHTML(R"HTML(
    <style> body { margin: 0 } </style>
    <div id='preserve' style='transform-style: preserve-3d'>
    <div id='transform' style='margin-left: 50px; margin-top: 100px;
        width: 400px; height: 300px;
        transform: translate3d(123px, 456px, 789px)'>
    </div>
    </div>
  )HTML");

  Element* preserve = GetDocument().getElementById(AtomicString("preserve"));
  const ObjectPaintProperties* preserve_properties =
      preserve->GetLayoutObject()->FirstFragment().PaintProperties();

  EXPECT_TRUE(preserve_properties->Transform());
  EXPECT_TRUE(preserve_properties->Transform()->HasDirectCompositingReasons());
}

TEST_P(PaintPropertyTreeBuilderTest, Perspective3DTransformedDescendant) {
  SetBodyInnerHTML(R"HTML(
    <style> body { margin: 0 } </style>
    <div id='perspective' style='perspective: 800px;'>
    <div id='transform' style='margin-left: 50px; margin-top: 100px;
        width: 400px; height: 300px;
        transform: translate3d(123px, 456px, 789px)'>
    </div>
    </div>
  )HTML");

  Element* perspective =
      GetDocument().getElementById(AtomicString("perspective"));
  const ObjectPaintProperties* perspective_properties =
      perspective->GetLayoutObject()->FirstFragment().PaintProperties();

  EXPECT_TRUE(perspective_properties->Transform());
  EXPECT_TRUE(
      perspective_properties->Transform()->HasDirectCompositingReasons());
}

TEST_P(PaintPropertyTreeBuilderTest,
       TransformPerspective3DTransformedDescendant) {
  SetBodyInnerHTML(R"HTML(
    <style> body { margin: 0 } </style>
    <div id='perspective' style='transform: perspective(800px);'>
      <div id='transform' style='margin-left: 50px; margin-top: 100px;
          width: 400px; height: 300px;
          transform: translate3d(123px, 456px, 789px)'
```