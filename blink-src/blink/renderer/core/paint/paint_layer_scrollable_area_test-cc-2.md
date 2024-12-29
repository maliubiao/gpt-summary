Response:
The user wants a summary of the functionality of the provided C++ code file, `paint_layer_scrollable_area_test.cc`, which is part of the Chromium Blink rendering engine. The summary should include:

1. **Core Functionality**: What does this file primarily test?
2. **Relationship to Web Technologies**: How does it relate to JavaScript, HTML, and CSS? Provide examples.
3. **Logical Reasoning**: If there are tests involving logical conditions, describe the assumed input and expected output.
4. **Common Errors**:  Are there any tests that highlight potential user or programming errors? Give examples.
5. **User Journey**: How might a user action lead to this code being executed (debugging perspective)?
6. **Overall Summary**:  A concise conclusion about the file's purpose.

Let's break down the code section by section to identify these aspects:

* **Includes and Namespace**: Standard boilerplate. Not directly functional.
* **Test Fixture `PaintLayerScrollableAreaTest`**:  This indicates the file is testing the `PaintLayerScrollableArea` class.
* **`UsedColorSchemeRootScrollbarsInvalidateOnDarkToLightChange` and `UsedColorSchemeRootScrollbarsInvalidateOnLightToNormalChange`**: These tests are about how changes in the `color-scheme` CSS property affect the need to repaint scrollbars, specifically for the root scrollable area. They manipulate CSS and check if a flag indicating a repaint is set correctly.
* **`UsedColorSchemeRootScrollbarsUseCounterUpdated`**: This test checks if a usage counter is incremented when the root scrollable area's color scheme is accessed. This relates to tracking feature usage.
* **`NotScrollsOverflowWithScrollableScrollbar`**: This test seems to address a specific bug related to how overflow is handled when a scrollbar is present. It might expose an edge case where calculations for scroll geometry are incorrect.
* **`ScrollbarGutterBothEdgesWith...` tests**: These tests are focused on the `scrollbar-gutter` CSS property, specifically the `both-edges` value. They verify the layout and size calculations when this property is applied and how it interacts with padding, borders, and content size, including right-to-left scenarios.
* **Test Fixture `PaintLayerScrollableAreaWithWebFrameTest`**: This fixture seems to be testing scenarios that require a `WebLocalFrame` to simulate a more complete browser environment, likely related to main-thread scrolling.
* **`UpdateShouldAnimateScrollOnMainThread`**: This test verifies the behavior of scrolling, specifically whether it should occur on the main thread, based on the `overflow` CSS property. It checks how changes to the `overflow` property affect whether a `Scroll` paint property is created.

**Planning the Response:**

1. **Functionality**: Start by stating the core purpose: testing the `PaintLayerScrollableArea` class, which manages scrollable areas within the rendering engine.
2. **Web Technologies**: Explain how the tests interact with HTML (structure), CSS (styling and scrollbar properties like `color-scheme` and `scrollbar-gutter`), and potentially indirectly with JavaScript (by manipulating the DOM and triggering layout changes, although no explicit JavaScript is in the provided snippet). Provide specific examples from the code, like setting `color-scheme` or `scrollbar-gutter` in the HTML strings.
3. **Logical Reasoning**: Focus on the `ExpectEqAllScrollControlsNeedPaintInvalidation` assertions. For the color scheme tests, the input is changing the `color-scheme` CSS property, and the output is whether the scrollbars are flagged for repaint. For the `scrollbar-gutter` tests, the input is the CSS properties and the output is the calculated layout properties.
4. **Common Errors**: The "TODO" comments highlight potential bugs. The rounding issue in `NotScrollsOverflowWithScrollableScrollbar` is a good example of a programming error. The `scrollbar-gutter` tests, with their "TODO" comments about potentially incorrect expectations, suggest a possible misunderstanding or bug in the implementation or testing of this feature.
5. **User Journey**:  Describe how a user setting CSS properties (like `overflow`, `color-scheme`, `scrollbar-gutter`) or interacting with a scrollable area could lead to this code being executed during the rendering process.
6. **Overall Summary**:  Reiterate that the file tests the behavior and correctness of the `PaintLayerScrollableArea` in various scenarios, including interactions with CSS properties and potential edge cases.这是一个名为 `paint_layer_scrollable_area_test.cc` 的 Chromium Blink 引擎源代码文件，它的主要功能是**测试 `PaintLayerScrollableArea` 类的行为和逻辑**。`PaintLayerScrollableArea` 负责管理渲染层中可滚动区域的各种属性和行为，例如滚动条的显示和更新、滚动位置、内容大小以及与布局相关的计算。

以下是针对你提出的问题，根据代码片段进行的分析：

**1. 功能列举:**

* **测试根滚动条的颜色主题变化：** 测试当根元素的颜色主题 (`color-scheme`) 从 `dark` 变为 `light` 或从 `light` 变为 `normal` 时，根滚动条是否被正确地标记为需要重绘。这确保了滚动条的视觉样式能根据页面的颜色主题进行更新。
* **测试非根滚动条的颜色主题变化：** 验证非根滚动区域的滚动条在根元素颜色主题变化时是否不受影响，避免不必要的重绘。
* **测试根滚动条颜色主题使用计数器：**  检查当访问根滚动区域的 `UsedColorSchemeScrollbars()` 方法时，是否会正确地增加一个使用计数器 (`WebFeature::kUsedColorSchemeRootScrollbarsDark`)。这用于跟踪 Chromium 的特性使用情况。
* **测试带有可滚动滚动条的元素是否不应该溢出：** 这个测试（目前被注释为 TODO，表示可能存在问题）似乎是为了验证在特定尺寸和内边距的 RTL (Right-to-Left) 滚动容器中，即使存在滚动条，容器自身也不应被判断为溢出。这可能与滚动几何计算中的舍入误差有关。
* **测试 `scrollbar-gutter: stable both-edges` 属性：**  一系列测试验证了 CSS 属性 `scrollbar-gutter: stable both-edges` 的行为，包括在水平、垂直和同时存在滚动条的情况下，以及在 RTL 布局中，滚动区域的布局、内容大小、溢出矩形和裁剪矩形是否符合预期。这涉及到滚动槽（gutter）如何影响元素的尺寸和滚动行为。
* **测试在主线程上更新滚动动画：**  这个测试用例使用了 `PaintLayerScrollableAreaWithWebFrameTest` 测试夹具，表明它关注的是在拥有 `WebLocalFrame` 的情况下，滚动动画是否在主线程上执行。它通过改变元素的 `overflow` 属性，验证了当 `overflow` 从 `hidden` 变为 `auto` 或反之，以及调用 `scrollTo` 方法时，`PaintProperties` 中 `Scroll` 属性的创建与否，以及 `ShouldScrollOnMainThread()` 的返回值是否正确。

**2. 与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:** 测试用例通过 `SetHtmlInnerHTML` 和 `SetBodyInnerHTML` 方法设置 HTML 结构，例如创建带有特定 ID 和样式的 `div` 元素。这些 HTML 结构定义了需要测试的滚动容器及其内容。
    * **例子:** `<div id="normal" class="container"><div class="scrollable"></div></div>` 定义了一个 ID 为 "normal" 的容器，用于测试非根滚动区域。
* **CSS:** 测试用例通过内联样式或者通过设置文档的样式属性来应用 CSS 样式，例如 `overflow`, `width`, `height`, `color-scheme`, `scrollbar-gutter`, `direction` 等。这些 CSS 属性直接影响滚动区域的行为和外观。
    * **例子:**
        * `style="width: 100px; height: 100px; overflow: auto;"` 设置了滚动容器的尺寸和溢出行为。
        * `style="color-scheme: light;"`  设置了元素的颜色主题。
        * `style="scrollbar-gutter: stable both-edges;"` 设置了滚动槽的样式。
        * `style="direction: rtl;"` 设置了文本方向为从右到左。
* **JavaScript:** 虽然这个代码文件本身是 C++，用于测试渲染引擎的内部逻辑，但它模拟了 JavaScript 可能触发的操作。例如，通过改变 CSS 属性，测试模拟了 JavaScript 修改元素样式可能导致的滚动条更新。`scrollTo` 方法的调用也模拟了 JavaScript 执行滚动操作。
    * **间接关系:** 当 JavaScript 代码修改元素的 `color-scheme` 或 `overflow` 属性时，会触发浏览器的渲染流程，最终可能会执行到 `PaintLayerScrollableArea` 相关的代码，并可能触发这里的测试用例中验证的逻辑。

**3. 逻辑推理 (假设输入与输出):**

* **`UsedColorSchemeRootScrollbarsInvalidateOnDarkToLightChange`:**
    * **假设输入:**
        1. HTML 包含一个设置了 `color-scheme: dark;` 的根元素。
        2. 调用 `SetPreferredColorSchemesToDark` 设置浏览器首选颜色主题为深色。
        3. 将根元素的 `color-scheme` 属性通过内联样式更改为 `light`。
    * **预期输出:**
        1. 根滚动区域的滚动条应该被标记为需要重绘 (`ExpectEqAllScrollControlsNeedPaintInvalidation(root_scrollable_area, true)`）。
        2. 非根滚动区域的滚动条不应该被标记为需要重绘 (`ExpectEqAllScrollControlsNeedPaintInvalidation(non_root_scrollable_area, false)`）。
        3. 根滚动区域使用的颜色主题应该更新为浅色 (`EXPECT_EQ(root_scrollable_area->UsedColorSchemeScrollbars(), mojom::blink::ColorScheme::kLight);`)。

* **`ScrollbarGutterBothEdgesWithHorizontalScrollbar`:**
    * **假设输入:**  HTML 中包含一个设置了 `scrollbar-gutter: stable both-edges` 并且内容宽度超出容器宽度的 `div` 元素，从而产生水平滚动条。同时设置了 `border` 和 `padding`。
    * **预期输出:**
        1. `LayoutContentRect(kExcludeScrollbars)` (不包含滚动条的布局内容矩形) 的宽度应该等于容器的宽度减去左右 `border` 和 `padding` 的宽度。
        2. `LayoutContentRect(kIncludeScrollbars)` (包含滚动条的布局内容矩形) 的宽度应该等于容器的宽度。
        3. `ContentsSize()` (内容大小) 的宽度应该等于内部内容元素的宽度。
        4. `ScrollableOverflowRect()` (可滚动溢出矩形) 的位置和大小应该反映内容超出容器的部分。
        5. `OverflowClipRect()` (溢出裁剪矩形) 的大小应该等于容器的内部大小（包括 padding，但不包括 border）。
        6. `ScrollOrigin()` (滚动原点) 应该为 `(0, 0)`。

**4. 用户或编程常见的使用错误举例说明:**

* **颜色主题不一致导致的视觉错误:** 如果开发者在 CSS 中设置了 `color-scheme` 属性，但浏览器或操作系统的主题设置与此不符，可能会导致滚动条的颜色与页面其他元素不协调。测试用例通过验证滚动条是否因颜色主题变化而重绘，来确保渲染引擎能正确处理这种情况。
* **错误地假设滚动槽不影响布局:**  开发者可能错误地认为 `scrollbar-gutter` 属性不会影响元素的布局尺寸。测试用例针对 `scrollbar-gutter: stable both-edges` 的测试，明确了滚动槽会占据空间，即使滚动条不总是显示。如果开发者没有考虑到这一点，可能会导致页面布局错乱。
* **RTL 布局中滚动行为的误解:**  在 RTL 布局中，滚动条的位置和滚动行为与 LTR 布局不同。开发者可能在没有充分测试的情况下，错误地假设 RTL 布局的滚动行为与 LTR 相同。测试用例针对 RTL 布局的 `scrollbar-gutter` 测试，有助于验证渲染引擎在 RTL 布局下的正确性。
* **过度依赖主线程滚动:**  在性能敏感的应用中，强制滚动在主线程执行可能会导致性能问题。`UpdateShouldAnimateScrollOnMainThread` 测试验证了在特定情况下（例如 `overflow: hidden`），滚动是否在主线程执行。开发者应该尽量避免这种情况，除非必要。

**5. 用户操作如何一步步的到达这里 (调试线索):**

1. **用户加载一个网页:** 用户在浏览器中输入网址或点击链接，加载一个包含滚动区域的网页。
2. **浏览器解析 HTML, CSS:** 浏览器开始解析 HTML 结构和 CSS 样式。
3. **创建渲染树和布局树:** 浏览器根据 HTML 和 CSS 构建渲染树和布局树，确定每个元素的位置和大小。
4. **创建绘制层 (Paint Layers):**  浏览器根据布局树创建绘制层。对于包含 `overflow: auto` 或 `overflow: scroll` 的元素，会创建 `PaintLayerScrollableArea` 来管理其滚动行为。
5. **用户交互触发滚动或样式变化:**
    * **滚动:** 用户通过鼠标滚轮、触摸滑动或键盘操作滚动页面或特定容器。这会触发 `PaintLayerScrollableArea` 中与滚动位置更新相关的逻辑。
    * **样式变化:** 用户浏览器的主题设置发生变化，或者网页通过 CSS 或 JavaScript 修改了元素的 `color-scheme`、`overflow` 或 `scrollbar-gutter` 属性。这些变化会触发重新布局和重绘，并可能导致 `PaintLayerScrollableArea` 的状态更新。
6. **渲染引擎执行绘制:** 当需要更新滚动条外观或重新绘制滚动区域时，渲染引擎会调用 `PaintLayerScrollableArea` 的相关方法，确定是否需要进行重绘和如何绘制。
7. **测试执行 (开发者角度):**  作为 Chromium 的开发者，在修改或添加与滚动相关的代码后，会运行 `paint_layer_scrollable_area_test.cc` 中的测试用例，以验证修改是否引入了 bug 或是否符合预期行为。例如，修改了 `scrollbar-gutter` 的实现后，会运行相关的测试用例来确保布局计算的正确性。

**6. 功能归纳 (第 3 部分):**

作为 `paint_layer_scrollable_area_test.cc` 的第三部分，这部分代码主要关注以下功能：

* **深入测试了 `scrollbar-gutter: stable both-edges` 属性的各种场景**:  通过更细致的布局和尺寸断言，验证了该属性在不同滚动条状态和布局方向下的行为，确保了其实现的正确性。
* **测试了在具有 `WebLocalFrame` 的完整浏览器环境下的滚动行为**: 重点是验证滚动动画是否在主线程上按预期执行，这对于理解渲染性能和优化至关重要。这部分测试考虑了更接近真实用户环境的情况。

总而言之，`paint_layer_scrollable_area_test.cc` 文件通过一系列细致的测试用例，确保了 `PaintLayerScrollableArea` 类的功能正确性和稳定性，涵盖了颜色主题、滚动槽、RTL 布局以及主线程滚动等多个关键方面。 这些测试对于保证 Chromium 渲染引擎在处理网页滚动行为时的正确性和性能至关重要。

Prompt: 
```
这是目录为blink/renderer/core/paint/paint_layer_scrollable_area_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共3部分，请归纳一下它的功能

"""
olsNeedPaintInvalidation(root_scrollable_area, true);

  // Non root scrollbars should not change.
  ExpectEqAllScrollControlsNeedPaintInvalidation(non_root_scrollable_area,
                                                 false);

  EXPECT_EQ(root_scrollable_area->UsedColorSchemeScrollbars(),
            mojom::blink::ColorScheme::kLight);
}

TEST_P(PaintLayerScrollableAreaTest,
       UsedColorSchemeRootScrollbarsInvalidateOnLightToNormalChange) {
  USE_NON_OVERLAY_SCROLLBARS_OR_QUIT();

  SetHtmlInnerHTML(R"HTML(
    <style>
      html { height: 1000px; width: 1000px; color-scheme: light; }
      .container { overflow: scroll; width: 100px; height: 100px; }
      .scrollable { height: 400px; width: 400px; }
    </style>
    <div id="normal" class="container">
      <div class="scrollable"></div>
    </div>
  )HTML");

  AssertDefaultPreferredColorSchemes();

  const auto* root_scrollable_area = GetLayoutView().GetScrollableArea();
  ASSERT_TRUE(root_scrollable_area);
  const auto* non_root_scrollable_area =
      GetPaintLayerByElementId("normal")->GetScrollableArea();
  ASSERT_TRUE(non_root_scrollable_area);

  ColorSchemeHelper color_scheme_helper(GetDocument());
  SetPreferredColorSchemesToDark(color_scheme_helper);
  UpdateAllLifecyclePhasesForTest();

  // Set root element's color scheme to normal.
  GetDocument().documentElement()->SetInlineStyleProperty(
      CSSPropertyID::kColorScheme, AtomicString("normal"));

  // Update lifecycle up until the pre-paint before the scrollbars paint is
  // invalidated.
  GetDocument().View()->UpdateLifecycleToCompositingInputsClean(
      DocumentUpdateReason::kTest);

  // Root scrollbars should be set for invalidation after the color scheme
  // change.
  ExpectEqAllScrollControlsNeedPaintInvalidation(root_scrollable_area, true);

  // Non root scrollbars should not change.
  ExpectEqAllScrollControlsNeedPaintInvalidation(non_root_scrollable_area,
                                                 false);

  EXPECT_EQ(root_scrollable_area->UsedColorSchemeScrollbars(),
            mojom::blink::ColorScheme::kDark);
}

TEST_P(PaintLayerScrollableAreaTest,
       UsedColorSchemeRootScrollbarsUseCounterUpdated) {
  USE_NON_OVERLAY_SCROLLBARS_OR_QUIT();

  SetHtmlInnerHTML(R"HTML(
    <style>
      :root { height: 1000px; }
    </style>
  )HTML");

  AssertDefaultPreferredColorSchemes();

  const auto* root_scrollable_area = GetLayoutView().GetScrollableArea();
  ASSERT_TRUE(root_scrollable_area);

  ColorSchemeHelper color_scheme_helper(GetDocument());
  SetPreferredColorSchemesToDark(color_scheme_helper);
  UpdateAllLifecyclePhasesForTest();

  root_scrollable_area->UsedColorSchemeScrollbars();
  EXPECT_TRUE(GetDocument().IsUseCounted(
      WebFeature::kUsedColorSchemeRootScrollbarsDark));
}

// TODO(crbug.com/1020913): Actually this tests a situation that should not
// exist but it does exist due to different or incorrect rounding methods for
// scroll geometries. This test can be converted to test the correct behavior
// when we fix the bug. For now it just ensures we won't crash.
TEST_P(PaintLayerScrollableAreaTest,
       NotScrollsOverflowWithScrollableScrollbar) {
  USE_NON_OVERLAY_SCROLLBARS_OR_QUIT();

  SetBodyInnerHTML(R"HTML(
    <div id="scroller"
         style="box-sizing: border-box; width: 54.6px; height: 99.9px;
                padding: 20.1px; overflow: scroll; direction: rtl;
                will-change: scroll-position">
      <div style="width: 0; height: 20px"></div>
    </div>
  )HTML");

  auto* scroller = GetLayoutBoxByElementId("scroller");
  auto* scrollable_area = scroller->GetScrollableArea();
  EXPECT_FALSE(scrollable_area->ScrollsOverflow());
  ASSERT_TRUE(scrollable_area->HorizontalScrollbar());
  EXPECT_TRUE(scrollable_area->HorizontalScrollbar()->Maximum());
}

// TODO(crbug.com/340578714): The expectations match the current actual outputs
// which may not be fully correct.
TEST_P(PaintLayerScrollableAreaTest,
       ScrollbarGutterBothEdgesWithHorizontalScrollbar) {
  USE_NON_OVERLAY_SCROLLBARS_OR_QUIT();
  SetBodyInnerHTML(R"HTML(
    <div id="scroll" style="width: 100px; height: 100px; overflow: auto;
                            border: 20px solid blue; padding: 10px;
                            scrollbar-gutter: stable both-edges">
      <div style="width: 300px"></div>
    </div>
  )HTML");

  auto* scroll = GetLayoutBoxByElementId("scroll")->GetScrollableArea();
  EXPECT_EQ(PhysicalRect(0, 0, 90, 105),
            scroll->LayoutContentRect(kExcludeScrollbars));
  EXPECT_EQ(PhysicalRect(0, 0, 120, 120),
            scroll->LayoutContentRect(kIncludeScrollbars));
  EXPECT_EQ(gfx::Size(320, 105), scroll->ContentsSize());
  EXPECT_EQ(PhysicalRect(35, 20, 320, 105),
            scroll->GetLayoutBox()->ScrollableOverflowRect());
  EXPECT_EQ(PhysicalRect(20, 20, 120, 105),
            scroll->GetLayoutBox()->OverflowClipRect(PhysicalOffset()));
  EXPECT_EQ(gfx::Point(), scroll->ScrollOrigin());
}

// TODO(crbug.com/340578714): The expectations match the current actual outputs
// which may not be fully correct.
TEST_P(PaintLayerScrollableAreaTest,
       ScrollbarGutterBothEdgesWithVerticalScrollbars) {
  USE_NON_OVERLAY_SCROLLBARS_OR_QUIT();
  SetBodyInnerHTML(R"HTML(
    <div id="scroll" style="width: 100px; height: 100px; overflow: auto;
                            border: 20px solid blue; padding: 10px;
                            scrollbar-gutter: stable both-edges">
      <div style="height: 300px"></div>
    </div>
  )HTML");

  auto* scroll = GetLayoutBoxByElementId("scroll")->GetScrollableArea();
  EXPECT_EQ(PhysicalRect(0, 0, 90, 120),
            scroll->LayoutContentRect(kExcludeScrollbars));
  EXPECT_EQ(PhysicalRect(0, 0, 120, 120),
            scroll->LayoutContentRect(kIncludeScrollbars));
  EXPECT_EQ(gfx::Size(90, 320), scroll->ContentsSize());
  EXPECT_EQ(PhysicalRect(35, 20, 90, 320),
            scroll->GetLayoutBox()->ScrollableOverflowRect());
  EXPECT_EQ(PhysicalRect(20, 20, 105, 120),
            scroll->GetLayoutBox()->OverflowClipRect(PhysicalOffset()));
  EXPECT_EQ(gfx::Point(), scroll->ScrollOrigin());
}

// TODO(crbug.com/340578714): The expectations match the current actual outputs
// which may not be fully correct.
TEST_P(PaintLayerScrollableAreaTest,
       ScrollbarGutterBothEdgesWithBothScrollbars) {
  USE_NON_OVERLAY_SCROLLBARS_OR_QUIT();
  SetBodyInnerHTML(R"HTML(
    <div id="scroll" style="width: 100px; height: 100px; overflow: auto;
                            border: 20px solid blue; padding: 10px;
                            scrollbar-gutter: stable both-edges">
      <div style="width: 300px; height: 300px"></div>
    </div>
  )HTML");

  auto* scroll = GetLayoutBoxByElementId("scroll")->GetScrollableArea();
  EXPECT_EQ(PhysicalRect(0, 0, 90, 105),
            scroll->LayoutContentRect(kExcludeScrollbars));
  EXPECT_EQ(PhysicalRect(0, 0, 120, 120),
            scroll->LayoutContentRect(kIncludeScrollbars));
  EXPECT_EQ(gfx::Size(320, 320), scroll->ContentsSize());
  EXPECT_EQ(PhysicalRect(35, 20, 320, 320),
            scroll->GetLayoutBox()->ScrollableOverflowRect());
  EXPECT_EQ(PhysicalRect(20, 20, 105, 105),
            scroll->GetLayoutBox()->OverflowClipRect(PhysicalOffset()));
  EXPECT_EQ(gfx::Point(), scroll->ScrollOrigin());
}

// TODO(crbug.com/340578714): The expectations match the current actual outputs
// which may not be fully correct.
TEST_P(PaintLayerScrollableAreaTest,
       ScrollbarGutterBothEdgesOverflowIntoGutter) {
  USE_NON_OVERLAY_SCROLLBARS_OR_QUIT();
  SetBodyInnerHTML(R"HTML(
    <div id="scroll" style="width: 100px; height: 100px; overflow: auto;
                            border: 20px solid blue; padding: 10px;
                            scrollbar-gutter: stable both-edges">
      <div style="position: relative; left: -15px; width: 100px"></div>
    </div>
  )HTML");

  auto* scroll = GetLayoutBoxByElementId("scroll")->GetScrollableArea();
  EXPECT_EQ(PhysicalRect(0, 0, 90, 120),
            scroll->LayoutContentRect(kExcludeScrollbars));
  EXPECT_EQ(PhysicalRect(0, 0, 120, 120),
            scroll->LayoutContentRect(kIncludeScrollbars));
  EXPECT_EQ(gfx::Size(120, 120), scroll->ContentsSize());
  EXPECT_EQ(PhysicalRect(35, 20, 120, 120),
            scroll->GetLayoutBox()->ScrollableOverflowRect());
  EXPECT_EQ(PhysicalRect(20, 20, 120, 120),
            scroll->GetLayoutBox()->OverflowClipRect(PhysicalOffset()));
  EXPECT_EQ(gfx::Point(), scroll->ScrollOrigin());
}

// TODO(crbug.com/340578714): The expectations match the current actual outputs
// which may not be fully correct.
TEST_P(PaintLayerScrollableAreaTest,
       ScrollbarGutterBothEdgesRtlWithHorizontalScrollbar) {
  USE_NON_OVERLAY_SCROLLBARS_OR_QUIT();
  SetBodyInnerHTML(R"HTML(
    <div id="scroll" style="width: 100px; height: 100px; overflow: auto;
                            border: 20px solid blue; padding: 10px;
                            scrollbar-gutter: stable both-edges;
                            direction: rtl">
      <div style="width: 300px"></div>
    </div>
  )HTML");

  auto* scroll = GetLayoutBoxByElementId("scroll")->GetScrollableArea();
  EXPECT_EQ(PhysicalRect(200, 0, 90, 105),
            scroll->LayoutContentRect(kExcludeScrollbars));
  EXPECT_EQ(PhysicalRect(200, 0, 120, 120),
            scroll->LayoutContentRect(kIncludeScrollbars));
  EXPECT_EQ(gfx::Size(320, 105), scroll->ContentsSize());
  EXPECT_EQ(PhysicalRect(-195, 20, 320, 105),
            scroll->GetLayoutBox()->ScrollableOverflowRect());
  EXPECT_EQ(PhysicalRect(20, 20, 120, 105),
            scroll->GetLayoutBox()->OverflowClipRect(PhysicalOffset()));
  EXPECT_EQ(gfx::Point(230, 0), scroll->ScrollOrigin());
}

// TODO(crbug.com/340578714): The expectations match the current actual outputs
// which may not be fully correct.
TEST_P(PaintLayerScrollableAreaTest,
       ScrollbarGutterBothEdgesRtlWithVerticalScrollbar) {
  USE_NON_OVERLAY_SCROLLBARS_OR_QUIT();
  SetBodyInnerHTML(R"HTML(
    <div id="scroll" style="width: 100px; height: 100px; overflow: auto;
                            border: 20px solid blue; padding: 10px;
                            scrollbar-gutter: stable both-edges;
                            direction: rtl">
      <div style="height: 300px"></div>
    </div>
  )HTML");

  auto* scroll = GetLayoutBoxByElementId("scroll")->GetScrollableArea();
  EXPECT_EQ(PhysicalRect(0, 0, 90, 120),
            scroll->LayoutContentRect(kExcludeScrollbars));
  EXPECT_EQ(PhysicalRect(0, 0, 120, 120),
            scroll->LayoutContentRect(kIncludeScrollbars));
  EXPECT_EQ(gfx::Size(90, 320), scroll->ContentsSize());
  EXPECT_EQ(PhysicalRect(35, 20, 90, 320),
            scroll->GetLayoutBox()->ScrollableOverflowRect());
  EXPECT_EQ(PhysicalRect(35, 20, 105, 120),
            scroll->GetLayoutBox()->OverflowClipRect(PhysicalOffset()));
  EXPECT_EQ(gfx::Point(0, 0), scroll->ScrollOrigin());
}

// TODO(crbug.com/340578714): The expectations match the current actual outputs
// which may not be fully correct.
TEST_P(PaintLayerScrollableAreaTest,
       ScrollbarGutterBothEdgesRtlWithBothScrollbars) {
  USE_NON_OVERLAY_SCROLLBARS_OR_QUIT();
  SetBodyInnerHTML(R"HTML(
    <div id="scroll" style="width: 100px; height: 100px; overflow: auto;
                            border: 20px solid blue; padding: 10px;
                            scrollbar-gutter: stable both-edges;
                            direction: rtl">
      <div style="width: 300px; height: 300px"></div>
    </div>
  )HTML");

  auto* scroll = GetLayoutBoxByElementId("scroll")->GetScrollableArea();
  EXPECT_EQ(PhysicalRect(215, 0, 90, 105),
            scroll->LayoutContentRect(kExcludeScrollbars));
  EXPECT_EQ(PhysicalRect(215, 0, 120, 120),
            scroll->LayoutContentRect(kIncludeScrollbars));
  EXPECT_EQ(gfx::Size(320, 320), scroll->ContentsSize());
  EXPECT_EQ(PhysicalRect(-195, 20, 320, 320),
            scroll->GetLayoutBox()->ScrollableOverflowRect());
  EXPECT_EQ(PhysicalRect(35, 20, 105, 105),
            scroll->GetLayoutBox()->OverflowClipRect(PhysicalOffset()));
  EXPECT_EQ(gfx::Point(230, 0), scroll->ScrollOrigin());
}

class PaintLayerScrollableAreaWithWebFrameTest : public ::testing::Test {
 public:
  void SetUp() override { web_view_helper_.Initialize(); }
  void TearDown() override { web_view_helper_.Reset(); }

  Document& GetDocument() {
    return *web_view_helper_.LocalMainFrame()->GetFrame()->GetDocument();
  }

 private:
  test::TaskEnvironment task_environment;
  frame_test_helpers::WebViewHelper web_view_helper_;
};

// This test needs a WebLocalFrame for accurate main thread scrolling reasons.
// Otherwise we'll force main-thread scrolling for reason kPopupNoThreadedInput
// because threaded scrolling is not possible without a WebLocalFrame.
TEST_F(PaintLayerScrollableAreaWithWebFrameTest,
       UpdateShouldAnimateScrollOnMainThread) {
  GetDocument().documentElement()->setInnerHTML(R"HTML(
    <div id="scroller"
         style="width: 100px; height: 100px; background: red; overflow: hidden">
      <div style="height: 2000px"></div>
    </div>
  )HTML");
  GetDocument().View()->UpdateAllLifecyclePhasesForTest();

  auto* scroller = GetDocument().getElementById(AtomicString("scroller"));
  auto* box = scroller->GetLayoutBox();
  auto* scrollable_area = box->GetScrollableArea();
  ASSERT_TRUE(scrollable_area);
  EXPECT_TRUE(scrollable_area->ShouldScrollOnMainThread());
  EXPECT_FALSE(box->FirstFragment().PaintProperties()->Scroll());

  scroller->SetInlineStyleProperty(CSSPropertyID::kOverflow, CSSValueID::kAuto);
  GetDocument().View()->UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(scrollable_area->ShouldScrollOnMainThread());
  EXPECT_TRUE(box->FirstFragment().PaintProperties()->Scroll());

  scroller->SetInlineStyleProperty(CSSPropertyID::kOverflow,
                                   CSSValueID::kHidden);
  GetDocument().View()->UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(scrollable_area->ShouldScrollOnMainThread());
  EXPECT_FALSE(box->FirstFragment().PaintProperties()->Scroll());

  scroller->scrollTo(0, 200);
  GetDocument().View()->UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(scrollable_area->ShouldScrollOnMainThread());
  EXPECT_TRUE(box->FirstFragment().PaintProperties()->Scroll());
}

}  // namespace blink

"""


```