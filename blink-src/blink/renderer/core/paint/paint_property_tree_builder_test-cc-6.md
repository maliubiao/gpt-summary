Response:
The user wants to understand the functionality of the given C++ code file `paint_property_tree_builder_test.cc`. This file is part of the Chromium Blink rendering engine and seems to contain unit tests for the `PaintPropertyTreeBuilder`.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the Core Functionality:** The filename strongly suggests that this file tests the `PaintPropertyTreeBuilder`. This builder is responsible for constructing the paint property tree, which is a crucial data structure in Blink's rendering pipeline.

2. **Analyze the Test Structure:** The code consists of multiple `TEST_P` blocks. Each block focuses on testing a specific aspect of the `PaintPropertyTreeBuilder`. The structure within each `TEST_P` generally involves:
    * Setting up HTML content using `SetBodyInnerHTML`.
    * Optionally getting `LayoutObject` or `PaintProperties` for specific elements.
    * Performing assertions (`EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_FALSE`, etc.) to verify the state of the paint property tree.

3. **Categorize the Tests:** Group the tests based on the features they are verifying. This will make the explanation more organized and easier to understand. Common themes observed include:
    * Transform properties (`transform`, `transform-origin`, `will-change: transform`).
    * Offset properties (`offset-path`, `offset-distance`, `offset-rotate`).
    * Clipping (`overflow`, `mask`, `clip-path`, `border-radius`).
    * Effect properties (`opacity`, `mix-blend-mode`).
    * Scrolling (`overflow: scroll`).
    * Element capture.
    * SVG specific scenarios.
    * Printing.

4. **Explain Each Category with Examples:** For each category, describe the functionality being tested and provide specific examples from the code.
    * **Transforms:** Focus on how `transform` and `transform-origin` create `TransformPaintPropertyNode`s and how `will-change` can influence this. Highlight the difference between applying a transform and just declaring `will-change`.
    * **Offsets:** Explain how motion paths and offset properties create `OffsetPaintPropertyNode`s.
    * **Clipping:** Detail how `overflow`, `mask`, and `border-radius` lead to the creation of `ClipPaintPropertyNode`s. Explain the different types of clipping (overflow, mask, border-radius).
    * **Effects:**  Show how `opacity` and `mix-blend-mode` create `EffectPaintPropertyNode`s.
    * **Scrolling:** Explain how `overflow: scroll` creates `ScrollPaintPropertyNode`s and `ScrollTranslationPaintPropertyNode`s.
    * **Element Capture:**  Describe how `RestrictionTargetId` in combination with stacking context properties leads to `ElementCaptureEffectPaintPropertyNode`s.
    * **SVG:** Highlight tests related to SVG elements, resources (like `<marker>`, `<symbol>`), and blending.
    * **Printing:**  Explain how printing affects the creation of content clips for iframes.

5. **Identify Relationships with Web Technologies:** Connect the tested features to corresponding HTML, CSS, and JavaScript concepts. For example:
    * `transform` and `transform-origin` are CSS properties.
    * `opacity` and `mix-blend-mode` are CSS properties.
    * `overflow` is a CSS property.
    * `mask` and `-webkit-mask-*` are CSS properties.
    * `border-radius` is a CSS property.
    * `offset-path` is a CSS property.
    * `will-change` is a CSS property that hints at potential changes for optimization.
    * JavaScript can manipulate the `style` attribute and trigger these rendering changes.

6. **Illustrate with Input and Output:** For selected tests, provide hypothetical inputs (CSS styles and HTML structure) and the expected outputs (the structure and properties of the paint property tree nodes). This demonstrates the logic being tested.

7. **Point Out Potential User/Programming Errors:**  Think about common mistakes developers might make when using these CSS properties and how the tests might catch these errors. Examples include forgetting units, incorrect syntax, or misunderstandings about how `will-change` works.

8. **Explain the User Journey:** Describe how a user's interaction with a web page could lead to the execution of this code. Focus on actions that trigger layout and paint, such as page load, scrolling, applying CSS styles (through stylesheets or JavaScript), and animations.

9. **Address the "Part 7 of 10" Information:**  Recognize that this is part of a larger test suite and infer that the `PaintPropertyTreeBuilder` is a complex component with many aspects to test. Summarize the specific functionalities covered in this part.

10. **Review and Refine:**  Read through the generated explanation to ensure clarity, accuracy, and completeness. Make sure the examples are easy to understand and the connections to web technologies are clear. Ensure the language is consistent and avoids jargon where possible. For example, initially, I might just say "it tests transform properties". Refining this would lead to "It tests how CSS transform properties like `transform` and `transform-origin` are handled...".
这个文件 `paint_property_tree_builder_test.cc` 是 Chromium Blink 引擎中的一个测试文件，专门用于测试 `PaintPropertyTreeBuilder` 类的功能。`PaintPropertyTreeBuilder` 的作用是根据元素的样式和布局信息构建用于绘制的属性树 (Paint Property Tree)。这个属性树优化了绘制过程，因为它将具有相同绘制属性的元素分组在一起，减少了不必要的绘制操作。

以下是该文件测试的主要功能归纳：

**核心功能：测试 `PaintPropertyTreeBuilder` 构建绘制属性树的正确性**

更具体地说，它测试了在不同 CSS 属性组合下，`PaintPropertyTreeBuilder` 是否能正确创建和连接各种类型的绘制属性节点 (Paint Property Nodes)，例如：

* **TransformPaintPropertyNode:** 处理 CSS `transform` 和 `transform-origin` 属性。
* **EffectPaintPropertyNode:** 处理 CSS `opacity`, `mix-blend-mode` 等影响视觉效果的属性。
* **ClipPaintPropertyNode:** 处理 CSS `overflow`, `clip-path`, `-webkit-mask-*`, `border-radius` 等裁剪相关的属性。
* **ScrollPaintPropertyNode:** 处理 CSS `overflow: scroll` 或 `overflow: auto` 引起的滚动。
* **ScrollTranslationPaintPropertyNode:** 用于表示滚动偏移。
* **OffsetPaintPropertyNode:** 处理 CSS `offset-path` 等路径动画相关的属性。
* **ElementCaptureEffectPaintPropertyNode:**  用于处理元素捕获的特殊效果。

**与 Javascript, HTML, CSS 的关系及举例说明:**

这个测试文件直接关联到 HTML 结构和 CSS 样式如何影响渲染过程。`PaintPropertyTreeBuilder` 读取解析后的样式信息，并根据这些信息构建属性树。JavaScript 可以动态修改 HTML 结构和 CSS 样式，从而间接影响 `PaintPropertyTreeBuilder` 的行为。

* **HTML:** HTML 定义了页面的结构和元素。`SetBodyInnerHTML` 函数用于在测试中创建各种 HTML 结构，例如嵌套的 `div` 元素、带有 ID 的元素等。这些结构是 CSS 样式应用的基础。
    * **例子:** `<div id='translation'></div>`  定义了一个 ID 为 `translation` 的 `div` 元素，后续 CSS 可以针对这个元素应用样式。

* **CSS:** CSS 决定了元素的视觉呈现。测试用例通过内联样式或 `<style>` 标签设置各种 CSS 属性，并验证 `PaintPropertyTreeBuilder` 是否正确地根据这些属性构建了属性树。
    * **例子:**
        * `transform: translate(100px, 200px);`  测试 `TransformPaintPropertyNode` 是否正确记录了平移变换。
        * `opacity: 0.5;` 测试 `EffectPaintPropertyNode` 是否正确记录了透明度。
        * `overflow: hidden;` 测试 `ClipPaintPropertyNode` 是否正确创建并应用裁剪。
        * `-webkit-mask:linear-gradient(red,red);` 测试 `ClipPaintPropertyNode` 和 `MaskPaintPropertyNode` 是否正确创建用于遮罩。

* **Javascript:** 虽然这个测试文件本身不包含 JavaScript 代码，但 JavaScript 可以动态地修改元素的样式和属性，从而触发 `PaintPropertyTreeBuilder` 重新构建属性树。例如，通过 JavaScript 修改元素的 `style` 属性或添加/删除 CSS 类。
    * **例子 (假设的 JavaScript 代码):**
        ```javascript
        document.getElementById('translation').style.transform = 'rotate(45deg)';
        ```
        这个 JavaScript 代码会修改 `translation` 元素的 `transform` 属性，导致 `PaintPropertyTreeBuilder` 在下一次布局和绘制更新时重新构建属性树，并且 `TransformPaintPropertyNode` 的值也会相应改变。

**逻辑推理，假设输入与输出:**

* **假设输入 (HTML & CSS):**
  ```html
  <div id='target' style='transform: scale(2); opacity: 0.8;'>Hello</div>
  ```
* **假设输出 (部分 Paint Property Tree):**
    * 存在一个 `TransformPaintPropertyNode`，其 `Matrix()` 属性表示缩放 2 倍。
    * 存在一个 `EffectPaintPropertyNode`，其 `Opacity()` 属性为 0.8。
    * `EffectPaintPropertyNode` 是 `TransformPaintPropertyNode` 的父节点 (取决于具体的实现细节和优化)。

* **假设输入 (HTML & CSS):**
  ```html
  <div id='container' style='overflow: hidden; width: 100px; height: 100px;'>
    <div id='content' style='width: 200px; height: 200px;'></div>
  </div>
  ```
* **假设输出 (部分 Paint Property Tree):**
    * 存在一个 `ClipPaintPropertyNode` 与 `container` 元素关联，表示其 `overflow: hidden` 属性。
    * 该 `ClipPaintPropertyNode` 的裁剪区域大小为 100x100 像素。
    * `content` 元素的绘制会受到这个 `ClipPaintPropertyNode` 的影响。

**用户或编程常见的使用错误举例:**

* **CSS 属性值错误:** 用户可能会提供无效的 CSS 属性值，例如 `transform: scalex(abc);`。`PaintPropertyTreeBuilder` 应该能够处理这些错误，或者依赖于 CSS 解析器的错误处理。测试可以验证在这些情况下，属性树是否仍然能够正确构建（例如，忽略无效的属性）。
* **对 `will-change` 的误解:** 开发者可能会错误地认为设置 `will-change: transform` 就能立即创建一个合成层。测试用例 `TransformOriginWithAndWithoutTransform` 证明了即使设置了 `will-change: transform`，如果没有实际的 `transform` 属性，也不会创建 `TransformPaintPropertyNode` (或者创建的是 identity 变换)。这有助于开发者理解 `will-change` 只是一个提示，实际的合成层创建还取决于其他因素。
* **遮罩 (mask) 的层叠上下文问题:**  开发者可能不清楚遮罩是如何影响层叠上下文的。测试用例涉及到遮罩的场景可以帮助理解遮罩如何与其他的绘制属性节点交互。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器中加载网页:**  当用户访问一个网页时，浏览器开始解析 HTML、CSS 和 JavaScript。
2. **渲染引擎解析样式:**  Blink 渲染引擎中的 CSS 解析器会解析 CSS 样式，包括外部样式表、`<style>` 标签内的样式以及元素的内联样式。
3. **布局计算:** 渲染引擎根据 HTML 结构和 CSS 样式计算每个元素的位置和大小 (layout)。
4. **构建绘制属性树 (Paint Property Tree Building):** 在布局计算完成后，`PaintPropertyTreeBuilder`  根据元素的样式属性（例如 `transform`, `opacity`, `overflow` 等）构建绘制属性树。这是 `paint_property_tree_builder_test.cc` 测试的核心环节。
5. **绘制 (Painting):** 渲染引擎遍历绘制属性树，根据属性节点的信息执行绘制操作，将网页内容渲染到屏幕上。
6. **合成 (Compositing):** 如果启用了硬件加速合成，渲染引擎会将部分或全部的绘制层上传到 GPU 进行合成，以提高渲染性能。

**作为调试线索:** 如果在渲染过程中出现视觉错误，例如元素没有按照预期的 transform 或 opacity 渲染，开发者可能会怀疑 `PaintPropertyTreeBuilder` 是否正确地构建了属性树。他们可以使用浏览器的开发者工具查看元素的渲染层信息，或者在 Blink 引擎的开发过程中，可以使用像这个测试文件一样的单元测试来验证 `PaintPropertyTreeBuilder` 的正确性。

**第 7 部分的功能归纳:**

这第 7 部分的测试用例主要关注以下 `PaintPropertyTreeBuilder` 的功能：

* **`transform-origin` 的处理:** 测试了在有和没有 `transform` 属性的情况下，`transform-origin` 是否被正确记录和应用。
* **`offset-path` 和 `transform-origin` 的组合:** 测试了 CSS 路径动画属性和 `transform-origin` 的交互，以及 `will-change: transform` 对此的影响。
* **`position` 属性变化对后代节点属性的影响:**  测试了当祖先元素的 `position` 属性改变时，是否会正确更新后代元素的绘制属性（例如，祖先从 `absolute` 变为 `static` 会影响后代元素的裁剪）。
* **未动画的 Transform 和 Effect 节点是否具有 CompositorElementId:** 测试了即使没有动画，应用了 `transform` 或 `opacity` 的元素是否仍然拥有用于合成的 ID。
* **动画的 Transform 和 Effect 节点是否具有 CompositorElementId:** 测试了当 `transform` 或 `opacity` 应用动画时，元素是否拥有用于合成的 ID。
* **浮动元素在行内元素下的属性继承:** 测试了浮动元素如何继承其父级行内元素的 effect 属性。
* **滚动容器的 CompositorElementId:** 测试了滚动容器 (`overflow: auto`) 的不同绘制属性节点是否正确分配了用于合成的 ID。
* **`overflow: hidden` 和亚像素定位:** 测试了当 `overflow: hidden` 的容器定位在亚像素位置时，裁剪区域的计算是否正确。
* **简单的遮罩 (mask) 测试:** 测试了基本的 CSS 遮罩属性是否能正确创建 `MaskPaintPropertyNode` 和 `ClipPaintPropertyNode`。
* **带外延 (outset) 的遮罩测试:** 测试了 `-webkit-mask-box-image-outset` 属性是否能正确调整遮罩的裁剪区域。
* **遮罩的溢出裁剪 (escape clip):** 测试了带有遮罩的绝对定位元素如何逃脱静态定位祖先的滚动，但仍然受到遮罩的裁剪。
* **行内元素的遮罩:** 测试了应用于行内元素的遮罩是否被正确地裁剪到行框 (line box)。
* **SVG 资源 (marker) 的属性树隔离:** 测试了 SVG 的 `<marker>` 元素创建了一个新的绘制属性树，内部的 transform 不会继承外部的 transform。
* **SVG 隐藏资源 (symbol) 的属性树隔离:** 类似于 `<marker>`，测试了 `<symbol>` 元素也创建了独立的绘制属性树。
* **SVG 的混合模式 (blending):** 测试了 SVG 元素上的 `mix-blend-mode` 属性是否能正确创建 `EffectPaintPropertyNode`。
* **SVG 根元素的混合模式:** 测试了 SVG 根元素上的 `mix-blend-mode` 如何影响其自身的 `EffectPaintPropertyNode` 以及与父元素的交互。
* **滚动边界偏移:** 测试了滚动容器的 margin 和 border 如何影响其 `ScrollPaintPropertyNode` 和 `PaintOffsetTranslationPaintPropertyNode`。
* **`backface-visibility: hidden` 的处理:** 测试了 `backface-visibility: hidden` 属性是否能正确创建 `TransformPaintPropertyNode` 并设置其背面可见性。
* **iframe 的 border-radius:** 测试了 `iframe` 元素的 `border-radius` 属性是否能正确创建 `InnerBorderRadiusClipPaintPropertyNode` 和 `ClipPaintPropertyNode`。
* **带有反射的 SVG 文本不创建属性节点:** 测试了带有 `-webkit-box-reflect` 属性的 SVG 文本元素不应该创建绘制属性节点。
* **图片 (img) 的 border-radius:** 测试了 `<img>` 元素的 `border-radius` 属性如何创建 `InnerBorderRadiusClipPaintPropertyNode` 和 `ClipPaintPropertyNode`。
* **打印时的 Frame 裁剪:** 测试了在打印过程中，主 frame 和子 frame 的内容裁剪 (content clip) 是否被正确处理。
* **溢出控制条 (scrollbar) 的裁剪:** 测试了当元素宽度不足以显示滚动条时，是否会创建 `OverflowControlsClipPaintPropertyNode`。
* **亚像素溢出控制条裁剪:** 类似于上一个测试，但关注亚像素宽度的情况。
* **滚动容器下的分栏布局的绘制偏移:** 测试了在滚动容器内使用分栏布局时，不同分栏的绘制偏移是否正确。
* **带有 mask 属性的 SVG 根元素:** 测试了 SVG 根元素使用 HTML 的 `mask` 属性是否能正确创建 `MaskPaintPropertyNode`。
* **带有 CSS mask 属性的 SVG 根元素:** 测试了 SVG 根元素使用 CSS 的 `-webkit-mask-image` 属性是否能正确创建 `MaskPaintPropertyNode`。
* **元素捕获 Effect 节点:** 测试了当元素具有 restriction ID 并且是一个层叠上下文时，是否会创建 `ElementCaptureEffectPaintPropertyNode`。
* **清除 ClipPath Effect 节点:** 测试了当移除 `clip-path` 属性时，是否会正确清除相关的 `ClipPathMaskPaintPropertyNode`。

总而言之，这部分测试着重验证了 `PaintPropertyTreeBuilder` 在处理各种复杂的 CSS 属性组合以及特定场景（例如 SVG 和 iframe）时的正确性和健壮性，确保渲染引擎能够准确地构建用于高效绘制的属性树。

Prompt: 
```
这是目录为blink/renderer/core/paint/paint_property_tree_builder_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第7部分，共10部分，请归纳一下它的功能

"""
d_paint_state.Effect());
}

TEST_P(PaintPropertyTreeBuilderTest, TransformOriginWithAndWithoutTransform) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin: 0 }
      div {
        width: 400px;
        height: 100px;
      }
      #translation {
        transform: translate(100px, 200px);
        transform-origin: 75% 75% 0;
      }
      #scale {
        transform: scale(2);
        transform-origin: 75% 75% 0;
      }
      #willChange {
        will-change: transform;
        transform-origin: 75% 75% 0;
      }
    </style>
    <div id='translation'></div>
    <div id='scale'></div>
    <div id='willChange'></div>
  )HTML");

  auto* translation = PaintPropertiesForElement("translation")->Transform();
  EXPECT_EQ(gfx::Vector2dF(100, 200), translation->Get2dTranslation());
  EXPECT_EQ(gfx::Point3F(300, 75, 0), translation->Origin());

  auto* scale = PaintPropertiesForElement("scale")->Transform();
  EXPECT_EQ(MakeScaleMatrix(2), scale->Matrix());
  EXPECT_EQ(gfx::Point3F(300, 75, 0), scale->Origin());

  auto* will_change = PaintPropertiesForElement("willChange")->Transform();
  EXPECT_TRUE(will_change->IsIdentity());
  EXPECT_EQ(gfx::Point3F(), will_change->Origin());
}

TEST_P(PaintPropertyTreeBuilderTest, TransformOriginWithAndWithoutMotionPath) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin: 0 }
      div {
        width: 100px;
        height: 100px;
      }
      #motionPath {
        position: absolute;
        offset-path: path('M0 0 L 200 400');
        offset-distance: 50%;
        offset-rotate: 0deg;
        transform-origin: 50% 50% 0;
      }
      #willChange {
        will-change: transform;
        transform-origin: 50% 50% 0;
      }
    </style>
    <div id='motionPath'></div>
    <div id='willChange'></div>
  )HTML");

  auto* motion_path = GetLayoutObjectByElementId("motionPath");
  auto* motion_path_properties = motion_path->FirstFragment().PaintProperties();
  EXPECT_EQ(motion_path_properties->Transform(), nullptr);
  EXPECT_EQ(gfx::Vector2dF(50, 150),
            motion_path_properties->Offset()->Get2dTranslation());
  EXPECT_EQ(gfx::Point3F(50, 50, 0),
            motion_path_properties->Offset()->Origin());

  auto* will_change = GetLayoutObjectByElementId("willChange");
  auto* will_change_properties = will_change->FirstFragment().PaintProperties();
  EXPECT_EQ(will_change_properties->Offset(), nullptr);
  EXPECT_TRUE(will_change_properties->Transform()->IsIdentity());
  EXPECT_EQ(gfx::Point3F(), will_change_properties->Transform()->Origin());
}

TEST_P(PaintPropertyTreeBuilderTest, ChangePositionUpdateDescendantProperties) {
  SetBodyInnerHTML(R"HTML(
    <style>
      * { margin: 0; }
      #ancestor { position: absolute; overflow: hidden }
      #descendant { position: absolute }
    </style>
    <div id='ancestor'>
      <div id='descendant'></div>
    </div>
  )HTML");

  LayoutObject* ancestor = GetLayoutObjectByElementId("ancestor");
  LayoutObject* descendant = GetLayoutObjectByElementId("descendant");
  EXPECT_EQ(ancestor->FirstFragment().PaintProperties()->OverflowClip(),
            &descendant->FirstFragment().LocalBorderBoxProperties().Clip());

  To<Element>(ancestor->GetNode())
      ->setAttribute(html_names::kStyleAttr, AtomicString("position: static"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_NE(ancestor->FirstFragment().PaintProperties()->OverflowClip(),
            &descendant->FirstFragment().LocalBorderBoxProperties().Clip());
}

TEST_P(PaintPropertyTreeBuilderTest,
       TransformNodeNotAnimatedStillHasCompositorElementId) {
  SetBodyInnerHTML("<div id='target' style='transform: translateX(2em)'></div");
  const ObjectPaintProperties* properties = PaintPropertiesForElement("target");
  EXPECT_TRUE(properties->Transform());
  EXPECT_NE(CompositorElementId(),
            properties->Transform()->GetCompositorElementId());
}

TEST_P(PaintPropertyTreeBuilderTest,
       EffectNodeNotAnimatedStillHasCompositorElementId) {
  SetBodyInnerHTML("<div id='target' style='opacity: 0.5'></div");
  const ObjectPaintProperties* properties = PaintPropertiesForElement("target");
  EXPECT_TRUE(properties->Effect());
  // TODO(flackr): Revisit whether effect ElementId should still exist when
  // animations are no longer keyed off of the existence it:
  // https://crbug.com/900241
  EXPECT_NE(CompositorElementId(),
            properties->Effect()->GetCompositorElementId());
}

TEST_P(PaintPropertyTreeBuilderTest,
       TransformNodeAnimatedHasCompositorElementId) {
  LoadTestData("transform-animation.html");
  const ObjectPaintProperties* properties = PaintPropertiesForElement("target");
  EXPECT_TRUE(properties->Transform());
  EXPECT_NE(CompositorElementId(),
            properties->Transform()->GetCompositorElementId());
  EXPECT_TRUE(properties->Transform()->HasActiveTransformAnimation());
}

TEST_P(PaintPropertyTreeBuilderTest, EffectNodeAnimatedHasCompositorElementId) {
  LoadTestData("opacity-animation.html");
  const ObjectPaintProperties* properties = PaintPropertiesForElement("target");
  EXPECT_TRUE(properties->Effect());
  EXPECT_NE(CompositorElementId(),
            properties->Effect()->GetCompositorElementId());
  EXPECT_TRUE(properties->Effect()->HasActiveOpacityAnimation());
}

TEST_P(PaintPropertyTreeBuilderTest, FloatUnderInline) {
  SetBodyInnerHTML(R"HTML(
    <div style='position: absolute; top: 55px; left: 66px'>
      <span id='span'
          style='position: relative; top: 100px; left: 200px; opacity: 0.5'>
        <div id='target'
             style='overflow: hidden; float: left; width: 3px; height: 4px'>
        </div>
      </span>
    </div>
  )HTML");

  LayoutObject* span = GetLayoutObjectByElementId("span");
  const auto* effect = span->FirstFragment().PaintProperties()->Effect();
  ASSERT_TRUE(effect);
  EXPECT_EQ(0.5f, effect->Opacity());

  LayoutObject* target = GetLayoutObjectByElementId("target");
  EXPECT_EQ(PhysicalOffset(266, 155), target->FirstFragment().PaintOffset());
  EXPECT_EQ(effect,
            &target->FirstFragment().LocalBorderBoxProperties().Effect());
}

TEST_P(PaintPropertyTreeBuilderTest, ScrollNodeHasCompositorElementId) {
  SetBodyInnerHTML(R"HTML(
    <div id='target' style='overflow: auto; width: 100px; height: 100px'>
      <div style='width: 200px; height: 200px'></div>
    </div>
  )HTML");

  const ObjectPaintProperties* properties = PaintPropertiesForElement("target");
  // The scroll translation node should not have the element id as it should be
  // stored directly on the ScrollNode.
  EXPECT_EQ(CompositorElementId(),
            properties->ScrollTranslation()->GetCompositorElementId());
  EXPECT_NE(CompositorElementId(),
            properties->Scroll()->GetCompositorElementId());
}

TEST_P(PaintPropertyTreeBuilderTest, OverflowClipSubpixelPosition) {
  SetBodyInnerHTML(R"HTML(
    <style>body { margin: 20px 30px; }</style>
    <div id='clipper'
        style='position: relative; overflow: hidden;
               width: 400px; height: 300px; left: 1.5px'>
      <div style='width: 1000px; height: 1000px'></div>
    </div>
  )HTML");

  auto* clipper =
      To<LayoutBoxModelObject>(GetLayoutObjectByElementId("clipper"));
  const ObjectPaintProperties* clip_properties =
      clipper->FirstFragment().PaintProperties();

  EXPECT_EQ(PhysicalOffset(LayoutUnit(31.5), LayoutUnit(20)),
            clipper->FirstFragment().PaintOffset());
  // Result is pixel-snapped.
  EXPECT_EQ(FloatClipRect(gfx::RectF(31.5, 20, 400, 300)),
            clip_properties->OverflowClip()->LayoutClipRect());
  EXPECT_EQ(FloatRoundedRect(32, 20, 400, 300),
            clip_properties->OverflowClip()->PaintClipRect());
}

TEST_P(PaintPropertyTreeBuilderTest, MaskSimple) {
  SetBodyInnerHTML(R"HTML(
    <div id='target' style='width:300px; height:200.5px;
        -webkit-mask:linear-gradient(red,red)'>
      Lorem ipsum
    </div>
  )HTML");

  const ObjectPaintProperties* properties = PaintPropertiesForElement("target");
  const ClipPaintPropertyNode* mask_clip = properties->MaskClip();

  const auto* target = GetLayoutObjectByElementId("target");
  EXPECT_EQ(mask_clip,
            &target->FirstFragment().LocalBorderBoxProperties().Clip());
  EXPECT_EQ(DocContentClip(), mask_clip->Parent());
  EXPECT_EQ(FloatClipRect(gfx::RectF(8, 8, 300, 200.5)),
            mask_clip->LayoutClipRect());
  EXPECT_EQ(FloatRoundedRect(8, 8, 300, 201), mask_clip->PaintClipRect());

  EXPECT_EQ(properties->Effect(),
            &target->FirstFragment().LocalBorderBoxProperties().Effect());
  EXPECT_TRUE(DocEffect());
  EXPECT_EQ(SkBlendMode::kSrcOver, properties->Effect()->BlendMode());
  EXPECT_EQ(mask_clip->Parent(), properties->Effect()->OutputClip());

  EXPECT_EQ(properties->Effect(), properties->Mask()->Parent());
  EXPECT_EQ(SkBlendMode::kDstIn, properties->Mask()->BlendMode());
  EXPECT_EQ(mask_clip->Parent(), properties->Mask()->OutputClip());
}

TEST_P(PaintPropertyTreeBuilderTest, MaskWithOutset) {
  SetBodyInnerHTML(R"HTML(
    <div id='target' style='width:300px; height:200px;
        -webkit-mask-box-image-source:linear-gradient(red,red);
        -webkit-mask-box-image-outset:10px 20px;'>
      Lorem ipsum
    </div>
  )HTML");

  const ObjectPaintProperties* properties = PaintPropertiesForElement("target");
  const ClipPaintPropertyNode* mask_clip = properties->MaskClip();

  const auto* target = GetLayoutObjectByElementId("target");
  EXPECT_EQ(mask_clip,
            &target->FirstFragment().LocalBorderBoxProperties().Clip());
  EXPECT_EQ(DocContentClip(), mask_clip->Parent());
  EXPECT_CLIP_RECT(FloatRoundedRect(-12, -2, 340, 220), mask_clip);

  EXPECT_EQ(properties->Effect(),
            &target->FirstFragment().LocalBorderBoxProperties().Effect());
  EXPECT_TRUE(DocEffect());
  EXPECT_EQ(SkBlendMode::kSrcOver, properties->Effect()->BlendMode());
  EXPECT_EQ(mask_clip->Parent(), properties->Effect()->OutputClip());

  EXPECT_EQ(properties->Effect(), properties->Mask()->Parent());
  EXPECT_EQ(SkBlendMode::kDstIn, properties->Mask()->BlendMode());
  EXPECT_EQ(mask_clip->Parent(), properties->Mask()->OutputClip());
}

TEST_P(PaintPropertyTreeBuilderTest, MaskEscapeClip) {
  // This test verifies an abs-pos element still escape the scroll of a
  // static-pos ancestor, but gets clipped due to the presence of a mask.
  SetBodyInnerHTML(R"HTML(
    <div id='scroll' style='width:300px; height:200px; overflow:scroll;'>
      <div id='target' style='width:200px; height:300px;
          -webkit-mask:linear-gradient(red,red); border:10px dashed black;
          overflow:hidden;'>
        <div id='absolute' style='position:absolute; left:0; top:0;'>
          Lorem ipsum
        </div>
      </div>
    </div>
  )HTML");

  const ObjectPaintProperties* target_properties =
      PaintPropertiesForElement("target");
  const auto* overflow_clip1 = target_properties->MaskClip()->Parent();
  const auto* mask_clip = target_properties->MaskClip();
  const auto* overflow_clip2 = target_properties->OverflowClip();
  const auto* target = GetLayoutObjectByElementId("target");
  const auto& scroll_translation =
      target->FirstFragment().LocalBorderBoxProperties().Transform();

  const ObjectPaintProperties* scroll_properties =
      PaintPropertiesForElement("scroll");

  EXPECT_EQ(DocContentClip(), overflow_clip1->Parent());
  EXPECT_CLIP_RECT(FloatRoundedRect(0, 0, 300, 200),
                   &ToUnaliased(*overflow_clip1));
  EXPECT_EQ(scroll_properties->PaintOffsetTranslation(),
            &ToUnaliased(*overflow_clip1).LocalTransformSpace());

  EXPECT_EQ(mask_clip,
            &target->FirstFragment().LocalBorderBoxProperties().Clip());
  EXPECT_EQ(overflow_clip1, mask_clip->Parent());
  EXPECT_CLIP_RECT(FloatRoundedRect(0, 0, 220, 320), mask_clip);
  EXPECT_EQ(&scroll_translation, &mask_clip->LocalTransformSpace());

  EXPECT_EQ(mask_clip, overflow_clip2->Parent());
  EXPECT_CLIP_RECT(FloatRoundedRect(10, 10, 200, 300), overflow_clip2);
  EXPECT_EQ(&scroll_translation, &overflow_clip2->LocalTransformSpace());

  EXPECT_EQ(target_properties->Effect(),
            &target->FirstFragment().LocalBorderBoxProperties().Effect());
  EXPECT_TRUE(DocEffect());
  EXPECT_EQ(SkBlendMode::kSrcOver, target_properties->Effect()->BlendMode());
  EXPECT_EQ(nullptr, target_properties->Effect()->OutputClip());

  EXPECT_EQ(target_properties->Effect(), target_properties->Mask()->Parent());
  EXPECT_EQ(SkBlendMode::kDstIn, target_properties->Mask()->BlendMode());
  EXPECT_EQ(mask_clip->Parent(), target_properties->Mask()->OutputClip());

  const auto* absolute = GetLayoutObjectByElementId("absolute");
  EXPECT_EQ(DocScrollTranslation(),
            &absolute->FirstFragment().LocalBorderBoxProperties().Transform());
  EXPECT_EQ(mask_clip,
            &absolute->FirstFragment().LocalBorderBoxProperties().Clip());
}

TEST_P(PaintPropertyTreeBuilderTest, MaskInline) {
  LoadAhem();
  // This test verifies CSS mask applied on an inline element is clipped to
  // the line box of the said element. In this test the masked element has
  // only one box, and one of the child element overflows the box.
  SetBodyInnerHTML(R"HTML(
    <style>* { font-family:Ahem; font-size:16px; }</style>
    Lorem
    <span id='target' style='-webkit-mask:linear-gradient(red,red);'>
      ipsum
      <span id='overflowing' style='position:relative; font-size:32px;'>
        dolor
      </span>
      sit amet,
    </span>
  )HTML");

  const ObjectPaintProperties* properties = PaintPropertiesForElement("target");
  const ClipPaintPropertyNode* mask_clip = properties->MaskClip();
  const auto* target = GetLayoutObjectByElementId("target");

  EXPECT_EQ(mask_clip,
            &target->FirstFragment().LocalBorderBoxProperties().Clip());
  EXPECT_EQ(DocContentClip(), mask_clip->Parent());
  EXPECT_CLIP_RECT(FloatRoundedRect(104, 21, 432, 16), mask_clip);

  EXPECT_EQ(properties->Effect(),
            &target->FirstFragment().LocalBorderBoxProperties().Effect());
  EXPECT_TRUE(DocEffect());
  EXPECT_EQ(SkBlendMode::kSrcOver, properties->Effect()->BlendMode());
  EXPECT_EQ(mask_clip->Parent(), properties->Effect()->OutputClip());

  EXPECT_EQ(properties->Effect(), properties->Mask()->Parent());
  EXPECT_EQ(SkBlendMode::kDstIn, properties->Mask()->BlendMode());
  EXPECT_EQ(mask_clip->Parent(), properties->Mask()->OutputClip());

  const auto* overflowing = GetLayoutObjectByElementId("overflowing");
  EXPECT_EQ(mask_clip,
            &overflowing->FirstFragment().LocalBorderBoxProperties().Clip());
  EXPECT_EQ(properties->Effect(),
            &overflowing->FirstFragment().LocalBorderBoxProperties().Effect());
}

TEST_P(PaintPropertyTreeBuilderTest, SVGResource) {
  SetBodyInnerHTML(R"HTML(
    <svg id='svg' xmlns='http://www.w3.org/2000/svg' >
     <g transform='scale(1000)'>
       <marker id='markerMiddle'  markerWidth='2' markerHeight='2' refX='5'
           refY='5' markerUnits='strokeWidth'>
         <g id='transformInsideMarker' transform='scale(4)'>
           <circle cx='5' cy='5' r='7' fill='green'/>
         </g>
       </marker>
     </g>
     <g id='transformOutsidePath' transform='scale(2)'>
       <path d='M 130 135 L 180 135 L 180 185'
           marker-mid='url(#markerMiddle)' fill='none' stroke-width='8px'
           stroke='black'/>
     </g>
    </svg>
  )HTML");

  const ObjectPaintProperties* transform_inside_marker_properties =
      PaintPropertiesForElement("transformInsideMarker");
  const ObjectPaintProperties* transform_outside_path_properties =
      PaintPropertiesForElement("transformOutsidePath");
  const ObjectPaintProperties* svg_properties =
      PaintPropertiesForElement("svg");

  // The <marker> object resets to a new paint property tree, so the
  // transform within it should have the root as parent.
  EXPECT_EQ(&TransformPaintPropertyNode::Root(),
            transform_inside_marker_properties->Transform()->Parent());

  // Whereas this is not true of the transform above the path.
  EXPECT_EQ(svg_properties->PaintOffsetTranslation(),
            transform_outside_path_properties->Transform()->Parent());
}

TEST_P(PaintPropertyTreeBuilderTest, SVGHiddenResource) {
  SetBodyInnerHTML(R"HTML(
    <svg id='svg' xmlns='http://www.w3.org/2000/svg' >
     <g transform='scale(1000)'>
       <symbol id='symbol'>
         <g id='transformInsideSymbol' transform='scale(4)'>
           <circle cx='5' cy='5' r='7' fill='green'/>
         </g>
       </symbol>
     </g>
     <g id='transformOutsideUse' transform='scale(2)'>
       <use x='25' y='25' width='400' height='400' xlink:href='#symbol'/>
     </g>
    </svg>
  )HTML");

  const ObjectPaintProperties* transform_inside_symbol_properties =
      PaintPropertiesForElement("transformInsideSymbol");
  const ObjectPaintProperties* transform_outside_use_properties =
      PaintPropertiesForElement("transformOutsideUse");
  const ObjectPaintProperties* svg_properties =
      PaintPropertiesForElement("svg");

  // The <marker> object resets to a new paint property tree, so the
  // transform within it should have the root as parent.
  EXPECT_EQ(&TransformPaintPropertyNode::Root(),
            transform_inside_symbol_properties->Transform()->Parent());

  // Whereas this is not true of the transform above the path.
  EXPECT_EQ(svg_properties->PaintOffsetTranslation(),
            transform_outside_use_properties->Transform()->Parent());
}

TEST_P(PaintPropertyTreeBuilderTest, SVGBlending) {
  SetBodyInnerHTML(R"HTML(
    <svg id='svgroot' width='100' height='100'
        style='position: relative; z-index: 0'>
      <rect id='rect' width='100' height='100' fill='#00FF00'
          style='mix-blend-mode: difference'/>
    </svg>
  )HTML");

  const auto* rect_properties = PaintPropertiesForElement("rect");
  ASSERT_TRUE(rect_properties->Effect());
  EXPECT_EQ(SkBlendMode::kDifference, rect_properties->Effect()->BlendMode());

  const auto* svg_root_properties = PaintPropertiesForElement("svgroot");
  ASSERT_TRUE(svg_root_properties->Effect());
  EXPECT_EQ(SkBlendMode::kSrcOver, svg_root_properties->Effect()->BlendMode());

  EXPECT_EQ(DocEffect(), svg_root_properties->Effect()->Parent());
  EXPECT_EQ(svg_root_properties->Effect(), rect_properties->Effect()->Parent());
}

TEST_P(PaintPropertyTreeBuilderTest, SVGRootBlending) {
  SetBodyInnerHTML(R"HTML(
    <svg id='svgroot' 'width=100' height='100' style='mix-blend-mode: multiply'>
    </svg>
  )HTML");

  const auto* html_properties = GetDocument()
                                    .documentElement()
                                    ->GetLayoutObject()
                                    ->FirstFragment()
                                    .PaintProperties();
  ASSERT_TRUE(html_properties->Effect());
  EXPECT_EQ(SkBlendMode::kSrcOver, html_properties->Effect()->BlendMode());

  const auto* svg_root_properties = PaintPropertiesForElement("svgroot");
  ASSERT_TRUE(svg_root_properties->Effect());
  EXPECT_EQ(SkBlendMode::kMultiply, svg_root_properties->Effect()->BlendMode());

  EXPECT_EQ(DocEffect(), html_properties->Effect()->Parent());
  EXPECT_EQ(html_properties->Effect(), svg_root_properties->Effect()->Parent());
}

TEST_P(PaintPropertyTreeBuilderTest, ScrollBoundsOffset) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body {
        margin: 0px;
      }
      #scroller {
        overflow-y: scroll;
        width: 100px;
        height: 100px;
        margin-left: 7px;
        margin-top: 11px;
      }
      .forceScroll {
        height: 200px;
      }
    </style>
    <div id='scroller'>
      <div class='forceScroll'></div>
    </div>
  )HTML");

  Element* scroller = GetDocument().getElementById(AtomicString("scroller"));
  scroller->setScrollTop(42);

  UpdateAllLifecyclePhasesForTest();

  const ObjectPaintProperties* scroll_properties =
      scroller->GetLayoutObject()->FirstFragment().PaintProperties();
  // Because the frameView is does not scroll, overflowHidden's scroll should be
  // under the root.
  auto* scroll_translation = scroll_properties->ScrollTranslation();
  auto* paint_offset_translation = scroll_properties->PaintOffsetTranslation();
  auto* scroll_node = scroll_translation->ScrollNode();
  EXPECT_EQ(DocScroll(), scroll_node->Parent());
  EXPECT_EQ(gfx::Vector2dF(0, -42), scroll_translation->Get2dTranslation());
  // The paint offset node should be offset by the margin.
  EXPECT_EQ(gfx::Vector2dF(7, 11),
            paint_offset_translation->Get2dTranslation());
  // And the scroll node should not.
  EXPECT_EQ(gfx::Rect(0, 0, 100, 100), scroll_node->ContainerRect());

  scroller->setAttribute(html_names::kStyleAttr,
                         AtomicString("border: 20px solid black;"));
  UpdateAllLifecyclePhasesForTest();
  // The paint offset node should be offset by the margin.
  EXPECT_EQ(gfx::Vector2dF(7, 11),
            paint_offset_translation->Get2dTranslation());
  // The scroll node should be offset by the border.
  EXPECT_EQ(gfx::Rect(20, 20, 100, 100), scroll_node->ContainerRect());

  scroller->setAttribute(html_names::kStyleAttr,
                         AtomicString("border: 20px solid black;"
                                      "transform: translate(20px, 30px);"));
  UpdateAllLifecyclePhasesForTest();
  // The scroll node's offset should not include margin if it has already been
  // included in a paint offset node.
  EXPECT_EQ(gfx::Rect(20, 20, 100, 100), scroll_node->ContainerRect());
  EXPECT_EQ(gfx::Vector2dF(7, 11),
            scroll_properties->PaintOffsetTranslation()->Get2dTranslation());
}

TEST_P(PaintPropertyTreeBuilderTest, BackfaceHidden) {
  SetBodyInnerHTML(R"HTML(
    <style>#target { position: absolute; top: 50px; left: 60px }</style>
    <div id='target' style='backface-visibility: hidden'></div>
  )HTML");

  const auto* target = GetLayoutObjectByElementId("target");
  const auto* target_properties = target->FirstFragment().PaintProperties();
  ASSERT_NE(nullptr, target_properties);
  const auto* paint_offset_translation =
      target_properties->PaintOffsetTranslation();
  ASSERT_NE(nullptr, paint_offset_translation);
  EXPECT_EQ(gfx::Vector2dF(60, 50),
            paint_offset_translation->Get2dTranslation());
  EXPECT_EQ(TransformPaintPropertyNode::BackfaceVisibility::kInherited,
            paint_offset_translation->GetBackfaceVisibilityForTesting());

  const auto* transform = target_properties->Transform();
  ASSERT_NE(nullptr, transform);
  EXPECT_TRUE(transform->IsIdentity());
  EXPECT_EQ(TransformPaintPropertyNode::BackfaceVisibility::kHidden,
            transform->GetBackfaceVisibilityForTesting());

  To<Element>(target->GetNode())
      ->setAttribute(html_names::kStyleAttr, g_empty_atom);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(PhysicalOffset(60, 50), target->FirstFragment().PaintOffset());
  EXPECT_EQ(nullptr, target->FirstFragment().PaintProperties());
}

TEST_P(PaintPropertyTreeBuilderTest, FrameBorderRadius) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #iframe {
        width: 200px;
        height: 200px;
        border: 10px solid blue;
        border-radius: 50px;
        padding: 10px;
        overflow: visible;
      }
    </style>
    <iframe id='iframe'></iframe>
  )HTML");

  const auto* properties = PaintPropertiesForElement("iframe");
  ASSERT_NE(nullptr, properties);
  const auto* border_radius_clip = properties->InnerBorderRadiusClip();
  ASSERT_NE(nullptr, border_radius_clip);
  EXPECT_CLIP_RECT(FloatRoundedRect(gfx::RectF(28, 28, 200, 200),
                                    FloatRoundedRect::Radii(30)),
                   border_radius_clip);
  auto* overflow_clip = properties->OverflowClip();
  EXPECT_CLIP_RECT(FloatRoundedRect(28, 28, 200, 200), overflow_clip);
  EXPECT_EQ(overflow_clip->Parent(), border_radius_clip);
  EXPECT_EQ(DocContentClip(), border_radius_clip->Parent());
  EXPECT_EQ(DocScrollTranslation(), &border_radius_clip->LocalTransformSpace());
}

TEST_P(PaintPropertyTreeBuilderTest, NoPropertyForSVGTextWithReflection) {
  SetBodyInnerHTML(R"HTML(
    <svg>
      <text id='target' style='-webkit-box-reflect: below 2px'>x</text>
    </svg>
  )HTML");
  EXPECT_FALSE(PaintPropertiesForElement("target"));
}

TEST_P(PaintPropertyTreeBuilderTest, ImageBorderRadius) {
  SetBodyInnerHTML(R"HTML(
    <img id='img'
        style='width: 50px; height: 50px; border-radius: 30px; padding: 10px'>
  )HTML");

  const auto* properties = PaintPropertiesForElement("img");
  const auto* overflow_clip = properties->OverflowClip();
  ASSERT_NE(nullptr, overflow_clip);
  EXPECT_CLIP_RECT(
      FloatRoundedRect(gfx::RectF(18, 18, 50, 50), FloatRoundedRect::Radii(0)),
      overflow_clip);
  EXPECT_EQ(properties->InnerBorderRadiusClip(), overflow_clip->Parent());
  EXPECT_EQ(DocScrollTranslation(), &overflow_clip->LocalTransformSpace());

  const auto* border_radius_clip = properties->InnerBorderRadiusClip();
  ASSERT_NE(nullptr, border_radius_clip);
  EXPECT_EQ(DocContentClip(), border_radius_clip->Parent());
  EXPECT_CLIP_RECT(
      FloatRoundedRect(gfx::RectF(18, 18, 50, 50), FloatRoundedRect::Radii(20)),
      border_radius_clip);
}

TEST_P(PaintPropertyTreeBuilderTest, FrameClipWhenPrinting) {
  SetBodyInnerHTML("<iframe></iframe>");
  SetChildFrameHTML("");
  UpdateAllLifecyclePhasesForTest();

  // When not printing, both main and child frame views have content clip.
  auto* const main_frame_doc = &GetDocument();
  auto* const child_frame_doc = &ChildDocument();
  EXPECT_CLIP_RECT(gfx::RectF(0, 0, 800, 600), DocContentClip(main_frame_doc));
  EXPECT_CLIP_RECT(gfx::RectF(0, 0, 300, 150), DocContentClip(child_frame_doc));

  // When the main frame is printing, it should not have content clip.
  gfx::SizeF page_size(100, 100);
  GetFrame().StartPrinting(WebPrintParams(page_size));
  GetDocument().View()->UpdateLifecyclePhasesForPrinting();
  EXPECT_EQ(nullptr, DocContentClip(main_frame_doc));
  EXPECT_CLIP_RECT(gfx::RectF(0, 0, 300, 150), DocContentClip(child_frame_doc));

  GetFrame().EndPrinting();
  UpdateAllLifecyclePhasesForTest();

  // When only the child frame is printing, it should not have content clip but
  // the main frame still have (which doesn't matter though).
  ChildFrame().StartPrinting(WebPrintParams(page_size));
  GetDocument().View()->UpdateLifecyclePhasesForPrinting();
  ASSERT_NE(nullptr, DocContentClip(main_frame_doc));
  EXPECT_CLIP_RECT(gfx::RectF(0, 0, 800, 600), DocContentClip(main_frame_doc));
  EXPECT_EQ(nullptr, DocContentClip(child_frame_doc));
}

TEST_P(PaintPropertyTreeBuilderTest, OverflowControlsClip) {
  SetBodyInnerHTML(R"HTML(
    <style>::-webkit-scrollbar { width: 20px }</style>
    <div id='div1' style='overflow: scroll; width: 5px; height: 50px'></div>
    <div id='div2' style='overflow: scroll; width: 50px; height: 50px'></div>
  )HTML");

  const auto* properties1 = PaintPropertiesForElement("div1");
  ASSERT_NE(nullptr, properties1);
  const auto* overflow_controls_clip = properties1->OverflowControlsClip();
  EXPECT_CLIP_RECT(gfx::RectF(0, 0, 5, 50), overflow_controls_clip);

  const auto* properties2 = PaintPropertiesForElement("div2");
  ASSERT_NE(nullptr, properties2);
  EXPECT_EQ(nullptr, properties2->OverflowControlsClip());
}

TEST_P(PaintPropertyTreeBuilderTest, OverflowControlsClipSubpixel) {
  SetBodyInnerHTML(R"HTML(
    <style>::-webkit-scrollbar { width: 20px }</style>
    <div id='div1' style='overflow: scroll; width: 5.5px; height: 50px'></div>
    <div id='div2' style='overflow: scroll; width: 50.5px; height: 50px'></div>
  )HTML");

  const auto* properties1 = PaintPropertiesForElement("div1");
  ASSERT_NE(nullptr, properties1);
  const auto* overflow_controls_clip = properties1->OverflowControlsClip();
  EXPECT_EQ(FloatClipRect(gfx::RectF(0, 0, 5.5, 50)),
            overflow_controls_clip->LayoutClipRect());
  EXPECT_EQ(FloatRoundedRect(0, 0, 6, 50),
            overflow_controls_clip->PaintClipRect());

  const auto* properties2 = PaintPropertiesForElement("div2");
  ASSERT_NE(nullptr, properties2);
  EXPECT_EQ(nullptr, properties2->OverflowControlsClip());
}

TEST_P(PaintPropertyTreeBuilderTest, FragmentPaintOffsetUnderOverflowScroll) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin: 0 }
      ::-webkit-scrollbar { width: 20px }
    </style>
    <div id='container' style='margin-top: 50px; overflow-y: scroll'>
      <div style='columns: 2; height: 40px; column-gap: 0'>
        <div id='content' style='width: 20px; height: 20px'>TEST</div>
      </div>
    </div>
  )HTML");

  // container establishes paint_offset_root because it has scrollbar.
  EXPECT_NE(nullptr,
            PaintPropertiesForElement("container")->PaintOffsetTranslation());

  const auto* content = GetLayoutObjectByElementId("content");
  FragmentDataIterator iterator(*content);
  const auto* first_fragment = iterator.GetFragmentData();
  ASSERT_TRUE(iterator.Advance());
  const auto* second_fragment = iterator.GetFragmentData();
  ASSERT_NE(nullptr, second_fragment);

  EXPECT_EQ(PhysicalOffset(), first_fragment->PaintOffset());
  EXPECT_EQ(PhysicalOffset(390, 0), second_fragment->PaintOffset());
}

TEST_P(PaintPropertyTreeBuilderTest, SVGRootWithMask) {
  SetBodyInnerHTML(R"HTML(
    <svg id="svg" width="16" height="16" mask="url(#test)">
      <rect width="100%" height="16" fill="#fff"></rect>
      <defs>
        <mask id="test">
          <g>
            <rect width="100%" height="100%" fill="#ffffff" style=""></rect>
          </g>
        </mask>
      </defs>
    </svg>
  )HTML");

  const auto& root = *To<LayoutSVGRoot>(GetLayoutObjectByElementId("svg"));
  EXPECT_TRUE(root.FirstFragment().PaintProperties()->Mask());
}

TEST_P(PaintPropertyTreeBuilderTest, SVGRootWithCSSMask) {
  SetBodyInnerHTML(R"HTML(
    <svg id="svg" width="16" height="16" style="-webkit-mask-image: url(fake);">
    </svg>
  )HTML");

  const auto& root = *To<LayoutSVGRoot>(GetLayoutObjectByElementId("svg"));
  EXPECT_TRUE(root.FirstFragment().PaintProperties()->Mask());
}

TEST_P(PaintPropertyTreeBuilderTest, ElementCaptureEffectNode) {
  ScopedElementCaptureForTest scoped_element_capture(true);

  // This test makes sure that an ElementCaptureEffect node is properly added
  // when an element has a restriction ID.
  SetBodyInnerHTML(R"HTML(
     <style>
      .stacking {
        opacity: 0.9;
      }
    </style>
    <body id="body1">
      <div id="div1" width="640" height="480"/>
    </body>
  )HTML");

  Element* element = GetDocument().getElementById(AtomicString("div1"));
  ASSERT_TRUE(element);

  // As a plain div, the element shouldn't have a separate stacking context.
  EXPECT_FALSE(element->GetLayoutObject()->HasLayer());
  EXPECT_FALSE(element->GetLayoutObject()->IsStackingContext());
  element->SetRestrictionTargetId(
      std::make_unique<RestrictionTargetId>(base::Token::CreateRandom()));
  UpdateAllLifecyclePhasesForTest();

  // The element should still not have a proper stacking context.
  EXPECT_FALSE(element->GetLayoutObject()->HasLayer());
  EXPECT_FALSE(element->GetLayoutObject()->IsStackingContext());

  // Now that the div has a restriction ID and a stacking context, it should
  // have an element capture effect node.
  element->setAttribute(html_names::kClassAttr, AtomicString("stacking"));
  UpdateAllLifecyclePhasesForTest();
  const ObjectPaintProperties* paint_properties =
      element->GetLayoutObject()->FirstFragment().PaintProperties();
  EXPECT_TRUE(paint_properties && paint_properties->ElementCaptureEffect());
  EXPECT_TRUE(element->GetLayoutObject()->HasLayer());
  EXPECT_TRUE(element->GetLayoutObject()->IsStackingContext());

  // NOTE: we don't currently have a teardown path for element capture. Once an
  // element is marked for capture it is marked for the rest of its lifetime.
  // TODO(https://crbug.com/1472139): add a teardown path for element capture.
}

TEST_P(PaintPropertyTreeBuilderTest, ClearClipPathEffectNode) {
  // This test makes sure ClipPath effect node is cleared properly upon
  // removal of a clip-path.
  SetBodyInnerHTML(R"HTML(
    <svg>
      <clipPath clip-path="circle()" id="clip"></clipPath>
      <rect id="rect" width="800" clip-path="url(#clip)" height="800"/>
    </svg>
  )HTML");

  {
    const auto* rect = GetLayoutObjectByElementId("rect");
    ASSERT_TRUE(rect);
    EXPECT_TRUE(rect->FirstFragment().PaintProperties()->MaskClip());
    EXPECT_TRUE(rect->FirstFragment().PaintProperties()->ClipPathMask());
  }

  Element* clip = GetDocument().getElementById(AtomicString("clip"));
  ASSERT_TRUE(clip);
  clip->remove();
  UpdateAllLifecyclePhasesExceptPaint();

  {
    const auto* rect = GetLayoutObjectByElementId("rect");
    ASSERT_TRUE(rect);
    EXPECT_FALSE(rect->FirstFragment().PaintProperties()->MaskClip());
    EXPECT_FALSE(rect->FirstFragment().PaintProperti
"""


```