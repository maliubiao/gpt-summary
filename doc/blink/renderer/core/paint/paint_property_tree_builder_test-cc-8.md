Response:
The user wants a summary of the functionality of the `paint_property_tree_builder_test.cc` file in the Chromium Blink engine, based on the provided code snippet. This is the 9th part of a 10-part request, indicating a progressive exploration of the file's content.

Here's a plan to address the request:

1. **Identify the core purpose of the file:** The file name strongly suggests it contains unit tests for the `PaintPropertyTreeBuilder`.
2. **Analyze the code snippets:** Examine each test case to understand what aspect of the `PaintPropertyTreeBuilder` is being tested. Look for patterns and common themes.
3. **Relate to web technologies (JavaScript, HTML, CSS):** Identify how the tested functionalities interact with these core web technologies. Provide concrete examples from the test code.
4. **Infer logical reasoning:** For tests involving assertions and expectations, deduce the underlying logic being validated. Formulate potential input scenarios and their expected outputs.
5. **Identify potential user/programming errors:** Based on the tested scenarios, highlight common mistakes users or developers might make that these tests aim to prevent or catch.
6. **Trace user actions to the tested code:**  Describe how a user's interaction with a web page could trigger the code paths being tested.
7. **Synthesize the findings into a concise summary:**  Combine the observations into a high-level description of the file's overall function, considering this is part 9 of 10.
```cpp
        break-inside: avoid;
      }
    </style>
    <div id="target"></div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();
  auto* target = GetDocument().getElementById(AtomicString("target"));
  EXPECT_BACKGROUND_CLIP(
      PaintPropertiesForElement(target->firstChild()),
      gfx::RectF(0, 0, 300, 200));
  EXPECT_BACKGROUND_CLIP(
      PaintPropertiesForElement(target->lastChild()),
      gfx::RectF(0, 200, 300, 200));

  target->setAttribute(html_names::kStyleAttr,
                       AtomicString("background-clip: padding-box"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_BACKGROUND_CLIP(
      PaintPropertiesForElement(target->firstChild()),
      gfx::RectF(20, 20, 260, 160));
  EXPECT_BACKGROUND_CLIP(
      PaintPropertiesForElement(target->lastChild()),
      gfx::RectF(20, 220, 260, 160));

  target->setAttribute(html_names::kStyleAttr,
                       AtomicString("background-clip: content-box"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_BACKGROUND_CLIP(
      PaintPropertiesForElement(target->firstChild()),
      gfx::RectF(30, 30, 240, 140));
  EXPECT_BACKGROUND_CLIP(
      PaintPropertiesForElement(target->lastChild()),
      gfx::RectF(30, 230, 240, 140));
}

TEST_P(PaintPropertyTreeBuilderTest, AvoidCompositingReasonLoop) {
  // Regression test for https://crbug.com/1466985.
  SetBodyInnerHTML(R"HTML(
    <div style="perspective: 100px;">
      <div style="transform-style: preserve-3d;">
        <div style="transform: translateZ(0);"></div>
        <div style="will-change: transform;"></div>
      </div>
    </div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();
}

}  // namespace blink
```

**功能列举：**

这个C++文件 `paint_property_tree_builder_test.cc` 包含了大量的单元测试，用于验证 Blink 渲染引擎中 `PaintPropertyTreeBuilder` 类的功能是否正确。 `PaintPropertyTreeBuilder` 的核心职责是构建用于渲染的属性树（Property Trees），这些属性树优化了渲染过程，特别是涉及到合成（Compositing）时。

具体来说，这些测试覆盖了以下功能点：

* **Opacity 处理:** 测试 `opacity` CSS 属性的正确处理，包括初始值、动态修改以及与合成层之间的同步。
* **滚动 (Scroll) 处理:** 验证滚动事件是否会触发不必要的属性树更新，以及滚动偏移在属性树中的正确表示。
* **Sticky 定位处理:**  测试 `position: sticky` 元素的变换是如何处理的，以及滚动如何影响 sticky 元素的最终位置，并确保不触发不必要的更新。
* **Transform 处理:** 详细测试 `transform` CSS 属性在不同场景下的行为，包括：
    * 非合成层上的 transform 变化是否会触发属性树更新。
    * 动画 transform 的轴对齐方式的判断。
    * 3D transform 对合成的影响。
    *  `transform-origin` 的处理。
* **Clip Rect 处理:** 验证 `clip` 和 `clip-path` 属性对元素裁剪区域的计算，特别是针对视频元素等特殊情况。
* **Paint Property 的创建和避免:**  测试在哪些情况下会为元素创建 Paint Properties，并验证某些类型的元素（如文本节点）在特定情况下不会创建 Paint Properties。
* **Viewport Bounds Delta 的影响:**  测试固定定位元素是否会受到外部视口边界变化的影响。
* **属性树的层级关系:**  验证不同定位方式的元素（如 fixed, absolute, relative）在属性树中的父子关系，以及滚动容器对子元素的影响。
* **合成 (Compositing) 的触发:** 测试哪些 CSS 属性或操作会触发元素的合成，例如 `will-change: transform`，并验证合成原因的正确性。
* **多列布局 (Multi-column) 中的 Out-of-flow 元素:**  测试在多列布局中，绝对定位和固定定位的元素如何关联到其父元素的变换属性。
* **SVG 相关的处理:**  验证 SVG 元素上 `backdrop-filter` 和 `transform` 动画的处理。
* **`will-change` 属性的影响:**  测试 `will-change` 属性对 `backdrop-filter` 和 `filter` 的影响，以及是否会触发不必要的合成层创建。
* **几何映射器 (Geometry Mapper) 的缓存失效:** 验证 transform 的变化是否会正确地使几何映射器的缓存失效。
* **Contain 属性 (Isolation Nodes) 的影响:** 测试 `contain: layout paint` 属性创建的隔离节点如何影响属性树的构建。
* **低端设备的处理:**  测试在低端设备上是否会避免为简单的 3D transform 创建合成层。
* **`background-clip` 属性的处理:** 验证 `background-clip` 属性在不同值下的表现，包括对片段化元素的处理。
* **避免合成原因循环:**  测试特定场景下是否会避免出现无限循环的合成原因判断。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

这个测试文件直接关联到 HTML 和 CSS，并通过测试代码中的 DOM 操作间接关联到 JavaScript 可以操作的部分。

* **HTML:** 测试用例通过 `SetHtmlInnerHTML` 或 `SetBodyInnerHTML` 方法设置 HTML 结构，这些 HTML 结构定义了被测试的元素及其父子关系。例如：
    ```cpp
    SetHtmlInnerHTML(R"HTML(
      <div id="element" style="opacity: 0.5"></div>
    )HTML");
    ```
    这部分 HTML 代码创建了一个 `id` 为 "element" 的 `div` 元素，并设置了 `opacity` CSS 属性。

* **CSS:**  测试用例主要通过设置元素的 `style` 属性来应用 CSS 样式，以触发 `PaintPropertyTreeBuilder` 的不同逻辑分支。例如：
    ```cpp
    element->setAttribute(html_names::kStyleAttr, AtomicString("opacity: 0.9"));
    ```
    这行代码使用 JavaScript (在测试环境中模拟) 修改了元素的 `opacity` CSS 属性。其他 CSS 属性如 `transform`, `position`, `overflow`, `will-change`, `clip`, `clip-path`, `background-clip` 等都在测试中被广泛使用。

* **JavaScript:** 虽然这个文件本身是 C++ 代码，但它模拟了 JavaScript 对 DOM 和 CSS 的操作。 例如，`GetDocument().getElementById(AtomicString("element"))->setScrollTop(10.)`  模拟了 JavaScript 设置元素的滚动位置。当 JavaScript 修改元素的样式或属性时，Blink 引擎会重新构建或更新属性树，而这些测试正是验证这个过程是否正确。

**逻辑推理、假设输入与输出：**

以 `TEST_P(PaintPropertyTreeBuilderTest, SimpleOpacityChange)` 为例：

* **假设输入:**  一个 `id` 为 "element" 的 `div` 元素，初始 `opacity` 为 0.5。
* **测试步骤:**
    1. 获取该元素的 Effect 属性。
    2. 断言初始 opacity 值是否为 0.5，并且 effect 已更改，但属性树不需要更新。
    3. 使用 JavaScript (模拟) 将该元素的 `opacity` 修改为 0.9。
    4. 触发更新生命周期。
    5. 断言更新后的 opacity 值是否为 0.9，effect 已更改，并且属性树需要更新。
* **预期输出:** 所有断言都应为真。这验证了当 opacity 发生变化时，属性树能够正确地反映这一变化，并且在适当的时候标记属性树需要更新。

**用户或编程常见的使用错误：**

* **错误地认为滚动不会触发合成层的更新:**  例如，开发者可能认为仅仅滚动一个设置了 `will-change: transform` 的元素不会导致性能问题，但测试 `SimpleScrollChangeDoesNotCausePacUpdate` 验证了在某些情况下，滚动并不会触发整个 Paint Artifact Compositor 的更新。 开发者需要理解哪些滚动操作会触发更昂贵的更新。
* **过度使用 `will-change`:**  开发者可能会为了性能优化而滥用 `will-change` 属性，但测试如 `WillChangeBackdropFilterWithTransformAndFilter` 和 `WillChangeFilterWithTransformAndOpacity`  表明 `will-change` 不应该引入额外的副作用，例如不必要地为 transform 或 filter 创建合成节点。
* **不理解不同定位方式对属性树的影响:** 开发者可能不清楚 `position: fixed`, `position: absolute`, `position: relative` 的元素在属性树中的层级关系和变换方式，测试 `OverflowScrollPropertyHierarchy`  帮助理解这些关系。

**用户操作如何一步步到达这里 (调试线索):**

当用户在浏览器中进行以下操作时，可能会触发与 `PaintPropertyTreeBuilder` 相关的代码：

1. **页面加载:** 当浏览器加载 HTML 文档时，`PaintPropertyTreeBuilder` 会根据 HTML 结构和 CSS 样式构建初始的属性树。
2. **CSS 样式更改:**  用户交互或 JavaScript 代码修改了元素的 CSS 样式 (例如通过 JavaScript 动态修改 `element.style.opacity`)。
3. **滚动页面:** 用户滚动页面会导致滚动偏移的变化，`PaintPropertyTreeBuilder` 需要更新与滚动相关的属性。
4. **执行 CSS 动画或过渡:** CSS 动画或过渡会改变元素的视觉属性，`PaintPropertyTreeBuilder` 需要跟踪这些变化。
5. **JavaScript 操作 DOM:**  JavaScript 动态添加、删除或移动 DOM 元素也会触发属性树的重建或更新。

作为调试线索，如果渲染出现问题，例如元素没有按照预期的样式显示，或者性能出现瓶颈，开发者可能会检查属性树的构建过程，查看特定元素的 Paint Properties 和相关的变换、裁剪等属性是否正确。这个测试文件中的各种测试用例可以帮助开发者理解在不同场景下属性树应该如何构建，从而定位问题。

**第9部分功能归纳：**

作为第9部分，这个代码片段主要集中在测试 `PaintPropertyTreeBuilder` 在处理以下方面的功能：

* **`background-clip` 属性:**  验证不同 `background-clip` 值的渲染效果，包括在元素被分片的情况下的处理。
* **避免合成原因的无限循环:**  确保在特定复杂的场景下，不会因为合成原因的判断而进入死循环。

总而言之，这个文件是 Blink 渲染引擎中一个关键的测试组件，它通过大量的单元测试确保了 `PaintPropertyTreeBuilder` 能够正确地根据 HTML 结构和 CSS 样式构建用于渲染优化的属性树。它覆盖了各种常见的 CSS 属性和场景，并模拟了 JavaScript 的 DOM 操作，以验证属性树构建的正确性和性能。

Prompt: 
```
这是目录为blink/renderer/core/paint/paint_property_tree_builder_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第9部分，共10部分，请归纳一下它的功能

"""
c_effect =
      GetChromeClient()
          .layer_tree_host()
          ->property_trees()
          ->effect_tree_mutable()
          .FindNodeFromElementId(
              properties->Effect()->GetCompositorElementId());
  ASSERT_TRUE(cc_effect);
  EXPECT_FLOAT_EQ(cc_effect->opacity, 0.5f);
  EXPECT_TRUE(cc_effect->effect_changed);
  EXPECT_FALSE(GetChromeClient()
                   .layer_tree_host()
                   ->property_trees()
                   ->effect_tree()
                   .needs_update());

  Element* element = GetDocument().getElementById(AtomicString("element"));
  element->setAttribute(html_names::kStyleAttr, AtomicString("opacity: 0.9"));

  UpdateAllLifecyclePhasesExceptPaint();
  EXPECT_FLOAT_EQ(properties->Effect()->Opacity(), 0.9f);
  EXPECT_FLOAT_EQ(cc_effect->opacity, 0.9f);
  EXPECT_TRUE(cc_effect->effect_changed);
  EXPECT_FALSE(pac->NeedsUpdate());
  EXPECT_TRUE(GetChromeClient()
                  .layer_tree_host()
                  ->property_trees()
                  ->effect_tree()
                  .needs_update());
}

TEST_P(PaintPropertyTreeBuilderTest, SimpleScrollChangeDoesNotCausePacUpdate) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      #element {
        width: 100px;
        height: 100px;
        overflow: scroll;
        will-change: transform;
      }
      #spacer {
        width: 100px;
        height: 1000px;
      }
    </style>
    <div id="element"><div id="spacer"></div></div>
  )HTML");

  auto* pac = GetDocument().View()->GetPaintArtifactCompositor();
  ASSERT_TRUE(pac);

  const auto* properties = PaintPropertiesForElement("element");
  ASSERT_TRUE(properties);
  ASSERT_TRUE(properties->ScrollTranslation());
  ASSERT_TRUE(properties->ScrollTranslation()->ScrollNode());
  EXPECT_EQ(gfx::Vector2dF(0, 0),
            properties->ScrollTranslation()->Get2dTranslation());
  EXPECT_FALSE(pac->NeedsUpdate());

  auto* property_trees = GetChromeClient().layer_tree_host()->property_trees();
  const auto* cc_scroll_node =
      property_trees->scroll_tree().FindNodeFromElementId(
          properties->ScrollTranslation()
              ->ScrollNode()
              ->GetCompositorElementId());
  ASSERT_TRUE(cc_scroll_node);

  const auto* cc_transform_node =
      property_trees->transform_tree().Node(cc_scroll_node->transform_id);
  ASSERT_TRUE(cc_transform_node);

  EXPECT_TRUE(cc_transform_node->local.IsIdentity());
  EXPECT_FLOAT_EQ(cc_transform_node->scroll_offset.x(), 0);
  EXPECT_FLOAT_EQ(cc_transform_node->scroll_offset.y(), 0);
  auto current_scroll_offset =
      property_trees->scroll_tree().current_scroll_offset(
          properties->ScrollTranslation()
              ->ScrollNode()
              ->GetCompositorElementId());
  EXPECT_FLOAT_EQ(current_scroll_offset.x(), 0);
  EXPECT_FLOAT_EQ(current_scroll_offset.y(), 0);

  GetDocument().getElementById(AtomicString("element"))->setScrollTop(10.);
  UpdateAllLifecyclePhasesExceptPaint();

  EXPECT_EQ(gfx::Vector2dF(0, -10),
            properties->ScrollTranslation()->Get2dTranslation());
  EXPECT_FALSE(pac->NeedsUpdate());
  EXPECT_TRUE(cc_transform_node->local.IsIdentity());
  EXPECT_FLOAT_EQ(cc_transform_node->scroll_offset.x(), 0);
  EXPECT_FLOAT_EQ(cc_transform_node->scroll_offset.y(), 10);
  current_scroll_offset = property_trees->scroll_tree().current_scroll_offset(
      properties->ScrollTranslation()->ScrollNode()->GetCompositorElementId());
  EXPECT_FLOAT_EQ(current_scroll_offset.x(), 0);
  EXPECT_FLOAT_EQ(current_scroll_offset.y(), 10);
  EXPECT_TRUE(property_trees->transform_tree().needs_update());
  EXPECT_TRUE(cc_transform_node->transform_changed);

  UpdateAllLifecyclePhasesForTest();
}

TEST_P(PaintPropertyTreeBuilderTest,
       SimpleStickyTranslationChangeDoesNotCausePacUpdate) {
  SetBodyInnerHTML(R"HTML(
    <style>::webkit-scrollbar { width: 0; height: 0 }</style>
    <!-- position: relative and z-index: 1 are needed to make the scroller a
     stacking context (otherwise scroll of a non-stacking-context containing
     stacked descendant would cause PAC update).
     TODO(wangxianzhu): Remove them when fixing crbug.com/1310586. -->
    <div id="scroller" style="width: 200px; height: 200px; overflow: scroll;
                              background: blue; position: relative; z-index: 1">
      <div style="height: 300px"></div>
      <div id="target" style="position: sticky; bottom: 0; height: 20px"></div>
    </div>
  )HTML");

  auto* pac = GetDocument().View()->GetPaintArtifactCompositor();
  ASSERT_TRUE(pac);

  auto* properties = PaintPropertiesForElement("target");
  ASSERT_TRUE(properties);
  auto* sticky_translation = properties->StickyTranslation();
  ASSERT_TRUE(sticky_translation);
  EXPECT_EQ(gfx::Vector2dF(0, -120), sticky_translation->Get2dTranslation());

  auto* property_trees = GetChromeClient().layer_tree_host()->property_trees();
  const auto* cc_transform_node =
      property_trees->transform_tree().FindNodeFromElementId(
          sticky_translation->GetCompositorElementId());
  ASSERT_TRUE(cc_transform_node);
  // We don't push the sticky offset to cc.
  EXPECT_EQ(gfx::Vector2dF(), cc_transform_node->local.To2dTranslation());

  GetDocument().getElementById(AtomicString("scroller"))->setScrollTop(200);
  UpdateAllLifecyclePhasesExceptPaint();

  EXPECT_EQ(gfx::Vector2dF(), sticky_translation->Get2dTranslation());
  EXPECT_FALSE(pac->NeedsUpdate());
  EXPECT_EQ(gfx::Vector2dF(), cc_transform_node->local.To2dTranslation());
  EXPECT_TRUE(property_trees->transform_tree().needs_update());
  EXPECT_TRUE(cc_transform_node->transform_changed);

  UpdateAllLifecyclePhasesForTest();
}

TEST_P(PaintPropertyTreeBuilderTest,
       NonCompositedTransformChangeCausesPacUpdate) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #outer {
        width: 100px;
        height: 100px;
        transform: translateY(0);
      }
      #inner {
        width: 10px;
        height: 10px;
        will-change: transform;
      }
    </style>
    <div id="outer">
      <div id="inner"></div>
    </div>
  )HTML");

  EXPECT_FALSE(
      GetDocument().View()->GetPaintArtifactCompositor()->NeedsUpdate());

  Element* outer = GetDocument().getElementById(AtomicString("outer"));
  outer->setAttribute(html_names::kStyleAttr,
                      AtomicString("transform: translateY(10px)"));
  UpdateAllLifecyclePhasesExceptPaint();

  EXPECT_TRUE(
      GetDocument().View()->GetPaintArtifactCompositor()->NeedsUpdate());
}

TEST_P(PaintPropertyTreeBuilderTest, VideoClipRect) {
  SetBodyInnerHTML(R"HTML(
    <video id="video" style="position:absolute;top:0;left:0;" controls
       src="missing_file.webm" width=320.2 height=240>
    </video>
  )HTML");

  Element* video_element = GetDocument().getElementById(AtomicString("video"));
  ASSERT_NE(nullptr, video_element);
  video_element->SetInlineStyleProperty(CSSPropertyID::kWidth, "320.2px");
  video_element->SetInlineStyleProperty(CSSPropertyID::kTop, "0.1px");
  video_element->SetInlineStyleProperty(CSSPropertyID::kLeft, "0.1px");
  LocalFrameView* frame_view = GetDocument().View();
  frame_view->UpdateAllLifecyclePhasesForTest();
  const ObjectPaintProperties* video_element_properties =
      video_element->GetLayoutObject()->FirstFragment().PaintProperties();
  // |video_element| is now sub-pixel positioned, at 0.1,0.1 320.2x240. With or
  // without pixel-snapped clipping, this will get clipped at 0,0 320x240.
  EXPECT_CLIP_RECT(FloatRoundedRect(0, 0, 320, 240),
                   video_element_properties->OverflowClip());

  // Now, move |video_element| to 10.4,10.4. At this point, without pixel
  // snapping that doesn't depend on paint offset, it will be clipped at 10,10
  // 321x240. With proper pixel snapping, the clip will be at 10,10,320,240.
  video_element->SetInlineStyleProperty(CSSPropertyID::kTop, "10.4px");
  video_element->SetInlineStyleProperty(CSSPropertyID::kLeft, "10.4px");
  frame_view->UpdateAllLifecyclePhasesForTest();
  EXPECT_CLIP_RECT(FloatRoundedRect(10, 10, 320, 240),
                   video_element_properties->OverflowClip());
}

// For NoPaintPropertyForXXXText cases. The styles trigger almost all paint
// properties on the container. The contained text should not create paint
// properties in any case.
#define ALL_PROPERTY_STYLES                                                  \
  "backface-visibility: hidden; transform: rotateY(1deg); perspective: 1px;" \
  "opacity: 0.5; filter: blur(5px); clip-path: circle(100%); "               \
  "clip: rect(0px, 2px, 2px, 0px); overflow: scroll; border-radius: 2px; "   \
  "width: 10px; height: 10px; top: 0; left: 0; position: sticky; columns: 2"

TEST_P(PaintPropertyTreeBuilderTest, NoPaintPropertyForBlockText) {
  SetBodyInnerHTML("<div id='container' style='" ALL_PROPERTY_STYLES
                   "'>T</div>");
  EXPECT_TRUE(PaintPropertiesForElement("container"));
  auto* text = GetDocument()
                   .getElementById(AtomicString("container"))
                   ->firstChild()
                   ->GetLayoutObject();
  ASSERT_TRUE(text->IsText());
  EXPECT_FALSE(text->FirstFragment().PaintProperties());
}

TEST_P(PaintPropertyTreeBuilderTest, NoPaintPropertyForInlineText) {
  SetBodyInnerHTML("<span id='container' style='" ALL_PROPERTY_STYLES
                   "'>T</span>");
  EXPECT_TRUE(PaintPropertiesForElement("container"));
  auto* text = GetDocument()
                   .getElementById(AtomicString("container"))
                   ->firstChild()
                   ->GetLayoutObject();
  ASSERT_TRUE(text->IsText());
  EXPECT_FALSE(text->FirstFragment().PaintProperties());
}

TEST_P(PaintPropertyTreeBuilderTest, NoPaintPropertyForSVGText) {
  SetBodyInnerHTML("<svg><text id='container' style='" ALL_PROPERTY_STYLES
                   "'>T</text>");
  EXPECT_TRUE(PaintPropertiesForElement("container"));
  auto* text = GetDocument()
                   .getElementById(AtomicString("container"))
                   ->firstChild()
                   ->GetLayoutObject();
  ASSERT_TRUE(text->IsText());
  EXPECT_FALSE(text->FirstFragment().PaintProperties());
}

TEST_P(PaintPropertyTreeBuilderTest, IsAffectedByOuterViewportBoundsDelta) {
  SetBodyInnerHTML(R"HTML(
    <style>div { will-change: transform; position: fixed; }</style>
    <div id="fixed1"></div>
    <div id="fixed2" style="right: 0"></div>
    <div id="fixed3" style="bottom: 0"></div>
    <div id="fixed4" style="bottom: 20px"></div>
    <div style="transform: translateX(100px)">
      <div id="fixed5" style="bottom: 0"></div>
    </div>
    <iframe></iframe>
  )HTML");
  SetChildFrameHTML(R"HTML(
     <div id="fixed"
          style="will-change: transform; position: fixed; bottom: 0"></div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  auto check_result = [&](const ObjectPaintProperties* properties,
                          bool expected) {
    ASSERT_TRUE(properties);
    ASSERT_TRUE(properties->PaintOffsetTranslation());
    EXPECT_EQ(expected, properties->PaintOffsetTranslation()
                            ->IsAffectedByOuterViewportBoundsDelta());
  };

  check_result(PaintPropertiesForElement("fixed1"), false);
  check_result(PaintPropertiesForElement("fixed2"), false);
  check_result(PaintPropertiesForElement("fixed3"), true);
  check_result(PaintPropertiesForElement("fixed4"), true);
  check_result(PaintPropertiesForElement("fixed5"), false);

  // Fixed elements in subframes are not affected by viewport.
  check_result(ChildDocument()
                   .getElementById(AtomicString("fixed"))
                   ->GetLayoutObject()
                   ->FirstFragment()
                   .PaintProperties(),
               false);
}

TEST_P(PaintPropertyTreeBuilderTest, TransformAnimationAxisAlignment) {
  SetBodyInnerHTML(R"HTML(
      <!DOCTYPE html>
      <style>
        @keyframes transform_translation {
          0% { transform: translate(10px, 11px); }
          100% { transform: translate(20px, 21px); }
        }
        #translation_animation {
          animation-name: transform_translation;
          animation-duration: 1s;
          width: 100px;
          height: 100px;
          will-change: transform;
        }
        @keyframes transform_rotation {
          0% { transform: rotateZ(10deg); }
          100% { transform: rotateZ(20deg); }
        }
        #rotation_animation {
          animation-name: transform_rotation;
          animation-duration: 1s;
          width: 100px;
          height: 100px;
          will-change: transform;
        }
      </style>
      <div id="translation_animation"></div>
      <div id="rotation_animation"></div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  const auto* translation =
      PaintPropertiesForElement("translation_animation")->Transform();
  EXPECT_TRUE(translation->HasActiveTransformAnimation());
  EXPECT_TRUE(translation->TransformAnimationIsAxisAligned());

  const auto* rotation =
      PaintPropertiesForElement("rotation_animation")->Transform();
  EXPECT_TRUE(rotation->HasActiveTransformAnimation());
  EXPECT_FALSE(rotation->TransformAnimationIsAxisAligned());
}

TEST_P(PaintPropertyTreeBuilderTest, OverflowScrollPropertyHierarchy) {
  SetBodyInnerHTML(R"HTML(
    <div id="top-scroller"
        style="position: relative; width: 50px; height: 50px; overflow: scroll">
      <div id="middle-scroller"
           style="width: 100px; height: 100px; overflow: scroll; opacity: 0.9">
        <div id="fixed" style="position: fixed"></div>
        <div id="absolute" style="position: absolute"></div>
        <div id="relative" style="position: relative; height: 1000px"></div>
      </div>
    </div>
  )HTML");

  auto* top_properties = PaintPropertiesForElement("top-scroller");
  ASSERT_TRUE(top_properties->OverflowClip());
  EXPECT_EQ(top_properties->ScrollTranslation()->ScrollNode(),
            top_properties->Scroll());

  auto* middle_properties = PaintPropertiesForElement("middle-scroller");
  EXPECT_EQ(middle_properties->PaintOffsetTranslation(),
            &middle_properties->OverflowClip()->LocalTransformSpace());
  EXPECT_EQ(top_properties->OverflowClip(),
            middle_properties->OverflowClip()->Parent());
  EXPECT_EQ(top_properties->Scroll(), middle_properties->Scroll()->Parent());
  EXPECT_EQ(middle_properties->ScrollTranslation()->ScrollNode(),
            middle_properties->Scroll());
  EXPECT_EQ(top_properties->ScrollTranslation(),
            middle_properties->ScrollTranslation()->Parent()->Parent());
  EXPECT_EQ(middle_properties->PaintOffsetTranslation(),
            &middle_properties->Effect()->LocalTransformSpace());

  // |fixed| escapes both top and middle scrollers.
  auto& fixed_fragment = GetLayoutObjectByElementId("fixed")->FirstFragment();
  EXPECT_EQ(fixed_fragment.PaintProperties()->PaintOffsetTranslation(),
            &fixed_fragment.PreTransform());
  EXPECT_EQ(top_properties->OverflowClip()->Parent(),
            &fixed_fragment.PreClip());

  // |absolute| escapes |middle-scroller| (position: static), but is contained
  // by |top-scroller| (position: relative)
  auto& absolute_fragment =
      GetLayoutObjectByElementId("absolute")->FirstFragment();
  EXPECT_EQ(top_properties->ScrollTranslation(),
            &absolute_fragment.PreTransform());
  EXPECT_EQ(top_properties->OverflowClip(), &absolute_fragment.PreClip());

  // |relative| is contained by |middle-scroller|.
  auto& relative_fragment =
      GetLayoutObjectByElementId("relative")->FirstFragment();
  EXPECT_EQ(middle_properties->ScrollTranslation(),
            &relative_fragment.PreTransform());
  EXPECT_EQ(middle_properties->OverflowClip(), &relative_fragment.PreClip());

  // The opacity on |middle-scroller| applies to all children.
  EXPECT_EQ(middle_properties->Effect(),
            &fixed_fragment.LocalBorderBoxProperties().Effect());
  EXPECT_EQ(middle_properties->Effect(),
            &absolute_fragment.LocalBorderBoxProperties().Effect());
  EXPECT_EQ(middle_properties->Effect(),
            &relative_fragment.LocalBorderBoxProperties().Effect());
}

TEST_P(PaintPropertyTreeBuilderTest, CompositedInline) {
  SetBodyInnerHTML(R"HTML(
    <span id="span" style="will-change: transform; position: relative">
      SPAN
    </span>
  )HTML");

  auto* properties = PaintPropertiesForElement("span");
  ASSERT_TRUE(properties);
  ASSERT_TRUE(properties->Transform());
  EXPECT_TRUE(properties->Transform()->HasDirectCompositingReasons());
}

TEST_P(PaintPropertyTreeBuilderTest, OutOfFlowContainedInMulticol) {
  SetBodyInnerHTML(R"HTML(
    <div id="columns" style="columns: 2; height: 100px">
      <div id="relative"
           style="position: relative; height: 200px; transform: translateX(0)">
        <div style="overflow: clip; height: 150px">
          <div id="absolute"
               style="position: absolute; width: 100%; height: 200px"></div>
          <div id="fixed"
               style="position: fixed; width: 100%; height: 200px"></div>
        </div>
      </div>
    </div>
  )HTML");

  const auto* relative = GetLayoutObjectByElementId("relative");
  ASSERT_EQ(2u, NumFragments(relative));
  const auto* absolute = GetLayoutObjectByElementId("absolute");
  ASSERT_EQ(2u, NumFragments(absolute));
  const auto* fixed = GetLayoutObjectByElementId("fixed");
  ASSERT_EQ(2u, NumFragments(fixed));

  for (unsigned i = 0; i < NumFragments(relative); i++) {
    SCOPED_TRACE(testing::Message() << "Fragment " << i);
    const auto* relative_transform =
        FragmentAt(relative, i).PaintProperties()->Transform();
    const auto& absolute_properties =
        FragmentAt(absolute, i).LocalBorderBoxProperties();
    const auto& fixed_properties =
        FragmentAt(fixed, i).LocalBorderBoxProperties();
    EXPECT_EQ(relative_transform, &absolute_properties.Transform());
    EXPECT_EQ(relative_transform, &fixed_properties.Transform());
  }
}

TEST_P(PaintPropertyTreeBuilderTest, SVGChildBackdropFilter) {
  SetBodyInnerHTML(R"HTML(
    <svg id="svg">
      <text id="text" style="backdrop-filter: blur(5px)">Text</text>
    </svg>
  )HTML");

  auto* svg_properties = PaintPropertiesForElement("svg");
  ASSERT_TRUE(svg_properties);
  ASSERT_TRUE(svg_properties->PaintOffsetTranslation());
  EXPECT_FALSE(
      svg_properties->PaintOffsetTranslation()->HasDirectCompositingReasons());

  auto* svg_text_properties = PaintPropertiesForElement("text");
  ASSERT_TRUE(svg_text_properties);
  ASSERT_TRUE(svg_text_properties->Effect());
  EXPECT_TRUE(svg_text_properties->Effect()->HasDirectCompositingReasons());
  // TODO(crbug.com/1131987): Backdrop-filter doesn't work in SVG yet.
  EXPECT_FALSE(svg_text_properties->Effect()->BackdropFilter());
  EXPECT_FALSE(svg_text_properties->Transform());
  EXPECT_FALSE(GetLayoutObjectByElementId("text")
                   ->SlowFirstChild()
                   ->FirstFragment()
                   .PaintProperties());
}

TEST_P(PaintPropertyTreeBuilderTest, SVGTransformAnimationAndOrigin) {
  SetBodyInnerHTML(R"HTML(
    <svg width="200" height="200">
      <rect id="rect"
            style="animation: 2s infinite spin; transform-origin: 50% 50%">
    </svg>
    <style>
      @keyframes spin {
        0% { transform: rotate(0); }
        100% { transform: rotate(360deg); }
      }
    </style>
  )HTML");

  auto* properties = PaintPropertiesForElement("rect");
  ASSERT_TRUE(properties);
  auto* transform_node = properties->Transform();
  ASSERT_TRUE(transform_node);
  EXPECT_TRUE(transform_node->HasActiveTransformAnimation());
  EXPECT_EQ(gfx::Transform(), transform_node->Matrix());
  EXPECT_EQ(gfx::Point3F(100, 100, 0), transform_node->Origin());
}

TEST_P(PaintPropertyTreeBuilderTest, WillChangeBackdropFilter) {
  SetBodyInnerHTML(R"HTML(
    <div id="target" style="will-change: backdrop-filter"></div>
  )HTML");

  auto* properties = PaintPropertiesForElement("target");
  ASSERT_TRUE(properties);
  ASSERT_TRUE(properties->Effect());
  EXPECT_FALSE(properties->Effect()->BackdropFilter());
  EXPECT_TRUE(
      properties->Effect()->RequiresCompositingForWillChangeBackdropFilter());

  // will-change:backdrop-filter should not cause transform or filter node.
  EXPECT_FALSE(properties->Transform());
  EXPECT_FALSE(properties->Filter());
}

TEST_P(PaintPropertyTreeBuilderTest,
       WillChangeBackdropFilterWithTransformAndFilter) {
  SetBodyInnerHTML(R"HTML(
    <div id="target" style="will-change: backdrop-filter;
        transform: translateX(10px); filter: blur(5px)"></div>
  )HTML");

  auto* properties = PaintPropertiesForElement("target");
  ASSERT_TRUE(properties);
  ASSERT_TRUE(properties->Effect());
  EXPECT_FALSE(properties->Effect()->BackdropFilter());
  EXPECT_TRUE(
      properties->Effect()->RequiresCompositingForWillChangeBackdropFilter());

  // will-change:backdrop-filter should not add compositing reason for the
  // transform or the filter node.
  ASSERT_TRUE(properties->Transform());
  EXPECT_FALSE(properties->Transform()->HasDirectCompositingReasons());
  ASSERT_TRUE(properties->Filter());
  EXPECT_FALSE(properties->Filter()->HasDirectCompositingReasons());
}

TEST_P(PaintPropertyTreeBuilderTest, WillChangeFilter) {
  SetBodyInnerHTML(R"HTML(
    <div id="target" style="will-change: filter"></div>
  )HTML");

  auto* properties = PaintPropertiesForElement("target");
  ASSERT_TRUE(properties);
  ASSERT_TRUE(properties->Filter());
  EXPECT_TRUE(properties->Filter()->Filter().IsEmpty());
  EXPECT_TRUE(properties->Filter()->RequiresCompositingForWillChangeFilter());

  // will-change:filter should not cause transform or effect node.
  EXPECT_FALSE(properties->Transform());
  EXPECT_FALSE(properties->Effect());
}

TEST_P(PaintPropertyTreeBuilderTest, WillChangeFilterWithTransformAndOpacity) {
  SetBodyInnerHTML(R"HTML(
    <div id="target" style="will-change: filter;
        transform: translateX(10px); opacity: 0.5"></div>
  )HTML");

  auto* properties = PaintPropertiesForElement("target");
  ASSERT_TRUE(properties);
  ASSERT_TRUE(properties->Filter());
  EXPECT_TRUE(properties->Filter()->Filter().IsEmpty());
  EXPECT_TRUE(properties->Filter()->RequiresCompositingForWillChangeFilter());

  // will-change:filter should not add compositing reason for the transform or
  // the filter node.
  ASSERT_TRUE(properties->Transform());
  EXPECT_FALSE(properties->Transform()->HasDirectCompositingReasons());
  ASSERT_TRUE(properties->Effect());
  EXPECT_FALSE(properties->Effect()->HasDirectCompositingReasons());
}

TEST_P(PaintPropertyTreeBuilderTest, EffectCanUseCurrentClipAsOutputClipCrash) {
  SetBodyInnerHTML(R"HTML(
      <style type="text/css">
      .c1 { transform: rotate(180deg); }
      .c9 { position: relative; opacity: 0.1; }
      .c9 > .c18 { position: fixed; }
      </style>
      <fieldset id="f" class="c1"><samp class="c9"><footer
       class="c18"></footer></samp></fiedlset>
  )HTML");

  EXPECT_TRUE(GetLayoutObjectByElementId("f")
                  ->SlowFirstChild()
                  ->FirstFragment()
                  .HasLocalBorderBoxProperties());
}

// Test case for crbug.com/1381173.
TEST_P(PaintPropertyTreeBuilderTest, EffectOutputClipOfMissedOutOfFlow) {
  SetBodyInnerHTML(R"HTML(
    <div style="columns:2; column-fill:auto; height:100px;">
      <div style="height:150px;"></div>
      <div style="will-change:transform; width:50px; height:50px;">
        <div id="oof" style="position:absolute; top:-100px; opacity:0;">
          <div style="position:fixed;"></div>
        </div>
      </div>
    </div>
  )HTML");

  auto* properties = PaintPropertiesForElement("oof");
  ASSERT_TRUE(properties);
  ASSERT_TRUE(properties->Effect());
  EXPECT_FALSE(properties->Effect()->OutputClip());
}

TEST_P(PaintPropertyTreeBuilderTest, TransformChangesInvalidateGeometryMapper) {
  SetBodyInnerHTML(R"HTML(
    <style>#div { width:10px; height:10px; transform:translateX(9px); }</style>
    <div id="div" style="transform: translateX(5px);"></div>
  )HTML");

  const auto* properties = PaintPropertiesForElement("div");
  const auto& transform_cache = GetTransformCache(*properties->Transform());
  EXPECT_TRUE(transform_cache.IsValid());

  // Change the transform and ensure the geometry mapper cache is invalidated.
  auto* div = GetDocument().getElementById(AtomicString("div"));
  div->removeAttribute(html_names::kStyleAttr);
  UpdateAllLifecyclePhasesExceptPaint();
  EXPECT_FALSE(transform_cache.IsValid());

  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(transform_cache.IsValid());

  // Make a color change and ensure the geometry mapper cache is not
  // invalidated.
  div->setAttribute(html_names::kStyleAttr, AtomicString("background: green;"));
  UpdateAllLifecyclePhasesExceptPaint();
  EXPECT_TRUE(transform_cache.IsValid());
}

TEST_P(PaintPropertyTreeBuilderTest,
       GeometryMapperCacheInvalidationAcrossIsolationNodes) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #composited { transform: translate3d(1px, 2px, 3px); }
      #container { contain: layout paint; width: 100px; height: 100px; }
      #target { transform: translateX(1px); }
    </style>
    <div id='composited'>
      <div id='container' style='transform: translate3d(1px, 2px, 3px);'>
        <div id='target'></div>
      </div>
    </div>
  )HTML");

  LocalFrameView* frame_view = GetDocument().View();
  frame_view->UpdateAllLifecyclePhasesForTest();

  auto* container = GetLayoutObjectByElementId("container");
  auto* container_properties = container->FirstFragment().PaintProperties();
  auto* target = GetLayoutObjectByElementId("target");
  auto* target_properties = target->FirstFragment().PaintProperties();
  EXPECT_EQ(target_properties->Transform()->NearestDirectlyCompositedAncestor(),
            container_properties->Transform());

  // Remove the direct compositing reason from #container.
  auto* container_element =
      GetDocument().getElementById(AtomicString("container"));
  container_element->setAttribute(html_names::kStyleAttr, g_empty_atom);
  frame_view->UpdateAllLifecyclePhasesForTest();

  auto* composited = GetLayoutObjectByElementId("composited");
  auto* composited_properties = composited->FirstFragment().PaintProperties();
  EXPECT_EQ(target_properties->Transform()->NearestDirectlyCompositedAncestor(),
            composited_properties->Transform());
}

TEST_P(PaintPropertyTreeBuilderTest, PromoteTrivial3DWithHighEndDevice) {
  SetBodyInnerHTML(R"HTML(
    <style>div {width: 100px; height: 100px; transform: translateZ(0)}</style>
    <div id='non-scroll'></div>
    <div id='scroll' style='overflow: scroll'>
      <div style='height: 2000px'></div>
    </div>
    <div id='effect' style="opacity: 0.5"></div>
  )HTML");

  const auto* non_scroll_properties = PaintPropertiesForElement("non-scroll");
  EXPECT_TRUE(
      non_scroll_properties->Transform()->HasDirectCompositingReasons());
  EXPECT_FALSE(non_scroll_properties->Effect());

  const auto* scroll_properties = PaintPropertiesForElement("scroll");
  EXPECT_TRUE(scroll_properties->Transform()->HasDirectCompositingReasons());
  EXPECT_EQ(CompositedScrollingPreference::kPreferred,
            scroll_properties->Scroll()->GetCompositedScrollingPreference());
  EXPECT_FALSE(scroll_properties->Effect());

  // Trivial 3d transform also triggers composited effect if effect exist.
  const auto* effect_properties = PaintPropertiesForElement("effect");
  EXPECT_TRUE(effect_properties->Transform()->HasDirectCompositingReasons());
  EXPECT_TRUE(effect_properties->Effect()->HasDirectCompositingReasons());
}

TEST_P(PaintPropertyTreeBuilderTest, DontPromoteTrivial3DWithLowEndDevice) {
  class LowEndPlatform : public TestingPlatformSupport {
    bool IsLowEndDevice() override { return true; }
  };

  ScopedTestingPlatformSupport<LowEndPlatform> platform;
  SetBodyInnerHTML(R"HTML(
    <style>div {width: 100px; height: 100px; transform: translateZ(0)}</style>
    <div id='non-scroll'></div>
    <div id='scroll' style='overflow: scroll'>
      <div style='height: 2000px'></div>
    </div>
    <div id='effect' style="opacity: 0.5"></div>
  )HTML");

  const auto* non_scroll_properties = PaintPropertiesForElement("non-scroll");
  EXPECT_FALSE(
      non_scroll_properties->Transform()->HasDirectCompositingReasons());
  EXPECT_FALSE(non_scroll_properties->Effect());

  const auto* scroll_properties = PaintPropertiesForElement("scroll");
  EXPECT_FALSE(scroll_properties->Transform()->HasDirectCompositingReasons());
  // We still prefer composited scrolling with Trivial 3d transform.
  EXPECT_EQ(CompositedScrollingPreference::kPreferred,
            scroll_properties->Scroll()->GetCompositedScrollingPreference());
  EXPECT_FALSE(scroll_properties->Effect());

  const auto* effect_properties = PaintPropertiesForElement("effect");
  EXPECT_FALSE(effect_properties->Transform()->HasDirectCompositingReasons());
  EXPECT_FALSE(effect_properties->Effect()->HasDirectCompositingReasons());
}

#define EXPECT_BACKGROUND_CLIP(properties, rect)                            \
  do {                                                                      \
    ASSERT_TRUE(properties);                                                \
    ASSERT_TRUE(properties->BackgroundClip());                              \
    EXPECT_EQ(rect, properties->BackgroundClip()->PaintClipRect().Rect());  \
    EXPECT_EQ(rect, properties->BackgroundClip()->LayoutClipRect().Rect()); \
  } while (false)

TEST_P(PaintPropertyTreeBuilderTest, BackgroundClip) {
  SetPreferCompositingToLCDText(true);

  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin: 0; }
      #target {
        width: 300px;
        height: 200px;
        border: 20px solid black;
        padding: 10px;
        box-sizing: border-box;
        background-image: linear-gradient(blue, red);
        background-attachment: fixed;
      }
    </style>
    <div id="target"></div>
  )HTML");

  auto* target = GetDocument().getElementById(AtomicString("target"));
  EXPECT_BACKGROUND_CLIP(PaintPropertiesForElement("target"),
                         gfx::RectF(0, 0, 300, 200));

  target->setAttribute(html_names::kStyleAttr,
                       AtomicString("background-clip: padding-box"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_BACKGROUND_CLIP(PaintPropertiesForElement("target"),
                         gfx::RectF(20, 20, 260, 160));

  target->setAttribute(
      html_names::kStyleAttr,
      AtomicString("background-clip: padding-box; border-top-width: 15px"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_BACKGROUND_CLIP(PaintPropertiesForElement("target"),
                         gfx::RectF(20, 15, 260, 165));

  target->setAttribute(html_names::kStyleAttr,
                       AtomicString("background-clip: content-box"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_BACKGROUND_CLIP(PaintPropertiesForElement("target"),
                         gfx::RectF(30, 30, 240, 140));

  target->setAttribute(
      html_names::kStyleAttr,
      AtomicString("background-clip: content-box; padding-left: 25px"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_BACKGROUND_CLIP(PaintPropertiesForElement("target"),
                         gfx::RectF(45, 30, 225, 140));

  target->setAttribute(html_names::kStyleAttr, g_empty_atom);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_BACKGROUND_CLIP(PaintPropertiesForElement("target"),
                         gfx::RectF(0, 0, 300, 200));

  target->setAttribute(html_names::kStyleAttr,
                       AtomicString("border-radius: 20px"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(PaintPropertiesForElement("target"));

  target->setAttribute(html_names::kStyleAttr, g_empty_atom);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_BACKGROUND_CLIP(PaintPropertiesForElement("target"),
                         gfx::RectF(0, 0, 300, 200));

  target->setAttribute(html_names::kStyleAttr,
                       AtomicString("box-shadow: 10px 20px blue"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(PaintPropertiesForElement("target"));

  target->setAttribute(html_names::kStyleAttr, g_empty_atom);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_BACKGROUND_CLIP(PaintPropertiesForElement("target"),
                         gfx::RectF(0, 0, 300, 200));

  target->setAttribute(html_names::kStyleAttr,
                       AtomicString("background-attachment: local"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(PaintPropertiesForElement("target"));
}

TEST_P(PaintPropertyTreeBuilderTest, BackgroundClipFragmented) {
  SetPreferCompositingToLCDText(true);

  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin: 0; }
      #target {
        height: 600px;
        border: 20px solid black;
        padding: 10px;
        box-sizing: border-box;
        background-image: linear-gradient(blue, red);
     
"""


```