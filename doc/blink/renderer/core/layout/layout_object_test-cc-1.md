Response:
The user wants a summary of the provided C++ code, which is a test file for the `LayoutObject` class in the Chromium Blink engine.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the core purpose:** The filename `layout_object_test.cc` and the presence of `TEST_F` macros immediately indicate that this file contains unit tests for the `LayoutObject` class.

2. **Scan the test names:**  The test names provide high-level information about the features being tested. Look for recurring themes and keywords. Keywords like `DisplayContents`, `InlineWrapper`, `DumpLayoutObject`, `HasDistortingVisualEffects`, `TouchAction`, `HitTestForOcclusion`, `FirstLineBackgroundImage`, `NeedsScrollableOverflowRecalc`, `ContainValueIsRelayoutBoundary`, `Perspective`, `LocalToAncestorRect`, `SetNeedsCollectInlines`, and `RemovePendingTransformUpdates` stand out.

3. **Group related tests:**  Observe patterns in the test names to group them by functionality. For example, multiple tests deal with `DisplayContents` and `InlineWrapper`, suggesting this is a significant area of testing. Similarly, several tests involve `FirstLineBackgroundImage`.

4. **Infer the functionality being tested:** Based on the test names and the code snippets within each test, deduce what aspect of `LayoutObject` is being verified.
    * `DisplayContents`:  Tests how `display: contents` affects the layout tree, particularly regarding the creation and behavior of anonymous inline wrappers.
    * `DumpLayoutObject`: Verifies the debugging output of `LayoutObject`.
    * `HasDistortingVisualEffects`: Checks if the logic correctly identifies elements with visual effects that might require rasterization or other special handling.
    * `TouchAction`: Tests the integration of `touch-action` CSS property with event handling in iframes.
    * `HitTestForOcclusion`:  Confirms the accuracy of hit-testing logic, especially when elements are occluded or within iframes.
    * `FirstLineBackgroundImage`: Examines how background images on `::first-line` pseudo-elements are handled during style updates and invalidation.
    * `NeedsScrollableOverflowRecalc`: Verifies if changes to content correctly trigger recalculation of scrollable overflow.
    * `ContainValueIsRelayoutBoundary`: Checks if the `contain` CSS property correctly identifies relayout boundaries.
    * `Perspective`: Tests how the `perspective` CSS property interacts with transforms, especially in table layouts.
    * `LocalToAncestorRect`:  Verifies the conversion of coordinates between elements, considering scrolling.
    * `SetNeedsCollectInlines`:  Tests the mechanism for triggering inline layout collection for SVG elements.
    * `RemovePendingTransformUpdates`: Checks the proper handling of transform updates.

5. **Relate to web technologies:**  Connect the tested functionalities to JavaScript, HTML, and CSS. This involves understanding how these web standards manifest in the rendering engine. For instance, `display: contents` is a CSS property, and event handling is a core part of JavaScript interaction.

6. **Identify assumptions, inputs, and outputs:**  For tests involving logic, consider the initial HTML structure (input) and the expected state of the layout tree or specific properties (output) after certain actions are performed. For example, adding a `color` style to a `display: contents` element is expected to create an inline wrapper.

7. **Recognize common errors:** Consider the scenarios tested that might represent potential mistakes developers could make when using these features or edge cases the rendering engine needs to handle. For example, the tests for `FirstLineBackgroundImage` seem to focus on preventing crashes due to improper management of image resources during style changes.

8. **Focus on the specific part requested:** The prompt explicitly states "This is part 2," implying there are other parts. Therefore, the summary should focus on the functionalities covered in *this specific snippet*. Avoid drawing conclusions about the entire file unless the provided part offers a complete picture of a certain feature.

9. **Structure the summary:** Organize the findings logically, using clear headings and bullet points. Start with a general overview, then delve into specific functionalities.

10. **Refine and review:** Ensure the summary is accurate, concise, and easy to understand. Check for any ambiguities or technical jargon that might need clarification. For instance, explaining what an "anonymous inline wrapper" is in the context of `display: contents` is helpful.
这是提供的 `blink/renderer/core/layout/layout_object_test.cc` 源代码文件的第二部分，主要关注于 `LayoutObject` 的以下功能测试：

**功能归纳：**

* **`display: contents` 的行为和匿名内联盒子的创建:**  这部分深入测试了 CSS 属性 `display: contents` 的行为，特别是它如何影响布局树的结构。重点在于当一个元素的 `display` 属性被设置为 `contents` 时，该元素自身不会生成布局盒子，而是将其子节点“提升”到其父节点的布局上下文中。为了处理内联样式（如 `color`），会为文本节点创建匿名的内联盒子（anonymous inline wrapper）。测试覆盖了以下方面：
    * **是否创建匿名内联盒子：**  根据 `display: contents` 的元素上是否存在会影响内联样式的属性来判断是否创建匿名内联盒子。
    * **匿名内联盒子的生命周期：**  测试了添加和移除内联样式属性时，匿名内联盒子的创建和销毁。
    * **兄弟文本节点与匿名内联盒子：**  验证了兄弟文本节点不会共享同一个匿名内联盒子。
    * **`display: contents` 在表格布局中的行为：**  测试了在 `display: table`、`display: table-row-group`、`display: table-row` 和 `display: table-cell` 等表格相关元素上使用 `display: contents` 时，匿名内联盒子的创建和父子关系。

* **`DumpLayoutObject` 的调试输出:**  测试了 `LayoutObject` 的调试输出功能，验证了换行符和非 ASCII 字符是否被正确转义。同时测试了被销毁的 `LayoutObject` 的调试输出是否带有 `[DESTROYED]` 前缀。

* **SVG `g` 元素在 HTML 中的 `display: contents`:** 测试了当 SVG 的 `<g>` 元素的 `display` 属性被设置为 `contents` 时，其自身是否不会创建布局对象，并且其子节点（文本节点）也不会创建布局对象。

* **`HasDistortingVisualEffects` 的判断:** 测试了 `LayoutObject` 的 `HasDistortingVisualEffects` 方法，该方法用于判断元素是否具有可能导致视觉 искажения 的效果，例如 `opacity` 小于 1，`filter` 效果，`mix-blend-mode`，以及特定的 `transform` 属性（如 `rotate`）。

* **`DistortingVisualEffectsUnaliases` 的正确性:** 针对 `HasDistortingVisualEffects` 方法，测试了当父元素应用了 `opacity` 并且子元素设置了 `contain: paint` 时，子元素的 `HasDistortingVisualEffects` 应该返回 true，并且不会因为节点别名问题而导致断言失败。

* **祖先元素布局后更新可视矩形:** 测试了在祖先元素的布局发生变化后，子元素的视觉矩形是否能正确更新。

* **`TouchAction` 属性对子框架事件处理的影响:**  使用 `SimTest` 类模拟了页面加载和子框架交互，测试了在主框架和子框架上设置或移除 `touch-action` CSS 属性时，子框架的事件处理器注册表是否会正确更新。

* **iframe 中的遮挡测试 (`HitTestForOcclusion`):** 使用 `SimTest` 模拟了 iframe 环境，测试了当一个元素被另一个带有 `will-change: transform` 属性的元素遮挡时，`HitTestForOcclusion` 方法是否能正确返回遮挡元素。

* **`::first-line` 伪元素背景图的处理:**  使用 `SimTest` 模拟了页面加载，测试了当 `::first-line` 伪元素设置了背景图片时，图片资源的加载和更新如何影响布局对象的重绘。重点关注了图片资源变化时，是否会正确地标记需要重绘的布局对象，以及在相关元素被设置为 `display: none` 后，图片资源是否仍然存活。同时，测试了在各种场景下（嵌套元素、添加块级背景图、修改样式等）对 `::first-line` 背景图的处理，以避免潜在的崩溃问题。

* **`NeedsScrollableOverflowRecalc` 的触发:** 测试了修改元素内容是否会触发其父元素的 `NeedsScrollableOverflowRecalc` 标志，结论是修改子元素内容本身并不会直接触发父元素的滚动溢出重新计算。

* **`contain` 属性与重排边界:** 测试了 CSS 属性 `contain` 的不同值是否会使布局对象成为重排边界。

* **`perspective` 属性与变换:** 测试了 `perspective` 属性在普通元素和包含匿名表格元素的父元素上的效果，验证了子元素获取到的变换是否包含了正确的透视效果。

* **`LocalToAncestorRect` 的坐标转换:** 测试了 `LocalToAncestorRect` 方法在有滚动容器的情况下，如何将元素的局部矩形坐标转换为祖先元素的坐标，并验证了 `kIgnoreScrollOffset` 标志的作用，即忽略祖先元素的滚动偏移。

* **`SetNeedsCollectInlines` 对 SVG 元素的影响:** 测试了调用 SVG 文本元素或内联元素的 `SetNeedsCollectInlines` 方法后，其祖先元素是否也会被标记为需要收集内联布局信息。

* **移除待处理的变换更新:** 测试了在更新变换属性的同时设置元素的 `display: none`，是否能正确移除待处理的变换更新。

**与 JavaScript, HTML, CSS 的关系举例说明：**

* **HTML:**  大量的测试用例通过 `SetBodyInnerHTML` 函数设置 HTML 结构，这是测试的基础。例如，测试 `display: contents` 时，会创建包含特定 `id` 和样式的 `<div>` 元素。
* **CSS:** 测试直接关联到 CSS 属性，例如 `display: contents`, `color`, `opacity`, `filter`, `transform`, `touch-action`, `background-image`, `contain`, `perspective` 等。测试验证了这些 CSS 属性在 Blink 引擎中的具体实现行为。
* **JavaScript:** 虽然这部分代码主要是 C++ 测试，但它间接测试了当 JavaScript 修改 DOM 结构或样式时，布局引擎的反应。例如，通过 `div->SetInlineStyleProperty(CSSPropertyID::kColor, "pink");` 模拟了 JavaScript 修改元素样式，并验证了布局是否相应地更新（例如，创建匿名内联盒子）。`SimTest` 类模拟了页面加载和脚本执行环境。

**逻辑推理的假设输入与输出举例:**

* **假设输入:**  一个 `<div>` 元素，其 `style` 属性设置为 `display:contents;color:pink`，并且包含一个文本子节点 "A"。
* **预期输出:**  会为文本节点 "A" 创建一个匿名的 `LayoutInline` 类型的布局对象（匿名内联盒子），因为 `color: pink` 是一个会影响内联样式的属性。

**用户或编程常见的使用错误举例:**

* **错误使用 `display: contents`:**  开发者可能错误地认为将一个容器元素的 `display` 设置为 `contents` 会使其完全消失，而忽略了其子元素会“提升”到父元素的布局上下文中。这可能导致意外的布局效果，尤其是在涉及到样式继承和定位时。例如，如果一个设置了 `display: contents` 的 `div` 有背景色，这个背景色不会显示，因为该 `div` 本身不生成布局盒子。
* **不理解 `touch-action` 对事件的影响:** 开发者可能没有意识到在 iframe 或其内部元素上设置 `touch-action: none` 会阻止默认的触摸行为，这可能影响到页面的可交互性。测试用例验证了 Blink 引擎在这种情况下会正确处理事件监听器的添加和移除。

总而言之，这部分测试专注于验证 Blink 引擎中 `LayoutObject` 类的核心功能，特别是与 CSS 属性 `display: contents` 相关的布局行为，以及其他重要的渲染特性如调试输出、视觉效果判断、事件处理、背景图处理和坐标转换等。这些测试确保了 Blink 引擎能够正确地解析和渲染 HTML 和 CSS，并处理各种复杂的布局场景。

### 提示词
```
这是目录为blink/renderer/core/layout/layout_object_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
;

  const auto* layout_object0 =
      To<LayoutTextFragment>(AssociatedLayoutObjectOf(*text, 0));
  EXPECT_FALSE(layout_object0->IsRemainingTextLayoutObject());

  const auto* layout_object1 =
      To<LayoutTextFragment>(AssociatedLayoutObjectOf(*text, 1));
  EXPECT_TRUE(layout_object1->IsRemainingTextLayoutObject());

  const auto* layout_object2 =
      To<LayoutTextFragment>(AssociatedLayoutObjectOf(*text, 2));
  EXPECT_EQ(layout_object1, layout_object2);
}

TEST_F(LayoutObjectTest, DisplayContentsInlineWrapper) {
  SetBodyInnerHTML("<div id='div' style='display:contents;color:pink'>A</div>");
  Element* div = GetElementById("div");
  ASSERT_TRUE(div);
  Node* text = div->firstChild();
  ASSERT_TRUE(text);
  ExpectAnonymousInlineWrapperFor<true>(text);
}

TEST_F(LayoutObjectTest, DisplayContentsNoInlineWrapper) {
  SetBodyInnerHTML("<div id='div' style='display:contents'>A</div>");
  Element* div = GetElementById("div");
  ASSERT_TRUE(div);
  Node* text = div->firstChild();
  ASSERT_TRUE(text);
  ExpectAnonymousInlineWrapperFor<false>(text);
}

TEST_F(LayoutObjectTest, DisplayContentsAddInlineWrapper) {
  SetBodyInnerHTML("<div id='div' style='display:contents'>A</div>");
  Element* div = GetElementById("div");
  ASSERT_TRUE(div);
  Node* text = div->firstChild();
  ASSERT_TRUE(text);
  ExpectAnonymousInlineWrapperFor<false>(text);

  div->SetInlineStyleProperty(CSSPropertyID::kColor, "pink");
  UpdateAllLifecyclePhasesForTest();
  ExpectAnonymousInlineWrapperFor<true>(text);
}

TEST_F(LayoutObjectTest, DisplayContentsRemoveInlineWrapper) {
  SetBodyInnerHTML("<div id='div' style='display:contents;color:pink'>A</div>");
  Element* div = GetElementById("div");
  ASSERT_TRUE(div);
  Node* text = div->firstChild();
  ASSERT_TRUE(text);
  ExpectAnonymousInlineWrapperFor<true>(text);

  div->RemoveInlineStyleProperty(CSSPropertyID::kColor);
  UpdateAllLifecyclePhasesForTest();
  ExpectAnonymousInlineWrapperFor<false>(text);
}

TEST_F(LayoutObjectTest, DisplayContentsWrapperPerTextNode) {
  // This test checks the current implementation; that text node siblings do not
  // share inline wrappers. Doing so requires code to handle all situations
  // where text nodes are no longer layout tree siblings by splitting wrappers,
  // and merge wrappers when text nodes become layout tree siblings.
  SetBodyInnerHTML(
      "<div id='div' style='display:contents;color:pink'>A<!-- -->B</div>");
  Element* div = GetElementById("div");
  ASSERT_TRUE(div);
  Node* text1 = div->firstChild();
  ASSERT_TRUE(text1);
  Node* text2 = div->lastChild();
  ASSERT_TRUE(text2);
  EXPECT_NE(text1, text2);

  ExpectAnonymousInlineWrapperFor<true>(text1);
  ExpectAnonymousInlineWrapperFor<true>(text2);

  EXPECT_NE(text1->GetLayoutObject()->Parent(),
            text2->GetLayoutObject()->Parent());
}

TEST_F(LayoutObjectTest, DisplayContentsWrapperInTable) {
  SetBodyInnerHTML(R"HTML(
    <div id='table' style='display:table'>
      <div id='none' style='display:none'></div>
      <div id='contents' style='display:contents;color:green'>Green</div>
    </div>
  )HTML");

  Element* none = GetElementById("none");
  Element* contents = GetElementById("contents");

  ExpectAnonymousInlineWrapperFor<true>(contents->firstChild());

  none->SetInlineStyleProperty(CSSPropertyID::kDisplay, "inline");
  UpdateAllLifecyclePhasesForTest();
  ASSERT_TRUE(none->GetLayoutObject());
  LayoutObject* inline_parent = none->GetLayoutObject()->Parent();
  ASSERT_TRUE(inline_parent);
  LayoutObject* wrapper_parent =
      contents->firstChild()->GetLayoutObject()->Parent()->Parent();
  ASSERT_TRUE(wrapper_parent);
  EXPECT_EQ(wrapper_parent, inline_parent);
  EXPECT_TRUE(inline_parent->IsTableCell());
  EXPECT_TRUE(inline_parent->IsAnonymous());
}

TEST_F(LayoutObjectTest, DisplayContentsWrapperInTableSection) {
  SetBodyInnerHTML(R"HTML(
    <div id='section' style='display:table-row-group'>
      <div id='none' style='display:none'></div>
      <div id='contents' style='display:contents;color:green'>Green</div>
    </div>
  )HTML");

  Element* none = GetElementById("none");
  Element* contents = GetElementById("contents");

  ExpectAnonymousInlineWrapperFor<true>(contents->firstChild());

  none->SetInlineStyleProperty(CSSPropertyID::kDisplay, "inline");
  UpdateAllLifecyclePhasesForTest();
  ASSERT_TRUE(none->GetLayoutObject());
  LayoutObject* inline_parent = none->GetLayoutObject()->Parent();
  ASSERT_TRUE(inline_parent);
  LayoutObject* wrapper_parent =
      contents->firstChild()->GetLayoutObject()->Parent()->Parent();
  ASSERT_TRUE(wrapper_parent);
  EXPECT_EQ(wrapper_parent, inline_parent);
  EXPECT_TRUE(inline_parent->IsTableCell());
  EXPECT_TRUE(inline_parent->IsAnonymous());
}

TEST_F(LayoutObjectTest, DisplayContentsWrapperInTableRow) {
  SetBodyInnerHTML(R"HTML(
    <div id='row' style='display:table-row'>
      <div id='none' style='display:none'></div>
      <div id='contents' style='display:contents;color:green'>Green</div>
    </div>
  )HTML");

  Element* none = GetElementById("none");
  Element* contents = GetElementById("contents");

  ExpectAnonymousInlineWrapperFor<true>(contents->firstChild());

  none->SetInlineStyleProperty(CSSPropertyID::kDisplay, "inline");
  UpdateAllLifecyclePhasesForTest();
  ASSERT_TRUE(none->GetLayoutObject());
  LayoutObject* inline_parent = none->GetLayoutObject()->Parent();
  ASSERT_TRUE(inline_parent);
  LayoutObject* wrapper_parent =
      contents->firstChild()->GetLayoutObject()->Parent()->Parent();
  ASSERT_TRUE(wrapper_parent);
  EXPECT_EQ(wrapper_parent, inline_parent);
  EXPECT_TRUE(inline_parent->IsTableCell());
  EXPECT_TRUE(inline_parent->IsAnonymous());
}

TEST_F(LayoutObjectTest, DisplayContentsWrapperInTableCell) {
  SetBodyInnerHTML(R"HTML(
    <div id='cell' style='display:table-cell'>
      <div id='none' style='display:none'></div>
      <div id='contents' style='display:contents;color:green'>Green</div>
    </div>
  )HTML");

  Element* cell = GetElementById("cell");
  Element* none = GetElementById("none");
  Element* contents = GetElementById("contents");

  ExpectAnonymousInlineWrapperFor<true>(contents->firstChild());

  none->SetInlineStyleProperty(CSSPropertyID::kDisplay, "inline");
  UpdateAllLifecyclePhasesForTest();
  ASSERT_TRUE(none->GetLayoutObject());
  EXPECT_EQ(cell->GetLayoutObject(), none->GetLayoutObject()->Parent());
}

#if DCHECK_IS_ON()
TEST_F(LayoutObjectTest, DumpLayoutObject) {
  // Test dumping for debugging, in particular that newlines and non-ASCII
  // characters are escaped as expected.
  SetBodyInnerHTML(String::FromUTF8(R"HTML(
    <div id='block' style='background:
lime'>
      testing Среќен роденден
</div>
  )HTML"));

  LayoutObject* block = GetLayoutObjectByElementId("block");
  ASSERT_TRUE(block);
  LayoutObject* text = block->SlowFirstChild();
  ASSERT_TRUE(text);

  StringBuilder result;
  block->DumpLayoutObject(result, false, 0);
  EXPECT_THAT(result.ToString().Utf8(),
              MatchesRegex(
                  "LayoutN?G?BlockFlow \\(children-inline\\)\tDIV id=\"block\" "
                  "style=\"background:\\\\nlime\""));

  result.Clear();
  text->DumpLayoutObject(result, false, 0);
  EXPECT_EQ(
      result.ToString(),
      String("LayoutText\t#text \"\\n      testing "
             "\\u0421\\u0440\\u0435\\u045C\\u0435\\u043D "
             "\\u0440\\u043E\\u0434\\u0435\\u043D\\u0434\\u0435\\u043D\\n\""));
}

TEST_F(LayoutObjectTest, DumpDestroyedLayoutObject) {
  SetBodyInnerHTML(R"HTML(
    <div id="target"></div>
  )HTML");

  Element* element = GetElementById("target");
  LayoutObject* layout_object = element->GetLayoutObject();
  StringBuilder builder;
  layout_object->DumpLayoutObject(builder, false, 0);
  String result = builder.ToString();
  EXPECT_FALSE(result.StartsWith("[DESTROYED] "));

  element->remove();
  UpdateAllLifecyclePhasesForTest();
  builder.Clear();
  layout_object->DumpLayoutObject(builder, false, 0);
  result = builder.ToString();
  EXPECT_TRUE(result.StartsWith("[DESTROYED] "));
}
#endif  // DCHECK_IS_ON()

TEST_F(LayoutObjectTest, DisplayContentsSVGGElementInHTML) {
  SetBodyInnerHTML(R"HTML(
    <style>*|g { display:contents}</style>
    <span id=span></span>
  )HTML");

  Element* span = GetElementById("span");
  auto* svg_element = MakeGarbageCollected<SVGGElement>(GetDocument());
  Text* text = Text::Create(GetDocument(), "text");
  svg_element->appendChild(text);
  span->appendChild(svg_element);

  UpdateAllLifecyclePhasesForTest();

  ASSERT_FALSE(svg_element->GetLayoutObject());
  ASSERT_FALSE(text->GetLayoutObject());
}

TEST_F(LayoutObjectTest, HasDistortingVisualEffects) {
  SetBodyInnerHTML(R"HTML(
    <div id=opaque style='opacity:1'><div class=inner></div></div>
    <div id=transparent style='opacity:0.99'><div class=inner></div></div>
    <div id=blurred style='filter:blur(5px)'><div class=inner></div></div>
    <div id=blended style='mix-blend-mode:hue'><div class=inner></div></div>
    <div id=good-transform style='transform:translateX(10px) scale(1.6)'>
      <div class=inner></div>
    </div>
    <div id=bad-transform style='transform:rotate(45deg)'>
      <div class=inner></div>
    </div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  Element* outer = GetElementById("opaque");
  Element* inner = outer->QuerySelector(AtomicString(".inner"));
  ASSERT_FALSE(inner->GetLayoutObject()->HasDistortingVisualEffects());

  outer = GetElementById("transparent");
  inner = outer->QuerySelector(AtomicString(".inner"));
  ASSERT_TRUE(inner->GetLayoutObject()->HasDistortingVisualEffects());

  outer = GetElementById("blurred");
  inner = outer->QuerySelector(AtomicString(".inner"));
  ASSERT_TRUE(inner->GetLayoutObject()->HasDistortingVisualEffects());

  outer = GetElementById("blended");
  inner = outer->QuerySelector(AtomicString(".inner"));
  ASSERT_TRUE(inner->GetLayoutObject()->HasDistortingVisualEffects());

  outer = GetElementById("good-transform");
  inner = outer->QuerySelector(AtomicString(".inner"));
  ASSERT_FALSE(inner->GetLayoutObject()->HasDistortingVisualEffects());

  outer = GetElementById("bad-transform");
  inner = outer->QuerySelector(AtomicString(".inner"));
  ASSERT_TRUE(inner->GetLayoutObject()->HasDistortingVisualEffects());
}

TEST_F(LayoutObjectTest, DistortingVisualEffectsUnaliases) {
  SetBodyInnerHTML(R"HTML(
    <div style="opacity: 0.2;">
      <div style="width: 100px height:100px; contain: paint">
        <div id="child"
             style="position: relative; width: 100px; height:100px;"></div>
      </div>
    </div>
  )HTML");

  const auto* child = GetElementById("child");
  const auto* object = child->GetLayoutObject();
  // This should pass and not DCHECK if the nodes are unaliased correctly.
  EXPECT_TRUE(object->HasDistortingVisualEffects());
  EXPECT_TRUE(object->HasNonZeroEffectiveOpacity());
}

TEST_F(LayoutObjectTest, UpdateVisualRectAfterAncestorLayout) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #target {
        width: 50px;
        height: 0;
        position: relative;
      }
    </style>
    <div id=ancestor style="width: 100px; height: 100px; position: relative">
      <div>
        <div id=target></div>
      </div>
    </div>
  )HTML");

  auto* target = GetElementById("target");
  target->setAttribute(html_names::kStyleAttr, AtomicString("height: 300px"));
  UpdateAllLifecyclePhasesForTest();
  const auto* container = GetLayoutBoxByElementId("ancestor");
  EXPECT_EQ(PhysicalRect(0, 0, 100, 300), container->VisualOverflowRect());
}

class LayoutObjectSimTest : public SimTest {
 public:
  bool DocumentHasTouchActionRegion(const EventHandlerRegistry& registry) {
    GetDocument().View()->UpdateAllLifecyclePhasesForTest();
    return registry.HasEventHandlers(
        EventHandlerRegistry::EventHandlerClass::kTouchAction);
  }

 protected:
  static HitTestResult HitTestForOcclusion(const Element& target) {
    const LayoutObject* object = target.GetLayoutObject();
    return object->HitTestForOcclusion(VisualRectInDocument(*object));
  }
};

TEST_F(LayoutObjectSimTest, TouchActionUpdatesSubframeEventHandler) {
  SimRequest main_resource("https://example.com/test.html", "text/html");
  SimRequest frame_resource("https://example.com/frame.html", "text/html");

  LoadURL("https://example.com/test.html");
  main_resource.Complete(
      "<!DOCTYPE html>"
      "<div id='container'>"
      "<iframe src=frame.html></iframe>"
      "</div>");
  frame_resource.Complete(
      "<!DOCTYPE html>"
      "<html><body>"
      "<div id='inner'></div>"
      "</body></html>");

  Element* iframe_element = GetDocument().QuerySelector(AtomicString("iframe"));
  auto* frame_owner_element = To<HTMLFrameOwnerElement>(iframe_element);
  Document* iframe_doc = frame_owner_element->contentDocument();
  Element* inner = iframe_doc->getElementById(AtomicString("inner"));
  Element* iframe_doc_element = iframe_doc->documentElement();
  Element* container = GetDocument().getElementById(AtomicString("container"));

  EventHandlerRegistry& registry =
      iframe_doc->GetFrame()->GetEventHandlerRegistry();

  // We should add event handler if touch action is set on subframe.
  inner->setAttribute(html_names::kStyleAttr,
                      AtomicString("touch-action: none"));
  EXPECT_TRUE(DocumentHasTouchActionRegion(registry));

  // We should remove event handler if touch action is removed on subframe.
  inner->setAttribute(html_names::kStyleAttr,
                      AtomicString("touch-action: auto"));
  EXPECT_FALSE(DocumentHasTouchActionRegion(registry));

  // We should add event handler if touch action is set on main frame.
  container->setAttribute(html_names::kStyleAttr,
                          AtomicString("touch-action: none"));
  EXPECT_TRUE(DocumentHasTouchActionRegion(registry));

  // We should keep event handler if touch action is set on subframe document
  // element.
  iframe_doc_element->setAttribute(html_names::kStyleAttr,
                                   AtomicString("touch-action: none"));
  EXPECT_TRUE(DocumentHasTouchActionRegion(registry));

  // We should keep the event handler if touch action is removed on subframe
  // document element.
  iframe_doc_element->setAttribute(html_names::kStyleAttr,
                                   AtomicString("touch-action: auto"));
  EXPECT_TRUE(DocumentHasTouchActionRegion(registry));

  // We should remove the handler if touch action is removed on main frame.
  container->setAttribute(html_names::kStyleAttr,
                          AtomicString("touch-action: auto"));
  EXPECT_FALSE(DocumentHasTouchActionRegion(registry));
}

TEST_F(LayoutObjectSimTest, HitTestForOcclusionInIframe) {
  SimRequest main_resource("https://example.com/test.html", "text/html");
  SimRequest frame_resource("https://example.com/frame.html", "text/html");

  LoadURL("https://example.com/test.html");
  main_resource.Complete(R"HTML(
    <iframe style='width:300px;height:150px;' src=frame.html></iframe>
    <div id='occluder' style='will-change:transform;width:100px;height:100px;'>
    </div>
  )HTML");
  frame_resource.Complete(R"HTML(
    <div id='target'>target</div>
  )HTML");

  GetDocument().View()->UpdateAllLifecyclePhasesForTest();
  Element* iframe_element = GetDocument().QuerySelector(AtomicString("iframe"));
  auto* frame_owner_element = To<HTMLFrameOwnerElement>(iframe_element);
  Document* iframe_doc = frame_owner_element->contentDocument();
  Element* target = iframe_doc->getElementById(AtomicString("target"));
  HitTestResult result = HitTestForOcclusion(*target);
  EXPECT_EQ(result.InnerNode(), target);

  Element* occluder = GetDocument().getElementById(AtomicString("occluder"));
  occluder->SetInlineStyleProperty(CSSPropertyID::kMarginTop, "-150px");
  GetDocument().View()->UpdateAllLifecyclePhasesForTest();
  result = HitTestForOcclusion(*target);
  EXPECT_EQ(result.InnerNode(), occluder);
}

TEST_F(LayoutObjectSimTest, FirstLineBackgroundImage) {
  SimRequest main_resource("https://example.com/test.html", "text/html");

  LoadURL("https://example.com/test.html");
  main_resource.Complete(R"HTML(
    <style>
      div::first-line {
        background-image: url(data:image/gif;base64,R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw==);
      }
      span { background: rgba(0, 255, 0, 0.3); }
    </style>
    <div id="target">
      <span id="first-line1">Text</span><span id="first-line2">Text</span><br>
      <span id="second-line">Text</span>
    </div>
    <div>To keep the image alive when target is set display: none</div>
  )HTML");

  GetDocument().View()->UpdateAllLifecyclePhasesForTest();

  auto* target = GetDocument().getElementById(AtomicString("target"));
  auto* target_object = target->GetLayoutObject();
  auto* image_resource_content = target_object->FirstLineStyleRef()
                                     .BackgroundLayers()
                                     .GetImage()
                                     ->CachedImage();

  // Simulate an image change notification, and we should invalidate the objects
  // in the first line.
  static_cast<ImageObserver*>(image_resource_content)
      ->Changed(image_resource_content->GetImage());

  // The block is the layout object of the first line's root line box, so we
  // invalidate it.
  EXPECT_TRUE(target_object->ShouldDoFullPaintInvalidation());

  auto* first_line1 = GetDocument()
                          .getElementById(AtomicString("first-line1"))
                          ->GetLayoutObject();
  EXPECT_TRUE(first_line1->ShouldDoFullPaintInvalidation());
  EXPECT_TRUE(first_line1->SlowFirstChild()->ShouldDoFullPaintInvalidation());
  auto* first_line2 = GetDocument()
                          .getElementById(AtomicString("first-line2"))
                          ->GetLayoutObject();
  EXPECT_TRUE(first_line2->ShouldDoFullPaintInvalidation());
  EXPECT_TRUE(first_line2->SlowFirstChild()->ShouldDoFullPaintInvalidation());
  auto* second_line = GetDocument()
                          .getElementById(AtomicString("second-line"))
                          ->GetLayoutObject();
  EXPECT_FALSE(second_line->ShouldDoFullPaintInvalidation());
  EXPECT_FALSE(second_line->SlowFirstChild()->ShouldDoFullPaintInvalidation());

  target->setAttribute(html_names::kStyleAttr, AtomicString("display: none"));
  GetDocument().View()->UpdateAllLifecyclePhasesForTest();
  target_object = target->GetLayoutObject();
  EXPECT_EQ(nullptr, target_object);
  // The image is still alive because the other div's first line style still
  // reference it. The following statement should not crash.
  static_cast<ImageObserver*>(image_resource_content)
      ->Changed(image_resource_content->GetImage());
}

TEST_F(LayoutObjectTest, FirstLineBackgroundImageNestedCrash) {
  SetBodyInnerHTML(R"HTML(
    <style>
      *::first-line { background-image: linear-gradient(red, blue); }
    </style>
    <div><span><div>ABCDE</div></span></div>
  )HTML");

  // The following code should not crash due to incorrectly paired
  // StyleImage::AddClient() and RemoveClient().
  GetDocument().documentElement()->setAttribute(html_names::kStyleAttr,
                                                AtomicString("display: none"));
  UpdateAllLifecyclePhasesForTest();
}

TEST_F(LayoutObjectTest, FirstLineBackgroundImageAddBlockBackgroundImageCrash) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #target::first-line { background-image: linear-gradient(red, blue); }
    </style>
    <div id="target"></div>
  )HTML");

  // The following code should not crash due to incorrectly paired
  // StyleImage::AddClient() and RemoveClient().
  GetElementById("target")->setAttribute(
      html_names::kStyleAttr,
      AtomicString("background-image: url(data:image/gif;base64,"
                   "R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw==)"));
  UpdateAllLifecyclePhasesForTest();
}

TEST_F(LayoutObjectTest, FirstLineBackgroundImageChangeStyleCrash) {
  SetBodyInnerHTML(R"HTML(
    <style id="style">
      #target::first-line {
        background-image: url(data:image/gif;base64,R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw==);
      }
    </style>
    <div id="target">Target</div>
  )HTML");

  // These should not crash.
  GetElementById("target")->setAttribute(html_names::kStyleAttr,
                                         AtomicString("color: blue"));
  UpdateAllLifecyclePhasesForTest();

  GetElementById("target")->setAttribute(html_names::kStyleAttr,
                                         AtomicString("display: none"));
  UpdateAllLifecyclePhasesForTest();

  auto* style_element = GetElementById("style");
  style_element->setTextContent(style_element->textContent() + "dummy");
  UpdateAllLifecyclePhasesForTest();
}

TEST_F(LayoutObjectSimTest, FirstLineBackgroundImageDirtyStyleCrash) {
  SimRequest main_resource("https://example.com/test.html", "text/html");

  LoadURL("https://example.com/test.html");
  main_resource.Complete(R"HTML(
    <style id="style">
      #target { display: list-item; }
      div::first-line {
        background-image: url(data:image/gif;base64,R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw==);
      }
    </style>
    <div id="target">Text</div>
  )HTML");

  GetDocument().View()->UpdateAllLifecyclePhasesForTest();

  CSSStyleSheet* sheet =
      To<HTMLStyleElement>(GetDocument().getElementById(AtomicString("style")))
          ->sheet();
  {
    // "Mutate" the rules to clear the StyleSheetContents RuleSet member.
    CSSStyleSheet::RuleMutationScope scope(sheet);
  }
  EXPECT_FALSE(sheet->Contents()->HasRuleSet());

  auto* target = GetDocument().getElementById(AtomicString("target"));
  auto* target_object = target->GetLayoutObject();
  auto* image_resource_content = target_object->FirstLineStyleRef()
                                     .BackgroundLayers()
                                     .GetImage()
                                     ->CachedImage();
  auto* image = image_resource_content->GetImage();
  auto* image_observer = static_cast<ImageObserver*>(image_resource_content);

  // LayoutBlock::ImageChanged() will be triggered which makes us look up the
  // ::first-line style before marking for paint invalidation. We should not try
  // to compute style if it doesn't exist. The first invocation will mark for
  // paint invalidation which will clear the cached ::first-line styles.
  image_observer->Changed(image);
  EXPECT_TRUE(target_object->ShouldDoFullPaintInvalidation());

  // For the second invocation, the ::first-line styles is null. If we try to
  // compute the styles here, we will crash since the RuleSet is null and we
  // need an active style update.
  image_observer->Changed(image);
  EXPECT_TRUE(target_object->ShouldDoFullPaintInvalidation());
}

TEST_F(LayoutObjectTest, NeedsScrollableOverflowRecalc) {
  SetBodyInnerHTML(R"HTML(
    <div id='wrapper'>
      <div id='target'>foo</div>
      <div id='other'>bar</div>
    </div>
  )HTML");

  auto* wrapper = GetLayoutObjectByElementId("wrapper");
  auto* target = GetLayoutObjectByElementId("target");
  auto* other = GetLayoutObjectByElementId("other");

  DCHECK(wrapper);
  DCHECK(target);
  DCHECK(other);

  EXPECT_FALSE(wrapper->NeedsScrollableOverflowRecalc());
  EXPECT_FALSE(target->NeedsScrollableOverflowRecalc());
  EXPECT_FALSE(other->NeedsScrollableOverflowRecalc());

  auto* target_element = GetElementById("target");
  target_element->setInnerHTML("baz");
  UpdateAllLifecyclePhasesForTest();

  EXPECT_FALSE(wrapper->NeedsScrollableOverflowRecalc());
  EXPECT_FALSE(target->NeedsScrollableOverflowRecalc());
  EXPECT_FALSE(other->NeedsScrollableOverflowRecalc());
}

TEST_F(LayoutObjectTest, ContainValueIsRelayoutBoundary) {
  SetBodyInnerHTML(R"HTML(
    <div id='target1' style='contain:layout'></div>
    <div id='target2' style='contain:layout size'></div>
    <div id='target3' style='contain:paint'></div>
    <div id='target4' style='contain:size'></div>
    <div id='target5' style='contain:content'></div>
    <div id='target6' style='contain:strict'></div>
  )HTML");
  EXPECT_FALSE(GetLayoutObjectByElementId("target1")->IsRelayoutBoundary());
  EXPECT_TRUE(GetLayoutObjectByElementId("target2")->IsRelayoutBoundary());
  EXPECT_FALSE(GetLayoutObjectByElementId("target3")->IsRelayoutBoundary());
  EXPECT_FALSE(GetLayoutObjectByElementId("target4")->IsRelayoutBoundary());
  EXPECT_FALSE(GetLayoutObjectByElementId("target5")->IsRelayoutBoundary());
  EXPECT_TRUE(GetLayoutObjectByElementId("target6")->IsRelayoutBoundary());
}

TEST_F(LayoutObjectTest, PerspectiveIsNotParent) {
  GetDocument().SetBaseURLOverride(KURL("http://test.com"));
  SetBodyInnerHTML(R"HTML(
    <style>body { margin:0; }</style>
    <div id='ancestor' style='perspective: 100px'>
      <div>
        <div id='child' style='width: 10px; height: 10px; transform: rotateY(45deg);
        position: absolute'></div>
      </div>
    </div>
  )HTML");

  auto* ancestor = GetLayoutBoxByElementId("ancestor");
  auto* child = GetLayoutBoxByElementId("child");

  gfx::Transform transform;
  child->GetTransformFromContainer(ancestor, PhysicalOffset(), transform);
  std::optional<gfx::DecomposedTransform> decomp = transform.Decompose();
  ASSERT_TRUE(decomp);
  EXPECT_EQ(0, decomp->perspective[2]);
}

TEST_F(LayoutObjectTest, PerspectiveWithAnonymousTable) {
  SetBodyInnerHTML(R"HTML(
    <style>body { margin:0; }</style>
    <div id='ancestor' style='display: table; perspective: 100px; width: 100px; height: 100px;'>
      <div id='child' style='display: table-cell; width: 100px; height: 100px; transform: rotateY(45deg);
        position: absolute'></div>
    </table>
  )HTML");

  LayoutObject* child = GetLayoutObjectByElementId("child");
  auto* ancestor =
      To<LayoutBoxModelObject>(GetLayoutObjectByElementId("ancestor"));

  gfx::Transform transform;
  child->GetTransformFromContainer(ancestor, PhysicalOffset(), transform);
  std::optional<gfx::DecomposedTransform> decomp = transform.Decompose();
  ASSERT_TRUE(decomp);
  EXPECT_EQ(-0.01, decomp->perspective[2]);
}

TEST_F(LayoutObjectTest, LocalToAncestoRectIgnoreAncestorScroll) {
  SetBodyInnerHTML(R"HTML(
    <style>body { margin:0; }</style>
    <div id=ancestor style="overflow:scroll; width: 100px; height: 100px">
      <div style="height: 2000px"></div>
      <div id="target" style="width: 100px; height: 100px"></div>
    </div>
    )HTML");

  LayoutObject* target = GetLayoutObjectByElementId("target");
  LayoutBoxModelObject* ancestor =
      To<LayoutBoxModelObject>(GetLayoutObjectByElementId("ancestor"));
  ancestor->GetScrollableArea()->ScrollBy(ScrollOffset(0, 100),
                                          mojom::blink::ScrollType::kUser);
  UpdateAllLifecyclePhasesForTest();

  PhysicalRect rect(0, 0, 100, 100);

  EXPECT_EQ(PhysicalRect(0, 2000, 100, 100),
            target->LocalToAncestorRect(rect, ancestor, kIgnoreScrollOffset));

  EXPECT_EQ(PhysicalRect(0, 1900, 100, 100),
            target->LocalToAncestorRect(rect, ancestor, 0));
}

TEST_F(LayoutObjectTest, LocalToAncestoRectViewIgnoreAncestorScroll) {
  SetBodyInnerHTML(R"HTML(
    <style>body { margin:0; }</style>
    <div style="height: 2000px"></div>
    <div id="target" style="width: 100px; height: 100px"></div>
    )HTML");

  LayoutObject* target = GetLayoutObjectByElementId("target");
  GetDocument().View()->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, 100), mojom::blink::ScrollType::kProgrammatic);
  UpdateAllLifecyclePhasesForTest();

  PhysicalRect rect(0, 0, 100, 100);

  EXPECT_EQ(PhysicalRect(0, 2000, 100, 100),
            target->LocalToAncestorRect(rect, nullptr, kIgnoreScrollOffset));

  EXPECT_EQ(PhysicalRect(0, 1900, 100, 100),
            target->LocalToAncestorRect(rect, nullptr, 0));
}

TEST_F(LayoutObjectTest,
       LocalToAncestoRectIgnoreAncestorScrollIntermediateScroller) {
  SetBodyInnerHTML(R"HTML(
    <style>body { margin:0; }</style>
    <div id=ancestor style="overflow:scroll; width: 100px; height: 100px">
      <div id=intermediate style="overflow:scroll; width: 100px; height: 100px">
        <div style="height: 2000px"></div>
        <div id="target" style="width: 100px; height: 100px"></div>
      </div>
      <div style="height: 2000px"></div>
    </div>
    )HTML");

  LayoutObject* target = GetLayoutObjectByElementId("target");
  LayoutBoxModelObject* ancestor =
      To<LayoutBoxModelObject>(GetLayoutObjectByElementId("ancestor"));
  LayoutBoxModelObject* intermediate =
      To<LayoutBoxModelObject>(GetLayoutObjectByElementId("intermediate"));
  ancestor->GetScrollableArea()->ScrollBy(ScrollOffset(0, 100),
                                          mojom::blink::ScrollType::kUser);
  intermediate->GetScrollableArea()->ScrollBy(ScrollOffset(0, 100),
                                              mojom::blink::ScrollType::kUser);
  UpdateAllLifecyclePhasesForTest();

  PhysicalRect rect(0, 0, 100, 100);

  EXPECT_EQ(PhysicalRect(0, 2000, 100, 100),
            target->LocalToAncestorRect(rect, ancestor, kIgnoreScrollOffset));

  EXPECT_EQ(PhysicalRect(0, 1800, 100, 100),
            target->LocalToAncestorRect(rect, ancestor, 0));
}

TEST_F(LayoutObjectTest,
       LocalToAncestoRectViewIgnoreAncestorScrollIntermediateScroller) {
  SetBodyInnerHTML(R"HTML(
    <style>body { margin:0; }</style>
    <div id=intermediate style="overflow:scroll; width: 100px; height: 100px">
      <div style="height: 2000px"></div>
      <div id="target" style="width: 100px; height: 100px"></div>
    </div>
    <div style="height: 2000px"></div>
    )HTML");

  LayoutObject* target = GetLayoutObjectByElementId("target");
  LayoutBoxModelObject* intermediate =
      To<LayoutBoxModelObject>(GetLayoutObjectByElementId("intermediate"));
  GetDocument().View()->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, 100), mojom::blink::ScrollType::kProgrammatic);
  intermediate->GetScrollableArea()->ScrollBy(ScrollOffset(0, 100),
                                              mojom::blink::ScrollType::kUser);
  UpdateAllLifecyclePhasesForTest();

  PhysicalRect rect(0, 0, 100, 100);

  EXPECT_EQ(PhysicalRect(0, 2000, 100, 100),
            target->LocalToAncestorRect(rect, nullptr, kIgnoreScrollOffset));

  EXPECT_EQ(PhysicalRect(0, 1800, 100, 100),
            target->LocalToAncestorRect(rect, nullptr, 0));
}

// crbug.com/1246619
TEST_F(LayoutObjectTest, SetNeedsCollectInlinesForSvgText) {
  SetBodyInnerHTML(R"HTML(
    <div>
    <svg xmlns="http://www.w3.org/2000/svg" id="ancestor">
    <text id="text">Internet</text>
    </svg></div>)HTML");
  UpdateAllLifecyclePhasesForTest();

  auto* text = GetLayoutObjectByElementId("text");
  if (text->IsSVGText()) {
    text->SetNeedsCollectInlines();
    EXPECT_TRUE(GetLayoutObjectByElementId("ancestor")->NeedsCollectInlines());
  }
}

// crbug.com/1247686
TEST_F(LayoutObjectTest, SetNeedsCollectInlinesForSvgInline) {
  SetBodyInnerHTML(R"HTML(
    <div>
    <svg xmlns="http://www.w3.org/2000/svg" id="ancestor">
    <text id="text">Inter<a id="anchor">net</a></text>
    </svg></div>)HTML");
  UpdateAllLifecyclePhasesForTest();

  auto* anchor = GetLayoutObjectByElementId("anchor");
  anchor->SetNeedsCollectInlines();
  EXPECT_TRUE(GetLayoutObjectByElementId("text")->NeedsCollectInlines());
}

TEST_F(LayoutObjectTest, RemovePendingTransformUpdatesCorrectly) {
  SetBodyInnerHTML(R"HTML(
  <div id="div1" style="transform:translateX(100px)">
  </div>
  <div id="div2" style="transform:translateX(100px)">
  </div>
      )HTML");

  auto* div2 = GetElementById("div2");
  div2->setAttribute(html_names::kStyleAttr,
                     AtomicString("transform: translateX(200px)"));
  GetDocument().View()->UpdateLifecycleToLayoutClean(
      DocumentUpdateReason::kTest);

  auto* div1 = GetElementById("div1");
  div1->setAttribute(html_names::kStyleAttr,
                     AtomicString("transform: translateX(200px)"));
  div2->SetInlineStyleProperty(CSSPropertyID::kDisplay, "none");
  UpdateAllLifecyclePhasesForTest();
}

static const char* const kTransformsWith3D[] = {"transform: rotateX(20deg)",
                                                "transform: translateZ(30px)"};
static const char kTransformWithout3D[] =
    "transform: matrix(2, 2, 0, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 0, 2)";
static const char kPreserve3D[] = "transform-style: preserve-3d";

TEST_F(LayoutObjectTestWithCompositing,
       UseCountDifferentPerspectiveCBOrParent) {
  // Start with a case that has no containing block / parent difference.
  SetBodyInnerHTML(R"HTML(
    <div style='perspective: 200px'>
      <div id=target></div>
    </div>
  )HTML");

  auto* target = GetElementById("target");

  target->setAttribute(html_names::kStyleAttr,
                       AtomicString(kTransf
```