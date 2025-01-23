Response:
The user wants to understand the functionality of the `cull_rect_updater_test.cc` file in the Chromium Blink engine. This is the second part of the analysis.

To fulfill this request, I need to:

1. **Summarize the overall purpose of the code snippets provided.**  Focus on what the tests are trying to verify.
2. **Identify connections to web technologies (JavaScript, HTML, CSS).** Explain how the tests relate to these technologies.
3. **Analyze the test cases for logical reasoning and provide input/output examples.**  Look for specific scenarios being tested.
4. **Point out potential user or programming errors illustrated by the tests.** Think about common mistakes that could lead to the tested behaviors.
5. **Describe user actions that could lead to these code paths being executed.** Explain how a user interacting with a web page might trigger these tests.
这是 `blink/renderer/core/paint/cull_rect_updater_test.cc` 文件的第二部分，延续了第一部分的功能，主要目的是 **测试视口裁剪矩形（cull rect）的更新逻辑是否正确**。

**归纳其功能如下：**

这部分测试用例主要关注在各种场景下，PaintLayer 的裁剪矩形 (CullRect) 和内容裁剪矩形 (ContentsCullRect) 是否按照预期进行更新。这些场景包括：

* **容器的裁剪属性变化:** 例如 `overflow: hidden` 导致的裁剪。
* **滚动容器的滚动:** 测试滚动行为如何触发裁剪矩形的更新，特别是需要更新的时机和更新后的值。
* **特定元素类型:**  测试 `select` 和 `input` 元素是否会不必要地扩展裁剪矩形。
* **锚点定位 (Anchor Positioning):** 测试使用 `anchor-name` 和 `position-anchor` 的元素的裁剪矩形计算。
* **影响绘制的属性变化:**  测试修改诸如 `opacity`, `filter`, `transform` 等 CSS 属性时，是否会触发裁剪矩形的更新以及是否需要重绘。
* **内容大小变化:** 测试当滚动容器的内容大小发生变化时，裁剪矩形是否会更新。
* **滚动偏移变化:** 测试不同大小的内容滚动时，裁剪矩形的更新策略，包括何时需要更新以及何时可以避免不必要的更新。

**与 Javascript, HTML, CSS 的功能关系及举例说明:**

这些测试用例直接关联到 HTML 结构和 CSS 样式，并通过模拟用户操作（例如滚动）或直接修改样式来触发裁剪矩形的更新逻辑。JavaScript 可以用来动态修改元素的样式或进行滚动操作，这些操作会间接地影响裁剪矩形的计算。

* **HTML:**  测试用例使用 HTML 结构来创建需要进行裁剪测试的元素，例如具有 `overflow: hidden` 属性的 `div`，或者可以滚动的 `div`。
    ```html
    <div id="clip" style="width: 300px; height: 300px; overflow: hidden">
      <div id="scroller" style="width: 1000px; height: 1000px; overflow: scroll;">
        <div></div>
      </div>
    </div>
    ```
* **CSS:** CSS 样式定义了元素的尺寸、位置、滚动行为、视觉效果等，这些属性直接影响裁剪矩形的计算。例如，`overflow` 属性决定了是否需要裁剪子元素，`width` 和 `height` 决定了元素的尺寸，`transform` 影响元素的渲染变换。
    ```css
    #clip {
      width: 300px;
      height: 300px;
      overflow: hidden;
    }
    #scroller {
      width: 1000px;
      height: 1000px;
      overflow: scroll;
    }
    ```
* **JavaScript:** 测试代码中使用了 JavaScript 的 DOM API 来获取元素，修改元素的样式，以及模拟滚动操作。
    ```javascript
    document.getElementById("clip");
    document.getElementById("scroller").scrollTo(0, 300);
    ```

**逻辑推理的假设输入与输出:**

**示例 1: `LimitedDynamicCullRectExpansionX` 测试**

* **假设输入 (HTML/CSS):**
    ```html
    <div id="clip" style="width: 300px; height: 300px; overflow: hidden">
      <div id="scroller" style="width: 1000px; height: 1000px; overflow: scroll; will-change: scroll-position">
        <div style="width: 2000px; height: 1000px"></div>
      </div>
    </div>
    ```
* **逻辑推理:**
    * `clip` 元素的 `overflow: hidden` 将其裁剪矩形限制为 300x300。
    * `scroller` 元素的内容宽度为 2000px，滚动范围为 1000px。
    * 因为 `will-change: scroll-position`，`scroller` 的裁剪矩形会动态扩展。
    * 动态扩展的计算会考虑到滚动范围，但会限制在内容矩形内。
* **预期输出:**
    * `GetCullRect(clip).Rect()`: `gfx::Rect(0, 0, 800, 600)` (浏览器视口大小)
    * `GetContentsCullRect(clip).Rect()`: `gfx::Rect(0, 0, 300, 300)` (被 `overflow: hidden` 裁剪)
    * `GetCullRect(scroller).Rect()`: `gfx::Rect(0, 0, 300, 300)` (初始裁剪矩形)
    * `GetContentsCullRect(scroller).Rect()`: `gfx::Rect(0, 0, 1300, 300)` (动态扩展后的内容裁剪矩形，受限于内容宽度和裁剪范围)

**示例 2: `ViewScrollNeedsCullRectUpdate` 测试**

* **假设输入 (HTML/CSS):**
    ```html
    <div style='height: 5000px'></div>
    ```
* **逻辑推理:**
    * 页面内容高度大于视口高度，因此可以滚动。
    * 首次加载时，不需要更新裁剪矩形。
    * 首次滚动一段距离后（例如 300px），仍然可能不需要立即更新裁剪矩形。
    * 当滚动距离足够大，暴露出新的内容时，需要更新裁剪矩形。
* **预期输出:**
    * 初始状态: `layer.NeedsCullRectUpdate()` 为 `false`。
    * 首次滚动后: `layer.NeedsCullRectUpdate()` 为 `false`。
    * 再次滚动较大距离后: `layer.NeedsCullRectUpdate()` 为 `true`，并且 `GetContentsCullRect(layer).Rect()` 的高度会增加。

**涉及用户或者编程常见的使用错误及举例说明:**

* **误用 `will-change` 属性:** 开发者可能会不必要地对元素应用 `will-change` 属性，期望提高性能，但如果使用不当，可能会导致不必要的资源消耗或影响裁剪矩形的计算。测试用例通过对比有无 `will-change` 属性时的行为，验证了相关逻辑的正确性。
* **对性能的错误理解:** 开发者可能认为任何 CSS 属性的改变都需要立即更新裁剪矩形并重绘，但实际上，浏览器会进行优化。测试用例验证了哪些属性变化会触发裁剪矩形的更新，哪些不会。例如，非像素移动的 `filter` 属性变化通常不需要更新裁剪矩形。
* **滚动容器内容过大导致的性能问题:** 当滚动容器的内容非常大时，不合理的裁剪矩形计算可能导致性能问题。测试用例通过模拟大内容滚动的情况，验证了裁剪矩形更新的优化策略，例如只在需要暴露新内容时才更新。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户加载网页:** 当用户在浏览器中打开一个包含复杂布局和滚动元素的网页时，Blink 引擎会开始解析 HTML、CSS 并构建渲染树。
2. **布局计算:** 引擎会计算每个元素的大小和位置，确定滚动区域等。
3. **图层创建:**  为了优化渲染性能，某些元素会被提升到独立的 PaintLayer。
4. **首次绘制:**  在首次绘制时，会计算每个 PaintLayer 的初始裁剪矩形。
5. **用户交互触发变化:**
    * **滚动:** 用户滚动页面或某个可滚动容器时，会触发滚动事件。
    * **样式修改:** 用户操作或 JavaScript 代码可能会修改元素的 CSS 样式。
    * **内容变化:** JavaScript 可能会动态添加或删除元素，改变滚动容器的内容大小。
6. **裁剪矩形更新:**  当上述变化发生时，Blink 引擎会根据一定的规则判断是否需要更新受影响的 PaintLayer 的裁剪矩形。`CullRectUpdater` 类及其相关逻辑负责执行这个更新过程。
7. **重绘:** 如果裁剪矩形的更新导致可见区域发生变化，或者影响了其他需要重绘的属性，Blink 引擎会安排相应的图层进行重绘。

**调试线索:** 如果在开发过程中发现渲染异常或性能问题，例如：

* **元素不应该显示时却显示了:**  可能是裁剪矩形计算错误，导致本应被裁剪掉的内容显示出来。
* **滚动性能不佳:**  可能是裁剪矩形更新过于频繁或不准确，导致不必要的绘制。

此时，开发者可以使用 Chromium 的开发者工具，例如 "Layers" 面板，来查看 PaintLayer 的结构和裁剪矩形，并结合断点调试 `blink/renderer/core/paint/cull_rect_updater.cc` 文件中的代码，来分析裁剪矩形是如何计算和更新的，从而找到问题的根源。这些测试用例正是为了确保这些核心逻辑的正确性。

### 提示词
```
这是目录为blink/renderer/core/paint/cull_rect_updater_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
lementId("clip");
  auto& scroller = *GetPaintLayerByElementId("scroller");
  EXPECT_EQ(gfx::Rect(0, 0, 800, 600), GetCullRect(clip).Rect());
  EXPECT_EQ(gfx::Rect(0, 0, 300, 300), GetContentsCullRect(clip).Rect());
  EXPECT_EQ(gfx::Rect(0, 0, 300, 300), GetCullRect(scroller).Rect());
  EXPECT_EQ(gfx::Rect(0, 0, 300, 1300), GetContentsCullRect(scroller).Rect());
}

TEST_F(CullRectUpdaterTest, LimitedDynamicCullRectExpansionX) {
  SetBodyInnerHTML(R"HTML(
    <style>body { margin: 0 }</style>
    <div id="clip" style="width: 300px; height: 300px; overflow: hidden">
      <div id="scroller" style="width: 1000px; height: 1000px;
                                overflow: scroll; will-change: scroll-position">
        <div style="width: 2000px; height: 1000px"></div>
      <div>
    </div>
  )HTML");

  // The outer overflow:hidden div causes CullRect::rect_ to be 300x300 and
  // the scroll range is 1000, so we end up with an expanded rect of (-1000, 0,
  // 2300, 300). Since the contents_rect is (0, 0, 2000, 1000), we intersect to
  // (0, 0, 1300, 300).  If we don't limit to the scroll range, we expand to
  // (-4000, 0, 8300, 300) and clip to (0, 0, 2000, 300).
  auto& clip = *GetPaintLayerByElementId("clip");
  auto& scroller = *GetPaintLayerByElementId("scroller");
  EXPECT_EQ(gfx::Rect(0, 0, 800, 600), GetCullRect(clip).Rect());
  EXPECT_EQ(gfx::Rect(0, 0, 300, 300), GetContentsCullRect(clip).Rect());
  EXPECT_EQ(gfx::Rect(0, 0, 300, 300), GetCullRect(scroller).Rect());
  EXPECT_EQ(gfx::Rect(0, 0, 1300, 300), GetContentsCullRect(scroller).Rect());
}

TEST_F(CullRectUpdaterTest, ViewScrollNeedsCullRectUpdate) {
  SetBodyInnerHTML("<div style='height: 5000px'>");

  auto& layer = *GetLayoutView().Layer();
  EXPECT_FALSE(layer.NeedsCullRectUpdate());
  EXPECT_EQ(gfx::PointF(),
            layer.GetScrollableArea()->LastCullRectUpdateScrollPosition());
  EXPECT_EQ(gfx::Rect(0, 0, 800, 4600), GetContentsCullRect(layer).Rect());

  GetDocument().domWindow()->scrollBy(0, 300);
  UpdateAllLifecyclePhasesExceptPaint(/*update_cull_rects*/ false);
  EXPECT_FALSE(layer.NeedsCullRectUpdate());
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(gfx::PointF(),
            layer.GetScrollableArea()->LastCullRectUpdateScrollPosition());
  EXPECT_EQ(gfx::Rect(0, 0, 800, 4600), GetContentsCullRect(layer).Rect());

  GetDocument().domWindow()->scrollBy(0, 300);
  UpdateAllLifecyclePhasesExceptPaint(/*update_cull_rects*/ false);
  EXPECT_TRUE(layer.NeedsCullRectUpdate());
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(gfx::PointF(0, 600),
            layer.GetScrollableArea()->LastCullRectUpdateScrollPosition());
  EXPECT_EQ(gfx::Rect(0, 0, 800, 5016), GetContentsCullRect(layer).Rect());

  GetDocument().domWindow()->scrollBy(0, 300);
  UpdateAllLifecyclePhasesExceptPaint(/*update_cull_rects*/ false);
  EXPECT_FALSE(layer.NeedsCullRectUpdate());
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(gfx::PointF(0, 600),
            layer.GetScrollableArea()->LastCullRectUpdateScrollPosition());
  EXPECT_EQ(gfx::Rect(0, 0, 800, 5016), GetContentsCullRect(layer).Rect());
}

// The test doesn't apply on Android or iOS where the LayoutObject of <select>
// doesn't scroll.
#if !BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_IOS)
TEST_F(CullRectUpdaterTest, SelectDoesntExpandCullRect) {
  SetBodyInnerHTML(R"HTML(
    <select id="select" style="height: 50px; font-size: 20px" size="3">
      <option>a</option>
      <option>b</option>
      <option>c</option>
      <option>d</option>
      <option>e</option>
    </select>
  )HTML");

  const PaintLayer* layer = GetPaintLayerByElementId("select");
  ASSERT_TRUE(layer->GetScrollableArea());
  gfx::Rect contents_cull_rect = GetContentsCullRect(*layer).Rect();
  EXPECT_LE(contents_cull_rect.height(), 50);
}
#endif

TEST_F(CullRectUpdaterTest, InputDoesntExpandCullRect) {
  SetBodyInnerHTML(R"HTML(
    <input id="input" style="font-size: 20px; width: 100px; height: 20px"
           value="ABCDEFGHIJKLMNOPQRSTUVWXYZ">
  )HTML");

  const LayoutObject* editor =
      GetLayoutObjectByElementId("input")->SlowFirstChild();
  ASSERT_TRUE(editor);
  ASSERT_TRUE(editor->HasLayer());
  const PaintLayer* layer = To<LayoutBoxModelObject>(editor)->Layer();
  ASSERT_TRUE(layer->GetScrollableArea());
  gfx::Rect contents_cull_rect = GetContentsCullRect(*layer).Rect();
  EXPECT_LE(contents_cull_rect.width(), 100);
}

TEST_F(CullRectUpdaterTest, AnchorPosition) {
  SetBodyInnerHTML(R"HTML(
    <div style="width: 200px; height: 200px; overflow: scroll">
      <div style="anchor-name: --a; height: 50px">anchor</div>
      <div style="height: 1000px"></div>
    </div>
    <div id="anchored1"
         style="position: fixed; position-anchor: --a; top: anchor(bottom)">
      Anchored1
    </div>
    <div id="anchored2"
         style="position: fixed; position-anchor: --a; top: anchor(bottom);
                transform: translateY(100px)">
      Anchored2
    </div>
  )HTML");

  EXPECT_EQ(gfx::Size(8800, 8600), GetCullRect("anchored1").Rect().size());
  EXPECT_EQ(gfx::Size(8800, 8600), GetCullRect("anchored2").Rect().size());
}

class CullRectUpdateOnPaintPropertyChangeTest : public CullRectUpdaterTest {
 protected:
  void Check(const String& old_style,
             const String& new_style,
             bool expected_needs_repaint,
             bool expected_needs_cull_rect_update,
             bool expected_needs_repaint_after_cull_rect_update) {
    UpdateAllLifecyclePhasesExceptPaint(/*update_cull_rects*/ false);
    const auto* target_layer = GetPaintLayerByElementId("target");
    EXPECT_EQ(expected_needs_repaint, target_layer->SelfNeedsRepaint())
        << old_style << " -> " << new_style;
    EXPECT_EQ(expected_needs_cull_rect_update,
              target_layer->NeedsCullRectUpdate())
        << old_style << " -> " << new_style;
    UpdateCullRects();
    EXPECT_EQ(expected_needs_repaint_after_cull_rect_update,
              target_layer->SelfNeedsRepaint())
        << old_style << " -> " << new_style;
  }

  void TestTargetChange(const char* old_style,
                        const char* new_style,
                        bool expected_needs_repaint,
                        bool expected_needs_cull_rect_update,
                        bool expected_needs_repaint_after_cull_rect_update) {
    SetBodyInnerHTML(html_);
    auto* target = GetDocument().getElementById(AtomicString("target"));
    target->setAttribute(html_names::kStyleAttr, AtomicString(old_style));
    UpdateAllLifecyclePhasesForTest();
    target->setAttribute(html_names::kStyleAttr, AtomicString(new_style));
    Check(old_style, new_style, expected_needs_repaint,
          expected_needs_cull_rect_update,
          expected_needs_repaint_after_cull_rect_update);
  }

  void TestChildChange(const char* old_style,
                       const char* new_style,
                       bool expected_needs_repaint,
                       bool expected_needs_cull_rect_update,
                       bool expected_needs_repaint_after_cull_rect_update) {
    SetBodyInnerHTML(html_);
    auto* child = GetDocument().getElementById(AtomicString("child"));
    child->setAttribute(html_names::kStyleAttr, AtomicString(old_style));
    UpdateAllLifecyclePhasesForTest();
    child->setAttribute(html_names::kStyleAttr, AtomicString(new_style));
    Check(old_style, new_style, expected_needs_repaint,
          expected_needs_cull_rect_update,
          expected_needs_repaint_after_cull_rect_update);
  }

  void TestTargetScroll(const ScrollOffset& old_scroll_offset,
                        const ScrollOffset& new_scroll_offset,
                        bool expected_needs_repaint,
                        bool expected_needs_cull_rect_update,
                        bool expected_needs_repaint_after_cull_rect_update) {
    SetBodyInnerHTML(html_);
    auto* target = GetDocument().getElementById(AtomicString("target"));
    target->scrollTo(old_scroll_offset.x(), old_scroll_offset.y()),
        UpdateAllLifecyclePhasesForTest();
    target->scrollTo(new_scroll_offset.x(), new_scroll_offset.y()),
        Check(String(old_scroll_offset.ToString()),
              String(new_scroll_offset.ToString()), expected_needs_repaint,
              expected_needs_cull_rect_update,
              expected_needs_repaint_after_cull_rect_update);
  }

  String html_ = R"HTML(
    <style>
      #target {
        width: 100px;
        height: 100px;
        position: relative;
        overflow: scroll;
        background: white;
      }
      #child { width: 1000px; height: 1000px; }
    </style>
    <div id="target">
      <div id="child">child</div>
    </div>"
  )HTML";
};

TEST_F(CullRectUpdateOnPaintPropertyChangeTest, Opacity) {
  TestTargetChange("opacity: 0.2", "opacity: 0.8", false, false, false);
  TestTargetChange("opacity: 0.5", "", true, false, true);
  TestTargetChange("", "opacity: 0.5", true, false, true);
  TestTargetChange("will-change: opacity", "will-change: opacity; opacity: 0.5",
                   false, false, false);
  TestTargetChange("will-change: opacity; opacity: 0.5", "will-change: opacity",
                   false, false, false);
}

TEST_F(CullRectUpdateOnPaintPropertyChangeTest, NonPixelMovingFilter) {
  TestTargetChange("filter: invert(5%)", "filter: invert(8%)", false, false,
                   false);
  TestTargetChange("filter: invert(5%)", "", true, false, true);
  TestTargetChange("", "filter: invert(5%)", true, false, true);
  TestTargetChange("will-change: filter; filter: invert(5%)",
                   "will-change: filter", false, false, false);
  TestTargetChange("will-change: filter",
                   "will-change: filter; filter: invert(5%)", false, false,
                   false);
}

TEST_F(CullRectUpdateOnPaintPropertyChangeTest, PixelMovingFilter) {
  TestTargetChange("filter: blur(5px)", "filter: blur(8px)", false, false,
                   false);
  TestTargetChange("filter: blur(5px)", "", true, true, true);
  TestTargetChange("", "filter: blur(5px)", true, true, true);
  TestTargetChange("will-change: filter; filter: blur(5px)",
                   "will-change: filter", true, false, true);
  TestTargetChange("will-change: filter",
                   "will-change: filter; filter: blur(5px)", true, false, true);
}

TEST_F(CullRectUpdateOnPaintPropertyChangeTest, Transform) {
  // We use infinite cull rect for small layers with non-composited transforms,
  // so don't need to update cull rect on non-composited transform change.
  TestTargetChange("transform: translateX(10px)", "transform: translateX(20px)",
                   false, false, false);
  TestTargetChange("transform: translateX(10px)", "", true, true, true);
  TestTargetChange("", "transform: translateX(10px)", true, true, true);
  // We don't use infinite cull rect for layers with composited transforms.
  TestTargetChange("will-change: transform; transform: translateX(10px)",
                   "will-change: transform; transform: translateX(20px)", false,
                   true, false);
  TestTargetChange("will-change: transform; transform: translateX(10px)",
                   "will-change: transform", false, true, false);
  TestTargetChange("will-change: transform",
                   "will-change: transform; transform: translateX(10px)", false,
                   true, false);
}

TEST_F(CullRectUpdateOnPaintPropertyChangeTest, AnimatingTransform) {
  html_ = html_ + R"HTML(
    <style>
      @keyframes test {
        0% { transform: translateX(0); }
        100% { transform: translateX(200px); }
      }
      #target { animation: test 1s infinite; }
    </style>
  )HTML";
  TestTargetChange("transform: translateX(10px)", "transform: translateX(20px)",
                   false, false, false);
  TestTargetChange("transform: translateX(10px)", "", false, false, false);
  TestTargetChange("", "transform: translateX(10px)", false, false, false);
}

TEST_F(CullRectUpdateOnPaintPropertyChangeTest, ScrollContentsSizeChange) {
  TestChildChange("", "width: 3000px", true, true, true);
  TestChildChange("", "height: 3000px", true, true, true);
  TestChildChange("", "width: 50px; height: 50px", true, true, true);
}

TEST_F(CullRectUpdateOnPaintPropertyChangeTest, SmallContentsScroll) {
  // TODO(wangxianzhu): Optimize for scrollers with small contents.
  bool needs_cull_rect_update = false;
  TestTargetScroll(ScrollOffset(), ScrollOffset(100, 200), false,
                   needs_cull_rect_update, false);
  TestTargetScroll(ScrollOffset(100, 200), ScrollOffset(1000, 1000), false,
                   needs_cull_rect_update, false);
  TestTargetScroll(ScrollOffset(1000, 1000), ScrollOffset(), false,
                   needs_cull_rect_update, false);
}

TEST_F(CullRectUpdateOnPaintPropertyChangeTest,
       LargeContentsScrollSmallDeltaOrNotExposingNewContents1) {
  html_ = html_ + "<style>#child { width: auto; height: 10000px; }</style>";
  // Scroll offset changes that are small or won't expose new contents don't
  // need cull rect update.
  bool needs_cull_rect_update = false;
  TestTargetScroll(ScrollOffset(), ScrollOffset(0, 200), false,
                   needs_cull_rect_update, false);
  TestTargetScroll(ScrollOffset(0, 200), ScrollOffset(), false,
                   needs_cull_rect_update, false);
  TestTargetScroll(ScrollOffset(0, 2000), ScrollOffset(), false,
                   needs_cull_rect_update, false);
  TestTargetScroll(ScrollOffset(0, 7000), ScrollOffset(0, 8000), false,
                   needs_cull_rect_update, false);
}

TEST_F(CullRectUpdateOnPaintPropertyChangeTest,
       LargeContentsScrollSmallDeltaOrNotExposingNewContents2) {
  html_ = html_ + "<style>#child { width: 10000px; height: 10000px; }</style>";
  // Scroll offset changes that are small or won't expose new contents don't
  // need cull rect update.
  bool needs_cull_rect_update = false;
  TestTargetScroll(ScrollOffset(), ScrollOffset(200, 200), false,
                   needs_cull_rect_update, false);
  TestTargetScroll(ScrollOffset(200, 200), ScrollOffset(), false,
                   needs_cull_rect_update, false);
  TestTargetScroll(ScrollOffset(2000, 2000), ScrollOffset(), false,
                   needs_cull_rect_update, false);
  TestTargetScroll(ScrollOffset(7000, 7000), ScrollOffset(7500, 7500), false,
                   needs_cull_rect_update, false);
}

TEST_F(CullRectUpdateOnPaintPropertyChangeTest,
       LargeContentsScrollExposingNewContents) {
  html_ = html_ + "<style>#child { width: 10000px; height: 10000px; }</style>";
  // Big scroll offset changes that will expose new contents to paint need cull
  // rect update.
  TestTargetScroll(ScrollOffset(100, 200), ScrollOffset(100, 800), false, true,
                   true);
  TestTargetScroll(ScrollOffset(100, 800), ScrollOffset(700, 800), false, true,
                   true);
  TestTargetScroll(ScrollOffset(700, 800), ScrollOffset(1700, 1800), false,
                   true, true);
  TestTargetScroll(ScrollOffset(8000, 8000), ScrollOffset(0, 8000), false, true,
                   true);
  TestTargetScroll(ScrollOffset(8000, 100), ScrollOffset(), false, true, true);
  TestTargetScroll(ScrollOffset(100, 8000), ScrollOffset(), false, true, true);
}

}  // namespace blink
```