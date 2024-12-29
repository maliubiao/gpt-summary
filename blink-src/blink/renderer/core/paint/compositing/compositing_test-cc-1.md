Response:
The user wants a summary of the provided C++ code snippet from `compositing_test.cc`.
This involves understanding the functionality of the code, its relation to web technologies (HTML, CSS, JavaScript), identifying potential assumptions and logic, pinpointing common usage errors, and explaining how a user's action could lead to this code being executed during debugging.

**Plan:**

1. **High-level functionality:**  Identify the main purpose of the code. It's a test file, so it's testing compositing behavior.
2. **Individual test analysis:** Go through each `TEST_P` block and describe what it's testing. Look for assertions (`EXPECT_*`) to understand the expected behavior.
3. **Relation to web technologies:** Connect the tests to specific HTML elements, CSS properties, and potentially JavaScript interactions.
4. **Logic and assumptions:**  Identify any logical steps or assumptions made within the tests (e.g., what happens when a CSS property changes).
5. **User/programming errors:** Think about common mistakes developers might make that these tests could help catch.
6. **User journey:**  Imagine a user interacting with a web page and how their actions could trigger the underlying rendering and compositing processes being tested.
7. **Synthesize a summary:** Combine the individual test analyses into a concise overview of the file's functionality.
```
功能归纳:

这段代码是 `blink/renderer/core/paint/compositing/compositing_test.cc` 文件的一部分，主要功能是测试 Blink 渲染引擎中与**合成 (Compositing)** 相关的行为。具体来说，它包含了一系列单元测试，用于验证在各种场景下，元素的合成方式和属性是否符合预期。

以下是这段代码中包含的测试功能点的详细归纳：

1. **Pointer-events 属性对合成层的影响:**
   - 测试了 `pointer-events` CSS 属性的更改如何影响合成层的 `hit_test_opaqueness` 属性。
   - 验证了修改 `pointer-events` 属性是否会触发图层的重绘。
   - 考虑了父元素 `inert` 属性对子元素 `pointer-events` 的影响。

2. **滚动容器与固定定位、绝对定位子元素的合成:**
   - 测试了当一个非堆叠的滚动容器 (non-stacked scroller) 内部同时存在相对定位子元素以及固定定位和绝对定位的兄弟元素时，合成层的创建情况。
   - 验证了 `HitTestOpaquenessEnabled` 特性是否会影响合成层的合并行为。
   - 测试了将固定定位元素改为绝对定位后，合成层是否会发生合并。

3. **锚点定位的合成层引用:**
   - 测试了使用 CSS 锚点定位 (`position-anchor`, `anchor-name`, `anchor(...)`) 的元素在合成层树中的 `transform_tree_index` 关系。
   - 验证了滚动容器的变换节点 ID 是否小于锚点定位元素的变换节点 ID，确保了渲染顺序的正确性。

4. **滚动内容裁剪矩形 (Scrolling Contents Cull Rect):**
   - 测试了对于可滚动容器，是否正确计算并设置了 `ScrollingContentsCullRect`，用于优化渲染性能。
   - 分别测试了内容较短和较长的可滚动容器，以及是否合成和不合成的滚动容器。
   - 验证了滚动偏移 (scroll offset) 的改变是否会触发 `PaintArtifactCompositor` 的更新。
   - 测试了只进行滚动操作是否会触发重绘，以及是否会更新裁剪矩形。

5. **合成模拟测试 (CompositingSimTest):**
   - 测试了图层的更新是否会不必要地影响其他图层。
   - 验证了修改一个图层的属性是否只会导致该图层需要推送属性。
   - 测试了非操作性的更改 (noop change) 是否会导致完整的图层树同步或属性树更新。
   - 验证了变换属性的更改如何影响图层的 `subtree_property_changed` 标志和变换节点的 `transform_changed` 标志。
   - 测试了简单的变换属性更新 (不涉及轴对齐变化) 是否可以进行直接更新，而无需标记图层为脏。
   - 验证了通过样式直接更新变换和透明度属性是否可以跳过某些渲染流程，提高性能。
   - 针对 SVG 元素的变换属性更新进行了测试。
   - 测试了直接更新的变换属性值在其他需要 `PaintArtifactCompositor` 运行的更改发生时仍然会被正确设置。

**与 JavaScript, HTML, CSS 的关系及举例:**

- **HTML:** 代码中大量使用了 HTML 结构来创建测试场景。例如，使用 `<div>` 元素设置不同的定位方式 (`position: fixed`, `position: absolute`, `position: relative`)，使用 `<div id="...">` 设置元素的 ID 以便在测试中查找，使用 `setAttribute` 和 `removeAttribute` 修改 HTML 属性（如 `inert`）。
  ```html
  <div id="target" style="pointer-events: auto;">Target</div>
  <div id="scroller" style="overflow: scroll; width: 200px; height: 200px">
      <div id="anchor" style="anchor-name: --a">anchor</div>
  </div>
  ```
- **CSS:** 测试中使用了 CSS 属性来控制元素的样式和行为，例如 `pointer-events`, `position`, `overflow`, `width`, `height`, `transform`, `opacity`, `animation-name`, `animation-duration`, `animation-delay`, 以及 CSS 锚点定位相关的属性。
  ```css
  #fixed { position: fixed; }
  .scroller { overflow: scroll; width: 200px; height: 200px; }
  #anchored1 { position: absolute; position-anchor: --a; top: anchor(bottom); }
  ```
- **JavaScript:** 虽然这段代码本身是 C++ 测试代码，但它模拟了 JavaScript 操作可能触发的渲染行为。例如，`target->SetInlineStyleProperty(CSSPropertyID::kPointerEvents, "none")` 模拟了通过 JavaScript 修改元素的内联样式。`GetElementById("scroller")->scrollTo(5000, 5000)` 模拟了 JavaScript 调用 `scrollTo` 方法。

**逻辑推理及假设输入与输出:**

以 `TEST_P(CompositingTest, PointerEventsInvalidation)` 为例：

**假设输入:**
- 创建一个包含一个父元素和一个子元素的 HTML 结构。
- 子元素初始 `pointer-events` 属性为 `auto`。

**逻辑推理:**
- 当修改子元素的 `pointer-events` 属性时，会影响其合成层的 `hit_test_opaqueness` 属性。
- 启用 `RuntimeEnabledFeatures::HitTestOpaquenessEnabled()` 时，修改 `pointer-events` 属性应该导致合成层需要重绘，但不应使 `DisplayItemClient` 失效。
- 修改父元素的 `inert` 属性也会影响子元素的有效 `pointer-events` 属性，并可能触发合成层的重绘。

**预期输出:**
- `EXPECT_EQ(EPointerEvents::kAuto, target_box->StyleRef().UsedPointerEvents());`  // 初始状态 `pointer-events` 为 `auto`。
- `EXPECT_EQ(hit_test_opaque, target_layer->hit_test_opaqueness());` // 初始状态 `hit_test_opaqueness` 为 opaque。
- `EXPECT_EQ(EPointerEvents::kNone, target_box->StyleRef().UsedPointerEvents());` // 修改后 `pointer-events` 为 `none`。
- `EXPECT_EQ(hit_test_transparent, target_layer->hit_test_opaqueness());` // 修改后 `hit_test_opaqueness` 为 transparent。
- `EXPECT_TRUE(target_box->Layer()->SelfNeedsRepaint());` // 在某些情况下，修改 `pointer-events` 会触发重绘。
- `EXPECT_TRUE(display_item_client->IsValid());` // 修改 `pointer-events` 不应使 `DisplayItemClient` 失效。

**用户或编程常见的使用错误及举例:**

- **错误地认为修改 `pointer-events` 总会触发重绘:** 测试表明，在某些情况下，修改 `pointer-events` 不会立即触发重绘，需要理解 Blink 的渲染优化机制。
- **忽略父元素的 `inert` 属性对子元素交互行为的影响:**  开发者可能只关注子元素自身的 `pointer-events` 属性，而忽略了父元素的 `inert` 属性会禁用子元素的交互。
  ```html
  <div inert>
    <button style="pointer-events: auto;">Click Me</button>  <!-- 这个按钮仍然无法点击 -->
  </div>
  ```
- **不理解合成层的合并规则:** 开发者可能错误地假设某些元素会被提升为独立的合成层，或者某些合成层会被合并，导致性能问题或渲染错误。例如，在滚动容器的测试中，理解 `HitTestOpaquenessEnabled` 如何影响合成层的合并非常重要。

**用户操作如何一步步到达这里作为调试线索:**

假设开发者在调试一个网页，发现一个按钮在滚动容器中无法点击，即使设置了 `pointer-events: auto;`。

1. **用户操作:** 用户尝试点击页面上的一个按钮，但按钮没有响应。
2. **开发者检查:** 开发者使用浏览器的开发者工具检查按钮的样式，确认 `pointer-events` 属性设置为 `auto`。
3. **怀疑合成问题:** 开发者怀疑可能是合成层的问题导致点击事件没有正确传递。
4. **查找相关代码:** 开发者可能会搜索 Blink 引擎中与 `pointer-events` 和合成相关的代码，最终找到 `blink/renderer/core/paint/compositing/compositing_test.cc` 文件，特别是 `PointerEventsInvalidation` 测试。
5. **分析测试:** 通过阅读测试代码，开发者可以了解 Blink 如何处理 `pointer-events` 属性的变化，以及父元素的 `inert` 属性的影响。
6. **调试页面:** 开发者可能会检查按钮的父元素是否设置了 `inert` 属性，或者是否有其他合成层干扰了事件的传递。
7. **定位问题:**  最终，开发者可能发现是父元素意外地设置了 `inert` 属性，导致按钮无法接收点击事件。

总而言之，这段代码通过一系列细致的单元测试，覆盖了 Blink 渲染引擎中合成机制的多个关键方面，确保了在各种场景下，合成行为的正确性和性能优化。这些测试对于理解 Blink 的内部工作原理以及排查渲染问题非常有价值。

Prompt: 
```
这是目录为blink/renderer/core/paint/compositing/compositing_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共5部分，请归纳一下它的功能

"""
ayoutBox();
  EXPECT_EQ(EPointerEvents::kAuto, target_box->StyleRef().UsedPointerEvents());
  ASSERT_FALSE(target_box->Layer()->SelfNeedsRepaint());
  auto* display_item_client = static_cast<const DisplayItemClient*>(target_box);
  ASSERT_TRUE(display_item_client->IsValid());
  const cc::Layer* target_layer =
      CcLayersByDOMElementId(RootCcLayer(), "target")[0];
  EXPECT_EQ(hit_test_opaque, target_layer->hit_test_opaqueness());

  target->SetInlineStyleProperty(CSSPropertyID::kPointerEvents, "none");
  UpdateAllLifecyclePhasesExceptPaint();
  // Change of PointerEvents should not invalidate the painting layer, but not
  // the display item client.
  EXPECT_EQ(EPointerEvents::kNone, target_box->StyleRef().UsedPointerEvents());
  if (RuntimeEnabledFeatures::HitTestOpaquenessEnabled()) {
    EXPECT_TRUE(target_box->Layer()->SelfNeedsRepaint());
  }
  EXPECT_TRUE(display_item_client->IsValid());
  UpdateAllLifecyclePhases();
  EXPECT_EQ(hit_test_transparent, target_layer->hit_test_opaqueness());

  target->RemoveInlineStyleProperty(CSSPropertyID::kPointerEvents);
  UpdateAllLifecyclePhasesExceptPaint();
  EXPECT_EQ(EPointerEvents::kAuto, target_box->StyleRef().UsedPointerEvents());
  if (RuntimeEnabledFeatures::HitTestOpaquenessEnabled()) {
    EXPECT_TRUE(target_box->Layer()->SelfNeedsRepaint());
  }
  EXPECT_TRUE(display_item_client->IsValid());
  UpdateAllLifecyclePhases();
  EXPECT_EQ(hit_test_opaque, target_layer->hit_test_opaqueness());

  parent->setAttribute(html_names::kInertAttr, AtomicString(""));
  UpdateAllLifecyclePhasesExceptPaint();
  EXPECT_EQ(EPointerEvents::kNone, target_box->StyleRef().UsedPointerEvents());
  // Change of parent inert attribute (affecting target's used pointer events)
  // should invalidate the painting layer but not the display item client.
  if (RuntimeEnabledFeatures::HitTestOpaquenessEnabled()) {
    EXPECT_TRUE(target_box->Layer()->SelfNeedsRepaint());
  }
  EXPECT_TRUE(display_item_client->IsValid());
  UpdateAllLifecyclePhases();
  EXPECT_EQ(hit_test_transparent, target_layer->hit_test_opaqueness());

  parent->removeAttribute(html_names::kInertAttr);
  UpdateAllLifecyclePhasesExceptPaint();
  EXPECT_EQ(EPointerEvents::kAuto, target_box->StyleRef().UsedPointerEvents());
  if (RuntimeEnabledFeatures::HitTestOpaquenessEnabled()) {
    EXPECT_TRUE(target_box->Layer()->SelfNeedsRepaint());
  }
  EXPECT_TRUE(display_item_client->IsValid());
  UpdateAllLifecyclePhases();
  EXPECT_EQ(hit_test_opaque, target_layer->hit_test_opaqueness());
}

// Based on the minimized test case of https://crbug.com/343198769.
TEST_P(CompositingTest,
       NonStackedScrollerWithRelativeChildAboveFixedAndAbsolute) {
  GetLocalFrameView()
      ->GetFrame()
      .GetSettings()
      ->SetPreferCompositingToLCDTextForTesting(false);

  InitializeWithHTML(*WebView()->MainFrameImpl()->GetFrame(), R"HTML(
    <!doctype html>
    <style>
      div { width: 100px; height: 100px; }
      ::-webkit-scrollbar { display: none; }
    </style>
    <div id="fixed" style="position: fixed"></div>
    <div id="absolute" style="position: absolute"></div>
    <div style="overflow: scroll">
      <div id="relative" style="position: relative; height: 2000px">
        Contents
      </div>
    </div>
  )HTML");

  EXPECT_TRUE(CcLayerByDOMElementId("fixed"));     // Directly composited.
  EXPECT_TRUE(CcLayerByDOMElementId("absolute"));  // Overlaps with #fixed.
  if (RuntimeEnabledFeatures::HitTestOpaquenessEnabled()) {
    // Not merged because that would miss #relative's scroll state without a
    // MainThreadScrollHitTestRegion.
    EXPECT_TRUE(CcLayerByDOMElementId("relative"));
  } else {
    // Merged into #absolute.
    EXPECT_FALSE(CcLayerByDOMElementId("relative"));
  }

  GetElementById("fixed")->SetInlineStyleProperty(CSSPropertyID::kPosition,
                                                  "absolute");
  UpdateAllLifecyclePhases();
  // All layers are merged together.
  EXPECT_FALSE(CcLayerByDOMElementId("fixed"));
  EXPECT_FALSE(CcLayerByDOMElementId("absolute"));
  EXPECT_FALSE(CcLayerByDOMElementId("relative"));
}

TEST_P(CompositingTest, AnchorPositionAdjustmentTransformIdReference) {
  GetLocalFrameView()
      ->GetFrame()
      .GetSettings()
      ->SetPreferCompositingToLCDTextForTesting(false);

  InitializeWithHTML(*WebView()->MainFrameImpl()->GetFrame(), R"HTML(
    <div id="anchored1"
         style="position: absolute; position-anchor: --a; top: anchor(bottom)">
      anchored
    </div>
    <div id="scroller" style="overflow: scroll; width: 200px; height: 200px">
      <div id="anchor" style="anchor-name: --a">anchor</div>
      <div style="height: 1000px"></div>
    </div>
    <div id="anchored2"
         style="position: absolute; position-anchor: --a; top: anchor(bottom)">
      anchored
    </div>
  )HTML");
  UpdateAllLifecyclePhases();

  int scroll_translation_id =
      GetElementById("scroller")
          ->GetLayoutObject()
          ->FirstFragment()
          .PaintProperties()
          ->ScrollTranslation()
          ->CcNodeId(LayerTreeHost()->property_trees()->sequence_number());
  EXPECT_LT(scroll_translation_id,
            CcLayersByDOMElementId(RootCcLayer(), "anchored1")[0]
                ->transform_tree_index());
  EXPECT_LT(scroll_translation_id,
            CcLayersByDOMElementId(RootCcLayer(), "anchored2")[0]
                ->transform_tree_index());
}

class ScrollingContentsCullRectTest : public CompositingTest {
 protected:
  void SetUp() override {
    CompositingTest::SetUp();
    GetLocalFrameView()
        ->GetFrame()
        .GetSettings()
        ->SetPreferCompositingToLCDTextForTesting(false);
  }

  void CheckCullRect(const char* id, const std::optional<gfx::Rect>& expected) {
    const gfx::Rect* actual =
        GetPropertyTrees()->scroll_tree().ScrollingContentsCullRect(
            GetLayoutObjectById(id)
                ->FirstFragment()
                .PaintProperties()
                ->Scroll()
                ->GetCompositorElementId());
    if (expected) {
      ASSERT_TRUE(actual);
      EXPECT_EQ(*expected, *actual);
    } else {
      EXPECT_FALSE(actual);
    }
  }
};

INSTANTIATE_PAINT_TEST_SUITE_P(ScrollingContentsCullRectTest);

TEST_P(ScrollingContentsCullRectTest, Basics) {
  InitializeWithHTML(*WebView()->MainFrameImpl()->GetFrame(), R"HTML(
    <!doctype html>
    <style>
      .scroller {
         width: 200px;
         height: 200px;
         overflow: scroll;
         font-size: 20px;
         border: 20px solid black;
       }
    </style>
    <div id="short-composited-scroller" class="scroller">
      <div style="height: 2000px; background: yellow">Content</div>
    </div>
    <div id="long-composited-scroller" class="scroller">
      <div style="height: 10000px; background: yellow">Content</div>
    </div>
    <div id="narrow-non-composited-scroller" class="scroller">
      <div style="width: 200px; height: 2000px">Content</div>
    </div>
    <div id="wide-non-composited-scroller" class="scroller">
      <div style="width: 10000px; height: 200px">Content</div>
    </div>
  )HTML");

  UpdateAllLifecyclePhases();
  auto sequence_number = GetPropertyTrees()->sequence_number();

  EXPECT_TRUE(CcLayerByDOMElementId("short-composited-scroller"));
  EXPECT_TRUE(CcLayerByDOMElementId("long-composited-scroller"));
  EXPECT_FALSE(CcLayerByDOMElementId("narrow-non-composited-scroller"));
  EXPECT_FALSE(CcLayerByDOMElementId("wide-non-composited-scroller"));

  CheckCullRect("short-composited-scroller", std::nullopt);
  CheckCullRect("long-composited-scroller", gfx::Rect(20, 20, 200, 4200));
  CheckCullRect("narrow-non-composited-scroller", std::nullopt);
  CheckCullRect("wide-non-composited-scroller", gfx::Rect(20, 20, 4200, 200));

  GetElementById("short-composited-scroller")->scrollTo(5000, 5000);
  GetElementById("long-composited-scroller")->scrollTo(5000, 5000);
  GetElementById("narrow-non-composited-scroller")->scrollTo(5000, 5000);
  GetElementById("wide-non-composited-scroller")->scrollTo(5000, 5000);

  UpdateAllLifecyclePhasesExceptPaint();
  if (RuntimeEnabledFeatures::RasterInducingScrollEnabled()) {
    // All scroll offset changes were directly updated.
    EXPECT_FALSE(paint_artifact_compositor()->NeedsUpdate());
  } else {
    // Non-composited scrolls need PaintArtifactCompositor update.
    EXPECT_TRUE(paint_artifact_compositor()->NeedsUpdate());
  }
  UpdateAllLifecyclePhases();
  // Some scrollers no longer have the foreground paint chunk, which caused a
  // full PaintArtifactCompositor update.
  EXPECT_EQ(sequence_number + 1, GetPropertyTrees()->sequence_number());

  EXPECT_TRUE(CcLayerByDOMElementId("short-composited-scroller"));
  EXPECT_TRUE(CcLayerByDOMElementId("long-composited-scroller"));
  EXPECT_FALSE(CcLayerByDOMElementId("narrow-non-composited-scroller"));
  EXPECT_FALSE(CcLayerByDOMElementId("wide-non-composited-scroller"));

  CheckCullRect("short-composited-scroller", std::nullopt);
  CheckCullRect("long-composited-scroller", gfx::Rect(20, 1020, 200, 8200));
  CheckCullRect("narrow-non-composited-scroller", std::nullopt);
  CheckCullRect("wide-non-composited-scroller", gfx::Rect(1020, 20, 8200, 200));
}

TEST_P(ScrollingContentsCullRectTest, RepaintOnlyScroll) {
  InitializeWithHTML(*WebView()->MainFrameImpl()->GetFrame(), R"HTML(
    <!doctype html>
    <div id="scroller" style="width: 200px; height: 200px; overflow: scroll">
      <div id="content" style="background: yellow">
        <div style="height: 100px; background: blue"></div>
      </div>
    </div>
  )HTML");

  Element* scroller = GetElementById("scroller");
  Element* content = GetElementById("content");
  for (int i = 0; i < 60; i++) {
    content->appendChild(content->firstElementChild()->cloneNode(true));
  }
  UpdateAllLifecyclePhases();
  auto sequence_number = GetPropertyTrees()->sequence_number();

  EXPECT_TRUE(CcLayerByDOMElementId("scroller"));
  CheckCullRect("scroller", gfx::Rect(0, 0, 200, 4200));

  GetElementById("scroller")->scrollTo(0, 3000);
  UpdateAllLifecyclePhasesExceptPaint();
  EXPECT_FALSE(paint_artifact_compositor()->NeedsUpdate());
  UpdateAllLifecyclePhases();
  // The scroll caused only repaint.
  EXPECT_EQ(sequence_number, GetPropertyTrees()->sequence_number());
  // Now the cull rect covers all scrolling contents.
  CheckCullRect("scroller", std::nullopt);

  scroller->scrollTo(0, 5000);
  scroller->GetLayoutBox()->Layer()->SetNeedsRepaint();
  // Force a repaint to proactively update cull rect.
  UpdateAllLifecyclePhasesExceptPaint();
  EXPECT_FALSE(paint_artifact_compositor()->NeedsUpdate());
  UpdateAllLifecyclePhases();
  EXPECT_EQ(sequence_number, GetPropertyTrees()->sequence_number());
  CheckCullRect("scroller", gfx::Rect(0, 1000, 200, 5100));
}

class CompositingSimTest : public PaintTestConfigurations, public SimTest {
 public:
  void InitializeWithHTML(const String& html) {
    SimRequest request("https://example.com/test.html", "text/html");
    LoadURL("https://example.com/test.html");
    request.Complete(html);
    UpdateAllLifecyclePhases();
    DCHECK(paint_artifact_compositor());
  }

  const cc::Layer* RootCcLayer() {
    return paint_artifact_compositor()->RootLayer();
  }

  const cc::Layer* CcLayerByDOMElementId(const char* id) {
    auto layers = CcLayersByDOMElementId(RootCcLayer(), id);
    return layers.empty() ? nullptr : layers[0];
  }

  const cc::Layer* CcLayerByOwnerNode(Node* node) {
    return CcLayerByOwnerNodeId(RootCcLayer(), node->GetDomNodeId());
  }

  const cc::Layer* CcLayerForIFrameContent(Document* iframe_doc) {
    if (RuntimeEnabledFeatures::HitTestOpaquenessEnabled()) {
      return CcLayerByOwnerNode(iframe_doc);
    }
    return CcLayerByOwnerNode(iframe_doc->documentElement());
  }

  Element* GetElementById(const char* id) {
    return MainFrame().GetFrame()->GetDocument()->getElementById(
        AtomicString(id));
  }

  void UpdateAllLifecyclePhases() {
    WebView().MainFrameWidget()->UpdateAllLifecyclePhases(
        DocumentUpdateReason::kTest);
  }

  void UpdateAllLifecyclePhasesExceptPaint() {
    WebView().MainFrameWidget()->UpdateLifecycle(WebLifecycleUpdate::kPrePaint,
                                                 DocumentUpdateReason::kTest);
  }

  cc::PropertyTrees* GetPropertyTrees() {
    return Compositor().LayerTreeHost()->property_trees();
  }

  cc::TransformNode* GetTransformNode(const cc::Layer* layer) {
    return GetPropertyTrees()->transform_tree_mutable().Node(
        layer->transform_tree_index());
  }

  cc::EffectNode* GetEffectNode(const cc::Layer* layer) {
    return GetPropertyTrees()->effect_tree_mutable().Node(
        layer->effect_tree_index());
  }

  PaintArtifactCompositor* paint_artifact_compositor() {
    return MainFrame().GetFrameView()->GetPaintArtifactCompositor();
  }

 private:
  void SetUp() override {
    SimTest::SetUp();
    // Ensure a non-empty size so painting does not early-out.
    WebView().Resize(gfx::Size(800, 600));
  }
};

INSTANTIATE_PAINT_TEST_SUITE_P(CompositingSimTest);

TEST_P(CompositingSimTest, LayerUpdatesDoNotInvalidateEarlierLayers) {
  InitializeWithHTML(R"HTML(
      <!DOCTYPE html>
      <style>
        html { overflow: hidden; }
        div {
          width: 100px;
          height: 100px;
          will-change: transform;
          background: lightblue;
        }
      </style>
      <div id='a'></div>
      <div id='b'></div>
  )HTML");

  Compositor().BeginFrame();

  auto* a_layer = CcLayerByDOMElementId("a");
  auto* b_element = GetElementById("b");
  auto* b_layer = CcLayerByDOMElementId("b");

  // Initially, neither a nor b should have a layer that should push properties.
  const cc::LayerTreeHost& host = *Compositor().LayerTreeHost();
  EXPECT_FALSE(
      host.pending_commit_state()->layers_that_should_push_properties.count(
          a_layer));
  EXPECT_FALSE(
      host.pending_commit_state()->layers_that_should_push_properties.count(
          b_layer));

  // Modifying b should only cause the b layer to need to push properties.
  b_element->setAttribute(html_names::kStyleAttr, AtomicString("opacity: 0.2"));
  UpdateAllLifecyclePhases();
  EXPECT_FALSE(
      host.pending_commit_state()->layers_that_should_push_properties.count(
          a_layer));
  EXPECT_TRUE(
      host.pending_commit_state()->layers_that_should_push_properties.count(
          b_layer));

  // After a frame, no layers should need to push properties again.
  Compositor().BeginFrame();
  EXPECT_FALSE(
      host.pending_commit_state()->layers_that_should_push_properties.count(
          a_layer));
  EXPECT_FALSE(
      host.pending_commit_state()->layers_that_should_push_properties.count(
          b_layer));
}

TEST_P(CompositingSimTest, LayerUpdatesDoNotInvalidateLaterLayers) {
  InitializeWithHTML(R"HTML(
      <!DOCTYPE html>
      <style>
        html { overflow: hidden; }
        div {
          width: 100px;
          height: 100px;
          will-change: transform;
          background: lightblue;
        }
      </style>
      <div id='a'></div>
      <div id='b' style='opacity: 0.2;'></div>
      <div id='c'></div>
  )HTML");

  Compositor().BeginFrame();

  auto* a_element = GetElementById("a");
  auto* a_layer = CcLayerByDOMElementId("a");
  auto* b_element = GetElementById("b");
  auto* b_layer = CcLayerByDOMElementId("b");
  auto* c_layer = CcLayerByDOMElementId("c");

  // Initially, no layer should need to push properties.
  const cc::LayerTreeHost& host = *Compositor().LayerTreeHost();
  EXPECT_FALSE(
      host.pending_commit_state()->layers_that_should_push_properties.count(
          a_layer));
  EXPECT_FALSE(
      host.pending_commit_state()->layers_that_should_push_properties.count(
          b_layer));
  EXPECT_FALSE(
      host.pending_commit_state()->layers_that_should_push_properties.count(
          c_layer));

  // Modifying a and b (adding opacity to a and removing opacity from b) should
  // not cause the c layer to push properties.
  a_element->setAttribute(html_names::kStyleAttr, AtomicString("opacity: 0.3"));
  b_element->setAttribute(html_names::kStyleAttr, g_empty_atom);
  UpdateAllLifecyclePhases();
  EXPECT_TRUE(
      host.pending_commit_state()->layers_that_should_push_properties.count(
          a_layer));
  EXPECT_TRUE(
      host.pending_commit_state()->layers_that_should_push_properties.count(
          b_layer));
  EXPECT_FALSE(
      host.pending_commit_state()->layers_that_should_push_properties.count(
          c_layer));

  // After a frame, no layers should need to push properties again.
  Compositor().BeginFrame();
  EXPECT_FALSE(
      host.pending_commit_state()->layers_that_should_push_properties.count(
          a_layer));
  EXPECT_FALSE(
      host.pending_commit_state()->layers_that_should_push_properties.count(
          b_layer));
  EXPECT_FALSE(
      host.pending_commit_state()->layers_that_should_push_properties.count(
          c_layer));
}

TEST_P(CompositingSimTest,
       NoopChangeDoesNotCauseFullTreeSyncOrPropertyTreeUpdate) {
  InitializeWithHTML(R"HTML(
      <!DOCTYPE html>
      <style>
        div {
          width: 100px;
          height: 100px;
          will-change: transform;
        }
      </style>
      <div></div>
  )HTML");

  Compositor().BeginFrame();

  // Initially the host should not need to sync.
  cc::LayerTreeHost& layer_tree_host = *Compositor().LayerTreeHost();
  EXPECT_FALSE(layer_tree_host.needs_full_tree_sync());
  int sequence_number = GetPropertyTrees()->sequence_number();
  EXPECT_GT(sequence_number, 0);

  // A no-op update should not cause the host to need a full tree sync.
  UpdateAllLifecyclePhases();
  EXPECT_FALSE(layer_tree_host.needs_full_tree_sync());
  // It should also not cause a property tree update - the sequence number
  // should not change.
  EXPECT_EQ(sequence_number, GetPropertyTrees()->sequence_number());
}

// When a property tree change occurs that affects layer transform in the
// general case, all layers associated with the changed property tree node, and
// all layers associated with a descendant of the changed property tree node
// need to have |subtree_property_changed| set for damage tracking. In
// non-layer-list mode, this occurs in BuildPropertyTreesInternal (see:
// SetLayerPropertyChangedForChild).
TEST_P(CompositingSimTest, LayerSubtreeTransformPropertyChanged) {
  InitializeWithHTML(R"HTML(
      <!DOCTYPE html>
      <style>
        html { overflow: hidden; }
        #outer {
          width: 100px;
          height: 100px;
          will-change: transform;
          transform: translate(10px, 10px);
          background: lightgreen;
        }
        #inner {
          width: 100px;
          height: 100px;
          will-change: transform;
          background: lightblue;
        }
      </style>
      <div id='outer'>
        <div id='inner'></div>
      </div>
  )HTML");

  Compositor().BeginFrame();

  auto* outer_element = GetElementById("outer");
  auto* outer_element_layer = CcLayerByDOMElementId("outer");
  auto* inner_element_layer = CcLayerByDOMElementId("inner");

  // Initially, no layer should have |subtree_property_changed| set.
  EXPECT_FALSE(outer_element_layer->subtree_property_changed());
  EXPECT_FALSE(GetTransformNode(outer_element_layer)->transform_changed);
  EXPECT_FALSE(inner_element_layer->subtree_property_changed());
  EXPECT_FALSE(GetTransformNode(inner_element_layer)->transform_changed);

  // Modifying the transform style should set |subtree_property_changed| on
  // both layers.
  outer_element->setAttribute(html_names::kStyleAttr,
                              AtomicString("transform: rotate(10deg)"));
  UpdateAllLifecyclePhases();
  // This is still set by the traditional GraphicsLayer::SetTransform().
  EXPECT_TRUE(outer_element_layer->subtree_property_changed());
  // Set by blink::PropertyTreeManager.
  EXPECT_TRUE(GetTransformNode(outer_element_layer)->transform_changed);
  // TODO(wangxianzhu): Probably avoid setting this flag on transform change.
  EXPECT_TRUE(inner_element_layer->subtree_property_changed());
  EXPECT_FALSE(GetTransformNode(inner_element_layer)->transform_changed);

  // After a frame the |subtree_property_changed| value should be reset.
  Compositor().BeginFrame();
  EXPECT_FALSE(outer_element_layer->subtree_property_changed());
  EXPECT_FALSE(GetTransformNode(outer_element_layer)->transform_changed);
  EXPECT_FALSE(inner_element_layer->subtree_property_changed());
  EXPECT_FALSE(GetTransformNode(inner_element_layer)->transform_changed);
}

// When a property tree change occurs that affects layer transform in a simple
// case (ie before and after transforms both preserve axis alignment), the
// transforms can be directly updated without explicitly marking layers as
// damaged. The ensure damage occurs, the transform node should have
// |transform_changed| set.
TEST_P(CompositingSimTest, DirectTransformPropertyUpdate) {
  InitializeWithHTML(R"HTML(
      <!DOCTYPE html>
      <style>
        html { overflow: hidden; }
        @keyframes animateTransformA {
          0% { transform: translateX(0px); }
          100% { transform: translateX(100px); }
        }
        @keyframes animateTransformB {
          0% { transform: translateX(200px); }
          100% { transform: translateX(300px); }
        }
        #outer {
          width: 100px;
          height: 100px;
          background: lightgreen;
          animation-name: animateTransformA;
          animation-duration: 999s;
        }
        #inner {
          width: 100px;
          height: 100px;
          will-change: transform;
          background: lightblue;
        }
      </style>
      <div id='outer'>
        <div id='inner'></div>
      </div>
  )HTML");

  Compositor().BeginFrame();

  auto* outer_element = GetElementById("outer");
  auto* outer_element_layer = CcLayerByDOMElementId("outer");
  auto transform_tree_index = outer_element_layer->transform_tree_index();
  const auto* transform_node =
      GetPropertyTrees()->transform_tree().Node(transform_tree_index);

  // Initially, transform should be unchanged.
  EXPECT_FALSE(transform_node->transform_changed);
  EXPECT_FALSE(paint_artifact_compositor()->NeedsUpdate());

  // Modifying the transform in a simple way allowed for a direct update.
  outer_element->setAttribute(
      html_names::kStyleAttr,
      AtomicString("animation-name: animateTransformB"));
  UpdateAllLifecyclePhasesExceptPaint();
  EXPECT_TRUE(transform_node->transform_changed);
  EXPECT_FALSE(paint_artifact_compositor()->NeedsUpdate());

  // After a frame the |transform_changed| value should be reset.
  Compositor().BeginFrame();
  EXPECT_FALSE(transform_node->transform_changed);
}

// Test that, for simple transform updates with an existing cc transform node,
// we can go from style change to updated cc transform node without running
// the blink property tree builder and without running paint artifact
// compositor.
// This is similar to |DirectTransformPropertyUpdate|, but the update is done
// from style rather than the property tree builder.
TEST_P(CompositingSimTest, FastPathTransformUpdateFromStyle) {
  InitializeWithHTML(R"HTML(
      <!DOCTYPE html>
      <style>
        @keyframes animation {
          0% { transform: translateX(200px); }
          100% { transform: translateX(300px); }
        }
        #div {
          transform: translateX(100px);
          width: 100px;
          height: 100px;
          /*
            This causes the transform to have an active animation, but because
            the delay is so large, it will not have an effect for the duration
            of this unit test.
          */
          animation-name: animation;
          animation-duration: 999s;
          animation-delay: 999s;
        }
      </style>
      <div id='div'></div>
  )HTML");

  Compositor().BeginFrame();

  // Check the initial state of the blink transform node.
  auto* div = GetElementById("div");
  auto* div_properties =
      div->GetLayoutObject()->FirstFragment().PaintProperties();
  ASSERT_TRUE(div_properties);
  EXPECT_EQ(gfx::Transform::MakeTranslation(100, 0),
            div_properties->Transform()->Matrix());
  EXPECT_TRUE(div_properties->Transform()->HasActiveTransformAnimation());
  EXPECT_FALSE(div->GetLayoutObject()->NeedsPaintPropertyUpdate());

  // Check the initial state of the cc transform node.
  auto* div_cc_layer = CcLayerByDOMElementId("div");
  auto transform_tree_index = div_cc_layer->transform_tree_index();
  const auto* transform_node =
      GetPropertyTrees()->transform_tree().Node(transform_tree_index);
  EXPECT_FALSE(transform_node->transform_changed);
  EXPECT_FALSE(paint_artifact_compositor()->NeedsUpdate());
  EXPECT_EQ(100.0f, transform_node->local.To2dTranslation().x());

  // Change the transform style and ensure the blink and cc transform nodes are
  // not marked for a full update.
  div->setAttribute(html_names::kStyleAttr,
                    AtomicString("transform: translateX(400px)"));
  GetDocument().View()->UpdateLifecycleToLayoutClean(
      DocumentUpdateReason::kTest);
  EXPECT_FALSE(div->GetLayoutObject()->NeedsPaintPropertyUpdate());
  EXPECT_FALSE(paint_artifact_compositor()->NeedsUpdate());

  // Continue to run the lifecycle to paint and ensure that updates are
  // performed.
  UpdateAllLifecyclePhasesExceptPaint();
  EXPECT_EQ(gfx::Transform::MakeTranslation(400, 0),
            div_properties->Transform()->Matrix());
  EXPECT_EQ(400.0f, transform_node->local.To2dTranslation().x());
  EXPECT_TRUE(transform_node->transform_changed);
  EXPECT_FALSE(div->GetLayoutObject()->NeedsPaintPropertyUpdate());
  EXPECT_FALSE(paint_artifact_compositor()->NeedsUpdate());
  EXPECT_TRUE(transform_node->transform_changed);

  // After a frame the |transform_changed| value should be reset.
  Compositor().BeginFrame();
  EXPECT_FALSE(transform_node->transform_changed);
}

// Same as the test above but for opacity changes
TEST_P(CompositingSimTest, FastPathOpacityUpdateFromStyle) {
  InitializeWithHTML(R"HTML(
      <!DOCTYPE html>
      <style>
        @keyframes animation {
          0% { opacity: 0.2; }
          100% { opacity: 0.8; }
        }
        #div {
          opacity: 0.1;
          width: 100px;
          height: 100px;
          /*
            This causes the opacity to have an active animation, but because
            the delay is so large, it will not have an effect for the duration
            of this unit test.
          */
          animation-name: animation;
          animation-duration: 999s;
          animation-delay: 999s;
        }
      </style>
      <div id='div'></div>
  )HTML");

  Compositor().BeginFrame();

  // Check the initial state of the blink effect node.
  auto* div = GetElementById("div");
  auto* div_properties =
      div->GetLayoutObject()->FirstFragment().PaintProperties();
  ASSERT_TRUE(div_properties);
  EXPECT_NEAR(0.1, div_properties->Effect()->Opacity(), 0.001);
  EXPECT_TRUE(div_properties->Effect()->HasActiveOpacityAnimation());
  EXPECT_FALSE(div->GetLayoutObject()->NeedsPaintPropertyUpdate());

  // Check the initial state of the cc effect node.
  auto* div_cc_layer = CcLayerByDOMElementId("div");
  auto effect_tree_index = div_cc_layer->effect_tree_index();
  const auto* effect_node =
      GetPropertyTrees()->effect_tree().Node(effect_tree_index);
  EXPECT_FALSE(effect_node->effect_changed);
  EXPECT_FALSE(paint_artifact_compositor()->NeedsUpdate());
  EXPECT_NEAR(0.1, effect_node->opacity, 0.001);

  // Change the effect style and ensure the blink and cc effect nodes are
  // not marked for a full update.
  div->setAttribute(html_names::kStyleAttr, AtomicString("opacity: 0.15"));
  GetDocument().View()->UpdateLifecycleToLayoutClean(
      DocumentUpdateReason::kTest);
  EXPECT_FALSE(div->GetLayoutObject()->NeedsPaintPropertyUpdate());
  EXPECT_FALSE(paint_artifact_compositor()->NeedsUpdate());

  // Continue to run the lifecycle to paint and ensure that updates are
  // performed.
  UpdateAllLifecyclePhasesExceptPaint();
  EXPECT_NEAR(0.15, div_properties->Effect()->Opacity(), 0.001);
  EXPECT_NEAR(0.15, effect_node->opacity, 0.001);
  EXPECT_TRUE(effect_node->effect_changed);
  EXPECT_FALSE(div->GetLayoutObject()->NeedsPaintPropertyUpdate());
  EXPECT_FALSE(paint_artifact_compositor()->NeedsUpdate());
  EXPECT_TRUE(effect_node->effect_changed);

  // After a frame the |opacity_changed| value should be reset.
  Compositor().BeginFrame();
  EXPECT_FALSE(effect_node->effect_changed);
}

TEST_P(CompositingSimTest, DirectSVGTransformPropertyUpdate) {
  InitializeWithHTML(R"HTML(
    <!doctype html>
    <style>
      @keyframes animateTransformA {
        0% { transform: translateX(0px); }
        100% { transform: translateX(100px); }
      }
      @keyframes animateTransformB {
        0% { transform: translateX(200px); }
        100% { transform: translateX(300px); }
      }
      #willChangeWithAnimation {
        width: 100px;
        height: 100px;
        animation-name: animateTransformA;
        animation-duration: 999s;
      }
    </style>
    <svg width="200" height="200">
      <rect id="willChangeWithAnimation" fill="blue"></rect>
    </svg>
  )HTML");

  Compositor().BeginFrame();

  auto* will_change_layer = CcLayerByDOMElementId("willChangeWithAnimation");
  auto transform_tree_index = will_change_layer->transform_tree_index();
  const auto* transform_node =
      GetPropertyTrees()->transform_tree().Node(transform_tree_index);

  // Initially, transform should be unchanged.
  EXPECT_FALSE(transform_node->transform_changed);
  EXPECT_FALSE(paint_artifact_compositor()->NeedsUpdate());

  // Modifying the transform in a simple way allowed for a direct update.
  auto* will_change_element = GetElementById("willChangeWithAnimation");
  will_change_element->setAttribute(
      html_names::kStyleAttr,
      AtomicString("animation-name: animateTransformB"));
  UpdateAllLifecyclePhasesExceptPaint();
  EXPECT_TRUE(transform_node->transform_changed);
  EXPECT_FALSE(paint_artifact_compositor()->NeedsUpdate());

  // After a frame the |transform_changed| value should be reset.
  Compositor().BeginFrame();
  EXPECT_FALSE(transform_node->transform_changed);
}

// This test is similar to |DirectTransformPropertyUpdate| but tests that
// the changed value of a directly updated transform is still set if some other
// change causes PaintArtifactCompositor to run and do non-direct updates.
TEST_P(CompositingSimTest, DirectTransformPropertyUpdateCausesChange) {
  InitializeWithHTML(R"HTML(
      <!DOCTYPE html>
      <style>
        html { overflow: hidden; }
        @keyframes animateTransformA {
          0% { transform: translateX(0px); }
          100% { transform: translateX(100px); }
        }
        @keyframes animateTransformB {
          0% { transform: translateX(200px); }
          100% { transform: translateX(300px); }
        }
        #outer {
          width: 100px;
          height: 100px;
          animation-name: animateTransformA;
          animation-duration: 999s;
          background: lightgreen;
        }
        #inner {
          width: 100px;
          height: 100px;
          will-change: transform;
          background: lightblue;
          transform: translate(3px, 4px);
        }
      </style>
      <div id='outer'>
        <div id='inner'></div>
      </div>
  )HTML");

  Compositor().BeginFrame();

  auto* outer_element = GetElementById("outer");
  auto* outer_element_layer = CcLayerByDOMElementId("outer");
  auto outer_transform_tree_index = outer_element_layer->transform_tree_index();
  const auto* outer_transform_node =
      GetPropertyTrees()->transform_tree().Node(outer_transform_tree_index);

  auto* inner_element = GetElementById("inner");
  auto* inner_element_layer = CcLayerByDOMElementId("inner");
  auto inner_transform_tree_index = inner_element_layer->transform_tree_index();
  const auto* inner_transform_node =
      GetPropertyTrees()->transform_tree().Node(inner_transform_tree_index);

  // Initially, the transforms should be unchanged.
  EXPECT_FALSE(outer_transform_node->transform_changed);
  EXPECT_FALSE(inner_transform_node->transform_changed);
  EXPECT_FALSE(paint_artifact_compositor()->NeedsUpdate());

  // Modifying the outer transform in a simple way should allow for a direct
  // update of the outer transform. Modifying the inner transform in a
  // non-simple way should not allow for a direct update of the inner transform.
  outer_element->setAttribute(
      html_names::kStyleAttr,
      AtomicString("animation-name: animateTransformB"));
  inner_element->setAttribute(html_names::kStyleAttr,
                              AtomicString("transform: rotate(30deg)"));
  UpdateAl
"""


```