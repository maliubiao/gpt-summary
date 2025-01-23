Response:
The user wants a summary of the functionality of the provided C++ code, which is a test file for the Blink rendering engine, specifically related to compositing. I need to extract the main topics covered by the tests, explain their relevance to web technologies (JavaScript, HTML, CSS), provide examples, discuss potential user/programming errors, and explain how a user's actions might lead to the execution of this code.

Here's a breakdown of the thought process:

1. **Identify the Core Functionality:** The file name `compositing_test.cc` immediately points to tests related to the compositing process in Blink. Scanning the test names and the code within the tests will reveal the specific aspects being tested.

2. **Categorize Test Scenarios:** Group the tests based on the features they are verifying. Common themes emerge, like:
    * Page scale factor updates and their impact on the transform tree.
    * Main thread vs. compositor thread scroll interactions and commit requirements.
    * Attribution of layers to their respective frames (especially in iframes).
    * Identification of visible frame roots.
    * Handling of transform changes (with and without subtree changes).
    * Different types of paint updates (repaint vs. full) based on CSS property changes.
    * Factors influencing whether a full compositing update is needed (e.g., z-index changes, adding/removing elements, uncachable content).
    * Compositing behavior in iframes, including hidden iframes.
    * Interaction with remote frames and surface layers.
    * Optimization related to solid color layers and subpixel rendering.
    * Compositing of effects (opacity, filters) in combination with transforms.

3. **Relate to Web Technologies:** For each category, explain how it relates to JavaScript, HTML, and CSS:
    * **Page Scale:** Directly influenced by JavaScript (`viewport.setScale()`) and browser zoom settings.
    * **Scrolling:** Triggered by user interaction (mouse wheel, touch) or JavaScript (`window.scrollTo()`). CSS properties like `position: fixed` can influence scrolling behavior.
    * **Iframes:** Defined by the HTML `<iframe>` tag. JavaScript can interact with iframe content. CSS properties like `isolation` can affect compositing.
    * **Transforms:**  A CSS property (`transform`). JavaScript can manipulate element styles to change transforms.
    * **Paint Updates:**  Reflect changes to the visual appearance defined by HTML content and CSS styles. JavaScript can dynamically modify these.
    * **Z-index:** A CSS property controlling stacking order.
    * **Opacity and Filters:** CSS properties (`opacity`, `filter`).
    * **Visibility:** CSS property (`visibility`).

4. **Provide Concrete Examples:** For each relationship, give a simple code snippet demonstrating the connection. This makes the explanation more tangible.

5. **Address Logic and Assumptions:**  Look for tests that involve comparisons and assertions. These often reveal underlying assumptions. For instance, tests verifying the page scale factor after certain operations imply a specific order of execution and update mechanisms. Present these as "assumptions" with example inputs and expected outputs.

6. **Identify Potential Errors:** Think about common mistakes developers or users might make that could expose the behavior being tested. Examples:
    * Setting the wrong scale in JavaScript.
    * Conflicting CSS properties leading to unexpected compositing behavior.
    * Not understanding the performance implications of certain CSS properties (like `will-change`).

7. **Trace User Actions:**  Describe the step-by-step user interactions that would eventually trigger the code being tested. This helps understand the context of the tests.

8. **Synthesize the Functionality:** Based on the categorized tests and explanations, provide a concise summary of the file's overall purpose. Emphasize that it's a testing ground for the correctness and efficiency of Blink's compositing logic.

9. **Structure and Language:** Organize the information logically using headings and bullet points. Use clear and concise language, avoiding overly technical jargon where possible. Maintain a consistent tone throughout. Pay attention to the "Part 4 of 5" instruction and ensure the summary reflects the cumulative understanding.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focus heavily on the C++ code details.
* **Correction:** Shift focus to *what* the tests are verifying and *why* it matters for web developers and users. The C++ is the *how*, but the user asked for the *what* and *why*.
* **Initial thought:**  Provide very technical explanations of compositing.
* **Correction:**  Simplify the explanations and focus on the observable effects in terms of HTML, CSS, and JavaScript.
* **Initial thought:** Treat each test in isolation.
* **Correction:** Group related tests to identify overarching themes and provide a more coherent explanation.

By following these steps and refining the explanations, I can generate a comprehensive and understandable summary of the `compositing_test.cc` file.
好的，让我们归纳一下 `blink/renderer/core/paint/compositing/compositing_test.cc` 这个文件的功能，并结合之前分析的部分。

**综合之前部分（Part 1, 2, 3）和当前部分（Part 4），`compositing_test.cc` 的主要功能是：**

这是一个 Chromium Blink 引擎的 C++ 单元测试文件，专门用于测试**渲染引擎中与合成（Compositing）相关的核心功能**。它的目标是验证在各种场景下，Blink 的合成逻辑是否正确且高效地工作。

具体来说，该文件测试了以下几个关键方面：

1. **属性树（Property Trees）的正确更新和使用：**
   - 测试了页面缩放因子（page scale factor）的改变如何正确地反映在变换树（transform tree）中，包括主线程更新和在构建树时的设置。
   - 验证了在执行生命周期更新时，变换树是否能正确计算页面缩放因子。
   - 涉及到 CSS 的 `zoom` 属性或用户手动缩放页面。 JavaScript 可以通过 `visualViewport.scale` 来设置页面缩放。

2. **合成提交（Compositing Commit）的触发条件：**
   - 测试了当存在需要主线程参与的滚动原因（例如，`background-attachment: fixed` 的元素）时，即使在合成器线程滚动，也需要触发提交。
   - 这与 CSS 的 `background-attachment: fixed` 属性有关。 当用户滚动页面时，如果存在这类元素，即使滚动发生在 GPU 进程，也需要通知主进程进行同步。

3. **图层归属（Layer Attribution）：**
   - 验证了主框架和子框架（iframe）中的图层是否能正确地归属于它们所属的文档。
   - 特别关注了 `will-change: transform` 等触发合成的 CSS 属性对图层归属的影响。
   - 涉及到 HTML 的 `<iframe>` 标签以及 CSS 的 `will-change` 属性。

4. **可见帧根图层（Visible Frame Root Layers）：**
   - 测试了顶级文档和 iframe 是否被正确标记为可见帧根。
   - 验证了当 iframe 应用 `pointer-events: none` 后，是否不再被认为是可见根。
   - 与 HTML 的 `<iframe>` 标签和 CSS 的 `pointer-events` 属性相关。

5. **变换更新（Transform Updates）：**
   - 测试了当应用了 `will-change: transform` 的元素其变换属性发生变化时，是否能正确标记子树属性已更改。
   - 例如，CSS `transform: rotate3d(...)` 属性的改变。

6. **油漆更新类型（Paint Update Types）：**
   - 详细测试了不同类型的 CSS 属性变化如何触发不同类型的油漆更新（repaint 或 full）。
   - **Repaint 更新（快速路径）：**  针对背景颜色等简单样式的变化，验证是否使用了更快的 repaint 更新路径。
     - 例如，修改元素的 `background-color` 属性。
   - **Full 更新：** 针对影响合成决策的属性变化，例如透明度（`opacity`）、是否绘制内容（影响遮罩层创建）、z-index、添加/删除/改变大小的绘制块（paint chunk）。
     - 例如，修改元素的 `opacity` 或 `z-index` 属性，或者通过 JavaScript 动态添加或删除元素。
   - 特别关注了带有后绘制合成 SVG 的场景下的油漆更新。

7. **内容不透明度（Contents Opaque）：**
   - 测试了背景颜色和文本内容的不透明度如何影响合成图层的 `contents_opaque` 和 `contents_opaque_for_text` 属性。
   - 例如，设置 `background: white` 会使内容不透明，而 `background: rgba(..., 0.5)` 则不会。

8. **绘制内容属性（Draws Content）：**
   - 验证了当元素的 `draws_content` 属性发生变化时（例如，从没有背景到有背景），是否会触发 full 更新。

9. **亚像素尺寸和内容不透明度：**
   - 测试了当元素尺寸为亚像素时，是否能正确判断内容是否不透明。

10. **合成更新原因（Compositing Update Reasons）：**
    - 详细测试了各种触发 full 合成更新的原因，例如：
        - 绘制块的重新排序（例如，通过修改 `z-index`）。
        - 绘制块的移除或添加。
        - 绘制块大小的改变。
        - 针对后绘制合成 SVG 的类似变化。
        - 新创建的绘制块。
        - 不可缓存的绘制块。

11. **隐藏 iframe 中的合成：**
    - 测试了当 iframe 被隐藏时，其内部的合成图层是否会被正确地分解（decomposited）。
    - 与 CSS 的 `visibility: hidden` 属性相关。

12. **移动子序列中的外部图层（Foreign Layers）：**
    - 测试了当包含外部图层（例如来自跨域 iframe 的图层）的子序列被移动时，油漆更新的处理是否正确。
    - 涉及到跨域 iframe 和 Blink 的外部图层合成机制。

13. **实心颜色图层（Solid Color Layers）：**
    - 验证了在启用像素捕捉（snapping）的情况下，背景是否能使用实心颜色图层，这对于性能很重要。
    - 测试了亚像素变换下的实心颜色图层。

14. **效果节点合成（Effect Node Compositing）：**
    - 测试了当元素应用了 3D 变换时，其效果节点（例如，opacity 或 filter）是否仍然会被合成，以提高性能。
    - 与 CSS 的 `opacity`、`filter` 和 3D `transform` 属性相关。

**与 JavaScript, HTML, CSS 的关系举例：**

* **JavaScript:**
    - 通过 JavaScript 修改 DOM 结构或样式，例如 `document.getElementById('target').style.backgroundColor = 'red';`，会导致油漆更新，该测试会验证更新类型是否正确。
    - JavaScript 可以通过 `visualViewport.scale` 来动态设置页面的缩放比例，这些测试验证了缩放变化如何影响合成。
* **HTML:**
    - HTML 结构定义了渲染对象和图层的基本组织。例如，`<iframe>` 标签的出现会引入新的合成根，这些测试会验证 iframe 的合成行为。
* **CSS:**
    - 各种 CSS 属性直接影响合成行为：
        - `transform`: 触发合成层创建，测试验证变换变化时的更新机制。
        - `opacity`:  测试验证透明度变化是否触发 full 更新。
        - `will-change`: 提示浏览器优化，测试验证其对合成的影响。
        - `z-index`:  影响图层的叠放顺序，测试验证 z-index 变化是否触发 full 更新。
        - `background-color`:  测试验证背景色变化是否能使用 repaint 更新。
        - `filter`:  测试验证滤镜效果的合成。
        - `visibility`: 测试验证隐藏元素时的合成行为。
        - `pointer-events`: 测试验证禁用指针事件的 iframe 是否被视为可见根。
        - `background-attachment: fixed`: 测试验证固定背景的滚动是否需要主线程参与。

**逻辑推理的假设输入与输出：**

例如，对于 `TEST_P(CompositingSimTest, MainThreadScaleUpdatesTransformTree)` 这个测试：

* **假设输入:** 一个简单的 HTML 页面，并且通过 JavaScript 调用 `visualViewport.setScale(2.0)` 将页面缩放设置为 2.0。
* **预期输出:**
    - `Compositor().LayerTreeHost()->page_scale_factor()` 立即返回 `2.0f`。
    - 在执行生命周期更新后，`GetPropertyTrees()->transform_tree().page_scale_factor()` 也返回 `2.0f`。
    - 对应的变换节点（scale_node）的局部变换（local）是一个 2D 缩放，缩放比例为 (2, 2)。

**涉及用户或编程常见的使用错误：**

* **错误地认为所有样式更改都是 repaint 更新：** 开发者可能认为修改任何 CSS 属性都只会触发 repaint，但实际上像 `opacity` 或 `z-index` 的变化会触发更昂贵的 full 更新。这可能导致性能问题。
* **过度使用 `will-change`：**  开发者可能为了“优化”而对很多元素使用 `will-change`，但这实际上可能会适得其反，消耗更多内存。这些测试帮助确保 `will-change` 的行为符合预期。
* **不理解 `background-attachment: fixed` 的性能影响：** 开发者可能不清楚固定背景元素会导致滚动时需要主线程参与，从而影响滚动流畅性。相关的测试可以帮助发现这类问题。
* **在 iframe 合成方面的问题：** 开发者可能不清楚跨域 iframe 的合成边界以及相关的性能考量。这些测试覆盖了 iframe 的各种合成场景。

**用户操作如何一步步到达这里，作为调试线索：**

1. **用户访问网页:** 用户在浏览器中打开一个包含复杂动画、变换、iframe 或固定背景的网页。
2. **用户进行操作:** 用户滚动页面、缩放页面、或者与页面中的元素进行交互（例如，鼠标悬停触发动画）。
3. **浏览器触发渲染流程:** 用户的操作导致浏览器的渲染引擎需要更新页面的显示。
4. **样式计算与布局:** Blink 的样式计算和布局阶段确定了元素的最终样式和几何属性。
5. **生成绘制列表:**  根据布局结果，生成绘制列表，描述了如何绘制每个元素。
6. **合成（Compositing）:**  Blink 的合成器根据绘制列表和图层树构建最终的渲染输出。`compositing_test.cc` 中测试的逻辑就在这个阶段发挥作用。例如，如果页面包含 `will-change: transform` 的元素，合成器会创建独立的合成层。如果用户滚动页面，合成器会负责平滑地移动这些图层。
7. **调试线索:** 如果用户遇到渲染问题（例如，动画卡顿、图层显示错误），开发者可能会检查 Blink 的合成逻辑。运行 `compositing_test.cc` 中的相关测试可以帮助验证合成器的行为是否符合预期，从而定位问题的原因。例如，如果页面缩放功能异常，可以运行与页面缩放相关的测试。

**总结 `compositing_test.cc` 的功能：**

总而言之，`compositing_test.cc` 是 Blink 渲染引擎中至关重要的测试文件，它通过大量的单元测试，细致地检验了各种场景下合成逻辑的正确性、效率以及与 HTML、CSS 和 JavaScript 的协同工作方式。这些测试覆盖了属性树的更新、合成提交的触发、图层归属、不同类型的油漆更新、内容不透明度、合成更新原因以及 iframe 和外部图层的合成等关键方面，确保了 Blink 能够正确且高效地渲染复杂的网页内容。

### 提示词
```
这是目录为blink/renderer/core/paint/compositing/compositing_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
sform tree's page scale factor isn't computed until we perform a
  // lifecycle update.
  ASSERT_EQ(1.f, GetPropertyTrees()->transform_tree().page_scale_factor());

  // Update just the blink lifecycle because a full frame would clear the bit
  // for whether a commit was requested.
  UpdateAllLifecyclePhases();

  EXPECT_EQ(2.f, GetPropertyTrees()->transform_tree().page_scale_factor());

  // A main frame is needed to call UpdateLayers which updates property trees,
  // re-calculating cached to/from-screen transforms.
  EXPECT_TRUE(Compositor().LayerTreeHost()->RequestedMainFramePending());

  // A full commit is not needed.
  EXPECT_FALSE(Compositor().LayerTreeHost()->CommitRequested());
}

// Ensure that updates to page scale coming from the main thread update the
// page scale factor on the transform tree.
TEST_P(CompositingSimTest, MainThreadScaleUpdatesTransformTree) {
  InitializeWithHTML(R"HTML(
    <div>Empty Page</div>
  )HTML");
  Compositor().BeginFrame();

  ASSERT_EQ(1.f, GetPropertyTrees()->transform_tree().page_scale_factor());

  VisualViewport& viewport = WebView().GetPage()->GetVisualViewport();

  // This test checks that the transform tree's page scale factor is correctly
  // updated when scale is set with an existing property tree.
  ASSERT_TRUE(viewport.GetPageScaleNode());
  viewport.SetScale(2.f);

  // The scale factor on the layer tree should be updated immediately.
  ASSERT_EQ(2.f, Compositor().LayerTreeHost()->page_scale_factor());

  // The transform tree's page scale factor isn't computed until we perform a
  // lifecycle update.
  ASSERT_EQ(1.f, GetPropertyTrees()->transform_tree().page_scale_factor());

  Compositor().BeginFrame();

  EXPECT_EQ(2.f, GetPropertyTrees()->transform_tree().page_scale_factor());

  // Ensure the transform node is also correctly updated.
  const cc::TransformNode* scale_node =
      GetPropertyTrees()->transform_tree().FindNodeFromElementId(
          viewport.GetPageScaleNode()->GetCompositorElementId());
  ASSERT_TRUE(scale_node);
  EXPECT_TRUE(scale_node->local.IsScale2d());
  EXPECT_EQ(gfx::Vector2dF(2, 2), scale_node->local.To2dScale());
}

// Similar to above but ensure the transform tree is correctly setup when scale
// already exists when building the tree.
TEST_P(CompositingSimTest, BuildTreeSetsScaleOnTransformTree) {
  SimRequest main_resource("https://origin-a.com/a.html", "text/html");
  LoadURL("https://origin-a.com/a.html");
  main_resource.Complete(R"HTML(
      <!DOCTYPE html>
      <div>Empty Page</div>
  )HTML");

  VisualViewport& viewport = WebView().GetPage()->GetVisualViewport();

  // This test checks that the transform tree's page scale factor is correctly
  // set when scale is set before property trees have been built.
  ASSERT_FALSE(viewport.GetPageScaleNode());
  viewport.SetScale(2.f);

  // The scale factor on the layer tree should be updated immediately.
  ASSERT_EQ(2.f, Compositor().LayerTreeHost()->page_scale_factor());

  // The transform tree's page scale factor isn't computed until we perform a
  // lifecycle update.
  ASSERT_EQ(1.f, GetPropertyTrees()->transform_tree().page_scale_factor());

  Compositor().BeginFrame();

  EXPECT_EQ(2.f, GetPropertyTrees()->transform_tree().page_scale_factor());

  // Ensure the transform node is also correctly updated.
  const cc::TransformNode* scale_node =
      GetPropertyTrees()->transform_tree().FindNodeFromElementId(
          viewport.GetPageScaleNode()->GetCompositorElementId());
  ASSERT_TRUE(scale_node);
  EXPECT_TRUE(scale_node->local.IsScale2d());
  EXPECT_EQ(gfx::Vector2dF(2, 2), scale_node->local.To2dScale());
}

TEST_P(CompositingSimTest, ScrollWithMainThreadReasonsNeedsCommit) {
  InitializeWithHTML(R"HTML(
    <style>
      body { height: 2500px; }
      #h { background: url(data:image/png;base64,invalid) fixed; }
    </style>
    <div id="h">ABCDE</div>
  )HTML");
  Compositor().BeginFrame();
  auto* layer_tree_host = Compositor().LayerTreeHost();
  EXPECT_FALSE(layer_tree_host->CommitRequested());

  // Simulate 100px scroll from compositor thread.
  cc::CompositorCommitData commit_data;
  commit_data.scrolls.emplace_back(
      MainFrame().GetFrameView()->LayoutViewport()->GetScrollElementId(),
      gfx::Vector2dF(0, 100.f), std::nullopt);
  layer_tree_host->ApplyCompositorChanges(&commit_data);

  // Due to main thread scrolling reasons (fixed-background element), we need a
  // commit to push the update to the transform tree.
  EXPECT_TRUE(layer_tree_host->CommitRequested());
}

TEST_P(CompositingSimTest, FrameAttribution) {
  InitializeWithHTML(R"HTML(
    <div id='child' style='will-change: transform;'>test</div>
    <iframe id='iframe' sandbox></iframe>
  )HTML");

  Compositor().BeginFrame();

  // Ensure that we correctly attribute child layers in the main frame to their
  // containing document.
  auto* child_layer = CcLayerByDOMElementId("child");
  ASSERT_TRUE(child_layer);

  auto* child_transform_node = GetTransformNode(child_layer);
  ASSERT_TRUE(child_transform_node);

  // Iterate the transform tree to gather the parent frame element ID.
  cc::ElementId visible_frame_element_id;
  const auto* current_transform_node = child_transform_node;
  while (current_transform_node) {
    visible_frame_element_id = current_transform_node->visible_frame_element_id;
    if (visible_frame_element_id)
      break;
    current_transform_node =
        GetPropertyTrees()->transform_tree().parent(current_transform_node);
  }

  EXPECT_EQ(visible_frame_element_id,
            CompositorElementIdFromUniqueObjectId(
                GetDocument().GetDomNodeId(),
                CompositorElementIdNamespace::kDOMNodeId));

  // Test that a layerized subframe's frame element ID is that of its
  // containing document.
  Document* iframe_doc =
      To<HTMLFrameOwnerElement>(GetElementById("iframe"))->contentDocument();
  auto* iframe_layer = CcLayerForIFrameContent(iframe_doc);
  ASSERT_TRUE(iframe_layer);
  auto* iframe_transform_node = GetTransformNode(iframe_layer);
  EXPECT_TRUE(iframe_transform_node);

  EXPECT_EQ(iframe_transform_node->visible_frame_element_id,
            CompositorElementIdFromUniqueObjectId(
                iframe_doc->GetDomNodeId(),
                CompositorElementIdNamespace::kDOMNodeId));
}

TEST_P(CompositingSimTest, VisibleFrameRootLayers) {
  SimRequest main_resource("https://origin-a.com/a.html", "text/html");
  SimRequest frame_resource("https://origin-b.com/b.html", "text/html");

  LoadURL("https://origin-a.com/a.html");
  main_resource.Complete(R"HTML(
      <!DOCTYPE html>
      <iframe id="iframe" src="https://origin-b.com/b.html"></iframe>
  )HTML");
  frame_resource.Complete("<!DOCTYPE html>");
  Compositor().BeginFrame();

  // Ensure that the toplevel is marked as a visible root.
  auto* toplevel_layer = CcLayerByOwnerNode(&GetDocument());
  ASSERT_TRUE(toplevel_layer);
  auto* toplevel_transform_node = GetTransformNode(toplevel_layer);
  ASSERT_TRUE(toplevel_transform_node);

  EXPECT_TRUE(toplevel_transform_node->visible_frame_element_id);

  // Ensure that the iframe is marked as a visible root.
  Document* iframe_doc =
      To<HTMLFrameOwnerElement>(GetElementById("iframe"))->contentDocument();
  auto* iframe_layer = CcLayerForIFrameContent(iframe_doc);
  ASSERT_TRUE(iframe_layer);
  auto* iframe_transform_node = GetTransformNode(iframe_layer);
  ASSERT_TRUE(iframe_transform_node);

  EXPECT_TRUE(iframe_transform_node->visible_frame_element_id);

  // Verify that after adding `pointer-events: none`, the subframe is no longer
  // considered a visible root.
  GetElementById("iframe")->SetInlineStyleProperty(
      CSSPropertyID::kPointerEvents, "none");

  UpdateAllLifecyclePhases();

  iframe_layer = CcLayerForIFrameContent(iframe_doc);
  ASSERT_TRUE(iframe_layer);
  iframe_transform_node = GetTransformNode(iframe_layer);
  ASSERT_TRUE(iframe_transform_node);

  EXPECT_FALSE(iframe_transform_node->visible_frame_element_id);
}

TEST_P(CompositingSimTest, DecompositedTransformWithChange) {
  InitializeWithHTML(R"HTML(
    <style>
      svg { overflow: hidden; }
      .initial { transform: rotate3d(0,0,1,10deg); }
      .changed { transform: rotate3d(0,0,1,0deg); }
    </style>
    <div style='will-change: transform;'>
      <svg id='svg' xmlns='http://www.w3.org/2000/svg' class='initial'>
        <line x1='50%' x2='50%' y1='0' y2='100%' stroke='blue'/>
        <line y1='50%' y2='50%' x1='0' x2='100%' stroke='blue'/>
      </svg>
    </div>
  )HTML");

  Compositor().BeginFrame();

  auto* svg_element_layer = CcLayerByDOMElementId("svg");
  EXPECT_FALSE(svg_element_layer->subtree_property_changed());

  auto* svg_element = GetElementById("svg");
  svg_element->setAttribute(html_names::kClassAttr, AtomicString("changed"));
  UpdateAllLifecyclePhases();
  EXPECT_TRUE(svg_element_layer->subtree_property_changed());
}

// A simple repaint update should use a fast-path in PaintArtifactCompositor.
TEST_P(CompositingSimTest, BackgroundColorChangeUsesRepaintUpdate) {
  InitializeWithHTML(R"HTML(
      <!DOCTYPE html>
      <style>
        #target {
          width: 100px;
          height: 100px;
          will-change: transform;
          background: white;
        }
      </style>
      <div id='target'></div>
  )HTML");

  Compositor().BeginFrame();

  EXPECT_EQ(CcLayerByDOMElementId("target")->background_color(),
            SkColors::kWhite);

  // Initially, no update is needed.
  EXPECT_FALSE(paint_artifact_compositor()->NeedsUpdate());

  // Clear the previous update to ensure we record a new one in the next update.
  paint_artifact_compositor()->ClearPreviousUpdateForTesting();

  // Modifying paint in a simple way only requires a repaint update.
  auto* target_element = GetElementById("target");
  target_element->setAttribute(html_names::kStyleAttr,
                               AtomicString("background: black"));
  Compositor().BeginFrame();
  EXPECT_EQ(paint_artifact_compositor()->PreviousUpdateForTesting(),
            PaintArtifactCompositor::PreviousUpdateType::kRepaint);

  // Though a repaint-only update was done, the background color should still
  // be updated.
  EXPECT_EQ(CcLayerByDOMElementId("target")->background_color(),
            SkColors::kBlack);
}

// Similar to |BackgroundColorChangeUsesRepaintUpdate| but with multiple paint
// chunks being squashed into a single PendingLayer, and the background coming
// from the last paint chunk.
TEST_P(CompositingSimTest, MultipleChunkBackgroundColorChangeRepaintUpdate) {
  InitializeWithHTML(R"HTML(
      <!DOCTYPE html>
      <style>
        div {
          position: absolute;
          width: 20px;
          height: 20px;
          top: 0px;
          left: 0px;
        }
        #a {
          background: lime;
        }
        #b {
          background: red;
          transform: translate(-100px, -100px);
        }
        #c {
          width: 800px;
          height: 600px;
          background: black;
        }
      </style>
      <div id="a"></div>
      <div id="b"></div>
      <!-- background color source -->
      <div id="c"></div>
  )HTML");

  Compositor().BeginFrame();

  auto* scrolling_contents = ScrollingContentsCcLayerByScrollElementId(
      RootCcLayer(),
      MainFrame().GetFrameView()->LayoutViewport()->GetScrollElementId());

  EXPECT_EQ(scrolling_contents->background_color(), SkColors::kBlack);

  // Clear the previous update to ensure we record a new one in the next update.
  paint_artifact_compositor()->ClearPreviousUpdateForTesting();

  // Modifying paint in a simple way only requires a repaint update.
  auto* background_element = GetElementById("c");
  background_element->setAttribute(html_names::kStyleAttr,
                                   AtomicString("background: white"));
  Compositor().BeginFrame();
  EXPECT_EQ(paint_artifact_compositor()->PreviousUpdateForTesting(),
            PaintArtifactCompositor::PreviousUpdateType::kRepaint);

  // Though a repaint-only update was done, the background color should still
  // be updated.
  EXPECT_EQ(scrolling_contents->background_color(), SkColors::kWhite);
}

// Similar to |BackgroundColorChangeUsesRepaintUpdate| but with post-paint
// composited SVG. This test changes paint for a composited SVG element, as well
// as a regular HTML element in the presence of composited SVG.
TEST_P(CompositingSimTest, SVGColorChangeUsesRepaintUpdate) {
  InitializeWithHTML(R"HTML(
      <!DOCTYPE html>
      <style>
        rect, div {
          width: 100px;
          height: 100px;
          will-change: transform;
        }
      </style>
      <svg>
        <rect fill="blue" />
        <rect id="rect" fill="blue" />
        <rect fill="blue" />
      </svg>
      <div id="div" style="background: blue;" />
      <svg>
        <rect fill="blue" />
      </svg>
  )HTML");

  Compositor().BeginFrame();

  // Initially, no update is needed.
  EXPECT_FALSE(paint_artifact_compositor()->NeedsUpdate());

  // Clear the previous update to ensure we record a new one in the next update.
  paint_artifact_compositor()->ClearPreviousUpdateForTesting();

  // Modifying paint in a simple way only requires a repaint update.
  auto* rect_element = GetElementById("rect");
  rect_element->setAttribute(svg_names::kFillAttr, AtomicString("black"));
  Compositor().BeginFrame();
  EXPECT_EQ(paint_artifact_compositor()->PreviousUpdateForTesting(),
            PaintArtifactCompositor::PreviousUpdateType::kRepaint);

  // Clear the previous update to ensure we record a new one in the next update.
  paint_artifact_compositor()->ClearPreviousUpdateForTesting();

  // Modifying paint in a simple way only requires a repaint update.
  auto* div_element = GetElementById("div");
  div_element->setAttribute(html_names::kStyleAttr,
                            AtomicString("background: black"));
  Compositor().BeginFrame();
  EXPECT_EQ(paint_artifact_compositor()->PreviousUpdateForTesting(),
            PaintArtifactCompositor::PreviousUpdateType::kRepaint);
}

TEST_P(CompositingSimTest, ChangingOpaquenessRequiresFullUpdate) {
  InitializeWithHTML(R"HTML(
      <!DOCTYPE html>
      <style>
        #target {
          width: 100px;
          height: 100px;
          will-change: transform;
          background: lightgreen;
        }
      </style>
      <div id="target"></div>
  )HTML");

  Compositor().BeginFrame();

  // Initially, no update is needed.
  EXPECT_FALSE(paint_artifact_compositor()->NeedsUpdate());
  EXPECT_TRUE(CcLayerByDOMElementId("target")->contents_opaque());

  // Clear the previous update to ensure we record a new one in the next update.
  paint_artifact_compositor()->ClearPreviousUpdateForTesting();

  // A change in opaqueness still requires a full update because opaqueness is
  // used during compositing to set the cc::Layer's contents opaque property
  // (see: PaintArtifactCompositor::CompositedLayerForPendingLayer).
  auto* target_element = GetElementById("target");
  target_element->setAttribute(html_names::kStyleAttr,
                               AtomicString("background: rgba(1, 0, 0, 0.1)"));
  Compositor().BeginFrame();
  EXPECT_EQ(paint_artifact_compositor()->PreviousUpdateForTesting(),
            PaintArtifactCompositor::PreviousUpdateType::kFull);
  EXPECT_FALSE(CcLayerByDOMElementId("target")->contents_opaque());
}

TEST_P(CompositingSimTest, ChangingContentsOpaqueForTextRequiresFullUpdate) {
  InitializeWithHTML(R"HTML(
      <!DOCTYPE html>
      <style>
        #target {
          width: 100px;
          height: 100px;
          will-change: transform;
        }
        #textContainer {
          width: 50px;
          height: 50px;
          padding: 5px;
          background: lightblue;
        }
      </style>
      <div id="target">
        <div id="textContainer">
          mars
        </div>
      </div>
  )HTML");

  Compositor().BeginFrame();

  // Initially, no update is needed.
  EXPECT_FALSE(paint_artifact_compositor()->NeedsUpdate());
  EXPECT_FALSE(CcLayerByDOMElementId("target")->contents_opaque());
  EXPECT_TRUE(CcLayerByDOMElementId("target")->contents_opaque_for_text());

  // Clear the previous update to ensure we record a new one in the next update.
  paint_artifact_compositor()->ClearPreviousUpdateForTesting();

  // A change in opaqueness for text still requires a full update because
  // opaqueness is used during compositing to set the cc::Layer's contents
  // opaque for text property (see:
  // PaintArtifactCompositor::CompositedLayerForPendingLayer).
  auto* text_container_element = GetElementById("textContainer");
  text_container_element->setAttribute(
      html_names::kStyleAttr, AtomicString("background: rgba(1, 0, 0, 0.1)"));
  Compositor().BeginFrame();
  EXPECT_EQ(paint_artifact_compositor()->PreviousUpdateForTesting(),
            PaintArtifactCompositor::PreviousUpdateType::kFull);
  EXPECT_FALSE(CcLayerByDOMElementId("target")->contents_opaque());
  EXPECT_FALSE(CcLayerByDOMElementId("target")->contents_opaque_for_text());
}

TEST_P(CompositingSimTest, ChangingDrawsContentRequiresFullUpdate) {
  InitializeWithHTML(R"HTML(
      <!DOCTYPE html>
      <style>
        #target {
          width: 100px;
          height: 100px;
          will-change: transform;
        }
      </style>
      <div id="target"></div>
  )HTML");

  Compositor().BeginFrame();

  // Initially, no update is needed.
  EXPECT_FALSE(paint_artifact_compositor()->NeedsUpdate());
  EXPECT_FALSE(CcLayerByDOMElementId("target")->draws_content());

  // Clear the previous update to ensure we record a new one in the next update.
  paint_artifact_compositor()->ClearPreviousUpdateForTesting();

  // A simple repaint change that causes Layer::DrawsContent to change still
  // needs to cause a full update because it can affect whether mask layers are
  // created.
  auto* target = GetElementById("target");
  target->setAttribute(html_names::kStyleAttr,
                       AtomicString("background: rgba(0,0,0,0.5)"));
  Compositor().BeginFrame();
  EXPECT_EQ(paint_artifact_compositor()->PreviousUpdateForTesting(),
            PaintArtifactCompositor::PreviousUpdateType::kFull);
  EXPECT_TRUE(CcLayerByDOMElementId("target")->draws_content());
}

TEST_P(CompositingSimTest, ContentsOpaqueForTextWithSubpixelSizeSimpleBg) {
  InitializeWithHTML(R"HTML(
      <!DOCTYPE html>
      <div id="target" style="will-change: transform; background: white;
                              width: 100.6px; height: 10.3px">
        TEXT
      </div>
  )HTML");
  Compositor().BeginFrame();
  auto* cc_layer = CcLayerByDOMElementId("target");
  // We adjust visual rect of the DrawingDisplayItem with simple painting to the
  // bounds of the painting.
  EXPECT_EQ(gfx::Size(101, 10), cc_layer->bounds());
  EXPECT_TRUE(cc_layer->contents_opaque());
  EXPECT_TRUE(cc_layer->contents_opaque_for_text());
}

TEST_P(CompositingSimTest, ContentsOpaqueForTextWithSubpixelSizeComplexBg) {
  InitializeWithHTML(R"HTML(
      <!DOCTYPE html>
      <div id="target" style="will-change: transform; background: white;
                              border: 2px inset blue;
                              width: 100.6px; height: 10.3px">
        TEXT
      </div>
  )HTML");
  Compositor().BeginFrame();
  auto* cc_layer = CcLayerByDOMElementId("target");
  EXPECT_EQ(gfx::Size(105, 15), cc_layer->bounds());
  EXPECT_FALSE(cc_layer->contents_opaque());
  EXPECT_TRUE(cc_layer->contents_opaque_for_text());
}

TEST_P(CompositingSimTest, ContentsOpaqueForTextWithPartialBackground) {
  InitializeWithHTML(R"HTML(
      <!DOCTYPE html>
      <div id="target" style="will-change: transform; padding: 10px">
        <div style="background: white">TEXT</div>
      </div>
  )HTML");
  Compositor().BeginFrame();
  auto* cc_layer = CcLayerByDOMElementId("target");
  EXPECT_FALSE(cc_layer->contents_opaque());
  EXPECT_TRUE(cc_layer->contents_opaque_for_text());
}

TEST_P(CompositingSimTest, ContentsOpaqueForTextWithBorderRadiusAndPadding) {
  InitializeWithHTML(R"HTML(
      <!DOCTYPE html>
      <div id="target" style="will-change: transform; border-radius: 5px;
                              padding: 10px; background: blue">
        TEXT
      </div>
  )HTML");
  Compositor().BeginFrame();
  auto* cc_layer = CcLayerByDOMElementId("target");
  EXPECT_FALSE(cc_layer->contents_opaque());
  EXPECT_TRUE(cc_layer->contents_opaque_for_text());
}

TEST_P(CompositingSimTest, FullCompositingUpdateReasons) {
  InitializeWithHTML(R"HTML(
      <!DOCTYPE html>
      <style>
        div {
          width: 100px;
          height: 100px;
          will-change: transform;
          position: absolute;
        }
        #a {
          background: lightgreen;
          z-index: 10;
        }
        #b {
          background: lightblue;
          z-index: 20;
        }
      </style>
      <div id="a"></div>
      <div id="b"></div>
  )HTML");

  Compositor().BeginFrame();

  // Initially, no update is needed.
  EXPECT_FALSE(paint_artifact_compositor()->NeedsUpdate());

  // Clear the previous update to ensure we record a new one in the next update.
  paint_artifact_compositor()->ClearPreviousUpdateForTesting();

  // Reordering paint chunks requires a full update. Overlap testing and the
  // order of synthetic effect layers are two examples of paint changes that
  // affect compositing decisions.
  auto* b_element = GetElementById("b");
  b_element->setAttribute(html_names::kStyleAttr, AtomicString("z-index: 5"));
  Compositor().BeginFrame();
  EXPECT_EQ(paint_artifact_compositor()->PreviousUpdateForTesting(),
            PaintArtifactCompositor::PreviousUpdateType::kFull);

  // Clear the previous update to ensure we record a new one in the next update.
  paint_artifact_compositor()->ClearPreviousUpdateForTesting();

  // Removing a paint chunk requires a full update.
  b_element->setAttribute(html_names::kStyleAttr,
                          AtomicString("display: none"));
  Compositor().BeginFrame();
  EXPECT_EQ(paint_artifact_compositor()->PreviousUpdateForTesting(),
            PaintArtifactCompositor::PreviousUpdateType::kFull);

  // Clear the previous update to ensure we record a new one in the next update.
  paint_artifact_compositor()->ClearPreviousUpdateForTesting();

  // Adding a paint chunk requires a full update.
  b_element->setAttribute(html_names::kStyleAttr, g_empty_atom);
  Compositor().BeginFrame();
  EXPECT_EQ(paint_artifact_compositor()->PreviousUpdateForTesting(),
            PaintArtifactCompositor::PreviousUpdateType::kFull);

  // Clear the previous update to ensure we record a new one in the next update.
  paint_artifact_compositor()->ClearPreviousUpdateForTesting();

  // Changing the size of a chunk affects overlap and requires a full update.
  b_element->setAttribute(html_names::kStyleAttr, AtomicString("width: 101px"));
  Compositor().BeginFrame();
  EXPECT_EQ(paint_artifact_compositor()->PreviousUpdateForTesting(),
            PaintArtifactCompositor::PreviousUpdateType::kFull);
}

// Similar to |FullCompositingUpdateReasons| but for changes in post-paint
// composited SVG.
TEST_P(CompositingSimTest, FullCompositingUpdateReasonWithCompositedSVG) {
  InitializeWithHTML(R"HTML(
      <!DOCTYPE html>
      <style>
        #rect {
          width: 100px;
          height: 100px;
          will-change: transform;
        }
      </style>
      <svg>
        <rect id="rect" fill="blue" />
      </svg>
  )HTML");

  Compositor().BeginFrame();

  // Initially, no update is needed.
  EXPECT_FALSE(paint_artifact_compositor()->NeedsUpdate());

  // Clear the previous update to ensure we record a new one in the next update.
  paint_artifact_compositor()->ClearPreviousUpdateForTesting();

  // Changing the size of a chunk affects overlap and requires a full update.
  auto* rect = GetElementById("rect");
  rect->setAttribute(html_names::kStyleAttr, AtomicString("width: 101px"));
  Compositor().BeginFrame();
  EXPECT_EQ(paint_artifact_compositor()->PreviousUpdateForTesting(),
            PaintArtifactCompositor::PreviousUpdateType::kFull);
}

TEST_P(CompositingSimTest, FullCompositingUpdateForJustCreatedChunks) {
  InitializeWithHTML(R"HTML(
      <!DOCTYPE html>
      <style>
        .firstLetterStyle:first-letter {
          background: red;
        }
        rect {
          width: 100px;
          height: 100px;
          fill: blue;
        }
      </style>
      <svg>
        <rect style="will-change: transform;"></rect>
        <rect id="target"></rect>
      </svg>
  )HTML");

  Compositor().BeginFrame();

  // Initially, no update is needed.
  EXPECT_FALSE(paint_artifact_compositor()->NeedsUpdate());

  // Clear the previous update to ensure we record a new one in the next update.
  paint_artifact_compositor()->ClearPreviousUpdateForTesting();

  // A new LayoutObject is "just created" and will not match existing chunks and
  // needs a full update. A first letter style adds a pseudo element which
  // results in rebuilding the #target LayoutObject.
  auto* target = GetElementById("target");
  target->setAttribute(html_names::kClassAttr,
                       AtomicString("firstLetterStyle"));
  Compositor().BeginFrame();
  EXPECT_EQ(paint_artifact_compositor()->PreviousUpdateForTesting(),
            PaintArtifactCompositor::PreviousUpdateType::kFull);
}

TEST_P(CompositingSimTest, FullCompositingUpdateForUncachableChunks) {
  InitializeWithHTML(R"HTML(
      <!DOCTYPE html>
      <style>
        rect {
          width: 100px;
          height: 100px;
          fill: blue;
          will-change: transform;
        }
        div {
          width: 100px;
          height: 100px;
          background: lightblue;
        }
      </style>
      <svg>
        <rect id="rect"></rect>
      </svg>
      <div id="target"></div>
  )HTML");

  Compositor().BeginFrame();

  // Make the rect display item client uncachable. To avoid depending on when
  // this occurs in practice (see: |DisplayItemCacheSkipper|), this is done
  // directly.
  auto* rect = GetElementById("rect");
  auto* rect_client = static_cast<DisplayItemClient*>(rect->GetLayoutObject());
  rect_client->Invalidate(PaintInvalidationReason::kUncacheable);
  rect->setAttribute(html_names::kStyleAttr, AtomicString("fill: green"));
  Compositor().BeginFrame();

  // Initially, no update is needed.
  EXPECT_FALSE(paint_artifact_compositor()->NeedsUpdate());

  // Clear the previous update to ensure we record a new one in the next update.
  paint_artifact_compositor()->ClearPreviousUpdateForTesting();

  // A full update should be required due to the presence of uncacheable
  // paint chunks.
  auto* target = GetElementById("target");
  target->setAttribute(html_names::kStyleAttr,
                       AtomicString("background: lightgreen"));
  Compositor().BeginFrame();
  EXPECT_EQ(paint_artifact_compositor()->PreviousUpdateForTesting(),
            PaintArtifactCompositor::PreviousUpdateType::kFull);
}

TEST_P(CompositingSimTest, DecompositeScrollerInHiddenIframe) {
  SimRequest top_resource("https://example.com/top.html", "text/html");
  SimRequest middle_resource("https://example.com/middle.html", "text/html");
  SimRequest bottom_resource("https://example.com/bottom.html", "text/html");

  LoadURL("https://example.com/top.html");
  top_resource.Complete(R"HTML(
    <iframe id='middle' src='https://example.com/middle.html'></iframe>
  )HTML");
  middle_resource.Complete(R"HTML(
    <iframe id='bottom' src='bottom.html'></iframe>
  )HTML");
  bottom_resource.Complete(R"HTML(
    <div id='scroller' style='overflow:scroll;max-height:100px;background-color:#888'>
      <div style='height:1000px;'>Hello, world!</div>
    </div>
  )HTML");

  LocalFrame& middle_frame =
      *To<LocalFrame>(GetDocument().GetFrame()->Tree().FirstChild());
  LocalFrame& bottom_frame = *To<LocalFrame>(middle_frame.Tree().FirstChild());
  middle_frame.View()->BeginLifecycleUpdates();
  bottom_frame.View()->BeginLifecycleUpdates();
  Compositor().BeginFrame();
  EXPECT_TRUE(CcLayerByDOMElementId("scroller"));

  // Hide the iframes. Scroller should be decomposited.
  GetDocument()
      .getElementById(AtomicString("middle"))
      ->SetInlineStyleProperty(CSSPropertyID::kVisibility, CSSValueID::kHidden);
  Compositor().BeginFrame();
  EXPECT_FALSE(CcLayerByDOMElementId("scroller"));
}

TEST_P(CompositingSimTest, ForeignLayersInMovedSubsequence) {
  SimRequest main_resource("https://origin-a.com/a.html", "text/html");
  LoadURL("https://origin-a.com/a.html");
  main_resource.Complete(R"HTML(
      <!DOCTYPE html>
      <style> iframe { isolation: isolate; } </style>
      <iframe sandbox src="https://origin-b.com/b.html"></iframe>
      <div id="target" style="background: blue;">a</div>
  )HTML");

  FakeRemoteFrameHost remote_frame_host;
  WebRemoteFrameImpl* remote_frame = frame_test_helpers::CreateRemote();
  frame_test_helpers::SwapRemoteFrame(
      MainFrame().FirstChild(), remote_frame,
      remote_frame_host.BindNewAssociatedRemote());

  Compositor().BeginFrame();

  auto remote_surface_layer = cc::SurfaceLayer::Create();
  remote_frame->GetFrame()->SetCcLayerForTesting(remote_surface_layer, true);
  Compositor().BeginFrame();

  // Initially, no update is needed.
  EXPECT_FALSE(paint_artifact_compositor()->NeedsUpdate());

  // Clear the previous update to ensure we record a new one in the next update.
  paint_artifact_compositor()->ClearPreviousUpdateForTesting();

  // Modifying paint in a simple way only requires a repaint update.
  auto* target_element = GetElementById("target");
  target_element->setAttribute(html_names::kStyleAttr,
                               AtomicString("background: green;"));
  Compositor().BeginFrame();
  EXPECT_EQ(paint_artifact_compositor()->PreviousUpdateForTesting(),
            PaintArtifactCompositor::PreviousUpdateType::kRepaint);

  remote_frame->Detach();
}

// While not required for correctness, it is important for performance that
// snapped backgrounds use solid color layers which avoid tiling.
TEST_P(CompositingSimTest, SolidColorLayersWithSnapping) {
  InitializeWithHTML(R"HTML(
      <!DOCTYPE html>
      <style>
        #snapDown {
          width: 60.1px;
          height: 100px;
          will-change: opacity;
          background: blue;
        }
        #snapUp {
          width: 60.9px;
          height: 100px;
          will-change: opacity;
          background: blue;
        }
      </style>
      <div id="snapDown"></div>
      <div id="snapUp"></div>
  )HTML");

  Compositor().BeginFrame();

  auto* snap_down = CcLayerByDOMElementId("snapDown");
  auto* snap_up = CcLayerByDOMElementId("snapUp");
  EXPECT_TRUE(snap_down->IsSolidColorLayerForTesting());
  EXPECT_TRUE(snap_up->IsSolidColorLayerForTesting());
}

TEST_P(CompositingSimTest, SolidColorLayerWithSubpixelTransform) {
  InitializeWithHTML(R"HTML(
      <!DOCTYPE html>
      <style>
        #forceCompositing {
          position: absolute;
          width: 100px;
          height: 100px;
          will-change: transform;
        }
        #target {
          position: absolute;
          top: 0;
          left: 0;
          width: 60.9px;
          height: 60.1px;
          transform: translate(0.4px, 0.6px);
          background: blue;
        }
      </style>
      <div id="forceCompositing"></div>
      <div id="target"></div>
  )HTML");

  Compositor().BeginFrame();

  auto* target = CcLayerByDOMElementId("target");
  EXPECT_TRUE(target->IsSolidColorLayerForTesting());
  EXPECT_NEAR(0.4, target->offset_to_transform_parent().x(), 0.001);
  EXPECT_NEAR(0.6, target->offset_to_transform_parent().y(), 0.001);
}

// While not required for correctness, it is important for performance (e.g.,
// the MotionMark Focus benchmark) that we do not decomposite effect nodes (see:
// |PaintArtifactCompositor::DecompositeEffect|) when the author has specified
// 3D transforms which are frequently used as a generic compositing trigger.
TEST_P(CompositingSimTest, EffectCompositedWith3DTransform) {
  InitializeWithHTML(R"HTML(
      <!DOCTYPE html>
      <style>
        div {
          width: 100px;
          height: 100px;
          background: rebeccapurple;
          transform: translate3d(1px, 1px, 0);
        }
      </style>
      <div id="opacity" style="opacity: 0.5;"></div>
      <div id="filter" style="filter: blur(1px);"></div>
  )HTML");
  Compositor().BeginFrame();

  auto* opacity_effect = GetEffectNode(CcLayerByDOMElementId("opacity"));
  EXPECT_TRUE(opacity_effect);
  EXPECT_EQ(opacity_effect->opacity, 0.5f);
  EXPECT_TRUE(opacity_effect->filters.IsEmpty());

  auto* filter_effect = GetEffectNode(CcLayerByDOMElementId("filter"));
  EXPECT_TRUE(filter_effect);
  EXPECT_EQ(filter_effect->opacity, 1.f);
  EXPECT_FALSE(filter
```