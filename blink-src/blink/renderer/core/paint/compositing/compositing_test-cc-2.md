Response:
The user wants a summary of the functionality of the provided C++ code snippet from a Chromium source file. They also want to know about its relationship to web technologies (JavaScript, HTML, CSS), examples of logical reasoning with input/output, common user/programming errors, and how a user's actions could lead to this code being executed.

Here's a breakdown of the code and how to address the user's request:

1. **Identify the core purpose:** The code consists of several test cases within a C++ testing framework (`TEST_P`). These tests seem to be focused on verifying the behavior of the compositing system in Blink (the rendering engine of Chromium). They are specifically testing how changes to CSS properties and the structure of the DOM affect the creation and management of composited layers and property trees (transform, effect, clip).

2. **Relate to web technologies:**  The tests manipulate the DOM and CSS styles. This directly links to HTML and CSS. While JavaScript isn't explicitly present in *this* snippet, it's crucial to understand that JavaScript is often the mechanism for making dynamic changes to styles and the DOM, which these tests are simulating.

3. **Logical reasoning (Input/Output):**  Each test case sets up an initial HTML structure and potentially some initial conditions. Then, it performs an action (e.g., changing a CSS attribute) and asserts the resulting state of the compositing system (e.g., whether a transform node has changed, whether a layer has a specific property set). The input is the initial state and the action; the output is the asserted state of the compositing system.

4. **User/Programming errors:** The tests implicitly highlight potential errors. For example, if a developer doesn't understand how `will-change` affects compositing, they might be surprised by which elements get their own layers. Incorrectly setting `position: fixed` could lead to unexpected behavior related to viewport bounds.

5. **User actions as debugging clues:**  The tests often simulate user interactions or the results of user interactions. For example, scrolling, changing the size of the viewport, or the loading of iframes are directly related to user actions. Understanding these tests can help developers debug compositing-related issues that users might encounter.

6. **Summarize the functionality:** Combine the understanding of individual test cases to provide an overall summary of the file's purpose.

**Constraint Checklist & Confidence Score:**

* Provide functionality: Yes
* Relationship to JS/HTML/CSS: Yes
* Examples for JS/HTML/CSS: Yes
* Logical reasoning: Yes
* Input/Output for reasoning: Yes
* User/programming errors: Yes
* Examples for errors: Yes
* User operation to reach here: Yes
* Debugging clues: Yes
* Part 3 of 5: Acknowledge and focus on the provided snippet.
*归纳功能: Yes

Confidence Score: 5/5

**Mental Sandbox:**

I'll mentally walk through a couple of the test cases to solidify my understanding:

* **`LifecyclePhasesExceptPaint`:**  This test shows how a transform change on an inner element triggers an update that marks both the inner and outer transform nodes as changed, ensuring damage and repaint. The input is the initial HTML and the change to the inner element's transform. The output is the state of the `transform_changed` flags on the transform nodes.
* **`AffectedByOuterViewportBoundsDelta`:** This test demonstrates how `position: fixed` elements are handled. When fixed to the bottom, their transform node needs to be aware of viewport changes. The input is the HTML and the changing of the `bottom` and `top` styles. The output is the `moved_by_outer_viewport_bounds_delta_y` flag on the transform node.

By analyzing these examples, I can generate a comprehensive and accurate summary addressing all the user's points. I will avoid making assumptions about parts 1, 2, 4, and 5 and focus solely on the provided code.
这是`blink/renderer/core/paint/compositing/compositing_test.cc`文件的第三部分，延续了前两部分的内容，继续测试 Blink 渲染引擎中与 Compositing（合成）相关的各种功能。 这部分代码主要关注以下几个方面的测试：

**核心功能归纳：**

* **验证 Transform 属性更改后的 Compositing 行为:** 测试 Transform 属性的更改如何影响 Compositing 图层的更新和标记，包括 `transform_changed` 标志的设置和重置。涵盖了直接修改 Transform 属性以及修改影响 Transform 的其他属性（如 `transform-origin`）的情况。
* **测试固定定位元素 (position: fixed) 与视口变化的交互:**  验证当固定定位元素固定在视口底部时，其 Transform 节点是否正确标记，以便在视口大小变化时进行必要的调整。
* **验证 Effect 属性 (如 filter) 更改后的 Compositing 行为:** 测试 Effect 属性的更改如何导致 Compositing 图层及其子树的更新，并检查 `subtree_property_changed` 和 `effect_changed` 标志的设置。
* **验证 Clip 属性 (包括 `clip` 和 `overflow`) 更改后的 Compositing 行为:**  测试 Clip 属性的更改如何影响 Compositing 图层及其子树的更新，并检查 `subtree_property_changed` 标志的设置。 还包括了 Clip 节点本身未改变，但与图层关联的 Clip 节点发生变化的情况。
* **测试 `safeOpaqueBackgroundColor` 的计算:** 验证在不同背景颜色和内容不透明度的情况下，Compositing 图层 `safeOpaqueBackgroundColor` 的计算是否正确。 这涉及到纯色背景、渐变背景、半透明背景以及包含子元素的场景。
* **测试跨域 Iframe 的 Compositing 处理:**  验证跨域 Iframe 是否会被提升为独立的 Compositing 图层，以及在 Iframe 加载后或改变域后，Compositing 状态的变化。
* **验证 Effect 节点是否包含 Element ID:**  这是一个回归测试，确保 Effect 节点在某些特定场景下（如使用了 `backdrop-filter`）正确设置了 Element ID。
* **测试 Impl-Side Scroll (合成器侧滚动) 的优化:** 验证在合成器侧滚动的场景下，是否可以跳过主线程的 Commit 阶段，以提高性能。涵盖了 `will-change: transform` 触发合成的情况和普通滚动的情况，以及滚动元素是否可见的情况。
* **测试 Impl-Side Page Scale (合成器侧页面缩放) 的优化:** 验证在合成器侧进行页面缩放时，是否可以跳过主线程的 Commit 阶段。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:** 代码中使用了 `InitializeWithHTML` 方法来设置测试所需的 HTML 结构。例如：
    ```c++
    InitializeWithHTML(R"HTML(
        <!DOCTYPE html>
        <div id='box' style='transform: translateX(10px);'></div>
    )HTML");
    ```
    这部分 HTML 代码定义了一个带有 ID 为 `box` 的 `div` 元素，并设置了初始的 `transform` 样式。

* **CSS:** 测试代码通过修改 DOM 元素的 `style` 属性来模拟 CSS 属性的更改。例如：
    ```c++
    box_element->setAttribute(html_names::kStyleAttr,
                              AtomicString("transform: translateX(20px)"));
    ```
    这模拟了通过 JavaScript 或 CSS 规则更改元素的 `transform` 属性。测试会验证这种更改如何影响 Compositing 层的 `transform_changed` 状态。

* **JavaScript:** 虽然这个 C++ 文件本身不包含 JavaScript 代码，但它测试的场景通常与 JavaScript 操作有关。例如，JavaScript 可以通过以下方式触发这里测试的 Compositing 行为：
    * 使用 JavaScript 修改元素的 `style` 属性（如上面的 CSS 例子）。
    * 使用 JavaScript 动画 API (如 `requestAnimationFrame`) 来驱动元素的 Transform 或 Effect 属性的变化。
    * 通过用户交互触发 JavaScript 代码，间接修改元素的样式。

**逻辑推理 (假设输入与输出):**

**示例 1: `LifecyclePhasesExceptPaint` 测试**

* **假设输入:**
    * HTML 结构包含一个外部 `div` 和一个内部 `div`，外部 `div` 设置了 `will-change: transform`，内部 `div` 的 Transform 属性被 JavaScript 或 CSS 动画更改。
    * 初始状态下，Transform 节点的 `transform_changed` 标志为 `false`。
* **操作:** 内部 `div` 的 Transform 属性发生变化。
* **预期输出:**
    * 在 `UpdateAllLifecyclePhasesExceptPaint()` 调用后，外部和内部 `div` 对应的 Transform 节点的 `transform_changed` 标志都为 `true`。
    * 在 `UpdateAllLifecyclePhases()` 调用后，外部和内部 `div` 对应的 Transform 节点的 `transform_changed` 标志仍然为 `true`。
    * 在 `Compositor().BeginFrame()` 调用后，外部和内部 `div` 对应的 Transform 节点的 `transform_changed` 标志被重置为 `false`。

**示例 2: `AffectedByOuterViewportBoundsDelta` 测试**

* **假设输入:**
    * HTML 结构包含一个 `position: fixed` 的 `div` 元素。
    * 初始状态下，该 `div` 的 `bottom` 属性设置为 `0`。
* **操作:** 调用 `Compositor().BeginFrame()` 触发 Compositing。
* **预期输出:** 该 `div` 对应的 Transform 节点的 `moved_by_outer_viewport_bounds_delta_y` 标志为 `true`，因为该元素固定在底部，需要根据视口变化进行调整。
* **操作:** 将该 `div` 的 `bottom` 属性修改为 `top: 0`，并再次调用 `Compositor().BeginFrame()`。
* **预期输出:** 该 `div` 对应的 Transform 节点的 `moved_by_outer_viewport_bounds_delta_y` 标志为 `false`，因为该元素固定在顶部，不需要根据视口变化进行调整。

**用户或编程常见的使用错误及举例说明:**

* **忘记使用 `will-change` 导致意外的 Compositing:** 开发者可能期望某个元素进行 Compositing，但忘记设置 `will-change: transform` 或其他触发 Compositing 的属性，导致性能问题。例如，一个经常移动的元素没有被提升为独立的 Compositing 图层，每次移动都会触发重绘。
* **过度使用 `will-change`:**  开发者可能为了“优化”性能而对所有可能发生变化的元素都设置 `will-change`，但这会消耗额外的内存，并可能导致性能下降。只应该对实际会频繁变化的属性使用 `will-change`。
* **不理解 `position: fixed` 与 Compositing 的关系:** 开发者可能没有意识到固定定位的元素在某些情况下需要特殊的 Compositing 处理，例如视口变化时的调整。如果开发者错误地假设固定定位元素的行为与其他定位方式相同，可能会导致布局或渲染问题。
* **跨域 Iframe 的 Compositing 问题:** 开发者可能不清楚跨域 Iframe 会被提升为独立的 Compositing 图层，这可能会影响到一些依赖于父框架的渲染效果或事件处理。例如，父框架的某些 CSS 效果可能不会应用到跨域 Iframe 上。

**用户操作是如何一步步的到达这里，作为调试线索:**

这些测试是自动化测试，通常不由最终用户直接触发。但是，用户在浏览器中的操作会触发浏览器的渲染引擎执行相应的 Compositing 逻辑，而这些测试就是用来验证这些逻辑是否正确的。以下是一些用户操作如何间接触发这些测试所覆盖的功能：

1. **用户滚动页面:**  `ImplSideScrollSkipsCommit` 和 `RasterInducingScrollSkipsCommit` 测试了滚动相关的优化。用户的滚动操作会触发滚动事件，导致页面内容发生位移，Compositing 系统需要更新滚动区域的显示。
2. **用户拖拽或调整窗口大小:**  这些操作可能导致视口大小改变，从而触发 `AffectedByOuterViewportBoundsDelta` 测试所覆盖的固定定位元素的处理逻辑。
3. **用户与页面上的动画元素交互:**  如果页面包含使用 CSS 动画或 JavaScript 动画的元素，这些动画会改变元素的 Transform 或 Effect 属性，从而触发 `LifecyclePhasesExceptPaint` 和 `LayerSubtreeEffectPropertyChanged` 等测试所覆盖的逻辑。
4. **用户加载包含 Iframe 的页面:**  当页面包含 Iframe 时，特别是跨域 Iframe，会触发 `PromoteCrossOriginIframe` 等测试所覆盖的逻辑，涉及到 Compositing 图层的创建和管理。
5. **用户进行页面缩放 (pinch-zoom):**  `ImplSideScaleSkipsCommit` 测试了用户进行页面缩放时的优化。

**作为调试线索:** 当开发者在 Chromium 浏览器中遇到与 Compositing 相关的 Bug 时，例如页面滚动卡顿、动画性能不佳、固定定位元素行为异常、跨域 Iframe 渲染问题等，他们可以查看这些 Compositing 相关的测试代码，了解 Blink 引擎是如何处理这些情况的。如果某个具体的测试失败，就可能表明相关的 Compositing 功能存在问题。开发者可以通过分析测试代码和失败的场景，找到 Bug 的根源并进行修复。

总而言之，这部分测试代码深入验证了 Blink 引擎中 Compositing 机制的各个方面，确保了在各种场景下（包括 CSS 属性变化、用户交互、Iframe 处理等）Compositing 行为的正确性和性能。它们是理解和调试 Chromium 渲染引擎 Compositing 功能的重要资源。

Prompt: 
```
这是目录为blink/renderer/core/paint/compositing/compositing_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共5部分，请归纳一下它的功能

"""
lLifecyclePhasesExceptPaint();
  EXPECT_TRUE(outer_transform_node->transform_changed);
  EXPECT_FALSE(inner_transform_node->transform_changed);
  EXPECT_TRUE(paint_artifact_compositor()->NeedsUpdate());

  // After a PaintArtifactCompositor update, which was needed due to the inner
  // element's transform change, both the inner and outer transform nodes
  // should be marked as changed to ensure they result in damage.
  UpdateAllLifecyclePhases();
  EXPECT_TRUE(outer_transform_node->transform_changed);
  EXPECT_TRUE(inner_transform_node->transform_changed);

  // After a frame the |transform_changed| values should be reset.
  Compositor().BeginFrame();
  EXPECT_FALSE(outer_transform_node->transform_changed);
  EXPECT_FALSE(inner_transform_node->transform_changed);
}

// This test ensures that the correct transform nodes are created and bits set
// so that the browser controls movement adjustments needed by bottom-fixed
// elements will work.
TEST_P(CompositingSimTest, AffectedByOuterViewportBoundsDelta) {
  InitializeWithHTML(R"HTML(
      <!DOCTYPE html>
      <style>
        body { height: 2000px; }
        #fixed {
          width: 100px;
          height: 100px;
          position: fixed;
          left: 0;
          background-color: red;
        }
      </style>
      <div id='fixed'></div>
  )HTML");

  auto* fixed_element = GetElementById("fixed");
  auto* fixed_element_layer = CcLayerByDOMElementId("fixed");

  // Fix the DIV to the bottom of the viewport. Since the viewport height will
  // expand/contract, the fixed element will need to be moved as the bounds
  // delta changes.
  {
    fixed_element->setAttribute(html_names::kStyleAttr,
                                AtomicString("bottom: 0"));
    Compositor().BeginFrame();

    auto transform_tree_index = fixed_element_layer->transform_tree_index();
    const auto* transform_node =
        GetPropertyTrees()->transform_tree().Node(transform_tree_index);

    DCHECK(transform_node);
    EXPECT_TRUE(transform_node->moved_by_outer_viewport_bounds_delta_y);
  }

  // Fix it to the top now. Since the top edge doesn't change (relative to the
  // renderer origin), we no longer need to move it as the bounds delta
  // changes.
  {
    fixed_element->setAttribute(html_names::kStyleAttr, AtomicString("top: 0"));
    Compositor().BeginFrame();

    auto transform_tree_index = fixed_element_layer->transform_tree_index();
    const auto* transform_node =
        GetPropertyTrees()->transform_tree().Node(transform_tree_index);

    DCHECK(transform_node);
    EXPECT_FALSE(transform_node->moved_by_outer_viewport_bounds_delta_y);
  }
}

// When a property tree change occurs that affects layer transform-origin, the
// transform can be directly updated without explicitly marking the layer as
// damaged. The ensure damage occurs, the transform node should have
// |transform_changed| set.
TEST_P(CompositingSimTest, DirectTransformOriginPropertyUpdate) {
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
        #box {
          width: 100px;
          height: 100px;
          animation-name: animateTransformA;
          animation-duration: 999s;
          transform-origin: 10px 10px 100px;
          background: lightblue;
        }
      </style>
      <div id='box'></div>
  )HTML");

  Compositor().BeginFrame();

  auto* box_element = GetElementById("box");
  auto* box_element_layer = CcLayerByDOMElementId("box");
  auto transform_tree_index = box_element_layer->transform_tree_index();
  const auto* transform_node =
      GetPropertyTrees()->transform_tree().Node(transform_tree_index);

  // Initially, transform should be unchanged.
  EXPECT_FALSE(transform_node->transform_changed);
  EXPECT_FALSE(paint_artifact_compositor()->NeedsUpdate());

  // Modifying the transform-origin in a simple way allowed for a direct update.
  box_element->setAttribute(html_names::kStyleAttr,
                            AtomicString("animation-name: animateTransformB"));
  UpdateAllLifecyclePhasesExceptPaint();
  EXPECT_TRUE(transform_node->transform_changed);
  EXPECT_FALSE(paint_artifact_compositor()->NeedsUpdate());

  // After a frame the |transform_changed| value should be reset.
  Compositor().BeginFrame();
  EXPECT_FALSE(transform_node->transform_changed);
}

// This test is similar to |LayerSubtreeTransformPropertyChanged| but for
// effect property node changes.
TEST_P(CompositingSimTest, LayerSubtreeEffectPropertyChanged) {
  InitializeWithHTML(R"HTML(
      <!DOCTYPE html>
      <style>
        html { overflow: hidden; }
        #outer {
          width: 100px;
          height: 100px;
          will-change: transform;
          filter: blur(10px);
        }
        #inner {
          width: 100px;
          height: 100px;
          will-change: transform, filter;
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
  EXPECT_FALSE(GetEffectNode(outer_element_layer)->effect_changed);
  EXPECT_FALSE(inner_element_layer->subtree_property_changed());
  EXPECT_FALSE(GetEffectNode(inner_element_layer)->effect_changed);

  // Modifying the filter style should set |subtree_property_changed| on
  // both layers.
  outer_element->setAttribute(html_names::kStyleAttr,
                              AtomicString("filter: blur(20px)"));
  UpdateAllLifecyclePhases();
  EXPECT_TRUE(outer_element_layer->subtree_property_changed());
  // Set by blink::PropertyTreeManager.
  EXPECT_TRUE(GetEffectNode(outer_element_layer)->effect_changed);
  EXPECT_TRUE(inner_element_layer->subtree_property_changed());
  EXPECT_FALSE(GetEffectNode(inner_element_layer)->effect_changed);

  // After a frame the |subtree_property_changed| value should be reset.
  Compositor().BeginFrame();
  EXPECT_FALSE(outer_element_layer->subtree_property_changed());
  EXPECT_FALSE(GetEffectNode(outer_element_layer)->effect_changed);
  EXPECT_FALSE(inner_element_layer->subtree_property_changed());
  EXPECT_FALSE(GetEffectNode(inner_element_layer)->effect_changed);
}

// This test is similar to |LayerSubtreeTransformPropertyChanged| but for
// clip property node changes.
TEST_P(CompositingSimTest, LayerSubtreeClipPropertyChanged) {
  InitializeWithHTML(R"HTML(
      <!DOCTYPE html>
      <style>
        html { overflow: hidden; }
        #outer {
          width: 100px;
          height: 100px;
          will-change: transform;
          position: absolute;
          clip: rect(10px, 80px, 70px, 40px);
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
  EXPECT_FALSE(inner_element_layer->subtree_property_changed());

  // Modifying the clip style should set |subtree_property_changed| on
  // both layers.
  outer_element->setAttribute(html_names::kStyleAttr,
                              AtomicString("clip: rect(1px, 8px, 7px, 4px);"));
  UpdateAllLifecyclePhases();
  EXPECT_TRUE(outer_element_layer->subtree_property_changed());
  EXPECT_TRUE(inner_element_layer->subtree_property_changed());

  // After a frame the |subtree_property_changed| value should be reset.
  Compositor().BeginFrame();
  EXPECT_FALSE(outer_element_layer->subtree_property_changed());
  EXPECT_FALSE(inner_element_layer->subtree_property_changed());
}

TEST_P(CompositingSimTest, LayerSubtreeOverflowClipPropertyChanged) {
  InitializeWithHTML(R"HTML(
      <!DOCTYPE html>
      <style>
        html { overflow: hidden; }
        #outer {
          width: 100px;
          height: 100px;
          will-change: transform;
          position: absolute;
          overflow: hidden;
        }
        #inner {
          width: 200px;
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
  EXPECT_FALSE(inner_element_layer->subtree_property_changed());

  // Modifying the clip width should set |subtree_property_changed| on
  // both layers.
  outer_element->setAttribute(html_names::kStyleAttr,
                              AtomicString("width: 200px;"));
  UpdateAllLifecyclePhases();
  // The overflow clip does not affect |outer_element_layer|, so
  // subtree_property_changed should be false for it. It does affect
  // |inner_element_layer| though.
  EXPECT_FALSE(outer_element_layer->subtree_property_changed());
  EXPECT_TRUE(inner_element_layer->subtree_property_changed());

  // After a frame the |subtree_property_changed| value should be reset.
  Compositor().BeginFrame();
  EXPECT_FALSE(outer_element_layer->subtree_property_changed());
  EXPECT_FALSE(inner_element_layer->subtree_property_changed());
}

// This test is similar to |LayerSubtreeClipPropertyChanged| but for cases when
// the clip node itself does not change but the clip node associated with a
// layer changes.
TEST_P(CompositingSimTest, LayerClipPropertyChanged) {
  InitializeWithHTML(R"HTML(
      <!DOCTYPE html>
      <style>
        #outer {
          width: 100px;
          height: 100px;
        }
        #inner {
          width: 50px;
          height: 200px;
          backface-visibility: hidden;
          background: lightblue;
        }
      </style>
      <div id='outer' style='overflow: hidden;'>
        <div id='inner'></div>
      </div>
  )HTML");

  Compositor().BeginFrame();

  auto* inner_element_layer = CcLayerByDOMElementId("inner");
  EXPECT_TRUE(inner_element_layer->should_check_backface_visibility());

  // Initially, no layer should have |subtree_property_changed| set.
  EXPECT_FALSE(inner_element_layer->subtree_property_changed());

  // Removing overflow: hidden on the outer div should set
  // |subtree_property_changed| on the inner div's cc::Layer.
  auto* outer_element = GetElementById("outer");
  outer_element->setAttribute(html_names::kStyleAttr, g_empty_atom);
  UpdateAllLifecyclePhases();

  inner_element_layer = CcLayerByDOMElementId("inner");
  EXPECT_TRUE(inner_element_layer->should_check_backface_visibility());
  EXPECT_TRUE(inner_element_layer->subtree_property_changed());

  // After a frame the |subtree_property_changed| value should be reset.
  Compositor().BeginFrame();
  EXPECT_FALSE(inner_element_layer->subtree_property_changed());
}

TEST_P(CompositingSimTest, SafeOpaqueBackgroundColor) {
  InitializeWithHTML(R"HTML(
    <!DOCTYPE html>
    <style>
      body { background: yellow; }
      div {
        position: absolute;
        z-index: 1;
        width: 20px;
        height: 20px;
        will-change: transform; /* Composited */
      }
      #opaque-color {
        background: blue;
      }
      #opaque-image, #opaque-image-translucent-color {
        background: linear-gradient(blue, green);
      }
      #partly-opaque div {
        width: 15px;
        height: 15px;
        background: blue;
        will-change: initial;
      }
      #translucent, #opaque-image-translucent-color div {
        background: rgba(0, 255, 255, 0.5);
        will-change: initial;
      }
    </style>
    <div id="opaque-color"></div>
    <div id="opaque-image"></div>
    <div id="opaque-image-translucent-color">
      <div></div>
    </div>
    <div id="partly-opaque">
      <div></div>
    </div>
    <div id="translucent"></div>
  )HTML");

  Compositor().BeginFrame();

  auto* opaque_color = CcLayerByDOMElementId("opaque-color");
  EXPECT_TRUE(opaque_color->contents_opaque());
  EXPECT_EQ(opaque_color->background_color(), SkColors::kBlue);
  EXPECT_EQ(opaque_color->SafeOpaqueBackgroundColor(), SkColors::kBlue);

  auto* opaque_image = CcLayerByDOMElementId("opaque-image");
  EXPECT_FALSE(opaque_image->contents_opaque());
  EXPECT_EQ(opaque_image->background_color(), SkColors::kTransparent);
  EXPECT_EQ(opaque_image->SafeOpaqueBackgroundColor(), SkColors::kTransparent);

  // TODO(crbug.com/1399566): Alpha here should be 0.5.
  const SkColor4f kTranslucentCyan{0.0f, 1.0f, 1.0f, 128.0f / 255.0f};
  auto* opaque_image_translucent_color =
      CcLayerByDOMElementId("opaque-image-translucent-color");
  EXPECT_TRUE(opaque_image_translucent_color->contents_opaque());
  EXPECT_EQ(opaque_image_translucent_color->background_color(),
            kTranslucentCyan);
  // Use background_color() with the alpha channel forced to be opaque.
  EXPECT_EQ(opaque_image_translucent_color->SafeOpaqueBackgroundColor(),
            SkColors::kCyan);

  auto* partly_opaque = CcLayerByDOMElementId("partly-opaque");
  EXPECT_FALSE(partly_opaque->contents_opaque());
  EXPECT_EQ(partly_opaque->background_color(), SkColors::kBlue);
  // SafeOpaqueBackgroundColor() returns SK_ColorTRANSPARENT when
  // background_color() is opaque and contents_opaque() is false.
  EXPECT_EQ(partly_opaque->SafeOpaqueBackgroundColor(), SkColors::kTransparent);

  auto* translucent = CcLayerByDOMElementId("translucent");
  EXPECT_FALSE(translucent->contents_opaque());
  EXPECT_EQ(translucent->background_color(), kTranslucentCyan);
  // SafeOpaqueBackgroundColor() returns background_color() if it's not opaque
  // and contents_opaque() is false.
  EXPECT_EQ(translucent->SafeOpaqueBackgroundColor(), kTranslucentCyan);
}

TEST_P(CompositingSimTest, SquashingLayerSafeOpaqueBackgroundColor) {
  InitializeWithHTML(R"HTML(
    <!DOCTYPE html>
    <style>
      div {
        position: absolute;
        z-index: 1;
        width: 20px;
        height: 20px;
      }
      #behind {
        top: 12px;
        left: 12px;
        background: blue;
        will-change: transform; /* Composited */
      }
      #topleft {
        top: 0px;
        left: 0px;
        background: lime;
      }
      #bottomright {
        top: 24px;
        left: 24px;
        width: 100px;
        height: 100px;
        background: cyan;
      }
    </style>
    <div id="behind"></div>
    <div id="topleft"></div>
    <div id="bottomright"></div>
  )HTML");

  Compositor().BeginFrame();

  auto* squashing_layer = CcLayerByDOMElementId("topleft");
  ASSERT_TRUE(squashing_layer);
  EXPECT_EQ(gfx::Size(124, 124), squashing_layer->bounds());

  // Top left and bottom right are squashed.
  // This squashed layer should not be opaque, as it is squashing two squares
  // with some gaps between them.
  EXPECT_FALSE(squashing_layer->contents_opaque());
  // The background color of #bottomright is used as the background color
  // because it covers the most significant area of the squashing layer.
  EXPECT_EQ(squashing_layer->background_color(), SkColors::kCyan);
  // SafeOpaqueBackgroundColor() returns SK_ColorTRANSPARENT when
  // background_color() is opaque and contents_opaque() is false.
  EXPECT_EQ(squashing_layer->SafeOpaqueBackgroundColor(),
            SkColors::kTransparent);
}

// Test that a pleasant checkerboard color is used in the presence of blending.
TEST_P(CompositingSimTest, RootScrollingContentsSafeOpaqueBackgroundColor) {
  InitializeWithHTML(R"HTML(
      <!DOCTYPE html>
      <div style="mix-blend-mode: multiply;"></div>
      <div id="forcescroll" style="height: 10000px;"></div>
  )HTML");
  Compositor().BeginFrame();

  auto* scrolling_contents = ScrollingContentsCcLayerByScrollElementId(
      RootCcLayer(),
      MainFrame().GetFrameView()->LayoutViewport()->GetScrollElementId());
  EXPECT_EQ(scrolling_contents->background_color(), SkColors::kWhite);
  EXPECT_EQ(scrolling_contents->SafeOpaqueBackgroundColor(), SkColors::kWhite);
}

TEST_P(CompositingSimTest, NonDrawableLayersIgnoredForRenderSurfaces) {
  InitializeWithHTML(R"HTML(
      <!DOCTYPE html>
      <style>
        #outer {
          width: 100px;
          height: 100px;
          opacity: 0.5;
          background: blue;
        }
        #inner {
          width: 10px;
          height: 10px;
          will-change: transform;
        }
      </style>
      <div id='outer'>
        <div id='inner'></div>
      </div>
  )HTML");

  Compositor().BeginFrame();

  auto* inner_element_layer = CcLayerByDOMElementId("inner");
  EXPECT_FALSE(inner_element_layer->draws_content());
  auto* outer_element_layer = CcLayerByDOMElementId("outer");
  EXPECT_TRUE(outer_element_layer->draws_content());

  // The inner element layer is only needed for hit testing and does not draw
  // content, so it should not cause a render surface.
  auto effect_tree_index = outer_element_layer->effect_tree_index();
  const auto* effect_node =
      GetPropertyTrees()->effect_tree().Node(effect_tree_index);
  EXPECT_EQ(effect_node->opacity, 0.5f);
  EXPECT_FALSE(effect_node->HasRenderSurface());
}

TEST_P(CompositingSimTest, NoRenderSurfaceWithAxisAlignedTransformAnimation) {
  InitializeWithHTML(R"HTML(
      <!DOCTYPE html>
      <style>
        @keyframes translation {
          0% { transform: translate(10px, 11px); }
          100% { transform: translate(20px, 21px); }
        }
        .animate {
          animation-name: translation;
          animation-duration: 1s;
          width: 100px;
          height: 100px;
          overflow: hidden;
        }
        .compchild {
          height: 200px;
          width: 10px;
          background: lightblue;
          will-change: transform;
        }
      </style>
      <div class="animate"><div class="compchild"></div></div>
  )HTML");
  Compositor().BeginFrame();
  // No effect node with kClipAxisAlignment should be created because the
  // animation is axis-aligned.
  for (const auto& effect_node : GetPropertyTrees()->effect_tree().nodes()) {
    EXPECT_NE(cc::RenderSurfaceReason::kClipAxisAlignment,
              effect_node.render_surface_reason);
  }
}

TEST_P(CompositingSimTest, PromoteCrossOriginIframe) {
  InitializeWithHTML("<!DOCTYPE html><iframe id=iframe sandbox></iframe>");
  Compositor().BeginFrame();
  Document* iframe_doc =
      To<HTMLFrameOwnerElement>(GetElementById("iframe"))->contentDocument();
  auto* layer = CcLayerForIFrameContent(iframe_doc);
  EXPECT_TRUE(layer);
  EXPECT_EQ(layer->bounds(), gfx::Size(300, 150));
}

// On initial layout, the iframe is not yet loaded and is not considered
// cross origin. This test ensures the iframe is promoted due to being cross
// origin after the iframe loads.
TEST_P(CompositingSimTest, PromoteCrossOriginIframeAfterLoading) {
  SimRequest main_resource("https://origin-a.com/a.html", "text/html");
  SimRequest frame_resource("https://origin-b.com/b.html", "text/html");

  LoadURL("https://origin-a.com/a.html");
  main_resource.Complete(R"HTML(
      <!DOCTYPE html>
      <iframe id="iframe" src="https://origin-b.com/b.html"></iframe>
  )HTML");
  frame_resource.Complete("<!DOCTYPE html>");
  Compositor().BeginFrame();

  Document* iframe_doc =
      To<HTMLFrameOwnerElement>(GetElementById("iframe"))->contentDocument();
  EXPECT_TRUE(CcLayerForIFrameContent(iframe_doc));
}

// An iframe that is cross-origin to the parent should be composited. This test
// sets up nested frames with domains A -> B -> A. Both the child and grandchild
// frames should be composited because they are cross-origin to their parent.
TEST_P(CompositingSimTest, PromoteCrossOriginToParent) {
  SimRequest main_resource("https://origin-a.com/a.html", "text/html");
  SimRequest child_resource("https://origin-b.com/b.html", "text/html");
  SimRequest grandchild_resource("https://origin-a.com/c.html", "text/html");

  LoadURL("https://origin-a.com/a.html");
  main_resource.Complete(R"HTML(
      <!DOCTYPE html>
      <iframe id="main_iframe" src="https://origin-b.com/b.html"></iframe>
  )HTML");
  child_resource.Complete(R"HTML(
      <!DOCTYPE html>
      <iframe id="child_iframe" src="https://origin-a.com/c.html"></iframe>
  )HTML");
  grandchild_resource.Complete("<!DOCTYPE html>");
  Compositor().BeginFrame();

  Document* iframe_doc =
      To<HTMLFrameOwnerElement>(GetElementById("main_iframe"))
          ->contentDocument();
  EXPECT_TRUE(CcLayerByOwnerNode(iframe_doc));

  iframe_doc = To<HTMLFrameOwnerElement>(
                   iframe_doc->getElementById(AtomicString("child_iframe")))
                   ->contentDocument();
  EXPECT_TRUE(CcLayerForIFrameContent(iframe_doc));
}

// Initially the iframe is cross-origin and should be composited. After changing
// to same-origin, the frame should no longer be composited.
TEST_P(CompositingSimTest, PromoteCrossOriginIframeAfterDomainChange) {
  SimRequest main_resource("https://origin-a.com/a.html", "text/html");
  SimRequest frame_resource("https://sub.origin-a.com/b.html", "text/html");

  LoadURL("https://origin-a.com/a.html");
  main_resource.Complete(R"HTML(
      <!DOCTYPE html>
      <iframe id="iframe" src="https://sub.origin-a.com/b.html"></iframe>
  )HTML");
  frame_resource.Complete("<!DOCTYPE html>");
  Compositor().BeginFrame();

  auto* iframe_element = To<HTMLIFrameElement>(
      GetDocument().getElementById(AtomicString("iframe")));

  Document* iframe_doc =
      To<HTMLFrameOwnerElement>(GetElementById("iframe"))->contentDocument();
  EXPECT_TRUE(CcLayerForIFrameContent(iframe_doc));

  NonThrowableExceptionState exception_state;
  GetDocument().setDomain(String("origin-a.com"), exception_state);
  iframe_element->contentDocument()->setDomain(String("origin-a.com"),
                                               exception_state);
  // We may not have scheduled a visual update so force an update instead of
  // using BeginFrame.
  UpdateAllLifecyclePhases();

  iframe_doc =
      To<HTMLFrameOwnerElement>(GetElementById("iframe"))->contentDocument();
  EXPECT_FALSE(CcLayerForIFrameContent(iframe_doc));
}

// This test sets up nested frames with domains A -> B -> A. Initially, the
// child frame and grandchild frame should be composited. After changing the
// child frame to A (same-origin), both child and grandchild frames should no
// longer be composited.
TEST_P(CompositingSimTest, PromoteCrossOriginToParentIframeAfterDomainChange) {
  SimRequest main_resource("https://origin-a.com/a.html", "text/html");
  SimRequest child_resource("https://sub.origin-a.com/b.html", "text/html");
  SimRequest grandchild_resource("https://origin-a.com/c.html", "text/html");

  LoadURL("https://origin-a.com/a.html");
  main_resource.Complete(R"HTML(
      <!DOCTYPE html>
      <iframe id="main_iframe" src="https://sub.origin-a.com/b.html"></iframe>
  )HTML");
  child_resource.Complete(R"HTML(
      <!DOCTYPE html>
      <iframe id="child_iframe" src="https://origin-a.com/c.html"></iframe>
  )HTML");
  grandchild_resource.Complete("<!DOCTYPE html>");
  Compositor().BeginFrame();

  Document* iframe_doc =
      To<HTMLFrameOwnerElement>(GetElementById("main_iframe"))
          ->contentDocument();
  EXPECT_TRUE(CcLayerByOwnerNode(iframe_doc));

  iframe_doc = To<HTMLFrameOwnerElement>(
                   iframe_doc->getElementById(AtomicString("child_iframe")))
                   ->contentDocument();
  EXPECT_TRUE(CcLayerForIFrameContent(iframe_doc));

  auto* main_iframe_element = To<HTMLIFrameElement>(
      GetDocument().getElementById(AtomicString("main_iframe")));
  NonThrowableExceptionState exception_state;

  GetDocument().setDomain(String("origin-a.com"), exception_state);
  auto* child_iframe_element = To<HTMLIFrameElement>(
      main_iframe_element->contentDocument()->getElementById(
          AtomicString("child_iframe")));
  child_iframe_element->contentDocument()->setDomain(String("origin-a.com"),
                                                     exception_state);
  main_iframe_element->contentDocument()->setDomain(String("origin-a.com"),
                                                    exception_state);

  // We may not have scheduled a visual update so force an update instead of
  // using BeginFrame.
  UpdateAllLifecyclePhases();
  iframe_doc = To<HTMLFrameOwnerElement>(GetElementById("main_iframe"))
                   ->contentDocument();
  EXPECT_FALSE(CcLayerByOwnerNode(iframe_doc));

  iframe_doc = To<HTMLFrameOwnerElement>(
                   iframe_doc->getElementById(AtomicString("child_iframe")))
                   ->contentDocument();
  EXPECT_FALSE(CcLayerForIFrameContent(iframe_doc));
}

// Regression test for https://crbug.com/1095167. Render surfaces require that
// EffectNode::stable_id is set.
TEST_P(CompositingTest, EffectNodesShouldHaveElementIds) {
  InitializeWithHTML(*WebView()->MainFrameImpl()->GetFrame(), R"HTML(
    <div style="overflow: hidden; border-radius: 2px; height: 10px;">
      <div style="backdrop-filter: grayscale(3%);">
        a
        <span style="backdrop-filter: grayscale(3%);">b</span>
      </div>
    </div>
  )HTML");
  auto* property_trees = RootCcLayer()->layer_tree_host()->property_trees();
  for (const auto& effect_node : property_trees->effect_tree().nodes()) {
    if (effect_node.parent_id != cc::kInvalidPropertyNodeId) {
      EXPECT_TRUE(!!effect_node.element_id);
    }
  }
}

TEST_P(CompositingSimTest, ImplSideScrollSkipsCommit) {
  InitializeWithHTML(R"HTML(
    <div id='scroller' style='will-change: transform; overflow: scroll;
        width: 100px; height: 100px'>
      <div style='height: 1000px'></div>
    </div>
  )HTML");
  Compositor().BeginFrame();

  auto* scroller = GetDocument().getElementById(AtomicString("scroller"));
  auto* scrollable_area = scroller->GetLayoutBox()->GetScrollableArea();
  auto element_id = scrollable_area->GetScrollElementId();

  EXPECT_FALSE(Compositor().LayerTreeHost()->CommitRequested());

  // Simulate the scroll update with scroll delta from impl-side.
  cc::CompositorCommitData commit_data;
  commit_data.scrolls.emplace_back(element_id, gfx::Vector2dF(0, 10),
                                   std::nullopt);
  Compositor().LayerTreeHost()->ApplyCompositorChanges(&commit_data);
  EXPECT_EQ(gfx::PointF(0, 10), scrollable_area->ScrollPosition());
  EXPECT_EQ(
      gfx::PointF(0, 10),
      GetPropertyTrees()->scroll_tree().current_scroll_offset(element_id));

  UpdateAllLifecyclePhasesExceptPaint();
  // The scroll offset change should be directly updated, and the direct update
  // should not schedule commit because the scroll offset is the same as the
  // current cc scroll offset.
  EXPECT_FALSE(paint_artifact_compositor()->NeedsUpdate());
  EXPECT_FALSE(Compositor().LayerTreeHost()->CommitRequested());

  // Update just the blink lifecycle because a full frame would clear the bit
  // for whether a commit was requested.
  UpdateAllLifecyclePhases();

  // A main frame is needed to call UpdateLayers which updates property trees,
  // re-calculating cached to/from-screen transforms.
  EXPECT_TRUE(Compositor().LayerTreeHost()->RequestedMainFramePending());

  // A full commit is not needed.
  EXPECT_FALSE(Compositor().LayerTreeHost()->CommitRequested());
}

TEST_P(CompositingSimTest, RasterInducingScrollSkipsCommit) {
  InitializeWithHTML(R"HTML(
    <div id='scroller' style='overflow: scroll; width: 100px; height: 100px'>
      <div style='height: 1000px'></div>
    </div>
  )HTML");
  Compositor().BeginFrame();

  auto* scroller = GetDocument().getElementById(AtomicString("scroller"));
  auto* scrollable_area = scroller->GetLayoutBox()->GetScrollableArea();
  auto element_id = scrollable_area->GetScrollElementId();

  EXPECT_FALSE(Compositor().LayerTreeHost()->CommitRequested());

  // Simulate the scroll update with scroll delta from impl-side.
  cc::CompositorCommitData commit_data;
  commit_data.scrolls.emplace_back(element_id, gfx::Vector2dF(0, 10),
                                   std::nullopt);
  Compositor().LayerTreeHost()->ApplyCompositorChanges(&commit_data);
  EXPECT_EQ(gfx::PointF(0, 10), scrollable_area->ScrollPosition());
  EXPECT_EQ(
      gfx::PointF(0, 10),
      GetPropertyTrees()->scroll_tree().current_scroll_offset(element_id));

  UpdateAllLifecyclePhasesExceptPaint();
  if (RuntimeEnabledFeatures::RasterInducingScrollEnabled()) {
    // The scroll offset change should be directly updated, and the direct
    // update should not schedule commit because the scroll offset is the same
    // as the current cc scroll offset.
    EXPECT_FALSE(paint_artifact_compositor()->NeedsUpdate());
    EXPECT_FALSE(Compositor().LayerTreeHost()->CommitRequested());
  } else {
    EXPECT_TRUE(paint_artifact_compositor()->NeedsUpdate());
    EXPECT_TRUE(Compositor().LayerTreeHost()->CommitRequested());
  }

  // Update just the blink lifecycle because a full frame would clear the bit
  // for whether a commit was requested.
  UpdateAllLifecyclePhases();

  // A main frame is needed to call UpdateLayers which updates property trees,
  // re-calculating cached to/from-screen transforms.
  EXPECT_TRUE(Compositor().LayerTreeHost()->RequestedMainFramePending());

  if (RuntimeEnabledFeatures::RasterInducingScrollEnabled()) {
    // A full commit is not needed.
    EXPECT_FALSE(Compositor().LayerTreeHost()->CommitRequested());
  } else {
    EXPECT_TRUE(Compositor().LayerTreeHost()->CommitRequested());
  }
}

TEST_P(CompositingSimTest, ImplSideScrollUnpaintedSkipsCommit) {
  InitializeWithHTML(R"HTML(
    <div style='height: 10000px'></div>
    <div id='scroller' style='overflow: scroll; width: 100px; height: 100px'>
      <div style='height: 1000px'></div>
    </div>
  )HTML");
  Compositor().BeginFrame();

  auto* scroller = GetDocument().getElementById(AtomicString("scroller"));
  auto* scrollable_area = scroller->GetLayoutBox()->GetScrollableArea();
  auto element_id = scrollable_area->GetScrollElementId();

  // The scroller is far away from the viewport so is not painted.
  // The scroll node always exists.
  auto* scroll_node =
      GetPropertyTrees()->scroll_tree().FindNodeFromElementId(element_id);
  ASSERT_TRUE(scroll_node);
  EXPECT_EQ(cc::kInvalidPropertyNodeId, scroll_node->transform_id);

  EXPECT_FALSE(Compositor().LayerTreeHost()->CommitRequested());

  // Simulate the scroll update with scroll delta from impl-side.
  cc::CompositorCommitData commit_data;
  commit_data.scrolls.emplace_back(element_id, gfx::Vector2dF(0, 10),
                                   std::nullopt);
  Compositor().LayerTreeHost()->ApplyCompositorChanges(&commit_data);
  EXPECT_EQ(gfx::PointF(0, 10), scrollable_area->ScrollPosition());
  EXPECT_EQ(
      gfx::PointF(0, 10),
      GetPropertyTrees()->scroll_tree().current_scroll_offset(element_id));

  // Update just the blink lifecycle because a full frame would clear the bit
  // for whether a commit was requested.
  UpdateAllLifecyclePhases();

  // A main frame is needed to call UpdateLayers which updates property trees,
  // re-calculating cached to/from-screen transforms.
  EXPECT_TRUE(Compositor().LayerTreeHost()->RequestedMainFramePending());

  // A full commit is not needed.
  EXPECT_FALSE(Compositor().LayerTreeHost()->CommitRequested());
}

TEST_P(CompositingSimTest, ImplSideScaleSkipsCommit) {
  InitializeWithHTML(R"HTML(
    <div>Empty Page</div>
  )HTML");
  Compositor().BeginFrame();

  ASSERT_FALSE(Compositor().LayerTreeHost()->CommitRequested());
  ASSERT_EQ(1.f, GetPropertyTrees()->transform_tree().page_scale_factor());

  // Simulate a page scale delta (i.e. user pinch-zoomed) on the compositor.
  cc::CompositorCommitData commit_data;
  commit_data.page_scale_delta = 2.f;

  {
    auto sync = Compositor().LayerTreeHost()->SimulateSyncingDeltasForTesting();
    Compositor().LayerTreeHost()->ApplyCompositorChanges(&commit_data);
  }

  // The tran
"""


```