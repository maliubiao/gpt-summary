Response:
Let's break down the thought process for analyzing the provided C++ test file.

1. **Identify the Core Purpose:** The file name `compositing_reason_finder_test.cc` immediately suggests its primary function: testing the `CompositingReasonFinder` class. This class likely determines *why* an element in the rendering engine needs to be composited onto its own layer.

2. **Examine Includes:** The included headers provide vital clues:
    * `compositing_reason_finder.h`:  Confirms the target of the tests.
    * `base/test/scoped_feature_list.h`: Indicates feature flag testing.
    * `third_party/blink/public/common/features.h`:  More feature flag related stuff.
    *  Headers related to core Blink concepts: `animation`, `css`, `frame`, `html`, `layout`, `page`, `paint`, `scroll`. This strongly suggests the tests cover how different aspects of web content trigger compositing.
    *  Testing utilities: `core_unit_test_helper.h`, `paint_test_configurations.h`, `runtime_enabled_features_test_helpers.h`.

3. **Understand the Test Structure:**
    * `CompositingReasonFinderTest` inherits from `RenderingTest` and `PaintTestConfigurations`. This establishes it as a rendering-focused unit test.
    * `SetUp()` enables compositing. This is crucial as the tests are about *why* compositing occurs.
    * `SimulateFrame()` hints at testing scenarios involving animation or updates.
    * `CheckCompositingReasonsForAnimation()` is a dedicated helper function for animation-related compositing tests.
    * The use of `TEST_P` and `INSTANTIATE_PAINT_TEST_SUITE_P` indicates parameterized tests, allowing the same test logic to run with different configurations.

4. **Analyze Individual Tests (Iterative Process):** Go through each `TEST_P` function and identify:
    * **Setup (`SetBodyInnerHTML`):** What HTML and CSS are being used to create the test scenario?  Look for specific properties and values that are likely to trigger compositing (e.g., `transform`, `position: fixed`, `will-change`, `opacity`, `filter`).
    * **Assertion (`EXPECT_REASONS`):** What compositing reasons are expected for the targeted element(s)?  The `CompositingReason::ToString` part is helpful for understanding the expected values.
    * **Underlying Logic:**  Try to connect the HTML/CSS with the expected compositing reason. For example, `transform: translateZ(0)` is explicitly tested for `kTrivial3DTransform`. `position: fixed` is tested for `kFixedPosition`.

5. **Identify Relationships to Web Technologies:** As you analyze the tests, connect the tested CSS properties and HTML elements to their corresponding functionalities:
    * **CSS:** `transform`, `position`, `opacity`, `filter`, `will-change`, `backface-visibility`, `transform-style`, `anchor-name`, `position-anchor`, `top: anchor()`, `position: sticky`, `overflow`.
    * **HTML:** `<div>`, `<span>`, `<iframe>`, `<svg>`, `<text>`, `<tspan>`, `<filter>`, `<feBlend>`.
    * **JavaScript (Indirect):**  The tests involving animations (using `SimulateFrame` and the `CheckCompositingReasonsForAnimation` function) indirectly relate to JavaScript because animations are often driven by script. The `will-change` property also hints at potential JavaScript interactions where developers might dynamically change styles.

6. **Infer Logical Reasoning and Assumptions:**  Consider the *why* behind the tests:
    * **Assumption:** The `CompositingReasonFinder` correctly identifies the reasons for compositing based on CSS properties, element types, and browser features.
    * **Logic:** If a specific CSS property is set, a certain compositing reason should be triggered. The tests verify this logic. For example, if `transform: translateZ(0)` is applied, the expectation is `kTrivial3DTransform`.

7. **Consider User/Developer Errors:** Think about how a web developer might unintentionally trigger or fail to trigger compositing:
    * **Incorrect `will-change` usage:**  Using `will-change` for too many properties or properties that don't benefit from compositing can waste resources. The test with `will-change: scroll-position` demonstrates a specific case.
    * **Misunderstanding compositing triggers:**  Developers might not realize that certain seemingly innocuous CSS properties can lead to compositing.
    * **Forgetting necessary properties:**  For example, expecting an element with a transform animation to be composited on older browsers might fail if hardware acceleration isn't enabled or the browser doesn't promote inline elements.

8. **Trace User Actions (Debugging Clues):**  Imagine a user navigating a webpage and how their actions might lead to the code being tested:
    * **Scrolling:** Fixed position elements and sticky elements are directly affected by scrolling. Overscroll behavior is also tested.
    * **Animations/Transitions:**  Any animation or CSS transition involving compositable properties will engage this code.
    * **Page Load:** The initial rendering of elements with compositing-triggering properties will involve this code.
    * **Dynamic Content Changes:** JavaScript manipulating styles or adding/removing elements can cause compositing reasons to be re-evaluated.
    * **Iframe Interactions:** Loading or interacting with iframes, especially cross-origin iframes, involves compositing decisions.

9. **Structure the Answer:**  Organize the findings logically:
    * Start with a high-level summary of the file's purpose.
    * Detail the functionalities it tests, grouping related tests together.
    * Explain the relationships to web technologies with concrete examples.
    * Describe the logical reasoning and assumptions.
    * Provide examples of user/developer errors.
    * Outline how user actions can lead to this code being executed.

10. **Refine and Elaborate:** Review the generated answer for clarity, accuracy, and completeness. Add more detail or context where needed. For instance, explicitly mentioning that compositing happens on the GPU can add valuable context.

By following these steps, we can systematically analyze the C++ test file and provide a comprehensive and insightful explanation of its purpose and implications. The key is to understand the domain (browser rendering), interpret the code (especially the test setup and assertions), and connect it back to the user-facing web experience.
这个文件 `compositing_reason_finder_test.cc` 是 Chromium Blink 引擎中用于测试 `CompositingReasonFinder` 类的单元测试。`CompositingReasonFinder` 的主要功能是 **确定一个渲染对象（LayoutObject）为什么需要被提升到自己的合成层（Composited Layer）进行绘制**。

换句话说，这个测试文件验证了 Blink 引擎判断一个元素是否需要进行硬件加速合成的逻辑是否正确。

**功能列表:**

1. **测试各种 CSS 属性触发合成的情况:** 验证不同的 CSS 属性（例如 `transform`, `opacity`, `filter`, `position: fixed`, `position: sticky`, `will-change` 等）是否能正确地被 `CompositingReasonFinder` 识别为需要合成的原因。
2. **测试动画触发合成的情况:** 验证当元素应用了动画（例如 `transform`, `opacity`, `filter` 等动画）时，`CompositingReasonFinder` 是否能正确识别。
3. **测试特定 HTML 元素触发合成的情况:**  验证某些特定的 HTML 元素（例如 `<iframe>`）是否会被识别为需要合成。
4. **测试继承的合成原因:** 验证某些合成原因是否会从父元素传递到子元素，例如 `backface-visibility: hidden` 和 `transform-style: preserve-3d` 的组合。
5. **测试 Overscroll 行为对合成的影响:** 验证浏览器的 Overscroll 设置是否会影响固定定位元素的合成。
6. **测试 Anchor Positioning 对合成的影响:** 验证使用 CSS Anchor Positioning 的固定定位元素是否会被正确合成。
7. **测试 `will-change` 属性的效果:** 验证 `will-change` 属性是否能正确触发合成。
8. **测试 SVG 元素相关的合成:** 验证 SVG 元素及其子元素的合成行为。
9. **测试跨域 iframe 的合成:** 验证跨域 iframe 是否会被提升到自己的合成层。
10. **测试性能优化相关的合成策略:** 例如，对于空的 iframe 是否进行合成。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个测试文件直接关联到 HTML 和 CSS，并且间接地关联到 JavaScript，因为 JavaScript 经常用于动态修改 HTML 和 CSS，从而影响元素的合成行为。

* **HTML:**
    * **`<div>`, `<span>`:**  基础的 HTML 元素，用于测试各种 CSS 属性触发合成的情况。 例如，测试 `transform` 属性：
      ```html
      <div id='target' style='width: 100px; height: 100px; transform: translateZ(0)'></div>
      ```
      测试验证了 `CompositingReasonFinder` 能否正确识别出 `transform: translateZ(0)` 应该触发 `CompositingReason::kTrivial3DTransform`。
    * **`<iframe>`:** 用于测试跨域 iframe 的合成。当 iframe 是跨域时，它会被提升到自己的合成层。
      ```html
      <iframe id=iframe sandbox></iframe>
      ```
      测试验证了 `CompositingReasonFinder` 能否正确识别出跨域 iframe 需要合成，并给出 `CompositingReason::kIFrame` 的原因。
    * **`<svg>`, `<text>`, `<tspan>`:** 用于测试 SVG 元素的合成。
      ```html
      <svg>
        <text id="text" style="will-change: opacity">Text</text>
      </svg>
      ```
      测试验证了对于设置了 `will-change: opacity` 的 SVG 文本元素，`CompositingReasonFinder` 能否给出 `CompositingReason::kWillChangeOpacity` 的原因。

* **CSS:**
    * **`transform`:** 用于测试 2D 和 3D 变换是否触发合成。
    * **`opacity`:** 用于测试透明度是否触发合成。
    * **`filter`:** 用于测试滤镜效果是否触发合成。
    * **`position: fixed`:** 用于测试固定定位元素是否触发合成。
    * **`position: sticky`:** 用于测试粘性定位元素是否触发合成。
    * **`will-change`:** 用于测试开发者明确声明元素可能发生变化的属性是否触发合成。
    * **`backface-visibility: hidden` 和 `transform-style: preserve-3d`:** 用于测试 3D 场景下的背面不可见性是否触发合成。
    * **`anchor-name`, `position-anchor`, `top: anchor()`:** 用于测试 CSS Anchor Positioning 是否影响合成。
    * **`overflow: scroll`, `overflow: auto`, `overflow: hidden`:**  用于测试滚动容器对子元素 sticky 定位的影响。
    * **`animation` 和 `@keyframes`:** 用于测试 CSS 动画是否触发合成。

* **JavaScript:**
    * 虽然这个测试文件本身是 C++ 代码，不包含 JavaScript，但它测试的合成逻辑是前端开发者在使用 JavaScript 操作 DOM 和 CSS 时会遇到的。例如，当 JavaScript 动态地为一个元素添加 `transform` 属性时，Blink 引擎会运行类似的 `CompositingReasonFinder` 逻辑来判断是否需要将该元素提升到合成层。
    * 测试中使用了 `SimulateFrame()` 函数来模拟动画的进行，这与 JavaScript 通过 `requestAnimationFrame` 或 CSS 动画/过渡驱动的动画效果相关。

**逻辑推理、假设输入与输出:**

很多测试都基于这样的逻辑推理：如果一个元素应用了某个特定的 CSS 属性或满足某个条件，那么 `CompositingReasonFinder` 应该给出特定的合成原因。

**假设输入与输出示例:**

1. **假设输入 (HTML/CSS):**
   ```html
   <div id='target' style='width: 100px; height: 100px; transform: translateZ(0)'></div>
   ```
   **预期输出 (CompositingReason):** `CompositingReason::kTrivial3DTransform`

2. **假设输入 (HTML/CSS):**
   ```html
   <div id='fixedDiv' style='position: fixed; width: 100px; height: 100px;'></div>
   ```
   **预期输出 (CompositingReason，取决于浏览器 Overscroll 设置):**
     * 如果 OverscrollType 是 `kTransform`: `CompositingReason::kFixedPosition | CompositingReason::kUndoOverscroll`
     * 如果 OverscrollType 是 `kNone`: `CompositingReason::kFixedPosition` (某些情况下可能会有其他原因)

3. **假设输入 (HTML/CSS):**
   ```html
   <div id='target' style='will-change: opacity;'></div>
   ```
   **预期输出 (CompositingReason):** `CompositingReason::kWillChangeOpacity`

**用户或编程常见的使用错误及举例说明:**

1. **过度使用 `will-change`:**  开发者可能会为了“优化性能”而对很多元素应用 `will-change`，即使这些元素实际上并不需要合成。这会导致不必要的内存消耗和 GPU 负载。测试中虽然没有直接模拟这种错误，但验证了 `will-change` 的基本功能，开发者可以通过阅读这些测试来理解 `will-change` 的触发条件。

2. **不理解合成的触发条件:** 开发者可能不清楚哪些 CSS 属性或 HTML 结构会导致元素被提升到合成层。例如，他们可能意外地使用了某些 CSS 属性，导致了不必要的合成，从而影响性能。这个测试文件可以帮助开发者理解这些触发条件。

3. **在 SVG 元素上使用不支持的 transform 动画:**  开发者可能会尝试在 SVG 元素上使用 CSS transform 动画，但某些情况下浏览器可能不会为其创建合成层进行硬件加速。测试 `NotSupportedTransformAnimationsOnSVG` 验证了这一点。

**用户操作是如何一步步的到达这里，作为调试线索:**

作为一名 Web 开发者，当你遇到页面性能问题，怀疑是过度合成导致时，你可能会需要了解哪些元素被提升到了合成层以及为什么。你可以使用 Chrome DevTools 的 Layers 面板来查看页面的合成层结构和合成原因。

1. **用户打开一个网页:**  浏览器开始解析 HTML、CSS 并构建渲染树。
2. **渲染引擎遍历渲染树:**  `CompositingReasonFinder` 会被调用，根据元素的样式和属性，判断该元素是否需要被提升到合成层。
3. **如果元素满足合成条件:** 例如，应用了 `transform` 属性，`CompositingReasonFinder` 会返回 `CompositingReason::k3DTransform`（或其他相关的 transform 原因）。
4. **浏览器创建合成层:**  对于需要合成的元素，浏览器会在 GPU 上创建一个独立的纹理层。
5. **用户与页面交互:**  例如滚动页面、触发动画等，如果合成正确，这些操作可以在 GPU 上高效地完成。
6. **开发者使用 Chrome DevTools:**
   * 打开 "More tools" -> "Layers"。
   * 在 Layers 面板中，可以看到页面的合成层结构。
   * 点击一个合成层，可以在 "Details" 面板中看到 "Compositing Reasons"，这里显示的原因就是由 `CompositingReasonFinder` 确定的。

因此，`compositing_reason_finder_test.cc` 中测试的逻辑，正是 Chrome DevTools 的 Layers 面板中显示的 "Compositing Reasons" 的幕后功臣。当你看到某个元素因为 "Transform" 或 "Opacity" 等原因被合成时，正是 Blink 引擎中类似于 `CompositingReasonFinder` 的代码在起作用。

这个测试文件对于理解 Blink 引擎的合成策略至关重要，它帮助开发者理解浏览器是如何优化渲染性能的，以及如何避免不必要的合成。

Prompt: 
```
这是目录为blink/renderer/core/paint/compositing/compositing_reason_finder_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/paint/compositing/compositing_reason_finder.h"

#include "base/test/scoped_feature_list.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/renderer/core/animation/animation_clock.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/html/html_frame_owner_element.h"
#include "third_party/blink/renderer/core/layout/layout_block.h"
#include "third_party/blink/renderer/core/page/page_animator.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/scroll/scroll_types.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/platform/testing/paint_test_configurations.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"

namespace blink {

class CompositingReasonFinderTest : public RenderingTest,
                                    public PaintTestConfigurations {
 public:
  CompositingReasonFinderTest()
      : RenderingTest(MakeGarbageCollected<SingleChildLocalFrameClient>()) {}

 protected:
  void SetUp() override {
    EnableCompositing();
    RenderingTest::SetUp();
  }

  void SimulateFrame() {
    // Advance time by 100 ms.
    auto new_time = GetAnimationClock().CurrentTime() + base::Milliseconds(100);
    GetPage().Animator().ServiceScriptedAnimations(new_time);
  }

  void CheckCompositingReasonsForAnimation(bool supports_transform_animation);
};

#define EXPECT_REASONS(expect, actual)                        \
  EXPECT_EQ(expect, actual)                                   \
      << " expected: " << CompositingReason::ToString(expect) \
      << " actual: " << CompositingReason::ToString(actual)

INSTANTIATE_PAINT_TEST_SUITE_P(CompositingReasonFinderTest);

TEST_P(CompositingReasonFinderTest, PromoteTrivial3D) {
  SetBodyInnerHTML(R"HTML(
    <div id='target'
      style='width: 100px; height: 100px; transform: translateZ(0)'></div>
  )HTML");

  EXPECT_REASONS(CompositingReason::kTrivial3DTransform,
                 CompositingReasonFinder::DirectReasonsForPaintProperties(
                     *GetLayoutObjectByElementId("target")));
}

TEST_P(CompositingReasonFinderTest, PromoteNonTrivial3D) {
  SetBodyInnerHTML(R"HTML(
    <div id='target'
      style='width: 100px; height: 100px; transform: translateZ(1px)'></div>
  )HTML");

  EXPECT_REASONS(CompositingReason::k3DTransform,
                 CompositingReasonFinder::DirectReasonsForPaintProperties(
                     *GetLayoutObjectByElementId("target")));
}

TEST_P(CompositingReasonFinderTest, UndoOverscroll) {
  SetBodyInnerHTML(R"HTML(
    <style>
    .fixedDivStyle {
      position: fixed;
      width: 100px;
      height: 100px;
      border: 1px solid;
    }
    </style>
    <body style="background-image: linear-gradient(grey, yellow);">
      <div id="fixedDiv" class='fixedDivStyle'></div>
    </body>
  )HTML");

  auto& visual_viewport = GetDocument().GetPage()->GetVisualViewport();
  auto default_overscroll_type = visual_viewport.GetOverscrollType();
  EXPECT_REASONS(default_overscroll_type == OverscrollType::kTransform
                     ? CompositingReason::kFixedPosition |
                           CompositingReason::kUndoOverscroll
                     : CompositingReason::kNone,
                 CompositingReasonFinder::DirectReasonsForPaintProperties(
                     *GetLayoutObjectByElementId("fixedDiv")));

  visual_viewport.SetOverscrollTypeForTesting(OverscrollType::kNone);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_REASONS(CompositingReason::kNone,
                 CompositingReasonFinder::DirectReasonsForPaintProperties(
                     *GetLayoutObjectByElementId("fixedDiv")));

  visual_viewport.SetOverscrollTypeForTesting(OverscrollType::kTransform);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_REASONS(
      CompositingReason::kFixedPosition | CompositingReason::kUndoOverscroll,
      CompositingReasonFinder::DirectReasonsForPaintProperties(
          *GetLayoutObjectByElementId("fixedDiv")));
}

// Tests that an anchored-positioned fixpos element should overscroll if the
// anchor cab be overscrolled, so that it keeps "attached" to the anchor.
TEST_P(CompositingReasonFinderTest, FixedPosAnchorPosOverscroll) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body { height: 200vh; }
      div { width: 100px; height: 100px; }
      #anchor { anchor-name: --a; position: absolute; background: orange; }
      #target { position-anchor: --a; top: anchor(top);
                position: fixed; background: lime; }
    </style>
    <div id="anchor"></div>
    <div id="target"></div>
  )HTML");

  // Need frame update to update `AnchorPositionScrollData`.
  SimulateFrame();
  UpdateAllLifecyclePhasesForTest();

  auto& visual_viewport = GetDocument().GetPage()->GetVisualViewport();
  visual_viewport.SetOverscrollTypeForTesting(OverscrollType::kNone);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_REASONS(
      CompositingReason::kFixedPosition | CompositingReason::kAnchorPosition,
      CompositingReasonFinder::DirectReasonsForPaintProperties(
          *GetLayoutObjectByElementId("target")));

  visual_viewport.SetOverscrollTypeForTesting(OverscrollType::kTransform);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_REASONS(
      CompositingReason::kFixedPosition | CompositingReason::kAnchorPosition,
      CompositingReasonFinder::DirectReasonsForPaintProperties(
          *GetLayoutObjectByElementId("target")));
}

// Tests that an anchored-positioned fixpos element should not overscroll if
// the anchor does not overscroll.
TEST_P(CompositingReasonFinderTest, FixedPosAnchorPosUndoOverscroll) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body { height: 200vh; }
      #scroller {
        position: fixed; overflow: scroll; width: 200px; height: 200px;
      }
      #anchor, #target { width: 100px; height: 100px; }
      #anchor { anchor-name: --a; position: absolute;
                top: 300px; background: orange; }
      #target { position-anchor: --a; top: anchor(top);
                position: fixed; background: lime; }
    </style>
    <div id="scroller">
      <div id="anchor"></div>
    </div>
    <div id="target"></div>
  )HTML");

  // Need frame update to update `AnchorPositionScrollData`.
  SimulateFrame();
  UpdateAllLifecyclePhasesForTest();

  auto& visual_viewport = GetDocument().GetPage()->GetVisualViewport();
  visual_viewport.SetOverscrollTypeForTesting(OverscrollType::kNone);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_REASONS(
      CompositingReason::kFixedPosition | CompositingReason::kAnchorPosition,
      CompositingReasonFinder::DirectReasonsForPaintProperties(
          *GetLayoutObjectByElementId("target")));

  visual_viewport.SetOverscrollTypeForTesting(OverscrollType::kTransform);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_REASONS(CompositingReason::kFixedPosition |
                     CompositingReason::kAnchorPosition |
                     CompositingReason::kUndoOverscroll,
                 CompositingReasonFinder::DirectReasonsForPaintProperties(
                     *GetLayoutObjectByElementId("target")));
}
TEST_P(CompositingReasonFinderTest, OnlyAnchoredStickyPositionPromoted) {
  SetBodyInnerHTML(R"HTML(
    <style>
    .scroller {contain: paint; width: 400px; height: 400px; overflow: auto;
    will-change: transform;}
    .sticky { position: sticky; width: 10px; height: 10px;}</style>
    <div class='scroller'>
      <div id='sticky-top' class='sticky' style='top: 0px;'></div>
      <div id='sticky-no-anchor' class='sticky'></div>
      <div style='height: 2000px;'></div>
    </div>
  )HTML");

  EXPECT_REASONS(CompositingReason::kStickyPosition,
                 CompositingReasonFinder::DirectReasonsForPaintProperties(
                     *GetLayoutObjectByElementId("sticky-top")));
  EXPECT_REASONS(CompositingReason::kNone,
                 CompositingReasonFinder::DirectReasonsForPaintProperties(
                     *GetLayoutObjectByElementId("sticky-no-anchor")));
}

TEST_P(CompositingReasonFinderTest, OnlyScrollingStickyPositionPromoted) {
  SetBodyInnerHTML(R"HTML(
    <style>
      .scroller {
        width: 400px;
        height: 400px;
        overflow: auto;
        will-change: transform;
      }
      .sticky {
        position: sticky;
        top: 0;
        width: 10px;
        height: 10px;
      }
      .overflow-hidden {
        width: 400px;
        height: 400px;
        overflow: hidden;
        will-change: transform;
      }
    </style>
    <div class='scroller'>
      <div id='sticky-scrolling' class='sticky'></div>
      <div style='height: 2000px;'></div>
    </div>
    <div class='scroller'>
      <div id='sticky-no-scrolling' class='sticky'></div>
    </div>
    <div class='overflow-hidden'>
      <div id='overflow-hidden-scrolling' class='sticky'></div>
      <div style='height: 2000px;'></div>
    </div>
    <div class='overflow-hidden'>
      <div id='overflow-hidden-no-scrolling' class='sticky'></div>
    </div>
    <div style="position: fixed">
      <div id='under-fixed' class='sticky'></div>
    </div>
    < div style='height: 2000px;"></div>
  )HTML");

  EXPECT_REASONS(CompositingReason::kStickyPosition,
                 CompositingReasonFinder::DirectReasonsForPaintProperties(
                     *GetLayoutObjectByElementId("sticky-scrolling")));

  EXPECT_REASONS(CompositingReason::kNone,
                 CompositingReasonFinder::DirectReasonsForPaintProperties(
                     *GetLayoutObjectByElementId("sticky-no-scrolling")));

  EXPECT_REASONS(CompositingReason::kStickyPosition,
                 CompositingReasonFinder::DirectReasonsForPaintProperties(
                     *GetLayoutObjectByElementId("overflow-hidden-scrolling")));

  EXPECT_REASONS(
      CompositingReason::kNone,
      CompositingReasonFinder::DirectReasonsForPaintProperties(
          *GetLayoutObjectByElementId("overflow-hidden-no-scrolling")));

  EXPECT_REASONS(CompositingReason::kNone,
                 CompositingReasonFinder::DirectReasonsForPaintProperties(
                     *GetLayoutObjectByElementId("under-fixed")));
}

void CompositingReasonFinderTest::CheckCompositingReasonsForAnimation(
    bool supports_transform_animation) {
  auto* object = GetLayoutObjectByElementId("target");
  ComputedStyleBuilder builder =
      GetDocument().GetStyleResolver().CreateComputedStyleBuilder();

  builder.SetSubtreeWillChangeContents(false);
  builder.SetHasCurrentTransformAnimation(false);
  builder.SetHasCurrentScaleAnimation(false);
  builder.SetHasCurrentRotateAnimation(false);
  builder.SetHasCurrentTranslateAnimation(false);
  builder.SetHasCurrentOpacityAnimation(false);
  builder.SetHasCurrentFilterAnimation(false);
  builder.SetHasCurrentBackdropFilterAnimation(false);
  object->SetStyle(builder.TakeStyle());

  EXPECT_REASONS(
      CompositingReason::kNone,
      CompositingReasonFinder::CompositingReasonsForAnimation(*object));

  CompositingReasons expected_reason = CompositingReason::kNone;

  builder = ComputedStyleBuilder(object->StyleRef());
  builder.SetHasCurrentTransformAnimation(true);
  object->SetStyle(builder.TakeStyle());
  if (supports_transform_animation)
    expected_reason |= CompositingReason::kActiveTransformAnimation;
  EXPECT_EQ(expected_reason,
            CompositingReasonFinder::CompositingReasonsForAnimation(*object));

  builder = ComputedStyleBuilder(object->StyleRef());
  builder.SetHasCurrentScaleAnimation(true);
  object->SetStyle(builder.TakeStyle());
  if (supports_transform_animation)
    expected_reason |= CompositingReason::kActiveScaleAnimation;
  EXPECT_EQ(expected_reason,
            CompositingReasonFinder::CompositingReasonsForAnimation(*object));

  builder = ComputedStyleBuilder(object->StyleRef());
  builder.SetHasCurrentRotateAnimation(true);
  object->SetStyle(builder.TakeStyle());
  if (supports_transform_animation)
    expected_reason |= CompositingReason::kActiveRotateAnimation;
  EXPECT_EQ(expected_reason,
            CompositingReasonFinder::CompositingReasonsForAnimation(*object));

  builder = ComputedStyleBuilder(object->StyleRef());
  builder.SetHasCurrentTranslateAnimation(true);
  object->SetStyle(builder.TakeStyle());
  if (supports_transform_animation)
    expected_reason |= CompositingReason::kActiveTranslateAnimation;
  EXPECT_EQ(expected_reason,
            CompositingReasonFinder::CompositingReasonsForAnimation(*object));

  builder = ComputedStyleBuilder(object->StyleRef());
  builder.SetHasCurrentOpacityAnimation(true);
  object->SetStyle(builder.TakeStyle());
  expected_reason |= CompositingReason::kActiveOpacityAnimation;
  EXPECT_EQ(expected_reason,
            CompositingReasonFinder::CompositingReasonsForAnimation(*object));

  builder = ComputedStyleBuilder(object->StyleRef());
  builder.SetHasCurrentFilterAnimation(true);
  object->SetStyle(builder.TakeStyle());
  expected_reason |= CompositingReason::kActiveFilterAnimation;
  EXPECT_EQ(expected_reason,
            CompositingReasonFinder::CompositingReasonsForAnimation(*object));

  builder = ComputedStyleBuilder(object->StyleRef());
  builder.SetHasCurrentBackdropFilterAnimation(true);
  object->SetStyle(builder.TakeStyle());
  expected_reason |= CompositingReason::kActiveBackdropFilterAnimation;
  EXPECT_EQ(expected_reason,
            CompositingReasonFinder::CompositingReasonsForAnimation(*object));
}

TEST_P(CompositingReasonFinderTest, CompositingReasonsForAnimationBox) {
  SetBodyInnerHTML("<div id='target'>Target</div>");
  CheckCompositingReasonsForAnimation(/*supports_transform_animation*/ true);
}

TEST_P(CompositingReasonFinderTest, CompositingReasonsForAnimationInline) {
  SetBodyInnerHTML("<span id='target'>Target</span>");
  CheckCompositingReasonsForAnimation(/*supports_transform_animation*/ false);
}

TEST_P(CompositingReasonFinderTest, DontPromoteEmptyIframe) {
  SetPreferCompositingToLCDText(true);

  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <iframe style="width:0; height:0; border: 0;" srcdoc="<!DOCTYPE html>"></iframe>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  auto* child_frame =
      To<LocalFrame>(GetDocument().GetFrame()->Tree().FirstChild());
  ASSERT_TRUE(child_frame);
  LocalFrameView* child_frame_view = child_frame->View();
  ASSERT_TRUE(child_frame_view);
  EXPECT_FALSE(child_frame_view->CanThrottleRendering());
}

TEST_P(CompositingReasonFinderTest, PromoteCrossOriginIframe) {
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <iframe id=iframe></iframe>
  )HTML");

  HTMLFrameOwnerElement* iframe = To<HTMLFrameOwnerElement>(
      GetDocument().getElementById(AtomicString("iframe")));
  ASSERT_TRUE(iframe);
  iframe->contentDocument()->OverrideIsInitialEmptyDocument();
  To<LocalFrame>(iframe->ContentFrame())->View()->BeginLifecycleUpdates();
  ASSERT_FALSE(iframe->ContentFrame()->IsCrossOriginToNearestMainFrame());
  UpdateAllLifecyclePhasesForTest();
  LayoutView* iframe_layout_view =
      To<LocalFrame>(iframe->ContentFrame())->ContentLayoutObject();
  ASSERT_TRUE(iframe_layout_view);
  PaintLayer* iframe_layer = iframe_layout_view->Layer();
  ASSERT_TRUE(iframe_layer);
  EXPECT_FALSE(iframe_layer->GetScrollableArea()->UsesCompositedScrolling());
  EXPECT_REASONS(CompositingReason::kNone,
                 CompositingReasonFinder::DirectReasonsForPaintProperties(
                     *iframe_layout_view));

  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <iframe id=iframe sandbox></iframe>
  )HTML");
  iframe = To<HTMLFrameOwnerElement>(
      GetDocument().getElementById(AtomicString("iframe")));
  iframe->contentDocument()->OverrideIsInitialEmptyDocument();
  To<LocalFrame>(iframe->ContentFrame())->View()->BeginLifecycleUpdates();
  UpdateAllLifecyclePhasesForTest();
  iframe_layout_view =
      To<LocalFrame>(iframe->ContentFrame())->ContentLayoutObject();
  iframe_layer = iframe_layout_view->Layer();
  ASSERT_TRUE(iframe_layer);
  ASSERT_TRUE(iframe->ContentFrame()->IsCrossOriginToNearestMainFrame());
  EXPECT_FALSE(iframe_layer->GetScrollableArea()->UsesCompositedScrolling());
  EXPECT_REASONS(CompositingReason::kIFrame,
                 CompositingReasonFinder::DirectReasonsForPaintProperties(
                     *iframe_layout_view));

  // Make the iframe contents scrollable.
  iframe->contentDocument()->body()->setAttribute(
      html_names::kStyleAttr, AtomicString("height: 2000px"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_REASONS(CompositingReason::kIFrame,
                 CompositingReasonFinder::DirectReasonsForPaintProperties(
                     *iframe_layout_view));
  EXPECT_TRUE(CompositingReasonFinder::ShouldForcePreferCompositingToLCDText(
      *iframe_layout_view, CompositingReason::kIFrame));
}

TEST_P(CompositingReasonFinderTest,
       CompositeWithBackfaceVisibilityAncestorAndPreserve3DAncestor) {
  ScopedBackfaceVisibilityInteropForTest bfi_enabled(true);

  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <style>
      div { width: 100px; height: 100px; position: relative }
    </style>
    <div style="backface-visibility: hidden; transform-style: preserve-3d">
      <div id=target></div>
    </div>
  )HTML");

  EXPECT_REASONS(CompositingReason::kBackfaceInvisibility3DAncestor |
                     CompositingReason::kTransform3DSceneLeaf,
                 CompositingReasonFinder::DirectReasonsForPaintProperties(
                     *GetLayoutObjectByElementId("target")));
}

TEST_P(CompositingReasonFinderTest,
       CompositeWithBackfaceVisibilityAncestorAndPreserve3D) {
  ScopedBackfaceVisibilityInteropForTest bfi_enabled(true);

  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <style>
      div { width: 100px; height: 100px; position: relative }
    </style>
    <div style="backface-visibility: hidden; transform-style: preserve-3d">
      <div id=target style="transform-style: preserve-3d"></div>
    </div>
  )HTML");

  EXPECT_REASONS(CompositingReason::kBackfaceInvisibility3DAncestor,
                 CompositingReasonFinder::DirectReasonsForPaintProperties(
                     *GetLayoutObjectByElementId("target")));
}

TEST_P(CompositingReasonFinderTest,
       CompositeWithBackfaceVisibilityAncestorAndPreserve3DWithInterveningDiv) {
  ScopedBackfaceVisibilityInteropForTest bfi_enabled(true);

  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <style>
      div { width: 100px; height: 100px }
    </style>
    <div style="backface-visibility: hidden; transform-style: preserve-3d">
      <div>
        <div id=target style="position: relative"></div>
      </div>
    </div>
  )HTML");

  EXPECT_REASONS(CompositingReason::kBackfaceInvisibility3DAncestor,
                 CompositingReasonFinder::DirectReasonsForPaintProperties(
                     *GetLayoutObjectByElementId("target")));
}

TEST_P(CompositingReasonFinderTest,
       CompositeWithBackfaceVisibilityAncestorWithInterveningStackingDiv) {
  ScopedBackfaceVisibilityInteropForTest bfi_enabled(true);

  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <style>
      div { width: 100px; height: 100px }
    </style>
    <div style="backface-visibility: hidden; transform-style: preserve-3d">
      <div id=intermediate style="isolation: isolate">
        <div id=target style="position: relative"></div>
      </div>
    </div>
  )HTML");

  EXPECT_REASONS(CompositingReason::kBackfaceInvisibility3DAncestor |
                     CompositingReason::kTransform3DSceneLeaf,
                 CompositingReasonFinder::DirectReasonsForPaintProperties(
                     *GetLayoutObjectByElementId("intermediate")));
  EXPECT_REASONS(CompositingReason::kNone,
                 CompositingReasonFinder::DirectReasonsForPaintProperties(
                     *GetLayoutObjectByElementId("target")));
}

TEST_P(CompositingReasonFinderTest,
       CompositeWithBackfaceVisibilityAncestorAndFlattening) {
  ScopedBackfaceVisibilityInteropForTest bfi_enabled(true);

  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <style>
      div { width: 100px; height: 100px; position: relative }
    </style>
    <div style="backface-visibility: hidden;">
      <div id=target></div>
    </div>
  )HTML");

  EXPECT_REASONS(CompositingReason::kNone,
                 CompositingReasonFinder::DirectReasonsForPaintProperties(
                     *GetLayoutObjectByElementId("target")));
}

TEST_P(CompositingReasonFinderTest, CompositeWithBackfaceVisibility) {
  ScopedBackfaceVisibilityInteropForTest bfi_enabled(true);

  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <style>
      div { width: 100px; height: 100px; position: relative }
    </style>
    <div id=target style="backface-visibility: hidden;">
      <div></div>
    </div>
  )HTML");

  EXPECT_REASONS(CompositingReason::kNone,
                 CompositingReasonFinder::DirectReasonsForPaintProperties(
                     *GetLayoutObjectByElementId("target")));
}

TEST_P(CompositingReasonFinderTest, CompositedSVGText) {
  SetBodyInnerHTML(R"HTML(
    <svg>
      <text id="text" style="will-change: opacity">Text</text>
    </svg>
  )HTML");

  auto* svg_text = GetLayoutObjectByElementId("text");
  EXPECT_EQ(
      CompositingReason::kWillChangeOpacity,
      CompositingReasonFinder::DirectReasonsForPaintProperties(*svg_text));
  auto* text = svg_text->SlowFirstChild();
  ASSERT_TRUE(text->IsText());
  EXPECT_REASONS(
      CompositingReason::kNone,
      CompositingReasonFinder::DirectReasonsForPaintProperties(*text));
}

TEST_P(CompositingReasonFinderTest, NotSupportedTransformAnimationsOnSVG) {
  SetBodyInnerHTML(R"HTML(
    <style>
      * { animation: transformKeyframes 1s infinite; }
      @keyframes transformKeyframes {
        0% { transform: rotate(-5deg); }
        100% { transform: rotate(5deg); }
      }
    </style>
    <svg>
      <defs id="defs" />
      <text id="text">text content
        <tspan id="tspan">tspan content</tspan>
      </text>
      <filter>
        <feBlend id="feBlend"></feBlend>
      </filter>
    </svg>
  )HTML");

  auto* defs = GetLayoutObjectByElementId("defs");
  EXPECT_REASONS(
      CompositingReason::kNone,
      CompositingReasonFinder::DirectReasonsForPaintProperties(*defs));

  auto* text = GetLayoutObjectByElementId("text");
  EXPECT_REASONS(
      CompositingReason::kActiveTransformAnimation,
      CompositingReasonFinder::DirectReasonsForPaintProperties(*text));

  auto* text_content = text->SlowFirstChild();
  ASSERT_TRUE(text_content->IsText());
  EXPECT_EQ(
      CompositingReason::kNone,
      CompositingReasonFinder::DirectReasonsForPaintProperties(*text_content));

  auto* tspan = GetLayoutObjectByElementId("tspan");
  EXPECT_REASONS(
      CompositingReason::kNone,
      CompositingReasonFinder::DirectReasonsForPaintProperties(*tspan));

  auto* tspan_content = tspan->SlowFirstChild();
  ASSERT_TRUE(tspan_content->IsText());
  EXPECT_EQ(
      CompositingReason::kNone,
      CompositingReasonFinder::DirectReasonsForPaintProperties(*tspan_content));

  auto* feBlend = GetLayoutObjectByElementId("feBlend");
  EXPECT_REASONS(
      CompositingReason::kNone,
      CompositingReasonFinder::DirectReasonsForPaintProperties(*feBlend));
}

TEST_P(CompositingReasonFinderTest, WillChangeScrollPosition) {
  SetBodyInnerHTML(R"HTML(
    <div id="target" style="width: 100px; height: 100px; overflow: scroll;
                            will-change: scroll-position">
      <div style="height: 2000px"></div>
    </div>
  )HTML");

  auto* target = GetLayoutObjectByElementId("target");
  EXPECT_TRUE(CompositingReasonFinder::ShouldForcePreferCompositingToLCDText(
      *target, CompositingReason::kNone));
  EXPECT_REASONS(
      CompositingReason::kNone,
      CompositingReasonFinder::DirectReasonsForPaintProperties(*target));

  GetDocument()
      .getElementById(AtomicString("target"))
      ->RemoveInlineStyleProperty(CSSPropertyID::kWillChange);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(CompositingReasonFinder::ShouldForcePreferCompositingToLCDText(
      *target, CompositingReason::kNone));
  EXPECT_REASONS(
      CompositingReason::kNone,
      CompositingReasonFinder::DirectReasonsForPaintProperties(*target));
}

}  // namespace blink

"""

```