Response:
Let's break down the thought process for analyzing this C++ test file.

**1. Initial Understanding and Keywords:**

The filename `paint_and_raster_invalidation_test.cc` immediately tells us the core purpose: it's a test file related to *paint invalidation* and *raster invalidation*. The directory `blink/renderer/core/paint/` confirms this is within the painting system of the Blink rendering engine. Keywords like "raster," "paint," "invalidation," "test," and later, concepts like "layers," "compositing," "CSS," "HTML," and even "JavaScript" come to mind as potential connections.

**2. Examining the Includes:**

The `#include` statements are crucial for understanding the dependencies and the scope of the code.

*   `paint_and_raster_invalidation_test.h`:  This likely defines the test fixture class used in this file.
*   `testing/gmock/include/gmock/gmock-matchers.h`: Indicates the use of Google Mock for assertions and matching (like `EXPECT_THAT`, `UnorderedElementsAre`). This is a strong signal that this is a unit or integration test.
*   `third_party/blink/renderer/core/frame/local_dom_window.h`: Points to interaction with the DOM (Document Object Model) and window context, which links to HTML and potentially JavaScript interactions.
*   `third_party/blink/renderer/core/loader/resource/image_resource_content.h`: Suggests testing scenarios involving images.
*   `third_party/blink/renderer/core/svg_names.h`: Indicates testing with SVG elements might be involved.
*   `third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h`:  Highlights the use of tracing for debugging or performance analysis of invalidation.
*   `third_party/blink/renderer/platform/testing/find_cc_layer.h`:  Suggests the tests interact with the Compositing Layer Tree (CC Layer), crucial for understanding how rendering is offloaded to the GPU.
*   `third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h`: Implies tests might involve enabling or disabling certain Blink features.

**3. Analyzing the Code Structure:**

*   **Namespaces:** The `namespace blink {` indicates this code is part of the Blink rendering engine.
*   **Helper Functions:** The `GetRasterInvalidationTracking` function suggests a mechanism to retrieve information about raster invalidations happening on specific layers. The `SetUpHTML` function indicates a common setup routine for creating test HTML structures.
*   **Test Fixture:** The `INSTANTIATE_PAINT_TEST_SUITE_P(PaintAndRasterInvalidationTest);` line reveals that the tests are likely parameterized, allowing them to run with different configurations (though not explicitly shown in this snippet).
*   **Scoped Class:** The `ScopedEnablePaintInvalidationTracing` class is a RAII (Resource Acquisition Is Initialization) wrapper to enable and disable tracing around specific test sections.
*   **Individual Tests:** The `TEST_P` macros define the actual test cases (e.g., `TrackingForTracing`, `IncrementalInvalidationExpand`). Each test focuses on a specific aspect of paint and raster invalidation.

**4. Connecting to Web Technologies (HTML, CSS, JavaScript):**

*   **HTML:** The `SetUpHTML` function directly manipulates HTML structure using `SetBodyInnerHTML`. The test cases use methods like `GetDocument().getElementById()` and `target->setAttribute()` to interact with DOM elements, reflecting real-world JavaScript manipulation of the DOM.
*   **CSS:** The `<style>` block within `SetUpHTML` defines CSS rules. The test cases change styles using `setAttribute('style', ...)` which mirrors how JavaScript dynamically modifies CSS. The class attributes (`target->setAttribute(html_names::kClassAttr, ...)`) also relate to CSS styling.
*   **JavaScript (Indirect):** While no explicit JavaScript code is shown in this snippet, the tests simulate the effects of JavaScript actions that would lead to style changes, DOM manipulations, and ultimately, paint and raster invalidations. For example, setting an attribute via JavaScript would have the same effect as the `setAttribute` calls in the tests.

**5. Inferring Functionality and Examples:**

Based on the test names and the code within the tests, we can infer the following functionalities being tested:

*   **Tracking Invalidation for Tracing:**  Verifying that paint invalidations are correctly recorded when tracing is enabled.
*   **Incremental Invalidation:** Testing how changes in element size trigger invalidations in only the affected regions. This is performance-critical.
*   **Subpixel Changes:** Examining how changes smaller than a pixel are handled.
*   **Transforms and Rotations:** Testing how CSS transforms affect invalidation regions.
*   **Scrolling and Overflow:**  Investigating invalidation behavior in scrolling containers (iframes, divs with `overflow: scroll`).
*   **Background Attachment (`background-attachment: local`):**  Testing a specific CSS property and how it influences invalidation during scrolling and resizing.
*   **Gradients:**  Special handling for background gradients.

**6. Reasoning and Hypothetical Inputs/Outputs:**

For example, in `IncrementalInvalidationExpand`, the initial size of `#target` is 50x100. Changing it to 100x200 means the right 50px and bottom 100px need to be repainted. This is the logic the test verifies. Similar reasoning applies to other tests by analyzing the initial state, the change applied, and the expected invalidation regions.

**7. Identifying Potential User/Programming Errors:**

*   **Incorrectly assuming no repaint:** A developer might change a style thinking it's a minor change and won't trigger a repaint, but these tests demonstrate that even seemingly small changes can cause invalidations.
*   **Not considering transform effects:** Developers might forget that transforms can significantly enlarge the repaint area.
*   **Misunderstanding `background-attachment: local`:**  This property's behavior during scrolling can be confusing, and these tests ensure it's handled correctly.

**8. Tracing User Actions (Debugging Clues):**

The "User Operation Steps" section in the provided answer is a good example of how to reverse-engineer the user actions that could lead to these code paths being executed. It involves thinking about common web interactions (scrolling, resizing, changing styles) and how they map to the underlying rendering engine operations.

**9. Iterative Refinement:**

The analysis is not always linear. You might jump between different parts of the code, make initial assumptions, and then refine them as you uncover more details. For example, seeing `will-change: transform` quickly suggests the involvement of compositing.

By following these steps, we can systematically understand the purpose and functionality of a complex source code file like this one. The key is to combine code examination with knowledge of web technologies and rendering engine principles.
这是目录为`blink/renderer/core/paint/paint_and_raster_invalidation_test.cc`的 Chromium Blink 引擎源代码文件，用于测试 **绘制（Paint）和栅格化（Raster）失效（Invalidation）** 机制。

**功能归纳:**

该文件包含了一系列的 C++ 测试用例，用于验证 Blink 渲染引擎在各种场景下正确地标记需要重新绘制和重新栅格化的区域。它主要关注以下几个方面：

*   **追踪失效信息:**  记录由于各种操作（例如修改样式、改变大小、滚动等）引起的绘制和栅格化失效。
*   **增量失效:** 验证引擎是否能够精确地识别出需要重新绘制/栅格化的最小区域，而不是整个元素或页面。
*   **全量失效:**  测试在某些特殊情况下，是否会触发全量的绘制和栅格化。
*   **不同类型的失效原因:**  区分由于布局（Layout）、增量（Incremental）、背景（Background）等不同原因引起的失效。
*   **composited（合成）和 non-composited（非合成）场景:** 测试在元素是否被提升为独立合成层的情况下，失效机制的不同行为。
*   **CSS 属性的影响:**  测试特定 CSS 属性（例如 `transform`, `background-attachment`, `overflow` 等）如何影响失效区域。
*   **子像素变化:** 验证对于小于一个像素的变化是否会触发失效。
*   **Tracing 支持:**  测试在启用 tracing 功能时，失效信息能否被正确记录。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

该测试文件直接测试由 JavaScript、HTML 和 CSS 导致的渲染更新。用户通过操作网页（这些操作最终会转化为对 DOM 和 CSSOM 的修改），触发渲染引擎的失效流程。

*   **JavaScript:**
    *   **举例:** JavaScript 代码修改了元素的 `style` 属性，例如改变了元素的宽度或高度。
        ```javascript
        document.getElementById('target').style.width = '100px';
        ```
        这个操作会导致 `paint_and_raster_invalidation_test.cc` 中的某些测试用例被触发，验证是否正确识别出需要重新绘制的区域。 例如，`IncrementalInvalidationExpand` 测试用例就模拟了这种场景。

*   **HTML:**
    *   **举例:** HTML 结构的改变，例如添加或删除元素。
        ```html
        <div id='container'><div id='target' class='solid'></div></div>
        ```
        如果 JavaScript 删除了 `target` 元素，会导致其父元素 `container` 相关的渲染信息失效，需要重新绘制。虽然这个文件中的例子主要关注属性修改，但 HTML 结构变化也会导致失效。

*   **CSS:**
    *   **举例:** CSS 样式的修改，例如改变元素的背景颜色、边框、transform 等。
        ```css
        #target {
          width: 50px;
          height: 100px;
          background: blue;
        }
        ```
        测试用例中通过 `target->setAttribute(html_names::kStyleAttr, ...)` 来模拟 CSS 属性的修改。例如，修改 `#target` 的 `background` 会触发重新绘制。 `ResizeRotated` 测试用例测试了 `transform` 属性变化带来的失效。

**逻辑推理、假设输入与输出:**

以 `IncrementalInvalidationExpand` 测试用例为例：

*   **假设输入:**
    *   HTML 结构包含一个 `id='target'` 的 div，初始宽度 50px，高度 100px。
    *   JavaScript (或测试代码) 将 `target` 的宽度修改为 100px，高度修改为 200px。
*   **逻辑推理:**
    *   元素的尺寸发生了改变。
    *   旧的渲染区域需要部分失效。
    *   新增的渲染区域需要被绘制。
    *   引擎应该能够识别出增量的变化区域。
*   **预期输出:**
    *   `GetRasterInvalidationTracking()->Invalidations()` 应该包含两个 `RasterInvalidationInfo` 对象，分别对应宽度和高度增加导致的失效区域。
    *   一个失效区域表示右侧新增的 50px 宽度 (gfx::Rect(50, 0, 50, 200))。
    *   另一个失效区域表示底部新增的 100px 高度 (gfx::Rect(0, 100, 100, 100))。
    *   失效原因是 `PaintInvalidationReason::kIncremental`。

**用户或编程常见的使用错误及举例说明:**

*   **错误地假设样式修改不会触发重绘:**  开发者可能认为修改某些“不重要”的样式属性不会触发重绘，但实际上，即使是小的样式变化也可能导致渲染失效。 例如，修改一个未显示元素的样式，虽然用户不可见，但仍然可能导致失效。
*   **过度使用 `will-change` 属性:** 开发者可能为了性能优化而滥用 `will-change` 属性，但这可能会导致不必要的图层提升和内存消耗。  测试用例中使用了 `will-change: transform` 来模拟 composited 场景，开发者需要理解其影响。
*   **不理解 `background-attachment: local` 的影响:**  当元素滚动时，`local` 值会使背景图跟随内容滚动，这会影响失效策略。`CompositedBackgroundAttachmentLocalResize` 和 `NonCompositedBackgroundAttachmentLocalResize` 测试用例验证了这种行为。
*   **在 JavaScript 中进行大量的、同步的样式修改:**  这会导致浏览器频繁地进行布局和绘制，影响性能。 理解失效机制可以帮助开发者优化 JavaScript 代码，减少不必要的渲染操作。

**用户操作如何一步步的到达这里 (调试线索):**

1. **用户在浏览器中加载了一个网页。**
2. **用户与网页进行交互，例如：**
    *   **滚动页面:** 这可能触发 `CompositedLayoutViewResize` 等测试用例。
    *   **调整浏览器窗口大小:** 这会影响视口大小，可能触发全量或部分失效。
    *   **点击按钮或链接，导致 JavaScript 代码执行。**
    *   **JavaScript 代码修改了 DOM 结构或元素的样式。** 例如，点击一个按钮，JavaScript 代码修改了某个 div 的宽度。
    *   **CSS 动画或 transitions 触发样式变化。**
3. **渲染引擎接收到这些变化的通知。**
4. **Blink 的 Layout 阶段计算元素的新布局。**
5. **Blink 的 Paint 阶段根据新的布局信息，标记需要重新绘制的区域。**  `paint_and_raster_invalidation_test.cc` 这个文件就是用来测试这个阶段的逻辑是否正确。
6. **Blink 的 Raster 阶段将需要更新的绘制内容栅格化成位图。**

**作为调试线索:**

当开发者在 Chromium 中调试渲染问题（例如页面闪烁、性能问题）时，理解绘制和栅格化失效机制至关重要。

*   **分析失效区域:**  通过开发者工具或者 tracing 工具，可以查看哪些区域被标记为失效，以及失效的原因。这可以帮助开发者定位引起不必要重绘的代码。
*   **验证失效逻辑:**  如果怀疑失效逻辑有问题，可以参考 `paint_and_raster_invalidation_test.cc` 中的测试用例，编写类似的测试来验证特定的场景。
*   **理解 Compositing 的影响:**  当元素被提升为合成层时，失效的处理方式会有所不同。 理解这些差异有助于解决与合成相关的渲染问题。

**总结 (针对第 1 部分):**

`paint_and_raster_invalidation_test.cc` 的主要功能是 **测试 Blink 渲染引擎的绘制和栅格化失效机制的正确性**。 它通过模拟各种由 HTML、CSS 和 JavaScript 引起的变化，验证引擎能否精确地识别需要更新的渲染区域，并区分不同的失效原因。 这对于保证浏览器的渲染性能和用户体验至关重要。

Prompt: 
```
这是目录为blink/renderer/core/paint/paint_and_raster_invalidation_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/paint/paint_and_raster_invalidation_test.h"

#include "testing/gmock/include/gmock/gmock-matchers.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/loader/resource/image_resource_content.h"
#include "third_party/blink/renderer/core/svg_names.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/testing/find_cc_layer.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"

namespace blink {

using ::testing::MatchesRegex;
using ::testing::UnorderedElementsAre;
using ::testing::UnorderedElementsAreArray;

const RasterInvalidationTracking* GetRasterInvalidationTracking(
    const LocalFrameView& root_frame_view,
    wtf_size_t index,
    const String& name_regex) {
  if (auto* client = root_frame_view.GetPaintArtifactCompositor()
                         ->ContentLayerClientForTesting(index)) {
    DCHECK(client->Layer().draws_content())
        << index << ": " << client->Layer().DebugName();
    DCHECK(::testing::Matcher<std::string>(
               ::testing::ContainsRegex(name_regex.Utf8()))
               .Matches(client->Layer().DebugName()))
        << index << ": " << client->Layer().DebugName()
        << " regex=" << name_regex;
    return client->GetRasterInvalidator().GetTracking();
  }
  return nullptr;
}

void SetUpHTML(PaintAndRasterInvalidationTest& test) {
  test.SetBodyInnerHTML(R"HTML(
    <style>
      body {
        margin: 0;
        height: 0;
      }
      ::-webkit-scrollbar { display: none }
      #target {
        width: 50px;
        height: 100px;
        transform-origin: 0 0;
      }
      .solid {
        background: blue;
      }
      .translucent {
        background: rgba(0, 0, 255, 0.5);
      }
      .gradient {
        background-image: linear-gradient(blue, yellow);
      }
      .scroll {
        overflow: scroll;
      }
      .solid-composited-scroller {
        overflow: scroll;
        will-change: transform;
        background: blue;
      }
      .local-attachment {
        background-attachment: local;
      }
      .transform {
        transform: scale(2);
      }
      .border {
        border: 10px solid black;
      }
      .composited {
        will-change: transform;
      }
    </style>
    <div id='target' class='solid'></div>
  )HTML");
}

INSTANTIATE_PAINT_TEST_SUITE_P(PaintAndRasterInvalidationTest);

class ScopedEnablePaintInvalidationTracing {
 public:
  ScopedEnablePaintInvalidationTracing() {
    trace_event::EnableTracing(TRACE_DISABLED_BY_DEFAULT("blink.invalidation"));
  }
  ~ScopedEnablePaintInvalidationTracing() { trace_event::DisableTracing(); }
};

TEST_P(PaintAndRasterInvalidationTest, TrackingForTracing) {
  SetBodyInnerHTML(R"HTML(
    <style>#target { width: 100px; height: 100px; background: blue }</style>
    <div id="target"></div>
  )HTML");
  auto* target = GetDocument().getElementById(AtomicString("target"));
  auto& cc_layer = *GetDocument()
                        .View()
                        ->GetPaintArtifactCompositor()
                        ->RootLayer()
                        ->children()[1];

  {
    ScopedEnablePaintInvalidationTracing tracing;

    target->setAttribute(html_names::kStyleAttr, AtomicString("height: 200px"));
    UpdateAllLifecyclePhasesForTest();
    ASSERT_TRUE(cc_layer.debug_info());
    EXPECT_EQ(1u, cc_layer.debug_info()->invalidations.size());

    target->setAttribute(html_names::kStyleAttr,
                         AtomicString("height: 200px; width: 200px"));
    UpdateAllLifecyclePhasesForTest();
    ASSERT_TRUE(cc_layer.debug_info());
    EXPECT_EQ(2u, cc_layer.debug_info()->invalidations.size());
  }

  target->setAttribute(html_names::kStyleAttr,
                       AtomicString("height: 300px; width: 300px"));
  UpdateAllLifecyclePhasesForTest();
  ASSERT_TRUE(cc_layer.debug_info());
  // No new invalidations tracked.
  EXPECT_EQ(2u, cc_layer.debug_info()->invalidations.size());
}

TEST_P(PaintAndRasterInvalidationTest, IncrementalInvalidationExpand) {
  SetUpHTML(*this);
  Element* target = GetDocument().getElementById(AtomicString("target"));
  auto* object = target->GetLayoutObject();

  GetDocument().View()->SetTracksRasterInvalidations(true);
  target->setAttribute(html_names::kStyleAttr,
                       AtomicString("width: 100px; height: 200px"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_THAT(
      GetRasterInvalidationTracking()->Invalidations(),
      UnorderedElementsAre(
          RasterInvalidationInfo{object->Id(), object->DebugName(),
                                 gfx::Rect(50, 0, 50, 200),
                                 PaintInvalidationReason::kIncremental},
          RasterInvalidationInfo{object->Id(), object->DebugName(),
                                 gfx::Rect(0, 100, 100, 100),
                                 PaintInvalidationReason::kIncremental}));
  GetDocument().View()->SetTracksRasterInvalidations(false);
}

TEST_P(PaintAndRasterInvalidationTest, IncrementalInvalidationShrink) {
  SetUpHTML(*this);
  Element* target = GetDocument().getElementById(AtomicString("target"));
  auto* object = target->GetLayoutObject();

  GetDocument().View()->SetTracksRasterInvalidations(true);
  target->setAttribute(html_names::kStyleAttr,
                       AtomicString("width: 20px; height: 80px"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_THAT(
      GetRasterInvalidationTracking()->Invalidations(),
      UnorderedElementsAre(
          RasterInvalidationInfo{object->Id(), object->DebugName(),
                                 gfx::Rect(20, 0, 30, 100),
                                 PaintInvalidationReason::kIncremental},
          RasterInvalidationInfo{object->Id(), object->DebugName(),
                                 gfx::Rect(0, 80, 50, 20),
                                 PaintInvalidationReason::kIncremental}));
  GetDocument().View()->SetTracksRasterInvalidations(false);
}

TEST_P(PaintAndRasterInvalidationTest, IncrementalInvalidationMixed) {
  SetUpHTML(*this);
  Element* target = GetDocument().getElementById(AtomicString("target"));
  auto* object = target->GetLayoutObject();

  GetDocument().View()->SetTracksRasterInvalidations(true);
  target->setAttribute(html_names::kStyleAttr,
                       AtomicString("width: 100px; height: 80px"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_THAT(
      GetRasterInvalidationTracking()->Invalidations(),
      UnorderedElementsAre(
          RasterInvalidationInfo{object->Id(), object->DebugName(),
                                 gfx::Rect(50, 0, 50, 80),
                                 PaintInvalidationReason::kIncremental},
          RasterInvalidationInfo{object->Id(), object->DebugName(),
                                 gfx::Rect(0, 80, 50, 20),
                                 PaintInvalidationReason::kIncremental}));
  GetDocument().View()->SetTracksRasterInvalidations(false);
}

TEST_P(PaintAndRasterInvalidationTest, ResizeEmptyContent) {
  SetUpHTML(*this);
  Element* target = GetDocument().getElementById(AtomicString("target"));
  // Make the view not solid color so that we can track raster invalidations.
  GetDocument().body()->setAttribute(
      html_names::kStyleAttr,
      AtomicString("height: 400px; background: linear-gradient(red, blue)"));
  // Make the box empty.
  target->setAttribute(html_names::kClassAttr, g_empty_atom);
  UpdateAllLifecyclePhasesForTest();

  GetDocument().View()->SetTracksRasterInvalidations(true);
  target->setAttribute(html_names::kStyleAttr,
                       AtomicString("width: 100px; height: 80px"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(GetRasterInvalidationTracking()->HasInvalidations());
  GetDocument().View()->SetTracksRasterInvalidations(false);
}

TEST_P(PaintAndRasterInvalidationTest, SubpixelChange) {
  SetUpHTML(*this);
  Element* target = GetDocument().getElementById(AtomicString("target"));
  auto* object = target->GetLayoutObject();

  GetDocument().View()->SetTracksRasterInvalidations(true);
  target->setAttribute(html_names::kStyleAttr,
                       AtomicString("width: 100.6px; height: 70.3px"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_THAT(GetRasterInvalidationTracking()->Invalidations(),
              UnorderedElementsAre(
                  RasterInvalidationInfo{object->Id(), object->DebugName(),
                                         gfx::Rect(0, 0, 50, 100),
                                         PaintInvalidationReason::kLayout},
                  RasterInvalidationInfo{object->Id(), object->DebugName(),
                                         gfx::Rect(0, 0, 101, 70),
                                         PaintInvalidationReason::kLayout}));
  GetDocument().View()->SetTracksRasterInvalidations(false);

  GetDocument().View()->SetTracksRasterInvalidations(true);
  target->setAttribute(html_names::kStyleAttr,
                       AtomicString("width: 50px; height: 100px"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_THAT(GetRasterInvalidationTracking()->Invalidations(),
              UnorderedElementsAre(
                  RasterInvalidationInfo{object->Id(), object->DebugName(),
                                         gfx::Rect(0, 0, 50, 100),
                                         PaintInvalidationReason::kLayout},
                  RasterInvalidationInfo{object->Id(), object->DebugName(),
                                         gfx::Rect(0, 0, 101, 70),
                                         PaintInvalidationReason::kLayout}));
  GetDocument().View()->SetTracksRasterInvalidations(false);
}

TEST_P(PaintAndRasterInvalidationTest, SubpixelVisualRectChangeWithTransform) {
  SetUpHTML(*this);
  Element* target = GetDocument().getElementById(AtomicString("target"));
  auto* object = target->GetLayoutObject();
  target->setAttribute(html_names::kClassAttr, AtomicString("solid transform"));
  UpdateAllLifecyclePhasesForTest();

  GetDocument().View()->SetTracksRasterInvalidations(true);
  target->setAttribute(html_names::kStyleAttr,
                       AtomicString("width: 100.6px; height: 70.3px"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_THAT(GetRasterInvalidationTracking()->Invalidations(),
              UnorderedElementsAre(
                  RasterInvalidationInfo{object->Id(), object->DebugName(),
                                         gfx::Rect(0, 0, 100, 200),
                                         PaintInvalidationReason::kLayout},
                  RasterInvalidationInfo{object->Id(), object->DebugName(),
                                         gfx::Rect(0, 0, 202, 140),
                                         PaintInvalidationReason::kLayout}));
  GetDocument().View()->SetTracksRasterInvalidations(false);

  GetDocument().View()->SetTracksRasterInvalidations(true);
  target->setAttribute(html_names::kStyleAttr,
                       AtomicString("width: 50px; height: 100px"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_THAT(GetRasterInvalidationTracking()->Invalidations(),
              UnorderedElementsAre(
                  RasterInvalidationInfo{object->Id(), object->DebugName(),
                                         gfx::Rect(0, 0, 100, 200),
                                         PaintInvalidationReason::kLayout},
                  RasterInvalidationInfo{object->Id(), object->DebugName(),
                                         gfx::Rect(0, 0, 202, 140),
                                         PaintInvalidationReason::kLayout}));
  GetDocument().View()->SetTracksRasterInvalidations(false);
}

TEST_P(PaintAndRasterInvalidationTest, SubpixelWithinPixelsChange) {
  SetUpHTML(*this);
  Element* target = GetDocument().getElementById(AtomicString("target"));
  LayoutObject* object = target->GetLayoutObject();

  GetDocument().View()->SetTracksRasterInvalidations(true);
  target->setAttribute(
      html_names::kStyleAttr,
      AtomicString("margin-top: 0.6px; width: 50px; height: 99.3px"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_THAT(GetRasterInvalidationTracking()->Invalidations(),
              UnorderedElementsAre(RasterInvalidationInfo{
                  object->Id(), object->DebugName(), gfx::Rect(0, 0, 50, 100),
                  PaintInvalidationReason::kLayout}));
  GetDocument().View()->SetTracksRasterInvalidations(false);

  GetDocument().View()->SetTracksRasterInvalidations(true);
  target->setAttribute(
      html_names::kStyleAttr,
      AtomicString("margin-top: 0.6px; width: 49.3px; height: 98.5px"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_THAT(GetRasterInvalidationTracking()->Invalidations(),
              UnorderedElementsAre(RasterInvalidationInfo{
                  object->Id(), object->DebugName(), gfx::Rect(0, 1, 50, 99),
                  PaintInvalidationReason::kLayout}));
  GetDocument().View()->SetTracksRasterInvalidations(false);
}

TEST_P(PaintAndRasterInvalidationTest, ResizeRotated) {
  SetUpHTML(*this);
  Element* target = GetDocument().getElementById(AtomicString("target"));
  auto* object = target->GetLayoutObject();
  target->setAttribute(html_names::kStyleAttr,
                       AtomicString("transform: rotate(45deg)"));
  UpdateAllLifecyclePhasesForTest();

  GetDocument().View()->SetTracksRasterInvalidations(true);
  target->setAttribute(html_names::kStyleAttr,
                       AtomicString("transform: rotate(45deg); width: 200px"));
  UpdateAllLifecyclePhasesForTest();
  auto expected_rect =
      MakeRotationMatrix(45).MapRect(gfx::Rect(50, 0, 150, 100));
  expected_rect.Intersect(gfx::Rect(0, 0, 800, 600));
  EXPECT_THAT(GetRasterInvalidationTracking()->Invalidations(),
              UnorderedElementsAre(RasterInvalidationInfo{
                  object->Id(), object->DebugName(), expected_rect,
                  PaintInvalidationReason::kIncremental}));
  GetDocument().View()->SetTracksRasterInvalidations(false);
}

TEST_P(PaintAndRasterInvalidationTest, ResizeRotatedChild) {
  SetUpHTML(*this);
  Element* target = GetDocument().getElementById(AtomicString("target"));
  target->setAttribute(html_names::kStyleAttr,
                       AtomicString("transform: rotate(45deg); width: 200px"));
  target->setInnerHTML(
      "<div id=child style='width: 50px; height: 50px; background: "
      "red'></div>");
  UpdateAllLifecyclePhasesForTest();
  Element* child = GetDocument().getElementById(AtomicString("child"));
  auto* child_object = child->GetLayoutObject();

  GetDocument().View()->SetTracksRasterInvalidations(true);
  child->setAttribute(
      html_names::kStyleAttr,
      AtomicString("width: 100px; height: 50px; background: red"));
  UpdateAllLifecyclePhasesForTest();
  auto expected_rect = MakeRotationMatrix(45).MapRect(gfx::Rect(50, 0, 50, 50));
  expected_rect.Intersect(gfx::Rect(0, 0, 800, 600));
  EXPECT_THAT(GetRasterInvalidationTracking()->Invalidations(),
              UnorderedElementsAre(RasterInvalidationInfo{
                  child_object->Id(), child_object->DebugName(), expected_rect,
                  PaintInvalidationReason::kIncremental}));
  GetDocument().View()->SetTracksRasterInvalidations(false);
}

TEST_P(PaintAndRasterInvalidationTest, CompositedLayoutViewResize) {
  SetUpHTML(*this);
  Element* target = GetDocument().getElementById(AtomicString("target"));
  target->setAttribute(html_names::kClassAttr, g_empty_atom);
  target->setAttribute(html_names::kStyleAttr, AtomicString("height: 2000px"));
  // Make the scrolling contents layer not solid color so that we can track
  // raster invalidations.
  target->setInnerHTML("<div style='height: 20px'>Text</div>");
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(kBackgroundPaintInContentsSpace,
            GetLayoutView().GetBackgroundPaintLocation());

  // Resize the content.
  GetDocument().View()->SetTracksRasterInvalidations(true);
  target->setAttribute(html_names::kStyleAttr, AtomicString("height: 3000px"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_THAT(GetRasterInvalidationTracking()->Invalidations(),
              UnorderedElementsAre(RasterInvalidationInfo{
                  ViewScrollingBackgroundClient().Id(),
                  ViewScrollingBackgroundClient().DebugName(),
                  gfx::Rect(0, 2000, 800, 1000),
                  PaintInvalidationReason::kIncremental}));
  GetDocument().View()->SetTracksRasterInvalidations(false);

  // Resize the viewport. No invalidation.
  GetDocument().View()->SetTracksRasterInvalidations(true);
  GetDocument().View()->Resize(800, 1000);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(GetRasterInvalidationTracking()->HasInvalidations());
  GetDocument().View()->SetTracksRasterInvalidations(false);
}

TEST_P(PaintAndRasterInvalidationTest, CompositedLayoutViewGradientResize) {
  SetUpHTML(*this);
  GetDocument().body()->setAttribute(html_names::kClassAttr,
                                     AtomicString("gradient"));
  Element* target = GetDocument().getElementById(AtomicString("target"));
  target->setAttribute(html_names::kClassAttr, g_empty_atom);
  target->setAttribute(html_names::kStyleAttr, AtomicString("height: 2000px"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(kBackgroundPaintInContentsSpace,
            GetLayoutView().GetBackgroundPaintLocation());

  // Resize the content.
  GetDocument().View()->SetTracksRasterInvalidations(true);
  target->setAttribute(html_names::kStyleAttr, AtomicString("height: 3000px"));
  UpdateAllLifecyclePhasesForTest();

  EXPECT_THAT(
      GetRasterInvalidationTracking()->Invalidations(),
      UnorderedElementsAre(RasterInvalidationInfo{
          ViewScrollingBackgroundClient().Id(),
          ViewScrollingBackgroundClient().DebugName(),
          gfx::Rect(0, 0, 800, 3000), PaintInvalidationReason::kBackground}));
  GetDocument().View()->SetTracksRasterInvalidations(false);

  // Resize the viewport. No invalidation.
  GetDocument().View()->SetTracksRasterInvalidations(true);
  GetDocument().View()->Resize(800, 1000);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(GetRasterInvalidationTracking()->HasInvalidations());
  GetDocument().View()->SetTracksRasterInvalidations(false);
}

TEST_P(PaintAndRasterInvalidationTest, NonCompositedLayoutViewResize) {
  ScopedPreferNonCompositedScrollingForTest non_composited_scrolling(true);

  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin: 0 }
      iframe { display: block; width: 100px; height: 100px; border: none; }
    </style>
    <iframe id='iframe'></iframe>
  )HTML");
  SetChildFrameHTML(R"HTML(
    <style>
      ::-webkit-scrollbar { display: none }
      body { margin: 0; background: green; height: 0 }
    </style>
    <div id='content' style='width: 200px; height: 200px'></div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();
  Element* iframe = GetDocument().getElementById(AtomicString("iframe"));
  LayoutView* iframe_layout_view = ChildDocument().View()->GetLayoutView();
  Element* content = ChildDocument().getElementById(AtomicString("content"));
  EXPECT_EQ(kBackgroundPaintInContentsSpace,
            iframe_layout_view->GetBackgroundPaintLocation());

  // Resize the content.
  GetDocument().View()->SetTracksRasterInvalidations(true);
  content->setAttribute(html_names::kStyleAttr, AtomicString("height: 500px"));
  UpdateAllLifecyclePhasesForTest();
  // No invalidation because the changed part of scrollable overflow is clipped.
  EXPECT_FALSE(GetRasterInvalidationTracking()->HasInvalidations());
  GetDocument().View()->SetTracksRasterInvalidations(false);

  // Resize the iframe.
  GetDocument().View()->SetTracksRasterInvalidations(true);
  iframe->setAttribute(html_names::kStyleAttr, AtomicString("height: 200px"));
  UpdateAllLifecyclePhasesForTest();
  // The iframe doesn't have anything visible by itself, so we only issue
  // raster invalidation for the frame contents.
  const auto& client = iframe_layout_view->GetScrollableArea()
                           ->GetScrollingBackgroundDisplayItemClient();
  EXPECT_THAT(GetRasterInvalidationTracking()->Invalidations(),
              UnorderedElementsAre(RasterInvalidationInfo{
                  client.Id(), client.DebugName(), gfx::Rect(0, 100, 100, 100),
                  PaintInvalidationReason::kIncremental}));
  GetDocument().View()->SetTracksRasterInvalidations(false);
}

TEST_P(PaintAndRasterInvalidationTest, FullInvalidationWithHTMLTransform) {
  GetDocument().documentElement()->setAttribute(
      html_names::kStyleAttr, AtomicString("transform: scale(0.5)"));
  const DisplayItemClient& client = ViewScrollingBackgroundClient();
  UpdateAllLifecyclePhasesForTest();

  GetDocument().View()->SetTracksRasterInvalidations(true);
  GetDocument().View()->Resize(gfx::Size(500, 500));
  UpdateAllLifecyclePhasesForTest();

  EXPECT_THAT(
      GetRasterInvalidationTracking()->Invalidations(),
      UnorderedElementsAre(
          RasterInvalidationInfo{client.Id(), client.DebugName(),
                                 gfx::Rect(0, 0, 500, 500),
                                 PaintInvalidationReason::kBackground},
          RasterInvalidationInfo{client.Id(), client.DebugName(),
                                 gfx::Rect(0, 0, 500, 500),
                                 PaintInvalidationReason::kBackground}));
}

TEST_P(PaintAndRasterInvalidationTest, NonCompositedLayoutViewGradientResize) {
  ScopedPreferNonCompositedScrollingForTest non_composited_scrolling(true);

  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin: 0 }
      iframe { display: block; width: 100px; height: 100px; border: none; }
    </style>
    <iframe id='iframe'></iframe>
  )HTML");
  SetChildFrameHTML(R"HTML(
    <style>
      ::-webkit-scrollbar { display: none }
      body {
        margin: 0;
        height: 0;
        background-image: linear-gradient(blue, yellow);
      }
    </style>
    <div id='content' style='width: 200px; height: 200px'></div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();
  Element* iframe = GetDocument().getElementById(AtomicString("iframe"));
  const auto* iframe_layout_view = ChildDocument().View()->GetLayoutView();
  Element* content = ChildDocument().getElementById(AtomicString("content"));

  // Resize the content.
  GetDocument().View()->SetTracksRasterInvalidations(true);
  content->setAttribute(html_names::kStyleAttr, AtomicString("height: 500px"));
  UpdateAllLifecyclePhasesForTest();
  const auto* client = &iframe_layout_view->GetScrollableArea()
                            ->GetScrollingBackgroundDisplayItemClient();
  // The two invalidations are for the old background and the new background.
  // The rects are the same because they are clipped by the layer bounds.
  EXPECT_THAT(
      GetRasterInvalidationTracking()->Invalidations(),
      UnorderedElementsAre(
          RasterInvalidationInfo{client->Id(), client->DebugName(),
                                 gfx::Rect(0, 0, 100, 100),
                                 PaintInvalidationReason::kBackground},
          RasterInvalidationInfo{client->Id(), client->DebugName(),
                                 gfx::Rect(0, 0, 100, 100),
                                 PaintInvalidationReason::kBackground}));
  GetDocument().View()->SetTracksRasterInvalidations(false);

  // Resize the iframe.
  GetDocument().View()->SetTracksRasterInvalidations(true);
  iframe->setAttribute(html_names::kStyleAttr, AtomicString("height: 200px"));
  UpdateAllLifecyclePhasesForTest();
  // The iframe doesn't have anything visible by itself, so we only issue
  // raster invalidation for the frame contents.
  EXPECT_THAT(
      GetRasterInvalidationTracking()->Invalidations(),
      UnorderedElementsAre(
          RasterInvalidationInfo{client->Id(), client->DebugName(),
                                 gfx::Rect(0, 100, 100, 100),
                                 PaintInvalidationReason::kIncremental},
          RasterInvalidationInfo{client->Id(), client->DebugName(),
                                 gfx::Rect(0, 0, 100, 200),
                                 PaintInvalidationReason::kBackground}));
  GetDocument().View()->SetTracksRasterInvalidations(false);
}

TEST_P(PaintAndRasterInvalidationTest,
       CompositedBackgroundAttachmentLocalResize) {
  SetUpHTML(*this);
  Element* target = GetDocument().getElementById(AtomicString("target"));
  target->setAttribute(
      html_names::kClassAttr,
      AtomicString("solid composited scroll local-attachment border"));
  UpdateAllLifecyclePhasesForTest();
  target->setInnerHTML(
      "<div id=child style='width: 500px; height: 500px'></div>",
      ASSERT_NO_EXCEPTION);
  Element* child = GetDocument().getElementById(AtomicString("child"));
  UpdateAllLifecyclePhasesForTest();

  auto* target_obj = target->GetLayoutBox();
  EXPECT_EQ(kBackgroundPaintInContentsSpace,
            target_obj->GetBackgroundPaintLocation());

  auto container_raster_invalidation_tracking =
      [&]() -> const RasterInvalidationTracking* {
    return GetRasterInvalidationTracking(0, "target");
  };
  auto contents_raster_invalidation_tracking =
      [&]() -> const RasterInvalidationTracking* {
    return GetRasterInvalidationTracking(1, "target");
  };

  // Resize the content.
  GetDocument().View()->SetTracksRasterInvalidations(true);
  child->setAttribute(html_names::kStyleAttr,
                      AtomicString("width: 500px; height: 1000px"));
  UpdateAllLifecyclePhasesForTest();
  // No invalidation on the container layer.
  EXPECT_FALSE(container_raster_invalidation_tracking()->HasInvalidations());
  // Incremental invalidation of background on contents layer.
  const auto& client = target_obj->GetScrollableArea()
                           ->GetScrollingBackgroundDisplayItemClient();
  EXPECT_THAT(contents_raster_invalidation_tracking()->Invalidations(),
              UnorderedElementsAre(RasterInvalidationInfo{
                  client.Id(), client.DebugName(), gfx::Rect(0, 500, 500, 500),
                  PaintInvalidationReason::kIncremental}));
  GetDocument().View()->SetTracksRasterInvalidations(false);

  // Resize the container.
  GetDocument().View()->SetTracksRasterInvalidations(true);
  target->setAttribute(html_names::kStyleAttr, AtomicString("height: 200px"));
  UpdateAllLifecyclePhasesForTest();
  // Border invalidated in the container layer.
  EXPECT_THAT(container_raster_invalidation_tracking()->Invalidations(),
              UnorderedElementsAre(RasterInvalidationInfo{
                  target_obj->Id(), target_obj->DebugName(),
                  gfx::Rect(0, 0, 70, 220), PaintInvalidationReason::kLayout}));
  // No invalidation on scrolling contents for container resize.
  EXPECT_FALSE(contents_raster_invalidation_tracking()->HasInvalidations());
  GetDocument().View()->SetTracksRasterInvalidations(false);
}

TEST_P(PaintAndRasterInvalidationTest,
       CompositedBackgroundAttachmentLocalGradientResize) {
  SetUpHTML(*this);
  Element* target = GetDocument().getElementById(AtomicString("target"));
  target->setAttribute(
      html_names::kClassAttr,
      AtomicString("gradient composited scroll local-attachment border"));
  target->setInnerHTML(
      "<div id='child' style='width: 500px; height: 500px'></div>",
      ASSERT_NO_EXCEPTION);
  Element* child = GetDocument().getElementById(AtomicString("child"));
  UpdateAllLifecyclePhasesForTest();

  auto* target_obj = target->GetLayoutBox();
  auto container_raster_invalidation_tracking =
      [&]() -> const RasterInvalidationTracking* {
    return GetRasterInvalidationTracking(0, "target");
  };
  auto contents_raster_invalidation_tracking =
      [&]() -> const RasterInvalidationTracking* {
    return GetRasterInvalidationTracking(1, "target");
  };

  // Resize the content.
  GetDocument().View()->SetTracksRasterInvalidations(true);
  child->setAttribute(html_names::kStyleAttr,
                      AtomicString("width: 500px; height: 1000px"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(kBackgroundPaintInContentsSpace,
            target_obj->GetBackgroundPaintLocation());

  // No invalidation on the container layer.
  EXPECT_FALSE(container_raster_invalidation_tracking()->HasInvalidations());
  // Full invalidation of background on contents layer because the gradient
  // background is resized.
  const auto& client = target_obj->GetScrollableArea()
                           ->GetScrollingBackgroundDisplayItemClient();
  EXPECT_THAT(contents_raster_invalidation_tracking()->Invalidations(),
              UnorderedElementsAre(RasterInvalidationInfo{
                  client.Id(), client.DebugName(), gfx::Rect(0, 0, 500, 1000),
                  PaintInvalidationReason::kBackground}));
  GetDocument().View()->SetTracksRasterInvalidations(false);

  // Resize the container.
  GetDocument().View()->SetTracksRasterInvalidations(true);
  target->setAttribute(html_names::kStyleAttr, AtomicString("height: 200px"));
  UpdateAllLifecyclePhasesForTest();
  // Border invalidated in the container layer.
  EXPECT_THAT(container_raster_invalidation_tracking()->Invalidations(),
              UnorderedElementsAre(RasterInvalidationInfo{
                  target_obj->Id(), target_obj->DebugName(),
                  gfx::Rect(0, 0, 70, 220), PaintInvalidationReason::kLayout}));
  // No invalidation on scrolling contents for container resize.
  EXPECT_FALSE(contents_raster_invalidation_tracking()->HasInvalidations());
  GetDocument().View()->SetTracksRasterInvalidations(false);
}

TEST_P(PaintAndRasterInvalidationTest,
       NonCompositedBackgroundAttachmentLocalResize) {
  SetUpHTML(*this);
  Element* target = GetDocument().getElementById(AtomicString("target"));
  auto* object = target->GetLayoutBox();
  target->setAttribute(html_names::kClassAttr,
                       AtomicString("translucent local-attachment scroll"));
  target->setInnerHTML(
      "<div id=child style='width: 500px; height: 500px'></div>",
      ASSERT_NO_EXCEPTION);
  Element* child = GetDocument().getElementById(AtomicString("child"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(kBackgroundPaintInContentsSpace,
            object->GetBackgroundPaintLocation());

  // Resize the content.
  GetDocument().View()->SetTracksRasterInvalidations(true);
  child->setAttribute(html_names::kStyleAttr,
                      AtomicString("width: 500px; height: 1000px"));
  UpdateAllLifecyclePhasesForTest();
  // No invalidation because the changed part is invisible.
  EXPECT_FALSE(GetRasterInvalidationTracking()->HasInvalidations());

  // Resize the container.
  GetDocument().View()->SetTracksRasterInvalidations(true);
  target->setAttribute(html_names::kStyleAttr, AtomicString("height: 200px"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_THAT(GetRasterInvalidationTracking()->Invalidations(),
              UnorderedElementsAre(RasterInvalidationInfo{
                  object->Id(), object->DebugName(), gfx::Rect(0, 100, 50, 100),
                  PaintInvalidationReason::kIncremental}));
  GetDocument().View()->SetTracksRasterInvalidations(false);
}

TEST_P(PaintAndRasterInvalidationTest, CompositedSolidBackgroundResize) {
  // To trigger background painting on both container and contents layer.
  // Note that the test may need update when we change the background paint
  // location rules.
  SetPreferCompositingToLCDText(false);

  SetUpHTML(*this);
  Element* target = GetDocument().getElementById(AtomicString("target"));
  target->setAttribute(html_names::kClassAttr,
                       AtomicString("solid composited scroll"));
  target->setInnerHTML(
      "<div style='width: 50px; height: 500px; background: yellow'></div>");
  UpdateAllLifecyclePhasesForTest();

  // Resize the scroller.
  GetDocument().View()->SetTracksRasterInvalidations(true);
  target->setAttribute(html_names::kStyleAttr, AtomicString("width: 100px"));
  UpdateAllLifecyclePhasesForTest();

  auto* target_object = target->GetLayoutBox();
  EXPECT_EQ(kBackgroundPaintInBothSpaces,
            target_object->GetBackgroundPaintLocation());

  const auto* contents_raster_invalidation_tracking =
      GetRasterInvalidationTracking(0, "target");
  // Only the contents layer is eligible for blink-side raster invalidation.
  EXPECT_FALSE(GetRasterInvalidationTracking(1, ""));
  const auto& client = target_object->GetScrollableArea()
                           ->GetScrollingBackgroundDisplayItemClient();
  EXPECT_THAT(contents_raster_invalidation_tracking->Invalidations(),
              UnorderedElementsAre(RasterInvalidationIn
"""


```