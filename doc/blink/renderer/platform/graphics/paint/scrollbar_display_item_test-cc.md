Response:
Let's break down the thought process for analyzing the C++ test file.

1. **Understand the Goal:** The request asks for the functionality of the C++ file, its relation to web technologies (JavaScript, HTML, CSS), examples of logical reasoning, and common usage errors. The file name `scrollbar_display_item_test.cc` strongly suggests it's testing code related to how scrollbars are displayed in the Blink rendering engine.

2. **Initial Code Scan (High-Level):** Read through the `#include` directives and the namespace declaration (`namespace blink`). This immediately tells us it's part of the Blink rendering engine and deals with graphics (`platform/graphics`). The `testing/gtest/include/gtest/gtest.h` include indicates it's using Google Test for unit testing.

3. **Identify the Core Class Under Test:** The name of the test fixture, `ScrollbarDisplayItemTest`, and the fact that most tests create a `ScrollbarDisplayItem` object point to this class as the central focus.

4. **Analyze Helper Functions:** The `protected` section defines `ScrollbarElementId` and `ScrollElementId`. These functions clearly deal with identifying scrollbar and scrollable elements within the compositor (the part of Chrome that handles rendering). The `CreateScrollState` function seems to set up a basic scrollable area for testing. These helper functions provide context for how the `ScrollbarDisplayItem` interacts with the broader rendering pipeline.

5. **Examine Individual Test Cases:** Go through each `TEST_F` function one by one.

   * **`HorizontalSolidColorScrollbar` and `VerticalSolidColorScrollbar`:** These tests focus on creating `ScrollbarDisplayItem` for solid-color scrollbars (the kind you see with a simple, consistent color). They check properties like the layer type (`kSolidColor`), bounds, offset, orientation, thumb thickness, and track start. They verify that the correct `cc::SolidColorScrollbarLayer` is created and its attributes are set correctly.

   * **`PaintedScrollbar`:** This test handles scrollbars that are "painted," meaning they can have more complex visual styles defined by CSS. It checks that a `cc::PaintedScrollbarLayer` is created when the scrollbar isn't a simple solid color. It also verifies basic properties like bounds and offset.

   * **`PaintedScrollbarOverlayNonNinePatch` and `PaintedScrollbarOverlayNinePatch`:** These tests deal with *overlay* scrollbars (those that appear on top of the content, often semi-transparent). They specifically differentiate between scrollbars that use "nine-patch" images (a technique for resizing images without distortion) and those that don't. They assert the correct layer type is created (`kPaintedScrollbarLayer` or `kNinePatchThumbScrollbarLayer`).

   * **`CreateOrReuseLayer`:** This is a crucial test for performance and correctness. It verifies that if the same scrollbar is used in multiple `ScrollbarDisplayItem` objects, the *same* underlying layer object is reused. This avoids unnecessary layer creation and improves efficiency. It also tests scenarios where a *new* layer should be created (different scrollbar, or a change in the scrollbar's properties like `is_left_side_vertical_scrollbar`).

6. **Identify Relationships to Web Technologies:**

   * **CSS:** The concept of "solid color" vs. "painted" scrollbars directly relates to CSS styling of scrollbars. CSS properties like `::-webkit-scrollbar-thumb`, `::-webkit-scrollbar-track`, and vendor prefixes allow web developers to customize scrollbar appearance. The nine-patch handling also connects to CSS background images and how they are stretched. Overlay scrollbars are a style often controlled by CSS.
   * **HTML:**  While not directly creating HTML elements, the scrollbars are rendered in response to content that overflows its container in the HTML structure. The presence of scrollbars is a consequence of how the HTML content and CSS layout interact.
   * **JavaScript:** JavaScript can trigger scrolling actions (e.g., `element.scrollTo()`), which indirectly involves the rendering and updating of scrollbars. JavaScript could also potentially interact with custom scrollbar implementations, although this test focuses on the browser's built-in rendering.

7. **Logical Reasoning and Examples:**

   * **Assumption:** The test assumes that the `cc::FakeScrollbar` accurately simulates the behavior of a real `cc::Scrollbar`.
   * **Input/Output:**  The tests demonstrate clear input (setting properties of the `cc::FakeScrollbar`, the `scrollbar_rect`, and the `scroll_state`) and expected output (the type and properties of the created `cc::Layer` object).

8. **Common Usage Errors:** Think about what developers might do wrong when dealing with scrollbars or related concepts:

   * **Incorrectly assuming overlay scrollbar behavior:** Developers might expect overlay scrollbars to always behave the same way across browsers, but their appearance and interaction can vary.
   * **Over-styling scrollbars:**  Excessive or complex CSS scrollbar styling can sometimes lead to performance issues or unexpected visual results.
   * **Not handling different scrollbar types:**  For example, not considering the differences between solid-color and painted scrollbars when implementing custom scrollbar logic.
   * **Misunderstanding nine-patch images:**  Not using nine-patch images correctly for resizable elements can lead to visual artifacts.

9. **Structure and Refine:** Organize the findings into the requested categories: functionality, web technology relationships, logical reasoning, and usage errors. Ensure the explanations are clear and concise, using specific examples from the code where possible. Review for accuracy and completeness.

This systematic approach allows for a thorough understanding of the C++ test file and its implications within the broader context of a web browser rendering engine.
这个C++文件 `scrollbar_display_item_test.cc` 是 Chromium Blink 引擎中的一个测试文件，专门用来测试 `ScrollbarDisplayItem` 类的功能。 `ScrollbarDisplayItem` 负责创建和管理用于在渲染过程中绘制滚动条的显示项（Display Items）。显示项是 Blink 渲染引擎中用于记录绘制操作的一种数据结构。

**主要功能:**

1. **测试 `ScrollbarDisplayItem` 的创建:**  测试文件会创建不同类型的 `ScrollbarDisplayItem` 对象，模拟各种滚动条的场景，例如水平滚动条、垂直滚动条、实色滚动条、绘制型滚动条（painted scrollbar）、覆盖型滚动条（overlay scrollbar）等。

2. **测试 `CreateOrReuseLayer` 方法:**  这个方法是 `ScrollbarDisplayItem` 的核心功能之一，它负责创建或重用用于渲染滚动条的 Layer 对象（在 Chromium 的 Compositor 线程中使用的图层）。测试会验证在不同情况下，`CreateOrReuseLayer` 是否能正确创建或重用合适的 Layer 对象，例如：
   -  首次创建 Layer。
   -  重用已存在的 Layer（当 `ScrollbarDisplayItem` 对象相同且滚动条对象也相同时）。
   -  创建新的 Layer（当滚动条对象不同时，或者滚动条的某些属性发生变化时）。

3. **验证 Layer 对象的属性:** 测试会检查创建的 Layer 对象的属性是否符合预期，例如：
   - **Layer 类型 (`GetScrollbarLayerType()`):**  验证是否创建了正确的滚动条 Layer 类型，例如 `cc::SolidColorScrollbarLayer` 用于实色滚动条， `cc::PaintedScrollbarLayer` 或 `cc::NinePatchThumbScrollbarLayer` 用于绘制型滚动条。
   - **边界 (`bounds()`):** 验证 Layer 的尺寸是否与滚动条的尺寸一致。
   - **偏移量 (`offset_to_transform_parent()`):** 验证 Layer 相对于其父 Layer 的偏移量是否正确。
   - **滚动条方向 (`orientation()`):** 验证滚动条是水平还是垂直。
   - **拇指粗细 (`thumb_thickness()`):**  验证实色滚动条 Layer 的拇指粗细是否正确。
   - **轨道起始位置 (`track_start()`):** 验证实色滚动条 Layer 的轨道起始位置是否正确。
   - **元素 ID (`element_id()`):** 验证 Layer 关联的元素 ID 是否正确。
   - **滚动元素 ID (`scroll_element_id()`):** 验证 Layer 关联的滚动容器的元素 ID 是否正确。
   - **命中测试不透明度 (`hit_test_opaqueness()`):** 验证滚动条的命中测试属性是否正确。

**与 JavaScript, HTML, CSS 的关系：**

`ScrollbarDisplayItem` 本身是一个底层的渲染概念，直接与 JavaScript, HTML, CSS 的交互并不多，但它是实现这些 Web 技术中滚动条显示的关键部分。

* **CSS:**
    - **滚动条样式:** CSS 属性（特别是带有 `-webkit-` 前缀的属性，如 `::-webkit-scrollbar`, `::-webkit-scrollbar-thumb`, `::-webkit-scrollbar-track` 等）允许开发者自定义滚动条的外观，包括颜色、尺寸、形状等。`ScrollbarDisplayItem` 会根据这些 CSS 样式信息来决定创建哪种类型的 Layer 对象（例如，如果指定了背景图片，则可能创建 `PaintedScrollbarLayer` 或 `NinePatchThumbScrollbarLayer`）。
    - **覆盖型滚动条:** CSS 可以设置滚动条为覆盖型（overlay），这意味着滚动条会绘制在内容之上，而不是占用布局空间。测试中的 `scrollbar->set_is_overlay(true)` 模拟了这种 CSS 设置。

    **举例说明:**

    ```css
    /* 自定义滚动条样式 */
    ::-webkit-scrollbar {
      width: 10px;
      height: 10px;
    }

    ::-webkit-scrollbar-thumb {
      background-color: blue;
      border-radius: 5px;
    }

    ::-webkit-scrollbar-track {
      background-color: lightgray;
    }

    /* 设置为覆盖型滚动条 */
    .scrollable-container {
      overflow: auto;
      scrollbar-width: thin; /* 一种设置覆盖型滚动条的方式 */
    }
    ```

    当浏览器渲染带有这些 CSS 样式的页面时，Blink 引擎会创建相应的 `ScrollbarDisplayItem`，并根据样式信息设置其属性，最终影响 Layer 对象的创建和属性。

* **HTML:**
    - **滚动容器:** HTML 元素可以通过 CSS 的 `overflow` 属性（如 `auto`, `scroll`) 变为滚动容器。当内容超出滚动容器的大小时，浏览器会显示滚动条。`ScrollbarDisplayItem` 就是为了渲染这些滚动条而存在的。

    **举例说明:**

    ```html
    <div class="scrollable-container">
      <!-- 大量内容，超出容器大小 -->
      <p>This is some long content...</p>
      ...
    </div>
    ```

    当渲染这个 `div` 元素时，如果内容溢出，Blink 会创建 `ScrollbarDisplayItem` 来绘制相应的滚动条。

* **JavaScript:**
    - **滚动操作:** JavaScript 可以通过修改元素的 `scrollTop` 和 `scrollLeft` 属性来控制滚动。虽然 JavaScript 不直接创建 `ScrollbarDisplayItem`，但当 JavaScript 触发滚动时，滚动条的位置和状态会发生变化，这会导致相关的 `ScrollbarDisplayItem` 和 Layer 对象进行更新和重新绘制。

    **举例说明:**

    ```javascript
    const container = document.querySelector('.scrollable-container');
    container.scrollTop = 100; // 滚动到垂直方向的 100px 位置
    ```

    执行这段 JavaScript 代码后，滚动条的位置会更新，Blink 引擎会相应地更新 `ScrollbarDisplayItem` 和 Layer 的状态，以反映新的滚动位置。

**逻辑推理和假设输入与输出：**

测试文件中的每个 `TEST_F` 都是一个独立的逻辑推理过程，它基于一些假设的输入（例如，滚动条的属性、滚动容器的状态），并验证预期的输出（例如，创建的 Layer 对象的类型和属性）。

**示例 1：`HorizontalSolidColorScrollbar` 测试**

* **假设输入:**
    - 滚动条方向：水平 (`cc::ScrollbarOrientation::kHorizontal`)
    - 滚动条类型：实色 (`scrollbar->set_is_solid_color(true)`)
    - 滚动条是否覆盖：是 (`scrollbar->set_is_overlay(true)`)
    - 轨道矩形：`gfx::Rect(2, 90, 96, 10)`
    - 拇指尺寸：`gfx::Size(30, 7)`
    - 滚动容器的 Transform 状态 (`scroll_state`)

* **预期输出:**
    - 创建的 Layer 类型为 `cc::SolidColorScrollbarLayer`。
    - Layer 的边界为 `gfx::Size(100, 10)`。
    - Layer 相对于父节点的偏移量为 `gfx::Vector2dF(10, 110)` (首次创建) 和 `gfx::Vector2dF(30, 130)` (重用)。
    - Layer 的滚动条方向为水平 (`cc::ScrollbarOrientation::kHorizontal`)。
    - Layer 的拇指粗细为 `7`。
    - Layer 的轨道起始位置为 `2`。
    - Layer 的元素 ID 与滚动条的元素 ID 一致。
    - Layer 的滚动元素 ID 与滚动容器的元素 ID 一致。

**示例 2：`CreateOrReuseLayer` 测试**

* **假设输入 (第一次调用 `CreateOrReuseLayer`):**
    - 一个新的 `ScrollbarDisplayItem` 对象 (`display_item1a`)
    - 一个新的 `cc::FakeScrollbar` 对象 (`scrollbar1`)
    - 一个 `nullptr` 的现有 Layer 指针。

* **预期输出 (第一次调用 `CreateOrReuseLayer`):**
    - 创建一个新的 Layer 对象 (`layer1`)。
    - `layer1` 的属性根据 `scrollbar1` 的属性和 `ScrollbarDisplayItem` 的其他参数进行设置。

* **假设输入 (第二次调用 `CreateOrReuseLayer`):**
    - 另一个 `ScrollbarDisplayItem` 对象 (`display_item1b`)，但使用相同的 `scrollbar1` 对象。
    - 上一次创建的 Layer 对象指针 (`layer1`)。

* **预期输出 (第二次调用 `CreateOrReuseLayer`):**
    - **重用** 之前创建的 Layer 对象 (`layer1`)。
    - `layer1` 的某些属性（例如，偏移量）可能会根据新的 `ScrollbarDisplayItem` 的状态进行更新，但 Layer 对象本身不会被销毁和重新创建。

* **假设输入 (第三次调用 `CreateOrReuseLayer`):**
    - 一个新的 `ScrollbarDisplayItem` 对象 (`display_item2`)
    - 一个新的 `cc::FakeScrollbar` 对象 (`scrollbar2`)
    - 之前的 Layer 对象指针 (`layer1`)。

* **预期输出 (第三次调用 `CreateOrReuseLayer`):**
    - 创建一个 **新的** Layer 对象，因为它关联的滚动条对象不同。
    - 新的 Layer 对象与之前的 `layer1` 对象不同 (`EXPECT_NE(layer1, ...)`）。

**用户或编程常见的使用错误：**

虽然这个测试文件是针对 Blink 内部实现的，但它可以帮助理解一些与滚动条相关的常见误解或使用错误：

1. **错误地假设所有滚动条都是相同的：**  开发者可能会忘记考虑不同类型的滚动条（例如，实色 vs. 绘制型，覆盖型 vs. 非覆盖型）在渲染方式和性能上的差异。Blink 引擎会根据滚动条的属性和样式选择不同的 Layer 类型进行渲染。

2. **过度或不必要地重新创建滚动条相关的对象：**  `CreateOrReuseLayer` 测试强调了 Layer 对象的重用。在编程中，如果频繁地销毁和重新创建滚动条或相关的渲染对象，可能会导致性能问题。Blink 引擎通过 Display Item 和 Layer 机制来优化渲染过程，避免不必要的资源分配和释放。

3. **没有正确理解覆盖型滚动条的布局影响：**  覆盖型滚动条不会占用布局空间，这与传统的滚动条不同。开发者在布局设计时需要考虑到这一点，避免内容被覆盖。

4. **错误地假设滚动条的样式和行为在所有浏览器中完全一致：**  虽然 CSS 提供了滚动条样式化的能力，但不同浏览器（特别是不同内核的浏览器）对滚动条的实现和样式支持可能存在差异。测试文件中的 `-webkit-` 前缀就暗示了某些特性是 WebKit 或 Blink 特有的。

**总结：**

`scrollbar_display_item_test.cc` 是一个重要的测试文件，它确保了 Blink 引擎中 `ScrollbarDisplayItem` 类的正确性和性能。通过测试创建和管理滚动条 Layer 对象的各种场景，它验证了 Blink 引擎能够根据不同的滚动条属性和状态，生成正确的渲染指令。虽然它是一个底层的测试文件，但它所测试的功能直接支撑了 Web 页面中滚动条的渲染，与 CSS 样式、HTML 结构以及 JavaScript 的滚动操作密切相关。理解这些测试用例可以帮助开发者更好地理解浏览器如何渲染滚动条，从而避免一些常见的误解和错误。

### 提示词
```
这是目录为blink/renderer/platform/graphics/paint/scrollbar_display_item_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/graphics/paint/scrollbar_display_item.h"

#include "cc/layers/solid_color_scrollbar_layer.h"
#include "cc/test/fake_scrollbar.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/graphics/paint/scroll_paint_property_node.h"
#include "third_party/blink/renderer/platform/testing/fake_display_item_client.h"
#include "third_party/blink/renderer/platform/testing/paint_property_test_helpers.h"

namespace blink {

class ScrollbarDisplayItemTest : public testing::Test {
 protected:
  static CompositorElementId ScrollbarElementId(
      const cc::Scrollbar& scrollbar) {
    return CompositorElementIdFromUniqueObjectId(
        13579, scrollbar.Orientation() == cc::ScrollbarOrientation::kHorizontal
                   ? CompositorElementIdNamespace::kHorizontalScrollbar
                   : CompositorElementIdNamespace::kVerticalScrollbar);
  }

  static CompositorElementId ScrollElementId(const PropertyTreeState& state) {
    return state.Transform().ScrollNode()->GetCompositorElementId();
  }

  static PropertyTreeState CreateScrollState() {
    return CreateScrollTranslationState(PropertyTreeState::Root(), 0, 0,
                                        gfx::Rect(0, 0, 100, 100),
                                        gfx::Size(1000, 1000));
  }
};

TEST_F(ScrollbarDisplayItemTest, HorizontalSolidColorScrollbar) {
  auto scroll_state = CreateScrollState();
  auto scrollbar = base::MakeRefCounted<cc::FakeScrollbar>();
  scrollbar->set_orientation(cc::ScrollbarOrientation::kHorizontal);
  scrollbar->set_is_solid_color(true);
  scrollbar->set_is_overlay(true);
  scrollbar->set_track_rect(gfx::Rect(2, 90, 96, 10));
  scrollbar->set_thumb_size(gfx::Size(30, 7));

  FakeDisplayItemClient& client =
      *MakeGarbageCollected<FakeDisplayItemClient>();
  gfx::Rect scrollbar_rect(0, 90, 100, 10);
  auto element_id = ScrollbarElementId(*scrollbar);
  ScrollbarDisplayItem display_item(
      client.Id(), DisplayItem::kScrollbarHorizontal, scrollbar, scrollbar_rect,
      &scroll_state.Transform(), element_id,
      cc::HitTestOpaqueness::kTransparent,
      client.VisualRectOutsetForRasterEffects());
  auto layer = display_item.CreateOrReuseLayer(nullptr, gfx::Vector2dF(10, 20));
  ASSERT_EQ(cc::ScrollbarLayerBase::kSolidColor,
            layer->GetScrollbarLayerType());
  EXPECT_EQ(cc::HitTestOpaqueness::kTransparent, layer->hit_test_opaqueness());

  auto* scrollbar_layer =
      static_cast<cc::SolidColorScrollbarLayer*>(layer.get());
  EXPECT_EQ(gfx::Size(100, 10), scrollbar_layer->bounds());
  EXPECT_EQ(gfx::Vector2dF(10, 110),
            scrollbar_layer->offset_to_transform_parent());
  EXPECT_EQ(cc::ScrollbarOrientation::kHorizontal,
            scrollbar_layer->orientation());
  EXPECT_EQ(7, scrollbar_layer->thumb_thickness());
  EXPECT_EQ(2, scrollbar_layer->track_start());
  EXPECT_EQ(element_id, scrollbar_layer->element_id());
  EXPECT_EQ(ScrollElementId(scroll_state),
            scrollbar_layer->scroll_element_id());

  EXPECT_EQ(layer, display_item.CreateOrReuseLayer(layer.get(),
                                                   gfx::Vector2dF(30, 40)));
  EXPECT_EQ(gfx::Size(100, 10), scrollbar_layer->bounds());
  EXPECT_EQ(gfx::Vector2dF(30, 130),
            scrollbar_layer->offset_to_transform_parent());
}

TEST_F(ScrollbarDisplayItemTest, VerticalSolidColorScrollbar) {
  auto scroll_state = CreateScrollState();
  auto scrollbar = base::MakeRefCounted<cc::FakeScrollbar>();
  scrollbar->set_orientation(cc::ScrollbarOrientation::kVertical);
  scrollbar->set_is_solid_color(true);
  scrollbar->set_is_overlay(true);
  scrollbar->set_track_rect(gfx::Rect(90, 2, 10, 96));
  scrollbar->set_thumb_size(gfx::Size(7, 30));

  FakeDisplayItemClient& client =
      *MakeGarbageCollected<FakeDisplayItemClient>();
  gfx::Rect scrollbar_rect(90, 0, 10, 100);
  auto element_id = ScrollbarElementId(*scrollbar);
  ScrollbarDisplayItem display_item(
      client.Id(), DisplayItem::kScrollbarHorizontal, scrollbar, scrollbar_rect,
      &scroll_state.Transform(), element_id,
      cc::HitTestOpaqueness::kTransparent,
      client.VisualRectOutsetForRasterEffects());
  auto layer = display_item.CreateOrReuseLayer(nullptr, gfx::Vector2dF(10, 20));
  ASSERT_EQ(cc::ScrollbarLayerBase::kSolidColor,
            layer->GetScrollbarLayerType());
  EXPECT_EQ(cc::HitTestOpaqueness::kTransparent, layer->hit_test_opaqueness());

  auto* scrollbar_layer =
      static_cast<cc::SolidColorScrollbarLayer*>(layer.get());
  EXPECT_EQ(gfx::Size(10, 100), scrollbar_layer->bounds());
  EXPECT_EQ(gfx::Vector2dF(100, 20),
            scrollbar_layer->offset_to_transform_parent());
  EXPECT_EQ(cc::ScrollbarOrientation::kVertical,
            scrollbar_layer->orientation());
  EXPECT_EQ(7, scrollbar_layer->thumb_thickness());
  EXPECT_EQ(2, scrollbar_layer->track_start());
  EXPECT_EQ(element_id, scrollbar_layer->element_id());
  EXPECT_EQ(ScrollElementId(scroll_state),
            scrollbar_layer->scroll_element_id());

  EXPECT_EQ(layer, display_item.CreateOrReuseLayer(layer.get(),
                                                   gfx::Vector2dF(30, 40)));
  EXPECT_EQ(gfx::Size(10, 100), scrollbar_layer->bounds());
  EXPECT_EQ(gfx::Vector2dF(120, 40),
            scrollbar_layer->offset_to_transform_parent());
}

TEST_F(ScrollbarDisplayItemTest, PaintedScrollbar) {
  auto scroll_state = CreateScrollState();
  auto scrollbar = base::MakeRefCounted<cc::FakeScrollbar>();

  FakeDisplayItemClient& client =
      *MakeGarbageCollected<FakeDisplayItemClient>();
  gfx::Rect scrollbar_rect(0, 90, 100, 10);
  auto element_id = ScrollbarElementId(*scrollbar);
  ScrollbarDisplayItem display_item(
      client.Id(), DisplayItem::kScrollbarHorizontal, scrollbar, scrollbar_rect,
      &scroll_state.Transform(), element_id, cc::HitTestOpaqueness::kOpaque,
      client.VisualRectOutsetForRasterEffects());
  auto layer = display_item.CreateOrReuseLayer(nullptr, gfx::Vector2dF(10, 20));
  EXPECT_EQ(gfx::Size(100, 10), layer->bounds());
  EXPECT_EQ(gfx::Vector2dF(10, 110), layer->offset_to_transform_parent());
  ASSERT_EQ(cc::ScrollbarLayerBase::kPainted, layer->GetScrollbarLayerType());
  EXPECT_EQ(cc::HitTestOpaqueness::kOpaque, layer->hit_test_opaqueness());

  EXPECT_EQ(layer, display_item.CreateOrReuseLayer(layer.get(),
                                                   gfx::Vector2dF(30, 40)));
  EXPECT_EQ(gfx::Size(100, 10), layer->bounds());
  EXPECT_EQ(gfx::Vector2dF(30, 130), layer->offset_to_transform_parent());
}

TEST_F(ScrollbarDisplayItemTest, PaintedScrollbarOverlayNonNinePatch) {
  auto scroll_state = CreateScrollState();
  auto scrollbar = base::MakeRefCounted<cc::FakeScrollbar>();
  scrollbar->set_has_thumb(true);
  scrollbar->set_is_overlay(true);

  FakeDisplayItemClient& client =
      *MakeGarbageCollected<FakeDisplayItemClient>();
  gfx::Rect scrollbar_rect(0, 90, 100, 10);
  auto element_id = ScrollbarElementId(*scrollbar);
  ScrollbarDisplayItem display_item(
      client.Id(), DisplayItem::kScrollbarHorizontal, scrollbar, scrollbar_rect,
      &scroll_state.Transform(), element_id, cc::HitTestOpaqueness::kOpaque,
      client.VisualRectOutsetForRasterEffects());
  auto layer = display_item.CreateOrReuseLayer(nullptr, gfx::Vector2dF());
  // We should create PaintedScrollbarLayer instead of
  // NinePatchThumbScrollbarLayer for non-nine-patch overlay scrollbars.
  ASSERT_EQ(cc::ScrollbarLayerBase::kPainted, layer->GetScrollbarLayerType());
  EXPECT_EQ(cc::HitTestOpaqueness::kOpaque, layer->hit_test_opaqueness());

  EXPECT_EQ(layer,
            display_item.CreateOrReuseLayer(layer.get(), gfx::Vector2dF()));
}

TEST_F(ScrollbarDisplayItemTest, PaintedScrollbarOverlayNinePatch) {
  auto scroll_state = CreateScrollState();
  auto scrollbar = base::MakeRefCounted<cc::FakeScrollbar>();
  scrollbar->set_has_thumb(true);
  scrollbar->set_is_overlay(true);
  scrollbar->set_uses_nine_patch_thumb_resource(true);

  FakeDisplayItemClient& client =
      *MakeGarbageCollected<FakeDisplayItemClient>();
  gfx::Rect scrollbar_rect(0, 90, 100, 10);
  auto element_id = ScrollbarElementId(*scrollbar);
  ScrollbarDisplayItem display_item(
      client.Id(), DisplayItem::kScrollbarHorizontal, scrollbar, scrollbar_rect,
      &scroll_state.Transform(), element_id, cc::HitTestOpaqueness::kOpaque,
      client.VisualRectOutsetForRasterEffects());
  auto layer = display_item.CreateOrReuseLayer(nullptr, gfx::Vector2dF());
  ASSERT_EQ(cc::ScrollbarLayerBase::kNinePatchThumb,
            layer->GetScrollbarLayerType());
  EXPECT_EQ(cc::HitTestOpaqueness::kOpaque, layer->hit_test_opaqueness());

  EXPECT_EQ(layer,
            display_item.CreateOrReuseLayer(layer.get(), gfx::Vector2dF()));
}

TEST_F(ScrollbarDisplayItemTest, CreateOrReuseLayer) {
  auto scroll_state = CreateScrollState();
  auto scrollbar1 = base::MakeRefCounted<cc::FakeScrollbar>();

  FakeDisplayItemClient& client =
      *MakeGarbageCollected<FakeDisplayItemClient>();
  gfx::Rect scrollbar_rect(0, 90, 100, 10);
  auto element_id = ScrollbarElementId(*scrollbar1);
  ScrollbarDisplayItem display_item1a(
      client.Id(), DisplayItem::kScrollbarHorizontal, scrollbar1,
      scrollbar_rect, &scroll_state.Transform(), element_id,
      cc::HitTestOpaqueness::kOpaque,
      client.VisualRectOutsetForRasterEffects());
  auto layer1 =
      display_item1a.CreateOrReuseLayer(nullptr, gfx::Vector2dF(10, 20));
  EXPECT_EQ(gfx::Size(100, 10), layer1->bounds());
  EXPECT_EQ(gfx::Vector2dF(10, 110), layer1->offset_to_transform_parent());

  ScrollbarDisplayItem display_item1b(
      client.Id(), DisplayItem::kScrollbarHorizontal, scrollbar1,
      scrollbar_rect, &scroll_state.Transform(), element_id,
      cc::HitTestOpaqueness::kOpaque,
      client.VisualRectOutsetForRasterEffects());
  // Should reuse layer for a different display item and the same scrollbar.
  EXPECT_EQ(layer1, display_item1b.CreateOrReuseLayer(layer1.get(),
                                                      gfx::Vector2dF(30, 40)));
  EXPECT_EQ(gfx::Size(100, 10), layer1->bounds());
  EXPECT_EQ(gfx::Vector2dF(30, 130), layer1->offset_to_transform_parent());

  auto scrollbar2 = base::MakeRefCounted<cc::FakeScrollbar>();
  ScrollbarDisplayItem display_item2(
      client.Id(), DisplayItem::kScrollbarHorizontal, scrollbar2,
      scrollbar_rect, &scroll_state.Transform(), element_id,
      cc::HitTestOpaqueness::kOpaque,
      client.VisualRectOutsetForRasterEffects());
  // Should create new layer for a different scrollbar.
  EXPECT_NE(layer1,
            display_item2.CreateOrReuseLayer(layer1.get(), gfx::Vector2dF()));

  ASSERT_FALSE(scrollbar1->IsLeftSideVerticalScrollbar());
  scrollbar1->set_is_left_side_vertical_scrollbar(true);
  // Should create new layer for changed is_left_side_vertical_scrollbar of
  // the same scrollbar.
  EXPECT_NE(layer1,
            display_item1a.CreateOrReuseLayer(layer1.get(), gfx::Vector2dF()));

  ScrollbarDisplayItem display_item1c(
      client.Id(), DisplayItem::kScrollbarHorizontal, scrollbar1,
      scrollbar_rect, &scroll_state.Transform(), element_id,
      cc::HitTestOpaqueness::kOpaque,
      client.VisualRectOutsetForRasterEffects());
  // Should reuse layer for a different display item and the same scrollbar.
  EXPECT_NE(layer1,
            display_item1b.CreateOrReuseLayer(layer1.get(), gfx::Vector2dF()));
}

}  // namespace blink
```