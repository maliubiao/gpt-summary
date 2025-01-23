Response:
Let's break down the thought process for analyzing the provided C++ test file.

**1. Initial Understanding - The Big Picture:**

* **File Name:** `caret_display_item_client_test.cc` immediately tells us it's a test file related to the `CaretDisplayItemClient`. This likely deals with how the text cursor (caret) is displayed and managed in the rendering process.
* **Chromium/Blink:**  The file path `blink/renderer/core/...` confirms it's part of the Blink rendering engine within Chromium. This means it's concerned with low-level details of web page rendering.
* **`_test.cc` Suffix:** Standard practice in C++ projects indicates this file contains unit or integration tests.
* **Includes:**  The included headers give clues about the functionality being tested. We see things like:
    * `caret_display_item_client.h`: The core class being tested.
    * `frame_caret.h`, `frame_selection.h`:  Related to text selection and cursor management.
    * `layout_view.h`, `layout_block.h`, `inline_cursor.h`:  Involved in the layout and positioning of elements.
    * `paint/...`:  Related to the painting and rendering process.
    * `testing/gmock/...`:  Using Google Mock for writing assertions and expectations in the tests.
    * `platform/testing/...`:  Blink-specific testing utilities.

**2. Deeper Dive - Key Components and Functionality:**

* **`CaretDisplayItemClient`:** The central piece. It likely manages the visual representation of the caret (its position, size, visibility). The "Display Item" part suggests it's part of the rendering pipeline.
* **`FrameCaret`:**  A higher-level object that manages the caret's logical state (position in the document, visibility rules, blinking). The `CaretDisplayItemClient` is likely a component *of* `FrameCaret`.
* **`FrameSelection`:** Handles the currently selected text range. The caret's position is often linked to the selection.
* **Layout Objects (`LayoutBlock`, `LayoutText`):** Represent the rendered structure of the HTML elements. The caret's position is relative to these layout objects.
* **Paint System:** The tests frequently interact with the paint system (e.g., `UpdateAllLifecyclePhasesForCaretTest`, checking for `cc::Layer`s). This means the tests verify that the caret is rendered correctly and invalidations are happening when needed.
* **Focus:**  The tests often involve focusing elements (`GetDocument().body()->Focus();`). The caret is typically only visible when an element is focused and editable.
* **`contenteditable`:**  A key attribute for making elements editable, thus enabling the display of a caret.

**3. Analyzing the Tests (Pattern Recognition):**

* **Test Structure:** The tests generally follow a pattern:
    1. **Setup:** Create a test environment (e.g., set `contenteditable`, focus elements, append HTML).
    2. **Action:** Perform an action that should affect the caret (e.g., move the selection, insert text, change styles, scroll).
    3. **Assertion:** Verify the expected outcome using `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_EQ`, `ASSERT_CARET_LAYER()`, etc. These assertions often check:
        * Caret position (`CaretLocalRect()`).
        * Visibility (`ShouldPaintCursorCaret()`).
        * Invalidation status (`GetCaretDisplayItemClient().IsValid()`).
        * Presence of the caret layer (`CaretLayer()`).
        * Previous layout block (`PreviousCaretLayoutBlock()`).

* **Common Test Scenarios:**  The tests cover various scenarios related to caret behavior:
    * **Basic movement:** Moving the caret within a text node and between blocks.
    * **Paint invalidation:** Ensuring the caret is repainted when its position or visibility changes.
    * **Blinking:** Testing the blinking behavior and that it doesn't cause unnecessary repaints.
    * **Compositing:** How changes in compositing affect the caret's rendering.
    * **Right-to-Left (RTL) text:** Ensuring the caret is positioned correctly in RTL text.
    * **`white-space: pre-wrap`:** Handling caret positioning in elements with pre-wrap.
    * **Edges of inline blocks:**  Positioning the caret at the boundaries of inline-block elements.
    * **Full document painting:**  Verifying the caret is included in the display item list during painting.
    * **Edge cases:**  Scenarios like caret after ellipsis or near non-editable content.

**4. Connecting to Web Technologies (JavaScript, HTML, CSS):**

* **HTML:** The tests directly manipulate the DOM using methods like `AppendTextNode`, `AppendBlock`, `SetBodyInnerHTML`. The `contenteditable` attribute is crucial for enabling caret display.
* **CSS:** Styles are used to influence the layout and rendering of elements, which in turn affects caret positioning. Examples include setting `width`, `padding`, `font`, `white-space`, `unicode-bidi`, and `will-change`.
* **JavaScript (Indirectly):** While the tests are in C++, the underlying functionality being tested is what makes interactive web pages work. JavaScript APIs like `document.execCommand` (used for `insertText`) and the Selection API are implemented in C++ within Blink. User interactions in a web browser (typing, clicking) trigger events that eventually lead to the code being tested.

**5. Logical Reasoning and Examples:**

* The tests often involve setting up a specific HTML structure and then simulating user actions (like moving the cursor) by manipulating the `Selection` object. The assertions then check if the `CaretDisplayItemClient` behaves as expected.

**6. Common Errors and Debugging:**

* The tests implicitly highlight potential errors. For example, if the caret isn't invalidating correctly, the tests will fail. The tests also show how to debug caret-related issues by:
    * Inspecting the caret's local rectangle (`CaretLocalRect()`).
    * Checking if the caret layer exists (`CaretLayer()`).
    * Examining which layout block the caret is associated with (`CaretLayoutBlock()`).

**7. User Actions and Debugging Clues:**

* The tests provide a map of how user actions lead to this code. Actions like:
    * Clicking to place the cursor.
    * Typing text.
    * Selecting text.
    * Focusing on an editable element.
    * Scrolling the page.
    * Applying CSS styles.

These user actions trigger events that propagate through the browser, eventually reaching the Blink rendering engine where the `CaretDisplayItemClient` plays a role.

By following this structured approach, we can effectively dissect the provided C++ test file and understand its purpose, its relation to web technologies, and how it contributes to the overall functionality of a web browser.这个文件 `blink/renderer/core/editing/caret_display_item_client_test.cc` 是 Chromium Blink 渲染引擎中的一个测试文件，专门用于测试 `CaretDisplayItemClient` 类的功能。`CaretDisplayItemClient` 负责管理和渲染文本光标（caret）。

**功能概括:**

该测试文件的主要功能是验证 `CaretDisplayItemClient` 在各种场景下是否能正确地：

1. **创建和销毁光标的渲染对象 (Display Item)。**
2. **确定光标的绘制位置和大小。**
3. **在光标位置发生变化时触发重绘。**
4. **处理光标的显示和隐藏（包括闪烁）。**
5. **处理与布局对象 (LayoutObject) 的关联。**
6. **处理在不同布局块 (LayoutBlock) 之间移动光标。**
7. **处理因元素属性变化（例如 `contenteditable`，`will-change`）导致的光标更新。**
8. **处理不同书写模式 (例如 RTL - 从右到左) 下的光标位置。**
9. **确保光标在特定情况下（例如在 `white-space: pre-wrap` 的元素中）的正确行为。**
10. **处理与合成层 (Compositing Layer) 的交互。**
11. **验证光标是否参与完整的文档绘制流程。**
12. **处理光标在不可编辑元素附近的行为。**

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个测试文件虽然是用 C++ 编写，但它测试的功能直接关系到网页的显示和用户交互，因此与 JavaScript、HTML 和 CSS 都有密切联系。

* **HTML (`contenteditable`):**
    * **例子:** 测试用例中大量使用了 `GetDocument().body()->setContentEditable("true", ASSERT_NO_EXCEPTION);`，这模拟了用户在 HTML 中设置了 `contenteditable` 属性，使得元素可以编辑，从而需要显示光标。
    * **说明:** `contenteditable` 属性决定了元素是否可以接收用户的文本输入，从而决定是否需要显示光标。测试验证了当 `contenteditable` 状态改变时，光标是否能正确地显示或隐藏。

* **CSS (`white-space`, `unicode-bidi`, `will-change`, `text-overflow`):**
    * **`white-space: pre-wrap` 和 `unicode-bidi: plaintext`:**  测试用例 `InsertSpaceToWhiteSpacePreWrapRTL` 和 `InsertSpaceToWhiteSpacePreWrap` 使用了这些 CSS 属性来模拟在保留空格和处理双向文本的场景下光标的位置。
        * **假设输入:** 一个 `div` 元素设置了 `white-space: pre-wrap` 和 `unicode-bidi: plaintext`，并且包含一些文本。用户在文本末尾插入空格。
        * **预期输出:** 光标应该移动到正确的空格之后的位置。
    * **`will-change: transform`:** 测试用例 `CompositingChange` 使用了 `will-change` 属性来触发元素的合成。
        * **假设输入:** 一个包含可编辑元素的 `div`，然后给父元素设置 `will-change: transform`。
        * **预期输出:** 光标的渲染应该不受合成状态变化的影响，依然显示在正确的位置。
    * **`text-overflow: ellipsis`:** 测试用例 `CaretRectAfterEllipsisNoCrash` 模拟了在文本溢出并显示省略号的情况下光标的定位。
        * **假设输入:** 一个 `pre` 元素设置了 `text-overflow: ellipsis`，文本内容超出宽度。
        * **预期输出:**  测试主要关注是否会崩溃，而不是具体的坐标，因为省略号情况下的光标位置可能比较复杂。
    * **`direction: rtl` (通过 `dir='rtl'` 属性模拟):**  测试用例 `PlainTextRTLCaretPosition` 和 `CaretAtStartInWhiteSpacePreWrapRTL` 模拟了在 RTL 语言环境下光标的定位。
        * **假设输入:** 一个 `div` 元素设置了 `dir='rtl'` 并包含阿拉伯语文本。
        * **预期输出:** 光标应该出现在文本的开头（最右侧）。

* **JavaScript (通过 C++ 测试模拟):**
    * **`document.execCommand("insertText", ...)`:** 测试用例 `InsertSpaceToWhiteSpacePreWrapRTL` 和 `InsertSpaceToWhiteSpacePreWrap` 使用这个命令来模拟用户输入文本。
    * **`Selection` API (通过 `Selection()` 方法访问):** 测试用例大量使用 `Selection().SetSelection(...)` 来模拟用户通过鼠标或键盘改变光标位置。
        * **假设输入:** 用户点击或使用键盘导航将光标移动到文本的不同位置。
        * **预期输出:** `CaretDisplayItemClient` 应该根据新的光标位置更新渲染，触发必要的重绘。

**逻辑推理 (假设输入与输出):**

* **场景：光标在两个不同的 `div` 块之间移动。**
    * **假设输入:**
        1. HTML 结构包含两个可编辑的 `div` 元素（`block_element1`, `block_element2`）。
        2. 光标当前在 `block_element1` 中。
        3. 用户通过点击或键盘操作将光标移动到 `block_element2` 的开头。
    * **预期输出:**
        1. `CaretDisplayItemClient` 会检测到光标位置的改变。
        2. 之前关联的布局块 `block1` 会被标记为需要重绘（移除旧光标）。
        3. 新关联的布局块 `block2` 会被标记为需要重绘（绘制新光标）。
        4. `CaretLocalRect()` 返回的光标位置会更新为 `block_element2` 开头的坐标。
        5. `CaretLayoutBlock()` 返回指向 `block2` 的指针。
        6. `PreviousCaretLayoutBlock()` 返回指向 `block1` 的指针（在第一次移动后）。

**用户或编程常见的使用错误举例说明:**

* **用户错误:**
    * **快速连续点击导致光标位置跳跃：**  `CaretDisplayItemClient` 需要能够快速响应光标位置的变化，并确保渲染的连贯性。如果实现不当，可能会出现光标位置和渲染不同步的情况。测试用例通过模拟快速移动光标来验证这一点。
    * **在复杂的布局中光标位置不正确：** 例如，在 `position: absolute` 或 `float` 元素的边界附近，光标的定位可能会出现问题。测试用例 `CaretAtEdgeOfInlineBlock` 就关注了类似的情况。

* **编程错误:**
    * **没有正确处理光标的显示/隐藏状态：** 当元素失去焦点或 `contenteditable` 属性被移除时，光标应该被隐藏。如果 `CaretDisplayItemClient` 没有正确处理这些状态变化，可能会导致光标仍然显示。测试用例 `CaretPaintInvalidation` 中移除 selection 的部分验证了这一点。
    * **在光标位置变化时没有触发必要的重绘：** 如果 `CaretDisplayItemClient` 没有正确地标记需要重绘的区域，可能会导致光标移动后没有及时更新显示。测试用例 `CaretMovesBetweenBlocks` 和 `CaretHideMoveAndShow` 都在测试重绘机制。
    * **在 RTL 语言环境下光标定位错误：**  RTL 语言的光标定位逻辑与 LTR (从左到右) 不同，需要特殊处理。如果 `CaretDisplayItemClient` 没有正确处理，可能会导致 RTL 文本的光标显示在错误的位置。测试用例 `PlainTextRTLCaretPosition` 验证了这一点。

**用户操作是如何一步步到达这里的，作为调试线索:**

1. **用户在浏览器中打开一个网页。**
2. **网页包含一个或多个设置了 `contenteditable` 属性的元素（例如 `<div>`，`<p>`，或者设置了 `designMode` 的 `<iframe>`）。**
3. **用户点击该可编辑元素，或者使用 Tab 键将焦点移动到该元素上。**  这会触发浏览器的事件处理机制，最终会调用 Blink 引擎中与焦点管理相关的代码。
4. **当元素获得焦点时，Blink 引擎会创建或更新与该元素关联的 `FrameCaret` 对象。**
5. **`FrameCaret` 对象会使用 `CaretDisplayItemClient` 来管理光标的渲染。**
6. **如果用户在该可编辑元素中输入文本、删除文本、或者通过鼠标或键盘移动光标，都会触发 `FrameSelection` 的更新。**
7. **`FrameSelection` 的改变会通知 `FrameCaret`，进而通知 `CaretDisplayItemClient` 更新光标的渲染位置和状态。**
8. **`CaretDisplayItemClient` 会根据新的光标位置和状态，生成相应的渲染指令 (Display Items)，并触发页面的重绘。** 这些渲染指令最终会被送到 Compositor 线程进行合成和绘制。

**作为调试线索，当开发者遇到光标显示相关的 bug 时，可以按照以下步骤进行排查：**

1. **确认问题发生的具体场景：** 例如，是在特定的 HTML 结构下出现，还是在特定的用户操作后出现？
2. **检查相关的 HTML 和 CSS：**  `contenteditable` 属性是否正确设置？是否有影响光标定位的 CSS 属性（例如 `position`, `float`, `direction`, `white-space`）？
3. **使用浏览器的开发者工具检查元素的布局信息：**  确认元素的布局是否如预期，光标应该在哪个布局对象中？
4. **断点调试 Blink 引擎的源代码：**  可以从 `FrameCaret::SetSelection` 或 `CaretDisplayItemClient::Update` 等关键函数开始，逐步跟踪光标位置的计算和渲染流程。
5. **查看 Compositor 线程的渲染信息：**  确认光标的渲染层是否被正确创建和更新。

总而言之，`caret_display_item_client_test.cc` 这个文件是理解 Blink 引擎如何管理和渲染文本光标的重要入口，它涵盖了各种复杂的场景和边界情况，确保了用户在网页上进行文本编辑时的良好体验。

### 提示词
```
这是目录为blink/renderer/core/editing/caret_display_item_client_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/editing/caret_display_item_client.h"

#include "build/build_config.h"
#include "testing/gmock/include/gmock/gmock-matchers.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "third_party/blink/renderer/core/editing/frame_caret.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/position_with_affinity.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/testing/editing_test_base.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/layout/inline/inline_cursor.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/page/focus_controller.h"
#include "third_party/blink/renderer/core/paint/paint_and_raster_invalidation_test.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/platform/testing/find_cc_layer.h"
#include "third_party/blink/renderer/platform/testing/picture_matchers.h"

namespace blink {

using ::testing::ElementsAre;
using ::testing::UnorderedElementsAre;

#define ASSERT_CARET_LAYER()                                       \
  do {                                                             \
    ASSERT_TRUE(CaretLayer());                                     \
    EXPECT_EQ(SkColors::kBlack, CaretLayer()->background_color()); \
    EXPECT_TRUE(CaretLayer()->IsSolidColorLayerForTesting());      \
  } while (false)

class CaretDisplayItemClientTest : public PaintAndRasterInvalidationTest {
 protected:
  void SetUp() override {
    PaintAndRasterInvalidationTest::SetUp();
    Selection().SetCaretBlinkingSuspended(true);
  }

  FrameSelection& Selection() const {
    return GetDocument().View()->GetFrame().Selection();
  }

  FrameCaret& GetFrameCaret() { return Selection().FrameCaretForTesting(); }

  bool IsVisibleIfActive() { return GetFrameCaret().IsVisibleIfActive(); }
  void SetVisibleIfActive(bool v) { GetFrameCaret().SetVisibleIfActive(v); }

  CaretDisplayItemClient& GetCaretDisplayItemClient() {
    return *GetFrameCaret().display_item_client_;
  }

  const PhysicalRect& CaretLocalRect() {
    return GetCaretDisplayItemClient().local_rect_;
  }

  PhysicalRect ComputeCaretRect(const PositionWithAffinity& position) const {
    return CaretDisplayItemClient::ComputeCaretRectAndPainterBlock(position)
        .caret_rect;
  }

  const LayoutBlock* CaretLayoutBlock() {
    return GetCaretDisplayItemClient().layout_block_.Get();
  }

  const LayoutBlock* PreviousCaretLayoutBlock() {
    return GetCaretDisplayItemClient().previous_layout_block_.Get();
  }

  const PhysicalBoxFragment* CaretBoxFragment() {
    return GetCaretDisplayItemClient().box_fragment_.Get();
  }

  bool ShouldPaintCursorCaret(const LayoutBlock& block) {
    return Selection().ShouldPaintCaret(block);
  }

  bool ShouldPaintCursorCaret(const PhysicalBoxFragment& fragment) {
    return Selection().ShouldPaintCaret(fragment);
  }

  Text* AppendTextNode(const String& data) {
    Text* text = GetDocument().createTextNode(data);
    GetDocument().body()->AppendChild(text);
    return text;
  }

  Element* AppendBlock(const String& data) {
    Element* block = GetDocument().CreateRawElement(html_names::kDivTag);
    Text* text = GetDocument().createTextNode(data);
    block->AppendChild(text);
    GetDocument().body()->AppendChild(block);
    return block;
  }

  const cc::Layer* CaretLayer() const {
    Vector<cc::Layer*> layers = CcLayersByName(
        GetDocument().View()->GetPaintArtifactCompositor()->RootLayer(),
        "Caret");
    if (layers.empty()) {
      return nullptr;
    }
    DCHECK_EQ(layers.size(), 1u);
    return layers.front();
  }

  void UpdateAllLifecyclePhasesForCaretTest() {
    // Partial lifecycle updates should not affect caret paint invalidation.
    GetDocument().View()->UpdateLifecycleToLayoutClean(
        DocumentUpdateReason::kTest);
    UpdateAllLifecyclePhasesForTest();
    // Partial lifecycle updates should not affect caret paint invalidation.
    GetDocument().View()->UpdateLifecycleToLayoutClean(
        DocumentUpdateReason::kTest);
  }
};

INSTANTIATE_PAINT_TEST_SUITE_P(CaretDisplayItemClientTest);

TEST_P(CaretDisplayItemClientTest, CaretPaintInvalidation) {
  GetDocument().body()->setContentEditable("true", ASSERT_NO_EXCEPTION);
  GetDocument().GetPage()->GetFocusController().SetActive(true);
  GetDocument().GetPage()->GetFocusController().SetFocused(true);

  Text* text = AppendTextNode("Hello, World!");
  UpdateAllLifecyclePhasesForCaretTest();
  const auto* block = To<LayoutBlock>(GetDocument().body()->GetLayoutObject());

  // Focus the body. Should invalidate the new caret.
  GetDocument().body()->Focus();

  UpdateAllLifecyclePhasesExceptPaint();
  EXPECT_FALSE(GetCaretDisplayItemClient().IsValid());

  UpdateAllLifecyclePhasesForCaretTest();
  EXPECT_TRUE(ShouldPaintCursorCaret(*block));
  EXPECT_TRUE(GetCaretDisplayItemClient().IsValid());
  EXPECT_EQ(PhysicalRect(0, 0, 1, 1), CaretLocalRect());

  ASSERT_CARET_LAYER();

  // Move the caret to the end of the text. Should invalidate both the old and
  // new carets.
  Selection().SetSelection(
      SelectionInDOMTree::Builder().Collapse(Position(text, 5)).Build(),
      SetSelectionOptions());

  EXPECT_TRUE(GetCaretDisplayItemClient().IsValid());
  UpdateAllLifecyclePhasesExceptPaint();
  EXPECT_FALSE(GetCaretDisplayItemClient().IsValid());

  UpdateAllLifecyclePhasesForCaretTest();
  EXPECT_TRUE(ShouldPaintCursorCaret(*block));
  EXPECT_TRUE(GetCaretDisplayItemClient().IsValid());
  int delta = CaretLocalRect().X().ToInt();
  EXPECT_GT(delta, 0);
  EXPECT_EQ(PhysicalRect(delta, 0, 1, 1), CaretLocalRect());

  ASSERT_CARET_LAYER();

  // Remove selection. Should invalidate the old caret.
  Selection().SetSelection(SelectionInDOMTree(), SetSelectionOptions());

  EXPECT_TRUE(GetCaretDisplayItemClient().IsValid());
  UpdateAllLifecyclePhasesExceptPaint();
  EXPECT_FALSE(GetCaretDisplayItemClient().IsValid());

  UpdateAllLifecyclePhasesForCaretTest();
  EXPECT_FALSE(ShouldPaintCursorCaret(*block));
  // The caret display item client painted nothing, so is not validated.
  EXPECT_FALSE(GetCaretDisplayItemClient().IsValid());
  EXPECT_EQ(PhysicalRect(), CaretLocalRect());
  EXPECT_FALSE(CaretLayer());
}

TEST_P(CaretDisplayItemClientTest, CaretMovesBetweenBlocks) {
  GetDocument().body()->setContentEditable("true", ASSERT_NO_EXCEPTION);
  GetDocument().GetPage()->GetFocusController().SetActive(true);
  GetDocument().GetPage()->GetFocusController().SetFocused(true);
  auto* block_element1 = AppendBlock("Block1");
  auto* block_element2 = AppendBlock("Block2");
  UpdateAllLifecyclePhasesForTest();
  auto* block1 = To<LayoutBlockFlow>(block_element1->GetLayoutObject());
  auto* block2 = To<LayoutBlockFlow>(block_element2->GetLayoutObject());

  // Focus the body.
  GetDocument().body()->Focus();

  UpdateAllLifecyclePhasesExceptPaint();
  EXPECT_FALSE(GetCaretDisplayItemClient().IsValid());

  UpdateAllLifecyclePhasesForCaretTest();
  EXPECT_TRUE(GetCaretDisplayItemClient().IsValid());

  EXPECT_EQ(PhysicalRect(0, 0, 1, 1), CaretLocalRect());
  EXPECT_TRUE(ShouldPaintCursorCaret(*block1));
  EXPECT_FALSE(ShouldPaintCursorCaret(*block2));

  // Move the caret into block2. Should invalidate both the old and new carets.
  Selection().SetSelection(SelectionInDOMTree::Builder()
                               .Collapse(Position(block_element2, 0))
                               .Build(),
                           SetSelectionOptions());

  EXPECT_TRUE(GetCaretDisplayItemClient().IsValid());
  UpdateAllLifecyclePhasesExceptPaint();
  EXPECT_FALSE(GetCaretDisplayItemClient().IsValid());

  UpdateAllLifecyclePhasesForCaretTest();
  EXPECT_TRUE(GetCaretDisplayItemClient().IsValid());

  EXPECT_EQ(PhysicalRect(0, 0, 1, 1), CaretLocalRect());
  EXPECT_FALSE(ShouldPaintCursorCaret(*block1));
  EXPECT_TRUE(ShouldPaintCursorCaret(*block2));

  ASSERT_CARET_LAYER();

  // Move the caret back into block1.
  Selection().SetSelection(SelectionInDOMTree::Builder()
                               .Collapse(Position(block_element1, 0))
                               .Build(),
                           SetSelectionOptions());

  EXPECT_TRUE(GetCaretDisplayItemClient().IsValid());
  UpdateAllLifecyclePhasesExceptPaint();
  EXPECT_FALSE(GetCaretDisplayItemClient().IsValid());

  UpdateAllLifecyclePhasesForCaretTest();
  EXPECT_TRUE(GetCaretDisplayItemClient().IsValid());

  EXPECT_EQ(PhysicalRect(0, 0, 1, 1), CaretLocalRect());
  EXPECT_TRUE(ShouldPaintCursorCaret(*block1));
  EXPECT_FALSE(ShouldPaintCursorCaret(*block2));

  ASSERT_CARET_LAYER();
}

TEST_P(CaretDisplayItemClientTest, UpdatePreviousLayoutBlock) {
  GetDocument().body()->setContentEditable("true", ASSERT_NO_EXCEPTION);
  GetDocument().GetPage()->GetFocusController().SetActive(true);
  GetDocument().GetPage()->GetFocusController().SetFocused(true);
  auto* block_element1 = AppendBlock("Block1");
  auto* block_element2 = AppendBlock("Block2");
  UpdateAllLifecyclePhasesForCaretTest();
  auto* block1 = To<LayoutBlock>(block_element1->GetLayoutObject());
  auto* block2 = To<LayoutBlock>(block_element2->GetLayoutObject());

  // Set caret into block2.
  GetDocument().body()->Focus();
  Selection().SetSelection(SelectionInDOMTree::Builder()
                               .Collapse(Position(block_element2, 0))
                               .Build(),
                           SetSelectionOptions());
  GetDocument().View()->UpdateLifecycleToLayoutClean(
      DocumentUpdateReason::kTest);
  EXPECT_TRUE(ShouldPaintCursorCaret(*block2));
  EXPECT_EQ(block2, CaretLayoutBlock());
  EXPECT_FALSE(ShouldPaintCursorCaret(*block1));
  EXPECT_FALSE(PreviousCaretLayoutBlock());

  // Move caret into block1. Should set PreviousCaretLayoutBlock to block2.
  Selection().SetSelection(SelectionInDOMTree::Builder()
                               .Collapse(Position(block_element1, 0))
                               .Build(),
                           SetSelectionOptions());
  GetDocument().View()->UpdateLifecycleToLayoutClean(
      DocumentUpdateReason::kTest);
  EXPECT_TRUE(ShouldPaintCursorCaret(*block1));
  EXPECT_EQ(block1, CaretLayoutBlock());
  EXPECT_FALSE(ShouldPaintCursorCaret(*block2));
  EXPECT_EQ(block2, PreviousCaretLayoutBlock());

  // Move caret into block2. Partial update should not change
  // PreviousCaretLayoutBlock.
  Selection().SetSelection(SelectionInDOMTree::Builder()
                               .Collapse(Position(block_element2, 0))
                               .Build(),
                           SetSelectionOptions());
  GetDocument().View()->UpdateLifecycleToLayoutClean(
      DocumentUpdateReason::kTest);
  EXPECT_TRUE(ShouldPaintCursorCaret(*block2));
  EXPECT_EQ(block2, CaretLayoutBlock());
  EXPECT_FALSE(ShouldPaintCursorCaret(*block1));
  EXPECT_EQ(block2, PreviousCaretLayoutBlock());

  // Remove block2. Should clear caretLayoutBlock and PreviousCaretLayoutBlock.
  block_element2->parentNode()->RemoveChild(block_element2);
  EXPECT_FALSE(CaretLayoutBlock());
  EXPECT_FALSE(PreviousCaretLayoutBlock());

  // Set caret into block1.
  Selection().SetSelection(SelectionInDOMTree::Builder()
                               .Collapse(Position(block_element1, 0))
                               .Build(),
                           SetSelectionOptions());
  UpdateAllLifecyclePhasesForCaretTest();
  // Remove selection.
  Selection().SetSelection(SelectionInDOMTree(), SetSelectionOptions());
  GetDocument().View()->UpdateLifecycleToLayoutClean(
      DocumentUpdateReason::kTest);
  EXPECT_EQ(block1, PreviousCaretLayoutBlock());
}

TEST_P(CaretDisplayItemClientTest, EnsureInvalidatePreviousLayoutBlock) {
  SetBodyInnerHTML(
      "<style>"
      "  .canvas {"
      "    width: 600px;"
      "  }"
      "  .page {"
      "    content-visibility: auto;"
      "    contain-intrinsic-size: auto 300px; "
      "  }"
      "  .paragraph {"
      "    position: relative;"
      "    left: 20px;"
      "  }"
      "  .high {"
      "    height: 10000px;"
      "  }"
      "</style>"

      "<div class='canvas' contenteditable='true'>"
      "  <div id='div1' class='page'>"
      "    <p id='p1' class='paragraph'>some text</p>"
      "  </div>"
      "  <div id='div2' class='high'></div>"
      "  <div id='div3' class='page'>"
      "    <p id='p3' class='paragraph'>some text</p>"
      "  </div>"
      "</div>");

  GetDocument().GetPage()->GetFocusController().SetActive(true);
  GetDocument().GetPage()->GetFocusController().SetFocused(true);
  UpdateAllLifecyclePhasesForCaretTest();
  auto* p1 = GetDocument().getElementById(AtomicString("p1"));
  auto* p1_block = To<LayoutBlock>(p1->GetLayoutObject());

  // Set caret into p1.
  GetDocument().body()->Focus();
  Selection().SetSelection(
      SelectionInDOMTree::Builder().Collapse(Position(p1, 0)).Build(),
      SetSelectionOptions());

  GetDocument().View()->UpdateLifecycleToLayoutClean(
      DocumentUpdateReason::kTest);
  EXPECT_FALSE(PreviousCaretLayoutBlock());

  UpdateAllLifecyclePhasesForCaretTest();
  EXPECT_EQ(p1_block, PreviousCaretLayoutBlock());

  // Scroll the page all the way to bottom. p1 will be display locked.
  GetDocument().documentElement()->setScrollTop(1000000000);
  UpdateAllLifecyclePhasesForCaretTest();

  auto* p3 = GetDocument().getElementById(AtomicString("p3"));
  // Set caret into p3. Should set PreviousCaretLayoutBlock to p1.
  Selection().SetSelection(
      SelectionInDOMTree::Builder().Collapse(Position(p3, 0)).Build(),
      SetSelectionOptions());
  GetDocument().View()->UpdateLifecycleToLayoutClean(
      DocumentUpdateReason::kTest);
  EXPECT_EQ(p1_block, PreviousCaretLayoutBlock());

  // PreviousCaretLayoutBlock should be invalidated and cleared after paint
  // invalidation.
  UpdateAllLifecyclePhasesForCaretTest();
  EXPECT_NE(p1_block, PreviousCaretLayoutBlock());
}

TEST_P(CaretDisplayItemClientTest, CaretHideMoveAndShow) {
  GetDocument().body()->setContentEditable("true", ASSERT_NO_EXCEPTION);
  GetDocument().GetPage()->GetFocusController().SetActive(true);
  GetDocument().GetPage()->GetFocusController().SetFocused(true);

  Text* text = AppendTextNode("Hello, World!");
  GetDocument().body()->Focus();
  UpdateAllLifecyclePhasesForCaretTest();
  EXPECT_EQ(PhysicalRect(0, 0, 1, 1), CaretLocalRect());

  // Simulate that the blinking cursor becomes invisible.
  Selection().SetCaretEnabled(false);
  // Move the caret to the end of the text.
  Selection().SetSelection(
      SelectionInDOMTree::Builder().Collapse(Position(text, 5)).Build(),
      SetSelectionOptions());
  // Simulate that the cursor blinking is restarted.
  Selection().SetCaretEnabled(true);

  EXPECT_TRUE(GetCaretDisplayItemClient().IsValid());
  UpdateAllLifecyclePhasesExceptPaint();
  EXPECT_FALSE(GetCaretDisplayItemClient().IsValid());

  UpdateAllLifecyclePhasesForCaretTest();
  EXPECT_TRUE(GetCaretDisplayItemClient().IsValid());
  int delta = CaretLocalRect().X().ToInt();
  EXPECT_GT(delta, 0);
  EXPECT_EQ(PhysicalRect(delta, 0, 1, 1), CaretLocalRect());

  ASSERT_CARET_LAYER();
}

TEST_P(CaretDisplayItemClientTest, BlinkingCaretNoInvalidation) {
  GetDocument().body()->setContentEditable("true", ASSERT_NO_EXCEPTION);
  GetDocument().GetPage()->GetFocusController().SetActive(true);
  GetDocument().GetPage()->GetFocusController().SetFocused(true);

  GetDocument().body()->Focus();
  UpdateAllLifecyclePhasesForCaretTest();
  EXPECT_EQ(PhysicalRect(0, 0, 1, 1), CaretLocalRect());

  // No paint or raster invalidation when caret is blinking.
  EXPECT_TRUE(IsVisibleIfActive());
  SetVisibleIfActive(false);
  EXPECT_TRUE(GetCaretDisplayItemClient().IsValid());
  UpdateAllLifecyclePhasesExceptPaint();
  EXPECT_TRUE(GetCaretDisplayItemClient().IsValid());

  EXPECT_TRUE(IsVisibleIfActive());
  SetVisibleIfActive(true);
  EXPECT_TRUE(GetCaretDisplayItemClient().IsValid());
  UpdateAllLifecyclePhasesExceptPaint();
  EXPECT_TRUE(GetCaretDisplayItemClient().IsValid());
}

TEST_P(CaretDisplayItemClientTest, CompositingChange) {
  SetBodyInnerHTML(
      "<style>"
      "  body { margin: 0 }"
      "  #container { position: absolute; top: 55px; left: 66px; }"
      "</style>"
      "<div id='container'>"
      "  <div id='editor' contenteditable style='padding: 50px'>ABCDE</div>"
      "</div>");

  GetDocument().GetPage()->GetFocusController().SetActive(true);
  GetDocument().GetPage()->GetFocusController().SetFocused(true);
  auto* container = GetDocument().getElementById(AtomicString("container"));
  auto* editor = GetDocument().getElementById(AtomicString("editor"));
  auto* editor_block = To<LayoutBlock>(editor->GetLayoutObject());
  Selection().SetSelection(
      SelectionInDOMTree::Builder().Collapse(Position(editor, 0)).Build(),
      SetSelectionOptions());

  UpdateAllLifecyclePhasesExceptPaint();
  EXPECT_FALSE(GetCaretDisplayItemClient().IsValid());
  UpdateAllLifecyclePhasesForCaretTest();
  EXPECT_TRUE(ShouldPaintCursorCaret(*editor_block));
  EXPECT_EQ(editor_block, CaretLayoutBlock());
  EXPECT_EQ(PhysicalRect(50, 50, 1, 1), CaretLocalRect());

  // Composite container.
  container->setAttribute(html_names::kStyleAttr,
                          AtomicString("will-change: transform"));
  UpdateAllLifecyclePhasesExceptPaint();
  EXPECT_FALSE(GetCaretDisplayItemClient().IsValid());
  UpdateAllLifecyclePhasesForCaretTest();
  EXPECT_EQ(PhysicalRect(50, 50, 1, 1), CaretLocalRect());

  // Uncomposite container.
  container->setAttribute(html_names::kStyleAttr, g_empty_atom);
  UpdateAllLifecyclePhasesExceptPaint();
  EXPECT_FALSE(GetCaretDisplayItemClient().IsValid());
  UpdateAllLifecyclePhasesForCaretTest();
  EXPECT_EQ(PhysicalRect(50, 50, 1, 1), CaretLocalRect());
}

TEST_P(CaretDisplayItemClientTest, PlainTextRTLCaretPosition) {
  LoadNoto();
  SetBodyInnerHTML(
      "<style>"
      "  div { width: 100px; padding: 5px; font: 20px NotoArabic }"
      "  #plaintext { unicode-bidi: plaintext }"
      "</style>"
      "<div id='regular' dir='rtl'>&#1575;&#1582;&#1578;&#1576;&#1585;</div>"
      "<div id='plaintext'>&#1575;&#1582;&#1578;&#1576;&#1585;</div>");

  auto* regular = GetDocument().getElementById(AtomicString("regular"));
  auto* regular_text_node = regular->firstChild();
  const Position& regular_position =
      Position::FirstPositionInNode(*regular_text_node);
  const PhysicalRect regular_caret_rect =
      ComputeCaretRect(PositionWithAffinity(regular_position));

  auto* plaintext = GetDocument().getElementById(AtomicString("plaintext"));
  auto* plaintext_text_node = plaintext->firstChild();
  const Position& plaintext_position =
      Position::FirstPositionInNode(*plaintext_text_node);
  const PhysicalRect plaintext_caret_rect =
      ComputeCaretRect(PositionWithAffinity(plaintext_position));

  EXPECT_EQ(regular_caret_rect, plaintext_caret_rect);
}

#if BUILDFLAG(IS_MAC) || BUILDFLAG(IS_IOS)
// TODO(crbug.com/1457081): Previously, this test passed on the Mac bots even
// though `LoadNoto()` always failed. Now that `LoadNoto()` actually succeeds,
// this test fails on Mac and iOS though...
#define MAYBE_InsertSpaceToWhiteSpacePreWrapRTL \
  DISABLED_InsertSpaceToWhiteSpacePreWrapRTL
#else
#define MAYBE_InsertSpaceToWhiteSpacePreWrapRTL \
  InsertSpaceToWhiteSpacePreWrapRTL
#endif
// http://crbug.com/1278559
TEST_P(CaretDisplayItemClientTest, MAYBE_InsertSpaceToWhiteSpacePreWrapRTL) {
  LoadNoto();
  SetBodyInnerHTML(
      "<style>"
      "  div { white-space: pre-wrap; unicode-bidi: plaintext; width: 100px; "
      "  font: 20px NotoArabic }"
      "</style>"
      "<div id='editor' contentEditable='true' "
      "dir='rtl'>&#1575;&#1582;&#1578;&#1576;&#1585;</div>");

  auto* editor = GetDocument().getElementById(AtomicString("editor"));
  auto* editor_block = To<LayoutBlock>(editor->GetLayoutObject());
  auto* text_node = editor->firstChild();
  const Position& position = Position::LastPositionInNode(*text_node);
  const PhysicalRect& caret_from_position =
      ComputeCaretRect(PositionWithAffinity(position));

  GetDocument().GetPage()->GetFocusController().SetActive(true);
  GetDocument().GetPage()->GetFocusController().SetFocused(true);
  Selection().SetSelection(
      SelectionInDOMTree::Builder().Collapse(position).Build(),
      SetSelectionOptions());

  UpdateAllLifecyclePhasesExceptPaint();
  EXPECT_FALSE(GetCaretDisplayItemClient().IsValid());
  UpdateAllLifecyclePhasesForCaretTest();
  EXPECT_TRUE(ShouldPaintCursorCaret(*editor_block));
  EXPECT_EQ(editor_block, CaretLayoutBlock());

  const PhysicalRect& caret_from_selection = CaretLocalRect();
  EXPECT_EQ(caret_from_position, caret_from_selection);

  // Compute the width of a white-space, give the NotoNaskhArabic font's
  // metrics.
  auto* text_layout_object = To<LayoutText>(text_node->GetLayoutObject());
  LayoutUnit width = text_layout_object->PhysicalLinesBoundingBox().Width();
  GetDocument().execCommand("insertText", false, " ", ASSERT_NO_EXCEPTION);
  UpdateAllLifecyclePhasesForCaretTest();
  text_layout_object = To<LayoutText>(text_node->GetLayoutObject());
  int space_width =
      (text_layout_object->PhysicalLinesBoundingBox().Width() - width).ToInt();
  EXPECT_GT(space_width, 0);

  GetDocument().execCommand("insertText", false, " ", ASSERT_NO_EXCEPTION);
  UpdateAllLifecyclePhasesForCaretTest();
  const PhysicalSize& delta1 =
      caret_from_position.DistanceAsSize(caret_from_selection.MinXMinYCorner());
  EXPECT_EQ(PhysicalSize(2 * space_width, 0), delta1);

  GetDocument().execCommand("insertText", false, " ", ASSERT_NO_EXCEPTION);
  UpdateAllLifecyclePhasesForCaretTest();
  const PhysicalSize& delta2 =
      caret_from_position.DistanceAsSize(caret_from_selection.MinXMinYCorner());
  EXPECT_EQ(PhysicalSize(3 * space_width, 0), delta2);
}

// http://crbug.com/1278559
TEST_P(CaretDisplayItemClientTest, InsertSpaceToWhiteSpacePreWrap) {
  LoadAhem();
  SetBodyInnerHTML(
      "<style>"
      "  div { white-space: pre-wrap; unicode-bidi: plaintext; width: 100px; "
      "font: 10px/1 Ahem}"
      "</style>"
      "<div id='editor' contentEditable='true'>XXXXX</div>");

  auto* editor = GetDocument().getElementById(AtomicString("editor"));
  auto* editor_block = To<LayoutBlock>(editor->GetLayoutObject());
  auto* text_node = editor->firstChild();
  const Position position = Position::LastPositionInNode(*text_node);
  const PhysicalRect& rect = ComputeCaretRect(PositionWithAffinity(position));
  // The 5 characters of arabic text rendered using the NotoArabic font has a
  // width of 20px and a height of 17px
  EXPECT_EQ(PhysicalRect(50, 0, 1, 10), rect);

  GetDocument().GetPage()->GetFocusController().SetActive(true);
  GetDocument().GetPage()->GetFocusController().SetFocused(true);
  Selection().SetSelection(
      SelectionInDOMTree::Builder().Collapse(position).Build(),
      SetSelectionOptions());

  UpdateAllLifecyclePhasesExceptPaint();
  EXPECT_FALSE(GetCaretDisplayItemClient().IsValid());
  UpdateAllLifecyclePhasesForCaretTest();
  EXPECT_TRUE(ShouldPaintCursorCaret(*editor_block));
  EXPECT_EQ(editor_block, CaretLayoutBlock());
  EXPECT_EQ(rect, CaretLocalRect());

  GetDocument().execCommand("insertText", false, " ", ASSERT_NO_EXCEPTION);
  UpdateAllLifecyclePhasesForCaretTest();
  EXPECT_EQ(PhysicalRect(60, 0, 1, 10), CaretLocalRect());

  GetDocument().execCommand("insertText", false, " ", ASSERT_NO_EXCEPTION);
  UpdateAllLifecyclePhasesForCaretTest();
  EXPECT_EQ(PhysicalRect(70, 0, 1, 10), CaretLocalRect());
}

// http://crbug.com/1330093
TEST_P(CaretDisplayItemClientTest, CaretAtStartInWhiteSpacePreWrapRTL) {
  LoadNoto();
  SetBodyInnerHTML(
      "<style>"
      "  body { margin: 0; padding: 0; }"
      "  div { white-space: pre-wrap; width: 90px; margin: 0; padding: 5px; "
      "  font: 20px NotoArabic }"
      "</style>"
      "<div dir=rtl contenteditable>&#1575;&#1582;&#1578;&#1576;&#1585; "
      "</div>");

  const Element& div = *GetDocument().QuerySelector(AtomicString("div"));
  const Position& position = Position::FirstPositionInNode(div);
  const PhysicalRect& rect = ComputeCaretRect(PositionWithAffinity(position));
  EXPECT_EQ(94, rect.X());
}

// https://crbug.com/1499405
TEST_P(CaretDisplayItemClientTest, CaretAtEdgeOfInlineBlock) {
  LoadAhem();
  InsertStyleElement(
      "body { margin: 0; padding: 0; font: 10px/10px Ahem; }"
      "div#editable { width: 80px; padding: 0px 10px; text-align: center; }"
      "span { padding: 0px 15px; display: inline-block }");
  SetBodyContent(
      "<div id=editable contenteditable>"
      "<span contenteditable=false>foo</span>"
      "</div>");

  const Element& editable =
      *GetDocument().QuerySelector(AtomicString("#editable"));
  const LayoutBlock* editable_block =
      To<LayoutBlock>(editable.GetLayoutObject());

  GetDocument().GetPage()->GetFocusController().SetActive(true);
  GetDocument().GetPage()->GetFocusController().SetFocused(true);

  auto test = [this, editable_block](const Position& position,
                                     const PhysicalRect& expected_rect) {
    Selection().SetSelection(
        SelectionInDOMTree::Builder().Collapse(position).Build(),
        SetSelectionOptions());

    UpdateAllLifecyclePhasesExceptPaint();
    EXPECT_FALSE(GetCaretDisplayItemClient().IsValid());
    UpdateAllLifecyclePhasesForCaretTest();

    EXPECT_TRUE(ShouldPaintCursorCaret(*editable_block));
    EXPECT_EQ(editable_block, CaretLayoutBlock());
    EXPECT_EQ(expected_rect, CaretLocalRect());

    DCHECK_EQ(editable_block->PhysicalFragmentCount(), 1u);
    auto* editable_fragment = editable_block->GetPhysicalFragment(0);
    EXPECT_TRUE(ShouldPaintCursorCaret(*editable_fragment));
    EXPECT_EQ(editable_fragment, CaretBoxFragment());
  };

  test(Position::FirstPositionInNode(editable), PhysicalRect(20, 0, 1, 10));
  test(Position::LastPositionInNode(editable), PhysicalRect(79, 0, 1, 10));
}

class ComputeCaretRectTest : public EditingTestBase {
 public:
  ComputeCaretRectTest() = default;

 protected:
  PhysicalRect ComputeCaretRect(const PositionWithAffinity& position) const {
    return CaretDisplayItemClient::ComputeCaretRectAndPainterBlock(position)
        .caret_rect;
  }
  HitTestResult HitTestResultAtLocation(const HitTestLocation& location) {
    return GetFrame().GetEventHandler().HitTestResultAtLocation(location);
  }
  HitTestResult HitTestResultAtLocation(int x, int y) {
    HitTestLocation location(gfx::Point(x, y));
    return HitTestResultAtLocation(location);
  }
};

TEST_P(CaretDisplayItemClientTest, FullDocumentPaintingWithCaret) {
  SetBodyInnerHTML(
      "<div id='div' contentEditable='true' style='outline:none'>XYZ</div>");
  GetDocument().GetPage()->GetFocusController().SetActive(true);
  GetDocument().GetPage()->GetFocusController().SetFocused(true);
  auto& div = *To<Element>(GetDocument().body()->firstChild());
  auto& layout_text = *To<Text>(div.firstChild())->GetLayoutObject();
  DCHECK(layout_text.IsInLayoutNGInlineFormattingContext());
  InlineCursor cursor;
  cursor.MoveTo(layout_text);
  const DisplayItemClient* text_inline_box =
      cursor.Current().GetDisplayItemClient();
  EXPECT_THAT(ContentDisplayItems(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_DISPLAY_ITEM,
                          IsSameId(text_inline_box->Id(), kForegroundType)));
  EXPECT_FALSE(CaretLayer());

  div.Focus();
  UpdateAllLifecyclePhasesForTest();

  EXPECT_THAT(ContentDisplayItems(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_DISPLAY_ITEM,
                          IsSameId(text_inline_box->Id(), kForegroundType),
                          // New!
                          IsSameId(GetCaretDisplayItemClient().Id(),
                                   DisplayItem::kCaret)));
  ASSERT_CARET_LAYER();
}

TEST_F(ComputeCaretRectTest, CaretRectAfterEllipsisNoCrash) {
  SetBodyInnerHTML(
      "<style>pre{width:30px; overflow:hidden; text-overflow:ellipsis}</style>"
      "<pre id=target>long long long long long long text</pre>");
  const Node* text = GetElementById("target")->firstChild();
  const Position position = Position::LastPositionInNode(*text);
  // Shouldn't crash inside. The actual result doesn't matter and may change.
  ComputeCaretRect(PositionWithAffinity(position));
}

TEST_F(ComputeCaretRectTest, CaretRectAvoidNonEditable) {
  LoadAhem();
  InsertStyleElement(
      "body { margin: 0; padding: 0; font: 10px/10px Ahem; }"
      "div { width: 70px; padding: 0px 10px; }"
      "span { padding: 0px 15px }");
  SetBodyContent(
      "<div contenteditable><span contenteditable=\"false\">foo</span></div>");

  const PositionWithAffinity& caret_position1 =
      HitTestResultAtLocation(20, 5).GetPosition();
  const PhysicalRect& rect1 = ComputeCaretRect(caret_position1);
  EXPECT_EQ(PhysicalRect(10, 0, 1, 10), rect1);

  const PositionWithAffinity& caret_position2 =
      HitTestResultAtLocation(60, 5).GetPosition();
  const PhysicalRect& rect2 = ComputeCaretRect(caret_position2);
  EXPECT_EQ(PhysicalRect(69, 0, 1, 10), rect2);
}

}  // namespace blink
```