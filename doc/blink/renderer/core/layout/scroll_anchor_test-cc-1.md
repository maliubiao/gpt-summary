Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of a test file for the Chromium Blink engine's scroll anchoring feature. The snippet contains several test cases. I need to analyze each test case to understand what specific scroll anchoring behavior it's verifying. I also need to identify if any of these tests relate to JavaScript, HTML, or CSS functionality and provide examples if they do. Finally, I need to look for common user or programming errors that these tests might be preventing.

Here's a breakdown of each test case and my thoughts on its purpose:

*   **`RestoreAnchorWithoutExistingAnchorObject`**:  Checks if restoring a scroll anchor works correctly when there isn't already an anchor object. This likely involves creating a new anchor object. The test sets up a simple HTML structure and verifies the scroll position after restoration.
*   **`RestoreAnchorSucceedsWithExistingAnchorObject`**:  Verifies that restoring an anchor works as expected even if an anchor object already exists. This might test the update mechanism or that it doesn't create redundant anchors.
*   **`DeleteAnonymousBlockCrash`**: This test is explicitly designed to check for a crash scenario. It involves removing an element that also removes an anonymous block, which previously caused issues in the layout engine. This is a regression test.
*   **`ClampAdjustsAnchorAnimation`**: This test focuses on how scroll anchoring interacts with animations, particularly when the available scrollable area changes (in this case, due to toggling the visibility of an element). It checks if the animation adjustment is correctly calculated. This involves CSS (`display: none/block`).
*   **`DynamicMultiColumnCrash`**: Another crash test. This one involves dynamically changing the font size and then the column layout of an element. This targets potential issues in how scroll anchoring handles multi-column layouts during updates. This is related to CSS (`font-size`, `columns`).
*   **`ScrollAnchorFindInPageTest` and its tests (`FindInPageResultPrioritized`, `FocusPrioritizedOverFindInPage`, `FocusedUnderStickyIsSkipped`)**: This section introduces a separate testing fixture for interactions between scroll anchoring and the "Find in Page" functionality.
    *   **`FindInPageResultPrioritized`**: Checks if the scroll anchoring system prioritizes keeping the "Find in Page" result in view when the page content changes. This relates to the browser's user interface and how it handles dynamic content during a find operation.
    *   **`FocusPrioritizedOverFindInPage`**: Tests if focusing an element takes precedence over the "Find in Page" result in terms of scroll anchoring. This tests the prioritization logic.
    *   **`FocusedUnderStickyIsSkipped`**: Checks if an element focused within a sticky positioned element is correctly skipped when selecting a scroll anchor. This avoids unexpected scrolling to the sticky element. This involves CSS (`position: sticky`).
*   **`ScrollAnchorPageTest` and its test (`SvgRelativeBoundsCrashAfterClearLayoutResults`)**: This introduces another testing fixture focused on a specific crash scenario.
    *   **`SvgRelativeBoundsCrashAfterClearLayoutResults`**: Tests for a crash that occurred when an SVG element with a foreign object was involved in layout changes and scroll anchoring. This is another regression test and involves SVG, which is often embedded in HTML.

Now, let's consider potential relationships to JavaScript, HTML, and CSS:

*   **JavaScript**: The tests manipulate the DOM (e.g., `SetBodyInnerHTML`, `getElementById`, `remove`, `setAttribute`), which are common JavaScript operations. Scroll anchoring is often triggered by JavaScript-initiated changes to the DOM or layout.
*   **HTML**: The tests define HTML structures to set up the scenarios they are testing. The presence and attributes of HTML elements are crucial for the scroll anchoring logic.
*   **CSS**:  Several tests directly involve CSS properties like `height`, `margin`, `display`, `columns`, `font-size`, and `position: sticky`. These properties affect the layout and therefore the behavior of scroll anchoring.

For hypothetical inputs and outputs, I'll focus on the `RestoreAnchorWithoutExistingAnchorObject` test as an example, as the others are more about crash prevention or complex scenarios.

**Hypothetical Input and Output Example (`RestoreAnchorWithoutExistingAnchorObject`):**

*   **Input:** HTML with two divs, the first with `id='block1'`. Initial scroll position is 0. A `SerializedAnchor` object is created referencing `#block1` with a logical offset of (0, 0).
*   **Expected Output:** After `RestoreAnchor` is called, the scroll position should be 0, as the top of `#block1` should be aligned with the top of the viewport.

Regarding common user/programming errors, the tests around crash scenarios (`DeleteAnonymousBlockCrash`, `DynamicMultiColumnCrash`, `SvgRelativeBoundsCrashAfterClearLayoutResults`) highlight potential issues in the browser engine that developers might indirectly trigger through their HTML, CSS, or JavaScript. For example, dynamically manipulating layout-related CSS properties (like `columns`) can sometimes expose edge cases in the rendering engine. The "Find in Page" tests address how user interactions and dynamic content updates should interact with scroll preservation.

Finally, for the overall summarization requested in this part 2, I will focus on the tests presented in *this specific snippet*.
这是对 `blink/renderer/core/layout/scroll_anchor_test.cc` 文件部分代码的分析，延续了之前对该文件其他部分的分析。

**功能归纳：**

这部分代码主要测试了 Blink 引擎中滚动锚定功能的以下方面：

1. **恢复滚动锚点（Restore Anchor）：**
    *   测试了在没有现有锚点对象的情况下，能否成功恢复滚动锚点，并验证恢复后的滚动位置是否正确。
    *   测试了在已经存在锚点对象的情况下，能否成功恢复滚动锚点，并验证恢复后的锚点对象和滚动位置是否符合预期。

2. **删除匿名块的安全性：**
    *   测试了在删除一个会导致匿名块也被删除的元素后，滚动锚定功能是否会发生崩溃。这是一个回归测试，旨在防止之前版本中存在的崩溃问题。

3. **滚动锚定与动画的协同工作：**
    *   测试了当页面内容变化导致滚动范围调整时，滚动锚定是否能正确调整滚动动画的偏移量。这涉及到在元素显示/隐藏时，滚动区域大小的变化。

4. **动态多列布局的安全性：**
    *   测试了在动态修改元素的字体大小和列布局属性后，滚动锚定功能是否会发生崩溃。这是一个回归测试，旨在防止在处理动态多列布局时可能出现的崩溃问题。

5. **滚动锚定与 "在页面中查找" 功能的优先级：**
    *   测试了当页面内容发生变化时，"在页面中查找" 功能的匹配结果是否会被优先考虑，以保持其在可视区域内。
    *   测试了当元素获得焦点时，焦点元素的可见性是否会优先于 "在页面中查找" 的匹配结果，即滚动锚定会优先保证焦点元素可见。
    *   测试了当焦点元素位于 `position: sticky` 的容器内时，滚动锚定是否会跳过该焦点元素，而选择其他合适的锚点。

6. **SVG 相关的滚动锚定问题：**
    *   测试了在特定情况下（涉及 SVG、foreignObject 和动态样式修改）是否会发生崩溃。这是一个回归测试，旨在防止在处理包含 SVG 的复杂布局时可能出现的崩溃问题。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

*   **JavaScript:**  这些测试使用 JavaScript API 来操作 DOM，例如 `SetBodyInnerHTML` 设置 HTML 内容，`GetDocument().getElementById()` 获取元素，`remove()` 删除元素，`setAttribute()` 修改属性，`scrollIntoView()` 滚动到元素等。滚动锚定功能的触发通常与 JavaScript 对 DOM 的修改有关。
    *   **举例：**  `GetDocument().getElementById(AtomicString("deleteMe"))->remove();`  这行代码使用 JavaScript 的 `remove()` 方法来删除 HTML 元素。

*   **HTML:** 测试用例中使用了 HTML 结构来构建测试场景。不同的 HTML 结构会影响滚动条的出现、元素的位置和大小，从而影响滚动锚定的行为。
    *   **举例：**  `<div id='block1'>abc</div>`  定义了一个带有 ID 的 HTML `div` 元素，用于作为滚动锚点的目标。

*   **CSS:**  测试用例中使用了 CSS 样式来控制元素的布局和行为，例如 `height` 设置高度，`margin` 设置外边距，`display: none/block` 控制元素的显示与隐藏，`columns` 定义多列布局，`font-size` 设置字体大小，`position: sticky` 设置粘性定位等。这些 CSS 属性直接影响了滚动锚定的计算和行为。
    *   **举例：** `<style> body { height: 1000px; margin: 0; } div { height: 100px } </style>` 定义了 `body` 和 `div` 元素的 CSS 样式。
    *   **举例：** `target->SetInlineStyleProperty(CSSPropertyID::kColumns, "2");` 使用 Blink 内部 API 设置元素的 `columns` CSS 属性。

**逻辑推理 (假设输入与输出):**

以 `RestoreAnchorWithoutExistingAnchorObject` 测试为例：

*   **假设输入:**
    *   HTML 内容为：`<style> body { height: 1000px; margin: 0; } div { height: 100px } </style> <div id='block1'>abc</div> <div id='block2'>def</div>`
    *   初始滚动位置为 0。
    *   `serialized_anchor` 对象指定锚点为 `#block1`，逻辑偏移为 (0, 0)。
*   **预期输出:**
    *   `RestoreAnchor` 方法返回 `true` (表示恢复成功)。
    *   `GetScrollAnchor(LayoutViewport()).AnchorObject()` 返回非空值 (表示成功创建了锚点对象)。
    *   `LayoutViewport()->ScrollOffsetInt().y()` 返回 0 (表示滚动位置已调整到 `#block1` 的顶部)。

以 `ClampAdjustsAnchorAnimation` 测试为例：

*   **假设输入:**
    *   初始 HTML 和 CSS 结构如代码所示。
    *   初始滚动位置为 (0, 2000)。
    *   随后，`#hidden` 元素的 `display` 属性从 `none` 变为 `block`。
*   **预期输出:**
    *   在 `#hidden` 显示后，`LayoutViewport()->GetScrollAnimator().ImplOnlyAnimationAdjustmentForTesting()` 返回 `gfx::Vector2d(0, 200)`，表示滚动动画的偏移量被调整。
    *   随后，`#hidden` 的 `display` 属性被移除。
    *   再次检查，`LayoutViewport()->GetScrollAnimator().ImplOnlyAnimationAdjustmentForTesting()` 返回 `gfx::Vector2d(0, 0)`，表示动画偏移量被重置。

**用户或编程常见的使用错误及举例说明：**

这些测试用例更多关注的是 Blink 引擎内部的逻辑和潜在的 bug，而不是直接针对用户或编程错误。然而，从这些测试中，我们可以推断出一些可能导致问题的用户或编程行为：

*   **动态修改影响布局的关键 CSS 属性：**  例如，频繁或不当的修改元素的 `display`、`position`、`height` 等属性，特别是在涉及到滚动容器的情况下，可能会触发滚动锚定中的边缘情况或 bug，如 `ClampAdjustsAnchorAnimation` 和 `DynamicMultiColumnCrash` 旨在防止的崩溃。
    *   **举例：** 使用 JavaScript 频繁切换一个包含大量内容的元素的 `display: none` 和 `display: block`，可能导致滚动位置意外跳动，而滚动锚定旨在缓解这种情况，但如果引擎自身存在 bug，则可能导致崩溃。

*   **不恰当的 DOM 操作：** 例如，在滚动锚定正在工作时删除或移动作为锚点的元素，可能导致意想不到的行为或崩溃，`DeleteAnonymousBlockCrash` 就是一个例子。
    *   **举例：**  用户可能通过 JavaScript 删除一个元素，而这个元素的删除会影响到周围匿名块的结构，如果滚动锚定没有正确处理这种情况，就可能导致问题。

*   **对 "在页面中查找" 功能的误解：** 用户可能期望在页面内容动态变化时，查找到的文本始终保持在屏幕的完全相同的位置，但实际情况是，滚动锚定会在一定程度上保持相对位置，但绝对位置可能会因为内容的增减而有所调整。`FindInPageResultPrioritized` 等测试确保了在合理范围内优先保持查找结果的可见性。

**归纳其功能：**

总而言之，这部分 `scroll_anchor_test.cc` 文件中的测试用例主要负责验证 Blink 引擎的滚动锚定功能在各种场景下的正确性和鲁棒性。这些场景包括：正常的锚点恢复、涉及匿名块的删除操作、与 CSS 动画的协同、动态多列布局、与 "在页面中查找" 功能的交互，以及涉及 SVG 元素的特定情况。这些测试旨在防止由于页面内容的动态变化而导致的滚动位置意外跳动，并确保在各种复杂情况下引擎不会崩溃。它们覆盖了与 JavaScript DOM 操作、HTML 结构和 CSS 样式密切相关的滚动锚定功能。

### 提示词
```
这是目录为blink/renderer/core/layout/scroll_anchor_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
GetScrollAnchor(LayoutViewport()).RestoreAnchor(serialized_anchor));
  EXPECT_EQ(LayoutViewport()->ScrollOffsetInt().y(), 100);
}

TEST_F(ScrollAnchorTest, RestoreAnchorSucceedsWithExistingAnchorObject) {
  SetBodyInnerHTML(
      "<style> body { height: 1000px; margin: 0; } div { height: 100px } "
      "</style>"
      "<div id='block1'>abc</div>"
      "<div id='block2'>def</div>");

  EXPECT_FALSE(GetScrollAnchor(LayoutViewport()).AnchorObject());

  SerializedAnchor serialized_anchor("#block1", LogicalOffset(0, 0));

  EXPECT_TRUE(
      GetScrollAnchor(LayoutViewport()).RestoreAnchor(serialized_anchor));
  EXPECT_TRUE(GetScrollAnchor(LayoutViewport()).AnchorObject());
  EXPECT_EQ(LayoutViewport()->ScrollOffsetInt().y(), 0);

  EXPECT_TRUE(
      GetScrollAnchor(LayoutViewport()).RestoreAnchor(serialized_anchor));
  EXPECT_TRUE(GetScrollAnchor(LayoutViewport()).AnchorObject());
  EXPECT_EQ(LayoutViewport()->ScrollOffsetInt().y(), 0);
}

TEST_F(ScrollAnchorTest, DeleteAnonymousBlockCrash) {
  SetBodyInnerHTML(R"HTML(
    <div>
      <div id="deleteMe" style="height:20000px;"></div>
      torsk
    </div>
  )HTML");

  // Removing #deleteMe will also remove the anonymous block around the text
  // node. This would cause NG to point to dead layout objects, prior to
  // https://chromium-review.googlesource.com/1193868 and therefore crash.

  ScrollLayoutViewport(ScrollOffset(0, 20000));
  GetDocument().getElementById(AtomicString("deleteMe"))->remove();
  Update();
}

TEST_F(ScrollAnchorTest, ClampAdjustsAnchorAnimation) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin: 0 }
      .content {
        height: 45vh;
        background: lightblue;
      }
      #hidden {
        height: 200px;
        display: none;
      }
    </style>
    <div class="content" id=one></div>
    <div id="hidden"></div>
    <div class="content" id=two></div>
    <div class="content" id=three></div>
    <div class="content" id=four></div>
  )HTML");
  LayoutViewport()->SetScrollOffset(ScrollOffset(0, 2000),
                                    mojom::blink::ScrollType::kUser);
  Update();
  GetDocument()
      .getElementById(AtomicString("hidden"))
      ->setAttribute(html_names::kStyleAttr, AtomicString("display:block"));
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  EXPECT_EQ(gfx::Vector2d(0, 200),
            LayoutViewport()
                ->GetScrollAnimator()
                .ImplOnlyAnimationAdjustmentForTesting());
  GetDocument()
      .getElementById(AtomicString("hidden"))
      ->setAttribute(html_names::kStyleAttr, g_empty_atom);
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  // The clamping scroll after resizing scrollable overflow to be smaller
  // should adjust the animation back to 0.
  EXPECT_EQ(gfx::Vector2d(0, 0), LayoutViewport()
                                     ->GetScrollAnimator()
                                     .ImplOnlyAnimationAdjustmentForTesting());
}

// crbug.com/1413945
TEST_F(ScrollAnchorTest, DynamicMultiColumnCrash) {
  SetBodyInnerHTML(R"HTML(
    <div id="id125" style="container:foo/size; overflow-y:hidden;
        writing-mode:vertical-rl;">
    x</div>)HTML");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  Element* target = GetDocument().getElementById(AtomicString("id125"));
  target->SetInlineStyleProperty(CSSPropertyID::kFontSize, "0");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  target->SetInlineStyleProperty(CSSPropertyID::kColumns, "2");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  // Pass if no crashes.
}

class ScrollAnchorTestFindInPageClient : public mojom::blink::FindInPageClient {
 public:
  ~ScrollAnchorTestFindInPageClient() override = default;

  void SetFrame(WebLocalFrameImpl* frame) {
    frame->GetFindInPage()->SetClient(receiver_.BindNewPipeAndPassRemote());
  }

  void SetNumberOfMatches(
      int request_id,
      unsigned int current_number_of_matches,
      mojom::blink::FindMatchUpdateType final_update) final {
    count_ = current_number_of_matches;
  }

  void SetActiveMatch(int request_id,
                      const gfx::Rect& active_match_rect,
                      int active_match_ordinal,
                      mojom::blink::FindMatchUpdateType final_update) final {}

  int Count() const { return count_; }
  void Reset() { count_ = -1; }

 private:
  int count_ = -1;
  mojo::Receiver<mojom::blink::FindInPageClient> receiver_{this};
};

class ScrollAnchorFindInPageTest : public testing::Test {
 public:
  void SetUp() override { web_view_helper_.Initialize(); }
  void TearDown() override { web_view_helper_.Reset(); }

  Document& GetDocument() {
    return *static_cast<Document*>(
        web_view_helper_.LocalMainFrame()->GetDocument());
  }
  FindInPage* GetFindInPage() {
    return web_view_helper_.LocalMainFrame()->GetFindInPage();
  }
  WebLocalFrameImpl* LocalMainFrame() {
    return web_view_helper_.LocalMainFrame();
  }

  void UpdateAllLifecyclePhasesForTest() {
    GetDocument().View()->UpdateAllLifecyclePhasesForTest();
  }

  void SetHtmlInnerHTML(const char* content) {
    GetDocument().documentElement()->setInnerHTML(String::FromUTF8(content));
    UpdateAllLifecyclePhasesForTest();
  }

  void ResizeAndFocus() {
    web_view_helper_.Resize(gfx::Size(640, 480));
    web_view_helper_.GetWebView()->MainFrameWidget()->SetFocus(true);
    test::RunPendingTasks();
  }

  mojom::blink::FindOptionsPtr FindOptions(bool new_session = true) {
    auto find_options = mojom::blink::FindOptions::New();
    find_options->run_synchronously_for_testing = true;
    find_options->new_session = new_session;
    find_options->forward = true;
    return find_options;
  }

  void Find(String search_text,
            ScrollAnchorTestFindInPageClient& client,
            bool new_session = true) {
    client.Reset();
    GetFindInPage()->Find(FAKE_FIND_ID, search_text, FindOptions(new_session));
    test::RunPendingTasks();
  }

  ScrollableArea* LayoutViewport() {
    return GetDocument().View()->LayoutViewport();
  }

  const int FAKE_FIND_ID = 1;

 private:
  test::TaskEnvironment task_environment_;
  frame_test_helpers::WebViewHelper web_view_helper_;
};

TEST_F(ScrollAnchorFindInPageTest, FindInPageResultPrioritized) {
  ResizeAndFocus();
  SetHtmlInnerHTML(R"HTML(
    <style>
    body { height: 4000px }
    .spacer { height: 100px }
    #growing { height: 100px }
    </style>

    <div class=spacer></div>
    <div class=spacer></div>
    <div class=spacer></div>
    <div class=spacer></div>
    <div id=growing></div>
    <div class=spacer></div>
    <div id=target>findme</div>
    <div class=spacer></div>
    <div class=spacer></div>
  )HTML");

  LayoutViewport()->SetScrollOffset(ScrollOffset(0, 150),
                                    mojom::blink::ScrollType::kUser);

  const String search_text = "findme";
  ScrollAnchorTestFindInPageClient client;
  client.SetFrame(LocalMainFrame());
  Find(search_text, client);
  ASSERT_EQ(1, client.Count());

  // Save the old bounds for comparison.
  auto* old_bounds = GetDocument()
                         .getElementById(AtomicString("target"))
                         ->GetBoundingClientRect();

  GetDocument()
      .getElementById(AtomicString("growing"))
      ->setAttribute(html_names::kStyleAttr, AtomicString("height: 3000px"));
  UpdateAllLifecyclePhasesForTest();

  auto* new_bounds = GetDocument()
                         .getElementById(AtomicString("target"))
                         ->GetBoundingClientRect();

  // The y coordinate of the target should not change.
  EXPECT_EQ(old_bounds->y(), new_bounds->y());
}

TEST_F(ScrollAnchorFindInPageTest, FocusPrioritizedOverFindInPage) {
  ResizeAndFocus();
  SetHtmlInnerHTML(R"HTML(
    <style>
    body { height: 4000px }
    .spacer { height: 100px }
    #growing { height: 100px }
    #focus_target { height: 10px }
    </style>

    <div class=spacer></div>
    <div class=spacer></div>
    <div class=spacer></div>
    <div class=spacer></div>
    <div id=focus_target contenteditable></div>
    <div id=growing></div>
    <div id=find_target>findme</div>
    <div class=spacer></div>
    <div class=spacer></div>
  )HTML");

  LayoutViewport()->SetScrollOffset(ScrollOffset(0, 150),
                                    mojom::blink::ScrollType::kUser);

  const String search_text = "findme";
  ScrollAnchorTestFindInPageClient client;
  client.SetFrame(LocalMainFrame());
  Find(search_text, client);
  ASSERT_EQ(1, client.Count());

  GetDocument().getElementById(AtomicString("focus_target"))->Focus();

  // Save the old bounds for comparison.
  auto* old_focus_bounds = GetDocument()
                               .getElementById(AtomicString("focus_target"))
                               ->GetBoundingClientRect();
  auto* old_find_bounds = GetDocument()
                              .getElementById(AtomicString("find_target"))
                              ->GetBoundingClientRect();

  GetDocument()
      .getElementById(AtomicString("growing"))
      ->setAttribute(html_names::kStyleAttr, AtomicString("height: 3000px"));
  UpdateAllLifecyclePhasesForTest();

  auto* new_focus_bounds = GetDocument()
                               .getElementById(AtomicString("focus_target"))
                               ->GetBoundingClientRect();
  auto* new_find_bounds = GetDocument()
                              .getElementById(AtomicString("find_target"))
                              ->GetBoundingClientRect();

  // `focus_target` should remain where it is, since it is prioritized.
  // `find_target`, however, is shifted.
  EXPECT_EQ(old_focus_bounds->y(), new_focus_bounds->y());
  EXPECT_NE(old_find_bounds->y(), new_find_bounds->y());
}

TEST_F(ScrollAnchorFindInPageTest, FocusedUnderStickyIsSkipped) {
  ResizeAndFocus();
  SetHtmlInnerHTML(R"HTML(
    <style>
    body { height: 4000px; position: relative; }
    .spacer { height: 100px }
    #growing { height: 100px }
    .sticky { position: sticky; top: 10px; }
    #target { width: 10px; height: 10px; }
    </style>

    <div class=spacer></div>
    <div class=spacer></div>
    <div class=spacer></div>
    <div class=spacer></div>
    <div id=growing></div>
    <div class=spacer></div>
    <div id=check></div>
    <div class=sticky>
      <div id=target contenteditable></div>
    </div>
    <div class=spacer></div>
    <div class=spacer></div>
  )HTML");

  LayoutViewport()->SetScrollOffset(ScrollOffset(0, 150),
                                    mojom::blink::ScrollType::kUser);

  GetDocument().getElementById(AtomicString("target"))->Focus();

  // Save the old bounds for comparison. Use #check, since sticky won't move
  // regardless of scroll anchoring.
  auto* old_bounds = GetDocument()
                         .getElementById(AtomicString("check"))
                         ->GetBoundingClientRect();

  GetDocument()
      .getElementById(AtomicString("growing"))
      ->setAttribute(html_names::kStyleAttr, AtomicString("height: 3000px"));
  UpdateAllLifecyclePhasesForTest();

  auto* new_bounds = GetDocument()
                         .getElementById(AtomicString("check"))
                         ->GetBoundingClientRect();

  // The y coordinate of #check should change since #target is not a valid
  // anchor, so we should have selected one of the spacers as the anchor.
  EXPECT_NE(old_bounds->y(), new_bounds->y());
}

class ScrollAnchorPageTest : public RenderingTest {};

// crbug.com/1443633
TEST_F(ScrollAnchorPageTest, SvgRelativeBoundsCrashAfterClearLayoutResults) {
  USE_NON_OVERLAY_SCROLLBARS_OR_QUIT();
  SetBodyInnerHTML(R"HTML(
<style>body { font-size: 18px; }</style>
<div style="overflow:auto; columns:1; column-fill:auto; width:300px; height:350px;">
  <svg viewbox="0 0 100 100">
    <foreignObject style="width:100px; height:2px;">
      <span id="target"><br>foo</span>
    </foreignObject>
  </svg>
  <div id="scrollbarSummoner" style="display:none;">
    <div style="height:200px;"></div>
  </div>
</div>)HTML");
  Document& doc = GetDocument();
  doc.UpdateStyleAndLayout(DocumentUpdateReason::kTest);

  doc.getElementById(AtomicString("target"))->scrollIntoView();
  doc.getElementById(AtomicString("scrollbarSummoner"))
      ->setAttribute(html_names::kStyleAttr,
                     AtomicString("display:block; contain:size; height:0"));

  // During the following layout, ClearLayoutResults() for the first <div> was
  // called, then ScrollAnchor::NotifyBeforeLayout() for <foreignObject> was
  // called. It accessed the geometry of the first <div>.
  doc.UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  // Pass if no crashes.
}
}
```