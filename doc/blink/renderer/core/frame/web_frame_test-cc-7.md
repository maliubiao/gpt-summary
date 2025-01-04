Response:
The user wants a summary of the functionalities present in the provided code snippet from `web_frame_test.cc`. This involves:

1. **Identifying the core functionalities being tested.**  The code consists of various `TEST_F` methods, each testing a specific aspect of `WebFrame` or related classes.
2. **Relating these functionalities to web technologies (JavaScript, HTML, CSS).** Look for operations that directly interact with or manipulate web content.
3. **Inferring logic and behavior.** Analyze the test setup, actions performed, and assertions made to understand the intended functionality. Consider edge cases and potential issues.
4. **Identifying potential user/developer errors.** Think about how incorrect usage of the tested APIs could lead to problems.
5. **Summarizing the overall purpose of this specific part of the test file.** Since it's part 8 of 19, focus on the themes covered in this section.

**Breakdown of the code:**

* **`FindDetachFrameWhileFinding` and `FindDetachFrameWhileScopingStrings`:** These tests seem to focus on the behavior of the "find in page" functionality when a frame is detached during the find or scoping process.
* **`ResetMatchCount`:** This test likely checks if the method to reset the count of matches found during "find in page" works correctly.
* **`SetTickmarks`:** This test is about setting visual markers (tickmarks) for find results, potentially both on the main view and within scrollable elements.
* **`FindInPageJavaScriptUpdatesDOM`:** This tests how the "find in page" functionality handles dynamic changes to the DOM made by JavaScript.
* **`FindInPageJavaScriptUpdatesDOMProperOrdinal`:**  Similar to the previous test, but specifically checking if the ordinal (index) of the active match is correctly updated after DOM manipulation.
* **`FindInPageStopFindActionKeepSelectionInAnotherDocument`:**  This appears to test a scenario where "find in page" is stopped while a selection exists, and the user navigates to a different document.
* **`FindInPageForcedRedoOfFindInPage`:** This tests the behavior when "find in page" is triggered multiple times, including cases where a forced re-search is requested.
* **`SelectRange`:** This set of tests (including variations like `SelectRangeDefaultHandleVisibility`, `SelectRangeHideHandle`, etc.) focuses on programmatically selecting ranges of text within a frame, including scenarios with iframes and contenteditable elements.
* **`MoveRangeSelectionExtent`:** This test likely explores how the selection can be extended or moved after an initial selection is made.

**Connecting to Web Technologies:**

* **JavaScript:**  Several tests explicitly use JavaScript (`frame->ExecuteScript`) to modify the DOM and then check how "find in page" reacts. The `selectElement` function suggests interaction with DOM elements via JavaScript.
* **HTML:** The tests load HTML files (`RegisterMockedHttpURLLoad`) which provide the content for testing the "find in page" and text selection functionalities. The tests interact with specific HTML elements like `div`, `textarea`, `input`, and iframes.
* **CSS:** While not explicitly manipulated, the layout and rendering of the HTML content (which is influenced by CSS) are implicitly involved in how text ranges are selected and how tickmarks are positioned.

**Logic and Assumptions:**

* **Assumption:** The `TestFindInPageClient` class is a mock or helper class used to observe the behavior of the "find in page" functionality (e.g., counting matches, tracking the active index).
* **Assumption:** `RunPendingTasks()` simulates the processing of asynchronous operations.
* **Logic:** The tests typically follow a pattern of: setting up the environment (loading a page, creating frames), performing an action (initiating a find, selecting a range), and then asserting that the state is as expected (number of matches, selected text, etc.).

**User/Developer Errors:**

* **Detaching frames during find:** Developers might inadvertently detach a frame while a "find in page" operation is in progress, and these tests verify the engine handles this gracefully.
* **Incorrectly managing the "find in page" state:**  Not properly resetting or managing the "find in page" state could lead to unexpected behavior.
* **Misusing `SelectRange`:**  Providing invalid coordinates or trying to select across non-selectable boundaries could lead to unexpected selection results.

**Summary of Part 8:**

This section of `web_frame_test.cc` primarily focuses on testing the **"find in page" functionality** and **programmatic text selection capabilities** within web frames. It covers scenarios involving dynamic DOM updates via JavaScript, handling frame detachments during find operations, controlling the display of selection handles, and accurately selecting text ranges, including in iframes and contenteditable elements. The tests aim to ensure the robustness and correctness of these core features of a web browser engine.
这是 `blink/renderer/core/frame/web_frame_test.cc` 文件的第 8 部分，主要关注以下功能的测试：

**1. 查找功能 (Find in Page) 的高级场景:**

* **在查找或作用域化字符串匹配时，分离 Frame:**  这两个测试 (`FindDetachFrameWhileFinding` 和 `FindDetachFrameWhileScopingStrings`) 验证了在查找过程中或开始对匹配项进行作用域化（scoping）时，如果将一个 iframe 从主框架中分离（detach），查找功能是否能够正确处理，避免崩溃或其他错误。
    * **假设输入:** 一个包含 iframe 的 HTML 页面，查找某个字符串。在查找开始后或作用域化开始后，通过 JavaScript 代码移除该 iframe 元素。
    * **预期输出:**  查找功能能够完成，并返回预期的结果状态（例如，`FindResultsAreReady()` 的真假）。
    * **与 JavaScript, HTML 的关系:** 这些测试直接涉及到 HTML 结构（iframe 元素）和 JavaScript 对 DOM 的操作（移除元素）。

* **重置匹配计数 (ResetMatchCount):** 测试 `ResetMatchCount` 方法是否能够正确地清除之前查找操作的匹配计数。这通常用于在开始新的查找或取消当前查找时重置状态。
    * **假设输入:** 执行一次查找操作后，调用 `ResetMatchCount()`。
    * **预期输出:** 随后的查找操作会重新计算匹配项，而不会受到之前计数的影响。

* **设置高亮标记 (SetTickmarks):** 测试 `SetTickmarks` 方法，该方法允许在页面中为查找结果设置自定义的视觉标记（小矩形）。测试了可以为整个主框架设置标记，也可以为特定的可滚动元素（例如 `textarea`）设置标记。
    * **假设输入:** 执行一次查找操作，然后调用 `SetTickmarks` 并传入一组 `gfx::Rect` 对象作为标记的位置和大小。
    * **预期输出:**  页面中会显示在指定位置的标记。
    * **与 HTML 的关系:**  标记的定位依赖于 HTML 元素的布局信息。

* **查找功能与 JavaScript 更新 DOM 的交互:**  `FindInPageJavaScriptUpdatesDOM` 和 `FindInPageJavaScriptUpdatesDOMProperOrdinal` 测试了在查找过程中，如果 JavaScript 修改了 DOM（例如插入新的文本节点），查找功能是否能够动态地更新匹配项。`FindInPageJavaScriptUpdatesDOMProperOrdinal` 更侧重于验证匹配项的序号（索引）是否在 DOM 更新后仍然正确。
    * **假设输入:** 加载一个包含可查找文本的页面，执行查找操作。然后，通过 JavaScript 代码插入新的包含查找字符串的文本。
    * **预期输出:** 查找功能能够识别新插入的匹配项，并更新匹配计数和当前激活的匹配项索引。
    * **与 JavaScript, HTML 的关系:** 这些测试直接测试了查找功能与 JavaScript 对 HTML DOM 的动态修改的协同工作。

* **停止查找并保持在另一个文档中的选择 (FindInPageStopFindActionKeepSelectionInAnotherDocument):**  测试了在执行查找操作并在页面中选中一些文本后，如果导航到另一个页面，然后调用 `StopFinding` 并指定保持选择，是否会发生崩溃。这个测试主要关注资源管理和避免悬 dangling 指针的问题。
    * **假设输入:** 在一个页面上执行查找并选中一段文本，然后加载另一个页面，最后调用 `StopFinding` 并保持选择。
    * **预期输出:**  不发生崩溃。

* **强制重新执行查找 (FindInPageForcedRedoOfFindInPage):** 测试在已经执行过查找操作后，再次使用相同的搜索条件和标识符执行查找，并设置 `force` 选项为 true，是否会强制重新执行查找，即使内容没有变化。
    * **假设输入:** 执行一次查找操作，然后再次执行相同的查找操作，但 `force` 选项设置为 true。
    * **预期输出:**  查找功能会重新执行，并更新匹配计数和激活的匹配项索引。

**2. 范围选择 (Range Selection) 功能:**

* **使用坐标选择范围 (SelectRange):**  测试了 `SelectRange` 方法，该方法允许通过指定起始和结束坐标在页面中选择文本。测试了基本选择、跨越滚动区域的选择。
    * **假设输入:**  页面加载完成后，调用 `SelectRange` 并传入两个 `gfx::Point` 对象作为选择的起始和结束坐标。
    * **预期输出:**  页面中指定坐标范围内的文本被选中。
    * **与 HTML 的关系:** 选择的范围是 HTML 内容的一部分。

* **控制选择句柄的可见性 (SelectRangeDefaultHandleVisibility, SelectRangeHideHandle, SelectRangeShowHandle, SelectRangePreserveHandleVisibility):** 测试了 `SelectRange` 方法的不同参数选项，用于控制移动或调整选择范围的句柄是否可见。
    * **假设输入:**  调用 `SelectRange` 并传入不同的 `WebLocalFrame::kHideSelectionHandle`、`WebLocalFrame::kShowSelectionHandle` 和 `WebLocalFrame::kPreserveHandleVisibility` 参数。
    * **预期输出:**  选择句柄的可见性符合传入的参数。

* **在 iframe 中选择范围 (SelectRangeInIframe):** 测试了在包含 iframe 的页面中，是否能够通过 `SelectRange` 方法选择 iframe 中的文本。
    * **假设输入:**  加载一个包含 iframe 的页面，并调用子框架的 `SelectRange` 方法。
    * **预期输出:**  iframe 中的指定文本被选中。
    * **与 HTML 的关系:** 涉及到 HTML 的 iframe 结构。

* **在 contenteditable 的 div 和 span 中选择范围 (SelectRangeDivContentEditable, DISABLED_SelectRangeSpanContentEditable):** 测试了在 `contenteditable` 属性设置为 true 的 `div` 和 `span` 元素中，`SelectRange` 方法的行为。特别是测试了选择范围是否会被限制在可编辑元素的边界内。注意 `DISABLED_SelectRangeSpanContentEditable`  表示这个测试当前是被禁用的，可能存在已知问题。
    * **假设输入:** 加载包含 `contenteditable` 元素的页面，并尝试使用 `SelectRange` 选择跨越可编辑和不可编辑区域的文本。
    * **预期输出:** 选择范围被限制在可编辑元素的边界内。
    * **与 HTML 的关系:** 直接测试了与 HTML `contenteditable` 属性的交互。

* **移动选择范围的起点和终点 (SelectRangeCanMoveSelectionStart, SelectRangeCanMoveSelectionEnd):** 测试了在已经有选中的文本后，再次调用 `SelectRange` 是否能够移动选择范围的起点或终点，包括跨越元素和内容可编辑区域的情况。
    * **假设输入:**  先选中一段文本，然后调用 `SelectRange` 修改选择的起始或结束位置。
    * **预期输出:**  选择范围按照指定的方式移动。

* **移动范围选择的扩展 (MoveRangeSelectionExtent):** 看起来这个测试与 `SelectRangeCanMoveSelectionStart` 和 `SelectRangeCanMoveSelectionEnd` 类似，但可能更侧重于通过拖动或其他用户交互方式来扩展选择范围。由于代码片段不完整，具体细节无法完全确定。

**常见使用错误举例:**

* **在查找过程中分离 Frame:**  开发者可能在 JavaScript 中动态地移除 iframe，而没有考虑到当前可能正在进行的查找操作，这可能导致资源泄漏或崩溃（这些测试旨在确保 Blink 引擎能够安全地处理这种情况）。
* **错误地使用 `SetTickmarks`:** 传入无效的 `gfx::Rect` 参数可能导致标记显示异常或错误。
* **在 JavaScript 修改 DOM 后，没有预期到查找结果的变化:** 开发者可能在修改 DOM 后，仍然依赖之前的查找结果，而没有意识到需要重新触发查找或更新结果。
* **`SelectRange` 使用错误的坐标:** 传入超出页面范围的坐标或不符合逻辑的起始和结束坐标可能导致选择失败或产生意外的结果。
* **尝试在不可编辑区域使用 `SelectRange` 进行选择修改:**  开发者可能会尝试使用 `SelectRange` 来扩展选择到不可编辑的区域，而期望它能像在可编辑区域一样工作。

**总结第 8 部分的功能:**

第 8 部分的 `web_frame_test.cc` 主要测试了 `WebFrame` 及其相关类中关于 **查找功能 (Find in Page)** 和 **程序化文本范围选择 (Range Selection)** 的高级和边缘场景。这些测试覆盖了在动态 DOM 更新、Frame 分离等复杂情况下查找功能的稳定性和正确性，以及各种控制和操作文本选择范围的方法。这些测试确保了 Blink 引擎在处理这些核心浏览器功能时的健壮性和可靠性。

Prompt: 
```
这是目录为blink/renderer/core/frame/web_frame_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第8部分，共19部分，请归纳一下它的功能

"""
>FindInternal(
        kFindIdentifier, search_text, *options, false));
  }
  RunPendingTasks();
  EXPECT_FALSE(find_in_page_client.FindResultsAreReady());

  // Detach the frame between finding and scoping.
  RemoveElementById(main_frame, AtomicString("frame"));

  main_frame->EnsureTextFinder().ResetMatchCount();

  for (WebLocalFrameImpl* frame = main_frame; frame;
       frame = To<WebLocalFrameImpl>(frame->TraverseNext())) {
    frame->EnsureTextFinder().StartScopingStringMatches(kFindIdentifier,
                                                        search_text, *options);
  }

  RunPendingTasks();
  EXPECT_TRUE(find_in_page_client.FindResultsAreReady());
}

TEST_F(WebFrameTest, FindDetachFrameWhileScopingStrings) {
  RegisterMockedHttpURLLoad("find_in_page.html");
  RegisterMockedHttpURLLoad("find_in_page_frame.html");

  frame_test_helpers::TestWebFrameClient frame_client;
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "find_in_page.html",
                                    &frame_client);
  web_view_helper.Resize(gfx::Size(640, 480));
  RunPendingTasks();

  const char kFindString[] = "result";
  const int kFindIdentifier = 12345;

  auto options = mojom::blink::FindOptions::New();
  options->run_synchronously_for_testing = true;
  WebString search_text = WebString::FromUTF8(kFindString);
  WebLocalFrameImpl* main_frame = web_view_helper.LocalMainFrame();
  TestFindInPageClient find_in_page_client;
  find_in_page_client.SetFrame(main_frame);

  for (WebLocalFrameImpl* frame = main_frame; frame;
       frame = To<WebLocalFrameImpl>(frame->TraverseNext())) {
    EXPECT_TRUE(frame->GetFindInPage()->FindInternal(
        kFindIdentifier, search_text, *options, false));
  }
  RunPendingTasks();
  EXPECT_FALSE(find_in_page_client.FindResultsAreReady());

  main_frame->EnsureTextFinder().ResetMatchCount();

  for (WebLocalFrameImpl* frame = main_frame; frame;
       frame = To<WebLocalFrameImpl>(frame->TraverseNext())) {
    frame->EnsureTextFinder().StartScopingStringMatches(kFindIdentifier,
                                                        search_text, *options);
  }

  // The first startScopingStringMatches will have reset the state. Detach
  // before it actually scopes.
  RemoveElementById(main_frame, AtomicString("frame"));

  for (WebLocalFrameImpl* frame = main_frame; frame;
       frame = To<WebLocalFrameImpl>(frame->TraverseNext())) {
    frame->EnsureTextFinder().StartScopingStringMatches(kFindIdentifier,
                                                        search_text, *options);
  }
  RunPendingTasks();
  EXPECT_TRUE(find_in_page_client.FindResultsAreReady());
}

TEST_F(WebFrameTest, ResetMatchCount) {
  RegisterMockedHttpURLLoad("find_in_generated_frame.html");

  frame_test_helpers::TestWebFrameClient frame_client;
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "find_in_generated_frame.html",
                                    &frame_client);
  web_view_helper.Resize(gfx::Size(640, 480));
  RunPendingTasks();

  const char kFindString[] = "result";
  const int kFindIdentifier = 12345;

  auto options = mojom::blink::FindOptions::New();
  options->run_synchronously_for_testing = true;
  WebString search_text = WebString::FromUTF8(kFindString);
  WebLocalFrameImpl* main_frame = web_view_helper.LocalMainFrame();
  TestFindInPageClient find_in_page_client;
  find_in_page_client.SetFrame(main_frame);

  // Check that child frame exists.
  EXPECT_TRUE(!!main_frame->TraverseNext());

  for (WebLocalFrameImpl* frame = main_frame; frame;
       frame = To<WebLocalFrameImpl>(frame->TraverseNext())) {
    EXPECT_FALSE(frame->GetFindInPage()->FindInternal(
        kFindIdentifier, search_text, *options, false));
  }

  RunPendingTasks();
  EXPECT_FALSE(find_in_page_client.FindResultsAreReady());

  main_frame->EnsureTextFinder().ResetMatchCount();
}

TEST_F(WebFrameTest, SetTickmarks) {
  RegisterMockedHttpURLLoad("find.html");

  frame_test_helpers::TestWebFrameClient frame_client;
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "find.html", &frame_client);
  web_view_helper.Resize(gfx::Size(640, 480));
  RunPendingTasks();

  const char kFindString[] = "foo";
  const int kFindIdentifier = 12345;

  auto options = mojom::blink::FindOptions::New();
  options->run_synchronously_for_testing = true;
  WebString search_text = WebString::FromUTF8(kFindString);
  WebLocalFrameImpl* main_frame = web_view_helper.LocalMainFrame();
  TestFindInPageClient find_in_page_client;
  find_in_page_client.SetFrame(main_frame);
  EXPECT_TRUE(main_frame->GetFindInPage()->FindInternal(
      kFindIdentifier, search_text, *options, false));

  main_frame->EnsureTextFinder().ResetMatchCount();
  main_frame->EnsureTextFinder().StartScopingStringMatches(
      kFindIdentifier, search_text, *options);

  RunPendingTasks();
  EXPECT_TRUE(find_in_page_client.FindResultsAreReady());

  const Vector<gfx::Rect> kExpectedOverridingTickmarks = {
      gfx::Rect(0, 0, 100, 100), gfx::Rect(0, 20, 100, 100),
      gfx::Rect(0, 30, 100, 100)};
  const Vector<gfx::Rect> kExpectedOverridingTickmarksIntRect = {
      kExpectedOverridingTickmarks[0], kExpectedOverridingTickmarks[1],
      kExpectedOverridingTickmarks[2]};
  const Vector<gfx::Rect> kResetTickmarks;

  {
    // Test SetTickmarks() with a null target WebElement.
    //
    // Get the tickmarks for the original find request. It should have 4
    // tickmarks, given the search performed above.
    LocalFrameView* frame_view =
        web_view_helper.LocalMainFrame()->GetFrameView();
    ScrollableArea* layout_viewport = frame_view->LayoutViewport();
    Vector<gfx::Rect> original_tickmarks = layout_viewport->GetTickmarks();
    EXPECT_EQ(4u, original_tickmarks.size());

    // Override the tickmarks.
    main_frame->SetTickmarks(WebElement(), kExpectedOverridingTickmarks);

    // Check the tickmarks are overridden correctly.
    Vector<gfx::Rect> overriding_tickmarks_actual =
        layout_viewport->GetTickmarks();
    EXPECT_EQ(kExpectedOverridingTickmarksIntRect, overriding_tickmarks_actual);

    // Reset the tickmark behavior.
    main_frame->SetTickmarks(WebElement(), kResetTickmarks);

    // Check that the original tickmarks are returned
    Vector<gfx::Rect> original_tickmarks_after_reset =
        layout_viewport->GetTickmarks();
    EXPECT_EQ(original_tickmarks, original_tickmarks_after_reset);
  }

  {
    // Test SetTickmarks() with a non-null target WebElement.
    //
    // Use an element from within find.html for testing. It has no tickmarks.
    WebLocalFrameImpl* frame = web_view_helper.LocalMainFrame();
    WebElement target = frame->GetDocument().GetElementById("textarea1");
    ASSERT_FALSE(target.IsNull());
    LayoutBox* box = target.ConstUnwrap<Element>()->GetLayoutBoxForScrolling();
    ASSERT_TRUE(box);
    ScrollableArea* scrollable_area = box->GetScrollableArea();
    ASSERT_TRUE(scrollable_area);
    Vector<gfx::Rect> original_tickmarks = scrollable_area->GetTickmarks();
    EXPECT_EQ(0u, original_tickmarks.size());

    // Override the tickmarks.
    main_frame->SetTickmarks(target, kExpectedOverridingTickmarks);

    // Check the tickmarks are overridden correctly.
    Vector<gfx::Rect> overriding_tickmarks_actual =
        scrollable_area->GetTickmarks();
    EXPECT_EQ(kExpectedOverridingTickmarksIntRect, overriding_tickmarks_actual);

    // Reset the tickmark behavior.
    main_frame->SetTickmarks(target, kResetTickmarks);

    // Check that the original tickmarks are returned
    Vector<gfx::Rect> original_tickmarks_after_reset =
        scrollable_area->GetTickmarks();
    EXPECT_EQ(original_tickmarks, original_tickmarks_after_reset);
  }
}

TEST_F(WebFrameTest, FindInPageJavaScriptUpdatesDOM) {
  RegisterMockedHttpURLLoad("find.html");

  frame_test_helpers::TestWebFrameClient frame_client;
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "find.html", &frame_client);
  web_view_helper.Resize(gfx::Size(640, 480));
  RunPendingTasks();

  WebLocalFrameImpl* frame = web_view_helper.LocalMainFrame();
  TestFindInPageClient find_in_page_client;
  find_in_page_client.SetFrame(frame);

  const int kFindIdentifier = 12345;
  static const char* kFindString = "foo";
  WebString search_text = WebString::FromUTF8(kFindString);
  auto options = mojom::blink::FindOptions::New();
  options->run_synchronously_for_testing = true;
  bool active_now;

  frame->EnsureTextFinder().ResetMatchCount();
  frame->EnsureTextFinder().StartScopingStringMatches(kFindIdentifier,
                                                      search_text, *options);
  RunPendingTasks();
  EXPECT_TRUE(find_in_page_client.FindResultsAreReady());

  // Find in a <div> element.
  options->new_session = false;
  EXPECT_TRUE(frame->GetFindInPage()->FindInternal(
      kFindIdentifier, search_text, *options, false, &active_now));
  EXPECT_TRUE(active_now);

  // Insert new text, which contains occurence of |searchText|.
  frame->ExecuteScript(WebScriptSource(
      "var newTextNode = document.createTextNode('bar5 foo5');"
      "var textArea = document.getElementsByTagName('textarea')[0];"
      "document.body.insertBefore(newTextNode, textArea);"));

  // Find in a <input> element.
  EXPECT_TRUE(frame->GetFindInPage()->FindInternal(
      kFindIdentifier, search_text, *options, false, &active_now));
  EXPECT_TRUE(active_now);

  // Find in the inserted text node.
  EXPECT_TRUE(frame->GetFindInPage()->FindInternal(
      kFindIdentifier, search_text, *options, false, &active_now));
  frame->GetFindInPage()->StopFinding(
      blink::mojom::StopFindAction::kStopFindActionKeepSelection);
  WebRange range = frame->SelectionRange();
  EXPECT_EQ(5, range.StartOffset());
  EXPECT_EQ(8, range.EndOffset());
  EXPECT_TRUE(frame->GetDocument().FocusedElement().IsNull());
  EXPECT_FALSE(active_now);
}

TEST_F(WebFrameTest, FindInPageJavaScriptUpdatesDOMProperOrdinal) {
  const WebString search_pattern = WebString::FromUTF8("abc");
  // We have 2 occurrences of the pattern in our text.
  const char* html =
      "foo bar foo bar foo abc bar foo bar foo bar foo bar foo bar foo bar foo "
      "bar foo bar foo bar foo bar foo bar foo bar foo bar foo bar foo bar foo "
      "bar foo bar foo abc bar <div id='new_text'></div>";

  frame_test_helpers::TestWebFrameClient frame_client;
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize(&frame_client);

  WebLocalFrameImpl* frame = web_view_helper.LocalMainFrame();
  frame_test_helpers::LoadHTMLString(frame, html,
                                     url_test_helpers::ToKURL(base_url_));
  web_view_helper.Resize(gfx::Size(640, 480));
  web_view_helper.GetWebView()->MainFrameWidget()->SetFocus(true);
  RunPendingTasks();

  TestFindInPageClient find_in_page_client;
  find_in_page_client.SetFrame(frame);
  const int kFindIdentifier = 12345;

  auto options = mojom::blink::FindOptions::New();
  options->run_synchronously_for_testing = true;
  options->new_session = true;
  options->forward = true;
  // The first search that will start the scoping process.
  frame->GetFindInPage()->Find(kFindIdentifier, search_pattern,
                               options->Clone());
  EXPECT_FALSE(find_in_page_client.FindResultsAreReady());
  RunPendingTasks();

  EXPECT_EQ(2, find_in_page_client.Count());
  EXPECT_EQ(1, find_in_page_client.ActiveIndex());

  options->new_session = false;
  // The second search will jump to the next match without any scoping.
  frame->GetFindInPage()->Find(kFindIdentifier, search_pattern,
                               options->Clone());
  // Run pending tasks to make sure IncreaseMatchCount calls passes.
  RunPendingTasks();
  EXPECT_EQ(2, find_in_page_client.Count());
  EXPECT_EQ(2, find_in_page_client.ActiveIndex());
  EXPECT_FALSE(frame->EnsureTextFinder().ScopingInProgress());

  // Insert new text, which contains occurence of |searchText|.
  frame->ExecuteScript(
      WebScriptSource("var textDiv = document.getElementById('new_text');"
                      "textDiv.innerHTML = 'foo abc';"));

  // The third search will find a new match and initiate a new scoping.
  frame->GetFindInPage()->Find(kFindIdentifier, search_pattern,
                               options->Clone());
  RunPendingTasks();

  EXPECT_EQ(3, find_in_page_client.Count());
  EXPECT_EQ(3, find_in_page_client.ActiveIndex());
}

TEST_F(WebFrameTest, FindInPageStopFindActionKeepSelectionInAnotherDocument) {
  RegisterMockedHttpURLLoad("find.html");
  RegisterMockedHttpURLLoad("hello_world.html");
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "find.html");
  ASSERT_TRUE(web_view_helper.LocalMainFrame());
  WebLocalFrameImpl* frame = web_view_helper.LocalMainFrame();
  const int kFindIdentifier = 12345;
  auto options = mojom::blink::FindOptions::New();

  // Set active match
  ASSERT_TRUE(frame->GetFindInPage()->FindInternal(
      kFindIdentifier, WebString::FromUTF8("foo"), *options, false));
  // Move to another page.
  frame_test_helpers::LoadFrame(frame, base_url_ + "hello_world.html");

  // Stop Find-In-Page. |TextFinder::active_match_| still hold a |Range| in
  // "find.html".
  frame->GetFindInPage()->StopFinding(
      blink::mojom::StopFindAction::kStopFindActionKeepSelection);

  // Pass if not crash. See http://crbug.com/719880 for details.
}

TEST_F(WebFrameTest, FindInPageForcedRedoOfFindInPage) {
  const WebString search_pattern = WebString::FromUTF8("bar");
  const char* html = "foo bar foo foo bar";
  frame_test_helpers::TestWebFrameClient frame_client;
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize(&frame_client);

  WebLocalFrameImpl* frame = web_view_helper.LocalMainFrame();
  frame_test_helpers::LoadHTMLString(frame, html,
                                     url_test_helpers::ToKURL(base_url_));
  web_view_helper.Resize(gfx::Size(640, 480));
  web_view_helper.GetWebView()->MainFrameWidget()->SetFocus(true);
  RunPendingTasks();

  TestFindInPageClient find_in_page_client;
  find_in_page_client.SetFrame(frame);
  const int kFindIdentifier = 12345;

  auto options = mojom::blink::FindOptions::New();
  options->run_synchronously_for_testing = true;
  options->new_session = true;
  options->forward = true;
  // First run.
  frame->GetFindInPage()->Find(kFindIdentifier, search_pattern,
                               options->Clone());
  RunPendingTasks();
  EXPECT_EQ(2, find_in_page_client.Count());
  EXPECT_EQ(1, find_in_page_client.ActiveIndex());

  options->force = true;
  frame->GetFindInPage()->Find(kFindIdentifier, search_pattern,
                               options->Clone());
  RunPendingTasks();
  EXPECT_EQ(2, find_in_page_client.Count());
  EXPECT_EQ(1, find_in_page_client.ActiveIndex());

  options->new_session = false;
  options->force = false;

  frame->GetFindInPage()->Find(kFindIdentifier, search_pattern,
                               options->Clone());
  RunPendingTasks();
  EXPECT_EQ(2, find_in_page_client.Count());
  EXPECT_EQ(2, find_in_page_client.ActiveIndex());

  options->new_session = true;
  options->force = true;

  frame->GetFindInPage()->Find(kFindIdentifier, search_pattern,
                               options->Clone());
  RunPendingTasks();
  EXPECT_EQ(2, find_in_page_client.Count());
  EXPECT_EQ(2, find_in_page_client.ActiveIndex());
}

static gfx::Point BottomRightMinusOne(const gfx::Rect& rect) {
  // FIXME: If we don't subtract 1 from the x- and y-coordinates of the
  // selection bounds, selectRange() will select the *next* element. That's
  // strictly correct, as hit-testing checks the pixel to the lower-right of
  // the input coordinate, but it's a wart on the API.
  if (rect.width() > 0) {
    return gfx::Point(rect.x() + rect.width() - 1,
                      rect.y() + rect.height() - 1);
  }
  return gfx::Point(rect.x() + rect.width(), rect.y() + rect.height() - 1);
}

static gfx::Rect ElementBounds(WebLocalFrame* frame, const WebString& id) {
  return gfx::Rect(frame->GetDocument().GetElementById(id).BoundsInWidget());
}

static std::string SelectionAsString(WebFrame* frame) {
  return frame->ToWebLocalFrame()->SelectionAsText().Utf8();
}

TEST_F(WebFrameTest, SelectRange) {
  WebLocalFrame* frame;
  gfx::Rect start_rect;
  gfx::Rect end_rect;

  RegisterMockedHttpURLLoad("select_range_basic.html");
  RegisterMockedHttpURLLoad("select_range_scroll.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  InitializeTextSelectionWebView(base_url_ + "select_range_basic.html",
                                 &web_view_helper);
  frame = web_view_helper.LocalMainFrame();
  EXPECT_EQ("Some test text for testing.", SelectionAsString(frame));
  web_view_helper.GetWebView()->MainFrameViewWidget()->CalculateSelectionBounds(
      start_rect, end_rect);
  frame->ExecuteCommand(WebString::FromUTF8("Unselect"));
  EXPECT_EQ("", SelectionAsString(frame));
  frame->SelectRange(start_rect.origin(), BottomRightMinusOne(end_rect));
  // On some devices, the above bottomRightMinusOne() causes the ending '.' not
  // selected.
  std::string selection_string = SelectionAsString(frame);
  EXPECT_TRUE(selection_string == "Some test text for testing." ||
              selection_string == "Some test text for testing");

  InitializeTextSelectionWebView(base_url_ + "select_range_scroll.html",
                                 &web_view_helper);
  frame = web_view_helper.LocalMainFrame();
  EXPECT_EQ("Some offscreen test text for testing.", SelectionAsString(frame));
  web_view_helper.GetWebView()->MainFrameViewWidget()->CalculateSelectionBounds(
      start_rect, end_rect);
  frame->ExecuteCommand(WebString::FromUTF8("Unselect"));
  EXPECT_EQ("", SelectionAsString(frame));
  frame->SelectRange(start_rect.origin(), BottomRightMinusOne(end_rect));
  // On some devices, the above bottomRightMinusOne() causes the ending '.' not
  // selected.
  selection_string = SelectionAsString(frame);
  EXPECT_TRUE(selection_string == "Some offscreen test text for testing." ||
              selection_string == "Some offscreen test text for testing");
}

TEST_F(WebFrameTest, SelectRangeDefaultHandleVisibility) {
  RegisterMockedHttpURLLoad("select_range_basic.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  InitializeTextSelectionWebView(base_url_ + "select_range_basic.html",
                                 &web_view_helper);

  WebLocalFrameImpl* frame = web_view_helper.LocalMainFrame();
  frame->SelectRange(WebRange(0, 5), WebLocalFrame::kHideSelectionHandle,
                     SelectionMenuBehavior::kHide,
                     WebLocalFrame::kSelectionSetFocus);
  EXPECT_FALSE(frame->SelectionRange().IsNull());

  EXPECT_FALSE(frame->GetFrame()->Selection().IsHandleVisible())
      << "By default selection handles should not be visible";
}

TEST_F(WebFrameTest, SelectRangeHideHandle) {
  RegisterMockedHttpURLLoad("select_range_basic.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  InitializeTextSelectionWebView(base_url_ + "select_range_basic.html",
                                 &web_view_helper);

  WebLocalFrameImpl* frame = web_view_helper.LocalMainFrame();
  frame->SelectRange(WebRange(0, 5), WebLocalFrame::kHideSelectionHandle,
                     SelectionMenuBehavior::kHide,
                     WebLocalFrame::kSelectionSetFocus);

  EXPECT_FALSE(frame->GetFrame()->Selection().IsHandleVisible())
      << "Selection handle should not be visible with kHideSelectionHandle";
}

TEST_F(WebFrameTest, SelectRangeShowHandle) {
  RegisterMockedHttpURLLoad("select_range_basic.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  InitializeTextSelectionWebView(base_url_ + "select_range_basic.html",
                                 &web_view_helper);

  WebLocalFrameImpl* frame = web_view_helper.LocalMainFrame();
  frame->SelectRange(WebRange(0, 5), WebLocalFrame::kShowSelectionHandle,
                     SelectionMenuBehavior::kHide,
                     WebLocalFrame::kSelectionSetFocus);

  EXPECT_TRUE(frame->GetFrame()->Selection().IsHandleVisible())
      << "Selection handle should be visible with kShowSelectionHandle";
}

TEST_F(WebFrameTest, SelectRangePreserveHandleVisibility) {
  RegisterMockedHttpURLLoad("select_range_basic.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  InitializeTextSelectionWebView(base_url_ + "select_range_basic.html",
                                 &web_view_helper);

  WebLocalFrameImpl* frame = web_view_helper.LocalMainFrame();
  frame->SelectRange(WebRange(0, 5), WebLocalFrame::kHideSelectionHandle,
                     SelectionMenuBehavior::kHide,
                     WebLocalFrame::kSelectionSetFocus);
  frame->SelectRange(WebRange(0, 6), WebLocalFrame::kPreserveHandleVisibility,
                     SelectionMenuBehavior::kHide,
                     WebLocalFrame::kSelectionSetFocus);

  EXPECT_FALSE(frame->GetFrame()->Selection().IsHandleVisible())
      << "kPreserveHandleVisibility should keep handles invisible";

  frame->SelectRange(WebRange(0, 5), WebLocalFrame::kShowSelectionHandle,
                     SelectionMenuBehavior::kHide,
                     WebLocalFrame::kSelectionSetFocus);
  frame->SelectRange(WebRange(0, 6), WebLocalFrame::kPreserveHandleVisibility,
                     SelectionMenuBehavior::kHide,
                     WebLocalFrame::kSelectionSetFocus);

  EXPECT_TRUE(frame->GetFrame()->Selection().IsHandleVisible())
      << "kPreserveHandleVisibility should keep handles visible";
}

TEST_F(WebFrameTest, SelectRangeInIframe) {
  WebFrame* frame;
  gfx::Rect start_rect;
  gfx::Rect end_rect;

  RegisterMockedHttpURLLoad("select_range_iframe.html");
  RegisterMockedHttpURLLoad("select_range_basic.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  InitializeTextSelectionWebView(base_url_ + "select_range_iframe.html",
                                 &web_view_helper);
  frame = web_view_helper.GetWebView()->MainFrame();
  WebLocalFrame* subframe = frame->FirstChild()->ToWebLocalFrame();
  EXPECT_EQ("Some test text for testing.", SelectionAsString(subframe));
  web_view_helper.GetWebView()->MainFrameViewWidget()->CalculateSelectionBounds(
      start_rect, end_rect);
  subframe->ExecuteCommand(WebString::FromUTF8("Unselect"));
  EXPECT_EQ("", SelectionAsString(subframe));
  subframe->SelectRange(start_rect.origin(), BottomRightMinusOne(end_rect));
  // On some devices, the above bottomRightMinusOne() causes the ending '.' not
  // selected.
  std::string selection_string = SelectionAsString(subframe);
  EXPECT_TRUE(selection_string == "Some test text for testing." ||
              selection_string == "Some test text for testing");
}

TEST_F(WebFrameTest, SelectRangeDivContentEditable) {
  WebLocalFrame* frame;
  gfx::Rect start_rect;
  gfx::Rect end_rect;

  RegisterMockedHttpURLLoad("select_range_div_editable.html");

  // Select the middle of an editable element, then try to extend the selection
  // to the top of the document.  The selection range should be clipped to the
  // bounds of the editable element.
  frame_test_helpers::WebViewHelper web_view_helper;
  InitializeTextSelectionWebView(base_url_ + "select_range_div_editable.html",
                                 &web_view_helper);
  frame = web_view_helper.LocalMainFrame();
  EXPECT_EQ("This text is initially selected.", SelectionAsString(frame));
  web_view_helper.GetWebView()->MainFrameViewWidget()->CalculateSelectionBounds(
      start_rect, end_rect);

  frame->SelectRange(BottomRightMinusOne(end_rect), gfx::Point());
  EXPECT_EQ("16-char header. This text is initially selected.",
            SelectionAsString(frame));

  // As above, but extending the selection to the bottom of the document.
  InitializeTextSelectionWebView(base_url_ + "select_range_div_editable.html",
                                 &web_view_helper);
  frame = web_view_helper.LocalMainFrame();

  web_view_helper.GetWebView()->MainFrameViewWidget()->CalculateSelectionBounds(
      start_rect, end_rect);
  frame->SelectRange(start_rect.origin(), BottomRightMinusOne(end_rect));
  EXPECT_EQ("This text is initially selected.", SelectionAsString(frame));
  web_view_helper.GetWebView()->MainFrameViewWidget()->CalculateSelectionBounds(
      start_rect, end_rect);

  web_view_helper.GetWebView()->MainFrameViewWidget()->CalculateSelectionBounds(
      start_rect, end_rect);
  frame->SelectRange(start_rect.origin(), gfx::Point(640, 480));
  EXPECT_EQ("This text is initially selected. 16-char footer.",
            SelectionAsString(frame));
}

// positionForPoint returns the wrong values for contenteditable spans. See
// http://crbug.com/238334.
TEST_F(WebFrameTest, DISABLED_SelectRangeSpanContentEditable) {
  WebLocalFrame* frame;
  gfx::Rect start_rect;
  gfx::Rect end_rect;

  RegisterMockedHttpURLLoad("select_range_span_editable.html");

  // Select the middle of an editable element, then try to extend the selection
  // to the top of the document.
  // The selection range should be clipped to the bounds of the editable
  // element.
  frame_test_helpers::WebViewHelper web_view_helper;
  InitializeTextSelectionWebView(base_url_ + "select_range_span_editable.html",
                                 &web_view_helper);
  frame = web_view_helper.LocalMainFrame();
  EXPECT_EQ("This text is initially selected.", SelectionAsString(frame));
  web_view_helper.GetWebView()->MainFrameViewWidget()->CalculateSelectionBounds(
      start_rect, end_rect);

  frame->SelectRange(BottomRightMinusOne(end_rect), gfx::Point());
  EXPECT_EQ("16-char header. This text is initially selected.",
            SelectionAsString(frame));

  // As above, but extending the selection to the bottom of the document.
  InitializeTextSelectionWebView(base_url_ + "select_range_span_editable.html",
                                 &web_view_helper);
  frame = web_view_helper.LocalMainFrame();

  web_view_helper.GetWebView()->MainFrameViewWidget()->CalculateSelectionBounds(
      start_rect, end_rect);
  frame->SelectRange(start_rect.origin(), BottomRightMinusOne(end_rect));
  EXPECT_EQ("This text is initially selected.", SelectionAsString(frame));
  web_view_helper.GetWebView()->MainFrameViewWidget()->CalculateSelectionBounds(
      start_rect, end_rect);

  EXPECT_EQ("This text is initially selected.", SelectionAsString(frame));
  web_view_helper.GetWebView()->MainFrameViewWidget()->CalculateSelectionBounds(
      start_rect, end_rect);
  frame->SelectRange(start_rect.origin(), gfx::Point(640, 480));
  EXPECT_EQ("This text is initially selected. 16-char footer.",
            SelectionAsString(frame));
}

TEST_F(WebFrameTest, SelectRangeCanMoveSelectionStart) {
  RegisterMockedHttpURLLoad("text_selection.html");
  frame_test_helpers::WebViewHelper web_view_helper;
  InitializeTextSelectionWebView(base_url_ + "text_selection.html",
                                 &web_view_helper);
  WebLocalFrame* frame = web_view_helper.LocalMainFrame();

  // Select second span. We can move the start to include the first span.
  frame->ExecuteScript(WebScriptSource("selectElement('header_2');"));
  EXPECT_EQ("Header 2.", SelectionAsString(frame));
  frame->SelectRange(BottomRightMinusOne(ElementBounds(frame, "header_2")),
                     ElementBounds(frame, "header_1").origin());
  EXPECT_EQ("Header 1. Header 2.", SelectionAsString(frame));

  // We can move the start and end together.
  frame->ExecuteScript(WebScriptSource("selectElement('header_1');"));
  EXPECT_EQ("Header 1.", SelectionAsString(frame));
  frame->SelectRange(BottomRightMinusOne(ElementBounds(frame, "header_1")),
                     BottomRightMinusOne(ElementBounds(frame, "header_1")));
  EXPECT_EQ("", SelectionAsString(frame));
  // Selection is a caret, not empty.
  EXPECT_FALSE(frame->SelectionRange().IsNull());

  // We can move the start across the end.
  frame->ExecuteScript(WebScriptSource("selectElement('header_1');"));
  EXPECT_EQ("Header 1.", SelectionAsString(frame));
  frame->SelectRange(BottomRightMinusOne(ElementBounds(frame, "header_1")),
                     BottomRightMinusOne(ElementBounds(frame, "header_2")));
  EXPECT_EQ(" Header 2.", SelectionAsString(frame));

  // Can't extend the selection part-way into an editable element.
  frame->ExecuteScript(WebScriptSource("selectElement('footer_2');"));
  EXPECT_EQ("Footer 2.", SelectionAsString(frame));
  frame->SelectRange(BottomRightMinusOne(ElementBounds(frame, "footer_2")),
                     ElementBounds(frame, "editable_2").origin());
  EXPECT_EQ(" [ Footer 1. Footer 2.", SelectionAsString(frame));

  // Can extend the selection completely across editable elements.
  frame->ExecuteScript(WebScriptSource("selectElement('footer_2');"));
  EXPECT_EQ("Footer 2.", SelectionAsString(frame));
  frame->SelectRange(BottomRightMinusOne(ElementBounds(frame, "footer_2")),
                     ElementBounds(frame, "header_2").origin());
  EXPECT_EQ("Header 2. ] [ Editable 1. Editable 2. ] [ Footer 1. Footer 2.",
            SelectionAsString(frame));

  // If the selection is editable text, we can't extend it into non-editable
  // text.
  frame->ExecuteScript(WebScriptSource("selectElement('editable_2');"));
  EXPECT_EQ("Editable 2.", SelectionAsString(frame));
  frame->SelectRange(BottomRightMinusOne(ElementBounds(frame, "editable_2")),
                     ElementBounds(frame, "header_2").origin());
  EXPECT_EQ("[ Editable 1. Editable 2.", SelectionAsString(frame));
}

TEST_F(WebFrameTest, SelectRangeCanMoveSelectionEnd) {
  RegisterMockedHttpURLLoad("text_selection.html");
  frame_test_helpers::WebViewHelper web_view_helper;
  InitializeTextSelectionWebView(base_url_ + "text_selection.html",
                                 &web_view_helper);
  WebLocalFrame* frame = web_view_helper.LocalMainFrame();

  // Select first span. We can move the end to include the second span.
  frame->ExecuteScript(WebScriptSource("selectElement('header_1');"));
  EXPECT_EQ("Header 1.", SelectionAsString(frame));
  frame->SelectRange(ElementBounds(frame, "header_1").origin(),
                     BottomRightMinusOne(ElementBounds(frame, "header_2")));
  EXPECT_EQ("Header 1. Header 2.", SelectionAsString(frame));

  // We can move the start and end together.
  frame->ExecuteScript(WebScriptSource("selectElement('header_2');"));
  EXPECT_EQ("Header 2.", SelectionAsString(frame));
  frame->SelectRange(ElementBounds(frame, "header_2").origin(),
                     ElementBounds(frame, "header_2").origin());
  EXPECT_EQ("", SelectionAsString(frame));
  // Selection is a caret, not empty.
  EXPECT_FALSE(frame->SelectionRange().IsNull());

  // We can move the end across the start.
  frame->ExecuteScript(WebScriptSource("selectElement('header_2');"));
  EXPECT_EQ("Header 2.", SelectionAsString(frame));
  frame->SelectRange(ElementBounds(frame, "header_2").origin(),
                     ElementBounds(frame, "header_1").origin());
  EXPECT_EQ("Header 1. ", SelectionAsString(frame));

  // Can't extend the selection part-way into an editable element.
  frame->ExecuteScript(WebScriptSource("selectElement('header_1');"));
  EXPECT_EQ("Header 1.", SelectionAsString(frame));
  frame->SelectRange(ElementBounds(frame, "header_1").origin(),
                     BottomRightMinusOne(ElementBounds(frame, "editable_1")));
  EXPECT_EQ("Header 1. Header 2. ] ", SelectionAsString(frame));

  // Can extend the selection completely across editable elements.
  frame->ExecuteScript(WebScriptSource("selectElement('header_1');"));
  EXPECT_EQ("Header 1.", SelectionAsString(frame));
  frame->SelectRange(ElementBounds(frame, "header_1").origin(),
                     BottomRightMinusOne(ElementBounds(frame, "footer_1")));
  EXPECT_EQ("Header 1. Header 2. ] [ Editable 1. Editable 2. ] [ Footer 1.",
            SelectionAsString(frame));

  // If the selection is editable text, we can't extend it into non-editable
  // text.
  frame->ExecuteScript(WebScriptSource("selectElement('editable_1');"));
  EXPECT_EQ("Editable 1.", SelectionAsString(frame));
  frame->SelectRange(ElementBounds(frame, "editable_1").origin(),
                     BottomRightMinusOne(ElementBounds(frame, "footer_1")));
  EXPECT_EQ("Editable 1. Editable 2. ]", SelectionAsString(frame));
}

TEST_F(WebFrameTest, MoveRangeSelectionExtent) {
  WebLocalFrameImpl* frame;
  gfx::Rect start_rect;
  gfx::Rect end_rect;

  RegisterMockedHttpURLLoad("move_range_selection_extent.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  InitializeTextSelectionWebView(b
"""


```