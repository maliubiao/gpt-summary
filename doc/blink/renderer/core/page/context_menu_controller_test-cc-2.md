Response:
The user wants a summary of the provided C++ code, which is part of Chromium's Blink rendering engine. Specifically, this file seems to be testing the functionality of the `ContextMenuController`. I need to analyze the different test cases within the code and synthesize a description of the `ContextMenuController`'s features that are being tested.

Here's a breakdown of the test cases and what they seem to be verifying:

1. **`ContextMenuControllerTest::ImageInDifferentFrame`**: Checks if requesting the context menu image node from a different frame returns null. This implies that the `ContextMenuController` needs to correctly identify the relevant frame for image context.
2. **`ContextMenuControllerTest::OpenedFromHighlight`**: Verifies if the context menu is aware of being triggered within a text highlight. This suggests the `ContextMenuController` tracks the origin of the context menu invocation.
3. **`ContextMenuControllerTest::KeyboardTriggeredContextMenuPreservesSelection`**: Tests that opening the context menu via keyboard doesn't alter the current text selection. This points to the `ContextMenuController` being able to handle different trigger mechanisms without unintended side effects.
4. **`ContextMenuControllerTest::CheckRendererIdFromContextMenuOnTextField`**: Examines if the context menu data correctly includes renderer IDs for form elements (input and textarea). This indicates that the `ContextMenuController` gathers relevant information about the target element, including form-related data.
5. **`ContextMenuControllerTest::AttributionSrc`**: Focuses on how the context menu handles the `attributionsrc` attribute on anchor elements, specifically regarding impression reporting. This suggests that the `ContextMenuController` interacts with features related to attribution and security contexts.
6. **`ContextMenuControllerTest::SelectUnselectableContent`**: Checks if the context menu extracts only the selectable parts of a selection that includes unselectable content. This highlights the `ContextMenuController`'s ability to process selections with mixed selectable/unselectable content.
7. **`ContextMenuControllerRemoteParentFrameTest::ShowContextMenuInChild`**: Tests the scenario where a context menu is triggered in a child frame of a remote frame. This verifies the inter-process communication and coordination involved in showing the context menu across frame boundaries.

Therefore, the overall function of the code seems to be testing various aspects of how the `ContextMenuController` in Blink handles context menu requests in different scenarios, including:

- Identifying the context of the menu trigger (e.g., image, text selection, keyboard).
- Gathering relevant information about the target element (e.g., form data, security attributes).
- Handling cross-frame scenarios.
- Correctly processing text selections with varying selectability.
这是`blink/renderer/core/page/context_menu_controller_test.cc`文件的第三部分，也是最后一部分，主要功能是**测试 Blink 渲染引擎中 `ContextMenuController` 类的各种功能，特别是涉及到跨域框架、文本高亮、键盘触发、表单元素以及内容选择的场景**。

**总结归纳它的功能：**

总的来说，这个测试文件主要验证了 `ContextMenuController` 在以下方面的行为和逻辑：

1. **跨域框架下的图片上下文菜单：**  确保在不同的 iframe 中请求图片上下文菜单时，`ContextMenuController` 能正确处理，不会错误地返回其他 iframe 的图片节点。
2. **从文本高亮处打开上下文菜单：**  测试当用户在选中的文本区域内打开上下文菜单时，`ContextMenuController` 能正确识别并标记 `opened_from_highlight` 属性。
3. **键盘触发上下文菜单并保持选择：** 验证使用键盘快捷键打开上下文菜单时，当前选中的文本不会被取消或修改。
4. **表单元素的上下文菜单：**  检查在不同类型的表单元素（如 `<input type="text">` 和 `<textarea>`）上打开上下文菜单时，`ContextMenuController` 是否能正确获取并传递表单元素的渲染器 ID 和表单类型。
5. **`attributionsrc` 属性的处理：** 测试 `ContextMenuController` 如何处理带有 `attributionsrc` 属性的链接元素，特别是涉及到安全上下文和异步请求的情况。
6. **包含不可选择内容的文本选择：**  验证当选中的文本包含 `user-select: none` 或 `user-select: all` 样式的内容时，`ContextMenuController` 在生成上下文菜单数据时，是否能正确排除或包含这些内容。
7. **远程父框架中的上下文菜单：** 测试在远程父框架下的子框架中触发上下文菜单时，父框架是否能正确接收到上下文菜单的请求位置。

**与 JavaScript, HTML, CSS 功能的关系及举例：**

* **HTML:**
    * **`<p>` 标签：** 用于测试文本高亮场景，例如 `<p id="one">This is a test page one</p>`。
    * **`<img>` 标签：** 用于测试图片上下文菜单，例如 `<img id=target src='http://test.png'>`。
    * **`<input>` 和 `<textarea>` 标签：** 用于测试表单元素的上下文菜单，例如 `<input type="text" id="name" name="name">` 和 `<textarea id="address" name="address"></textarea>`。
    * **`<a>` 标签及 `attributionsrc` 属性：** 用于测试 `attributionsrc` 功能，例如 `<a href="https://a.com/" attributionsrc="https://b.com/">abc</a>`。
    * **`<span>` 标签和 `user-select` CSS 属性：** 用于测试包含不可选择内容的文本选择，例如 `<span style="user-select:none;">test_none</span>` 和 `<span style="user-select:all;">test_all</span>`。
    * **`<iframe>` 标签（隐式）：** 虽然代码中没有直接创建 `<iframe>`，但 `ContextMenuControllerRemoteParentFrameTest` 涉及跨域框架的场景。

* **CSS:**
    * **`user-select: none` 和 `user-select: all`：** 用于控制元素内容是否可被用户选择，测试 `ContextMenuController` 在处理这类选择时的行为。
    * **其他样式属性 (例如 `position: absolute`, `z-index`)：** 虽然出现在 `<style>` 标签中，但在这些测试中，它们通常是为了创建特定的页面布局或元素层叠关系，以模拟真实的网页环境，但与 `ContextMenuController` 的核心功能测试关系不大。

* **JavaScript:**
    * **没有直接的 JavaScript 代码。** 这个测试文件是用 C++ 编写的，用于测试 Blink 渲染引擎的 C++ 代码。但是，`ContextMenuController` 的功能最终会影响到用户通过 JavaScript 触发的上下文菜单行为。例如，JavaScript 可以通过编程方式触发上下文菜单事件，或者根据上下文菜单的内容执行不同的操作。

**逻辑推理、假设输入与输出：**

**示例 1：`ContextMenuControllerTest::ImageInDifferentFrame`**

* **假设输入：**
    1. 加载包含一个 `<img>` 标签的 HTML 页面。
    2. 在页面中创建一个 `<iframe>`，但不加载任何内容或者加载一个不包含该 `<img>` 标签的页面。
    3. 在主框架中长按（`kMenuSourceLongPress`）图片，触发上下文菜单。
    4. 调用 `ContextMenuImageNodeForFrame(nullptr)`，模拟从一个不同的（可能是空的或不同的）帧请求图片节点。
* **预期输出：**
    * `ShowContextMenu` 返回 `true`，表示上下文菜单显示成功。
    * `ContextMenuImageNodeForFrame(nullptr)` 返回 `nullptr`，表示在不同的帧中找不到该图片节点。
    * 相关的 Histogram 计数会更新，反映跨帧检索的结果。

**示例 2：`ContextMenuControllerTest::OpenedFromHighlight`**

* **假设输入：**
    1. 加载包含多个 `<p>` 标签的 HTML 页面。
    2. 使用 `document->Markers().AddTextFragmentMarker()` 在其中一部分文本上添加文本片段标记。
    3. 在未被标记的 `<p>` 元素上点击右键（`kMenuSourceMouse`）。
    4. 在被标记的 `<p>` 元素上点击右键。
* **预期输出：**
    * 在未被标记的元素上打开上下文菜单时，`context_menu_data.opened_from_highlight` 为 `false`。
    * 在被标记的元素上打开上下文菜单时，`context_menu_data.opened_from_highlight` 为 `true`。

**用户或编程常见的使用错误举例：**

* **用户错误：** 用户可能会在没有选中任何文本的情况下，错误地认为从空白区域打开的上下文菜单会被标记为 `opened_from_highlight`。测试用例 `OpenedFromHighlight` 确保了只有在实际选中了带有标记的文本时，该标志才会被设置。
* **编程错误：** 开发者在处理跨域 iframe 时，可能会错误地尝试直接访问或操作其他 iframe 的 DOM 元素，而没有考虑到浏览器的安全限制。`ContextMenuControllerTest::ImageInDifferentFrame` 测试模拟了这种情况，确保了 `ContextMenuController` 不会错误地返回其他域或 iframe 的节点。
* **开发者在使用 `attributionsrc` 时，可能会混淆安全上下文的要求。** 例如，在一个非 HTTPS 页面上使用 HTTPS 的 `attributionsrc` 可能不会按预期工作。`AttributionSrc` 测试用例验证了在不同安全上下文下 `attributionsrc` 的行为。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户浏览网页：** 用户通过浏览器访问一个包含图片、文本、表单元素和可能包含 iframe 的网页。
2. **用户触发上下文菜单：**
    * **鼠标右键点击：** 用户将鼠标指针移动到网页上的某个元素（例如图片、文本、输入框），然后点击鼠标右键。
    * **长按（移动设备）：** 用户在触摸屏设备上长按某个元素。
    * **键盘快捷键：** 用户按下特定的键盘组合键（通常是 Shift + F10 或 Context Menu 键）。
3. **浏览器事件处理：** 浏览器接收到用户的上下文菜单触发事件。
4. **Blink 渲染引擎处理：**
    * 浏览器将事件传递给 Blink 渲染引擎。
    * Blink 确定触发上下文菜单的元素和位置。
    * **`ContextMenuController` 介入：** `ContextMenuController` 接收到请求，并开始收集上下文菜单所需的信息。
    * **获取目标节点：** `ContextMenuController` 确定用户点击或长按的 DOM 节点。
    * **检查选择：** 如果是文本区域，检查是否有文本被选中，并判断是否与文本片段标记重叠。
    * **处理跨域 iframe：** 如果点击发生在 iframe 中，需要考虑跨域的限制。
    * **收集表单信息：** 如果目标是表单元素，需要获取其渲染器 ID 和类型。
    * **处理 `attributionsrc`：** 如果目标是带有 `attributionsrc` 属性的链接，需要进行相应的处理。
    * **构建上下文菜单数据：** `ContextMenuController` 创建 `ContextMenuData` 对象，其中包含了要显示在上下文菜单中的项目以及其他相关信息（例如选中的文本、链接 URL、图片 URL 等）。
5. **将数据传递给浏览器：** Blink 将 `ContextMenuData` 传递回浏览器进程。
6. **浏览器显示上下文菜单：** 浏览器根据 `ContextMenuData` 生成并显示上下文菜单。

**作为调试线索：** 当开发者在 Chromium 中调试上下文菜单相关的问题时，`context_menu_controller_test.cc` 中的测试用例可以作为非常有价值的参考和调试入口。例如：

* **复现问题：** 如果用户报告了在特定场景下上下文菜单行为异常的问题，开发者可以尝试在测试文件中找到类似的测试用例，或者编写新的测试用例来复现该问题。
* **验证修复：** 在修复了与上下文菜单相关的 bug 后，开发者可以运行这些测试用例来验证修复是否有效，并且没有引入新的问题。
* **理解代码逻辑：** 阅读测试用例可以帮助开发者更好地理解 `ContextMenuController` 的工作原理和内部逻辑，例如它是如何处理不同类型的元素、跨域场景以及用户选择的。

总而言之，这个测试文件的主要目的是确保 `ContextMenuController` 在各种复杂的网页场景下都能正确、可靠地工作，并提供准确的上下文菜单选项。

### 提示词
```
这是目录为blink/renderer/core/page/context_menu_controller_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
luder {
          top: 0;
          left: 0;
          position: absolute;
          width: 100px;
          height: 100px;
          z-index: 2;
        }
      </style>
      <img id=target src='http://test.png'>
    </body>
  )HTML");

  base::HistogramTester histograms;

  PhysicalOffset location_with_image(LayoutUnit(5), LayoutUnit(5));
  EXPECT_TRUE(ShowContextMenu(location_with_image, kMenuSourceLongPress));

  // Pass in nullptr for frame reference as a way of simulating a different
  // frame being passed in.
  Node* image_node = web_view_helper_.GetWebView()
                         ->GetPage()
                         ->GetContextMenuController()
                         .ContextMenuImageNodeForFrame(nullptr);
  EXPECT_TRUE(image_node == nullptr);

  histograms.ExpectBucketCount(
      "Blink.ContextMenu.ImageSelection.RetrievalOutcome",
      ContextMenuController::ImageSelectionRetrievalOutcome::kImageFound, 0);
  histograms.ExpectBucketCount(
      "Blink.ContextMenu.ImageSelection.RetrievalOutcome",
      ContextMenuController::ImageSelectionRetrievalOutcome::kImageNotFound, 0);
  histograms.ExpectBucketCount(
      "Blink.ContextMenu.ImageSelection.RetrievalOutcome",
      ContextMenuController::ImageSelectionRetrievalOutcome::
          kCrossFrameRetrieval,
      1);
}

TEST_F(ContextMenuControllerTest, OpenedFromHighlight) {
  WebURL url = url_test_helpers::ToKURL("http://www.test.com/");
  frame_test_helpers::LoadHTMLString(LocalMainFrame(),
                                     R"(<html><head><style>body
      {background-color:transparent}</style></head>
      <p id="one">This is a test page one</p>
      <p id="two">This is a test page two</p>
      <p id="three">This is a test page three</p>
      <p id="four">This is a test page four</p>
      </html>
      )",
                                     url);

  Document* document = GetDocument();
  ASSERT_TRUE(IsA<HTMLDocument>(document));

  Element* first_element = document->getElementById(AtomicString("one"));
  Element* middle_element = document->getElementById(AtomicString("one"));
  Element* third_element = document->getElementById(AtomicString("three"));
  Element* last_element = document->getElementById(AtomicString("four"));

  // Install a text fragment marker from the beginning of <p> one to near the
  // end of <p> three.
  EphemeralRange dom_range =
      EphemeralRange(Position(first_element->firstChild(), 0),
                     Position(third_element->firstChild(), 22));
  document->Markers().AddTextFragmentMarker(dom_range);
  document->UpdateStyleAndLayout(DocumentUpdateReason::kTest);

  // Opening the context menu from the last <p> should not set
  // |opened_from_highlight|.
  EXPECT_TRUE(ShowContextMenuForElement(last_element, kMenuSourceMouse));
  ContextMenuData context_menu_data = GetWebFrameClient().GetContextMenuData();
  EXPECT_FALSE(context_menu_data.opened_from_highlight);

  // Opening the context menu from the second <p> should set
  // |opened_from_highlight|.
  EXPECT_TRUE(ShowContextMenuForElement(middle_element, kMenuSourceMouse));
  context_menu_data = GetWebFrameClient().GetContextMenuData();
  EXPECT_TRUE(context_menu_data.opened_from_highlight);

  // Opening the context menu from the middle of the third <p> should set
  // |opened_from_highlight|.
  EXPECT_TRUE(ShowContextMenuForElement(third_element, kMenuSourceMouse));
  context_menu_data = GetWebFrameClient().GetContextMenuData();
  EXPECT_TRUE(context_menu_data.opened_from_highlight);
}

// Test that opening context menu with keyboard does not change text selection.
TEST_F(ContextMenuControllerTest,
       KeyboardTriggeredContextMenuPreservesSelection) {
  ContextMenuAllowedScope context_menu_allowed_scope;

  GetDocument()->documentElement()->setInnerHTML(R"HTML(
    <body>
      <p id='first'>This is a sample text."</p>
    </body>
  )HTML");

  Node* first_paragraph =
      GetDocument()->getElementById(AtomicString("first"))->firstChild();
  const auto& selected_start = Position(first_paragraph, 5);
  const auto& selected_end = Position(first_paragraph, 9);

  GetDocument()->GetFrame()->Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(selected_start, selected_end)
          .Build(),
      SetSelectionOptions());
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(GetDocument()->GetFrame()->Selection().SelectedText(), "is a");

  PhysicalOffset location(LayoutUnit(5), LayoutUnit(5));
  EXPECT_TRUE(ShowContextMenu(location, kMenuSourceKeyboard));
  EXPECT_EQ(GetDocument()->GetFrame()->Selection().SelectedText(), "is a");
}

TEST_F(ContextMenuControllerTest, CheckRendererIdFromContextMenuOnTextField) {
  WebURL url = url_test_helpers::ToKURL("http://www.test.com/");
  frame_test_helpers::LoadHTMLString(LocalMainFrame(),
                                     R"(<html><head><style>body
      {background-color:transparent}</style></head>
      <form>
      <label for="name">Name:</label><br>
      <input type="text" id="name" name="name"><br>
      <label for="address">Address:</label><br>
      <textarea id="address" name="address"></textarea>
      </form>
      <p id="one">This is a test page one</p>
      <label for="two">Two:</label><br>
      <input type="text" id="two" name="two"><br>
      <label for="three">Three:</label><br>
      <textarea id="three" name="three"></textarea>
      </html>
      )",
                                     url);

  Document* document = GetDocument();
  ASSERT_TRUE(IsA<HTMLDocument>(document));

  // field_id, is_form_renderer_id_present, is_field_renderer_id_present,
  // form_control_type
  std::vector<std::tuple<AtomicString, bool, bool,
                         std::optional<mojom::FormControlType>>>
      expectations = {// Input Text Field
                      {AtomicString("name"), true, true,
                       mojom::FormControlType::kInputText},
                      // Text Area Field
                      {AtomicString("address"), true, true,
                       mojom::FormControlType::kTextArea},
                      // Non form element
                      {AtomicString("one"), false, false, std::nullopt},
                      // Formless Input field
                      {AtomicString("two"), false, true,
                       mojom::FormControlType::kInputText},
                      // Formless text area field
                      {AtomicString("three"), false, true,
                       mojom::FormControlType::kTextArea}};

  for (const auto& expectation : expectations) {
    auto [field_id, is_form_renderer_id_present, is_field_renderer_id_present,
          form_control_type] = expectation;
    Element* form_element = document->getElementById(field_id);
    EXPECT_TRUE(ShowContextMenuForElement(form_element, kMenuSourceMouse));
    ContextMenuData context_menu_data =
        GetWebFrameClient().GetContextMenuData();
    EXPECT_EQ(context_menu_data.form_renderer_id != 0,
              is_form_renderer_id_present);
    EXPECT_EQ(context_menu_data.form_control_type, form_control_type);
  }
}

TEST_F(ContextMenuControllerTest, AttributionSrc) {
  // The context must be secure for attributionsrc to work at all.
  frame_test_helpers::LoadHTMLString(
      LocalMainFrame(), R"(<html><body>)",
      url_test_helpers::ToKURL("https://test.com/"));

  static constexpr char kSecureURL[] = "https://a.com/";
  static constexpr char kInsecureURL[] = "http://b.com/";

  const struct {
    const char* href;
    const char* attributionsrc;
    bool impression_expected;
  } kTestCases[] = {
      {
          .href = nullptr,
          .attributionsrc = nullptr,
          .impression_expected = false,
      },
      {
          .href = nullptr,
          .attributionsrc = "",
          .impression_expected = false,
      },
      {
          .href = nullptr,
          .attributionsrc = kInsecureURL,
          .impression_expected = false,
      },
      {
          .href = nullptr,
          .attributionsrc = kSecureURL,
          .impression_expected = false,
      },
      {
          .href = kInsecureURL,
          .attributionsrc = nullptr,
          .impression_expected = false,
      },
      {
          .href = kInsecureURL,
          .attributionsrc = "",
          .impression_expected = false,
      },
      {
          .href = kInsecureURL,
          .attributionsrc = kInsecureURL,
          .impression_expected = false,
      },
      {
          .href = kInsecureURL,
          .attributionsrc = kSecureURL,
          .impression_expected = false,
      },
      {
          .href = kSecureURL,
          .attributionsrc = nullptr,
          .impression_expected = false,
      },
      {
          .href = kSecureURL,
          .attributionsrc = "",
          .impression_expected = true,
      },
      {
          .href = kSecureURL,
          .attributionsrc = kInsecureURL,
          .impression_expected = true,
      },
      {
          .href = kSecureURL,
          .attributionsrc = kSecureURL,
          .impression_expected = true,
      },
  };

  for (const auto& test_case : kTestCases) {
    Persistent<HTMLAnchorElement> anchor =
        MakeGarbageCollected<HTMLAnchorElement>(*GetDocument());
    anchor->setInnerText("abc");

    if (test_case.href)
      anchor->SetHref(AtomicString(test_case.href));

    if (test_case.attributionsrc) {
      anchor->setAttribute(html_names::kAttributionsrcAttr,
                           AtomicString(test_case.attributionsrc));
    }

    GetPage()->SetAttributionSupport(network::mojom::AttributionSupport::kWeb);

    GetDocument()->body()->AppendChild(anchor);
    ASSERT_TRUE(ShowContextMenuForElement(anchor, kMenuSourceMouse));

    url_test_helpers::ServeAsynchronousRequests();

    ContextMenuData context_menu_data =
        GetWebFrameClient().GetContextMenuData();

    EXPECT_EQ(context_menu_data.impression.has_value(),
              test_case.impression_expected);
  }
}

// Test that if text selection contains unselectable content, the opened context
// menu should omit the unselectable content.
TEST_F(ContextMenuControllerTest, SelectUnselectableContent) {
  GetDocument()->documentElement()->setInnerHTML(R"HTML(
    <body>
      <p id="test">A <span style="user-select:none;">test_none <span>test_span
        </span><span style="user-select:all;">test_all</span></span> B</p>
    </body>
  )HTML");

  Document* document = GetDocument();
  Element* element = document->getElementById(AtomicString("test"));

  // Select text, which has nested unselectable and selectable content.
  const auto& start = Position(element->firstChild(), 0);
  const auto& end = Position(element->lastChild(), 2);
  document->GetFrame()->Selection().SetSelection(
      SelectionInDOMTree::Builder().SetBaseAndExtent(start, end).Build(),
      SetSelectionOptions());

  // The context menu should omit the unselectable content from the selected
  // text.
  EXPECT_TRUE(ShowContextMenuForElement(element, kMenuSourceMouse));
  ContextMenuData context_menu_data = GetWebFrameClient().GetContextMenuData();
  EXPECT_EQ(context_menu_data.selected_text, "A test_all B");
}

class ContextMenuControllerRemoteParentFrameTest : public testing::Test {
 public:
  ContextMenuControllerRemoteParentFrameTest() = default;

  void SetUp() override {
    web_view_helper_.InitializeRemote();
    web_view_helper_.RemoteMainFrame()->View()->DisableAutoResizeForTesting(
        gfx::Size(640, 480));

    child_frame_ = web_view_helper_.CreateLocalChild(
        *web_view_helper_.RemoteMainFrame(),
        /*name=*/"child",
        /*properties=*/{},
        /*previous_sibling=*/nullptr, &child_web_frame_client_);
    frame_test_helpers::LoadFrame(child_frame_, "data:text/html,some page");

    auto& focus_controller =
        child_frame_->GetFrame()->GetPage()->GetFocusController();
    focus_controller.SetActive(true);
    focus_controller.SetFocusedFrame(child_frame_->GetFrame());
  }

  void ShowContextMenu(const gfx::Point& point) {
    child_frame_->LocalRootFrameWidget()->ShowContextMenu(
        ui::mojom::blink::MenuSourceType::kMouse, point);
    base::RunLoop().RunUntilIdle();
  }

  const TestWebFrameClientImpl& child_web_frame_client() const {
    return child_web_frame_client_;
  }

 protected:
  test::TaskEnvironment task_environment_;
  base::test::ScopedFeatureList feature_list_;
  TestWebFrameClientImpl child_web_frame_client_;
  frame_test_helpers::WebViewHelper web_view_helper_;
  Persistent<WebLocalFrameImpl> child_frame_;
};

TEST_F(ContextMenuControllerRemoteParentFrameTest, ShowContextMenuInChild) {
  const gfx::Point kPoint(123, 234);
  ShowContextMenu(kPoint);

  const std::optional<gfx::Point>& host_context_menu_location =
      child_web_frame_client().host_context_menu_location();
  ASSERT_TRUE(host_context_menu_location.has_value());
  EXPECT_EQ(kPoint, host_context_menu_location.value());
}

}  // namespace blink
```