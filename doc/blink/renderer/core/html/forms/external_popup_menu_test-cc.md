Response:
The user wants to understand the functionality of the `external_popup_menu_test.cc` file in the Chromium Blink engine. I need to analyze the test cases within the file and explain what aspects of the `ExternalPopupMenu` class they are verifying.

Here's a breakdown of the test cases and their functionalities:

1. **`ExternalPopupMenuDisplayNoneItemsTest`**: Tests how the `ExternalPopupMenu` handles `<option>` elements with `display: none`. It checks if these hidden options are included in the `PopupMenuInfo` and how index mapping works between the original `<select>` element and the external popup menu.
2. **`ExternalPopupMenuHrElementItemsTest`**:  Tests how the `ExternalPopupMenu` handles `<hr>` elements within a `<select>`. It verifies if the `<hr>` elements are included as separators in the `PopupMenuInfo` (depending on the platform) and how the index mapping is affected.
3. **`TestLocalFrameExternalPopupClient`**: This is a helper class to simulate the browser process's interaction with the renderer when showing an external popup menu. It captures the information passed to the browser.
4. **`ExternalPopupMenuTest`**: Contains various test cases for the `ExternalPopupMenu` functionality, including:
    *   **`PopupAccountsForVisualViewportTransform`**: Verifies that the popup menu position correctly accounts for visual viewport transformations (like zooming and scrolling).
    *   **`PopupAccountsForDeviceScaleFactor`**: Checks if the popup menu position is adjusted based on the device's pixel ratio.
    *   **`DidAcceptIndex` / `DidAcceptIndices`**: Tests the scenario where the user selects an item in the external popup menu and how the `<select>` element's value is updated.
    *   **`DidAcceptIndicesClearSelect`**: Tests the case where the user clears the selection in a multi-select popup.
    *   **`NormalCase`**:  Covers the basic flow of showing a popup, canceling it, and then selecting an item.
    *   **`ShowPopupThenNavigate`**: Tests what happens when the user navigates away from the page while the popup menu is open.
    *   **`EmptySelect`**: Checks if clicking on an empty `<select>` element causes any issues.
    *   **`RemoveOnChange`**: Verifies the behavior when the `<select>` element is removed from the DOM within its `onchange` event handler.
    *   **`RemoveFrameOnChange`**: Tests the scenario where an iframe containing the `<select>` element is removed within the `onchange` event handler.

Now, I can formulate the response by summarizing these functionalities and relating them to web technologies.这个文件 `external_popup_menu_test.cc` 是 Chromium Blink 引擎中的一个测试文件，专门用于测试 `ExternalPopupMenu` 类的功能。`ExternalPopupMenu` 类负责在 HTML 表单元素（主要是 `<select>` 元素）需要显示下拉菜单时，与浏览器进程进行交互，以显示一个原生操作系统的弹出菜单，而不是在渲染进程内部绘制。

以下是该文件主要测试的功能点：

**1. 获取弹出菜单信息 (`GetPopupMenuInfo`)**:

*   测试 `ExternalPopupMenu::GetPopupMenuInfo` 函数能否正确地从 `HTMLSelectElement` 中提取出创建外部弹出菜单所需的信息。这些信息包括：
    *   **菜单项的高度 (`item_height`)**:  基于当前样式计算出的每个菜单项的渲染高度。这与 CSS 的行高、字体大小等属性有关。
    *   **字体大小 (`font_size`)**:  用于渲染菜单项的字体大小。同样与 CSS 的 `font-size` 属性有关。
    *   **当前选中的项的索引 (`selected_item`)**:  `<select>` 元素当前被选中的 `<option>` 元素的索引。这直接对应于 HTML 结构。
    *   **菜单项列表 (`menu_items`)**:  一个包含所有可见菜单项信息的列表。每个菜单项可能包含文本、图标等。这与 `<select>` 元素下的 `<option>` 元素有关。
    *   **是否右对齐 (`right_aligned`)**:  可能用于控制弹出菜单的对齐方式，虽然在提供的代码中没有直接看到其影响，但在实际应用中可能与 CSS 的布局和文本方向有关。
    *   **是否允许多选 (`allow_multiple_selection`)**:  指示 `<select>` 元素是否允许多项选择。这与 `<select>` 元素的 `multiple` 属性有关。

**2. 索引映射 (`ToExternalPopupMenuItemIndex`, `ToPopupMenuItemIndex`)**:

*   测试在 `<select>` 元素中的原始索引和外部弹出菜单中的索引之间的正确转换。这是因为某些 `<option>` 元素可能由于 CSS 样式（如 `display: none;`）或特殊元素（如 `<hr>`）而在外部弹出菜单中被忽略或以不同的方式处理。
    *   **`ToExternalPopupMenuItemIndex`**:  将 `<select>` 元素中某个 `<option>` 的索引转换为外部弹出菜单中的对应索引。
    *   **`ToPopupMenuItemIndex`**: 将外部弹出菜单中的索引转换回 `<select>` 元素中对应的 `<option>` 的索引。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

*   **HTML**:
    *   `HTMLSelectElement`: 测试的核心对象是 HTML 的 `<select>` 元素，以及其包含的 `<option>` 和 `<hr>` 元素。测试会创建不同的 `<select>` 结构，例如包含隐藏的 `<option>` 或 `<hr>`。
        ```html
        <select>
          <option>Item 1</option>
          <option style="display:none;">Hidden Item</option>
          <option>Item 3</option>
          <hr>
          <option>Item 4</option>
        </select>
        ```
    *   `HTMLIFrameElement`: 测试中也涉及到 `<iframe>` 元素，用于模拟跨 frame 的场景，测试在 iframe 中的 `<select>` 元素的操作。

*   **CSS**:
    *   `display: none;`: 测试了当 `<option>` 元素设置 `display: none;` 时，外部弹出菜单如何处理这些隐藏的项。例如，`ExternalPopupMenuDisplayNoneItemsTest` 就专注于此。
    *   样式和布局计算:  `GetPopupMenuInfo` 函数依赖于 Blink 的布局引擎来计算菜单项的高度和字体大小，这些都受到 CSS 样式的影响。`GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest)` 就是触发样式和布局更新的操作。

*   **JavaScript**:
    *   事件处理 (`onchange`):  测试中模拟了在 JavaScript 的 `onchange` 事件处理函数中移除 `<select>` 元素或包含它的 `<iframe>` 的情况，以验证 `ExternalPopupMenu` 的健壮性。
        ```javascript
        document.getElementById('s').onchange = function() {
          this.remove(); // 或者移除包含它的 iframe
        };
        ```
    *   `select.ShowPopup()`:  测试通过调用 `select->ShowPopup()` 来触发外部弹出菜单的显示。虽然这是 C++ 代码，但在实际的网页中，JavaScript 可以通过编程方式触发某些与 `<select>` 元素交互的行为，从而间接触发弹出菜单。
    *   `select.selectedIndex()`: 测试会检查 `<select>` 元素的 `selectedIndex` 属性是否被正确更新，这与用户在弹出菜单中的选择有关。

**逻辑推理、假设输入与输出:**

**示例 1：`ExternalPopupMenuDisplayNoneItemsTest` - IndexMappingTest**

*   **假设输入**: 一个包含 8 个 `<option>` 的 `<select>` 元素，其中第 4 个和第 5 个 `<option>` 设置了 `display: none;`。
*   **逻辑推理**: 外部弹出菜单应该只包含 6 个可见的菜单项。因此，原始 `<select>` 元素的索引需要映射到外部弹出菜单的索引。
*   **预期输出**:
    *   `ExternalPopupMenu::ToExternalPopupMenuItemIndex(6, *owner_element_)` 应该返回 `4`，因为原始的第 7 个 `<option>` (索引为 6) 是外部弹出菜单中的第 5 个可见项 (索引为 4)。
    *   `ExternalPopupMenu::ToPopupMenuItemIndex(4, *owner_element_)` 应该返回 `6`，因为外部弹出菜单中的第 5 项 (索引为 4) 对应于原始 `<select>` 元素的第 7 个 `<option>` (索引为 6)。
    *   对于超出范围的索引，例如 `8`，两个映射函数都应该返回 `-1`。

**示例 2：`ExternalPopupMenuTest` - `PopupAccountsForVisualViewportTransform`**

*   **假设输入**: 一个位于页面中间的 `<select>` 元素，页面进行了缩放（`kScaleFactor = 2`）和滚动（`scroll_delta(20, 30)`）。
*   **逻辑推理**: 外部弹出菜单的位置应该根据页面的缩放和滚动进行调整，以确保它出现在相对于视口的正确位置。
*   **预期输出**: 弹出菜单的显示位置 `ShownBounds()` 的 `x` 坐标应该等于 `(select元素在文档中的绝对位置的 x 坐标 - 页面滚动的 x 偏移) * 缩放比例`，`y` 坐标同理。

**用户或编程常见的使用错误:**

*   **不考虑 `display: none;` 的影响**:  开发者可能会错误地认为 `<select>` 元素中 `<option>` 的索引与外部弹出菜单中的索引总是一致的，而忽略了 `display: none;` 导致的差异。这可能导致在 JavaScript 中操作选择项时出现错误。
    *   **错误示例**:  假设用户在外部弹出菜单中选择了第三项，开发者可能会错误地认为这对应于 `<select>` 元素中索引为 2 的 `<option>`，而没有考虑到中间可能存在 `display: none;` 的 `<option>`。
*   **在 `onchange` 事件中移除元素或 frame**:  虽然测试中验证了这种情况的健壮性，但在实际开发中，在 `onchange` 事件处理函数中直接移除触发事件的 `<select>` 元素或包含它的 frame 是一种不推荐的做法，因为它可能导致意外的行为或错误。开发者应该谨慎处理这类操作，确保逻辑的正确性。
*   **假设弹出菜单的位置**: 开发者不应该假设外部弹出菜单的具体位置，因为它是由操作系统控制的，可能会受到多种因素的影响，例如屏幕边界、父元素的布局等。尝试通过 JavaScript 精确控制外部弹出菜单的位置是不可靠的。

总而言之，`external_popup_menu_test.cc` 文件通过各种测试用例，细致地检验了 `ExternalPopupMenu` 类在处理不同 HTML 结构、CSS 样式以及用户交互时的正确性和健壮性，确保了 Chromium 浏览器能够正确地显示和处理 HTML 表单的下拉选择菜单。

Prompt: 
```
这是目录为blink/renderer/core/html/forms/external_popup_menu_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/html/forms/external_popup_menu.h"

#include <memory>

#include "content/test/test_blink_web_unit_test_support.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/mojom/choosers/popup_menu.mojom-blink.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/public/web/web_popup_menu_info.h"
#include "third_party/blink/public/web/web_settings.h"
#include "third_party/blink/renderer/core/frame/frame_test_helpers.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/html/forms/html_select_element.h"
#include "third_party/blink/renderer/core/html/forms/popup_menu.h"
#include "third_party/blink/renderer/core/html/html_iframe_element.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/testing/fake_local_frame_host.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/url_loader_mock_factory.h"
#include "third_party/blink/renderer/platform/testing/url_test_helpers.h"

namespace blink {

class ExternalPopupMenuDisplayNoneItemsTest : public PageTestBase {
 public:
  ExternalPopupMenuDisplayNoneItemsTest() = default;

 protected:
  void SetUp() override {
    PageTestBase::SetUp();
    auto* element = MakeGarbageCollected<HTMLSelectElement>(GetDocument());
    // Set the 4th an 5th items to have "display: none" property
    element->setInnerHTML(
        "<option><option><option><option style='display:none;'><option "
        "style='display:none;'><option><option>");
    GetDocument().body()->AppendChild(element, ASSERT_NO_EXCEPTION);
    owner_element_ = element;
    GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  }

  Persistent<HTMLSelectElement> owner_element_;
};

TEST_F(ExternalPopupMenuDisplayNoneItemsTest, PopupMenuInfoSizeTest) {
  int32_t item_height;
  double font_size;
  int32_t selected_item;
  Vector<mojom::blink::MenuItemPtr> menu_items;
  bool right_aligned;
  bool allow_multiple_selection;
  ExternalPopupMenu::GetPopupMenuInfo(
      *owner_element_, &item_height, &font_size, &selected_item, &menu_items,
      &right_aligned, &allow_multiple_selection);
  EXPECT_EQ(5U, menu_items.size());
}

TEST_F(ExternalPopupMenuDisplayNoneItemsTest, IndexMappingTest) {
  // 6th indexed item in popupmenu would be the 4th item in ExternalPopupMenu,
  // and vice-versa.
  EXPECT_EQ(
      4, ExternalPopupMenu::ToExternalPopupMenuItemIndex(6, *owner_element_));
  EXPECT_EQ(6, ExternalPopupMenu::ToPopupMenuItemIndex(4, *owner_element_));

  // Invalid index, methods should return -1.
  EXPECT_EQ(
      -1, ExternalPopupMenu::ToExternalPopupMenuItemIndex(8, *owner_element_));
  EXPECT_EQ(-1, ExternalPopupMenu::ToPopupMenuItemIndex(8, *owner_element_));
}

class ExternalPopupMenuHrElementItemsTest : public PageTestBase {
 public:
  ExternalPopupMenuHrElementItemsTest() = default;

 protected:
  void SetUp() override {
    PageTestBase::SetUp();
    auto* element = MakeGarbageCollected<HTMLSelectElement>(GetDocument());
    element->setInnerHTML(R"HTML(
      <option>zero</option>
      <option>one</option>
      <hr>
      <option>two or three</option>
    )HTML");
    GetDocument().body()->AppendChild(element, ASSERT_NO_EXCEPTION);
    owner_element_ = element;
    GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  }

  Persistent<HTMLSelectElement> owner_element_;
};

TEST_F(ExternalPopupMenuHrElementItemsTest, PopupMenuInfoSizeTest) {
  int32_t item_height;
  double font_size;
  int32_t selected_item;
  Vector<mojom::blink::MenuItemPtr> menu_items;
  bool right_aligned;
  bool allow_multiple_selection;
  ExternalPopupMenu::GetPopupMenuInfo(
      *owner_element_, &item_height, &font_size, &selected_item, &menu_items,
      &right_aligned, &allow_multiple_selection);
#if BUILDFLAG(IS_ANDROID)
  EXPECT_EQ(3U, menu_items.size());
#else
  EXPECT_EQ(4U, menu_items.size());
#endif
}

TEST_F(ExternalPopupMenuHrElementItemsTest, IndexMappingTest) {
  EXPECT_EQ(
      0, ExternalPopupMenu::ToExternalPopupMenuItemIndex(0, *owner_element_));
  EXPECT_EQ(
      1, ExternalPopupMenu::ToExternalPopupMenuItemIndex(1, *owner_element_));
#if BUILDFLAG(IS_ANDROID)
  EXPECT_EQ(
      -1, ExternalPopupMenu::ToExternalPopupMenuItemIndex(2, *owner_element_));
  EXPECT_EQ(
      2, ExternalPopupMenu::ToExternalPopupMenuItemIndex(3, *owner_element_));
#else
  EXPECT_EQ(
      2, ExternalPopupMenu::ToExternalPopupMenuItemIndex(2, *owner_element_));
  EXPECT_EQ(
      3, ExternalPopupMenu::ToExternalPopupMenuItemIndex(3, *owner_element_));
#endif

  EXPECT_EQ(0, ExternalPopupMenu::ToPopupMenuItemIndex(0, *owner_element_));
  EXPECT_EQ(1, ExternalPopupMenu::ToPopupMenuItemIndex(1, *owner_element_));
#if BUILDFLAG(IS_ANDROID)
  EXPECT_EQ(3, ExternalPopupMenu::ToPopupMenuItemIndex(2, *owner_element_));
  EXPECT_EQ(-1, ExternalPopupMenu::ToPopupMenuItemIndex(3, *owner_element_));
#else
  EXPECT_EQ(2, ExternalPopupMenu::ToPopupMenuItemIndex(2, *owner_element_));
  EXPECT_EQ(3, ExternalPopupMenu::ToPopupMenuItemIndex(3, *owner_element_));
#endif
}

class TestLocalFrameExternalPopupClient : public FakeLocalFrameHost {
 public:
  void ShowPopupMenu(
      mojo::PendingRemote<mojom::blink::PopupMenuClient> popup_client,
      const gfx::Rect& bounds,
      int32_t item_height,
      double font_size,
      int32_t selected_item,
      Vector<mojom::blink::MenuItemPtr> menu_items,
      bool right_aligned,
      bool allow_multiple_selection) override {
    Reset();

    bounds_ = bounds;
    selected_item_ = selected_item;
    menu_items_ = std::move(menu_items);
    popup_client_.Bind(std::move(popup_client));
    popup_client_.set_disconnect_handler(WTF::BindOnce(
        &TestLocalFrameExternalPopupClient::Reset, WTF::Unretained(this)));
    std::move(showed_callback_).Run();
  }

  void Reset() { popup_client_.reset(); }

  void WaitUntilShowedPopup() {
    base::RunLoop run_loop;
    showed_callback_ = run_loop.QuitClosure();
    run_loop.Run();
  }

  mojom::blink::PopupMenuClient* PopupClient() {
    DCHECK(popup_client_);
    return popup_client_.get();
  }

  bool IsBound() const { return popup_client_.is_bound(); }

  const Vector<mojom::blink::MenuItemPtr>& MenuItems() const {
    return menu_items_;
  }

  int32_t SelectedItem() const { return selected_item_; }

  const gfx::Rect& ShownBounds() const { return bounds_; }

 private:
  base::OnceClosure showed_callback_;
  mojo::Remote<mojom::blink::PopupMenuClient> popup_client_;
  int32_t selected_item_;
  Vector<mojom::blink::MenuItemPtr> menu_items_;
  gfx::Rect bounds_;
};

class ExternalPopupMenuTest : public PageTestBase {
 public:
  ExternalPopupMenuTest() : base_url_("http://www.test.com") {}

 protected:
  void SetUp() override {
    frame_host_.Init(
        web_frame_client_.GetRemoteNavigationAssociatedInterfaces());
    helper_.Initialize(&web_frame_client_);
    WebView()->SetUseExternalPopupMenus(true);
  }
  void TearDown() override {
    url_test_helpers::UnregisterAllURLsAndClearMemoryCache();
  }

  void RegisterMockedURLLoad(const std::string& file_name) {
    // TODO(crbug.com/751425): We should use the mock functionality
    // via |helper_|.
    url_test_helpers::RegisterMockedURLLoadFromBase(
        WebString::FromUTF8(base_url_), test::CoreTestDataPath("popup"),
        WebString::FromUTF8(file_name), WebString::FromUTF8("text/html"));
  }

  void LoadFrame(const std::string& file_name) {
    frame_test_helpers::LoadFrame(MainFrame(), base_url_ + file_name);
    WebView()->MainFrameViewWidget()->Resize(gfx::Size(800, 600));
    WebView()->MainFrameWidget()->UpdateAllLifecyclePhases(
        DocumentUpdateReason::kTest);
  }

  WebViewImpl* WebView() const { return helper_.GetWebView(); }

  const Vector<mojom::blink::MenuItemPtr>& MenuItems() const {
    return frame_host_.MenuItems();
  }

  bool IsBound() const { return frame_host_.IsBound(); }

  int32_t SelectedItem() const { return frame_host_.SelectedItem(); }

  const gfx::Rect& ShownBounds() const { return frame_host_.ShownBounds(); }

  mojom::blink::PopupMenuClient* PopupClient() {
    return frame_host_.PopupClient();
  }

  void WaitUntilShowedPopup() { frame_host_.WaitUntilShowedPopup(); }

  WebLocalFrameImpl* MainFrame() const { return helper_.LocalMainFrame(); }

 private:
  TestLocalFrameExternalPopupClient frame_host_;
  frame_test_helpers::TestWebFrameClient web_frame_client_;
  std::string base_url_;
  frame_test_helpers::WebViewHelper helper_;
};

TEST_F(ExternalPopupMenuTest, PopupAccountsForVisualViewportTransform) {
  RegisterMockedURLLoad("select_mid_screen.html");
  LoadFrame("select_mid_screen.html");

  WebView()->MainFrameViewWidget()->Resize(gfx::Size(100, 100));
  WebView()->MainFrameWidget()->UpdateAllLifecyclePhases(
      DocumentUpdateReason::kTest);

  auto* select = To<HTMLSelectElement>(
      MainFrame()->GetFrame()->GetDocument()->getElementById(
          AtomicString("select")));
  auto* layout_object = select->GetLayoutObject();
  ASSERT_TRUE(layout_object);

  VisualViewport& visual_viewport = WebView()->GetPage()->GetVisualViewport();

  gfx::Rect rect_in_document = layout_object->AbsoluteBoundingBoxRect();

  constexpr int kScaleFactor = 2;
  ScrollOffset scroll_delta(20, 30);

  const int expected_x =
      (rect_in_document.x() - scroll_delta.x()) * kScaleFactor;
  const int expected_y =
      (rect_in_document.y() - scroll_delta.y()) * kScaleFactor;

  WebView()->SetPageScaleFactor(kScaleFactor);
  visual_viewport.Move(scroll_delta);
  select->ShowPopup();
  WaitUntilShowedPopup();

  EXPECT_EQ(expected_x, ShownBounds().x());
  EXPECT_EQ(expected_y, ShownBounds().y());
}

// Android doesn't use this position data and we don't adjust it for DPR there..
#ifdef OS_ANDROID
#define MAYBE_PopupAccountsForDeviceScaleFactor \
  DISABLED_PopupAccountsForDeviceScaleFactor
#else
#define MAYBE_PopupAccountsForDeviceScaleFactor \
  PopupAccountsForDeviceScaleFactor
#endif

TEST_F(ExternalPopupMenuTest, MAYBE_PopupAccountsForDeviceScaleFactor) {
  RegisterMockedURLLoad("select_mid_screen.html");
  LoadFrame("select_mid_screen.html");

  constexpr float kScaleFactor = 2.0f;
  WebView()->MainFrameWidget()->SetDeviceScaleFactorForTesting(kScaleFactor);
  WebView()->MainFrameWidget()->UpdateAllLifecyclePhases(
      DocumentUpdateReason::kTest);

  auto* select = To<HTMLSelectElement>(
      MainFrame()->GetFrame()->GetDocument()->getElementById(
          AtomicString("select")));
  auto* layout_object = select->GetLayoutObject();
  ASSERT_TRUE(layout_object);

  select->ShowPopup();
  WaitUntilShowedPopup();

  // The test file has no body margins but 50px of padding.
  EXPECT_EQ(50, ShownBounds().x());
  EXPECT_EQ(50, ShownBounds().y());
}

TEST_F(ExternalPopupMenuTest, DidAcceptIndex) {
  RegisterMockedURLLoad("select.html");
  LoadFrame("select.html");

  auto* select = To<HTMLSelectElement>(
      MainFrame()->GetFrame()->GetDocument()->getElementById(
          AtomicString("select")));
  auto* layout_object = select->GetLayoutObject();
  ASSERT_TRUE(layout_object);

  select->ShowPopup();
  WaitUntilShowedPopup();

  ASSERT_TRUE(select->PopupIsVisible());

  PopupClient()->DidAcceptIndices({2});
  base::RunLoop().RunUntilIdle();

  EXPECT_FALSE(select->PopupIsVisible());
  ASSERT_EQ("2", select->InnerElement().innerText().Utf8());
  EXPECT_EQ(2, select->selectedIndex());
}

TEST_F(ExternalPopupMenuTest, DidAcceptIndices) {
  RegisterMockedURLLoad("select.html");
  LoadFrame("select.html");

  auto* select = To<HTMLSelectElement>(
      MainFrame()->GetFrame()->GetDocument()->getElementById(
          AtomicString("select")));
  auto* layout_object = select->GetLayoutObject();
  ASSERT_TRUE(layout_object);

  select->ShowPopup();
  WaitUntilShowedPopup();

  ASSERT_TRUE(select->PopupIsVisible());

  PopupClient()->DidAcceptIndices({2});
  base::RunLoop().RunUntilIdle();

  EXPECT_FALSE(select->PopupIsVisible());
  EXPECT_EQ("2", select->InnerElement().innerText());
  EXPECT_EQ(2, select->selectedIndex());
}

TEST_F(ExternalPopupMenuTest, DidAcceptIndicesClearSelect) {
  RegisterMockedURLLoad("select.html");
  LoadFrame("select.html");

  auto* select = To<HTMLSelectElement>(
      MainFrame()->GetFrame()->GetDocument()->getElementById(
          AtomicString("select")));
  auto* layout_object = select->GetLayoutObject();
  ASSERT_TRUE(layout_object);

  select->ShowPopup();
  WaitUntilShowedPopup();

  ASSERT_TRUE(select->PopupIsVisible());
  PopupClient()->DidAcceptIndices({});
  base::RunLoop().RunUntilIdle();

  EXPECT_FALSE(select->PopupIsVisible());
  EXPECT_EQ(-1, select->selectedIndex());
}

// Normal case: test showing a select popup, canceling/selecting an item.
TEST_F(ExternalPopupMenuTest, NormalCase) {
  RegisterMockedURLLoad("select.html");
  LoadFrame("select.html");

  // Show the popup-menu.
  auto* select = To<HTMLSelectElement>(
      MainFrame()->GetFrame()->GetDocument()->getElementById(
          AtomicString("select")));
  auto* layout_object = select->GetLayoutObject();
  ASSERT_TRUE(layout_object);

  select->ShowPopup();
  WaitUntilShowedPopup();

  ASSERT_TRUE(select->PopupIsVisible());
  ASSERT_EQ(3U, MenuItems().size());
  EXPECT_EQ(1, SelectedItem());

  // Simulate the user canceling the popup; the index should not have changed.
  PopupClient()->DidCancel();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1, select->selectedIndex());

  // Show the pop-up again and this time make a selection.
  select->ShowPopup();
  WaitUntilShowedPopup();

  PopupClient()->DidAcceptIndices({0});
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(0, select->selectedIndex());

  // Show the pop-up again and make another selection.
  select->ShowPopup();
  WaitUntilShowedPopup();

  ASSERT_EQ(3U, MenuItems().size());
  EXPECT_EQ(0, SelectedItem());
}

// Page shows popup, then navigates away while popup showing, then select.
TEST_F(ExternalPopupMenuTest, ShowPopupThenNavigate) {
  RegisterMockedURLLoad("select.html");
  LoadFrame("select.html");

  // Show the popup-menu.
  auto* document = MainFrame()->GetFrame()->GetDocument();
  auto* select =
      To<HTMLSelectElement>(document->getElementById(AtomicString("select")));
  auto* layout_object = select->GetLayoutObject();
  ASSERT_TRUE(layout_object);

  select->ShowPopup();
  WaitUntilShowedPopup();

  // Now we navigate to another pager.
  document->documentElement()->setInnerHTML("<blink>Awesome page!</blink>");
  document->UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  base::RunLoop().RunUntilIdle();

  // Now HTMLSelectElement should be nullptr and mojo is disconnected.
  select =
      To<HTMLSelectElement>(document->getElementById(AtomicString("select")));
  EXPECT_FALSE(select);
  EXPECT_FALSE(IsBound());
}

// An empty select should not cause a crash when clicked.
// http://crbug.com/63774
TEST_F(ExternalPopupMenuTest, EmptySelect) {
  RegisterMockedURLLoad("select.html");
  LoadFrame("select.html");

  auto* select = To<HTMLSelectElement>(
      MainFrame()->GetFrame()->GetDocument()->getElementById(
          AtomicString("emptySelect")));
  EXPECT_TRUE(select);
  select->click();
}

// Tests that nothing bad happen when the page removes the select when it
// changes. (http://crbug.com/61997)
TEST_F(ExternalPopupMenuTest, RemoveOnChange) {
  RegisterMockedURLLoad("select_event_remove_on_change.html");
  LoadFrame("select_event_remove_on_change.html");

  // Show the popup-menu.
  auto* document = MainFrame()->GetFrame()->GetDocument();
  auto* select =
      To<HTMLSelectElement>(document->getElementById(AtomicString("s")));
  auto* layout_object = select->GetLayoutObject();
  ASSERT_TRUE(layout_object);

  select->ShowPopup();
  WaitUntilShowedPopup();

  // Select something, it causes the select to be removed from the page.
  PopupClient()->DidAcceptIndices({1});
  base::RunLoop().RunUntilIdle();

  // Just to check the soundness of the test.
  // It should return nullptr as the select has been removed.
  select = To<HTMLSelectElement>(document->getElementById(AtomicString("s")));
  EXPECT_FALSE(select);
}

// crbug.com/912211
TEST_F(ExternalPopupMenuTest, RemoveFrameOnChange) {
  RegisterMockedURLLoad("select_event_remove_frame_on_change.html");
  LoadFrame("select_event_remove_frame_on_change.html");

  // Open a popup.
  auto* iframe = To<HTMLIFrameElement>(
      MainFrame()->GetFrame()->GetDocument()->QuerySelector(
          AtomicString("iframe")));
  auto* select = To<HTMLSelectElement>(
      iframe->contentDocument()->QuerySelector(AtomicString("select")));
  auto* layout_object = select->GetLayoutObject();
  ASSERT_TRUE(layout_object);

  select->ShowPopup();

  // Select something on the sub-frame, it causes the frame to be removed from
  // the page.
  select->SelectOptionByPopup(1);
  // The test passes if the test didn't crash and ASAN didn't complain.
}

}  // namespace blink

"""

```