Response:
The user wants me to analyze a C++ source code file (`context_menu_controller_test.cc`) from the Chromium Blink engine. I need to extract its functionalities and explain its relation to web technologies like JavaScript, HTML, and CSS. Additionally, I should provide examples of logical reasoning with input and output, discuss common user/programming errors, and describe the user interaction leading to the execution of this code. Finally, as this is part 1 of 3, I need to summarize the functionalities covered in this part.

**Plan:**

1. **Identify Core Functionality:** Scan the code for test cases and the main class being tested. It seems to be testing `ContextMenuController`.
2. **Explain Functionality:** Describe what `ContextMenuController` does based on the test names and included headers. It manages the display and data associated with context menus.
3. **Relate to Web Technologies:**
    - **HTML:**  Context menus are triggered by right-clicks or long-presses on HTML elements. The tests use HTML elements like `embed`, `video`, `text`, `div`, etc. The data sent with the context menu is often related to the HTML element (e.g., link URL, video source).
    - **JavaScript:** While not directly interacting in this *test* file, JavaScript can trigger and manipulate context menus. I'll need to provide a hypothetical example.
    - **CSS:** CSS affects the visual presentation of elements, which might indirectly influence where a context menu is triggered. I'll need to consider this.
4. **Logical Reasoning with Examples:**  Pick a simple test case, like the `CopyFromPlugin` test, and explain the input (plugin attributes) and expected output (context menu data).
5. **Common Errors:** Think about common mistakes users or developers might make that would involve the context menu. For users, it might be accidental right-clicks. For developers, it could be incorrect handling of context menu events or data.
6. **User Steps:** Describe the user actions (mouse clicks, long presses) that lead to the context menu appearing and thus involve this code.
7. **Part 1 Summary:** Focus on the functionalities tested in this specific snippet. The tests seem to revolve around context menus on plugins and video elements and basic text selection scenarios.
这是对 `blink/renderer/core/page/context_menu_controller_test.cc` 文件功能的分析和总结（第 1 部分）。

**功能归纳:**

这个 C++ 文件是 Chromium Blink 引擎中 `ContextMenuController` 类的单元测试。它的主要功能是测试在各种场景下，`ContextMenuController` 如何正确地收集和传递上下文菜单的数据。 具体来说，这部分代码主要测试了以下功能：

1. **插件 (Plugin) 的上下文菜单:** 测试了当在插件上触发上下文菜单时，`ContextMenuController` 如何获取插件的相关信息，例如是否允许复制以及插件中选中的文本。
2. **视频 (Video) 元素的上下文菜单:** 详细测试了在不同视频加载状态（未加载、仅音频、已加载）、不同配置（是否启用画中画）以及使用 MediaStream 的情况下，`ContextMenuController` 如何收集视频元素的媒体信息，并设置相应的 `ContextMenuData` 标志。
3. **SVG 和 XML 文档的编辑操作:** 测试了在 SVG 和 XML 文档中，当选中文字时，上下文菜单是否正确启用了复制等编辑操作。

**与 JavaScript, HTML, CSS 的关系举例:**

* **HTML:**  这个测试文件直接与 HTML 元素交互。例如，测试用例中创建了 `<embed>` (插件), `<video>` 等 HTML 元素，并通过模拟用户在这些元素上点击右键或者长按来触发上下文菜单。
    * **举例:**  `TEST_F(ContextMenuControllerTest, CopyFromPlugin)` 测试用例创建了一个 `<embed>` 元素，模拟用户在该元素上点击右键，然后断言 `ContextMenuController` 收集到的 `ContextMenuData` 中关于插件的信息是否正确。
* **JavaScript:**  虽然这个测试文件本身是用 C++ 编写的，用于测试 Blink 引擎的 C++ 代码，但 `ContextMenuController` 的功能最终会影响到 JavaScript 中与上下文菜单相关的事件和 API。例如，JavaScript 可以监听 `contextmenu` 事件，并根据 `ContextMenuData` 中的信息来修改或阻止默认的上下文菜单行为。
    * **假设输入:** 用户在浏览器中访问了一个网页，该网页通过 JavaScript 注册了 `contextmenu` 事件监听器。
    * **用户操作:** 用户在一个图片上点击鼠标右键。
    * **逻辑推理:** `ContextMenuController` 会根据图片的 URL 等信息生成 `ContextMenuData`，然后浏览器会将这个数据传递给 JavaScript 的 `contextmenu` 事件处理函数。JavaScript 可以访问这个数据并决定是否显示默认菜单，或者显示自定义菜单。
* **CSS:** CSS 主要负责页面的样式，它间接地影响上下文菜单的触发。 例如，CSS 可以控制元素的大小和位置，这决定了用户点击的位置是否会命中特定的元素并触发其上下文菜单。
    * **举例:** `TEST_F(ContextMenuControllerTest, HitTestVideoChildElements)` 测试用例中，使用了 CSS 的 `position: absolute` 来定位视频元素，然后测试在视频元素的不同位置点击右键是否都能正确触发视频元素的上下文菜单。

**逻辑推理的假设输入与输出:**

* **假设输入 (针对 `TEST_F(ContextMenuControllerTest, VideoNotLoaded)`)**:  一个 `<video>` 元素被添加到文档中，但视频尚未加载完成 (`SetReadyState(video.Get(), HTMLMediaElement::kHaveNothing)`)。
* **用户操作:** 用户在该视频元素上点击鼠标右键。
* **逻辑推理:** `ContextMenuController` 检测到这是一个视频元素且未加载完成，会设置 `ContextMenuData` 中的 `media_type` 为 `kVideo`，并将 `kMediaPaused` 标志设置为 true，表示视频处于暂停状态（因为还没加载完）。
* **输出:** `GetWebFrameClient().GetContextMenuData()` 返回的 `ContextMenuData` 对象的 `media_type` 字段为 `mojom::blink::ContextMenuDataMediaType::kVideo`，且 `media_flags` 字段包含 `ContextMenuData::kMediaPaused`。

**涉及用户或编程常见的使用错误:**

* **用户错误:** 用户可能会在不希望看到上下文菜单的时候意外点击鼠标右键或长按触摸屏，导致上下文菜单弹出。这并非编程错误，而是用户操作失误。
* **编程错误:**
    * **未正确处理 `contextmenu` 事件:** 开发者可能没有正确地在 JavaScript 中监听和处理 `contextmenu` 事件，导致自定义的上下文菜单逻辑无法执行。
    * **错误的 `ContextMenuData` 假设:** 开发者可能错误地假设 `ContextMenuData` 中会包含某些信息，但实际情况下由于元素类型或状态的不同，这些信息可能不存在。例如，假设在所有情况下都能获取到视频的播放时长，但对于未加载完成的视频，这个信息是不可用的。
    * **插件开发错误:**  如果插件开发者没有正确实现获取选中文本或复制权限的接口，那么 `ContextMenuController` 获取到的信息可能不准确。 例如，插件明明允许复制，但 `CanCopy()` 方法返回了 `false`。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户浏览网页:** 用户使用 Chrome 浏览器访问一个包含插件或视频元素的网页。
2. **用户触发上下文菜单:** 用户在网页上的一个元素（例如，一个插件、一个视频、一段文本）上执行以下操作之一：
    * **鼠标右键点击:** 这是最常见的触发上下文菜单的方式。
    * **触摸屏长按:** 在触摸屏设备上，长按也会触发上下文菜单。
    * **键盘快捷键:**  某些情况下，键盘快捷键（例如，Shift+F10 或 Context Menu 键）也可以触发上下文菜单。
3. **浏览器事件处理:** 浏览器接收到用户的输入事件 (鼠标点击、触摸事件、键盘事件)。
4. **Blink 引擎处理:**  Blink 引擎的事件处理机制识别出这是一个请求显示上下文菜单的事件。
5. **命中测试 (Hit Testing):** Blink 引擎执行命中测试，确定用户点击或长按的屏幕坐标对应哪个 DOM 元素。
6. **`ContextMenuController::ShowContextMenu` 调用:**  根据命中测试的结果，Blink 引擎会调用 `ContextMenuController` 的 `ShowContextMenu` 方法，并将相关的坐标和源类型 (鼠标、触摸等) 作为参数传递进去。
7. **`ContextMenuController` 数据收集:**  `ContextMenuController` 负责收集被点击元素的相关信息，例如元素类型、URL、选中的文本、媒体信息等，并将这些信息填充到 `ContextMenuData` 对象中。
8. **上下文菜单显示:**  `ContextMenuController` 将 `ContextMenuData` 传递给浏览器进程，最终由浏览器显示上下文菜单。 在测试环境中，`TestWebFrameClientImpl::UpdateContextMenuDataForTesting` 方法会被调用，存储 `ContextMenuData` 以供测试断言。

**第 1 部分功能总结:**

这部分测试主要集中在验证 `ContextMenuController` 针对 **插件和视频元素** 以及在 **SVG/XML 文档中选中文字** 时，能否正确地收集并传递上下文菜单所需的数据。测试涵盖了插件的复制权限和选中文本，以及视频的不同加载状态和配置对上下文菜单数据的影响。

Prompt: 
```
这是目录为blink/renderer/core/page/context_menu_controller_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/page/context_menu_controller.h"

#include <algorithm>
#include <limits>
#include <memory>
#include <optional>
#include <utility>

#include "base/run_loop.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/test/scoped_feature_list.h"
#include "build/build_config.h"
#include "services/network/public/mojom/attribution.mojom-blink.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/context_menu_data/context_menu_data.h"
#include "third_party/blink/public/common/context_menu_data/edit_flags.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/input/web_keyboard_event.h"
#include "third_party/blink/public/common/input/web_menu_source_type.h"
#include "third_party/blink/public/mojom/context_menu/context_menu.mojom-blink.h"
#include "third_party/blink/public/web/web_plugin.h"
#include "third_party/blink/renderer/core/dom/events/native_event_listener.h"
#include "third_party/blink/renderer/core/dom/xml_document.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/markers/document_marker_controller.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/exported/web_plugin_container_impl.h"
#include "third_party/blink/renderer/core/frame/frame_test_helpers.h"
#include "third_party/blink/renderer/core/frame/web_frame_widget_impl.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/geometry/dom_rect.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/html_anchor_element.h"
#include "third_party/blink/renderer/core/html/html_document.h"
#include "third_party/blink/renderer/core/html/html_embed_element.h"
#include "third_party/blink/renderer/core/html/media/html_video_element.h"
#include "third_party/blink/renderer/core/input/context_menu_allowed_scope.h"
#include "third_party/blink/renderer/core/layout/layout_embedded_content.h"
#include "third_party/blink/renderer/core/page/focus_controller.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/core/testing/fake_web_plugin.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_component.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_descriptor.h"
#include "third_party/blink/renderer/platform/testing/empty_web_media_player.h"
#include "third_party/blink/renderer/platform/testing/scoped_mocked_url.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/url_loader_mock.h"
#include "third_party/blink/renderer/platform/testing/url_loader_mock_factory_impl.h"
#include "third_party/blink/renderer/platform/testing/url_test_helpers.h"
#include "third_party/blink/renderer/platform/wtf/casting.h"
#include "ui/base/mojom/menu_source_type.mojom-blink.h"
#include "ui/gfx/geometry/rect.h"

using testing::Return;

namespace blink {

namespace {

constexpr char kTestResourceFilename[] = "white-1x1.png";
constexpr char kTestResourceMimeType[] = "image/png";

class MockWebMediaPlayerForContextMenu : public EmptyWebMediaPlayer {
 public:
  MOCK_CONST_METHOD0(Duration, double());
  MOCK_CONST_METHOD0(HasAudio, bool());
  MOCK_CONST_METHOD0(HasVideo, bool());
};

class ContextMenuControllerTestPlugin : public FakeWebPlugin {
 public:
  struct PluginAttributes {
    // Whether the plugin has copy permission.
    bool can_copy;

    // The selected text in the plugin when the context menu is created.
    WebString selected_text;
  };

  explicit ContextMenuControllerTestPlugin(const WebPluginParams& params)
      : FakeWebPlugin(params) {}

  // FakeWebPlugin:
  WebString SelectionAsText() const override { return selected_text_; }
  bool CanCopy() const override { return can_copy_; }

  void SetAttributesForTesting(const PluginAttributes& attributes) {
    can_copy_ = attributes.can_copy;
    selected_text_ = attributes.selected_text;
  }

 private:
  bool can_copy_ = true;
  WebString selected_text_;
};

class TestWebFrameClientImpl : public frame_test_helpers::TestWebFrameClient {
 public:
  WebPlugin* CreatePlugin(const WebPluginParams& params) override {
    return new ContextMenuControllerTestPlugin(params);
  }

  void UpdateContextMenuDataForTesting(
      const ContextMenuData& data,
      const std::optional<gfx::Point>& host_context_menu_location) override {
    context_menu_data_ = data;
    host_context_menu_location_ = host_context_menu_location;
  }

  std::unique_ptr<WebMediaPlayer> CreateMediaPlayer(
      const WebMediaPlayerSource&,
      WebMediaPlayerClient*,
      blink::MediaInspectorContext*,
      WebMediaPlayerEncryptedMediaClient*,
      WebContentDecryptionModule*,
      const WebString& sink_id,
      const cc::LayerTreeSettings* settings,
      scoped_refptr<base::TaskRunner> compositor_worker_task_runner) override {
    return std::make_unique<MockWebMediaPlayerForContextMenu>();
  }

  const ContextMenuData& GetContextMenuData() const {
    return context_menu_data_;
  }

  const std::optional<gfx::Point>& host_context_menu_location() const {
    return host_context_menu_location_;
  }

 private:
  ContextMenuData context_menu_data_;
  std::optional<gfx::Point> host_context_menu_location_;
};

void RegisterMockedImageURLLoad(const String& url) {
  url_test_helpers::RegisterMockedURLLoad(
      url_test_helpers::ToKURL(url.Utf8().c_str()),
      test::CoreTestDataPath(kTestResourceFilename), kTestResourceMimeType);
}

}  // namespace

template <>
struct DowncastTraits<ContextMenuControllerTestPlugin> {
  static bool AllowFrom(const WebPlugin& object) { return true; }
};

class ContextMenuControllerTest : public testing::Test {
 public:
  ContextMenuControllerTest() = default;

  void SetUp() override {
    web_view_helper_.Initialize(&web_frame_client_);

    WebLocalFrameImpl* local_main_frame = web_view_helper_.LocalMainFrame();
    local_main_frame->ViewImpl()->MainFrameViewWidget()->Resize(
        gfx::Size(640, 480));
    local_main_frame->ViewImpl()->MainFrameWidget()->UpdateAllLifecyclePhases(
        DocumentUpdateReason::kTest);
  }

  void TearDown() override {
    url_test_helpers::UnregisterAllURLsAndClearMemoryCache();
  }

  bool ShowContextMenu(const PhysicalOffset& location,
                       WebMenuSourceType source) {
    bool success =
        web_view_helper_.GetWebView()
            ->GetPage()
            ->GetContextMenuController()
            .ShowContextMenu(GetDocument()->GetFrame(), location, source);
    base::RunLoop().RunUntilIdle();
    return success;
  }

  bool ShowContextMenuForElement(Element* element, WebMenuSourceType source) {
    const DOMRect* rect = element->GetBoundingClientRect();
    PhysicalOffset location(LayoutUnit((rect->left() + rect->right()) / 2),
                            LayoutUnit((rect->top() + rect->bottom()) / 2));
    ContextMenuAllowedScope context_menu_allowed_scope;
    return ShowContextMenu(location, source);
  }

  Document* GetDocument() {
    return static_cast<Document*>(
        web_view_helper_.LocalMainFrame()->GetDocument());
  }

  WebView* GetWebView() { return web_view_helper_.GetWebView(); }
  Page* GetPage() { return web_view_helper_.GetWebView()->GetPage(); }
  WebLocalFrameImpl* LocalMainFrame() {
    return web_view_helper_.LocalMainFrame();
  }
  void LoadAhem() { web_view_helper_.LoadAhem(); }

  const TestWebFrameClientImpl& GetWebFrameClient() const {
    return web_frame_client_;
  }

  void DurationChanged(HTMLVideoElement* video) { video->DurationChanged(); }

  void SetReadyState(HTMLVideoElement* video,
                     HTMLMediaElement::ReadyState state) {
    video->SetReadyState(state);
  }

 protected:
  test::TaskEnvironment task_environment_;
  base::test::ScopedFeatureList feature_list_;
  TestWebFrameClientImpl web_frame_client_;
  frame_test_helpers::WebViewHelper web_view_helper_;
};

TEST_F(ContextMenuControllerTest, CopyFromPlugin) {
  ContextMenuAllowedScope context_menu_allowed_scope;
  frame_test_helpers::LoadFrame(LocalMainFrame(), R"HTML(data:text/html,
  <html>
    <body>
      <embed id="embed" type="application/x-webkit-test-webplugin"
       src="chrome-extension://test" original-url="http://www.test.pdf">
      </embed>
    </body>
  <html>
  )HTML");

  Document* document = GetDocument();
  ASSERT_TRUE(IsA<HTMLDocument>(document));

  Element* embed_element = document->getElementById(AtomicString("embed"));
  ASSERT_TRUE(IsA<HTMLEmbedElement>(embed_element));

  auto* embedded =
      DynamicTo<LayoutEmbeddedContent>(embed_element->GetLayoutObject());
  WebPluginContainerImpl* embedded_plugin_view = embedded->Plugin();
  ASSERT_TRUE(!!embedded_plugin_view);

  auto* test_plugin = DynamicTo<ContextMenuControllerTestPlugin>(
      embedded_plugin_view->Plugin());

  // The plugin has copy permission but no text is selected.
  test_plugin->SetAttributesForTesting(
      {/*can_copy=*/true, /*selected_text=*/""});

  ASSERT_TRUE(ShowContextMenuForElement(embed_element, kMenuSourceMouse));
  ContextMenuData context_menu_data = GetWebFrameClient().GetContextMenuData();
  EXPECT_EQ(context_menu_data.media_type,
            mojom::blink::ContextMenuDataMediaType::kPlugin);
  EXPECT_FALSE(
      !!(context_menu_data.edit_flags & ContextMenuDataEditFlags::kCanCopy));
  EXPECT_EQ(context_menu_data.selected_text, "");

  // The plugin has copy permission and some text is selected.
  test_plugin->SetAttributesForTesting({/*can_copy=*/true,
                                        /*selected_text=*/"some text"});
  ASSERT_TRUE(ShowContextMenuForElement(embed_element, kMenuSourceMouse));
  context_menu_data = GetWebFrameClient().GetContextMenuData();
  EXPECT_EQ(context_menu_data.media_type,
            mojom::blink::ContextMenuDataMediaType::kPlugin);
  EXPECT_TRUE(
      !!(context_menu_data.edit_flags & ContextMenuDataEditFlags::kCanCopy));
  EXPECT_EQ(context_menu_data.selected_text, "some text");

  // The plugin does not have copy permission and no text is selected.
  test_plugin->SetAttributesForTesting({/*can_copy=*/false,
                                        /*selected_text=*/""});
  ASSERT_TRUE(ShowContextMenuForElement(embed_element, kMenuSourceMouse));
  context_menu_data = GetWebFrameClient().GetContextMenuData();
  EXPECT_EQ(context_menu_data.media_type,
            mojom::blink::ContextMenuDataMediaType::kPlugin);
  EXPECT_FALSE(
      !!(context_menu_data.edit_flags & ContextMenuDataEditFlags::kCanCopy));
  EXPECT_EQ(context_menu_data.selected_text, "");

  // The plugin does not have copy permission but some text is selected.
  test_plugin->SetAttributesForTesting({/*can_copy=*/false,
                                        /*selected_text=*/"some text"});
  ASSERT_TRUE(ShowContextMenuForElement(embed_element, kMenuSourceMouse));
  context_menu_data = GetWebFrameClient().GetContextMenuData();
  EXPECT_EQ(context_menu_data.media_type,
            mojom::blink::ContextMenuDataMediaType::kPlugin);
  EXPECT_EQ(context_menu_data.selected_text, "some text");
  EXPECT_FALSE(
      !!(context_menu_data.edit_flags & ContextMenuDataEditFlags::kCanCopy));
}

TEST_F(ContextMenuControllerTest, VideoNotLoaded) {
  ContextMenuAllowedScope context_menu_allowed_scope;
  HitTestResult hit_test_result;
  AtomicString video_url("https://example.com/foo.webm");

  // Make sure Picture-in-Picture is enabled.
  GetDocument()->GetSettings()->SetPictureInPictureEnabled(true);

  // Setup video element.
  Persistent<HTMLVideoElement> video =
      MakeGarbageCollected<HTMLVideoElement>(*GetDocument());
  video->SetSrc(video_url);
  GetDocument()->body()->AppendChild(video);
  test::RunPendingTasks();
  SetReadyState(video.Get(), HTMLMediaElement::kHaveNothing);
  test::RunPendingTasks();

  EXPECT_CALL(*static_cast<MockWebMediaPlayerForContextMenu*>(
                  video->GetWebMediaPlayer()),
              HasVideo())
      .WillRepeatedly(Return(false));

  DOMRect* rect = video->GetBoundingClientRect();
  PhysicalOffset location(LayoutUnit((rect->left() + rect->right()) / 2),
                          LayoutUnit((rect->top() + rect->bottom()) / 2));
  EXPECT_TRUE(ShowContextMenu(location, kMenuSourceMouse));

  // Context menu info are sent to the WebLocalFrameClient.
  ContextMenuData context_menu_data = GetWebFrameClient().GetContextMenuData();
  EXPECT_EQ(mojom::blink::ContextMenuDataMediaType::kVideo,
            context_menu_data.media_type);
  EXPECT_EQ(video_url, context_menu_data.src_url.spec().c_str());

  const Vector<std::pair<ContextMenuData::MediaFlags, bool>>
      expected_media_flags = {
          {ContextMenuData::kMediaInError, false},
          {ContextMenuData::kMediaPaused, true},
          {ContextMenuData::kMediaMuted, false},
          {ContextMenuData::kMediaLoop, false},
          {ContextMenuData::kMediaCanSave, true},
          {ContextMenuData::kMediaHasAudio, false},
          {ContextMenuData::kMediaCanToggleControls, false},
          {ContextMenuData::kMediaControls, false},
          {ContextMenuData::kMediaCanPrint, false},
          {ContextMenuData::kMediaCanRotate, false},
          {ContextMenuData::kMediaCanPictureInPicture, false},
          {ContextMenuData::kMediaPictureInPicture, false},
          {ContextMenuData::kMediaCanLoop, true},
      };

  for (const auto& expected_media_flag : expected_media_flags) {
    EXPECT_EQ(expected_media_flag.second,
              !!(context_menu_data.media_flags & expected_media_flag.first))
        << "Flag 0x" << std::hex << expected_media_flag.first;
  }
}

TEST_F(ContextMenuControllerTest, VideoWithAudioOnly) {
  ContextMenuAllowedScope context_menu_allowed_scope;
  HitTestResult hit_test_result;
  AtomicString video_url("https://example.com/foo.webm");

  // Make sure Picture-in-Picture is enabled.
  GetDocument()->GetSettings()->SetPictureInPictureEnabled(true);

  // Setup video element.
  Persistent<HTMLVideoElement> video =
      MakeGarbageCollected<HTMLVideoElement>(*GetDocument());
  video->SetSrc(video_url);
  GetDocument()->body()->AppendChild(video);
  test::RunPendingTasks();
  SetReadyState(video.Get(), HTMLMediaElement::kHaveNothing);
  test::RunPendingTasks();

  EXPECT_CALL(*static_cast<MockWebMediaPlayerForContextMenu*>(
                  video->GetWebMediaPlayer()),
              HasVideo())
      .WillRepeatedly(Return(false));
  EXPECT_CALL(*static_cast<MockWebMediaPlayerForContextMenu*>(
                  video->GetWebMediaPlayer()),
              HasAudio())
      .WillRepeatedly(Return(true));

  DOMRect* rect = video->GetBoundingClientRect();
  PhysicalOffset location(LayoutUnit((rect->left() + rect->right()) / 2),
                          LayoutUnit((rect->top() + rect->bottom()) / 2));
  EXPECT_TRUE(ShowContextMenu(location, kMenuSourceMouse));

  // Context menu info are sent to the WebLocalFrameClient.
  ContextMenuData context_menu_data = GetWebFrameClient().GetContextMenuData();
  EXPECT_EQ(mojom::blink::ContextMenuDataMediaType::kAudio,
            context_menu_data.media_type);
  EXPECT_EQ(video_url, context_menu_data.src_url.spec().c_str());

  const Vector<std::pair<ContextMenuData::MediaFlags, bool>>
      expected_media_flags = {
          {ContextMenuData::kMediaInError, false},
          {ContextMenuData::kMediaPaused, true},
          {ContextMenuData::kMediaMuted, false},
          {ContextMenuData::kMediaLoop, false},
          {ContextMenuData::kMediaCanSave, true},
          {ContextMenuData::kMediaHasAudio, true},
          {ContextMenuData::kMediaCanToggleControls, false},
          {ContextMenuData::kMediaControls, false},
          {ContextMenuData::kMediaCanPrint, false},
          {ContextMenuData::kMediaCanRotate, false},
          {ContextMenuData::kMediaCanPictureInPicture, false},
          {ContextMenuData::kMediaPictureInPicture, false},
          {ContextMenuData::kMediaCanLoop, true},
      };

  for (const auto& expected_media_flag : expected_media_flags) {
    EXPECT_EQ(expected_media_flag.second,
              !!(context_menu_data.media_flags & expected_media_flag.first))
        << "Flag 0x" << std::hex << expected_media_flag.first;
  }
}

TEST_F(ContextMenuControllerTest, PictureInPictureEnabledVideoLoaded) {
  // Make sure Picture-in-Picture is enabled.
  GetDocument()->GetSettings()->SetPictureInPictureEnabled(true);

  ContextMenuAllowedScope context_menu_allowed_scope;
  HitTestResult hit_test_result;
  AtomicString video_url("https://example.com/foo.webm");

  // Setup video element.
  Persistent<HTMLVideoElement> video =
      MakeGarbageCollected<HTMLVideoElement>(*GetDocument());
  video->SetSrc(video_url);
  GetDocument()->body()->AppendChild(video);
  test::RunPendingTasks();
  SetReadyState(video.Get(), HTMLMediaElement::kHaveMetadata);
  test::RunPendingTasks();

  EXPECT_CALL(*static_cast<MockWebMediaPlayerForContextMenu*>(
                  video->GetWebMediaPlayer()),
              HasVideo())
      .WillRepeatedly(Return(true));

  DOMRect* rect = video->GetBoundingClientRect();
  PhysicalOffset location(LayoutUnit((rect->left() + rect->right()) / 2),
                          LayoutUnit((rect->top() + rect->bottom()) / 2));
  EXPECT_TRUE(ShowContextMenu(location, kMenuSourceMouse));

  // Context menu info are sent to the WebLocalFrameClient.
  ContextMenuData context_menu_data = GetWebFrameClient().GetContextMenuData();
  EXPECT_EQ(mojom::blink::ContextMenuDataMediaType::kVideo,
            context_menu_data.media_type);
  EXPECT_EQ(video_url, context_menu_data.src_url.spec().c_str());

  const Vector<std::pair<ContextMenuData::MediaFlags, bool>>
      expected_media_flags = {
          {ContextMenuData::kMediaInError, false},
          {ContextMenuData::kMediaPaused, true},
          {ContextMenuData::kMediaMuted, false},
          {ContextMenuData::kMediaLoop, false},
          {ContextMenuData::kMediaCanSave, true},
          {ContextMenuData::kMediaHasAudio, false},
          {ContextMenuData::kMediaCanToggleControls, true},
          {ContextMenuData::kMediaControls, false},
          {ContextMenuData::kMediaCanPrint, false},
          {ContextMenuData::kMediaCanRotate, false},
          {ContextMenuData::kMediaCanPictureInPicture, true},
          {ContextMenuData::kMediaPictureInPicture, false},
          {ContextMenuData::kMediaCanLoop, true},
      };

  for (const auto& expected_media_flag : expected_media_flags) {
    EXPECT_EQ(expected_media_flag.second,
              !!(context_menu_data.media_flags & expected_media_flag.first))
        << "Flag 0x" << std::hex << expected_media_flag.first;
  }
}

TEST_F(ContextMenuControllerTest, PictureInPictureDisabledVideoLoaded) {
  // Make sure Picture-in-Picture is disabled.
  GetDocument()->GetSettings()->SetPictureInPictureEnabled(false);

  ContextMenuAllowedScope context_menu_allowed_scope;
  HitTestResult hit_test_result;
  AtomicString video_url("https://example.com/foo.webm");

  // Setup video element.
  Persistent<HTMLVideoElement> video =
      MakeGarbageCollected<HTMLVideoElement>(*GetDocument());
  video->SetSrc(video_url);
  GetDocument()->body()->AppendChild(video);
  test::RunPendingTasks();
  SetReadyState(video.Get(), HTMLMediaElement::kHaveMetadata);
  test::RunPendingTasks();

  EXPECT_CALL(*static_cast<MockWebMediaPlayerForContextMenu*>(
                  video->GetWebMediaPlayer()),
              HasVideo())
      .WillRepeatedly(Return(true));

  DOMRect* rect = video->GetBoundingClientRect();
  PhysicalOffset location(LayoutUnit((rect->left() + rect->right()) / 2),
                          LayoutUnit((rect->top() + rect->bottom()) / 2));
  EXPECT_TRUE(ShowContextMenu(location, kMenuSourceMouse));

  // Context menu info are sent to the WebLocalFrameClient.
  ContextMenuData context_menu_data = GetWebFrameClient().GetContextMenuData();
  EXPECT_EQ(mojom::blink::ContextMenuDataMediaType::kVideo,
            context_menu_data.media_type);
  EXPECT_EQ(video_url, context_menu_data.src_url.spec().c_str());

  const Vector<std::pair<ContextMenuData::MediaFlags, bool>>
      expected_media_flags = {
          {ContextMenuData::kMediaInError, false},
          {ContextMenuData::kMediaPaused, true},
          {ContextMenuData::kMediaMuted, false},
          {ContextMenuData::kMediaLoop, false},
          {ContextMenuData::kMediaCanSave, true},
          {ContextMenuData::kMediaHasAudio, false},
          {ContextMenuData::kMediaCanToggleControls, true},
          {ContextMenuData::kMediaControls, false},
          {ContextMenuData::kMediaCanPrint, false},
          {ContextMenuData::kMediaCanRotate, false},
          {ContextMenuData::kMediaCanPictureInPicture, false},
          {ContextMenuData::kMediaPictureInPicture, false},
          {ContextMenuData::kMediaCanLoop, true},
      };

  for (const auto& expected_media_flag : expected_media_flags) {
    EXPECT_EQ(expected_media_flag.second,
              !!(context_menu_data.media_flags & expected_media_flag.first))
        << "Flag 0x" << std::hex << expected_media_flag.first;
  }
}

TEST_F(ContextMenuControllerTest, MediaStreamVideoLoaded) {
  // Make sure Picture-in-Picture is enabled.
  GetDocument()->GetSettings()->SetPictureInPictureEnabled(true);

  ContextMenuAllowedScope context_menu_allowed_scope;
  HitTestResult hit_test_result;

  // Setup video element.
  Persistent<HTMLVideoElement> video =
      MakeGarbageCollected<HTMLVideoElement>(*GetDocument());
  MediaStreamComponentVector dummy_components;
  auto* media_stream_descriptor = MakeGarbageCollected<MediaStreamDescriptor>(
      dummy_components, dummy_components);
  video->SetSrcObjectVariant(media_stream_descriptor);
  GetDocument()->body()->AppendChild(video);
  test::RunPendingTasks();
  SetReadyState(video.Get(), HTMLMediaElement::kHaveMetadata);
  test::RunPendingTasks();

  EXPECT_CALL(*static_cast<MockWebMediaPlayerForContextMenu*>(
                  video->GetWebMediaPlayer()),
              HasVideo())
      .WillRepeatedly(Return(true));

  DOMRect* rect = video->GetBoundingClientRect();
  PhysicalOffset location(LayoutUnit((rect->left() + rect->right()) / 2),
                          LayoutUnit((rect->top() + rect->bottom()) / 2));
  EXPECT_TRUE(ShowContextMenu(location, kMenuSourceMouse));

  // Context menu info are sent to the WebLocalFrameClient.
  ContextMenuData context_menu_data = GetWebFrameClient().GetContextMenuData();
  EXPECT_EQ(mojom::blink::ContextMenuDataMediaType::kVideo,
            context_menu_data.media_type);

  const Vector<std::pair<ContextMenuData::MediaFlags, bool>>
      expected_media_flags = {
          {ContextMenuData::kMediaInError, false},
          {ContextMenuData::kMediaPaused, true},
          {ContextMenuData::kMediaMuted, false},
          {ContextMenuData::kMediaLoop, false},
          {ContextMenuData::kMediaCanSave, false},
          {ContextMenuData::kMediaHasAudio, false},
          {ContextMenuData::kMediaCanToggleControls, true},
          {ContextMenuData::kMediaControls, false},
          {ContextMenuData::kMediaCanPrint, false},
          {ContextMenuData::kMediaCanRotate, false},
          {ContextMenuData::kMediaCanPictureInPicture, true},
          {ContextMenuData::kMediaPictureInPicture, false},
          {ContextMenuData::kMediaCanLoop, false},
      };

  for (const auto& expected_media_flag : expected_media_flags) {
    EXPECT_EQ(expected_media_flag.second,
              !!(context_menu_data.media_flags & expected_media_flag.first))
        << "Flag 0x" << std::hex << expected_media_flag.first;
  }
}

TEST_F(ContextMenuControllerTest, InfiniteDurationVideoLoaded) {
  // Make sure Picture-in-Picture is enabled.
  GetDocument()->GetSettings()->SetPictureInPictureEnabled(true);

  ContextMenuAllowedScope context_menu_allowed_scope;
  HitTestResult hit_test_result;
  AtomicString video_url("https://example.com/foo.webm");

  // Setup video element.
  Persistent<HTMLVideoElement> video =
      MakeGarbageCollected<HTMLVideoElement>(*GetDocument());
  video->SetSrc(video_url);
  GetDocument()->body()->AppendChild(video);
  test::RunPendingTasks();
  SetReadyState(video.Get(), HTMLMediaElement::kHaveMetadata);
  test::RunPendingTasks();

  EXPECT_CALL(*static_cast<MockWebMediaPlayerForContextMenu*>(
                  video->GetWebMediaPlayer()),
              HasVideo())
      .WillRepeatedly(Return(true));

  EXPECT_CALL(*static_cast<MockWebMediaPlayerForContextMenu*>(
                  video->GetWebMediaPlayer()),
              Duration())
      .WillRepeatedly(Return(std::numeric_limits<double>::infinity()));
  DurationChanged(video.Get());

  DOMRect* rect = video->GetBoundingClientRect();
  PhysicalOffset location(LayoutUnit((rect->left() + rect->right()) / 2),
                          LayoutUnit((rect->top() + rect->bottom()) / 2));
  EXPECT_TRUE(ShowContextMenu(location, kMenuSourceMouse));

  // Context menu info are sent to the WebLocalFrameClient.
  ContextMenuData context_menu_data = GetWebFrameClient().GetContextMenuData();
  EXPECT_EQ(mojom::blink::ContextMenuDataMediaType::kVideo,
            context_menu_data.media_type);
  EXPECT_EQ(video_url, context_menu_data.src_url.spec().c_str());

  const Vector<std::pair<ContextMenuData::MediaFlags, bool>>
      expected_media_flags = {
          {ContextMenuData::kMediaInError, false},
          {ContextMenuData::kMediaPaused, true},
          {ContextMenuData::kMediaMuted, false},
          {ContextMenuData::kMediaLoop, false},
          {ContextMenuData::kMediaCanSave, false},
          {ContextMenuData::kMediaHasAudio, false},
          {ContextMenuData::kMediaCanToggleControls, true},
          {ContextMenuData::kMediaControls, false},
          {ContextMenuData::kMediaCanPrint, false},
          {ContextMenuData::kMediaCanRotate, false},
          {ContextMenuData::kMediaCanPictureInPicture, true},
          {ContextMenuData::kMediaPictureInPicture, false},
          {ContextMenuData::kMediaCanLoop, false},
      };

  for (const auto& expected_media_flag : expected_media_flags) {
    EXPECT_EQ(expected_media_flag.second,
              !!(context_menu_data.media_flags & expected_media_flag.first))
        << "Flag 0x" << std::hex << expected_media_flag.first;
  }
}

TEST_F(ContextMenuControllerTest, HitTestVideoChildElements) {
  // Test that hit tests on parts of a video element result in hits on the video
  // element itself as opposed to its child elements.

  ContextMenuAllowedScope context_menu_allowed_scope;
  HitTestResult hit_test_result;
  AtomicString video_url("https://example.com/foo.webm");

  // Setup video element.
  Persistent<HTMLVideoElement> video =
      MakeGarbageCollected<HTMLVideoElement>(*GetDocument());
  video->SetSrc(video_url);
  video->setAttribute(
      html_names::kStyleAttr,
      AtomicString(
          "position: absolute; left: 0; top: 0; width: 200px; height: 200px"));
  GetDocument()->body()->AppendChild(video);
  test::RunPendingTasks();
  SetReadyState(video.Get(), HTMLMediaElement::kHaveMetadata);
  test::RunPendingTasks();

  auto check_location = [&](PhysicalOffset location) {
    EXPECT_TRUE(ShowContextMenu(location, kMenuSourceMouse));

    ContextMenuData context_menu_data =
        GetWebFrameClient().GetContextMenuData();
    EXPECT_EQ(mojom::blink::ContextMenuDataMediaType::kVideo,
              context_menu_data.media_type);
    EXPECT_EQ(video_url, context_menu_data.src_url.spec().c_str());
  };

  // Center of video.
  check_location(PhysicalOffset(100, 100));

  // Play button.
  check_location(PhysicalOffset(10, 195));

  // Timeline bar.
  check_location(PhysicalOffset(100, 195));
}

TEST_F(ContextMenuControllerTest, EditingActionsEnabledInSVGDocument) {
  frame_test_helpers::LoadFrame(LocalMainFrame(), R"SVG(data:image/svg+xml,
    <svg xmlns='http://www.w3.org/2000/svg'
         xmlns:h='http://www.w3.org/1999/xhtml'
         font-family='Ahem'>
      <text y='20' id='t'>Copyable text</text>
      <foreignObject y='30' width='100' height='200'>
        <h:div id='e' style='width: 100px; height: 50px'
               contenteditable='true'>
          XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        </h:div>
      </foreignObject>
    </svg>
  )SVG");
  LoadAhem();

  Document* document = GetDocument();
  ASSERT_TRUE(document->IsSVGDocument());

  Element* text_element = document->getElementById(AtomicString("t"));
  document->UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  FrameSelection& selection = document->GetFrame()->Selection();

  // <text> element
  selection.SelectSubString(*text_element, 4, 8);
  EXPECT_TRUE(ShowContextMenuForElement(text_element, kMenuSourceMouse));

  ContextMenuData context_menu_data = GetWebFrameClient().GetContextMenuData();
  EXPECT_EQ(context_menu_data.media_type,
            mojom::blink::ContextMenuDataMediaType::kNone);
  EXPECT_EQ(context_menu_data.edit_flags, ContextMenuDataEditFlags::kCanCopy);
  EXPECT_EQ(context_menu_data.selected_text, "able tex");

  // <div contenteditable=true>
  Element* editable_element = document->getElementById(AtomicString("e"));
  selection.SelectSubString(*editable_element, 0, 42);
  EXPECT_TRUE(ShowContextMenuForElement(editable_element, kMenuSourceMouse));

  context_menu_data = GetWebFrameClient().GetContextMenuData();
  EXPECT_EQ(context_menu_data.media_type,
            mojom::blink::ContextMenuDataMediaType::kNone);
  EXPECT_EQ(context_menu_data.edit_flags,
            ContextMenuDataEditFlags::kCanCut |
                ContextMenuDataEditFlags::kCanCopy |
                ContextMenuDataEditFlags::kCanPaste |
                ContextMenuDataEditFlags::kCanDelete |
                ContextMenuDataEditFlags::kCanEditRichly);
}

TEST_F(ContextMenuControllerTest, EditingActionsEnabledInXMLDocument) {
  frame_test_helpers::LoadFrame(LocalMainFrame(), R"XML(data:text/xml,
    <root>
      <style xmlns="http://www.w3.org/1999/xhtml">
        root { color: blue; }
      </style>
      <text id="t">Blue text</text>
    </root>
  )XML");

  Document* document = GetDocument();
  ASSERT_TRUE(IsA<XMLDocument>(document));
  ASSERT_FALSE(IsA<HTMLDocument>(document));

  Element* text_element = document->getElementById(AtomicString("t"));
  document->UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  FrameSelection& selection = document->GetFrame()->Selection();

  selection.SelectAll();
  EXPECT_TRUE(ShowContextMenuForElement(text_element, kMenuSourceMouse));

  ContextMenuData context_menu_data = GetWebFrameClient().GetContextMenuData();
  EXPECT_EQ(context_menu_data.media_type,
            mojom::blink::ContextMenuDataMediaType::kNone);
  EXPECT_EQ(context_menu_data.edit_flags, ContextMenuDataEditFlags::kCanCopy);
  EXPECT_EQ(context_menu_data.selected_text, "Blue text");
}

TEST_F(ContextMenuControllerTest, ShowNonLocatedContextMenuEvent) {
  GetDocument()->documentElement()->setInnerHTML(
      "<input id='sample' type='text' size='5' value='Sample Input Text'>");

  Document* document = GetDocument();
  Element* input_element = document->getElementById(AtomicString("sample"));
  document->UpdateStyleAndLayout(DocumentUpdateReason::kTest);

  // Select the 'Sample' of |input|.
  DOMRect* rect = input_element->GetBoundingClientRect();
  WebGestureEvent gesture_event(
      WebInputEvent::Type::kGestureLongPress, WebInputEvent::kNoModifiers,
      base::TimeTicks::Now(), WebGestureDevice::kTouchscreen);
  gesture_event.SetPositionInWidget(gfx::PointF(rect->left(), rect->top()));
  GetWebView()->MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(gesture_event, ui::LatencyInfo()));

  ContextMenuData context_menu_data = GetWebFrameClient().GetContextMenuData();
  EXPECT_EQ(context_menu_data.selected_text, "Sample");

  // Adjust the selection from the start of |input| to the middle.
  gfx::Point middle_point((rect->left() + rect->right()) / 2,
                          (rect->top() + rect->bottom()) / 2);
  LocalMainFrame()->MoveRangeSelectionExtent(middle_point);
  LocalMainFrame()->LocalRootFrameWidget()->ShowContextMenu(
      ui::mojom::blink::MenuSourceType::kTouchHandle, middle_point);

  
"""


```