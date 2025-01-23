Response:
Let's break down the thought process for analyzing this code snippet and generating the response.

**1. Understanding the Goal:**

The request asks for a functional summary of `web_page_popup_impl.cc`, focusing on its relationship with web technologies (JavaScript, HTML, CSS), logical inferences, potential errors, debugging steps, and a concise summary for the first part of the file.

**2. Initial Scan and Keyword Recognition:**

The first step is to quickly scan the code, looking for familiar terms and patterns:

* **Includes:** `WebPagePopupImpl.h`, `WebViewImpl.h`, `LocalFrame.h`, `Document.h`, `EventHandler.h`, `Page.h`, `Settings.h`, `WebInputEvent.h`, etc. These immediately suggest the file is about creating and managing pop-up windows within a web browser.
* **Namespaces:** `blink`. This confirms it's part of the Blink rendering engine.
* **Class Definition:** `class WebPagePopupImpl`. This is the core class we need to understand.
* **Inheritance/Composition:**  The constructor takes `WebViewImpl`, `PagePopupClient`, and manages `WidgetBase`. This indicates relationships with the main browser window and the specific logic for the pop-up.
* **Methods:** `SetWindowRect`, `ShowPopup`, `ClosePopup`, `HandleKeyEvent`, `HandleMouseEvent`, `HandleGestureEvent`, `PostMessageToPopup`, etc. These hint at the lifecycle and interaction aspects of the pop-up.
* **Event Handling:**  The presence of `HandleKeyEvent`, `HandleMouseEvent`, and `HandleGestureEvent` clearly links it to processing user interactions.
* **Configuration:** References to `Settings` suggest the pop-up's behavior can be configured.
* **Callbacks and Delegates:**  The use of `WTF::BindOnce` for `DidShowPopup` and `DidSetBounds` indicates asynchronous operations and communication with other components.
* **Compositing:**  Includes for `cc/animation`, `cc/layers`, and methods like `InitializeCompositing`, `SetRootLayer` indicate involvement in the rendering pipeline.

**3. Deeper Dive into Functionality (Mental Modeling):**

Based on the initial scan, I started building a mental model of what `WebPagePopupImpl` *does*:

* **Creation:** It's responsible for creating and initializing a new pop-up window. This involves creating a new `Page`, `LocalFrame`, and connecting them.
* **Display:** It interacts with the platform to show the pop-up (`popup_widget_host_->ShowPopup`).
* **Positioning and Sizing:** It manages the pop-up's size and position on the screen (`SetWindowRect`).
* **Input Handling:** It receives and processes user input events (keyboard, mouse, touch) and dispatches them to the appropriate parts of the rendering engine.
* **Communication:** It can send messages to the pop-up's content (`PostMessageToPopup`).
* **Lifecycle Management:** It handles the opening, updating, and closing of the pop-up.
* **Accessibility:** It integrates with the accessibility tree.
* **Configuration:** It applies settings from the parent window.
* **Rendering:** It participates in the compositing process.

**4. Connecting to Web Technologies (JavaScript, HTML, CSS):**

Now, the task is to link these functionalities to the core web technologies:

* **HTML:** The `WriteDocument` method and the creation of a `LocalFrame` suggest that the pop-up will load and render HTML content.
* **CSS:** The rendering process inherently involves CSS styling. The `Settings` related to font sizes and color schemes also point to CSS influence.
* **JavaScript:**  `PostMessageToPopup` provides a direct mechanism for JavaScript in the opener window to communicate with JavaScript in the pop-up. The event handling (mouse clicks, key presses) triggers JavaScript event listeners within the pop-up.

**5. Logical Inferences and Examples:**

With the core functionality understood, I started thinking about logical flows:

* **Input:**  A user action (click, key press) in the pop-up region is captured by the browser, translated into a `WebInputEvent`, and passed to `WebPagePopupImpl` for processing.
* **Positioning:** The `initial_rect_` and `GetAnchorRectInScreen` suggest the pop-up's initial position is often related to the element that triggered it.
* **Closing:**  Clicking outside the pop-up or pressing Escape likely triggers the `Cancel()` method and ultimately closes the pop-up.

**6. Identifying Potential Errors and User Actions:**

Consider common issues:

* **Pop-up Blockers:**  While not directly in this code, the pop-up mechanism is often targeted by blockers.
* **Incorrect Positioning:**  The pop-up might appear off-screen or overlap other elements if positioning calculations are wrong.
* **Focus Issues:** The pop-up might not receive focus correctly, leading to unexpected behavior.
* **Unexpected Closing:**  The pop-up might close prematurely due to unintended interactions.

**7. Debugging Clues:**

Think about how a developer might debug issues related to pop-ups:

* **Breakpoints:** Setting breakpoints in `HandleKeyEvent`, `HandleMouseEvent`, `SetWindowRect` would be crucial.
* **Logging:** The `AddMessageToConsole` (even if not directly used in this snippet's primary logic) indicates a general mechanism for logging.
* **Event Flow:** Understanding the sequence of events leading to the pop-up's creation and interaction is key.

**8. Structuring the Response:**

Finally, organize the information into the requested categories: functionality, web technology relationships, logical inferences, errors, debugging, and summary. Use clear and concise language, providing specific examples.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Perhaps the file directly handles the *content* of the pop-up. **Correction:** The file manages the *window* and its interaction, while the content is loaded into the `LocalFrame`.
* **Focus on the "Impl" suffix:** This often indicates an implementation detail of a more abstract interface (like `WebPagePopup`).
* **Double-checking includes:** Ensure the included headers align with the identified functionalities.

By following these steps, combining code analysis with knowledge of web browser architecture and common development practices, a comprehensive and accurate response can be generated.
好的，我们来分析一下 `blink/renderer/core/exported/web_page_popup_impl.cc` 文件的功能。

**文件功能归纳:**

`WebPagePopupImpl.cc` 实现了 Chromium Blink 引擎中页面弹出窗口 (Page Popup) 的核心逻辑。 它负责创建、管理和销毁页面弹出窗口，并处理与弹出窗口相关的用户交互、渲染和生命周期事件。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`WebPagePopupImpl.cc` 虽然是 C++ 代码，但它所管理的功能与 JavaScript, HTML, CSS 息息相关，因为页面弹出窗口最终会加载并渲染这些 Web 技术构成的内容。

1. **HTML:**
   - **功能关系:** 当一个页面弹出窗口被创建时，它会加载并显示 HTML 内容。`WebPagePopupImpl` 通过 `popup_client_->WriteDocument(data)` 获取需要加载的 HTML 数据。
   - **举例:**  假设一个网页 JavaScript 使用 `window.open()` 创建了一个新的弹出窗口。`WebPagePopupImpl` 负责创建这个新的窗口，并且会从某个地方（通常是网络或者缓存）获取要在这个新窗口中显示的 HTML 代码。

2. **CSS:**
   - **功能关系:**  弹出窗口中的 HTML 内容会应用 CSS 样式进行渲染。`WebPagePopupImpl` 中创建的 `Page` 对象会处理 CSS 的解析和应用。`popup_client_->AdjustSettings(page_->GetSettings())` 可能会根据父窗口的设置调整弹出窗口的样式相关设置。
   - **举例:**  弹出窗口可能继承了父窗口的一些样式设置（例如，最小字体大小），或者拥有自己独立的 CSS 样式表来控制其外观。

3. **JavaScript:**
   - **功能关系:**  弹出窗口中可以运行 JavaScript 代码，并且父窗口和弹出窗口之间可以通过 `postMessage` API 进行通信。`WebPagePopupImpl::PostMessageToPopup` 方法就实现了向弹出窗口发送消息的功能。 弹出窗口内部的 JavaScript 代码也会通过各种事件监听器（例如 `onclick`）来响应用户的交互。
   - **举例:**
     - 父窗口的 JavaScript 代码可以使用 `popup.postMessage("hello from parent", "*")` 向弹出窗口发送消息。
     - 弹出窗口的 JavaScript 代码可以监听 `message` 事件来接收父窗口发送的消息：`window.addEventListener('message', function(event) { console.log(event.data); });`
     - 弹出窗口中的按钮点击事件会触发相应的 JavaScript 代码执行。

**逻辑推理及假设输入与输出:**

假设输入：用户在一个网页上点击了一个链接，该链接的 `target` 属性设置为 `_blank` 或者通过 JavaScript 调用 `window.open()` 创建了一个新的弹出窗口。

逻辑推理：

1. 浏览器接收到创建弹出窗口的请求。
2. Blink 渲染引擎会创建 `WebPagePopupImpl` 的实例来管理这个新的弹出窗口。
3. `WebPagePopupImpl` 会创建新的 `Page` 和 `LocalFrame` 对象，用于加载和渲染弹出窗口的内容。
4. `popup_client_` (实现了 `PagePopupClient` 接口的对象) 会提供弹出窗口的初始配置信息和要加载的 HTML 数据。
5. `WebPagePopupImpl` 将 HTML 数据加载到 `LocalFrame` 中。
6. 浏览器进程会与操作系统进行交互，创建一个新的窗口并显示出来。
7. 用户可以在弹出窗口中进行操作，例如点击链接、填写表单等。
8. `WebPagePopupImpl` 会处理这些用户输入事件，并将其传递给相应的 DOM 元素进行处理。

假设输出：一个新的浏览器窗口被打开，显示了由 `popup_client_->WriteDocument(data)` 提供的 HTML 内容，并且用户可以与该窗口进行交互。

**涉及用户或编程常见的使用错误及举例说明:**

1. **弹出窗口被浏览器拦截:**
   - **错误原因:**  浏览器通常会阻止未经用户交互触发的弹出窗口，以防止恶意广告或骚扰。
   - **举例:**  在页面的 `onload` 事件中直接调用 `window.open()` 很可能会被浏览器拦截。正确的做法通常是在用户点击按钮或其他用户操作后调用 `window.open()`。

2. **父窗口和弹出窗口之间的通信错误:**
   - **错误原因:** 使用 `postMessage` 进行跨域通信时，如果目标窗口的 `origin` 设置不正确，消息可能无法送达。
   - **举例:** 父窗口使用 `popup.postMessage("data", "http://example.com")` 发送消息，但弹出窗口的 URL 不是 `http://example.com`，则消息可能不会被接收。

3. **弹出窗口的大小和位置控制不当:**
   - **错误原因:**  `window.open()` 的参数设置不正确可能导致弹出窗口显示在屏幕外或者大小不合适。
   - **举例:**  `window.open("...", "", "width=10,height=10")` 会创建一个非常小的窗口，可能难以使用。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在网页上触发了创建弹出窗口的操作。** 这可能是：
   - 点击了一个 `<a>` 标签，其 `target` 属性为 `_blank` 或其他指定名称。
   - 点击了一个按钮，该按钮的事件处理程序中调用了 `window.open()`。
   - 某些 JavaScript 代码在特定条件下（例如用户交互后）调用了 `window.open()`。

2. **浏览器接收到创建弹出窗口的请求。** 浏览器内核（例如 Chromium 的 Browser 进程）会识别这个请求。

3. **Browser 进程会指示 Renderer 进程创建一个新的渲染进程 (如果需要) 并创建一个新的 `WebPagePopupImpl` 对象。**  这个过程涉及到进程间通信 (IPC)。

4. **`WebPagePopupImpl` 的构造函数被调用。**  传入相关的参数，例如 `popup_widget_host` 和 `popup_client`。

5. **`popup_client_->WriteDocument(data)` 被调用，获取要加载的 HTML 数据。**  这通常涉及 Browser 进程从网络或缓存中获取数据，并通过 IPC 传递给 Renderer 进程。

6. **`WebPagePopupImpl::ShowPopup` 或类似的方法被调用，指示操作系统创建并显示窗口。**

7. **后续的用户在弹出窗口中的操作（例如鼠标点击、键盘输入）会被操作系统捕获，并传递给 Renderer 进程进行处理。**  `WebPagePopupImpl` 的 `HandleKeyEvent`、`HandleMouseEvent` 等方法会接收这些事件。

**调试线索:**

- 如果弹出窗口没有被创建，检查浏览器是否阻止了弹出窗口。
- 如果弹出窗口内容显示不正确，检查 `popup_client_->WriteDocument(data)` 提供的数据是否正确。
- 如果弹出窗口无法响应用户交互，检查相关的事件处理逻辑是否正确，以及 `HandleKeyEvent`、`HandleMouseEvent` 等方法是否被调用。
- 可以通过在 `WebPagePopupImpl` 的关键方法中添加日志输出或断点，来跟踪弹出窗口的创建和生命周期。

**第 1 部分功能归纳:**

这部分代码主要负责 `WebPagePopupImpl` 类的**初始化和基本设置**。它完成了以下关键功能：

- **创建 `WebPagePopupImpl` 对象:**  包括构造函数的初始化，设置各种客户端接口 (ChromeClient, LocalFrameClient)。
- **创建和配置 `Page` 对象:**  为弹出窗口创建一个独立的 `Page` 对象，并根据父窗口的设置进行一些初始配置（例如，启用 JavaScript、允许脚本关闭窗口等）。
- **连接到 `PagePopupClient`:**  接收来自 `PagePopupClient` 的信息，例如初始大小、位置和要加载的 HTML 数据。
- **初始化 Compositing:** 设置渲染相关的组件。
- **创建主 `LocalFrame`:** 为弹出窗口创建主框架，用于加载和渲染内容。
- **加载初始 HTML 内容:**  调用 `ForceSynchronousDocumentInstall` 加载由 `popup_client_` 提供的 HTML 数据。
- **显示弹出窗口:**  调用 `popup_widget_host_->ShowPopup` 请求操作系统显示窗口。
- **处理焦点:**  设置弹出窗口的初始焦点。

总而言之，这部分代码是弹出窗口生命周期的起点，负责搭建弹出窗口的基本框架和加载初始内容。

### 提示词
```
这是目录为blink/renderer/core/exported/web_page_popup_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2012 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/exported/web_page_popup_impl.h"

#include <memory>

#include "cc/animation/animation_host.h"
#include "cc/animation/animation_timeline.h"
#include "cc/base/features.h"
#include "cc/layers/picture_layer.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "third_party/blink/public/common/storage_key/storage_key.h"
#include "third_party/blink/public/common/tokens/tokens.h"
#include "third_party/blink/public/mojom/input/input_handler.mojom-blink.h"
#include "third_party/blink/public/web/web_view_client.h"
#include "third_party/blink/renderer/core/accessibility/ax_object_cache_base.h"
#include "third_party/blink/renderer/core/css/media_feature_overrides.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/events/event_dispatch_forbidden_scope.h"
#include "third_party/blink/renderer/core/events/message_event.h"
#include "third_party/blink/renderer/core/events/web_input_event_conversion.h"
#include "third_party/blink/renderer/core/exported/web_settings_impl.h"
#include "third_party/blink/renderer/core/exported/web_view_impl.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/frame/local_frame_ukm_aggregator.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/screen_metrics_emulator.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/frame/web_frame_widget_impl.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/geometry/dom_rect.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/loader/empty_clients.h"
#include "third_party/blink/renderer/core/loader/frame_load_request.h"
#include "third_party/blink/renderer/core/page/focus_controller.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/page_animator.h"
#include "third_party/blink/renderer/core/page/page_popup_client.h"
#include "third_party/blink/renderer/core/page/page_popup_controller.h"
#include "third_party/blink/renderer/platform/bindings/script_forbidden_scope.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/keyboard_codes.h"
#include "third_party/blink/renderer/platform/scheduler/public/agent_group_scheduler.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread.h"
#include "third_party/blink/renderer/platform/text/text_direction.h"
#include "third_party/blink/renderer/platform/web_test_support.h"
#include "third_party/blink/renderer/platform/widget/frame_widget.h"
#include "third_party/blink/renderer/platform/widget/input/input_metrics.h"
#include "third_party/blink/renderer/platform/widget/input/widget_input_handler_manager.h"
#include "third_party/blink/renderer/platform/widget/widget_base.h"

namespace blink {
namespace {
ScrollableArea* ToScrollableArea(Node* node) {
  DCHECK(node);
  LayoutBox* scrolling_box = node->GetLayoutBox();
  if (auto* element = DynamicTo<Element>(node))
    scrolling_box = element->GetLayoutBoxForScrolling();
  return scrolling_box ? scrolling_box->GetScrollableArea() : nullptr;
}

bool CanScroll(Node* node) {
  if (!node)
    return false;
  return ToScrollableArea(node);
}

Node* FindFirstScroller(Node* event_target) {
  DCHECK(event_target);
  Node* cur_node = nullptr;
  bool found = false;
  LayoutBox* cur_box = event_target->GetLayoutObject()
                           ? event_target->GetLayoutObject()->EnclosingBox()
                           : nullptr;
  while (cur_box) {
    cur_node = cur_box->GetNode();
    if (CanScroll(cur_node)) {
      found = true;
      break;
    }
    cur_box = cur_box->ContainingBlock();
  }
  if (found && cur_node)
    return cur_node;
  return nullptr;
}

Page* CreatePage(ChromeClient& chrome_client, WebViewImpl& opener_web_view) {
  Settings& main_settings = opener_web_view.GetPage()->GetSettings();
  Page* page = Page::CreateNonOrdinary(
      chrome_client,
      opener_web_view.GetPage()->GetPageScheduler()->GetAgentGroupScheduler(),
      &opener_web_view.GetPage()->GetColorProviderColorMaps());
  page->GetSettings().SetAcceleratedCompositingEnabled(true);
  page->GetSettings().SetScriptEnabled(true);
  page->GetSettings().SetAllowScriptsToCloseWindows(true);
  page->GetSettings().SetMinimumFontSize(main_settings.GetMinimumFontSize());
  page->GetSettings().SetMinimumLogicalFontSize(
      main_settings.GetMinimumLogicalFontSize());
  page->GetSettings().SetScrollAnimatorEnabled(
      main_settings.GetScrollAnimatorEnabled());
  page->GetSettings().SetAvailablePointerTypes(
      main_settings.GetAvailablePointerTypes());
  page->GetSettings().SetPrimaryPointerType(
      main_settings.GetPrimaryPointerType());
  page->GetSettings().SetPreferredColorScheme(
      main_settings.GetPreferredColorScheme());
  page->GetSettings().SetForceDarkModeEnabled(
      main_settings.GetForceDarkModeEnabled());
  page->GetSettings().SetInForcedColors(main_settings.GetInForcedColors());

  const MediaFeatureOverrides* media_feature_overrides =
      opener_web_view.GetPage()->GetMediaFeatureOverrides();
  if (media_feature_overrides &&
      media_feature_overrides->GetPreferredColorScheme().has_value()) {
    page->SetMediaFeatureOverride(
        AtomicString("prefers-color-scheme"),
        media_feature_overrides->GetPreferredColorScheme().value() ==
                mojom::blink::PreferredColorScheme::kDark
            ? "dark"
            : "light");
  }
  return page;
}

}  // namespace

class PagePopupChromeClient final : public EmptyChromeClient {
 public:
  explicit PagePopupChromeClient(WebPagePopupImpl* popup) : popup_(popup) {}

  void SetWindowRect(const gfx::Rect& rect, LocalFrame&) override {
    popup_->SetWindowRect(rect);
  }

  bool IsPopup() override { return true; }

 private:
  void CloseWindow() override {
    // This skips past the PopupClient by calling ClosePopup() instead of
    // Cancel().
    popup_->ClosePopup();
  }

  gfx::Rect RootWindowRect(LocalFrame&) override {
    // There is only one frame/widget in a WebPagePopup, so we can ignore the
    // param.
    return popup_->WindowRectInScreen();
  }

  gfx::Rect LocalRootToScreenDIPs(const gfx::Rect& rect_in_local_root,
                                  const LocalFrameView* view) const override {
    DCHECK(view);
    DCHECK_EQ(view->GetChromeClient(), this);

    gfx::Rect window_rect = popup_->WindowRectInScreen();
    gfx::Rect rect_in_dips =
        popup_->widget_base_->BlinkSpaceToEnclosedDIPs(rect_in_local_root);
    rect_in_dips.Offset(window_rect.x(), window_rect.y());
    return rect_in_dips;
  }

  float WindowToViewportScalar(LocalFrame*,
                               const float scalar_value) const override {
    return popup_->widget_base_->DIPsToBlinkSpace(scalar_value);
  }

  void AddMessageToConsole(LocalFrame*,
                           mojom::ConsoleMessageSource,
                           mojom::ConsoleMessageLevel,
                           const String& message,
                           unsigned line_number,
                           const String&,
                           const String&) override {
#ifndef NDEBUG
    fprintf(stderr, "CONSOLE MESSAGE:%u: %s\n", line_number,
            message.Utf8().c_str());
#endif
  }

  void ScheduleAnimation(const LocalFrameView*,
                         base::TimeDelta delay = base::TimeDelta()) override {
    // Destroying/removing the popup's content can be seen as a mutation that
    // ends up calling ScheduleAnimation(). Since the popup is going away, we
    // do not wish to actually do anything.
    if (popup_->closing_)
      return;

    // When the renderer has a compositor thread we need to follow the
    // normal code path.
    if (WebTestSupport::IsRunningWebTest() && !Thread::CompositorThread()) {
      // In single-threaded web tests, the owner frame tree runs the composite
      // step for the popup. Popup widgets don't run any composite step on their
      // own. And we don't run popup tests with a compositor thread, so no need
      // to check for that.
      Document& opener_document =
          popup_->popup_client_->OwnerElement().GetDocument();
      if (Page* page = opener_document.GetPage()) {
        page->GetChromeClient().ScheduleAnimation(
            opener_document.GetFrame()->View(), delay);
      }
      return;
    }
    popup_->widget_base_->RequestAnimationAfterDelay(delay);
  }

  cc::AnimationHost* GetCompositorAnimationHost(LocalFrame&) const override {
    return popup_->widget_base_->AnimationHost();
  }

  cc::AnimationTimeline* GetScrollAnimationTimeline(
      LocalFrame&) const override {
    return popup_->widget_base_->ScrollAnimationTimeline();
  }

  const display::ScreenInfo& GetScreenInfo(LocalFrame&) const override {
    // LocalFrame is ignored since there is only 1 frame in a popup.
    return popup_->GetScreenInfo();
  }

  const display::ScreenInfos& GetScreenInfos(LocalFrame&) const override {
    // LocalFrame is ignored since there is only 1 frame in a popup.
    return popup_->GetScreenInfos();
  }

  gfx::Size MinimumWindowSize() const override { return gfx::Size(0, 0); }

  void SetEventListenerProperties(
      LocalFrame* frame,
      cc::EventListenerClass event_class,
      cc::EventListenerProperties properties) override {
    // WebPagePopup always routes input to main thread (set up in RenderWidget),
    // so no need to update listener properties.
  }

  void SetHasScrollEventHandlers(LocalFrame* frame,
                                 bool has_event_handlers) override {
    // WebPagePopup's compositor does not handle compositor thread input (set up
    // in RenderWidget) so there is no need to signal this.
  }

  void SetTouchAction(LocalFrame* frame, TouchAction touch_action) override {
    // Touch action is not used in the compositor for WebPagePopup.
  }

  void AttachRootLayer(scoped_refptr<cc::Layer> layer,
                       LocalFrame* local_root) override {
    popup_->SetRootLayer(layer.get());
  }

  void UpdateTooltipUnderCursor(LocalFrame&,
                                const String& tooltip_text,
                                TextDirection dir) override {
    popup_->widget_base_->UpdateTooltipUnderCursor(tooltip_text, dir);
  }

  void UpdateTooltipFromKeyboard(LocalFrame&,
                                 const String& tooltip_text,
                                 TextDirection dir,
                                 const gfx::Rect& bounds) override {
    popup_->widget_base_->UpdateTooltipFromKeyboard(tooltip_text, dir, bounds);
  }

  void ClearKeyboardTriggeredTooltip(LocalFrame&) override {
    popup_->widget_base_->ClearKeyboardTriggeredTooltip();
  }

  void InjectScrollbarGestureScroll(
      LocalFrame& local_frame,
      const gfx::Vector2dF& delta,
      ui::ScrollGranularity granularity,
      cc::ElementId scrollable_area_element_id,
      WebInputEvent::Type injected_type) override {
    popup_->InjectScrollbarGestureScroll(
        delta, granularity, scrollable_area_element_id, injected_type);
  }

  WebPagePopupImpl* popup_;
};

// WebPagePopupImpl ----------------------------------------------------------

WebPagePopupImpl::WebPagePopupImpl(
    CrossVariantMojoAssociatedRemote<mojom::blink::PopupWidgetHostInterfaceBase>
        popup_widget_host,
    CrossVariantMojoAssociatedRemote<mojom::blink::WidgetHostInterfaceBase>
        widget_host,
    CrossVariantMojoAssociatedReceiver<mojom::blink::WidgetInterfaceBase>
        widget,
    WebViewImpl* opener_web_view,
    AgentGroupScheduler& agent_group_scheduler,
    const display::ScreenInfos& screen_infos,
    PagePopupClient* popup_client)
    : opener_web_view_(opener_web_view),
      chrome_client_(MakeGarbageCollected<PagePopupChromeClient>(this)),
      local_frame_client_(MakeGarbageCollected<EmptyLocalFrameClient>()),
      page_(CreatePage(*chrome_client_, *opener_web_view)),
      popup_client_(popup_client),
      popup_widget_host_(std::move(popup_widget_host)),
      widget_base_(std::make_unique<WidgetBase>(
          /*widget_base_client=*/this,
          std::move(widget_host),
          std::move(widget),
          agent_group_scheduler.DefaultTaskRunner(),
          /*hidden=*/false,
          /*never_composited=*/false,
          /*is_embedded=*/false,
          /*is_for_scalable_page=*/true)) {
  DCHECK(popup_client_);
  popup_widget_host_.set_disconnect_handler(WTF::BindOnce(
      &WebPagePopupImpl::WidgetHostDisconnected, WTF::Unretained(this)));
  if (auto* main_frame_widget = opener_web_view->MainFrameViewWidget()) {
    if (auto* device_emulator = main_frame_widget->DeviceEmulator()) {
      opener_widget_screen_origin_ = device_emulator->ViewRectOrigin();
      opener_original_widget_screen_origin_ =
          device_emulator->original_view_rect().origin();
      opener_emulator_scale_ = device_emulator->scale();
    }
  }

  InitializeCompositing(screen_infos,
                        /*settings=*/nullptr);

  popup_client_->AdjustSettings(page_->GetSettings());
  popup_client_->CreatePagePopupController(*page_, *this);

  // Creating new WindowAgentFactory because page popup content is owned by the
  // user agent and should be isolated from the main frame. However, if we are a
  // page popup in LayoutTests ensure we use the popup owner's frame for looking
  // up the Agent so tests can possibly access the document via internals API.
  WindowAgentFactory* window_agent_factory = nullptr;
  if (WebTestSupport::IsRunningWebTest()) {
    Document& owner_document = popup_client_->OwnerElement().GetDocument();
    window_agent_factory = &owner_document.GetFrame()->window_agent_factory();
  }

  auto* frame = MakeGarbageCollected<LocalFrame>(
      local_frame_client_, *page_,
      /* FrameOwner* */ nullptr, /* Frame* parent */ nullptr,
      /* Frame* previous_sibling */ nullptr,
      FrameInsertType::kInsertInConstructor, LocalFrameToken(),
      window_agent_factory,
      /* InterfaceRegistry* */ nullptr,
      /* BrowserInterfaceBroker */ mojo::NullRemote());
  frame->SetPagePopupOwner(popup_client_->OwnerElement());
  frame->SetView(MakeGarbageCollected<LocalFrameView>(*frame));

  if (WebTestSupport::IsRunningWebTest()) {
    // In order for the shared WindowAgentFactory for tests to work correctly,
    // we need to also copy settings used in WindowAgent selection over to the
    // popup frame.
    Settings* owner_settings =
        popup_client_->OwnerElement().GetDocument().GetFrame()->GetSettings();
    frame->GetSettings()->SetWebSecurityEnabled(
        owner_settings->GetWebSecurityEnabled());
    frame->GetSettings()->SetAllowUniversalAccessFromFileURLs(
        owner_settings->GetAllowUniversalAccessFromFileURLs());
  }

  // TODO(https://crbug.com/1355751) Initialize `storage_key`.
  frame->Init(/*opener=*/nullptr, DocumentToken(), /*policy_container=*/nullptr,
              StorageKey(), /*document_ukm_source_id=*/ukm::kInvalidSourceId,
              /*creator_base_url=*/KURL());
  frame->View()->SetParentVisible(true);
  frame->View()->SetSelfVisible(true);

  DCHECK(frame->DomWindow());
  DCHECK_EQ(popup_client_->OwnerElement().GetDocument().ExistingAXObjectCache(),
            frame->GetDocument()->ExistingAXObjectCache());
  if (AXObjectCache* cache = frame->GetDocument()->ExistingAXObjectCache())
    cache->ChildrenChanged(&popup_client_->OwnerElement());

  page_->DidInitializeCompositing(*widget_base_->AnimationHost());

  SegmentedBuffer data;
  popup_client_->WriteDocument(data);
  frame->SetLayoutZoomFactor(popup_client_->ZoomFactor());
  frame->ForceSynchronousDocumentInstall(AtomicString("text/html"),
                                         std::move(data));

  popup_owner_client_rect_ =
      popup_client_->OwnerElement().GetBoundingClientRect();
  popup_widget_host_->ShowPopup(
      initial_rect_, GetAnchorRectInScreen(),
      WTF::BindOnce(&WebPagePopupImpl::DidShowPopup, WTF::Unretained(this)));
  should_defer_setting_window_rect_ = false;
  widget_base_->SetPendingWindowRect(initial_rect_);

  SetFocus(true);
}

WebPagePopupImpl::~WebPagePopupImpl() {
  // Ensure DestroyPage was called.
  DCHECK(!page_);
}

void WebPagePopupImpl::DidShowPopup() {
  if (!widget_base_)
    return;
  widget_base_->AckPendingWindowRect();
}

void WebPagePopupImpl::DidSetBounds() {
  if (!widget_base_)
    return;
  widget_base_->AckPendingWindowRect();
}

void WebPagePopupImpl::InitializeCompositing(
    const display::ScreenInfos& screen_infos,
    const cc::LayerTreeSettings* settings) {
  // Careful Initialize() is called after InitializeCompositing, so don't do
  // much work here.
  widget_base_->InitializeCompositing(*page_->GetPageScheduler(), screen_infos,
                                      settings,
                                      /*frame_widget_input_handler=*/nullptr,
                                      /*previous_widget=*/nullptr);
  cc::LayerTreeDebugState debug_state =
      widget_base_->LayerTreeHost()->GetDebugState();
  debug_state.TurnOffHudInfoDisplay();
  widget_base_->LayerTreeHost()->SetDebugState(debug_state);
}

void WebPagePopupImpl::SetCursor(const ui::Cursor& cursor) {
  widget_base_->SetCursor(cursor);
}

bool WebPagePopupImpl::HandlingInputEvent() {
  return widget_base_->input_handler().handling_input_event();
}

void WebPagePopupImpl::SetHandlingInputEvent(bool handling) {
  widget_base_->input_handler().set_handling_input_event(handling);
}

void WebPagePopupImpl::ProcessInputEventSynchronouslyForTesting(
    const WebCoalescedInputEvent& event) {
  widget_base_->input_handler().HandleInputEvent(event, nullptr,
                                                 base::DoNothing());
}

void WebPagePopupImpl::DispatchNonBlockingEventForTesting(
    std::unique_ptr<WebCoalescedInputEvent> event) {
  widget_base_->widget_input_handler_manager()
      ->DispatchEventOnInputThreadForTesting(
          std::move(event),
          mojom::blink::WidgetInputHandler::DispatchEventCallback());
}

void WebPagePopupImpl::UpdateTextInputState() {
  widget_base_->UpdateTextInputState();
}

void WebPagePopupImpl::UpdateSelectionBounds() {
  widget_base_->UpdateSelectionBounds();
}

void WebPagePopupImpl::ShowVirtualKeyboard() {
  widget_base_->ShowVirtualKeyboard();
}

void WebPagePopupImpl::SetFocus(bool focus) {
  widget_base_->SetFocus(focus
                             ? mojom::blink::FocusState::kFocused
                             : mojom::blink::FocusState::kNotFocusedAndActive);
}

bool WebPagePopupImpl::HasFocus() {
  return widget_base_->has_focus();
}

void WebPagePopupImpl::FlushInputProcessedCallback() {
  widget_base_->FlushInputProcessedCallback();
}

void WebPagePopupImpl::CancelCompositionForPepper() {
  widget_base_->CancelCompositionForPepper();
}

void WebPagePopupImpl::ApplyVisualProperties(
    const VisualProperties& visual_properties) {
  widget_base_->UpdateVisualProperties(visual_properties);
}

const display::ScreenInfo& WebPagePopupImpl::GetScreenInfo() {
  return widget_base_->GetScreenInfo();
}

const display::ScreenInfos& WebPagePopupImpl::GetScreenInfos() {
  return widget_base_->screen_infos();
}

const display::ScreenInfo& WebPagePopupImpl::GetOriginalScreenInfo() {
  return widget_base_->GetScreenInfo();
}

const display::ScreenInfos& WebPagePopupImpl::GetOriginalScreenInfos() {
  return widget_base_->screen_infos();
}

gfx::Rect WebPagePopupImpl::WindowRect() {
  return widget_base_->WindowRect();
}

gfx::Rect WebPagePopupImpl::ViewRect() {
  return widget_base_->ViewRect();
}

void WebPagePopupImpl::SetScreenRects(const gfx::Rect& widget_screen_rect,
                                      const gfx::Rect& window_screen_rect) {
  widget_base_->SetScreenRects(widget_screen_rect, window_screen_rect);
}

gfx::Size WebPagePopupImpl::VisibleViewportSizeInDIPs() {
  return widget_base_->VisibleViewportSizeInDIPs();
}

bool WebPagePopupImpl::IsHidden() const {
  return widget_base_->is_hidden();
}

void WebPagePopupImpl::SetCompositorVisible(bool visible) {
  widget_base_->SetCompositorVisible(visible);
}

void WebPagePopupImpl::WarmUpCompositor() {
  widget_base_->WarmUpCompositor();
}

void WebPagePopupImpl::PostMessageToPopup(const String& message) {
  if (!page_)
    return;
  ScriptForbiddenScope::AllowUserAgentScript allow_script;
  MainFrame().DomWindow()->DispatchEvent(*MessageEvent::Create(message));
}

void WebPagePopupImpl::Update() {
  if (!page_ && !popup_client_)
    return;

  DOMRect* dom_rect = popup_client_->OwnerElement().GetBoundingClientRect();
  bool forced_update = (*dom_rect != *popup_owner_client_rect_);
  if (forced_update)
    popup_owner_client_rect_ = dom_rect;

  popup_client_->Update(forced_update);
  if (forced_update)
    SetWindowRect(WindowRectInScreen());
}

void WebPagePopupImpl::DestroyPage() {
  page_->WillStopCompositing();
  page_->WillBeDestroyed();
  page_.Clear();
}

AXObject* WebPagePopupImpl::RootAXObject(Element* popup_owner) {
  if (!page_)
    return nullptr;
  // If |page_| is non-null, the main frame must have a Document.
  Document* document = MainFrame().GetDocument();
  AXObjectCacheBase* cache =
      To<AXObjectCacheBase>(document->ExistingAXObjectCache());
  // There should never be a circumstance when RootAXObject() is triggered
  // and the AXObjectCache doesn't already exist. It's called when trying
  // to attach the accessibility tree of the pop-up to the host page.
  return cache->GetOrCreate(document, cache->Get(popup_owner));
}

void WebPagePopupImpl::SetWindowRect(const gfx::Rect& rect_in_screen) {
  if (ShouldCheckPopupPositionForTelemetry()) {
    gfx::Rect owner_window_rect_in_screen = OwnerWindowRectInScreen();
    Document& document = popup_client_->OwnerElement().GetDocument();
    if (owner_window_rect_in_screen.Contains(rect_in_screen)) {
      UseCounter::Count(document,
                        WebFeature::kPopupDoesNotExceedOwnerWindowBounds);
    } else {
      WebFeature feature =
          document.GetFrame()->IsOutermostMainFrame()
              ? WebFeature::kPopupExceedsOwnerWindowBounds
              : WebFeature::kPopupExceedsOwnerWindowBoundsForIframe;
      UseCounter::Count(document, feature);
    }
  }

  gfx::Rect window_rect = rect_in_screen;

  // Popups aren't emulated, but the WidgetScreenRect and WindowScreenRect
  // given to them are. When they set the WindowScreenRect it is based on those
  // emulated values, so we reverse the emulation.
  if (opener_emulator_scale_)
    EmulatedToScreenRect(window_rect);

  if (!should_defer_setting_window_rect_) {
    widget_base_->SetPendingWindowRect(window_rect);
    popup_widget_host_->SetPopupBounds(
        window_rect,
        WTF::BindOnce(&WebPagePopupImpl::DidSetBounds, WTF::Unretained(this)));
  } else {
    initial_rect_ = window_rect;
  }
}

void WebPagePopupImpl::SetRootLayer(scoped_refptr<cc::Layer> layer) {
  root_layer_ = std::move(layer);
  widget_base_->LayerTreeHost()->SetRootLayer(root_layer_);
}

void WebPagePopupImpl::SetSuppressFrameRequestsWorkaroundFor704763Only(
    bool suppress_frame_requests) {
  if (!page_)
    return;
  page_->Animator().SetSuppressFrameRequestsWorkaroundFor704763Only(
      suppress_frame_requests);
}

void WebPagePopupImpl::UpdateLifecycle(WebLifecycleUpdate requested_update,
                                       DocumentUpdateReason reason) {
  if (!page_)
    return;
  // Popups always update their lifecycle in the context of the containing
  // document's lifecycle, so explicitly override the reason.
  page_->UpdateLifecycle(MainFrame(), requested_update,
                         DocumentUpdateReason::kPagePopup);
}

void WebPagePopupImpl::Resize(const gfx::Size& new_size_in_viewport) {
  gfx::Size new_size_in_dips =
      widget_base_->BlinkSpaceToFlooredDIPs(new_size_in_viewport);
  gfx::Rect window_rect_in_dips = WindowRectInScreen();

  // TODO(bokan): We should only call into this if the bounds actually changed
  // but this reveals a bug in Aura. crbug.com/633140.
  window_rect_in_dips.set_size(new_size_in_dips);
  SetWindowRect(window_rect_in_dips);

  if (page_) {
    MainFrame().View()->Resize(new_size_in_viewport);
    page_->GetVisualViewport().SetSize(new_size_in_viewport);
  }
}

WebInputEventResult WebPagePopupImpl::HandleKeyEvent(
    const WebKeyboardEvent& event) {
  if (closing_)
    return WebInputEventResult::kNotHandled;

  if (suppress_next_keypress_event_) {
    suppress_next_keypress_event_ = false;
    return WebInputEventResult::kHandledSuppressed;
  }

  if (WebInputEvent::Type::kRawKeyDown == event.GetType()) {
    Element* focused_element = FocusedElement();
    if (event.windows_key_code == VKEY_TAB && focused_element &&
        focused_element->IsKeyboardFocusable()) {
      // If the tab key is pressed while a keyboard focusable element is
      // focused, we should not send a corresponding keypress event.
      suppress_next_keypress_event_ = true;
    }
  }
  LocalFrame::NotifyUserActivation(
      popup_client_->OwnerElement().GetDocument().GetFrame(),
      mojom::blink::UserActivationNotificationType::kInteraction);
  return MainFrame().GetEventHandler().KeyEvent(event);
}

cc::LayerTreeHost* WebPagePopupImpl::LayerTreeHostForTesting() {
  return widget_base_->LayerTreeHost();
}

void WebPagePopupImpl::OnCommitRequested() {
  if (page_ && page_->MainFrame()) {
    if (auto* view = MainFrame().View())
      view->OnCommitRequested();
  }
}

void WebPagePopupImpl::BeginMainFrame(base::TimeTicks last_frame_time) {
  if (!page_)
    return;
  // FIXME: This should use lastFrameTimeMonotonic but doing so
  // breaks tests.
  page_->Animate(base::TimeTicks::Now());
}

void WebPagePopupImpl::WillHandleGestureEvent(const WebGestureEvent& event,
                                              bool* suppress) {}

void WebPagePopupImpl::WillHandleMouseEvent(const WebMouseEvent& event) {}

void WebPagePopupImpl::ObserveGestureEventAndResult(
    const WebGestureEvent& gesture_event,
    const gfx::Vector2dF& unused_delta,
    const cc::OverscrollBehavior& overscroll_behavior,
    bool event_processed) {
}

WebInputEventResult WebPagePopupImpl::HandleCharEvent(
    const WebKeyboardEvent& event) {
  if (suppress_next_keypress_event_) {
    suppress_next_keypress_event_ = false;
    return WebInputEventResult::kHandledSuppressed;
  }
  return HandleKeyEvent(event);
}

WebInputEventResult WebPagePopupImpl::HandleGestureEvent(
    const WebGestureEvent& event) {
  if (closing_)
    return WebInputEventResult::kNotHandled;
  if (event.GetType() == WebInputEvent::Type::kGestureTap ||
      event.GetType() == WebInputEvent::Type::kGestureTapDown) {
    if (!IsViewportPointInWindow(event.PositionInWidget().x(),
                                 event.PositionInWidget().y())) {
      Cancel();
      return WebInputEventResult::kNotHandled;
    }
    LocalFrame::NotifyUserActivation(
        popup_client_->OwnerElement().GetDocument().GetFrame(),
        mojom::blink::UserActivationNotificationType::kInteraction);
    CheckScreenPointInOwnerWindowAndCount(
        event.PositionInScreen(),
        WebFeature::kPopupGestureTapExceedsOwnerWindowBounds);
  }
  if (event.GetType() == WebInputEvent::Type::kGestureScrollBegin) {
    HitTestLocation locationScroll(event.PositionInWidget());
    HitTestResult resultScroll =
        MainFrame().GetEventHandler().HitTestResultAtLocation(locationScroll);
    scrollable_node_ = FindFirstScroller(resultScroll.InnerNode());
    RecordScrollReasonsMetric(
        event.SourceDevice(),
        cc::MainThreadScrollingReason::kPopupNoThreadedInput);
    return WebInputEventResult::kHandledSystem;
  }
  if (event.GetType() == WebInputEvent::Type::kGestureScrollUpdate) {
    if (!scrollable_node_) {
      return WebInputEventResult::kNotHandled;
    }

    ScrollableArea* scrollable = ToScrollableArea(scrollable_node_);

    if (!scrollable) {
      return WebInputEventResult::kNotHandled;
    }
    ScrollOffset scroll_offset(-event.data.scroll_update.delta_x,
                               -event.data.scroll_update.delta_y);
    scrollable->UserScroll(event.data.scroll_update.delta_units, scroll_offset,
                           ScrollableArea::ScrollCallback());
    return WebInputEventResult::kHandledSystem;
  }
  if (event.GetType() == WebInputEvent::Type::kGestureScrollEnd) {
    scrollable_node_ = nullptr;
    return WebInputEventResult::kHandledSystem;
  }
  WebGestureEvent scaled_event =
      TransformWebGestureEvent(MainFrame().View(), event);
  return MainFrame().GetEventHandler().HandleGestureEvent(scaled_event);
}

void WebPagePopupImpl::HandleMouseDown(LocalFrame& main_frame,
                                       const WebMouseEvent& event) {
  if (IsViewportPointInWindow(event.PositionInWidget().x(),
                              event.PositionInWidget().y())) {
    LocalFrame::NotifyUserActivation(
        popup_client_->OwnerElement().GetDocument().GetFrame(),
        mojom::blink::UserActivationNotificationType::kInteraction);
    CheckScreenPointInOwnerWindowAndCount(
        event.PositionInScreen(),
        WebFeature::kPopupMouseDownExceedsOwnerWindowBounds);
    WidgetEventHandler::HandleMouseDown(main_frame, event);
  } else {
    Cancel();
  }
}

WebInputEventResult WebPagePopupImpl::HandleMouseWheel(
    LocalFrame& main_frame,
    const WebMouseWheelEvent& event) {
  if (IsViewportPointInWindow(event.PositionInWidget().x(),
                              event.PositionInWidget().y())) {
    CheckScreenPointInOwnerWindowAndCount(
        event.PositionInScreen(),
        WebFeature::kPopupMouseWheelExceedsOwnerWindowBounds);
    return WidgetEventHandler::HandleMouseWheel(main_frame, event);
  }
  Cancel();
  return WebInputEventResult::kNotHandled;
}

LocalFrame& WebPagePopupImpl::MainFrame() const {
  DCHECK(page_);
  // The main frame for a popup will never be out-of-process.
  return *To<LocalFrame>(page_->MainFrame());
}

Element* WebPagePopupImpl::FocusedElement() const {
  if (!page_)
    return nullptr;

  LocalFrame* frame = page_->GetFocusController().FocusedFrame();
  if (!frame)
    return nullptr;

  Document* document = frame->GetDocument();
  if (!document)
    return nullptr;

  return document->FocusedElement();
}

bool WebPagePopupImpl::IsViewportPointInWindow(int x, int y) {
  gfx::Point point_in_dips =
      widget_base_->BlinkSpaceToFlooredDIPs(gfx::Point(x, y));
  gfx::Rect window_rect = WindowRectInScreen();
  return gfx::Rect(window_re
```