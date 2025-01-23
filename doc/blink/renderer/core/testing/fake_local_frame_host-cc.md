Response:
My thinking process to analyze the `fake_local_frame_host.cc` file goes like this:

1. **Understand the Purpose:** The filename itself, "fake_local_frame_host.cc", strongly suggests this is a mock or stub implementation. The "fake" prefix is a common convention for test doubles. The "LocalFrameHost" part indicates it's simulating the behavior of a real `LocalFrameHost` component.

2. **Identify the Context:** The directory path `blink/renderer/core/testing/` confirms this is part of the Blink rendering engine and resides within the testing infrastructure. This immediately tells me this code isn't used in production builds but is solely for testing other parts of Blink.

3. **Analyze the `Init` Method:** This method is key. It uses `provider->OverrideBinderForTesting`. This confirms the "fake" nature. It's overriding the mechanism that binds the `LocalFrameHost` interface. Instead of using the real implementation, it's substituting `FakeLocalFrameHost`. This is a classic dependency injection technique used in testing.

4. **Examine the Methods:**  I go through each method within the class. I notice a recurring pattern:
    * Many methods are empty (`{}`). This reinforces the "fake" idea – they don't perform real actions.
    * Some methods have simple, predictable return values or side effects specifically designed for testing scenarios. For example, `EnterFullscreen` always calls the callback with `true`. Modal dialogs also return predictable values.
    * Methods dealing with more complex behavior in the real `LocalFrameHost` are often either empty or contain a `NOTREACHED()` macro. This indicates these functionalities are not intended to be tested through this fake implementation.

5. **Relate to Web Technologies (JavaScript, HTML, CSS):**  Now I start connecting the method names and their parameters to web technologies:
    * **Fullscreen:** `EnterFullscreen`, `ExitFullscreen`, `FullscreenStateChanged` directly relate to the JavaScript Fullscreen API.
    * **Protocol Handlers:** `RegisterProtocolHandler`, `UnregisterProtocolHandler` are about allowing web pages to handle specific URL schemes.
    * **Security:** `DidDisplayInsecureContent`, `DidContainInsecureFormAction`, `EnforceInsecureRequestPolicy` are related to web security features and how the browser flags insecure content.
    * **DOM and Rendering:** `MainDocumentElementAvailable`, `SetNeedsOcclusionTracking`, `VisibilityChanged`, `DidChangeThemeColor`, `DidChangeBackgroundColor` are connected to how the browser builds and renders the web page.
    * **Navigation:** `DidFailLoadWithError`, `DidFinishLoad`, `DidChangeLoadProgress`, `GoToEntryAtOffset`, `DidBlockNavigation` are all about the process of loading and navigating between web pages.
    * **Title and Favicon:** `UpdateTitle`, `UpdateAppTitle`, `UpdateFaviconURL` are about displaying information in the browser's UI.
    * **User Interaction:** `DidFocusFrame`, `DidCallFocus`, `ScrollRectToVisibleInParentFrame`, `BubbleLogicalScrollInParentFrame`, `UpdateUserActivationState` are related to how users interact with the page (focusing, scrolling, clicking).
    * **Dialogs:** `RunModalAlertDialog`, `RunModalConfirmDialog`, `RunModalPromptDialog`, `RunBeforeUnloadConfirm` are the browser's native dialog boxes triggered by JavaScript.
    * **Popups and Context Menus:** `ShowPopupMenu`, `CreateNewPopupWidget`, `ShowContextMenu` deal with UI elements that appear on user interaction.
    * **Drag and Drop:** `StartDragging` is for the drag-and-drop functionality.
    * **Console Logging:** `DidAddMessageToConsole` is about logging messages from JavaScript.
    * **Accessibility:** `HandleAccessibilityFindInPageResult`, `HandleAccessibilityFindInPageTermination` are related to accessibility features.
    * **Resource Timing:** `ForwardResourceTimingToParent` is about performance monitoring.

6. **Identify Logical Inferences (Assumptions & Outputs):** Since this is a *fake*, the "logic" is usually very simple and predetermined.
    * **Assumption:** A test calls `EnterFullscreen`.
    * **Output:** The `EnterFullscreenCallback` will be invoked with `true`.
    * **Assumption:** A test calls `RunModalConfirmDialog`.
    * **Output:** The `RunModalConfirmDialogCallback` will be invoked with `true`. This allows tests to proceed as if the user confirmed the dialog.

7. **Identify Common Usage Errors (for Testers):**  Thinking about how this fake is *used* in testing helps.
    * **Error:** Assuming a method has real side effects. For instance, if a test expects `ExitFullscreen` to actually exit fullscreen mode, it will be wrong. This fake only simulates the *interface*.
    * **Error:** Not setting up expectations correctly. If a test needs to verify that `DidFailLoadWithError` is called under certain conditions, it would need to add code to the test to check if this fake method was invoked.
    * **Error:**  Relying on the fake's simplistic behavior when testing complex scenarios. The fake is designed for isolated unit tests, not end-to-end tests of complex interactions.

8. **Explain User Actions and Debugging:**  I consider how a developer might end up looking at this file during debugging.
    * **Scenario:**  A bug is suspected in the fullscreen functionality. A developer might trace the code and see the `EnterFullscreen` call. They might then investigate the `LocalFrameHost` implementation. If they are running a unit test, they might land here in the fake implementation.
    * **Scenario:** A test is failing, and the test uses a mock `LocalFrameHost`. The developer would examine this `FakeLocalFrameHost` to understand its behavior and whether the mock is behaving as expected.

9. **Structure the Output:** Finally, I organize the information logically, starting with the main purpose, then detailing the individual methods and their relevance to web technologies, including examples, assumptions, potential errors, and debugging scenarios. Using headings and bullet points makes the information easier to read and understand.

By following these steps, I can systematically analyze the code and extract the relevant information to answer the prompt comprehensively. The key is to recognize the "fake" nature of the class and analyze its methods in that context.

这个文件 `blink/renderer/core/testing/fake_local_frame_host.cc` 的主要功能是**提供一个用于测试的 `LocalFrameHost` 接口的虚假实现 (mock implementation)**。

在 Chromium 的 Blink 渲染引擎中，`LocalFrameHost` 是一个重要的接口，它代表了一个渲染进程中的主框架 (main frame)。它负责处理与浏览器进程 (browser process) 之间的通信，以及管理框架的各种行为和状态。

由于 `LocalFrameHost` 涉及到大量的复杂交互和浏览器内部机制，直接在单元测试中使用真实的 `LocalFrameHost` 会非常困难且耗时。`FakeLocalFrameHost` 的作用就是**简化测试，隔离被测试代码的依赖，并提供可预测的行为**。

以下是它的一些具体功能和与 Web 技术的关系：

**核心功能：**

* **提供 `LocalFrameHost` 接口的实现:** 它实现了 `third_party/blink/public/mojom/frame/local_frame_host.mojom` 中定义的 `LocalFrameHost` 接口的所有方法。
* **默认行为为空或简单返回:** 大部分方法的实现都是空的 (`{}`) 或者返回一个简单的、预设的值。这使得测试可以专注于被测试代码的逻辑，而不用担心 `LocalFrameHost` 的真实行为带来的干扰。
* **允许测试设置期望和断言:** 虽然代码中没有直接体现，但通常在测试代码中，会创建 `FakeLocalFrameHost` 的实例，并对某些方法的调用进行断言，以验证被测试代码是否按预期与 `LocalFrameHost` 交互。

**与 JavaScript, HTML, CSS 的关系 (通过 `LocalFrameHost` 接口):**

`LocalFrameHost` 接口涵盖了浏览器框架的许多方面，因此 `FakeLocalFrameHost` 的方法也间接与 JavaScript, HTML, CSS 的功能相关。以下是一些例子：

* **Fullscreen API (JavaScript):**
    * `EnterFullscreen(mojom::blink::FullscreenOptionsPtr options, EnterFullscreenCallback callback)`:  模拟进入全屏模式。在真实的浏览器中，JavaScript 可以调用 `element.requestFullscreen()` 进入全屏。`FakeLocalFrameHost` 简单地调用回调并返回 `true`，表示进入全屏成功。
    * **假设输入:**  测试代码调用了一个模拟 JavaScript 的全屏请求。
    * **输出:**  `EnterFullscreenCallback` 被调用，参数为 `true`。

* **Alert/Confirm/Prompt Dialogs (JavaScript):**
    * `RunModalAlertDialog(...)`, `RunModalConfirmDialog(...)`, `RunModalPromptDialog(...)`: 模拟 JavaScript 的 `alert()`, `confirm()`, `prompt()` 函数。`FakeLocalFrameHost` 返回预设的值 (例如 `confirm` 始终返回 `true`)，避免在测试中弹出真实的模态对话框。
    * **假设输入:**  被测试的 JavaScript 代码执行了 `confirm("Are you sure?")`。
    * **输出:** `RunModalConfirmDialogCallback` 被调用，参数为 `true`。

* **Navigation (JavaScript, HTML):**
    * `DidFinishLoad(const KURL& validated_url)`:  模拟框架加载完成。这与 HTML 页面的加载过程相关，也可能由 JavaScript 发起的导航导致。
    * **假设输入:**  测试代码模拟了一个导航到新页面的过程。
    * **输出:** `DidFinishLoad` 被调用，参数是新页面的 URL。

* **Title Updates (JavaScript, HTML):**
    * `UpdateTitle(const WTF::String& title, base::i18n::TextDirection title_direction)`: 模拟 JavaScript 通过 `document.title` 或 HTML 的 `<title>` 标签更新页面标题。
    * **假设输入:**  测试代码模拟了 JavaScript 执行 `document.title = "New Title";`。
    * **输出:** `UpdateTitle` 被调用，参数为 "New Title"。

* **User Activation (JavaScript):**
    * `UpdateUserActivationState(...)`: 模拟用户激活状态的变化，这与某些需要用户交互才能触发的功能 (例如自动播放媒体) 有关。JavaScript 的事件处理程序可能会影响用户激活状态。

* **Context Menu (JavaScript, HTML):**
    * `ShowContextMenu(...)`: 模拟显示上下文菜单。这通常由用户的右键点击触发，也可以通过 JavaScript API 控制。

* **Theme Color (CSS):**
    * `DidChangeThemeColor(std::optional<::SkColor> theme_color)`: 模拟页面主题颜色的改变，这可能由 CSS 的 `meta` 标签或 JavaScript 修改。

**逻辑推理的假设输入与输出:**

由于 `FakeLocalFrameHost` 的目的是模拟，其内部逻辑通常非常简单。对于大多数方法，假设输入会导致一个预期的、固定的输出或行为。

* **假设输入:** 调用 `EnterFullscreen` 方法。
* **输出:**  `EnterFullscreenCallback` 被同步调用，参数为 `true`。

* **假设输入:** 调用 `RunModalConfirmDialog` 方法。
* **输出:** `RunModalConfirmDialogCallback` 被同步调用，参数为 `true`。

* **假设输入:** 调用 `VisibilityChanged` 方法，参数为 `mojom::blink::FrameVisibility::kHidden`。
* **输出:**  该方法内部没有逻辑，因此没有明显的输出，但测试代码可能会断言这个方法被调用了。

**用户或编程常见的使用错误举例:**

* **错误假设 FakeLocalFrameHost 具有真实行为:**  开发者可能会错误地认为调用 `FakeLocalFrameHost::ExitFullscreen()` 会真的退出全屏模式。实际上，这个方法是空的，不会产生任何可见的效果。测试需要通过其他方式验证全屏退出逻辑。

* **忽略 FakeLocalFrameHost 的默认返回值:**  如果被测试的代码依赖于 `LocalFrameHost` 接口的某个方法的返回值，而 `FakeLocalFrameHost` 默认返回一个特定的值，开发者需要确保他们的测试考虑到这一点。例如，如果测试的代码期望 `RunModalConfirmDialog` 返回 `false` 的情况，但 `FakeLocalFrameHost` 始终返回 `true`，则测试会出错。

* **没有针对特定场景定制 FakeLocalFrameHost 的行为:** 在某些复杂的测试场景中，仅仅使用默认的 `FakeLocalFrameHost` 可能不够。开发者可能需要创建自定义的 mock 对象，或者修改 `FakeLocalFrameHost` 的行为，以更精确地模拟特定的 `LocalFrameHost` 行为。

**用户操作如何一步步到达这里 (作为调试线索):**

`FakeLocalFrameHost` 主要用于 **单元测试**，而不是在用户实际操作浏览器时被调用。 调试线索通常发生在开发或调试 **Blink 渲染引擎的单元测试** 时。

1. **开发者编写或运行一个针对 Blink 渲染引擎中某个功能的单元测试。** 这个功能可能涉及到框架的生命周期、导航、用户交互等等。

2. **测试代码中会创建 `FakeLocalFrameHost` 的实例，并将其注入到被测试的代码中，以替代真实的 `LocalFrameHost`。**  这通常通过依赖注入或 mock 对象框架来实现。

3. **当被测试的代码需要与 `LocalFrameHost` 交互时，它实际上会调用 `FakeLocalFrameHost` 的方法。**

4. **如果测试失败或需要调试 `LocalFrameHost` 相关的行为，开发者可能会查看 `FakeLocalFrameHost.cc` 文件，以了解其模拟的行为。**

**例如：**

假设开发者正在测试一个处理 JavaScript `confirm()` 对话框的模块。

1. 测试代码会创建一个 `FakeLocalFrameHost` 实例。
2. 测试代码会初始化一个需要测试的对象，并将 `FakeLocalFrameHost` 传递给它。
3. 测试代码会模拟一个触发 JavaScript `confirm()` 的场景。
4. 被测试的代码会调用 `FakeLocalFrameHost` 的 `RunModalConfirmDialog` 方法。
5. 开发者可能会在 `RunModalConfirmDialog` 方法中设置断点，或者查看其实现，以了解测试过程中 `confirm()` 对话框是如何被模拟的。

总而言之，`FakeLocalFrameHost.cc` 是 Blink 渲染引擎测试基础设施的关键组成部分，它通过提供一个轻量级、可控的 `LocalFrameHost` 实现，极大地简化了单元测试的编写和维护。它与 JavaScript, HTML, CSS 的关系主要体现在它模拟了真实 `LocalFrameHost` 中处理这些 Web 技术相关事件和操作的方法。

### 提示词
```
这是目录为blink/renderer/core/testing/fake_local_frame_host.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/testing/fake_local_frame_host.h"

#include "skia/public/mojom/skcolor.mojom-blink.h"
#include "third_party/blink/public/mojom/choosers/popup_menu.mojom-blink.h"
#include "third_party/blink/public/mojom/frame/frame_owner_properties.mojom-blink.h"
#include "third_party/blink/public/mojom/frame/frame_replication_state.mojom-blink.h"
#include "third_party/blink/public/mojom/frame/fullscreen.mojom-blink.h"
#include "third_party/blink/public/mojom/frame/remote_frame.mojom-blink.h"
#include "third_party/blink/public/mojom/timing/resource_timing.mojom-blink.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

void FakeLocalFrameHost::Init(blink::AssociatedInterfaceProvider* provider) {
  provider->OverrideBinderForTesting(
      mojom::blink::LocalFrameHost::Name_,
      WTF::BindRepeating(&FakeLocalFrameHost::BindFrameHostReceiver,
                         base::Unretained(this)));
}

void FakeLocalFrameHost::EnterFullscreen(
    mojom::blink::FullscreenOptionsPtr options,
    EnterFullscreenCallback callback) {
  std::move(callback).Run(true);
}

void FakeLocalFrameHost::ExitFullscreen() {}

void FakeLocalFrameHost::FullscreenStateChanged(
    bool is_fullscreen,
    mojom::blink::FullscreenOptionsPtr options) {}

void FakeLocalFrameHost::RegisterProtocolHandler(const WTF::String& scheme,
                                                 const ::blink::KURL& url,
                                                 bool user_gesture) {}

void FakeLocalFrameHost::UnregisterProtocolHandler(const WTF::String& scheme,
                                                   const ::blink::KURL& url,
                                                   bool user_gesture) {}

void FakeLocalFrameHost::DidDisplayInsecureContent() {}

void FakeLocalFrameHost::DidContainInsecureFormAction() {}

void FakeLocalFrameHost::MainDocumentElementAvailable(
    bool uses_temporary_zoom_level) {}

void FakeLocalFrameHost::SetNeedsOcclusionTracking(bool needs_tracking) {}
void FakeLocalFrameHost::SetVirtualKeyboardMode(
    ui::mojom::blink::VirtualKeyboardMode mode) {}

void FakeLocalFrameHost::VisibilityChanged(
    mojom::blink::FrameVisibility visibility) {}

void FakeLocalFrameHost::DidChangeThemeColor(
    std::optional<::SkColor> theme_color) {}

void FakeLocalFrameHost::DidChangeBackgroundColor(
    const SkColor4f& background_color,
    bool color_adjust) {}

void FakeLocalFrameHost::DidFailLoadWithError(const ::blink::KURL& url,
                                              int32_t error_code) {}

void FakeLocalFrameHost::DidFocusFrame() {}

void FakeLocalFrameHost::DidCallFocus() {}

void FakeLocalFrameHost::EnforceInsecureRequestPolicy(
    mojom::InsecureRequestPolicy policy_bitmap) {}

void FakeLocalFrameHost::EnforceInsecureNavigationsSet(
    const WTF::Vector<uint32_t>& set) {}

void FakeLocalFrameHost::SuddenTerminationDisablerChanged(
    bool present,
    blink::mojom::SuddenTerminationDisablerType disabler_type) {}

void FakeLocalFrameHost::HadStickyUserActivationBeforeNavigationChanged(
    bool value) {}

void FakeLocalFrameHost::ScrollRectToVisibleInParentFrame(
    const gfx::RectF& rect_to_scroll,
    blink::mojom::blink::ScrollIntoViewParamsPtr params) {}

void FakeLocalFrameHost::BubbleLogicalScrollInParentFrame(
    blink::mojom::blink::ScrollDirection direction,
    ui::ScrollGranularity granularity) {}

void FakeLocalFrameHost::DidBlockNavigation(
    const KURL& blocked_url,
    mojom::NavigationBlockedReason reason) {}

void FakeLocalFrameHost::DidChangeLoadProgress(double load_progress) {}

void FakeLocalFrameHost::DidFinishLoad(const KURL& validated_url) {}

void FakeLocalFrameHost::DispatchLoad() {}

void FakeLocalFrameHost::GoToEntryAtOffset(
    int32_t offset,
    bool has_user_gesture,
    std::optional<blink::scheduler::TaskAttributionId>) {}

void FakeLocalFrameHost::UpdateTitle(
    const WTF::String& title,
    base::i18n::TextDirection title_direction) {}

void FakeLocalFrameHost::UpdateAppTitle(const WTF::String& app_title) {}

void FakeLocalFrameHost::UpdateUserActivationState(
    mojom::blink::UserActivationUpdateType update_type,
    mojom::UserActivationNotificationType notification_type) {}

void FakeLocalFrameHost::HandleAccessibilityFindInPageResult(
    mojom::blink::FindInPageResultAXParamsPtr params) {}

void FakeLocalFrameHost::HandleAccessibilityFindInPageTermination() {}

void FakeLocalFrameHost::DocumentOnLoadCompleted() {}

void FakeLocalFrameHost::ForwardResourceTimingToParent(
    mojom::blink::ResourceTimingInfoPtr timing) {}

void FakeLocalFrameHost::DidDispatchDOMContentLoadedEvent() {}

void FakeLocalFrameHost::RunModalAlertDialog(
    const WTF::String& alert_message,
    bool disable_third_party_subframe_suppresion,
    RunModalAlertDialogCallback callback) {
  std::move(callback).Run();
}

void FakeLocalFrameHost::RunModalConfirmDialog(
    const WTF::String& alert_message,
    bool disable_third_party_subframe_suppresion,
    RunModalConfirmDialogCallback callback) {
  std::move(callback).Run(true);
}

void FakeLocalFrameHost::RunModalPromptDialog(
    const WTF::String& alert_message,
    const WTF::String& default_value,
    bool disable_third_party_subframe_suppresion,
    RunModalPromptDialogCallback callback) {
  std::move(callback).Run(true, g_empty_string);
}

void FakeLocalFrameHost::RunBeforeUnloadConfirm(
    bool is_reload,
    RunBeforeUnloadConfirmCallback callback) {
  std::move(callback).Run(true);
}

void FakeLocalFrameHost::UpdateFaviconURL(
    WTF::Vector<blink::mojom::blink::FaviconURLPtr> favicon_urls) {}

void FakeLocalFrameHost::DownloadURL(
    mojom::blink::DownloadURLParamsPtr params) {}

void FakeLocalFrameHost::FocusedElementChanged(
    bool is_editable_element,
    bool is_richly_editable_element,
    const gfx::Rect& bounds_in_frame_widget,
    blink::mojom::FocusType focus_type) {}

void FakeLocalFrameHost::TextSelectionChanged(const WTF::String& text,
                                              uint32_t offset,
                                              const gfx::Range& range) {}
void FakeLocalFrameHost::ShowPopupMenu(
    mojo::PendingRemote<mojom::blink::PopupMenuClient> popup_client,
    const gfx::Rect& bounds,
    int32_t item_height,
    double font_size,
    int32_t selected_item,
    Vector<mojom::blink::MenuItemPtr> menu_items,
    bool right_aligned,
    bool allow_multiple_selection) {}

void FakeLocalFrameHost::CreateNewPopupWidget(
    mojo::PendingAssociatedReceiver<mojom::blink::PopupWidgetHost>
        popup_widget_host,
    mojo::PendingAssociatedReceiver<mojom::blink::WidgetHost> widget_host,
    mojo::PendingAssociatedRemote<mojom::blink::Widget> widget) {}

void FakeLocalFrameHost::ShowContextMenu(
    mojo::PendingAssociatedRemote<mojom::blink::ContextMenuClient>
        context_menu_client,
    const blink::UntrustworthyContextMenuParams& params) {}

void FakeLocalFrameHost::DidLoadResourceFromMemoryCache(
    const KURL& url,
    const WTF::String& http_method,
    const WTF::String& mime_type,
    network::mojom::blink::RequestDestination request_destination,
    bool include_credentials) {}

void FakeLocalFrameHost::DidChangeFrameOwnerProperties(
    const blink::FrameToken& child_frame_token,
    mojom::blink::FrameOwnerPropertiesPtr frame_owner_properties) {}

void FakeLocalFrameHost::DidChangeOpener(
    const std::optional<LocalFrameToken>& opener_frame) {}

void FakeLocalFrameHost::DidChangeIframeAttributes(
    const blink::FrameToken& child_frame_token,
    mojom::blink::IframeAttributesPtr) {}

void FakeLocalFrameHost::DidChangeFramePolicy(
    const blink::FrameToken& child_frame_token,
    const FramePolicy& frame_policy) {}

void FakeLocalFrameHost::CapturePaintPreviewOfSubframe(
    const gfx::Rect& clip_rect,
    const base::UnguessableToken& guid) {}

void FakeLocalFrameHost::SetCloseListener(
    mojo::PendingRemote<mojom::blink::CloseListener>) {}

void FakeLocalFrameHost::Detach() {}

void FakeLocalFrameHost::GetKeepAliveHandleFactory(
    mojo::PendingReceiver<mojom::blink::KeepAliveHandleFactory> receiver) {}

void FakeLocalFrameHost::DidAddMessageToConsole(
    mojom::ConsoleMessageLevel log_level,
    const WTF::String& message,
    uint32_t line_no,
    const WTF::String& source_id,
    const WTF::String& untrusted_stack_trace) {}

void FakeLocalFrameHost::FrameSizeChanged(const gfx::Size& frame_size) {}

void FakeLocalFrameHost::DidInferColorScheme(
    blink::mojom::PreferredColorScheme preferred_color_scheme) {}

void FakeLocalFrameHost::BindFrameHostReceiver(
    mojo::ScopedInterfaceEndpointHandle handle) {
  receiver_.Bind(mojo::PendingAssociatedReceiver<mojom::blink::LocalFrameHost>(
      std::move(handle)));
}

void FakeLocalFrameHost::DidChangeSrcDoc(
    const blink::FrameToken& child_frame_token,
    const WTF::String& srcdoc_value) {}

void FakeLocalFrameHost::ReceivedDelegatedCapability(
    blink::mojom::DelegatedCapability delegated_capability) {}

void FakeLocalFrameHost::SendFencedFrameReportingBeacon(
    const WTF::String& event_data,
    const WTF::String& event_type,
    const WTF::Vector<blink::FencedFrame::ReportingDestination>& destinations,
    bool cross_origin_exposed) {}

void FakeLocalFrameHost::SendFencedFrameReportingBeaconToCustomURL(
    const blink::KURL& destination_url,
    bool cross_origin_exposed) {}

void FakeLocalFrameHost::SetFencedFrameAutomaticBeaconReportEventData(
    blink::mojom::AutomaticBeaconType event_type,
    const WTF::String& event_data,
    const WTF::Vector<blink::FencedFrame::ReportingDestination>& destinations,
    bool once,
    bool cross_origin_exposed) {}

void FakeLocalFrameHost::DisableUntrustedNetworkInFencedFrame(
    DisableUntrustedNetworkInFencedFrameCallback callback) {
  std::move(callback).Run();
}

void FakeLocalFrameHost::ExemptUrlFromNetworkRevocationForTesting(
    const blink::KURL& exempted_url,
    ExemptUrlFromNetworkRevocationForTestingCallback callback) {
  std::move(callback).Run();
}

void FakeLocalFrameHost::SendLegacyTechEvent(
    const WTF::String& type,
    mojom::blink::LegacyTechEventCodeLocationPtr code_location) {}

void FakeLocalFrameHost::SendPrivateAggregationRequestsForFencedFrameEvent(
    const WTF::String& event_type) {}

void FakeLocalFrameHost::CreateFencedFrame(
    mojo::PendingAssociatedReceiver<mojom::blink::FencedFrameOwnerHost>,
    mojom::blink::RemoteFrameInterfacesFromRendererPtr remote_frame_interfaces,
    const RemoteFrameToken& frame_token,
    const base::UnguessableToken& devtools_frame_token) {
  NOTREACHED() << "At the moment, FencedFrame is not used in any unit tests, "
                  "so this path should not be hit";
}

void FakeLocalFrameHost::ForwardFencedFrameEventAndUserActivationToEmbedder(
    const WTF::String& event_type) {
  NOTREACHED() << "ForwardFencedFrameEventToEmbedder is tested above the unit "
                  "test layer";
}

void FakeLocalFrameHost::StartDragging(
    const blink::WebDragData& drag_data,
    blink::DragOperationsMask operations_allowed,
    const SkBitmap& bitmap,
    const gfx::Vector2d& cursor_offset_in_dip,
    const gfx::Rect& drag_obj_rect_in_dip,
    mojom::blink::DragEventSourceInfoPtr event_info) {}

void FakeLocalFrameHost::IssueKeepAliveHandle(
    mojo::PendingReceiver<mojom::blink::NavigationStateKeepAliveHandle>
        receiver) {}

void FakeLocalFrameHost::NotifyStorageAccessed(
    blink::mojom::StorageTypeAccessed storageType,
    bool blocked) {}

void FakeLocalFrameHost::RecordWindowProxyUsageMetrics(
    const blink::FrameToken& target_frame_token,
    blink::mojom::WindowProxyAccessType access_type) {}

void FakeLocalFrameHost::NotifyDocumentInteractive() {}

}  // namespace blink
```