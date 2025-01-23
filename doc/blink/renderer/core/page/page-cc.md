Response:
My thinking process to answer the request about `blink/renderer/core/page/page.cc` went something like this:

1. **Understand the Core Request:** The user wants to know the *functionality* of the `page.cc` file in the Chromium Blink rendering engine. They also want specific examples relating to JavaScript, HTML, and CSS, logical reasoning with hypothetical inputs/outputs, common user errors, debugging information, and finally, a summary of its functionality (for Part 1).

2. **Initial Code Scan and Keyword Identification:** I first scanned the code for key classes, methods, and concepts. I looked for things like:
    * Includes of other important Blink files (`frame/local_frame.h`, `css/style_engine.h`, `dom/document.h`, etc.). This gives clues about dependencies and interactions.
    * Instantiated member variables. These are the core data the `Page` class manages.
    * Methods that perform actions (e.g., `CloseSoon`, `SetVisibilityState`, `UpdateColorProviders`).
    * Concepts like lifecycle management, rendering, event handling, and resource management.

3. **Categorize Functionality Based on Code Analysis:** Based on the keywords and the included headers, I started grouping the functionalities:
    * **Page Lifecycle:** Creation, destruction, closing (`CreateOrdinary`, `~Page`, `CloseSoon`).
    * **Frame Management:**  Handling the main frame and potentially subframes (`main_frame_`, `SetMainFrame`).
    * **Rendering and Layout:** Interaction with `LayoutView`, `ScrollingCoordinator`, `VisualViewport`, page scale factors.
    * **Styling and CSS:**  Interaction with `StyleEngine`, handling color schemes, forced colors, and platform colors (`UpdateColorProviders`, `ColorSchemeChanged`).
    * **JavaScript Interaction:** Management of `ScriptController` (indirectly, through included headers like `bindings/core/v8/script_controller.h`).
    * **Event Handling:**  Potentially through the inclusion of `dom/events/event.h` and interaction with `FocusController`, `ContextMenuController`, `DragController`.
    * **Navigation and History:**  Potentially related to `LocalFrame`, although less directly visible in this snippet.
    * **Settings and Preferences:** Management of `Settings` and `PreferenceManager`.
    * **Plugin Management:**  Handling plugin data (`PluginData`).
    * **Accessibility:** (Less obvious in this snippet, but could be related to focus management).
    * **Debugging and Inspection:**  Interaction with `ConsoleMessageStorage`, `InspectorIssueStorage`.

4. **Address Specific Request Points:**

    * **Relationship to JavaScript, HTML, and CSS:** I looked for concrete examples where the `Page` class interacts with these technologies. This involved inferring based on the member variables and methods. For example, `StyleEngine` is directly involved in applying CSS, and `ScriptController` manages JavaScript execution within the page. HTML is represented by the `Document` and `Frame` structures.

    * **Logical Reasoning (Hypothetical Input/Output):** I chose a relatively simple example like `SetVisibilityState`. I outlined a clear input (a specific visibility state) and its expected output (potential events and updates to the frame). The key was to pick something demonstrable even without the full codebase.

    * **Common User Errors:** I thought about common mistakes developers make when dealing with web pages, such as relying on synchronous closing or incorrect assumptions about visibility events.

    * **User Operations and Debugging:** I mapped common user actions (clicking a link, opening a new tab, minimizing a window) to how they might lead to execution within `page.cc`. For debugging, I focused on the core role of `page.cc` and suggested logging key lifecycle events.

    * **Summary of Functionality (Part 1):** I synthesized the information gathered into a concise summary, hitting the major areas of responsibility for the `Page` class. I focused on what could be definitively stated based on the provided code snippet.

5. **Structure and Refine:** I organized the information logically, using headings and bullet points for clarity. I tried to use precise language and avoid making unsubstantiated claims. I explicitly marked the "Part 1" summary.

6. **Self-Correction/Refinement During the Process:**

    * **Initial Overgeneralization:** I might have initially been too broad in some areas (e.g., assuming too much about navigation without seeing more code). I refined this by focusing on what was *explicitly* visible in the snippet.
    * **Prioritizing Key Functions:** I made sure to highlight the most important responsibilities of the `Page` class rather than getting bogged down in minor details.
    * **Clarity of Examples:** I ensured that the examples for JavaScript, HTML, and CSS were clear and directly related to the functionality of `page.cc`.

By following this process of code analysis, categorization, targeted response to the request points, and careful refinement, I could generate a comprehensive and accurate answer based on the provided source code snippet.
这是 Chromium Blink 引擎中 `blink/renderer/core/page/page.cc` 文件的第一部分，主要负责 **`Page` 类的实现**。`Page` 类是 Blink 渲染引擎中一个非常核心的类，它代表了一个浏览器标签页或者窗口的抽象。

以下是根据提供的代码分析，对 `page.cc` 中 `Page` 类功能的归纳：

**核心功能：**

1. **页面生命周期管理:**
   - **创建:** 提供 `CreateOrdinary` 和 `CreateNonOrdinary` 静态方法来创建 `Page` 对象。`CreateOrdinary` 用于创建普通的用户可见的页面，`CreateNonOrdinary` 可能用于内部或者特殊用途的页面。
   - **销毁:**  通过析构函数 `~Page()` 进行清理。代码中注释强调了 `WillBeDestroyed()` 必须在 `Page` 销毁前调用。
   - **关闭:**  提供 `CloseSoon()` 方法来异步或同步地关闭页面。对于弹窗，会立即关闭；对于 WebView，会post一个任务来异步关闭，避免在 JavaScript 执行过程中关闭导致问题。

2. **Frame 结构管理:**
   - **主 Frame 管理:**  维护一个指向主 `Frame` 的指针 `main_frame_`，并通过 `SetMainFrame()` 方法进行设置。
   - **关联页面管理:**  通过 `next_related_page_` 和 `prev_related_page_` 实现关联页面的链表结构，用于管理通过 `window.open()` 等方式打开的页面之间的关系。
   - **Frame 数量限制:**  通过 `kMaxNumberOfFrames` 和 `kTenFrames` 限制页面中的 Frame 数量，防止递归 Frameset 导致性能问题。

3. **渲染控制:**
   - **Viewport 管理:**  包含 `VisualViewport` 成员，负责管理页面的可视视口。
   - **缩放控制:**  通过 `PageScaleConstraintsSet` 管理页面的缩放约束，并提供设置默认和用户代理缩放限制的方法 (`SetDefaultPageScaleLimits`, `SetUserAgentPageScaleConstraints`)。
   - **滚动协调:**  通过 `ScrollingCoordinator` (如果启用硬件加速合成) 来管理页面的滚动。
   - **CSS 样式更新:** 响应强制颜色模式、平台颜色变化和配色方案变化 (`ForcedColorsChanged`, `PlatformColorsChanged`, `ColorSchemeChanged`)，并通知相关的 `Document` 和 `LayoutView` 进行更新。

4. **用户交互处理:**
   - **焦点控制:**  包含 `FocusController`，负责管理页面的焦点。
   - **拖拽控制:**  包含 `DragController` 和 `DragCaret`，负责处理页面的拖拽操作。
   - **上下文菜单控制:**  包含 `ContextMenuController`，负责显示和处理上下文菜单。
   - **指针锁定控制:**  包含 `PointerLockController`，负责处理指针锁定 API。
   - **自动滚动控制:**  包含 `AutoscrollController`，用于实现页面的自动滚动。

5. **浏览器集成:**
   - **ChromeClient 集成:**  通过 `ChromeClient` 接口与浏览器进程进行交互，例如请求关闭窗口、获取插件信息等。
   - **BrowserControls 管理:**  包含 `BrowserControls`，用于管理浏览器的控件（例如前进/后退按钮）。

6. **JavaScript 集成:**
   - **脚本控制:** 虽然代码中没有直接看到 `ScriptController` 的实例化，但包含了 `third_party/blink/renderer/bindings/core/v8/script_controller.h`，表明 `Page` 类与 JavaScript 的执行有密切关系。
   - **编译提示:**  包含 `V8CrowdsourcedCompileHintsProducer` 和 `V8CrowdsourcedCompileHintsConsumer`，用于优化 V8 的 JavaScript 编译。

7. **调试和检查:**
   - **控制台消息存储:**  包含 `ConsoleMessageStorage`，用于存储控制台输出的消息。
   - **检查器问题存储:** 包含 `InspectorIssueStorage`，用于存储检查器发现的问题。

8. **设置和偏好:**
   - **Settings 管理:**  包含 `Settings` 对象，用于管理页面的各种设置。
   - **偏好管理:**  虽然没有直接的 `PreferenceManager` 成员，但包含了相关的头文件，表明 `Page` 类与用户偏好设置有关。

9. **插件管理:**
   - **PluginData 管理:**  包含 `PluginData`，用于管理页面中的插件信息。

10. **其他功能:**
    - **全屏管理:**  包含 `Fullscreen`，用于处理全屏相关的操作。
    - **链接高亮:**  包含 `LinkHighlight`，用于在用户与链接交互时提供视觉反馈。
    - **表单验证:**  包含 `ValidationMessageClientImpl`，用于处理表单验证消息。
    - **虚拟时间控制:**  通过 `HistoryNavigationVirtualTimePauser` 支持历史导航的虚拟时间控制。
    - **页面可见性管理:**  通过 `SetVisibilityState` 管理页面的可见性状态，并通知观察者。
    - **颜色主题管理:**  通过 `UpdateColorProviders` 管理页面的颜色提供器，支持亮色、暗色和强制颜色模式。

**与 JavaScript, HTML, CSS 的关系举例说明:**

* **JavaScript:**
    * **事件处理:** `FocusController`, `ContextMenuController`, `DragController` 等组件会响应 JavaScript 触发的事件，例如 `focus`, `contextmenu`, `dragstart` 等。
    * **DOM 操作:**  虽然 `Page` 类本身不直接操作 DOM，但它是 `Frame` 的容器，而 `Frame` 负责管理 `Document`，`Document` 才是 DOM 的根节点。JavaScript 通过 `document` 对象访问和操作 DOM。
    * **页面生命周期事件:** `SetVisibilityState` 的改变会触发 `visibilitychange` 事件，JavaScript 可以监听这个事件来执行相应的操作。
    * **`window.open()`:**  `CreateOrdinary` 方法被调用可能源于 JavaScript 调用 `window.open()`，从而创建一个新的 `Page` 对象。

* **HTML:**
    * **Frame 结构:** `Page` 类管理着页面的 Frame 结构，这直接对应于 HTML 中的 `<frame>`, `<iframe>` 等标签。
    * **Viewport Meta 标签:**  `GetViewportDescription()` 方法可能会解析 HTML 中的 `<meta name="viewport">` 标签，从而影响页面的渲染。

* **CSS:**
    * **样式计算:**  `StyleEngine` 负责 CSS 样式的解析和计算，而 `Page` 类包含了 `StyleEngine`，并且会在颜色模式变化等事件发生时通知 `StyleEngine` 进行更新。
    * **媒体查询:**  `MediaFeatureOverrides` 和代码中对颜色模式的响应都与 CSS 媒体查询有关。例如，CSS 可以使用 `@media (prefers-color-scheme: dark)` 来针对暗色模式应用样式。
    * **安全区域:**  `SetSafeAreaEnvVariables` 函数设置 CSS 环境变量，允许开发者使用 CSS `env()` 函数访问设备的屏幕安全区域信息。

**逻辑推理的假设输入与输出：**

假设输入：用户在 JavaScript 中调用 `window.open('https://example.com')`。

输出：
1. Blink 引擎会创建一个新的 `Page` 对象 (通过 `CreateOrdinary`)。
2. 新的 `Page` 对象会被添加到关联页面链表中 (如果存在 opener)。
3. 新的 `Page` 对象会关联一个新的 `LocalFrame` 对象，用于加载 `https://example.com`。

**涉及用户或编程常见的使用错误：**

* **依赖同步关闭:**  在非弹窗情况下，开发者不应假设 `window.close()` 会立即生效。`CloseSoon()` 的实现表明，对于 WebView，关闭操作是异步的。
* **误解页面生命周期事件:**  开发者可能没有正确处理 `visibilitychange` 事件，导致在页面被隐藏或显示时出现错误的行为。
* **不正确的缩放设置:**  开发者可能会错误地设置页面的最小或最大缩放比例，导致用户体验不佳。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户在浏览器中输入网址并访问一个网页。** 这会触发创建主 `Frame` 和 `Page` 的过程。
2. **用户点击了一个带有 `target="_blank"` 的链接，或者 JavaScript 代码调用了 `window.open()`。** 这会导致创建一个新的 `Page` 对象。
3. **用户最小化或切换了浏览器标签页。** 这会触发 `SetVisibilityState` 方法的调用。
4. **用户更改了操作系统的主题颜色设置。** 这会触发 `ForcedColorsChanged` 或 `ColorSchemeChanged` 方法的调用。
5. **开发者在开发者工具的控制台中输出消息。** 这些消息会存储在 `ConsoleMessageStorage` 中。

**作为调试线索，可以关注以下几点：**

* **页面创建和销毁的时机:**  通过断点或日志记录，观察 `CreateOrdinary`, `CreateNonOrdinary` 和 `~Page` 的调用，可以了解页面的生命周期。
* **`SetMainFrame` 的调用:**  确定主 Frame 何时被设置，这对于理解页面加载流程至关重要。
* **可见性状态的改变:**  观察 `SetVisibilityState` 的调用和参数，可以调试与页面可见性相关的 Bug。
* **颜色模式变化的触发:**  观察 `ForcedColorsChanged`, `PlatformColorsChanged`, `ColorSchemeChanged` 的调用，可以调试与颜色主题相关的渲染问题。

**总结一下 `page.cc` 的功能 (针对提供的部分代码):**

`blink/renderer/core/page/page.cc` (第一部分) 主要实现了 `Page` 类的核心功能，该类是 Blink 渲染引擎中代表浏览器标签页或窗口的关键抽象。它负责管理页面的生命周期、Frame 结构、渲染属性（如视口、缩放）、用户交互处理、与浏览器进程的集成、以及与 JavaScript 和 CSS 的基本交互。此外，它还提供了调试和检查的基础设施，并管理着一些页面级别的设置和偏好。总而言之，`Page` 类是构建和管理网页内容的基础。

### 提示词
```
这是目录为blink/renderer/core/page/page.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2006, 2007, 2008, 2009, 2010, 2011, 2012, 2013 Apple Inc. All
 * Rights Reserved.
 * Copyright (C) 2008 Torch Mobile Inc. All rights reserved.
 * (http://www.torchmobile.com/)
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#include "third_party/blink/renderer/core/page/page.h"

#include "base/check.h"
#include "base/compiler_specific.h"
#include "base/feature_list.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/page/color_provider_color_maps.h"
#include "third_party/blink/public/mojom/frame/lifecycle.mojom-blink-forward.h"
#include "third_party/blink/public/mojom/partitioned_popins/partitioned_popin_params.mojom.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/web/blink.h"
#include "third_party/blink/renderer/bindings/core/v8/script_controller.h"
#include "third_party/blink/renderer/core/core_export.h"
#include "third_party/blink/renderer/core/css/media_feature_overrides.h"
#include "third_party/blink/renderer/core/css/style_change_reason.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/css/vision_deficiency.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/dom/node_rare_data.h"
#include "third_party/blink/renderer/core/dom/visited_link_state.h"
#include "third_party/blink/renderer/core/editing/drag_caret.h"
#include "third_party/blink/renderer/core/editing/markers/document_marker_controller.h"
#include "third_party/blink/renderer/core/frame/browser_controls.h"
#include "third_party/blink/renderer/core/frame/display_cutout_client_impl.h"
#include "third_party/blink/renderer/core/frame/event_handler_registry.h"
#include "third_party/blink/renderer/core/frame/frame_console.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/navigator.h"
#include "third_party/blink/renderer/core/frame/page_scale_constraints.h"
#include "third_party/blink/renderer/core/frame/page_scale_constraints_set.h"
#include "third_party/blink/renderer/core/frame/remote_frame.h"
#include "third_party/blink/renderer/core/frame/remote_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/viewport_data.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/fullscreen/fullscreen.h"
#include "third_party/blink/renderer/core/html/fenced_frame/document_fenced_frames.h"
#include "third_party/blink/renderer/core/html/media/html_media_element.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/inspector/console_message_storage.h"
#include "third_party/blink/renderer/core/inspector/inspector_issue_storage.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/layout/text_autosizer.h"
#include "third_party/blink/renderer/core/loader/idleness_detector.h"
#include "third_party/blink/renderer/core/page/autoscroll_controller.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/context_menu_controller.h"
#include "third_party/blink/renderer/core/page/drag_controller.h"
#include "third_party/blink/renderer/core/page/focus_controller.h"
#include "third_party/blink/renderer/core/page/link_highlight.h"
#include "third_party/blink/renderer/core/page/page_animator.h"
#include "third_party/blink/renderer/core/page/page_hidden_state.h"
#include "third_party/blink/renderer/core/page/plugin_data.h"
#include "third_party/blink/renderer/core/page/plugins_changed_observer.h"
#include "third_party/blink/renderer/core/page/pointer_lock_controller.h"
#include "third_party/blink/renderer/core/page/scoped_browsing_context_group_pauser.h"
#include "third_party/blink/renderer/core/page/scoped_page_pauser.h"
#include "third_party/blink/renderer/core/page/scrolling/scrolling_coordinator.h"
#include "third_party/blink/renderer/core/page/scrolling/top_document_root_scroller_controller.h"
#include "third_party/blink/renderer/core/page/spatial_navigation_controller.h"
#include "third_party/blink/renderer/core/page/validation_message_client_impl.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/preferences/navigator_preferences.h"
#include "third_party/blink/renderer/core/preferences/preference_manager.h"
#include "third_party/blink/renderer/core/preferences/preference_overrides.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/core/scroll/scrollbar_theme.h"
#include "third_party/blink/renderer/core/scroll/scrollbar_theme_overlay_mobile.h"
#include "third_party/blink/renderer/core/scroll/smooth_scroll_sequencer.h"
#include "third_party/blink/renderer/core/svg/graphics/svg_image_chrome_client.h"
#include "third_party/blink/renderer/core/svg/svg_resource_document_cache.h"
#include "third_party/blink/renderer/platform/bindings/source_location.h"
#include "third_party/blink/renderer/platform/graphics/paint/drawing_recorder.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/scheduler/public/agent_group_scheduler.h"
#include "third_party/blink/renderer/platform/scheduler/public/frame_scheduler.h"
#include "third_party/blink/renderer/platform/web_test_support.h"
#include "third_party/skia/include/core/SkColor.h"
#include "ui/color/color_provider.h"
#include "ui/color/color_provider_utils.h"

namespace blink {

namespace {
// This seems like a reasonable upper bound, and otherwise mutually
// recursive frameset pages can quickly bring the program to its knees
// with exponential growth in the number of frames.
const int kMaxNumberOfFrames = 1000;

// It is possible to use a reduced frame limit for testing, but only two values
// are permitted, the default or reduced limit.
const int kTenFrames = 10;

bool g_limit_max_frames_to_ten_for_testing = false;

// static
void SetSafeAreaEnvVariables(LocalFrame* frame, const gfx::Insets& safe_area) {
  DocumentStyleEnvironmentVariables& vars =
      frame->GetDocument()->GetStyleEngine().EnsureEnvironmentVariables();
  vars.SetVariable(UADefinedVariable::kSafeAreaInsetTop,
                   StyleEnvironmentVariables::FormatPx(safe_area.top()));
  vars.SetVariable(UADefinedVariable::kSafeAreaInsetLeft,
                   StyleEnvironmentVariables::FormatPx(safe_area.left()));
  vars.SetVariable(UADefinedVariable::kSafeAreaInsetBottom,
                   StyleEnvironmentVariables::FormatPx(safe_area.bottom()));
  vars.SetVariable(UADefinedVariable::kSafeAreaInsetRight,
                   StyleEnvironmentVariables::FormatPx(safe_area.right()));
}

}  // namespace

// Function defined in third_party/blink/public/web/blink.h.
void ResetPluginCache(bool reload_pages) {
  // At this point we already know that the browser has refreshed its list, so
  // it is not necessary to force it to be regenerated.
  DCHECK(!reload_pages);
  Page::ResetPluginData();
}

// Set of all live pages; includes internal Page objects that are
// not observable from scripts.
static Page::PageSet& AllPages() {
  DEFINE_STATIC_LOCAL(Persistent<Page::PageSet>, pages,
                      (MakeGarbageCollected<Page::PageSet>()));
  return *pages;
}

Page::PageSet& Page::OrdinaryPages() {
  DEFINE_STATIC_LOCAL(Persistent<Page::PageSet>, pages,
                      (MakeGarbageCollected<Page::PageSet>()));
  return *pages;
}

void Page::InsertOrdinaryPageForTesting(Page* page) {
  OrdinaryPages().insert(page);
}

HeapVector<Member<Page>> Page::RelatedPages() {
  HeapVector<Member<Page>> result;
  Page* ptr = next_related_page_;
  while (ptr != this) {
    result.push_back(ptr);
    ptr = ptr->next_related_page_;
  }
  return result;
}

Page* Page::CreateNonOrdinary(
    ChromeClient& chrome_client,
    AgentGroupScheduler& agent_group_scheduler,
    const ColorProviderColorMaps* color_provider_colors) {
  return MakeGarbageCollected<Page>(
      base::PassKey<Page>(), chrome_client, agent_group_scheduler,
      BrowsingContextGroupInfo::CreateUnique(), color_provider_colors,
      /*partitioned_popin_params=*/nullptr,
      /*is_ordinary=*/false);
}

Page* Page::CreateOrdinary(
    ChromeClient& chrome_client,
    Page* opener,
    AgentGroupScheduler& agent_group_scheduler,
    const BrowsingContextGroupInfo& browsing_context_group_info,
    const ColorProviderColorMaps* color_provider_colors,
    blink::mojom::PartitionedPopinParamsPtr partitioned_popin_params) {
  Page* page = MakeGarbageCollected<Page>(
      base::PassKey<Page>(), chrome_client, agent_group_scheduler,
      browsing_context_group_info, color_provider_colors,
      std::move(partitioned_popin_params), /*is_ordinary=*/true);
  page->opener_ = opener;

  OrdinaryPages().insert(page);

  bool should_pause = false;
  if (base::FeatureList::IsEnabled(
          features::kPausePagesPerBrowsingContextGroup)) {
    should_pause = ScopedBrowsingContextGroupPauser::IsActive(*page);
  } else {
    should_pause = ScopedPagePauser::IsActive();
  }
  if (should_pause) {
    page->SetPaused(true);
  }

  return page;
}

Page::Page(base::PassKey<Page>,
           ChromeClient& chrome_client,
           AgentGroupScheduler& agent_group_scheduler,
           const BrowsingContextGroupInfo& browsing_context_group_info,
           const ColorProviderColorMaps* color_provider_colors,
           blink::mojom::PartitionedPopinParamsPtr partitioned_popin_params,
           bool is_ordinary)
    : SettingsDelegate(std::make_unique<Settings>()),
      main_frame_(nullptr),
      agent_group_scheduler_(agent_group_scheduler),
      animator_(MakeGarbageCollected<PageAnimator>(*this)),
      autoscroll_controller_(MakeGarbageCollected<AutoscrollController>(*this)),
      chrome_client_(&chrome_client),
      drag_caret_(MakeGarbageCollected<DragCaret>()),
      drag_controller_(MakeGarbageCollected<DragController>(this)),
      focus_controller_(MakeGarbageCollected<FocusController>(this)),
      context_menu_controller_(
          MakeGarbageCollected<ContextMenuController>(this)),
      page_scale_constraints_set_(
          MakeGarbageCollected<PageScaleConstraintsSet>(this)),
      pointer_lock_controller_(
          MakeGarbageCollected<PointerLockController>(this)),
      browser_controls_(MakeGarbageCollected<BrowserControls>(*this)),
      console_message_storage_(MakeGarbageCollected<ConsoleMessageStorage>()),
      global_root_scroller_controller_(
          MakeGarbageCollected<TopDocumentRootScrollerController>(*this)),
      visual_viewport_(MakeGarbageCollected<VisualViewport>(*this)),
      link_highlight_(MakeGarbageCollected<LinkHighlight>(*this)),
      plugin_data_(nullptr),
      // TODO(pdr): Initialize |validation_message_client_| lazily.
      validation_message_client_(
          MakeGarbageCollected<ValidationMessageClientImpl>(*this)),
      opened_by_dom_(false),
      tab_key_cycles_through_elements_(true),
      inspector_device_scale_factor_override_(1),
      lifecycle_state_(mojom::blink::PageLifecycleState::New()),
      is_ordinary_(is_ordinary),
      is_cursor_visible_(true),
      subframe_count_(0),
      next_related_page_(this),
      prev_related_page_(this),
      autoplay_flags_(0),
      web_text_autosizer_page_info_({0, 0, 1.f}),
      v8_compile_hints_producer_(
          MakeGarbageCollected<
              v8_compile_hints::V8CrowdsourcedCompileHintsProducer>(this)),
      v8_compile_hints_consumer_(
          MakeGarbageCollected<
              v8_compile_hints::V8CrowdsourcedCompileHintsConsumer>()),
      browsing_context_group_info_(browsing_context_group_info) {
  if (partitioned_popin_params) {
    partitioned_popin_opener_properties_ = PartitionedPopinOpenerProperties(
        SecurityOrigin::CreateFromUrlOrigin(
            partitioned_popin_params->opener_top_frame_origin),
        partitioned_popin_params->opener_site_for_cookies);
  }
  DCHECK(!AllPages().Contains(this));
  AllPages().insert(this);

  page_scheduler_ = agent_group_scheduler_->CreatePageScheduler(this);
  // The scheduler should be set before the main frame.
  DCHECK(!main_frame_);
  if (auto* virtual_time_controller =
          page_scheduler_->GetVirtualTimeController()) {
    history_navigation_virtual_time_pauser_ =
        virtual_time_controller->CreateWebScopedVirtualTimePauser(
            "HistoryNavigation",
            WebScopedVirtualTimePauser::VirtualTaskDuration::kInstant);
  }
  UpdateColorProviders(color_provider_colors &&
                               !color_provider_colors->IsEmpty()
                           ? *color_provider_colors
                           : ColorProviderColorMaps::CreateDefault());
}

Page::~Page() {
  // WillBeDestroyed() must be called before Page destruction.
  DCHECK(!main_frame_);
}

// Closing a window/FrameTree happens asynchronously. It's important to keep
// track of the "current" Page because it might change, e.g. if a navigation
// committed in between the time the task gets posted but before the task runs.
// This class keeps track of the "current" Page and ensures that the window
// close happens on the correct Page.
class Page::CloseTaskHandler : public GarbageCollected<Page::CloseTaskHandler> {
 public:
  explicit CloseTaskHandler(WeakMember<Page> page) : page_(page) {}
  ~CloseTaskHandler() = default;

  void DoDeferredClose() {
    if (page_) {
      CHECK(page_->MainFrame());
      page_->GetChromeClient().CloseWindow();
    }
  }

  void SetPage(Page* page) { page_ = page; }

  void Trace(Visitor* visitor) const { visitor->Trace(page_); }

 private:
  WeakMember<Page> page_;
};

void Page::CloseSoon() {
  // Make sure this Page can no longer be found by JS.
  is_closing_ = true;

  // TODO(dcheng): Try to remove this in a followup, it's not obviously needed.
  if (auto* main_local_frame = DynamicTo<LocalFrame>(main_frame_.Get()))
    main_local_frame->Loader().StopAllLoaders(/*abort_client=*/true);

  // If the client is a popup, immediately close the window. This preserves the
  // previous behavior where we do the closing synchronously.
  if (GetChromeClient().IsPopup()) {
    GetChromeClient().CloseWindow();
    return;
  }
  // If the client is a WebView, post a task to close the window asynchronously.
  // This is because we could be called from deep in Javascript.  If we ask the
  // WebView to close now, the window could be closed before the JS finishes
  // executing, thanks to nested message loops running and handling the
  // resulting disconnecting PageBroadcast. So instead, post a message back to
  // the message loop, which won't run until the JS is complete, and then the
  // close request can be sent. Note that we won't post this task if the Page is
  // already marked as being destroyed: in that case, `MainFrame()` will be
  // null.
  if (!close_task_handler_ && MainFrame()) {
    close_task_handler_ = MakeGarbageCollected<Page::CloseTaskHandler>(this);
    GetPageScheduler()->GetAgentGroupScheduler().DefaultTaskRunner()->PostTask(
        FROM_HERE,
        WTF::BindOnce(&Page::CloseTaskHandler::DoDeferredClose,
                      WrapWeakPersistent(close_task_handler_.Get())));
  }
}

ViewportDescription Page::GetViewportDescription() const {
  return MainFrame() && MainFrame()->IsLocalFrame() &&
                 DeprecatedLocalMainFrame()->GetDocument()
             ? DeprecatedLocalMainFrame()
                   ->GetDocument()
                   ->GetViewportData()
                   .GetViewportDescription()
             : ViewportDescription();
}

ScrollingCoordinator* Page::GetScrollingCoordinator() {
  if (!scrolling_coordinator_ && settings_->GetAcceleratedCompositingEnabled())
    scrolling_coordinator_ = MakeGarbageCollected<ScrollingCoordinator>(this);

  return scrolling_coordinator_.Get();
}

PageScaleConstraintsSet& Page::GetPageScaleConstraintsSet() {
  return *page_scale_constraints_set_;
}

const PageScaleConstraintsSet& Page::GetPageScaleConstraintsSet() const {
  return *page_scale_constraints_set_;
}

BrowserControls& Page::GetBrowserControls() {
  return *browser_controls_;
}

const BrowserControls& Page::GetBrowserControls() const {
  return *browser_controls_;
}

ConsoleMessageStorage& Page::GetConsoleMessageStorage() {
  return *console_message_storage_;
}

const ConsoleMessageStorage& Page::GetConsoleMessageStorage() const {
  return *console_message_storage_;
}

InspectorIssueStorage& Page::GetInspectorIssueStorage() {
  return inspector_issue_storage_;
}

const InspectorIssueStorage& Page::GetInspectorIssueStorage() const {
  return inspector_issue_storage_;
}

TopDocumentRootScrollerController& Page::GlobalRootScrollerController() const {
  return *global_root_scroller_controller_;
}

VisualViewport& Page::GetVisualViewport() {
  return *visual_viewport_;
}

const VisualViewport& Page::GetVisualViewport() const {
  return *visual_viewport_;
}

LinkHighlight& Page::GetLinkHighlight() {
  return *link_highlight_;
}

void Page::SetMainFrame(Frame* main_frame) {
  // TODO(https://crbug.com/952836): Assert that this is only called during
  // initialization or swaps between local and remote frames.
  main_frame_ = main_frame;

  page_scheduler_->SetIsMainFrameLocal(main_frame->IsLocalFrame());

  // Now that the page has a main frame, connect it to related pages if needed.
  // However, if the main frame is a fake RemoteFrame used for a new Page to
  // host a provisional main LocalFrame, don't connect it just yet, as this Page
  // should not be interacted with until the provisional main LocalFrame gets
  // swapped in. After the LocalFrame gets swapped in, we will call this
  // function again and connect this Page to the related pages at that time.
  auto* remote_main_frame = DynamicTo<RemoteFrame>(main_frame);
  if (!remote_main_frame || remote_main_frame->IsRemoteFrameHostRemoteBound()) {
    LinkRelatedPagesIfNeeded();
  }
}

void Page::LinkRelatedPagesIfNeeded() {
  // Don't link if there's no opener, or if this page is already linked to other
  // pages, or if the opener is being detached (its related pages has been set
  // to null).
  if (!opener_ || prev_related_page_ != this || next_related_page_ != this ||
      !opener_->next_related_page_) {
    return;
  }
  // Before: ... -> opener -> next -> ...
  // After: ... -> opener -> page -> next -> ...
  Page* next = opener_->next_related_page_;
  opener_->next_related_page_ = this;
  prev_related_page_ = opener_;
  next_related_page_ = next;
  next->prev_related_page_ = this;
}

void Page::TakePropertiesForLocalMainFrameSwap(Page* old_page) {
  // Setting the CloseTaskHandler using this function should only be done
  // when transferring the CloseTaskHandler from a previous Page to the new
  // Page during LocalFrame <-> LocalFrame swap. The new Page should not have
  // a CloseTaskHandler yet at this point.
  CHECK(!close_task_handler_);
  close_task_handler_ = old_page->close_task_handler_;
  old_page->close_task_handler_ = nullptr;
  if (close_task_handler_) {
    close_task_handler_->SetPage(this);
  }
  CHECK_EQ(prev_related_page_, this);
  CHECK_EQ(next_related_page_, this);

  // Make the related pages list include `this` in place of `old_page`.
  if (old_page->prev_related_page_ != old_page) {
    prev_related_page_ = old_page->prev_related_page_;
    prev_related_page_->next_related_page_ = this;
    old_page->prev_related_page_ = old_page;
  }
  if (old_page->next_related_page_ != old_page) {
    next_related_page_ = old_page->next_related_page_;
    next_related_page_->prev_related_page_ = this;
    old_page->next_related_page_ = old_page;
  }

  // If the previous page is an opener for other pages, make sure that the
  // openees point to the new page instead.
  for (auto page : RelatedPages()) {
    if (page->opener_ == old_page) {
      page->opener_ = this;
    }
  }

  // Note that we don't update the `opener_` member here, since the
  // renderer-side opener is only set during construction and might be stale.
  // When we create the new page, we get the latest opener frame token, so the
  // new page's opener should be the most up-to-date opener.
}

bool Page::IsPartitionedPopin() const {
  // The feature must be enabled if a popin site for cookies was set.
  CHECK(RuntimeEnabledFeatures::PartitionedPopinsEnabled() ||
        !partitioned_popin_opener_properties_);

  return !!partitioned_popin_opener_properties_;
}

const PartitionedPopinOpenerProperties&
Page::GetPartitionedPopinOpenerProperties() const {
  // This function is only usable if we are in a popin.
  CHECK(IsPartitionedPopin());

  return *partitioned_popin_opener_properties_;
}

LocalFrame* Page::DeprecatedLocalMainFrame() const {
  return To<LocalFrame>(main_frame_.Get());
}

void Page::DocumentDetached(Document* document) {
  pointer_lock_controller_->DocumentDetached(document);
  context_menu_controller_->DocumentDetached(document);
  if (validation_message_client_)
    validation_message_client_->DocumentDetached(*document);

  GetChromeClient().DocumentDetached(*document);
}

bool Page::OpenedByDOM() const {
  return opened_by_dom_;
}

void Page::SetOpenedByDOM() {
  opened_by_dom_ = true;
}

SpatialNavigationController& Page::GetSpatialNavigationController() {
  if (!spatial_navigation_controller_) {
    spatial_navigation_controller_ =
        MakeGarbageCollected<SpatialNavigationController>(*this);
  }
  return *spatial_navigation_controller_;
}

SVGResourceDocumentCache& Page::GetSVGResourceDocumentCache() {
  if (!svg_resource_document_cache_) {
    svg_resource_document_cache_ =
        MakeGarbageCollected<SVGResourceDocumentCache>(
            GetPageScheduler()->GetAgentGroupScheduler().DefaultTaskRunner());
  }
  return *svg_resource_document_cache_;
}

void Page::UsesOverlayScrollbarsChanged() {
  for (Page* page : AllPages()) {
    for (Frame* frame = page->MainFrame(); frame;
         frame = frame->Tree().TraverseNext()) {
      if (auto* local_frame = DynamicTo<LocalFrame>(frame)) {
        if (LocalFrameView* view = local_frame->View()) {
          view->UsesOverlayScrollbarsChanged();
        }
      }
    }
  }
}

void Page::ForcedColorsChanged() {
  PlatformColorsChanged();
  ColorSchemeChanged();
}

void Page::PlatformColorsChanged() {
  for (const Page* page : AllPages()) {
    for (Frame* frame = page->MainFrame(); frame;
         frame = frame->Tree().TraverseNext()) {
      if (auto* local_frame = DynamicTo<LocalFrame>(frame)) {
        if (Document* document = local_frame->GetDocument()) {
          document->PlatformColorsChanged();
        }
        if (LayoutView* view = local_frame->ContentLayoutObject())
          view->InvalidatePaintForViewAndDescendants();
      }
    }
  }
}

void Page::ColorSchemeChanged() {
  for (const Page* page : AllPages())
    for (Frame* frame = page->MainFrame(); frame;
         frame = frame->Tree().TraverseNext()) {
      if (auto* local_frame = DynamicTo<LocalFrame>(frame)) {
        if (Document* document = local_frame->GetDocument()) {
          document->ColorSchemeChanged();
        }
      }
    }
}

void Page::EmulateForcedColors(bool is_dark_theme) {
  emulated_forced_colors_provider_ =
      WebTestSupport::IsRunningWebTest()
          ? ui::CreateEmulatedForcedColorsColorProviderForTest()
          : ui::CreateEmulatedForcedColorsColorProvider(is_dark_theme);
}

void Page::DisableEmulatedForcedColors() {
  emulated_forced_colors_provider_.reset();
}

bool Page::UpdateColorProviders(
    const ColorProviderColorMaps& color_provider_colors) {
  // Color maps should not be empty as they are needed to create the color
  // providers.
  CHECK(!color_provider_colors.IsEmpty());

  bool did_color_provider_update = false;
  if (!ui::IsRendererColorMappingEquivalent(
          light_color_provider_.get(),
          color_provider_colors.light_colors_map)) {
    light_color_provider_ = ui::CreateColorProviderFromRendererColorMap(
        color_provider_colors.light_colors_map);
    did_color_provider_update = true;
  }
  if (!ui::IsRendererColorMappingEquivalent(
          dark_color_provider_.get(), color_provider_colors.dark_colors_map)) {
    dark_color_provider_ = ui::CreateColorProviderFromRendererColorMap(
        color_provider_colors.dark_colors_map);
    did_color_provider_update = true;
  }
  if (!ui::IsRendererColorMappingEquivalent(
          forced_colors_color_provider_.get(),
          color_provider_colors.forced_colors_map)) {
    forced_colors_color_provider_ =
        WebTestSupport::IsRunningWebTest()
            ? ui::CreateEmulatedForcedColorsColorProviderForTest()
            : ui::CreateColorProviderFromRendererColorMap(
                  color_provider_colors.forced_colors_map);
    did_color_provider_update = true;
  }

  if (did_color_provider_update) {
    SetColorProviderColorMaps(color_provider_colors);
  }

  return did_color_provider_update;
}

void Page::UpdateColorProvidersForTest() {
  light_color_provider_ =
      ui::CreateDefaultColorProviderForBlink(/*dark_mode=*/false);
  dark_color_provider_ =
      ui::CreateDefaultColorProviderForBlink(/*dark_mode=*/true);
  forced_colors_color_provider_ =
      ui::CreateEmulatedForcedColorsColorProviderForTest();
}

const ui::ColorProvider* Page::GetColorProviderForPainting(
    mojom::blink::ColorScheme color_scheme,
    bool in_forced_colors) const {
  // All providers should be initialized and non-null before this function is
  // called.
  CHECK(light_color_provider_);
  CHECK(dark_color_provider_);
  CHECK(forced_colors_color_provider_);
  if (in_forced_colors) {
    if (emulated_forced_colors_provider_) {
      return emulated_forced_colors_provider_.get();
    }
    return forced_colors_color_provider_.get();
  }

  return color_scheme == mojom::blink::ColorScheme::kDark
             ? dark_color_provider_.get()
             : light_color_provider_.get();
}

void Page::InitialStyleChanged() {
  for (Frame* frame = MainFrame(); frame;
       frame = frame->Tree().TraverseNext()) {
    auto* local_frame = DynamicTo<LocalFrame>(frame);
    if (!local_frame)
      continue;
    local_frame->GetDocument()->GetStyleEngine().InitialStyleChanged();
  }
}

PluginData* Page::GetPluginData() {
  if (!plugin_data_)
    plugin_data_ = MakeGarbageCollected<PluginData>();

  plugin_data_->UpdatePluginList();
  return plugin_data_.Get();
}

void Page::ResetPluginData() {
  for (Page* page : AllPages()) {
    if (page->plugin_data_) {
      page->plugin_data_->ResetPluginData();
      page->NotifyPluginsChanged();
    }
  }
}

static void RestoreSVGImageAnimations() {
  for (const Page* page : AllPages()) {
    if (auto* svg_image_chrome_client =
            DynamicTo<IsolatedSVGChromeClient>(page->GetChromeClient())) {
      svg_image_chrome_client->RestoreAnimationIfNeeded();
    }
  }
}

void Page::SetValidationMessageClientForTesting(
    ValidationMessageClient* client) {
  validation_message_client_ = client;
}

void Page::SetPaused(bool paused) {
  if (paused == paused_)
    return;

  paused_ = paused;
  for (Frame* frame = MainFrame(); frame;
       frame = frame->Tree().TraverseNext()) {
    if (auto* local_frame = DynamicTo<LocalFrame>(frame)) {
      local_frame->OnPageLifecycleStateUpdated();
    }
  }
}

void Page::SetShowPausedHudOverlay(bool show_overlay) {
  show_paused_hud_overlay_ = show_overlay;
}

void Page::SetDefaultPageScaleLimits(float min_scale, float max_scale) {
  PageScaleConstraints new_defaults =
      GetPageScaleConstraintsSet().DefaultConstraints();
  new_defaults.minimum_scale = min_scale;
  new_defaults.maximum_scale = max_scale;

  if (new_defaults == GetPageScaleConstraintsSet().DefaultConstraints())
    return;

  GetPageScaleConstraintsSet().SetDefaultConstraints(new_defaults);
  GetPageScaleConstraintsSet().ComputeFinalConstraints();
  GetPageScaleConstraintsSet().SetNeedsReset(true);

  if (!MainFrame() || !MainFrame()->IsLocalFrame())
    return;

  LocalFrameView* root_view = DeprecatedLocalMainFrame()->View();

  if (!root_view)
    return;

  root_view->SetNeedsLayout();
}

void Page::SetUserAgentPageScaleConstraints(
    const PageScaleConstraints& new_constraints) {
  if (new_constraints == GetPageScaleConstraintsSet().UserAgentConstraints())
    return;

  GetPageScaleConstraintsSet().SetUserAgentConstraints(new_constraints);

  if (!MainFrame() || !MainFrame()->IsLocalFrame())
    return;

  LocalFrameView* root_view = DeprecatedLocalMainFrame()->View();

  if (!root_view)
    return;

  root_view->SetNeedsLayout();
}

void Page::SetPageScaleFactor(float scale) {
  GetVisualViewport().SetScale(scale);
}

float Page::PageScaleFactor() const {
  return GetVisualViewport().Scale();
}

void Page::AllVisitedStateChanged(bool invalidate_visited_link_hashes) {
  for (const Page* page : OrdinaryPages()) {
    for (Frame* frame = page->main_frame_; frame;
         frame = frame->Tree().TraverseNext()) {
      if (auto* main_local_frame = DynamicTo<LocalFrame>(frame))
        main_local_frame->GetDocument()
            ->GetVisitedLinkState()
            .InvalidateStyleForAllLinks(invalidate_visited_link_hashes);
    }
  }
}

void Page::VisitedStateChanged(LinkHash link_hash) {
  for (const Page* page : OrdinaryPages()) {
    for (Frame* frame = page->main_frame_; frame;
         frame = frame->Tree().TraverseNext()) {
      if (auto* main_local_frame = DynamicTo<LocalFrame>(frame))
        main_local_frame->GetDocument()
            ->GetVisitedLinkState()
            .InvalidateStyleForLink(link_hash);
    }
  }
}

void Page::SetVisibilityState(
    mojom::blink::PageVisibilityState visibility_state,
    bool is_initial_state) {
  if (lifecycle_state_->visibility == visibility_state)
    return;

  // Are we entering / leaving a state that would map to the "visible" state, in
  // the `document.visibilityState` sense?
  const bool was_visible = lifecycle_state_->visibility ==
                           mojom::blink::PageVisibilityState::kVisible;
  const bool is_visible =
      visibility_state == mojom::blink::PageVisibilityState::kVisible;

  lifecycle_state_->visibility = visibility_state;

  if (is_initial_state)
    return;

  for (auto observer : page_visibility_observer_set_) {
    observer->PageVisibilityChanged();
  }

  if (main_frame_) {
    if (lifecycle_state_->visibility ==
        mojom::blink::PageVisibilityState::kVisible) {
      RestoreSVGImageAnimations();
    }
    // If we're eliding visibility transitions between the two `kHidden*`
    // states, then we never get here unless one state was `kVisible` and the
    // other was not.  However, if we aren't eliding those transitions, then we
    // need to do so now; from the Frame's point of view, nothing is changing if
    // this is a change between the two `kHidden*` states.  Both map to "hidden"
    // in the sense of `document.visibilityState`, and dispatching an event when
    // the web-exposed state hasn't changed is confusing.
    //
    // This check could be enabled for both cases, and the result in the
    // "eliding" case shouldn't change.  It's not, just to be safe, since this
    // is intended as a fall-back to previous behavior.
    if (!RuntimeEnabledFeatures::DispatchHiddenVisibilityTransitionsEnabled() ||
        was_visible || is_visible) {
      main_frame_->DidChangeVisibilityState();
    }
  }
}

mojom::blink::PageVisibilityState Page::GetVisibilityState() const {
  return life
```