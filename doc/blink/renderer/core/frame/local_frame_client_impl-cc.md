Response:
The user wants me to analyze the provided C++ source code file `local_frame_client_impl.cc` from the Chromium Blink rendering engine.

Here's a breakdown of the requested analysis:

1. **Functionality Listing:** I need to identify the primary responsibilities of this file. Based on the file name, it likely implements the client-side interface for a local frame within the rendering engine. This involves handling events and communication related to the lifecycle and behavior of a frame.

2. **Relationship to Web Technologies:** I should look for connections to JavaScript, HTML, and CSS. Since this is part of the rendering engine, it will undoubtedly interact with these technologies. Examples could include handling script execution, managing the DOM structure represented by HTML, and applying CSS styles.

3. **Logic Inference (Hypothetical Input/Output):** I need to identify sections of code that perform logical operations and provide examples of inputs and their expected outputs. This might involve analyzing conditional statements or function calls that transform data.

4. **Common Usage Errors:** I should consider scenarios where developers might misuse the functionalities provided by this code or where the code itself might be prone to errors.

5. **Summary of Functionality (Part 1):** Finally, I need to summarize the functionality covered in the provided code snippet. Since the user indicated this is part 1, I should focus on the aspects evident in this specific portion of the file.

**Plan:**

* **Scan for Key Class/Method Names:** Look for prominent class and method names to understand the core purpose of the file. `LocalFrameClientImpl` is the central class.
* **Analyze Included Headers:**  Examine the included header files (`#include`) to get hints about the types of functionalities this file interacts with (e.g., networking, scripting, events).
* **Focus on Method Implementations:**  Go through the implementations of the methods within `LocalFrameClientImpl` to understand their specific roles.
* **Identify Interactions with Web Concepts:** Look for mentions of or operations related to HTML elements, JavaScript contexts, CSS styling, and browser events.
* **Look for Conditional Logic:**  Find `if` statements and other control flow structures that indicate logical decision-making.
* **Consider Potential Errors:** Think about scenarios where function arguments might be invalid or where external systems might behave unexpectedly.
* **Synthesize a Summary:**  Combine the findings into a concise summary of the file's purpose based on the first part of the code.
这是 `blink/renderer/core/frame/local_frame_client_impl.cc` 文件的第一部分，它主要负责实现 `LocalFrameClient` 接口。`LocalFrameClient` 是 Blink 渲染引擎中用于连接 `LocalFrame`（表示一个本地的 HTML 框架）和外部环境（例如，浏览器进程）的桥梁。`LocalFrameClientImpl` 提供了 `LocalFrame` 与外部环境通信的具体实现。

**功能列举 (基于第一部分代码):**

1. **生命周期管理:**
   - **创建和销毁:**  实现了 `LocalFrameClientImpl` 的构造函数和析构函数。
   - **分离 (Detachment):**  提供了 `WillBeDetached()` 和 `Detached()` 方法，处理框架从父框架或页面分离时的逻辑，包括通知客户端 (浏览器进程) 以及清理资源。
   - **设置 WebLocalFrame:**  通过构造函数接收 `WebLocalFrameImpl` 的指针，并提供 `GetWebFrame()` 方法获取该指针。

2. **与 JavaScript 的交互:**
   - **清理 Window 对象:**  `DispatchDidClearWindowObjectInMainWorld()`  在主世界 JavaScript 上下文被清理后执行，通知客户端并执行一些初始化操作。
   - **文档元素可用时运行脚本:**  `DocumentElementAvailable()` 和 `RunScriptsAtDocumentElementAvailable()` 在文档的根元素可用时通知客户端并运行脚本。
   - **文档就绪时运行脚本:** `RunScriptsAtDocumentReady()` 在文档完成解析且可以被脚本操作时通知客户端并运行脚本。 特别提到了对于 MHTML 档案页面的处理，会在文档就绪时通过脚本重新创建 Shadow DOM。
   - **文档空闲时运行脚本:** `RunScriptsAtDocumentIdle()` 在文档加载和解析完成后，并且主线程空闲时通知客户端并运行脚本。
   - **脚本上下文的创建和释放:**  `DidCreateScriptContext()` 和 `WillReleaseScriptContext()` 在 JavaScript 上下文创建和释放时通知客户端。
   - **允许脚本扩展:** `AllowScriptExtensions()`  表明是否允许脚本扩展。

3. **页面状态和事件通知:**
   - **滚动偏移改变:** `DidChangeScrollOffset()` 在框架的滚动偏移发生变化时通知客户端。
   - **当前历史记录项改变:** `NotifyCurrentHistoryItemChanged()` 在当前浏览历史记录项发生变化时通知客户端。
   - **更新当前历史记录项:** `DidUpdateCurrentHistoryItem()` 在当前浏览历史记录项更新后通知客户端。

4. **导航控制和处理:**
   - **允许内容发起的 data URL 导航:** `AllowContentInitiatedDataUrlNavigations()` 决定是否允许页面内容发起的到 `data:` URL 的导航。
   - **最终确定请求:** `DispatchFinalizeRequest()`  在发送网络请求前，允许客户端修改请求。
   - **即将发送请求:** `DispatchWillSendRequest()` 在即将发送网络请求时通知客户端，并允许客户端进行修改或取消。
   - **DOMContentLoaded 事件分发:** `DispatchDidDispatchDOMContentLoadedEvent()` 在 `DOMContentLoaded` 事件分发后通知客户端。
   - **从内存缓存加载资源:** `DispatchDidLoadResourceFromMemoryCache()` 在资源从内存缓存加载时通知客户端。
   - **处理 onload 事件:** `DispatchDidHandleOnloadEvents()` 在处理完 `onload` 事件后通知客户端。
   - **完成同文档导航:** `DidFinishSameDocumentNavigation()` 在完成同文档导航时通知客户端，并处理与历史记录和截图相关的逻辑。
   - **异步同文档提交失败:** `DidFailAsyncSameDocumentCommit()` 在异步同文档提交失败时通知客户端。
   - **打开文档输入流:** `DispatchDidOpenDocumentInputStream()` 在打开文档输入流时通知客户端。
   - **接收到标题:** `DispatchDidReceiveTitle()` 在接收到文档标题时通知客户端。
   - **提交加载:** `DispatchDidCommitLoad()` 在提交加载时通知客户端，并进行一些与加载相关的设置，例如重置触摸和鼠标滚轮事件处理器的属性。  特别提到了对于主框架的特殊处理，包括更新 compositor 的状态和 UKM 指标。
   - **加载失败:** `DispatchDidFailLoad()` 在加载失败时通知客户端。
   - **加载完成:** `DispatchDidFinishLoad()` 在加载完成时通知客户端。
   - **开始导航:** `BeginNavigation()` 在开始导航时，构建 `WebNavigationInfo` 对象，包含导航的各种信息，并通知客户端。

5. **插件处理:**  虽然在第一部分代码中没有直接涉及插件相关的函数调用，但是头文件中包含了 `<third_party/blink/public/web/web_plugin.h>` 和 `<third_party/blink/public/web/web_plugin_params.h>`，暗示了 `LocalFrameClientImpl` 负责处理与插件相关的事件。

**与 JavaScript, HTML, CSS 的关系举例:**

* **JavaScript:**
    * `DispatchDidClearWindowObjectInMainWorld()` 在 JavaScript 的 `window` 对象被清理后调用，用于执行一些与 JavaScript 环境相关的初始化操作，例如设置全局对象。
    * `RunScriptsAtDocumentReady()` 的实现中，对于 MHTML 页面，直接使用了 JavaScript 代码来操作 DOM，重新创建 Shadow DOM 结构。
    * `DidCreateScriptContext()` 和 `WillReleaseScriptContext()` 直接关联 JavaScript 上下文的生命周期。

* **HTML:**
    * `DocumentElementAvailable()` 在 HTML 文档的根元素 (`<html>`) 可用时被触发。
    *  `BeginNavigation()` 中处理的导航请求通常加载的是 HTML 文档。

* **CSS:**
    * 尽管第一部分代码没有直接体现与 CSS 的交互，但加载 HTML 文档最终会涉及到 CSS 的解析和应用。`LocalFrameClientImpl` 参与了加载过程的管理，间接地影响了 CSS 的加载和渲染。

**逻辑推理举例:**

**假设输入:** 用户在浏览器地址栏输入一个新的 URL 并按下回车键。

**输出:**

1. `BeginNavigation()` 会被调用，`request` 参数会包含新 URL 的请求信息，`type` 参数会是 `kWebUserGesture` 或类似的表示用户发起的导航。
2. `DispatchWillSendRequest()` 可能会被调用，允许客户端（浏览器进程）检查并修改请求。
3. 如果请求成功，`DispatchDidCommitLoad()` 会被调用，通知客户端加载已提交。
4. `RunScriptsAtDocumentReady()` 会在文档解析完成后调用，执行页面中的 JavaScript 代码。

**假设输入:** 页面通过 JavaScript 调用 `window.location.href = 'another_page.html'`.

**输出:**

1. `BeginNavigation()` 会被调用，`request` 参数会包含 `another_page.html` 的请求信息，`type` 参数会是 `kWebScript` 或类似的表示脚本发起的导航。
2. 后续的调用流程类似用户在地址栏输入 URL 的情况。

**用户或编程常见的使用错误举例:**

* **在 `Detached()` 或 `WillBeDetached()` 之后尝试访问 `web_frame_`:**  `Detached()` 方法会清理 `web_frame_` 的指针。如果在这些方法调用之后，仍然尝试访问 `web_frame_`，会导致空指针解引用。这是一个常见的生命周期管理错误。

* **在 `DispatchWillSendRequest()` 中进行耗时操作:**  `DispatchWillSendRequest()` 在网络请求发送前同步调用。如果在其中执行了耗时的操作，会阻塞渲染进程的网络线程，影响页面加载性能。

**功能归纳 (Part 1):**

`blink/renderer/core/frame/local_frame_client_impl.cc` 的第一部分主要负责实现 `LocalFrameClient` 接口的关键功能，该接口是 `LocalFrame` 与外部环境（通常是浏览器进程）进行通信的桥梁。其功能涵盖了框架的生命周期管理（创建、销毁、分离），与 JavaScript 引擎的集成（清理 Window 对象、运行脚本、管理脚本上下文），页面状态和事件的通知（滚动、历史记录），以及导航过程的控制和处理（开始导航、请求处理、加载提交和完成等）。  它为 Blink 渲染引擎中的本地框架提供了一个与浏览器环境交互的核心机制。

### 提示词
```
这是目录为blink/renderer/core/frame/local_frame_client_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2009, 2012 Google Inc. All rights reserved.
 * Copyright (C) 2011 Apple Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
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

#include "third_party/blink/renderer/core/frame/local_frame_client_impl.h"

#include <utility>

#include "base/metrics/histogram_functions.h"
#include "base/time/time.h"
#include "base/types/optional_util.h"
#include "components/viz/common/frame_timing_details.h"
#include "mojo/public/cpp/bindings/pending_receiver.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "mojo/public/cpp/bindings/type_converter.h"
#include "net/storage_access_api/status.h"
#include "third_party/blink/public/common/blob/blob_utils.h"
#include "third_party/blink/public/common/permissions_policy/permissions_policy.h"
#include "third_party/blink/public/common/scheduler/task_attribution_id.h"
#include "third_party/blink/public/common/tokens/tokens.h"
#include "third_party/blink/public/common/user_agent/user_agent_metadata.h"
#include "third_party/blink/public/mojom/frame/user_activation_update_types.mojom-blink-forward.h"
#include "third_party/blink/public/mojom/loader/fetch_later.mojom-blink.h"
#include "third_party/blink/public/platform/modules/service_worker/web_service_worker_provider.h"
#include "third_party/blink/public/platform/modules/service_worker/web_service_worker_provider_client.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/web_background_resource_fetch_assets.h"
#include "third_party/blink/public/platform/web_media_player_source.h"
#include "third_party/blink/public/platform/web_security_origin.h"
#include "third_party/blink/public/platform/web_url.h"
#include "third_party/blink/public/platform/web_url_error.h"
#include "third_party/blink/public/platform/web_vector.h"
#include "third_party/blink/public/web/web_autofill_client.h"
#include "third_party/blink/public/web/web_document.h"
#include "third_party/blink/public/web/web_dom_event.h"
#include "third_party/blink/public/web/web_form_element.h"
#include "third_party/blink/public/web/web_local_frame_client.h"
#include "third_party/blink/public/web/web_manifest_manager.h"
#include "third_party/blink/public/web/web_navigation_params.h"
#include "third_party/blink/public/web/web_node.h"
#include "third_party/blink/public/web/web_plugin.h"
#include "third_party/blink/public/web/web_plugin_params.h"
#include "third_party/blink/public/web/web_view_client.h"
#include "third_party/blink/renderer/bindings/core/v8/capture_source_location.h"
#include "third_party/blink/renderer/core/core_initializer.h"
#include "third_party/blink/renderer/core/events/current_input_event.h"
#include "third_party/blink/renderer/core/events/message_event.h"
#include "third_party/blink/renderer/core/events/mouse_event.h"
#include "third_party/blink/renderer/core/exported/web_dev_tools_agent_impl.h"
#include "third_party/blink/renderer/core/exported/web_plugin_container_impl.h"
#include "third_party/blink/renderer/core/exported/web_view_impl.h"
#include "third_party/blink/renderer/core/fileapi/public_url_manager.h"
#include "third_party/blink/renderer/core/frame/frame.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/web_frame_widget_impl.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/fullscreen/fullscreen.h"
#include "third_party/blink/renderer/core/html/html_frame_element_base.h"
#include "third_party/blink/renderer/core/html/html_plugin_element.h"
#include "third_party/blink/renderer/core/html/media/html_media_element.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/inspector/dev_tools_emulator.h"
#include "third_party/blink/renderer/core/layout/hit_test_result.h"
#include "third_party/blink/renderer/core/layout/layout_shift_tracker.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/loader/frame_load_request.h"
#include "third_party/blink/renderer/core/loader/frame_loader.h"
#include "third_party/blink/renderer/core/loader/history_item.h"
#include "third_party/blink/renderer/core/origin_trials/origin_trial_context.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/plugin_data.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/core/script/classic_script.h"
#include "third_party/blink/renderer/platform/exported/wrapped_resource_request.h"
#include "third_party/blink/renderer/platform/exported/wrapped_resource_response.h"
#include "third_party/blink/renderer/platform/instrumentation/histogram.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"
#include "third_party/blink/renderer/platform/network/http_parsers.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "v8/include/v8.h"

namespace blink {

namespace {

// Convenience helper for frame tree helpers in FrameClient to reduce the amount
// of null-checking boilerplate code. Since the frame tree is maintained in the
// web/ layer, the frame tree helpers often have to deal with null WebFrames:
// for example, a frame with no parent will return null for WebFrame::parent().
// TODO(dcheng): Remove duplication between LocalFrameClientImpl and
// RemoteFrameClientImpl somehow...
Frame* ToCoreFrame(WebFrame* frame) {
  return frame ? WebFrame::ToCoreFrame(*frame) : nullptr;
}

// Return the parent of |frame| as a LocalFrame, nullptr when there is no
// parent or when the parent is a remote frame.
LocalFrame* GetLocalParentFrame(WebLocalFrameImpl* frame) {
  WebFrame* parent = frame->Parent();
  auto* parent_web_local_frame = DynamicTo<WebLocalFrameImpl>(parent);
  if (!parent_web_local_frame)
    return nullptr;

  return parent_web_local_frame->GetFrame();
}

// Returns whether the |local_frame| has been loaded using an MHTMLArchive. When
// it is the case, each subframe must use it for loading.
bool IsLoadedAsMHTMLArchive(LocalFrame* local_frame) {
  return local_frame && local_frame->GetDocument()->Fetcher()->Archive();
}

// Returns whether the |local_frame| is in a middle of a back/forward
// navigation.
bool IsBackForwardNavigationInProgress(LocalFrame* local_frame) {
  return local_frame &&
         IsBackForwardOrRestore(
             local_frame->Loader().GetDocumentLoader()->LoadType()) &&
         !local_frame->GetDocument()->LoadEventFinished();
}

// Called after committing provisional load to reset the EventHandlerProperties.
// Only called on local frame roots.
void ResetWheelAndTouchEventHandlerProperties(LocalFrame& frame) {
  // If we are loading a local root, it is important to explicitly set the event
  // listener properties to Nothing as this triggers notifications to the
  // client. Clients may assume the presence of handlers for touch and wheel
  // events, so these notifications tell it there are (presently) no handlers.
  auto& chrome_client = frame.GetPage()->GetChromeClient();
  chrome_client.SetEventListenerProperties(
      &frame, cc::EventListenerClass::kTouchStartOrMove,
      cc::EventListenerProperties::kNone);
  chrome_client.SetEventListenerProperties(&frame,
                                           cc::EventListenerClass::kMouseWheel,
                                           cc::EventListenerProperties::kNone);
  chrome_client.SetEventListenerProperties(
      &frame, cc::EventListenerClass::kTouchEndOrCancel,
      cc::EventListenerProperties::kNone);
}

bool IsCompositedOutermostMainFrame(WebLocalFrameImpl* web_frame) {
  return web_frame->GetFrame()->IsMainFrame() &&
         !web_frame->IsInFencedFrameTree() &&
         web_frame->ViewImpl()->does_composite();
}

}  // namespace

LocalFrameClientImpl::LocalFrameClientImpl(WebLocalFrameImpl* frame)
    : web_frame_(frame) {}

LocalFrameClientImpl::~LocalFrameClientImpl() = default;

void LocalFrameClientImpl::Trace(Visitor* visitor) const {
  visitor->Trace(web_frame_);
  LocalFrameClient::Trace(visitor);
}

WebLocalFrameImpl* LocalFrameClientImpl::GetWebFrame() const {
  return web_frame_.Get();
}

WebContentCaptureClient* LocalFrameClientImpl::GetWebContentCaptureClient()
    const {
  return web_frame_->ContentCaptureClient();
}

void LocalFrameClientImpl::DidCommitDocumentReplacementNavigation(
    DocumentLoader* loader) {
  if (web_frame_->Client()) {
    web_frame_->Client()->DidCommitDocumentReplacementNavigation(loader);
  }
}

void LocalFrameClientImpl::DispatchDidClearWindowObjectInMainWorld(
    v8::Isolate* isolate,
    v8::MicrotaskQueue* microtask_queue) {
  if (web_frame_->Client()) {
    // Do not run microtasks while invoking the callback.
    {
      v8::MicrotasksScope microtasks(isolate, microtask_queue,
                                     v8::MicrotasksScope::kDoNotRunMicrotasks);
      web_frame_->Client()->DidClearWindowObject();
    }
    Document* document = web_frame_->GetFrame()->GetDocument();
    if (document) {
      const Settings* const settings = web_frame_->GetFrame()->GetSettings();
      CoreInitializer::GetInstance().OnClearWindowObjectInMainWorld(*document,
                                                                    *settings);
    }
  }
}

void LocalFrameClientImpl::DocumentElementAvailable() {
  if (web_frame_->Client())
    web_frame_->Client()->DidCreateDocumentElement();
}

void LocalFrameClientImpl::RunScriptsAtDocumentElementAvailable() {
  if (web_frame_->Client())
    web_frame_->Client()->RunScriptsAtDocumentElementAvailable();
  // The callback might have deleted the frame, do not use |this|!
}

void LocalFrameClientImpl::RunScriptsAtDocumentReady(bool document_is_empty) {
  if (!document_is_empty && IsLoadedAsMHTMLArchive(web_frame_->GetFrame())) {
    // For MHTML pages, recreate the shadow DOM contents from the templates that
    // are captured from the shadow DOM trees at serialization.
    // Note that the MHTML page is loaded in sandboxing mode with script
    // execution disabled and thus only the following script will be executed.
    // Any other scripts and event handlers outside the scope of the following
    // script, including those that may be inserted in shadow DOM templates,
    // will NOT be run.
    String script = R"(
function createShadowRootWithin(node) {
  var nodes = node.querySelectorAll('template[shadowmode]');
  for (var i = 0; i < nodes.length; ++i) {
    var template = nodes[i];
    var mode = template.getAttribute('shadowmode');
    var parent = template.parentNode;
    if (!parent)
      continue;
    parent.removeChild(template);
    var shadowRoot;
    if (mode == 'open' || mode == 'closed') {
      var delegatesFocus = template.hasAttribute('shadowdelegatesfocus');
      shadowRoot = parent.attachShadow({'mode': mode,
                                        'delegatesFocus': delegatesFocus});
    }
    if (!shadowRoot)
      continue;
    var clone = document.importNode(template.content, true);
    shadowRoot.appendChild(clone);
    createShadowRootWithin(shadowRoot);
  }
}
createShadowRootWithin(document.body);
)";
    ClassicScript::CreateUnspecifiedScript(script,
                                           ScriptSourceLocationType::kInternal)
        ->RunScript(web_frame_->GetFrame()->DomWindow(),
                    ExecuteScriptPolicy::kExecuteScriptWhenScriptsDisabled);
  }

  if (web_frame_->Client()) {
    web_frame_->Client()->RunScriptsAtDocumentReady();
  }
  // The callback might have deleted the frame, do not use |this|!
}

void LocalFrameClientImpl::RunScriptsAtDocumentIdle() {
  if (web_frame_->Client())
    web_frame_->Client()->RunScriptsAtDocumentIdle();
  // The callback might have deleted the frame, do not use |this|!
}

void LocalFrameClientImpl::DidCreateScriptContext(
    v8::Local<v8::Context> context,
    int32_t world_id) {
  if (web_frame_->Client())
    web_frame_->Client()->DidCreateScriptContext(context, world_id);
}

void LocalFrameClientImpl::WillReleaseScriptContext(
    v8::Local<v8::Context> context,
    int32_t world_id) {
  if (web_frame_->Client()) {
    web_frame_->Client()->WillReleaseScriptContext(context, world_id);
  }
}

bool LocalFrameClientImpl::AllowScriptExtensions() {
  return true;
}

void LocalFrameClientImpl::DidChangeScrollOffset() {
  if (web_frame_->Client())
    web_frame_->Client()->DidChangeScrollOffset();
}

void LocalFrameClientImpl::NotifyCurrentHistoryItemChanged() {
  if (web_frame_->Client())
    web_frame_->Client()->NotifyCurrentHistoryItemChanged();
}

void LocalFrameClientImpl::DidUpdateCurrentHistoryItem() {
  web_frame_->Client()->DidUpdateCurrentHistoryItem();
}

bool LocalFrameClientImpl::AllowContentInitiatedDataUrlNavigations(
    const KURL& url) {
  if (RuntimeEnabledFeatures::AllowContentInitiatedDataUrlNavigationsEnabled())
    return true;
  if (web_frame_->Client())
    return web_frame_->Client()->AllowContentInitiatedDataUrlNavigations(url);
  return false;
}

bool LocalFrameClientImpl::HasWebView() const {
  return web_frame_->ViewImpl();
}

bool LocalFrameClientImpl::InShadowTree() const {
  return web_frame_->GetTreeScopeType() == mojom::blink::TreeScopeType::kShadow;
}

void LocalFrameClientImpl::WillBeDetached() {
  web_frame_->WillBeDetached();
}

void LocalFrameClientImpl::Detached(FrameDetachType type) {
  // Alert the client that the frame is being detached. This is the last
  // chance we have to communicate with the client.
  WebLocalFrameClient* client = web_frame_->Client();
  if (!client)
    return;

  web_frame_->WillDetachParent();

  // Signal that no further communication with WebLocalFrameClient should take
  // place at this point since we are no longer associated with the Page.
  web_frame_->SetClient(nullptr);

  DetachReason detach_reason = (type == FrameDetachType::kSwap)
                                   ? DetachReason::kNavigation
                                   : DetachReason::kFrameDeletion;
  client->WillDetach(detach_reason);

  // We only notify the browser process when the frame is being detached for
  // removal, not after a swap.
  if (type == FrameDetachType::kRemove)
    web_frame_->GetFrame()->GetLocalFrameHostRemote().Detach();

  client->FrameDetached(detach_reason);

  if (type == FrameDetachType::kRemove)
    ToCoreFrame(web_frame_)->DetachFromParent();

  // Clear our reference to LocalFrame at the very end, in case the client
  // refers to it.
  web_frame_->SetCoreFrame(nullptr);
}

void LocalFrameClientImpl::DispatchFinalizeRequest(ResourceRequest& request) {
  // Give the WebLocalFrameClient a crack at the request.
  if (web_frame_->Client()) {
    WrappedResourceRequest webreq(request);
    web_frame_->Client()->FinalizeRequest(webreq);
  }
}

std::optional<KURL> LocalFrameClientImpl::DispatchWillSendRequest(
    const KURL& requested_url,
    const scoped_refptr<const SecurityOrigin>& requestor_origin,
    const net::SiteForCookies& site_for_cookies,
    bool has_redirect_info,
    const KURL& upstream_url) {
  if (!web_frame_->Client()) {
    return std::nullopt;
  }
  return web_frame_->Client()->WillSendRequest(
      requested_url, requestor_origin, site_for_cookies,
      WebLocalFrameClient::ForRedirect(has_redirect_info), upstream_url);
}

void LocalFrameClientImpl::DispatchDidDispatchDOMContentLoadedEvent() {
  if (web_frame_->Client())
    web_frame_->Client()->DidDispatchDOMContentLoadedEvent();

  web_frame_->DidDispatchDOMContentLoadedEvent();
}

void LocalFrameClientImpl::DispatchDidLoadResourceFromMemoryCache(
    const ResourceRequest& request,
    const ResourceResponse& response) {
  if (web_frame_->Client()) {
    web_frame_->Client()->DidLoadResourceFromMemoryCache(
        WrappedResourceRequest(request), WrappedResourceResponse(response));
  }
}

void LocalFrameClientImpl::DispatchDidHandleOnloadEvents() {
  if (web_frame_->Client())
    web_frame_->Client()->DidHandleOnloadEvents();
}

void LocalFrameClientImpl::DidFinishSameDocumentNavigation(
    WebHistoryCommitType commit_type,
    bool is_synchronously_committed,
    mojom::blink::SameDocumentNavigationType same_document_navigation_type,
    bool is_client_redirect,
    bool is_browser_initiated) {
  bool should_create_history_entry = commit_type == kWebStandardCommit;
  // TODO(dglazkov): Does this need to be called for subframes?
  web_frame_->ViewImpl()->DidCommitLoad(should_create_history_entry, true);
  if (web_frame_->Client()) {
    // This unique token is used to associate the session history entry, and its
    // viewport screenshot before the navigation finishes in the renderer.
    base::UnguessableToken screenshot_destination;

    // Exclude `kWebHistoryInertCommit` because these types of navigations does
    // not originate from nor add entries to the session history (i.e., they are
    // not history-traversable).
    // Exclude the WebView not being composited because we won't present any
    // frame if it is not being actively drawn.
    // Exclude cases with prefers-reduced-motion. Back forward transitions are
    // disabled in this case so no screenshots are necessary.
    // We however always propagate the history sequence number for correctness
    // in CompositedOuterMainFrame cases.
    bool navigation_with_screenshot = false;
    if (IsCompositedOutermostMainFrame(web_frame_)) {
      WebFrameWidgetImpl* frame_widget = web_frame_->FrameWidgetImpl();
      // The outermost mainframe must have a frame widget.
      CHECK(frame_widget);
      frame_widget->PropagateHistorySequenceNumberToCompositor();

      if (commit_type != kWebHistoryInertCommit &&
          !web_frame_->GetFrame()->GetSettings()->GetPrefersReducedMotion()) {
        navigation_with_screenshot = true;
        if (RuntimeEnabledFeatures::
                IncrementLocalSurfaceIdForMainframeSameDocNavigationEnabled()) {
          frame_widget->RequestNewLocalSurfaceId();
          if (RuntimeEnabledFeatures::BackForwardTransitionsEnabled()) {
            screenshot_destination = base::UnguessableToken::Create();
            frame_widget->RequestViewportScreenshot(screenshot_destination);
          }
        }

        frame_widget->NotifyPresentationTime(WTF::BindOnce(
            [](base::TimeTicks start,
               const viz::FrameTimingDetails& frame_timing_details) {
              base::TimeDelta duration =
                  frame_timing_details.presentation_feedback.timestamp - start;
              base::UmaHistogramTimes(
                  "Navigation."
                  "MainframeSameDocumentNavigationCommitToPresentFirstFrame",
                  duration);
            },
            base::TimeTicks::Now()));
      }
    }
    base::UmaHistogramBoolean("Navigation.SameDocumentNavigationWithScreenshot",
                              navigation_with_screenshot);

    std::optional<blink::SameDocNavigationScreenshotDestinationToken> token =
        std::nullopt;
    if (!screenshot_destination.is_empty()) {
      token = blink::SameDocNavigationScreenshotDestinationToken(
          screenshot_destination);
    }
    web_frame_->Client()->DidFinishSameDocumentNavigation(
        commit_type, is_synchronously_committed, same_document_navigation_type,
        is_client_redirect, token);
  }

  // Set the layout shift exclusion window for the browser initiated same
  // document navigation.
  if (is_browser_initiated) {
    LocalFrame* frame = web_frame_->GetFrame();
    if (frame) {
      frame->View()
          ->GetLayoutShiftTracker()
          .NotifyBrowserInitiatedSameDocumentNavigation();
    }
  }
}
void LocalFrameClientImpl::DidFailAsyncSameDocumentCommit() {
  web_frame_->Client()->DidFailAsyncSameDocumentCommit();
}

void LocalFrameClientImpl::DispatchDidOpenDocumentInputStream(const KURL& url) {
  web_frame_->Client()->DidOpenDocumentInputStream(url);
}

void LocalFrameClientImpl::DispatchDidReceiveTitle(const String& title) {
  if (web_frame_->Client()) {
    web_frame_->Client()->DidReceiveTitle(title);
  }
}

void LocalFrameClientImpl::DispatchDidCommitLoad(
    HistoryItem* item,
    WebHistoryCommitType commit_type,
    bool should_reset_browser_interface_broker,
    const blink::ParsedPermissionsPolicy& permissions_policy_header,
    const blink::DocumentPolicyFeatureState& document_policy_header) {
  if (!web_frame_->Parent()) {
    web_frame_->ViewImpl()->DidCommitLoad(commit_type == kWebStandardCommit,
                                          false);
  }

  if (web_frame_->Client()) {
    web_frame_->Client()->DidCommitNavigation(
        commit_type, should_reset_browser_interface_broker,
        permissions_policy_header, document_policy_header);

    // With local to local swap it's possible for the frame to be deleted as a
    // side effect of JS event handlers called in DidCommitNavigation
    // (e.g. unload).
    if (!web_frame_->Client())
      return;
    if (web_frame_->GetFrame()->IsLocalRoot()) {
      // This update should be sent as soon as loading the new document begins
      // so that the browser and compositor could reset their states. However,
      // up to this point |web_frame_| is still provisional and the updates will
      // not get sent. Revise this when https://crbug.com/578349 is fixed.
      ResetWheelAndTouchEventHandlerProperties(*web_frame_->GetFrame());

      web_frame_->FrameWidgetImpl()->DidNavigate();

      // The navigation state pushed to the compositor is limited to outermost
      // main frames. This is particularly important for UKM metrics, since we
      // only record URL keyed data if the URL is being displayed in the main
      // frame.
      if (IsCompositedOutermostMainFrame(web_frame_)) {
        WebFrameWidgetImpl* frame_widget = web_frame_->FrameWidgetImpl();

        // Update the navigation states (URL, the document source id used to key
        // UKM metrics in the compositor. Note that the metrics for all frames
        // are keyed to the main frame's URL.
        frame_widget->UpdateNavigationStateForCompositor(
            web_frame_->GetDocument().GetUkmSourceId(),
            KURL(web_frame_->Client()->LastCommittedUrlForUKM()));

        auto shmem = frame_widget->CreateSharedMemoryForSmoothnessUkm();
        if (shmem.IsValid()) {
          web_frame_->Client()->SetUpSharedMemoryForSmoothness(
              std::move(shmem));
        }
      }
    }
  }
  if (WebDevToolsAgentImpl* dev_tools =
          DevToolsAgent(/*create_if_necessary=*/false)) {
    dev_tools->DidCommitLoadForLocalFrame(web_frame_->GetFrame());
  }

  web_frame_->DidCommitLoad();
}

void LocalFrameClientImpl::DispatchDidFailLoad(
    const ResourceError& error,
    WebHistoryCommitType commit_type) {
  web_frame_->DidFailLoad(error, commit_type);
}

void LocalFrameClientImpl::DispatchDidFinishLoad() {
  web_frame_->DidFinish();
}

void LocalFrameClientImpl::DispatchDidFinishLoadForPrinting() {
  web_frame_->DidFinishLoadForPrinting();
}

void LocalFrameClientImpl::BeginNavigation(
    const ResourceRequest& request,
    const KURL& requestor_base_url,
    mojom::RequestContextFrameType frame_type,
    LocalDOMWindow* origin_window,
    DocumentLoader* document_loader,
    WebNavigationType type,
    NavigationPolicy policy,
    WebFrameLoadType frame_load_type,
    mojom::blink::ForceHistoryPush force_history_push,
    bool is_client_redirect,
    bool is_unfenced_top_navigation,
    mojom::blink::TriggeringEventInfo triggering_event_info,
    HTMLFormElement* form,
    network::mojom::CSPDisposition
        should_check_main_world_content_security_policy,
    mojo::PendingRemote<mojom::blink::BlobURLToken> blob_url_token,
    base::TimeTicks input_start_time,
    const String& href_translate,
    const std::optional<Impression>& impression,
    const LocalFrameToken* initiator_frame_token,
    std::unique_ptr<SourceLocation> source_location,
    mojo::PendingRemote<mojom::blink::NavigationStateKeepAliveHandle>
        initiator_navigation_state_keep_alive_handle,
    bool is_container_initiated,
    bool has_rel_opener) {
  if (!web_frame_->Client())
    return;

  // |initiator_frame_token| and |initiator_navigation_state_keep_alive_handle|
  // should either be both specified or both null.
  DCHECK(!initiator_frame_token ==
         !initiator_navigation_state_keep_alive_handle);

  auto navigation_info = std::make_unique<WebNavigationInfo>();
  navigation_info->url_request.CopyFrom(WrappedResourceRequest(request));
  navigation_info->requestor_base_url = requestor_base_url;
  navigation_info->frame_type = frame_type;
  navigation_info->force_history_push = force_history_push;
  navigation_info->navigation_type = type;
  navigation_info->navigation_policy = static_cast<WebNavigationPolicy>(policy);
  navigation_info->has_transient_user_activation = request.HasUserGesture();
  navigation_info->is_unfenced_top_navigation = is_unfenced_top_navigation;
  navigation_info->frame_load_type = frame_load_type;
  navigation_info->is_client_redirect = is_client_redirect;
  navigation_info->triggering_event_info = triggering_event_info;
  navigation_info->should_check_main_world_content_security_policy =
      should_check_main_world_content_security_policy;
  navigation_info->blob_url_token = std::move(blob_url_token);
  navigation_info->input_start = input_start_time;
  navigation_info->initiator_frame_token =
      base::OptionalFromPtr(initiator_frame_token);
  navigation_info->initiator_navigation_state_keep_alive_handle =
      std::move(initiator_navigation_state_keep_alive_handle);
  LocalFrame* origin_frame =
      origin_window ? origin_window->GetFrame() : nullptr;
  if (origin_frame) {
    // Many navigation paths do not pass an |initiator_frame_token|, so we need
    // to compute it here.
    if (!navigation_info->initiator_frame_token) {
      navigation_info->initiator_frame_token =
          origin_frame->GetLocalFrameToken();
    }
    // Similarly, many navigation paths do not pass an
    // |initiator_navigation_state_keep_alive_handle|.
    if (!navigation_info->initiator_navigation_state_keep_alive_handle) {
      navigation_info->initiator_navigation_state_keep_alive_handle =
          origin_frame->IssueKeepAliveHandle();
    }
  } else {
    // TODO(https://crbug.com/1173409 and https://crbug.com/1059959): Check that
    // we always pass an |initiator_frame_token| and an
    // |initiator_navigation_state_keep_alive_handle| if |origin_window| is not
    // set.
  }

  navigation_info->impression = impression;

  // Allow cookie access via Storage Access API during the navigation, if the
  // initiator has obtained storage access. Note that the network service still
  // applies cookie semantics and user settings, and that this value is not
  // trusted by the browser process. (The Storage Access API is only relevant
  // when third-party cookies are blocked.)
  navigation_info->storage_access_api_status =
      origin_window ? origin_window->GetStorageAccessApiStatus()
                    : net::StorageAccessApiStatus::kNone;

  // Can be null.
  LocalFrame* local_parent_frame = GetLocalParentFrame(web_frame_);

  // Newly created child frames may need to be navigated to a history item
  // during a back/forward navigation. This will only happen when the parent
  // is a LocalFrame doing a back/forward navigation that has not completed.
  // (If the load has completed and the parent later adds a frame with script,
  // we do not want to use a history item for it.)
  navigation_info->is_history_navigation_in_new_child_frame =
      IsBackForwardNavigationInProgress(local_parent_frame);

  // TODO(nasko): How should this work with OOPIF?
  // The MHTMLArchive is parsed as a whole, but can be constructed from frames
  // in multiple processes. In that case, which process should parse it and how
  // should the output be spread back across multiple processes?
  navigation_info->archive_status =
      IsLoadedAsMHTMLArchive(local_parent_frame)
          ? WebNavigationInfo::ArchiveStatus::Present
          : WebNavigationInfo::ArchiveStatus::Absent;

  if (form)
    navigation_info->form = WebFormElement(form);

  if (origin_frame) {
    navigation_info->is_opener_navigation =
        origin_frame->Opener() == ToCoreFrame(web_frame_);
    navigation_info->initiator_frame_has_download_sandbox_flag =
        origin_window->IsSandboxed(
            network::mojom::blink::WebSandboxFlags::kDownloads);
    navigation_info->initiator_frame_is_ad = origin_frame->IsAdFrame();
    navigation_info->is_ad_script_in_stack = origin_frame->IsAdScriptInStack();
  }

  navigation_info->has_rel_opener = has_rel_opener;

  // The frame has navigated either by itself or by the action of the
  // |origin_window| when it is defined. |source_location| represents the
  // line of code that has initiated the navigation. It is used to let web
  // developers locate the root cause of blocked navigations.
  // If `origin_window` is defined, then `source_location` must be, too, since
  // it should have been captured when creating the `FrameLoadRequest`.
  // Otherwise, try to capture the `source_location` from the current frame.
  if (!source_location) {
    DCHECK(!origin_window);
    source_location =
        CaptureSourceLocation(web_frame_->GetFrame()->DomWindow());
  }
  if (!source_location->IsUnknown()) {
    navigation_info->source_location.url = source_location->Url();
    navigation_info->source_location.line_number =
        source_location->LineNumber();
    navigation_info->source_location.column_number =
        source_location->ColumnNumber();
  }

  std::unique_ptr<Vector<mojom::blink::OriginTrialFeature>>
      initiator_origin_trial_features =
          OriginTrialContext::GetEnabledNavigationFeatures(
              web_frame_->GetFrame()->DomWindow());
  if (initiator_origin_trial_features) {
    navigation_info->initiator_origin_trial_features.reserve(
        initiator_origin_trial_features->size());
    for (auto feature : *initiator_origin_trial_features) {
      // Convert from OriginTrialFeature to int. We convert to int here since
      // OriginTrialFeature is not visible (and is not needed) outside of
      // blink. These values are only passed outside of blink so they can be
      // forwarded to the next blink navigation, but aren't used outside of
      // blink other than to forward the values between navigations.
      navigation_info->initiator_origin_trial_features.emplace_back(
          static_cast<int>(feature));
    }
  }

  if (WebDevToolsAgentImpl* devtools =
          DevToolsAgent(/*create_if_necessary=*/false)) {
    navigation_info->devtools_initiator_info =
        devtools->NavigationInitiatorInfo(web_frame_->GetFrame());
  }

  auto* owner = ToCoreFrame(web_frame_)->Owner();
  navigation_info->frame_policy =
```