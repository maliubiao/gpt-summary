Response:
Let's break down the thought process for analyzing the `find_in_page.cc` file.

1. **Understand the Goal:** The request asks for the functionality of the file, its relationship to web technologies, its logic, and potential user errors. This requires a systematic approach to dissecting the code.

2. **Initial Scan for Keywords and Structure:**  A quick scan reveals key terms like "FindInPage," "Find," "TextFinder," "plugin," "match," "selection," "JavaScript," "HTML," and "CSS" (though the latter are less directly evident in the *code* itself and more in the *context* of its function). The structure reveals a class `FindInPage` with several methods.

3. **Deconstruct the `FindInPage` Class:**  The core functionality revolves around this class. The constructor takes a `WebLocalFrameImpl` and an `InterfaceRegistry`. The presence of `InterfaceRegistry` hints at its role in inter-process communication (IPC) within Chromium.

4. **Analyze Key Methods:**  Focus on the methods that seem central to find-in-page functionality:

    * **`Find(request_id, search_text, options)`:** This is the entry point for initiating a find operation. Notice the handling of plugins and the `TextFinder`. The `options` parameter suggests various search configurations. The `ReportFindInPageMatchCount` call indicates a mechanism for reporting results.

    * **`FindInternal(identifier, search_text, options, wrap_within_frame, active_now)`:** This appears to be the core search logic, delegated to the `TextFinder`. The `wrap_within_frame` argument suggests a frame-specific search scope.

    * **`StopFinding(action)`:**  Handles stopping the find operation, potentially clearing the selection or activating the selected match. The interaction with `WebPlugin` and `TextFinder` is important.

    * **Methods related to reporting results (`ReportFindInPageMatchCount`, `ReportFindInPageSelection`):** These methods clearly handle sending information about found matches back to the client (likely the browser UI). The scaling logic in `ReportFindInPageSelection` is noteworthy.

    * **Methods interacting with `TextFinder` (`EnsureTextFinder`, `GetTextFinder`):**  Recognize `TextFinder` as a crucial dependency responsible for the actual text searching.

    * **Plugin-related methods (`GetWebPluginForFind`, `SetPluginFindHandler`):**  Understand that find-in-page needs to work within plugins as well.

    * **Tickmark-related methods (`SetTickmarks`):** These methods relate to visually marking find results.

5. **Identify Relationships with Web Technologies:**

    * **JavaScript:**  The `FindInPage` functionality is triggered by JavaScript (e.g., `window.find()`). The results are likely communicated back to JavaScript to update the UI.

    * **HTML:**  The search operates on the content of the HTML document. The highlighting of matches directly manipulates the DOM.

    * **CSS:**  While not explicitly manipulated in this code, CSS is used to style the highlighted search results (e.g., background color, outline).

6. **Infer Logic and Assumptions:**

    * **New Session vs. Existing Session:** The `options->new_session` flag is a key differentiator in how the search is handled.

    * **Focus:** The code considers whether the frame is focused. This affects whether a match is immediately activated.

    * **Scoping:**  The concept of "scoping" is present, indicating that the search might be performed in stages or to optimize for performance.

    * **Asynchronous Operations:** The mention of `async` in `FindForTesting` and the use of callbacks suggest that some parts of the find operation might be asynchronous.

7. **Consider User and Programming Errors:**

    * **User Errors:**  Typos in the search term, not realizing the search is case-sensitive, expecting to find content within a plugin differently.

    * **Programming Errors:**  Incorrectly handling the `request_id`, not checking for null pointers, issues with coordinate transformations, forgetting to handle the `final_update` flag correctly.

8. **Structure the Answer:** Organize the findings into the requested categories: Functionality, Relationship to Web Technologies, Logic and Assumptions, and Errors. Provide concrete examples where possible.

9. **Refine and Elaborate:**  Review the generated points. Add more details and explanations. For instance,  explain *why* plugins are handled separately or *how* the `TextFinder` likely works. Ensure the language is clear and concise.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe the file directly manipulates the DOM for highlighting.
* **Correction:**  Realize that the `TextFinder` likely handles the DOM manipulation, and this file focuses on orchestrating the find process and communicating results.

* **Initial thought:** The file is solely responsible for finding within the current frame.
* **Correction:** The mention of plugins shows it handles cross-frame or embedded content scenarios.

* **Initial thought:** The communication with the UI is direct.
* **Correction:**  The use of `mojom::blink::FindInPageClient` and the `InterfaceRegistry` points to a more structured IPC mechanism.

By following this systematic process, combining code analysis with an understanding of web browser architecture, and iteratively refining the analysis, a comprehensive and accurate answer can be generated.
好的，让我们来分析一下 `blink/renderer/core/frame/find_in_page.cc` 这个文件的功能。

**主要功能:**

这个文件实现了 Chromium Blink 渲染引擎中 **“在页面中查找” (Find in Page)** 的核心功能。它负责处理用户发起的查找请求，在当前页面中搜索指定的文本，并高亮显示匹配的结果。

**具体功能点:**

1. **接收查找请求:**  `FindInPage::Find` 方法是接收查找请求的入口。它接收请求 ID、要查找的文本 (`search_text`) 和查找选项 (`options`)。
2. **处理插件内容:** 如果当前页面包含插件 (如 Flash)，`GetWebPluginForFind` 会尝试获取插件实例。如果找到了插件，查找操作会委托给插件处理 (`plugin->StartFind` 或 `plugin->SelectFindResult`)。
3. **处理普通页面内容:** 如果没有插件或者需要进行新的查找，代码会使用 `TextFinder` 类来执行文本查找。
4. **管理查找会话:** 通过 `options->new_session` 来判断是否是新的查找会话。新的会话会初始化 `TextFinder`。
5. **查找匹配项:** `FindInternal` 方法调用 `TextFinder::Find` 来在页面内容中查找匹配的文本。它可以指定是否在当前帧内循环查找 (`wrap_within_frame`)。
6. **报告查找结果:**
    * `ReportFindInPageMatchCount` 方法向客户端 (通常是浏览器 UI) 报告匹配到的数量。
    * `ReportFindInPageSelection` 方法报告当前激活的匹配项的位置和范围。
7. **停止查找:** `StopFinding` 方法负责停止查找操作，可以选择保留或清除当前的选择，或者激活当前选中的匹配项。
8. **高亮显示匹配项:** 虽然这个文件本身不直接负责渲染高亮，但它通过 `TextFinder` 来管理匹配项的信息，这些信息会被渲染模块用来高亮显示。
9. **处理异步查找:**  涉及到 `StartScopingStringMatches` 等方法，表明查找过程可能包含异步操作，以便在大型页面中提高性能。
10. **与客户端通信:**  通过 `mojo::PendingRemote<mojom::blink::FindInPageClient>` 与浏览器进程通信，传递查找结果和状态。
11. **处理Android平台特定的查找功能:** 包含一些 `#if BUILDFLAG(IS_ANDROID)` 的代码，用于处理 Android 平台上的特定查找需求，例如获取激活匹配项的矩形区域、激活最近的匹配项等。
12. **设置/获取查找标记:**  `SetTickmarks` 方法允许设置用于在滚动条上显示查找匹配位置的标记。
13. **测试接口:** 提供了 `WebLocalFrameImpl::FindForTesting` 方法，方便进行单元测试。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **JavaScript:**
    * **触发查找:**  用户在浏览器地址栏输入 `javascript:find('your text')` 或者通过网页上的 JavaScript 代码调用 `window.find('your text')`，会最终触发 `FindInPage::Find` 方法。
    * **获取查找结果:**  JavaScript 可以监听浏览器的查找事件，或者通过 Chromium 提供的 API (例如 DevTools Protocol) 获取查找结果，这些结果是由 `FindInPage` 计算并报告的。
    * **示例:**
        ```javascript
        // 在 JavaScript 中发起查找
        window.find("example");

        // 监听查找结果 (这是一个简化的概念，实际实现会更复杂)
        window.addEventListener('find', function(event) {
          console.log('找到 ' + event.count + ' 个匹配项');
        });
        ```

* **HTML:**
    * **查找目标:** `FindInPage` 的查找目标是 HTML 文档的内容。它会遍历 HTML DOM 树来查找匹配的文本。
    * **结构影响:** HTML 的结构会影响查找的效率和结果。例如，隐藏的元素（通过 `display: none`）通常不会被查找。
    * **示例:** 如果 HTML 中包含以下内容，搜索 "hello" 将会找到匹配项：
        ```html
        <!DOCTYPE html>
        <html>
        <head>
          <title>Example Page</title>
        </head>
        <body>
          <p>Hello, world!</p>
        </body>
        </html>
        ```

* **CSS:**
    * **样式影响:** CSS 的样式规则会影响文本的呈现方式，但一般不会直接影响 `FindInPage` 的查找逻辑。但是，`visibility: hidden` 和 `display: none` 等属性可能会导致内容不被查找。
    * **高亮显示:**  当找到匹配项后，浏览器通常会使用 CSS 来高亮显示这些匹配的文本。Blink 渲染引擎会添加特定的 CSS 类或样式到匹配的元素上，从而实现高亮效果。
    * **示例:**  浏览器可能会动态添加类似以下的 CSS 规则来高亮显示匹配项：
        ```css
        ::selection {
          background-color: yellow;
          color: black;
        }
        ```
        或者使用特定的类名：
        ```css
        .find-in-page-match {
          background-color: yellow;
          color: black;
        }
        ```

**逻辑推理、假设输入与输出:**

**假设输入:**

* `request_id`: 123
* `search_text`: "example"
* `options`:
    * `new_session`: true
    * `match_case`: false
    * `forward`: true

**逻辑推理:**

1. `Find` 方法被调用，传入上述参数。
2. 检查当前帧是否包含插件。假设没有插件。
3. 由于 `new_session` 为 `true`，`EnsureTextFinder().InitNewSession(*options)` 会被调用，初始化一个新的查找会话。
4. `FindInternal` 方法会被调用，将查找任务委托给 `TextFinder::Find`。
5. `TextFinder::Find` 在当前页面的 DOM 树中搜索 "example" (忽略大小写)。
6. 假设找到 3 个匹配项。
7. `ReportFindInPageMatchCount(123, 1, false)` 可能会被调用，表示找到了至少一个匹配项，但可能还有更多。
8. `EnsureTextFinder().StartScopingStringMatches(123, "example", *options)` 启动匹配项的范围界定，用于更精确地计算总数和高亮。
9. 当范围界定完成后，`ReportFindInPageMatchCount(123, 3, true)` 会被调用，报告最终找到 3 个匹配项。
10. 第一个匹配项会被激活和高亮，`ReportFindInPageSelection` 会被调用，报告其位置。

**假设输出 (通过 IPC 传递给客户端):**

* `SetNumberOfMatches(123, 1, kMoreUpdatesComing)`
* `SetNumberOfMatches(123, 3, kFinalUpdate)`
* `SetActiveMatch(123, {x: 10, y: 20, width: 50, height: 15}, 1, kFinalUpdate)` (假设第一个匹配项的矩形位置)

**用户或编程常见的使用错误:**

1. **用户错误 - 拼写错误:** 用户在搜索框中输入错误的关键词，导致找不到预期的结果。
   * **示例:** 用户想搜索 "Chromium"，但输入了 "Chrmoium"。
2. **用户错误 - 大小写敏感:** 用户可能没有意识到查找是区分大小写的 (取决于 `match_case` 选项)。
   * **示例:** 页面中有 "Example"，用户搜索 "example" 但 `match_case` 为 `true`。
3. **用户错误 - 期望在插件内容中查找:** 用户可能期望在 Flash 或其他插件的内容中进行查找，但插件没有实现相应的查找功能，或者浏览器没有将查找请求传递给插件。
4. **编程错误 - 请求 ID 管理不当:** 开发者在与 `FindInPage` 通信时，如果 `request_id` 管理不当，可能会导致查找结果与请求不匹配。
5. **编程错误 - 忽略异步性:** 查找操作可能是异步的，开发者如果没有正确处理回调或 Promise，可能会在结果返回前就执行后续操作。
6. **编程错误 - 坐标转换错误:** 在处理 Android 平台的 `ActiveFindMatchRect` 等方法时，如果坐标转换出现错误，可能会导致高亮位置不正确。
7. **编程错误 - 不正确的停止操作:**  使用 `StopFinding` 时，如果 `action` 参数设置不当，可能会导致意外的选中或取消选中行为。

总而言之，`find_in_page.cc` 文件是 Blink 渲染引擎中实现核心查找功能的重要组成部分，它协调了文本搜索、插件处理、结果报告以及与浏览器 UI 的通信。理解这个文件的功能有助于我们理解浏览器是如何实现“在页面中查找”这一常用特性的。

Prompt: 
```
这是目录为blink/renderer/core/frame/find_in_page.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
/*
 * Copyright (C) 2009 Google Inc. All rights reserved.
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

#include "third_party/blink/renderer/core/frame/find_in_page.h"

#include <utility>

#include "base/numerics/safe_conversions.h"
#include "third_party/blink/public/web/web_document.h"
#include "third_party/blink/public/web/web_local_frame_client.h"
#include "third_party/blink/public/web/web_plugin.h"
#include "third_party/blink/public/web/web_plugin_document.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_document_state.h"
#include "third_party/blink/renderer/core/editing/finder/text_finder.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/focus_controller.h"
#include "third_party/blink/renderer/core/page/page.h"

namespace blink {

FindInPage::FindInPage(WebLocalFrameImpl& frame,
                       InterfaceRegistry* interface_registry)
    : frame_(&frame) {
  // TODO(rakina): Use InterfaceRegistry of |frame| directly rather than passing
  // both of them.
  if (!interface_registry)
    return;
  // TODO(crbug.com/800641): Use InterfaceValidator when it works for associated
  // interfaces.
  interface_registry->AddAssociatedInterface(WTF::BindRepeating(
      &FindInPage::BindToReceiver, WrapWeakPersistent(this)));
}

void FindInPage::Find(int request_id,
                      const String& search_text,
                      mojom::blink::FindOptionsPtr options) {
  DCHECK(!search_text.empty());

  // Record the fact that we have a find-in-page request.
  frame_->GetFrame()->GetDocument()->MarkHasFindInPageRequest();

  blink::WebPlugin* plugin = GetWebPluginForFind();
  // Check if the plugin still exists in the document.
  if (plugin) {
    if (!options->new_session) {
      // Just navigate back/forward.
      plugin->SelectFindResult(options->forward, request_id);
      LocalFrame* core_frame = frame_->GetFrame();
      core_frame->GetPage()->GetFocusController().SetFocusedFrame(core_frame);
    } else if (!plugin->StartFind(search_text, options->match_case,
                                  request_id)) {
      // Send "no results"
      ReportFindInPageMatchCount(request_id, 0 /* count */,
                                 true /* final_update */);
    }
    return;
  }

  // Send "no results" if this frame has no visible content.
  if (!frame_->HasVisibleContent()) {
    ReportFindInPageMatchCount(request_id, 0 /* count */,
                               true /* final_update */);
    return;
  }

  WebRange current_selection = frame_->SelectionRange();
  bool result = false;
  bool active_now = false;

  if (options->new_session)
    EnsureTextFinder().InitNewSession(*options);

  // Search for an active match only if this frame is focused or if this is an
  // existing session.
  if (options->find_match &&
      (frame_->IsFocused() || !options->new_session)) {
    result = FindInternal(request_id, search_text, *options,
                          false /* wrap_within_frame */, &active_now);
  }

  if (result && options->new_session) {
    // Indicate that at least one match has been found. 1 here means
    // possibly more matches could be coming.
    ReportFindInPageMatchCount(request_id, 1 /* count */,
                               false /* final_update */);
  }

  // There are three cases in which scoping is needed:
  //
  // (1) This is a new find session. This will be its first scoping effort.
  //
  // (2) Something has been selected since the last search. This means that we
  // cannot just increment the current match ordinal; we need to re-generate
  // it.
  //
  // (3) TextFinder::Find() found what should be the next match (|result| is
  // true), but was unable to activate it (|activeNow| is false). This means
  // that the text containing this match was dynamically added since the last
  // scope of the frame. The frame needs to be re-scoped so that any matches
  // in the new text can be highlighted and included in the reported number of
  // matches.
  //
  // If none of these cases are true, then we just report the current match
  // count without scoping.
  if (/* (1) */ !options->new_session && /* (2) */ current_selection.IsNull() &&
      /* (3) */ !(result && !active_now)) {
    // Force report of the actual count.
    EnsureTextFinder().IncreaseMatchCount(request_id, 0);
    return;
  }

  // Start a new scoping  If the scoping function determines that it
  // needs to scope, it will defer until later.
  EnsureTextFinder().StartScopingStringMatches(request_id, search_text,
                                               *options);
}

bool WebLocalFrameImpl::FindForTesting(int identifier,
                                       const WebString& search_text,
                                       bool match_case,
                                       bool forward,
                                       bool new_session,
                                       bool force,
                                       bool wrap_within_frame,
                                       bool async) {
  auto options = mojom::blink::FindOptions::New();
  options->match_case = match_case;
  options->forward = forward;
  options->new_session = new_session;
  options->force = force;
  options->run_synchronously_for_testing = !async;
  bool result = find_in_page_->FindInternal(identifier, search_text, *options,
                                            wrap_within_frame, nullptr);
  find_in_page_->StopFinding(
      mojom::blink::StopFindAction::kStopFindActionKeepSelection);
  return result;
}

bool FindInPage::FindInternal(int identifier,
                              const String& search_text,
                              const mojom::blink::FindOptions& options,
                              bool wrap_within_frame,
                              bool* active_now) {
  if (!frame_->GetFrame())
    return false;

  // Unlikely, but just in case we try to find-in-page on a detached frame.
  DCHECK(frame_->GetFrame()->GetPage());

  return EnsureTextFinder().Find(identifier, search_text, options,
                                 wrap_within_frame, active_now);
}

void FindInPage::StopFinding(mojom::StopFindAction action) {
  WebPlugin* const plugin = GetWebPluginForFind();
  if (plugin) {
    plugin->StopFind();
    return;
  }

  const bool clear_selection =
      action == mojom::StopFindAction::kStopFindActionClearSelection;
  if (clear_selection)
    frame_->ExecuteCommand(WebString::FromUTF8("Unselect"));

  if (GetTextFinder()) {
    if (!clear_selection)
      GetTextFinder()->SetFindEndstateFocusAndSelection();
    GetTextFinder()->StopFindingAndClearSelection();
  }

  if (action == mojom::StopFindAction::kStopFindActionActivateSelection &&
      frame_->IsFocused()) {
    WebDocument doc = frame_->GetDocument();
    if (!doc.IsNull()) {
      WebElement element = doc.FocusedElement();
      if (!element.IsNull())
        element.SimulateClick();
    }
  }
}

int FindInPage::FindMatchMarkersVersion() const {
  if (GetTextFinder())
    return GetTextFinder()->FindMatchMarkersVersion();
  return 0;
}

void FindInPage::SetClient(
    mojo::PendingRemote<mojom::blink::FindInPageClient> remote) {
  // TODO(crbug.com/984878): Having to call reset() to try to bind a remote that
  // might be bound is questionable behavior and suggests code may be buggy.
  client_.reset();
  client_.Bind(std::move(remote),
               frame_->GetTaskRunner(blink::TaskType::kInternalDefault));
}

#if BUILDFLAG(IS_ANDROID)
gfx::RectF FindInPage::ActiveFindMatchRect() {
  if (GetTextFinder())
    return GetTextFinder()->ActiveFindMatchRect();
  return gfx::RectF();
}

void FindInPage::ActivateNearestFindResult(int request_id,
                                           const gfx::PointF& point) {
  gfx::Rect active_match_rect;
  const int ordinal =
      EnsureTextFinder().SelectNearestFindMatch(point, &active_match_rect);
  if (ordinal == -1) {
    // Something went wrong, so send a no-op reply (force the frame to report
    // the current match count) in case the host is waiting for a response due
    // to rate-limiting.
    EnsureTextFinder().IncreaseMatchCount(request_id, 0);
    return;
  }
  ReportFindInPageSelection(request_id, ordinal, active_match_rect,
                            true /* final_update */);
}

void FindInPage::GetNearestFindResult(const gfx::PointF& point,
                                      GetNearestFindResultCallback callback) {
  float distance;
  EnsureTextFinder().NearestFindMatch(point, &distance);
  std::move(callback).Run(distance);
}

void FindInPage::FindMatchRects(int current_version,
                                FindMatchRectsCallback callback) {
  int rects_version = FindMatchMarkersVersion();
  Vector<gfx::RectF> rects;
  if (current_version != rects_version)
    rects = EnsureTextFinder().FindMatchRects();
  std::move(callback).Run(rects_version, rects, ActiveFindMatchRect());
}
#endif  // BUILDFLAG(IS_ANDROID)

void FindInPage::ClearActiveFindMatch() {
  // TODO(rakina): Do collapse selection as this currently does nothing.
  frame_->ExecuteCommand(WebString::FromUTF8("CollapseSelection"));
  EnsureTextFinder().ClearActiveFindMatch();
}

void WebLocalFrameImpl::SetTickmarks(const WebElement& target,
                                     const WebVector<gfx::Rect>& tickmarks) {
  find_in_page_->SetTickmarks(target, tickmarks);
}

void FindInPage::SetTickmarks(
    const WebElement& target,
    const WebVector<gfx::Rect>& tickmarks_in_layout_space) {
  LayoutBox* box;
  if (target.IsNull())
    box = frame_->GetFrame()->ContentLayoutObject();
  else
    box = target.ConstUnwrap<Element>()->GetLayoutBoxForScrolling();

  if (!box)
    return;

  Vector<gfx::Rect> tickmarks_converted(
      base::checked_cast<wtf_size_t>(tickmarks_in_layout_space.size()));
  for (wtf_size_t i = 0; i < tickmarks_in_layout_space.size(); ++i)
    tickmarks_converted[i] = tickmarks_in_layout_space[i];

  box->OverrideTickmarks(std::move(tickmarks_converted));
}

TextFinder* WebLocalFrameImpl::GetTextFinder() const {
  return find_in_page_->GetTextFinder();
}

TextFinder* FindInPage::GetTextFinder() const {
  return text_finder_.Get();
}

TextFinder& WebLocalFrameImpl::EnsureTextFinder() {
  return find_in_page_->EnsureTextFinder();
}

TextFinder& FindInPage::EnsureTextFinder() {
  if (!text_finder_)
    text_finder_ = MakeGarbageCollected<TextFinder>(*frame_);

  return *text_finder_;
}

void FindInPage::SetPluginFindHandler(WebPluginContainer* plugin) {
  plugin_find_handler_ = plugin;
}

WebPluginContainer* FindInPage::PluginFindHandler() const {
  return plugin_find_handler_;
}

WebPlugin* FindInPage::GetWebPluginForFind() {
  if (frame_->GetDocument().IsPluginDocument())
    return frame_->GetDocument().To<WebPluginDocument>().Plugin();
  if (plugin_find_handler_)
    return plugin_find_handler_->Plugin();
  return nullptr;
}

void FindInPage::BindToReceiver(
    mojo::PendingAssociatedReceiver<mojom::blink::FindInPage> receiver) {
  receiver_.Bind(std::move(receiver),
                 frame_->GetTaskRunner(blink::TaskType::kInternalDefault));
}

void FindInPage::Dispose() {
  receiver_.reset();
}

void FindInPage::ReportFindInPageMatchCount(int request_id,
                                            int count,
                                            bool final_update) {
  // In tests, |client_| might not be set.
  if (!client_)
    return;
  client_->SetNumberOfMatches(
      request_id, count,
      final_update ? mojom::blink::FindMatchUpdateType::kFinalUpdate
                   : mojom::blink::FindMatchUpdateType::kMoreUpdatesComing);
}

void FindInPage::ReportFindInPageSelection(
    int request_id,
    int active_match_ordinal,
    const gfx::Rect& local_selection_rect,
    bool final_update) {
  // In tests, |client_| might not be set.
  if (!client_)
    return;

  float device_scale_factor = 1.f;
  if (LocalFrame* local_frame = frame_->GetFrame()) {
    device_scale_factor =
        local_frame->GetPage()->GetChromeClient().WindowToViewportScalar(
            local_frame, 1.0f);
  }
  auto selection_rect = gfx::ScaleToEnclosingRect(local_selection_rect,
                                                  1.f / device_scale_factor);
  client_->SetActiveMatch(
      request_id, selection_rect, active_match_ordinal,
      final_update ? mojom::blink::FindMatchUpdateType::kFinalUpdate
                   : mojom::blink::FindMatchUpdateType::kMoreUpdatesComing);
}

}  // namespace blink

"""

```