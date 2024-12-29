Response:
Let's break down the thought process for analyzing the `frame_tree.cc` file.

1. **Understand the Goal:** The primary goal is to understand the functionality of `frame_tree.cc` in the Chromium Blink rendering engine. This includes its relationships with HTML, CSS, and JavaScript, potential usage errors, and debugging tips.

2. **Initial Scan and Identification of Key Concepts:**  The first step is to quickly scan the code, looking for keywords and familiar terms. I see:
    * `FrameTree`: The central class.
    * `Frame`:  Appears frequently, suggesting a hierarchical structure.
    * `Parent`, `Child`, `Sibling`, `Top`:  Confirms the tree structure.
    * `Name`:  Frames have names.
    * `Navigation`:  Functions like `FindFrameForNavigationInternal`.
    * `Document`, `LocalFrame`, `RemoteFrame`:  Different types of frames.
    * `Page`:  Frames belong to pages.
    * `CreateWindow`:  Frames can create new windows.
    * `Client`:  Interaction with the embedder (browser).
    * `SecurityOrigin`:  Relates to cross-origin issues.

3. **Deconstructing the Class Functionality:**  Now, I'll go through the public methods of `FrameTree` and try to understand their purpose.

    * **Constructor/Destructor:** Basic setup and cleanup.
    * **`GetName()`/`SetName()`:**  Getting and setting the frame's name. The comments about `experimental_set_nulled_name_` and `cross_site_cross_browsing_context_group_set_nulled_name_` indicate ongoing experiments/data gathering related to naming. The `ReplicationPolicy` hints at how the name change is propagated. The comment about browser assumptions and unique names highlights a potential area of complexity/coupling.
    * **Tree Traversal (`Parent`, `Top`, `NextSibling`, `FirstChild`, `ScopedChild`, `ScopedChildCount`, `ChildCount`, `TraverseNext`, `IsDescendantOf`):** These clearly deal with navigating the frame hierarchy. The "scoped" versions likely filter based on shadow DOM.
    * **Frame Finding (`FindFrameByName`, `FindOrCreateFrameForNavigation`, `FindFrameForNavigationInternal`):**  Core logic for locating frames based on name, target attributes, and URLs. The special handling of `_blank`, `_self`, `_top`, `_parent`, and `_unfencedTop` is important. The interaction with `FrameLoadRequest` during navigation is also key. The logic for searching across pages within a namespace is noteworthy.
    * **Utility (`InvalidateScopedChildCount`, `Trace`):**  Internal management and debugging support.

4. **Relating to Web Technologies (HTML, CSS, JavaScript):**

    * **HTML:** The frame tree directly reflects the structure of `<iframe>` and `<frame>` elements in HTML. Target attributes in links and forms use the frame names managed by `FrameTree`. The creation of new windows via `<a>` tags with `target="_blank"` also involves this code.
    * **CSS:** While `FrameTree` doesn't directly handle CSS parsing or application, it provides the structural context. The dimensions mentioned in the debug printing (`view->Width()`, `view->Height()`) are influenced by CSS. Styles can affect which frame a navigation targets.
    * **JavaScript:** JavaScript can manipulate the frame tree using `window.frames`, `window.parent`, `window.top`, `window.open()`, and by setting the `target` attribute of forms and links. The `name` property of the `window` object corresponds to the frame's name managed here. JavaScript's ability to navigate between frames relies on the logic in `FindFrameForNavigationInternal`. Cross-origin restrictions enforced at this level impact JavaScript's ability to access frames.

5. **Logical Reasoning and Examples:**  For more complex functions like `FindOrCreateFrameForNavigation`, it's helpful to think about specific scenarios:

    * **Input:** A link with `target="myframe"` is clicked.
    * **Output:** The `Frame` object representing the frame named "myframe" (if it exists) or a newly created frame/window.
    * **Input:** A form submission with `target="_blank"`.
    * **Output:** A new `Frame` in a new browsing context.

6. **Identifying Potential Errors:**  Consider common developer mistakes:

    * **Incorrect `target` attribute:**  Spelling errors in frame names.
    * **Cross-origin issues:** Trying to access a frame from a different domain without proper permissions.
    * **Conflicting navigation policies:**  User actions (like Ctrl+click) overriding intended behavior.
    * **Race conditions:** Issues if frame creation or navigation happens in an unexpected order.

7. **Debugging Workflow:**  How does a developer end up looking at this code?

    * **Unexpected navigation:** A link or form isn't targeting the correct frame.
    * **JavaScript errors related to frame access:**  `Cannot read properties of undefined (reading 'document')` might indicate a problem finding a frame.
    * **New window not opening or opening in the wrong place.**
    * **Browser crashes or unexpected behavior related to iframes.**

8. **Structuring the Answer:** Finally, organize the information into clear sections: Functionality, Relationship to Web Tech, Logical Reasoning, Usage Errors, and Debugging. Use bullet points and examples for readability. Highlight key points and use code snippets where appropriate.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe `FrameTree` is just about the visual layout of frames. **Correction:** Realized it's more about the logical hierarchy and navigation.
* **Overlooking Shadow DOM:**  Initially missed the significance of `ScopedChild` and the `InShadowTree()` check. **Correction:**  Added a note about shadow DOM.
* **Not emphasizing cross-origin:**  Initially focused too much on simple frame finding. **Correction:**  Added explicit mentions of cross-origin issues and the role of `SecurityOrigin`.
* **Vague examples:**  Initial examples were too general. **Correction:** Made the examples more concrete with specific HTML scenarios.

By following these steps, including the self-correction, we can arrive at a comprehensive and accurate understanding of the `frame_tree.cc` file.
这个 `blink/renderer/core/page/frame_tree.cc` 文件是 Chromium Blink 渲染引擎中负责管理和维护页面中 **Frame (框架) 树** 的核心组件。它的主要功能是构建、维护和操作一个表示页面内嵌框架（如 `<iframe>` 和 `<frame>` 元素）层次结构的树形数据结构。

以下是 `FrameTree` 类的主要功能，并结合 JavaScript, HTML, CSS 的关系进行说明：

**主要功能:**

1. **维护 Frame 的层级结构:**
   - `FrameTree` 类代表一个 `Frame` 对象在其所属的框架树中的位置和关系。
   - 它存储了指向父框架 (`Parent()`)、第一个子框架 (`FirstChild()`)、下一个兄弟框架 (`NextSibling()`) 和顶层框架 (`Top()`) 的指针，从而构建出完整的框架树。
   - **与 HTML 的关系:**  HTML 中的 `<iframe>` 和 `<frame>` 标签会创建新的 Frame 对象，这些对象会被添加到当前页面的 `FrameTree` 中。嵌套的 `<iframe>` 会反映在 `FrameTree` 的层级结构中。
   - **例子:** 如果 HTML 结构如下：
     ```html
     <!-- 主框架 -->
     <html>
       <body>
         <iframe name="frame1" src="..."></iframe>
         <iframe name="frame2" src="...">
           <iframe name="subframe" src="..."></iframe>
         </iframe>
       </body>
     </html>
     ```
     那么在 `FrameTree` 中，`frame1` 和 `frame2` 会是主框架的子节点，而 `subframe` 会是 `frame2` 的子节点。

2. **管理和查找 Frame:**
   - 提供方法来查找特定名称的框架 (`FindFrameByName()`, `FindOrCreateFrameForNavigation()`, `FindFrameForNavigationInternal()`)。
   - 可以根据索引查找作用域内的子框架 (`ScopedChild()`). "作用域内" 通常指排除 Shadow DOM 中的框架。
   - 可以获取作用域内的子框架数量 (`ScopedChildCount()`).
   - **与 JavaScript 的关系:** JavaScript 可以通过 `window.frames['frameName']` 或 `window.parent.frames['frameName']` 等方式访问其他框架。这些操作的底层实现会用到 `FrameTree` 提供的查找功能。
   - **例子 (假设输入):**
     - **假设输入 (JavaScript):** `window.frames['frame2']`
     - **输出 (FrameTree 的 `FindFrameByName` 或类似方法):** 返回代表名为 "frame2" 的 `Frame` 对象。

3. **处理框架间的导航:**
   - `FindOrCreateFrameForNavigation()` 方法负责根据导航请求（`FrameLoadRequest`）和目标名称，查找或创建一个合适的框架进行导航。
   - 这涉及到处理特殊的 `target` 属性值，如 `_blank`, `_self`, `_top`, `_parent`。
   - **与 HTML 和 JavaScript 的关系:**  当用户点击一个带有 `target` 属性的链接 (`<a target="...">`) 或 JavaScript 执行 `window.open()` 或修改 `window.location.href` 时，Blink 会使用 `FrameTree` 的方法来确定导航的目标框架。
   - **例子:**
     - **假设输入 (HTML):** `<a href="/new_page.html" target="frame1">Go to Frame 1</a>`，用户点击了这个链接。
     - **`FindOrCreateFrameForNavigation` 的处理逻辑:** 会查找名为 "frame1" 的框架。如果找到，则在该框架中加载 `/new_page.html`。

4. **处理框架的命名:**
   - `GetName()` 和 `SetName()` 方法用于获取和设置框架的名称。
   - 名称可以通过 HTML 的 `name` 属性或 JavaScript 设置。
   - **与 HTML 和 JavaScript 的关系:** HTML 的 `<iframe name="...">` 属性会设置框架的名称。JavaScript 可以通过 `window.name` 获取或设置当前框架的名称。`FrameTree` 负责同步和管理这些名称。

5. **维护框架树的完整性:**
   - 提供方法判断一个框架是否是另一个框架的后代 (`IsDescendantOf()`).
   - 提供方法遍历框架树 (`TraverseNext()`).

**逻辑推理的举例:**

- **假设输入:** 当前框架名为 "parentFrame"，其 HTML 包含一个 `<iframe name="childFrame"></iframe>`。
- **FrameTree 的内部逻辑:** 当解析到 `<iframe>` 标签时，会创建一个新的 `Frame` 对象，并将其添加到 "parentFrame" 的 `FrameTree` 中，成为其子节点。
- **输出:** `parentFrame->Tree().FirstChild()` 会返回代表 "childFrame" 的 `Frame` 对象。

**用户或编程常见的使用错误:**

1. **错误的 `target` 属性:**
   - **错误:** 在 HTML 中使用了错误的框架名称作为 `target` 属性值，例如 `<a href="..." target="wrongFrameName">`，而实际上不存在名为 "wrongFrameName" 的框架。
   - **后果:** 导航可能发生在错误的框架，或者创建一个新的窗口（如果 `target="_blank"`）。
   - **调试线索:** 当用户点击链接后，页面没有在预期的框架中加载，或者意外地打开了新窗口。开发者可以通过检查浏览器的开发者工具中的 "Frames" 面板来查看当前的框架结构和名称，并与 HTML 代码中的 `target` 属性进行比对。

2. **跨域访问限制:**
   - **错误:**  JavaScript 尝试访问不同域的 `<iframe>` 的内容，例如 `window.frames['otherDomainFrame'].document`。
   - **后果:**  浏览器会抛出跨域访问错误 (CORS error)，阻止 JavaScript 访问。
   - **调试线索:** 浏览器的开发者工具的控制台会显示类似于 "Blocked a frame with origin \"http://example.com\" from accessing a cross-origin frame." 的错误信息。这通常与 `FrameTree` 中维护的框架的安全上下文有关。

3. **在框架加载完成前访问:**
   - **错误:** JavaScript 尝试在 `<iframe>` 完全加载之前访问其内容，例如在 `<iframe>` 的 `onload` 事件触发之前就执行了访问其 `document` 的代码。
   - **后果:** 可能会遇到空指针异常或访问未定义属性的错误。
   - **调试线索:** 开发者工具的控制台可能会显示类似于 "Cannot read properties of null (reading 'document')" 的错误。确保在访问框架内容之前，该框架已经完全加载。

**用户操作如何一步步地到达这里（调试线索）:**

1. **用户在浏览器中打开一个包含 `<iframe>` 标签的网页。**
2. **Blink 的 HTML 解析器解析 HTML 代码，遇到 `<iframe>` 标签。**
3. **Blink 创建一个新的 `Frame` 对象来表示这个 `<iframe>`。**
4. **`FrameTree` 的相关方法被调用，将新的 `Frame` 对象添加到当前页面的框架树中，维护父子关系。**
5. **用户点击一个带有 `target` 属性的链接或提交一个带有 `target` 属性的表单。**
6. **Blink 的导航系统会调用 `FrameTree::FindOrCreateFrameForNavigation()` 方法，根据 `target` 属性的值查找目标框架。**
7. **如果找到了目标框架，导航请求会被发送到该框架。**
8. **如果目标框架不存在，并且 `target="_blank"`，则会创建一个新的浏览上下文和框架。**
9. **JavaScript 代码执行，尝试通过 `window.frames` 或 `window.parent.frames` 访问其他框架。**
10. **Blink 会调用 `FrameTree` 的查找方法 (`FindFrameByName` 等) 来定位目标框架。**

在调试与框架相关的问题时，以下是一些可能有用的步骤：

- **查看浏览器的开发者工具的 "Elements" 或 "Inspector" 面板:** 确认 HTML 结构中 `<iframe>` 标签的 `name` 和 `id` 属性是否正确。
- **查看浏览器的开发者工具的 "Frames" 面板:** 了解当前页面的框架结构，包括框架的名称和层级关系。
- **在 JavaScript 代码中使用 `console.log(window.frames)` 或 `console.log(window.parent.frames)`:** 查看当前窗口及其父窗口的框架集合，确认框架是否存在以及名称是否正确。
- **使用断点调试 JavaScript 代码:**  在尝试访问其他框架的代码处设置断点，查看 `window.frames` 或 `window.parent.frames` 的值，以及目标框架是否可访问。
- **检查浏览器的控制台 (Console):** 查看是否有与跨域访问相关的错误信息。

总而言之，`blink/renderer/core/page/frame_tree.cc` 是 Blink 渲染引擎中管理页面框架结构的关键部分，它与 HTML 的框架元素、CSS 的布局以及 JavaScript 的框架操作紧密相关，确保了浏览器能够正确地呈现和管理包含多个框架的网页。

Prompt: 
```
这是目录为blink/renderer/core/page/frame_tree.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) Research In Motion Limited 2010. All rights reserved.
 * Copyright (C) 2006 Apple Computer, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
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

#include "third_party/blink/renderer/core/page/frame_tree.h"

#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/frame/frame_client.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/remote_frame.h"
#include "third_party/blink/renderer/core/frame/remote_frame_view.h"
#include "third_party/blink/renderer/core/loader/frame_load_request.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/create_window.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {

namespace {

const unsigned kInvalidChildCount = ~0U;

}  // namespace

FrameTree::FrameTree(Frame* this_frame)
    : this_frame_(this_frame), scoped_child_count_(kInvalidChildCount) {}

FrameTree::~FrameTree() = default;

const AtomicString& FrameTree::GetName() const {
  // TODO(andypaicu): remove this once we have gathered the data
  if (experimental_set_nulled_name_) {
    auto* frame = DynamicTo<LocalFrame>(this_frame_.Get());
    if (!frame)
      frame = DynamicTo<LocalFrame>(&Top());
    if (frame) {
      UseCounter::Count(frame->GetDocument(),
                        WebFeature::kCrossOriginMainFrameNulledNameAccessed);
      if (!name_.empty()) {
        UseCounter::Count(
            frame->GetDocument(),
            WebFeature::kCrossOriginMainFrameNulledNonEmptyNameAccessed);
      }
    }
  }

  if (cross_site_cross_browsing_context_group_set_nulled_name_) {
    auto* frame = DynamicTo<LocalFrame>(this_frame_.Get());
    if (frame && frame->IsOutermostMainFrame() && !name_.empty()) {
      UseCounter::Count(
          frame->GetDocument(),
          WebFeature::
              kCrossBrowsingContextGroupMainFrameNulledNonEmptyNameAccessed);
    }
  }
  return name_;
}

// TODO(andypaicu): remove this once we have gathered the data
void FrameTree::ExperimentalSetNulledName() {
  experimental_set_nulled_name_ = true;
}

// TODO(shuuran): remove this once we have gathered the data
void FrameTree::CrossSiteCrossBrowsingContextGroupSetNulledName() {
  cross_site_cross_browsing_context_group_set_nulled_name_ = true;
}

void FrameTree::SetName(const AtomicString& name,
                        ReplicationPolicy replication) {
  if (replication == kReplicate) {
    // Avoid calling out to notify the embedder if the browsing context name
    // didn't change. This is important to avoid violating the browser
    // assumption that the unique name doesn't change if the browsing context
    // name doesn't change.
    // TODO(dcheng): This comment is indicative of a problematic layering
    // violation. The browser should not be relying on the renderer to get this
    // correct; unique name calculation should be moved up into the browser.
    if (name != name_) {
      // TODO(lukasza): https://crbug.com/660485: Eventually we need to also
      // support replication of name changes that originate in a *remote* frame.
      To<LocalFrame>(this_frame_.Get())->Client()->DidChangeName(name);
    }
  }

  // TODO(andypaicu): remove this once we have gathered the data
  experimental_set_nulled_name_ = false;

  auto* frame = DynamicTo<LocalFrame>(this_frame_.Get());
  if (frame && frame->IsOutermostMainFrame() && !name.empty()) {
    // TODO(shuuran): remove this once we have gathered the data
    cross_site_cross_browsing_context_group_set_nulled_name_ = false;
  }
  name_ = name;
}

DISABLE_CFI_PERF
Frame* FrameTree::Parent() const {
  return this_frame_->Parent();
}

Frame& FrameTree::Top() const {
  return *this_frame_->Top();
}

Frame* FrameTree::NextSibling() const {
  return this_frame_->NextSibling();
}

Frame* FrameTree::FirstChild() const {
  return this_frame_->FirstChild();
}

Frame* FrameTree::ScopedChild(unsigned index) const {
  unsigned scoped_index = 0;
  for (Frame* child = FirstChild(); child;
       child = child->Tree().NextSibling()) {
    if (child->Client()->InShadowTree())
      continue;
    if (scoped_index == index)
      return child;
    scoped_index++;
  }

  return nullptr;
}

Frame* FrameTree::ScopedChild(const AtomicString& name) const {
  if (name.empty())
    return nullptr;

  for (Frame* child = FirstChild(); child;
       child = child->Tree().NextSibling()) {
    if (child->Client()->InShadowTree())
      continue;
    if (child->Tree().GetName() == name)
      return child;
  }
  return nullptr;
}

unsigned FrameTree::ScopedChildCount() const {
  if (scoped_child_count_ == kInvalidChildCount) {
    unsigned scoped_count = 0;
    for (Frame* child = FirstChild(); child;
         child = child->Tree().NextSibling()) {
      if (child->Client()->InShadowTree())
        continue;
      scoped_count++;
    }
    scoped_child_count_ = scoped_count;
  }
  return scoped_child_count_;
}

void FrameTree::InvalidateScopedChildCount() {
  scoped_child_count_ = kInvalidChildCount;
}

unsigned FrameTree::ChildCount() const {
  unsigned count = 0;
  for (Frame* result = FirstChild(); result;
       result = result->Tree().NextSibling())
    ++count;
  return count;
}

Frame* FrameTree::FindFrameByName(const AtomicString& name) const {
  // Named frame lookup should always be relative to a local frame.
  DCHECK(IsA<LocalFrame>(this_frame_.Get()));
  LocalFrame* current_frame = To<LocalFrame>(this_frame_.Get());

  Frame* frame = FindFrameForNavigationInternal(name, KURL());
  if (frame && !current_frame->CanNavigate(*frame)) {
    frame = nullptr;
  }
  return frame;
}

FrameTree::FindResult FrameTree::FindOrCreateFrameForNavigation(
    FrameLoadRequest& request,
    const AtomicString& name) const {
  // Named frame lookup should always be relative to a local frame.
  DCHECK(IsA<LocalFrame>(this_frame_.Get()));
  LocalFrame* current_frame = To<LocalFrame>(this_frame_.Get());

  // A GetNavigationPolicy() value other than kNavigationPolicyCurrentTab at
  // this point indicates that a user event modified the navigation policy
  // (e.g., a ctrl-click). Let the user's action override any target attribute.
  if (request.GetNavigationPolicy() != kNavigationPolicyCurrentTab)
    return FindResult(current_frame, false);

  const KURL& url = request.GetResourceRequest().Url();
  Frame* frame = FindFrameForNavigationInternal(name, url, &request);
  bool new_window = false;
  if (!frame) {
    frame = CreateNewWindow(*current_frame, request, name);
    new_window = true;
    // CreateNewWindow() might have modified NavigationPolicy.
    // Set it back now that the new window is known to be the right one.
    request.SetNavigationPolicy(kNavigationPolicyCurrentTab);
  } else if (!current_frame->CanNavigate(*frame, url)) {
    frame = nullptr;
  }

  if (frame && !new_window) {
    if (frame->GetPage() != current_frame->GetPage())
      frame->FocusPage(current_frame);

    // Focusing can fire onblur, so check for detach.
    if (!frame->GetPage())
      frame = nullptr;
  }
  return FindResult(frame, new_window);
}

Frame* FrameTree::FindFrameForNavigationInternal(
    const AtomicString& name,
    const KURL& url,
    FrameLoadRequest* request) const {
  LocalFrame* current_frame = To<LocalFrame>(this_frame_.Get());

  if (EqualIgnoringASCIICase(name, "_current")) {
    UseCounter::Count(current_frame->GetDocument(), WebFeature::kTargetCurrent);
  }

  if (EqualIgnoringASCIICase(name, "_self") ||
      EqualIgnoringASCIICase(name, "_current") || name.empty()) {
    return current_frame;
  }

  if (EqualIgnoringASCIICase(name, "_top")) {
    return &Top();
  }

  // The target _unfencedTop should only be treated as a special name in
  // opaque-ads mode fenced frames.
  if (EqualIgnoringASCIICase(name, "_unfencedTop")) {
    // In fenced frames, we set a flag that will later indicate to the browser
    // that this is an _unfencedTop navigation, and return the current frame
    // so that the renderer-side checks will succeed.
    // TODO(crbug.com/1315802): Refactor MPArch _unfencedTop handling.
    if (current_frame->GetDeprecatedFencedFrameMode() ==
            blink::FencedFrame::DeprecatedFencedFrameMode::kOpaqueAds &&
        request != nullptr) {
      request->SetIsUnfencedTopNavigation(true);
      return current_frame;
    }
  }

  if (EqualIgnoringASCIICase(name, "_parent")) {
    return Parent() ? Parent() : current_frame;
  }

  // Since "_blank" should never be any frame's name, the following just amounts
  // to an optimization.
  if (EqualIgnoringASCIICase(name, "_blank")) {
    return nullptr;
  }

  // Search subtree starting with this frame first.
  for (Frame* frame = current_frame; frame;
       frame = frame->Tree().TraverseNext(current_frame)) {
    if (frame->Tree().GetName() == name &&
        current_frame->CanNavigate(*frame, url)) {
      return frame;
    }
  }

  // Search the entire tree for this page next.
  Page* page = current_frame->GetPage();

  // The frame could have been detached from the page, so check it.
  if (!page) {
    return nullptr;
  }

  for (Frame *top = &current_frame->Tree().Top(), *frame = top; frame;
       frame = frame->Tree().TraverseNext(top)) {
    // Skip descendants of this frame that were searched above to avoid
    // showing duplicate console messages if a frame is found by name
    // but access is blocked.
    if (frame->Tree().GetName() == name &&
        !frame->Tree().IsDescendantOf(current_frame) &&
        current_frame->CanNavigate(*frame, url)) {
      return frame;
    }
  }

  // In fenced frames, only resolve target names using the above lookup methods
  // (keywords, descendants, and the rest of the frame tree within the fence).
  // TODO(crbug.com/1262022): Remove this early return when we get rid of
  // ShadowDOM fenced frames, because it is unnecessary in MPArch.
  if (current_frame->IsInFencedFrameTree()) {
    return nullptr;
  }

  // Search the entire tree of each of the other pages in this namespace.
  for (const Page* other_page : page->RelatedPages()) {
    if (other_page == page || other_page->IsClosing()) {
      continue;
    }
    for (Frame* frame = other_page->MainFrame(); frame;
         frame = frame->Tree().TraverseNext(nullptr)) {
      if (frame->Tree().GetName() == name &&
          current_frame->CanNavigate(*frame, url)) {
        return frame;
      }
    }
  }

  // Ask the embedder as a fallback.
  Frame* named_frame = current_frame->Client()->FindFrame(name);
  // The embedder can return a frame from another agent cluster. Make sure
  // that the returned frame, if any, has explicitly allowed cross-agent
  // cluster access.
  DCHECK(!named_frame || current_frame->DomWindow()
                             ->GetSecurityOrigin()
                             ->IsGrantedCrossAgentClusterAccess());
  return named_frame;
}

bool FrameTree::IsDescendantOf(const Frame* ancestor) const {
  if (!ancestor)
    return false;

  if (this_frame_->GetPage() != ancestor->GetPage())
    return false;

  for (Frame* frame = this_frame_; frame; frame = frame->Tree().Parent()) {
    if (frame == ancestor)
      return true;
  }
  return false;
}

DISABLE_CFI_PERF
Frame* FrameTree::TraverseNext(const Frame* stay_within) const {
  Frame* child = FirstChild();
  if (child) {
    DCHECK(!stay_within || child->Tree().IsDescendantOf(stay_within));
    return child;
  }

  if (this_frame_ == stay_within)
    return nullptr;

  Frame* sibling = NextSibling();
  if (sibling) {
    DCHECK(!stay_within || sibling->Tree().IsDescendantOf(stay_within));
    return sibling;
  }

  Frame* frame = this_frame_;
  while (!sibling && (!stay_within || frame->Tree().Parent() != stay_within)) {
    frame = frame->Tree().Parent();
    if (!frame)
      return nullptr;
    sibling = frame->Tree().NextSibling();
  }

  if (frame) {
    DCHECK(!stay_within || !sibling ||
           sibling->Tree().IsDescendantOf(stay_within));
    return sibling;
  }

  return nullptr;
}

void FrameTree::Trace(Visitor* visitor) const {
  visitor->Trace(this_frame_);
}

}  // namespace blink

#if DCHECK_IS_ON()

static void PrintIndent(int indent) {
  for (int i = 0; i < indent; ++i)
    printf("    ");
}

static void PrintFrames(const blink::Frame* frame,
                        const blink::Frame* targetFrame,
                        int indent) {
  if (frame == targetFrame) {
    printf("--> ");
    PrintIndent(indent - 1);
  } else {
    PrintIndent(indent);
  }

  auto* local_frame = blink::DynamicTo<blink::LocalFrame>(frame);
  blink::LocalFrameView* view = local_frame ? local_frame->View() : nullptr;
  printf("Frame %p %dx%d\n", frame, view ? view->Width() : 0,
         view ? view->Height() : 0);
  PrintIndent(indent);
  printf("  owner=%p\n", frame->Owner());
  PrintIndent(indent);
  printf("  frameView=%p\n", view);
  PrintIndent(indent);
  printf("  document=%p\n", local_frame ? local_frame->GetDocument() : nullptr);
  PrintIndent(indent);
  printf("  uri=%s\n\n",
         local_frame && local_frame->GetDocument()
             ? local_frame->GetDocument()->Url().GetString().Utf8().c_str()
             : nullptr);

  for (blink::Frame* child = frame->Tree().FirstChild(); child;
       child = child->Tree().NextSibling())
    PrintFrames(child, targetFrame, indent + 1);
}

void ShowFrameTree(const blink::Frame* frame) {
  if (!frame) {
    printf("Null input frame\n");
    return;
  }

  PrintFrames(&frame->Tree().Top(), frame, 0);
}

#endif  // DCHECK_IS_ON()

"""

```