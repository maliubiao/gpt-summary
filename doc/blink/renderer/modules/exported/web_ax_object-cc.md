Response:
My thinking process to answer the request goes like this:

1. **Understand the Goal:** The request asks for a summary of the `web_ax_object.cc` file's functionality, specifically looking for connections to JavaScript, HTML, and CSS, examples of logical reasoning, potential user errors, debugging hints, and a final summarized function.

2. **Initial Scan for Keywords:** I quickly scan the code for relevant keywords like "JavaScript," "HTML," "CSS," "DOM," "layout," "accessibility," "event," "action," "scroll," "focus," "selection," "value," "name," "role," and the various `WebAXObject` methods. This gives me a high-level understanding of the file's purpose.

3. **Identify Core Functionality:** The file clearly deals with accessibility. The name `WebAXObject` and the inclusion of headers like `third_party/blink/renderer/modules/accessibility/ax_object.h` strongly indicate this. It appears to be a C++ wrapper around the internal accessibility objects (`AXObject`) to expose accessibility information to the outside world (likely through the Chromium accessibility API).

4. **Analyze Included Headers:** The included headers provide clues about the functionalities:
    * `web/web_document.h`, `web/web_element.h`, `web/web_node.h`: Interaction with the DOM.
    * `core/css/css_primitive_value_mappings.h`:  Involvement with CSS properties.
    * `core/layout/layout_view.h`: Connection to the layout engine.
    * `core/input/keyboard_event_manager.h`: Handling keyboard events (relevant for accessibility interactions).
    * `modules/accessibility/*`:  Definitive indication of accessibility functionality.
    * `ui/accessibility/ax_action_data.h`: Handling accessibility actions.

5. **Examine Key Classes and Methods:** I focus on the `WebAXObject` class and its methods. The methods names clearly indicate their function:
    * `Action()`, `CanSetValueAttribute()`: Getting and checking properties.
    * `ChildCount()`, `ChildAt()`, `ParentObject()`: Traversing the accessibility tree.
    * `Serialize()`:  Converting internal representation to an external format (for the accessibility API).
    * `HitTest()`: Finding the accessible object at a given point.
    * `PerformAction()`: Triggering accessibility actions.
    * `Role()`, `Name()`, `Description()`, `Value()`:  Retrieving accessible properties.
    * `ScrollToMakeVisible()`:  Controlling scrolling.
    * `SetSelection()`, `Selection()`:  Managing text selections.

6. **Identify Connections to JavaScript, HTML, and CSS:**
    * **JavaScript:**  The `WebAXObject` is likely exposed to JavaScript through the Chromium extension APIs. JavaScript can call methods on these objects to inspect the accessibility tree and trigger actions. I formulate an example of JavaScript getting the role of an element.
    * **HTML:** The accessibility tree directly reflects the HTML structure. The `WebAXObject` represents elements in the HTML. I provide an example of how HTML elements with ARIA attributes are represented.
    * **CSS:** CSS influences the visual representation, which in turn affects accessibility (e.g., `display: none` hides elements from the accessibility tree). CSS properties like `content` can influence accessible names. I formulate an example using `aria-label` which is related to CSS styling indirectly.

7. **Look for Logical Reasoning and Assumptions:** The `HitTest()` method involves logical reasoning about which accessible object is at a specific point. The code considers popup documents. I describe the input (a point) and the output (a `WebAXObject`).

8. **Consider Potential User/Programming Errors:** Incorrectly using the API (e.g., calling methods on detached objects) is a common error. I give an example of accessing a detached object.

9. **Trace User Operations (Debugging Clues):**  I think about how a user interaction might lead to this code being executed. Using assistive technologies like screen readers or accessibility inspectors would heavily rely on this code. I describe a scenario where a screen reader interacts with a button.

10. **Summarize the Functionality:** Based on the analysis, I synthesize a concise summary of the file's main purpose.

11. **Review and Refine:** I reread my answer to ensure it's clear, accurate, and addresses all parts of the request. I check for consistency and make any necessary adjustments. For instance, I double-check that my examples are relevant and understandable. I ensure I've explicitly addressed each aspect of the prompt (JavaScript, HTML, CSS connections, logical reasoning, errors, debugging).

This iterative process of scanning, analyzing, connecting concepts, and refining helps me construct a comprehensive and accurate answer to the request. The key is to move from a general understanding to specific details and then synthesize the information back into a coherent summary.
好的，让我们来分析一下 `blink/renderer/modules/exported/web_ax_object.cc` 文件的功能。

**文件功能归纳：**

`web_ax_object.cc` 文件定义了 `WebAXObject` 类，它是 Chromium Blink 渲染引擎中用于**暴露和操作可访问性（Accessibility）信息的公共接口**。  它本质上是一个 C++ 的包装器（wrapper），包裹了内部的 `AXObject` 类，使得外部（例如 Chromium 的其他部分，甚至可能是 JavaScript）可以通过一套简洁的 API 来查询和操作渲染树中元素的可访问性属性。

**具体功能点：**

1. **表示可访问性对象:** `WebAXObject` 的实例代表了渲染树中的一个可访问性节点。这个节点可能对应于一个 HTML 元素，也可能是由某些 CSS 属性或 ARIA 属性创建的逻辑上的可访问性节点。

2. **获取可访问性属性:**  该文件提供了大量的方法来获取与可访问性相关的各种属性，例如：
    * **基本信息:**  `AxID()`, `Role()`, `Action()`, `IsDetached()`
    * **层级关系:** `ChildCount()`, `ChildAt()`, `ParentObject()`
    * **状态:** `IsFocused()`, `IsModal()`, `IsVisited()`, `CheckedState()`
    * **文本内容:** `GetName()`, `Description()`, `GetValueForControl()`
    * **位置和尺寸:** `GetBoundsInFrameCoordinates()`, `GetRelativeBounds()`
    * **链接信息:** `InPageLinkTarget()`, `Url()`
    * **表格信息:** `ColumnCount()`, `RowCount()`, `CellForColumnAndRow()`
    * **滚动信息:** `GetScrollOffset()`, `MinimumScrollOffset()`, `MaximumScrollOffset()`
    * **ARIA 属性:** `AriaCurrentState()`, `LiveRegionAtomic()`, `LiveRegionRelevant()`, `AriaActiveDescendant()`
    * **其他属性:** `Language()`, `HeadingLevel()`, `SortDirection()`

3. **执行可访问性操作:**  `WebAXObject` 允许执行与可访问性相关的操作，例如：
    * **点击:** `IsClickable()` 检查是否可点击，但实际执行点击操作可能在其他地方。
    * **设置焦点:** 虽然没有直接的 `SetFocused()` 方法，但可以通过某些操作（如 `SetSelection()`）间接影响焦点。
    * **滚动:** `ScrollToMakeVisible()`, `SetScrollOffset()`, `ScrollToMakeVisibleWithSubFocus()`
    * **设置值:** `CanSetValueAttribute()` 检查是否可以设置值，具体的设置操作可能在更底层的代码中。
    * **设置选中范围:** `SetSelection()`, `Selection()`

4. **与可访问性树的交互:**  提供了方法来遍历和查询可访问性树的结构。

5. **与事件和动作的关联:**  `ScopedActionAnnotator` 类用于在执行程序化操作时标记相关的可访问性事件来源和动作类型。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

* **HTML:**  HTML 结构是构建可访问性树的基础。`WebAXObject` 实例通常对应于 HTML 元素。
    * **例子:**  当一个 HTML 元素 `<button aria-label="关闭">X</button>` 被渲染时，会创建一个对应的 `WebAXObject`。通过 `GetName()` 方法可以获取到 "关闭" 这个名字，即使按钮的文本内容是 "X"。

* **CSS:** CSS 属性会影响元素的可访问性。例如，`display: none` 的元素通常不会出现在可访问性树中。ARIA 属性也可以通过 CSS 的 `content` 属性来设置。
    * **例子:**  如果一个 `<div>` 元素通过 CSS 设置了 `content: attr(aria-label);` 并且 HTML 中设置了 `<div aria-label="重要信息"></div>`，那么该 `WebAXObject` 的 `GetName()` 方法会返回 "重要信息"。

* **JavaScript:**  JavaScript 可以通过 Chromium 提供的 API (例如 Chrome DevTools 的 Accessibility 面板，或者扩展程序 API) 来访问和操作 `WebAXObject`。
    * **例子:**  在 JavaScript 中，可以通过某些方法获取到代表一个按钮的 `WebAXObject`，然后调用它的 `Role()` 方法来判断其角色是否为 "button"。或者，可以使用 JavaScript 触发一个 `ScrollIntoView()` 操作，这可能会最终调用到 `WebAXObject` 的 `ScrollToMakeVisible()` 方法。

**逻辑推理及假设输入与输出：**

`HitTest()` 方法是一个明显的逻辑推理的例子。

* **假设输入:**  一个 `gfx::Point` 对象，表示屏幕上的一个坐标点。
* **逻辑推理:**  `HitTest()` 方法会遍历可访问性树，并检查哪个 `WebAXObject` 的边界包含了给定的点。它还会考虑弹出窗口的情况，优先在弹出窗口中进行命中测试。
* **假设输出:**  一个 `WebAXObject` 对象，表示在给定点上的可访问性对象。如果该点上没有可访问性对象，则返回一个空的 `WebAXObject`。

**用户或编程常见的使用错误及举例说明：**

* **操作已分离的对象:**  在 DOM 结构发生变化后，之前获取的 `WebAXObject` 可能已经变得无效（detached）。尝试访问已分离的对象的属性或执行操作会导致错误或未定义的行为。
    * **例子:**  用户通过 JavaScript 获取了一个代表某个列表项的 `WebAXObject`，然后页面上的 JavaScript 代码移除了该列表项。如果用户继续尝试调用该 `WebAXObject` 的 `GetName()` 方法，可能会导致崩溃或返回错误的结果。

* **假设布局已经完成:**  很多 `WebAXObject` 的方法依赖于当前的布局信息。如果在布局尚未完成时调用这些方法，可能会得到不准确的结果。
    * **例子:** 在 JavaScript 中，尝试在元素刚刚添加到 DOM 但浏览器尚未完成布局的情况下，立即获取其 `GetBoundsInFrameCoordinates()`，返回的可能是初始的或不正确的边界。

**用户操作如何一步步到达这里（调试线索）：**

1. **用户与网页交互:** 用户使用鼠标点击、键盘导航、或者使用辅助技术（如屏幕阅读器）与网页进行交互。
2. **事件触发:**  用户的操作会触发各种浏览器事件（例如 `click`, `focus`, `keydown` 等）。
3. **事件处理:**  Blink 渲染引擎会处理这些事件。例如，当用户点击一个按钮时，会触发一个点击事件。
4. **可访问性 API 调用:**  辅助技术或者 Chromium 的可访问性服务会通过公共 API (例如 Chromium 的 `content/browser/accessibility/`)  请求可访问性信息。
5. **`WebAXObject` 方法调用:**  这些请求最终会调用到 `web_ax_object.cc` 中定义的 `WebAXObject` 的各种方法，以获取所需的信息（例如，屏幕阅读器需要知道当前焦点的元素的名称和角色）。
6. **内部 `AXObject` 操作:** `WebAXObject` 的方法会调用内部的 `AXObject` 类的方法来获取或修改底层的可访问性数据。

**作为调试线索，当你在调试可访问性相关问题时：**

* **断点设置:** 可以在 `WebAXObject` 的关键方法（例如 `GetName()`, `Role()`, `GetBoundsInFrameCoordinates()`, `PerformAction()`) 中设置断点，来观察在特定用户操作下哪些可访问性信息被请求。
* **检查对象状态:**  使用调试器检查 `WebAXObject` 是否已分离 (`IsDetached()`)，以及它内部的 `AXObject` 指针是否有效。
* **查看可访问性树:**  使用 Chrome DevTools 的 Accessibility 面板来查看当前页面的可访问性树结构，这有助于理解 `WebAXObject` 实例之间的关系。

**第 1 部分功能归纳：**

总而言之，`blink/renderer/modules/exported/web_ax_object.cc` 文件的主要功能是**提供了一个 C++ 接口，用于访问和操作 Chromium Blink 渲染引擎中的可访问性信息**。它充当了内部可访问性表示 (`AXObject`) 和外部世界之间的桥梁，使得其他组件（包括辅助技术和 Chromium 的上层代码）能够理解和与网页的可访问性结构进行交互。

### 提示词
```
这是目录为blink/renderer/modules/exported/web_ax_object.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
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

#include "third_party/blink/public/web/web_ax_object.h"

#include "base/ranges/algorithm.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/public/platform/web_url.h"
#include "third_party/blink/public/web/web_document.h"
#include "third_party/blink/public/web/web_element.h"
#include "third_party/blink/public/web/web_node.h"
#include "third_party/blink/public/web/web_view.h"
#include "third_party/blink/renderer/core/css/css_primitive_value_mappings.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_utilities.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/editing/visible_position.h"
#include "third_party/blink/renderer/core/exported/web_view_impl.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/input/keyboard_event_manager.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/page_popup.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/modules/accessibility/ax_object.h"
#include "third_party/blink/renderer/modules/accessibility/ax_object_cache_impl.h"
#include "third_party/blink/renderer/modules/accessibility/ax_position.h"
#include "third_party/blink/renderer/modules/accessibility/ax_range.h"
#include "third_party/blink/renderer/modules/accessibility/ax_selection.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "ui/accessibility/ax_action_data.h"

namespace blink {

namespace {
mojom::blink::ScrollAlignment::Behavior ToBlinkScrollAlignmentBehavior(
    ax::mojom::ScrollAlignment alignment) {
  switch (alignment) {
    case ax::mojom::ScrollAlignment::kNone:
      return mojom::blink::ScrollAlignment::Behavior::kNoScroll;
    case ax::mojom::ScrollAlignment::kScrollAlignmentCenter:
      return mojom::blink::ScrollAlignment::Behavior::kCenter;
    case ax::mojom::ScrollAlignment::kScrollAlignmentTop:
      return mojom::blink::ScrollAlignment::Behavior::kTop;
    case ax::mojom::ScrollAlignment::kScrollAlignmentBottom:
      return mojom::blink::ScrollAlignment::Behavior::kBottom;
    case ax::mojom::ScrollAlignment::kScrollAlignmentLeft:
      return mojom::blink::ScrollAlignment::Behavior::kLeft;
    case ax::mojom::ScrollAlignment::kScrollAlignmentRight:
      return mojom::blink::ScrollAlignment::Behavior::kRight;
    case ax::mojom::ScrollAlignment::kScrollAlignmentClosestEdge:
      return mojom::blink::ScrollAlignment::Behavior::kClosestEdge;
  }
  NOTREACHED() << alignment;
}
}  // namespace

// A utility class which uses the lifetime of this object to signify when
// AXObjCache or AXObjectCacheImpl handles programmatic actions.
class ScopedActionAnnotator {
 public:
  ScopedActionAnnotator(AXObject* obj,
                        ax::mojom::blink::Action event_from_action)
      : cache_(&obj->AXObjectCache()) {
    std::pair<ax::mojom::blink::EventFrom, ax::mojom::blink::Action>
        event_from_data = cache_->active_event_from_data();
    DCHECK_EQ(event_from_data.first, ax::mojom::blink::EventFrom::kNone)
        << "Multiple ScopedActionAnnotator instances cannot be nested.";
    DCHECK_EQ(event_from_data.second, ax::mojom::blink::Action::kNone)
        << "event_from_action must not be set before construction.";
    cache_->set_active_event_from_data(ax::mojom::blink::EventFrom::kAction,
                                       event_from_action);
  }

  ~ScopedActionAnnotator() {
    cache_->set_active_event_from_data(ax::mojom::blink::EventFrom::kNone,
                                       ax::mojom::blink::Action::kNone);
  }

 private:
  Persistent<AXObjectCacheImpl> cache_;
};

#if DCHECK_IS_ON()
static void CheckLayoutClean(const Document* document) {
  DCHECK(document);
  LocalFrameView* view = document->View();
  DCHECK(view);
  DCHECK(!document->NeedsLayoutTreeUpdate());
  LayoutView* lview = view->GetLayoutView();

  DCHECK(!view->NeedsLayout())
      << "\n  Layout pending: " << view->LayoutPending()
      << "\n  Needs layout: " << (lview && lview->NeedsLayout());

  DCHECK_GE(document->Lifecycle().GetState(), DocumentLifecycle::kLayoutClean)
      << "Document lifecycle must be at LayoutClean or later, was "
      << document->Lifecycle().GetState();
}
#endif

void WebAXObject::Reset() {
  private_.Reset();
}

void WebAXObject::Assign(const WebAXObject& other) {
  private_ = other.private_;
}

bool WebAXObject::Equals(const WebAXObject& n) const {
  return private_.Get() == n.private_.Get();
}

bool WebAXObject::IsDetached() const {
  if (private_.IsNull())
    return true;

  return private_->IsDetached();
}

int WebAXObject::AxID() const {
  if (IsDetached())
    return -1;

  return private_->AXObjectID();
}

ax::mojom::DefaultActionVerb WebAXObject::Action() const {
  if (IsDetached())
    return ax::mojom::DefaultActionVerb::kNone;

  return private_->Action();
}

bool WebAXObject::CanSetValueAttribute() const {
  if (IsDetached())
    return false;

  return private_->CanSetValueAttribute();
}

unsigned WebAXObject::ChildCount() const {
  if (IsDetached())
    return 0;
  return private_->ChildCountIncludingIgnored();
}

WebAXObject WebAXObject::ChildAt(unsigned index) const {
  if (IsDetached())
    return WebAXObject();

  return WebAXObject(
      private_->ChildAtIncludingIgnored(static_cast<int>(index)));
}

WebAXObject WebAXObject::ParentObject() const {
  if (IsDetached())
    return WebAXObject();

  return WebAXObject(private_->ParentObjectIncludedInTree());
}

void WebAXObject::Serialize(ui::AXNodeData* node_data,
                            ui::AXMode accessibility_mode) const {
  if (IsDetached())
    return;

#if DCHECK_IS_ON()
  if (Node* node = private_->GetNode()) {
    Document* document = private_->GetDocument();
    DCHECK(
        !document->NeedsLayoutTreeUpdateForNodeIncludingDisplayLocked(*node) ||
        DisplayLockUtilities::LockedAncestorPreventingPaint(*node))
        << "Node needs layout update and is not display locked";
  }
#endif

  ScopedFreezeAXCache freeze(private_->AXObjectCache());
  private_->Serialize(node_data, accessibility_mode);
}

void WebAXObject::AddDirtyObjectToSerializationQueue(
    ax::mojom::blink::EventFrom event_from,
    ax::mojom::blink::Action event_from_action,
    std::vector<ui::AXEventIntent> event_intents) const {
  if (IsDetached())
    return;
  private_->AXObjectCache().AddDirtyObjectToSerializationQueue(
      private_.Get(), event_from, event_from_action, event_intents);
}

void WebAXObject::OnLoadInlineTextBoxes() const {
  if (IsDetached())
    return;

  private_->LoadInlineTextBoxes();
}

BLINK_EXPORT void WebAXObject::SetImageAsDataNodeId(
    const gfx::Size& max_size) const {
  if (IsDetached())
    return;
  private_->AXObjectCache().SetImageAsDataNodeId(private_->AXObjectID(),
                                                 max_size);
}

BLINK_EXPORT int WebAXObject::ImageDataNodeId() const {
  if (IsDetached())
    return -1;
  return private_->AXObjectCache().image_data_node_id();
}

WebString WebAXObject::AutoComplete() const {
  if (IsDetached())
    return WebString();

  return private_->AutoComplete();
}

ax::mojom::AriaCurrentState WebAXObject::AriaCurrentState() const {
  if (IsDetached())
    return ax::mojom::AriaCurrentState::kNone;

  return private_->GetAriaCurrentState();
}

ax::mojom::CheckedState WebAXObject::CheckedState() const {
  if (IsDetached())
    return ax::mojom::CheckedState::kNone;

  return private_->CheckedState();
}

bool WebAXObject::IsClickable() const {
  if (IsDetached())
    return false;

  // Filter out any action = kClickAncestor.
  // Explanation: although elements are technically clickable if an ancestor is
  // clickable, we do not expose them as such unless they have a widget role,
  // otherwise there would often be an overwhelming number of clickable nodes.
  ax::mojom::blink::DefaultActionVerb action = Action();
  return action != ax::mojom::blink::DefaultActionVerb::kNone &&
         action != ax::mojom::blink::DefaultActionVerb::kClickAncestor;
}

bool WebAXObject::IsFocused() const {
  if (IsDetached())
    return false;

  return private_->IsFocused();
}

bool WebAXObject::IsModal() const {
  if (IsDetached())
    return false;

  return private_->IsModal();
}

bool WebAXObject::IsVisited() const {
  if (IsDetached())
    return false;

  return private_->IsVisited();
}

unsigned WebAXObject::ColorValue() const {
  if (IsDetached())
    return 0;

  // RGBA32 is an alias for unsigned int.
  return private_->ColorValue();
}

WebAXObject WebAXObject::AriaActiveDescendant() const {
  if (IsDetached())
    return WebAXObject();

  return WebAXObject(private_->ActiveDescendant());
}

bool WebAXObject::IsEditable() const {
  if (IsDetached())
    return false;

  return private_->IsEditable();
}

bool WebAXObject::LiveRegionAtomic() const {
  if (IsDetached())
    return false;

  return private_->LiveRegionAtomic();
}

WebString WebAXObject::LiveRegionRelevant() const {
  if (IsDetached())
    return WebString();

  return private_->LiveRegionRelevant();
}

WebString WebAXObject::LiveRegionStatus() const {
  if (IsDetached())
    return WebString();

  return private_->LiveRegionStatus();
}

bool WebAXObject::AriaOwns(WebVector<WebAXObject>& owns_elements) const {
  // aria-owns rearranges the accessibility tree rather than just
  // exposing an attribute.

  // FIXME(dmazzoni): remove this function after we stop calling it
  // from Chromium.  http://crbug.com/489590

  return false;
}

bool WebAXObject::CanvasHasFallbackContent() const {
  if (IsDetached())
    return false;

  return private_->CanvasHasFallbackContent();
}

ax::mojom::InvalidState WebAXObject::InvalidState() const {
  if (IsDetached())
    return ax::mojom::InvalidState::kNone;

  return private_->GetInvalidState();
}

int WebAXObject::HeadingLevel() const {
  if (IsDetached())
    return 0;

  return private_->HeadingLevel();
}

int WebAXObject::HierarchicalLevel() const {
  if (IsDetached())
    return 0;

  return private_->HierarchicalLevel();
}

// FIXME: This method passes in a point that has page scale applied but assumes
// that (0, 0) is the top left of the visual viewport. In other words, the
// point has the VisualViewport scale applied, but not the VisualViewport
// offset. crbug.com/459591.
WebAXObject WebAXObject::HitTest(const gfx::Point& point) const {
  if (IsDetached()) {
    return WebAXObject();
  }

  ScopedFreezeAXCache freeze(private_->AXObjectCache());

  // If there's a popup document, hit test on that first.
  // TODO(kschmi) - move this logic to `AXObject` once crbug.com/459591
  // is fixed.
  Document* popup_document =
      private_->AXObjectCache().GetPopupDocumentIfShowing();
  if (popup_document && popup_document != private_->GetDocument()) {
    auto popup_root_obj = WebAXObject::FromWebDocument(popup_document);
    gfx::RectF popup_bounds;
    WebAXObject popup_container;
    gfx::Transform transform;
    popup_root_obj.GetRelativeBounds(popup_container, popup_bounds, transform);

    // The |popup_container| will never be set for a popup element. See
    // `AXObject::GetRelativeBounds`.
    DCHECK(popup_container.IsNull());

    WebAXObject hit_object = popup_root_obj.HitTest(
        point - ToRoundedVector2d(popup_bounds.OffsetFromOrigin()));

    // If the popup hit test succeeded, return that result.
    if (!hit_object.IsDetached()) {
      return hit_object;
    }
  }

  private_->GetDocument()->View()->CheckDoesNotNeedLayout();

  ScopedActionAnnotator annotater(private_.Get(),
                                  ax::mojom::blink::Action::kHitTest);
  gfx::Point contents_point =
      private_->DocumentFrameView()->SoonToBeRemovedUnscaledViewportToContents(
          point);

  if (AXObject* hit = private_->AccessibilityHitTest(contents_point)) {
    return WebAXObject(hit);
  }

  if (private_->GetBoundsInFrameCoordinates().Contains(
          PhysicalOffset(contents_point))) {
    return *this;
  }

  return WebAXObject();
}

gfx::Rect WebAXObject::GetBoundsInFrameCoordinates() const {
  PhysicalRect rect = private_->GetBoundsInFrameCoordinates();
  return ToEnclosingRect(rect);
}

WebString WebAXObject::Language() const {
  if (IsDetached())
    return WebString();

  return private_->Language();
}

bool WebAXObject::PerformAction(const ui::AXActionData& action_data) const {
  if (IsDetached())
    return false;

  Document* document = private_->GetDocument();
  if (!document)
    return false;

  document->View()->UpdateAllLifecyclePhasesExceptPaint(
      DocumentUpdateReason::kAccessibility);

  if (IsDetached())
    return false;  // Updating lifecycle could detach object.

  ScopedActionAnnotator annotater(private_.Get(), action_data.action);
  return private_->PerformAction(action_data);
}

WebAXObject WebAXObject::InPageLinkTarget() const {
  if (IsDetached())
    return WebAXObject();
  AXObject* target = private_->InPageLinkTarget();
  if (!target)
    return WebAXObject();
  return WebAXObject(target);
}

ax::mojom::Role WebAXObject::Role() const {
  if (IsDetached())
    return ax::mojom::Role::kUnknown;

  return private_->RoleValue();
}

static ax::mojom::TextAffinity ToAXAffinity(TextAffinity affinity) {
  switch (affinity) {
    case TextAffinity::kUpstream:
      return ax::mojom::TextAffinity::kUpstream;
    case TextAffinity::kDownstream:
      return ax::mojom::TextAffinity::kDownstream;
    default:
      NOTREACHED();
  }
}

bool WebAXObject::IsLoaded() const {
  if (IsDetached())
    return false;

  return private_->IsLoaded();
}

void WebAXObject::Selection(bool& is_selection_backward,
                            WebAXObject& anchor_object,
                            int& anchor_offset,
                            ax::mojom::TextAffinity& anchor_affinity,
                            WebAXObject& focus_object,
                            int& focus_offset,
                            ax::mojom::TextAffinity& focus_affinity) const {
  is_selection_backward = false;
  anchor_object = WebAXObject();
  anchor_offset = -1;
  anchor_affinity = ax::mojom::TextAffinity::kDownstream;
  focus_object = WebAXObject();
  focus_offset = -1;
  focus_affinity = ax::mojom::TextAffinity::kDownstream;

  if (IsDetached() || GetDocument().IsNull())
    return;

  WebAXObject focus = FromWebDocumentFocused(GetDocument());
  if (focus.IsDetached())
    return;

  const auto ax_selection =
      focus.private_->IsAtomicTextField()
          ? AXSelection::FromCurrentSelection(
                ToTextControl(*focus.private_->GetNode()))
          : AXSelection::FromCurrentSelection(*focus.private_->GetDocument());
  if (!ax_selection)
    return;

  const AXPosition ax_anchor = ax_selection.Anchor();
  anchor_object =
      WebAXObject(const_cast<AXObject*>(ax_anchor.ContainerObject()));
  const AXPosition ax_focus = ax_selection.Focus();
  focus_object = WebAXObject(const_cast<AXObject*>(ax_focus.ContainerObject()));

  is_selection_backward = ax_anchor > ax_focus;
  if (ax_anchor.IsTextPosition()) {
    anchor_offset = ax_anchor.TextOffset();
    anchor_affinity = ToAXAffinity(ax_anchor.Affinity());
  } else {
    anchor_offset = ax_anchor.ChildIndex();
  }

  if (ax_focus.IsTextPosition()) {
    focus_offset = ax_focus.TextOffset();
    focus_affinity = ToAXAffinity(ax_focus.Affinity());
  } else {
    focus_offset = ax_focus.ChildIndex();
  }
}

bool WebAXObject::SetSelection(const WebAXObject& anchor_object,
                               int anchor_offset,
                               const WebAXObject& focus_object,
                               int focus_offset) const {
  if (IsDetached() || anchor_object.IsDetached() || focus_object.IsDetached()) {
    return false;
  }

  ScopedActionAnnotator annotater(private_.Get(),
                                  ax::mojom::blink::Action::kSetSelection);
  AXPosition ax_anchor, ax_focus;
  if (static_cast<const AXObject*>(anchor_object)->IsTextObject() ||
      static_cast<const AXObject*>(anchor_object)->IsAtomicTextField()) {
    ax_anchor =
        AXPosition::CreatePositionInTextObject(*anchor_object, anchor_offset);
  } else if (anchor_offset <= 0) {
    ax_anchor = AXPosition::CreateFirstPositionInObject(*anchor_object);
  } else if (anchor_offset >= static_cast<int>(anchor_object.ChildCount())) {
    ax_anchor = AXPosition::CreateLastPositionInObject(*anchor_object);
  } else {
    DCHECK_GE(anchor_offset, 0);
    ax_anchor = AXPosition::CreatePositionBeforeObject(
        *anchor_object.ChildAt(static_cast<unsigned int>(anchor_offset)));
  }

  if (static_cast<const AXObject*>(focus_object)->IsTextObject() ||
      static_cast<const AXObject*>(focus_object)->IsAtomicTextField()) {
    ax_focus =
        AXPosition::CreatePositionInTextObject(*focus_object, focus_offset);
  } else if (focus_offset <= 0) {
    ax_focus = AXPosition::CreateFirstPositionInObject(*focus_object);
  } else if (focus_offset >= static_cast<int>(focus_object.ChildCount())) {
    ax_focus = AXPosition::CreateLastPositionInObject(*focus_object);
  } else {
    DCHECK_GE(focus_offset, 0);
    ax_focus = AXPosition::CreatePositionBeforeObject(
        *focus_object.ChildAt(static_cast<unsigned int>(focus_offset)));
  }

  AXSelection::Builder builder;
  AXSelection ax_selection =
      builder.SetAnchor(ax_anchor).SetFocus(ax_focus).Build();
  return ax_selection.Select();
}

WebString WebAXObject::GetValueForControl() const {
  if (IsDetached())
    return WebString();

  // TODO(nektar): Switch to `GetValueForControl()` once browser changes have
  // landed.
  return private_->SlowGetValueForControlIncludingContentEditable();
}

ax::mojom::blink::WritingDirection WebAXObject::GetTextDirection() const {
  if (IsDetached())
    return ax::mojom::blink::WritingDirection::kLtr;

  return private_->GetTextDirection();
}

WebURL WebAXObject::Url() const {
  if (IsDetached())
    return WebURL();

  return private_->Url();
}

WebString WebAXObject::GetName(ax::mojom::NameFrom& out_name_from,
                               WebVector<WebAXObject>& out_name_objects) const {
  out_name_from = ax::mojom::blink::NameFrom::kNone;

  if (IsDetached())
    return WebString();

  ScopedFreezeAXCache freeze(private_->AXObjectCache());

  HeapVector<Member<AXObject>> name_objects;
  WebString result = private_->GetName(out_name_from, &name_objects);

  out_name_objects.reserve(name_objects.size());
  out_name_objects.resize(name_objects.size());
  base::ranges::copy(name_objects, out_name_objects.begin());

  return result;
}

WebString WebAXObject::GetName() const {
  if (IsDetached())
    return WebString();

  ScopedFreezeAXCache freeze(private_->AXObjectCache());

  ax::mojom::NameFrom name_from;
  HeapVector<Member<AXObject>> name_objects;
  return private_->GetName(name_from, &name_objects);
}

WebString WebAXObject::Description(
    ax::mojom::NameFrom name_from,
    ax::mojom::DescriptionFrom& out_description_from,
    WebVector<WebAXObject>& out_description_objects) const {
  out_description_from = ax::mojom::blink::DescriptionFrom::kNone;

  if (IsDetached())
    return WebString();

  HeapVector<Member<AXObject>> description_objects;
  String result = private_->Description(name_from, out_description_from,
                                        &description_objects);

  out_description_objects.reserve(description_objects.size());
  out_description_objects.resize(description_objects.size());
  base::ranges::copy(description_objects, out_description_objects.begin());

  return result;
}

WebString WebAXObject::Placeholder(ax::mojom::NameFrom name_from) const {
  if (IsDetached())
    return WebString();

  return private_->Placeholder(name_from);
}

bool WebAXObject::SupportsRangeValue() const {
  if (IsDetached())
    return false;

  return private_->IsRangeValueSupported();
}

bool WebAXObject::ValueForRange(float* out_value) const {
  if (IsDetached())
    return false;

  return private_->ValueForRange(out_value);
}

bool WebAXObject::MaxValueForRange(float* out_value) const {
  if (IsDetached())
    return false;

  return private_->MaxValueForRange(out_value);
}

bool WebAXObject::MinValueForRange(float* out_value) const {
  if (IsDetached())
    return false;

  return private_->MinValueForRange(out_value);
}

bool WebAXObject::StepValueForRange(float* out_value) const {
  if (IsDetached())
    return false;

  return private_->StepValueForRange(out_value);
}

WebNode WebAXObject::GetNode() const {
  if (IsDetached())
    return WebNode();

  Node* node = private_->GetNode();
  if (!node)
    return WebNode();

  return WebNode(node);
}

WebDocument WebAXObject::GetDocument() const {
  if (IsDetached())
    return WebDocument();

  Document* document = private_->GetDocument();
  if (!document)
    return WebDocument();

  return WebDocument(document);
}

bool WebAXObject::IsIgnored() const {
  if (IsDetached())
    return false;

  return private_->IsIgnored();
}

bool WebAXObject::IsIncludedInTree() const {
  if (IsDetached())
    return false;

  DCHECK(private_->GetDocument());
  DCHECK_GE(private_->GetDocument()->Lifecycle().GetState(),
            DocumentLifecycle::kLayoutClean)
      << "Document lifecycle must be at LayoutClean or later, was "
      << private_->GetDocument()->Lifecycle().GetState();

  return private_->IsIncludedInTree();
}

unsigned WebAXObject::ColumnCount() const {
  if (IsDetached())
    return false;

  return private_->IsTableLikeRole() ? private_->ColumnCount() : 0;
}

unsigned WebAXObject::RowCount() const {
  if (IsDetached())
    return 0;

  if (!private_->IsTableLikeRole())
    return 0;

  return private_->RowCount();
}

WebAXObject WebAXObject::CellForColumnAndRow(unsigned column,
                                             unsigned row) const {
  if (IsDetached())
    return WebAXObject();

  if (!private_->IsTableLikeRole())
    return WebAXObject();

  return WebAXObject(private_->CellForColumnAndRow(column, row));
}

void WebAXObject::RowHeaders(
    WebVector<WebAXObject>& row_header_elements) const {
  if (IsDetached())
    return;

  if (!private_->IsTableLikeRole())
    return;

  AXObject::AXObjectVector headers;
  private_->RowHeaders(headers);
  row_header_elements.reserve(headers.size());
  row_header_elements.resize(headers.size());
  base::ranges::copy(headers, row_header_elements.begin());
}

void WebAXObject::ColumnHeaders(
    WebVector<WebAXObject>& column_header_elements) const {
  if (IsDetached())
    return;

  if (!private_->IsTableLikeRole())
    return;

  AXObject::AXObjectVector headers;
  private_->ColumnHeaders(headers);
  column_header_elements.reserve(headers.size());
  column_header_elements.resize(headers.size());
  base::ranges::copy(headers, column_header_elements.begin());
}

unsigned WebAXObject::CellColumnIndex() const {
  if (IsDetached())
    return 0;

  return private_->IsTableCellLikeRole() ? private_->ColumnIndex() : 0;
}

unsigned WebAXObject::CellColumnSpan() const {
  if (IsDetached())
    return 0;

  return private_->IsTableCellLikeRole() ? private_->ColumnSpan() : 0;
}

unsigned WebAXObject::CellRowIndex() const {
  if (IsDetached())
    return 0;

  return private_->IsTableCellLikeRole() ? private_->RowIndex() : 0;
}

unsigned WebAXObject::CellRowSpan() const {
  if (IsDetached())
    return 0;

  return private_->IsTableCellLikeRole() ? private_->RowSpan() : 0;
}

ax::mojom::SortDirection WebAXObject::SortDirection() const {
  if (IsDetached())
    return ax::mojom::SortDirection::kNone;

  return private_->GetSortDirection();
}

WebAXObject WebAXObject::NextOnLine() const {
  if (IsDetached())
    return WebAXObject();

  ScopedFreezeAXCache freeze(private_->AXObjectCache());
  // Force computation of next/previous on line data, since this API may call
  // serializations outside of the regular flow. AXObjectCacheImpl may not had
  // the chance to compute next|previous on line data. Clear the cache and force
  // the computation.
  private_->AXObjectCache().ClearCachedNodesOnLine();
  private_->AXObjectCache().ComputeNodesOnLine(private_->GetLayoutObject());
  return WebAXObject(private_.Get()->NextOnLine());
}

WebAXObject WebAXObject::PreviousOnLine() const {
  if (IsDetached())
    return WebAXObject();

  ScopedFreezeAXCache freeze(private_->AXObjectCache());
  // Force computation of next/previous on line data, since this API may call
  // serializations outside of the regular flow. AXObjectCacheImpl may not had
  // the chance to compute next|previous on line data. Clear the cache and force
  // the computation.
  private_->AXObjectCache().ClearCachedNodesOnLine();
  private_->AXObjectCache().ComputeNodesOnLine(private_->GetLayoutObject());
  return WebAXObject(private_.Get()->PreviousOnLine());
}

void WebAXObject::CharacterOffsets(WebVector<int>& offsets) const {
  if (IsDetached())
    return;

  Vector<int> offsets_vector;
  private_->TextCharacterOffsets(offsets_vector);
  offsets = offsets_vector;
}

void WebAXObject::GetWordBoundaries(WebVector<int>& starts,
                                    WebVector<int>& ends) const {
  if (IsDetached())
    return;

  Vector<int> src_starts;
  Vector<int> src_ends;
  private_->GetWordBoundaries(src_starts, src_ends);
  DCHECK_EQ(src_starts.size(), src_ends.size());

  WebVector<int> word_start_offsets(src_starts.size());
  WebVector<int> word_end_offsets(src_ends.size());
  for (wtf_size_t i = 0; i < src_starts.size(); ++i) {
    word_start_offsets[i] = src_starts[i];
    word_end_offsets[i] = src_ends[i];
  }

  starts.swap(word_start_offsets);
  ends.swap(word_end_offsets);
}

gfx::Point WebAXObject::GetScrollOffset() const {
  if (IsDetached())
    return gfx::Point();

  return private_->GetScrollOffset();
}

gfx::Point WebAXObject::MinimumScrollOffset() const {
  if (IsDetached())
    return gfx::Point();

  return private_->MinimumScrollOffset();
}

gfx::Point WebAXObject::MaximumScrollOffset() const {
  if (IsDetached())
    return gfx::Point();

  return private_->MaximumScrollOffset();
}

void WebAXObject::SetScrollOffset(const gfx::Point& offset) const {
  if (IsDetached())
    return;

  private_->SetScrollOffset(offset);
}

void WebAXObject::GetRelativeBounds(WebAXObject& offset_container,
                                    gfx::RectF& bounds_in_container,
                                    gfx::Transform& container_transform,
                                    bool* clips_children) const {
  if (IsDetached())
    return;

#if DCHECK_IS_ON()
  CheckLayoutClean(private_->GetDocument());
#endif

  AXObject* container = nullptr;
  gfx::RectF bounds;
  private_->GetRelativeBounds(&container, bounds, container_transform,
                              clips_children);
  offset_container = WebAXObject(container);
  bounds_in_container = bounds;
}

bool WebAXObject::ScrollToMakeVisible() const {
  if (IsDetached())
    return false;

  ScopedActionAnnotator annotater(
      private_.Get(), ax::mojom::blink::Action::kScrollToMakeVisible);
  ui::AXActionData action_data;
  action_data.action = ax::mojom::blink::Action::kScrollToMakeVisible;
  return private_->PerformAction(action_data);
}

bool WebAXObject::ScrollToMakeVisibleWithSubFocus(
    const gfx::Rect& subfocus,
    ax::mojom::ScrollAlignment horizontal_scroll_alignment,
    ax::mojom::ScrollAlignment vertical_scroll_alignment,
    ax::mojom::ScrollBehavior scroll_behavior) const {
  if (IsDetached())
    return false;

  ScopedActionAnnotator annotater(
      private_.Get(), ax::mojom::blink::Action::kScrollToMakeVisible);
  auto horizontal_behavior =
      ToBlinkScrollAlignmentBehavior(horizontal_scroll_alignment);
  auto vertical_behavior =
      ToBlinkScrollAlignmentBehavior(vertical_scroll_alignment);

  mojom::blink::ScrollAlignment::Behavior visible_horizontal_behavior =
      scroll_behavior == ax::mojom::ScrollBehavior::kScrollIfVisible
          ? horizontal_behavior
          : mojom::blink::ScrollAlignment::Behavior::kNoScroll;
  mojom::blink::ScrollAlignment::Behavior visible_vertical_behavior =
      scroll_behavior == ax::mojom::ScrollBehavior::kScrollIfVisible
          ? vertical_behavior
          : mojom::blink::ScrollAlignment::Behavior::kNoScroll;

  blink::mojom::blink::ScrollAlignment blink_horizontal_scroll_alignment = {
      visible_horizontal_behavior, horizontal_behavior, horizontal_behavior};
  blink::mojom::blink::ScrollAlignment blink_vertical_scroll_alignment = {
      visible_vertical_behavior, vertical_behavior, vertical_behavior};

  return private_->RequestScrollToMakeVisibleWithSubFocusAction(
      subfocus, blink_horizontal_scroll_alignment,
      blink_vertical_scroll_alignment);
}

void WebAXObject::HandleAutofillSuggestionAvailabilityChanged(
    blink::WebAXAutofillSuggestionAvailability suggestion_availability) const {
  if (IsDetached() || !private_->GetLayoutObject()) {
    return;
  }

  private_->HandleAutofillSuggestionAvailabilityChanged(
      suggestion_availability);
}

int WebAXObject::GenerateAXID() {
  DCHECK(private_->GetDocument() && private_->GetDocument()->IsActive());
  return private_->AXObjectCache().GenerateAXID();
}

void WebAXObject::SetPluginTreeSource(
    ui::AXTreeSource<const ui::AXNode*, ui::AXTreeData*, ui::AXNodeData>*
        source) {
  private_->AXObjectCache().SetPluginTreeSource(source);
}

void WebAXObject::MarkPluginDescendantDirty(ui::AXNodeID node_id) {
  private_->AXObjectCache().MarkPluginDescendantDirty(node_id);
}

WebString WebAXObject::ToString(bool verbose) const {
  if (private_.IsNull())
    return WebString("[Null]");

  return private_->ToString(verbose);
}

WebAXObject::WebAXObject(AXObject* object) : private_(object) {}

WebAXObject& WebAXObject::operator=(AXObject* object) {
  private_ = object;
  return *this;
}

bool WebAXObject::operator==(const WebAXObject& other) const {
  if (IsDetached() || other.IsDetached())
    return false;
  return *private_ == *other.private_;
}

bool WebAXObject::operator!=(const WebAXObject& other) const {
  if (IsDetached() || other.IsDetached())
    return false;
  return *private_ != *other.private_;
}

bool WebAXObject::operator<(const WebAXObject& other) const {
  if (IsDetached() || other.IsDetached())
    return false;
  return *private_ < *other.private_;
}

bool WebAXObject::operator<=(const WebAXObject& other) const {
  if (IsDetached() || other.IsDetached())
    return false;
  return *private_ <= *other.private_;
}

bool WebAXObject::operator>(const WebAXObject& other) const {
  if (IsDetached() || other.IsDetached())
    return false;
  return *private_ > *other.private_;
}

bool WebAXObject::operator>=(const WebAXObject& other) const {
  if (IsDetached() || other.IsDetached())
    return false;
  return *private_ >= *other.private_;
}

WebAXObject::operator AXObject*() const {
  return pri
```