Response:
The user wants to understand the functionality of the provided C++ code snippet from the Chromium Blink engine. This file seems to be related to the "Inspector DOM Agent". I need to:

1. **Identify the primary purpose of `InspectorDOMAgent`**: Based on the name and included headers, it's highly likely that this class handles communication between the browser's rendering engine and the developer tools (DevTools) regarding the Document Object Model (DOM).

2. **List specific functionalities**: Go through the code and identify key methods and data structures that reveal its capabilities. Look for actions like getting/setting DOM properties, handling events, interacting with the DevTools protocol, etc.

3. **Relate to Javascript, HTML, CSS**:  Since the DOM represents HTML structure and CSS styling, any interaction with the DOM will inherently involve these technologies. I need to find specific examples in the code that demonstrate this connection.

4. **Logical Reasoning (Input/Output)**:  For some of the core functions, I can hypothesize what kind of input they would receive and what the expected output would be based on the method names and parameters.

5. **Common Usage Errors**: Think about how developers using the DevTools might interact with the functionalities provided by this agent and what mistakes they could make.

6. **Summarize the functionality of this first part**: Condense the findings into a concise summary.
这是 `blink/renderer/core/inspector/inspector_dom_agent.cc` 文件的第一部分，主要功能是**负责将渲染引擎的 DOM 结构暴露给开发者工具 (DevTools) 的 DOM 面板，并处理来自 DevTools 的关于 DOM 的请求**。

以下是根据代码内容归纳出的更具体的功能点，并结合了与 JavaScript、HTML、CSS 的关系，逻辑推理以及可能的用户错误：

**核心功能：**

* **DOM 树的表示和同步：**
    * **维护节点 ID 映射 (`document_node_to_id_map_`, `id_to_node_`, `id_to_nodes_map_`)：**  为 DOM 树中的每个节点分配一个唯一的 ID，并在内部维护 ID 和节点之间的映射关系。这使得 DevTools 可以通过 ID 来引用和操作特定的 DOM 节点。
    * **构建 DOM 节点对象 (例如 `BuildObjectForNode`)：**  将渲染引擎内部的 DOM 节点信息转换为符合 DevTools 协议的数据结构，以便发送到前端。
    * **推送子节点信息到前端 (`PushChildNodesToFrontend`)：**  当 DevTools 请求某个节点的子节点时，将这些子节点的详细信息发送到前端。
    * **处理文档更新事件：**  当文档加载完成或发生变化时，通知 DevTools (`GetFrontend()->documentUpdated()`)。
    * **处理节点添加和移除事件：**  通过 `NotifyDidAddDocument` 和 `NotifyWillRemoveDOMNode` 通知监听器（通常是 DevTools 前端）DOM 结构的变化。

* **处理 DevTools 的 DOM 操作请求：**
    * **启用和禁用 DOM 代理 (`enable`, `disable`)：**  控制 DOM 代理是否处于活动状态。
    * **获取完整文档树 (`getDocument`)：**  将整个或部分 DOM 树发送到 DevTools。
    * **按样式查找节点 (`getNodesForSubtreeByStyle`)：**  根据 CSS 属性值查找匹配的节点。
    * **获取扁平化的文档树 (`getFlattenedDocument`)：**  以扁平化的形式返回 DOM 树。
    * **请求子节点 (`requestChildNodes`)：**  请求指定节点的子节点信息。
    * **根据 CSS 选择器查询节点 (`querySelector`, `querySelectorAll`)：**  允许 DevTools 使用 CSS 选择器在指定的节点下查找元素。
    * **获取顶层元素 (`getTopLayerElements`)：** 获取诸如全屏元素或画中画元素等顶层元素。
    * **收集子树中的类名 (`collectClassNamesFromSubtree`)：** 获取指定节点及其子树中所有元素的 class 属性值。

* **节点查找和断言：**
    * **通过 ID 获取节点 (`NodeForId`)：**  根据节点 ID 查找对应的 DOM 节点。
    * **断言节点存在性 (`AssertNode`)：**  验证给定的节点 ID 是否有效，并返回对应的节点。
    * **断言节点可编辑性 (`AssertEditableNode`, `AssertEditableChildNode`, `AssertEditableElement`)：**  检查节点是否可以被编辑，例如排除 Shadow DOM 中的节点或伪元素。

* **与其他 Inspector 模块交互：**
    * **与 CSS 代理 (`InspectorCSSAgent`) 交互：**  虽然代码中没有直接调用 `InspectorCSSAgent` 的方法，但它使用了 CSS 相关的类，例如 `CSSComputedStyleDeclaration`，表明它与 CSS 代理存在关联，可能用于获取或修改样式信息。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

* **HTML：** `InspectorDOMAgent` 的核心职责是表示和操作 HTML 结构。
    * **举例：** `getDocument` 方法会将 HTML 标签、属性等信息转换成 DevTools 可以理解的格式发送过去。  例如，一个 `<div>` 元素会被表示为一个包含 `tagName: "div"` 等属性的对象。
* **CSS：**  `InspectorDOMAgent` 允许根据 CSS 样式查找节点，并且在表示节点信息时会包含一些 CSS 相关的信息。
    * **举例：** `getNodesForSubtreeByStyle` 方法允许 DevTools 根据特定的 CSS 属性值（例如 `color: red`）查找所有匹配的元素。
* **JavaScript：**  DevTools 前端是用 JavaScript 编写的，它通过 Inspector 协议与后端通信。  `InspectorDOMAgent` 接收来自 JavaScript 前端的请求，并返回 JavaScript 可以解析的数据。
    * **举例：** 当你在 DevTools 的 Elements 面板中点击一个元素时，前端 JavaScript 代码会调用 Inspector API，最终触发 `InspectorDOMAgent` 中的方法来获取该元素的详细信息。

**逻辑推理 (假设输入与输出)：**

* **假设输入：** DevTools 请求 `node_id = 10` 的子节点，且 `depth = 2`。
* **预期输出：** `PushChildNodesToFrontend(10, 2, false)` 会被调用，该方法会查找 ID 为 10 的节点，并将其直接子节点以及孙子节点的信息构建成一个 `protocol::Array<protocol::DOM::Node>` 对象，并发送到 DevTools 前端。

* **假设输入：** DevTools 调用 `querySelector(5, ".my-class")`。
* **预期输出：**  `InspectorDOMAgent` 会找到 ID 为 5 的节点，并使用 CSS 选择器 `.my-class` 在该节点下执行查询。如果找到匹配的元素，则将其 ID 返回给 DevTools 前端。

**用户或编程常见的使用错误：**

* **错误的节点 ID：** DevTools 前端可能由于某些原因（例如缓存问题）使用了过期的或错误的节点 ID 来请求信息，导致 `AssertNode` 等方法返回错误。
* **请求编辑不可编辑的节点：**  尝试修改 Shadow DOM 的内部节点或伪元素会导致 `AssertEditableNode` 等方法返回错误，因为这些节点通常不允许直接编辑。
* **CSS 选择器错误：**  在 `querySelector` 或 `querySelectorAll` 中使用了无效的 CSS 选择器，会导致异常或无法找到预期的元素。

**本部分功能总结：**

总而言之，这部分代码定义了 `InspectorDOMAgent` 类的核心功能，使其能够作为渲染引擎 DOM 和 DevTools 之间沟通的桥梁。它负责维护 DOM 树的表示，处理来自 DevTools 的查询和操作请求，并确保这些操作的有效性和安全性。  它与 HTML、CSS 和 JavaScript 紧密相关，因为它的目标就是将这些 Web 技术构建的页面结构暴露给开发者进行调试和分析。

Prompt: 
```
这是目录为blink/renderer/core/inspector/inspector_dom_agent.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共4部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2009 Apple Inc. All rights reserved.
 * Copyright (C) 2011 Google Inc. All rights reserved.
 * Copyright (C) 2009 Joseph Pecoraro
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 * 3.  Neither the name of Apple Computer, Inc. ("Apple") nor the names of
 *     its contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE AND ITS CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL APPLE OR ITS CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/inspector/inspector_dom_agent.h"

#include <memory>

#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/bindings/core/v8/binding_security.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_file.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_html_document.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_node.h"
#include "third_party/blink/renderer/core/css/css_computed_style_declaration.h"
#include "third_party/blink/renderer/core/css/css_container_rule.h"
#include "third_party/blink/renderer/core/css/css_property_name.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/dom/attr.h"
#include "third_party/blink/renderer/core/dom/character_data.h"
#include "third_party/blink/renderer/core/dom/container_node.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/document_fragment.h"
#include "third_party/blink/renderer/core/dom/document_type.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/dom/dom_node_ids.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/flat_tree_traversal.h"
#include "third_party/blink/renderer/core/dom/focus_params.h"
#include "third_party/blink/renderer/core/dom/layout_tree_builder_traversal.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/dom/pseudo_element.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/dom/static_node_list.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/dom/xml_document.h"
#include "third_party/blink/renderer/core/editing/serializers/serialization.h"
#include "third_party/blink/renderer/core/fileapi/file.h"
#include "third_party/blink/renderer/core/frame/frame.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/location.h"
#include "third_party/blink/renderer/core/frame/remote_frame.h"
#include "third_party/blink/renderer/core/html/fenced_frame/document_fenced_frames.h"
#include "third_party/blink/renderer/core/html/fenced_frame/html_fenced_frame_element.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/html_document.h"
#include "third_party/blink/renderer/core/html/html_frame_owner_element.h"
#include "third_party/blink/renderer/core/html/html_link_element.h"
#include "third_party/blink/renderer/core/html/html_slot_element.h"
#include "third_party/blink/renderer/core/html/html_template_element.h"
#include "third_party/blink/renderer/core/input_type_names.h"
#include "third_party/blink/renderer/core/inspector/dom_editor.h"
#include "third_party/blink/renderer/core/inspector/dom_patch_support.h"
#include "third_party/blink/renderer/core/inspector/identifiers_factory.h"
#include "third_party/blink/renderer/core/inspector/inspected_frames.h"
#include "third_party/blink/renderer/core/inspector/inspector_css_agent.h"
#include "third_party/blink/renderer/core/inspector/inspector_highlight.h"
#include "third_party/blink/renderer/core/inspector/inspector_history.h"
#include "third_party/blink/renderer/core/inspector/resolve_node.h"
#include "third_party/blink/renderer/core/inspector/v8_inspector_string.h"
#include "third_party/blink/renderer/core/layout/hit_test_location.h"
#include "third_party/blink/renderer/core/layout/hit_test_result.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/layout/layout_inline.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/page/frame_tree.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/scroll/scroll_alignment.h"
#include "third_party/blink/renderer/core/scroll/scroll_into_view_util.h"
#include "third_party/blink/renderer/core/style/computed_style_constants.h"
#include "third_party/blink/renderer/core/svg/svg_svg_element.h"
#include "third_party/blink/renderer/core/view_transition/view_transition_utils.h"
#include "third_party/blink/renderer/core/xml/document_xpath_evaluator.h"
#include "third_party/blink/renderer/core/xml/xpath_result.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/graphics/color.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

using mojom::blink::FormControlType;
using protocol::Maybe;

namespace {

const size_t kMaxTextSize = 10000;
const UChar kEllipsisUChar[] = {0x2026, 0};

template <typename Functor>
void ForEachSupportedPseudo(const Element* element, Functor& func) {
  for (PseudoId pseudo_id :
       {kPseudoIdCheck, kPseudoIdBefore, kPseudoIdAfter, kPseudoIdSelectArrow,
        kPseudoIdMarker, kPseudoIdBackdrop}) {
    if (!PseudoElement::IsWebExposed(pseudo_id, element))
      continue;
    if (PseudoElement* pseudo_element = element->GetPseudoElement(pseudo_id))
      func(pseudo_element);
  }
  ViewTransitionUtils::ForEachDirectTransitionPseudo(element, func);
}

}  // namespace

class InspectorRevalidateDOMTask final
    : public GarbageCollected<InspectorRevalidateDOMTask> {
 public:
  explicit InspectorRevalidateDOMTask(InspectorDOMAgent*);
  void ScheduleStyleAttrRevalidationFor(Element*);
  void Reset() { timer_.Stop(); }
  void OnTimer(TimerBase*);
  void Trace(Visitor*) const;

 private:
  Member<InspectorDOMAgent> dom_agent_;
  HeapTaskRunnerTimer<InspectorRevalidateDOMTask> timer_;
  HeapHashSet<Member<Element>> style_attr_invalidated_elements_;
};

InspectorRevalidateDOMTask::InspectorRevalidateDOMTask(
    InspectorDOMAgent* dom_agent)
    : dom_agent_(dom_agent),
      timer_(
          dom_agent->GetDocument()->GetTaskRunner(TaskType::kDOMManipulation),
          this,
          &InspectorRevalidateDOMTask::OnTimer) {}

void InspectorRevalidateDOMTask::ScheduleStyleAttrRevalidationFor(
    Element* element) {
  style_attr_invalidated_elements_.insert(element);
  if (!timer_.IsActive())
    timer_.StartOneShot(base::TimeDelta(), FROM_HERE);
}

void InspectorRevalidateDOMTask::OnTimer(TimerBase*) {
  // The timer is stopped on m_domAgent destruction, so this method will never
  // be called after m_domAgent has been destroyed.
  HeapVector<Member<Element>> elements;
  for (auto& attribute : style_attr_invalidated_elements_)
    elements.push_back(attribute.Get());
  dom_agent_->StyleAttributeInvalidated(elements);
  style_attr_invalidated_elements_.clear();
}

void InspectorRevalidateDOMTask::Trace(Visitor* visitor) const {
  visitor->Trace(dom_agent_);
  visitor->Trace(style_attr_invalidated_elements_);
  visitor->Trace(timer_);
}

protocol::Response InspectorDOMAgent::ToResponse(
    DummyExceptionStateForTesting& exception_state) {
  if (exception_state.HadException()) {
    String name_prefix = IsDOMExceptionCode(exception_state.Code())
                             ? DOMException::GetErrorName(
                                   exception_state.CodeAs<DOMExceptionCode>()) +
                                   " "
                             : g_empty_string;
    String msg = name_prefix + exception_state.Message();
    return protocol::Response::ServerError(msg.Utf8());
  }
  return protocol::Response::Success();
}

protocol::DOM::PseudoType InspectorDOMAgent::ProtocolPseudoElementType(
    PseudoId pseudo_id) {
  switch (pseudo_id) {
    case kPseudoIdFirstLine:
      return protocol::DOM::PseudoTypeEnum::FirstLine;
    case kPseudoIdFirstLetter:
      return protocol::DOM::PseudoTypeEnum::FirstLetter;
    case kPseudoIdCheck:
      return protocol::DOM::PseudoTypeEnum::Check;
    case kPseudoIdBefore:
      return protocol::DOM::PseudoTypeEnum::Before;
    case kPseudoIdAfter:
      return protocol::DOM::PseudoTypeEnum::After;
    case kPseudoIdSelectArrow:
      return protocol::DOM::PseudoTypeEnum::SelectArrow;
    case kPseudoIdMarker:
      return protocol::DOM::PseudoTypeEnum::Marker;
    case kPseudoIdBackdrop:
      return protocol::DOM::PseudoTypeEnum::Backdrop;
    case kPseudoIdSelection:
      return protocol::DOM::PseudoTypeEnum::Selection;
    case kPseudoIdSearchText:
      return protocol::DOM::PseudoTypeEnum::SearchText;
    case kPseudoIdTargetText:
      return protocol::DOM::PseudoTypeEnum::TargetText;
    case kPseudoIdSpellingError:
      return protocol::DOM::PseudoTypeEnum::SpellingError;
    case kPseudoIdGrammarError:
      return protocol::DOM::PseudoTypeEnum::GrammarError;
    case kPseudoIdHighlight:
      return protocol::DOM::PseudoTypeEnum::Highlight;
    case kPseudoIdFirstLineInherited:
      return protocol::DOM::PseudoTypeEnum::FirstLineInherited;
    case kPseudoIdScrollbar:
      return protocol::DOM::PseudoTypeEnum::Scrollbar;
    case kPseudoIdScrollbarThumb:
      return protocol::DOM::PseudoTypeEnum::ScrollbarThumb;
    case kPseudoIdScrollbarButton:
      return protocol::DOM::PseudoTypeEnum::ScrollbarButton;
    case kPseudoIdScrollbarTrack:
      return protocol::DOM::PseudoTypeEnum::ScrollbarTrack;
    case kPseudoIdScrollbarTrackPiece:
      return protocol::DOM::PseudoTypeEnum::ScrollbarTrackPiece;
    case kPseudoIdScrollbarCorner:
      return protocol::DOM::PseudoTypeEnum::ScrollbarCorner;
    case kPseudoIdScrollMarker:
      return protocol::DOM::PseudoTypeEnum::ScrollMarker;
    case kPseudoIdScrollMarkerGroup:
    case kPseudoIdScrollMarkerGroupAfter:
    case kPseudoIdScrollMarkerGroupBefore:
      return protocol::DOM::PseudoTypeEnum::ScrollMarkerGroup;
    case kPseudoIdScrollNextButton:
      return protocol::DOM::PseudoTypeEnum::ScrollNextButton;
    case kPseudoIdScrollPrevButton:
      return protocol::DOM::PseudoTypeEnum::ScrollPrevButton;
    case kPseudoIdColumn:
      return protocol::DOM::PseudoTypeEnum::Column;
    case kPseudoIdResizer:
      return protocol::DOM::PseudoTypeEnum::Resizer;
    case kPseudoIdInputListButton:
      return protocol::DOM::PseudoTypeEnum::InputListButton;
    case kPseudoIdPlaceholder:
      return protocol::DOM::PseudoTypeEnum::Placeholder;
    case kPseudoIdFileSelectorButton:
      return protocol::DOM::PseudoTypeEnum::FileSelectorButton;
    case kPseudoIdDetailsContent:
      return protocol::DOM::PseudoTypeEnum::DetailsContent;
    case kPseudoIdPickerSelect:
      return protocol::DOM::PseudoTypeEnum::Picker;
    case kPseudoIdViewTransition:
      return protocol::DOM::PseudoTypeEnum::ViewTransition;
    case kPseudoIdViewTransitionGroup:
      return protocol::DOM::PseudoTypeEnum::ViewTransitionGroup;
    case kPseudoIdViewTransitionImagePair:
      return protocol::DOM::PseudoTypeEnum::ViewTransitionImagePair;
    case kPseudoIdViewTransitionNew:
      return protocol::DOM::PseudoTypeEnum::ViewTransitionNew;
    case kPseudoIdViewTransitionOld:
      return protocol::DOM::PseudoTypeEnum::ViewTransitionOld;
    case kAfterLastInternalPseudoId:
    case kPseudoIdNone:
    case kPseudoIdInvalid:
      CHECK(false);
      return "";
  }
}

InspectorDOMAgent::InspectorDOMAgent(
    v8::Isolate* isolate,
    InspectedFrames* inspected_frames,
    v8_inspector::V8InspectorSession* v8_session)
    : isolate_(isolate),
      inspected_frames_(inspected_frames),
      v8_session_(v8_session),
      document_node_to_id_map_(MakeGarbageCollected<NodeToIdMap>()),
      last_node_id_(1),
      suppress_attribute_modified_event_(false),
      enabled_(&agent_state_, /*default_value=*/false),
      include_whitespace_(&agent_state_,
                          /*default_value=*/static_cast<int32_t>(
                              InspectorDOMAgent::IncludeWhitespaceEnum::NONE)),
      capture_node_stack_traces_(&agent_state_, /*default_value=*/false) {}

InspectorDOMAgent::~InspectorDOMAgent() = default;

void InspectorDOMAgent::Restore() {
  if (enabled_.Get())
    EnableAndReset();
}

HeapVector<Member<Document>> InspectorDOMAgent::Documents() {
  HeapVector<Member<Document>> result;
  if (document_) {
    for (LocalFrame* frame : *inspected_frames_) {
      if (Document* document = frame->GetDocument())
        result.push_back(document);
    }
  }
  return result;
}

void InspectorDOMAgent::AddDOMListener(DOMListener* listener) {
  dom_listeners_.insert(listener);
}

void InspectorDOMAgent::RemoveDOMListener(DOMListener* listener) {
  dom_listeners_.erase(listener);
}

void InspectorDOMAgent::NotifyDidAddDocument(Document* document) {
  for (DOMListener* listener : dom_listeners_)
    listener->DidAddDocument(document);
}

void InspectorDOMAgent::NotifyWillRemoveDOMNode(Node* node) {
  for (DOMListener* listener : dom_listeners_)
    listener->WillRemoveDOMNode(node);
}

void InspectorDOMAgent::NotifyDidModifyDOMAttr(Element* element) {
  for (DOMListener* listener : dom_listeners_)
    listener->DidModifyDOMAttr(element);
}

void InspectorDOMAgent::SetDocument(Document* doc) {
  if (doc == document_.Get())
    return;

  DiscardFrontendBindings();
  document_ = doc;

  if (!enabled_.Get())
    return;

  // Immediately communicate 0 document or document that has finished loading.
  if (!doc || !doc->Parsing())
    GetFrontend()->documentUpdated();
}

bool InspectorDOMAgent::Enabled() const {
  return enabled_.Get();
}

InspectorDOMAgent::IncludeWhitespaceEnum InspectorDOMAgent::IncludeWhitespace()
    const {
  return static_cast<InspectorDOMAgent::IncludeWhitespaceEnum>(
      include_whitespace_.Get());
}

void InspectorDOMAgent::ReleaseDanglingNodes() {
  dangling_node_to_id_maps_.clear();
}

int InspectorDOMAgent::Bind(Node* node, NodeToIdMap* nodes_map) {
  if (!nodes_map)
    return 0;
  auto it = nodes_map->find(node);
  if (it != nodes_map->end())
    return it->value;

  int id = last_node_id_++;
  nodes_map->Set(node, id);
  id_to_node_.Set(id, node);
  id_to_nodes_map_.Set(id, nodes_map);
  return id;
}

void InspectorDOMAgent::Unbind(Node* node) {
  int id = BoundNodeId(node);
  if (!id)
    return;

  id_to_node_.erase(id);
  id_to_nodes_map_.erase(id);

  if (auto* frame_owner = DynamicTo<HTMLFrameOwnerElement>(node)) {
    Document* content_document = frame_owner->contentDocument();
    if (content_document)
      Unbind(content_document);
  }

  if (ShadowRoot* root = node->GetShadowRoot())
    Unbind(root);

  auto* element = DynamicTo<Element>(node);
  if (element) {
    auto unbind_pseudo = [&](PseudoElement* pseudo_element) {
      Unbind(pseudo_element);
    };
    ForEachSupportedPseudo(element, unbind_pseudo);
  }

  NotifyWillRemoveDOMNode(node);
  document_node_to_id_map_->erase(node);

  bool children_requested = children_requested_.Contains(id);
  if (children_requested) {
    // Unbind subtree known to client recursively.
    children_requested_.erase(id);
    InspectorDOMAgent::IncludeWhitespaceEnum include_whitespace =
        IncludeWhitespace();
    Node* child = InnerFirstChild(node, include_whitespace);
    while (child) {
      Unbind(child);
      child = InnerNextSibling(child, include_whitespace);
    }
  }
  cached_child_count_.erase(id);
}

protocol::Response InspectorDOMAgent::AssertNode(int node_id, Node*& node) {
  node = NodeForId(node_id);
  if (!node)
    return protocol::Response::ServerError("Could not find node with given id");
  return protocol::Response::Success();
}

protocol::Response InspectorDOMAgent::AssertNode(
    const protocol::Maybe<int>& node_id,
    const protocol::Maybe<int>& backend_node_id,
    const protocol::Maybe<String>& object_id,
    Node*& node) {
  if (node_id.has_value()) {
    return AssertNode(node_id.value(), node);
  }

  if (backend_node_id.has_value()) {
    node = DOMNodeIds::NodeForId(backend_node_id.value());
    return !node ? protocol::Response::ServerError(
                       "No node found for given backend id")
                 : protocol::Response::Success();
  }

  if (object_id.has_value()) {
    return NodeForRemoteObjectId(object_id.value(), node);
  }

  return protocol::Response::ServerError(
      "Either nodeId, backendNodeId or objectId must be specified");
}

protocol::Response InspectorDOMAgent::AssertElement(int node_id,
                                                    Element*& element) {
  Node* node = nullptr;
  protocol::Response response = AssertNode(node_id, node);
  if (!response.IsSuccess())
    return response;

  element = DynamicTo<Element>(node);
  if (!element)
    return protocol::Response::ServerError("Node is not an Element");
  return protocol::Response::Success();
}

// static
ShadowRoot* InspectorDOMAgent::UserAgentShadowRoot(Node* node) {
  if (!node || !node->IsInShadowTree())
    return nullptr;

  Node* candidate = node;
  while (candidate && !IsA<ShadowRoot>(candidate))
    candidate = candidate->ParentOrShadowHostNode();
  DCHECK(candidate);
  ShadowRoot* shadow_root = To<ShadowRoot>(candidate);

  return shadow_root->IsUserAgent() ? shadow_root : nullptr;
}

protocol::Response InspectorDOMAgent::AssertEditableNode(int node_id,
                                                         Node*& node) {
  protocol::Response response = AssertNode(node_id, node);
  if (!response.IsSuccess())
    return response;

  if (node->IsInShadowTree()) {
    if (IsA<ShadowRoot>(node))
      return protocol::Response::ServerError("Cannot edit shadow roots");
    if (UserAgentShadowRoot(node)) {
      return protocol::Response::ServerError(
          "Cannot edit nodes from user-agent shadow trees");
    }
  }

  if (node->IsPseudoElement())
    return protocol::Response::ServerError("Cannot edit pseudo elements");
  return protocol::Response::Success();
}

protocol::Response InspectorDOMAgent::AssertEditableChildNode(
    Element* parent_element,
    int node_id,
    Node*& node) {
  protocol::Response response = AssertEditableNode(node_id, node);
  if (!response.IsSuccess())
    return response;
  if (node->parentNode() != parent_element) {
    return protocol::Response::ServerError(
        "Anchor node must be child of the target element");
  }
  return protocol::Response::Success();
}

protocol::Response InspectorDOMAgent::AssertEditableElement(int node_id,
                                                            Element*& element) {
  protocol::Response response = AssertElement(node_id, element);
  if (!response.IsSuccess())
    return response;
  if (element->IsInShadowTree() && UserAgentShadowRoot(element)) {
    return protocol::Response::ServerError(
        "Cannot edit elements from user-agent shadow trees");
  }
  if (element->IsPseudoElement())
    return protocol::Response::ServerError("Cannot edit pseudo elements");

  return protocol::Response::Success();
}

void InspectorDOMAgent::EnableAndReset() {
  enabled_.Set(true);
  history_ = MakeGarbageCollected<InspectorHistory>();
  dom_editor_ = MakeGarbageCollected<DOMEditor>(history_.Get());
  document_ = inspected_frames_->Root()->GetDocument();
  instrumenting_agents_->AddInspectorDOMAgent(this);
}

protocol::Response InspectorDOMAgent::enable(Maybe<String> includeWhitespace) {
  if (!enabled_.Get()) {
    EnableAndReset();
    include_whitespace_.Set(static_cast<int32_t>(
        includeWhitespace.value_or(
            protocol::DOM::Enable::IncludeWhitespaceEnum::None) ==
                protocol::DOM::Enable::IncludeWhitespaceEnum::All
            ? InspectorDOMAgent::IncludeWhitespaceEnum::ALL
            : InspectorDOMAgent::IncludeWhitespaceEnum::NONE));
  }
  return protocol::Response::Success();
}

protocol::Response InspectorDOMAgent::disable() {
  if (!enabled_.Get())
    return protocol::Response::ServerError("DOM agent hasn't been enabled");
  include_whitespace_.Clear();
  enabled_.Clear();
  instrumenting_agents_->RemoveInspectorDOMAgent(this);
  history_.Clear();
  dom_editor_.Clear();
  SetDocument(nullptr);
  return protocol::Response::Success();
}

protocol::Response InspectorDOMAgent::getDocument(
    Maybe<int> depth,
    Maybe<bool> pierce,
    std::unique_ptr<protocol::DOM::Node>* root) {
  // Backward compatibility. Mark agent as enabled when it requests document.
  if (!enabled_.Get())
    enable(Maybe<String>());

  if (!document_)
    return protocol::Response::ServerError("Document is not available");

  DiscardFrontendBindings();

  int sanitized_depth = depth.value_or(2);
  if (sanitized_depth == -1)
    sanitized_depth = INT_MAX;

  *root = BuildObjectForNode(document_.Get(), sanitized_depth,
                             pierce.value_or(false),
                             document_node_to_id_map_.Get());
  return protocol::Response::Success();
}

namespace {

bool NodeHasMatchingStyles(
    const HashMap<CSSPropertyID, HashSet<String>>* properties,
    Node* node) {
  if (auto* element = DynamicTo<Element>(node)) {
    auto* computed_style_info =
        MakeGarbageCollected<CSSComputedStyleDeclaration>(element, true);
    for (const auto& property : *properties) {
      const CSSValue* computed_value =
          computed_style_info->GetPropertyCSSValue(property.key);
      if (computed_value &&
          property.value.Contains(computed_value->CssText())) {
        return true;
      }
    }
  }
  return false;
}

}  // namespace

protocol::Response InspectorDOMAgent::getNodesForSubtreeByStyle(
    int node_id,
    std::unique_ptr<protocol::Array<protocol::DOM::CSSComputedStyleProperty>>
        computed_styles,
    Maybe<bool> pierce,
    std::unique_ptr<protocol::Array<int>>* node_ids) {
  if (!enabled_.Get())
    return protocol::Response::ServerError("DOM agent hasn't been enabled");

  if (!document_)
    return protocol::Response::ServerError("Document is not available");

  Node* root_node = nullptr;
  protocol::Response response = AssertNode(node_id, root_node);
  if (!response.IsSuccess())
    return response;

  HashMap<CSSPropertyID, HashSet<String>> properties;
  for (const auto& style : *computed_styles) {
    std::optional<CSSPropertyName> property_name = CSSPropertyName::From(
        document_->GetExecutionContext(), style->getName());
    if (!property_name)
      return protocol::Response::InvalidParams("Invalid CSS property name");
    auto property_id = property_name->Id();
    HashMap<CSSPropertyID, HashSet<String>>::iterator it =
        properties.find(property_id);
    if (it != properties.end())
      it->value.insert(style->getValue());
    else
      properties.Set(property_id, HashSet<String>({style->getValue()}));
  }

  HeapVector<Member<Node>> nodes;

  CollectNodes(
      root_node, INT_MAX, pierce.value_or(false), IncludeWhitespace(),
      WTF::BindRepeating(&NodeHasMatchingStyles, WTF::Unretained(&properties)),
      &nodes);

  NodeToIdMap* nodes_map = document_node_to_id_map_.Get();
  *node_ids = std::make_unique<protocol::Array<int>>();
  for (Node* node : nodes) {
    int id = PushNodePathToFrontend(node, nodes_map);
    (*node_ids)->push_back(id);
  }

  return protocol::Response::Success();
}

protocol::Response InspectorDOMAgent::getFlattenedDocument(
    Maybe<int> depth,
    Maybe<bool> pierce,
    std::unique_ptr<protocol::Array<protocol::DOM::Node>>* nodes) {
  if (!enabled_.Get())
    return protocol::Response::ServerError("DOM agent hasn't been enabled");

  if (!document_)
    return protocol::Response::ServerError("Document is not available");

  DiscardFrontendBindings();

  int sanitized_depth = depth.value_or(-1);
  if (sanitized_depth == -1)
    sanitized_depth = INT_MAX;

  *nodes = std::make_unique<protocol::Array<protocol::DOM::Node>>();
  (*nodes)->emplace_back(BuildObjectForNode(
      document_.Get(), sanitized_depth, pierce.value_or(false),
      document_node_to_id_map_.Get(), nodes->get()));
  return protocol::Response::Success();
}

void InspectorDOMAgent::PushChildNodesToFrontend(int node_id,
                                                 int depth,
                                                 bool pierce) {
  Node* node = NodeForId(node_id);
  if (!node || (!node->IsElementNode() && !node->IsDocumentNode() &&
                !node->IsDocumentFragment()))
    return;

  NodeToIdMap* node_map = id_to_nodes_map_.at(node_id);

  if (children_requested_.Contains(node_id)) {
    if (depth <= 1)
      return;

    depth--;

    InspectorDOMAgent::IncludeWhitespaceEnum include_whitespace =
        IncludeWhitespace();
    for (node = InnerFirstChild(node, include_whitespace); node;
         node = InnerNextSibling(node, include_whitespace)) {
      int child_node_id = node_map->at(node);
      DCHECK(child_node_id);
      PushChildNodesToFrontend(child_node_id, depth, pierce);
    }

    return;
  }

  std::unique_ptr<protocol::Array<protocol::DOM::Node>> children =
      BuildArrayForContainerChildren(node, depth, pierce, node_map, nullptr);
  GetFrontend()->setChildNodes(node_id, std::move(children));
}

void InspectorDOMAgent::DiscardFrontendBindings() {
  if (history_)
    history_->Reset();
  search_results_.clear();
  document_node_to_id_map_->clear();
  id_to_node_.clear();
  id_to_nodes_map_.clear();
  ReleaseDanglingNodes();
  children_requested_.clear();
  cached_child_count_.clear();
  if (revalidate_task_)
    revalidate_task_->Reset();
}

Node* InspectorDOMAgent::NodeForId(int id) const {
  if (!id)
    return nullptr;

  const auto it = id_to_node_.find(id);
  if (it != id_to_node_.end())
    return it->value.Get();
  return nullptr;
}

protocol::Response InspectorDOMAgent::collectClassNamesFromSubtree(
    int node_id,
    std::unique_ptr<protocol::Array<String>>* class_names) {
  HashSet<String> unique_names;
  *class_names = std::make_unique<protocol::Array<String>>();
  Node* parent_node = NodeForId(node_id);
  if (!parent_node) {
    return protocol::Response::ServerError(
        "No suitable node with given id found");
  }
  auto* parent_element = DynamicTo<Element>(parent_node);
  if (!parent_element && !parent_node->IsDocumentNode() &&
      !parent_node->IsDocumentFragment()) {
    return protocol::Response::ServerError(
        "No suitable node with given id found");
  }

  for (Node* node = parent_node; node;
       node = FlatTreeTraversal::Next(*node, parent_node)) {
    if (const auto* element = DynamicTo<Element>(node)) {
      if (!element->HasClass())
        continue;
      const SpaceSplitString& class_name_list = element->ClassNames();
      for (unsigned i = 0; i < class_name_list.size(); ++i)
        unique_names.insert(class_name_list[i]);
    }
  }
  for (const String& class_name : unique_names)
    (*class_names)->emplace_back(class_name);
  return protocol::Response::Success();
}

protocol::Response InspectorDOMAgent::requestChildNodes(
    int node_id,
    Maybe<int> depth,
    Maybe<bool> maybe_taverse_frames) {
  int sanitized_depth = depth.value_or(1);
  if (sanitized_depth == 0 || sanitized_depth < -1) {
    return protocol::Response::ServerError(
        "Please provide a positive integer as a depth or -1 for entire "
        "subtree");
  }
  if (sanitized_depth == -1)
    sanitized_depth = INT_MAX;

  PushChildNodesToFrontend(node_id, sanitized_depth,
                           maybe_taverse_frames.value_or(false));
  return protocol::Response::Success();
}

protocol::Response InspectorDOMAgent::querySelector(int node_id,
                                                    const String& selectors,
                                                    int* element_id) {
  *element_id = 0;
  Node* node = nullptr;
  protocol::Response response = AssertNode(node_id, node);
  if (!response.IsSuccess())
    return response;
  auto* container_node = DynamicTo<ContainerNode>(node);
  if (!container_node)
    return protocol::Response::ServerError("Not a container node");

  DummyExceptionStateForTesting exception_state;
  Element* element =
      container_node->QuerySelector(AtomicString(selectors), exception_state);
  if (exception_state.HadException())
    return protocol::Response::ServerError("DOM Error while querying");

  if (element)
    *element_id = PushNodePathToFrontend(element);
  return protocol::Response::Success();
}

protocol::Response InspectorDOMAgent::querySelectorAll(
    int node_id,
    const String& selectors,
    std::unique_ptr<protocol::Array<int>>* result) {
  Node* node = nullptr;
  protocol::Response response = AssertNode(node_id, node);
  if (!response.IsSuccess())
    return response;
  auto* container_node = DynamicTo<ContainerNode>(node);
  if (!container_node)
    return protocol::Response::ServerError("Not a container node");

  DummyExceptionStateForTesting exception_state;
  StaticElementList* elements = container_node->QuerySelectorAll(
      AtomicString(selectors), exception_state);
  if (exception_state.HadException())
    return protocol::Response::ServerError("DOM Error while querying");

  *result = std::make_unique<protocol::Array<int>>();

  for (unsigned i = 0; i < elements->length(); ++i)
    (*result)->emplace_back(PushNodePathToFrontend(elements->item(i)));
  return protocol::Response::Success();
}

protocol::Response InspectorDOMAgent::getTopLayerElements(
    std::unique_ptr<protocol::Array<int>>* result) {
  if (!document_)
    return protocol::Response::ServerError("DOM agent hasn't been enabled");

  *result = std::make_unique<protocol::Array<int>>();
  for (auto document : Documents()) {
    for (auto element : document->TopLayerElements()) {
      int node_id = PushNodePathToFrontend(element);
      if (node_id)
        (*result)->emplace_back(node_id);
    }
  }

  return protocol::Response::Success();
}

int InspectorDOMAgent::PushNodePathToFrontend(Node* node_to_push,
                                              NodeToIdMap* node_map) {
  DCHECK(node_to_push);  // Invalid input
  // InspectorDOMAgent might have been resetted already. See crbug.com/450491
  if (!document_)
    return 0;
  if (!BoundNodeId(document_))
    return 0;

  // Return id in case the node is known.
  if (auto it = node_map->find(node_to_push); it != node_map->end())
    return it->value;

  Node* node = node_to_push;
  HeapVector<Member<Node>> path;

  while (true) {
    Node* parent = InnerParentNode(node);
    if (!parent)
      return 0;
    path.push_back(parent);
    if (node_map->Contains(parent))
      break;
    node = parent;
  }

  for (int i = path.size() - 1; i >= 0; --i) {
    if (auto it = node_map->find(path.at(i).Get()); it != node_map->end()) {
      int node_id = it->value;
      DCHECK(node_id);
      PushChildNodesToFrontend(node_id);
    }
  }
  auto it = node_map->find(node_to_push);
  return it != node_map->end() ? it->value : 0;
}

int InspectorDOMAgent::PushNodePathToFrontend(Node* node_to_push) {
  if (!document_)
    return 0;

  int node_id =
      PushNodePathToFrontend(node_to_push, document_node_to_id_map_.Get());
  if (node_id)
    return node_id;

  Node* node = n
"""


```