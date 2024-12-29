Response:
Let's break down the thought process for analyzing this `AnnotationAgentImpl.cc` file. The goal is to understand its functionality and its relationship to web technologies.

**1. Initial Skim and Keyword Recognition:**

The first step is a quick scan of the code, looking for recognizable keywords and patterns. I'd be looking for things like:

* **Headers:** `#include ...`  These reveal dependencies and give hints about what areas of Blink are involved (e.g., `dom`, `editing`, `layout`, `scroll`, `mojom`).
* **Class Name:** `AnnotationAgentImpl`. The "Impl" suffix often suggests this is a concrete implementation of an interface (likely defined elsewhere). "Annotation" suggests it deals with some kind of marking or information overlaid on content.
* **Methods:** Public methods like `Attach`, `Remove`, `ScrollIntoView`, `Bind` immediately suggest the core actions this class performs.
* **Member Variables:**  `attached_range_`, `pending_range_`, `agent_host_`, `receiver_`, `selector_`, `type_`. These hold the state of the agent. "Range" likely relates to selected text, "host" and "receiver" hint at IPC communication, "selector" suggests a way to identify the annotation target, and "type" indicates different kinds of annotations.
* **Namespaces:** `blink`. This confirms it's part of the Blink rendering engine.
* **Comments:** The copyright notice and other comments can offer high-level context.

**2. Understanding the Core Functionality:**

Based on the initial scan, I can start forming hypotheses about what the class does:

* **Manages Annotations:**  The name is a big clue. It probably handles the creation, attachment, removal, and manipulation of annotations.
* **Deals with Text Ranges:** The presence of `RangeInFlatTree` and related classes strongly suggests it works with selected portions of text.
* **Involves Scrolling:** The `ScrollIntoView` method is explicit.
* **Has a Lifecycle:** Methods like `Attach` and `Remove` point to a defined lifecycle.
* **Communicates Externally:** `agent_host_` and `receiver_` suggest interaction with other components, possibly through Mojo.

**3. Analyzing Key Methods and Logic:**

Now, I would delve deeper into the most important methods:

* **`Attach`:**  This is likely the starting point for associating an annotation with content. It calls `selector_->FindRange`, indicating that finding the target text is a separate step.
* **`DidFinishFindRange`:** This seems to be the callback after the target range is found. It manages the `pending_range_` and decides whether to perform DOM mutations before finalizing the attachment.
* **`ProcessAttachmentFinished`:** This method finalizes the attachment, adds document markers (highlights), and notifies the `agent_host_`.
* **`ScrollIntoView`:**  This uses Blink's scrolling utilities to bring the annotated text into view.
* **`Remove`:**  This cleans up the annotation, including removing markers.

**4. Connecting to Web Technologies (HTML, CSS, JavaScript):**

This is where I would try to bridge the gap between the C++ code and the technologies web developers use:

* **HTML:** Annotations are attached to elements and text content within the HTML structure. The interaction with `<details>` elements and `hidden=until-found` attributes is a direct link to HTML features.
* **CSS:** The checks for `overflow: hidden`, `opacity: 0`, and `position: fixed` indicate that CSS properties can affect the visibility and findability of annotated text. The highlighting of annotations is also likely styled using CSS.
* **JavaScript:** While this C++ code doesn't directly execute JavaScript, it's part of the rendering engine that *supports* JavaScript features. JavaScript APIs could trigger actions that eventually lead to the use of `AnnotationAgentImpl`. For instance, a JavaScript function to "find in page" could use this class internally.

**5. Identifying Assumptions, Inputs, and Outputs:**

I would look for logical branches and decision points in the code:

* **Input to `IsValidRange`:** A `RangeInFlatTree` pointer.
* **Output of `IsValidRange`:** A boolean indicating whether the range is valid for annotation.
* **Input to `NeedsDOMMutationToAttach`:** The `pending_range_` and the `annotation_type_`.
* **Output of `NeedsDOMMutationToAttach`:** A boolean indicating whether DOM mutations are needed.
* **Input to `ScrollIntoView`:**  An attached annotation.
* **Output of `ScrollIntoView`:**  The browser viewport is scrolled to bring the annotation into view.

**6. Considering User and Programming Errors:**

I'd think about scenarios where things could go wrong:

* **User Errors:**  A user might expect to scroll to text that is hidden by CSS or within collapsed elements.
* **Programming Errors:** Incorrectly setting up the `AnnotationSelector`, providing invalid ranges, or issues with the Mojo communication.

**7. Debugging and User Interaction:**

Finally, I'd consider how a developer might end up looking at this code during debugging:

* **Scenario:** A user reports that "find in page" isn't working correctly for text within a `<details>` element.
* **Debugging Steps:** A developer might trace the "find in page" functionality through Blink's code and eventually arrive at `AnnotationAgentImpl`, noticing the logic related to expanding `<details>` elements.

**Self-Correction/Refinement during the process:**

* Initially, I might just think "annotations are highlights."  But looking deeper, I see different `annotation_type_` values, suggesting broader use cases.
* I might overlook the significance of `RangeInFlatTree` at first, but recognizing it as a core Blink data structure for representing text selections is crucial.
*  Realizing the interaction with Mojo helps understand how this component fits into the larger Chromium architecture.

By following this structured approach, combining code analysis with knowledge of web technologies and potential error scenarios, I can arrive at a comprehensive understanding of the `AnnotationAgentImpl.cc` file's purpose and functionality.好的，让我们来分析一下 `blink/renderer/core/annotation/annotation_agent_impl.cc` 这个文件。

**功能概要:**

`AnnotationAgentImpl` 看起来是 Blink 渲染引擎中负责管理和操作**文本注解 (Text Annotations)** 的核心实现类。它的主要功能包括：

1. **管理注解的生命周期:**  负责注解的创建、绑定、附加到 DOM 树、更新和移除。
2. **定位注解目标:** 通过 `AnnotationSelector` 找到需要在文档中进行注解的文本范围 (`RangeInFlatTree`)。
3. **在视图中滚动显示注解:** 提供 `ScrollIntoView()` 方法，将注解的文本范围滚动到用户的可视区域。
4. **处理注解的附加和DOM变动:**  在附加注解前，会考虑是否需要进行 DOM 变动，例如展开 `<details>` 元素或显示 `hidden=until-found` 的元素。
5. **添加和移除文档标记 (Document Markers):**  使用 `DocumentMarkerController` 在注解的文本范围内添加 `TextFragmentMarker`，用于高亮显示等目的。
6. **与外部模块通信:**  通过 `AnnotationAgentHost` 进行通信，通知注解的附加状态和位置信息。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`AnnotationAgentImpl` 虽然是用 C++ 实现的，但它直接服务于浏览器渲染引擎的核心功能，因此与 JavaScript, HTML, CSS 有着密切的联系：

* **HTML:**
    * **定位目标:**  `AnnotationSelector` 的作用是根据某种规则（例如，可能是通过 URL 的 Fragment 指令，如 `#targetText=...`，或者通过 JavaScript 代码指定）在 HTML 文档中找到特定的文本范围。
    * **`<details>` 元素:**  代码中提到了 `HTMLDetailsElement::ExpandDetailsAncestors`，这意味着当注解的目标文本位于一个折叠的 `<details>` 元素内部时，`AnnotationAgentImpl` 能够展开该元素，以便将目标文本滚动到视图中。
    * **`hidden=until-found` 属性:**  代码中提到了 `DisplayLockUtilities::RevealHiddenUntilFoundAncestors`，表明如果注解的目标文本在一个设置了 `hidden=until-found` 属性的元素内，该类能够将其显示出来。
* **CSS:**
    * **控制可见性:**  代码中会检查元素的 CSS 属性，如 `overflow: hidden`、`opacity: 0` 和 `position: fixed`，来判断目标文本是否可见。如果文本被隐藏，可能不会进行滚动操作（对于 `TextFinder` 类型的注解）。
    * **高亮显示:** `TextFragmentMarker` 通常会关联特定的 CSS 样式，用于在页面上高亮显示注解的文本。
* **JavaScript:**
    * **触发注解:**  JavaScript 代码可以通过浏览器提供的 API（例如，Navigation API 或者一些内部的接口）触发创建和附加文本注解的操作。
    * **`scrollIntoView()` 方法:**  虽然 `AnnotationAgentImpl` 实现了底层的滚动逻辑，但 JavaScript 中元素的 `scrollIntoView()` 方法可能会间接地触发这里的代码。

**举例说明:**

假设有一个 HTML 文件如下：

```html
<!DOCTYPE html>
<html>
<head>
  <title>Annotation Example</title>
</head>
<body>
  <p>This is some text.</p>
  <details>
    <summary>Click to expand</summary>
    <p id="target">This is the target text for annotation.</p>
  </details>
  <div style="overflow: hidden; height: 0;">
    <p id="hidden-text">This text is hidden by overflow.</p>
  </div>
  <div style="opacity: 0;">
    <p id="invisible-text">This text is invisible due to opacity.</p>
  </div>
  <script>
    // 假设 JavaScript 代码触发了对 id 为 "target" 的文本的注解
  </script>
</body>
</html>
```

1. **HTML 与 `<details>`:** 如果通过某种方式创建了一个指向 "This is the target text for annotation." 的注解，`AnnotationAgentImpl` 在附加注解时，会展开 `<details>` 元素，确保用户可以看到目标文本。
2. **CSS 与 `overflow: hidden`:** 如果创建了一个指向 "This text is hidden by overflow." 的 `TextFinder` 类型的注解，由于其父元素的 `overflow: hidden` 和 `height: 0`，`IsValidRangeForTextFinder` 可能会返回 `false`，从而阻止滚动到该文本。
3. **CSS 与 `opacity: 0`:**  类似地，如果注解目标是 "This text is invisible due to opacity."，且注解类型为 `TextFinder`，由于父元素的 `opacity: 0`，可能也会阻止滚动。
4. **JavaScript 触发:** JavaScript 代码可以使用 `URL` 的 hash 部分（例如 `document.location.hash = '#targetText=target%20text'`) 来触发浏览器查找并滚动到页面上的特定文本，这个过程会涉及到 `AnnotationAgentImpl` 来处理注解的创建和滚动。

**逻辑推理 (假设输入与输出):**

假设输入一个 `RangeInFlatTree` 对象，该对象指向上述 HTML 中 `<p id="target">` 元素内的文本 "the target text"。

* **假设输入:**  一个指向 "the target text" 的 `RangeInFlatTree` 对象。
* **输出 (`IsValidRange`):** `true` (假设该文本在 DOM 中连接且未折叠)。
* **输出 (对于 `ScrollIntoView()`):** 浏览器窗口会滚动，使得 "the target text" 可见，并且由于代码中设置了 `ScrollAlignment::CenterAlways()`，该文本很可能会在视口的中心位置。
* **输出 (对于 `ProcessAttachmentFinished()`):**
    * 如果 `annotation_type_` 不是 `kTextFinder`，则会在该文本范围内添加一个 `TextFragmentMarker`，导致该文本被高亮显示（具体的样式由 CSS 控制）。
    * `agent_host_` 会收到 `DidFinishAttachment` 消息，包含该文本范围在文档坐标系中的矩形信息。

**用户或编程常见的使用错误:**

1. **注解目标文本不存在或已删除:** 如果 `AnnotationSelector` 找不到指定的文本范围，`DidFinishFindRange` 接收到的 `range` 将为 null，导致注解无法附加。
2. **注解目标文本不可见:**  如上面 CSS 的例子，如果目标文本被 CSS 隐藏，用户可能会期望滚动到该文本，但 `AnnotationAgentImpl`（特别是 `TextFinder` 类型）可能会阻止滚动。
3. **在不合适的时机调用方法:**  例如，在 DOM 结构尚未完全加载或渲染完成时尝试附加注解，可能会导致找不到目标文本。
4. **Mojo 通信错误:**  如果 `agent_host_` 的连接断开，`AnnotationAgentImpl` 将无法通知外部模块注解的状态。

**用户操作如何一步步到达这里 (作为调试线索):**

以下是一些可能导致代码执行到 `AnnotationAgentImpl` 的用户操作场景：

1. **用户点击包含文本片段的链接:** 用户点击一个包含 `#targetText=...` 形式的 URL 片段的链接。浏览器会解析该片段，并尝试在页面中找到匹配的文本，然后滚动到该位置并高亮显示。这个过程会触发 `AnnotationAgentImpl` 的功能。
2. **用户使用浏览器的 "查找" (Ctrl+F 或 Cmd+F) 功能:** 当用户在页面上查找特定文本时，浏览器内部会使用类似的机制来定位文本并滚动显示。`AnnotationAgentImpl` 的 `TextFinder` 类型可能与此功能有关。
3. **网页 JavaScript 代码调用相关 API:**  网页上的 JavaScript 代码可能使用浏览器的 API（例如，某些实验性的或内部的 API）来创建和管理文本注解。
4. **浏览器扩展或插件的功能:** 某些浏览器扩展可能会利用浏览器的内部接口来添加自定义的文本注解功能。

**调试线索:**

如果在调试与文本注解相关的问题时，可以关注以下几点：

* **URL 的 hash 部分:** 检查 URL 是否包含 `#targetText=...` 等与文本片段相关的指令。
* **浏览器的 "查找" 功能:** 测试浏览器的查找功能是否正常工作，这有助于判断是否是底层的文本定位机制出现了问题。
* **JavaScript 代码:**  检查网页的 JavaScript 代码是否调用了与注解相关的 API，例如 Navigation API 的相关事件。
* **DOM 结构:**  在附加注解时，检查目标文本是否实际存在于 DOM 树中，并且没有被 CSS 隐藏。
* **Mojo 连接状态:**  如果涉及到外部模块的通信，检查 `AnnotationAgentHost` 的连接状态是否正常。

希望这个详细的分析能够帮助你理解 `AnnotationAgentImpl.cc` 的功能和它在 Chromium Blink 引擎中的作用。

Prompt: 
```
这是目录为blink/renderer/core/annotation/annotation_agent_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/annotation/annotation_agent_impl.h"

#include "base/memory/scoped_refptr.h"
#include "base/task/single_thread_task_runner.h"
#include "base/trace_event/typed_macros.h"
#include "third_party/blink/public/mojom/scroll/scroll_into_view_params.mojom-blink.h"
#include "third_party/blink/renderer/core/annotation/annotation_agent_container_impl.h"
#include "third_party/blink/renderer/core/annotation/annotation_selector.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_utilities.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/markers/document_marker_controller.h"
#include "third_party/blink/renderer/core/editing/markers/text_fragment_marker.h"
#include "third_party/blink/renderer/core/editing/range_in_flat_tree.h"
#include "third_party/blink/renderer/core/editing/visible_units.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/highlight/highlight_style_utils.h"
#include "third_party/blink/renderer/core/html/html_details_element.h"
#include "third_party/blink/renderer/core/layout/geometry/physical_rect.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/layout/layout_text.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/scroll/scroll_alignment.h"
#include "third_party/blink/renderer/core/scroll/scroll_into_view_util.h"
#include "third_party/blink/renderer/core/scroll/scrollable_area.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/heap/visitor.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"

namespace blink {

namespace {
bool IsValidRange(const RangeInFlatTree* range) {
  // An attached range may have !IsCollapsed but converting to EphemeralRange
  // results in IsCollapsed. For an example, see
  // AnnotationAgentImplTest.ScrollIntoViewCollapsedRange.
  return range && range->IsConnected() && !range->IsCollapsed() &&
         !range->ToEphemeralRange().IsCollapsed();
}

// There are several cases where text isn't visible/presented to the user but
// does appear findable to FindBuffer. The TextFinder use case wants to prevent
// offering scrolls to these sections as its confusing (in fact, document
// Markers will avoid creating a highlight for these, despite the fact we can
// scroll to it). We probably want to do this for general SharedHighlights as
// well but that will require some more thought and spec changes but we can
// experiment with this for TextFinder to see how it works.
bool IsValidRangeForTextFinder(const RangeInFlatTree* range) {
  if (!IsValidRange(range)) {
    return false;
  }

  EphemeralRangeInFlatTree ephemeral_range = range->ToEphemeralRange();

  // Technically, the text could span multiple Elements, each of which could
  // hide overflow. However, that doesn't seem to be common so do the more
  // performant thing and check the common ancestor.
  Node* common_node = ephemeral_range.CommonAncestorContainer();

  LayoutObject* object = common_node->GetLayoutObject();
  CHECK(object);

  for (; !object->IsLayoutView(); object = object->Parent()) {
    LayoutBox* box = DynamicTo<LayoutBox>(object);
    if (!box) {
      continue;
    }

    // It's common for collapsible sections to be implemented by hiding
    // collapsed text within a `height:0; overflow: hidden` box. However,
    // FindBuffer does find this text (as typically overflow: hidden can still
    // be programmatically scrolled).
    if (box->HasNonVisibleOverflow()) {
      if (box->StyleRef().OverflowX() != EOverflow::kVisible &&
          box->Size().width.RawValue() <= 0) {
        return false;
      }

      if (box->StyleRef().OverflowY() != EOverflow::kVisible &&
          box->Size().height.RawValue() <= 0) {
        return false;
      }
    }

    // If an ancestor is set to opacity 0, consider the target invisible.
    if (box->StyleRef().Opacity() == 0) {
      return false;
    }

    // If the range is in a fixed subtree, scrolling the view won't change its
    // viewport-relative location so report the range as unfindable if its
    // currently offscreen.
    if (box->StyleRef().GetPosition() == EPosition::kFixed) {
      PhysicalRect view_rect =
          PhysicalRect::EnclosingRect(box->View()->AbsoluteBoundingBoxRectF());
      if (!view_rect.Intersects(
              common_node->GetLayoutObject()
                  ->AbsoluteBoundingBoxRectForScrollIntoView())) {
        return false;
      }
    }
  }

  return true;
}
}  // namespace

AnnotationAgentImpl::AnnotationAgentImpl(
    AnnotationAgentContainerImpl& owning_container,
    mojom::blink::AnnotationType annotation_type,
    AnnotationSelector& selector,
    AnnotationAgentContainerImpl::PassKey)
    : agent_host_(owning_container.GetSupplementable()->GetExecutionContext()),
      receiver_(this,
                owning_container.GetSupplementable()->GetExecutionContext()),
      owning_container_(&owning_container),
      selector_(&selector),
      type_(annotation_type) {
  DCHECK(!IsAttached());
  DCHECK(!IsRemoved());
}

void AnnotationAgentImpl::Trace(Visitor* visitor) const {
  visitor->Trace(agent_host_);
  visitor->Trace(receiver_);
  visitor->Trace(owning_container_);
  visitor->Trace(selector_);
  visitor->Trace(attached_range_);
  visitor->Trace(pending_range_);
}

void AnnotationAgentImpl::Bind(
    mojo::PendingRemote<mojom::blink::AnnotationAgentHost> host_remote,
    mojo::PendingReceiver<mojom::blink::AnnotationAgent> agent_receiver) {
  DCHECK(!IsRemoved());

  scoped_refptr<base::SingleThreadTaskRunner> task_runner =
      owning_container_->GetSupplementable()->GetTaskRunner(
          TaskType::kInternalDefault);

  agent_host_.Bind(std::move(host_remote), task_runner);
  receiver_.Bind(std::move(agent_receiver), task_runner);

  // Breaking the mojo connection will cause this agent to remove itself from
  // the container.
  receiver_.set_disconnect_handler(
      WTF::BindOnce(&AnnotationAgentImpl::Remove, WrapWeakPersistent(this)));
}

void AnnotationAgentImpl::Attach(AnnotationAgentContainerImpl::PassKey) {
  TRACE_EVENT("blink", "AnnotationAgentImpl::Attach");
  CHECK(!IsRemoved());
  CHECK(!IsAttached());
  CHECK(!pending_range_);
  CHECK(owning_container_->IsLifecycleCleanForAttachment());

  // We may still have an old range despite the CHECK above if the range become
  // collapsed due to DOM changes.
  attached_range_.Clear();

  needs_attachment_ = false;
  Document& document = *owning_container_->GetSupplementable();
  selector_->FindRange(document, AnnotationSelector::kSynchronous,
                       WTF::BindOnce(&AnnotationAgentImpl::DidFinishFindRange,
                                     WrapWeakPersistent(this)));
}

bool AnnotationAgentImpl::IsAttached() const {
  return IsValidRange(attached_range_);
}

bool AnnotationAgentImpl::IsAttachmentPending() const {
  // This can be an invalid range but still returns true because the attachment
  // is still in progress until the DomMutation task runs in the next rAF.
  return pending_range_ != nullptr;
}

bool AnnotationAgentImpl::IsBoundForTesting() const {
  DCHECK_EQ(agent_host_.is_bound(), receiver_.is_bound());
  return receiver_.is_bound();
}

void AnnotationAgentImpl::Remove() {
  DCHECK(!IsRemoved());

  if (IsAttached()) {
    EphemeralRange dom_range =
        EphemeralRange(ToPositionInDOMTree(attached_range_->StartPosition()),
                       ToPositionInDOMTree(attached_range_->EndPosition()));
    Document* document = attached_range_->StartPosition().GetDocument();
    DCHECK(document);

    if (LocalFrame* frame = document->GetFrame()) {
      // Markers require that layout is up to date if we're making any
      // modifications.
      frame->GetDocument()->UpdateStyleAndLayout(
          DocumentUpdateReason::kFindInPage);

      document->Markers().RemoveMarkersInRange(
          dom_range, DocumentMarker::MarkerTypes::TextFragment());
    }
  }

  attached_range_.Clear();
  pending_range_.Clear();

  agent_host_.reset();
  receiver_.reset();
  owning_container_->RemoveAgent(*this, PassKey());

  selector_.Clear();
  owning_container_.Clear();
}

void AnnotationAgentImpl::ScrollIntoView() const {
  DCHECK(!IsRemoved());

  if (!IsAttached())
    return;

  EphemeralRangeInFlatTree range = attached_range_->ToEphemeralRange();
  CHECK(range.Nodes().begin() != range.Nodes().end());
  Node& first_node = *range.Nodes().begin();

  Document& document = *owning_container_->GetSupplementable();
  document.EnsurePaintLocationDataValidForNode(
      &first_node, DocumentUpdateReason::kFindInPage);

  // TODO(bokan): Text can be attached without having a LayoutObject since it
  // may be inside an unexpanded <details> element or inside a
  // `content-visibility: auto` subtree. In those cases we should make sure we
  // expand/make-visible the node. This is implemented in TextFragmentAnchor
  // but that doesn't cover all cases we can get here so we should migrate that
  // code here.
  if (!first_node.GetLayoutObject()) {
    return;
  }

  // Set the bounding box height to zero because we want to center the top of
  // the text range.
  PhysicalRect bounding_box(ComputeTextRect(range));
  bounding_box.SetHeight(LayoutUnit());

  mojom::blink::ScrollIntoViewParamsPtr params =
      scroll_into_view_util::CreateScrollIntoViewParams(
          ScrollAlignment::CenterAlways(), ScrollAlignment::CenterAlways(),
          mojom::blink::ScrollType::kProgrammatic);
  params->cross_origin_boundaries = false;

  scroll_into_view_util::ScrollRectToVisible(*first_node.GetLayoutObject(),
                                             bounding_box, std::move(params));
}

void AnnotationAgentImpl::DidFinishFindRange(const RangeInFlatTree* range) {
  TRACE_EVENT("blink", "AnnotationAgentImpl::DidFinishFindRange",
              "bound_to_host", agent_host_.is_bound());
  if (IsRemoved()) {
    TRACE_EVENT_INSTANT("blink", "Removed");
    return;
  }

  pending_range_ = range;

  // In some cases, attaching to text can lead to DOM mutation. For example,
  // expanding <details> elements or unhiding an hidden=until-found element.
  // That needs to be done before processing the attachment (i.e. adding a
  // highlight). However, DOM/layout may not be safe to do here so we'll post a
  // task in that case.  However, if we don't need to perform those actions we
  // can avoid the extra post and just process the attachment now.
  if (!NeedsDOMMutationToAttach()) {
    ProcessAttachmentFinished();
  } else {
    // TODO(bokan): We may need to force an animation frame e.g. if we're in a
    // throttled iframe.
    Document& document = *owning_container_->GetSupplementable();
    document.EnqueueAnimationFrameTask(
        WTF::BindOnce(&AnnotationAgentImpl::PerformPreAttachDOMMutation,
                      WrapPersistent(this)));
  }
}

bool AnnotationAgentImpl::NeedsDOMMutationToAttach() const {
  if (!IsValidRange(pending_range_)) {
    return false;
  }

  // TextFinder type is used only to determine whether a given text can be
  // found in the page, it should have no side-effects.
  if (type_ == mojom::blink::AnnotationType::kTextFinder) {
    return false;
  }

  EphemeralRangeInFlatTree range = pending_range_->ToEphemeralRange();

  // TODO(crbug.com/1252872): Only |first_node| is considered in the range, but
  // we should be considering the entire range of selected text for ancestor
  // unlocking as well.
  if (DisplayLockUtilities::NeedsActivationForFindInPage(range)) {
    return true;
  }

  return false;
}

void AnnotationAgentImpl::PerformPreAttachDOMMutation() {
  if (IsValidRange(pending_range_)) {
    // TODO(crbug.com/1252872): Only |first_node| is considered for the below
    // ancestor expanding code, but we should be considering the entire range
    // of selected text for ancestor unlocking as well.
    Node& first_node = *pending_range_->ToEphemeralRange().Nodes().begin();

    // Activate content-visibility:auto subtrees if needed.
    DisplayLockUtilities::ActivateFindInPageMatchRangeIfNeeded(
        pending_range_->ToEphemeralRange());

    // If the active match is hidden inside a <details> element, then we should
    // expand it so we can scroll to it.
    if (HTMLDetailsElement::ExpandDetailsAncestors(first_node)) {
      UseCounter::Count(
          first_node.GetDocument(),
          WebFeature::kAutoExpandedDetailsForScrollToTextFragment);
    }

    // If the active match is hidden inside a hidden=until-found element, then
    // we should reveal it so we can scroll to it.
    DisplayLockUtilities::RevealHiddenUntilFoundAncestors(first_node);

    // Ensure we leave clean layout since we'll be applying markers after this.
    first_node.GetDocument().UpdateStyleAndLayout(
        DocumentUpdateReason::kFindInPage);
  }

  ProcessAttachmentFinished();
}

void AnnotationAgentImpl::ProcessAttachmentFinished() {
  CHECK(!attached_range_);

  // See IsValidRangeForTextFinder for why we treat kTextFinder differently
  // here.
  bool pending_range_valid = type_ == mojom::blink::AnnotationType::kTextFinder
                                 ? IsValidRangeForTextFinder(pending_range_)
                                 : IsValidRange(pending_range_);

  if (pending_range_valid) {
    attached_range_ = pending_range_;

    TRACE_EVENT_INSTANT("blink", "IsAttached");

    EphemeralRange dom_range =
        EphemeralRange(ToPositionInDOMTree(attached_range_->StartPosition()),
                       ToPositionInDOMTree(attached_range_->EndPosition()));
    Document* document = attached_range_->StartPosition().GetDocument();
    DCHECK(document);

    // TextFinder type is used only to determine whether a given text can be
    // found in the page, it should have no side-effects.
    if (type_ != mojom::blink::AnnotationType::kTextFinder) {
      document->Markers().AddTextFragmentMarker(dom_range);
      document->Markers().MergeOverlappingMarkers(
          DocumentMarker::kTextFragment);
    }

    if (type_ != mojom::blink::AnnotationType::kUserNote) {
      Node* anchor_node = attached_range_->StartPosition().AnchorNode();
      CHECK(anchor_node);
      if (anchor_node->IsInShadowTree()) {
        UseCounter::Count(document, WebFeature::kTextDirectiveInShadowDOM);
      }
    }
  } else {
    TRACE_EVENT_INSTANT("blink", "NotAttached");
  }

  pending_range_.Clear();

  // If we're bound to one, let the host know we've finished attempting to
  // attach.
  // TODO(bokan): Perhaps we should keep track of whether we've called
  // DidFinishFindRange and, if set, call the host method when binding.
  if (agent_host_.is_bound()) {
    gfx::Rect range_rect_in_document;
    if (IsAttached()) {
      gfx::Rect rect_in_frame =
          ComputeTextRect(attached_range_->ToEphemeralRange());

      Document* document = attached_range_->StartPosition().GetDocument();
      DCHECK(document);

      LocalFrameView* view = document->View();
      DCHECK(view);

      range_rect_in_document = view->FrameToDocument(rect_in_frame);
    }

    // Empty rect means the selector didn't find its content.
    agent_host_->DidFinishAttachment(range_rect_in_document);
  }
}

bool AnnotationAgentImpl::IsRemoved() const {
  // selector_ and owning_container_ should only ever be null if the agent was
  // removed.
  DCHECK_EQ(!owning_container_, !selector_);

  // If the agent is removed, all its state should be cleared.
  DCHECK(owning_container_ || !attached_range_);
  DCHECK(owning_container_ || !agent_host_.is_bound());
  DCHECK(owning_container_ || !receiver_.is_bound());
  return !owning_container_;
}

}  // namespace blink

"""

```