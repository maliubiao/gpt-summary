Response:
Let's break down the thought process for analyzing the `ViewTransitionSupplement.cc` file.

1. **Understand the Core Purpose:** The file name `view_transition_supplement.cc` immediately suggests its role: to *supplement* the functionality related to view transitions in Blink. The term "supplement" in the Chromium codebase often implies a helper class that adds features to a core object (in this case, `Document`).

2. **Identify Key Classes and Concepts:**  Scanning the `#include` directives and the code itself reveals the central players:
    * `ViewTransitionSupplement`: The class being analyzed.
    * `DOMViewTransition`: The JavaScript-accessible object representing a view transition.
    * `ViewTransition`: The internal C++ class managing the transition logic.
    * `Document`: The web page itself, the context in which transitions happen.
    * `LocalFrame`: Represents an iframe.
    * `ViewTransitionRequest`: Data passed to the compositor for the actual animation.
    * `ViewTransitionOptions`: JavaScript options for `startViewTransition`.
    * `V8ViewTransitionCallback`:  A wrapper for the JavaScript callback function.
    * `PageSwapEvent`:  An event related to navigation view transitions.

3. **Analyze Key Methods:**  Focus on the public and important-looking methods:
    * `FromIfExists`, `From`:  Standard Chromium pattern for accessing supplement objects.
    * `startViewTransition` (various overloads):  The entry point for initiating a view transition from JavaScript. This is a crucial area to understand.
    * `StartViewTransitionInternal`, `StartTransition`: Internal methods that handle the core logic of starting a transition. Note the distinction between script-initiated and navigation-initiated transitions.
    * `DidChangeVisibilityState`: Handles the document being hidden or shown, potentially cancelling transitions.
    * `SendOptInStatusToHost`, `SetCrossDocumentOptIn`:  Deal with cross-document view transitions and informing the browser process.
    * `SnapshotDocumentForNavigation`, `CreateFromSnapshotForNavigation`:  Methods specific to navigation-triggered view transitions.
    * `AbortTransition`:  Allows programmatic cancellation of a transition.
    * `OnTransitionFinished`:  Called when a transition completes.
    * `GetTransition`:  Retrieves the current transition object.
    * `AddPendingRequest`, `TakePendingRequests`:  Manage requests sent to the compositor.
    * `OnViewTransitionsStyleUpdated`:  Handles updates to the `@view-transition` CSS rule.
    * `WillInsertBody`, `ResolveCrossDocumentViewTransition`: Logic related to navigation and cross-document transitions.
    * `GenerateResourceId`, `InitializeResourceIdSequence`:  Deal with unique identifiers for transition elements.

4. **Map Functionality to Concepts:** Connect the methods to their purpose in the view transition process:
    * `startViewTransition`: Starts a transition triggered by JavaScript.
    * Navigation-related methods: Handle transitions when navigating between pages.
    * Visibility changes:  React to the page becoming hidden (e.g., by tab switching).
    * Cross-document transitions: Enable transitions between different origins under certain conditions.
    * Compositor interaction:  Use `ViewTransitionRequest` to send animation details to the rendering engine.

5. **Identify Relationships with Web Technologies:** Consider how the code interacts with JavaScript, HTML, and CSS:
    * **JavaScript:**  The `startViewTransition` methods are directly called from JavaScript. The `DOMViewTransition` object is returned to JavaScript. Callbacks are involved.
    * **HTML:**  The transition affects the rendering of the HTML content. The `Document` object represents the HTML document.
    * **CSS:**  The `@view-transition` rule (though not explicitly parsed in this file) is mentioned, indicating CSS plays a role in defining transition behavior. The `OnViewTransitionsStyleUpdated` method processes information related to this rule.

6. **Look for Logic and Assumptions:** Analyze the conditional statements and function calls:
    * Checks for existing transitions and how they're handled.
    * Handling of transitions in parent frames.
    * The concept of "opt-in" for cross-document transitions.
    * The distinction between script-initiated and navigation-initiated transitions.
    * Handling of hidden documents.

7. **Consider Potential User/Programming Errors:**  Think about how developers might misuse the API:
    * Calling `startViewTransition` when a transition is already in progress.
    * Issues with cross-document transitions if not properly configured.
    * Incorrect usage of the `ViewTransitionOptions` object.
    * Trying to start a transition when the document isn't fully loaded.

8. **Formulate Examples:**  Create concrete examples to illustrate the interaction with JavaScript, HTML, and CSS. This helps solidify understanding and explain the concepts clearly.

9. **Structure the Answer:** Organize the information logically, starting with a high-level summary of the file's purpose and then drilling down into specific functionalities, relationships with web technologies, logic, and potential errors. Use clear headings and bullet points for readability.

10. **Review and Refine:**  Read through the explanation to ensure accuracy, clarity, and completeness. Check for any inconsistencies or areas that need further elaboration. For instance, initially, I might have overlooked the nuances of cross-document transitions, and a review would prompt me to revisit that section.

By following these steps, we can effectively analyze and explain the functionality of a complex source code file like `ViewTransitionSupplement.cc`. The key is to break down the problem into smaller, manageable parts and then synthesize the information into a coherent understanding.
好的，我们来分析一下 `blink/renderer/core/view_transition/view_transition_supplement.cc` 这个文件。

**文件功能概览:**

`ViewTransitionSupplement.cc` 文件是 Chromium Blink 引擎中负责实现 **View Transitions API** 的核心组件之一。它作为一个 `Document` 的 Supplement，意味着它为 `Document` 对象添加了与视图过渡相关的功能。 主要功能包括：

1. **启动视图过渡:**  允许通过 JavaScript 调用 `document.startViewTransition()` 方法来启动视图过渡。它负责创建和管理 `DOMViewTransition` 对象，该对象是 JavaScript 中与视图过渡交互的句柄。
2. **处理导航相关的视图过渡:**  支持在页面导航时自动触发和管理视图过渡，例如在单页应用 (SPA) 中进行路由切换。
3. **管理视图过渡的状态:**  跟踪当前文档是否正在进行视图过渡，并在适当的时候取消或跳过过渡。
4. **与渲染引擎通信:**  负责将视图过渡的请求信息传递给 Chromium 的合成器 (Compositor) 线程，以便进行实际的动画渲染。
5. **处理跨文档的视图过渡:**  支持在满足特定条件的情况下，在不同文档之间进行视图过渡。
6. **管理资源 ID:**  为视图过渡中的元素生成唯一的资源 ID，以便在合成器线程中进行跟踪。
7. **处理视图过渡相关的 CSS 更新:**  响应 `@view-transition` CSS 规则的变化，并更新视图过渡的行为。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **JavaScript:**  `ViewTransitionSupplement` 提供了 JavaScript API `document.startViewTransition()` 的底层实现。
    * **举例:**  当 JavaScript 代码调用 `document.startViewTransition(() => { /* 更新 DOM */ })` 时，`ViewTransitionSupplement::startViewTransition` 方法会被调用，创建一个 `DOMViewTransition` 对象并开始处理过渡。
    * **假设输入:** JavaScript 调用 `document.startViewTransition(updateCallback)`，其中 `updateCallback` 是一个用于更新 DOM 的函数。
    * **假设输出:**  `ViewTransitionSupplement` 创建一个 `DOMViewTransition` 对象，并启动视图过渡流程，最终执行 `updateCallback` 函数。

* **HTML:**  视图过渡作用于 HTML 结构的变化。`ViewTransitionSupplement` 关注的是 `Document` 对象，它是 HTML 内容的抽象表示。
    * **举例:**  HTML 中某个元素的 `id` 属性可以被用作视图过渡中的命名视图（named view），以便在过渡过程中对该元素进行特定的动画处理。 虽然这个文件本身不直接解析 HTML，但它所管理的视图过渡操作会影响 HTML 元素的渲染。

* **CSS:**  CSS 的 `@view-transition` 规则可以用来定制视图过渡的外观和行为。 `ViewTransitionSupplement` 监听这些 CSS 规则的变化。
    * **举例:**  开发者可以使用 CSS 定义在视图过渡过程中某个命名视图的动画效果，例如：
      ```css
      ::view-transition-group(image) {
        animation-duration: 0.5s;
        transform: scale(1.2);
      }
      ```
      `ViewTransitionSupplement::OnViewTransitionsStyleUpdated` 方法会处理这些 CSS 规则，并将相关信息传递给视图过渡流程。

**逻辑推理及假设输入与输出:**

* **逻辑推理 1:  避免在父框架存在活跃过渡时启动子框架的过渡**
    * **假设输入:**  一个包含 iframe 的页面，父页面正在进行视图过渡，iframe 中的 JavaScript 代码尝试调用 `document.startViewTransition()`。
    * **逻辑:** `HasActiveTransitionInAncestorFrame` 函数会检查是否存在活跃的父框架过渡。如果存在，子框架的 `StartTransition` 方法会返回一个跳过的过渡 (skipped transition)。
    * **假设输出:** iframe 中启动的视图过渡会被立即跳过，不会执行动画。

* **逻辑推理 2:  同一 Widget (通常对应一个标签页) 只允许一个活跃的视图过渡**
    * **假设输入:**  在同一个标签页的两个不同的 iframe 中，几乎同时调用了 `document.startViewTransition()`。
    * **逻辑:** `SkipTransitionInAllLocalFrames` 函数会遍历与当前文档关联的所有本地框架，并跳过除了当前框架之外的所有框架中的现有过渡。
    * **假设输出:**  先启动的过渡会正常进行，后启动的过渡会被跳过。

**用户或编程常见的使用错误举例:**

1. **在过渡进行时尝试启动新的过渡:**
   * **错误代码:**
     ```javascript
     document.startViewTransition(() => {
       // ... 更新 DOM ...
       document.startViewTransition(() => { // 错误：尝试启动第二个过渡
         // ... 再次更新 DOM ...
       });
     });
     ```
   * **说明:**  `ViewTransitionSupplement` 会检测到已经存在一个活跃的过渡 (`transition_` 不为空)，并跳过后续的过渡请求。开发者应该等待当前过渡完成后再启动新的过渡。

2. **在文档隐藏时启动视图过渡:**
   * **错误场景:** 用户切换标签页，导致文档进入隐藏状态，此时 JavaScript 代码尝试启动视图过渡。
   * **说明:** `ViewTransitionSupplement::DidChangeVisibilityState` 方法会检测到文档变为隐藏，并调用 `transition_->SkipTransition(ViewTransition::PromiseResponse::kRejectInvalidState)` 来取消过渡，并返回一个被拒绝的 Promise。

3. **跨文档过渡配置错误:**
   * **错误场景:**  尝试在不同源的文档之间进行视图过渡，但没有正确配置 `@view-transition` 规则或使用 `ViewTransitionSupplement::SetCrossDocumentOptIn` 进行显式授权。
   * **说明:**  `ResolveCrossDocumentViewTransition` 方法会检查跨文档过渡的 opt-in 状态。如果未启用，过渡会被跳过。

4. **忘记处理 `updateCallback` 中的 DOM 更新:**
   * **错误代码:**
     ```javascript
     document.startViewTransition(() => {
       // 这里忘记更新 DOM 了！
     });
     ```
   * **说明:**  虽然这不是 `ViewTransitionSupplement` 直接处理的错误，但这是一个常见的编程错误。如果没有在 `updateCallback` 中进行 DOM 更新，视图过渡将没有任何可见的效果。

**总结:**

`ViewTransitionSupplement.cc` 是 Blink 引擎中实现 View Transitions API 的关键组件，它连接了 JavaScript API、HTML 文档结构以及底层的渲染机制。它负责启动、管理和协调视图过渡的整个生命周期，并处理各种边界情况和潜在的错误使用场景。理解这个文件的功能对于深入理解浏览器如何实现平滑的页面过渡至关重要。

### 提示词
```
这是目录为blink/renderer/core/view_transition/view_transition_supplement.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/view_transition/view_transition_supplement.h"

#include "cc/trees/layer_tree_host.h"
#include "cc/view_transition/view_transition_request.h"
#include "third_party/blink/public/mojom/frame/frame.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_view_transition_callback.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_view_transition_options.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/view_transition/dom_view_transition.h"
#include "third_party/blink/renderer/core/view_transition/page_swap_event.h"
#include "third_party/blink/renderer/core/view_transition/view_transition.h"
#include "third_party/blink/renderer/core/view_transition/view_transition_utils.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/graphics/compositing/paint_artifact_compositor.h"
#include "third_party/blink/renderer/platform/scheduler/public/task_attribution_tracker.h"

namespace blink {
namespace {

bool HasActiveTransitionInAncestorFrame(LocalFrame* frame) {
  auto* parent = frame ? frame->Parent() : nullptr;

  while (parent && parent->IsLocalFrame()) {
    if (To<LocalFrame>(parent)->GetDocument() &&
        ViewTransitionUtils::GetTransition(
            *To<LocalFrame>(parent)->GetDocument())) {
      return true;
    }

    parent = parent->Parent();
  }

  return false;
}

// Skips transitions in all local frames underneath |curr_frame|'s local root
// except |curr_frame| itself.
void SkipTransitionInAllLocalFrames(LocalFrame* curr_frame) {
  auto* root_view = curr_frame ? curr_frame->LocalFrameRoot().View() : nullptr;
  if (!root_view)
    return;

  root_view->ForAllChildLocalFrameViews([curr_frame](LocalFrameView& child) {
    if (child.GetFrame() == *curr_frame)
      return;

    auto* document = child.GetFrame().GetDocument();
    auto* transition =
        document ? ViewTransitionUtils::GetTransition(*document) : nullptr;
    if (!transition)
      return;

    transition->SkipTransition();
    DCHECK(!ViewTransitionUtils::GetTransition(*document));
  });
}

}  // namespace

// static
const char ViewTransitionSupplement::kSupplementName[] = "ViewTransition";

// static
ViewTransitionSupplement* ViewTransitionSupplement::FromIfExists(
    const Document& document) {
  return Supplement<Document>::From<ViewTransitionSupplement>(document);
}

// static
ViewTransitionSupplement* ViewTransitionSupplement::From(Document& document) {
  auto* supplement =
      Supplement<Document>::From<ViewTransitionSupplement>(document);
  if (!supplement) {
    supplement = MakeGarbageCollected<ViewTransitionSupplement>(document);
    Supplement<Document>::ProvideTo(document, supplement);
  }
  return supplement;
}

// static
DOMViewTransition* ViewTransitionSupplement::StartViewTransitionInternal(
    ScriptState* script_state,
    Document& document,
    V8ViewTransitionCallback* callback,
    const std::optional<Vector<String>>& types,
    ExceptionState& exception_state) {
  DCHECK(script_state);
  auto* supplement = From(document);

  if (callback) {
    auto* tracker =
        scheduler::TaskAttributionTracker::From(script_state->GetIsolate());
    // Set the parent task ID if we're not in an extension task (as extensions
    // are not currently supported in TaskAttributionTracker).
    if (tracker && script_state->World().IsMainWorld()) {
      callback->SetParentTask(tracker->RunningTask());
    }
  }
  return supplement->StartTransition(document, callback, types,
                                     exception_state);
}

DOMViewTransition* ViewTransitionSupplement::startViewTransition(
    ScriptState* script_state,
    Document& document,
    V8ViewTransitionCallback* callback,
    ExceptionState& exception_state) {
  return StartViewTransitionInternal(script_state, document, callback,
                                     std::nullopt, exception_state);
}

DOMViewTransition* ViewTransitionSupplement::startViewTransition(
    ScriptState* script_state,
    Document& document,
    ViewTransitionOptions* options,
    ExceptionState& exception_state) {
  CHECK(!options || (options->hasUpdate() && options->hasTypes()));
  return StartViewTransitionInternal(
      script_state, document, options ? options->update() : nullptr,
      options ? options->types() : std::nullopt, exception_state);
}

DOMViewTransition* ViewTransitionSupplement::startViewTransition(
    ScriptState* script_state,
    Document& document,
    ExceptionState& exception_state) {
  return StartViewTransitionInternal(
      script_state, document, static_cast<V8ViewTransitionCallback*>(nullptr),
      std::nullopt, exception_state);
}

DOMViewTransition* ViewTransitionSupplement::StartTransition(
    Document& document,
    V8ViewTransitionCallback* callback,
    const std::optional<Vector<String>>& types,
    ExceptionState& exception_state) {
  // Disallow script initiated transitions during a navigation initiated
  // transition.
  if (transition_ && !transition_->IsCreatedViaScriptAPI()) {
    return ViewTransition::CreateSkipped(&document, callback)
        ->GetScriptDelegate();
  }

  if (transition_) {
    transition_->SkipTransition();
  }

  DCHECK(!transition_)
      << "SkipTransition() should finish existing |transition_|";

  // We need to be connected to a view to have a transition. We also need a
  // document element, since that's the originating element for the pseudo tree.
  if (!document.View() || !document.documentElement()) {
    return nullptr;
  }

  transition_ =
      ViewTransition::CreateFromScript(&document, callback, types, this);

  if (document.hidden()) {
    auto skipped_transition = transition_;
    skipped_transition->SkipTransition(
        ViewTransition::PromiseResponse::kRejectInvalidState);

    DCHECK(!transition_);
    return skipped_transition->GetScriptDelegate();
  }

  // If there is a transition in a parent frame, give that precedence over a
  // transition in a child frame.
  if (!RuntimeEnabledFeatures::ConcurrentViewTransitionsSPAEnabled() &&
      HasActiveTransitionInAncestorFrame(document.GetFrame())) {
    auto skipped_transition = transition_;
    skipped_transition->SkipTransition();

    DCHECK(!transition_);
    return skipped_transition->GetScriptDelegate();
  }

  // Skip transitions in all frames associated with this widget. We can only
  // have one transition per widget/CC.
  if (!RuntimeEnabledFeatures::ConcurrentViewTransitionsSPAEnabled()) {
    SkipTransitionInAllLocalFrames(document.GetFrame());
  }
  DCHECK(transition_);

  return transition_->GetScriptDelegate();
}

void ViewTransitionSupplement::DidChangeVisibilityState() {
  if (GetSupplementable()->hidden() && transition_) {
    transition_->SkipTransition(
        ViewTransition::PromiseResponse::kRejectInvalidState);
  }
  SendOptInStatusToHost();
}

void ViewTransitionSupplement::SendOptInStatusToHost() {
  // If we have a frame, notify the frame host that the opt-in has changed.
  Document* document = GetSupplementable();
  if (!document || !document->GetFrame() || !document->domWindow()) {
    return;
  }

  document->GetFrame()->GetLocalFrameHostRemote().OnViewTransitionOptInChanged(
      (document->domWindow()->HasBeenRevealed() && !document->hidden())
          ? cross_document_opt_in_
          : mojom::blink::ViewTransitionSameOriginOptIn::kDisabled);
}

void ViewTransitionSupplement::SetCrossDocumentOptIn(
    mojom::blink::ViewTransitionSameOriginOptIn cross_document_opt_in) {
  if (cross_document_opt_in_ == cross_document_opt_in) {
    return;
  }

  cross_document_opt_in_ = cross_document_opt_in;
  SendOptInStatusToHost();
}

// static
void ViewTransitionSupplement::SnapshotDocumentForNavigation(
    Document& document,
    const blink::ViewTransitionToken& navigation_id,
    mojom::blink::PageSwapEventParamsPtr params,
    ViewTransition::ViewTransitionStateCallback callback) {
  DCHECK(RuntimeEnabledFeatures::ViewTransitionOnNavigationEnabled());
  auto* supplement = From(document);
  supplement->StartTransition(document, navigation_id, std::move(params),
                              std::move(callback));
}

void ViewTransitionSupplement::StartTransition(
    Document& document,
    const blink::ViewTransitionToken& navigation_id,
    mojom::blink::PageSwapEventParamsPtr params,
    ViewTransition::ViewTransitionStateCallback callback) {
  // TODO(khushalsagar): Per spec, we should be checking the opt-in at this
  // point. See step 2 in
  // https://drafts.csswg.org/css-view-transitions-2/#setup-outbound-transition.

  if (transition_) {
    // We should skip a transition if one exists, regardless of how it was
    // created, since navigation transition takes precedence.
    transition_->SkipTransition();
  }

  DCHECK(!transition_)
      << "SkipTransition() should finish existing |transition_|";
  transition_ = ViewTransition::CreateForSnapshotForNavigation(
      &document, navigation_id, std::move(callback), cross_document_types_,
      this);

  auto* page_swap_event = MakeGarbageCollected<PageSwapEvent>(
      document, std::move(params), transition_->GetScriptDelegate());
  document.domWindow()->DispatchEvent(*page_swap_event);
}

// static
void ViewTransitionSupplement::CreateFromSnapshotForNavigation(
    Document& document,
    ViewTransitionState transition_state) {
  DCHECK(RuntimeEnabledFeatures::ViewTransitionOnNavigationEnabled());
  auto* supplement = From(document);
  supplement->StartTransition(document, std::move(transition_state));
}

// static
void ViewTransitionSupplement::AbortTransition(Document& document) {
  auto* supplement = FromIfExists(document);
  if (supplement && supplement->transition_) {
    supplement->transition_->SkipTransition();
    DCHECK(!supplement->transition_);
  }
}

void ViewTransitionSupplement::StartTransition(
    Document& document,
    ViewTransitionState transition_state) {
  DCHECK(!transition_) << "Existing transition on new Document";
  transition_ = ViewTransition::CreateFromSnapshotForNavigation(
      &document, std::move(transition_state), this);
}

void ViewTransitionSupplement::OnTransitionFinished(
    ViewTransition* transition) {
  CHECK(transition);
  CHECK_EQ(transition, transition_);
  // Clear the transition so it can be garbage collected if needed (and to
  // prevent callers of GetTransition thinking there's an ongoing transition).
  transition_ = nullptr;
}

ViewTransition* ViewTransitionSupplement::GetTransition() {
  return transition_.Get();
}

ViewTransitionSupplement::ViewTransitionSupplement(Document& document)
    : Supplement<Document>(document) {}

ViewTransitionSupplement::~ViewTransitionSupplement() = default;

void ViewTransitionSupplement::Trace(Visitor* visitor) const {
  visitor->Trace(transition_);

  Supplement<Document>::Trace(visitor);
}

void ViewTransitionSupplement::AddPendingRequest(
    std::unique_ptr<ViewTransitionRequest> request) {
  pending_requests_.push_back(std::move(request));

  auto* document = GetSupplementable();
  if (!document || !document->GetPage() || !document->View())
    return;

  // Schedule a new frame.
  document->View()->ScheduleAnimation();

  // Ensure paint artifact compositor does an update, since that's the mechanism
  // we use to pass transition requests to the compositor.
  document->View()->SetPaintArtifactCompositorNeedsUpdate();
}

VectorOf<std::unique_ptr<ViewTransitionRequest>>
ViewTransitionSupplement::TakePendingRequests() {
  return std::move(pending_requests_);
}

void ViewTransitionSupplement::OnViewTransitionsStyleUpdated(
    bool cross_document_enabled,
    const Vector<String>& types) {
  CHECK(RuntimeEnabledFeatures::ViewTransitionOnNavigationEnabled());
  CHECK(RuntimeEnabledFeatures::ViewTransitionTypesEnabled() || types.empty());
  SetCrossDocumentOptIn(
      cross_document_enabled
          ? mojom::blink::ViewTransitionSameOriginOptIn::kEnabled
          : mojom::blink::ViewTransitionSameOriginOptIn::kDisabled);
  cross_document_types_ = types;
}

void ViewTransitionSupplement::WillInsertBody() {
  if (!transition_ || !transition_->IsForNavigationOnNewDocument()) {
    return;
  }

  CHECK(RuntimeEnabledFeatures::ViewTransitionOnNavigationEnabled());

  auto* document = GetSupplementable();
  CHECK(document);

  // Update active styles will compute the @view-transition
  // navigation opt in.
  // TODO(https://crbug.com/1463966): This is probably a bit of a heavy hammer.
  // In the long term, we probably don't want to make this decision at
  // WillInsertBody or, if we do, we could look specifically for
  // @view-transition rather than all rules. Note: the opt-in is checked below
  // from dispatching the pagereveal event during the first update-the-rendering
  // steps.
  document->GetStyleEngine().UpdateActiveStyle();
}

DOMViewTransition*
ViewTransitionSupplement::ResolveCrossDocumentViewTransition() {
  if (!transition_ || !transition_->IsForNavigationOnNewDocument()) {
    return nullptr;
  }

  // We auto-skip *outbound* transitions when the document has not been
  // revealed yet. We expect it to not be revealed yet when resolving the
  // inbound transition.
  CHECK(!GetSupplementable()->domWindow()->HasBeenRevealed());

  if (cross_document_opt_in_ ==
      mojom::blink::ViewTransitionSameOriginOptIn::kDisabled) {
    transition_->SkipTransition();
    CHECK(!ViewTransitionUtils::GetTransition(*GetSupplementable()));
    return nullptr;
  }

  transition_->InitTypes(cross_document_types_);

  // TODO(https://crbug.com/1502628): This is where types from the used
  // @view-transition should be applied.

  return transition_->GetScriptDelegate();
}

viz::ViewTransitionElementResourceId
ViewTransitionSupplement::GenerateResourceId(
    const blink::ViewTransitionToken& transition_token) {
  return viz::ViewTransitionElementResourceId(transition_token,
                                              ++resource_local_id_sequence_);
}

void ViewTransitionSupplement::InitializeResourceIdSequence(
    uint32_t next_local_id) {
  CHECK_GT(next_local_id,
           viz::ViewTransitionElementResourceId::kInvalidLocalId);
  resource_local_id_sequence_ =
      std::max(next_local_id - 1, resource_local_id_sequence_);
}

}  // namespace blink
```