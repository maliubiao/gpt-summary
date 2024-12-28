Response:
The user wants a summary of the provided C++ code file `fullscreen.cc`. I need to identify the core functionalities of this file, focusing on its interaction with web technologies like JavaScript, HTML, and CSS. I also need to look for examples of logical reasoning in the code, potential user/programming errors, and finally, provide a concise overview of the file's purpose.

Here's a breakdown of the thought process:

1. **Identify the core purpose:** The filename `fullscreen.cc` and the included headers (like `fullscreen.h`, `HTMLBodyElement.h`, etc.) strongly suggest this file manages the fullscreen functionality within the Blink rendering engine.

2. **Analyze the functionalities by examining the code structure and keywords:**
    * Functions like `RequestFullscreen`, `ExitFullscreen`, `FullscreenElementFrom` are key indicators of core functionalities.
    * Look for state management related to fullscreen, such as `FullscreenParamsMap`, `SetFullscreenFlag`, `UnsetFullscreenFlag`.
    * Identify how the code interacts with the DOM (Document Object Model) using classes like `Element`, `Document`.
    * Check for event handling mechanisms using terms like "event", "dispatch".
    * Look for interactions with browser features like permissions using `PermissionService`.
    * Note the use of histograms for tracking metrics (`UMA_HISTOGRAM`).

3. **Relate functionalities to JavaScript, HTML, and CSS:**
    * **JavaScript:**  The functions like `RequestFullscreen` are directly exposed to JavaScript. The use of `ScriptPromiseResolver` confirms this. The code interacts with JavaScript events like `fullscreenchange` and `fullscreenerror`.
    * **HTML:** The code manipulates HTML elements to enter and exit fullscreen. It checks for specific element types (`HTMLElement`, `SVGSVGElement`, `HTMLDialogElement`). The interaction with the `<dialog>` element is a specific example.
    * **CSS:** The code manipulates CSS pseudo-classes (`:fullscreen`, `:-webkit-full-screen`) to style elements in fullscreen mode. The `EnsureUAStyleForFullscreen` function indicates the application of user-agent stylesheets.

4. **Identify logical reasoning and provide examples:**
    * The code has conditional logic to determine if a fullscreen request is allowed based on factors like user activation, permissions, and element type. I can create hypothetical scenarios to illustrate these checks. For example, a button click (user activation) triggering fullscreen vs. a script attempting fullscreen without user interaction.

5. **Identify potential user/programming errors:**
    *  The code includes error checks and returns specific error codes (e.g., `kElementNotConnected`, `kDisallowedByPermissionsPolicy`). I can use these error codes to create examples of common mistakes, like trying to make a detached element fullscreen or being blocked by browser permissions.

6. **Summarize the functionalities:** Based on the analysis, synthesize a concise overview of the file's responsibilities.

7. **Address specific instructions:**
    * Ensure the output is clearly divided into functionality listing, relation to web technologies, logical reasoning examples, common errors, and a final summary.
    * Mark the current output as "Part 1" as requested.

**Self-Correction/Refinement during the thought process:**

* Initially, I might just list the functions. However, the user wants to understand the *functionality*, so I need to group related functions and describe their purpose in a more user-friendly way.
* I need to be precise when describing the relationship with JavaScript, HTML, and CSS. Simply saying "it's related" is not enough. I need to provide specific examples of how the code interacts with these technologies.
* For logical reasoning, generic statements are not helpful. I need to create concrete input/output examples to illustrate the code's behavior.
* For user errors, I need to think from the perspective of a web developer using the fullscreen API.

By following these steps, I can generate a comprehensive and accurate summary of the provided code file as requested by the user.
这是对 `blink/renderer/core/fullscreen/fullscreen.cc` 文件功能的归纳总结，基于您提供的第一部分代码。

**功能归纳:**

该文件主要负责实现 Chromium Blink 引擎中**全屏 (Fullscreen) 功能的核心逻辑**。它处理了以下关键方面：

1. **管理全屏状态:**
   - 跟踪哪些元素处于全屏状态 (`FullscreenParamsMap`)。
   - 维护文档的全屏元素栈 (`TopLayerElements`)。
   - 记录全屏请求的元数据，如请求类型和选项 (`MetaParams`).
   - 提供方法判断元素是否在全屏栈中 (`IsInFullscreenElementStack`).

2. **处理全屏请求:**
   - 接收和处理 `requestFullscreen()` JavaScript API 的调用。
   - 执行全屏请求前的各种条件检查，例如：
     - 元素类型是否允许全屏 (HTML 或 SVG)。
     - 是否是 `<dialog>` 元素。
     - 元素是否连接到文档。
     - 是否被 Permissions Policy 阻止。
     - 元素是否已经以 Popover 形式打开。
     - 浏览器是否支持全屏。
     - 权限检查 (例如用户是否授予了全屏权限)。
     - 是否有用户激活或全屏请求能力委托。
   - 如果条件满足，将元素添加到文档的顶层 (`AddToTopLayer`)，并设置全屏标志。
   - 异步处理全屏请求，并使用 Promise 返回结果。

3. **处理退出全屏:**
   - 提供逻辑来退出全屏模式 (`Unfullscreen`)。
   - 从文档的顶层移除全屏元素 (`ScheduleForTopLayerRemoval`).
   - 清除全屏标志。
   - 处理嵌套的全屏元素退出。

4. **触发和处理全屏事件:**
   - 在全屏状态改变时，触发 `fullscreenchange` 和 `fullscreenerror` 事件。
   - 处理带前缀的事件 (`webkitfullscreenchange`, `webkitfullscreenerror`).
   - 使用 `EnqueueAnimationFrameTask` 将事件添加到动画帧任务队列中。

5. **与 CSS 样式交互:**
   - 在元素进入全屏时，应用特定的用户代理样式 (`EnsureUAStyleForFullscreen`).
   - 切换元素的伪类 (`:fullscreen`, `:-webkit-full-screen`, `:modal`) 以应用相应的 CSS 样式。
   - 当全屏元素改变时，触发样式重算 (`SetNeedsStyleRecalc`).

6. **与其他 Blink 组件交互:**
   - 与 `Document` 对象交互，管理文档的顶层元素和状态。
   - 与 `LocalFrame` 和 `LocalDOMWindow` 交互，获取页面和窗口信息。
   - 与 `Page` 和 `ChromeClient` 交互，通知浏览器全屏状态的改变。
   - 与 `PermissionsService` 交互，进行全屏权限检查。
   - 使用 `UseCounter` 记录全屏特性的使用情况。
   - 与 `VisualViewport` 交互，更新可视视口的绘制属性。
   - 与无障碍功能树交互 (`RefreshAccessibilityTree`)，更新元素的状态。

7. **处理 WebXR 集成:**
   - 考虑 WebXR DOM Overlay 模式下的全屏行为，例如在 XR 会话期间阻止更改全屏元素。

**与 JavaScript, HTML, CSS 的关系举例:**

* **JavaScript:**
    - 当 JavaScript 调用 `element.requestFullscreen()` 时，该文件中的 `RequestFullscreen` 方法会被调用来处理请求。
    - 当全屏状态改变时，JavaScript 可以监听 `fullscreenchange` 事件，该事件由该文件中的逻辑触发。
    - **假设输入:** JavaScript 代码 `document.getElementById('myVideo').requestFullscreen();`
    - **输出:** 该文件中的逻辑会检查 `myVideo` 元素是否满足全屏条件，如果满足则将其设置为全屏，并触发 `fullscreenchange` 事件。

* **HTML:**
    - 只有特定的 HTML 元素（例如 `<div>`, `<video>`) 可以进入全屏模式，该文件中的逻辑会检查元素类型。
    - `<dialog>` 元素不能直接进入全屏，该文件中的逻辑会阻止 `<dialog>` 元素的全屏请求。
    - **假设输入:** HTML 中有一个 `<dialog id="myDialog">` 元素，JavaScript 调用 `document.getElementById('myDialog').requestFullscreen();`
    - **输出:** 该文件中的 `EnforceRequestFullscreenConditions` 方法会检测到该元素是 `HTMLDialogElement`，并拒绝全屏请求，可能触发 `fullscreenerror` 事件。

* **CSS:**
    - 当一个元素进入全屏时，浏览器会自动给该元素添加 `:fullscreen` 或 `:-webkit-full-screen` 伪类，开发者可以使用 CSS 来定义全屏状态下的样式。该文件中的 `FullscreenElementChanged` 方法会负责切换这些伪类。
    - **假设输入:** CSS 样式规则 `.my-fullscreen-element:fullscreen { background-color: black; }` 和一个进入全屏的 HTML 元素，其类名为 `my-fullscreen-element`。
    - **输出:** 该文件中的逻辑会将 `:fullscreen` 伪类添加到该元素上，浏览器会应用背景色为黑色的样式。

**逻辑推理的假设输入与输出:**

* **假设输入:** 用户点击了一个按钮，该按钮的事件监听器调用了 `document.getElementById('myVideo').requestFullscreen();`，且当前页面没有用户激活状态。浏览器设置中阻止了未经用户交互的全屏请求。
* **输出:** 该文件中的 `EnforceRequestFullscreenConditions` 方法会检查到缺少用户激活，并且权限检查会失败，最终导致全屏请求被拒绝，并且 `RequestFullscreen` 返回的 Promise 会被 reject，可能触发 `fullscreenerror` 事件。

**涉及用户或编程常见的使用错误举例:**

* **用户错误:** 用户可能会在浏览器设置中阻止网站发起全屏请求，导致 `requestFullscreen()` 调用失败。
* **编程错误:**
    - 开发者可能会尝试让一个未连接到 DOM 树的元素进入全屏模式。该文件中的 `FullscreenElementReadyCheck` 方法会检查元素的连接状态并返回 `RequestFullscreenError::kElementNotConnected` 错误。
    - 开发者可能会尝试让 `<dialog>` 元素进入全屏模式。该文件中的 `EnforceRequestFullscreenConditions` 方法会检查元素类型并返回 `RequestFullscreenError::kElementTypeDialog` 错误。
    - 开发者可能没有处理 `requestFullscreen()` 返回的 Promise 的 rejection，导致在全屏请求失败时没有适当的反馈。

总而言之，`fullscreen.cc` 文件是 Blink 引擎中处理网页全屏功能的核心组件，它负责管理全屏状态、处理请求、触发事件，并与浏览器的其他组件协同工作，以实现符合 Web 标准的全屏体验。

Prompt: 
```
这是目录为blink/renderer/core/fullscreen/fullscreen.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 1999 Lars Knoll (knoll@kde.org)
 *           (C) 1999 Antti Koivisto (koivisto@kde.org)
 *           (C) 2001 Dirk Mueller (mueller@kde.org)
 *           (C) 2006 Alexey Proskuryakov (ap@webkit.org)
 * Copyright (C) 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2012 Apple Inc. All
 * rights reserved.
 * Copyright (C) 2008, 2009 Torch Mobile Inc. All rights reserved.
 * (http://www.torchmobile.com/)
 * Copyright (C) 2010 Nokia Corporation and/or its subsidiary(-ies)
 * Copyright (C) 2013 Google Inc. All rights reserved.
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
 *
 */

#include "third_party/blink/renderer/core/fullscreen/fullscreen.h"

#include "base/containers/adapters.h"
#include "base/metrics/histogram_macros.h"
#include "base/time/time.h"
#include "third_party/blink/public/mojom/permissions/permission.mojom-blink.h"
#include "third_party/blink/public/mojom/permissions_policy/permissions_policy.mojom-blink.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_fullscreen_options.h"
#include "third_party/blink/renderer/core/css/style_change_reason.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/execution_context/agent.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/fullscreen/fullscreen_request_type.h"
#include "third_party/blink/renderer/core/fullscreen/scoped_allow_fullscreen.h"
#include "third_party/blink/renderer/core/html/html_body_element.h"
#include "third_party/blink/renderer/core/html/html_dialog_element.h"
#include "third_party/blink/renderer/core/html/html_iframe_element.h"
#include "third_party/blink/renderer/core/html_element_type_helpers.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/svg/svg_svg_element.h"
#include "third_party/blink/renderer/platform/bindings/exception_messages.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/scheduler/public/event_loop.h"

namespace blink {

namespace {

// UMA key for tracking the duration of a fullscreen request.
static constexpr char kFullscreenDurationMetricKeyRequestFullscreen[] =
    "Blink.Element.Fullscreen.DurationUpTo1H.RequestFullscreen";

void FullscreenElementChanged(Document& document,
                              Element* old_element,
                              Element* new_element,
                              FullscreenRequestType new_request_type,
                              const FullscreenOptions* new_options) {
  DCHECK_NE(old_element, new_element);

  if (new_element) {
    document.GetStyleEngine().EnsureUAStyleForFullscreen(*new_element);
  }

  if (old_element) {
    DCHECK_NE(old_element, Fullscreen::FullscreenElementFrom(document));

    old_element->PseudoStateChanged(CSSSelector::kPseudoFullScreen);
    old_element->PseudoStateChanged(CSSSelector::kPseudoFullscreen);
    old_element->PseudoStateChanged(CSSSelector::kPseudoModal);

    old_element->SetContainsFullScreenElement(false);
    old_element->SetContainsFullScreenElementOnAncestorsCrossingFrameBoundaries(
        false);
  }

  if (new_element) {
    DCHECK_EQ(new_element, Fullscreen::FullscreenElementFrom(document));
    // FullscreenOptions should be provided for incoming fullscreen element.
    CHECK(new_options);

    new_element->PseudoStateChanged(CSSSelector::kPseudoFullScreen);
    new_element->PseudoStateChanged(CSSSelector::kPseudoFullscreen);
    new_element->PseudoStateChanged(CSSSelector::kPseudoModal);

    // OOPIF: For RequestType::kForCrossProcessDescendant, |new_element|
    // is the iframe element for the out-of-process frame that contains the
    // fullscreen element. Hence, it must match :-webkit-full-screen-ancestor.
    if (new_request_type & FullscreenRequestType::kForCrossProcessDescendant) {
      DCHECK(IsA<HTMLIFrameElement>(new_element));
      new_element->SetContainsFullScreenElement(true);
    }
    new_element->SetContainsFullScreenElementOnAncestorsCrossingFrameBoundaries(
        true);
  }

  // Update IsInert() flags.
  const StyleChangeReasonForTracing& reason =
      StyleChangeReasonForTracing::Create(style_change_reason::kFullscreen);
  if (old_element && new_element) {
    old_element->SetNeedsStyleRecalc(kLocalStyleChange, reason);
    new_element->SetNeedsStyleRecalc(kLocalStyleChange, reason);
  } else if (Element* root = document.documentElement()) {
    root->SetNeedsStyleRecalc(kLocalStyleChange, reason);
  }

  // Any element not contained by the fullscreen element is inert (see
  // |Node::IsInert()|), so changing the fullscreen element will typically
  // change the inertness of most elements. Reserialize the entire document.
  document.RefreshAccessibilityTree();

  if (LocalFrame* frame = document.GetFrame()) {
    // TODO(foolip): Synchronize hover state changes with animation frames.
    // https://crbug.com/668758
    frame->GetEventHandler().ScheduleHoverStateUpdate();
    frame->GetChromeClient().FullscreenElementChanged(
        old_element, new_element, new_options, new_request_type);

    // Update paint properties on the visual viewport since
    // user-input-scrollable bits will change based on fullscreen state.
    if (Page* page = frame->GetPage()) {
      if (page->GetVisualViewport().IsActiveViewport())
        page->GetVisualViewport().SetNeedsPaintPropertyUpdate();
    }
  }
}

class MetaParams : public GarbageCollected<MetaParams> {
 public:
  MetaParams() = default;
  MetaParams(FullscreenRequestType request_type,
             const FullscreenOptions* options,
             const base::TimeTicks& fullscreen_enter_time)
      : request_type_(request_type),
        options_(options),
        fullscreen_enter_time_(fullscreen_enter_time) {}
  MetaParams(const MetaParams&) = delete;
  MetaParams& operator=(const MetaParams&) = delete;

  virtual ~MetaParams() = default;

  virtual void Trace(Visitor* visitor) const { visitor->Trace(options_); }

  FullscreenRequestType request_type() const { return request_type_; }
  const FullscreenOptions* options() const { return options_.Get(); }
  const base::TimeTicks& fullscreen_enter_time() const {
    return fullscreen_enter_time_;
  }

 private:
  FullscreenRequestType request_type_;
  Member<const FullscreenOptions> options_;
  const base::TimeTicks fullscreen_enter_time_;
};

using ElementMetaParamsMap =
    HeapHashMap<WeakMember<const Element>, Member<const MetaParams>>;

ElementMetaParamsMap& FullscreenParamsMap() {
  DEFINE_STATIC_LOCAL(Persistent<ElementMetaParamsMap>, map,
                      (MakeGarbageCollected<ElementMetaParamsMap>()));
  return *map;
}

bool HasFullscreenFlag(const Element& element) {
  return FullscreenParamsMap().Contains(&element);
}

void SetFullscreenFlag(const Element& element,
                       FullscreenRequestType request_type,
                       const FullscreenOptions* options) {
  FullscreenParamsMap().insert(
      &element, MakeGarbageCollected<MetaParams>(request_type, options,
                                                 base::TimeTicks::Now()));
}

void UnsetFullscreenFlag(const Element& element) {
  FullscreenParamsMap().erase(&element);
}

FullscreenRequestType GetRequestType(const Element& element) {
  return FullscreenParamsMap().find(&element)->value->request_type();
}

const MetaParams* GetParams(Element& element) {
  return FullscreenParamsMap().find(&element)->value.Get();
}

// https://fullscreen.spec.whatwg.org/#fullscreen-an-element
void GoFullscreen(Element& element,
                  FullscreenRequestType request_type,
                  const FullscreenOptions* options) {
  Document& document = element.GetDocument();
  Element* old_element = Fullscreen::FullscreenElementFrom(document);

  // If |element| is already in top layer remove it so it will
  // be appended to the end.
  if (element.IsInTopLayer()) {
    document.RemoveFromTopLayerImmediately(&element);
  } else {
    DCHECK(!HasFullscreenFlag(element));
  }

  // Proposed new behavior: top layer elements like dialogs and fullscreen
  // elements can be nested inside popovers.
  // Old/existing behavior: showing a modal dialog or fullscreen
  // element should hide all open popovers.
  auto* hide_until = HTMLElement::TopLayerElementPopoverAncestor(
      element, TopLayerElementType::kFullscreen);
  HTMLElement::HideAllPopoversUntil(
      hide_until, document, HidePopoverFocusBehavior::kNone,
      HidePopoverTransitionBehavior::kFireEventsAndWaitForTransitions);

  // To fullscreen an |element| within a |document|, set the |element|'s
  // fullscreen flag and add it to |document|'s top layer.
  SetFullscreenFlag(element, request_type, options);
  document.AddToTopLayer(&element);

  DCHECK_EQ(&element, Fullscreen::FullscreenElementFrom(document));
  FullscreenElementChanged(document, old_element, &element, request_type,
                           options);
}

// https://fullscreen.spec.whatwg.org/#unfullscreen-an-element
void Unfullscreen(Element& element) {
  Document& document = element.GetDocument();
  Element* old_element = Fullscreen::FullscreenElementFrom(document);

  // To unfullscreen an |element| within a |document|, unset the element's
  // fullscreen flag and iframe fullscreen flag (if any), and remove it from
  // |document|'s top layer.
  DCHECK(element.IsInTopLayer());
  DCHECK(HasFullscreenFlag(element));
  UnsetFullscreenFlag(element);
  document.ScheduleForTopLayerRemoval(&element,
                                      Document::TopLayerReason::kFullscreen);

  // WebXR DOM Overlay mode doesn't allow changing the fullscreen element, this
  // is enforced in AllowedToRequestFullscreen. In this mode, unfullscreening
  // should only be happening via ExitFullscreen. This may involve previous
  // nested fullscreen elements being unfullscreened first, ignore those. This
  // matches kPseudoXrOverlay rules in SelectorChecker::CheckPseudoClass().
  if (document.IsXrOverlay() && element == old_element) {
    // If this was the active fullscreen element, we're exiting fullscreen mode,
    // and this also ends WebXR DOM Overlay mode.
    document.SetIsXrOverlay(false, &element);
  }

  Element* new_element = Fullscreen::FullscreenElementFrom(document);
  if (old_element != new_element) {
    FullscreenRequestType new_request_type;
    const FullscreenOptions* new_options;
    if (new_element) {
      const MetaParams* params = GetParams(*new_element);
      new_request_type = params->request_type();
      new_options = params->options();
    } else {
      new_request_type = FullscreenRequestType::kUnprefixed;
      new_options = FullscreenOptions::Create();
    }
    FullscreenElementChanged(document, old_element, new_element,
                             new_request_type, new_options);
  }
}

// https://fullscreen.spec.whatwg.org/#unfullscreen-a-document
void Unfullscreen(Document& document) {
  // To unfullscreen a |document|, unfullscreen all elements, within
  // |document|'s top layer, whose fullscreen flag is set.

  HeapVector<Member<Element>> fullscreen_elements;
  for (Element* element : document.TopLayerElements()) {
    if (HasFullscreenFlag(*element))
      fullscreen_elements.push_back(element);
  }

  for (Element* element : fullscreen_elements)
    Unfullscreen(*element);
}

// https://html.spec.whatwg.org/C/#allowed-to-use
bool AllowedToUseFullscreen(const Document& document,
                            ReportOptions report_on_failure) {
  // To determine whether a Document object |document| is allowed to use the
  // feature indicated by attribute name |allowattribute|, run these steps:

  // 1. If |document| has no browsing context, then return false.
  if (!document.GetFrame())
    return false;

  // 2. If Permissions Policy is enabled, return the policy for "fullscreen"
  // feature.
  return document.GetExecutionContext()->IsFeatureEnabled(
      mojom::blink::PermissionsPolicyFeature::kFullscreen, report_on_failure);
}

// https://fullscreen.spec.whatwg.org/#fullscreen-is-supported
bool FullscreenIsSupported(const Document& document) {
  LocalFrame* frame = document.GetFrame();
  if (!frame)
    return false;

  // Fullscreen is not currently supported in document pip.
  // TODO(crbug.com/1402928): Figure out the correct way of handling fullscreen
  // element in picture-in-picture window.
  if (RuntimeEnabledFeatures::DocumentPictureInPictureAPIEnabled(
          document.GetExecutionContext()) &&
      frame->LocalFrameRoot().DomWindow() &&
      frame->LocalFrameRoot().DomWindow()->IsPictureInPictureWindow()) {
    return false;
  }

  // Fullscreen is supported if there is no previously-established user
  // preference, security risk, or platform limitation.
  return !document.GetSettings() ||
         document.GetSettings()->GetFullscreenSupported();
}

// https://fullscreen.spec.whatwg.org/#fullscreen-element-ready-check
RequestFullscreenError FullscreenElementReadyCheck(
    const Element& element,
    ReportOptions report_on_failure) {
  // A fullscreen element ready check for an element `element` returns true if
  // all of the following are true, and false otherwise:

  // `element` is in a document.
  if (!element.isConnected())
    return RequestFullscreenError::kElementNotConnected;

  // `element`'s node document is allowed to use the "fullscreen" feature.
  if (!AllowedToUseFullscreen(element.GetDocument(), report_on_failure))
    return RequestFullscreenError::kDisallowedByPermissionsPolicy;

  // `element` namespace is not the HTML namespace or `element`’s popover
  // visibility state is hidden.
  if (auto* html_element = DynamicTo<HTMLElement>(element);
      html_element && html_element->popoverOpen()) {
    return RequestFullscreenError::kElementOpenAsPopover;
  }

  return RequestFullscreenError::kNone;
}

// RequestFullscreenScope is allocated at the top of |RequestFullscreen()| and
// used to avoid synchronously changing any state within that method, by
// deferring changes in |DidEnterFullscreen()|.
class RequestFullscreenScope {
  STACK_ALLOCATED();

 public:
  RequestFullscreenScope() {
    DCHECK(!running_request_fullscreen_);
    running_request_fullscreen_ = true;
  }
  RequestFullscreenScope(const RequestFullscreenScope&) = delete;
  RequestFullscreenScope& operator=(const RequestFullscreenScope&) = delete;

  ~RequestFullscreenScope() {
    DCHECK(running_request_fullscreen_);
    running_request_fullscreen_ = false;
  }

  static bool RunningRequestFullscreen() { return running_request_fullscreen_; }

 private:
  static bool running_request_fullscreen_;
};

bool RequestFullscreenScope::running_request_fullscreen_ = false;

// Walks the frame tree and returns the first local ancestor frame, if any.
LocalFrame* NextLocalAncestor(Frame& frame) {
  Frame* parent = frame.Tree().Parent();
  if (!parent)
    return nullptr;
  if (auto* parent_local_frame = DynamicTo<LocalFrame>(parent))
    return parent_local_frame;
  return NextLocalAncestor(*parent);
}

// Walks the document's frame tree and returns the document of the first local
// ancestor frame, if any.
Document* NextLocalAncestor(Document& document) {
  LocalFrame* frame = document.GetFrame();
  if (!frame)
    return nullptr;
  LocalFrame* next = NextLocalAncestor(*frame);
  if (!next)
    return nullptr;
  DCHECK(next->GetDocument());
  return next->GetDocument();
}

// Helper to walk the ancestor chain and return the Document of the topmost
// local ancestor frame. Note that this is not the same as the topmost frame's
// Document, which might be unavailable in OOPIF scenarios. For example, with
// OOPIFs, when called on the bottom frame's Document in a A-B-C-B hierarchy in
// process B, this will skip remote frame C and return this frame: A-[B]-C-B.
Document& TopmostLocalAncestor(Document& document) {
  if (Document* next = NextLocalAncestor(document))
    return TopmostLocalAncestor(*next);
  return document;
}

size_t CountFullscreenInTopLayer(const Document& document) {
  size_t count = 0;
  for (Element* element : document.TopLayerElements()) {
    if (HasFullscreenFlag(*element))
      ++count;
  }
  return count;
}

// https://fullscreen.spec.whatwg.org/#simple-fullscreen-document
bool IsSimpleFullscreenDocument(const Document& document) {
  return CountFullscreenInTopLayer(document) == 1;
}

// https://fullscreen.spec.whatwg.org/#collect-documents-to-unfullscreen
HeapVector<Member<Document>> CollectDocumentsToUnfullscreen(Document& doc) {
  // 1. Let |docs| be an ordered set consisting of |doc|.
  HeapVector<Member<Document>> docs;
  docs.push_back(&doc);

  // 2. While true:
  for (Document* lastDoc = &doc;;) {
    // 2.1. Let |lastDoc| be |docs|'s last document.

    // 2.2. Assert: |lastDoc|'s fullscreen element is not null.
    DCHECK(Fullscreen::FullscreenElementFrom(*lastDoc));

    // 2.3. If |lastDoc| is not a simple fullscreen document, break.
    if (!IsSimpleFullscreenDocument(*lastDoc))
      break;

    // 2.4. Let |container| be |lastDoc|'s browsing context container, if any,
    // and otherwise break.
    //
    // OOPIF: Skip over remote frames, assuming that they have exactly one
    // element in their fullscreen element stacks, thereby erring on the side of
    // exiting fullscreen. TODO(alexmos): Deal with nested fullscreen cases, see
    // https://crbug.com/617369.
    lastDoc = NextLocalAncestor(*lastDoc);
    if (!lastDoc)
      break;

    // 2.5. If |container|'s iframe fullscreen flag is set, break.
    // TODO(foolip): Support the iframe fullscreen flag.
    // https://crbug.com/644695

    // 2.6. Append |container|'s node document to |docs|.
    docs.push_back(lastDoc);
  }

  // 3. Return |docs|.
  return docs;
}

// https://fullscreen.spec.whatwg.org/#run-the-fullscreen-rendering-steps
void FireEvent(const AtomicString& type, Element* element, Document* document) {
  if (!document || !element)
    return;

  // |Document::EnqueueAnimationFrameTask()| is used instead of a "list of
  // pending fullscreen events", so only the body of the "run the fullscreen
  // rendering steps" loop appears here:

  // 3.1. Let |target| be |element| if |element| is connected and its node
  // document is |document|, and otherwise let |target| be |document|.
  EventTarget* target =
      element->isConnected() && &element->GetDocument() == document
          ? static_cast<EventTarget*>(element)
          : static_cast<EventTarget*>(document);

  // 3.2. Fire an event named |type|, with its bubbles and composed attributes
  // set to true, at |target|.
  Event* event = Event::CreateBubble(type);
  event->SetComposed(true);
  target->DispatchEvent(*event);
}

const AtomicString& AdjustEventType(const AtomicString& type,
                                    FullscreenRequestType request_type) {
  DCHECK(type == event_type_names::kFullscreenchange ||
         type == event_type_names::kFullscreenerror);

  if (!(request_type & FullscreenRequestType::kPrefixed))
    return type;
  return type == event_type_names::kFullscreenchange
             ? event_type_names::kWebkitfullscreenchange
             : event_type_names::kWebkitfullscreenerror;
}

void EnqueueEvent(const AtomicString& type,
                  Element& element,
                  Document& document,
                  FullscreenRequestType request_type) {
  const AtomicString& adjusted_type = AdjustEventType(type, request_type);
  document.EnqueueAnimationFrameTask(
      WTF::BindOnce(FireEvent, adjusted_type, WrapWeakPersistent(&element),
                    WrapWeakPersistent(&document)));
}

const char* GetErrorString(RequestFullscreenError error) {
  switch (error) {
    case RequestFullscreenError::kNone:
      NOTREACHED();
    case RequestFullscreenError::kElementTypeNotHTMLNorSVG:
      return "Element is not an HTML or SVG element";
    case RequestFullscreenError::kElementTypeDialog:
      return "Dialog elements are invalid";
    case RequestFullscreenError::kElementNotConnected:
      return "Element is not connected";
    case RequestFullscreenError::kDisallowedByPermissionsPolicy:
      return "Disallowed by permissions policy";
    case RequestFullscreenError::kElementOpenAsPopover:
      return "The element is already open as a Popover, and therefore cannot "
             "be opened via the fullscreen API.";
    case RequestFullscreenError::kFullscreenNotSupported:
      return "Fullscreen is not supported";
    case RequestFullscreenError::kPermissionCheckFailed:
      return "Permissions check failed";
    case RequestFullscreenError::kDocumentIncorrect:
      return "Incorrect document";
    case RequestFullscreenError::kNotGranted:
      return "not granted";
  }
}

}  // anonymous namespace

const char Fullscreen::kSupplementName[] = "Fullscreen";

Fullscreen& Fullscreen::From(LocalDOMWindow& window) {
  Fullscreen* fullscreen = Supplement<LocalDOMWindow>::From<Fullscreen>(window);
  if (!fullscreen) {
    fullscreen = MakeGarbageCollected<Fullscreen>(window);
    ProvideTo(window, fullscreen);
  }
  return *fullscreen;
}

// static
bool Fullscreen::HasFullscreenElements() {
  return !FullscreenParamsMap().empty();
}

Element* Fullscreen::FullscreenElementFrom(Document& document) {
  // The fullscreen element is the topmost element in the document's top layer
  // whose fullscreen flag is set, if any, and null otherwise.

  const auto& elements = document.TopLayerElements();
  for (const auto& element : base::Reversed(elements)) {
    if (HasFullscreenFlag(*element))
      return element.Get();
  }

  return nullptr;
}

// https://fullscreen.spec.whatwg.org/#fullscreen-element
Element* Fullscreen::FullscreenElementForBindingFrom(TreeScope& scope) {
  Element* element = FullscreenElementFrom(scope.GetDocument());
  if (!element)
    return nullptr;
  return scope.AdjustedElement(*element);
}

bool Fullscreen::IsInFullscreenElementStack(const Element& element) {
  return HasFullscreenFlag(const_cast<Element&>(element));
}

Fullscreen::Fullscreen(LocalDOMWindow& window)
    : Supplement<LocalDOMWindow>(window),
      ExecutionContextLifecycleObserver(&window) {}

Fullscreen::~Fullscreen() = default;

void Fullscreen::ContextDestroyed() {
  pending_requests_.clear();
  pending_exits_.clear();
}

// https://fullscreen.spec.whatwg.org/#dom-element-requestfullscreen
void Fullscreen::RequestFullscreen(Element& pending) {
  FullscreenOptions* options = FullscreenOptions::Create();
  options->setNavigationUI("hide");
  RequestFullscreen(pending, options, FullscreenRequestType::kUnprefixed);
}

ScriptPromise<IDLUndefined> Fullscreen::RequestFullscreen(
    Element& pending,
    const FullscreenOptions* options,
    FullscreenRequestType request_type,
    ScriptState* script_state,
    ExceptionState* exception_state) {
  RequestFullscreenScope scope;

  // 1. Let `pendingDoc` be `this`'s node document.
  // The context object for `this` comes from `pending`.
  Document& document = pending.GetDocument();

  // 2. Let `promise` be a new promise.
  // For optimization allocate the ScriptPromiseResolver later.
  ScriptPromiseResolver<IDLUndefined>* resolver = nullptr;

  // 3. If `pendingDoc` is not fully active, then reject `promise` with a
  // TypeError exception and return `promise`.
  if (!document.IsActive() || !document.GetFrame()) {
    if (!exception_state)
      return EmptyPromise();
    exception_state->ThrowTypeError("Document not active");
    return EmptyPromise();
  }

  if (script_state) {
    // We should only be creating promises for unprefixed variants.
    DCHECK(!(request_type & FullscreenRequestType::kPrefixed));
    resolver =
        MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  }

  bool for_cross_process_descendant =
      request_type & FullscreenRequestType::kForCrossProcessDescendant;

  // Only increment use counters in the actual fullscreen element's process.
  LocalDOMWindow& window = *document.domWindow();
  if (!for_cross_process_descendant) {
    if (window.IsSecureContext())
      UseCounter::Count(window, WebFeature::kFullscreenSecureOrigin);
    else
      UseCounter::Count(window, WebFeature::kFullscreenInsecureOrigin);
    // Coarsely measure whether this request may be specifying another screen.
    if (options->hasScreen())
      UseCounter::Count(window, WebFeature::kFullscreenCrossScreen);
  }

  // 4. Let `error` be false.
  RequestFullscreenError error = RequestFullscreenError::kNone;

  // 5. If any of the following conditions are false, then set `error` to true:
  // OOPIF: If `RequestFullscreen()` was already called in a descendant frame
  // and passed the conditions enforcement, do not check again here.
  if (for_cross_process_descendant) {
    ContinueRequestFullscreenAfterConditionsEnforcement(
        &pending, request_type, options, resolver, error);
  } else {
    EnforceRequestFullscreenConditions(
        pending, document,
        WTF::BindOnce(
            &Fullscreen::ContinueRequestFullscreenAfterConditionsEnforcement,
            WrapPersistent(&pending), request_type, WrapPersistent(options),
            WrapPersistent(resolver)));
  }

  // 7. Return |promise|, and run the remaining steps in parallel.
  return resolver ? resolver->Promise() : ScriptPromise<IDLUndefined>();
}

void Fullscreen::EnforceRequestFullscreenConditions(
    Element& pending,
    Document& document,
    base::OnceCallback<void(RequestFullscreenError)> callback) {
  // This’s namespace is the HTML namespace or this is an SVG svg or MathML math
  // element.
  if (!pending.IsHTMLElement() && !IsA<SVGSVGElement>(pending)) {
    std::move(callback).Run(RequestFullscreenError::kElementTypeNotHTMLNorSVG);
    return;
  }

  // This is not a dialog element.
  if (IsA<HTMLDialogElement>(pending)) {
    std::move(callback).Run(RequestFullscreenError::kElementTypeDialog);
    return;
  }

  // The fullscreen element ready check for this returns true.
  RequestFullscreenError ready_error =
      FullscreenElementReadyCheck(pending, ReportOptions::kReportOnFailure);
  if (ready_error != RequestFullscreenError::kNone) {
    std::move(callback).Run(ready_error);
    return;
  }

  // Fullscreen is supported.
  if (!FullscreenIsSupported(document)) {
    std::move(callback).Run(RequestFullscreenError::kFullscreenNotSupported);
    return;
  }

  //  WebXR DOM Overlay integration, cf.
  //  https://immersive-web.github.io/dom-overlays/
  //
  // The current implementation of WebXR's "dom-overlay" mode internally uses
  // the Fullscreen API to show a single DOM element based on configuration at
  // XR session start. In addition, for WebXR sessions without "dom-overlay"
  // the renderer may need to force the page to fullscreen to ensure that
  // browser UI hides/responds accordingly. In either case, requesting a WebXR
  // Session does require a user gesture, but it has likely expired by the time
  // the renderer actually gets the XR session from the device and attempts
  // to fullscreen the page.
  if (ScopedAllowFullscreen::FullscreenAllowedReason() ==
          ScopedAllowFullscreen::kXrOverlay ||
      ScopedAllowFullscreen::FullscreenAllowedReason() ==
          ScopedAllowFullscreen::kXrSession) {
    DVLOG(1) << __func__ << ": allowing fullscreen element setup for XR";
    std::move(callback).Run(RequestFullscreenError::kNone);
    return;
  }

  // The WebXR API doesn't support changing elements during the session if the
  // dom-overlay feature is in use (indicated by the IsXrOverlay property). To
  // avoid inconsistencies between implementations we need to block changes via
  // Fullscreen API while the XR session is active, while still allowing the XR
  // code to set up fullscreen mode on session start.
  if (document.IsXrOverlay()) {
    DVLOG(1) << __func__
             << ": rejecting change of fullscreen element for XR DOM overlay";
    std::move(callback).Run(RequestFullscreenError::kPermissionCheckFailed);
    return;
  }

  // An algorithm is allowed to request fullscreen if one of the following is
  // true:

  // The algorithm is triggered by a user activation.
  if (LocalFrame::HasTransientUserActivation(document.GetFrame())) {
    std::move(callback).Run(RequestFullscreenError::kNone);
    return;
  }

  // The algorithm is triggered by a fullscreen request capability delegation.
  if (document.domWindow()->IsFullscreenRequestTokenActive()) {
    std::move(callback).Run(RequestFullscreenError::kNone);
    return;
  }

  // The algorithm is triggered by a user-generated orientation change.
  if (ScopedAllowFullscreen::FullscreenAllowedReason() ==
      ScopedAllowFullscreen::kOrientationChange) {
    UseCounter::Count(document,
                      WebFeature::kFullscreenAllowedByOrientationChange);
    std::move(callback).Run(RequestFullscreenError::kNone);
    return;
  }

  // The context has permission to use fullscreen without transient activation,
  // and no blocking cooldown period is in effect from a recent fullscreen exit.
  //
  // The supplement may be null before this window ever enters fullscreen, but
  // the browser enforces broader per-origin cooldowns with FullscreenUserData.
  if (Fullscreen* fullscreen =
          Supplement<LocalDOMWindow>::From<Fullscreen>(*document.domWindow());
      fullscreen && base::TimeTicks::Now() <=
                        fullscreen->block_automatic_fullscreen_until()) {
    std::move(callback).Run(RequestFullscreenError::kPermissionCheckFailed);
    return;
  }

  // Check permission and wait for the async result.
  auto* permission_service =
      document.GetPermissionService(document.GetExecutionContext());
  CHECK(permission_service);
  auto descriptor = mojom::blink::PermissionDescriptor::New();
  descriptor->name = mojom::blink::PermissionName::FULLSCREEN;
  descriptor->extension =
      mojom::blink::PermissionDescriptorExtension::NewFullscreen(
          mojom::blink::FullscreenPermissionDescriptor::New(
              /*allow_without_user_gesture=*/true));
  permission_service->HasPermission(
      std::move(descriptor),
      WTF::BindOnce(
          [](base::OnceCallback<void(RequestFullscreenError)> callback,
             Document* document, mojom::blink::PermissionStatus status) {
            if (status == mojom::blink::PermissionStatus::GRANTED) {
              UseCounter::Count(document,
                                WebFeature::kFullscreenAllowedByContentSetting);
              std::move(callback).Run(RequestFullscreenError::kNone);
            } else {
              std::move(callback).Run(
                  RequestFullscreenError::kPermissionCheckFailed);
            }
          },
          std::move(callback), WrapPersistent(&document)));
}

void Fullscreen::ContinueRequestFullscreenAfterConditionsEnforcement(
    Element* pending,
    FullscreenRequestType request_type,
    const FullscreenOptions* options,
    ScriptPromiseResolver<IDLUndefined>* resolver,
    RequestFullscreenError error) {
  CHECK(pending);
  Document& document =
"""


```