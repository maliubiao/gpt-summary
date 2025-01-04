Response:
The user is asking for a summary of the functionality of the provided C++ code snippet, which is part of the Chromium Blink rendering engine and defines the `HTMLFencedFrameElement` class. I need to identify the key responsibilities of this class, particularly as they relate to HTML, CSS, and JavaScript, and look for examples of logical reasoning or potential user/developer errors.

**Plan:**

1. **Identify Core Functionality:** Read through the code and comments to understand the main purpose of `HTMLFencedFrameElement`. It appears to be related to embedding isolated content.
2. **HTML Relationship:** Look for interactions with HTML elements and attributes. The code mentions `<iframe>`, `sandbox`, `allow`, `width`, `height`, suggesting it implements the `<fencedframe>` HTML element.
3. **CSS Relationship:**  See if the code manipulates or interacts with CSS properties or styling. The `CollectStyleForPresentationAttribute` and `AddHTMLLengthToStyle` methods suggest CSS interaction.
4. **JavaScript Relationship:** Look for methods callable from JavaScript or interactions with the JavaScript environment (e.g., `ScriptState`). The `canLoadOpaqueURL` function is a clear example.
5. **Logical Reasoning:**  Identify any conditional logic or decision-making within the code, and try to infer the inputs and outputs of these decisions. The size coercion logic is a good candidate.
6. **User/Developer Errors:**  Look for checks or warnings that indicate potential misuse or common mistakes. The `sandbox` attribute parsing and the URL validation seem relevant.
7. **Summarize Functionality:**  Consolidate the findings into a concise description of the class's role.
这是 `blink/renderer/core/html/fenced_frame/html_fenced_frame_element.cc` 文件的第一部分，主要定义了 `HTMLFencedFrameElement` 类的实现。`HTMLFencedFrameElement` 类是 Chromium Blink 引擎中用于表示 `<fencedframe>` HTML 元素的 C++ 类。 fenced frames 提供了一种嵌入内容的方式，该内容与其嵌入器具有隔离的渲染和数据。

**主要功能归纳:**

1. **实现 `<fencedframe>` HTML 元素:**  这个类是 `<fencedframe>` 标签在 Blink 渲染引擎中的具体实现，负责处理该元素相关的行为和属性。

2. **内容隔离和管理:**  核心目标是管理 fenced frame 中加载的内容，确保其与嵌入页面隔离。这包括：
    * **代理 (Delegate):** 使用 `FencedFrameDelegate` 来处理与实际帧加载和渲染相关的复杂逻辑。
    * **配置 (Config):**  通过 `FencedFrameConfig` 对象来配置 fenced frame 的行为，例如加载的 URL、是否冻结初始大小等。
    * **导航 (Navigation):**  提供 `Navigate` 和 `NavigateToConfig` 方法来加载内容到 fenced frame 中。
    * **销毁 (DisconnectContentFrame):**  提供方法来断开和清理 fenced frame 中加载的帧。

3. **处理 `sandbox` 属性:**  实现了对 `<fencedframe>` 元素上 `sandbox` 属性的处理，包括解析属性值、应用沙箱标志，并记录使用情况。

4. **处理 `allow` 属性:**  实现了对 `<fencedframe>` 元素上 `allow` 属性（用于权限策略）的处理。

5. **尺寸控制和调整:**
    * **尺寸限制 (Opaque Ads 模式):**  对于特定模式 (例如 `opaque-ads`) 的 fenced frame，会强制执行预定义的尺寸列表，并提供尺寸强制逻辑 (`CoerceFrameSize`)，将请求的尺寸调整到最接近的允许尺寸。
    * **尺寸冻结 (Size Freezing):**  支持在导航开始时冻结 fenced frame 的尺寸，以防止在内容加载时发生布局抖动。提供了 `FreezeCurrentFrameSize` 和 `UnfreezeFrameSize` 等方法。
    * **容器尺寸设置:**  允许通过 `SetContainerSize` 方法设置 fenced frame 的外部尺寸。
    * **Resize Observer:** 使用 `ResizeObserver` 监听 fenced frame 自身尺寸的变化，并在尺寸变化时执行相应的操作。

6. **与父页面的有限交互:**  通过 `DispatchFencedEvent` 方法，允许 fenced frame 向父页面发送特定类型的事件，以实现有限的跨隔离边界的通信。

7. **与安全相关的处理:**
    * **安全上下文检查:**  在导航时会检查当前页面是否处于安全上下文 (HTTPS)。
    * **URL 类型检查:**  确保 fenced frame 导航到允许的 URL 类型 (例如 HTTPS, localhost HTTP, `about:blank`, `urn:uuid`)。
    * **CSP (内容安全策略) 交互:**  检查父页面的 CSP 是否允许加载 fenced frame 的内容，特别是在 `opaque-ads` 模式下。

8. **性能优化 (尺寸冻结):** 通过冻结尺寸来优化渲染性能，避免在内容加载过程中发生不必要的重排和重绘。

**与 JavaScript, HTML, CSS 的关系和举例说明:**

* **HTML:**
    * **元素实现:**  `HTMLFencedFrameElement` 类直接对应于 HTML 中的 `<fencedframe>` 标签。
    * **属性处理:**  代码中解析和处理了 `<fencedframe>` 的 `sandbox` 和 `allow` 等属性。
        * **示例:** 当 HTML 中存在 `<fencedframe sandbox="allow-scripts">` 时，`ParseAttribute` 方法会被调用，解析 `sandbox` 属性，并设置相应的沙箱标志。
    * **尺寸属性:**  代码处理了 `width` 和 `height` 属性，影响 fenced frame 的布局。
        * **示例:** `<fencedframe width="300px" height="250px">` 会导致 `CollectStyleForPresentationAttribute` 被调用，将这些值转换为 CSS 样式。

* **CSS:**
    * **样式应用:**  通过 `CollectStyleForPresentationAttribute` 方法，将 HTML 属性（如 `width` 和 `height`）转换为 CSS 属性并应用到 fenced frame。
    * **布局影响:**  `HTMLFencedFrameElement` 创建 `LayoutIFrame` 对象，最终影响 fenced frame 在页面上的布局。
    * **尺寸冻结影响:**  尺寸冻结会影响 fenced frame 的渲染尺寸，这可以通过 CSS 观察到。

* **JavaScript:**
    * **API 提供:**  `canLoadOpaqueURL` 是一个可以从 JavaScript 调用的静态方法，用于检查当前环境是否允许加载 `opaque-ads` 模式的 fenced frame。
        * **假设输入:** 在 JavaScript 中调用 `HTMLFencedFrameElement.canLoadOpaqueURL()`.
        * **输出:**  返回 `true` 或 `false`，指示是否允许加载该类型的 fenced frame。
    * **事件分发:**  `DispatchFencedEvent` 方法允许 fenced frame 向父页面发送事件，父页面可以使用 JavaScript 监听这些事件。
        * **假设输入:**  在 fenced frame 内部的 JavaScript 中触发了一个需要通知父页面的事件。
        * **输出:** 父页面的 JavaScript 代码可以捕获到名为 `fencedtreeclick` (或其他转换后的 fenced event 类型) 的事件。
    * **配置对象:**  可以通过 JavaScript 创建 `FencedFrameConfig` 对象，并将其赋值给 `<fencedframe>` 元素的 `config` 属性，从而控制 fenced frame 的行为。

**逻辑推理举例说明:**

* **尺寸强制逻辑 (Opaque Ads 模式):**
    * **假设输入:**  一个 `opaque-ads` 模式的 fenced frame 尝试加载，其请求的尺寸为 200x100px。 允许的尺寸列表中包含 300x250px 和 160x600px。
    * **输出:** `ComputeSizeLossFunction` 会计算请求尺寸与允许尺寸之间的损失分数。假设 300x250px 的损失分数较低，则 `CoerceFrameSize` 方法将返回 `PhysicalSize(300, 250)`，强制 fenced frame 使用该尺寸。

**用户或编程常见的使用错误举例说明:**

* **在不安全上下文中使用 fenced frame:**  如果开发者尝试在非 HTTPS 页面中使用 `<fencedframe>`，控制台会输出警告信息，并且 fenced frame 将无法加载。
* **导航到不允许的 URL 类型:**  如果开发者尝试将 fenced frame 导航到一个非 HTTPS、非 localhost HTTP、非 `about:blank` 或非 `urn:uuid` 的 URL，控制台会输出警告信息，并且导航会失败。
* **不正确的 `sandbox` 属性值:**  如果 `sandbox` 属性的值包含语法错误或不被支持的标志，控制台会输出错误信息。
* **在嵌套的 fenced frame 中使用不兼容的模式:** 如果父 fenced frame 和子 fenced frame 使用不同的 `DeprecatedFencedFrameMode` (例如父级是默认模式，子级是 `opaque-ads` 模式)，则子 fenced frame 将无法加载，并会输出警告信息。
* **在设置了强制沙箱标志的情况下尝试通过 embedder 进行导航:** 如果 fenced frame 的 `sandbox` 属性没有设置允许 embedder 导航所需的标志 (例如 `allow-same-origin`, `allow-forms`, `allow-scripts` 等)，则尝试通过 JavaScript 设置 `src` 属性进行导航将会失败，并输出警告信息。

总而言之，`HTMLFencedFrameElement` 类的第一部分主要负责 fenced frame 元素的基础生命周期管理、属性处理、尺寸控制以及与安全和导航相关的核心功能实现。它作为 Blink 渲染引擎中 `<fencedframe>` 标签的具象化，连接了 HTML 结构、CSS 样式和 JavaScript 交互，并确保了 fenced frame 内容的隔离性和安全性。

Prompt: 
```
这是目录为blink/renderer/core/html/fenced_frame/html_fenced_frame_element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/html/fenced_frame/html_fenced_frame_element.h"

#include "base/metrics/histogram_macros.h"
#include "base/types/pass_key.h"
#include "mojo/public/cpp/bindings/associated_remote.h"
#include "services/network/public/cpp/is_potentially_trustworthy.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/fenced_frame/fenced_frame_utils.h"
#include "third_party/blink/public/common/frame/fenced_frame_sandbox_flags.h"
#include "third_party/blink/public/mojom/devtools/console_message.mojom-blink.h"
#include "third_party/blink/public/mojom/fenced_frame/fenced_frame.mojom-blink.h"
#include "third_party/blink/public/mojom/frame/frame.mojom-blink.h"
#include "third_party/blink/public/mojom/use_counter/metrics/web_feature.mojom-blink.h"
#include "third_party/blink/renderer/core/css/style_change_reason.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/event_type_names.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/csp/content_security_policy.h"
#include "third_party/blink/renderer/core/frame/csp/csp_directive_list.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/frame/remote_frame.h"
#include "third_party/blink/renderer/core/frame/screen.h"
#include "third_party/blink/renderer/core/geometry/dom_rect_read_only.h"
#include "third_party/blink/renderer/core/html/fenced_frame/document_fenced_frames.h"
#include "third_party/blink/renderer/core/html/fenced_frame/fenced_frame_ad_sizes.h"
#include "third_party/blink/renderer/core/html/html_iframe_element.h"
#include "third_party/blink/renderer/core/html/html_style_element.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/layout/layout_iframe.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/resize_observer/resize_observer_entry.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"

namespace blink {

namespace {

PhysicalRect ToPhysicalRect(const DOMRectReadOnly& rect) {
  return PhysicalRect(LayoutUnit::FromDoubleRound(rect.x()),
                      LayoutUnit::FromDoubleRound(rect.y()),
                      LayoutUnit::FromDoubleRound(rect.width()),
                      LayoutUnit::FromDoubleRound(rect.height()));
}

String DeprecatedFencedFrameModeToString(
    blink::FencedFrame::DeprecatedFencedFrameMode mode) {
  switch (mode) {
    case blink::FencedFrame::DeprecatedFencedFrameMode::kDefault:
      return "default";
    case blink::FencedFrame::DeprecatedFencedFrameMode::kOpaqueAds:
      return "opaque-ads";
  }

  NOTREACHED();
}

// Helper function that returns whether the mode of the parent tree is different
// than the mode given to the function. Note that this function will return
// false if there is no mode set in the parent tree (i.e. not in a fenced frame
// tree).
bool ParentModeIsDifferent(
    blink::FencedFrame::DeprecatedFencedFrameMode current_mode,
    LocalFrame& frame) {
  Page* ancestor_page = frame.GetPage();
  return ancestor_page->IsMainFrameFencedFrameRoot() &&
         ancestor_page->DeprecatedFencedFrameMode() != current_mode;
}

bool HasDifferentModeThanParent(HTMLFencedFrameElement& outer_element) {
  return ParentModeIsDifferent(outer_element.GetDeprecatedMode(),
                               *(outer_element.GetDocument().GetFrame()));
}

// Returns whether `requested_size` is exactly the same size as `allowed_size`.
// `requested_size` and `allowed_size` should both be in CSS pixel units.
bool SizeMatchesExactly(const PhysicalSize& requested_size,
                        const gfx::Size& allowed_size) {
  // The comparison must be performed as a `PhysicalSize`, in order to use
  // its fixed point representation and get exact results.
  return requested_size == PhysicalSize(allowed_size);
}

// Returns a loss score (higher is worse) comparing the fit between
// `requested_size` and `allowed_size`.
// Both sizes should be in CSS pixel units.
double ComputeSizeLossFunction(const PhysicalSize& requested_size,
                               const gfx::Size& allowed_size) {
  const double requested_width = requested_size.width.ToDouble();
  const double requested_height = requested_size.height.ToDouble();

  const double allowed_width = allowed_size.width();
  const double allowed_height = allowed_size.height();

  const double allowed_area = allowed_width * allowed_height;
  const double requested_area = requested_width * requested_height;

  // Calculate the fraction of the outer container that is wasted when the
  // allowed inner frame size is scaled to fit inside of it.
  const double scale_x = allowed_width / requested_width;
  const double scale_y = allowed_height / requested_height;

  const double wasted_area =
      scale_x < scale_y
          ? allowed_width * (allowed_height - (scale_x * requested_height))
          : allowed_height * (allowed_width - (scale_y * requested_width));

  const double wasted_area_fraction = wasted_area / allowed_area;

  // Calculate a penalty to tie-break between allowed sizes with the same
  // aspect ratio in favor of resolutions closer to the requested one.
  const double resolution_penalty =
      std::abs(1 - std::min(requested_area, allowed_area) /
                       std::max(requested_area, allowed_area));

  return wasted_area_fraction + resolution_penalty;
}

std::optional<WTF::AtomicString> ConvertEventTypeToFencedEventType(
    const WTF::String& event_type) {
  if (!CanNotifyEventTypeAcrossFence(event_type.Ascii())) {
    return std::nullopt;
  }

  return event_type_names::kFencedtreeclick;
}

}  // namespace

HTMLFencedFrameElement::HTMLFencedFrameElement(Document& document)
    : HTMLFrameOwnerElement(html_names::kFencedframeTag, document),
      sandbox_(MakeGarbageCollected<HTMLIFrameElementSandbox>(this)) {
  DCHECK(RuntimeEnabledFeatures::FencedFramesEnabled(GetExecutionContext()));
  UseCounter::Count(document, WebFeature::kHTMLFencedFrameElement);
  StartResizeObserver();
}

HTMLFencedFrameElement::~HTMLFencedFrameElement() = default;

void HTMLFencedFrameElement::Trace(Visitor* visitor) const {
  HTMLFrameOwnerElement::Trace(visitor);
  visitor->Trace(frame_delegate_);
  visitor->Trace(resize_observer_);
  visitor->Trace(config_);
  visitor->Trace(sandbox_);
}

DOMTokenList* HTMLFencedFrameElement::sandbox() const {
  return sandbox_.Get();
}

void HTMLFencedFrameElement::DisconnectContentFrame() {
  DCHECK(!GetDocument().IsPrerendering());

  // The `frame_delegate_` will not exist if the element was not allowed to
  // create its underlying frame at insertion-time.
  if (frame_delegate_) {
    frame_delegate_->Dispose();
  }
  frame_delegate_ = nullptr;

  HTMLFrameOwnerElement::DisconnectContentFrame();
}

ParsedPermissionsPolicy HTMLFencedFrameElement::ConstructContainerPolicy()
    const {
  if (!GetExecutionContext()) {
    return ParsedPermissionsPolicy();
  }

  scoped_refptr<const SecurityOrigin> src_origin =
      GetOriginForPermissionsPolicy();
  scoped_refptr<const SecurityOrigin> self_origin =
      GetExecutionContext()->GetSecurityOrigin();

  PolicyParserMessageBuffer logger;

  ParsedPermissionsPolicy container_policy =
      PermissionsPolicyParser::ParseAttribute(allow_, self_origin, src_origin,
                                              logger, GetExecutionContext());

  for (const auto& message : logger.GetMessages()) {
    GetDocument().AddConsoleMessage(
        MakeGarbageCollected<ConsoleMessage>(
            mojom::blink::ConsoleMessageSource::kOther, message.level,
            message.content),
        /* discard_duplicates */ true);
  }

  return container_policy;
}

void HTMLFencedFrameElement::SetCollapsed(bool collapse) {
  if (collapsed_by_client_ == collapse) {
    return;
  }

  collapsed_by_client_ = collapse;

  // This is always called in response to an IPC, so should not happen in the
  // middle of a style recalc.
  DCHECK(!GetDocument().InStyleRecalc());

  // Trigger style recalc to trigger layout tree re-attachment.
  SetNeedsStyleRecalc(kLocalStyleChange, StyleChangeReasonForTracing::Create(
                                             style_change_reason::kFrame));
}

void HTMLFencedFrameElement::DidChangeContainerPolicy() {
  // Don't notify about updates if frame_delegate_ is null, for example when
  // the delegate hasn't been created yet.
  if (frame_delegate_) {
    frame_delegate_->DidChangeFramePolicy(GetFramePolicy());
  }
}

HTMLIFrameElement* HTMLFencedFrameElement::InnerIFrameElement() const {
  if (const ShadowRoot* root = UserAgentShadowRoot())
    return To<HTMLIFrameElement>(root->lastChild());
  return nullptr;
}

void HTMLFencedFrameElement::setConfig(FencedFrameConfig* config) {
  config_ = config;

  if (config_) {
    NavigateToConfig();
  } else {
    Navigate(BlankURL());
  }
}

// static
bool HTMLFencedFrameElement::canLoadOpaqueURL(ScriptState* script_state) {
  if (!script_state->ContextIsValid())
    return false;

  LocalDOMWindow::From(script_state)
      ->document()
      ->AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
          mojom::blink::ConsoleMessageSource::kJavaScript,
          mojom::blink::ConsoleMessageLevel::kWarning,
          "HTMLFencedFrameElement.canLoadOpaqueURL() is deprecated and will be "
          "removed. Please use navigator.canLoadAdAuctionFencedFrame() "
          "instead."));

  UseCounter::Count(LocalDOMWindow::From(script_state)->document(),
                    WebFeature::kFencedFrameCanLoadOpaqueURL);

  LocalFrame* frame_to_check = LocalDOMWindow::From(script_state)->GetFrame();
  ExecutionContext* context = ExecutionContext::From(script_state);
  DCHECK(frame_to_check && context);

  // "A fenced frame tree of one mode cannot contain a child fenced frame of
  // another mode."
  // See: https://github.com/WICG/fenced-frame/blob/master/explainer/modes.md
  // TODO(lbrady) Link to spec once it's written.
  if (ParentModeIsDifferent(
          blink::FencedFrame::DeprecatedFencedFrameMode::kOpaqueAds,
          *frame_to_check)) {
    return false;
  }

  if (!context->IsSecureContext())
    return false;

  // Check that the flags specified in kFencedFrameMandatoryUnsandboxedFlags
  // are not set in this context. Fenced frames loaded in a sandboxed document
  // require these flags to remain unsandboxed.
  if (context->IsSandboxed(kFencedFrameMandatoryUnsandboxedFlags))
    return false;

  // Check the results of the browser checks for the current frame.
  // If the embedding frame is an iframe with CSPEE set, or any ancestor
  // iframes has CSPEE set, the fenced frame will not be allowed to load.
  // The renderer has no knowledge of CSPEE up the ancestor chain, so we defer
  // to the browser to determine the existence of CSPEE outside of the scope
  // we can see here.
  if (frame_to_check->AncestorOrSelfHasCSPEE())
    return false;

  // Ensure that if any CSP headers are set that will affect a fenced frame,
  // they allow all https urls to load. Opaque-ads fenced frames do not support
  // allowing/disallowing specific hosts, as that could reveal information to
  // a fenced frame about its embedding page. See design doc for more info:
  // https://github.com/WICG/fenced-frame/blob/master/explainer/interaction_with_content_security_policy.md
  // This is being checked in the renderer because processing of <meta> tags
  // (including CSP) happen in the renderer after navigation commit, so we can't
  // piggy-back off of the ancestor_or_self_has_cspee bit being sent from the
  // browser (which is sent at commit time) since it doesn't know about all the
  // CSP headers yet.
  ContentSecurityPolicy* csp = context->GetContentSecurityPolicy();
  DCHECK(csp);
  if (!csp->AllowFencedFrameOpaqueURL()) {
    return false;
  }

  return true;
}

Node::InsertionNotificationRequest HTMLFencedFrameElement::InsertedInto(
    ContainerNode& insertion_point) {
  HTMLFrameOwnerElement::InsertedInto(insertion_point);
  return kInsertionShouldCallDidNotifySubtreeInsertions;
}

void HTMLFencedFrameElement::DidNotifySubtreeInsertionsToDocument() {
  CreateDelegateAndNavigate();
}

void HTMLFencedFrameElement::RemovedFrom(ContainerNode& node) {
  // Verify that the underlying frame has already been disconnected via
  // `DisconnectContentFrame()`. This is only relevant for the MPArch
  // implementation.
  DCHECK_EQ(ContentFrame(), nullptr);
  HTMLFrameOwnerElement::RemovedFrom(node);
}

void HTMLFencedFrameElement::ParseAttribute(
    const AttributeModificationParams& params) {
  if (params.name == html_names::kSandboxAttr) {
    sandbox_->DidUpdateAttributeValue(params.old_value, params.new_value);

    network::mojom::blink::WebSandboxFlags current_flags =
        network::mojom::blink::WebSandboxFlags::kNone;
    if (!params.new_value.IsNull()) {
      using network::mojom::blink::WebSandboxFlags;
      auto parsed = network::ParseWebSandboxPolicy(sandbox_->value().Utf8(),
                                                   WebSandboxFlags::kNone);
      current_flags = parsed.flags;
      if (!parsed.error_message.empty()) {
        GetDocument().AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
            mojom::blink::ConsoleMessageSource::kOther,
            mojom::blink::ConsoleMessageLevel::kError,
            "Error while parsing the 'sandbox' attribute: " +
                String::FromUTF8(parsed.error_message)));
      }
    }
    SetSandboxFlags(current_flags);
    UseCounter::Count(GetDocument(), WebFeature::kSandboxViaFencedFrame);
  } else if (params.name == html_names::kAllowAttr) {
    if (allow_ != params.new_value) {
      allow_ = params.new_value;
      if (!params.new_value.empty()) {
        UseCounter::Count(GetDocument(),
                          WebFeature::kFeaturePolicyAllowAttribute);
      }
    }
  } else {
    HTMLFrameOwnerElement::ParseAttribute(params);
  }
}

bool HTMLFencedFrameElement::IsPresentationAttribute(
    const QualifiedName& name) const {
  if (name == html_names::kWidthAttr || name == html_names::kHeightAttr)
    return true;
  return HTMLFrameOwnerElement::IsPresentationAttribute(name);
}

void HTMLFencedFrameElement::CollectStyleForPresentationAttribute(
    const QualifiedName& name,
    const AtomicString& value,
    MutableCSSPropertyValueSet* style) {
  if (name == html_names::kWidthAttr) {
    AddHTMLLengthToStyle(style, CSSPropertyID::kWidth, value);
  } else if (name == html_names::kHeightAttr) {
    AddHTMLLengthToStyle(style, CSSPropertyID::kHeight, value);
  } else {
    HTMLFrameOwnerElement::CollectStyleForPresentationAttribute(name, value,
                                                                style);
  }
}

void HTMLFencedFrameElement::Navigate(
    const KURL& url,
    std::optional<bool> deprecated_should_freeze_initial_size,
    std::optional<gfx::Size> container_size,
    std::optional<gfx::Size> content_size,
    String embedder_shared_storage_context) {
  TRACE_EVENT0("navigation", "HTMLFencedFrameElement::Navigate");
  if (!isConnected())
    return;

  // Please see `FencedFrameDelegate::Create` for a list of conditions which
  // could result in not having a frame delegate at this point, one of which is
  // prerendering. If this function is called while prerendering we won't have a
  // delegate and will bail early, but this should still be correct since,
  // post-activation, CreateDelegateAndNavigate will be run which will navigate
  // to the most current config.
  if (!frame_delegate_)
    return;

  if (url.IsEmpty())
    return;

  if (!GetExecutionContext()->IsSecureContext()) {
    GetDocument().AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::blink::ConsoleMessageSource::kRendering,
        mojom::blink::ConsoleMessageLevel::kWarning,
        "A fenced frame was not loaded because the page is not in a secure "
        "context."));
    RecordFencedFrameCreationOutcome(
        FencedFrameCreationOutcome::kInsecureContext);
    return;
  }

  if (IsValidUrnUuidURL(GURL(url))) {
    mode_ = blink::FencedFrame::DeprecatedFencedFrameMode::kOpaqueAds;
  } else if (IsValidFencedFrameURL(GURL(url))) {
    mode_ = blink::FencedFrame::DeprecatedFencedFrameMode::kDefault;
  } else {
    GetDocument().AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::blink::ConsoleMessageSource::kRendering,
        mojom::blink::ConsoleMessageLevel::kWarning,
        "A fenced frame must be navigated to an \"https\" URL, an \"http\" "
        "localhost URL,"
        " \"about:blank\", or a \"urn:uuid\"."));
    RecordFencedFrameCreationOutcome(
        FencedFrameCreationOutcome::kIncompatibleURLDefault);
    return;
  }

  if (HasDifferentModeThanParent(*this)) {
    blink::FencedFrame::DeprecatedFencedFrameMode parent_mode =
        GetDocument().GetPage()->DeprecatedFencedFrameMode();

    GetDocument().AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::blink::ConsoleMessageSource::kRendering,
        mojom::blink::ConsoleMessageLevel::kWarning,
        "Cannot create a fenced frame with mode '" +
            DeprecatedFencedFrameModeToString(GetDeprecatedMode()) +
            "' nested in a fenced frame with mode '" +
            DeprecatedFencedFrameModeToString(parent_mode) + "'."));
    RecordFencedFrameCreationOutcome(
        FencedFrameCreationOutcome::kIncompatibleMode);
    return;
  }

  // Cannot perform an embedder-initiated navigation in a fenced frame when the
  // sandbox attribute restricts any of the mandatory unsandboxed features.
  if (static_cast<int>(GetFramePolicy().sandbox_flags) &
      static_cast<int>(blink::kFencedFrameMandatoryUnsandboxedFlags)) {
    GetDocument().AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::blink::ConsoleMessageSource::kJavaScript,
        mojom::blink::ConsoleMessageLevel::kWarning,
        "Can't navigate the fenced frame. A sandboxed fenced frame can "
        "only be navigated by its embedder when all of the following "
        "flags are set: allow-same-origin, allow-forms, allow-scripts, "
        "allow-popups, allow-popups-to-escape-sandbox, and "
        "allow-top-navigation-by-user-activation."));
    RecordFencedFrameCreationOutcome(
        FencedFrameCreationOutcome::kSandboxFlagsNotSet);
    RecordFencedFrameUnsandboxedFlags(GetFramePolicy().sandbox_flags);
    return;
  }

  UpdateContainerPolicy();

  frame_delegate_->Navigate(url, embedder_shared_storage_context);

  RecordFencedFrameCreationOutcome(
      mode_ == blink::FencedFrame::DeprecatedFencedFrameMode::kDefault
          ? FencedFrameCreationOutcome::kSuccessDefault
          : FencedFrameCreationOutcome::kSuccessOpaque);

  // Inherit the container size from the FencedFrameConfig, if one is present.
  if (container_size.has_value()) {
    SetContainerSize(*container_size);
  }

  // Handle size freezing.
  // This isn't strictly correct, because the size is frozen on navigation
  // start rather than navigation commit (i.e. if the navigation fails, the
  // size will still be frozen). This is unavoidable in our current
  // implementation, where the embedder freezes the size (because the embedder
  // doesn't/shouldn't know when/if the config navigation commits). This
  // inconsistency should be resolved when we make the browser responsible for
  // size freezing, rather than the embedder.
  if (content_size.has_value()) {
    // Check if the config has a content size specified inside it. If so, we
    // should freeze to that size rather than check the current size.
    // It is nonsensical to ask for the old size freezing behavior (freeze the
    // initial size) while also specifying a content size.
    CHECK(deprecated_should_freeze_initial_size.has_value() &&
          !deprecated_should_freeze_initial_size.value());
    PhysicalSize converted_size(LayoutUnit(content_size->width()),
                                LayoutUnit(content_size->height()));
    FreezeFrameSize(converted_size, /*should_coerce_size=*/false);
  } else {
    if ((!deprecated_should_freeze_initial_size.has_value() &&
         IsValidUrnUuidURL(GURL(url))) ||
        (deprecated_should_freeze_initial_size.has_value() &&
         *deprecated_should_freeze_initial_size)) {
      // If we are using a urn, or if the config is still using the deprecated
      // API, freeze the current size at navigation start (or soon after).
      FreezeCurrentFrameSize();
    } else {
      // Otherwise, make sure the frame size isn't frozen.
      UnfreezeFrameSize();
    }
  }
}

void HTMLFencedFrameElement::NavigateToConfig() {
  CHECK(config_);

  // Prioritize navigating to `config_`'s internal URN if it exists. If so, that
  // means it was created by information from the browser process, and the URN
  // is stored in the `FencedFrameURLMapping`. Otherwise, `config_` was
  // constructed from script and has a user-supplied URL that `this` will
  // navigate to instead.
  KURL url;
  if (config_->urn_uuid(PassKey())) {
    url = config_->urn_uuid(PassKey()).value();
    CHECK(IsValidUrnUuidURL(GURL(url)));
  } else {
    CHECK(config_->url());
    url =
        config_
            ->GetValueIgnoringVisibility<FencedFrameConfig::Attribute::kURL>();
  }
  Navigate(url, config_->deprecated_should_freeze_initial_size(PassKey()),
           config_->container_size(PassKey()), config_->content_size(PassKey()),
           config_->GetSharedStorageContext());
}

void HTMLFencedFrameElement::CreateDelegateAndNavigate() {
  TRACE_EVENT0("navigation",
               "HTMLFencedFrameElement::CreateDelegateAndNavigate");
  // We may queue up several calls to CreateDelegateAndNavigate while
  // prerendering, but we should only actually create the delegate once. Note,
  // this will also mean that we skip calling Navigate() again, but the result
  // should still be correct since the first Navigate call will use the
  // up-to-date config.
  if (frame_delegate_)
    return;
  if (GetDocument().IsPrerendering()) {
    GetDocument().AddPostPrerenderingActivationStep(
        WTF::BindOnce(&HTMLFencedFrameElement::CreateDelegateAndNavigate,
                      WrapWeakPersistent(this)));
    return;
  }

  frame_delegate_ = FencedFrameDelegate::Create(this);

  if (config_) {
    NavigateToConfig();
  }
}

void HTMLFencedFrameElement::AttachLayoutTree(AttachContext& context) {
  HTMLFrameOwnerElement::AttachLayoutTree(context);
  if (frame_delegate_)
    frame_delegate_->AttachLayoutTree();
}

bool HTMLFencedFrameElement::LayoutObjectIsNeeded(
    const DisplayStyle& style) const {
  return !collapsed_by_client_ &&
         HTMLFrameOwnerElement::LayoutObjectIsNeeded(style);
}

LayoutObject* HTMLFencedFrameElement::CreateLayoutObject(const ComputedStyle&) {
  return MakeGarbageCollected<LayoutIFrame>(this);
}

FocusableState HTMLFencedFrameElement::SupportsFocus(UpdateBehavior) const {
  return (frame_delegate_ && frame_delegate_->SupportsFocus())
             ? FocusableState::kFocusable
             : FocusableState::kNotFocusable;
}

PhysicalSize HTMLFencedFrameElement::CoerceFrameSize(
    const PhysicalSize& requested_size) {
  // Only top-level opaque-ads fenced frames are restricted to a list of sizes.
  // TODO(crbug.com/1123606): Later, we will change the size restriction design
  // such that the size is a property bound to opaque URLs, rather than the
  // mode. When that happens, much of this function will need to change.
  // Remember to remove the following includes:
  // #include
  // "third_party/blink/renderer/core/html/fenced_frame/fenced_frame_ad_sizes.h"
  // #include "third_party/blink/renderer/core/frame/local_dom_window.h"
  // #include "third_party/blink/renderer/core/frame/screen.h"
  if (GetDeprecatedMode() !=
          blink::FencedFrame::DeprecatedFencedFrameMode::kOpaqueAds ||
      GetDocument().GetFrame()->IsInFencedFrameTree()) {
    return requested_size;
  }

  // If the requested size is degenerate, return the first allowed ad size.
  if (requested_size.width.ToDouble() <
          std::numeric_limits<double>::epsilon() ||
      requested_size.height.ToDouble() <
          std::numeric_limits<double>::epsilon()) {
    return PhysicalSize(kAllowedAdSizes[0]);
  }

  // If the requested size has an exact match on the allow list, allow it.
  static_assert(kAllowedAdSizes.size() > 0UL);
  for (const gfx::Size& allowed_size : kAllowedAdSizes) {
    if (SizeMatchesExactly(requested_size, allowed_size)) {
      RecordOpaqueFencedFrameSizeCoercion(false);
      return requested_size;
    }
  }

#if BUILDFLAG(IS_ANDROID)
  // TODO(crbug.com/1123606): For now, only allow screen-width ads on Android.
  // We will improve this condition in the future, to account for all cases
  // e.g. split screen, desktop mode, WebView.
  Document& document = GetDocument();
  int width_for_scaling = document.domWindow() && document.domWindow()->screen()
                              ? document.domWindow()->screen()->availWidth()
                              : 0;

  // If scaling based on screen width is allowed, check for exact matches
  // with the list of heights and aspect ratios.
  if (width_for_scaling > 0) {
    static_assert(kAllowedAdHeights.size() > 0UL);
    for (const int allowed_height : kAllowedAdHeights) {
      if (SizeMatchesExactly(requested_size,
                             {width_for_scaling, allowed_height})) {
        return requested_size;
      }
    }

    static_assert(kAllowedAdAspectRatios.size() > 0UL);
    for (const gfx::Size& allowed_aspect_ratio : kAllowedAdAspectRatios) {
      if (SizeMatchesExactly(
              requested_size,
              {width_for_scaling,
               (width_for_scaling * allowed_aspect_ratio.height()) /
                   allowed_aspect_ratio.width()})) {
        return requested_size;
      }
    }
  }
#endif

  // If the requested size isn't allowed, we will freeze the inner frame
  // element with the nearest available size (the best fit according to our
  // size loss function).
  GetDocument().AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
      mojom::blink::ConsoleMessageSource::kRendering,
      mojom::blink::ConsoleMessageLevel::kWarning,
      "A fenced frame in opaque-ads mode attempted to load with an "
      "unsupported size, and was therefore rounded to the nearest supported "
      "size."));
  RecordOpaqueFencedFrameSizeCoercion(true);

  // The best size so far, and its loss. A lower loss represents
  // a better fit, so we will find the size that minimizes it, i.e.
  // the least bad size.
  gfx::Size best_size = kAllowedAdSizes[0];
  double best_size_loss = std::numeric_limits<double>::infinity();

  for (const gfx::Size& allowed_size : kAllowedAdSizes) {
    double size_loss = ComputeSizeLossFunction(requested_size, allowed_size);
    if (size_loss < best_size_loss) {
      best_size_loss = size_loss;
      best_size = allowed_size;
    }
  }

#if BUILDFLAG(IS_ANDROID)
  if (width_for_scaling > 0) {
    for (const int allowed_height : kAllowedAdHeights) {
      const gfx::Size allowed_size = {width_for_scaling, allowed_height};
      double size_loss = ComputeSizeLossFunction(requested_size, allowed_size);
      if (size_loss < best_size_loss) {
        best_size_loss = size_loss;
        best_size = allowed_size;
      }
    }

    for (const gfx::Size& allowed_aspect_ratio : kAllowedAdAspectRatios) {
      const gfx::Size allowed_size = {
          width_for_scaling,
          (width_for_scaling * allowed_aspect_ratio.height()) /
              allowed_aspect_ratio.width()};
      double size_loss = ComputeSizeLossFunction(requested_size, allowed_size);
      if (size_loss < best_size_loss) {
        best_size_loss = size_loss;
        best_size = allowed_size;
      }
    }
  }
#endif

  return PhysicalSize(best_size);
}

const std::optional<PhysicalSize> HTMLFencedFrameElement::FrozenFrameSize()
    const {
  if (!frozen_frame_size_)
    return std::nullopt;
  const float ratio = GetDocument().DevicePixelRatio();
  return PhysicalSize(
      LayoutUnit::FromFloatRound(frozen_frame_size_->width * ratio),
      LayoutUnit::FromFloatRound(frozen_frame_size_->height * ratio));
}

void HTMLFencedFrameElement::UnfreezeFrameSize() {
  should_freeze_frame_size_on_next_layout_ = false;

  // If the frame was already unfrozen, we don't need to do anything.
  if (!frozen_frame_size_.has_value()) {
    return;
  }

  // Otherwise, the frame previously had a frozen size. Unfreeze it.
  frozen_frame_size_ = std::nullopt;
  frame_delegate_->MarkFrozenFrameSizeStale();
}

void HTMLFencedFrameElement::FreezeCurrentFrameSize() {
  should_freeze_frame_size_on_next_layout_ = false;

  // If the inner frame size is already frozen to the current outer frame size,
  // we don't need to do anything.
  if (frozen_frame_size_.has_value() && content_rect_.has_value() &&
      content_rect_->size == *frozen_frame_size_) {
    return;
  }

  // Otherwise, we need to change the frozen size of the frame.
  frozen_frame_size_ = std::nullopt;

  // If we know the current outer frame size, freeze the inner frame to it.
  if (content_rect_) {
    FreezeFrameSize(content_rect_->size, /*should_coerce_size=*/true);
    return;
  }

  // Otherwise, we need to wait for the next layout.
  should_freeze_frame_size_on_next_layout_ = true;
}

void HTMLFencedFrameElement::SetContainerSize(const gfx::Size& size) {
  setAttribute(html_names::kWidthAttr,
               AtomicString(String::Format("%dpx", size.width())));
  setAttribute(html_names::kHeightAttr,
               AtomicString(String::Format("%dpx", size.height())));

  frame_delegate_->MarkContainerSizeStale();
}

void HTMLFencedFrameElement::FreezeFrameSize(const PhysicalSize& size,
                                             bool should_coerce_size) {
  frozen_frame_size_ = size;
  if (should_coerce_size) {
    frozen_frame_size_ = CoerceFrameSize(size);
  }

  frame_delegate_->MarkFrozenFrameSizeStale();
}

void HTMLFencedFrameElement::StartResizeObserver() {
  DCHECK(!resize_observer_);
  resize_observer_ =
      ResizeObserver::Create(GetDocument().domWindow(),
                             MakeGarbageCollected<ResizeObserverDelegate>());
  resize_observer_->observe(this);
}

void HTMLFencedFrameElement::ResizeObserverDelegate::OnResize(
    const HeapVector<Member<ResizeObserverEntry>>& entries) {
  if (entries.empty())
    return;
  const Member<ResizeObserverEntry>& entry = entries.back();
  auto* element = To<HTMLFencedFrameElement>(entry->target());
  const DOMRectReadOnly* content_rect = entry->contentRect();
  element->OnResize(ToPhysicalRect(*content_rect));
}

void HTMLFencedFrameElement::OnResize(const PhysicalRect& content_rect) {
  // If we don't have a delegate, then we won't have a frame, so no reason to
  // freeze.
  if (!frame_delegate_)
    return;
  if (frozen_frame_size_.has_value() && !size_set_after_freeze_) {
    // Only log this once per fenced frame.
    RecordFencedFrameResizedAfterSizeFrozen();
    size_set_after_freeze_ = true;
  }
  content_rect_ = content_rect;

  // If we postponed freezing the frame size until the next layout (in
  // `FreezeCurrentFrameSize`), do it now.
  if (should_freeze_frame_size_on_next_layout_) {
    should_freeze_frame_size_on_next_layout_ = false;
    DCHECK(!frozen_frame_size_);
    FreezeFrameSize(content_rect_->size, /*should_coerce_size=*/true);
  }
}

void HTMLFencedFrameElement::DispatchFencedEvent(
    const WTF::String& event_type) {
  std::optional<WTF::AtomicString> fenced_event_type =
      ConvertEventTypeToFencedEventType(event_type);
  CHECK(fenced_event_type.has_value());
  // Note: This method sets isTrusted = true on the event object, to indicate
  // that the event was dispatched by the browser.
  DispatchEvent(*Event::CreateFenced(*fenced_event_type));
}

// START HTMLFencedFrameElement::
"""


```