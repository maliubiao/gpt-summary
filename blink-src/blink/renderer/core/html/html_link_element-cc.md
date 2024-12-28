Response:
My goal is to analyze the provided C++ source code for `html_link_element.cc` and extract its functionalities, especially concerning its relation to HTML, CSS, and JavaScript. I also need to identify potential user or programming errors and analyze any logical reasoning within the code.

Here's a breakdown of the thinking process:

1. **Understand the Core Functionality:** The file name `html_link_element.cc` and the presence of `#include "third_party/blink/renderer/core/html/html_link_element.h"` immediately tell me this file defines the behavior of the `<link>` HTML element within the Blink rendering engine.

2. **Identify Key Responsibilities by Analyzing Class Members and Methods:** I'll scan the class definition (`HTMLLinkElement`) and its methods to understand what tasks this class handles. Keywords like `Load`, `Process`, `StyleSheet`, `Prefetch`, `Manifest`, `Blocking`, and attribute parsing are strong indicators of functionality.

3. **Relate to HTML:**  The `<link>` element in HTML is used for various purposes. I need to connect the code's functionality to these HTML uses. For example:
    * `rel="stylesheet"`:  Loading and applying CSS stylesheets.
    * `rel="prefetch"`:  Preloading resources.
    * `rel="manifest"`:  Linking to a web app manifest.
    * `href`:  Specifying the URL of the linked resource.
    * Attributes like `media`, `type`, `sizes`, `integrity`, `crossorigin`, etc. directly correspond to HTML attributes and their handling in the code.

4. **Relate to CSS:** The handling of `rel="stylesheet"` is the primary connection to CSS. I need to look for how the code interacts with CSS loading, parsing, and application. The presence of `LinkStyle` and mentions of "stylesheets" are key.

5. **Relate to JavaScript:** While the C++ code itself isn't JavaScript, it provides the underlying mechanism that JavaScript can interact with. I'll look for:
    * How JavaScript can trigger loading or manipulate `<link>` elements (though this file primarily *implements* the behavior, not the JS API).
    * Event handling (`load`, `error`) that JavaScript can listen to.
    * Properties that JavaScript can access or modify.

6. **Identify Logical Reasoning and Assumptions:** I'll look for conditional statements (`if`, `else`), loops (though less common in this type of class), and specific logic related to attribute changes or lifecycle events. For instance, the handling of the `blocking` attribute and `rel="expect"` involves specific logic for delaying rendering. I should also consider the assumptions the code makes about the input (HTML attributes).

7. **Identify Potential User/Programming Errors:**  Based on the code's functionality and how users/programmers interact with `<link>` elements, I can identify common mistakes:
    * Incorrect `rel` values.
    * Incorrect or missing `href` values.
    * Conflicts between attributes (e.g., `blocking` with certain `rel` values).
    * Incorrect media queries.
    * Problems with resource loading (network errors).

8. **Structure the Output:** I need to organize my findings clearly, addressing each part of the prompt:
    * List of functionalities.
    * Relation to HTML with examples.
    * Relation to CSS with examples.
    * Relation to JavaScript with examples.
    * Logical reasoning with input/output examples.
    * Common user/programming errors with examples.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Focus solely on CSS loading.
* **Correction:** Realized the `<link>` element has broader uses (prefetch, manifest, etc.) and adjusted the analysis accordingly.

* **Initial thought:**  Assume direct JavaScript interaction is heavily present in this file.
* **Correction:** Recognized this file implements the core behavior, and the JavaScript interaction is more about manipulating the DOM and listening to events, which this code facilitates.

* **Initial thought:**  Just list the methods.
* **Correction:**  Categorized the methods and functionalities based on their purpose and relation to HTML/CSS/JS.

By following these steps, I can systematically analyze the code and generate a comprehensive and accurate response to the prompt.
```cpp
/*
 * Copyright (C) 1999 Lars Knoll (knoll@kde.org)
 *           (C) 1999 Antti Koivisto (koivisto@kde.org)
 *           (C) 2001 Dirk Mueller (mueller@kde.org)
 * Copyright (C) 2003, 2006, 2007, 2008, 2009, 2010 Apple Inc. All rights
 * reserved.
 * Copyright (C) 2009 Rob Buis (rwlbuis@gmail.com)
 * Copyright (C) 2011 Google Inc. All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this library; see the file COPYING.LIB. If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#include "third_party/blink/renderer/core/html/html_link_element.h"

#include <utility>

#include "base/numerics/safe_conversions.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/public/platform/web_icon_sizes_parser.h"
#include "third_party/blink/public/platform/web_prescient_networking.h"
#include "third_party/blink/renderer/core/core_initializer.h"
#include "third_party/blink/renderer/core/dom/attribute.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/frame/frame_console.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/html/cross_origin_attribute.h"
#include "third_party/blink/renderer/core/html/link_manifest.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/loader/link_loader.h"
#include "third_party/blink/renderer/core/loader/render_blocking_resource_manager.h"
#include "third_party/blink/renderer/core/origin_trials/origin_trial_context.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/weborigin/security_policy.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

HTMLLinkElement::HTMLLinkElement(Document& document,
                                 const CreateElementFlags flags)
    : HTMLElement(html_names::kLinkTag, document),
      link_loader_(MakeGarbageCollected<LinkLoader>(this)),
      sizes_(MakeGarbageCollected<DOMTokenList>(*this, html_names::kSizesAttr)),
      rel_list_(MakeGarbageCollected<RelList>(this)),
      blocking_attribute_(MakeGarbageCollected<BlockingAttribute>(this)),
      created_by_parser_(flags.IsCreatedByParser()) {}

HTMLLinkElement::~HTMLLinkElement() = default;

void HTMLLinkElement::ParseAttribute(
    const AttributeModificationParams& params) {
  const QualifiedName& name = params.name;
  const AtomicString& value = params.new_value;
  if (name == html_names::kRelAttr) {
    // We're about to change the rel attribute. If it was "expect", first remove
    // it from a render blocking list.
    RemoveExpectRenderBlockingLink();

    rel_attribute_ = LinkRelAttribute(value);
    // TODO(vmpstr): Add rel=expect to UseCounter.
    AddExpectRenderBlockingLinkIfNeeded();

    if (rel_attribute_.IsMonetization() &&
        GetDocument().IsInOutermostMainFrame()) {
      // TODO(1031476): The Web Monetization specification is an unofficial
      // draft, available at https://webmonetization.org/specification.html
      // Currently it relies on a <meta> tag but there is an open issue about
      // whether the <link rel="monetization"> should be used instead:
      // https://github.com/interledger/webmonetization.org/issues/19
      // For now, only use counters are implemented in Blink.
      UseCounter::Count(&GetDocument(),
                        WebFeature::kHTMLLinkElementMonetization);
    }
    if (rel_attribute_.IsCanonical() &&
        GetDocument().IsInOutermostMainFrame()) {
      UseCounter::Count(&GetDocument(), WebFeature::kLinkRelCanonical);
    }
    if (rel_attribute_.IsPrivacyPolicy()) {
      UseCounter::Count(&GetDocument(), WebFeature::kLinkRelPrivacyPolicy);
    }
    if (rel_attribute_.IsTermsOfService()) {
      UseCounter::Count(&GetDocument(), WebFeature::kLinkRelTermsOfService);
    }
    if (rel_attribute_.IsPayment() && GetDocument().IsInOutermostMainFrame()) {
      UseCounter::Count(&GetDocument(), WebFeature::kLinkRelPayment);
#if BUILDFLAG(IS_ANDROID)
      if (RuntimeEnabledFeatures::PaymentLinkDetectionEnabled()) {
        GetDocument().HandlePaymentLink(
            GetNonEmptyURLAttribute(html_names::kHrefAttr));
      }
#endif
    }
    rel_list_->DidUpdateAttributeValue(params.old_value, value);
    Process();
  } else if (name == html_names::kBlockingAttr) {
    blocking_attribute_->OnAttributeValueChanged(params.old_value, value);
    if (!IsPotentiallyRenderBlocking()) {
      if (GetLinkStyle() && GetLinkStyle()->StyleSheetIsLoading())
        GetLinkStyle()->UnblockRenderingForPendingSheet();
    }
    HandleExpectBlockingChanges();
  } else if (name == html_names::kHrefAttr) {
    // Log href attribute before logging resource fetching in process().
    LogUpdateAttributeIfIsolatedWorldAndInDocument("link", params);
    HandleExpectHrefChanges(params.old_value, value);
    Process();
  } else if (name == html_names::kTypeAttr) {
    type_ = value;
    Process();
  } else if (name == html_names::kAsAttr) {
    as_ = value;
    Process();
  } else if (name == html_names::kReferrerpolicyAttr) {
    if (!value.IsNull()) {
      SecurityPolicy::ReferrerPolicyFromString(
          value, kDoNotSupportReferrerPolicyLegacyKeywords, &referrer_policy_);
      UseCounter::Count(GetDocument(),
                        WebFeature::kHTMLLinkElementReferrerPolicyAttribute);
    }
  } else if (name == html_names::kSizesAttr) {
    sizes_->DidUpdateAttributeValue(params.old_value, value);
    WebVector<gfx::Size> web_icon_sizes =
        WebIconSizesParser::ParseIconSizes(value);
    icon_sizes_.resize(base::checked_cast<wtf_size_t>(web_icon_sizes.size()));
    for (wtf_size_t i = 0; i < icon_sizes_.size(); ++i)
      icon_sizes_[i] = web_icon_sizes[i];
    Process();
  } else if (name == html_names::kMediaAttr) {
    media_ = value.LowerASCII();
    HandleExpectMediaChanges();
    Process(LinkLoadParameters::Reason::kMediaChange);
  } else if (name == html_names::kIntegrityAttr) {
    integrity_ = value;
  } else if (name == html_names::kFetchpriorityAttr) {
    UseCounter::Count(GetDocument(), WebFeature::kPriorityHints);
    fetch_priority_hint_ = value;
  } else if (name == html_names::kDisabledAttr) {
    UseCounter::Count(GetDocument(), WebFeature::kHTMLLinkElementDisabled);
    if (params.reason == AttributeModificationReason::kByParser)
      UseCounter::Count(GetDocument(), WebFeature::kHTMLLinkElementDisabledByParser);
    LinkStyle* link = GetLinkStyle();
    if (!link) {
      link = MakeGarbageCollected<LinkStyle>(this);
      link_ = link;
    }
    link->SetDisabledState(!value.IsNull());
  } else {
    if (name == html_names::kTitleAttr) {
      if (LinkStyle* link = GetLinkStyle())
        link->SetSheetTitle(value);
    }

    HTMLElement::ParseAttribute(params);
  }
}

bool HTMLLinkElement::ShouldLoadLink() {
  // Common case: We should load <link> on document that will be rendered.
  if (!InActiveDocument()) {
    // Handle rare cases.

    if (!isConnected())
      return false;

    // Load:
    // - <link> tags for stylesheets regardless of its document state
    //   (TODO: document why this is the case. kouhei@ doesn't know.)
    if (!rel_attribute_.IsStyleSheet())
      return false;
  }

  // We don't load links for the rel=expect, since that's just an expectation of
  // parsing of some other element on the page.
  if (rel_attribute_.IsExpect()) {
    return false;
  }

  const KURL& href = GetNonEmptyURLAttribute(html_names::kHrefAttr);
  return !href.PotentiallyDanglingMarkup();
}

bool HTMLLinkElement::IsLinkCreatedByParser() {
  return IsCreatedByParser();
}

bool HTMLLinkElement::LoadLink(const LinkLoadParameters& params) {
  return link_loader_->LoadLink(params, GetDocument());
}

void HTMLLinkElement::LoadStylesheet(const LinkLoadParameters& params,
                                     const WTF::TextEncoding& charset,
                                     FetchParameters::DeferOption defer_option,
                                     ResourceClient* link_client,
                                     RenderBlockingBehavior render_blocking) {
  return link_loader_->LoadStylesheet(params, localName(), charset,
                                      defer_option, GetDocument(), link_client,
                                      render_blocking);
}

LinkResource* HTMLLinkElement::LinkResourceToProcess() {
  if (!ShouldLoadLink()) {
    // If we shouldn't load the link, but the link is already of type
    // LinkType::kStyle and has a stylesheet loaded, it is because the
    // rel attribute is modified and we need to process it to remove
    // the sheet from the style engine and do style recalculation.
    if (GetLinkStyle() && GetLinkStyle()->HasSheet())
      return GetLinkStyle();
    return nullptr;
  }

  if (!link_) {
    if (rel_attribute_.IsManifest()) {
      link_ = MakeGarbageCollected<LinkManifest>(this);
    } else {
      auto* link = MakeGarbageCollected<LinkStyle>(this);
      if (FastHasAttribute(html_names::kDisabledAttr)) {
        UseCounter::Count(GetDocument(), WebFeature::kHTMLLinkElementDisabled);
        link->SetDisabledState(true);
      }
      link_ = link;
    }
  }

  return link_.Get();
}

LinkStyle* HTMLLinkElement::GetLinkStyle() const {
  if (!link_ || link_->GetType() != LinkResource::kStyle)
    return nullptr;
  return static_cast<LinkStyle*>(link_.Get());
}

void HTMLLinkElement::Process(LinkLoadParameters::Reason reason) {
  if (LinkResource* link = LinkResourceToProcess()) {
    link->Process(reason);
  }
}

Node::InsertionNotificationRequest HTMLLinkElement::InsertedInto(
    ContainerNode& insertion_point) {
  HTMLElement::InsertedInto(insertion_point);
  LogAddElementIfIsolatedWorldAndInDocument("link", html_names::kRelAttr,
                                            html_names::kHrefAttr);
  if (!insertion_point.isConnected())
    return kInsertionDone;
  DCHECK(isConnected());

  GetDocument().GetStyleEngine().AddStyleSheetCandidateNode(*this);

  if (!ShouldLoadLink() && IsInShadowTree()) {
    String message = "HTML element <link> is ignored in shadow tree.";
    GetDocument().AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::ConsoleMessageSource::kJavaScript,
        mojom::ConsoleMessageLevel::kWarning, message));
    return kInsertionDone;
  }

  Process();

  if (link_)
    link_->OwnerInserted();

  AddExpectRenderBlockingLinkIfNeeded();
  return kInsertionDone;
}

void HTMLLinkElement::RemovedFrom(ContainerNode& insertion_point) {
  // Store the result of isConnected() here before Node::removedFrom(..) clears
  // the flags.
  bool was_connected = isConnected();
  HTMLElement::RemovedFrom(insertion_point);
  if (!insertion_point.isConnected() ||
      GetDocument().StatePreservingAtomicMoveInProgress()) {
    return;
  }

  link_loader_->Abort();

  if (!was_connected) {
    DCHECK(!GetLinkStyle() || !GetLinkStyle()->HasSheet());
    return;
  }
  GetDocument().GetStyleEngine().RemoveStyleSheetCandidateNode(*this,
                                                               insertion_point);
  if (link_)
    link_->OwnerRemoved();

  RemoveExpectRenderBlockingLink();
}

void HTMLLinkElement::FinishParsingChildren() {
  created_by_parser_ = false;
  HTMLElement::FinishParsingChildren();
}

bool HTMLLinkElement::HasActivationBehavior() const {
  // TODO(tkent): Implement activation behavior. crbug.com/422732.
  return false;
}

bool HTMLLinkElement::StyleSheetIsLoading() const {
  return GetLinkStyle() && GetLinkStyle()->StyleSheetIsLoading();
}

void HTMLLinkElement::LinkLoaded() {
  if (rel_attribute_.IsLinkPrefetch()) {
    UseCounter::Count(GetDocument(), WebFeature::kLinkPrefetchLoadEvent);
  }
  DispatchEvent(*Event::Create(event_type_names::kLoad));
}

void HTMLLinkElement::LinkLoadingErrored() {
  if (rel_attribute_.IsLinkPrefetch()) {
    UseCounter::Count(GetDocument(), WebFeature::kLinkPrefetchErrorEvent);
  }
  DispatchEvent(*Event::Create(event_type_names::kError));
}

bool HTMLLinkElement::SheetLoaded() {
  DCHECK(GetLinkStyle());
  return GetLinkStyle()->SheetLoaded();
}

void HTMLLinkElement::NotifyLoadedSheetAndAllCriticalSubresources(
    LoadedSheetErrorStatus error_status) {
  DCHECK(GetLinkStyle());
  GetLinkStyle()->NotifyLoadedSheetAndAllCriticalSubresources(error_status);
}

void HTMLLinkElement::DispatchPendingEvent(
    std::unique_ptr<IncrementLoadEventDelayCount> count) {
  DCHECK(link_);
  if (link_->HasLoaded())
    LinkLoaded();
  else
    LinkLoadingErrored();

  // Checks Document's load event synchronously here for performance.
  // This is safe because dispatchPendingEvent() is called asynchronously.
  count->ClearAndCheckLoadEvent();
}

void HTMLLinkElement::ScheduleEvent() {
  GetDocument()
      .GetTaskRunner(TaskType::kDOMManipulation)
      ->PostTask(
          FROM_HERE,
          WTF::BindOnce(
              &HTMLLinkElement::DispatchPendingEvent, WrapPersistent(this),
              std::make_unique<IncrementLoadEventDelayCount>(GetDocument())));
}

void HTMLLinkElement::SetToPendingState() {
  DCHECK(GetLinkStyle());
  GetLinkStyle()->SetToPendingState();
}

bool HTMLLinkElement::IsPotentiallyRenderBlocking() const {
  return blocking_attribute_->HasRenderToken() ||
         (IsCreatedByParser() && rel_attribute_.IsStyleSheet());
}

bool HTMLLinkElement::IsURLAttribute(const Attribute& attribute) const {
  return attribute.GetName().LocalName() == html_names::kHrefAttr ||
         HTMLElement::IsURLAttribute(attribute);
}

bool HTMLLinkElement::HasLegalLinkAttribute(const QualifiedName& name) const {
  return name == html_names::kHrefAttr ||
         HTMLElement::HasLegalLinkAttribute(name);
}

KURL HTMLLinkElement::Href() const {
  const String& url = FastGetAttribute(html_names::kHrefAttr);
  if (url.empty())
    return KURL();
  return GetDocument().CompleteURL(url);
}

const AtomicString& HTMLLinkElement::Rel() const {
  return FastGetAttribute(html_names::kRelAttr);
}

const AtomicString& HTMLLinkElement::GetType() const {
  return FastGetAttribute(html_names::kTypeAttr);
}

bool HTMLLinkElement::Async() const {
  return FastHasAttribute(html_names::kAsyncAttr);
}

mojom::blink::FaviconIconType HTMLLinkElement::GetIconType() const {
  return rel_attribute_.GetIconType();
}

const Vector<gfx::Size>& HTMLLinkElement::IconSizes() const {
  return icon_sizes_;
}

DOMTokenList* HTMLLinkElement::sizes() const {
  return sizes_.Get();
}

void HTMLLinkElement::Trace(Visitor* visitor) const {
  visitor->Trace(link_);
  visitor->Trace(sizes_);
  visitor->Trace(link_loader_);
  visitor->Trace(rel_list_);
  visitor->Trace(blocking_attribute_);
  HTMLElement::Trace(visitor);
  LinkLoaderClient::Trace(visitor);
}

void HTMLLinkElement::HandleExpectBlockingChanges() {
  if (!rel_attribute_.IsExpect()) {
    return;
  }

  if (blocking_attribute_->HasRenderToken()) {
    AddExpectRenderBlockingLinkIfNeeded();
  } else {
    RemoveExpectRenderBlockingLink();
  }
}

void HTMLLinkElement::HandleExpectHrefChanges(const String& old_value,
                                              const String& new_value) {
  if (!rel_attribute_.IsExpect()) {
    return;
  }

  RemoveExpectRenderBlockingLink(old_value);
  AddExpectRenderBlockingLinkIfNeeded(new_value);
}

bool HTMLLinkElement::MediaQueryMatches() const {
  if (LocalFrame* frame = GetDocument().GetFrame(); frame && !media_.empty()) {
    auto* media_queries =
        MediaQuerySet::Create(media_, GetDocument().GetExecutionContext());
    MediaQueryEvaluator* evaluator =
        MakeGarbageCollected<MediaQueryEvaluator>(frame);
    return evaluator->Eval(*media_queries);
  }
  return true;
}

void HTMLLinkElement::HandleExpectMediaChanges() {
  if (!rel_attribute_.IsExpect()) {
    return;
  }

  if (MediaQueryMatches()) {
    AddExpectRenderBlockingLinkIfNeeded(String(),
                                        /*media_known_to_match=*/true);
  } else {
    RemoveExpectRenderBlockingLink();
  }
}

void HTMLLinkElement::RemoveExpectRenderBlockingLink(const String& href) {
  if (!rel_attribute_.IsExpect()) {
    return;
  }

  if (auto* render_blocking_resource_manager =
          GetDocument().GetRenderBlockingResourceManager()) {
    render_blocking_resource_manager->RemovePendingParsingElementLink(
        ParseSameDocumentIdFromHref(href), this);
  }
}

AtomicString HTMLLinkElement::ParseSameDocumentIdFromHref(const String& href) {
  String actual_href =
      href.IsNull() ? FastGetAttribute(html_names::kHrefAttr) : href;
  if (actual_href.empty()) {
    return WTF::g_null_atom;
  }

  KURL url = GetDocument().CompleteURL(actual_href);
  if (!url.HasFragmentIdentifier()) {
    return WTF::g_null_atom;
  }

  return EqualIgnoringFragmentIdentifier(url, GetDocument().Url())
             ? AtomicString(url.FragmentIdentifier())
             : g_null_atom;
}

void HTMLLinkElement::AddExpectRenderBlockingLinkIfNeeded(
    const String& href,
    bool media_known_to_match) {
  if (!rel_attribute_.IsExpect()) {
    return;
  }

  bool media_matches = media_known_to_match || MediaQueryMatches();
  bool is_blocking_render = blocking_attribute_->HasRenderToken();
  if (!media_matches || !is_blocking_render || !isConnected()) {
    return;
  }

  if (auto* render_blocking_resource_manager =
          GetDocument().GetRenderBlockingResourceManager()) {
    render_blocking_resource_manager->AddPendingParsingElementLink(
        ParseSameDocumentIdFromHref(href), this);
  }
}

}  // namespace blink
```

这个文件 `html_link_element.cc` 定义了 Chromium Blink 引擎中 `HTMLLinkElement` 类的实现。这个类对应于 HTML 中的 `<link>` 元素。  它负责处理与 `<link>` 元素相关的各种功能。

**主要功能:**

1. **处理 `<link>` 元素的属性:**
   - **`ParseAttribute`:**  当 `<link>` 元素的属性发生变化时被调用。它根据不同的属性执行相应的操作：
     - **`rel`:**  处理 `rel` 属性，该属性定义了链接资源与当前文档的关系。例如：
       - `stylesheet`: 加载 CSS 样式表。
       - `prefetch`: 预加载资源。
       - `manifest`:  指定 Web App Manifest 文件。
       - `canonical`: 指定文档的首选 URL。
       - `monetization`, `privacy-policy`, `terms-of-service`, `payment`:  处理与这些语义相关的链接。
       - `expect`:  处理实验性的 "expect" rel 类型，用于指示对页面上其他元素的期望。
     - **`blocking`:**  控制链接资源是否阻塞渲染。
     - **`href`:**  处理链接资源的 URL。
     - **`type`:**  指定链接资源的 MIME 类型。
     - **`as`:**  指定被提取资源的类型（用于预加载）。
     - **`referrerpolicy`:**  设置请求链接资源时使用的 referrer 策略。
     - **`sizes`:**  指定图标尺寸 (用于 `rel="icon"`)。
     - **`media`:**  指定链接资源应用的媒体查询。
     - **`integrity`:**  指定子资源完整性校验值。
     - **`fetchpriority`:**  指定资源获取的优先级。
     - **`disabled`:**  禁用链接的资源。
     - **`title`:**  设置样式表的标题。
   - 更新内部状态，例如 `rel_attribute_`, `type_`, `as_`, `referrer_policy_`, `icon_sizes_`, `media_`, `integrity_`, `fetch_priority_hint_`。
   - 调用 `Process()` 来触发链接的处理逻辑。

2. **加载和处理链接资源:**
   - **`ShouldLoadLink()`:**  决定是否应该加载链接资源。 例如，不在活动文档中的某些链接可能不会被加载，`rel="expect"` 的链接也不会被加载。
   - **`LoadLink()`:**  使用 `LinkLoader` 实际加载链接资源。
   - **`LoadStylesheet()`:** 使用 `LinkLoader` 加载 CSS 样式表，可以指定字符编码、延迟加载选项和渲染阻塞行为。
   - **`LinkResourceToProcess()`:**  返回要处理的 `LinkResource` 对象。它可以是 `LinkStyle` (用于样式表) 或 `LinkManifest` (用于 Web App Manifest)。
   - **`Process()`:**  触发链接资源的具体处理逻辑（例如，加载样式表、预加载资源、解析 manifest 文件）。

3. **管理样式表:**
   - **`GetLinkStyle()`:**  返回与此链接关联的 `LinkStyle` 对象（如果存在且是样式表链接）。
   - **`StyleSheetIsLoading()`:**  检查关联的样式表是否正在加载。
   - **`SheetLoaded()`:**  检查关联的样式表是否已加载完成。
   - **`NotifyLoadedSheetAndAllCriticalSubresources()`:**  通知样式表及其关键子资源已加载完成。
   - **`SetToPendingState()`:**  将样式表设置为待处理状态。

4. **处理链接的生命周期:**
   - **`InsertedInto()`:**  当 `<link>` 元素插入到 DOM 中时被调用。
     - 将该节点添加到样式引擎的候选节点列表中。
     - 对于不在活动文档或在 Shadow Tree 中的某些链接，可能会发出警告。
     - 调用 `Process()` 启动加载。
     - 调用 `link_->OwnerInserted()` 通知关联的资源。
     - 处理 `rel="expect"` 的渲染阻塞。
   - **`RemovedFrom()`:**  当 `<link>` 元素从 DOM 中移除时被调用。
     - 中止正在进行的加载 (`link_loader_->Abort()`).
     - 将该节点从样式引擎的候选节点列表中移除。
     - 调用 `link_->OwnerRemoved()` 通知关联的资源。
     - 移除 `rel="expect"` 的渲染阻塞。
   - **`FinishParsingChildren()`:**  在解析完 `<link>` 元素的子节点后被调用。

5. **事件处理:**
   - **`LinkLoaded()`:**  当链接资源加载成功时触发 `load` 事件。
   - **`LinkLoadingErrored()`:**  当链接资源加载失败时触发 `error` 事件。
   - **`DispatchPendingEvent()`:** 异步派发 `load` 或 `error` 事件。
   - **`ScheduleEvent()`:**  将事件派发调度到 DOM 操作任务队列。

6. **渲染阻塞:**
   - **`IsPotentiallyRenderBlocking()`:**  确定链接是否可能阻塞页面的首次渲染。这取决于 `blocking` 属性和 `rel="stylesheet"` (对于通过解析器创建的链接)。
   - **`HandleExpectBlockingChanges()` / `HandleExpectHrefChanges()` / `HandleExpectMediaChanges()` / `AddExpectRenderBlockingLinkIfNeeded()` / `RemoveExpectRenderBlockingLink()`:**  处理 `rel="expect"` 带来的渲染阻塞逻辑。 这允许开发者声明对其他元素的期望，并在这些元素可用之前阻塞渲染。

7. **其他功能:**
   - **`Href()`, `Rel()`, `GetType()`, `Async()`:**  提供获取 `<link>` 元素属性值的便捷方法。
   - **`GetIconType()`, `IconSizes()`, `sizes()`:**  处理图标相关的属性。
   - **`MediaQueryMatches()`:**  检查 `media` 查询是否匹配当前环境。
   - **`IsURLAttribute()`, `HasLegalLinkAttribute()`:**  用于确定属性是否为 URL 属性或合法的链接属性。

**与 JavaScript, HTML, CSS 的关系：**

* **HTML:** `HTMLLinkElement` 直接对应于 HTML 的 `<link>` 元素。这个类负责实现浏览器如何解析和处理 HTML 中声明的 `<link>` 元素。例如，当 HTML 解析器遇到 `<link rel="stylesheet" href="style.css">` 时，会创建一个 `HTMLLinkElement` 对象，并调用其方法来加载和应用 `style.css`。

* **CSS:**  `HTMLLinkElement` 是加载和应用 CSS 样式表的关键。
   - **例子:** 当 `rel` 属性设置为 `stylesheet` 时，`LoadStylesheet()` 方法会被调用，从 `href` 指定的 URL 获取 CSS 文件，并将其添加到文档的样式表中。
   - **例子:** `media` 属性允许基于不同的媒体类型应用不同的样式表。`MediaQueryMatches()` 方法用于评估 `media` 查询。
   - **例子:** `disabled` 属性可以动态启用或禁用样式表。

* **JavaScript:** JavaScript 可以通过 DOM API 与 `<link>` 元素进行交互：
   - **例子:** JavaScript 可以创建和插入 `<link>` 元素到 DOM 中：
     ```javascript
     const link = document.createElement('link');
     link.rel = 'stylesheet';
     link.href = 'dynamic.css';
     document.head.appendChild(link);
     ```
     这会导致 `HTMLLinkElement` 的构造和 `InsertedInto()` 方法的调用。
   - **例子:** JavaScript 可以修改 `<link>` 元素的属性：
     ```javascript
     const linkElement = document.querySelector('link[rel="stylesheet"]');
     linkElement.disabled = true;
     ```
     这会触发 `ParseAttribute()` 方法的调用，并更新样式表的禁用状态。
   - **例子:** JavaScript 可以监听 `<link>` 元素的 `load` 和 `error` 事件，以了解资源加载的状态：
     ```javascript
     const linkElement = document.createElement('link');
     linkElement.rel = 'stylesheet';
     linkElement.href = 'style.css';
     linkElement.onload = () => console.log('样式表加载成功');
     linkElement.onerror = () => console.log('样式表加载失败');
     document.head.appendChild(linkElement);
     ```
     `LinkLoaded()` 和 `LinkLoadingErrored()` 方法负责触发这些事件。

**逻辑推理与假设输入/输出:**

* **假设输入:**  一个 HTML 文档包含以下 `<link>` 元素:
  ```html
  <link rel="stylesheet" href="style.css">
  ```
* **逻辑推理:**
    1. HTML 解析器遇到 `<link>` 标签。
    2. 创建一个 `HTMLLinkElement` 对象。
    3. `ParseAttribute()` 被调用，处理 `rel="stylesheet"` 和 `href="style.css"`。
    4. `ShouldLoadLink()` 返回 `true`。
    5. `LinkResourceToProcess()` 返回一个 `LinkStyle` 对象。
    6. `Process()` 被调用，导致 `LinkLoader` 加载 `style.css`。
    7. 当 `style.css` 加载成功后，
Prompt: 
```
这是目录为blink/renderer/core/html/html_link_element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
/*
 * Copyright (C) 1999 Lars Knoll (knoll@kde.org)
 *           (C) 1999 Antti Koivisto (koivisto@kde.org)
 *           (C) 2001 Dirk Mueller (mueller@kde.org)
 * Copyright (C) 2003, 2006, 2007, 2008, 2009, 2010 Apple Inc. All rights
 * reserved.
 * Copyright (C) 2009 Rob Buis (rwlbuis@gmail.com)
 * Copyright (C) 2011 Google Inc. All rights reserved.
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

#include "third_party/blink/renderer/core/html/html_link_element.h"

#include <utility>

#include "base/numerics/safe_conversions.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/public/platform/web_icon_sizes_parser.h"
#include "third_party/blink/public/platform/web_prescient_networking.h"
#include "third_party/blink/renderer/core/core_initializer.h"
#include "third_party/blink/renderer/core/dom/attribute.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/frame/frame_console.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/html/cross_origin_attribute.h"
#include "third_party/blink/renderer/core/html/link_manifest.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/loader/link_loader.h"
#include "third_party/blink/renderer/core/loader/render_blocking_resource_manager.h"
#include "third_party/blink/renderer/core/origin_trials/origin_trial_context.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/weborigin/security_policy.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

HTMLLinkElement::HTMLLinkElement(Document& document,
                                 const CreateElementFlags flags)
    : HTMLElement(html_names::kLinkTag, document),
      link_loader_(MakeGarbageCollected<LinkLoader>(this)),
      sizes_(MakeGarbageCollected<DOMTokenList>(*this, html_names::kSizesAttr)),
      rel_list_(MakeGarbageCollected<RelList>(this)),
      blocking_attribute_(MakeGarbageCollected<BlockingAttribute>(this)),
      created_by_parser_(flags.IsCreatedByParser()) {}

HTMLLinkElement::~HTMLLinkElement() = default;

void HTMLLinkElement::ParseAttribute(
    const AttributeModificationParams& params) {
  const QualifiedName& name = params.name;
  const AtomicString& value = params.new_value;
  if (name == html_names::kRelAttr) {
    // We're about to change the rel attribute. If it was "expect", first remove
    // it from a render blocking list.
    RemoveExpectRenderBlockingLink();

    rel_attribute_ = LinkRelAttribute(value);
    // TODO(vmpstr): Add rel=expect to UseCounter.
    AddExpectRenderBlockingLinkIfNeeded();

    if (rel_attribute_.IsMonetization() &&
        GetDocument().IsInOutermostMainFrame()) {
      // TODO(1031476): The Web Monetization specification is an unofficial
      // draft, available at https://webmonetization.org/specification.html
      // Currently it relies on a <meta> tag but there is an open issue about
      // whether the <link rel="monetization"> should be used instead:
      // https://github.com/interledger/webmonetization.org/issues/19
      // For now, only use counters are implemented in Blink.
      UseCounter::Count(&GetDocument(),
                        WebFeature::kHTMLLinkElementMonetization);
    }
    if (rel_attribute_.IsCanonical() &&
        GetDocument().IsInOutermostMainFrame()) {
      UseCounter::Count(&GetDocument(), WebFeature::kLinkRelCanonical);
    }
    if (rel_attribute_.IsPrivacyPolicy()) {
      UseCounter::Count(&GetDocument(), WebFeature::kLinkRelPrivacyPolicy);
    }
    if (rel_attribute_.IsTermsOfService()) {
      UseCounter::Count(&GetDocument(), WebFeature::kLinkRelTermsOfService);
    }
    if (rel_attribute_.IsPayment() && GetDocument().IsInOutermostMainFrame()) {
      UseCounter::Count(&GetDocument(), WebFeature::kLinkRelPayment);
#if BUILDFLAG(IS_ANDROID)
      if (RuntimeEnabledFeatures::PaymentLinkDetectionEnabled()) {
        GetDocument().HandlePaymentLink(
            GetNonEmptyURLAttribute(html_names::kHrefAttr));
      }
#endif
    }
    rel_list_->DidUpdateAttributeValue(params.old_value, value);
    Process();
  } else if (name == html_names::kBlockingAttr) {
    blocking_attribute_->OnAttributeValueChanged(params.old_value, value);
    if (!IsPotentiallyRenderBlocking()) {
      if (GetLinkStyle() && GetLinkStyle()->StyleSheetIsLoading())
        GetLinkStyle()->UnblockRenderingForPendingSheet();
    }
    HandleExpectBlockingChanges();
  } else if (name == html_names::kHrefAttr) {
    // Log href attribute before logging resource fetching in process().
    LogUpdateAttributeIfIsolatedWorldAndInDocument("link", params);
    HandleExpectHrefChanges(params.old_value, value);
    Process();
  } else if (name == html_names::kTypeAttr) {
    type_ = value;
    Process();
  } else if (name == html_names::kAsAttr) {
    as_ = value;
    Process();
  } else if (name == html_names::kReferrerpolicyAttr) {
    if (!value.IsNull()) {
      SecurityPolicy::ReferrerPolicyFromString(
          value, kDoNotSupportReferrerPolicyLegacyKeywords, &referrer_policy_);
      UseCounter::Count(GetDocument(),
                        WebFeature::kHTMLLinkElementReferrerPolicyAttribute);
    }
  } else if (name == html_names::kSizesAttr) {
    sizes_->DidUpdateAttributeValue(params.old_value, value);
    WebVector<gfx::Size> web_icon_sizes =
        WebIconSizesParser::ParseIconSizes(value);
    icon_sizes_.resize(base::checked_cast<wtf_size_t>(web_icon_sizes.size()));
    for (wtf_size_t i = 0; i < icon_sizes_.size(); ++i)
      icon_sizes_[i] = web_icon_sizes[i];
    Process();
  } else if (name == html_names::kMediaAttr) {
    media_ = value.LowerASCII();
    HandleExpectMediaChanges();
    Process(LinkLoadParameters::Reason::kMediaChange);
  } else if (name == html_names::kIntegrityAttr) {
    integrity_ = value;
  } else if (name == html_names::kFetchpriorityAttr) {
    UseCounter::Count(GetDocument(), WebFeature::kPriorityHints);
    fetch_priority_hint_ = value;
  } else if (name == html_names::kDisabledAttr) {
    UseCounter::Count(GetDocument(), WebFeature::kHTMLLinkElementDisabled);
    if (params.reason == AttributeModificationReason::kByParser)
      UseCounter::Count(GetDocument(), WebFeature::kHTMLLinkElementDisabledByParser);
    LinkStyle* link = GetLinkStyle();
    if (!link) {
      link = MakeGarbageCollected<LinkStyle>(this);
      link_ = link;
    }
    link->SetDisabledState(!value.IsNull());
  } else {
    if (name == html_names::kTitleAttr) {
      if (LinkStyle* link = GetLinkStyle())
        link->SetSheetTitle(value);
    }

    HTMLElement::ParseAttribute(params);
  }
}

bool HTMLLinkElement::ShouldLoadLink() {
  // Common case: We should load <link> on document that will be rendered.
  if (!InActiveDocument()) {
    // Handle rare cases.

    if (!isConnected())
      return false;

    // Load:
    // - <link> tags for stylesheets regardless of its document state
    //   (TODO: document why this is the case. kouhei@ doesn't know.)
    if (!rel_attribute_.IsStyleSheet())
      return false;
  }

  // We don't load links for the rel=expect, since that's just an expectation of
  // parsing of some other element on the page.
  if (rel_attribute_.IsExpect()) {
    return false;
  }

  const KURL& href = GetNonEmptyURLAttribute(html_names::kHrefAttr);
  return !href.PotentiallyDanglingMarkup();
}

bool HTMLLinkElement::IsLinkCreatedByParser() {
  return IsCreatedByParser();
}

bool HTMLLinkElement::LoadLink(const LinkLoadParameters& params) {
  return link_loader_->LoadLink(params, GetDocument());
}

void HTMLLinkElement::LoadStylesheet(const LinkLoadParameters& params,
                                     const WTF::TextEncoding& charset,
                                     FetchParameters::DeferOption defer_option,
                                     ResourceClient* link_client,
                                     RenderBlockingBehavior render_blocking) {
  return link_loader_->LoadStylesheet(params, localName(), charset,
                                      defer_option, GetDocument(), link_client,
                                      render_blocking);
}

LinkResource* HTMLLinkElement::LinkResourceToProcess() {
  if (!ShouldLoadLink()) {
    // If we shouldn't load the link, but the link is already of type
    // LinkType::kStyle and has a stylesheet loaded, it is because the
    // rel attribute is modified and we need to process it to remove
    // the sheet from the style engine and do style recalculation.
    if (GetLinkStyle() && GetLinkStyle()->HasSheet())
      return GetLinkStyle();
    return nullptr;
  }

  if (!link_) {
    if (rel_attribute_.IsManifest()) {
      link_ = MakeGarbageCollected<LinkManifest>(this);
    } else {
      auto* link = MakeGarbageCollected<LinkStyle>(this);
      if (FastHasAttribute(html_names::kDisabledAttr)) {
        UseCounter::Count(GetDocument(), WebFeature::kHTMLLinkElementDisabled);
        link->SetDisabledState(true);
      }
      link_ = link;
    }
  }

  return link_.Get();
}

LinkStyle* HTMLLinkElement::GetLinkStyle() const {
  if (!link_ || link_->GetType() != LinkResource::kStyle)
    return nullptr;
  return static_cast<LinkStyle*>(link_.Get());
}

void HTMLLinkElement::Process(LinkLoadParameters::Reason reason) {
  if (LinkResource* link = LinkResourceToProcess()) {
    link->Process(reason);
  }
}

Node::InsertionNotificationRequest HTMLLinkElement::InsertedInto(
    ContainerNode& insertion_point) {
  HTMLElement::InsertedInto(insertion_point);
  LogAddElementIfIsolatedWorldAndInDocument("link", html_names::kRelAttr,
                                            html_names::kHrefAttr);
  if (!insertion_point.isConnected())
    return kInsertionDone;
  DCHECK(isConnected());

  GetDocument().GetStyleEngine().AddStyleSheetCandidateNode(*this);

  if (!ShouldLoadLink() && IsInShadowTree()) {
    String message = "HTML element <link> is ignored in shadow tree.";
    GetDocument().AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::ConsoleMessageSource::kJavaScript,
        mojom::ConsoleMessageLevel::kWarning, message));
    return kInsertionDone;
  }

  Process();

  if (link_)
    link_->OwnerInserted();

  AddExpectRenderBlockingLinkIfNeeded();
  return kInsertionDone;
}

void HTMLLinkElement::RemovedFrom(ContainerNode& insertion_point) {
  // Store the result of isConnected() here before Node::removedFrom(..) clears
  // the flags.
  bool was_connected = isConnected();
  HTMLElement::RemovedFrom(insertion_point);
  if (!insertion_point.isConnected() ||
      GetDocument().StatePreservingAtomicMoveInProgress()) {
    return;
  }

  link_loader_->Abort();

  if (!was_connected) {
    DCHECK(!GetLinkStyle() || !GetLinkStyle()->HasSheet());
    return;
  }
  GetDocument().GetStyleEngine().RemoveStyleSheetCandidateNode(*this,
                                                               insertion_point);
  if (link_)
    link_->OwnerRemoved();

  RemoveExpectRenderBlockingLink();
}

void HTMLLinkElement::FinishParsingChildren() {
  created_by_parser_ = false;
  HTMLElement::FinishParsingChildren();
}

bool HTMLLinkElement::HasActivationBehavior() const {
  // TODO(tkent): Implement activation behavior. crbug.com/422732.
  return false;
}

bool HTMLLinkElement::StyleSheetIsLoading() const {
  return GetLinkStyle() && GetLinkStyle()->StyleSheetIsLoading();
}

void HTMLLinkElement::LinkLoaded() {
  if (rel_attribute_.IsLinkPrefetch()) {
    UseCounter::Count(GetDocument(), WebFeature::kLinkPrefetchLoadEvent);
  }
  DispatchEvent(*Event::Create(event_type_names::kLoad));
}

void HTMLLinkElement::LinkLoadingErrored() {
  if (rel_attribute_.IsLinkPrefetch()) {
    UseCounter::Count(GetDocument(), WebFeature::kLinkPrefetchErrorEvent);
  }
  DispatchEvent(*Event::Create(event_type_names::kError));
}

bool HTMLLinkElement::SheetLoaded() {
  DCHECK(GetLinkStyle());
  return GetLinkStyle()->SheetLoaded();
}

void HTMLLinkElement::NotifyLoadedSheetAndAllCriticalSubresources(
    LoadedSheetErrorStatus error_status) {
  DCHECK(GetLinkStyle());
  GetLinkStyle()->NotifyLoadedSheetAndAllCriticalSubresources(error_status);
}

void HTMLLinkElement::DispatchPendingEvent(
    std::unique_ptr<IncrementLoadEventDelayCount> count) {
  DCHECK(link_);
  if (link_->HasLoaded())
    LinkLoaded();
  else
    LinkLoadingErrored();

  // Checks Document's load event synchronously here for performance.
  // This is safe because dispatchPendingEvent() is called asynchronously.
  count->ClearAndCheckLoadEvent();
}

void HTMLLinkElement::ScheduleEvent() {
  GetDocument()
      .GetTaskRunner(TaskType::kDOMManipulation)
      ->PostTask(
          FROM_HERE,
          WTF::BindOnce(
              &HTMLLinkElement::DispatchPendingEvent, WrapPersistent(this),
              std::make_unique<IncrementLoadEventDelayCount>(GetDocument())));
}

void HTMLLinkElement::SetToPendingState() {
  DCHECK(GetLinkStyle());
  GetLinkStyle()->SetToPendingState();
}

bool HTMLLinkElement::IsPotentiallyRenderBlocking() const {
  return blocking_attribute_->HasRenderToken() ||
         (IsCreatedByParser() && rel_attribute_.IsStyleSheet());
}

bool HTMLLinkElement::IsURLAttribute(const Attribute& attribute) const {
  return attribute.GetName().LocalName() == html_names::kHrefAttr ||
         HTMLElement::IsURLAttribute(attribute);
}

bool HTMLLinkElement::HasLegalLinkAttribute(const QualifiedName& name) const {
  return name == html_names::kHrefAttr ||
         HTMLElement::HasLegalLinkAttribute(name);
}

KURL HTMLLinkElement::Href() const {
  const String& url = FastGetAttribute(html_names::kHrefAttr);
  if (url.empty())
    return KURL();
  return GetDocument().CompleteURL(url);
}

const AtomicString& HTMLLinkElement::Rel() const {
  return FastGetAttribute(html_names::kRelAttr);
}

const AtomicString& HTMLLinkElement::GetType() const {
  return FastGetAttribute(html_names::kTypeAttr);
}

bool HTMLLinkElement::Async() const {
  return FastHasAttribute(html_names::kAsyncAttr);
}

mojom::blink::FaviconIconType HTMLLinkElement::GetIconType() const {
  return rel_attribute_.GetIconType();
}

const Vector<gfx::Size>& HTMLLinkElement::IconSizes() const {
  return icon_sizes_;
}

DOMTokenList* HTMLLinkElement::sizes() const {
  return sizes_.Get();
}

void HTMLLinkElement::Trace(Visitor* visitor) const {
  visitor->Trace(link_);
  visitor->Trace(sizes_);
  visitor->Trace(link_loader_);
  visitor->Trace(rel_list_);
  visitor->Trace(blocking_attribute_);
  HTMLElement::Trace(visitor);
  LinkLoaderClient::Trace(visitor);
}

void HTMLLinkElement::HandleExpectBlockingChanges() {
  if (!rel_attribute_.IsExpect()) {
    return;
  }

  if (blocking_attribute_->HasRenderToken()) {
    AddExpectRenderBlockingLinkIfNeeded();
  } else {
    RemoveExpectRenderBlockingLink();
  }
}

void HTMLLinkElement::HandleExpectHrefChanges(const String& old_value,
                                              const String& new_value) {
  if (!rel_attribute_.IsExpect()) {
    return;
  }

  RemoveExpectRenderBlockingLink(old_value);
  AddExpectRenderBlockingLinkIfNeeded(new_value);
}

bool HTMLLinkElement::MediaQueryMatches() const {
  if (LocalFrame* frame = GetDocument().GetFrame(); frame && !media_.empty()) {
    auto* media_queries =
        MediaQuerySet::Create(media_, GetDocument().GetExecutionContext());
    MediaQueryEvaluator* evaluator =
        MakeGarbageCollected<MediaQueryEvaluator>(frame);
    return evaluator->Eval(*media_queries);
  }
  return true;
}

void HTMLLinkElement::HandleExpectMediaChanges() {
  if (!rel_attribute_.IsExpect()) {
    return;
  }

  if (MediaQueryMatches()) {
    AddExpectRenderBlockingLinkIfNeeded(String(),
                                        /*media_known_to_match=*/true);
  } else {
    RemoveExpectRenderBlockingLink();
  }
}

void HTMLLinkElement::RemoveExpectRenderBlockingLink(const String& href) {
  if (!rel_attribute_.IsExpect()) {
    return;
  }

  if (auto* render_blocking_resource_manager =
          GetDocument().GetRenderBlockingResourceManager()) {
    render_blocking_resource_manager->RemovePendingParsingElementLink(
        ParseSameDocumentIdFromHref(href), this);
  }
}

AtomicString HTMLLinkElement::ParseSameDocumentIdFromHref(const String& href) {
  String actual_href =
      href.IsNull() ? FastGetAttribute(html_names::kHrefAttr) : href;
  if (actual_href.empty()) {
    return WTF::g_null_atom;
  }

  KURL url = GetDocument().CompleteURL(actual_href);
  if (!url.HasFragmentIdentifier()) {
    return WTF::g_null_atom;
  }

  return EqualIgnoringFragmentIdentifier(url, GetDocument().Url())
             ? AtomicString(url.FragmentIdentifier())
             : g_null_atom;
}

void HTMLLinkElement::AddExpectRenderBlockingLinkIfNeeded(
    const String& href,
    bool media_known_to_match) {
  if (!rel_attribute_.IsExpect()) {
    return;
  }

  bool media_matches = media_known_to_match || MediaQueryMatches();
  bool is_blocking_render = blocking_attribute_->HasRenderToken();
  if (!media_matches || !is_blocking_render || !isConnected()) {
    return;
  }

  if (auto* render_blocking_resource_manager =
          GetDocument().GetRenderBlockingResourceManager()) {
    render_blocking_resource_manager->AddPendingParsingElementLink(
        ParseSameDocumentIdFromHref(href), this);
  }
}

}  // namespace blink

"""

```