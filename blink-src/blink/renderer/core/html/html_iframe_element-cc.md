Response:
Let's break down the thought process for analyzing the `HTMLIFrameElement.cc` file.

**1. Initial Understanding of the File's Role:**

The file name itself, `html_iframe_element.cc`, is a strong indicator. It suggests this code is responsible for the behavior and properties of the `<iframe>` HTML element within the Blink rendering engine. The `blink/renderer/core/html/` path further reinforces this, placing it within the core HTML processing logic.

**2. Examining the Includes:**

The included headers provide valuable clues about the file's dependencies and functionality. I'd scan them looking for keywords related to:

* **Core HTML/DOM:**  `html_names.h`, `element.h`, `html_document.h`
* **JavaScript Integration:** `v8_html_iframe_element.h` (V8 is the JavaScript engine in Chrome)
* **CSS Styling:** `css_property_names.h`, `style_change_reason.h`
* **Frame Management:** `local_frame.h`, `frame.mojom-blink.h`
* **Security and Permissions:** `content_security_policy.h`, `permissions_policy/`, `network/public/`
* **Network Requests:**  (Implicit through sandbox, CSP, referrer policy, trust tokens)
* **Layout:** `layout_iframe.h`
* **Browser Integration (IPC):**  `third_party/blink/public/mojom/frame/frame.mojom-blink.h` (mojom usually indicates inter-process communication)
* **Utilities and Data Structures:**  `platform/heap/`, `platform/instrumentation/`, `platform/json/`

This quick scan gives a high-level idea of the file's scope.

**3. Analyzing the Class Definition (`HTMLIFrameElement`):**

The class definition confirms the initial assumption. It inherits from `HTMLFrameElementBase`, indicating it builds upon a more general frame element implementation. The private members offer insights into the state the class manages:

* `collapsed_by_client_`: Suggests a client-side mechanism for hiding the iframe.
* `sandbox_`: Points to a class handling the `sandbox` attribute.
* `referrer_policy_`:  Relates to the `referrerpolicy` attribute.
* `policy_`:  Likely the feature policy object.
* `required_csp_`, `required_policy_`, `trust_token_`, `allow_`: These are all attributes controlling the iframe's behavior and security context.

**4. Examining Key Methods and their Logic:**

This is where the detailed functionality is revealed. I'd focus on methods that are clearly related to HTML, JavaScript, and CSS, and those involving more complex logic:

* **`SetCollapsed()`:**  Clearly related to CSS (style recalc) and client-side control.
* **`sandbox()` and `featurePolicy()`:**  Provide access to important iframe features.
* **`IsPresentationAttribute()` and `CollectStyleForPresentationAttribute()`:** Directly involve CSS styling based on HTML attributes. The examples here (`width`, `height`, `align`, `frameborder`) are very informative.
* **`ParseAttribute()`:**  This is the core of how the iframe responds to changes in its HTML attributes. I'd go through each attribute case (`name`, `sandbox`, `referrerpolicy`, `allowfullscreen`, etc.) and understand what each block of code does. The use of `UseCounter` hints at tracking feature usage. The console messages are important for debugging and developer feedback.
* **`ConstructRequiredPolicy()` and `ConstructContainerPolicy()`:**  Deal with the more advanced security and permission features (`policy` and `allow` attributes).
* **`LayoutObjectIsNeeded()` and `CreateLayoutObject()`:** Connect the HTML element to the layout engine.
* **`InsertedInto()` and `RemovedFrom()`:** Handle the iframe's lifecycle within the DOM tree, including interactions with the parent document's named items.
* **`ConstructTrustTokenParams()`:**  Demonstrates interaction with a specific web API.
* **`DidChangeAttributes()`:**  Crucial for communication with the browser process to inform it about changes to the iframe's attributes. The parsing of CSP and the creation of `IframeAttributes` are key.

**5. Identifying Relationships with HTML, JavaScript, and CSS:**

As I analyze the methods, I would explicitly note the connections:

* **HTML:** The entire file revolves around the `<iframe>` tag and its attributes. The `ParseAttribute()` method is the prime example.
* **JavaScript:** The `sandbox()` and `featurePolicy()` methods return objects that are accessible via JavaScript. The interaction with V8 through `v8_html_iframe_element.h` is important. The handling of events (implicitly through frame loading) also ties into JavaScript.
* **CSS:**  `IsPresentationAttribute()` and `CollectStyleForPresentationAttribute()` directly manipulate CSS properties based on HTML attributes. The `SetCollapsed()` method triggers style recalculation.

**6. Looking for Logic and Reasoning:**

Within the methods, I'd identify decision points and transformations of data:

* The conditional logic within `ParseAttribute()` based on the attribute name.
* The parsing of the `sandbox` attribute string into flags.
* The logic for handling the `allowfullscreen` and `allowpaymentrequest` attributes and their interaction with the `allow` attribute.
* The parsing of the JSON string in `ConstructTrustTokenParams()`.

**7. Considering User and Programmer Errors:**

The console messages within `ParseAttribute()` are strong indicators of potential errors: invalid `sandbox` attribute, invalid `csp` attribute, usage of the deprecated `gesture="media"` attribute. The checks for secure contexts also highlight potential issues.

**8. Structuring the Output:**

Finally, I would organize the findings into logical sections:

* **Core Functionality:** A high-level overview of the file's purpose.
* **Relationship with HTML:**  Concrete examples of how the code interacts with HTML features.
* **Relationship with JavaScript:**  Examples of JavaScript APIs exposed by this code.
* **Relationship with CSS:**  Examples of how the code affects styling.
* **Logic and Reasoning:**  Explanation of some of the decision-making processes within the code, including hypothetical input/output for clarity.
* **Common Errors:**  Examples of mistakes users or developers might make that this code handles or flags.

This structured approach allows for a comprehensive understanding of the file's role and its interactions within the larger Chromium/Blink ecosystem. It moves from a general understanding to specific details, connecting the code to the web technologies it implements.
这个文件 `blink/renderer/core/html/html_iframe_element.cc` 是 Chromium Blink 渲染引擎中负责 `<iframe>` HTML 元素的核心实现。它定义了 `HTMLIFrameElement` 类，该类继承自 `HTMLFrameElementBase`，并包含了 `<iframe>` 元素的所有特定行为和属性处理逻辑。

以下是该文件的主要功能，以及它与 JavaScript、HTML 和 CSS 功能的关系，并附带相关示例：

**核心功能：**

1. **表示和管理 `<iframe>` 元素:**
   - 创建和管理 DOM 树中的 `<iframe>` 元素对象。
   - 处理 `<iframe>` 元素的属性，例如 `src`、`name`、`sandbox`、`allowfullscreen`、`referrerpolicy`、`srcdoc` 等。
   - 维护 `<iframe>` 元素的内部状态，例如是否被客户端折叠 (`collapsed_by_client_`)。

2. **处理 `<iframe>` 元素的属性:**
   - **解析属性值:**  当 `<iframe>` 元素的 HTML 属性发生变化时，`ParseAttribute()` 方法会被调用，负责解析新的属性值并更新对象的内部状态。
   - **属性驱动的行为:**  不同的属性值会触发不同的行为，例如：
     - `src`:  加载新的 URL 到 iframe 中。
     - `sandbox`:  设置 iframe 的安全沙箱策略。
     - `allowfullscreen`:  允许 iframe 请求全屏显示。
     - `referrerpolicy`:  控制 iframe 发起的请求的 Referer 首部。
     - `srcdoc`:  使用提供的 HTML 内容替换 iframe 的内容。
     - `name`:  设置 iframe 的名称，可以通过 JavaScript 引用。
     - `allow`: 设置 Feature Policy，控制 iframe 内的功能权限。
     - `policy`: 设置 Document Policy，影响 iframe 内的文档行为。
     - 其他呈现属性如 `width`、`height`、`align`、`frameborder` 用于设置 iframe 的样式。
   - **通知浏览器进程:**  `DidChangeAttributes()` 方法负责将 `<iframe>` 元素的关键属性变化通知到浏览器进程，以便进行跨进程的资源加载和安全策略管理。

3. **集成安全特性:**
   - **Sandbox:**  处理 `sandbox` 属性，解析其值并设置 iframe 的安全沙箱标志，限制 iframe 的能力，例如阻止脚本执行、表单提交、访问父窗口等。
   - **Content Security Policy (CSP):** 处理 `csp` 属性，为 iframe 设置内容安全策略，限制 iframe 可以加载的资源来源。
   - **Referrer Policy:** 处理 `referrerpolicy` 属性，控制 iframe 发起的请求的 Referer 首部。
   - **Feature Policy (Permissions Policy):** 处理 `allow` 属性，控制 iframe 内可以使用的浏览器特性，例如地理位置、麦克风、摄像头等。
   - **Document Policy:** 处理 `policy` 属性，定义影响 iframe 内文档行为的策略。
   - **Trust Tokens:** 处理 `privatetoken` 属性，允许 iframe 发起与 Trust Tokens 相关的操作。
   - **Credentialless Iframes:** 处理 `credentialless` 属性，允许创建不继承父文档 Cookie 和其他凭据的 iframe。

4. **与 Layout 引擎交互:**
   - `LayoutObjectIsNeeded()`:  确定是否需要为 `<iframe>` 元素创建一个布局对象。
   - `CreateLayoutObject()`:  创建 `LayoutIFrame` 对象，负责 `<iframe>` 元素的布局和渲染。

5. **处理 DOM 生命周期事件:**
   - `InsertedInto()`: 当 `<iframe>` 元素被插入到 DOM 树时执行相应的操作，例如将 iframe 的 `name` 添加到文档的命名项集合中。
   - `RemovedFrom()`: 当 `<iframe>` 元素从 DOM 树中移除时执行相应的操作，例如移除其在文档命名项集合中的记录。

**与 JavaScript 的关系:**

- **DOM API:** `HTMLIFrameElement` 类实现了 JavaScript 中 `HTMLIFrameElement` 接口对应的功能，使得 JavaScript 可以访问和操作 `<iframe>` 元素的属性和方法。
  - **示例:** JavaScript 可以通过 `iframeElement.src = "new_url";` 来修改 iframe 的 `src` 属性，触发 `HTMLIFrameElement::ParseAttribute()` 方法的执行。
  - **示例:** JavaScript 可以通过 `iframeElement.contentWindow` 或 `iframeElement.contentDocument` 访问 iframe 的 window 对象和 document 对象。
  - **示例:** `sandbox()` 方法返回一个 `DOMTokenList` 对象，JavaScript 可以通过该对象操作 `sandbox` 属性的值，例如 `iframeElement.sandbox.add('allow-scripts')`。
  - **示例:** `featurePolicy()` 方法返回一个 `DOMFeaturePolicy` 对象，JavaScript 可以查询和控制 iframe 的 Feature Policy。

**与 HTML 的关系:**

- **解析 HTML 标签:**  当 HTML 解析器遇到 `<iframe>` 标签时，会创建 `HTMLIFrameElement` 对象来表示该元素。
- **处理 HTML 属性:**  `ParseAttribute()` 方法直接处理 HTML 标签中的属性。
  - **示例:** `<iframe src="https://example.com"></iframe>` 中的 `src` 属性会被 `ParseAttribute()` 解析并用于加载指定的 URL。
  - **示例:** `<iframe sandbox="allow-scripts allow-forms"></iframe>` 中的 `sandbox` 属性会被解析并设置相应的安全沙箱标志。
- **呈现属性影响样式:**  某些 HTML 属性（如 `width`、`height`、`align`、`frameborder`）会影响 iframe 的默认样式。`CollectStyleForPresentationAttribute()` 方法负责将这些属性转换为对应的 CSS 样式。

**与 CSS 的关系:**

- **样式应用:**  CSS 规则可以应用于 `<iframe>` 元素，控制其外观和布局。
  - **示例:**  `iframe { border: 1px solid black; width: 500px; height: 300px; }`
- **呈现属性到样式:**  `IsPresentationAttribute()` 判断哪些 HTML 属性是呈现属性，`CollectStyleForPresentationAttribute()` 将这些属性的值转换为对应的 CSS 属性和值。
  - **假设输入:** `<iframe width="640" height="480"></iframe>`
  - **输出:** `CollectStyleForPresentationAttribute()` 会将 `width="640"` 转换为 `style->setProperty(CSSPropertyID::kWidth, Length(640, CSSPrimitiveValue::UnitType::kPixels))`，将 `height="480"` 转换为类似的 CSS `height` 属性。
- **客户端折叠 (`collapsed_by_client_`):** 当客户端（例如 Chrome 浏览器）决定折叠 iframe 时，会调用 `SetCollapsed(true)`，这会触发样式重新计算，可能导致 iframe 在布局中被隐藏。

**逻辑推理示例:**

**假设输入:**  一个 `<iframe>` 元素带有以下 `sandbox` 属性：`<iframe sandbox="allow-forms allow-popups"></iframe>`

**处理过程:**

1. HTML 解析器创建 `HTMLIFrameElement` 对象。
2. 解析器遇到 `sandbox` 属性，调用 `ParseAttribute(html_names::kSandboxAttr, "allow-forms allow-popups")`。
3. `ParseAttribute()` 方法调用 `sandbox_->DidUpdateAttributeValue(null_value, "allow-forms allow-popups")`。
4. `network::ParseWebSandboxPolicy("allow-forms allow-popups", ...)` 被调用，解析沙箱策略字符串。
5. 解析结果是 `network::mojom::blink::WebSandboxFlags::kAllowForms | network::mojom::blink::WebSandboxFlags::kAllowPopups`。
6. `SetSandboxFlags()` 方法被调用，设置 iframe 的内部沙箱标志。

**预期输出:**  该 iframe 将被允许提交表单和打开新的弹出窗口，但可能仍然受到其他沙箱限制（例如，不允许执行脚本，除非明确指定 `allow-scripts`）。

**用户或编程常见的使用错误示例:**

1. **拼写错误的 `sandbox` 属性值:**
   - **假设输入:** `<iframe sandbox="allow-scrpts"></iframe>` (拼写错误 "scripts")
   - **处理过程:** `network::ParseWebSandboxPolicy()` 可能无法识别 `allow-scrpts`，或者将其视为无效的沙箱标志。
   - **输出:**  浏览器控制台可能会输出警告信息：“Error while parsing the 'sandbox' attribute: Invalid sandbox keyword 'allow-scrpts'.”，并且该 iframe 的沙箱策略可能不会按预期设置。

2. **在不安全的上下文中使用需要安全上下文的属性:**
   - **假设输入:** 在一个 `http://` 页面中使用 `<iframe browsingtopics>`。
   - **处理过程:** `ParseAttribute()` 中会检查 `GetExecutionContext()->IsSecureContext()`。
   - **输出:** 如果当前上下文不是安全的（HTTPS），浏览器控制台可能会输出错误信息，指示 `browsingtopics` 属性只能在安全上下文中使用，并且该属性可能不会生效。

3. **误解 `allowfullscreen` 的作用:**
   - **错误使用:** 认为设置了 `allowfullscreen` 属性就一定能让 iframe 全屏。
   - **实际情况:** `allowfullscreen` 只是允许 iframe *请求* 全屏。用户仍然需要在 iframe 内部触发全屏 API (例如 JavaScript 的 `requestFullscreen()`)，并且浏览器可能会有额外的限制或用户提示。

4. **`csp` 属性值不合法:**
   - **假设输入:** `<iframe csp="script-src 'self''unsafe-inline'"></iframe>` (缺少空格分隔符)
   - **处理过程:** `MatchesTheSerializedCSPGrammar()` 或后续的 CSP 解析会检测到语法错误。
   - **输出:** 浏览器控制台会输出错误信息：“'csp' attribute is invalid: script-src 'self''unsafe-inline'”，并且该 `csp` 属性可能被忽略，或者应用了默认的限制更强的策略。

理解 `html_iframe_element.cc` 的功能对于深入了解 Chromium 如何处理 `<iframe>` 元素至关重要，特别是涉及到安全、性能和与其他 Web 技术的集成方面。

Prompt: 
```
这是目录为blink/renderer/core/html/html_iframe_element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
/*
 * Copyright (C) 1999 Lars Knoll (knoll@kde.org)
 *           (C) 1999 Antti Koivisto (koivisto@kde.org)
 *           (C) 2000 Simon Hausmann (hausmann@kde.org)
 *           (C) 2001 Dirk Mueller (mueller@kde.org)
 * Copyright (C) 2004, 2006, 2008, 2009 Apple Inc. All rights reserved.
 * Copyright (C) 2009 Ericsson AB. All rights reserved.
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

#include "third_party/blink/renderer/core/html/html_iframe_element.h"

#include "base/metrics/histogram_macros.h"
#include "services/network/public/cpp/features.h"
#include "services/network/public/cpp/web_sandbox_flags.h"
#include "services/network/public/mojom/trust_tokens.mojom-blink.h"
#include "services/network/public/mojom/web_sandbox_flags.mojom-blink.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/mojom/frame/frame.mojom-blink.h"
#include "third_party/blink/public/mojom/permissions_policy/permissions_policy.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_html_iframe_element.h"
#include "third_party/blink/renderer/core/css/css_property_names.h"
#include "third_party/blink/renderer/core/css/style_change_reason.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/frame/csp/content_security_policy.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/html/client_hints_util.h"
#include "third_party/blink/renderer/core/html/html_document.h"
#include "third_party/blink/renderer/core/html/trust_token_attribute_parsing.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/layout/layout_iframe.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/permissions_policy/document_policy_parser.h"
#include "third_party/blink/renderer/core/permissions_policy/iframe_policy.h"
#include "third_party/blink/renderer/core/permissions_policy/permissions_policy_parser.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/json/json_parser.h"
#include "third_party/blink/renderer/platform/network/content_security_policy_parsers.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"

namespace blink {

namespace {
// Cut down |value| if too long . This is used to convert the HTML attributes
// to report to the browser.
String ConvertToReportValue(const AtomicString& value) {
  if (value.IsNull()) {
    // If the value is null, report null so that it can be distinguishable from
    // an empty string.
    return String();
  }
  static constexpr size_t kMaxLengthToReport = 1024;
  return value.GetString().Left(kMaxLengthToReport);
}

}  // namespace

HTMLIFrameElement::HTMLIFrameElement(Document& document)
    : HTMLFrameElementBase(html_names::kIFrameTag, document),
      collapsed_by_client_(false),
      sandbox_(MakeGarbageCollected<HTMLIFrameElementSandbox>(this)),
      referrer_policy_(network::mojom::ReferrerPolicy::kDefault) {}

void HTMLIFrameElement::Trace(Visitor* visitor) const {
  visitor->Trace(sandbox_);
  visitor->Trace(policy_);
  HTMLFrameElementBase::Trace(visitor);
  Supplementable<HTMLIFrameElement>::Trace(visitor);
}

HTMLIFrameElement::~HTMLIFrameElement() = default;

const AttrNameToTrustedType& HTMLIFrameElement::GetCheckedAttributeTypes()
    const {
  DEFINE_STATIC_LOCAL(AttrNameToTrustedType, attribute_map,
                      ({{"srcdoc", SpecificTrustedType::kHTML}}));
  return attribute_map;
}

void HTMLIFrameElement::SetCollapsed(bool collapse) {
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

DOMTokenList* HTMLIFrameElement::sandbox() const {
  return sandbox_.Get();
}

DOMFeaturePolicy* HTMLIFrameElement::featurePolicy() {
  if (!policy_ && GetExecutionContext()) {
    policy_ = MakeGarbageCollected<IFramePolicy>(
        GetExecutionContext(), GetFramePolicy().container_policy,
        GetOriginForPermissionsPolicy());
  }
  return policy_.Get();
}

bool HTMLIFrameElement::IsPresentationAttribute(
    const QualifiedName& name) const {
  if (name == html_names::kWidthAttr || name == html_names::kHeightAttr ||
      name == html_names::kAlignAttr || name == html_names::kFrameborderAttr) {
    return true;
  }
  return HTMLFrameElementBase::IsPresentationAttribute(name);
}

void HTMLIFrameElement::CollectStyleForPresentationAttribute(
    const QualifiedName& name,
    const AtomicString& value,
    MutableCSSPropertyValueSet* style) {
  if (name == html_names::kWidthAttr) {
    AddHTMLLengthToStyle(style, CSSPropertyID::kWidth, value);
  } else if (name == html_names::kHeightAttr) {
    AddHTMLLengthToStyle(style, CSSPropertyID::kHeight, value);
  } else if (name == html_names::kAlignAttr) {
    ApplyAlignmentAttributeToStyle(value, style);
  } else if (name == html_names::kFrameborderAttr) {
    // LocalFrame border doesn't really match the HTML4 spec definition for
    // iframes. It simply adds a presentational hint that the border should be
    // off if set to zero.
    if (!value.ToInt()) {
      // Add a rule that nulls out our border width.
      for (CSSPropertyID property_id :
           {CSSPropertyID::kBorderTopWidth, CSSPropertyID::kBorderBottomWidth,
            CSSPropertyID::kBorderLeftWidth,
            CSSPropertyID::kBorderRightWidth}) {
        AddPropertyToPresentationAttributeStyle(
            style, property_id, 0, CSSPrimitiveValue::UnitType::kPixels);
      }
    }
  } else {
    HTMLFrameElementBase::CollectStyleForPresentationAttribute(name, value,
                                                               style);
  }
}

void HTMLIFrameElement::ParseAttribute(
    const AttributeModificationParams& params) {
  const QualifiedName& name = params.name;
  const AtomicString& value = params.new_value;
  // This is only set to true for values needed by the browser.
  bool should_call_did_change_attributes = false;
  if (name == html_names::kNameAttr) {
    auto* document = DynamicTo<HTMLDocument>(GetDocument());
    if (document && IsInDocumentTree()) {
      document->RemoveNamedItem(name_);
      document->AddNamedItem(value);
    }
    AtomicString old_name = name_;
    name_ = value;
    if (name_ != old_name) {
      FrameOwnerPropertiesChanged();
      should_call_did_change_attributes = true;
    }
    if (name_.Contains('\n')) {
      UseCounter::Count(GetDocument(), WebFeature::kFrameNameContainsNewline);
    }
    if (name_.Contains('<')) {
      UseCounter::Count(GetDocument(), WebFeature::kFrameNameContainsBrace);
    }
    if (name_.Contains('\n') && name_.Contains('<')) {
      UseCounter::Count(GetDocument(), WebFeature::kDanglingMarkupInWindowName);
      if (!name_.EndsWith('>')) {
        UseCounter::Count(GetDocument(),
                          WebFeature::kDanglingMarkupInWindowNameNotEndsWithGT);
        if (!name_.EndsWith('\n')) {
          UseCounter::Count(
              GetDocument(),
              WebFeature::kDanglingMarkupInWindowNameNotEndsWithNewLineOrGT);
        }
      }
    }
  } else if (name == html_names::kSandboxAttr) {
    sandbox_->DidUpdateAttributeValue(params.old_value, value);

    network::mojom::blink::WebSandboxFlags current_flags =
        network::mojom::blink::WebSandboxFlags::kNone;
    if (!value.IsNull()) {
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
    UseCounter::Count(GetDocument(), WebFeature::kSandboxViaIFrame);
  } else if (name == html_names::kReferrerpolicyAttr) {
    referrer_policy_ = network::mojom::ReferrerPolicy::kDefault;
    if (!value.IsNull()) {
      SecurityPolicy::ReferrerPolicyFromString(
          value, kSupportReferrerPolicyLegacyKeywords, &referrer_policy_);
      UseCounter::Count(GetDocument(),
                        WebFeature::kHTMLIFrameElementReferrerPolicyAttribute);
    }
  } else if (name == html_names::kAllowfullscreenAttr) {
    bool old_allow_fullscreen = allow_fullscreen_;
    allow_fullscreen_ = !value.IsNull();
    if (allow_fullscreen_ != old_allow_fullscreen) {
      // TODO(iclelland): Remove this use counter when the allowfullscreen
      // attribute state is snapshotted on document creation. crbug.com/682282
      if (allow_fullscreen_ && ContentFrame()) {
        UseCounter::Count(
            GetDocument(),
            WebFeature::
                kHTMLIFrameElementAllowfullscreenAttributeSetAfterContentLoad);
      }
      FrameOwnerPropertiesChanged();
      UpdateContainerPolicy();
    }
  } else if (name == html_names::kAllowpaymentrequestAttr) {
    bool old_allow_payment_request = allow_payment_request_;
    allow_payment_request_ = !value.IsNull();
    if (allow_payment_request_ != old_allow_payment_request) {
      FrameOwnerPropertiesChanged();
      UpdateContainerPolicy();
    }
  } else if (name == html_names::kCspAttr) {
    static const size_t kMaxLengthCSPAttribute = 4096;
    if (value && (value.Contains('\n') || value.Contains('\r') ||
                  !MatchesTheSerializedCSPGrammar(value.GetString()))) {
      // TODO(antoniosartori): It would be safer to block loading iframes with
      // invalid 'csp' attribute.
      required_csp_ = g_null_atom;
      GetDocument().AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
          mojom::blink::ConsoleMessageSource::kOther,
          mojom::blink::ConsoleMessageLevel::kError,
          "'csp' attribute is invalid: " + value));
    } else if (value && value.length() > kMaxLengthCSPAttribute) {
      // TODO(antoniosartori): It would be safer to block loading iframes with
      // invalid 'csp' attribute.
      required_csp_ = g_null_atom;
      GetDocument().AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
          mojom::blink::ConsoleMessageSource::kOther,
          mojom::blink::ConsoleMessageLevel::kError,
          String::Format("'csp' attribute too long. The max length for the "
                         "'csp' attribute is %zu bytes.",
                         kMaxLengthCSPAttribute)));
    } else if (required_csp_ != value) {
      required_csp_ = value;
      should_call_did_change_attributes = true;
      UseCounter::Count(GetDocument(), WebFeature::kIFrameCSPAttribute);
    }
  } else if (name == html_names::kBrowsingtopicsAttr) {
    if (GetExecutionContext() &&
        RuntimeEnabledFeatures::TopicsAPIEnabled(GetExecutionContext()) &&
        GetExecutionContext()->IsSecureContext()) {
      bool old_browsing_topics = !params.old_value.IsNull();
      bool new_browsing_topics = !params.new_value.IsNull();

      if (new_browsing_topics) {
        UseCounter::Count(GetDocument(),
                          WebFeature::kIframeBrowsingTopicsAttribute);
        UseCounter::Count(GetDocument(), WebFeature::kTopicsAPIAll);
      }

      if (new_browsing_topics != old_browsing_topics) {
        should_call_did_change_attributes = true;
      }
    }
  } else if (name == html_names::kAdauctionheadersAttr &&
             GetExecutionContext()) {
    if (!GetExecutionContext()->IsSecureContext()) {
      GetDocument().AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
          mojom::blink::ConsoleMessageSource::kOther,
          mojom::blink::ConsoleMessageLevel::kError,
          String("adAuctionHeaders: Protected Audience APIs "
                 "are only available in secure contexts.")));
    } else {
      if (params.new_value.IsNull() != params.old_value.IsNull()) {
        should_call_did_change_attributes = true;
      }
      if (!params.new_value.IsNull()) {
        UseCounter::Count(GetDocument(),
                          WebFeature::kSharedStorageAPI_Iframe_Attribute);
      }
    }
  } else if (name == html_names::kSharedstoragewritableAttr &&
             GetExecutionContext() &&
             RuntimeEnabledFeatures::SharedStorageAPIM118Enabled(
                 GetExecutionContext())) {
    if (!GetExecutionContext()->IsSecureContext()) {
      GetDocument().AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
          mojom::blink::ConsoleMessageSource::kOther,
          mojom::blink::ConsoleMessageLevel::kError,
          String("sharedStorageWritable: sharedStorage operations "
                 "are only available in secure contexts.")));
    } else {
      if (params.new_value.IsNull() != params.old_value.IsNull()) {
        should_call_did_change_attributes = true;
      }
      if (!params.new_value.IsNull()) {
        UseCounter::Count(GetDocument(),
                          WebFeature::kSharedStorageAPI_Iframe_Attribute);
      }
    }
  } else if (name == html_names::kCredentiallessAttr &&
             RuntimeEnabledFeatures::AnonymousIframeEnabled()) {
    bool new_value = !value.IsNull();
    if (credentialless_ != new_value) {
      credentialless_ = new_value;
      should_call_did_change_attributes = true;
    }
  } else if (name == html_names::kAllowAttr) {
    if (allow_ != value) {
      allow_ = value;
      UpdateContainerPolicy();
      if (!value.empty()) {
        UseCounter::Count(GetDocument(),
                          WebFeature::kFeaturePolicyAllowAttribute);
      }
    }
  } else if (name == html_names::kPolicyAttr) {
    if (required_policy_ != value) {
      required_policy_ = value;
      UpdateRequiredPolicy();
    }
  } else if (name == html_names::kPrivatetokenAttr) {
    UseCounter::Count(GetDocument(), WebFeature::kTrustTokenIframe);
    trust_token_ = value;
  } else {
    // Websites picked up a Chromium article that used this non-specified
    // attribute which ended up changing shape after the specification process.
    // This error message and use count will help developers to move to the
    // proper solution.
    // To avoid polluting the console, this is being recorded only once per
    // page.
    if (name == AtomicString("gesture") && value == AtomicString("media") &&
        GetDocument().Loader() &&
        !GetDocument().Loader()->GetUseCounter().IsCounted(
            WebFeature::kHTMLIFrameElementGestureMedia)) {
      UseCounter::Count(GetDocument(),
                        WebFeature::kHTMLIFrameElementGestureMedia);
      GetDocument().AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
          mojom::ConsoleMessageSource::kOther,
          mojom::ConsoleMessageLevel::kWarning,
          "<iframe gesture=\"media\"> is not supported. "
          "Use <iframe allow=\"autoplay\">, "
          "https://goo.gl/ximf56"));
    }

    if (name == html_names::kSrcAttr) {
      LogUpdateAttributeIfIsolatedWorldAndInDocument("iframe", params);
      if (src_ != value) {
        src_ = value;
        should_call_did_change_attributes = true;
      }
    }
    if (name == html_names::kIdAttr && id_ != value) {
      id_ = value;
      should_call_did_change_attributes = true;
    }
    if (name == html_names::kNameAttr && name_ != value) {
      name_ = value;
      should_call_did_change_attributes = true;
    }
    HTMLFrameElementBase::ParseAttribute(params);
  }
  if (should_call_did_change_attributes) {
    // This causes IPC to the browser. Only call it once per parsing.
    DidChangeAttributes();
  }
}

DocumentPolicyFeatureState HTMLIFrameElement::ConstructRequiredPolicy() const {
  if (!RuntimeEnabledFeatures::DocumentPolicyNegotiationEnabled(
          GetExecutionContext())) {
    return {};
  }

  if (!required_policy_.empty()) {
    UseCounter::Count(
        GetDocument(),
        mojom::blink::WebFeature::kDocumentPolicyIframePolicyAttribute);
  }

  PolicyParserMessageBuffer logger;
  DocumentPolicy::ParsedDocumentPolicy new_required_policy =
      DocumentPolicyParser::Parse(required_policy_, logger)
          .value_or(DocumentPolicy::ParsedDocumentPolicy{});

  for (const auto& message : logger.GetMessages()) {
    GetDocument().AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::blink::ConsoleMessageSource::kOther, message.level,
        message.content));
  }

  if (!new_required_policy.endpoint_map.empty()) {
    GetDocument().AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::blink::ConsoleMessageSource::kOther,
        mojom::blink::ConsoleMessageLevel::kWarning,
        "Iframe policy attribute cannot specify reporting endpoint."));
  }

  for (const auto& policy_entry : new_required_policy.feature_state) {
    mojom::blink::DocumentPolicyFeature feature = policy_entry.first;
    if (!GetDocument().DocumentPolicyFeatureObserved(feature)) {
      UMA_HISTOGRAM_ENUMERATION(
          "Blink.UseCounter.DocumentPolicy.PolicyAttribute", feature);
    }
  }
  return new_required_policy.feature_state;
}

ParsedPermissionsPolicy HTMLIFrameElement::ConstructContainerPolicy() const {
  if (!GetExecutionContext()) {
    return ParsedPermissionsPolicy();
  }

  scoped_refptr<const SecurityOrigin> src_origin =
      GetOriginForPermissionsPolicy();
  scoped_refptr<const SecurityOrigin> self_origin =
      GetExecutionContext()->GetSecurityOrigin();

  PolicyParserMessageBuffer logger;

  // Start with the allow attribute
  ParsedPermissionsPolicy container_policy =
      PermissionsPolicyParser::ParseAttribute(allow_, self_origin, src_origin,
                                              logger, GetExecutionContext());

  // Process the allow* attributes. These only take effect if the corresponding
  // feature is not present in the allow attribute's value.

  // If allowfullscreen attribute is present and no fullscreen policy is set,
  // enable the feature for all origins.
  if (AllowFullscreen()) {
    bool policy_changed = AllowFeatureEverywhereIfNotPresent(
        mojom::blink::PermissionsPolicyFeature::kFullscreen, container_policy);
    if (!policy_changed) {
      logger.Warn(
          "Allow attribute will take precedence over 'allowfullscreen'.");
    }
  }
  // If the allowpaymentrequest attribute is present and no 'payment' policy is
  // set, enable the feature for all origins.
  if (AllowPaymentRequest()) {
    bool policy_changed = AllowFeatureEverywhereIfNotPresent(
        mojom::blink::PermissionsPolicyFeature::kPayment, container_policy);
    // Measure cases where allowpaymentrequest had an actual effect, to see if
    // we can deprecate it. See https://crbug.com/1127988
    if (policy_changed) {
      UseCounter::Count(GetDocument(),
                        WebFeature::kAllowPaymentRequestAttributeHasEffect);
    } else {
      logger.Warn(
          "Allow attribute will take precedence over 'allowpaymentrequest'.");
    }
  }

  // Factor in changes in client hint permissions.
  UpdateIFrameContainerPolicyWithDelegationSupportForClientHints(
      container_policy, GetDocument().domWindow());

  // Update the JavaScript policy object associated with this iframe, if it
  // exists.
  if (policy_) {
    policy_->UpdateContainerPolicy(container_policy, src_origin);
  }

  for (const auto& message : logger.GetMessages()) {
    GetDocument().AddConsoleMessage(
        MakeGarbageCollected<ConsoleMessage>(
            mojom::blink::ConsoleMessageSource::kOther, message.level,
            message.content),
        /* discard_duplicates */ true);
  }

  return container_policy;
}

bool HTMLIFrameElement::LayoutObjectIsNeeded(const DisplayStyle& style) const {
  return ContentFrame() && !collapsed_by_client_ &&
         HTMLElement::LayoutObjectIsNeeded(style);
}

LayoutObject* HTMLIFrameElement::CreateLayoutObject(const ComputedStyle&) {
  return MakeGarbageCollected<LayoutIFrame>(this);
}

Node::InsertionNotificationRequest HTMLIFrameElement::InsertedInto(
    ContainerNode& insertion_point) {
  InsertionNotificationRequest result =
      HTMLFrameElementBase::InsertedInto(insertion_point);

  auto* html_doc = DynamicTo<HTMLDocument>(GetDocument());
  if (html_doc && insertion_point.IsInDocumentTree()) {
    html_doc->AddNamedItem(name_);
  }
  LogAddElementIfIsolatedWorldAndInDocument("iframe", html_names::kSrcAttr);
  return result;
}

void HTMLIFrameElement::RemovedFrom(ContainerNode& insertion_point) {
  HTMLFrameElementBase::RemovedFrom(insertion_point);
  auto* html_doc = DynamicTo<HTMLDocument>(GetDocument());
  if (html_doc && insertion_point.IsInDocumentTree()) {
    html_doc->RemoveNamedItem(name_);
  }
}

bool HTMLIFrameElement::IsInteractiveContent() const {
  return true;
}

network::mojom::ReferrerPolicy HTMLIFrameElement::ReferrerPolicyAttribute() {
  return referrer_policy_;
}

network::mojom::blink::TrustTokenParamsPtr
HTMLIFrameElement::ConstructTrustTokenParams() const {
  if (!trust_token_) {
    return nullptr;
  }

  JSONParseError parse_error;
  std::unique_ptr<JSONValue> parsed_attribute =
      ParseJSON(trust_token_, &parse_error);
  if (!parsed_attribute) {
    GetDocument().AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::blink::ConsoleMessageSource::kOther,
        mojom::blink::ConsoleMessageLevel::kError,
        "iframe trusttoken attribute was invalid JSON: " + parse_error.message +
            String::Format(" (line %d, col %d)", parse_error.line,
                           parse_error.column)));
    return nullptr;
  }

  network::mojom::blink::TrustTokenParamsPtr parsed_params =
      internal::TrustTokenParamsFromJson(std::move(parsed_attribute));
  if (!parsed_params) {
    GetDocument().AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::blink::ConsoleMessageSource::kOther,
        mojom::blink::ConsoleMessageLevel::kError,
        "Couldn't parse iframe trusttoken attribute (was it missing a "
        "field?)"));
    return nullptr;
  }

  // Only the send-redemption-record (the kSigning variant) operation is
  // valid in the iframe context.
  if (parsed_params->operation !=
      network::mojom::blink::TrustTokenOperationType::kSigning) {
    GetDocument().AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::blink::ConsoleMessageSource::kOther,
        mojom::blink::ConsoleMessageLevel::kError,
        "Trust Tokens: Attempted a trusttoken operation which isn't "
        "send-redemption-record in an iframe."));
    return nullptr;
  }

  if (!GetExecutionContext()->IsFeatureEnabled(
          mojom::blink::PermissionsPolicyFeature::kTrustTokenRedemption)) {
    GetExecutionContext()->AddConsoleMessage(MakeGarbageCollected<
                                             ConsoleMessage>(
        mojom::blink::ConsoleMessageSource::kOther,
        mojom::blink::ConsoleMessageLevel::kError,
        "Trust Tokens: Attempted redemption or signing without the "
        "private-state-token-redemption Permissions Policy feature present."));
    return nullptr;
  }

  return parsed_params;
}

void HTMLIFrameElement::DidChangeAttributes() {
  // Don't notify about updates if ContentFrame() is null, for example when
  // the subframe hasn't been created yet; or if we are in the middle of
  // swapping one frame for another, in which case the final state
  // will be propagated at the end of the swapping operation.
  if (is_swapping_frames() || !ContentFrame()) {
    return;
  }

  // ParseContentSecurityPolicies needs a url to resolve report endpoints and
  // for matching the keyword 'self'. However, the csp attribute does not allow
  // report endpoints. Moreover, in the csp attribute, 'self' should not match
  // the owner's url, but rather the frame src url. This is taken care by the
  // Content-Security-Policy Embedded Enforcement algorithm, implemented in the
  // NavigationRequest. That's why we pass an empty url here.
  Vector<network::mojom::blink::ContentSecurityPolicyPtr> csp =
      ParseContentSecurityPolicies(
          required_csp_,
          network::mojom::blink::ContentSecurityPolicyType::kEnforce,
          network::mojom::blink::ContentSecurityPolicySource::kHTTP, KURL());
  DCHECK_LE(csp.size(), 1u);

  auto attributes = mojom::blink::IframeAttributes::New();
  attributes->parsed_csp_attribute = csp.empty() ? nullptr : std::move(csp[0]);
  attributes->credentialless = credentialless_;

  if (RuntimeEnabledFeatures::TopicsAPIEnabled(GetExecutionContext()) &&
      GetExecutionContext()->IsSecureContext()) {
    attributes->browsing_topics =
        !FastGetAttribute(html_names::kBrowsingtopicsAttr).IsNull();
  }

  if (GetExecutionContext()->IsSecureContext()) {
    attributes->ad_auction_headers =
        !FastGetAttribute(html_names::kAdauctionheadersAttr).IsNull();
  }

  if (RuntimeEnabledFeatures::SharedStorageAPIM118Enabled(
          GetExecutionContext()) &&
      GetExecutionContext()->IsSecureContext()) {
    attributes->shared_storage_writable_opted_in =
        !FastGetAttribute(html_names::kSharedstoragewritableAttr).IsNull();
  }

  attributes->id = ConvertToReportValue(id_);
  attributes->name = ConvertToReportValue(name_);
  attributes->src = ConvertToReportValue(src_);
  GetDocument().GetFrame()->GetLocalFrameHostRemote().DidChangeIframeAttributes(
      ContentFrame()->GetFrameToken(), std::move(attributes));

  // Make sure we update the srcdoc value, if any, in the browser.
  String srcdoc_value = "";
  if (FastHasAttribute(html_names::kSrcdocAttr)) {
    srcdoc_value = FastGetAttribute(html_names::kSrcdocAttr).GetString();
  }
  GetDocument().GetFrame()->GetLocalFrameHostRemote().DidChangeSrcDoc(
      ContentFrame()->GetFrameToken(), srcdoc_value);
}

}  // namespace blink

"""

```