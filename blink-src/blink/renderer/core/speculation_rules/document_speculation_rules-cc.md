Response:
My thinking process to analyze the provided C++ code snippet and answer the user's request goes like this:

1. **Understand the Goal:** The user wants to know the functionality of the `DocumentSpeculationRules.cc` file in the Chromium Blink engine. They are particularly interested in its relation to JavaScript, HTML, and CSS, and common usage errors. They also want to know how a user might trigger this code and a summary of its functionality.

2. **Initial Code Scan and Keyword Identification:** I'll quickly scan the code for important keywords and structures. I see:
    * `#include` statements:  These reveal dependencies and hint at the file's responsibilities. Notable includes are related to speculation rules, DOM, CSS, frames, HTML elements, and platform features.
    * `namespace blink`: This confirms the context is the Blink rendering engine.
    * Class definition: `class DocumentSpeculationRules`.
    * Methods like `AddRuleSet`, `RemoveRuleSet`, `LinkInserted`, `HrefAttributeChanged`, `UpdateSpeculationCandidates`, etc. These suggest the class manages speculation rules and reacts to DOM changes.
    * Mentions of "prefetch" and "prerender": This immediately flags the core functionality as related to speculative loading.
    * References to `HTMLAnchorElementBase`: This indicates interaction with links.
    * References to `ComputedStyle`: This shows interaction with CSS.
    * `SpeculationRuleSet`, `SpeculationCandidate`: These are key data structures for managing speculation.
    * `ConsoleMessage`, `UseCounter`:  These indicate logging and usage tracking.

3. **High-Level Functionality Deduction:** Based on the keywords, includes, and method names, I can infer the primary function of `DocumentSpeculationRules`: It's responsible for managing and applying speculation rules defined in a document. These rules dictate when and how the browser should speculatively load resources (prefetching, prerendering) based on link attributes or `<script type="speculationrules">` elements.

4. **Relating to JavaScript, HTML, and CSS:**

    * **HTML:** The code directly interacts with HTML elements, especially `<a>` (anchor) and `<area>` elements, as seen by methods like `LinkInserted`, `LinkRemoved`, and `HrefAttributeChanged`. The speculation rules themselves are often defined within `<script type="speculationrules">` tags in the HTML.
    * **CSS:** The code checks the computed style of links using `GetComputedStyle()`. This is crucial for determining if a link is visible and therefore a good candidate for speculation. The `DocumentStyleUpdated`, `ChildStyleRecalcBlocked`, and `DidStyleChildren` methods further highlight the connection to CSS and the rendering pipeline.
    * **JavaScript:** While the provided code is C++, the *trigger* for the speculation rules often comes from JavaScript adding or modifying `<script type="speculationrules">` elements. The code doesn't directly *execute* JavaScript, but it reacts to changes initiated by it.

5. **Logical Reasoning and Examples:**

    * **Input:** A `<script type="speculationrules">` tag is added to the HTML.
    * **Processing:** The `AddRuleSet` method parses the JSON within the tag and creates `SpeculationRuleSet` objects. The code then identifies links matching the rules and creates `SpeculationCandidate` objects.
    * **Output:** The browser starts prefetching or prerendering the URLs specified in the `SpeculationCandidate` objects.

    * **Input:** A user hovers over a link that matches a prerender rule.
    * **Processing:**  While not explicitly shown in *this* file, other parts of Blink (related to input handling) would trigger the speculation logic. `DocumentSpeculationRules` would be involved in checking if a prerender rule matches the hovered link.
    * **Output:** The browser starts prerendering the linked page.

6. **Common User/Programming Errors:**

    * **Incorrect JSON syntax:** If the JSON within the `<script type="speculationrules">` tag is invalid, the rules won't be parsed correctly, and no speculative loading will occur. The `SpeculationRulesLoadOutcome` enum and related logging suggest this is handled.
    * **Lax `referrerpolicy`:** The code explicitly checks `referrerpolicy` attributes and warns in the console if a policy is too lax for cross-site requests. This is a common security-related mistake.
    * **Specifying non-HTTP/HTTPS URLs:**  The `push_link_candidates` function checks `!link->HrefURL().ProtocolIsInHTTPFamily()`, highlighting that speculation is generally for web pages.
    * **Overly broad selectors:**  Using very general selectors in the speculation rules might lead to unnecessary prefetching/prerendering of many resources, potentially wasting bandwidth.

7. **User Actions as Debugging Clues:**

    * **Page load:** The initial parsing of `<script type="speculationrules">` happens during page load.
    * **Dynamic addition of `<script>` tags:** JavaScript can add speculation rules dynamically.
    * **Modifying link attributes (href, rel, referrerpolicy, target):** These trigger updates in `DocumentSpeculationRules`.
    * **User interaction (hover, click):** While not directly in this file, these events can trigger the application of speculation rules.
    * **CSS changes (visibility, display):** Changes that affect the computed style of links can trigger re-evaluation of speculation candidates.

8. **Summarizing Functionality (Part 1):** Based on the analysis of the first part of the code, I can summarize its core responsibilities:

    * **Parsing and Managing Speculation Rules:**  It takes rules from `<script type="speculationrules">` tags and stores them.
    * **Identifying Speculation Candidates:** It matches these rules against links on the page to determine which URLs to speculatively load.
    * **Considering Link Attributes:** It respects attributes like `rel`, `referrerpolicy`, and `target` on links.
    * **Considering CSS:** It uses computed styles to determine link visibility.
    * **Updating Candidates on DOM/CSS Changes:** It reacts to changes in the DOM and CSS to update the list of speculation candidates.
    * **Interfacing with the Browser:** It communicates the speculation candidates to the browser for prefetching and prerendering.
    * **Logging and Metrics:** It tracks the usage and errors related to speculation rules.

By following these steps, I can systematically analyze the code and provide a comprehensive and accurate answer to the user's request, including the requested details about its relationship with web technologies, potential errors, and debugging.
好的，让我们来分析一下 `blink/renderer/core/speculation_rules/document_speculation_rules.cc` 文件的功能。

**文件功能概述：**

`DocumentSpeculationRules.cc` 文件的主要功能是**管理和应用文档中定义的推测规则（Speculation Rules）**。这些规则指示浏览器在用户执行导航操作之前，提前执行某些操作，例如预取资源（prefetch）或预渲染页面（prerender），以提高页面加载速度和用户体验。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

1. **HTML:**
    *   **定义推测规则：** 推测规则通常通过 HTML 中的 `<script type="speculationrules">` 标签来定义，其中包含 JSON 格式的规则。
        ```html
        <script type="speculationrules">
        {
          "prerender": [
            { "source": "list", "urls": ["/page1.html", "/page2.html"] }
          ]
        }
        </script>
        ```
        `DocumentSpeculationRules.cc` 负责解析这些 HTML 中的 `<script>` 标签，提取并解析其中的 JSON 规则。
    *   **关联链接：** 推测规则可以基于页面上的链接（`<a>` 或 `<area>` 元素）的属性来应用，例如 `href`, `rel`, `referrerpolicy`, `target` 等。
        ```html
        <a href="/next_page.html" rel="prefetch">下一页</a>
        ```
        `DocumentSpeculationRules.cc` 监听这些链接的插入、移除和属性变化，并根据定义的规则来决定是否进行预取或预渲染。

2. **JavaScript:**
    *   **动态添加/修改推测规则：** JavaScript 可以动态地创建或修改 `<script type="speculationrules">` 标签，从而改变推测规则。
        ```javascript
        const script = document.createElement('script');
        script.type = 'speculationrules';
        script.textContent = JSON.stringify({
          "prefetch": [
            { "source": "document", "where": { "selector": "a[href^='/api/']" } }
          ]
        });
        document.head.appendChild(script);
        ```
        `DocumentSpeculationRules.cc` 会响应这些动态变化，重新解析和应用新的规则。
    *   **用户交互触发：** 虽然这个文件本身不执行 JavaScript，但用户的交互行为（例如鼠标悬停在链接上）可能触发浏览器开始应用与该链接相关的推测规则，而 `DocumentSpeculationRules.cc` 负责管理这些规则。

3. **CSS:**
    *   **基于 CSS 选择器的规则：** 推测规则可以基于 CSS 选择器来定位需要应用规则的链接。
        ```json
        {
          "prerender": [
            { "source": "document", "where": { "selector": ".prerender-candidate" } }
          ]
        }
        ```
        `DocumentSpeculationRules.cc` 使用 Blink 的 CSS 选择器引擎来匹配文档中的元素。
    *   **链接可见性：**  `DocumentSpeculationRules.cc` 会考虑链接的计算样式（ComputedStyle），例如链接是否可见（`display: none` 等），来决定是否进行推测。例如，隐藏的链接通常不会被视为预取/预渲染的候选对象。代码中可以看到 `ComputedStyle::IsNullOrEnsured(link->GetComputedStyle())` 的检查。

**逻辑推理、假设输入与输出：**

**假设输入：**

1. HTML 包含以下推测规则：
    ```html
    <script type="speculationrules">
    {
      "prefetch": [
        { "source": "list", "urls": ["/image1.png", "/image2.png"] }
      ],
      "prerender": [
        { "source": "document", "where": { "selector": "a.prerender" } }
      ]
    }
    </script>
    <a href="/target_page.html" class="prerender">预渲染页面</a>
    <img src="/another_image.png">
    ```
2. 用户鼠标悬停在 `<a href="/target_page.html" class="prerender">` 链接上。

**逻辑推理：**

1. `DocumentSpeculationRules.cc` 会解析 HTML 中的推测规则，识别出两个规则集：一个用于预取 `/image1.png` 和 `/image2.png`，另一个用于预渲染匹配选择器 `a.prerender` 的链接。
2. 当 DOM 中插入链接时 (`LinkInserted`)，或者链接的属性发生变化时 (`HrefAttributeChanged` 等)，`DocumentSpeculationRules.cc` 会检查这些链接是否匹配任何推测规则。
3. 当用户鼠标悬停在带有 `class="prerender"` 的链接上时（虽然这个文件不直接处理鼠标事件，但它会收到来自更上层模块的通知），并且该链接匹配了 "prerender" 规则，`DocumentSpeculationRules.cc` 会指示浏览器开始预渲染 `/target_page.html`。
4. 同时，根据 "prefetch" 规则，浏览器会开始预取 `/image1.png` 和 `/image2.png`。

**假设输出：**

1. 浏览器开始预取 `/image1.png` 和 `/image2.png`。
2. 当用户点击带有 `class="prerender"` 的链接时，由于页面已经被预渲染，加载会非常迅速。

**用户或编程常见的使用错误及举例说明：**

1. **JSON 格式错误：** 推测规则必须是有效的 JSON。如果 JSON 格式错误，`DocumentSpeculationRules.cc` 在解析时会失败，规则将不会生效。
    ```html
    <script type="speculationrules">
    { // 缺少引号
      prerender: [
        { "source": "list", "urls": ["/page1.html"] }
      ]
    }
    </script>
    ```
    **错误现象：** 预渲染不会发生，控制台可能会有 JSON 解析错误提示。

2. **referrerpolicy 使用不当：** 对于跨域的预取或预渲染，需要使用更严格的 `referrerpolicy`。如果策略过于宽松，可能会被浏览器阻止。
    ```html
    <a href="https://example.com/other_page.html" referrerpolicy="unsafe-url" rel="prefetch">跨域预取</a>
    ```
    **错误现象：** 预取可能会被阻止，控制台会输出警告信息，提示 `referrer policy` 不可接受。代码中 `AcceptableReferrerPolicy` 函数和 `MakeReferrerWarning` 函数就处理了这种情况。

3. **选择器错误：** 如果推测规则中的 CSS 选择器无法匹配到任何元素，则规则不会生效。
    ```html
    <script type="speculationrules">
    {
      "prerender": [
        { "source": "document", "where": { "selector": ".non-existent-class" } }
      ]
    }
    </script>
    <a href="/some_page.html" class="some-other-class">目标链接</a>
    ```
    **错误现象：** 预渲染不会发生，因为选择器 `.non-existent-class` 没有匹配到任何链接。

4. **过度使用推测规则：**  如果页面上定义了过多的推测规则，或者规则匹配了大量的链接，可能会导致浏览器预取或预渲染过多的资源，浪费用户带宽和设备资源。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户在浏览器中打开一个网页。**
2. **网页的 HTML 中包含了 `<script type="speculationrules">` 标签，定义了预取或预渲染规则。**  `DocumentSpeculationRules::AddRuleSet` 方法会被调用，解析这些规则。
3. **网页加载过程中，浏览器解析 HTML，遇到 `<a>` 或 `<area>` 链接。** `DocumentSpeculationRules::LinkInserted` 方法会被调用。
4. **如果链接的 `href` 属性发生变化（例如通过 JavaScript 动态修改），`DocumentSpeculationRules::HrefAttributeChanged` 方法会被调用。**
5. **如果链接的 `rel` 或 `referrerpolicy` 等属性发生变化，相应的 `DocumentSpeculationRules::RelAttributeChanged` 或 `DocumentSpeculationRules::ReferrerPolicyAttributeChanged` 方法会被调用。**
6. **Blink 的 CSS 引擎计算出链接的样式。** `DocumentSpeculationRules::LinkGainedOrLostComputedStyle` 方法会被调用，以更新推测候选者的状态。
7. **当满足推测规则的条件时（例如，鼠标悬停在链接上），`DocumentSpeculationRules::UpdateSpeculationCandidates` 方法会被调用，生成推测候选者列表，并发送给浏览器进行预取或预渲染。**
8. **在调试过程中，可以在 `DocumentSpeculationRules.cc` 中设置断点，例如在 `AddRuleSet`、`LinkInserted`、`UpdateSpeculationCandidates` 等方法中，来观察规则的解析、链接的匹配以及推测候选者的生成过程。** 还可以查看控制台的输出，了解是否有关于推测规则的警告或错误信息。

**归纳一下它的功能 (第 1 部分)：**

`DocumentSpeculationRules.cc` 的主要功能是：

*   **接收和解析来自 HTML `<script type="speculationrules">` 标签的推测规则。**
*   **监听文档中链接（`<a>` 和 `<area>` 元素）的插入、移除和属性变化。**
*   **根据定义的推测规则和链接的属性，识别出潜在的预取或预渲染目标。**
*   **考虑链接的 CSS 计算样式，以决定是否进行推测。**
*   **管理和更新推测候选者列表。**
*   **与浏览器的其他组件交互，指示其执行预取或预渲染操作。**
*   **处理与 `referrerpolicy` 相关的安全问题。**
*   **记录推测规则的使用情况和错误信息。**

总而言之，`DocumentSpeculationRules.cc` 是 Blink 引擎中负责实现和管理基于 HTML 的推测规则的核心组件，它连接了 HTML、CSS 和浏览器的预加载机制，旨在提升网页的加载性能。

Prompt: 
```
这是目录为blink/renderer/core/speculation_rules/document_speculation_rules.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/speculation_rules/document_speculation_rules.h"

#include "base/containers/contains.h"
#include "base/metrics/histogram_functions.h"
#include "base/not_fatal_until.h"
#include "base/numerics/safe_conversions.h"
#include "base/ranges/algorithm.h"
#include "base/state_transitions.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/mojom/use_counter/metrics/web_feature.mojom-shared.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/css/style_rule.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_utilities.h"
#include "third_party/blink/renderer/core/dom/flat_tree_traversal.h"
#include "third_party/blink/renderer/core/dom/shadow_including_tree_order_traversal.h"
#include "third_party/blink/renderer/core/execution_context/agent.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/event_handler_registry.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/html/html_anchor_element.h"
#include "third_party/blink/renderer/core/html/html_area_element.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/lcp_critical_path_predictor/lcp_critical_path_predictor.h"
#include "third_party/blink/renderer/core/loader/speculation_rule_loader.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/core/speculation_rules/document_rule_predicate.h"
#include "third_party/blink/renderer/core/speculation_rules/speculation_candidate.h"
#include "third_party/blink/renderer/core/speculation_rules/speculation_rules_metrics.h"
#include "third_party/blink/renderer/platform/scheduler/public/event_loop.h"
#include "third_party/blink/renderer/platform/weborigin/referrer.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/weborigin/security_policy.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {

namespace {

// https://wicg.github.io/nav-speculation/prefetch.html#list-of-sufficiently-strict-speculative-navigation-referrer-policies
bool AcceptableReferrerPolicy(const Referrer& referrer,
                              bool is_initially_same_site) {
  // Lax referrer policies are acceptable for same-site. The browser is
  // responsible for aborting in the case of cross-site redirects with lax
  // referrer policies.
  if (is_initially_same_site)
    return true;

  switch (referrer.referrer_policy) {
    case network::mojom::ReferrerPolicy::kAlways:
    case network::mojom::ReferrerPolicy::kNoReferrerWhenDowngrade:
    case network::mojom::ReferrerPolicy::kOrigin:
    case network::mojom::ReferrerPolicy::kOriginWhenCrossOrigin:
      return false;

    case network::mojom::ReferrerPolicy::kNever:
    case network::mojom::ReferrerPolicy::kSameOrigin:
    case network::mojom::ReferrerPolicy::kStrictOrigin:
    case network::mojom::ReferrerPolicy::kStrictOriginWhenCrossOrigin:
      return true;

    case network::mojom::ReferrerPolicy::kDefault:
      NOTREACHED();
  }
}

String SpeculationActionAsString(mojom::blink::SpeculationAction action) {
  switch (action) {
    case mojom::blink::SpeculationAction::kPrefetch:
    case mojom::blink::SpeculationAction::kPrefetchWithSubresources:
      return "prefetch";
    case mojom::blink::SpeculationAction::kPrerender:
      return "prerender";
  }
}

String MakeReferrerWarning(mojom::blink::SpeculationAction action,
                           const KURL& url,
                           const Referrer& referrer,
                           bool has_link) {
  const String action_string = SpeculationActionAsString(action);

  const String suggested_fix =
      has_link ? "A stricter referrer policy may be set using the matched "
                 "link's \"referrerpolicy\" attribute, or it may be set "
                 "specifically for the " +
                     action_string +
                     " request using the \"referrer_policy\" key in the "
                     "speculation rule."
               : "A stricter referrer policy may be set for this specific " +
                     action_string +
                     " request using the \"referrer_policy\" key in the "
                     "speculation rule.";
  constexpr auto kExampleAcceptablePolicy =
      network::mojom::ReferrerPolicy::kStrictOriginWhenCrossOrigin;

  return "Ignored attempt to " + action_string + " " + url.ElidedString() +
         " due to unacceptable referrer policy (" +
         SecurityPolicy::ReferrerPolicyAsString(referrer.referrer_policy) +
         "). " + suggested_fix + " For example, the policy \"" +
         SecurityPolicy::ReferrerPolicyAsString(kExampleAcceptablePolicy) +
         "\" is sufficiently strict.";
}

// Computes a referrer based on a Speculation Rule, and its URL or the link it
// is matched against. Return std::nullopt if the computed referrer policy is
// not acceptable (see AcceptableReferrerPolicy above).
std::optional<Referrer> GetReferrer(const SpeculationRule* rule,
                                    const SpeculationRuleSet& rule_set,
                                    Document& document,
                                    mojom::blink::SpeculationAction action,
                                    HTMLAnchorElementBase* link,
                                    std::optional<KURL> opt_url) {
  ExecutionContext* execution_context = document.GetExecutionContext();
  DCHECK(link || opt_url);
  network::mojom::ReferrerPolicy referrer_policy;
  if (rule->referrer_policy()) {
    referrer_policy = rule->referrer_policy().value();
  } else if (link && link->HasRel(kRelationNoReferrer)) {
    referrer_policy = network::mojom::ReferrerPolicy::kNever;
    UseCounter::Count(document,
                      WebFeature::kSpeculationRulesUsedLinkReferrerPolicy);
  } else if (link && link->FastHasAttribute(html_names::kReferrerpolicyAttr)) {
    // Override |referrer_policy| with value derived from link's
    // referrerpolicy attribute (if valid).
    bool valid = SecurityPolicy::ReferrerPolicyFromString(
        link->FastGetAttribute(html_names::kReferrerpolicyAttr),
        kSupportReferrerPolicyLegacyKeywords, &referrer_policy);
    if (valid) {
      UseCounter::Count(document,
                        WebFeature::kSpeculationRulesUsedLinkReferrerPolicy);
    } else {
      referrer_policy = execution_context->GetReferrerPolicy();
    }
  } else {
    referrer_policy = execution_context->GetReferrerPolicy();
  }

  String outgoing_referrer = execution_context->OutgoingReferrer();
  KURL url = link ? link->HrefURL() : opt_url.value();
  scoped_refptr<const SecurityOrigin> url_origin = SecurityOrigin::Create(url);
  const bool is_initially_same_site =
      url_origin->IsSameSiteWith(execution_context->GetSecurityOrigin());
  Referrer referrer =
      SecurityPolicy::GenerateReferrer(referrer_policy, url, outgoing_referrer);

  if (!AcceptableReferrerPolicy(referrer, is_initially_same_site)) {
    auto* console_message = MakeGarbageCollected<ConsoleMessage>(
        mojom::blink::ConsoleMessageSource::kOther,
        mojom::blink::ConsoleMessageLevel::kWarning,
        MakeReferrerWarning(action, url, referrer, link));
    Vector<DOMNodeId> nodes;
    if (rule_set.source()->GetNodeId()) {
      nodes.push_back(*rule_set.source()->GetNodeId());
    }
    if (link) {
      nodes.push_back(link->GetDomNodeId());
    }
    console_message->SetNodes(document.GetFrame(), std::move(nodes));
    execution_context->AddConsoleMessage(console_message);
    UseCounter::Count(document,
                      WebFeature::kSpeculationRulesRejectedLaxReferrerPolicy);
    return std::nullopt;
  }

  return referrer;
}

// The reason for calling |UpdateSpeculationCandidates| for metrics.
// Currently, this is designed to measure the impact of the project of
// retriggering preloading on BFCache restoration (crbug.com/1449163), so
// other update reasons (such as ruleset insertion/removal etc...) will be
// tentatively classified as |kOther|.
// These values are persisted to logs. Entries should not be renumbered and
// numeric values should never be reused.
enum class UpdateSpeculationCandidatesReason {
  kOther = 0,
  kRestoredFromBFCache = 1,
  kMaxValue = kRestoredFromBFCache,
};

}  // namespace

std::ostream& operator<<(
    std::ostream& o,
    const DocumentSpeculationRules::PendingUpdateState& s) {
  return o << static_cast<unsigned>(s);
}

// static
const char DocumentSpeculationRules::kSupplementName[] =
    "DocumentSpeculationRules";

// static
DocumentSpeculationRules& DocumentSpeculationRules::From(Document& document) {
  if (DocumentSpeculationRules* self = FromIfExists(document))
    return *self;

  auto* self = MakeGarbageCollected<DocumentSpeculationRules>(document);
  ProvideTo(document, self);
  return *self;
}

// static
DocumentSpeculationRules* DocumentSpeculationRules::FromIfExists(
    Document& document) {
  return Supplement::From<DocumentSpeculationRules>(document);
}

DocumentSpeculationRules::DocumentSpeculationRules(Document& document)
    : Supplement(document), host_(document.GetExecutionContext()) {
  if (!base::FeatureList::IsEnabled(features::kLCPTimingPredictorPrerender2)) {
    return;
  }
  auto* frame = GetSupplementable()->GetFrame();
  if (!frame) {
    return;
  }
  // LCPP is supposed to be attached to outer-most-main-frame only.
  // This matches with the current implementation of prerender2.
  LCPCriticalPathPredictor* lcpp = frame->GetLCPP();
  if (!lcpp) {
    return;
  }
  lcpp->AddLCPPredictedCallback(WTF::BindOnce(
      &DocumentSpeculationRules::OnLCPPredicted, WrapPersistent(this)));
}

void DocumentSpeculationRules::OnLCPPredicted(const Element*) {
  CHECK(base::FeatureList::IsEnabled(features::kLCPTimingPredictorPrerender2));
  mojom::blink::SpeculationHost* host = GetHost();
  if (!host) {
    return;
  }
  host->OnLCPPredicted();
}

void DocumentSpeculationRules::AddRuleSet(SpeculationRuleSet* rule_set) {
  SpeculationRulesLoadOutcome outcome = SpeculationRulesLoadOutcome::kSuccess;
  if (rule_set->ShouldReportUMAForError()) {
    if (rule_set->source()->IsFromRequest()) {
      outcome = SpeculationRulesLoadOutcome::kParseErrorFetched;
    } else if (rule_set->source()->IsFromInlineScript()) {
      outcome = SpeculationRulesLoadOutcome::kParseErrorInline;
    } else if (rule_set->source()->IsFromBrowserInjected()) {
      outcome = SpeculationRulesLoadOutcome::kParseErrorBrowserInjected;
    } else {
      NOTREACHED() << "error with unknown rule source";
    }
  } else if (rule_set->source()->IsFromBrowserInjectedAndRespectsOptOut()) {
    // Don't insert browser-injected rule sets that respect the opt-out on pages
    // that have other rules.
    for (const auto& other_rule_set : rule_sets_) {
      if (!other_rule_set->source()->IsFromBrowserInjected()) {
        CountSpeculationRulesLoadOutcome(
            SpeculationRulesLoadOutcome::kAutoSpeculationRulesOptedOut);
        UseCounter::Count(GetSupplementable(),
                          WebFeature::kAutoSpeculationRulesOptedOut);
        return;
      }
    }
  }

  CountSpeculationRulesLoadOutcome(outcome);

  DCHECK(!base::Contains(rule_sets_, rule_set));
  rule_sets_.push_back(rule_set);
  if (rule_set->has_document_rule()) {
    UseCounter::Count(GetSupplementable(),
                      WebFeature::kSpeculationRulesDocumentRules);
    InitializeIfNecessary();
    InvalidateAllLinks();
    if (!rule_set->selectors().empty()) {
      UpdateSelectors();
    }
  }
  if (!wants_pointer_events_ && rule_set->requires_unfiltered_input()) {
    wants_pointer_events_ = true;
    Document& document = *GetSupplementable();
    if (auto* frame = document.GetFrame()) {
      frame->GetEventHandlerRegistry().DidAddEventHandler(
          document, EventHandlerRegistry::kPointerEvent);
    }
  }
  QueueUpdateSpeculationCandidates();

  probe::DidAddSpeculationRuleSet(*GetSupplementable(), *rule_set);

  // Record some use counters about the kinds of actions being proposed.
  if (rule_set->prefetch_rules().size()) {
    UseCounter::Count(GetSupplementable(),
                      rule_set->source()->IsFromBrowserInjected()
                          ? WebFeature::kSpeculationRulesBrowserPrefetchRule
                          : WebFeature::kSpeculationRulesAuthorPrefetchRule);
  }
  if (rule_set->prerender_rules().size()) {
    UseCounter::Count(GetSupplementable(),
                      rule_set->source()->IsFromBrowserInjected()
                          ? WebFeature::kSpeculationRulesBrowserPrerenderRule
                          : WebFeature::kSpeculationRulesAuthorPrerenderRule);
  }

  // If non-browser-injected speculation rules are injected, then remove all
  // opt-out respecting browser-injected speculation rules.
  if (!rule_set->source()->IsFromBrowserInjected()) {
    HeapVector<Member<SpeculationRuleSet>> to_remove;
    for (const auto& other_rule_set : rule_sets_) {
      if (other_rule_set->source()->IsFromBrowserInjectedAndRespectsOptOut()) {
        to_remove.push_back(other_rule_set);
      }
    }

    if (!to_remove.empty()) {
      UseCounter::Count(GetSupplementable(),
                        WebFeature::kAutoSpeculationRulesOptedOut);
      for (const auto& to_remove_rule_set : to_remove) {
        RemoveRuleSet(to_remove_rule_set);
      }
    }
  }
}

void DocumentSpeculationRules::RemoveRuleSet(SpeculationRuleSet* rule_set) {
  auto it = base::ranges::remove(rule_sets_, rule_set);
  CHECK(it != rule_sets_.end(), base::NotFatalUntil::M130)
      << "rule set was removed without existing";
  rule_sets_.erase(it, rule_sets_.end());
  if (rule_set->has_document_rule()) {
    InvalidateAllLinks();
    if (!rule_set->selectors().empty()) {
      UpdateSelectors();
    }
  }
  if (wants_pointer_events_ && rule_set->requires_unfiltered_input() &&
      base::ranges::none_of(rule_sets_,
                            &SpeculationRuleSet::requires_unfiltered_input)) {
    wants_pointer_events_ = false;
    Document& document = *GetSupplementable();
    if (auto* frame = document.GetFrame()) {
      frame->GetEventHandlerRegistry().DidRemoveEventHandler(
          document, EventHandlerRegistry::kPointerEvent);
    }
  }

  // When a rule set is removed, we want to assure that an update including the
  // removal is promptly processed, so that the browser can cancel any activity
  // that is no longer needed. This makes it more predictable when the author
  // can re-add those rules to start a new speculation (to freshen it), rather
  // than continuing an existing one.
  //
  // Since style doesn't necessarily become clean promptly enough for that (a
  // scheduled microtask is what we have in mind), we want style to be forced
  // clean by the deadline, if necessary.
  QueueUpdateSpeculationCandidates(/*force_style_update=*/true);

  probe::DidRemoveSpeculationRuleSet(*GetSupplementable(), *rule_set);
}

void DocumentSpeculationRules::AddSpeculationRuleLoader(
    SpeculationRuleLoader* speculation_rule_loader) {
  speculation_rule_loaders_.insert(speculation_rule_loader);
}

void DocumentSpeculationRules::RemoveSpeculationRuleLoader(
    SpeculationRuleLoader* speculation_rule_loader) {
  speculation_rule_loaders_.erase(speculation_rule_loader);
}

void DocumentSpeculationRules::LinkInserted(HTMLAnchorElementBase* link) {
  if (!initialized_)
    return;

  DCHECK(link->IsLink());
  DCHECK(link->isConnected());
  AddLink(link);
  QueueUpdateSpeculationCandidates();
}

void DocumentSpeculationRules::LinkRemoved(HTMLAnchorElementBase* link) {
  if (!initialized_)
    return;

  DCHECK(link->IsLink());
  RemoveLink(link);
  QueueUpdateSpeculationCandidates();
}

void DocumentSpeculationRules::HrefAttributeChanged(
    HTMLAnchorElementBase* link,
    const AtomicString& old_value,
    const AtomicString& new_value) {
  if (!initialized_)
    return;

  DCHECK_NE(old_value, new_value);
  DCHECK(link->isConnected());

  if (old_value.IsNull())
    AddLink(link);
  else if (new_value.IsNull())
    RemoveLink(link);
  else
    InvalidateLink(link);

  QueueUpdateSpeculationCandidates();
}

void DocumentSpeculationRules::ReferrerPolicyAttributeChanged(
    HTMLAnchorElementBase* link) {
  LinkAttributeChanged(link);
}

void DocumentSpeculationRules::RelAttributeChanged(
    HTMLAnchorElementBase* link) {
  LinkAttributeChanged(link);
}

void DocumentSpeculationRules::TargetAttributeChanged(
    HTMLAnchorElementBase* link) {
  LinkAttributeChanged(link);
}

void DocumentSpeculationRules::DocumentReferrerPolicyChanged() {
  DocumentPropertyChanged();
}

void DocumentSpeculationRules::DocumentBaseURLChanged() {
  if (initialized_)
    InvalidateAllLinks();
  QueueUpdateSpeculationCandidates();
}

void DocumentSpeculationRules::DocumentBaseTargetChanged() {
  DocumentPropertyChanged();
}

void DocumentSpeculationRules::LinkMatchedSelectorsUpdated(
    HTMLAnchorElementBase* link) {
  DCHECK(initialized_);
  InvalidateLink(link);
  QueueUpdateSpeculationCandidates();
}

void DocumentSpeculationRules::LinkGainedOrLostComputedStyle(
    HTMLAnchorElementBase* link) {
  if (!initialized_) {
    return;
  }
  InvalidateLink(link);
  QueueUpdateSpeculationCandidates();
}

void DocumentSpeculationRules::DocumentStyleUpdated() {
  if (pending_update_state_ == PendingUpdateState::kOnNextStyleUpdate) {
    UpdateSpeculationCandidates();
  }
}

void DocumentSpeculationRules::ChildStyleRecalcBlocked(Element* root) {
  if (!initialized_) {
    return;
  }

  if (!elements_blocking_child_style_recalc_.insert(root).is_new_entry) {
    return;
  }

  bool queue_update = false;

  Node* node = FlatTreeTraversal::Next(*root, root);
  while (node) {
    if (node->IsLink() && (node->HasTagName(html_names::kATag) ||
                           node->HasTagName(html_names::kAreaTag))) {
      HTMLAnchorElementBase* anchor = To<HTMLAnchorElementBase>(node);
      if (stale_links_.insert(anchor).is_new_entry) {
        InvalidateLink(anchor);
        queue_update = true;
      }
    }

    // If |node| is an element that is already marked as blocking child style
    // recalc, we don't need to traverse its subtree (all of its children should
    // already be accounted for).
    if (auto* element = DynamicTo<Element>(node);
        element && elements_blocking_child_style_recalc_.Contains(element)) {
      node = FlatTreeTraversal::NextSkippingChildren(*node, root);
      continue;
    }

    node = FlatTreeTraversal::Next(*node, root);
  }

  if (queue_update) {
    QueueUpdateSpeculationCandidates();
  }
}

void DocumentSpeculationRules::DidStyleChildren(Element* root) {
  if (!initialized_) {
    return;
  }

  if (!elements_blocking_child_style_recalc_.Take(root)) {
    return;
  }

  bool queue_update = false;

  Node* node = FlatTreeTraversal::Next(*root, root);
  while (node) {
    if (node->IsLink() && (node->HasTagName(html_names::kATag) ||
                           node->HasTagName(html_names::kAreaTag))) {
      HTMLAnchorElementBase* anchor = To<HTMLAnchorElementBase>(node);
      if (auto it = stale_links_.find(anchor); it != stale_links_.end()) {
        stale_links_.erase(it);
        InvalidateLink(anchor);
        queue_update = true;
      }
    }

    // If |node| is a display-locked element that is already marked as blocking
    // child style recalc, we don't need to traverse its children.
    if (auto* element = DynamicTo<Element>(node);
        element && elements_blocking_child_style_recalc_.Contains(element)) {
      node = FlatTreeTraversal::NextSkippingChildren(*node, root);
      continue;
    }

    node = FlatTreeTraversal::Next(*node, root);
  }

  if (queue_update) {
    QueueUpdateSpeculationCandidates();
  }
}

void DocumentSpeculationRules::DisplayLockedElementDisconnected(Element* root) {
  elements_blocking_child_style_recalc_.erase(root);
  // Note: We don't queue an update or invalidate any links here because
  // |root|'s children will also be disconnected shortly after this.
}

void DocumentSpeculationRules::DocumentRestoredFromBFCache() {
  first_update_after_restored_from_bfcache_ = true;
  QueueUpdateSpeculationCandidates();
}

void DocumentSpeculationRules::InitiatePreview(const KURL& url) {
  CHECK(base::FeatureList::IsEnabled(features::kLinkPreview));

  auto* host = GetHost();
  if (host) {
    host->InitiatePreview(url);
  }
}

void DocumentSpeculationRules::QueueUpdateSpeculationCandidates(
    bool force_style_update) {
  const bool microtask_already_queued = IsMicrotaskQueued();

  bool needs_microtask = true;
  if (force_style_update) {
    SetPendingUpdateState(
        PendingUpdateState::kMicrotaskQueuedWithForcedStyleUpdate);
  } else if (pending_update_state_ == PendingUpdateState::kNoUpdate) {
    SetPendingUpdateState(PendingUpdateState::kMicrotaskQueued);
  } else {
    // An update of some kind is already scheduled, whether on a microtask or
    // the next style update. That's sufficient.
    needs_microtask = false;
  }

  auto* execution_context = GetSupplementable()->GetExecutionContext();
  if (needs_microtask && !microtask_already_queued && execution_context) {
    execution_context->GetAgent()->event_loop()->EnqueueMicrotask(WTF::BindOnce(
        &DocumentSpeculationRules::UpdateSpeculationCandidatesMicrotask,
        WrapWeakPersistent(this)));
  }
}

void DocumentSpeculationRules::Trace(Visitor* visitor) const {
  Supplement::Trace(visitor);
  visitor->Trace(rule_sets_);
  visitor->Trace(host_);
  visitor->Trace(speculation_rule_loaders_);
  visitor->Trace(matched_links_);
  visitor->Trace(unmatched_links_);
  visitor->Trace(pending_links_);
  visitor->Trace(stale_links_);
  visitor->Trace(elements_blocking_child_style_recalc_);
  visitor->Trace(selectors_);
}

mojom::blink::SpeculationHost* DocumentSpeculationRules::GetHost() {
  if (!host_.is_bound()) {
    auto* execution_context = GetSupplementable()->GetExecutionContext();
    if (!execution_context)
      return nullptr;
    execution_context->GetBrowserInterfaceBroker().GetInterface(
        host_.BindNewPipeAndPassReceiver(
            execution_context->GetTaskRunner(TaskType::kInternalDefault)));
  }
  return host_.get();
}

void DocumentSpeculationRules::UpdateSpeculationCandidatesMicrotask() {
  DCHECK(IsMicrotaskQueued());

  // Wait for style to be clean before proceeding. Or force it, if this update
  // needs to happen promptly.
  Document& document = *GetSupplementable();
  if (document.NeedsLayoutTreeUpdate()) {
    if (pending_update_state_ ==
        PendingUpdateState::kMicrotaskQueuedWithForcedStyleUpdate) {
      document.UpdateStyleAndLayoutTree();
    } else {
      SetPendingUpdateState(PendingUpdateState::kOnNextStyleUpdate);
      return;
    }
  }

  UpdateSpeculationCandidates();
}

void DocumentSpeculationRules::UpdateSpeculationCandidates() {
  Document& document = *GetSupplementable();
  DCHECK_NE(pending_update_state_, PendingUpdateState::kNoUpdate);
  DCHECK(!document.NeedsLayoutTreeUpdate());

  // We are actually performing the update below, so mark as no update pending.
  SetPendingUpdateState(PendingUpdateState::kNoUpdate);

  mojom::blink::SpeculationHost* host = GetHost();
  auto* execution_context = document.GetExecutionContext();
  if (!host || !execution_context) {
    return;
  }

  HeapVector<Member<SpeculationCandidate>> candidates;
  auto push_candidates = [&candidates, &document](
                             mojom::blink::SpeculationAction action,
                             SpeculationRuleSet* rule_set,
                             const HeapVector<Member<SpeculationRule>>& rules) {
    for (SpeculationRule* rule : rules) {
      for (const KURL& url : rule->urls()) {
        std::optional<Referrer> referrer = GetReferrer(
            rule, *rule_set, document, action, /*link=*/nullptr, url);
        if (!referrer)
          continue;

        // Ensured by `SpeculationRuleSet`.
        CHECK(!rule->target_browsing_context_name_hint() ||
              action == mojom::blink::SpeculationAction::kPrerender);
        CHECK(!rule->requires_anonymous_client_ip_when_cross_origin() ||
              action == mojom::blink::SpeculationAction::kPrefetch);

        candidates.push_back(MakeGarbageCollected<SpeculationCandidate>(
            url, action, referrer.value(),
            rule->requires_anonymous_client_ip_when_cross_origin(),
            rule->target_browsing_context_name_hint().value_or(
                mojom::blink::SpeculationTargetHint::kNoHint),
            rule->eagerness(), rule->no_vary_search_expected().Clone(),
            rule->injection_type(), rule_set, /*anchor=*/nullptr));
      }
    }
  };

  for (SpeculationRuleSet* rule_set : rule_sets_) {
    push_candidates(mojom::blink::SpeculationAction::kPrefetch, rule_set,
                    rule_set->prefetch_rules());

    if (RuntimeEnabledFeatures::SpeculationRulesPrefetchWithSubresourcesEnabled(
            execution_context)) {
      push_candidates(
          mojom::blink::SpeculationAction::kPrefetchWithSubresources, rule_set,
          rule_set->prefetch_with_subresources_rules());
    }

    // If kPrerender2 is enabled, collect all prerender speculation rules.
    if (RuntimeEnabledFeatures::Prerender2Enabled(execution_context)) {
      push_candidates(mojom::blink::SpeculationAction::kPrerender, rule_set,
                      rule_set->prerender_rules());

      // Set the flag to evict the cached data of Session Storage when the
      // document is frozen or unload to avoid reusing old data in the cache
      // after the session storage has been modified by another renderer
      // process. See crbug.com/1215680 for more details.
      LocalFrame* frame = document.GetFrame();
      if (frame && frame->IsMainFrame()) {
        frame->SetEvictCachedSessionStorageOnFreezeOrUnload();
      }
    }
  }

  // Add candidates derived from document rule predicates.
  AddLinkBasedSpeculationCandidates(candidates);

  // Remove candidates for links to fragments in the current document. These are
  // unlikely to be useful to preload, because such navigations are likely to
  // trigger fragment navigation (see
  // |FrameLoader::ShouldPerformFragmentNavigation|).
  // Note that the document's URL is not necessarily the same as the base URL
  // (e,g., when a <base> element is present in the document).
  const KURL& document_url = document.Url();
  auto last = base::ranges::remove_if(candidates, [&](const auto& candidate) {
    const KURL& url = candidate->url();
    return url.HasFragmentIdentifier() &&
           EqualIgnoringFragmentIdentifier(url, document_url);
  });
  candidates.Shrink(base::checked_cast<wtf_size_t>(last - candidates.begin()));

  probe::SpeculationCandidatesUpdated(document, candidates);

  using SpeculationEagerness = blink::mojom::SpeculationEagerness;
  base::EnumSet<SpeculationEagerness, SpeculationEagerness::kMinValue,
                SpeculationEagerness::kMaxValue>
      eagerness_set;

  Vector<mojom::blink::SpeculationCandidatePtr> mojom_candidates;
  mojom_candidates.ReserveInitialCapacity(candidates.size());
  for (SpeculationCandidate* candidate : candidates) {
    eagerness_set.Put(candidate->eagerness());
    mojom_candidates.push_back(candidate->ToMojom());
  }

  host->UpdateSpeculationCandidates(std::move(mojom_candidates));

  if (eagerness_set.Has(SpeculationEagerness::kConservative)) {
    UseCounter::Count(document,
                      WebFeature::kSpeculationRulesEagernessConservative);
  }
  if (eagerness_set.Has(SpeculationEagerness::kModerate)) {
    UseCounter::Count(document, WebFeature::kSpeculationRulesEagernessModerate);
  }
  if (eagerness_set.Has(SpeculationEagerness::kEager)) {
    UseCounter::Count(document, WebFeature::kSpeculationRulesEagernessEager);
  }

  base::UmaHistogramEnumeration(
      "Preloading.Experimental.UpdateSpeculationCandidatesReason",
      first_update_after_restored_from_bfcache_
          ? UpdateSpeculationCandidatesReason::kRestoredFromBFCache
          : UpdateSpeculationCandidatesReason::kOther);

  first_update_after_restored_from_bfcache_ = false;
}

void DocumentSpeculationRules::AddLinkBasedSpeculationCandidates(
    HeapVector<Member<SpeculationCandidate>>& candidates) {
  // Match all the unmatched
  while (!pending_links_.empty()) {
    auto it = pending_links_.begin();
    HTMLAnchorElementBase* link = *it;
    HeapVector<Member<SpeculationCandidate>>* link_candidates =
        MakeGarbageCollected<HeapVector<Member<SpeculationCandidate>>>();
    Document& document = *GetSupplementable();
    ExecutionContext* execution_context = document.GetExecutionContext();
    CHECK(execution_context);

    const auto push_link_candidates =
        [&link, &link_candidates, &document, this](
            mojom::blink::SpeculationAction action,
            SpeculationRuleSet* rule_set,
            const HeapVector<Member<SpeculationRule>>& speculation_rules) {
          if (!link->HrefURL().ProtocolIsInHTTPFamily()) {
            return;
          }

          // We exclude links that don't have a ComputedStyle stored (or have
          // a ComputedStyle only because EnsureComputedStyle was called, and
          // otherwise wouldn't). This corresponds to links that are not in
          // the flat tree or links with a "display: none" inclusive-ancestor.
          if (ComputedStyle::IsNullOrEnsured(link->GetComputedStyle())) {
            return;
          }

          // Links with display locked ancestors can have a stale
          // ComputedStyle, i.e. a ComputedStyle that wasn't updated during a
          // style update because the element isn't currently being rendered,
          // but is not discarded either. We ignore these links as well.
          if (stale_links_.Contains(link)) {
            return;
          }

          for (SpeculationRule* rule : speculation_rules) {
            if (!rule->predicate())
              continue;
            if (!rule->predicate()->Matches(*link))
              continue;

            std::optional<Referrer> referrer =
                GetReferrer(rule, *rule_set, document, action, link,
                            /*opt_url=*/std::nullopt);
            if (!referrer)
              continue;

            mojom::blink::SpeculationTargetHint target_hint =
                mojom::blink::SpeculationTargetHint::kNoHint;
            if (action == mojom::blink::SpeculationAction::kPrerender) {
              if (rule->target_browsing_context_name_hint()) {
                target_hint = rule->target_browsing_context_name_hint().value();
              } else {
                // Obtain target hint from the link's target (if specified).
                target_hint =
                    SpeculationRuleSet::SpeculationTargetHintFromString(
                        link->GetEffectiveTarget());
              }
            }

            SpeculationCandidate* candidate =
                MakeGarbageCollected<SpeculationCandidate>(
                    link->HrefURL(), action, referrer.value(),
                    rule->requires_anonymous_client_ip_when_cross_origin(),
                    target_hint, rule->eagerness(),
                    rule->no_vary_search_expected().Clone(),
                    rule->injection_type(), rule_set, link);
            link_candidates->push_back(std::move(candidate));
          }
        };

    for (SpeculationRuleSet* rule_set : rule_sets_) {
      push_link_candidates(mojom::blink::SpeculationAction::kPrefetch, rule_set,
                           rule_set->prefetch_rules());

      if (RuntimeEnabledFeatures::
              SpeculationRulesPrefetchWithSubresourcesEnabled(
                  execution_context)) {
        push_link_candidates(
            mojom::blink::SpeculationAction::kPrefetchWithSubresources,
            rule_set, rule_set->prefetch_with_subresources_rules());
      }

      if (RuntimeEnabledFeatures::Prerender2Enabled(execution_context)) {
        push_link_candidates(mojom::blink::SpeculationAction::kPrerender,
                             rule_set, rule_set->prerender_rules());
      }
    }

    if (!link_candidates->empty()) {
      matched_links_.Set(link, link_candidate
"""


```