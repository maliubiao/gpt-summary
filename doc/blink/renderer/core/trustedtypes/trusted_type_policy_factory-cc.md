Response:
Let's break down the thought process for analyzing the provided C++ code.

1. **Understand the Goal:** The request is to understand the functionality of the `TrustedTypePolicyFactory` class in the Chromium Blink engine. This involves identifying its purpose, its relationship with web technologies (JavaScript, HTML, CSS), and potential usage errors.

2. **Initial Scan for Keywords and Structures:**  Start by quickly scanning the code for important keywords and structural elements. Look for:
    * Class name: `TrustedTypePolicyFactory`
    * Included headers: These often give clues about dependencies and functionality (e.g., `TrustedTypePolicy.h`, `v8_trusted_html.h`, `dom/document.h`, `frame/csp/content_security_policy.h`).
    * Member variables: `policy_map_`, `empty_html_`, `empty_script_`, `hadAssignmentError`.
    * Member functions: `createPolicy`, `defaultPolicy`, `isHTML`, `isScript`, `isScriptURL`, `emptyHTML`, `emptyScript`, `getPropertyType`, `getAttributeType`, `getTypeMapping`, `CountTrustedTypeAssignmentError`, `IsEventHandlerAttributeName`.
    * Static data structures: `kTypeTable`, `BuildAttributeVector`, `BuildPropertyVector`.
    * Namespaces: `blink`.

3. **Deduce Core Functionality from the Class Name and Key Functions:**  The name "TrustedTypePolicyFactory" strongly suggests that this class is responsible for creating and managing `TrustedTypePolicy` objects. The `createPolicy` function confirms this. The presence of `isHTML`, `isScript`, and `isScriptURL` indicates it deals with different types of trusted content.

4. **Analyze `createPolicy`:** This function is central. Key observations:
    * It takes a `policy_name` and `TrustedTypePolicyOptions`.
    * It checks for `RuntimeEnabledFeatures::TrustedTypeBeforePolicyCreationEventEnabled()`, suggesting an event mechanism before policy creation.
    * It interacts with `ContentSecurityPolicy` to check if policy creation is allowed. This immediately links it to web security.
    * It handles duplicate policy names, particularly the "default" policy.
    * It uses `UseCounter` to track usage.
    * It creates and stores `TrustedTypePolicy` objects in `policy_map_`.
    * It throws `DOMException` in case of errors.

5. **Examine the Static Data Structures (`BuildAttributeVector`, `BuildPropertyVector`):** These are crucial.
    * They define mappings between HTML elements, attributes/properties, and specific trusted types (`kHTML`, `kScript`, `kScriptURL`).
    * The `EVENT_HANDLER_LIST` macro in `BuildAttributeVector` clearly connects Trusted Types to event handlers.
    * This reveals the core mechanism of how the system knows what kind of trusted type is required for a particular attribute or property.

6. **Analyze the "Getter" Functions (`getPropertyType`, `getAttributeType`):** These functions use the static data structures to determine the expected trusted type for a given HTML element, attribute, or property.

7. **Understand `getTypeMapping`:** This function generates a JavaScript-compatible representation of the mappings defined in `BuildAttributeVector` and `BuildPropertyVector`. This explains how JavaScript code can understand the Trusted Types requirements.

8. **Connect to Web Technologies (JavaScript, HTML, CSS):**
    * **JavaScript:** The `getTypeMapping` function directly provides information to JavaScript. The `isHTML`, `isScript`, `isScriptURL` functions are used in the JavaScript bindings. The policy creation happens due to JavaScript calls.
    * **HTML:** The static data structures explicitly list HTML elements and attributes. Trusted Types aim to protect against vulnerabilities when manipulating HTML.
    * **CSS:** While not directly manipulated by this class, the protection offered by Trusted Types can indirectly prevent CSS injection vulnerabilities if those vulnerabilities rely on injecting malicious HTML or JavaScript. *Initially, I might not see a direct link to CSS, but upon closer thought about the attack vectors Trusted Types prevent, I realize the indirect connection.*

9. **Identify Potential Usage Errors:**
    * Trying to create a policy with a name that violates the CSP.
    * Trying to create a duplicate policy, especially the "default" policy.
    * Attempting to use untrusted strings in contexts that require trusted types. *This requires inferring from the overall purpose of Trusted Types.*

10. **Consider Logic and Assumptions:**
    * The code assumes attribute and element names are case-insensitive (converted to lowercase).
    * It handles namespaces correctly.
    * The use of `AtomicString` suggests optimization for string comparisons.

11. **Structure the Output:** Organize the findings into clear categories:
    * Core Functionality
    * Relationship with JavaScript, HTML, CSS (with examples)
    * Logical Reasoning (with hypothetical inputs and outputs where appropriate - even if the "output" is a type, not a concrete value)
    * Common Usage Errors

12. **Refine and Elaborate:** Review the generated output and add more detail where necessary. For instance, explaining *why* Trusted Types are important for security when discussing the relationship with web technologies. Explain the purpose of the `BeforeCreatePolicyEvent`.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This seems like just a factory for creating policy objects."
* **Correction:** "Wait, there's a lot of interaction with CSP and predefined mappings. It's not *just* a factory; it's enforcing security rules."
* **Initial thought:** "How does this relate to JavaScript?"
* **Correction:** "The `getTypeMapping` function is the key. Also, the `is...` functions are likely used in the V8 bindings for type checking in JavaScript."
* **Initial thought:** "Does it directly interact with CSS?"
* **Correction:** "Not directly, but it prevents HTML and JavaScript injection, which can be used to exploit CSS vulnerabilities, so there's an indirect benefit."

By following this iterative process of scanning, deducing, analyzing, connecting, and refining, we arrive at a comprehensive understanding of the `TrustedTypePolicyFactory` class.
这个 `TrustedTypePolicyFactory.cc` 文件是 Chromium Blink 引擎中负责创建和管理 Trusted Types Policy 的核心组件。Trusted Types 是一种 Web 安全机制，旨在防止基于 DOM 的跨站脚本攻击 (DOM XSS)。

以下是该文件的主要功能：

**1. Trusted Type Policy 的创建和管理:**

* **`createPolicy(const String& policy_name, ExceptionState& exception_state)` 和 `createPolicy(const String& policy_name, const TrustedTypePolicyOptions* policy_options, ExceptionState& exception_state)`:**  这两个函数是创建新的 `TrustedTypePolicy` 对象的核心方法。
    * 它接收一个策略名称 (`policy_name`) 和可选的策略选项 (`policy_options`)。
    * 它会检查 Content Security Policy (CSP) 中是否允许创建具有该名称的策略。
    * 如果启用了 `TrustedTypeBeforePolicyCreationEventEnabled` 特性，它会派发一个 `BeforeCreatePolicyEvent`，允许开发者取消策略的创建。
    * 它会检查是否已经存在同名的策略，特别是对于 "default" 策略。
    * 如果策略创建被 CSP 阻止或存在重名，它会抛出 JavaScript `TypeError` 异常。
    * 创建成功后，会将新的 `TrustedTypePolicy` 对象存储在 `policy_map_` 中。
    * 它会使用 `UseCounter` 记录策略创建的相关指标，例如是否使用了空名称。
* **`defaultPolicy() const`:**  返回名为 "default" 的 `TrustedTypePolicy` 对象，如果没有则返回 `nullptr`。
* **`policy_map_`:**  一个 `HashMap`，用于存储已创建的 `TrustedTypePolicy` 对象，键是策略名称，值是 `TrustedTypePolicy` 对象。

**2. 判断 JavaScript 值的类型:**

* **`isHTML(ScriptState* script_state, const ScriptValue& script_value)`:** 判断给定的 JavaScript 值是否是 `TrustedHTML` 类型的实例。
* **`isScript(ScriptState* script_state, const ScriptValue& script_value)`:** 判断给定的 JavaScript 值是否是 `TrustedScript` 类型的实例。
* **`isScriptURL(ScriptState* script_state, const ScriptValue& script_value)`:** 判断给定的 JavaScript 值是否是 `TrustedScriptURL` 类型的实例。

**3. 提供空的 Trusted Types 对象:**

* **`emptyHTML() const`:** 返回一个空的 `TrustedHTML` 对象。
* **`emptyScript() const`:** 返回一个空的 `TrustedScript` 对象。

**4. 获取属性或属性的期望 Trusted Type 类型:**

* **`getPropertyType(const String& tagName, const String& propertyName, const String& elementNS) const`:**  根据 HTML 标签名 (`tagName`)、属性名 (`propertyName`) 和命名空间 (`elementNS`)，返回该属性期望的 Trusted Type 类型（例如 "TrustedHTML"、"TrustedScript" 或 "TrustedScriptURL"）。
* **`getAttributeType(const String& tagName, const String& attributeName, const String& tagNS, const String& attributeNS) const`:** 根据 HTML 标签名 (`tagName`)、属性名 (`attributeName`)、标签命名空间 (`tagNS`) 和属性命名空间 (`attributeNS`)，返回该属性期望的 Trusted Type 类型。

**5. 生成类型映射表:**

* **`getTypeMapping(ScriptState* script_state) const` 和 `getTypeMapping(ScriptState* script_state, const String& ns) const`:** 生成一个 JavaScript 对象，描述了哪些 HTML 属性和属性需要特定的 Trusted Type。这个映射表可以被 JavaScript 代码使用，以便更好地理解和使用 Trusted Types。

**6. 统计 Trusted Type 赋值错误:**

* **`CountTrustedTypeAssignmentError()`:** 记录发生了 Trusted Type 赋值错误的次数。这用于 Chrome 的使用情况统计。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **JavaScript:**
    * **策略创建:**  JavaScript 代码可以使用 `TrustedTypes.createPolicy()` 方法来调用 `TrustedTypePolicyFactory::createPolicy()` 创建新的策略。
        ```javascript
        // 假设没有名为 'myPolicy' 的策略
        const myPolicy = trustedTypes.createPolicy('myPolicy', {
          createHTML: (input) => `<p>${input}</p>`,
          createScript: (input) => `console.log(${input});`,
          createScriptURL: (input) => `https://example.com/${input}`
        });
        ```
        **假设输入:**  JavaScript 代码调用 `trustedTypes.createPolicy('myPolicy', ...)`。
        **输出:** 如果 CSP 允许创建名为 'myPolicy' 的策略，则会在 `policy_map_` 中创建一个新的 `TrustedTypePolicy` 对象，并返回给 JavaScript。否则，会抛出一个 `TypeError`。
    * **类型检查:**  `isHTML`, `isScript`, `isScriptURL` 方法对应 JavaScript 中 `instanceof` 操作符对 Trusted Types 对象进行的类型检查。
        ```javascript
        const trustedHTML = myPolicy.createHTML('some html');
        console.log(trustedHTML instanceof TrustedHTML); // 输出 true
        ```
    * **获取类型映射:**  JavaScript 可以通过 `TrustedTypes.getTypeMapping()` 获取属性和属性的类型映射。
        ```javascript
        const typeMapping = trustedTypes.getTypeMapping();
        console.log(typeMapping.script.properties.textContent); // 可能输出 "TrustedScript"
        ```
* **HTML:**
    * **属性赋值:** 当 JavaScript 代码尝试将一个字符串赋值给需要 Trusted Type 的 HTML 属性时，浏览器会检查是否使用了相应的 Trusted Type 对象。`getPropertyType` 和 `getAttributeType` 方法用于确定特定属性的期望类型。
        ```html
        <div id="myDiv"></div>
        <script>
          const div = document.getElementById('myDiv');
          const untrustedHTML = '<img src="x" onerror="alert(1)">';
          // div.innerHTML = untrustedHTML; // 可能触发 Trusted Types 错误

          const trustedHTML = trustedTypes.defaultPolicy.createHTML(untrustedHTML);
          div.innerHTML = trustedHTML; // 允许，因为使用了 TrustedHTML 对象
        </script>
        ```
        **假设输入:** JavaScript 代码尝试设置 `div.innerHTML` 的值为一个普通字符串。
        **输出:**  `TrustedTypePolicyFactory` 会通过 `getPropertyType` 判断 `innerHTML` 属性需要 `TrustedHTML` 类型。如果赋值的是普通字符串，则会触发 Trusted Types 错误（如果策略强制执行）。如果赋值的是 `TrustedHTML` 对象，则允许赋值。
    * **事件处理属性:**  诸如 `onclick` 等事件处理属性也需要 `TrustedScript` 类型的赋值。
        ```html
        <button id="myButton">Click Me</button>
        <script>
          const button = document.getElementById('myButton');
          const untrustedCode = 'alert("clicked!")';
          // button.onclick = untrustedCode; // 可能触发 Trusted Types 错误

          const trustedCode = trustedTypes.defaultPolicy.createScript(untrustedCode);
          button.onclick = trustedCode; // 允许，如果转换正确
        </script>
        ```
        **假设输入:** JavaScript 代码尝试设置 `button.onclick` 的值为一个普通字符串。
        **输出:** `TrustedTypePolicyFactory` 会判断 `onclick` 属性需要 `TrustedScript` 类型。如果赋值的是普通字符串，则会触发 Trusted Types 错误。

* **CSS:**
    * **间接关系:**  Trusted Types 主要关注 HTML 和 JavaScript 的安全，但它可以间接地防止某些依赖于注入恶意 HTML 或 JavaScript 的 CSS 攻击。例如，如果攻击者试图通过注入包含恶意 `<style>` 标签的 HTML 来进行 CSS 注入，Trusted Types 可以阻止这种注入，因为它会要求使用 `TrustedHTML` 对象来设置 `innerHTML` 等属性。

**逻辑推理的假设输入与输出:**

假设我们有以下场景：

* **输入:**  JavaScript 代码尝试使用 `trustedTypes.createPolicy("myPolicy", ...)` 创建一个名为 "myPolicy" 的策略。
* **假设条件:**
    1. CSP 中允许创建名为 "myPolicy" 的策略（例如，CSP 指令包含 `require-trusted-types-for 'script'; trusted-types myPolicy;`）。
    2. 当前环境中没有其他名为 "myPolicy" 的策略存在。
* **输出:** `TrustedTypePolicyFactory::createPolicy()` 函数会成功创建一个新的 `TrustedTypePolicy` 对象，并将其存储在 `policy_map_` 中，然后返回该对象。

* **输入:** JavaScript 代码尝试将一个普通字符串赋值给 `<iframe>` 元素的 `srcdoc` 属性。
* **假设条件:**  Trusted Types 被启用且强制执行。
* **输出:** `TrustedTypePolicyFactory::getPropertyType()` 会返回 "TrustedHTML"，表明 `srcdoc` 属性期望 `TrustedHTML` 类型。由于赋值的是普通字符串，浏览器会抛出一个 Trusted Types 错误。

**用户或编程常见的使用错误举例说明:**

1. **尝试创建已存在的策略:**
   ```javascript
   trustedTypes.createPolicy('myPolicy', { createHTML: (s) => s });
   // 稍后尝试再次创建同名策略
   try {
     trustedTypes.createPolicy('myPolicy', { createHTML: (s) => `<p>${s}</p>` });
   } catch (e) {
     console.error(e); // 会抛出一个 TypeError，提示策略已存在
   }
   ```

2. **将普通字符串赋值给需要 Trusted Type 的属性:**
   ```html
   <div id="myDiv"></div>
   <script>
     const div = document.getElementById('myDiv');
     div.innerHTML = '<script>alert("evil")</script>'; // 可能会触发 Trusted Types 错误
   </script>
   ```
   用户常常忘记需要使用 `TrustedHTML`, `TrustedScript`, `TrustedScriptURL` 等对象来赋值，而是直接使用普通字符串。

3. **CSP 配置错误导致无法创建策略:**
   如果 CSP 中没有允许创建特定名称的策略，或者设置了 `require-trusted-types-for 'script'` 但没有配置任何 `trusted-types` 指令，尝试创建策略会失败。
   ```javascript
   try {
     trustedTypes.createPolicy('myNewPolicy', { createHTML: (s) => s });
   } catch (e) {
     console.error(e); // 会抛出一个 TypeError，提示策略被 CSP 阻止
   }
   ```

4. **在不支持 Trusted Types 的浏览器中使用:**
   在不支持 Trusted Types 的浏览器中，`trustedTypes` 对象可能不存在或功能不完整，导致代码出错。开发者需要进行特性检测。

总而言之，`TrustedTypePolicyFactory.cc` 文件是 Blink 引擎中 Trusted Types 功能的关键组成部分，负责策略的创建、类型检查和与 Web 标准的集成，旨在提高 Web 应用的安全性，防止 DOM XSS 攻击。

Prompt: 
```
这是目录为blink/renderer/core/trustedtypes/trusted_type_policy_factory.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/trustedtypes/trusted_type_policy_factory.h"

#include "third_party/blink/public/mojom/use_counter/metrics/web_feature.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_trusted_html.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_trusted_script.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_trusted_script_url.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/event_target_names.h"
#include "third_party/blink/renderer/core/events/before_create_policy_event.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/csp/content_security_policy.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/inspector/exception_metadata.h"
#include "third_party/blink/renderer/core/inspector/identifiers_factory.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/core/trustedtypes/event_handler_names.h"
#include "third_party/blink/renderer/core/trustedtypes/trusted_html.h"
#include "third_party/blink/renderer/core/trustedtypes/trusted_script.h"
#include "third_party/blink/renderer/core/trustedtypes/trusted_type_policy.h"
#include "third_party/blink/renderer/core/trustedtypes/trusted_types_util.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/v8_dom_wrapper.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/wtf/text/string_hash.h"

namespace blink {

namespace {

const char* kHtmlNamespace = "http://www.w3.org/1999/xhtml";

struct AttributeTypeEntry {
  AtomicString element;
  AtomicString attribute;
  AtomicString element_namespace;
  AtomicString attribute_namespace;
  SpecificTrustedType type;
};

typedef Vector<AttributeTypeEntry> AttributeTypeVector;

AttributeTypeVector BuildAttributeVector() {
  const QualifiedName any_element(g_null_atom, g_star_atom, g_null_atom);
  const struct {
    const QualifiedName& element;
    const AtomicString attribute;
    SpecificTrustedType type;
  } kTypeTable[] = {
      {html_names::kEmbedTag, html_names::kSrcAttr.LocalName(),
       SpecificTrustedType::kScriptURL},
      {html_names::kIFrameTag, html_names::kSrcdocAttr.LocalName(),
       SpecificTrustedType::kHTML},
      {html_names::kObjectTag, html_names::kCodebaseAttr.LocalName(),
       SpecificTrustedType::kScriptURL},
      {html_names::kObjectTag, html_names::kDataAttr.LocalName(),
       SpecificTrustedType::kScriptURL},
      {html_names::kScriptTag, html_names::kSrcAttr.LocalName(),
       SpecificTrustedType::kScriptURL},
#define FOREACH_EVENT_HANDLER(name) \
  {any_element, AtomicString(#name), SpecificTrustedType::kScript},
      EVENT_HANDLER_LIST(FOREACH_EVENT_HANDLER)
#undef FOREACH_EVENT_HANDLER
  };

  AttributeTypeVector table;
  for (const auto& entry : kTypeTable) {
    // Attribute comparisons are case-insensitive, for both element and
    // attribute name. We rely on the fact that they're stored as lowercase.
    DCHECK(entry.element.LocalName().IsLowerASCII());
    DCHECK(entry.attribute.IsLowerASCII());
    table.push_back(AttributeTypeEntry{
        entry.element.LocalName(), entry.attribute,
        entry.element.NamespaceURI(), g_null_atom, entry.type});
  }
  return table;
}

const AttributeTypeVector& GetAttributeTypeVector() {
  DEFINE_STATIC_LOCAL(AttributeTypeVector, attribute_table_,
                      (BuildAttributeVector()));
  return attribute_table_;
}

AttributeTypeVector BuildPropertyVector() {
  const QualifiedName any_element(g_null_atom, g_star_atom, g_null_atom);
  const struct {
    const QualifiedName& element;
    const char* property;
    SpecificTrustedType type;
  } kTypeTable[] = {
      {html_names::kEmbedTag, "src", SpecificTrustedType::kScriptURL},
      {html_names::kIFrameTag, "srcdoc", SpecificTrustedType::kHTML},
      {html_names::kObjectTag, "codeBase", SpecificTrustedType::kScriptURL},
      {html_names::kObjectTag, "data", SpecificTrustedType::kScriptURL},
      {html_names::kScriptTag, "innerText", SpecificTrustedType::kScript},
      {html_names::kScriptTag, "src", SpecificTrustedType::kScriptURL},
      {html_names::kScriptTag, "text", SpecificTrustedType::kScript},
      {html_names::kScriptTag, "textContent", SpecificTrustedType::kScript},
      {any_element, "innerHTML", SpecificTrustedType::kHTML},
      {any_element, "outerHTML", SpecificTrustedType::kHTML},
  };
  AttributeTypeVector table;
  for (const auto& entry : kTypeTable) {
    // Elements are case-insensitive, but property names are not.
    // Properties don't have a namespace, so we're leaving that blank.
    DCHECK(entry.element.LocalName().IsLowerASCII());
    table.push_back(AttributeTypeEntry{
        entry.element.LocalName(), AtomicString(entry.property),
        entry.element.NamespaceURI(), AtomicString(), entry.type});
  }
  return table;
}

const AttributeTypeVector& GetPropertyTypeVector() {
  DEFINE_STATIC_LOCAL(AttributeTypeVector, property_table_,
                      (BuildPropertyVector()));
  return property_table_;
}

// Find an entry matching `attribute` on any element in an AttributeTypeVector.
// Assumes that argument normalization has already happened.
SpecificTrustedType FindUnboundAttributeInAttributeTypeVector(
    const AttributeTypeVector& attribute_type_vector,
    const AtomicString& attribute) {
  for (const auto& entry : attribute_type_vector) {
    bool entry_matches = entry.attribute == attribute &&
                         entry.element == g_star_atom &&
                         entry.attribute_namespace == g_null_atom;
    if (entry_matches) {
      return entry.type;
    }
  }
  return SpecificTrustedType::kNone;
}

// Find a matching entry in an AttributeTypeVector. Assumes that argument
// normalization has already happened.
SpecificTrustedType FindEntryInAttributeTypeVector(
    const AttributeTypeVector& attribute_type_vector,
    const AtomicString& element,
    const AtomicString& attribute,
    const AtomicString& element_namespace,
    const AtomicString& attribute_namespace) {
  for (const auto& entry : attribute_type_vector) {
    bool entry_matches = ((entry.element == element &&
                           entry.element_namespace == element_namespace) ||
                          entry.element == g_star_atom) &&
                         entry.attribute == attribute &&
                         entry.attribute_namespace == attribute_namespace;
    if (entry_matches)
      return entry.type;
  }
  return SpecificTrustedType::kNone;
}

// Find a matching entry in an AttributeTypeVector. Converts arguments to
// AtomicString and does spec-mandated mapping of empty strings as namespaces.
SpecificTrustedType FindEntryInAttributeTypeVector(
    const AttributeTypeVector& attribute_type_vector,
    const String& element,
    const String& attribute,
    const String& element_namespace,
    const String& attribute_namespace) {
  return FindEntryInAttributeTypeVector(
      attribute_type_vector, AtomicString(element), AtomicString(attribute),
      element_namespace.empty() ? AtomicString(kHtmlNamespace)
                                : AtomicString(element_namespace),
      attribute_namespace.empty() ? AtomicString()
                                  : AtomicString(attribute_namespace));
}

}  // anonymous namespace

TrustedTypePolicy* TrustedTypePolicyFactory::createPolicy(
    const String& policy_name,
    ExceptionState& exception_state) {
  return createPolicy(policy_name,
                      MakeGarbageCollected<TrustedTypePolicyOptions>(),
                      exception_state);
}

TrustedTypePolicy* TrustedTypePolicyFactory::createPolicy(
    const String& policy_name,
    const TrustedTypePolicyOptions* policy_options,
    ExceptionState& exception_state) {
  if (RuntimeEnabledFeatures::TrustedTypeBeforePolicyCreationEventEnabled()) {
    DispatchEventResult result =
        DispatchEvent(*BeforeCreatePolicyEvent::Create(policy_name));
    if (result != DispatchEventResult::kNotCanceled) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kNotAllowedError,
          "The policy creation has been canceled.");
      return nullptr;
    }
  }
  if (!GetExecutionContext()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "The document is detached.");
    return nullptr;
  }
  UseCounter::Count(GetExecutionContext(),
                    WebFeature::kTrustedTypesCreatePolicy);

  // Count policy creation with empty names.
  if (policy_name.empty()) {
    UseCounter::Count(GetExecutionContext(),
                      WebFeature::kTrustedTypesCreatePolicyWithEmptyName);
  }

  // TT requires two validity checks: One against the CSP, and one for the
  // default policy. Use |disallowed| (and |violation_details|) to aggregate
  // these, so we can have unified error handling.
  //
  // Spec ref:
  // https://www.w3.org/TR/2022/WD-trusted-types-20220927/#create-trusted-type-policy-algorithm,
  // steps 2 + 3
  bool disallowed = false;
  ContentSecurityPolicy::AllowTrustedTypePolicyDetails violation_details =
      ContentSecurityPolicy::AllowTrustedTypePolicyDetails::kAllowed;

  // This issue_id is used to generate a link in the DevTools front-end from
  // the JavaScript TypeError to the inspector issue which is reported by
  // ContentSecurityPolicy::ReportViolation via the call to
  // AllowTrustedTypeAssignmentFailure below.
  base::UnguessableToken issue_id = base::UnguessableToken::Create();

  if (GetExecutionContext()->GetContentSecurityPolicy()) {
    disallowed = !GetExecutionContext()
                      ->GetContentSecurityPolicy()
                      ->AllowTrustedTypePolicy(
                          policy_name, policy_map_.Contains(policy_name),
                          violation_details, issue_id);
  }
  if (!disallowed && policy_name == "default" &&
      policy_map_.Contains("default")) {
    disallowed = true;
    violation_details = ContentSecurityPolicy::AllowTrustedTypePolicyDetails::
        kDisallowedDuplicateName;
  }

  if (violation_details != ContentSecurityPolicy::ContentSecurityPolicy::
                               AllowTrustedTypePolicyDetails::kAllowed) {
    // We may report a violation here even when disallowed is false
    // in case policy is a report-only one.
    probe::OnContentSecurityPolicyViolation(
        GetExecutionContext(),
        ContentSecurityPolicyViolationType::kTrustedTypesPolicyViolation);
  }
  if (disallowed) {
    // For a better error message, we'd like to disambiguate between
    // "disallowed" and "disallowed because of a duplicate name".
    bool disallowed_because_of_duplicate_name =
        violation_details ==
        ContentSecurityPolicy::AllowTrustedTypePolicyDetails::
            kDisallowedDuplicateName;
    const String message =
        disallowed_because_of_duplicate_name
            ? "Policy with name \"" + policy_name + "\" already exists."
            : "Policy \"" + policy_name + "\" disallowed.";
    v8::Isolate* isolate = GetExecutionContext()->GetIsolate();
    TryRethrowScope rethrow_scope(isolate, exception_state);
    auto exception = V8ThrowException::CreateTypeError(isolate, message);
    MaybeAssociateExceptionMetaData(exception, "issueId",
                                    IdentifiersFactory::IdFromToken(issue_id));
    V8ThrowException::ThrowException(isolate, exception);
    return nullptr;
  }

  UseCounter::Count(GetExecutionContext(),
                    WebFeature::kTrustedTypesPolicyCreated);
  if (policy_name == "default") {
    DCHECK(!policy_map_.Contains("default"));
    UseCounter::Count(GetExecutionContext(),
                      WebFeature::kTrustedTypesDefaultPolicyCreated);
  }

  auto* policy = MakeGarbageCollected<TrustedTypePolicy>(
      policy_name, const_cast<TrustedTypePolicyOptions*>(policy_options));
  policy_map_.insert(policy_name, policy);
  return policy;
}

TrustedTypePolicy* TrustedTypePolicyFactory::defaultPolicy() const {
  const auto iter = policy_map_.find("default");
  return iter != policy_map_.end() ? iter->value : nullptr;
}

TrustedTypePolicyFactory::TrustedTypePolicyFactory(ExecutionContext* context)
    : ExecutionContextClient(context),
      empty_html_(MakeGarbageCollected<TrustedHTML>("")),
      empty_script_(MakeGarbageCollected<TrustedScript>("")) {}

bool TrustedTypePolicyFactory::isHTML(ScriptState* script_state,
                                      const ScriptValue& script_value) {
  return V8TrustedHTML::HasInstance(script_state->GetIsolate(),
                                    script_value.V8Value());
}

bool TrustedTypePolicyFactory::isScript(ScriptState* script_state,
                                        const ScriptValue& script_value) {
  return V8TrustedScript::HasInstance(script_state->GetIsolate(),
                                      script_value.V8Value());
}

bool TrustedTypePolicyFactory::isScriptURL(ScriptState* script_state,
                                           const ScriptValue& script_value) {
  return V8TrustedScriptURL::HasInstance(script_state->GetIsolate(),
                                         script_value.V8Value());
}

TrustedHTML* TrustedTypePolicyFactory::emptyHTML() const {
  return empty_html_.Get();
}

TrustedScript* TrustedTypePolicyFactory::emptyScript() const {
  return empty_script_.Get();
}

String getTrustedTypeName(SpecificTrustedType type) {
  switch (type) {
    case SpecificTrustedType::kHTML:
      return "TrustedHTML";
    case SpecificTrustedType::kScript:
      return "TrustedScript";
    case SpecificTrustedType::kScriptURL:
      return "TrustedScriptURL";
    case SpecificTrustedType::kNone:
      return String();
  }
}

String TrustedTypePolicyFactory::getPropertyType(
    const String& tagName,
    const String& propertyName,
    const String& elementNS) const {
  return getTrustedTypeName(FindEntryInAttributeTypeVector(
      GetPropertyTypeVector(), tagName.LowerASCII(), propertyName, elementNS,
      String()));
}

String TrustedTypePolicyFactory::getAttributeType(
    const String& tagName,
    const String& attributeName,
    const String& tagNS,
    const String& attributeNS) const {
  return getTrustedTypeName(FindEntryInAttributeTypeVector(
      GetAttributeTypeVector(), tagName.LowerASCII(),
      attributeName.LowerASCII(), tagNS, attributeNS));
}

ScriptValue TrustedTypePolicyFactory::getTypeMapping(
    ScriptState* script_state) const {
  return getTypeMapping(script_state, String());
}

namespace {

// Support method for getTypeMapping: Ensure that top has a an element and
// attributes or properties entry.
// E.g. {element: { "attributes": {}}
void EnsureAttributeAndPropertiesDict(
    ScriptState* script_state,
    v8::Local<v8::Object>& top,
    const v8::Local<v8::String>& element,
    const v8::Local<v8::String>& attributes_or_properties) {
  if (!top->Has(script_state->GetContext(), element).ToChecked()) {
    top->Set(script_state->GetContext(), element,
             v8::Object::New(script_state->GetIsolate()))
        .Check();
  }
  v8::Local<v8::Object> middle = top->Get(script_state->GetContext(), element)
                                     .ToLocalChecked()
                                     ->ToObject(script_state->GetContext())
                                     .ToLocalChecked();
  if (!middle->Has(script_state->GetContext(), attributes_or_properties)
           .ToChecked()) {
    middle
        ->Set(script_state->GetContext(), attributes_or_properties,
              v8::Object::New(script_state->GetIsolate()))
        .Check();
  }
}

// Support method for getTypeMapping: Iterate over AttributeTypeVector and
// fill in the map entries.
void PopulateTypeMapping(
    ScriptState* script_state,
    v8::Local<v8::Object>& top,
    const AttributeTypeVector& attribute_vector,
    const v8::Local<v8::String>& attributes_or_properties) {
  for (const auto& iter : attribute_vector) {
    v8::Local<v8::String> element =
        V8String(script_state->GetIsolate(), iter.element);
    EnsureAttributeAndPropertiesDict(script_state, top, element,
                                     attributes_or_properties);
    top->Get(script_state->GetContext(), element)
        .ToLocalChecked()
        ->ToObject(script_state->GetContext())
        .ToLocalChecked()
        ->Get(script_state->GetContext(), attributes_or_properties)
        .ToLocalChecked()
        ->ToObject(script_state->GetContext())
        .ToLocalChecked()
        ->Set(
            script_state->GetContext(),
            V8String(script_state->GetIsolate(), iter.attribute),
            V8String(script_state->GetIsolate(), getTrustedTypeName(iter.type)))
        .Check();
  }
}

}  // anonymous namespace

ScriptValue TrustedTypePolicyFactory::getTypeMapping(ScriptState* script_state,
                                                     const String& ns) const {
  // Create three-deep dictionary of properties, like so:
  // {tagname: { ["attributes"|"properties"]: { attribute: type }}}

  if (!ns.empty())
    return ScriptValue::CreateNull(script_state->GetIsolate());

  v8::HandleScope handle_scope(script_state->GetIsolate());
  v8::Local<v8::Object> top = v8::Object::New(script_state->GetIsolate());
  PopulateTypeMapping(script_state, top, GetAttributeTypeVector(),
                      V8String(script_state->GetIsolate(), "attributes"));
  PopulateTypeMapping(script_state, top, GetPropertyTypeVector(),
                      V8String(script_state->GetIsolate(), "properties"));
  return ScriptValue(script_state->GetIsolate(), top);
}

void TrustedTypePolicyFactory::CountTrustedTypeAssignmentError() {
  if (!hadAssignmentError) {
    UseCounter::Count(GetExecutionContext(),
                      WebFeature::kTrustedTypesAssignmentError);
    hadAssignmentError = true;
  }
}

const AtomicString& TrustedTypePolicyFactory::InterfaceName() const {
  return event_target_names::kTrustedTypePolicyFactory;
}

ExecutionContext* TrustedTypePolicyFactory::GetExecutionContext() const {
  return ExecutionContextClient::GetExecutionContext();
}

void TrustedTypePolicyFactory::Trace(Visitor* visitor) const {
  EventTarget::Trace(visitor);
  ExecutionContextClient::Trace(visitor);
  visitor->Trace(empty_html_);
  visitor->Trace(empty_script_);
  visitor->Trace(policy_map_);
}

inline bool FindEventHandlerAttributeInTable(
    const AtomicString& attributeName) {
  return SpecificTrustedType::kScript ==
         FindUnboundAttributeInAttributeTypeVector(GetAttributeTypeVector(),
                                                   attributeName);
}

bool TrustedTypePolicyFactory::IsEventHandlerAttributeName(
    const AtomicString& attributeName) {
  // Check that the "on" prefix indeed filters out only non-event handlers.
  DCHECK(!FindEventHandlerAttributeInTable(attributeName) ||
         attributeName.StartsWithIgnoringASCIICase("on"));

  return attributeName.StartsWithIgnoringASCIICase("on") &&
         FindEventHandlerAttributeInTable(attributeName);
}

}  // namespace blink

"""

```