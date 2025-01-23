Response:
The user wants a breakdown of the provided C++ code for the Chromium Blink engine file `trusted_types_util.cc`. I need to identify the functionalities within this file and explain their relevance to web technologies like JavaScript, HTML, and CSS. If the code involves conditional logic, I should provide examples of inputs and outputs. Furthermore, I need to pinpoint common user or programming errors that this code might help to prevent or handle.

Here's a plan:

1. **Identify Core Functionality:**  The filename and the content of the file heavily suggest that it's related to the "Trusted Types" web security feature. I need to understand how this utility file supports Trusted Types.

2. **Analyze Key Functions:**  I'll go through the prominent functions in the code, like `TrustedTypesCheckForHTML`, `TrustedTypesCheckForScript`, `TrustedTypeFail`, etc., and describe what each function does.

3. **Connect to Web Technologies:**  For each key function, I'll explain how it relates to JavaScript, HTML, and potentially CSS. This will involve understanding how Trusted Types are used to secure these technologies.

4. **Illustrate with Examples:**
    - **Logic Reasoning:**  For functions that perform checks or transformations based on conditions, I'll create hypothetical input and output scenarios.
    - **Relationship to Web Technologies:**  I'll provide code snippets (JavaScript, HTML) that demonstrate how these functions are relevant in a web development context.

5. **Identify Potential Errors:** I'll look for scenarios where using or not using Trusted Types could lead to common errors, particularly security vulnerabilities like Cross-Site Scripting (XSS).

6. **Structure the Response:** I'll organize the information logically, starting with a general overview and then diving into specifics for each function and its relation to web technologies and potential errors.
这个文件 `trusted_types_util.cc` 是 Chromium Blink 引擎中实现 **Trusted Types (可信类型)** 功能的核心工具集。Trusted Types 是一种 Web 安全特性，旨在帮助开发者防范基于 DOM 的跨站脚本攻击 (DOM XSS)。

以下是该文件的主要功能及其与 JavaScript、HTML、CSS 的关系，以及可能涉及的常见错误：

**主要功能：**

1. **强制执行 Trusted Types 策略:** 该文件包含一系列函数（例如 `TrustedTypesCheckForHTML`, `TrustedTypesCheckForScript`, `TrustedTypesCheckForScriptURL`），用于在将字符串赋值给可能导致脚本执行或 HTML 注入的 DOM 属性时，强制执行 Trusted Types 策略。这些函数会检查传入的值是否是受信任的类型对象（例如 `TrustedHTML`, `TrustedScript`, `TrustedScriptURL` 的实例），或者是否可以通过定义的策略进行安全转换。

2. **处理 Trusted Types 违规:**  `TrustedTypeFail` 函数负责处理 Trusted Types 策略检查失败的情况。它会：
    - 向 Content Security Policy (CSP) 报告违规行为。
    - 增加相应的错误计数器。
    - 如果启用了强制执行，则抛出 JavaScript 异常。
    - 向开发者控制台输出错误信息。

3. **获取默认策略:** `GetDefaultPolicy` 函数用于获取当前执行上下文的默认 Trusted Types 策略。

4. **辅助函数:** 文件中还包含一些辅助函数，例如：
    - `GetMessage`:  根据不同的违规类型返回相应的错误消息。
    - `GetSamplePrefix`:  生成用于错误消息的前缀，指示哪个接口和属性正在进行赋值。
    - `GetStringFromScriptHelper`:  一个通用的助手函数，用于处理脚本类型值的检查，特别是在非脚本执行的上下文中（例如导航到 `javascript:` URL）。
    - `RequireTrustedTypesCheck`:  检查当前执行上下文是否需要进行 Trusted Types 检查。
    - `IsTrustedTypesEventHandlerAttribute`: 检查给定的属性是否是需要 Trusted Types 的事件处理属性。
    - `GetTrustedTypesLiteral`: 检查一个 JavaScript 值是否是特定的模板字面量，用于支持从字面量创建受信任类型。

**与 JavaScript、HTML、CSS 的关系：**

Trusted Types 主要关注如何安全地处理可能被解释为 HTML、JavaScript 或 URL 的字符串，因此与 JavaScript 和 HTML 的关系最为密切。CSS 的注入漏洞通常不通过字符串直接注入，因此 Trusted Types 对 CSS 的直接影响较小。

**举例说明：**

**1. 与 JavaScript 的关系：**

* **场景:** 当你尝试将一个普通的字符串赋值给 `script` 标签的 `textContent` 属性时，如果启用了 Trusted Types，则会触发检查。

   ```javascript
   // 假设启用了 Trusted Types
   const scriptElement = document.createElement('script');
   scriptElement.textContent = '< злонамеренный код >'; // 赋值一个普通的字符串
   document.body.appendChild(scriptElement);
   ```

   **逻辑推理 (假设输入与输出):**
   - **输入:**  `scriptElement.textContent = '< злонамеренный код >'`
   - **`TrustedTypesCheckForScript` 函数会被调用。**
   - **如果不存在默认策略或默认策略没有成功创建 `TrustedScript` 对象，`TrustedTypeFail` 会被调用。**
   - **输出:**  浏览器会阻止脚本执行，并可能在控制台中显示错误信息，例如 "This document requires 'TrustedScript' assignment."。

* **场景:** 使用 `eval()` 或 `Function()` 构造函数动态执行代码。

   ```javascript
   // 假设启用了 Trusted Types
   const code = 'alert("hello");';
   eval(code); // 或者 new Function(code)();
   ```

   **逻辑推理 (假设输入与输出):**
   - **输入:** `eval('alert("hello");')`
   - **`TrustedTypesCheckForScript` 函数会被调用。**
   - **需要将字符串 `code` 转换为 `TrustedScript` 对象才能安全执行。**
   - **输出:** 如果 `code` 不是 `TrustedScript` 的实例，浏览器会阻止执行，并可能在控制台中显示错误信息。

**2. 与 HTML 的关系：**

* **场景:** 将字符串赋值给可能注入 HTML 的 DOM 属性，例如 `innerHTML`。

   ```javascript
   // 假设启用了 Trusted Types
   const div = document.createElement('div');
   div.innerHTML = '<img src="x" onerror="alert(\'XSS\')">'; // 赋值一个包含恶意 HTML 的字符串
   document.body.appendChild(div);
   ```

   **逻辑推理 (假设输入与输出):**
   - **输入:** `div.innerHTML = '<img src="x" onerror="alert(\'XSS\')">'`
   - **`TrustedTypesCheckForHTML` 函数会被调用。**
   - **需要将字符串转换为 `TrustedHTML` 对象才能安全赋值。**
   - **输出:** 浏览器会阻止 HTML 注入，并可能在控制台中显示错误信息，例如 "This document requires 'TrustedHTML' assignment."。

**3. 与 CSS 的关系 (间接):**

虽然 Trusted Types 主要处理 HTML 和 JavaScript，但它可以通过限制 JavaScript 操作来间接影响 CSS 相关的安全问题。例如，防止通过 JavaScript 动态创建包含恶意 CSS 的 `<style>` 标签。

**用户或编程常见的使用错误举例：**

1. **直接将字符串赋值给敏感的 DOM 属性:**  在启用了 Trusted Types 的情况下，直接将从用户输入或其他不受信任来源获取的字符串赋值给 `innerHTML`, `outerHTML`, `srcdoc` (iframe), `textContent` (script 标签) 等属性会导致错误。

   ```javascript
   // 错误示例 (假设启用了 Trusted Types)
   const userInput = '<p>用户输入</p><img src="x" onerror="attack()">';
   document.getElementById('output').innerHTML = userInput; // 导致 Trusted Types 违规
   ```

   **解决方法:**  使用 Trusted Types Policy 创建 `TrustedHTML` 对象：

   ```javascript
   // 正确示例
   const userInput = '<p>用户输入</p>'; // 假设我们只允许 <p> 标签
   const policy = trustedTypes.createPolicy('myPolicy', {
       createHTML: (input) => input.replace(/<img.*?>/g, '') // 清理掉 <img> 标签
   });
   const trustedHTML = policy.createHTML(userInput);
   document.getElementById('output').innerHTML = trustedHTML;
   ```

2. **在需要 `TrustedScriptURL` 的地方使用普通字符串:** 当设置 `<a>` 标签的 `href` 属性为 `javascript:` URL 时，需要使用 `TrustedScriptURL` 对象。

   ```javascript
   // 错误示例 (假设启用了 Trusted Types)
   const maliciousURL = 'javascript:alert("XSS")';
   document.getElementById('link').href = maliciousURL; // 导致 Trusted Types 违规
   ```

   **解决方法:** 创建 `TrustedScriptURL` 对象：

   ```javascript
   // 正确示例 (通常应该避免使用 javascript: URL)
   const policy = trustedTypes.createPolicy('urlPolicy');
   const trustedURL = policy.createScriptURL('javascript:void(0)'); // 或者其他安全的 URL
   document.getElementById('link').href = trustedURL;
   ```

3. **混淆 Trusted Types 和字符串:** 开发者可能会忘记将字符串转换为受信任的类型对象，或者在应该使用受信任类型对象的地方仍然使用字符串。

4. **错误配置 Trusted Types 策略:**  策略配置不当可能导致过度限制，阻止合法操作，或者过于宽松，未能有效防止 XSS。

**总结:**

`trusted_types_util.cc` 文件是 Blink 引擎中实现和强制执行 Trusted Types 安全特性的关键组成部分。它通过一系列检查和处理函数，确保只有受信任的 HTML、JavaScript 和 URL 才能被赋值给敏感的 DOM 属性，从而帮助开发者防范 DOM XSS 攻击。理解这个文件中的功能对于理解 Trusted Types 的工作原理以及如何正确使用它来提高 Web 应用的安全性至关重要。

### 提示词
```
这是目录为blink/renderer/core/trustedtypes/trusted_types_util.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/trustedtypes/trusted_types_util.h"

#include "base/unguessable_token.h"
#include "third_party/blink/public/mojom/devtools/console_message.mojom-blink-forward.h"
#include "third_party/blink/public/mojom/reporting/reporting.mojom-blink.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/bindings/core/v8/script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_string_trustedscript.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_stringlegacynulltoemptystring_trustedscript.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_trustedhtml_trustedscript_trustedscripturl.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/csp/content_security_policy.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/inspector/exception_metadata.h"
#include "third_party/blink/renderer/core/inspector/identifiers_factory.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/core/script/script_element_base.h"
#include "third_party/blink/renderer/core/trustedtypes/trusted_html.h"
#include "third_party/blink/renderer/core/trustedtypes/trusted_script.h"
#include "third_party/blink/renderer/core/trustedtypes/trusted_script_url.h"
#include "third_party/blink/renderer/core/trustedtypes/trusted_type_policy.h"
#include "third_party/blink/renderer/core/trustedtypes/trusted_type_policy_factory.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {

namespace {

enum TrustedTypeViolationKind {
  kTrustedHTMLAssignment,
  kTrustedScriptAssignment,
  kTrustedScriptURLAssignment,
  kTrustedHTMLAssignmentAndDefaultPolicyFailed,
  kTrustedHTMLAssignmentAndNoDefaultPolicyExisted,
  kTrustedScriptAssignmentAndDefaultPolicyFailed,
  kTrustedScriptAssignmentAndNoDefaultPolicyExisted,
  kTrustedScriptURLAssignmentAndDefaultPolicyFailed,
  kTrustedScriptURLAssignmentAndNoDefaultPolicyExisted,
  kNavigateToJavascriptURL,
  kNavigateToJavascriptURLAndDefaultPolicyFailed,
  kScriptExecution,
  kScriptExecutionAndDefaultPolicyFailed,
};

// String to determine whether an incoming eval-ish call is comig from
// an actual eval or a Function constructor. The value is derived from
// from how JS builds up a string in the Function constructor, which in
// turn is defined in the TC39 spec.
const char* kAnonymousPrefix = "(function anonymous";

const char kFunctionConstructorFailureConsoleMessage[] =
    "The JavaScript Function constructor does not accept TrustedString "
    "arguments. See https://github.com/w3c/webappsec-trusted-types/wiki/"
    "Trusted-Types-for-function-constructor for more information.";

const char kScriptExecutionTrustedTypeFailConsoleMessage[] =
    "This document requires 'TrustedScript' assignment. "
    "An HTMLScriptElement was directly modified and will not be executed.";

const char* GetMessage(TrustedTypeViolationKind kind) {
  switch (kind) {
    case kTrustedHTMLAssignment:
      return "This document requires 'TrustedHTML' assignment.";
    case kTrustedScriptAssignment:
      return "This document requires 'TrustedScript' assignment.";
    case kTrustedScriptURLAssignment:
      return "This document requires 'TrustedScriptURL' assignment.";
    case kTrustedHTMLAssignmentAndDefaultPolicyFailed:
      return "This document requires 'TrustedHTML' assignment and the "
             "'default' policy failed to execute.";
    case kTrustedHTMLAssignmentAndNoDefaultPolicyExisted:
      return "This document requires 'TrustedHTML' assignment and no "
             "'default' policy for 'TrustedHTML' has been defined.";
    case kTrustedScriptAssignmentAndDefaultPolicyFailed:
      return "This document requires 'TrustedScript' assignment and the "
             "'default' policy failed to execute.";
    case kTrustedScriptAssignmentAndNoDefaultPolicyExisted:
      return "This document requires 'TrustedScript' assignment and no "
             "'default' policy for 'TrustedScript' has been defined.";
    case kTrustedScriptURLAssignmentAndDefaultPolicyFailed:
      return "This document requires 'TrustedScriptURL' assignment and the "
             "'default' policy failed to execute.";
    case kTrustedScriptURLAssignmentAndNoDefaultPolicyExisted:
      return "This document requires 'TrustedScriptURL' assignment and no "
             "'default' policy for 'TrustedScriptURL' has been defined.";
    case kNavigateToJavascriptURL:
      return "This document requires 'TrustedScript' assignment. "
             "Navigating to a javascript:-URL is equivalent to a "
             "'TrustedScript' assignment.";
    case kNavigateToJavascriptURLAndDefaultPolicyFailed:
      return "This document requires 'TrustedScript' assignment. "
             "Navigating to a javascript:-URL is equivalent to a "
             "'TrustedScript' assignment and the 'default' policy failed to"
             "execute.";
    case kScriptExecution:
      return "This document requires 'TrustedScript' assignment. "
             "This script element was modified without use of TrustedScript "
             "assignment.";
    case kScriptExecutionAndDefaultPolicyFailed:
      return "This document requires 'TrustedScript' assignment. "
             "This script element was modified without use of TrustedScript "
             "assignment and the 'default' policy failed to execute.";
  }
  NOTREACHED();
}

String GetSamplePrefix(const char* interface_name,
                       const char* property_name,
                       const String& value) {
  // We have two sample formats, one for eval and one for assignment.
  // If we don't have the required values being passed in, just leave the
  // sample empty.
  StringBuilder sample_prefix;
  if (!interface_name) {
    // No interface name? Then we have no prefix to use.
  } else if (strcmp("eval", interface_name) == 0) {
    // eval? Try to distinguish between eval and Function constructor.
    sample_prefix.Append(value.StartsWith(kAnonymousPrefix) ? "Function"
                                                            : "eval");
  } else if ((strcmp("Worker", interface_name) == 0 ||
              strcmp("SharedWorker", interface_name) == 0) &&
             property_name) {
    // Worker/SharedWorker constructor has nullptr as property_name.
    sample_prefix.Append(interface_name);
    sample_prefix.Append(" constructor");
  } else if (interface_name && property_name) {
    sample_prefix.Append(interface_name);
    sample_prefix.Append(" ");
    sample_prefix.Append(property_name);
  }
  return sample_prefix.ToString();
}

const char* GetElementName(const ScriptElementBase::Type type) {
  switch (type) {
    case ScriptElementBase::Type::kHTMLScriptElement:
      return "HTMLScriptElement";
    case ScriptElementBase::Type::kSVGScriptElement:
      return "SVGScriptElement";
  }
  NOTREACHED();
}

HeapVector<ScriptValue> GetDefaultCallbackArgs(
    v8::Isolate* isolate,
    const char* type,
    const char* interface_name,
    const char* property_name,
    const String& value = g_empty_string) {
  HeapVector<ScriptValue> args;
  args.push_back(ScriptValue(isolate, V8String(isolate, type)));
  args.push_back(ScriptValue(
      isolate, V8String(isolate, GetSamplePrefix(interface_name, property_name,
                                                 value))));
  return args;
}

// Handle failure of a Trusted Type assignment.
//
// If trusted type assignment fails, we need to
// - report the violation via CSP
// - increment the appropriate counter,
// - raise a JavaScript exception (if enforced).
//
// Returns whether the failure should be enforced.
bool TrustedTypeFail(TrustedTypeViolationKind kind,
                     const ExecutionContext* execution_context,
                     const char* interface_name,
                     const char* property_name,
                     ExceptionState& exception_state,
                     const String& value) {
  if (!execution_context)
    return true;

  // Test case docs (Document::CreateForTest()) might not have a window
  // and hence no TrustedTypesPolicyFactory.
  if (execution_context->GetTrustedTypes())
    execution_context->GetTrustedTypes()->CountTrustedTypeAssignmentError();

  String prefix = GetSamplePrefix(interface_name, property_name, value);
  // This issue_id is used to generate a link in the DevTools front-end from
  // the JavaScript TypeError to the inspector issue which is reported by
  // ContentSecurityPolicy::ReportViolation via the call to
  // AllowTrustedTypeAssignmentFailure below.
  base::UnguessableToken issue_id = base::UnguessableToken::Create();
  bool allow =
      execution_context->GetContentSecurityPolicy()
          ->AllowTrustedTypeAssignmentFailure(
              GetMessage(kind),
              prefix == "Function" ? value.Substring(static_cast<wtf_size_t>(
                                         strlen(kAnonymousPrefix)))
                                   : value,
              prefix, issue_id);

  // TODO(1087743): Add a console message for Trusted Type-related Function
  // constructor failures, to warn the developer of the outstanding issues
  // with TT and Function  constructors. This should be removed once the
  // underlying issue has been fixed.
  if (prefix == "Function" && !allow &&
      !RuntimeEnabledFeatures::TrustedTypesUseCodeLikeEnabled()) {
    DCHECK(kind == kTrustedScriptAssignment ||
           kind == kTrustedScriptAssignmentAndDefaultPolicyFailed ||
           kind == kTrustedScriptAssignmentAndNoDefaultPolicyExisted);
    execution_context->GetContentSecurityPolicy()->LogToConsole(
        MakeGarbageCollected<ConsoleMessage>(
            mojom::blink::ConsoleMessageSource::kRecommendation,
            mojom::blink::ConsoleMessageLevel::kInfo,
            kFunctionConstructorFailureConsoleMessage));
  }
  probe::OnContentSecurityPolicyViolation(
      const_cast<ExecutionContext*>(execution_context),
      ContentSecurityPolicyViolationType::kTrustedTypesSinkViolation);

  if (!allow) {
    v8::Isolate* isolate = execution_context->GetIsolate();
    TryRethrowScope rethrow_scope(isolate, exception_state);
    auto exception =
        V8ThrowException::CreateTypeError(isolate, GetMessage(kind));
    MaybeAssociateExceptionMetaData(exception, "issueId",
                                    IdentifiersFactory::IdFromToken(issue_id));
    V8ThrowException::ThrowException(isolate, exception);
  }
  return !allow;
}

TrustedTypePolicy* GetDefaultPolicy(const ExecutionContext* execution_context) {
  DCHECK(execution_context);
  return execution_context->GetTrustedTypes()
             ? execution_context->GetTrustedTypes()->defaultPolicy()
             : nullptr;
}

// Functionally identical to TrustedTypesCheckForScript(const String&, ..), but
// to be called outside of regular script execution. This is required for both
// GetStringForScriptExecution & TrustedTypesCheckForJavascriptURLinNavigation,
// and has a number of additional parameters to enable proper error reporting
// for each case.
String GetStringFromScriptHelper(
    const String& script,
    ExecutionContext* context,
    // Parameters to customize error messages:
    const char* interface_name,
    const char* property_name,
    TrustedTypeViolationKind violation_kind,
    TrustedTypeViolationKind violation_kind_when_default_policy_failed) {
  if (!context)
    return script;
  if (!RequireTrustedTypesCheck(context))
    return script;

  // Set up JS context & friends.
  //
  // All other functions in here are expected to be called during JS execution,
  // where naturally everything is properly set up for more JS execution.
  // This one is called during navigation, and thus needs to do a bit more
  // work. We need two JavaScript-ish things:
  // - TrustedTypeFail expects an ExceptionState, which it will use to throw
  //   an exception. In our case, we will always clear the exception (as there
  //   is no user script to pass it to), and we only use this as a signalling
  //   mechanism.
  // - If the default policy applies, we need to execute the JS callback.
  //   Unlike the various ScriptController::Execute* and ..::Eval* methods,
  //   we are not executing a source String, but an already compiled callback
  //   function.
  v8::HandleScope handle_scope(context->GetIsolate());
  ScriptState::Scope script_state_scope(ToScriptStateForMainWorld(context));
  DummyExceptionStateForTesting exception_state;

  TrustedTypePolicy* default_policy = GetDefaultPolicy(context);
  if (!default_policy) {
    if (TrustedTypeFail(violation_kind, context, interface_name, property_name,
                        exception_state, script)) {
      return String();
    }
    return script;
  }

  TrustedScript* result = default_policy->createScript(
      context->GetIsolate(), script,
      GetDefaultCallbackArgs(context->GetIsolate(), "TrustedScript",
                             interface_name, property_name, script),
      exception_state);
  if (!result) {
    return String();
  }

  if (result->toString().IsNull()) {
    if (TrustedTypeFail(violation_kind_when_default_policy_failed, context,
                        interface_name, property_name, exception_state,
                        script)) {
      return String();
    }
    return script;
  }
  return result->toString();
}

}  // namespace

bool RequireTrustedTypesCheck(const ExecutionContext* execution_context) {
  return execution_context && execution_context->RequireTrustedTypes() &&
         !ContentSecurityPolicy::ShouldBypassMainWorldDeprecated(
             execution_context);
}

String TrustedTypesCheckForHTML(const String& html,
                                const ExecutionContext* execution_context,
                                const char* interface_name,
                                const char* property_name,
                                ExceptionState& exception_state) {
  bool require_trusted_type = RequireTrustedTypesCheck(execution_context);
  if (!require_trusted_type) {
    return html;
  }

  TrustedTypePolicy* default_policy = GetDefaultPolicy(execution_context);
  if (!default_policy) {
    if (TrustedTypeFail(kTrustedHTMLAssignment, execution_context,
                        interface_name, property_name, exception_state, html)) {
      return g_empty_string;
    }
    return html;
  }

  if (!default_policy->HasCreateHTML()) {
    if (TrustedTypeFail(kTrustedHTMLAssignmentAndNoDefaultPolicyExisted,
                        execution_context, interface_name, property_name,
                        exception_state, html)) {
      return g_empty_string;
    } else {
      return html;
    }
  }
  // TODO(ajwong): This can be optimized to avoid a AddRef in the
  // StringCache::CreateStringAndInsertIntoCache() also, but it's a hard mess.
  // Punt for now.
  TrustedHTML* result = default_policy->createHTML(
      execution_context->GetIsolate(), html,
      GetDefaultCallbackArgs(execution_context->GetIsolate(), "TrustedHTML",
                             interface_name, property_name),
      exception_state);
  if (exception_state.HadException()) {
    return g_empty_string;
  }

  if (result->toString().IsNull()) {
    if (TrustedTypeFail(kTrustedHTMLAssignmentAndDefaultPolicyFailed,
                        execution_context, interface_name, property_name,
                        exception_state, html)) {
      return g_empty_string;
    } else {
      return html;
    }
  }

  return result->toString();
}

String TrustedTypesCheckForScript(const String& script,
                                  const ExecutionContext* execution_context,
                                  const char* interface_name,
                                  const char* property_name,
                                  ExceptionState& exception_state) {
  bool require_trusted_type = RequireTrustedTypesCheck(execution_context);
  if (!require_trusted_type) {
    return script;
  }

  TrustedTypePolicy* default_policy = GetDefaultPolicy(execution_context);
  if (!default_policy) {
    if (TrustedTypeFail(kTrustedScriptAssignment, execution_context,
                        interface_name, property_name, exception_state,
                        script)) {
      return g_empty_string;
    }
    return script;
  }

  if (!default_policy->HasCreateScript()) {
    if (TrustedTypeFail(kTrustedScriptAssignmentAndNoDefaultPolicyExisted,
                        execution_context, interface_name, property_name,
                        exception_state, script)) {
      return g_empty_string;
    } else {
      return script;
    }
  }
  // TODO(ajwong): This can be optimized to avoid a AddRef in the
  // StringCache::CreateStringAndInsertIntoCache() also, but it's a hard mess.
  // Punt for now.
  TrustedScript* result = default_policy->createScript(
      execution_context->GetIsolate(), script,
      GetDefaultCallbackArgs(execution_context->GetIsolate(), "TrustedScript",
                             interface_name, property_name, script),
      exception_state);
  DCHECK_EQ(!result, exception_state.HadException());
  if (exception_state.HadException()) {
    return g_empty_string;
  }

  if (result->toString().IsNull()) {
    if (TrustedTypeFail(kTrustedScriptAssignmentAndDefaultPolicyFailed,
                        execution_context, interface_name, property_name,
                        exception_state, script)) {
      return g_empty_string;
    } else {
      return script;
    }
  }

  return result->toString();
}

String TrustedTypesCheckForScriptURL(const String& script_url,
                                     const ExecutionContext* execution_context,
                                     const char* interface_name,
                                     const char* property_name,
                                     ExceptionState& exception_state) {
  bool require_trusted_type = RequireTrustedTypesCheck(execution_context);
  if (!require_trusted_type) {
    return script_url;
  }

  TrustedTypePolicy* default_policy = GetDefaultPolicy(execution_context);
  if (!default_policy) {
    if (TrustedTypeFail(kTrustedScriptURLAssignment, execution_context,
                        interface_name, property_name, exception_state,
                        script_url)) {
      return g_empty_string;
    }
    return script_url;
  }

  if (!default_policy->HasCreateScriptURL()) {
    if (TrustedTypeFail(kTrustedScriptURLAssignmentAndNoDefaultPolicyExisted,
                        execution_context, interface_name, property_name,
                        exception_state, script_url)) {
      return g_empty_string;
    } else {
      return script_url;
    }
  }
  // TODO(ajwong): This can be optimized to avoid a AddRef in the
  // StringCache::CreateStringAndInsertIntoCache() also, but it's a hard mess.
  // Punt for now.
  TrustedScriptURL* result = default_policy->createScriptURL(
      execution_context->GetIsolate(), script_url,
      GetDefaultCallbackArgs(execution_context->GetIsolate(),
                             "TrustedScriptURL", interface_name, property_name),
      exception_state);

  if (exception_state.HadException()) {
    return g_empty_string;
  }

  if (result->toString().IsNull()) {
    if (TrustedTypeFail(kTrustedScriptURLAssignmentAndDefaultPolicyFailed,
                        execution_context, interface_name, property_name,
                        exception_state, script_url)) {
      return g_empty_string;
    } else {
      return script_url;
    }
  }

  return result->toString();
}

String TrustedTypesCheckFor(SpecificTrustedType type,
                            const V8TrustedType* trusted,
                            const ExecutionContext* execution_context,
                            const char* interface_name,
                            const char* property_name,
                            ExceptionState& exception_state) {
  DCHECK(trusted);

  // Whatever happens below, we will need the string value:
  String value;
  bool does_type_match = false;
  switch (trusted->GetContentType()) {
    case V8TrustedType::ContentType::kTrustedHTML:
      value = trusted->GetAsTrustedHTML()->toString();
      does_type_match = type == SpecificTrustedType::kHTML;
      break;
    case V8TrustedType::ContentType::kTrustedScript:
      value = trusted->GetAsTrustedScript()->toString();
      does_type_match = type == SpecificTrustedType::kScript;
      break;
    case V8TrustedType::ContentType::kTrustedScriptURL:
      value = trusted->GetAsTrustedScriptURL()->toString();
      does_type_match = type == SpecificTrustedType::kScriptURL;
      break;
  }

  if (type == SpecificTrustedType::kNone || does_type_match)
    return value;

  // In all other cases: run the full check against the string value.
  return TrustedTypesCheckFor(type, std::move(value), execution_context,
                              interface_name, property_name, exception_state);
}

String TrustedTypesCheckForScript(const V8UnionStringOrTrustedScript* value,
                                  const ExecutionContext* execution_context,
                                  const char* interface_name,
                                  const char* property_name,
                                  ExceptionState& exception_state) {
  // To remain compatible with legacy behaviour, HTMLElement uses extended IDL
  // attributes to allow for nullable union of (DOMString or TrustedScript).
  // Thus, this method is required to handle the case where |!value|, unlike
  // the various similar methods in this file.
  if (!value) {
    return TrustedTypesCheckForScript(g_empty_string, execution_context,
                                      interface_name, property_name,
                                      exception_state);
  }

  switch (value->GetContentType()) {
    case V8UnionStringOrTrustedScript::ContentType::kString:
      return TrustedTypesCheckForScript(value->GetAsString(), execution_context,
                                        interface_name, property_name,
                                        exception_state);
    case V8UnionStringOrTrustedScript::ContentType::kTrustedScript:
      return value->GetAsTrustedScript()->toString();
  }

  NOTREACHED();
}

String TrustedTypesCheckForScript(
    const V8UnionStringLegacyNullToEmptyStringOrTrustedScript* value,
    const ExecutionContext* execution_context,
    const char* interface_name,
    const char* property_name,
    ExceptionState& exception_state) {
  // To remain compatible with legacy behaviour, HTMLElement uses extended IDL
  // attributes to allow for nullable union of (DOMString or TrustedScript).
  // Thus, this method is required to handle the case where |!value|, unlike
  // the various similar methods in this file.
  if (!value) {
    return TrustedTypesCheckForScript(g_empty_string, execution_context,
                                      interface_name, property_name,
                                      exception_state);
  }

  switch (value->GetContentType()) {
    case V8UnionStringLegacyNullToEmptyStringOrTrustedScript::ContentType::
        kStringLegacyNullToEmptyString:
      return TrustedTypesCheckForScript(
          value->GetAsStringLegacyNullToEmptyString(), execution_context,
          interface_name, property_name, exception_state);
    case V8UnionStringLegacyNullToEmptyStringOrTrustedScript::ContentType::
        kTrustedScript:
      return value->GetAsTrustedScript()->toString();
  }

  NOTREACHED();
}

String TrustedTypesCheckFor(SpecificTrustedType type,
                            String trusted,
                            const ExecutionContext* execution_context,
                            const char* interface_name,
                            const char* property_name,
                            ExceptionState& exception_state) {
  switch (type) {
    case SpecificTrustedType::kHTML:
      return TrustedTypesCheckForHTML(std::move(trusted), execution_context,
                                      interface_name, property_name,
                                      exception_state);
    case SpecificTrustedType::kScript:
      return TrustedTypesCheckForScript(std::move(trusted), execution_context,
                                        interface_name, property_name,
                                        exception_state);
    case SpecificTrustedType::kScriptURL:
      return TrustedTypesCheckForScriptURL(std::move(trusted),
                                           execution_context, interface_name,
                                           property_name, exception_state);
    case SpecificTrustedType::kNone:
      return trusted;
  }
  NOTREACHED();
}

String CORE_EXPORT
GetStringForScriptExecution(const String& script,
                            const ScriptElementBase::Type type,
                            ExecutionContext* context) {
  String value = GetStringFromScriptHelper(
      script, context, GetElementName(type), "text", kScriptExecution,
      kScriptExecutionAndDefaultPolicyFailed);
  if (!script.IsNull() && value.IsNull()) {
    context->AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::blink::ConsoleMessageSource::kSecurity,
        mojom::blink::ConsoleMessageLevel::kError,
        kScriptExecutionTrustedTypeFailConsoleMessage));
  }
  return value;
}

String TrustedTypesCheckForJavascriptURLinNavigation(
    const String& javascript_url,
    ExecutionContext* context) {
  return GetStringFromScriptHelper(
      std::move(javascript_url), context, "Location", "href",
      kNavigateToJavascriptURL, kNavigateToJavascriptURLAndDefaultPolicyFailed);
}

String TrustedTypesCheckForExecCommand(
    const String& html,
    const ExecutionContext* execution_context,
    ExceptionState& exception_state) {
  return TrustedTypesCheckForHTML(html, execution_context, "Document",
                                  "execCommand", exception_state);
}

bool IsTrustedTypesEventHandlerAttribute(const QualifiedName& q_name) {
  return q_name.NamespaceURI().IsNull() &&
         TrustedTypePolicyFactory::IsEventHandlerAttributeName(
             q_name.LocalName());
}

String GetTrustedTypesLiteral(const ScriptValue& script_value,
                              ScriptState* script_state) {
  DCHECK(script_state);
  // TrustedTypes fromLiteral requires several checks, which are steps 1-3
  // in the "create a trusted type from literal algorithm". Ref:
  // https://w3c.github.io/trusted-types/dist/spec/#create-a-trusted-type-from-literal-algorithm

  // The core functionality here are the checks that we, indeed, have a
  // literal object. The key work is done by
  // v8::Context::HasTemplateLiteralObject, but we will additionally check that
  // we have an object, with a real (non-inherited) property 0 (but not 1),
  // whose value is a string.
  v8::Local<v8::Context> context = script_state->GetContext();
  v8::Local<v8::Value> value = script_value.V8ValueFor(script_state);
  if (!context.IsEmpty() && !value.IsEmpty() &&
      context->HasTemplateLiteralObject(value) && value->IsObject()) {
    v8::Local<v8::Object> value_as_object = v8::Local<v8::Object>::Cast(value);
    v8::Local<v8::Value> first_value;
    if (value_as_object->HasRealIndexedProperty(context, 0).FromMaybe(false) &&
        !value_as_object->HasRealIndexedProperty(context, 1).FromMaybe(false) &&
        value_as_object->Get(context, 0).ToLocal(&first_value) &&
        first_value->IsString()) {
      v8::Local<v8::String> first_value_as_string =
          v8::Local<v8::String>::Cast(first_value);
      return ToCoreString(script_state->GetIsolate(), first_value_as_string);
    }
  }

  // Fall-through: Some of the required conditions didn't hold. Return a
  // null-string.
  return String();
}

}  // namespace blink
```