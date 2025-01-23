Response:
Let's break down the thought process to analyze the provided C++ code.

1. **Understand the Goal:** The core request is to analyze the `digital_identity_credential.cc` file and explain its function, relation to web technologies, logic, potential errors, and how a user might trigger its execution.

2. **High-Level Overview (Skim and Scan):**  First, quickly scan the file for keywords and structure. Notice the `#include` statements, the namespace `blink`, and the presence of functions like `DiscoverDigitalIdentityCredentialFromExternalSource`. The included headers hint at the file's purpose: credential management, bindings to JavaScript (V8), DOM manipulation, and communication with other parts of the Chromium browser (mojom).

3. **Identify the Core Functionality:** The function `DiscoverDigitalIdentityCredentialFromExternalSource` stands out as the primary entry point. The name strongly suggests its role is to fetch digital identity credentials. The parameters `ScriptPromiseResolver`, `CredentialRequestOptions`, and `ExceptionState` further solidify this idea, connecting it to JavaScript promises and error handling in the browser.

4. **Deconstruct `DiscoverDigitalIdentityCredentialFromExternalSource`:**  Analyze the steps within this function:
    * **Checks:**  Several `CHECK` statements and `if` conditions verify prerequisites:
        * `IsDigitalIdentityCredentialType(options)`:  Ensures the request is indeed for a digital identity credential.
        * `RuntimeEnabledFeatures::WebIdentityDigitalCredentialsEnabled(...)`: Checks if the feature is enabled in the browser.
        * `CheckGenericSecurityRequirementsForCredentialsContainerRequest(...)`:  Performs standard security checks for credential requests.
        * Permissions Policy check: Ensures the feature isn't blocked by Permissions Policy.
    * **Provider Processing:** The code iterates through `options.digital()->providers()`. This indicates the possibility of multiple identity providers. The `ValidateAndStringifyObject` function and the handling of string vs. object types for the request are crucial.
    * **Use Counter:** `UseCounter::Count(...)` suggests tracking usage statistics for this feature.
    * **Abort Signal Handling:** The code deals with `AbortSignal`, allowing the user or the browser to cancel the credential request.
    * **CredentialManagerProxy:** This class appears to be the interface to the underlying browser implementation for handling credential requests. The `DigitalIdentityRequest()` method suggests this file is a module within a larger credential management system.
    * **`OnCompleteRequest` Callback:** This function handles the result of the asynchronous request, whether success or failure.

5. **Analyze Helper Functions:** Examine the purpose of other functions:
    * `AbortRequest`:  Clearly used to cancel an ongoing request.
    * `ValidateAndStringifyObject`:  Ensures the request data is a valid JSON string or can be converted to one, with size limits.
    * `OnCompleteRequest`:  Handles the various outcomes of the credential request (success, cancellation, errors), mapping them to appropriate promise resolutions or rejections.

6. **Relate to Web Technologies (JavaScript, HTML, CSS):**
    * **JavaScript:** The presence of `ScriptPromiseResolver`, `CredentialRequestOptions`, and the validation of input from JavaScript objects directly link this code to the JavaScript Credential Management API, specifically the `navigator.credentials.get()` method. The example illustrates how a JavaScript call would trigger this C++ code.
    * **HTML:**  The Permissions Policy check implies that HTML can control access to this feature through the `Permissions-Policy` header or iframe attributes.
    * **CSS:** No direct relationship with CSS is apparent in this specific file.

7. **Infer Logic and Assumptions:**
    * **Input:** The primary input is `CredentialRequestOptions` from JavaScript, specifically the `digital` property. This contains an array of provider configurations (protocol and request details).
    * **Output:** The function ultimately resolves or rejects a JavaScript Promise with a `DigitalCredential` object (on success) or a `DOMException` (on failure).
    * **Assumptions:** The code assumes the browser has a mechanism to communicate with identity providers based on the provided `protocol` and `request` data. It also assumes the existence of a `CredentialManagerProxy` to handle the underlying request logic.

8. **Identify Potential Errors and Usage Mistakes:**
    * **Type Errors:** Providing a non-stringifiable object or a plain string when an object is expected in the `request` field.
    * **Too Many Requests:** Making concurrent `navigator.credentials.get()` calls.
    * **Canceled Requests:**  Manually aborting the request using an `AbortSignal`.
    * **No Providers:**  Calling the API without any configured identity providers.
    * **No Transient User Activation:**  Calling the API outside of a user-initiated event.
    * **Permissions Policy Block:** The feature being disabled by the website's Permissions Policy.
    * **Network Errors:**  Failures in communication with the identity provider.
    * **Oversized JSON:** Providing a request object that serializes to a JSON string exceeding the limit.

9. **Trace User Interaction (Debugging Clues):**  Think about the steps a user would take that would eventually lead to this code being executed. This involves starting from a web page interaction and following the chain of events:
    * User interacts with a website (e.g., clicks a "Login with..." button).
    * JavaScript code on the page calls `navigator.credentials.get({ digital: ... })`.
    * The browser's JavaScript engine processes this call and eventually invokes the corresponding C++ code in Blink, including `DiscoverDigitalIdentityCredentialFromExternalSource`.

10. **Structure the Output:** Organize the findings into clear sections based on the prompt's requirements: Functionality, Relation to Web Technologies, Logic and Assumptions, Potential Errors, and User Interaction. Use examples to illustrate the concepts.

11. **Review and Refine:** Read through the analysis, ensuring accuracy, clarity, and completeness. Check for any logical inconsistencies or missed points. For instance, initially, I might not have explicitly mentioned the Permissions Policy aspect, but the code clearly handles it, so I would add that during the review. Similarly, explicitly mentioning the asynchronous nature of the operation and the role of the callback is important.
好的，这是对 `blink/renderer/modules/credentialmanagement/digital_identity_credential.cc` 文件的功能分析：

**文件功能概述:**

`digital_identity_credential.cc` 文件是 Chromium Blink 引擎中，负责处理 **Digital Identity Credential** 相关的逻辑。它实现了 W3C 的 Credential Management API 的一部分，专注于获取用户数字身份凭据（例如，来自特定身份提供商的访问令牌）。这个文件定义了如何接收来自 JavaScript 的请求，验证这些请求，并与浏览器的其他部分（例如，权限管理、网络请求）协同工作来完成凭据获取流程。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个文件直接与 JavaScript 的 Credential Management API 交互，特别是与 `navigator.credentials.get()` 方法一起使用，当 `options` 参数中包含 `digital` 属性时会被触发。它不直接与 HTML 或 CSS 交互。

* **JavaScript:**
    * **触发点:**  网站的 JavaScript 代码调用 `navigator.credentials.get(options)`，并且 `options` 对象中包含 `digital` 属性，指示需要获取数字身份凭据。
    * **参数传递:** JavaScript 代码通过 `options.digital` 属性传递身份提供商的信息，例如 `protocol` (身份协议) 和 `providers` (身份提供商数组)，每个提供商可以包含 `protocol` 和 `request` (请求参数)。
    * **Promise 处理:**  `navigator.credentials.get()` 返回一个 Promise。这个 C++ 文件负责处理请求，并在成功或失败时解析或拒绝这个 Promise。成功时，Promise 的 resolve 回调会接收到一个 `DigitalCredential` 对象。

    **示例 JavaScript 代码:**

    ```javascript
    navigator.credentials.get({
      digital: {
        providers: [
          {
            protocol: "https://example.com/oidc",
            request: {
              scope: "openid profile email"
            }
          }
        ]
      }
    }).then(credential => {
      if (credential) {
        console.log("获取到数字身份凭据:", credential);
        // 使用凭据进行身份验证或其他操作
      } else {
        console.log("未获取到数字身份凭据");
      }
    }).catch(error => {
      console.error("获取数字身份凭据失败:", error);
    });
    ```

* **HTML:** 尽管不直接交互，但网站的 HTML 结构和 `<script>` 标签会包含上述 JavaScript 代码，从而间接地涉及到该文件。此外， Permissions Policy 可能会在 HTTP 头部或 HTML 的 `<iframe>` 标签中设置，影响 `digital-credentials-get` 功能是否可用。

* **CSS:**  与 CSS 没有直接关系。CSS 负责页面的样式，而此文件负责处理底层的凭据获取逻辑。

**逻辑推理及假设输入与输出:**

假设用户访问了一个需要使用其 Google 账户登录的网站。

**假设输入 (来自 JavaScript):**

```javascript
navigator.credentials.get({
  digital: {
    providers: [
      {
        protocol: "https://accounts.google.com",
        request: {
          client_id: "YOUR_GOOGLE_CLIENT_ID",
          nonce: "someRandomValue"
        }
      }
    ]
  },
  signal: abortController.signal // 可选的 AbortSignal
});
```

**逻辑推理过程 (在 `digital_identity_credential.cc` 中):**

1. **接收请求:** `DiscoverDigitalIdentityCredentialFromExternalSource` 函数被调用，接收 `CredentialRequestOptions` 参数。
2. **安全检查:**  进行安全检查，例如是否在安全上下文（HTTPS）中运行，是否符合 Permissions Policy。
3. **提供商处理:** 提取 `options.digital.providers` 中的信息，验证 `protocol` 和 `request` 参数。`ValidateAndStringifyObject` 函数会将 `request` 对象转换为 JSON 字符串。
4. **调用 CredentialManagerProxy:**  调用 `CredentialManagerProxy` 的 `DigitalIdentityRequest()` 方法，发起实际的凭据请求。这可能涉及到与浏览器或其他进程通信，以处理与 Google 账户的交互。
5. **异步处理:**  这是一个异步过程。`OnCompleteRequest` 函数作为回调函数，在凭据请求完成时被调用。
6. **根据结果处理:**
    * **成功 (kSuccess):** 创建 `DigitalCredential` 对象，包含协议和令牌信息，并通过 Promise 的 resolve 回调返回给 JavaScript。
    * **失败 (kError, kErrorCanceled, kErrorNoProviders 等):** 创建相应的 `DOMException` 对象，并通过 Promise 的 reject 回调返回给 JavaScript。

**假设输出 (返回给 JavaScript):**

* **成功:** 一个 `DigitalCredential` 对象，例如：

  ```javascript
  {
    id: "https://accounts.google.com", // 通常是协议
    type: "public-key", // 注意：这里实际可能是 "digital-identity"，具体取决于实现细节
    // ... 其他可能的属性
  }
  ```
  或者，根据代码，`DigitalCredential` 类似乎更专注于存储协议和令牌，所以返回的可能是一个更具体的对象，包含 `protocol` 和 `token` 属性。

* **失败:** 一个 `DOMException` 对象，例如：

  ```javascript
  DOMException: The request has been aborted.
  ```

**用户或编程常见的使用错误及举例说明:**

1. **`TypeError`:  IdentityRequestProvider 请求对象应为字符串或可 JSON 序列化的对象。**
   * **错误示例:**  JavaScript 代码传递了不可序列化的对象作为 `request`：
     ```javascript
     navigator.credentials.get({
       digital: {
         providers: [{
           protocol: "...",
           request: () => {} // 函数不可序列化
         }]
       }
     });
     ```

2. **`TypeError`: IdentityRequestProvider 请求对象的 JSON 序列化结果不应超过 %zu 个字符。**
   * **错误示例:**  JavaScript 代码传递了一个非常大的对象作为 `request`，导致序列化后的 JSON 字符串过长。

3. **`NotAllowedError`: 只能同时存在一个 navigator.credentials.get 请求。**
   * **错误示例:**  在之前的 `navigator.credentials.get()` Promise 完成之前，再次调用 `navigator.credentials.get()`。

4. **`AbortError`: 请求已被中止。**
   * **错误示例:**  JavaScript 代码使用了 `AbortController` 来取消请求：
     ```javascript
     const controller = new AbortController();
     navigator.credentials.get({
       digital: { /* ... */ },
       signal: controller.signal
     });
     controller.abort();
     ```

5. **`TypeError`: Digital identity API 至少需要一个提供商。**
   * **错误示例:**  JavaScript 代码中 `providers` 数组为空：
     ```javascript
     navigator.credentials.get({
       digital: {
         providers: []
       }
     });
     ```

6. **`NotAllowedError`: 'digital-credentials-get' 功能需要瞬时用户激活。**
   * **错误示例:**  在页面加载时或没有用户交互的情况下直接调用 `navigator.credentials.get()`。该 API 通常需要用户主动触发（例如，点击按钮）。

7. **`NotAllowedError`: 文档中未启用 'digital-credentials-get' 功能。可以使用 Permissions Policy 将数字凭据 API 功能委托给跨域子框架。**
   * **错误示例:**  网站的 Permissions Policy 设置禁止了 `digital-credentials-get` 功能。

8. **`NetworkError`: 检索令牌时出错。**
   * **错误示例:**  与身份提供商的通信过程中发生网络错误或身份提供商返回错误。

**用户操作如何一步步的到达这里 (作为调试线索):**

1. **用户在网页上执行某个操作:** 例如，点击一个 "使用 Google 登录" 或类似的按钮。
2. **JavaScript 事件处理程序被触发:**  与该按钮关联的 JavaScript 代码开始执行。
3. **调用 `navigator.credentials.get()`:**  JavaScript 代码中调用了 `navigator.credentials.get()` 方法，并且 `options` 参数中包含了 `digital` 属性，指定了需要获取数字身份凭据。
4. **浏览器接收到请求:** 浏览器的渲染进程接收到这个 JavaScript API 调用。
5. **Blink 引擎处理请求:** Blink 引擎的 Credential Management 模块开始处理这个请求。由于 `options` 中有 `digital` 属性，控制流程会进入 `blink/renderer/modules/credentialmanagement/digital_identity_credential.cc` 文件中的 `DiscoverDigitalIdentityCredentialFromExternalSource` 函数。
6. **执行安全检查和参数验证:**  在该函数中，会进行一系列的安全检查，例如检查当前上下文是否安全，是否符合 Permissions Policy，以及验证提供的参数是否有效。
7. **与 Credential Manager 通信:**  如果验证通过，会调用 `CredentialManagerProxy` 来协调实际的凭据获取过程。这可能涉及到与浏览器的其他部分（例如，网络模块，权限模块）进行交互，并最终可能与外部的身份提供商通信。
8. **异步凭据获取:** 凭据的获取通常是异步的，可能需要用户在弹出的窗口中进行身份验证。
9. **接收凭据或错误:**  一旦凭据获取完成（成功或失败），结果会通过回调函数 (`OnCompleteRequest`) 传递回 `digital_identity_credential.cc`。
10. **Promise 的解决或拒绝:**  根据凭据获取的结果，最初的 `navigator.credentials.get()` 返回的 Promise 会被解决（resolve）并返回一个 `DigitalCredential` 对象，或者被拒绝（reject）并返回一个 `DOMException` 对象。
11. **JavaScript 处理结果:**  网页的 JavaScript 代码中的 `.then()` 或 `.catch()` 方法会处理 Promise 的结果，并根据结果执行相应的操作。

**调试线索:**

当调试与数字身份凭据相关的错误时，可以关注以下几点：

* **JavaScript 代码中的 `navigator.credentials.get()` 调用:** 检查传递给 `get()` 方法的 `options` 对象，特别是 `digital` 属性中的 `providers` 信息是否正确。
* **浏览器控制台的错误信息:**  查看是否有 `TypeError`, `NotAllowedError`, `AbortError` 等异常抛出，这些异常通常会提供关于错误原因的线索。
* **Permissions Policy:** 检查网站的 HTTP 头部或 HTML 中是否设置了 Permissions Policy，并确认 `digital-credentials-get` 功能是否被允许。
* **网络请求:**  使用浏览器的开发者工具查看网络请求，特别是与身份提供商相关的请求，以检查是否有网络错误或身份验证失败的情况。
* **用户交互:** 确认 `navigator.credentials.get()` 是否在用户交互后被调用，以避免 "需要瞬时用户激活" 的错误。
* **断点调试:** 在 Blink 引擎的源代码中设置断点，例如在 `DiscoverDigitalIdentityCredentialFromExternalSource` 和 `OnCompleteRequest` 函数中，可以逐步跟踪代码的执行流程，了解请求是如何被处理的，以及在哪个环节出现了问题。

希望以上分析能够帮助你理解 `digital_identity_credential.cc` 文件的功能和作用。

### 提示词
```
这是目录为blink/renderer/modules/credentialmanagement/digital_identity_credential.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/credentialmanagement/digital_identity_credential.h"

#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "base/notreached.h"
#include "base/ranges/algorithm.h"
#include "third_party/blink/public/mojom/permissions_policy/permissions_policy_feature.mojom-forward.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_object_string.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_credential_request_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_digital_credential_request_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_identity_provider_request_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_identity_request_provider.h"
#include "third_party/blink/renderer/core/dom/abort_signal.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/dom/scoped_abort_state.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/navigator.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/modules/credentialmanagement/credential.h"
#include "third_party/blink/renderer/modules/credentialmanagement/credential_manager_proxy.h"
#include "third_party/blink/renderer/modules/credentialmanagement/credential_manager_type_converters.h"  // IWYU pragma: keep
#include "third_party/blink/renderer/modules/credentialmanagement/credential_utils.h"
#include "third_party/blink/renderer/modules/credentialmanagement/digital_credential.h"
#include "third_party/blink/renderer/modules/credentialmanagement/identity_credential.h"
#include "third_party/blink/renderer/platform/bindings/callback_method_retriever.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/to_blink_string.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/wtf/wtf_size_t.h"

namespace blink {

namespace {

using mojom::blink::RequestDigitalIdentityStatus;

// Abort an ongoing WebIdentityDigitalCredential request. This will only be
// called before the request finishes due to `scoped_abort_state`.
void AbortRequest(ScriptState* script_state) {
  if (!script_state->ContextIsValid()) {
    return;
  }

  CredentialManagerProxy::From(script_state)->DigitalIdentityRequest()->Abort();
}

String ValidateAndStringifyObject(
    ScriptPromiseResolver<IDLNullable<Credential>>* resolver,
    const ScriptValue& input) {
  v8::Local<v8::String> value;
  if (input.IsEmpty() || !input.V8Value()->IsObject() ||
      !v8::JSON::Stringify(resolver->GetScriptState()->GetContext(),
                           input.V8Value().As<v8::Object>())
           .ToLocal(&value)) {
    resolver->RejectWithTypeError(
        "IdentityRequestProvider request objects should either by strings or "
        "JSON-Serializable objects.");
    return String();
  }

  String output = ToBlinkString<String>(
      resolver->GetScriptState()->GetIsolate(), value, kDoNotExternalize);

  // Implementation defined constant controlling the allowed JSON length.
  static constexpr size_t kMaxJSONStringLength = 1024 * 1024;

  if (output.length() > kMaxJSONStringLength) {
    resolver->RejectWithTypeError(
        String::Format("JSON serialization of IdentityRequestProvider request "
                       "objects should be no longer than %zu characters",
                       kMaxJSONStringLength));
    return String();
  }

  return output;
}

void OnCompleteRequest(ScriptPromiseResolver<IDLNullable<Credential>>* resolver,
                       std::unique_ptr<ScopedAbortState> scoped_abort_state,
                       RequestDigitalIdentityStatus status,
                       const WTF::String& protocol,
                       const WTF::String& token) {
  switch (status) {
    case RequestDigitalIdentityStatus::kErrorTooManyRequests: {
      resolver->Reject(MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kNotAllowedError,
          "Only one navigator.credentials.get request may be outstanding at "
          "one time."));
      return;
    }
    case RequestDigitalIdentityStatus::kErrorCanceled: {
      AbortSignal* signal =
          scoped_abort_state ? scoped_abort_state->Signal() : nullptr;
      if (signal && signal->aborted()) {
        auto* script_state = resolver->GetScriptState();
        ScriptState::Scope script_state_scope(script_state);
        resolver->Reject(signal->reason(script_state));
      } else {
        resolver->Reject(MakeGarbageCollected<DOMException>(
            DOMExceptionCode::kAbortError, "The request has been aborted."));
      }
      return;
    }
    case RequestDigitalIdentityStatus::kErrorNoProviders:
      resolver->RejectWithTypeError(
          "Digital identity API needs at least one provider.");
      return;

    case RequestDigitalIdentityStatus::kErrorNoTransientUserActivation:
      resolver->Reject(MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kNotAllowedError,
          "The 'digital-credentials-get' feature requires transient "
          "activation."));
      return;

    case RequestDigitalIdentityStatus::kError: {
      resolver->Reject(MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kNetworkError, "Error retrieving a token."));
      return;
    }
    case RequestDigitalIdentityStatus::kSuccess: {
      UseCounter::Count(resolver->GetExecutionContext(),
                        WebFeature::kIdentityDigitalCredentialsSuccess);

      DigitalCredential* credential =
          DigitalCredential::Create(protocol, token);
      resolver->Resolve(credential);
      return;
    }
  }
}

}  // anonymous namespace

bool IsDigitalIdentityCredentialType(const CredentialRequestOptions& options) {
  return options.hasDigital();
}

void DiscoverDigitalIdentityCredentialFromExternalSource(
    ScriptPromiseResolver<IDLNullable<Credential>>* resolver,
    const CredentialRequestOptions& options,
    ExceptionState& exception_state) {
  CHECK(IsDigitalIdentityCredentialType(options));
  CHECK(RuntimeEnabledFeatures::WebIdentityDigitalCredentialsEnabled(
      resolver->GetExecutionContext()));

  if (!CheckGenericSecurityRequirementsForCredentialsContainerRequest(
          resolver)) {
    return;
  }

  if (!resolver->GetExecutionContext()->IsFeatureEnabled(
          mojom::blink::PermissionsPolicyFeature::kDigitalCredentialsGet)) {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kNotAllowedError,
        "The 'digital-credentials-get' feature is not enabled in this "
        "document. Permissions Policy may be used to delegate digital "
        "credential API capabilities to cross-origin child frames."));
    return;
  }

  Vector<blink::mojom::blink::DigitalCredentialProviderPtr> providers;
  for (const auto& provider : options.digital()->providers()) {
    V8UnionObjectOrString* request_object_or_string = provider->request();

    String stringified_request;
    if (request_object_or_string->IsString()) {
      stringified_request = request_object_or_string->GetAsString();
    } else {
      stringified_request = ValidateAndStringifyObject(
          resolver, request_object_or_string->GetAsObject());
      if (stringified_request.IsNull()) {
        continue;
      }
    }

    blink::mojom::blink::DigitalCredentialProviderPtr
        digital_credential_provider =
            blink::mojom::blink::DigitalCredentialProvider::New();
    digital_credential_provider->protocol = provider->protocol();
    digital_credential_provider->request = stringified_request;
    providers.push_back(std::move(digital_credential_provider));
  }

  UseCounter::Count(resolver->GetExecutionContext(),
                    WebFeature::kIdentityDigitalCredentials);

  ScriptState* script_state = resolver->GetScriptState();
  std::unique_ptr<ScopedAbortState> scoped_abort_state;
  if (auto* signal = options.getSignalOr(nullptr)) {
    auto callback = WTF::BindOnce(&AbortRequest, WrapPersistent(script_state));
    auto* handle = signal->AddAlgorithm(std::move(callback));
    scoped_abort_state = std::make_unique<ScopedAbortState>(signal, handle);
  }


  auto* request =
      CredentialManagerProxy::From(script_state)->DigitalIdentityRequest();
  request->Request(std::move(providers),
                   WTF::BindOnce(&OnCompleteRequest, WrapPersistent(resolver),
                                 std::move(scoped_abort_state)));
}

}  // namespace blink
```