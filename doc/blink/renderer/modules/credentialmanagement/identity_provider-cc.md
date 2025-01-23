Response:
Let's break down the thought process for analyzing the given C++ code.

1. **Understand the Goal:** The request asks for the functionality of the `IdentityProvider.cc` file, its relation to web technologies (JS, HTML, CSS), logical reasoning with examples, common errors, and debugging information.

2. **Identify the Core Functionality:** The file is named `identity_provider.cc` and located within the `credentialmanagement` module. This immediately suggests it's related to the browser's credential management features, specifically concerning identity providers. The `#include` directives confirm this by mentioning things like `FederatedAuthRequest`, `IdentityProviderToken`, `IdentityUserInfo`, etc. These strongly indicate the file handles interactions with external identity providers.

3. **Analyze Public Methods:** The core functionalities are exposed through the public methods of the `IdentityProvider` class:
    * `getUserInfo`:  This method clearly aims to fetch user information from an identity provider.
    * `close`: This suggests closing some kind of UI related to identity management.
    * `registerIdentityProvider`: This is about registering a new identity provider.
    * `unregisterIdentityProvider`:  The opposite of registration, removing an identity provider.
    * `resolve`: This seems to be about confirming or validating an identity token with the provider.

4. **Examine Internal Logic and Data Flow:**  For each public method, analyze the steps involved:
    * **`getUserInfo`:**
        * Takes `IdentityProviderConfig` as input.
        * Performs checks: feature enabled, `configURL` present, `configURL` validity, same-origin policy, CSP.
        * Creates a `FederatedAuthRequest` via `CredentialManagerProxy`.
        * Calls `RequestUserInfo` on the request, passing the provider config.
        * Handles the response in `OnRequestUserInfo`: success (parses and resolves with `IdentityUserInfo` objects), error (rejects with a `DOMException`).
    * **`close`:** Directly calls `CloseModalDialogView` on the `FederatedAuthRequest`.
    * **`registerIdentityProvider`:**
        * Takes a `configURL`.
        * Creates a `FederatedAuthRequest`.
        * Calls `RegisterIdP` with the URL.
        * Handles the response in `OnRegisterIdP`, resolving or rejecting based on the `RegisterIdpStatus`.
    * **`unregisterIdentityProvider`:**
        * Takes a `configURL`.
        * Creates a `FederatedAuthRequest`.
        * Calls `UnregisterIdP`.
        * Handles the response in `OnUnregisterIdP`, resolving or rejecting.
    * **`resolve`:**
        * Takes a token (either a custom `IdentityProviderToken` or a string) and `IdentityResolveOptions`.
        * Extracts the token and optionally `account_id`.
        * Creates a `FederatedAuthRequest`.
        * Calls `ResolveTokenRequest`.
        * Handles the response in `OnResolveTokenRequest`, resolving or rejecting.

5. **Identify Connections to Web Technologies:**
    * **JavaScript:** The methods are clearly meant to be called from JavaScript. The use of `ScriptPromise`, `ScriptState`, and the interaction with `CredentialManagerProxy` (which bridges to Blink's core) points to a JavaScript API. The types like `IDLSequence`, `IDLBoolean`, and the V8 type conversions further solidify this.
    * **HTML:** The concept of "identity" is linked to user authentication, often initiated by user actions on HTML pages (e.g., clicking a "Login with..." button). The `close` method suggests a modal dialog, a common HTML element.
    * **CSS:** While not directly manipulated by this code, the visual presentation of any UI elements involved (like the modal dialog) would be styled with CSS.

6. **Develop Examples for Logical Reasoning:**  For each function, create simple scenarios with input and expected output, highlighting the core logic (success and failure cases). This helps demonstrate understanding of how the code behaves.

7. **Identify Potential User/Programming Errors:** Think about common mistakes developers might make when using these APIs:
    * Incorrect or missing configuration URLs.
    * Violating same-origin policy.
    * Not handling promise rejections.
    * Misunderstanding the need for user activation for registration.

8. **Outline the User Interaction Flow:** Trace the steps a user would take that would eventually lead to this C++ code being executed. Start from the user's perspective and work down to the code level.

9. **Structure the Response:** Organize the information logically:
    * Start with a high-level summary of the file's purpose.
    * Detail the functionality of each public method.
    * Explain the relationship to web technologies with examples.
    * Provide logical reasoning examples with inputs and outputs.
    * List common user/programming errors.
    * Describe the user interaction flow.

10. **Review and Refine:** Check for clarity, accuracy, and completeness. Ensure the examples are easy to understand and the explanations are concise. For example, initially, I might have missed the CSP check in `getUserInfo` and added it during the review. Similarly, double-checking the parameter types and return types ensures accuracy.

This systematic approach, moving from the overall purpose down to specific details and then connecting those details back to the broader context of web development, is crucial for understanding and explaining complex code.
好的，让我们来分析一下 `blink/renderer/modules/credentialmanagement/identity_provider.cc` 这个文件。

**文件功能概要**

这个 C++ 文件 `identity_provider.cc` 定义了 Blink 渲染引擎中 `IdentityProvider` 类的实现。`IdentityProvider` 类是 Federated Credentials Management (FedCM)，也被称为 WebID API 的一部分。它的主要功能是允许网站与身份提供商 (Identity Provider, IdP) 进行交互，以实现用户身份验证和授权。

具体来说，`IdentityProvider` 类提供了以下核心功能：

1. **获取用户信息 (`getUserInfo`)**: 允许网站从已配置的身份提供商处获取用户的基本信息（如姓名、邮箱、头像等）。
2. **关闭模态对话框 (`close`)**:  在 FedCM 流程中，可能会出现一个由浏览器控制的模态对话框，用于用户与 IdP 之间的交互。这个方法用于关闭这个对话框。
3. **注册身份提供商 (`registerIdentityProvider`)**: 允许网站动态地向浏览器注册一个新的身份提供商。
4. **注销身份提供商 (`unregisterIdentityProvider`)**: 允许网站取消注册之前注册的身份提供商。
5. **解析令牌请求 (`resolve`)**: 允许身份提供商处理来自网站的令牌请求，并提供相应的响应。

**与 JavaScript, HTML, CSS 的关系及举例**

`IdentityProvider` 类的方法主要通过 JavaScript API 暴露给网页开发者。以下是它们与 JavaScript, HTML, CSS 的关系：

* **JavaScript**:  网页开发者会使用 JavaScript 代码来调用 `navigator.credentials.get()` 方法，并在 `IdentityProvider` 相关的配置项中指定身份提供商的信息。`IdentityProvider` 的方法对应着 JavaScript 中 `IdentityProvider` 接口的方法。

    **举例:**

    ```javascript
    async function loginWithIdP() {
      try {
        const credential = await navigator.credentials.get({
          identity: {
            providers: [
              {
                configURL: 'https://idp.example.com/.well-known/web-identity',
                clientId: 'your-client-id'
              }
            ]
          }
        });

        if (credential) {
          console.log('登录成功！', credential);
        } else {
          console.log('用户取消登录。');
        }
      } catch (error) {
        console.error('登录失败:', error);
      }
    }

    // 当用户点击某个按钮时调用
    document.getElementById('loginButton').addEventListener('click', loginWithIdP);
    ```

    在这个例子中，`navigator.credentials.get()` 的 `identity` 属性配置了身份提供商的信息，其中 `configURL` 就对应了 `IdentityProvider` 中处理的配置信息。当浏览器执行到这里时，可能会触发 `IdentityProvider::getUserInfo` 的相关逻辑。

* **HTML**:  HTML 定义了网页的结构，用户通过与 HTML 元素交互（例如点击按钮）来触发 JavaScript 代码，从而间接地触发 `IdentityProvider` 的功能。

    **举例:**

    ```html
    <!DOCTYPE html>
    <html>
    <head>
      <title>使用身份提供商登录</title>
    </head>
    <body>
      <button id="loginButton">使用示例 IdP 登录</button>
      <script src="your-script.js"></script>
    </body>
    </html>
    ```

    这里的 `<button id="loginButton">` 元素就是用户触发 FedCM 流程的入口。

* **CSS**: CSS 用于控制网页的样式和布局。虽然 `IdentityProvider` 的核心逻辑不直接涉及 CSS，但在 FedCM 流程中，浏览器可能会展示一个模态对话框，这个对话框的样式会受到浏览器内置 CSS 的影响。网站本身也可以通过某些方式影响这个对话框的呈现（具体取决于浏览器的实现）。

    **举例 (间接关系):**  浏览器在展示 FedCM 的用户选择界面时，会使用预定义的 CSS 来渲染界面元素。网站可能无法直接控制这些样式，但了解浏览器如何呈现这些界面有助于开发者理解用户体验。

**逻辑推理与假设输入输出**

**1. `getUserInfo` 方法:**

* **假设输入:**
    * `provider`: 一个 `IdentityProviderConfig` 对象，其中 `configURL` 为 "https://idp.example.com/.well-known/web-identity"，`clientId` 为 "your-client-id"。
    * 调用此方法的上下文是来自 "https://example.com" 的页面。
* **逻辑推理:**
    * 检查 `identity-credentials-get` Feature Policy 是否启用。
    * 检查 `configURL` 是否存在且有效。
    * 检查调用页面 Origin ("https://example.com") 是否与 `configURL` 的 Origin ("https://idp.example.com") 相同。 **如果不同源，则会拒绝 Promise。**
    * 如果同源，则会向 IdP 发起获取用户信息的请求。
* **假设输出 (成功):**  一个 `ScriptPromise`，最终 resolve 为一个 `IdentityUserInfo` 对象的序列，包含用户的姓名、邮箱等信息。
* **假设输出 (失败 - 不同源):** 一个 `ScriptPromise`，最终 reject，并抛出一个 `DOMException`，错误消息为 "UserInfo request must be initiated from a frame that is the same origin with the provider."

**2. `registerIdentityProvider` 方法:**

* **假设输入:**
    * `configURL`: 字符串 "https://new-idp.example.com/.well-known/web-identity"。
    * 用户在页面上有活跃的用户激活（例如，刚刚点击了一个按钮）。
* **逻辑推理:**
    * 检查 FedCM IdP 注册功能是否启用。
    * 检查 `configURL` 是否是跨域的（相对于当前页面）。
    * 检查是否存在瞬时用户激活。
    * 如果所有条件都满足，则向浏览器注册该 IdP。
* **假设输出 (成功):** 一个 `ScriptPromise`，最终 resolve 为 `true`。
* **假设输出 (失败 - 无瞬时用户激活):** 一个 `ScriptPromise`，最终 reject，并抛出一个 `DOMException`，错误消息为 "There is no transient user activation for identity provider registration."

**用户或编程常见的使用错误**

1. **`getUserInfo` 在跨域上下文中调用:** 开发者可能会错误地认为可以在任何页面上调用 `getUserInfo` 来获取 IdP 的用户信息，而没有注意到同源策略的限制。
   * **错误示例:** 在 "https://attacker.com" 的页面上尝试获取 "https://idp.example.com" 的用户信息。
   * **错误结果:**  `getUserInfo` 返回的 Promise 会被 reject，并抛出 `DOMException`。

2. **`registerIdentityProvider` 时缺少用户激活:**  开发者可能会在页面加载时立即尝试注册 IdP，而没有等待用户的交互。
   * **错误示例:** 在 `DOMContentLoaded` 事件处理函数中直接调用 `registerIdentityProvider`。
   * **错误结果:** `registerIdentityProvider` 返回的 Promise 会被 reject，并抛出 `DOMException`。

3. **错误的 `configURL` 或 `clientId`:**  开发者可能在配置身份提供商时提供了错误的 URL 或客户端 ID。
   * **错误示例:**  `configURL` 指向了一个不存在的文件或返回了错误的格式。
   * **错误结果:**  `getUserInfo` 或 `navigator.credentials.get()` 可能会失败，并抛出网络错误或其他类型的错误。

4. **没有处理 Promise 的 rejection:** 开发者可能没有正确地处理 `getUserInfo`、`registerIdentityProvider` 等方法返回的 Promise 的 rejection，导致错误被忽略。
   * **错误示例:**  调用 `getUserInfo()` 后没有 `.catch()` 来处理错误。
   * **错误结果:**  如果操作失败，开发者可能无法得知原因。

**用户操作如何一步步到达这里 (调试线索)**

假设用户想要使用一个支持 FedCM 的网站进行登录：

1. **用户访问 Relying Party (RP) 网站:** 用户在浏览器中输入 RP 网站的 URL，例如 "https://example.com"。
2. **RP 网站加载并执行 JavaScript:** 网站的 HTML、CSS 和 JavaScript 代码被下载到用户的浏览器并执行。
3. **用户点击登录按钮:**  用户在网页上找到一个登录按钮（例如，上面 HTML 例子中的按钮），并点击它。
4. **JavaScript 调用 `navigator.credentials.get()`:**  点击事件触发了 JavaScript 代码，该代码调用了 `navigator.credentials.get()` 方法，并在 `identity` 选项中配置了身份提供商的信息。
5. **Blink 渲染引擎处理 `navigator.credentials.get()`:** 浏览器内核（Blink）接收到这个请求，并开始处理 FedCM 流程。
6. **Blink 查找匹配的 `IdentityProvider` 配置:** Blink 会根据 `navigator.credentials.get()` 中提供的 `providers` 信息，找到对应的 `IdentityProvider` 实例或创建一个新的。
7. **调用 `IdentityProvider::getUserInfo` (如果需要):** 如果浏览器需要从 IdP 获取用户信息（例如，在显示用户选择界面之前），可能会调用 `IdentityProvider::getUserInfo` 方法。
8. **与 IdP 的通信:** `IdentityProvider::getUserInfo` 内部会通过 `CredentialManagerProxy` 和更底层的网络模块，向配置的 `configURL` 发起网络请求，获取 IdP 的配置信息和用户的相关信息。
9. **浏览器显示用户选择界面:**  根据 IdP 返回的信息，浏览器可能会展示一个模态对话框，让用户选择要使用的身份或确认登录。
10. **用户与模态对话框交互:** 用户在模态对话框中选择一个身份或取消操作。
11. **调用 `IdentityProvider::resolve` (如果用户选择登录):** 如果用户选择使用某个身份登录，浏览器可能会调用 `IdentityProvider::resolve` 方法，将 RP 网站提供的 client ID 和用户在 IdP 处的信息传递给 IdP 进行验证，并获取访问令牌。
12. **IdP 返回访问令牌:** IdP 验证信息后，会返回一个访问令牌给浏览器。
13. **RP 网站接收凭据:**  `navigator.credentials.get()` 返回的 Promise resolve，并携带包含用户信息的凭据。
14. **RP 网站完成登录流程:** RP 网站使用接收到的凭据完成用户的登录。

**调试线索:**

* **网络请求:** 开发者可以使用浏览器的开发者工具（Network 面板）查看与 IdP 之间的网络请求，包括请求的 URL、请求头、响应状态码和响应内容。这可以帮助诊断配置问题或网络错误。
* **控制台日志:** 在 `IdentityProvider.cc` 中添加调试日志（例如，使用 `DLOG` 或 `DVLOG`），可以帮助追踪代码的执行流程和变量的值。这些日志可以在 Chrome 的内部日志中查看（chrome://webrtc-logs/ 或启动 Chrome 时添加 `--enable-logging --v=1` 参数）。
* **断点调试:**  开发者可以在 `IdentityProvider.cc` 中设置断点，使用调试器逐步执行代码，查看变量的值和调用堆栈。这需要编译 Chromium 源码。
* **浏览器内部页面:**  Chrome 提供了一些内部页面，例如 `chrome://identity-internals/`，可以查看与身份验证相关的状态和信息。虽然不直接针对 `IdentityProvider.cc`，但可以提供上下文信息。
* **Feature Policy 检查:** 确保页面的 Feature Policy 允许使用 `identity-credentials-get` 特性。

希望以上分析能够帮助你理解 `blink/renderer/modules/credentialmanagement/identity_provider.cc` 文件的功能和它在 WebID API 中的作用。

### 提示词
```
这是目录为blink/renderer/modules/credentialmanagement/identity_provider.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/credentialmanagement/identity_provider.h"

#include "third_party/blink/public/mojom/webid/federated_auth_request.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_identity_provider_token.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_identity_resolve_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_identity_user_info.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_union_identityprovidertoken_usvstring.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/csp/content_security_policy.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/modules/credentialmanagement/credential_manager_proxy.h"
#include "third_party/blink/renderer/modules/credentialmanagement/credential_manager_type_converters.h"
#include "third_party/blink/renderer/modules/credentialmanagement/identity_credential.h"
#include "third_party/blink/renderer/modules/credentialmanagement/scoped_promise_resolver.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"

namespace blink {

namespace {

using mojom::blink::RegisterIdpStatus;
using mojom::blink::RequestUserInfoStatus;

void OnRequestUserInfo(
    ScriptPromiseResolver<IDLSequence<IdentityUserInfo>>* resolver,
    RequestUserInfoStatus status,
    std::optional<Vector<mojom::blink::IdentityUserInfoPtr>>
        all_user_info_ptr) {
  switch (status) {
    case RequestUserInfoStatus::kError: {
      resolver->Reject(MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kNetworkError, "Error retrieving user info."));
      return;
    }
    case RequestUserInfoStatus::kSuccess: {
      HeapVector<Member<IdentityUserInfo>> all_user_info;
      for (const auto& user_info_ptr : all_user_info_ptr.value()) {
        IdentityUserInfo* user_info = IdentityUserInfo::Create();
        user_info->setEmail(user_info_ptr->email);
        user_info->setGivenName(user_info_ptr->given_name);
        user_info->setName(user_info_ptr->name);
        user_info->setPicture(user_info_ptr->picture);
        all_user_info.push_back(user_info);
      }

      DCHECK_GT(all_user_info.size(), 0u);
      resolver->Resolve(all_user_info);
      return;
    }
    default: {
      NOTREACHED();
    }
  }
}

}  // namespace

ScriptPromise<IDLSequence<IdentityUserInfo>> IdentityProvider::getUserInfo(
    ScriptState* script_state,
    const blink::IdentityProviderConfig* provider,
    ExceptionState& exception_state) {
  auto* resolver = MakeGarbageCollected<
      ScriptPromiseResolver<IDLSequence<IdentityUserInfo>>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();
  if (!resolver->GetExecutionContext()->IsFeatureEnabled(
          mojom::blink::PermissionsPolicyFeature::kIdentityCredentialsGet)) {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kNotAllowedError,
        "The 'identity-credentials-get' feature is not enabled in this "
        "document."));
    return promise;
  }

  DCHECK(provider);

  if (!provider->hasConfigURL()) {
    resolver->RejectWithTypeError("Missing the provider's configURL.");
    return promise;
  }

  KURL provider_url(provider->configURL());
  String client_id = provider->clientId();

  if (!provider_url.IsValid() || client_id == "") {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kInvalidStateError,
        String::Format("Provider information is incomplete.")));
    return promise;
  }

  const SecurityOrigin* origin =
      resolver->GetExecutionContext()->GetSecurityOrigin();
  if (!SecurityOrigin::CreateFromString(provider_url)
           ->IsSameOriginWith(origin)) {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kInvalidStateError,
        "UserInfo request must be initiated from a frame that is the same "
        "origin with the provider."));
    return promise;
  }

  ContentSecurityPolicy* policy =
      resolver->GetExecutionContext()
          ->GetContentSecurityPolicyForCurrentWorld();
  // We disallow redirects (in idp_network_request_manager.cc), so it is
  // sufficient to check the initial URL here.
  if (IdentityCredential::IsRejectingPromiseDueToCSP(policy, resolver,
                                                     provider_url)) {
    return promise;
  }

  mojom::blink::IdentityProviderConfigPtr identity_provider =
      blink::mojom::blink::IdentityProviderConfig::From(*provider);

  auto* user_info_request =
      CredentialManagerProxy::From(script_state)->FederatedAuthRequest();
  user_info_request->RequestUserInfo(
      std::move(identity_provider),
      WTF::BindOnce(&OnRequestUserInfo, WrapPersistent(resolver)));

  return promise;
}

void IdentityProvider::close(ScriptState* script_state) {
  auto* request =
      CredentialManagerProxy::From(script_state)->FederatedAuthRequest();
  request->CloseModalDialogView();
}

void OnRegisterIdP(ScriptPromiseResolver<IDLBoolean>* resolver,
                   RegisterIdpStatus status) {
  switch (status) {
    case RegisterIdpStatus::kSuccess: {
      resolver->Resolve(true);
      return;
    }
    case RegisterIdpStatus::kErrorFeatureDisabled: {
      resolver->Reject(MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kNotAllowedError,
          "FedCM IdP registration feature is disabled."));
      return;
    }
    case RegisterIdpStatus::kErrorCrossOriginConfig: {
      resolver->Reject(MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kNotAllowedError,
          "Attempting to register a cross-origin config."));
      return;
    }
    case RegisterIdpStatus::kErrorNoTransientActivation: {
      resolver->Reject(MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kNotAllowedError,
          "There is no transient user activation for identity provider "
          "registration."));
      return;
    }
    case RegisterIdpStatus::kErrorDeclined: {
      resolver->Reject(MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kNotAllowedError,
          "User declined the permission to register the identity provider."));
      return;
    }
  };
}

ScriptPromise<IDLBoolean> IdentityProvider::registerIdentityProvider(
    ScriptState* script_state,
    const String& configURL) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLBoolean>>(script_state);
  auto promise = resolver->Promise();

  auto* request =
      CredentialManagerProxy::From(script_state)->FederatedAuthRequest();
  request->RegisterIdP(KURL(configURL),
                       WTF::BindOnce(&OnRegisterIdP, WrapPersistent(resolver)));

  return promise;
}

void OnUnregisterIdP(ScriptPromiseResolver<IDLUndefined>* resolver,
                     bool accepted) {
  if (!accepted) {
    resolver->RejectWithDOMException(
        DOMExceptionCode::kNotAllowedError,
        "Not allowed to unregister the Identity Provider.");
    return;
  }
  resolver->Resolve();
}

ScriptPromise<IDLUndefined> IdentityProvider::unregisterIdentityProvider(
    ScriptState* script_state,
    const String& configURL) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  auto promise = resolver->Promise();

  auto* request =
      CredentialManagerProxy::From(script_state)->FederatedAuthRequest();
  request->UnregisterIdP(
      KURL(configURL),
      WTF::BindOnce(&OnUnregisterIdP, WrapPersistent(resolver)));

  return promise;
}

void OnResolveTokenRequest(ScriptPromiseResolver<IDLUndefined>* resolver,
                           bool accepted) {
  if (!accepted) {
    resolver->RejectWithDOMException(DOMExceptionCode::kNotAllowedError,
                                     "Not allowed to provide a token.");
    return;
  }
  resolver->Resolve();
}

ScriptPromise<IDLUndefined> IdentityProvider::resolve(
    ScriptState* script_state,
    const V8UnionIdentityProviderTokenOrUSVString* token_union,
    const IdentityResolveOptions* options) {
  DCHECK(options);

  String token;
  if (token_union->IsIdentityProviderToken()) {
    token = token_union->GetAsIdentityProviderToken()->token();
  } else {
    CHECK(token_union->IsUSVString());
    token = token_union->GetAsUSVString();
  }

  String account_id;
  if (options->hasAccountId() && !options->accountId().empty()) {
    account_id = options->accountId();
  }

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  auto promise = resolver->Promise();

  auto* request =
      CredentialManagerProxy::From(script_state)->FederatedAuthRequest();
  request->ResolveTokenRequest(
      account_id, token,
      WTF::BindOnce(&OnResolveTokenRequest, WrapPersistent(resolver)));

  return promise;
}

}  // namespace blink
```