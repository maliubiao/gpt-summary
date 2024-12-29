Response:
The user wants a summary of the functionalities of the provided C++ code for `authentication_credentials_container.cc`.

Here's a breakdown of the code's functions and their relation to web technologies:

1. **`get()`**: Retrieves credentials. It handles different credential types (PublicKeyCredential, OTP, Identity, Federated) and mediation requirements.
2. **`store()`**: Saves credentials. Currently supports Federated and Password credentials.
3. **`create()`**: Creates new credentials. Supports Password, Federated, and PublicKey credentials (WebAuthn).
4. **`preventSilentAccess()`**: Prevents silent access to credentials.
5. **`GetForIdentity()`**:  Specifically handles the logic for retrieving identity credentials (FedCM).

I need to explain these functionalities, connect them to JavaScript, HTML, and CSS where applicable, provide examples of logic, common errors, and how a user might trigger this code. Finally, I will provide an overall summary.
这是 `blink/renderer/modules/credentialmanagement/authentication_credentials_container.cc` 文件的功能归纳：

**核心功能:**

这个文件实现了 `AuthenticationCredentialsContainer` 类，该类是浏览器 Credential Management API 的核心部分，允许网页通过 JavaScript 与用户的凭据进行交互。它提供了以下主要功能：

*   **获取凭据 (`get()`):** 允许网站请求用户存储的凭据。支持多种凭据类型，包括：
    *   **PublicKeyCredential (WebAuthn):** 用于强大的无密码身份验证。
    *   **OTP (One-Time Password):**  用于通过短信验证码进行身份验证。
    *   **Identity (FedCM/Web Identity):**  用于通过身份提供商进行联合身份验证。
    *   **Federated Credentials:**  传统的联合身份验证。
    *   **Password Credentials:**  传统的用户名和密码。
*   **存储凭据 (`store()`):** 允许网站存储新的凭据。目前支持存储 FederatedCredential 和 PasswordCredential。
*   **创建凭据 (`create()`):** 允许网站请求创建新的凭据。支持创建 PasswordCredential、FederatedCredential 和 PublicKeyCredential。
*   **阻止静默访问 (`preventSilentAccess()`):** 允许网站阻止在不提示用户的情况下自动使用凭据。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这些功能通过 JavaScript 的 `navigator.credentials` 对象暴露给网页开发者。

*   **`navigator.credentials.get(options)`:**  对应 C++ 代码中的 `Get()` 方法。
    *   **JavaScript 示例:**
        ```javascript
        navigator.credentials.get({
          publicKey: {
            challenge: new Uint8Array([ /* ... */ ]),
            allowCredentials: [ /* ... */ ],
            // ...
          },
          mediation: 'optional'
        })
        .then(credential => {
          // 使用获取到的凭据
          console.log(credential);
        })
        .catch(error => {
          console.error("获取凭据失败:", error);
        });
        ```
    *   **HTML/CSS 关系:**  虽然 `get()` 本身不直接涉及 HTML 或 CSS 的渲染，但用户与页面元素的交互（例如点击登录按钮）可能会触发此 JavaScript 代码。页面的 HTML 结构和 CSS 样式影响用户如何与触发凭据请求的元素进行交互。

*   **`navigator.credentials.store(credential)`:** 对应 C++ 代码中的 `Store()` 方法。
    *   **JavaScript 示例:**
        ```javascript
        const newPassword = new PasswordCredential({
          id: 'user@example.com',
          password: 'mysecretpassword'
        });
        navigator.credentials.store(newPassword)
          .then(() => console.log("凭据已保存"))
          .catch(error => console.error("保存凭据失败:", error));
        ```
    *   **HTML 关系:** 通常在用户填写 HTML 表单后调用 `store()` 来保存凭据。例如，在注册或登录表单提交时。

*   **`navigator.credentials.create(options)`:** 对应 C++ 代码中的 `Create()` 方法。
    *   **JavaScript 示例 (WebAuthn 注册):**
        ```javascript
        navigator.credentials.create({
          publicKey: {
            challenge: new Uint8Array([ /* ... */ ]),
            rp: { name: "Example Corp" },
            user: {
              id: new Uint8Array([ /* ... */ ]),
              name: "John Doe",
              displayName: "John Doe"
            },
            pubKeyCredParams: [ { alg: -7, type: "public-key" } ],
            // ...
          }
        })
        .then(newCredential => {
          // 将新凭据发送到服务器进行注册
          console.log(newCredential);
        })
        .catch(error => console.error("创建凭据失败:", error));
        ```
    *   **HTML 关系:**  通常在用户点击注册按钮或进行需要创建新凭据的操作时触发。

*   **`navigator.credentials.preventSilentAccess()`:** 对应 C++ 代码中的 `PreventSilentAccess()` 方法。
    *   **JavaScript 示例:**
        ```javascript
        navigator.credentials.preventSilentAccess()
          .then(() => console.log("已阻止静默访问"))
          .catch(error => console.error("阻止静默访问失败:", error));
        ```
    *   **HTML 关系:**  可能在用户执行注销操作或更改某些安全设置时调用。

**逻辑推理及假设输入与输出:**

**场景： `get()` 方法处理 OTP 凭据请求**

*   **假设输入:**
    *   JavaScript 调用 `navigator.credentials.get({ otp: { transport: ['sms'] } })`
    *   用户在页面上触发了请求 OTP 的操作。
*   **逻辑推理:**
    1. `get()` 方法会检查 `options` 是否包含 `otp` 属性，并且 `transport` 中包含 "sms"。
    2. 它会创建一个 `OtpRequestAbortAlgorithm` 用于处理中止信号。
    3. 它会调用 `WebOTPService::Receive()` 来监听来自短信的 OTP。
    4. `OnSmsReceive` 回调函数会在收到短信后被调用，并将 OTP 解析出来传递给 Promise 的 resolve。
*   **预期输出:**  Promise 会成功 resolve，并携带包含接收到的 OTP 的凭据对象。

**用户或编程常见的使用错误及举例说明:**

*   **错误使用 `create()` 方法：指定了多个凭据类型。**
    *   **JavaScript 示例:**
        ```javascript
        navigator.credentials.create({
          password: { /* ... */ },
          federated: { /* ... */ }
        }); // 错误：同时指定了 password 和 federated
        ```
    *   **C++ 逻辑:**  `create()` 方法中会检查是否只设置了 `password`、`federated` 或 `publicKey` 中的一个，否则会拒绝 Promise 并抛出 `NotSupportedError`。

*   **错误使用 `store()` 方法：尝试存储不支持的凭据类型。**
    *   **JavaScript 示例:**  假设尝试存储一个通用的 `Credential` 对象（不是 `PasswordCredential` 或 `FederatedCredential` 的实例）。
    *   **C++ 逻辑:** `store()` 方法会检查 `credential` 的类型，如果不是 `FederatedCredential` 或 `PasswordCredential`，则会拒绝 Promise 并抛出 `NotSupportedError`。

*   **忘记检查安全上下文 (HTTPS):**  Credential Management API 的许多功能（特别是涉及敏感凭据的操作）需要在安全上下文（HTTPS）下才能使用。
    *   **用户操作:** 在非 HTTPS 页面调用 `navigator.credentials.get()` 或 `navigator.credentials.create()`。
    *   **C++ 逻辑:**  `CheckSecurityRequirementsBeforeRequest` 函数会进行安全上下文检查，如果失败则拒绝 Promise。

**用户操作如何一步步的到达这里 (作为调试线索):**

以 `navigator.credentials.get()` 获取 PublicKeyCredential 为例：

1. **用户访问一个网站，该网站需要用户进行身份验证。**
2. **网站的 JavaScript 代码被执行。**
3. **JavaScript 代码调用 `navigator.credentials.get({ publicKey: { ... } })`。**  这通常发生在用户点击 "登录" 按钮或网站需要静默尝试登录时。
4. **浏览器接收到 `get()` 调用，并进入 Blink 渲染引擎。**
5. **`AuthenticationCredentialsContainer::get()` 方法被调用。**
6. **根据 `options` 参数，代码会进入处理 PublicKeyCredential 的分支。**
7. **进行安全检查（例如 HTTPS）。**
8. **浏览器可能会显示一个 UI 界面，提示用户选择要使用的凭据，或者连接到认证器设备 (例如指纹识别器或安全密钥)。**
9. **如果用户成功选择或验证了凭据，浏览器会将凭据信息返回给网站的 JavaScript 代码，Promise 会 resolve。**
10. **如果出现错误（例如用户取消操作，或者没有找到匹配的凭据），Promise 会 reject。**

**功能归纳 (第 3 部分，共 3 部分):**

总的来说，`authentication_credentials_container.cc` 文件实现了 Credential Management API 的核心功能，允许网页安全地与用户的凭据进行交互。它处理了获取、存储和创建不同类型的凭据的复杂逻辑，并确保符合安全性和用户体验的最佳实践。 这个文件是浏览器凭据管理功能在渲染引擎中的关键实现部分，连接了 JavaScript API 和底层的凭据管理系统。它通过各种检查和流程，保障了用户凭据的安全性和隐私。

Prompt: 
```
这是目录为blink/renderer/modules/credentialmanagement/authentication_credentials_container.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共3部分，请归纳一下它的功能

"""
s missing in 'options.publicKey'."));
      return promise;
    }
    if (!ambient_request_enabled) {
      return promise;
    }
  }

  if (options->hasOtp() && options->otp()->hasTransport()) {
    if (!options->otp()->transport().Contains("sms")) {
      resolver->Reject(MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kNotSupportedError,
          "Unsupported transport type for OTP Credentials"));
      return promise;
    }

    std::unique_ptr<ScopedAbortState> scoped_abort_state = nullptr;
    if (auto* signal = options->getSignalOr(nullptr)) {
      auto* handle = signal->AddAlgorithm(
          MakeGarbageCollected<OtpRequestAbortAlgorithm>(script_state));
      scoped_abort_state = std::make_unique<ScopedAbortState>(signal, handle);
    }

    auto* webotp_service =
        CredentialManagerProxy::From(script_state)->WebOTPService();
    webotp_service->Receive(
        WTF::BindOnce(&OnSmsReceive, WrapPersistent(resolver),
                      std::move(scoped_abort_state), base::TimeTicks::Now()));

    UseCounter::Count(context, WebFeature::kWebOTP);
    return promise;
  }

  if (options->hasIdentity() && options->identity()->hasProviders()) {
    GetForIdentity(script_state, resolver, *options, *options->identity());
    return promise;
  }

  Vector<KURL> providers;
  if (options->hasFederated() && options->federated()->hasProviders()) {
    for (const auto& provider : options->federated()->providers()) {
      KURL url = KURL(NullURL(), provider);
      if (url.IsValid()) {
        providers.push_back(std::move(url));
      }
    }
  }
  CredentialMediationRequirement requirement;
  if (!ambient_request_enabled && options->mediation() == "conditional") {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kNotSupportedError,
        "Conditional mediation is not supported for this credential type"));
    return promise;
  }
  if (options->mediation() == "silent") {
    UseCounter::Count(context,
                      WebFeature::kCredentialManagerGetMediationSilent);
    requirement = CredentialMediationRequirement::kSilent;
  } else if (options->mediation() == "optional") {
    UseCounter::Count(context,
                      WebFeature::kCredentialManagerGetMediationOptional);
    requirement = CredentialMediationRequirement::kOptional;
  } else if (options->mediation() == "required") {
    UseCounter::Count(context,
                      WebFeature::kCredentialManagerGetMediationRequired);
    requirement = CredentialMediationRequirement::kRequired;
  } else {
    CHECK_EQ("conditional", options->mediation());
    requirement = CredentialMediationRequirement::kRequired;
  }

  auto* credential_manager =
      CredentialManagerProxy::From(script_state)->CredentialManager();
  credential_manager->Get(
      requirement, requested_credential_types, std::move(providers),
      WTF::BindOnce(&OnGetComplete,
                    std::make_unique<ScopedPromiseResolver>(resolver),
                    required_origin_type));

  return promise;
}

ScriptPromise<Credential> AuthenticationCredentialsContainer::store(
    ScriptState* script_state,
    Credential* credential,
    ExceptionState& exception_state) {
  if (!script_state->ContextIsValid()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Context is detached");
    return EmptyPromise();
  }

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<Credential>>(script_state);
  auto promise = resolver->Promise();

  if (!(credential->IsFederatedCredential() ||
        credential->IsPasswordCredential())) {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kNotSupportedError,
        "Store operation not permitted for this credential type."));
    return promise;
  }

  if (!CheckSecurityRequirementsBeforeRequest(
          resolver, RequiredOriginType::kSecureAndSameWithAncestors)) {
    return promise;
  }

  if (credential->IsFederatedCredential()) {
    UseCounter::Count(resolver->GetExecutionContext(),
                      WebFeature::kCredentialManagerStoreFederatedCredential);
  } else if (credential->IsPasswordCredential()) {
    UseCounter::Count(resolver->GetExecutionContext(),
                      WebFeature::kCredentialManagerStorePasswordCredential);
  }

  const KURL& url =
      credential->IsFederatedCredential()
          ? static_cast<const FederatedCredential*>(credential)->iconURL()
          : static_cast<const PasswordCredential*>(credential)->iconURL();
  if (!IsIconURLNullOrSecure(url)) {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kSecurityError, "'iconURL' should be a secure URL"));
    return promise;
  }

  auto* credential_manager =
      CredentialManagerProxy::From(script_state)->CredentialManager();

  DCHECK_NE(mojom::blink::CredentialType::EMPTY,
            CredentialInfo::From(credential)->type);

  credential_manager->Store(
      CredentialInfo::From(credential),
      WTF::BindOnce(&OnStoreComplete,
                    std::make_unique<ScopedPromiseResolver>(resolver)));

  return promise;
}

ScriptPromise<IDLNullable<Credential>>
AuthenticationCredentialsContainer::create(
    ScriptState* script_state,
    const CredentialCreationOptions* options,
    ExceptionState& exception_state) {
  if (!script_state->ContextIsValid()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Context is detached");
    return ScriptPromise<IDLNullable<Credential>>();
  }

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLNullable<Credential>>>(
          script_state);
  auto promise = resolver->Promise();

  RequiredOriginType required_origin_type;
  if (IsForPayment(options, resolver->GetExecutionContext())) {
    required_origin_type = RequiredOriginType::
        kSecureWithPaymentOrCreateCredentialPermissionPolicy;
  } else if (options->hasPublicKey()) {
    // hasPublicKey() implies that this is a WebAuthn request.
    required_origin_type = RequiredOriginType::
        kSecureAndPermittedByWebAuthCreateCredentialPermissionsPolicy;
  } else {
    required_origin_type = RequiredOriginType::kSecure;
  }
  if (!CheckSecurityRequirementsBeforeRequest(resolver, required_origin_type)) {
    return promise;
  }

  if ((options->hasPassword() + options->hasFederated() +
       options->hasPublicKey()) != 1) {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kNotSupportedError,
        "Only exactly one of 'password', 'federated', and 'publicKey' "
        "credential types are currently supported."));
    return promise;
  }

  if (options->hasPassword()) {
    UseCounter::Count(resolver->GetExecutionContext(),
                      WebFeature::kCredentialManagerCreatePasswordCredential);
    resolver->Resolve(
        options->password()->IsPasswordCredentialData()
            ? PasswordCredential::Create(
                  options->password()->GetAsPasswordCredentialData(),
                  exception_state)
            : PasswordCredential::Create(
                  options->password()->GetAsHTMLFormElement(),
                  exception_state));
    return promise;
  }
  if (options->hasFederated()) {
    UseCounter::Count(resolver->GetExecutionContext(),
                      WebFeature::kCredentialManagerCreateFederatedCredential);
    resolver->Resolve(
        FederatedCredential::Create(options->federated(), exception_state));
    return promise;
  }
  DCHECK(options->hasPublicKey());
  UseCounter::Count(resolver->GetExecutionContext(),
                    WebFeature::kCredentialManagerCreatePublicKeyCredential);

  if (!IsArrayBufferOrViewBelowSizeLimit(options->publicKey()->challenge())) {
    resolver->Reject(DOMException::Create(
        "The `challenge` attribute exceeds the maximum allowed size.",
        "RangeError"));
    return promise;
  }

  if (!IsArrayBufferOrViewBelowSizeLimit(options->publicKey()->user()->id())) {
    resolver->Reject(DOMException::Create(
        "The `user.id` attribute exceeds the maximum allowed size.",
        "RangeError"));
    return promise;
  }

  if (!IsCredentialDescriptorListBelowSizeLimit(
          options->publicKey()->excludeCredentials())) {
    resolver->Reject(
        DOMException::Create("The `excludeCredentials` attribute exceeds the "
                             "maximum allowed size (64).",
                             "RangeError"));
    return promise;
  }

  for (const auto& credential : options->publicKey()->excludeCredentials()) {
    if (!IsArrayBufferOrViewBelowSizeLimit(credential->id())) {
      resolver->Reject(DOMException::Create(
          "The `excludeCredentials.id` attribute exceeds the maximum "
          "allowed size.",
          "RangeError"));
      return promise;
    }
  }

  if (options->publicKey()->hasExtensions()) {
    if (options->publicKey()->extensions()->hasAppid()) {
      resolver->Reject(MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kNotSupportedError,
          "The 'appid' extension is only valid when requesting an assertion "
          "for a pre-existing credential that was registered using the "
          "legacy FIDO U2F API."));
      return promise;
    }
    if (options->publicKey()->extensions()->hasAppidExclude()) {
      const auto& appid_exclude =
          options->publicKey()->extensions()->appidExclude();
      if (!appid_exclude.empty()) {
        KURL appid_exclude_url(appid_exclude);
        if (!appid_exclude_url.IsValid()) {
          resolver->Reject(MakeGarbageCollected<DOMException>(
              DOMExceptionCode::kSyntaxError,
              "The `appidExclude` extension value is neither "
              "empty/null nor a valid URL."));
          return promise;
        }
      }
    }
    if (options->publicKey()->extensions()->hasCableAuthentication()) {
      resolver->Reject(MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kNotSupportedError,
          "The 'cableAuthentication' extension is only valid when requesting "
          "an assertion"));
      return promise;
    }
    if (options->publicKey()->extensions()->hasLargeBlob()) {
      if (options->publicKey()->extensions()->largeBlob()->hasRead()) {
        resolver->Reject(MakeGarbageCollected<DOMException>(
            DOMExceptionCode::kNotSupportedError,
            "The 'largeBlob' extension's 'read' parameter is only valid when "
            "requesting an assertion"));
        return promise;
      }
      if (options->publicKey()->extensions()->largeBlob()->hasWrite()) {
        resolver->Reject(MakeGarbageCollected<DOMException>(
            DOMExceptionCode::kNotSupportedError,
            "The 'largeBlob' extension's 'write' parameter is only valid "
            "when requesting an assertion"));
        return promise;
      }
    }
    if (options->publicKey()->extensions()->hasPayment() &&
        !IsPaymentExtensionValid(options, resolver)) {
      return promise;
    }
    if (options->publicKey()->extensions()->hasPrf()) {
      const char* error = validateCreatePublicKeyCredentialPRFExtension(
          *options->publicKey()->extensions()->prf());
      if (error != nullptr) {
        resolver->Reject(MakeGarbageCollected<DOMException>(
            DOMExceptionCode::kNotSupportedError, error));
        return promise;
      }
    }
  }

  // In the case of create() in a cross-origin iframe, the spec requires that
  // the caller must have transient user activation (which is consumed).
  // https://w3c.github.io/webauthn/#sctn-createCredential, step 2.
  //
  // TODO(crbug.com/1512245): This check should be used for payment credentials
  // as well, but currently the SPC spec expects a SecurityError rather than
  // NotAllowedError.
  if (!IsSameSecurityOriginWithAncestors(
          To<LocalDOMWindow>(resolver->GetExecutionContext())->GetFrame()) &&
      (!options->publicKey()->hasExtensions() ||
       !options->publicKey()->extensions()->hasPayment())) {
    bool has_user_activation = LocalFrame::ConsumeTransientUserActivation(
        To<LocalDOMWindow>(resolver->GetExecutionContext())->GetFrame(),
        UserActivationUpdateSource::kRenderer);
    if (!has_user_activation) {
      resolver->Reject(MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kNotAllowedError,
          "A user activation is required to create a credential in a "
          "cross-origin iframe."));
      return promise;
    }
  }

  std::unique_ptr<ScopedAbortState> scoped_abort_state = nullptr;
  if (auto* signal = options->getSignalOr(nullptr)) {
    if (signal->aborted()) {
      resolver->Reject(signal->reason(script_state));
      return promise;
    }
    auto* handle = signal->AddAlgorithm(
        MakeGarbageCollected<PublicKeyRequestAbortAlgorithm>(script_state));
    scoped_abort_state = std::make_unique<ScopedAbortState>(signal, handle);
  }

  if (options->publicKey()->hasAttestation() &&
      !mojo::ConvertTo<std::optional<AttestationConveyancePreference>>(
          options->publicKey()->attestation())) {
    resolver->GetExecutionContext()->AddConsoleMessage(
        MakeGarbageCollected<ConsoleMessage>(
            mojom::blink::ConsoleMessageSource::kJavaScript,
            mojom::blink::ConsoleMessageLevel::kWarning,
            "Ignoring unknown publicKey.attestation value"));
  }

  if (options->publicKey()->hasAuthenticatorSelection() &&
      options->publicKey()
          ->authenticatorSelection()
          ->hasAuthenticatorAttachment()) {
    std::optional<String> attachment = options->publicKey()
                                           ->authenticatorSelection()
                                           ->authenticatorAttachment();
    if (!mojo::ConvertTo<std::optional<AuthenticatorAttachment>>(attachment)) {
      resolver->GetExecutionContext()->AddConsoleMessage(
          MakeGarbageCollected<ConsoleMessage>(
              mojom::blink::ConsoleMessageSource::kJavaScript,
              mojom::blink::ConsoleMessageLevel::kWarning,
              "Ignoring unknown "
              "publicKey.authenticatorSelection.authnticatorAttachment value"));
    }
  }

  if (options->publicKey()->hasAuthenticatorSelection() &&
      options->publicKey()->authenticatorSelection()->hasUserVerification() &&
      !mojo::ConvertTo<
          std::optional<mojom::blink::UserVerificationRequirement>>(
          options->publicKey()->authenticatorSelection()->userVerification())) {
    resolver->GetExecutionContext()->AddConsoleMessage(
        MakeGarbageCollected<ConsoleMessage>(
            mojom::blink::ConsoleMessageSource::kJavaScript,
            mojom::blink::ConsoleMessageLevel::kWarning,
            "Ignoring unknown "
            "publicKey.authenticatorSelection.userVerification value"));
  }

  bool is_rk_required = false;
  if (options->publicKey()->hasAuthenticatorSelection() &&
      options->publicKey()->authenticatorSelection()->hasResidentKey()) {
    auto rk_requirement =
        mojo::ConvertTo<std::optional<mojom::blink::ResidentKeyRequirement>>(
            options->publicKey()->authenticatorSelection()->residentKey());
    if (!rk_requirement) {
      resolver->GetExecutionContext()->AddConsoleMessage(
          MakeGarbageCollected<ConsoleMessage>(
              mojom::blink::ConsoleMessageSource::kJavaScript,
              mojom::blink::ConsoleMessageLevel::kWarning,
              "Ignoring unknown publicKey.authenticatorSelection.residentKey "
              "value"));
    } else {
      is_rk_required =
          (rk_requirement == mojom::blink::ResidentKeyRequirement::REQUIRED);
    }
  }
  // An empty list uses default algorithm identifiers.
  if (options->publicKey()->pubKeyCredParams().size() != 0) {
    WTF::HashSet<int16_t> algorithm_set;
    for (const auto& param : options->publicKey()->pubKeyCredParams()) {
      // 0 and -1 are special values that cannot be inserted into the HashSet.
      if (param->alg() != 0 && param->alg() != -1) {
        algorithm_set.insert(param->alg());
      }
    }
    if (!algorithm_set.Contains(-7) || !algorithm_set.Contains(-257)) {
      resolver->GetExecutionContext()->AddConsoleMessage(
          MakeGarbageCollected<ConsoleMessage>(
              mojom::blink::ConsoleMessageSource::kJavaScript,
              mojom::blink::ConsoleMessageLevel::kWarning,
              "publicKey.pubKeyCredParams is missing at least one of the "
              "default algorithm identifiers: ES256 and RS256. This can "
              "result in registration failures on incompatible "
              "authenticators. See "
              "https://chromium.googlesource.com/chromium/src/+/main/"
              "content/browser/webauth/pub_key_cred_params.md for details"));
    }
  }

  auto mojo_options =
      MojoPublicKeyCredentialCreationOptions::From(*options->publicKey());
  if (!mojo_options) {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kNotSupportedError,
        "Required parameters missing in `options.publicKey`."));
    return promise;
  }

  if (mojo_options->user->id.size() > 64) {
    // https://www.w3.org/TR/webauthn/#user-handle
    v8::Isolate* isolate = resolver->GetScriptState()->GetIsolate();
    resolver->Reject(V8ThrowException::CreateTypeError(
        isolate, "User handle exceeds 64 bytes."));
    return promise;
  }

  if (!mojo_options->relying_party->id) {
    mojo_options->relying_party->id =
        resolver->GetExecutionContext()->GetSecurityOrigin()->Domain();
  }

  auto* authenticator =
      CredentialManagerProxy::From(script_state)->Authenticator();
  if (mojo_options->is_payment_credential_creation) {
    String rp_id_for_payment_extension = mojo_options->relying_party->id;
    WTF::Vector<uint8_t> user_id_for_payment_extension = mojo_options->user->id;
    authenticator->MakeCredential(
        std::move(mojo_options),
        WTF::BindOnce(&OnMakePublicKeyCredentialWithPaymentExtensionComplete,
                      std::make_unique<ScopedPromiseResolver>(resolver),
                      std::move(scoped_abort_state),
                      rp_id_for_payment_extension,
                      std::move(user_id_for_payment_extension)));
  } else {
    if (RuntimeEnabledFeatures::WebAuthenticationConditionalCreateEnabled()) {
      mojo_options->is_conditional = options->mediation() == "conditional";
    }
    authenticator->MakeCredential(
        std::move(mojo_options),
        WTF::BindOnce(&OnMakePublicKeyCredentialComplete,
                      std::make_unique<ScopedPromiseResolver>(resolver),
                      std::move(scoped_abort_state), required_origin_type,
                      is_rk_required));
  }

  return promise;
}

ScriptPromise<IDLUndefined>
AuthenticationCredentialsContainer::preventSilentAccess(
    ScriptState* script_state) {
  if (!script_state->ContextIsValid()) {
    return ScriptPromise<IDLUndefined>::RejectWithDOMException(
        script_state,
        MakeGarbageCollected<DOMException>(DOMExceptionCode::kInvalidStateError,
                                           "Context is detached"));
  }

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  auto promise = resolver->Promise();
  const auto required_origin_type = RequiredOriginType::kSecure;
  if (!CheckSecurityRequirementsBeforeRequest(resolver, required_origin_type)) {
    return promise;
  }

  auto* credential_manager =
      CredentialManagerProxy::From(script_state)->CredentialManager();
  credential_manager->PreventSilentAccess(
      WTF::BindOnce(&OnPreventSilentAccessComplete,
                    std::make_unique<ScopedPromiseResolver>(resolver)));

  // TODO(https://crbug.com/1441075): Unify the implementation for
  // different CredentialTypes and avoid the duplication eventually.
  auto* auth_request =
      CredentialManagerProxy::From(script_state)->FederatedAuthRequest();
  auth_request->PreventSilentAccess(
      WTF::BindOnce(&OnPreventSilentAccessComplete,
                    std::make_unique<ScopedPromiseResolver>(resolver)));

  return promise;
}

void AuthenticationCredentialsContainer::Trace(Visitor* visitor) const {
  Supplement<Navigator>::Trace(visitor);
  CredentialsContainer::Trace(visitor);
}

void AuthenticationCredentialsContainer::GetForIdentity(
    ScriptState* script_state,
    ScriptPromiseResolver<IDLNullable<Credential>>* resolver,
    const CredentialRequestOptions& options,
    const IdentityCredentialRequestOptions& identity_options) {
  // Common errors for FedCM and WebIdentityDigitalCredential.
  if (identity_options.providers().size() == 0) {
    resolver->RejectWithTypeError("Need at least one identity provider.");
    return;
  }

  ExecutionContext* context = ExecutionContext::From(script_state);

  // TODO(https://crbug.com/1441075): Ideally the logic should be handled in
  // CredentialManager via Get. However currently it's only for password
  // management and we should refactor the logic to make it generic.

  ContentSecurityPolicy* policy =
      resolver->GetExecutionContext()
          ->GetContentSecurityPolicyForCurrentWorld();
  if (identity_options.providers().size() > 1) {
    if (RuntimeEnabledFeatures::FedCmMultipleIdentityProvidersEnabled(
            context)) {
      UseCounter::Count(resolver->GetExecutionContext(),
                        WebFeature::kFedCmMultipleIdentityProviders);
    } else {
      resolver->RejectWithTypeError(
          "Multiple providers specified but FedCmMultipleIdentityProviders "
          "flag is disabled.");
      return;
    }
  }

  // Log the UseCounter only when the WebID flag is enabled.
  UseCounter::Count(context, WebFeature::kFedCm);
  if (!To<LocalDOMWindow>(resolver->GetExecutionContext())
           ->GetFrame()
           ->IsMainFrame()) {
    UseCounter::Count(resolver->GetExecutionContext(),
                      WebFeature::kFedCmIframe);
  }
  // Track when websites use FedCM with the IDP sign-in status opt-in
  if (RuntimeEnabledFeatures::FedCmIdpSigninStatusEnabled(
          resolver->GetExecutionContext())) {
    UseCounter::Count(resolver->GetExecutionContext(),
                      WebFeature::kFedCmIdpSigninStatusApi);
  }
  int provider_index = 0;
  Vector<mojom::blink::IdentityProviderRequestOptionsPtr>
      identity_provider_ptrs;
  for (const auto& provider : identity_options.providers()) {
    if (provider->hasLoginHint()) {
      UseCounter::Count(resolver->GetExecutionContext(),
                        WebFeature::kFedCmLoginHint);
    }
    if (RuntimeEnabledFeatures::FedCmDomainHintEnabled() &&
        provider->hasDomainHint()) {
      UseCounter::Count(resolver->GetExecutionContext(),
                        WebFeature::kFedCmDomainHint);
    }

    if (!provider->hasConfigURL()) {
      resolver->RejectWithTypeError("Missing the provider's configURL.");
      return;
    }

    mojom::blink::IdentityProviderRequestOptionsPtr identity_provider;
    {
      // It is possible that serializing the custom parameters to JSON fails
      // due to a JS exception, e.g. a custom getter throwing an exception.
      // Catch it here and rethrow so the caller knows what went wrong.
      v8::TryCatch try_catch(script_state->GetIsolate());
      identity_provider =
          blink::mojom::blink::IdentityProviderRequestOptions::From(*provider);
      if (!identity_provider) {
        DCHECK(try_catch.HasCaught())
            << "Converting to mojo should only fail due to JS exception";
        resolver->Reject(try_catch.Exception());
        return;
      }
    }

    if (blink::RuntimeEnabledFeatures::FedCmIdPRegistrationEnabled() &&
        blink::RuntimeEnabledFeatures::FedCmMultipleIdentityProvidersEnabled(
            context) &&
        provider->configURL() == "any") {
      identity_provider_ptrs.push_back(std::move(identity_provider));
      continue;
    }

    // TODO(kenrb): Add some renderer-side validation here, such as
    // validating |provider|, and making sure the calling context is legal.
    // Some of this has not been spec'd yet.

    KURL provider_url(provider->configURL());

    if (!provider->hasClientId()) {
      resolver->RejectWithTypeError("Missing the provider's clientId.");
      return;
    }

    String client_id = provider->clientId();

    ++provider_index;
    if (!provider_url.IsValid() || client_id.empty()) {
      resolver->Reject(MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kInvalidStateError,
          String::Format("Provider %i information is incomplete.",
                         provider_index)));
      return;
    }
    // We disallow redirects (in idp_network_request_manager.cc), so it is
    // enough to check the initial URL here.
    if (IdentityCredential::IsRejectingPromiseDueToCSP(policy, resolver,
                                                       provider_url)) {
      return;
    }

    identity_provider_ptrs.push_back(std::move(identity_provider));
  }

  mojom::blink::RpContext rp_context = mojom::blink::RpContext::kSignIn;
  if (identity_options.hasContext()) {
    UseCounter::Count(resolver->GetExecutionContext(),
                      WebFeature::kFedCmRpContext);
    rp_context =
        mojo::ConvertTo<mojom::blink::RpContext>(identity_options.context());
  }
  base::UmaHistogramEnumeration("Blink.FedCm.RpContext", rp_context);

  CredentialMediationRequirement mediation_requirement;
  if (options.mediation() == "conditional") {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kNotSupportedError,
        "Conditional mediation is not supported for this credential type"));
    return;
  }
  if (options.mediation() == "silent") {
    mediation_requirement = CredentialMediationRequirement::kSilent;
  } else if (options.mediation() == "required") {
    mediation_requirement = CredentialMediationRequirement::kRequired;
  } else {
    DCHECK_EQ("optional", options.mediation());
    mediation_requirement = CredentialMediationRequirement::kOptional;
  }

  if (identity_options.hasMediation()) {
    resolver->GetExecutionContext()->AddConsoleMessage(
        MakeGarbageCollected<ConsoleMessage>(
            mojom::blink::ConsoleMessageSource::kJavaScript,
            mojom::blink::ConsoleMessageLevel::kWarning,
            "The 'mediation' parameter should be used outside of 'identity' in "
            "the FedCM API call."));
  }

  mojom::blink::RpMode rp_mode = mojom::blink::RpMode::kPassive;
  if (blink::RuntimeEnabledFeatures::FedCmButtonModeEnabled(
          resolver->GetExecutionContext())) {
    auto v8_rp_mode = identity_options.mode();
    // TODO(crbug.com/372198646): remove the debugging aid enums after shipping
    // active mode.
    if (v8_rp_mode ==
            blink::V8IdentityCredentialRequestOptionsMode::Enum::kWidget ||
        v8_rp_mode ==
            blink::V8IdentityCredentialRequestOptionsMode::Enum::kButton) {
      resolver->GetExecutionContext()->AddConsoleMessage(
          MakeGarbageCollected<ConsoleMessage>(
              mojom::blink::ConsoleMessageSource::kJavaScript,
              mojom::blink::ConsoleMessageLevel::kWarning,
              "The mode button/widget are renamed to active/passive "
              "respectively and will be deprecated soon."));
    }

    rp_mode = mojo::ConvertTo<mojom::blink::RpMode>(v8_rp_mode);
    if (rp_mode == mojom::blink::RpMode::kActive) {
      if (identity_provider_ptrs.size() > 1u) {
        resolver->Reject(MakeGarbageCollected<DOMException>(
            DOMExceptionCode::kInvalidStateError,
            "Active mode is not currently supported with multiple identity "
            "providers."));
        return;
      }
      if (mediation_requirement == CredentialMediationRequirement::kSilent) {
        resolver->Reject(MakeGarbageCollected<DOMException>(
            DOMExceptionCode::kNotSupportedError,
            "mediation:silent is not supported in active mode"));
        return;
      }
    }
  }

  std::unique_ptr<ScopedAbortState> scoped_abort_state;
  if (auto* signal = options.getSignalOr(nullptr)) {
    // Checked signal->aborted() at the top of get().

    auto callback = WTF::BindOnce(&AbortIdentityCredentialRequest,
                                  WrapPersistent(script_state));

    auto* handle = signal->AddAlgorithm(std::move(callback));
    scoped_abort_state = std::make_unique<ScopedAbortState>(signal, handle);
  }

  Vector<mojom::blink::IdentityProviderGetParametersPtr> idp_get_params;
  mojom::blink::IdentityProviderGetParametersPtr get_params =
      mojom::blink::IdentityProviderGetParameters::New(
          std::move(identity_provider_ptrs), rp_context, rp_mode);
  idp_get_params.push_back(std::move(get_params));

  auto* auth_request =
      CredentialManagerProxy::From(script_state)->FederatedAuthRequest();
  auth_request->RequestToken(
      std::move(idp_get_params), mediation_requirement,
      WTF::BindOnce(&OnRequestToken,
                    std::make_unique<ScopedPromiseResolver>(resolver),
                    std::move(scoped_abort_state), WrapPersistent(&options)));
}

}  // namespace blink

"""


```