Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of the Chromium Blink engine and located in `blink/renderer/modules/credentialmanagement/authentication_credentials_container.cc`.

Here's a breakdown of the code's key functionalities:

1. **Handling Promises:** The code heavily utilizes `ScriptPromiseResolver` to manage the asynchronous nature of credential management operations. Callbacks like `OnSaveCredentialIdForPaymentExtension`, `OnGetAssertionComplete`, and `OnSmsReceive` handle the results from lower-level operations and either resolve or reject the JavaScript promises.

2. **WebAuthn Flow (PublicKeyCredential):**  The code deals with both creating (`IsPaymentExtensionValid` indirectly relates to creation) and getting (`OnGetAssertionComplete`) `PublicKeyCredential` objects. It handles success and failure scenarios, including abort signals. It also interacts with the `Authenticator` through `CredentialManagerProxy`.

3. **Payment Extension:** The `IsPaymentExtensionValid` function validates the "payment" extension during credential creation, enforcing requirements like user verification and platform authenticators. The `OnSaveCredentialIdForPaymentExtension` function handles the result of storing payment credentials.

4. **SMS OTP Flow (OTPCredential):**  The `OnSmsReceive` function handles the result of requesting an SMS OTP. It manages different status codes like success, timeout, aborted, etc., and resolves the promise with an `OTPCredential` or rejects it with a `DOMException`.

5. **Error Handling:** The `AuthenticatorStatusToDOMException` function converts internal `AuthenticatorStatus` codes into corresponding JavaScript `DOMException` objects, providing more meaningful error information to web developers.

6. **Abort Handling:** The code uses `AbortSignal` to allow JavaScript to cancel ongoing credential management operations. `PublicKeyRequestAbortAlgorithm` and `OtpRequestAbortAlgorithm` implement the logic for aborting WebAuthn and OTP requests, respectively.

7. **Security Checks:** Functions like `AssertSecurityRequirementsBeforeResponse` and the checks within the `get` method ensure that credential management operations are performed in secure contexts (e.g., HTTPS).

8. **Feature Flags and Use Counters:**  The code uses `RuntimeEnabledFeatures` to conditionally enable features and `UseCounter` to track usage of different credential management functionalities.

9. **Input Validation:**  Functions like `validatePRFInputs`, `validateCreatePublicKeyCredentialPRFExtension`, and `validateGetPublicKeyCredentialPRFExtension` validate the inputs for the "prf" extension.

**Relationship to JavaScript, HTML, CSS:**

* **JavaScript:**  This C++ code implements the backend logic for JavaScript APIs like `navigator.credentials.create()` and `navigator.credentials.get()`. When a website calls these JavaScript methods, the browser's rendering engine (Blink) eventually calls into this C++ code to perform the underlying operations. The results are then passed back to the JavaScript promise.

* **HTML:**  HTML provides the structure for web pages. The security context of the HTML page (e.g., whether it's served over HTTPS) is crucial for these credential management APIs to function. For example, many of these APIs only work on secure origins.

* **CSS:** CSS is primarily for styling and doesn't directly interact with the core functionality implemented in this code. However, CSS can indirectly influence the user experience around credential management, for example, by styling login forms or error messages.

**Hypothetical Input and Output:**

* **Assume Input:** A website calls `navigator.credentials.get({ publicKey: { challenge: ..., allowCredentials: [...] } })`.
* **Assume Output (Success):** The authenticator successfully provides a signature. The `OnGetAssertionComplete` function receives `AuthenticatorStatus::SUCCESS` and a valid `GetAssertionAuthenticatorResponsePtr`. It creates a `PublicKeyCredential` object and resolves the JavaScript promise with this object.
* **Assume Output (Failure - Aborted):** The user cancels the operation through a browser UI. The `Authenticator` returns an error, or the `AbortSignal` is triggered. The `OnGetAssertionComplete` function receives an error status or detects the aborted signal and rejects the JavaScript promise with a `DOMException`.

**User/Programming Errors:**

* **User Error:** The user might deny permission for the website to access their credentials. This would result in an error status being returned to the `OnGetAssertionComplete` function, which would then reject the promise with a `NotAllowedError` `DOMException`.
* **Programming Error:** A website might call `navigator.credentials.create()` with an invalid relying party ID. This could lead to the `AuthenticatorStatus::BAD_RELYING_PARTY_ID` being returned, and the promise being rejected with a `SecurityError` `DOMException`. Another example is providing an `appid` that isn't a valid URL.

**User Operation Steps to Reach the Code:**

1. The user visits a website that implements WebAuthn or the Credential Management API.
2. The website's JavaScript code calls `navigator.credentials.create()` (e.g., during registration) or `navigator.credentials.get()` (e.g., during login).
3. The browser's JavaScript engine executes this code.
4. The call is routed to the corresponding C++ implementation in the Blink rendering engine, specifically within the `AuthenticationCredentialsContainer` class.
5. The functions within this class, such as `get()` or the callbacks like `OnGetAssertionComplete`, are executed to handle the request.

**Summary of Functionality (Part 2):**

This section of the code primarily focuses on handling the **successful completion and error handling** of asynchronous credential management operations, specifically for **`PublicKeyCredential` (WebAuthn)** and **`OTPCredential` (SMS OTP)**. It defines callback functions (`OnGetAssertionComplete`, `OnSmsReceive`) that are invoked when the underlying authenticator or SMS retrieval process finishes. These callbacks are responsible for:

* **Checking for abort signals:** Determining if the operation was canceled by the user or the website.
* **Converting internal status codes to JavaScript exceptions:**  Using `AuthenticatorStatusToDOMException` to provide meaningful error information to the web page.
* **Constructing and resolving JavaScript promises:**  Creating `PublicKeyCredential` or `OTPCredential` objects with the received data and resolving the promises associated with the `navigator.credentials.get()` or `navigator.credentials.create()` calls.
* **Handling specific success scenarios:**  For example, in `OnGetAssertionComplete`, it creates an `AuthenticatorAssertionResponse` and a `PublicKeyCredential` upon successful authentication.
* **Performing security checks:**  Ensuring the operations are performed in secure contexts.
* **Validating inputs for extensions:**  Specifically, it includes validation logic for the "prf" (Proof of Possession) extension.

这是 `blink/renderer/modules/credentialmanagement/authentication_credentials_container.cc` 源代码文件的第二部分，主要功能是处理 **Credential Management API 中异步操作的完成和错误处理**，特别是针对 `PublicKeyCredential` (WebAuthn) 和 `OTPCredential` (短信验证码)。

**功能归纳:**

1. **`OnGetAssertionComplete` 函数:**
   - **功能:** 处理 `navigator.credentials.get()` 请求 `PublicKeyCredential` 时的异步操作完成。
   - **成功情况:** 如果认证器操作成功 (`status == AuthenticatorStatus::SUCCESS`)，则会创建一个 `AuthenticatorAssertionResponse` 和 `PublicKeyCredential` 对象，并将结果传递给 JavaScript 的 Promise。
   - **失败情况:** 如果认证器操作失败，则会检查是否有中止信号，如果有且被触发，则使用中止原因拒绝 Promise；否则，将认证器状态转换为对应的 `DOMException` 并拒绝 Promise。
   - **与 JavaScript 关系:** 当 JavaScript 调用 `navigator.credentials.get()` 并请求 `publicKey` 时，浏览器会调用底层的认证器 API。该函数是认证器操作完成后的回调，用于将结果返回给 JavaScript。
   - **假设输入与输出:**
     - **假设输入:** 认证器成功返回了 `credential` 数据 (包含签名、认证器数据等)。
     - **输出:**  JavaScript 的 Promise 会 resolve 一个 `PublicKeyCredential` 对象。
     - **假设输入:** 认证器返回了错误状态 `AuthenticatorStatus::NOT_ALLOWED_ERROR`。
     - **输出:** JavaScript 的 Promise 会 reject 一个 `NotAllowedError` 类型的 `DOMException`。

2. **`OnSmsReceive` 函数:**
   - **功能:** 处理 `navigator.credentials.get()` 请求 `OTPCredential` (通过短信接收验证码) 时的异步操作完成。
   - **成功情况:** 如果短信接收成功 (`status == mojom::blink::SmsStatus::kOK`, 虽然代码片段中未直接展示 kOK，但逻辑上存在)，则会创建一个 `OTPCredential` 对象并将验证码传递给 JavaScript 的 Promise。
   - **失败情况:** 处理各种失败状态，例如请求未处理、中止、取消、超时、后端不可用等，并根据状态创建相应的 `DOMException` 拒绝 Promise。
   - **与 JavaScript 关系:** 当 JavaScript 调用 `navigator.credentials.get()` 并请求 `otp` 时，浏览器会尝试接收短信验证码。该函数是接收短信操作完成后的回调，用于将结果返回给 JavaScript。
   - **假设输入与输出:**
     - **假设输入:** 短信成功接收，`otp` 包含接收到的验证码字符串。
     - **输出:** JavaScript 的 Promise 会 resolve 一个 `OTPCredential` 对象，其中包含 `otp` 字符串。
     - **假设输入:** 短信接收超时，`status == mojom::blink::SmsStatus::kTimeout`。
     - **输出:** JavaScript 的 Promise 会 reject 一个 `InvalidStateError` 类型的 `DOMException`。

3. **`IsPaymentExtensionValid` 函数:**
   - **功能:** 验证创建 `PublicKeyCredential` 时 "payment" 扩展的有效性。
   - **与 JavaScript, HTML 关系:** 当 JavaScript 调用 `navigator.credentials.create()` 并包含 "payment" 扩展时，此函数会被调用以确保满足特定的安全和功能要求。例如，它会检查是否在安全上下文 (HTTPS) 中，是否需要用户激活，以及认证器的选择是否符合支付扩展的要求 (例如需要用户验证的平台认证器和常驻密钥)。
   - **假设输入与输出:**
     - **假设输入:**  `CredentialCreationOptions` 包含 "payment" 扩展，但 `authenticatorSelection` 中 `userVerification` 未设置为 "required"。
     - **输出:**  该函数会调用 `resolver->Reject` 并返回 `false`，导致 JavaScript 的 Promise reject 一个 `NotSupportedError` 类型的 `DOMException`，提示用户验证是必需的。

4. **`validatePRFInputs`, `validateCreatePublicKeyCredentialPRFExtension`, `validateGetPublicKeyCredentialPRFExtension` 函数:**
   - **功能:** 验证 "prf" (Proof of Possession Result) 扩展的输入参数。
   - **与 JavaScript 关系:** 当 JavaScript 调用 `navigator.credentials.create()` 或 `navigator.credentials.get()` 并包含 "prf" 扩展时，这些函数会被调用来验证扩展参数的有效性，防止恶意或错误的输入。
   - **假设输入与输出:**
     - **假设输入:**  `AuthenticationExtensionsPRFInputs` 中的 `eval` 字段包含超过最大允许大小的数据。
     - **输出:**  `validatePRFInputs` 返回一个错误字符串，最终导致 JavaScript 的 Promise reject 一个 `SyntaxError` 类型的 `DOMException`。

5. **错误处理 (`AuthenticatorStatusToDOMException` 函数):**
   - **功能:** 将底层的 `AuthenticatorStatus` 枚举值转换为对应的 JavaScript `DOMException` 对象。
   - **与 JavaScript 关系:** 当底层的认证器操作返回错误状态时，此函数用于创建可以传递给 JavaScript Promise 的标准错误对象，使得开发者能够获取更详细的错误信息。
   - **假设输入与输出:**
     - **假设输入:** `AuthenticatorStatus::NOT_ALLOWED_ERROR`。
     - **输出:**  返回一个 `NotAllowedError` 类型的 `DOMException` 对象。

**用户或编程常见的使用错误举例:**

- **用户错误:** 用户在浏览器提示时拒绝了 WebAuthn 或短信验证码的请求。这会导致 `OnGetAssertionComplete` 或 `OnSmsReceive` 中收到相应的错误状态，最终 JavaScript 的 Promise 会 reject 一个 `NotAllowedError` 或 `AbortError`。
- **编程错误:**
    - 在调用 `navigator.credentials.create()` 时，为 "payment" 扩展提供的参数不符合要求，例如未设置 `userVerification: "required"`，会导致 `IsPaymentExtensionValid` 返回 `false` 并拒绝 Promise，提示 "User verification is required for 'payment' extension."。
    - 在使用 "prf" 扩展时，提供了过大的输入数据，会导致 `validatePRFInputs` 校验失败，Promise 会 reject 一个 `SyntaxError`。
    - 在非 HTTPS 页面调用 `navigator.credentials.get()` 或 `navigator.credentials.create()`，会导致安全检查失败，Promise 会 reject 一个 `SecurityError` (尽管此部分代码片段未直接展示此安全检查，但它是 Credential Management API 的基本要求)。

**用户操作如何一步步的到达这里 (调试线索):**

1. 用户访问一个需要身份验证的网站。
2. 网站的 JavaScript 代码调用 `navigator.credentials.get()`，可能请求 `publicKey` (WebAuthn) 或 `otp` (短信验证码)。
3. 浏览器接收到 JavaScript 的请求，并将其传递给 Blink 渲染引擎的 Credential Management 模块。
4. 如果请求的是 `publicKey`，相关的逻辑会调用底层的认证器 API，例如通过 USB、NFC 或其他方式与硬件安全密钥交互。认证器操作完成后，会调用 `OnGetAssertionComplete`。
5. 如果请求的是 `otp`，浏览器会尝试接收来自服务器的短信验证码。接收操作完成后，会调用 `OnSmsReceive`。
6. 在 `OnGetAssertionComplete` 或 `OnSmsReceive` 函数中，会根据操作的结果（成功或失败）来 resolve 或 reject 相应的 JavaScript Promise。

总而言之，这部分代码是 Credential Management API 实现的关键部分，负责处理异步操作的结果，并将底层的操作状态和数据转换成 JavaScript 可以理解的 Promise 结果和错误信息。它确保了 API 的正确性和安全性，并为开发者提供了标准的错误处理机制。

### 提示词
```
这是目录为blink/renderer/modules/credentialmanagement/authentication_credentials_container.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
scoped_abort_state ? scoped_abort_state->Signal() : nullptr;
    if (signal && signal->aborted()) {
      auto* script_state = resolver->GetScriptState();
      ScriptState::Scope script_state_scope(script_state);
      resolver->Reject(signal->reason(script_state));
    } else {
      resolver->Reject(
          AuthenticatorStatusToDOMException(status, dom_exception_details));
    }
    return;
  }

  Vector<uint8_t> credential_id = credential->info->raw_id;
  auto* payment_credential_remote =
      CredentialManagerProxy::From(resolver->GetScriptState())
          ->PaymentCredential();
  payment_credential_remote->StorePaymentCredential(
      std::move(credential_id), rp_id_for_payment_extension,
      std::move(user_id_for_payment_extension),
      WTF::BindOnce(&OnSaveCredentialIdForPaymentExtension,
                    std::make_unique<ScopedPromiseResolver>(resolver),
                    std::move(scoped_abort_state), std::move(credential)));
}

void OnGetAssertionComplete(
    std::unique_ptr<ScopedPromiseResolver> scoped_resolver,
    std::unique_ptr<ScopedAbortState> scoped_abort_state,
    bool is_conditional_ui_request,
    AuthenticatorStatus status,
    GetAssertionAuthenticatorResponsePtr credential,
    WebAuthnDOMExceptionDetailsPtr dom_exception_details) {
  auto* resolver =
      scoped_resolver->Release()->DowncastTo<IDLNullable<Credential>>();
  const auto required_origin_type = RequiredOriginType::kSecure;

  AssertSecurityRequirementsBeforeResponse(resolver, required_origin_type);
  if (status == AuthenticatorStatus::SUCCESS) {
    DCHECK(credential);
    DCHECK(!credential->signature.empty());
    DCHECK(!credential->info->authenticator_data.empty());
    UseCounter::Count(
        resolver->GetExecutionContext(),
        WebFeature::kCredentialManagerGetPublicKeyCredentialSuccess);

    if (is_conditional_ui_request) {
      UseCounter::Count(resolver->GetExecutionContext(),
                        WebFeature::kWebAuthnConditionalUiGetSuccess);
    }

    auto* authenticator_response =
        MakeGarbageCollected<AuthenticatorAssertionResponse>(
            std::move(credential->info->client_data_json),
            std::move(credential->info->authenticator_data),
            std::move(credential->signature), credential->user_handle);

    AuthenticationExtensionsClientOutputs* extension_outputs =
        ConvertTo<AuthenticationExtensionsClientOutputs*>(
            credential->extensions);
#if BUILDFLAG(IS_ANDROID)
    if (credential->extensions->echo_user_verification_methods) {
      UseCounter::Count(resolver->GetExecutionContext(),
                        WebFeature::kCredentialManagerGetSuccessWithUVM);
    }
#endif
    resolver->Resolve(MakeGarbageCollected<PublicKeyCredential>(
        credential->info->id,
        VectorToDOMArrayBuffer(std::move(credential->info->raw_id)),
        authenticator_response, credential->authenticator_attachment,
        extension_outputs));
    return;
  }
  DCHECK(!credential);
  AbortSignal* signal =
      scoped_abort_state ? scoped_abort_state->Signal() : nullptr;
  if (signal && signal->aborted()) {
    auto* script_state = resolver->GetScriptState();
    ScriptState::Scope script_state_scope(script_state);
    resolver->Reject(signal->reason(script_state));
  } else {
    resolver->Reject(
        AuthenticatorStatusToDOMException(status, dom_exception_details));
  }
}

void OnSmsReceive(ScriptPromiseResolver<IDLNullable<Credential>>* resolver,
                  std::unique_ptr<ScopedAbortState> scoped_abort_state,
                  base::TimeTicks start_time,
                  mojom::blink::SmsStatus status,
                  const String& otp) {
  AssertSecurityRequirementsBeforeResponse(
      resolver, resolver->GetExecutionContext()->IsFeatureEnabled(
                    mojom::blink::PermissionsPolicyFeature::kOTPCredentials)
                    ? RequiredOriginType::
                          kSecureAndPermittedByWebOTPAssertionPermissionsPolicy
                    : RequiredOriginType::kSecureAndSameWithAncestors);
  if (status == mojom::blink::SmsStatus::kUnhandledRequest) {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kInvalidStateError,
        "OTP retrieval request not handled."));
    return;
  }
  if (status == mojom::blink::SmsStatus::kAborted) {
    AbortSignal* signal =
        scoped_abort_state ? scoped_abort_state->Signal() : nullptr;
    if (signal && signal->aborted()) {
      auto* script_state = resolver->GetScriptState();
      ScriptState::Scope script_state_scope(script_state);
      resolver->Reject(signal->reason(script_state));
    } else {
      resolver->Reject(MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kAbortError, "OTP retrieval was aborted."));
    }
    return;
  }
  if (status == mojom::blink::SmsStatus::kCancelled) {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kAbortError, "OTP retrieval was cancelled."));
    return;
  }
  if (status == mojom::blink::SmsStatus::kTimeout) {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kInvalidStateError, "OTP retrieval timed out."));
    return;
  }
  if (status == mojom::blink::SmsStatus::kBackendNotAvailable) {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kInvalidStateError, "OTP backend unavailable."));
    return;
  }
  resolver->Resolve(MakeGarbageCollected<OTPCredential>(otp));
}

// Validates the "payment" extension for public key credential creation. The
// function rejects the promise before returning in this case.
bool IsPaymentExtensionValid(const CredentialCreationOptions* options,
                             ScriptPromiseResolverBase* resolver) {
  const auto* payment = options->publicKey()->extensions()->payment();
  if (!payment->hasIsPayment() || !payment->isPayment()) {
    return true;
  }

  // TODO(crbug.com/1512245): Remove this check in favour of the validation in
  // |AuthenticationCredentialsContainer::create|, which throws a
  // NotAllowedError rather than a SecurityError like the SPC spec currently
  // requires.
  if (!IsSameSecurityOriginWithAncestors(
          To<LocalDOMWindow>(resolver->GetExecutionContext())->GetFrame())) {
    bool has_user_activation = LocalFrame::ConsumeTransientUserActivation(
        To<LocalDOMWindow>(resolver->GetExecutionContext())->GetFrame(),
        UserActivationUpdateSource::kRenderer);
    if (!has_user_activation) {
      resolver->Reject(MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kSecurityError,
          "A user activation is required to create a credential in a "
          "cross-origin iframe."));
      return false;
    }
  }

  const auto* context = resolver->GetExecutionContext();
  DCHECK(RuntimeEnabledFeatures::SecurePaymentConfirmationEnabled(context));

  if (RuntimeEnabledFeatures::SecurePaymentConfirmationDebugEnabled()) {
    return true;
  }

  if (!options->publicKey()->hasAuthenticatorSelection()) {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kNotSupportedError,
        "A user verifying platform authenticator with resident key support is "
        "required for 'payment' extension."));
    return false;
  }

  const auto* authenticator = options->publicKey()->authenticatorSelection();
  if (!authenticator->hasUserVerification() ||
      authenticator->userVerification() != "required") {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kNotSupportedError,
        "User verification is required for 'payment' extension."));
    return false;
  }

  if ((!authenticator->hasResidentKey() &&
       !authenticator->hasRequireResidentKey()) ||
      (authenticator->hasResidentKey() &&
       authenticator->residentKey() == "discouraged") ||
      (!authenticator->hasResidentKey() &&
       authenticator->hasRequireResidentKey() &&
       !authenticator->requireResidentKey())) {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kNotSupportedError,
        "A resident key must be 'preferred' or 'required' for 'payment' "
        "extension."));
    return false;
  }

  if (!authenticator->hasAuthenticatorAttachment() ||
      authenticator->authenticatorAttachment() != "platform") {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kNotSupportedError,
        "A platform authenticator is required for 'payment' extension."));
    return false;
  }

  return true;
}

const char* validatePRFInputs(
    const blink::AuthenticationExtensionsPRFValues& values) {
  constexpr size_t kMaxInputSize = 256;
  if (DOMArrayPiece(values.first()).ByteLength() > kMaxInputSize ||
      (values.hasSecond() &&
       DOMArrayPiece(values.second()).ByteLength() > kMaxInputSize)) {
    return "'prf' extension contains excessively large input";
  }
  return nullptr;
}

const char* validateCreatePublicKeyCredentialPRFExtension(
    const AuthenticationExtensionsPRFInputs& prf) {
  if (prf.hasEval()) {
    const char* error = validatePRFInputs(*prf.eval());
    if (error != nullptr) {
      return error;
    }
  }

  if (prf.hasEvalByCredential()) {
    return "The 'evalByCredential' field cannot be set when creating a "
           "credential.";
  }

  return nullptr;
}

const char* validateGetPublicKeyCredentialPRFExtension(
    const AuthenticationExtensionsPRFInputs& prf,
    const HeapVector<Member<PublicKeyCredentialDescriptor>>&
        allow_credentials) {
  std::vector<base::span<const uint8_t>> cred_ids;
  cred_ids.reserve(allow_credentials.size());
  for (const auto cred : allow_credentials) {
    DOMArrayPiece piece(cred->id());
    cred_ids.emplace_back(piece.Bytes(), piece.ByteLength());
  }
  const auto compare = [](const base::span<const uint8_t>& a,
                          const base::span<const uint8_t>& b) -> bool {
    return std::lexicographical_compare(a.begin(), a.end(), b.begin(), b.end());
  };
  std::sort(cred_ids.begin(), cred_ids.end(), compare);

  if (prf.hasEval()) {
    const char* error = validatePRFInputs(*prf.eval());
    if (error != nullptr) {
      return error;
    }
  }

  if (prf.hasEvalByCredential()) {
    for (const auto& pair : prf.evalByCredential()) {
      Vector<char> cred_id;
      if (!pair.first.Is8Bit() ||
          !WTF::Base64UnpaddedURLDecode(pair.first, cred_id)) {
        return "'prf' extension contains invalid base64url data in "
               "'evalByCredential'";
      }
      if (cred_id.empty()) {
        return "'prf' extension contains an empty credential ID in "
               "'evalByCredential'";
      }
      if (!std::binary_search(cred_ids.begin(), cred_ids.end(),
                              base::as_bytes(base::make_span(cred_id)),
                              compare)) {
        return "'prf' extension contains 'evalByCredential' key that doesn't "
               "match any in allowedCredentials";
      }
      const char* error = validatePRFInputs(*pair.second);
      if (error != nullptr) {
        return error;
      }
    }
  }
  return nullptr;
}

}  // namespace

const char AuthenticationCredentialsContainer::kSupplementName[] =
    "AuthenticationCredentialsContainer";

DOMException* AuthenticatorStatusToDOMException(
    AuthenticatorStatus status,
    const WebAuthnDOMExceptionDetailsPtr& dom_exception_details) {
  DCHECK_EQ(status != AuthenticatorStatus::ERROR_WITH_DOM_EXCEPTION_DETAILS,
            dom_exception_details.is_null());
  switch (status) {
    case AuthenticatorStatus::SUCCESS:
      NOTREACHED();
    case AuthenticatorStatus::PENDING_REQUEST:
      return MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kOperationError, "A request is already pending.");
    case AuthenticatorStatus::NOT_ALLOWED_ERROR:
      return MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kNotAllowedError,
          "The operation either timed out or was not allowed. See: "
          "https://www.w3.org/TR/webauthn-2/"
          "#sctn-privacy-considerations-client.");
    case AuthenticatorStatus::INVALID_DOMAIN:
      return MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kSecurityError, "This is an invalid domain.");
    case AuthenticatorStatus::CREDENTIAL_EXCLUDED:
      return MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kInvalidStateError,
          "The user attempted to register an authenticator that contains one "
          "of the credentials already registered with the relying party.");
    case AuthenticatorStatus::NOT_IMPLEMENTED:
      return MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kNotSupportedError, "Not implemented");
    case AuthenticatorStatus::NOT_FOCUSED:
      return MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kNotAllowedError,
          "The operation is not allowed at this time "
          "because the page does not have focus.");
    case AuthenticatorStatus::RESIDENT_CREDENTIALS_UNSUPPORTED:
      return MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kNotSupportedError,
          "Resident credentials or empty "
          "'allowCredentials' lists are not supported "
          "at this time.");
    case AuthenticatorStatus::USER_VERIFICATION_UNSUPPORTED:
      return MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kNotSupportedError,
          "The specified `userVerification` "
          "requirement cannot be fulfilled by "
          "this device unless the device is secured "
          "with a screen lock.");
    case AuthenticatorStatus::ALGORITHM_UNSUPPORTED:
      return MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kNotSupportedError,
          "None of the algorithms specified in "
          "`pubKeyCredParams` are supported by "
          "this device.");
    case AuthenticatorStatus::EMPTY_ALLOW_CREDENTIALS:
      return MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kNotSupportedError,
          "Use of an empty `allowCredentials` list is "
          "not supported on this device.");
    case AuthenticatorStatus::ANDROID_NOT_SUPPORTED_ERROR:
      return MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kNotSupportedError,
          "Either the device has received unexpected "
          "request parameters, or the device "
          "cannot support this request.");
    case AuthenticatorStatus::PROTECTION_POLICY_INCONSISTENT:
      return MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kNotSupportedError,
          "Requested protection policy is inconsistent or incongruent with "
          "other requested parameters.");
    case AuthenticatorStatus::ABORT_ERROR:
      return MakeGarbageCollected<DOMException>(DOMExceptionCode::kAbortError,
                                                "Request has been aborted.");
    case AuthenticatorStatus::OPAQUE_DOMAIN:
      return MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kNotAllowedError,
          "The current origin is an opaque origin and hence not allowed to "
          "access 'PublicKeyCredential' objects.");
    case AuthenticatorStatus::INVALID_PROTOCOL:
      return MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kSecurityError,
          "Public-key credentials are only available to HTTPS origins with "
          "valid certificates, HTTP origins that fall under 'localhost', or "
          "pages served from an extension. See "
          "https://chromium.googlesource.com/chromium/src/+/main/content/"
          "browser/webauth/origins.md for details");
    case AuthenticatorStatus::BAD_RELYING_PARTY_ID:
      return MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kSecurityError,
          "The relying party ID is not a registrable domain suffix of, nor "
          "equal to the current domain.");
    case AuthenticatorStatus::BAD_RELYING_PARTY_ID_ATTEMPTED_FETCH:
      return MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kSecurityError,
          "The relying party ID is not a registrable domain suffix of, nor "
          "equal to the current domain. Subsequently, an attempt to fetch the "
          ".well-known/webauthn resource of the claimed RP ID failed.");
    case AuthenticatorStatus::BAD_RELYING_PARTY_ID_WRONG_CONTENT_TYPE:
      return MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kSecurityError,
          "The relying party ID is not a registrable domain suffix of, nor "
          "equal to the current domain. Subsequently, the "
          ".well-known/webauthn resource of the claimed RP ID had the "
          "wrong content-type. (It should be application/json.)");
    case AuthenticatorStatus::BAD_RELYING_PARTY_ID_JSON_PARSE_ERROR:
      return MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kSecurityError,
          "The relying party ID is not a registrable domain suffix of, nor "
          "equal to the current domain. Subsequently, fetching the "
          ".well-known/webauthn resource of the claimed RP ID resulted "
          "in a JSON parse error.");
    case AuthenticatorStatus::BAD_RELYING_PARTY_ID_NO_JSON_MATCH:
      return MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kSecurityError,
          "The relying party ID is not a registrable domain suffix of, nor "
          "equal to the current domain. Subsequently, fetching the "
          ".well-known/webauthn resource of the claimed RP ID was "
          "successful, but no listed origin matched the caller.");
    case AuthenticatorStatus::BAD_RELYING_PARTY_ID_NO_JSON_MATCH_HIT_LIMITS:
      return MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kSecurityError,
          "The relying party ID is not a registrable domain suffix of, nor "
          "equal to the current domain. Subsequently, fetching the "
          ".well-known/webauthn resource of the claimed RP ID was "
          "successful, but no listed origin matched the caller. Note that a "
          "match may have been found but the limit on the number of eTLD+1 "
          "labels was reached, causing some entries to be ignored.");
    case AuthenticatorStatus::CANNOT_READ_AND_WRITE_LARGE_BLOB:
      return MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kNotSupportedError,
          "Only one of the 'largeBlob' extension's 'read' and 'write' "
          "parameters is allowed at a time");
    case AuthenticatorStatus::INVALID_ALLOW_CREDENTIALS_FOR_LARGE_BLOB:
      return MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kNotSupportedError,
          "The 'largeBlob' extension's 'write' parameter can only be used "
          "with a single credential present on 'allowCredentials'");
    case AuthenticatorStatus::
        FAILED_TO_SAVE_CREDENTIAL_ID_FOR_PAYMENT_EXTENSION:
      return MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kNotReadableError,
          "Failed to save the credential identifier for the 'payment' "
          "extension.");
    case AuthenticatorStatus::REMOTE_DESKTOP_CLIENT_OVERRIDE_NOT_AUTHORIZED:
      return MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kNotAllowedError,
          "This origin is not permitted to use the "
          "'remoteDesktopClientOverride' extension.");
    case AuthenticatorStatus::CERTIFICATE_ERROR:
      return MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kNotAllowedError,
          "WebAuthn is not supported on sites with TLS certificate errors.");
    case AuthenticatorStatus::ERROR_WITH_DOM_EXCEPTION_DETAILS:
      return DOMException::Create(
          /*message=*/dom_exception_details->message,
          /*name=*/dom_exception_details->name);
    case AuthenticatorStatus::DEVICE_PUBLIC_KEY_ATTESTATION_REJECTED:
      return MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kNotAllowedError,
          "The authenticator responded with an invalid message");
    case AuthenticatorStatus::UNKNOWN_ERROR:
      return MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kNotReadableError,
          "An unknown error occurred while talking "
          "to the credential manager.");
  }
  return nullptr;
}

class AuthenticationCredentialsContainer::OtpRequestAbortAlgorithm final
    : public AbortSignal::Algorithm {
 public:
  explicit OtpRequestAbortAlgorithm(ScriptState* script_state)
      : script_state_(script_state) {}
  ~OtpRequestAbortAlgorithm() override = default;

  // Abort an ongoing OtpCredential get() operation.
  void Run() override {
    if (!script_state_->ContextIsValid()) {
      return;
    }

    auto* webotp_service =
        CredentialManagerProxy::From(script_state_)->WebOTPService();
    webotp_service->Abort();
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(script_state_);
    Algorithm::Trace(visitor);
  }

 private:
  Member<ScriptState> script_state_;
};

class AuthenticationCredentialsContainer::PublicKeyRequestAbortAlgorithm final
    : public AbortSignal::Algorithm {
 public:
  explicit PublicKeyRequestAbortAlgorithm(ScriptState* script_state)
      : script_state_(script_state) {}
  ~PublicKeyRequestAbortAlgorithm() override = default;

  // Abort an ongoing PublicKeyCredential create() or get() operation.
  void Run() override {
    if (!script_state_->ContextIsValid()) {
      return;
    }

    auto* authenticator =
        CredentialManagerProxy::From(script_state_)->Authenticator();
    authenticator->Cancel();
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(script_state_);
    Algorithm::Trace(visitor);
  }

 private:
  Member<ScriptState> script_state_;
};

CredentialsContainer* AuthenticationCredentialsContainer::credentials(
    Navigator& navigator) {
  AuthenticationCredentialsContainer* credentials =
      Supplement<Navigator>::From<AuthenticationCredentialsContainer>(
          navigator);
  if (!credentials) {
    credentials =
        MakeGarbageCollected<AuthenticationCredentialsContainer>(navigator);
    ProvideTo(navigator, credentials);
  }
  return credentials;
}

AuthenticationCredentialsContainer::AuthenticationCredentialsContainer(
    Navigator& navigator)
    : Supplement<Navigator>(navigator) {}

ScriptPromise<IDLNullable<Credential>> AuthenticationCredentialsContainer::get(
    ScriptState* script_state,
    const CredentialRequestOptions* options,
    ExceptionState& exception_state) {
  if (!script_state->ContextIsValid()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Context is detached");
    return ScriptPromise<IDLNullable<Credential>>();
  }

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLNullable<Credential>>>(
          script_state, exception_state.GetContext());
  auto promise = resolver->Promise();
  ExecutionContext* context = ExecutionContext::From(script_state);

  if (options->hasSignal() && options->signal()->aborted()) {
    resolver->Reject(options->signal()->reason(script_state));
    return promise;
  }

  if (IsDigitalIdentityCredentialType(*options) &&
      RuntimeEnabledFeatures::WebIdentityDigitalCredentialsEnabled(
          resolver->GetExecutionContext())) {
    DiscoverDigitalIdentityCredentialFromExternalSource(resolver, *options,
                                                        exception_state);
    return promise;
  }

  auto required_origin_type = RequiredOriginType::kSecureAndSameWithAncestors;
  // hasPublicKey() implies that this is a WebAuthn request.
  if (options->hasPublicKey()) {
    required_origin_type = RequiredOriginType::
        kSecureAndPermittedByWebAuthGetAssertionPermissionsPolicy;
  } else if (options->hasOtp() &&
             RuntimeEnabledFeatures::WebOTPAssertionFeaturePolicyEnabled()) {
    required_origin_type = RequiredOriginType::
        kSecureAndPermittedByWebOTPAssertionPermissionsPolicy;
  } else if (options->hasIdentity() && options->identity()->hasProviders() &&
             options->identity()->providers().size() == 1) {
    required_origin_type =
        RequiredOriginType::kSecureAndPermittedByFederatedPermissionsPolicy;
  }
  if (!CheckSecurityRequirementsBeforeRequest(resolver, required_origin_type)) {
    return promise;
  }

  uint32_t requested_credential_types =
      static_cast<int>(mojom::blink::CredentialTypeFlags::kNone);

  // TODO(cbiesinger): Consider removing the hasIdentity() check after FedCM
  // ships. Before then, it is useful for RPs to pass both identity and
  // federated while transitioning from the older to the new API.
  if (options->hasFederated() && options->federated()->hasProviders() &&
      options->federated()->providers().size() > 0 && !options->hasIdentity()) {
    UseCounter::Count(
        context, WebFeature::kCredentialManagerGetLegacyFederatedCredential);
    requested_credential_types |=
        static_cast<int>(mojom::blink::CredentialTypeFlags::kFederated);
  }

  if (options->hasPublicKey()) {
    requested_credential_types |=
        static_cast<int>(mojom::blink::CredentialTypeFlags::kPublicKey);
  }

  if (options->hasPassword() && options->password()) {
    UseCounter::Count(context,
                      WebFeature::kCredentialManagerGetPasswordCredential);
    requested_credential_types |=
        static_cast<int>(mojom::blink::CredentialTypeFlags::kPassword);
  }

  bool ambient_request_enabled = false;
  if (RuntimeEnabledFeatures::WebAuthenticationAmbientEnabled() &&
      options->hasPublicKey() && options->hasPassword() &&
      options->password() && options->mediation() == "conditional") {
    // TODO(crbug.com/358119268): For prototyping we allow this for all
    // conditionally-mediated requests that contain both credential types. This
    // will change.
    ambient_request_enabled = true;

    // Unsupported ambient credential types:
    if (options->hasOtp() || options->hasIdentity() ||
        (options->publicKey()->hasExtensions() &&
         options->publicKey()->extensions()->hasPayment()) ||
        options->hasFederated()) {
      resolver->Reject(MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kNotSupportedError,
          "Unsupported combination of credential types requested."));
      return promise;
    }
  }

  if (options->hasPublicKey()) {
    UseCounter::Count(context,
                      WebFeature::kCredentialManagerGetPublicKeyCredential);

#if BUILDFLAG(IS_ANDROID)
    if (options->publicKey()->hasExtensions() &&
        options->publicKey()->extensions()->hasUvm()) {
      UseCounter::Count(context, WebFeature::kCredentialManagerGetWithUVM);
    }
#endif

    if (!IsArrayBufferOrViewBelowSizeLimit(options->publicKey()->challenge())) {
      resolver->Reject(DOMException::Create(
          "The `challenge` attribute exceeds the maximum allowed size.",
          "RangeError"));
      return promise;
    }

    if (!IsCredentialDescriptorListBelowSizeLimit(
            options->publicKey()->allowCredentials())) {
      resolver->Reject(
          DOMException::Create("The `allowCredentials` attribute exceeds the "
                               "maximum allowed size (64).",
                               "RangeError"));
      return promise;
    }

    if (options->publicKey()->hasExtensions()) {
      if (options->publicKey()->extensions()->hasAppid()) {
        const auto& appid = options->publicKey()->extensions()->appid();
        if (!appid.empty()) {
          KURL appid_url(appid);
          if (!appid_url.IsValid()) {
            resolver->Reject(MakeGarbageCollected<DOMException>(
                DOMExceptionCode::kSyntaxError,
                "The `appid` extension value is neither "
                "empty/null nor a valid URL"));
            return promise;
          }
        }
      }
      if (options->publicKey()->extensions()->credProps()) {
        resolver->Reject(MakeGarbageCollected<DOMException>(
            DOMExceptionCode::kNotSupportedError,
            "The 'credProps' extension is only valid when creating "
            "a credential"));
        return promise;
      }
      if (options->publicKey()->extensions()->hasLargeBlob()) {
        DCHECK(RuntimeEnabledFeatures::
                   WebAuthenticationLargeBlobExtensionEnabled());
        if (options->publicKey()->extensions()->largeBlob()->hasSupport()) {
          resolver->Reject(MakeGarbageCollected<DOMException>(
              DOMExceptionCode::kNotSupportedError,
              "The 'largeBlob' extension's 'support' parameter is only valid "
              "when creating a credential"));
          return promise;
        }
        if (options->publicKey()->extensions()->largeBlob()->hasWrite()) {
          const size_t write_size =
              DOMArrayPiece(
                  options->publicKey()->extensions()->largeBlob()->write())
                  .ByteLength();
          if (write_size > kMaxLargeBlobSize) {
            resolver->Reject(MakeGarbageCollected<DOMException>(
                DOMExceptionCode::kNotSupportedError,
                "The 'largeBlob' extension's 'write' parameter exceeds the "
                "maximum allowed size (2kb)"));
            return promise;
          }
        }
      }
      if (options->publicKey()->extensions()->hasPrf()) {
        if (options->publicKey()->extensions()->prf()->hasEvalByCredential() &&
            options->publicKey()->allowCredentials().empty()) {
          resolver->Reject(MakeGarbageCollected<DOMException>(
              DOMExceptionCode::kNotSupportedError,
              "'prf' extension has 'evalByCredential' with an empty allow "
              "list"));
          return promise;
        }

        const char* error = validateGetPublicKeyCredentialPRFExtension(
            *options->publicKey()->extensions()->prf(),
            options->publicKey()->allowCredentials());
        if (error != nullptr) {
          resolver->Reject(MakeGarbageCollected<DOMException>(
              DOMExceptionCode::kSyntaxError, error));
          return promise;
        }

        // Prohibiting uv=preferred is omitted. See
        // https://github.com/w3c/webauthn/pull/1836.
      }
      if (RuntimeEnabledFeatures::SecurePaymentConfirmationEnabled(context) &&
          options->publicKey()->extensions()->hasPayment()) {
        resolver->Reject(MakeGarbageCollected<DOMException>(
            DOMExceptionCode::kNotAllowedError,
            "The 'payment' extension is only valid when creating a "
            "credential"));
        return promise;
      }
    }

    if (options->publicKey()->hasUserVerification() &&
        !mojo::ConvertTo<
            std::optional<mojom::blink::UserVerificationRequirement>>(
            options->publicKey()->userVerification())) {
      resolver->GetExecutionContext()->AddConsoleMessage(
          MakeGarbageCollected<ConsoleMessage>(
              mojom::blink::ConsoleMessageSource::kJavaScript,
              mojom::blink::ConsoleMessageLevel::kWarning,
              "Ignoring unknown publicKey.userVerification value"));
    }

    std::unique_ptr<ScopedAbortState> scoped_abort_state = nullptr;
    if (auto* signal = options->getSignalOr(nullptr)) {
      auto* handle = signal->AddAlgorithm(
          MakeGarbageCollected<PublicKeyRequestAbortAlgorithm>(script_state));
      scoped_abort_state = std::make_unique<ScopedAbortState>(signal, handle);
    }

    bool is_conditional_ui_request = options->mediation() == "conditional";

    if (is_conditional_ui_request) {
      UseCounter::Count(context, WebFeature::kWebAuthnConditionalUiGet);
      CredentialMetrics::From(script_state).RecordWebAuthnConditionalUiCall();
    }

    auto mojo_options =
        MojoPublicKeyCredentialRequestOptions::From(*options->publicKey());
    if (mojo_options) {
      mojo_options->is_conditional = is_conditional_ui_request;
      if (!mojo_options->relying_party_id) {
        mojo_options->relying_party_id = context->GetSecurityOrigin()->Domain();
      }
      mojo_options->requested_credential_type_flags =
          requested_credential_types;
      auto* authenticator =
          CredentialManagerProxy::From(script_state)->Authenticator();
      authenticator->GetAssertion(
          std::move(mojo_options),
          WTF::BindOnce(&OnGetAssertionComplete,
                        std::make_unique<ScopedPromiseResolver>(resolver),
                        std::move(scoped_abort_state),
                        is_conditional_ui_request));
    } else {
      resolver->Reject(MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kNotSupportedError,
          "Required parameter
```