Response:
My thought process to analyze the `crypto_result_impl.cc` file and answer the prompt went like this:

1. **Understand the Core Purpose:** The filename itself, "crypto_result_impl.cc," strongly suggests this file deals with the *results* of cryptographic operations within the Blink rendering engine. The `Impl` suffix often indicates an implementation detail, suggesting this class is used internally to manage the outcome of asynchronous crypto operations.

2. **Identify Key Classes and Structures:**  I scanned the `#include` directives and the class declaration (`CryptoResultImpl`) to identify the main players:
    * `CryptoResultImpl`: The central class, inheriting from `CryptoResult` and `ExecutionContextLifecycleObserver`. This tells me it's tied to the lifecycle of a browsing context.
    * `ScriptPromiseResolverBase`: This is crucial. Promises are fundamental to asynchronous JavaScript, so this immediately highlights the connection to JavaScript's `crypto` API.
    * `WebCryptoAlgorithm`, `WebCryptoKey`: These platform-level types suggest this code bridges the gap between Blink's JavaScript API and the underlying platform's crypto capabilities.
    * `DOMArrayBuffer`:  Important for handling binary data, which is common in cryptographic operations.
    * `CryptoKey`: Blink's representation of cryptographic keys.
    * `DOMException`: Used for reporting errors to JavaScript.

3. **Analyze Key Methods:** I then examined the methods within `CryptoResultImpl`:
    * `CompleteWithError`:  Clearly for handling errors. The `WebCryptoErrorType` and conversion to `DOMExceptionCode` are significant.
    * `CompleteWithBuffer`, `CompleteWithJson`, `CompleteWithBoolean`, `CompleteWithKey`, `CompleteWithKeyPair`:  These are the success handlers, each tailored to different types of cryptographic results. The interaction with `ScriptPromiseResolverBase` and the conversion to V8 values are key.
    * `Cancel`:  Allows for the cancellation of ongoing operations.
    * `RejectWithTypeError`:  A specific error handling case.

4. **Connect to JavaScript, HTML, CSS:** Based on the presence of `ScriptPromiseResolverBase`, the core link to JavaScript became clear. The `crypto` API in JavaScript is asynchronous and relies on Promises. This file is part of the implementation that resolves or rejects those Promises.

    * **JavaScript:** The `window.crypto` API is the entry point. Methods like `crypto.subtle.encrypt()`, `crypto.subtle.decrypt()`, `crypto.subtle.generateKey()`, etc., will ultimately trigger code that interacts with `CryptoResultImpl`.
    * **HTML:**  HTML provides the structure for web pages. JavaScript embedded within or linked to an HTML page uses the `crypto` API. So, while not directly related to HTML rendering, this code is essential for the functionality enabled by JavaScript within an HTML context.
    * **CSS:** CSS is for styling. It has no direct relationship with the core cryptographic functionality handled by this file.

5. **Logical Reasoning (Hypothetical Input/Output):**  I considered a common crypto operation, like generating a key pair.

    * **Input (Hypothetical):** A JavaScript call to `crypto.subtle.generateKey("RSA-PKCS1-v1_5", { modulusLength: 2048, publicExponent: new Uint8Array([0x01, 0x00, 0x01]) }, true, ["encrypt", "decrypt"])`. This would involve the browser's internal crypto mechanisms.
    * **Processing within `crypto_result_impl.cc`:**  The underlying platform crypto library would eventually produce the key pair. This key pair (as `WebCryptoKey` objects) would then be passed to `CryptoResultImpl::CompleteWithKeyPair`.
    * **Output:** The `CompleteWithKeyPair` method would create a JavaScript object with `publicKey` and `privateKey` properties (as `CryptoKey` objects) and resolve the Promise associated with the original `generateKey` call.

6. **User/Programming Errors:**  I considered common mistakes when using the Web Crypto API:

    * **Incorrect Algorithm:**  Specifying an algorithm that's not supported by the browser. This could lead to `CompleteWithError` being called with `kWebCryptoErrorTypeNotSupported`.
    * **Invalid Key Usage:**  Trying to use a key for an operation it wasn't intended for. This might trigger a `kWebCryptoErrorTypeInvalidAccess` error.
    * **Incorrect Data Format:** Providing data in the wrong format for a specific cryptographic operation. This could result in `kWebCryptoErrorTypeData` or `kWebCryptoErrorTypeSyntax`.

7. **Debugging Scenario:** I imagined a scenario where a developer reports an error with their Web Crypto code.

    * **User Action:**  The user interacts with a web page that uses the `crypto` API (e.g., clicking a "Encrypt" button).
    * **JavaScript Execution:** The JavaScript code calls a `crypto.subtle` method.
    * **Blink Processing:**  Blink internally calls the platform's crypto functions.
    * **Error Occurs:**  The platform returns an error.
    * **`crypto_result_impl.cc` Involvement:** The `CompleteWithError` method in `crypto_result_impl.cc` would be called to reject the JavaScript Promise with a `DOMException`.
    * **Developer Debugging:** The developer might see an error message in the browser's console related to a `NotSupportedError` or `DataError`, pointing them towards issues with the algorithm or input data. Setting breakpoints in `crypto_result_impl.cc`, particularly in `CompleteWithError`, could help diagnose the issue by revealing the specific `WebCryptoErrorType`.

By following this structured approach, I could systematically analyze the code, understand its role, and connect it to the broader web development context. The key was recognizing the centrality of Promises and the flow of data between JavaScript and the underlying crypto implementation.
这个文件 `blink/renderer/modules/crypto/crypto_result_impl.cc` 是 Chromium Blink 引擎中实现 Web Cryptography API 的一部分。它的主要功能是**处理和传递异步加密操作的结果（成功或失败）给 JavaScript 代码。**  它充当了底层加密操作和 JavaScript Promise 之间的桥梁。

以下是它的详细功能分解：

**1. 处理异步操作的完成和错误:**

*   **成功完成:**  当一个加密操作（例如，加密、解密、签名、验证、生成密钥等）成功完成时，这个文件中的方法会将结果数据转换成 JavaScript 可以理解的格式，并解析（resolve）与该操作关联的 Promise。
*   **发生错误:** 如果加密操作失败，这个文件中的方法会根据错误类型创建一个相应的 JavaScript `DOMException` 或 `TypeError`，并拒绝（reject）与该操作关联的 Promise。

**2. 结果类型处理:**

这个文件针对不同的加密操作结果类型提供了专门的处理方法：

*   **`CompleteWithBuffer(base::span<const uint8_t> bytes)`:** 处理结果是 `ArrayBuffer` 的情况，例如加密或解密操作的输出。
*   **`CompleteWithJson(std::string_view utf8_data)`:**  处理结果是 JSON 字符串的情况。虽然在 Web Crypto API 中不常见直接返回 JSON，但可能用于某些特定场景。
*   **`CompleteWithBoolean(bool b)`:** 处理结果是布尔值的情况，例如某些密钥操作的成功与否。
*   **`CompleteWithKey(const WebCryptoKey& key)`:** 处理结果是单个 `CryptoKey` 对象的情况，例如导入密钥或生成对称密钥。
*   **`CompleteWithKeyPair(const WebCryptoKey& public_key, const WebCryptoKey& private_key)`:** 处理结果是密钥对 (`CryptoKey` 对象) 的情况，例如生成非对称密钥对。
*   **`CompleteWithError(WebCryptoErrorType error_type, const WebString& error_details)`:** 处理操作失败的情况，根据 `WebCryptoErrorType` 生成相应的 JavaScript 异常。

**3. 与 JavaScript、HTML、CSS 的关系 (及其举例说明):**

这个文件直接关联到 JavaScript 的 Web Cryptography API (`window.crypto.subtle`)。它负责将底层的 C++ 加密操作结果传递回 JavaScript 代码，因此是 JavaScript 代码能够使用加密功能的关键一环。

*   **JavaScript:**
    *   **功能关系:** JavaScript 代码通过 `window.crypto.subtle` 对象调用加密函数（例如 `encrypt()`, `decrypt()`, `generateKey()` 等），这些调用在底层会触发 C++ 代码的执行。当 C++ 的加密操作完成时，`crypto_result_impl.cc` 中的方法会将结果返回给 JavaScript 的 Promise。
    *   **举例说明:**
        ```javascript
        // JavaScript 代码
        async function encryptData(key, data) {
          const encoded = new TextEncoder().encode(data);
          const ciphertext = await window.crypto.subtle.encrypt(
            { name: "AES-CBC", iv: crypto.getRandomValues(new Uint8Array(16)) },
            key,
            encoded
          );
          return ciphertext;
        }

        // 假设 key 是一个 CryptoKey 对象
        encryptData(key, "Hello, world!")
          .then(ciphertext => {
            console.log("加密成功:", ciphertext); // ciphertext 就是 CompleteWithBuffer 传递的结果
          })
          .catch(error => {
            console.error("加密失败:", error); // error 就是 CompleteWithError 传递的异常
          });
        ```
        在这个例子中，`window.crypto.subtle.encrypt()` 调用会触发底层的加密操作。当加密完成后，`crypto_result_impl.cc` 中的 `CompleteWithBuffer` 方法会被调用，将加密后的 `ArrayBuffer` 数据传递给 JavaScript 的 Promise，最终在 `.then()` 中被接收。如果加密过程中发生错误，`CompleteWithError` 会创建并抛出一个异常，在 `.catch()` 中被捕获。

*   **HTML:**
    *   **功能关系:** HTML 作为网页的结构，本身不直接涉及加密操作。但是，HTML 中嵌入的 JavaScript 代码可以使用 Web Cryptography API 来实现加密功能，而 `crypto_result_impl.cc` 正是这个 API 的底层实现部分。
    *   **举例说明:**  一个网页的表单可能会使用 JavaScript 的加密功能来加密用户提交的敏感数据，然后再发送到服务器。这个 JavaScript 代码的执行就依赖于 `crypto_result_impl.cc` 的功能。

*   **CSS:**
    *   **功能关系:** CSS 负责网页的样式，与加密功能没有直接关系。

**4. 逻辑推理 (假设输入与输出):**

假设 JavaScript 代码调用 `crypto.subtle.digest("SHA-256", data)`，其中 `data` 是一个 `ArrayBuffer` 类型的输入数据。

*   **假设输入:**  一个包含字符串 "test" 的 `ArrayBuffer`。
*   **Blink 处理:** 底层的 SHA-256 哈希算法会被执行。
*   **`crypto_result_impl.cc` 的处理:**  `CompleteWithBuffer` 方法会被调用，参数 `bytes` 将会是 "test" 的 SHA-256 哈希值的字节数组。
*   **输出:** JavaScript 的 Promise 会被 resolve，返回一个包含 SHA-256 哈希值的 `ArrayBuffer`。

假设 JavaScript 代码调用 `crypto.subtle.generateKey({ name: "RSA", modulusLength: 2048, publicExponent: new Uint8Array([0x01, 0x00, 0x01]) }, true, ["sign", "verify"])`，但由于某种原因（例如，浏览器不支持该算法），生成密钥失败。

*   **假设输入:** 生成 RSA 密钥对的请求。
*   **Blink 处理:** 底层密钥生成过程尝试生成密钥，但遇到错误。
*   **`crypto_result_impl.cc` 的处理:** `CompleteWithError` 方法会被调用，参数 `error_type` 可能为 `kWebCryptoErrorTypeNotSupported`，`error_details` 会包含相关的错误信息。
*   **输出:** JavaScript 的 Promise 会被 reject，抛出一个 `NotSupportedError` 类型的 `DOMException`。

**5. 用户或编程常见的使用错误 (及其举例说明):**

*   **错误 1: 使用错误的算法名称或参数。**
    ```javascript
    // 错误的算法名称 "AES-WRONG"
    window.crypto.subtle.encrypt({ name: "AES-WRONG" }, key, data)
      .catch(error => {
        console.error("错误:", error); // 可能会抛出 NotSupportedError
      });
    ```
    在这种情况下，底层的加密操作无法找到对应的算法实现，`CompleteWithError` 会被调用，并将 Promise 拒绝，抛出一个 `NotSupportedError`。

*   **错误 2:  在不支持的操作中使用密钥。**
    ```javascript
    // 假设 key 只允许用于签名
    window.crypto.subtle.encrypt({ name: "AES-CBC" }, key, data)
      .catch(error => {
        console.error("错误:", error); // 可能会抛出 InvalidAccessError
      });
    ```
    如果尝试使用一个仅限签名的密钥进行加密，底层的密钥使用检查会失败，`CompleteWithError` 会被调用，并抛出一个 `InvalidAccessError`。

*   **错误 3: 提供错误格式的数据。**
    ```javascript
    // 加密需要 Uint8Array，但提供了字符串
    window.crypto.subtle.encrypt({ name: "AES-CBC" }, key, "invalid data")
      .catch(error => {
        console.error("错误:", error); // 可能会抛出 TypeError 或 DataError
      });
    ```
    如果传递给加密函数的输入数据类型不正确，`CompleteWithError` 可能会被调用，抛出一个 `TypeError` 或 `DataError`。

**6. 用户操作如何一步步的到达这里 (作为调试线索):**

1. **用户在网页上执行了某个操作，触发了 JavaScript 代码。** 例如，用户点击了一个 "加密" 按钮，或者网页在加载时执行了某些加密操作。
2. **JavaScript 代码调用了 `window.crypto.subtle` 的方法。**  例如 `encrypt()`, `decrypt()`, `generateKey()` 等。
3. **Blink 引擎接收到 JavaScript 的加密请求。** 这会将请求传递给底层的 C++ Web Crypto 实现。
4. **底层的 C++ 代码执行相应的加密操作。** 这可能涉及调用操作系统提供的加密库或其他安全库。
5. **加密操作完成（成功或失败）。**
6. **`crypto_result_impl.cc` 中的相应方法被调用。**
    *   如果成功，调用 `CompleteWithBuffer`, `CompleteWithJson`, `CompleteWithBoolean`, `CompleteWithKey`, 或 `CompleteWithKeyPair`，并将结果传递给 JavaScript 的 Promise 的 `resolve` 回调。
    *   如果失败，调用 `CompleteWithError`，创建一个 JavaScript 异常，并将 Promise 拒绝 (reject)。
7. **JavaScript 代码中的 Promise 的 `.then()` 或 `.catch()` 回调函数被执行。**

**调试线索:**

*   如果在 JavaScript 控制台中看到与 Web Crypto API 相关的 `DOMException` 或 `TypeError`，这可能意味着 `CompleteWithError` 方法被调用了。
*   可以使用浏览器的开发者工具设置断点来调试 JavaScript 代码中调用 `window.crypto.subtle` 的地方，跟踪代码的执行流程。
*   如果需要深入调试 C++ 代码，可以在 `blink/renderer/modules/crypto/crypto_result_impl.cc` 中的 `CompleteWithError` 或其他 `CompleteWith...` 方法中设置断点，查看具体的错误类型和数据是如何传递的。
*   查看 Chromium 的日志输出 (通过 `chrome://tracing` 或命令行参数启动 Chrome) 可能会提供关于底层加密操作的更多信息。

总而言之，`crypto_result_impl.cc` 是 Web Cryptography API 的核心组成部分，它负责确保异步的加密操作能够将结果和错误正确地传递回 JavaScript 环境，使得网页开发者能够安全地使用加密功能。

### 提示词
```
这是目录为blink/renderer/modules/crypto/crypto_result_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2013 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/modules/crypto/crypto_result_impl.h"

#include "base/compiler_specific.h"
#include "base/containers/span.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/web_crypto_algorithm.h"
#include "third_party/blink/renderer/bindings/core/v8/dictionary.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_object_builder.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_throw_dom_exception.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_crypto_key.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/execution_context/execution_context_lifecycle_observer.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer.h"
#include "third_party/blink/renderer/modules/crypto/crypto_key.h"
#include "third_party/blink/renderer/modules/crypto/normalize_algorithm.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/bindings/v8_throw_exception.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"

namespace blink {

static void RejectWithTypeError(const String& error_details,
                                ScriptPromiseResolverBase* resolver) {
  // Duplicate some of the checks done by ScriptPromiseResolverBase.
  if (!resolver->GetExecutionContext() ||
      resolver->GetExecutionContext()->IsContextDestroyed())
    return;

  ScriptState::Scope scope(resolver->GetScriptState());
  v8::Isolate* isolate = resolver->GetScriptState()->GetIsolate();
  resolver->Reject(V8ThrowException::CreateTypeError(isolate, error_details));
}

ExceptionCode WebCryptoErrorToExceptionCode(WebCryptoErrorType error_type) {
  switch (error_type) {
    case kWebCryptoErrorTypeNotSupported:
      return ToExceptionCode(DOMExceptionCode::kNotSupportedError);
    case kWebCryptoErrorTypeSyntax:
      return ToExceptionCode(DOMExceptionCode::kSyntaxError);
    case kWebCryptoErrorTypeInvalidAccess:
      return ToExceptionCode(DOMExceptionCode::kInvalidAccessError);
    case kWebCryptoErrorTypeData:
      return ToExceptionCode(DOMExceptionCode::kDataError);
    case kWebCryptoErrorTypeOperation:
      return ToExceptionCode(DOMExceptionCode::kOperationError);
    case kWebCryptoErrorTypeType:
      return ToExceptionCode(ESErrorType::kTypeError);
  }
}

CryptoResultImpl::~CryptoResultImpl() {
  DCHECK(!resolver_);
}

void CryptoResultImpl::Trace(Visitor* visitor) const {
  visitor->Trace(resolver_);
  ExecutionContextLifecycleObserver::Trace(visitor);
  CryptoResult::Trace(visitor);
}

void CryptoResultImpl::ClearResolver() {
  resolver_ = nullptr;
}

void CryptoResultImpl::CompleteWithError(WebCryptoErrorType error_type,
                                         const WebString& error_details) {
  if (!resolver_)
    return;

  ScriptState* resolver_script_state = resolver_->GetScriptState();
  if (!IsInParallelAlgorithmRunnable(resolver_->GetExecutionContext(),
                                     resolver_script_state)) {
    return;
  }
  ScriptState::Scope script_state_scope(resolver_script_state);

  ExceptionCode exception_code = WebCryptoErrorToExceptionCode(error_type);

  // Handle TypeError separately, as it cannot be created using
  // DOMException.
  if (exception_code == ToExceptionCode(ESErrorType::kTypeError)) {
    RejectWithTypeError(error_details, resolver_);
  } else if (IsDOMExceptionCode(exception_code)) {
    resolver_->Reject(V8ThrowDOMException::CreateOrDie(
        resolver_script_state->GetIsolate(),
        static_cast<DOMExceptionCode>(exception_code), error_details));
  } else {
    NOTREACHED();
  }
  ClearResolver();
}

void CryptoResultImpl::CompleteWithBuffer(base::span<const uint8_t> bytes) {
  if (!resolver_)
    return;

  auto* buffer = DOMArrayBuffer::Create(bytes);
  if (type_ == ResolverType::kTyped) {
    resolver_->DowncastTo<DOMArrayBuffer>()->Resolve(buffer);
  } else {
    ScriptState* script_state = resolver_->GetScriptState();
    ScriptState::Scope scope(script_state);
    resolver_->DowncastTo<IDLAny>()->Resolve(buffer->ToV8(script_state));
  }
  ClearResolver();
}

void CryptoResultImpl::CompleteWithJson(std::string_view utf8_data) {
  if (!resolver_)
    return;

  ScriptState* script_state = resolver_->GetScriptState();
  ScriptState::Scope scope(script_state);

  if (utf8_data.size() > v8::String::kMaxLength) {
    // TODO(crbug.com/1316976): this should probably raise an exception instead.
    LOG(FATAL) << "Result string is longer than v8::String::kMaxLength";
  }

  v8::TryCatch try_catch(script_state->GetIsolate());
  v8::Local<v8::Value> json_dictionary =
      FromJSONString(script_state, String::FromUTF8(utf8_data));
  CHECK_EQ(type_, ResolverType::kAny);
  if (try_catch.HasCaught()) {
    resolver_->Reject(try_catch.Exception());
  } else {
    resolver_->DowncastTo<IDLAny>()->Resolve(json_dictionary);
  }
  ClearResolver();
}

void CryptoResultImpl::CompleteWithBoolean(bool b) {
  if (!resolver_)
    return;

  CHECK_EQ(type_, ResolverType::kAny);
  resolver_->DowncastTo<IDLAny>()->Resolve(
      v8::Boolean::New(resolver_->GetScriptState()->GetIsolate(), b));
  ClearResolver();
}

void CryptoResultImpl::CompleteWithKey(const WebCryptoKey& key) {
  if (!resolver_)
    return;

  auto* result = MakeGarbageCollected<CryptoKey>(key);
  if (type_ == ResolverType::kTyped) {
    resolver_->DowncastTo<CryptoKey>()->Resolve(result);
  } else {
    ScriptState* script_state = resolver_->GetScriptState();
    ScriptState::Scope scope(script_state);
    resolver_->DowncastTo<IDLAny>()->Resolve(result->ToV8(script_state));
  }
  ClearResolver();
}

void CryptoResultImpl::CompleteWithKeyPair(const WebCryptoKey& public_key,
                                           const WebCryptoKey& private_key) {
  if (!resolver_)
    return;

  ScriptState* script_state = resolver_->GetScriptState();
  ScriptState::Scope scope(script_state);

  V8ObjectBuilder key_pair(script_state);

  key_pair.Add("publicKey", MakeGarbageCollected<CryptoKey>(public_key));
  key_pair.Add("privateKey", MakeGarbageCollected<CryptoKey>(private_key));

  CHECK_EQ(type_, ResolverType::kAny);
  resolver_->DowncastTo<IDLAny>()->Resolve(key_pair.V8Value());
  ClearResolver();
}

void CryptoResultImpl::Cancel() {
  cancel_->Cancel();
  ClearResolver();
}

}  // namespace blink
```