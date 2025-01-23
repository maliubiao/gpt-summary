Response:
Let's break down the thought process for analyzing the `openssl_ssl_util.cc` file and answering the user's request.

**1. Understanding the Core Task:**

The primary goal is to understand the functionality of `openssl_ssl_util.cc` within the Chromium networking stack. This involves identifying its purpose, the core tasks it performs, and its relationship to other components, particularly concerning JavaScript and potential user errors.

**2. Initial Scan and Keyword Identification:**

A quick read-through reveals key terms and patterns:

* **`net/ssl/openssl_ssl_util.h`:**  The `#include` immediately suggests this file is a utility related to OpenSSL within the `net/ssl` directory. This points to its role in handling SSL/TLS operations.
* **`OpenSSLNetErrorLibSingleton`:**  Implies handling and mapping errors specific to network operations within OpenSSL.
* **`MapOpenSSLErrorSSL`, `MapOpenSSLError`, `MapOpenSSLErrorWithDetails`:**  Strong indicators of error code translation between OpenSSL's error codes and Chromium's `net::ERR_*` error codes. This is crucial for a consistent error reporting mechanism.
* **`NetLogOpenSSLErrorParams`, `NetLogOpenSSLError`:** Suggests logging of OpenSSL-related errors for debugging and monitoring.
* **`GetNetSSLVersion`:**  A function to retrieve the negotiated SSL/TLS version.
* **`SetSSLChainAndKey`:**  Deals with setting up the certificate chain and private key for SSL/TLS connections, likely for client authentication.
* **`SslSetClearMask`:**  Indicates a mechanism for configuring OpenSSL flags, likely for customizing SSL/TLS behavior.

**3. Categorizing Functionality:**

Based on the initial scan, we can group the functionality:

* **Error Handling and Mapping:** This appears to be a central function. Mapping OpenSSL errors to Chromium's error codes is vital for providing meaningful error information to the rest of the browser.
* **OpenSSL Configuration:**  The `SslSetClearMask` suggests a way to influence OpenSSL's internal settings.
* **SSL/TLS Information Retrieval:**  `GetNetSSLVersion` falls into this category.
* **Certificate and Key Management:** `SetSSLChainAndKey` manages the credentials used for SSL/TLS.
* **Logging:** The `NetLog` functions handle logging events, which is important for debugging.

**4. Detailing Each Function/Area:**

Now, we examine each function or logical block more closely:

* **`SslSetClearMask`:**  It manages setting and clearing flags, preventing conflicts. This is about fine-grained control over OpenSSL's behavior.
* **Error Mapping (`MapOpenSSLError...`):**  This is the most complex part. The code iterates through the OpenSSL error stack. It distinguishes between generic OpenSSL errors (`ERR_LIB_SSL`) and custom "net errors" injected by Chromium. The `switch` statement in `MapOpenSSLErrorSSL` shows the mapping logic, connecting specific OpenSSL error reasons to `net::ERR_*` values.
* **Net Logging (`NetLogOpenSSLError...`):** These functions format and record error information in Chromium's logging system.
* **Version Retrieval (`GetNetSSLVersion`):**  A straightforward mapping of OpenSSL version constants to Chromium's.
* **Certificate/Key Setting (`SetSSLChainAndKey`):**  This function uses OpenSSL's API to associate a certificate chain and private key with an `SSL` object.

**5. Considering the Relationship with JavaScript:**

This is where we need to connect the backend (C++ code) to the frontend (JavaScript). JavaScript doesn't directly call these C++ functions. The interaction happens through higher-level APIs. Think about how a webpage initiates an HTTPS connection:

* **User Interaction:**  The user types a URL starting with "https://" or clicks a link.
* **Browser's Network Stack:** Chromium's network stack (where this code resides) handles the request.
* **SSL/TLS Handshake:**  This code is involved in establishing the secure connection. If an error occurs during the handshake (e.g., certificate issues, protocol mismatches), the error mapping functions are crucial for translating the underlying OpenSSL error into a `net::ERR_*` code.
* **Error Reporting to JavaScript:**  The `net::ERR_*` code might eventually be surfaced to the JavaScript layer, perhaps through a `fetch()` API rejection or an error event on an `XMLHttpRequest` object. The JavaScript code can then display an appropriate message to the user.

**6. Developing Examples (Assumptions and Outputs):**

For the logical inference, we need to create scenarios. The key here is to choose error conditions handled by the mapping functions:

* **Assumption:**  The server uses an outdated TLS version.
* **OpenSSL Error:**  `SSL_R_TLSV1_ALERT_PROTOCOL_VERSION`
* **Mapping:** This gets mapped to `ERR_SSL_VERSION_OR_CIPHER_MISMATCH`.
* **Output (to NetLog):** The log entry would contain both the original OpenSSL error reason and the mapped `net_error` code.

* **Assumption:** The server's certificate has expired.
* **OpenSSL Error:** `SSL_R_SSLV3_ALERT_CERTIFICATE_EXPIRED`
* **Mapping:** This gets mapped to `ERR_BAD_SSL_CLIENT_AUTH_CERT`. *(Self-correction: Initially I might think of a more generic certificate error, but looking at the code, this specific OpenSSL error maps to this Chromium error code. It's important to be precise based on the code.)*
* **Output (to NetLog):** Similar log output with the specific error codes.

**7. Identifying User/Programming Errors:**

Think about common mistakes that could lead to these errors:

* **User Error:**  Ignoring browser warnings about untrusted certificates, trying to access a site with a revoked certificate, the system clock being significantly incorrect (leading to certificate expiry issues).
* **Programming Error:**  Misconfiguring the server's SSL/TLS settings (e.g., only supporting outdated protocols), providing an incomplete certificate chain, using incorrect key material.

**8. Tracing User Actions (Debugging Clues):**

How does a user end up triggering this code?

* The user types an `https://` URL and presses Enter.
* The browser's networking code starts the SSL/TLS handshake.
* OpenSSL is used for the cryptographic operations.
* If an error occurs during the handshake within OpenSSL, the functions in this file are called to map the error.

**9. Structuring the Answer:**

Finally, organize the information logically, addressing each part of the user's request:

* **Functionality:** List the key tasks.
* **JavaScript Relationship:** Explain the indirect connection through the browser's network stack and error reporting. Provide an example with `fetch()`.
* **Logical Inference:**  Present clear assumptions, the corresponding OpenSSL error, the mapped Chromium error, and example NetLog output.
* **User/Programming Errors:** Give concrete examples of each type of error.
* **User Journey (Debugging):**  Describe the steps a user takes to reach a scenario where this code is relevant.

This structured approach, starting with a broad understanding and progressively drilling down into details, helps in thoroughly analyzing the code and providing a comprehensive answer to the user's request. The self-correction during the example generation is also a key part of the process.
这个 `net/ssl/openssl_ssl_util.cc` 文件是 Chromium 网络栈中处理 OpenSSL 相关的实用工具函数集合。它的主要功能是连接 Chromium 的网络层和底层的 OpenSSL 库，以便进行安全的网络通信（如 HTTPS）。

下面分点列举其功能，并根据你的要求进行详细说明：

**1. OpenSSL 错误码映射到 Chromium 网络错误码：**

* **功能:**  当 OpenSSL 库在执行 SSL/TLS 操作时遇到错误，它会返回一个 OpenSSL 特定的错误码。这个文件中的函数（如 `MapOpenSSLErrorSSL` 和 `MapOpenSSLError`）负责将这些 OpenSSL 错误码转换为 Chromium 定义的网络错误码（定义在 `net/base/net_errors.h` 中，通常以 `ERR_` 开头）。
* **意义:** 这样做的好处是，Chromium 的上层代码可以统一处理网络错误，而不需要直接理解和处理 OpenSSL 特有的错误码。这提高了代码的可读性和维护性。
* **逻辑推理 (假设输入与输出):**
    * **假设输入 (OpenSSL 错误码):**  `SSL_R_TLSV1_ALERT_PROTOCOL_VERSION` (表示对端使用了不兼容的 TLS 版本)
    * **输出 (Chromium 网络错误码):** `ERR_SSL_VERSION_OR_CIPHER_MISMATCH`
    * **代码逻辑:** `MapOpenSSLErrorSSL` 函数内部的 `switch` 语句会根据 `ERR_GET_REASON(error_code)` 来匹配，当匹配到 `SSL_R_TLSV1_ALERT_PROTOCOL_VERSION` 时，返回 `ERR_SSL_VERSION_OR_CIPHER_MISMATCH`。
* **与 JavaScript 的关系:**  JavaScript 代码通过浏览器提供的 API (如 `fetch` 或 `XMLHttpRequest`) 发起网络请求时，如果底层 SSL/TLS 握手失败，Chromium 的网络层会捕获到这个错误。经过 `openssl_ssl_util.cc` 的映射，将 OpenSSL 的错误转换为 Chromium 的网络错误。最终，这个网络错误可能会以某种形式传递给 JavaScript。
    * **举例说明:**
        ```javascript
        fetch('https://example.com')
          .then(response => {
            console.log('请求成功', response);
          })
          .catch(error => {
            // 如果由于 TLS 版本不匹配导致握手失败，error 对象可能包含有关网络错误的信息
            console.error('请求失败', error);
            // error.message 可能包含类似 "net::ERR_SSL_VERSION_OR_CIPHER_MISMATCH" 的信息
          });
        ```
        在这种情况下，如果 `example.com` 服务器只支持旧版本的 TLS，而客户端配置为不接受，OpenSSL 会返回相应的错误，`openssl_ssl_util.cc` 会将其映射为 `ERR_SSL_VERSION_OR_CIPHER_MISMATCH`，最终导致 `fetch` 请求失败，并在 JavaScript 的 `catch` 块中捕获到错误信息。

**2. 将 Chromium 网络错误码注入到 OpenSSL 错误队列：**

* **功能:**  `OpenSSLPutNetError` 函数允许将 Chromium 特定的网络错误码（通常是由于网络层自身的逻辑判断产生，而不是 OpenSSL 直接返回的）添加到 OpenSSL 的错误队列中。
* **意义:** 这使得在处理 OpenSSL 错误时，可以统一考虑来自 OpenSSL 库本身以及 Chromium 网络层产生的错误。
* **逻辑推理 (假设输入与输出):**
    * **假设输入 (Chromium 网络错误码):** `ERR_TIMED_OUT`
    * **代码逻辑:** `OpenSSLPutNetError` 会将 `-ERR_TIMED_OUT` 这个正数编码后放入 OpenSSL 的错误队列中。
    * **输出 (OpenSSL 错误队列):** OpenSSL 的错误队列中会包含一个表示 `ERR_TIMED_OUT` 的条目，可以通过 `ERR_get_error_line` 等函数读取。
* **与 JavaScript 的关系:** 这种情况不太会直接影响 JavaScript 的错误处理，因为通常 JavaScript 感知的是最终的、经过 OpenSSL 处理后的错误结果，而不是中间注入的 Chromium 特有错误。

**3. 提供 NetLog 支持来记录 OpenSSL 错误信息：**

* **功能:** `NetLogOpenSSLError` 函数用于将 OpenSSL 相关的错误信息记录到 Chromium 的 NetLog 系统中。NetLog 是 Chromium 用来记录网络事件和调试信息的机制。
* **意义:** 这对于调试网络问题非常有用，可以帮助开发者了解 SSL/TLS 握手过程中发生的具体错误，包括 OpenSSL 的错误码、错误发生的文件和行号等。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:** Chromium 网络错误码 `net_error` 为 -107 (对应 `ERR_SSL_PROTOCOL_ERROR`)，OpenSSL 错误码 `ssl_error` 为一个具体的 OpenSSL 错误（例如通过 `ERR_get_error()` 获取）。
    * **代码逻辑:** `NetLogOpenSSLError` 函数会调用 NetLog 的 API，创建一个包含 `net_error`、`ssl_error` 以及可能的错误发生的文件和行号的日志事件。
    * **输出 (NetLog):** NetLog 中会生成一条类似以下的记录：
        ```json
        {
          "params": {
            "net_error": -107,
            "ssl_error": 336030196,
            "error_lib": 23,
            "error_reason": 100,
            "file": "net/ssl/openssl_ssl_util.cc",
            "line": 123
          },
          "phase": 0,
          "source_dependency": {
            "source_type": "URL_REQUEST"
          },
          "time": "12345.567",
          "type": "SSL_HANDSHAKE_ERROR"
        }
        ```
* **与 JavaScript 的关系:**  NetLog 信息主要是供开发者调试使用，JavaScript 代码本身无法直接访问 NetLog。开发者可以通过 Chrome 浏览器的 `chrome://net-export/` 页面导出 NetLog 日志进行分析。

**4. 获取 SSL 连接的版本信息：**

* **功能:** `GetNetSSLVersion` 函数用于获取当前 SSL 连接使用的协议版本（例如 TLS 1.2, TLS 1.3）。
* **意义:**  可以用来判断连接的安全性级别，或者用于兼容性判断。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:**  一个已经建立的 SSL 连接的 `SSL*` 指针，并且该连接使用了 TLS 1.3 协议。
    * **代码逻辑:** `SSL_version(ssl)` 会返回 OpenSSL 中表示 TLS 1.3 的常量 `TLS1_3_VERSION`，然后 `GetNetSSLVersion` 将其映射为 Chromium 定义的 `SSL_CONNECTION_VERSION_TLS1_3`。
    * **输出:** `SSL_CONNECTION_VERSION_TLS1_3`
* **与 JavaScript 的关系:**  JavaScript 代码通常无法直接获取底层的 SSL 连接版本。浏览器可能会通过一些安全相关的 API 或开发者工具来展示这些信息。

**5. 设置 SSL 连接的证书链和私钥：**

* **功能:** `SetSSLChainAndKey` 函数用于为 SSL 连接设置服务器或客户端的证书链和私钥。这通常用于服务器配置或客户端身份验证。
* **意义:**  确保连接的身份验证和加密是基于正确的证书和密钥。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:**  一个 `SSL*` 指针，一个 `X509Certificate*` 对象表示证书，一个 `EVP_PKEY*` 对象表示私钥。
    * **代码逻辑:** `SSL_set_chain_and_key` 函数会被调用，将证书链和私钥关联到指定的 SSL 连接。
    * **输出:** 如果设置成功，函数返回 `true`；否则返回 `false`，并可能在日志中记录错误。
* **与 JavaScript 的关系:**  对于一般的网页浏览，JavaScript 代码通常不会直接涉及到设置服务器证书。但是，在一些高级的网络应用中，例如使用 `WebCrypto API` 进行客户端证书认证，或者在 Node.js 等服务端 JavaScript 环境中配置 HTTPS 服务器时，可能会间接地涉及到这些操作。

**6. 配置 SSL 标志 (使用 `SslSetClearMask`):**

* **功能:** `SslSetClearMask` 类提供了一种方便的方式来设置或清除 OpenSSL SSL 对象的标志位。
* **意义:** 可以用来定制 SSL 连接的行为，例如启用或禁用特定的功能。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:** 创建一个 `SslSetClearMask` 对象，并调用 `ConfigureFlag(SSL_OP_NO_TLSv1, true)`。
    * **代码逻辑:** `set_mask` 会被设置为包含 `SSL_OP_NO_TLSv1` 的值。
    * **输出:** 当这个 mask 应用到 SSL 对象时，会禁用 TLS 1.0 协议。
* **与 JavaScript 的关系:**  JavaScript 代码无法直接控制这些底层的 SSL 选项。这些配置通常在 Chromium 的 C++ 代码中进行。

**用户或编程常见的使用错误示例：**

* **用户错误:**
    * **忽略证书错误:** 当浏览器提示证书无效或不受信任时，用户选择忽略并继续访问，这可能导致安全风险，并且底层的 SSL 握手可能会因为证书验证失败而触发这里的错误处理逻辑。
    * **系统时间不正确:** 如果用户的计算机系统时间与实际时间相差太远，可能导致证书过期验证失败，从而触发 OpenSSL 的证书过期错误，并被此文件映射为相应的 Chromium 网络错误。
* **编程错误:**
    * **服务器配置错误:**  服务器管理员配置了错误的证书链、私钥，或者只支持过时的 SSL/TLS 协议版本，导致客户端连接失败。这些错误会被 OpenSSL 捕获并映射。
    * **客户端证书配置错误:**  在使用客户端证书认证时，如果客户端提供的证书无效或与服务器要求的不匹配，也会导致握手失败，并触发这里的错误处理。
    * **在 Chromium 代码中错误地使用 OpenSSL API:**  如果 Chromium 的开发者在调用 OpenSSL API 时出现错误（例如传递了错误的参数），OpenSSL 可能会返回错误，这些错误会被此文件映射。

**用户操作如何一步步到达这里（作为调试线索）：**

1. **用户在地址栏输入 `https://www.example.com` 并按下回车。**
2. **Chromium 浏览器发起对 `www.example.com` 的网络请求。**
3. **由于是 HTTPS 请求，Chromium 的网络栈开始与服务器进行 SSL/TLS 握手。**
4. **在握手过程中，Chromium 调用底层的 OpenSSL 库来执行加密和身份验证操作。**
5. **如果 OpenSSL 在握手过程中遇到错误（例如，服务器证书无效、协议版本不匹配等），OpenSSL 会返回一个错误码。**
6. **`net/ssl/openssl_ssl_util.cc` 中的函数（例如 `MapOpenSSLError`）会被调用，将 OpenSSL 的错误码转换为 Chromium 的网络错误码。**
7. **Chromium 的网络层会根据这个 Chromium 网络错误码来处理请求失败的情况，并可能将错误信息传递给上层代码（例如，渲染进程显示错误页面）。**
8. **开发者可以通过 Chrome 的开发者工具（Network 面板）或者通过导出 NetLog 日志来查看这个过程中发生的错误，包括 `openssl_ssl_util.cc` 记录的 OpenSSL 错误信息。**

总之，`net/ssl/openssl_ssl_util.cc` 在 Chromium 的网络安全机制中扮演着关键的角色，它负责连接 Chromium 的高级网络逻辑和底层的 OpenSSL 库，处理错误映射、日志记录等关键任务，确保网络通信的安全性。虽然 JavaScript 代码通常不直接操作这个文件中的函数，但其行为会受到这里错误处理结果的影响。

### 提示词
```
这是目录为net/ssl/openssl_ssl_util.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/ssl/openssl_ssl_util.h"

#include <errno.h>

#include <utility>

#include "base/lazy_instance.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/notreached.h"
#include "base/values.h"
#include "build/build_config.h"
#include "crypto/openssl_util.h"
#include "net/base/net_errors.h"
#include "net/cert/x509_util.h"
#include "net/log/net_log_with_source.h"
#include "net/ssl/ssl_connection_status_flags.h"
#include "third_party/boringssl/src/include/openssl/err.h"
#include "third_party/boringssl/src/include/openssl/ssl.h"

namespace net {

SslSetClearMask::SslSetClearMask() = default;

void SslSetClearMask::ConfigureFlag(long flag, bool state) {
  (state ? set_mask : clear_mask) |= flag;
  // Make sure we haven't got any intersection in the set & clear options.
  DCHECK_EQ(0, set_mask & clear_mask) << flag << ":" << state;
}

namespace {

class OpenSSLNetErrorLibSingleton {
 public:
  OpenSSLNetErrorLibSingleton() {
    // Allocate a new error library value for inserting net errors into
    // OpenSSL. This does not register any ERR_STRING_DATA for the errors, so
    // stringifying error codes through OpenSSL will return NULL.
    net_error_lib_ = ERR_get_next_error_library();
  }

  int net_error_lib() const { return net_error_lib_; }

 private:
  int net_error_lib_;
};

base::LazyInstance<OpenSSLNetErrorLibSingleton>::Leaky g_openssl_net_error_lib =
    LAZY_INSTANCE_INITIALIZER;

int OpenSSLNetErrorLib() {
  return g_openssl_net_error_lib.Get().net_error_lib();
}

int MapOpenSSLErrorSSL(uint32_t error_code) {
  DCHECK_EQ(ERR_LIB_SSL, ERR_GET_LIB(error_code));

#if DCHECK_IS_ON()
  char buf[ERR_ERROR_STRING_BUF_LEN];
  ERR_error_string_n(error_code, buf, sizeof(buf));
  DVLOG(1) << "OpenSSL SSL error, reason: " << ERR_GET_REASON(error_code)
           << ", name: " << buf;
#endif

  switch (ERR_GET_REASON(error_code)) {
    case SSL_R_READ_TIMEOUT_EXPIRED:
      return ERR_TIMED_OUT;
    case SSL_R_UNKNOWN_CERTIFICATE_TYPE:
    case SSL_R_UNKNOWN_CIPHER_TYPE:
    case SSL_R_UNKNOWN_KEY_EXCHANGE_TYPE:
    case SSL_R_UNKNOWN_SSL_VERSION:
      return ERR_NOT_IMPLEMENTED;
    case SSL_R_NO_CIPHER_MATCH:
    case SSL_R_NO_SHARED_CIPHER:
    case SSL_R_TLSV1_ALERT_INSUFFICIENT_SECURITY:
    case SSL_R_TLSV1_ALERT_PROTOCOL_VERSION:
    case SSL_R_UNSUPPORTED_PROTOCOL:
      return ERR_SSL_VERSION_OR_CIPHER_MISMATCH;
    case SSL_R_SSLV3_ALERT_BAD_CERTIFICATE:
    case SSL_R_SSLV3_ALERT_UNSUPPORTED_CERTIFICATE:
    case SSL_R_SSLV3_ALERT_CERTIFICATE_REVOKED:
    case SSL_R_SSLV3_ALERT_CERTIFICATE_EXPIRED:
    case SSL_R_SSLV3_ALERT_CERTIFICATE_UNKNOWN:
    case SSL_R_TLSV1_ALERT_ACCESS_DENIED:
    case SSL_R_TLSV1_ALERT_CERTIFICATE_REQUIRED:
    case SSL_R_TLSV1_ALERT_UNKNOWN_CA:
      return ERR_BAD_SSL_CLIENT_AUTH_CERT;
    case SSL_R_SSLV3_ALERT_DECOMPRESSION_FAILURE:
      return ERR_SSL_DECOMPRESSION_FAILURE_ALERT;
    case SSL_R_SSLV3_ALERT_BAD_RECORD_MAC:
      return ERR_SSL_BAD_RECORD_MAC_ALERT;
    case SSL_R_TLSV1_ALERT_DECRYPT_ERROR:
      return ERR_SSL_DECRYPT_ERROR_ALERT;
    case SSL_R_TLSV1_UNRECOGNIZED_NAME:
      return ERR_SSL_UNRECOGNIZED_NAME_ALERT;
    case SSL_R_SERVER_CERT_CHANGED:
      return ERR_SSL_SERVER_CERT_CHANGED;
    case SSL_R_WRONG_VERSION_ON_EARLY_DATA:
      return ERR_WRONG_VERSION_ON_EARLY_DATA;
    case SSL_R_TLS13_DOWNGRADE:
      return ERR_TLS13_DOWNGRADE_DETECTED;
    case SSL_R_ECH_REJECTED:
      return ERR_ECH_NOT_NEGOTIATED;
    // SSL_R_SSLV3_ALERT_HANDSHAKE_FAILURE may be returned from the server after
    // receiving ClientHello if there's no common supported cipher. Map that
    // specific case to ERR_SSL_VERSION_OR_CIPHER_MISMATCH to match the NSS
    // implementation. See https://goo.gl/oMtZW and https://crbug.com/446505.
    case SSL_R_SSLV3_ALERT_HANDSHAKE_FAILURE: {
      uint32_t previous = ERR_peek_error();
      if (previous != 0 && ERR_GET_LIB(previous) == ERR_LIB_SSL &&
          ERR_GET_REASON(previous) == SSL_R_HANDSHAKE_FAILURE_ON_CLIENT_HELLO) {
        return ERR_SSL_VERSION_OR_CIPHER_MISMATCH;
      }
      return ERR_SSL_PROTOCOL_ERROR;
    }
    case SSL_R_KEY_USAGE_BIT_INCORRECT:
      return ERR_SSL_KEY_USAGE_INCOMPATIBLE;
    default:
      return ERR_SSL_PROTOCOL_ERROR;
  }
}

base::Value::Dict NetLogOpenSSLErrorParams(int net_error,
                                           int ssl_error,
                                           const OpenSSLErrorInfo& error_info) {
  base::Value::Dict dict;
  dict.Set("net_error", net_error);
  dict.Set("ssl_error", ssl_error);
  if (error_info.error_code != 0) {
    dict.Set("error_lib", ERR_GET_LIB(error_info.error_code));
    dict.Set("error_reason", ERR_GET_REASON(error_info.error_code));
  }
  if (error_info.file != nullptr)
    dict.Set("file", error_info.file);
  if (error_info.line != 0)
    dict.Set("line", error_info.line);
  return dict;
}

}  // namespace

void OpenSSLPutNetError(const base::Location& location, int err) {
  // Net error codes are negative. Encode them as positive numbers.
  err = -err;
  if (err < 0 || err > 0xfff) {
    // OpenSSL reserves 12 bits for the reason code.
    NOTREACHED();
  }
  ERR_put_error(OpenSSLNetErrorLib(), 0 /* unused */, err, location.file_name(),
                location.line_number());
}

int MapOpenSSLError(int err, const crypto::OpenSSLErrStackTracer& tracer) {
  OpenSSLErrorInfo error_info;
  return MapOpenSSLErrorWithDetails(err, tracer, &error_info);
}

int MapOpenSSLErrorWithDetails(int err,
                               const crypto::OpenSSLErrStackTracer& tracer,
                               OpenSSLErrorInfo* out_error_info) {
  *out_error_info = OpenSSLErrorInfo();

  switch (err) {
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
      return ERR_IO_PENDING;
    case SSL_ERROR_EARLY_DATA_REJECTED:
      return ERR_EARLY_DATA_REJECTED;
    case SSL_ERROR_SYSCALL:
      PLOG(ERROR) << "OpenSSL SYSCALL error, earliest error code in "
                     "error queue: "
                  << ERR_peek_error();
      return ERR_FAILED;
    case SSL_ERROR_SSL:
      // Walk down the error stack to find an SSL or net error.
      while (true) {
        OpenSSLErrorInfo error_info;
        error_info.error_code =
            ERR_get_error_line(&error_info.file, &error_info.line);
        if (error_info.error_code == 0) {
          // Map errors to ERR_SSL_PROTOCOL_ERROR by default, reporting the most
          // recent error in |*out_error_info|.
          return ERR_SSL_PROTOCOL_ERROR;
        }

        *out_error_info = error_info;
        if (ERR_GET_LIB(error_info.error_code) == ERR_LIB_SSL) {
          return MapOpenSSLErrorSSL(error_info.error_code);
        }
        if (ERR_GET_LIB(error_info.error_code) == OpenSSLNetErrorLib()) {
          // Net error codes are negative but encoded in OpenSSL as positive
          // numbers.
          return -ERR_GET_REASON(error_info.error_code);
        }
      }
    default:
      // TODO(joth): Implement full mapping.
      LOG(WARNING) << "Unknown OpenSSL error " << err;
      return ERR_SSL_PROTOCOL_ERROR;
  }
}

void NetLogOpenSSLError(const NetLogWithSource& net_log,
                        NetLogEventType type,
                        int net_error,
                        int ssl_error,
                        const OpenSSLErrorInfo& error_info) {
  net_log.AddEvent(type, [&] {
    return NetLogOpenSSLErrorParams(net_error, ssl_error, error_info);
  });
}

int GetNetSSLVersion(SSL* ssl) {
  switch (SSL_version(ssl)) {
    case TLS1_VERSION:
      return SSL_CONNECTION_VERSION_TLS1;
    case TLS1_1_VERSION:
      return SSL_CONNECTION_VERSION_TLS1_1;
    case TLS1_2_VERSION:
      return SSL_CONNECTION_VERSION_TLS1_2;
    case TLS1_3_VERSION:
      return SSL_CONNECTION_VERSION_TLS1_3;
    default:
      NOTREACHED();
  }
}

bool SetSSLChainAndKey(SSL* ssl,
                       X509Certificate* cert,
                       EVP_PKEY* pkey,
                       const SSL_PRIVATE_KEY_METHOD* custom_key) {
  std::vector<CRYPTO_BUFFER*> chain_raw;
  chain_raw.reserve(1 + cert->intermediate_buffers().size());
  chain_raw.push_back(cert->cert_buffer());
  for (const auto& handle : cert->intermediate_buffers())
    chain_raw.push_back(handle.get());

  if (!SSL_set_chain_and_key(ssl, chain_raw.data(), chain_raw.size(), pkey,
                             custom_key)) {
    LOG(WARNING) << "Failed to set client certificate";
    return false;
  }

  return true;
}

}  // namespace net
```