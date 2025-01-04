Response:
Let's break down the thought process for analyzing this C++ code and answering the request.

**1. Understanding the Goal:**

The request asks for several things about the provided C++ file: its functionality, relationship to JavaScript, logical flow (input/output), potential user/programming errors, and debugging information (how to reach this code).

**2. Initial Code Scan & Keyword Identification:**

I'd start by quickly scanning the code for keywords and familiar patterns related to network authentication and security. I'd look for:

* `#include`: Indicates dependencies. `net/http/http_auth*.h`, `base/base64.h`, `net/base/net_errors.h`, `net/log/*` are strong hints.
* `namespace net`:  Confirms it's part of the Chromium networking stack.
* `GSSAPI`, `SPNEGO`, `Kerberos`:  These are the core technologies being used.
* `gss_*` function calls: These are the GSSAPI library calls, the heart of the functionality.
* `base::Base64Encode`: Shows base64 encoding, common in authentication.
* `NetLogEventType::AUTH_*`: Indicates logging within the networking stack.
* `HttpAuthChallengeTokenizer`:  Points to parsing authentication challenges.
* `AuthCredentials`: Represents user credentials.
* `CompletionOnceCallback`: Suggests asynchronous operations (though not heavily used in *this* specific file).
* `DelegationType`:  Relates to Kerberos delegation.
* `ERR_*`:  Indicates network error codes.

**3. Deconstructing Functionality:**

Based on the keywords, I would start piecing together the main purpose of the file. The file name itself, `http_auth_gssapi_posix.cc`, is a strong indicator: it handles GSSAPI (Generic Security Services Application Programming Interface) authentication on POSIX-like systems (Linux, macOS, etc.) for HTTP.

I would then examine the key classes and functions:

* `GSSAPISharedLibrary`: Manages loading and binding to the GSSAPI system library. This is crucial because GSSAPI isn't a standard part of Chromium's code, so it needs to interact with the OS's implementation.
* `HttpAuthGSSAPI`: The main class responsible for handling GSSAPI authentication. It encapsulates the security context and interacts with the `GSSAPILibrary`.
* `Init()`: Initializes the GSSAPI library.
* `NeedsIdentity()`, `AllowsExplicitCredentials()`: Indicate authentication flow requirements.
* `ParseChallenge()`: Handles parsing the `WWW-Authenticate` header from the server. This involves processing the server's GSSAPI response token.
* `GenerateAuthToken()`: Generates the client's response token (`Authorization` header) to send to the server. This is where the core GSSAPI logic of `gss_init_sec_context` is used.
* `GetNextSecurityToken()`:  The low-level function to obtain a GSSAPI security token. This involves calling `gss_init_sec_context`.

**4. Identifying JavaScript Relationship (or lack thereof):**

With a good understanding of the core functionality, I'd consider the JavaScript relationship. Web browsers use JavaScript, so how does this C++ code interact with it?

The key is that *this C++ code runs within the browser's networking stack*. JavaScript in a web page can trigger HTTP requests. When an HTTP server requires GSSAPI authentication (like Kerberos), the browser's *internal* mechanisms (this C++ code) handle the authentication challenge-response flow. JavaScript itself *doesn't directly interact with these GSSAPI calls*. It just initiates the request and receives the eventual response (success or failure).

Therefore, the relationship is indirect: JavaScript triggers network activity, and this C++ code handles a specific type of authentication required by the server for that activity.

**5. Logical Flow (Input/Output):**

I'd trace the execution flow of the main authentication steps:

* **Input (from the server):** A `WWW-Authenticate: Negotiate ...` header containing a base64-encoded GSSAPI token.
* **Processing:** `ParseChallenge()` decodes the token. `GenerateAuthToken()` uses the token (or lack thereof initially) and the SPN to call GSSAPI functions (`gss_init_sec_context`) to generate a response token.
* **Output (to the server):** An `Authorization: Negotiate ...` header containing the base64-encoded GSSAPI response token.

I'd also consider the initial "first round" where no server token exists yet.

**6. User/Programming Errors:**

I'd think about common pitfalls:

* **User Errors:**  Incorrect Kerberos configuration on the user's machine (no tickets, wrong `krb5.conf`), trying to use GSSAPI without server support, incorrect SPN.
* **Programming Errors:**  Incorrectly handling GSSAPI return codes, not properly initializing the GSSAPI library, memory management issues with GSSAPI buffers (although the `ScopedBuffer` helps mitigate this).

**7. Debugging Clues:**

I'd look for clues about how a developer might end up debugging this code:

* The code extensively uses `DLOG` and `net_log` for logging. This is a primary debugging mechanism. A developer would look at these logs.
* The code handles different GSSAPI status codes and maps them to Chromium's `ERR_*` codes. This is important for error reporting within the browser.
* The code includes `base::Value::Dict` for structured logging information, making it easier to inspect GSSAPI context and status.

**8. Structuring the Answer:**

Finally, I'd organize the information into the requested sections: functionality, JavaScript relationship, logical flow, errors, and debugging. I would use clear language and provide specific examples where possible.

**Self-Correction/Refinement:**

During the process, I might realize some initial assumptions were slightly off. For example, I might initially overemphasize the direct interaction with JavaScript, but then correct myself to explain the indirect nature of the relationship. I might also need to review the GSSAPI function calls to ensure I understand their specific roles in the authentication process. Looking at the comments in the code itself can be very helpful for clarifying the intended purpose of different sections.
这个文件 `net/http/http_auth_gssapi_posix.cc` 是 Chromium 网络栈中专门用于处理基于 GSSAPI (Generic Security Services Application Programming Interface) 的 HTTP 身份验证的 POSIX 系统特定实现。GSSAPI 是一种标准化的方式，允许应用程序使用各种安全机制（如 Kerberos）进行身份验证和安全通信。

以下是它的主要功能：

**1. GSSAPI 库加载与绑定:**

*  **动态加载 GSSAPI 库:**  代码尝试加载系统上的 GSSAPI 共享库 (例如 `libgssapi_krb5.so.2`)。它会尝试一系列可能的库名称，并记录加载尝试的结果。
*  **绑定 GSSAPI 函数:** 加载库后，它会使用 `base::GetFunctionPointerFromNativeLibrary` 绑定所需的 GSSAPI 函数，例如 `gss_init_sec_context`, `gss_import_name`, `gss_display_name` 等。这使得 Chromium 可以调用底层的 GSSAPI 实现。
*  **`GSSAPISharedLibrary` 类:**  负责管理 GSSAPI 库的加载、卸载和函数绑定。

**2. HTTP 身份验证处理:**

*  **`HttpAuthGSSAPI` 类:**  是处理 GSSAPI HTTP 身份验证的核心类。
*  **`ParseChallenge()`:**  解析服务器发送的 `WWW-Authenticate: Negotiate ...` 质询头。这通常包含一个 Base64 编码的 GSSAPI 令牌。
*  **`GenerateAuthToken()`:**  生成发送给服务器的 `Authorization: Negotiate ...` 认证令牌。这涉及到调用 GSSAPI 函数 (`gss_init_sec_context`) 来建立安全上下文并生成令牌。
*  **`GetNextSecurityToken()`:**  执行实际的 GSSAPI 安全上下文初始化过程。它会根据服务器的质询令牌（如果存在）和目标服务主体名称 (SPN) 调用 GSSAPI 函数来生成新的安全令牌。
*  **安全上下文管理:**  使用 `ScopedSecurityContext` 类来自动管理 GSSAPI 安全上下文的生命周期，确保在不再需要时释放资源。
*  **委托 (Delegation):** 支持 GSSAPI 委托，允许客户端将自己的凭据委托给服务器。可以通过 `SetDelegation()` 方法设置委托类型。

**3. 错误处理与日志记录:**

*  **GSSAPI 错误代码映射:**  代码将 GSSAPI 返回的错误代码映射到 Chromium 的网络错误代码 (例如 `ERR_INVALID_RESPONSE`, `ERR_MISSING_AUTH_CREDENTIALS`)，以便更好地向用户或开发者报告错误。
*  **详细的日志记录:**  使用 Chromium 的网络日志系统 (`net_log`) 记录 GSSAPI 操作的各个阶段，包括库加载、函数调用、安全上下文状态等。这对于调试身份验证问题非常有用。
*  **`GetGssStatusValue()` 等辅助函数:**  用于将 GSSAPI 状态码转换为更易读的日志信息。

**4. SPNEGO 支持:**

*  **`CHROME_GSS_SPNEGO_MECH_OID_DESC`:**  定义了 SPNEGO (Simple and Protected GSSAPI Negotiation Mechanism) 的 OID (Object Identifier)。Chromium 使用 SPNEGO 作为其 GSSAPI 机制，因为它允许在客户端和服务器之间协商最佳的可用身份验证协议。

**与 JavaScript 功能的关系:**

这个 C++ 文件本身不直接包含 JavaScript 代码，但它为浏览器处理 HTTP GSSAPI 身份验证提供了底层支持。当 JavaScript 发起一个需要 GSSAPI 认证的 HTTP 请求时，Chromium 的网络栈会调用这个文件中的代码来处理认证流程。

**举例说明:**

假设一个使用 JavaScript 的 Web 应用需要访问一个配置了 Kerberos 认证的服务器。

1. **JavaScript 发起请求:**  JavaScript 代码使用 `fetch()` 或 `XMLHttpRequest` 发起对服务器资源的请求。
2. **服务器返回 401 和 Negotiate 质询:** 服务器收到请求后，如果需要认证，会返回 HTTP 状态码 `401 Unauthorized`，并在 `WWW-Authenticate` 头中包含 `Negotiate` 质询，可能包含一个 Base64 编码的 GSSAPI 令牌。
3. **Chromium 处理质询:** 浏览器接收到响应后，网络栈会识别出 `Negotiate` 方案，并调用 `net/http/http_auth_gssapi_posix.cc` 中的 `ParseChallenge()` 来解析质询。
4. **生成认证令牌:** 如果需要发送认证信息，`GenerateAuthToken()` 会被调用。这个函数会利用 GSSAPI 库，根据用户的 Kerberos 票据授予票据 (TGT) 或其他凭据，生成一个 GSSAPI 令牌。
5. **发送 Authorization 头:** 浏览器将生成的 GSSAPI 令牌进行 Base64 编码，并将其添加到下一个请求的 `Authorization` 头中，例如 `Authorization: Negotiate YII...`.
6. **服务器验证:** 服务器收到带有 `Authorization` 头的请求后，会使用自己的 GSSAPI 实现来验证令牌。
7. **JavaScript 接收响应:**  认证成功后，服务器会返回请求的资源，JavaScript 代码可以继续处理响应。

**逻辑推理、假设输入与输出:**

**假设输入:**

* **服务器 `WWW-Authenticate` 头:** `Negotiate YIGfMIIE...` (一个 Base64 编码的 GSSAPI 令牌)
* **目标服务主体名称 (SPN):** `HTTP/server.example.com`
* **用户已登录 Kerberos，并且拥有有效的 TGT。**

**逻辑推理:**

1. `ParseChallenge()` 会解码 `YIGfMIIE...` 并存储它作为服务器的认证令牌。
2. `GenerateAuthToken()` 会被调用，因为它需要生成发送给服务器的认证信息。
3. `GetNextSecurityToken()` 会使用解码后的服务器令牌和 SPN，调用底层的 GSSAPI 函数 (`gss_init_sec_context`)。
4. GSSAPI 库会利用用户的 TGT 来与 Kerberos 密钥分发中心 (KDC) 交互，获取访问服务器的票据。
5. `gss_init_sec_context` 会生成一个新的 GSSAPI 令牌，包含了客户端的认证信息。
6. `GenerateAuthToken()` 会将这个新的 GSSAPI 令牌进行 Base64 编码。

**输出:**

* **`Authorization` 头:** `Negotiate YIIJ...` (一个新的 Base64 编码的 GSSAPI 令牌，与输入的服务器令牌不同)

**用户或编程常见的使用错误:**

1. **未正确配置 Kerberos:** 用户的机器上没有有效的 Kerberos 配置（例如，缺少 `krb5.conf` 文件或配置不正确），或者用户没有通过 `kinit` 获取有效的 TGT。这将导致 GSSAPI 函数调用失败。
   * **现象:** 浏览器可能提示身份验证失败，或者网络日志中会显示 GSSAPI 相关的错误信息。

2. **目标服务主体名称 (SPN) 不正确:**  当构建认证令牌时，需要知道目标服务的 SPN。如果提供的 SPN 与服务器配置的不匹配，身份验证将会失败。
   * **现象:**  浏览器可能陷入认证循环，或者服务器返回身份验证错误。

3. **GSSAPI 库未安装或版本不兼容:**  如果系统上缺少 GSSAPI 库，或者 Chromium 尝试加载的库版本与系统实际安装的版本不兼容，加载过程会失败。
   * **现象:**  浏览器可能无法处理 `Negotiate` 认证，或者在网络日志中会显示库加载失败的错误。

4. **委托配置错误:** 如果尝试使用委托，但服务器或客户端的 Kerberos 配置不允许委托，认证可能会失败。
   * **现象:**  认证过程可能成功，但后续需要访问被委托资源的操作会失败。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器中输入一个 URL，或者点击一个链接。** 这个 URL 指向一个需要 Kerberos (或通常的 `Negotiate` 认证) 的 Web 资源。
2. **浏览器发送 HTTP 请求到服务器。**
3. **服务器返回 HTTP 401 Unauthorized 响应，并且 `WWW-Authenticate` 头包含 `Negotiate`。**
4. **Chromium 的网络栈接收到这个响应。**  HTTP 认证相关的代码开始处理。
5. **`net::HttpAuthCache` (或其他相关组件) 会识别出 `Negotiate` 认证方案。**
6. **Chromium 会查找或创建对应的 `HttpAuthenticator` 对象，对于 `Negotiate` 方案，会使用 `HttpAuthGSSAPI`。**
7. **`HttpAuthGSSAPI::ParseChallenge()` 被调用，解析服务器发送的质询令牌。**
8. **如果需要生成认证信息，`HttpAuthGSSAPI::GenerateAuthToken()` 会在后续的请求尝试中被调用。**
9. **`HttpAuthGSSAPI::GetNextSecurityToken()` 会执行底层的 GSSAPI 函数调用。**  在这个函数中，你可以看到与 GSSAPI 库的交互。
10. **如果出现问题，例如 GSSAPI 函数返回错误，相关的日志信息会被记录到 `net_log` 中。** 开发者可以通过 chrome://net-export/ 或其他网络日志查看工具来检查这些日志。

**调试线索:**

* **查看 `chrome://net-internals/#events` 或导出网络日志 (`chrome://net-export/`)**: 可以查看详细的网络事件，包括 HTTP 请求头、响应头，以及 GSSAPI 相关的日志信息 (事件类型通常包含 `AUTH_LIBRARY_` 或与 GSSAPI 相关的描述)。
* **检查 GSSAPI 库的加载情况:**  网络日志会显示是否成功加载了 GSSAPI 库，以及尝试加载的库名称。
* **查看 `gss_init_sec_context` 等 GSSAPI 函数的调用结果:**  日志会记录这些函数的返回值（major status 和 minor status），可以帮助判断 GSSAPI 调用是否成功以及失败的原因。
* **检查安全上下文的状态:**  日志中可能包含安全上下文的信息，例如目标主体名称、机制类型、标志等，可以帮助理解认证过程中的状态。
* **使用系统工具检查 Kerberos 状态:**  例如 `klist` 命令可以查看当前用户的 Kerberos 票据，`kdestroy` 可以清除票据。确保用户拥有有效的票据是 GSSAPI 认证成功的关键。

总而言之，`net/http/http_auth_gssapi_posix.cc` 是 Chromium 处理 HTTP GSSAPI 身份验证的核心 C++ 文件，负责加载 GSSAPI 库、解析认证质询、生成认证令牌以及处理相关的错误和日志记录。它虽然不直接包含 JavaScript 代码，但为浏览器处理需要 GSSAPI 认证的 Web 请求提供了必要的底层支持。 开发者可以通过网络日志和系统工具来调试与该文件相关的身份验证问题。

Prompt: 
```
这是目录为net/http/http_auth_gssapi_posix.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/http/http_auth_gssapi_posix.h"

#include <limits>
#include <string>
#include <string_view>

#include "base/base64.h"
#include "base/compiler_specific.h"
#include "base/feature_list.h"
#include "base/files/file_path.h"
#include "base/format_macros.h"
#include "base/logging.h"
#include "base/memory/raw_ptr.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/threading/thread_restrictions.h"
#include "base/values.h"
#include "build/build_config.h"
#include "net/base/features.h"
#include "net/base/net_errors.h"
#include "net/http/http_auth.h"
#include "net/http/http_auth_gssapi_posix.h"
#include "net/http/http_auth_multi_round_parse.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_values.h"
#include "net/log/net_log_with_source.h"
#include "net/net_buildflags.h"

namespace net {

using DelegationType = HttpAuth::DelegationType;

// Exported mechanism for GSSAPI. We always use SPNEGO:

// iso.org.dod.internet.security.mechanism.snego (1.3.6.1.5.5.2)
gss_OID_desc CHROME_GSS_SPNEGO_MECH_OID_DESC_VAL = {
  6,
  const_cast<char*>("\x2b\x06\x01\x05\x05\x02")
};

gss_OID CHROME_GSS_SPNEGO_MECH_OID_DESC =
    &CHROME_GSS_SPNEGO_MECH_OID_DESC_VAL;

OM_uint32 DelegationTypeToFlag(DelegationType delegation_type) {
  switch (delegation_type) {
    case DelegationType::kNone:
      return 0;
    case DelegationType::kByKdcPolicy:
      return GSS_C_DELEG_POLICY_FLAG;
    case DelegationType::kUnconstrained:
      return GSS_C_DELEG_FLAG;
  }
}

// ScopedBuffer releases a gss_buffer_t when it goes out of scope.
class ScopedBuffer {
 public:
  ScopedBuffer(gss_buffer_t buffer, GSSAPILibrary* gssapi_lib)
      : buffer_(buffer), gssapi_lib_(gssapi_lib) {
    DCHECK(gssapi_lib_);
  }

  ScopedBuffer(const ScopedBuffer&) = delete;
  ScopedBuffer& operator=(const ScopedBuffer&) = delete;

  ~ScopedBuffer() {
    if (buffer_ != GSS_C_NO_BUFFER) {
      OM_uint32 minor_status = 0;
      OM_uint32 major_status =
          gssapi_lib_->release_buffer(&minor_status, buffer_);
      DLOG_IF(WARNING, major_status != GSS_S_COMPLETE)
          << "Problem releasing buffer. major=" << major_status
          << ", minor=" << minor_status;
      buffer_ = GSS_C_NO_BUFFER;
    }
  }

 private:
  gss_buffer_t buffer_;
  raw_ptr<GSSAPILibrary> gssapi_lib_;
};

// ScopedName releases a gss_name_t when it goes out of scope.
class ScopedName {
 public:
  ScopedName(gss_name_t name, GSSAPILibrary* gssapi_lib)
      : name_(name), gssapi_lib_(gssapi_lib) {
    DCHECK(gssapi_lib_);
  }

  ScopedName(const ScopedName&) = delete;
  ScopedName& operator=(const ScopedName&) = delete;

  ~ScopedName() {
    if (name_ != GSS_C_NO_NAME) {
      OM_uint32 minor_status = 0;
      OM_uint32 major_status = gssapi_lib_->release_name(&minor_status, &name_);
      if (major_status != GSS_S_COMPLETE) {
        DLOG_IF(WARNING, major_status != GSS_S_COMPLETE)
            << "Problem releasing name. "
            << GetGssStatusValue(nullptr, "gss_release_name", major_status,
                                 minor_status);
      }
      name_ = GSS_C_NO_NAME;
    }
  }

 private:
  gss_name_t name_;
  raw_ptr<GSSAPILibrary> gssapi_lib_;
};

bool OidEquals(const gss_OID left, const gss_OID right) {
  if (left->length != right->length)
    return false;
  return 0 == memcmp(left->elements, right->elements, right->length);
}

base::Value::Dict GetGssStatusCodeValue(GSSAPILibrary* gssapi_lib,
                                        OM_uint32 status,
                                        OM_uint32 status_code_type) {
  base::Value::Dict rv;

  rv.Set("status", static_cast<int>(status));

  // Message lookups aren't performed if there's no library or if the status
  // indicates success.
  if (!gssapi_lib || status == GSS_S_COMPLETE)
    return rv;

  // gss_display_status() can potentially return multiple strings by sending
  // each string on successive invocations. State is maintained across these
  // invocations in a caller supplied OM_uint32.  After each successful call,
  // the context is set to a non-zero value that should be passed as a message
  // context to each successive gss_display_status() call.  The initial and
  // terminal values of this context storage is 0.
  OM_uint32 message_context = 0;

  // To account for the off chance that gss_display_status() misbehaves and gets
  // into an infinite loop, we'll artificially limit the number of iterations to
  // |kMaxDisplayIterations|. This limit is arbitrary.
  constexpr size_t kMaxDisplayIterations = 8;
  size_t iterations = 0;

  // In addition, each message string is again arbitrarily limited to
  // |kMaxMsgLength|. There's no real documented limit to work with here.
  constexpr size_t kMaxMsgLength = 4096;

  base::Value::List messages;
  do {
    gss_buffer_desc_struct message_buffer = GSS_C_EMPTY_BUFFER;
    ScopedBuffer message_buffer_releaser(&message_buffer, gssapi_lib);

    OM_uint32 minor_status = 0;
    OM_uint32 major_status = gssapi_lib->display_status(
        &minor_status, status, status_code_type, GSS_C_NO_OID, &message_context,
        &message_buffer);

    if (major_status != GSS_S_COMPLETE || message_buffer.length == 0 ||
        !message_buffer.value) {
      continue;
    }

    std::string_view message_string{
        static_cast<const char*>(message_buffer.value),
        std::min(kMaxMsgLength, message_buffer.length)};

    // The returned string is almost assuredly ASCII, but be defensive.
    if (!base::IsStringUTF8(message_string))
      continue;

    messages.Append(message_string);
  } while (message_context != 0 && ++iterations < kMaxDisplayIterations);

  if (!messages.empty())
    rv.Set("message", std::move(messages));
  return rv;
}

base::Value::Dict GetGssStatusValue(GSSAPILibrary* gssapi_lib,
                                    std::string_view method,
                                    OM_uint32 major_status,
                                    OM_uint32 minor_status) {
  base::Value::Dict params;
  params.Set("function", method);
  params.Set("major_status",
             GetGssStatusCodeValue(gssapi_lib, major_status, GSS_C_GSS_CODE));
  params.Set("minor_status",
             GetGssStatusCodeValue(gssapi_lib, minor_status, GSS_C_MECH_CODE));
  return params;
}

base::Value::Dict OidToValue(gss_OID oid) {
  base::Value::Dict params;

  if (!oid || oid->length == 0) {
    params.Set("oid", "<Empty OID>");
    return params;
  }

  params.Set("length", static_cast<int>(oid->length));
  if (!oid->elements)
    return params;

  // Cap OID content at arbitrary limit 1k.
  constexpr OM_uint32 kMaxOidDataSize = 1024;
  params.Set("bytes", NetLogBinaryValue(oid->elements, std::min(kMaxOidDataSize,
                                                                oid->length)));

  // Based on RFC 2744 Appendix A. Hardcoding the OIDs in the list below to
  // avoid having a static dependency on the library.
  static const struct {
    const char* symbolic_name;
    const gss_OID_desc oid_desc;
  } kWellKnownOIDs[] = {
      {"GSS_C_NT_USER_NAME",
       {10, const_cast<char*>("\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x01")}},
      {"GSS_C_NT_MACHINE_UID_NAME",
       {10, const_cast<char*>("\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x02")}},
      {"GSS_C_NT_STRING_UID_NAME",
       {10, const_cast<char*>("\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x03")}},
      {"GSS_C_NT_HOSTBASED_SERVICE_X",
       {6, const_cast<char*>("\x2b\x06\x01\x05\x06\x02")}},
      {"GSS_C_NT_HOSTBASED_SERVICE",
       {10, const_cast<char*>("\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x04")}},
      {"GSS_C_NT_ANONYMOUS", {6, const_cast<char*>("\x2b\x06\01\x05\x06\x03")}},
      {"GSS_C_NT_EXPORT_NAME",
       {6, const_cast<char*>("\x2b\x06\x01\x05\x06\x04")}}};

  for (auto& well_known_oid : kWellKnownOIDs) {
    if (OidEquals(oid, const_cast<const gss_OID>(&well_known_oid.oid_desc)))
      params.Set("oid", well_known_oid.symbolic_name);
  }

  return params;
}

base::Value::Dict GetDisplayNameValue(GSSAPILibrary* gssapi_lib,
                                      const gss_name_t gss_name) {
  OM_uint32 major_status = 0;
  OM_uint32 minor_status = 0;
  gss_buffer_desc_struct name = GSS_C_EMPTY_BUFFER;
  gss_OID name_type = GSS_C_NO_OID;

  base::Value::Dict rv;
  major_status =
      gssapi_lib->display_name(&minor_status, gss_name, &name, &name_type);
  ScopedBuffer scoped_output_name(&name, gssapi_lib);
  if (major_status != GSS_S_COMPLETE) {
    rv.Set("error", GetGssStatusValue(gssapi_lib, "gss_display_name",
                                      major_status, minor_status));
    return rv;
  }
  auto name_string =
      std::string_view(reinterpret_cast<const char*>(name.value), name.length);
  rv.Set("name", base::IsStringUTF8(name_string)
                     ? NetLogStringValue(name_string)
                     : NetLogBinaryValue(name.value, name.length));
  rv.Set("type", OidToValue(name_type));
  return rv;
}

base::Value::Dict ContextFlagsToValue(OM_uint32 flags) {
  base::Value::Dict rv;
  rv.Set("value", base::StringPrintf("0x%08x", flags));
  rv.Set("delegated", (flags & GSS_C_DELEG_FLAG) == GSS_C_DELEG_FLAG);
  rv.Set("mutual", (flags & GSS_C_MUTUAL_FLAG) == GSS_C_MUTUAL_FLAG);
  return rv;
}

base::Value::Dict GetContextStateAsValue(GSSAPILibrary* gssapi_lib,
                                         const gss_ctx_id_t context_handle) {
  base::Value::Dict rv;
  if (context_handle == GSS_C_NO_CONTEXT) {
    rv.Set("error", GetGssStatusValue(nullptr, "<none>", GSS_S_NO_CONTEXT, 0));
    return rv;
  }

  OM_uint32 major_status = 0;
  OM_uint32 minor_status = 0;
  gss_name_t src_name = GSS_C_NO_NAME;
  gss_name_t targ_name = GSS_C_NO_NAME;
  OM_uint32 lifetime_rec = 0;
  gss_OID mech_type = GSS_C_NO_OID;
  OM_uint32 ctx_flags = 0;
  int locally_initiated = 0;
  int open = 0;
  major_status = gssapi_lib->inquire_context(&minor_status,
                                             context_handle,
                                             &src_name,
                                             &targ_name,
                                             &lifetime_rec,
                                             &mech_type,
                                             &ctx_flags,
                                             &locally_initiated,
                                             &open);
  if (major_status != GSS_S_COMPLETE) {
    rv.Set("error", GetGssStatusValue(gssapi_lib, "gss_inquire_context",
                                      major_status, minor_status));
    return rv;
  }
  ScopedName scoped_src_name(src_name, gssapi_lib);
  ScopedName scoped_targ_name(targ_name, gssapi_lib);

  rv.Set("source", GetDisplayNameValue(gssapi_lib, src_name));
  rv.Set("target", GetDisplayNameValue(gssapi_lib, targ_name));
  // lifetime_rec is a uint32, while base::Value only takes ints. On 32 bit
  // platforms uint32 doesn't fit on an int.
  rv.Set("lifetime", base::NumberToString(lifetime_rec));
  rv.Set("mechanism", OidToValue(mech_type));
  rv.Set("flags", ContextFlagsToValue(ctx_flags));
  rv.Set("open", !!open);
  return rv;
}

namespace {

// Return a NetLog value for the result of loading a library.
base::Value::Dict LibraryLoadResultParams(std::string_view library_name,
                                          std::string_view load_result) {
  base::Value::Dict params;
  params.Set("library_name", library_name);
  if (!load_result.empty())
    params.Set("load_result", load_result);
  return params;
}

}  // namespace

GSSAPISharedLibrary::GSSAPISharedLibrary(const std::string& gssapi_library_name)
    : gssapi_library_name_(gssapi_library_name) {}

GSSAPISharedLibrary::~GSSAPISharedLibrary() {
  if (gssapi_library_) {
    base::UnloadNativeLibrary(gssapi_library_);
    gssapi_library_ = nullptr;
  }
}

bool GSSAPISharedLibrary::Init(const NetLogWithSource& net_log) {
  if (!initialized_)
    InitImpl(net_log);
  return initialized_;
}

bool GSSAPISharedLibrary::InitImpl(const NetLogWithSource& net_log) {
  DCHECK(!initialized_);
  gssapi_library_ = LoadSharedLibrary(net_log);
  if (gssapi_library_ == nullptr)
    return false;
  initialized_ = true;
  return true;
}

base::NativeLibrary GSSAPISharedLibrary::LoadSharedLibrary(
    const NetLogWithSource& net_log) {
  const char* const* library_names;
  size_t num_lib_names;
  const char* user_specified_library[1];
  if (!gssapi_library_name_.empty()) {
    user_specified_library[0] = gssapi_library_name_.c_str();
    library_names = user_specified_library;
    num_lib_names = 1;
  } else {
    static const char* const kDefaultLibraryNames[] = {
#if BUILDFLAG(IS_APPLE)
      "/System/Library/Frameworks/GSS.framework/GSS"
#elif BUILDFLAG(IS_OPENBSD)
      "libgssapi.so"  // Heimdal - OpenBSD
#else
      "libgssapi_krb5.so.2",  // MIT Kerberos - FC, Suse10, Debian
      "libgssapi.so.4",       // Heimdal - Suse10, MDK
      "libgssapi.so.2",       // Heimdal - Gentoo
      "libgssapi.so.1"        // Heimdal - Suse9, CITI - FC, MDK, Suse10
#endif
    };
    library_names = kDefaultLibraryNames;
    num_lib_names = std::size(kDefaultLibraryNames);
  }

  net_log.BeginEvent(NetLogEventType::AUTH_LIBRARY_LOAD);

  // There has to be at least one candidate.
  DCHECK_NE(0u, num_lib_names);

  const char* library_name = nullptr;
  base::NativeLibraryLoadError load_error;

  for (size_t i = 0; i < num_lib_names; ++i) {
    load_error = base::NativeLibraryLoadError();
    library_name = library_names[i];
    base::FilePath file_path(library_name);

    // TODO(asanka): Move library loading to a separate thread.
    //               http://crbug.com/66702
    base::ScopedAllowBlocking scoped_allow_blocking_temporarily;
    base::NativeLibrary lib = base::LoadNativeLibrary(file_path, &load_error);
    if (lib) {
      if (BindMethods(lib, library_name, net_log)) {
        net_log.EndEvent(NetLogEventType::AUTH_LIBRARY_LOAD, [&] {
          return LibraryLoadResultParams(library_name, "");
        });
        return lib;
      }
      base::UnloadNativeLibrary(lib);
    }
  }

  // If loading failed, then log the result of the final attempt. Doing so
  // is specially important on platforms where there's only one possible
  // library. Doing so also always logs the failure when the GSSAPI library
  // name is explicitly specified.
  net_log.EndEvent(NetLogEventType::AUTH_LIBRARY_LOAD, [&] {
    return LibraryLoadResultParams(library_name, load_error.ToString());
  });
  return nullptr;
}

namespace {

base::Value::Dict BindFailureParams(std::string_view library_name,
                                    std::string_view method) {
  base::Value::Dict params;
  params.Set("library_name", library_name);
  params.Set("method", method);
  return params;
}

void* BindUntypedMethod(base::NativeLibrary lib,
                        std::string_view library_name,
                        const char* method,
                        const NetLogWithSource& net_log) {
  void* ptr = base::GetFunctionPointerFromNativeLibrary(lib, method);
  if (ptr == nullptr) {
    net_log.AddEvent(NetLogEventType::AUTH_LIBRARY_BIND_FAILED,
                     [&] { return BindFailureParams(library_name, method); });
  }
  return ptr;
}

template <typename T>
bool BindMethod(base::NativeLibrary lib,
                std::string_view library_name,
                const char* method,
                T* receiver,
                const NetLogWithSource& net_log) {
  *receiver = reinterpret_cast<T>(
      BindUntypedMethod(lib, library_name, method, net_log));
  return *receiver != nullptr;
}

}  // namespace

bool GSSAPISharedLibrary::BindMethods(base::NativeLibrary lib,
                                      std::string_view name,
                                      const NetLogWithSource& net_log) {
  bool ok = true;
  // It's unlikely for BindMethods() to fail if LoadNativeLibrary() succeeded. A
  // failure in this function indicates an interoperability issue whose
  // diagnosis requires knowing all the methods that are missing. Hence |ok| is
  // updated in a manner that prevents short-circuiting the BindGssMethod()
  // invocations.
  ok &= BindMethod(lib, name, "gss_delete_sec_context", &delete_sec_context_,
                   net_log);
  ok &= BindMethod(lib, name, "gss_display_name", &display_name_, net_log);
  ok &= BindMethod(lib, name, "gss_display_status", &display_status_, net_log);
  ok &= BindMethod(lib, name, "gss_import_name", &import_name_, net_log);
  ok &= BindMethod(lib, name, "gss_init_sec_context", &init_sec_context_,
                   net_log);
  ok &=
      BindMethod(lib, name, "gss_inquire_context", &inquire_context_, net_log);
  ok &= BindMethod(lib, name, "gss_release_buffer", &release_buffer_, net_log);
  ok &= BindMethod(lib, name, "gss_release_name", &release_name_, net_log);
  ok &=
      BindMethod(lib, name, "gss_wrap_size_limit", &wrap_size_limit_, net_log);

  if (ok) [[likely]] {
    return true;
  }

  delete_sec_context_ = nullptr;
  display_name_ = nullptr;
  display_status_ = nullptr;
  import_name_ = nullptr;
  init_sec_context_ = nullptr;
  inquire_context_ = nullptr;
  release_buffer_ = nullptr;
  release_name_ = nullptr;
  wrap_size_limit_ = nullptr;
  return false;
}

OM_uint32 GSSAPISharedLibrary::import_name(
    OM_uint32* minor_status,
    const gss_buffer_t input_name_buffer,
    const gss_OID input_name_type,
    gss_name_t* output_name) {
  DCHECK(initialized_);
  return import_name_(minor_status, input_name_buffer, input_name_type,
                      output_name);
}

OM_uint32 GSSAPISharedLibrary::release_name(
    OM_uint32* minor_status,
    gss_name_t* input_name) {
  DCHECK(initialized_);
  return release_name_(minor_status, input_name);
}

OM_uint32 GSSAPISharedLibrary::release_buffer(
    OM_uint32* minor_status,
    gss_buffer_t buffer) {
  DCHECK(initialized_);
  return release_buffer_(minor_status, buffer);
}

OM_uint32 GSSAPISharedLibrary::display_name(
    OM_uint32* minor_status,
    const gss_name_t input_name,
    gss_buffer_t output_name_buffer,
    gss_OID* output_name_type) {
  DCHECK(initialized_);
  return display_name_(minor_status,
                       input_name,
                       output_name_buffer,
                       output_name_type);
}

OM_uint32 GSSAPISharedLibrary::display_status(
    OM_uint32* minor_status,
    OM_uint32 status_value,
    int status_type,
    const gss_OID mech_type,
    OM_uint32* message_context,
    gss_buffer_t status_string) {
  DCHECK(initialized_);
  return display_status_(minor_status, status_value, status_type, mech_type,
                         message_context, status_string);
}

OM_uint32 GSSAPISharedLibrary::init_sec_context(
    OM_uint32* minor_status,
    const gss_cred_id_t initiator_cred_handle,
    gss_ctx_id_t* context_handle,
    const gss_name_t target_name,
    const gss_OID mech_type,
    OM_uint32 req_flags,
    OM_uint32 time_req,
    const gss_channel_bindings_t input_chan_bindings,
    const gss_buffer_t input_token,
    gss_OID* actual_mech_type,
    gss_buffer_t output_token,
    OM_uint32* ret_flags,
    OM_uint32* time_rec) {
  DCHECK(initialized_);
  return init_sec_context_(minor_status,
                           initiator_cred_handle,
                           context_handle,
                           target_name,
                           mech_type,
                           req_flags,
                           time_req,
                           input_chan_bindings,
                           input_token,
                           actual_mech_type,
                           output_token,
                           ret_flags,
                           time_rec);
}

OM_uint32 GSSAPISharedLibrary::wrap_size_limit(
    OM_uint32* minor_status,
    const gss_ctx_id_t context_handle,
    int conf_req_flag,
    gss_qop_t qop_req,
    OM_uint32 req_output_size,
    OM_uint32* max_input_size) {
  DCHECK(initialized_);
  return wrap_size_limit_(minor_status,
                          context_handle,
                          conf_req_flag,
                          qop_req,
                          req_output_size,
                          max_input_size);
}

OM_uint32 GSSAPISharedLibrary::delete_sec_context(
    OM_uint32* minor_status,
    gss_ctx_id_t* context_handle,
    gss_buffer_t output_token) {
  // This is called from the owner class' destructor, even if
  // Init() is not called, so we can't assume |initialized_|
  // is set.
  if (!initialized_)
    return 0;
  return delete_sec_context_(minor_status,
                             context_handle,
                             output_token);
}

OM_uint32 GSSAPISharedLibrary::inquire_context(
    OM_uint32* minor_status,
    const gss_ctx_id_t context_handle,
    gss_name_t* src_name,
    gss_name_t* targ_name,
    OM_uint32* lifetime_rec,
    gss_OID* mech_type,
    OM_uint32* ctx_flags,
    int* locally_initiated,
    int* open) {
  DCHECK(initialized_);
  return inquire_context_(minor_status,
                          context_handle,
                          src_name,
                          targ_name,
                          lifetime_rec,
                          mech_type,
                          ctx_flags,
                          locally_initiated,
                          open);
}

const std::string& GSSAPISharedLibrary::GetLibraryNameForTesting() {
  return gssapi_library_name_;
}

ScopedSecurityContext::ScopedSecurityContext(GSSAPILibrary* gssapi_lib)
    : security_context_(GSS_C_NO_CONTEXT),
      gssapi_lib_(gssapi_lib) {
  DCHECK(gssapi_lib_);
}

ScopedSecurityContext::~ScopedSecurityContext() {
  if (security_context_ != GSS_C_NO_CONTEXT) {
    gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
    OM_uint32 minor_status = 0;
    OM_uint32 major_status = gssapi_lib_->delete_sec_context(
        &minor_status, &security_context_, &output_token);
    DLOG_IF(WARNING, major_status != GSS_S_COMPLETE)
        << "Problem releasing security_context. "
        << GetGssStatusValue(gssapi_lib_, "delete_sec_context", major_status,
                             minor_status);
    security_context_ = GSS_C_NO_CONTEXT;
  }
}

HttpAuthGSSAPI::HttpAuthGSSAPI(GSSAPILibrary* library, gss_OID gss_oid)
    : gss_oid_(gss_oid), library_(library), scoped_sec_context_(library) {
  DCHECK(library_);
}

HttpAuthGSSAPI::~HttpAuthGSSAPI() = default;

bool HttpAuthGSSAPI::Init(const NetLogWithSource& net_log) {
  if (!library_)
    return false;
  return library_->Init(net_log);
}

bool HttpAuthGSSAPI::NeedsIdentity() const {
  return decoded_server_auth_token_.empty();
}

bool HttpAuthGSSAPI::AllowsExplicitCredentials() const {
#if BUILDFLAG(IS_CHROMEOS)
  if (base::FeatureList::IsEnabled(features::kKerberosInBrowserRedirect)) {
    return true;
  } else {
    return false;
  }
#else
  return false;
#endif
}

void HttpAuthGSSAPI::SetDelegation(DelegationType delegation_type) {
  delegation_type_ = delegation_type;
}

HttpAuth::AuthorizationResult HttpAuthGSSAPI::ParseChallenge(
    HttpAuthChallengeTokenizer* tok) {
  if (scoped_sec_context_.get() == GSS_C_NO_CONTEXT) {
    return ParseFirstRoundChallenge(HttpAuth::AUTH_SCHEME_NEGOTIATE, tok);
  }
  std::string encoded_auth_token;
  return ParseLaterRoundChallenge(HttpAuth::AUTH_SCHEME_NEGOTIATE, tok,
                                  &encoded_auth_token,
                                  &decoded_server_auth_token_);
}

int HttpAuthGSSAPI::GenerateAuthToken(const AuthCredentials* credentials,
                                      const std::string& spn,
                                      const std::string& channel_bindings,
                                      std::string* auth_token,
                                      const NetLogWithSource& net_log,
                                      CompletionOnceCallback /*callback*/) {
  DCHECK(auth_token);

  gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
  input_token.length = decoded_server_auth_token_.length();
  input_token.value = (input_token.length > 0)
                          ? const_cast<char*>(decoded_server_auth_token_.data())
                          : nullptr;
  gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
  ScopedBuffer scoped_output_token(&output_token, library_);
  int rv = GetNextSecurityToken(spn, channel_bindings, &input_token,
                                &output_token, net_log);
  if (rv != OK)
    return rv;

  // Base64 encode data in output buffer and prepend the scheme.
  std::string encode_input(static_cast<char*>(output_token.value),
                           output_token.length);
  std::string encode_output = base::Base64Encode(encode_input);
  *auth_token = "Negotiate " + encode_output;
  return OK;
}

namespace {

// GSSAPI status codes consist of a calling error (essentially, a programmer
// bug), a routine error (defined by the RFC), and supplementary information,
// all bitwise-or'ed together in different regions of the 32 bit return value.
// This means a simple switch on the return codes is not sufficient.

int MapImportNameStatusToError(OM_uint32 major_status) {
  if (major_status == GSS_S_COMPLETE)
    return OK;
  if (GSS_CALLING_ERROR(major_status) != 0)
    return ERR_UNEXPECTED;
  OM_uint32 routine_error = GSS_ROUTINE_ERROR(major_status);
  switch (routine_error) {
    case GSS_S_FAILURE:
      // Looking at the MIT Kerberos implementation, this typically is returned
      // when memory allocation fails. However, the API does not guarantee
      // that this is the case, so using ERR_UNEXPECTED rather than
      // ERR_OUT_OF_MEMORY.
      return ERR_UNEXPECTED_SECURITY_LIBRARY_STATUS;
    case GSS_S_BAD_NAME:
    case GSS_S_BAD_NAMETYPE:
      return ERR_MALFORMED_IDENTITY;
    case GSS_S_DEFECTIVE_TOKEN:
      // Not mentioned in the API, but part of code.
      return ERR_UNEXPECTED_SECURITY_LIBRARY_STATUS;
    case GSS_S_BAD_MECH:
      return ERR_UNSUPPORTED_AUTH_SCHEME;
    default:
      return ERR_UNDOCUMENTED_SECURITY_LIBRARY_STATUS;
  }
}

int MapInitSecContextStatusToError(OM_uint32 major_status) {
  // Although GSS_S_CONTINUE_NEEDED is an additional bit, it seems like
  // other code just checks if major_status is equivalent to it to indicate
  // that there are no other errors included.
  if (major_status == GSS_S_COMPLETE || major_status == GSS_S_CONTINUE_NEEDED)
    return OK;
  if (GSS_CALLING_ERROR(major_status) != 0)
    return ERR_UNEXPECTED;
  OM_uint32 routine_status = GSS_ROUTINE_ERROR(major_status);
  switch (routine_status) {
    case GSS_S_DEFECTIVE_TOKEN:
      return ERR_INVALID_RESPONSE;
    case GSS_S_DEFECTIVE_CREDENTIAL:
      // Not expected since this implementation uses the default credential.
      return ERR_UNEXPECTED_SECURITY_LIBRARY_STATUS;
    case GSS_S_BAD_SIG:
      // Probably won't happen, but it's a bad response.
      return ERR_INVALID_RESPONSE;
    case GSS_S_NO_CRED:
      return ERR_INVALID_AUTH_CREDENTIALS;
    case GSS_S_CREDENTIALS_EXPIRED:
      return ERR_INVALID_AUTH_CREDENTIALS;
    case GSS_S_BAD_BINDINGS:
      // This only happens with mutual authentication.
      return ERR_UNEXPECTED_SECURITY_LIBRARY_STATUS;
    case GSS_S_NO_CONTEXT:
      return ERR_UNEXPECTED_SECURITY_LIBRARY_STATUS;
    case GSS_S_BAD_NAMETYPE:
      return ERR_UNSUPPORTED_AUTH_SCHEME;
    case GSS_S_BAD_NAME:
      return ERR_UNSUPPORTED_AUTH_SCHEME;
    case GSS_S_BAD_MECH:
      return ERR_UNEXPECTED_SECURITY_LIBRARY_STATUS;
    case GSS_S_FAILURE:
      // This should be an "Unexpected Security Status" according to the
      // GSSAPI documentation, but it's typically used to indicate that
      // credentials are not correctly set up on a user machine, such
      // as a missing credential cache or hitting this after calling
      // kdestroy.
      // TODO(cbentzel): Use minor code for even better mapping?
      return ERR_MISSING_AUTH_CREDENTIALS;
    default:
      if (routine_status != 0)
        return ERR_UNDOCUMENTED_SECURITY_LIBRARY_STATUS;
      break;
  }
  OM_uint32 supplemental_status = GSS_SUPPLEMENTARY_INFO(major_status);
  // Replays could indicate an attack.
  if (supplemental_status & (GSS_S_DUPLICATE_TOKEN | GSS_S_OLD_TOKEN |
                             GSS_S_UNSEQ_TOKEN | GSS_S_GAP_TOKEN))
    return ERR_INVALID_RESPONSE;

  // At this point, every documented status has been checked.
  return ERR_UNDOCUMENTED_SECURITY_LIBRARY_STATUS;
}

base::Value::Dict ImportNameErrorParams(GSSAPILibrary* library,
                                        std::string_view spn,
                                        OM_uint32 major_status,
                                        OM_uint32 minor_status) {
  base::Value::Dict params;
  params.Set("spn", spn);
  if (major_status != GSS_S_COMPLETE)
    params.Set("status", GetGssStatusValue(library, "import_name", major_status,
                                           minor_status));
  return params;
}

base::Value::Dict InitSecContextErrorParams(GSSAPILibrary* library,
                                            gss_ctx_id_t context,
                                            OM_uint32 major_status,
                                            OM_uint32 minor_status) {
  base::Value::Dict params;
  if (major_status != GSS_S_COMPLETE)
    params.Set("status", GetGssStatusValue(library, "gss_init_sec_context",
                                           major_status, minor_status));
  if (context != GSS_C_NO_CONTEXT)
    params.Set("context", GetContextStateAsValue(library, context));
  return params;
}

}  // anonymous namespace

int HttpAuthGSSAPI::GetNextSecurityToken(const std::string& spn,
                                         const std::string& channel_bindings,
                                         gss_buffer_t in_token,
                                         gss_buffer_t out_token,
                                         const NetLogWithSource& net_log) {
  // GSSAPI header files, to this day, require OIDs passed in as non-const
  // pointers. Rather than const casting, let's just leave this as non-const.
  // Even if the OID pointer is const, the inner |elements| pointer is still
  // non-const.
  static gss_OID_desc kGSS_C_NT_HOSTBASED_SERVICE = {
      10, const_cast<char*>("\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x04")};

  // Create a name for the principal
  // TODO(cbentzel): Just do this on the first pass?
  std::string spn_principal = spn;
  gss_buffer_desc spn_buffer = GSS_C_EMPTY_BUFFER;
  spn_buffer.value = const_cast<char*>(spn_principal.c_str());
  spn_buffer.length = spn_principal.size() + 1;
  OM_uint32 minor_status = 0;
  gss_name_t principal_name = GSS_C_NO_NAME;

  OM_uint32 major_status =
      library_->import_name(&minor_status, &spn_buffer,
                            &kGSS_C_NT_HOSTBASED_SERVICE, &principal_name);
  net_log.AddEvent(NetLogEventType::AUTH_LIBRARY_IMPORT_NAME, [&] {
    return ImportNameErrorParams(library_, spn, major_status, minor_status);
  });
  int rv = MapImportNameStatusToError(major_status);
  if (rv != OK)
    return rv;
  ScopedName scoped_name(principal_name, library_);

  // Continue creating a security context.
  net_log.BeginEvent(NetLogEventType::AUTH_LIBRARY_INIT_SEC_CTX);
  major_status = library_->init_sec_context(
      &minor_status, GSS_C_NO_CREDENTIAL, scoped_sec_context_.receive(),
      principal_name, gss_oid_, DelegationTypeToFlag(delegation_type_),
      GSS_C_INDEFINITE, GSS_C_NO_CHANNEL_BINDINGS, in_token,
      nullptr,  // actual_mech_type
      out_token,
      nullptr,  // ret flags
      nullptr);
  net_log.EndEvent(NetLogEventType::AUTH_LIBRARY_INIT_SEC_CTX, [&] {
    return InitSecContextErrorParams(library_, scoped_sec_context_.get(),
                                     major_status, minor_status);
  });
  return MapInitSecContextStatusToError(major_status);
}

}  // namespace net

"""

```