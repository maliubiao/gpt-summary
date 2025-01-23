Response:
Let's break down the thought process for analyzing this C++ code and generating the response.

1. **Understand the Goal:** The request asks for the functionality of the `http_auth_sspi_win.cc` file, its relationship to JavaScript, how to trigger it, common errors, and examples of input/output.

2. **Initial Code Scan (Keywords and Structure):**  Read through the code, looking for key terms and the overall structure. Notice `#include`, namespaces (`net`), classes (`HttpAuthSSPI`, `SSPILibrary`), functions like `AcquireCredentialsHandle`, `InitializeSecurityContext`, and mentions of Windows-specific APIs (SSPI). This immediately suggests a Windows-specific authentication mechanism.

3. **Identify the Core Functionality:** The file's name (`http_auth_sspi_win.cc`) strongly hints at handling HTTP authentication using SSPI (Security Support Provider Interface) on Windows. The code confirms this with calls to Windows SSPI functions. The `HttpAuthSSPI` class is likely the main orchestrator.

4. **Deconstruct Key Functions:** Examine the purpose of major functions:
    * `AcquireCredentialsHandle`:  Obtains credentials for authentication. Notices the `SEC_WINNT_AUTH_IDENTITY` structure, hinting at username/password usage. Two versions exist: one for explicit credentials and one for default credentials.
    * `InitializeSecurityContext`: The core SSPI function for establishing a security context (authentication handshake). It takes input tokens and generates output tokens.
    * `GenerateAuthToken`:  Combines the credential acquisition and security context initialization to produce the actual authentication token sent to the server. It involves base64 encoding.
    * `ParseChallenge`:  Handles the server's authentication challenges, likely part of a multi-step authentication process.
    * Helper functions (`Map...StatusToError`, `SplitDomainAndUser`, etc.):  These provide utility and error handling.

5. **Relate to HTTP Authentication:**  Connect the SSPI concepts to standard HTTP authentication schemes like Negotiate (Kerberos/SPNEGO) and NTLM. The `scheme_` member and the prefixes "Negotiate" and "NTLM" in `GenerateAuthToken` confirm this.

6. **JavaScript Connection:** Consider how JavaScript interacts with web authentication. JavaScript itself doesn't directly call SSPI. The browser (Chromium, in this case) handles the SSPI part. JavaScript might trigger this through:
    * Fetch API/XMLHttpRequest requests to servers requiring Windows authentication.
    * Setting `withCredentials` to `true` for cross-origin requests.
    * Browser settings related to integrated authentication.

7. **Logical Reasoning (Input/Output):**  Imagine a simplified flow:
    * **Input:** A server sends a `WWW-Authenticate: Negotiate` or `WWW-Authenticate: NTLM` header.
    * **SSPI Processing:**  Chromium uses `HttpAuthSSPI` to handle this. It might involve multiple rounds of `InitializeSecurityContext` to exchange tokens.
    * **Output:**  Chromium sends an `Authorization: Negotiate <token>` or `Authorization: NTLM <token>` header back to the server.
    * Consider edge cases: invalid credentials, unsupported schemes.

8. **User/Programming Errors:**  Think about common mistakes developers or users might make:
    * Incorrect username/password.
    * Misconfigured server (not expecting Windows authentication).
    * Trying to use SSPI on non-Windows platforms (programming error).
    * Issues with domain membership or network connectivity.

9. **Debugging Steps:** Trace how a user's action might lead to this code being executed:
    * User types a URL or clicks a link.
    * Browser sends an initial request.
    * Server responds with a 401 and a `WWW-Authenticate` header.
    * Chromium's network stack identifies the Negotiate or NTLM scheme.
    * The `HttpAuthSSPI` class is instantiated.
    * `ParseChallenge` is called.
    * `GenerateAuthToken` is called (potentially multiple times).

10. **Structure the Response:** Organize the findings into clear sections: Functionality, JavaScript Relationship, Logical Reasoning, Usage Errors, and Debugging. Use bullet points and code snippets to make it easy to read.

11. **Refine and Review:** Go back through the response to ensure accuracy, clarity, and completeness. Check for any inconsistencies or areas that need further explanation. For example, ensure the examples in the JavaScript section are concrete and illustrate the connection.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This is just about authentication."
* **Correction:**  Realize it's *specifically* about *Windows-integrated* authentication using SSPI.
* **Initial thought:** "JavaScript directly calls this code."
* **Correction:** Understand that JavaScript triggers the *browser* to use this code, not a direct function call. Clarify the role of the Fetch API and `withCredentials`.
* **Initial thought:** "Just list the functions."
* **Correction:** Explain the *purpose* of each key function and how they relate to the overall authentication process. Provide context.
* **Initial thought:**  Focus only on successful authentication.
* **Correction:**  Include common error scenarios and how they might manifest.

By following this iterative process of understanding, analyzing, connecting concepts, and refining the explanation, the comprehensive and accurate response can be generated.
这个文件 `net/http/http_auth_sspi_win.cc` 是 Chromium 网络栈中专门用于处理 **基于 Windows SSPI (Security Support Provider Interface) 的 HTTP 身份验证** 的源代码文件。它实现了客户端在与服务器进行需要 Windows 身份验证（通常是 Negotiate/Kerberos 或 NTLM 协议）的 HTTP 请求时的认证逻辑。

以下是它的主要功能：

**1. SSPI 认证流程管理:**

* **初始化安全上下文:** 使用 Windows SSPI API (`AcquireCredentialsHandle`, `InitializeSecurityContext`) 来建立与服务器的安全上下文。这个过程可能需要多次往返（即多次调用 `InitializeSecurityContext`）。
* **生成认证令牌:** 根据服务器的挑战（challenge），生成相应的认证令牌（token）。这些令牌会被添加到 HTTP 请求的 `Authorization` 头中。
* **处理服务器挑战:** 解析服务器发送的 `WWW-Authenticate` 头信息，提取认证协议和相关的令牌，并用于下一步的认证过程。
* **管理凭据:**  处理用户的身份凭据（用户名和密码），或者使用默认的 Windows 登录凭据。
* **支持 Negotiate 和 NTLM 协议:**  该文件主要处理这两种基于 SSPI 的 HTTP 认证协议。

**2. 与网络栈的集成:**

* **HttpAuth 接口的实现:**  实现了 Chromium 网络栈中定义的 `HttpAuth` 接口，使得它能够作为一种认证方案被网络栈调用。
* **NetLog 集成:** 使用 Chromium 的 NetLog 系统记录认证过程中的关键事件和状态，方便调试。

**3. 错误处理和状态管理:**

* **映射 SSPI 错误:** 将 Windows SSPI API 返回的错误码映射到 Chromium 的网络错误码 (`net::Error`)。
* **管理安全上下文生命周期:**  创建、使用和销毁 SSPI 安全上下文。

**4. 其他辅助功能:**

* **Base64 编码:** 对生成的 SSPI 令牌进行 Base64 编码，以便作为 HTTP 头的值传输。
* **字符串处理:**  处理 UTF-8 和 UTF-16 之间的转换，以及域名和用户名的分割。

**与 JavaScript 的关系:**

这个 C++ 文件本身不包含 JavaScript 代码，它属于 Chromium 浏览器的底层网络实现。然而，它处理的身份验证过程是由 JavaScript 发起的 HTTP 请求触发的。

**举例说明:**

假设一个网页上的 JavaScript 代码使用 `fetch` API 向一个需要 Windows 身份验证的网站发起请求：

```javascript
fetch('https://your-internal-website.example.com/api/data', {
  credentials: 'include' // 或者 'same-origin'，取决于具体情况
})
.then(response => {
  // 处理响应
})
.catch(error => {
  // 处理错误
});
```

当浏览器发送这个请求时，如果服务器返回 `401 Unauthorized` 状态码，并且 `WWW-Authenticate` 头包含 `Negotiate` 或 `NTLM`，那么 Chromium 的网络栈会调用 `net/http/http_auth_sspi_win.cc` 中的代码来处理认证。

* **JavaScript 发起请求:**  `fetch` 调用指示浏览器需要进行身份验证。
* **服务器返回挑战:** 服务器发送包含 `WWW-Authenticate: Negotiate` 或 `WWW-Authenticate: NTLM` 的响应。
* **C++ 代码介入:** `HttpAuthSSPI::ParseChallenge` 会被调用来解析服务器的挑战。
* **生成认证令牌:** `HttpAuthSSPI::GenerateAuthToken` 会根据挑战和用户凭据（如果需要）生成认证令牌。
* **浏览器发送认证信息:** 浏览器将生成的令牌添加到新的请求头 `Authorization: Negotiate <token>` 或 `Authorization: NTLM <token>`，并重新发送请求。

**逻辑推理 (假设输入与输出):**

**假设输入:**

1. **服务器响应头:** `WWW-Authenticate: Negotiate`
2. **用户环境:**  用户已登录到 Windows 域环境。

**输出:**

1. **`HttpAuthSSPI::ParseChallenge` 的行为:**  会识别出 `Negotiate` 协议，并准备进行第一轮的认证。由于是第一轮，通常 `decoded_server_auth_token_` 会是空的。
2. **`HttpAuthSSPI::GenerateAuthToken` 的行为:**
   * 如果没有提供显式凭据，则会尝试获取默认的 Windows 登录凭据。
   * 调用 Windows SSPI API (`AcquireCredentialsHandle`, `InitializeSecurityContext`) 生成一个 SPNEGO 或 Kerberos 令牌。
   * 将生成的令牌进行 Base64 编码。
   * 返回的 `auth_token` 字符串会是类似 `Negotiate YII...` 的格式。

**假设输入:**

1. **服务器响应头:** `WWW-Authenticate: Negotiate YIIEiwYJKoZIhvcNAQcCoYIBBDCCAQgCAQExCzAJBgUrDgMCGgUAMGkGCSqGSIb3DQEHAi9iME4GCyqGSIb3DQEJARYeaHR0cDovL2FkLmNocm9taXVtLm9yZy9uZXRsb2cvdXJsPWh0dHA6Ly9leGFtcGxlLmNvbTAKggEWBgorBgEEAYI3AgIKoU0FOzBJAgEBBgorBgEEAYI3AgIBA6FFAgQxUjAwMQYKCisGAQQBggcCAQwBoCcEJjEyMzQ1Njc4OQYKKwYBBAGCNwIBDCCABgwcAQIBBgorBgEEAYI3AgEGMRAxADABMAAwCgIEAQapAwQCAAEwggEABIGAvYSJd796u0vH4Lq4l2m0R+2mG/J7n/iXb35/Y0jZ8P+V0g+` (一个实际的 Negotiate 令牌)

**输出:**

1. **`HttpAuthSSPI::ParseChallenge` 的行为:** 会识别出 `Negotiate` 协议，并将 Base64 解码后的令牌存储在 `decoded_server_auth_token_` 中。

**用户或编程常见的使用错误:**

1. **凭据错误:**
   * **用户错误:** 输入错误的用户名或密码。这将导致 SSPI 认证失败，`AcquireExplicitCredentials` 或 `InitializeSecurityContext` 返回错误，最终导致 HTTP 请求失败。
   * **编程错误:** 在需要提供凭据的情况下，没有正确地设置 `AuthCredentials` 对象。

2. **SSPI 配置问题:**
   * **用户或系统管理员错误:** Windows 上的 SSPI 配置不正确，例如 Kerberos 配置问题，可能导致认证失败。Chromium 会映射 SSPI 错误到 `ERR_MISCONFIGURED_AUTH_ENVIRONMENT` 等错误。

3. **SPN (Service Principal Name) 错误:**
   * **编程错误:**  在某些情况下，可能需要指定 SPN。如果 SPN 不正确，`InitializeSecurityContext` 可能会失败。

4. **跨域问题和凭据传递:**
   * **编程错误:**  在跨域请求中，如果没有正确设置 `credentials: 'include'`，浏览器可能不会发送认证信息。

5. **不支持的身份验证方案:**
   * **编程错误:**  尝试使用此代码处理非 Negotiate 或 NTLM 的身份验证方案。Chromium 会返回 `ERR_UNSUPPORTED_AUTH_SCHEME`。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器地址栏输入 URL 或点击链接。**
2. **浏览器发起 HTTP 请求到服务器。**
3. **服务器检测到用户未认证，返回 HTTP 状态码 `401 Unauthorized`。**
4. **服务器的响应头中包含 `WWW-Authenticate: Negotiate` 或 `WWW-Authenticate: NTLM`。**
5. **Chromium 的网络栈接收到这个响应。**
6. **网络栈识别出需要使用 SSPI 进行身份验证。**
7. **实例化 `HttpAuthSSPI` 对象，并设置相应的认证方案（Negotiate 或 NTLM）。**
8. **调用 `HttpAuthSSPI::ParseChallenge` 方法解析服务器的挑战。**
9. **如果需要生成认证令牌（通常是第一轮或后续轮），则调用 `HttpAuthSSPI::GenerateAuthToken` 方法。**
   * 如果需要用户凭据，并且之前没有提供，浏览器可能会弹出身份验证对话框。
   * `AcquireCredentialsHandle` 函数会被调用以获取凭据句柄。
   * `InitializeSecurityContext` 函数会被调用以生成认证令牌。
10. **生成的认证令牌会被添加到新的 HTTP 请求的 `Authorization` 头中。**
11. **浏览器重新发送带有认证信息的 HTTP 请求。**

**调试线索:**

* **NetLog:** Chromium 的 NetLog 是最重要的调试工具。它会记录 `AUTH_LIBRARY_ACQUIRE_CREDS` 和 `AUTH_LIBRARY_INIT_SEC_CTX` 等事件，包含详细的 SSPI 调用信息，如错误码、上下文属性等。
* **抓包工具 (如 Wireshark):**  可以捕获客户端和服务器之间的 HTTP 交互，查看 `WWW-Authenticate` 和 `Authorization` 头的内容，以及可能的 Kerberos/NTLM 协议交互。
* **Windows 事件查看器:**  有时 SSPI 相关的错误也会记录在 Windows 的系统或安全日志中。

通过以上分析，我们可以了解到 `net/http/http_auth_sspi_win.cc` 文件在 Chromium 网络栈中扮演着关键的角色，负责处理 Windows 环境下特定的 HTTP 身份验证流程，并且与用户操作和 JavaScript 代码的请求有着紧密的联系。

### 提示词
```
这是目录为net/http/http_auth_sspi_win.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2011 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

// See "SSPI Sample Application" at
// http://msdn.microsoft.com/en-us/library/aa918273.aspx

#include "net/http/http_auth_sspi_win.h"

#include "base/base64.h"
#include "base/logging.h"
#include "base/notreached.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_string_conversions.h"
#include "base/values.h"
#include "net/base/net_errors.h"
#include "net/http/http_auth.h"
#include "net/http/http_auth_multi_round_parse.h"
#include "net/log/net_log.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_values.h"
#include "net/log/net_log_with_source.h"

namespace net {
using DelegationType = HttpAuth::DelegationType;

namespace {

base::Value::Dict SecurityStatusToValue(Error mapped_error,
                                        SECURITY_STATUS status) {
  base::Value::Dict params;
  params.Set("net_error", mapped_error);
  params.Set("security_status", static_cast<int>(status));
  return params;
}

base::Value::Dict AcquireCredentialsHandleParams(const std::u16string* domain,
                                                 const std::u16string* user,
                                                 Error result,
                                                 SECURITY_STATUS status) {
  base::Value::Dict params;
  if (domain && user) {
    params.Set("domain", base::UTF16ToUTF8(*domain));
    params.Set("user", base::UTF16ToUTF8(*user));
  }
  params.Set("status", SecurityStatusToValue(result, status));
  return params;
}

base::Value::Dict ContextFlagsToValue(DWORD flags) {
  base::Value::Dict params;
  params.Set("value", base::StringPrintf("0x%08lx", flags));
  params.Set("delegated", (flags & ISC_RET_DELEGATE) == ISC_RET_DELEGATE);
  params.Set("mutual", (flags & ISC_RET_MUTUAL_AUTH) == ISC_RET_MUTUAL_AUTH);
  return params;
}

base::Value::Dict ContextAttributesToValue(SSPILibrary* library,
                                           PCtxtHandle handle,
                                           DWORD attributes) {
  base::Value::Dict params;

  SecPkgContext_NativeNames native_names = {0};
  auto qc_result = library->QueryContextAttributesEx(
      handle, SECPKG_ATTR_NATIVE_NAMES, &native_names, sizeof(native_names));
  if (qc_result == SEC_E_OK && native_names.sClientName &&
      native_names.sServerName) {
    params.Set("source", base::as_u16cstr(native_names.sClientName));
    params.Set("target", base::as_u16cstr(native_names.sServerName));
  }

  SecPkgContext_NegotiationInfo negotiation_info = {0};
  qc_result = library->QueryContextAttributesEx(
      handle, SECPKG_ATTR_NEGOTIATION_INFO, &negotiation_info,
      sizeof(negotiation_info));
  if (qc_result == SEC_E_OK && negotiation_info.PackageInfo &&
      negotiation_info.PackageInfo->Name) {
    params.Set("mechanism",
               base::as_u16cstr(negotiation_info.PackageInfo->Name));
    params.Set("open", negotiation_info.NegotiationState !=
                           SECPKG_NEGOTIATION_COMPLETE);
  }

  SecPkgContext_Authority authority = {0};
  qc_result = library->QueryContextAttributesEx(handle, SECPKG_ATTR_AUTHORITY,
                                                &authority, sizeof(authority));
  if (qc_result == SEC_E_OK && authority.sAuthorityName) {
    params.Set("authority", base::as_u16cstr(authority.sAuthorityName));
  }

  params.Set("flags", ContextFlagsToValue(attributes));
  return params;
}

base::Value::Dict InitializeSecurityContextParams(SSPILibrary* library,
                                                  PCtxtHandle handle,
                                                  Error result,
                                                  SECURITY_STATUS status,
                                                  DWORD attributes) {
  base::Value::Dict params;
  params.Set("status", SecurityStatusToValue(result, status));
  if (result == OK) {
    params.Set("context",
               ContextAttributesToValue(library, handle, attributes));
  }
  return params;
}

Error MapAcquireCredentialsStatusToError(SECURITY_STATUS status) {
  switch (status) {
    case SEC_E_OK:
      return OK;
    case SEC_E_INSUFFICIENT_MEMORY:
      return ERR_OUT_OF_MEMORY;
    case SEC_E_INTERNAL_ERROR:
      return ERR_UNEXPECTED_SECURITY_LIBRARY_STATUS;
    case SEC_E_NO_CREDENTIALS:
    case SEC_E_NOT_OWNER:
    case SEC_E_UNKNOWN_CREDENTIALS:
      return ERR_INVALID_AUTH_CREDENTIALS;
    case SEC_E_SECPKG_NOT_FOUND:
      // This indicates that the SSPI configuration does not match expectations
      return ERR_UNSUPPORTED_AUTH_SCHEME;
    default:
      return ERR_UNDOCUMENTED_SECURITY_LIBRARY_STATUS;
  }
}

Error AcquireExplicitCredentials(SSPILibrary* library,
                                 const std::u16string& domain,
                                 const std::u16string& user,
                                 const std::u16string& password,
                                 const NetLogWithSource& net_log,
                                 CredHandle* cred) {
  SEC_WINNT_AUTH_IDENTITY identity;
  identity.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
  identity.User = reinterpret_cast<unsigned short*>(
      const_cast<wchar_t*>(base::as_wcstr(user)));
  identity.UserLength = user.size();
  identity.Domain = reinterpret_cast<unsigned short*>(
      const_cast<wchar_t*>(base::as_wcstr(domain)));
  identity.DomainLength = domain.size();
  identity.Password = reinterpret_cast<unsigned short*>(
      const_cast<wchar_t*>(base::as_wcstr(password)));
  identity.PasswordLength = password.size();

  TimeStamp expiry;

  net_log.BeginEvent(NetLogEventType::AUTH_LIBRARY_ACQUIRE_CREDS);

  // Pass the username/password to get the credentials handle.
  SECURITY_STATUS status = library->AcquireCredentialsHandle(
      nullptr,                          // pszPrincipal
      SECPKG_CRED_OUTBOUND,             // fCredentialUse
      nullptr,                          // pvLogonID
      &identity,                        // pAuthData
      nullptr,                          // pGetKeyFn (not used)
      nullptr,                          // pvGetKeyArgument (not used)
      cred,                             // phCredential
      &expiry);                         // ptsExpiry

  auto result = MapAcquireCredentialsStatusToError(status);
  net_log.EndEvent(NetLogEventType::AUTH_LIBRARY_ACQUIRE_CREDS, [&] {
    return AcquireCredentialsHandleParams(&domain, &user, result, status);
  });
  return result;
}

Error AcquireDefaultCredentials(SSPILibrary* library,
                                const NetLogWithSource& net_log,
                                CredHandle* cred) {
  TimeStamp expiry;
  net_log.BeginEvent(NetLogEventType::AUTH_LIBRARY_ACQUIRE_CREDS);

  // Pass the username/password to get the credentials handle.
  // Note: Since the 5th argument is nullptr, it uses the default
  // cached credentials for the logged in user, which can be used
  // for a single sign-on.
  SECURITY_STATUS status = library->AcquireCredentialsHandle(
      nullptr,                          // pszPrincipal
      SECPKG_CRED_OUTBOUND,             // fCredentialUse
      nullptr,                          // pvLogonID
      nullptr,                          // pAuthData
      nullptr,                          // pGetKeyFn (not used)
      nullptr,                          // pvGetKeyArgument (not used)
      cred,                             // phCredential
      &expiry);                         // ptsExpiry

  auto result = MapAcquireCredentialsStatusToError(status);
  net_log.EndEvent(NetLogEventType::AUTH_LIBRARY_ACQUIRE_CREDS, [&] {
    return AcquireCredentialsHandleParams(nullptr, nullptr, result, status);
  });
  return result;
}

Error MapInitializeSecurityContextStatusToError(SECURITY_STATUS status) {
  switch (status) {
    case SEC_E_OK:
    case SEC_I_CONTINUE_NEEDED:
      return OK;
    case SEC_I_COMPLETE_AND_CONTINUE:
    case SEC_I_COMPLETE_NEEDED:
    case SEC_I_INCOMPLETE_CREDENTIALS:
    case SEC_E_INCOMPLETE_MESSAGE:
    case SEC_E_INTERNAL_ERROR:
      // These are return codes reported by InitializeSecurityContext
      // but not expected by Chrome (for example, INCOMPLETE_CREDENTIALS
      // and INCOMPLETE_MESSAGE are intended for schannel).
      return ERR_UNEXPECTED_SECURITY_LIBRARY_STATUS;
    case SEC_E_INSUFFICIENT_MEMORY:
      return ERR_OUT_OF_MEMORY;
    case SEC_E_UNSUPPORTED_FUNCTION:
      DUMP_WILL_BE_NOTREACHED();
      return ERR_UNEXPECTED;
    case SEC_E_INVALID_HANDLE:
      DUMP_WILL_BE_NOTREACHED();
      return ERR_INVALID_HANDLE;
    case SEC_E_INVALID_TOKEN:
      return ERR_INVALID_RESPONSE;
    case SEC_E_LOGON_DENIED:
    case SEC_E_NO_CREDENTIALS:
    case SEC_E_WRONG_PRINCIPAL:
      return ERR_INVALID_AUTH_CREDENTIALS;
    case SEC_E_NO_AUTHENTICATING_AUTHORITY:
    case SEC_E_TARGET_UNKNOWN:
      return ERR_MISCONFIGURED_AUTH_ENVIRONMENT;
    default:
      return ERR_UNDOCUMENTED_SECURITY_LIBRARY_STATUS;
  }
}

Error MapQuerySecurityPackageInfoStatusToError(SECURITY_STATUS status) {
  switch (status) {
    case SEC_E_OK:
      return OK;
    case SEC_E_SECPKG_NOT_FOUND:
      // This isn't a documented return code, but has been encountered
      // during testing.
      return ERR_UNSUPPORTED_AUTH_SCHEME;
    default:
      return ERR_UNDOCUMENTED_SECURITY_LIBRARY_STATUS;
  }
}

Error MapFreeContextBufferStatusToError(SECURITY_STATUS status) {
  switch (status) {
    case SEC_E_OK:
      return OK;
    default:
      // The documentation at
      // http://msdn.microsoft.com/en-us/library/aa375416(VS.85).aspx
      // only mentions that a non-zero (or non-SEC_E_OK) value is returned
      // if the function fails, and does not indicate what the failure
      // conditions are.
      return ERR_UNDOCUMENTED_SECURITY_LIBRARY_STATUS;
  }
}

}  // anonymous namespace

Error SSPILibrary::DetermineMaxTokenLength(ULONG* max_token_length) {
  if (!is_supported_)
    return ERR_UNSUPPORTED_AUTH_SCHEME;

  if (max_token_length_ != 0) {
    *max_token_length = max_token_length_;
    return OK;
  }

  DCHECK(max_token_length);
  PSecPkgInfo pkg_info = nullptr;
  is_supported_ = false;

  SECURITY_STATUS status = QuerySecurityPackageInfo(&pkg_info);
  Error rv = MapQuerySecurityPackageInfoStatusToError(status);
  if (rv != OK)
    return rv;
  int token_length = pkg_info->cbMaxToken;

  status = FreeContextBuffer(pkg_info);
  rv = MapFreeContextBufferStatusToError(status);
  if (rv != OK)
    return rv;
  *max_token_length = max_token_length_ = token_length;
  is_supported_ = true;
  return OK;
}

SECURITY_STATUS SSPILibraryDefault::AcquireCredentialsHandle(
    LPWSTR pszPrincipal,
    unsigned long fCredentialUse,
    void* pvLogonId,
    void* pvAuthData,
    SEC_GET_KEY_FN pGetKeyFn,
    void* pvGetKeyArgument,
    PCredHandle phCredential,
    PTimeStamp ptsExpiry) {
  return ::AcquireCredentialsHandleW(
      pszPrincipal, const_cast<LPWSTR>(package_name_.c_str()), fCredentialUse,
      pvLogonId, pvAuthData, pGetKeyFn, pvGetKeyArgument, phCredential,
      ptsExpiry);
}

SECURITY_STATUS SSPILibraryDefault::InitializeSecurityContext(
    PCredHandle phCredential,
    PCtxtHandle phContext,
    SEC_WCHAR* pszTargetName,
    unsigned long fContextReq,
    unsigned long Reserved1,
    unsigned long TargetDataRep,
    PSecBufferDesc pInput,
    unsigned long Reserved2,
    PCtxtHandle phNewContext,
    PSecBufferDesc pOutput,
    unsigned long* contextAttr,
    PTimeStamp ptsExpiry) {
  return ::InitializeSecurityContextW(phCredential, phContext, pszTargetName,
                                      fContextReq, Reserved1, TargetDataRep,
                                      pInput, Reserved2, phNewContext, pOutput,
                                      contextAttr, ptsExpiry);
}

SECURITY_STATUS SSPILibraryDefault::QueryContextAttributesEx(
    PCtxtHandle phContext,
    ULONG ulAttribute,
    PVOID pBuffer,
    ULONG cbBuffer) {
  // TODO(crbug.com/41475489): QueryContextAttributesExW is not included
  // in Secur32.Lib in 10.0.18362.0 SDK. This symbol requires switching to using
  // Windows SDK API sets in mincore.lib or OneCore.Lib. Switch to using
  // QueryContextAttributesEx when the switch is made.
  return ::QueryContextAttributes(phContext, ulAttribute, pBuffer);
}

SECURITY_STATUS SSPILibraryDefault::QuerySecurityPackageInfo(
    PSecPkgInfoW* pkgInfo) {
  return ::QuerySecurityPackageInfoW(const_cast<LPWSTR>(package_name_.c_str()),
                                     pkgInfo);
}

SECURITY_STATUS SSPILibraryDefault::FreeCredentialsHandle(
    PCredHandle phCredential) {
  return ::FreeCredentialsHandle(phCredential);
}

SECURITY_STATUS SSPILibraryDefault::DeleteSecurityContext(
    PCtxtHandle phContext) {
  return ::DeleteSecurityContext(phContext);
}

SECURITY_STATUS SSPILibraryDefault::FreeContextBuffer(PVOID pvContextBuffer) {
  return ::FreeContextBuffer(pvContextBuffer);
}

HttpAuthSSPI::HttpAuthSSPI(SSPILibrary* library, HttpAuth::Scheme scheme)
    : library_(library),
      scheme_(scheme),
      delegation_type_(DelegationType::kNone) {
  DCHECK(library_);
  DCHECK(scheme_ == HttpAuth::AUTH_SCHEME_NEGOTIATE ||
         scheme_ == HttpAuth::AUTH_SCHEME_NTLM);
  SecInvalidateHandle(&cred_);
  SecInvalidateHandle(&ctxt_);
}

HttpAuthSSPI::~HttpAuthSSPI() {
  ResetSecurityContext();
  if (SecIsValidHandle(&cred_)) {
    library_->FreeCredentialsHandle(&cred_);
    SecInvalidateHandle(&cred_);
  }
}

bool HttpAuthSSPI::Init(const NetLogWithSource&) {
  return true;
}

bool HttpAuthSSPI::NeedsIdentity() const {
  return decoded_server_auth_token_.empty();
}

bool HttpAuthSSPI::AllowsExplicitCredentials() const {
  return true;
}

void HttpAuthSSPI::SetDelegation(DelegationType delegation_type) {
  delegation_type_ = delegation_type;
}

void HttpAuthSSPI::ResetSecurityContext() {
  if (SecIsValidHandle(&ctxt_)) {
    library_->DeleteSecurityContext(&ctxt_);
    SecInvalidateHandle(&ctxt_);
  }
}

HttpAuth::AuthorizationResult HttpAuthSSPI::ParseChallenge(
    HttpAuthChallengeTokenizer* tok) {
  if (!SecIsValidHandle(&ctxt_)) {
    return ParseFirstRoundChallenge(scheme_, tok);
  }
  std::string encoded_auth_token;
  return ParseLaterRoundChallenge(scheme_, tok, &encoded_auth_token,
                                  &decoded_server_auth_token_);
}

int HttpAuthSSPI::GenerateAuthToken(const AuthCredentials* credentials,
                                    const std::string& spn,
                                    const std::string& channel_bindings,
                                    std::string* auth_token,
                                    const NetLogWithSource& net_log,
                                    CompletionOnceCallback /*callback*/) {
  // Initial challenge.
  if (!SecIsValidHandle(&cred_)) {
    // ParseChallenge fails early if a non-empty token is received on the first
    // challenge.
    DCHECK(decoded_server_auth_token_.empty());
    int rv = OnFirstRound(credentials, net_log);
    if (rv != OK)
      return rv;
  }

  DCHECK(SecIsValidHandle(&cred_));
  void* out_buf;
  int out_buf_len;
  int rv = GetNextSecurityToken(
      spn, channel_bindings,
      static_cast<void*>(const_cast<char*>(decoded_server_auth_token_.c_str())),
      decoded_server_auth_token_.length(), net_log, &out_buf, &out_buf_len);
  if (rv != OK)
    return rv;

  // Base64 encode data in output buffer and prepend the scheme.
  std::string encode_input(static_cast<char*>(out_buf), out_buf_len);
  std::string encode_output = base::Base64Encode(encode_input);
  // OK, we are done with |out_buf|
  free(out_buf);
  if (scheme_ == HttpAuth::AUTH_SCHEME_NEGOTIATE) {
    *auth_token = "Negotiate " + encode_output;
  } else {
    *auth_token = "NTLM " + encode_output;
  }
  return OK;
}

int HttpAuthSSPI::OnFirstRound(const AuthCredentials* credentials,
                               const NetLogWithSource& net_log) {
  DCHECK(!SecIsValidHandle(&cred_));
  int rv = OK;
  if (credentials) {
    std::u16string domain;
    std::u16string user;
    SplitDomainAndUser(credentials->username(), &domain, &user);
    rv = AcquireExplicitCredentials(library_, domain, user,
                                    credentials->password(), net_log, &cred_);
    if (rv != OK)
      return rv;
  } else {
    rv = AcquireDefaultCredentials(library_, net_log, &cred_);
    if (rv != OK)
      return rv;
  }

  return rv;
}

int HttpAuthSSPI::GetNextSecurityToken(const std::string& spn,
                                       const std::string& channel_bindings,
                                       const void* in_token,
                                       int in_token_len,
                                       const NetLogWithSource& net_log,
                                       void** out_token,
                                       int* out_token_len) {
  ULONG max_token_length = 0;
  // Microsoft SDKs have a loose relationship with const.
  Error rv = library_->DetermineMaxTokenLength(&max_token_length);
  if (rv != OK)
    return rv;

  CtxtHandle* ctxt_ptr = nullptr;
  SecBufferDesc in_buffer_desc, out_buffer_desc;
  SecBufferDesc* in_buffer_desc_ptr = nullptr;
  SecBuffer in_buffers[2], out_buffer;

  in_buffer_desc.ulVersion = SECBUFFER_VERSION;
  in_buffer_desc.cBuffers = 0;
  in_buffer_desc.pBuffers = in_buffers;
  if (in_token_len > 0) {
    // Prepare input buffer.
    SecBuffer& sec_buffer = in_buffers[in_buffer_desc.cBuffers++];
    sec_buffer.BufferType = SECBUFFER_TOKEN;
    sec_buffer.cbBuffer = in_token_len;
    sec_buffer.pvBuffer = const_cast<void*>(in_token);
    ctxt_ptr = &ctxt_;
  } else {
    // If there is no input token, then we are starting a new authentication
    // sequence.  If we have already initialized our security context, then
    // we're incorrectly reusing the auth handler for a new sequence.
    if (SecIsValidHandle(&ctxt_)) {
      return ERR_UNEXPECTED;
    }
  }

  std::vector<char> sec_channel_bindings_buffer;
  if (!channel_bindings.empty()) {
    sec_channel_bindings_buffer.reserve(sizeof(SEC_CHANNEL_BINDINGS) +
                                        channel_bindings.size());
    sec_channel_bindings_buffer.resize(sizeof(SEC_CHANNEL_BINDINGS));
    SEC_CHANNEL_BINDINGS* bindings_desc =
        reinterpret_cast<SEC_CHANNEL_BINDINGS*>(
            sec_channel_bindings_buffer.data());
    bindings_desc->cbApplicationDataLength = channel_bindings.size();
    bindings_desc->dwApplicationDataOffset = sizeof(SEC_CHANNEL_BINDINGS);
    sec_channel_bindings_buffer.insert(sec_channel_bindings_buffer.end(),
                                       channel_bindings.begin(),
                                       channel_bindings.end());
    DCHECK_EQ(sizeof(SEC_CHANNEL_BINDINGS) + channel_bindings.size(),
              sec_channel_bindings_buffer.size());

    SecBuffer& sec_buffer = in_buffers[in_buffer_desc.cBuffers++];
    sec_buffer.BufferType = SECBUFFER_CHANNEL_BINDINGS;
    sec_buffer.cbBuffer = sec_channel_bindings_buffer.size();
    sec_buffer.pvBuffer = sec_channel_bindings_buffer.data();
  }

  if (in_buffer_desc.cBuffers > 0)
    in_buffer_desc_ptr = &in_buffer_desc;

  // Prepare output buffer.
  out_buffer_desc.ulVersion = SECBUFFER_VERSION;
  out_buffer_desc.cBuffers = 1;
  out_buffer_desc.pBuffers = &out_buffer;
  out_buffer.BufferType = SECBUFFER_TOKEN;
  out_buffer.cbBuffer = max_token_length;
  out_buffer.pvBuffer = malloc(out_buffer.cbBuffer);
  if (!out_buffer.pvBuffer)
    return ERR_OUT_OF_MEMORY;

  DWORD context_flags = 0;
  // Firefox only sets ISC_REQ_DELEGATE, but MSDN documentation indicates that
  // ISC_REQ_MUTUAL_AUTH must also be set. On Windows delegation by KDC policy
  // is always respected.
  if (delegation_type_ != DelegationType::kNone)
    context_flags |= (ISC_REQ_DELEGATE | ISC_REQ_MUTUAL_AUTH);

  net_log.BeginEvent(NetLogEventType::AUTH_LIBRARY_INIT_SEC_CTX, [&] {
    base::Value::Dict params;
    params.Set("spn", spn);
    params.Set("flags", ContextFlagsToValue(context_flags));
    return params;
  });

  // This returns a token that is passed to the remote server.
  DWORD context_attributes = 0;
  std::u16string spn16 = base::ASCIIToUTF16(spn);
  SECURITY_STATUS status = library_->InitializeSecurityContext(
      &cred_,                          // phCredential
      ctxt_ptr,                        // phContext
      base::as_writable_wcstr(spn16),  // pszTargetName
      context_flags,                   // fContextReq
      0,                               // Reserved1 (must be 0)
      SECURITY_NATIVE_DREP,            // TargetDataRep
      in_buffer_desc_ptr,              // pInput
      0,                               // Reserved2 (must be 0)
      &ctxt_,                          // phNewContext
      &out_buffer_desc,                // pOutput
      &context_attributes,             // pfContextAttr
      nullptr);                        // ptsExpiry
  rv = MapInitializeSecurityContextStatusToError(status);
  net_log.EndEvent(NetLogEventType::AUTH_LIBRARY_INIT_SEC_CTX, [&] {
    return InitializeSecurityContextParams(library_, &ctxt_, rv, status,
                                           context_attributes);
  });

  if (rv != OK) {
    ResetSecurityContext();
    free(out_buffer.pvBuffer);
    return rv;
  }
  if (!out_buffer.cbBuffer) {
    free(out_buffer.pvBuffer);
    out_buffer.pvBuffer = nullptr;
  }
  *out_token = out_buffer.pvBuffer;
  *out_token_len = out_buffer.cbBuffer;
  return OK;
}

void SplitDomainAndUser(const std::u16string& combined,
                        std::u16string* domain,
                        std::u16string* user) {
  // |combined| may be in the form "user" or "DOMAIN\user".
  // Separate the two parts if they exist.
  // TODO(cbentzel): I believe user@domain is also a valid form.
  size_t backslash_idx = combined.find(L'\\');
  if (backslash_idx == std::u16string::npos) {
    domain->clear();
    *user = combined;
  } else {
    *domain = combined.substr(0, backslash_idx);
    *user = combined.substr(backslash_idx + 1);
  }
}

}  // namespace net
```