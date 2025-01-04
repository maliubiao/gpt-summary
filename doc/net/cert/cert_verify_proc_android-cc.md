Response:
Let's break down the thought process to analyze the provided C++ code.

**1. Understanding the Goal:**

The request asks for an explanation of the `net/cert/cert_verify_proc_android.cc` file in Chromium's network stack. Specifically, it wants to know:

* **Functionality:** What does this code do?
* **JavaScript Relation:**  How does it relate to JavaScript (if at all)?
* **Logical Reasoning (with examples):**  Show how the code behaves with specific inputs.
* **Common Errors:**  What mistakes can users or programmers make related to this code?
* **Debugging:** How does a user's action lead to this code being executed?

**2. Initial Code Scan and Keyword Identification:**

I'd start by quickly scanning the code for prominent keywords and patterns:

* **Includes:**  `#include ...`  This gives a high-level overview of dependencies: `cert_verify_proc.h`, `X509Certificate.h`, `net/android/`, `CertNetFetcher.h`, etc. This immediately suggests it's about certificate verification on Android.
* **Namespaces:** `namespace net { ... }`  Confirms it's part of Chromium's network stack.
* **Class Name:** `CertVerifyProcAndroid`  This is the core component. The `Proc` suffix often indicates a processing or verification step.
* **Function Names:** `VerifyInternal`, `VerifyX509CertChain`, `TryVerifyWithAIAFetching`, `FindLastCertWithUnknownIssuer`, `PerformAIAFetchAndAddResultToVector`. These names are very descriptive and provide clues about the functionality.
* **Android Specifics:**  References to `android::...` indicate interaction with the Android operating system's certificate management.
* **Error Handling:**  References to `net::ERR_...` and `android::CERT_VERIFY_STATUS_ANDROID_...` signal error handling logic.
* **AIA Fetching:**  The presence of `TryVerifyWithAIAFetching` and related functions suggests the code handles fetching intermediate certificates.
* **Metrics:**  `base::metrics::...` indicates logging and performance tracking.

**3. Deeper Dive into Key Functions:**

I'd then focus on the most important functions to understand their purpose:

* **`CertVerifyProcAndroid::VerifyInternal`:** This is likely the main entry point for certificate verification. It calls `VerifyFromAndroidTrustManager`.
* **`VerifyFromAndroidTrustManager`:** This function directly calls the Android system's `android::VerifyX509CertChain`. It also handles the case where the Android system doesn't trust the certificate and initiates AIA fetching.
* **`TryVerifyWithAIAFetching`:**  This is a crucial function. The comments explain its purpose: fetching intermediate certificates using Authority Information Access (AIA) extensions. I'd pay attention to the loop, the `kMaxAIAFetches` limit, and how it builds the certificate chain.
* **`FindLastCertWithUnknownIssuer`:**  This helper function is used within AIA fetching to identify the point in the chain where trust breaks down.
* **`PerformAIAFetchAndAddResultToVector`:**  This function handles the actual network request to fetch the intermediate certificate.

**4. Connecting to the Request's Questions:**

Now, I'd start explicitly addressing each point in the request:

* **Functionality:** Based on the function names and code structure, the primary function is to perform certificate verification on Android devices by leveraging the Android operating system's built-in certificate verification mechanisms. It extends this by attempting to fetch missing intermediate certificates.
* **JavaScript Relation:**  This is a C++ file in the *browser's* network stack. JavaScript running in a webpage *indirectly* triggers this code when making secure HTTPS requests. I'd explain this indirect relationship, focusing on how the browser uses this code behind the scenes.
* **Logical Reasoning (Examples):**  I need to create scenarios to illustrate the code's behavior. Think of different certificate chain configurations:
    * **Valid Chain:**  Android trusts the root.
    * **Untrusted Root, Included Intermediates:** Android will verify successfully.
    * **Untrusted Root, Missing Intermediates (AIA available):** AIA fetching kicks in, and the verification might succeed after fetching.
    * **Untrusted Root, Missing Intermediates (No AIA or fetch fails):** Verification fails.
* **Common Errors:** Think about what could go wrong from a user's or programmer's perspective:
    * **User:** Outdated Android system, network issues preventing AIA fetching.
    * **Programmer:**  Incorrect server certificate configuration (missing AIA), issues with the `CertNetFetcher`.
* **Debugging:** Trace a typical user action: typing a URL, the browser initiating a connection, the SSL handshake, and finally, this code being called for certificate verification.

**5. Structuring the Answer:**

Organize the information logically, using headings and bullet points for clarity. Start with a high-level overview and then go into more detail. Provide concrete examples and clearly separate the different aspects of the request.

**Self-Correction/Refinement During the Process:**

* **Initial Thought:**  Maybe this file directly handles all certificate verification logic.
* **Correction:**  Realized it *delegates* to the Android system's `VerifyX509CertChain` and adds the *extra* logic of AIA fetching. This delegation is a key aspect.
* **Initial Thought:**  Focus only on the happy path (successful verification).
* **Correction:**  Need to also cover error scenarios, especially the `NO_TRUSTED_ROOT` case and how AIA fetching attempts to resolve it.
* **Initial Thought:**  The connection to JavaScript might be too complex to explain simply.
* **Correction:**  Focus on the core concept: JavaScript makes a request, and the *browser's* underlying C++ code handles the security aspects, including certificate verification.

By following this thought process, systematically analyzing the code, and explicitly addressing each part of the request, I can generate a comprehensive and accurate explanation like the example you provided.
这个文件 `net/cert/cert_verify_proc_android.cc` 是 Chromium 网络栈中用于处理 Android 平台证书验证的核心组件。它的主要功能是：

**1. 利用 Android 系统提供的证书验证机制:**

   -  它通过 JNI (Java Native Interface) 调用 Android 系统底层的 `X509TrustManager` 来进行证书链的验证。
   -  具体来说，它使用 `android::VerifyX509CertChain` 函数，该函数会将待验证的证书链传递给 Android 系统进行验证。
   -  这样做的目的是利用 Android 系统内置的根证书存储和证书验证逻辑，确保在 Android 设备上用户信任的证书也能被 Chromium 信任。

**2. 处理 Android 系统验证的返回结果:**

   -  `VerifyFromAndroidTrustManager` 函数接收 `android::VerifyX509CertChain` 的返回状态，并将 Android 特定的错误代码（如 `CERT_VERIFY_STATUS_ANDROID_NO_TRUSTED_ROOT`，`CERT_VERIFY_STATUS_ANDROID_EXPIRED` 等）转换为 Chromium 的通用证书状态标志 (`CertStatus`)。
   -  例如，如果 Android 系统返回 `CERT_VERIFY_STATUS_ANDROID_NO_TRUSTED_ROOT`，则 Chromium 会设置 `verify_result->cert_status |= CERT_STATUS_AUTHORITY_INVALID;`。

**3. 尝试通过 AIA (Authority Information Access) 获取中间证书并重试验证:**

   - 当 Android 系统返回 `CERT_VERIFY_STATUS_ANDROID_NO_TRUSTED_ROOT` (表示证书链中缺少受信任的根证书或中间证书) 并且网络请求未被禁用时 (`!(flags & CertVerifyProc::VERIFY_DISABLE_NETWORK_FETCHES)`)，该文件会尝试通过 AIA 扩展中提供的 URL 下载缺少的中间证书。
   - `TryVerifyWithAIAFetching` 函数实现了这个逻辑：
     - 它首先解析证书链，找到缺少签发者的证书 (`FindLastCertWithUnknownIssuer`)。
     - 然后，它从该证书的 AIA 扩展中提取 URL。
     - 使用 `CertNetFetcher` 下载这些 URL 指向的证书。
     - 将下载的证书添加到现有的证书链中。
     - 再次调用 `AttemptVerificationAfterAIAFetch`，它会再次调用 Android 的证书验证机制来验证扩展后的证书链。
     - 这个过程会重复进行，直到验证成功、达到最大尝试次数 (`kMaxAIAFetches`) 或者没有更多的 AIA URL 可以获取。

**4. 记录验证结果和相关信息:**

   -  无论验证成功与否，都会将结果存储在 `CertVerifyResult` 结构体中，包括证书状态 (`cert_status`)，是否由已知根证书签发 (`is_issued_by_known_root`)，以及验证后的证书链 (`verified_cert`)。
   -  它还会提取证书链中每个证书的公钥哈希值，用于后续的策略决策和统计。

**5. 作为 `CertVerifyProc` 的一个具体实现:**

   -  `CertVerifyProcAndroid` 继承自 `CertVerifyProc` 抽象基类，提供了平台特定的证书验证实现。Chromium 的其他网络组件可以使用 `CertVerifyProc` 接口来进行证书验证，而不需要关心底层平台的具体实现。

**与 JavaScript 的关系：**

`net/cert/cert_verify_proc_android.cc` 本身是 C++ 代码，与 JavaScript 没有直接的语法或 API 上的联系。但是，它在浏览器中扮演着至关重要的角色，直接影响着用户在使用 JavaScript 发起 HTTPS 请求时的安全性。

**举例说明:**

假设一个 JavaScript 应用程序需要向一个使用 HTTPS 的服务器发起请求 (`fetch('https://example.com')`)。

1. **用户操作:** JavaScript 代码调用 `fetch()` 发起 HTTPS 请求。
2. **网络栈处理:** Chromium 的网络栈会解析这个请求，并需要验证 `example.com` 服务器提供的 SSL/TLS 证书。
3. **到达 `CertVerifyProcAndroid`:**  在 Android 平台上，Chromium 会使用 `CertVerifyProcAndroid` 来进行证书验证。
4. **Android 系统验证:** `CertVerifyProcAndroid` 会将服务器提供的证书链传递给 Android 系统的 `X509TrustManager` 进行验证。
5. **可能的场景和逻辑推理:**
   - **假设输入:** 服务器提供的证书链是：`[服务器证书, 中级CA证书]`。Android 系统中信任签发 `中级CA证书` 的根证书。
   - **输出:** Android 系统验证通过，`VerifyFromAndroidTrustManager` 返回成功，`verify_result->cert_status` 为 `CERT_STATUS_OK`。
   - **假设输入:** 服务器提供的证书链是：`[服务器证书]`。Android 系统中不信任签发该服务器证书的根证书，并且服务器配置了 AIA 信息指向中级 CA 证书。
   - **输出:**
     - Android 系统初始验证失败，返回 `CERT_VERIFY_STATUS_ANDROID_NO_TRUSTED_ROOT`。
     - `TryVerifyWithAIAFetching` 被调用。
     - 从服务器证书的 AIA 扩展中获取中级 CA 证书的 URL。
     - `CertNetFetcher` 下载中级 CA 证书。
     - 再次调用 Android 系统验证，这次的证书链是 `[服务器证书, 下载的中级CA证书]`。
     - 假设 Android 系统信任签发下载的 `中级CA证书` 的根证书，则验证通过，`verify_result->cert_status` 为 `CERT_STATUS_OK`。
   - **假设输入:** 服务器提供的证书链是：`[服务器证书]`。Android 系统中不信任签发该服务器证书的根证书，且服务器没有配置 AIA 信息，或者 AIA 信息指向的 URL 下载失败。
   - **输出:**
     - Android 系统初始验证失败，返回 `CERT_VERIFY_STATUS_ANDROID_NO_TRUSTED_ROOT`。
     - `TryVerifyWithAIAFetching` 被调用，但由于没有 AIA 信息或下载失败，无法获取到中间证书。
     - 最终验证失败，`verify_result->cert_status` 包含 `CERT_STATUS_AUTHORITY_INVALID`，浏览器会阻止 JavaScript 的 `fetch()` 请求，并可能在页面上显示安全警告。

**用户或编程常见的使用错误：**

1. **用户错误：**
   - **系统时间不正确:** 如果用户的 Android 设备系统时间不正确，可能导致证书过期或未生效的判断错误，从而触发 `CERT_VERIFY_STATUS_ANDROID_EXPIRED` 或 `CERT_VERIFY_STATUS_ANDROID_NOT_YET_VALID` 错误。
   - **网络连接问题:** 如果用户网络连接不稳定或无法访问互联网，`TryVerifyWithAIAFetching` 将无法下载中间证书，导致本应成功的验证失败。
   - **安装了恶意或不受信任的证书:** 用户可能手动安装了一些恶意或过期的证书到系统中，这些证书可能会干扰正常的证书验证过程。

2. **编程错误（服务器配置）：**
   - **服务器未配置正确的证书链:** 服务器可能只提供了终端证书，而没有提供必要的中间 CA 证书。
   - **服务器的 AIA 信息配置错误或不可访问:** 如果服务器配置了 AIA 扩展，但其中的 URL 不正确或无法访问，`TryVerifyWithAIAFetching` 将无法获取中间证书。

**用户操作如何一步步到达这里（作为调试线索）：**

1. **用户在 Chrome 浏览器地址栏输入一个 HTTPS 网站的 URL 并按下回车键，或者点击了一个指向 HTTPS 链接的超链接。**
2. **Chrome 浏览器开始与目标服务器建立 TCP 连接。**
3. **TCP 连接建立后，Chrome 发起 TLS 握手过程。**
4. **在 TLS 握手过程中，服务器会将它的 SSL/TLS 证书链发送给 Chrome 浏览器。**
5. **Chrome 接收到服务器的证书链后，需要对其进行验证，以确保服务器的身份是可信的。**
6. **在 Android 平台上，Chrome 会使用 `CertVerifyProcAndroid` 组件来进行证书验证。**
7. **`CertVerifyProcAndroid::VerifyInternal` 函数会被调用，传入服务器提供的证书、主机名等参数。**
8. **`VerifyInternal` 函数会调用 `VerifyFromAndroidTrustManager`，后者会调用 Android 系统的 `android::VerifyX509CertChain` 进行初步验证。**
9. **如果 Android 系统验证失败，并且返回 `CERT_VERIFY_STATUS_ANDROID_NO_TRUSTED_ROOT`，且网络未被禁用，则 `TryVerifyWithAIAFetching` 会尝试通过网络获取中间证书并重试验证。**
10. **根据验证结果，Chrome 会决定是否信任服务器的证书，并继续完成 TLS 握手。如果验证失败，Chrome 会阻止连接并显示安全警告。**

因此，当用户访问任何 HTTPS 网站时，如果涉及到证书验证，`net/cert/cert_verify_proc_android.cc` 中的代码都有可能被执行。 在调试与 Android 平台上的 HTTPS 连接问题相关的证书错误时，这是一个关键的入口点。

Prompt: 
```
这是目录为net/cert/cert_verify_proc_android.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/cert_verify_proc_android.h"

#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "base/check_op.h"
#include "base/containers/adapters.h"
#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_macros.h"
#include "base/notreached.h"
#include "crypto/sha2.h"
#include "net/android/cert_verify_result_android.h"
#include "net/android/network_library.h"
#include "net/base/net_errors.h"
#include "net/cert/asn1_util.h"
#include "net/cert/cert_net_fetcher.h"
#include "net/cert/cert_status_flags.h"
#include "net/cert/cert_verify_proc.h"
#include "net/cert/cert_verify_result.h"
#include "net/cert/crl_set.h"
#include "net/cert/known_roots.h"
#include "net/cert/test_root_certs.h"
#include "net/cert/x509_certificate.h"
#include "net/cert/x509_util.h"
#include "third_party/boringssl/src/pki/cert_errors.h"
#include "third_party/boringssl/src/pki/parsed_certificate.h"
#include "url/gurl.h"

namespace net {

namespace {

// Android ignores the authType parameter to
// X509TrustManager.checkServerTrusted, so pass in a dummy value. See
// https://crbug.com/627154.
const char kAuthType[] = "RSA";

// The maximum number of AIA fetches that TryVerifyWithAIAFetching() will
// attempt. If a valid chain cannot be built after this many fetches,
// TryVerifyWithAIAFetching() will give up and return
// CERT_VERIFY_STATUS_ANDROID_NO_TRUSTED_ROOT.
const unsigned int kMaxAIAFetches = 5;

// Starting at certs[start], this function searches |certs| for an issuer of
// certs[start], then for an issuer of that issuer, and so on until it finds a
// certificate |cert| for which |certs| does not contain an issuer of
// |cert|. Returns a pointer to this |cert|, or nullptr if all certificates
// while path-building from |start| have an issuer in |certs| (including if
// there is a loop). Note that the returned certificate will be equal to |start|
// if |start| does not have an issuer in |certs|.
//
// TODO(estark): when searching for an issuer, this always uses the first
// encountered issuer in |certs|, and does not handle the situation where
// |certs| contains more than one issuer for a given certificate.
std::shared_ptr<const bssl::ParsedCertificate> FindLastCertWithUnknownIssuer(
    const bssl::ParsedCertificateList& certs,
    const std::shared_ptr<const bssl::ParsedCertificate>& start) {
  DCHECK_GE(certs.size(), 1u);
  std::set<std::shared_ptr<const bssl::ParsedCertificate>> used_in_path;
  std::shared_ptr<const bssl::ParsedCertificate> last = start;
  while (true) {
    used_in_path.insert(last);
    std::shared_ptr<const bssl::ParsedCertificate> last_issuer;
    // Find an issuer for |last| (which might be |last| itself if self-signed).
    for (const auto& cert : certs) {
      if (cert->normalized_subject() == last->normalized_issuer()) {
        last_issuer = cert;
        break;
      }
    }
    if (!last_issuer) {
      // There is no issuer for |last| in |certs|.
      return last;
    }
    if (last_issuer->normalized_subject() == last_issuer->normalized_issuer()) {
      // A chain can be built from |start| to a self-signed certificate, so
      // return nullptr to indicate that there is no certificate with an unknown
      // issuer.
      return nullptr;
    }
    if (used_in_path.find(last_issuer) != used_in_path.end()) {
      // |certs| contains a loop.
      return nullptr;
    }
    // Continue the search for |last_issuer|'s issuer.
    last = last_issuer;
  }
  NOTREACHED();
}

// Uses |fetcher| to fetch issuers from |uri|. If the fetch succeeds, the
// certificate is parsed and added to |cert_list|. Returns true if the fetch was
// successful and the result could be parsed as a certificate, and false
// otherwise.
bool PerformAIAFetchAndAddResultToVector(
    scoped_refptr<CertNetFetcher> fetcher,
    std::string_view uri,
    bssl::ParsedCertificateList* cert_list) {
  GURL url(uri);
  if (!url.is_valid())
    return false;
  std::unique_ptr<CertNetFetcher::Request> request(fetcher->FetchCaIssuers(
      url, CertNetFetcher::DEFAULT, CertNetFetcher::DEFAULT));
  Error error;
  std::vector<uint8_t> aia_fetch_bytes;
  request->WaitForResult(&error, &aia_fetch_bytes);
  if (error != OK)
    return false;
  bssl::CertErrors errors;
  return bssl::ParsedCertificate::CreateAndAddToVector(
      x509_util::CreateCryptoBuffer(aia_fetch_bytes),
      x509_util::DefaultParseCertificateOptions(), cert_list, &errors);
}

// Uses android::VerifyX509CertChain() to verify the certificates in |certs| for
// |hostname| and returns the verification status. If the verification was
// successful, this function populates |verify_result| and |verified_chain|;
// otherwise it leaves them untouched.
android::CertVerifyStatusAndroid AttemptVerificationAfterAIAFetch(
    const bssl::ParsedCertificateList& certs,
    const std::string& hostname,
    CertVerifyResult* verify_result,
    std::vector<std::string>* verified_chain) {
  std::vector<std::string> cert_bytes;
  for (const auto& cert : certs) {
    cert_bytes.push_back(cert->der_cert().AsString());
  }

  bool is_issued_by_known_root;
  std::vector<std::string> candidate_verified_chain;
  android::CertVerifyStatusAndroid status;
  android::VerifyX509CertChain(cert_bytes, kAuthType, hostname, &status,
                               &is_issued_by_known_root,
                               &candidate_verified_chain);

  if (status == android::CERT_VERIFY_STATUS_ANDROID_OK) {
    verify_result->is_issued_by_known_root = is_issued_by_known_root;
    *verified_chain = candidate_verified_chain;
  }
  return status;
}

// After a CERT_VERIFY_STATUS_ANDROID_NO_TRUSTED_ROOT error is encountered, this
// function can be called to fetch intermediates and retry verification.
//
// It will start from the first certificate in |cert_bytes| and construct a
// chain as far as it can using certificates in |cert_bytes|, and then
// iteratively fetch issuers from any AIA URLs in the last certificate in this
// chain. It will fetch issuers until it encounters a chain that verifies with
// status CERT_VERIFY_STATUS_ANDROID_OK, or it runs out of AIA URLs to fetch, or
// it has attempted |kMaxAIAFetches| fetches.
//
// If it finds a chain that verifies successfully, it returns
// CERT_VERIFY_STATUS_ANDROID_OK and sets |verify_result| and |verified_chain|
// correspondingly. Otherwise, it returns
// CERT_VERIFY_STATUS_ANDROID_NO_TRUSTED_ROOT and does not modify
// |verify_result| or |verified_chain|.
android::CertVerifyStatusAndroid TryVerifyWithAIAFetching(
    const std::vector<std::string>& cert_bytes,
    const std::string& hostname,
    scoped_refptr<CertNetFetcher> cert_net_fetcher,
    CertVerifyResult* verify_result,
    std::vector<std::string>* verified_chain) {
  if (!cert_net_fetcher)
    return android::CERT_VERIFY_STATUS_ANDROID_NO_TRUSTED_ROOT;

  // Convert the certificates into ParsedCertificates for ease of pulling out
  // AIA URLs.
  bssl::CertErrors errors;
  bssl::ParsedCertificateList certs;
  for (const auto& cert : cert_bytes) {
    if (!bssl::ParsedCertificate::CreateAndAddToVector(
            x509_util::CreateCryptoBuffer(cert),
            x509_util::DefaultParseCertificateOptions(), &certs, &errors)) {
      return android::CERT_VERIFY_STATUS_ANDROID_NO_TRUSTED_ROOT;
    }
  }

  // Build a chain as far as possible from the target certificate at index 0,
  // using the initially provided certificates.
  std::shared_ptr<const bssl::ParsedCertificate> last_cert_with_unknown_issuer =
      FindLastCertWithUnknownIssuer(certs, certs[0]);
  if (!last_cert_with_unknown_issuer) {
    // |certs| either contains a loop, or contains a full chain to a self-signed
    // certificate. Do not attempt AIA fetches for such a chain.
    return android::CERT_VERIFY_STATUS_ANDROID_NO_TRUSTED_ROOT;
  }

  unsigned int num_aia_fetches = 0;
  while (true) {
    // If chain-building has terminated in a certificate that does not have an
    // AIA URL, give up.
    //
    // TODO(estark): Instead of giving up at this point, it would be more robust
    // to go back to the certificate before |last_cert| in the chain and attempt
    // an AIA fetch from that point (if one hasn't already been done). This
    // would accomodate chains where the server serves Leaf -> I1 signed by a
    // root not in the client's trust store, but AIA fetching would yield an
    // intermediate I2 signed by a root that *is* in the client's trust store.
    if (!last_cert_with_unknown_issuer->has_authority_info_access())
      return android::CERT_VERIFY_STATUS_ANDROID_NO_TRUSTED_ROOT;

    for (const auto& uri : last_cert_with_unknown_issuer->ca_issuers_uris()) {
      num_aia_fetches++;
      if (num_aia_fetches > kMaxAIAFetches)
        return android::CERT_VERIFY_STATUS_ANDROID_NO_TRUSTED_ROOT;
      if (!PerformAIAFetchAndAddResultToVector(cert_net_fetcher, uri, &certs))
        continue;
      android::CertVerifyStatusAndroid status =
          AttemptVerificationAfterAIAFetch(certs, hostname, verify_result,
                                           verified_chain);
      if (status == android::CERT_VERIFY_STATUS_ANDROID_OK)
        return status;
    }

    // If verification still failed but the path expanded, continue to attempt
    // AIA fetches.
    std::shared_ptr<const bssl::ParsedCertificate>
        new_last_cert_with_unknown_issuer =
            FindLastCertWithUnknownIssuer(certs, last_cert_with_unknown_issuer);
    if (!new_last_cert_with_unknown_issuer ||
        new_last_cert_with_unknown_issuer == last_cert_with_unknown_issuer) {
      // The last round of AIA fetches (if there were any) didn't expand the
      // path, or it did such that |certs| now contains a full path to an
      // (untrusted) root or a loop.
      //
      // TODO(estark): As above, it would be more robust to go back one
      // certificate and attempt an AIA fetch from that point.
      return android::CERT_VERIFY_STATUS_ANDROID_NO_TRUSTED_ROOT;
    }
    last_cert_with_unknown_issuer = new_last_cert_with_unknown_issuer;
  }

  NOTREACHED();
}

// Returns true if the certificate verification call was successful (regardless
// of its result), i.e. if |verify_result| was set. Otherwise returns false.
bool VerifyFromAndroidTrustManager(
    const std::vector<std::string>& cert_bytes,
    const std::string& hostname,
    int flags,
    scoped_refptr<CertNetFetcher> cert_net_fetcher,
    CertVerifyResult* verify_result) {
  android::CertVerifyStatusAndroid status;
  std::vector<std::string> verified_chain;

  android::VerifyX509CertChain(cert_bytes, kAuthType, hostname, &status,
                               &verify_result->is_issued_by_known_root,
                               &verified_chain);

  // If verification resulted in a NO_TRUSTED_ROOT error, then fetch
  // intermediates and retry.
  if (status == android::CERT_VERIFY_STATUS_ANDROID_NO_TRUSTED_ROOT &&
      !(flags & CertVerifyProc::VERIFY_DISABLE_NETWORK_FETCHES)) {
    status = TryVerifyWithAIAFetching(cert_bytes, hostname,
                                      std::move(cert_net_fetcher),
                                      verify_result, &verified_chain);
  }

  switch (status) {
    case android::CERT_VERIFY_STATUS_ANDROID_FAILED:
      return false;
    case android::CERT_VERIFY_STATUS_ANDROID_OK:
      break;
    case android::CERT_VERIFY_STATUS_ANDROID_NO_TRUSTED_ROOT:
      verify_result->cert_status |= CERT_STATUS_AUTHORITY_INVALID;
      break;
    case android::CERT_VERIFY_STATUS_ANDROID_EXPIRED:
    case android::CERT_VERIFY_STATUS_ANDROID_NOT_YET_VALID:
      verify_result->cert_status |= CERT_STATUS_DATE_INVALID;
      break;
    case android::CERT_VERIFY_STATUS_ANDROID_UNABLE_TO_PARSE:
      verify_result->cert_status |= CERT_STATUS_INVALID;
      break;
    case android::CERT_VERIFY_STATUS_ANDROID_INCORRECT_KEY_USAGE:
      verify_result->cert_status |= CERT_STATUS_INVALID;
      break;
    default:
      NOTREACHED();
  }

  // Save the verified chain.
  if (!verified_chain.empty()) {
    std::vector<std::string_view> verified_chain_pieces(verified_chain.size());
    for (size_t i = 0; i < verified_chain.size(); i++) {
      verified_chain_pieces[i] = std::string_view(verified_chain[i]);
    }
    scoped_refptr<X509Certificate> verified_cert =
        X509Certificate::CreateFromDERCertChain(verified_chain_pieces);
    if (verified_cert.get())
      verify_result->verified_cert = std::move(verified_cert);
    else
      verify_result->cert_status |= CERT_STATUS_INVALID;
  }

  // Extract the public key hashes and check whether or not any are known
  // roots. Walk from the end of the chain (root) to leaf, to optimize for
  // known root checks.
  for (const auto& cert : base::Reversed(verified_chain)) {
    std::string_view spki_bytes;
    if (!asn1::ExtractSPKIFromDERCert(cert, &spki_bytes)) {
      verify_result->cert_status |= CERT_STATUS_INVALID;
      continue;
    }

    HashValue sha256(HASH_VALUE_SHA256);
    crypto::SHA256HashString(spki_bytes, sha256.data(), crypto::kSHA256Length);
    verify_result->public_key_hashes.push_back(sha256);

    if (!verify_result->is_issued_by_known_root) {
      verify_result->is_issued_by_known_root =
          GetNetTrustAnchorHistogramIdForSPKI(sha256) != 0;
    }
  }

  // Reverse the hash list, to maintain the leaf->root ordering.
  std::reverse(verify_result->public_key_hashes.begin(),
               verify_result->public_key_hashes.end());

  return true;
}

void GetChainDEREncodedBytes(X509Certificate* cert,
                             std::vector<std::string>* chain_bytes) {
  chain_bytes->reserve(1 + cert->intermediate_buffers().size());
  chain_bytes->emplace_back(
      net::x509_util::CryptoBufferAsStringPiece(cert->cert_buffer()));
  for (const auto& handle : cert->intermediate_buffers()) {
    chain_bytes->emplace_back(
        net::x509_util::CryptoBufferAsStringPiece(handle.get()));
  }
}

}  // namespace

CertVerifyProcAndroid::CertVerifyProcAndroid(
    scoped_refptr<CertNetFetcher> cert_net_fetcher,
    scoped_refptr<CRLSet> crl_set)
    : CertVerifyProc(std::move(crl_set)),
      cert_net_fetcher_(std::move(cert_net_fetcher)) {}

CertVerifyProcAndroid::~CertVerifyProcAndroid() = default;

int CertVerifyProcAndroid::VerifyInternal(X509Certificate* cert,
                                          const std::string& hostname,
                                          const std::string& ocsp_response,
                                          const std::string& sct_list,
                                          int flags,
                                          CertVerifyResult* verify_result,
                                          const NetLogWithSource& net_log) {
  std::vector<std::string> cert_bytes;
  GetChainDEREncodedBytes(cert, &cert_bytes);
  if (!VerifyFromAndroidTrustManager(cert_bytes, hostname, flags,
                                     cert_net_fetcher_, verify_result)) {
    return ERR_FAILED;
  }

  if (IsCertStatusError(verify_result->cert_status))
    return MapCertStatusToNetError(verify_result->cert_status);

  if (TestRootCerts::HasInstance() &&
      !verify_result->verified_cert->intermediate_buffers().empty() &&
      TestRootCerts::GetInstance()->IsKnownRoot(x509_util::CryptoBufferAsSpan(
          verify_result->verified_cert->intermediate_buffers().back().get()))) {
    verify_result->is_issued_by_known_root = true;
  }

  LogNameNormalizationMetrics(".Android", verify_result->verified_cert.get(),
                              verify_result->is_issued_by_known_root);

  return OK;
}

}  // namespace net

"""

```