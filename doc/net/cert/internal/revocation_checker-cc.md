Response:
Let's break down the thought process for analyzing this C++ code and generating the response.

1. **Understand the Goal:** The request asks for an analysis of a specific Chromium source file (`revocation_checker.cc`). The focus is on its functionality, relationship to JavaScript, logical reasoning (with examples), common usage errors, and how a user's action might lead to this code being executed (debugging).

2. **High-Level Overview (Skimming):**  First, I quickly skim the code to grasp its main purpose. Keywords like "revocation," "OCSP," "CRL," "certificate," "net_fetcher" immediately jump out. This tells me the file is about checking if a website's SSL/TLS certificate has been revoked.

3. **Decomposition of Functionality (Detailed Reading):** I then go through the code more carefully, examining each function and its logic.

    * **`MarkCertificateRevoked`:** Simple function to add a "revoked" error.
    * **`CheckCertRevocation`:** This is the core function. I note the different ways it checks revocation:
        * **Stapled OCSP:** Check if the server provided an OCSP response.
        * **Online OCSP:** Fetch OCSP information from the certificate's Authority Information Access (AIA) extension.
        * **CRL:** Fetch and check Certificate Revocation Lists from the certificate's CRL Distribution Points extension.
        * **Policy Handling:**  Pay attention to the `RevocationPolicy` structure and how it influences the checks (e.g., `check_revocation`, `networking_allowed`, `allow_missing_info`).
        * **Error Handling:** Observe how errors are added to `cert_errors`.
    * **`CheckValidatedChainRevocation`:**  Iterates through the certificate chain, calling `CheckCertRevocation` for each certificate. It skips trust anchors.
    * **`CheckChainRevocationUsingCRLSet`:**  Specifically deals with `CRLSet`, a mechanism Chromium uses for efficient revocation checking. It checks for revocation based on SPKI, subject, and serial number/issuer SPKI.

4. **Identify Key Concepts and Relationships:** I connect the different parts of the code. For instance, `CheckValidatedChainRevocation` orchestrates the revocation check for the entire chain, using `CheckCertRevocation` for individual certificates. I also note the role of `CertNetFetcher` in retrieving OCSP and CRL data.

5. **Address Specific Questions:** Now, I systematically answer each part of the request.

    * **Functionality:**  Summarize the main purpose and the different revocation methods.
    * **JavaScript Relationship:**  This requires thinking about how certificate revocation affects the user's browsing experience. While the C++ code doesn't *directly* interact with JavaScript, the *outcome* (whether a connection is considered secure) definitely impacts JavaScript execution and web page behavior. I focus on the *indirect* relationship – how the C++ code ensures a secure connection, which allows JavaScript to run in a trusted environment. I brainstorm examples of what happens when a certificate is revoked (error pages, blocked connections).
    * **Logical Reasoning (Hypothetical Inputs/Outputs):**  Choose a significant function (`CheckCertRevocation`) and illustrate its behavior with simple scenarios. I focus on different outcomes (revoked, good, unknown) based on whether stapled OCSP is present and its status. This demonstrates the decision-making within the function.
    * **User/Programming Errors:** Think about common mistakes related to certificate management and revocation. Examples include:
        * Misconfigured servers (not providing OCSP stapling).
        * Incorrect policies (disabling necessary checks).
        * Network issues preventing OCSP/CRL retrieval.
    * **User Journey/Debugging:** Trace back how a user interaction could lead to this code being executed. The most obvious path is accessing an HTTPS website. I outline the steps involved in establishing a secure connection and where revocation checking fits in. This helps understand the context of the code.

6. **Structure and Refine:** I organize the information logically with clear headings. I use bullet points and code formatting to improve readability. I ensure the language is clear and concise. For the JavaScript section, I emphasize the indirect connection and provide concrete examples of user-visible effects. For the input/output examples, I make them simple and easy to understand.

7. **Review and Verify:**  I re-read my response and compare it to the original code and the request to ensure accuracy and completeness. I check for any misinterpretations or omissions. For instance, I initially might have overlooked the CRLSet functionality and then would go back to include it.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** Focus too much on the technical details of OCSP and CRL.
* **Correction:**  Shift focus to the *user impact* and the overall goal of certificate revocation.
* **Initial thought:**  Struggle to find a direct link to JavaScript.
* **Correction:**  Realize the link is indirect but crucial – the security established by this C++ code enables secure JavaScript execution.
* **Initial thought:**  Make the input/output examples too complex.
* **Correction:** Simplify the examples to illustrate the basic logic clearly.

By following this systematic approach, combining code analysis with an understanding of the broader context and user experience, I can generate a comprehensive and informative response like the example provided.
这个文件 `net/cert/internal/revocation_checker.cc` 是 Chromium 网络栈中负责检查 SSL/TLS 证书吊销状态的核心组件。它的主要功能是确保用户连接的网站使用的证书仍然有效，没有被证书颁发机构（CA）吊销。

**以下是它的主要功能列表：**

1. **证书吊销检查策略执行:**  根据预设的策略（`RevocationPolicy`），决定是否以及如何进行证书吊销检查。策略可以指定是否允许网络请求、是否强制检查、以及对过期信息的容忍度等。

2. **在线证书状态协议 (OCSP) 检查:**
   -  解析证书中的授权信息访问扩展 (Authority Information Access - AIA)，查找 OCSP 服务器的 URI。
   -  构建并发送 OCSP 请求到 OCSP 服务器，查询证书的状态。
   -  处理 OCSP 响应，判断证书是否被吊销。
   -  支持 OCSP Stapling：检查服务器在 TLS 握手期间提供的已签名的 OCSP 响应。

3. **证书吊销列表 (CRL) 检查:**
   -  解析证书中的 CRL 分发点扩展 (CRL Distribution Points - CDP)，查找 CRL 文件的 URI。
   -  下载 CRL 文件。
   -  解析 CRL 文件，检查目标证书的序列号是否在吊销列表中。

4. **CRLSet 支持:**  使用 Chromium 的 CRLSet 组件进行高效的证书吊销检查。CRLSet 是一个预先下载的、经过压缩和优化的吊销信息集合。

5. **时间限制处理:**  在进行网络请求时，会考虑设置的截止时间 (`deadline`)，避免无限期的等待。

6. **错误处理:**  如果吊销检查失败或发现证书被吊销，会记录相应的错误信息到 `bssl::CertErrors` 或 `bssl::CertPathErrors` 对象中。

7. **链式证书吊销检查:**  对证书链中的每个证书（除了信任锚点）进行吊销检查，确保整个证书路径的有效性。

**与 JavaScript 功能的关系：**

`revocation_checker.cc` 本身是用 C++ 编写的，并不直接包含 JavaScript 代码。然而，它的功能对于安全的 Web 浏览至关重要，并且间接地影响着 JavaScript 的执行。

**举例说明：**

* **HTTPS 连接安全性:** 当用户通过浏览器访问一个 HTTPS 网站时，`revocation_checker.cc` 会被调用来验证服务器提供的 SSL/TLS 证书是否有效。如果证书被吊销，Chrome 会阻止连接，并显示一个安全警告页面，例如 "您的连接不是私密连接"。这时，页面上的任何 JavaScript 代码都不会被执行，因为浏览器认为连接不安全。

* **`fetch()` API 和安全性:**  JavaScript 的 `fetch()` API 可以用来发起网络请求。对于 HTTPS 请求，浏览器会在底层使用网络栈（包括 `revocation_checker.cc`）来确保连接的安全性。如果目标服务器的证书被吊销，`fetch()` 请求将会失败，并且 JavaScript 代码可能会捕获到一个网络错误。

**假设输入与输出（逻辑推理）：**

**场景 1：检查一个已吊销的证书，使用 OCSP Stapling。**

* **假设输入:**
    * `certs`: 包含目标证书和颁发者证书的证书链。
    * `target_cert_index`: 0 (指向目标证书)。
    * `policy`: 允许 OCSP 检查的策略。
    * `stapled_ocsp_response`:  一个有效的但指示证书已被吊销的 OCSP 响应。
    * `current_time`: 当前时间。

* **预期输出:**
    * `CheckCertRevocation` 返回 `false`。
    * `cert_errors` 中包含 `bssl::cert_errors::kCertificateRevoked` 错误。

**场景 2：检查一个有效的证书，没有提供 OCSP Stapling，需要进行在线 OCSP 查询。**

* **假设输入:**
    * `certs`: 包含目标证书和颁发者证书的证书链，目标证书的 AIA 扩展中包含 OCSP 服务器的 URI。
    * `target_cert_index`: 0。
    * `policy`: 允许 OCSP 检查和网络请求的策略。
    * `stapled_ocsp_response`: 空。
    * `net_fetcher`:  一个可以进行网络请求的 `CertNetFetcher` 对象。
    * `current_time`: 当前时间。

* **预期输出:**
    * `CheckCertRevocation` 返回 `true` (假设 OCSP 服务器返回证书有效的响应)。
    * `cert_errors` 中不包含吊销相关的错误。

**用户或编程常见的使用错误举例说明：**

1. **用户错误：系统时间不正确。** 如果用户的计算机时间与真实时间相差太远，可能会导致 OCSP 响应或 CRL 的有效性判断错误。例如，如果系统时间早于 OCSP 响应的颁发时间，校验可能会失败。

2. **编程错误：未配置 `CertNetFetcher`。** 如果在需要进行在线 OCSP 或 CRL 查询时，没有提供有效的 `CertNetFetcher` 对象，`CheckCertRevocation` 函数会记录错误并可能无法完成吊销检查。这通常发生在嵌入式环境或测试场景中，开发者需要确保正确初始化网络请求功能。

3. **编程错误：错误的 `RevocationPolicy` 配置。**  如果策略配置错误，例如禁用了网络请求 (`networking_allowed = false`)，即使证书需要在线检查，也无法进行，可能导致误判或无法完成检查。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户在 Chrome 浏览器中输入一个 HTTPS 网站的 URL 并按下回车键。**
2. **Chrome 建立 TCP 连接到目标服务器的 443 端口。**
3. **Chrome 发起 TLS 握手。**
4. **服务器在 TLS 握手过程中发送其 SSL/TLS 证书。**
5. **Chrome 的网络栈接收到服务器的证书。**
6. **证书验证过程启动，其中一步是证书吊销检查。**
7. **`CheckValidatedChainRevocation` 函数被调用，传入接收到的证书链和相关的策略。**
8. **`CheckValidatedChainRevocation` 遍历证书链，并对每个证书调用 `CheckCertRevocation`。**
9. **`CheckCertRevocation` 函数根据策略和证书信息，尝试以下操作：**
    * 检查服务器是否提供了 OCSP Stapling 响应。
    * 如果没有 Stapling，解析证书的 AIA 扩展，尝试进行在线 OCSP 查询。这会涉及到使用 `CertNetFetcher` 发起网络请求。
    * 如果 OCSP 检查未完成或失败，解析证书的 CDP 扩展，尝试下载并检查 CRL。这也会涉及到 `CertNetFetcher`。
10. **如果任何一个证书被检测到已吊销，或者吊销检查因错误而失败，连接会被终止，并显示安全警告。**

**调试线索：**

* **网络日志 (net-internals):**  Chrome 的 `chrome://net-internals/#events` 可以提供详细的网络请求日志，包括 OCSP 和 CRL 的请求和响应，以及相关的错误信息。
* **证书信息:**  可以通过开发者工具的安全标签查看网站的证书信息，包括 AIA 和 CDP 扩展，以及 OCSP Stapling 的状态。
* **`chrome://flags`:**  可以尝试调整一些与证书吊销相关的实验性标志，例如禁用或启用特定的吊销检查机制，以帮助诊断问题。
* **断点调试:**  在 Chromium 源代码中设置断点，跟踪 `CheckValidatedChainRevocation` 和 `CheckCertRevocation` 的执行流程，查看中间变量的值，例如策略配置、网络请求的状态、以及错误信息。

理解 `revocation_checker.cc` 的功能对于理解 Chromium 如何保证 HTTPS 连接的安全性至关重要。它在后台默默地工作，保护用户免受使用被吊销证书的恶意网站的侵害。

### 提示词
```
这是目录为net/cert/internal/revocation_checker.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/internal/revocation_checker.h"

#include <optional>
#include <string>
#include <string_view>

#include "base/logging.h"
#include "crypto/sha2.h"
#include "net/cert/cert_net_fetcher.h"
#include "third_party/boringssl/src/pki/common_cert_errors.h"
#include "third_party/boringssl/src/pki/crl.h"
#include "third_party/boringssl/src/pki/ocsp.h"
#include "third_party/boringssl/src/pki/ocsp_verify_result.h"
#include "third_party/boringssl/src/pki/parsed_certificate.h"
#include "third_party/boringssl/src/pki/trust_store.h"
#include "url/gurl.h"

namespace net {

namespace {

void MarkCertificateRevoked(bssl::CertErrors* errors) {
  // TODO(eroman): Add a parameter to the error indicating which mechanism
  // caused the revocation (i.e. CRLSet, OCSP, stapled OCSP, etc).
  errors->AddError(bssl::cert_errors::kCertificateRevoked);
}

// Checks the revocation status of |certs[target_cert_index]| according to
// |policy|. If the checks failed, returns false and adds errors to
// |cert_errors|.
//
// TODO(eroman): Make the verification time an input.
bool CheckCertRevocation(const bssl::ParsedCertificateList& certs,
                         size_t target_cert_index,
                         const RevocationPolicy& policy,
                         base::TimeTicks deadline,
                         std::string_view stapled_ocsp_response,
                         std::optional<int64_t> max_age_seconds,
                         base::Time current_time,
                         CertNetFetcher* net_fetcher,
                         bssl::CertErrors* cert_errors,
                         bssl::OCSPVerifyResult* stapled_ocsp_verify_result) {
  DCHECK_LT(target_cert_index, certs.size());
  const bssl::ParsedCertificate* cert = certs[target_cert_index].get();
  const bssl::ParsedCertificate* issuer_cert =
      target_cert_index + 1 < certs.size() ? certs[target_cert_index + 1].get()
                                           : nullptr;

  time_t time_now = current_time.ToTimeT();

  // Check using stapled OCSP, if available.
  if (!stapled_ocsp_response.empty() && issuer_cert) {
    bssl::OCSPVerifyResult::ResponseStatus response_details;
    bssl::OCSPRevocationStatus ocsp_status =
        bssl::CheckOCSP(stapled_ocsp_response, cert, issuer_cert, time_now,
                        max_age_seconds, &response_details);
    if (stapled_ocsp_verify_result) {
      stapled_ocsp_verify_result->response_status = response_details;
      stapled_ocsp_verify_result->revocation_status = ocsp_status;
    }

    // TODO(eroman): Save the stapled OCSP response to cache.
    switch (ocsp_status) {
      case bssl::OCSPRevocationStatus::REVOKED:
        MarkCertificateRevoked(cert_errors);
        return false;
      case bssl::OCSPRevocationStatus::GOOD:
        return true;
      case bssl::OCSPRevocationStatus::UNKNOWN:
        // TODO(eroman): If the OCSP response was invalid, should we keep
        //               looking or fail?
        break;
    }
  }

  if (!policy.check_revocation) {
    // TODO(eroman): Should still check CRL/OCSP caches.
    return true;
  }

  bool found_revocation_info = false;

  // Check OCSP.
  if (cert->has_authority_info_access()) {
    // Try each of the OCSP URIs
    for (const auto& ocsp_uri : cert->ocsp_uris()) {
      // Only consider http:// URLs (https:// could create a circular
      // dependency).
      GURL parsed_ocsp_url(ocsp_uri);
      if (!parsed_ocsp_url.is_valid() ||
          !parsed_ocsp_url.SchemeIs(url::kHttpScheme)) {
        continue;
      }

      found_revocation_info = true;

      // Check the deadline after setting found_revocation_info, to not give a
      // misleading kNoRevocationMechanism failure.
      if (!deadline.is_null() && base::TimeTicks::Now() > deadline)
        break;

      if (!policy.networking_allowed)
        continue;

      if (!net_fetcher) {
        LOG(ERROR) << "Cannot fetch OCSP as didn't specify a |net_fetcher|";
        continue;
      }

      // TODO(eroman): Duplication of work if there are multiple URLs to try.
      // TODO(eroman): Are there cases where we would need to POST instead?
      std::optional<std::string> get_url_str =
          CreateOCSPGetURL(cert, issuer_cert, ocsp_uri);
      if (!get_url_str.has_value()) {
        // An unexpected failure from BoringSSL, or the input was too large to
        // base64-encode.
        continue;
      }
      GURL get_url(get_url_str.value());
      if (!get_url.is_valid()) {
        // Invalid URL.
        continue;
      }

      // Fetch it over network.
      //
      // TODO(eroman): Issue POST instead of GET if request is larger than 255
      //               bytes?
      // TODO(eroman): Improve interplay with HTTP cache.
      std::unique_ptr<CertNetFetcher::Request> net_ocsp_request =
          net_fetcher->FetchOcsp(get_url, CertNetFetcher::DEFAULT,
                                 CertNetFetcher::DEFAULT);

      Error net_error;
      std::vector<uint8_t> ocsp_response_bytes;
      net_ocsp_request->WaitForResult(&net_error, &ocsp_response_bytes);

      if (net_error != OK)
        continue;

      bssl::OCSPVerifyResult::ResponseStatus response_details;

      bssl::OCSPRevocationStatus ocsp_status = bssl::CheckOCSP(
          std::string_view(
              reinterpret_cast<const char*>(ocsp_response_bytes.data()),
              ocsp_response_bytes.size()),
          cert, issuer_cert, time_now, max_age_seconds, &response_details);

      switch (ocsp_status) {
        case bssl::OCSPRevocationStatus::REVOKED:
          MarkCertificateRevoked(cert_errors);
          return false;
        case bssl::OCSPRevocationStatus::GOOD:
          return true;
        case bssl::OCSPRevocationStatus::UNKNOWN:
          break;
      }
    }
  }

  // Check CRLs.
  bssl::ParsedExtension crl_dp_extension;
  if (policy.crl_allowed &&
      cert->GetExtension(bssl::der::Input(bssl::kCrlDistributionPointsOid),
                         &crl_dp_extension)) {
    std::vector<bssl::ParsedDistributionPoint> distribution_points;
    if (ParseCrlDistributionPoints(crl_dp_extension.value,
                                   &distribution_points)) {
      for (const auto& distribution_point : distribution_points) {
        if (distribution_point.crl_issuer) {
          // Ignore indirect CRLs (CRL where CRLissuer != cert issuer), which
          // are optional according to RFC 5280's profile.
          continue;
        }

        if (distribution_point.reasons) {
          // Ignore CRLs that only contain some reasons. RFC 5280's profile
          // requires that conforming CAs "MUST include at least one
          // DistributionPoint that points to a CRL that covers the certificate
          // for all reasons".
          continue;
        }

        if (!distribution_point.distribution_point_fullname) {
          // Only distributionPoints with a fullName containing URIs are
          // supported.
          continue;
        }

        for (const auto& crl_uri :
             distribution_point.distribution_point_fullname
                 ->uniform_resource_identifiers) {
          // Only consider http:// URLs (https:// could create a circular
          // dependency).
          GURL parsed_crl_url(crl_uri);
          if (!parsed_crl_url.is_valid() ||
              !parsed_crl_url.SchemeIs(url::kHttpScheme)) {
            continue;
          }

          found_revocation_info = true;

          // Check the deadline after setting found_revocation_info, to not give
          // a misleading kNoRevocationMechanism failure.
          if (!deadline.is_null() && base::TimeTicks::Now() > deadline)
            break;

          if (!policy.networking_allowed)
            continue;

          if (!net_fetcher) {
            LOG(ERROR) << "Cannot fetch CRL as didn't specify a |net_fetcher|";
            continue;
          }

          // Fetch it over network.
          //
          // Note that no attempt is made to refetch without cache if a cached
          // CRL is too old, nor is there a separate CRL cache. It is assumed
          // the CRL server will send reasonable HTTP caching headers.
          std::unique_ptr<CertNetFetcher::Request> net_crl_request =
              net_fetcher->FetchCrl(parsed_crl_url, CertNetFetcher::DEFAULT,
                                    CertNetFetcher::DEFAULT);

          Error net_error;
          std::vector<uint8_t> crl_response_bytes;
          net_crl_request->WaitForResult(&net_error, &crl_response_bytes);

          if (net_error != OK)
            continue;

          bssl::CRLRevocationStatus crl_status = CheckCRL(
              std::string_view(
                  reinterpret_cast<const char*>(crl_response_bytes.data()),
                  crl_response_bytes.size()),
              certs, target_cert_index, distribution_point, time_now,
              max_age_seconds);

          switch (crl_status) {
            case bssl::CRLRevocationStatus::REVOKED:
              MarkCertificateRevoked(cert_errors);
              return false;
            case bssl::CRLRevocationStatus::GOOD:
              return true;
            case bssl::CRLRevocationStatus::UNKNOWN:
              break;
          }
        }
      }
    }
  }

  // Reaching here means that revocation checking was inconclusive. Determine
  // whether failure to complete revocation checking constitutes an error.

  if (!found_revocation_info) {
    if (policy.allow_missing_info) {
      // If the certificate lacked any (recognized) revocation mechanisms, and
      // the policy permits it, consider revocation checking a success.
      return true;
    } else {
      // If the certificate lacked any (recognized) revocation mechanisms, and
      // the policy forbids it, fail revocation checking.
      cert_errors->AddError(bssl::cert_errors::kNoRevocationMechanism);
      return false;
    }
  }

  // In soft-fail mode permit other failures.
  // TODO(eroman): Add a warning to |cert_errors| indicating the failure.
  if (policy.allow_unable_to_check)
    return true;

  // Otherwise the policy doesn't allow revocation checking to fail.
  cert_errors->AddError(bssl::cert_errors::kUnableToCheckRevocation);
  return false;
}

}  // namespace

void CheckValidatedChainRevocation(
    const bssl::ParsedCertificateList& certs,
    const RevocationPolicy& policy,
    base::TimeTicks deadline,
    std::string_view stapled_leaf_ocsp_response,
    base::Time current_time,
    CertNetFetcher* net_fetcher,
    bssl::CertPathErrors* errors,
    bssl::OCSPVerifyResult* stapled_ocsp_verify_result) {
  if (stapled_ocsp_verify_result)
    *stapled_ocsp_verify_result = bssl::OCSPVerifyResult();

  // Check each certificate for revocation using OCSP/CRL. Checks proceed
  // from the root certificate towards the leaf certificate. Revocation errors
  // are added to |errors|.
  for (size_t reverse_i = 0; reverse_i < certs.size(); ++reverse_i) {
    size_t i = certs.size() - reverse_i - 1;

    // Trust anchors bypass OCSP/CRL revocation checks. (The only way to revoke
    // trust anchors is via CRLSet or the built-in SPKI block list). Since
    // |certs| must be a validated chain, the final cert must be a trust
    // anchor.
    if (reverse_i == 0)
      continue;

    // TODO(eroman): Plumb stapled OCSP for non-leaf certificates from TLS?
    std::string_view stapled_ocsp =
        (i == 0) ? stapled_leaf_ocsp_response : std::string_view();

    std::optional<int64_t> max_age_seconds;
    if (policy.enforce_baseline_requirements) {
      max_age_seconds = ((i == 0) ? kMaxRevocationLeafUpdateAge
                                  : kMaxRevocationIntermediateUpdateAge)
                            .InSeconds();
    }

    // Check whether this certificate's revocation status complies with the
    // policy.
    bool cert_ok = CheckCertRevocation(
        certs, i, policy, deadline, stapled_ocsp, max_age_seconds, current_time,
        net_fetcher, errors->GetErrorsForCert(i),
        (i == 0) ? stapled_ocsp_verify_result : nullptr);

    if (!cert_ok) {
      // If any certificate in the chain fails revocation checks, the chain is
      // revoked and no need to check revocation status for the remaining
      // certificates.
      DCHECK(errors->GetErrorsForCert(i)->ContainsAnyErrorWithSeverity(
          bssl::CertError::SEVERITY_HIGH));
      break;
    }
  }
}

CRLSet::Result CheckChainRevocationUsingCRLSet(
    const CRLSet* crl_set,
    const bssl::ParsedCertificateList& certs,
    bssl::CertPathErrors* errors) {
  // Iterate from the root certificate towards the leaf (the root certificate is
  // also checked for revocation by CRLSet).
  std::string issuer_spki_hash;
  for (size_t reverse_i = 0; reverse_i < certs.size(); ++reverse_i) {
    size_t i = certs.size() - reverse_i - 1;
    const bssl::ParsedCertificate* cert = certs[i].get();

    // True if |cert| is the root of the chain.
    const bool is_root = reverse_i == 0;
    // True if |cert| is the leaf certificate of the chain.
    const bool is_target = i == 0;

    // Check for revocation using the certificate's SPKI.
    std::string spki_hash =
        crypto::SHA256HashString(cert->tbs().spki_tlv.AsStringView());
    CRLSet::Result result = crl_set->CheckSPKI(spki_hash);

    // Check for revocation using the certificate's Subject.
    if (result != CRLSet::REVOKED) {
      result = crl_set->CheckSubject(cert->tbs().subject_tlv.AsStringView(),
                                     spki_hash);
    }

    // Check for revocation using the certificate's serial number and issuer's
    // SPKI.
    if (result != CRLSet::REVOKED && !is_root) {
      result = crl_set->CheckSerial(cert->tbs().serial_number.AsStringView(),
                                    issuer_spki_hash);
    }

    // Prepare for the next iteration.
    issuer_spki_hash = std::move(spki_hash);

    switch (result) {
      case CRLSet::REVOKED:
        MarkCertificateRevoked(errors->GetErrorsForCert(i));
        return CRLSet::Result::REVOKED;
      case CRLSet::UNKNOWN:
        // If the status is unknown, advance to the subordinate certificate.
        break;
      case CRLSet::GOOD:
        if (is_target && !crl_set->IsExpired()) {
          // If the target is covered by the CRLSet and known good, consider
          // the entire chain to be valid (even though the revocation status
          // of the intermediates may have been UNKNOWN).
          //
          // Only the leaf certificate is considered for coverage because some
          // intermediates have CRLs with no revocations (after filtering) and
          // those CRLs are pruned from the CRLSet at generation time.
          return CRLSet::Result::GOOD;
        }
        break;
    }
  }

  // If no certificate was revoked, and the target was not known good, then
  // the revocation status is still unknown.
  return CRLSet::Result::UNKNOWN;
}

}  // namespace net
```