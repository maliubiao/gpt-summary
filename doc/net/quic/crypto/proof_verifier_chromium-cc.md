Response:
Let's break down the thought process for analyzing this C++ code and answering the prompt.

**1. Understanding the Core Task:**

The prompt asks for the functionality of `proof_verifier_chromium.cc` within the Chromium network stack, specifically focusing on its relationship with JavaScript, logical reasoning with inputs/outputs, potential user errors, and how a user action might lead to this code being executed.

**2. Initial Skim and Keyword Identification:**

A quick read reveals key components:

* **`ProofVerifierChromium` class:** This is clearly the central class.
* **`Job` inner class:** Seems to handle individual verification tasks.
* **`CertVerifier`:**  Indicates interaction with certificate verification logic.
* **`TransportSecurityState`:**  Suggests handling of HSTS, HPKP, and CT.
* **`crypto::SignatureVerifier`:** Deals with cryptographic signature verification.
* **`VerifyProof` and `VerifyCertChain` methods:**  Likely the entry points for the main functionality.
* **`ProofVerifyDetailsChromium`:** A data structure holding verification results.

**3. Deconstructing the Functionality (Top-Down Approach):**

* **`ProofVerifierChromium` Class:**
    * **Purpose:**  Serves as the primary interface for verifying server proofs in QUIC connections within Chromium. It manages the lifecycle of verification `Job`s.
    * **Dependencies:** Relies on `CertVerifier`, `TransportSecurityState`, `SCTAuditingDelegate`, and manages a set of allowed hostnames for unknown roots.
    * **Workflow:** Receives a request to verify a proof or certificate chain, creates a `Job` object to handle it, and manages the asynchronous completion of the verification.
* **`Job` Class:**
    * **Purpose:**  Encapsulates the logic for a single proof verification attempt. This makes the verification process manageable and allows for asynchronous operations.
    * **Key Methods:**
        * `VerifyProof`: Verifies the entire server proof, including signature and certificate chain.
        * `VerifyCertChain`:  Verifies only the certificate chain.
        * `GetX509Certificate`: Converts DER-encoded certificate strings to an `X509Certificate` object.
        * `VerifyCert`:  Delegates the actual certificate verification to the `CertVerifier`.
        * `VerifySignature`:  Cryptographically verifies the server configuration signature.
        * `DoLoop` and `OnIOComplete`: Manage the asynchronous state machine for verification.
        * `CheckCTRequirements`:  Checks if Certificate Transparency requirements are met.
    * **State Machine:** The `Job` class uses a state machine (`STATE_NONE`, `STATE_VERIFY_CERT`, `STATE_VERIFY_CERT_COMPLETE`) to manage the asynchronous verification process. This is common in network programming.

**4. Identifying Connections to JavaScript:**

* **Indirect Relationship:**  The code is C++, part of the Chromium network stack. JavaScript running in a browser context *indirectly* relies on this. JavaScript makes network requests (e.g., `fetch`, `XMLHttpRequest`). If the connection uses QUIC, this C++ code will be involved in verifying the server's identity.
* **Example:**  A JavaScript `fetch()` call to an HTTPS website using QUIC will eventually trigger this code to verify the server's certificate and proof.

**5. Logical Reasoning (Input/Output):**

* **`VerifyProof`:**
    * **Input:** Hostname, port, server config, QUIC version, CHLO hash, certificate chain, SCT data, signature.
    * **Output (Success):** `QUIC_SUCCESS`, verification details (including certificate status).
    * **Output (Failure):** `QUIC_FAILURE`, error details.
* **`VerifyCertChain`:**
    * **Input:** Hostname, port, certificate chain, OCSP response, SCT data.
    * **Output (Success):** `QUIC_SUCCESS`, verification details.
    * **Output (Failure):** `QUIC_FAILURE`, error details.

**6. Common User/Programming Errors:**

* **Incorrect Certificate Chain:** The server provides an incomplete or incorrectly ordered certificate chain. This will likely lead to `CERT_STATUS_INVALID` and errors during `CertVerifier::Verify`.
* **Mismatched Signature:** The signature provided by the server doesn't match the signed server configuration. The `VerifySignature` method will return `false`.
* **Outdated or Revoked Certificates:**  The `CertVerifier` will detect this, leading to errors like `ERR_CERT_REVOKED` or `ERR_CERT_DATE_INVALID`.
* **HPKP Pinning Violations:** If the server has HPKP pins set, and the presented certificate chain doesn't match the pins, `ERR_SSL_PINNED_KEY_NOT_IN_CERT_CHAIN` will occur.
* **Certificate Transparency Issues:** If the server is required to present valid SCTs and doesn't, `ERR_CERTIFICATE_TRANSPARENCY_REQUIRED` will be returned.
* **Allowing Unknown Roots Incorrectly:**  Developers might mistakenly add hostnames to `hostnames_to_allow_unknown_roots_` for production environments, weakening security.

**7. User Actions Leading to this Code:**

* **Basic HTTPS Navigation:** A user types an HTTPS URL into the browser's address bar. If QUIC is negotiated for that connection, this code will be used.
* **Clicking on an HTTPS Link:** Similar to the above.
* **Web Applications Using `fetch` or `XMLHttpRequest`:** JavaScript code in a web page makes an HTTPS request using QUIC.
* **Background Sync:**  Browser features that perform background data synchronization over HTTPS using QUIC.
* **Service Workers:** Service workers intercept network requests, and if they forward them over QUIC, this code will be invoked.

**8. Debugging Clues:**

* **NetLog:** The code uses `net_log_`. Enabling Chrome's NetLog (`chrome://net-export/`) will provide detailed information about the certificate verification process, including errors and the different stages.
* **Error Messages:** The code sets `error_details_`. Examining these error messages can pinpoint the issue.
* **`UMA_HISTOGRAM_TIMES`:**  Performance histograms can indicate if the verification process is taking an unusually long time, potentially suggesting a problem.
* **Breakpoints:**  Setting breakpoints in the `VerifyProof`, `VerifyCertChain`, `DoVerifyCertComplete`, and `VerifySignature` methods can allow developers to step through the verification process and inspect variables.
* **Checking Certificate Status:** The `cert_verify_result.cert_status` flags are crucial for understanding the nature of certificate errors.

**Self-Correction/Refinement During Thought Process:**

* **Initially, I might overemphasize the direct interaction with JavaScript.**  It's important to clarify the *indirect* relationship through browser APIs.
* **I need to ensure the logical reasoning section provides clear input/output for the key methods.** Just describing the functionality isn't enough.
* **When listing user errors, I should provide specific examples related to the code's functionality (e.g., HPKP, CT).**  Generic certificate errors are less helpful in this context.
* **For debugging, I should focus on tools and techniques specific to Chromium and network debugging.**  Generic debugging advice is less useful.

By following these steps, combining code analysis with an understanding of the broader context, and refining the analysis along the way, I can arrive at a comprehensive and accurate answer to the prompt.
这个 C++ 源代码文件 `net/quic/crypto/proof_verifier_chromium.cc` 是 Chromium 中负责 **QUIC 协议的服务器身份验证（Proof Verification）** 的核心组件。它主要的功能是验证服务器提供的证书链和签名，确保客户端连接到的是合法的服务器，防止中间人攻击。

以下是它的详细功能列表：

**主要功能:**

1. **验证服务器提供的证书链：**
   - 使用 Chromium 的 `CertVerifier` 组件来验证服务器提供的 X.509 证书链的有效性，包括证书的签名、有效期、吊销状态等。
   - 考虑了网络匿名化密钥 (NetworkAnonymizationKey) 的影响。
   - 支持配置允许未知根证书的主机列表 (`hostnames_to_allow_unknown_roots_`)，用于开发或测试环境。

2. **验证服务器配置的签名：**
   - 验证服务器发送的配置信息（`server_config`）的数字签名，以确保配置信息的完整性和真实性。
   - 使用服务器证书中的公钥来验证签名。
   - 签名的数据包括一个固定的标签 (`quic::kProofSignatureLabel`)、客户端的 CHLO 哈希值和服务器配置本身。

3. **处理证书透明度 (Certificate Transparency, CT)：**
   - 检查服务器提供的证书是否满足证书透明度的要求。
   - 使用 `TransportSecurityState` 组件来判断是否需要 CT，并使用 `SCTAuditingDelegate` 来处理 SCT 相关的审计报告。

4. **处理 HTTP 公钥固定 (HTTP Public Key Pinning, HPKP)：**
   - 检查服务器的证书链是否与本地存储的 HPKP 信息匹配，防止中间人使用未授权的证书。
   - 使用 `TransportSecurityState` 组件来检查 HPKP 的状态。

5. **异步执行验证：**
   - 验证过程可能是耗时的操作，例如网络请求 OCSP 信息或 CRL。因此，`ProofVerifierChromium` 使用异步的方式执行验证，避免阻塞主线程。
   - 使用内部的 `Job` 类来管理单个的验证任务。

6. **提供验证结果：**
   - 将验证的结果通过 `quic::ProofVerifyDetails` 结构体返回给 QUIC 的上层模块。
   - 验证结果包括证书验证的详细信息 (`CertVerifyResult`)，是否绕过了 HPKP，以及是否是致命的证书错误。

7. **提供默认的验证上下文：**
   - 通过 `CreateDefaultContext()` 方法创建一个默认的 `ProofVerifyContext`，其中包含了证书验证的标志位和网络日志对象。

**与 JavaScript 的关系：**

`ProofVerifierChromium.cc` 本身是 C++ 代码，JavaScript 代码不能直接调用它。但是，JavaScript 在浏览器环境中发起的 HTTPS 请求（特别是使用 QUIC 协议）会间接地使用到这个组件。

**举例说明：**

当用户在 Chrome 浏览器的地址栏中输入一个以 `https://` 开头的 URL，并且该网站支持 QUIC 协议时，浏览器会尝试使用 QUIC 连接。在 QUIC 握手过程中，服务器会向客户端提供其证书链和签名后的配置信息。

此时，浏览器内部的 QUIC 实现会调用 `ProofVerifierChromium` 的 `VerifyProof` 方法来验证服务器的身份。

**JavaScript 交互流程（简化）：**

1. **JavaScript 代码发起 HTTPS 请求:**
   ```javascript
   fetch('https://example.com')
     .then(response => {
       // 处理响应
     })
     .catch(error => {
       // 处理错误
     });
   ```

2. **浏览器网络栈处理请求，尝试 QUIC 连接。**

3. **QUIC 握手过程中，服务器提供证书链和签名。**

4. **Chromium 的 QUIC 代码调用 `ProofVerifierChromium::VerifyProof`，将服务器提供的证书链、签名等信息传递给它。**

5. **`ProofVerifierChromium` 执行证书链验证、签名验证、CT 检查和 HPKP 检查等操作。**

6. **验证结果返回给 QUIC 代码。**

7. **如果验证成功，QUIC 连接建立，JavaScript 代码可以接收到服务器的响应。如果验证失败，连接会被终止，JavaScript 代码会收到一个网络错误。**

**逻辑推理：假设输入与输出**

**假设输入 (针对 `VerifyProof` 方法):**

* `hostname`: "www.example.com"
* `port`: 443
* `server_config`:  一串表示服务器配置的字节流
* `quic_version`:  `QUIC_VERSION_58` (或其他 QUIC 版本)
* `chlo_hash`:  客户端发送的 CHLO 包的哈希值
* `certs`:  包含服务器证书链的字符串向量，例如 `{"server_cert_der", "intermediate_cert_der", "root_cert_der"}`
* `cert_sct`:  证书的 SCT 信息 (可能为空)
* `signature`:  服务器配置的数字签名

**预期输出 (成功情况):**

* 返回 `quic::QUIC_SUCCESS`
* `verify_details` 指向的 `quic::ProofVerifyDetails` 对象包含：
    - `cert_verify_result`:  包含证书验证的详细结果，例如 `cert_status` 为 `CERT_STATUS_COMMON_NAME_IS_VALID`，`is_issued_by_known_root` 为 `true` 等。
    - `pkp_bypassed`:  如果 HPKP 验证成功，则为 `false`。
    - `is_fatal_cert_error`:  `false`

**预期输出 (失败情况，例如签名验证失败):**

* 返回 `quic::QUIC_FAILURE`
* `error_details` 指向的字符串包含错误信息，例如 "Failed to verify signature of server config"
* `verify_details` 指向的 `quic::ProofVerifyDetails` 对象可能包含：
    - `cert_verify_result.cert_status`:  包含表示签名无效的证书状态，例如 `CERT_STATUS_INVALID`。

**涉及用户或者编程常见的使用错误，举例说明：**

1. **服务器配置错误：**
   - **错误:** 服务器在配置签名时使用了错误的私钥，或者签名的数据不正确。
   - **结果:** `ProofVerifierChromium::Job::VerifySignature` 会返回 `false`，导致验证失败，客户端无法建立 QUIC 连接。
   - **用户现象:** 用户尝试访问网站时，浏览器显示连接错误，例如 `ERR_QUIC_PROTOCOL_ERROR` 或类似的错误信息。

2. **证书链不完整或顺序错误：**
   - **错误:** 服务器提供的证书链缺少中间证书，或者证书的顺序不正确（应该从服务器证书到根证书）。
   - **结果:** `CertVerifier` 验证证书链时会失败，`verify_details_->cert_verify_result.cert_status` 会包含相应的错误码，例如 `CERT_STATUS_INCOMPLETE_CERT_CHAIN`。
   - **用户现象:** 浏览器显示证书错误，例如 "您的连接不是私密连接"，并显示 `NET::ERR_CERT_AUTHORITY_INVALID` 或 `NET::ERR_CERT_COMMON_NAME_INVALID` 等错误。

3. **HPKP 配置错误：**
   - **错误:** 网站配置了 HPKP，但是服务器提供的证书链的公钥与本地存储的 pin 不匹配。
   - **结果:** `ProofVerifierChromium::Job::DoVerifyCertComplete` 中会检测到 HPKP 违规，并将 `result` 设置为 `ERR_SSL_PINNED_KEY_NOT_IN_CERT_CHAIN`，`verify_details_->cert_verify_result.cert_status` 会包含 `CERT_STATUS_PINNED_KEY_MISSING`。
   - **用户现象:** 浏览器显示证书错误，提示公钥不匹配。

4. **证书透明度要求未满足：**
   - **错误:** 网站要求证书透明度，但服务器提供的证书缺少有效的 SCT 信息。
   - **结果:** `ProofVerifierChromium::Job::CheckCTRequirements` 会返回 `ERR_CERTIFICATE_TRANSPARENCY_REQUIRED`，`verify_details_->cert_verify_result.cert_status` 会包含 `CERT_STATUS_CERTIFICATE_TRANSPARENCY_REQUIRED`。
   - **用户现象:** 浏览器可能显示证书错误，指示缺少证书透明度信息。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户在 Chrome 浏览器地址栏输入 `https://www.example.com` 并按下回车。**
2. **Chrome 浏览器解析 URL，并查找与该域名对应的 IP 地址。**
3. **浏览器尝试与服务器建立连接。如果浏览器和服务器都支持 QUIC 协议，并且满足其他条件（例如，之前成功建立过 QUIC 连接），浏览器会尝试使用 QUIC 连接。**
4. **QUIC 客户端发起握手，发送 Client Hello (CHLO) 数据包。**
5. **服务器响应 Server Hello (SHLO) 数据包，其中包含服务器的配置信息和签名。**
6. **服务器发送证书链和任何相关的 SCT 信息。**
7. **Chrome 浏览器的 QUIC 实现接收到服务器的证书链、签名和配置信息。**
8. **QUIC 代码会创建一个 `ProofVerifyContextChromium` 对象，其中包含用于证书验证的标志和网络日志对象。**
9. **QUIC 代码调用 `ProofVerifierChromium::VerifyProof` 方法，并将服务器提供的信息和创建的上下文对象传递给它。**
10. **`ProofVerifierChromium` 创建一个 `Job` 对象来处理这个验证任务。**
11. **`Job` 对象首先调用 `GetX509Certificate` 将 DER 编码的证书转换为 `X509Certificate` 对象。**
12. **然后，`Job` 对象调用 `VerifySignature` 验证服务器配置的签名。**
13. **如果签名验证成功，`Job` 对象调用 `VerifyCert` 启动证书链的验证。这会使用 `CertVerifier` 组件进行异步的证书链验证，可能涉及到网络请求 OCSP 或 CRL 信息。**
14. **在证书链验证完成后，`Job` 对象会调用 `DoVerifyCertComplete` 进行后续的检查，包括 HPKP 和 CT 检查。**
15. **验证结果最终会通过回调函数返回给 QUIC 代码。**

**作为调试线索：**

- 如果用户报告无法访问某个 HTTPS 网站，并且怀疑是证书问题，可以启用 Chrome 的网络日志 (chrome://net-export/) 来查看详细的网络交互信息，包括 QUIC 握手过程和证书验证的详细信息。
- 在网络日志中可以找到 `ProofVerifierChromium` 相关的事件，例如证书链的内容、验证结果、错误信息等。
- 可以设置断点在 `ProofVerifierChromium.cc` 的关键函数中，例如 `VerifyProof`、`VerifySignature`、`DoVerifyCertComplete` 等，来跟踪验证过程中的变量值和执行流程。
- 查看 `verify_details_->cert_verify_result.cert_status` 的值可以快速定位证书验证失败的原因。
- 检查 `error_details_` 字符串可以获取更详细的错误描述。

总而言之，`net/quic/crypto/proof_verifier_chromium.cc` 在 Chromium 的 QUIC 实现中扮演着至关重要的角色，它负责确保客户端连接到的是经过身份验证的合法服务器，是 QUIC 安全性的关键组成部分。它与 JavaScript 的联系是间接的，但直接影响着用户通过浏览器访问 HTTPS 网站的体验。

### 提示词
```
这是目录为net/quic/crypto/proof_verifier_chromium.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2013 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/quic/crypto/proof_verifier_chromium.h"

#include <string_view>
#include <utility>

#include "base/containers/contains.h"
#include "base/containers/span.h"
#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/logging.h"
#include "base/memory/raw_ptr.h"
#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_macros.h"
#include "base/strings/stringprintf.h"
#include "base/time/time.h"
#include "crypto/signature_verifier.h"
#include "net/base/host_port_pair.h"
#include "net/base/net_errors.h"
#include "net/base/network_anonymization_key.h"
#include "net/cert/cert_status_flags.h"
#include "net/cert/cert_verifier.h"
#include "net/cert/ct_verifier.h"
#include "net/cert/sct_auditing_delegate.h"
#include "net/cert/x509_util.h"
#include "net/http/transport_security_state.h"
#include "net/third_party/quiche/src/quiche/quic/core/crypto/crypto_protocol.h"

using base::StringPrintf;
using std::string;

namespace net {

ProofVerifyDetailsChromium::ProofVerifyDetailsChromium() = default;

ProofVerifyDetailsChromium::~ProofVerifyDetailsChromium() = default;

ProofVerifyDetailsChromium::ProofVerifyDetailsChromium(
    const ProofVerifyDetailsChromium&) = default;

quic::ProofVerifyDetails* ProofVerifyDetailsChromium::Clone() const {
  ProofVerifyDetailsChromium* other = new ProofVerifyDetailsChromium;
  other->cert_verify_result = cert_verify_result;
  return other;
}

// A Job handles the verification of a single proof.  It is owned by the
// quic::ProofVerifier. If the verification can not complete synchronously, it
// will notify the quic::ProofVerifier upon completion.
class ProofVerifierChromium::Job {
 public:
  Job(ProofVerifierChromium* proof_verifier,
      CertVerifier* cert_verifier,
      TransportSecurityState* transport_security_state,
      SCTAuditingDelegate* sct_auditing_delegate,
      int cert_verify_flags,
      const NetLogWithSource& net_log);

  Job(const Job&) = delete;
  Job& operator=(const Job&) = delete;

  ~Job();

  // Starts the proof verification.  If |quic::QUIC_PENDING| is returned, then
  // |callback| will be invoked asynchronously when the verification completes.
  quic::QuicAsyncStatus VerifyProof(
      const std::string& hostname,
      const uint16_t port,
      const std::string& server_config,
      quic::QuicTransportVersion quic_version,
      std::string_view chlo_hash,
      const std::vector<std::string>& certs,
      const std::string& cert_sct,
      const std::string& signature,
      std::string* error_details,
      std::unique_ptr<quic::ProofVerifyDetails>* verify_details,
      std::unique_ptr<quic::ProofVerifierCallback> callback);

  // Starts the certificate chain verification of |certs|.  If
  // |quic::QUIC_PENDING| is returned, then |callback| will be invoked
  // asynchronously when the verification completes.
  quic::QuicAsyncStatus VerifyCertChain(
      const std::string& hostname,
      const uint16_t port,
      const std::vector<std::string>& certs,
      const std::string& ocsp_response,
      const std::string& cert_sct,
      std::string* error_details,
      std::unique_ptr<quic::ProofVerifyDetails>* verify_details,
      std::unique_ptr<quic::ProofVerifierCallback> callback);

 private:
  enum State {
    STATE_NONE,
    STATE_VERIFY_CERT,
    STATE_VERIFY_CERT_COMPLETE,
  };

  // Convert |certs| to |cert_|(X509Certificate). Returns true if successful.
  bool GetX509Certificate(
      const std::vector<string>& certs,
      std::string* error_details,
      std::unique_ptr<quic::ProofVerifyDetails>* verify_details);

  // Start the cert verification.
  quic::QuicAsyncStatus VerifyCert(
      const string& hostname,
      const uint16_t port,
      const std::string& ocsp_response,
      const std::string& cert_sct,
      std::string* error_details,
      std::unique_ptr<quic::ProofVerifyDetails>* verify_details,
      std::unique_ptr<quic::ProofVerifierCallback> callback);

  int DoLoop(int last_io_result);
  void OnIOComplete(int result);
  int DoVerifyCert(int result);
  int DoVerifyCertComplete(int result);

  bool VerifySignature(const std::string& signed_data,
                       quic::QuicTransportVersion quic_version,
                       std::string_view chlo_hash,
                       const std::string& signature,
                       const std::string& cert);

  bool ShouldAllowUnknownRootForHost(const std::string& hostname);

  int CheckCTRequirements();

  // Must be before `cert_verifier_request_`, to avoid dangling pointer
  // warnings, as the Request may be storing a raw pointer to which may have a
  // raw_ptr to its `cert_verify_result`.
  std::unique_ptr<ProofVerifyDetailsChromium> verify_details_;

  // Proof verifier to notify when this jobs completes.
  raw_ptr<ProofVerifierChromium> proof_verifier_;

  // The underlying verifier used for verifying certificates.
  raw_ptr<CertVerifier> verifier_;
  std::unique_ptr<CertVerifier::Request> cert_verifier_request_;

  raw_ptr<TransportSecurityState> transport_security_state_;

  raw_ptr<SCTAuditingDelegate> sct_auditing_delegate_;

  // |hostname| specifies the hostname for which |certs| is a valid chain.
  std::string hostname_;
  // |port| specifies the target port for the connection.
  uint16_t port_;
  // Encoded stapled OCSP response for |certs|.
  std::string ocsp_response_;
  // Encoded SignedCertificateTimestampList for |certs|.
  std::string cert_sct_;

  std::unique_ptr<quic::ProofVerifierCallback> callback_;
  std::string error_details_;

  // X509Certificate from a chain of DER encoded certificates.
  scoped_refptr<X509Certificate> cert_;

  // |cert_verify_flags| is bitwise OR'd of CertVerifier::VerifyFlags and it is
  // passed to CertVerifier::Verify.
  int cert_verify_flags_;

  State next_state_ = STATE_NONE;

  base::TimeTicks start_time_;

  NetLogWithSource net_log_;
};

ProofVerifierChromium::Job::Job(
    ProofVerifierChromium* proof_verifier,
    CertVerifier* cert_verifier,
    TransportSecurityState* transport_security_state,
    SCTAuditingDelegate* sct_auditing_delegate,
    int cert_verify_flags,
    const NetLogWithSource& net_log)
    : proof_verifier_(proof_verifier),
      verifier_(cert_verifier),
      transport_security_state_(transport_security_state),
      sct_auditing_delegate_(sct_auditing_delegate),
      cert_verify_flags_(cert_verify_flags),
      start_time_(base::TimeTicks::Now()),
      net_log_(net_log) {
  CHECK(proof_verifier_);
  CHECK(verifier_);
  CHECK(transport_security_state_);
}

ProofVerifierChromium::Job::~Job() {
  base::TimeTicks end_time = base::TimeTicks::Now();
  UMA_HISTOGRAM_TIMES("Net.QuicSession.VerifyProofTime",
                      end_time - start_time_);
  // |hostname_| will always be canonicalized to lowercase.
  if (hostname_.compare("www.google.com") == 0) {
    UMA_HISTOGRAM_TIMES("Net.QuicSession.VerifyProofTime.google",
                        end_time - start_time_);
  }
}

quic::QuicAsyncStatus ProofVerifierChromium::Job::VerifyProof(
    const string& hostname,
    const uint16_t port,
    const string& server_config,
    quic::QuicTransportVersion quic_version,
    std::string_view chlo_hash,
    const std::vector<string>& certs,
    const std::string& cert_sct,
    const string& signature,
    std::string* error_details,
    std::unique_ptr<quic::ProofVerifyDetails>* verify_details,
    std::unique_ptr<quic::ProofVerifierCallback> callback) {
  DCHECK(error_details);
  DCHECK(verify_details);
  DCHECK(callback);

  error_details->clear();

  if (STATE_NONE != next_state_) {
    *error_details = "Certificate is already set and VerifyProof has begun";
    DLOG(DFATAL) << *error_details;
    return quic::QUIC_FAILURE;
  }

  verify_details_ = std::make_unique<ProofVerifyDetailsChromium>();

  // Converts |certs| to |cert_|.
  if (!GetX509Certificate(certs, error_details, verify_details))
    return quic::QUIC_FAILURE;

  // We call VerifySignature first to avoid copying of server_config and
  // signature.
  if (!VerifySignature(server_config, quic_version, chlo_hash, signature,
                       certs[0])) {
    *error_details = "Failed to verify signature of server config";
    DLOG(WARNING) << *error_details;
    verify_details_->cert_verify_result.cert_status = CERT_STATUS_INVALID;
    *verify_details = std::move(verify_details_);
    return quic::QUIC_FAILURE;
  }

  return VerifyCert(hostname, port, /*ocsp_response=*/std::string(), cert_sct,
                    error_details, verify_details, std::move(callback));
}

quic::QuicAsyncStatus ProofVerifierChromium::Job::VerifyCertChain(
    const string& hostname,
    const uint16_t port,
    const std::vector<string>& certs,
    const std::string& ocsp_response,
    const std::string& cert_sct,
    std::string* error_details,
    std::unique_ptr<quic::ProofVerifyDetails>* verify_details,
    std::unique_ptr<quic::ProofVerifierCallback> callback) {
  DCHECK(error_details);
  DCHECK(verify_details);
  DCHECK(callback);

  error_details->clear();

  if (STATE_NONE != next_state_) {
    *error_details = "Certificate is already set and VerifyCertChain has begun";
    DLOG(DFATAL) << *error_details;
    return quic::QUIC_FAILURE;
  }

  verify_details_ = std::make_unique<ProofVerifyDetailsChromium>();

  // Converts |certs| to |cert_|.
  if (!GetX509Certificate(certs, error_details, verify_details))
    return quic::QUIC_FAILURE;

  return VerifyCert(hostname, port, ocsp_response, cert_sct, error_details,
                    verify_details, std::move(callback));
}

bool ProofVerifierChromium::Job::GetX509Certificate(
    const std::vector<string>& certs,
    std::string* error_details,
    std::unique_ptr<quic::ProofVerifyDetails>* verify_details) {
  if (certs.empty()) {
    *error_details = "Failed to create certificate chain. Certs are empty.";
    DLOG(WARNING) << *error_details;
    verify_details_->cert_verify_result.cert_status = CERT_STATUS_INVALID;
    *verify_details = std::move(verify_details_);
    return false;
  }

  // Convert certs to X509Certificate.
  std::vector<std::string_view> cert_pieces(certs.size());
  for (unsigned i = 0; i < certs.size(); i++) {
    cert_pieces[i] = std::string_view(certs[i]);
  }
  cert_ = X509Certificate::CreateFromDERCertChain(cert_pieces);
  if (!cert_.get()) {
    *error_details = "Failed to create certificate chain";
    DLOG(WARNING) << *error_details;
    verify_details_->cert_verify_result.cert_status = CERT_STATUS_INVALID;
    *verify_details = std::move(verify_details_);
    return false;
  }
  return true;
}

quic::QuicAsyncStatus ProofVerifierChromium::Job::VerifyCert(
    const string& hostname,
    const uint16_t port,
    const std::string& ocsp_response,
    const std::string& cert_sct,
    std::string* error_details,
    std::unique_ptr<quic::ProofVerifyDetails>* verify_details,
    std::unique_ptr<quic::ProofVerifierCallback> callback) {
  hostname_ = hostname;
  port_ = port;
  ocsp_response_ = ocsp_response;
  cert_sct_ = cert_sct;

  next_state_ = STATE_VERIFY_CERT;
  switch (DoLoop(OK)) {
    case OK:
      *verify_details = std::move(verify_details_);
      return quic::QUIC_SUCCESS;
    case ERR_IO_PENDING:
      callback_ = std::move(callback);
      return quic::QUIC_PENDING;
    default:
      *error_details = error_details_;
      *verify_details = std::move(verify_details_);
      return quic::QUIC_FAILURE;
  }
}

int ProofVerifierChromium::Job::DoLoop(int last_result) {
  int rv = last_result;
  do {
    State state = next_state_;
    next_state_ = STATE_NONE;
    switch (state) {
      case STATE_VERIFY_CERT:
        DCHECK(rv == OK);
        rv = DoVerifyCert(rv);
        break;
      case STATE_VERIFY_CERT_COMPLETE:
        rv = DoVerifyCertComplete(rv);
        break;
      case STATE_NONE:
      default:
        rv = ERR_UNEXPECTED;
        LOG(DFATAL) << "unexpected state " << state;
        break;
    }
  } while (rv != ERR_IO_PENDING && next_state_ != STATE_NONE);
  return rv;
}

void ProofVerifierChromium::Job::OnIOComplete(int result) {
  int rv = DoLoop(result);
  if (rv != ERR_IO_PENDING) {
    std::unique_ptr<quic::ProofVerifierCallback> callback(std::move(callback_));
    // Callback expects quic::ProofVerifyDetails not ProofVerifyDetailsChromium.
    std::unique_ptr<quic::ProofVerifyDetails> verify_details(
        std::move(verify_details_));
    callback->Run(rv == OK, error_details_, &verify_details);
    // Will delete |this|.
    proof_verifier_->OnJobComplete(this);
  }
}

int ProofVerifierChromium::Job::DoVerifyCert(int result) {
  next_state_ = STATE_VERIFY_CERT_COMPLETE;

  return verifier_->Verify(
      CertVerifier::RequestParams(cert_, hostname_, cert_verify_flags_,
                                  ocsp_response_, cert_sct_),
      &verify_details_->cert_verify_result,
      base::BindOnce(&ProofVerifierChromium::Job::OnIOComplete,
                     base::Unretained(this)),
      &cert_verifier_request_, net_log_);
}

bool ProofVerifierChromium::Job::ShouldAllowUnknownRootForHost(
    const std::string& hostname) {
  if (base::Contains(proof_verifier_->hostnames_to_allow_unknown_roots_, "")) {
    return true;
  }
  return base::Contains(proof_verifier_->hostnames_to_allow_unknown_roots_,
                        hostname);
}

int ProofVerifierChromium::Job::DoVerifyCertComplete(int result) {
  base::UmaHistogramSparse("Net.QuicSession.CertVerificationResult", -result);
  cert_verifier_request_.reset();

  const CertVerifyResult& cert_verify_result =
      verify_details_->cert_verify_result;
  const CertStatus cert_status = cert_verify_result.cert_status;

  // If the connection was good, check HPKP and CT status simultaneously,
  // but prefer to treat the HPKP error as more serious, if there was one.
  if (result == OK) {
    int ct_result = CheckCTRequirements();
    TransportSecurityState::PKPStatus pin_validity =
        transport_security_state_->CheckPublicKeyPins(
            HostPortPair(hostname_, port_),
            cert_verify_result.is_issued_by_known_root,
            cert_verify_result.public_key_hashes);
    switch (pin_validity) {
      case TransportSecurityState::PKPStatus::VIOLATED:
        result = ERR_SSL_PINNED_KEY_NOT_IN_CERT_CHAIN;
        verify_details_->cert_verify_result.cert_status |=
            CERT_STATUS_PINNED_KEY_MISSING;
        break;
      case TransportSecurityState::PKPStatus::BYPASSED:
        verify_details_->pkp_bypassed = true;
        [[fallthrough]];
      case TransportSecurityState::PKPStatus::OK:
        // Do nothing.
        break;
    }
    if (result != ERR_SSL_PINNED_KEY_NOT_IN_CERT_CHAIN && ct_result != OK)
      result = ct_result;
  }

  if (result == OK &&
      !verify_details_->cert_verify_result.is_issued_by_known_root &&
      !ShouldAllowUnknownRootForHost(hostname_)) {
    result = ERR_QUIC_CERT_ROOT_NOT_KNOWN;
  }

  verify_details_->is_fatal_cert_error =
      IsCertStatusError(cert_status) &&
      result != ERR_CERT_KNOWN_INTERCEPTION_BLOCKED &&
      transport_security_state_->ShouldSSLErrorsBeFatal(hostname_);

  if (result != OK) {
    std::string error_string = ErrorToString(result);
    error_details_ = StringPrintf("Failed to verify certificate chain: %s",
                                  error_string.c_str());
    DLOG(WARNING) << error_details_;
  }

  // Exit DoLoop and return the result to the caller to VerifyProof.
  DCHECK_EQ(STATE_NONE, next_state_);
  return result;
}

bool ProofVerifierChromium::Job::VerifySignature(
    const string& signed_data,
    quic::QuicTransportVersion quic_version,
    std::string_view chlo_hash,
    const string& signature,
    const string& cert) {
  size_t size_bits;
  X509Certificate::PublicKeyType type;
  X509Certificate::GetPublicKeyInfo(cert_->cert_buffer(), &size_bits, &type);
  crypto::SignatureVerifier::SignatureAlgorithm algorithm;
  switch (type) {
    case X509Certificate::kPublicKeyTypeRSA:
      algorithm = crypto::SignatureVerifier::RSA_PSS_SHA256;
      break;
    case X509Certificate::kPublicKeyTypeECDSA:
      algorithm = crypto::SignatureVerifier::ECDSA_SHA256;
      break;
    default:
      LOG(ERROR) << "Unsupported public key type " << type;
      return false;
  }

  if (signature.empty()) {
    DLOG(WARNING) << "Signature is empty, thus cannot possibly be valid";
    return false;
  }

  crypto::SignatureVerifier verifier;
  if (!x509_util::SignatureVerifierInitWithCertificate(
          &verifier, algorithm, base::as_byte_span(signature),
          cert_->cert_buffer())) {
    DLOG(WARNING) << "SignatureVerifierInitWithCertificate failed";
    return false;
  }

  verifier.VerifyUpdate(base::as_byte_span(quic::kProofSignatureLabel));
  uint32_t len = chlo_hash.length();
  verifier.VerifyUpdate(base::byte_span_from_ref(len));
  verifier.VerifyUpdate(base::as_byte_span(chlo_hash));
  verifier.VerifyUpdate(base::as_byte_span(signed_data));

  if (!verifier.VerifyFinal()) {
    DLOG(WARNING) << "VerifyFinal failed";
    return false;
  }

  DVLOG(1) << "VerifyFinal success";
  return true;
}

int ProofVerifierChromium::Job::CheckCTRequirements() {
  const CertVerifyResult& cert_verify_result =
      verify_details_->cert_verify_result;

  TransportSecurityState::CTRequirementsStatus ct_requirement_status =
      transport_security_state_->CheckCTRequirements(
          HostPortPair(hostname_, port_),
          cert_verify_result.is_issued_by_known_root,
          cert_verify_result.public_key_hashes,
          cert_verify_result.verified_cert.get(),
          cert_verify_result.policy_compliance);

  if (sct_auditing_delegate_) {
    sct_auditing_delegate_->MaybeEnqueueReport(
        HostPortPair(hostname_, port_), cert_verify_result.verified_cert.get(),
        cert_verify_result.scts);
  }

  switch (ct_requirement_status) {
    case TransportSecurityState::CT_REQUIREMENTS_NOT_MET:
      verify_details_->cert_verify_result.cert_status |=
          CERT_STATUS_CERTIFICATE_TRANSPARENCY_REQUIRED;
      return ERR_CERTIFICATE_TRANSPARENCY_REQUIRED;
    case TransportSecurityState::CT_REQUIREMENTS_MET:
    case TransportSecurityState::CT_NOT_REQUIRED:
      return OK;
  }
}

ProofVerifierChromium::ProofVerifierChromium(
    CertVerifier* cert_verifier,
    TransportSecurityState* transport_security_state,
    SCTAuditingDelegate* sct_auditing_delegate,
    std::set<std::string> hostnames_to_allow_unknown_roots,
    const NetworkAnonymizationKey& network_anonymization_key)
    : cert_verifier_(cert_verifier),
      transport_security_state_(transport_security_state),
      sct_auditing_delegate_(sct_auditing_delegate),
      hostnames_to_allow_unknown_roots_(hostnames_to_allow_unknown_roots),
      network_anonymization_key_(network_anonymization_key) {
  DCHECK(cert_verifier_);
  DCHECK(transport_security_state_);
}

ProofVerifierChromium::~ProofVerifierChromium() = default;

quic::QuicAsyncStatus ProofVerifierChromium::VerifyProof(
    const std::string& hostname,
    const uint16_t port,
    const std::string& server_config,
    quic::QuicTransportVersion quic_version,
    std::string_view chlo_hash,
    const std::vector<std::string>& certs,
    const std::string& cert_sct,
    const std::string& signature,
    const quic::ProofVerifyContext* verify_context,
    std::string* error_details,
    std::unique_ptr<quic::ProofVerifyDetails>* verify_details,
    std::unique_ptr<quic::ProofVerifierCallback> callback) {
  if (!verify_context) {
    DLOG(FATAL) << "Missing proof verify context";
    *error_details = "Missing context";
    return quic::QUIC_FAILURE;
  }
  const ProofVerifyContextChromium* chromium_context =
      reinterpret_cast<const ProofVerifyContextChromium*>(verify_context);
  std::unique_ptr<Job> job = std::make_unique<Job>(
      this, cert_verifier_, transport_security_state_, sct_auditing_delegate_,
      chromium_context->cert_verify_flags, chromium_context->net_log);
  quic::QuicAsyncStatus status = job->VerifyProof(
      hostname, port, server_config, quic_version, chlo_hash, certs, cert_sct,
      signature, error_details, verify_details, std::move(callback));
  if (status == quic::QUIC_PENDING) {
    Job* job_ptr = job.get();
    active_jobs_[job_ptr] = std::move(job);
  }
  return status;
}

quic::QuicAsyncStatus ProofVerifierChromium::VerifyCertChain(
    const std::string& hostname,
    const uint16_t port,
    const std::vector<std::string>& certs,
    const std::string& ocsp_response,
    const std::string& cert_sct,
    const quic::ProofVerifyContext* verify_context,
    std::string* error_details,
    std::unique_ptr<quic::ProofVerifyDetails>* verify_details,
    uint8_t* /*out_alert*/,
    std::unique_ptr<quic::ProofVerifierCallback> callback) {
  if (!verify_context) {
    *error_details = "Missing context";
    return quic::QUIC_FAILURE;
  }
  const ProofVerifyContextChromium* chromium_context =
      reinterpret_cast<const ProofVerifyContextChromium*>(verify_context);
  std::unique_ptr<Job> job = std::make_unique<Job>(
      this, cert_verifier_, transport_security_state_, sct_auditing_delegate_,
      chromium_context->cert_verify_flags, chromium_context->net_log);
  quic::QuicAsyncStatus status =
      job->VerifyCertChain(hostname, port, certs, ocsp_response, cert_sct,
                           error_details, verify_details, std::move(callback));
  if (status == quic::QUIC_PENDING) {
    Job* job_ptr = job.get();
    active_jobs_[job_ptr] = std::move(job);
  }
  return status;
}

std::unique_ptr<quic::ProofVerifyContext>
ProofVerifierChromium::CreateDefaultContext() {
  return std::make_unique<ProofVerifyContextChromium>(0,
                                                      net::NetLogWithSource());
}

void ProofVerifierChromium::OnJobComplete(Job* job) {
  active_jobs_.erase(job);
}

}  // namespace net
```