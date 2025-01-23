Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of the `net/cert/cert_verify_proc_builtin.cc` file in Chromium's network stack. I need to explain what this code does, identify any relationships with JavaScript, provide examples of logical reasoning (input/output), discuss potential user/programming errors, explain how a user might reach this code (debugging), and finally, summarize the overall functionality.

**Plan:**

1. **High-level function:**  Determine the primary purpose of this code snippet within the larger file. It seems to be related to adding additional trust anchors and untrusted authorities for certificate verification.
2. **Detailed Breakdown:** Analyze the loops and conditional statements to understand exactly how the additional certificates are processed and stored. Pay attention to the different categories of additional certificates.
3. **JavaScript Relationship:** Consider if this server-side certificate verification process directly interacts with JavaScript running in a browser. The likely interaction is indirect, through the results of this verification influencing the browser's decision to trust a website, which could then impact JavaScript execution.
4. **Logical Reasoning (Input/Output):**  Hypothesize scenarios with different types of `instance_params.additional_...` data and predict how the `additional_trust_store_` and `additional_constraints_` would be updated.
5. **User/Programming Errors:** Think about common mistakes in providing additional certificates, such as invalid certificate formats or incorrect usage of the API.
6. **User Operation to Reach Here:** Trace the steps a user might take in a browser that would trigger certificate verification involving these additional certificates. This likely involves enterprise policies or developer settings.
7. **Overall Summary:**  Condense the detailed breakdown into a concise summary of the code's purpose.
这是 `net/cert/cert_verify_proc_builtin.cc` 文件的一部分，主要负责在 Chromium 中处理自定义的信任锚点和不受信任的授权机构，以便在证书验证过程中使用。

**功能归纳:**

这段代码的主要功能是配置 `CertVerifyProcBuiltin` 实例，使其能够处理除了系统默认信任存储之外的额外信任锚点和不受信任的授权机构。具体来说，它执行以下操作：

1. **处理带有强制过期策略的锚点：**  遍历 `instance_params.trust_anchors_with_enforced_expiry`，将这些证书添加到 `additional_trust_store_` 中，并强制执行其过期策略。
2. **处理带有约束的锚点和叶子证书：** 遍历 `instance_params.additional_trust_anchors_and_leafs`。
    - 如果证书不在 `additional_trust_store_` 中，并且定义了允许的 DNS 名称或 CIDR，则将其添加到 `additional_constraints_` 列表中，以便在后续的证书路径构建过程中应用这些约束。
    - 将证书添加到 `additional_trust_store_` 中，指定其信任类型为锚点或叶子证书。
    - 使用 `net_log` 记录添加证书的事件。
3. **处理带有强制约束的锚点：** 遍历 `instance_params.additional_trust_anchors_with_enforced_constraints`。
    - 如果证书不在 `additional_trust_store_` 中，则将其添加到 `additional_trust_store_` 中，并强制执行其约束。
    - 使用 `net_log` 记录添加证书的事件。
4. **处理额外的信任锚点：** 遍历 `instance_params.additional_trust_anchors`。
    - 如果证书尚未存在于 `additional_trust_store_` 中，则将其添加为信任锚点。这样做是为了避免重复添加，并且如果同一个锚点已经以强制约束的方式添加过，则优先使用带有强制约束的版本。
    - 使用 `net_log` 记录添加证书的事件。
5. **处理额外的不受信任的授权机构：** 遍历 `instance_params.additional_untrusted_authorities`。
    - 如果证书尚未存在于 `additional_trust_store_` 中，则将其添加为不受信任的证书。这是为了避免将已经作为信任锚点添加的证书再次添加为不受信任的，因为这可能会导致其不再被视为信任锚点。
    - 使用 `net_log` 记录添加证书的事件。
6. **记录实例创建完成事件：** 使用 `net_log` 记录 `CertVerifyProcBuiltin` 实例创建完成的事件。

**与 JavaScript 的关系：**

这段 C++ 代码本身不直接与 JavaScript 代码交互。但是，它所执行的证书验证过程对于 Web 浏览器的安全至关重要，并且会间接地影响 JavaScript 的执行。

例如：

- **HTTPS 连接建立：** 当 JavaScript 代码尝试通过 `fetch` 或 `XMLHttpRequest` 与一个 HTTPS 网站建立连接时，Chromium 的网络栈会使用此代码配置的证书验证过程来验证服务器的 SSL/TLS 证书。如果验证失败（例如，证书是由一个未知的或不受信任的 CA 签发的），浏览器可能会阻止连接或显示安全警告，从而阻止 JavaScript 代码成功获取数据。
- **企业策略或开发者设置：**  企业管理员或开发者可能会配置额外的信任锚点，以便访问内部网站或进行开发测试。这些配置最终会传递到这段 C++ 代码中进行处理。如果配置的信任锚点不正确，可能会导致 JavaScript 无法访问预期的资源。

**逻辑推理（假设输入与输出）：**

**假设输入：**

```c++
CertVerifyProc::InstanceParams instance_params;

// 假设添加一个自定义的企业根证书
bssl::UniquePtr<CRYPTO_BUFFER> enterprise_root_cert_buffer = ...; // 假设已加载证书数据
auto parsed_enterprise_root_cert = bssl::ParsedCertificate::Create(enterprise_root_cert_buffer.get());
instance_params.additional_trust_anchors.push_back(parsed_enterprise_root_cert);

// 假设添加一个带有 DNS 约束的内部 CA 证书
bssl::UniquePtr<CRYPTO_BUFFER> internal_ca_cert_buffer = ...; // 假设已加载证书数据
auto parsed_internal_ca_cert = bssl::ParsedCertificate::Create(internal_ca_cert_buffer.get());
CertVerifyProc::CertificateWithConstraints internal_ca_with_constraints;
internal_ca_with_constraints.certificate = parsed_internal_ca_cert;
internal_ca_with_constraints.permitted_dns_names = {"internal.example.com"};
instance_params.additional_trust_anchors_and_leafs.push_back(internal_ca_with_constraints);
```

**预期输出：**

- `additional_trust_store_` 将包含 `parsed_enterprise_root_cert` 和 `parsed_internal_ca_cert`。
- `additional_constraints_` 将包含 `internal_ca_with_constraints`，这意味着在验证由 `parsed_internal_ca_cert` 签发的证书时，会检查其域名是否为 `internal.example.com`。
- 当使用配置了这些 `instance_params` 的 `CertVerifyProcBuiltin` 实例验证证书时：
    - 由 `enterprise_root_cert` 签发的证书将被认为是受信任的。
    - 由 `internal_ca_cert` 签发的证书，并且其域名为 `internal.example.com`，将被认为是有效的。如果域名不是 `internal.example.com`，则验证可能会失败。

**用户或编程常见的使用错误：**

1. **添加无效的证书数据：**  如果 `instance_params` 中包含无法解析为有效 X.509 证书的二进制数据，`ParseCertificateFromBuffer` 将返回空，但代码中似乎没有针对这种情况的直接错误处理来阻止添加到存储中。不过，后续的证书验证过程会因为无法构建有效的证书链而失败。
   ```c++
   // 错误示例：传入非证书数据
   CertVerifyProc::InstanceParams instance_params;
   std::string invalid_cert_data = "This is not a certificate.";
   auto invalid_buffer = CRYPTO_BUFFER_new(reinterpret_cast<const uint8_t*>(invalid_cert_data.data()), invalid_cert_data.size(), nullptr);
   auto parsed_invalid_cert = bssl::ParsedCertificate::Create(invalid_buffer.get());
   // parsed_invalid_cert 将为空，但代码会尝试添加（虽然可能不会成功）
   instance_params.additional_trust_anchors.push_back(parsed_invalid_cert);
   ```
2. **添加重复的信任锚点：**  代码中虽然有 `additional_trust_store_.Contains()` 的检查，但如果以不同的方式添加同一个证书（例如，同时添加到 `additional_trust_anchors` 和 `additional_trust_anchors_with_enforced_constraints`），可能会导致意外行为，因为 `TrustStoreInMemory` 不期望包含重复项。
3. **错误的 DNS 或 CIDR 约束配置：**  在 `permitted_dns_names` 或 `permitted_cidrs` 中配置错误的域名或 IP 地址范围会导致对由这些受限 CA 签发的证书进行验证时出现意外的成功或失败。
4. **忘记处理证书解析错误：** 虽然代码中使用了 `bssl::CertErrors` 来捕获解析错误，但在添加证书到存储的过程中，并没有直接使用这些错误信息进行判断或记录，这可能会在调试时带来困难。

**用户操作如何一步步到达这里（调试线索）：**

1. **企业策略配置：** 企业管理员可以通过 Chromium 的管理策略配置额外的根证书或中间 CA 证书，以便员工可以访问内部网站。这些策略最终会转化为 `CertVerifyProc::InstanceParams` 并传递给 `CreateCertVerifyProcBuiltin`。
2. **开发者标志或命令行参数：** 开发者可能使用 Chromium 的命令行参数或开发者标志来加载自定义的证书用于测试目的。
3. **扩展程序或应用程序 API：** 某些浏览器扩展程序或应用程序可能使用 Chromium 提供的 API 来配置自定义的证书验证行为。
4. **网络请求失败：** 当用户尝试访问一个使用 HTTPS 的网站时，如果服务器的证书无法被系统默认的信任存储验证，Chromium 可能会尝试使用配置的额外信任锚点。可以通过查看 Chrome 的 `net-internals` (chrome://net-internals/#security) 页面来查看证书链和验证状态。
5. **安全警告：** 如果证书验证失败，浏览器通常会显示安全警告。用户查看详细信息或选择继续访问（如果允许）可能会触发更详细的日志记录，从而帮助开发者定位到 `CertVerifyProcBuiltin` 的执行。

**总结功能:**

这段代码负责初始化 `CertVerifyProcBuiltin` 实例，使其能够识别和使用除了系统默认信任存储之外的自定义信任锚点、带有约束的证书以及不受信任的授权机构。这使得 Chromium 能够适应各种特殊的证书验证需求，例如企业内部 PKI 或开发者测试环境。它通过遍历 `InstanceParams` 中提供的不同类型的证书集合，并将这些证书添加到内部的信任存储和约束列表中来实现这一功能，并在过程中使用 `net_log` 记录相关事件。

### 提示词
```
这是目录为net/cert/cert_verify_proc_builtin.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
.WithEnforceAnchorExpiry();

  for (const auto& cert_with_possible_constraints :
       instance_params.additional_trust_anchors_and_leafs) {
    const std::shared_ptr<const bssl::ParsedCertificate>& cert =
        cert_with_possible_constraints.certificate;
    if (!additional_trust_store_.Contains(cert.get())) {
      if (!cert_with_possible_constraints.permitted_dns_names.empty() ||
          !cert_with_possible_constraints.permitted_cidrs.empty()) {
        additional_constraints_.push_back(cert_with_possible_constraints);
      }

      bssl::CertErrors parsing_errors;
      additional_trust_store_.AddCertificate(cert, anchor_leaf_trust);
      net_log.AddEvent(NetLogEventType::CERT_VERIFY_PROC_ADDITIONAL_CERT, [&] {
        return NetLogAdditionalCert(cert->cert_buffer(), anchor_leaf_trust,
                                    parsing_errors);
      });
    }
  }

  for (const auto& cert :
       instance_params.additional_trust_anchors_with_enforced_constraints) {
    bssl::CertErrors parsing_errors;
    if (!additional_trust_store_.Contains(cert.get())) {
      additional_trust_store_.AddCertificate(cert, anchor_trust_enforcement);
      net_log.AddEvent(NetLogEventType::CERT_VERIFY_PROC_ADDITIONAL_CERT, [&] {
        return NetLogAdditionalCert(cert->cert_buffer(),
                                    anchor_trust_enforcement, parsing_errors);
      });
    }
  }

  for (const auto& cert : instance_params.additional_trust_anchors) {
    bssl::CertErrors parsing_errors;
    // Only add if it wasn't already present in `additional_trust_store_`. This
    // is for two reasons:
    //   (1) TrustStoreInMemory doesn't expect to contain duplicates
    //   (2) If the same anchor is added with enforced constraints, that takes
    //       precedence.
    if (!additional_trust_store_.Contains(cert.get())) {
      additional_trust_store_.AddTrustAnchor(cert);
    }
    net_log.AddEvent(NetLogEventType::CERT_VERIFY_PROC_ADDITIONAL_CERT, [&] {
      return NetLogAdditionalCert(cert->cert_buffer(),
                                  bssl::CertificateTrust::ForTrustAnchor(),
                                  parsing_errors);
    });
  }

  for (const auto& cert : instance_params.additional_untrusted_authorities) {
    bssl::CertErrors parsing_errors;
    // Only add the untrusted cert if it isn't already present in
    // `additional_trust_store_`. If the same cert was already added as a
    // trust anchor then adding it again as an untrusted cert can lead to it
    // not being treated as a trust anchor since TrustStoreInMemory doesn't
    // expect to contain duplicates.
    if (!additional_trust_store_.Contains(cert.get())) {
      additional_trust_store_.AddCertificateWithUnspecifiedTrust(cert);
    }
    net_log.AddEvent(NetLogEventType::CERT_VERIFY_PROC_ADDITIONAL_CERT, [&] {
      return NetLogAdditionalCert(cert->cert_buffer(),
                                  bssl::CertificateTrust::ForUnspecified(),
                                  parsing_errors);
    });
  }

  net_log.EndEvent(NetLogEventType::CERT_VERIFY_PROC_CREATED);
}

CertVerifyProcBuiltin::~CertVerifyProcBuiltin() = default;

void AddIntermediatesToIssuerSource(X509Certificate* x509_cert,
                                    bssl::CertIssuerSourceStatic* intermediates,
                                    const NetLogWithSource& net_log) {
  for (const auto& intermediate : x509_cert->intermediate_buffers()) {
    bssl::CertErrors errors;
    std::shared_ptr<const bssl::ParsedCertificate> cert =
        ParseCertificateFromBuffer(intermediate.get(), &errors);
    // TODO(crbug.com/40479281): this duplicates the logging of the input chain
    // maybe should only log if there is a parse error/warning?
    net_log.AddEvent(NetLogEventType::CERT_VERIFY_PROC_INPUT_CERT, [&] {
      return NetLogCertParams(intermediate.get(), errors);
    });
    if (cert) {
      intermediates->AddCert(std::move(cert));
    }
  }
}

// Appends the SHA256 hashes of |spki_bytes| to |*hashes|.
// TODO(eroman): Hashes are also calculated at other times (such as when
//               checking CRLSet). Consider caching to avoid recalculating (say
//               in the delegate's PathInfo).
void AppendPublicKeyHashes(const bssl::der::Input& spki_bytes,
                           HashValueVector* hashes) {
  HashValue sha256(HASH_VALUE_SHA256);
  crypto::SHA256HashString(spki_bytes.AsStringView(), sha256.data(),
                           crypto::kSHA256Length);
  hashes->push_back(sha256);
}

// Appends the SubjectPublicKeyInfo hashes for all certificates in
// |path| to |*hashes|.
void AppendPublicKeyHashes(const bssl::CertPathBuilderResultPath& path,
                           HashValueVector* hashes) {
  for (const std::shared_ptr<const bssl::ParsedCertificate>& cert :
       path.certs) {
    AppendPublicKeyHashes(cert->tbs().spki_tlv, hashes);
  }
}

// Sets the bits on |cert_status| for all the errors present in |errors| (the
// errors for a particular path).
void MapPathBuilderErrorsToCertStatus(const bssl::CertPathErrors& errors,
                                      CertStatus* cert_status) {
  // If there were no errors, nothing to do.
  if (!errors.ContainsHighSeverityErrors())
    return;

  if (errors.ContainsError(bssl::cert_errors::kCertificateRevoked)) {
    *cert_status |= CERT_STATUS_REVOKED;
  }

  if (errors.ContainsError(bssl::cert_errors::kNoRevocationMechanism)) {
    *cert_status |= CERT_STATUS_NO_REVOCATION_MECHANISM;
  }

  if (errors.ContainsError(bssl::cert_errors::kUnableToCheckRevocation)) {
    *cert_status |= CERT_STATUS_UNABLE_TO_CHECK_REVOCATION;
  }

  if (errors.ContainsError(bssl::cert_errors::kUnacceptablePublicKey)) {
    *cert_status |= CERT_STATUS_WEAK_KEY;
  }

  if (errors.ContainsError(bssl::cert_errors::kValidityFailedNotAfter) ||
      errors.ContainsError(bssl::cert_errors::kValidityFailedNotBefore)) {
    *cert_status |= CERT_STATUS_DATE_INVALID;
  }

  if (errors.ContainsError(bssl::cert_errors::kDistrustedByTrustStore) ||
      errors.ContainsError(bssl::cert_errors::kVerifySignedDataFailed) ||
      errors.ContainsError(bssl::cert_errors::kNoIssuersFound) ||
      errors.ContainsError(bssl::cert_errors::kSubjectDoesNotMatchIssuer) ||
      errors.ContainsError(bssl::cert_errors::kDeadlineExceeded) ||
      errors.ContainsError(bssl::cert_errors::kIterationLimitExceeded) ||
      errors.ContainsError(kChromeRootConstraintsFailed)) {
    *cert_status |= CERT_STATUS_AUTHORITY_INVALID;
  }

  // IMPORTANT: If the path was invalid for a reason that was not
  // explicity checked above, set a general error. This is important as
  // |cert_status| is what ultimately indicates whether verification was
  // successful or not (absence of errors implies success).
  if (!IsCertStatusError(*cert_status))
    *cert_status |= CERT_STATUS_INVALID;
}

// Creates a X509Certificate (chain) to return as the verified result.
//
//  * |target_cert|: The original X509Certificate that was passed in to
//                   VerifyInternal()
//  * |path|: The result (possibly failed) from path building.
scoped_refptr<X509Certificate> CreateVerifiedCertChain(
    X509Certificate* target_cert,
    const bssl::CertPathBuilderResultPath& path) {
  std::vector<bssl::UniquePtr<CRYPTO_BUFFER>> intermediates;

  // Skip the first certificate in the path as that is the target certificate
  for (size_t i = 1; i < path.certs.size(); ++i) {
    intermediates.push_back(bssl::UpRef(path.certs[i]->cert_buffer()));
  }

  scoped_refptr<X509Certificate> result =
      target_cert->CloneWithDifferentIntermediates(std::move(intermediates));
  DCHECK(result);

  return result;
}

// Describes the parameters for a single path building attempt. Path building
// may be re-tried with different parameters for EV and for accepting SHA1
// certificates.
struct BuildPathAttempt {
  BuildPathAttempt(VerificationType verification_type,
                   bssl::SimplePathBuilderDelegate::DigestPolicy digest_policy,
                   bool use_system_time)
      : verification_type(verification_type),
        digest_policy(digest_policy),
        use_system_time(use_system_time) {}

  BuildPathAttempt(VerificationType verification_type, bool use_system_time)
      : BuildPathAttempt(verification_type,
                         bssl::SimplePathBuilderDelegate::DigestPolicy::kStrong,
                         use_system_time) {}

  VerificationType verification_type;
  bssl::SimplePathBuilderDelegate::DigestPolicy digest_policy;
  bool use_system_time;
};

bssl::CertPathBuilder::Result TryBuildPath(
    const std::shared_ptr<const bssl::ParsedCertificate>& target,
    bssl::CertIssuerSourceStatic* intermediates,
    CertVerifyProcTrustStore* trust_store,
    const std::vector<net::CertVerifyProc::CertificateWithConstraints>&
        additional_constraints,
    const bssl::der::GeneralizedTime& der_verification_time,
    base::Time current_time,
    base::TimeTicks deadline,
    VerificationType verification_type,
    bssl::SimplePathBuilderDelegate::DigestPolicy digest_policy,
    int flags,
    std::string_view ocsp_response,
    std::string_view sct_list,
    const CRLSet* crl_set,
    CTVerifier* ct_verifier,
    const CTPolicyEnforcer* ct_policy_enforcer,
    CertNetFetcher* net_fetcher,
    const EVRootCAMetadata* ev_metadata,
    bool* checked_revocation,
    const NetLogWithSource& net_log) {
  // Path building will require candidate paths to conform to at least one of
  // the policies in |user_initial_policy_set|.
  std::set<bssl::der::Input> user_initial_policy_set;

  if (verification_type == VerificationType::kEV) {
    GetEVPolicyOids(ev_metadata, target.get(), &user_initial_policy_set);
    // TODO(crbug.com/40479281): netlog user_initial_policy_set.
  } else {
    user_initial_policy_set = {bssl::der::Input(bssl::kAnyPolicyOid)};
  }

  PathBuilderDelegateImpl path_builder_delegate(
      crl_set, ct_verifier, ct_policy_enforcer, net_fetcher, verification_type,
      digest_policy, flags, trust_store, additional_constraints, ocsp_response,
      sct_list, ev_metadata, deadline, current_time, checked_revocation,
      net_log);

  std::optional<CertIssuerSourceAia> aia_cert_issuer_source;

  // Initialize the path builder.
  bssl::CertPathBuilder path_builder(
      target, trust_store->trust_store(), &path_builder_delegate,
      der_verification_time, bssl::KeyPurpose::SERVER_AUTH,
      bssl::InitialExplicitPolicy::kFalse, user_initial_policy_set,
      bssl::InitialPolicyMappingInhibit::kFalse,
      bssl::InitialAnyPolicyInhibit::kFalse);

  // Allow the path builder to discover the explicitly provided intermediates in
  // |input_cert|.
  path_builder.AddCertIssuerSource(intermediates);

  // Allow the path builder to discover intermediates through AIA fetching.
  // TODO(crbug.com/40479281): hook up netlog to AIA.
  if (!(flags & CertVerifyProc::VERIFY_DISABLE_NETWORK_FETCHES)) {
    if (net_fetcher) {
      aia_cert_issuer_source.emplace(net_fetcher);
      path_builder.AddCertIssuerSource(&aia_cert_issuer_source.value());
    } else {
      VLOG(1) << "No net_fetcher for performing AIA chasing.";
    }
  }

  path_builder.SetIterationLimit(kPathBuilderIterationLimit);

  return path_builder.Run();
}

int AssignVerifyResult(X509Certificate* input_cert,
                       const std::string& hostname,
                       bssl::CertPathBuilder::Result& result,
                       VerificationType verification_type,
                       bool checked_revocation_for_some_path,
                       CertVerifyProcTrustStore* trust_store,
                       CertVerifyResult* verify_result) {
  const bssl::CertPathBuilderResultPath* best_path_possibly_invalid =
      result.GetBestPathPossiblyInvalid();

  if (!best_path_possibly_invalid) {
    // TODO(crbug.com/41267838): What errors to communicate? Maybe the path
    // builder should always return some partial path (even if just containing
    // the target), then there is a bssl::CertErrors to test.
    verify_result->cert_status |= CERT_STATUS_AUTHORITY_INVALID;
    return ERR_CERT_AUTHORITY_INVALID;
  }

  const bssl::CertPathBuilderResultPath& partial_path =
      *best_path_possibly_invalid;

  AppendPublicKeyHashes(partial_path, &verify_result->public_key_hashes);

  bool path_is_valid = partial_path.IsValid();

  const bssl::ParsedCertificate* trusted_cert = partial_path.GetTrustedCert();
  if (trusted_cert) {
    verify_result->is_issued_by_known_root =
        trust_store->IsKnownRoot(trusted_cert);

    verify_result->is_issued_by_additional_trust_anchor =
        trust_store->IsAdditionalTrustAnchor(trusted_cert);
  }

  if (path_is_valid && (verification_type == VerificationType::kEV)) {
    verify_result->cert_status |= CERT_STATUS_IS_EV;
  }

  // TODO(eroman): Add documentation for the meaning of
  // CERT_STATUS_REV_CHECKING_ENABLED. Based on the current tests it appears to
  // mean whether revocation checking was attempted during path building,
  // although does not necessarily mean that revocation checking was done for
  // the final returned path.
  if (checked_revocation_for_some_path)
    verify_result->cert_status |= CERT_STATUS_REV_CHECKING_ENABLED;

  verify_result->verified_cert =
      CreateVerifiedCertChain(input_cert, partial_path);

  MapPathBuilderErrorsToCertStatus(partial_path.errors,
                                   &verify_result->cert_status);

  // TODO(eroman): Is it possible that IsValid() fails but no errors were set in
  // partial_path.errors?
  CHECK(path_is_valid || IsCertStatusError(verify_result->cert_status));

  if (!path_is_valid) {
    VLOG(1) << "CertVerifyProcBuiltin for " << hostname << " failed:\n"
            << partial_path.errors.ToDebugString(partial_path.certs);
  }

  const PathBuilderDelegateDataImpl* delegate_data =
      PathBuilderDelegateDataImpl::Get(partial_path);
  if (delegate_data) {
    verify_result->ocsp_result = delegate_data->stapled_ocsp_verify_result;
    verify_result->scts = std::move(delegate_data->scts);
    verify_result->policy_compliance = delegate_data->ct_policy_compliance;
  }

  return IsCertStatusError(verify_result->cert_status)
             ? MapCertStatusToNetError(verify_result->cert_status)
             : OK;
}

// Returns true if retrying path building with a less stringent signature
// algorithm *might* successfully build a path, based on the earlier failed
// |result|.
//
// This implementation is simplistic, and looks only for the presence of the
// kUnacceptableSignatureAlgorithm error somewhere among the built paths.
bool CanTryAgainWithWeakerDigestPolicy(
    const bssl::CertPathBuilder::Result& result) {
  return result.AnyPathContainsError(
      bssl::cert_errors::kUnacceptableSignatureAlgorithm);
}

// Returns true if retrying with the system time as the verification time might
// successfully build a path, based on the earlier failed |result|.
bool CanTryAgainWithSystemTime(const bssl::CertPathBuilder::Result& result) {
  // TODO(crbug.com/363034686): Retries should also be triggered for CT
  // failures.
  return result.AnyPathContainsError(
             bssl::cert_errors::kValidityFailedNotAfter) ||
         result.AnyPathContainsError(
             bssl::cert_errors::kValidityFailedNotBefore) ||
         result.AnyPathContainsError(bssl::cert_errors::kCertificateRevoked) ||
         result.AnyPathContainsError(
             bssl::cert_errors::kUnableToCheckRevocation);
}

int CertVerifyProcBuiltin::VerifyInternal(X509Certificate* input_cert,
                                          const std::string& hostname,
                                          const std::string& ocsp_response,
                                          const std::string& sct_list,
                                          int flags,
                                          CertVerifyResult* verify_result,
                                          const NetLogWithSource& net_log) {
  base::TimeTicks deadline = base::TimeTicks::Now() + kMaxVerificationTime;
  bssl::der::GeneralizedTime der_verification_system_time;
  bssl::der::GeneralizedTime der_verification_custom_time;
  if (!EncodeTimeAsGeneralizedTime(base::Time::Now(),
                                   &der_verification_system_time)) {
    // This shouldn't be possible.
    // We don't really have a good error code for this type of error.
    verify_result->cert_status |= CERT_STATUS_AUTHORITY_INVALID;
    return ERR_CERT_AUTHORITY_INVALID;
  }
  bool custom_time_available = false;
  base::Time custom_time;
  if (time_tracker_.has_value()) {
    custom_time_available = time_tracker_->GetTime(
        base::Time::Now(), base::TimeTicks::Now(), &custom_time, nullptr);
    if (custom_time_available &&
        !EncodeTimeAsGeneralizedTime(custom_time,
                                     &der_verification_custom_time)) {
      // This shouldn't be possible, but if it somehow happens, just use system
      // time.
      custom_time_available = false;
    }
  }
#if BUILDFLAG(CHROME_ROOT_STORE_SUPPORTED)
  int64_t chrome_root_store_version =
      system_trust_store_->chrome_root_store_version();
  if (chrome_root_store_version != 0) {
    net_log.AddEvent(
        NetLogEventType::CERT_VERIFY_PROC_CHROME_ROOT_STORE_VERSION, [&] {
          return NetLogChromeRootStoreVersion(chrome_root_store_version);
        });
  }
#endif

  // TODO(crbug.com/40928765): Netlog extra configuration information stored
  // inside CertVerifyProcBuiltin (e.g. certs in additional_trust_store and
  // system trust store)

  // Parse the target certificate.
  std::shared_ptr<const bssl::ParsedCertificate> target;
  {
    bssl::CertErrors parsing_errors;
    target =
        ParseCertificateFromBuffer(input_cert->cert_buffer(), &parsing_errors);
    // TODO(crbug.com/40479281): this duplicates the logging of the input chain
    // maybe should only log if there is a parse error/warning?
    net_log.AddEvent(NetLogEventType::CERT_VERIFY_PROC_TARGET_CERT, [&] {
      return NetLogCertParams(input_cert->cert_buffer(), parsing_errors);
    });
    if (!target) {
      verify_result->cert_status |= CERT_STATUS_INVALID;
      return ERR_CERT_INVALID;
    }
  }

  // Parse the provided intermediates.
  bssl::CertIssuerSourceStatic intermediates;
  AddIntermediatesToIssuerSource(input_cert, &intermediates, net_log);

  CertVerifyProcTrustStore trust_store(system_trust_store_.get(),
                                       &additional_trust_store_);

  // Get the global dependencies.
  const EVRootCAMetadata* ev_metadata = EVRootCAMetadata::GetInstance();

  // This boolean tracks whether online revocation checking was performed for
  // *any* of the built paths, and not just the final path returned (used for
  // setting output flag CERT_STATUS_REV_CHECKING_ENABLED).
  bool checked_revocation_for_some_path = false;

  // Run path building with the different parameters (attempts) until a valid
  // path is found. Earlier successful attempts have priority over later
  // attempts.
  //
  // Attempts are enqueued into |attempts| and drained in FIFO order.
  std::vector<BuildPathAttempt> attempts;

  // First try EV validation. Can skip this if the leaf certificate has no
  // chance of verifying as EV (lacks an EV policy).
  if (IsEVCandidate(ev_metadata, target.get()))
    attempts.emplace_back(VerificationType::kEV, !custom_time_available);

  // Next try DV validation.
  attempts.emplace_back(VerificationType::kDV, !custom_time_available);

  bssl::CertPathBuilder::Result result;
  VerificationType verification_type = VerificationType::kDV;

  // Iterate over |attempts| until there are none left to try, or an attempt
  // succeeded.
  for (size_t cur_attempt_index = 0; cur_attempt_index < attempts.size();
       ++cur_attempt_index) {
    const auto& cur_attempt = attempts[cur_attempt_index];
    verification_type = cur_attempt.verification_type;
    net_log.BeginEvent(
        NetLogEventType::CERT_VERIFY_PROC_PATH_BUILD_ATTEMPT, [&] {
          base::Value::Dict results;
          if (verification_type == VerificationType::kEV)
            results.Set("is_ev_attempt", true);
          results.Set("is_network_time_attempt", !cur_attempt.use_system_time);
          if (!cur_attempt.use_system_time) {
            results.Set(
                "network_time_value",
                NetLogNumberValue(custom_time.InMillisecondsSinceUnixEpoch()));
          }
          results.Set("digest_policy",
                      static_cast<int>(cur_attempt.digest_policy));
          return results;
        });

    // If a previous attempt used up most/all of the deadline, extend the
    // deadline a little bit to give this verification attempt a chance at
    // success.
    deadline = std::max(
        deadline, base::TimeTicks::Now() + kPerAttemptMinVerificationTimeLimit);

    // Run the attempt through the path builder.
    result = TryBuildPath(
        target, &intermediates, &trust_store, additional_constraints_,
        cur_attempt.use_system_time ? der_verification_system_time
                                    : der_verification_custom_time,
        cur_attempt.use_system_time ? base::Time::Now() : custom_time, deadline,
        cur_attempt.verification_type, cur_attempt.digest_policy, flags,
        ocsp_response, sct_list, crl_set(), ct_verifier_.get(),
        ct_policy_enforcer_.get(), net_fetcher_.get(), ev_metadata,
        &checked_revocation_for_some_path, net_log);

    net_log.EndEvent(NetLogEventType::CERT_VERIFY_PROC_PATH_BUILD_ATTEMPT,
                     [&] { return NetLogPathBuilderResult(result); });

    if (result.HasValidPath())
      break;

    if (result.exceeded_deadline) {
      // Stop immediately if an attempt exceeds the deadline.
      break;
    }

    if (!cur_attempt.use_system_time && CanTryAgainWithSystemTime(result)) {
      BuildPathAttempt system_time_attempt = cur_attempt;
      system_time_attempt.use_system_time = true;
      attempts.push_back(system_time_attempt);
    } else if (cur_attempt.digest_policy ==
                   bssl::SimplePathBuilderDelegate::DigestPolicy::kStrong &&
               CanTryAgainWithWeakerDigestPolicy(result)) {
      // If this path building attempt (may have) failed due to the chain using
      // a
      // weak signature algorithm, enqueue a similar attempt but with weaker
      // signature algorithms (SHA1) permitted.
      //
      // This fallback is necessary because the CertVerifyProc layer may decide
      // to allow SHA1 based on its own policy, so path building should return
      // possibly weak chains too.
      //
      // TODO(eroman): Would be better for the SHA1 policy to be part of the
      // delegate instead so it can interact with path building.
      BuildPathAttempt sha1_fallback_attempt = cur_attempt;
      sha1_fallback_attempt.digest_policy =
          bssl::SimplePathBuilderDelegate::DigestPolicy::kWeakAllowSha1;
      attempts.push_back(sha1_fallback_attempt);
    }
  }

  // Write the results to |*verify_result|.
  int error = AssignVerifyResult(
      input_cert, hostname, result, verification_type,
      checked_revocation_for_some_path, &trust_store, verify_result);
  if (error == OK) {
    LogNameNormalizationMetrics(".Builtin", verify_result->verified_cert.get(),
                                verify_result->is_issued_by_known_root);
  }
  return error;
}

}  // namespace

scoped_refptr<CertVerifyProc> CreateCertVerifyProcBuiltin(
    scoped_refptr<CertNetFetcher> net_fetcher,
    scoped_refptr<CRLSet> crl_set,
    std::unique_ptr<CTVerifier> ct_verifier,
    scoped_refptr<CTPolicyEnforcer> ct_policy_enforcer,
    std::unique_ptr<SystemTrustStore> system_trust_store,
    const CertVerifyProc::InstanceParams& instance_params,
    std::optional<network_time::TimeTracker> time_tracker) {
  return base::MakeRefCounted<CertVerifyProcBuiltin>(
      std::move(net_fetcher), std::move(crl_set), std::move(ct_verifier),
      std::move(ct_policy_enforcer), std::move(system_trust_store),
      instance_params, std::move(time_tracker));
}

base::TimeDelta GetCertVerifyProcBuiltinTimeLimitForTesting() {
  return kMaxVerificationTime;
}

}  // namespace net
```