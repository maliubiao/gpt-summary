Response:
The user is asking for a summary of the functionality of the `net/test/cert_builder.cc` file in the Chromium network stack. The request also asks for connections to JavaScript, logical reasoning with input/output examples, common usage errors, debugging steps to reach this code, and finally, a concise summary of the file's purpose.

**Plan:**

1. **Analyze the code:** Read through the code, paying attention to the class definition (`CertBuilder`), its methods, and the included headers. Identify the core functionalities.
2. **Summarize core functionalities:**  List the main actions the `CertBuilder` class enables.
3. **Identify JavaScript connections (if any):** Look for any indications of interaction with JavaScript concepts or APIs.
4. **Develop logical reasoning examples:**  Choose a method and illustrate its behavior with a hypothetical input and its expected output.
5. **Pinpoint common usage errors:** Consider how a developer might misuse the `CertBuilder` and provide examples.
6. **Outline debugging steps:** Describe a scenario where a developer might end up inspecting or using this code for debugging.
7. **Formulate a concise summary:**  Condense the identified functionalities into a brief statement.```
这是目录为net/test/cert_builder.cc的chromium 网络栈的源代码文件， 请列举一下它的功能,
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

**功能列举:**

`net/test/cert_builder.cc` 文件中的 `CertBuilder` 类主要用于在 Chromium 的网络栈测试中动态创建和操作 X.509 证书。其核心功能包括：

1. **创建证书:** 可以从头开始创建新的证书，也可以基于现有的证书进行修改。
2. **设置证书属性:**  可以设置证书的各种关键属性，例如：
    * **版本 (Version)**
    * **序列号 (Serial Number)**
    * **签名算法 (Signature Algorithm)**
    * **颁发者 (Issuer)**
    * **有效期 (Validity - Not Before/Not After)**
    * **主体 (Subject)**
    * **主体公钥信息 (Subject Public Key Info)**
    * **扩展 (Extensions):**  例如基本约束 (Basic Constraints)、密钥用途 (Key Usage)、扩展密钥用途 (Extended Key Usage)、主题备用名称 (Subject Alternative Name)、颁发机构信息访问 (Authority Information Access)、CRL 分发点 (CRL Distribution Points) 等。
3. **管理密钥:** 可以关联证书的私钥。
4. **添加 SCT (Signed Certificate Timestamp):** 支持添加签名证书时间戳，用于 Certificate Transparency。
5. **签名证书:** 使用提供的私钥对证书进行签名。
6. **生成 DER 编码的证书:**  将构建好的证书转换为 DER (Distinguished Encoding Rules) 格式的字节流。
7. **创建证书链:** 可以方便地创建由多个证书组成的证书链。
8. **从文件加载证书:** 可以从 PEM 格式的文件加载现有的证书和私钥。
9. **处理 ASN.1 结构:**  底层使用了 BoringSSL 的 CBB (Certificate Building Blocks) 接口来构建 ASN.1 结构。

**与 JavaScript 的关系举例说明:**

该文件本身是用 C++ 编写的，直接与 JavaScript 没有直接的功能关系。然而，它创建的证书最终会被 Chromium 的网络栈使用，而 Chromium 的网络栈会处理来自 JavaScript 的网络请求。

例如：

* **场景：测试 HTTPS 连接:**  开发者可能在 JavaScript 中发起一个 `fetch` 请求到一个使用自签名证书或测试证书的 HTTPS 服务器。Chromium 的网络栈会使用 `CertBuilder` 创建的证书来模拟服务器证书或中间 CA 证书，以测试证书验证逻辑。在这种情况下，`CertBuilder` 生成的证书影响了 JavaScript 网络请求的成功与否。

* **代码示例（JavaScript）：**

```javascript
fetch('https://test.example.com', { /* ... */ })
  .then(response => {
    console.log('请求成功:', response);
  })
  .catch(error => {
    console.error('请求失败:', error);
  });
```

如果 `test.example.com` 的服务器使用了由 `CertBuilder` 创建的自签名证书，那么在没有进行特殊配置的情况下，上述 `fetch` 请求在浏览器中会因为证书不受信任而失败。`CertBuilder` 的作用在于提供了创建这种测试场景的能力。

**逻辑推理、假设输入与输出:**

假设我们使用 `CertBuilder` 创建一个简单的自签名证书：

**假设输入:**

* 调用 `CertBuilder` 的默认构造函数或者从头开始创建。
* 设置主体通用名称 (Subject Common Name) 为 "test.example.com"。
* 生成一个 RSA 私钥。
* 设置有效期为当前时间前后各 7 天。
* 设置基本约束为 CA:FALSE。
* 设置密钥用途为数字签名。
* 设置扩展密钥用途为服务器身份验证。
* 使用生成的私钥对证书进行签名。

**预期输出:**

* 生成一个 DER 编码的 X.509 证书，该证书：
    * 其主体通用名称 (CN) 为 "test.example.com"。
    * 其有效期包含当前时间。
    * `Basic Constraints` 扩展中 `cA` 字段为 `FALSE`。
    * `Key Usage` 扩展中包含 `digitalSignature` 位。
    * `Extended Key Usage` 扩展中包含 `serverAuth` 的 OID。
    * 使用了我们生成的 RSA 私钥进行了签名。

**用户或编程常见的使用错误:**

1. **忘记设置关键属性:**  例如，创建 CA 证书时忘记设置 `Basic Constraints` 的 `cA` 为 `TRUE`，或者创建叶子证书时忘记设置 `Extended Key Usage`。
    * **后果:** 导致证书在特定场景下无法正常使用，例如作为 CA 证书颁发其他证书，或者作为服务器证书进行 TLS 握手。
2. **有效期设置错误:**  将证书的有效期设置为过去的时间，或者设置得过短。
    * **后果:** 证书会立即过期或很快过期，导致连接失败或证书验证错误。
3. **签名算法不匹配:**  使用与私钥类型不匹配的签名算法。例如，使用 RSA 私钥但指定 ECDSA 签名算法。
    * **后果:** 签名过程会失败，无法生成有效的证书。
4. **扩展设置冲突:**  设置了相互冲突的扩展，例如同时设置了关键的策略约束和禁止策略映射，可能导致解析或验证错误。
5. **Subject Key Identifier 和 Authority Key Identifier 的不一致:**  在颁发证书时，如果子证书的 SKI 与父证书的 AKI 不匹配，会导致证书链验证失败。

**用户操作到达此处的调试线索:**

通常，开发者不会直接手动编写代码来调用 `net/test/cert_builder.cc` 中的类。这个文件主要用于 Chromium 自身的测试。开发者可能在以下调试场景中会接触到与此相关的代码或概念：

1. **调试网络连接失败:**  当开发者遇到 HTTPS 连接失败，并且怀疑是证书问题时，他们可能会查看 Chromium 的网络日志 (`chrome://net-export/`)。如果日志中显示证书验证错误，并且涉及到测试环境或自签名证书，那么开发者可能会搜索相关的 Chromium 测试代码，从而找到 `CertBuilder` 的使用。

2. **分析 Chromium 网络栈的测试代码:**  当开发者需要理解 Chromium 网络栈中关于证书处理的逻辑时，他们可能会查看网络栈的测试代码。`CertBuilder` 在这些测试中被广泛使用，因此开发者可能会阅读该文件的代码来理解证书的创建和使用方式。

3. **贡献 Chromium 代码:**  如果开发者正在为 Chromium 的网络栈添加新的功能或修复 bug，他们可能需要编写新的测试用例，这时就可能会用到 `CertBuilder` 来创建各种测试所需的证书场景。

**归纳功能 (第 1 部分):**

`net/test/cert_builder.cc` 文件的主要功能是提供一个用于在 Chromium 网络栈测试中动态生成和操作 X.509 证书的 C++ 工具类 `CertBuilder`。它允许测试代码灵活地创建具有各种属性和扩展的证书，用于模拟不同的证书场景，从而验证 Chromium 网络栈中与证书处理相关的逻辑。 该文件是测试基础设施的一部分，不直接在生产代码中使用。

Prompt: 
```
这是目录为net/test/cert_builder.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/test/cert_builder.h"

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "base/files/file_path.h"
#include "base/memory/ptr_util.h"
#include "base/memory/scoped_refptr.h"
#include "base/notreached.h"
#include "base/ranges/algorithm.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/time/time.h"
#include "crypto/ec_private_key.h"
#include "crypto/rsa_private_key.h"
#include "crypto/sha2.h"
#include "net/cert/asn1_util.h"
#include "net/cert/ct_objects_extractor.h"
#include "net/cert/ct_serialization.h"
#include "net/cert/signed_certificate_timestamp.h"
#include "net/cert/time_conversions.h"
#include "net/cert/x509_util.h"
#include "net/test/cert_test_util.h"
#include "net/test/key_util.h"
#include "net/test/test_data_directory.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/boringssl/src/include/openssl/evp.h"
#include "third_party/boringssl/src/include/openssl/mem.h"
#include "third_party/boringssl/src/pki/certificate_policies.h"
#include "third_party/boringssl/src/pki/extended_key_usage.h"
#include "third_party/boringssl/src/pki/input.h"
#include "third_party/boringssl/src/pki/parse_certificate.h"
#include "third_party/boringssl/src/pki/parse_values.h"
#include "third_party/boringssl/src/pki/parser.h"
#include "third_party/boringssl/src/pki/verify_signed_data.h"
#include "url/gurl.h"

namespace net {

namespace {

constexpr char kSimpleChainHostname[] = "www.example.com";

std::string Sha256WithRSAEncryption() {
  const uint8_t kSha256WithRSAEncryption[] = {0x30, 0x0D, 0x06, 0x09, 0x2a,
                                              0x86, 0x48, 0x86, 0xf7, 0x0d,
                                              0x01, 0x01, 0x0b, 0x05, 0x00};
  return std::string(std::begin(kSha256WithRSAEncryption),
                     std::end(kSha256WithRSAEncryption));
}

std::string Sha1WithRSAEncryption() {
  const uint8_t kSha1WithRSAEncryption[] = {0x30, 0x0D, 0x06, 0x09, 0x2a,
                                            0x86, 0x48, 0x86, 0xf7, 0x0d,
                                            0x01, 0x01, 0x05, 0x05, 0x00};
  return std::string(std::begin(kSha1WithRSAEncryption),
                     std::end(kSha1WithRSAEncryption));
}

std::string EcdsaWithSha256() {
  const uint8_t kDer[] = {0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86,
                          0x48, 0xce, 0x3d, 0x04, 0x03, 0x02};
  return std::string(std::begin(kDer), std::end(kDer));
}

std::string EcdsaWithSha1() {
  const uint8_t kDer[] = {0x30, 0x09, 0x06, 0x07, 0x2a, 0x86,
                          0x48, 0xce, 0x3d, 0x04, 0x01};
  return std::string(std::begin(kDer), std::end(kDer));
}

// Adds bytes (specified as a std::string_view) to the given CBB.
// The argument ordering follows the boringssl CBB_* api style.
bool CBBAddBytes(CBB* cbb, std::string_view bytes) {
  return CBB_add_bytes(cbb, reinterpret_cast<const uint8_t*>(bytes.data()),
                       bytes.size());
}

// Adds bytes (from fixed size array) to the given CBB.
// The argument ordering follows the boringssl CBB_* api style.
template <size_t N>
bool CBBAddBytes(CBB* cbb, const uint8_t (&data)[N]) {
  return CBB_add_bytes(cbb, data, N);
}

// Finalizes the CBB to a std::string.
std::string FinishCBB(CBB* cbb) {
  size_t cbb_len;
  uint8_t* cbb_bytes;

  if (!CBB_finish(cbb, &cbb_bytes, &cbb_len)) {
    ADD_FAILURE() << "CBB_finish() failed";
    return std::string();
  }

  bssl::UniquePtr<uint8_t> delete_bytes(cbb_bytes);
  return std::string(reinterpret_cast<char*>(cbb_bytes), cbb_len);
}

// Finalizes the CBB to a std::vector.
std::vector<uint8_t> FinishCBBToVector(CBB* cbb) {
  size_t cbb_len;
  uint8_t* cbb_bytes;

  if (!CBB_finish(cbb, &cbb_bytes, &cbb_len)) {
    ADD_FAILURE() << "CBB_finish() failed";
    return {};
  }

  bssl::UniquePtr<uint8_t> delete_bytes(cbb_bytes);
  return std::vector<uint8_t>(cbb_bytes, cbb_bytes + cbb_len);
}

}  // namespace

CertBuilder::SctConfig::SctConfig() = default;
CertBuilder::SctConfig::SctConfig(std::string log_id,
                                  bssl::UniquePtr<EVP_PKEY> log_key,
                                  base::Time timestamp)
    : log_id(std::move(log_id)),
      log_key(std::move(log_key)),
      timestamp(timestamp) {}
CertBuilder::SctConfig::SctConfig(const SctConfig& other)
    : SctConfig(other.log_id,
                bssl::UpRef(other.log_key.get()),
                other.timestamp) {}
CertBuilder::SctConfig::SctConfig(SctConfig&&) = default;
CertBuilder::SctConfig::~SctConfig() = default;
CertBuilder::SctConfig& CertBuilder::SctConfig::operator=(
    const SctConfig& other) {
  log_id = other.log_id;
  log_key = bssl::UpRef(other.log_key.get());
  timestamp = other.timestamp;
  return *this;
}
CertBuilder::SctConfig& CertBuilder::SctConfig::operator=(SctConfig&&) =
    default;

CertBuilder::CertBuilder(CRYPTO_BUFFER* orig_cert, CertBuilder* issuer)
    : CertBuilder(orig_cert, issuer, /*unique_subject_key_identifier=*/true) {}

// static
std::unique_ptr<CertBuilder> CertBuilder::FromFile(
    const base::FilePath& cert_and_key_file,
    CertBuilder* issuer) {
  scoped_refptr<X509Certificate> cert = ImportCertFromFile(cert_and_key_file);
  if (!cert)
    return nullptr;

  bssl::UniquePtr<EVP_PKEY> private_key(
      key_util::LoadEVP_PKEYFromPEM(cert_and_key_file));
  if (!private_key)
    return nullptr;

  auto builder = base::WrapUnique(new CertBuilder(cert->cert_buffer(), issuer));
  builder->key_ = std::move(private_key);
  return builder;
}

// static
std::unique_ptr<CertBuilder> CertBuilder::FromStaticCert(CRYPTO_BUFFER* cert,
                                                         EVP_PKEY* key) {
  std::unique_ptr<CertBuilder> builder = base::WrapUnique(
      new CertBuilder(cert, nullptr, /*unique_subject_key_identifier=*/false));
  // |cert_|, |key_|, and |subject_tlv_| must be initialized for |builder| to
  // function as the |issuer| of another CertBuilder.
  builder->cert_ = bssl::UpRef(cert);
  builder->key_ = bssl::UpRef(key);
  std::string_view subject_tlv;
  CHECK(asn1::ExtractSubjectFromDERCert(
      x509_util::CryptoBufferAsStringPiece(cert), &subject_tlv));
  builder->subject_tlv_ = std::string(subject_tlv);
  return builder;
}

// static
std::unique_ptr<CertBuilder> CertBuilder::FromStaticCertFile(
    const base::FilePath& cert_and_key_file) {
  scoped_refptr<X509Certificate> cert = ImportCertFromFile(cert_and_key_file);
  if (!cert)
    return nullptr;

  bssl::UniquePtr<EVP_PKEY> private_key(
      key_util::LoadEVP_PKEYFromPEM(cert_and_key_file));
  if (!private_key)
    return nullptr;

  return CertBuilder::FromStaticCert(cert->cert_buffer(), private_key.get());
}

// static
std::unique_ptr<CertBuilder> CertBuilder::FromSubjectPublicKeyInfo(
    base::span<const uint8_t> spki_der,
    CertBuilder* issuer) {
  DCHECK(issuer);
  auto builder = std::make_unique<CertBuilder>(/*orig_cert=*/nullptr, issuer);

  CBS cbs;
  CBS_init(&cbs, spki_der.data(), spki_der.size());
  builder->key_ = bssl::UniquePtr<EVP_PKEY>(EVP_parse_public_key(&cbs));
  // Check that there was no error in `EVP_parse_public_key` and that it
  // consumed the entire public key.
  if (!builder->key_ || (CBS_len(&cbs) != 0))
    return nullptr;

  return builder;
}

CertBuilder::~CertBuilder() = default;

// static
std::vector<std::unique_ptr<CertBuilder>> CertBuilder::CreateSimpleChain(
    size_t chain_length) {
  std::vector<std::unique_ptr<CertBuilder>> chain;
  base::Time not_before = base::Time::Now() - base::Days(7);
  base::Time not_after = base::Time::Now() + base::Days(7);
  CertBuilder* parent_builder = nullptr;
  for (size_t remaining_chain_length = chain_length; remaining_chain_length;
       remaining_chain_length--) {
    auto builder = std::make_unique<CertBuilder>(nullptr, parent_builder);
    builder->SetValidity(not_before, not_after);
    if (remaining_chain_length > 1) {
      // CA properties:
      builder->SetBasicConstraints(/*is_ca=*/true, /*path_len=*/-1);
      builder->SetKeyUsages(
          {bssl::KEY_USAGE_BIT_KEY_CERT_SIGN, bssl::KEY_USAGE_BIT_CRL_SIGN});
    } else {
      // Leaf properties:
      builder->SetBasicConstraints(/*is_ca=*/false, /*path_len=*/-1);
      builder->SetKeyUsages({bssl::KEY_USAGE_BIT_DIGITAL_SIGNATURE});
      builder->SetExtendedKeyUsages({bssl::der::Input(bssl::kServerAuth)});
      builder->SetSubjectAltName(kSimpleChainHostname);
    }
    parent_builder = builder.get();
    chain.push_back(std::move(builder));
  }
  base::ranges::reverse(chain);
  return chain;
}

// static
std::array<std::unique_ptr<CertBuilder>, 3> CertBuilder::CreateSimpleChain3() {
  auto chain = CreateSimpleChain(3);
  return {std::move(chain[0]), std::move(chain[1]), std::move(chain[2])};
}

// static
std::array<std::unique_ptr<CertBuilder>, 2> CertBuilder::CreateSimpleChain2() {
  auto chain = CreateSimpleChain(2);
  return {std::move(chain[0]), std::move(chain[1])};
}

// static
std::optional<bssl::SignatureAlgorithm>
CertBuilder::DefaultSignatureAlgorithmForKey(EVP_PKEY* key) {
  if (EVP_PKEY_id(key) == EVP_PKEY_RSA)
    return bssl::SignatureAlgorithm::kRsaPkcs1Sha256;
  if (EVP_PKEY_id(key) == EVP_PKEY_EC)
    return bssl::SignatureAlgorithm::kEcdsaSha256;
  return std::nullopt;
}

// static
bool CertBuilder::SignData(bssl::SignatureAlgorithm signature_algorithm,
                           std::string_view tbs_data,
                           EVP_PKEY* key,
                           CBB* out_signature) {
  if (!key)
    return false;

  int expected_pkey_id = 1;
  const EVP_MD* digest;
  switch (signature_algorithm) {
    case bssl::SignatureAlgorithm::kRsaPkcs1Sha1:
      expected_pkey_id = EVP_PKEY_RSA;
      digest = EVP_sha1();
      break;
    case bssl::SignatureAlgorithm::kRsaPkcs1Sha256:
      expected_pkey_id = EVP_PKEY_RSA;
      digest = EVP_sha256();
      break;
    case bssl::SignatureAlgorithm::kRsaPkcs1Sha384:
      expected_pkey_id = EVP_PKEY_RSA;
      digest = EVP_sha384();
      break;
    case bssl::SignatureAlgorithm::kRsaPkcs1Sha512:
      expected_pkey_id = EVP_PKEY_RSA;
      digest = EVP_sha512();
      break;

    case bssl::SignatureAlgorithm::kEcdsaSha1:
      expected_pkey_id = EVP_PKEY_EC;
      digest = EVP_sha1();
      break;
    case bssl::SignatureAlgorithm::kEcdsaSha256:
      expected_pkey_id = EVP_PKEY_EC;
      digest = EVP_sha256();
      break;
    case bssl::SignatureAlgorithm::kEcdsaSha384:
      expected_pkey_id = EVP_PKEY_EC;
      digest = EVP_sha384();
      break;
    case bssl::SignatureAlgorithm::kEcdsaSha512:
      expected_pkey_id = EVP_PKEY_EC;
      digest = EVP_sha512();
      break;

    case bssl::SignatureAlgorithm::kRsaPssSha256:
    case bssl::SignatureAlgorithm::kRsaPssSha384:
    case bssl::SignatureAlgorithm::kRsaPssSha512:
      // Unsupported algorithms.
      return false;
  }

  return expected_pkey_id == EVP_PKEY_id(key) &&
         SignDataWithDigest(digest, tbs_data, key, out_signature);
}

// static
bool CertBuilder::SignDataWithDigest(const EVP_MD* digest,
                                     std::string_view tbs_data,
                                     EVP_PKEY* key,
                                     CBB* out_signature) {
  const uint8_t* tbs_bytes = reinterpret_cast<const uint8_t*>(tbs_data.data());
  bssl::ScopedEVP_MD_CTX ctx;
  uint8_t* sig_out;
  size_t sig_len;

  return EVP_DigestSignInit(ctx.get(), nullptr, digest, nullptr, key) &&
         EVP_DigestSign(ctx.get(), nullptr, &sig_len, tbs_bytes,
                        tbs_data.size()) &&
         CBB_reserve(out_signature, &sig_out, sig_len) &&
         EVP_DigestSign(ctx.get(), sig_out, &sig_len, tbs_bytes,
                        tbs_data.size()) &&
         CBB_did_write(out_signature, sig_len);
}

// static
std::string CertBuilder::SignatureAlgorithmToDer(
    bssl::SignatureAlgorithm signature_algorithm) {
  switch (signature_algorithm) {
    case bssl::SignatureAlgorithm::kRsaPkcs1Sha1:
      return Sha1WithRSAEncryption();
    case bssl::SignatureAlgorithm::kRsaPkcs1Sha256:
      return Sha256WithRSAEncryption();
    case bssl::SignatureAlgorithm::kEcdsaSha1:
      return EcdsaWithSha1();
    case bssl::SignatureAlgorithm::kEcdsaSha256:
      return EcdsaWithSha256();
    default:
      ADD_FAILURE();
      return std::string();
  }
}

// static
std::string CertBuilder::MakeRandomHexString(size_t num_bytes) {
  std::vector<uint8_t> rand_bytes(num_bytes);
  base::RandBytes(rand_bytes);
  return base::HexEncode(rand_bytes);
}

// static
std::vector<uint8_t> CertBuilder::BuildNameWithCommonNameOfType(
    std::string_view common_name,
    unsigned common_name_tag) {
  // See RFC 4519.
  static const uint8_t kCommonName[] = {0x55, 0x04, 0x03};

  // See RFC 5280, section 4.1.2.4.
  bssl::ScopedCBB cbb;
  CBB rdns, rdn, attr, type, value;
  if (!CBB_init(cbb.get(), 64) ||
      !CBB_add_asn1(cbb.get(), &rdns, CBS_ASN1_SEQUENCE) ||
      !CBB_add_asn1(&rdns, &rdn, CBS_ASN1_SET) ||
      !CBB_add_asn1(&rdn, &attr, CBS_ASN1_SEQUENCE) ||
      !CBB_add_asn1(&attr, &type, CBS_ASN1_OBJECT) ||
      !CBBAddBytes(&type, kCommonName) ||
      !CBB_add_asn1(&attr, &value, common_name_tag) ||
      !CBBAddBytes(&value, common_name)) {
    ADD_FAILURE();
    return {};
  }

  return FinishCBBToVector(cbb.get());
}

void CertBuilder::SetCertificateVersion(bssl::CertificateVersion version) {
  version_ = version;
  Invalidate();
}

void CertBuilder::SetExtension(const bssl::der::Input& oid,
                               std::string value,
                               bool critical) {
  auto& extension_value = extensions_[oid.AsString()];
  extension_value.critical = critical;
  extension_value.value = std::move(value);

  Invalidate();
}

void CertBuilder::EraseExtension(const bssl::der::Input& oid) {
  extensions_.erase(oid.AsString());

  Invalidate();
}

void CertBuilder::ClearExtensions() {
  extensions_.clear();
  Invalidate();
}

void CertBuilder::SetBasicConstraints(bool is_ca, int path_len) {
  // From RFC 5280:
  //
  //   BasicConstraints ::= SEQUENCE {
  //        cA                      BOOLEAN DEFAULT FALSE,
  //        pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
  bssl::ScopedCBB cbb;
  CBB basic_constraints;
  ASSERT_TRUE(CBB_init(cbb.get(), 64));
  ASSERT_TRUE(CBB_add_asn1(cbb.get(), &basic_constraints, CBS_ASN1_SEQUENCE));
  if (is_ca)
    ASSERT_TRUE(CBB_add_asn1_bool(&basic_constraints, true));
  if (path_len >= 0)
    ASSERT_TRUE(CBB_add_asn1_uint64(&basic_constraints, path_len));

  SetExtension(bssl::der::Input(bssl::kBasicConstraintsOid),
               FinishCBB(cbb.get()),
               /*critical=*/true);
}

namespace {
void AddNameConstraintsSubTrees(CBB* cbb,
                                const std::vector<std::string>& dns_names) {
  CBB subtrees;
  ASSERT_TRUE(CBB_add_asn1(
      cbb, &subtrees, CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0));
  for (const auto& name : dns_names) {
    CBB subtree;
    ASSERT_TRUE(CBB_add_asn1(&subtrees, &subtree, CBS_ASN1_SEQUENCE));
    CBB general_name;
    ASSERT_TRUE(
        CBB_add_asn1(&subtree, &general_name, CBS_ASN1_CONTEXT_SPECIFIC | 2));
    ASSERT_TRUE(CBBAddBytes(&general_name, name));
    ASSERT_TRUE(CBB_flush(&subtrees));
  }
  ASSERT_TRUE(CBB_flush(cbb));
}
}  // namespace

void CertBuilder::SetNameConstraintsDnsNames(
    const std::vector<std::string>& permitted_dns_names,
    const std::vector<std::string>& excluded_dns_names) {
  // From RFC 5280:
  //
  //   id-ce-nameConstraints OBJECT IDENTIFIER ::=  { id-ce 30 }
  //
  //   NameConstraints ::= SEQUENCE {
  //        permittedSubtrees       [0]     GeneralSubtrees OPTIONAL,
  //        excludedSubtrees        [1]     GeneralSubtrees OPTIONAL }
  //
  //   GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree
  //
  //   GeneralSubtree ::= SEQUENCE {
  //        base                    GeneralName,
  //        minimum         [0]     BaseDistance DEFAULT 0,
  //        maximum         [1]     BaseDistance OPTIONAL }
  //
  //   BaseDistance ::= INTEGER (0..MAX)

  if (permitted_dns_names.empty() && excluded_dns_names.empty()) {
    EraseExtension(bssl::der::Input(bssl::kNameConstraintsOid));
    return;
  }

  bssl::ScopedCBB cbb;
  CBB name_constraints;
  ASSERT_TRUE(CBB_init(cbb.get(), 64));
  ASSERT_TRUE(CBB_add_asn1(cbb.get(), &name_constraints, CBS_ASN1_SEQUENCE));
  if (!permitted_dns_names.empty()) {
    ASSERT_NO_FATAL_FAILURE(
        AddNameConstraintsSubTrees(&name_constraints, permitted_dns_names));
  }
  if (!excluded_dns_names.empty()) {
    ASSERT_NO_FATAL_FAILURE(
        AddNameConstraintsSubTrees(&name_constraints, excluded_dns_names));
  }
  SetExtension(bssl::der::Input(bssl::kNameConstraintsOid),
               FinishCBB(cbb.get()),
               /*critical=*/true);
}

void CertBuilder::SetCaIssuersUrl(const GURL& url) {
  SetCaIssuersAndOCSPUrls({url}, {});
}

void CertBuilder::SetCaIssuersAndOCSPUrls(
    const std::vector<GURL>& ca_issuers_urls,
    const std::vector<GURL>& ocsp_urls) {
  std::vector<std::pair<bssl::der::Input, GURL>> entries;
  for (const auto& url : ca_issuers_urls)
    entries.emplace_back(bssl::der::Input(bssl::kAdCaIssuersOid), url);
  for (const auto& url : ocsp_urls)
    entries.emplace_back(bssl::der::Input(bssl::kAdOcspOid), url);

  if (entries.empty()) {
    EraseExtension(bssl::der::Input(bssl::kAuthorityInfoAccessOid));
    return;
  }

  // From RFC 5280:
  //
  //   AuthorityInfoAccessSyntax  ::=
  //           SEQUENCE SIZE (1..MAX) OF AccessDescription
  //
  //   AccessDescription  ::=  SEQUENCE {
  //           accessMethod          OBJECT IDENTIFIER,
  //           accessLocation        GeneralName  }
  bssl::ScopedCBB cbb;
  CBB aia;
  ASSERT_TRUE(CBB_init(cbb.get(), 64));
  ASSERT_TRUE(CBB_add_asn1(cbb.get(), &aia, CBS_ASN1_SEQUENCE));

  for (const auto& entry : entries) {
    CBB access_description, access_method, access_location;
    ASSERT_TRUE(CBB_add_asn1(&aia, &access_description, CBS_ASN1_SEQUENCE));
    ASSERT_TRUE(
        CBB_add_asn1(&access_description, &access_method, CBS_ASN1_OBJECT));
    ASSERT_TRUE(CBBAddBytes(&access_method, entry.first.AsStringView()));
    ASSERT_TRUE(CBB_add_asn1(&access_description, &access_location,
                             CBS_ASN1_CONTEXT_SPECIFIC | 6));
    ASSERT_TRUE(CBBAddBytes(&access_location, entry.second.spec()));
    ASSERT_TRUE(CBB_flush(&aia));
  }

  SetExtension(bssl::der::Input(bssl::kAuthorityInfoAccessOid),
               FinishCBB(cbb.get()));
}

void CertBuilder::SetCrlDistributionPointUrl(const GURL& url) {
  SetCrlDistributionPointUrls({url});
}

void CertBuilder::SetCrlDistributionPointUrls(const std::vector<GURL>& urls) {
  bssl::ScopedCBB cbb;
  ASSERT_TRUE(CBB_init(cbb.get(), 64));
  CBB dps, dp, dp_name, dp_fullname;

  //    CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
  ASSERT_TRUE(CBB_add_asn1(cbb.get(), &dps, CBS_ASN1_SEQUENCE));

  //    DistributionPoint ::= SEQUENCE {
  //         distributionPoint       [0]     DistributionPointName OPTIONAL,
  //         reasons                 [1]     ReasonFlags OPTIONAL,
  //         cRLIssuer               [2]     bssl::GeneralNames OPTIONAL }
  ASSERT_TRUE(CBB_add_asn1(&dps, &dp, CBS_ASN1_SEQUENCE));
  ASSERT_TRUE(CBB_add_asn1(
      &dp, &dp_name, CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0));

  //    DistributionPointName ::= CHOICE {
  //         fullName                [0]     bssl::GeneralNames,
  //         nameRelativeToCRLIssuer [1]     bssl::RelativeDistinguishedName }
  ASSERT_TRUE(
      CBB_add_asn1(&dp_name, &dp_fullname,
                   CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0));

  //   bssl::GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
  //   GeneralName ::= CHOICE {
  // uniformResourceIdentifier       [6]     IA5String,
  for (const auto& url : urls) {
    CBB dp_url;
    ASSERT_TRUE(
        CBB_add_asn1(&dp_fullname, &dp_url, CBS_ASN1_CONTEXT_SPECIFIC | 6));
    ASSERT_TRUE(CBBAddBytes(&dp_url, url.spec()));
    ASSERT_TRUE(CBB_flush(&dp_fullname));
  }

  SetExtension(bssl::der::Input(bssl::kCrlDistributionPointsOid),
               FinishCBB(cbb.get()));
}

void CertBuilder::SetIssuerTLV(base::span<const uint8_t> issuer_tlv) {
  if (issuer_tlv.empty())
    issuer_tlv_ = std::nullopt;
  else
    issuer_tlv_ = std::string(issuer_tlv.begin(), issuer_tlv.end());
  Invalidate();
}

void CertBuilder::SetSubjectCommonName(std::string_view common_name) {
  SetSubjectTLV(
      BuildNameWithCommonNameOfType(common_name, CBS_ASN1_UTF8STRING));
  Invalidate();
}

void CertBuilder::SetSubjectTLV(base::span<const uint8_t> subject_tlv) {
  subject_tlv_.assign(subject_tlv.begin(), subject_tlv.end());
  Invalidate();
}

void CertBuilder::SetSubjectAltName(std::string_view dns_name) {
  SetSubjectAltNames({std::string(dns_name)}, {});
}

void CertBuilder::SetSubjectAltNames(
    const std::vector<std::string>& dns_names,
    const std::vector<IPAddress>& ip_addresses) {
  // From RFC 5280:
  //
  //   SubjectAltName ::= bssl::GeneralNames
  //
  //   bssl::GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
  //
  //   GeneralName ::= CHOICE {
  //        ...
  //        dNSName                         [2]     IA5String,
  //        ...
  //        iPAddress                       [7]     OCTET STRING,
  //        ... }
  ASSERT_GT(dns_names.size() + ip_addresses.size(), 0U);
  bssl::ScopedCBB cbb;
  CBB general_names;
  ASSERT_TRUE(CBB_init(cbb.get(), 64));
  ASSERT_TRUE(CBB_add_asn1(cbb.get(), &general_names, CBS_ASN1_SEQUENCE));
  if (!dns_names.empty()) {
    for (const auto& name : dns_names) {
      CBB general_name;
      ASSERT_TRUE(CBB_add_asn1(&general_names, &general_name,
                               CBS_ASN1_CONTEXT_SPECIFIC | 2));
      ASSERT_TRUE(CBBAddBytes(&general_name, name));
      ASSERT_TRUE(CBB_flush(&general_names));
    }
  }
  if (!ip_addresses.empty()) {
    for (const auto& addr : ip_addresses) {
      CBB general_name;
      ASSERT_TRUE(CBB_add_asn1(&general_names, &general_name,
                               CBS_ASN1_CONTEXT_SPECIFIC | 7));
      ASSERT_TRUE(
          CBB_add_bytes(&general_name, addr.bytes().data(), addr.size()));
      ASSERT_TRUE(CBB_flush(&general_names));
    }
  }
  SetExtension(bssl::der::Input(bssl::kSubjectAltNameOid),
               FinishCBB(cbb.get()));
}

void CertBuilder::SetKeyUsages(const std::vector<bssl::KeyUsageBit>& usages) {
  ASSERT_GT(usages.size(), 0U);
  int number_of_unused_bits = 0;
  std::vector<uint8_t> bytes;
  for (auto usage : usages) {
    int bit_index = static_cast<int>(usage);

    // Index of the byte that contains the bit.
    size_t byte_index = bit_index / 8;

    if (byte_index + 1 > bytes.size()) {
      bytes.resize(byte_index + 1);
      number_of_unused_bits = 8;
    }

    // Within a byte, bits are ordered from most significant to least
    // significant. Convert |bit_index| to an index within the |byte_index|
    // byte, measured from its least significant bit.
    uint8_t bit_index_in_byte = 7 - (bit_index - byte_index * 8);

    if (byte_index + 1 == bytes.size() &&
        bit_index_in_byte < number_of_unused_bits) {
      number_of_unused_bits = bit_index_in_byte;
    }

    bytes[byte_index] |= (1 << bit_index_in_byte);
  }

  // From RFC 5290:
  //   KeyUsage ::= BIT STRING {...}
  bssl::ScopedCBB cbb;
  CBB ku_cbb;
  ASSERT_TRUE(CBB_init(cbb.get(), bytes.size() + 1));
  ASSERT_TRUE(CBB_add_asn1(cbb.get(), &ku_cbb, CBS_ASN1_BITSTRING));
  ASSERT_TRUE(CBB_add_u8(&ku_cbb, number_of_unused_bits));
  ASSERT_TRUE(CBB_add_bytes(&ku_cbb, bytes.data(), bytes.size()));
  SetExtension(bssl::der::Input(bssl::kKeyUsageOid), FinishCBB(cbb.get()),
               /*critical=*/true);
}

void CertBuilder::SetExtendedKeyUsages(
    const std::vector<bssl::der::Input>& purpose_oids) {
  // From RFC 5280:
  //   ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
  //   KeyPurposeId ::= OBJECT IDENTIFIER
  ASSERT_GT(purpose_oids.size(), 0U);
  bssl::ScopedCBB cbb;
  CBB eku;
  ASSERT_TRUE(CBB_init(cbb.get(), 64));
  ASSERT_TRUE(CBB_add_asn1(cbb.get(), &eku, CBS_ASN1_SEQUENCE));

  for (const auto& oid : purpose_oids) {
    CBB purpose_cbb;
    ASSERT_TRUE(CBB_add_asn1(&eku, &purpose_cbb, CBS_ASN1_OBJECT));
    ASSERT_TRUE(CBBAddBytes(&purpose_cbb, oid.AsStringView()));
    ASSERT_TRUE(CBB_flush(&eku));
  }
  SetExtension(bssl::der::Input(bssl::kExtKeyUsageOid), FinishCBB(cbb.get()));
}

void CertBuilder::SetCertificatePolicies(
    const std::vector<std::string>& policy_oids) {
  // From RFC 5280:
  //    certificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation
  //
  //    PolicyInformation ::= SEQUENCE {
  //         policyIdentifier   CertPolicyId,
  //         policyQualifiers   SEQUENCE SIZE (1..MAX) OF
  //                                 PolicyQualifierInfo OPTIONAL }
  //
  //    CertPolicyId ::= OBJECT IDENTIFIER
  if (policy_oids.empty()) {
    EraseExtension(bssl::der::Input(bssl::kCertificatePoliciesOid));
    return;
  }

  bssl::ScopedCBB cbb;
  CBB certificate_policies;
  ASSERT_TRUE(CBB_init(cbb.get(), 64));
  ASSERT_TRUE(
      CBB_add_asn1(cbb.get(), &certificate_policies, CBS_ASN1_SEQUENCE));
  for (const auto& oid : policy_oids) {
    CBB policy_information, policy_identifier;
    ASSERT_TRUE(CBB_add_asn1(&certificate_policies, &policy_information,
                             CBS_ASN1_SEQUENCE));
    ASSERT_TRUE(
        CBB_add_asn1(&policy_information, &policy_identifier, CBS_ASN1_OBJECT));
    ASSERT_TRUE(
        CBB_add_asn1_oid_from_text(&policy_identifier, oid.data(), oid.size()));
    ASSERT_TRUE(CBB_flush(&certificate_policies));
  }

  SetExtension(bssl::der::Input(bssl::kCertificatePoliciesOid),
               FinishCBB(cbb.get()));
}

void CertBuilder::SetPolicyMappings(
    const std::vector<std::pair<std::string, std::string>>& policy_mappings) {
  // From RFC 5280:
  //   PolicyMappings ::= SEQUENCE SIZE (1..MAX) OF SEQUENCE {
  //        issuerDomainPolicy      CertPolicyId,
  //        subjectDomainPolicy     CertPolicyId }
  if (policy_mappings.empty()) {
    EraseExtension(bssl::der::Input(bssl::kPolicyMappingsOid));
    return;
  }

  bssl::ScopedCBB cbb;
  CBB mappings_sequence;
  ASSERT_TRUE(CBB_init(cbb.get(), 64));
  ASSERT_TRUE(CBB_add_asn1(cbb.get(), &mappings_sequence, CBS_ASN1_SEQUENCE));
  for (const auto& [issuer_domain_policy, subject_domain_policy] :
       policy_mappings) {
    CBB mapping_sequence;
    CBB issuer_policy_object;
    CBB subject_policy_object;
    ASSERT_TRUE(
        CBB_add_asn1(&mappings_sequence, &mapping_sequence, CBS_ASN1_SEQUENCE));

    ASSERT_TRUE(CBB_add_asn1(&mapping_sequence, &issuer_policy_object,
                             CBS_ASN1_OBJECT));
    ASSERT_TRUE(CBB_add_asn1_oid_from_text(&issuer_policy_object,
                                           issuer_domain_policy.data(),
                                           issuer_domain_policy.size()));

    ASSERT_TRUE(CBB_add_asn1(&mapping_sequence, &subject_policy_object,
                             CBS_ASN1_OBJECT));
    ASSERT_TRUE(CBB_add_asn1_oid_from_text(&subject_policy_object,
                                           subject_domain_policy.data(),
                                           subject_domain_policy.size()));

    ASSERT_TRUE(CBB_flush(&mappings_sequence));
  }

  SetExtension(bssl::der::Input(bssl::kPolicyMappingsOid), FinishCBB(cbb.get()),
               /*critical=*/true);
}

void CertBuilder::SetPolicyConstraints(
    std::optional<uint64_t> require_explicit_policy,
    std::optional<uint64_t> inhibit_policy_mapping) {
  if (!require_explicit_policy.has_value() &&
      !inhibit_policy_mapping.has_value()) {
    EraseExtension(bssl::der::Input(bssl::kPolicyConstraintsOid));
    return;
  }

  // From RFC 5280:
  //   PolicyConstraints ::= SEQUENCE {
  //        requireExplicitPolicy           [0] SkipCerts OPTIONAL,
  //        inhibitPolicyMapping            [1] SkipCerts OPTIONAL }
  //
  //   SkipCerts ::= INTEGER (0..MAX)
  bssl::ScopedCBB cbb;
  CBB policy_constraints;
  ASSERT_TRUE(CBB_init(cbb.get(), 64));
  ASSERT_TRUE(CBB_add_asn1(cbb.get(), &policy_constraints, CBS_ASN1_SEQUENCE));
  if (require_explicit_policy.has_value()) {
    ASSERT_TRUE(CBB_add_asn1_uint64_with_tag(&policy_constraints,
                                             *require_explicit_policy,
                                             CBS_ASN1_CONTEXT_SPECIFIC | 0));
  }
  if (inhibit_policy_mapping.has_value()) {
    ASSERT_TRUE(CBB_add_asn1_uint64_with_tag(&policy_constraints,
                                             *inhibit_policy_mapping,
                                             CBS_ASN1_CONTEXT_SPECIFIC | 1));
  }

  SetExtension(bssl::der::Input(bssl::kPolicyConstraintsOid),
               FinishCBB(cbb.get()),
               /*critical=*/true);
}

void CertBuilder::SetInhibitAnyPolicy(uint64_t skip_certs) {
  // From RFC 5280:
  //   id-ce-inhibitAnyPolicy OBJECT IDENTIFIER ::=  { id-ce 54 }
  //
  //   InhibitAnyPolicy ::= SkipCerts
  //
  //   SkipCerts ::= INTEGER (0..MAX)
  bssl::ScopedCBB cbb;
  ASSERT_TRUE(CBB_init(cbb.get(), 64));
  ASSERT_TRUE(CBB_add_asn1_uint64(cbb.get(), skip_certs));
  SetExtension(bssl::der::Input(bssl::kInhibitAnyPolicyOid),
               FinishCBB(cbb.get()),
               /*critical=*/true);
}

void CertBuilder::SetValidity(base::Time not_before, base::Time not_after) {
  // From RFC 5280:
  //   Validity ::= SEQUENCE {
  //        notBefore      Time,
  //        notAfter       Time }
  bssl::ScopedCBB cbb;
  CBB validity;
  ASSERT_TRUE(CBB_init(cbb.get(), 64));
  ASSERT_TRUE(CBB_add_asn1(cbb.get(), &validity, CBS_ASN1_SEQUENCE));
  ASSERT_TRUE(x509_util::CBBAddTime(&validity, not_before));
  ASSERT_TRUE(x509_util::CBBAddTime(&validity, not_after));
  validity_tlv_ = FinishCBB(cbb.get());
  Invalidate();
}

void CertBuilder::SetSubjectKeyIdentifier(
    const std::string& subject_key_identifier) {
  ASSERT_FALSE(subject_key_identifier.empty());

  // From RFC 5280:
  //   KeyIdentifier ::= OCTET STRING
  //   SubjectKeyIdentifier ::= KeyIdentifier
  bssl::ScopedCBB cbb;
  ASSERT_TRUE(CBB_init(cbb.get(), 32));

  ASSERT_TRUE(CBB_add_asn1_octet_string(
      cbb.get(),
      reinterpret_cast<const uint8_t*>(subject_key_identifier.data()),
      subject_key_identifier.size()));

  // Replace the existing SKI. Note it MUST be non-critical, per RFC 5280.
  SetExtension(bssl::der::Input(bssl::kSubjectKeyIdentifierOid),
               FinishCBB(cbb.get()),
               /*critical=*/false);
}

void CertBuilder::SetAuthorityKeyIdentifier(
    const std::string& authority_key_identifier) {
  // If an empty AKI is presented, simply erase the existing one. Creating
  // an empty AKI is technically valid, but there's no use case for this.
  // An empty AKI would an empty (ergo, non-unique) SKI on the issuer,
  // which would violate RFC 5280, so using the empty value as a placeholder
  // unless and until a use case emerges is fine.
  if (authority_key_identifier.empty()) {
    EraseExtension(bssl::der::Input(bssl::kAuthorityKeyIdentifierOid));
    return;
  }

  // From RFC 5280:
  //
  //   AuthorityKeyIdentifier ::= SEQUENCE {
  //       keyIdentifier             [0] KeyIdentifier           OPTIONAL,
  //       authorityCertIssuer       [1] bssl::GeneralNames            OPTIONAL,
  //       authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL  }
  //
  //   KeyIdentifier ::= OCTET STRING
  bssl::ScopedCBB cbb;
  CBB aki, aki_value;
  ASSERT_TRUE(CBB_init(cbb.get(), 32));
  ASSERT_TRUE(CBB_add_asn1(cbb.get(), &aki, CBS_ASN1_SEQUENCE));
  ASSERT_TRUE(CBB_add_asn1(&aki, &aki_value, CBS_ASN1_CONTEXT_SPECIFIC | 0));
  ASSERT_TRUE(CBBAddBytes(&aki_value, authority_key_identifier));
  ASSERT_TRUE(CBB_flush(&aki));

  SetExtension(bssl::der::Input(bssl::kAuthorityKeyIdentifierOid),
               FinishCBB(cbb.get()));
}

void CertBuilder::SetSignatureAlgorithm(
    bssl::SignatureAlgorithm signature_algorithm) {
  signature_algorithm_ = signature_algorithm;
  Invalidate();
}

void CertBuilder::SetSignatureAlgorithmTLV(
    std::string_view signature_algorithm_tlv) {
  SetOuterSignatureAlgorithmTLV(signature_algorithm_tlv);
  SetTBSSignatureAlgorithmTLV(signature_algorithm_tlv);
}

void CertBuilder::SetOuterSignatureAlgo
"""


```