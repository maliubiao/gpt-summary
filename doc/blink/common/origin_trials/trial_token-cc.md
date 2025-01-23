Response:
Let's break down the thought process for analyzing this C++ code and generating the comprehensive explanation.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of `trial_token.cc` in Chromium's Blink engine, specifically in the context of Origin Trials. This means identifying its purpose, how it interacts with other web technologies (JavaScript, HTML, CSS), its internal logic, and potential usage errors.

**2. Initial Scan and Keyword Identification:**

I started by quickly scanning the code for keywords and common programming patterns:

* **Includes:**  `#include` statements reveal dependencies like `base/base64.h`, `base/json/json_reader.h`, `url/gurl.h`,  `third_party/blink/public/common/origin_trials/`. These immediately point to base64 decoding, JSON parsing, URL handling, and the core Origin Trials functionality.
* **Namespaces:** `namespace blink` indicates this code is part of the Blink rendering engine.
* **Class Definition:** The presence of the `TrialToken` class is central. This class likely represents the structure and behavior of an Origin Trial token.
* **Methods:**  Methods like `From`, `IsValid`, `Extract`, `Parse`, `ValidateOrigin`, `ValidateFeatureName`, `ValidateDate`, and `ValidateSignature` suggest the core operations performed on these tokens. Static methods hint at utility or factory functions.
* **Constants:**  Constants like `kMaxPayloadSize`, `kMaxTokenSize`, `kVersionOffset`, `kSignatureOffset` reveal internal limitations and the token structure.
* **Data Members:**  The private members of `TrialToken` (`origin_`, `match_subdomains_`, `feature_name_`, `expiry_time_`, `is_third_party_`, `usage_restriction_`, `signature_`) represent the key information stored within a token.
* **Logging:** `DVLOG(2)` statements suggest debugging and informational logging, which can be useful for understanding the flow.
* **Error Handling:**  The `OriginTrialTokenStatus` enum and its usage in return values indicate how different error conditions are handled.
* **Cryptography:** The include of `third_party/boringssl/src/include/openssl/curve25519.h` and the use of `ED25519_verify` strongly suggest cryptographic signature verification.
* **JSON Keywords:**  Strings like "origin", "isSubdomain", "feature", "expiry", "isThirdParty", "usage" within the `Parse` method clearly indicate the expected structure of the JSON payload.

**3. Deductive Reasoning and Functionality Mapping:**

Based on the keywords and the structure, I began to deduce the primary functions:

* **Token Creation (Implicit):** While not directly creating tokens *in this file*, the code *processes* them. The existence of `Extract` and `Parse` strongly implies that tokens are generated elsewhere and then processed here.
* **Token Validation:** The `IsValid` method is the most obvious validation function. It checks origin, expiry date, and (implicitly) the signature via the `Extract` method.
* **Token Extraction:** `Extract` decodes the base64 token, verifies the signature, and extracts the payload.
* **Token Parsing:** `Parse` takes the JSON payload and populates the `TrialToken` object's members.

**4. Connecting to Web Technologies (JavaScript, HTML, CSS):**

This required thinking about *how* Origin Trials are used on the web:

* **HTML Meta Tags:**  The most common way to provide tokens is via `<meta>` tags. I made this connection.
* **HTTP Headers:** The `Origin-Trial` header is another key method.
* **JavaScript:** While this C++ code doesn't directly interact with JavaScript, the *results* of token validation affect JavaScript APIs. Features gated by Origin Trials become available or unavailable based on token validity. I hypothesized about this indirect relationship.
* **CSS (Less Direct):**  Similarly, the availability of CSS features can be controlled by Origin Trials. The connection is less direct but still present.

**5. Logical Reasoning and Examples:**

To illustrate the functionality, I created examples based on the code's logic:

* **`Extract`:** Showed a base64 encoded token and how it's broken down.
* **`Parse`:**  Demonstrated the expected JSON structure and the resulting `TrialToken` object.
* **`IsValid`:** Provided scenarios for valid and invalid tokens based on origin and expiry.

**6. Identifying Potential Usage Errors:**

I considered common mistakes developers might make:

* **Incorrect Token Format:** Typos, invalid base64, malformed JSON.
* **Wrong Origin:** Using a token for a different domain.
* **Expired Tokens:** Not updating tokens.
* **Incorrect Feature Name:** Mismatch between the token and the feature being tested.
* **Subdomain Mismatches:** Not understanding the `isSubdomain` flag.

**7. Structuring the Explanation:**

I organized the information logically:

* **Introduction:** Briefly stated the file's purpose.
* **Core Functionality:**  Summarized the main tasks.
* **Detailed Function Breakdown:** Explained each important method.
* **Relationship to Web Technologies:** Made the connections to JavaScript, HTML, and CSS.
* **Logical Reasoning Examples:**  Provided concrete illustrations.
* **Common Usage Errors:**  Highlighted potential pitfalls.

**8. Refinement and Review:**

I reread the code and my explanation to ensure accuracy and clarity. I checked for any missing pieces or areas that could be explained better. For example, initially, I might not have explicitly mentioned the base64 decoding in `Extract`, so I would add that detail upon review. I also double-checked the interpretation of the version numbers and their associated features (third-party support).

This iterative process of scanning, deducing, connecting, illustrating, and refining allowed me to generate a comprehensive and accurate explanation of the `trial_token.cc` file.
这个文件 `blink/common/origin_trials/trial_token.cc` 是 Chromium Blink 引擎中负责处理 **Origin Trial Token** 的核心组件。Origin Trials 是一种机制，允许开发者在生产环境中试用实验性的 Web 平台功能。这个文件定义了 `TrialToken` 类以及相关的函数，用于解析、验证和管理这些 token。

以下是该文件主要功能的详细列表：

**核心功能：**

1. **Token 的表示和存储:**
   - 定义了 `TrialToken` 类，用于存储 Origin Trial Token 的解析结果。这个类包含了诸如 token 对应的 origin（域名）、是否匹配子域名、特性名称、过期时间、是否为第三方 token 以及使用限制等信息。

2. **Token 的解析 (`TrialToken::From`, `TrialToken::Extract`, `TrialToken::Parse`):**
   - **`TrialToken::From`:**  这是主要的入口点，接收 base64 编码的 token 字符串和对应的公钥。它会调用 `Extract` 进行初步提取，然后调用 `Parse` 来解析 token 的 payload 部分。
   - **`TrialToken::Extract`:**  负责从 base64 编码的 token 字符串中提取出版本号、签名和 payload 数据。它还会验证 token 的基本格式和签名是否有效。
   - **`TrialToken::Parse`:**  负责解析 token 的 JSON payload 部分，提取出 origin、特性名称、过期时间等关键信息，并创建 `TrialToken` 对象。

3. **Token 的验证 (`TrialToken::IsValid`, `TrialToken::ValidateOrigin`, `TrialToken::ValidateFeatureName`, `TrialToken::ValidateDate`, `TrialToken::ValidateSignature`):**
   - **`TrialToken::IsValid`:**  这是主要的验证函数，用于检查 token 对于给定的 origin 和当前时间是否有效。它会依次调用其他验证函数。
   - **`TrialToken::ValidateOrigin`:**  验证 token 中指定的 origin 是否与当前的 origin 匹配。会考虑是否需要匹配子域名。
   - **`TrialToken::ValidateFeatureName`:**  验证 token 中指定的特性名称是否与期望的特性名称一致。
   - **`TrialToken::ValidateDate`:**  验证 token 是否在过期时间之前。
   - **`TrialToken::ValidateSignature`:**  使用提供的公钥验证 token 的签名，确保 token 未被篡改。

4. **支持不同版本的 Token:**
   - 代码中区分了 token 的版本号 (`kVersion2`, `kVersion3`)，并根据版本号处理不同的字段和逻辑。例如，版本 3 引入了对第三方 origin 的支持。

**与 JavaScript, HTML, CSS 的关系：**

这个 C++ 文件本身并不直接包含 JavaScript, HTML 或 CSS 代码。然而，它处理的 Origin Trial Token 是浏览器用于控制是否启用某些实验性 Web 平台功能的关键。这些功能往往会影响 JavaScript API、HTML 元素或属性，以及 CSS 特性。

以下是一些具体的例子：

* **JavaScript API 的启用/禁用:**
    - **假设输入:** 一个有效的 Origin Trial Token，其 `feature_name` 为 "SuperCoolAPI"，且当前页面 origin 与 token 中的 origin 匹配，时间未过期。
    - **输出:**  `TrialToken::IsValid` 返回 `OriginTrialTokenStatus::kSuccess`。
    - **关系:**  Blink 引擎会根据这个成功的验证结果，使得名为 "SuperCoolAPI" 的 JavaScript API 在当前页面上可用。如果 token 无效或不存在，这个 API 将不可用，尝试调用会抛出错误或返回未定义。

* **HTML 元素或属性的行为改变:**
    - **假设输入:** 一个有效的 Origin Trial Token，其 `feature_name` 为 "ExperimentalImageFormat"，允许浏览器解析和渲染一种新的图片格式。
    - **输出:** `TrialToken::IsValid` 返回 `OriginTrialTokenStatus::kSuccess`。
    - **关系:**  当 HTML 中使用了这种新的图片格式（例如通过 `<img src="image.exotic">`），浏览器会根据 Origin Trial Token 的验证结果尝试解析和渲染该图片。如果没有有效的 token，浏览器可能无法识别该格式，导致图片加载失败或显示为占位符。

* **CSS 特性的启用/禁用:**
    - **假设输入:** 一个有效的 Origin Trial Token，其 `feature_name` 为 "CSSCustomPropertiesExtended"，引入了对 CSS 自定义属性的扩展功能。
    - **输出:** `TrialToken::IsValid` 返回 `OriginTrialTokenStatus::kSuccess`。
    - **关系:**  开发者可以在 CSS 中使用 "CSSCustomPropertiesExtended" 引入的新特性（例如更复杂的计算或继承规则）。如果存在有效的 token，浏览器会按照新的规则解析和应用 CSS 样式。否则，这些新的 CSS 特性可能被忽略或导致解析错误。

**逻辑推理的假设输入与输出：**

**场景 1: 有效的第一方 Token**

* **假设输入:**
    * `token_text`: 一个有效的 base64 编码的 Origin Trial Token 字符串，其中包含：
        * `origin`: "https://example.com"
        * `isSubdomain`: false
        * `feature`: "MyFeature"
        * `expiry`:  未来某个时间戳
    * `public_key`: 与生成此 token 配对的公钥
    * `origin`: `url::Origin::Create(GURL("https://example.com"))`
    * `now`: 当前时间，早于 token 的过期时间

* **输出:**
    * `TrialToken::From` 返回一个指向 `TrialToken` 对象的智能指针。
    * `TrialToken::IsValid` 返回 `OriginTrialTokenStatus::kSuccess`。
    * `TrialToken` 对象内部的 `origin_` 为 "https://example.com"。
    * `TrialToken` 对象内部的 `feature_name_` 为 "MyFeature"。
    * `TrialToken` 对象内部的 `expiry_time_`  对应于 token 中指定的过期时间。

**场景 2: 无效的签名**

* **假设输入:**
    * `token_text`: 一个 base64 编码的 Origin Trial Token 字符串，但其签名已被篡改。
    * `public_key`:  与原始 token 配对的公钥

* **输出:**
    * `TrialToken::From` 返回 `nullptr`。
    * 传递给 `TrialToken::From` 的 `out_status` 参数将被设置为 `OriginTrialTokenStatus::kInvalidSignature`。

**场景 3: 过期的 Token**

* **假设输入:**
    * `token_text`: 一个有效的 Origin Trial Token 字符串，但其 `expiry` 时间早于 `now`。
    * `public_key`: 与生成此 token 配对的公钥
    * `origin`:  token 中指定的 origin
    * `now`: 当前时间，晚于 token 的过期时间

* **输出:**
    * `TrialToken::From` 返回一个 `TrialToken` 对象（因为格式正确，可以解析）。
    * `TrialToken::IsValid` 返回 `OriginTrialTokenStatus::kExpired`。

**用户或编程常见的使用错误举例：**

1. **Token 格式错误或损坏:**
   - **错误:** 用户在 HTML 中粘贴 Origin Trial Token 时，不小心引入了空格或其他字符。
   - **后果:** `TrialToken::Extract` 或 `TrialToken::From` 会返回 `nullptr`，`out_status` 可能为 `OriginTrialTokenStatus::kMalformed`。实验性功能不会被启用。

2. **使用了错误的 Origin:**
   - **错误:** 开发者在 `https://sub.example.com` 上使用了为 `https://example.com` 生成的且 `isSubdomain` 为 `false` 的 token。
   - **后果:** `TrialToken::ValidateOrigin` 会返回 `false`，`TrialToken::IsValid` 返回 `OriginTrialTokenStatus::kWrongOrigin`。实验性功能不会被启用。

3. **Token 已过期:**
   - **错误:** 开发者忘记更新已经过期的 Origin Trial Token。
   - **后果:** `TrialToken::ValidateDate` 会返回 `false`，`TrialToken::IsValid` 返回 `OriginTrialTokenStatus::kExpired`。实验性功能会被禁用。

4. **使用了与预期功能不匹配的 Token:**
   - **错误:** 开发者尝试启用名为 "NewFeatureA" 的功能，但提供的 token 的 `feature` 字段是 "NewFeatureB"。
   - **后果:**  尽管 token 可能在其他方面是有效的，但 Blink 引擎在检查特定功能是否启用时，会验证 `feature_name_`。如果名称不匹配，该功能不会被启用。

5. **公钥不匹配（虽然这个文件不直接处理公钥的管理，但会影响验证）：**
   - **错误:**  用于验证 token 的公钥与生成 token 时使用的私钥不匹配。
   - **后果:** `TrialToken::ValidateSignature` 会返回 `false`，`TrialToken::Extract` 或 `TrialToken::From` 会返回 `nullptr`，`out_status` 为 `OriginTrialTokenStatus::kInvalidSignature`。

总而言之，`trial_token.cc` 文件在 Chromium Blink 引擎中扮演着至关重要的角色，它负责 Origin Trial Token 的生命周期管理，确保只有在提供有效、未过期的 token 的情况下，实验性 Web 平台功能才会被启用。这对于 Web 技术的迭代和演进至关重要。

### 提示词
```
这是目录为blink/common/origin_trials/trial_token.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/public/common/origin_trials/trial_token.h"

#include <memory>
#include <optional>
#include <string_view>

#include "base/base64.h"
#include "base/json/json_reader.h"
#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "base/numerics/byte_conversions.h"
#include "base/strings/strcat.h"
#include "base/time/time.h"
#include "base/values.h"
#include "third_party/blink/public/common/origin_trials/origin_trials.h"
#include "third_party/boringssl/src/include/openssl/curve25519.h"
#include "url/gurl.h"
#include "url/origin.h"

namespace blink {

namespace {

// Token payloads can be at most 4KB in size, as a guard against trying to parse
// excessively large tokens (see crbug.com/802377). The origin is the only part
// of the payload that is user-supplied. The 4KB payload limit allows for the
// origin to be ~3900 chars. In some cases, 2KB is suggested as the practical
// limit for URLs, e.g.:
// https://stackoverflow.com/questions/417142/what-is-the-maximum-length-of-a-url-in-different-browsers
// This means tokens can contain origins that are nearly twice as long as any
// expected to be seen in the wild.
const size_t kMaxPayloadSize = 4096;
// Encoded tokens can be at most 6KB in size. Based on the 4KB payload limit,
// this allows for the payload, signature, and other format bits, plus the
// Base64 encoding overhead (~4/3 of the input).
const size_t kMaxTokenSize = 6144;

// Version is a 1-byte field at offset 0.
const size_t kVersionOffset = 0;
const size_t kVersionSize = 1;

// These constants define the Version 2 field sizes and offsets.
const size_t kSignatureOffset = kVersionOffset + kVersionSize;
const size_t kSignatureSize = 64;
const size_t kPayloadLengthOffset = kSignatureOffset + kSignatureSize;
const size_t kPayloadLengthSize = 4;
const size_t kPayloadOffset = kPayloadLengthOffset + kPayloadLengthSize;

// Version 3 introduced support to match tokens against third party origins (see
// design doc
// https://docs.google.com/document/d/1xALH9W7rWmX0FpjudhDeS2TNTEOXuPn4Tlc9VmuPdHA
// for more details).
const uint8_t kVersion3 = 3;
// Version 2 is also currently supported. Version 1 was
// introduced in Chrome M50, and removed in M51. There were no experiments
// enabled in the stable M50 release which would have used those tokens.
const uint8_t kVersion2 = 2;

const char* kUsageSubset = "subset";

}  // namespace

TrialToken::~TrialToken() = default;

// static
std::unique_ptr<TrialToken> TrialToken::From(
    std::string_view token_text,
    const OriginTrialPublicKey& public_key,
    OriginTrialTokenStatus* out_status) {
  DCHECK(out_status);
  std::string token_payload;
  std::string token_signature;
  uint8_t token_version;
  *out_status = Extract(token_text, public_key, &token_payload,
                        &token_signature, &token_version);
  if (*out_status != OriginTrialTokenStatus::kSuccess) {
    DVLOG(2) << "Malformed origin trial token found (unable to extract)";
    return nullptr;
  }
  std::unique_ptr<TrialToken> token = Parse(token_payload, token_version);
  if (token) {
    token->signature_ = token_signature;
    *out_status = OriginTrialTokenStatus::kSuccess;
    DVLOG(2) << "Well-formed origin trial token found for feature "
             << token->feature_name();
  } else {
    DVLOG(2) << "Malformed origin trial token found (unable to parse)";
    *out_status = OriginTrialTokenStatus::kMalformed;
  }
  return token;
}

OriginTrialTokenStatus TrialToken::IsValid(const url::Origin& origin,
                                           const base::Time& now) const {
  // The order of these checks is intentional. For example, will only report a
  // token as expired if it is valid for the origin.
  if (!ValidateOrigin(origin)) {
    DVLOG(2) << "Origin trial token from different origin";
    return OriginTrialTokenStatus::kWrongOrigin;
  }
  if (!ValidateDate(now)) {
    DVLOG(2) << "Origin trial token expired";
    return OriginTrialTokenStatus::kExpired;
  }
  return OriginTrialTokenStatus::kSuccess;
}

// static
OriginTrialTokenStatus TrialToken::Extract(
    std::string_view token_text,
    const OriginTrialPublicKey& public_key,
    std::string* out_token_payload,
    std::string* out_token_signature,
    uint8_t* out_token_version) {
  if (token_text.empty()) {
    return OriginTrialTokenStatus::kMalformed;
  }

  // Protect against attempting to extract arbitrarily large tokens.
  // See crbug.com/802377.
  if (token_text.length() > kMaxTokenSize) {
    return OriginTrialTokenStatus::kMalformed;
  }

  // Token is base64-encoded; decode first.
  std::string token_contents;
  if (!base::Base64Decode(token_text, &token_contents)) {
    return OriginTrialTokenStatus::kMalformed;
  }

  // Only version 2 and 3 currently supported.
  if (token_contents.length() < (kVersionOffset + kVersionSize)) {
    return OriginTrialTokenStatus::kMalformed;
  }
  uint8_t version = token_contents[kVersionOffset];
  if (version != kVersion2 && version != kVersion3) {
    return OriginTrialTokenStatus::kWrongVersion;
  }

  // Token must be large enough to contain a version, signature, and payload
  // length.
  if (token_contents.length() < (kPayloadLengthOffset + kPayloadLengthSize)) {
    return OriginTrialTokenStatus::kMalformed;
  }

  auto token_bytes = base::as_byte_span(token_contents);

  // Extract the length of the signed data (Big-endian).
  uint32_t payload_length = base::U32FromBigEndian(
      token_bytes.subspan(kPayloadLengthOffset).first<4>());

  // Validate that the stated length matches the actual payload length.
  if (payload_length != token_contents.length() - kPayloadOffset) {
    return OriginTrialTokenStatus::kMalformed;
  }

  // Extract the version-specific contents of the token.
  std::string_view version_piece(
      base::as_string_view(token_bytes.subspan(kVersionOffset, kVersionSize)));
  std::string_view signature(base::as_string_view(
      token_bytes.subspan(kSignatureOffset, kSignatureSize)));
  std::string_view payload_piece(base::as_string_view(token_bytes.subspan(
      kPayloadLengthOffset, kPayloadLengthSize + payload_length)));

  // The data which is covered by the signature is (version + length + payload).
  std::string signed_data = base::StrCat({version_piece, payload_piece});

  // Validate the signature on the data before proceeding.
  if (!TrialToken::ValidateSignature(signature, signed_data, public_key)) {
    return OriginTrialTokenStatus::kInvalidSignature;
  }

  // Return the payload and signature, as new strings.
  *out_token_version = version;
  *out_token_payload = token_contents.substr(kPayloadOffset, payload_length);
  *out_token_signature = std::string(signature);
  return OriginTrialTokenStatus::kSuccess;
}

// static
std::unique_ptr<TrialToken> TrialToken::Parse(const std::string& token_payload,
                                              const uint8_t version) {
  // Protect against attempting to parse arbitrarily large tokens. This check is
  // required here because the fuzzer calls Parse() directly, bypassing the size
  // check in Extract().
  // See crbug.com/802377.
  if (token_payload.length() > kMaxPayloadSize) {
    return nullptr;
  }

  std::optional<base::Value> data = base::JSONReader::Read(token_payload);
  if (!data || !data->is_dict()) {
    return nullptr;
  }
  base::Value::Dict& datadict = data->GetDict();

  // Ensure that the origin is a valid (non-opaque) origin URL.
  std::string* origin_string = datadict.FindString("origin");
  if (!origin_string) {
    return nullptr;
  }
  url::Origin origin = url::Origin::Create(GURL(*origin_string));
  if (origin.opaque()) {
    return nullptr;
  }

  // The |isSubdomain| flag is optional. If found, ensure it is a valid boolean.
  bool is_subdomain = false;
  base::Value* is_subdomain_value = datadict.Find("isSubdomain");
  if (is_subdomain_value) {
    if (!is_subdomain_value->is_bool()) {
      return nullptr;
    }
    is_subdomain = is_subdomain_value->GetBool();
  }

  // Ensure that the feature name is a valid string.
  std::string* feature_name = datadict.FindString("feature");
  if (!feature_name || feature_name->empty()) {
    return nullptr;
  }

  // Ensure that the expiry timestamp is a valid (positive) integer.
  int expiry_timestamp = datadict.FindInt("expiry").value_or(0);
  if (expiry_timestamp <= 0) {
    return nullptr;
  }

  // Initialize optional version 3 fields to default values.
  bool is_third_party = false;
  UsageRestriction usage = UsageRestriction::kNone;

  if (version == kVersion3) {
    // The |isThirdParty| flag is optional. If found, ensure it is a valid
    // boolean.
    base::Value* is_third_party_value = datadict.Find("isThirdParty");
    if (is_third_party_value) {
      if (!is_third_party_value->is_bool()) {
        return nullptr;
      }
      is_third_party = is_third_party_value->GetBool();
    }

    // The |usage| field is optional. If found, ensure its value is either empty
    // or "subset".
    std::string* usage_value = datadict.FindString("usage");
    if (usage_value) {
      if (usage_value->empty()) {
        usage = UsageRestriction::kNone;
      } else if (*usage_value == kUsageSubset) {
        usage = UsageRestriction::kSubset;
      } else {
        return nullptr;
      }
    }
  }

  return base::WrapUnique(
      new TrialToken(origin, is_subdomain, *feature_name,
                     base::Time::FromSecondsSinceUnixEpoch(expiry_timestamp),
                     is_third_party, usage));
}

bool TrialToken::ValidateOrigin(const url::Origin& origin) const {
  // TODO(crbug.com/1418906): Remove override for persistent origin trials.
  // This override is currently in place to let sites enable persistent origin
  // trials on behalf of services they make requests to, who do not have the
  // option to enable the trial on their own.
  if (is_third_party_ &&
      origin_trials::IsTrialPersistentToNextResponse(feature_name_)) {
    return true;
  }

  // TODO(crbug.com/1227440): `OriginTrials::MatchesTokenOrigin()` is meant to
  // mirror the logic used in this method (below). Find a way to share/reuse
  // this logic. Otherwise, the logic could change in one place and not the
  // other.
  if (match_subdomains_) {
    return origin.scheme() == origin_.scheme() &&
           origin.DomainIs(origin_.host()) && origin.port() == origin_.port();
  }
  return origin == origin_;
}

bool TrialToken::ValidateFeatureName(std::string_view feature_name) const {
  return feature_name == feature_name_;
}

bool TrialToken::ValidateDate(const base::Time& now) const {
  return expiry_time_ > now;
}

// static
bool TrialToken::ValidateSignature(std::string_view signature,
                                   const std::string& data,
                                   const OriginTrialPublicKey& public_key) {
  // Signature must be 64 bytes long.
  if (signature.length() != 64) {
    return false;
  }

  int result = ED25519_verify(
      reinterpret_cast<const uint8_t*>(data.data()), data.length(),
      reinterpret_cast<const uint8_t*>(signature.data()), public_key.data());
  return (result != 0);
}

TrialToken::TrialToken(const url::Origin& origin,
                       bool match_subdomains,
                       const std::string& feature_name,
                       base::Time expiry_time,
                       bool is_third_party,
                       UsageRestriction usage_restriction)
    : origin_(origin),
      match_subdomains_(match_subdomains),
      feature_name_(feature_name),
      expiry_time_(expiry_time),
      is_third_party_(is_third_party),
      usage_restriction_(usage_restriction) {}

// static
std::unique_ptr<TrialToken> TrialToken::CreateTrialTokenForTesting(
    const url::Origin& origin,
    bool match_subdomains,
    const std::string& feature_name,
    base::Time expiry_time,
    bool is_third_party,
    UsageRestriction usage_restriction,
    const std::string& signature) {
  std::unique_ptr<TrialToken> token = base::WrapUnique(
      new TrialToken(origin, match_subdomains, feature_name, expiry_time,
                     is_third_party, usage_restriction));
  token->signature_ = signature;
  return token;
}

}  // namespace blink
```