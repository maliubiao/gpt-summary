Response: Let's break down the thought process to analyze the provided C++ unittest file.

1. **Understand the Goal:** The request asks for a comprehensive analysis of `trial_token_validator_unittest.cc`. This includes its functionality, relationship to web technologies (JS, HTML, CSS), logical reasoning (input/output), and potential user/programmer errors.

2. **Identify the Core Subject:** The file name strongly suggests it's a unit test for something related to "trial tokens" and their validation. This immediately points to the concept of Origin Trials in Chromium.

3. **Examine the Includes:**  The included headers provide crucial context:
    * `third_party/blink/public/common/origin_trials/trial_token_validator.h`:  This is the primary class being tested.
    * Standard C++ headers (`memory`, `string`, `vector`): Indicate standard programming practices.
    * `base/containers/flat_set.h`, `base/functional/bind.h`, etc.: Point to Chromium's base library usage, particularly for data structures, callbacks, and time manipulation.
    * `net/http/http_response_headers.h`:  Signals interaction with HTTP headers, a key part of how Origin Trials are delivered.
    * `testing/gtest/include/gtest/gtest.h`: Confirms this is a Google Test-based unit test.
    * `third_party/blink/public/common/origin_trials/...`:  Indicates the file's role within the Origin Trials subsystem.
    * `url/gurl.h`: Shows interaction with URLs, essential for origin-based security and feature gating.

4. **Analyze Key Constants and Data Structures:**
    * `kTestPublicKey1`, `kTestPublicKey2`:  These are public keys used for verifying the signatures of trial tokens. The comments even provide the corresponding private keys (for generating new test tokens). This is a crucial element for understanding the security aspect.
    * `kSampleToken`, `kSampleToken2`, `kExpiredToken`, etc.: These are example trial tokens in their encoded string format. The comments explain how these tokens were generated using a specific tool, which is valuable information. Notice the different variations: expired, invalid signature, different features, third-party, subdomain, etc. This hints at the wide range of scenarios the tests cover.
    * `kAppropriateOrigin`, `kInappropriateFeatureName`, etc.:  These constants define test inputs, making it easier to understand the intent of each test.

5. **Understand the Test Structure:**
    * The code uses Google Test (`TEST_F`, `TEST_P`, `EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_FALSE`).
    * `TestOriginTrialPolicy`:  A mock implementation of `OriginTrialPolicy`. This is essential for isolating the `TrialTokenValidator` and controlling the environment in which it's tested (e.g., defining public keys, disabling features).
    * `TrialTokenValidatorTest`: The main test fixture, setting up common test data and the `TrialTokenValidator` instance.
    * Wrapper classes (`ValidateTokenWrapper`, `ValidateTokenAndTrialWrapper`, etc.): These indicate different ways of interacting with the validator, likely testing different API entry points or scenarios. The parameterization using `testing::WithParamInterface` and factories further highlights a systematic testing approach.

6. **Infer Functionality from Tests:**  The individual test cases are the most informative part:
    * Tests like `ValidateValidToken`, `ValidateExpiredToken`, `ValidateInvalidSignature` directly test the core validation logic.
    * Tests involving "ThirdPartyToken" explore how the validator handles cross-origin scenarios.
    * Tests with "SubdomainToken" verify subdomain matching.
    * Tests involving "UnknownFeatureToken" demonstrate how the validator reacts to features it doesn't know about.
    * Tests using "RequestEnablesFeature" focus on how tokens are processed from HTTP headers.
    * Tests using "RevalidateTokenAndTrial" likely involve caching or re-checking of token validity.

7. **Connect to Web Technologies:**  Based on the functionality:
    * **JavaScript:** Origin Trials are often enabled via `<meta>` tags or HTTP headers, impacting how JavaScript features are exposed. The tests don't directly show JS interaction, but the underlying mechanism is related.
    * **HTML:** The `<meta>` tag method of providing tokens is a direct HTML connection.
    * **CSS:** New CSS features can also be gated by Origin Trials. The tests don't explicitly target CSS, but the principle is the same as with JavaScript features.

8. **Identify Logical Reasoning and Input/Output:** Analyze individual test cases. For example:
    * **Input:** `kSampleToken`, `appropriate_origin_`, `Now()`
    * **Expected Output:** `blink::OriginTrialTokenStatus::kSuccess`

9. **Consider User/Programmer Errors:**  Think about how someone might misuse the Origin Trials system or the `TrialTokenValidator` API:
    * Providing an invalid token string.
    * Using a token for the wrong origin.
    * Expecting a token for a disabled feature to work.
    * Misunderstanding the expiry mechanism.

10. **Structure the Analysis:** Organize the findings into logical sections: Functionality, Web Technology Relations, Logical Reasoning, Common Errors, etc. Use clear and concise language. Provide specific examples from the code.

11. **Review and Refine:** Ensure the analysis is accurate and comprehensive. Double-check for any missed details or areas for clarification. For example, initially, I might just say it validates tokens. But then, looking at the different token types and test cases, I'd refine it to be more specific about handling expiry, signatures, origins, third-party status, etc. The wrapper classes also hint at different validation contexts that should be mentioned.
这个C++源代码文件 `trial_token_validator_unittest.cc` 是 Chromium Blink 引擎中用于测试 **Origin Trials (源试用)** 功能的 **`TrialTokenValidator` 类** 的单元测试。

**主要功能:**

这个文件的核心目的是验证 `TrialTokenValidator` 类的各种功能，确保其能够正确地解析、验证和判断 Origin Trial Token 的有效性。它通过一系列的测试用例来模拟不同的场景，并检查 `TrialTokenValidator` 的输出是否符合预期。

具体来说，它测试了以下方面：

1. **Token 的解析和基本验证:**
   - 能够正确解析不同格式的 Token 字符串。
   - 能够验证 Token 的签名是否有效，防止篡改。
   - 能够判断 Token 是否过期。
   - 能够识别格式错误的 Token。

2. **Origin 匹配:**
   - 能够验证 Token 中指定的 Origin 是否与当前页面的 Origin 匹配。
   - 能够处理子域名匹配的情况 (通过 `isSubdomain` 标记)。
   - 能够处理第三方 Origin 的情况 (通过 `isThirdParty` 标记)。

3. **Feature 匹配:**
   - 能够验证 Token 中指定的 Feature 名称是否与期望的 Feature 名称匹配。
   - 能够处理未知的 Feature 名称。

4. **安全性检查:**
   - 能够判断 Token 是否仅适用于安全的 Origin (HTTPS)。
   - 能够处理针对非安全 Origin 的 Deprecation Trial Token。

5. **禁用功能和 Token:**
   - 能够模拟 Origin Trial Policy 中禁用特定 Feature 的情况，并验证 Token 是否被正确地判定为无效。
   - 能够模拟 Origin Trial Policy 中禁用特定 Token 的情况，并验证 Token 是否被正确地判定为无效。
   - 能够模拟针对特定用户的 Feature 禁用，并验证 Token 是否被正确判定为无效。

6. **Expiry Grace Period (过期宽限期):**
   - 能够验证具有过期宽限期的 Token 在宽限期内仍然有效。

7. **`RequestEnablesFeature` 和 `RequestEnablesDeprecatedFeature` 方法的测试:**
   - 能够模拟从 HTTP 响应头中解析 `Origin-Trial` 字段，并判断是否启用了特定的 Feature。

8. **`RevalidateTokenAndTrial` 方法的测试:**
   - 能够测试在已知 Token 信息的情况下，重新验证其有效性的功能。

**与 JavaScript, HTML, CSS 的功能关系及举例说明:**

Origin Trials 允许开发者在正式发布之前，在生产环境中测试新的 Web 平台功能。这些功能可能涉及到 JavaScript API 的新增、HTML 元素的改变或 CSS 属性的引入。`TrialTokenValidator` 的作用是验证浏览器是否应该启用这些实验性的功能。

- **JavaScript:**
  - **举例:** 假设有一个新的 JavaScript API `navigator.experimentalFeature()`. 为了让特定网站能够测试这个 API，开发者可以获取一个包含 `feature: "ExperimentalFeature"` 的 Origin Trial Token。浏览器通过 `TrialTokenValidator` 验证 Token 的有效性后，才会启用 `navigator.experimentalFeature()` API。如果 Token 无效，则该 API 不可用。

- **HTML:**
  - **举例:**  假设引入了一个新的 HTML 元素 `<experimental-element>`. 一个有效的 Origin Trial Token 可以让浏览器识别并渲染这个新的元素。如果 Token 无效，浏览器可能会忽略这个未知元素或者以不同的方式处理。

- **CSS:**
  - **举例:** 假设引入了一个新的 CSS 属性 `animation-composition`. 一个有效的 Origin Trial Token 可以让浏览器解析并应用这个新的 CSS 属性。如果 Token 无效，浏览器可能会忽略该属性。

**逻辑推理及假设输入与输出:**

以下是一些假设的输入和输出示例，展示了 `TrialTokenValidator` 的逻辑推理：

**假设 1:**

- **输入 Token:** `kSampleToken` (一个有效的、未过期的 Token，针对 `https://valid.example.com` 的 `Frobulate` 功能)
- **输入 Origin:** `https://valid.example.com`
- **输入 当前时间:** `kNowTimestamp` (Token 未过期)
- **`ValidateToken` 输出:** `blink::OriginTrialTokenStatus::kSuccess` (成功)

**假设 2:**

- **输入 Token:** `kExpiredToken` (一个已过期的 Token，针对 `https://valid.example.com` 的 `Frobulate` 功能)
- **输入 Origin:** `https://valid.example.com`
- **输入 当前时间:** `kNowTimestamp` (晚于 Token 的过期时间)
- **`ValidateToken` 输出:** `blink::OriginTrialTokenStatus::kExpired` (已过期)

**假设 3:**

- **输入 Token:** `kSampleToken`
- **输入 Origin:** `https://invalid.example.com` (与 Token 中指定的 Origin 不符)
- **输入 当前时间:** `kNowTimestamp`
- **`ValidateToken` 输出:** `blink::OriginTrialTokenStatus::kWrongOrigin` (Origin 不匹配)

**假设 4:**

- **输入 Token:** `kInvalidSignatureToken` (Token 的签名无效)
- **输入 Origin:** `https://valid.example.com`
- **输入 当前时间:** `kNowTimestamp`
- **`ValidateToken` 输出:** `blink::OriginTrialTokenStatus::kInvalidSignature` (签名无效)

**假设 5:**

- **输入 Token:** `kUnknownFeatureToken` (Token 中包含一个未知的 Feature 名称)
- **输入 Origin:** `https://valid.example.com`
- **输入 当前时间:** `kNowTimestamp`
- **`ValidateToken` 输出:** `blink::OriginTrialTokenStatus::kSuccess` (Token 本身有效，但 Feature 未知)
- **`ValidateTokenAndTrial` 输出:** `blink::OriginTrialTokenStatus::kUnknownTrial` (由于 Feature 未知，Trial 未启用)

**涉及用户或编程常见的使用错误及举例说明:**

1. **开发者配置错误的 Token:**
   - **错误:** 开发者为 `https://example.com` 生成了一个 Origin Trial Token，但是却在 `https://sub.example.com` 的网站上使用了这个 Token。
   - **结果:** `TrialTokenValidator` 会返回 `blink::OriginTrialTokenStatus::kWrongOrigin`，导致 Origin Trial 功能无法启用。

2. **Token 过期:**
   - **错误:** 开发者使用了一个已经过期的 Origin Trial Token。
   - **结果:** `TrialTokenValidator` 会返回 `blink::OriginTrialTokenStatus::kExpired`，导致 Origin Trial 功能无法启用。

3. **错误的 HTTP Header 配置:**
   - **错误:** 开发者在 HTTP 响应头中错误地配置了 `Origin-Trial` 字段，例如 Token 字符串不完整或格式错误。
   - **结果:** `TrialTokenValidator` 可能无法解析 Token，返回 `blink::OriginTrialTokenStatus::kMalformed`，或者即使解析成功，也可能因为签名无效等原因导致功能无法启用。

4. **忘记启用 Feature:**
   - **错误:** 开发者获得了有效的 Origin Trial Token，并在网站上配置了，但是忘记在浏览器或 Chrome 命令行中启用对应的实验性 Feature Flag。
   - **结果:**  即使 Token 有效，如果 Feature Flag 未启用，相关的实验性功能也不会生效。这并非 `TrialTokenValidator` 的错误，而是使用者对 Origin Trials 机制理解不足。

5. **使用错误的 Public Key:**
   - **错误:** 如果浏览器配置了错误的 Origin Trial Public Key，那么即使是有效的 Token 也无法通过签名验证。
   - **结果:** `TrialTokenValidator` 会返回 `blink::OriginTrialTokenStatus::kInvalidSignature`。这通常是浏览器配置问题，而不是网站开发者的问题。

总而言之，`trial_token_validator_unittest.cc` 是一个关键的测试文件，用于确保 Chromium 浏览器能够正确地处理 Origin Trial Token，从而保证实验性 Web 平台功能的安全可靠部署和测试。它覆盖了各种可能的场景和错误情况，为 `TrialTokenValidator` 类的健壮性提供了保障。

Prompt: 
```
这是目录为blink/common/origin_trials/trial_token_validator_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/public/common/origin_trials/trial_token_validator.h"

#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "base/containers/flat_set.h"
#include "base/functional/bind.h"
#include "base/memory/ptr_util.h"
#include "base/memory/raw_ref.h"
#include "base/strings/string_util.h"
#include "base/test/simple_test_clock.h"
#include "base/time/time.h"
#include "net/http/http_response_headers.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/origin_trials/origin_trial_policy.h"
#include "third_party/blink/public/common/origin_trials/trial_token.h"
#include "third_party/blink/public/common/origin_trials/trial_token_result.h"
#include "url/gurl.h"

namespace blink::trial_token_validator_unittest {

// These are sample public keys for testing the API.

// For the first public key, the corresponding private key (use this
// to generate new samples for this test file) is:
//
//  0x83, 0x67, 0xf4, 0xcd, 0x2a, 0x1f, 0x0e, 0x04, 0x0d, 0x43, 0x13,
//  0x4c, 0x67, 0xc4, 0xf4, 0x28, 0xc9, 0x90, 0x15, 0x02, 0xe2, 0xba,
//  0xfd, 0xbb, 0xfa, 0xbc, 0x92, 0x76, 0x8a, 0x2c, 0x4b, 0xc7, 0x75,
//  0x10, 0xac, 0xf9, 0x3a, 0x1c, 0xb8, 0xa9, 0x28, 0x70, 0xd2, 0x9a,
//  0xd0, 0x0b, 0x59, 0xe1, 0xac, 0x2b, 0xb7, 0xd5, 0xca, 0x1f, 0x64,
//  0x90, 0x08, 0x8e, 0xa8, 0xe0, 0x56, 0x3a, 0x04, 0xd0

//  For the second public key, the corresponding private key is:

//  0x21, 0xee, 0xfa, 0x81, 0x6a, 0xff, 0xdf, 0xb8, 0xc1, 0xdd, 0x75,
//  0x05, 0x04, 0x29, 0x68, 0x67, 0x60, 0x85, 0x91, 0xd0, 0x50, 0x16,
//  0x0a, 0xcf, 0xa2, 0x37, 0xa3, 0x2e, 0x11, 0x7a, 0x17, 0x96, 0x50,
//  0x07, 0x4d, 0x76, 0x55, 0x56, 0x42, 0x17, 0x2d, 0x8a, 0x9c, 0x47,
//  0x96, 0x25, 0xda, 0x70, 0xaa, 0xb9, 0xfd, 0x53, 0x5d, 0x51, 0x3e,
//  0x16, 0xab, 0xb4, 0x86, 0xea, 0xf3, 0x35, 0xc6, 0xca
const OriginTrialPublicKey kTestPublicKey1 = {
    0x75, 0x10, 0xac, 0xf9, 0x3a, 0x1c, 0xb8, 0xa9, 0x28, 0x70, 0xd2,
    0x9a, 0xd0, 0x0b, 0x59, 0xe1, 0xac, 0x2b, 0xb7, 0xd5, 0xca, 0x1f,
    0x64, 0x90, 0x08, 0x8e, 0xa8, 0xe0, 0x56, 0x3a, 0x04, 0xd0,
};

const OriginTrialPublicKey kTestPublicKey2 = {
    0x50, 0x07, 0x4d, 0x76, 0x55, 0x56, 0x42, 0x17, 0x2d, 0x8a, 0x9c,
    0x47, 0x96, 0x25, 0xda, 0x70, 0xaa, 0xb9, 0xfd, 0x53, 0x5d, 0x51,
    0x3e, 0x16, 0xab, 0xb4, 0x86, 0xea, 0xf3, 0x35, 0xc6, 0xca,
};

// This is a good trial token, signed with the above test private key.
// TODO(iclelland): This token expires in 2033. Update it or find a way
// to autogenerate it before then.
// Generate this token with the command (in tools/origin_trials):
// generate_token.py valid.example.com Frobulate --expire-timestamp=2000000000
const char kSampleToken[] =
    "AuR/1mg+/w5ROLN54Ok20rApK3opgR7Tq9ZfzhATQmnCa+BtPA1RRw4Nigf336r+"
    "O4fM3Sa+MEd+5JcIgSZafw8AAABZeyJvcmlnaW4iOiAiaHR0cHM6Ly92YWxpZC5l"
    "eGFtcGxlLmNvbTo0NDMiLCAiZmVhdHVyZSI6ICJGcm9idWxhdGUiLCAiZXhwaXJ5"
    "IjogMjAwMDAwMDAwMH0=";
const uint8_t kSampleTokenSignature[] = {
    0xe4, 0x7f, 0xd6, 0x68, 0x3e, 0xff, 0x0e, 0x51, 0x38, 0xb3, 0x79,
    0xe0, 0xe9, 0x36, 0xd2, 0xb0, 0x29, 0x2b, 0x7a, 0x29, 0x81, 0x1e,
    0xd3, 0xab, 0xd6, 0x5f, 0xce, 0x10, 0x13, 0x42, 0x69, 0xc2, 0x6b,
    0xe0, 0x6d, 0x3c, 0x0d, 0x51, 0x47, 0x0e, 0x0d, 0x8a, 0x07, 0xf7,
    0xdf, 0xaa, 0xfe, 0x3b, 0x87, 0xcc, 0xdd, 0x26, 0xbe, 0x30, 0x47,
    0x7e, 0xe4, 0x97, 0x08, 0x81, 0x26, 0x5a, 0x7f, 0x0f};

// The expiry time of the sample token (2033-05-18 03:33:20 UTC).
const base::Time kSampleTokenExpiryTime =
    base::Time::FromMillisecondsSinceUnixEpoch(2000000000000);

// This is a trial token signed with the corresponding private key
// for kTestPublicKeys2
// TODO(iclelland): This token expires in 2033. Update it or find a way
// to autogenerate it before then.
// Generate this token with the command (in tools/origin_trials):
// generate_token.py valid.example.com Frobulate --expire-timestamp=2000000000
// --key-file=eftest2.key
const char kSampleToken2[] =
    "Ar3e2ev1rH7T/5NRr/9g/ehLLk7dXBi4mjluPG7pohGifzTJCgBtuGhgJXO/8tD/"
    "m59D2hj0sLjSYSDw4B5NiA4AAABZeyJvcmlnaW4iOiAiaHR0cHM6Ly92YWxpZC5le"
    "GFtcGxlLmNvbTo0NDMiLCAiZmVhdHVyZSI6ICJGcm9idWxhdGUiLCAiZXhwaXJ5Ij"
    "ogMjAwMDAwMDAwMH0=";

// The token should be valid for this origin and for this feature.
const char kAppropriateOrigin[] = "https://valid.example.com";
const char kAppropriateFeatureName[] = "Frobulate";
const char kAppropriateThirdPartyFeatureName[] = "FrobulateThirdParty";
const char kAppropriateDeprecationFeatureName[] = "FrobulateDeprecation";
const char kAppropriateGracePeriodFeatureName[] = "FrobulateExpiryGracePeriod";

const char kInappropriateFeatureName[] = "Grokalyze";
const char kInappropriateOrigin[] = "https://invalid.example.com";
const char kInsecureOrigin[] = "http://valid.example.com";
const char kUnrelatedOrigin[] = "https://www.google.com";

// Well-formed trial token with an invalid signature.
// This token is a corruption of the above valid token.
const char kInvalidSignatureToken[] =
    "AuR/1mg+/w5ROLN54Ok20rApK3opgR7Tq9ZfzhATQmnCa+BtPA1RRw4Nigf336r+"
    "RrOtlAwa0gPqqn+A8GTD3AQAAABZeyJvcmlnaW4iOiAiaHR0cHM6Ly92YWxpZC5l"
    "eGFtcGxlLmNvbTo0NDMiLCAiZmVhdHVyZSI6ICJGcm9idWxhdGUiLCAiZXhwaXJ5"
    "IjogMjAwMDAwMDAwMH0=";

// Well-formed, but expired, trial token. (Expired in 2001)
// Generate this token with the command (in tools/origin_trials):
// generate_token.py valid.example.com Frobulate --expire-timestamp=1000000000
const char kExpiredToken[] =
    "AmHPUIXMaXe9jWW8kJeDFXolVjT93p4XMnK4+jMYd2pjqtFcYB1bUmdD8PunQKM+"
    "RrOtlAwa0gPqqn+A8GTD3AQAAABZeyJvcmlnaW4iOiAiaHR0cHM6Ly92YWxpZC5l"
    "eGFtcGxlLmNvbTo0NDMiLCAiZmVhdHVyZSI6ICJGcm9idWxhdGUiLCAiZXhwaXJ5"
    "IjogMTAwMDAwMDAwMH0=";
const uint8_t kExpiredTokenSignature[] = {
    0x61, 0xcf, 0x50, 0x85, 0xcc, 0x69, 0x77, 0xbd, 0x8d, 0x65, 0xbc,
    0x90, 0x97, 0x83, 0x15, 0x7a, 0x25, 0x56, 0x34, 0xfd, 0xde, 0x9e,
    0x17, 0x32, 0x72, 0xb8, 0xfa, 0x33, 0x18, 0x77, 0x6a, 0x63, 0xaa,
    0xd1, 0x5c, 0x60, 0x1d, 0x5b, 0x52, 0x67, 0x43, 0xf0, 0xfb, 0xa7,
    0x40, 0xa3, 0x3e, 0x46, 0xb3, 0xad, 0x94, 0x0c, 0x1a, 0xd2, 0x03,
    0xea, 0xaa, 0x7f, 0x80, 0xf0, 0x64, 0xc3, 0xdc, 0x04};

const char kUnparsableToken[] = "abcde";

// Well-formed token, for an insecure origin.
// Generate this token with the command (in tools/origin_trials):
// generate_token.py http://valid.example.com Frobulate
// --expire-timestamp=2000000000
const char kInsecureOriginToken[] =
    "AjfC47H1q8/Ho5ALFkjkwf9CBK6oUUeRTlFc50Dj+eZEyGGKFIY2WTxMBfy8cLc3"
    "E0nmFroDA3OmABmO5jMCFgkAAABXeyJvcmlnaW4iOiAiaHR0cDovL3ZhbGlkLmV4"
    "YW1wbGUuY29tOjgwIiwgImZlYXR1cmUiOiAiRnJvYnVsYXRlIiwgImV4cGlyeSI6"
    "IDIwMDAwMDAwMDB9";

// Well-formed token, for match against third party origins.
// Generate this token with the command (in tools/origin_trials):
// generate_token.py valid.example.com FrobulateThirdParty
// --is-third-party --expire-timestamp=2000000000
const char kThirdPartyToken[] =
    "A51LHxdQmDueLf8V89ayrd5I0A2xatWl3Eu7feXlCYOTMQJgFznqw8CTmawLphLz"
    "5k6WshIBcIDEqKjVrAKRqAwAAAB5eyJvcmlnaW4iOiAiaHR0cHM6Ly92YWxpZC5l"
    "eGFtcGxlLmNvbTo0NDMiLCAiZmVhdHVyZSI6ICJGcm9idWxhdGVUaGlyZFBhcnR5"
    "IiwgImV4cGlyeSI6IDIwMDAwMDAwMDAsICJpc1RoaXJkUGFydHkiOiB0cnVlfQ==";

// Well-formed token, for match against third party origins and its usage
// set to user subset exclusion.
// Generate this token with the command (in tools/origin_trials):
// generate_token.py valid.example.com FrobulateThirdParty
//  --version 3 --is-third-party --usage-restriction subset
//  --expire-timestamp=2000000000
const char kThirdPartyUsageSubsetToken[] =
    "A3mGpVqzEea9V9Nl6Qr2LS84PxTf2ZnWdtU6cNZvGmX1rRX5khvJSYuYSCP0J8Ca"
    "XLG+MH6jT+3IH7CWVASK0gcAAACMeyJvcmlnaW4iOiAiaHR0cHM6Ly92YWxpZC5l"
    "eGFtcGxlLmNvbTo0NDMiLCAiaXNUaGlyZFBhcnR5IjogdHJ1ZSwgInVzYWdlIjog"
    "InN1YnNldCIsICJmZWF0dXJlIjogIkZyb2J1bGF0ZVRoaXJkUGFydHkiLCAiZXhw"
    "aXJ5IjogMjAwMDAwMDAwMH0=";

// Well-formed token, for first party, with usage set to user subset exclusion.
// Generate this token with the command (in tools/origin_trials):
// generate_token.py valid.example.com FrobulateThirdParty
//  --version 3 --usage-restriction subset --expire-timestamp=2000000000
const char kUsageSubsetToken[] =
    "Axi0wjIp8gaGr/"
    "pTPzwrHqeWXnmhCiZhE2edsJ9fHX25GV6A8zg1fCv27qhBNnbxjqDpU0a+"
    "xKScEiqKK1MS3QUAAAB2eyJvcmlnaW4iOiAiaHR0cHM6Ly92YWxpZC5leGFtcGxlLmNvbTo0ND"
    "MiLCAidXNhZ2UiOiAic3Vic2V0IiwgImZlYXR1cmUiOiAiRnJvYnVsYXRlVGhpcmRQYXJ0eSIs"
    "ICJleHBpcnkiOiAyMDAwMDAwMDAwfQ==";

// Well-formed token for a feature with an expiry grace period.
// Generate this token with the command (in tools/origin_trials):
// generate_token.py valid.example.com FrobulateExpiryGracePeriod
//  --expire-timestamp=2000000000
const char kExpiryGracePeriodToken[] =
    "A2AVLsM2Set66KCwTfxH1ni9v8Jcs685qHKDLGam1LmpvnJE9GhYQwbLid3Xlqs/"
    "2Em2HBp8CMZlj11Qk6R06QUAAABqeyJvcmlnaW4iOiAiaHR0cHM6Ly92YWxpZC5leGFtcGxlLm"
    "NvbTo0NDMiLCAiZmVhdHVyZSI6ICJGcm9idWxhdGVFeHBpcnlHcmFjZVBlcmlvZCIsICJleHBp"
    "cnkiOiAyMDAwMDAwMDAwfQ==";

// Well-formed token for match against third party origins and a feature with an
// expiry grace period.
// Generate this token with the command (in tools/origin_trials):
// generate_token.py valid.example.com FrobulateExpiryGracePeriodThirdParty
//  --is-third-party --expire-timestamp=2000000000
const char kExpiryGracePeriodThirdPartyToken[] =
    "AwLU1cK4P3vWskpAlt5cSiiLl9QOJBeVIQEu5ZFJWEZRFSk7zckx8K6MCa+WZ3cU"
    "8hgF7xoA20QJpfkGzTsCvAEAAACKeyJvcmlnaW4iOiAiaHR0cHM6Ly92YWxpZC5l"
    "eGFtcGxlLmNvbTo0NDMiLCAiZmVhdHVyZSI6ICJGcm9idWxhdGVFeHBpcnlHcmFj"
    "ZVBlcmlvZFRoaXJkUGFydHkiLCAiZXhwaXJ5IjogMjAwMDAwMDAwMCwgImlzVGhp"
    "cmRQYXJ0eSI6IHRydWV9";

// Well-formed token, with an unknown feature name.
// Generate this token with the command (in tools/origin_trials):
// generate_token.py valid.example.com Grokalyze
//  --expire-timestamp=2000000000
const char kUnknownFeatureToken[] =
    "AxjosEuqWyp9mrBFMOHJtO84YyY4QYuJ6TUNBMVzKMUWPE+B7Nwg2kgZKGO+"
    "85m0bG0vWEs4m53TWtO1LNf0RgsAAABZeyJvcmlnaW4iOiAiaHR0cHM6Ly92YWxpZC5leGFtcG"
    "xlLmNvbTo0NDMiLCAiZmVhdHVyZSI6ICJHcm9rYWx5emUiLCAiZXhwaXJ5IjogMjAwMDAwMDAw"
    "MH0=";

// Well-formed token for match against third party origins, with an unknown
// feature name. Generate this token with the command (in tools/origin_trials):
// generate_token.py valid.example.com Grokalyze
//  --is-third-party --expire-timestamp=2000000000
const char kUnknownFeatureThirdPartyToken[] =
    "A7BJkSTbLJ8/EM61BwStBGK3+hAnss/"
    "fmvpkRmuGuBssyEKczr0iqmj4J3hvRM+"
    "WzjotyzFopeNLSNU6FGlFZwMAAABveyJvcmlnaW4iOiAiaHR0cHM6Ly92YWxpZC5leGFtcGxlL"
    "mNvbTo0NDMiLCAiZmVhdHVyZSI6ICJHcm9rYWx5emUiLCAiZXhwaXJ5IjogMjAwMDAwMDAwMCw"
    "gImlzVGhpcmRQYXJ0eSI6IHRydWV9";

// Well-formed token, for match against third party origins for a trial that
// doesn't allow third-party origins.
// Generate this token with the command (in tools/origin_trials):
// generate_token.py valid.example.com Frobulate
// --is-third-party --expire-timestamp=2000000000
const char kThirdPartyTokenForNonThirdPartyTrial[] =
    "AzZhTxsmsC9fGlNnLEwMuo88WpNjUCDWRzP9NGyP854gRMcvTvbpO1OzEMwbyFeC"
    "NjRE7SiCKXMzjchwl0rwTQcAAABveyJvcmlnaW4iOiAiaHR0cHM6Ly92YWxpZC5l"
    "eGFtcGxlLmNvbTo0NDMiLCAiZmVhdHVyZSI6ICJGcm9idWxhdGUiLCAiZXhwaXJ5"
    "IjogMjAwMDAwMDAwMCwgImlzVGhpcmRQYXJ0eSI6IHRydWV9";

// Well-formed token, for match against insecure origins for a deprecation
// trial.
// Generate this token with the command (in tools/origin_trials):
// generate_token.py http://valid.example.com FrobulateDeprecation
// --expire-timestamp=2000000000
const char kDeprecationInsecureToken[] =
    "A1k7VFKXf+PKrR4J+QPP/pzXmDGKpYqFvWtGxAP0MZoV37/o/Eu1az8ivCp4Z9le"
    "grPkZW4Hi5wUN5NaA0j64AsAAABieyJvcmlnaW4iOiAiaHR0cDovL3ZhbGlkLmV4"
    "YW1wbGUuY29tOjgwIiwgImZlYXR1cmUiOiAiRnJvYnVsYXRlRGVwcmVjYXRpb24i"
    "LCAiZXhwaXJ5IjogMjAwMDAwMDAwMH0=";

// Well-formed token, for match against insecure third-party origins.
// Generate this token with the command (in tools/origin_trials):
// generate_token.py http://valid.example.com FrobulateThirdParty
// --is-third-party --expire-timestamp=2000000000
const char kThirdPartyInsecureToken[] =
    "AxlhBSHLsMiWo84CUgo6vejsWrVDLB1v6oyNxVMvY9Yb9ccf6/1CmDnEEp/vuGk0"
    "lG9Hn4y91ysAkEGnDtJYMwIAAAB3eyJvcmlnaW4iOiAiaHR0cDovL3ZhbGlkLmV4"
    "YW1wbGUuY29tOjgwIiwgImZlYXR1cmUiOiAiRnJvYnVsYXRlVGhpcmRQYXJ0eSIs"
    "ICJleHBpcnkiOiAyMDAwMDAwMDAwLCAiaXNUaGlyZFBhcnR5IjogdHJ1ZX0=";

// Well-formed token, for match against subdomain origins.
// Generate this token with the command (in tools/origin_trials):
// generate_token.py example.com Frobulate
// --is-subdomain --expire-timestamp=2000000000
const char kSubdomainToken[] =
    "A6Q929l21zbxF8lhVu75RktCi6DIz9tcVTDFCeH752NfJ8cIs4dJjp8xLKRtbPgS"
    "5p6sR9JDlEu23ubXsWN21w4AAABoeyJvcmlnaW4iOiAiaHR0cHM6Ly9leGFtcGxl"
    "LmNvbTo0NDMiLCAiZmVhdHVyZSI6ICJGcm9idWxhdGUiLCAiZXhwaXJ5IjogMjAw"
    "MDAwMDAwMCwgImlzU3ViZG9tYWluIjogdHJ1ZX0=";

// Well-formed token, for match against third-party subdomain origins.
// Generate this token with the command (in tools/origin_trials):
// generate_token.py example.com FrobulateThirdParty
// --is-subdomain --is-third-party --expire-timestamp=2000000000
const char kThirdPartySubdomainToken[] =
    "A+rkIJ7LrKWl0fV+V4Wp5eolmX62Q8IAQgXvHV/DxKVsPjROQPuy9tMkrTgRdHto"
    "xs/3G3UC4kONFRazlfmE7A8AAACIeyJvcmlnaW4iOiAiaHR0cHM6Ly9leGFtcGxl"
    "LmNvbTo0NDMiLCAiZmVhdHVyZSI6ICJGcm9idWxhdGVUaGlyZFBhcnR5IiwgImV4"
    "cGlyeSI6IDIwMDAwMDAwMDAsICJpc1N1YmRvbWFpbiI6IHRydWUsICJpc1RoaXJk"
    "UGFydHkiOiB0cnVlfQ==";

// Token for insecure third-party subdomain matching.
// Generate this token with the command (in tools/origin_trials):
// generate_token.py http://example.com FrobulateThirdParty
// --is-subdomain --is-third-party --expire-timestamp=2000000000
const char kThirdPartyInsecureSubdomainToken[] =
    "A09GOcBObv3Ltpr5tt+sKE16irURhADqX6p+cLIs/pHHmciM8QYJ2YT7JHqGoSsm"
    "0sSNl8I7KCDSfPaRevse7AYAAACGeyJvcmlnaW4iOiAiaHR0cDovL2V4YW1wbGUu"
    "Y29tOjgwIiwgImZlYXR1cmUiOiAiRnJvYnVsYXRlVGhpcmRQYXJ0eSIsICJleHBp"
    "cnkiOiAyMDAwMDAwMDAwLCAiaXNTdWJkb21haW4iOiB0cnVlLCAiaXNUaGlyZFBh"
    "cnR5IjogdHJ1ZX0=";

// This timestamp is set to a time after the expiry timestamp of kExpiredToken,
// but before the expiry timestamp of kValidToken.
double kNowTimestamp = 1500000000;

class TestOriginTrialPolicy : public OriginTrialPolicy {
 public:
  bool IsOriginTrialsSupported() const override { return true; }
  bool IsOriginSecure(const GURL& url) const override {
    return url.SchemeIs("https");
  }
  const std::vector<blink::OriginTrialPublicKey>& GetPublicKeys()
      const override {
    return keys_;
  }
  bool IsFeatureDisabled(std::string_view feature) const override {
    return disabled_features_.count(feature) > 0;
  }

  bool IsFeatureDisabledForUser(std::string_view feature) const override {
    return disabled_features_for_user_.count(std::string(feature)) > 0;
  }

  // Test setup methods
  void SetPublicKeys(const std::vector<OriginTrialPublicKey>& keys) {
    keys_ = keys;
  }

  void DisableFeature(const std::string& feature) {
    disabled_features_.insert(feature);
  }
  void DisableFeatureForUser(const std::string& feature) {
    disabled_features_for_user_.insert(feature);
  }
  void DisableToken(const std::string& token) {
    disabled_tokens_.insert(token);
  }

 protected:
  bool IsTokenDisabled(std::string_view token_signature) const override {
    return disabled_tokens_.count(std::string(token_signature)) > 0;
  }

 private:
  std::vector<blink::OriginTrialPublicKey> keys_;
  base::flat_set<std::string> disabled_features_;
  base::flat_set<std::string> disabled_features_for_user_;
  base::flat_set<std::string> disabled_tokens_;
};

class TrialTokenValidatorTest : public testing::Test {
 public:
  TrialTokenValidatorTest()
      : appropriate_origin_(url::Origin::Create(GURL(kAppropriateOrigin))),
        inappropriate_origin_(url::Origin::Create(GURL(kInappropriateOrigin))),
        insecure_origin_(url::Origin::Create(GURL(kInsecureOrigin))),
        unrelated_origin_(url::Origin::Create(GURL(kUnrelatedOrigin))),
        valid_token_signature_(
            std::string(reinterpret_cast<const char*>(kSampleTokenSignature),
                        std::size(kSampleTokenSignature))),
        expired_token_signature_(
            std::string(reinterpret_cast<const char*>(kExpiredTokenSignature),
                        std::size(kExpiredTokenSignature))),
        response_headers_(new net::HttpResponseHeaders("")) {
    TrialTokenValidator::SetOriginTrialPolicyGetter(
        base::BindRepeating([](OriginTrialPolicy* policy) { return policy; },
                            base::Unretained(&policy_)));
    SetPublicKeys({kTestPublicKey1, kTestPublicKey2});
  }

  ~TrialTokenValidatorTest() override {
    TrialTokenValidator::ResetOriginTrialPolicyGetter();
  }

  void SetPublicKeys(const std::vector<OriginTrialPublicKey> keys) {
    policy_.SetPublicKeys(keys);
  }

  void DisableFeature(const std::string& feature) {
    policy_.DisableFeature(feature);
  }

  void DisableFeatureForUser(const std::string& feature) {
    policy_.DisableFeatureForUser(feature);
  }

  void DisableToken(const std::string& token_signature) {
    policy_.DisableToken(token_signature);
  }

  base::Time Now() {
    return base::Time::FromSecondsSinceUnixEpoch(kNowTimestamp);
  }

  TrialTokenValidator::OriginInfo WithInfo(const url::Origin& origin) const {
    return TrialTokenValidator::OriginInfo(origin);
  }

  std::vector<TrialTokenValidator::OriginInfo> WithInfo(
      base::span<const url::Origin> origins) const {
    std::vector<TrialTokenValidator::OriginInfo> info;
    for (const url::Origin& origin : origins) {
      info.emplace_back(origin);
    }
    return info;
  }

  const url::Origin appropriate_origin_;
  const url::Origin inappropriate_origin_;
  const url::Origin insecure_origin_;
  const url::Origin unrelated_origin_;

  std::string valid_token_signature_;
  std::string expired_token_signature_;

  scoped_refptr<net::HttpResponseHeaders> response_headers_;

  TestOriginTrialPolicy policy_;
  const TrialTokenValidator validator_;
};

// Define two classes that wrap the ValidateToken and ValidateTokenAndTrial
// methods respectively under a common name, so we can repeat the tests for each
// function where it makes sense
class ValidateTokenWrapper {
 public:
  explicit ValidateTokenWrapper(const blink::TrialTokenValidator& validator)
      : validator_(validator) {}
  virtual ~ValidateTokenWrapper() = default;

  virtual TrialTokenResult Validate(std::string_view token,
                                    const url::Origin& origin,
                                    base::Time timestamp) const {
    return validator_->ValidateToken(token, origin, timestamp);
  }

  virtual TrialTokenResult Validate(
      std::string_view token,
      const url::Origin& origin,
      base::span<const url::Origin> script_origins,
      base::Time timestamp) const {
    return validator_->ValidateToken(token, origin, script_origins, timestamp);
  }

 protected:
  const raw_ref<const blink::TrialTokenValidator> validator_;
};

class ValidateTokenAndTrialWrapper : public ValidateTokenWrapper {
 public:
  explicit ValidateTokenAndTrialWrapper(
      const blink::TrialTokenValidator& validator)
      : ValidateTokenWrapper(validator) {}
  ~ValidateTokenAndTrialWrapper() override = default;

  TrialTokenResult Validate(std::string_view token,
                            const url::Origin& origin,
                            base::Time timestamp) const override {
    return validator_->ValidateTokenAndTrial(token, origin, timestamp);
  }

  TrialTokenResult Validate(std::string_view token,
                            const url::Origin& origin,
                            base::span<const url::Origin> script_origins,
                            base::Time timestamp) const override {
    return validator_->ValidateTokenAndTrial(token, origin, script_origins,
                                             timestamp);
  }
};

class ValidateTokenAndTrialWithOriginInfoWrapper : public ValidateTokenWrapper {
 public:
  explicit ValidateTokenAndTrialWithOriginInfoWrapper(
      const blink::TrialTokenValidator& validator)
      : ValidateTokenWrapper(validator) {}
  ~ValidateTokenAndTrialWithOriginInfoWrapper() override = default;

  TrialTokenResult Validate(std::string_view token,
                            const url::Origin& origin,
                            base::Time timestamp) const override {
    return validator_->ValidateTokenAndTrialWithOriginInfo(
        token, TrialTokenValidator::OriginInfo(origin), {}, timestamp);
  }

  TrialTokenResult Validate(std::string_view token,
                            const url::Origin& origin,
                            base::span<const url::Origin> script_origins,
                            base::Time timestamp) const override {
    std::vector<TrialTokenValidator::OriginInfo> info;
    for (const url::Origin& script_origin : script_origins) {
      info.emplace_back(script_origin);
    }
    return validator_->ValidateTokenAndTrialWithOriginInfo(
        token, TrialTokenValidator::OriginInfo(origin), info, timestamp);
  }
};
// Factory classes that allows us to instantiate a parameterized test
class ValidateTokenWrapperFactory {
 public:
  virtual ~ValidateTokenWrapperFactory() = default;
  virtual std::unique_ptr<const ValidateTokenWrapper> CreateWrapper(
      const blink::TrialTokenValidator& validator) const {
    return std::make_unique<ValidateTokenWrapper>(validator);
  }
};

class ValidateTokenAndTrialWrapperFactory : public ValidateTokenWrapperFactory {
 public:
  ~ValidateTokenAndTrialWrapperFactory() override = default;
  std::unique_ptr<const ValidateTokenWrapper> CreateWrapper(
      const blink::TrialTokenValidator& validator) const override {
    return std::make_unique<ValidateTokenAndTrialWrapper>(validator);
  }
};

class ValidateTokenAndTrialWithOriginInfoWrapperFactory
    : public ValidateTokenWrapperFactory {
 public:
  ~ValidateTokenAndTrialWithOriginInfoWrapperFactory() override = default;
  std::unique_ptr<const ValidateTokenWrapper> CreateWrapper(
      const blink::TrialTokenValidator& validator) const override {
    return std::make_unique<ValidateTokenAndTrialWithOriginInfoWrapper>(
        validator);
  }
};

// Test suite for tests where TrialTokenValidator::ValidateToken and
// TrialTokenValidator::ValidateTokenAndTrial should yield the same result
class TrialTokenValidatorEquivalenceTest
    : public TrialTokenValidatorTest,
      public testing::WithParamInterface<ValidateTokenWrapperFactory> {
 public:
  TrialTokenValidatorEquivalenceTest()
      : validator_wrapper_(GetParam().CreateWrapper(validator_)) {
    DCHECK(validator_wrapper_);
  }

  ~TrialTokenValidatorEquivalenceTest() noexcept override = default;

  // Expose the |Validate| functions of the wrapper for shorter code in tests
  TrialTokenResult Validate(std::string_view token,
                            const url::Origin& origin,
                            base::Time timestamp) const {
    return validator_wrapper_->Validate(token, origin, timestamp);
  }

  TrialTokenResult Validate(std::string_view token,
                            const url::Origin& origin,
                            base::span<const url::Origin> script_origins,
                            base::Time timestamp) const {
    return validator_wrapper_->Validate(token, origin, script_origins,
                                        timestamp);
  }

 protected:
  std::unique_ptr<const ValidateTokenWrapper> validator_wrapper_;
};

// Tests of the basic ValidateToken functionality where ValidateTokenAndTrial
// should yield the same result
// Using TrialTokenValidatorTest as prefix to allow for unified gtest_filter
INSTANTIATE_TEST_SUITE_P(
    TrialTokenValidatorTest,
    TrialTokenValidatorEquivalenceTest,
    testing::Values(ValidateTokenWrapperFactory(),
                    ValidateTokenAndTrialWrapperFactory(),
                    ValidateTokenAndTrialWithOriginInfoWrapperFactory()));

TEST_P(TrialTokenValidatorEquivalenceTest, ValidateValidToken) {
  TrialTokenResult result = Validate(kSampleToken, appropriate_origin_, Now());
  EXPECT_EQ(blink::OriginTrialTokenStatus::kSuccess, result.Status());
  EXPECT_EQ(kAppropriateFeatureName, result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());
  EXPECT_FALSE(result.ParsedToken()->is_third_party());

  // All signing keys should be able to validate their tokens.
  TrialTokenResult result2 =
      Validate(kSampleToken2, appropriate_origin_, Now());
  EXPECT_EQ(blink::OriginTrialTokenStatus::kSuccess, result2.Status());
  EXPECT_EQ(kAppropriateFeatureName, result2.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result2.ParsedToken()->expiry_time());
  EXPECT_FALSE(result2.ParsedToken()->is_third_party());
}

TEST_P(TrialTokenValidatorEquivalenceTest, ValidateThirdPartyToken) {
  url::Origin third_party_origins[] = {appropriate_origin_};
  TrialTokenResult result = Validate(kThirdPartyToken, appropriate_origin_,
                                     third_party_origins, Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kSuccess);
  EXPECT_EQ(kAppropriateThirdPartyFeatureName,
            result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());
}

TEST_P(TrialTokenValidatorEquivalenceTest,
       ValidateThirdPartyTokenFromExternalScript) {
  url::Origin third_party_origins[] = {appropriate_origin_};
  TrialTokenResult result = Validate(kThirdPartyToken, inappropriate_origin_,
                                     third_party_origins, Now());
  EXPECT_EQ(blink::OriginTrialTokenStatus::kSuccess, result.Status());
  EXPECT_EQ(kAppropriateThirdPartyFeatureName,
            result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());
  EXPECT_TRUE(result.ParsedToken()->is_third_party());
}

TEST_P(TrialTokenValidatorEquivalenceTest,
       ValidateThirdPartyTokenFromMultipleExternalScripts) {
  url::Origin third_party_origins[] = {inappropriate_origin_,
                                       appropriate_origin_};
  TrialTokenResult result = Validate(kThirdPartyToken, inappropriate_origin_,
                                     third_party_origins, Now());
  EXPECT_EQ(blink::OriginTrialTokenStatus::kSuccess, result.Status());
  EXPECT_EQ(kAppropriateThirdPartyFeatureName,
            result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());
  EXPECT_TRUE(result.ParsedToken()->is_third_party());
}

TEST_P(TrialTokenValidatorEquivalenceTest,
       ValidateThirdPartyTokenFromInappropriateScriptOrigin) {
  url::Origin third_party_origins[] = {inappropriate_origin_};
  EXPECT_EQ(blink::OriginTrialTokenStatus::kWrongOrigin,
            Validate(kThirdPartyToken, appropriate_origin_, third_party_origins,
                     Now())
                .Status());
}

TEST_P(TrialTokenValidatorEquivalenceTest,
       ValidateThirdPartyTokenFromMultipleInappropriateScriptOrigins) {
  url::Origin third_party_origins[] = {inappropriate_origin_, insecure_origin_};
  EXPECT_EQ(blink::OriginTrialTokenStatus::kWrongOrigin,
            Validate(kThirdPartyToken, appropriate_origin_, third_party_origins,
                     Now())
                .Status());
}

TEST_P(TrialTokenValidatorEquivalenceTest,
       ValidateThirdPartyTokenNotFromExternalScript) {
  EXPECT_EQ(blink::OriginTrialTokenStatus::kWrongOrigin,
            Validate(kThirdPartyToken, appropriate_origin_,
                     base::span<const url::Origin>{}, Now())
                .Status());
  std::vector<url::Origin> empty_origin_list;
  EXPECT_EQ(
      blink::OriginTrialTokenStatus::kWrongOrigin,
      Validate(kThirdPartyToken, appropriate_origin_, empty_origin_list, Now())
          .Status());
}

TEST_P(TrialTokenValidatorEquivalenceTest, ValidateInappropriateOrigin) {
  TrialTokenResult inappropriate_result =
      Validate(kSampleToken, inappropriate_origin_, Now());
  EXPECT_EQ(inappropriate_result.Status(),
            blink::OriginTrialTokenStatus::kWrongOrigin);
  EXPECT_NE(inappropriate_result.ParsedToken(), nullptr);

  TrialTokenResult insecure_result =
      Validate(kSampleToken, insecure_origin_, Now());
  EXPECT_EQ(insecure_result.Status(),
            blink::OriginTrialTokenStatus::kWrongOrigin);
  EXPECT_NE(insecure_result.ParsedToken(), nullptr);
}

TEST_P(TrialTokenValidatorEquivalenceTest, ValidateInvalidSignature) {
  TrialTokenResult result =
      Validate(kInvalidSignatureToken, appropriate_origin_, Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kInvalidSignature);
  EXPECT_EQ(result.ParsedToken(), nullptr);
}

TEST_P(TrialTokenValidatorEquivalenceTest, ValidateUnparsableToken) {
  TrialTokenResult result =
      Validate(kUnparsableToken, appropriate_origin_, Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kMalformed);
  EXPECT_EQ(result.ParsedToken(), nullptr);
}

TEST_P(TrialTokenValidatorEquivalenceTest, ValidateExpiredToken) {
  TrialTokenResult result = Validate(kExpiredToken, appropriate_origin_, Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kExpired);
  EXPECT_NE(result.ParsedToken(), nullptr);
}

TEST_P(TrialTokenValidatorEquivalenceTest, ValidateValidTokenWithIncorrectKey) {
  SetPublicKeys({kTestPublicKey2});
  TrialTokenResult result = Validate(kSampleToken, appropriate_origin_, Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kInvalidSignature);
  EXPECT_EQ(result.ParsedToken(), nullptr);
}

TEST_P(TrialTokenValidatorEquivalenceTest, PublicKeyNotAvailable) {
  SetPublicKeys({});
  TrialTokenResult result = Validate(kSampleToken, appropriate_origin_, Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kNotSupported);
  EXPECT_EQ(result.ParsedToken(), nullptr);
}

TEST_P(TrialTokenValidatorEquivalenceTest, ValidatorRespectsDisabledFeatures) {
  TrialTokenResult result = Validate(kSampleToken, appropriate_origin_, Now());
  // Disable an irrelevant feature; token should still validate
  DisableFeature(kInappropriateFeatureName);
  EXPECT_EQ(blink::OriginTrialTokenStatus::kSuccess, result.Status());
  EXPECT_EQ(kAppropriateFeatureName, result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());
  // Disable the token's feature; it should no longer be valid
  DisableFeature(kAppropriateFeatureName);
  EXPECT_EQ(blink::OriginTrialTokenStatus::kFeatureDisabled,
            Validate(kSampleToken, appropriate_origin_, Now()).Status());
}
TEST_P(TrialTokenValidatorEquivalenceTest,
       ValidatorRespectsDisabledFeaturesForUserWithFirstPartyToken) {
  // Token should be valid if the feature is not disabled for user.
  TrialTokenResult result =
      Validate(kUsageSubsetToken, appropriate_origin_, Now());
  EXPECT_EQ(blink::OriginTrialTokenStatus::kSuccess, result.Status());
  EXPECT_EQ(kAppropriateThirdPartyFeatureName,
            result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());
  // Token should be invalid when the feature is disabled for user.
  DisableFeatureForUser(kAppropriateThirdPartyFeatureName);
  EXPECT_EQ(blink::OriginTrialTokenStatus::kFeatureDisabledForUser,
            Validate(kUsageSubsetToken, appropriate_origin_, Now()).Status());
}

TEST_P(TrialTokenValidatorEquivalenceTest,
       ValidatorRespectsDisabledFeaturesForUserWithThirdPartyToken) {
  // Token should be valid if the feature is not disabled for user.
  url::Origin third_party_origins[] = {appropriate_origin_};
  TrialTokenResult result =
      Validate(kThirdPartyUsageSubsetToken, inappropriate_origin_,
               third_party_origins, Now());
  EXPECT_EQ(blink::OriginTrialTokenStatus::kSuccess, result.Status());
  EXPECT_EQ(kAppropriateThirdPartyFeatureName,
            result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());
  // Token should be invalid when the feature is disabled for user.
  DisableFeatureForUser(kAppropriateThirdPartyFeatureName);
  EXPECT_EQ(blink::OriginTrialTokenStatus::kFeatureDisabledForUser,
            Validate(kThirdPartyUsageSubsetToken, inappropriate_origin_,
                     third_party_origins, Now())
                .Status());
}

TEST_P(TrialTokenValidatorEquivalenceTest, ValidatorRespectsDisabledTokens) {
  TrialTokenResult result = Validate(kSampleToken, appropriate_origin_, Now());
  // Disable an irrelevant token; token should still validate
  DisableToken(expired_token_signature_);
  EXPECT_EQ(blink::OriginTrialTokenStatus::kSuccess, result.Status());
  EXPECT_EQ(kAppropriateFeatureName, result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());

  // Disable the token; it should no longer be valid
  DisableToken(valid_token_signature_);
  EXPECT_EQ(blink::OriginTrialTokenStatus::kTokenDisabled,
            Validate(kSampleToken, appropriate_origin_, Now()).Status());
}

TEST_P(TrialTokenValidatorEquivalenceTest, ValidateValidExpiryGraceToken) {
  // This token is valid one day before the end of the expiry grace period,
  // even though it is past the token's expiry time.
  auto current_time =
      kSampleTokenExpiryTime + kExpiryGracePeriod - base::Days(1);
  TrialTokenResult result =
      Validate(kExpiryGracePeriodToken, appropriate_origin_, current_time);
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kSuccess);
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());
}

TEST_P(TrialTokenValidatorEquivalenceTest, ValidateExpiredExpiryGraceToken) {
  // This token is expired at the end of the expiry grace period.
  auto current_time = kSampleTokenExpiryTime + kExpiryGracePeriod;
  TrialTokenResult result =
      Validate(kExpiryGracePeriodToken, appropriate_origin_, current_time);
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kExpired);
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());
}

TEST_P(TrialTokenValidatorEquivalenceTest,
       ValidateValidExpiryGraceThirdPartyToken) {
  url::Origin third_party_origins[] = {appropriate_origin_};
  // This token is valid one day before the end of the expiry grace period,
  // even though it is past the token's expiry time.
  auto current_time =
      kSampleTokenExpiryTime + kExpiryGracePeriod - base::Days(1);
  TrialTokenResult result =
      Validate(kExpiryGracePeriodThirdPartyToken, appropriate_origin_,
               third_party_origins, current_time);
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kSuccess);
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());
  EXPECT_TRUE(result.ParsedToken()->is_third_party());
}

TEST_P(TrialTokenValidatorEquivalenceTest,
       ValidateExpiredExpiryGraceThirdPartyToken) {
  url::Origin third_party_origins[] = {appropriate_origin_};
  // This token is expired at the end of the expiry grace period.
  auto current_time = kSampleTokenExpiryTime + kExpiryGracePeriod;
  TrialTokenResult result =
      Validate(kExpiryGracePeriodThirdPartyToken, appropriate_origin_,
               third_party_origins, current_time);
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kExpired);
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());
  EXPECT_TRUE(result.ParsedToken()->is_third_party());
}

TEST_P(TrialTokenValidatorEquivalenceTest, ValidateSubdomainToken) {
  TrialTokenResult result =
      Validate(kSubdomainToken, appropriate_origin_, {}, Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kSuccess);
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());
  EXPECT_TRUE(result.ParsedToken()->match_subdomains());
}

TEST_P(TrialTokenValidatorEquivalenceTest,
       ValidateSubdomainTokenUnrelatedOrigin) {
  // A subdomain token should not match against an unrelated origin
  TrialTokenResult result =
      Validate(kSubdomainToken, unrelated_origin_, {}, Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kWrongOrigin);
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());
  EXPECT_TRUE(result.ParsedToken()->match_subdomains());
}

TEST_P(TrialTokenValidatorEquivalenceTest, ValidateThirdPartySubdomainToken) {
  // Subdomain third-party tokens should validate even if the primary origin
  // is unrelated and there are other, insecure, origins as well
  url::Origin script_origins[] = {insecure_origin_, appropriate_origin_};
  TrialTokenResult result = Validate(kThirdPartySubdomainToken,
                                     unrelated_origin_, script_origins, Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kSuccess);
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());
  EXPECT_TRUE(result.ParsedToken()->match_subdomains());
}

TEST_P(TrialTokenValidatorEquivalenceTest,
       ValidateThirdPartySubdomainTokenInsecureOrigin) {
  // Subdomain third-party tokens should not validate against insecure origins
  url::Origin script_origins[] = {insecure_origin_};
  TrialTokenResult result = Validate(kThirdPartySubdomainToken,
                                     unrelated_origin_, script_origins, Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kWrongOrigin);
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());
  EXPECT_TRUE(result.ParsedToken()->match_subdomains());
}

// Tests of RequestEnablesFeature methods

TEST_F(TrialTokenValidatorTest, ValidateRequestInsecure) {
  response_headers_->AddHeader("Origin-Trial", kInsecureOriginToken);
  EXPECT_FALSE(validator_.RequestEnablesFeature(
      GURL(kInsecureOrigin), response_headers_.get(), kAppropriateFeatureName,
      Now()));
}

TEST_F(TrialTokenValidatorTest, ValidateRequestForDeprecationInsecure) {
  response_headers_->AddHeader("Origin-Trial", kDeprecationInsecureToken);
  EXPECT_TRUE(validator_.RequestEnablesDeprecatedFeature(
      GURL(kInsecureOrigin), response_headers_.get(),
      kAppropriateDeprecationFeatureName, Now()));
}

TEST_F(TrialTokenValidatorTest, ValidateRequestValidToken) {
  response_headers_->AddHeader("Origin-Trial", kSampleToken);
  EXPECT_TRUE(validator_.RequestEnablesFeature(GURL(kAppropriateOrigin),
                                               response_headers_.get(),
                                               kAppropriateFeatureName, Now()));
}

TEST_F(TrialTokenValidatorTest, ValidateRequestForDeprecationValidToken) {
  response_headers_->AddHeader("Origin-Trial", kSampleToken);
  EXPECT_TRUE(validator_.RequestEnablesDeprecatedFeature(
      GURL(kAppropriateOrigin), response_headers_.get(),
      kAppropriateFeatureName, Now()));
}

TEST_F(TrialTokenValidatorTest, ValidateRequestNoTokens) {
  EXPECT_FALSE(validator_.RequestEnablesFeature(
      GURL(kAppropriateOrigin), response_headers_.get(),
      kAppropriateFeatureName, Now()));
}

TEST_F(TrialTokenValidatorTest, ValidateRequestForDeprecationNoTokens) {
  EXPECT_FALSE(validator_.RequestEnablesDeprecatedFeature(
      GURL(kAppropriateOrigin), response_headers_.get(),
      kAppropriateFeatureName, Now()));
}

TEST_F(TrialTokenValidatorTest, ValidateRequestMultipleHeaders) {
  response_headers_->AddHeader("Origin-Trial", kSampleToken);
  response_headers_->AddHeader("Origin-Trial", kExpiredToken);
  EXPECT_TRUE(validator_.RequestEnablesFeature(GURL(kAppropriateOrigin),
                                               response_headers_.get(),
                                               kAppropriateFeatureName, Now()));
  EXPECT_FALSE(validator_.RequestEnablesFeature(
      GURL(kAppropriateOrigin), response_headers_.get(),
      kInappropriateFeatureName, Now()));
  EXPECT_FALSE(validator_.RequestEnablesFeature(
      GURL(kInappropriateOrigin), response_headers_.get(),
      kAppropriateFeatureName, Now()));
}

TEST_F(TrialTokenValidatorTest, ValidateRequestMultipleHeaderValues) {
  response_headers_->AddHeader(
      "Origin-Trial", std::string(kExpiredToken) + ", " + kSampleToken);
  EXPECT_TRUE(validator_.RequestEnablesFeature(GURL(kAppropriateOrigin),
                                               response_headers_.get(),
                                               kAppropriateFeatureName, Now()));
  EXPECT_FALSE(validator_.RequestEnablesFeature(
      GURL(kAppropriateOrigin), response_headers_.get(),
      kInappropriateFeatureName, Now()));
  EXPECT_FALSE(validator_.RequestEnablesFeature(
      GURL(kInappropriateOrigin), response_headers_.get(),
      kAppropriateFeatureName, Now()));
}

TEST_F(TrialTokenValidatorTest, ValidateRequestUnknownFeatureToken) {
  response_headers_->AddHeader("Origin-Trial", kUnknownFeatureToken);
  EXPECT_FALSE(validator_.RequestEnablesFeature(
      GURL(kAppropriateOrigin), response_headers_.get(),
      kInappropriateFeatureName, Now()));
}

// Tests where ValidateToken and ValidateTokenAndTrial are expected
// to yield different results.
// These tests should test both |ValidateToken|, |ValidateTokenAndTrial|,
// and |ValidateTokenAndTrialWithOriginInfo| to ensure all entry points
// give the expected results

TEST_F(TrialTokenValidatorTest, ValidateUnknownFeatureToken) {
  // An unknown feature token can be valid, but the trial validation won't be
  TrialTokenResult result = validator_.ValidateToken(
      kUnknownFeatureToken, appropriate_origin_, Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kSuccess);
  EXPECT_EQ(kInappropriateFeatureName, result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());

  result = validator_.ValidateTokenAndTrial(kUnknownFeatureToken,
                                            appropriate_origin_, Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kUnknownTrial);
  EXPECT_EQ(kInappropriateFeatureName, result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());

  result = validator_.ValidateTokenAndTrialWithOriginInfo(
      kUnknownFeatureToken, WithInfo(appropriate_origin_), {}, Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kUnknownTrial);
  EXPECT_EQ(kInappropriateFeatureName, result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());
}

TEST_F(TrialTokenValidatorTest, ValidateUnknownFeatureThirdPartyToken) {
  // An unknown feature token can be valid, but the trial validation won't be
  url::Origin third_party_origins[] = {appropriate_origin_};
  TrialTokenResult result =
      validator_.ValidateToken(kUnknownFeatureThirdPartyToken,
                               appropriate_origin_, third_party_origins, Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kSuccess);
  EXPECT_EQ(kInappropriateFeatureName, result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());
  EXPECT_EQ(true, result.ParsedToken()->is_third_party());

  result = validator_.ValidateTokenAndTrial(kUnknownFeatureThirdPartyToken,
                                            appropriate_origin_,
                                            third_party_origins, Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kUnknownTrial);
  EXPECT_EQ(kInappropriateFeatureName, result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());
  EXPECT_EQ(true, result.ParsedToken()->is_third_party());

  result = validator_.ValidateTokenAndTrialWithOriginInfo(
      kUnknownFeatureThirdPartyToken, WithInfo(appropriate_origin_),
      WithInfo(third_party_origins), Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kUnknownTrial);
  EXPECT_EQ(kInappropriateFeatureName, result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());
  EXPECT_EQ(true, result.ParsedToken()->is_third_party());
}

TEST_F(TrialTokenValidatorTest, ValidateInsecureToken) {
  // An insecure token validates against an insecure origin, but only if the
  // trial allows it
  TrialTokenResult result =
      validator_.ValidateToken(kInsecureOriginToken, insecure_origin_, Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kSuccess);
  EXPECT_EQ(kAppropriateFeatureName, result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());

  result = validator_.ValidateTokenAndTrial(kInsecureOriginToken,
                                            insecure_origin_, Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kInsecure);
  EXPECT_EQ(kAppropriateFeatureName, result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());

  // Ensure the result is the same if we provide our own security information
  result = validator_.ValidateTokenAndTrialWithOriginInfo(
      kInsecureOriginToken, WithInfo(insecure_origin_), {}, Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kInsecure);
  EXPECT_EQ(kAppropriateFeatureName, result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());
}

TEST_F(TrialTokenValidatorTest,
       ValidateThirdPartyTokenForNonThirdPartyFeature) {
  // A third-party token should validate against an appropriate third-party
  // origin, but not if the trial doesn't allow for third-party tokens.
  url::Origin third_party_origins[] = {appropriate_origin_};
  TrialTokenResult result =
      validator_.ValidateToken(kThirdPartyTokenForNonThirdPartyTrial,
                               appropriate_origin_, third_party_origins, Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kSuccess);
  EXPECT_EQ(kAppropriateFeatureName, result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());
  EXPECT_EQ(true, result.ParsedToken()->is_third_party());

  result = validator_.ValidateTokenAndTrial(
      kThirdPartyTokenForNonThirdPartyTrial, appropriate_origin_,
      third_party_origins, Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kFeatureDisabled);
  EXPECT_EQ(kAppropriateFeatureName, result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());
  EXPECT_EQ(true, result.ParsedToken()->is_third_party());

  result = validator_.ValidateTokenAndTrialWithOriginInfo(
      kThirdPartyTokenForNonThirdPartyTrial, WithInfo(appropriate_origin_),
      WithInfo(third_party_origins), Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kFeatureDisabled);
  EXPECT_EQ(kAppropriateFeatureName, result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());
  EXPECT_EQ(true, result.ParsedToken()->is_third_party());
}

TEST_F(TrialTokenValidatorTest, ValidateInsecureThirdPartyToken) {
  // An insecure third-party token is valid against insecure origins,
  // but only if the trial allows insecure tokens.
  url::Origin third_party_origins[] = {insecure_origin_};
  TrialTokenResult result =
      validator_.ValidateToken(kThirdPartyInsecureToken, appropriate_origin_,
                               third_party_origins, Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kSuccess);
  EXPECT_EQ(kAppropriateThirdPartyFeatureName,
            result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());

  result = validator_.ValidateTokenAndTrial(kThirdPartyInsecureToken,
                                            appropriate_origin_,
                                            third_party_origins, Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kInsecure);
  EXPECT_EQ(kAppropriateThirdPartyFeatureName,
            result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());

  result = validator_.ValidateTokenAndTrialWithOriginInfo(
      kThirdPartyInsecureToken, WithInfo(appropriate_origin_),
      WithInfo(third_party_origins), Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kInsecure);
  EXPECT_EQ(kAppropriateThirdPartyFeatureName,
            result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());
}

TEST_F(TrialTokenValidatorTest, ValidateInsecureThirdPartyTokenInsecureOrigin) {
  // A third-party token should validate against an insecure primary origin
  // and a secure third-party origin, but only if the trial allows
  // for insecure origins in general
  url::Origin third_party_origins[] = {inappropriate_origin_,
                                       appropriate_origin_};
  TrialTokenResult result = validator_.ValidateToken(
      kThirdPartyToken, insecure_origin_, third_party_origins, Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kSuccess);
  EXPECT_EQ(kAppropriateThirdPartyFeatureName,
            result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());

  result = validator_.ValidateTokenAndTrial(kThirdPartyToken, insecure_origin_,
                                            third_party_origins, Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kInsecure);
  EXPECT_EQ(kAppropriateThirdPartyFeatureName,
            result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());

  result = validator_.ValidateTokenAndTrialWithOriginInfo(
      kThirdPartyToken, WithInfo(insecure_origin_),
      WithInfo(third_party_origins), Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kInsecure);
  EXPECT_EQ(kAppropriateThirdPartyFeatureName,
            result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());
}

TEST_F(TrialTokenValidatorTest,
       ValidateInsecureThirdPartyTokenMultipleOrigins) {
  // An insecure third-party token is valid against insecure origins,
  // but only if the trial allows insecure tokens. And other, unrelated but
  // secure third-party origins should not change this-.
  url::Origin third_party_origins[] = {insecure_origin_, inappropriate_origin_};
  TrialTokenResult result =
      validator_.ValidateToken(kThirdPartyInsecureToken, appropriate_origin_,
                               third_party_origins, Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kSuccess);
  EXPECT_EQ(kAppropriateThirdPartyFeatureName,
            result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());

  result = validator_.ValidateTokenAndTrial(kThirdPartyInsecureToken,
                                            appropriate_origin_,
                                            third_party_origins, Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kInsecure);
  EXPECT_EQ(kAppropriateThirdPartyFeatureName,
            result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());

  result = validator_.ValidateTokenAndTrialWithOriginInfo(
      kThirdPartyInsecureToken, WithInfo(appropriate_origin_),
      WithInfo(third_party_origins), Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kInsecure);
  EXPECT_EQ(kAppropriateThirdPartyFeatureName,
            result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());
}

TEST_F(TrialTokenValidatorTest, ValidateThirdPartyTokenInsecureOrigin) {
  // An insecure third-party subdomain token is valid against an insecure
  // third-party subdomain, but not if the trial doesn't allow insecure origins.
  url::Origin third_party_origins[] = {unrelated_origin_, insecure_origin_};
  TrialTokenResult result =
      validator_.ValidateToken(kThirdPartyInsecureSubdomainToken,
                               appropriate_origin_, third_party_origins, Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kSuccess);
  EXPECT_EQ(kAppropriateThirdPartyFeatureName,
            result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());

  result = validator_.ValidateTokenAndTrial(kThirdPartyInsecureSubdomainToken,
                                            appropriate_origin_,
                                            third_party_origins, Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kInsecure);
  EXPECT_EQ(kAppropriateThirdPartyFeatureName,
            result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());

  result = validator_.ValidateTokenAndTrialWithOriginInfo(
      kThirdPartyInsecureSubdomainToken, WithInfo(appropriate_origin_),
      WithInfo(third_party_origins), Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kInsecure);
  EXPECT_EQ(kAppropriateThirdPartyFeatureName,
            result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());
}

// Tests that only check the behaviour of
// |ValidateTokenAndTrialWithOriginInfo| - these are the ones
// that rely on changes in passing in specific OriginInfo

TEST_F(TrialTokenValidatorTest, ValidateInsecureOriginInfo) {
  TrialTokenValidator::OriginInfo insecure_origin_info(appropriate_origin_,
                                                       false);
  TrialTokenResult result = validator_.ValidateTokenAndTrialWithOriginInfo(
      kSampleToken, insecure_origin_info, {}, Now());
  EXPECT_EQ(blink::OriginTrialTokenStatus::kInsecure, result.Status());
  EXPECT_EQ(kAppropriateFeatureName, result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());
  EXPECT_EQ(false, result.ParsedToken()->is_third_party());
}

TEST_F(TrialTokenValidatorTest, ValidateInsecureOriginThirdPartyOriginInfo) {
  // Third-party tokens should not be secure if the primary origin is insecure
  TrialTokenValidator::OriginInfo insecure_origin_info(appropriate_origin_,
                                                       false);
  url::Origin third_party_origins[] = {appropriate_origin_};
  TrialTokenResult result = validator_.ValidateTokenAndTrialWithOriginInfo(
      kThirdPartyToken, insecure_origin_info, WithInfo(third_party_origins),
      Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kInsecure);
  EXPECT_EQ(kAppropriateThirdPartyFeatureName,
            result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());
}

TEST_F(TrialTokenValidatorTest,
       ValidateInsecureThirdPartyOriginThirdPartyOriginInfo) {
  // Third-party tokens should not be secure if the third-party origin is
  // insecure
  TrialTokenValidator::OriginInfo insecure_origin_info(appropriate_origin_,
                                                       false);
  TrialTokenValidator::OriginInfo insecure_third_parties[] = {
      insecure_origin_info};
  TrialTokenResult result = validator_.ValidateTokenAndTrialWithOriginInfo(
      kThirdPartyToken, WithInfo(appropriate_origin_), insecure_third_parties,
      Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kInsecure);
  EXPECT_EQ(kAppropriateThirdPartyFeatureName,
            result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());
}

TEST_F(TrialTokenValidatorTest,
       ValidateMultipleInsecureThirdPartyOriginThirdPartyOriginInfo) {
  // Third-party tokens should not be secure if the third-party origin is
  // insecure, even if there are other, secure, third-party origins
  TrialTokenValidator::OriginInfo insecure_origin_info(appropriate_origin_,
                                                       false);

  TrialTokenValidator::OriginInfo third_party_origins[] = {
      WithInfo(inappropriate_origin_),  // Secure, but not appropriate
      insecure_origin_info};
  TrialTokenResult result = validator_.ValidateTokenAndTrialWithOriginInfo(
      kThirdPartyToken, WithInfo(appropriate_origin_), third_party_origins,
      Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kInsecure);
  EXPECT_EQ(kAppropriateThirdPartyFeatureName,
            result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());
}

//
// Tests of |RevalidateTokenAndTrial|
//
TEST_F(TrialTokenValidatorTest, RevalidateTokenInformation) {
  EXPECT_TRUE(validator_.RevalidateTokenAndTrial(
      kAppropriateFeatureName, kSampleTokenExpiryTime,
      blink::TrialToken::UsageRestriction::kNone, valid_token_signature_,
      Now()));
}

TEST_F(TrialTokenValidatorTest, RevalidateExpiredToken) {
  // Check basic expiration. The expiry must be > the current time
  base::Time expiry = Now();

  EXPECT_FALSE(validator_.RevalidateTokenAndTrial(
      kAppropriateFeatureName, expiry,
      blink::TrialToken::UsageRestriction::kNone, valid_token_signature_,
      Now()));

  // Check grace period expiration
  EXPECT_TRUE(validator_.RevalidateTokenAndTrial(
      kAppropriateGracePeriodFeatureName, expiry,
      blink::TrialToken::UsageRestriction::kNone, valid_token_signature_,
      Now()));

  // Check the boundary of the grace period.
  expiry = Now() - kExpiryGracePeriod;
  EXPECT_FALSE(validator_.RevalidateTokenAndTrial(
      kAppropriateGracePeriodFeatureName, expiry,
      blink::TrialToken::UsageRestriction::kNone, valid_token_signature_,
      Now()));
}

TEST_F(TrialTokenValidatorTest, RevalidateDisabledTrial) {
  policy_.DisableFeature(kAppropriateFeatureName);
  EXPECT_FALSE(validator_.RevalidateTokenAndTrial(
      kAppropriateFeatureName, kSampleTokenExpiryTime,
      blink::TrialToken::UsageRestriction::kNone, valid_token_signature_,
      Now()));
}

TEST_F(TrialTokenValidatorTest, RevalidateDisabledToken) {
  policy_.DisableToken(valid_token_signature_);
  EXPECT_FALSE(validator_.RevalidateTokenAndTrial(
      kAppropriateFeatureName, kSampleTokenExpiryTime,
      blink::TrialToken::UsageRestriction::kNone, valid_token_signature_,
      Now()));
}

TEST_F(TrialTokenValidatorTest, RevalidateDisabledTrialForUser) {
  policy_.DisableFeatureForUser(kAppropriateThirdPartyFeatureName);
  // Per-user disabled trials should only be disabled if the token is marked as
  // kSubset
  EXPECT_TRUE(validator_.RevalidateTokenAndTrial(
      kAppropriateThirdPartyFeatureName, kSampleTokenExpiryTime,
      blink::TrialToken::UsageRestriction::kNone, valid_token_signature_,
      Now()));

  EXPECT_FALSE(validator_.RevalidateTokenAndTrial(
      kAppropriateThirdPartyFeatureName, kSampleTokenExpiryTime,
      blink::TrialToken::UsageRestriction::kSubset, valid_token_signature_,
      Now()));
}

TEST_F(TrialTokenValidatorTest, XRWTrialAllowedForAll3POrigins) {
  // Specific test for WebViewXRequestedWithDeprecation origin trial, which
  // omits origin checks for third-party tokens.
  // Can be removed when the origin trial is removed from
  // |runtime_enabled_features.json5|.

  // Generated with
  // tools/origin_trials/generate_token.py thirdparty.com
  // WebViewXRequestedWithDeprecation --expire-timestamp=2000000000
  const char kXRW1PToken[] =
      "Ay6L+HCN2v3sAGUg/"
      "UUqhAD5OR2rE+FzVlQpAVBbSUrzDvx3Uz76a84EpeLiOyMpy6NGNH5z4KrC+"
      "CEnhCGLOgIAAABteyJvcmlnaW4iOiAiaHR0cHM6Ly90aGlyZHBhcnR5LmNvbTo0NDMiLCAiZ"
      "mVhdHVyZSI6ICJXZWJWaWV3WFJlcXVlc3RlZFdpdGhEZXByZWNhdGlvbiIsICJleHBpcnkiO"
      "iAyMDAwMDAwMDAwfQ==";

  // Generated with
  // tools/origin_trials/generate_token.py thirdparty.com
  // WebViewXRequestedWithDeprecation --expire-timestamp=2000000000
  // --is-third-party
  const char kXRW3PToken[] =
      "AwINH5I2lshWrnPvEqz1KRya3QU2Zx5djBDcr7Q5CnnccjUgNtWaAecPL26JnZlvye3WgAz6"
      "/MZDIRfewUNHOg4AAACDeyJvcmlnaW4iOiAiaHR0cHM6Ly90aGlyZHBhcnR5LmNvbTo0NDMi"
      "LCAiZmVhdHVyZSI6ICJXZWJWaWV3WFJlcXVlc3RlZFdpdGhEZXByZWNhdGlvbiIsICJleHBp"
      "cnkiOiAyMDAwMDAwMDAwLCAiaXNUaGlyZFBhcnR5IjogdHJ1ZX0=";

  // Note that the tokens are for thirdparty.com, which is different from both
  // `appropriate_origin_` (valid.example.com) and `inappropriate_origin_`
  // (invalid.example.com)
  url::Origin scriptOrigins[] = {appropriate_origin_};

  // First party tokens should match the origin, so we expect a non-success
  // result.
  TrialTokenResult firstPartyResult = validator_.ValidateTokenAndTrial(
      kXRW1PToken, inappropriate_origin_, scriptOrigins, Now());
  EXPECT_EQ(blink::OriginTrialTokenStatus::kWrongOrigin,
            firstPartyResult.Status());

  // For this trial only, we have disabled the origin check on third-party
  // tokens. See |trial_token.cc|.
  TrialTokenResult thirdPartyResult = validator_.ValidateTokenAndTrial(
      kXRW3PToken, inappropriate_origin_, scriptOrigins, Now());
  EXPECT_EQ(blink::OriginTrialTokenStatus::kSuccess, thirdPartyResult.Status());
}

}  // namespace blink::trial_token_validator_unittest

"""

```