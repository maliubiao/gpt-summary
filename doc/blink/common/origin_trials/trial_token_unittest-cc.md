Response:
My thinking process to address the user's request about the `trial_token_unittest.cc` file goes like this:

1. **Understand the Core Request:** The user wants to know the functionality of this specific C++ file within the Chromium Blink engine. They are also interested in its relation to web technologies (JavaScript, HTML, CSS), logical reasoning examples (input/output), common usage errors, and a summary of its functionality (as part 1 of 2).

2. **Analyze the File Path and Name:**  `blink/common/origin_trials/trial_token_unittest.cc` strongly suggests this is a unit test file for code related to "origin trials" and specifically "trial tokens". The `_unittest.cc` suffix is a standard convention for unit tests in Chromium.

3. **Scan the Includes:** The included headers provide immediate clues about the file's purpose:
    * `third_party/blink/public/common/origin_trials/trial_token.h`: This is the main header for the `TrialToken` class, indicating this file tests that class.
    * `<memory>`:  Likely involves dynamic memory allocation, potentially for `std::unique_ptr` used with `TrialToken`.
    * `base/strings/string_util.h`: Indicates string manipulation, probably involved in parsing or comparing token data.
    * `base/test/simple_test_clock.h`:  Suggests the tests will involve manipulating time, likely to test token expiry.
    * `base/time/time.h`:  Confirms time-related operations.
    * `testing/gtest/include/gtest/gtest.h`: This is the Google Test framework, confirming this is a unit test file.
    * `url/gurl.h`:  Indicates the file deals with URLs, which are central to origin trials.

4. **Examine Key Constants and Variables:** The file defines several constants that are crucial for understanding its function:
    * `kVersion2`, `kVersion3`:  Indicate support for different versions of trial tokens.
    * `kTestPublicKey`, `kTestPublicKey2`: These are public keys used for signature verification in origin trials. The comments explain their purpose and how to generate corresponding private keys.
    * `kSampleTokenV2`, `kSampleTokenV3`, `kSampleSubdomainToken`, etc.: These are base64-encoded examples of valid and invalid trial tokens with different properties (version, subdomain, third-party, usage restrictions). The corresponding signature byte arrays are also present.
    * `kExpectedFeatureName`, `kExpectedOrigin`, `kExpectedExpiry`, etc.: These are the expected values extracted from the valid sample tokens, used for comparison in the tests.
    * `kInvalidOrigin`, `kInvalidFeatureName`, etc.: These represent inputs that should lead to invalid token verification.
    * `kValidTimestamp`, `kInvalidTimestamp`: These timestamps are used to test token expiry logic.
    * `kInvalidSignatureToken`, `kTruncatedToken`, `kIncorrectLengthToken`, `kIncorrectVersionToken`: Examples of malformed tokens used to test parsing and validation failures.
    * `kSampleTokenJSON`, `kSampleNonSubdomainTokenJSON`, etc.: JSON representations of the sample tokens, showing the structure of the token payload.
    * `kInvalidTokens`, `kInvalidTokensVersion3`: Arrays of invalid JSON payloads used for testing parsing failures.
    * `kLargeTokenJSON`, `kTooLargeTokenJSON`, `kLargeValidToken`: Examples of tokens with large sizes, used to test handling of larger data.

5. **Infer Functionality from the Data:**  Based on the constants and includes, it's clear that `trial_token_unittest.cc` tests the following core functionalities of the `TrialToken` class:
    * **Token Parsing:**  The tests parse base64-encoded strings into `TrialToken` objects.
    * **Signature Verification:** The tests verify the cryptographic signature of the tokens using a provided public key.
    * **Data Extraction:**  The tests extract information from the token, such as origin, feature name, expiry date, and flags (isSubdomain, isThirdParty, usage).
    * **Token Validation:** The tests validate token properties against expected values, including checking for correct origins, feature names, expiry dates, and subdomain/third-party status.
    * **Expiry Time Handling:** The tests check if a token is valid at a given time.
    * **Handling of Invalid Tokens:** The tests verify that invalid tokens (bad signatures, incorrect formatting, invalid JSON, etc.) are correctly identified as invalid.
    * **Handling of Different Token Versions:** The tests cover different versions of the token format.
    * **Handling of Usage Restrictions:** The tests verify the `usage` field (subset/empty).
    * **Handling of Large Tokens:** The tests check the ability to parse and validate tokens with large origins and feature names, including cases exceeding certain size limits.

6. **Relate to Web Technologies (JavaScript, HTML, CSS):** Origin Trials are a mechanism that directly impacts web developers. While this C++ file doesn't *directly* execute JavaScript, HTML, or CSS, it underpins the functionality that *enables* origin trials to work in those environments.
    * **JavaScript:**  JavaScript code running on a website will interact with the Origin Trials API (though not directly tested here). The browser, using code like the `TrialToken` class being tested, will validate tokens provided in HTTP headers or `<meta>` tags and enable/disable features accordingly. *Example:* A JavaScript feature protected by an origin trial will only be available if a valid token is present for the current origin.
    * **HTML:**  Origin trial tokens can be delivered via `<meta>` tags in the HTML. The parsing logic in the `TrialToken` class is responsible for processing these tokens. *Example:*  `<meta http-equiv="Origin-Trial" content="...">` includes the token string that this C++ code helps validate.
    * **CSS:**  New CSS features can be gated by origin trials. If a valid token for a CSS feature is present, the browser will enable that CSS functionality. *Example:* A new CSS property might only be recognized and applied if the corresponding origin trial token is valid.

7. **Construct Logical Reasoning Examples (Input/Output):**  Based on the test cases, I can create input/output examples.

8. **Identify Common Usage Errors:**  By examining the tests for invalid tokens, I can deduce common developer errors.

9. **Summarize Functionality:** Finally, I can synthesize the information gathered into a concise summary.

By following these steps, I can comprehensively address the user's request and provide a detailed explanation of the `trial_token_unittest.cc` file's functionality and its relation to web technologies.
这是对 `blink/common/origin_trials/trial_token_unittest.cc` 文件功能的归纳总结，基于您提供的第一部分代码：

**功能归纳:**

`trial_token_unittest.cc` 是 Chromium Blink 引擎中的一个单元测试文件，专门用于测试 `blink::TrialToken` 类的功能。该类负责处理和验证 Origin Trials 的 Token。  这个测试文件通过一系列测试用例，验证了以下核心功能：

1. **Token 的解析 (Parsing):**
   - 能够正确解析 Base64 编码的 Origin Trial Token 字符串。
   - 能够处理不同版本的 Token 格式 (如 Version 2 和 Version 3)。
   - 能够解析包含不同属性的 Token，例如是否是子域名 Token、是否是第三方 Token、以及使用限制 (usage restriction)。
   - 能够处理 Token 中 JSON 格式的元数据，提取 origin, feature, expiry 等信息。
   - 能够正确处理各种格式错误的 Token 字符串，并判断其无效。

2. **Token 的验证 (Validation):**
   - 能够使用公钥验证 Token 的签名，确保 Token 的真实性和完整性。
   - 能够判断 Token 的有效期，根据当前时间戳判断 Token 是否过期。
   - 能够根据 Token 中包含的 origin 信息，判断 Token 是否适用于特定的域名。
   - 能够根据 Token 中包含的 feature 信息，判断 Token 是否适用于特定的功能。
   - 能够根据 Token 中 `isSubdomain` 和 `isThirdParty` 字段，判断 Token 是否应用于子域名或第三方上下文。
   - 能够根据 Token 中的 `usage` 字段，判断 Token 的使用限制。

3. **处理不同类型的 Token:**
   - 测试了域名级别的 Token (包括精确匹配和子域名匹配)。
   - 测试了第三方 Token 和非第三方 Token。
   - 测试了带有使用限制的 Token (subset 和 empty)。

4. **处理边界情况和错误情况:**
   - 测试了各种格式错误的 Token 字符串，例如：
     - 无效的 Base64 编码
     - JSON 格式错误
     - 缺少必要的字段
     - 字段类型错误
     - 过期的 Token
     - 签名无效的 Token
     - 长度不正确的 Token
     - 版本号错误的 Token
   - 测试了超长的 feature name 和 origin。
   - 测试了超过 4KB 的 Token。

**与 JavaScript, HTML, CSS 的关系举例说明:**

Origin Trials 是一种允许开发者在正式标准发布之前，在生产环境中测试实验性 Web 平台特性的机制。`TrialToken` 类负责在浏览器内部验证这些特性是否被允许在当前页面中使用。

* **JavaScript:**  当 JavaScript 代码尝试使用一个由 Origin Trial 保护的 API 时，浏览器会检查是否存在有效的 Token。`TrialToken` 类的验证逻辑决定了该 API 是否可以被 JavaScript 调用。
    * **假设输入:** JavaScript 代码尝试调用一个受名为 "SuperFeature" 的 Origin Trial 保护的 API。
    * **输出:** 如果当前页面的 HTTP 头部或 `<meta>` 标签中存在一个有效的、针对当前 origin 和 "SuperFeature" 的 Token，则该 API 调用成功。否则，API 调用失败或行为受限。

* **HTML:** Origin Trial Token 可以通过 `<meta>` 标签添加到 HTML 文档中。浏览器解析 HTML 时，会提取这些 Token 并使用 `TrialToken` 类进行验证。
    * **假设输入:**  HTML 文件包含 `<meta http-equiv="Origin-Trial" content="[有效的Token字符串]">`。
    * **输出:** `TrialToken` 类解析并验证该 Token。如果 Token 有效，则浏览器可能会启用该 Token 对应的实验性特性。

* **CSS:**  一些新的 CSS 特性也可能通过 Origin Trial 进行控制。浏览器会检查是否存在允许使用该 CSS 特性的有效 Token。
    * **假设输入:**  CSS 样式表中使用了某个实验性的 CSS 属性，例如 `-webkit-experimental-property: value;`。
    * **输出:** 只有当存在有效的、允许当前 origin 使用该实验性特性的 Origin Trial Token 时，浏览器才会解析并应用该 CSS 属性。

**逻辑推理的假设输入与输出:**

* **假设输入:**  一个有效的 Version 2 的 Token 字符串 `kSampleTokenV2` 和一个正确的公钥 `kTestPublicKey`。
* **输出:**  `TrialToken::Parse()` 方法成功解析 Token，并且 `IsValid()` 方法返回 `true`。`GetFeatureName()` 返回 "Frobulate"，`GetOrigin()` 返回 "https://valid.example.com"，`GetExpiryTime()` 返回 1458766277。

* **假设输入:**  一个有效的 Token 字符串，但当前时间戳 `kInvalidTimestamp` 大于 Token 的过期时间。
* **输出:** `IsValid()` 方法返回 `false`。

* **假设输入:**  一个有效的 Token 字符串，但当前页面的 Origin 是 `kInvalidOrigin` ("https://invalid.example.com")。
* **输出:** `IsValid()` 方法返回 `false`。

**涉及用户或编程常见的使用错误举例说明:**

* **错误地复制粘贴 Token 字符串:**  用户在配置 Origin Trial 时，可能会因为复制粘贴错误导致 Token 字符串不完整或包含额外的字符，导致 `TrialToken::Parse()` 解析失败。
    * **例子:**  复制 Token 时漏掉结尾的几个字符。

* **使用错误的公钥验证 Token:** 开发者可能使用了与生成 Token 时不同的私钥对应的公钥进行验证，导致签名验证失败，即使 Token 本身是有效的。
    * **例子:**  使用 `kTestPublicKey2` 尝试验证用与 `kTestPublicKey` 配对的私钥生成的 Token。

* **Token 过期:**  开发者可能忘记更新 Token，导致 Token 过期，使得实验性特性失效。
    * **例子:**  使用在 `kInvalidTimestamp` 之后生成的 Token。

* **Origin 不匹配:** 开发者可能在错误的域名下使用了特定域名的 Token，导致 Token 验证失败。
    * **例子:**  在 `https://invalid.example.com` 页面上使用为 `https://valid.example.com` 生成的 Token。

* **Feature Name 不匹配:**  开发者可能尝试使用一个 Token 来启用与 Token 中声明的 Feature Name 不同的特性。
    * **例子:**  使用 feature 为 "Frobulate" 的 Token 来尝试启用名为 "Grokalyze" 的特性。

**总结:**

`trial_token_unittest.cc` 的主要功能是全面测试 `blink::TrialToken` 类在解析、验证和处理 Origin Trial Token 方面的各种能力，确保该类能够正确可靠地工作，从而保证了 Chromium 浏览器对 Origin Trials 功能的正确支持。 这对于 Web 开发者测试和使用实验性 Web 平台特性至关重要。

### 提示词
```
这是目录为blink/common/origin_trials/trial_token_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/public/common/origin_trials/trial_token.h"

#include <memory>

#include "base/strings/string_util.h"
#include "base/test/simple_test_clock.h"
#include "base/time/time.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"

namespace blink {

namespace {

const uint8_t kVersion2 = 2;
const uint8_t kVersion3 = 3;

// This is a sample public key for testing the API. The corresponding private
// key (use this to generate new samples for this test file) is:
//
//  0x83, 0x67, 0xf4, 0xcd, 0x2a, 0x1f, 0x0e, 0x04, 0x0d, 0x43, 0x13,
//  0x4c, 0x67, 0xc4, 0xf4, 0x28, 0xc9, 0x90, 0x15, 0x02, 0xe2, 0xba,
//  0xfd, 0xbb, 0xfa, 0xbc, 0x92, 0x76, 0x8a, 0x2c, 0x4b, 0xc7, 0x75,
//  0x10, 0xac, 0xf9, 0x3a, 0x1c, 0xb8, 0xa9, 0x28, 0x70, 0xd2, 0x9a,
//  0xd0, 0x0b, 0x59, 0xe1, 0xac, 0x2b, 0xb7, 0xd5, 0xca, 0x1f, 0x64,
//  0x90, 0x08, 0x8e, 0xa8, 0xe0, 0x56, 0x3a, 0x04, 0xd0
//
//  This private key can also be found in tools/origin_trials/eftest.key in
//  binary form. Please update that if changing the key.
//
//  To use this with a real browser, use --origin-trial-public-key with the
//  public key, base-64-encoded:
//  --origin-trial-public-key=dRCs+TocuKkocNKa0AtZ4awrt9XKH2SQCI6o4FY6BNA=
const OriginTrialPublicKey kTestPublicKey = {
    0x75, 0x10, 0xac, 0xf9, 0x3a, 0x1c, 0xb8, 0xa9, 0x28, 0x70, 0xd2,
    0x9a, 0xd0, 0x0b, 0x59, 0xe1, 0xac, 0x2b, 0xb7, 0xd5, 0xca, 0x1f,
    0x64, 0x90, 0x08, 0x8e, 0xa8, 0xe0, 0x56, 0x3a, 0x04, 0xd0,
};

// This is a valid, but incorrect, public key for testing signatures against.
// The corresponding private key is:
//
//  0x21, 0xee, 0xfa, 0x81, 0x6a, 0xff, 0xdf, 0xb8, 0xc1, 0xdd, 0x75,
//  0x05, 0x04, 0x29, 0x68, 0x67, 0x60, 0x85, 0x91, 0xd0, 0x50, 0x16,
//  0x0a, 0xcf, 0xa2, 0x37, 0xa3, 0x2e, 0x11, 0x7a, 0x17, 0x96, 0x50,
//  0x07, 0x4d, 0x76, 0x55, 0x56, 0x42, 0x17, 0x2d, 0x8a, 0x9c, 0x47,
//  0x96, 0x25, 0xda, 0x70, 0xaa, 0xb9, 0xfd, 0x53, 0x5d, 0x51, 0x3e,
//  0x16, 0xab, 0xb4, 0x86, 0xea, 0xf3, 0x35, 0xc6, 0xca
const OriginTrialPublicKey kTestPublicKey2 = {
    0x50, 0x07, 0x4d, 0x76, 0x55, 0x56, 0x42, 0x17, 0x2d, 0x8a, 0x9c,
    0x47, 0x96, 0x25, 0xda, 0x70, 0xaa, 0xb9, 0xfd, 0x53, 0x5d, 0x51,
    0x3e, 0x16, 0xab, 0xb4, 0x86, 0xea, 0xf3, 0x35, 0xc6, 0xca,
};

// This is a good trial token, signed with the above test private key.
// Generate this token with the command (in tools/origin_trials):
// generate_token.py valid.example.com 2 Frobulate --expire-timestamp=1458766277
const char kSampleTokenV2[] =
    "Ap+Q/Qm0ELadZql+dlEGSwnAVsFZKgCEtUZg8idQC3uekkIeSZIY1tftoYdrwhqj"
    "7FO5L22sNvkZZnacLvmfNwsAAABZeyJvcmlnaW4iOiAiaHR0cHM6Ly92YWxpZC5l"
    "eGFtcGxlLmNvbTo0NDMiLCAiZmVhdHVyZSI6ICJGcm9idWxhdGUiLCAiZXhwaXJ5"
    "IjogMTQ1ODc2NjI3N30=";
const uint8_t kSampleTokenV2Signature[] = {
    0x9f, 0x90, 0xfd, 0x09, 0xb4, 0x10, 0xb6, 0x9d, 0x66, 0xa9, 0x7e,
    0x76, 0x51, 0x06, 0x4b, 0x09, 0xc0, 0x56, 0xc1, 0x59, 0x2a, 0x00,
    0x84, 0xb5, 0x46, 0x60, 0xf2, 0x27, 0x50, 0x0b, 0x7b, 0x9e, 0x92,
    0x42, 0x1e, 0x49, 0x92, 0x18, 0xd6, 0xd7, 0xed, 0xa1, 0x87, 0x6b,
    0xc2, 0x1a, 0xa3, 0xec, 0x53, 0xb9, 0x2f, 0x6d, 0xac, 0x36, 0xf9,
    0x19, 0x66, 0x76, 0x9c, 0x2e, 0xf9, 0x9f, 0x37, 0x0b};

// This is a good trial token, signed with the above test private key.
// Generate this token with the command (in tools/origin_trials):
// generate_token.py valid.example.com 3 Frobulate --expire-timestamp=1458766277
const char kSampleTokenV3[] =
    "A79AvyC9SLsjuRTUsjIeGmEfw8Ow0pZSoFtHs8qtrAhUKSNbluCYo86D4M3F6bco"
    "F2BOyjyI7mEWztV+HQvxUAsAAABZeyJvcmlnaW4iOiAiaHR0cHM6Ly92YWxpZC5l"
    "eGFtcGxlLmNvbTo0NDMiLCAiZmVhdHVyZSI6ICJGcm9idWxhdGUiLCAiZXhwaXJ5"
    "IjogMTQ1ODc2NjI3N30=";
const uint8_t kSampleTokenV3Signature[] = {
    0xbf, 0x40, 0xbf, 0x20, 0xbd, 0x48, 0xbb, 0x23, 0xb9, 0x14, 0xd4,
    0xb2, 0x32, 0x1e, 0x1a, 0x61, 0x1f, 0xc3, 0xc3, 0xb0, 0xd2, 0x96,
    0x52, 0xa0, 0x5b, 0x47, 0xb3, 0xca, 0xad, 0xac, 0x08, 0x54, 0x29,
    0x23, 0x5b, 0x96, 0xe0, 0x98, 0xa3, 0xce, 0x83, 0xe0, 0xcd, 0xc5,
    0xe9, 0xb7, 0x28, 0x17, 0x60, 0x4e, 0xca, 0x3c, 0x88, 0xee, 0x61,
    0x16, 0xce, 0xd5, 0x7e, 0x1d, 0x0b, 0xf1, 0x50, 0x0b};

// This is a good subdomain trial token, signed with the above test private key.
// Generate this token with the command (in tools/origin_trials):
// generate_token.py 2 example.com Frobulate --is-subdomain
//   --expire-timestamp=1458766277
const char kSampleSubdomainToken[] =
    "Auu+j9nXAQoy5+t00MiWakZwFExcdNC8ENkRdK1gL4OMFHS0AbZCscslDTcP1fjN"
    "FjpbmQG+VCPk1NrldVXZng4AAABoeyJvcmlnaW4iOiAiaHR0cHM6Ly9leGFtcGxl"
    "LmNvbTo0NDMiLCAiaXNTdWJkb21haW4iOiB0cnVlLCAiZmVhdHVyZSI6ICJGcm9i"
    "dWxhdGUiLCAiZXhwaXJ5IjogMTQ1ODc2NjI3N30=";
const uint8_t kSampleSubdomainTokenSignature[] = {
    0xeb, 0xbe, 0x8f, 0xd9, 0xd7, 0x01, 0x0a, 0x32, 0xe7, 0xeb, 0x74,
    0xd0, 0xc8, 0x96, 0x6a, 0x46, 0x70, 0x14, 0x4c, 0x5c, 0x74, 0xd0,
    0xbc, 0x10, 0xd9, 0x11, 0x74, 0xad, 0x60, 0x2f, 0x83, 0x8c, 0x14,
    0x74, 0xb4, 0x01, 0xb6, 0x42, 0xb1, 0xcb, 0x25, 0x0d, 0x37, 0x0f,
    0xd5, 0xf8, 0xcd, 0x16, 0x3a, 0x5b, 0x99, 0x01, 0xbe, 0x54, 0x23,
    0xe4, 0xd4, 0xda, 0xe5, 0x75, 0x55, 0xd9, 0x9e, 0x0e};

// This is a good trial token, explicitly not a subdomain, signed with the above
// test private key. Generate this token with the command:
// generate_token.py 2 valid.example.com Frobulate --no-subdomain
//   --expire-timestamp=1458766277
const char kSampleNonSubdomainToken[] =
    "AreD979D7tO0luSZTr1+/+J6E0SSj/GEUyLK41o1hXFzXw1R7Z1hCDHs0gXWVSu1"
    "lvH52Winvy39tHbsU2gJJQYAAABveyJvcmlnaW4iOiAiaHR0cHM6Ly92YWxpZC5l"
    "eGFtcGxlLmNvbTo0NDMiLCAiaXNTdWJkb21haW4iOiBmYWxzZSwgImZlYXR1cmUi"
    "OiAiRnJvYnVsYXRlIiwgImV4cGlyeSI6IDE0NTg3NjYyNzd9";
const uint8_t kSampleNonSubdomainTokenSignature[] = {
    0xb7, 0x83, 0xf7, 0xbf, 0x43, 0xee, 0xd3, 0xb4, 0x96, 0xe4, 0x99,
    0x4e, 0xbd, 0x7e, 0xff, 0xe2, 0x7a, 0x13, 0x44, 0x92, 0x8f, 0xf1,
    0x84, 0x53, 0x22, 0xca, 0xe3, 0x5a, 0x35, 0x85, 0x71, 0x73, 0x5f,
    0x0d, 0x51, 0xed, 0x9d, 0x61, 0x08, 0x31, 0xec, 0xd2, 0x05, 0xd6,
    0x55, 0x2b, 0xb5, 0x96, 0xf1, 0xf9, 0xd9, 0x68, 0xa7, 0xbf, 0x2d,
    0xfd, 0xb4, 0x76, 0xec, 0x53, 0x68, 0x09, 0x25, 0x06};

// This is a good third party trial token, signed with the above test private
// key. Generate this token with the command (in tools/origin_trials):
// generate_token.py 3 example.com Frobulate --is-third-party
//   --expire-timestamp=1458766277
const char kSampleThirdPartyToken[] =
    "A9+2NjaYsaFkwtULzbWjcsSJiXD0LuoOgma9fET8hq1uEqVcNyqjGH4ExpF7mYUk"
    "ireYovWqOwsZEyiX6eodfw4AAABveyJvcmlnaW4iOiAiaHR0cHM6Ly92YWxpZC5l"
    "eGFtcGxlLmNvbTo0NDMiLCAiaXNUaGlyZFBhcnR5IjogdHJ1ZSwgImZlYXR1cmUi"
    "OiAiRnJvYnVsYXRlIiwgImV4cGlyeSI6IDE0NTg3NjYyNzd9";
const uint8_t kSampleThirdPartyTokenSignature[] = {
    0xdf, 0xb6, 0x36, 0x36, 0x98, 0xb1, 0xa1, 0x64, 0xc2, 0xd5, 0x0b,
    0xcd, 0xb5, 0xa3, 0x72, 0xc4, 0x89, 0x89, 0x70, 0xf4, 0x2e, 0xea,
    0x0e, 0x82, 0x66, 0xbd, 0x7c, 0x44, 0xfc, 0x86, 0xad, 0x6e, 0x12,
    0xa5, 0x5c, 0x37, 0x2a, 0xa3, 0x18, 0x7e, 0x04, 0xc6, 0x91, 0x7b,
    0x99, 0x85, 0x24, 0x8a, 0xb7, 0x98, 0xa2, 0xf5, 0xaa, 0x3b, 0x0b,
    0x19, 0x13, 0x28, 0x97, 0xe9, 0xea, 0x1d, 0x7f, 0x0e};

// This is a good trial token, explicitly not a third party, signed with the
// above test private key. Generate this token with the command:
// generate_token.py 3 valid.example.com Frobulate --no-third-party
//   --expire-timestamp=1458766277
const char kSampleNonThirdPartyToken[] =
    "Ay0uBIEXlhMfvS43Z+m8bgeqnnZq27xV4OG13d+bkyGuCKx6Wa+hSkLkk6OStg+D"
    "l8pRdqUG19BhWnizn5TbKAMAAABweyJvcmlnaW4iOiAiaHR0cHM6Ly92YWxpZC5l"
    "eGFtcGxlLmNvbTo0NDMiLCAiaXNUaGlyZFBhcnR5IjogZmFsc2UsICJmZWF0dXJl"
    "IjogIkZyb2J1bGF0ZSIsICJleHBpcnkiOiAxNDU4NzY2Mjc3fQ==";
const uint8_t kSampleNonThirdPartyTokenSignature[] = {
    0x2d, 0x2e, 0x04, 0x81, 0x17, 0x96, 0x13, 0x1f, 0xbd, 0x2e, 0x37,
    0x67, 0xe9, 0xbc, 0x6e, 0x07, 0xaa, 0x9e, 0x76, 0x6a, 0xdb, 0xbc,
    0x55, 0xe0, 0xe1, 0xb5, 0xdd, 0xdf, 0x9b, 0x93, 0x21, 0xae, 0x08,
    0xac, 0x7a, 0x59, 0xaf, 0xa1, 0x4a, 0x42, 0xe4, 0x93, 0xa3, 0x92,
    0xb6, 0x0f, 0x83, 0x97, 0xca, 0x51, 0x76, 0xa5, 0x06, 0xd7, 0xd0,
    0x61, 0x5a, 0x78, 0xb3, 0x9f, 0x94, 0xdb, 0x28, 0x03};

// This is a good third party trial token with usage restriction set to subset,
// signed with the above test private key. Generate this token with the
// command:
// generate_token.py valid.example.com Frobulate --version 3 --is-third-party
//   --expire-timestamp=1458766277 --usage-restriction subset
const char kSampleThirdPartyUsageSubsetToken[] =
    "A27Ee1Bm6HYjEu2Zz1DbGNUaPuM8x0Tnk15Gyx8TRKZg72+JUXgCccMxlLIjVh4l"
    "enOES58tfJxrRCorBAKmBwcAAACCeyJvcmlnaW4iOiAiaHR0cHM6Ly92YWxpZC5l"
    "eGFtcGxlLmNvbTo0NDMiLCAiaXNUaGlyZFBhcnR5IjogdHJ1ZSwgInVzYWdlIjog"
    "InN1YnNldCIsICJmZWF0dXJlIjogIkZyb2J1bGF0ZSIsICJleHBpcnkiOiAxNDU4"
    "NzY2Mjc3fQ==";
const uint8_t kSampleThirdPartyUsageSubsetTokenSignature[] = {
    0x6e, 0xc4, 0x7b, 0x50, 0x66, 0xe8, 0x76, 0x23, 0x12, 0xed, 0x99,
    0xcf, 0x50, 0xdb, 0x18, 0xd5, 0x1a, 0x3e, 0xe3, 0x3c, 0xc7, 0x44,
    0xe7, 0x93, 0x5e, 0x46, 0xcb, 0x1f, 0x13, 0x44, 0xa6, 0x60, 0xef,
    0x6f, 0x89, 0x51, 0x78, 0x02, 0x71, 0xc3, 0x31, 0x94, 0xb2, 0x23,
    0x56, 0x1e, 0x25, 0x7a, 0x73, 0x84, 0x4b, 0x9f, 0x2d, 0x7c, 0x9c,
    0x6b, 0x44, 0x2a, 0x2b, 0x04, 0x02, 0xa6, 0x07, 0x07};

// This is a good third party trial token with usage restriction set to none,
// signed with the above test private key. Generate this token with the
// command:
// generate_token.py valid.example.com Frobulate --version 3 --is-third-party
//   --expire-timestamp=1458766277 --usage-restriction ""
const char kSampleThirdPartyUsageEmptyToken[] =
    "A+gXf6yZgfN8NADWvnEhQ/GKycwCg34USmDlQ9UXTP6jDGJLBV+jI1npSUI0W/YW"
    "hNyNYbzBaE2iCJSGCD56pwwAAAB8eyJvcmlnaW4iOiAiaHR0cHM6Ly92YWxpZC5l"
    "eGFtcGxlLmNvbTo0NDMiLCAiaXNUaGlyZFBhcnR5IjogdHJ1ZSwgInVzYWdlIjog"
    "IiIsICJmZWF0dXJlIjogIkZyb2J1bGF0ZSIsICJleHBpcnkiOiAxNDU4NzY2Mjc3"
    "fQ==";
const uint8_t kSampleThirdPartyUsageEmptyTokenSignature[] = {
    0xe8, 0x17, 0x7f, 0xac, 0x99, 0x81, 0xf3, 0x7c, 0x34, 0x00, 0xd6,
    0xbe, 0x71, 0x21, 0x43, 0xf1, 0x8a, 0xc9, 0xcc, 0x02, 0x83, 0x7e,
    0x14, 0x4a, 0x60, 0xe5, 0x43, 0xd5, 0x17, 0x4c, 0xfe, 0xa3, 0x0c,
    0x62, 0x4b, 0x05, 0x5f, 0xa3, 0x23, 0x59, 0xe9, 0x49, 0x42, 0x34,
    0x5b, 0xf6, 0x16, 0x84, 0xdc, 0x8d, 0x61, 0xbc, 0xc1, 0x68, 0x4d,
    0xa2, 0x08, 0x94, 0x86, 0x08, 0x3e, 0x7a, 0xa7, 0x0c};

const char kExpectedFeatureName[] = "Frobulate";
// This is an excessively long feature name (100 characters). This is valid, as
// there is no explicit limit on feature name length. Excessive refers to the
// fact that is very unlikely that a developer would choose such a long name.
const char kExpectedLongFeatureName[] =
    "ThisTrialNameIs100CharactersLongIncludingPaddingAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAA";
const char kExpectedOrigin[] = "https://valid.example.com";
const char kExpectedSubdomainOrigin[] = "https://example.com";
const char kExpectedMultipleSubdomainOrigin[] =
    "https://part1.part2.part3.example.com";
const uint64_t kExpectedExpiry = 1458766277;

// The token should not be valid for this origin, or for this feature.
const char kInvalidOrigin[] = "https://invalid.example.com";
const char kInsecureOrigin[] = "http://valid.example.com";
const char kIncorrectPortOrigin[] = "https://valid.example.com:444";
const char kIncorrectDomainOrigin[] = "https://valid.example2.com";
const char kInvalidTLDOrigin[] = "https://com";
const char kInvalidFeatureName[] = "Grokalyze";

// The token should be valid if the current time is kValidTimestamp or earlier.
double kValidTimestamp = 1458766276.0;

// The token should be invalid if the current time is kInvalidTimestamp or
// later.
double kInvalidTimestamp = 1458766278.0;

// Well-formed trial token with an invalid signature.
const char kInvalidSignatureToken[] =
    "Ap+Q/Qm0ELadZql+dlEGSwnAVsFZKgCEtUZg8idQC3uekkIeSZIY1tftoYdrwhqj"
    "7FO5L22sNvkZZnacLvmfNwsAAABaeyJvcmlnaW4iOiAiaHR0cHM6Ly92YWxpZC5l"
    "eGFtcGxlLmNvbTo0NDMiLCAiZmVhdHVyZSI6ICJGcm9idWxhdGV4IiwgImV4cGly"
    "eSI6IDE0NTg3NjYyNzd9";

// Trial token truncated in the middle of the length field; too short to
// possibly be valid.
const char kTruncatedToken[] =
    "Ap+Q/Qm0ELadZql+dlEGSwnAVsFZKgCEtUZg8idQC3uekkIeSZIY1tftoYdrwhqj"
    "7FO5L22sNvkZZnacLvmfNwsA";

// Trial token with an incorrectly-declared length, but with a valid signature.
const char kIncorrectLengthToken[] =
    "Ao06eNl/CZuM88qurWKX4RfoVEpHcVHWxdOTrEXZkaC1GUHyb/8L4sthADiVWdc9"
    "kXFyF1BW5bbraqp6MBVr3wEAAABaeyJvcmlnaW4iOiAiaHR0cHM6Ly92YWxpZC5l"
    "eGFtcGxlLmNvbTo0NDMiLCAiZmVhdHVyZSI6ICJGcm9idWxhdGUiLCAiZXhwaXJ5"
    "IjogMTQ1ODc2NjI3N30=";

// Trial token with a misidentified version (42).
const char kIncorrectVersionToken[] =
    "KlH8wVLT5o59uDvlJESorMDjzgWnvG1hmIn/GiT9Ng3f45ratVeiXCNTeaJheOaG"
    "A6kX4ir4Amv8aHVC+OJHZQkAAABZeyJvcmlnaW4iOiAiaHR0cHM6Ly92YWxpZC5l"
    "eGFtcGxlLmNvbTo0NDMiLCAiZmVhdHVyZSI6ICJGcm9idWxhdGUiLCAiZXhwaXJ5"
    "IjogMTQ1ODc2NjI3N30=";

const char kSampleTokenJSON[] =
    "{\"origin\": \"https://valid.example.com:443\", \"feature\": "
    "\"Frobulate\", \"expiry\": 1458766277}";

const char kSampleNonSubdomainTokenJSON[] =
    "{\"origin\": \"https://valid.example.com:443\", \"isSubdomain\": false, "
    "\"feature\": \"Frobulate\", \"expiry\": 1458766277}";

const char kSampleSubdomainTokenJSON[] =
    "{\"origin\": \"https://example.com:443\", \"isSubdomain\": true, "
    "\"feature\": \"Frobulate\", \"expiry\": 1458766277}";

const char kUsageEmptyTokenJSON[] =
    "{\"origin\": \"https://valid.example.com:443\", \"usage\": \"\", "
    "\"feature\": \"Frobulate\", \"expiry\": 1458766277}";

const char kUsageSubsetTokenJSON[] =
    "{\"origin\": \"https://valid.example.com:443\", \"usage\": \"subset\", "
    "\"feature\": \"Frobulate\", \"expiry\": 1458766277}";

const char kSampleNonThirdPartyTokenJSON[] =
    "{\"origin\": \"https://valid.example.com:443\", \"isThirdParty\": false, "
    "\"feature\": \"Frobulate\", \"expiry\": 1458766277}";

const char kSampleThirdPartyTokenJSON[] =
    "{\"origin\": \"https://valid.example.com:443\", \"isThirdParty\": true, "
    "\"feature\": \"Frobulate\", \"expiry\": 1458766277}";

const char kSampleThirdPartyTokenUsageSubsetJSON[] =
    "{\"origin\": \"https://valid.example.com:443\", \"isThirdParty\": true, "
    "\"usage\": \"subset\", \"feature\": \"Frobulate\", \"expiry\": "
    "1458766277}";

const char kSampleThirdPartyTokenUsageEmptyJSON[] =
    "{\"origin\": \"https://valid.example.com:443\", \"isThirdParty\": true, "
    "\"usage\": \"\", \"feature\": \"Frobulate\", \"expiry\": 1458766277}";

// Various ill-formed trial tokens. These should all fail to parse.
const char* kInvalidTokens[] = {
    // Empty String
    "",
    // Invalid - Not JSON at all
    "abcde",
    // Invalid JSON
    "{",
    // Not an object
    "\"abcde\"",
    "123.4",
    "[0, 1, 2]",
    // Missing keys
    "{}",
    "{\"something\": 1}",
    "{\"origin\": \"https://a.a\"}",
    "{\"origin\": \"https://a.a\", \"feature\": \"a\"}",
    "{\"origin\": \"https://a.a\", \"expiry\": 1458766277}",
    "{\"feature\": \"FeatureName\", \"expiry\": 1458766277}",
    // Incorrect types
    "{\"origin\": 1, \"feature\": \"a\", \"expiry\": 1458766277}",
    "{\"origin\": \"https://a.a\", \"feature\": 1, \"expiry\": 1458766277}",
    "{\"origin\": \"https://a.a\", \"feature\": \"a\", \"expiry\": \"1\"}",
    "{\"origin\": \"https://a.a\", \"isSubdomain\": \"true\", \"feature\": "
    "\"a\", \"expiry\": 1458766277}",
    "{\"origin\": \"https://a.a\", \"isSubdomain\": 1, \"feature\": \"a\", "
    "\"expiry\": 1458766277}",
    // Negative expiry timestamp
    "{\"origin\": \"https://a.a\", \"feature\": \"a\", \"expiry\": -1}",
    // Origin not a proper origin URL
    "{\"origin\": \"abcdef\", \"feature\": \"a\", \"expiry\": 1458766277}",
    "{\"origin\": \"data:text/plain,abcdef\", \"feature\": \"a\", \"expiry\": "
    "1458766277}",
    "{\"origin\": \"javascript:alert(1)\", \"feature\": \"a\", \"expiry\": "
    "1458766277}",
};

const char* kInvalidTokensVersion3[] = {
    // Incorrect types
    "{\"origin\": \"https://a.a\", \"isThirdParty\": \"true\", \"feature\": "
    "\"a\", \"expiry\": 1458766277}",
    "{\"origin\": \"https://a.a\", \"isThirdParty\": 1, \"feature\": \"a\", "
    "\"expiry\": 1458766277}",
    // Invalid value in usage field
    "{\"origin\": \"https://a.a\", \"isThirdParty\": true, \"usage\": "
    "\"cycle\", \"feature\": \"a\", "
    "\"expiry\": 1458766277}",
};

// Valid token JSON. The feature name matches matches kExpectedLongFeatureName
// (100 characters), and the origin is 2048 chars.
const char kLargeTokenJSON[] =
    "{\"origin\": "
    "\"https://"
    "www."
    "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.com:9999\","
    // clang-format off
    "\"isSubdomain\": true,"
    "\"feature\": \"ThisTrialNameIs100CharactersLongIncludingPaddingAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\","
    "\"expiry\": 1458766277}";
// clang-format on

const char kExpectedLongTokenOrigin[] =
    "https://"
    "www."
    "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.com:9999";

// Valid token JSON, over 4KB in size. The feature name matches
// kExpectedLongFeatureName (100 characters), and the origin is 3929 chars.
const char kTooLargeTokenJSON[] =
    "{\"origin\": "
    "\"https://"
    "www."
    "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.com:9999\","
    // clang-format off
    "\"isSubdomain\": true,"
    "\"feature\": \"ThisTrialNameIs100CharactersLongIncludingPaddingAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\","
    "\"expiry\": 1458766277}";
// clang-format on

// Large valid token, size = 3052 chars. The feature name matches
// kExpectedLongFeatureName (100 characters), and the origin is 2048 chars.
// Generate this token with the command:
// generate_token.py --is-subdomain --expire-timestamp=1458766277 \
//   2 https://www.<2027 random chars>.com:9999 \
//   ThisTrialNameIs100CharactersLongIncludingPaddingAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
const char kLargeValidToken[] =
    "Aq1wGS1wFPBT/"
    "S0tRbXIhO6fntc3GuDacAPAcfTBMxkdXpgXJMERVcVEVNfZAu1laKHhMUjTp0pOIBi/"
    "KyWXrAQAAAireyJvcmlnaW4iOiAiaHR0cHM6Ly93d3cuYWFhcHB0eXFpbm0wcGFsMWJpZnlpdH"
    "Vkb2h4dThzbWh2Zmx4aTVnbmdsYTVzbWtwbmw2MnFpOWdscWlmanBpZ3V4bDlweHVkYXN6YnVz"
    "Y3Ric3htaTd2MXRyYnhsdWd1YTdpeGp2dXZxM2ZoejVocnVmZmhmN2RocGVxeWN6Zjdzd3Zmcn"
    "hscDBseWhpaHZ0bno3Mnl3a2FucWlqeGZjZ2l4M3d6Z25za3lhODlma2plaGgzZ3h6Y3dmY3Fn"
    "aGI4NnZvNjFxeGhtNG5vc211ZXYyeGN0ajlkNG5hZHR4c3k1bHVld3RjZW5tM2pibWxsd3J1dW"
    "hscGx2ejBmbXdpcm9leGdxc3IxbzJsaTRwYmF5eTJvamt2b3dhaGZ5Z3h1eTJwOWVlYW5zeXNp"
    "YXQ5dzNrdzI1NmVuajRoeHZjZ3A1andleGJnN2liZHk1a2Y1bWlsY2hlZXp4OHhlcnN6Znc2ZW"
    "RweHlzOG15bGl2bzZqcm9ja2JncmhhcWVzZmFod2JycnJoemZzamV4cm13bDF3ZmU1amFub3Rr"
    "cmFidXR2a29tdXJhYXAwMXh0eXJjZThjdW9mZXRtdmFyaGZsYng5dnBhdTB3ZXZvbmV3MG95dz"
    "gya3RlamtwNG9kc3NyM2h2cmh2NGx6ZmZodnBnc2hmbWxoaHl3NWdwejExdzB1ZmhjdzF5N2Fy"
    "MGIwemVnYjZtZ3djYnJ1eGZhNDJmcXJscW50dWdocm9yZzdpNWV0cGhhZ3k0MXNydnUwbmJrdz"
    "k5ZmxybXl4M2JyZTB6a3EyZmtwbGNibzVrZHg3YmQyZWNtd21veXp6c2R1ZnB1dXlucHhlMW13"
    "MGd3NnVoeGljODdsb3VqZXd3Z3RtcXFyOXJlYXkxdjlhZ2dka2dhems0aGJka29yaXVsODhvaH"
    "l1d2h1N2JqbW95aHB5c3Zsb2gxZWZvbm9ybXA1NDFuanRzMXhyZWpvNWo2d21pN2J3bW5obHd5"
    "djJsaWdzdGFkY2k0YXR4MGJpdHJkYmVqYXJ0YnExZGRlNGlmb21wcjBrdHJsdHA5aWNjdm9mYW"
    "ZrYzBjY3RjZWM4NmtmaG5meHNjcjZjcWlqcnV2aWtrdWJva2Zsc2hpcWV1emZ4aTJvbHNjYWUz"
    "a2M5MDJpbjZmOW5qaTNrZGl3bzB2dGN3MzJrbm5qaXhuZm54MjNtOXN2emd6cnFmYmNpYjk2bj"
    "JvZzdzdXhzZTZ2Y2U5a3Q1ZW1qeTVvYXFmcnpjZ3lvaXB3MGdmZWp1b2pvbXlqb3hzb2Nod3l3"
    "eHg1Z2UyMmJndnVrenl2eThqbHk2NmwwaWdwODFvZXI2d2t1bjh5NnljdGR5bnRqZGtsZnF6NH"
    "dqeG14eWduY3RnaGtneDF2eXJmeHlqcTAwNXprdnVkaDBxZnZqc2JyYmo0bng1bTd2Zm1rdnV6"
    "b2k5a2Znb2djMnFhZ294eGFzb3J
```