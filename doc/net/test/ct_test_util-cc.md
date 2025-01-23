Response:
Let's break down the thought process for analyzing this C++ file and generating the response.

**1. Initial Understanding of the Request:**

The request asks for a functional description of a Chromium network stack file (`net/test/ct_test_util.cc`), focusing on its purpose, relationship to JavaScript (if any), logical deductions (with examples), common usage errors, and debugging context.

**2. Analyzing the File Content - The Core Task:**

* **Headers:**  The `#include` directives provide the first clues. We see `<stdint.h>`, `<string.h>`, `<string_view>`, `<vector>`, `base/base64.h`, `base/strings/...`, `net/base/hex_utils.h`, and crucial ones like `net/cert/ct_serialization.h`, `net/cert/merkle_tree_leaf.h`, and `net/cert/signed_tree_head.h`. These point strongly towards Certificate Transparency (CT) functionality and test utilities.

* **Namespace:** `namespace net::ct` confirms the CT focus.

* **Test Vectors (The "meat" of the file):** The large constant character arrays (e.g., `kDefaultDerCert`, `kDefaultIssuerKeyHash`, `kTestSignedCertificateTimestamp`) are clearly encoded data related to certificates, SCTs, and other CT structures. The comments like "// The following test vectors are from..." are direct indicators of their purpose.

* **Functions:**  The function names are very descriptive (e.g., `GetX509CertSignedEntry`, `GetPrecertTreeLeaf`, `GetTestSignedCertificateTimestamp`, `GetSampleSignedTreeHead`, `CreateSignedTreeHeadJsonString`). They are clearly helper functions for generating or retrieving specific CT-related data structures. The presence of `Get...` and `Create...` functions is a common pattern for test utilities.

* **Data Structure Population:** The functions populate C++ data structures like `SignedEntryData`, `MerkleTreeLeaf`, and `SignedCertificateTimestamp`. This confirms its role in creating test inputs.

**3. Identifying Key Functionality:**

Based on the analysis above, the primary function of the file is clear: **providing test utilities for Certificate Transparency related code.**  Specifically, it generates pre-defined data structures and encoded representations of various CT components.

**4. Relating to JavaScript (or lack thereof):**

The core of the file is C++. There are no direct JavaScript code or interactions within this file. However, the *data* it generates can be used in contexts that *do* involve JavaScript. The key connection point is the JSON output from functions like `CreateSignedTreeHeadJsonString`. JavaScript often consumes JSON for web-based CT interactions. This requires the crucial distinction between direct code interaction and data usage.

**5. Logical Deduction and Examples:**

The functions often take no input and produce specific outputs (the predefined test vectors). This makes the "input/output" examples straightforward. For instance, `GetDerEncodedX509Cert()` always returns the DER encoding of `kDefaultDerCert`. For functions like `CreateSignedTreeHeadJsonString`, we can deduce how the inputs (tree size, timestamp, hashes, signature) map to the JSON output format. This requires understanding the structure of a Signed Tree Head and the JSON format.

**6. Common Usage Errors:**

The main area for usage errors isn't within this *file* itself, but in how the *functions* of this file are used. The most likely errors involve:

* **Incorrect assumptions about the data:** Assuming the test data represents a valid, real-world scenario when it might be intentionally crafted for a specific test case.
* **Mismatched data types:**  Trying to use a string representing a DER-encoded certificate as if it were a parsed `X509Certificate` object.
* **Incorrect encoding/decoding:**  Forgetting to decode hex strings before using them.

**7. Debugging Context and User Actions:**

To connect this file to user actions, we need to think about how CT is used in a browser. A user browsing to an HTTPS website is the starting point. The browser then performs certificate verification, which *may* involve checking for CT information. The debugging scenario involves tracing how CT data (like SCTs) gets processed, potentially leading to the code that uses these test utilities. The key is to illustrate the *path* from user action to this specific part of the Chromium codebase (albeit indirectly via testing).

**8. Structuring the Response:**

Organizing the information clearly is essential. Using headings and bullet points makes the response easier to read and understand. The request had specific categories (functionality, JavaScript relationship, logical deductions, errors, debugging), which provided a natural structure.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This file *is* used by JavaScript."  **Correction:**  "No, the *data* it generates *can be used* by JavaScript." This distinction is important.
* **Focus on the *functions*:**  The analysis should center on what the functions *do* and what data they provide, rather than just listing the constants.
* **Provide concrete examples:** Abstract descriptions are less helpful than showing actual input and output (even if the input is often implicit).
* **Connect to the larger system:** Explain *why* these test utilities are necessary within the context of Certificate Transparency and browser security.

By following this breakdown, analyzing the code, and connecting it to the broader context of Chromium's network stack and web security, we can generate a comprehensive and accurate response to the user's request.
这个文件 `net/test/ct_test_util.cc` 是 Chromium 网络栈中专门用于**Certificate Transparency (CT) 功能测试的工具库**。 它提供了一系列辅助函数，用于生成、获取和操作与 CT 相关的测试数据。

以下是它的主要功能：

**1. 提供预定义的测试数据：**

* **证书数据:** 包含了 DER 编码的证书 (`kDefaultDerCert`)，TBS 证书 (`kDefaultDerTbsCert`)，以及签发者密钥哈希 (`kDefaultIssuerKeyHash`)。
* **扩展数据:** 提供了一个示例扩展数据 (`kDefaultExtensions`)。
* **签名数据:** 包含了用于测试数字签名的数据 (`kTestDigitallySigned`)。
* **签名证书时间戳 (SCT) 数据:** 提供了有效和无效的 SCT 数据 (`kTestSignedCertificateTimestamp`)，以及用于预验证证书的 SCT 数据 (`kTestSCTPrecertSignatureData`)。
* **公钥和密钥 ID:** 提供了 EC P-256 公钥 (`kEcP256PublicKey`) 及其对应的密钥 ID (`kTestKeyId`)。
* **时间戳:** 提供了一个用于测试的时间戳 (`kTestTimestamp`)。
* **OCSP 响应数据:**  提供了一个包含伪造 SCT 内容的 OCSP 响应 (`kFakeOCSPResponse`)，以及相关的证书和签发者证书。
* **签名树头 (STH) 数据:** 提供了有效的和无效的 STH 数据，包括根哈希 (`kSampleSTHSHA256RootHash`)，树头签名 (`kSampleSTHTreeHeadSignature`) 和树大小。

**2. 提供用于创建和获取 CT 相关数据结构的辅助函数：**

* **获取证书相关的结构体:**  例如 `GetX509CertSignedEntry`, `GetX509CertTreeLeaf`, `GetPrecertSignedEntry`, `GetPrecertTreeLeaf`，用于填充 `SignedEntryData` 和 `MerkleTreeLeaf` 结构体。
* **获取编码后的数据:** 例如 `GetDerEncodedX509Cert`, `GetTestDigitallySigned`, `GetTestSignedCertificateTimestamp`, `GetDefaultIssuerKeyHash`, `GetDerEncodedFakeOCSPResponse` 等，用于获取十六进制编码的字符串表示。
* **创建 SCT 对象:**  例如 `GetX509CertSCT`, `GetPrecertSCT`，用于创建 `SignedCertificateTimestamp` 对象。
* **创建 STH 对象:** 例如 `GetSampleSignedTreeHead`, `GetSampleEmptySignedTreeHead`, `GetBadEmptySignedTreeHead`，用于创建 `SignedTreeHead` 对象。
* **创建 JSON 字符串:** 例如 `CreateSignedTreeHeadJsonString`, `CreateConsistencyProofJsonString`，用于生成 STH 和一致性证明的 JSON 格式字符串。
* **创建 SCT 列表:** `GetSCTListForTesting`, `GetSCTListWithInvalidSCT` 用于创建包含一个或多个 SCT 的列表，方便测试。

**3. 提供用于校验测试结果的辅助函数：**

* `CheckForSingleVerifiedSCTInResult`: 检查结果中是否只有一个状态为 OK 的 SCT，并且其日志描述是否匹配。
* `CheckForSCTOrigin`: 检查 SCT 列表中是否存在指定来源的 SCT。

**与 JavaScript 的关系：**

这个 C++ 文件本身不包含 JavaScript 代码，但它生成的数据在 Chromium 浏览器中与 JavaScript 功能有密切关系。

* **CT Policy 和 Reporting:** Chromium 的渲染器进程（通常运行 JavaScript）会接收来自网络栈的 CT 信息。这些信息（例如 SCTs）可能被用于评估 CT 策略，并向开发者工具或指定的报告 URI 发送报告。
* **`chrome.certificateTransparency` API:** Chrome 提供了 `chrome.certificateTransparency` API，允许扩展程序查询有关 CT 的信息。网络栈提供的 CT 数据会通过 Chromium 的内部机制暴露给这个 API，供 JavaScript 代码使用。

**举例说明 (JavaScript 场景):**

假设一个网站的 HTTPS 连接返回了一个包含 SCT 的 TLS 握手。

1. **网络栈处理:**  Chromium 的网络栈（由 C++ 代码实现，包括使用 `ct_test_util.cc` 辅助测试的代码）会解析这些 SCT 数据。
2. **数据传递:**  网络栈会将解析后的 SCT 信息传递给渲染器进程。
3. **JavaScript API 使用:**  一个 Chrome 扩展程序可以使用 `chrome.certificateTransparency.getSCTs` 方法来获取与当前连接相关的 SCT 信息。

```javascript
chrome.certificateTransparency.getSCTs({ tabId: chrome.devtools.inspectedWindow.tabId }, function(scts) {
  if (scts && scts.length > 0) {
    console.log("找到 SCTs:");
    scts.forEach(function(sct) {
      console.log("  Log ID:", sct.logId);
      console.log("  Timestamp:", sct.timestamp);
      // ... 更多 SCT 属性
    });
  } else {
    console.log("未找到 SCTs。");
  }
});
```

在这个例子中，虽然 `ct_test_util.cc` 是 C++ 文件，它生成的测试数据（例如模拟 TLS 握手中包含的 SCT）可以被用来测试网络栈的 CT 功能，最终影响 JavaScript API 返回给扩展程序的信息。

**逻辑推理 - 假设输入与输出:**

由于这个文件主要是提供预定义数据和辅助函数，很多函数的输入是隐含的（使用预定义的常量），输出也是预期的常量值或基于这些常量的派生值。

**示例 1: `GetDerEncodedX509Cert()`**

* **假设输入:** (无显式输入)
* **输出:**  字符串 "308202ca30820233a003020102020106300d06092a864886f70d01010505003055310b3009..." (即 `kDefaultDerCert` 的十六进制表示)。

**示例 2: `CreateSignedTreeHeadJsonString(21, 1396877277237, "726467216167397babca293dca398e4ce6b621b18b9bc42f30c900d1f92ac1e4", "0403004730450220365a91a2a88f2b9332f41d8959fa7086da7e6d634b7b089bc9da0664266c7a20022100e38464f3c0fd066257b982074f7ac87655e0c8f714768a050b4be9a7b441cbd3")`**

* **假设输入:**
    * `tree_size`: 21
    * `timestamp`: 1396877277237
    * `sha256_root_hash`: "726467216167397babca293dca398e4ce6b621b18b9bc42f30c900d1f92ac1e4"
    * `tree_head_signature`: "0403004730450220365a91a2a88f2b9332f41d8959fa7086da7e6d634b7b089bc9da0664266c7a20022100e38464f3c0fd066257b982074f7ac87655e0c8f714768a050b4be9a7b441cbd3"
* **输出:**  JSON 字符串 `{"tree_size":21,"timestamp":1396877277237,"sha256_root_hash":"cmRneyFhZzlmeyvCyjndyjnuTOZsGxiryPwMDh8y8erHl8A8jww9HyrB5","tree_head_signature":"BAEAAEYwRQIgNlqRoqiPK5My9B2JWfpwhtp+bWNLewibydoGZCZsYgACIRDLhGTzwP0GYlc5ggdPeseHZecjS3aKBULL6ae0Qcs90"}` (其中哈希和签名是 Base64 编码后的结果)。

**用户或编程常见的使用错误：**

由于 `ct_test_util.cc` 主要用于测试，用户直接操作到这里的可能性很小。常见的错误发生在**编写或使用依赖于这些测试数据的代码时**。

* **错误地假设测试数据的有效性:**  测试数据可能被故意构造为无效或边缘情况，不应直接用于生产环境。例如，使用 `GetSCTListWithInvalidSCT()` 生成的 SCT 列表进行正常 SCT 处理将会失败。
* **忘记进行必要的解码:**  很多函数返回的是十六进制编码的字符串，如果直接将其作为二进制数据使用会导致解析错误。例如，在处理 `GetDerEncodedX509Cert()` 的结果之前，需要使用 `net::HexDecode()` 进行解码。
* **使用了错误的辅助函数:**  例如，需要预证书的 SCT 数据时，错误地使用了 `GetX509CertSCT()`。
* **在不适合的测试场景中使用了特定的测试数据:** 例如，用一个只包含 X.509 证书 SCT 的列表去测试预证书的处理逻辑。

**用户操作是如何一步步的到达这里，作为调试线索:**

作为一个用户，你不太可能直接触发 `ct_test_util.cc` 中的代码。这个文件主要在 Chromium 的开发和测试阶段使用。但是，你的操作会间接地触发依赖于 CT 功能的代码，而这些 CT 功能的测试可能使用了 `ct_test_util.cc`。

**调试线索 - 从用户操作到 `ct_test_util.cc` (间接路径):**

1. **用户访问 HTTPS 网站:** 当用户在 Chrome 浏览器中访问一个 HTTPS 网站时，浏览器会建立安全连接，这个过程涉及到 TLS 握手。
2. **服务器提供 CT 信息:**  服务器在 TLS 握手中可能会提供 Signed Certificate Timestamps (SCTs)，证明其证书被记录在 CT 日志中。
3. **Chromium 网络栈处理 CT 信息:**  Chromium 的网络栈接收并验证这些 SCTs。这部分代码的测试可能就使用了 `ct_test_util.cc` 提供的测试数据来模拟各种 SCT 场景（有效、无效、不同来源等）。
4. **开发者工具或内部日志:** 如果在开发模式下或者使用了特定的 Chrome 标志，与 CT 相关的错误或信息可能会被记录在开发者工具的 "安全" 面板或者 Chromium 的内部日志中。
5. **开发人员调试网络栈:**  当网络栈的 CT 功能出现问题时，Chromium 的开发人员可能会使用断点、日志等工具来调试网络栈的代码。为了复现问题或进行单元测试，他们会使用像 `ct_test_util.cc` 这样的测试工具来创建特定的 CT 数据场景。

**总结:**

`net/test/ct_test_util.cc` 是一个为 Chromium 网络栈的 Certificate Transparency 功能提供测试支持的关键文件。它通过提供预定义的数据和辅助函数，简化了 CT 相关代码的测试工作，确保了 Chromium 能够正确处理各种 CT 场景，从而提升用户的网络安全。虽然用户不会直接操作到这个文件，但其功能对于保证用户访问 HTTPS 网站时的安全性和透明度至关重要。

### 提示词
```
这是目录为net/test/ct_test_util.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
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

#include "net/test/ct_test_util.h"

#include <stdint.h>
#include <string.h>

#include <string_view>
#include <vector>

#include "base/base64.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "net/base/hex_utils.h"
#include "net/cert/ct_serialization.h"
#include "net/cert/merkle_tree_leaf.h"
#include "net/cert/signed_tree_head.h"
#include "net/cert/x509_certificate.h"

namespace net::ct {

namespace {

// The following test vectors are from
// http://code.google.com/p/certificate-transparency

const char kDefaultDerCert[] =
    "308202ca30820233a003020102020106300d06092a864886f70d01010505003055310b3009"
    "06035504061302474231243022060355040a131b4365727469666963617465205472616e73"
    "706172656e6379204341310e300c0603550408130557616c65733110300e06035504071307"
    "4572772057656e301e170d3132303630313030303030305a170d3232303630313030303030"
    "305a3052310b30090603550406130247423121301f060355040a1318436572746966696361"
    "7465205472616e73706172656e6379310e300c0603550408130557616c65733110300e0603"
    "55040713074572772057656e30819f300d06092a864886f70d010101050003818d00308189"
    "02818100b1fa37936111f8792da2081c3fe41925008531dc7f2c657bd9e1de4704160b4c9f"
    "19d54ada4470404c1c51341b8f1f7538dddd28d9aca48369fc5646ddcc7617f8168aae5b41"
    "d43331fca2dadfc804d57208949061f9eef902ca47ce88c644e000f06eeeccabdc9dd2f68a"
    "22ccb09dc76e0dbc73527765b1a37a8c676253dcc10203010001a381ac3081a9301d060355"
    "1d0e041604146a0d982a3b62c44b6d2ef4e9bb7a01aa9cb798e2307d0603551d2304763074"
    "80145f9d880dc873e654d4f80dd8e6b0c124b447c355a159a4573055310b30090603550406"
    "1302474231243022060355040a131b4365727469666963617465205472616e73706172656e"
    "6379204341310e300c0603550408130557616c65733110300e060355040713074572772057"
    "656e82010030090603551d1304023000300d06092a864886f70d010105050003818100171c"
    "d84aac414a9a030f22aac8f688b081b2709b848b4e5511406cd707fed028597a9faefc2eee"
    "2978d633aaac14ed3235197da87e0f71b8875f1ac9e78b281749ddedd007e3ecf50645f8cb"
    "f667256cd6a1647b5e13203bb8582de7d6696f656d1c60b95f456b7fcf338571908f1c6972"
    "7d24c4fccd249295795814d1dac0e6";

const char kDefaultIssuerKeyHash[] =
    "02adddca08b8bf9861f035940c940156d8350fdff899a6239c6bd77255b8f8fc";

const char kDefaultDerTbsCert[] =
    "30820233a003020102020107300d06092a864886f70d01010505003055310b300906035504"
    "061302474231243022060355040a131b4365727469666963617465205472616e7370617265"
    "6e6379204341310e300c0603550408130557616c65733110300e0603550407130745727720"
    "57656e301e170d3132303630313030303030305a170d3232303630313030303030305a3052"
    "310b30090603550406130247423121301f060355040a131843657274696669636174652054"
    "72616e73706172656e6379310e300c0603550408130557616c65733110300e060355040713"
    "074572772057656e30819f300d06092a864886f70d010101050003818d0030818902818100"
    "beef98e7c26877ae385f75325a0c1d329bedf18faaf4d796bf047eb7e1ce15c95ba2f80ee4"
    "58bd7db86f8a4b252191a79bd700c38e9c0389b45cd4dc9a120ab21e0cb41cd0e72805a410"
    "cd9c5bdb5d4927726daf1710f60187377ea25b1a1e39eed0b88119dc154dc68f7da8e30caf"
    "158a33e6c9509f4a05b01409ff5dd87eb50203010001a381ac3081a9301d0603551d0e0416"
    "04142031541af25c05ffd8658b6843794f5e9036f7b4307d0603551d230476307480145f9d"
    "880dc873e654d4f80dd8e6b0c124b447c355a159a4573055310b3009060355040613024742"
    "31243022060355040a131b4365727469666963617465205472616e73706172656e63792043"
    "41310e300c0603550408130557616c65733110300e060355040713074572772057656e8201"
    "0030090603551d1304023000";

const char kDefaultExtensions[] = "666f6f626172"; // "foobar"

const char kTestDigitallySigned[] =
    "0403004730450220606e10ae5c2d5a1b0aed49dc4937f48de71a4e9784e9c208dfbfe9ef53"
    "6cf7f2022100beb29c72d7d06d61d06bdb38a069469aa86fe12e18bb7cc45689a2c0187ef5"
    "a5";

const char kTestSignedCertificateTimestamp[] =
    "00df1c2ec11500945247a96168325ddc5c7959e8f7c6d388fc002e0bbd3f74d7640000013d"
    "db27ded900000403004730450220606e10ae5c2d5a1b0aed49dc4937f48de71a4e9784e9c2"
    "08dfbfe9ef536cf7f2022100beb29c72d7d06d61d06bdb38a069469aa86fe12e18bb7cc456"
    "89a2c0187ef5a5";

const char kEcP256PublicKey[] =
    "3059301306072a8648ce3d020106082a8648ce3d0301070342000499783cb14533c0161a5a"
    "b45bf95d08a29cd0ea8dd4c84274e2be59ad15c676960cf0afa1074a57ac644b23479e5b3f"
    "b7b245eb4b420ef370210371a944beaceb";

const char kTestKeyId[] =
    "df1c2ec11500945247a96168325ddc5c7959e8f7c6d388fc002e0bbd3f74d764";

const int64_t kTestTimestamp = INT64_C(1396877277237);

const char kTestSCTSignatureData[] =
    "30450220606e10ae5c2d5a1b0aed49dc4937f48de71a4e9784e9c208dfbfe9ef536cf7f202"
    "2100beb29c72d7d06d61d06bdb38a069469aa86fe12e18bb7cc45689a2c0187ef5a5";

const char kTestSCTPrecertSignatureData[] =
    "30450220482f6751af35dba65436be1fd6640f3dbf9a41429495924530288fa3e5e23e0602"
    "2100e4edc0db3ac572b1e2f5e8ab6a680653987dcf41027dfeffa105519d89edbf08";

// A well-formed OCSP response with fake SCT contents. Does not come from
// http://code.google.com/p/certificate-transparency, does not pertain to any
// of the test certs here, and is only used to test extracting the extension
// contents from the response.
const char kFakeOCSPResponse[] =
    "3082016e0a0100a08201673082016306092b060105050730010104820154308201503081ba"
    "a21604144edfdf5ff9c90ffacfca66e7fbc436bc39ee3fc7180f3230313030313031303630"
    "3030305a30818e30818b3049300906052b0e03021a050004141833a1e6a4f09577cca0e64c"
    "e7d145ca4b93700904144edfdf5ff9c90ffacfca66e7fbc436bc39ee3fc7021001aef99bde"
    "e0bb58c6f2b816bc3ae02f8000180f32303130303130313036303030305aa011180f323033"
    "30303130313036303030305aa11830163014060a2b06010401d67902040504060404746573"
    "74300d06092a864886f70d0101050500038181003586ffcf0794e64eb643d52a3d570a1c93"
    "836395986a2f792dd4e9c70b05161186c55c1658e0607dc9ec0d0924ac37fb99506c870579"
    "634be1de62ba2fced5f61f3b428f959fcee9bddf6f268c8e14c14fdf3b447786e638a5c8cc"
    "b610893df17a60e4cff30f4780aeffe0086ef19910f0d9cd7414bc93d1945686f88ad0a3c3"
    ;

const char kFakeOCSPResponseCert[] =
    "3082022930820192a003020102021001aef99bdee0bb58c6f2b816bc3ae02f300d06092a86"
    "4886f70d01010505003015311330110603550403130a54657374696e67204341301e170d31"
    "30303130313036303030305a170d3332313230313036303030305a30373112301006035504"
    "0313093132372e302e302e31310b300906035504061302585831143012060355040a130b54"
    "657374696e67204f726730819d300d06092a864886f70d010101050003818b003081870281"
    "8100a71998f2930bfe73d031a87f133d2f378eeeeed52a77e44d0fc9ff6f07ff32cbf3da99"
    "9de4ed65832afcb0807f98787506539d258a0ce3c2c77967653099a9034a9b115a876c39a8"
    "c4e4ed4acd0c64095946fb39eeeb47a0704dbb018acf48c3a1c4b895fc409fb4a340a986b1"
    "afc45519ab9eca47c30185c771c64aa5ecf07d020103a35a3058303a06082b060105050701"
    "01010100042b3029302706082b06010505073001861b687474703a2f2f3132372e302e302e"
    "313a35353038312f6f637370301a0603551d200101000410300e300c060a2b06010401d679"
    "020401300d06092a864886f70d01010505000381810065e04fadd3484197f3412479d917e1"
    "9d8f7db57b526f2d0e4c046f86cebe643bf568ea0cd6570b228842aa057c6a7c79f209dfcd"
    "3419a4d93b1ecfb1c0224f33083c7d4da023499fbd00d81d6711ad58ffcf65f1545247fe9d"
    "83203425fd706b4fc5e797002af3d88151be5901eef56ec30aacdfc404be1bd35865ff1943"
    "2516";

const char kFakeOCSPResponseIssuerCert[] =
    "308201d13082013aa003020102020101300d06092a864886f70d0101050500301531133011"
    "0603550403130a54657374696e67204341301e170d3130303130313036303030305a170d33"
    "32313230313036303030305a3015311330110603550403130a54657374696e672043413081"
    "9d300d06092a864886f70d010101050003818b0030818702818100a71998f2930bfe73d031"
    "a87f133d2f378eeeeed52a77e44d0fc9ff6f07ff32cbf3da999de4ed65832afcb0807f9878"
    "7506539d258a0ce3c2c77967653099a9034a9b115a876c39a8c4e4ed4acd0c64095946fb39"
    "eeeb47a0704dbb018acf48c3a1c4b895fc409fb4a340a986b1afc45519ab9eca47c30185c7"
    "71c64aa5ecf07d020103a333303130120603551d130101ff040830060101ff020100301b06"
    "03551d200101000411300f300d060b2b06010401d6790201ce0f300d06092a864886f70d01"
    "01050500038181003f4936f8d00e83fbdde331f2c64335dcf7dec8b1a2597683edeed61af0"
    "fa862412fad848938fe7ab77f1f9a43671ff6fdb729386e26f49e7aca0c0ea216e5970d933"
    "3ea1e11df2ccb357a5fed5220f9c6239e8946b9b7517707631d51ab996833d58a022cff5a6"
    "2169ac9258ec110efee78da9ab4a641e3b3c9ee5e8bd291460";

const char kFakeOCSPExtensionValue[] = "74657374";  // "test"

// For the sample STH
const char kSampleSTHSHA256RootHash[] =
    "726467216167397babca293dca398e4ce6b621b18b9bc42f30c900d1f92ac1e4";
const char kSampleSTHTreeHeadSignature[] =
    "0403004730450220365a91a2a88f2b9332f41d8959fa7086da7e6d634b7b089bc9da066426"
    "6c7a20022100e38464f3c0fd066257b982074f7ac87655e0c8f714768a050b4be9a7b441cb"
    "d3";
size_t kSampleSTHTreeSize = 21u;

}  // namespace

void GetX509CertSignedEntry(SignedEntryData* entry) {
  entry->type = ct::SignedEntryData::LOG_ENTRY_TYPE_X509;
  entry->leaf_certificate = HexDecode(kDefaultDerCert);
}

void GetX509CertTreeLeaf(MerkleTreeLeaf* tree_leaf) {
  tree_leaf->timestamp =
      base::Time::FromMillisecondsSinceUnixEpoch(kTestTimestamp);
  GetX509CertSignedEntry(&tree_leaf->signed_entry);
  tree_leaf->extensions = HexDecode(kDefaultExtensions);
}

std::string GetDerEncodedX509Cert() {
  return HexDecode(kDefaultDerCert);
}

void GetPrecertSignedEntry(SignedEntryData* entry) {
  entry->type = ct::SignedEntryData::LOG_ENTRY_TYPE_PRECERT;
  std::string issuer_hash(HexDecode(kDefaultIssuerKeyHash));
  memcpy(entry->issuer_key_hash.data, issuer_hash.data(), issuer_hash.size());
  entry->tbs_certificate = HexDecode(kDefaultDerTbsCert);
}

void GetPrecertTreeLeaf(MerkleTreeLeaf* tree_leaf) {
  tree_leaf->timestamp =
      base::Time::FromMillisecondsSinceUnixEpoch(kTestTimestamp);
  GetPrecertSignedEntry(&tree_leaf->signed_entry);
  tree_leaf->extensions = HexDecode(kDefaultExtensions);
}

std::string GetTestDigitallySigned() {
  return HexDecode(kTestDigitallySigned);
}

std::string GetTestSignedCertificateTimestamp() {
  return HexDecode(kTestSignedCertificateTimestamp);
}

std::string GetTestPublicKey() {
  return HexDecode(kEcP256PublicKey);
}

std::string GetTestPublicKeyId() {
  return HexDecode(kTestKeyId);
}

void GetX509CertSCT(scoped_refptr<SignedCertificateTimestamp>* sct_ref) {
  CHECK(sct_ref != nullptr);
  *sct_ref = base::MakeRefCounted<SignedCertificateTimestamp>();
  SignedCertificateTimestamp *const sct(sct_ref->get());
  sct->version = ct::SignedCertificateTimestamp::V1;
  sct->log_id = HexDecode(kTestKeyId);
  // Time the log issued a SCT for this certificate, which is
  // Fri Apr  5 10:04:16.089 2013
  sct->timestamp =
      base::Time::UnixEpoch() + base::Milliseconds(INT64_C(1365181456089));
  sct->extensions.clear();

  sct->signature.hash_algorithm = ct::DigitallySigned::HASH_ALGO_SHA256;
  sct->signature.signature_algorithm = ct::DigitallySigned::SIG_ALGO_ECDSA;
  sct->signature.signature_data = HexDecode(kTestSCTSignatureData);
}

void GetPrecertSCT(scoped_refptr<SignedCertificateTimestamp>* sct_ref) {
  CHECK(sct_ref != nullptr);
  *sct_ref = base::MakeRefCounted<SignedCertificateTimestamp>();
  SignedCertificateTimestamp *const sct(sct_ref->get());
  sct->version = ct::SignedCertificateTimestamp::V1;
  sct->log_id = HexDecode(kTestKeyId);
  // Time the log issued a SCT for this Precertificate, which is
  // Fri Apr  5 10:04:16.275 2013
  sct->timestamp =
      base::Time::UnixEpoch() + base::Milliseconds(INT64_C(1365181456275));
  sct->extensions.clear();

  sct->signature.hash_algorithm = ct::DigitallySigned::HASH_ALGO_SHA256;
  sct->signature.signature_algorithm = ct::DigitallySigned::SIG_ALGO_ECDSA;
  sct->signature.signature_data = HexDecode(kTestSCTPrecertSignatureData);
}

std::string GetDefaultIssuerKeyHash() {
  return HexDecode(kDefaultIssuerKeyHash);
}

std::string GetDerEncodedFakeOCSPResponse() {
  return HexDecode(kFakeOCSPResponse);
}

std::string GetFakeOCSPExtensionValue() {
  return HexDecode(kFakeOCSPExtensionValue);
}

std::string GetDerEncodedFakeOCSPResponseCert() {
  return HexDecode(kFakeOCSPResponseCert);
}

std::string GetDerEncodedFakeOCSPResponseIssuerCert() {
  return HexDecode(kFakeOCSPResponseIssuerCert);
}

// A sample, valid STH
bool GetSampleSignedTreeHead(SignedTreeHead* sth) {
  sth->version = SignedTreeHead::V1;
  sth->timestamp = base::Time::UnixEpoch() + base::Milliseconds(kTestTimestamp);
  sth->tree_size = kSampleSTHTreeSize;
  std::string sha256_root_hash = GetSampleSTHSHA256RootHash();
  memcpy(sth->sha256_root_hash, sha256_root_hash.c_str(), kSthRootHashLength);
  sth->log_id = GetTestPublicKeyId();

  return GetSampleSTHTreeHeadDecodedSignature(&(sth->signature));
}

bool GetSampleEmptySignedTreeHead(SignedTreeHead* sth) {
  sth->version = SignedTreeHead::V1;
  sth->timestamp =
      base::Time::UnixEpoch() + base::Milliseconds(INT64_C(1450443594920));
  sth->tree_size = 0;
  std::string empty_root_hash = HexDecode(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  memcpy(sth->sha256_root_hash, empty_root_hash.c_str(), kSthRootHashLength);
  sth->log_id = GetTestPublicKeyId();

  std::string tree_head_signature = HexDecode(
      "040300463044022046c26401de9416403da54762dc1f1687c38eafd791b15e484ab4c5f7"
      "f52721fe02201bf537a3bbea47109fc76c2273fe0f3349f493a07de9335c266330105fb0"
      "2a4a");
  std::string_view sp(tree_head_signature);
  return DecodeDigitallySigned(&sp, &(sth->signature)) && sp.empty();
}

bool GetBadEmptySignedTreeHead(SignedTreeHead* sth) {
  sth->version = SignedTreeHead::V1;
  sth->timestamp =
      base::Time::UnixEpoch() + base::Milliseconds(INT64_C(1450870952897));
  sth->tree_size = 0;
  memset(sth->sha256_root_hash, 'f', kSthRootHashLength);
  sth->log_id = GetTestPublicKeyId();

  std::string tree_head_signature = HexDecode(
      "04030046304402207cab04c62dee5d1cbc95fec30cd8417313f71587b75f133ad2e6f324"
      "74f164d702205e2f3a9bce46f87d7e20e951a4e955da3cb502f8717a22fabd7c5d7e1bef"
      "46ea");
  std::string_view sp(tree_head_signature);
  return DecodeDigitallySigned(&sp, &(sth->signature)) && sp.empty();
}

std::string GetSampleSTHSHA256RootHash() {
  return HexDecode(kSampleSTHSHA256RootHash);
}

std::string GetSampleSTHTreeHeadSignature() {
  return HexDecode(kSampleSTHTreeHeadSignature);
}

bool GetSampleSTHTreeHeadDecodedSignature(DigitallySigned* signature) {
  std::string tree_head_signature = HexDecode(kSampleSTHTreeHeadSignature);
  std::string_view sp(tree_head_signature);
  return DecodeDigitallySigned(&sp, signature) && sp.empty();
}

std::string GetSampleSTHAsJson() {
  return CreateSignedTreeHeadJsonString(kSampleSTHTreeSize, kTestTimestamp,
                                        GetSampleSTHSHA256RootHash(),
                                        GetSampleSTHTreeHeadSignature());
}

std::string CreateSignedTreeHeadJsonString(size_t tree_size,
                                           int64_t timestamp,
                                           std::string sha256_root_hash,
                                           std::string tree_head_signature) {
  std::string sth_json =
      std::string("{\"tree_size\":") + base::NumberToString(tree_size) +
      std::string(",\"timestamp\":") + base::NumberToString(timestamp);

  if (!sha256_root_hash.empty()) {
    std::string root_hash_b64 = base::Base64Encode(sha256_root_hash);
    sth_json += base::StringPrintf(",\"sha256_root_hash\":\"%s\"",
                                   root_hash_b64.c_str());
  }
  if (!tree_head_signature.empty()) {
    std::string tree_head_signature_b64 =
        base::Base64Encode(tree_head_signature);
    sth_json += base::StringPrintf(",\"tree_head_signature\":\"%s\"",
                                   tree_head_signature_b64.c_str());
  }

  sth_json += "}";
  return sth_json;
}

std::string CreateConsistencyProofJsonString(
    const std::vector<std::string>& raw_nodes) {
  std::string consistency_proof_json = std::string("{\"consistency\":[");

  for (auto it = raw_nodes.begin(); it != raw_nodes.end(); ++it) {
    std::string proof_node_b64 = base::Base64Encode(*it);
    consistency_proof_json +=
        base::StringPrintf("\"%s\"", proof_node_b64.c_str());
    if (it + 1 != raw_nodes.end())
      consistency_proof_json += std::string(",");
  }
  consistency_proof_json += std::string("]}");

  return consistency_proof_json;
}

std::string GetSCTListForTesting() {
  const std::string sct = ct::GetTestSignedCertificateTimestamp();
  std::string sct_list;
  ct::EncodeSCTListForTesting({sct}, &sct_list);
  return sct_list;
}

std::string GetSCTListWithInvalidSCT() {
  std::string sct(ct::GetTestSignedCertificateTimestamp());

  // Change a byte inside the Log ID part of the SCT so it does not match the
  // log used in the tests.
  sct[15] = 't';

  std::string sct_list;
  ct::EncodeSCTListForTesting({sct}, &sct_list);
  return sct_list;
}

bool CheckForSingleVerifiedSCTInResult(
    const SignedCertificateTimestampAndStatusList& scts,
    const std::string& log_description) {
  return (scts.size() == 1 && scts[0].status == ct::SCT_STATUS_OK &&
          scts[0].sct->log_description == log_description);
}

bool CheckForSCTOrigin(const SignedCertificateTimestampAndStatusList& scts,
                       ct::SignedCertificateTimestamp::Origin origin) {
  for (const auto& sct_and_status : scts)
    if (sct_and_status.status == SCT_STATUS_OK &&
        sct_and_status.sct->origin == origin)
      return true;

  return false;
}

}  // namespace net::ct
```