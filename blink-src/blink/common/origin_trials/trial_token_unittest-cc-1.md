Response:
The user wants to understand the functionality of the C++ source code file `trial_token_unittest.cc` in the Chromium Blink engine. This file seems to contain unit tests for the `TrialToken` class.

Here's a breakdown of the thought process to answer the request:

1. **Identify the core purpose:** The file name strongly suggests unit testing. The presence of `TEST_F` macros confirms this. The primary goal is to test the `TrialToken` class.

2. **Analyze the test cases:** Go through each `TEST_F` function and understand what aspect of `TrialToken` is being tested. Look for patterns in the test names and the assertions being made.

3. **Relate to web technologies (JavaScript, HTML, CSS):**  Consider how origin trials and trial tokens interact with these technologies. Origin trials allow developers to experiment with new web platform features. Trial tokens are the mechanism for enabling these features on specific origins.

4. **Look for logical reasoning and examples:**  Identify tests that validate the logic of the `TrialToken` class. Pay attention to tests that use different inputs and check the outputs. Construct hypothetical scenarios if needed.

5. **Identify potential usage errors:**  Focus on tests that check for malformed tokens, invalid signatures, incorrect versions, etc. These represent common errors developers might make when dealing with trial tokens.

6. **Address the "part 2" aspect:**  Since this is part 2 of the analysis, ensure that the current summary builds upon the understanding developed in part 1. The key is to consolidate the functionality observed in this specific code snippet.

7. **Structure the answer:** Organize the findings into logical categories:
    * Core functionality (testing).
    * Relationship to web technologies.
    * Logical reasoning examples.
    * Common usage errors.
    * Summary of functionality.

8. **Refine and clarify:**  Ensure the language is clear and concise. Provide concrete examples where possible. Avoid jargon or explain it if necessary. Double-check for accuracy.

**Pre-computation/Pre-analysis (based on the code):**

* **Token Structure:** The code deals with the structure of trial tokens, which includes a version, payload (JSON), and signature.
* **Validation Logic:**  Tests validate the origin, feature name, and expiry date of a token.
* **Error Handling:** Tests cover various error conditions like invalid signatures, malformed tokens, and incorrect versions.
* **Subdomain Matching:**  Some tests specifically focus on tokens that apply to subdomains.
* **Third-party Context:** The code introduces the concept of third-party usage restrictions for trial tokens.

**Example of applying the thought process to a specific test case (e.g., `TEST_F(TrialTokenTest, ExtractValidSignatureVersion2)`):**

1. **Purpose:**  Test the extraction of the signature from a valid version 2 token.
2. **Mechanism:**  Calls the `Extract` method, passing in a valid token string and the correct public key.
3. **Assertions:** Checks that the extraction was successful, the version is correct, the payload matches the expected JSON, and the extracted signature is correct.
4. **Relation to web tech:**  This relates to how browsers verify the authenticity of trial tokens.
5. **Logical reasoning:** The test confirms that the signature verification process works for valid version 2 tokens.
6. **Usage errors:**  Implicitly tests that providing an invalid signature would fail.

By applying this process to each test case, a comprehensive understanding of the file's functionality can be built.
这是对`blink/common/origin_trials/trial_token_unittest.cc` 文件第二部分的分析总结。结合第一部分，我们可以归纳出该文件的主要功能是：

**核心功能：对 Origin Trial Token 的解析、验证和提取进行单元测试。**

该文件包含了一系列单元测试，用于验证 `TrialToken` 类及其相关函数的行为是否符合预期。 这些测试覆盖了以下几个关键方面：

**1. Token 提取 (Extraction):**

* **验证不同版本的签名:** 测试了从不同版本 (Version 2 和 Version 3) 的有效 token 中提取签名、payload 和版本号的功能。
* **验证子域名和非子域名的签名:** 测试了能够正确提取针对子域名和非子域名 token 的签名。
* **验证第三方和非第三方上下文的签名:**  测试了能够正确提取在第三方和非第三方上下文中使用的 token 的签名。
* **验证不同 Usage Restriction 的签名:** 测试了能够正确提取具有不同使用限制（例如：允许在所有上下文或仅在子集上下文中使用）的 token 的签名。
* **处理无效签名:** 测试了当 token 签名无效时，能够正确识别并返回错误状态。
* **处理密钥不匹配的情况:** 测试了使用错误的公钥尝试提取签名时，能够正确识别并返回错误状态。
* **处理 malformed 的 token:** 测试了当 token 格式不正确（例如，过短、版本号错误、签名长度错误）时，能够正确识别并返回错误状态。
* **处理过大的 token:** 测试了能够识别并拒绝处理超出大小限制的 token。

**2. Token 解析 (Parsing):**

* **解析有效 token 的各个字段:** 测试了能够从 JSON 格式的 payload 中正确解析出 feature name、是否匹配子域名、origin 和过期时间等关键信息。
* **解析不同类型的有效 token:** 测试了能够解析非子域名 token、子域名 token 和包含较长 feature name 或 origin 的 token。
* **处理无效的 JSON payload:** 测试了当 token 的 JSON payload 无效时，能够正确识别并拒绝解析。

**3. Token 验证 (Validation):**

* **验证 Origin:** 测试了 `ValidateOrigin` 方法能够正确判断 token 的 origin 是否与给定的 origin 匹配。包括了对子域名匹配规则的验证。
* **验证 Feature Name:** 测试了 `ValidateFeatureName` 方法能够正确判断 token 的 feature name 是否与给定的 feature name 匹配（大小写敏感）。
* **验证日期 (Expiry Time):** 测试了 `ValidateDate` 方法能够正确判断 token 是否已过期。
* **整体验证 (IsValid):** 测试了 `IsValid` 方法能够综合验证 token 的 origin 和过期时间，并返回相应的状态。

**与 JavaScript, HTML, CSS 的关系举例说明:**

* **JavaScript:** 当网站使用 JavaScript 代码尝试启用一个 Origin Trial 特性时，浏览器会检查是否存在与当前页面 origin 匹配的有效 Trial Token。`TrialTokenTest` 中的 `ValidateOrigin` 和 `IsValid` 测试就模拟了这个过程。例如，一个测试用例可能会验证一个针对 `https://example.com` 的 token 是否能被 `example.com` 域名下的 JavaScript 代码成功验证。

* **HTML:**  可以在 HTML 的 `<meta>` 标签中使用 `http-equiv="origin-trial"` 来声明 Origin Trial Token。 浏览器解析 HTML 时会提取这个 token 并进行验证。 `TrialTokenTest` 中的解析测试 (`ParseValidToken`) 就模拟了这个过程，确保浏览器能够正确解析 HTML 中声明的 token。

* **CSS:**  Origin Trials 可能会影响 CSS 功能的行为。 虽然 Token 本身不直接涉及 CSS 语法，但浏览器在解析和应用 CSS 时，会依赖于 Origin Trial 的状态。  如果一个 CSS 特性被 Origin Trial 保护，浏览器会先检查是否存在有效的 token。`TrialTokenTest` 中测试的整体验证流程 (`IsValid`) 间接影响了 CSS 特性的可用性。

**逻辑推理的假设输入与输出:**

假设我们有一个针对 feature "SuperFeature" 的 token，其 payload 如下：

```json
{
  "origin": "https://test.example",
  "isSubdomain": false,
  "feature": "SuperFeature",
  "expiry": 1678886400
}
```

* **假设输入 (ValidateOrigin):**  `ValidateOrigin(token, url::Origin::Create(GURL("https://test.example")))`
* **预期输出:** `true`

* **假设输入 (ValidateOrigin):**  `ValidateOrigin(token, url::Origin::Create(GURL("https://sub.test.example")))`
* **预期输出:** `false` (因为 `isSubdomain` 为 false)

* **假设输入 (ValidateFeatureName):** `ValidateFeatureName(token, "SuperFeature")`
* **预期输出:** `true`

* **假设输入 (ValidateFeatureName):** `ValidateFeatureName(token, "superfeature")`
* **预期输出:** `false` (大小写敏感)

* **假设输入 (ValidateDate, 当前时间戳为 1678800000):** `ValidateDate(token, base::Time::FromSecondsSinceUnixEpoch(1678800000))`
* **预期输出:** `true` (未过期)

* **假设输入 (ValidateDate, 当前时间戳为 1678900000):** `ValidateDate(token, base::Time::FromSecondsSinceUnixEpoch(1678900000))`
* **预期输出:** `false` (已过期)

**用户或编程常见的使用错误举例说明:**

* **错误的 Token 字符串:** 用户可能复制粘贴 Token 时出错，导致 Token 字符串不完整或包含多余字符。  `ExtractShortToken` 和 `ExtractMalformedToken` 等测试覆盖了这种情况。
* **使用了过期的 Token:** 开发者可能没有及时更新已过期的 Token。 `TokenIsValid` 和 `SubdomainTokenIsValid` 测试用例中就包含了对过期时间的验证。
* **Origin 不匹配:** 开发者可能在错误的域名下使用了 Token。 `ValidateValidToken` 和 `ValidateValidSubdomainToken` 测试用例验证了 Origin 匹配的逻辑。
* **Feature Name 拼写错误:** 开发者可能在代码中使用了错误的 Feature Name。 `ValidateFeatureName` 测试用例强调了 Feature Name 的大小写敏感性。
* **Subdomain 设置错误:** 开发者可能错误地认为一个非子域名的 Token 可以用于其子域名，或者反之。 `ValidateValidSubdomainToken` 测试用例明确了子域名匹配的规则。
* **使用了错误的公钥进行验证:** 如果使用了与生成 Token 时不同的公钥进行验证，则会导致验证失败。 `ExtractSignatureWithIncorrectKey` 测试用例模拟了这种情况。

**总结该部分的功能:**

这部分的代码主要集中在对 Origin Trial Token 进行更细致的提取和验证测试，特别是针对不同版本的签名、子域名和非子域名、第三方和非第三方上下文以及不同 Usage Restriction 的 Token 进行了详尽的测试。 这些测试确保了 `TrialToken` 类能够准确地解析和验证各种类型的有效 Token，并能够正确地处理各种错误情况，从而保证了 Origin Trial 功能的稳定性和安全性。

Prompt: 
```
这是目录为blink/common/origin_trials/trial_token_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
ydXJtZzN2dG5pd3FxbTI4emZoOGp2bTR1MnZhMGhsb2huaW"
    "81dGl0empxenp3dmxiZHpmN3pseXdsZ2JpbHB5eG5tbWlpcnk4Zzdpc3o0dm0zc3ZuanR5YXlj"
    "bm9wOWhzd25ta3Njc2E1NmwwZTlqcjN5eXk5dzd0d2pycTdmcnFkempraHNyMGl1NmFucmFtbW"
    "F5d2dscmdwb29ucTg0OWtvaG8zNWx0aDBzeml1ZzRrb2w4aTdicWtncWNmeG1rNnBoMGZuMjdn"
    "Ymdsdml4dG9ucW14eGhoYzI5bGNodmhraWY4eXZkdmVkYXVybmt4dXB5bHN6N2NucGl2YjR3Ym"
    "dya3JheWhpdzIwaGZiMWtjNGdudGtxaHBpbnR6c21pNDQ3ZnkyOWx5andsamJuc3hhaG1kYWVp"
    "amVnYmM0aGZwbGZhOHdkMHE0cWpieHR1ZnNjaWJiamY2YXNnYjV2dWV6Y2FwenZ4bXhpdGVhc3"
    "R4aXVpenVlaDV4cncxbHk3aHBzYnliaGltbmp6cDB4cDZwb2thc2hlYmhpcTMxZnZnbWVvdG9n"
    "NHY0M2huc3Uzenp0bGRveGxobG9teGttNmZndHh3OHhtOHQ0dTJtemNmMWFwZXNxdXF3ejV5d3"
    "ludXUwb2JyZWkycWlwcW5sdWVzaG01c3AxMndscTZoOW4wdTZ3cmF1cXRkN2hrZnJ1bmFleWVs"
    "NWphNnptZWp6cGJkeXEyNnRncGo5eXY4bThtZXducmZxd29zZ2Y3aG5oNHI3aXZ5OGN4NXgxcG"
    "lpd3NvZHh2ODVjeWltczU3MTE2Zm56YWcya3h0dG16cTc1dXJ6MWEydDBhazR5empxejRkNjZi"
    "ZGJ5dmU0bmJoc2VsN2NwN2h3bnQ4NWIya3RiOGlwZG95Mmc1dmx0b29ydXB5NDN5aWhxdWd0cG"
    "dhcGo2eXIzOWd5eGNlaW9vZ284cGM2c2lqZ2ZoYml1NmZ1aGIwcW9jeGprcHJvOHlycXphaXR3"
    "d3l3b2xnZ2Fzbnl0bnhlazV3aHhwd3ZnMHA1aWRrbHBnNWZjaHlpbXJmYWx1Yzl2N3U0dWJvbW"
    "hkaWlyajF1YjBnaTRlc2dxazhjdHJiajByOXBpNGM3eGoyMTR2bWQ2Mzhub3JxcDNtaGpob2Yw"
    "NHVxbnJjaDRmbnN5emhyZmJlczZhY2VodW9qc2hucjd0OTFvam8xdno1ZHF2am83NzY5amJ5bn"
    "p6dW02amkuY29tOjk5OTkiLCAiaXNTdWJkb21haW4iOiB0cnVlLCAiZmVhdHVyZSI6ICJUaGlz"
    "VHJpYWxOYW1lSXMxMDBDaGFyYWN0ZXJzTG9uZ0luY2x1ZGluZ1BhZGRpbmdBQUFBQUFBQUFBQU"
    "FBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUEiLCAiZXhwaXJ5IjogMTQ1"
    "ODc2NjI3N30=";
const uint8_t kLargeValidTokenSignature[] = {
    0xad, 0x70, 0x19, 0x2d, 0x70, 0x14, 0xf0, 0x53, 0xfd, 0x2d, 0x2d,
    0x45, 0xb5, 0xc8, 0x84, 0xee, 0x9f, 0x9e, 0xd7, 0x37, 0x1a, 0xe0,
    0xda, 0x70, 0x03, 0xc0, 0x71, 0xf4, 0xc1, 0x33, 0x19, 0x1d, 0x5e,
    0x98, 0x17, 0x24, 0xc1, 0x11, 0x55, 0xc5, 0x44, 0x54, 0xd7, 0xd9,
    0x02, 0xed, 0x65, 0x68, 0xa1, 0xe1, 0x31, 0x48, 0xd3, 0xa7, 0x4a,
    0x4e, 0x20, 0x18, 0xbf, 0x2b, 0x25, 0x97, 0xac, 0x04};

// Valid token that is too large, size = 4100 chars. The feature name matches
// kExpectedLongFeatureName (100 characters), and the origin is 2833 chars.
// Generate this token with the command:
// generate_token.py --is-subdomain --expire-timestamp=1458766277 \
//   2 https://www.<4348 random chars>.com:9999 \
//   ThisTrialNameIs100CharactersLongIncludingPaddingAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
const char kTooLargeValidToken[] =
    "AswTUJEo9qF5QaVITkRzMQ+muYHK13+"
    "IFGmg6ZGTiAlHtdIzOS0Kbngkgk3OM43Z8sRVCVq6bl7lCGrjmG3l/"
    "gUAABG8eyJvcmlnaW4iOiAiaHR0cHM6Ly93d3cuYWFwMDdobW9yendvY254bGZnZ3N1ZmplbWY"
    "zamViaDh2MzQxMnBxb3ZzbGh0Y2IyM3ppejVhaG1nZTh3aG03eGZzb2ExdmFuNXhqb2poZ3Jje"
    "nphdng1Mm5raW1zd3ZrdmpvMXFzZmc0dHAxc2NtY3dvNjU3Z3diNG0zdWl6cTJtNHhianpoemp"
    "vMjA1aTltdHNrN2ZrMmdpYXNycmwwNGt0a2xnbnc0aHJkcThib3NnamdvcDA2dWt3ZXY5dTJhe"
    "HZ3a2VuaDY5bjhyNjEzemhtaG5nY3Qxcm5lbGNoa2ZyMXBmcndoN3NnZTlnbGRudHZ5Y296NnM"
    "3YWg1b2dyZWdtOHoxNzduY3p3Y2FsM3k5dnFhaWhrdjN3cTJ0MnZqaWZ1MXZiY244aGd4b3Y2N"
    "mVhNTB2eWdsdXNiazBwcXRqaWFibGdmaWxweHNmeDh3cWJ0ajllaTl4cjJsaXRydXBjbWloeWV"
    "leGl6aHBtNzltcG9zeHp0eDB0eWd0b3hwMWN0Y2JkdHpwbGVydmN5dTdlbnZia2R4OGNweGNjM"
    "jJzYjZhdm93YnZ1ZWhiaXJkdnBrbXp6anV1b2NnY3p5ZW5iNmdnbGU2NjJnemU1c29jN2NwaDN"
    "5ZDlpajIwYXdlbGYwd3pseWpjMnN6eDQwZ2NteWJlMnhxeGF2dXo4YWxiMWRscnp1eXNpeDVxN"
    "mt0NXV1ZHIweHRvbmpwb3Ftem5jaGJtaG0wb3AyNnc5bGQ2amlxY3FwdWo1ZWl2Y3d6amM5OHN"
    "nNGhlMXl4cWhqeHdyZ2hnczlqaDFzaHJ6aXU5ZmllcTl5aHI4NHlhdjRxdWxrdGdmdW5hczF5Z"
    "WF1bGw0MHJ4a2lmOGdmenptaHZwdmo1enhlYXF6bXN0cDZmZmtseDV0bzByamdtajlhb3BueTF"
    "6enhsbWpqZW5uMW9ranIwM2Uxdm54bG9tYTl4dDNwd2FpdHp6bjFtbmJucmVhaGxyd3oyZXFvc"
    "HBhMHhna3Vlb3RrMmdqbnN6eXl1d2Vla3lic245OXF4eDU0d3FheHNwNzR2Z2IxMm05bnllbGx"
    "0dHdhbWlvOWpnMHd6bTFwbWo2YTNkaHVxMHlscmVzNXhnbHZsanlrbWZvMml6dGZ3amViZG1md"
    "Hl4OHh0ZWxnN3Q5d3phYW11eXV1dzR6NXprMmhwYmxpd3Z2b2NwODg2YThkYm9zdjVlZmszamd"
    "renpxZ3ZvMHphcDJ4ZTlzOWp2YW81bjVreHpjemp6OGl6MW95NTZkYnh2cTluYzlmN2ZwdXhsO"
    "GI1N2o3a3ZlNW5qenBwa2FhcGJ2cHZ6NWU3enFlcmw3ZjJ3cGZ4eDNjbXZ6YmdqZXQxcHpjOGl"
    "2cXhmbWpob3ZsbzVzcXk4cXM1djh0Y3p3YnlmZXFrejBrNmVha2Z5Ym10ZmJvZnp4ODF6ZXNvO"
    "G1oeHNzMXdhem11ZnR4cXhiY3d4c2ZwemUzems5Zzk2ZHZlaG51ajdncGpscnN6Z3c0NnhmN2w"
    "xdHVuYWhmdnZhMXBzenhldmFiOTlzbWx5bDZvNDBhbjFoZ3c0Z2txa2Job2pxdHljZ2NzaGRrd"
    "HZta3J2cm9pYm9sYWs3OGJvbWdvZXFqMmN5bXJ6dmlkbHUzYnp4bm95ZHdnZzd0enFhd216cWh"
    "ldnh6c2Y4eWE0eHpsamJxa3lnbDlsYmEyMXBucnNwOG9lcmh4dm1leHV5eHZhNGlmc3FvN2s2d"
    "zY0cm1hdmdmdjc1eXZ5NWFhbXlzeG96eWU4bnF6aTYwdzR2MXhnYXdjOXY2eW1hazJvczdxNWw"
    "2enJibDJpYmZnemZhendhNHI1N2xndmY5NWRwajN4d2NjYW03bzFzYXRicXp3NTNnbXZ0cGJsb"
    "GM2OGhueHBnem1menhhbHJ3dG5vMXJjbXF4ZTJ5azVoaDN4ZmE0d3o5cG5xamtmY290ZXhiZzF"
    "4Z3N3anB6YnhvNGdxMmc4bTd2aGtkMHpuMWpmZWlrd3l2N21ia2t0anh3NHo3c21scnAzMzM4d"
    "3JvN2s1cWtoYmtvYTIwd2Rma2g4MGFjemY5dWhldzlhdmMzOGl1dGI5c29mamlmYmJmdTBiNWh"
    "kaDl3a2NuaDd1NWJmajVlMTZwZnpqamlsZ2FybzV0M2F6dHd6MnRuZmk3cDhsc2xvZGhuOGp6c"
    "WJyOXhuMjN4Zmw1dWhucmxzczFkam5pbWljc2FiemRlYWxid2s2Ymc3am1sZm0yeXZ6cDFyY2x"
    "5OXZ2cjZ1Y2Z2Zmxpa3hrcW1senpkNXNpZjR2Z2JpczQxY3Nwc2N6bnR0dnd5b2Juc2RuZndnc"
    "2dka2gwbWUzNGpsaTh0b3FxaHh5c211dzJlM29wZ20waGluY2JtZ3hxanhvdGJvdXlyNHJ5dG5"
    "uemlwYnRxcWlzZXQwcWxkdWFwcnFtdWdvMTFub29rc2dyenpnZTd2a3p3N3F2eWF1b2V6eHMyc"
    "XlrNHM5cm9pdmlseGpiazVtZmp0Y2JrdXZ1c2FtYzd0aGFkYXVmcHZheHRnZXJjZ3Bjcnh3eWd"
    "4djZ3dnE1d3kyd3ZmZDNqd3Nza3NvY2xod2ZneGpiYWhydWhyeWd1NnZmZ3ZuN3ZueWN2Mmd3b"
    "mdoaXBieDFubnRuc3M4cTZwMzl2bnVua3UyZWtudWJwbmpwYXd6bjJwZmRzcnA2NnM3YWZhYWd"
    "pam10eXNlZ2U0eXV0eGpnODR3cms4dTZnOHdkbWtjaG9zeWJvNnJibnNtY3RsdzMzZWF5Z3duZ"
    "DZvZ2ppeG9ocG5uNmFoZzIycm5tbHd2NXBnaXpleXRvN3dhMWVnaXB1dHVxdGxpYTVwdmRzdXd"
    "pamtqeWUxbjhoangxdGpsa3lrZTJ3bWMyYWhkcmh5Nml6ajJsY2VremJ4MWhxYmFzYzV6emJ0c"
    "zN3bGIwbWJ0ZHFwYXYyeHd6bWdnMXo1cnNwaGYwbHZpbGdwb2FnZWl1cXJzNWpuZ3hzeW9hcXg"
    "yY3ZodHZva3g0bWc2bmh2bm5mYnhuMG0zcmU3N2FqeHNsd3IwdmxqMDN0bG11dnJpYmxoNGRld"
    "zJxamRxbW5jbmU0dWZ0Y2dvdHNidXdjd3p2ejNld291emtyZXdrNWx3c29waXVlN3k0amYzbnR"
    "1eHV0b3hiYTV4b29lNGpocnV4cmdrZmI4bmxubXFrNmp2bHFmMG9jM2Nzb3J5cnZzbTNxc2l5e"
    "mZwYmlkYXpxdnlraTl2YXFldHI5ODdlbmpmNzB1aWx4eHJhc3Jha3NjcjZxNmprdmJtaXBrY2R"
    "lbHlkZ3B5OGJqbWN2dW15d21qaGNyZ3h1enB4ZThhZXpiZWdlaDhidnlzOGJudml5b29lcTA1Y"
    "jAyejdpY2ljbTJ3ZnY1cmNwcDdjd3QzdXVzMWNzdG5yNnJtb2cxZWZqaGlwbjM0M2I1Z2hpYXZ"
    "oeGc1cWM0ODVvbDM5ZWJ0bWZxb296bmJicnZienlqc2poZ2tmcTdzMXJ3c2hieHpsYmVoenhxd"
    "G41d21zb2h2YWh0dW9jbHo1cDJsb3JldXl5MG9yYzR6c3E5bWNlZ3dibnltYnJ6Y2d5Z20xcnV"
    "qeXJiOGN1bWY1YnRtcDY3Ynl6NmE3MDAyc2kwM3hua2Jyb3J2c2Vvams5enNpeG5kOWp1YmV0O"
    "XpyeXBoY2Z2cWVyOWp1cm1nbWJoazBwOG9xdDVudGh6a2pkY2FtOWpvbDJzYTlubWRrdXc0ZzR"
    "2ZnZ5Y3k2ZmJ4Ynd1MGphcGtjYzFzZmJqazQxM2licGpqeGljZXlweGp3cmxjZHd0ZXBjZXNkY"
    "3FocHo4dGNwbDYzczRrOW5ubmNldm5hajA2OGhsY3N6NWRxb3pneHN0NTVyZ21tMWcxaXd4eHg"
    "3YWh0a3psdG9xMTJpZm1temp1d3ozcHlvd2RmaDdta29jYzFxdXR4c254eTN1NHZpcDZiYzNtd"
    "280aXd5aWVtNnowbXZuanpqY3l1MnZhbnpqOHR4YTZ3enlqY253ZmZtMHlqdmt1MnV4dDdrYTN"
    "0bXZ6eXB6M2puMnN5eXM2ZmFwa3J1eHpudWFueGJocHNyc2FiMmR6MmE2N3JubDVnMW9mZndtb"
    "G5ybmV5MWs0eWtzcmVqd2wyN2FqdGp1MWh3OGZ5OGhsZHlkdmdxbnZxa3pvMzF3bml1eGYzem5"
    "3em9mOXQ3bGJxcnAxemVld2s0dzZrbGdvZWczdnEya2ZkaWR6NGtyZjZ2bWtwYzRnZjVzZml1Z"
    "nFraHhhb2dpZmhtdGt1dWZhcWJsaHR6YWc2d2h0MWF6dzBjdnZ6bms4bTh0dDhqZzM5anR6OGV"
    "0aHp3bnFvN3lxczhwdzA3YWlndXR1cmtocm5qMTdoc3E4dnhoZzlqaDhjd214Y3RpNjN2NnVmN"
    "2R1eG1yeGhtOGhuZTZveHZ4ZHZzaDIybjl0NWQ2ZjQzdWtrdDAwYjRmbG1yYmRtaGM0aHVraDJ"
    "sbGJ3OHg1cHBnMGgxa2Z3NndxZjVhZXZrbHBlbGdodmFwM3pxcG5qeHhtcmFveGl5emNtYndzc"
    "2x1czR2NXBxdnVxYmhuYW14em8wb21qcGFzb3RwbHVwcW91dmVuZmxjdGVvNmZqOTdjYW5tejN"
    "kYzJ6ZmtjeHdzaWpqa2V1Mm9vMDNxdWhpcGhrYXN1djdybnlqYmJoMWEwdDNueXdjeWJxaXk0c"
    "XFhaGZnMXlmdGtjcDV4b3dzamlmMWUxaHJiaWtjamwwY3oya2Mwc3JoMXVxYThtcmZjMnpzY2h"
    "2ZW16ejZsbDJuZXh0MDFyOWFreHl2YWo1dWU2eW5rYmZmdGlnY3Jjc2d6MG1ncm1zazl1MnN5N"
    "GZ6c2V2em4zeWRvY2pvNTU1cHV2enl3YXNzbnI2YWE0bmx3ZHkwcXBxdnpicWdreXV3cmptMnR"
    "nenpqb211N3ZmanhtbGJoN29uY3V1MXU2d3R4czM3b2xxd3F3bnJpdnJ2bG53Z3FqdGJqb3R2N"
    "2JqeGRqaWFkcjBndW0zdWp5OGZteHc3aWUzcHdpYmg4dWF1aDVjZW9ja3ZtOGw3YWthYXFhcmV"
    "0bmZycnR6bml3eWVkeWh1NGt4d2tyODJkaWt6b3Y5ZnZrajNwaDh2ZW5wb296dDlscG5pdGlra"
    "zFndW5vbHRrbnBqZHJzMXRudm42anJ2eGoybWY1aGJsd2x3enZ4d2Znc3ZxdGkxNXcyMHIxZWp"
    "nM3BhY3V0NjY2MXFjYnVoeGhueG51aG80ajN2eHNscWZ2Z3htYTNoYjZ4bTJ3bmlidmZiNXFvN"
    "nJ4cXV0Y2hmbGcxZmdzenF0MnlsaTV1dnFxcnFjZXBqaXBvZjF1ajlvNHFpeXJteGhxNnBjemV"
    "hMjRrejV4bzJnaGh5b29sNmZ4cTE2YnVxeGtpa2Vnd2JsbHhyb245NWhoYW85MnlmdXBmN2lsa"
    "mhod2NsemdsZjJxeTNmcGdveXhqaWJubnR4ZjJnZnlteWU5bW9rdnB4NXlkdnFubG5veHlrdGN"
    "oNDB2c3Z5ZnQ3dmJndHA4ZTh0dmg3dTFpamxlcXJzdXR0eWRteHZvejhrd2MyYjdsZmt0dndic"
    "2h1cXZsc2VkZXB4dGd5Y20waGVnZTdpcWV5MG1zZnduemZhejBob2w2ZHBwdjI1dHVlYTlodmx"
    "mb3d2NWl0bGtiajNpcW03eGhzZzl6eG94bWVzdzI2N2xtdHB1Y28xa2hvem10NHl0MGk1cHMyb"
    "zh2em9keHdmeTBrb2VpYjJwbGZ0eGc0d280cnRncHV6Zmh4NGlzejhuMGdwZW5ndC5jb206OTk"
    "5OSIsICJpc1N1YmRvbWFpbiI6IHRydWUsICJmZWF0dXJlIjogIlRoaXNUcmlhbE5hbWVJczEwM"
    "ENoYXJhY3RlcnNMb25nSW5jbHVkaW5nUGFkZGluZ0FBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUF"
    "BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQSIsICJleHBpcnkiOiAxNDU4NzY2Mjc3fQ==";

}  // namespace

class TrialTokenTest : public testing::Test {
 public:
  TrialTokenTest()
      : expected_origin_(url::Origin::Create(GURL(kExpectedOrigin))),
        expected_subdomain_origin_(
            url::Origin::Create(GURL(kExpectedSubdomainOrigin))),
        expected_multiple_subdomain_origin_(
            url::Origin::Create(GURL(kExpectedMultipleSubdomainOrigin))),
        invalid_origin_(url::Origin::Create(GURL(kInvalidOrigin))),
        insecure_origin_(url::Origin::Create(GURL(kInsecureOrigin))),
        incorrect_port_origin_(url::Origin::Create(GURL(kIncorrectPortOrigin))),
        incorrect_domain_origin_(
            url::Origin::Create(GURL(kIncorrectDomainOrigin))),
        invalid_tld_origin_(url::Origin::Create(GURL(kInvalidTLDOrigin))),
        expected_expiry_(
            base::Time::FromSecondsSinceUnixEpoch(kExpectedExpiry)),
        valid_timestamp_(
            base::Time::FromSecondsSinceUnixEpoch(kValidTimestamp)),
        invalid_timestamp_(
            base::Time::FromSecondsSinceUnixEpoch(kInvalidTimestamp)),
        expected_v2_signature_(
            std::string(reinterpret_cast<const char*>(kSampleTokenV2Signature),
                        std::size(kSampleTokenV2Signature))),
        expected_v3_signature_(
            std::string(reinterpret_cast<const char*>(kSampleTokenV3Signature),
                        std::size(kSampleTokenV3Signature))),
        expected_subdomain_signature_(std::string(
            reinterpret_cast<const char*>(kSampleSubdomainTokenSignature),
            std::size(kSampleSubdomainTokenSignature))),
        expected_nonsubdomain_signature_(std::string(
            reinterpret_cast<const char*>(kSampleNonSubdomainTokenSignature),
            std::size(kSampleNonSubdomainTokenSignature))),
        expected_third_party_signature_(std::string(
            reinterpret_cast<const char*>(kSampleThirdPartyTokenSignature),
            std::size(kSampleThirdPartyTokenSignature))),
        expected_non_third_party_signature_(std::string(
            reinterpret_cast<const char*>(kSampleNonThirdPartyTokenSignature),
            std::size(kSampleNonThirdPartyTokenSignature))),
        expected_third_party_usage_empty_signature_(
            std::string(reinterpret_cast<const char*>(
                            kSampleThirdPartyUsageEmptyTokenSignature),
                        std::size(kSampleThirdPartyUsageEmptyTokenSignature))),
        expected_third_party_usage_subset_signature_(
            std::string(reinterpret_cast<const char*>(
                            kSampleThirdPartyUsageSubsetTokenSignature),
                        std::size(kSampleThirdPartyUsageSubsetTokenSignature))),
        correct_public_key_(kTestPublicKey),
        incorrect_public_key_(kTestPublicKey2) {}

 protected:
  OriginTrialTokenStatus Extract(const std::string& token_text,
                                 const OriginTrialPublicKey& public_key,
                                 std::string* token_payload,
                                 std::string* token_signature,
                                 uint8_t* token_version) {
    return TrialToken::Extract(token_text, public_key, token_payload,
                               token_signature, token_version);
  }

  OriginTrialTokenStatus ExtractStatusOnly(
      const std::string& token_text,
      const OriginTrialPublicKey& public_key) {
    std::string token_payload;
    std::string token_signature;
    uint8_t token_version;
    return Extract(token_text, public_key, &token_payload, &token_signature,
                   &token_version);
  }

  std::unique_ptr<TrialToken> Parse(const std::string& token_payload,
                                    const uint8_t token_version) {
    return TrialToken::Parse(token_payload, token_version);
  }

  bool ValidateOrigin(TrialToken* token, const url::Origin origin) {
    return token->ValidateOrigin(origin);
  }

  bool ValidateFeatureName(TrialToken* token, const char* feature_name) {
    return token->ValidateFeatureName(feature_name);
  }

  bool ValidateDate(TrialToken* token, const base::Time& now) {
    return token->ValidateDate(now);
  }

  const OriginTrialPublicKey& correct_public_key() {
    return correct_public_key_;
  }
  const OriginTrialPublicKey& incorrect_public_key() {
    return incorrect_public_key_;
  }

  const url::Origin expected_origin_;
  const url::Origin expected_subdomain_origin_;
  const url::Origin expected_multiple_subdomain_origin_;
  const url::Origin invalid_origin_;
  const url::Origin insecure_origin_;
  const url::Origin incorrect_port_origin_;
  const url::Origin incorrect_domain_origin_;
  const url::Origin invalid_tld_origin_;

  const base::Time expected_expiry_;
  const base::Time valid_timestamp_;
  const base::Time invalid_timestamp_;

  std::string expected_v2_signature_;
  std::string expected_v3_signature_;
  std::string expected_subdomain_signature_;
  std::string expected_nonsubdomain_signature_;
  std::string expected_third_party_signature_;
  std::string expected_non_third_party_signature_;
  std::string expected_third_party_usage_empty_signature_;
  std::string expected_third_party_usage_subset_signature_;

 private:
  OriginTrialPublicKey correct_public_key_;
  OriginTrialPublicKey incorrect_public_key_;
};

// Test the extraction of the signed payload from token strings. This includes
// checking the included version identifier, payload length, and cryptographic
// signature.

TEST_F(TrialTokenTest, ExtractValidSignatureVersion2) {
  std::string token_payload;
  std::string token_signature;
  uint8_t token_version;
  OriginTrialTokenStatus status =
      Extract(kSampleTokenV2, correct_public_key(), &token_payload,
              &token_signature, &token_version);
  ASSERT_EQ(OriginTrialTokenStatus::kSuccess, status);
  EXPECT_EQ(kVersion2, token_version);
  EXPECT_STREQ(kSampleTokenJSON, token_payload.c_str());
  EXPECT_EQ(expected_v2_signature_, token_signature);
}

TEST_F(TrialTokenTest, ExtractValidSignatureVersion3) {
  std::string token_payload;
  std::string token_signature;
  uint8_t token_version;
  OriginTrialTokenStatus status =
      Extract(kSampleTokenV3, correct_public_key(), &token_payload,
              &token_signature, &token_version);
  ASSERT_EQ(OriginTrialTokenStatus::kSuccess, status);
  EXPECT_EQ(kVersion3, token_version);
  EXPECT_STREQ(kSampleTokenJSON, token_payload.c_str());
  EXPECT_EQ(expected_v3_signature_, token_signature);
}

TEST_F(TrialTokenTest, ExtractSubdomainValidSignature) {
  std::string token_payload;
  std::string token_signature;
  uint8_t token_version;
  OriginTrialTokenStatus status =
      Extract(kSampleSubdomainToken, correct_public_key(), &token_payload,
              &token_signature, &token_version);
  ASSERT_EQ(OriginTrialTokenStatus::kSuccess, status);
  EXPECT_EQ(kVersion2, token_version);
  EXPECT_STREQ(kSampleSubdomainTokenJSON, token_payload.c_str());
  EXPECT_EQ(expected_subdomain_signature_, token_signature);
}

TEST_F(TrialTokenTest, ExtractNonSubdomainValidSignature) {
  std::string token_payload;
  std::string token_signature;
  uint8_t token_version;
  OriginTrialTokenStatus status =
      Extract(kSampleNonSubdomainToken, correct_public_key(), &token_payload,
              &token_signature, &token_version);
  ASSERT_EQ(OriginTrialTokenStatus::kSuccess, status);
  EXPECT_EQ(kVersion2, token_version);
  EXPECT_STREQ(kSampleNonSubdomainTokenJSON, token_payload.c_str());
  EXPECT_EQ(expected_nonsubdomain_signature_, token_signature);
}

TEST_F(TrialTokenTest, ExtractThirdPartyValidSignature) {
  std::string token_payload;
  std::string token_signature;
  uint8_t token_version;
  OriginTrialTokenStatus status =
      Extract(kSampleThirdPartyToken, correct_public_key(), &token_payload,
              &token_signature, &token_version);
  ASSERT_EQ(OriginTrialTokenStatus::kSuccess, status);
  EXPECT_EQ(kVersion3, token_version);
  EXPECT_STREQ(kSampleThirdPartyTokenJSON, token_payload.c_str());
  EXPECT_EQ(expected_third_party_signature_, token_signature);
}

TEST_F(TrialTokenTest, ExtractNonThirdPartyValidSignature) {
  std::string token_payload;
  std::string token_signature;
  uint8_t token_version;
  OriginTrialTokenStatus status =
      Extract(kSampleNonThirdPartyToken, correct_public_key(), &token_payload,
              &token_signature, &token_version);
  ASSERT_EQ(OriginTrialTokenStatus::kSuccess, status);
  EXPECT_EQ(kVersion3, token_version);
  EXPECT_STREQ(kSampleNonThirdPartyTokenJSON, token_payload.c_str());
  EXPECT_EQ(expected_non_third_party_signature_, token_signature);
}

TEST_F(TrialTokenTest, ExtractThirdPartyUsageEmptyValidSignature) {
  std::string token_payload;
  std::string token_signature;
  uint8_t token_version;
  OriginTrialTokenStatus status =
      Extract(kSampleThirdPartyUsageEmptyToken, correct_public_key(),
              &token_payload, &token_signature, &token_version);
  ASSERT_EQ(OriginTrialTokenStatus::kSuccess, status);
  EXPECT_EQ(kVersion3, token_version);
  EXPECT_STREQ(kSampleThirdPartyTokenUsageEmptyJSON, token_payload.c_str());
  EXPECT_EQ(expected_third_party_usage_empty_signature_, token_signature);
}

TEST_F(TrialTokenTest, ExtractThirdPartyUsageSubsetValidSignature) {
  std::string token_payload;
  std::string token_signature;
  uint8_t token_version;
  OriginTrialTokenStatus status =
      Extract(kSampleThirdPartyUsageSubsetToken, correct_public_key(),
              &token_payload, &token_signature, &token_version);
  ASSERT_EQ(OriginTrialTokenStatus::kSuccess, status);
  EXPECT_EQ(kVersion3, token_version);
  EXPECT_STREQ(kSampleThirdPartyTokenUsageSubsetJSON, token_payload.c_str());
  EXPECT_EQ(expected_third_party_usage_subset_signature_, token_signature);
}

TEST_F(TrialTokenTest, ExtractInvalidSignature) {
  OriginTrialTokenStatus status =
      ExtractStatusOnly(kInvalidSignatureToken, correct_public_key());
  EXPECT_EQ(OriginTrialTokenStatus::kInvalidSignature, status);
}

TEST_F(TrialTokenTest, ExtractSignatureWithIncorrectKey) {
  OriginTrialTokenStatus status =
      ExtractStatusOnly(kSampleTokenV2, incorrect_public_key());
  EXPECT_EQ(OriginTrialTokenStatus::kInvalidSignature, status);
}

TEST_F(TrialTokenTest, ExtractEmptyToken) {
  OriginTrialTokenStatus status = ExtractStatusOnly("", correct_public_key());
  EXPECT_EQ(OriginTrialTokenStatus::kMalformed, status);
}

TEST_F(TrialTokenTest, ExtractShortToken) {
  OriginTrialTokenStatus status =
      ExtractStatusOnly(kTruncatedToken, correct_public_key());
  EXPECT_EQ(OriginTrialTokenStatus::kMalformed, status);
}

TEST_F(TrialTokenTest, ExtractUnsupportedVersion) {
  OriginTrialTokenStatus status =
      ExtractStatusOnly(kIncorrectVersionToken, correct_public_key());
  EXPECT_EQ(OriginTrialTokenStatus::kWrongVersion, status);
}

TEST_F(TrialTokenTest, ExtractSignatureWithIncorrectLength) {
  OriginTrialTokenStatus status =
      ExtractStatusOnly(kIncorrectLengthToken, correct_public_key());
  EXPECT_EQ(OriginTrialTokenStatus::kMalformed, status);
}

TEST_F(TrialTokenTest, ExtractLargeToken) {
  std::string token_payload;
  std::string token_signature;
  uint8_t token_version;
  OriginTrialTokenStatus status =
      Extract(kLargeValidToken, correct_public_key(), &token_payload,
              &token_signature, &token_version);
  ASSERT_EQ(OriginTrialTokenStatus::kSuccess, status);
  EXPECT_EQ(kVersion2, token_version);
  std::string expected_signature(
      std::string(reinterpret_cast<const char*>(kLargeValidTokenSignature),
                  std::size(kLargeValidTokenSignature)));
  EXPECT_EQ(expected_signature, token_signature);
}

TEST_F(TrialTokenTest, ExtractTooLargeToken) {
  OriginTrialTokenStatus status =
      ExtractStatusOnly(kTooLargeValidToken, correct_public_key());
  EXPECT_EQ(OriginTrialTokenStatus::kMalformed, status);
}

// Test parsing of fields from JSON token.
class TrialTokenParseInvalidTest
    : public TrialTokenTest,
      public testing::WithParamInterface<std::tuple<const char*, uint8_t>> {};

TEST_P(TrialTokenParseInvalidTest, ParseInvalidString) {
  std::tuple<const char*, uint8_t> param = GetParam();
  std::unique_ptr<TrialToken> empty_token =
      Parse(std::get<0>(param), std::get<1>(param));
  EXPECT_FALSE(empty_token) << "Invalid trial token should not parse.";
}

INSTANTIATE_TEST_SUITE_P(TrialTokenTest,
                         TrialTokenParseInvalidTest,
                         testing::Combine(testing::ValuesIn(kInvalidTokens),
                                          testing::Values(kVersion2,
                                                          kVersion3)));

class TrialTokenParseInvalidVersion3Test
    : public TrialTokenTest,
      public testing::WithParamInterface<const char*> {};

TEST_P(TrialTokenParseInvalidVersion3Test, ParseInvalidString) {
  std::unique_ptr<TrialToken> empty_token = Parse(GetParam(), kVersion3);
  EXPECT_FALSE(empty_token) << "Invalid trial token should not parse.";
}

INSTANTIATE_TEST_SUITE_P(TrialTokenTest,
                         TrialTokenParseInvalidVersion3Test,
                         testing::ValuesIn(kInvalidTokensVersion3));

// Test parsing of fields from JSON token.
class TrialTokenParseTest : public TrialTokenTest,
                            public testing::WithParamInterface<uint8_t> {};

TEST_P(TrialTokenParseTest, ParseValidToken) {
  std::unique_ptr<TrialToken> token = Parse(kSampleTokenJSON, GetParam());
  ASSERT_TRUE(token);
  EXPECT_EQ(kExpectedFeatureName, token->feature_name());
  EXPECT_FALSE(token->match_subdomains());
  EXPECT_EQ(expected_origin_, token->origin());
  EXPECT_EQ(expected_expiry_, token->expiry_time());
  EXPECT_EQ(TrialToken::UsageRestriction::kNone, token->usage_restriction());
}

TEST_P(TrialTokenParseTest, ParseValidNonSubdomainToken) {
  std::unique_ptr<TrialToken> token =
      Parse(kSampleNonSubdomainTokenJSON, GetParam());
  ASSERT_TRUE(token);
  EXPECT_EQ(kExpectedFeatureName, token->feature_name());
  EXPECT_FALSE(token->match_subdomains());
  EXPECT_EQ(expected_origin_, token->origin());
  EXPECT_EQ(expected_expiry_, token->expiry_time());
}

TEST_P(TrialTokenParseTest, ParseValidSubdomainToken) {
  std::unique_ptr<TrialToken> token =
      Parse(kSampleSubdomainTokenJSON, GetParam());
  ASSERT_TRUE(token);
  EXPECT_EQ(kExpectedFeatureName, token->feature_name());
  EXPECT_TRUE(token->match_subdomains());
  EXPECT_EQ(kExpectedSubdomainOrigin, token->origin().Serialize());
  EXPECT_EQ(expected_subdomain_origin_, token->origin());
  EXPECT_EQ(expected_expiry_, token->expiry_time());
}

TEST_P(TrialTokenParseTest, ParseValidLargeToken) {
  std::unique_ptr<TrialToken> token = Parse(kLargeTokenJSON, GetParam());
  ASSERT_TRUE(token);
  EXPECT_EQ(kExpectedLongFeatureName, token->feature_name());
  EXPECT_TRUE(token->match_subdomains());
  url::Origin expected_long_origin(
      url::Origin::Create(GURL(kExpectedLongTokenOrigin)));
  EXPECT_EQ(expected_long_origin, token->origin());
  EXPECT_EQ(expected_expiry_, token->expiry_time());
}

TEST_P(TrialTokenParseTest, ParseTooLargeToken) {
  std::unique_ptr<TrialToken> token = Parse(kTooLargeTokenJSON, GetParam());
  ASSERT_FALSE(token);
}

TEST_P(TrialTokenParseTest, ValidateValidToken) {
  std::unique_ptr<TrialToken> token = Parse(kSampleTokenJSON, GetParam());
  ASSERT_TRUE(token);
  EXPECT_TRUE(ValidateOrigin(token.get(), expected_origin_));
  EXPECT_FALSE(ValidateOrigin(token.get(), invalid_origin_));
  EXPECT_FALSE(ValidateOrigin(token.get(), insecure_origin_));
  EXPECT_FALSE(ValidateOrigin(token.get(), incorrect_port_origin_));
  EXPECT_FALSE(ValidateOrigin(token.get(), incorrect_domain_origin_));
  EXPECT_FALSE(ValidateOrigin(token.get(), invalid_tld_origin_));
  EXPECT_TRUE(ValidateFeatureName(token.get(), kExpectedFeatureName));
  EXPECT_FALSE(ValidateFeatureName(token.get(), kInvalidFeatureName));
  EXPECT_FALSE(ValidateFeatureName(
      token.get(), base::ToUpperASCII(kExpectedFeatureName).c_str()));
  EXPECT_FALSE(ValidateFeatureName(
      token.get(), base::ToLowerASCII(kExpectedFeatureName).c_str()));
  EXPECT_TRUE(ValidateDate(token.get(), valid_timestamp_));
  EXPECT_FALSE(ValidateDate(token.get(), invalid_timestamp_));
}

TEST_P(TrialTokenParseTest, ValidateValidSubdomainToken) {
  std::unique_ptr<TrialToken> token =
      Parse(kSampleSubdomainTokenJSON, GetParam());
  ASSERT_TRUE(token);
  EXPECT_TRUE(ValidateOrigin(token.get(), expected_origin_));
  EXPECT_TRUE(ValidateOrigin(token.get(), expected_subdomain_origin_));
  EXPECT_TRUE(ValidateOrigin(token.get(), expected_multiple_subdomain_origin_));
  EXPECT_FALSE(ValidateOrigin(token.get(), insecure_origin_));
  EXPECT_FALSE(ValidateOrigin(token.get(), incorrect_port_origin_));
  EXPECT_FALSE(ValidateOrigin(token.get(), incorrect_domain_origin_));
  EXPECT_FALSE(ValidateOrigin(token.get(), invalid_tld_origin_));
}

TEST_P(TrialTokenParseTest, TokenIsValid) {
  std::unique_ptr<TrialToken> token = Parse(kSampleTokenJSON, GetParam());
  ASSERT_TRUE(token);
  EXPECT_EQ(OriginTrialTokenStatus::kSuccess,
            token->IsValid(expected_origin_, valid_timestamp_));
  EXPECT_EQ(OriginTrialTokenStatus::kWrongOrigin,
            token->IsValid(invalid_origin_, valid_timestamp_));
  EXPECT_EQ(OriginTrialTokenStatus::kWrongOrigin,
            token->IsValid(insecure_origin_, valid_timestamp_));
  EXPECT_EQ(OriginTrialTokenStatus::kWrongOrigin,
            token->IsValid(incorrect_port_origin_, valid_timestamp_));
  EXPECT_EQ(OriginTrialTokenStatus::kExpired,
            token->IsValid(expected_origin_, invalid_timestamp_));
}

TEST_P(TrialTokenParseTest, SubdomainTokenIsValid) {
  std::unique_ptr<TrialToken> token =
      Parse(kSampleSubdomainTokenJSON, GetParam());
  ASSERT_TRUE(token);
  EXPECT_EQ(OriginTrialTokenStatus::kSuccess,
            token->IsValid(expected_origin_, valid_timestamp_));
  EXPECT_EQ(OriginTrialTokenStatus::kSuccess,
            token->IsValid(expected_subdomain_origin_, valid_timestamp_));
  EXPECT_EQ(
      OriginTrialTokenStatus::kSuccess,
      token->IsValid(expected_multiple_subdomain_origin_, valid_timestamp_));
  EXPECT_EQ(OriginTrialTokenStatus::kWrongOrigin,
            token->IsValid(incorrect_domain_origin_, valid_timestamp_));
  EXPECT_EQ(OriginTrialTokenStatus::kWrongOrigin,
            token->IsValid(insecure_origin_, valid_timestamp_));
  EXPECT_EQ(OriginTrialTokenStatus::kWrongOrigin,
            token->IsValid(incorrect_port_origin_, valid_timestamp_));
  EXPECT_EQ(OriginTrialTokenStatus::kExpired,
            token->IsValid(expected_origin_, invalid_timestamp_));
}

INSTANTIATE_TEST_SUITE_P(TrialTokenTest,
                         TrialTokenParseTest,
                         testing::Values(kVersion2, kVersion3));

TEST_F(TrialTokenTest, ParseValidNonThirdPartyToken) {
  std::unique_ptr<TrialToken> token =
      Parse(kSampleNonThirdPartyTokenJSON, kVersion3);
  ASSERT_TRUE(token);
  EXPECT_EQ(kExpectedFeatureName, token->feature_name());
  EXPECT_FALSE(token->is_third_party());
  EXPECT_EQ(expected_origin_, token->origin());
  EXPECT_EQ(expected_expiry_, token->expiry_time());
}

TEST_F(TrialTokenTest, ParseValidThirdPartyToken) {
  std::unique_ptr<TrialToken> token =
      Parse(kSampleThirdPartyTokenJSON, kVersion3);
  ASSERT_TRUE(token);
  EXPECT_EQ(kExpectedFeatureName, token->feature_name());
  EXPECT_TRUE(token->is_third_party());
  EXPECT_EQ(expected_origin_, token->origin());
  EXPECT_EQ(expected_expiry_, token->expiry_time());
}

TEST_F(TrialTokenTest, ParseValidThirdPartyTokenInvalidVersion) {
  std::unique_ptr<TrialToken> token =
      Parse(kSampleThirdPartyTokenJSON, kVersion2);
  ASSERT_TRUE(token);
  EXPECT_EQ(kExpectedFeatureName, token->feature_name());
  EXPECT_FALSE(token->is_third_party());
  EXPECT_EQ(expected_origin_, token->origin());
  EXPECT_EQ(expected_expiry_, token->expiry_time());
}

TEST_F(TrialTokenTest, ParseValidUsageEmptyToken) {
  std::unique_ptr<TrialToken> token = Parse(kUsageEmptyTokenJSON, kVersion3);
  ASSERT_TRUE(token);
  EXPECT_EQ(kExpectedFeatureName, token->feature_name());
  EXPECT_FALSE(token->is_third_party());
  EXPECT_EQ(TrialToken::UsageRestriction::kNone, token->usage_restriction());
  EXPECT_EQ(expected_origin_, token->origin());
  EXPECT_EQ(expected_expiry_, token->expiry_time());
}

TEST_F(TrialTokenTest, ParseValidUsageSubsetToken) {
  std::unique_ptr<TrialToken> token = Parse(kUsageSubsetTokenJSON, kVersion3);
  ASSERT_TRUE(token);
  EXPECT_EQ(kExpectedFeatureName, token->feature_name());
  EXPECT_FALSE(token->is_third_party());
  EXPECT_EQ(TrialToken::UsageRestriction::kSubset, token->usage_restriction());
  EXPECT_EQ(expected_origin_, token->origin());
  EXPECT_EQ(expected_expiry_, token->expiry_time());
}

TEST_F(TrialTokenTest, ParseValidThirdPartyUsageSubsetToken) {
  std::unique_ptr<TrialToken> token =
      Parse(kSampleThirdPartyTokenUsageSubsetJSON, kVersion3);
  ASSERT_TRUE(token);
  EXPECT_EQ(kExpectedFeatureName, token->feature_name());
  EXPECT_TRUE(token->is_third_party());
  EXPECT_EQ(TrialToken::UsageRestriction::kSubset, token->usage_restriction());
  EXPECT_EQ(expected_origin_, token->origin());
  EXPECT_EQ(expected_expiry_, token->expiry_time());
}

TEST_F(TrialTokenTest, ParseValidThirdPartyUsageEmptyToken) {
  std::unique_ptr<TrialToken> token =
      Parse(kSampleThirdPartyTokenUsageEmptyJSON, kVersion3);
  ASSERT_TRUE(token);
  EXPECT_EQ(kExpectedFeatureName, token->feature_name());
  EXPECT_TRUE(token->is_third_party());
  EXPECT_EQ(TrialToken::UsageRestriction::kNone, token->usage_restriction());
  EXPECT_EQ(expected_origin_, token->origin());
  EXPECT_EQ(expected_expiry_, token->expiry_time());
}

// Test overall extraction and parsing, to ensure output status matches returned
// token, and signature is provided.
// Test Version 2.
TEST_F(TrialTokenTest, FromValidToken) {
  OriginTrialTokenStatus status;
  std::unique_ptr<TrialToken> token =
      TrialToken::From(kSampleTokenV2, correct_public_key(), &status);
  EXPECT_TRUE(token);
  EXPECT_EQ(OriginTrialTokenStatus::kSuccess, status);
  EXPECT_EQ(expected_v2_signature_, token->signature());
}

TEST_F(TrialTokenTest, FromInvalidSignature) {
  OriginTrialTokenStatus status;
  std::unique_ptr<TrialToken> token =
      TrialToken::From(kSampleTokenV2, incorrect_public_key(), &status);
  EXPECT_FALSE(token);
  EXPECT_EQ(OriginTrialTokenStatus::kInvalidSignature, status);
}

// Test Version 3.
TEST_F(TrialTokenTest, FromValidTokenVersion3) {
  OriginTrialTokenStatus status;
  std::unique_ptr<TrialToken> token =
      TrialToken::From(kSampleTokenV3, correct_public_key(), &status);
  EXPECT_TRUE(token);
  EXPECT_EQ(OriginTrialTokenStatus::kSuccess, status);
  EXPECT_EQ(expected_v3_signature_, token->signature());
}

TEST_F(TrialTokenTest, FromInvalidSignatureVersion3) {
  OriginTrialTokenStatus status;
  std::unique_ptr<TrialToken> token =
      TrialToken::From(kSampleTokenV3, incorrect_public_key(), &status);
  EXPECT_FALSE(token);
  EXPECT_EQ(OriginTrialTokenStatus::kInvalidSignature, status);
}

TEST_F(TrialTokenTest, FromMalformedToken) {
  OriginTrialTokenStatus status;
  std::unique_ptr<TrialToken> token =
      TrialToken::From(kIncorrectLengthToken, correct_public_key(), &status);
  EXPECT_FALSE(token);
  EXPECT_EQ(OriginTrialTokenStatus::kMalformed, status);
}

}  // namespace blink

"""


```