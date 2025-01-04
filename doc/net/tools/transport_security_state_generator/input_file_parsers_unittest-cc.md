Response:
Let's break down the thought process to generate the detailed explanation of the `input_file_parsers_unittest.cc` file.

1. **Understand the Core Purpose:** The file name `input_file_parsers_unittest.cc` immediately suggests its primary function: to test the functionality of input file parsers. The directory `net/tools/transport_security_state_generator` gives context: these parsers are used by a tool to generate transport security state information.

2. **Identify the Parsed Data Structures:**  Scanning the `#include` statements reveals the key data structures involved:
    * `Pinsets`: Represents a collection of pinset configurations.
    * `TransportSecurityStateEntry`: Represents a single entry for HSTS or HPKP.

3. **Analyze the Test Structure:** The file uses Google Test (`testing/gtest/include/gtest/gtest.h`). This means the core structure will be `TEST(TestSuiteName, TestName) { ... }`. The `TestSuiteName` will likely relate to the file being tested (e.g., `InputFileParsersTest`).

4. **Examine Individual Tests:**  Go through each `TEST` block and determine what it's testing:
    * **`ParseJSON`:**  This test parses JSON input. It provides examples of valid HSTS and HPKP configurations and verifies that the parsed `entries` and `pinsets` match the expected values. This is the core positive test case.
    * **`ParseJSONInvalid`:** This test focuses on *invalid* JSON inputs for HSTS/HPKP entries. It checks for missing required fields like "entries," "pinsets," "name," and "policy."
    * **`ParseJSONInvalidPinset`:** This test specifically validates that invalid pinset definitions (missing "name") are correctly handled.
    * **`ParseJSONInvalidMode`:**  This test checks the handling of invalid values for the "mode" field in HSTS entries.
    * **`ParseJSONUnkownField`:** This verifies that the parser rejects JSON with unexpected or unknown fields in the entries.
    * **`ParseJSONUnkownPolicy`:**  Similar to the above, but specifically tests for unknown values in the "policy" field.
    * **`ParseCertificatesFile`:** This test parses a file format for certificate pinning information. It checks for a specific format including "PinsListTimestamp," public key/certificate data, and verifies the parsed `pinsets` and timestamp. It also handles different SPKI formats (raw hash, PEM-encoded public key, PEM-encoded certificate).
    * **`ParseCertificatesFileInvalid`:** This tests the handling of a general invalid format in the certificates file.
    * **`ParseCertificatesFileInvalidName`:** This tests various invalid naming conventions for certificate entries in the file.
    * **`ParseCertificatesFileInvalidCertificateName`:**  This focuses on the specific naming requirements for certificates (e.g., "Chromium_Class3_G1_Test").
    * **`ParseCertificatesFileInvalidTimestamp`:** This tests the parsing of the timestamp at the beginning of the certificates file, covering missing, incorrect, and multiple timestamp entries.

5. **Synthesize Functionality:** Based on the individual tests, summarize the overall functionality of the code being tested: parsing JSON for HSTS/HPKP and a custom format for certificate pinning.

6. **Analyze JavaScript Relevance:** Consider where the parsed data might be used. Transport Security State is a web platform feature. While the *parsing* is done in C++, the *results* of this parsing are used by the Chromium browser, which has a significant JavaScript component. The generated data informs the browser's behavior when interacting with websites, which directly affects JavaScript code running on those websites (e.g., whether `https://` is enforced, whether certificate pinning is active).

7. **Construct JavaScript Examples (Hypothetical):** Since the C++ code itself doesn't *execute* JavaScript, the connection is about the *effect* of the parsed data. Create hypothetical scenarios where the parsed HSTS/HPKP and pinning data would influence JavaScript behavior. Focus on observable differences.

8. **Infer Logic and Provide Examples:** For each test, identify the underlying logic being tested. Provide a simple "Input -> Expected Output" example that illustrates the test's purpose. This clarifies how the parser is expected to behave.

9. **Identify Common User/Programming Errors:** Think about the kinds of mistakes developers might make when creating the input files. Focus on the errors that the tests are designed to catch (e.g., missing fields, invalid formats, typos). Provide concrete examples of these errors.

10. **Trace User Operations (Debugging Clues):** Consider how a user (likely a Chromium developer) would end up needing to look at this test file. This usually involves modifying the input file parsing logic or the input file formats and then needing to verify the correctness of their changes. Outline the steps a developer would take.

11. **Refine and Organize:** Review the generated information for clarity, accuracy, and completeness. Organize the points logically using headings and bullet points for readability. Ensure consistent terminology. For instance, clearly distinguish between HSTS and HPKP where relevant.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focus solely on the C++ parsing.
* **Correction:** Realize the broader context of Transport Security State and its relevance to the web platform and therefore JavaScript.
* **Initial thought:** Describe each test case in isolation.
* **Correction:** Group similar test cases (e.g., all the `ParseJSON` variations) to show the comprehensive testing strategy.
* **Initial thought:** Provide very technical details about the parsing implementation.
* **Correction:** Focus on the *behavior* being tested rather than the internal implementation details. The user asking the question likely cares more about the input/output behavior and potential errors.
* **Initial thought:**  Provide only positive examples.
* **Correction:**  Recognize the importance of negative test cases and explicitly illustrate invalid inputs and expected failures.
这个文件 `input_file_parsers_unittest.cc` 是 Chromium 网络栈中用于测试输入文件解析器功能的单元测试文件。它的主要目的是验证 `net/tools/transport_security_state_generator/input_file_parsers.h` 中定义的解析器是否能够正确地将各种格式的输入文件（主要是 JSON 和一种自定义的证书 pinning 文件格式）解析成程序内部使用的数据结构。

**功能列表:**

1. **解析 JSON 格式的 HSTS (HTTP Strict Transport Security) 和 HPKP (HTTP Public Key Pinning) 数据:**
   - 测试解析包含 HSTS 规则的 JSON 数据，例如域名、策略（policy）、模式（mode）、是否包含子域名等。
   - 测试解析包含 HPKP 规则的 JSON 数据，例如域名、引用的 pinset 名称、是否包含子域名等。
   - 测试解析包含 pinset 定义的 JSON 数据，例如 pinset 名称、静态 SPKI 哈希值、坏的静态 SPKI 哈希值、报告 URI 等。
   - 测试解析同时包含 HSTS/HPKP 条目和 pinset 定义的 JSON 数据。

2. **解析自定义格式的证书 pinning 文件:**
   - 测试解析包含证书 pinning 信息的文本文件，该文件包含时间戳以及用于 pinning 的公钥或证书信息。
   - 支持多种公钥/证书格式，包括原始 SHA256 哈希值、PEM 编码的公钥和 PEM 编码的证书。
   - 验证解析后的 pinset 数据（SPKI 哈希值）和时间戳是否正确。

3. **错误处理测试:**
   - 测试解析无效的 JSON 数据，例如缺少必要的字段（"entries"、"pinsets"、"name"、"policy"）、无效的模式值、未知的字段或策略等。
   - 测试解析无效的 pinset 定义，例如缺少 pinset 名称。
   - 测试解析无效的证书 pinning 文件，例如格式错误、缺少或无效的时间戳、无效的公钥/证书名称等。

**与 JavaScript 的关系:**

虽然此 C++ 文件本身不包含 JavaScript 代码，但它所测试的解析器处理的数据直接影响 Chromium 浏览器在与网站交互时的行为，这与 JavaScript 的功能密切相关。

**举例说明:**

假设解析后的 HSTS 数据包含以下条目：

```json
{
  "entries": [
    {
      "name": "example.com",
      "policy": "test",
      "mode": "force-https",
      "include_subdomains": true
    }
  ]
}
```

当用户在浏览器中访问 `http://example.com` 或其任何子域名时，Chromium 的网络栈会查找此 HSTS 条目。由于 `mode` 是 `"force-https"`，浏览器会自动将其升级为 `https://example.com`。这个过程对 JavaScript 代码是透明的，但会影响到：

* **`window.location`:** 如果 JavaScript 代码尝试设置 `window.location` 为 `http://example.com`，浏览器可能会在 JavaScript 执行前将其重定向到 `https://example.com`。
* **`fetch` 或 `XMLHttpRequest`:** 如果 JavaScript 代码尝试向 `http://example.com` 发起请求，浏览器会将其转换为 HTTPS 请求。
* **Mixed Content:** 如果一个 HTTPS 页面包含来自 `http://example.com` 的资源（例如图片、脚本），浏览器会阻止这些混合内容加载，这可能会导致 JavaScript 代码出现错误或功能不正常。

类似地，HPKP 数据会影响浏览器对网站证书的信任。如果解析后的 HPKP 数据指定了某些公钥指纹，当网站提供的证书链中不包含这些指纹时，浏览器会拒绝连接，即使证书是由受信任的 CA 签发的。这会阻止 JavaScript 代码与该网站建立连接。

**逻辑推理和假设输入/输出:**

**测试用例：`TEST(InputFileParsersTest, ParseJSON)`**

**假设输入 (valid_hsts):**

```json
{
  "entries": [
    {
      "name": "hsts.example.com",
      "policy": "test",
      "mode": "force-https",
      "include_subdomains": true
    }
  ]
}
```

**假设输入 (valid_pinning):**

```json
{
  "pinsets": [{"name": "test", "static_spki_hashes": ["TestSPKI"], "bad_static_spki_hashes": ["BadTestSPKI"], "report_uri": "https://hpkp-log.example.com"}],
  "entries": [
    {
      "name": "hpkp.example.com",
      "pins": "test",
      "include_subdomains": true
    }
  ]
}
```

**预期输出 (部分 entries):**

```
entries[0]->hostname == "hsts.example.com"
entries[0]->force_https == true
entries[0]->include_subdomains == true
entries[0]->pinset == ""

entries[1]->hostname == "hpkp.example.com"
entries[1]->force_https == false
entries[1]->include_subdomains == true
entries[1]->pinset == "test"
```

**预期输出 (部分 pinsets):**

```
pinsets["test"]->name() == "test"
pinsets["test"]->static_spki_hashes()[0] == "TestSPKI"
pinsets["test"]->bad_static_spki_hashes()[0] == "BadTestSPKI"
pinsets["test"]->report_uri() == "https://hpkp-log.example.com"
```

**用户或编程常见的使用错误举例:**

1. **JSON 文件格式错误:** 用户可能在编辑 JSON 文件时引入语法错误，例如缺少逗号、引号不匹配等。这会导致解析失败。

   ```json
   // 错误示例：缺少逗号
   {
     "entries": [
       {
         "name": "example.com"
         "policy": "test"
       }
     ]
   }
   ```

2. **拼写错误或大小写错误:** 用户可能在输入字段名称或值时拼写错误，例如将 `"mode"` 拼写成 `"mdoe"`，或者将 `"force-https"` 拼写成 `"Force-Https"`。

   ```json
   // 错误示例：拼写错误
   {
     "entries": [
       {
         "name": "example.com",
         "policy": "test",
         "mdoe": "force-https"
       }
     ]
   }
   ```

3. **缺少必要的字段:** 用户可能忘记在 JSON 对象中包含必要的字段，例如 HSTS 条目缺少 `"mode"` 或 HPKP 条目缺少 `"pins"`。

   ```json
   // 错误示例：缺少 "mode" 字段
   {
     "entries": [
       {
         "name": "example.com",
         "policy": "test"
       }
     ]
   }
   ```

4. **在证书 pinning 文件中使用错误的名称格式:**  用户可能没有按照 `Chromium_Class<N>_G<M>_<描述>` 的格式命名证书条目。

   ```
   // 错误示例：缺少 "Chromium_" 前缀
   PinsListTimestamp
   1649894400
   Class3_G1_Test
   sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
   ```

5. **提供无效的时间戳:** 证书 pinning 文件开头的时间戳必须是 Unix 时间戳。提供非数字或格式错误的时间戳会导致解析失败。

   ```
   // 错误示例：无效的时间戳
   PinsListTimestamp
   NotATimestamp
   Chromium_Class3_G1_Test
   sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
   ```

**用户操作如何一步步到达这里 (调试线索):**

1. **开发者修改了预加载的 HSTS/HPKP 数据或证书 pinning 数据:** Chromium 的预加载列表通常以文本或 JSON 文件的形式存在。开发者可能需要修改这些文件来添加、删除或更新 HSTS/HPKP 规则或证书 pinning 信息。

2. **开发者运行 `transport_security_state_generator` 工具:** 这个工具负责将上述修改后的数据文件解析并生成最终的二进制格式数据，供 Chromium 浏览器使用。

3. **工具解析输入文件失败:** 如果开发者在修改数据文件时犯了错误（如上述例子），`transport_security_state_generator` 工具在解析这些文件时会失败。

4. **开发者需要调试解析错误:** 为了找到错误原因，开发者可能会查看 `transport_security_state_generator` 工具的源代码，特别是负责解析输入文件的部分，即 `input_file_parsers.cc` 和 `input_file_parsers_unittest.cc`。

5. **开发者运行单元测试:**  `input_file_parsers_unittest.cc` 提供了各种测试用例，涵盖了正确和错误的输入格式。开发者可以运行这些单元测试，来验证他们对解析器代码的修改是否正确，或者帮助他们理解为什么特定的输入文件无法被正确解析。他们可能会修改测试用例，添加新的测试用例来复现他们遇到的问题。

通过阅读和理解 `input_file_parsers_unittest.cc`，开发者可以了解期望的输入格式、常见的错误类型以及如何编写正确的输入数据文件，从而解决 `transport_security_state_generator` 工具的解析错误。

Prompt: 
```
这是目录为net/tools/transport_security_state_generator/input_file_parsers_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>

#include "base/time/time.h"
#include "net/tools/transport_security_state_generator/input_file_parsers.h"
#include "net/tools/transport_security_state_generator/pinsets.h"
#include "net/tools/transport_security_state_generator/transport_security_state_entry.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net::transport_security_state {

namespace {

// Test that all values are correctly parsed from a valid JSON input.
TEST(InputFileParsersTest, ParseJSON) {
  std::string valid_hsts =
      "{"
      "  \"entries\": ["
      "    {"
      "      \"name\": \"hsts.example.com\","
      "      \"policy\": \"test\","
      "      \"mode\": \"force-https\", "
      "      \"include_subdomains\": true"
      "    }, {"
      "      \"name\": \"hsts-no-subdomains.example.com\","
      "      \"policy\": \"test\","
      "      \"mode\": \"force-https\", "
      "      \"include_subdomains\": false"
      "    }, {"
      "      \"name\": \"hpkp.example.com\","
      "      \"policy\": \"test\""
      "    }, {"
      "      \"name\": \"hpkp-no-subdomains.example.com\","
      "      \"policy\": \"test\""
      "    }"
      "  ]"
      "}";

  std::string valid_pinning =
      "{"
      "  \"pinsets\": [{"
      "      \"name\": \"test\","
      "      \"static_spki_hashes\": [\"TestSPKI\"],"
      "      \"bad_static_spki_hashes\": [\"BadTestSPKI\"],"
      "      \"report_uri\": \"https://hpkp-log.example.com\""
      "  }],"
      "  \"entries\": ["
      "    {"
      "      \"name\": \"hpkp.example.com\","
      "      \"pins\": \"thepinset\","
      "      \"include_subdomains\": true"
      "    }, {"
      "      \"name\": \"hpkp-no-subdomains.example.com\","
      "      \"pins\": \"thepinset2\", "
      "      \"include_subdomains\": false"
      "    }, {"
      "      \"name\": \"hpkp-no-hsts.example.com\","
      "      \"pins\": \"test\", "
      "      \"include_subdomains\": true"
      "    }"
      "  ]"
      "}";

  TransportSecurityStateEntries entries;
  Pinsets pinsets;

  EXPECT_TRUE(ParseJSON(valid_hsts, valid_pinning, &entries, &pinsets));

  ASSERT_EQ(1U, pinsets.size());
  auto pinset = pinsets.pinsets().find("test");
  ASSERT_NE(pinset, pinsets.pinsets().cend());
  EXPECT_EQ("test", pinset->second->name());
  EXPECT_EQ("https://hpkp-log.example.com", pinset->second->report_uri());

  ASSERT_EQ(1U, pinset->second->static_spki_hashes().size());
  EXPECT_EQ("TestSPKI", pinset->second->static_spki_hashes()[0]);

  ASSERT_EQ(1U, pinset->second->bad_static_spki_hashes().size());
  EXPECT_EQ("BadTestSPKI", pinset->second->bad_static_spki_hashes()[0]);

  ASSERT_EQ(5U, entries.size());
  TransportSecurityStateEntry* entry = entries[0].get();
  EXPECT_EQ("hsts.example.com", entry->hostname);
  EXPECT_TRUE(entry->force_https);
  EXPECT_TRUE(entry->include_subdomains);
  EXPECT_FALSE(entry->hpkp_include_subdomains);
  EXPECT_EQ("", entry->pinset);

  entry = entries[1].get();
  EXPECT_EQ("hsts-no-subdomains.example.com", entry->hostname);
  EXPECT_TRUE(entry->force_https);
  EXPECT_FALSE(entry->include_subdomains);
  EXPECT_FALSE(entry->hpkp_include_subdomains);
  EXPECT_EQ("", entry->pinset);

  entry = entries[2].get();
  EXPECT_EQ("hpkp.example.com", entry->hostname);
  EXPECT_FALSE(entry->force_https);
  EXPECT_FALSE(entry->include_subdomains);
  EXPECT_TRUE(entry->hpkp_include_subdomains);
  EXPECT_EQ("thepinset", entry->pinset);

  entry = entries[3].get();
  EXPECT_EQ("hpkp-no-subdomains.example.com", entry->hostname);
  EXPECT_FALSE(entry->force_https);
  EXPECT_FALSE(entry->include_subdomains);
  EXPECT_FALSE(entry->hpkp_include_subdomains);
  EXPECT_EQ("thepinset2", entry->pinset);

  entry = entries[4].get();
  EXPECT_EQ("hpkp-no-hsts.example.com", entry->hostname);
  EXPECT_FALSE(entry->force_https);
  EXPECT_FALSE(entry->include_subdomains);
  EXPECT_TRUE(entry->hpkp_include_subdomains);
  EXPECT_EQ("test", entry->pinset);
}

// Test that parsing valid JSON with missing keys fails.
TEST(InputFileParsersTest, ParseJSONInvalid) {
  TransportSecurityStateEntries entries;
  Pinsets pinsets;

  std::string no_pinsets =
      "{"
      "  \"entries\": []"
      "}";

  EXPECT_FALSE(ParseJSON(no_pinsets, "", &entries, &pinsets));

  std::string no_entries =
      "{"
      "  \"pinsets\": []"
      "}";

  EXPECT_FALSE(ParseJSON("", no_entries, &entries, &pinsets));

  std::string missing_hostname =
      "{"
      "  \"entries\": ["
      "    {"
      "      \"policy\": \"test\","
      "      \"mode\": \"force-https\""
      "    }"
      "  ]"
      "}";

  EXPECT_FALSE(ParseJSON(missing_hostname, "", &entries, &pinsets));

  std::string missing_policy =
      "{"
      "  \"entries\": ["
      "    {"
      "      \"name\": \"example.test\","
      "      \"mode\": \"force-https\""
      "    }"
      "  ]"
      "}";

  EXPECT_FALSE(ParseJSON(missing_policy, "", &entries, &pinsets));
}

// Test that parsing valid JSON with an invalid (HPKP) pinset fails.
TEST(InputFileParsersTest, ParseJSONInvalidPinset) {
  TransportSecurityStateEntries entries;
  Pinsets pinsets;

  std::string missing_pinset_name =
      "{"
      "  \"pinsets\": [{"
      "      \"static_spki_hashes\": [\"TestSPKI\"],"
      "      \"bad_static_spki_hashes\": [\"BadTestSPKI\"],"
      "      \"report_uri\": \"https://hpkp-log.example.com\""
      "  }],"
      "  \"entries\": []"
      "}";

  EXPECT_FALSE(ParseJSON("", missing_pinset_name, &entries, &pinsets));
}

// Test that parsing valid JSON containing an entry with an invalid mode fails.
TEST(InputFileParsersTest, ParseJSONInvalidMode) {
  TransportSecurityStateEntries entries;
  Pinsets pinsets;

  std::string invalid_mode =
      "{"
      "  \"entries\": ["
      "    {"
      "      \"name\": \"preloaded.test\","
      "      \"policy\": \"test\","
      "      \"mode\": \"something-invalid\""
      "    }"
      "  ]"
      "}";

  EXPECT_FALSE(ParseJSON(invalid_mode, "", &entries, &pinsets));
}

// Test that parsing valid JSON containing an entry with an unknown field fails.
TEST(InputFileParsersTest, ParseJSONUnkownField) {
  TransportSecurityStateEntries entries;
  Pinsets pinsets;

  std::string unknown_field =
      "{"
      "  \"entries\": ["
      "    {"
      "      \"name\": \"preloaded.test\","
      "      \"policy\": \"test\","
      "      \"unknown_key\": \"value\""
      "    }"
      "  ]"
      "}";

  EXPECT_FALSE(ParseJSON(unknown_field, "", &entries, &pinsets));
}

// Test that parsing valid JSON containing an entry with an unknown policy
// fails.
TEST(InputFileParsersTest, ParseJSONUnkownPolicy) {
  TransportSecurityStateEntries entries;
  Pinsets pinsets;

  std::string unknown_policy =
      "{"
      "  \"entries\": ["
      "    {"
      "      \"name\": \"preloaded.test\","
      "      \"policy\": \"invalid\""
      "    }"
      "  ]"
      "}";

  EXPECT_FALSE(ParseJSON(unknown_policy, "", &entries, &pinsets));
}

// Test parsing of all 3 SPKI formats.
TEST(InputFileParsersTest, ParseCertificatesFile) {
  std::string valid =
      "# This line should ignored. The rest should result in 3 pins.\n"
      "PinsListTimestamp\n"
      "1649894400\n"
      "TestPublicKey1\n"
      "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
      "\n"
      "TestPublicKey2\n"
      "-----BEGIN PUBLIC KEY-----\n"
      "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAujzwcb5bJuC/A/Y9izGl\n"
      "LlA3fnKGbeyn53BdVznJN4fQwU82WKVYdqt8d/1ZDRdYyhGrTgXJeCURe9VSJyX1\n"
      "X2a5EApSFsopP8Yjy0Rl6dNOLO84KCW9dPmfHC3uP0ac4hnHT5dUr05YvhJmHCkf\n"
      "as6v/aEgpPLDhRF6UruSUh+gIpUg/F3+vlD99HLfbloukoDtQyxW+86s9sO7RQ00\n"
      "pd79VOoa/v09FvoS7MFgnBBOtvBQLOXjEH7/qBsnrXFtHBeOtxSLar/FL3OhVXuh\n"
      "dUTRyc1Mg0ECtz8zHZugW+LleIm5Bf5Yr0bN1O/HfDPCkDaCldcm6xohEHn9pBaW\n"
      "+wIDAQAB\n"
      "-----END PUBLIC KEY-----\n"
      "\n"
      "# The 'Chromium' prefix is required here.\n"
      "ChromiumTestCertificate3\n"
      "-----BEGIN CERTIFICATE-----\n"
      "MIIDeTCCAmGgAwIBAgIJAMRHXuiAgufAMA0GCSqGSIb3DQEBCwUAMFMxETAPBgNV\n"
      "BAMMCENocm9taXVtMR4wHAYDVQQKDBVUaGUgQ2hyb21pdW0gUHJvamVjdHMxETAP\n"
      "BgNVBAsMCFNlY3VyaXR5MQswCQYDVQQGEwJVUzAeFw0xNzAyMDExOTAyMzFaFw0x\n"
      "ODAyMDExOTAyMzFaMFMxETAPBgNVBAMMCENocm9taXVtMR4wHAYDVQQKDBVUaGUg\n"
      "Q2hyb21pdW0gUHJvamVjdHMxETAPBgNVBAsMCFNlY3VyaXR5MQswCQYDVQQGEwJV\n"
      "UzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALtggpf5vNVsmQrJKTQe\n"
      "ynTeOzVOyROGDugGtR+Cri8WlNg1UAlIyYIS8txZ4oCknsT8gs3TFfu0wxmWNxx5\n"
      "4oLGy2BQOHH00dgBAsKgqX//mY4mH5AZ85UFYni1hj9aszIJMIBWtgbNGVkppW65\n"
      "8maF1KVdHmxXMvtKxn/9UsusH/A0ng5UJDYBPISQMv0XqIlv0wdVTIVWIcQhOjWz\n"
      "MGwFDSjxS1WgEnPgd4Qi7MYaDbUTsXGtWba83vZJ8CQzjLumSJJCnz2aquGmraX0\n"
      "J0joUjB4fuYL8xrbDqnFmADvozMMVkZ4843w8ikvJkM8nWoIXexVvirfXDoqtdUo\n"
      "YOcCAwEAAaNQME4wHQYDVR0OBBYEFGJ6O/oLtzpb4OWvrEFxieYb1JbsMB8GA1Ud\n"
      "IwQYMBaAFGJ6O/oLtzpb4OWvrEFxieYb1JbsMAwGA1UdEwQFMAMBAf8wDQYJKoZI\n"
      "hvcNAQELBQADggEBAFpt9jlBT6OsfKFAJZnmExbW8JlsqXOJAaR+nD1XOnp6o+DM\n"
      "NIguj9+wJOW34OM+2Om0n+KMYbDER0p4g3gxoaDblu7otgnC0OTOnx3DPUYab0jr\n"
      "uT6O4C3/nfWW5sl3Ni3Y99dmdcqKcmYkHsr7uADLPWsjb+sfUrQQfHHnPwzyUz/A\n"
      "w4rSJ0wxnLOmjk5F5YHMLkNpPrzFA1mFyGIau7THsRIr3B632MLNcOlNR21nOc7i\n"
      "eB4u+OzpcZXuiQg3bqrNp6Xb70OIW1rfNEiCpps4UZyRnZ/nrzByxeHH5zPWWZk9\n"
      "nZtxI+65PFOekOjBpbnRC8v1CfOmUSVKIqWaPys=\n"
      "-----END CERTIFICATE-----";

  Pinsets pinsets;
  base::Time timestamp;

  base::Time expected_timestamp;
  ASSERT_TRUE(
      base::Time::FromUTCString("2022-04-14T00:00:00Z", &expected_timestamp));

  EXPECT_TRUE(ParseCertificatesFile(valid, &pinsets, &timestamp));

  EXPECT_EQ(3U, pinsets.spki_size());

  EXPECT_EQ(timestamp, expected_timestamp);

  const SPKIHashMap& hashes = pinsets.spki_hashes();
  EXPECT_NE(hashes.cend(), hashes.find("TestPublicKey1"));
  EXPECT_NE(hashes.cend(), hashes.find("TestPublicKey2"));
  EXPECT_NE(hashes.cend(), hashes.find("ChromiumTestCertificate3"));
}

TEST(InputFileParsersTest, ParseCertificatesFileInvalid) {
  Pinsets pinsets;
  base::Time unused;

  std::string invalid =
      "PinsListTimestamp\n"
      "1649894400\n"
      "TestName\n"
      "unexpected";
  EXPECT_FALSE(ParseCertificatesFile(invalid, &pinsets, &unused));
}

// Test that parsing invalid certificate names fails.
TEST(InputFileParsersTest, ParseCertificatesFileInvalidName) {
  Pinsets pinsets;
  base::Time unused;

  std::string invalid_name_small_character =
      "PinsListTimestamp\n"
      "1649894400\n"
      "startsWithSmallLetter\n"
      "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n";
  EXPECT_FALSE(
      ParseCertificatesFile(invalid_name_small_character, &pinsets, &unused));

  std::string invalid_name_invalid_characters =
      "PinsListTimestamp\n"
      "1649894400\n"
      "Invalid-Characters-In-Name\n"
      "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n";
  EXPECT_FALSE(ParseCertificatesFile(invalid_name_invalid_characters, &pinsets,
                                     &unused));

  std::string invalid_name_number =
      "PinsListTimestamp\n"
      "1649894400\n"
      "1InvalidName\n"
      "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n";
  EXPECT_FALSE(ParseCertificatesFile(invalid_name_number, &pinsets, &unused));

  std::string invalid_name_space =
      "PinsListTimestamp\n"
      "1649894400\n"
      "Invalid Name\n"
      "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n";
  EXPECT_FALSE(ParseCertificatesFile(invalid_name_space, &pinsets, &unused));
}

// Test that parsing of a certificate with an incomplete or incorrect name
// fails.
TEST(InputFileParsersTest, ParseCertificatesFileInvalidCertificateName) {
  Pinsets pinsets;
  base::Time unused;
  std::string timestamp_prefix =
      "PinsListTimestamp\n"
      "1649894400\n";
  std::string certificate =
      "-----BEGIN CERTIFICATE-----\n"
      "MIIDIzCCAgugAwIBAgIJALs84KlxWh4GMA0GCSqGSIb3DQEBCwUAMCgxGTAXBgNV\n"
      "BAoMEENocm9taXVtIENsYXNzIDMxCzAJBgNVBAsMAkcxMB4XDTE3MDIwMTE5NTUw\n"
      "NVoXDTE4MDIwMTE5NTUwNVowKDEZMBcGA1UECgwQQ2hyb21pdW0gQ2xhc3MgMzEL\n"
      "MAkGA1UECwwCRzEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDkolrR\n"
      "7gCPm22Cc9psS2Jh1mksVneee5ntEezZ2gEU20y9Z9URBReo8SFvaZcgKkAkca1v\n"
      "552YIG+FBO/u8njxzlHXvuVJ5x2geciqqR4TRhA4jO1ndrNW6nlJfOoYueWbdym3\n"
      "8zwugoULoCtyLyzdiMI5g8iVBQHDh8+K3TZIHar3HS49TjX5u5nv4igO4RfDcFUa\n"
      "h8g+6x5nWoFF8oa3FG0YTN+q6iI1i2JHmj/q03fVPv3WLPGJ3JADau9gO1Lw1/qf\n"
      "R/N3l4MVtjDFFGYzclfqW2UmL6zRirEV0GF2gwSBAGVX3WWhpOcM8rFIWYkZCsI5\n"
      "iUdtwFNBfcKS9sNpAgMBAAGjUDBOMB0GA1UdDgQWBBTm4VJfibducqwb9h4XELn3\n"
      "p6zLVzAfBgNVHSMEGDAWgBTm4VJfibducqwb9h4XELn3p6zLVzAMBgNVHRMEBTAD\n"
      "AQH/MA0GCSqGSIb3DQEBCwUAA4IBAQApTm40RfsZG20IIgWJ62pZ2end/lvaneTh\n"
      "MZSgFnoTRjKkd/5dh22YyKPw9PnpIuiyi85L36COreqZUvbxqRQnpL1oSCRlLBJQ\n"
      "2LcGlF0j0Opa+SY2VWup4XjnYF8CvwMl4obNpSuywTFmkXCRxzN23tn8whNHvWHM\n"
      "BQ7abw8X1KY02uPbHucrpou6KXkKkhyhfML8OD8IRkSM56K6YyedqV97cmEdW0Ie\n"
      "LlpFJQVX13bmojtSNI1zaiCiEenn5xLa/dAlyFT18Mq6y8plioBinVWFYd0qcRoA\n"
      "E2j3m+jTVIv3CZ+ivGxggZQ8ZYN8FJ/iTW3pXGojogHh0NRJJ8dM\n"
      "-----END CERTIFICATE-----";

  std::string missing_prefix =
      timestamp_prefix + "Class3_G1_Test\n" + certificate;
  EXPECT_FALSE(ParseCertificatesFile(missing_prefix, &pinsets, &unused));

  std::string missing_class =
      timestamp_prefix + "Chromium_G1_Test\n" + certificate;
  EXPECT_FALSE(ParseCertificatesFile(missing_class, &pinsets, &unused));

  std::string missing_number =
      timestamp_prefix + "Chromium_Class3_Test\n" + certificate;
  EXPECT_FALSE(ParseCertificatesFile(missing_number, &pinsets, &unused));

  std::string valid =
      timestamp_prefix + "Chromium_Class3_G1_Test\n" + certificate;
  EXPECT_TRUE(ParseCertificatesFile(valid, &pinsets, &unused));
}

// Tests that parsing a certificate with a missing or incorrect timestamp fails.
TEST(InputFileParsersTest, ParseCertificatesFileInvalidTimestamp) {
  Pinsets pinsets;
  base::Time unused;
  std::string timestamp_prefix =
      "PinsListTimestamp\n"
      "1649894400\n";
  std::string bad_timestamp_prefix =
      "PinsListTimestamp\n"
      "NotReallyTimestamp\n";
  std::string certificate =
      "Chromium_Class3_G1_Test\n"
      "-----BEGIN CERTIFICATE-----\n"
      "MIIDIzCCAgugAwIBAgIJALs84KlxWh4GMA0GCSqGSIb3DQEBCwUAMCgxGTAXBgNV\n"
      "BAoMEENocm9taXVtIENsYXNzIDMxCzAJBgNVBAsMAkcxMB4XDTE3MDIwMTE5NTUw\n"
      "NVoXDTE4MDIwMTE5NTUwNVowKDEZMBcGA1UECgwQQ2hyb21pdW0gQ2xhc3MgMzEL\n"
      "MAkGA1UECwwCRzEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDkolrR\n"
      "7gCPm22Cc9psS2Jh1mksVneee5ntEezZ2gEU20y9Z9URBReo8SFvaZcgKkAkca1v\n"
      "552YIG+FBO/u8njxzlHXvuVJ5x2geciqqR4TRhA4jO1ndrNW6nlJfOoYueWbdym3\n"
      "8zwugoULoCtyLyzdiMI5g8iVBQHDh8+K3TZIHar3HS49TjX5u5nv4igO4RfDcFUa\n"
      "h8g+6x5nWoFF8oa3FG0YTN+q6iI1i2JHmj/q03fVPv3WLPGJ3JADau9gO1Lw1/qf\n"
      "R/N3l4MVtjDFFGYzclfqW2UmL6zRirEV0GF2gwSBAGVX3WWhpOcM8rFIWYkZCsI5\n"
      "iUdtwFNBfcKS9sNpAgMBAAGjUDBOMB0GA1UdDgQWBBTm4VJfibducqwb9h4XELn3\n"
      "p6zLVzAfBgNVHSMEGDAWgBTm4VJfibducqwb9h4XELn3p6zLVzAMBgNVHRMEBTAD\n"
      "AQH/MA0GCSqGSIb3DQEBCwUAA4IBAQApTm40RfsZG20IIgWJ62pZ2end/lvaneTh\n"
      "MZSgFnoTRjKkd/5dh22YyKPw9PnpIuiyi85L36COreqZUvbxqRQnpL1oSCRlLBJQ\n"
      "2LcGlF0j0Opa+SY2VWup4XjnYF8CvwMl4obNpSuywTFmkXCRxzN23tn8whNHvWHM\n"
      "BQ7abw8X1KY02uPbHucrpou6KXkKkhyhfML8OD8IRkSM56K6YyedqV97cmEdW0Ie\n"
      "LlpFJQVX13bmojtSNI1zaiCiEenn5xLa/dAlyFT18Mq6y8plioBinVWFYd0qcRoA\n"
      "E2j3m+jTVIv3CZ+ivGxggZQ8ZYN8FJ/iTW3pXGojogHh0NRJJ8dM\n"
      "-----END CERTIFICATE-----";

  std::string missing_timestamp = certificate;
  EXPECT_FALSE(ParseCertificatesFile(certificate, &pinsets, &unused));

  std::string incorrect_timestamp = bad_timestamp_prefix + certificate;
  EXPECT_FALSE(ParseCertificatesFile(incorrect_timestamp, &pinsets, &unused));

  std::string multiple_timestamp =
      timestamp_prefix + timestamp_prefix + certificate;
  EXPECT_FALSE(ParseCertificatesFile(multiple_timestamp, &pinsets, &unused));

  std::string valid = timestamp_prefix + certificate;
  EXPECT_TRUE(ParseCertificatesFile(valid, &pinsets, &unused));
}

}  // namespace

}  // namespace net::transport_security_state

"""

```