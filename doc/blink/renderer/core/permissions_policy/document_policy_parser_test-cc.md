Response:
Let's break down the thought process to generate the explanation for `document_policy_parser_test.cc`.

1. **Understand the Goal:** The primary goal is to explain the functionality of this test file, its relation to web technologies, demonstrate logical reasoning with examples, highlight common user/programming errors, and outline how a user might reach this code.

2. **Identify the Core Function:**  The filename itself, `document_policy_parser_test.cc`, strongly suggests it tests a parser for "Document Policy". Looking inside the code confirms this. The `#include "third_party/blink/renderer/core/permissions_policy/document_policy_parser.h"` is a key indicator.

3. **Pinpoint the Testing Framework:** The presence of `#include "testing/gtest/include/gtest/gtest.h"` immediately reveals that this is a unit test file using Google Test. This tells us the code's purpose is *testing*, not implementing the main functionality.

4. **Analyze the Test Structure:**  The code defines a `DocumentPolicyParserTest` class derived from `::testing::TestWithParam`. This signifies that the tests are parameterized, meaning the same test logic will be run with different inputs (the `ParseTestCase` struct).

5. **Decipher `ParseTestCase`:** This struct is crucial. It contains:
    * `test_name`:  A descriptive name for each test case.
    * `input_string`:  The string that will be fed to the parser (the document policy string).
    * `parsed_policy`: The *expected* output of the parser for the given `input_string`. This includes the `feature_state` and `endpoint_map`.
    * `messages`:  The *expected* warning/error messages the parser should generate.

6. **Examine the Test Cases:**  Carefully go through the `kCases` array. Look for patterns and the intent behind each test:
    * **Valid Policies:** Tests for correctly parsing valid document policy strings (empty, whitespace, single features, multiple features, `report-to`).
    * **Invalid Policies:** Tests for how the parser handles incorrect or malformed policy strings (unrecognized feature names, wrong parameter types, invalid parameter structures, invalid `report-to` values).

7. **Understand `DocumentPolicy` Concepts:** The code uses terms like "feature state," "endpoint map," and "report-to."  Researching "Document Policy" in the context of web browsers will reveal that it's a mechanism for controlling browser features and specifying where to send violation reports.

8. **Connect to Web Technologies:** Now link the concepts to JavaScript, HTML, and CSS:
    * **HTML:**  Document policies are often delivered via HTTP headers (`Document-Policy`). Think about how a server would send this header.
    * **JavaScript:** JavaScript code running within a document is subject to the enforced policies. Examples of features controlled by policies (though not explicitly tested in *this* file) include things like accessing the microphone or geolocation.
    * **CSS:** While not directly related in the parsing stage, the *effects* of a document policy might influence how CSS features work (e.g., a policy could block certain visual effects if they rely on a restricted API).

9. **Illustrate Logical Reasoning:**  Choose a few test cases from `kCases` and explain the expected input and output, outlining *why* the output is expected. For example, the "ParseBoolFeatureWithValueFalse" case directly demonstrates the parsing of a boolean parameter.

10. **Identify Potential User/Programming Errors:** Think about common mistakes when defining document policies:
    * Typographical errors in feature names.
    * Using incorrect parameter types.
    * Misunderstanding the syntax of the `report-to` directive.

11. **Trace User Interaction (Debugging Clues):** Imagine a scenario where a developer is encountering issues with document policies. How might they end up looking at this test file?
    * They might see a warning/error in the browser's developer console related to a document policy.
    * They might be implementing a new feature related to document policies and want to understand how parsing works.
    * They might be debugging a bug in the Blink rendering engine itself.

12. **Explain `Serialize` and `SerializeAndParse` Tests:**  Recognize that these tests verify the serialization (converting the internal representation back to a string) and that the serialization/deserialization process is consistent.

13. **Structure the Explanation:** Organize the information logically with clear headings and bullet points. Start with a high-level overview and then delve into specifics.

14. **Refine and Review:** Read through the explanation to ensure clarity, accuracy, and completeness. Are there any ambiguities?  Are the examples clear?  Is the language accessible? For example, ensure to explain what "feature state" and "endpoint map" represent.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Focus heavily on the C++ code.
* **Correction:** Realize the need to bridge the gap to web technologies (HTML, CSS, JS) to make it more understandable to a wider audience.
* **Initial thought:**  Simply list the test cases.
* **Correction:** Explain the *purpose* of the tests (valid vs. invalid input).
* **Initial thought:** Assume the reader understands "Document Policy."
* **Correction:** Provide a brief explanation of what Document Policy is and its role.
* **Initial thought:** Focus only on the `Parse` function.
* **Correction:**  Recognize the importance of the `Serialize` function and the round-trip testing (`SerializeAndParse`).

By following this thought process, combining code analysis with understanding of web technologies and common development practices, a comprehensive and informative explanation of `document_policy_parser_test.cc` can be generated.
这个文件 `document_policy_parser_test.cc` 是 Chromium Blink 引擎中用于测试 `DocumentPolicyParser` 类的单元测试文件。它的主要功能是验证 `DocumentPolicyParser` 是否能正确地解析和处理不同的文档策略字符串。

**以下是该文件的详细功能分解：**

1. **测试 `DocumentPolicyParser::ParseInternal` 函数:**
   - 该文件通过一系列测试用例，验证 `DocumentPolicyParser::ParseInternal` 函数是否能够将文档策略字符串解析成内部的数据结构 `DocumentPolicy::ParsedDocumentPolicy`。
   - `DocumentPolicy::ParsedDocumentPolicy` 包含两个关键部分：
     - `feature_state`:  一个映射，存储了各个策略特性（features）及其对应的布尔值或数值。
     - `endpoint_map`: 一个映射，存储了策略特性和报告端点（report endpoints）的关联。

2. **测试不同类型的策略字符串:**
   - **空字符串和只包含空格的字符串:** 验证是否能正确处理空策略。
   - **布尔类型特性:**  例如 "f-bool" (表示 true) 和 "f-bool=?0" (表示 false)。
   - **数值类型特性:** 例如 "f-double=1.0" 和 "f-double=2"。
   - **包含多个特性的字符串:** 例如 "f-double=1,f-bool=?0"。
   - **包含 `report-to` 指令的字符串:**  例如 "f-bool=?0,f-double=1;report-to=default"。 这用于测试是否能正确解析报告端点。
   - **包含 `report-to=none` 的字符串:** 验证是否能正确处理禁用报告端点的情况。
   - **包含 `*` 代表默认策略的字符串:**  验证是否能正确处理默认策略的设置和覆盖。

3. **测试解析错误和警告:**
   - 该文件还测试了当解析到无效策略字符串时，是否会产生预期的警告信息。
   - 例如，测试了以下错误情况：
     - 未知的特性名称 (例如 "bad-feature-name")。
     - 参数类型错误 (例如，布尔类型特性赋值为数值 "f-bool=1.0")。
     - 参数格式错误 (例如 "f-double=()")。
     - `report-to` 参数的值不是 token 类型 (例如 "f-bool;report-to=\"default\"")。

4. **测试 `DocumentPolicy::SerializeInternal` 函数:**
   - 除了解析，该文件还测试了 `DocumentPolicy::SerializeInternal` 函数，用于将内部的 `DocumentPolicyFeatureState` 数据结构序列化回字符串。
   - 验证序列化后的字符串是否符合预期。

5. **测试序列化和解析的互逆性:**
   - 通过 `SerializeAndParse` 测试，验证了将一个已解析的策略序列化后再解析，是否能得到原始的策略状态。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

`DocumentPolicy` 是一种用于控制浏览器行为的安全机制，它允许开发者声明文档允许使用的浏览器特性。这与 JavaScript, HTML, CSS 有着密切的关系：

* **HTML:** 文档策略通常通过 HTTP 响应头 `Document-Policy` 来传递给浏览器。例如：
  ```html
  HTTP/1.1 200 OK
  Content-Type: text/html
  Document-Policy: f-bool=?0, f-double=1; report-to=default
  ```
  这个 HTTP 头部声明了文档策略，其中 `f-bool` 特性被设置为 false，`f-double` 特性被设置为 1，并且指定了名为 "default" 的报告端点。

* **JavaScript:** JavaScript 代码的行为会受到文档策略的约束。例如，如果一个文档策略禁止使用地理位置 API，那么 JavaScript 代码调用 `navigator.geolocation` 可能会失败或受到限制。虽然此测试文件本身不直接测试 JavaScript API 的行为，但它验证了策略的解析，而策略的正确解析是控制 JavaScript 行为的基础。

* **CSS:** 某些 CSS 功能也可能受到文档策略的影响。例如，一些较新的 CSS 特性可能需要特定的策略许可才能使用。虽然此测试文件不直接涉及 CSS 的解析或应用，但它确保了策略本身的正确解析，这对于后续 CSS 特性的行为控制至关重要。

**逻辑推理，假设输入与输出：**

* **假设输入:**  `input_string = "f-bool, f-double=2.5"`
* **预期输出:**
  ```
  parsed_policy = {
      feature_state: {
          kBoolFeature: PolicyValue::CreateBool(true),
          kDoubleFeature: PolicyValue::CreateDecDouble(2.5)
      },
      endpoint_map: {}
  }
  messages: {}
  ```
  **推理:**  该输入字符串表示启用了布尔特性 `f-bool` (默认值为 true)，并将数值特性 `f-double` 设置为 2.5。没有指定报告端点。

* **假设输入:** `input_string = "unsupported-feature"`
* **预期输出:**
  ```
  parsed_policy = {
      feature_state: {},
      endpoint_map: {}
  }
  messages: [
      { level: mojom::blink::ConsoleMessageLevel::kWarning, content: "Unrecognized document policy feature name unsupported-feature." }
  ]
  ```
  **推理:**  由于 "unsupported-feature" 不是已知的策略特性，解析器会忽略它并产生一个警告信息。

**用户或编程常见的使用错误举例说明：**

1. **拼写错误的特性名称:**
   - **错误:** 在 HTTP 头部中写成 `Documnet-Policy: fl-bool` (将 `f-bool` 拼写错误)。
   - **结果:** 浏览器可能无法识别该策略，或者会将其视为未知的特性并忽略。这个测试文件中的 "ParsePolicyWithUnrecognizedFeatureName1" 和 "ParsePolicyWithUnrecognizedFeatureName2" 测试用例就模拟了这种情况。

2. **错误的参数类型:**
   - **错误:**  假设 `f-bool` 是一个布尔特性，但在 HTTP 头部中写成 `Document-Policy: f-bool=1.0`。
   - **结果:** 解析器会发现类型不匹配，并产生一个警告信息，如 "ParsePolicyWithWrongTypeOfParamExpectedBooleanTypeButGetDoubleType" 测试用例所示。

3. **`report-to` 参数的值不是 token:**
   - **错误:**  在 HTTP 头部中写成 `Document-Policy: f-bool; report-to="my-endpoint"` (使用了带引号的字符串而不是 token)。
   - **结果:**  解析器会产生一个警告，因为 `report-to` 的值应该是一个不带引号的标识符。 "ReportToParameterValueTypeShouldBeTokenInsteadOfString" 测试用例就模拟了这种情况。

**用户操作如何一步步到达这里，作为调试线索：**

1. **开发者在网站的 HTTP 响应头中设置了 `Document-Policy`:**  开发者可能尝试使用新的浏览器特性，并通过 `Document-Policy` 来控制其行为。
2. **浏览器接收到包含 `Document-Policy` 的响应头:**  当用户访问该网站时，浏览器会下载 HTML 和其他资源，其中包括 HTTP 响应头。
3. **Blink 引擎的解析器开始解析 `Document-Policy`:**  Blink 引擎会负责解析 `Document-Policy` 头部的值。这部分代码就涉及到 `DocumentPolicyParser::ParseInternal` 函数。
4. **如果解析过程中出现错误或警告，Blink 引擎可能会输出到控制台:**  例如，如果策略字符串格式错误，开发者可能会在浏览器的开发者工具的控制台中看到相关的警告信息。这些警告信息对应于此测试文件中的 `messages` 字段。
5. **开发者可能需要调试策略解析问题:**
   - 如果开发者发现某些策略没有生效，或者看到意外的警告信息，他们可能会开始检查 `Document-Policy` 头部的值是否正确。
   - 为了理解 Blink 引擎是如何解析策略的，开发者可能会查看 Blink 相关的源代码，包括 `document_policy_parser_test.cc` 和 `document_policy_parser.h`。
   - `document_policy_parser_test.cc` 中的各种测试用例可以帮助开发者理解不同策略语法的解析结果，从而找到他们配置中的错误。
6. **开发者可能会修改 Blink 引擎的代码并运行测试:**  如果开发者发现了 Blink 引擎在策略解析方面的 bug，他们可能会修改 `DocumentPolicyParser` 的代码，并运行 `document_policy_parser_test.cc` 中的测试用例来验证他们的修复是否有效。

总而言之，`document_policy_parser_test.cc` 是 Blink 引擎中一个至关重要的测试文件，它确保了文档策略这一安全机制能够正确地解析和执行，从而保障了 Web 应用的安全性和功能性。开发者可以通过研究这个文件来理解文档策略的语法和 Blink 引擎的解析行为，从而避免常见的配置错误并进行有效的调试。

### 提示词
```
这是目录为blink/renderer/core/permissions_policy/document_policy_parser_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/permissions_policy/document_policy_parser.h"

#include <vector>

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/permissions_policy/document_policy.h"
#include "third_party/blink/public/mojom/permissions_policy/permissions_policy_feature.mojom-blink.h"

namespace blink {

constexpr const mojom::blink::DocumentPolicyFeature kDefault =
    mojom::blink::DocumentPolicyFeature::kDefault;
constexpr const mojom::blink::DocumentPolicyFeature kBoolFeature =
    static_cast<mojom::blink::DocumentPolicyFeature>(1);
constexpr const mojom::blink::DocumentPolicyFeature kDoubleFeature =
    static_cast<mojom::blink::DocumentPolicyFeature>(2);

// This is the test version of |PolicyParserMessageBuffer::Message| as
// WTF::String cannot be statically allocated.
struct MessageForTest {
  mojom::ConsoleMessageLevel level;
  const char* content;
};

struct ParseTestCase {
  const char* test_name;
  const char* input_string;
  DocumentPolicy::ParsedDocumentPolicy parsed_policy;
  std::vector<MessageForTest> messages;
};

class DocumentPolicyParserTest
    : public ::testing::TestWithParam<ParseTestCase> {
 protected:
  DocumentPolicyParserTest()
      : name_feature_map(DocumentPolicyNameFeatureMap{
            {"*", kDefault},
            {"f-bool", kBoolFeature},
            {"f-double", kDoubleFeature},
        }),
        feature_info_map(DocumentPolicyFeatureInfoMap{
            {kDefault, {"*", PolicyValue::CreateBool(true)}},
            {kBoolFeature, {"f-bool", PolicyValue::CreateBool(true)}},
            {kDoubleFeature, {"f-double", PolicyValue::CreateDecDouble(1.0)}},
        }) {
    available_features.insert(kBoolFeature);
    available_features.insert(kDoubleFeature);
  }

  ~DocumentPolicyParserTest() override = default;

  std::optional<DocumentPolicy::ParsedDocumentPolicy> Parse(
      const String& policy_string,
      PolicyParserMessageBuffer& logger) {
    return DocumentPolicyParser::ParseInternal(policy_string, name_feature_map,
                                               feature_info_map,
                                               available_features, logger);
  }

  std::optional<std::string> Serialize(
      const DocumentPolicyFeatureState& policy) {
    return DocumentPolicy::SerializeInternal(policy, feature_info_map);
  }

 private:
  const DocumentPolicyNameFeatureMap name_feature_map;
  const DocumentPolicyFeatureInfoMap feature_info_map;
  DocumentPolicyFeatureSet available_features;

 public:
  static const ParseTestCase kCases[];
};

const ParseTestCase DocumentPolicyParserTest::kCases[] = {
    //
    // Parse valid policy strings.
    //
    {
        "ParseEmptyPolicyString",
        "",
        /* parsed_policy */
        {
            /* feature_state */ {},
            /* endpoint_map */ {},
        },
        /* messages */ {},
    },
    {
        "ParseWhitespaceOnlyString",
        " ",
        /* parsed_policy */
        {
            /* feature_state */ {},
            /* endpoint_map */ {},
        },
        /* messages */ {},
    },
    {
        "ParseBoolFeatureWithValueTrue",
        "f-bool",
        /* parsed_policy */
        {
            /* feature_state */ {{kBoolFeature, PolicyValue::CreateBool(true)}},
            /* endpoint_map */ {},
        },
        /* messages */ {},
    },
    {
        "ParseBoolFeatureWithValueFalse",
        "f-bool=?0",
        /* parsed_policy */
        {
            /* feature_state */ {
                {kBoolFeature, PolicyValue::CreateBool(false)}},
            /* endpoint_map */ {},
        },
        /* messages */ {},
    },
    {
        "ParseDoubleFeature1",
        "f-double=1.0",
        /* parsed_policy */
        {
            /* feature_state */ {
                {kDoubleFeature, PolicyValue::CreateDecDouble(1.0)}},
            /* endpoint_map */ {},
        },
        /* messages */ {},
    },
    {
        "ParseDoubleFeature2",
        "f-double=2",
        /* parsed_policy */
        {
            /* feature_state */ {
                {kDoubleFeature, PolicyValue::CreateDecDouble(2.0)}},
            /* endpoint_map */ {},
        },
        /* messages */ {},
    },
    {
        "ParseDoubleFeatureAndBoolFeature",
        "f-double=1,f-bool=?0",
        /* parsed_policy */
        {
            /* feature_state */ {
                {kBoolFeature, PolicyValue::CreateBool(false)},
                {kDoubleFeature, PolicyValue::CreateDecDouble(1.0)}},
            /* endpoint_map */ {},
        },
        /* messages */ {},
    },
    {
        "ParseBoolFeatureAndDoubleFeature",
        "f-bool=?0,f-double=1",
        /* parsed_policy */
        {
            /* feature_state */ {
                {kBoolFeature, PolicyValue::CreateBool(false)},
                {kDoubleFeature, PolicyValue::CreateDecDouble(1.0)}},
            /* endpoint_map */ {},
        },
        /* messages */ {},
    },
    {
        "WhitespaceIsAllowedInSomePositionsInStructuredHeader",
        "f-bool=?0,   f-double=1",
        /* parsed_policy */
        {/* feature_state */ {
             {kBoolFeature, PolicyValue::CreateBool(false)},
             {kDoubleFeature, PolicyValue::CreateDecDouble(1.0)}},
         /* endpoint_map */ {}},
        /* messages */ {},
    },
    {
        "UnrecognizedParametersAreIgnoredButTheFeatureEntryShould"
        "RemainValid",
        "f-bool=?0,f-double=1;unknown_param=xxx",
        /* parsed_policy */
        {/* feature_state */ {
             {kBoolFeature, PolicyValue::CreateBool(false)},
             {kDoubleFeature, PolicyValue::CreateDecDouble(1.0)}},
         /* endpoint_map */ {}},
        /* messages */
        {{mojom::blink::ConsoleMessageLevel::kWarning,
          "Unrecognized parameter name unknown_param for feature f-double."}},
    },
    {
        "ParsePolicyWithReportEndpointSpecified1",
        "f-bool=?0,f-double=1;report-to=default",
        /* parsed_policy */
        {/* feature_state */ {
             {kBoolFeature, PolicyValue::CreateBool(false)},
             {kDoubleFeature, PolicyValue::CreateDecDouble(1.0)}},
         /* endpoint_map */ {{kDoubleFeature, "default"}}},
        /* messages */ {},
    },
    {
        "ParsePolicyWithReportEndpointSpecified2",
        "f-bool=?0;report-to=default,f-double=1",
        /* parsed_policy */
        {/* feature_state */ {
             {kBoolFeature, PolicyValue::CreateBool(false)},
             {kDoubleFeature, PolicyValue::CreateDecDouble(1.0)}},
         /* endpoint_map */ {{kBoolFeature, "default"}}},
        /* messages */ {},
    },
    {
        "ParsePolicyWithDefaultReportEndpointAndNone"
        "KeywordShouldOverwriteDefaultValue",
        "f-bool=?0;report-to=none, f-double=2.0, *;report-to=default",
        /* parsed_policy */
        {/* feature_state */ {
             {kBoolFeature, PolicyValue::CreateBool(false)},
             {kDoubleFeature, PolicyValue::CreateDecDouble(2.0)}},
         /* endpoint_map */ {{kDoubleFeature, "default"}}},
        /* messages */ {},
    },
    {
        "ParsePolicyWithDefaultReportEndpointSpecified",
        "f-bool=?0;report-to=not_none, f-double=2.0, "
        "*;report-to=default",
        /* parsed_policy */
        {/* feature_state */ {
             {kBoolFeature, PolicyValue::CreateBool(false)},
             {kDoubleFeature, PolicyValue::CreateDecDouble(2.0)}},
         /* endpoint_map */ {{kBoolFeature, "not_none"},
                             {kDoubleFeature, "default"}}},
        /* messages */ {},
    },
    {
        "ParsePolicyWithDefaultReportEndpointSpecifiedAsNone",
        "f-bool=?0;report-to=not_none, f-double=2.0, *;report-to=none",
        /* parsed_policy */
        {/* feature_state */ {
             {kBoolFeature, PolicyValue::CreateBool(false)},
             {kDoubleFeature, PolicyValue::CreateDecDouble(2.0)}},
         /* endpoint_map */ {{kBoolFeature, "not_none"}}},
        /* messages */ {},
    },
    {
        "DefaultEndpointCanBeSpecifiedAnywhereInTheHeader",
        "f-bool=?0;report-to=not_none, *;report-to=default, "
        "f-double=2.0",
        /* parsed_policy */
        {/* feature_state */ {
             {kBoolFeature, PolicyValue::CreateBool(false)},
             {kDoubleFeature, PolicyValue::CreateDecDouble(2.0)}},
         /* endpoint_map */ {{kBoolFeature, "not_none"},
                             {kDoubleFeature, "default"}}},
        /* messages */ {},
    },
    {
        "DefaultEndpointCanBeSpecifiedMultipleTimesInTheHeader",
        "f-bool=?0;report-to=not_none, f-double=2.0, "
        "*;report-to=default, *;report-to=none",
        /* parsed_policy */
        {/* feature_state */ {
             {kBoolFeature, PolicyValue::CreateBool(false)},
             {kDoubleFeature, PolicyValue::CreateDecDouble(2.0)}},
         /* endpoint_map */ {{kBoolFeature, "not_none"}}},
        /* messages */ {},
    },
    {
        "EvenIfDefaultEndpointIsNotSpecifiedNoneStillShouldBe"
        "TreatedAsReservedKeywordForEndpointNames",
        "f-bool=?0;report-to=none",
        /* parsed_policy */
        {/* feature_state */ {{kBoolFeature, PolicyValue::CreateBool(false)}},
         /* endpoint_map */ {}},
        /* messages */ {},
    },
    {
        "MissingEndpointGroupForDefaultFeature1",
        "*",
        /* parsed_policy */
        {
            /* feature_state */ {},
            /* endpoint_map */ {},
        },
        /* messages */ {},
    },
    {
        "MissingEndpointGroupForDefaultFeature2",
        "*,f-bool=?0,f-double=1;report-to=default",
        /* parsed_policy */
        {/* feature_state */ {
             {kBoolFeature, PolicyValue::CreateBool(false)},
             {kDoubleFeature, PolicyValue::CreateDecDouble(1.0)}},
         /* endpoint_map */ {{kDoubleFeature, "default"}}},
        /* messages */ {},
    },
    //
    // Parse invalid policies.
    //
    {
        "ParsePolicyWithUnrecognizedFeatureName1",
        "bad-feature-name",
        /* parsed_policy */
        {
            /* feature_state */ {},
            /* endpoint_map */ {},
        },
        /* messages */
        {{mojom::blink::ConsoleMessageLevel::kWarning,
          "Unrecognized document policy feature name "
          "bad-feature-name."}},
    },
    {
        "ParsePolicyWithUnrecognizedFeatureName2",
        "no-bad-feature-name",
        /* parsed_policy */
        {
            /* feature_state */ {},
            /* endpoint_map */ {},
        },
        /* messages */
        {{mojom::blink::ConsoleMessageLevel::kWarning,
          "Unrecognized document policy feature name "
          "no-bad-feature-name."}},
    },
    {
        "ParsePolicyWithWrongTypeOfParamExpectedDoubleTypeButGet"
        "BooleanType",
        "f-double=?0",
        /* parsed_policy */
        {
            /* feature_state */ {},
            /* endpoint_map */ {},
        },
        /* messages */
        {{mojom::blink::ConsoleMessageLevel::kWarning,
          "Parameter for feature f-double should be double, not "
          "boolean."}},
    },
    {
        "ParsePolicyWithWrongTypeOfParamExpectedBooleanTypeButGet"
        "DoubleType",
        "f-bool=1.0",
        /* parsed_policy */
        {
            /* feature_state */ {},
            /* endpoint_map */ {},
        },
        /* messages */
        {{mojom::blink::ConsoleMessageLevel::kWarning,
          "Parameter for feature f-bool should be boolean, not "
          "decimal."}},
    },
    {
        "FeatureValueItemShouldNotBeEmpty",
        "f-double=()",
        /* parsed_policy */
        {
            /* feature_state */ {},
            /* endpoint_map */ {},
        },
        /* messages */
        {{mojom::blink::ConsoleMessageLevel::kWarning,
          "Parameter for feature f-double should be single item, but get list "
          "of items(length=0)."}},
    },
    {
        "TooManyFeatureValueItems",
        "f-double=(1.1 2.0)",
        /* parsed_policy */
        {
            /* feature_state */ {},
            /* endpoint_map */ {},
        },
        /* messages */
        {{mojom::blink::ConsoleMessageLevel::kWarning,
          "Parameter for feature f-double should be single item, but get list "
          "of items(length=2)."}},
    },
    {
        "ReportToParameterValueTypeShouldBeTokenInsteadOf"
        "String",
        "f-bool;report-to=\"default\"",
        /* parsed_policy */
        {
            /* feature_state */ {},
            /* endpoint_map */ {},
        },
        /* messages */
        {{mojom::blink::ConsoleMessageLevel::kWarning,
          "\"report-to\" parameter should be a token in feature f-bool."}},
    },
};

const std::pair<DocumentPolicyFeatureState, std::string>
    kPolicySerializationTestCases[] = {
        {{{kBoolFeature, PolicyValue::CreateBool(false)},
          {kDoubleFeature, PolicyValue::CreateDecDouble(1.0)}},
         "f-bool=?0, f-double=1.0"},
        // Changing ordering of FeatureState element should not affect
        // serialization result.
        {{{kDoubleFeature, PolicyValue::CreateDecDouble(1.0)},
          {kBoolFeature, PolicyValue::CreateBool(false)}},
         "f-bool=?0, f-double=1.0"},
        // Flipping boolean-valued policy from false to true should not affect
        // result ordering of feature.
        {{{kBoolFeature, PolicyValue::CreateBool(true)},
          {kDoubleFeature, PolicyValue::CreateDecDouble(1.0)}},
         "f-bool, f-double=1.0"}};

const DocumentPolicyFeatureState kParsedPolicies[] = {
    {},  // An empty policy
    {{kBoolFeature, PolicyValue::CreateBool(false)}},
    {{kBoolFeature, PolicyValue::CreateBool(true)}},
    {{kDoubleFeature, PolicyValue::CreateDecDouble(1.0)}},
    {{kBoolFeature, PolicyValue::CreateBool(true)},
     {kDoubleFeature, PolicyValue::CreateDecDouble(1.0)}}};

// Serialize and then Parse the result of serialization should cancel each
// other out, i.e. d == Parse(Serialize(d)).
// The other way s == Serialize(Parse(s)) is not always true because structured
// header allows some optional white spaces in its parsing targets and floating
// point numbers will be rounded, e.g. value=1 will be parsed to
// PolicyValue::CreateDecDouble(1.0) and get serialized to value=1.0.
TEST_F(DocumentPolicyParserTest, SerializeAndParse) {
  for (const auto& policy : kParsedPolicies) {
    const std::optional<std::string> policy_string = Serialize(policy);
    ASSERT_TRUE(policy_string.has_value());
    PolicyParserMessageBuffer logger;
    const std::optional<DocumentPolicy::ParsedDocumentPolicy> reparsed_policy =
        Parse(policy_string.value().c_str(), logger);

    ASSERT_TRUE(reparsed_policy.has_value());
    EXPECT_EQ(reparsed_policy.value().feature_state, policy);
  }
}

TEST_F(DocumentPolicyParserTest, SerializeResultShouldMatch) {
  for (const auto& test_case : kPolicySerializationTestCases) {
    const DocumentPolicyFeatureState& policy = test_case.first;
    const std::string& expected = test_case.second;
    const auto result = Serialize(policy);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), expected);
  }
}

INSTANTIATE_TEST_SUITE_P(
    All,
    DocumentPolicyParserTest,
    ::testing::ValuesIn(DocumentPolicyParserTest::kCases),
    [](const ::testing::TestParamInfo<ParseTestCase>& param_info) {
      return param_info.param.test_name;
    });

TEST_P(DocumentPolicyParserTest, ParseResultShouldMatch) {
  const ParseTestCase& test_case = GetParam();
  PolicyParserMessageBuffer logger;

  const auto result = Parse(test_case.input_string, logger);

  // All tese cases should not return std::nullopt because they all comply to
  // structured header syntax.
  ASSERT_TRUE(result.has_value());

  EXPECT_EQ(result->endpoint_map, test_case.parsed_policy.endpoint_map)
      << "\n endpoint map should match";
  EXPECT_EQ(result->feature_state, test_case.parsed_policy.feature_state)
      << "\n feature state should match";
  EXPECT_EQ(logger.GetMessages().size(), test_case.messages.size())
      << "\n messages length should match";

  const auto& actual_messages = logger.GetMessages();
  const std::vector<MessageForTest>& expected_messages = test_case.messages;

  ASSERT_EQ(actual_messages.size(), expected_messages.size())
      << "message count should match";
  for (wtf_size_t i = 0; i < expected_messages.size(); ++i) {
    const auto& actual_message = actual_messages[i];
    const MessageForTest& expected_message = expected_messages[i];

    EXPECT_EQ(actual_message.level, expected_message.level)
        << "\n message level should match";
    EXPECT_EQ(actual_message.content, String(expected_message.content))
        << "\n message content should match";
  }
}

}  // namespace blink
```