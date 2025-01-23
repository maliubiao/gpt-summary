Response:
Let's break down the thought process to analyze this C++ unittest file for Chromium's Blink engine.

**1. Understanding the Goal:**

The request asks for a breakdown of the file's functionality, its relationship to web technologies (JavaScript, HTML, CSS), examples of logical reasoning, common usage errors, and debugging clues. The core task is to understand what this specific unit test is testing.

**2. Initial Scan and Key Observations:**

* **Filename:** `public_key_credential_unittest.cc` - immediately suggests this tests the `PublicKeyCredential` functionality within the Credential Management API.
* **Includes:**  A quick glance at the includes reveals:
    * Standard testing libraries (`gmock`, `gtest`).
    * Blink-specific bindings and core components (`v8_binding_for_core.h`, various `v8_...` headers, `local_frame.h`, `dummy_page_holder.h`). The `v8_` prefixes are a strong indicator of interaction with JavaScript.
    * Platform utilities (`script_state.h`, `task_environment.h`, `base64.h`).
* **Namespaces:** `blink` and an anonymous namespace.
* **Test Fixtures/Helpers:** The code defines structs like `CredentialDescriptorValues`, `ExtensionsClientInputsValues`, `CredentialCreationOptionsValues`, `CredentialRequestOptionsValues`, and functions to create the corresponding JSON objects (`MakeExtensionsInputsJSON`, `MakeCreationOptionsJSON`, `MakeRequestOptionsJSON`). This suggests the tests involve creating and parsing these structured data types.
* **Matchers:** Custom matchers like `StrEq`, `Base64URL`, `CredentialDescriptorsEq`, `PubKeyCredParamsEq`, etc., are defined using `gmock`. This is a strong indicator that the tests verify the *content* of parsed objects.
* **Test Cases:** The `TEST` macros indicate individual unit tests with names like `ParseCreationOptionsFromJSON`, `ParseRequestOptions`, and variations with "_Full" and "_WithExtensions".
* **Exception Handling:**  `DummyExceptionStateForTesting` is used, indicating that the tests verify how the code handles invalid input.

**3. Deciphering the Functionality:**

Based on the above observations, the core function of this file is to test the parsing logic for `PublicKeyCredential` objects from their JSON representations. Specifically, it checks the `parseCreationOptionsFromJSON` and `parseRequestOptionsFromJSON` methods.

**4. Identifying Relationships with Web Technologies:**

* **JavaScript:** The inclusion of `v8_...` headers points directly to the JavaScript bindings. The Credential Management API is exposed to JavaScript, allowing websites to interact with it. The JSON structures being parsed are the direct representation of the JavaScript objects passed to these APIs.
* **HTML:** While not directly manipulated in the *unit test*, the Credential Management API is triggered by user actions within a web page (e.g., clicking a "register" or "login" button). The JavaScript code using this API resides within the HTML page.
* **CSS:** CSS has no direct relationship with the *functional logic* of the Credential Management API or its parsing. It might be used to style the UI elements that trigger the API calls, but that's outside the scope of this unit test.

**5. Logical Reasoning and Examples:**

The tests use a structured approach:

* **Setup:** Create a JSON object representing the input (e.g., using `MakeCreationOptionsJSON`).
* **Action:** Call the parsing function being tested (`PublicKeyCredential::parseCreationOptionsFromJSON`).
* **Assertion:** Use `EXPECT_...` and custom matchers to verify that the resulting `PublicKeyCredential` object has the expected properties and values.

* **Hypothetical Input/Output (for `ParseCreationOptionsFromJSON`):**
    * **Input (JSON):**  `{"challenge": "dGVzdA", "rp": {"id": "example.com"}, "user": {"id": "dGVzdA", "name": "example user"}, "pubKeyCredParams": [{"type": "public-key", "alg": -7}]}`
    * **Expected Output (C++ `PublicKeyCredentialCreationOptions` object):**  An object where `options.challenge()` equals the decoded "test", `options.rp()->id()` equals "example.com", etc.

**6. Common Usage Errors:**

The tests with "_InvalidBase64URL" directly target a common error: providing incorrectly encoded base64url strings. This highlights that developers using the JavaScript Credential Management API need to ensure their data is properly formatted.

**7. Debugging Clues and User Actions:**

This is about tracing the execution flow that *leads* to this C++ code being executed.

* **User Action:** A user attempts to register or log in on a website that utilizes the Web Authentication API (part of Credential Management).
* **JavaScript API Call:** The website's JavaScript code calls `navigator.credentials.create()` or `navigator.credentials.get()`, passing in the JSON options.
* **Blink Processing:** The browser's Blink engine receives this JavaScript call.
* **JSON Parsing:** Blink needs to parse the JSON options provided by JavaScript. This is where the code being tested comes into play. The `parseCreationOptionsFromJSON` and `parseRequestOptionsFromJSON` functions are invoked.
* **Unit Test as Debug Aid:** If something goes wrong during this process (e.g., an invalid JSON format), these unit tests help developers isolate and fix the parsing logic in the C++ code. If a bug is reported, developers might write a new unit test that reproduces the issue to ensure the fix is correct.

**8. Refinement and Structuring the Answer:**

Finally, organize the findings into a clear and structured answer, covering each point requested in the original prompt. Use bullet points, code snippets (where relevant), and clear explanations to make the information easily understandable. Emphasize the connection between the C++ code and the corresponding JavaScript APIs and data structures.
这个文件 `public_key_credential_unittest.cc` 是 Chromium Blink 引擎中用于测试 `blink::PublicKeyCredential` 类的单元测试文件。它的主要功能是验证 `PublicKeyCredential` 类的各种功能，特别是与解析和处理 Web Authentication API (WebAuthn) 中关键的 JSON 数据结构相关的部分。

以下是该文件的功能和与 Web 技术的关系的详细说明：

**1. 功能:**

* **测试 JSON 解析:** 该文件主要测试 `PublicKeyCredential` 类中用于解析 WebAuthn 规范中定义的 JSON 对象的静态方法，例如 `parseCreationOptionsFromJSON` 和 `parseRequestOptionsFromJSON`。这些方法负责将 JavaScript 传递的 JSON 数据转换为 C++ 的对象表示。
* **验证数据映射:** 测试用例验证从 JSON 数据到 C++ 对象属性的正确映射。例如，测试会检查 JSON 中的 `challenge` 字段是否正确地映射到 `PublicKeyCredentialCreationOptions` 或 `PublicKeyCredentialRequestOptions` 对象的 `challenge()` 方法的返回值。
* **测试各种选项组合:**  文件中包含了各种测试用例，覆盖了 `PublicKeyCredentialCreationOptions` 和 `PublicKeyCredentialRequestOptions` 中不同的字段和选项组合，包括可选字段、扩展字段 (extensions) 等。
* **验证错误处理:**  部分测试用例专门用于测试在解析无效的 JSON 数据（例如，格式错误的 base64url 编码）时，代码是否能够正确地抛出异常并给出有意义的错误信息。
* **使用 Mocking 和 Assertion:** 该文件使用了 `gmock` 和 `gtest` 框架进行单元测试。自定义的 matcher (例如 `StrEq`, `Base64URL`, `CredentialDescriptorsEq`) 用于方便地比较 C++ 对象和期望的值。

**2. 与 Javascript, HTML, CSS 的关系:**

这个文件直接关系到 Web Authentication API，这是一个 JavaScript API，允许网页使用公钥凭据进行更安全的身份验证。

* **Javascript:**
    * **直接关联:** `PublicKeyCredential` 类和这个测试文件所测试的解析逻辑，是 WebAuthn API 在浏览器内部的具体实现。当 JavaScript 代码调用 `navigator.credentials.create(options)` 或 `navigator.credentials.get(options)` 时，传递的 `options` 对象会被转换为 JSON 并在 Blink 引擎中被 `PublicKeyCredential` 类的相关方法解析。
    * **示例:**
        ```javascript
        // 创建凭据的 JavaScript 代码
        navigator.credentials.create({
          publicKey: {
            challenge: Uint8Array.from([1, 2, 3, 4]),
            rp: { name: "Example" },
            user: { id: Uint8Array.from([5, 6, 7, 8]), name: "user" },
            // ... 其他选项
          }
        }).then(credential => {
          // ...
        });

        // 请求凭据的 JavaScript 代码
        navigator.credentials.get({
          publicKey: {
            challenge: Uint8Array.from([9, 10, 11, 12]),
            // ... 其他选项
          }
        }).then(credential => {
          // ...
        });
        ```
        在这个例子中，传递给 `navigator.credentials.create` 和 `navigator.credentials.get` 的 `publicKey` 对象的内容，最终会以 JSON 格式传递到 Blink 引擎，并由 `PublicKeyCredential::parseCreationOptionsFromJSON` 或 `PublicKeyCredential::parseRequestOptionsFromJSON` 进行解析。

* **HTML:**
    * **间接关系:**  HTML 提供了用户交互的界面，用户操作（例如点击登录按钮）可能会触发 JavaScript 代码调用 WebAuthn API。然而，这个 C++ 单元测试文件本身并不直接涉及 HTML 的解析或渲染。
    * **示例:**  一个 HTML 按钮的 `onclick` 事件可能绑定一个 JavaScript函数，该函数调用 `navigator.credentials.create`。

* **CSS:**
    * **无直接关系:** CSS 用于控制网页的样式，与 WebAuthn API 的功能逻辑或其内部数据结构的解析没有直接关系。

**3. 逻辑推理的假设输入与输出:**

以 `ParseCreationOptionsFromJSON` 测试为例：

**假设输入 (JSON 字符串的 C++ 表示):**

```json
{
  "challenge": "dGVzdA",
  "rp": {
    "id": "example.com"
  },
  "user": {
    "id": "dGVzdA",
    "name": "example user"
  },
  "pubKeyCredParams": [
    {
      "type": "public-key",
      "alg": -7
    }
  ]
}
```
这里的 `"dGVzdA"` 是 "test" 的 base64url 编码。

**预期输出 (C++ `PublicKeyCredentialCreationOptions` 对象):**

* `options->challenge()` 的返回值应该是解码后的字节数组，对应于 "test"。
* `options->rp()->id()` 的返回值应该是字符串 "example.com"。
* `options->user()->id()` 的返回值应该是解码后的字节数组，对应于 "test"。
* `options->user()->name()` 的返回值应该是字符串 "example user"。
* `options->pubKeyCredParams()` 应该包含一个 `PublicKeyCredentialParameters` 对象，其 `type()` 为 "public-key"，`alg()` 为 -7。

**4. 用户或编程常见的使用错误:**

* **无效的 Base64URL 编码:** WebAuthn 规范中很多字段使用 base64url 编码。如果 JavaScript 代码传递了格式错误的 base64url 字符串，`parseCreationOptionsFromJSON` 或 `parseRequestOptionsFromJSON` 会抛出异常。
    * **示例:** 用户或程序员可能会错误地使用标准的 base64 编码，或者在 base64url 编码中包含了填充字符 (`=`)。测试用例 `ParseCreationOptionsFromJSON_InvalidBase64URL` 和 `ParseRequestOptionsFromJSON_InvalidBase64URL` 就是为了测试这种情况。
* **缺少必要的字段:**  某些字段在 `PublicKeyCredentialCreationOptions` 和 `PublicKeyCredentialRequestOptions` 中是必需的。如果 JavaScript 代码中遗漏了这些字段，解析过程会失败。虽然这个单元测试文件主要关注 JSON 解析的正确性，但相关的验证逻辑也会在其他地方进行测试。
* **字段类型不匹配:** 如果 JSON 中字段的类型与规范要求的类型不符（例如，应该是一个字符串却传递了一个数字），解析可能会失败。

**5. 用户操作如何一步步的到达这里，作为调试线索:**

1. **用户在网页上发起身份验证操作:** 用户可能点击了 "注册" 或 "登录" 按钮。
2. **网页 JavaScript 代码调用 WebAuthn API:**  网页上的 JavaScript 代码会调用 `navigator.credentials.create(options)` (用于注册) 或 `navigator.credentials.get(options)` (用于登录)。
3. **JavaScript 对象转换为 JSON:** 浏览器会将 JavaScript 传递的 `options` 对象序列化为 JSON 字符串。
4. **JSON 传递到 Blink 引擎:**  这个 JSON 字符串会被传递到 Chromium Blink 引擎的相应模块进行处理。
5. **`PublicKeyCredential::parseCreationOptionsFromJSON` 或 `PublicKeyCredential::parseRequestOptionsFromJSON` 被调用:**  Blink 引擎会根据调用的 API 函数，调用相应的静态方法来解析 JSON 数据。这就是 `public_key_credential_unittest.cc` 所测试的代码路径。
6. **解析过程中的错误可能触发断点或日志:** 如果在解析过程中发生错误（例如，无效的 base64url 编码），开发人员在调试时可能会在这个单元测试文件所覆盖的代码区域设置断点，或者查看相关的错误日志，以追踪问题的原因。
7. **单元测试帮助验证修复:**  当开发者修复了与 JSON 解析相关的 bug 后，他们可能会运行这些单元测试来确保修复是正确的，并且没有引入新的问题。

总之，`public_key_credential_unittest.cc` 是 Blink 引擎中一个关键的测试文件，它专注于验证 WebAuthn API 中 JSON 数据结构的解析逻辑，确保浏览器能够正确地处理来自网页 JavaScript 的凭据创建和请求选项。这对于保障 WebAuthn API 的正确性和安全性至关重要。

### 提示词
```
这是目录为blink/renderer/modules/credentialmanagement/public_key_credential_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/credentialmanagement/public_key_credential.h"

#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_arraybuffer_arraybufferview_string.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_authentication_extensions_client_inputs.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_authentication_extensions_client_inputs_js_on.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_authentication_extensions_prf_inputs.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_authentication_extensions_prf_inputs_js_on.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_authentication_extensions_prf_values.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_authentication_extensions_prf_values_js_on.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_authenticator_selection_criteria.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_public_key_credential_creation_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_public_key_credential_creation_options_js_on.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_public_key_credential_descriptor.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_public_key_credential_descriptor_js_on.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_public_key_credential_parameters.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_public_key_credential_request_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_public_key_credential_request_options_js_on.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_public_key_credential_rp_entity.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_public_key_credential_user_entity.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_public_key_credential_user_entity_js_on.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_piece.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/wtf/text/base64.h"

namespace blink {
namespace {

using testing::AllOf;
using testing::Eq;
using testing::Field;
using testing::IsNull;
using testing::Matcher;
using testing::Pointee;
using testing::Pointwise;
using testing::Property;
using WTF::String;

#define SUBTEST(F)                                          \
  {                                                         \
    SCOPED_TRACE(testing::Message() << "<-- invoked here"); \
    F;                                                      \
  }

constexpr char kTestB64URL[] = "dGVzdA";    // 'test' base64-url encoded
constexpr char kTest2B64URL[] = "VEVTVDI";  // 'TEST2' base64-url encoded
constexpr char kInvalidB64URL[] = "invalid base64url string";

// Fields to instantiate PublicKeyCredentialOptionsJSON (non-exhaustive). All
// required fields are default-initialized.
struct CredentialDescriptorValues {
  std::string id = kTestB64URL;
  std::string type = "public-key";
};

// Fields to instantiate AuthenticationExtensionsClientInputsJSON.
struct ExtensionsClientInputsValues {
  std::optional<std::string> appid;
  std::optional<std::string> appid_exclude;
  struct CredProtect {
    std::string credential_protection_policy;
    bool enforce_credential_protection_policy;
  };
  std::optional<CredProtect> cred_protect;
  std::optional<bool> cred_props;
  std::optional<std::string> cred_blob;
  std::optional<bool> get_cred_blob;
  using PRFValues = std::pair<std::string, std::string>;
  std::optional<PRFValues> prf_eval;
  std::optional<std::vector<std::pair<std::string, PRFValues>>>
      prf_eval_by_credential;
};

AuthenticationExtensionsClientInputsJSON* MakeExtensionsInputsJSON(
    const ExtensionsClientInputsValues& in) {
  auto* extensions = AuthenticationExtensionsClientInputsJSON::Create();
  if (in.appid) {
    extensions->setAppid(String(*in.appid));
  }
  if (in.appid_exclude) {
    extensions->setAppidExclude(String(*in.appid_exclude));
  }
  if (in.cred_protect) {
    extensions->setCredentialProtectionPolicy(
        String(in.cred_protect->credential_protection_policy));
    extensions->setEnforceCredentialProtectionPolicy(
        in.cred_protect->enforce_credential_protection_policy);
  }
  if (in.cred_props) {
    extensions->setCredProps(*in.cred_props);
  }
  if (in.cred_blob) {
    extensions->setCredBlob(String(*in.cred_blob));
  }
  if (in.get_cred_blob) {
    extensions->setGetCredBlob(*in.get_cred_blob);
  }
  if (in.prf_eval) {
    auto* prf_inputs = AuthenticationExtensionsPRFInputsJSON::Create();
    auto* prf_values = AuthenticationExtensionsPRFValuesJSON::Create();
    prf_values->setFirst(String(in.prf_eval->first));
    prf_values->setSecond(String(in.prf_eval->second));
    prf_inputs->setEval(prf_values);
    extensions->setPrf(prf_inputs);
  }
  if (in.prf_eval_by_credential) {
    HeapVector<std::pair<String, Member<AuthenticationExtensionsPRFValuesJSON>>>
        prf_values_by_cred;
    for (const auto& cred_and_values : *in.prf_eval_by_credential) {
      auto* prf_values = AuthenticationExtensionsPRFValuesJSON::Create();
      prf_values->setFirst(String(cred_and_values.second.first));
      prf_values->setSecond(String(cred_and_values.second.second));
      prf_values_by_cred.emplace_back(String(cred_and_values.first),
                                      prf_values);
    }
    auto* prf_inputs = AuthenticationExtensionsPRFInputsJSON::Create();
    prf_inputs->setEvalByCredential(prf_values_by_cred);
    extensions->setPrf(prf_inputs);
  }
  return extensions;
}

// Fields to instantiate PublicKeyCredentialCreationOptionsJSON.
struct CredentialCreationOptionsValues {
  std::string rp_id = "example.com";
  std::string user_id = kTestB64URL;
  std::string user_name = "example user";
  std::string pub_key_cred_params_type = "public-key";
  int pub_key_cred_params_alg = -7;
  std::string challenge = kTestB64URL;
  std::optional<uint32_t> timeout;
  std::vector<CredentialDescriptorValues> exclude_credentials;
  struct AuthSelection {
    std::optional<std::string> attachment;
    std::optional<std::string> resident_key;
    bool require_resident_key = false;
    std::string user_verification = "preferred";
  };
  std::optional<AuthSelection> authenticator_selection;
  std::vector<std::string> hints;
  std::string attestation = "none";
  std::optional<ExtensionsClientInputsValues> extensions;
};

PublicKeyCredentialCreationOptionsJSON* MakeCreationOptionsJSON(
    const CredentialCreationOptionsValues& in) {
  auto* json = PublicKeyCredentialCreationOptionsJSON::Create();
  json->setChallenge(String(in.challenge));
  auto* rp = PublicKeyCredentialRpEntity::Create();
  rp->setId(String(in.rp_id));
  json->setRp(rp);
  auto* user = PublicKeyCredentialUserEntityJSON::Create();
  user->setId(String(in.user_id));
  user->setName(String(in.user_name));
  json->setUser(user);
  // Test only supports single pubKeyCredParams.
  auto* pub_key_cred_params = PublicKeyCredentialParameters::Create();
  pub_key_cred_params->setType(String(in.pub_key_cred_params_type));
  pub_key_cred_params->setAlg(in.pub_key_cred_params_alg);
  json->setPubKeyCredParams(
      VectorOf<PublicKeyCredentialParameters>({pub_key_cred_params}));
  if (in.timeout) {
    json->setTimeout(*in.timeout);
  }
  VectorOf<PublicKeyCredentialDescriptorJSON> exclude_credentials;
  for (const CredentialDescriptorValues& desc : in.exclude_credentials) {
    auto* desc_json = PublicKeyCredentialDescriptorJSON::Create();
    desc_json->setId(String(desc.id));
    desc_json->setType(String(desc.type));
    exclude_credentials.push_back(desc_json);
  }
  json->setExcludeCredentials(std::move(exclude_credentials));
  if (in.authenticator_selection) {
    auto* authenticator_selection = AuthenticatorSelectionCriteria::Create();
    if (in.authenticator_selection->attachment) {
      authenticator_selection->setAuthenticatorAttachment(
          String(*in.authenticator_selection->attachment));
    }
    if (in.authenticator_selection->resident_key) {
      authenticator_selection->setResidentKey(
          String(*in.authenticator_selection->resident_key));
    }
    authenticator_selection->setRequireResidentKey(
        in.authenticator_selection->require_resident_key);
    authenticator_selection->setUserVerification(
        String(in.authenticator_selection->user_verification));
    json->setAuthenticatorSelection(authenticator_selection);
  }
  VectorOf<String> hints;
  for (const std::string& hint : in.hints) {
    hints.push_back(String(hint));
  }
  json->setHints(hints);
  json->setAttestation(String(in.attestation));
  if (in.extensions) {
    json->setExtensions(MakeExtensionsInputsJSON(*in.extensions));
  }
  return json;
}

// Fields to instantiate PublicKeyCredentialRequestOptionsJSON.
struct CredentialRequestOptionsValues {
  std::string challenge = kTestB64URL;
  std::optional<uint32_t> timeout;
  std::optional<std::string> rp_id;
  std::vector<CredentialDescriptorValues> allow_credentials;
  std::string user_verification = "preferred";
  std::vector<std::string> hints;
  std::optional<ExtensionsClientInputsValues> extensions;
};

PublicKeyCredentialRequestOptionsJSON* MakeRequestOptionsJSON(
    const CredentialRequestOptionsValues& in) {
  auto* json = PublicKeyCredentialRequestOptionsJSON::Create();
  json->setChallenge(String(in.challenge));
  if (in.timeout) {
    json->setTimeout(*in.timeout);
  }
  if (in.rp_id) {
    json->setRpId(String(*in.rp_id));
  }
  VectorOf<PublicKeyCredentialDescriptorJSON> allow_credentials;
  for (const CredentialDescriptorValues& desc : in.allow_credentials) {
    auto* desc_json = PublicKeyCredentialDescriptorJSON::Create();
    desc_json->setId(String(desc.id));
    desc_json->setType(String(desc.type));
    allow_credentials.emplace_back(desc_json);
  }
  json->setAllowCredentials(std::move(allow_credentials));
  json->setUserVerification(String(in.user_verification));
  VectorOf<String> hints;
  for (const std::string& hint : in.hints) {
    hints.push_back(String(hint));
  }
  json->setHints(hints);
  if (in.extensions) {
    json->setExtensions(MakeExtensionsInputsJSON(*in.extensions));
  }
  return json;
}

// Matches a blink WTF::String and a std::string for byte equality.
MATCHER_P(StrEq, str, "") {
  return ExplainMatchResult(Eq(String(str)), arg, result_listener);
}

// Matches a pair of (WTF::String, std::string) for equality (used with
// `testing::Pointwise`).
MATCHER(StrEq, "") {
  const String& s1 = std::get<0>(arg);
  const std::string& s2 = std::get<1>(arg);
  return ExplainMatchResult(Eq(String(s2)), s1, result_listener);
}

// Matches the underlying `T` pointee of a `blink::Member<T>`.
template <typename T>
Matcher<Member<T>> MemberField(Matcher<T*> matcher) {
  return Property("Get", &Member<T>::Get, matcher);
}

// Performs WebAuthn Base64URL encoding, which is always unpadded.
WTF::String Base64URLEncode(DOMArrayPiece buffer) {
  // WTF::Base64URLEncode always pads, so we strip trailing '='.
  String encoded = WTF::Base64URLEncode(buffer.ByteSpan());
  unsigned padding_start = encoded.length();
  for (; padding_start > 0; --padding_start) {
    if (encoded[padding_start - 1] != '=') {
      break;
    }
  }
  encoded.Truncate(padding_start);
  return encoded;
}

// Matches the Base64URL-encoding of the byte contents of a DOMArrayPiece.
MATCHER_P(Base64URL, matcher, "") {
  String encoded = Base64URLEncode(arg);
  return ExplainMatchResult(matcher, encoded, result_listener);
}

// Matches a pair of `Member<PublicKeyCredentialDescriptor>` and
// `CredentialDescriptorValues`. (Use with `testing::Pointwise`).
MATCHER(CredentialDescriptorsEq, "") {
  const Member<PublicKeyCredentialDescriptor>& desc = std::get<0>(arg);
  const CredentialDescriptorValues& values = std::get<1>(arg);
  return ExplainMatchResult(
      MemberField<PublicKeyCredentialDescriptor>(
          AllOf(Property("id", &PublicKeyCredentialDescriptor::id,
                         Base64URL(StrEq(values.id))),
                Property("type", &PublicKeyCredentialDescriptor::type,
                         StrEq(values.type)))),
      desc, result_listener);
}

// Matches `PublicKeyCredentialParameters`.
MATCHER_P2(PubKeyCredParamsEq, type, alg, "") {
  return arg->type() == String(type) && arg->alg() == alg;
}

// Matches `AuthenticationExtensionsPRFValues`.
MATCHER_P(PRFValuesEq, values, "") {
  return ExplainMatchResult(
      AllOf(Property(&AuthenticationExtensionsPRFValues::first,
                     Base64URL(StrEq(values.first))),
            Property(&AuthenticationExtensionsPRFValues::second,
                     Base64URL(StrEq(values.second)))),
      arg, result_listener);
}

// Matches `AuthenticationExtensionsPRFInputs::evalByCredential()`.
MATCHER(PRFCredIdAndValuesEq, "") {
  const std::pair<String, Member<AuthenticationExtensionsPRFValues>>& actual =
      std::get<0>(arg);
  const std::pair<std::string, ExtensionsClientInputsValues::PRFValues>&
      expected = std::get<1>(arg);
  return ExplainMatchResult(
      AllOf(Field(&std::pair<String,
                             Member<AuthenticationExtensionsPRFValues>>::first,
                  StrEq(expected.first)),
            Field(&std::pair<String,
                             Member<AuthenticationExtensionsPRFValues>>::second,
                  MemberField<AuthenticationExtensionsPRFValues>(
                      PRFValuesEq(expected.second)))),
      actual, result_listener);
}

// Tests `AuthenticationExtensionsClientInputs` and
// `ExtensionsClientInputsValues` for equality. Invoke with SUBTEST().
void ExpectExtensionsMatch(
    const AuthenticationExtensionsClientInputs& extensions,
    const ExtensionsClientInputsValues& values) {
  if (values.appid) {
    EXPECT_THAT(extensions.appid(), StrEq(*values.appid));
  } else {
    EXPECT_FALSE(extensions.hasAppid());
  }
  if (values.appid_exclude) {
    EXPECT_THAT(extensions.appidExclude(), StrEq(*values.appid_exclude));
  } else {
    EXPECT_FALSE(extensions.hasAppidExclude());
  }
  if (values.cred_protect) {
    EXPECT_THAT(extensions.credentialProtectionPolicy(),
                StrEq(values.cred_protect->credential_protection_policy));
    EXPECT_EQ(extensions.enforceCredentialProtectionPolicy(),
              values.cred_protect->enforce_credential_protection_policy);
  } else {
    EXPECT_FALSE(extensions.hasCredentialProtectionPolicy());
    EXPECT_FALSE(
        extensions.enforceCredentialProtectionPolicy());  // defaults to 'false'
  }
  if (values.cred_props) {
    EXPECT_EQ(extensions.credProps(), *values.cred_props);
  } else {
    EXPECT_FALSE(extensions.credProps());  // defaults to 'false'
  }
  if (values.cred_blob) {
    EXPECT_THAT(extensions.credBlob(), Base64URL(StrEq(*values.cred_blob)));
  } else {
    EXPECT_FALSE(extensions.hasCredBlob());
  }
  if (values.get_cred_blob) {
    EXPECT_EQ(extensions.getCredBlob(), *values.get_cred_blob);
  } else {
    EXPECT_FALSE(extensions.hasGetCredBlob());
  }
  if (values.prf_eval) {
    EXPECT_THAT(extensions.prf()->eval(),
                MemberField<AuthenticationExtensionsPRFValues>(
                    PRFValuesEq(*values.prf_eval)));
  } else {
    EXPECT_TRUE(!extensions.hasPrf() || !extensions.prf()->hasEval());
  }
  if (values.prf_eval_by_credential) {
    EXPECT_THAT(
        extensions.prf()->evalByCredential(),
        Pointwise(PRFCredIdAndValuesEq(), *values.prf_eval_by_credential));
  } else {
    EXPECT_TRUE(!extensions.hasPrf() ||
                !extensions.prf()->hasEvalByCredential());
  }
  EXPECT_EQ(extensions.hasPrf(),
            values.prf_eval || values.prf_eval_by_credential);
}

// Tests `PublicKeyCredentialCreationOptions` and `CreationOptionsValues` for
// equality. Invoke with SUBTEST().
void ExpectCreationOptionsMatches(
    const PublicKeyCredentialCreationOptions& options,
    const CredentialCreationOptionsValues& values) {
  EXPECT_THAT(options.rp()->id(), StrEq(values.rp_id));
  EXPECT_THAT(options.user(),
              AllOf(Property("id", &PublicKeyCredentialUserEntity::id,
                             Base64URL(StrEq(values.user_id))),
                    Property("name", &PublicKeyCredentialUserEntity::name,
                             StrEq(values.user_name))));
  EXPECT_THAT(options.pubKeyCredParams(),
              testing::ElementsAre(MemberField<PublicKeyCredentialParameters>(
                  PubKeyCredParamsEq(values.pub_key_cred_params_type,
                                     values.pub_key_cred_params_alg))));
  EXPECT_THAT(options.challenge(), Base64URL(StrEq(values.challenge)));
  if (values.timeout.has_value()) {
    EXPECT_EQ(options.timeout(), *values.timeout);
  } else {
    EXPECT_FALSE(options.hasTimeout());
  }
  EXPECT_THAT(options.excludeCredentials(),
              Pointwise(CredentialDescriptorsEq(), values.exclude_credentials));
  if (values.authenticator_selection) {
    if (values.authenticator_selection->attachment) {
      EXPECT_THAT(options.authenticatorSelection()->authenticatorAttachment(),
                  StrEq(*values.authenticator_selection->attachment));
    } else {
      EXPECT_FALSE(
          options.authenticatorSelection()->hasAuthenticatorAttachment());
    }
    if (values.authenticator_selection->resident_key) {
      EXPECT_THAT(options.authenticatorSelection()->residentKey(),
                  StrEq(*values.authenticator_selection->resident_key));
    } else {
      EXPECT_FALSE(options.authenticatorSelection()->hasResidentKey());
    }
    EXPECT_EQ(options.authenticatorSelection()->requireResidentKey(),
              values.authenticator_selection->require_resident_key);
    EXPECT_THAT(options.authenticatorSelection()->userVerification(),
                StrEq(values.authenticator_selection->user_verification));
  } else {
    EXPECT_FALSE(options.hasAuthenticatorSelection());
  }
  EXPECT_THAT(options.hints(), Pointwise(StrEq(), values.hints));
  EXPECT_THAT(options.attestation(), StrEq(values.attestation));
  if (values.extensions.has_value()) {
    EXPECT_TRUE(options.hasExtensions());
    SUBTEST(ExpectExtensionsMatch(*options.extensions(), *values.extensions));
  } else {
    EXPECT_FALSE(options.hasExtensions());
  }
}

// Tests `PublicKeyCredentialRequestOptions` and `RequestOptionsValues` for
// equality. Invoke with SUBTEST().
void ExpectRequestOptionsMatches(
    const PublicKeyCredentialRequestOptions& options,
    const CredentialRequestOptionsValues& values) {
  EXPECT_THAT(options.challenge(), Base64URL(StrEq(values.challenge)));
  if (values.timeout.has_value()) {
    EXPECT_EQ(options.timeout(), *values.timeout);
  } else {
    EXPECT_FALSE(options.hasTimeout());
  }
  if (values.rp_id) {
    EXPECT_THAT(options.rpId(), StrEq(*values.rp_id));
  } else {
    EXPECT_FALSE(options.hasRpId());
  }
  EXPECT_THAT(options.allowCredentials(),
              Pointwise(CredentialDescriptorsEq(), values.allow_credentials));
  EXPECT_THAT(options.userVerification(), StrEq(values.user_verification));
  EXPECT_THAT(options.hints(), Pointwise(StrEq(), values.hints));
  if (values.extensions.has_value()) {
    EXPECT_TRUE(options.hasExtensions());
    SUBTEST(ExpectExtensionsMatch(*options.extensions(), *values.extensions));
  } else {
    EXPECT_FALSE(options.hasExtensions());
  }
}

// Test parseCreationOptionsFromJSON with minimal fields.
TEST(PublicKeyCredentialTest, ParseCreationOptionsFromJSON) {
  test::TaskEnvironment task_environment;
  DummyPageHolder holder;
  ScriptState* script_state = ToScriptStateForMainWorld(&holder.GetFrame());
  CredentialCreationOptionsValues options_values{};
  PublicKeyCredentialCreationOptionsJSON* json =
      MakeCreationOptionsJSON(options_values);
  DummyExceptionStateForTesting exception_state;
  const PublicKeyCredentialCreationOptions* options =
      PublicKeyCredential::parseCreationOptionsFromJSON(script_state, json,
                                                        exception_state);
  EXPECT_FALSE(exception_state.HadException());
  ASSERT_NE(options, nullptr);
  SUBTEST(ExpectCreationOptionsMatches(*options, options_values))
}

// Test parseRequestOptionsFromJSON with minimal fields.
TEST(PublicKeyCredentialTest, ParseRequestOptions) {
  test::TaskEnvironment task_environment;
  DummyPageHolder holder;
  ScriptState* script_state = ToScriptStateForMainWorld(&holder.GetFrame());
  CredentialRequestOptionsValues options_values{};
  PublicKeyCredentialRequestOptionsJSON* json =
      MakeRequestOptionsJSON(options_values);
  DummyExceptionStateForTesting exception_state;
  const PublicKeyCredentialRequestOptions* options =
      PublicKeyCredential::parseRequestOptionsFromJSON(script_state, json,
                                                       exception_state);
  EXPECT_FALSE(exception_state.HadException());
  ASSERT_NE(options, nullptr);
  SUBTEST(ExpectRequestOptionsMatches(*options, options_values));
}

// Test parseCreationOptionsFromJSON with all fields.
TEST(PublicKeyCredentialTest, ParseCreationOptionsFromJSON_Full) {
  test::TaskEnvironment task_environment;
  DummyPageHolder holder;
  ScriptState* script_state = ToScriptStateForMainWorld(&holder.GetFrame());
  CredentialCreationOptionsValues options_values{
      .timeout = 123,
      .exclude_credentials = {{.id = kTestB64URL}, {.id = kTest2B64URL}},
      .authenticator_selection =
          CredentialCreationOptionsValues::AuthSelection{
              .attachment = "cross-platform",
              .resident_key = "required",
              .require_resident_key = true,
              .user_verification = "required"},
      .hints = {"security-key"},
      .attestation = "required",
  };
  PublicKeyCredentialCreationOptionsJSON* json =
      MakeCreationOptionsJSON(options_values);
  DummyExceptionStateForTesting exception_state;
  const PublicKeyCredentialCreationOptions* options =
      PublicKeyCredential::parseCreationOptionsFromJSON(script_state, json,
                                                        exception_state);
  EXPECT_FALSE(exception_state.HadException());
  ASSERT_NE(options, nullptr);
  SUBTEST(ExpectCreationOptionsMatches(*options, options_values));
}

// Test parseRequestOptionsFromJSON with all fields.
TEST(PublicKeyCredentialTest, ParseRequestOptionsFromJSON_Full) {
  test::TaskEnvironment task_environment;
  DummyPageHolder holder;
  ScriptState* script_state = ToScriptStateForMainWorld(&holder.GetFrame());
  CredentialRequestOptionsValues options_values{
      .timeout = 123,
      .rp_id = "example.com",
      .allow_credentials = {{.id = kTestB64URL}, {.id = kTest2B64URL}},
      .user_verification = "required",
      .hints = {"security-key"},
  };
  PublicKeyCredentialRequestOptionsJSON* json =
      MakeRequestOptionsJSON(options_values);
  DummyExceptionStateForTesting exception_state;
  const PublicKeyCredentialRequestOptions* options =
      PublicKeyCredential::parseRequestOptionsFromJSON(script_state, json,
                                                       exception_state);
  EXPECT_FALSE(exception_state.HadException());
  ASSERT_NE(options, nullptr);
  SUBTEST(ExpectRequestOptionsMatches(*options, options_values));
}

// PublicKeyCredentialCreationOptions extensions should convert as expected.
TEST(PublicKeyCredentialTest, ParseCreationOptionsFromJSON_WithExtensions) {
  test::TaskEnvironment task_environment;
  DummyPageHolder holder;
  ScriptState* script_state = ToScriptStateForMainWorld(&holder.GetFrame());
  static const ExtensionsClientInputsValues::PRFValues kTestPRFValues{
      kTestB64URL, kTest2B64URL};
  static const ExtensionsClientInputsValues kTestCases[] = {
      {.appid_exclude = "https://example.com/appid.json"},
      {.cred_protect =
           ExtensionsClientInputsValues::CredProtect{"Level One", true}},
      {.cred_props = true},
      {.cred_blob = kTestB64URL},
      {.prf_eval = kTestPRFValues},
  };
  for (const auto& ext : kTestCases) {
    CredentialCreationOptionsValues options_values{.extensions = ext};
    PublicKeyCredentialCreationOptionsJSON* json =
        MakeCreationOptionsJSON(options_values);
    DummyExceptionStateForTesting exception_state;
    const PublicKeyCredentialCreationOptions* options =
        PublicKeyCredential::parseCreationOptionsFromJSON(script_state, json,
                                                          exception_state);
    EXPECT_FALSE(exception_state.HadException());
    ASSERT_NE(options, nullptr);
    SUBTEST(ExpectCreationOptionsMatches(*options, options_values))
  }
}

// PublicKeyCredentialRequestOptions extensions should convert as expected.
TEST(PublicKeyCredentialTest, ParseRequestOptionsFromJSON_WithExtensions) {
  test::TaskEnvironment task_environment;
  DummyPageHolder holder;
  ScriptState* script_state = ToScriptStateForMainWorld(&holder.GetFrame());
  static const ExtensionsClientInputsValues::PRFValues kTestPRFValues{
      kTestB64URL, kTest2B64URL};
  static const ExtensionsClientInputsValues kTestCases[] = {
      {.appid = "https://example.com/appid.json"},
      {.get_cred_blob = true},
      {.prf_eval_by_credential = {{std::make_pair("ABEiMw", kTestPRFValues)}}},
  };
  for (const auto& ext : kTestCases) {
    CredentialRequestOptionsValues options_values{.extensions = ext};
    PublicKeyCredentialRequestOptionsJSON* json =
        MakeRequestOptionsJSON(options_values);
    DummyExceptionStateForTesting exception_state;
    const PublicKeyCredentialRequestOptions* options =
        PublicKeyCredential::parseRequestOptionsFromJSON(script_state, json,
                                                         exception_state);
    EXPECT_FALSE(exception_state.HadException());
    ASSERT_NE(options, nullptr);
    SUBTEST(ExpectRequestOptionsMatches(*options, options_values));
  }
}

// Parsing PublicKeyCredentialCreationOptionsJSON with invalid base64url data
// should yield meaningful error messages.
TEST(PublicKeyCredentialTest, ParseCreationOptionsFromJSON_InvalidBase64URL) {
  test::TaskEnvironment task_environment;
  static const struct {
    CredentialCreationOptionsValues in;
    std::string expected_message;
  } kTestCases[] = {
      {{.user_id = kInvalidB64URL},
       "'user.id' contains invalid base64url data"},
      {{.challenge = kInvalidB64URL},
       "'challenge' contains invalid base64url data"},
      {{.exclude_credentials = {{.id = kInvalidB64URL}}},
       "'excludeCredentials' contains PublicKeyCredentialDescriptorJSON with "
       "invalid base64url data in 'id'"},
  };
  for (const auto& t : kTestCases) {
    SCOPED_TRACE(testing::Message() << t.expected_message);
    PublicKeyCredentialCreationOptionsJSON* json =
        MakeCreationOptionsJSON(t.in);
    DummyPageHolder holder;
    ScriptState* script_state = ToScriptStateForMainWorld(&holder.GetFrame());
    DummyExceptionStateForTesting exception_state;
    const PublicKeyCredentialCreationOptions* options =
        PublicKeyCredential::parseCreationOptionsFromJSON(script_state, json,
                                                          exception_state);

    EXPECT_EQ(options, nullptr);
    ASSERT_TRUE(exception_state.HadException());
    EXPECT_EQ(exception_state.Message().Utf8(), t.expected_message);
  }
}

// Parsing PublicKeyCredentialRequestOptionsJSON with invalid base64url data
// should yield meaningful error messages.
TEST(PublicKeyCredentialTest, ParseRequestOptionsFromJSON_InvalidBase64URL) {
  test::TaskEnvironment task_environment;
  static const struct {
    CredentialRequestOptionsValues in;
    std::string expected_message;
  } kTestCases[] = {
      {{.challenge = kInvalidB64URL},
       "'challenge' contains invalid base64url data"},
      {{.allow_credentials = {{.id = kInvalidB64URL}}},
       "'allowCredentials' contains PublicKeyCredentialDescriptorJSON with "
       "invalid base64url data in 'id'"},
  };
  for (const auto& t : kTestCases) {
    SCOPED_TRACE(testing::Message() << t.expected_message);
    PublicKeyCredentialRequestOptionsJSON* json = MakeRequestOptionsJSON(t.in);
    DummyPageHolder holder;
    ScriptState* script_state = ToScriptStateForMainWorld(&holder.GetFrame());
    DummyExceptionStateForTesting exception_state;
    const PublicKeyCredentialRequestOptions* options =
        PublicKeyCredential::parseRequestOptionsFromJSON(script_state, json,
                                                         exception_state);

    EXPECT_EQ(options, nullptr);
    ASSERT_TRUE(exception_state.HadException());
    EXPECT_EQ(exception_state.Message().Utf8(), t.expected_message);
  }
}

}  // namespace
}  // namespace blink
```