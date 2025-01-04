Response:
Let's break down the thought process to analyze the given C++ test file.

1. **Understand the Goal:** The core request is to understand the *functionality* of the given test file (`v8_binding_for_modules_test.cc`) within the Chromium Blink engine. This means identifying what aspects of the engine it's testing and how.

2. **Initial Scan and Keywords:**  Quickly skim the file for prominent keywords and patterns. I see:
    * `TEST(...)` - Clearly a testing file using Google Test.
    * `#include "third_party/blink/renderer/bindings/modules/v8/v8_binding_for_modules.h"` -  The header this file is testing. This suggests the tests are about the bindings between JavaScript modules and the V8 engine within Blink.
    * `IDBKey`, `IDBValue`, `IDBKeyPath` - These strongly indicate tests related to IndexedDB.
    * `ScriptValue`, `V8TestingScope`, `V8ObjectBuilder` -  These are utilities for interacting with V8 within the test environment.
    * `SerializeV8Value`, `DeserializeIDBValue` -  Indicates testing of serialization and deserialization, likely related to IndexedDB.

3. **Focus on the Tested Header:** The primary header is `v8_binding_for_modules.h`. The file name suggests this header deals with the V8 binding specifically for *modules*. This hints at features beyond basic JavaScript integration, potentially involving more advanced module loading and interaction.

4. **Analyze Test Cases:** Go through the `TEST(...)` blocks individually. For each test case:
    * **Name Breakdown:**  The test case names are often descriptive. For example, `IDBKeyFromValueAndKeyPathTest.TopLevelPropertyStringValue` tells us it's testing the creation of an `IDBKey` from a JavaScript value with a key path pointing to a top-level string property.
    * **Setup and Assertions:** Look at the code within each test. What is being set up (`V8TestingScope`, creating JavaScript objects/values)? What are the assertions being made (`EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_FALSE`)?
    * **Identify the Feature Under Test:**  Based on the setup and assertions, determine what specific functionality is being exercised. For example, the `TopLevelPropertyStringValue` test is checking if `CreateIDBKeyFromValueAndKeyPath` correctly extracts the string value "zoo" when the key path is "foo" and the object is `{ foo: "zoo" }`.

5. **Categorize Functionality:**  As you analyze the test cases, group them into logical categories. In this file, the major categories seem to be:
    * **`IDBKey` Creation from JavaScript Values:** Tests on `CreateIDBKeyFromValue` with various JavaScript types (number, date, string, array, etc.) and invalid cases.
    * **`IDBKey` Extraction with Key Paths:** Tests on `CreateIDBKeyFromValueAndKeyPath` with different key path structures (top-level, nested), data types, and edge cases (null values, exceptions).
    * **`IDBKey` Extraction with Compound Key Paths:** Tests on `CreateIDBKeyFromValueAndKeyPaths` specifically for IndexedDB index keys.
    * **Injecting `IDBKey` into JavaScript Objects:** Tests on `InjectV8KeyIntoV8Value` to see if an `IDBKey` can be inserted into a JavaScript object based on a key path.
    * **Serialization and Deserialization of `IDBValue`:** Tests on `SerializeV8Value` and `DeserializeIDBValue`, including handling different V8 versions and potential data corruption scenarios.

6. **Relate to Web Technologies (JavaScript, HTML, CSS):** For each category of functionality, consider how it relates to web technologies. IndexedDB is a JavaScript API, so the connection is direct. The tests ensure that JavaScript code interacting with IndexedDB behaves as expected.

7. **Infer Logic and Assumptions:**  For tests involving logical operations (like key path traversal), think about the assumptions the code makes. For instance, when a key path is "foo.bar", the code expects the object to have a property "foo" which is itself an object with a property "bar". Consider potential inputs and outputs.

8. **Identify Potential User Errors:** Based on the tested scenarios, think about common mistakes a web developer might make when using the related APIs. Incorrect key path strings, trying to store unsupported JavaScript types as keys, or issues with data serialization are good examples.

9. **Trace User Operations (Debugging):** Imagine a scenario where one of these tests fails. How might a user's actions lead to the code being executed?  In the context of IndexedDB, the user might be interacting with a web application that uses IndexedDB to store data. A failure in these tests could indicate a bug in how the browser handles IndexedDB operations.

10. **Structure the Answer:**  Organize the findings into clear sections as requested: functionality, relationship to web technologies, logical inference, user errors, and debugging hints. Use examples to illustrate the points.

11. **Review and Refine:**  Read through the generated answer to ensure accuracy, clarity, and completeness. Check for any inconsistencies or areas that could be explained better. For example, initially, I might just say "tests IndexedDB". Refining it to "tests the V8 bindings for IndexedDB within the modules context" is more precise.

By following this systematic approach, combining code analysis with an understanding of the underlying web technologies and potential user interactions, it's possible to generate a comprehensive and informative answer about the functionality of the given test file.
这个文件 `v8_binding_for_modules_test.cc` 是 Chromium Blink 渲染引擎中的一个 C++ 单元测试文件。 它的主要功能是**测试 Blink 中针对 JavaScript 模块的 V8 绑定机制是否正确工作**。  更具体地说，它测试了如何在 JavaScript 和 C++ 之间传递和转换数据，特别是涉及到 IndexedDB API 相关的数据类型。

以下是它的具体功能以及与 JavaScript, HTML, CSS 的关系、逻辑推理、用户错误和调试线索的详细说明：

**1. 主要功能:**

* **测试 `IDBKey` 和 `IDBValue` 的创建和转换:** 该文件测试了如何从 JavaScript 的值（例如数字、字符串、日期、数组、ArrayBuffer 等）创建 `IDBKey` 对象，以及反过来。同时，也测试了 `IDBValue` 对象的序列化和反序列化，确保数据在 JavaScript 和 C++ 之间传递时保持一致。
* **测试通过 Key Path 访问和注入数据:**  该文件测试了如何使用 Key Path (例如 "foo", "foo.bar") 从 JavaScript 对象中提取 `IDBKey`，以及如何将 `IDBKey` 注入到 JavaScript 对象中。这对于 IndexedDB 的对象存储操作至关重要。
* **测试 IndexedDB 索引键的创建:**  测试了在有存储键路径和索引键路径的情况下，如何正确地从 JavaScript 对象中创建用于 IndexedDB 索引的 `IDBKey`。
* **测试序列化和反序列化的兼容性:**  测试了在不同 V8 版本之间序列化和反序列化 `IDBValue` 的情况，确保即使使用不同版本的 V8，数据也能正确地读取和写入。
* **测试异常处理:**  测试了在尝试从无效的 JavaScript 值创建 `IDBKey` 或访问不存在的 Key Path 时，是否能正确地处理异常。

**2. 与 JavaScript, HTML, CSS 的关系:**

这个文件直接关系到 **JavaScript**，特别是与 **IndexedDB API** 相关的部分。

* **JavaScript:** IndexedDB 是一个 JavaScript API，允许客户端在浏览器中存储结构化数据。这个测试文件验证了 Blink 引擎如何将 JavaScript 中与 IndexedDB 相关的值（例如存储的对象、键）转换成 C++ 中的 `IDBKey` 和 `IDBValue` 对象，以及反过来。
    * **举例:**  JavaScript 代码可以使用 `indexedDB.open(...)` 打开一个数据库，然后使用 `transaction.objectStore("myStore").add({ id: 1, name: "Alice" })` 添加一个对象。这个测试文件就测试了当添加这个对象时，Blink 引擎如何将 JavaScript 对象 `{ id: 1, name: "Alice" }` 和键 `1` 转换成内部的 C++ 数据结构。
* **HTML:**  虽然这个文件本身不直接涉及到 HTML 或 CSS 的解析和渲染，但 IndexedDB 通常被用于增强 Web 应用的功能，这些应用最终会通过 HTML 结构和 CSS 样式呈现给用户。
    * **举例:** 一个 HTML 页面可能包含一个 JavaScript 脚本，该脚本使用 IndexedDB 来缓存用户的搜索结果，以便下次更快地加载。这个测试文件确保了 IndexedDB 在 Blink 引擎中的核心机制是可靠的，从而保证了该 HTML 页面的功能正常。
* **CSS:** CSS 与这个测试文件没有直接关系。

**3. 逻辑推理 (假设输入与输出):**

* **假设输入 (测试 `IDBKeyFromValueAndKeyPathTest.TopLevelPropertyStringValue`):**
    * JavaScript 代码创建了一个对象: `{ foo: "zoo" }`
    * C++ 测试代码使用 Key Path "foo" 来尝试提取 `IDBKey`
* **预期输出:**
    * C++ 代码应该成功创建一个 `IDBKey` 对象。
    * 该 `IDBKey` 对象的类型应该是字符串 (`mojom::IDBKeyType::String`).
    * 该 `IDBKey` 对象的值应该是 "zoo".

* **假设输入 (测试 `InjectIDBKeyTest.TopLevelPropertyStringValue`):**
    * JavaScript 代码创建了一个对象: `{ foo: "zoo" }`
    * C++ 测试代码创建了一个 `IDBKey` 对象，值为 "myNewKey"。
    * C++ 测试代码尝试使用 Key Path "bar" 将该 `IDBKey` 注入到 JavaScript 对象中。
* **预期输出:**
    * C++ 代码应该成功将 `IDBKey` 注入到 JavaScript 对象中。
    * 修改后的 JavaScript 对象应该变成: `{ foo: "zoo", bar: "myNewKey" }`

* **假设输入 (测试 `DeserializeIDBValueTest.CurrentVersions`):**
    * C++ 代码序列化一个空的 JavaScript 对象 `{}` 成 `IDBValue`。
    * 该 `IDBValue` 被反序列化回 JavaScript。
* **预期输出:**
    * 反序列化后的 JavaScript 值应该是一个空对象 `{}`。
    * 如果 `IDBValue` 中包含通过 Key Path 注入的数据，例如主键，那么反序列化后的对象应该包含该主键。

**4. 用户或编程常见的使用错误 (举例说明):**

* **错误的 Key Path:** 用户可能在 JavaScript 代码中使用了错误的 Key Path 来访问 IndexedDB 对象存储中的数据。例如，如果存储的对象是 `{ user: { name: "Bob" } }`，但用户尝试使用 Key Path `"username"` 来获取用户名，这个测试文件中的相关测试会帮助确保 Blink 引擎能正确处理这种情况（可能返回 `undefined` 或抛出错误，取决于具体的 API 行为）。
* **尝试存储不支持作为键的数据类型:**  IndexedDB 的键必须是特定的类型（例如数字、字符串、日期、ArrayBuffer 和数组），并且遵循特定的排序规则。用户可能会尝试将不支持的数据类型（例如函数、对象字面量）作为键存储。 这个测试文件确保 Blink 引擎能正确地拒绝这些操作。
* **序列化/反序列化不兼容:**  理论上，如果存储数据使用的浏览器版本与读取数据使用的浏览器版本在 IndexedDB 序列化格式上存在不兼容，可能会导致数据损坏或无法读取。这个测试文件中关于不同 V8 版本的测试，有助于发现和预防这类问题。
* **并发修改问题:** 虽然这个测试文件本身不直接测试并发，但在实际使用中，如果多个 JavaScript 代码同时访问和修改 IndexedDB 数据，可能会导致数据不一致。理解 Blink 引擎如何处理底层的 `IDBKey` 和 `IDBValue` 转换有助于理解并发问题的根源。

**5. 用户操作是如何一步步的到达这里 (调试线索):**

当一个 Web 开发者在使用 IndexedDB API 时遇到问题，例如数据无法正确存储、检索或键值不正确时，他们可能会需要调试 Blink 引擎的源代码。以下是可能导致他们查看 `v8_binding_for_modules_test.cc` 的步骤：

1. **开发者在浏览器控制台中发现 IndexedDB 操作出现异常或数据不一致。**
2. **开发者怀疑是浏览器引擎在处理 IndexedDB 数据转换时出现了错误。**
3. **开发者可能会搜索 Chromium 源代码中与 IndexedDB 和 V8 绑定相关的代码。**  关键词可能包括 "IndexedDB", "V8 binding", "IDBKey", "IDBValue"。
4. **通过代码搜索或浏览源代码目录结构 (例如 `blink/renderer/bindings/modules/v8/`)，开发者可能会找到 `v8_binding_for_modules_test.cc` 文件。**
5. **开发者查看这个测试文件，可以了解 Blink 引擎是如何测试 IndexedDB 数据在 JavaScript 和 C++ 之间转换的。**  通过阅读测试用例，他们可以更深入地理解引擎的内部工作原理，并可能找到他们遇到的问题的线索。
6. **如果开发者想要更深入地调试，他们可能需要在本地编译 Chromium，并运行这些单元测试。**  如果某个特定的测试用例失败了，可以帮助他们定位到 Blink 引擎中具体的代码错误。
7. **开发者还可以通过修改测试用例来复现他们遇到的问题场景，从而更好地进行调试。** 例如，如果他们怀疑某个特定的 JavaScript 数据类型导致了问题，他们可以修改测试用例，添加针对该数据类型的测试。

总而言之，`v8_binding_for_modules_test.cc` 是 Blink 引擎中一个非常重要的测试文件，它确保了 JavaScript 模块（特别是涉及到 IndexedDB API）与底层的 C++ 代码能够正确地进行数据交互，对于保证 Web 应用的功能和数据完整性至关重要。

Prompt: 
```
这是目录为blink/renderer/bindings/modules/v8/v8_binding_for_modules_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2011 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE AND ITS CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL APPLE OR ITS CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/bindings/modules/v8/v8_binding_for_modules.h"

#include "base/memory/scoped_refptr.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/mojom/indexeddb/indexeddb.mojom-shared.h"
#include "third_party/blink/public/platform/web_blob_info.h"
#include "third_party/blink/public/platform/web_data.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/renderer/bindings/core/v8/serialization/serialization_tag.h"
#include "third_party/blink/renderer/bindings/core/v8/serialization/serialized_script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_object_builder.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/fileapi/file.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/testing/file_backed_blob_factory_test_helper.h"
#include "third_party/blink/renderer/modules/indexeddb/idb_any.h"
#include "third_party/blink/renderer/modules/indexeddb/idb_key.h"
#include "third_party/blink/renderer/modules/indexeddb/idb_key_path.h"
#include "third_party/blink/renderer/modules/indexeddb/idb_value.h"
#include "third_party/blink/renderer/platform/bindings/v8_per_isolate_data.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/wtf/text/string_view.h"

namespace blink {

namespace {

v8::Local<v8::Object> EvaluateScriptAsObject(V8TestingScope& scope,
                                             const char* source) {
  v8::Local<v8::Script> script =
      v8::Script::Compile(scope.GetContext(),
                          V8String(scope.GetIsolate(), source))
          .ToLocalChecked();
  return script->Run(scope.GetContext()).ToLocalChecked().As<v8::Object>();
}

std::unique_ptr<IDBKey> ScriptToKey(V8TestingScope& scope, const char* source) {
  NonThrowableExceptionState exception_state;
  v8::Isolate* isolate = scope.GetIsolate();
  v8::Local<v8::Context> context = scope.GetContext();
  v8::Local<v8::Script> script =
      v8::Script::Compile(context, V8String(isolate, source)).ToLocalChecked();
  v8::Local<v8::Value> value = script->Run(context).ToLocalChecked();
  return CreateIDBKeyFromValue(isolate, value, exception_state);
}

std::unique_ptr<IDBKey> CheckKeyFromValueAndKeyPathInternal(
    v8::Isolate* isolate,
    const ScriptValue& value,
    const String& key_path) {
  IDBKeyPath idb_key_path(key_path);
  EXPECT_TRUE(idb_key_path.IsValid());

  NonThrowableExceptionState exception_state;
  return CreateIDBKeyFromValueAndKeyPath(isolate, value.V8Value(), idb_key_path,
                                         exception_state);
}

void CheckKeyPathNullValue(v8::Isolate* isolate,
                           const ScriptValue& value,
                           const String& key_path) {
  ASSERT_FALSE(CheckKeyFromValueAndKeyPathInternal(isolate, value, key_path));
}

bool InjectKey(ScriptState* script_state,
               IDBKey* key,
               ScriptValue& value,
               const String& key_path) {
  IDBKeyPath idb_key_path(key_path);
  EXPECT_TRUE(idb_key_path.IsValid());
  ScriptValue key_value(script_state->GetIsolate(), key->ToV8(script_state));
  return InjectV8KeyIntoV8Value(script_state->GetIsolate(), key_value.V8Value(),
                                value.V8Value(), idb_key_path);
}

void CheckInjection(ScriptState* script_state,
                    IDBKey* key,
                    ScriptValue& value,
                    const String& key_path) {
  bool result = InjectKey(script_state, key, value, key_path);
  ASSERT_TRUE(result);
  std::unique_ptr<IDBKey> extracted_key = CheckKeyFromValueAndKeyPathInternal(
      script_state->GetIsolate(), value, key_path);
  EXPECT_TRUE(key->IsEqual(extracted_key.get()));
}

void CheckInjectionIgnored(ScriptState* script_state,
                           IDBKey* key,
                           ScriptValue& value,
                           const String& key_path) {
  bool result = InjectKey(script_state, key, value, key_path);
  ASSERT_TRUE(result);
  std::unique_ptr<IDBKey> extracted_key = CheckKeyFromValueAndKeyPathInternal(
      script_state->GetIsolate(), value, key_path);
  EXPECT_FALSE(key->IsEqual(extracted_key.get()));
}

void CheckInjectionDisallowed(ScriptState* script_state,
                              ScriptValue& value,
                              const String& key_path) {
  const IDBKeyPath idb_key_path(key_path);
  ASSERT_TRUE(idb_key_path.IsValid());
  EXPECT_FALSE(CanInjectIDBKeyIntoScriptValue(script_state->GetIsolate(), value,
                                              idb_key_path));
}

void CheckKeyPathStringValue(v8::Isolate* isolate,
                             const ScriptValue& value,
                             const String& key_path,
                             const String& expected) {
  std::unique_ptr<IDBKey> idb_key =
      CheckKeyFromValueAndKeyPathInternal(isolate, value, key_path);
  ASSERT_TRUE(idb_key);
  ASSERT_EQ(mojom::IDBKeyType::String, idb_key->GetType());
  ASSERT_TRUE(expected == idb_key->GetString());
}

void CheckKeyPathNumberValue(v8::Isolate* isolate,
                             const ScriptValue& value,
                             const String& key_path,
                             int expected) {
  std::unique_ptr<IDBKey> idb_key =
      CheckKeyFromValueAndKeyPathInternal(isolate, value, key_path);
  ASSERT_TRUE(idb_key);
  ASSERT_EQ(mojom::IDBKeyType::Number, idb_key->GetType());
  ASSERT_TRUE(expected == idb_key->Number());
}

// Compare a key against an array of keys. Supports keys with "holes" (keys of
// type None), so IDBKey::Compare() can't be used directly.
void CheckArrayKey(const IDBKey* key, const IDBKey::KeyArray& expected) {
  EXPECT_EQ(mojom::IDBKeyType::Array, key->GetType());
  const IDBKey::KeyArray& array = key->Array();
  EXPECT_EQ(expected.size(), array.size());
  for (wtf_size_t i = 0; i < array.size(); ++i) {
    EXPECT_EQ(array[i]->GetType(), expected[i]->GetType());
    if (array[i]->GetType() != mojom::IDBKeyType::None) {
      EXPECT_EQ(0, expected[i]->Compare(array[i].get()));
    }
  }
}

// SerializedScriptValue header format offsets are inferred from the Blink and
// V8 serialization code. The code below DCHECKs that
constexpr static size_t kSSVHeaderBlinkVersionTagOffset = 0;
constexpr static size_t kSSVHeaderBlinkVersionOffset = 1;
constexpr static size_t kSSVHeaderV8VersionTagOffset = 15;
// constexpr static size_t kSSVHeaderV8VersionOffset = 16;

// Follows the same steps as the IndexedDB value serialization code.
void SerializeV8Value(v8::Local<v8::Value> value,
                      v8::Isolate* isolate,
                      Vector<char>* wire_bytes) {
  NonThrowableExceptionState non_throwable_exception_state;

  SerializedScriptValue::SerializeOptions options;
  scoped_refptr<SerializedScriptValue> serialized_value =
      SerializedScriptValue::Serialize(isolate, value, options,
                                       non_throwable_exception_state);

  DCHECK(wire_bytes->empty());
  wire_bytes->AppendSpan(serialized_value->GetWireData());

  // Sanity check that the serialization header has not changed, as the tests
  // that use this method rely on the header format.
  //
  // The cast from char* to unsigned char* is necessary to avoid VS2015 warning
  // C4309 (truncation of constant value). This happens because VersionTag is
  // 0xFF.
  const unsigned char* wire_data =
      reinterpret_cast<unsigned char*>(wire_bytes->data());
  ASSERT_EQ(static_cast<unsigned char>(kVersionTag),
            wire_data[kSSVHeaderBlinkVersionTagOffset]);
  ASSERT_EQ(
      static_cast<unsigned char>(SerializedScriptValue::kWireFormatVersion),
      wire_data[kSSVHeaderBlinkVersionOffset]);

  ASSERT_EQ(static_cast<unsigned char>(kVersionTag),
            wire_data[kSSVHeaderV8VersionTagOffset]);
  // TODO(jbroman): Use the compile-time constant for V8 data format version.
  // ASSERT_EQ(v8::ValueSerializer::GetCurrentDataFormatVersion(),
  //           wire_data[kSSVHeaderV8VersionOffset]);
}

std::unique_ptr<IDBValue> CreateIDBValue(v8::Isolate* isolate,
                                         Vector<char>&& wire_bytes,
                                         double primary_key,
                                         const String& key_path) {
  auto value =
      std::make_unique<IDBValue>(std::move(wire_bytes), Vector<WebBlobInfo>());
  value->SetInjectedPrimaryKey(IDBKey::CreateNumber(primary_key),
                               IDBKeyPath(key_path));

  value->SetIsolate(isolate);
  return value;
}

TEST(IDBKeyFromValueAndKeyPathTest, TopLevelPropertyStringValue) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  v8::Isolate* isolate = scope.GetIsolate();

  // object = { foo: "zoo" }
  ScriptValue script_value = V8ObjectBuilder(scope.GetScriptState())
                                 .AddString("foo", "zoo")
                                 .GetScriptValue();
  CheckKeyPathStringValue(isolate, script_value, "foo", "zoo");
  CheckKeyPathNullValue(isolate, script_value, "bar");
}

}  // namespace

TEST(IDBKeyFromValueAndKeyPathTest, TopLevelPropertyNumberValue) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  v8::Isolate* isolate = scope.GetIsolate();

  // object = { foo: 456 }
  ScriptValue script_value = V8ObjectBuilder(scope.GetScriptState())
                                 .AddNumber("foo", 456)
                                 .GetScriptValue();
  CheckKeyPathNumberValue(isolate, script_value, "foo", 456);
  CheckKeyPathNullValue(isolate, script_value, "bar");
}

TEST(IDBKeyFromValueAndKeyPathTest, FileLastModifiedDateUseCounterTest) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;

  FileBackedBlobFactoryTestHelper file_factory_helper(
      scope.GetExecutionContext());
  File* file =
      MakeGarbageCollected<File>(scope.GetExecutionContext(), "/native/path");
  file_factory_helper.FlushForTesting();
  v8::Local<v8::Value> wrapper =
      ToV8Traits<File>::ToV8(scope.GetScriptState(), file);

  IDBKeyPath idb_key_path("lastModifiedDate");
  ASSERT_TRUE(idb_key_path.IsValid());

  NonThrowableExceptionState exception_state;
  ASSERT_TRUE(CreateIDBKeyFromValueAndKeyPath(scope.GetIsolate(), wrapper,
                                              idb_key_path, exception_state));
  ASSERT_TRUE(scope.GetDocument().IsUseCounted(
      WebFeature::kIndexedDBFileLastModifiedDate));
}

TEST(IDBKeyFromValueAndKeyPathTest, SubProperty) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScriptState* script_state = scope.GetScriptState();
  v8::Isolate* isolate = scope.GetIsolate();

  // object = { foo: { bar: "zee" } }
  ScriptValue script_value =
      V8ObjectBuilder(script_state)
          .Add("foo", V8ObjectBuilder(script_state).AddString("bar", "zee"))
          .GetScriptValue();
  CheckKeyPathStringValue(isolate, script_value, "foo.bar", "zee");
  CheckKeyPathNullValue(isolate, script_value, "bar");
}

TEST(IDBKeyFromValue, Number) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;

  auto key = ScriptToKey(scope, "42.0");
  EXPECT_EQ(key->GetType(), mojom::IDBKeyType::Number);
  EXPECT_EQ(key->Number(), 42);

  EXPECT_FALSE(ScriptToKey(scope, "NaN")->IsValid());
}

TEST(IDBKeyFromValue, Date) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;

  auto key = ScriptToKey(scope, "new Date(123)");
  EXPECT_EQ(key->GetType(), mojom::IDBKeyType::Date);
  EXPECT_EQ(key->Date(), 123);

  EXPECT_FALSE(ScriptToKey(scope, "new Date(NaN)")->IsValid());
  EXPECT_FALSE(ScriptToKey(scope, "new Date(Infinity)")->IsValid());
}

TEST(IDBKeyFromValue, String) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;

  auto key = ScriptToKey(scope, "'abc'");
  EXPECT_EQ(key->GetType(), mojom::IDBKeyType::String);
  EXPECT_EQ(key->GetString(), "abc");
}

TEST(IDBKeyFromValue, Binary) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;

  // Key which is an ArrayBuffer.
  {
    auto key = ScriptToKey(scope, "new ArrayBuffer(3)");
    EXPECT_EQ(key->GetType(), mojom::IDBKeyType::Binary);
    EXPECT_EQ(key->Binary()->data.size(), 3UL);
  }

  // Key which is a TypedArray view on an ArrayBuffer.
  {
    auto key = ScriptToKey(scope, "new Uint8Array([0,1,2])");
    EXPECT_EQ(key->GetType(), mojom::IDBKeyType::Binary);
    EXPECT_EQ(key->Binary()->data.size(), 3UL);
  }
}

TEST(IDBKeyFromValue, InvalidSimpleKeyTypes) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;

  const char* cases[] = {
      "true", "false", "null", "undefined", "{}", "(function(){})", "/regex/",
  };

  for (const char* expr : cases)
    EXPECT_FALSE(ScriptToKey(scope, expr)->IsValid());
}

TEST(IDBKeyFromValue, SimpleArrays) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;

  {
    auto key = ScriptToKey(scope, "[]");
    EXPECT_EQ(key->GetType(), mojom::IDBKeyType::Array);
    EXPECT_EQ(key->Array().size(), 0UL);
  }

  {
    auto key = ScriptToKey(scope, "[0, 'abc']");
    EXPECT_EQ(key->GetType(), mojom::IDBKeyType::Array);

    const IDBKey::KeyArray& array = key->Array();
    EXPECT_EQ(array.size(), 2UL);
    EXPECT_EQ(array[0]->GetType(), mojom::IDBKeyType::Number);
    EXPECT_EQ(array[1]->GetType(), mojom::IDBKeyType::String);
  }
}

TEST(IDBKeyFromValue, NestedArray) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;

  auto key = ScriptToKey(scope, "[0, ['xyz', Infinity], 'abc']");
  EXPECT_EQ(key->GetType(), mojom::IDBKeyType::Array);

  const IDBKey::KeyArray& array = key->Array();
  EXPECT_EQ(array.size(), 3UL);
  EXPECT_EQ(array[0]->GetType(), mojom::IDBKeyType::Number);
  EXPECT_EQ(array[1]->GetType(), mojom::IDBKeyType::Array);
  EXPECT_EQ(array[1]->Array().size(), 2UL);
  EXPECT_EQ(array[1]->Array()[0]->GetType(), mojom::IDBKeyType::String);
  EXPECT_EQ(array[1]->Array()[1]->GetType(), mojom::IDBKeyType::Number);
  EXPECT_EQ(array[2]->GetType(), mojom::IDBKeyType::String);
}

TEST(IDBKeyFromValue, CircularArray) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto key = ScriptToKey(scope,
                         "(() => {"
                         "  const a = [];"
                         "  a.push(a);"
                         "  return a;"
                         "})()");
  EXPECT_FALSE(key->IsValid());
}

TEST(IDBKeyFromValue, DeepArray) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto key = ScriptToKey(scope,
                         "(() => {"
                         "  let a = [];"
                         "  for (let i = 0; i < 10000; ++i) { a.push(a); }"
                         "  return a;"
                         "})()");
  EXPECT_FALSE(key->IsValid());
}

TEST(IDBKeyFromValue, SparseArray) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto key = ScriptToKey(scope, "[,1]");
  EXPECT_FALSE(key->IsValid());

  // Ridiculously large sparse array - ensure we check before allocating.
  key = ScriptToKey(scope, "Object.assign([], {length: 2e9})");
  EXPECT_FALSE(key->IsValid());

  // Large sparse arrays as subkeys - ensure we check while recursing.
  key = ScriptToKey(scope, "[Object.assign([], {length: 2e9})]");
  EXPECT_FALSE(key->IsValid());
}

TEST(IDBKeyFromValue, ShrinkingArray) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto key = ScriptToKey(
      scope,
      "(() => {"
      "  const a = [0, 1, 2];"
      "  Object.defineProperty(a, 1, {get: () => { a.length = 2; return 1; }});"
      "  return a;"
      "})()");
  EXPECT_FALSE(key->IsValid());
}

TEST(IDBKeyFromValue, Exceptions) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;

  const char* cases[] = {
      // Detached ArrayBuffer.
      "(() => {"
      "  const a = new ArrayBuffer(3);"
      "  postMessage(a, '*', [a]);"
      "  return a;"
      "})()",

      // Detached ArrayBuffer view.
      "(() => {"
      "  const a = new Uint8Array([0,1,2]);"
      "  postMessage(a.buffer, '*', [a.buffer]);"
      "  return a;"
      "})()",

      // Value is an array with a getter that throws.
      "(()=>{"
      "  const a = [0, 1, 2];"
      "  Object.defineProperty(a, 1, {get: () => { throw Error(); }});"
      "  return a;"
      "})()",

      // Value is an array containing an array with a getter that throws.
      "(()=>{"
      "  const a = [0, 1, 2];"
      "  Object.defineProperty(a, 1, {get: () => { throw Error(); }});"
      "  return ['x', a, 'z'];"
      "})()",

      // Array with unconvertable item
      "(() => {"
      "  const a = new ArrayBuffer(3);"
      "  postMessage(a, '*', [a]);"
      "  return [a];"
      "})()",
  };

  for (const char* source : cases) {
    DummyExceptionStateForTesting exception_state;
    auto key = CreateIDBKeyFromValue(scope.GetIsolate(),
                                     EvaluateScriptAsObject(scope, source),
                                     exception_state);
    EXPECT_FALSE(key->IsValid());
    EXPECT_TRUE(exception_state.HadException());
  }
}

TEST(IDBKeyFromValueAndKeyPathTest, Exceptions) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  v8::Local<v8::Value> value = EvaluateScriptAsObject(
      scope, "({id:1, get throws() { throw Error(); }})");
  {
    // Key path references a property that throws.
    DummyExceptionStateForTesting exception_state;
    EXPECT_FALSE(CreateIDBKeyFromValueAndKeyPath(
        scope.GetIsolate(), value, IDBKeyPath("throws"), exception_state));
    EXPECT_TRUE(exception_state.HadException());
  }

  {
    // Compound key path references a property that throws.
    DummyExceptionStateForTesting exception_state;
    EXPECT_FALSE(CreateIDBKeyFromValueAndKeyPath(
        scope.GetIsolate(), value, IDBKeyPath(Vector<String>{"id", "throws"}),
        exception_state));
    EXPECT_TRUE(exception_state.HadException());
  }

  {
    // Compound key path references a property that throws, index case.
    DummyExceptionStateForTesting exception_state;
    EXPECT_FALSE(CreateIDBKeyFromValueAndKeyPaths(
        scope.GetIsolate(), value,
        /*store_key_path=*/IDBKeyPath("id"),
        /*index_key_path=*/IDBKeyPath(Vector<String>{"id", "throws"}),
        exception_state));
    EXPECT_TRUE(exception_state.HadException());
  }
}

TEST(IDBKeyFromValueAndKeyPathsTest, IndexKeys) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScriptState* script_state = scope.GetScriptState();
  v8::Isolate* isolate = scope.GetIsolate();
  NonThrowableExceptionState exception_state;

  // object = { foo: { bar: "zee" }, bad: null }
  v8::Local<v8::Value> value =
      V8ObjectBuilder(script_state)
          .Add("foo", V8ObjectBuilder(script_state).AddString("bar", "zee"))
          .AddNull("bad")
          .V8Value();

  // Index key path member matches store key path.
  std::unique_ptr<IDBKey> key = CreateIDBKeyFromValueAndKeyPaths(
      isolate, value,
      /*store_key_path=*/IDBKeyPath("id"),
      /*index_key_path=*/IDBKeyPath(Vector<String>{"id", "foo.bar"}),
      exception_state);
  IDBKey::KeyArray expected;
  expected.emplace_back(IDBKey::CreateNone());
  expected.emplace_back(IDBKey::CreateString("zee"));
  CheckArrayKey(key.get(), expected);

  // Index key path member matches, but there are unmatched members too.
  EXPECT_FALSE(CreateIDBKeyFromValueAndKeyPaths(
      isolate, value,
      /*store_key_path=*/IDBKeyPath("id"),
      /*index_key_path=*/IDBKeyPath(Vector<String>{"id", "foo.bar", "nope"}),
      exception_state));

  // Index key path member matches, but there are invalid subkeys too.
  EXPECT_FALSE(
      CreateIDBKeyFromValueAndKeyPaths(
          isolate, value,
          /*store_key_path=*/IDBKeyPath("id"),
          /*index_key_path=*/IDBKeyPath(Vector<String>{"id", "foo.bar", "bad"}),
          exception_state)
          ->IsValid());

  // Index key path member does not match store key path.
  EXPECT_FALSE(CreateIDBKeyFromValueAndKeyPaths(
      isolate, value,
      /*store_key_path=*/IDBKeyPath("id"),
      /*index_key_path=*/IDBKeyPath(Vector<String>{"id2", "foo.bar"}),
      exception_state));

  // Index key path is not array, matches store key path.
  EXPECT_FALSE(CreateIDBKeyFromValueAndKeyPaths(
      isolate, value,
      /*store_key_path=*/IDBKeyPath("id"),
      /*index_key_path=*/IDBKeyPath("id"), exception_state));
}

TEST(InjectIDBKeyTest, ImplicitValues) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  v8::Isolate* isolate = scope.GetIsolate();
  {
    v8::Local<v8::String> string = V8String(isolate, "string");
    ScriptValue value = ScriptValue(scope.GetIsolate(), string);
    std::unique_ptr<IDBKey> idb_key = IDBKey::CreateNumber(123);
    CheckInjectionIgnored(scope.GetScriptState(), idb_key.get(), value,
                          "length");
  }
  {
    v8::Local<v8::Array> array = v8::Array::New(isolate);
    ScriptValue value = ScriptValue(scope.GetIsolate(), array);
    std::unique_ptr<IDBKey> idb_key = IDBKey::CreateNumber(456);
    CheckInjectionIgnored(scope.GetScriptState(), idb_key.get(), value,
                          "length");
  }
}

TEST(InjectIDBKeyTest, TopLevelPropertyStringValue) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;

  // object = { foo: "zoo" }
  ScriptValue script_object = V8ObjectBuilder(scope.GetScriptState())
                                  .AddString("foo", "zoo")
                                  .GetScriptValue();
  std::unique_ptr<IDBKey> idb_string_key = IDBKey::CreateString("myNewKey");
  CheckInjection(scope.GetScriptState(), idb_string_key.get(), script_object,
                 "bar");
  std::unique_ptr<IDBKey> idb_number_key = IDBKey::CreateNumber(1234);
  CheckInjection(scope.GetScriptState(), idb_number_key.get(), script_object,
                 "bar");

  CheckInjectionDisallowed(scope.GetScriptState(), script_object, "foo.bar");
}

TEST(InjectIDBKeyTest, SubProperty) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScriptState* script_state = scope.GetScriptState();

  // object = { foo: { bar: "zee" } }
  ScriptValue script_object =
      V8ObjectBuilder(script_state)
          .Add("foo", V8ObjectBuilder(script_state).AddString("bar", "zee"))
          .GetScriptValue();

  std::unique_ptr<IDBKey> idb_string_key = IDBKey::CreateString("myNewKey");
  CheckInjection(scope.GetScriptState(), idb_string_key.get(), script_object,
                 "foo.baz");
  std::unique_ptr<IDBKey> idb_number_key = IDBKey::CreateNumber(789);
  CheckInjection(scope.GetScriptState(), idb_number_key.get(), script_object,
                 "foo.baz");
  std::unique_ptr<IDBKey> idb_date_key = IDBKey::CreateDate(4567);
  CheckInjection(scope.GetScriptState(), idb_date_key.get(), script_object,
                 "foo.baz");
  CheckInjection(scope.GetScriptState(), idb_date_key.get(), script_object,
                 "bar");
  std::unique_ptr<IDBKey> idb_array_key =
      IDBKey::CreateArray(IDBKey::KeyArray());
  CheckInjection(scope.GetScriptState(), idb_array_key.get(), script_object,
                 "foo.baz");
  CheckInjection(scope.GetScriptState(), idb_array_key.get(), script_object,
                 "bar");

  CheckInjectionDisallowed(scope.GetScriptState(), script_object,
                           "foo.bar.baz");
  std::unique_ptr<IDBKey> idb_zoo_key = IDBKey::CreateString("zoo");
  CheckInjection(scope.GetScriptState(), idb_zoo_key.get(), script_object,
                 "foo.xyz.foo");
}

TEST(DeserializeIDBValueTest, CurrentVersions) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  v8::Isolate* isolate = scope.GetIsolate();

  Vector<char> object_bytes;
  v8::Local<v8::Object> empty_object = v8::Object::New(isolate);
  SerializeV8Value(empty_object, isolate, &object_bytes);
  std::unique_ptr<IDBValue> idb_value =
      CreateIDBValue(isolate, std::move(object_bytes), 42.0, "foo");

  v8::Local<v8::Value> v8_value =
      DeserializeIDBValue(scope.GetScriptState(), idb_value.get());
  EXPECT_TRUE(!scope.GetExceptionState().HadException());

  ASSERT_TRUE(v8_value->IsObject());
  v8::Local<v8::Object> v8_value_object = v8_value.As<v8::Object>();
  v8::Local<v8::Value> v8_number_value =
      v8_value_object->Get(scope.GetContext(), V8AtomicString(isolate, "foo"))
          .ToLocalChecked();
  ASSERT_TRUE(v8_number_value->IsNumber());
  v8::Local<v8::Number> v8_number = v8_number_value.As<v8::Number>();
  EXPECT_EQ(v8_number->Value(), 42.0);
}

TEST(DeserializeIDBValueTest, FutureV8Version) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  v8::Isolate* isolate = scope.GetIsolate();

  // Pretend that the object was serialized by a future version of V8.
  Vector<char> object_bytes;
  v8::Local<v8::Object> empty_object = v8::Object::New(isolate);
  SerializeV8Value(empty_object, isolate, &object_bytes);
  object_bytes[kSSVHeaderV8VersionTagOffset] += 1;

  // The call sequence below mimics IndexedDB's usage pattern when attempting to
  // read a value in an object store with a key generator and a key path, but
  // the serialized value uses a newer format version.
  //
  // http://crbug.com/703704 has a reproduction for this test's circumstances.
  std::unique_ptr<IDBValue> idb_value =
      CreateIDBValue(isolate, std::move(object_bytes), 42.0, "foo");

  v8::Local<v8::Value> v8_value =
      DeserializeIDBValue(scope.GetScriptState(), idb_value.get());
  EXPECT_TRUE(!scope.GetExceptionState().HadException());
  EXPECT_TRUE(v8_value->IsNull());
}

TEST(DeserializeIDBValueTest, InjectionIntoNonObject) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  v8::Isolate* isolate = scope.GetIsolate();

  // Simulate a storage corruption where an object is read back as a number.
  // This test uses a one-segment key path.
  Vector<char> object_bytes;
  v8::Local<v8::Number> number = v8::Number::New(isolate, 42.0);
  SerializeV8Value(number, isolate, &object_bytes);
  std::unique_ptr<IDBValue> idb_value =
      CreateIDBValue(isolate, std::move(object_bytes), 42.0, "foo");

  v8::Local<v8::Value> v8_value =
      DeserializeIDBValue(scope.GetScriptState(), idb_value.get());
  EXPECT_TRUE(!scope.GetExceptionState().HadException());
  ASSERT_TRUE(v8_value->IsNumber());
  v8::Local<v8::Number> v8_number = v8_value.As<v8::Number>();
  EXPECT_EQ(v8_number->Value(), 42.0);
}

TEST(DeserializeIDBValueTest, NestedInjectionIntoNonObject) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  v8::Isolate* isolate = scope.GetIsolate();

  // Simulate a storage corruption where an object is read back as a number.
  // This test uses a multiple-segment key path.
  Vector<char> object_bytes;
  v8::Local<v8::Number> number = v8::Number::New(isolate, 42.0);
  SerializeV8Value(number, isolate, &object_bytes);
  std::unique_ptr<IDBValue> idb_value =
      CreateIDBValue(isolate, std::move(object_bytes), 42.0, "foo.bar");

  v8::Local<v8::Value> v8_value =
      DeserializeIDBValue(scope.GetScriptState(), idb_value.get());
  EXPECT_TRUE(!scope.GetExceptionState().HadException());
  ASSERT_TRUE(v8_value->IsNumber());
  v8::Local<v8::Number> v8_number = v8_value.As<v8::Number>();
  EXPECT_EQ(v8_number->Value(), 42.0);
}

}  // namespace blink

"""

```