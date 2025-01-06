Response:
The user wants a summary of the functionality of the provided C++ code snippet. This snippet is part of the `test-serialize.cc` file in the V8 project.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the core purpose of the file:** The filename `test-serialize.cc` strongly suggests that this file contains tests related to the serialization and deserialization mechanisms within V8. The presence of `SnapshotCreator`, `StartupData`, and `CustomSnapshotDataBlob` further confirms this.

2. **Analyze the code structure:** The code is organized into a series of `UNINITIALIZED_TEST` and `TEST` blocks. This indicates these are individual test cases. Each test case likely focuses on a specific aspect of the serialization process.

3. **Examine individual test cases and group them by functionality:**  Go through each test case and try to understand what it's testing. Look for keywords and patterns:

    * **`CustomSnapshotDataBlob`:**  This is the most frequent pattern, indicating tests related to creating and using custom snapshot data blobs. Further analysis within these tests reveals different scenarios being tested, such as:
        * Basic functionality with simple JavaScript code.
        * Handling of strings and internalization.
        * Dealing with compiled Irregexp code and its flushing/keeping behavior.
        * Verifying snapshot checksums.
        * Serializing and deserializing internal fields of objects.
        * Handling various types of TypedArrays (Uint8Array, Int32Array, etc.), including shared array buffers and array buffers with offsets.
        * Testing DataViews.
        * Handling detached ArrayBuffers.
        * Differentiating between on-heap and off-heap TypedArrays.
        * Scenarios without embedder field callbacks.
        * More complex JavaScript code with multiple functions.
        * Cases involving outdated contexts and potential overflow.
        * Testing with `v8::Locker`.
        * Scenarios leading to stack overflow.
    * **`SnapshotChecksum`:**  Specifically tests the verification of snapshot checksums.
    * **`SerializeInternalFields` and `DeserializeInternalFields`:** These functions are used in tests related to serializing and deserializing custom data associated with JavaScript objects.
    * **`SnapshotDataBlobWithWarmup` and `CustomSnapshotDataBlobWithWarmup`:** These tests focus on the "warm-up" process of snapshots, where scripts are run to pre-compile functions.
    * **`CustomSnapshotDataBlobWithKeep`:** Tests the option to keep function code during snapshot creation.
    * **`CustomSnapshotDataBlobImmortalImmovableRoots`:**  Tests a specific internal detail about the layout of the snapshot.
    * **Basic `TEST` macros (`TestThatAlwaysSucceeds`, `TestCheckThatAlwaysFails`, `TestFatal`):** These appear to be basic sanity checks or examples of different test outcomes.
    * **`CountBuiltins`:**  This utility function is used in other test files to verify the number of built-in functions.
    * **`CompileScript` and `CompileScriptAndProduceCache`:** These are utility functions used for compiling JavaScript code with and without producing code cache, used in other test files (not directly part of the serialization tests here, but present in the file).

4. **Identify connections to JavaScript functionality:** Many of the `CustomSnapshotDataBlob` tests directly execute JavaScript code using `CompileRun`. This confirms the relationship between the serialization tests and JavaScript's runtime behavior, especially concerning object states and data structures like arrays and typed arrays.

5. **Note any explicit error handling or edge case testing:** The tests involving stack overflow, detached array buffers, and the alternating array buffer allocator suggest an attempt to cover potential failure scenarios and edge cases during serialization.

6. **Summarize the findings:** Combine the observations into a concise summary, highlighting the key functionalities being tested. Emphasize the core goal of testing V8's serialization and deserialization mechanisms.

7. **Address the specific questions in the prompt:**

    * **Functionality:** List the discovered functionalities based on the test cases.
    * **Torque:**  Confirm that the file is C++ and not Torque based on the `.cc` extension.
    * **JavaScript relationship:** Explain the connection through the execution of JavaScript code within the tests and provide relevant examples.
    * **Code logic and input/output:** For simple tests, provide illustrative examples of input JavaScript code and expected outcomes.
    * **Common programming errors:** Point out the tests related to potential errors, such as detaching array buffers.
    * **Part 2 of 8:** Acknowledge the context provided by the user.

By following these steps, a comprehensive and accurate summary of the code's functionality can be generated.这是目录为v8/test/cctest/test-serialize.cc的一个v8源代码的第2部分，主要功能是测试 V8 引擎的序列化和反序列化机制，特别是针对自定义快照数据（Custom Snapshot Data Blob）的功能。

以下是代码片段中测试功能的详细列举和说明：

**核心功能：测试自定义快照数据 (Custom Snapshot Data Blob)**

这一部分代码的核心围绕着 `CreateSnapshotDataBlob` 函数以及与之相关的 `v8::SnapshotCreator` 和 `v8::Isolate::CreateParams` 来测试如何创建和使用自定义的快照数据。自定义快照允许开发者在 V8 引擎启动时加载预先序列化的数据和状态，从而加速启动过程。

**具体测试的功能点：**

1. **基本的快照创建和加载：**
   -  测试使用 `CreateSnapshotDataBlob` 创建包含简单 JavaScript 代码 (`"function f() { return 'AB'; }"`) 的快照。
   -  测试使用创建的快照 `data1` 来创建一个新的 `v8::Isolate`，并验证在新的 Isolate 中可以执行快照中定义的函数 `f()`，并且其行为符合预期（返回字符串 "AB"）。
   -  验证从快照中加载的字符串是否不是内部化字符串，也不是只读堆中的字符串。

2. **处理包含正则表达式的快照：**
   -  测试 `TestCustomSnapshotDataBlobWithIrregexpCode` 函数，它针对包含正则表达式的 JavaScript 代码创建快照。
   -  测试了两种 `FunctionCodeHandling` 模式：`kKeep` 和 `kClear`，分别代表在序列化时保留或清除已编译的函数代码。
   -  验证在反序列化后，正则表达式的代码是否按照 `FunctionCodeHandling` 的设置进行处理。例如，`kClear` 模式下，已编译的非原子正则表达式代码会被清除。
   -  验证原子正则表达式在快照中仍然有效。

3. **快照校验和 (Snapshot Checksum)：**
   -  测试 `SnapshotChecksum` 函数，验证快照数据的校验和机制。
   -  测试创建快照后，修改快照数据会导致校验和验证失败。

4. **序列化和反序列化内部字段 (Internal Fields)：**
   -  测试 `SerializeInternalFields` 和 `DeserializeInternalFields` 函数以及相关的测试用例。
   -  允许在快照创建时，通过回调函数 `SerializeInternalFields` 将对象的内部字段数据序列化到快照中。
   -  在反序列化时，通过 `DeserializeInternalFields` 回调函数将这些数据恢复到新的 Isolate 中。
   -  测试了在序列化和反序列化过程中传递自定义数据 (`void* data`) 的功能。

5. **处理 TypedArray (类型化数组)：**
   -  `TypedArrayTestHelper` 函数是一个辅助函数，用于测试包含不同类型 TypedArray 的快照。
   -  测试了 `Uint8Array`, `Uint32Array`, `Int16Array` 等不同类型的 TypedArray 的序列化和反序列化。
   -  测试了 `SharedArrayBuffer` 的序列化和反序列化。
   -  测试了带有偏移量的 `ArrayBuffer` 创建的 TypedArray 的序列化和反序列化，并验证它们是否指向同一块内存。
   -  测试了 `DataView` 的序列化和反序列化。
   -  测试了包含大量 ArrayBuffer 的快照创建和加载。
   -  测试了 `Detached ArrayBuffer` (已分离的 ArrayBuffer) 的序列化和反序列化。

6. **处理 On-Heap 和 Off-Heap TypedArray：**
   -  测试了快照如何处理存储在堆上（On-Heap）和堆外（Off-Heap）的 TypedArray 的数据。

7. **TypedArray 没有 Embedder Field Callback：**
   -  测试了在创建包含 TypedArray 的快照时，不提供 `SerializeInternalFieldsCallback` 的情况。

8. **更复杂的快照场景：**
   -  `CustomSnapshotDataBlob2` 测试了包含多个函数调用的更复杂的 JavaScript 代码的快照创建和加载。

9. **处理过时的上下文和溢出：**
   -  `CustomSnapshotDataBlobOutdatedContextWithOverflow` 测试了在快照创建和加载过程中，上下文可能发生变化的情况，以及如何处理潜在的溢出。

10. **与 Locker 一起使用快照：**
    - `CustomSnapshotDataBlobWithLocker` 测试了在持有 `v8::Locker` 的情况下创建和加载快照。

11. **处理栈溢出：**
    - `CustomSnapshotDataBlobStackOverflow` 测试了在快照中包含可能导致栈溢出的数据结构（例如，深度嵌套的数组）的情况。

12. **快照预热 (Snapshot Warmup)：**
    - `SnapshotDataBlobWithWarmup` 和 `CustomSnapshotDataBlobWithWarmup` 测试了快照预热的功能。预热允许在创建快照后，执行一段脚本来预先编译一些函数，从而进一步提升启动性能。

13. **保留函数代码的快照：**
    - `CustomSnapshotDataBlobWithKeep` 测试了在创建快照时，使用 `FunctionCodeHandling::kKeep` 选项来保留已编译的函数代码。

14. **处理 Immortal Immovable Roots：**
    - `CustomSnapshotDataBlobImmortalImmovableRoots` 测试了快照创建过程中，对 Immortal Immovable Roots 的处理，这是一个 V8 内部的优化机制。

15. **基本的测试框架示例：**
    -  `TestThatAlwaysSucceeds`, `TestCheckThatAlwaysFails`, `TestFatal` 展示了 CCTests 的基本使用方法，包括成功、失败和致命错误的情况。

16. **统计 Builtin 函数：**
    - `CountBuiltins` 是一个辅助函数，用于统计堆中 Builtin 代码对象的数量，这可能用于验证快照加载过程中 Builtin 函数的处理。

17. **编译脚本并生成/使用缓存：**
    - `CompileScript` 和 `CompileScriptAndProduceCache` 是用于编译 JavaScript 代码并生成或使用代码缓存的辅助函数，虽然它们不直接属于快照测试的核心功能，但也在这个文件中出现，可能用于其他相关的测试场景。

**如果 v8/test/cctest/test-serialize.cc 以 .tq 结尾：**

如果文件名是 `test-serialize.tq`，那么它将是一个 V8 Torque 源代码文件。Torque 是一种 V8 用于定义内置函数和运行时函数的领域特定语言。然而，当前的文件名是 `.cc`，表明它是 C++ 源代码。

**与 JavaScript 的功能关系及示例：**

这些测试直接关联到 JavaScript 的运行时行为，因为它们涉及到序列化和反序列化 JavaScript 对象、函数、数组、类型化数组等。

例如，在测试类型化数组时：

```javascript
// 快照创建时的 JavaScript 代码
var x = new Uint8Array(1);
x[0] = 100;

// 快照加载后，在新的 Isolate 中
console.log(x[0]); // 输出 100，证明类型化数组的状态被正确恢复
```

在测试正则表达式时：

```javascript
// 快照创建时的 JavaScript 代码
var re = /abc/;
function f() { return re.test('abc'); }

// 快照加载后，在新的 Isolate 中
console.log(f()); // 输出 true，证明正则表达式对象和使用它的函数的状态被正确恢复
```

**代码逻辑推理示例：**

在 `SnapshotChecksum` 测试中：

**假设输入：**

1. JavaScript 源代码 `"function f() { return 42; }"`
2. 使用 `CreateSnapshotDataBlob` 创建了对应的快照数据 `data1`。

**输出：**

1. `i::Snapshot::VerifyChecksum(&data1)` 返回 `true` (初始快照校验和验证成功)。
2. 修改 `data1.data` 中的一个字节。
3. `i::Snapshot::VerifyChecksum(&data1)` 返回 `false` (修改后的快照校验和验证失败)。

**用户常见的编程错误示例：**

与这些测试相关的常见编程错误可能包括：

1. **不正确地处理快照数据：**  例如，手动修改快照数据而不更新校验和，导致加载失败或出现不可预测的行为。测试中的 `SnapshotChecksum` 就模拟了这种情况。
2. **在序列化/反序列化过程中丢失对象状态：**  例如，如果自定义对象的内部状态没有正确地通过 `SerializeInternalFieldsCallback` 和 `DeserializeInternalFieldsCallback` 进行处理，那么在快照加载后，对象可能处于不一致的状态。
3. **错误地假设跨 Isolate 的对象引用保持不变：** 快照用于创建新的 Isolate，对象在新的 Isolate 中是全新的实例，而不是原始 Isolate 中的对象。测试中创建新的 `v8::Isolate` 并验证其状态就体现了这一点。
4. **在快照中包含不必要的大型对象或数据：** 这会增加快照的大小和加载时间，影响启动性能。

**归纳一下它的功能 (作为第2部分)：**

作为 `test-serialize.cc` 的第 2 部分，这段代码延续了对 V8 序列化机制的测试，并且更加深入地探索了**自定义快照数据 (Custom Snapshot Data Blob)** 的各种应用场景和细节。它涵盖了从简单的代码序列化到复杂的对象状态（包括类型化数组、正则表达式、内部字段等）的序列化和反序列化，并测试了相关的错误处理和优化策略（如快照校验和和预热）。 这部分主要关注使用 C++ API 来创建和加载自定义快照，并验证其在不同场景下的正确性和健壮性。

Prompt: 
```
这是目录为v8/test/cctest/test-serialize.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-serialize.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共8部分，请归纳一下它的功能

"""
:Isolate* isolate1 = TestSerializer::NewIsolate(params1);
  {
    v8::Isolate::Scope i_scope(isolate1);
    v8::HandleScope h_scope(isolate1);
    v8::Local<v8::Context> context = v8::Context::New(isolate1);
    v8::Context::Scope c_scope(context);
    v8::Local<v8::Value> result = CompileRun("f()").As<v8::Value>();
    CHECK(result->IsString());
    i::Tagged<i::String> str =
        *v8::Utils::OpenDirectHandle(*result.As<v8::String>());
    CHECK_EQ(std::string(str->ToCString().get()), "AB");
    CHECK(!IsInternalizedString(str));
    CHECK(!i::ReadOnlyHeap::Contains(str));
  }
  isolate1->Dispose();
  delete[] data1.data;  // We can dispose of the snapshot blob now.
  FreeCurrentEmbeddedBlob();
}

namespace {

void TestCustomSnapshotDataBlobWithIrregexpCode(
    v8::SnapshotCreator::FunctionCodeHandling function_code_handling) {
  DisableAlwaysOpt();
  const char* source =
      "var re1 = /\\/\\*[^*]*\\*+([^/*][^*]*\\*+)*\\//;\n"
      "function f() { return '/* a comment */'.search(re1); }\n"
      "function g() { return 'not a comment'.search(re1); }\n"
      "function h() { return '// this is a comment'.search(re1); }\n"
      "var re2 = /a/;\n"
      "function i() { return '/* a comment */'.search(re2); }\n"
      "f(); f(); g(); g(); h(); h(); i(); i();\n";

  DisableEmbeddedBlobRefcounting();
  v8::StartupData data1 =
      CreateSnapshotDataBlobInternal(function_code_handling, source);

  v8::Isolate::CreateParams params1;
  params1.snapshot_blob = &data1;
  params1.array_buffer_allocator = CcTest::array_buffer_allocator();

  // Test-appropriate equivalent of v8::Isolate::New.
  v8::Isolate* isolate1 = TestSerializer::NewIsolate(params1);
  Isolate* i_isolate1 = reinterpret_cast<Isolate*>(isolate1);
  {
    v8::Isolate::Scope i_scope(isolate1);
    v8::HandleScope h_scope(isolate1);
    v8::Local<v8::Context> context = v8::Context::New(isolate1);
    v8::Context::Scope c_scope(context);
    {
      // Check that compiled irregexp code has been flushed prior to
      // serialization.
      i::DirectHandle<i::JSRegExp> re =
          Utils::OpenDirectHandle(*CompileRun("re1").As<v8::RegExp>());
      CHECK(!re->data(i_isolate1)->HasCompiledCode());
    }
    {
      v8::Maybe<int32_t> result =
          CompileRun("f()")->Int32Value(isolate1->GetCurrentContext());
      CHECK_EQ(0, result.FromJust());
    }
    {
      v8::Maybe<int32_t> result =
          CompileRun("g()")->Int32Value(isolate1->GetCurrentContext());
      CHECK_EQ(-1, result.FromJust());
    }
    {
      v8::Maybe<int32_t> result =
          CompileRun("h()")->Int32Value(isolate1->GetCurrentContext());
      CHECK_EQ(-1, result.FromJust());
    }
    {
      // Check that ATOM regexp remains valid.
      i::DirectHandle<i::JSRegExp> re =
          Utils::OpenDirectHandle(*CompileRun("re2").As<v8::RegExp>());
      i::Tagged<i::RegExpData> data = re->data(i_isolate1);
      CHECK_EQ(data->type_tag(), RegExpData::Type::ATOM);
      CHECK(!data->HasCompiledCode());
    }
  }
  isolate1->Dispose();
  delete[] data1.data;  // We can dispose of the snapshot blob now.
  FreeCurrentEmbeddedBlob();
}

}  // namespace

UNINITIALIZED_TEST(CustomSnapshotDataBlobWithIrregexpCodeKeepCode) {
  TestCustomSnapshotDataBlobWithIrregexpCode(
      v8::SnapshotCreator::FunctionCodeHandling::kKeep);
}

UNINITIALIZED_TEST(CustomSnapshotDataBlobWithIrregexpCodeClearCode) {
  TestCustomSnapshotDataBlobWithIrregexpCode(
      v8::SnapshotCreator::FunctionCodeHandling::kClear);
}

UNINITIALIZED_TEST(SnapshotChecksum) {
  DisableAlwaysOpt();
  const char* source1 = "function f() { return 42; }";

  DisableEmbeddedBlobRefcounting();
  v8::StartupData data1 = CreateSnapshotDataBlob(source1);
  CHECK(i::Snapshot::VerifyChecksum(&data1));
  const_cast<char*>(data1.data)[142] = data1.data[142] ^ 4;  // Flip a bit.
  CHECK(!i::Snapshot::VerifyChecksum(&data1));
  delete[] data1.data;  // We can dispose of the snapshot blob now.
  FreeCurrentEmbeddedBlob();
}

struct InternalFieldData {
  uint32_t data;
};

v8::StartupData SerializeInternalFields(v8::Local<v8::Object> holder, int index,
                                        void* data) {
  if (data == reinterpret_cast<void*>(2000)) {
    // Used for SnapshotCreatorTemplates test. We check that none of the fields
    // have been cleared yet.
    CHECK_NOT_NULL(holder->GetAlignedPointerFromInternalField(1));
  } else {
    CHECK_EQ(reinterpret_cast<void*>(2016), data);
  }
  if (index != 1) return {nullptr, 0};
  InternalFieldData* embedder_field = static_cast<InternalFieldData*>(
      holder->GetAlignedPointerFromInternalField(index));
  if (embedder_field == nullptr) return {nullptr, 0};
  int size = sizeof(*embedder_field);
  char* payload = new char[size];
  // We simply use memcpy to serialize the content.
  memcpy(payload, embedder_field, size);
  return {payload, size};
}

std::vector<InternalFieldData*> deserialized_data;

void DeserializeInternalFields(v8::Local<v8::Object> holder, int index,
                               v8::StartupData payload, void* data) {
  if (payload.raw_size == 0) {
    holder->SetAlignedPointerInInternalField(index, nullptr);
    return;
  }
  CHECK_EQ(reinterpret_cast<void*>(2017), data);
  InternalFieldData* embedder_field = new InternalFieldData{0};
  memcpy(embedder_field, payload.data, payload.raw_size);
  holder->SetAlignedPointerInInternalField(index, embedder_field);
  deserialized_data.push_back(embedder_field);
}

using Int32Expectations = std::vector<std::tuple<const char*, int32_t>>;

void TestInt32Expectations(const Int32Expectations& expectations) {
  for (const auto& e : expectations) {
    ExpectInt32(std::get<0>(e), std::get<1>(e));
  }
}

struct SnapshotCreatorParams {
  explicit SnapshotCreatorParams(const intptr_t* external_references = nullptr,
                                 const StartupData* existing_blob = nullptr) {
    allocator.reset(ArrayBuffer::Allocator::NewDefaultAllocator());
    create_params.array_buffer_allocator = allocator.get();
    create_params.external_references = external_references;
    create_params.snapshot_blob = existing_blob;
  }

  std::unique_ptr<v8::ArrayBuffer::Allocator> allocator;
  v8::Isolate::CreateParams create_params;
};

void TypedArrayTestHelper(
    const char* code, const Int32Expectations& expectations,
    const char* code_to_run_after_restore = nullptr,
    const Int32Expectations& after_restore_expectations = Int32Expectations(),
    v8::ArrayBuffer::Allocator* allocator = nullptr) {
  DisableAlwaysOpt();
  i::v8_flags.allow_natives_syntax = true;
  DisableEmbeddedBlobRefcounting();
  v8::StartupData blob;
  {
    SnapshotCreatorParams testing_params;
    v8::SnapshotCreator creator(testing_params.create_params);
    v8::Isolate* isolate = creator.GetIsolate();
    {
      v8::HandleScope handle_scope(isolate);
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      v8::Context::Scope context_scope(context);

      CompileRun(code);
      TestInt32Expectations(expectations);
      creator.SetDefaultContext(
          context, v8::SerializeInternalFieldsCallback(
                       SerializeInternalFields, reinterpret_cast<void*>(2016)));
    }
    blob =
        creator.CreateBlob(v8::SnapshotCreator::FunctionCodeHandling::kClear);
  }

  v8::Isolate::CreateParams create_params;
  create_params.snapshot_blob = &blob;
  create_params.array_buffer_allocator =
      allocator != nullptr ? allocator : CcTest::array_buffer_allocator();
  v8::Isolate* isolate = TestSerializer::NewIsolate(create_params);
  {
    v8::Isolate::Scope i_scope(isolate);
    v8::HandleScope h_scope(isolate);
    v8::Local<v8::Context> context = v8::Context::New(
        isolate, nullptr, v8::MaybeLocal<v8::ObjectTemplate>(),
        v8::MaybeLocal<v8::Value>(),
        v8::DeserializeInternalFieldsCallback(DeserializeInternalFields,
                                              reinterpret_cast<void*>(2017)));
    CHECK(deserialized_data.empty());  // We do not expect any embedder data.
    v8::Context::Scope c_scope(context);
    TestInt32Expectations(expectations);
    if (code_to_run_after_restore) {
      CompileRun(code_to_run_after_restore);
    }
    TestInt32Expectations(after_restore_expectations);
  }
  isolate->Dispose();
  delete[] blob.data;  // We can dispose of the snapshot blob now.
  FreeCurrentEmbeddedBlob();
}

UNINITIALIZED_TEST(CustomSnapshotDataBlobWithOffHeapTypedArray) {
  const char* code =
      "var x = new Uint8Array(128);"
      "x[0] = 12;"
      "var arr = new Array(17);"
      "arr[1] = 24;"
      "var y = new Uint32Array(arr);"
      "var buffer = new ArrayBuffer(128);"
      "var z = new Int16Array(buffer);"
      "z[0] = 48;";
  Int32Expectations expectations = {std::make_tuple("x[0]", 12),
                                    std::make_tuple("y[1]", 24),
                                    std::make_tuple("z[0]", 48)};

  TypedArrayTestHelper(code, expectations);
}

UNINITIALIZED_TEST(CustomSnapshotDataBlobSharedArrayBuffer) {
  const char* code =
      "var x = new Int32Array([12, 24, 48, 96]);"
      "var y = new Uint8Array(x.buffer)";
  Int32Expectations expectations = {
    std::make_tuple("x[0]", 12),
    std::make_tuple("x[1]", 24),
#if !V8_TARGET_BIG_ENDIAN
    std::make_tuple("y[0]", 12),
    std::make_tuple("y[1]", 0),
    std::make_tuple("y[2]", 0),
    std::make_tuple("y[3]", 0),
    std::make_tuple("y[4]", 24)
#else
    std::make_tuple("y[3]", 12),
    std::make_tuple("y[2]", 0),
    std::make_tuple("y[1]", 0),
    std::make_tuple("y[0]", 0),
    std::make_tuple("y[7]", 24)
#endif
  };

  TypedArrayTestHelper(code, expectations);
}

UNINITIALIZED_TEST(CustomSnapshotDataBlobArrayBufferWithOffset) {
  const char* code =
      "var x = new Int32Array([12, 24, 48, 96]);"
      "var y = new Int32Array(x.buffer, 4, 2)";
  Int32Expectations expectations = {
      std::make_tuple("x[1]", 24),
      std::make_tuple("x[2]", 48),
      std::make_tuple("y[0]", 24),
      std::make_tuple("y[1]", 48),
  };

  // Verify that the typed arrays use the same buffer (not independent copies).
  const char* code_to_run_after_restore = "x[2] = 57; y[0] = 42;";
  Int32Expectations after_restore_expectations = {
      std::make_tuple("x[1]", 42),
      std::make_tuple("y[1]", 57),
  };

  TypedArrayTestHelper(code, expectations, code_to_run_after_restore,
                       after_restore_expectations);
}

UNINITIALIZED_TEST(CustomSnapshotDataBlobDataView) {
  const char* code =
      "var x = new Int8Array([1, 2, 3, 4]);"
      "var v = new DataView(x.buffer)";
  Int32Expectations expectations = {std::make_tuple("v.getInt8(0)", 1),
                                    std::make_tuple("v.getInt8(1)", 2),
                                    std::make_tuple("v.getInt16(0)", 258),
                                    std::make_tuple("v.getInt16(1)", 515)};

  TypedArrayTestHelper(code, expectations);
}

namespace {
class AlternatingArrayBufferAllocator : public v8::ArrayBuffer::Allocator {
 public:
  AlternatingArrayBufferAllocator()
      : allocation_fails_(false),
        allocator_(v8::ArrayBuffer::Allocator::NewDefaultAllocator()) {}
  ~AlternatingArrayBufferAllocator() { delete allocator_; }
  void* Allocate(size_t length) override {
    allocation_fails_ = !allocation_fails_;
    if (allocation_fails_) return nullptr;
    return allocator_->Allocate(length);
  }

  void* AllocateUninitialized(size_t length) override {
    return this->Allocate(length);
  }

  void Free(void* data, size_t size) override { allocator_->Free(data, size); }

  void* Reallocate(void* data, size_t old_length, size_t new_length) override {
    START_ALLOW_USE_DEPRECATED()
    return allocator_->Reallocate(data, old_length, new_length);
    END_ALLOW_USE_DEPRECATED()
  }

 private:
  bool allocation_fails_;
  v8::ArrayBuffer::Allocator* allocator_;
};
}  // anonymous namespace

UNINITIALIZED_TEST(CustomSnapshotManyArrayBuffers) {
  const char* code =
      "var buffers = [];"
      "for (let i = 0; i < 70; i++) buffers.push(new Uint8Array(1000));";
  Int32Expectations expectations = {std::make_tuple("buffers.length", 70)};
  std::unique_ptr<v8::ArrayBuffer::Allocator> allocator(
      new AlternatingArrayBufferAllocator());
  TypedArrayTestHelper(code, expectations, nullptr, Int32Expectations(),
                       allocator.get());
}

UNINITIALIZED_TEST(CustomSnapshotDataBlobDetachedArrayBuffer) {
  const char* code =
      "var x = new Int16Array([12, 24, 48]);"
      "%ArrayBufferDetach(x.buffer);";
  Int32Expectations expectations = {std::make_tuple("x.buffer.byteLength", 0),
                                    std::make_tuple("x.length", 0)};

  DisableAlwaysOpt();
  i::v8_flags.allow_natives_syntax = true;
  DisableEmbeddedBlobRefcounting();
  v8::StartupData blob;
  {
    SnapshotCreatorParams testing_params;
    v8::SnapshotCreator creator(testing_params.create_params);
    v8::Isolate* isolate = creator.GetIsolate();
    {
      v8::HandleScope handle_scope(isolate);
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      v8::Context::Scope context_scope(context);

      CompileRun(code);
      TestInt32Expectations(expectations);
      creator.SetDefaultContext(
          context, v8::SerializeInternalFieldsCallback(
                       SerializeInternalFields, reinterpret_cast<void*>(2016)));
    }
    blob =
        creator.CreateBlob(v8::SnapshotCreator::FunctionCodeHandling::kClear);
  }

  v8::Isolate::CreateParams create_params;
  create_params.snapshot_blob = &blob;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = TestSerializer::NewIsolate(create_params);
  {
    v8::Isolate::Scope i_scope(isolate);
    v8::HandleScope h_scope(isolate);
    v8::Local<v8::Context> context = v8::Context::New(
        isolate, nullptr, v8::MaybeLocal<v8::ObjectTemplate>(),
        v8::MaybeLocal<v8::Value>(),
        v8::DeserializeInternalFieldsCallback(DeserializeInternalFields,
                                              reinterpret_cast<void*>(2017)));
    v8::Context::Scope c_scope(context);
    TestInt32Expectations(expectations);

    v8::Local<v8::Value> x = CompileRun("x");
    CHECK(x->IsTypedArray());
    i::DirectHandle<i::JSTypedArray> array =
        i::Cast<i::JSTypedArray>(v8::Utils::OpenDirectHandle(*x));
    CHECK(array->WasDetached());
  }
  isolate->Dispose();
  delete[] blob.data;  // We can dispose of the snapshot blob now.
  FreeCurrentEmbeddedBlob();
}

i::Handle<i::JSArrayBuffer> GetBufferFromTypedArray(
    v8::Local<v8::Value> typed_array) {
  CHECK(typed_array->IsTypedArray());

  i::DirectHandle<i::JSArrayBufferView> view =
      i::Cast<i::JSArrayBufferView>(v8::Utils::OpenDirectHandle(*typed_array));

  return i::handle(i::Cast<i::JSArrayBuffer>(view->buffer()),
                   view->GetIsolate());
}

UNINITIALIZED_TEST(CustomSnapshotDataBlobOnOrOffHeapTypedArray) {
  const char* code =
      "var x = new Uint8Array(8);"
      "x[0] = 12;"
      "x[7] = 24;"
      "var y = new Int16Array([12, 24, 48]);"
      "var z = new Int32Array(64);"
      "z[0] = 96;";
  Int32Expectations expectations = {
      std::make_tuple("x[0]", 12), std::make_tuple("x[7]", 24),
      std::make_tuple("y[2]", 48), std::make_tuple("z[0]", 96)};

  DisableAlwaysOpt();
  i::v8_flags.allow_natives_syntax = true;
  DisableEmbeddedBlobRefcounting();
  v8::StartupData blob;
  {
    SnapshotCreatorParams testing_params;
    v8::SnapshotCreator creator(testing_params.create_params);
    v8::Isolate* isolate = creator.GetIsolate();
    {
      v8::HandleScope handle_scope(isolate);
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      v8::Context::Scope context_scope(context);

      CompileRun(code);
      TestInt32Expectations(expectations);
      i::DirectHandle<i::JSArrayBuffer> buffer =
          GetBufferFromTypedArray(CompileRun("x"));
      // The resulting buffer should be on-heap.
      CHECK(buffer->IsEmpty());
      creator.SetDefaultContext(
          context, v8::SerializeInternalFieldsCallback(
                       SerializeInternalFields, reinterpret_cast<void*>(2016)));
    }
    blob =
        creator.CreateBlob(v8::SnapshotCreator::FunctionCodeHandling::kClear);
  }

  v8::Isolate::CreateParams create_params;
  create_params.snapshot_blob = &blob;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = TestSerializer::NewIsolate(create_params);
  {
    v8::Isolate::Scope i_scope(isolate);
    v8::HandleScope h_scope(isolate);
    v8::Local<v8::Context> context = v8::Context::New(
        isolate, nullptr, v8::MaybeLocal<v8::ObjectTemplate>(),
        v8::MaybeLocal<v8::Value>(),
        v8::DeserializeInternalFieldsCallback(DeserializeInternalFields,
                                              reinterpret_cast<void*>(2017)));
    v8::Context::Scope c_scope(context);
    TestInt32Expectations(expectations);

    i::DirectHandle<i::JSArrayBuffer> buffer =
        GetBufferFromTypedArray(CompileRun("x"));
    // The resulting buffer should be on-heap.
    CHECK(buffer->IsEmpty());

    buffer = GetBufferFromTypedArray(CompileRun("y"));
    CHECK(buffer->IsEmpty());

    buffer = GetBufferFromTypedArray(CompileRun("z"));
    // The resulting buffer should be off-heap.
    CHECK(!buffer->IsEmpty());
  }
  isolate->Dispose();
  delete[] blob.data;  // We can dispose of the snapshot blob now.
  FreeCurrentEmbeddedBlob();
}

UNINITIALIZED_TEST(CustomSnapshotDataBlobTypedArrayNoEmbedderFieldCallback) {
  const char* code = "var x = new Uint8Array(8);";
  DisableAlwaysOpt();
  i::v8_flags.allow_natives_syntax = true;
  DisableEmbeddedBlobRefcounting();
  v8::StartupData blob;
  {
    SnapshotCreatorParams testing_params;
    v8::SnapshotCreator creator(testing_params.create_params);
    v8::Isolate* isolate = creator.GetIsolate();
    {
      v8::HandleScope handle_scope(isolate);
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      v8::Context::Scope context_scope(context);

      CompileRun(code);
      creator.SetDefaultContext(context, v8::SerializeInternalFieldsCallback());
    }
    blob =
        creator.CreateBlob(v8::SnapshotCreator::FunctionCodeHandling::kClear);
  }

  v8::Isolate::CreateParams create_params;
  create_params.snapshot_blob = &blob;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = TestSerializer::NewIsolate(create_params);
  {
    v8::Isolate::Scope i_scope(isolate);
    v8::HandleScope h_scope(isolate);
    v8::Local<v8::Context> context = v8::Context::New(
        isolate, nullptr, v8::MaybeLocal<v8::ObjectTemplate>(),
        v8::MaybeLocal<v8::Value>(), v8::DeserializeInternalFieldsCallback());
    v8::Context::Scope c_scope(context);
  }
  isolate->Dispose();
  delete[] blob.data;  // We can dispose of the snapshot blob now.
  FreeCurrentEmbeddedBlob();
}

UNINITIALIZED_TEST(CustomSnapshotDataBlob2) {
  DisableAlwaysOpt();
  const char* source2 =
      "function f() { return g() * 2; }"
      "function g() { return 43; }"
      "/./.test('a')";

  DisableEmbeddedBlobRefcounting();
  v8::StartupData data2 = CreateSnapshotDataBlob(source2);

  v8::Isolate::CreateParams params2;
  params2.snapshot_blob = &data2;
  params2.array_buffer_allocator = CcTest::array_buffer_allocator();
  // Test-appropriate equivalent of v8::Isolate::New.
  v8::Isolate* isolate2 = TestSerializer::NewIsolate(params2);
  {
    v8::Isolate::Scope i_scope(isolate2);
    v8::HandleScope h_scope(isolate2);
    v8::Local<v8::Context> context = v8::Context::New(isolate2);
    v8::Context::Scope c_scope(context);
    v8::Maybe<int32_t> result =
        CompileRun("f()")->Int32Value(isolate2->GetCurrentContext());
    CHECK_EQ(86, result.FromJust());
    result = CompileRun("g()")->Int32Value(isolate2->GetCurrentContext());
    CHECK_EQ(43, result.FromJust());
  }
  isolate2->Dispose();
  delete[] data2.data;  // We can dispose of the snapshot blob now.
  FreeCurrentEmbeddedBlob();
}

static void SerializationFunctionTemplate(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  info.GetReturnValue().Set(info[0]);
}

UNINITIALIZED_TEST(CustomSnapshotDataBlobOutdatedContextWithOverflow) {
  DisableAlwaysOpt();
  const char* source1 =
      "var o = {};"
      "(function() {"
      "  function f1(x) { return f2(x) instanceof Array; }"
      "  function f2(x) { return foo.bar(x); }"
      "  o.a = f2.bind(null);"
      "  o.b = 1;"
      "  o.c = 2;"
      "  o.d = 3;"
      "  o.e = 4;"
      "})();\n";

  const char* source2 = "o.a(42)";

  DisableEmbeddedBlobRefcounting();
  v8::StartupData data = CreateSnapshotDataBlob(source1);

  v8::Isolate::CreateParams params;
  params.snapshot_blob = &data;
  params.array_buffer_allocator = CcTest::array_buffer_allocator();

  // Test-appropriate equivalent of v8::Isolate::New.
  v8::Isolate* isolate = TestSerializer::NewIsolate(params);
  {
    v8::Isolate::Scope i_scope(isolate);
    v8::HandleScope h_scope(isolate);

    v8::Local<v8::ObjectTemplate> global = v8::ObjectTemplate::New(isolate);
    v8::Local<v8::ObjectTemplate> property = v8::ObjectTemplate::New(isolate);
    v8::Local<v8::FunctionTemplate> function =
        v8::FunctionTemplate::New(isolate, SerializationFunctionTemplate);
    property->Set(isolate, "bar", function);
    global->Set(isolate, "foo", property);

    v8::Local<v8::Context> context = v8::Context::New(isolate, nullptr, global);
    v8::Context::Scope c_scope(context);
    v8::Local<v8::Value> result = CompileRun(source2);
    v8::Maybe<bool> compare =
        v8_str("42")->Equals(isolate->GetCurrentContext(), result);
    CHECK(compare.FromJust());
  }
  isolate->Dispose();
  delete[] data.data;  // We can dispose of the snapshot blob now.
  FreeCurrentEmbeddedBlob();
}

UNINITIALIZED_TEST(CustomSnapshotDataBlobWithLocker) {
  DisableAlwaysOpt();
  DisableEmbeddedBlobRefcounting();
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate0 = v8::Isolate::New(create_params);
  {
    v8::Locker locker(isolate0);
    v8::Isolate::Scope i_scope(isolate0);
    v8::HandleScope h_scope(isolate0);
    v8::Local<v8::Context> context = v8::Context::New(isolate0);
    v8::Context::Scope c_scope(context);
    v8::Maybe<int32_t> result =
        CompileRun("Math.cos(0)")->Int32Value(isolate0->GetCurrentContext());
    CHECK_EQ(1, result.FromJust());
  }
  isolate0->Dispose();

  const char* source1 = "function f() { return 42; }";

  DisableEmbeddedBlobRefcounting();
  v8::StartupData data1 = CreateSnapshotDataBlob(source1);

  v8::Isolate::CreateParams params1;
  params1.snapshot_blob = &data1;
  params1.array_buffer_allocator = CcTest::array_buffer_allocator();
  // Test-appropriate equivalent of v8::Isolate::New.
  v8::Isolate* isolate1 = TestSerializer::NewIsolate(params1);
  {
    v8::Locker locker(isolate1);
    v8::Isolate::Scope i_scope(isolate1);
    v8::HandleScope h_scope(isolate1);
    v8::Local<v8::Context> context = v8::Context::New(isolate1);
    v8::Context::Scope c_scope(context);
    v8::Maybe<int32_t> result = CompileRun("f()")->Int32Value(context);
    CHECK_EQ(42, result.FromJust());
  }
  isolate1->Dispose();
  delete[] data1.data;  // We can dispose of the snapshot blob now.
  FreeCurrentEmbeddedBlob();
}

UNINITIALIZED_TEST(CustomSnapshotDataBlobStackOverflow) {
  DisableAlwaysOpt();
  const char* source =
      "var a = [0];"
      "var b = a;"
      "for (var i = 0; i < 10000; i++) {"
      "  var c = [i];"
      "  b.push(c);"
      "  b.push(c);"
      "  b = c;"
      "}";

  DisableEmbeddedBlobRefcounting();
  v8::StartupData data = CreateSnapshotDataBlob(source);

  v8::Isolate::CreateParams params;
  params.snapshot_blob = &data;
  params.array_buffer_allocator = CcTest::array_buffer_allocator();

  // Test-appropriate equivalent of v8::Isolate::New.
  v8::Isolate* isolate = TestSerializer::NewIsolate(params);
  {
    v8::Isolate::Scope i_scope(isolate);
    v8::HandleScope h_scope(isolate);
    v8::Local<v8::Context> context = v8::Context::New(isolate);
    v8::Context::Scope c_scope(context);
    const char* test =
        "var sum = 0;"
        "while (a) {"
        "  sum += a[0];"
        "  a = a[1];"
        "}"
        "sum";
    v8::Maybe<int32_t> result =
        CompileRun(test)->Int32Value(isolate->GetCurrentContext());
    CHECK_EQ(9999 * 5000, result.FromJust());
  }
  isolate->Dispose();
  delete[] data.data;  // We can dispose of the snapshot blob now.
  FreeCurrentEmbeddedBlob();
}

bool IsCompiled(const char* name) {
  return i::Cast<i::JSFunction>(v8::Utils::OpenHandle(*CompileRun(name)))
      ->shared()
      ->is_compiled();
}

UNINITIALIZED_TEST(SnapshotDataBlobWithWarmup) {
  DisableAlwaysOpt();
  const char* warmup = "Math.abs(1); Math.random = 1;";

  DisableEmbeddedBlobRefcounting();
  v8::StartupData cold = CreateSnapshotDataBlob(nullptr);
  v8::StartupData warm = WarmUpSnapshotDataBlobInternal(cold, warmup);
  delete[] cold.data;

  v8::Isolate::CreateParams params;
  params.snapshot_blob = &warm;
  params.array_buffer_allocator = CcTest::array_buffer_allocator();

  // Test-appropriate equivalent of v8::Isolate::New.
  v8::Isolate* isolate = TestSerializer::NewIsolate(params);
  {
    v8::Isolate::Scope i_scope(isolate);
    v8::HandleScope h_scope(isolate);
    v8::Local<v8::Context> context = v8::Context::New(isolate);
    v8::Context::Scope c_scope(context);
    // Running the warmup script has effect on whether functions are
    // pre-compiled, but does not pollute the context.
    CHECK(IsCompiled("Math.abs"));
    CHECK(IsCompiled("String.raw"));
    CHECK(CompileRun("Math.random")->IsFunction());
  }
  isolate->Dispose();
  delete[] warm.data;
  FreeCurrentEmbeddedBlob();
}

UNINITIALIZED_TEST(CustomSnapshotDataBlobWithWarmup) {
  DisableAlwaysOpt();
  const char* source =
      "function f() { return Math.abs(1); }\n"
      "function g() { return String.raw(1); }\n"
      "Object.valueOf(1);"
      "var a = 5";
  const char* warmup = "a = f()";

  DisableEmbeddedBlobRefcounting();
  v8::StartupData cold = CreateSnapshotDataBlob(source);
  v8::StartupData warm = WarmUpSnapshotDataBlobInternal(cold, warmup);
  delete[] cold.data;

  v8::Isolate::CreateParams params;
  params.snapshot_blob = &warm;
  params.array_buffer_allocator = CcTest::array_buffer_allocator();

  // Test-appropriate equivalent of v8::Isolate::New.
  v8::Isolate* isolate = TestSerializer::NewIsolate(params);
  {
    v8::Isolate::Scope i_scope(isolate);
    v8::HandleScope h_scope(isolate);
    v8::Local<v8::Context> context = v8::Context::New(isolate);
    v8::Context::Scope c_scope(context);
    // Running the warmup script has effect on whether functions are
    // pre-compiled, but does not pollute the context.
    CHECK(IsCompiled("f"));
    CHECK(IsCompiled("Math.abs"));
    CHECK(!IsCompiled("g"));
    CHECK(IsCompiled("String.raw"));
    CHECK(IsCompiled("Array.prototype.lastIndexOf"));
    CHECK_EQ(5, CompileRun("a")->Int32Value(context).FromJust());
  }
  isolate->Dispose();
  delete[] warm.data;
  FreeCurrentEmbeddedBlob();
}

namespace {
v8::StartupData CreateCustomSnapshotWithKeep() {
  SnapshotCreatorParams testing_params;
  v8::SnapshotCreator creator(testing_params.create_params);
  v8::Isolate* isolate = creator.GetIsolate();
  {
    v8::HandleScope handle_scope(isolate);
    {
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      v8::Context::Scope context_scope(context);
      v8::Local<v8::String> source_str = v8_str(
          "function f() { return Math.abs(1); }\n"
          "function g() { return String.raw(1); }");
      v8::ScriptOrigin origin(v8_str("test"));
      v8::ScriptCompiler::Source source(source_str, origin);
      CompileRun(isolate->GetCurrentContext(), &source,
                 v8::ScriptCompiler::kEagerCompile);
      creator.SetDefaultContext(context);
    }
  }
  return creator.CreateBlob(v8::SnapshotCreator::FunctionCodeHandling::kKeep);
}
}  // namespace

UNINITIALIZED_TEST(CustomSnapshotDataBlobWithKeep) {
  DisableAlwaysOpt();
  DisableEmbeddedBlobRefcounting();
  v8::StartupData blob = CreateCustomSnapshotWithKeep();

  {
    v8::Isolate::CreateParams params;
    params.snapshot_blob = &blob;
    params.array_buffer_allocator = CcTest::array_buffer_allocator();
    // Test-appropriate equivalent of v8::Isolate::New.
    v8::Isolate* isolate = TestSerializer::NewIsolate(params);
    {
      v8::Isolate::Scope isolate_scope(isolate);
      v8::HandleScope handle_scope(isolate);
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      v8::Context::Scope context_scope(context);
      CHECK(IsCompiled("f"));
      CHECK(IsCompiled("g"));
    }
    isolate->Dispose();
  }
  delete[] blob.data;
  FreeCurrentEmbeddedBlob();
}

UNINITIALIZED_TEST(CustomSnapshotDataBlobImmortalImmovableRoots) {
  DisableAlwaysOpt();
  // Flood the startup snapshot with shared function infos. If they are
  // serialized before the immortal immovable root, the root will no longer end
  // up on the first page.
  base::Vector<const char> source =
      ConstructSource(base::StaticCharVector("var a = [];"),
                      base::StaticCharVector("a.push(function() {return 7});"),
                      base::StaticCharVector("\0"), 10000);

  DisableEmbeddedBlobRefcounting();
  v8::StartupData data = CreateSnapshotDataBlob(source.begin());

  v8::Isolate::CreateParams params;
  params.snapshot_blob = &data;
  params.array_buffer_allocator = CcTest::array_buffer_allocator();

  // Test-appropriate equivalent of v8::Isolate::New.
  v8::Isolate* isolate = TestSerializer::NewIsolate(params);
  {
    v8::Isolate::Scope i_scope(isolate);
    v8::HandleScope h_scope(isolate);
    v8::Local<v8::Context> context = v8::Context::New(isolate);
    v8::Context::Scope c_scope(context);
    CHECK_EQ(7, CompileRun("a[0]()")->Int32Value(context).FromJust());
  }
  isolate->Dispose();
  source.Dispose();
  delete[] data.data;  // We can dispose of the snapshot blob now.
  FreeCurrentEmbeddedBlob();
}

TEST(TestThatAlwaysSucceeds) {}

TEST(TestCheckThatAlwaysFails) {
  bool ArtificialFailure = false;
  CHECK(ArtificialFailure);
}

TEST(TestFatal) { GRACEFUL_FATAL("fatal"); }

int CountBuiltins() {
  // Check that we have not deserialized any additional builtin.
  HeapObjectIterator iterator(CcTest::heap());
  DisallowGarbageCollection no_gc;
  int counter = 0;
  for (Tagged<HeapObject> obj = iterator.Next(); !obj.is_null();
       obj = iterator.Next()) {
    if (IsCode(obj) && Cast<Code>(obj)->kind() == CodeKind::BUILTIN) counter++;
  }
  return counter;
}

static DirectHandle<SharedFunctionInfo> CompileScript(
    Isolate* isolate, Handle<String> source,
    const ScriptDetails& script_details, AlignedCachedData* cached_data,
    v8::ScriptCompiler::CompileOptions options,
    ScriptCompiler::InMemoryCacheResult expected_lookup_result =
        ScriptCompiler::InMemoryCacheResult::kMiss) {
  ScriptCompiler::CompilationDetails compilation_details;
  auto result = Compiler::GetSharedFunctionInfoForScriptWithCachedData(
                    isolate, source, script_details, cached_data, options,
                    ScriptCompiler::kNoCacheNoReason, NOT_NATIVES_CODE,
                    &compilation_details)
                    .ToHandleChecked();
  CHECK_EQ(compilation_details.in_memory_cache_result, expected_lookup_result);
  return result;
}

static DirectHandle<SharedFunctionInfo> CompileScriptAndProduceCache(
    Isolate* isolate, Handle<String> source,
    const ScriptDetails& script_details, AlignedCachedData** out_cached_data,
    v8::ScriptCompiler::CompileOptions options,
    ScriptCompiler::InMemoryCacheResult expected_lookup_result =
        ScriptCompiler::InMemoryCacheResult::kMiss) {
  ScriptCompiler::CompilationDetails compilation_details;
  DirectHandle<SharedFunctionInfo> sfi =
      Compiler::GetSharedFunctionInfoForScript(
          isolate, source, script_details, options,
          ScriptCompiler::kNoCacheNoReason, NOT_NATIVES_CODE,
          &compilation_details)
          .ToHandleChecked();
  CHECK_EQ(compilation_details.in_memory_cache_result, expected_lookup_result);
  std::unique_ptr<ScriptCompiler::CachedData> cached_data(
      ScriptCompiler::CreateCodeCache(ToApiHandle<UnboundScript>(sfi)));
  uint8_t* buffer = NewArray<uint8_t>(cached_data->length);
  MemCopy(buffer, cached_data->data, cached_data->length);
  *out_cached_data = new i::AlignedCachedData(buffer, cached_data->length);
  (*out_cached_data)->AcquireDataOwnership();
  return sfi;
}


"""


```