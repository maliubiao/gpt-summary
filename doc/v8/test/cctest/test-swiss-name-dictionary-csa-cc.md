Response:
Let's break down the thought process for analyzing this C++ code snippet.

1. **Understand the Context:** The filename `v8/test/cctest/test-swiss-name-dictionary-csa.cc` immediately tells us this is a test file within the V8 project. The `cctest` directory suggests it's a component client test, likely testing some specific functionality. The `swiss-name-dictionary` part hints at a data structure implementation. Finally, `-csa` strongly suggests "CodeStubAssembler," a V8-specific mechanism for generating low-level code.

2. **Initial Scan for High-Level Purpose:**  Read the initial comments. The copyright notice is standard. The comment about the non-SIMD implementation needing 64-bit integers is a crucial piece of information. It sets a constraint on which platforms the CSA tests can run. The `CSATestRunner` class name further reinforces the idea of testing the SwissNameDictionary using CSA.

3. **Identify the Core Class:** The `CSATestRunner` class seems to be the central component. It likely wraps the actual SwissNameDictionary and provides methods to interact with it using CSA-generated code.

4. **Analyze `CSATestRunner`'s Members:**
    * **Constructor:** Takes an `Isolate` (V8's execution context), initial capacity, and a `KeyCache`. This points to the setup required for testing.
    * **`IsEnabled()`:** Checks CPU features (AVX, SSSE3). This confirms the earlier comment about platform limitations.
    * **`Add()`, `FindEntry()`, `Put()`, `Delete()`, `RehashInplace()`, `Shrink()`:** These method names are strong indicators of common dictionary operations.
    * **`GetData()`, `CheckCounts()`, `CheckEnumerationOrder()`, `CheckCopy()`, `VerifyHeap()`, `PrintTable()`:** These seem like utility methods for inspecting the state of the dictionary during testing.
    * **`table`, `reference_`:**  `table` is likely the dictionary under test. `reference_` suggests a way to compare the CSA implementation against a known-good (likely C++) implementation. This is a common and good testing practice.
    * **`find_entry_ft_`, `get_data_ft_`, etc.:** The `_ft_` suffix strongly suggests "Function Tester." These are likely instances of a class that helps execute CSA-generated code.
    * **`create_get_data()`, `create_find_entry()`, etc.:**  These static methods likely define the CSA code snippets for each dictionary operation.
    * **`kFindEntryParams`, `kGetDataParams`, etc.:** Constants defining the number of parameters for the CSA functions.

5. **Examine the `create_*` Methods:** These methods contain the core logic of the CSA tests. Look for keywords like `CodeStubAssembler`, `TNode`, `Label`, `TVariable`, and specific V8 API calls like `SwissNameDictionaryFindEntry`, `LoadSwissNameDictionaryKey`, etc. This confirms that these methods are indeed generating CSA code.

6. **Understand the Test Flow:** The `CSATestRunner` seems to mirror operations on both the CSA-executed `table` and the C++ `reference_`. The `CheckAgainstReference()` method confirms this by comparing their states. This pattern is crucial for verifying the correctness of the CSA implementation.

7. **Connect to JavaScript (if applicable):**  The SwissNameDictionary is used internally by V8 to store properties of JavaScript objects. Think about how JavaScript interacts with objects and their properties. Adding, accessing, modifying, and deleting properties are the key actions.

8. **Identify Potential Errors:** Think about common mistakes when implementing hash tables or dictionaries:
    * **Incorrect hash function:** While not directly visible here, it's a fundamental concern.
    * **Collision handling issues:**  The SwissNameDictionary uses a specific collision resolution strategy. Errors in the CSA implementation of this strategy are possible.
    * **Incorrect size calculations:**  Calculating capacity, used slots, and deleted slots accurately is important.
    * **Off-by-one errors:**  Common in array/buffer manipulation.
    * **Memory management issues:** Incorrect allocation or deallocation.
    * **Write barrier issues:**  Important for garbage collection in V8.

9. **Consider the `.tq` Extension:** The prompt mentions `.tq`. This stands for "Torque," another V8 language for generating built-in code. The code comments mention Torque as an alternative. If the file *were* `.tq`, the syntax would be different, but the underlying purpose of testing the SwissNameDictionary would likely be the same.

10. **Structure the Answer:** Organize the findings into logical sections: Functionality, JavaScript relationship, code logic (with examples), and common errors. Use clear and concise language. Highlight key concepts like CSA and the role of the `reference_` dictionary.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe this is just a C++ implementation of the dictionary.
* **Correction:** The `-csa` suffix and the presence of `CodeStubAssembler` clearly indicate it's a *test* using CSA, not the primary implementation.
* **Initial thought:** The JavaScript connection might be vague.
* **Refinement:** Focus on the core dictionary operations (add, find, put, delete) and how they map to JavaScript property access. Mentioning internal usage for object properties makes the connection clearer.
* **Initially missed:** The importance of the `reference_` dictionary.
* **Correction:** Realized its crucial role in validating the CSA implementation.

By following these steps and continually refining the understanding, you can effectively analyze and explain the purpose and functionality of this type of code.
这个C++源代码文件 `v8/test/cctest/test-swiss-name-dictionary-csa.cc` 的主要功能是**测试 V8 引擎中 SwissNameDictionary 数据结构的 CodeStubAssembler (CSA) 实现**。

以下是详细的功能列表：

1. **使用 CodeStubAssembler (CSA) 实现测试用例:**  这个文件中的代码使用 V8 的 CodeStubAssembler 框架来生成低级代码，用于执行和测试 `SwissNameDictionary` 的各种操作。CSA 允许以一种更接近机器码的方式编写代码，这对于测试性能敏感的代码路径非常有用。

2. **测试 `SwissNameDictionary` 的核心功能:**  `CSATestRunner` 类封装了针对 `SwissNameDictionary` 的各种测试方法，包括：
    * **添加 (Add):** 向字典中添加新的键值对。
    * **查找 (FindEntry):** 根据键查找条目的内部索引。
    * **更新 (Put):** 更新现有条目的值和属性。
    * **删除 (Delete):** 从字典中删除一个条目。
    * **调整大小 (RehashInplace):**  虽然 CSA 版本没有实现，但测试框架包含了这个概念。
    * **收缩 (Shrink):** 虽然 CSA 版本没有实现，但测试框架包含了这个概念。
    * **获取数据 (GetData):** 获取指定索引处条目的键、值和属性信息。
    * **检查计数 (CheckCounts):** 验证字典的容量、元素数量和已删除元素数量是否正确。
    * **检查枚举顺序 (CheckEnumerationOrder):** 虽然 CSA 版本没有实现，但测试框架包含了这个概念。
    * **复制 (CheckCopy):** 创建字典的副本并进行比较。
    * **堆验证 (VerifyHeap):** 在启用堆验证的情况下，检查字典在堆中的状态是否有效。
    * **打印表格 (PrintTable):**  用于调试，打印字典的内容。

3. **与 C++ 实现进行对比测试:** `CSATestRunner` 维护了一个 `reference_` 成员变量，它是 `SwissNameDictionary` 的 C++ 实现。每次在 CSA 实现上执行操作后，`CheckAgainstReference()` 方法会比较 CSA 实现的结果与 C++ 实现的结果，确保 CSA 实现的正确性。

4. **平台限制:** 代码中明确指出，由于 CSA/Torque 在 32 位平台上不支持 64 位整数运算（IA32 除外），因此 CSA 版本的测试在这些平台上无法运行。

5. **依赖于共享测试用例:**  该文件使用 `SharedSwissTableTests` 模板类来执行在 `test-swiss-name-dictionary-shared-tests.h` 中定义的共享测试用例。这使得测试代码可以复用，并确保 C++ 和 CSA 实现都经过相同的测试。

**关于 `.tq` 扩展名:**

如果 `v8/test/cctest/test-swiss-name-dictionary-csa.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码**文件。Torque 是 V8 专门用于生成高效运行时代码的领域特定语言。在这种情况下，测试用例将使用 Torque 语言编写，而不是 C++ 和 CSA 的混合。

**与 JavaScript 的功能关系:**

`SwissNameDictionary` 是 V8 引擎内部用于存储对象属性的一种优化的数据结构，特别是在对象属性数量较多时。它可以被认为是 JavaScript 对象的内部属性存储的一种实现方式。

**JavaScript 示例:**

```javascript
const obj = {};

// 当向对象添加属性时，V8 可能会使用 SwissNameDictionary 来存储这些属性。
obj.property1 = 'value1';
obj.property2 = 123;
obj.property3 = true;

// 访问属性时，V8 需要在内部的属性存储结构中查找。
console.log(obj.property2); // 输出 123

// 删除属性也会影响内部的属性存储结构。
delete obj.property1;
```

在这个例子中，虽然 JavaScript 开发者不需要直接与 `SwissNameDictionary` 交互，但 V8 引擎会在幕后使用它来高效地管理对象 `obj` 的属性。`test-swiss-name-dictionary-csa.cc` 中的测试就是为了确保 V8 在内部使用 CSA 生成的代码来操作这种数据结构时是正确和高效的。

**代码逻辑推理和假设输入输出:**

以 `CSATestRunner::Add` 方法为例：

**假设输入:**

* `table`:  一个空的或已包含一些条目的 `SwissNameDictionary` 对象。
* `key`: 一个 `Handle<Name>` 类型的键，例如表示字符串 "propertyName" 的 `Name` 对象。
* `value`: 一个 `Handle<Object>` 类型的值，可以是任何 JavaScript 值（例如，字符串 "test"，数字 42，布尔值 true）。
* `details`: 一个 `PropertyDetails` 对象，包含属性的元数据（例如，是否可写、可枚举、可配置）。

**代码逻辑:**

1. 调用 C++ 版本的 `SwissNameDictionary::Add` 来更新 `reference_`，作为预期结果。
2. 调用 CSA 生成的 `add_ft_` 函数，在 `table` 上执行添加操作。
3. 如果 `add_ft_` 返回 false，表示需要扩容，则使用 C++ 版本的 `SwissNameDictionary::Add` 进行扩容。
4. 调用 `CheckAgainstReference()` 比较 `table` 和 `reference_` 的状态。

**可能的输出:**

* 如果添加成功且不需要扩容，`table` 的状态将与添加 `key` 和 `value` 后的 `reference_` 状态一致。
* 如果需要扩容，`table` 将被重新分配，并且状态将与添加 `key` 和 `value` 后的 `reference_` 状态一致。

**用户常见的编程错误（如果相关）:**

虽然这个测试文件本身不直接涉及用户编写 JavaScript 代码，但它测试的 `SwissNameDictionary` 与 JavaScript 对象属性的内部管理密切相关。 用户在使用 JavaScript 时，可能会遇到与对象属性相关的性能问题，这可能与 V8 引擎内部如何高效地管理这些属性有关。 例如：

1. **频繁添加和删除大量属性:**  如果用户在循环中频繁地向对象添加和删除属性，可能会导致 V8 引擎频繁地调整内部属性存储结构的大小，影响性能。

   ```javascript
   const obj = {};
   for (let i = 0; i < 10000; i++) {
     obj[`prop${i}`] = i;
   }
   for (let i = 0; i < 10000; i++) {
     delete obj[`prop${i}`];
   }
   ```

2. **以非预测性的顺序添加属性:**  V8 可能会根据属性添加的顺序进行一些优化。如果属性以非预测性的顺序添加，可能会影响 V8 的优化效果。

   ```javascript
   const obj = {};
   obj.b = 2;
   obj.a = 1; //  与先添加 'a' 后添加 'b' 可能有不同的内部存储结构
   ```

3. **访问不存在的属性:**  虽然不会直接导致 `SwissNameDictionary` 出错，但频繁访问不存在的属性会导致 V8 在内部进行查找，这会带来一定的开销。

总而言之，`v8/test/cctest/test-swiss-name-dictionary-csa.cc` 是 V8 引擎的一个重要测试文件，它专注于使用 CSA 来验证 `SwissNameDictionary` 数据结构的正确性和性能，而这个数据结构是 JavaScript 对象属性管理的关键组成部分。

Prompt: 
```
这是目录为v8/test/cctest/test-swiss-name-dictionary-csa.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-swiss-name-dictionary-csa.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <optional>

#include "src/codegen/code-stub-assembler-inl.h"
#include "src/codegen/cpu-features.h"
#include "src/objects/objects-inl.h"
#include "src/objects/swiss-name-dictionary-inl.h"
#include "test/cctest/compiler/function-tester.h"
#include "test/cctest/test-swiss-name-dictionary-infra.h"
#include "test/cctest/test-swiss-name-dictionary-shared-tests.h"
#include "test/common/code-assembler-tester.h"

namespace v8 {
namespace internal {
namespace test_swiss_hash_table {

#include "src/codegen/define-code-stub-assembler-macros.inc"

// The non-SIMD SwissNameDictionary implementation requires 64 bit integer
// operations, which CSA/Torque don't offer on 32 bit platforms. Therefore, we
// cannot run the CSA version of the tests on 32 bit platforms. The only
// exception is IA32, where we can use SSE and don't need 64 bit integers.
// TODO(v8:11330) The Torque SIMD implementation is not specific to SSE (like
// the C++ one), but works on other platforms. It should be possible to create a
// workaround where on 32 bit, non-IA32 platforms we use the "portable", non-SSE
// implementation on the C++ side (which uses a group size of 8) and create a
// special version of the SIMD Torque implementation that works for group size 8
// instead of 16.
#if V8_TARGET_ARCH_64_BIT || V8_TARGET_ARCH_IA32

// Executes tests by executing CSA/Torque versions of dictionary operations.
// See RuntimeTestRunner for description of public functions.
class CSATestRunner {
 public:
  CSATestRunner(Isolate* isolate, int initial_capacity, KeyCache& keys);

  // TODO(v8:11330): Remove once CSA implementation has a fallback for
  // non-SSSE3/AVX configurations.
  static bool IsEnabled() {
#if V8_TARGET_ARCH_X64 || V8_TARGET_ARCH_IA32
    CpuFeatures::SupportedFeatures();
    return CpuFeatures::IsSupported(CpuFeature::AVX) ||
           CpuFeatures::IsSupported(CpuFeature::SSSE3);
#else
    // Other 64-bit architectures always support the required operations.
    return true;
#endif
  }

  void Add(Handle<Name> key, Handle<Object> value, PropertyDetails details);
  InternalIndex FindEntry(Handle<Name> key);
  void Put(InternalIndex entry, Handle<Object> new_value,
           PropertyDetails new_details);
  void Delete(InternalIndex entry);
  void RehashInplace();
  void Shrink();

  Handle<FixedArray> GetData(InternalIndex entry);
  void CheckCounts(std::optional<int> capacity, std::optional<int> elements,
                   std::optional<int> deleted);
  void CheckEnumerationOrder(const std::vector<std::string>& expected_keys);
  void CheckCopy();
  void VerifyHeap();

  void PrintTable();

  Handle<SwissNameDictionary> table;

 private:
  using Label = compiler::CodeAssemblerLabel;
  template <class T>
  using TVariable = compiler::TypedCodeAssemblerVariable<T>;

  void CheckAgainstReference();

  void Allocate(Handle<Smi> capacity);

  Isolate* isolate_;

  // Used to mirror all operations using C++ versions of all operations,
  // yielding a reference to compare against.
  Handle<SwissNameDictionary> reference_;

  // CSA functions execute the corresponding dictionary operation.
  compiler::FunctionTester find_entry_ft_;
  compiler::FunctionTester get_data_ft_;
  compiler::FunctionTester put_ft_;
  compiler::FunctionTester delete_ft_;
  compiler::FunctionTester add_ft_;
  compiler::FunctionTester allocate_ft_;
  compiler::FunctionTester get_counts_ft_;
  compiler::FunctionTester copy_ft_;

  // Used to create the FunctionTesters above.
  static Handle<Code> create_get_data(Isolate* isolate);
  static Handle<Code> create_find_entry(Isolate* isolate);
  static Handle<Code> create_put(Isolate* isolate);
  static Handle<Code> create_delete(Isolate* isolate);
  static Handle<Code> create_add(Isolate* isolate);
  static Handle<Code> create_allocate(Isolate* isolate);
  static Handle<Code> create_get_counts(Isolate* isolate);
  static Handle<Code> create_copy(Isolate* isolate);

  // Number of parameters of each of the tester functions above.
  static constexpr int kFindEntryParams = 2;  // (table, key)
  static constexpr int kGetDataParams = 2;    // (table, entry)
  static constexpr int kPutParams = 4;        // (table, entry, value,  details)
  static constexpr int kDeleteParams = 2;     // (table, entry)
  static constexpr int kAddParams = 4;        // (table, key, value, details)
  static constexpr int kAllocateParams = 1;   // (capacity)
  static constexpr int kGetCountsParams = 1;  // (table)
  static constexpr int kCopyParams = 1;       // (table)
};

CSATestRunner::CSATestRunner(Isolate* isolate, int initial_capacity,
                             KeyCache& keys)
    : isolate_{isolate},
      reference_{isolate_->factory()->NewSwissNameDictionaryWithCapacity(
          initial_capacity, AllocationType::kYoung)},
      find_entry_ft_(create_find_entry(isolate), kFindEntryParams),
      get_data_ft_(create_get_data(isolate), kGetDataParams),
      put_ft_{create_put(isolate), kPutParams},
      delete_ft_{create_delete(isolate), kDeleteParams},
      add_ft_{create_add(isolate), kAddParams},
      allocate_ft_{create_allocate(isolate), kAllocateParams},
      get_counts_ft_{create_get_counts(isolate), kGetCountsParams},
      copy_ft_{create_copy(isolate), kCopyParams} {
  Allocate(handle(Smi::FromInt(initial_capacity), isolate));
}

void CSATestRunner::Add(Handle<Name> key, Handle<Object> value,
                        PropertyDetails details) {
  ReadOnlyRoots roots(isolate_);
  reference_ =
      SwissNameDictionary::Add(isolate_, reference_, key, value, details);

  Handle<Smi> details_smi = handle(details.AsSmi(), isolate_);
  DirectHandle<Boolean> success =
      add_ft_.CallChecked<Boolean>(table, key, value, details_smi);

  if (*success == roots.false_value()) {
    // |add_ft_| does not resize and indicates the need to do so by returning
    // false.
    int capacity = table->Capacity();
    int used_capacity = table->UsedCapacity();
    CHECK_GT(used_capacity + 1,
             SwissNameDictionary::MaxUsableCapacity(capacity));

    table = SwissNameDictionary::Add(isolate_, table, key, value, details);
  }

  CheckAgainstReference();
}

void CSATestRunner::Allocate(Handle<Smi> capacity) {
  // We must handle |capacity| == 0 specially, because
  // AllocateSwissNameDictionary (just like AllocateNameDictionary) always
  // returns a non-zero sized table.
  if ((*capacity).value() == 0) {
    table = ReadOnlyRoots(isolate_).empty_swiss_property_dictionary_handle();
  } else {
    table = allocate_ft_.CallChecked<SwissNameDictionary>(capacity);
  }

  CheckAgainstReference();
}

InternalIndex CSATestRunner::FindEntry(Handle<Name> key) {
  Tagged<Smi> index = *find_entry_ft_.CallChecked<Smi>(table, key);
  if (index.value() == SwissNameDictionary::kNotFoundSentinel) {
    return InternalIndex::NotFound();
  } else {
    return InternalIndex(index.value());
  }
}

Handle<FixedArray> CSATestRunner::GetData(InternalIndex entry) {
  DCHECK(entry.is_found());

  return get_data_ft_.CallChecked<FixedArray>(
      table, handle(Smi::FromInt(entry.as_int()), isolate_));
}

void CSATestRunner::CheckCounts(std::optional<int> capacity,
                                std::optional<int> elements,
                                std::optional<int> deleted) {
  DirectHandle<FixedArray> counts =
      get_counts_ft_.CallChecked<FixedArray>(table);

  if (capacity.has_value()) {
    CHECK_EQ(Smi::FromInt(capacity.value()), counts->get(0));
  }

  if (elements.has_value()) {
    CHECK_EQ(Smi::FromInt(elements.value()), counts->get(1));
  }

  if (deleted.has_value()) {
    CHECK_EQ(Smi::FromInt(deleted.value()), counts->get(2));
  }

  CheckAgainstReference();
}

void CSATestRunner::CheckEnumerationOrder(
    const std::vector<std::string>& expected_keys) {
  // Not implemented in CSA. Making this a no-op (rather than forbidding
  // executing CSA tests with this operation) because CheckEnumerationOrder is
  // also used by some tests whose main goal is not to test the enumeration
  // order.
}

void CSATestRunner::Put(InternalIndex entry, Handle<Object> new_value,
                        PropertyDetails new_details) {
  DCHECK(entry.is_found());
  reference_->ValueAtPut(entry, *new_value);
  reference_->DetailsAtPut(entry, new_details);

  Handle<Smi> entry_smi = handle(Smi::FromInt(entry.as_int()), isolate_);
  Handle<Smi> details_smi = handle(new_details.AsSmi(), isolate_);

  put_ft_.Call(table, entry_smi, new_value, details_smi);

  CheckAgainstReference();
}

void CSATestRunner::Delete(InternalIndex entry) {
  DCHECK(entry.is_found());
  reference_ = SwissNameDictionary::DeleteEntry(isolate_, reference_, entry);

  Handle<Smi> entry_smi = handle(Smi::FromInt(entry.as_int()), isolate_);
  table = delete_ft_.CallChecked<SwissNameDictionary>(table, entry_smi);

  CheckAgainstReference();
}

void CSATestRunner::RehashInplace() {
  // There's no CSA version of this. Use IsRuntimeTest to ensure that we only
  // run a test using this if it's a runtime test.
  UNREACHABLE();
}

void CSATestRunner::Shrink() {
  // There's no CSA version of this. Use IsRuntimeTest to ensure that we only
  // run a test using this if it's a runtime test.
  UNREACHABLE();
}

void CSATestRunner::CheckCopy() {
  DirectHandle<SwissNameDictionary> copy =
      copy_ft_.CallChecked<SwissNameDictionary>(table);
  CHECK(table->EqualsForTesting(*copy));
}

void CSATestRunner::VerifyHeap() {
#if VERIFY_HEAP
  table->SwissNameDictionaryVerify(isolate_, true);
#endif
}

void CSATestRunner::PrintTable() {
#ifdef OBJECT_PRINT
  table->SwissNameDictionaryPrint(std::cout);
#endif
}

Handle<Code> CSATestRunner::create_find_entry(Isolate* isolate) {
  // TODO(v8:11330): Remove once CSA implementation has a fallback for
  // non-SSSE3/AVX configurations.
  if (!IsEnabled()) {
    return isolate->builtins()->code_handle(Builtin::kIllegal);
  }
  static_assert(kFindEntryParams == 2);  // (table, key)
  compiler::CodeAssemblerTester asm_tester(isolate,
                                           JSParameterCount(kFindEntryParams));
  CodeStubAssembler m(asm_tester.state());
  {
    TNode<SwissNameDictionary> table = m.Parameter<SwissNameDictionary>(1);
    TNode<Name> key = m.Parameter<Name>(2);

    Label done(&m);
    TVariable<IntPtrT> entry_var(
        m.IntPtrConstant(SwissNameDictionary::kNotFoundSentinel), &m);

    // |entry_var| defaults to |kNotFoundSentinel| meaning that  one label
    // suffices.
    m.SwissNameDictionaryFindEntry(table, key, &done, &entry_var, &done);

    m.Bind(&done);
    m.Return(m.SmiFromIntPtr(entry_var.value()));
  }

  return asm_tester.GenerateCodeCloseAndEscape();
}

Handle<Code> CSATestRunner::create_get_data(Isolate* isolate) {
  static_assert(kGetDataParams == 2);  // (table, entry)
  compiler::CodeAssemblerTester asm_tester(isolate,
                                           JSParameterCount(kGetDataParams));
  CodeStubAssembler m(asm_tester.state());
  {
    TNode<SwissNameDictionary> table = m.Parameter<SwissNameDictionary>(1);
    TNode<IntPtrT> entry = m.SmiToIntPtr(m.Parameter<Smi>(2));

    TNode<FixedArray> data = m.AllocateZeroedFixedArray(m.IntPtrConstant(3));

    TNode<Object> key = m.LoadSwissNameDictionaryKey(table, entry);
    TNode<Object> value = m.LoadValueByKeyIndex(table, entry);
    TNode<Smi> details = m.SmiFromUint32(m.LoadDetailsByKeyIndex(table, entry));

    m.StoreFixedArrayElement(data, 0, key);
    m.StoreFixedArrayElement(data, 1, value);
    m.StoreFixedArrayElement(data, 2, details);

    m.Return(data);
  }
  return asm_tester.GenerateCodeCloseAndEscape();
}

Handle<Code> CSATestRunner::create_put(Isolate* isolate) {
  static_assert(kPutParams == 4);  // (table, entry, value, details)
  compiler::CodeAssemblerTester asm_tester(isolate,
                                           JSParameterCount(kPutParams));
  CodeStubAssembler m(asm_tester.state());
  {
    TNode<SwissNameDictionary> table = m.Parameter<SwissNameDictionary>(1);
    TNode<Smi> entry = m.Parameter<Smi>(2);
    TNode<Object> value = m.Parameter<Object>(3);
    TNode<Smi> details = m.Parameter<Smi>(4);

    TNode<IntPtrT> entry_intptr = m.SmiToIntPtr(entry);

    m.StoreValueByKeyIndex(table, entry_intptr, value,
                           WriteBarrierMode::UPDATE_WRITE_BARRIER);
    m.StoreDetailsByKeyIndex(table, entry_intptr, details);

    m.Return(m.UndefinedConstant());
  }
  return asm_tester.GenerateCodeCloseAndEscape();
}

Handle<Code> CSATestRunner::create_delete(Isolate* isolate) {
  // TODO(v8:11330): Remove once CSA implementation has a fallback for
  // non-SSSE3/AVX configurations.
  if (!IsEnabled()) {
    return isolate->builtins()->code_handle(Builtin::kIllegal);
  }
  static_assert(kDeleteParams == 2);  // (table, entry)
  compiler::CodeAssemblerTester asm_tester(isolate,
                                           JSParameterCount(kDeleteParams));
  CodeStubAssembler m(asm_tester.state());
  {
    TNode<SwissNameDictionary> table = m.Parameter<SwissNameDictionary>(1);
    TNode<IntPtrT> entry = m.SmiToIntPtr(m.Parameter<Smi>(2));

    TVariable<SwissNameDictionary> shrunk_table_var(table, &m);
    Label done(&m);

    m.SwissNameDictionaryDelete(table, entry, &done, &shrunk_table_var);
    m.Goto(&done);

    m.Bind(&done);
    m.Return(shrunk_table_var.value());
  }
  return asm_tester.GenerateCodeCloseAndEscape();
}

Handle<Code> CSATestRunner::create_add(Isolate* isolate) {
  // TODO(v8:11330): Remove once CSA implementation has a fallback for
  // non-SSSE3/AVX configurations.
  if (!IsEnabled()) {
    return isolate->builtins()->code_handle(Builtin::kIllegal);
  }
  static_assert(kAddParams == 4);  // (table, key, value, details)
  compiler::CodeAssemblerTester asm_tester(isolate,
                                           JSParameterCount(kAddParams));
  CodeStubAssembler m(asm_tester.state());
  {
    TNode<SwissNameDictionary> table = m.Parameter<SwissNameDictionary>(1);
    TNode<Name> key = m.Parameter<Name>(2);
    TNode<Object> value = m.Parameter<Object>(3);
    TNode<Smi> details = m.Parameter<Smi>(4);

    Label needs_resize(&m);

    TNode<Int32T> d32 = m.SmiToInt32(details);
    TNode<Uint8T> d = m.UncheckedCast<Uint8T>(d32);

    m.SwissNameDictionaryAdd(table, key, value, d, &needs_resize);
    m.Return(m.TrueConstant());

    m.Bind(&needs_resize);
    m.Return(m.FalseConstant());
  }
  return asm_tester.GenerateCodeCloseAndEscape();
}

Handle<Code> CSATestRunner::create_allocate(Isolate* isolate) {
  static_assert(kAllocateParams == 1);  // (capacity)
  compiler::CodeAssemblerTester asm_tester(isolate,
                                           JSParameterCount(kAllocateParams));
  CodeStubAssembler m(asm_tester.state());
  {
    TNode<IntPtrT> capacity = m.SmiToIntPtr(m.Parameter<Smi>(1));

    TNode<SwissNameDictionary> table =
        m.AllocateSwissNameDictionaryWithCapacity(capacity);

    m.Return(table);
  }
  return asm_tester.GenerateCodeCloseAndEscape();
}

Handle<Code> CSATestRunner::create_get_counts(Isolate* isolate) {
  static_assert(kGetCountsParams == 1);  // (table)
  compiler::CodeAssemblerTester asm_tester(isolate,
                                           JSParameterCount(kGetCountsParams));
  CodeStubAssembler m(asm_tester.state());
  {
    TNode<SwissNameDictionary> table = m.Parameter<SwissNameDictionary>(1);

    TNode<IntPtrT> capacity =
        m.ChangeInt32ToIntPtr(m.LoadSwissNameDictionaryCapacity(table));
    TNode<IntPtrT> elements =
        m.LoadSwissNameDictionaryNumberOfElements(table, capacity);
    TNode<IntPtrT> deleted =
        m.LoadSwissNameDictionaryNumberOfDeletedElements(table, capacity);

    TNode<FixedArray> results = m.AllocateZeroedFixedArray(m.IntPtrConstant(3));

    auto check_and_add = [&](TNode<IntPtrT> value, int array_index) {
      CSA_DCHECK(&m, m.UintPtrGreaterThanOrEqual(value, m.IntPtrConstant(0)));
      CSA_DCHECK(&m, m.UintPtrLessThanOrEqual(
                         value, m.IntPtrConstant(Smi::kMaxValue)));
      TNode<Smi> smi = m.SmiFromIntPtr(value);
      m.StoreFixedArrayElement(results, array_index, smi);
    };

    check_and_add(capacity, 0);
    check_and_add(elements, 1);
    check_and_add(deleted, 2);

    m.Return(results);
  }
  return asm_tester.GenerateCodeCloseAndEscape();
}

Handle<Code> CSATestRunner::create_copy(Isolate* isolate) {
  static_assert(kCopyParams == 1);  // (table)
  compiler::CodeAssemblerTester asm_tester(isolate,
                                           JSParameterCount(kCopyParams));
  CodeStubAssembler m(asm_tester.state());
  {
    TNode<SwissNameDictionary> table = m.Parameter<SwissNameDictionary>(1);

    m.Return(m.CopySwissNameDictionary(table));
  }
  return asm_tester.GenerateCodeCloseAndEscape();
}

void CSATestRunner::CheckAgainstReference() {
  CHECK(table->EqualsForTesting(*reference_));
}

// Executes the tests defined in test-swiss-name-dictionary-shared-tests.h as if
// they were defined in this file, using the CSATestRunner. See comments in
// test-swiss-name-dictionary-shared-tests.h and in
// swiss-name-dictionary-infra.h for details.
const char kCSATestFileName[] = __FILE__;
SharedSwissTableTests<CSATestRunner, kCSATestFileName> execute_shared_tests_csa;

#endif

#include "src/codegen/undef-code-stub-assembler-macros.inc"

}  // namespace test_swiss_hash_table
}  // namespace internal
}  // namespace v8

"""

```