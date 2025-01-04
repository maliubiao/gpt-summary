Response: My thinking process to answer the request goes like this:

1. **Understand the Goal:** The request asks for a summary of the C++ code's functionality and an explanation of its relationship to JavaScript, with a JavaScript example if applicable. The file name strongly suggests it's related to the `SwissNameDictionary` in V8, which is an internal data structure. The "CSA" in the name hints at CodeStubAssembler, a low-level code generation mechanism in V8.

2. **High-Level Scan and Keywords:** I'll quickly scan the code for key terms and patterns:
    * `SwissNameDictionary`:  This is the central object.
    * `CSA`:  Indicates the use of CodeStubAssembler.
    * `test`: This is a test file.
    * `Add`, `FindEntry`, `Put`, `Delete`, `RehashInplace`, `Shrink`, `GetData`, `CheckCounts`, `CheckEnumerationOrder`, `CheckCopy`, `VerifyHeap`, `PrintTable`: These look like methods for manipulating and inspecting the dictionary.
    * `compiler::FunctionTester`: This confirms it's testing CSA-generated code.
    * `Handle<...>`: V8's smart pointers for garbage-collected objects.
    * Platform-specific `#if` directives: Indicates platform dependencies, particularly around 64-bit and CPU features like AVX/SSSE3.

3. **Infer the Purpose:** Based on the keywords, I can infer that this file tests the `SwissNameDictionary` using CodeStubAssembler. It likely implements tests for common dictionary operations. The platform-specific checks suggest that the CSA implementation might have different requirements than a standard C++ implementation.

4. **Focus on `CSATestRunner`:** The `CSATestRunner` class is the core of the testing mechanism. I'll analyze its methods:
    * **Constructor:** Initializes the runner, including a reference `SwissNameDictionary` for comparison.
    * **`IsEnabled()`:**  Checks for required CPU features, crucial for understanding platform limitations.
    * **`Add`, `FindEntry`, `Put`, `Delete`, etc.:** These methods mirror dictionary operations. They interact with both a reference C++ implementation and the CSA-generated versions. This dual approach is key to verifying the CSA implementation.
    * **`CheckAgainstReference()`:** This confirms the CSA implementation's correctness by comparing its state with the reference implementation.
    * **`Allocate()`:** Handles the creation of the dictionary.
    * **`GetData()`:** Retrieves key, value, and details for a given entry.
    * **`CheckCounts()`:** Verifies the dictionary's metadata (capacity, element count, deleted count).
    * **`CheckEnumerationOrder()`:** Note the comment "Not implemented in CSA." This is important.
    * **`RehashInplace()`, `Shrink()`:**  Marked as `UNREACHABLE()`, indicating these operations aren't tested via CSA in this file.
    * **`CheckCopy()`:** Tests the copying functionality.
    * **`VerifyHeap()`, `PrintTable()`:** Utility functions for debugging and verification.
    * **`create_*` methods:** These are static methods that define and generate the CSA code for each dictionary operation being tested. They use `compiler::CodeAssemblerTester` and `CodeStubAssembler`.

5. **Connect to JavaScript:**  The `SwissNameDictionary` is used internally by V8 to store object properties (names and their values). When JavaScript code accesses properties of an object, V8 uses data structures like `SwissNameDictionary` behind the scenes.

6. **Formulate the Summary:** Based on the analysis, I'll construct a summary that highlights the key aspects:
    * Purpose: Testing the CSA implementation of `SwissNameDictionary`.
    * Methodology:  Using `CSATestRunner` to compare CSA results with a reference C++ implementation.
    * Scope: Testing core dictionary operations (add, find, put, delete, etc.).
    * Technology: Using CodeStubAssembler (CSA) for code generation.
    * Platform Dependency:  Mention the 64-bit and CPU feature requirements.
    * Limitations:  Note operations not tested via CSA in this file.

7. **Create the JavaScript Example:**  To illustrate the connection to JavaScript, I need a scenario where `SwissNameDictionary` would be used. Object property access is the most direct example. Creating an object and adding properties demonstrates this. I'll focus on the *concept* rather than a direct mapping of CSA code to JavaScript (which isn't possible at a high level).

8. **Review and Refine:** I'll reread my summary and example to ensure clarity, accuracy, and conciseness. I'll double-check for any technical terms that might need explanation. I'll also make sure the JavaScript example is simple and effectively illustrates the connection. For example, initially, I might have thought of showing more complex object manipulations, but simple property access is the clearest link. I need to emphasize that the `SwissNameDictionary` is an *internal* implementation detail.

By following these steps, I arrive at the detailed and accurate answer provided previously. The key is to break down the code, understand its purpose within the V8 context, and then relate those internal mechanisms back to observable JavaScript behavior.
这个C++源代码文件 `test-swiss-name-dictionary-csa.cc` 的功能是**测试 V8 引擎中 `SwissNameDictionary` 数据结构的基于 CodeStubAssembler (CSA) 的实现**。

更具体地说，它做了以下几件事：

1. **定义了一个测试运行器 `CSATestRunner`:** 这个类负责执行针对 `SwissNameDictionary` 的各种操作，例如添加、查找、更新、删除元素等。它使用 CSA 来生成执行这些操作的代码。

2. **提供了一组测试方法:** `CSATestRunner` 类中包含了 `Add`, `FindEntry`, `Put`, `Delete`, `RehashInplace`, `Shrink`, `GetData`, `CheckCounts`, `CheckEnumerationOrder`, `CheckCopy`, `VerifyHeap`, `PrintTable` 等方法。这些方法对应了 `SwissNameDictionary` 的核心功能。

3. **使用 CSA 生成测试代码:**  对于每个需要测试的操作，`CSATestRunner` 都有一个对应的 `create_*` 静态方法（例如 `create_find_entry`, `create_put` 等）。这些方法使用 `CodeStubAssembler` 来生成低级的机器码，用于执行相应的 `SwissNameDictionary` 操作。

4. **与 C++ 实现进行对比:** `CSATestRunner` 维护了一个 `reference_` 成员变量，它是一个使用标准 C++ 实现的 `SwissNameDictionary`。在执行 CSA 代码的同时，它也会对 `reference_` 进行相同的操作。然后，它会使用 `CheckAgainstReference()` 方法来比较 CSA 实现的结果是否与 C++ 实现的结果一致，从而验证 CSA 实现的正确性。

5. **考虑了平台差异:**  代码中包含了一些平台相关的 `#if` 宏，例如 `V8_TARGET_ARCH_64_BIT` 和 `V8_TARGET_ARCH_IA32`。这是因为 CSA 的某些功能（例如 64 位整数运算）在不同的平台上可能有所不同。代码会根据平台选择合适的测试策略或跳过某些测试。

6. **集成了共享测试:**  代码通过包含 `test-swiss-name-dictionary-shared-tests.h` 来复用一些通用的 `SwissNameDictionary` 测试用例。这避免了重复编写相同的测试逻辑。

**它与 JavaScript 的功能的关系：**

`SwissNameDictionary` 是 V8 引擎内部用于实现 JavaScript 对象属性存储的关键数据结构之一。当你在 JavaScript 中创建一个对象并向其添加属性时，V8 可能会使用 `SwissNameDictionary` 来存储这些属性的键值对。

**JavaScript 示例：**

```javascript
const obj = {};
obj.name = "Alice";
obj.age = 30;
```

在这个简单的 JavaScript 示例中，当你执行 `obj.name = "Alice"` 和 `obj.age = 30;` 时，V8 引擎内部可能会将 `name` 和 `age` 作为键，将 `"Alice"` 和 `30` 作为值存储在一个 `SwissNameDictionary` 中（或其他类似的内部数据结构，具体取决于对象的属性数量和类型等因素）。

`test-swiss-name-dictionary-csa.cc` 这个测试文件就是在底层测试 V8 引擎如何使用 CSA 来高效且正确地实现这些属性的添加、查找等操作。  它确保了当 JavaScript 代码执行类似上述的属性操作时，V8 内部的 `SwissNameDictionary` 能够按照预期工作。

**总结来说， `test-swiss-name-dictionary-csa.cc` 是一个 V8 引擎的内部测试文件，用于验证其使用 CodeStubAssembler 实现的 `SwissNameDictionary` 数据结构的正确性和性能，而 `SwissNameDictionary` 是 JavaScript 对象属性存储的重要底层机制。**

Prompt: 
```
这是目录为v8/test/cctest/test-swiss-name-dictionary-csa.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

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