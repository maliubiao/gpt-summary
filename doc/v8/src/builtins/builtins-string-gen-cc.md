Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/builtins/builtins-string-gen.cc`. The request has several constraints:

1. **List Functionality:**  Identify the main purposes of the code.
2. **Torque Source:** Determine if the file would be a Torque source if its extension was `.tq`.
3. **JavaScript Relation:** If the code relates to JavaScript string operations, provide JavaScript examples.
4. **Code Logic Inference:** If there are logical code blocks, explain them with hypothetical inputs and outputs.
5. **Common Programming Errors:** Point out potential user errors this code helps avoid or handle.
6. **Part 1 Summary:** Synthesize the identified functionalities into a concise summary.

**Mental Walkthrough:**

* **Code Inspection:** The code uses the CodeStubAssembler (CSA) within V8, which is a lower-level mechanism for generating optimized code. It deals with raw memory access and low-level operations. The functions seem to be focused on string manipulation, comparison, and allocation.
* **Function Breakdown:**
    * `DirectStringData`:  Retrieves the raw data pointer of a string, handling different string representations (sequential, external).
    * `CallSearchStringRaw` and related `Search...` functions: Implement efficient string searching using optimized C library functions or custom routines for different string encodings.
    * `GenerateStringEqual` and `StringEqual_Core`/`_FastLoop`/`_Loop`:  Implement string equality comparison, with optimizations for different string types and lengths.
    * `StringFromSingleUTF16EncodedCodePoint`: Creates a string from a single Unicode code point.
    * `AllocateConsString`:  Allocates a "cons string" (a string formed by concatenating two other strings).
    * `StringAdd`: Implements string concatenation, including optimizations and handling of large strings.
    * `BranchIfCanDerefIndirectString`, `DerefIndirectString`, `MaybeDerefIndirectString(s)`: Handle "indirect strings" (thin or cons strings), which are wrappers around actual string data.
    * `GenerateStringRelationalComparison`: Implements string comparison operators (<, >, <=, >=).
* **Torque Consideration:** The code uses CSA, which is a precursor to Torque. Many of these operations could be expressed in Torque.
* **JavaScript Connection:** String operations in JavaScript (e.g., `===`, `+`, `substring`, `indexOf`) are the high-level counterparts to these low-level implementations.
* **Logic Inference:** For functions like `DirectStringData` or the search functions, consider different string types as inputs and how the output (data pointer or index) would change.
* **Common Errors:**  String manipulation can lead to errors like exceeding maximum string length, comparing strings with different encodings incorrectly, or inefficient concatenation. This code helps ensure correctness and performance.

**Constraint Checklist & Confidence Score:**

1. List Functionality: Yes (High Confidence)
2. Torque Source: Yes (High Confidence)
3. JavaScript Relation: Yes (High Confidence)
4. Code Logic Inference: Yes (Medium Confidence - some functions are complex)
5. Common Programming Errors: Yes (High Confidence)
6. Part 1 Summary: Yes (High Confidence)

**Strategizing complete. Proceeding with response generation.**

`v8/src/builtins/builtins-string-gen.cc` 是 V8 引擎中负责生成字符串相关内置函数代码的 C++ 源文件。 它利用 `CodeStubAssembler` (CSA) 这个 V8 内部的汇编器来高效地实现这些功能。

**功能列举:**

1. **获取字符串的原始数据指针 (`DirectStringData`)**:  这个函数用于获取字符串对象内部存储字符数据的原始内存地址。它会根据字符串的不同内部表示方式（例如，连续存储的字符串、外部字符串等）来计算正确的偏移量。
2. **高效的字符串搜索 (`CallSearchStringRaw`, `SearchOneByteStringInTwoByteString` 等)**:  提供了一系列函数，用于在字符串中搜索子字符串。这些函数针对不同的字符编码组合（单字节 vs. 双字节）进行了优化，并可能调用底层的 C 库函数（如 `memchr`）来实现高性能搜索。
3. **字符串相等性比较 (`GenerateStringEqual`, `StringEqual_Core`, `StringEqual_FastLoop`, `StringEqual_Loop`)**:  实现了高效的字符串相等性比较。它会考虑字符串的不同类型和编码，并使用优化的循环来逐字符或逐块地进行比较。
4. **从单个 Unicode 码点创建字符串 (`StringFromSingleUTF16EncodedCodePoint`)**:  根据给定的 Unicode 码点创建一个新的字符串对象。
5. **分配 ConsString (`AllocateConsString`)**:  用于分配 `ConsString` 对象。`ConsString` 是一种用于优化字符串连接的内部表示，它将两个较小的字符串链接在一起，而不是立即创建一个新的包含所有字符的字符串。
6. **字符串连接 (`StringAdd`)**:  实现了字符串连接操作。它会根据字符串的长度和类型选择不同的策略，包括使用 `ConsString` 或直接分配新的连续存储的字符串。
7. **处理间接字符串 (`BranchIfCanDerefIndirectString`, `DerefIndirectString`, `MaybeDerefIndirectString(s)`)**:  用于处理 V8 内部的 "间接字符串" (如 `ThinString` 和 `ConsString`)。这些类型的字符串实际上是对其他字符串的引用，这些函数用于获取它们引用的实际字符串。
8. **字符串关系比较 (`GenerateStringRelationalComparison`)**: 实现了字符串的关系比较操作（例如，小于、大于等）。它同样会考虑字符串的类型和编码，并使用优化的方法进行比较。

**关于 .tq 扩展名:**

如果 `v8/src/builtins/builtins-string-gen.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码**。 Torque 是 V8 开发的一种类型化的中间语言，用于更安全、更易于理解和维护地编写内置函数的代码。 Torque 代码会被编译成 CSA 代码。

**与 JavaScript 功能的关系 (含 JavaScript 示例):**

`v8/src/builtins/builtins-string-gen.cc` 中实现的功能直接对应于 JavaScript 中字符串对象的各种操作。

* **字符串相等性比较 (`GenerateStringEqual`)**: 对应 JavaScript 中的 `===` 和 `==` (在类型相同的情况下)。

```javascript
const str1 = "hello";
const str2 = "hello";
const str3 = new String("hello");

console.log(str1 === str2); // true (可能由 StringEqual_FastLoop 等处理)
console.log(str1 == str3);  // true (可能由 Runtime::kStringEqual 处理)
console.log(str1 === str3); // false
```

* **字符串搜索 (`Search...`)**: 对应 JavaScript 中的 `String.prototype.indexOf()`, `String.prototype.lastIndexOf()`, `String.prototype.includes()`, `String.prototype.startsWith()`, `String.prototype.endsWith()`, 以及正则表达式的搜索方法。

```javascript
const text = "This is a test string.";
console.log(text.indexOf("test"));   // 10 (可能由 SearchOneByteStringInOneByteString 处理)
console.log(text.includes("string")); // true
```

* **字符串连接 (`StringAdd`)**: 对应 JavaScript 中的 `+` 运算符和 `String.prototype.concat()` 方法。

```javascript
const greeting = "Hello, ";
const name = "World!";
const message = greeting + name; // "Hello, World!" (可能由 AllocateConsString 或直接分配处理)
```

* **`StringFromSingleUTF16EncodedCodePoint`**: 虽然 JavaScript 没有直接对应的函数名，但涉及到 `String.fromCharCode()` 和处理 Unicode 码点的情况。

```javascript
console.log(String.fromCharCode(65));    // "A"
console.log(String.fromCodePoint(0x1F600)); // "😀"
```

* **子字符串 (`SubString` 函数在其他文件中，但相关逻辑会在此文件中涉及)**: 对应 JavaScript 中的 `String.prototype.substring()`, `String.prototype.slice()`.

```javascript
const longString = "This is a longer string";
const sub = longString.substring(10, 16); // "a long"
```

**代码逻辑推理 (假设输入与输出):**

假设我们调用 `StringBuiltinsAssembler::DirectStringData` 函数，并传入一个单字节的内部字符串对象 `myString` (内容为 "abc")：

**假设输入:**

* `string`: 一个 V8 内部的字符串对象，表示 JavaScript 字符串 "abc"。
* `string_instance_type`:  表示 `myString` 是一个单字节内部字符串的类型标记。

**代码逻辑推理:**

1. `Word32Equal(Word32And(string_instance_type, Int32Constant(kStringRepresentationMask)), Int32Constant(kSeqStringTag))` 会判断 `myString` 是否是顺序存储的字符串 (SeqString)。 假设是，则条件成立。
2. 进入 `if_sequential` 分支。
3. `var_data` 被赋值为 `myString` 数据起始位置的原始指针。这个地址是通过将 `myString` 的地址转换为 `RawPtrT`，然后加上 `OFFSET_OF_DATA_START(SeqOneByteString) - kHeapObjectTag` 偏移量计算出来的。

**可能的输出:**

* `var_data.value()`:  指向 "abc" 字符数据在内存中的起始地址的 `RawPtrT` 指针。

**涉及用户常见的编程错误 (举例说明):**

1. **不正确的字符串比较:**  在 JavaScript 中使用 `==` 比较字符串时，可能会因为类型转换而产生意外的结果。V8 的 `GenerateStringEqual` 等函数确保了在底层进行正确的字符比较。

   ```javascript
   const numStr = "10";
   const num = 10;
   console.log(numStr == num);  // true (发生了类型转换)
   console.log(numStr === num); // false (类型不同)
   ```

2. **字符串连接性能问题:**  在循环中频繁使用 `+` 连接字符串会导致性能问题，因为每次都会创建新的字符串对象。V8 的 `StringAdd` 尝试使用 `ConsString` 来优化这种情况。

   ```javascript
   let result = "";
   for (let i = 0; i < 1000; i++) {
     result += "a"; // 在 V8 底层可能使用 ConsString 优化
   }
   ```

3. **假设字符串是单字节的:** 用户可能会错误地假设所有字符串都是单字节编码，这在处理包含非 ASCII 字符的字符串时会导致问题。V8 的字符串处理函数会根据实际编码进行操作。

   ```javascript
   const multiByte = "你好";
   console.log(multiByte.length); // 2
   // 错误地假设每个字符占一个字节会导致处理问题
   ```

**归纳功能 (第 1 部分):**

总而言之，`v8/src/builtins/builtins-string-gen.cc` 实现了 V8 引擎中用于高效处理 JavaScript 字符串的核心底层操作。它包含了获取字符串数据、搜索子串、比较字符串、创建和连接字符串以及处理不同内部字符串表示形式的关键逻辑。 这些功能直接支撑着 JavaScript 中各种常用的字符串操作，并力求在性能和正确性之间取得平衡。它通过使用底层的 `CodeStubAssembler` 和针对不同字符串类型和编码的优化策略来实现高性能。

### 提示词
```
这是目录为v8/src/builtins/builtins-string-gen.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/builtins-string-gen.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/builtins/builtins-string-gen.h"

#include "src/base/strings.h"
#include "src/builtins/builtins-regexp-gen.h"
#include "src/builtins/builtins-utils-gen.h"
#include "src/builtins/builtins.h"
#include "src/codegen/code-stub-assembler-inl.h"
#include "src/execution/protectors.h"
#include "src/heap/factory-inl.h"
#include "src/heap/heap-inl.h"
#include "src/logging/counters.h"
#include "src/objects/instance-type.h"
#include "src/objects/objects.h"
#include "src/objects/property-cell.h"

namespace v8 {
namespace internal {

#include "src/codegen/define-code-stub-assembler-macros.inc"

TNode<RawPtrT> StringBuiltinsAssembler::DirectStringData(
    TNode<String> string, TNode<Word32T> string_instance_type) {
  // Compute the effective offset of the first character.
  TVARIABLE(RawPtrT, var_data);
  Label if_sequential(this), if_external(this), if_join(this);
  Branch(Word32Equal(Word32And(string_instance_type,
                               Int32Constant(kStringRepresentationMask)),
                     Int32Constant(kSeqStringTag)),
         &if_sequential, &if_external);

  BIND(&if_sequential);
  {
    static_assert(OFFSET_OF_DATA_START(SeqOneByteString) ==
                  OFFSET_OF_DATA_START(SeqTwoByteString));
    var_data = RawPtrAdd(ReinterpretCast<RawPtrT>(BitcastTaggedToWord(string)),
                         IntPtrConstant(OFFSET_OF_DATA_START(SeqOneByteString) -
                                        kHeapObjectTag));
    Goto(&if_join);
  }

  BIND(&if_external);
  {
    var_data = LoadExternalStringResourceDataPtr(CAST(string));
    Goto(&if_join);
  }

  BIND(&if_join);
  return var_data.value();
}

template <typename SubjectChar, typename PatternChar>
TNode<IntPtrT> StringBuiltinsAssembler::CallSearchStringRaw(
    const TNode<RawPtrT> subject_ptr, const TNode<IntPtrT> subject_length,
    const TNode<RawPtrT> search_ptr, const TNode<IntPtrT> search_length,
    const TNode<IntPtrT> start_position) {
  const TNode<ExternalReference> function_addr = ExternalConstant(
      ExternalReference::search_string_raw<SubjectChar, PatternChar>());
  const TNode<ExternalReference> isolate_ptr =
      ExternalConstant(ExternalReference::isolate_address());

  MachineType type_ptr = MachineType::Pointer();
  MachineType type_intptr = MachineType::IntPtr();

  const TNode<IntPtrT> result = UncheckedCast<IntPtrT>(CallCFunction(
      function_addr, type_intptr, std::make_pair(type_ptr, isolate_ptr),
      std::make_pair(type_ptr, subject_ptr),
      std::make_pair(type_intptr, subject_length),
      std::make_pair(type_ptr, search_ptr),
      std::make_pair(type_intptr, search_length),
      std::make_pair(type_intptr, start_position)));

  return result;
}
TNode<IntPtrT> StringBuiltinsAssembler::SearchOneByteStringInTwoByteString(
    const TNode<RawPtrT> subject_ptr, const TNode<IntPtrT> subject_length,
    const TNode<RawPtrT> search_ptr, const TNode<IntPtrT> search_length,
    const TNode<IntPtrT> start_position) {
  return CallSearchStringRaw<const base::uc16, const uint8_t>(
      subject_ptr, subject_length, search_ptr, search_length, start_position);
}
TNode<IntPtrT> StringBuiltinsAssembler::SearchOneByteStringInOneByteString(
    const TNode<RawPtrT> subject_ptr, const TNode<IntPtrT> subject_length,
    const TNode<RawPtrT> search_ptr, const TNode<IntPtrT> search_length,
    const TNode<IntPtrT> start_position) {
  return CallSearchStringRaw<const uint8_t, const uint8_t>(
      subject_ptr, subject_length, search_ptr, search_length, start_position);
}
TNode<IntPtrT> StringBuiltinsAssembler::SearchTwoByteStringInTwoByteString(
    const TNode<RawPtrT> subject_ptr, const TNode<IntPtrT> subject_length,
    const TNode<RawPtrT> search_ptr, const TNode<IntPtrT> search_length,
    const TNode<IntPtrT> start_position) {
  return CallSearchStringRaw<const base::uc16, const base::uc16>(
      subject_ptr, subject_length, search_ptr, search_length, start_position);
}
TNode<IntPtrT> StringBuiltinsAssembler::SearchTwoByteStringInOneByteString(
    const TNode<RawPtrT> subject_ptr, const TNode<IntPtrT> subject_length,
    const TNode<RawPtrT> search_ptr, const TNode<IntPtrT> search_length,
    const TNode<IntPtrT> start_position) {
  return CallSearchStringRaw<const uint8_t, const base::uc16>(
      subject_ptr, subject_length, search_ptr, search_length, start_position);
}
TNode<IntPtrT> StringBuiltinsAssembler::SearchOneByteInOneByteString(
    const TNode<RawPtrT> subject_ptr, const TNode<IntPtrT> subject_length,
    const TNode<RawPtrT> search_ptr, const TNode<IntPtrT> start_position) {
  const TNode<RawPtrT> subject_start_ptr =
      RawPtrAdd(subject_ptr, start_position);
  const TNode<IntPtrT> search_byte =
      ChangeInt32ToIntPtr(Load<Uint8T>(search_ptr));
  const TNode<UintPtrT> search_length =
      Unsigned(IntPtrSub(subject_length, start_position));
  const TNode<ExternalReference> memchr =
      ExternalConstant(ExternalReference::libc_memchr_function());
  const TNode<RawPtrT> result_address = UncheckedCast<RawPtrT>(
      CallCFunction(memchr, MachineType::Pointer(),
                    std::make_pair(MachineType::Pointer(), subject_start_ptr),
                    std::make_pair(MachineType::IntPtr(), search_byte),
                    std::make_pair(MachineType::UintPtr(), search_length)));
  return Select<IntPtrT>(
      WordEqual(result_address, IntPtrConstant(0)),
      [=, this] { return IntPtrConstant(-1); },
      [=, this] {
        return IntPtrAdd(RawPtrSub(result_address, subject_start_ptr),
                         start_position);
      });
}

void StringBuiltinsAssembler::GenerateStringEqual(TNode<String> left,
                                                  TNode<String> right,
                                                  TNode<IntPtrT> length) {
  TVARIABLE(String, var_left, left);
  TVARIABLE(String, var_right, right);
  Label if_equal(this), if_notequal(this), if_indirect(this, Label::kDeferred),
      start(this, {&var_left, &var_right});

  // Callers must handle the case where {lhs} and {rhs} refer to the same
  // String object.
  CSA_DCHECK(this, TaggedNotEqual(left, right));

  CSA_DCHECK(this, IntPtrEqual(LoadStringLengthAsWord(left), length));
  CSA_DCHECK(this, IntPtrEqual(LoadStringLengthAsWord(right), length));

  Goto(&start);
  BIND(&start);
  TNode<String> lhs = var_left.value();
  TNode<String> rhs = var_right.value();

  TNode<Uint16T> lhs_instance_type = LoadInstanceType(lhs);
  TNode<Uint16T> rhs_instance_type = LoadInstanceType(rhs);

  StringEqual_Core(lhs, lhs_instance_type, rhs, rhs_instance_type, length,
                   &if_equal, &if_notequal, &if_indirect);

  BIND(&if_indirect);
  {
    Label restart(this, {&var_left, &var_right});
    // Try to unwrap indirect strings, restart the above attempt on success.
    MaybeDerefIndirectStrings(&var_left, lhs_instance_type, &var_right,
                              rhs_instance_type, &restart);

    TailCallRuntime(Runtime::kStringEqual, NoContextConstant(), lhs, rhs);

    BIND(&restart);
    GotoIf(TaggedEqual(var_left.value(), var_right.value()), &if_equal);
    Goto(&start);
  }

  BIND(&if_equal);
  Return(TrueConstant());

  BIND(&if_notequal);
  Return(FalseConstant());
}

void StringBuiltinsAssembler::StringEqual_Core(
    TNode<String> lhs, TNode<Word32T> lhs_instance_type, TNode<String> rhs,
    TNode<Word32T> rhs_instance_type, TNode<IntPtrT> length, Label* if_equal,
    Label* if_not_equal, Label* if_indirect) {
  CSA_DCHECK(this, WordEqual(LoadStringLengthAsWord(lhs), length));
  CSA_DCHECK(this, WordEqual(LoadStringLengthAsWord(rhs), length));

  // Callers must handle the case where {lhs} and {rhs} refer to the same
  // String object.
  CSA_DCHECK(this, TaggedNotEqual(lhs, rhs));

  // Combine the instance types into a single 16-bit value, so we can check
  // both of them at once.
  TNode<Word32T> both_instance_types = Word32Or(
      lhs_instance_type, Word32Shl(rhs_instance_type, Int32Constant(8)));

  // Check if both {lhs} and {rhs} are internalized. Since we already know
  // that they're not the same object, they're not equal in that case.
  int const kBothInternalizedMask =
      kIsNotInternalizedMask | (kIsNotInternalizedMask << 8);
  int const kBothInternalizedTag = kInternalizedTag | (kInternalizedTag << 8);
  GotoIf(Word32Equal(Word32And(both_instance_types,
                               Int32Constant(kBothInternalizedMask)),
                     Int32Constant(kBothInternalizedTag)),
         if_not_equal);

  // Check if both {lhs} and {rhs} are direct strings, and that in case of
  // ExternalStrings the data pointer is cached.
  static_assert(kUncachedExternalStringTag != 0);
  static_assert(kIsIndirectStringTag != 0);
  int const kBothDirectStringMask =
      kIsIndirectStringMask | kUncachedExternalStringMask |
      ((kIsIndirectStringMask | kUncachedExternalStringMask) << 8);
  GotoIfNot(Word32Equal(Word32And(both_instance_types,
                                  Int32Constant(kBothDirectStringMask)),
                        Int32Constant(0)),
            if_indirect);

  Label if_skip_fast_case(this), if_fast_case(this), if_oneonebytestring(this),
      if_twotwobytestring(this), if_onetwobytestring(this),
      if_twoonebytestring(this);

  // Dispatch based on the {lhs} and {rhs} string encoding.
  int const kBothStringEncodingMask =
      kStringEncodingMask | (kStringEncodingMask << 8);
  int const kBothExternalStringTag =
      kExternalStringTag | (kExternalStringTag << 8);
  int const kOneOneByteStringTag = kOneByteStringTag | (kOneByteStringTag << 8);
  int const kTwoTwoByteStringTag = kTwoByteStringTag | (kTwoByteStringTag << 8);
  int const kOneTwoByteStringTag = kOneByteStringTag | (kTwoByteStringTag << 8);

  TNode<Word32T> masked_instance_types =
      Word32And(both_instance_types, Int32Constant(kBothStringEncodingMask));
  TNode<Word32T> both_are_one_byte =
      Word32Equal(masked_instance_types, Int32Constant(kOneOneByteStringTag));
  TNode<Word32T> both_are_two_byte =
      Word32Equal(masked_instance_types, Int32Constant(kTwoTwoByteStringTag));

  // If both strings are not external we know that their payload length is
  // kTagged sized. When they have the same type we can compare in chunks. The
  // padding bytes are set to zero.
  GotoIf(Word32And(both_instance_types, Int32Constant(kBothExternalStringTag)),
         &if_skip_fast_case);
  TVARIABLE(IntPtrT, byte_length, length);
  GotoIf(both_are_one_byte, &if_fast_case);
  byte_length = WordShl(byte_length.value(), IntPtrConstant(1));
  Branch(both_are_two_byte, &if_fast_case, &if_skip_fast_case);
  BIND(&if_fast_case);
  StringEqual_FastLoop(lhs, lhs_instance_type, rhs, rhs_instance_type,
                       byte_length.value(), if_equal, if_not_equal);

  BIND(&if_skip_fast_case);
  GotoIf(both_are_one_byte, &if_oneonebytestring);
  GotoIf(both_are_two_byte, &if_twotwobytestring);
  Branch(
      Word32Equal(masked_instance_types, Int32Constant(kOneTwoByteStringTag)),
      &if_onetwobytestring, &if_twoonebytestring);

  BIND(&if_oneonebytestring);
  StringEqual_Loop(lhs, lhs_instance_type, MachineType::Uint8(), rhs,
                   rhs_instance_type, MachineType::Uint8(), length, if_equal,
                   if_not_equal);

  BIND(&if_twotwobytestring);
  StringEqual_Loop(lhs, lhs_instance_type, MachineType::Uint16(), rhs,
                   rhs_instance_type, MachineType::Uint16(), length, if_equal,
                   if_not_equal);

  BIND(&if_onetwobytestring);
  StringEqual_Loop(lhs, lhs_instance_type, MachineType::Uint8(), rhs,
                   rhs_instance_type, MachineType::Uint16(), length, if_equal,
                   if_not_equal);

  BIND(&if_twoonebytestring);
  StringEqual_Loop(lhs, lhs_instance_type, MachineType::Uint16(), rhs,
                   rhs_instance_type, MachineType::Uint8(), length, if_equal,
                   if_not_equal);
}

void StringBuiltinsAssembler::StringEqual_FastLoop(
    TNode<String> lhs, TNode<Word32T> lhs_instance_type, TNode<String> rhs,
    TNode<Word32T> rhs_instance_type, TNode<IntPtrT> byte_length,
    Label* if_equal, Label* if_not_equal) {
  TNode<RawPtrT> lhs_data = DirectStringData(lhs, lhs_instance_type);
  TNode<RawPtrT> rhs_data = DirectStringData(rhs, rhs_instance_type);

  const int kChunk = kTaggedSize;
  static_assert(kObjectAlignment % kChunk == 0);
  // Round up the byte_length to `ceiling(length / kChunk) * kChunk`
  TNode<IntPtrT> rounded_up_len = UncheckedCast<IntPtrT>(WordAnd(
      UncheckedCast<WordT>(IntPtrAdd(byte_length, IntPtrConstant(kChunk - 1))),
      UncheckedCast<WordT>(IntPtrConstant(~(kChunk - 1)))));
  TNode<RawPtrT> lhs_end = RawPtrAdd(lhs_data, rounded_up_len);

#ifdef ENABLE_SLOW_DCHECKS
  // The padding must be zeroed for chunked comparison to be correct. This loop
  // checks all bytes being 0 from byte_length up to rounded_up_len.
  // If we ever stop zeroing the padding, GenerateStringRelationalComparison
  // below will also need to be updated.
  {
    TVARIABLE(IntPtrT, var_padding_offset, byte_length);
    Label loop(this, &var_padding_offset), loop_end(this);
    Goto(&loop);
    BIND(&loop);
    {
      GotoIf(WordEqual(var_padding_offset.value(), rounded_up_len), &loop_end);

      // Load the next byte
      TNode<Word32T> lhs_value = UncheckedCast<Word32T>(Load(
          MachineType::Uint8(), lhs_data,
          WordShl(var_padding_offset.value(),
                  ElementSizeLog2Of(MachineType::Uint8().representation()))));
      TNode<Word32T> rhs_value = UncheckedCast<Word32T>(Load(
          MachineType::Uint8(), rhs_data,
          WordShl(var_padding_offset.value(),
                  ElementSizeLog2Of(MachineType::Uint8().representation()))));

      // Check the padding is zero.
      CSA_CHECK(this, Word32Equal(lhs_value, Int32Constant(0)));
      CSA_CHECK(this, Word32Equal(rhs_value, Int32Constant(0)));

      // Advance to next byte.
      var_padding_offset =
          IntPtrAdd(var_padding_offset.value(), IntPtrConstant(1));
      Goto(&loop);
    }
    BIND(&loop_end);
  }
#endif  // ENABLE_SLOW_DCHECKS

  // Compare strings in chunks of either 4 or 8 bytes, depending on the
  // alignment of allocations.
  static_assert(kChunk == ElementSizeInBytes(MachineRepresentation::kWord64) ||
                kChunk == ElementSizeInBytes(MachineRepresentation::kWord32));
  TVARIABLE(RawPtrT, rhs_ptr, rhs_data);
  VariableList vars({&rhs_ptr}, zone());

  if (kChunk == ElementSizeInBytes(MachineRepresentation::kWord64)) {
    BuildFastLoop<RawPtrT>(
        vars, lhs_data, lhs_end,
        [&](TNode<RawPtrT> lhs_ptr) {
          TNode<Word64T> lhs_value = Load<Uint64T>(lhs_ptr);
          TNode<Word64T> rhs_value = Load<Uint64T>(rhs_ptr.value());
          GotoIf(Word64NotEqual(lhs_value, rhs_value), if_not_equal);

          // Advance {rhs_ptr} to next characters. {lhs_ptr} will be
          // advanced along loop's {var_index}.
          Increment(&rhs_ptr, kChunk);
        },
        kChunk, LoopUnrollingMode::kYes, IndexAdvanceMode::kPost);
  } else {
    BuildFastLoop<RawPtrT>(
        vars, lhs_data, lhs_end,
        [&](TNode<RawPtrT> lhs_ptr) {
          TNode<Word32T> lhs_value = Load<Uint32T>(lhs_ptr);
          TNode<Word32T> rhs_value = Load<Uint32T>(rhs_ptr.value());
          GotoIf(Word32NotEqual(lhs_value, rhs_value), if_not_equal);

          // Advance {rhs_ptr} to next characters. {lhs_ptr} will be
          // advanced along loop's {var_index}.
          Increment(&rhs_ptr, kChunk);
        },
        kChunk, LoopUnrollingMode::kYes, IndexAdvanceMode::kPost);
  }
  Goto(if_equal);
}

void StringBuiltinsAssembler::StringEqual_Loop(
    TNode<String> lhs, TNode<Word32T> lhs_instance_type, MachineType lhs_type,
    TNode<String> rhs, TNode<Word32T> rhs_instance_type, MachineType rhs_type,
    TNode<IntPtrT> length, Label* if_equal, Label* if_not_equal) {
  Comment("StringEqual_Loop");
  CSA_DCHECK(this, WordEqual(LoadStringLengthAsWord(lhs), length));
  CSA_DCHECK(this, WordEqual(LoadStringLengthAsWord(rhs), length));

  // Compute the effective offset of the first character.
  TNode<RawPtrT> lhs_data = DirectStringData(lhs, lhs_instance_type);
  TNode<RawPtrT> rhs_data = DirectStringData(rhs, rhs_instance_type);
  TNode<RawPtrT> lhs_end =
      RawPtrAdd(lhs_data, WordShl(length, IntPtrConstant(ElementSizeLog2Of(
                                              lhs_type.representation()))));
  TVARIABLE(RawPtrT, rhs_ptr, rhs_data);
  VariableList vars({&rhs_ptr}, zone());

  // Loop over the {lhs} and {rhs} strings to see if they are equal.
  BuildFastLoop<RawPtrT>(
      vars, lhs_data, lhs_end,
      [&](TNode<RawPtrT> lhs_ptr) {
        TNode<Word32T> lhs_value =
            UncheckedCast<Word32T>(Load(lhs_type, lhs_ptr));
        TNode<Word32T> rhs_value =
            UncheckedCast<Word32T>(Load(rhs_type, rhs_ptr.value()));

        // Check if the characters match.
        GotoIf(Word32NotEqual(lhs_value, rhs_value), if_not_equal);

        // Advance {rhs_ptr} to next characters. {lhs_ptr} will be
        // advanced along loop's {var_index}.
        Increment(&rhs_ptr, ElementSizeInBytes(rhs_type.representation()));
      },
      ElementSizeInBytes(lhs_type.representation()), LoopUnrollingMode::kNo,
      IndexAdvanceMode::kPost);

  // All characters are checked and no difference was found, so the strings
  // are equal.
  Goto(if_equal);
}

TNode<String> StringBuiltinsAssembler::StringFromSingleUTF16EncodedCodePoint(
    TNode<Int32T> codepoint) {
  TVARIABLE(String, var_result, EmptyStringConstant());

  Label if_isword16(this), if_isword32(this), return_result(this);

  Branch(Uint32LessThan(codepoint, Int32Constant(0x10000)), &if_isword16,
         &if_isword32);

  BIND(&if_isword16);
  {
    var_result = StringFromSingleCharCode(codepoint);
    Goto(&return_result);
  }

  BIND(&if_isword32);
  {
    TNode<String> value = AllocateSeqTwoByteString(2);
    StoreNoWriteBarrier(
        MachineRepresentation::kWord32, value,
        IntPtrConstant(OFFSET_OF_DATA_START(SeqTwoByteString) - kHeapObjectTag),
        codepoint);
    var_result = value;
    Goto(&return_result);
  }

  BIND(&return_result);
  return var_result.value();
}

TNode<String> StringBuiltinsAssembler::AllocateConsString(TNode<Uint32T> length,
                                                          TNode<String> left,
                                                          TNode<String> right) {
  // Added string can be a cons string.
  Comment("Allocating ConsString");
  TVARIABLE(String, first, left);
  TNode<Int32T> left_instance_type = LoadInstanceType(left);
  Label handle_right(this);
  static_assert(base::bits::CountPopulation(kThinStringTagBit) == 1);
  GotoIfNot(IsSetWord32(left_instance_type, kThinStringTagBit), &handle_right);
  {
    first = LoadObjectField<String>(left, offsetof(ThinString, actual_));
    Goto(&handle_right);
  }

  BIND(&handle_right);
  TVARIABLE(String, second, right);
  TNode<Int32T> right_instance_type = LoadInstanceType(right);
  Label allocate(this);
  GotoIfNot(IsSetWord32(right_instance_type, kThinStringTagBit), &allocate);
  {
    second = LoadObjectField<String>(right, offsetof(ThinString, actual_));
    Goto(&allocate);
  }

  BIND(&allocate);
  // Determine the resulting ConsString map to use depending on whether
  // any of {left} or {right} has two byte encoding.
  static_assert(kOneByteStringTag != 0);
  static_assert(kTwoByteStringTag == 0);
  TNode<Int32T> combined_instance_type =
      Word32And(left_instance_type, right_instance_type);
  TNode<Map> result_map = CAST(Select<Object>(
      IsSetWord32(combined_instance_type, kStringEncodingMask),
      [=, this] { return ConsOneByteStringMapConstant(); },
      [=, this] { return ConsTwoByteStringMapConstant(); }));
  TNode<HeapObject> result = AllocateInNewSpace(sizeof(ConsString));
  StoreMapNoWriteBarrier(result, result_map);
  StoreObjectFieldNoWriteBarrier(result, offsetof(ConsString, length_), length);
  StoreObjectFieldNoWriteBarrier(result, offsetof(ConsString, raw_hash_field_),
                                 Int32Constant(String::kEmptyHashField));
  StoreObjectFieldNoWriteBarrier(result, offsetof(ConsString, first_),
                                 first.value());
  StoreObjectFieldNoWriteBarrier(result, offsetof(ConsString, second_),
                                 second.value());
  return CAST(result);
}

TNode<String> StringBuiltinsAssembler::StringAdd(
    TNode<ContextOrEmptyContext> context, TNode<String> left,
    TNode<String> right) {
  CSA_DCHECK(this, IsZeroOrContext(context));

  TVARIABLE(String, result);
  Label check_right(this), runtime(this, Label::kDeferred), cons(this),
      done(this, &result);

  TNode<Uint32T> left_length = LoadStringLengthAsWord32(left);
  GotoIfNot(Word32Equal(left_length, Uint32Constant(0)), &check_right);
  result = right;
  Goto(&done);

  BIND(&check_right);
  TNode<Uint32T> right_length = LoadStringLengthAsWord32(right);
  GotoIfNot(Word32Equal(right_length, Uint32Constant(0)), &cons);
  result = left;
  Goto(&done);

  BIND(&cons);
  {
    TNode<Uint32T> new_length = Uint32Add(left_length, right_length);

    // If new length is greater than String::kMaxLength, goto runtime to
    // throw. Note: we also need to invalidate the string length protector, so
    // can't just throw here directly.
    GotoIf(Uint32GreaterThan(new_length, Uint32Constant(String::kMaxLength)),
           &runtime);

    TVARIABLE(String, var_left, left);
    TVARIABLE(String, var_right, right);
    Label non_cons(this, {&var_left, &var_right});
    Label slow(this, Label::kDeferred);
    GotoIf(Uint32LessThan(new_length, Uint32Constant(ConsString::kMinLength)),
           &non_cons);

    result =
        AllocateConsString(new_length, var_left.value(), var_right.value());
    Goto(&done);

    BIND(&non_cons);

    Comment("Full string concatenate");
    TNode<Int32T> left_instance_type = LoadInstanceType(var_left.value());
    TNode<Int32T> right_instance_type = LoadInstanceType(var_right.value());
    // Compute intersection and difference of instance types.

    TNode<Int32T> ored_instance_types =
        Word32Or(left_instance_type, right_instance_type);
    TNode<Word32T> xored_instance_types =
        Word32Xor(left_instance_type, right_instance_type);

    // Check if both strings have the same encoding and both are sequential.
    GotoIf(IsSetWord32(xored_instance_types, kStringEncodingMask), &runtime);
    GotoIf(IsSetWord32(ored_instance_types, kStringRepresentationMask), &slow);

    TNode<IntPtrT> word_left_length = Signed(ChangeUint32ToWord(left_length));
    TNode<IntPtrT> word_right_length = Signed(ChangeUint32ToWord(right_length));

    Label two_byte(this);
    GotoIf(Word32Equal(Word32And(ored_instance_types,
                                 Int32Constant(kStringEncodingMask)),
                       Int32Constant(kTwoByteStringTag)),
           &two_byte);
    // One-byte sequential string case
    result = AllocateSeqOneByteString(new_length);
    CopyStringCharacters(var_left.value(), result.value(), IntPtrConstant(0),
                         IntPtrConstant(0), word_left_length,
                         String::ONE_BYTE_ENCODING, String::ONE_BYTE_ENCODING);
    CopyStringCharacters(var_right.value(), result.value(), IntPtrConstant(0),
                         word_left_length, word_right_length,
                         String::ONE_BYTE_ENCODING, String::ONE_BYTE_ENCODING);
    Goto(&done);

    BIND(&two_byte);
    {
      // Two-byte sequential string case
      result = AllocateSeqTwoByteString(new_length);
      CopyStringCharacters(var_left.value(), result.value(), IntPtrConstant(0),
                           IntPtrConstant(0), word_left_length,
                           String::TWO_BYTE_ENCODING,
                           String::TWO_BYTE_ENCODING);
      CopyStringCharacters(var_right.value(), result.value(), IntPtrConstant(0),
                           word_left_length, word_right_length,
                           String::TWO_BYTE_ENCODING,
                           String::TWO_BYTE_ENCODING);
      Goto(&done);
    }

    BIND(&slow);
    {
      // Try to unwrap indirect strings, restart the above attempt on success.
      MaybeDerefIndirectStrings(&var_left, left_instance_type, &var_right,
                                right_instance_type, &non_cons);
      Goto(&runtime);
    }
  }
  BIND(&runtime);
  {
    result = CAST(CallRuntime(Runtime::kStringAdd, context, left, right));
    Goto(&done);
  }

  BIND(&done);
  return result.value();
}

void StringBuiltinsAssembler::BranchIfCanDerefIndirectString(
    TNode<String> string, TNode<Int32T> instance_type, Label* can_deref,
    Label* cannot_deref) {
  TNode<Int32T> representation =
      Word32And(instance_type, Int32Constant(kStringRepresentationMask));
  GotoIf(Word32Equal(representation, Int32Constant(kThinStringTag)), can_deref);
  GotoIf(Word32NotEqual(representation, Int32Constant(kConsStringTag)),
         cannot_deref);
  // Cons string.
  TNode<String> rhs =
      LoadObjectField<String>(string, offsetof(ConsString, second_));
  GotoIf(IsEmptyString(rhs), can_deref);
  Goto(cannot_deref);
}

void StringBuiltinsAssembler::DerefIndirectString(TVariable<String>* var_string,
                                                  TNode<Int32T> instance_type) {
#ifdef DEBUG
  Label can_deref(this), cannot_deref(this);
  BranchIfCanDerefIndirectString(var_string->value(), instance_type, &can_deref,
                                 &cannot_deref);
  BIND(&cannot_deref);
  DebugBreak();  // Should be able to dereference string.
  Goto(&can_deref);
  BIND(&can_deref);
#endif  // DEBUG

  static_assert(static_cast<int>(offsetof(ThinString, actual_)) ==
                static_cast<int>(offsetof(ConsString, first_)));
  *var_string = LoadObjectField<String>(var_string->value(),
                                        offsetof(ThinString, actual_));
}

void StringBuiltinsAssembler::MaybeDerefIndirectString(
    TVariable<String>* var_string, TNode<Int32T> instance_type,
    Label* did_deref, Label* cannot_deref) {
  Label deref(this);
  BranchIfCanDerefIndirectString(var_string->value(), instance_type, &deref,
                                 cannot_deref);

  BIND(&deref);
  {
    DerefIndirectString(var_string, instance_type);
    Goto(did_deref);
  }
}

void StringBuiltinsAssembler::MaybeDerefIndirectStrings(
    TVariable<String>* var_left, TNode<Int32T> left_instance_type,
    TVariable<String>* var_right, TNode<Int32T> right_instance_type,
    Label* did_something) {
  Label did_nothing_left(this), did_something_left(this),
      didnt_do_anything(this);
  MaybeDerefIndirectString(var_left, left_instance_type, &did_something_left,
                           &did_nothing_left);

  BIND(&did_something_left);
  {
    MaybeDerefIndirectString(var_right, right_instance_type, did_something,
                             did_something);
  }

  BIND(&did_nothing_left);
  {
    MaybeDerefIndirectString(var_right, right_instance_type, did_something,
                             &didnt_do_anything);
  }

  BIND(&didnt_do_anything);
  // Fall through if neither string was an indirect string.
}

TNode<String> StringBuiltinsAssembler::DerefIndirectString(
    TNode<String> string, TNode<Int32T> instance_type, Label* cannot_deref) {
  Label deref(this);
  BranchIfCanDerefIndirectString(string, instance_type, &deref, cannot_deref);
  BIND(&deref);
  static_assert(static_cast<int>(offsetof(ThinString, actual_)) ==
                static_cast<int>(offsetof(ConsString, first_)));
  return LoadObjectField<String>(string, offsetof(ThinString, actual_));
}

TF_BUILTIN(StringAdd_CheckNone, StringBuiltinsAssembler) {
  auto left = Parameter<String>(Descriptor::kLeft);
  auto right = Parameter<String>(Descriptor::kRight);
  TNode<ContextOrEmptyContext> context =
      UncheckedParameter<ContextOrEmptyContext>(Descriptor::kContext);
  CSA_DCHECK(this, IsZeroOrContext(context));
  Return(StringAdd(context, left, right));
}

TF_BUILTIN(SubString, StringBuiltinsAssembler) {
  auto string = Parameter<String>(Descriptor::kString);
  auto from = Parameter<Smi>(Descriptor::kFrom);
  auto to = Parameter<Smi>(Descriptor::kTo);
  Return(SubString(string, SmiUntag(from), SmiUntag(to)));
}

void StringBuiltinsAssembler::GenerateStringRelationalComparison(
    TNode<String> left, TNode<String> right, StringComparison op) {
  TVARIABLE(String, var_left, left);
  TVARIABLE(String, var_right, right);

  Label if_less(this), if_equal(this), if_greater(this);
  Label restart(this, {&var_left, &var_right});
  Goto(&restart);
  BIND(&restart);

  TNode<String> lhs = var_left.value();
  TNode<String> rhs = var_right.value();
  // Fast check to see if {lhs} and {rhs} refer to the same String object.
  GotoIf(TaggedEqual(lhs, rhs), &if_equal);

  // Load instance types of {lhs} and {rhs}.
  TNode<Uint16T> lhs_instance_type = LoadInstanceType(lhs);
  TNode<Uint16T> rhs_instance_type = LoadInstanceType(rhs);

  // Combine the instance types into a single 16-bit value, so we can check
  // both of them at once.
  TNode<Int32T> both_instance_types = Word32Or(
      lhs_instance_type, Word32Shl(rhs_instance_type, Int32Constant(8)));

  // Check that both {lhs} and {rhs} are flat one-byte strings.
  int const kBothSeqOneByteStringMask =
      kStringEncodingMask | kStringRepresentationMask |
      ((kStringEncodingMask | kStringRepresentationMask) << 8);
  int const kBothSeqOneByteStringTag =
      kOneByteStringTag | kSeqStringTag |
      ((kOneByteStringTag | kSeqStringTag) << 8);
  Label if_bothonebyteseqstrings(this), if_notbothonebyteseqstrings(this);
  Branch(Word32Equal(Word32And(both_instance_types,
                               Int32Constant(kBothSeqOneByteStringMask)),
                     Int32Constant(kBothSeqOneByteStringTag)),
         &if_bothonebyteseqstrings, &if_notbothonebyteseqstrings);

  BIND(&if_bothonebyteseqstrings);
  {
    TNode<IntPtrT> lhs_length = LoadStringLengthAsWord(lhs);
    TNode<IntPtrT> rhs_length = LoadStringLengthAsWord(rhs);

    TNode<IntPtrT> length = IntPtrMin(lhs_length, rhs_length);

    // Loop over the {lhs} and {rhs} strings to see if they are equal.
    constexpr int kBeginOffset =
        OFFSET_OF_DATA_START(SeqOneByteString) - kHeapObjectTag;
    TNode<IntPtrT> begin = IntPtrConstant(kBeginOffset);
    TNode<IntPtrT> end = IntPtrAdd(begin, length);
    TVARIABLE(IntPtrT, var_offset, begin);
    Label chunk_loop(this, &var_offset), char_loop(this, &var_offset);
    Label if_done(this);

    // Unrolled first iteration.
    GotoIf(IntPtrEqual(length, IntPtrConstant(0)), &if_done);

    constexpr int kChunkSize = kTaggedSize;
    static_assert(
        kChunkSize == ElementSizeInBytes(MachineRepresentation::kWord64) ||
        kChunkSize == ElementSizeInBytes(MachineRepresentation::kWord32));
    if (kChunkSize == ElementSizeInBytes(MachineRepresentation::kWord32)) {
      TNode<Uint32T> lhs_chunk =
          Load<Uint32T>(lhs, IntPtrConstant(kBeginOffset));
      TNode<Uint32T> rhs_chunk =
          Load<Uint32T>(rhs, IntPtrConstant(kBeginOffset));
      GotoIf(Word32NotEqual(lhs_chunk, rhs_chunk), &char_loop);
    } else {
      TNode<Uint64T> lhs_chunk =
          Load<Uint64T>(lhs, IntPtrConstant(kBeginOffset));
      TNode<Uint64T> rhs_chunk =
          Load<Uint64T>(rhs, IntPtrConstant(kBeginOffset));
      GotoIf(Word64NotEqual(lhs_chunk, rhs_chunk), &char_loop);
    }

    var_offset = IntPtrConstant(OFFSET_OF_DATA_START(SeqOneByteString) -
                                kHeapObjectTag + kChunkSize);

    Goto(&chunk_loop);

    // Try skipping over chunks of kChunkSize identical characters.
    // This depends on padding (between strings' lengths and the actual end
    // of the heap object) being zeroed out.
    BIND(&chunk_loop);
    {
      GotoIf(IntPtrGreaterThanOrEqual(var_offset.value(), end), &if_done);

      if (kChunkSize == ElementSizeInBytes(MachineRepresentation::kWord32)) {
        TNode<Uint32T> lhs_chunk = Load<Uint32T>(lhs, var_offset.value());
        TNode<Uint32T> rhs_chunk = Load<Uint32T>(rhs, var_offset.value());
        GotoIf(Word32NotEqual(lhs_chunk, rhs_chunk), &char_loop);
      } else {
        TNode<Uint64T> lhs_chunk = Load<Uint64T>(lhs, var_offset.value());
        TNode<Uint64T> rhs_chunk = Load<Uint64T>(rhs, var_offset.value());
        GotoIf(Word64NotEqual(lhs_chunk, rhs_chunk), &char_loop);
      }

      var_offset = IntPtrAdd(var_offset.value(), IntPtrConstant(kChunkSize)
```