Response:
Let's break down the thought process for analyzing this C++ code.

1. **Initial Understanding of the File Path:** The path `v8/src/codegen/source-position-table.cc` immediately gives a strong hint. `codegen` suggests it's involved in code generation, and `source-position-table` indicates it likely deals with mapping generated code back to the original source code. This is crucial for debugging, error reporting, and potentially performance analysis.

2. **Scanning the Includes:** The `#include` directives provide more context:
    * `"src/codegen/source-position-table.h"`: The header file, likely containing declarations for the classes defined in this `.cc` file. This reinforces the main purpose.
    * `"src/base/export-template.h"`:  Indicates potential use of templates for code generation.
    * `"src/base/logging.h"`: Suggests the presence of logging statements for debugging or informational purposes.
    * `"src/common/assert-scope.h"`: Points to the use of assertions for internal consistency checks.
    * `"src/heap/local-factory-inl.h"` and `"src/objects/objects-inl.h"`, `"src/objects/objects.h"`: Clearly indicate interaction with V8's object model and memory management (the heap). This signifies that the source position table is stored and managed within V8's internal structures.

3. **Namespace Exploration:** The code is within `namespace v8 { namespace internal { ... } }`. This confirms it's part of V8's internal implementation details and not part of the public API.

4. **Core Data Structures - Spotting the Key Concepts:**  The comments and the code itself highlight the core components:
    * **`PositionTableEntry`:**  This likely represents a single entry in the table, mapping a code offset to a source position and indicating whether it's a statement or expression.
    * **`SourcePositionTableBuilder`:**  A class responsible for constructing the source position table. The methods like `AddPosition` and `ToSourcePositionTable` are key.
    * **`SourcePositionTableIterator`:**  A class for iterating through the entries in the table. Methods like `Advance` and accessing `code_offset`, `source_position`, and `is_statement` are important.

5. **Encoding Scheme - Understanding the "How":** The detailed comment section explaining the encoding is crucial. It describes:
    * **Variable-length integer coding:** Optimizing storage by using fewer bytes for smaller values.
    * **Difference encoding:** Storing the difference from the previous entry, further reducing storage for sequential code.
    * **Bit stuffing for type:**  Cleverly using a bit in the code offset to store the statement/expression type.
    * **Little-endian and zig-zag encoding:** Common techniques for efficient data representation.

6. **Analyzing the Functions:**  Reading through the implementations of `EncodeInt`, `DecodeInt`, `EncodeEntry`, `DecodeEntry`, `AddPosition`, `ToSourcePositionTable`, and the iterator methods reveals the concrete logic of how the table is built, stored, and traversed. The helper functions (`AddAndSetEntry`, `SubtractFromEntry`) simplify the code.

7. **Identifying Key Functionality:** Based on the analysis so far, the main functionalities emerge:
    * Building the source position table.
    * Encoding the table efficiently.
    * Iterating through the table to retrieve source position information.

8. **Connecting to JavaScript (if applicable):**  The core purpose of a source position table is to link generated code back to the original JavaScript source. This is fundamental for stack traces in error messages, debugging tools, and potentially profilers. The thought process here is: *How does V8 use this information when something goes wrong or when developers are inspecting code?*  This leads to the examples related to error messages and debugging.

9. **Considering Potential Errors:** Thinking about how developers interact with JavaScript and how the source position table plays a role leads to the identification of common errors, like incorrect line numbers in stack traces or stepping into the wrong location during debugging, if the table is inaccurate.

10. **Inferring Torque (Based on the Prompt):** The prompt specifically mentions the `.tq` extension. Since the file is `.cc`, the answer is straightforward: it's *not* a Torque file. However, it's important to understand *why* Torque is relevant – it's another language V8 uses for internal implementation, often for performance-critical or type-sensitive code.

11. **Code Logic Inference (Hypothetical Inputs and Outputs):** To illustrate the encoding/decoding, a simple example of adding a few positions and how they might be encoded is helpful. This requires mentally stepping through the encoding process.

12. **Review and Refinement:** After drafting the initial explanation, reviewing it for clarity, accuracy, and completeness is essential. Ensuring that the explanation flows logically and addresses all parts of the prompt is important. For instance, making sure the explanation of the encoding scheme is clear and concise.

This structured approach, combining code reading with an understanding of the system's purpose, helps to effectively analyze and explain the functionality of a complex piece of software like this V8 source code file.
```cpp
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/codegen/source-position-table.h"

#include "src/base/export-template.h"
#include "src/base/logging.h"
#include "src/common/assert-scope.h"
#include "src/heap/local-factory-inl.h"
#include "src/objects/objects-inl.h"
#include "src/objects/objects.h"

namespace v8 {
namespace internal {

// We'll use a simple encoding scheme to record the source positions.
// Conceptually, each position consists of:
// - code_offset: An integer index into the BytecodeArray or code.
// - source_position: An integer index into the source string.
// - position type: Each position is either a statement or an expression.
//
// The basic idea for the encoding is to use a variable-length integer coding,
// where each byte contains 7 bits of payload data, and 1 'more' bit that
// determines whether additional bytes follow. Additionally:
// - we record the difference from the previous position,
// - we just stuff one bit for the type into the code offset,
// - we write least-significant bits first,
// - we use zig-zag encoding to encode both positive and negative numbers.

namespace {

// Each byte is encoded as MoreBit | ValueBits.
using MoreBit = base::BitField8<bool, 7, 1>;
using ValueBits = base::BitField8<unsigned, 0, 7>;

// Helper: Add the offsets from 'other' to 'value'. Also set is_statement.
void AddAndSetEntry(PositionTableEntry* value,
                    const PositionTableEntry& other) {
  value->code_offset += other.code_offset;
  DCHECK_IMPLIES(value->code_offset != kFunctionEntryBytecodeOffset,
                 value->code_offset >= 0);
  value->source_position += other.source_position;
  DCHECK_LE(0, value->source_position);
  value->is_statement = other.is_statement;
}

// Helper: Subtract the offsets from 'other' from 'value'.
void SubtractFromEntry(PositionTableEntry* value,
                       const PositionTableEntry& other) {
  value->code_offset -= other.code_offset;
  value->source_position -= other.source_position;
}

// Helper: Encode an integer.
template <typename T>
void EncodeInt(ZoneVector<uint8_t>* bytes, T value) {
  using unsigned_type = typename std::make_unsigned<T>::type;
  // Zig-zag encoding.
  static constexpr int kShift = sizeof(T) * kBitsPerByte - 1;
  value = ((static_cast<unsigned_type>(value) << 1) ^ (value >> kShift));
  DCHECK_GE(value, 0);
  unsigned_type encoded = static_cast<unsigned_type>(value);
  bool more;
  do {
    more = encoded > ValueBits::kMax;
    uint8_t current =
        MoreBit::encode(more) | ValueBits::encode(encoded & ValueBits::kMask);
    bytes->push_back(current);
    encoded >>= ValueBits::kSize;
  } while (more);
}

// Encode a PositionTableEntry.
void EncodeEntry(ZoneVector<uint8_t>* bytes, const PositionTableEntry& entry) {
  // We only accept ascending code offsets.
  DCHECK_LE(0, entry.code_offset);
  // All but the first entry must be *strictly* ascending (no two entries for
  // the same position).
  // TODO(11496): This DCHECK fails tests.
  // DCHECK_IMPLIES(!bytes->empty(), entry.code_offset > 0);
  // Since code_offset is not negative, we use sign to encode is_statement.
  EncodeInt(bytes,
            entry.is_statement ? entry.code_offset : -entry.code_offset - 1);
  EncodeInt(bytes, entry.source_position);
}

// Helper: Decode an integer.
template <typename T>
T DecodeInt(base::Vector<const uint8_t> bytes, int* index) {
  uint8_t current;
  int shift = 0;
  T decoded = 0;
  bool more;
  do {
    current = bytes[(*index)++];
    decoded |= static_cast<typename std::make_unsigned<T>::type>(
                   ValueBits::decode(current))
               << shift;
    more = MoreBit::decode(current);
    shift += ValueBits::kSize;
  } while (more);
  DCHECK_GE(decoded, 0);
  decoded = (decoded >> 1) ^ (-(decoded & 1));
  return decoded;
}

void DecodeEntry(base::Vector<const uint8_t> bytes, int* index,
                 PositionTableEntry* entry) {
  int tmp = DecodeInt<int>(bytes, index);
  if (tmp >= 0) {
    entry->is_statement = true;
    entry->code_offset = tmp;
  } else {
    entry->is_statement = false;
    entry->code_offset = -(tmp + 1);
  }
  entry->source_position = DecodeInt<int64_t>(bytes, index);
}

base::Vector<const uint8_t> VectorFromByteArray(
    Tagged<TrustedByteArray> byte_array) {
  return base::Vector<const uint8_t>(byte_array->begin(), byte_array->length());
}

#ifdef ENABLE_SLOW_DCHECKS
void CheckTableEquals(const ZoneVector<PositionTableEntry>& raw_entries,
                      SourcePositionTableIterator* encoded) {
  // Brute force testing: Record all positions and decode
  // the entire table to verify they are identical.
  auto raw = raw_entries.begin();
  for (; !encoded->done(); encoded->Advance(), raw++) {
    DCHECK(raw != raw_entries.end());
    DCHECK_EQ(encoded->code_offset(), raw->code_offset);
    DCHECK_EQ(encoded->source_position().raw(), raw->source_position);
    DCHECK_EQ(encoded->is_statement(), raw->is_statement);
  }
  DCHECK(raw == raw_entries.end());
}
#endif

}  // namespace

SourcePositionTableBuilder::SourcePositionTableBuilder(
    Zone* zone, SourcePositionTableBuilder::RecordingMode mode)
    : mode_(mode),
      bytes_(zone),
#ifdef ENABLE_SLOW_DCHECKS
      raw_entries_(zone),
#endif
      previous_() {
}

void SourcePositionTableBuilder::AddPosition(size_t code_offset,
                                             SourcePosition source_position,
                                             bool is_statement) {
  if (Omit()) return;
  DCHECK(source_position.IsKnown());
  int offset = static_cast<int>(code_offset);
  AddEntry({offset, source_position.raw(), is_statement});
}

V8_INLINE void SourcePositionTableBuilder::AddEntry(
    const PositionTableEntry& entry) {
  PositionTableEntry tmp(entry);
  SubtractFromEntry(&tmp, previous_);
  EncodeEntry(&bytes_, tmp);
  previous_ = entry;
#ifdef ENABLE_SLOW_DCHECKS
  raw_entries_.push_back(entry);
#endif
}

template <typename IsolateT>
Handle<TrustedByteArray> SourcePositionTableBuilder::ToSourcePositionTable(
    IsolateT* isolate) {
  if (bytes_.empty()) return isolate->factory()->empty_trusted_byte_array();
  DCHECK(!Omit());

  Handle<TrustedByteArray> table =
      isolate->factory()->NewTrustedByteArray(static_cast<int>(bytes_.size()));
  MemCopy(table->begin(), bytes_.data(), bytes_.size());

#ifdef ENABLE_SLOW_DCHECKS
  // Brute force testing: Record all positions and decode
  // the entire table to verify they are identical.
  SourcePositionTableIterator it(
      *table, SourcePositionTableIterator::kAll,
      SourcePositionTableIterator::kDontSkipFunctionEntry);
  CheckTableEquals(raw_entries_, &it);
  // No additional source positions after creating the table.
  mode_ = OMIT_SOURCE_POSITIONS;
#endif
  return table;
}

template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)
    Handle<TrustedByteArray> SourcePositionTableBuilder::ToSourcePositionTable(
        Isolate* isolate);
template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)
    Handle<TrustedByteArray> SourcePositionTableBuilder::ToSourcePositionTable(
        LocalIsolate* isolate);

base::OwnedVector<uint8_t>
SourcePositionTableBuilder::ToSourcePositionTableVector() {
  if (bytes_.empty()) return base::OwnedVector<uint8_t>();
  DCHECK(!Omit());

  base::OwnedVector<uint8_t> table = base::OwnedVector<uint8_t>::Of(bytes_);

#ifdef ENABLE_SLOW_DCHECKS
  // Brute force testing: Record all positions and decode
  // the entire table to verify they are identical.
  SourcePositionTableIterator it(
      table.as_vector(), SourcePositionTableIterator::kAll,
      SourcePositionTableIterator::kDontSkipFunctionEntry);
  CheckTableEquals(raw_entries_, &it);
  // No additional source positions after creating the table.
  mode_ = OMIT_SOURCE_POSITIONS;
#endif
  return table;
}

void SourcePositionTableIterator::Initialize() {
  Advance();
  if (function_entry_filter_ == kSkipFunctionEntry &&
      current_.code_offset == kFunctionEntryBytecodeOffset && !done()) {
    Advance();
  }
}

SourcePositionTableIterator::SourcePositionTableIterator(
    Tagged<TrustedByteArray> byte_array, IterationFilter iteration_filter,
    FunctionEntryFilter function_entry_filter)
    : raw_table_(VectorFromByteArray(byte_array)),
      iteration_filter_(iteration_filter),
      function_entry_filter_(function_entry_filter) {
  Initialize();
}

SourcePositionTableIterator::SourcePositionTableIterator(
    Handle<TrustedByteArray> byte_array, IterationFilter iteration_filter,
    FunctionEntryFilter function_entry_filter)
    : table_(byte_array),
      iteration_filter_(iteration_filter),
      function_entry_filter_(function_entry_filter) {
  Initialize();
#ifdef DEBUG
  // We can enable allocation because we keep the table in a handle.
  no_gc.Release();
#endif  // DEBUG
}

SourcePositionTableIterator::SourcePositionTableIterator(
    base::Vector<const uint8_t> bytes, IterationFilter iteration_filter,
    FunctionEntryFilter function_entry_filter)
    : raw_table_(bytes),
      iteration_filter_(iteration_filter),
      function_entry_filter_(function_entry_filter) {
  Initialize();
#ifdef DEBUG
  // We can enable allocation because the underlying vector does not move.
  no_gc.Release();
#endif  // DEBUG
}

void SourcePositionTableIterator::Advance() {
  base::Vector<const uint8_t> bytes =
      table_.is_null() ? raw_table_ : VectorFromByteArray(*table_);
  DCHECK(!done());
  DCHECK(index_ >= 0 && index_ <= bytes.length());
  bool filter_satisfied = false;
  while (!done() && !filter_satisfied) {
    if (index_ >= bytes.length()) {
      index_ = kDone;
    } else {
      PositionTableEntry tmp;
      DecodeEntry(bytes, &index_, &tmp);
      AddAndSetEntry(&current_, tmp);
      SourcePosition p = source_position();
      filter_satisfied =
          (iteration_filter_ == kAll) ||
          (iteration_filter_ == kJavaScriptOnly && p.IsJavaScript()) ||
          (iteration_filter_ == kExternalOnly && p.IsExternal());
    }
  }
}

}  // namespace internal
}  // namespace v8
```

### 功能

`v8/src/codegen/source-position-table.cc` 的功能是 **维护和管理源代码位置信息与生成的机器码/字节码之间的映射关系**。

更具体地说，它做了以下事情：

1. **存储源代码位置信息:** 它记录了在生成代码过程中，生成的每一段代码（例如字节码指令或机器码指令）对应于源代码中的哪个位置（行号、列号等，在 V8 内部表示为 `SourcePosition`）。
2. **高效编码:** 为了节省内存空间，它使用了一种紧凑的编码方案来存储这些映射关系。这种编码方案采用了：
    * **变长整数编码:** 较小的偏移量可以用更少的字节表示。
    * **差分编码:** 存储当前位置与前一个位置的差异，进一步减小存储空间。
    * **位域 (bit stuffing):** 将 "是否为语句" 的信息编码到代码偏移量的符号位中。
    * **Zig-zag 编码:** 有效地表示正数和负数。
3. **构建器 (Builder):** `SourcePositionTableBuilder` 类负责在代码生成过程中收集源代码位置信息，并将其编码后存储起来。
4. **迭代器 (Iterator):** `SourcePositionTableIterator` 类允许遍历已编码的源代码位置表，将编码后的信息解码回原始的源代码位置和代码偏移量。
5. **用于调试和性能分析:** 这些源代码位置信息对于调试器来说至关重要，它可以将执行的代码位置映射回源代码，方便开发者理解代码的执行流程和定位错误。它也可能被用于性能分析工具，以确定性能瓶颈在源代码中的位置。

### 关于 .tq 后缀

如果 `v8/src/codegen/source-position-table.cc` 以 `.tq` 结尾，那么它将是一个 **v8 Torque 源代码文件**。 Torque 是 V8 开发的一种领域特定语言 (DSL)，用于编写 V8 内部的运行时代码，特别是那些对性能有较高要求的内置函数和操作。

**目前，该文件以 `.cc` 结尾，因此它是一个 C++ 源代码文件。**

### 与 JavaScript 的关系及示例

`v8/src/codegen/source-position-table.cc` 与 JavaScript 的功能有密切关系。当 JavaScript 代码被 V8 执行时，它首先会被编译成字节码或机器码。  `source-position-table.cc` 中定义的机制正是用于记录这些生成的代码与原始 JavaScript 代码之间的对应关系。

**JavaScript 示例:**

考虑以下简单的 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}

console.log(add(5, 3)); // 行 5
```

当 V8 编译这段代码时，它会为 `add` 函数和 `console.log` 调用生成相应的字节码或机器码。  `SourcePositionTableBuilder` 会记录下以下类似的信息（简化表示）：

* **字节码/机器码地址 X**  ->  `add` 函数定义的开始位置（例如，对应于 `function add(a, b) {`）
* **字节码/机器码地址 Y**  ->  `return a + b;` 语句的源代码位置（行 2，列 2）
* **字节码/机器码地址 Z**  ->  `console.log(add(5, 3))` 调用的源代码位置（行 5，列 0）

**用途示例 (错误堆栈跟踪):**

如果上面的 JavaScript 代码发生错误，例如在 `add` 函数内部访问了一个未定义的变量，V8 会生成一个错误堆栈跟踪，其中会包含出错代码的源代码位置：

```
ReferenceError: someUndefinedVariable is not defined
    at add (your_script.js:2:10)  // 注意这里的 "your_script.js:2:10"
    at <anonymous> (your_script.js:5:0)
```

V8 如何知道将错误指向 `your_script.js:2:10` 呢？ 这就是 `source-position-table.cc` 的功劳。当错误发生时，V8 可以找到导致错误的字节码/机器码的地址，然后通过查询源代码位置表，找到该地址对应的源代码位置信息，从而生成有意义的错误消息。

**用途示例 (调试器):**

当你在 Chrome 开发者工具中调试 JavaScript 代码时，你可以设置断点并单步执行代码。调试器能够高亮显示当前执行到的源代码行。 这同样依赖于源代码位置表，它将当前执行的机器码指令映射回对应的 JavaScript 源代码行，让调试器能够正确地显示代码的执行进度。

### 代码逻辑推理 (假设输入与输出)

假设我们有以下简单的 JavaScript 函数：

```javascript
function foo() { // Source position 0
  const x = 1;   // Source position 10
  return x;      // Source position 25
}
```

并且 V8 为其生成了以下（简化的）字节码，以及对应的 `SourcePosition` 和 `is_statement` 信息：

| 字节码偏移量 | 对应源代码位置 | 是否为语句 |
|---|---|---|
| 0 | 0 | true |  // function foo() {
| 5 | 10 | true | // const x = 1;
| 15 | 25 | true | // return x;

**SourcePositionTableBuilder 的处理过程:**

1. **添加第一个位置:**
   - `AddPosition(0, SourcePosition(0), true)`
   - `previous_` 为空，编码 `code_offset = 0`, `source_position = 0`, `is_statement = true`。
   - 编码后的字节 (根据编码规则):  `0b00000000`, `0b00000000`  (假设 `EncodeInt` 将 0 编码为单个字节)

2. **添加第二个位置:**
   - `AddPosition(5, SourcePosition(10), true)`
   - `entry = {5, 10, true}`
   - `tmp = {5 - 0, 10 - 0, true} = {5, 10, true}`
   - 编码 `code_offset = 5`, `source_position = 10`, `is_statement = true`。
   - 编码后的字节 (根据编码规则):  `0b00000101`, `0b00001010`

3. **添加第三个位置:**
   - `AddPosition(15, SourcePosition(25), true)`
   - `entry = {15, 25, true}`
   - `tmp = {15 - 5, 25 - 10, true} = {10, 15, true}`
   - 编码 `code_offset = 10`, `source_position = 15`, `is_statement = true`。
   - 编码后的字节 (根据编码规则): `0b00001010`, `0b00001111`

**假设的 `ToSourcePositionTable` 输出:**

最终生成的 `TrustedByteArray` 中会包含编码后的字节序列：

`[0b00000000, 0b00000000, 0b00000101, 0b00001010, 0b00001010, 0b00001111]`

**SourcePositionTableIterator 的处理过程:**

`SourcePositionTableIterator` 会逐步解码这些字节，恢复出原始的源代码位置信息。例如，调用 `Advance()` 会读取并解码这些字节，并更新 `current_` 成员，使其包含当前的 `code_offset`, `source_position` 和 `is_statement`。

### 用户常见的编程错误

`source-position-table.cc` 本身是 V8 内部的代码，用户不会直接与之交互。然而，**如果源代码位置表出现错误或不准确，可能会导致以下用户可见的编程错误相关的困扰:**

1. **错误的错误堆栈信息:**  如果源代码位置映射不正确，错误堆栈跟踪可能会指向错误的源代码行号和列号，使得开发者难以定位错误的真正来源。

   **示例:**  一个拼写错误导致访问了一个未定义的变量，但堆栈跟踪却指向了变量声明的上一行。

2. **调试器行为异常:** 调试器可能会在错误的源代码行上暂停，或者单步执行时跳转到不期望的位置，这会严重影响调试效率。

   **示例:**  你在某一行设置了断点，但程序执行到该行时并没有触发断点，或者触发了，但显示的是上一行或下一行的代码。

3. **性能分析不准确:**  如果性能分析工具依赖于源代码位置信息，不准确的映射可能导致错误的性能瓶颈报告，误导优化方向。

   **示例:**  性能分析报告显示某个函数调用占用了大量时间，但实际上瓶颈在该函数调用的内部，由于位置信息错误，分析工具无法精确定位。

**总结:**

`v8/src/codegen/source-position-table.cc` 是 V8 引擎中一个关键的组件，它维护着源代码与生成代码之间的桥梁。虽然开发者不会直接编写或修改这个文件，但其功能对于提供准确的错误报告、有效的代码调试和可靠的性能分析至关重要，直接影响着 JavaScript 开发者的体验。

### 提示词
```
这是目录为v8/src/codegen/source-position-table.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/source-position-table.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/codegen/source-position-table.h"

#include "src/base/export-template.h"
#include "src/base/logging.h"
#include "src/common/assert-scope.h"
#include "src/heap/local-factory-inl.h"
#include "src/objects/objects-inl.h"
#include "src/objects/objects.h"

namespace v8 {
namespace internal {

// We'll use a simple encoding scheme to record the source positions.
// Conceptually, each position consists of:
// - code_offset: An integer index into the BytecodeArray or code.
// - source_position: An integer index into the source string.
// - position type: Each position is either a statement or an expression.
//
// The basic idea for the encoding is to use a variable-length integer coding,
// where each byte contains 7 bits of payload data, and 1 'more' bit that
// determines whether additional bytes follow. Additionally:
// - we record the difference from the previous position,
// - we just stuff one bit for the type into the code offset,
// - we write least-significant bits first,
// - we use zig-zag encoding to encode both positive and negative numbers.

namespace {

// Each byte is encoded as MoreBit | ValueBits.
using MoreBit = base::BitField8<bool, 7, 1>;
using ValueBits = base::BitField8<unsigned, 0, 7>;

// Helper: Add the offsets from 'other' to 'value'. Also set is_statement.
void AddAndSetEntry(PositionTableEntry* value,
                    const PositionTableEntry& other) {
  value->code_offset += other.code_offset;
  DCHECK_IMPLIES(value->code_offset != kFunctionEntryBytecodeOffset,
                 value->code_offset >= 0);
  value->source_position += other.source_position;
  DCHECK_LE(0, value->source_position);
  value->is_statement = other.is_statement;
}

// Helper: Subtract the offsets from 'other' from 'value'.
void SubtractFromEntry(PositionTableEntry* value,
                       const PositionTableEntry& other) {
  value->code_offset -= other.code_offset;
  value->source_position -= other.source_position;
}

// Helper: Encode an integer.
template <typename T>
void EncodeInt(ZoneVector<uint8_t>* bytes, T value) {
  using unsigned_type = typename std::make_unsigned<T>::type;
  // Zig-zag encoding.
  static constexpr int kShift = sizeof(T) * kBitsPerByte - 1;
  value = ((static_cast<unsigned_type>(value) << 1) ^ (value >> kShift));
  DCHECK_GE(value, 0);
  unsigned_type encoded = static_cast<unsigned_type>(value);
  bool more;
  do {
    more = encoded > ValueBits::kMax;
    uint8_t current =
        MoreBit::encode(more) | ValueBits::encode(encoded & ValueBits::kMask);
    bytes->push_back(current);
    encoded >>= ValueBits::kSize;
  } while (more);
}

// Encode a PositionTableEntry.
void EncodeEntry(ZoneVector<uint8_t>* bytes, const PositionTableEntry& entry) {
  // We only accept ascending code offsets.
  DCHECK_LE(0, entry.code_offset);
  // All but the first entry must be *strictly* ascending (no two entries for
  // the same position).
  // TODO(11496): This DCHECK fails tests.
  // DCHECK_IMPLIES(!bytes->empty(), entry.code_offset > 0);
  // Since code_offset is not negative, we use sign to encode is_statement.
  EncodeInt(bytes,
            entry.is_statement ? entry.code_offset : -entry.code_offset - 1);
  EncodeInt(bytes, entry.source_position);
}

// Helper: Decode an integer.
template <typename T>
T DecodeInt(base::Vector<const uint8_t> bytes, int* index) {
  uint8_t current;
  int shift = 0;
  T decoded = 0;
  bool more;
  do {
    current = bytes[(*index)++];
    decoded |= static_cast<typename std::make_unsigned<T>::type>(
                   ValueBits::decode(current))
               << shift;
    more = MoreBit::decode(current);
    shift += ValueBits::kSize;
  } while (more);
  DCHECK_GE(decoded, 0);
  decoded = (decoded >> 1) ^ (-(decoded & 1));
  return decoded;
}

void DecodeEntry(base::Vector<const uint8_t> bytes, int* index,
                 PositionTableEntry* entry) {
  int tmp = DecodeInt<int>(bytes, index);
  if (tmp >= 0) {
    entry->is_statement = true;
    entry->code_offset = tmp;
  } else {
    entry->is_statement = false;
    entry->code_offset = -(tmp + 1);
  }
  entry->source_position = DecodeInt<int64_t>(bytes, index);
}

base::Vector<const uint8_t> VectorFromByteArray(
    Tagged<TrustedByteArray> byte_array) {
  return base::Vector<const uint8_t>(byte_array->begin(), byte_array->length());
}

#ifdef ENABLE_SLOW_DCHECKS
void CheckTableEquals(const ZoneVector<PositionTableEntry>& raw_entries,
                      SourcePositionTableIterator* encoded) {
  // Brute force testing: Record all positions and decode
  // the entire table to verify they are identical.
  auto raw = raw_entries.begin();
  for (; !encoded->done(); encoded->Advance(), raw++) {
    DCHECK(raw != raw_entries.end());
    DCHECK_EQ(encoded->code_offset(), raw->code_offset);
    DCHECK_EQ(encoded->source_position().raw(), raw->source_position);
    DCHECK_EQ(encoded->is_statement(), raw->is_statement);
  }
  DCHECK(raw == raw_entries.end());
}
#endif

}  // namespace

SourcePositionTableBuilder::SourcePositionTableBuilder(
    Zone* zone, SourcePositionTableBuilder::RecordingMode mode)
    : mode_(mode),
      bytes_(zone),
#ifdef ENABLE_SLOW_DCHECKS
      raw_entries_(zone),
#endif
      previous_() {
}

void SourcePositionTableBuilder::AddPosition(size_t code_offset,
                                             SourcePosition source_position,
                                             bool is_statement) {
  if (Omit()) return;
  DCHECK(source_position.IsKnown());
  int offset = static_cast<int>(code_offset);
  AddEntry({offset, source_position.raw(), is_statement});
}

V8_INLINE void SourcePositionTableBuilder::AddEntry(
    const PositionTableEntry& entry) {
  PositionTableEntry tmp(entry);
  SubtractFromEntry(&tmp, previous_);
  EncodeEntry(&bytes_, tmp);
  previous_ = entry;
#ifdef ENABLE_SLOW_DCHECKS
  raw_entries_.push_back(entry);
#endif
}

template <typename IsolateT>
Handle<TrustedByteArray> SourcePositionTableBuilder::ToSourcePositionTable(
    IsolateT* isolate) {
  if (bytes_.empty()) return isolate->factory()->empty_trusted_byte_array();
  DCHECK(!Omit());

  Handle<TrustedByteArray> table =
      isolate->factory()->NewTrustedByteArray(static_cast<int>(bytes_.size()));
  MemCopy(table->begin(), bytes_.data(), bytes_.size());

#ifdef ENABLE_SLOW_DCHECKS
  // Brute force testing: Record all positions and decode
  // the entire table to verify they are identical.
  SourcePositionTableIterator it(
      *table, SourcePositionTableIterator::kAll,
      SourcePositionTableIterator::kDontSkipFunctionEntry);
  CheckTableEquals(raw_entries_, &it);
  // No additional source positions after creating the table.
  mode_ = OMIT_SOURCE_POSITIONS;
#endif
  return table;
}

template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)
    Handle<TrustedByteArray> SourcePositionTableBuilder::ToSourcePositionTable(
        Isolate* isolate);
template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)
    Handle<TrustedByteArray> SourcePositionTableBuilder::ToSourcePositionTable(
        LocalIsolate* isolate);

base::OwnedVector<uint8_t>
SourcePositionTableBuilder::ToSourcePositionTableVector() {
  if (bytes_.empty()) return base::OwnedVector<uint8_t>();
  DCHECK(!Omit());

  base::OwnedVector<uint8_t> table = base::OwnedVector<uint8_t>::Of(bytes_);

#ifdef ENABLE_SLOW_DCHECKS
  // Brute force testing: Record all positions and decode
  // the entire table to verify they are identical.
  SourcePositionTableIterator it(
      table.as_vector(), SourcePositionTableIterator::kAll,
      SourcePositionTableIterator::kDontSkipFunctionEntry);
  CheckTableEquals(raw_entries_, &it);
  // No additional source positions after creating the table.
  mode_ = OMIT_SOURCE_POSITIONS;
#endif
  return table;
}

void SourcePositionTableIterator::Initialize() {
  Advance();
  if (function_entry_filter_ == kSkipFunctionEntry &&
      current_.code_offset == kFunctionEntryBytecodeOffset && !done()) {
    Advance();
  }
}

SourcePositionTableIterator::SourcePositionTableIterator(
    Tagged<TrustedByteArray> byte_array, IterationFilter iteration_filter,
    FunctionEntryFilter function_entry_filter)
    : raw_table_(VectorFromByteArray(byte_array)),
      iteration_filter_(iteration_filter),
      function_entry_filter_(function_entry_filter) {
  Initialize();
}

SourcePositionTableIterator::SourcePositionTableIterator(
    Handle<TrustedByteArray> byte_array, IterationFilter iteration_filter,
    FunctionEntryFilter function_entry_filter)
    : table_(byte_array),
      iteration_filter_(iteration_filter),
      function_entry_filter_(function_entry_filter) {
  Initialize();
#ifdef DEBUG
  // We can enable allocation because we keep the table in a handle.
  no_gc.Release();
#endif  // DEBUG
}

SourcePositionTableIterator::SourcePositionTableIterator(
    base::Vector<const uint8_t> bytes, IterationFilter iteration_filter,
    FunctionEntryFilter function_entry_filter)
    : raw_table_(bytes),
      iteration_filter_(iteration_filter),
      function_entry_filter_(function_entry_filter) {
  Initialize();
#ifdef DEBUG
  // We can enable allocation because the underlying vector does not move.
  no_gc.Release();
#endif  // DEBUG
}

void SourcePositionTableIterator::Advance() {
  base::Vector<const uint8_t> bytes =
      table_.is_null() ? raw_table_ : VectorFromByteArray(*table_);
  DCHECK(!done());
  DCHECK(index_ >= 0 && index_ <= bytes.length());
  bool filter_satisfied = false;
  while (!done() && !filter_satisfied) {
    if (index_ >= bytes.length()) {
      index_ = kDone;
    } else {
      PositionTableEntry tmp;
      DecodeEntry(bytes, &index_, &tmp);
      AddAndSetEntry(&current_, tmp);
      SourcePosition p = source_position();
      filter_satisfied =
          (iteration_filter_ == kAll) ||
          (iteration_filter_ == kJavaScriptOnly && p.IsJavaScript()) ||
          (iteration_filter_ == kExternalOnly && p.IsExternal());
    }
  }
}

}  // namespace internal
}  // namespace v8
```