Response:
The user wants to understand the functionality of the `v8/src/regexp/regexp-interpreter.cc` file in V8. They've provided the initial part of the file's content. I need to:

1. **Identify the core function:** Based on the code, it seems to be an interpreter for regular expression bytecode.
2. **List the functionalities:**  I'll go through the code and enumerate the operations it performs, particularly focusing on the different bytecodes and their actions.
3. **Address the `.tq` question:**  Confirm that the file is `.cc` and not `.tq`, therefore not a Torque source file.
4. **Explain the relationship to JavaScript:** This interpreter executes regular expressions, a core feature of JavaScript. I need to provide a simple JavaScript regex example.
5. **Demonstrate code logic inference:** I'll select a bytecode (e.g., `CHECK_CHAR`) and show how the interpreter would handle it with a specific input and expected output.
6. **Illustrate common programming errors:** I'll think about typical mistakes users make when working with regular expressions in JavaScript that this interpreter would handle.
7. **Summarize the functionality:** Condense the identified functionalities into a concise summary.
```
这是目录为v8/src/regexp/regexp-interpreter.cc的一个v8源代码， 请列举一下它的功能,
如果v8/src/regexp/regexp-interpreter.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

根据提供的代码，`v8/src/regexp/regexp-interpreter.cc` 的主要功能是：

1. **Irregexp 字节码的解释器:** 这是一个用于执行 Irregexp（V8 的内部正则表达式引擎）生成的字节码的解释器。它逐条读取并执行这些字节码指令，从而实现正则表达式的匹配过程。

2. **状态管理:**  解释器维护正则表达式匹配的状态，包括：
   - **当前匹配位置 (current):**  在被匹配字符串中的当前位置。
   - **当前字符 (current_char):**  当前位置的字符（或多个字符，取决于指令）。
   - **回溯栈 (backtrack_stack):** 用于保存匹配过程中的状态，以便在匹配失败时进行回溯。
   - **寄存器 (registers):**  存储匹配结果（例如捕获组的起始和结束位置）和内部状态。

3. **字节码指令处理:**  代码中定义了大量的 `BYTECODE(指令名称)` 宏，每个宏对应一个特定的 Irregexp 字节码指令。解释器根据当前指令执行相应的操作，例如：
   - **控制流指令 (GOTO, ADVANCE_CP_AND_GOTO):**  改变程序的执行流程。
   - **栈操作指令 (PUSH_CP, POP_BT):**  操作回溯栈。
   - **寄存器操作指令 (SET_REGISTER, ADVANCE_REGISTER):**  读写寄存器。
   - **字符匹配指令 (CHECK_CHAR, CHECK_CHAR_IN_RANGE):**  检查当前字符是否符合条件。
   - **边界匹配指令 (CHECK_AT_START):**  检查是否到达字符串的开头或结尾。
   - **反向引用指令 (CHECK_NOT_BACK_REF):**  检查当前匹配是否与之前捕获的子字符串相同。

4. **性能优化 (可选):** 代码中包含了对使用 computed gotos 进行优化的尝试 (`#if V8_USE_COMPUTED_GOTO`)，这是一种通过直接跳转到指令处理代码来提高解释器效率的技术。

5. **中断处理:**  解释器能够处理执行过程中的中断，例如栈溢出或 JavaScript 执行被挂起。

**关于 `.tq` 结尾:**

`v8/src/regexp/regexp-interpreter.cc` 的文件扩展名是 `.cc`，这表明它是一个 C++ 源代码文件。如果文件以 `.tq` 结尾，那么它才是 V8 Torque 源代码。 Torque 是一种用于生成高效 C++ 代码的 V8 内部领域特定语言。

**与 JavaScript 的关系:**

`v8/src/regexp/regexp-interpreter.cc` 是 V8 引擎处理 JavaScript 正则表达式的核心组件之一。当你在 JavaScript 中使用正则表达式时，V8 内部会将其编译成 Irregexp 字节码，然后由 `regexp-interpreter.cc` 中的代码来执行。

**JavaScript 示例:**

```javascript
const regex = /ab*c/;
const str = 'abbbcdef';
const result = str.match(regex);

console.log(result); // 输出: [ 'abbbc', index: 0, input: 'abbbcdef', groups: undefined ]
```

在这个例子中，当 JavaScript 引擎执行 `str.match(regex)` 时，会使用 V8 的正则表达式引擎。`regexp-interpreter.cc` 负责解释和执行与 `/ab*c/` 对应的 Irregexp 字节码，从而在字符串 `abbbcdef` 中找到匹配项 "abbbc"。

**代码逻辑推理 (以 `CHECK_CHAR` 指令为例):**

**假设输入:**

- `current_char`:  字符 'a' 的 ASCII 码 (97)
- `pc` 指向 `CHECK_CHAR` 指令的起始位置
- `insn` (从 `pc` 读取的 32 位值):  包含字节码 `CHECK_CHAR` 和要检查的字符 'a' 的 ASCII 码 (97)。假设 `insn` 的高 24 位编码了 97。
- `pc + 4` 指向如果匹配成功要跳转的偏移量，假设偏移量为 `0x10`。

**执行流程:**

1. 解释器读取 `insn`，识别出 `CHECK_CHAR` 指令。
2. 从 `insn` 中提取要检查的字符，即 97 ('a')。
3. 比较 `current_char` (97) 和提取出的字符 (97)。
4. 因为它们相等，条件成立。
5. 解释器从 `pc + 4` 读取偏移量 `0x10`。
6. 将 `next_pc` 设置为 `code_base + 0x10`。
7. 通过 `DISPATCH()` 跳转到 `next_pc` 指向的指令。

**输出:**  程序计数器 `pc` 被更新为 `code_base + 0x10`，继续执行该位置的指令。

**用户常见的编程错误 (与正则表达式相关):**

1. **忘记转义特殊字符:** 例如，想要匹配字面量 `.`，却写成 `/./`，这将匹配任何字符。正确的写法是 `/\./`。
   ```javascript
   const text = "example.com";
   const wrongRegex = /./;
   const rightRegex = /\./;

   console.log(text.match(wrongRegex)); // 输出: [ 'e', index: 0, input: 'example.com', groups: undefined ]
   console.log(text.match(rightRegex)); // 输出: [ '.', index: 7, input: 'example.com', groups: undefined ]
   ```

2. **贪婪匹配超出预期:**  默认情况下，正则表达式的量词 (如 `*`, `+`) 是贪婪的，会尽可能多地匹配字符。有时这会导致匹配到比预期更长的字符串。
   ```javascript
   const text = "<a>content</a>";
   const greedyRegex = /<.*>/;
   const nonGreedyRegex = /<.*?>/;

   console.log(text.match(greedyRegex)); // 输出: [ '<a>content</a>', index: 0, input: '<a>content</a>', groups: undefined ]
   console.log(text.match(nonGreedyRegex)); // 输出: [ '<a>', index: 0, input: '<a>content</a>', groups: undefined ]
   ```

3. **不正确的字符类使用:**  例如，`[a-Z]` 不会匹配所有字母，因为 ASCII 码中大写字母在小写字母之前。正确的写法是 `[a-zA-Z]`。

4. **回溯过多导致性能问题:**  复杂的正则表达式在某些输入下可能会导致大量的回溯，从而显著降低性能。这通常发生在嵌套的重复模式中。

**功能归纳:**

`v8/src/regexp/regexp-interpreter.cc` 的主要功能是作为 V8 引擎的正则表达式解释器，负责执行 Irregexp 字节码，管理匹配状态，处理各种字节码指令以实现正则表达式的匹配逻辑。它是 JavaScript 正则表达式功能的基础实现。

### 提示词
```
这是目录为v8/src/regexp/regexp-interpreter.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/regexp/regexp-interpreter.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2011 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// A simple interpreter for the Irregexp byte code.

#include "src/regexp/regexp-interpreter.h"

#include "src/base/small-vector.h"
#include "src/base/strings.h"
#include "src/execution/isolate.h"
#include "src/logging/counters.h"
#include "src/objects/js-regexp-inl.h"
#include "src/objects/string-inl.h"
#include "src/regexp/regexp-bytecodes.h"
#include "src/regexp/regexp-macro-assembler.h"
#include "src/regexp/regexp-stack.h"  // For kMaximumStackSize.
#include "src/regexp/regexp-utils.h"
#include "src/regexp/regexp.h"
#include "src/strings/unicode.h"
#include "src/utils/memcopy.h"
#include "src/utils/utils.h"

#ifdef V8_INTL_SUPPORT
#include "unicode/uchar.h"
#endif  // V8_INTL_SUPPORT

// Use token threaded dispatch iff the compiler supports computed gotos and the
// build argument v8_enable_regexp_interpreter_threaded_dispatch was set.
#if V8_HAS_COMPUTED_GOTO && \
    defined(V8_ENABLE_REGEXP_INTERPRETER_THREADED_DISPATCH)
#define V8_USE_COMPUTED_GOTO 1
#endif  // V8_HAS_COMPUTED_GOTO

namespace v8 {
namespace internal {

namespace {

bool BackRefMatchesNoCase(Isolate* isolate, int from, int current, int len,
                          base::Vector<const base::uc16> subject,
                          bool unicode) {
  Address offset_a =
      reinterpret_cast<Address>(const_cast<base::uc16*>(&subject.at(from)));
  Address offset_b =
      reinterpret_cast<Address>(const_cast<base::uc16*>(&subject.at(current)));
  size_t length = len * base::kUC16Size;

  bool result = unicode
                    ? RegExpMacroAssembler::CaseInsensitiveCompareUnicode(
                          offset_a, offset_b, length, isolate)
                    : RegExpMacroAssembler::CaseInsensitiveCompareNonUnicode(
                          offset_a, offset_b, length, isolate);
  return result == 1;
}

bool BackRefMatchesNoCase(Isolate* isolate, int from, int current, int len,
                          base::Vector<const uint8_t> subject, bool unicode) {
  // For Latin1 characters the unicode flag makes no difference.
  for (int i = 0; i < len; i++) {
    unsigned int old_char = subject[from++];
    unsigned int new_char = subject[current++];
    if (old_char == new_char) continue;
    // Convert both characters to lower case.
    old_char |= 0x20;
    new_char |= 0x20;
    if (old_char != new_char) return false;
    // Not letters in the ASCII range and Latin-1 range.
    if (!(old_char - 'a' <= 'z' - 'a') &&
        !(old_char - 224 <= 254 - 224 && old_char != 247)) {
      return false;
    }
  }
  return true;
}

#ifdef DEBUG
void MaybeTraceInterpreter(const uint8_t* code_base, const uint8_t* pc,
                           int stack_depth, int current_position,
                           uint32_t current_char, int bytecode_length,
                           const char* bytecode_name) {
  if (v8_flags.trace_regexp_bytecodes) {
    const bool printable = std::isprint(current_char);
    const char* format =
        printable
            ? "pc = %02x, sp = %d, curpos = %d, curchar = %08x (%c), bc = "
            : "pc = %02x, sp = %d, curpos = %d, curchar = %08x .%c., bc = ";
    PrintF(format, pc - code_base, stack_depth, current_position, current_char,
           printable ? current_char : '.');

    RegExpBytecodeDisassembleSingle(code_base, pc);
  }
}
#endif  // DEBUG

int32_t Load32Aligned(const uint8_t* pc) {
  DCHECK_EQ(0, reinterpret_cast<intptr_t>(pc) & 3);
  return *reinterpret_cast<const int32_t*>(pc);
}

uint32_t Load16AlignedUnsigned(const uint8_t* pc) {
  DCHECK_EQ(0, reinterpret_cast<intptr_t>(pc) & 1);
  return *reinterpret_cast<const uint16_t*>(pc);
}

int32_t Load16AlignedSigned(const uint8_t* pc) {
  DCHECK_EQ(0, reinterpret_cast<intptr_t>(pc) & 1);
  return *reinterpret_cast<const int16_t*>(pc);
}

// Helpers to access the packed argument. Takes the 32 bits containing the
// current bytecode, where the 8 LSB contain the bytecode and the rest contains
// a packed 24-bit argument.
// TODO(jgruber): Specify signed-ness in bytecode signature declarations, and
// police restrictions during bytecode generation.
int32_t LoadPacked24Signed(int32_t bytecode_and_packed_arg) {
  return bytecode_and_packed_arg >> BYTECODE_SHIFT;
}
uint32_t LoadPacked24Unsigned(int32_t bytecode_and_packed_arg) {
  return static_cast<uint32_t>(bytecode_and_packed_arg) >> BYTECODE_SHIFT;
}

// A simple abstraction over the backtracking stack used by the interpreter.
//
// Despite the name 'backtracking' stack, it's actually used as a generic stack
// that stores both program counters (= offsets into the bytecode) and generic
// integer values.
class BacktrackStack {
 public:
  BacktrackStack() = default;
  BacktrackStack(const BacktrackStack&) = delete;
  BacktrackStack& operator=(const BacktrackStack&) = delete;

  V8_WARN_UNUSED_RESULT bool push(int v) {
    data_.emplace_back(v);
    return (static_cast<int>(data_.size()) <= kMaxSize);
  }
  int peek() const {
    SBXCHECK(!data_.empty());
    return data_.back();
  }
  int pop() {
    int v = peek();
    data_.pop_back();
    return v;
  }

  // The 'sp' is the index of the first empty element in the stack.
  int sp() const { return static_cast<int>(data_.size()); }
  void set_sp(uint32_t new_sp) {
    DCHECK_LE(new_sp, sp());
    data_.resize_no_init(new_sp);
  }

 private:
  // Semi-arbitrary. Should be large enough for common cases to remain in the
  // static stack-allocated backing store, but small enough not to waste space.
  static constexpr int kStaticCapacity = 64;

  using ValueT = int;
  base::SmallVector<ValueT, kStaticCapacity> data_;

  static constexpr int kMaxSize =
      RegExpStack::kMaximumStackSize / sizeof(ValueT);
};

// Registers used during interpreter execution. These consist of output
// registers in indices [0, output_register_count[ which will contain matcher
// results as a {start,end} index tuple for each capture (where the whole match
// counts as implicit capture 0); and internal registers in indices
// [output_register_count, total_register_count[.
class InterpreterRegisters {
 public:
  using RegisterT = int;

  InterpreterRegisters(int total_register_count, RegisterT* output_registers,
                       int output_register_count)
      : registers_(total_register_count),
        output_registers_(output_registers),
        total_register_count_(total_register_count),
        output_register_count_(output_register_count) {
    // TODO(jgruber): Use int32_t consistently for registers. Currently, CSA
    // uses int32_t while runtime uses int.
    static_assert(sizeof(int) == sizeof(int32_t));
    SBXCHECK_GE(output_register_count, 2);  // At least 2 for the match itself.
    SBXCHECK_GE(total_register_count, output_register_count);
    SBXCHECK_LE(total_register_count, RegExpMacroAssembler::kMaxRegisterCount);
    DCHECK_NOT_NULL(output_registers);

    // Initialize the output register region to -1 signifying 'no match'.
    std::memset(registers_.data(), -1,
                output_register_count * sizeof(RegisterT));
    USE(total_register_count_);
  }

  const RegisterT& operator[](size_t index) const {
    SBXCHECK_LT(index, total_register_count_);
    return registers_[index];
  }
  RegisterT& operator[](size_t index) {
    SBXCHECK_LT(index, total_register_count_);
    return registers_[index];
  }

  void CopyToOutputRegisters() {
    MemCopy(output_registers_, registers_.data(),
            output_register_count_ * sizeof(RegisterT));
  }

 private:
  static constexpr int kStaticCapacity = 64;  // Arbitrary.
  base::SmallVector<RegisterT, kStaticCapacity> registers_;
  RegisterT* const output_registers_;
  const int total_register_count_;
  const int output_register_count_;
};

IrregexpInterpreter::Result ThrowStackOverflow(Isolate* isolate,
                                               RegExp::CallOrigin call_origin) {
  CHECK(call_origin == RegExp::CallOrigin::kFromRuntime);
  // We abort interpreter execution after the stack overflow is thrown, and thus
  // allow allocation here despite the outer DisallowGarbageCollectionScope.
  AllowGarbageCollection yes_gc;
  isolate->StackOverflow();
  return IrregexpInterpreter::EXCEPTION;
}

// Only throws if called from the runtime, otherwise just returns the EXCEPTION
// status code.
IrregexpInterpreter::Result MaybeThrowStackOverflow(
    Isolate* isolate, RegExp::CallOrigin call_origin) {
  if (call_origin == RegExp::CallOrigin::kFromRuntime) {
    return ThrowStackOverflow(isolate, call_origin);
  } else {
    return IrregexpInterpreter::EXCEPTION;
  }
}

template <typename Char>
void UpdateCodeAndSubjectReferences(
    Isolate* isolate, DirectHandle<TrustedByteArray> code_array,
    DirectHandle<String> subject_string,
    Tagged<TrustedByteArray>* code_array_out, const uint8_t** code_base_out,
    const uint8_t** pc_out, Tagged<String>* subject_string_out,
    base::Vector<const Char>* subject_string_vector_out) {
  DisallowGarbageCollection no_gc;

  if (*code_base_out != code_array->begin()) {
    *code_array_out = *code_array;
    const intptr_t pc_offset = *pc_out - *code_base_out;
    DCHECK_GT(pc_offset, 0);
    *code_base_out = code_array->begin();
    *pc_out = *code_base_out + pc_offset;
  }

  DCHECK(subject_string->IsFlat());
  *subject_string_out = *subject_string;
  *subject_string_vector_out = subject_string->GetCharVector<Char>(no_gc);
}

// Runs all pending interrupts and updates unhandlified object references if
// necessary.
template <typename Char>
IrregexpInterpreter::Result HandleInterrupts(
    Isolate* isolate, RegExp::CallOrigin call_origin,
    Tagged<TrustedByteArray>* code_array_out,
    Tagged<String>* subject_string_out, const uint8_t** code_base_out,
    base::Vector<const Char>* subject_string_vector_out,
    const uint8_t** pc_out) {
  DisallowGarbageCollection no_gc;

  StackLimitCheck check(isolate);
  bool js_has_overflowed = check.JsHasOverflowed();

  if (call_origin == RegExp::CallOrigin::kFromJs) {
    // Direct calls from JavaScript can be interrupted in two ways:
    // 1. A real stack overflow, in which case we let the caller throw the
    //    exception.
    // 2. The stack guard was used to interrupt execution for another purpose,
    //    forcing the call through the runtime system.
    if (js_has_overflowed) {
      return IrregexpInterpreter::EXCEPTION;
    } else if (check.InterruptRequested()) {
      return IrregexpInterpreter::RETRY;
    }
  } else {
    DCHECK(call_origin == RegExp::CallOrigin::kFromRuntime);
    // Prepare for possible GC.
    HandleScope handles(isolate);
    Handle<TrustedByteArray> code_handle(*code_array_out, isolate);
    Handle<String> subject_handle(*subject_string_out, isolate);

    if (js_has_overflowed) {
      return ThrowStackOverflow(isolate, call_origin);
    } else if (check.InterruptRequested()) {
      const bool was_one_byte =
          (*subject_string_out)->IsOneByteRepresentation();
      Tagged<Object> result;
      {
        AllowGarbageCollection yes_gc;
        result = isolate->stack_guard()->HandleInterrupts();
      }
      if (IsException(result, isolate)) {
        return IrregexpInterpreter::EXCEPTION;
      }

      // If we changed between a LATIN1 and a UC16 string, we need to
      // restart regexp matching with the appropriate template instantiation of
      // RawMatch.
      if (subject_handle->IsOneByteRepresentation() != was_one_byte) {
        return IrregexpInterpreter::RETRY;
      }

      UpdateCodeAndSubjectReferences(
          isolate, code_handle, subject_handle, code_array_out, code_base_out,
          pc_out, subject_string_out, subject_string_vector_out);
    }
  }

  return IrregexpInterpreter::SUCCESS;
}

bool CheckBitInTable(const uint32_t current_char, const uint8_t* const table) {
  int mask = RegExpMacroAssembler::kTableMask;
  int b = table[(current_char & mask) >> kBitsPerByteLog2];
  int bit = (current_char & (kBitsPerByte - 1));
  return (b & (1 << bit)) != 0;
}

// Returns true iff 0 <= index < length.
bool IndexIsInBounds(int index, int length) {
  DCHECK_GE(length, 0);
  return static_cast<uintptr_t>(index) < static_cast<uintptr_t>(length);
}

// If computed gotos are supported by the compiler, we can get addresses to
// labels directly in C/C++. Every bytecode handler has its own label and we
// store the addresses in a dispatch table indexed by bytecode. To execute the
// next handler we simply jump (goto) directly to its address.
#if V8_USE_COMPUTED_GOTO
#define BC_LABEL(name) BC_##name:
#define DECODE()                                                   \
  do {                                                             \
    next_insn = Load32Aligned(next_pc);                            \
    next_handler_addr = dispatch_table[next_insn & BYTECODE_MASK]; \
  } while (false)
#define DISPATCH()  \
  pc = next_pc;     \
  insn = next_insn; \
  goto* next_handler_addr
// Without computed goto support, we fall back to a simple switch-based
// dispatch (A large switch statement inside a loop with a case for every
// bytecode).
#else  // V8_USE_COMPUTED_GOTO
#define BC_LABEL(name) case BC_##name:
#define DECODE() next_insn = Load32Aligned(next_pc)
#define DISPATCH()  \
  pc = next_pc;     \
  insn = next_insn; \
  goto switch_dispatch_continuation
#endif  // V8_USE_COMPUTED_GOTO

// ADVANCE/SET_PC_FROM_OFFSET are separated from DISPATCH, because ideally some
// instructions can be executed between ADVANCE/SET_PC_FROM_OFFSET and DISPATCH.
// We want those two macros as far apart as possible, because the goto in
// DISPATCH is dependent on a memory load in ADVANCE/SET_PC_FROM_OFFSET. If we
// don't hit the cache and have to fetch the next handler address from physical
// memory, instructions between ADVANCE/SET_PC_FROM_OFFSET and DISPATCH can
// potentially be executed unconditionally, reducing memory stall.
#define ADVANCE(name)                             \
  next_pc = pc + RegExpBytecodeLength(BC_##name); \
  DECODE()
#define SET_PC_FROM_OFFSET(offset) \
  next_pc = code_base + offset;    \
  DECODE()

// Current position mutations.
#define SET_CURRENT_POSITION(value)                        \
  do {                                                     \
    current = (value);                                     \
    DCHECK(base::IsInRange(current, 0, subject.length())); \
  } while (false)
#define ADVANCE_CURRENT_POSITION(by) SET_CURRENT_POSITION(current + (by))

#ifdef DEBUG
#define BYTECODE(name)                                                \
  BC_LABEL(name)                                                      \
  MaybeTraceInterpreter(code_base, pc, backtrack_stack.sp(), current, \
                        current_char, RegExpBytecodeLength(BC_##name), #name);
#else
#define BYTECODE(name) BC_LABEL(name)
#endif  // DEBUG

template <typename Char>
IrregexpInterpreter::Result RawMatch(
    Isolate* isolate, Tagged<TrustedByteArray>* code_array,
    Tagged<String>* subject_string, base::Vector<const Char> subject,
    int* output_registers, int output_register_count, int total_register_count,
    int current, uint32_t current_char, RegExp::CallOrigin call_origin,
    const uint32_t backtrack_limit) {
  DisallowGarbageCollection no_gc;

#if V8_USE_COMPUTED_GOTO

// We have to make sure that no OOB access to the dispatch table is possible and
// all values are valid label addresses.
// Otherwise jumps to arbitrary addresses could potentially happen.
// This is ensured as follows:
// Every index to the dispatch table gets masked using BYTECODE_MASK in
// DECODE(). This way we can only get values between 0 (only the least
// significant byte of an integer is used) and kRegExpPaddedBytecodeCount - 1
// (BYTECODE_MASK is defined to be exactly this value).
// All entries from kRegExpBytecodeCount to kRegExpPaddedBytecodeCount have to
// be filled with BREAKs (invalid operation).

// Fill dispatch table from last defined bytecode up to the next power of two
// with BREAK (invalid operation).
// TODO(pthier): Find a way to fill up automatically (at compile time)
// 59 real bytecodes -> 5 fillers
#define BYTECODE_FILLER_ITERATOR(V) \
  V(BREAK) /* 1 */                  \
  V(BREAK) /* 2 */                  \
  V(BREAK) /* 3 */                  \
  V(BREAK) /* 4 */                  \
  V(BREAK) /* 5 */

#define COUNT(...) +1
  static constexpr int kRegExpBytecodeFillerCount =
      BYTECODE_FILLER_ITERATOR(COUNT);
#undef COUNT

  // Make sure kRegExpPaddedBytecodeCount is actually the closest possible power
  // of two.
  DCHECK_EQ(kRegExpPaddedBytecodeCount,
            base::bits::RoundUpToPowerOfTwo32(kRegExpBytecodeCount));

  // Make sure every bytecode we get by using BYTECODE_MASK is well defined.
  static_assert(kRegExpBytecodeCount <= kRegExpPaddedBytecodeCount);
  static_assert(kRegExpBytecodeCount + kRegExpBytecodeFillerCount ==
                kRegExpPaddedBytecodeCount);

#define DECLARE_DISPATCH_TABLE_ENTRY(name, ...) &&BC_##name,
  static const void* const dispatch_table[kRegExpPaddedBytecodeCount] = {
      BYTECODE_ITERATOR(DECLARE_DISPATCH_TABLE_ENTRY)
          BYTECODE_FILLER_ITERATOR(DECLARE_DISPATCH_TABLE_ENTRY)};
#undef DECLARE_DISPATCH_TABLE_ENTRY
#undef BYTECODE_FILLER_ITERATOR

#endif  // V8_USE_COMPUTED_GOTO

  const uint8_t* pc = (*code_array)->begin();
  const uint8_t* code_base = pc;

  InterpreterRegisters registers(total_register_count, output_registers,
                                 output_register_count);
  BacktrackStack backtrack_stack;

  uint32_t backtrack_count = 0;

#ifdef DEBUG
  if (v8_flags.trace_regexp_bytecodes) {
    PrintF("\n\nStart bytecode interpreter\n\n");
  }
#endif

  while (true) {
    const uint8_t* next_pc = pc;
    int32_t insn;
    int32_t next_insn;
#if V8_USE_COMPUTED_GOTO
    const void* next_handler_addr;
    DECODE();
    DISPATCH();
#else
    insn = Load32Aligned(pc);
    switch (insn & BYTECODE_MASK) {
#endif  // V8_USE_COMPUTED_GOTO
    BYTECODE(BREAK) { UNREACHABLE(); }
    BYTECODE(PUSH_CP) {
      ADVANCE(PUSH_CP);
      if (!backtrack_stack.push(current)) {
        return MaybeThrowStackOverflow(isolate, call_origin);
      }
      DISPATCH();
    }
    BYTECODE(PUSH_BT) {
      ADVANCE(PUSH_BT);
      if (!backtrack_stack.push(Load32Aligned(pc + 4))) {
        return MaybeThrowStackOverflow(isolate, call_origin);
      }
      DISPATCH();
    }
    BYTECODE(PUSH_REGISTER) {
      ADVANCE(PUSH_REGISTER);
      if (!backtrack_stack.push(registers[LoadPacked24Unsigned(insn)])) {
        return MaybeThrowStackOverflow(isolate, call_origin);
      }
      DISPATCH();
    }
    BYTECODE(SET_REGISTER) {
      ADVANCE(SET_REGISTER);
      registers[LoadPacked24Unsigned(insn)] = Load32Aligned(pc + 4);
      DISPATCH();
    }
    BYTECODE(ADVANCE_REGISTER) {
      ADVANCE(ADVANCE_REGISTER);
      registers[LoadPacked24Unsigned(insn)] += Load32Aligned(pc + 4);
      DISPATCH();
    }
    BYTECODE(SET_REGISTER_TO_CP) {
      ADVANCE(SET_REGISTER_TO_CP);
      registers[LoadPacked24Unsigned(insn)] = current + Load32Aligned(pc + 4);
      DISPATCH();
    }
    BYTECODE(SET_CP_TO_REGISTER) {
      ADVANCE(SET_CP_TO_REGISTER);
      SET_CURRENT_POSITION(registers[LoadPacked24Unsigned(insn)]);
      DISPATCH();
    }
    BYTECODE(SET_REGISTER_TO_SP) {
      ADVANCE(SET_REGISTER_TO_SP);
      registers[LoadPacked24Unsigned(insn)] = backtrack_stack.sp();
      DISPATCH();
    }
    BYTECODE(SET_SP_TO_REGISTER) {
      ADVANCE(SET_SP_TO_REGISTER);
      backtrack_stack.set_sp(registers[LoadPacked24Unsigned(insn)]);
      DISPATCH();
    }
    BYTECODE(POP_CP) {
      ADVANCE(POP_CP);
      SET_CURRENT_POSITION(backtrack_stack.pop());
      DISPATCH();
    }
    BYTECODE(POP_BT) {
      static_assert(JSRegExp::kNoBacktrackLimit == 0);
      if (++backtrack_count == backtrack_limit) {
        int return_code = LoadPacked24Signed(insn);
        return static_cast<IrregexpInterpreter::Result>(return_code);
      }

      IrregexpInterpreter::Result return_code =
          HandleInterrupts(isolate, call_origin, code_array, subject_string,
                           &code_base, &subject, &pc);
      if (return_code != IrregexpInterpreter::SUCCESS) return return_code;

      SET_PC_FROM_OFFSET(backtrack_stack.pop());
      DISPATCH();
    }
    BYTECODE(POP_REGISTER) {
      ADVANCE(POP_REGISTER);
      registers[LoadPacked24Unsigned(insn)] = backtrack_stack.pop();
      DISPATCH();
    }
    BYTECODE(FAIL) {
      isolate->counters()->regexp_backtracks()->AddSample(
          static_cast<int>(backtrack_count));
      return IrregexpInterpreter::FAILURE;
    }
    BYTECODE(SUCCEED) {
      isolate->counters()->regexp_backtracks()->AddSample(
          static_cast<int>(backtrack_count));
      registers.CopyToOutputRegisters();
      return IrregexpInterpreter::SUCCESS;
    }
    BYTECODE(ADVANCE_CP) {
      ADVANCE(ADVANCE_CP);
      ADVANCE_CURRENT_POSITION(LoadPacked24Signed(insn));
      DISPATCH();
    }
    BYTECODE(GOTO) {
      SET_PC_FROM_OFFSET(Load32Aligned(pc + 4));
      DISPATCH();
    }
    BYTECODE(ADVANCE_CP_AND_GOTO) {
      SET_PC_FROM_OFFSET(Load32Aligned(pc + 4));
      ADVANCE_CURRENT_POSITION(LoadPacked24Signed(insn));
      DISPATCH();
    }
    BYTECODE(CHECK_GREEDY) {
      if (current == backtrack_stack.peek()) {
        SET_PC_FROM_OFFSET(Load32Aligned(pc + 4));
        backtrack_stack.pop();
      } else {
        ADVANCE(CHECK_GREEDY);
      }
      DISPATCH();
    }
    BYTECODE(LOAD_CURRENT_CHAR) {
      int pos = current + LoadPacked24Signed(insn);
      if (pos >= subject.length() || pos < 0) {
        SET_PC_FROM_OFFSET(Load32Aligned(pc + 4));
      } else {
        ADVANCE(LOAD_CURRENT_CHAR);
        current_char = subject[pos];
      }
      DISPATCH();
    }
    BYTECODE(LOAD_CURRENT_CHAR_UNCHECKED) {
      ADVANCE(LOAD_CURRENT_CHAR_UNCHECKED);
      int pos = current + LoadPacked24Signed(insn);
      current_char = subject[pos];
      DISPATCH();
    }
    BYTECODE(LOAD_2_CURRENT_CHARS) {
      int pos = current + LoadPacked24Signed(insn);
      if (pos + 2 > subject.length() || pos < 0) {
        SET_PC_FROM_OFFSET(Load32Aligned(pc + 4));
      } else {
        ADVANCE(LOAD_2_CURRENT_CHARS);
        Char next = subject[pos + 1];
        current_char = (subject[pos] | (next << (kBitsPerByte * sizeof(Char))));
      }
      DISPATCH();
    }
    BYTECODE(LOAD_2_CURRENT_CHARS_UNCHECKED) {
      ADVANCE(LOAD_2_CURRENT_CHARS_UNCHECKED);
      int pos = current + LoadPacked24Signed(insn);
      Char next = subject[pos + 1];
      current_char = (subject[pos] | (next << (kBitsPerByte * sizeof(Char))));
      DISPATCH();
    }
    BYTECODE(LOAD_4_CURRENT_CHARS) {
      DCHECK_EQ(1, sizeof(Char));
      int pos = current + LoadPacked24Signed(insn);
      if (pos + 4 > subject.length() || pos < 0) {
        SET_PC_FROM_OFFSET(Load32Aligned(pc + 4));
      } else {
        ADVANCE(LOAD_4_CURRENT_CHARS);
        Char next1 = subject[pos + 1];
        Char next2 = subject[pos + 2];
        Char next3 = subject[pos + 3];
        current_char =
            (subject[pos] | (next1 << 8) | (next2 << 16) | (next3 << 24));
      }
      DISPATCH();
    }
    BYTECODE(LOAD_4_CURRENT_CHARS_UNCHECKED) {
      ADVANCE(LOAD_4_CURRENT_CHARS_UNCHECKED);
      DCHECK_EQ(1, sizeof(Char));
      int pos = current + LoadPacked24Signed(insn);
      Char next1 = subject[pos + 1];
      Char next2 = subject[pos + 2];
      Char next3 = subject[pos + 3];
      current_char =
          (subject[pos] | (next1 << 8) | (next2 << 16) | (next3 << 24));
      DISPATCH();
    }
    BYTECODE(CHECK_4_CHARS) {
      uint32_t c = Load32Aligned(pc + 4);
      if (c == current_char) {
        SET_PC_FROM_OFFSET(Load32Aligned(pc + 8));
      } else {
        ADVANCE(CHECK_4_CHARS);
      }
      DISPATCH();
    }
    BYTECODE(CHECK_CHAR) {
      uint32_t c = LoadPacked24Unsigned(insn);
      if (c == current_char) {
        SET_PC_FROM_OFFSET(Load32Aligned(pc + 4));
      } else {
        ADVANCE(CHECK_CHAR);
      }
      DISPATCH();
    }
    BYTECODE(CHECK_NOT_4_CHARS) {
      uint32_t c = Load32Aligned(pc + 4);
      if (c != current_char) {
        SET_PC_FROM_OFFSET(Load32Aligned(pc + 8));
      } else {
        ADVANCE(CHECK_NOT_4_CHARS);
      }
      DISPATCH();
    }
    BYTECODE(CHECK_NOT_CHAR) {
      uint32_t c = LoadPacked24Unsigned(insn);
      if (c != current_char) {
        SET_PC_FROM_OFFSET(Load32Aligned(pc + 4));
      } else {
        ADVANCE(CHECK_NOT_CHAR);
      }
      DISPATCH();
    }
    BYTECODE(AND_CHECK_4_CHARS) {
      uint32_t c = Load32Aligned(pc + 4);
      if (c == (current_char & Load32Aligned(pc + 8))) {
        SET_PC_FROM_OFFSET(Load32Aligned(pc + 12));
      } else {
        ADVANCE(AND_CHECK_4_CHARS);
      }
      DISPATCH();
    }
    BYTECODE(AND_CHECK_CHAR) {
      uint32_t c = LoadPacked24Unsigned(insn);
      if (c == (current_char & Load32Aligned(pc + 4))) {
        SET_PC_FROM_OFFSET(Load32Aligned(pc + 8));
      } else {
        ADVANCE(AND_CHECK_CHAR);
      }
      DISPATCH();
    }
    BYTECODE(AND_CHECK_NOT_4_CHARS) {
      uint32_t c = Load32Aligned(pc + 4);
      if (c != (current_char & Load32Aligned(pc + 8))) {
        SET_PC_FROM_OFFSET(Load32Aligned(pc + 12));
      } else {
        ADVANCE(AND_CHECK_NOT_4_CHARS);
      }
      DISPATCH();
    }
    BYTECODE(AND_CHECK_NOT_CHAR) {
      uint32_t c = LoadPacked24Unsigned(insn);
      if (c != (current_char & Load32Aligned(pc + 4))) {
        SET_PC_FROM_OFFSET(Load32Aligned(pc + 8));
      } else {
        ADVANCE(AND_CHECK_NOT_CHAR);
      }
      DISPATCH();
    }
    BYTECODE(MINUS_AND_CHECK_NOT_CHAR) {
      uint32_t c = LoadPacked24Unsigned(insn);
      uint32_t minus = Load16AlignedUnsigned(pc + 4);
      uint32_t mask = Load16AlignedUnsigned(pc + 6);
      if (c != ((current_char - minus) & mask)) {
        SET_PC_FROM_OFFSET(Load32Aligned(pc + 8));
      } else {
        ADVANCE(MINUS_AND_CHECK_NOT_CHAR);
      }
      DISPATCH();
    }
    BYTECODE(CHECK_CHAR_IN_RANGE) {
      uint32_t from = Load16AlignedUnsigned(pc + 4);
      uint32_t to = Load16AlignedUnsigned(pc + 6);
      if (from <= current_char && current_char <= to) {
        SET_PC_FROM_OFFSET(Load32Aligned(pc + 8));
      } else {
        ADVANCE(CHECK_CHAR_IN_RANGE);
      }
      DISPATCH();
    }
    BYTECODE(CHECK_CHAR_NOT_IN_RANGE) {
      uint32_t from = Load16AlignedUnsigned(pc + 4);
      uint32_t to = Load16AlignedUnsigned(pc + 6);
      if (from > current_char || current_char > to) {
        SET_PC_FROM_OFFSET(Load32Aligned(pc + 8));
      } else {
        ADVANCE(CHECK_CHAR_NOT_IN_RANGE);
      }
      DISPATCH();
    }
    BYTECODE(CHECK_BIT_IN_TABLE) {
      if (CheckBitInTable(current_char, pc + 8)) {
        SET_PC_FROM_OFFSET(Load32Aligned(pc + 4));
      } else {
        ADVANCE(CHECK_BIT_IN_TABLE);
      }
      DISPATCH();
    }
    BYTECODE(CHECK_LT) {
      uint32_t limit = LoadPacked24Unsigned(insn);
      if (current_char < limit) {
        SET_PC_FROM_OFFSET(Load32Aligned(pc + 4));
      } else {
        ADVANCE(CHECK_LT);
      }
      DISPATCH();
    }
    BYTECODE(CHECK_GT) {
      uint32_t limit = LoadPacked24Unsigned(insn);
      if (current_char > limit) {
        SET_PC_FROM_OFFSET(Load32Aligned(pc + 4));
      } else {
        ADVANCE(CHECK_GT);
      }
      DISPATCH();
    }
    BYTECODE(CHECK_REGISTER_LT) {
      if (registers[LoadPacked24Unsigned(insn)] < Load32Aligned(pc + 4)) {
        SET_PC_FROM_OFFSET(Load32Aligned(pc + 8));
      } else {
        ADVANCE(CHECK_REGISTER_LT);
      }
      DISPATCH();
    }
    BYTECODE(CHECK_REGISTER_GE) {
      if (registers[LoadPacked24Unsigned(insn)] >= Load32Aligned(pc + 4)) {
        SET_PC_FROM_OFFSET(Load32Aligned(pc + 8));
      } else {
        ADVANCE(CHECK_REGISTER_GE);
      }
      DISPATCH();
    }
    BYTECODE(CHECK_REGISTER_EQ_POS) {
      if (registers[LoadPacked24Unsigned(insn)] == current) {
        SET_PC_FROM_OFFSET(Load32Aligned(pc + 4));
      } else {
        ADVANCE(CHECK_REGISTER_EQ_POS);
      }
      DISPATCH();
    }
    BYTECODE(CHECK_NOT_REGS_EQUAL) {
      if (registers[LoadPacked24Unsigned(insn)] ==
          registers[Load32Aligned(pc + 4)]) {
        ADVANCE(CHECK_NOT_REGS_EQUAL);
      } else {
        SET_PC_FROM_OFFSET(Load32Aligned(pc + 8));
      }
      DISPATCH();
    }
    BYTECODE(CHECK_NOT_BACK_REF) {
      int from = registers[LoadPacked24Unsigned(insn)];
      int len = registers[LoadPacked24Unsigned(insn) + 1] - from;
      if (from >= 0 && len > 0) {
        if (current + len > subject.length() ||
            !CompareCharsEqual(&subject[from], &subject[current], len)) {
          SET_PC_FROM_OFFSET(Load32Aligned(pc + 4));
          DISPATCH();
        }
        ADVANCE_CURRENT_POSITION(len);
      }
      ADVANCE(CHECK_NOT_BACK_REF);
      DISPATCH();
    }
    BYTECODE(CHECK_NOT_BACK_REF_BACKWARD) {
      int from = registers[LoadPacked24Unsigned(insn)];
      int len = registers[LoadPacked24Unsigned(insn) + 1] - from;
      if (from >= 0 && len > 0) {
        if (current - len < 0 ||
            !CompareCharsEqual(&subject[from], &subject[current - len], len)) {
          SET_PC_FROM_OFFSET(Load32Aligned(pc + 4));
          DISPATCH();
        }
        SET_CURRENT_POSITION(current - len);
      }
      ADVANCE(CHECK_NOT_BACK_REF_BACKWARD);
      DISPATCH();
    }
    BYTECODE(CHECK_NOT_BACK_REF_NO_CASE_UNICODE) {
      int from = registers[LoadPacked24Unsigned(insn)];
      int len = registers[LoadPacked24Unsigned(insn) + 1] - from;
      if (from >= 0 && len > 0) {
        if (current + len > subject.length() ||
            !BackRefMatchesNoCase(isolate, from, current, len, subject, true)) {
          SET_PC_FROM_OFFSET(Load32Aligned(pc + 4));
          DISPATCH();
        }
        ADVANCE_CURRENT_POSITION(len);
      }
      ADVANCE(CHECK_NOT_BACK_REF_NO_CASE_UNICODE);
      DISPATCH();
    }
    BYTECODE(CHECK_NOT_BACK_REF_NO_CASE) {
      int from = registers[LoadPacked24Unsigned(insn)];
      int len = registers[LoadPacked24Unsigned(insn) + 1] - from;
      if (from >= 0 && len > 0) {
        if (current + len > subject.length() ||
            !BackRefMatchesNoCase(isolate, from, current, len, subject,
                                  false)) {
          SET_PC_FROM_OFFSET(Load32Aligned(pc + 4));
          DISPATCH();
        }
        ADVANCE_CURRENT_POSITION(len);
      }
      ADVANCE(CHECK_NOT_BACK_REF_NO_CASE);
      DISPATCH();
    }
    BYTECODE(CHECK_NOT_BACK_REF_NO_CASE_UNICODE_BACKWARD) {
      int from = registers[LoadPacked24Unsigned(insn)];
      int len = registers[LoadPacked24Unsigned(insn) + 1] - from;
      if (from >= 0 && len > 0) {
        if (current - len < 0 ||
            !BackRefMatchesNoCase(isolate, from, current - len, len, subject,
                                  true)) {
          SET_PC_FROM_OFFSET(Load32Aligned(pc + 4));
          DISPATCH();
        }
        SET_CURRENT_POSITION(current - len);
      }
      ADVANCE(CHECK_NOT_BACK_REF_NO_CASE_UNICODE_BACKWARD);
      DISPATCH();
    }
    BYTECODE(CHECK_NOT_BACK_REF_NO_CASE_BACKWARD) {
      int from = registers[LoadPacked24Unsigned(insn)];
      int len = registers[LoadPacked24Unsigned(insn) + 1] - from;
      if (from >= 0 && len > 0) {
        if (current - len < 0 ||
            !BackRefMatchesNoCase(isolate, from, current - len, len, subject,
                                  false)) {
          SET_PC_FROM_OFFSET(Load32Aligned(pc + 4));
          DISPATCH();
        }
        SET_CURRENT_POSITION(current - len);
      }
      ADVANCE(CHECK_NOT_BACK_REF_NO_CASE_BACKWARD);
      DISPATCH();
    }
    BYTECODE(CHECK_AT_START) {
      if (current + LoadPacked24Signed(insn) == 0) {
        SET_PC_FROM_OFFSET(Load32Aligned(pc + 4));
      } else {
        ADVANCE(CHECK_AT_START);
      }
      DISPATCH();
    }
    BYTECODE(CHECK_NOT_AT_START) {
      if (current + LoadPacked24Signed(insn) == 0) {
        ADVANCE(CHECK_NOT_AT_START);
      } else {
        SET_PC_FROM_OFFSET(Load32Aligned(pc + 4));
      }
      DISPATCH();
    }
    BYTECODE(SET_CURRENT_POSITION_FROM_END) {
      ADVANCE(SET_CURRENT_POSITION_FROM_END);
      int by = LoadPacked24Unsigned(insn);
      if (subject.length() - current > by) {
        SET_CURRENT_POSITION(subject.length() - by);
        current_char = subject[current - 1];
      }
      DISPATCH();
    }
    BYTECODE(CHECK_CURRENT_POSITION) {
      int pos = current + LoadPacked24Signed(insn);
      if (pos > subject.length() || pos < 0) {
        SET_PC_FROM_OFFSET(Load32Aligned(pc + 4));
      } else {
        ADVANCE(CHECK_CURRENT_POSITION);
      }
      DISPA
```