Response: Let's break down the thought process for analyzing the C++ code and explaining its functionality in relation to JavaScript regular expressions.

1. **Understanding the Goal:** The request asks for a summary of the C++ code's function and how it relates to JavaScript regular expressions, including a JavaScript example. This means we need to bridge the gap between low-level implementation and high-level usage.

2. **Initial Skim and Keyword Spotting:**  A quick glance reveals important terms: "Irregexp," "interpreter," "byte code," "stack," "registers," "match," "unicode," "case-insensitive," "backtracking." These words strongly suggest this code is about executing regular expressions using an interpreted approach. The file path `v8/src/regexp/regexp-interpreter.cc` confirms this is part of the V8 engine, specifically the regular expression component.

3. **Deconstructing the Code - Core Components:**  Start identifying the key classes and functions.

    * **`IrregexpInterpreter`:** This is the main class, likely responsible for orchestrating the interpretation process. The `Match` and `MatchInternal` methods are obvious entry points for performing a regex match.
    * **`RawMatch` (template):** This function seems to be the core loop of the interpreter, handling the actual execution of bytecodes. The template suggests it works with different character types (likely one-byte and two-byte strings).
    * **`BacktrackStack`:**  The name is self-explanatory. Regular expressions often use backtracking, so this stack likely manages the state needed for that.
    * **`InterpreterRegisters`:**  This class probably holds the intermediate results and capture groups during the matching process.
    * **Helper Functions (e.g., `BackRefMatchesNoCase`, `CheckBitInTable`):** These perform specific tasks needed during bytecode execution.
    * **Bytecode Definitions (implicit through `BC_...` macros):** The code heavily uses macros like `BYTECODE(PUSH_CP)`, `BYTECODE(CHECK_CHAR)`, etc. These represent the instructions of the regular expression bytecode.

4. **Tracing the Execution Flow:** Try to follow the logical flow of a match operation.

    * **`Match`:**  This likely takes the compiled regex data, the subject string, and other parameters. It might handle global matches (multiple matches).
    * **`MatchInternal`:** This seems to prepare for the actual interpretation, handling string encoding (one-byte vs. two-byte) and calling `RawMatch`.
    * **`RawMatch`:**  This is the heart of the interpreter. It fetches bytecodes, uses a dispatch mechanism (either computed goto or a switch), and executes the corresponding actions. The `backtrack_stack` is used for managing backtracking points. `InterpreterRegisters` stores intermediate results.

5. **Connecting to JavaScript:** Consider how these internal mechanisms relate to JavaScript's `RegExp` object and its methods (`test`, `exec`, `match`, `search`, `replace`).

    * When a JavaScript regex method is called, V8 compiles the regular expression into bytecode.
    * This `regexp-interpreter.cc` file contains the code that *interprets* this bytecode. This is one way V8 can execute regular expressions (the other being using a dedicated machine code generator).
    * The capture groups in JavaScript (`(...)`) correspond to the registers managed by `InterpreterRegisters`.
    * The `g` flag (global match) in JavaScript relates to the loop in `IrregexpInterpreter::Match` that allows for multiple matches.
    * Case-insensitive matching (`/i` flag) likely uses the `BackRefMatchesNoCase` functions.

6. **Formulating the Explanation:**  Structure the explanation logically.

    * Start with a high-level summary of the file's purpose.
    * Explain the core components (interpreter, bytecode, stack, registers).
    * Describe the interpretation process (fetching bytecodes, dispatching, executing actions).
    * Explicitly connect the C++ code to JavaScript features (regex object, flags, capture groups).

7. **Creating the JavaScript Example:**  Choose a simple JavaScript regex that demonstrates the concepts.

    * Include a pattern with a capture group.
    * Use the `exec` method to get detailed match information, including capture groups.
    * Explain how the C++ code's registers would store the start and end indices of the match and the capture group.

8. **Refinement and Clarity:** Review the explanation for accuracy and clarity. Use precise language and avoid jargon where possible. Ensure the JavaScript example clearly illustrates the connection to the C++ code. For example, explicitly mentioning how the capture group in the JavaScript example relates to the registers in the C++ code is crucial. Also, highlight the role of the bytecode.

By following these steps, we can systematically analyze the C++ code and produce a comprehensive explanation that effectively links the low-level implementation to the user-facing JavaScript regular expression features.
这个C++源代码文件 `v8/src/regexp/regexp-interpreter.cc` 是 **V8 JavaScript 引擎中用于解释执行正则表达式字节码的解释器实现**。

**功能归纳:**

1. **解释执行字节码:**  该文件实现了 `IrregexpInterpreter` 类，负责读取和执行由正则表达式编译器生成的特定字节码指令。这些字节码描述了正则表达式的匹配逻辑。
2. **状态管理:** 解释器维护执行状态，包括：
    * **当前匹配位置 (current):**  在输入字符串中正在匹配的位置。
    * **当前字符 (current_char):** 当前位置的字符或字符组合。
    * **回溯栈 (backtrack_stack):** 用于支持正则表达式的回溯机制，存储程序计数器 (PC) 和寄存器值等信息，以便在匹配失败时回溯到之前的状态。
    * **寄存器 (registers):**  存储匹配结果（捕获组的起始和结束位置）和临时状态。
3. **处理各种字节码指令:** `RawMatch` 函数是解释器的核心循环，它根据当前指令执行相应的操作，例如：
    * **字符匹配:** 检查当前字符是否与模式中的字符匹配。
    * **控制流:** 跳转到不同的代码位置 (GOTO)，条件跳转 (CHECK_CHAR, CHECK_REGISTER_LT 等)。
    * **栈操作:** 推入和弹出回溯信息 (PUSH_CP, POP_BT)。
    * **寄存器操作:** 设置、读取和修改寄存器的值 (SET_REGISTER, ADVANCE_REGISTER)。
    * **断言:** 检查匹配位置是否在字符串的开头或结尾 (CHECK_AT_START)。
    * **反向引用:** 检查之前捕获的组是否与当前位置的字符串匹配 (CHECK_NOT_BACK_REF)。
4. **处理 Unicode 和大小写不敏感匹配:**  代码中包含了处理 Unicode 字符和进行大小写不敏感比较的逻辑 (`BackRefMatchesNoCase`)。
5. **性能优化:**  代码中使用了编译时计算的 `goto` 语句 (如果编译器支持) 来提高指令分发的效率。
6. **集成到 V8 引擎:**  该解释器是 V8 引擎正则表达式功能的一部分，与正则表达式的编译和执行流程紧密结合。

**与 JavaScript 功能的关系及 JavaScript 举例:**

该文件直接支持 JavaScript 中正则表达式的执行。当你在 JavaScript 中使用 `RegExp` 对象进行匹配操作时，V8 引擎可能会选择使用这个解释器来执行正则表达式的匹配逻辑。

**JavaScript 例子:**

```javascript
const regex = /a(b*)c/i; // 定义一个正则表达式，包含一个捕获组 (b*)，并使用 i 标志表示大小写不敏感
const text = "ABBC";

const match = regex.exec(text);

if (match) {
  console.log("匹配结果:", match[0]);   // 输出: "ABBC" (完整匹配)
  console.log("第一个捕获组:", match[1]); // 输出: "BB"  (捕获组 (b*) 的内容)
  console.log("匹配开始位置:", match.index); // 输出: 0
  console.log("输入字符串:", match.input); // 输出: "ABBC"
}
```

**C++ 代码中的对应关系 (简化说明):**

* **`const regex = /a(b*)c/i;`**:  V8 引擎会将这个正则表达式编译成一系列的字节码指令。例如，可能会有指令来：
    * 匹配字符 'a' (大小写不敏感)。
    * 进入一个循环，匹配零个或多个 'b' 字符，并将匹配到的 'b' 存储到某个寄存器（对应捕获组）。
    * 匹配字符 'c' (大小写不敏感)。
* **`const text = "ABBC";`**: 这是解释器要处理的输入字符串。
* **`regex.exec(text);`**:  这个 JavaScript 方法调用会触发 V8 引擎的正则表达式匹配流程，其中可能就会用到 `regexp-interpreter.cc` 中的 `IrregexpInterpreter::Match` 或 `IrregexpInterpreter::MatchInternal` 函数。
* **`match[0]` (完整匹配):**  对应于解释器执行成功后，存储在输出寄存器中的整体匹配的起始和结束位置。
* **`match[1]` (第一个捕获组):** 对应于解释器在执行匹配捕获组的字节码指令时，将匹配到的子字符串的起始和结束位置存储到特定的寄存器中。
* **大小写不敏感 ( `/i` 标志):** 会影响解释器中字符匹配指令的行为，可能会调用 `BackRefMatchesNoCase` 等函数进行比较。
* **回溯 (例如，如果模式更复杂，比如 `/a.*bc/`):**  当匹配失败时，解释器会使用 `backtrack_stack` 中保存的信息，回退到之前的状态，尝试其他的匹配路径。

**总结:**

`regexp-interpreter.cc` 文件是 V8 引擎中至关重要的组件，它实现了正则表达式的解释器，使得 JavaScript 能够执行强大的文本模式匹配功能。它通过解释执行预编译的字节码，管理匹配状态，处理各种正则表达式语法和标志，最终得出匹配结果。

### 提示词
```
这是目录为v8/src/regexp/regexp-interpreter.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
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
      DISPATCH();
    }
    BYTECODE(SKIP_UNTIL_CHAR) {
      int32_t load_offset = LoadPacked24Signed(insn);
      int32_t advance = Load16AlignedSigned(pc + 4);
      uint32_t c = Load16AlignedUnsigned(pc + 6);
      while (IndexIsInBounds(current + load_offset, subject.length())) {
        current_char = subject[current + load_offset];
        if (c == current_char) {
          SET_PC_FROM_OFFSET(Load32Aligned(pc + 8));
          DISPATCH();
        }
        ADVANCE_CURRENT_POSITION(advance);
      }
      SET_PC_FROM_OFFSET(Load32Aligned(pc + 12));
      DISPATCH();
    }
    BYTECODE(SKIP_UNTIL_CHAR_AND) {
      int32_t load_offset = LoadPacked24Signed(insn);
      int32_t advance = Load16AlignedSigned(pc + 4);
      uint16_t c = Load16AlignedUnsigned(pc + 6);
      uint32_t mask = Load32Aligned(pc + 8);
      int32_t maximum_offset = Load32Aligned(pc + 12);
      while (static_cast<uintptr_t>(current + maximum_offset) <=
             static_cast<uintptr_t>(subject.length())) {
        current_char = subject[current + load_offset];
        if (c == (current_char & mask)) {
          SET_PC_FROM_OFFSET(Load32Aligned(pc + 16));
          DISPATCH();
        }
        ADVANCE_CURRENT_POSITION(advance);
      }
      SET_PC_FROM_OFFSET(Load32Aligned(pc + 20));
      DISPATCH();
    }
    BYTECODE(SKIP_UNTIL_CHAR_POS_CHECKED) {
      int32_t load_offset = LoadPacked24Signed(insn);
      int32_t advance = Load16AlignedSigned(pc + 4);
      uint16_t c = Load16AlignedUnsigned(pc + 6);
      int32_t maximum_offset = Load32Aligned(pc + 8);
      while (static_cast<uintptr_t>(current + maximum_offset) <=
             static_cast<uintptr_t>(subject.length())) {
        current_char = subject[current + load_offset];
        if (c == current_char) {
          SET_PC_FROM_OFFSET(Load32Aligned(pc + 12));
          DISPATCH();
        }
        ADVANCE_CURRENT_POSITION(advance);
      }
      SET_PC_FROM_OFFSET(Load32Aligned(pc + 16));
      DISPATCH();
    }
    BYTECODE(SKIP_UNTIL_BIT_IN_TABLE) {
      int32_t load_offset = LoadPacked24Signed(insn);
      int32_t advance = Load32Aligned(pc + 4);
      const uint8_t* table = pc + 8;
      while (IndexIsInBounds(current + load_offset, subject.length())) {
        current_char = subject[current + load_offset];
        if (CheckBitInTable(current_char, table)) {
          SET_PC_FROM_OFFSET(Load32Aligned(pc + 24));
          DISPATCH();
        }
        ADVANCE_CURRENT_POSITION(advance);
      }
      SET_PC_FROM_OFFSET(Load32Aligned(pc + 28));
      DISPATCH();
    }
    BYTECODE(SKIP_UNTIL_GT_OR_NOT_BIT_IN_TABLE) {
      int32_t load_offset = LoadPacked24Signed(insn);
      int32_t advance = Load16AlignedSigned(pc + 4);
      uint16_t limit = Load16AlignedUnsigned(pc + 6);
      const uint8_t* table = pc + 8;
      while (IndexIsInBounds(current + load_offset, subject.length())) {
        current_char = subject[current + load_offset];
        if (current_char > limit) {
          SET_PC_FROM_OFFSET(Load32Aligned(pc + 24));
          DISPATCH();
        }
        if (!CheckBitInTable(current_char, table)) {
          SET_PC_FROM_OFFSET(Load32Aligned(pc + 24));
          DISPATCH();
        }
        ADVANCE_CURRENT_POSITION(advance);
      }
      SET_PC_FROM_OFFSET(Load32Aligned(pc + 28));
      DISPATCH();
    }
    BYTECODE(SKIP_UNTIL_CHAR_OR_CHAR) {
      int32_t load_offset = LoadPacked24Signed(insn);
      int32_t advance = Load32Aligned(pc + 4);
      uint16_t c = Load16AlignedUnsigned(pc + 8);
      uint16_t c2 = Load16AlignedUnsigned(pc + 10);
      while (IndexIsInBounds(current + load_offset, subject.length())) {
        current_char = subject[current + load_offset];
        // The two if-statements below are split up intentionally, as combining
        // them seems to result in register allocation behaving quite
        // differently and slowing down the resulting code.
        if (c == current_char) {
          SET_PC_FROM_OFFSET(Load32Aligned(pc + 12));
          DISPATCH();
        }
        if (c2 == current_char) {
          SET_PC_FROM_OFFSET(Load32Aligned(pc + 12));
          DISPATCH();
        }
        ADVANCE_CURRENT_POSITION(advance);
      }
      SET_PC_FROM_OFFSET(Load32Aligned(pc + 16));
      DISPATCH();
    }
#if V8_USE_COMPUTED_GOTO
// Lint gets confused a lot if we just use !V8_USE_COMPUTED_GOTO or ifndef
// V8_USE_COMPUTED_GOTO here.
#else
      default:
        UNREACHABLE();
    }
  // Label we jump to in DISPATCH(). There must be no instructions between the
  // end of the switch, this label and the end of the loop.
  switch_dispatch_continuation : {}
#endif  // V8_USE_COMPUTED_GOTO
  }
}

#undef BYTECODE
#undef ADVANCE_CURRENT_POSITION
#undef SET_CURRENT_POSITION
#undef DISPATCH
#undef DECODE
#undef SET_PC_FROM_OFFSET
#undef ADVANCE
#undef BC_LABEL
#undef V8_USE_COMPUTED_GOTO

}  // namespace

// static
int IrregexpInterpreter::Match(Isolate* isolate,
                               Tagged<IrRegExpData> regexp_data,
                               Tagged<String> subject_string,
                               int* output_registers, int output_register_count,
                               int start_position,
                               RegExp::CallOrigin call_origin) {
  if (v8_flags.regexp_tier_up) regexp_data->TierUpTick();

  bool is_any_unicode =
      IsEitherUnicode(JSRegExp::AsRegExpFlags(regexp_data->flags()));
  bool is_one_byte = subject_string->IsOneByteRepresentation();
  Tagged<TrustedByteArray> code_array = regexp_data->bytecode(is_one_byte);
  int total_register_count = regexp_data->max_register_count();

  // MatchInternal only supports returning a single match per call. In global
  // mode, i.e. when output_registers has space for more than one match, we
  // need to keep running until all matches are filled in.
  int registers_per_match =
      JSRegExp::RegistersForCaptureCount(regexp_data->capture_count());
  DCHECK_LE(registers_per_match, output_register_count);
  int number_of_matches_in_output_registers =
      output_register_count / registers_per_match;

  int backtrack_limit = regexp_data->backtrack_limit();

  int num_matches = 0;
  int* current_output_registers = output_registers;
  for (int i = 0; i < number_of_matches_in_output_registers; i++) {
    auto current_result = MatchInternal(
        isolate, &code_array, &subject_string, current_output_registers,
        registers_per_match, total_register_count, start_position, call_origin,
        backtrack_limit);

    if (current_result == SUCCESS) {
      // Fall through.
    } else if (current_result == FAILURE) {
      break;
    } else {
      DCHECK(current_result == EXCEPTION ||
             current_result == FALLBACK_TO_EXPERIMENTAL ||
             current_result == RETRY);
      return current_result;
    }

    // Found a match. Advance the index.

    num_matches++;

    int next_start_position = current_output_registers[1];
    if (next_start_position == current_output_registers[0]) {
      // Zero-length matches.
      // TODO(jgruber): Use AdvanceStringIndex based on flat contents instead.
      next_start_position = static_cast<int>(RegExpUtils::AdvanceStringIndex(
          subject_string, next_start_position, is_any_unicode));
      if (next_start_position > static_cast<int>(subject_string->length())) {
        break;
      }
    }

    start_position = next_start_position;
    current_output_registers += registers_per_match;
  }

  return num_matches;
}

IrregexpInterpreter::Result IrregexpInterpreter::MatchInternal(
    Isolate* isolate, Tagged<TrustedByteArray>* code_array,
    Tagged<String>* subject_string, int* output_registers,
    int output_register_count, int total_register_count, int start_position,
    RegExp::CallOrigin call_origin, uint32_t backtrack_limit) {
  DCHECK((*subject_string)->IsFlat());

  // Note: Heap allocation *is* allowed in two situations if calling from
  // Runtime:
  // 1. When creating & throwing a stack overflow exception. The interpreter
  //    aborts afterwards, and thus possible-moved objects are never used.
  // 2. When handling interrupts. We manually relocate unhandlified references
  //    after interrupts have run.
  DisallowGarbageCollection no_gc;

  base::uc16 previous_char = '\n';
  String::FlatContent subject_content =
      (*subject_string)->GetFlatContent(no_gc);
  // Because interrupts can result in GC and string content relocation, the
  // checksum verification in FlatContent may fail even though this code is
  // safe. See (2) above.
  subject_content.UnsafeDisableChecksumVerification();
  if (subject_content.IsOneByte()) {
    base::Vector<const uint8_t> subject_vector =
        subject_content.ToOneByteVector();
    if (start_position != 0) previous_char = subject_vector[start_position - 1];
    return RawMatch(isolate, code_array, subject_string, subject_vector,
                    output_registers, output_register_count,
                    total_register_count, start_position, previous_char,
                    call_origin, backtrack_limit);
  } else {
    DCHECK(subject_content.IsTwoByte());
    base::Vector<const base::uc16> subject_vector =
        subject_content.ToUC16Vector();
    if (start_position != 0) previous_char = subject_vector[start_position - 1];
    return RawMatch(isolate, code_array, subject_string, subject_vector,
                    output_registers, output_register_count,
                    total_register_count, start_position, previous_char,
                    call_origin, backtrack_limit);
  }
}

#ifndef COMPILING_IRREGEXP_FOR_EXTERNAL_EMBEDDER

// This method is called through an external reference from RegExpExecInternal
// builtin.
int IrregexpInterpreter::MatchForCallFromJs(
    Address subject, int32_t start_position, Address, Address,
    int* output_registers, int32_t output_register_count,
    RegExp::CallOrigin call_origin, Isolate* isolate, Address regexp_data) {
  DCHECK_NOT_NULL(isolate);
  DCHECK_NOT_NULL(output_registers);
  DCHECK(call_origin == RegExp::CallOrigin::kFromJs);

  DisallowGarbageCollection no_gc;
  DisallowJavascriptExecution no_js(isolate);
  DisallowHandleAllocation no_handles;
  DisallowHandleDereference no_deref;

  Tagged<String> subject_string = Cast<String>(Tagged<Object>(subject));
  Tagged<IrRegExpData> regexp_data_obj =
      Cast<IrRegExpData>(Tagged<Object>(regexp_data));

  if (regexp_data_obj->MarkedForTierUp()) {
    // Returning RETRY will re-enter through runtime, where actual recompilation
    // for tier-up takes place.
    return IrregexpInterpreter::RETRY;
  }

  return Match(isolate, regexp_data_obj, subject_string, output_registers,
               output_register_count, start_position, call_origin);
}

#endif  // !COMPILING_IRREGEXP_FOR_EXTERNAL_EMBEDDER

int IrregexpInterpreter::MatchForCallFromRuntime(
    Isolate* isolate, DirectHandle<IrRegExpData> regexp_data,
    DirectHandle<String> subject_string, int* output_registers,
    int output_register_count, int start_position) {
  return Match(isolate, *regexp_data, *subject_string, output_registers,
               output_register_count, start_position,
               RegExp::CallOrigin::kFromRuntime);
}

}  // namespace internal
}  // namespace v8
```