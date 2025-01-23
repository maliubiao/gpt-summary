Response:
Let's break down the request and figure out how to generate the response.

**1. Understanding the Core Request:**

The user wants to understand the functionality of the `regexp-macro-assembler.h` header file in the V8 JavaScript engine. This involves:

* **General Functionality:** What is the purpose of this file?
* **Torque Check:**  Is it a Torque file? (Answer: No, it's a `.h` file)
* **JavaScript Relationship:** How does it relate to JavaScript's regular expressions?
* **Code Logic:** Can we provide examples of its methods in action (input/output)?
* **Common Errors:** Are there common mistakes related to its usage (from a *user* perspective, though this file isn't directly used by users)?

**2. Initial Analysis of the Header File:**

The file defines a class `RegExpMacroAssembler` and a subclass `NativeRegExpMacroAssembler`. The name "macro assembler" strongly suggests it's responsible for generating low-level code (likely machine code or bytecode) for regular expression matching. The presence of methods like `Bind`, `GoTo`, `CheckCharacter`, `AdvanceCurrentPosition`, `PushBacktrack`, etc., reinforces this idea – these are reminiscent of assembly language instructions.

**3. Addressing Each Point in the Request:**

* **Functionality:** The main goal is to abstract away the platform-specific details of code generation for regular expressions. It provides a common interface for different architectures. This will be the central point of the "功能" section.

* **Torque Check:**  The file ends in `.h`, so it's not a Torque file. This is a straightforward check.

* **JavaScript Relationship:** This is crucial. JavaScript's `RegExp` object is the user-facing interface. This header file is *under the hood*, responsible for efficiently executing those regular expressions. I need to illustrate this connection clearly. A JavaScript example demonstrating a regular expression and mentioning that V8 uses this type of assembler internally will be effective.

* **Code Logic and Input/Output:** This is tricky because users don't directly interact with `RegExpMacroAssembler`. The "input" here is the state of the matching process (current position, register values, backtrack stack), and the "output" is the change in that state or a decision (match/no match, backtrack). I'll need to choose a simple method and illustrate its effect. `CheckCharacter` seems like a good candidate. I can posit a current character and the `on_equal` label and describe the flow.

* **Common Errors:**  Again, direct user errors are unlikely since users don't use this class directly. The common errors are more about *inefficient regular expressions* that could lead to excessive backtracking, which this class attempts to manage (through the backtrack limit). I'll frame the errors in terms of inefficient regex patterns.

**4. Structuring the Response:**

I'll follow the user's request format:

* **功能 (Functionality):** Explain the role of `RegExpMacroAssembler` in generating code for regex execution.
* **Torque Check:**  State that it's not a Torque file.
* **JavaScript 关系 (Relationship):** Explain how this relates to the JavaScript `RegExp` object and provide a simple JavaScript example.
* **代码逻辑推理 (Code Logic):** Pick a method (`CheckCharacter`), provide a hypothetical scenario (input), and describe the expected outcome (output).
* **用户常见的编程错误 (Common Errors):** Discuss common pitfalls in writing regular expressions that can lead to performance issues, relating it to the backtracking mechanism within the assembler.

**5. Pre-computation/Pre-analysis for Code Logic Example:**

For the `CheckCharacter` example:

* **Assumption:** Current character is 'a'.
* **Input to `CheckCharacter`:**  `c = 'a'`, `on_equal` is a valid label.
* **Output:** Execution jumps to `on_equal`.
* **Alternative Input:** Current character is 'b'.
* **Output:** Execution continues to the next instruction (doesn't jump).

**6. Pre-computation/Pre-analysis for Common Errors:**

Think about regex patterns known for causing backtracking issues:

* Nested quantifiers like `(a+)+`.
* Alternations with significant overlap, like `a|ab|abc`.

**7. Final Review and Refinement:**

Before generating the final response, I'll review my plan to ensure it's accurate, addresses all parts of the request, and is presented clearly and logically. I'll use clear, concise language and avoid overly technical jargon where possible. I'll emphasize the connection between this internal class and the user-facing JavaScript `RegExp` object.
好的，让我们来分析一下 `v8/src/regexp/regexp-macro-assembler.h` 这个 V8 源代码文件。

**功能列举:**

`v8/src/regexp/regexp-macro-assembler.h` 是 V8 引擎中用于生成正则表达式匹配代码的核心抽象类。它的主要功能是：

1. **提供一个与架构无关的接口:**  它定义了一组抽象方法，用于执行正则表达式匹配所需的各种操作，例如：
    * 加载字符 (`LoadCurrentCharacter`)
    * 比较字符 (`CheckCharacter`, `CheckCharacterInRange`)
    * 跳转和标签 (`Bind`, `GoTo`)
    * 回溯 (`Backtrack`, `PushBacktrack`)
    * 寄存器操作 (`AdvanceRegister`, `SetRegister`)
    * 栈操作 (`PushCurrentPosition`, `PopCurrentPosition`)
    * 边界检查 (`CheckAtStart`, `CheckPosition`)
    * 调用运行时函数 (例如，用于不区分大小写的比较 `CaseInsensitiveCompareNonUnicode`)
    * 失败和成功状态 (`Fail`, `Succeed`)

2. **封装了不同架构的细节:**  V8 支持多种处理器架构（如 IA32, ARM, X64 等）。`RegExpMacroAssembler` 的具体实现子类（例如 `IA32RegExpMacroAssembler`, `X64RegExpMacroAssembler`）会根据目标架构生成相应的机器码或汇编指令。这使得正则表达式的编译过程可以在不同平台上保持一致，而底层实现可以针对特定架构进行优化。

3. **管理正则表达式匹配的状态:**  它使用寄存器和栈来维护正则表达式匹配过程中的状态，例如：
    * 当前匹配位置 (`cp_offset`)
    * 捕获组的值
    * 回溯点

4. **处理各种正则表达式特性:**  它提供了支持各种正则表达式特性的操作，包括字符匹配、字符类、量词、分组、断言等。

5. **支持全局匹配和 Unicode:**  它提供了处理全局匹配（`global` 标志）和 Unicode 字符的支持。

6. **提供性能优化机制:**  例如，通过 `CheckBitInTable` 可以利用预先计算的字符集查找表进行快速匹配。

7. **控制回溯限制:**  通过 `set_backtrack_limit` 可以设置回溯次数的限制，防止因复杂的正则表达式导致无限循环。

**是否为 Torque 源代码:**

`v8/src/regexp/regexp-macro-assembler.h` 以 `.h` 结尾，这是一个 C++ 头文件，不是以 `.tq` 结尾的 V8 Torque 源代码。Torque 用于定义 V8 的内置函数和类型系统，而这个文件更多的是关于运行时代码生成的抽象接口。

**与 Javascript 的功能关系 (举例说明):**

`RegExpMacroAssembler` 直接服务于 JavaScript 的 `RegExp` 对象。当你在 JavaScript 中创建一个正则表达式并执行匹配操作时，V8 引擎会：

1. **解析正则表达式:** 将正则表达式的字符串表示解析成抽象语法树 (AST)。
2. **编译正则表达式:**  `RegExpMacroAssembler` 的具体子类会遍历 AST，并生成用于执行匹配的机器码或字节码。这个过程会将高层的正则表达式操作（例如，匹配一个字符类）转换成底层的机器指令。
3. **执行匹配:** 生成的代码会在输入字符串上执行匹配操作，并返回匹配结果。

**JavaScript 示例:**

```javascript
const regex = /ab+c/g;
const text = "abbc abbbbc";
let match;

while ((match = regex.exec(text)) !== null) {
  console.log(`Found ${match[0]} at index ${match.index}.`);
}
```

在这个例子中，当你执行 `regex.exec(text)` 时，V8 内部会使用 `RegExpMacroAssembler` 生成的代码来高效地查找 `text` 中与正则表达式 `/ab+c/g` 匹配的子字符串。

**代码逻辑推理 (假设输入与输出):**

假设我们正在处理正则表达式 `/a/` 并调用了 `CheckCharacter` 方法。

**假设输入:**

* 当前要检查的字符是 `'a'`。
* 调用 `CheckCharacter('a', on_equal_label)`，其中 `on_equal_label` 是一个预定义的标签。

**输出:**

* 如果当前字符确实是 `'a'`，则生成的代码会跳转到 `on_equal_label` 处继续执行。
* 如果当前字符不是 `'a'`，则生成的代码会继续执行 `CheckCharacter` 调用后的下一条指令（通常是回溯或尝试其他匹配路径）。

**用户常见的编程错误 (举例说明):**

虽然用户不直接使用 `RegExpMacroAssembler`，但用户编写的正则表达式的效率会直接影响到 V8 内部 `RegExpMacroAssembler` 生成代码的性能。常见的编程错误包括：

1. **过度回溯:**  编写导致大量回溯的正则表达式会导致性能急剧下降。例如：

   ```javascript
   const regex = /a*b*c*/; // 对于输入 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac" 会产生大量回溯
   const text = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac";
   regex.test(text);
   ```
   在这个例子中，`a*`, `b*`, `c*` 都是贪婪匹配，当 `text` 中没有 `b` 时，`a*` 会匹配所有 `a`，然后 `b*` 尝试匹配，失败后 `a*` 会回溯，导致大量不必要的尝试。

2. **使用复杂的、没有明确锚定的模式进行全局搜索:**

   ```javascript
   const regex = /.*?pattern.*?/g; // 效率可能不高
   const text = "long string with multiple occurrences of pattern";
   text.match(regex);
   ```
   非贪婪匹配 `.*?` 在全局搜索中可能会导致性能问题，因为它会在每次匹配后都尝试匹配尽可能少的字符。

3. **在循环中使用字面量正则表达式:**

   ```javascript
   const strings = ["abc", "def", "ghi"];
   for (const str of strings) {
     if (/a/.test(str)) { // 每次循环都会重新编译正则表达式
       console.log(str);
     }
   }
   ```
   应该将正则表达式定义在循环外部以避免重复编译：

   ```javascript
   const regex = /a/;
   const strings = ["abc", "def", "ghi"];
   for (const str of strings) {
     if (regex.test(str)) {
       console.log(str);
     }
   }
   ```

4. **滥用捕获组:**  过多的捕获组会增加内存消耗和执行时间。如果不需要捕获匹配的子字符串，应该使用非捕获组 `(?:...)`。

**总结:**

`v8/src/regexp/regexp-macro-assembler.h` 是 V8 引擎中一个关键的底层组件，它负责将正则表达式的抽象表示转化为可以在特定硬件上执行的低级代码。理解它的功能有助于我们更好地理解 JavaScript 正则表达式的执行机制以及如何编写更高效的正则表达式。虽然开发者不直接与这个头文件交互，但它背后的原理影响着我们编写的 JavaScript 代码的性能。

### 提示词
```
这是目录为v8/src/regexp/regexp-macro-assembler.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/regexp/regexp-macro-assembler.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_REGEXP_REGEXP_MACRO_ASSEMBLER_H_
#define V8_REGEXP_REGEXP_MACRO_ASSEMBLER_H_

#include "src/base/strings.h"
#include "src/execution/frame-constants.h"
#include "src/objects/fixed-array.h"
#include "src/regexp/regexp-ast.h"
#include "src/regexp/regexp.h"

namespace v8 {
namespace internal {

class ByteArray;
class JSRegExp;
class Label;
class String;

static const base::uc32 kLeadSurrogateStart = 0xd800;
static const base::uc32 kLeadSurrogateEnd = 0xdbff;
static const base::uc32 kTrailSurrogateStart = 0xdc00;
static const base::uc32 kTrailSurrogateEnd = 0xdfff;
static const base::uc32 kNonBmpStart = 0x10000;
static const base::uc32 kNonBmpEnd = 0x10ffff;

class RegExpMacroAssembler {
 public:
  // The implementation must be able to handle at least:
  static constexpr int kMaxRegisterCount = (1 << 16);
  static constexpr int kMaxRegister = kMaxRegisterCount - 1;
  static constexpr int kMaxCaptures = (kMaxRegister - 1) / 2;
  static constexpr int kMaxCPOffset = (1 << 15) - 1;
  static constexpr int kMinCPOffset = -(1 << 15);

  static constexpr int kTableSizeBits = 7;
  static constexpr int kTableSize = 1 << kTableSizeBits;
  static constexpr int kTableMask = kTableSize - 1;

  static constexpr int kUseCharactersValue = -1;

  RegExpMacroAssembler(Isolate* isolate, Zone* zone);
  virtual ~RegExpMacroAssembler() = default;

  virtual Handle<HeapObject> GetCode(Handle<String> source,
                                     RegExpFlags flags) = 0;

  // This function is called when code generation is aborted, so that
  // the assembler could clean up internal data structures.
  virtual void AbortedCodeGeneration() {}
  // The maximal number of pushes between stack checks. Users must supply
  // kCheckStackLimit flag to push operations (instead of kNoStackLimitCheck)
  // at least once for every stack_limit() pushes that are executed.
  virtual int stack_limit_slack_slot_count() = 0;
  virtual bool CanReadUnaligned() const = 0;

  virtual void AdvanceCurrentPosition(int by) = 0;  // Signed cp change.
  virtual void AdvanceRegister(int reg, int by) = 0;  // r[reg] += by.
  // Continues execution from the position pushed on the top of the backtrack
  // stack by an earlier PushBacktrack(Label*).
  virtual void Backtrack() = 0;
  virtual void Bind(Label* label) = 0;
  // Dispatch after looking the current character up in a 2-bits-per-entry
  // map.  The destinations vector has up to 4 labels.
  virtual void CheckCharacter(unsigned c, Label* on_equal) = 0;
  // Bitwise and the current character with the given constant and then
  // check for a match with c.
  virtual void CheckCharacterAfterAnd(unsigned c,
                                      unsigned and_with,
                                      Label* on_equal) = 0;
  virtual void CheckCharacterGT(base::uc16 limit, Label* on_greater) = 0;
  virtual void CheckCharacterLT(base::uc16 limit, Label* on_less) = 0;
  virtual void CheckGreedyLoop(Label* on_tos_equals_current_position) = 0;
  virtual void CheckAtStart(int cp_offset, Label* on_at_start) = 0;
  virtual void CheckNotAtStart(int cp_offset, Label* on_not_at_start) = 0;
  virtual void CheckNotBackReference(int start_reg, bool read_backward,
                                     Label* on_no_match) = 0;
  virtual void CheckNotBackReferenceIgnoreCase(int start_reg,
                                               bool read_backward, bool unicode,
                                               Label* on_no_match) = 0;
  // Check the current character for a match with a literal character.  If we
  // fail to match then goto the on_failure label.  End of input always
  // matches.  If the label is nullptr then we should pop a backtrack address
  // off the stack and go to that.
  virtual void CheckNotCharacter(unsigned c, Label* on_not_equal) = 0;
  virtual void CheckNotCharacterAfterAnd(unsigned c,
                                         unsigned and_with,
                                         Label* on_not_equal) = 0;
  // Subtract a constant from the current character, then and with the given
  // constant and then check for a match with c.
  virtual void CheckNotCharacterAfterMinusAnd(base::uc16 c, base::uc16 minus,
                                              base::uc16 and_with,
                                              Label* on_not_equal) = 0;
  virtual void CheckCharacterInRange(base::uc16 from,
                                     base::uc16 to,  // Both inclusive.
                                     Label* on_in_range) = 0;
  virtual void CheckCharacterNotInRange(base::uc16 from,
                                        base::uc16 to,  // Both inclusive.
                                        Label* on_not_in_range) = 0;
  // Returns true if the check was emitted, false otherwise.
  virtual bool CheckCharacterInRangeArray(
      const ZoneList<CharacterRange>* ranges, Label* on_in_range) = 0;
  virtual bool CheckCharacterNotInRangeArray(
      const ZoneList<CharacterRange>* ranges, Label* on_not_in_range) = 0;

  // The current character (modulus the kTableSize) is looked up in the byte
  // array, and if the found byte is non-zero, we jump to the on_bit_set label.
  virtual void CheckBitInTable(Handle<ByteArray> table, Label* on_bit_set) = 0;

  virtual void SkipUntilBitInTable(int cp_offset, Handle<ByteArray> table,
                                   Handle<ByteArray> nibble_table,
                                   int advance_by) = 0;
  virtual bool SkipUntilBitInTableUseSimd(int advance_by) { return false; }

  // Checks whether the given offset from the current position is before
  // the end of the string.  May overwrite the current character.
  virtual void CheckPosition(int cp_offset, Label* on_outside_input);
  // Check whether a standard/default character class matches the current
  // character. Returns false if the type of special character class does
  // not have custom support.
  // May clobber the current loaded character.
  virtual bool CheckSpecialClassRanges(StandardCharacterSet type,
                                       Label* on_no_match) {
    return false;
  }

  // Control-flow integrity:
  // Define a jump target and bind a label.
  virtual void BindJumpTarget(Label* label) { Bind(label); }

  virtual void Fail() = 0;
  virtual void GoTo(Label* label) = 0;
  // Check whether a register is >= a given constant and go to a label if it
  // is.  Backtracks instead if the label is nullptr.
  virtual void IfRegisterGE(int reg, int comparand, Label* if_ge) = 0;
  // Check whether a register is < a given constant and go to a label if it is.
  // Backtracks instead if the label is nullptr.
  virtual void IfRegisterLT(int reg, int comparand, Label* if_lt) = 0;
  // Check whether a register is == to the current position and go to a
  // label if it is.
  virtual void IfRegisterEqPos(int reg, Label* if_eq) = 0;
  V8_EXPORT_PRIVATE void LoadCurrentCharacter(
      int cp_offset, Label* on_end_of_input, bool check_bounds = true,
      int characters = 1, int eats_at_least = kUseCharactersValue);
  virtual void LoadCurrentCharacterImpl(int cp_offset, Label* on_end_of_input,
                                        bool check_bounds, int characters,
                                        int eats_at_least) = 0;
  virtual void PopCurrentPosition() = 0;
  virtual void PopRegister(int register_index) = 0;
  // Pushes the label on the backtrack stack, so that a following Backtrack
  // will go to this label. Always checks the backtrack stack limit.
  virtual void PushBacktrack(Label* label) = 0;
  virtual void PushCurrentPosition() = 0;
  enum StackCheckFlag { kNoStackLimitCheck = false, kCheckStackLimit = true };
  virtual void PushRegister(int register_index,
                            StackCheckFlag check_stack_limit) = 0;
  virtual void ReadCurrentPositionFromRegister(int reg) = 0;
  virtual void ReadStackPointerFromRegister(int reg) = 0;
  virtual void SetCurrentPositionFromEnd(int by) = 0;
  virtual void SetRegister(int register_index, int to) = 0;
  // Return whether the matching (with a global regexp) will be restarted.
  virtual bool Succeed() = 0;
  virtual void WriteCurrentPositionToRegister(int reg, int cp_offset) = 0;
  virtual void ClearRegisters(int reg_from, int reg_to) = 0;
  virtual void WriteStackPointerToRegister(int reg) = 0;

  // Check that we are not in the middle of a surrogate pair.
  void CheckNotInSurrogatePair(int cp_offset, Label* on_failure);

#define IMPLEMENTATIONS_LIST(V) \
  V(IA32)                       \
  V(ARM)                        \
  V(ARM64)                      \
  V(MIPS)                       \
  V(LOONG64)                    \
  V(RISCV)                      \
  V(RISCV32)                    \
  V(S390)                       \
  V(PPC)                        \
  V(X64)                        \
  V(Bytecode)

  enum IrregexpImplementation {
#define V(Name) k##Name##Implementation,
    IMPLEMENTATIONS_LIST(V)
#undef V
  };

  inline const char* ImplementationToString(IrregexpImplementation impl) {
    static const char* const kNames[] = {
#define V(Name) #Name,
        IMPLEMENTATIONS_LIST(V)
#undef V
    };
    return kNames[impl];
  }
#undef IMPLEMENTATIONS_LIST
  virtual IrregexpImplementation Implementation() = 0;

  // Compare two-byte strings case insensitively.
  //
  // Called from generated code.
  static int CaseInsensitiveCompareNonUnicode(Address byte_offset1,
                                              Address byte_offset2,
                                              size_t byte_length,
                                              Isolate* isolate);
  static int CaseInsensitiveCompareUnicode(Address byte_offset1,
                                           Address byte_offset2,
                                           size_t byte_length,
                                           Isolate* isolate);

  // `raw_byte_array` is a ByteArray containing a set of character ranges,
  // where ranges are encoded as uint16_t elements:
  //
  //  [from0, to0, from1, to1, ..., fromN, toN], or
  //  [from0, to0, from1, to1, ..., fromN]  (open-ended last interval).
  //
  // fromN is inclusive, toN is exclusive. Returns zero if not in a range,
  // non-zero otherwise.
  //
  // Called from generated code.
  static uint32_t IsCharacterInRangeArray(uint32_t current_char,
                                          Address raw_byte_array);

  // Controls the generation of large inlined constants in the code.
  void set_slow_safe(bool ssc) { slow_safe_compiler_ = ssc; }
  bool slow_safe() const { return slow_safe_compiler_; }

  // Controls after how many backtracks irregexp should abort execution.  If it
  // can fall back to the experimental engine (see `set_can_fallback`), it will
  // return the appropriate error code, otherwise it will return the number of
  // matches found so far (perhaps none).
  void set_backtrack_limit(uint32_t backtrack_limit) {
    backtrack_limit_ = backtrack_limit;
  }

  // Set whether or not irregexp can fall back to the experimental engine on
  // excessive backtracking.  The number of backtracks considered excessive can
  // be controlled with set_backtrack_limit.
  void set_can_fallback(bool val) { can_fallback_ = val; }

  enum GlobalMode {
    NOT_GLOBAL,
    GLOBAL_NO_ZERO_LENGTH_CHECK,
    GLOBAL,
    GLOBAL_UNICODE
  };
  // Set whether the regular expression has the global flag.  Exiting due to
  // a failure in a global regexp may still mean success overall.
  inline void set_global_mode(GlobalMode mode) { global_mode_ = mode; }
  inline bool global() const { return global_mode_ != NOT_GLOBAL; }
  inline bool global_with_zero_length_check() const {
    return global_mode_ == GLOBAL || global_mode_ == GLOBAL_UNICODE;
  }
  inline bool global_unicode() const { return global_mode_ == GLOBAL_UNICODE; }

  Isolate* isolate() const { return isolate_; }
  Zone* zone() const { return zone_; }

 protected:
  bool has_backtrack_limit() const;
  uint32_t backtrack_limit() const { return backtrack_limit_; }

  bool can_fallback() const { return can_fallback_; }

 private:
  bool slow_safe_compiler_;
  uint32_t backtrack_limit_;
  bool can_fallback_ = false;
  GlobalMode global_mode_;
  Isolate* const isolate_;
  Zone* const zone_;
};

class NativeRegExpMacroAssembler: public RegExpMacroAssembler {
 public:
  // Type of input string to generate code for.
  enum Mode { LATIN1 = 1, UC16 = 2 };

  // Result of calling generated native RegExp code.
  // RETRY: Something significant changed during execution, and the matching
  //        should be retried from scratch.
  // EXCEPTION: Something failed during execution. If no exception has been
  //            thrown, it's an internal out-of-memory, and the caller should
  //            throw the exception.
  // FAILURE: Matching failed.
  // SUCCESS: Matching succeeded, and the output array has been filled with
  //          capture positions.
  // FALLBACK_TO_EXPERIMENTAL: Execute the regexp on this subject using the
  //                           experimental engine instead.
  enum Result {
    FAILURE = RegExp::kInternalRegExpFailure,
    SUCCESS = RegExp::kInternalRegExpSuccess,
    EXCEPTION = RegExp::kInternalRegExpException,
    RETRY = RegExp::kInternalRegExpRetry,
    FALLBACK_TO_EXPERIMENTAL = RegExp::kInternalRegExpFallbackToExperimental,
    SMALLEST_REGEXP_RESULT = RegExp::kInternalRegExpSmallestResult,
  };

  NativeRegExpMacroAssembler(Isolate* isolate, Zone* zone)
      : RegExpMacroAssembler(isolate, zone), range_array_cache_(zone) {}
  ~NativeRegExpMacroAssembler() override = default;

  // Returns a {Result} sentinel, or the number of successful matches.
  static int Match(DirectHandle<IrRegExpData> regexp_data,
                   DirectHandle<String> subject, int* offsets_vector,
                   int offsets_vector_length, int previous_index,
                   Isolate* isolate);

  V8_EXPORT_PRIVATE static int ExecuteForTesting(
      Tagged<String> input, int start_offset, const uint8_t* input_start,
      const uint8_t* input_end, int* output, int output_size, Isolate* isolate,
      Tagged<JSRegExp> regexp);

  bool CanReadUnaligned() const override;

  void LoadCurrentCharacterImpl(int cp_offset, Label* on_end_of_input,
                                bool check_bounds, int characters,
                                int eats_at_least) override;
  // Load a number of characters at the given offset from the
  // current position, into the current-character register.
  virtual void LoadCurrentCharacterUnchecked(int cp_offset,
                                             int character_count) = 0;

  // Called from RegExp if the backtrack stack limit is hit. Tries to expand
  // the stack. Returns the new stack-pointer if successful, or returns 0 if
  // unable to grow the stack.
  // This function must not trigger a garbage collection.
  //
  // Called from generated code.
  static Address GrowStack(Isolate* isolate);

  // Called from generated code.
  static int CheckStackGuardState(Isolate* isolate, int start_index,
                                  RegExp::CallOrigin call_origin,
                                  Address* return_address,
                                  Tagged<InstructionStream> re_code,
                                  Address* subject, const uint8_t** input_start,
                                  const uint8_t** input_end, uintptr_t gap);

  static Address word_character_map_address() {
    return reinterpret_cast<Address>(&word_character_map[0]);
  }

 protected:
  // Byte map of one byte characters with a 0xff if the character is a word
  // character (digit, letter or underscore) and 0x00 otherwise.
  // Used by generated RegExp code.
  static const uint8_t word_character_map[256];

  Handle<ByteArray> GetOrAddRangeArray(const ZoneList<CharacterRange>* ranges);

 private:
  // Returns a {Result} sentinel, or the number of successful matches.
  static int Execute(Tagged<String> input, int start_offset,
                     const uint8_t* input_start, const uint8_t* input_end,
                     int* output, int output_size, Isolate* isolate,
                     Tagged<IrRegExpData> regexp_data);

  ZoneUnorderedMap<uint32_t, IndirectHandle<FixedUInt16Array>>
      range_array_cache_;
};

}  // namespace internal
}  // namespace v8

#endif  // V8_REGEXP_REGEXP_MACRO_ASSEMBLER_H_
```