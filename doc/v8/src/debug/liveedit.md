Response: Let's break down the thought process for analyzing this C++ code.

1. **Understand the Goal:** The request is to summarize the functionality of the `liveedit.cc` file and explain its relationship to JavaScript with examples. This means focusing on what the code *does* and how it connects to the user-facing language.

2. **Initial Scan for Keywords and Namespaces:**  A quick skim reveals the namespace `v8::internal::debug::LiveEdit`. This immediately tells us it's part of V8's internal debugging functionality, specifically for "Live Edit."  Keywords like `Comparator`, `String`, `Script`, `FunctionLiteral`, `SharedFunctionInfo`, `BytecodeArray`, `SourceChangeRange`, `ParseInfo`, and functions like `PatchScript`, `CompareStrings`, and `TranslatePosition` jump out.

3. **Identify Core Functionality Blocks:**  Based on the keywords, I can start grouping related code sections.

    * **String Comparison (`CompareStrings` and related classes):**  The code defines classes like `TokensCompareInput`, `TokensCompareOutput`, `LineArrayCompareInput`, `TokenizingLineArrayCompareOutput`. These strongly suggest functionality for comparing two versions of a string (likely the old and new source code). The `Comparator::CalculateDifference` call confirms this.

    * **Function Literal Tracking and Mapping (`CalculateFunctionLiteralChanges`, `MapLiterals`):**  Structures like `FunctionLiteralChange` and the use of `FunctionLiteral*` point to tracking changes within functions. The `MapLiterals` function name directly suggests mapping old function definitions to new ones.

    * **Code Patching (`PatchScript`):** This is the main entry point. It orchestrates the comparison, identifies changes, and updates the internal V8 structures. The presence of `SharedFunctionInfo`, `BytecodeArray`, and the logic for updating these suggests the core mechanism for applying live edits.

    * **Position Translation (`TranslatePosition`):**  The name is self-explanatory. This is crucial for adjusting source code positions after changes have been made.

    * **Auxiliary Structures and Helpers:** Classes like `LineEndsWrapper` and the various `Input` and `Output` classes for the comparator are supporting structures. `FunctionDataMap` hints at tracking function instances and their states.

4. **Deep Dive into Key Functions:**

    * **`PatchScript`:** This is the heart of the operation. I need to understand its steps:
        * **String comparison:** Uses `CompareStrings` to find differences.
        * **Parsing:** Parses both old and new scripts to get ASTs and function literals.
        * **Function literal change calculation:**  Determines how function definitions have changed.
        * **Mapping literals:** Matches old function literals to new ones.
        * **Checking patching feasibility (`CanPatchScript`):**  Ensures the live edit is allowed (e.g., no active functions on the stack blocking the change).
        * **Applying changes:** Updates `SharedFunctionInfo`, bytecode, and other internal structures.

    * **`CompareStrings`:** Focus on the line-based and token-based comparison, noting the nested approach.

    * **`TranslatePosition`:** Understand how it uses the `SourceChangeRange` to adjust positions.

5. **Connecting to JavaScript:** Now, think about *how* this internal C++ code impacts JavaScript developers.

    * **Core concept:** Live Edit is about making code changes without restarting the application. This directly benefits the development workflow.
    * **Mechanism:**  V8 is the JavaScript engine. This C++ code is *part* of V8 and enables this feature.
    * **Examples:** Construct scenarios where live edit is useful:
        * Changing a function's logic.
        * Modifying variable values.
        * Adding or removing code.
    * **Limitations:**  Live edit isn't magic. There are limitations (like changes affecting function signatures or significant structural changes) that might prevent it or require a restart. The code itself hints at some of these limitations (e.g., checking for active functions on the stack).

6. **Structuring the Summary:** Organize the findings into a coherent explanation.

    * Start with a high-level overview of the file's purpose.
    * Break down the core functionalities into logical sections.
    * Explain the relationship to JavaScript clearly.
    * Provide illustrative JavaScript examples.
    * Mention limitations and considerations.

7. **Refine and Iterate:** Review the summary for clarity, accuracy, and completeness. Ensure the JavaScript examples are correct and effectively illustrate the concepts. For example, initially, I might have just said "compares strings."  Refining it involves mentioning the line-by-line and token-by-token comparison for more detail. Similarly, initially, I might have missed the nuances of *why* certain edits are blocked, but the code about checking the stack helps to clarify this.

8. **Consider the Audience:**  The request doesn't specify a technical level, but aiming for a reasonably technical explanation that balances detail with clarity is generally a good approach. Avoid overly jargon-heavy language where possible, but don't oversimplify technical concepts. Explaining concepts like `SharedFunctionInfo` briefly adds value.

By following these steps, combining code analysis with an understanding of the feature's purpose and user impact, the detailed summary and relevant JavaScript examples can be generated.
这个C++源代码文件 `liveedit.cc` 实现了 V8 JavaScript 引擎的**热重载 (LiveEdit)** 功能。它的主要目标是在 JavaScript 代码运行时，允许开发者修改代码并立即看到效果，而无需完全重启程序或刷新页面。

**核心功能归纳:**

1. **比较代码差异 (Compare Strings):**
   - 使用 `Comparator` 类及其相关的 `Input` 和 `Output` 类来比较旧版本和新版本的 JavaScript 代码字符串。
   - 提供了基于行和基于 Token (目前是字符级别) 的两种比较方式，以更精细地找出代码的差异。
   - `NarrowDownInput` 函数优化比较过程，忽略前后相同的代码部分。
   - 比较结果以 `SourceChangeRange` 的形式存储，记录了旧代码和新代码中发生变化的起始和结束位置。

2. **映射和更新 Function Literal (函数字面量):**
   - `CalculateFunctionLiteralChanges` 函数分析代码差异对函数字面量的影响，计算出每个函数字面量在新代码中的起始和结束位置。
   - `MapLiterals` 函数将旧代码中的函数字面量映射到新代码中的函数字面量。它会考虑函数的内容和外部作用域是否发生变化。如果函数字面量的内容或其外部作用域发生了变化，则认为该函数字面量被修改或损坏。
   - 涉及到 `FunctionLiteral` 结构体和 `FunctionLiteralChanges` 以及 `LiteralMap` 等数据结构来管理和跟踪函数字面量的变化。

3. **更新 SharedFunctionInfo (共享函数信息):**
   - `PatchScript` 函数是热重载的核心入口。
   - 它会解析新旧版本的代码，获取抽象语法树 (AST) 和函数字面量。
   - 对于没有变化的函数，会更新其 `SharedFunctionInfo` 中的源码位置信息，使其指向新代码中的对应位置。
   - 对于发生变化的函数，会更新其 `SharedFunctionInfo`，并可能需要重新编译该函数。

4. **处理代码位置映射 (Translate Position):**
   - `TranslatePosition` 函数根据代码差异，将旧代码中的位置映射到新代码中的位置。这对于更新堆栈信息、断点位置等非常重要。

5. **管理函数实例 (Function Data Map):**
   - `FunctionDataMap` 类用于跟踪正在运行的函数实例 (JSFunction) 和生成器对象 (JSGeneratorObject)。
   - 在热重载过程中，需要考虑哪些函数正在栈上运行，以避免在运行时修改这些函数。

6. **判断是否可以进行热重载 (CanPatchScript):**
   -  在进行热重载之前，会检查一些条件，例如：
     -  修改的函数是否正在栈上运行。
     -  是否存在正在运行的生成器对象。
     -  是否修改了顶层 ES 模块。
   -  如果存在这些情况，热重载可能会被阻止。

7. **更新字节码 (Bytecode):**
   - `TranslateSourcePositionTable` 函数用于更新字节码中的源码位置表，使其与新的代码位置对应。

**与 JavaScript 的关系 (以及 JavaScript 示例):**

`liveedit.cc` 是 V8 引擎内部实现热重载功能的关键部分。开发者在浏览器开发者工具或 Node.js 的调试器中修改 JavaScript 代码时，V8 引擎会使用 `liveedit.cc` 中的逻辑来比较代码差异、更新内部数据结构，从而实现代码的动态更新。

**JavaScript 示例:**

假设有以下 JavaScript 代码：

```javascript
let counter = 0;

function increment() {
  counter++;
  console.log("Counter:", counter);
}

setInterval(increment, 1000);
```

1. **初始状态:**  V8 引擎加载并执行这段代码，`increment` 函数被 `setInterval` 定期调用，并在控制台输出计数器值。

2. **修改代码:** 开发者在不停止程序的情况下，将 `increment` 函数修改为：

```javascript
let counter = 0;

function increment() {
  counter += 2; // 修改了递增的步长
  console.log("New Counter:", counter); // 修改了输出的文本
}

setInterval(increment, 1000);
```

3. **热重载过程 (`liveedit.cc` 的作用):**
   - `CompareStrings` 会比较旧版本和新版本的 `increment` 函数的代码字符串，找出差异 (例如 `"counter++"` 变为 `"counter += 2"`，`"Counter:"` 变为 `"New Counter:"`)。
   - `CalculateFunctionLiteralChanges` 和 `MapLiterals` 会识别出 `increment` 函数字面量发生了变化。
   - `PatchScript` 会更新与 `increment` 函数相关的 `SharedFunctionInfo`。由于函数体发生了变化，V8 可能会重新编译 `increment` 函数。
   - 如果 `increment` 函数当前不在调用栈上 (即当前没有正在执行 `increment` 函数)，V8 就可以安全地替换旧版本的函数。
   - 下一次 `setInterval` 调用 `increment` 时，将会执行新版本的函数，开发者会在控制台上看到输出 "New Counter:" 和递增的步长变为 2。

**更复杂的例子，展示函数映射:**

```javascript
function outer() {
  let message = "Hello";
  function inner() {
    console.log(message);
  }
  return inner;
}

const myInner = outer();
myInner(); // 输出 "Hello"
```

假设我们修改了 `outer` 函数，但 `inner` 函数的代码没有变化：

```javascript
function outer() {
  let greeting = "Hi"; // 变量名修改
  function inner() {
    console.log(greeting); // 内部引用也需要更新
  }
  return inner;
}

const myInner = outer();
myInner(); // 希望能输出 "Hi"
```

在这种情况下，`liveedit.cc` 的功能会确保：

- `CompareStrings` 会识别出 `outer` 函数的变化。
- `MapLiterals` 会尝试将旧的 `inner` 函数字面量映射到新的 `inner` 函数字面量 (因为代码内容没有变化)。
- `PatchScript` 会更新 `outer` 函数的 `SharedFunctionInfo`。
- 关键的是，即使 `inner` 函数的代码没变，但由于它引用了 `outer` 函数作用域中的变量 `message`，而该变量被重命名为 `greeting`，V8 需要确保旧的 `myInner` 函数实例能够访问到新的 `greeting` 变量。  `liveedit.cc` 中的逻辑需要处理这种作用域变化的情况，或者在无法安全处理时，可能需要重新执行 `outer` 函数。

**总结:**

`liveedit.cc` 是 V8 引擎实现 JavaScript 热重载的核心 C++ 代码。它通过比较代码差异、映射和更新函数信息、处理代码位置映射等一系列操作，使得开发者能够在不中断程序运行的情况下修改代码并立即生效，极大地提高了开发效率。它与 JavaScript 的关系是底层实现与上层语言特性的关系，JavaScript 的热重载功能依赖于 `liveedit.cc` 中复杂的 C++ 逻辑。

Prompt: 
```
这是目录为v8/src/debug/liveedit.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/debug/liveedit.h"

#include <optional>

#include "src/api/api-inl.h"
#include "src/ast/ast-traversal-visitor.h"
#include "src/ast/ast.h"
#include "src/ast/scopes.h"
#include "src/codegen/compilation-cache.h"
#include "src/codegen/compiler.h"
#include "src/codegen/source-position-table.h"
#include "src/common/globals.h"
#include "src/debug/debug-interface.h"
#include "src/debug/debug-stack-trace-iterator.h"
#include "src/debug/debug.h"
#include "src/debug/liveedit-diff.h"
#include "src/execution/frames-inl.h"
#include "src/execution/v8threads.h"
#include "src/logging/log.h"
#include "src/objects/js-generator-inl.h"
#include "src/objects/js-objects.h"
#include "src/objects/objects-inl.h"
#include "src/parsing/parse-info.h"
#include "src/parsing/parsing.h"

namespace v8 {
namespace internal {
namespace {

bool CompareSubstrings(DirectHandle<String> s1, int pos1,
                       DirectHandle<String> s2, int pos2, int len) {
  for (int i = 0; i < len; i++) {
    if (s1->Get(i + pos1) != s2->Get(i + pos2)) return false;
  }
  return true;
}

// Additional to Input interface. Lets switch Input range to subrange.
// More elegant way would be to wrap one Input as another Input object
// and translate positions there, but that would cost us additional virtual
// call per comparison.
class SubrangableInput : public Comparator::Input {
 public:
  virtual void SetSubrange1(int offset, int len) = 0;
  virtual void SetSubrange2(int offset, int len) = 0;
};


class SubrangableOutput : public Comparator::Output {
 public:
  virtual void SetSubrange1(int offset, int len) = 0;
  virtual void SetSubrange2(int offset, int len) = 0;
};

// Finds common prefix and suffix in input. This parts shouldn't take space in
// linear programming table. Enable subranging in input and output.
void NarrowDownInput(SubrangableInput* input, SubrangableOutput* output) {
  const int len1 = input->GetLength1();
  const int len2 = input->GetLength2();

  int common_prefix_len;
  int common_suffix_len;

  {
    common_prefix_len = 0;
    int prefix_limit = std::min(len1, len2);
    while (common_prefix_len < prefix_limit &&
        input->Equals(common_prefix_len, common_prefix_len)) {
      common_prefix_len++;
    }

    common_suffix_len = 0;
    int suffix_limit =
        std::min(len1 - common_prefix_len, len2 - common_prefix_len);

    while (common_suffix_len < suffix_limit &&
        input->Equals(len1 - common_suffix_len - 1,
        len2 - common_suffix_len - 1)) {
      common_suffix_len++;
    }
  }

  if (common_prefix_len > 0 || common_suffix_len > 0) {
    int new_len1 = len1 - common_suffix_len - common_prefix_len;
    int new_len2 = len2 - common_suffix_len - common_prefix_len;

    input->SetSubrange1(common_prefix_len, new_len1);
    input->SetSubrange2(common_prefix_len, new_len2);

    output->SetSubrange1(common_prefix_len, new_len1);
    output->SetSubrange2(common_prefix_len, new_len2);
  }
}

// Represents 2 strings as 2 arrays of tokens.
// TODO(LiveEdit): Currently it's actually an array of charactres.
//     Make array of tokens instead.
class TokensCompareInput : public Comparator::Input {
 public:
  TokensCompareInput(Handle<String> s1, int offset1, int len1,
                       Handle<String> s2, int offset2, int len2)
      : s1_(s1), offset1_(offset1), len1_(len1),
        s2_(s2), offset2_(offset2), len2_(len2) {
  }
  int GetLength1() override { return len1_; }
  int GetLength2() override { return len2_; }
  bool Equals(int index1, int index2) override {
    return s1_->Get(offset1_ + index1) == s2_->Get(offset2_ + index2);
  }

 private:
  Handle<String> s1_;
  int offset1_;
  int len1_;
  Handle<String> s2_;
  int offset2_;
  int len2_;
};

// Stores compare result in std::vector. Converts substring positions
// to absolute positions.
class TokensCompareOutput : public Comparator::Output {
 public:
  TokensCompareOutput(int offset1, int offset2,
                      std::vector<SourceChangeRange>* output)
      : output_(output), offset1_(offset1), offset2_(offset2) {}

  void AddChunk(int pos1, int pos2, int len1, int len2) override {
    output_->emplace_back(
        SourceChangeRange{pos1 + offset1_, pos1 + len1 + offset1_,
                          pos2 + offset2_, pos2 + offset2_ + len2});
  }

 private:
  std::vector<SourceChangeRange>* output_;
  int offset1_;
  int offset2_;
};

// Wraps raw n-elements line_ends array as a list of n+1 lines. The last line
// never has terminating new line character.
class LineEndsWrapper {
 public:
  explicit LineEndsWrapper(Isolate* isolate, Handle<String> string)
      : ends_array_(String::CalculateLineEnds(isolate, string, false)),
        string_len_(string->length()) {}
  int length() {
    return ends_array_->length() + 1;
  }
  // Returns start for any line including start of the imaginary line after
  // the last line.
  int GetLineStart(int index) { return index == 0 ? 0 : GetLineEnd(index - 1); }
  int GetLineEnd(int index) {
    if (index == ends_array_->length()) {
      // End of the last line is always an end of the whole string.
      // If the string ends with a new line character, the last line is an
      // empty string after this character.
      return string_len_;
    } else {
      return GetPosAfterNewLine(index);
    }
  }

 private:
  Handle<FixedArray> ends_array_;
  int string_len_;

  int GetPosAfterNewLine(int index) {
    return Smi::ToInt(ends_array_->get(index)) + 1;
  }
};

// Represents 2 strings as 2 arrays of lines.
class LineArrayCompareInput : public SubrangableInput {
 public:
  LineArrayCompareInput(Handle<String> s1, Handle<String> s2,
                        LineEndsWrapper line_ends1, LineEndsWrapper line_ends2)
      : s1_(s1), s2_(s2), line_ends1_(line_ends1),
        line_ends2_(line_ends2),
        subrange_offset1_(0), subrange_offset2_(0),
        subrange_len1_(line_ends1_.length()),
        subrange_len2_(line_ends2_.length()) {
  }
  int GetLength1() override { return subrange_len1_; }
  int GetLength2() override { return subrange_len2_; }
  bool Equals(int index1, int index2) override {
    index1 += subrange_offset1_;
    index2 += subrange_offset2_;

    int line_start1 = line_ends1_.GetLineStart(index1);
    int line_start2 = line_ends2_.GetLineStart(index2);
    int line_end1 = line_ends1_.GetLineEnd(index1);
    int line_end2 = line_ends2_.GetLineEnd(index2);
    int len1 = line_end1 - line_start1;
    int len2 = line_end2 - line_start2;
    if (len1 != len2) {
      return false;
    }
    return CompareSubstrings(s1_, line_start1, s2_, line_start2,
                             len1);
  }
  void SetSubrange1(int offset, int len) override {
    subrange_offset1_ = offset;
    subrange_len1_ = len;
  }
  void SetSubrange2(int offset, int len) override {
    subrange_offset2_ = offset;
    subrange_len2_ = len;
  }

 private:
  Handle<String> s1_;
  Handle<String> s2_;
  LineEndsWrapper line_ends1_;
  LineEndsWrapper line_ends2_;
  int subrange_offset1_;
  int subrange_offset2_;
  int subrange_len1_;
  int subrange_len2_;
};

// Stores compare result in std::vector. For each chunk tries to conduct
// a fine-grained nested diff token-wise.
class TokenizingLineArrayCompareOutput : public SubrangableOutput {
 public:
  TokenizingLineArrayCompareOutput(Isolate* isolate, LineEndsWrapper line_ends1,
                                   LineEndsWrapper line_ends2,
                                   Handle<String> s1, Handle<String> s2,
                                   std::vector<SourceChangeRange>* output)
      : isolate_(isolate),
        line_ends1_(line_ends1),
        line_ends2_(line_ends2),
        s1_(s1),
        s2_(s2),
        subrange_offset1_(0),
        subrange_offset2_(0),
        output_(output) {}

  void AddChunk(int line_pos1, int line_pos2, int line_len1,
                int line_len2) override {
    line_pos1 += subrange_offset1_;
    line_pos2 += subrange_offset2_;

    int char_pos1 = line_ends1_.GetLineStart(line_pos1);
    int char_pos2 = line_ends2_.GetLineStart(line_pos2);
    int char_len1 = line_ends1_.GetLineStart(line_pos1 + line_len1) - char_pos1;
    int char_len2 = line_ends2_.GetLineStart(line_pos2 + line_len2) - char_pos2;

    if (char_len1 < CHUNK_LEN_LIMIT && char_len2 < CHUNK_LEN_LIMIT) {
      // Chunk is small enough to conduct a nested token-level diff.
      HandleScope subTaskScope(isolate_);

      TokensCompareInput tokens_input(s1_, char_pos1, char_len1,
                                      s2_, char_pos2, char_len2);
      TokensCompareOutput tokens_output(char_pos1, char_pos2, output_);

      Comparator::CalculateDifference(&tokens_input, &tokens_output);
    } else {
      output_->emplace_back(SourceChangeRange{
          char_pos1, char_pos1 + char_len1, char_pos2, char_pos2 + char_len2});
    }
  }
  void SetSubrange1(int offset, int len) override {
    subrange_offset1_ = offset;
  }
  void SetSubrange2(int offset, int len) override {
    subrange_offset2_ = offset;
  }

 private:
  static const int CHUNK_LEN_LIMIT = 800;

  Isolate* isolate_;
  LineEndsWrapper line_ends1_;
  LineEndsWrapper line_ends2_;
  Handle<String> s1_;
  Handle<String> s2_;
  int subrange_offset1_;
  int subrange_offset2_;
  std::vector<SourceChangeRange>* output_;
};

struct SourcePositionEvent {
  enum Type { LITERAL_STARTS, LITERAL_ENDS, DIFF_STARTS, DIFF_ENDS };

  int position;
  Type type;

  union {
    FunctionLiteral* literal;
    int pos_diff;
  };

  SourcePositionEvent(FunctionLiteral* literal, bool is_start)
      : position(is_start ? literal->start_position()
                          : literal->end_position()),
        type(is_start ? LITERAL_STARTS : LITERAL_ENDS),
        literal(literal) {}
  SourcePositionEvent(const SourceChangeRange& change, bool is_start)
      : position(is_start ? change.start_position : change.end_position),
        type(is_start ? DIFF_STARTS : DIFF_ENDS),
        pos_diff((change.new_end_position - change.new_start_position) -
                 (change.end_position - change.start_position)) {}

  static bool LessThan(const SourcePositionEvent& a,
                       const SourcePositionEvent& b) {
    if (a.position != b.position) return a.position < b.position;
    if (a.type != b.type) return a.type < b.type;
    if (a.type == LITERAL_STARTS && b.type == LITERAL_STARTS) {
      // If the literals start in the same position, we want the one with the
      // furthest (i.e. largest) end position to be first.
      if (a.literal->end_position() != b.literal->end_position()) {
        return a.literal->end_position() > b.literal->end_position();
      }
      // If they also end in the same position, we want the first in order of
      // literal ids to be first.
      return a.literal->function_literal_id() <
             b.literal->function_literal_id();
    } else if (a.type == LITERAL_ENDS && b.type == LITERAL_ENDS) {
      // If the literals end in the same position, we want the one with the
      // nearest (i.e. largest) start position to be first.
      if (a.literal->start_position() != b.literal->start_position()) {
        return a.literal->start_position() > b.literal->start_position();
      }
      // If they also end in the same position, we want the last in order of
      // literal ids to be first.
      return a.literal->function_literal_id() >
             b.literal->function_literal_id();
    } else {
      return a.pos_diff < b.pos_diff;
    }
  }
};

struct FunctionLiteralChange {
  // If any of start/end position is kNoSourcePosition, this literal is
  // considered damaged and will not be mapped and edited at all.
  int new_start_position;
  int new_end_position;
  bool has_changes;
  FunctionLiteral* outer_literal;

  explicit FunctionLiteralChange(int new_start_position, FunctionLiteral* outer)
      : new_start_position(new_start_position),
        new_end_position(kNoSourcePosition),
        has_changes(false),
        outer_literal(outer) {}
};

using FunctionLiteralChanges =
    std::unordered_map<FunctionLiteral*, FunctionLiteralChange>;
void CalculateFunctionLiteralChanges(
    const std::vector<FunctionLiteral*>& literals,
    const std::vector<SourceChangeRange>& diffs,
    FunctionLiteralChanges* result) {
  std::vector<SourcePositionEvent> events;
  events.reserve(literals.size() * 2 + diffs.size() * 2);
  for (FunctionLiteral* literal : literals) {
    events.emplace_back(literal, true);
    events.emplace_back(literal, false);
  }
  for (const SourceChangeRange& diff : diffs) {
    events.emplace_back(diff, true);
    events.emplace_back(diff, false);
  }
  std::sort(events.begin(), events.end(), SourcePositionEvent::LessThan);
  bool inside_diff = false;
  int delta = 0;
  std::stack<std::pair<FunctionLiteral*, FunctionLiteralChange>> literal_stack;
  for (const SourcePositionEvent& event : events) {
    switch (event.type) {
      case SourcePositionEvent::DIFF_ENDS:
        DCHECK(inside_diff);
        inside_diff = false;
        delta += event.pos_diff;
        break;
      case SourcePositionEvent::LITERAL_ENDS: {
        DCHECK_EQ(literal_stack.top().first, event.literal);
        FunctionLiteralChange& change = literal_stack.top().second;
        change.new_end_position = inside_diff
                                      ? kNoSourcePosition
                                      : event.literal->end_position() + delta;
        result->insert(literal_stack.top());
        literal_stack.pop();
        break;
      }
      case SourcePositionEvent::LITERAL_STARTS:
        literal_stack.push(std::make_pair(
            event.literal,
            FunctionLiteralChange(
                inside_diff ? kNoSourcePosition
                            : event.literal->start_position() + delta,
                literal_stack.empty() ? nullptr : literal_stack.top().first)));
        break;
      case SourcePositionEvent::DIFF_STARTS:
        DCHECK(!inside_diff);
        inside_diff = true;
        if (!literal_stack.empty()) {
          // Note that outer literal has not necessarily changed, unless the
          // diff goes past the end of this literal. In this case, we'll mark
          // this function as damaged and parent as changed later in
          // MapLiterals.
          literal_stack.top().second.has_changes = true;
        }
        break;
    }
  }
}

// Function which has not changed itself, but if any variable in its
// outer context has been added/removed, we must consider this function
// as damaged and not update references to it.
// This is because old compiled function has hardcoded references to
// it's outer context.
bool HasChangedScope(FunctionLiteral* a, FunctionLiteral* b) {
  Scope* scope_a = a->scope()->outer_scope();
  Scope* scope_b = b->scope()->outer_scope();
  while (scope_a && scope_b) {
    std::unordered_map<int, Handle<String>> vars;
    for (Variable* var : *scope_a->locals()) {
      if (!var->IsContextSlot()) continue;
      vars[var->index()] = var->name();
    }
    for (Variable* var : *scope_b->locals()) {
      if (!var->IsContextSlot()) continue;
      auto it = vars.find(var->index());
      if (it == vars.end()) return true;
      if (*it->second != *var->name()) return true;
    }
    scope_a = scope_a->outer_scope();
    scope_b = scope_b->outer_scope();
  }
  return scope_a != scope_b;
}

enum ChangeState { UNCHANGED, CHANGED, DAMAGED };

using LiteralMap = std::unordered_map<FunctionLiteral*, FunctionLiteral*>;
void MapLiterals(const FunctionLiteralChanges& changes,
                 const std::vector<FunctionLiteral*>& new_literals,
                 LiteralMap* unchanged, LiteralMap* changed) {
  // Track the top-level script function separately as it can overlap fully with
  // another function, e.g. the script "()=>42".
  const std::pair<int, int> kTopLevelMarker = std::make_pair(-1, -1);
  std::map<std::pair<int, int>, FunctionLiteral*> position_to_new_literal;
  for (FunctionLiteral* literal : new_literals) {
    DCHECK(literal->start_position() != kNoSourcePosition);
    DCHECK(literal->end_position() != kNoSourcePosition);
    std::pair<int, int> key =
        literal->function_literal_id() == kFunctionLiteralIdTopLevel
            ? kTopLevelMarker
            : std::make_pair(literal->start_position(),
                             literal->end_position());
    // Make sure there are no duplicate keys.
    DCHECK_EQ(position_to_new_literal.find(key), position_to_new_literal.end());
    position_to_new_literal[key] = literal;
  }
  LiteralMap mappings;
  std::unordered_map<FunctionLiteral*, ChangeState> change_state;
  for (const auto& change_pair : changes) {
    FunctionLiteral* literal = change_pair.first;
    const FunctionLiteralChange& change = change_pair.second;
    std::pair<int, int> key =
        literal->function_literal_id() == kFunctionLiteralIdTopLevel
            ? kTopLevelMarker
            : std::make_pair(change.new_start_position,
                             change.new_end_position);
    auto it = position_to_new_literal.find(key);
    if (it == position_to_new_literal.end() ||
        HasChangedScope(literal, it->second)) {
      change_state[literal] = ChangeState::DAMAGED;
      if (!change.outer_literal) continue;
      if (change_state[change.outer_literal] != ChangeState::DAMAGED) {
        change_state[change.outer_literal] = ChangeState::CHANGED;
      }
    } else {
      mappings[literal] = it->second;
      if (change_state.find(literal) == change_state.end()) {
        change_state[literal] =
            change.has_changes ? ChangeState::CHANGED : ChangeState::UNCHANGED;
      }
    }
  }
  for (const auto& mapping : mappings) {
    if (change_state[mapping.first] == ChangeState::UNCHANGED) {
      (*unchanged)[mapping.first] = mapping.second;
    } else if (change_state[mapping.first] == ChangeState::CHANGED) {
      (*changed)[mapping.first] = mapping.second;
    }
  }
}

class CollectFunctionLiterals final
    : public AstTraversalVisitor<CollectFunctionLiterals> {
 public:
  CollectFunctionLiterals(Isolate* isolate, AstNode* root)
      : AstTraversalVisitor<CollectFunctionLiterals>(isolate, root) {}
  void VisitFunctionLiteral(FunctionLiteral* lit) {
    AstTraversalVisitor::VisitFunctionLiteral(lit);
    literals_->push_back(lit);
  }
  void Run(std::vector<FunctionLiteral*>* literals) {
    literals_ = literals;
    AstTraversalVisitor::Run();
    literals_ = nullptr;
  }

 private:
  std::vector<FunctionLiteral*>* literals_;
};

bool ParseScript(Isolate* isolate, Handle<Script> script, ParseInfo* parse_info,
                 MaybeHandle<ScopeInfo> outer_scope_info, bool compile_as_well,
                 std::vector<FunctionLiteral*>* literals,
                 debug::LiveEditResult* result) {
  v8::TryCatch try_catch(reinterpret_cast<v8::Isolate*>(isolate));
  Handle<SharedFunctionInfo> shared;
  bool success = false;
  if (compile_as_well) {
    success = Compiler::CompileForLiveEdit(parse_info, script, outer_scope_info,
                                           isolate)
                  .ToHandle(&shared);
  } else {
    success =
        parsing::ParseProgram(parse_info, script, outer_scope_info, isolate,
                              parsing::ReportStatisticsMode::kYes);
    if (!success) {
      // Throw the parser error.
      parse_info->pending_error_handler()->PrepareErrors(
          isolate, parse_info->ast_value_factory());
      parse_info->pending_error_handler()->ReportErrors(isolate, script);
    }
  }
  if (!success) {
    DCHECK(try_catch.HasCaught());
    result->message = try_catch.Message()->Get();
    i::DirectHandle<i::JSMessageObject> msg =
        Utils::OpenDirectHandle(*try_catch.Message());
    i::JSMessageObject::EnsureSourcePositionsAvailable(isolate, msg);
    result->line_number = msg->GetLineNumber();
    result->column_number = msg->GetColumnNumber();
    result->status = debug::LiveEditResult::COMPILE_ERROR;
    return false;
  }
  CollectFunctionLiterals(isolate, parse_info->literal()).Run(literals);
  return true;
}

struct FunctionData {
  explicit FunctionData(FunctionLiteral* literal)
      : literal(literal), stack_position(NOT_ON_STACK) {}

  FunctionLiteral* literal;
  MaybeHandle<SharedFunctionInfo> shared;
  std::vector<Handle<JSFunction>> js_functions;
  std::vector<Handle<JSGeneratorObject>> running_generators;
  // In case of multiple functions with different stack position, the latest
  // one (in the order below) is used, since it is the most restrictive.
  // This is important only for functions to be restarted.
  enum StackPosition { NOT_ON_STACK, ON_TOP_ONLY, ON_STACK };
  StackPosition stack_position;
};

class FunctionDataMap : public ThreadVisitor {
 public:
  void AddInterestingLiteral(int script_id, FunctionLiteral* literal) {
    map_.emplace(GetFuncId(script_id, literal), FunctionData{literal});
  }

  bool Lookup(Tagged<SharedFunctionInfo> sfi, FunctionData** data) {
    int start_position = sfi->StartPosition();
    if (!IsScript(sfi->script()) || start_position == -1) {
      return false;
    }
    Tagged<Script> script = Cast<Script>(sfi->script());
    return Lookup(GetFuncId(script->id(), sfi), data);
  }

  bool Lookup(DirectHandle<Script> script, FunctionLiteral* literal,
              FunctionData** data) {
    return Lookup(GetFuncId(script->id(), literal), data);
  }

  void Fill(Isolate* isolate) {
    {
      HeapObjectIterator iterator(isolate->heap(),
                                  HeapObjectIterator::kFilterUnreachable);
      for (Tagged<HeapObject> obj = iterator.Next(); !obj.is_null();
           obj = iterator.Next()) {
        if (IsSharedFunctionInfo(obj)) {
          Tagged<SharedFunctionInfo> sfi = Cast<SharedFunctionInfo>(obj);
          FunctionData* data = nullptr;
          if (!Lookup(sfi, &data)) continue;
          data->shared = handle(sfi, isolate);
        } else if (IsJSFunction(obj)) {
          Tagged<JSFunction> js_function = Cast<JSFunction>(obj);
          Tagged<SharedFunctionInfo> sfi = js_function->shared();
          FunctionData* data = nullptr;
          if (!Lookup(sfi, &data)) continue;
          data->js_functions.emplace_back(js_function, isolate);
        } else if (IsJSGeneratorObject(obj)) {
          Tagged<JSGeneratorObject> gen = Cast<JSGeneratorObject>(obj);
          if (gen->is_closed()) continue;
          Tagged<SharedFunctionInfo> sfi = gen->function()->shared();
          FunctionData* data = nullptr;
          if (!Lookup(sfi, &data)) continue;
          data->running_generators.emplace_back(gen, isolate);
        }
      }
    }

    // Visit the current thread stack.
    VisitCurrentThread(isolate);

    // Visit the stacks of all archived threads.
    isolate->thread_manager()->IterateArchivedThreads(this);
  }

 private:
  // Unique id for a function: script_id + start_position, where start_position
  // is special cased to -1 for top-level so that it does not overlap with a
  // function whose start position is 0.
  using FuncId = std::pair<int, int>;

  FuncId GetFuncId(int script_id, FunctionLiteral* literal) {
    int start_position = literal->start_position();
    if (literal->function_literal_id() == 0) {
      // This is the top-level script function literal, so special case its
      // start position
      DCHECK_EQ(start_position, 0);
      start_position = -1;
    }
    return FuncId(script_id, start_position);
  }

  FuncId GetFuncId(int script_id, Tagged<SharedFunctionInfo> sfi) {
    DCHECK_EQ(script_id, Cast<Script>(sfi->script())->id());
    int start_position = sfi->StartPosition();
    DCHECK_NE(start_position, -1);
    if (sfi->is_toplevel()) {
      // This is the top-level function, so special case its start position
      DCHECK_EQ(start_position, 0);
      start_position = -1;
    }
    return FuncId(script_id, start_position);
  }

  bool Lookup(FuncId id, FunctionData** data) {
    auto it = map_.find(id);
    if (it == map_.end()) return false;
    *data = &it->second;
    return true;
  }

  void VisitThread(Isolate* isolate, ThreadLocalTop* top) override {
    for (JavaScriptStackFrameIterator it(isolate, top); !it.done();
         it.Advance()) {
      std::vector<Handle<SharedFunctionInfo>> sfis;
      it.frame()->GetFunctions(&sfis);
      for (auto& sfi : sfis) {
        FunctionData* data = nullptr;
        if (!Lookup(*sfi, &data)) continue;
        data->stack_position = FunctionData::ON_STACK;
      }
    }
  }

  void VisitCurrentThread(Isolate* isolate) {
    // We allow live editing the function that's currently top-of-stack. But
    // only if no activation of that function is anywhere else on the stack.
    bool is_top = true;
    for (DebugStackTraceIterator it(isolate, /* index */ 0); !it.Done();
         it.Advance(), is_top = false) {
      auto sfi = it.GetSharedFunctionInfo();
      if (sfi.is_null()) continue;
      FunctionData* data = nullptr;
      if (!Lookup(*sfi, &data)) continue;

      // ON_TOP_ONLY will only be set on the first iteration (and if the frame
      // can be restarted). Further activations will change the ON_TOP_ONLY to
      // ON_STACK and prevent the live edit from happening.
      data->stack_position = is_top && it.CanBeRestarted()
                                 ? FunctionData::ON_TOP_ONLY
                                 : FunctionData::ON_STACK;
    }
  }

  std::map<FuncId, FunctionData> map_;
};

bool CanPatchScript(const LiteralMap& changed, DirectHandle<Script> script,
                    DirectHandle<Script> new_script,
                    FunctionDataMap& function_data_map,
                    bool allow_top_frame_live_editing,
                    debug::LiveEditResult* result) {
  for (const auto& mapping : changed) {
    FunctionData* data = nullptr;
    function_data_map.Lookup(script, mapping.first, &data);
    FunctionData* new_data = nullptr;
    function_data_map.Lookup(new_script, mapping.second, &new_data);
    Handle<SharedFunctionInfo> sfi;
    if (!data->shared.ToHandle(&sfi)) {
      continue;
    } else if (IsModule(sfi->kind())) {
      DCHECK(script->origin_options().IsModule() && sfi->is_toplevel());
      result->status =
          debug::LiveEditResult::BLOCKED_BY_TOP_LEVEL_ES_MODULE_CHANGE;
      return false;
    } else if (data->stack_position == FunctionData::ON_STACK) {
      result->status = debug::LiveEditResult::BLOCKED_BY_ACTIVE_FUNCTION;
      return false;
    } else if (!data->running_generators.empty()) {
      result->status = debug::LiveEditResult::BLOCKED_BY_RUNNING_GENERATOR;
      return false;
    } else if (data->stack_position == FunctionData::ON_TOP_ONLY) {
      if (!allow_top_frame_live_editing) {
        result->status = debug::LiveEditResult::BLOCKED_BY_ACTIVE_FUNCTION;
        return false;
      }
      result->restart_top_frame_required = true;
    }
  }
  return true;
}

void TranslateSourcePositionTable(Isolate* isolate,
                                  DirectHandle<BytecodeArray> code,
                                  const std::vector<SourceChangeRange>& diffs) {
  Zone zone(isolate->allocator(), ZONE_NAME);
  SourcePositionTableBuilder builder(&zone);

  DirectHandle<TrustedByteArray> source_position_table(
      code->SourcePositionTable(), isolate);
  for (SourcePositionTableIterator iterator(*source_position_table);
       !iterator.done(); iterator.Advance()) {
    SourcePosition position = iterator.source_position();
    position.SetScriptOffset(
        LiveEdit::TranslatePosition(diffs, position.ScriptOffset()));
    builder.AddPosition(iterator.code_offset(), position,
                        iterator.is_statement());
  }

  DirectHandle<TrustedByteArray> new_source_position_table(
      builder.ToSourcePositionTable(isolate));
  code->set_source_position_table(*new_source_position_table, kReleaseStore);
  LOG_CODE_EVENT(isolate,
                 CodeLinePosInfoRecordEvent(code->GetFirstBytecodeAddress(),
                                            *new_source_position_table,
                                            JitCodeEvent::BYTE_CODE));
}

void UpdatePositions(Isolate* isolate, DirectHandle<SharedFunctionInfo> sfi,
                     FunctionLiteral* new_function,
                     const std::vector<SourceChangeRange>& diffs) {
  sfi->UpdateFromFunctionLiteralForLiveEdit(isolate, new_function);
  if (sfi->HasBytecodeArray()) {
    TranslateSourcePositionTable(
        isolate, direct_handle(sfi->GetBytecodeArray(isolate), isolate), diffs);
  }
}

#ifdef DEBUG
Tagged<ScopeInfo> FindOuterScopeInfoFromScriptSfi(Isolate* isolate,
                                                  DirectHandle<Script> script) {
  // We take some SFI from the script and walk outwards until we find the
  // EVAL_SCOPE. Then we do the same search as `DetermineOuterScopeInfo` and
  // check that we found the same ScopeInfo.
  SharedFunctionInfo::ScriptIterator it(isolate, *script);
  Tagged<ScopeInfo> other_scope_info;
  for (Tagged<SharedFunctionInfo> sfi = it.Next(); !sfi.is_null();
       sfi = it.Next()) {
    if (!sfi->scope_info()->IsEmpty()) {
      other_scope_info = sfi->scope_info();
      break;
    }
  }
  if (other_scope_info.is_null()) return other_scope_info;

  while (!other_scope_info->IsEmpty() &&
         other_scope_info->scope_type() != EVAL_SCOPE &&
         other_scope_info->HasOuterScopeInfo()) {
    other_scope_info = other_scope_info->OuterScopeInfo();
  }

  // This function is only called when we found a ScopeInfo candidate, so
  // technically the EVAL_SCOPE must have an outer_scope_info. But, the GC can
  // clean up some ScopeInfos it thinks are no longer needed. Abort the check
  // in that case.
  if (!other_scope_info->HasOuterScopeInfo()) return ScopeInfo();

  DCHECK_EQ(other_scope_info->scope_type(), EVAL_SCOPE);
  other_scope_info = other_scope_info->OuterScopeInfo();

  while (!other_scope_info->IsEmpty() && !other_scope_info->HasContext() &&
         other_scope_info->HasOuterScopeInfo()) {
    other_scope_info = other_scope_info->OuterScopeInfo();
  }
  return other_scope_info;
}
#endif

// For sloppy eval we need to know the ScopeInfo the eval was compiled in and
// re-use it when we compile the new version of the script.
MaybeHandle<ScopeInfo> DetermineOuterScopeInfo(Isolate* isolate,
                                               DirectHandle<Script> script) {
  if (!script->has_eval_from_shared()) return kNullMaybeHandle;
  DCHECK_EQ(script->compilation_type(), Script::CompilationType::kEval);
  Tagged<ScopeInfo> scope_info = script->eval_from_shared()->scope_info();
  // Sloppy eval compiles use the ScopeInfo of the context. Let's find it.
  while (!scope_info->IsEmpty()) {
    if (scope_info->HasContext()) {
#ifdef DEBUG
      Tagged<ScopeInfo> other_scope_info =
          FindOuterScopeInfoFromScriptSfi(isolate, script);
      DCHECK_IMPLIES(!other_scope_info.is_null(),
                     scope_info == other_scope_info);
#endif
      return handle(scope_info, isolate);
    } else if (!scope_info->HasOuterScopeInfo()) {
      break;
    }
    scope_info = scope_info->OuterScopeInfo();
  }

  return kNullMaybeHandle;
}

}  // anonymous namespace

void LiveEdit::PatchScript(Isolate* isolate, Handle<Script> script,
                           Handle<String> new_source, bool preview,
                           bool allow_top_frame_live_editing,
                           debug::LiveEditResult* result) {
  std::vector<SourceChangeRange> diffs;
  LiveEdit::CompareStrings(isolate,
                           handle(Cast<String>(script->source()), isolate),
                           new_source, &diffs);
  if (diffs.empty()) {
    result->status = debug::LiveEditResult::OK;
    return;
  }

  ReusableUnoptimizedCompileState reusable_state(isolate);

  UnoptimizedCompileState compile_state;
  UnoptimizedCompileFlags flags =
      UnoptimizedCompileFlags::ForScriptCompile(isolate, *script);
  flags.set_is_eager(true);
  flags.set_is_reparse(true);
  ParseInfo parse_info(isolate, flags, &compile_state, &reusable_state);
  MaybeHandle<ScopeInfo> outer_scope_info =
      DetermineOuterScopeInfo(isolate, script);
  std::vector<FunctionLiteral*> literals;
  if (!ParseScript(isolate, script, &parse_info, outer_scope_info, false,
                   &literals, result))
    return;

  Handle<Script> new_script =
      isolate->factory()->CloneScript(script, new_source);
  UnoptimizedCompileState new_compile_state;
  UnoptimizedCompileFlags new_flags =
      UnoptimizedCompileFlags::ForScriptCompile(isolate, *new_script);
  new_flags.set_is_eager(true);
  ParseInfo new_parse_info(isolate, new_flags, &new_compile_state,
                           &reusable_state);
  std::vector<FunctionLiteral*> new_literals;
  if (!ParseScript(isolate, new_script, &new_parse_info, outer_scope_info, true,
                   &new_literals, result)) {
    return;
  }

  FunctionLiteralChanges literal_changes;
  CalculateFunctionLiteralChanges(literals, diffs, &literal_changes);

  LiteralMap changed;
  LiteralMap unchanged;
  MapLiterals(literal_changes, new_literals, &unchanged, &changed);

  FunctionDataMap function_data_map;
  for (const auto& mapping : changed) {
    function_data_map.AddInterestingLiteral(script->id(), mapping.first);
    function_data_map.AddInterestingLiteral(new_script->id(), mapping.second);
  }
  for (const auto& mapping : unchanged) {
    function_data_map.AddInterestingLiteral(script->id(), mapping.first);
  }
  function_data_map.Fill(isolate);

  if (!CanPatchScript(changed, script, new_script, function_data_map,
                      allow_top_frame_live_editing, result)) {
    return;
  }

  if (preview) {
    result->status = debug::LiveEditResult::OK;
    return;
  }

  // Patching a script means that the bytecode on the stack may no longer
  // correspond to the bytecode of the JSFunction for that frame. As a result
  // it is no longer safe to flush bytecode since we might flush the new
  // bytecode for a JSFunction that is on the stack with an old bytecode, which
  // breaks the invariant that any JSFunction active on the stack is compiled.
  isolate->set_disable_bytecode_flushing(true);

  std::map<int, int> start_position_to_unchanged_id;
  for (const auto& mapping : unchanged) {
    FunctionData* data = nullptr;
    if (!function_data_map.Lookup(script, mapping.first, &data)) continue;
    Handle<SharedFunctionInfo> sfi;
    if (!data->shared.ToHandle(&sfi)) continue;
    DCHECK_EQ(sfi->script(), *script);

    isolate->compilation_cache()->Remove(sfi);
    isolate->debug()->DeoptimizeFunction(sfi);
    if (std::optional<Tagged<DebugInfo>> di = sfi->TryGetDebugInfo(isolate)) {
      DirectHandle<DebugInfo> debug_info(di.value(), isolate);
      isolate->debug()->RemoveBreakInfoAndMaybeFree(debug_info);
    }
    SharedFunctionInfo::EnsureSourcePositionsAvailable(isolate, sfi);
    UpdatePositions(isolate, sfi, mapping.second, diffs);

    sfi->set_script(*new_script, kReleaseStore);
    sfi->set_function_literal_id(mapping.second->function_literal_id());
    new_script->infos()->set(mapping.second->function_literal_id(),
                             MakeWeak(*sfi));
    DCHECK_EQ(sfi->function_literal_id(),
              mapping.second->function_literal_id());

    // Save the new start_position -> id mapping, so that we can recover it when
    // iterating over changed functions' constant pools.
    start_position_to_unchanged_id[mapping.second->start_position()] =
        mapping.second->function_literal_id();

    if (sfi->HasUncompiledDataWithPreparseData()) {
      sfi->ClearPreparseData(isolate);
    }

    for (auto& js_function : data->js_functions) {
      js_function->set_raw_feedback_cell(
          *isolate->factory()->many_closures_cell());
      if (!js_function->is_compiled(isolate)) continue;
      IsCompiledScope is_compiled_scope(
          js_function->shared()->is_compiled_scope(isolate));
      JSFunction::EnsureFeedbackVector(isolate, js_function,
                                       &is_compiled_scope);
    }

    if (!sfi->HasBytecodeArray()) continue;
    Tagged<TrustedFixedArray> constants =
        sfi->GetBytecodeArray(isolate)->constant_pool();
    for (int i = 0; i < constants->length(); ++i) {
      if (!IsSharedFunctionInfo(constants->get(i))) continue;
      data = nullptr;
      if (!function_data_map.Lookup(Cast<SharedFunctionInfo>(constants->get(i)),
                                    &data)) {
        continue;
      }
      auto change_it = changed.find(data->literal);
      if (change_it == changed.end()) continue;
      if (!function_data_map.Lookup(new_script, change_it->second, &data)) {
        continue;
      }
      Handle<SharedFunctionInfo> new_sfi;
      if (!data->shared.ToHandle(&new_sfi)) continue;
      constants->set(i, *new_sfi);
    }
  }
  for (const auto& mapping : changed) {
    FunctionData* data = nullptr;
    if (!function_data_map.Lookup(new_script, mapping.second, &data)) continue;
    Handle<SharedFunctionInfo> new_sfi;
    // In most cases the new FunctionLiteral should also have an SFI, but there
    // are some exceptions. E.g the compiler doesn't create SFIs for
    // inner functions that are never referenced.
    if (!data->shared.ToHandle(&new_sfi)) continue;
    DCHECK_EQ(new_sfi->script(), *new_script);

    if (!function_data_map.Lookup(script, mapping.first, &data)) continue;
    Handle<SharedFunctionInfo> sfi;
    if (!data->shared.ToHandle(&sfi)) continue;

    isolate->debug()->DeoptimizeFunction(sfi);
    isolate->compilation_cache()->Remove(sfi);
    for (auto& js_function : data->js_functions) {
#ifdef V8_ENABLE_LEAPTIERING
      js_function->AllocateDispatchHandle(
          isolate, new_sfi->internal_formal_parameter_count_with_receiver(),
          new_sfi->GetCode(isolate));
#endif
      js_function->set_raw_feedback_cell(
          *isolate->factory()->many_closures_cell());
      js_function->set_shared(*new_sfi);

      if (!js_function->is_compiled(isolate)) continue;
      IsCompiledScope is_compiled_scope(
          js_function->shared()->is_compiled_scope(isolate));
      JSFunction::EnsureFeedbackVector(isolate, js_function,
                                       &is_compiled_scope);
    }
  }
  SharedFunctionInfo::ScriptIterator it(isolate, *new_script);
  for (Tagged<SharedFunctionInfo> sfi = it.Next(); !sfi.is_null();
       sfi = it.Next()) {
    if (!sfi->HasBytecodeArray()) continue;
    Tagged<TrustedFixedArray> constants =
        sfi->GetBytecodeArray(isolate)->constant_pool();
    for (int i = 0; i < constants->length(); ++i) {
      if (!IsSharedFunctionInfo(constants->get(i))) continue;
      Tagged<SharedFunctionInfo> inner_sfi =
          Cast<SharedFunctionInfo>(constants->get(i));
      // See if there is a mapping from this function's start position to an
      // unchanged function's id.
      auto unchanged_it =
          start_position_to_unchanged_id.find(inner_sfi->StartPosition());
      if (unchanged_it == start_position_to_unchanged_id.end()) continue;

      // Grab that function id from the new script's SFI list, which should have
      // already been updated in in the unchanged pass.
      Tagged<SharedFunctionInfo> old_unchanged_inner_sfi =
          Cast<SharedFunctionInfo>(
              new_script->infos()->get(unchanged_it->second).GetHeapObject());
      if (old_unchanged_inner_sfi == inner_sfi) continue;
      DCHECK_NE(old_unchanged_inner_sfi, inner_sfi);
      // Now some sanity checks. Make sure that the unchanged SFI has already
      // been processed and patched to be on the new script ...
      DCHECK_EQ(old_unchanged_inner_sfi->script(), *new_script);
      constants->set(i, old_unchanged_inner_sfi);
    }
  }
#ifdef DEBUG
  {
    // Check that all the functions in the new script are valid, that their
    // function literals match what is expected, and that start positions are
    // unique.
    DisallowGarbageCollection no_gc;

    SharedFunctionInfo::ScriptIterator script_it(isolate, *new_script);
    std::set<int> start_positions;
    for (Tagged<SharedFunctionInfo> sfi = script_it.Next(); !sfi.is_null();
         sfi = script_it.Next()) {
      DCHECK_EQ(sfi->script(), *new_script);
      DCHECK_EQ(sfi->function_literal_id(), script_it.CurrentIndex());
      // Don't check the start position of the top-level function, as it can
      // overlap with a function in the script.
      if (sfi->is_toplevel()) {
        DCHECK_EQ(start_positions.find(sfi->StartPosition()),
                  start_positions.end());
        start_positions.insert(sfi->StartPosition());
      }

      if (!sfi->HasBytecodeArray()) continue;
      // Check that all the functions in this function's constant pool are also
      // on the new script, and that their id matches their index in the new
      // scripts function list.
      Tagged<TrustedFixedArray> constants =
          sfi->GetBytecodeArray(isolate)->constant_pool();
      for (int i = 0; i < constants->length(); ++i) {
        if (!IsSharedFunctionInfo(constants->get(i))) continue;
        Tagged<SharedFunctionInfo> inner_sfi =
            Cast<SharedFunctionInfo>(constants->get(i));
        DCHECK_EQ(inner_sfi->script(), *new_script);
        DCHECK_EQ(inner_sfi, new_script->infos()
                                 ->get(inner_sfi->function_literal_id())
                                 .GetHeapObject());
      }
    }
  }
#endif

  int script_id = script->id();
  script->set_id(new_script->id());
  new_script->set_id(script_id);
  result->status = debug::LiveEditResult::OK;
  result->script = ToApiHandle<v8::debug::Script>(new_script);
}

void LiveEdit::CompareStrings(Isolate* isolate, Handle<String> s1,
                              Handle<String> s2,
                              std::vector<SourceChangeRange>* diffs) {
  s1 = String::Flatten(isolate, s1);
  s2 = String::Flatten(isolate, s2);

  LineEndsWrapper line_ends1(isolate, s1);
  LineEndsWrapper line_ends2(isolate, s2);

  LineArrayCompareInput input(s1, s2, line_ends1, line_ends2);
  TokenizingLineArrayCompareOutput output(isolate, line_ends1, line_ends2, s1,
                                          s2, diffs);

  NarrowDownInput(&input, &output);

  Comparator::CalculateDifference(&input, &output);
}

int LiveEdit::TranslatePosition(const std::vector<SourceChangeRange>& diffs,
                                int position) {
  auto it = std::lower_bound(diffs.begin(), diffs.end(), position,
                             [](const SourceChangeRange& change, int position) {
                               return change.end_position < position;
                             });
  if (it != diffs.end() && position == it->end_position) {
    return it->new_end_position;
  }
  if (it == diffs.begin()) return position;
  DCHECK(it == diffs.end() || position <= it->start_position);
  it = std::prev(it);
  return position + (it->new_end_position - it->end_position);
}
}  // namespace internal
}  // namespace v8

"""

```