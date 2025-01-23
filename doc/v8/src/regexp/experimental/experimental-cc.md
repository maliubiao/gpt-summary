Response:
Let's break down the thought process for analyzing the provided C++ code.

1. **Initial Scan and Identification of Key Components:** The first step is to quickly skim the code to identify major sections and keywords. Keywords like `namespace v8::internal`, `class ExperimentalRegExp`, function definitions, and `#include` statements are good starting points. This helps in understanding the overall structure and purpose. We can immediately see it's part of the V8 JavaScript engine's internal implementation, specifically related to regular expressions.

2. **Understanding the File Name and Path:** The path `v8/src/regexp/experimental/experimental.cc` suggests this file implements an *experimental* regular expression engine within V8. This is important context. The `.cc` extension confirms it's C++ source code.

3. **Analyzing the `CanBeHandled` Function:** This function checks if the experimental engine can handle a given regular expression. The key logic lies in calling `ExperimentalRegExpCompiler::CanBeHandled`. The `v8_flags` checks indicate that this experimental engine is enabled via flags. The tracing output is also noteworthy for debugging purposes.

4. **Analyzing the `Initialize` Function:** This function seems to be responsible for setting up the experimental regular expression object (`JSRegExp`). It stores the source pattern and flags.

5. **Analyzing the `IsCompiled` Function:** This function checks if the regular expression has already been compiled into bytecode. The `re_data->has_bytecode(kIsLatin1)` is the core check. The `RegExpData::Type::EXPERIMENTAL` assertion is important for ensuring the correct type.

6. **Analyzing the `Compile` Function:** This is a crucial function. It takes the regular expression data and actually compiles it. The steps involve:
    * Parsing the regular expression source using `RegExpParser::ParseRegExpFromHeapString`.
    * Compiling the parsed tree into bytecode using `ExperimentalRegExpCompiler::Compile`.
    * Storing the bytecode and capture name map in the `IrRegExpData` object.
    * Handling potential parsing errors (stack overflow).

7. **Analyzing the `ExecRaw` and `ExecRawImpl` Functions:** These functions are responsible for *executing* the compiled bytecode against a subject string. The `ExperimentalRegExpInterpreter::FindMatches` function is the core of the execution. The `DisallowGarbageCollection` and `DisableGCMole` are important V8-specific mechanisms.

8. **Analyzing the `MatchForCallFromJs` Function:** This function acts as an interface for calling the execution engine from JavaScript. It handles the conversion of JavaScript strings and objects to the internal C++ representations.

9. **Analyzing the `Exec` Function:** This function provides a higher-level interface for executing the regular expression. It handles compilation if necessary and manages retries.

10. **Analyzing the `OneshotExecRaw` and `OneshotExec` Functions:** These functions appear to be similar to `ExecRaw` and `Exec`, but they are used when the experimental engine is enabled due to excessive backtracking in the main engine. This suggests a fallback mechanism.

11. **Identifying Key Data Structures and Classes:**  Throughout the analysis, pay attention to classes like `RegExpTree`, `JSRegExp`, `IrRegExpData`, `TrustedByteArray`, `RegExpFlags`, `RegExpInstruction`, and the compiler and interpreter classes. Understanding the purpose of these structures is key.

12. **Looking for Conditional Compilation and Debugging Aids:** The presence of `#ifdef VERIFY_HEAP` and `v8_flags.trace_experimental_regexp_engine` indicates debugging and verification features. These are important for understanding the development and testing aspects.

13. **Connecting the C++ Code to JavaScript Concepts:**  Think about how the C++ functions relate to JavaScript's regular expression features. For example, `Compile` is related to the compilation of a `RegExp` object, and `Exec` is related to the `exec`, `test`, `match`, `search`, and `replace` methods.

14. **Considering Potential Errors:**  Think about what could go wrong. Parsing errors, compilation failures, and errors during execution are all possibilities. The code handles stack overflow during parsing.

15. **Formulating the Explanation:** Based on the analysis, organize the findings into logical sections, addressing the specific questions in the prompt. Explain the functionality of each key function, highlighting the interaction between different components. Provide JavaScript examples where applicable.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Is this the *only* file for the experimental engine?  *Correction:*  The `#include` statements indicate that this file interacts with other files like `experimental-compiler.h` and `experimental-interpreter.h`, suggesting a modular design.
* **Initial thought:**  Is the "oneshot" execution for performance optimization? *Correction:* The comment `enable_experimental_regexp_engine_on_excessive_backtracks` suggests it's a fallback when the main engine struggles.
* **Ensuring Clarity:**  Review the explanation to make sure it's easy to understand, even for someone who isn't deeply familiar with the V8 internals. Use clear and concise language. Provide specific examples.

By following these steps and continuously refining the understanding, we can arrive at a comprehensive explanation of the provided C++ code.
根据提供的 V8 源代码文件 `v8/src/regexp/experimental/experimental.cc`，我们可以总结出以下功能：

**主要功能： 实现 V8 中实验性的正则表达式引擎。**

这个文件是 V8 JavaScript 引擎中一个实验性正则表达式引擎的核心实现。 它提供了一套用于编译和执行正则表达式的机制，旨在探索新的优化和算法。

**具体功能点：**

1. **判断是否可以使用实验性引擎 (`CanBeHandled`)：**
   - 接收一个 `RegExpTree` (正则表达式的抽象语法树)、正则表达式模式字符串 (`pattern`)、标志 (`flags`) 和捕获组的数量 (`capture_count`) 作为输入。
   - 通过调用 `ExperimentalRegExpCompiler::CanBeHandled` 来判断当前给定的正则表达式是否能被实验性引擎处理。
   - 如果不能处理，并且启用了跟踪功能 (`v8_flags.trace_experimental_regexp_engine`)，则会输出一条消息到控制台，说明该模式不被实验性引擎支持。
   - **与 JavaScript 的关系：** 当 JavaScript 代码尝试创建一个 `RegExp` 对象时，V8 内部会判断是否可以使用实验性引擎来处理这个正则表达式。

   ```javascript
   const regex1 = /abc/; // 可能会被实验性引擎处理
   const regex2 = /a(?<name>b)c/; // 包含命名捕获组，实验性引擎可能支持也可能不支持
   ```

2. **初始化实验性正则表达式对象 (`Initialize`)：**
   - 接收 `Isolate` (V8 的隔离环境)、一个新创建的 `JSRegExp` 对象 (`re`)、正则表达式的源代码 (`source`)、标志 (`flags`) 和捕获组的数量 (`capture_count`) 作为输入。
   - 将正则表达式的源字符串、标志和捕获组数量存储到 `JSRegExp` 对象的相关字段中，标记为实验性正则表达式数据。

3. **判断是否已编译 (`IsCompiled`)：**
   - 接收 `IrRegExpData` 对象 (`re_data`) 和 `Isolate` 作为输入。
   - 检查 `IrRegExpData` 对象是否已经包含编译后的字节码。实验性引擎使用字节码来执行匹配。
   - 只有当 `re_data` 的 `type_tag` 是 `RegExpData::Type::EXPERIMENTAL` 时才进行检查。

4. **编译正则表达式 (`Compile`)：**
   - 接收 `Isolate` 和 `IrRegExpData` 对象 (`re_data`) 作为输入。
   - 如果正则表达式尚未编译，则会进行编译。
   - **编译过程：**
     - 从 `IrRegExpData` 中获取正则表达式的源字符串。
     - 使用 `RegExpParser::ParseRegExpFromHeapString` 将源字符串解析成 `RegExpTree`。
     - 使用 `ExperimentalRegExpCompiler::Compile` 将 `RegExpTree` 编译成实验性引擎的字节码指令序列。
     - 将编译后的字节码存储到 `IrRegExpData` 对象中。
     - 创建并存储捕获组的名称映射（如果存在命名捕获组）。
   - **与 JavaScript 的关系：** 当首次需要执行一个正则表达式时，如果选择了实验性引擎，就会触发编译过程。

5. **将字节数组转换为指令序列 (`AsInstructionSequence`)：**
   - 接收一个 `TrustedByteArray` 对象 (`raw_bytes`) 作为输入，该对象包含了编译后的字节码。
   - 将字节数组重新解释为 `RegExpInstruction` 类型的序列，方便后续的执行。

6. **执行正则表达式 (`ExecRawImpl`, `ExecRaw`, `MatchForCallFromJs`, `Exec`)：**
   - 提供多种方式来执行编译后的正则表达式。
   - `ExecRawImpl` 是执行的核心实现，它接收编译后的字节码、目标字符串、捕获组数量等参数，并调用 `ExperimentalRegExpInterpreter::FindMatches` 来进行匹配。
   - `ExecRaw` 是 `ExecRawImpl` 的一个包装器，它从 `IrRegExpData` 对象中获取字节码和其他必要信息。
   - `MatchForCallFromJs` 是一个从 JavaScript 调用的接口，用于执行正则表达式匹配。它负责将 JavaScript 的字符串和参数转换为 C++ 的表示形式。
   - `Exec` 提供了一个更通用的执行接口，它会检查正则表达式是否已编译，如果没有则先进行编译，然后执行匹配。它处理了重试机制 (`RegExp::kInternalRegExpRetry`) 和异常情况。
   - **与 JavaScript 的关系：** 这些函数对应于 JavaScript 中 `RegExp.prototype.exec()`, `String.prototype.match()`, `String.prototype.search()` 等方法。

   ```javascript
   const regex = /abc/;
   const str = 'abcdefg';
   const result1 = regex.exec(str); // 可能会使用实验性引擎执行

   const result2 = str.match(regex); // 可能会使用实验性引擎执行
   ```

7. **一次性执行正则表达式 (`OneshotExecRaw`, `OneshotExec`)：**
   - 提供了一种在特定情况下（例如，主正则表达式引擎发生过多的回溯时）执行正则表达式的方式。
   - `OneshotExecRaw` 类似于 `ExecRawImpl`，但它是针对一次性执行的场景。
   - `OneshotExec` 类似于 `Exec`，用于一次性执行。
   - **使用场景：** 当主正则表达式引擎因为某些复杂的模式或输入导致性能问题时，V8 可能会尝试使用这个实验性的引擎进行一次性执行作为备选方案。

**关于文件扩展名 `.tq`：**

`v8/src/regexp/experimental/experimental.cc` 的文件扩展名是 `.cc`，这表明它是一个 **C++ 源代码文件**。如果文件扩展名是 `.tq`，那么它才是一个 V8 Torque 源代码文件。 Torque 是一种 V8 内部使用的类型安全的脚本语言，用于生成高效的 C++ 代码。

**JavaScript 示例：**

以下 JavaScript 代码展示了当使用实验性正则表达式引擎时，可能会涉及到的功能：

```javascript
// 假设 V8 启用了实验性正则表达式引擎的标志
const regex = /ab?c/g;
const text = 'ac abc abbc';

// 第一次执行，可能会触发实验性引擎的编译
let match1 = regex.exec(text);
console.log(match1); // 输出匹配结果

// 后续执行，如果已经编译，则直接使用编译后的字节码
let match2 = regex.exec(text);
console.log(match2);

// String.prototype.matchAll 也可以触发实验性引擎
const allMatches = text.matchAll(regex);
for (const match of allMatches) {
  console.log(match);
}
```

**代码逻辑推理示例：**

**假设输入：**

- 一个正则表达式模式 `/a+b/`
- 目标字符串 `"aaab"`

**输出：**

- 如果实验性引擎成功匹配，`ExecRaw` 或 `OneshotExecRaw` 可能会返回匹配的数量 (例如 1) 并将匹配的起始和结束位置写入 `output_registers`。
- `output_registers` 可能包含：
    - `output_registers[0]`: 匹配的起始位置 (例如 0)
    - `output_registers[1]`: 匹配的结束位置 (例如 4)
    - 如果有捕获组，则后续的寄存器会存储捕获组的起始和结束位置。

**用户常见的编程错误：**

1. **正则表达式语法错误：** 用户编写的正则表达式可能包含语法错误，导致解析失败。虽然 `experimental.cc` 自身不直接处理用户输入的语法错误，但它依赖的 `RegExpParser` 会处理这些错误。

   ```javascript
   // 语法错误：缺少闭合的括号
   const regex = /a(/;
   // 这会导致 JavaScript 抛出 SyntaxError
   ```

2. **期望实验性引擎支持所有正则表达式特性：** 实验性引擎可能并不支持所有标准的正则表达式特性。用户可能会使用一些实验性引擎尚未实现的特性，导致匹配结果不符合预期或无法被实验性引擎处理，最终回退到主引擎。

   ```javascript
   // 假设实验性引擎不支持 lookbehind assertions
   const regex = /(?<=a)b/;
   const text = 'ab';
   // 实验性引擎可能无法处理，或者结果与主引擎不同
   ```

3. **过度依赖实验性特性：** 用户可能会错误地认为实验性引擎的性能总是优于主引擎，并在生产环境过度依赖，但实验性功能可能不稳定或存在未知的 bug。

总而言之，`v8/src/regexp/experimental/experimental.cc` 是 V8 探索和实现新的正则表达式处理方式的关键组成部分，它负责编译和执行使用实验性方法的正则表达式。

### 提示词
```
这是目录为v8/src/regexp/experimental/experimental.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/regexp/experimental/experimental.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/regexp/experimental/experimental.h"

#include <optional>

#include "src/common/assert-scope.h"
#include "src/objects/js-regexp-inl.h"
#include "src/regexp/experimental/experimental-compiler.h"
#include "src/regexp/experimental/experimental-interpreter.h"
#include "src/regexp/regexp-parser.h"
#include "src/regexp/regexp-result-vector.h"
#include "src/utils/ostreams.h"

namespace v8::internal {

bool ExperimentalRegExp::CanBeHandled(RegExpTree* tree, Handle<String> pattern,
                                      RegExpFlags flags, int capture_count) {
  DCHECK(v8_flags.enable_experimental_regexp_engine ||
         v8_flags.enable_experimental_regexp_engine_on_excessive_backtracks);
  bool can_be_handled =
      ExperimentalRegExpCompiler::CanBeHandled(tree, flags, capture_count);
  if (!can_be_handled && v8_flags.trace_experimental_regexp_engine) {
    StdoutStream{} << "Pattern not supported by experimental engine: "
                   << pattern << std::endl;
  }
  return can_be_handled;
}

void ExperimentalRegExp::Initialize(Isolate* isolate, DirectHandle<JSRegExp> re,
                                    DirectHandle<String> source,
                                    RegExpFlags flags, int capture_count) {
  DCHECK(v8_flags.enable_experimental_regexp_engine);
  if (v8_flags.trace_experimental_regexp_engine) {
    StdoutStream{} << "Initializing experimental regexp " << *source
                   << std::endl;
  }

  isolate->factory()->SetRegExpExperimentalData(
      re, source, JSRegExp::AsJSRegExpFlags(flags), capture_count);
}

bool ExperimentalRegExp::IsCompiled(DirectHandle<IrRegExpData> re_data,
                                    Isolate* isolate) {
  DCHECK(v8_flags.enable_experimental_regexp_engine);
  DCHECK_EQ(re_data->type_tag(), RegExpData::Type::EXPERIMENTAL);
#ifdef VERIFY_HEAP
  if (v8_flags.verify_heap) re_data->IrRegExpDataVerify(isolate);
#endif

  static constexpr bool kIsLatin1 = true;
  return re_data->has_bytecode(kIsLatin1);
}

template <class T>
Handle<TrustedByteArray> VectorToByteArray(Isolate* isolate,
                                           base::Vector<T> data) {
  static_assert(std::is_trivial<T>::value);

  int byte_length = sizeof(T) * data.length();
  Handle<TrustedByteArray> byte_array =
      isolate->factory()->NewTrustedByteArray(byte_length);
  DisallowGarbageCollection no_gc;
  MemCopy(byte_array->begin(), data.begin(), byte_length);
  return byte_array;
}

namespace {

struct CompilationResult {
  Handle<TrustedByteArray> bytecode;
  Handle<FixedArray> capture_name_map;
};

// Compiles source pattern, but doesn't change the regexp object.
std::optional<CompilationResult> CompileImpl(
    Isolate* isolate, DirectHandle<IrRegExpData> re_data) {
  Zone zone(isolate->allocator(), ZONE_NAME);

  Handle<String> source(re_data->source(), isolate);

  // Parse and compile the regexp source.
  RegExpCompileData parse_result;
  DCHECK(!isolate->has_exception());

  RegExpFlags flags = JSRegExp::AsRegExpFlags(re_data->flags());
  bool parse_success = RegExpParser::ParseRegExpFromHeapString(
      isolate, &zone, source, flags, &parse_result);
  if (!parse_success) {
    // The pattern was already parsed successfully during initialization, so
    // the only way parsing can fail now is because of stack overflow.
    DCHECK_EQ(parse_result.error, RegExpError::kStackOverflow);
    USE(RegExp::ThrowRegExpException(isolate, flags, source,
                                     parse_result.error));
    return std::nullopt;
  }

  ZoneList<RegExpInstruction> bytecode = ExperimentalRegExpCompiler::Compile(
      parse_result.tree, JSRegExp::AsRegExpFlags(re_data->flags()), &zone);

  CompilationResult result;
  result.bytecode = VectorToByteArray(isolate, bytecode.ToVector());
  result.capture_name_map =
      RegExp::CreateCaptureNameMap(isolate, parse_result.named_captures);
  return result;
}

}  // namespace

bool ExperimentalRegExp::Compile(Isolate* isolate,
                                 DirectHandle<IrRegExpData> re_data) {
  DCHECK(v8_flags.enable_experimental_regexp_engine);
  DCHECK_EQ(re_data->type_tag(), RegExpData::Type::EXPERIMENTAL);
#ifdef VERIFY_HEAP
  if (v8_flags.verify_heap) re_data->IrRegExpDataVerify(isolate);
#endif

  DirectHandle<String> source(re_data->source(), isolate);
  if (v8_flags.trace_experimental_regexp_engine) {
    StdoutStream{} << "Compiling experimental regexp " << *source << std::endl;
  }

  std::optional<CompilationResult> compilation_result =
      CompileImpl(isolate, re_data);
  if (!compilation_result.has_value()) {
    DCHECK(isolate->has_exception());
    return false;
  }

  re_data->SetBytecodeForExperimental(isolate, *compilation_result->bytecode);
  re_data->set_capture_name_map(compilation_result->capture_name_map);

  return true;
}

base::Vector<RegExpInstruction> AsInstructionSequence(
    Tagged<TrustedByteArray> raw_bytes) {
  RegExpInstruction* inst_begin =
      reinterpret_cast<RegExpInstruction*>(raw_bytes->begin());
  int inst_num = raw_bytes->length() / sizeof(RegExpInstruction);
  DCHECK_EQ(sizeof(RegExpInstruction) * inst_num, raw_bytes->length());
  return base::Vector<RegExpInstruction>(inst_begin, inst_num);
}

namespace {

int32_t ExecRawImpl(Isolate* isolate, RegExp::CallOrigin call_origin,
                    Tagged<TrustedByteArray> bytecode, Tagged<String> subject,
                    int capture_count, int32_t* output_registers,
                    int32_t output_register_count, int32_t subject_index) {
  DisallowGarbageCollection no_gc;
  // TODO(cbruni): remove once gcmole is fixed.
  DisableGCMole no_gc_mole;

  int register_count_per_match =
      JSRegExp::RegistersForCaptureCount(capture_count);

  int32_t result;
  DCHECK(subject->IsFlat());
  Zone zone(isolate->allocator(), ZONE_NAME);
  result = ExperimentalRegExpInterpreter::FindMatches(
      isolate, call_origin, bytecode, register_count_per_match, subject,
      subject_index, output_registers, output_register_count, &zone);
  return result;
}

}  // namespace

// Returns the number of matches.
int32_t ExperimentalRegExp::ExecRaw(Isolate* isolate,
                                    RegExp::CallOrigin call_origin,
                                    Tagged<IrRegExpData> regexp_data,
                                    Tagged<String> subject,
                                    int32_t* output_registers,
                                    int32_t output_register_count,
                                    int32_t subject_index) {
  CHECK(v8_flags.enable_experimental_regexp_engine);
  DisallowGarbageCollection no_gc;

  if (v8_flags.trace_experimental_regexp_engine) {
    StdoutStream{} << "Executing experimental regexp " << regexp_data->source()
                   << std::endl;
  }

  static constexpr bool kIsLatin1 = true;
  Tagged<TrustedByteArray> bytecode = regexp_data->bytecode(kIsLatin1);

  return ExecRawImpl(isolate, call_origin, bytecode, subject,
                     regexp_data->capture_count(), output_registers,
                     output_register_count, subject_index);
}

int32_t ExperimentalRegExp::MatchForCallFromJs(
    Address subject, int32_t start_position, Address input_start,
    Address input_end, int* output_registers, int32_t output_register_count,
    RegExp::CallOrigin call_origin, Isolate* isolate, Address regexp_data) {
  DCHECK(v8_flags.enable_experimental_regexp_engine);
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

  return ExecRaw(isolate, RegExp::kFromJs, regexp_data_obj, subject_string,
                 output_registers, output_register_count, start_position);
}

// static
std::optional<int> ExperimentalRegExp::Exec(
    Isolate* isolate, DirectHandle<IrRegExpData> regexp_data,
    Handle<String> subject, int index, int32_t* result_offsets_vector,
    uint32_t result_offsets_vector_length) {
  DCHECK(v8_flags.enable_experimental_regexp_engine);
  DCHECK_EQ(regexp_data->type_tag(), RegExpData::Type::EXPERIMENTAL);
#ifdef VERIFY_HEAP
  if (v8_flags.verify_heap) regexp_data->IrRegExpDataVerify(isolate);
#endif

  if (!IsCompiled(regexp_data, isolate) && !Compile(isolate, regexp_data)) {
    DCHECK(isolate->has_exception());
    return {};
  }

  DCHECK(IsCompiled(regexp_data, isolate));

  subject = String::Flatten(isolate, subject);

  DCHECK_GE(result_offsets_vector_length,
            JSRegExp::RegistersForCaptureCount(regexp_data->capture_count()));

  do {
    int num_matches =
        ExecRaw(isolate, RegExp::kFromRuntime, *regexp_data, *subject,
                result_offsets_vector, result_offsets_vector_length, index);

    if (num_matches > 0) {
      DCHECK_LE(num_matches * JSRegExp::RegistersForCaptureCount(
                                  regexp_data->capture_count()),
                result_offsets_vector_length);
      return num_matches;
    } else if (num_matches == 0) {
      return num_matches;
    } else {
      DCHECK_LT(num_matches, 0);
      if (num_matches == RegExp::kInternalRegExpRetry) {
        // Re-run execution.
        continue;
      }
      DCHECK(isolate->has_exception());
      return {};
    }
  } while (true);
  UNREACHABLE();
}

int32_t ExperimentalRegExp::OneshotExecRaw(
    Isolate* isolate, DirectHandle<IrRegExpData> regexp_data,
    DirectHandle<String> subject, int32_t* output_registers,
    int32_t output_register_count, int32_t subject_index) {
  CHECK(v8_flags.enable_experimental_regexp_engine_on_excessive_backtracks);

  if (v8_flags.trace_experimental_regexp_engine) {
    StdoutStream{} << "Experimental execution (oneshot) of regexp "
                   << regexp_data->source() << std::endl;
  }

  std::optional<CompilationResult> compilation_result =
      CompileImpl(isolate, regexp_data);
  if (!compilation_result.has_value()) return RegExp::kInternalRegExpException;

  DisallowGarbageCollection no_gc;
  return ExecRawImpl(isolate, RegExp::kFromRuntime,
                     *compilation_result->bytecode, *subject,
                     regexp_data->capture_count(), output_registers,
                     output_register_count, subject_index);
}

std::optional<int> ExperimentalRegExp::OneshotExec(
    Isolate* isolate, DirectHandle<IrRegExpData> regexp_data,
    DirectHandle<String> subject, int subject_index,
    int32_t* result_offsets_vector, uint32_t result_offsets_vector_length) {
  DCHECK(v8_flags.enable_experimental_regexp_engine_on_excessive_backtracks);

  do {
    int num_matches =
        OneshotExecRaw(isolate, regexp_data, subject, result_offsets_vector,
                       result_offsets_vector_length, subject_index);

    if (num_matches > 0) {
      DCHECK_LE(num_matches * JSRegExp::RegistersForCaptureCount(
                                  regexp_data->capture_count()),
                result_offsets_vector_length);
      return num_matches;
    } else if (num_matches == 0) {
      return num_matches;
    } else {
      DCHECK_LT(num_matches, 0);
      if (num_matches == RegExp::kInternalRegExpRetry) {
        // Re-run execution.
        continue;
      }
      DCHECK(isolate->has_exception());
      return {};
    }
  } while (true);
  UNREACHABLE();
}

}  // namespace v8::internal
```