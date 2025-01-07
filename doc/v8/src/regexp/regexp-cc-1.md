Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/regexp/regexp.cc`.

Here's a breakdown of the thought process to achieve the requested summary:

1. **Identify the Core Functionality:** The filename `regexp.cc` strongly suggests this code deals with regular expressions within the V8 engine. The code contains functions like `IrregexpExec`, `Compile`, and mentions "bytecode" and "jitted code execution," indicating different execution paths for regex matching.

2. **Analyze Key Functions:**  Go through the main functions in the snippet and understand their purpose.
    * `IrregexpExec`: Seems to be the main entry point for executing Irregexp (V8's internal regex engine). It handles flattening the subject string, potentially forcing tier-up (optimization), preparing for execution, and calling the raw execution function. It also deals with fallback to the experimental engine and exception handling.
    * `IrregexpExecRaw`: This appears to be the core logic for actually matching the regex using the Irregexp interpreter or compiled code. It handles retries if the string representation changes.
    * `Compile`: This function is responsible for compiling the regular expression pattern. It involves parsing, optimization, and generating either native machine code or bytecode. It also handles error conditions and incorporates flags.
    * `RegExp::SetLastMatchInfo`: Updates the `RegExpMatchInfo` object, storing the results of the last regex match.
    * `RegExpGlobalExecRunner`:  Manages the execution of global regular expressions (using the `/g` flag). It handles multiple matches and advances the search.
    * `RegExpResultsCache`:  Implements a cache to store the results of regular expression operations, potentially improving performance for repeated calls with the same inputs.

3. **Look for Keywords and Patterns:** Identify important concepts and patterns in the code:
    * **Tier-up:** This refers to optimizing regex execution by compiling to native code. The code checks string length and complexity to trigger tier-up.
    * **Bytecode vs. Native Code:**  V8 uses both interpreted bytecode and compiled machine code for regex execution.
    * **Experimental Engine:**  There's a fallback mechanism to a potentially newer or different experimental regex engine.
    * **Global Flag:** Special handling for regular expressions with the `g` flag, requiring multiple matches.
    * **Caching:**  The `RegExpResultsCache` indicates performance optimization through result storage.
    * **Error Handling:** The code checks for exceptions and various error conditions during compilation and execution.
    * **Flags:** Regular expression flags (like `i`, `m`, `g`, `u`, `y`) are considered during compilation and execution.

4. **Infer Relationships to JavaScript:**  Consider how these C++ functions relate to JavaScript's `RegExp` object and its methods.
    * `IrregexpExec` is directly related to `String.prototype.match()`, `String.prototype.exec()`, and potentially `RegExp.prototype.exec()`.
    * `Compile` is invoked when a `RegExp` object is created or when V8 decides to optimize a regex.
    * The global execution logic corresponds to the behavior of `RegExp.prototype.exec()` when called repeatedly on a global regex.

5. **Consider Edge Cases and Potential Errors:**  Think about common mistakes developers might make when using regular expressions in JavaScript that this code might address:
    * **Stack Overflow:** The code mentions a check for `RegExpError::kStackOverflow` during compilation, which can occur with very complex or deeply nested regexes.
    * **Performance Issues:** The tier-up mechanism and result caching are clearly aimed at improving performance.
    * **Incorrect Global Matching:** The `RegExpGlobalExecRunner` deals with the complexities of global matching and advancing the search correctly.

6. **Structure the Summary:** Organize the findings into logical sections:
    * **Core Functionality:** Briefly state the main purpose of the code.
    * **Key Functions and Components:** Describe the roles of the most important functions and data structures.
    * **Relationship to JavaScript:**  Connect the C++ code to corresponding JavaScript features.
    * **Code Logic and Assumptions (with examples):**  Illustrate specific code behaviors with hypothetical inputs and outputs.
    * **Common Programming Errors:**  Provide examples of user errors related to the code's functionality.
    * **Summary of Functionality:**  Provide a concise overall summary.

7. **Refine and Elaborate:** Add details and explanations to make the summary more comprehensive and easier to understand. For instance, explaining what "tier-up" means or how the result cache works.

8. **Address Specific Instructions:** Ensure all parts of the prompt are addressed, such as mentioning Torque, JavaScript examples, input/output examples, and common errors. Since the prompt mentions ".tq", explicitly state that this file is C++ and not Torque.

By following these steps, we can create a detailed and accurate summary of the provided C++ code, addressing all aspects of the user's request.这是V8源代码 `v8/src/regexp/regexp.cc` 的第二部分，延续了第一部分关于正则表达式功能的实现。让我们来归纳一下这部分代码的功能：

**归纳 `v8/src/regexp/regexp.cc` 的功能 (结合第一部分和第二部分):**

总的来说，`v8/src/regexp/regexp.cc` 文件负责 **V8 引擎中正则表达式的核心实现**。它包含了编译、执行和管理正则表达式的逻辑，涵盖了解释执行和编译成机器码执行两种方式，并提供了一些优化策略。

**具体功能点 (第二部分细化):**

* **正则表达式匹配的执行 (Irregexp):**
    * **`RegExpImpl::IrregexpExec`:**  这是执行 Irregexp 引擎（V8 自研的正则表达式引擎）的主要入口点。它负责：
        * **扁平化 (Flattening) 主题字符串:**  确保字符串的内部表示形式方便匹配。
        * **性能优化 (Tier-Up):**  根据主题字符串的长度和正则表达式的复杂度，决定是否将正则表达式编译成更高效的机器码执行，以提升性能。这被称为 "tier-up"。
        * **准备执行 (IrregexpPrepare):**  为 Irregexp 引擎的执行做必要的准备工作。
        * **实际执行 (IrregexpExecRaw):**  调用底层的 Irregexp 解释器或已编译的代码来执行匹配。
        * **回退机制 (Fallback to Experimental):**  如果 Irregexp 执行失败并返回特定的错误码，则会尝试使用实验性的正则表达式引擎进行匹配。
        * **异常处理:**  捕获并处理执行过程中可能出现的异常。
    * **`RegExpImpl::IrregexpExecRaw`:**  真正执行 Irregexp 引擎匹配的核心函数。它可能使用解释器或已编译的机器码。它还处理在匹配过程中字符串表示形式发生变化时进行重试的情况。
* **设置最后匹配信息 (`RegExp::SetLastMatchInfo`):**  该函数用于更新 `RegExpMatchInfo` 对象，存储最后一次正则表达式匹配的结果，包括捕获组的信息。这个信息对于 JavaScript 中的 `$1`, `$2` 等捕获组变量以及 `RegExp.lastMatch` 等属性非常重要。
* **编译正则表达式 (`RegExpImpl::Compile`):**
    * 接收正则表达式模式、标志等信息，并将其编译成可执行的代码或字节码。
    * **优化 (Optimization):**  尝试对正则表达式进行优化，例如避免生成过多的代码。
    * **频率收集 (Frequency Collation):**  通过分析样本字符串中的字符频率，辅助编译器的优化决策。
    * **生成汇编代码/字节码:**  根据目标架构和配置，选择生成本地机器码或字节码。
    * **回溯限制 (Backtrack Limit):**  设置正则表达式引擎回溯的次数限制，防止因过于复杂的正则表达式导致的性能问题或拒绝服务攻击。
    * **全局模式 (Global Mode):**  处理带有 `g` 标志的全局正则表达式。
    * **打印调试信息:**  如果启用了相应的标志，可以打印生成的汇编代码或字节码。
* **全局正则表达式执行器 (`RegExpGlobalExecRunner`):**  专门用于处理带有 `g` (global) 标志的正则表达式。它负责在一个字符串中查找所有匹配项，并逐步返回结果。
    * **迭代匹配:**  重复执行正则表达式，从上一次匹配的结束位置开始查找新的匹配项。
    * **处理零长度匹配:**  需要特殊处理匹配结果为空的情况，避免无限循环。
* **正则表达式结果缓存 (`RegExpResultsCache`):**  用于缓存正则表达式操作的结果，例如 `String.prototype.split()` 的结果或全局匹配的结果，以提高性能。
    * **查找缓存 (`Lookup`):**  尝试从缓存中获取之前计算过的结果。
    * **添加缓存 (`Enter`):**  将新的计算结果添加到缓存中。
    * **清除缓存 (`Clear`):**  清除缓存中的所有条目。
* **原子正则表达式缓存 (`RegExpResultsCache_MatchGlobalAtom`):**  针对全局原子正则表达式（简单的字符串匹配）的优化缓存。
* **标志位输出 (`operator<<`):**  提供了一种将 `RegExpFlags` 枚举值转换为可读字符串的方式，用于调试和日志记录。

**与 JavaScript 功能的关系：**

这部分代码是 V8 引擎实现 JavaScript `RegExp` 对象的关键部分。以下 JavaScript 功能直接或间接地依赖于这些 C++ 代码：

* **`RegExp` 构造函数:** 当你创建一个新的 `RegExp` 对象时，V8 会调用 `RegExpImpl::Compile` 来编译正则表达式。
* **`String.prototype.match()`:**  在内部会调用 `RegExpImpl::IrregexpExec` 或其他匹配函数来执行正则表达式匹配。
* **`String.prototype.exec()`:**  与 `match()` 类似，也依赖于底层的正则表达式执行机制。
* **`RegExp.prototype.exec()`:**  直接调用 V8 的正则表达式执行逻辑。
* **`String.prototype.search()`:**  内部也使用正则表达式匹配。
* **`String.prototype.split()`:**  可以使用正则表达式作为分隔符，V8 会利用这里的代码进行分割。
* **`String.prototype.replace()`:**  可以使用正则表达式进行替换，V8 的正则表达式引擎负责查找匹配项。
* **捕获组:**  `RegExp::SetLastMatchInfo` 记录的捕获组信息会被 JavaScript 访问，例如 `$1`, `$2` 等。
* **全局匹配 (`/g` 标志):** `RegExpGlobalExecRunner` 实现了全局匹配的逻辑。

**代码逻辑推理 (假设输入与输出):**

假设我们有以下 JavaScript 代码：

```javascript
const regex = /ab*c/;
const str = 'abbbcdefabc';
```

当 V8 执行 `regex.test(str)` 或 `str.match(regex)` 时，会涉及以下逻辑：

1. **编译:** 如果 `regex` 对象是第一次使用，`RegExpImpl::Compile` 会被调用，将 `/ab*c/` 编译成内部表示。
2. **执行:** `RegExpImpl::IrregexpExec` 会被调用。
3. **`IrregexpExecRaw`:** 底层执行器会尝试在 `str` 中查找与 `/ab*c/` 匹配的子字符串。
4. **匹配成功:**  在 `str` 的开头找到 "abbbc"。
5. **`RegExp::SetLastMatchInfo`:**  如果使用了 `match()` 且正则表达式包含捕获组，匹配的信息（例如 "abbbc" 以及可能的捕获组）会被存储到 `RegExpMatchInfo` 中。
6. **输出:** `regex.test(str)` 返回 `true`， `str.match(regex)` 返回 `["abbbc"]` (如果正则表达式没有全局标志)。

如果正则表达式是全局的：

```javascript
const globalRegex = /ab*c/g;
const str = 'abbbcdefabc';
let match;
while ((match = globalRegex.exec(str)) !== null) {
  console.log(match[0]);
}
```

1. **编译:**  `RegExpImpl::Compile` 会被调用，并标记为全局。
2. **执行:**  第一次调用 `globalRegex.exec(str)` 会调用 `RegExpImpl::IrregexpExec`。
3. **`RegExpGlobalExecRunner`:** 由于是全局匹配，V8 会使用 `RegExpGlobalExecRunner` 来管理多次匹配。
4. **迭代匹配:**
   - 第一次匹配到 "abbbc"。
   - `RegExpGlobalExecRunner` 会将下一次搜索的起始位置设置为 "abbbc" 之后。
   - 第二次匹配到 "abc"。
   - 当没有更多匹配项时，`globalRegex.exec(str)` 返回 `null`。

**用户常见的编程错误:**

* **复杂的正则表达式导致性能问题或栈溢出:**  例如，使用没有明确终结条件的重复模式 (如 `(a+)+`) 可能导致回溯过多，甚至触发 `RegExpError::kStackOverflow`。V8 的回溯限制机制旨在缓解这个问题。
  ```javascript
  // 可能导致性能问题的正则表达式
  const problematicRegex = /(a+)+b/;
  const longString = 'a'.repeat(1000) + 'b';
  problematicRegex.test(longString); // 可能很慢甚至崩溃
  ```
* **忘记处理全局匹配的 `lastIndex` 属性:**  当使用全局正则表达式的 `exec()` 方法时，需要理解 `lastIndex` 属性的行为。如果不正确地重置 `lastIndex`，可能会导致意外的结果。
  ```javascript
  const globalRegex = /test/g;
  const str = 'test string test';

  globalRegex.exec(str); // 匹配 "test"，lastIndex 为 4
  globalRegex.exec(str); // 匹配 "test"，lastIndex 为 13
  globalRegex.lastIndex = 0; // 重置 lastIndex
  globalRegex.exec(str); // 重新从头开始匹配
  ```
* **不理解 Unicode 相关的正则表达式标志 (`u`):**  在处理包含 Unicode 字符的字符串时，如果忘记使用 `u` 标志，可能会导致正则表达式的行为不符合预期。
  ```javascript
  const emojiRegexWithoutU = /😀/;
  const emojiRegexWithU = /😀/u;
  const emoji = '😀';

  emojiRegexWithoutU.test(emoji); // 返回 false (会将 emoji 拆成两个 code units)
  emojiRegexWithU.test(emoji);    // 返回 true
  ```
* **错误地使用锚点 (`^`, `$`) 进行全局匹配:**  锚点通常与全局匹配一起使用时可能不会产生预期的效果，因为全局匹配会在字符串中查找多个匹配项。
  ```javascript
  const anchoredGlobalRegex = /^test/gm;
  const multiLineString = `test\nstring\ntest`;
  let match;
  while ((match = anchoredGlobalRegex.exec(multiLineString)) !== null) {
    console.log(match[0]); // 只会匹配第一行的 "test"
  }
  ```

**关于 `.tq` 结尾:**

你提到 "如果 v8/src/regexp/regexp.cc 以 .tq 结尾，那它是个 v8 torque 源代码"。 **`v8/src/regexp/regexp.cc` 文件不是以 `.tq` 结尾，所以它不是一个 Torque 源代码文件。** 这是一个标准的 C++ 源代码文件。

Torque 是 V8 使用的一种用于生成高效的运行时代码的语言。虽然正则表达式的某些部分（特别是内置函数的实现）可能会使用 Torque，但核心的正则表达式引擎实现，如 `regexp.cc` 中的代码，主要是用 C++ 编写的。

希望这个归纳能够帮助你理解 `v8/src/regexp/regexp.cc` 这部分代码的功能。

Prompt: 
```
这是目录为v8/src/regexp/regexp.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/regexp/regexp.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
  is_one_byte = subject->IsOneByteRepresentation();
    } while (true);
    UNREACHABLE();
  } else {
    DCHECK(regexp_data->ShouldProduceBytecode());

    do {
      int result = IrregexpInterpreter::MatchForCallFromRuntime(
          isolate, regexp_data, subject, output, output_size, index);
      DCHECK_IMPLIES(result == IrregexpInterpreter::EXCEPTION,
                     isolate->has_exception());

      static_assert(IrregexpInterpreter::FAILURE == 0);
      static_assert(IrregexpInterpreter::SUCCESS == 1);
      static_assert(IrregexpInterpreter::FALLBACK_TO_EXPERIMENTAL < 0);
      static_assert(IrregexpInterpreter::EXCEPTION < 0);
      static_assert(IrregexpInterpreter::RETRY < 0);
      if (result >= IrregexpInterpreter::FAILURE) {
        return result;
      }

      if (result == IrregexpInterpreter::RETRY) {
        // The string has changed representation, and we must restart the
        // match. We need to reset the tier up to start over with compilation.
        if (v8_flags.regexp_tier_up) regexp_data->ResetLastTierUpTick();
        is_one_byte = subject->IsOneByteRepresentation();
        EnsureCompiledIrregexp(isolate, regexp_data, subject, is_one_byte);
      } else {
        DCHECK(result == IrregexpInterpreter::EXCEPTION ||
               result == IrregexpInterpreter::FALLBACK_TO_EXPERIMENTAL);
        return result;
      }
    } while (true);
    UNREACHABLE();
  }
}

std::optional<int> RegExpImpl::IrregexpExec(
    Isolate* isolate, DirectHandle<IrRegExpData> regexp_data,
    Handle<String> subject, int previous_index, int32_t* result_offsets_vector,
    uint32_t result_offsets_vector_length) {
  subject = String::Flatten(isolate, subject);

#ifdef DEBUG
  if (v8_flags.trace_regexp_bytecodes && regexp_data->ShouldProduceBytecode()) {
    PrintF("\n\nRegexp match:   /%s/\n\n",
           regexp_data->source()->ToCString().get());
    PrintF("\n\nSubject string: '%s'\n\n", subject->ToCString().get());
  }
#endif

  const int original_register_count =
      JSRegExp::RegistersForCaptureCount(regexp_data->capture_count());

  // Maybe force early tier up:
  if (v8_flags.regexp_tier_up) {
    if (subject->length() >= JSRegExp::kTierUpForSubjectLengthValue) {
      // For very long subject strings, the regexp interpreter is currently much
      // slower than the jitted code execution. If the tier-up strategy is
      // turned on, we want to avoid this performance penalty so we eagerly
      // tier-up if the subject string length is equal or greater than the given
      // heuristic value.
      regexp_data->MarkTierUpForNextExec();
      if (v8_flags.trace_regexp_tier_up) {
        PrintF(
            "Forcing tier-up for very long strings in "
            "RegExpImpl::IrregexpExec\n");
      }
    } else if (static_cast<uint32_t>(original_register_count) <
               result_offsets_vector_length) {
      // Tier up because the interpreter doesn't do global execution.
      Cast<IrRegExpData>(regexp_data)->MarkTierUpForNextExec();
      if (v8_flags.trace_regexp_tier_up) {
        PrintF(
            "Forcing tier-up of RegExpData object %p for global irregexp "
            "mode\n",
            reinterpret_cast<void*>(regexp_data->ptr()));
      }
    }
  }

  int output_register_count =
      RegExpImpl::IrregexpPrepare(isolate, regexp_data, subject);
  if (output_register_count < 0) {
    DCHECK(isolate->has_exception());
    return {};
  }

  // TODO(jgruber): Consider changing these into DCHECKs once we're convinced
  // the conditions hold.
  CHECK_EQ(original_register_count, output_register_count);
  CHECK_LE(static_cast<uint32_t>(output_register_count),
           result_offsets_vector_length);

  RegExpStackScope stack_scope(isolate);

  int res = RegExpImpl::IrregexpExecRaw(isolate, regexp_data, subject,
                                        previous_index, result_offsets_vector,
                                        result_offsets_vector_length);

  if (res >= RegExp::RE_SUCCESS) {
    DCHECK_LE(res * output_register_count, result_offsets_vector_length);
    return res;
  } else if (res == RegExp::RE_FALLBACK_TO_EXPERIMENTAL) {
    return ExperimentalRegExp::OneshotExec(
        isolate, regexp_data, subject, previous_index, result_offsets_vector,
        result_offsets_vector_length);
  } else if (res == RegExp::RE_EXCEPTION) {
    DCHECK(isolate->has_exception());
    return {};
  } else {
    DCHECK(res == RegExp::RE_FAILURE);
    return 0;
  }
}

// static
Handle<RegExpMatchInfo> RegExp::SetLastMatchInfo(
    Isolate* isolate, Handle<RegExpMatchInfo> last_match_info,
    DirectHandle<String> subject, int capture_count, int32_t* match) {
  Handle<RegExpMatchInfo> result =
      RegExpMatchInfo::ReserveCaptures(isolate, last_match_info, capture_count);
  if (*result != *last_match_info) {
    if (*last_match_info == *isolate->regexp_last_match_info()) {
      // This inner condition is only needed for special situations like the
      // regexp fuzzer, where we pass our own custom RegExpMatchInfo to
      // RegExpImpl::Exec; there actually want to bypass the Isolate's match
      // info and execute the regexp without side effects.
      isolate->native_context()->set_regexp_last_match_info(*result);
    }
  }

  int capture_register_count =
      JSRegExp::RegistersForCaptureCount(capture_count);
  DisallowGarbageCollection no_gc;
  if (match != nullptr) {
    for (int i = 0; i < capture_register_count; i += 2) {
      result->set_capture(i, match[i]);
      result->set_capture(i + 1, match[i + 1]);
    }
  }
  result->set_last_subject(*subject);
  result->set_last_input(*subject);
  return result;
}

// static
void RegExp::DotPrintForTesting(const char* label, RegExpNode* node) {
  DotPrinter::DotPrint(label, node);
}

namespace {

// Returns true if we've either generated too much irregex code within this
// isolate, or the pattern string is too long.
bool TooMuchRegExpCode(Isolate* isolate, DirectHandle<String> pattern) {
  // Limit the space regexps take up on the heap.  In order to limit this we
  // would like to keep track of the amount of regexp code on the heap.  This
  // is not tracked, however.  As a conservative approximation we track the
  // total regexp code compiled including code that has subsequently been freed
  // and the total executable memory at any point.
  static constexpr size_t kRegExpExecutableMemoryLimit = 16 * MB;
  static constexpr size_t kRegExpCompiledLimit = 1 * MB;

  Heap* heap = isolate->heap();
  if (pattern->length() > RegExp::kRegExpTooLargeToOptimize) return true;
  return (isolate->total_regexp_code_generated() > kRegExpCompiledLimit &&
          heap->CommittedMemoryExecutable() > kRegExpExecutableMemoryLimit);
}

}  // namespace

// static
bool RegExp::CompileForTesting(Isolate* isolate, Zone* zone,
                               RegExpCompileData* data, RegExpFlags flags,
                               Handle<String> pattern,
                               Handle<String> sample_subject,
                               bool is_one_byte) {
  uint32_t backtrack_limit = JSRegExp::kNoBacktrackLimit;
  return RegExpImpl::Compile(isolate, zone, data, flags, pattern,
                             sample_subject, is_one_byte, backtrack_limit);
}

bool RegExpImpl::Compile(Isolate* isolate, Zone* zone, RegExpCompileData* data,
                         RegExpFlags flags, Handle<String> pattern,
                         Handle<String> sample_subject, bool is_one_byte,
                         uint32_t& backtrack_limit) {
  if (JSRegExp::RegistersForCaptureCount(data->capture_count) >
      RegExpMacroAssembler::kMaxRegisterCount) {
    data->error = RegExpError::kTooLarge;
    return false;
  }

  RegExpCompiler compiler(isolate, zone, data->capture_count, flags,
                          is_one_byte);

  if (compiler.optimize()) {
    compiler.set_optimize(!TooMuchRegExpCode(isolate, pattern));
  }

  // Sample some characters from the middle of the string.
  static const int kSampleSize = 128;

  sample_subject = String::Flatten(isolate, sample_subject);
  uint32_t start, end;
  if (sample_subject->length() > kSampleSize) {
    start = (sample_subject->length() - kSampleSize) / 2;
    end = start + kSampleSize;
  } else {
    start = 0;
    end = sample_subject->length();
  }
  for (uint32_t i = start; i < end; i++) {
    compiler.frequency_collator()->CountCharacter(sample_subject->Get(i));
  }

  data->node = compiler.PreprocessRegExp(data, is_one_byte);
  data->error = AnalyzeRegExp(isolate, is_one_byte, flags, data->node);
  if (data->error != RegExpError::kNone) {
    return false;
  }

  if (v8_flags.trace_regexp_graph) DotPrinter::DotPrint("Start", data->node);

  // Create the correct assembler for the architecture.
  std::unique_ptr<RegExpMacroAssembler> macro_assembler;
  if (data->compilation_target == RegExpCompilationTarget::kNative) {
    // Native regexp implementation.
    DCHECK(!v8_flags.jitless);

    NativeRegExpMacroAssembler::Mode mode =
        is_one_byte ? NativeRegExpMacroAssembler::LATIN1
                    : NativeRegExpMacroAssembler::UC16;

    const int output_register_count =
        JSRegExp::RegistersForCaptureCount(data->capture_count);
#if V8_TARGET_ARCH_IA32
    macro_assembler.reset(new RegExpMacroAssemblerIA32(isolate, zone, mode,
                                                       output_register_count));
#elif V8_TARGET_ARCH_X64
    macro_assembler.reset(new RegExpMacroAssemblerX64(isolate, zone, mode,
                                                      output_register_count));
#elif V8_TARGET_ARCH_ARM
    macro_assembler.reset(new RegExpMacroAssemblerARM(isolate, zone, mode,
                                                      output_register_count));
#elif V8_TARGET_ARCH_ARM64
    macro_assembler.reset(new RegExpMacroAssemblerARM64(isolate, zone, mode,
                                                        output_register_count));
#elif V8_TARGET_ARCH_S390X
    macro_assembler.reset(new RegExpMacroAssemblerS390(isolate, zone, mode,
                                                       output_register_count));
#elif V8_TARGET_ARCH_PPC64
    macro_assembler.reset(new RegExpMacroAssemblerPPC(isolate, zone, mode,
                                                      output_register_count));
#elif V8_TARGET_ARCH_MIPS64
    macro_assembler.reset(new RegExpMacroAssemblerMIPS(isolate, zone, mode,
                                                       output_register_count));
#elif V8_TARGET_ARCH_RISCV64
    macro_assembler.reset(new RegExpMacroAssemblerRISCV(isolate, zone, mode,
                                                        output_register_count));
#elif V8_TARGET_ARCH_RISCV32
    macro_assembler.reset(new RegExpMacroAssemblerRISCV(isolate, zone, mode,
                                                        output_register_count));
#elif V8_TARGET_ARCH_LOONG64
    macro_assembler.reset(new RegExpMacroAssemblerLOONG64(
        isolate, zone, mode, output_register_count));
#else
#error "Unsupported architecture"
#endif
  } else {
    DCHECK_EQ(data->compilation_target, RegExpCompilationTarget::kBytecode);
    // Interpreted regexp implementation.
    macro_assembler.reset(new RegExpBytecodeGenerator(isolate, zone));
  }

  macro_assembler->set_slow_safe(TooMuchRegExpCode(isolate, pattern));
  if (v8_flags.enable_experimental_regexp_engine_on_excessive_backtracks &&
      ExperimentalRegExp::CanBeHandled(data->tree, pattern, flags,
                                       data->capture_count)) {
    if (backtrack_limit == JSRegExp::kNoBacktrackLimit) {
      backtrack_limit = v8_flags.regexp_backtracks_before_fallback;
    } else {
      backtrack_limit = std::min(
          backtrack_limit, v8_flags.regexp_backtracks_before_fallback.value());
    }
    macro_assembler->set_backtrack_limit(backtrack_limit);
    macro_assembler->set_can_fallback(true);
  } else {
    macro_assembler->set_backtrack_limit(backtrack_limit);
    macro_assembler->set_can_fallback(false);
  }

  // Inserted here, instead of in Assembler, because it depends on information
  // in the AST that isn't replicated in the Node structure.
  bool is_end_anchored = data->tree->IsAnchoredAtEnd();
  bool is_start_anchored = data->tree->IsAnchoredAtStart();
  int max_length = data->tree->max_match();
  static const int kMaxBacksearchLimit = 1024;
  if (is_end_anchored && !is_start_anchored && !IsSticky(flags) &&
      max_length < kMaxBacksearchLimit) {
    macro_assembler->SetCurrentPositionFromEnd(max_length);
  }

  if (IsGlobal(flags)) {
    RegExpMacroAssembler::GlobalMode mode = RegExpMacroAssembler::GLOBAL;
    if (data->tree->min_match() > 0) {
      mode = RegExpMacroAssembler::GLOBAL_NO_ZERO_LENGTH_CHECK;
    } else if (IsEitherUnicode(flags)) {
      mode = RegExpMacroAssembler::GLOBAL_UNICODE;
    }
    macro_assembler->set_global_mode(mode);
  }

  RegExpMacroAssembler* macro_assembler_ptr = macro_assembler.get();
#ifdef DEBUG
  std::unique_ptr<RegExpMacroAssembler> tracer_macro_assembler;
  if (v8_flags.trace_regexp_assembler) {
    tracer_macro_assembler.reset(
        new RegExpMacroAssemblerTracer(isolate, macro_assembler_ptr));
    macro_assembler_ptr = tracer_macro_assembler.get();
  }
#endif

  RegExpCompiler::CompilationResult result = compiler.Assemble(
      isolate, macro_assembler_ptr, data->node, data->capture_count, pattern);

  // Code / bytecode printing.
  {
#ifdef ENABLE_DISASSEMBLER
    if (v8_flags.print_regexp_code &&
        data->compilation_target == RegExpCompilationTarget::kNative) {
      CodeTracer::Scope trace_scope(isolate->GetCodeTracer());
      OFStream os(trace_scope.file());
      auto code = Cast<Code>(result.code);
      std::unique_ptr<char[]> pattern_cstring = pattern->ToCString();
      code->Disassemble(pattern_cstring.get(), os, isolate);
    }
#endif
    if (v8_flags.print_regexp_bytecode &&
        data->compilation_target == RegExpCompilationTarget::kBytecode) {
      auto bytecode = Cast<TrustedByteArray>(result.code);
      std::unique_ptr<char[]> pattern_cstring = pattern->ToCString();
      RegExpBytecodeDisassemble(bytecode->begin(), bytecode->length(),
                                pattern_cstring.get());
    }
  }

  if (result.error != RegExpError::kNone) {
    if (v8_flags.correctness_fuzzer_suppressions &&
        result.error == RegExpError::kStackOverflow) {
      FATAL("Aborting on stack overflow");
    }
    data->error = result.error;
  }

  data->code = result.code;
  data->register_count = result.num_registers;

  return result.Succeeded();
}

RegExpGlobalExecRunner::RegExpGlobalExecRunner(Handle<RegExpData> regexp_data,
                                               Handle<String> subject,
                                               Isolate* isolate)
    : result_vector_scope_(isolate),
      regexp_data_(regexp_data),
      subject_(subject),
      isolate_(isolate) {
  DCHECK(IsGlobal(JSRegExp::AsRegExpFlags(regexp_data->flags())));

  switch (regexp_data_->type_tag()) {
    case RegExpData::Type::ATOM: {
      registers_per_match_ = JSRegExp::kAtomRegisterCount;
      register_array_size_ = Isolate::kJSRegexpStaticOffsetsVectorSize;
      break;
    }
    case RegExpData::Type::IRREGEXP: {
      registers_per_match_ = RegExpImpl::IrregexpPrepare(
          isolate_, Cast<IrRegExpData>(regexp_data_), subject_);
      if (registers_per_match_ < 0) {
        num_matches_ = -1;  // Signal exception.
        return;
      }
      if (Cast<IrRegExpData>(regexp_data_)->ShouldProduceBytecode()) {
        // Global loop in interpreted regexp is not implemented.  We choose the
        // size of the offsets vector so that it can only store one match.
        register_array_size_ = registers_per_match_;
      } else {
        register_array_size_ = std::max(
            {registers_per_match_, Isolate::kJSRegexpStaticOffsetsVectorSize});
      }
      break;
    }
    case RegExpData::Type::EXPERIMENTAL: {
      if (!ExperimentalRegExp::IsCompiled(Cast<IrRegExpData>(regexp_data_),
                                          isolate_) &&
          !ExperimentalRegExp::Compile(isolate_,
                                       Cast<IrRegExpData>(regexp_data_))) {
        DCHECK(isolate->has_exception());
        num_matches_ = -1;  // Signal exception.
        return;
      }
      registers_per_match_ = JSRegExp::RegistersForCaptureCount(
          Cast<IrRegExpData>(regexp_data_)->capture_count());
      register_array_size_ = std::max(
          {registers_per_match_, Isolate::kJSRegexpStaticOffsetsVectorSize});
      break;
    }
  }

  // Cache the result vector location.

  register_array_ = result_vector_scope_.Initialize(register_array_size_);

  // Set state so that fetching the results the first time triggers a call
  // to the compiled regexp.
  current_match_index_ = max_matches() - 1;
  num_matches_ = max_matches();
  DCHECK_LE(2, registers_per_match_);  // Each match has at least one capture.
  DCHECK_GE(register_array_size_, registers_per_match_);
  int32_t* last_match =
      &register_array_[current_match_index_ * registers_per_match_];
  last_match[0] = -1;
  last_match[1] = 0;
}

int RegExpGlobalExecRunner::AdvanceZeroLength(int last_index) const {
  if (IsEitherUnicode(JSRegExp::AsRegExpFlags(regexp_data_->flags())) &&
      static_cast<uint32_t>(last_index + 1) < subject_->length() &&
      unibrow::Utf16::IsLeadSurrogate(subject_->Get(last_index)) &&
      unibrow::Utf16::IsTrailSurrogate(subject_->Get(last_index + 1))) {
    // Advance over the surrogate pair.
    return last_index + 2;
  }
  return last_index + 1;
}

int32_t* RegExpGlobalExecRunner::FetchNext() {
  current_match_index_++;

  if (current_match_index_ >= num_matches_) {
    // Current batch of results exhausted.
    // Fail if last batch was not even fully filled.
    if (num_matches_ < max_matches()) {
      num_matches_ = 0;  // Signal failed match.
      return nullptr;
    }

    int32_t* last_match =
        &register_array_[(current_match_index_ - 1) * registers_per_match_];
    int last_end_index = last_match[1];

    switch (regexp_data_->type_tag()) {
      case RegExpData::Type::ATOM:
        num_matches_ = RegExpImpl::AtomExecRaw(
            isolate_, Cast<AtomRegExpData>(regexp_data_), subject_,
            last_end_index, register_array_, register_array_size_);
        break;
      case RegExpData::Type::EXPERIMENTAL: {
        DCHECK(ExperimentalRegExp::IsCompiled(Cast<IrRegExpData>(regexp_data_),
                                              isolate_));
        DisallowGarbageCollection no_gc;
        num_matches_ = ExperimentalRegExp::ExecRaw(
            isolate_, RegExp::kFromRuntime, *Cast<IrRegExpData>(regexp_data_),
            *subject_, register_array_, register_array_size_, last_end_index);
        break;
      }
      case RegExpData::Type::IRREGEXP: {
        int last_start_index = last_match[0];
        if (last_start_index == last_end_index) {
          // Zero-length match. Advance by one code point.
          last_end_index = AdvanceZeroLength(last_end_index);
        }
        if (static_cast<uint32_t>(last_end_index) > subject_->length()) {
          num_matches_ = 0;  // Signal failed match.
          return nullptr;
        }
        num_matches_ = RegExpImpl::IrregexpExecRaw(
            isolate_, Cast<IrRegExpData>(regexp_data_), subject_,
            last_end_index, register_array_, register_array_size_);
        break;
      }
    }

    // Fall back to experimental engine if needed and possible.
    if (num_matches_ == RegExp::kInternalRegExpFallbackToExperimental) {
      num_matches_ = ExperimentalRegExp::OneshotExecRaw(
          isolate_, Cast<IrRegExpData>(regexp_data_), subject_, register_array_,
          register_array_size_, last_end_index);
    }

    if (num_matches_ <= 0) {
      return nullptr;
    }

    // Number of matches can't exceed maximum matches.
    // This check is enough to prevent OOB accesses to register_array_ in the
    // else branch below, since current_match_index < num_matches_ in this
    // branch, it follows that current_match_index < max_matches(). And since
    // max_matches() = register_array_size_ / registers_per_match it follows
    // that current_match_index * registers_per_match_ < register_array_size_.
    SBXCHECK_LE(num_matches_, max_matches());

    current_match_index_ = 0;
    return register_array_;
  } else {
    return &register_array_[current_match_index_ * registers_per_match_];
  }
}

int32_t* RegExpGlobalExecRunner::LastSuccessfulMatch() const {
  int index = current_match_index_ * registers_per_match_;
  if (num_matches_ == 0) {
    // After a failed match we shift back by one result.
    index -= registers_per_match_;
  }
  return &register_array_[index];
}

Tagged<Object> RegExpResultsCache::Lookup(Heap* heap, Tagged<String> key_string,
                                          Tagged<Object> key_pattern,
                                          Tagged<FixedArray>* last_match_cache,
                                          ResultsCacheType type) {
  if (V8_UNLIKELY(!v8_flags.regexp_results_cache)) return Smi::zero();
  Tagged<FixedArray> cache;
  if (!IsInternalizedString(key_string)) return Smi::zero();
  if (type == STRING_SPLIT_SUBSTRINGS) {
    DCHECK(IsString(key_pattern));
    if (!IsInternalizedString(key_pattern)) return Smi::zero();
    cache = heap->string_split_cache();
  } else {
    DCHECK(type == REGEXP_MULTIPLE_INDICES);
    DCHECK(IsRegExpDataWrapper(key_pattern));
    cache = heap->regexp_multiple_cache();
  }

  uint32_t hash = key_string->hash();
  uint32_t index = ((hash & (kRegExpResultsCacheSize - 1)) &
                    ~(kArrayEntriesPerCacheEntry - 1));
  if (cache->get(index + kStringOffset) != key_string ||
      cache->get(index + kPatternOffset) != key_pattern) {
    index =
        ((index + kArrayEntriesPerCacheEntry) & (kRegExpResultsCacheSize - 1));
    if (cache->get(index + kStringOffset) != key_string ||
        cache->get(index + kPatternOffset) != key_pattern) {
      return Smi::zero();
    }
  }

  *last_match_cache = Cast<FixedArray>(cache->get(index + kLastMatchOffset));
  return cache->get(index + kArrayOffset);
}

void RegExpResultsCache::Enter(Isolate* isolate,
                               DirectHandle<String> key_string,
                               DirectHandle<Object> key_pattern,
                               DirectHandle<FixedArray> value_array,
                               DirectHandle<FixedArray> last_match_cache,
                               ResultsCacheType type) {
  if (V8_UNLIKELY(!v8_flags.regexp_results_cache)) return;
  Factory* factory = isolate->factory();
  DirectHandle<FixedArray> cache;
  if (!IsInternalizedString(*key_string)) return;
  if (type == STRING_SPLIT_SUBSTRINGS) {
    DCHECK(IsString(*key_pattern));
    if (!IsInternalizedString(*key_pattern)) return;
    cache = factory->string_split_cache();
  } else {
    DCHECK(type == REGEXP_MULTIPLE_INDICES);
    DCHECK(IsRegExpDataWrapper(*key_pattern));
    cache = factory->regexp_multiple_cache();
  }

  uint32_t hash = key_string->hash();
  uint32_t index = ((hash & (kRegExpResultsCacheSize - 1)) &
                    ~(kArrayEntriesPerCacheEntry - 1));
  if (cache->get(index + kStringOffset) == Smi::zero()) {
    cache->set(index + kStringOffset, *key_string);
    cache->set(index + kPatternOffset, *key_pattern);
    cache->set(index + kArrayOffset, *value_array);
    cache->set(index + kLastMatchOffset, *last_match_cache);
  } else {
    uint32_t index2 =
        ((index + kArrayEntriesPerCacheEntry) & (kRegExpResultsCacheSize - 1));
    if (cache->get(index2 + kStringOffset) == Smi::zero()) {
      cache->set(index2 + kStringOffset, *key_string);
      cache->set(index2 + kPatternOffset, *key_pattern);
      cache->set(index2 + kArrayOffset, *value_array);
      cache->set(index2 + kLastMatchOffset, *last_match_cache);
    } else {
      cache->set(index2 + kStringOffset, Smi::zero());
      cache->set(index2 + kPatternOffset, Smi::zero());
      cache->set(index2 + kArrayOffset, Smi::zero());
      cache->set(index2 + kLastMatchOffset, Smi::zero());
      cache->set(index + kStringOffset, *key_string);
      cache->set(index + kPatternOffset, *key_pattern);
      cache->set(index + kArrayOffset, *value_array);
      cache->set(index + kLastMatchOffset, *last_match_cache);
    }
  }
  // If the array is a reasonably short list of substrings, convert it into a
  // list of internalized strings.
  if (type == STRING_SPLIT_SUBSTRINGS && value_array->length() < 100) {
    for (int i = 0; i < value_array->length(); i++) {
      Handle<String> str(Cast<String>(value_array->get(i)), isolate);
      DirectHandle<String> internalized_str = factory->InternalizeString(str);
      value_array->set(i, *internalized_str);
    }
  }
  // Convert backing store to a copy-on-write array.
  value_array->set_map_no_write_barrier(
      isolate, ReadOnlyRoots(isolate).fixed_cow_array_map());
}

void RegExpResultsCache::Clear(Tagged<FixedArray> cache) {
  for (int i = 0; i < kRegExpResultsCacheSize; i++) {
    cache->set(i, Smi::zero());
  }
}

// static
void RegExpResultsCache_MatchGlobalAtom::TryInsert(Isolate* isolate,
                                                   Tagged<String> subject,
                                                   Tagged<String> pattern,
                                                   int number_of_matches,
                                                   int last_match_index) {
  DisallowGarbageCollection no_gc;
  DCHECK(Smi::IsValid(number_of_matches));
  DCHECK(Smi::IsValid(last_match_index));
  if (!IsSlicedString(subject)) return;
  Tagged<FixedArray> cache = isolate->heap()->regexp_match_global_atom_cache();
  DCHECK_EQ(cache->length(), kSize);
  cache->set(kSubjectIndex, subject);
  cache->set(kPatternIndex, pattern);
  cache->set(kNumberOfMatchesIndex, Smi::FromInt(number_of_matches));
  cache->set(kLastMatchIndexIndex, Smi::FromInt(last_match_index));
}

// static
bool RegExpResultsCache_MatchGlobalAtom::TryGet(Isolate* isolate,
                                                Tagged<String> subject,
                                                Tagged<String> pattern,
                                                int* number_of_matches_out,
                                                int* last_match_index_out) {
  DisallowGarbageCollection no_gc;
  Tagged<FixedArray> cache = isolate->heap()->regexp_match_global_atom_cache();
  DCHECK_EQ(cache->length(), kSize);

  if (!IsSlicedString(subject)) return false;
  if (pattern != cache->get(kPatternIndex)) return false;

  // Here we are looking for a subject slice that 1. starts at the same point
  // and 2. is of equal length or longer than the cached subject slice.
  Tagged<SlicedString> sliced_subject = Cast<SlicedString>(subject);
  Tagged<Object> cached_subject_object = cache->get(kSubjectIndex);
  if (!Is<SlicedString>(cached_subject_object)) {
    // Note while we insert only sliced strings, they may be converted into
    // other kinds, e.g. during GC or internalization.
    Clear(isolate->heap());
    return false;
  }
  auto cached_subject = Cast<SlicedString>(cached_subject_object);
  if (cached_subject->parent() != sliced_subject->parent()) return false;
  if (cached_subject->offset() != sliced_subject->offset()) return false;
  if (cached_subject->length() > sliced_subject->length()) return false;

  *number_of_matches_out = Smi::ToInt(cache->get(kNumberOfMatchesIndex));
  *last_match_index_out = Smi::ToInt(cache->get(kLastMatchIndexIndex));
  return true;
}

void RegExpResultsCache_MatchGlobalAtom::Clear(Heap* heap) {
  MemsetTagged(heap->regexp_match_global_atom_cache()->RawFieldOfFirstElement(),
               Smi::zero(), kSize);
}

std::ostream& operator<<(std::ostream& os, RegExpFlags flags) {
#define V(Lower, Camel, LowerCamel, Char, Bit) \
  if (flags & RegExpFlag::k##Camel) os << Char;
  REGEXP_FLAG_LIST(V)
#undef V
  return os;
}

}  // namespace internal
}  // namespace v8

"""


```