Response: Let's break down the thought process for summarizing the `regexp.cc` file.

1. **Understand the Goal:** The request asks for the file's functionality and its relation to JavaScript, illustrated with examples. This means I need to identify the core tasks, how they relate to JS regexps, and then translate that into understandable JS usage.

2. **Initial Skim for Keywords and Structure:**  I'll quickly scan the code for obvious keywords and structural elements:
    * `Copyright`, `#include`: Standard C++ header. Not directly functional.
    * `namespace v8::internal`:  Indicates internal V8 implementation details.
    * `class RegExpImpl`:  A core class likely containing the main logic. The `Impl` suffix suggests it's part of a broader `RegExp` interface (though not explicitly defined as such in this snippet).
    * Static methods within `RegExpImpl`: This hints at utility functions related to regexp operations.
    * Method names like `ToString`, `IrregexpInitialize`, `IrregexpPrepare`, `AtomCompile`, `AtomExecRaw`, `IrregexpExecRaw`, `CompileIrregexp`, `EnsureCompiledIrregexp`, `Compile`: These are action-oriented and suggest the different stages and types of regexp processing.
    * Mentions of "Irregexp," "Atom," "ExperimentalRegExp," "bytecode," "native code":  These suggest different internal engines or optimization strategies.
    * References to ECMA-262 (the JavaScript standard): This confirms the link to JavaScript.

3. **Categorize Functionality:** Based on the method names, I can start grouping functionalities:
    * **Representation:**  `ToString` (converting to a string).
    * **Initialization/Compilation:** `IrregexpInitialize`, `AtomCompile`, `CompileIrregexp`, `Compile`, `EnsureCompiledIrregexp`. This looks like setting up the internal representation of the regexp.
    * **Execution:** `IrregexpExecRaw`, `IrregexpExec`, `AtomExecRaw`, `AtomExec`, `ExperimentalOneshotExec`, `Exec`, `Exec_Single`. This is where the actual matching happens.
    * **Internal Data Handling:**  Methods interacting with `IrRegExpData`, `AtomRegExpData`.
    * **Utilities:** `VerifySyntax`, `ThrowRegExpException`, `IsUnmodifiedRegExp`, `CreateCaptureNameMap`, `SetLastMatchInfo`, `DotPrintForTesting`. These seem like helper functions.

4. **Identify Key Abstractions:**
    * **Irregexp:**  Seems to be the main, potentially more complex, regular expression engine within V8.
    * **Atom:**  Appears to be a simpler, optimized case for literal string matching.
    * **ExperimentalRegExp:**  Indicates a newer or still-in-development regexp engine.
    * **Bytecode vs. Native Code:** Two different ways to represent the compiled regexp for execution, suggesting optimization levels or different execution paths.

5. **Connect to JavaScript:** Now, I'll link the internal functionalities to how JavaScript developers use regular expressions:
    * `RegExp.prototype.toString()` in JavaScript likely maps to the `ToString` method in the C++ code.
    * The various `Exec` methods are definitely related to the `RegExp.prototype.exec()` and `String.prototype.match()` methods in JavaScript.
    * Compilation happens implicitly when a `RegExp` object is created or used for the first time. The `Compile` and `Initialize` methods handle this.
    * Flags like `i`, `g`, `m`, `u`, `s`, `y` are mentioned, directly corresponding to JavaScript regexp flags.
    * Capture groups (using parentheses in regexps) are handled by the `capture_count` and methods related to `RegExpMatchInfo`.

6. **Construct JavaScript Examples:**  With the connections made, I can create illustrative JavaScript examples for each major functionality:
    * **Creation/Compilation:**  Show creating a `RegExp` object with different flags.
    * **Execution:**  Demonstrate using `exec`, `match`, and how capture groups work.
    * **`toString()`:** A simple example of calling `toString`.

7. **Refine and Organize the Summary:**  I'll structure the summary logically:
    * Start with a high-level overview of the file's purpose.
    * Describe the main functionalities, grouping related methods.
    * Explain the different internal engines (Irregexp, Atom, Experimental).
    * Discuss the compilation process (bytecode vs. native code).
    * Provide clear JavaScript examples for each key concept.
    * Conclude with a summary statement.

8. **Review and Iterate:**  Read through the summary to ensure clarity, accuracy, and completeness. Check if the JavaScript examples are correct and effectively illustrate the corresponding C++ functionality. For instance, I initially might have focused too much on the C++ implementation details. I'd then revise to emphasize the *JavaScript-relevant* aspects and use C++ details to *explain* the behavior. I'd also make sure the examples are simple and easy to understand. For example, making sure to show the capture groups in the `exec` example. Initially I might have just shown a basic match.

This iterative process of skimming, categorizing, connecting, illustrating, and refining helps to create a comprehensive and understandable summary of a complex C++ source file for someone familiar with JavaScript.
这个C++源代码文件 `regexp.cc` 是 V8 JavaScript 引擎中负责处理 **正则表达式 (Regular Expressions)** 的核心组件。 它包含了正则表达式的 **编译** 和 **执行** 的主要逻辑。

**主要功能归纳:**

1. **正则表达式的解析 (Parsing):**
   - 它使用 `RegExpParser` 类来解析 JavaScript 中正则表达式的字符串模式和标志位（如 `i`, `g`, `m`, `u`, `s`, `y`）。
   - 将正则表达式的模式转换为内部的抽象语法树 (AST) 表示 (`RegExpNode`).

2. **正则表达式的编译 (Compilation):**
   - 针对不同的正则表达式模式和配置，选择合适的编译策略：
     - **Atom 编译 (Atom Compilation):**  对于简单的、不区分大小写且非粘性的字面字符串匹配，会采用优化的 `AtomCompile` 方法，本质上是使用字符串查找算法 (类似 `indexOf`)。
     - **Irregexp 编译 (Irregexp Compilation):**  这是主要的、更强大的正则表达式引擎。会将正则表达式编译成两种形式：
       - **字节码 (Bytecode):**  使用解释器执行，适用于一些简单或优化的场景。
       - **本地机器码 (Native Code):**  使用即时编译 (JIT) 技术，生成高效的机器码执行，以提升性能。
     - **ExperimentalRegExp:**  处理一些实验性的正则表达式特性。
   - `CompileIrregexp` 函数负责将 Irregexp 的 AST 编译成字节码或本地机器码。
   - `EnsureCompiledIrregexp` 函数确保在执行前，正则表达式已经被编译成适合当前输入字符串类型（单字节或双字节）的代码。

3. **正则表达式的执行 (Execution):**
   - 提供了多种执行方法，对应不同的内部引擎：
     - `AtomExecRaw` 和 `AtomExec` 用于执行简单的 Atom 编译的正则表达式。
     - `IrregexpExecRaw` 和 `IrregexpExec` 用于执行 Irregexp 编译的正则表达式。
     - `ExperimentalOneshotExec` 和 `ExperimentalRegExp::Exec` 用于执行实验性的正则表达式。
   - `RegExp::Exec` 是一个通用的执行入口，会根据 `RegExpData` 中的类型标签分发到相应的执行方法。
   - 执行过程会处理字符串的匹配、捕获组的记录，并返回匹配结果。

4. **结果管理 (Result Management):**
   - `RegExpMatchInfo` 类用于存储正则表达式的匹配结果，包括匹配到的子串和捕获组的信息。
   - `RegExp::SetLastMatchInfo` 用于更新全局的 `RegExp.lastMatch`, `RegExp.lastParen`, 等属性。

5. **性能优化 (Performance Optimization):**
   - **编译缓存 (Compilation Cache):**  `CompilationCache` 用于缓存已编译的正则表达式，避免重复编译，提升性能。
   - **分层编译 (Tier-Up):** Irregexp 可能会先编译成字节码执行，然后在执行过程中根据性能情况提升到本地机器码。
   - **Boyer-Moore 优化:** 对于特定的字符串匹配模式，可能会使用 Boyer-Moore 算法进行优化。
   - **ExperimentalRegExp:**  V8 持续进行正则表达式引擎的实验性改进，例如线性时间复杂度的匹配。

6. **错误处理 (Error Handling):**
   - `RegExp::ThrowRegExpException` 用于抛出 `SyntaxError` 类型的异常，当正则表达式模式有语法错误时。

7. **调试和测试 (Debugging and Testing):**
   - 提供了 `DotPrintForTesting` 用于将正则表达式的内部结构以 DOT 语言格式打印出来，用于可视化和调试。

**与 JavaScript 功能的关系以及 JavaScript 示例:**

`regexp.cc` 中的功能直接对应了 JavaScript 中 `RegExp` 对象的行为和方法，以及字符串对象上与正则表达式相关的方法。

**JavaScript 示例:**

```javascript
// 1. 创建正则表达式 (对应 regexp.cc 中的解析和编译过程)
const regex1 = /abc/i; // 创建一个不区分大小写的正则表达式
const regex2 = new RegExp("d+", "g"); // 使用构造函数创建全局匹配的正则表达式

// 2. 使用 RegExp.prototype.test() (虽然 regexp.cc 中没有直接对应的方法，但其编译和执行逻辑会被用到)
console.log(regex1.test("aBcDeF")); // 输出: true

// 3. 使用 RegExp.prototype.exec() (对应 regexp.cc 中的各种 Exec 方法)
const str = "abracadabra";
const regex3 = /a(b)(r)/g;
let match;
while ((match = regex3.exec(str)) !== null) {
  console.log(`找到匹配: ${match[0]}, 捕获组 1: ${match[1]}, 捕获组 2: ${match[2]}, 索引: ${match.index}`);
  // 输出:
  // 找到匹配: abr, 捕获组 1: b, 捕获组 2: r, 索引: 0
  // 找到匹配: abr, 捕获组 1: b, 捕获组 2: r, 索引: 7
}

// 4. 使用 String.prototype.match() (底层会调用 regexp.cc 中的执行逻辑)
const str2 = "The quick brown fox jumps over the lazy dog.";
const regex4 = /[A-Z]/g;
const matches = str2.match(regex4);
console.log(matches); // 输出: [ 'T' ]

// 5. 使用 String.prototype.search() (底层也会用到 regexp.cc 的执行逻辑，但只返回索引)
const position = str2.search(/quick/i);
console.log(position); // 输出: 4

// 6. 使用 String.prototype.split() (涉及到正则表达式的匹配和分割)
const str3 = "apple,banana,orange";
const parts = str3.split(/,/);
console.log(parts); // 输出: [ 'apple', 'banana', 'orange' ]

// 7. 使用 String.prototype.replace() (正则表达式用于查找和替换)
const str4 = "Hello World";
const newStr = str4.replace(/World/, "V8");
console.log(newStr); // 输出: Hello V8

// 8. 获取正则表达式的字符串表示 (对应 regexp.cc 中的 ToString 方法)
console.log(regex1.toString()); // 输出: /abc/i
```

**总结:**

`regexp.cc` 是 V8 引擎中处理正则表达式的核心 C++ 代码，它负责将 JavaScript 中的正则表达式字符串解析成内部表示，并通过不同的引擎和优化策略将其编译成可执行的代码（字节码或机器码），最终执行匹配操作并返回结果。 JavaScript 中所有与正则表达式相关的操作，例如创建 `RegExp` 对象、使用 `exec`, `test`, `match`, `search`, `split`, `replace` 等方法，其底层实现都离不开 `regexp.cc` 中定义的逻辑。

### 提示词
```
这是目录为v8/src/regexp/regexp.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/regexp/regexp.h"

#include "src/base/strings.h"
#include "src/codegen/compilation-cache.h"
#include "src/diagnostics/code-tracer.h"
#include "src/execution/interrupts-scope.h"
#include "src/heap/heap-inl.h"
#include "src/objects/js-regexp-inl.h"
#include "src/regexp/experimental/experimental.h"
#include "src/regexp/regexp-bytecode-generator.h"
#include "src/regexp/regexp-bytecodes.h"
#include "src/regexp/regexp-compiler.h"
#include "src/regexp/regexp-dotprinter.h"
#include "src/regexp/regexp-interpreter.h"
#include "src/regexp/regexp-macro-assembler-arch.h"
#include "src/regexp/regexp-macro-assembler-tracer.h"
#include "src/regexp/regexp-parser.h"
#include "src/regexp/regexp-stack.h"
#include "src/regexp/regexp-utils.h"
#include "src/strings/string-search.h"
#include "src/utils/ostreams.h"

namespace v8 {
namespace internal {

using namespace regexp_compiler_constants;  // NOLINT(build/namespaces)

class RegExpImpl final : public AllStatic {
 public:
  // Returns a string representation of a regular expression.
  // Implements RegExp.prototype.toString, see ECMA-262 section 15.10.6.4.
  // This function calls the garbage collector if necessary.
  static Handle<String> ToString(Handle<Object> value);

  // Prepares a JSRegExp object with Irregexp-specific data.
  static void IrregexpInitialize(Isolate* isolate, DirectHandle<JSRegExp> re,
                                 DirectHandle<String> pattern,
                                 RegExpFlags flags, int capture_count,
                                 uint32_t backtrack_limit);

  // Prepare a RegExp for being executed one or more times (using
  // IrregexpExecOnce) on the subject.
  // This ensures that the regexp is compiled for the subject, and that
  // the subject is flat.
  // Returns the number of integer spaces required by IrregexpExecOnce
  // as its "registers" argument.  If the regexp cannot be compiled,
  // an exception is thrown as indicated by a negative return value.
  static int IrregexpPrepare(Isolate* isolate,
                             DirectHandle<IrRegExpData> regexp_data,
                             Handle<String> subject);

  static void AtomCompile(Isolate* isolate, DirectHandle<JSRegExp> re,
                          DirectHandle<String> pattern, RegExpFlags flags,
                          DirectHandle<String> match_pattern);

  static int AtomExecRaw(Isolate* isolate,
                         DirectHandle<AtomRegExpData> regexp_data,
                         Handle<String> subject, int index,
                         int32_t* result_offsets_vector,
                         int result_offsets_vector_length);
  static int AtomExecRaw(Isolate* isolate, const String::FlatContent& pattern,
                         const String::FlatContent& subject, int index,
                         int32_t* result_offsets_vector,
                         int result_offsets_vector_length,
                         const DisallowGarbageCollection& no_gc);

  static int AtomExec(Isolate* isolate,
                      DirectHandle<AtomRegExpData> regexp_data,
                      Handle<String> subject, int index,
                      int32_t* result_offsets_vector,
                      int result_offsets_vector_length);

  // Execute a regular expression on the subject, starting from index.
  // If matching succeeds, return the number of matches.  This can be larger
  // than one in the case of global regular expressions.
  // The captures and subcaptures are stored into the registers vector.
  // If matching fails, returns RE_FAILURE.
  // If execution fails, sets an exception and returns RE_EXCEPTION.
  static int IrregexpExecRaw(Isolate* isolate,
                             DirectHandle<IrRegExpData> regexp_data,
                             Handle<String> subject, int index, int32_t* output,
                             int output_size);

  // Execute an Irregexp bytecode pattern. Returns the number of matches, or an
  // empty handle in case of an exception.
  V8_WARN_UNUSED_RESULT static std::optional<int> IrregexpExec(
      Isolate* isolate, DirectHandle<IrRegExpData> regexp_data,
      Handle<String> subject, int index, int32_t* result_offsets_vector,
      uint32_t result_offsets_vector_length);

  static bool CompileIrregexp(Isolate* isolate,
                              DirectHandle<IrRegExpData> re_data,
                              Handle<String> sample_subject, bool is_one_byte);
  static inline bool EnsureCompiledIrregexp(Isolate* isolate,
                                            DirectHandle<IrRegExpData> re_data,
                                            Handle<String> sample_subject,
                                            bool is_one_byte);

  // Returns true on success, false on failure.
  static bool Compile(Isolate* isolate, Zone* zone, RegExpCompileData* input,
                      RegExpFlags flags, Handle<String> pattern,
                      Handle<String> sample_subject, bool is_one_byte,
                      uint32_t& backtrack_limit);
};

// static
bool RegExp::CanGenerateBytecode() {
  return v8_flags.regexp_interpret_all || v8_flags.regexp_tier_up;
}

// static
bool RegExp::VerifyFlags(RegExpFlags flags) {
  if (IsUnicode(flags) && IsUnicodeSets(flags)) return false;
  return true;
}

// static
template <class CharT>
bool RegExp::VerifySyntax(Zone* zone, uintptr_t stack_limit, const CharT* input,
                          int input_length, RegExpFlags flags,
                          RegExpError* regexp_error_out,
                          const DisallowGarbageCollection& no_gc) {
  RegExpCompileData data;
  bool pattern_is_valid = RegExpParser::VerifyRegExpSyntax(
      zone, stack_limit, input, input_length, flags, &data, no_gc);
  *regexp_error_out = data.error;
  return pattern_is_valid;
}

template bool RegExp::VerifySyntax<uint8_t>(Zone*, uintptr_t, const uint8_t*,
                                            int, RegExpFlags,
                                            RegExpError* regexp_error_out,
                                            const DisallowGarbageCollection&);
template bool RegExp::VerifySyntax<base::uc16>(
    Zone*, uintptr_t, const base::uc16*, int, RegExpFlags,
    RegExpError* regexp_error_out, const DisallowGarbageCollection&);

MaybeHandle<Object> RegExp::ThrowRegExpException(Isolate* isolate,
                                                 RegExpFlags flags,
                                                 Handle<String> pattern,
                                                 RegExpError error) {
  base::Vector<const char> error_data =
      base::CStrVector(RegExpErrorString(error));
  Handle<String> error_text =
      isolate->factory()
          ->NewStringFromOneByte(base::Vector<const uint8_t>::cast(error_data))
          .ToHandleChecked();
  Handle<String> flag_string =
      JSRegExp::StringFromFlags(isolate, JSRegExp::AsJSRegExpFlags(flags));
  THROW_NEW_ERROR(isolate, NewSyntaxError(MessageTemplate::kMalformedRegExp,
                                          pattern, flag_string, error_text));
}

void RegExp::ThrowRegExpException(Isolate* isolate,
                                  DirectHandle<RegExpData> re_data,
                                  RegExpError error_text) {
  USE(ThrowRegExpException(isolate, JSRegExp::AsRegExpFlags(re_data->flags()),
                           Handle<String>(re_data->source(), isolate),
                           error_text));
}

bool RegExp::IsUnmodifiedRegExp(Isolate* isolate,
                                DirectHandle<JSRegExp> regexp) {
  return RegExpUtils::IsUnmodifiedRegExp(isolate, regexp);
}

namespace {

// Identifies the sort of regexps where the regexp engine is faster
// than the code used for atom matches.
bool HasFewDifferentCharacters(DirectHandle<String> pattern) {
  uint32_t length = std::min(kMaxLookaheadForBoyerMoore, pattern->length());
  if (length <= kPatternTooShortForBoyerMoore) return false;
  const int kMod = 128;
  bool character_found[kMod];
  uint32_t different = 0;
  memset(&character_found[0], 0, sizeof(character_found));
  for (uint32_t i = 0; i < length; i++) {
    int ch = (pattern->Get(i) & (kMod - 1));
    if (!character_found[ch]) {
      character_found[ch] = true;
      different++;
      // We declare a regexp low-alphabet if it has at least 3 times as many
      // characters as it has different characters.
      if (different * 3 > length) return false;
    }
  }
  return true;
}

}  // namespace

// Generic RegExp methods. Dispatches to implementation specific methods.

// static
MaybeHandle<Object> RegExp::Compile(Isolate* isolate, Handle<JSRegExp> re,
                                    Handle<String> pattern, RegExpFlags flags,
                                    uint32_t backtrack_limit) {
  DCHECK(pattern->IsFlat());

  // Caching is based only on the pattern and flags, but code also differs when
  // a backtrack limit is set. A present backtrack limit is very much *not* the
  // common case, so just skip the cache for these.
  const bool is_compilation_cache_enabled =
      (backtrack_limit == JSRegExp::kNoBacktrackLimit);

  Zone zone(isolate->allocator(), ZONE_NAME);
  CompilationCache* compilation_cache = nullptr;
  if (is_compilation_cache_enabled) {
    compilation_cache = isolate->compilation_cache();
    MaybeHandle<RegExpData> maybe_cached = compilation_cache->LookupRegExp(
        pattern, JSRegExp::AsJSRegExpFlags(flags));
    Handle<RegExpData> cached;
    if (maybe_cached.ToHandle(&cached)) {
      re->set_data(*cached);
      return re;
    }
  }

  PostponeInterruptsScope postpone(isolate);
  RegExpCompileData parse_result;
  DCHECK(!isolate->has_exception());
  if (!RegExpParser::ParseRegExpFromHeapString(isolate, &zone, pattern, flags,
                                               &parse_result)) {
    // Throw an exception if we fail to parse the pattern.
    return RegExp::ThrowRegExpException(isolate, flags, pattern,
                                        parse_result.error);
  }

  bool has_been_compiled = false;

  if (v8_flags.default_to_experimental_regexp_engine &&
      ExperimentalRegExp::CanBeHandled(parse_result.tree, pattern, flags,
                                       parse_result.capture_count)) {
    DCHECK(v8_flags.enable_experimental_regexp_engine);
    ExperimentalRegExp::Initialize(isolate, re, pattern, flags,
                                   parse_result.capture_count);
    has_been_compiled = true;
  } else if (flags & JSRegExp::kLinear) {
    DCHECK(v8_flags.enable_experimental_regexp_engine);
    if (!ExperimentalRegExp::CanBeHandled(parse_result.tree, pattern, flags,
                                          parse_result.capture_count)) {
      // TODO(mbid): The error could provide a reason for why the regexp can't
      // be executed in linear time (e.g. due to back references).
      return RegExp::ThrowRegExpException(isolate, flags, pattern,
                                          RegExpError::kNotLinear);
    }
    ExperimentalRegExp::Initialize(isolate, re, pattern, flags,
                                   parse_result.capture_count);
    has_been_compiled = true;
  } else if (parse_result.simple && !IsIgnoreCase(flags) && !IsSticky(flags) &&
             !HasFewDifferentCharacters(pattern)) {
    // Parse-tree is a single atom that is equal to the pattern.
    RegExpImpl::AtomCompile(isolate, re, pattern, flags, pattern);
    has_been_compiled = true;
  } else if (parse_result.tree->IsAtom() && !IsSticky(flags) &&
             parse_result.capture_count == 0) {
    RegExpAtom* atom = parse_result.tree->AsAtom();
    // The pattern source might (?) contain escape sequences, but they're
    // resolved in atom_string.
    base::Vector<const base::uc16> atom_pattern = atom->data();
    Handle<String> atom_string;
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, atom_string,
        isolate->factory()->NewStringFromTwoByte(atom_pattern));
    if (!IsIgnoreCase(flags) && !HasFewDifferentCharacters(atom_string)) {
      RegExpImpl::AtomCompile(isolate, re, pattern, flags, atom_string);
      has_been_compiled = true;
    }
  }
  if (!has_been_compiled) {
    RegExpImpl::IrregexpInitialize(isolate, re, pattern, flags,
                                   parse_result.capture_count, backtrack_limit);
  }
  // Compilation succeeded so the data is set on the regexp
  // and we can store it in the cache.
  DirectHandle<RegExpData> data(re->data(isolate), isolate);
  if (is_compilation_cache_enabled) {
    compilation_cache->PutRegExp(pattern, JSRegExp::AsJSRegExpFlags(flags),
                                 data);
  }

  return re;
}

// static
bool RegExp::EnsureFullyCompiled(Isolate* isolate,
                                 DirectHandle<RegExpData> re_data,
                                 Handle<String> subject) {
  switch (re_data->type_tag()) {
    case RegExpData::Type::ATOM:
      return true;
    case RegExpData::Type::IRREGEXP:
      if (RegExpImpl::IrregexpPrepare(isolate, Cast<IrRegExpData>(re_data),
                                      subject) == -1) {
        DCHECK(isolate->has_exception());
        return false;
      }
      return true;
    case RegExpData::Type::EXPERIMENTAL:
      if (!ExperimentalRegExp::IsCompiled(Cast<IrRegExpData>(re_data),
                                          isolate) &&
          !ExperimentalRegExp::Compile(isolate, Cast<IrRegExpData>(re_data))) {
        DCHECK(isolate->has_exception());
        return false;
      }
      return true;
  }
  UNREACHABLE();
}

// static
std::optional<int> RegExp::ExperimentalOneshotExec(
    Isolate* isolate, DirectHandle<JSRegExp> regexp,
    DirectHandle<String> subject, int index, int32_t* result_offsets_vector,
    uint32_t result_offsets_vector_length) {
  DirectHandle<RegExpData> data = direct_handle(regexp->data(isolate), isolate);
  SBXCHECK(Is<IrRegExpData>(*data));
  return ExperimentalRegExp::OneshotExec(isolate, Cast<IrRegExpData>(data),
                                         subject, index, result_offsets_vector,
                                         result_offsets_vector_length);
}

// static
std::optional<int> RegExp::Exec(Isolate* isolate, DirectHandle<JSRegExp> regexp,
                                Handle<String> subject, int index,
                                int32_t* result_offsets_vector,
                                uint32_t result_offsets_vector_length) {
  DirectHandle<RegExpData> data = direct_handle(regexp->data(isolate), isolate);
  switch (data->type_tag()) {
    case RegExpData::Type::ATOM:
      return RegExpImpl::AtomExec(isolate, Cast<AtomRegExpData>(data), subject,
                                  index, result_offsets_vector,
                                  result_offsets_vector_length);
    case RegExpData::Type::IRREGEXP:
      return RegExpImpl::IrregexpExec(isolate, Cast<IrRegExpData>(data),
                                      subject, index, result_offsets_vector,
                                      result_offsets_vector_length);
    case RegExpData::Type::EXPERIMENTAL:
      return ExperimentalRegExp::Exec(isolate, Cast<IrRegExpData>(data),
                                      subject, index, result_offsets_vector,
                                      result_offsets_vector_length);
  }
  // This UNREACHABLE() is necessary because we don't return a value here,
  // which causes the compiler to emit potentially unsafe code for the switch
  // above. See the commit message and b/326086002 for more details.
  UNREACHABLE();
}

// static
MaybeHandle<Object> RegExp::Exec_Single(
    Isolate* isolate, DirectHandle<JSRegExp> regexp, Handle<String> subject,
    int index, Handle<RegExpMatchInfo> last_match_info) {
  RegExpStackScope stack_scope(isolate);
  DirectHandle<RegExpData> data = direct_handle(regexp->data(isolate), isolate);
  int capture_count = data->capture_count();
  int result_offsets_vector_length =
      JSRegExp::RegistersForCaptureCount(capture_count);
  RegExpResultVectorScope result_vector_scope(isolate,
                                              result_offsets_vector_length);
  std::optional<int> result =
      RegExp::Exec(isolate, regexp, subject, index, result_vector_scope.value(),
                   result_offsets_vector_length);
  DCHECK_EQ(!result, isolate->has_exception());
  if (!result) return {};

  if (result.value() == 0) {
    return isolate->factory()->null_value();
  }

  DCHECK_EQ(result.value(), 1);
  return RegExp::SetLastMatchInfo(isolate, last_match_info, subject,
                                  capture_count, result_vector_scope.value());
}

// RegExp Atom implementation: Simple string search using indexOf.

void RegExpImpl::AtomCompile(Isolate* isolate, DirectHandle<JSRegExp> re,
                             DirectHandle<String> pattern, RegExpFlags flags,
                             DirectHandle<String> match_pattern) {
  isolate->factory()->SetRegExpAtomData(
      re, pattern, JSRegExp::AsJSRegExpFlags(flags), match_pattern);
}

namespace {

template <typename SChar, typename PChar>
int AtomExecRawImpl(Isolate* isolate, base::Vector<const SChar> subject,
                    base::Vector<const PChar> pattern, int index,
                    int32_t* output, int output_size,
                    const DisallowGarbageCollection& no_gc) {
  const int subject_length = subject.length();
  const int pattern_length = pattern.length();
  DCHECK_GT(pattern_length, 0);
  const int max_index = subject_length - pattern_length;

  StringSearch<PChar, SChar> search(isolate, pattern);
  for (int i = 0; i < output_size; i += JSRegExp::kAtomRegisterCount) {
    if (index > max_index) {
      static_assert(RegExp::RE_FAILURE == 0);
      return i / JSRegExp::kAtomRegisterCount;  // Return number of matches.
    }
    index = search.Search(subject, index);
    if (index == -1) {
      static_assert(RegExp::RE_FAILURE == 0);
      return i / JSRegExp::kAtomRegisterCount;  // Return number of matches.
    } else {
      output[i] = index;  // match start
      index += pattern_length;
      output[i + 1] = index;  // match end
    }
  }

  return output_size / JSRegExp::kAtomRegisterCount;
}

}  // namespace

// static
int RegExpImpl::AtomExecRaw(Isolate* isolate,
                            DirectHandle<AtomRegExpData> regexp_data,
                            Handle<String> subject, int index,
                            int32_t* result_offsets_vector,
                            int result_offsets_vector_length) {
  subject = String::Flatten(isolate, subject);

  DisallowGarbageCollection no_gc;
  Tagged<String> needle = regexp_data->pattern(isolate);
  String::FlatContent needle_content = needle->GetFlatContent(no_gc);
  String::FlatContent subject_content = subject->GetFlatContent(no_gc);
  return AtomExecRaw(isolate, needle_content, subject_content, index,
                     result_offsets_vector, result_offsets_vector_length,
                     no_gc);
}

// static
int RegExpImpl::AtomExecRaw(Isolate* isolate,
                            const String::FlatContent& pattern,
                            const String::FlatContent& subject, int index,
                            int32_t* result_offsets_vector,
                            int result_offsets_vector_length,
                            const DisallowGarbageCollection& no_gc) {
  DCHECK_GE(index, 0);
  DCHECK_LE(index, subject.length());
  CHECK_EQ(result_offsets_vector_length % JSRegExp::kAtomRegisterCount, 0);
  DCHECK(pattern.IsFlat());
  DCHECK(subject.IsFlat());

  return pattern.IsOneByte()
             ? (subject.IsOneByte()
                    ? AtomExecRawImpl(isolate, subject.ToOneByteVector(),
                                      pattern.ToOneByteVector(), index,
                                      result_offsets_vector,
                                      result_offsets_vector_length, no_gc)
                    : AtomExecRawImpl(isolate, subject.ToUC16Vector(),
                                      pattern.ToOneByteVector(), index,
                                      result_offsets_vector,
                                      result_offsets_vector_length, no_gc))
             : (subject.IsOneByte()
                    ? AtomExecRawImpl(isolate, subject.ToOneByteVector(),
                                      pattern.ToUC16Vector(), index,
                                      result_offsets_vector,
                                      result_offsets_vector_length, no_gc)
                    : AtomExecRawImpl(isolate, subject.ToUC16Vector(),
                                      pattern.ToUC16Vector(), index,
                                      result_offsets_vector,
                                      result_offsets_vector_length, no_gc));
}

// static
intptr_t RegExp::AtomExecRaw(Isolate* isolate,
                             Address /* AtomRegExpData */ data_address,
                             Address /* String */ subject_address,
                             int32_t index, int32_t* result_offsets_vector,
                             int32_t result_offsets_vector_length) {
  DisallowGarbageCollection no_gc;

  SBXCHECK(Is<AtomRegExpData>(Tagged<Object>(data_address)));
  auto data = Cast<AtomRegExpData>(Tagged<Object>(data_address));
  auto subject = Cast<String>(Tagged<Object>(subject_address));

  Tagged<String> pattern = data->pattern(isolate);
  String::FlatContent pattern_content = pattern->GetFlatContent(no_gc);
  String::FlatContent subject_content = subject->GetFlatContent(no_gc);
  return RegExpImpl::AtomExecRaw(isolate, pattern_content, subject_content,
                                 index, result_offsets_vector,
                                 result_offsets_vector_length, no_gc);
}

int RegExpImpl::AtomExec(Isolate* isolate, DirectHandle<AtomRegExpData> re_data,
                         Handle<String> subject, int index,
                         int32_t* result_offsets_vector,
                         int result_offsets_vector_length) {
  int res = AtomExecRaw(isolate, re_data, subject, index, result_offsets_vector,
                        result_offsets_vector_length);

  DCHECK(res == RegExp::RE_FAILURE || res == RegExp::RE_SUCCESS);
  return res;
}

// Irregexp implementation.

// Ensures that the regexp object contains a compiled version of the
// source for either one-byte or two-byte subject strings.
// If the compiled version doesn't already exist, it is compiled
// from the source pattern.
// If compilation fails, an exception is thrown and this function
// returns false.
bool RegExpImpl::EnsureCompiledIrregexp(Isolate* isolate,
                                        DirectHandle<IrRegExpData> re_data,
                                        Handle<String> sample_subject,
                                        bool is_one_byte) {
  bool has_bytecode = re_data->has_bytecode(is_one_byte);
  bool needs_initial_compilation = !re_data->has_code(is_one_byte);
  // Recompile is needed when we're dealing with the first execution of the
  // regexp after the decision to tier up has been made. If the tiering up
  // strategy is not in use, this value is always false.
  bool needs_tier_up_compilation = re_data->MarkedForTierUp() && has_bytecode;

  if (v8_flags.trace_regexp_tier_up && needs_tier_up_compilation) {
    PrintF("JSRegExp object (data: %p) needs tier-up compilation\n",
           reinterpret_cast<void*>(re_data->ptr()));
  }

  if (!needs_initial_compilation && !needs_tier_up_compilation) {
    DCHECK(re_data->has_code(is_one_byte));
    DCHECK_IMPLIES(v8_flags.regexp_interpret_all, has_bytecode);
    return true;
  }

  DCHECK_IMPLIES(needs_tier_up_compilation, has_bytecode);

  return CompileIrregexp(isolate, re_data, sample_subject, is_one_byte);
}

namespace {

#ifdef DEBUG
bool RegExpCodeIsValidForPreCompilation(IsolateForSandbox isolate,
                                        DirectHandle<IrRegExpData> re_data,
                                        bool is_one_byte) {
  bool has_code = re_data->has_code(is_one_byte);
  bool has_bytecode = re_data->has_bytecode(is_one_byte);
  if (re_data->ShouldProduceBytecode()) {
    DCHECK(!has_code);
    DCHECK(!has_bytecode);
  } else {
    DCHECK_IMPLIES(has_code, has_bytecode);
  }

  return true;
}
#endif

struct RegExpCaptureIndexLess {
  bool operator()(const RegExpCapture* lhs, const RegExpCapture* rhs) const {
    DCHECK_NOT_NULL(lhs);
    DCHECK_NOT_NULL(rhs);
    return lhs->index() < rhs->index();
  }
};

}  // namespace

// static
Handle<FixedArray> RegExp::CreateCaptureNameMap(
    Isolate* isolate, ZoneVector<RegExpCapture*>* named_captures) {
  if (named_captures == nullptr) return Handle<FixedArray>();

  DCHECK(!named_captures->empty());

  // Named captures are sorted by name (because the set is used to ensure
  // name uniqueness). But the capture name map must to be sorted by index.

  std::sort(named_captures->begin(), named_captures->end(),
            RegExpCaptureIndexLess{});

  int len = static_cast<int>(named_captures->size()) * 2;
  Handle<FixedArray> array = isolate->factory()->NewFixedArray(len);

  int i = 0;
  for (const RegExpCapture* capture : *named_captures) {
    base::Vector<const base::uc16> capture_name(capture->name()->data(),
                                                capture->name()->size());
    // CSA code in ConstructNewResultFromMatchInfo requires these strings to be
    // internalized so they can be used as property names in the 'exec' results.
    DirectHandle<String> name =
        isolate->factory()->InternalizeString(capture_name);
    array->set(i * 2, *name);
    array->set(i * 2 + 1, Smi::FromInt(capture->index()));

    i++;
  }
  DCHECK_EQ(i * 2, len);

  return array;
}

bool RegExpImpl::CompileIrregexp(Isolate* isolate,
                                 DirectHandle<IrRegExpData> re_data,
                                 Handle<String> sample_subject,
                                 bool is_one_byte) {
  // Compile the RegExp.
  Zone zone(isolate->allocator(), ZONE_NAME);
  PostponeInterruptsScope postpone(isolate);

  DCHECK(RegExpCodeIsValidForPreCompilation(isolate, re_data, is_one_byte));

  RegExpFlags flags = JSRegExp::AsRegExpFlags(re_data->flags());

  Handle<String> pattern(re_data->source(), isolate);
  pattern = String::Flatten(isolate, pattern);
  RegExpCompileData compile_data;
  if (!RegExpParser::ParseRegExpFromHeapString(isolate, &zone, pattern, flags,
                                               &compile_data)) {
    // Throw an exception if we fail to parse the pattern.
    // THIS SHOULD NOT HAPPEN. We already pre-parsed it successfully once.
    USE(RegExp::ThrowRegExpException(isolate, flags, pattern,
                                     compile_data.error));
    return false;
  }
  // The compilation target is a kBytecode if we're interpreting all regexp
  // objects, or if we're using the tier-up strategy but the tier-up hasn't
  // happened yet. The compilation target is a kNative if we're using the
  // tier-up strategy and we need to recompile to tier-up, or if we're producing
  // native code for all regexp objects.
  compile_data.compilation_target = re_data->ShouldProduceBytecode()
                                        ? RegExpCompilationTarget::kBytecode
                                        : RegExpCompilationTarget::kNative;
  uint32_t backtrack_limit = re_data->backtrack_limit();
  const bool compilation_succeeded =
      Compile(isolate, &zone, &compile_data, flags, pattern, sample_subject,
              is_one_byte, backtrack_limit);
  if (!compilation_succeeded) {
    DCHECK(compile_data.error != RegExpError::kNone);
    RegExp::ThrowRegExpException(isolate, re_data, compile_data.error);
    return false;
  }

  if (compile_data.compilation_target == RegExpCompilationTarget::kNative) {
    re_data->set_code(is_one_byte, Cast<Code>(*compile_data.code));

    // Reset bytecode to uninitialized. In case we use tier-up we know that
    // tier-up has happened this way.
    re_data->clear_bytecode(is_one_byte);
  } else {
    DCHECK_EQ(compile_data.compilation_target,
              RegExpCompilationTarget::kBytecode);
    // Store code generated by compiler in bytecode and trampoline to
    // interpreter in code.
    re_data->set_bytecode(is_one_byte,
                          Cast<TrustedByteArray>(*compile_data.code));
    DirectHandle<Code> trampoline =
        BUILTIN_CODE(isolate, RegExpInterpreterTrampoline);
    re_data->set_code(is_one_byte, *trampoline);
  }
  Handle<FixedArray> capture_name_map =
      RegExp::CreateCaptureNameMap(isolate, compile_data.named_captures);
  re_data->set_capture_name_map(capture_name_map);
  int register_max = re_data->max_register_count();
  if (compile_data.register_count > register_max) {
    re_data->set_max_register_count(compile_data.register_count);
  }
  re_data->set_backtrack_limit(backtrack_limit);

  if (v8_flags.trace_regexp_tier_up) {
    PrintF("JSRegExp data object %p %s size: %d\n",
           reinterpret_cast<void*>(re_data->ptr()),
           re_data->ShouldProduceBytecode() ? "bytecode" : "native code",
           re_data->ShouldProduceBytecode()
               ? re_data->bytecode(is_one_byte)->AllocatedSize()
               : re_data->code(isolate, is_one_byte)->Size());
  }

  return true;
}

void RegExpImpl::IrregexpInitialize(Isolate* isolate, DirectHandle<JSRegExp> re,
                                    DirectHandle<String> pattern,
                                    RegExpFlags flags, int capture_count,
                                    uint32_t backtrack_limit) {
  // Initialize compiled code entries to null.
  isolate->factory()->SetRegExpIrregexpData(re, pattern,
                                            JSRegExp::AsJSRegExpFlags(flags),
                                            capture_count, backtrack_limit);
}

// static
int RegExpImpl::IrregexpPrepare(Isolate* isolate,
                                DirectHandle<IrRegExpData> re_data,
                                Handle<String> subject) {
  DCHECK(subject->IsFlat());

  // Check representation of the underlying storage.
  bool is_one_byte = subject->IsOneByteRepresentation();
  if (!RegExpImpl::EnsureCompiledIrregexp(isolate, re_data, subject,
                                          is_one_byte)) {
    return -1;
  }

  // Only reserve room for output captures. Internal registers are allocated by
  // the engine.
  return JSRegExp::RegistersForCaptureCount(re_data->capture_count());
}

int RegExpImpl::IrregexpExecRaw(Isolate* isolate,
                                DirectHandle<IrRegExpData> regexp_data,
                                Handle<String> subject, int index,
                                int32_t* output, int output_size) {
  DCHECK_LE(0, index);
  DCHECK_LE(index, subject->length());
  DCHECK(subject->IsFlat());
  DCHECK_GE(output_size,
            JSRegExp::RegistersForCaptureCount(regexp_data->capture_count()));

  bool is_one_byte = subject->IsOneByteRepresentation();

  if (!regexp_data->ShouldProduceBytecode()) {
    do {
      EnsureCompiledIrregexp(isolate, regexp_data, subject, is_one_byte);
      // The stack is used to allocate registers for the compiled regexp code.
      // This means that in case of failure, the output registers array is left
      // untouched and contains the capture results from the previous successful
      // match.  We can use that to set the last match info lazily.
      int res = NativeRegExpMacroAssembler::Match(regexp_data, subject, output,
                                                  output_size, index, isolate);
      if (res != NativeRegExpMacroAssembler::RETRY) {
        DCHECK(res != NativeRegExpMacroAssembler::EXCEPTION ||
               isolate->has_exception());
        static_assert(static_cast<int>(NativeRegExpMacroAssembler::SUCCESS) ==
                      RegExp::RE_SUCCESS);
        static_assert(static_cast<int>(NativeRegExpMacroAssembler::FAILURE) ==
                      RegExp::RE_FAILURE);
        static_assert(static_cast<int>(NativeRegExpMacroAssembler::EXCEPTION) ==
                      RegExp::RE_EXCEPTION);
        return res;
      }
      // If result is RETRY, the string has changed representation, and we
      // must restart from scratch.
      // In this case, it means we must make sure we are prepared to handle
      // the, potentially, different subject (the string can switch between
      // being internal and external, and even between being Latin1 and
      // UC16, but the characters are always the same).
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
```