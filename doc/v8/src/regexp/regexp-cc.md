Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/regexp/regexp.cc`. The summary should also address specific points related to:

1. **Torque Source:** Whether the file would be a Torque source if it had a `.tq` extension.
2. **JavaScript Relevance:**  Connections to JavaScript functionality with examples.
3. **Code Logic:**  Illustrative input and output scenarios.
4. **Common Errors:**  Examples of typical programming mistakes related to the code's functionality.

**Plan:**

1. **High-Level Overview:** Start by identifying the core purpose of `regexp.cc`, which is handling regular expression operations within V8.
2. **Key Functionalities:** Analyze the provided class `RegExpImpl` and the global `RegExp` namespace to list the primary functions:
    *   String representation of regexps (`ToString`).
    *   Initialization of JSRegExp objects (`IrregexpInitialize`).
    *   Preparation for execution (`IrregexpPrepare`).
    *   Compilation (various forms: `AtomCompile`, `CompileIrregexp`, `Compile`).
    *   Execution (various forms: `AtomExecRaw`, `AtomExec`, `IrregexpExecRaw`, `IrregexpExec`, `ExperimentalOneshotExec`, `Exec`, `Exec_Single`).
    *   Bytecode generation check (`CanGenerateBytecode`).
    *   Flag verification (`VerifyFlags`).
    *   Syntax verification (`VerifySyntax`).
    *   Exception handling (`ThrowRegExpException`).
    *   Checking for unmodified regexps (`IsUnmodifiedRegExp`).
    *   Handling experimental regexps.
    *   Caching of compiled regexps.
    *   Creation of capture name maps.
3. **Torque Consideration:** Explain that a `.tq` extension signifies a Torque source file within V8, used for generating efficient code.
4. **JavaScript Connection:** Link the C++ functions to their corresponding JavaScript RegExp methods (e.g., `toString`, `exec`, constructor with flags). Provide concise JavaScript examples.
5. **Logic Deduction:** For a few key functions (like `AtomExecRaw` or `IrregexpExecRaw`), devise simple input strings and regular expressions and predict the output (match indices).
6. **Common Errors:** Think about typical mistakes developers make when working with regular expressions in JavaScript that might be related to the underlying V8 implementation (e.g., incorrect flags, unescaped characters, misunderstanding global matching).
7. **Structure and Language:** Organize the information clearly using headings and bullet points. Use precise language to explain technical concepts. Avoid overly detailed internal implementation specifics unless directly relevant to the user's understanding.

**Self-Correction/Refinement:**

*   Ensure the JavaScript examples are simple and directly illustrate the connection to the C++ code's functionality.
*   Avoid going too deep into the complexities of the different regexp engines (Irregexp, experimental). Focus on the user-visible aspects.
*   Clarify the role of compilation caching and how it impacts performance.
*   Emphasize the error handling aspects of the code.
好的，根据您提供的代码片段，以下是`v8/src/regexp/regexp.cc` 部分功能的归纳：

**功能归纳：**

该 C++ 源代码文件 `v8/src/regexp/regexp.cc` 是 V8 JavaScript 引擎中负责处理正则表达式的核心组件。它包含了用于编译、优化和执行正则表达式的各种功能。  主要功能可以概括为：

1. **正则表达式的表示和管理:**  定义了 `RegExpImpl` 类，用于实现正则表达式的相关操作，以及 `RegExp` 命名空间，提供静态方法来处理正则表达式。
2. **正则表达式到字符串的转换:** 实现了 `RegExp.prototype.toString` 的功能，可以将一个正则表达式对象转换为其字符串表示形式。
3. **不同类型的正则表达式处理:**  支持多种正则表达式的实现方式，包括：
    *   **Irregexp:** V8 默认的、功能强大的正则表达式引擎。
    *   **Atom:**  针对简单字符串匹配的优化实现。
    *   **ExperimentalRegExp:**  实验性的正则表达式引擎。
4. **正则表达式的编译:** 提供了多种编译方法，根据正则表达式的复杂度和特性选择合适的编译策略：
    *   **`IrregexpInitialize`:** 初始化 `JSRegExp` 对象，准备使用 Irregexp 引擎。
    *   **`IrregexpPrepare`:**  为 Irregexp 引擎的执行做准备，确保正则表达式已编译，并对匹配的字符串进行扁平化处理。
    *   **`AtomCompile`:**  针对简单的原子正则表达式进行编译。
    *   **`CompileIrregexp`:**  编译 Irregexp 正则表达式，生成字节码或本地机器码。
    *   **`Compile`:**  通用的编译入口，根据正则表达式的特性选择合适的编译方法。
5. **正则表达式的执行:** 提供了多种执行方法，对应不同的正则表达式类型：
    *   **`IrregexpExecRaw` 和 `IrregexpExec`:**  执行 Irregexp 编译后的代码或字节码。
    *   **`AtomExecRaw` 和 `AtomExec`:** 执行简单的原子正则表达式匹配。
    *   **`ExperimentalOneshotExec` 和 `Exec`:** 执行实验性正则表达式。
    *   **`Exec_Single`:**  执行正则表达式并返回匹配结果信息。
6. **编译缓存:**  实现了编译缓存机制，可以缓存编译好的正则表达式，避免重复编译，提高性能。
7. **正则表达式语法的验证:**  提供了 `VerifySyntax` 方法，用于在编译前验证正则表达式的语法是否正确。
8. **错误处理:**  定义了 `ThrowRegExpException` 方法，用于在正则表达式解析或编译过程中发生错误时抛出异常。
9. **标志位处理:**  提供了 `VerifyFlags` 方法来验证正则表达式的标志位是否合法。
10. **实验性功能支持:**  为实验性的正则表达式引擎提供支持。
11. **捕获组名称映射:**  提供了 `CreateCaptureNameMap` 方法，用于创建捕获组名称到索引的映射。

**关于您提出的问题：**

*   **如果 `v8/src/regexp/regexp.cc` 以 `.tq` 结尾，那它是个 v8 torque 源代码：**
    是的，如果一个 V8 源代码文件以 `.tq` 结尾，那么它就是一个 **Torque** 源代码文件。 Torque 是 V8 使用的一种领域特定语言（DSL），用于生成高效的 C++ 代码。

*   **如果它与 JavaScript 的功能有关系，请用 JavaScript 举例说明：**

    是的，`v8/src/regexp/regexp.cc` 中的功能直接对应于 JavaScript 中 `RegExp` 对象及其相关方法。以下是一些示例：

    ```javascript
    // 对应 RegExp.prototype.toString()
    const regex = /ab+c/g;
    console.log(regex.toString()); // 输出: "/ab+c/g"

    // 对应 RegExp 构造函数和标志位
    const regex2 = new RegExp("ab+c", "i"); // 'i' 是忽略大小写标志
    console.log(regex2.flags); // 输出: "i"

    // 对应 RegExp.prototype.exec() 和 RegExp.prototype.test()
    const str = 'abbbc';
    const regex3 = /ab+c/;
    const result = regex3.exec(str);
    console.log(result); // 输出: ["abbbc", index: 0, input: "abbbc", groups: undefined]
    console.log(regex3.test(str)); // 输出: true

    // 对应字符串的 match(), search(), replace(), split() 方法，
    // 这些方法内部会调用 V8 的正则表达式引擎。
    const str2 = 'The quick brown fox jumps over the lazy dog.';
    const regex4 = /the/i;
    console.log(str2.search(regex4)); // 输出: 0
    console.log(str2.match(regex4)); // 输出: ["The", index: 0, input: "The quick brown fox jumps over the lazy dog.", groups: undefined]
    ```

*   **如果有代码逻辑推理，请给出假设输入与输出：**

    假设我们调用了 `RegExpImpl::AtomExecRaw` 函数进行简单的字符串查找：

    **假设输入：**

    *   `isolate`: V8 隔离区指针（代表一个独立的 JavaScript 运行环境）。
    *   `pattern`: 字符串 "hello"。
    *   `subject`: 字符串 "world hello there"。
    *   `index`:  6 (表示从 `subject` 字符串的第 7 个字符开始查找)。
    *   `result_offsets_vector`: 一个足够大的整型数组用于存储匹配结果。
    *   `result_offsets_vector_length`:  数组的长度。

    **代码逻辑推理：**

    `AtomExecRaw` 函数会从 `subject` 字符串的索引 6 开始查找 `pattern` 字符串 "hello"。  在 "world **hello** there" 中，"hello" 从索引 6 开始匹配。

    **假设输出：**

    `result_offsets_vector` 的前两个元素将被填充：

    *   `result_offsets_vector[0]`: 6 (匹配开始的索引)
    *   `result_offsets_vector[1]`: 11 (匹配结束的索引，6 + "hello".length)

    函数会返回 `1`，表示找到了一个匹配项。

*   **如果涉及用户常见的编程错误，请举例说明：**

    以下是一些与正则表达式相关的常见 JavaScript 编程错误，这些错误与 V8 的正则表达式实现相关：

    1. **忘记转义特殊字符:**  正则表达式中有些字符具有特殊含义（例如 `.`、`*`、`+`、`?` 等）。如果想匹配这些字符本身，需要使用反斜杠 `\` 进行转义。

        ```javascript
        // 错误示例：想要匹配字符串 "a.b"
        const regex = /a.b/; //  . 会匹配任意字符
        console.log(regex.test("acb")); // 输出: true (错误地匹配了 "acb")

        // 正确示例：
        const regexCorrect = /a\.b/;
        console.log(regexCorrect.test("a.b")); // 输出: true
        console.log(regexCorrect.test("acb")); // 输出: false
        ```

    2. **滥用全局匹配标志 `g` 导致状态问题:**  如果同一个正则表达式实例多次用于全局匹配，它的 `lastIndex` 属性会被修改，可能会导致意外的结果。

        ```javascript
        const regexGlobal = /test/g;
        const strGlobal = "test test test";

        console.log(regexGlobal.exec(strGlobal)); // 输出: ["test", index: 0, input: "test test test", groups: undefined]
        console.log(regexGlobal.lastIndex);    // 输出: 4
        console.log(regexGlobal.exec(strGlobal)); // 输出: ["test", index: 5, input: "test test test", groups: undefined]
        console.log(regexGlobal.lastIndex);    // 输出: 9
        console.log(regexGlobal.test(strGlobal)); // 输出: true (由于 lastIndex 的存在，可能会出现不期望的结果)

        // 建议：每次使用新的 RegExp 实例或重置 lastIndex
        const regexGlobalNew = /test/g;
        console.log(regexGlobalNew.exec(strGlobal));
        const regexGlobalNew2 = /test/g;
        console.log(regexGlobalNew2.exec(strGlobal));
        ```

    3. **在字符集中忘记转义某些字符:**  在字符集 `[]` 中，某些特殊字符（例如 `-`、`^`、`\`、`]`）需要特殊处理。

        ```javascript
        // 错误示例：想要匹配 'a'、'b' 或 '-'
        const regexCharset = /[a-b]/; // 这表示匹配 'a' 到 'b' 之间的字符
        console.log(regexCharset.test('-')); // 输出: false (错误)

        // 正确示例：
        const regexCharsetCorrect = /[ab-]/; // 将 '-' 放在开头或结尾
        const regexCharsetCorrect2 = /[a\-b]/; // 或者转义
        console.log(regexCharsetCorrect.test('-')); // 输出: true
        console.log(regexCharsetCorrect2.test('-')); // 输出: true
        ```

    4. **对捕获组的理解错误:**  不清楚捕获组的工作方式，导致无法正确提取匹配到的子字符串。

        ```javascript
        const regexCapture = /(\w+)\s(\w+)/;
        const strCapture = "John Doe";
        const matchCapture = regexCapture.exec(strCapture);
        console.log(matchCapture); // 输出: ["John Doe", "John", "Doe", index: 0, input: "John Doe", groups: undefined]
        console.log(matchCapture[1]); // 输出: "John"
        console.log(matchCapture[2]); // 输出: "Doe"
        ```

**总结:**

`v8/src/regexp/regexp.cc` 是 V8 引擎中处理正则表达式的核心 C++ 代码，它负责正则表达式的编译、优化和执行，并直接支撑着 JavaScript 中 `RegExp` 对象及其相关方法的功能。 该文件涉及多种正则表达式引擎的实现，并包含了性能优化和错误处理机制。

Prompt: 
```
这是目录为v8/src/regexp/regexp.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/regexp/regexp.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
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
    
"""


```