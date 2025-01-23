Response:
Let's break down the thought process for analyzing this C++ header file.

**1. Initial Understanding - What is the goal?**

The request asks for the functionality of `v8/src/parsing/parse-info.h`. It also includes specific sub-questions related to Torque, JavaScript relevance, code logic, and common errors. This immediately tells me the analysis needs to be multi-faceted.

**2. Core Identification - What is `ParseInfo`?**

The file name and the class name `ParseInfo` strongly suggest this class holds information about parsing. The comments within the file reinforce this: "A container for the inputs, configuration options, and outputs of parsing." This is the central piece of information.

**3. Deconstructing `ParseInfo` - What data does it hold?**

I start examining the members of the `ParseInfo` class. I look for categories of members:

* **Inputs:** What information is needed *before* parsing?
    * `UnoptimizedCompileFlags`:  Clearly configuration flags related to compilation. The `FLAG_FIELDS` macro provides a detailed list.
    * `UnoptimizedCompileState`, `ReusableUnoptimizedCompileState`:  These likely manage the state during and across parsing.
    * `Utf16CharacterStream`: The source code itself.
    * `v8::Extension`:  Extensions to the JavaScript language.
    * `ConsumedPreparseData`:  Information from a previous parse (for optimization).
    * `function_name_`: The name of the function being parsed.
    * `stack_limit_`: Resource constraints.
    * `compile_hint_callback_`, `compile_hint_callback_data_`: Mechanisms for providing hints during compilation.

* **Outputs:** What information is produced *after* parsing?
    * `literal_`: A `FunctionLiteral` represents the parsed function. This is a core output.
    * `script_scope_`:  The scope of the script.
    * `source_range_map_`:  Mapping of source code ranges.
    * `language_mode_`: The language mode (strict, sloppy).
    * `allow_eval_cache_`, `contains_asm_module_`, `is_background_compilation_`, `is_streaming_compilation_`, `has_module_in_scope_chain_`: Boolean flags indicating properties discovered during parsing.

* **State Management:**
    * `UnoptimizedCompileState`: Holds mutable state for a single parse.
    * `ReusableUnoptimizedCompileState`: Holds state that can be reused across multiple parses (like the `AstValueFactory`).

* **Utility/Helpers:**
    * `zone()`: Memory management.
    * `ast_value_factory()`:  Creating AST nodes.
    * `dispatcher()`:  Handling lazy compilation.

**4. Understanding the Relationships - How do the pieces fit together?**

I observe the relationships between the classes: `ParseInfo` *has-a* `UnoptimizedCompileFlags`, `UnoptimizedCompileState`, and `ReusableUnoptimizedCompileState`. This suggests a hierarchy of information and control.

**5. Addressing the Specific Sub-Questions:**

* **Torque:** The request specifically asks about `.tq`. The code has `.h`, so the answer is straightforward: it's not a Torque file.

* **JavaScript Functionality:** I look for connections to JavaScript concepts. The flags (like `is_eval`, `is_module`, `allow_natives_syntax`), the `LanguageMode`, the concept of `Script`, `FunctionLiteral`, and the mention of "parsing JavaScript" in comments clearly link this to JavaScript processing. I then think of a simple JavaScript example that would trigger parsing and compilation, like a function declaration.

* **Code Logic and Assumptions:**  The `UnoptimizedCompileFlags` and its `For...` static methods suggest different initialization scenarios. I can infer potential input flags and their impact on the compilation process (e.g., if `is_toplevel` is true, it's a top-level script). I can also see that the `set_` methods modify the flags.

* **Common Programming Errors:** I think about what could go wrong during parsing. Syntax errors are the most obvious. Accessing variables before declaration (due to hoisting or scope issues) is another common JavaScript mistake that the parser would detect.

**6. Structuring the Answer:**

I organize the information logically, starting with the main purpose of `ParseInfo`, then detailing its components, and finally addressing the specific sub-questions in order. Using bullet points and clear headings helps with readability.

**7. Refinement and Review:**

I reread the generated answer and the original request to ensure all points are addressed accurately and comprehensively. I check for clarity and conciseness. For instance, initially, I might have just listed all the flags, but then I would refine it by grouping them conceptually (toplevel, eager, etc.) to make the explanation clearer. I also ensured that the JavaScript example was simple and illustrative.

This iterative process of examination, deduction, and structuring allows for a thorough understanding of the C++ header file and a comprehensive answer to the request.
`v8/src/parsing/parse-info.h` 是 V8 引擎中一个非常重要的头文件，它定义了 `ParseInfo` 类，这个类是用于存储和传递与 JavaScript 代码解析和初步编译相关的所有信息的核心容器。

**`v8/src/parsing/parse-info.h` 的主要功能：**

1. **存储解析和编译的输入信息:**  `ParseInfo` 对象包含了执行 JavaScript 代码解析和初步（未优化的）编译所需的所有输入信息。这包括：
    * **源代码:** 通过 `Utf16CharacterStream` 提供。
    * **编译标志 (Flags):**  `UnoptimizedCompileFlags` 结构体定义了大量的布尔标志和枚举，用于控制解析和编译的行为，例如是否是顶层代码、是否是 eval 代码、是否是模块、是否允许惰性解析等等。
    * **编译状态 (State):** `UnoptimizedCompileState` 存储了在编译过程中可变的状态信息，例如待处理的编译错误。
    * **可重用的编译状态 (Reusable State):** `ReusableUnoptimizedCompileState` 存储了可以在多次解析和编译过程中重用的信息，例如字符串常量工厂 (`AstValueFactory`)，这有助于提高效率。
    * **脚本信息:**  脚本的 ID。
    * **函数类型和语法类型:**  例如，是普通函数、箭头函数、生成器函数等。
    * **调试信息:**  是否在调试时解析。
    * **语言模式:**  严格模式或非严格模式。
    * **扩展信息:**  V8 扩展。
    * **预解析数据:**  如果之前进行过预解析，则包含相关数据。
    * **栈限制:**  用于防止栈溢出。
    * **运行时调用统计信息。**
    * **编译提示回调函数和数据。**

2. **管理解析和编译的状态:** `ParseInfo` 对象持有解析和编译过程中的状态信息，并提供访问和修改这些信息的方法。

3. **传递解析和编译的输出信息:** 虽然主要用于输入，但 `ParseInfo` 也存储了一些解析过程的输出，例如：
    * **抽象语法树 (AST) 节点:** 通过 `FunctionLiteral` 存储解析后的函数字面量。
    * **作用域信息:** 通过 `DeclarationScope` 存储。
    * **是否允许 eval 缓存。**
    * **是否包含 WebAssembly 模块。**
    * **最终确定的语言模式。**

4. **提供辅助方法:** `ParseInfo` 提供了一些辅助方法，例如创建 `Script` 对象，分配源代码范围映射等。

**如果 `v8/src/parsing/parse-info.h` 以 `.tq` 结尾:**

如果 `v8/src/parsing/parse-info.h` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码** 文件。 Torque 是 V8 使用的一种领域特定语言 (DSL)，用于生成高效的 C++ 代码，特别是用于实现 V8 的内置函数和运行时功能。

**与 JavaScript 功能的关系及 JavaScript 示例:**

`v8/src/parsing/parse-info.h` 与 JavaScript 的核心功能——代码的解析和编译直接相关。 每当你执行一段 JavaScript 代码，V8 引擎首先需要解析这段代码，将其转换为抽象语法树 (AST)。 `ParseInfo` 对象在这个解析过程中扮演着至关重要的角色，它携带了所有必要的上下文信息，指导解析器如何理解和处理代码。

例如，考虑以下简单的 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}

add(5, 3);
```

当 V8 引擎执行这段代码时，它会创建一个 `ParseInfo` 对象，并填充以下信息（仅为示例，实际情况更复杂）：

* **源代码:**  字符串 `"function add(a, b) { return a + b; } add(5, 3);"`
* **`is_toplevel`:**  `true` (因为这是顶层代码)
* **`language_mode`:**  根据上下文可能是严格模式或非严格模式。
* **`allow_lazy_parsing`:**  根据 V8 的配置可能为 `true` 或 `false`。
* **...其他编译标志...**

然后，解析器会使用这个 `ParseInfo` 对象来解析代码，生成 `add` 函数的 `FunctionLiteral` 对象，并建立相应的作用域。

**代码逻辑推理：假设输入与输出**

假设我们正在解析以下 JavaScript 函数：

```javascript
function foo(x) {
  'use strict';
  return x * 2;
}
```

**假设输入 (在 `ParseInfo` 对象中):**

* **源代码:**  字符串 `"function foo(x) { 'use strict'; return x * 2; }"`
* **`is_toplevel`:** `false` (因为这是一个函数声明)
* **`language_mode`:**  在解析前可能是一个默认值，例如 `SLOPPY`。
* **`allow_lazy_parsing`:**  `true` (假设允许惰性解析)
* **...其他编译标志...**

**代码逻辑推理 (V8 内部解析器的工作):**

1. 解析器读取源代码，遇到 `function` 关键字，开始解析函数声明。
2. 解析器遇到 `'use strict';` 指令。
3. 解析器会更新 `ParseInfo` 对象中的 `language_mode` 为 `STRICT`。
4. 解析器继续解析函数体，构建乘法表达式的 AST 节点。
5. 解析器完成函数解析，生成 `FunctionLiteral` 对象。

**可能的输出 (在 `ParseInfo` 对象中):**

* **`literal_`:** 指向表示 `foo` 函数的 `FunctionLiteral` 对象的指针。这个对象包含了函数的 AST。
* **`language_mode_`:** `STRICT` (因为函数内部有 `'use strict';`)
* **`script_scope_`:** 指向函数作用域的 `DeclarationScope` 对象。

**涉及用户常见的编程错误及示例:**

`ParseInfo` 在解析过程中会参与检测用户代码中的错误。以下是一些常见的编程错误，解析器可能会在 `ParseInfo` 的上下文中识别出来：

1. **语法错误 (SyntaxError):**  代码不符合 JavaScript 语法规则。

   ```javascript
   // 缺少闭合括号
   function bar(a {
     return a + 1;
   }
   ```

   解析器在解析时会遇到 `}` 前面的 `{`，导致语法错误。`PendingCompilationErrorHandler` 会记录这个错误。

2. **重复的参数名 (SyntaxError in strict mode):** 在严格模式下，函数参数名不能重复。

   ```javascript
   function baz(a, a) { // 在非严格模式下允许，但在严格模式下报错
     return a * a;
   }
   ```

   如果 `ParseInfo` 的 `language_mode` 为 `STRICT`，解析器会检测到重复的参数名并抛出错误。

3. **在声明前访问变量 (ReferenceError):**  在 `let` 或 `const` 声明的变量被声明前访问。

   ```javascript
   function qux() {
     console.log(y); // ReferenceError: Cannot access 'y' before initialization
     let y = 10;
   }
   ```

   虽然解析阶段可能不会立即抛出所有这类错误（某些错误可能在执行阶段才出现），但解析器会记录变量的声明和使用情况，为后续的静态分析和代码生成提供信息，从而在执行时抛出 `ReferenceError`。

4. **非法的 `return` 语句 (SyntaxError):** 在构造函数中返回对象。

   ```javascript
   class MyClass {
     constructor() {
       return { value: 1 }; // TypeError: Constructors do not allow non-empty return values
     }
   }
   ```

   解析器会识别出构造函数中的非法 `return` 语句。

**总结:**

`v8/src/parsing/parse-info.h` 中定义的 `ParseInfo` 类是 V8 引擎解析 JavaScript 代码的核心数据结构。它携带了所有必要的输入信息，并在解析过程中存储和传递状态和一些输出信息。理解 `ParseInfo` 的功能有助于深入理解 V8 引擎的解析和编译流程。如果它以 `.tq` 结尾，则表示它是一个使用 Torque 编写的源代码文件。

### 提示词
```
这是目录为v8/src/parsing/parse-info.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/parsing/parse-info.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_PARSING_PARSE_INFO_H_
#define V8_PARSING_PARSE_INFO_H_

#include <memory>

#include "include/v8-callbacks.h"
#include "src/base/bit-field.h"
#include "src/base/export-template.h"
#include "src/base/logging.h"
#include "src/common/globals.h"
#include "src/handles/handles.h"
#include "src/objects/function-kind.h"
#include "src/objects/function-syntax-kind.h"
#include "src/objects/script.h"
#include "src/parsing/pending-compilation-error-handler.h"
#include "src/parsing/preparse-data.h"

namespace v8 {

class Extension;

namespace internal {

class AccountingAllocator;
class AstRawString;
class AstStringConstants;
class AstValueFactory;
class LazyCompileDispatcher;
class DeclarationScope;
class FunctionLiteral;
class RuntimeCallStats;
class V8FileLogger;
class SourceRangeMap;
class Utf16CharacterStream;
class Zone;

// The flags for a parse + unoptimized compile operation.
#define FLAG_FIELDS(V, _)                                       \
  V(is_toplevel, bool, 1, _)                                    \
  V(is_eager, bool, 1, _)                                       \
  V(is_eval, bool, 1, _)                                        \
  V(is_reparse, bool, 1, _)                                     \
  V(outer_language_mode, LanguageMode, 1, _)                    \
  V(parse_restriction, ParseRestriction, 1, _)                  \
  V(is_module, bool, 1, _)                                      \
  V(allow_lazy_parsing, bool, 1, _)                             \
  V(is_lazy_compile, bool, 1, _)                                \
  V(coverage_enabled, bool, 1, _)                               \
  V(block_coverage_enabled, bool, 1, _)                         \
  V(is_asm_wasm_broken, bool, 1, _)                             \
  V(class_scope_has_private_brand, bool, 1, _)                  \
  V(private_name_lookup_skips_outer_class, bool, 1, _)          \
  V(requires_instance_members_initializer, bool, 1, _)          \
  V(has_static_private_methods_or_accessors, bool, 1, _)        \
  V(might_always_turbofan, bool, 1, _)                          \
  V(allow_natives_syntax, bool, 1, _)                           \
  V(allow_lazy_compile, bool, 1, _)                             \
  V(post_parallel_compile_tasks_for_eager_toplevel, bool, 1, _) \
  V(post_parallel_compile_tasks_for_lazy, bool, 1, _)           \
  V(collect_source_positions, bool, 1, _)                       \
  V(is_repl_mode, bool, 1, _)                                   \
  V(produce_compile_hints, bool, 1, _)                          \
  V(compile_hints_magic_enabled, bool, 1, _)

class V8_EXPORT_PRIVATE UnoptimizedCompileFlags {
 public:
  // Set-up flags for a toplevel compilation.
  static UnoptimizedCompileFlags ForToplevelCompile(Isolate* isolate,
                                                    bool is_user_javascript,
                                                    LanguageMode language_mode,
                                                    REPLMode repl_mode,
                                                    ScriptType type, bool lazy);

  // Set-up flags for a compiling a particular function (either a lazy compile
  // or a recompile).
  static UnoptimizedCompileFlags ForFunctionCompile(
      Isolate* isolate, Tagged<SharedFunctionInfo> shared);

  // Set-up flags for a full compilation of a given script.
  static UnoptimizedCompileFlags ForScriptCompile(Isolate* isolate,
                                                  Tagged<Script> script);

  // Set-up flags for a parallel toplevel function compilation, based on the
  // flags of an existing toplevel compilation.
  static UnoptimizedCompileFlags ForToplevelFunction(
      const UnoptimizedCompileFlags toplevel_flags,
      const FunctionLiteral* literal);

  // Create flags for a test.
  static UnoptimizedCompileFlags ForTest(Isolate* isolate);

#define FLAG_GET_SET(NAME, TYPE, SIZE, _)                       \
  TYPE NAME() const { return BitFields::NAME::decode(flags_); } \
  UnoptimizedCompileFlags& set_##NAME(TYPE value) {             \
    flags_ = BitFields::NAME::update(flags_, value);            \
    return *this;                                               \
  }

  FLAG_FIELDS(FLAG_GET_SET, _)

  int script_id() const { return script_id_; }
  UnoptimizedCompileFlags& set_script_id(int value) {
    script_id_ = value;
    return *this;
  }

  FunctionKind function_kind() const { return function_kind_; }
  UnoptimizedCompileFlags& set_function_kind(FunctionKind value) {
    function_kind_ = value;
    return *this;
  }

  FunctionSyntaxKind function_syntax_kind() const {
    return function_syntax_kind_;
  }
  UnoptimizedCompileFlags& set_function_syntax_kind(FunctionSyntaxKind value) {
    function_syntax_kind_ = value;
    return *this;
  }

  ParsingWhileDebugging parsing_while_debugging() const {
    return parsing_while_debugging_;
  }
  UnoptimizedCompileFlags& set_parsing_while_debugging(
      ParsingWhileDebugging value) {
    parsing_while_debugging_ = value;
    return *this;
  }

 private:
  struct BitFields {
    DEFINE_BIT_FIELDS(FLAG_FIELDS)
  };

  UnoptimizedCompileFlags(Isolate* isolate, int script_id);

  // Set function info flags based on those in either FunctionLiteral or
  // SharedFunctionInfo |function|
  template <typename T>
  void SetFlagsFromFunction(T function);
  void SetFlagsForToplevelCompile(bool is_user_javascript,
                                  LanguageMode language_mode,
                                  REPLMode repl_mode, ScriptType type,
                                  bool lazy);
  void SetFlagsForFunctionFromScript(Tagged<Script> script);

  uint32_t flags_;
  int script_id_;
  FunctionKind function_kind_;
  FunctionSyntaxKind function_syntax_kind_;
  ParsingWhileDebugging parsing_while_debugging_;
};

#undef FLAG_FIELDS
class ParseInfo;

// The mutable state for a parse + unoptimized compile operation.
class V8_EXPORT_PRIVATE UnoptimizedCompileState {
 public:
  const PendingCompilationErrorHandler* pending_error_handler() const {
    return &pending_error_handler_;
  }
  PendingCompilationErrorHandler* pending_error_handler() {
    return &pending_error_handler_;
  }

 private:
  PendingCompilationErrorHandler pending_error_handler_;
};

// A container for ParseInfo fields that are reusable across multiple parses and
// unoptimized compiles.
//
// Note that this is different from UnoptimizedCompileState, which has mutable
// state for a single compilation that is not reusable across multiple
// compilations.
class V8_EXPORT_PRIVATE ReusableUnoptimizedCompileState {
 public:
  explicit ReusableUnoptimizedCompileState(Isolate* isolate);
  explicit ReusableUnoptimizedCompileState(LocalIsolate* isolate);
  ~ReusableUnoptimizedCompileState();

  // The AstRawString Zone stores the AstRawStrings in the AstValueFactory that
  // can be reused across parses, and thereforce should stay alive between
  // parses that reuse this reusable state and its AstValueFactory.
  Zone* ast_raw_string_zone() { return &ast_raw_string_zone_; }

  // The single parse Zone stores the data of a single parse, and can be cleared
  // when that parse completes.
  //
  // This is in "reusable" state despite being wiped per-parse, because it
  // allows us to reuse the Zone itself, and e.g. keep the same single parse
  // Zone pointer in the AstValueFactory.
  Zone* single_parse_zone() { return &single_parse_zone_; }

  void NotifySingleParseCompleted() { single_parse_zone_.Reset(); }

  AstValueFactory* ast_value_factory() const {
    return ast_value_factory_.get();
  }
  uint64_t hash_seed() const { return hash_seed_; }
  AccountingAllocator* allocator() const { return allocator_; }
  const AstStringConstants* ast_string_constants() const {
    return ast_string_constants_;
  }
  // TODO(cbruni): Switch this back to the main logger.
  V8FileLogger* v8_file_logger() const { return v8_file_logger_; }
  LazyCompileDispatcher* dispatcher() const { return dispatcher_; }

 private:
  uint64_t hash_seed_;
  AccountingAllocator* allocator_;
  V8FileLogger* v8_file_logger_;
  LazyCompileDispatcher* dispatcher_;
  const AstStringConstants* ast_string_constants_;
  Zone ast_raw_string_zone_;
  Zone single_parse_zone_;
  std::unique_ptr<AstValueFactory> ast_value_factory_;
};

// A container for the inputs, configuration options, and outputs of parsing.
class V8_EXPORT_PRIVATE ParseInfo {
 public:
  ParseInfo(Isolate* isolate, const UnoptimizedCompileFlags flags,
            UnoptimizedCompileState* state,
            ReusableUnoptimizedCompileState* reusable_state);
  ParseInfo(LocalIsolate* isolate, const UnoptimizedCompileFlags flags,
            UnoptimizedCompileState* state,
            ReusableUnoptimizedCompileState* reusable_state,
            uintptr_t stack_limit);

  ~ParseInfo();

  template <typename IsolateT>
  EXPORT_TEMPLATE_DECLARE(V8_EXPORT_PRIVATE)
  Handle<Script> CreateScript(IsolateT* isolate, Handle<String> source,
                              MaybeHandle<FixedArray> maybe_wrapped_arguments,
                              ScriptOriginOptions origin_options,
                              NativesFlag natives = NOT_NATIVES_CODE);

  Zone* zone() const { return reusable_state_->single_parse_zone(); }

  const UnoptimizedCompileFlags& flags() const { return flags_; }

  // Getters for reusable state.
  uint64_t hash_seed() const { return reusable_state_->hash_seed(); }
  AccountingAllocator* allocator() const {
    return reusable_state_->allocator();
  }
  const AstStringConstants* ast_string_constants() const {
    return reusable_state_->ast_string_constants();
  }
  V8FileLogger* v8_file_logger() const {
    return reusable_state_->v8_file_logger();
  }
  LazyCompileDispatcher* dispatcher() const {
    return reusable_state_->dispatcher();
  }
  const UnoptimizedCompileState* state() const { return state_; }

  // Getters for state.
  PendingCompilationErrorHandler* pending_error_handler() {
    return state_->pending_error_handler();
  }

  // Accessors for per-thread state.
  uintptr_t stack_limit() const { return stack_limit_; }
  RuntimeCallStats* runtime_call_stats() const { return runtime_call_stats_; }

  // Accessor methods for output flags.
  bool allow_eval_cache() const { return allow_eval_cache_; }
  void set_allow_eval_cache(bool value) { allow_eval_cache_ = value; }

#if V8_ENABLE_WEBASSEMBLY
  bool contains_asm_module() const { return contains_asm_module_; }
  void set_contains_asm_module(bool value) { contains_asm_module_ = value; }
#endif  // V8_ENABLE_WEBASSEMBLY

  LanguageMode language_mode() const { return language_mode_; }
  void set_language_mode(LanguageMode value) { language_mode_ = value; }

  Utf16CharacterStream* character_stream() const {
    return character_stream_.get();
  }
  void set_character_stream(
      std::unique_ptr<Utf16CharacterStream> character_stream);
  void ResetCharacterStream();

  v8::Extension* extension() const { return extension_; }
  void set_extension(v8::Extension* extension) { extension_ = extension; }

  void set_consumed_preparse_data(std::unique_ptr<ConsumedPreparseData> data) {
    consumed_preparse_data_.swap(data);
  }
  ConsumedPreparseData* consumed_preparse_data() {
    return consumed_preparse_data_.get();
  }

  DeclarationScope* script_scope() const { return script_scope_; }
  void set_script_scope(DeclarationScope* script_scope) {
    script_scope_ = script_scope;
  }

  AstValueFactory* ast_value_factory() const {
    return reusable_state_->ast_value_factory();
  }

  const AstRawString* function_name() const { return function_name_; }
  void set_function_name(const AstRawString* function_name) {
    function_name_ = function_name;
  }

  FunctionLiteral* literal() const { return literal_; }
  void set_literal(FunctionLiteral* literal) { literal_ = literal; }

  DeclarationScope* scope() const;

  int parameters_end_pos() const { return parameters_end_pos_; }
  void set_parameters_end_pos(int parameters_end_pos) {
    parameters_end_pos_ = parameters_end_pos;
  }

  bool is_wrapped_as_function() const {
    return flags().function_syntax_kind() == FunctionSyntaxKind::kWrapped;
  }

  int max_info_id() const { return max_info_id_; }
  void set_max_info_id(int max_info_id) { max_info_id_ = max_info_id; }

  void AllocateSourceRangeMap();
  SourceRangeMap* source_range_map() const { return source_range_map_; }
  void set_source_range_map(SourceRangeMap* source_range_map) {
    source_range_map_ = source_range_map;
  }

  void CheckFlagsForFunctionFromScript(Tagged<Script> script);

  bool is_background_compilation() const { return is_background_compilation_; }

  void set_is_background_compilation() { is_background_compilation_ = true; }

  bool is_streaming_compilation() const { return is_streaming_compilation_; }

  void set_is_streaming_compilation() { is_streaming_compilation_ = true; }

  bool has_module_in_scope_chain() const { return has_module_in_scope_chain_; }
  void set_has_module_in_scope_chain() { has_module_in_scope_chain_ = true; }

  void SetCompileHintCallbackAndData(CompileHintCallback callback, void* data) {
    DCHECK_NULL(compile_hint_callback_);
    DCHECK_NULL(compile_hint_callback_data_);
    compile_hint_callback_ = callback;
    compile_hint_callback_data_ = data;
  }

  CompileHintCallback compile_hint_callback() const {
    return compile_hint_callback_;
  }

  void* compile_hint_callback_data() const {
    return compile_hint_callback_data_;
  }

 private:
  ParseInfo(const UnoptimizedCompileFlags flags, UnoptimizedCompileState* state,
            ReusableUnoptimizedCompileState* reusable_state,
            uintptr_t stack_limit, RuntimeCallStats* runtime_call_stats);

  void CheckFlagsForToplevelCompileFromScript(Tagged<Script> script);

  //------------- Inputs to parsing and scope analysis -----------------------
  const UnoptimizedCompileFlags flags_;
  UnoptimizedCompileState* state_;
  ReusableUnoptimizedCompileState* reusable_state_;

  v8::Extension* extension_;
  DeclarationScope* script_scope_;
  uintptr_t stack_limit_;
  int parameters_end_pos_;
  int max_info_id_;

  v8::CompileHintCallback compile_hint_callback_ = nullptr;
  void* compile_hint_callback_data_ = nullptr;

  //----------- Inputs+Outputs of parsing and scope analysis -----------------
  std::unique_ptr<Utf16CharacterStream> character_stream_;
  std::unique_ptr<ConsumedPreparseData> consumed_preparse_data_;
  const AstRawString* function_name_;
  RuntimeCallStats* runtime_call_stats_;
  SourceRangeMap* source_range_map_;  // Used when block coverage is enabled.

  //----------- Output of parsing and scope analysis ------------------------
  FunctionLiteral* literal_;
  bool allow_eval_cache_ : 1;
#if V8_ENABLE_WEBASSEMBLY
  bool contains_asm_module_ : 1;
#endif  // V8_ENABLE_WEBASSEMBLY
  LanguageMode language_mode_ : 1;
  bool is_background_compilation_ : 1;
  bool is_streaming_compilation_ : 1;
  bool has_module_in_scope_chain_ : 1;
};

}  // namespace internal
}  // namespace v8

#endif  // V8_PARSING_PARSE_INFO_H_
```