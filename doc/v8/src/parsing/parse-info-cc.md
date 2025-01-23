Response:
Let's break down the thought process for analyzing the `parse-info.cc` file.

1. **Understand the Goal:** The request asks for the functionalities of the `parse-info.cc` file in V8, explanations relating to JavaScript, examples, and potential programming errors.

2. **Initial Scan for Key Information:** Quickly skim the code looking for important keywords, class names, function names, and included headers. This gives a high-level overview.

    * Headers: `ast/ast-source-ranges.h`, `ast/ast-value-factory.h`, `ast/ast.h`, `base/logging.h`, `common/globals.h`, `compiler-dispatcher/lazy-compile-dispatcher.h`, `heap/heap-inl.h`, `logging/counters.h`, `logging/log.h`, `numbers/hash-seed-inl.h`, `objects/objects-inl.h`, `objects/scope-info.h`, `zone/zone.h`. These suggest interaction with the AST (Abstract Syntax Tree), heap, logging, and general V8 infrastructure. The "parsing" in the directory name reinforces the AST connection.
    * Namespaces: `v8::internal`. This indicates internal V8 functionality.
    * Class Names: `UnoptimizedCompileFlags`, `ReusableUnoptimizedCompileState`, `ParseInfo`. These are likely the core components.
    * Function Names:  Methods within the classes like `ForFunctionCompile`, `ForScriptCompile`, `SetFlagsFromFunction`, `CreateScript`, `AllocateSourceRangeMap`. These provide clues about the operations performed.

3. **Focus on the Core Class: `ParseInfo`:**  The file name strongly suggests this class is central. Analyze its members and constructor.

    * Members: `flags_`, `state_`, `reusable_state_`, `extension_`, `script_scope_`, `stack_limit_`, `parameters_end_pos_`, `max_info_id_`, `character_stream_`, `function_name_`, `runtime_call_stats_`, `source_range_map_`, `literal_`, `allow_eval_cache_`, `contains_asm_module_`, `language_mode_`, `is_background_compilation_`, `is_streaming_compilation_`, `has_module_in_scope_chain_`. Many of these seem related to compilation settings, source code representation, and optimization.
    * Constructor: Takes `UnoptimizedCompileFlags`, `UnoptimizedCompileState`, `ReusableUnoptimizedCompileState`, and other parameters. This confirms the dependencies between these classes.

4. **Analyze Helper Classes:** Examine `UnoptimizedCompileFlags` and `ReusableUnoptimizedCompileState`.

    * `UnoptimizedCompileFlags`:  A large number of boolean flags (using `set_`). Methods like `ForFunctionCompile`, `ForScriptCompile`, `ForToplevelCompile` suggest different compilation scenarios. This class seems to configure the *type* of compilation.
    * `ReusableUnoptimizedCompileState`: Members like `hash_seed_`, `allocator_`, `v8_file_logger_`, `dispatcher_`, `ast_string_constants_`, `ast_raw_string_zone_`, `single_parse_zone_`, `ast_value_factory_`. This looks like a collection of resources needed during parsing, aimed at reuse. The names clearly point to AST creation and management.

5. **Connect the Dots:**  Understand how these classes interact. `ParseInfo` *holds* instances of `UnoptimizedCompileFlags` and uses `ReusableUnoptimizedCompileState`. The `UnoptimizedCompileFlags` configure *how* to compile, and the `ReusableUnoptimizedCompileState` provides the *tools* for compilation. `ParseInfo` itself seems to be a container for information needed during parsing.

6. **Relate to JavaScript:** Consider how the concepts in the code relate to JavaScript.

    * Parsing: The core function of turning JavaScript text into an internal representation (AST).
    * Compilation Flags:  JavaScript features, like modules, `eval`, and different language modes (strict, sloppy), influence how the code is parsed and compiled. The flags in `UnoptimizedCompileFlags` directly correspond to these.
    * Script Object: The `CreateScript` method creates a V8 internal representation of a JavaScript script. This is a key step in executing JavaScript code.
    * Error Handling: While not explicitly present in this snippet, the parsing process is crucial for detecting syntax errors.

7. **Construct Examples:** Create JavaScript examples that demonstrate the concepts.

    * Modules: Show how the `is_module` flag relates to JavaScript modules.
    * `eval`: Illustrate how the `is_eval` flag is relevant.
    * Strict Mode:  Demonstrate the effect of `'use strict'` on parsing (although the code doesn't directly show *how* strict mode is handled, it sets flags related to it).

8. **Identify Potential Errors:** Think about common JavaScript programming mistakes that the parser would encounter.

    * Syntax Errors:  Mismatched brackets, incorrect keywords.
    * `eval` Usage:  Explain the performance and security implications.
    * Module Issues:  Import/export errors, circular dependencies.

9. **Address Specific Instructions:**

    * **Functionality Listing:** Summarize the identified roles of the file and its classes.
    * **`.tq` Extension:** Explicitly state that `.cc` means C++ and `.tq` would mean Torque.
    * **JavaScript Relationship:** Provide the JavaScript examples.
    * **Logic Reasoning:**  Choose a simple function (like `SetFlagsForToplevelCompile`) and demonstrate how input flags affect the internal state. Create hypothetical input and output.
    * **Common Errors:**  List and explain common JavaScript errors related to parsing.

10. **Review and Refine:** Read through the generated explanation, ensuring clarity, accuracy, and completeness. Check if all parts of the original request have been addressed. For example, ensure the explanation of each class and its methods is understandable.

This systematic approach, starting with a broad overview and then focusing on details while connecting them to the overall goal, helps in effectively analyzing and understanding complex source code like this.
好的，让我们来分析一下 `v8/src/parsing/parse-info.cc` 这个 V8 源代码文件的功能。

**功能概述:**

`v8/src/parsing/parse-info.cc` 文件定义了 `ParseInfo` 类及其相关的辅助类，这些类是 V8 引擎在解析 JavaScript 代码时用于存储和传递解析配置和状态信息的关键数据结构。 简单来说，它像一个容器，携带了解析器工作所需的所有上下文信息。

**主要功能点:**

1. **存储编译标志 (Compilation Flags):**
   -  `UnoptimizedCompileFlags` 类负责存储影响代码解析和初始编译方式的各种标志。这些标志控制着是否启用某些特性（例如代码覆盖率）、允许使用的语法（例如 `allow_natives_syntax`）、以及是否进行延迟编译等。
   -  `ParseInfo` 对象持有一个 `UnoptimizedCompileFlags` 实例，以便在解析过程中可以访问和使用这些配置。

2. **管理编译状态 (Compilation State):**
   - `ReusableUnoptimizedCompileState` 类管理在非优化编译阶段可以重用的资源，例如哈希种子、内存分配器、日志记录器、AST 字符串常量工厂和内存区域 (Zone)。
   - `ParseInfo` 对象关联着一个 `ReusableUnoptimizedCompileState` 实例，允许在解析过程中使用这些共享资源。

3. **传递解析上下文信息:**
   - `ParseInfo` 类本身存储了关于当前正在解析的代码的各种信息，例如：
     - 脚本 ID (`script_id_`)
     - 堆栈限制 (`stack_limit_`)
     - 参数结束位置 (`parameters_end_pos_`)
     - 函数名 (`function_name_`)
     - 源代码范围映射 (`source_range_map_`)，用于代码覆盖率
     - 字面量 (`literal_`)，代表正在解析的函数或脚本
     - 语言模式 (`language_mode_`)，例如严格模式或非严格模式
     - 是否为模块 (`is_module()`)
     - 是否为 `eval` 代码 (`is_eval()`)
     - 是否为后台编译或流式编译
   - 这些信息在解析器的不同阶段之间传递，确保解析过程能够正确地进行。

4. **创建 `Script` 对象:**
   - `ParseInfo::CreateScript` 方法用于创建一个 `Script` 对象，它是 V8 内部表示 JavaScript 代码的结构。这个方法使用 `ParseInfo` 中存储的编译标志和脚本元数据来初始化 `Script` 对象。

**如果 `v8/src/parsing/parse-info.cc` 以 `.tq` 结尾:**

如果 `v8/src/parsing/parse-info.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码**文件。Torque 是 V8 用来生成高效的内置函数和运行时代码的领域特定语言。在这种情况下，该文件将包含使用 Torque 语法编写的代码，用于实现与解析信息管理相关的底层逻辑。  当前的 `.cc` 后缀表明它是 C++ 源代码。

**与 JavaScript 功能的关系及 JavaScript 示例:**

`ParseInfo` 直接关系到 V8 如何理解和处理 JavaScript 代码。它携带的编译标志和上下文信息影响着 JavaScript 代码的语法解析、作用域分析以及后续的编译和执行。

**JavaScript 示例:**

```javascript
// 示例 1: 模块 vs. 脚本
// 当解析一个模块时，ParseInfo 中的 is_module() 会被设置为 true

// 模块 (module.js)
export function greet(name) {
  console.log(`Hello, ${name}!`);
}

// 脚本 (script.js)
function sayHello(name) {
  console.log("Hello " + name);
}
sayHello("World");

// 示例 2: eval
// 当解析 eval 中的代码时，ParseInfo 中的 is_eval() 会被设置为 true
function runEval(code) {
  eval(code);
}
runEval("console.log('This is from eval');");

// 示例 3: 严格模式
// 当解析包含 "use strict" 指令的代码时，ParseInfo 中的 language_mode_ 会被设置为严格模式
"use strict";
function strictFunction() {
  // ... 严格模式下的代码
}
```

在 V8 内部，当解析器遇到这些不同的 JavaScript 代码结构时，会相应地设置 `ParseInfo` 对象中的标志。例如，解析模块时设置 `is_module_`，解析 `eval` 代码时设置 `is_eval_`，解析包含 `"use strict"` 的代码时设置相应的语言模式。这些标志会影响后续的解析和编译行为。

**代码逻辑推理及假设输入与输出:**

让我们以 `UnoptimizedCompileFlags::SetFlagsForToplevelCompile` 方法为例进行代码逻辑推理。

**假设输入:**

```c++
Isolate* isolate = ...; // 假设已获取 Isolate 实例
bool is_user_javascript = true;
LanguageMode language_mode = LanguageMode::kSloppy;
REPLMode repl_mode = REPLMode::kNo;
ScriptType type = ScriptType::kClassic;
bool lazy = true;
```

**代码逻辑:**

```c++
void UnoptimizedCompileFlags::SetFlagsForToplevelCompile(
    bool is_user_javascript, LanguageMode language_mode, REPLMode repl_mode,
    ScriptType type, bool lazy) {
  set_is_toplevel(true);
  set_allow_lazy_parsing(lazy);
  set_allow_lazy_compile(lazy);
  set_outer_language_mode(
      stricter_language_mode(outer_language_mode(), language_mode));
  set_is_repl_mode((repl_mode == REPLMode::kYes));
  set_is_module(type == ScriptType::kModule);
  DCHECK_IMPLIES(is_eval(), !is_module());

  set_block_coverage_enabled(block_coverage_enabled() && is_user_javascript);
}
```

**推理过程:**

1. `set_is_toplevel(true);`:  无论输入如何，顶级编译的 `is_toplevel` 标志都会被设置为 `true`。
2. `set_allow_lazy_parsing(lazy);` 和 `set_allow_lazy_compile(lazy);`: 这两个标志的值直接取决于输入的 `lazy` 参数。如果 `lazy` 为 `true`，则允许延迟解析和编译。
3. `set_outer_language_mode(...)`:  `outer_language_mode()` 的当前值会与输入的 `language_mode` 进行比较，取更严格的模式。如果当前的 `outer_language_mode` 已经是严格模式，那么即使输入的是非严格模式，最终也会保持严格模式。
4. `set_is_repl_mode((repl_mode == REPLMode::kYes));`:  如果输入的 `repl_mode` 是 `REPLMode::kYes`，则 `is_repl_mode` 会被设置为 `true`。
5. `set_is_module(type == ScriptType::kModule);`: 如果输入的 `type` 是 `ScriptType::kModule`，则 `is_module` 会被设置为 `true`。
6. `DCHECK_IMPLIES(is_eval(), !is_module());`: 这是一个断言，用于确保如果当前是 `eval` 代码，则不能同时是模块。
7. `set_block_coverage_enabled(...)`:  只有当当前的 `block_coverage_enabled()` 为 `true` 且 `is_user_javascript` 也为 `true` 时，代码块覆盖率才会被启用。

**假设输出 (基于上述输入):**

假设在调用 `SetFlagsForToplevelCompile` 之前，`UnoptimizedCompileFlags` 对象的 `block_coverage_enabled()` 为 `true`，且 `outer_language_mode()` 为 `LanguageMode::kSloppy`。

调用 `SetFlagsForToplevelCompile(true, LanguageMode::kSloppy, REPLMode::kNo, ScriptType::kClassic, true)` 后，`UnoptimizedCompileFlags` 对象的状态可能会变成：

- `is_toplevel()`: `true`
- `allow_lazy_parsing()`: `true`
- `allow_lazy_compile()`: `true`
- `outer_language_mode()`: `LanguageMode::kSloppy` (因为传入的也是非严格模式)
- `is_repl_mode()`: `false`
- `is_module()`: `false`
- `block_coverage_enabled()`: `true`

**涉及用户常见的编程错误:**

虽然 `parse-info.cc` 本身不直接处理用户编写的 JavaScript 代码的错误，但它存储的信息间接地与这些错误有关。例如：

1. **语法错误:**  如果用户编写了不符合 JavaScript 语法的代码，解析器在解析过程中会发现这些错误，并可能在创建或使用 `ParseInfo` 对象时抛出异常或记录错误信息。`ParseInfo` 中存储的脚本 ID 等信息可以帮助定位错误发生的源文件。

   ```javascript
   // 示例：语法错误
   functoin myFunc() { // 拼写错误
       console.log("Hello");
   }
   ```

2. **`eval` 的滥用:**  虽然 `ParseInfo` 允许标记 `eval` 代码，但过度或不安全地使用 `eval` 是一个常见的编程错误，可能导致安全漏洞和性能问题。

   ```javascript
   // 示例：eval 的潜在风险
   let userInput = "<script>alert('XSS!');</script>";
   eval(userInput); // 危险！
   ```

3. **模块导入/导出错误:**  如果用户在模块中使用了错误的 `import` 或 `export` 语法，解析器会根据 `ParseInfo` 中 `is_module()` 的状态来判断是否允许这些语法，并在发现错误时报错。

   ```javascript
   // 示例：模块导入错误
   // moduleA.js
   export const message = "Hello";

   // moduleB.js
   import msage from './moduleA.js'; // 拼写错误
   console.log(msage);
   ```

4. **严格模式下的错误:**  在严格模式下，一些在非严格模式下被允许的“不好的”做法会被禁止并抛出错误。`ParseInfo` 中存储的语言模式信息决定了解析器是否应该应用严格模式的规则。

   ```javascript
   // 示例：严格模式下的错误
   "use strict";
   variableWithoutDeclaration = 10; // 错误：未声明的变量
   ```

总而言之，`v8/src/parsing/parse-info.cc` 定义的类是 V8 引擎解析 JavaScript 代码的基础设施，它携带了解析器工作所需的各种配置和上下文信息，并间接地影响着对用户代码的正确理解和执行。

### 提示词
```
这是目录为v8/src/parsing/parse-info.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/parsing/parse-info.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/parsing/parse-info.h"

#include "src/ast/ast-source-ranges.h"
#include "src/ast/ast-value-factory.h"
#include "src/ast/ast.h"
#include "src/base/logging.h"
#include "src/common/globals.h"
#include "src/compiler-dispatcher/lazy-compile-dispatcher.h"
#include "src/heap/heap-inl.h"
#include "src/logging/counters.h"
#include "src/logging/log.h"
#include "src/numbers/hash-seed-inl.h"
#include "src/objects/objects-inl.h"
#include "src/objects/scope-info.h"
#include "src/zone/zone.h"

namespace v8 {
namespace internal {

UnoptimizedCompileFlags::UnoptimizedCompileFlags(Isolate* isolate,
                                                 int script_id)
    : flags_(0),
      script_id_(script_id),
      function_kind_(FunctionKind::kNormalFunction),
      function_syntax_kind_(FunctionSyntaxKind::kDeclaration),
      parsing_while_debugging_(ParsingWhileDebugging::kNo) {
  set_coverage_enabled(!isolate->is_best_effort_code_coverage());
  set_block_coverage_enabled(isolate->is_block_code_coverage());
  set_might_always_turbofan(v8_flags.always_turbofan ||
                            v8_flags.prepare_always_turbofan);
  set_allow_natives_syntax(v8_flags.allow_natives_syntax);
  set_allow_lazy_compile(true);
  set_collect_source_positions(!v8_flags.enable_lazy_source_positions ||
                               isolate->NeedsDetailedOptimizedCodeLineInfo());
  set_post_parallel_compile_tasks_for_eager_toplevel(
      v8_flags.parallel_compile_tasks_for_eager_toplevel);
  set_post_parallel_compile_tasks_for_lazy(
      v8_flags.parallel_compile_tasks_for_lazy);
}

// static
UnoptimizedCompileFlags UnoptimizedCompileFlags::ForFunctionCompile(
    Isolate* isolate, Tagged<SharedFunctionInfo> shared) {
  Tagged<Script> script = Cast<Script>(shared->script());

  UnoptimizedCompileFlags flags(isolate, script->id());

  flags.SetFlagsForFunctionFromScript(script);
  flags.SetFlagsFromFunction(shared);
  flags.set_allow_lazy_parsing(true);
  flags.set_is_lazy_compile(true);

#if V8_ENABLE_WEBASSEMBLY
  flags.set_is_asm_wasm_broken(shared->is_asm_wasm_broken());
#endif  // V8_ENABLE_WEBASSEMBLY
  flags.set_is_repl_mode(script->is_repl_mode());

  // Do not support re-parsing top-level function of a wrapped script.
  DCHECK_IMPLIES(flags.is_toplevel(), !script->is_wrapped());

  return flags;
}

// static
UnoptimizedCompileFlags UnoptimizedCompileFlags::ForScriptCompile(
    Isolate* isolate, Tagged<Script> script) {
  UnoptimizedCompileFlags flags(isolate, script->id());

  flags.SetFlagsForFunctionFromScript(script);
  flags.SetFlagsForToplevelCompile(
      script->IsUserJavaScript(), flags.outer_language_mode(),
      construct_repl_mode(script->is_repl_mode()),
      script->origin_options().IsModule() ? ScriptType::kModule
                                          : ScriptType::kClassic,
      v8_flags.lazy);
  if (script->is_wrapped()) {
    flags.set_function_syntax_kind(FunctionSyntaxKind::kWrapped);
  }

  return flags;
}

// static
UnoptimizedCompileFlags UnoptimizedCompileFlags::ForToplevelCompile(
    Isolate* isolate, bool is_user_javascript, LanguageMode language_mode,
    REPLMode repl_mode, ScriptType type, bool lazy) {
  UnoptimizedCompileFlags flags(isolate, isolate->GetNextScriptId());
  flags.SetFlagsForToplevelCompile(is_user_javascript, language_mode, repl_mode,
                                   type, lazy);
  LOG(isolate, ScriptEvent(ScriptEventType::kReserveId, flags.script_id()));
  return flags;
}

// static
UnoptimizedCompileFlags UnoptimizedCompileFlags::ForToplevelFunction(
    const UnoptimizedCompileFlags toplevel_flags,
    const FunctionLiteral* literal) {
  DCHECK(toplevel_flags.is_toplevel());
  DCHECK(!literal->is_toplevel());

  // Replicate the toplevel flags, then setup the function-specific flags.
  UnoptimizedCompileFlags flags = toplevel_flags;
  flags.SetFlagsFromFunction(literal);

  return flags;
}

// static
UnoptimizedCompileFlags UnoptimizedCompileFlags::ForTest(Isolate* isolate) {
  return UnoptimizedCompileFlags(isolate, Script::kTemporaryScriptId);
}

template <typename T>
void UnoptimizedCompileFlags::SetFlagsFromFunction(T function) {
  set_outer_language_mode(function->language_mode());
  set_function_kind(function->kind());
  set_function_syntax_kind(function->syntax_kind());
  set_requires_instance_members_initializer(
      function->requires_instance_members_initializer());
  set_class_scope_has_private_brand(function->class_scope_has_private_brand());
  set_has_static_private_methods_or_accessors(
      function->has_static_private_methods_or_accessors());
  set_private_name_lookup_skips_outer_class(
      function->private_name_lookup_skips_outer_class());
  set_is_toplevel(function->is_toplevel());
}

void UnoptimizedCompileFlags::SetFlagsForToplevelCompile(
    bool is_user_javascript, LanguageMode language_mode, REPLMode repl_mode,
    ScriptType type, bool lazy) {
  set_is_toplevel(true);
  set_allow_lazy_parsing(lazy);
  set_allow_lazy_compile(lazy);
  set_outer_language_mode(
      stricter_language_mode(outer_language_mode(), language_mode));
  set_is_repl_mode((repl_mode == REPLMode::kYes));
  set_is_module(type == ScriptType::kModule);
  DCHECK_IMPLIES(is_eval(), !is_module());

  set_block_coverage_enabled(block_coverage_enabled() && is_user_javascript);
}

void UnoptimizedCompileFlags::SetFlagsForFunctionFromScript(
    Tagged<Script> script) {
  DCHECK_EQ(script_id(), script->id());

  set_is_eval(script->compilation_type() == Script::CompilationType::kEval);
  set_is_module(script->origin_options().IsModule());
  DCHECK_IMPLIES(is_eval(), !is_module());

  set_block_coverage_enabled(block_coverage_enabled() &&
                             script->IsUserJavaScript());
}

ReusableUnoptimizedCompileState::ReusableUnoptimizedCompileState(
    Isolate* isolate)
    : hash_seed_(HashSeed(isolate)),
      allocator_(isolate->allocator()),
      v8_file_logger_(isolate->v8_file_logger()),
      dispatcher_(isolate->lazy_compile_dispatcher()),
      ast_string_constants_(isolate->ast_string_constants()),
      ast_raw_string_zone_(allocator_,
                           "unoptimized-compile-ast-raw-string-zone"),
      single_parse_zone_(allocator_, "unoptimized-compile-parse-zone"),
      ast_value_factory_(
          new AstValueFactory(ast_raw_string_zone(), single_parse_zone(),
                              ast_string_constants(), hash_seed())) {}

ReusableUnoptimizedCompileState::ReusableUnoptimizedCompileState(
    LocalIsolate* isolate)
    : hash_seed_(HashSeed(isolate)),
      allocator_(isolate->allocator()),
      v8_file_logger_(isolate->main_thread_logger()),
      dispatcher_(isolate->lazy_compile_dispatcher()),
      ast_string_constants_(isolate->ast_string_constants()),
      ast_raw_string_zone_(allocator_,
                           "unoptimized-compile-ast-raw-string-zone"),
      single_parse_zone_(allocator_, "unoptimized-compile-parse-zone"),
      ast_value_factory_(
          new AstValueFactory(ast_raw_string_zone(), single_parse_zone(),
                              ast_string_constants(), hash_seed())) {}

ReusableUnoptimizedCompileState::~ReusableUnoptimizedCompileState() = default;

ParseInfo::ParseInfo(const UnoptimizedCompileFlags flags,
                     UnoptimizedCompileState* state,
                     ReusableUnoptimizedCompileState* reusable_state,
                     uintptr_t stack_limit,
                     RuntimeCallStats* runtime_call_stats)
    : flags_(flags),
      state_(state),
      reusable_state_(reusable_state),
      extension_(nullptr),
      script_scope_(nullptr),
      stack_limit_(stack_limit),
      parameters_end_pos_(kNoSourcePosition),
      max_info_id_(kInvalidInfoId),
      character_stream_(nullptr),
      function_name_(nullptr),
      runtime_call_stats_(runtime_call_stats),
      source_range_map_(nullptr),
      literal_(nullptr),
      allow_eval_cache_(false),
#if V8_ENABLE_WEBASSEMBLY
      contains_asm_module_(false),
#endif  // V8_ENABLE_WEBASSEMBLY
      language_mode_(flags.outer_language_mode()),
      is_background_compilation_(false),
      is_streaming_compilation_(false),
      has_module_in_scope_chain_(flags.is_module()) {
  if (flags.block_coverage_enabled()) {
    AllocateSourceRangeMap();
  }
}

ParseInfo::ParseInfo(Isolate* isolate, const UnoptimizedCompileFlags flags,
                     UnoptimizedCompileState* state,
                     ReusableUnoptimizedCompileState* reusable_state)
    : ParseInfo(flags, state, reusable_state,
                isolate->stack_guard()->real_climit(),
                isolate->counters()->runtime_call_stats()) {}

ParseInfo::ParseInfo(LocalIsolate* isolate, const UnoptimizedCompileFlags flags,
                     UnoptimizedCompileState* state,
                     ReusableUnoptimizedCompileState* reusable_state,
                     uintptr_t stack_limit)
    : ParseInfo(flags, state, reusable_state, stack_limit,
                isolate->runtime_call_stats()) {}

ParseInfo::~ParseInfo() { reusable_state_->NotifySingleParseCompleted(); }

DeclarationScope* ParseInfo::scope() const { return literal()->scope(); }

template <typename IsolateT>
Handle<Script> ParseInfo::CreateScript(
    IsolateT* isolate, Handle<String> source,
    MaybeHandle<FixedArray> maybe_wrapped_arguments,
    ScriptOriginOptions origin_options, NativesFlag natives) {
  // Create a script object describing the script to be compiled.
  DCHECK(flags().script_id() >= 0 ||
         flags().script_id() == Script::kTemporaryScriptId);
  auto event = ScriptEventType::kCreate;
  if (is_streaming_compilation()) {
    event = is_background_compilation()
                ? ScriptEventType::kStreamingCompileBackground
                : ScriptEventType::kStreamingCompileForeground;
  } else if (is_background_compilation()) {
    event = ScriptEventType::kBackgroundCompile;
  }
  Handle<Script> script =
      isolate->factory()->NewScriptWithId(source, flags().script_id(), event);
  DisallowGarbageCollection no_gc;
  Tagged<Script> raw_script = *script;
  switch (natives) {
    case EXTENSION_CODE:
      raw_script->set_type(Script::Type::kExtension);
      break;
    case INSPECTOR_CODE:
      raw_script->set_type(Script::Type::kInspector);
      break;
    case NOT_NATIVES_CODE:
      break;
  }
  raw_script->set_origin_options(origin_options);
  raw_script->set_is_repl_mode(flags().is_repl_mode());

  DCHECK_EQ(is_wrapped_as_function(), !maybe_wrapped_arguments.is_null());
  if (is_wrapped_as_function()) {
    raw_script->set_wrapped_arguments(
        *maybe_wrapped_arguments.ToHandleChecked());
  } else if (flags().is_eval()) {
    raw_script->set_compilation_type(Script::CompilationType::kEval);
  }
  CheckFlagsForToplevelCompileFromScript(raw_script);

  return script;
}

template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)
    Handle<Script> ParseInfo::CreateScript(
        Isolate* isolate, Handle<String> source,
        MaybeHandle<FixedArray> maybe_wrapped_arguments,
        ScriptOriginOptions origin_options, NativesFlag natives);
template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)
    Handle<Script> ParseInfo::CreateScript(
        LocalIsolate* isolate, Handle<String> source,
        MaybeHandle<FixedArray> maybe_wrapped_arguments,
        ScriptOriginOptions origin_options, NativesFlag natives);

void ParseInfo::AllocateSourceRangeMap() {
  DCHECK(flags().block_coverage_enabled());
  DCHECK_NULL(source_range_map());
  set_source_range_map(zone()->New<SourceRangeMap>(zone()));
}

void ParseInfo::ResetCharacterStream() { character_stream_.reset(); }

void ParseInfo::set_character_stream(
    std::unique_ptr<Utf16CharacterStream> character_stream) {
  DCHECK_NULL(character_stream_);
  character_stream_.swap(character_stream);
}

void ParseInfo::CheckFlagsForToplevelCompileFromScript(Tagged<Script> script) {
  CheckFlagsForFunctionFromScript(script);
  DCHECK(flags().is_toplevel());
  DCHECK_EQ(flags().is_repl_mode(), script->is_repl_mode());

  if (script->is_wrapped()) {
    DCHECK_EQ(flags().function_syntax_kind(), FunctionSyntaxKind::kWrapped);
  }
}

void ParseInfo::CheckFlagsForFunctionFromScript(Tagged<Script> script) {
  DCHECK_EQ(flags().script_id(), script->id());
  // We set "is_eval" for wrapped scripts to get an outer declaration scope.
  // This is a bit hacky, but ok since we can't be both eval and wrapped.
  DCHECK_EQ(flags().is_eval() && !script->is_wrapped(),
            script->compilation_type() == Script::CompilationType::kEval);
  DCHECK_EQ(flags().is_module(), script->origin_options().IsModule());
  DCHECK_IMPLIES(flags().block_coverage_enabled() && script->IsUserJavaScript(),
                 source_range_map() != nullptr);
}

}  // namespace internal
}  // namespace v8
```