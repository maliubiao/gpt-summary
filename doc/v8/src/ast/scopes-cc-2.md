Response:
The user wants me to analyze a C++ source code file from the V8 JavaScript engine. Specifically, the file `v8/src/ast/scopes.cc`.

Here's a breakdown of the requested analysis:

1. **Functionality:** Describe what this code does.
2. **Torque Check:** Determine if the filename ends with `.tq`. If so, it's related to V8's Torque language.
3. **JavaScript Relationship:** If the code interacts with JavaScript features, provide JavaScript examples.
4. **Code Logic Inference:**  Present scenarios with hypothetical inputs and outputs to illustrate the logic.
5. **Common Programming Errors:**  Highlight potential mistakes developers might make in relation to the code's functionality.
6. **Summary:** Concisely summarize the overall function of the code.
7. **Part Number:** Acknowledge that this is part 3 of 4.

Let's go through each point.

**1. Functionality:** The code deals with the concept of "scopes" in JavaScript. It seems responsible for managing how variables are declared, accessed, and resolved within different parts of a JavaScript program (functions, blocks, etc.). Key aspects likely include:

    * Representing different scope types (global, function, block, etc.).
    * Tracking variables declared within each scope.
    * Determining where a variable is located (stack, heap, context).
    * Handling variable lookups and resolving references.
    * Managing how variables are accessed from nested scopes.
    * Dealing with special scope types like `eval` and `with`.

**2. Torque Check:**  The provided filename `v8/src/ast/scopes.cc` ends with `.cc`, not `.tq`. So, it's standard C++, not Torque.

**3. JavaScript Relationship:**  Since it's about scopes, there's a direct link to fundamental JavaScript concepts. Examples should illustrate how variable declarations and access behave in different scopes.

**4. Code Logic Inference:**  This will require looking at specific parts of the code and imagining inputs (e.g., a variable proxy, a scope) and predicting the output (e.g., the resolved variable, an error condition).

**5. Common Programming Errors:**  This could involve things like:

    * Accessing variables before they are declared (temporal dead zone).
    * Confusing scope boundaries and variable visibility.
    * Misunderstanding the behavior of `var`, `let`, and `const`.
    * Issues with `eval` and `with` affecting scope.

**6. Summary:**  A concise statement capturing the main responsibility of the `scopes.cc` file.

**7. Part Number:** Simply stating that this is part 3 of 4.

Now, let's start generating the response, keeping these points in mind as I analyze the provided code snippet.
```
功能列举:

这段 C++ 代码是 V8 引擎中负责管理 JavaScript 代码作用域的核心部分。它定义了 `Scope` 类及其子类，用于表示不同类型的 JavaScript 作用域，并处理与作用域相关的操作，例如：

1. **作用域表示:**  定义了 `Scope` 类以及各种子类（如 `DeclarationScope`, `BlockScope`, `FunctionScope` 等）来表示不同类型的 JavaScript 作用域（全局作用域、函数作用域、块级作用域、catch 作用域等）。
2. **变量管理:**  在每个作用域内维护一个变量表 (`variables_`)，用于存储在该作用域内声明的变量。记录变量的名称、模式（var, let, const 等）、位置（栈、堆、上下文等）以及其他属性。
3. **变量查找:**  提供了 `Lookup` 函数，用于在作用域链中查找变量。它会从当前作用域向上遍历父作用域，直到找到目标变量或到达作用域链的顶端。
4. **变量解析:**  `ResolveVariable` 函数用于将变量引用（`VariableProxy`）绑定到实际的变量声明 (`Variable`)。
5. **变量分配:**  负责为变量分配存储空间（栈或堆）。`AllocateStackSlot`, `AllocateHeapSlot` 等函数用于执行此操作。
6. **预解析支持:**  支持代码的预解析阶段，例如 `SavePreparseData`, `ResetAfterPreparsing` 等函数表明了对预解析数据的处理。
7. **调试支持:**  包含了大量的调试代码（`#ifdef DEBUG`），例如 `Print`, `CheckScopePositions`, `CheckZones` 等函数用于在开发和调试过程中打印作用域信息和进行一致性检查。
8. **'eval' 和 'with' 处理:**  特殊处理了 `eval` 和 `with` 语句对作用域的影响，例如 `LookupSloppyEval`, `LookupWith`。
9. **模块支持:**  包含了对 JavaScript 模块作用域 (`ModuleScope`) 的处理。
10. **REPL 支持:**  包含对 REPL 环境下全局变量的处理 (`RewriteReplGlobalVariables`)。
11. **闭包管理:**  通过作用域链来管理闭包。

如果 v8/src/ast/scopes.cc 以 .tq 结尾：

如果 `v8/src/ast/scopes.cc` 以 `.tq` 结尾，那么它将是一个使用 V8 的 Torque 语言编写的源代码文件。Torque 是一种用于编写 V8 内部代码的领域特定语言，旨在提供更好的类型安全性和性能。在这种情况下，该文件将包含用 Torque 语法编写的作用域管理逻辑。

与 javascript 的功能关系及举例:

`v8/src/ast/scopes.cc` 中的代码直接对应于 JavaScript 中作用域的概念和行为。它实现了 JavaScript 引擎在执行代码时如何理解和管理变量的可见性和生命周期。

**JavaScript 示例:**

```javascript
// 函数作用域
function myFunction() {
  var localVar = 10;
  console.log(localVar); // 可以访问 localVar
}
myFunction();
// console.log(localVar); // 错误：localVar 在函数外部不可访问

// 块级作用域 (let 和 const)
if (true) {
  let blockVar = 20;
  const blockConst = 30;
  console.log(blockVar, blockConst); // 可以访问 blockVar 和 blockConst
}
// console.log(blockVar); // 错误：blockVar 在块外部不可访问
// console.log(blockConst); // 错误：blockConst 在块外部不可访问

// 全局作用域
var globalVar = 40;
console.log(globalVar); // 可以在任何地方访问 globalVar

function anotherFunction() {
  console.log(globalVar); // 可以在函数内部访问 globalVar
}
anotherFunction();
```

在上述 JavaScript 示例中，`v8/src/ast/scopes.cc` 中的代码负责创建和管理 `myFunction` 的函数作用域，以及 `if` 语句的块级作用域。它会记录 `localVar`、`blockVar`、`blockConst` 和 `globalVar` 这些变量，并确保在正确的作用域内可以访问它们。当尝试在作用域外访问变量时，V8 引擎会根据其维护的作用域信息抛出错误。

代码逻辑推理 (假设输入与输出):

**假设输入:**

1. 一个包含以下 JavaScript 代码的抽象语法树 (AST):
    ```javascript
    function outer() {
      var a = 1;
      function inner() {
        var b = 2;
        console.log(a + b);
      }
      inner();
    }
    outer();
    ```
2. 在解析 `inner` 函数时，需要查找变量 `a`。

**代码逻辑推理:**

1. 当解析器遇到 `console.log(a + b)` 中的 `a` 时，会创建一个 `VariableProxy` 来表示对变量 `a` 的引用。
2. `Scope::Lookup` 函数会被调用，并从 `inner` 函数的作用域开始查找。
3. `inner` 函数的作用域中没有名为 `a` 的本地变量。
4. `Lookup` 函数会沿着作用域链向上查找 `inner` 函数的父作用域，即 `outer` 函数的作用域。
5. 在 `outer` 函数的作用域中找到了名为 `a` 的变量。
6. `Lookup` 函数返回指向 `outer` 作用域中 `a` 变量的指针。
7. `ResolveTo` 函数将 `VariableProxy` 绑定到找到的 `Variable`。

**假设输出:**

`inner` 函数中的 `VariableProxy` 成功绑定到 `outer` 函数作用域中声明的 `a` 变量。

涉及用户常见的编程错误及举例:

1. **未声明的变量:**  在 strict 模式下，尝试使用未声明的变量会导致 `ReferenceError`。

    ```javascript
    "use strict";
    function foo() {
      undeclaredVar = 5; // ReferenceError: undeclaredVar is not defined
    }
    foo();
    ```

    `v8/src/ast/scopes.cc` 中的代码在解析时会检查变量是否已声明。

2. **块级作用域变量的提前使用 (Temporal Dead Zone):** 使用 `let` 或 `const` 声明的变量在其声明之前访问会导致 `ReferenceError`。

    ```javascript
    function bar() {
      console.log(myLet); // ReferenceError: Cannot access 'myLet' before initialization
      let myLet = 10;
    }
    bar();
    ```

    `v8/src/ast/scopes.cc` 中的代码会跟踪 `let` 和 `const` 变量的声明位置，并在访问时进行检查。`UpdateNeedsHoleCheck` 函数可能与此有关。

3. **错误地理解 `var` 的作用域提升:** `var` 声明的变量会被提升到其所在函数或全局作用域的顶部，可能导致意外的行为。

    ```javascript
    function baz() {
      console.log(myVar); // 输出 undefined，因为 myVar 被提升了，但还没有赋值
      var myVar = 20;
    }
    baz();
    ```

    `v8/src/ast/scopes.cc` 中的代码会处理 `var` 声明的提升行为。

4. **在 `eval` 中引入变量导致的作用域问题:**  `eval` 可以在当前作用域中引入新的变量，这可能导致难以预测的行为。

    ```javascript
    function qux() {
      eval('var evalVar = 30;');
      console.log(evalVar); // 可以访问 evalVar
    }
    qux();
    // console.log(evalVar); // 如果在 qux 外部，则无法访问
    ```

    `v8/src/ast/scopes.cc` 中 `LookupSloppyEval` 等函数处理了 `eval` 对作用域的影响。

归纳一下它的功能:

`v8/src/ast/scopes.cc` 负责在 V8 引擎中创建、管理和维护 JavaScript 代码的作用域。它定义了表示不同作用域类型的类，跟踪在每个作用域中声明的变量，并实现了变量查找、解析和分配的逻辑。该文件是 V8 引擎理解和执行 JavaScript 代码中作用域规则的关键组成部分，直接影响着变量的可见性、生命周期和访问方式。它还处理了诸如 `eval`、`with` 和模块等特殊情况下的作用域行为，并为调试提供了支持。
```
### 提示词
```
这是目录为v8/src/ast/scopes.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/ast/scopes.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
tory, &new_unresolved_list,
                            maybe_in_arrowhead);

    // Migrate function_ to the right Zone.
    if (function_ != nullptr) {
      function_ = ast_node_factory->CopyVariable(function_);
    }

    SavePreparseData(parser);
  }

#ifdef DEBUG
  if (v8_flags.print_scopes) {
    PrintF("Inner function scope:\n");
    Print();
  }
#endif

  ResetAfterPreparsing(ast_node_factory->ast_value_factory(), false);

  unresolved_list_ = std::move(new_unresolved_list);
}

void DeclarationScope::RewriteReplGlobalVariables() {
  DCHECK(is_script_scope());
  if (!is_repl_mode_scope()) return;

  for (VariableMap::Entry* p = variables_.Start(); p != nullptr;
       p = variables_.Next(p)) {
    Variable* var = reinterpret_cast<Variable*>(p->value);
    var->RewriteLocationForRepl();
  }
}

#ifdef DEBUG
namespace {

const char* Header(ScopeType scope_type, FunctionKind function_kind,
                   bool is_declaration_scope) {
  switch (scope_type) {
    case EVAL_SCOPE: return "eval";
    case FUNCTION_SCOPE:
      if (IsGeneratorFunction(function_kind)) return "function*";
      if (IsAsyncFunction(function_kind)) return "async function";
      if (IsArrowFunction(function_kind)) return "arrow";
      return "function";
    case MODULE_SCOPE: return "module";
    case REPL_MODE_SCOPE:
      return "repl";
    case SCRIPT_SCOPE: return "global";
    case CATCH_SCOPE: return "catch";
    case BLOCK_SCOPE: return is_declaration_scope ? "varblock" : "block";
    case CLASS_SCOPE:
      return "class";
    case WITH_SCOPE: return "with";
    case SHADOW_REALM_SCOPE:
      return "shadowrealm";
  }
  UNREACHABLE();
}

void Indent(int n, const char* str) { PrintF("%*s%s", n, "", str); }

void PrintName(const AstRawString* name) {
  PrintF("%.*s", name->length(), name->raw_data());
}

void PrintLocation(Variable* var) {
  switch (var->location()) {
    case VariableLocation::UNALLOCATED:
      break;
    case VariableLocation::PARAMETER:
      PrintF("parameter[%d]", var->index());
      break;
    case VariableLocation::LOCAL:
      PrintF("local[%d]", var->index());
      break;
    case VariableLocation::CONTEXT:
      PrintF("context[%d]", var->index());
      break;
    case VariableLocation::LOOKUP:
      PrintF("lookup");
      break;
    case VariableLocation::MODULE:
      PrintF("module");
      break;
    case VariableLocation::REPL_GLOBAL:
      PrintF("repl global[%d]", var->index());
      break;
  }
}

void PrintVar(int indent, Variable* var) {
  Indent(indent, VariableMode2String(var->mode()));
  PrintF(" ");
  if (var->raw_name()->IsEmpty())
    PrintF(".%p", reinterpret_cast<void*>(var));
  else
    PrintName(var->raw_name());
  PrintF(";  // (%p) ", reinterpret_cast<void*>(var));
  PrintLocation(var);
  bool comma = !var->IsUnallocated();
  if (var->has_forced_context_allocation()) {
    if (comma) PrintF(", ");
    PrintF("forced context allocation");
    comma = true;
  }
  if (var->maybe_assigned() == kNotAssigned) {
    if (comma) PrintF(", ");
    PrintF("never assigned");
    comma = true;
  }
  if (var->initialization_flag() == kNeedsInitialization &&
      !var->binding_needs_init()) {
    if (comma) PrintF(", ");
    PrintF("hole initialization elided");
  }
  PrintF("\n");
}

void PrintMap(int indent, const char* label, VariableMap* map, bool locals,
              Variable* function_var) {
  bool printed_label = false;
  for (VariableMap::Entry* p = map->Start(); p != nullptr; p = map->Next(p)) {
    Variable* var = reinterpret_cast<Variable*>(p->value);
    if (var == function_var) continue;
    bool local = !IsDynamicVariableMode(var->mode());
    if ((locals ? local : !local) &&
        (var->is_used() || !var->IsUnallocated())) {
      if (!printed_label) {
        Indent(indent, label);
        printed_label = true;
      }
      PrintVar(indent, var);
    }
  }
}

}  // anonymous namespace

void DeclarationScope::PrintParameters() {
  PrintF(" (");
  for (int i = 0; i < params_.length(); i++) {
    if (i > 0) PrintF(", ");
    const AstRawString* name = params_[i]->raw_name();
    if (name->IsEmpty()) {
      PrintF(".%p", reinterpret_cast<void*>(params_[i]));
    } else {
      PrintName(name);
    }
  }
  PrintF(")");
}

void Scope::Print(int n) {
  int n0 = (n > 0 ? n : 0);
  int n1 = n0 + 2;  // indentation

  // Print header.
  FunctionKind function_kind = is_function_scope()
                                   ? AsDeclarationScope()->function_kind()
                                   : FunctionKind::kNormalFunction;
  Indent(n0, Header(scope_type_, function_kind, is_declaration_scope()));
  if (scope_name_ != nullptr && !scope_name_->IsEmpty()) {
    PrintF(" ");
    PrintName(scope_name_);
  }

  // Print parameters, if any.
  Variable* function = nullptr;
  if (is_function_scope()) {
    AsDeclarationScope()->PrintParameters();
    function = AsDeclarationScope()->function_var();
  }

  PrintF(" { // (%p) (%d, %d)\n", reinterpret_cast<void*>(this),
         start_position(), end_position());
  if (is_hidden()) {
    Indent(n1, "// is hidden\n");
  }

  // Function name, if any (named function literals, only).
  if (function != nullptr) {
    Indent(n1, "// (local) function name: ");
    PrintName(function->raw_name());
    PrintF("\n");
  }

  // Scope info.
  if (is_strict(language_mode())) {
    Indent(n1, "// strict mode scope\n");
  }
#if V8_ENABLE_WEBASSEMBLY
  if (IsAsmModule()) Indent(n1, "// scope is an asm module\n");
#endif  // V8_ENABLE_WEBASSEMBLY
  if (is_declaration_scope() &&
      AsDeclarationScope()->sloppy_eval_can_extend_vars()) {
    Indent(n1, "// scope calls sloppy 'eval'\n");
  }
  if (private_name_lookup_skips_outer_class()) {
    Indent(n1, "// scope skips outer class for #-names\n");
  }
  if (inner_scope_calls_eval_) Indent(n1, "// inner scope calls 'eval'\n");
  if (is_declaration_scope()) {
    DeclarationScope* scope = AsDeclarationScope();
    if (scope->was_lazily_parsed()) Indent(n1, "// lazily parsed\n");
    if (scope->ShouldEagerCompile()) Indent(n1, "// will be compiled\n");
    if (scope->needs_private_name_context_chain_recalc()) {
      Indent(n1, "// needs #-name context chain recalc\n");
    }
    Indent(n1, "// ");
    PrintF("%s\n", FunctionKind2String(scope->function_kind()));
    if (scope->class_scope_has_private_brand()) {
      Indent(n1, "// class scope has private brand\n");
    }
  }
  if (num_stack_slots_ > 0) {
    Indent(n1, "// ");
    PrintF("%d stack slots\n", num_stack_slots_);
  }
  if (num_heap_slots_ > 0) {
    Indent(n1, "// ");
    PrintF("%d heap slots\n", num_heap_slots_);
  }

  // Print locals.
  if (function != nullptr) {
    Indent(n1, "// function var:\n");
    PrintVar(n1, function);
  }

  // Print temporaries.
  {
    bool printed_header = false;
    for (Variable* local : locals_) {
      if (local->mode() != VariableMode::kTemporary) continue;
      if (!printed_header) {
        printed_header = true;
        Indent(n1, "// temporary vars:\n");
      }
      PrintVar(n1, local);
    }
  }

  if (variables_.occupancy() > 0) {
    PrintMap(n1, "// local vars:\n", &variables_, true, function);
    PrintMap(n1, "// dynamic vars:\n", &variables_, false, function);
  }

  if (is_class_scope()) {
    ClassScope* class_scope = AsClassScope();
    if (class_scope->GetRareData() != nullptr) {
      PrintMap(n1, "// private name vars:\n",
               &(class_scope->GetRareData()->private_name_map), true, function);
      Variable* brand = class_scope->brand();
      if (brand != nullptr) {
        Indent(n1, "// brand var:\n");
        PrintVar(n1, brand);
      }
    }
    if (class_scope->class_variable() != nullptr) {
      Indent(n1, "// class var");
      PrintF("%s%s:\n",
             class_scope->class_variable()->is_used() ? ", used" : ", unused",
             class_scope->should_save_class_variable_index()
                 ? ", index saved"
                 : ", index not saved");
      PrintVar(n1, class_scope->class_variable());
    }
  }

  // Print inner scopes (disable by providing negative n).
  if (n >= 0) {
    for (Scope* scope = inner_scope_; scope != nullptr;
         scope = scope->sibling_) {
      PrintF("\n");
      scope->Print(n1);
    }
  }

  Indent(n0, "}\n");
}

void Scope::CheckScopePositions() {
  this->ForEach([](Scope* scope) {
    // Visible leaf scopes must have real positions.
    if (!scope->is_hidden() && scope->inner_scope_ == nullptr) {
      DCHECK_NE(kNoSourcePosition, scope->start_position());
      DCHECK_NE(kNoSourcePosition, scope->end_position());
    }
    return Iteration::kDescend;
  });
}

void Scope::CheckZones() {
  DCHECK(!needs_migration_);
  this->ForEach([](Scope* scope) {
    if (WasLazilyParsed(scope)) {
      DCHECK_NULL(scope->zone());
      DCHECK_NULL(scope->inner_scope_);
      return Iteration::kContinue;
    }
    return Iteration::kDescend;
  });
}
#endif  // DEBUG

Variable* Scope::NonLocal(const AstRawString* name, VariableMode mode) {
  // Declare a new non-local.
  DCHECK(IsDynamicVariableMode(mode));
  bool was_added;
  Variable* var = variables_.Declare(zone(), this, name, mode, NORMAL_VARIABLE,
                                     kCreatedInitialized, kNotAssigned,
                                     IsStaticFlag::kNotStatic, &was_added);
  // Allocate it by giving it a dynamic lookup.
  var->AllocateTo(VariableLocation::LOOKUP, -1);
  return var;
}

void Scope::ForceDynamicLookup(VariableProxy* proxy) {
  // At the moment this is only used for looking up private names dynamically
  // in debug-evaluate from top-level scope.
  DCHECK(proxy->IsPrivateName());
  DCHECK(is_script_scope() || is_module_scope() || is_eval_scope());
  Variable* dynamic = NonLocal(proxy->raw_name(), VariableMode::kDynamic);
  proxy->BindTo(dynamic);
}

// static
template <Scope::ScopeLookupMode mode>
Variable* Scope::Lookup(VariableProxy* proxy, Scope* scope,
                        Scope* outer_scope_end, Scope* cache_scope,
                        bool force_context_allocation) {
  // If we have already passed the cache scope in earlier recursions, we should
  // first quickly check if the current scope uses the cache scope before
  // continuing.
  if (mode == kDeserializedScope) {
    Variable* var = cache_scope->variables_.Lookup(proxy->raw_name());
    if (var != nullptr) return var;
  }

  while (true) {
    DCHECK_IMPLIES(mode == kParsedScope, !scope->is_debug_evaluate_scope_);
    // Short-cut: whenever we find a debug-evaluate scope, just look everything
    // up dynamically. Debug-evaluate doesn't properly create scope info for the
    // lookups it does. It may not have a valid 'this' declaration, and anything
    // accessed through debug-evaluate might invalidly resolve to
    // stack-allocated variables.
    // TODO(yangguo): Remove once debug-evaluate creates proper ScopeInfo for
    // the scopes in which it's evaluating.
    if (mode == kDeserializedScope &&
        V8_UNLIKELY(scope->is_debug_evaluate_scope_)) {
      return cache_scope->NonLocal(proxy->raw_name(), VariableMode::kDynamic);
    }

    // Try to find the variable in this scope.
    Variable* var;
    if (mode == kParsedScope) {
      var = scope->LookupLocal(proxy->raw_name());
    } else {
      DCHECK_EQ(mode, kDeserializedScope);
      var = scope->LookupInScopeInfo(proxy->raw_name(), cache_scope);
    }

    // We found a variable and we are done. (Even if there is an 'eval' in this
    // scope which introduces the same variable again, the resulting variable
    // remains the same.)
    //
    // For sloppy eval though, we skip dynamic variable to avoid resolving to a
    // variable when the variable and proxy are in the same eval execution. The
    // variable is not available on subsequent lazy executions of functions in
    // the eval, so this avoids inner functions from looking up different
    // variables during eager and lazy compilation.
    //
    // TODO(leszeks): Maybe we want to restrict this to e.g. lookups of a proxy
    // living in a different scope to the current one, or some other
    // optimisation.
    if (var != nullptr &&
        !(scope->is_eval_scope() && var->mode() == VariableMode::kDynamic)) {
      if (mode == kParsedScope && force_context_allocation &&
          !var->is_dynamic()) {
        var->ForceContextAllocation();
      }
      return var;
    }

    if (scope->outer_scope_ == outer_scope_end) break;

    DCHECK(!scope->is_script_scope());
    if (V8_UNLIKELY(scope->is_with_scope())) {
      return LookupWith(proxy, scope, outer_scope_end, cache_scope,
                        force_context_allocation);
    }
    if (V8_UNLIKELY(
            scope->is_declaration_scope() &&
            scope->AsDeclarationScope()->sloppy_eval_can_extend_vars())) {
      return LookupSloppyEval(proxy, scope, outer_scope_end, cache_scope,
                              force_context_allocation);
    }

    force_context_allocation |= scope->is_function_scope();
    scope = scope->outer_scope_;

    // TODO(verwaest): Separate through AnalyzePartially.
    if (mode == kParsedScope && !scope->scope_info_.is_null()) {
      DCHECK_NULL(cache_scope);
      return Lookup<kDeserializedScope>(proxy, scope, outer_scope_end, scope);
    }
  }

  // We may just be trying to find all free variables. In that case, don't
  // declare them in the outer scope.
  // TODO(marja): Separate Lookup for preparsed scopes better.
  if (mode == kParsedScope && !scope->is_script_scope()) {
    return nullptr;
  }

  // No binding has been found. Declare a variable on the global object.
  return scope->AsDeclarationScope()->DeclareDynamicGlobal(
      proxy->raw_name(), NORMAL_VARIABLE,
      mode == kDeserializedScope ? cache_scope : scope);
}

template Variable* Scope::Lookup<Scope::kParsedScope>(
    VariableProxy* proxy, Scope* scope, Scope* outer_scope_end,
    Scope* cache_scope, bool force_context_allocation);
template Variable* Scope::Lookup<Scope::kDeserializedScope>(
    VariableProxy* proxy, Scope* scope, Scope* outer_scope_end,
    Scope* cache_scope, bool force_context_allocation);

Variable* Scope::LookupWith(VariableProxy* proxy, Scope* scope,
                            Scope* outer_scope_end, Scope* cache_scope,
                            bool force_context_allocation) {
  DCHECK(scope->is_with_scope());

  Variable* var =
      scope->outer_scope_->scope_info_.is_null()
          ? Lookup<kParsedScope>(proxy, scope->outer_scope_, outer_scope_end,
                                 nullptr, force_context_allocation)
          : Lookup<kDeserializedScope>(proxy, scope->outer_scope_,
                                       outer_scope_end, cache_scope);

  if (var == nullptr) return var;

  // The current scope is a with scope, so the variable binding can not be
  // statically resolved. However, note that it was necessary to do a lookup
  // in the outer scope anyway, because if a binding exists in an outer
  // scope, the associated variable has to be marked as potentially being
  // accessed from inside of an inner with scope (the property may not be in
  // the 'with' object).
  if (!var->is_dynamic() && var->IsUnallocated()) {
    DCHECK(!scope->already_resolved_);
    var->set_is_used();
    var->ForceContextAllocation();
    if (proxy->is_assigned()) var->SetMaybeAssigned();
  }
  if (cache_scope) cache_scope->variables_.Remove(var);
  Scope* target = cache_scope == nullptr ? scope : cache_scope;
  Variable* dynamic =
      target->NonLocal(proxy->raw_name(), VariableMode::kDynamic);
  dynamic->set_local_if_not_shadowed(var);
  return dynamic;
}

Variable* Scope::LookupSloppyEval(VariableProxy* proxy, Scope* scope,
                                  Scope* outer_scope_end, Scope* cache_scope,
                                  bool force_context_allocation) {
  DCHECK(scope->is_declaration_scope() &&
         scope->AsDeclarationScope()->sloppy_eval_can_extend_vars());

  // If we're compiling eval, it's possible that the outer scope is the first
  // ScopeInfo-backed scope. We use the next declaration scope as the cache for
  // this case, to avoid complexity around sloppy block function hoisting and
  // conflict detection through catch scopes in the eval.
  Scope* entry_cache =
      cache_scope == nullptr ? scope->outer_scope() : cache_scope;
  Variable* var =
      scope->outer_scope_->scope_info_.is_null()
          ? Lookup<kParsedScope>(proxy, scope->outer_scope_, outer_scope_end,
                                 nullptr, force_context_allocation)
          : Lookup<kDeserializedScope>(proxy, scope->outer_scope_,
                                       outer_scope_end, entry_cache);
  if (var == nullptr) return var;

  // A variable binding may have been found in an outer scope, but the current
  // scope makes a sloppy 'eval' call, so the found variable may not be the
  // correct one (the 'eval' may introduce a binding with the same name). In
  // that case, change the lookup result to reflect this situation. Only
  // scopes that can host var bindings (declaration scopes) need be considered
  // here (this excludes block and catch scopes), and variable lookups at
  // script scope are always dynamic.
  if (var->IsGlobalObjectProperty()) {
    Scope* target = cache_scope == nullptr ? scope : cache_scope;
    var = target->NonLocal(proxy->raw_name(), VariableMode::kDynamicGlobal);
  }

  if (var->is_dynamic()) return var;

  Variable* invalidated = var;
  if (cache_scope != nullptr) cache_scope->variables_.Remove(invalidated);

  Scope* target = cache_scope == nullptr ? scope : cache_scope;
  var = target->NonLocal(proxy->raw_name(), VariableMode::kDynamicLocal);
  var->set_local_if_not_shadowed(invalidated);

  return var;
}

void Scope::ResolveVariable(VariableProxy* proxy) {
  DCHECK(!proxy->is_resolved());
  Variable* var;
  if (V8_UNLIKELY(proxy->is_home_object())) {
    // VariableProxies of the home object cannot be resolved like a normal
    // variable. Consider the case of a super.property usage in heritage
    // position:
    //
    //   class C extends super.foo { m() { super.bar(); } }
    //
    // The super.foo property access is logically nested under C's class scope,
    // which also has a home object due to its own method m's usage of
    // super.bar(). However, super.foo must resolve super in C's outer scope.
    //
    // Because of the above, start resolving home objects directly at the home
    // object scope instead of the current scope.
    Scope* scope = GetHomeObjectScope();
    DCHECK_NOT_NULL(scope);
    if (scope->scope_info_.is_null()) {
      var = Lookup<kParsedScope>(proxy, scope, nullptr);
    } else {
      var = Lookup<kDeserializedScope>(proxy, scope, nullptr, scope);
    }
  } else {
    var = Lookup<kParsedScope>(proxy, this, nullptr);
  }
  DCHECK_NOT_NULL(var);
  ResolveTo(proxy, var);
}

namespace {

void SetNeedsHoleCheck(Variable* var, VariableProxy* proxy,
                       Variable::ForceHoleInitializationFlag flag) {
  proxy->set_needs_hole_check();
  var->ForceHoleInitialization(flag);
}

void UpdateNeedsHoleCheck(Variable* var, VariableProxy* proxy, Scope* scope) {
  if (var->mode() == VariableMode::kDynamicLocal) {
    // Dynamically introduced variables never need a hole check (since they're
    // VariableMode::kVar bindings, either from var or function declarations),
    // but the variable they shadow might need a hole check, which we want to do
    // if we decide that no shadowing variable was dynamically introduced.
    DCHECK_EQ(kCreatedInitialized, var->initialization_flag());
    return UpdateNeedsHoleCheck(var->local_if_not_shadowed(), proxy, scope);
  }

  if (var->initialization_flag() == kCreatedInitialized) return;

  // It's impossible to eliminate module import hole checks here, because it's
  // unknown at compilation time whether the binding referred to in the
  // exporting module itself requires hole checks.
  if (var->location() == VariableLocation::MODULE && !var->IsExport()) {
    SetNeedsHoleCheck(var, proxy, Variable::kHasHoleCheckUseInUnknownScope);
    return;
  }

  // Check if the binding really needs an initialization check. The check
  // can be skipped in the following situation: we have a VariableMode::kLet or
  // VariableMode::kConst binding, both the Variable and the VariableProxy have
  // the same declaration scope (i.e. they are both in global code, in the same
  // function or in the same eval code), the VariableProxy is in the source
  // physically located after the initializer of the variable, and that the
  // initializer cannot be skipped due to a nonlinear scope.
  //
  // The condition on the closure scopes is a conservative check for
  // nested functions that access a binding and are called before the
  // binding is initialized:
  //   function() { f(); let x = 1; function f() { x = 2; } }
  //
  // The check cannot be skipped on non-linear scopes, namely switch
  // scopes, to ensure tests are done in cases like the following:
  //   switch (1) { case 0: let x = 2; case 1: f(x); }
  // The scope of the variable needs to be checked, in case the use is
  // in a sub-block which may be linear.
  if (var->scope()->GetClosureScope() != scope->GetClosureScope()) {
    SetNeedsHoleCheck(var, proxy,
                      Variable::kHasHoleCheckUseInDifferentClosureScope);
    return;
  }

  // We should always have valid source positions.
  DCHECK_NE(var->initializer_position(), kNoSourcePosition);
  DCHECK_NE(proxy->position(), kNoSourcePosition);

  if (var->scope()->is_nonlinear() ||
      var->initializer_position() >= proxy->position()) {
    SetNeedsHoleCheck(var, proxy, Variable::kHasHoleCheckUseInSameClosureScope);
    return;
  }
}

}  // anonymous namespace

void Scope::ResolveTo(VariableProxy* proxy, Variable* var) {
  DCHECK_NOT_NULL(var);
  UpdateNeedsHoleCheck(var, proxy, this);
  proxy->BindTo(var);
}

void Scope::ResolvePreparsedVariable(VariableProxy* proxy, Scope* scope,
                                     Scope* end) {
  // Resolve the variable in all parsed scopes to force context allocation.
  for (; scope != end; scope = scope->outer_scope_) {
    Variable* var = scope->LookupLocal(proxy->raw_name());
    if (var != nullptr) {
      var->set_is_used();
      if (!var->is_dynamic()) {
        var->ForceContextAllocation();
        if (proxy->is_assigned()) var->SetMaybeAssigned();
        return;
      }
    }
  }
}

bool Scope::ResolveVariablesRecursively(Scope* end) {
  // Lazy parsed declaration scopes are already partially analyzed. If there are
  // unresolved references remaining, they just need to be resolved in outer
  // scopes.
  if (WasLazilyParsed(this)) {
    DCHECK_EQ(variables_.occupancy(), 0);
    // Resolve in all parsed scopes except for the script scope.
    if (!end->is_script_scope()) end = end->outer_scope();

    for (VariableProxy* proxy : unresolved_list_) {
      ResolvePreparsedVariable(proxy, outer_scope(), end);
    }
  } else {
    // Resolve unresolved variables for this scope.
    for (VariableProxy* proxy : unresolved_list_) {
      ResolveVariable(proxy);
    }

    // Resolve unresolved variables for inner scopes.
    for (Scope* scope = inner_scope_; scope != nullptr;
         scope = scope->sibling_) {
      if (!scope->ResolveVariablesRecursively(end)) return false;
    }
  }
  return true;
}

bool Scope::MustAllocate(Variable* var) {
  DCHECK(var->location() != VariableLocation::MODULE);
  // Give var a read/write use if there is a chance it might be accessed
  // via an eval() call.  This is only possible if the variable has a
  // visible name.
  if (!var->raw_name()->IsEmpty() &&
      (inner_scope_calls_eval_ || is_catch_scope() || is_script_scope())) {
    var->set_is_used();
    if (inner_scope_calls_eval_ && !var->is_this()) var->SetMaybeAssigned();
  }
  CHECK(!var->has_forced_context_allocation() || var->is_used());
  // Global variables do not need to be allocated.
  return !var->IsGlobalObjectProperty() && var->is_used();
}


bool Scope::MustAllocateInContext(Variable* var) {
  // If var is accessed from an inner scope, or if there is a possibility
  // that it might be accessed from the current or an inner scope (through
  // an eval() call or a runtime with lookup), it must be allocated in the
  // context.
  //
  // Temporary variables are always stack-allocated.  Catch-bound variables are
  // always context-allocated.
  VariableMode mode = var->mode();
  if (mode == VariableMode::kTemporary) return false;
  if (is_catch_scope()) return true;
  if (is_script_scope() || is_eval_scope()) {
    if (IsLexicalVariableMode(mode)) {
      return true;
    }
  }
  return var->has_forced_context_allocation() || inner_scope_calls_eval_;
}

void Scope::AllocateStackSlot(Variable* var) {
  if (is_block_scope()) {
    outer_scope()->GetDeclarationScope()->AllocateStackSlot(var);
  } else {
    var->AllocateTo(VariableLocation::LOCAL, num_stack_slots_++);
  }
}


void Scope::AllocateHeapSlot(Variable* var) {
  var->AllocateTo(VariableLocation::CONTEXT, num_heap_slots_++);
}

void DeclarationScope::AllocateParameterLocals() {
  DCHECK(is_function_scope());

  bool has_mapped_arguments = false;
  if (arguments_ != nullptr) {
    DCHECK(!is_arrow_scope());
    if (MustAllocate(arguments_) && !has_arguments_parameter_) {
      // 'arguments' is used and does not refer to a function
      // parameter of the same name. If the arguments object
      // aliases formal parameters, we conservatively allocate
      // them specially in the loop below.
      has_mapped_arguments =
          GetArgumentsType() == CreateArgumentsType::kMappedArguments;
    } else {
      // 'arguments' is unused. Tell the code generator that it does not need to
      // allocate the arguments object by nulling out arguments_.
      arguments_ = nullptr;
    }
  }

  // The same parameter may occur multiple times in the parameters_ list.
  // If it does, and if it is not copied into the context object, it must
  // receive the highest parameter index for that parameter; thus iteration
  // order is relevant!
  for (int i = num_parameters() - 1; i >= 0; --i) {
    Variable* var = params_[i];
    DCHECK_NOT_NULL(var);
    DCHECK(!has_rest_ || var != rest_parameter());
    DCHECK_EQ(this, var->scope());
    if (has_mapped_arguments) {
      var->set_is_used();
      var->SetMaybeAssigned();
      var->ForceContextAllocation();
    }
    AllocateParameter(var, i);
  }
}

void DeclarationScope::AllocateParameter(Variable* var, int index) {
  if (!MustAllocate(var)) return;
  if (has_forced_context_allocation_for_parameters() ||
      MustAllocateInContext(var)) {
    DCHECK(var->IsUnallocated() || var->IsContextSlot());
    if (var->IsUnallocated()) AllocateHeapSlot(var);
  } else {
    DCHECK(var->IsUnallocated() || var->IsParameter());
    if (var->IsUnallocated()) {
      var->AllocateTo(VariableLocation::PARAMETER, index);
    }
  }
}

void DeclarationScope::AllocateReceiver() {
  if (!has_this_declaration()) return;
  DCHECK_NOT_NULL(receiver());
  DCHECK_EQ(receiver()->scope(), this);
  AllocateParameter(receiver(), -1);
}

void Scope::AllocateNonParameterLocal(Variable* var) {
  DCHECK_EQ(var->scope(), this);
  if (var->IsUnallocated() && MustAllocate(var)) {
    if (MustAllocateInContext(var)) {
      AllocateHeapSlot(var);
      DCHECK_IMPLIES(is_catch_scope(),
                     var->index() == Context::THROWN_OBJECT_INDEX);
    } else {
      AllocateStackSlot(var);
    }
  }
}

void Scope::AllocateNonParameterLocalsAndDeclaredGlobals() {
  if (is_declaration_scope() && AsDeclarationScope()->is_arrow_scope()) {
    // In arrow functions, allocate non-temporaries first and then all the
    // temporaries to make the local variable ordering stable when reparsing to
    // collect source positions.
    for (Variable* local : locals_) {
      if (local->mode() != VariableMode::kTemporary)
        AllocateNonParameterLocal(local);
    }

    for (Variable* local : locals_) {
      if (local->mode() == VariableMode::kTemporary)
        AllocateNonParameterLocal(local);
    }
  } else {
    for (Variable* local : locals_) {
      AllocateNonParameterLocal(local);
    }
  }

  if (is_declaration_scope()) {
    AsDeclarationScope()->AllocateLocals();
  }
}

void DeclarationScope::AllocateLocals() {
  // For now, function_ must be allocated at the very end.  If it gets
  // allocated in the context, it must be the last slot in the context,
  // because of the current ScopeInfo implementation (see
  // ScopeInfo::ScopeInfo(FunctionScope* scope) constructor).
  if (function_ != nullptr && MustAllocate(function_)) {
    AllocateNonParameterLocal(function_);
  } else {
    function_ = nullptr;
  }

  DCHECK(!has_rest_ || !MustAllocate(rest_parameter()) ||
         !rest_parameter()->IsUnallocated());

  if (new_target_ != nullptr && !MustAllocate(new_target_)) {
    new_target_ = nullptr;
  }

  NullifyRareVariableIf(RareVariable::kThisFunction, [=, this](Variable* var) {
    return !MustAllocate(var);
  });
}

void ModuleScope::AllocateModuleVariables() {
  for (const auto& it : module()->regular_imports()) {
    Variable* var = LookupLocal(it.first);
    var->AllocateTo(VariableLocation::MODULE, it.second->cell_index);
    DCHECK(!var->IsExport());
  }

  for (const auto& it : module()->regular_exports()) {
    Variable* var = LookupLocal(it.first);
    var->AllocateTo(VariableLocation::MODULE, it.second->cell_index);
    DCHECK(var->IsExport());
  }
}

// Needs to be kept in sync with ScopeInfo::UniqueIdInScript and
// SharedFunctionInfo::UniqueIdInScript.
int Scope::UniqueIdInScript() const {
  // Script scopes start "before" the script to avoid clashing with a scope that
  // starts on character 0.
  if (is_script_scope() || scope_type() == EVAL_SCOPE ||
      scope_type() == MODULE_SCOPE) {
    return -2;
  }
  // Wrapped functions start before the function body, but after the script
  // start, to avoid clashing with a scope starting on character 0.
  if (is_wrapped_function()) {
    return -1;
  }
  if (is_declaration_scope()) {
    // Default constructors have the same start position as their parent class
    // scope. Use the next char position to distinguish this scope.
    return start_position() +
           IsDefaultConstructor(AsDeclarationScope()->function_kind());
  }
  return start_position();
}

void Scope::AllocateVariablesRecursively() {
  this->ForEach([](Scope* scope) -> Iteration {
    DCHECK(!scope->already_resolved_);
    if (WasLazilyParsed(scope)) return Iteration::kContinue;
    if (scope->sloppy_eval_can_extend_vars_) {
      scope->num_heap_slots_ = Context::MIN_CONTEXT_EXTENDED_SLOTS;
    }
    DCHECK_EQ(scope->ContextHeaderLength(), scope->num_heap_slots_);

    // Allocate variables for this scope.
    // Parameters must be allocated first, if any.
    if (scope->is_declaration_scope()) {
      scope->AsDeclarationScope()->AllocateReceiver();
      if (scope->is_function_scope()) {
        scope->AsDeclarationScope()->AllocateParameterLocals();
      }
    }
    scope->AllocateNonParameterLocalsAndDeclaredGlobals();

    // Force allocation of a context for this scope if necessary. For a 'with'
    // scope and for a function scope that makes an 'eval' call we need a
    // context, even if no local variables were statically allocated in the
    // scope. Likewise for modules and function scopes representing asm.js
    // modules. Also force a context, if the scope is stricter than the outer
    // scope.
    bool must_have_context =
        scope->is_with_scope() || scope->is_module_scope() ||
#if V8_ENABLE_WEBASSEMBLY
        scope->IsAsmModule() ||
#endif  // V8_ENABLE_WEBASSEMBLY
        scope->ForceContextForLanguageMode() ||
        (scope->is_function_scope() &&
         scope->AsDeclarationScope()->sloppy_eval_can_extend_vars()) ||
        (scope->is_block_scope() && scope->is_declaration_scope() &&
         scope->AsDeclarationScope()->sloppy_eval_can_extend_vars());

    // If we didn't allocate any locals in the local context, then we only
    // need the minimal number of slots if we must have a context.
    if (scope->num_heap_slots_ == scope->ContextHeaderLength() &&
        !must_have_context) {
      scope->num_heap_slots_ = 0;
    }

    // Allocation done.
    DCHECK(scope->num_heap_slots_ == 0 ||
           scope->num_heap_slots_ >= scope->ContextHeaderLength());
    return Iteration::kDescend;
  });
}

template <typename IsolateT>
void Scope::AllocateScopeInfosRecursively(
    IsolateT* isolate, MaybeHandle<ScopeInfo> outer_scope,
    std::unordered_map<int, Handle<ScopeInfo>>& scope_infos_to_reuse) {
  DCHECK(scope_info_.is_null());
  MaybeHandle<ScopeInfo> next_outer_scope
```