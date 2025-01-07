Response: The user wants to understand the functionality of the C++ code in `v8/src/ast/scopes.cc`.
This is the second part of the file, so I should focus on the functionalities present in this segment.

Key functionalities that seem to be present in this part of the code:

1. **Scope Printing and Debugging:** Functions like `Print`, `PrintParameters`, `PrintVar`, and the anonymous namespace with helper printing functions are used for debugging and visualizing the scope structure.
2. **Variable Lookup:** The `Lookup` template function implements the logic for finding variable declarations within the scope hierarchy, considering different scope types like `with` and `eval`.
3. **Variable Resolution:** The `ResolveVariable`, `ResolveTo`, and `ResolvePreparsedVariable` functions are responsible for connecting `VariableProxy` nodes in the AST to their corresponding `Variable` declarations in the scopes. This includes handling hole checks for uninitialized variables.
4. **Recursive Scope Operations:** Functions like `ResolveVariablesRecursively`, `AllocateVariablesRecursively`, and `AllocateScopeInfosRecursively` demonstrate the traversal and manipulation of the scope tree.
5. **Variable Allocation:**  Functions like `AllocateStackSlot`, `AllocateHeapSlot`, `AllocateParameterLocals`, and `AllocateNonParameterLocalsAndDeclaredGlobals` manage the allocation of memory for variables, deciding whether they reside on the stack or in the context (heap).
6. **Scope Info Management:**  The code interacts with `ScopeInfo` objects, which store information about the scope that's used during compilation and runtime.
7. **Class Scope and Private Names:**  Specific functionality related to `ClassScope`, including declaring, looking up, and resolving private names, is present.
8. **Module Scope:** The `AllocateModuleVariables` function handles the allocation of variables for module imports and exports.

Now, let's consider the relationship with JavaScript and provide examples:

*   **Scope Printing:**  This is primarily a debugging feature in V8 and doesn't have a direct equivalent in JavaScript. However, developers can use the browser's debugger to inspect the scope chain.
*   **Variable Lookup:** This directly relates to how JavaScript resolves variable names.
*   **Variable Resolution and Allocation:** These concepts are fundamental to JavaScript's execution model. The engine needs to determine where to store variables and how to access them.
*   **Scope Info:**  While not directly accessible in JavaScript, the information in `ScopeInfo` influences performance and memory usage.
*   **Class Scope and Private Names:** This directly corresponds to JavaScript's class syntax and private class members.
*   **Module Scope:**  This relates to JavaScript's module system (`import` and `export`).
这个C++源代码文件（`v8/src/ast/scopes.cc`的第2部分）主要负责实现V8引擎中**作用域（Scope）**的各种操作和管理功能。它与JavaScript的功能密切相关，因为作用域是理解JavaScript代码执行上下文的关键。

以下是这个文件主要功能的归纳：

1. **作用域的打印和调试信息输出:** 提供了 `Print()` 函数及其相关的辅助函数 (`Header`, `Indent`, `PrintName`, `PrintLocation`, `PrintVar`, `PrintMap`)，用于在调试模式下打印作用域的结构、变量信息等，帮助开发者理解作用域的层次关系和变量的存储位置。

2. **变量的查找 (Lookup):**  实现了 `Lookup` 模板函数，用于在当前作用域及其父作用域中查找特定名称的变量。这个查找过程会考虑不同的作用域类型 (如 `with` 作用域, `eval` 作用域) 以及预解析和反序列化的情况。

3. **变量的解析 (Resolve):** 提供了 `ResolveVariable`, `ResolveTo`, `ResolvePreparsedVariable` 等函数，将抽象语法树中的 `VariableProxy` 节点（代表变量的使用）绑定到其在作用域中声明的 `Variable` 对象。这个过程包括处理未初始化变量的检查 (`UpdateNeedsHoleCheck`)。

4. **作用域的递归操作:** 实现了 `ResolveVariablesRecursively`, `AllocateVariablesRecursively`, `AllocateScopeInfosRecursively` 等函数，用于递归地处理作用域树中的变量解析、内存分配和 `ScopeInfo` 的创建。

5. **变量的内存分配:**  定义了 `AllocateStackSlot`, `AllocateHeapSlot`, `AllocateParameterLocals`, `AllocateNonParameterLocalsAndDeclaredGlobals` 等函数，用于决定变量是分配在栈上还是堆上（上下文）。这取决于变量的使用方式、作用域类型等因素。

6. **ScopeInfo 的管理:**  涉及 `ScopeInfo` 对象的创建和关联，`ScopeInfo` 存储了作用域的元数据，用于编译和运行时。`AllocateScopeInfosRecursively` 负责为作用域层级结构创建 `ScopeInfo` 对象。

7. **类作用域和私有名称的支持:**  提供了 `ClassScope` 相关的函数，如 `DeclarePrivateName`, `LookupLocalPrivateName`, `LookupPrivateName`, `ResolvePrivateNames`, `ResolvePrivateNamesPartially` 等，用于管理类中的私有成员变量和方法。

8. **模块作用域的支持:** 提供了 `ModuleScope` 相关的函数，如 `AllocateModuleVariables`，用于处理模块的导入和导出变量。

**它与JavaScript的功能的关系和JavaScript示例:**

作用域是JavaScript中一个核心概念，它决定了变量的可访问性。`scopes.cc` 中的代码直接影响着V8引擎如何理解和执行JavaScript的作用域规则。

**1. 变量查找 (Lookup):**

```javascript
function outer() {
  var x = 10;
  function inner() {
    console.log(x); // 内部函数可以访问外部函数的变量 x
  }
  inner();
}
outer(); // 输出 10
```

在V8引擎执行 `console.log(x)` 时，会使用类似于 `Lookup` 的机制，首先在 `inner` 函数的作用域中查找 `x`，如果没有找到，则会向上级作用域（`outer` 函数的作用域）查找。

**2. 变量解析 (Resolve) 和内存分配:**

```javascript
function example() {
  let a = 5;
  const b = 10;
  var c = 15;
  console.log(a + b + c);
}
example();
```

当V8解析这段代码时，会创建 `example` 函数的作用域。`ResolveVariable` 会将 `console.log` 中使用的 `a`, `b`, `c` 绑定到它们在 `example` 作用域中声明的变量。 `AllocateStackSlot` 和 `AllocateHeapSlot` 会根据变量的声明方式 (`let`, `const`, `var`) 和作用域类型，决定将 `a` 和 `b` (块级作用域) 可能分配在栈上或上下文中，而 `c` (函数级作用域) 通常会分配在上下文中。

**3. `with` 作用域:**

```javascript
var obj = { name: "Alice", age: 30 };
function greet() {
  with (obj) {
    console.log("Hello, " + name + "! You are " + age + " years old.");
  }
}
greet(); // 输出 "Hello, Alice! You are 30 years old."
```

`with` 语句创建的作用域在 `scopes.cc` 中有特殊的处理 (`LookupWith`)。V8需要动态地在 `obj` 的属性中查找 `name` 和 `age`。

**4. `eval` 作用域:**

```javascript
function dynamicCode(code) {
  var localVar = 100;
  eval(code); // eval 中的代码可以访问 dynamicCode 的作用域
  console.log(localVar);
}
dynamicCode("localVar = 200;"); // 输出 200
```

`eval` 创建的作用域 (`EVAL_SCOPE`) 也需要在变量查找时进行特殊处理 (`LookupSloppyEval`)，因为它会动态地改变当前作用域的变量。

**5. 类和私有名称:**

```javascript
class MyClass {
  #privateField = 42;
  constructor(value) {
    this.#privateField = value;
  }
  getPrivateField() {
    return this.#privateField;
  }
}

const instance = new MyClass(100);
console.log(instance.getPrivateField()); // 输出 100
// console.log(instance.#privateField); // 报错，无法从外部访问私有字段
```

`ClassScope` 相关的代码负责处理 `#privateField` 这样的私有字段，确保它们只能在类内部访问。`DeclarePrivateName`, `LookupPrivateName` 等函数实现了这些限制。

**6. 模块:**

```javascript
// module.js
export const message = "Hello from module!";

// main.js
import { message } from './module.js';
console.log(message); // 输出 "Hello from module!"
```

`ModuleScope` 和 `AllocateModuleVariables` 负责处理模块的导入和导出，确保 `main.js` 可以正确访问 `module.js` 中导出的 `message` 变量.

总而言之，`v8/src/ast/scopes.cc` 的这个部分是V8引擎实现JavaScript作用域规则的核心代码，它直接影响着JavaScript代码的语义和执行方式。理解这部分代码有助于深入理解JavaScript的执行机制。

Prompt: 
```
这是目录为v8/src/ast/scopes.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
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
  MaybeHandle<ScopeInfo> next_outer_scope = outer_scope;

  auto it = scope_infos_to_reuse.find(UniqueIdInScript());
  if (it != scope_infos_to_reuse.end()) {
    scope_info_ = it->second;
    DCHECK(!scope_info_.is_null());
    CHECK_EQ(scope_info_->scope_type(), scope_type_);
    CHECK_EQ(scope_info_->HasContext(), NeedsContext());
    CHECK_EQ(scope_info_->ContextLength(), num_heap_slots_);
#ifdef DEBUG
    // Consume the scope info.
    it->second = {};
#endif
  } else if (NeedsScopeInfo()) {
    scope_info_ = ScopeInfo::Create(isolate, zone(), this, outer_scope);
#ifdef DEBUG
    // Mark this ID as being used.
    if (v8_flags.reuse_scope_infos) {
      scope_infos_to_reuse[UniqueIdInScript()] = {};
      DCHECK_EQ(UniqueIdInScript(), scope_info_->UniqueIdInScript());
    }
#endif
  }

  // The ScopeInfo chain mirrors the context chain, so we only link to the
  // next outer scope that needs a context.
  if (NeedsContext()) next_outer_scope = scope_info_;

  // Allocate ScopeInfos for inner scopes.
  for (Scope* scope = inner_scope_; scope != nullptr; scope = scope->sibling_) {
#ifdef DEBUG
    DCHECK_GT(scope->UniqueIdInScript(), UniqueIdInScript());
    DCHECK_IMPLIES(scope->sibling_, scope->sibling_->UniqueIdInScript() !=
                                        scope->UniqueIdInScript());
#endif
    if (!scope->is_function_scope() ||
        scope->AsDeclarationScope()->ShouldEagerCompile()) {
      scope->AllocateScopeInfosRecursively(isolate, next_outer_scope,
                                           scope_infos_to_reuse);
    } else if (v8_flags.reuse_scope_infos) {
      auto it = scope_infos_to_reuse.find(scope->UniqueIdInScript());
      if (it != scope_infos_to_reuse.end()) {
        scope->scope_info_ = it->second;
#ifdef DEBUG
        // Consume the scope info
        it->second = {};
#endif
      }
    }
  }
}

template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE) void Scope::
    AllocateScopeInfosRecursively<Isolate>(
        Isolate* isolate, MaybeHandle<ScopeInfo> outer_scope,
        std::unordered_map<int, Handle<ScopeInfo>>& scope_infos_to_reuse);
template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE) void Scope::
    AllocateScopeInfosRecursively<LocalIsolate>(
        LocalIsolate* isolate, MaybeHandle<ScopeInfo> outer_scope,
        std::unordered_map<int, Handle<ScopeInfo>>& scope_infos_to_reuse);

void DeclarationScope::RecalcPrivateNameContextChain() {
  // The outermost scope in a class heritage expression is marked to skip the
  // class scope during private name resolution. It is possible, however, that
  // either the class scope won't require a Context and ScopeInfo, or the
  // outermost scope in the heritage position won't. Simply copying the bit from
  // full parse into the ScopeInfo will break lazy compilation. In the former
  // case the scope that is marked to skip its outer scope will incorrectly skip
  // a different class scope than the one we intended to skip. In the latter
  // case variables resolved through an inner scope will incorrectly check the
  // class scope since we lost the skip bit from the outermost heritage scope.
  //
  // This method fixes both cases by, in outermost to innermost order, copying
  // the value of the skip bit from outer scopes that don't require a Context.
  DCHECK(needs_private_name_context_chain_recalc_);
  this->ForEach([](Scope* scope) {
    Scope* outer = scope->outer_scope();
    if (!outer) return Iteration::kDescend;
    if (!outer->NeedsContext()) {
      scope->private_name_lookup_skips_outer_class_ =
          outer->private_name_lookup_skips_outer_class();
    }
    if (!scope->is_function_scope() ||
        scope->AsDeclarationScope()->ShouldEagerCompile()) {
      return Iteration::kDescend;
    }
    return Iteration::kContinue;
  });
}

void DeclarationScope::RecordNeedsPrivateNameContextChainRecalc() {
  DCHECK_EQ(GetClosureScope(), this);
  DeclarationScope* scope;
  for (scope = this; scope != nullptr;
       scope = scope->outer_scope() != nullptr
                   ? scope->outer_scope()->GetClosureScope()
                   : nullptr) {
    if (scope->needs_private_name_context_chain_recalc_) return;
    scope->needs_private_name_context_chain_recalc_ = true;
  }
}

// static
template <typename IsolateT>
void DeclarationScope::AllocateScopeInfos(ParseInfo* info,
                                          DirectHandle<Script> script,
                                          IsolateT* isolate) {
  DeclarationScope* scope = info->literal()->scope();

  // No one else should have allocated a scope info for this scope yet.
  DCHECK(scope->scope_info_.is_null());

  MaybeHandle<ScopeInfo> outer_scope;
  if (scope->outer_scope_ != nullptr) {
    DCHECK((std::is_same<Isolate, v8::internal::Isolate>::value));
    outer_scope = scope->outer_scope_->scope_info_;
  }

  if (scope->needs_private_name_context_chain_recalc()) {
    scope->RecalcPrivateNameContextChain();
  }

  Tagged<WeakFixedArray> infos = script->infos();
  std::unordered_map<int, Handle<ScopeInfo>> scope_infos_to_reuse;
  if (v8_flags.reuse_scope_infos && infos->length() != 0) {
    Tagged<SharedFunctionInfo> sfi = *info->literal()->shared_function_info();
    Tagged<ScopeInfo> outer = sfi->HasOuterScopeInfo()
                                  ? sfi->GetOuterScopeInfo()
                                  : Tagged<ScopeInfo>();
    // Look at all inner functions whether they have scope infos that we should
    // reuse. Also look at the compiled function itself, and reuse its function
    // scope info if it exists.
    for (int i = info->literal()->function_literal_id();
         i <= info->max_info_id(); ++i) {
      Tagged<MaybeObject> maybe_info = infos->get(i);
      if (maybe_info.IsWeak()) {
        Tagged<Object> info = maybe_info.GetHeapObjectAssumeWeak();
        Tagged<ScopeInfo> scope_info;
        if (Is<SharedFunctionInfo>(info)) {
          Tagged<SharedFunctionInfo> sfi = Cast<SharedFunctionInfo>(info);
          if (!sfi->scope_info()->IsEmpty()) {
            scope_info = sfi->scope_info();
          } else if (sfi->HasOuterScopeInfo()) {
            scope_info = sfi->GetOuterScopeInfo();
          } else {
            continue;
          }
        } else {
          scope_info = Cast<ScopeInfo>(info);
        }
        while (true) {
          if (scope_info == outer) break;
          int id = scope_info->UniqueIdInScript();
          auto it = scope_infos_to_reuse.find(id);
          if (it != scope_infos_to_reuse.end()) {
            if (V8_LIKELY(*it->second == scope_info)) break;
            if constexpr (std::is_same<IsolateT, Isolate>::value) {
              isolate->PushStackTraceAndDie(
                  reinterpret_cast<void*>(it->second->ptr()),
                  reinterpret_cast<void*>(scope_info->ptr()));
            }
            UNREACHABLE();
          }
          scope_infos_to_reuse[id] = handle(scope_info, isolate);
          if (!scope_info->HasOuterScopeInfo()) break;
          scope_info = scope_info->OuterScopeInfo();
        }
      }
    }
  }

  scope->AllocateScopeInfosRecursively(isolate, outer_scope,
                                       scope_infos_to_reuse);

  // The debugger expects all shared function infos to contain a scope info.
  // Since the top-most scope will end up in a shared function info, make sure
  // it has one, even if it doesn't need a scope info.
  // TODO(yangguo): Remove this requirement.
  if (scope->scope_info_.is_null()) {
    scope->scope_info_ =
        ScopeInfo::Create(isolate, scope->zone(), scope, outer_scope);
  }

  // Ensuring that the outer script scope has a scope info avoids having
  // special case for native contexts vs other contexts.
  if (info->script_scope() && info->script_scope()->scope_info_.is_null()) {
    info->script_scope()->scope_info_ = isolate->factory()->empty_scope_info();
  }
}

template V8_EXPORT_PRIVATE void DeclarationScope::AllocateScopeInfos(
    ParseInfo* info, DirectHandle<Script> script, Isolate* isolate);
template V8_EXPORT_PRIVATE void DeclarationScope::AllocateScopeInfos(
    ParseInfo* info, DirectHandle<Script> script, LocalIsolate* isolate);

int Scope::ContextLocalCount() const {
  if (num_heap_slots() == 0) return 0;
  Variable* function =
      is_function_scope() ? AsDeclarationScope()->function_var() : nullptr;
  bool is_function_var_in_context =
      function != nullptr && function->IsContextSlot();
  return num_heap_slots() - ContextHeaderLength() -
         (is_function_var_in_context ? 1 : 0);
}

bool IsComplementaryAccessorPair(VariableMode a, VariableMode b) {
  switch (a) {
    case VariableMode::kPrivateGetterOnly:
      return b == VariableMode::kPrivateSetterOnly;
    case VariableMode::kPrivateSetterOnly:
      return b == VariableMode::kPrivateGetterOnly;
    default:
      return false;
  }
}

Variable* ClassScope::DeclarePrivateName(const AstRawString* name,
                                         VariableMode mode,
                                         IsStaticFlag is_static_flag,
                                         bool* was_added) {
  Variable* result = EnsureRareData()->private_name_map.Declare(
      zone(), this, name, mode, NORMAL_VARIABLE,
      InitializationFlag::kNeedsInitialization, MaybeAssignedFlag::kNotAssigned,
      is_static_flag, was_added);
  if (*was_added) {
    locals_.Add(result);
    has_static_private_methods_ |=
        (result->is_static() &&
         IsPrivateMethodOrAccessorVariableMode(result->mode()));
  } else if (IsComplementaryAccessorPair(result->mode(), mode) &&
             result->is_static_flag() == is_static_flag) {
    *was_added = true;
    result->set_mode(VariableMode::kPrivateGetterAndSetter);
  }
  result->ForceContextAllocation();
  return result;
}

Variable* ClassScope::LookupLocalPrivateName(const AstRawString* name) {
  RareData* rare_data = GetRareData();
  if (rare_data == nullptr) {
    return nullptr;
  }
  return rare_data->private_name_map.Lookup(name);
}

UnresolvedList::Iterator ClassScope::GetUnresolvedPrivateNameTail() {
  RareData* rare_data = GetRareData();
  if (rare_data == nullptr) {
    return UnresolvedList::Iterator();
  }
  return rare_data->unresolved_private_names.end();
}

void ClassScope::ResetUnresolvedPrivateNameTail(UnresolvedList::Iterator tail) {
  RareData* rare_data = GetRareData();
  if (rare_data == nullptr ||
      rare_data->unresolved_private_names.end() == tail) {
    return;
  }

  bool tail_is_empty = tail == UnresolvedList::Iterator();
  if (tail_is_empty) {
    // If the saved tail is empty, the list used to be empty, so clear it.
    rare_data->unresolved_private_names.Clear();
  } else {
    rare_data->unresolved_private_names.Rewind(tail);
  }
}

void ClassScope::MigrateUnresolvedPrivateNameTail(
    AstNodeFactory* ast_node_factory, UnresolvedList::Iterator tail) {
  RareData* rare_data = GetRareData();
  if (rare_data == nullptr ||
      rare_data->unresolved_private_names.end() == tail) {
    return;
  }
  UnresolvedList migrated_names;

  // If the saved tail is empty, the list used to be empty, so we should
  // migrate everything after the head.
  bool tail_is_empty = tail == UnresolvedList::Iterator();
  UnresolvedList::Iterator it =
      tail_is_empty ? rare_data->unresolved_private_names.begin() : tail;

  for (; it != rare_data->unresolved_private_names.end(); ++it) {
    VariableProxy* proxy = *it;
    VariableProxy* copy = ast_node_factory->CopyVariableProxy(proxy);
    migrated_names.Add(copy);
  }

  // Replace with the migrated copies.
  if (tail_is_empty) {
    rare_data->unresolved_private_names.Clear();
  } else {
    rare_data->unresolved_private_names.Rewind(tail);
  }
  rare_data->unresolved_private_names.Append(std::move(migrated_names));
}

Variable* ClassScope::LookupPrivateNameInScopeInfo(const AstRawString* name) {
  DCHECK(!scope_info_.is_null());
  DCHECK_NULL(LookupLocalPrivateName(name));
  DisallowGarbageCollection no_gc;

  VariableLookupResult lookup_result;
  int index = scope_info_->ContextSlotIndex(name->string(), &lookup_result);
  if (index < 0) {
    return nullptr;
  }

  DCHECK(IsImmutableLexicalOrPrivateVariableMode(lookup_result.mode));
  DCHECK_EQ(lookup_result.init_flag, InitializationFlag::kNeedsInitialization);
  DCHECK_EQ(lookup_result.maybe_assigned_flag, MaybeAssignedFlag::kNotAssigned);

  // Add the found private name to the map to speed up subsequent
  // lookups for the same name.
  bool was_added;
  Variable* var = DeclarePrivateName(name, lookup_result.mode,
                                     lookup_result.is_static_flag, &was_added);
  DCHECK(was_added);
  var->AllocateTo(VariableLocation::CONTEXT, index);
  return var;
}

Variable* ClassScope::LookupPrivateName(VariableProxy* proxy) {
  DCHECK(!proxy->is_resolved());

  for (PrivateNameScopeIterator scope_iter(this); !scope_iter.Done();
       scope_iter.Next()) {
    ClassScope* scope = scope_iter.GetScope();
    // Try finding it in the private name map first, if it can't be found,
    // try the deserialized scope info.
    Variable* var = scope->LookupLocalPrivateName(proxy->raw_name());
    if (var == nullptr && !scope->scope_info_.is_null()) {
      var = scope->LookupPrivateNameInScopeInfo(proxy->raw_name());
    }
    if (var != nullptr) {
      return var;
    }
  }
  return nullptr;
}

bool ClassScope::ResolvePrivateNames(ParseInfo* info) {
  RareData* rare_data = GetRareData();
  if (rare_data == nullptr || rare_data->unresolved_private_names.is_empty()) {
    return true;
  }

  UnresolvedList& list = rare_data->unresolved_private_names;
  for (VariableProxy* proxy : list) {
    Variable* var = LookupPrivateName(proxy);
    if (var == nullptr) {
      // It's only possible to fail to resolve private names here if
      // this is at the top level or the private name is accessed through eval.
      DCHECK(info->flags().is_eval() || outer_scope_->is_script_scope());
      Scanner::Location loc = proxy->location();
      info->pending_error_handler()->ReportMessageAt(
          loc.beg_pos, loc.end_pos,
          MessageTemplate::kInvalidPrivateFieldResolution, proxy->raw_name());
      return false;
    } else {
      proxy->BindTo(var);
    }
  }

  // By now all unresolved private names should be resolved so
  // clear the list.
  list.Clear();
  return true;
}

VariableProxy* ClassScope::ResolvePrivateNamesPartially() {
  RareData* rare_data = GetRareData();
  if (rare_data == nullptr || rare_data->unresolved_private_names.is_empty()) {
    return nullptr;
  }

  PrivateNameScopeIterator private_name_scope_iter(this);
  private_name_scope_iter.Next();
  UnresolvedList& unresolved = rare_data->unresolved_private_names;
  bool has_private_names = rare_data->private_name_map.capacity() > 0;

  // If the class itself does not have private names, nor does it have
  // an outer private name scope, then we are certain any private name access
  // inside cannot be resolved.
  if (!has_private_names && private_name_scope_iter.Done() &&
      !unresolved.is_empty()) {
    return unresolved.first();
  }

  for (VariableProxy* proxy = unresolved.first(); proxy != nullptr;) {
    DCHECK(proxy->IsPrivateName());
    VariableProxy* next = proxy->next_unresolved();
    unresolved.Remove(proxy);
    Variable* var = nullptr;

    // If we can find private name in the current class scope, we can bind
    // them immediately because it's going to shadow any outer private names.
    if (has_private_names) {
      var = LookupLocalPrivateName(proxy->raw_name());
      if (var != nullptr) {
        var->set_is_used();
        proxy->BindTo(var);
        // If the variable being accessed is a static private method, we need to
        // save the class variable in the context to check that the receiver is
        // the class during runtime.
        has_explicit_static_private_methods_access_ |=
            (var->is_static() &&
             IsPrivateMethodOrAccessorVariableMode(var->mode()));
      }
    }

    // If the current scope does not have declared private names,
    // try looking from the outer class scope later.
    if (var == nullptr) {
      // There's no outer private name scope so we are certain that the variable
      // cannot be resolved later.
      if (private_name_scope_iter.Done()) {
        return proxy;
      }

      // The private name may be found later in the outer private name scope, so
      // push it to the outer scope.
      private_name_scope_iter.AddUnresolvedPrivateName(proxy);
    }

    proxy = next;
  }

  DCHECK(unresolved.is_empty());
  return nullptr;
}

Variable* ClassScope::DeclareBrandVariable(AstValueFactory* ast_value_factory,
                                           IsStaticFlag is_static_flag,
                                           int class_token_pos) {
  DCHECK_IMPLIES(GetRareData() != nullptr, GetRareData()->brand == nullptr);
  bool was_added;
  Variable* brand = Declare(zone(), ast_value_factory->dot_brand_string(),
                            VariableMode::kConst, NORMAL_VARIABLE,
                            InitializationFlag::kNeedsInitialization,
                            MaybeAssignedFlag::kNotAssigned, &was_added);
  DCHECK(was_added);
  brand->set_is_static_flag(is_static_flag);
  brand->ForceContextAllocation();
  brand->set_is_used();
  EnsureRareData()->brand = brand;
  brand->set_initializer_position(class_token_pos);
  return brand;
}

Variable* ClassScope::DeclareClassVariable(AstValueFactory* ast_value_factory,
                                           const AstRawString* name,
                                           int class_token_pos) {
  DCHECK_NULL(class_variable_);
  DCHECK_NOT_NULL(name);
  bool was_added;
  class_variable_ =
      Declare(zone(), name->IsEmpty() ? ast_value_factory->dot_string() : name,
              VariableMode::kConst, NORMAL_VARIABLE,
              InitializationFlag::kNeedsInitialization,
              MaybeAssignedFlag::kMaybeAssigned, &was_added);
  DCHECK(was_added);
  class_variable_->set_initializer_position(class_token_pos);
  return class_variable_;
}

PrivateNameScopeIterator::PrivateNameScopeIterator(Scope* start)
    : start_scope_(start), current_scope_(start) {
  if (!start->is_class_scope() || start->AsClassScope()->IsParsingHeritage()) {
    Next();
  }
}

void PrivateNameScopeIterator::Next() {
  DCHECK(!Done());
  Scope* inner = current_scope_;
  Scope* scope = inner->outer_scope();
  while (scope != nullptr) {
    if (scope->is_class_scope()) {
      if (!inner->private_name_lookup_skips_outer_class()) {
        current_scope_ = scope;
        return;
      }
      skipped_any_scopes_ = true;
    }
    inner = scope;
    scope = scope->outer_scope();
  }
  current_scope_ = nullptr;
}

void PrivateNameScopeIterator::AddUnresolvedPrivateName(VariableProxy* proxy) {
  // During a reparse, current_scope_->already_resolved_ may be true here,
  // because the class scope is deserialized while the function scope inside may
  // be new.
  DCHECK(!proxy->is_resolved());
  DCHECK(proxy->IsPrivateName());

  // Use dynamic lookup for top-level scopes in debug-evaluate.
  if (Done()) {
    start_scope_->ForceDynamicLookup(proxy);
    return;
  }

  GetScope()->EnsureRareData()->unresolved_private_names.Add(proxy);
  // Any closure scope that contain uses of private names that skips over a
  // class scope due to heritage expressions need private name context chain
  // recalculation, since not all scopes require a Context or ScopeInfo. See
  // comment in DeclarationScope::RecalcPrivateNameContextChain.
  if (V8_UNLIKELY(skipped_any_scopes_)) {
    start_scope_->GetClosureScope()->RecordNeedsPrivateNameContextChainRecalc();
  }
}

}  // namespace internal
}  // namespace v8

"""


```