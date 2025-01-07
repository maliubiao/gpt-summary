Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/ast/scopes.cc`. I need to identify the main actions and data structures involved in this code. The prompt also contains specific instructions based on file extensions and relationships to JavaScript, which are not directly applicable here since the provided text is already identified as a C++ source code. However, I will keep the possibility of JavaScript relationship in mind while summarizing.

Key elements I observe in the code:

- **Scope manipulation**: The code deals with operations like reparenting scopes, managing inner and outer scopes, and moving unresolved variables between scopes.
- **Variable management**:  It involves adding local variables, looking up variables, declaring parameters, locals, and dynamic globals. There are also mechanisms for handling unresolved variables and temporaries.
- **Declaration handling**:  The code manages declarations within scopes and checks for conflicting declarations.
- **Scope properties**: It tracks properties like whether a scope calls `eval`, needs a context, has arguments, or is being lazily parsed.
- **Preparsing and lazy parsing**: There are mentions of preparsing and handling scopes that were lazily parsed.

I will structure the summary around these core functionalities.
这是 `v8/src/ast/scopes.cc` 源代码的一部分，主要负责以下功能：

**1. 作用域的调整和连接 (Scope Reparenting and Linking):**

*   **`Scope::Snapshot::Reparent(DeclarationScope* new_parent)`**: 这个函数用于将一系列内部作用域（从 `new_parent->sibling_` 到 `top_inner_scope_`）重新连接到 `new_parent` 作用域下。这涉及到更新内部作用域的 `outer_scope_` 指针，并处理 `eval` 调用标志的传播。
*   它还会将原来父作用域中未解析的变量和临时变量转移到新的父作用域。

**2. 变量的声明和管理 (Variable Declaration and Management):**

*   **`DeclarationScope::AddLocal(Variable* var)`**: 将一个局部变量添加到当前声明作用域。
*   **`Scope::LookupInScopeInfo(const AstRawString* name, Scope* cache)`**: 在 `ScopeInfo` 中查找变量，并将其声明到指定的缓存作用域中。这通常用于处理来自序列化或外部信息的变量。
*   **`DeclarationScope::DeclareParameter(...)`**: 声明函数或模块的参数。它会设置参数的各种属性，例如是否为剩余参数 (`rest`)。
*   **`DeclarationScope::RecordParameter(bool is_rest)`**: 用于延迟解析的情况下记录参数信息。
*   **`Scope::DeclareLocal(...)`**: 在当前作用域中声明局部变量，可以指定变量的模式（`var`, `let`, `const` 等）和种类。
*   **`Scope::DeclareVariable(...)`**: 声明变量，并处理在不同作用域下的提升 (`hoisting`) 行为，以及检测变量的重复声明冲突。
*   **`Scope::DeclareVariableName(...)`**:  在预解析阶段声明变量名。
*   **`Scope::DeclareCatchVariableName(const AstRawString* name)`**: 声明 `catch` 语句中的绑定变量。
*   **`Scope::AddUnresolved(VariableProxy* proxy)`**: 将一个未解析的变量引用添加到当前作用域的未解析列表。
*   **`DeclarationScope::DeclareDynamicGlobal(...)`**: 声明动态全局变量（通常在脚本作用域中）。
*   **`Scope::DeleteUnresolved(VariableProxy* var)`**: 从未解析列表中删除一个变量引用。
*   **`Scope::NewTemporary(...)`**: 创建一个新的临时变量。

**3. 处理未解析的变量 (Handling Unresolved Variables):**

*   当在当前作用域中找不到变量声明时，会将其添加到一个未解析的列表中。这些未解析的变量会在后续的解析过程中尝试在外层作用域中找到声明。

**4. 变量声明冲突检测 (Conflicting Variable Declaration Check):**

*   **`DeclarationScope::CheckConflictingVarDeclarations(...)`**: 检查同一作用域内或嵌套作用域中是否存在变量的重复声明冲突，特别是 `let`/`const` 和 `var` 之间的冲突。

**5. 处理接收者 (Receiver Handling):**

*   **`DeclarationScope::DeserializeReceiver(AstValueFactory* ast_value_factory)`**: 反序列化接收者（`this`），并将其分配到上下文槽中。
*   **`Scope::HasReceiverToDeserialize() const`**: 检查是否需要反序列化接收者。
*   **`Scope::HasThisReference() const`**: 检查作用域或其内部作用域中是否存在 `this` 的引用。

**6. 预解析和延迟解析 (Preparsing and Lazy Parsing):**

*   代码中涉及到对作用域进行预解析和延迟解析的概念。
*   **`Scope::AllowsLazyParsingWithoutUnresolvedVariables(const Scope* outer) const`**: 判断是否允许在没有未解析变量的情况下进行延迟解析。
*   **`DeclarationScope::AllowsLazyCompilation() const`**: 判断当前声明作用域是否允许延迟编译。
*   **`DeclarationScope::ResetAfterPreparsing(...)`**: 在预解析后重置声明作用域的状态。
*   **`Scope::IsSkippableFunctionScope()`**: 判断一个函数作用域是否可以被跳过（用于延迟解析）。
*   **`Scope::SavePreparseData(Parser* parser)`**: 保存预解析的数据。
*   **`DeclarationScope::SavePreparseDataForDeclarationScope(Parser* parser)`**:  为声明作用域保存预解析数据。
*   **`DeclarationScope::AnalyzePartially(...)`**:  对作用域进行部分分析，用于处理延迟解析的情况。

**7. 上下文链长度计算 (Context Chain Length Calculation):**

*   **`Scope::ContextChainLength(Scope* scope) const`**: 计算当前作用域到指定作用域之间的上下文链的长度。
*   **`Scope::ContextChainLengthUntilOutermostSloppyEval() const`**: 计算直到最外层松散模式 `eval` 作用域的上下文链长度。

**8. 辅助函数 (Helper Functions):**

*   提供了一些用于获取特定类型作用域的辅助函数，例如 `GetDeclarationScope()`, `GetClosureScope()`, `GetScriptScope()`, `GetReceiverScope()`, `GetConstructorScope()`, `GetHomeObjectScope()`, `GetOuterScopeWithContext()`.
*   提供了一个用于遍历作用域树的 `ForEach` 模板函数。

**9. 其他功能:**

*   **`Scope::AllocateVariables(ParseInfo* info)`**: 分配作用域中的变量。
*   **`Scope::NeedsScopeInfo() const`**: 判断是否需要作用域信息。
*   **`Scope::ShouldBanArguments()`**: 判断是否禁止使用 `arguments` 对象。
*   **`Scope::IsConstructorScope() const`**: 判断是否为构造函数作用域。
*   **`Scope::IsOuterScopeOf(Scope* other) const`**: 判断当前作用域是否是另一个作用域的外层作用域。

**归纳一下它的功能：**

这段代码的核心功能是 **管理和操作 JavaScript 代码中的作用域链和变量声明**。它负责构建、连接和调整作用域结构，跟踪作用域内的变量（包括参数、局部变量、临时变量和未解析的变量），并处理变量的声明、查找和冲突检测。  此外，它还支持预解析和延迟解析等优化机制，以及与 `eval` 和 `this` 相关的特殊处理。  `Reparent` 函数是其中一个关键操作，用于在特定场景下重构作用域树，例如在处理某些复杂的语法结构或优化时。

由于代码片段没有 `.tq` 结尾，所以它不是 Torque 代码。

这段代码与 JavaScript 的作用域和变量声明机制密切相关。 例如，在 JavaScript 中使用 `var`, `let`, `const` 声明变量会直接影响到这里代码的执行逻辑。

**JavaScript 示例:**

```javascript
function outer() {
  var a = 10; // 对应 Scope::DeclareLocal 等
  function inner() {
    console.log(a); // 查找变量 'a'，可能涉及 LookupInScopeInfo
  }
  return inner;
}

let myInner = outer();
myInner(); // 调用时会查找 `outer` 作用域中的变量 `a`

function example(x, y = 5) { // 声明参数，对应 DeclareParameter
  console.log(x, y);
}

function withEval(str) {
  var localVar = 20;
  eval(str); // eval 的处理会影响作用域链，可能涉及 sloppy_eval_can_extend_vars_
}
```

**代码逻辑推理示例 (假设输入与输出):**

**假设输入:**

1. 一个已经创建的 `outer_scope`。
2. 一个 `inner_scope`，它的 `outer_scope_` 指向其他作用域。
3. 调用 `Reparent` 函数，将 `inner_scope` 及其兄弟作用域重新连接到 `outer_scope` 下。

**预期输出:**

1. `inner_scope` 的 `outer_scope_` 指针被更新为指向 `outer_scope`。
2. `inner_scope` 的兄弟作用域的 `outer_scope_` 指针也被更新为指向 `outer_scope`。
3. 原来父作用域中未解析的变量列表被添加到 `outer_scope` 的未解析列表的前面。

**用户常见的编程错误示例:**

*   **重复声明变量导致冲突:**

    ```javascript
    function example() {
      let x = 1;
      var x = 2; // 报错：Identifier 'x' has already been declared
    }
    ```

    这段代码在 V8 中解析时，`Scope::DeclareVariable` 或 `DeclarationScope::CheckConflictingVarDeclarations` 等函数会检测到 `x` 的重复声明，并抛出错误。

*   **在块级作用域中使用 `var` 导致意外的变量提升:**

    ```javascript
    function example() {
      if (true) {
        var y = 3;
      }
      console.log(y); // 输出 3，因为 var 声明被提升到函数作用域
    }
    ```

    V8 在解析时，会将 `var y` 的声明提升到 `example` 函数作用域的顶部，即使它在 `if` 语句块内声明。

*   **在 `eval` 中使用 `var` 导致作用域污染 (在 sloppy 模式下):**

    ```javascript
    function outer() {
      var a = 1;
      var evalStr = 'var a = 2;';
      eval(evalStr);
      console.log(a); // 在 sloppy 模式下输出 2，在 strict 模式下行为不同
    }
    outer();
    ```

    在 sloppy 模式下，`eval` 中声明的 `var` 变量会污染外层作用域，这涉及到代码中对 `eval` 作用域的处理。

希望这个归纳对您有所帮助！

Prompt: 
```
这是目录为v8/src/ast/scopes.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/ast/scopes.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共4部分，请归纳一下它的功能

"""
le (scope->sibling_ != nullptr) {
      scope = scope->sibling_;
      scope->outer_scope_ = outer_scope();
    }
    scope->sibling_ = outer_scope()->inner_scope_;
    outer_scope()->inner_scope_ = inner_scope_;
    inner_scope_ = nullptr;
  }

  // Move unresolved variables
  if (!unresolved_list_.is_empty()) {
    outer_scope()->unresolved_list_.Prepend(std::move(unresolved_list_));
    unresolved_list_.Clear();
  }

  if (inner_scope_calls_eval_) outer_scope()->inner_scope_calls_eval_ = true;

  // No need to propagate sloppy_eval_can_extend_vars_, since if it was relevant
  // to this scope we would have had to bail out at the top.
  DCHECK(!is_declaration_scope() ||
         !AsDeclarationScope()->sloppy_eval_can_extend_vars());

  // This block does not need a context.
  num_heap_slots_ = 0;

  // Mark scope as removed by making it its own sibling.
#ifdef DEBUG
  sibling_ = this;
#endif

  return nullptr;
}

void DeclarationScope::AddLocal(Variable* var) {
  DCHECK(!already_resolved_);
  // Temporaries are only placed in ClosureScopes.
  DCHECK_EQ(GetClosureScope(), this);
  locals_.Add(var);
}

void Scope::Snapshot::Reparent(DeclarationScope* new_parent) {
  DCHECK_EQ(new_parent, outer_scope_->inner_scope_);
  DCHECK_EQ(new_parent->outer_scope_, outer_scope_);
  DCHECK_EQ(new_parent, new_parent->GetClosureScope());
  DCHECK_NULL(new_parent->inner_scope_);
  DCHECK(new_parent->unresolved_list_.is_empty());
  Scope* inner_scope = new_parent->sibling_;
  if (inner_scope != top_inner_scope_) {
    for (; inner_scope->sibling() != top_inner_scope_;
         inner_scope = inner_scope->sibling()) {
      inner_scope->outer_scope_ = new_parent;
      if (inner_scope->inner_scope_calls_eval_) {
        new_parent->inner_scope_calls_eval_ = true;
      }
      DCHECK_NE(inner_scope, new_parent);
    }
    inner_scope->outer_scope_ = new_parent;
    if (inner_scope->inner_scope_calls_eval_) {
      new_parent->inner_scope_calls_eval_ = true;
    }
    new_parent->inner_scope_ = new_parent->sibling_;
    inner_scope->sibling_ = nullptr;
    // Reset the sibling rather than the inner_scope_ since we
    // want to keep new_parent there.
    new_parent->sibling_ = top_inner_scope_;
  }

  new_parent->unresolved_list_.MoveTail(&outer_scope_->unresolved_list_,
                                        top_unresolved_);

  // Move temporaries allocated for complex parameter initializers.
  DeclarationScope* outer_closure = outer_scope_->GetClosureScope();
  for (auto it = top_local_; it != outer_closure->locals()->end(); ++it) {
    Variable* local = *it;
    DCHECK_EQ(VariableMode::kTemporary, local->mode());
    DCHECK_EQ(local->scope(), local->scope()->GetClosureScope());
    DCHECK_NE(local->scope(), new_parent);
    local->set_scope(new_parent);
  }
  new_parent->locals_.MoveTail(outer_closure->locals(), top_local_);
  outer_closure->locals_.Rewind(top_local_);

  // Move eval calls since Snapshot's creation into new_parent.
  if (outer_scope_->calls_eval_) {
    new_parent->RecordEvalCall();
    outer_scope_->calls_eval_ = false;
    declaration_scope_->sloppy_eval_can_extend_vars_ = false;
  }
}

Variable* Scope::LookupInScopeInfo(const AstRawString* name, Scope* cache) {
  DCHECK(!scope_info_.is_null());
  DCHECK(this->IsOuterScopeOf(cache));
  DCHECK_NULL(cache->variables_.Lookup(name));
  DisallowGarbageCollection no_gc;

  Tagged<String> name_handle = *name->string();
  Tagged<ScopeInfo> scope_info = *scope_info_;
  // The Scope is backed up by ScopeInfo. This means it cannot operate in a
  // heap-independent mode, and all strings must be internalized immediately. So
  // it's ok to get the Handle<String> here.
  bool found = false;

  VariableLocation location;
  int index;
  VariableLookupResult lookup_result;

  {
    location = VariableLocation::CONTEXT;
    index = scope_info->ContextSlotIndex(name->string(), &lookup_result);
    found = index >= 0;
  }

  if (!found && is_module_scope()) {
    location = VariableLocation::MODULE;
    index = scope_info->ModuleIndex(name_handle, &lookup_result.mode,
                                    &lookup_result.init_flag,
                                    &lookup_result.maybe_assigned_flag);
    found = index != 0;
  }

  if (!found) {
    index = scope_info->FunctionContextSlotIndex(name_handle);
    if (index < 0) return nullptr;  // Nowhere found.
    Variable* var = AsDeclarationScope()->DeclareFunctionVar(name, cache);
    DCHECK_EQ(VariableMode::kConst, var->mode());
    var->AllocateTo(VariableLocation::CONTEXT, index);
    return cache->variables_.Lookup(name);
  }

  if (!is_module_scope()) {
    DCHECK_NE(index, scope_info->ReceiverContextSlotIndex());
  }

  bool was_added;
  Variable* var = cache->variables_.Declare(
      zone(), this, name, lookup_result.mode, NORMAL_VARIABLE,
      lookup_result.init_flag, lookup_result.maybe_assigned_flag,
      IsStaticFlag::kNotStatic, &was_added);
  DCHECK(was_added);
  var->AllocateTo(location, index);
  return var;
}

Variable* DeclarationScope::DeclareParameter(const AstRawString* name,
                                             VariableMode mode,
                                             bool is_optional, bool is_rest,
                                             AstValueFactory* ast_value_factory,
                                             int position) {
  DCHECK(!already_resolved_);
  DCHECK(is_function_scope() || is_module_scope());
  DCHECK(!has_rest_);
  DCHECK(!is_optional || !is_rest);
  DCHECK(!is_being_lazily_parsed_);
  DCHECK(!was_lazily_parsed_);
  Variable* var;
  if (mode == VariableMode::kTemporary) {
    var = NewTemporary(name);
  } else {
    var = LookupLocal(name);
    DCHECK_EQ(mode, VariableMode::kVar);
    DCHECK(var->is_parameter());
  }
  has_rest_ = is_rest;
  var->set_initializer_position(position);
  params_.Add(var, zone());
  if (!is_rest) ++num_parameters_;
  if (name == ast_value_factory->arguments_string()) {
    has_arguments_parameter_ = true;
  }
  // Params are automatically marked as used to make sure that the debugger and
  // function.arguments sees them.
  // TODO(verwaest): Reevaluate whether we always need to do this, since
  // strict-mode function.arguments does not make the arguments available.
  var->set_is_used();
  return var;
}

void DeclarationScope::RecordParameter(bool is_rest) {
  DCHECK(!already_resolved_);
  DCHECK(is_function_scope() || is_module_scope());
  DCHECK(is_being_lazily_parsed_);
  DCHECK(!has_rest_);
  has_rest_ = is_rest;
  if (!is_rest) ++num_parameters_;
}

Variable* Scope::DeclareLocal(const AstRawString* name, VariableMode mode,
                              VariableKind kind, bool* was_added,
                              InitializationFlag init_flag) {
  DCHECK(!already_resolved_);
  // Private methods should be declared with ClassScope::DeclarePrivateName()
  DCHECK(!IsPrivateMethodOrAccessorVariableMode(mode));
  // This function handles VariableMode::kVar, VariableMode::kLet,
  // VariableMode::kConst, VariableMode::kUsing, and VariableMode::kAwaitUsing
  // modes. VariableMode::kDynamic variables are introduced during variable
  // allocation, and VariableMode::kTemporary variables are allocated via
  // NewTemporary().
  DCHECK(IsDeclaredVariableMode(mode));
  DCHECK_IMPLIES(GetDeclarationScope()->is_being_lazily_parsed(),
                 mode == VariableMode::kVar || mode == VariableMode::kLet ||
                     mode == VariableMode::kConst ||
                     mode == VariableMode::kUsing ||
                     mode == VariableMode::kAwaitUsing);
  DCHECK(!GetDeclarationScope()->was_lazily_parsed());
  Variable* var =
      Declare(zone(), name, mode, kind, init_flag, kNotAssigned, was_added);

  // Pessimistically assume that top-level variables will be assigned and used.
  //
  // Top-level variables in a script can be accessed by other scripts or even
  // become global properties. While this does not apply to top-level variables
  // in a module (assuming they are not exported), we must still mark these as
  // assigned because they might be accessed by a lazily parsed top-level
  // function, which, for efficiency, we preparse without variable tracking.
  if (is_script_scope() || is_module_scope()) {
    if (mode != VariableMode::kConst) var->SetMaybeAssigned();
    var->set_is_used();
  }

  return var;
}

Variable* Scope::DeclareVariable(
    Declaration* declaration, const AstRawString* name, int pos,
    VariableMode mode, VariableKind kind, InitializationFlag init,
    bool* was_added, bool* sloppy_mode_block_scope_function_redefinition,
    bool* ok) {
  // Private methods should be declared with ClassScope::DeclarePrivateName()
  DCHECK(!IsPrivateMethodOrAccessorVariableMode(mode));
  DCHECK(IsDeclaredVariableMode(mode));
  DCHECK(!already_resolved_);
  DCHECK(!GetDeclarationScope()->is_being_lazily_parsed());
  DCHECK(!GetDeclarationScope()->was_lazily_parsed());

  if (mode == VariableMode::kVar && !is_declaration_scope()) {
    return GetDeclarationScope()->DeclareVariable(
        declaration, name, pos, mode, kind, init, was_added,
        sloppy_mode_block_scope_function_redefinition, ok);
  }
  DCHECK(!is_catch_scope());
  DCHECK(!is_with_scope());
  DCHECK(is_declaration_scope() ||
         (IsLexicalVariableMode(mode) && is_block_scope()));

  DCHECK_NOT_NULL(name);

  Variable* var = LookupLocal(name);
  // Declare the variable in the declaration scope.
  *was_added = var == nullptr;
  if (V8_LIKELY(*was_added)) {
    if (V8_UNLIKELY(is_eval_scope() && is_sloppy(language_mode()) &&
                    mode == VariableMode::kVar)) {
      // In a var binding in a sloppy direct eval, pollute the enclosing scope
      // with this new binding by doing the following:
      // The proxy is bound to a lookup variable to force a dynamic declaration
      // using the DeclareEvalVar or DeclareEvalFunction runtime functions.
      DCHECK_EQ(NORMAL_VARIABLE, kind);
      var = NonLocal(name, VariableMode::kDynamic);
      // Mark the var as used in case anyone outside the eval wants to use it.
      var->set_is_used();
    } else {
      // Declare the name.
      var = DeclareLocal(name, mode, kind, was_added, init);
      DCHECK(*was_added);
    }
  } else {
    var->SetMaybeAssigned();
    if (V8_UNLIKELY(IsLexicalVariableMode(mode) ||
                    IsLexicalVariableMode(var->mode()))) {
      // The name was declared in this scope before; check for conflicting
      // re-declarations. We have a conflict if either of the declarations is
      // not a var (in script scope, we also have to ignore legacy const for
      // compatibility). There is similar code in runtime.cc in the Declare
      // functions. The function CheckConflictingVarDeclarations checks for
      // var and let bindings from different scopes whereas this is a check
      // for conflicting declarations within the same scope. This check also
      // covers the special case
      //
      // function () { let x; { var x; } }
      //
      // because the var declaration is hoisted to the function scope where
      // 'x' is already bound.
      //
      // In harmony we treat re-declarations as early errors. See ES5 16 for a
      // definition of early errors.
      //
      // Allow duplicate function decls for web compat, see bug 4693.
      *ok = var->is_sloppy_block_function() &&
            kind == SLOPPY_BLOCK_FUNCTION_VARIABLE;
      *sloppy_mode_block_scope_function_redefinition = *ok;
    }
  }
  DCHECK_NOT_NULL(var);

  // We add a declaration node for every declaration. The compiler
  // will only generate code if necessary. In particular, declarations
  // for inner local variables that do not represent functions won't
  // result in any generated code.
  //
  // This will lead to multiple declaration nodes for the
  // same variable if it is declared several times. This is not a
  // semantic issue, but it may be a performance issue since it may
  // lead to repeated DeclareEvalVar or DeclareEvalFunction calls.
  decls_.Add(declaration);
  declaration->set_var(var);
  return var;
}

Variable* Scope::DeclareVariableName(const AstRawString* name,
                                     VariableMode mode, bool* was_added,
                                     VariableKind kind) {
  DCHECK(IsDeclaredVariableMode(mode));
  DCHECK(!already_resolved_);
  DCHECK(GetDeclarationScope()->is_being_lazily_parsed());
  // Private methods should be declared with ClassScope::DeclarePrivateName()
  DCHECK(!IsPrivateMethodOrAccessorVariableMode(mode));
  if (mode == VariableMode::kVar && !is_declaration_scope()) {
    return GetDeclarationScope()->DeclareVariableName(name, mode, was_added,
                                                      kind);
  }
  DCHECK(!is_with_scope());
  DCHECK(!is_eval_scope());
  DCHECK(is_declaration_scope() || IsLexicalVariableMode(mode));
  DCHECK(scope_info_.is_null());

  // Declare the variable in the declaration scope.
  Variable* var = DeclareLocal(name, mode, kind, was_added);
  if (!*was_added) {
    if (IsLexicalVariableMode(mode) || IsLexicalVariableMode(var->mode())) {
      if (!var->is_sloppy_block_function() ||
          kind != SLOPPY_BLOCK_FUNCTION_VARIABLE) {
        // Duplicate functions are allowed in the sloppy mode, but if this is
        // not a function declaration, it's an error. This is an error PreParser
        // hasn't previously detected.
        return nullptr;
      }
      // Sloppy block function redefinition.
    }
    var->SetMaybeAssigned();
  }
  var->set_is_used();
  return var;
}

Variable* Scope::DeclareCatchVariableName(const AstRawString* name) {
  DCHECK(!already_resolved_);
  DCHECK(is_catch_scope());
  DCHECK(scope_info_.is_null());

  bool was_added;
  Variable* result = Declare(zone(), name, VariableMode::kVar, NORMAL_VARIABLE,
                             kCreatedInitialized, kNotAssigned, &was_added);
  DCHECK(was_added);
  return result;
}

void Scope::AddUnresolved(VariableProxy* proxy) {
  // The scope is only allowed to already be resolved if we're reparsing a class
  // initializer. Class initializers will manually resolve these references
  // separate from regular variable resolution.
  DCHECK_IMPLIES(already_resolved_, reparsing_for_class_initializer_);
  DCHECK(!proxy->is_resolved());
  unresolved_list_.Add(proxy);
}

Variable* DeclarationScope::DeclareDynamicGlobal(const AstRawString* name,
                                                 VariableKind kind,
                                                 Scope* cache) {
  DCHECK(is_script_scope());
  bool was_added;
  return cache->variables_.Declare(
      zone(), this, name, VariableMode::kDynamicGlobal, kind,
      kCreatedInitialized, kNotAssigned, IsStaticFlag::kNotStatic, &was_added);
  // TODO(neis): Mark variable as maybe-assigned?
}

void Scope::DeleteUnresolved(VariableProxy* var) {
  DCHECK(unresolved_list_.Contains(var));
  var->mark_removed_from_unresolved();
}

Variable* Scope::NewTemporary(const AstRawString* name) {
  return NewTemporary(name, kMaybeAssigned);
}

Variable* Scope::NewTemporary(const AstRawString* name,
                              MaybeAssignedFlag maybe_assigned) {
  DeclarationScope* scope = GetClosureScope();
  Variable* var = zone()->New<Variable>(scope, name, VariableMode::kTemporary,
                                        NORMAL_VARIABLE, kCreatedInitialized);
  scope->AddLocal(var);
  if (maybe_assigned == kMaybeAssigned) var->SetMaybeAssigned();
  return var;
}

Declaration* DeclarationScope::CheckConflictingVarDeclarations(
    bool* allowed_catch_binding_var_redeclaration) {
  if (has_checked_syntax_) return nullptr;
  for (Declaration* decl : decls_) {
    // Lexical vs lexical conflicts within the same scope have already been
    // captured in Parser::Declare. The only conflicts we still need to check
    // are lexical vs nested var.
    if (decl->IsVariableDeclaration() &&
        decl->AsVariableDeclaration()->AsNested() != nullptr) {
      Scope* current = decl->AsVariableDeclaration()->AsNested()->scope();
      if (decl->var()->mode() != VariableMode::kVar &&
          decl->var()->mode() != VariableMode::kDynamic)
        continue;
      // Iterate through all scopes until the declaration scope.
      do {
        // There is a conflict if there exists a non-VAR binding.
        Variable* other_var = current->LookupLocal(decl->var()->raw_name());
        if (current->is_catch_scope()) {
          *allowed_catch_binding_var_redeclaration |= other_var != nullptr;
          current = current->outer_scope();
          continue;
        }
        if (other_var != nullptr) {
          DCHECK(IsLexicalVariableMode(other_var->mode()));
          return decl;
        }
        current = current->outer_scope();
      } while (current != this);
    }
  }

  if (V8_LIKELY(!is_eval_scope())) return nullptr;
  if (!is_sloppy(language_mode())) return nullptr;

  // Var declarations in sloppy eval are hoisted to the first non-eval
  // declaration scope. Check for conflicts between the eval scope that
  // declaration scope.
  Scope* end = outer_scope()->GetNonEvalDeclarationScope()->outer_scope();

  for (Declaration* decl : decls_) {
    if (IsLexicalVariableMode(decl->var()->mode())) continue;
    Scope* current = outer_scope_;
    // Iterate through all scopes until and including the declaration scope.
    do {
      // There is a conflict if there exists a non-VAR binding up to the
      // declaration scope in which this sloppy-eval runs.
      //
      // Use the current scope as the cache. We can't use the regular cache
      // since catch scope vars don't result in conflicts, but they will mask
      // variables for regular scope resolution. We have to make sure to not put
      // masked variables in the cache used for regular lookup.
      Variable* other_var =
          current->LookupInScopeOrScopeInfo(decl->var()->raw_name(), current);
      if (other_var != nullptr && !current->is_catch_scope()) {
        // If this is a VAR, then we know that it doesn't conflict with
        // anything, so we can't conflict with anything either. The one
        // exception is the binding variable in catch scopes, which is handled
        // by the if above.
        if (!IsLexicalVariableMode(other_var->mode())) break;
        return decl;
      }
      current = current->outer_scope();
    } while (current != end);
  }
  return nullptr;
}

const AstRawString* Scope::FindVariableDeclaredIn(Scope* scope,
                                                  VariableMode mode_limit) {
  const VariableMap& variables = scope->variables_;
  for (ZoneHashMap::Entry* p = variables.Start(); p != nullptr;
       p = variables.Next(p)) {
    const AstRawString* name = static_cast<const AstRawString*>(p->key);
    Variable* var = LookupLocal(name);
    if (var != nullptr && var->mode() <= mode_limit) return name;
  }
  return nullptr;
}

void DeclarationScope::DeserializeReceiver(AstValueFactory* ast_value_factory) {
  if (is_script_scope()) {
    DCHECK_NOT_NULL(receiver_);
    return;
  }
  DCHECK(has_this_declaration());
  DeclareThis(ast_value_factory);
  if (is_debug_evaluate_scope()) {
    receiver_->AllocateTo(VariableLocation::LOOKUP, -1);
  } else {
    receiver_->AllocateTo(VariableLocation::CONTEXT,
                          scope_info_->ReceiverContextSlotIndex());
  }
}

bool DeclarationScope::AllocateVariables(ParseInfo* info) {
  // Module variables must be allocated before variable resolution
  // to ensure that UpdateNeedsHoleCheck() can detect import variables.
  if (is_module_scope()) AsModuleScope()->AllocateModuleVariables();

  PrivateNameScopeIterator private_name_scope_iter(this);
  if (!private_name_scope_iter.Done() &&
      !private_name_scope_iter.GetScope()->ResolvePrivateNames(info)) {
    DCHECK(info->pending_error_handler()->has_pending_error());
    return false;
  }

  if (!ResolveVariablesRecursively(info->scope())) {
    DCHECK(info->pending_error_handler()->has_pending_error());
    return false;
  }

  // Don't allocate variables of preparsed scopes.
  if (!was_lazily_parsed()) AllocateVariablesRecursively();

  return true;
}

bool Scope::HasReceiverToDeserialize() const {
  return !scope_info_.is_null() && scope_info_->HasAllocatedReceiver();
}

bool Scope::HasThisReference() const {
  if (is_declaration_scope() && AsDeclarationScope()->has_this_reference()) {
    return true;
  }

  for (Scope* scope = inner_scope_; scope != nullptr; scope = scope->sibling_) {
    if (!scope->is_declaration_scope() ||
        !scope->AsDeclarationScope()->has_this_declaration()) {
      if (scope->HasThisReference()) return true;
    }
  }

  return false;
}

bool Scope::AllowsLazyParsingWithoutUnresolvedVariables(
    const Scope* outer) const {
  // If none of the outer scopes need to decide whether to context allocate
  // specific variables, we can preparse inner functions without unresolved
  // variables. Otherwise we need to find unresolved variables to force context
  // allocation of the matching declarations. We can stop at the outer scope for
  // the parse, since context allocation of those variables is already
  // guaranteed to be correct.
  for (const Scope* s = this; s != outer; s = s->outer_scope_) {
    // Eval forces context allocation on all outer scopes, so we don't need to
    // look at those scopes. Sloppy eval makes top-level non-lexical variables
    // dynamic, whereas strict-mode requires context allocation.
    if (s->is_eval_scope()) return is_sloppy(s->language_mode());
    // Catch scopes force context allocation of all variables.
    if (s->is_catch_scope()) continue;
    // With scopes do not introduce variables that need allocation.
    if (s->is_with_scope()) continue;
    DCHECK(s->is_module_scope() || s->is_block_scope() ||
           s->is_function_scope());
    return false;
  }
  return true;
}

bool DeclarationScope::AllowsLazyCompilation() const {
  // Functions which force eager compilation and class member initializer
  // functions are not lazily compilable.
  return !force_eager_compilation_ &&
         !IsClassMembersInitializerFunction(function_kind());
}

int Scope::ContextChainLength(Scope* scope) const {
  int n = 0;
  for (const Scope* s = this; s != scope; s = s->outer_scope_) {
    DCHECK_NOT_NULL(s);  // scope must be in the scope chain
    if (s->NeedsContext()) n++;
  }
  return n;
}

int Scope::ContextChainLengthUntilOutermostSloppyEval() const {
  int result = 0;
  int length = 0;

  for (const Scope* s = this; s != nullptr; s = s->outer_scope()) {
    if (!s->NeedsContext()) continue;
    length++;
    if (s->is_declaration_scope() &&
        s->AsDeclarationScope()->sloppy_eval_can_extend_vars()) {
      result = length;
    }
  }

  return result;
}

DeclarationScope* Scope::GetDeclarationScope() {
  Scope* scope = this;
  while (!scope->is_declaration_scope()) {
    scope = scope->outer_scope();
  }
  return scope->AsDeclarationScope();
}

DeclarationScope* Scope::GetNonEvalDeclarationScope() {
  Scope* scope = this;
  while (!scope->is_declaration_scope() || scope->is_eval_scope()) {
    scope = scope->outer_scope();
  }
  return scope->AsDeclarationScope();
}

const DeclarationScope* Scope::GetClosureScope() const {
  const Scope* scope = this;
  while (!scope->is_declaration_scope() || scope->is_block_scope()) {
    scope = scope->outer_scope();
  }
  return scope->AsDeclarationScope();
}

DeclarationScope* Scope::GetClosureScope() {
  Scope* scope = this;
  while (!scope->is_declaration_scope() || scope->is_block_scope()) {
    scope = scope->outer_scope();
  }
  return scope->AsDeclarationScope();
}

bool Scope::NeedsScopeInfo() const {
  DCHECK(!already_resolved_);
  DCHECK(GetClosureScope()->ShouldEagerCompile());
  // The debugger expects all functions to have scope infos.
  // TODO(yangguo): Remove this requirement.
  if (is_function_scope()) return true;
  return NeedsContext();
}

bool Scope::ShouldBanArguments() {
  return GetReceiverScope()->should_ban_arguments();
}

DeclarationScope* Scope::GetReceiverScope() {
  Scope* scope = this;
  while (!scope->is_declaration_scope() ||
         (!scope->is_script_scope() &&
          !scope->AsDeclarationScope()->has_this_declaration())) {
    scope = scope->outer_scope();
  }
  return scope->AsDeclarationScope();
}

DeclarationScope* Scope::GetConstructorScope() {
  Scope* scope = this;
  while (scope != nullptr && !scope->IsConstructorScope()) {
    scope = scope->outer_scope();
  }
  if (scope == nullptr) {
    return nullptr;
  }
  DCHECK(scope->IsConstructorScope());
  return scope->AsDeclarationScope();
}

Scope* Scope::GetHomeObjectScope() {
  Scope* scope = GetReceiverScope();
  DCHECK(scope->is_function_scope());
  FunctionKind kind = scope->AsDeclarationScope()->function_kind();
  // "super" in arrow functions binds outside the arrow function. Arrow
  // functions are also never receiver scopes since they close over the
  // receiver.
  DCHECK(!IsArrowFunction(kind));
  // If we find a function which doesn't bind "super" (is not a method etc.), we
  // know "super" here doesn't bind anywhere and we can return nullptr.
  if (!BindsSuper(kind)) return nullptr;
  // Functions that bind "super" can only syntactically occur nested inside home
  // object scopes (i.e. class scopes and object literal scopes), so directly
  // return the outer scope.
  Scope* outer_scope = scope->outer_scope();
  CHECK(outer_scope->is_home_object_scope());
  return outer_scope;
}

DeclarationScope* Scope::GetScriptScope() {
  Scope* scope = this;
  while (!scope->is_script_scope()) {
    scope = scope->outer_scope();
  }
  return scope->AsDeclarationScope();
}

Scope* Scope::GetOuterScopeWithContext() {
  Scope* scope = outer_scope_;
  while (scope && !scope->NeedsContext()) {
    scope = scope->outer_scope();
  }
  return scope;
}

namespace {
bool WasLazilyParsed(Scope* scope) {
  return scope->is_declaration_scope() &&
         scope->AsDeclarationScope()->was_lazily_parsed();
}

}  // namespace

template <typename FunctionType>
void Scope::ForEach(FunctionType callback) {
  Scope* scope = this;
  while (true) {
    Iteration iteration = callback(scope);
    // Try to descend into inner scopes first.
    if ((iteration == Iteration::kDescend) && scope->inner_scope_ != nullptr) {
      scope = scope->inner_scope_;
    } else {
      // Find the next outer scope with a sibling.
      while (scope->sibling_ == nullptr) {
        if (scope == this) return;
        scope = scope->outer_scope_;
      }
      if (scope == this) return;
      scope = scope->sibling_;
    }
  }
}

bool Scope::IsConstructorScope() const {
  return is_declaration_scope() &&
         IsClassConstructor(AsDeclarationScope()->function_kind());
}

bool Scope::IsOuterScopeOf(Scope* other) const {
  Scope* scope = other;
  while (scope) {
    if (scope == this) return true;
    scope = scope->outer_scope();
  }
  return false;
}

void Scope::AnalyzePartially(DeclarationScope* max_outer_scope,
                             AstNodeFactory* ast_node_factory,
                             UnresolvedList* new_unresolved_list,
                             bool maybe_in_arrowhead) {
  this->ForEach([max_outer_scope, ast_node_factory, new_unresolved_list,
                 maybe_in_arrowhead](Scope* scope) {
    // Skip already lazily parsed scopes. This can only happen to functions
    // inside arrowheads.
    if (WasLazilyParsed(scope)) {
      DCHECK(max_outer_scope->is_arrow_scope());
      return Iteration::kContinue;
    }

    for (VariableProxy* proxy = scope->unresolved_list_.first();
         proxy != nullptr; proxy = proxy->next_unresolved()) {
      if (proxy->is_removed_from_unresolved()) continue;
      DCHECK(!proxy->is_resolved());
      Variable* var =
          Lookup<kParsedScope>(proxy, scope, max_outer_scope->outer_scope());
      if (var == nullptr) {
        // Don't copy unresolved references to the script scope, unless it's a
        // reference to a private name or method. In that case keep it so we
        // can fail later.
        if (!max_outer_scope->outer_scope()->is_script_scope() ||
            maybe_in_arrowhead) {
          VariableProxy* copy = ast_node_factory->CopyVariableProxy(proxy);
          new_unresolved_list->Add(copy);
        }
      } else {
        var->set_is_used();
        if (proxy->is_assigned()) var->SetMaybeAssigned();
      }
    }

    // Clear unresolved_list_ as it's in an inconsistent state.
    scope->unresolved_list_.Clear();
    return Iteration::kDescend;
  });
}

void DeclarationScope::ResetAfterPreparsing(AstValueFactory* ast_value_factory,
                                            bool aborted) {
  DCHECK(is_function_scope());

  // Reset all non-trivial members.
  params_.DropAndClear();
  num_parameters_ = 0;
  decls_.Clear();
  locals_.Clear();
  inner_scope_ = nullptr;
  unresolved_list_.Clear();
  sloppy_block_functions_.Clear();
  rare_data_ = nullptr;
  has_rest_ = false;
  function_ = nullptr;

  DCHECK_NE(zone(), ast_value_factory->single_parse_zone());
  // Make sure this scope and zone aren't used for allocation anymore.
  {
    // Get the zone, while variables_ is still valid
    Zone* zone = this->zone();
    variables_.Invalidate();
    zone->Reset();
  }

  if (aborted) {
    // Prepare scope for use in the outer zone.
    variables_ = VariableMap(ast_value_factory->single_parse_zone());
    if (!IsArrowFunction(function_kind_)) {
      has_simple_parameters_ = true;
      DeclareDefaultFunctionVariables(ast_value_factory);
    }
  }

#ifdef DEBUG
  needs_migration_ = false;
  is_being_lazily_parsed_ = false;
#endif

  was_lazily_parsed_ = !aborted;
}

bool Scope::IsSkippableFunctionScope() {
  // Lazy non-arrow function scopes are skippable. Lazy functions are exactly
  // those Scopes which have their own PreparseDataBuilder object. This
  // logic ensures that the scope allocation data is consistent with the
  // skippable function data (both agree on where the lazy function boundaries
  // are).
  if (!is_function_scope()) return false;
  DeclarationScope* declaration_scope = AsDeclarationScope();
  return !declaration_scope->is_arrow_scope() &&
         declaration_scope->preparse_data_builder() != nullptr;
}

void Scope::SavePreparseData(Parser* parser) {
  this->ForEach([parser](Scope* scope) {
    // Save preparse data for every skippable scope, unless it was already
    // previously saved (this can happen with functions inside arrowheads).
    if (scope->IsSkippableFunctionScope() &&
        !scope->AsDeclarationScope()->was_lazily_parsed()) {
      scope->AsDeclarationScope()->SavePreparseDataForDeclarationScope(parser);
    }
    return Iteration::kDescend;
  });
}

void DeclarationScope::SavePreparseDataForDeclarationScope(Parser* parser) {
  if (preparse_data_builder_ == nullptr) return;
  preparse_data_builder_->SaveScopeAllocationData(this, parser);
}

void DeclarationScope::AnalyzePartially(Parser* parser,
                                        AstNodeFactory* ast_node_factory,
                                        bool maybe_in_arrowhead) {
  DCHECK(!force_eager_compilation_);
  UnresolvedList new_unresolved_list;

  // We don't need to do partial analysis for top level functions, since they
  // can only access values in the global scope, and we can't track assignments
  // for these since they're accessible across scripts.
  //
  // If the top level function has inner functions though, we do still want to
  // analyze those to save their preparse data.
  //
  // Additionally, functions in potential arrowheads _need_ to be analyzed, in
  // case they do end up being in an arrowhead and the arrow function needs to
  // know about context acceses. For example, in
  //
  //     (a, b=function foo(){ a = 1 }) => { b(); return a}
  //
  // `function foo(){ a = 1 }` is "maybe_in_arrowhead" but still top-level when
  // parsed, and is re-scoped to the arrow function when that one is parsed. The
  // arrow function needs to know that `a` needs to be context allocated, so
  // that the call to `b()` correctly updates the `a` parameter.
  const bool is_top_level_function = outer_scope_->is_script_scope();
  const bool has_inner_functions = preparse_data_builder_ != nullptr &&
                                   preparse_data_builder_->HasInnerFunctions();
  if (maybe_in_arrowhead || !is_top_level_function || has_inner_functions) {
    // Try to resolve unresolved variables for this Scope and migrate those
    // which cannot be resolved inside. It doesn't make sense to try to resolve
    // them in the outer Scopes here, because they are incomplete.
    Scope::AnalyzePartially(this, ast_node_fac
"""


```