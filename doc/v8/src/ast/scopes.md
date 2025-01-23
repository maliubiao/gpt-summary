Response: The user wants a summary of the C++ code provided, specifically focusing on its functionality and its relation to JavaScript.

**Plan:**

1. **High-level overview:** Read through the code to understand the main purpose. It seems to be managing scopes and variables within the V8 JavaScript engine.
2. **Key classes:** Identify the main classes and their roles (`LocalsMap`, `Scope`, `DeclarationScope`, etc.).
3. **Core functionalities:**  Analyze the methods within these classes to understand what operations are being performed (e.g., declaring variables, looking up variables, managing nested scopes).
4. **Relationship to JavaScript:**  Think about how these concepts map to JavaScript's scoping rules and variable declarations (e.g., `var`, `let`, `const`, function scopes, block scopes).
5. **Illustrative JavaScript example:** Create a simple JavaScript code snippet that demonstrates the concepts managed by the C++ code.
这个C++代码文件 `v8/src/ast/scopes.cc` 的主要功能是**定义和实现了用于表示 JavaScript 代码中作用域 (scopes) 和局部变量 (locals) 的数据结构和相关操作**。

更具体地说，它包含了以下核心功能：

1. **`LocalsMap` 类**:
   -  这是一个哈希表，用于存储特定作用域内的局部变量。
   -  它允许添加、删除和查找变量，并维护变量的名称和 `Variable` 对象的关联。

2. **`Scope` 类及其子类 (`DeclarationScope`, `ModuleScope`, `ClassScope`)**:
   -  `Scope` 是所有作用域类型的基类，代表了一个代码的词法作用域。
   -  它维护了指向外部作用域的指针 (`outer_scope_`)，以及内部嵌套的作用域列表 (`inner_scope_`).
   -  它包含了 `LocalsMap` 的实例 (`variables_`)，用于存储该作用域内的局部变量。
   -  它跟踪作用域的类型 (`scope_type_`)，例如脚本作用域、函数作用域、块级作用域等。
   -  `DeclarationScope` 是代表声明性作用域（如函数、脚本、模块）的子类，它持有关于函数的信息，例如参数 (`params_`) 和函数体内的声明 (`decls_`).
   -  `ModuleScope` 和 `ClassScope` 是更具体的作用域类型，分别用于表示模块和类的作用域。

3. **变量声明和管理**:
   -  代码提供了 `Declare()` 方法，用于在作用域中声明新的变量。
   -  它跟踪变量的模式 (`VariableMode`, 例如 `var`, `let`, `const`)、种类 (`VariableKind`) 和初始化状态。
   -  它处理不同类型的作用域下变量声明的特殊性，例如全局变量、函数参数、捕获变量等。

4. **作用域嵌套和查找**:
   -  代码通过 `outer_scope_` 指针维护了作用域之间的层级关系。
   -  它提供了 `Lookup()` 方法，用于在当前作用域及其外部作用域中查找变量。
   -  它处理了作用域链的构建和遍历。

5. **与解析器的集成**:
   -  代码中使用了 `AstRawString` 来表示变量名，这表明它与 V8 的抽象语法树 (AST) 表示紧密集成。
   -  它包含了处理预解析数据 (`preparse-data`) 的逻辑，以支持更快的 JavaScript 解析。

6. **支持不同的 JavaScript 语言特性**:
   -  代码中包含了处理 ES6 模块 (`ModuleScope`) 和类 (`ClassScope`) 的逻辑。
   -  它考虑了 `eval()` 函数对作用域的影响 (`eval_scope()`，`sloppy_eval_can_extend_vars_`).
   -  它处理了 `with` 语句引入的作用域 (`WITH_SCOPE`).
   -  它支持 `try...catch` 语句中的捕获变量 (`CATCH_SCOPE`).

**与 JavaScript 功能的关系及示例：**

这个文件中的代码直接关系到 JavaScript 的作用域规则和变量声明提升等行为。  JavaScript 的作用域决定了变量的可访问性，而这个 C++ 文件负责在 V8 引擎的内部表示和管理这些作用域。

**JavaScript 示例：**

```javascript
function outerFunction() {
  var outerVar = 10; // 对应 DeclarationScope 中的变量声明

  function innerFunction(param1) { // 对应 DeclarationScope 中的函数参数
    let innerVar = 20; // 对应块级作用域中的变量声明
    console.log(outerVar + innerVar + param1);
  }

  if (true) {
    const blockVar = 30; // 对应块级作用域中的常量声明
    // blockVar 在这个块级作用域内有效，对应 Scope 类的实例
  }

  innerFunction(5);
}

outerFunction();
```

**C++ 代码如何处理这个例子：**

- 当 V8 解析 `outerFunction` 时，会创建一个 `DeclarationScope` 对象来表示 `outerFunction` 的作用域。`outerVar` 会被添加到这个作用域的 `LocalsMap` 中。
- 当解析 `innerFunction` 时，会创建一个新的 `DeclarationScope` 对象，并将 `outerFunction` 的作用域设置为其外部作用域 (`outer_scope_`)。`param1` 会被添加到 `innerFunction` 的参数列表 (`params_`) 中，`innerVar` 会添加到其 `LocalsMap` 中。
- `if` 语句会创建一个 `Scope` 对象来表示块级作用域，`blockVar` 会被添加到这个块级作用域的 `LocalsMap` 中。
- 当在 `innerFunction` 中访问 `outerVar` 时，V8 会通过作用域链向上查找，直到在 `outerFunction` 的作用域中找到它。这个查找过程涉及到遍历 `Scope` 对象的 `outer_scope_` 指针。

**总结：**

`v8/src/ast/scopes.cc` 是 V8 引擎中负责管理 JavaScript 代码作用域和局部变量的关键组成部分。它定义了用于表示不同类型作用域的数据结构，并提供了声明、查找和管理变量的功能，从而实现了 JavaScript 的词法作用域规则。理解这个文件的功能有助于深入理解 JavaScript 引擎的内部工作原理。

### 提示词
```
这是目录为v8/src/ast/scopes.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/ast/scopes.h"

#include <optional>
#include <set>

#include "src/ast/ast.h"
#include "src/base/logging.h"
#include "src/builtins/accessors.h"
#include "src/common/message-template.h"
#include "src/heap/local-factory-inl.h"
#include "src/logging/runtime-call-stats-scope.h"
#include "src/objects/scope-info.h"
#include "src/objects/string-inl.h"
#include "src/objects/string-set.h"
#include "src/parsing/parse-info.h"
#include "src/parsing/parser.h"
#include "src/parsing/preparse-data.h"
#include "src/zone/zone.h"

namespace v8 {
namespace internal {

// ----------------------------------------------------------------------------
// Implementation of LocalsMap
//
// Note: We are storing the handle locations as key values in the hash map.
//       When inserting a new variable via Declare(), we rely on the fact that
//       the handle location remains alive for the duration of that variable
//       use. Because a Variable holding a handle with the same location exists
//       this is ensured.

static_assert(sizeof(VariableMap) == (sizeof(void*) + 2 * sizeof(uint32_t) +
                                      sizeof(ZoneAllocationPolicy)),
              "Empty base optimization didn't kick in for VariableMap");

VariableMap::VariableMap(Zone* zone)
    : ZoneHashMap(8, ZoneAllocationPolicy(zone)) {}

VariableMap::VariableMap(const VariableMap& other, Zone* zone)
    : ZoneHashMap(other, ZoneAllocationPolicy(zone)) {}

Variable* VariableMap::Declare(Zone* zone, Scope* scope,
                               const AstRawString* name, VariableMode mode,
                               VariableKind kind,
                               InitializationFlag initialization_flag,
                               MaybeAssignedFlag maybe_assigned_flag,
                               IsStaticFlag is_static_flag, bool* was_added) {
  DCHECK_EQ(zone, allocator().zone());
  // AstRawStrings are unambiguous, i.e., the same string is always represented
  // by the same AstRawString*.
  // FIXME(marja): fix the type of Lookup.
  Entry* p = ZoneHashMap::LookupOrInsert(const_cast<AstRawString*>(name),
                                         name->Hash());
  *was_added = p->value == nullptr;
  if (*was_added) {
    // The variable has not been declared yet -> insert it.
    DCHECK_EQ(name, p->key);
    Variable* variable =
        zone->New<Variable>(scope, name, mode, kind, initialization_flag,
                            maybe_assigned_flag, is_static_flag);
    p->value = variable;
  }
  return reinterpret_cast<Variable*>(p->value);
}

void VariableMap::Remove(Variable* var) {
  const AstRawString* name = var->raw_name();
  ZoneHashMap::Remove(const_cast<AstRawString*>(name), name->Hash());
}

void VariableMap::Add(Variable* var) {
  const AstRawString* name = var->raw_name();
  Entry* p = ZoneHashMap::LookupOrInsert(const_cast<AstRawString*>(name),
                                         name->Hash());
  DCHECK_NULL(p->value);
  DCHECK_EQ(name, p->key);
  p->value = var;
}

Variable* VariableMap::Lookup(const AstRawString* name) {
  Entry* p = ZoneHashMap::Lookup(const_cast<AstRawString*>(name), name->Hash());
  if (p != nullptr) {
    DCHECK(reinterpret_cast<const AstRawString*>(p->key) == name);
    DCHECK_NOT_NULL(p->value);
    return reinterpret_cast<Variable*>(p->value);
  }
  return nullptr;
}

// ----------------------------------------------------------------------------
// Implementation of Scope

Scope::Scope(Zone* zone, ScopeType scope_type)
    : outer_scope_(nullptr), variables_(zone), scope_type_(scope_type) {
  DCHECK(is_script_scope());
  SetDefaults();
}

Scope::Scope(Zone* zone, Scope* outer_scope, ScopeType scope_type)
    : outer_scope_(outer_scope), variables_(zone), scope_type_(scope_type) {
  DCHECK(!is_script_scope());
  SetDefaults();
  set_language_mode(outer_scope->language_mode());
  private_name_lookup_skips_outer_class_ =
      outer_scope->is_class_scope() &&
      outer_scope->AsClassScope()->IsParsingHeritage();
  outer_scope_->AddInnerScope(this);
}

Variable* Scope::DeclareHomeObjectVariable(AstValueFactory* ast_value_factory) {
  bool was_added;
  Variable* home_object_variable = Declare(
      zone(), ast_value_factory->dot_home_object_string(), VariableMode::kConst,
      NORMAL_VARIABLE, InitializationFlag::kCreatedInitialized,
      MaybeAssignedFlag::kNotAssigned, &was_added);
  DCHECK(was_added);
  home_object_variable->set_is_used();
  home_object_variable->ForceContextAllocation();
  return home_object_variable;
}

Variable* Scope::DeclareStaticHomeObjectVariable(
    AstValueFactory* ast_value_factory) {
  bool was_added;
  Variable* static_home_object_variable =
      Declare(zone(), ast_value_factory->dot_static_home_object_string(),
              VariableMode::kConst, NORMAL_VARIABLE,
              InitializationFlag::kCreatedInitialized,
              MaybeAssignedFlag::kNotAssigned, &was_added);
  DCHECK(was_added);
  static_home_object_variable->set_is_used();
  static_home_object_variable->ForceContextAllocation();
  return static_home_object_variable;
}

DeclarationScope::DeclarationScope(Zone* zone,
                                   AstValueFactory* ast_value_factory,
                                   REPLMode repl_mode)
    : Scope(zone, repl_mode == REPLMode::kYes ? REPL_MODE_SCOPE : SCRIPT_SCOPE),
      function_kind_(repl_mode == REPLMode::kYes
                         ? FunctionKind::kAsyncFunction
                         : FunctionKind::kNormalFunction),
      params_(4, zone) {
  DCHECK(is_script_scope());
  SetDefaults();
  receiver_ = DeclareDynamicGlobal(ast_value_factory->this_string(),
                                   THIS_VARIABLE, this);
}

DeclarationScope::DeclarationScope(Zone* zone, Scope* outer_scope,
                                   ScopeType scope_type,
                                   FunctionKind function_kind)
    : Scope(zone, outer_scope, scope_type),
      function_kind_(function_kind),
      params_(4, zone) {
  DCHECK(!is_script_scope());
  SetDefaults();
}

ModuleScope::ModuleScope(DeclarationScope* script_scope,
                         AstValueFactory* avfactory)
    : DeclarationScope(avfactory->single_parse_zone(), script_scope,
                       MODULE_SCOPE, FunctionKind::kModule),
      module_descriptor_(
          avfactory->single_parse_zone()->New<SourceTextModuleDescriptor>(
              avfactory->single_parse_zone())) {
  set_language_mode(LanguageMode::kStrict);
  DeclareThis(avfactory);
}

ModuleScope::ModuleScope(Handle<ScopeInfo> scope_info,
                         AstValueFactory* avfactory)
    : DeclarationScope(avfactory->single_parse_zone(), MODULE_SCOPE, avfactory,
                       scope_info),
      module_descriptor_(nullptr) {
  set_language_mode(LanguageMode::kStrict);
}

ClassScope::ClassScope(Zone* zone, Scope* outer_scope, bool is_anonymous)
    : Scope(zone, outer_scope, CLASS_SCOPE),
      rare_data_and_is_parsing_heritage_(nullptr),
      is_anonymous_class_(is_anonymous) {
  set_language_mode(LanguageMode::kStrict);
}

template <typename IsolateT>
ClassScope::ClassScope(IsolateT* isolate, Zone* zone,
                       AstValueFactory* ast_value_factory,
                       Handle<ScopeInfo> scope_info)
    : Scope(zone, CLASS_SCOPE, ast_value_factory, scope_info),
      rare_data_and_is_parsing_heritage_(nullptr) {
  set_language_mode(LanguageMode::kStrict);
  if (scope_info->ClassScopeHasPrivateBrand()) {
    Variable* brand =
        LookupInScopeInfo(ast_value_factory->dot_brand_string(), this);
    DCHECK_NOT_NULL(brand);
    EnsureRareData()->brand = brand;
  }

  // If the class variable is context-allocated and its index is
  // saved for deserialization, deserialize it.
  if (scope_info->HasSavedClassVariable()) {
    Tagged<String> name;
    int index;
    std::tie(name, index) = scope_info->SavedClassVariable();
    DCHECK_EQ(scope_info->ContextLocalMode(index), VariableMode::kConst);
    DCHECK_EQ(scope_info->ContextLocalInitFlag(index),
              InitializationFlag::kNeedsInitialization);
    DCHECK_EQ(scope_info->ContextLocalMaybeAssignedFlag(index),
              MaybeAssignedFlag::kMaybeAssigned);
    Variable* var = DeclareClassVariable(
        ast_value_factory,
        ast_value_factory->GetString(name,
                                     SharedStringAccessGuardIfNeeded(isolate)),
        kNoSourcePosition);
    var->AllocateTo(VariableLocation::CONTEXT,
                    Context::MIN_CONTEXT_SLOTS + index);
  }

  DCHECK(scope_info->HasPositionInfo());
  set_start_position(scope_info->StartPosition());
  set_end_position(scope_info->EndPosition());
}
template ClassScope::ClassScope(Isolate* isolate, Zone* zone,
                                AstValueFactory* ast_value_factory,
                                Handle<ScopeInfo> scope_info);
template ClassScope::ClassScope(LocalIsolate* isolate, Zone* zone,
                                AstValueFactory* ast_value_factory,
                                Handle<ScopeInfo> scope_info);

Scope::Scope(Zone* zone, ScopeType scope_type,
             AstValueFactory* ast_value_factory, Handle<ScopeInfo> scope_info)
    : outer_scope_(nullptr),
      variables_(zone),
      scope_info_(scope_info),
      scope_type_(scope_type) {
  DCHECK(!scope_info.is_null());
  SetDefaults();
#ifdef DEBUG
  already_resolved_ = true;
#endif
  set_language_mode(scope_info->language_mode());
  DCHECK_EQ(ContextHeaderLength(), num_heap_slots_);
  private_name_lookup_skips_outer_class_ =
      scope_info->PrivateNameLookupSkipsOuterClass();
  // We don't really need to use the preparsed scope data; this is just to
  // shorten the recursion in SetMustUsePreparseData.
  must_use_preparsed_scope_data_ = true;

  if (scope_type == BLOCK_SCOPE) {
    // Set is_block_scope_for_object_literal_ based on the existence of the home
    // object variable (we don't store it explicitly).
    DCHECK_NOT_NULL(ast_value_factory);
    int home_object_index = scope_info->ContextSlotIndex(
        ast_value_factory->dot_home_object_string()->string());
    DCHECK_IMPLIES(home_object_index >= 0,
                   scope_type == CLASS_SCOPE || scope_type == BLOCK_SCOPE);
    if (home_object_index >= 0) {
      is_block_scope_for_object_literal_ = true;
    }
  }
}

DeclarationScope::DeclarationScope(Zone* zone, ScopeType scope_type,
                                   AstValueFactory* ast_value_factory,
                                   Handle<ScopeInfo> scope_info)
    : Scope(zone, scope_type, ast_value_factory, scope_info),
      function_kind_(scope_info->function_kind()),
      params_(0, zone) {
  DCHECK(!is_script_scope());
  SetDefaults();
  if (scope_info->SloppyEvalCanExtendVars()) {
    DCHECK(!is_eval_scope());
    sloppy_eval_can_extend_vars_ = true;
  }
  if (scope_info->ClassScopeHasPrivateBrand()) {
    DCHECK(IsClassConstructor(function_kind()));
    class_scope_has_private_brand_ = true;
  }
}

Scope::Scope(Zone* zone, const AstRawString* catch_variable_name,
             MaybeAssignedFlag maybe_assigned, Handle<ScopeInfo> scope_info)
    : outer_scope_(nullptr),
      variables_(zone),
      scope_info_(scope_info),
      scope_type_(CATCH_SCOPE) {
  SetDefaults();
#ifdef DEBUG
  already_resolved_ = true;
#endif
  // Cache the catch variable, even though it's also available via the
  // scope_info, as the parser expects that a catch scope always has the catch
  // variable as first and only variable.
  bool was_added;
  Variable* variable =
      Declare(zone, catch_variable_name, VariableMode::kVar, NORMAL_VARIABLE,
              kCreatedInitialized, maybe_assigned, &was_added);
  DCHECK(was_added);
  AllocateHeapSlot(variable);
}

void DeclarationScope::SetDefaults() {
  is_declaration_scope_ = true;
  has_simple_parameters_ = true;
#if V8_ENABLE_WEBASSEMBLY
  is_asm_module_ = false;
#endif  // V8_ENABLE_WEBASSEMBLY
  force_eager_compilation_ = false;
  has_arguments_parameter_ = false;
  uses_super_property_ = false;
  has_checked_syntax_ = false;
  has_this_reference_ = false;
  has_this_declaration_ =
      (is_function_scope() && !is_arrow_scope()) || is_module_scope();
  needs_private_name_context_chain_recalc_ = false;
  has_rest_ = false;
  receiver_ = nullptr;
  new_target_ = nullptr;
  function_ = nullptr;
  arguments_ = nullptr;
  rare_data_ = nullptr;
  should_eager_compile_ = false;
  was_lazily_parsed_ = false;
  is_skipped_function_ = false;
  preparse_data_builder_ = nullptr;
  class_scope_has_private_brand_ = false;
#ifdef DEBUG
  DeclarationScope* outer_declaration_scope =
      outer_scope_ ? outer_scope_->GetDeclarationScope() : nullptr;
  is_being_lazily_parsed_ =
      outer_declaration_scope ? outer_declaration_scope->is_being_lazily_parsed_
                              : false;
#endif
}

void Scope::SetDefaults() {
#ifdef DEBUG
  scope_name_ = nullptr;
  already_resolved_ = false;
  needs_migration_ = false;
#endif
  inner_scope_ = nullptr;
  sibling_ = nullptr;
  unresolved_list_.Clear();

  start_position_ = kNoSourcePosition;
  end_position_ = kNoSourcePosition;

  calls_eval_ = false;
  sloppy_eval_can_extend_vars_ = false;
  scope_nonlinear_ = false;
  is_hidden_ = false;
  is_debug_evaluate_scope_ = false;

  inner_scope_calls_eval_ = false;
  force_context_allocation_for_parameters_ = false;

  is_declaration_scope_ = false;

  private_name_lookup_skips_outer_class_ = false;

  must_use_preparsed_scope_data_ = false;

  needs_home_object_ = false;
  is_block_scope_for_object_literal_ = false;

  has_using_declaration_ = false;
  has_await_using_declaration_ = false;

  is_wrapped_function_ = false;

  num_stack_slots_ = 0;
  num_heap_slots_ = ContextHeaderLength();

  set_language_mode(LanguageMode::kSloppy);
}

bool Scope::HasSimpleParameters() {
  DeclarationScope* scope = GetClosureScope();
  return !scope->is_function_scope() || scope->has_simple_parameters();
}

void DeclarationScope::set_should_eager_compile() {
  should_eager_compile_ = !was_lazily_parsed_;
}

#if V8_ENABLE_WEBASSEMBLY
void DeclarationScope::set_is_asm_module() { is_asm_module_ = true; }

bool Scope::IsAsmModule() const {
  return is_function_scope() && AsDeclarationScope()->is_asm_module();
}

bool Scope::ContainsAsmModule() const {
  if (IsAsmModule()) return true;

  // Check inner scopes recursively
  for (Scope* scope = inner_scope_; scope != nullptr; scope = scope->sibling_) {
    // Don't check inner functions which won't be eagerly compiled.
    if (!scope->is_function_scope() ||
        scope->AsDeclarationScope()->ShouldEagerCompile()) {
      if (scope->ContainsAsmModule()) return true;
    }
  }

  return false;
}
#endif  // V8_ENABLE_WEBASSEMBLY

template <typename IsolateT>
Scope* Scope::DeserializeScopeChain(IsolateT* isolate, Zone* zone,
                                    Tagged<ScopeInfo> scope_info,
                                    DeclarationScope* script_scope,
                                    AstValueFactory* ast_value_factory,
                                    DeserializationMode deserialization_mode,
                                    ParseInfo* parse_info) {
  // Reconstruct the outer scope chain from a closure's context chain.
  Scope* current_scope = nullptr;
  Scope* innermost_scope = nullptr;
  Scope* outer_scope = nullptr;
  while (!scope_info.is_null()) {
    if (scope_info->scope_type() == WITH_SCOPE) {
      if (scope_info->IsDebugEvaluateScope()) {
        outer_scope =
            zone->New<DeclarationScope>(zone, FUNCTION_SCOPE, ast_value_factory,
                                        handle(scope_info, isolate));
        outer_scope->set_is_debug_evaluate_scope();
      } else {
        // For scope analysis, debug-evaluate is equivalent to a with scope.
        outer_scope = zone->New<Scope>(zone, WITH_SCOPE, ast_value_factory,
                                       handle(scope_info, isolate));
      }

    } else if (scope_info->is_script_scope()) {
      // If we reach a script scope, it's the outermost scope. Install the
      // scope info of this script context onto the existing script scope to
      // avoid nesting script scopes.
      if (deserialization_mode == DeserializationMode::kIncludingVariables) {
        script_scope->SetScriptScopeInfo(handle(scope_info, isolate));
      }
      DCHECK(!scope_info->HasOuterScopeInfo());
      break;
    } else if (scope_info->scope_type() == FUNCTION_SCOPE) {
      outer_scope = zone->New<DeclarationScope>(
          zone, FUNCTION_SCOPE, ast_value_factory, handle(scope_info, isolate));
#if V8_ENABLE_WEBASSEMBLY
      if (scope_info->IsAsmModule()) {
        outer_scope->AsDeclarationScope()->set_is_asm_module();
      }
#endif  // V8_ENABLE_WEBASSEMBLY
    } else if (scope_info->scope_type() == EVAL_SCOPE) {
      outer_scope = zone->New<DeclarationScope>(
          zone, EVAL_SCOPE, ast_value_factory, handle(scope_info, isolate));
    } else if (scope_info->scope_type() == CLASS_SCOPE) {
      outer_scope = zone->New<ClassScope>(isolate, zone, ast_value_factory,
                                          handle(scope_info, isolate));
    } else if (scope_info->scope_type() == BLOCK_SCOPE) {
      if (scope_info->is_declaration_scope()) {
        outer_scope = zone->New<DeclarationScope>(
            zone, BLOCK_SCOPE, ast_value_factory, handle(scope_info, isolate));
      } else {
        outer_scope = zone->New<Scope>(zone, BLOCK_SCOPE, ast_value_factory,
                                       handle(scope_info, isolate));
      }
    } else if (scope_info->scope_type() == MODULE_SCOPE) {
      outer_scope = zone->New<ModuleScope>(handle(scope_info, isolate),
                                           ast_value_factory);
      if (parse_info) {
        parse_info->set_has_module_in_scope_chain();
      }
    } else {
      DCHECK_EQ(scope_info->scope_type(), CATCH_SCOPE);
      DCHECK_EQ(scope_info->ContextLocalCount(), 1);
      DCHECK_EQ(scope_info->ContextLocalMode(0), VariableMode::kVar);
      DCHECK_EQ(scope_info->ContextLocalInitFlag(0), kCreatedInitialized);
      DCHECK(scope_info->HasInlinedLocalNames());
      Tagged<String> name = scope_info->ContextInlinedLocalName(0);
      MaybeAssignedFlag maybe_assigned =
          scope_info->ContextLocalMaybeAssignedFlag(0);
      outer_scope =
          zone->New<Scope>(zone,
                           ast_value_factory->GetString(
                               name, SharedStringAccessGuardIfNeeded(isolate)),
                           maybe_assigned, handle(scope_info, isolate));
    }

    if (deserialization_mode == DeserializationMode::kScopesOnly) {
      outer_scope->scope_info_ = Handle<ScopeInfo>::null();
    }

    if (current_scope != nullptr) {
      outer_scope->AddInnerScope(current_scope);
    }
    current_scope = outer_scope;
    if (innermost_scope == nullptr) innermost_scope = current_scope;
    scope_info = scope_info->HasOuterScopeInfo() ? scope_info->OuterScopeInfo()
                                                 : Tagged<ScopeInfo>();
  }

  if (deserialization_mode == DeserializationMode::kIncludingVariables) {
    SetScriptScopeInfo(isolate, script_scope);
  }

  if (innermost_scope == nullptr) return script_scope;
  script_scope->AddInnerScope(current_scope);
  return innermost_scope;
}

template <typename IsolateT>
void Scope::SetScriptScopeInfo(IsolateT* isolate,
                               DeclarationScope* script_scope) {
  if (script_scope->scope_info_.is_null()) {
    script_scope->SetScriptScopeInfo(
        ReadOnlyRoots(isolate).global_this_binding_scope_info_handle());
  }
}

template EXPORT_TEMPLATE_DEFINE(
    V8_EXPORT_PRIVATE) void Scope::SetScriptScopeInfo(Isolate* isolate,
                                                      DeclarationScope*
                                                          script_scope);
template EXPORT_TEMPLATE_DEFINE(
    V8_EXPORT_PRIVATE) void Scope::SetScriptScopeInfo(LocalIsolate* isolate,
                                                      DeclarationScope*
                                                          script_scope);

template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)
    Scope* Scope::DeserializeScopeChain(
        Isolate* isolate, Zone* zone, Tagged<ScopeInfo> scope_info,
        DeclarationScope* script_scope, AstValueFactory* ast_value_factory,
        DeserializationMode deserialization_mode, ParseInfo* parse_info);
template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)
    Scope* Scope::DeserializeScopeChain(
        LocalIsolate* isolate, Zone* zone, Tagged<ScopeInfo> scope_info,
        DeclarationScope* script_scope, AstValueFactory* ast_value_factory,
        DeserializationMode deserialization_mode, ParseInfo* parse_info);

DeclarationScope* Scope::AsDeclarationScope() {
  // Here and below: if an attacker corrupts the in-sandox SFI::unique_id or
  // fields of a Script object, we can get confused about which type of scope
  // we're operating on. These CHECKs defend against that.
  SBXCHECK(is_declaration_scope());
  return static_cast<DeclarationScope*>(this);
}

const DeclarationScope* Scope::AsDeclarationScope() const {
  SBXCHECK(is_declaration_scope());
  return static_cast<const DeclarationScope*>(this);
}

ModuleScope* Scope::AsModuleScope() {
  SBXCHECK(is_module_scope());
  return static_cast<ModuleScope*>(this);
}

const ModuleScope* Scope::AsModuleScope() const {
  SBXCHECK(is_module_scope());
  return static_cast<const ModuleScope*>(this);
}

ClassScope* Scope::AsClassScope() {
  SBXCHECK(is_class_scope());
  return static_cast<ClassScope*>(this);
}

const ClassScope* Scope::AsClassScope() const {
  SBXCHECK(is_class_scope());
  return static_cast<const ClassScope*>(this);
}

void DeclarationScope::DeclareSloppyBlockFunction(
    SloppyBlockFunctionStatement* sloppy_block_function) {
  sloppy_block_functions_.Add(sloppy_block_function);
}

void DeclarationScope::HoistSloppyBlockFunctions(AstNodeFactory* factory) {
  DCHECK(is_sloppy(language_mode()));
  DCHECK(is_function_scope() || is_eval_scope() || is_script_scope() ||
         (is_block_scope() && outer_scope()->is_function_scope()));
  DCHECK(HasSimpleParameters() || is_block_scope() || is_being_lazily_parsed_);
  DCHECK_EQ(factory == nullptr, is_being_lazily_parsed_);

  if (sloppy_block_functions_.is_empty()) return;

  // In case of complex parameters the current scope is the body scope and the
  // parameters are stored in the outer scope.
  Scope* parameter_scope = HasSimpleParameters() ? this : outer_scope_;
  DCHECK(parameter_scope->is_function_scope() || is_eval_scope() ||
         is_script_scope());

  DeclarationScope* decl_scope = GetNonEvalDeclarationScope();
  Scope* outer_scope = decl_scope->outer_scope();

  // For each variable which is used as a function declaration in a sloppy
  // block,
  for (SloppyBlockFunctionStatement* sloppy_block_function :
       sloppy_block_functions_) {
    const AstRawString* name = sloppy_block_function->name();

    // If the variable wouldn't conflict with a lexical declaration
    // or parameter,

    // Check if there's a conflict with a parameter.
    Variable* maybe_parameter = parameter_scope->LookupLocal(name);
    if (maybe_parameter != nullptr && maybe_parameter->is_parameter()) {
      continue;
    }

    // Check if there's a conflict with a lexical declaration
    Scope* query_scope = sloppy_block_function->scope()->outer_scope();
    bool should_hoist = true;

    // It is not sufficient to just do a Lookup on query_scope: for
    // example, that does not prevent hoisting of the function in
    // `{ let e; try {} catch (e) { function e(){} } }`
    //
    // Don't use a generic cache scope, as the cache scope would be the outer
    // scope and we terminate the iteration there anyway.
    do {
      Variable* var = query_scope->LookupInScopeOrScopeInfo(name, query_scope);
      if (var != nullptr && IsLexicalVariableMode(var->mode()) &&
          !var->is_sloppy_block_function()) {
        should_hoist = false;
        break;
      }
      query_scope = query_scope->outer_scope();
    } while (query_scope != outer_scope);

    if (!should_hoist) continue;

    if (factory) {
      DCHECK(!is_being_lazily_parsed_);
      int pos = sloppy_block_function->position();
      bool ok = true;
      bool was_added;
      auto declaration = factory->NewVariableDeclaration(pos);
      // Based on the preceding checks, it doesn't matter what we pass as
      // sloppy_mode_block_scope_function_redefinition.
      //
      // This synthesized var for Annex B functions-in-block (FiB) may be
      // declared multiple times for the same var scope, such as in the case of
      // shadowed functions-in-block like the following:
      //
      // {
      //    function f() {}
      //    { function f() {} }
      // }
      //
      // Redeclarations for vars do not create new bindings, but the
      // redeclarations' initializers are still run. That is, shadowed FiB will
      // result in multiple assignments to the same synthesized var.
      Variable* var = DeclareVariable(
          declaration, name, pos, VariableMode::kVar, NORMAL_VARIABLE,
          Variable::DefaultInitializationFlag(VariableMode::kVar), &was_added,
          nullptr, &ok);
      DCHECK(ok);
      VariableProxy* source =
          factory->NewVariableProxy(sloppy_block_function->var());
      VariableProxy* target = factory->NewVariableProxy(var);
      Assignment* assignment = factory->NewAssignment(
          sloppy_block_function->init(), target, source, pos);
      assignment->set_lookup_hoisting_mode(LookupHoistingMode::kLegacySloppy);
      Statement* statement = factory->NewExpressionStatement(assignment, pos);
      sloppy_block_function->set_statement(statement);
    } else {
      DCHECK(is_being_lazily_parsed_);
      bool was_added;
      Variable* var = DeclareVariableName(name, VariableMode::kVar, &was_added);
      if (sloppy_block_function->init() == Token::kAssign) {
        var->SetMaybeAssigned();
      }
    }
  }
}

void DeclarationScope::TakeUnresolvedReferencesFromParent() {
  DCHECK(outer_scope_->reparsing_for_class_initializer_);
  unresolved_list_.MoveTail(&outer_scope_->unresolved_list_,
                            outer_scope_->unresolved_list_.begin());
}

bool DeclarationScope::Analyze(ParseInfo* info) {
  RCS_SCOPE(info->runtime_call_stats(),
            RuntimeCallCounterId::kCompileScopeAnalysis,
            RuntimeCallStats::kThreadSpecific);
  DCHECK_NOT_NULL(info->literal());
  DeclarationScope* scope = info->literal()->scope();

  std::optional<AllowHandleDereference> allow_deref;
#ifdef DEBUG
  if (scope->outer_scope() && !scope->outer_scope()->scope_info_.is_null()) {
    allow_deref.emplace();
  }
#endif

  if (scope->is_eval_scope() && is_sloppy(scope->language_mode())) {
    AstNodeFactory factory(info->ast_value_factory(), info->zone());
    scope->HoistSloppyBlockFunctions(&factory);
  }

  // We are compiling one of four cases:
  // 1) top-level code,
  // 2) a function/eval/module on the top-level
  // 4) a class member initializer function scope
  // 3) 4 function/eval in a scope that was already resolved.
  DCHECK(scope->is_script_scope() || scope->outer_scope()->is_script_scope() ||
         scope->outer_scope()->already_resolved_);

  // The outer scope is never lazy.
  scope->set_should_eager_compile();

  if (scope->must_use_preparsed_scope_data_) {
    DCHECK_EQ(scope->scope_type_, ScopeType::FUNCTION_SCOPE);
    allow_deref.emplace();
    info->consumed_preparse_data()->RestoreScopeAllocationData(
        scope, info->ast_value_factory(), info->zone());
  }

  if (!scope->AllocateVariables(info)) return false;
  scope->GetScriptScope()->RewriteReplGlobalVariables();

#ifdef DEBUG
  if (v8_flags.print_scopes) {
    PrintF("Global scope:\n");
    scope->Print();
  }
  scope->CheckScopePositions();
  scope->CheckZones();
#endif

  return true;
}

void DeclarationScope::DeclareThis(AstValueFactory* ast_value_factory) {
  DCHECK(has_this_declaration());

  bool derived_constructor = IsDerivedConstructor(function_kind_);

  receiver_ = zone()->New<Variable>(
      this, ast_value_factory->this_string(),
      derived_constructor ? VariableMode::kConst : VariableMode::kVar,
      THIS_VARIABLE,
      derived_constructor ? kNeedsInitialization : kCreatedInitialized,
      kNotAssigned);
  // Derived constructors have hole checks when calling super. Mark the 'this'
  // variable as having hole initialization forced so that TDZ elision analysis
  // applies and numbers the variable.
  if (derived_constructor) {
    receiver_->ForceHoleInitialization(
        Variable::kHasHoleCheckUseInUnknownScope);
  }
  locals_.Add(receiver_);
}

void DeclarationScope::DeclareArguments(AstValueFactory* ast_value_factory) {
  DCHECK(is_function_scope());
  DCHECK(!is_arrow_scope());

  // Because when arguments_ is not nullptr, we already declared
  // "arguments exotic object" to add it into parameters before
  // impl()->InsertShadowingVarBindingInitializers, so here
  // only declare "arguments exotic object" when arguments_
  // is nullptr
  if (arguments_ != nullptr) {
    return;
  }

  // Declare 'arguments' variable which exists in all non arrow functions.  Note
  // that it might never be accessed, in which case it won't be allocated during
  // variable allocation.
  bool was_added = false;

  arguments_ =
      Declare(zone(), ast_value_factory->arguments_string(), VariableMode::kVar,
              NORMAL_VARIABLE, kCreatedInitialized, kNotAssigned, &was_added);
  // According to ES#sec-functiondeclarationinstantiation step 18
  // we should set argumentsObjectNeeded to false if has lexical
  // declared arguments only when hasParameterExpressions is false
  if (!was_added && IsLexicalVariableMode(arguments_->mode()) &&
      has_simple_parameters_) {
    // Check if there's lexically declared variable named arguments to avoid
    // redeclaration. See ES#sec-functiondeclarationinstantiation, step 20.
    arguments_ = nullptr;
  }
}

void DeclarationScope::DeclareDefaultFunctionVariables(
    AstValueFactory* ast_value_factory) {
  DCHECK(is_function_scope());
  DCHECK(!is_arrow_scope());

  DeclareThis(ast_value_factory);
  bool was_added;
  new_target_ = Declare(zone(), ast_value_factory->new_target_string(),
                        VariableMode::kConst, NORMAL_VARIABLE,
                        kCreatedInitialized, kNotAssigned, &was_added);
  DCHECK(was_added);

  if (IsConciseMethod(function_kind_) || IsClassConstructor(function_kind_) ||
      IsAccessorFunction(function_kind_)) {
    EnsureRareData()->this_function = Declare(
        zone(), ast_value_factory->this_function_string(), VariableMode::kConst,
        NORMAL_VARIABLE, kCreatedInitialized, kNotAssigned, &was_added);
    DCHECK(was_added);
  }
}

Variable* DeclarationScope::DeclareFunctionVar(const AstRawString* name,
                                               Scope* cache) {
  DCHECK(is_function_scope());
  if (cache == nullptr) {
    DCHECK_NULL(function_);
    cache = this;
  } else if (function_ != nullptr) {
    return function_;
  }
  DCHECK(this->IsOuterScopeOf(cache));
  DCHECK_NULL(cache->variables_.Lookup(name));
  VariableKind kind = is_sloppy(language_mode()) ? SLOPPY_FUNCTION_NAME_VARIABLE
                                                 : NORMAL_VARIABLE;
  function_ = zone()->New<Variable>(this, name, VariableMode::kConst, kind,
                                    kCreatedInitialized);
  if (sloppy_eval_can_extend_vars()) {
    cache->NonLocal(name, VariableMode::kDynamic);
  } else {
    cache->variables_.Add(function_);
  }
  return function_;
}

Variable* DeclarationScope::DeclareGeneratorObjectVar(
    const AstRawString* name) {
  DCHECK(is_function_scope() || is_module_scope() || is_repl_mode_scope());
  DCHECK_NULL(generator_object_var());

  Variable* result = EnsureRareData()->generator_object =
      NewTemporary(name, kNotAssigned);
  result->set_is_used();
  return result;
}

Scope* Scope::FinalizeBlockScope() {
  DCHECK(is_block_scope());
#ifdef DEBUG
  DCHECK_NE(sibling_, this);
#endif

  if (variables_.occupancy() > 0 ||
      (is_declaration_scope() &&
       AsDeclarationScope()->sloppy_eval_can_extend_vars())) {
    return this;
  }

  DCHECK(!is_class_scope());

  // Remove this scope from outer scope.
  outer_scope()->RemoveInnerScope(this);

  // Reparent inner scopes.
  if (inner_scope_ != nullptr) {
    Scope* scope = inner_scope_;
    scope->outer_scope_ = outer_scope();
    while (scope->sibling_ != nullptr) {
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
```