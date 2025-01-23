Response: The user wants me to summarize the functionality of the C++ code in `v8/src/parsing/parser.cc`. This is part 2 of a 3-part request, implying there's a broader context. The provided code snippet focuses on parsing JavaScript language features related to module exports, variable declarations, function declarations (including async and generators), class declarations, try-catch statements, and for loops. It also includes logic for handling scopes and managing declarations. I need to distill these details into a concise summary. Since the prompt asks about the relationship with JavaScript, I should use JavaScript examples to illustrate the parsed features.

Here's a breakdown of the code's key responsibilities:

1. **Module Exports:** Parsing `export` statements, including `export *`, `export { ... }`, and default exports.
2. **Variable Declarations:** Handling `var`, `let`, and `const` declarations, including declaration and binding of variables.
3. **Function Declarations:** Parsing regular, async, and generator function declarations.
4. **Class Declarations:** Parsing class declarations, including methods, fields (public and private), static members, and static blocks.
5. **Control Flow:** Handling `try...catch...finally` statements and different types of `for` loops (`for`, `for...in`, `for...of`).
6. **Scope Management:** Creating and managing different types of scopes (function, block, class).
7. **Error Handling:** Reporting syntax errors encountered during parsing.
8. **Desugaring:** Transforming certain JavaScript constructs into simpler forms (e.g., `export * as ...`).
这是 `v8/src/parsing/parser.cc` 文件的一部分，主要负责解析 JavaScript 代码中的 **导出 (export)** 声明，以及与变量声明、函数声明、类声明、控制流语句等相关的解析逻辑。

**功能归纳:**

这部分代码主要负责以下功能：

1. **解析 `export` 声明:**
    *   解析 `export * from 'module'` 语法，将来自其他模块的所有导出项重新导出。
    *   解析 `export * as Name from 'module'` 语法，将来自其他模块的所有导出项以新的名称重新导出。
    *   解析 `export { identifier1, identifier2 as alias }` 语法，导出当前模块中的特定变量或函数。
    *   解析 `export { identifier1, identifier2 as alias } from 'module'` 语法，从其他模块导出特定项。
    *   解析 `export default ...` 语法，导出默认值。
    *   解析 `export var/let/const ...`，`export function ...`，`export class ...` 等声明并导出。

2. **声明和绑定变量:**
    *   `DeclareUnboundVariable`: 声明一个未绑定的变量。
    *   `DeclareBoundVariable`: 声明并绑定一个变量到其作用域。
    *   `DeclareAndBindVariable`: 声明变量，并将其绑定到一个已有的 `VariableProxy`。
    *   `DeclareVariable`: 声明变量并将其添加到作用域中。
    *   `Declare`: 执行变量声明的核心逻辑，处理作用域、重复声明等问题。

3. **构建初始化代码块:**
    *   `BuildInitializationBlock`:  为变量声明（例如 `let` 或 `const`）构建初始化代码块，确保在访问变量之前完成初始化。

4. **声明函数和类:**
    *   `DeclareFunction`: 声明一个函数，并将其添加到作用域中。
    *   `DeclareClass`: 声明一个类，并将其添加到作用域中。
    *   `DeclareNative`: 声明一个原生函数。

5. **处理控制流语句:**
    *   `RewriteSwitchStatement`:  将 `switch` 语句重写为包含块级作用域的结构。
    *   `InitializeVariables`: 为变量初始化创建赋值语句。
    *   `RewriteCatchPattern`: 重写 `catch` 语句中的模式匹配。
    *   `RewriteTryStatement`: 重写 `try...catch...finally` 语句，将其转换为嵌套的结构。

6. **解析生成器函数:**
    *   `ParseGeneratorFunctionBody`: 解析生成器函数的函数体，并在开头插入初始的 `yield` 语句。
    *   `ParseAsyncGeneratorFunctionBody`: 解析异步生成器函数的函数体，并在开头插入初始的 `yield` 语句。

7. **特殊处理 `for` 循环:**
    *   `RewriteForVarInLegacy`: 为传统的 `for (var ... in ...)` 循环的初始化部分创建特殊的代码块。
    *   `DesugarBindingInForEachStatement`: 将 `for...in` 和 `for...of` 循环中的变量绑定解构为临时变量赋值。
    *   `CreateForEachStatementTDZ`: 为 `for...in` 和 `for...of` 循环中声明的 `let` 或 `const` 变量创建临时死区 (TDZ)。
    *   `DesugarLexicalBindingsInForStatement`:  对包含 `let` 或 `const` 声明的 `for` 循环进行解构，以符合 ES6 规范，为每次迭代创建新的词法环境。

8. **解析函数字面量:**
    *   `ParseFunctionLiteral`:  解析函数字面量（包括普通函数、getter、setter）。这部分也涉及懒解析的逻辑。
    *   `SkipFunction`:  在懒解析模式下跳过函数体的解析。
    *   `ParseFunction`: 实际解析函数体。

9. **解析类相关的元素:**
    *   `DeclareClassVariable`: 声明一个类的变量。
    *   `CreateSyntheticContextVariableProxy`: 为类创建合成的上下文变量代理。
    *   `CreatePrivateNameVariable`: 创建私有成员变量。
    *   `AddInstanceFieldOrStaticElement`: 将类字段或静态元素添加到类信息中。
    *   `DeclarePublicClassField`: 声明公共类字段。
    *   `DeclarePrivateClassMember`: 声明私有类成员。
    *   `DeclarePublicClassMethod`: 声明公共类方法。
    *   `AddClassStaticBlock`: 添加类静态代码块。
    *   `CreateInitializerFunction`: 创建用于初始化类成员的函数。
    *   `CreateStaticElementsInitializer`: 创建用于初始化类静态元素的函数。
    *   `CreateInstanceMembersInitializer`: 创建用于初始化类实例成员的函数。
    *   `RewriteClassLiteral`:  将解析得到的类信息重写为 `ClassLiteral` AST 节点。

**与 JavaScript 功能的关系及示例:**

这部分代码直接对应 JavaScript 的语法结构和语义，负责将 JavaScript 源代码转换成抽象语法树 (AST)，为后续的编译和执行阶段提供基础。

**示例：**

**1. `export` 声明:**

```javascript
// my_module.js
export const PI = 3.14;
export function add(a, b) {
  return a + b;
}

// main.js
import { PI, add } from './my_module.js';
console.log(PI); // 3.14
console.log(add(1, 2)); // 3
```

`Parser::ParseExportDeclaration()` 等函数会解析 `export const PI = 3.14;` 和 `import { PI, add } from './my_module.js';` 这些语句，并构建相应的 AST 节点。

**2. 变量声明:**

```javascript
var x = 10;
let y = 20;
const z = 30;
```

`Parser::ParseVariableStatement()` 和相关的 `Declare...` 函数会处理 `var`, `let`, `const` 声明，并在当前作用域中声明和绑定变量。

**3. 函数声明:**

```javascript
function greet(name) {
  console.log('Hello, ' + name);
}

async function fetchData() {
  // ...
}

function* generateNumbers() {
  yield 1;
  yield 2;
}
```

`Parser::ParseHoistableDeclaration()`，`Parser::ParseAsyncFunctionDeclaration()` 等函数会解析不同类型的函数声明，并创建 `FunctionLiteral` AST 节点。

**4. 类声明:**

```javascript
class MyClass {
  constructor(value) {
    this.value = value;
  }

  static staticMethod() {
    console.log('Static method');
  }

  getValue() {
    return this.value;
  }

  #privateField = 0;
}
```

`Parser::ParseClassDeclaration()` 以及相关的 `DeclareClass...` 函数会解析类声明，包括构造函数、静态方法、实例方法、私有字段等，并构建 `ClassLiteral` AST 节点。

**5. `try...catch` 语句:**

```javascript
try {
  // ...可能会抛出异常的代码
} catch (error) {
  console.error('发生错误:', error);
} finally {
  // ... 总是会执行的代码
}
```

`Parser::ParseTryStatement()` 会解析 `try`, `catch`, `finally` 块，并构建相应的 `TryCatchStatement` 和 `TryFinallyStatement` AST 节点。

**6. `for` 循环:**

```javascript
for (let i = 0; i < 10; i++) {
  console.log(i);
}

const arr = [1, 2, 3];
for (const item of arr) {
  console.log(item);
}
```

`Parser::ParseForStatement()` 和 `Parser::ParseForInStatement()` 会解析不同类型的 `for` 循环，并根据 ES6 规范进行必要的解构和转换。

总而言之，这部分 `parser.cc` 代码是 V8 引擎将 JavaScript 源代码转化为内部表示的关键组成部分，它识别并解析 JavaScript 的各种语法结构，为后续的编译和执行奠定基础。

### 提示词
```
这是目录为v8/src/parsing/parser.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```
);
}

void Parser::ParseExportStar() {
  int pos = position();
  Consume(Token::kMul);

  if (!PeekContextualKeyword(ast_value_factory()->as_string())) {
    // 'export' '*' 'from' ModuleSpecifier ';'
    Scanner::Location loc = scanner()->location();
    ExpectContextualKeyword(ast_value_factory()->from_string());
    Scanner::Location specifier_loc = scanner()->peek_location();
    const AstRawString* module_specifier = ParseModuleSpecifier();
    const ImportAttributes* import_attributes = ParseImportWithOrAssertClause();
    ExpectSemicolon();
    module()->AddStarExport(module_specifier, import_attributes, loc,
                            specifier_loc, zone());
    return;
  }

  // 'export' '*' 'as' IdentifierName 'from' ModuleSpecifier ';'
  //
  // Desugaring:
  //   export * as x from "...";
  // ~>
  //   import * as .x from "..."; export {.x as x};
  //
  // Note that the desugared internal namespace export name (.x above) will
  // never conflict with a string literal export name, as literal string export
  // names in local name positions (i.e. left of 'as' or in a clause without
  // 'as') are disallowed without a following 'from' clause.

  ExpectContextualKeyword(ast_value_factory()->as_string());
  const AstRawString* export_name = ParseExportSpecifierName();
  Scanner::Location export_name_loc = scanner()->location();
  const AstRawString* local_name = NextInternalNamespaceExportName();
  Scanner::Location local_name_loc = Scanner::Location::invalid();
  DeclareUnboundVariable(local_name, VariableMode::kConst, kCreatedInitialized,
                         pos);

  ExpectContextualKeyword(ast_value_factory()->from_string());
  Scanner::Location specifier_loc = scanner()->peek_location();
  const AstRawString* module_specifier = ParseModuleSpecifier();
  const ImportAttributes* import_attributes = ParseImportWithOrAssertClause();
  ExpectSemicolon();

  module()->AddStarImport(local_name, module_specifier, import_attributes,
                          local_name_loc, specifier_loc, zone());
  module()->AddExport(local_name, export_name, export_name_loc, zone());
}

Statement* Parser::ParseExportDeclaration() {
  // ExportDeclaration:
  //    'export' '*' 'from' ModuleSpecifier ';'
  //    'export' '*' 'from' ModuleSpecifier [no LineTerminator here]
  //        AssertClause ';'
  //    'export' '*' 'as' IdentifierName 'from' ModuleSpecifier ';'
  //    'export' '*' 'as' IdentifierName 'from' ModuleSpecifier
  //        [no LineTerminator here] AssertClause ';'
  //    'export' '*' 'as' ModuleExportName 'from' ModuleSpecifier ';'
  //    'export' '*' 'as' ModuleExportName 'from' ModuleSpecifier ';'
  //        [no LineTerminator here] AssertClause ';'
  //    'export' ExportClause ('from' ModuleSpecifier)? ';'
  //    'export' ExportClause ('from' ModuleSpecifier [no LineTerminator here]
  //        AssertClause)? ';'
  //    'export' VariableStatement
  //    'export' Declaration
  //    'export' 'default' ... (handled in ParseExportDefault)
  //
  // ModuleExportName :
  //   StringLiteral

  Expect(Token::kExport);
  Statement* result = nullptr;
  ZonePtrList<const AstRawString> names(1, zone());
  Scanner::Location loc = scanner()->peek_location();
  switch (peek()) {
    case Token::kDefault:
      return ParseExportDefault();

    case Token::kMul:
      ParseExportStar();
      return factory()->EmptyStatement();

    case Token::kLeftBrace: {
      // There are two cases here:
      //
      // 'export' ExportClause ';'
      // and
      // 'export' ExportClause FromClause ';'
      //
      // In the first case, the exported identifiers in ExportClause must
      // not be reserved words, while in the latter they may be. We
      // pass in a location that gets filled with the first reserved word
      // encountered, and then throw a SyntaxError if we are in the
      // non-FromClause case.
      Scanner::Location reserved_loc = Scanner::Location::invalid();
      Scanner::Location string_literal_local_name_loc =
          Scanner::Location::invalid();
      ZoneChunkList<ExportClauseData>* export_data =
          ParseExportClause(&reserved_loc, &string_literal_local_name_loc);
      if (CheckContextualKeyword(ast_value_factory()->from_string())) {
        Scanner::Location specifier_loc = scanner()->peek_location();
        const AstRawString* module_specifier = ParseModuleSpecifier();
        const ImportAttributes* import_attributes =
            ParseImportWithOrAssertClause();
        ExpectSemicolon();

        if (export_data->empty()) {
          module()->AddEmptyImport(module_specifier, import_attributes,
                                   specifier_loc, zone());
        } else {
          for (const ExportClauseData& data : *export_data) {
            module()->AddExport(data.local_name, data.export_name,
                                module_specifier, import_attributes,
                                data.location, specifier_loc, zone());
          }
        }
      } else {
        if (reserved_loc.IsValid()) {
          // No FromClause, so reserved words are invalid in ExportClause.
          ReportMessageAt(reserved_loc, MessageTemplate::kUnexpectedReserved);
          return nullptr;
        } else if (string_literal_local_name_loc.IsValid()) {
          ReportMessageAt(string_literal_local_name_loc,
                          MessageTemplate::kModuleExportNameWithoutFromClause);
          return nullptr;
        }

        ExpectSemicolon();

        for (const ExportClauseData& data : *export_data) {
          module()->AddExport(data.local_name, data.export_name, data.location,
                              zone());
        }
      }
      return factory()->EmptyStatement();
    }

    case Token::kFunction:
      result = ParseHoistableDeclaration(&names, false);
      break;

    case Token::kClass:
      Consume(Token::kClass);
      result = ParseClassDeclaration(&names, false);
      break;

    case Token::kVar:
    case Token::kLet:
    case Token::kConst:
      result = ParseVariableStatement(kStatementListItem, &names);
      break;

    case Token::kAsync:
      Consume(Token::kAsync);
      if (peek() == Token::kFunction &&
          !scanner()->HasLineTerminatorBeforeNext()) {
        result = ParseAsyncFunctionDeclaration(&names, false);
        break;
      }
      [[fallthrough]];

    default:
      ReportUnexpectedToken(scanner()->current_token());
      return nullptr;
  }
  loc.end_pos = scanner()->location().end_pos;

  SourceTextModuleDescriptor* descriptor = module();
  for (const AstRawString* name : names) {
    descriptor->AddExport(name, name, loc, zone());
  }

  return result;
}

void Parser::DeclareUnboundVariable(const AstRawString* name, VariableMode mode,
                                    InitializationFlag init, int pos) {
  bool was_added;
  Variable* var = DeclareVariable(name, NORMAL_VARIABLE, mode, init, scope(),
                                  &was_added, pos, end_position());
  // The variable will be added to the declarations list, but since we are not
  // binding it to anything, we can simply ignore it here.
  USE(var);
}

VariableProxy* Parser::DeclareBoundVariable(const AstRawString* name,
                                            VariableMode mode, int pos) {
  DCHECK_NOT_NULL(name);
  VariableProxy* proxy =
      factory()->NewVariableProxy(name, NORMAL_VARIABLE, position());
  bool was_added;
  Variable* var = DeclareVariable(name, NORMAL_VARIABLE, mode,
                                  Variable::DefaultInitializationFlag(mode),
                                  scope(), &was_added, pos, end_position());
  proxy->BindTo(var);
  return proxy;
}

void Parser::DeclareAndBindVariable(VariableProxy* proxy, VariableKind kind,
                                    VariableMode mode, Scope* scope,
                                    bool* was_added, int initializer_position) {
  Variable* var = DeclareVariable(
      proxy->raw_name(), kind, mode, Variable::DefaultInitializationFlag(mode),
      scope, was_added, proxy->position(), kNoSourcePosition);
  var->set_initializer_position(initializer_position);
  proxy->BindTo(var);
}

Variable* Parser::DeclareVariable(const AstRawString* name, VariableKind kind,
                                  VariableMode mode, InitializationFlag init,
                                  Scope* scope, bool* was_added, int begin,
                                  int end) {
  Declaration* declaration;
  if (mode == VariableMode::kVar && !scope->is_declaration_scope()) {
    DCHECK(scope->is_block_scope() || scope->is_with_scope());
    declaration = factory()->NewNestedVariableDeclaration(scope, begin);
  } else {
    declaration = factory()->NewVariableDeclaration(begin);
  }
  Declare(declaration, name, kind, mode, init, scope, was_added, begin, end);
  return declaration->var();
}

void Parser::Declare(Declaration* declaration, const AstRawString* name,
                     VariableKind variable_kind, VariableMode mode,
                     InitializationFlag init, Scope* scope, bool* was_added,
                     int var_begin_pos, int var_end_pos) {
  bool local_ok = true;
  bool sloppy_mode_block_scope_function_redefinition = false;
  scope->DeclareVariable(
      declaration, name, var_begin_pos, mode, variable_kind, init, was_added,
      &sloppy_mode_block_scope_function_redefinition, &local_ok);
  if (!local_ok) {
    // If we only have the start position of a proxy, we can't highlight the
    // whole variable name.  Pretend its length is 1 so that we highlight at
    // least the first character.
    Scanner::Location loc(var_begin_pos, var_end_pos != kNoSourcePosition
                                             ? var_end_pos
                                             : var_begin_pos + 1);
    if (variable_kind == PARAMETER_VARIABLE) {
      ReportMessageAt(loc, MessageTemplate::kParamDupe);
    } else {
      ReportMessageAt(loc, MessageTemplate::kVarRedeclaration,
                      declaration->var()->raw_name());
    }
  } else if (sloppy_mode_block_scope_function_redefinition) {
    ++use_counts_[v8::Isolate::kSloppyModeBlockScopedFunctionRedefinition];
  }
}

Statement* Parser::BuildInitializationBlock(
    DeclarationParsingResult* parsing_result) {
  ScopedPtrList<Statement> statements(pointer_buffer());
  for (const auto& declaration : parsing_result->declarations) {
    if (!declaration.initializer) continue;
    InitializeVariables(&statements, parsing_result->descriptor.kind,
                        &declaration);
  }
  return factory()->NewBlock(true, statements);
}

Statement* Parser::DeclareFunction(const AstRawString* variable_name,
                                   FunctionLiteral* function, VariableMode mode,
                                   VariableKind kind, int beg_pos, int end_pos,
                                   ZonePtrList<const AstRawString>* names) {
  Declaration* declaration =
      factory()->NewFunctionDeclaration(function, beg_pos);
  bool was_added;
  Declare(declaration, variable_name, kind, mode, kCreatedInitialized, scope(),
          &was_added, beg_pos);
  if (info()->flags().coverage_enabled()) {
    // Force the function to be allocated when collecting source coverage, so
    // that even dead functions get source coverage data.
    declaration->var()->set_is_used();
  }
  if (names) names->Add(variable_name, zone());
  if (kind == SLOPPY_BLOCK_FUNCTION_VARIABLE) {
    Token::Value init =
        loop_nesting_depth() > 0 ? Token::kAssign : Token::kInit;
    SloppyBlockFunctionStatement* statement =
        factory()->NewSloppyBlockFunctionStatement(end_pos, declaration->var(),
                                                   init);
    GetDeclarationScope()->DeclareSloppyBlockFunction(statement);
    return statement;
  }
  return factory()->EmptyStatement();
}

Statement* Parser::DeclareClass(const AstRawString* variable_name,
                                Expression* value,
                                ZonePtrList<const AstRawString>* names,
                                int class_token_pos, int end_pos) {
  VariableProxy* proxy =
      DeclareBoundVariable(variable_name, VariableMode::kLet, class_token_pos);
  proxy->var()->set_initializer_position(end_pos);
  if (names) names->Add(variable_name, zone());

  Assignment* assignment =
      factory()->NewAssignment(Token::kInit, proxy, value, class_token_pos);
  return IgnoreCompletion(
      factory()->NewExpressionStatement(assignment, kNoSourcePosition));
}

Statement* Parser::DeclareNative(const AstRawString* name, int pos) {
  // Make sure that the function containing the native declaration
  // isn't lazily compiled. The extension structures are only
  // accessible while parsing the first time not when reparsing
  // because of lazy compilation.
  GetClosureScope()->ForceEagerCompilation();

  // TODO(1240846): It's weird that native function declarations are
  // introduced dynamically when we meet their declarations, whereas
  // other functions are set up when entering the surrounding scope.
  VariableProxy* proxy = DeclareBoundVariable(name, VariableMode::kVar, pos);
  NativeFunctionLiteral* lit =
      factory()->NewNativeFunctionLiteral(name, extension(), kNoSourcePosition);
  return factory()->NewExpressionStatement(
      factory()->NewAssignment(Token::kInit, proxy, lit, kNoSourcePosition),
      pos);
}

Block* Parser::IgnoreCompletion(Statement* statement) {
  Block* block = factory()->NewBlock(1, true);
  block->statements()->Add(statement, zone());
  return block;
}

Statement* Parser::RewriteSwitchStatement(SwitchStatement* switch_statement,
                                          Scope* scope) {
  // In order to get the CaseClauses to execute in their own lexical scope,
  // but without requiring downstream code to have special scope handling
  // code for switch statements, desugar into blocks as follows:
  // {  // To group the statements--harmless to evaluate Expression in scope
  //   .tag_variable = Expression;
  //   {  // To give CaseClauses a scope
  //     switch (.tag_variable) { CaseClause* }
  //   }
  // }
  DCHECK_NOT_NULL(scope);
  DCHECK(scope->is_block_scope());
  DCHECK_GE(switch_statement->position(), scope->start_position());
  DCHECK_LT(switch_statement->position(), scope->end_position());

  Block* switch_block = factory()->NewBlock(2, false);

  Expression* tag = switch_statement->tag();
  Variable* tag_variable =
      NewTemporary(ast_value_factory()->dot_switch_tag_string());
  Assignment* tag_assign = factory()->NewAssignment(
      Token::kAssign, factory()->NewVariableProxy(tag_variable), tag,
      tag->position());
  // Wrap with IgnoreCompletion so the tag isn't returned as the completion
  // value, in case the switch statements don't have a value.
  Statement* tag_statement = IgnoreCompletion(
      factory()->NewExpressionStatement(tag_assign, kNoSourcePosition));
  switch_block->statements()->Add(tag_statement, zone());

  switch_statement->set_tag(factory()->NewVariableProxy(tag_variable));
  Block* cases_block = factory()->NewBlock(1, false);
  cases_block->statements()->Add(switch_statement, zone());
  cases_block->set_scope(scope);
  switch_block->statements()->Add(cases_block, zone());
  return switch_block;
}

void Parser::InitializeVariables(
    ScopedPtrList<Statement>* statements, VariableKind kind,
    const DeclarationParsingResult::Declaration* declaration) {
  if (has_error()) return;

  DCHECK_NOT_NULL(declaration->initializer);

  int pos = declaration->value_beg_pos;
  if (pos == kNoSourcePosition) {
    pos = declaration->initializer->position();
  }
  Assignment* assignment = factory()->NewAssignment(
      Token::kInit, declaration->pattern, declaration->initializer, pos);
  statements->Add(factory()->NewExpressionStatement(assignment, pos));
}

Block* Parser::RewriteCatchPattern(CatchInfo* catch_info) {
  DCHECK_NOT_NULL(catch_info->pattern);

  DeclarationParsingResult::Declaration decl(
      catch_info->pattern, factory()->NewVariableProxy(catch_info->variable));

  ScopedPtrList<Statement> init_statements(pointer_buffer());
  InitializeVariables(&init_statements, NORMAL_VARIABLE, &decl);
  return factory()->NewBlock(true, init_statements);
}

void Parser::ReportVarRedeclarationIn(const AstRawString* name, Scope* scope) {
  for (Declaration* decl : *scope->declarations()) {
    if (decl->var()->raw_name() == name) {
      int position = decl->position();
      Scanner::Location location =
          position == kNoSourcePosition
              ? Scanner::Location::invalid()
              : Scanner::Location(position, position + name->length());
      ReportMessageAt(location, MessageTemplate::kVarRedeclaration, name);
      return;
    }
  }
  UNREACHABLE();
}

Statement* Parser::RewriteTryStatement(Block* try_block, Block* catch_block,
                                       const SourceRange& catch_range,
                                       Block* finally_block,
                                       const SourceRange& finally_range,
                                       const CatchInfo& catch_info, int pos) {
  // Simplify the AST nodes by converting:
  //   'try B0 catch B1 finally B2'
  // to:
  //   'try { try B0 catch B1 } finally B2'

  if (catch_block != nullptr && finally_block != nullptr) {
    // If we have both, create an inner try/catch.
    TryCatchStatement* statement;
    statement = factory()->NewTryCatchStatement(try_block, catch_info.scope,
                                                catch_block, kNoSourcePosition);
    RecordTryCatchStatementSourceRange(statement, catch_range);

    try_block = factory()->NewBlock(1, false);
    try_block->statements()->Add(statement, zone());
    catch_block = nullptr;  // Clear to indicate it's been handled.
  }

  if (catch_block != nullptr) {
    DCHECK_NULL(finally_block);
    TryCatchStatement* stmt = factory()->NewTryCatchStatement(
        try_block, catch_info.scope, catch_block, pos);
    RecordTryCatchStatementSourceRange(stmt, catch_range);
    return stmt;
  } else {
    DCHECK_NOT_NULL(finally_block);
    TryFinallyStatement* stmt =
        factory()->NewTryFinallyStatement(try_block, finally_block, pos);
    RecordTryFinallyStatementSourceRange(stmt, finally_range);
    return stmt;
  }
}

void Parser::ParseGeneratorFunctionBody(int pos, FunctionKind kind,
                                        ScopedPtrList<Statement>* body) {
  // For ES6 Generators, we just prepend the initial yield.
  Expression* initial_yield = BuildInitialYield(pos, kind);
  body->Add(
      factory()->NewExpressionStatement(initial_yield, kNoSourcePosition));
  ParseStatementList(body, Token::kRightBrace);
}

void Parser::ParseAsyncGeneratorFunctionBody(int pos, FunctionKind kind,
                                             ScopedPtrList<Statement>* body) {
  DCHECK(IsAsyncGeneratorFunction(kind));

  Expression* initial_yield = BuildInitialYield(pos, kind);
  body->Add(
      factory()->NewExpressionStatement(initial_yield, kNoSourcePosition));
  ParseStatementList(body, Token::kRightBrace);
}

void Parser::DeclareFunctionNameVar(const AstRawString* function_name,
                                    FunctionSyntaxKind function_syntax_kind,
                                    DeclarationScope* function_scope) {
  if (function_syntax_kind == FunctionSyntaxKind::kNamedExpression &&
      function_scope->LookupLocal(function_name) == nullptr) {
    DCHECK_EQ(function_scope, scope());
    function_scope->DeclareFunctionVar(function_name);
  }
}

// Special case for legacy for
//
//    for (var x = initializer in enumerable) body
//
// An initialization block of the form
//
//    {
//      x = initializer;
//    }
//
// is returned in this case.  It has reserved space for two statements,
// so that (later on during parsing), the equivalent of
//
//   for (x in enumerable) body
//
// is added as a second statement to it.
Block* Parser::RewriteForVarInLegacy(const ForInfo& for_info) {
  const DeclarationParsingResult::Declaration& decl =
      for_info.parsing_result.declarations[0];
  if (!IsLexicalVariableMode(for_info.parsing_result.descriptor.mode) &&
      decl.initializer != nullptr && decl.pattern->IsVariableProxy()) {
    ++use_counts_[v8::Isolate::kForInInitializer];
    const AstRawString* name = decl.pattern->AsVariableProxy()->raw_name();
    VariableProxy* single_var = NewUnresolved(name);
    Block* init_block = factory()->NewBlock(2, true);
    init_block->statements()->Add(
        factory()->NewExpressionStatement(
            factory()->NewAssignment(Token::kAssign, single_var,
                                     decl.initializer, decl.value_beg_pos),
            kNoSourcePosition),
        zone());
    return init_block;
  }
  return nullptr;
}

// Rewrite a for-in/of statement of the form
//
//   for (let/const/var x in/of e) b
//
// into
//
//   {
//     var temp;
//     for (temp in/of e) {
//       let/const/var x = temp;
//       b;
//     }
//     let x;  // for TDZ
//   }
void Parser::DesugarBindingInForEachStatement(ForInfo* for_info,
                                              Block** body_block,
                                              Expression** each_variable) {
  DCHECK_EQ(1, for_info->parsing_result.declarations.size());
  DeclarationParsingResult::Declaration& decl =
      for_info->parsing_result.declarations[0];
  Variable* temp = NewTemporary(ast_value_factory()->dot_for_string());
  ScopedPtrList<Statement> each_initialization_statements(pointer_buffer());
  DCHECK_IMPLIES(!has_error(), decl.pattern != nullptr);
  decl.initializer = factory()->NewVariableProxy(temp, for_info->position);
  InitializeVariables(&each_initialization_statements, NORMAL_VARIABLE, &decl);

  *body_block = factory()->NewBlock(3, false);
  (*body_block)
      ->statements()
      ->Add(factory()->NewBlock(true, each_initialization_statements), zone());
  *each_variable = factory()->NewVariableProxy(temp, for_info->position);
}

// Create a TDZ for any lexically-bound names in for in/of statements.
Block* Parser::CreateForEachStatementTDZ(Block* init_block,
                                         const ForInfo& for_info) {
  if (IsLexicalVariableMode(for_info.parsing_result.descriptor.mode)) {
    DCHECK_NULL(init_block);

    init_block = factory()->NewBlock(1, false);

    for (const AstRawString* bound_name : for_info.bound_names) {
      // TODO(adamk): This needs to be some sort of special
      // INTERNAL variable that's invisible to the debugger
      // but visible to everything else.
      VariableProxy* tdz_proxy = DeclareBoundVariable(
          bound_name, VariableMode::kLet, kNoSourcePosition);
      tdz_proxy->var()->set_initializer_position(position());
    }
  }
  return init_block;
}

Statement* Parser::DesugarLexicalBindingsInForStatement(
    ForStatement* loop, Statement* init, Expression* cond, Statement* next,
    Statement* body, Scope* inner_scope, const ForInfo& for_info) {
  // ES6 13.7.4.8 specifies that on each loop iteration the let variables are
  // copied into a new environment.  Moreover, the "next" statement must be
  // evaluated not in the environment of the just completed iteration but in
  // that of the upcoming one.  We achieve this with the following desugaring.
  // Extra care is needed to preserve the completion value of the original loop.
  //
  // We are given a for statement of the form
  //
  //  labels: for (let/const x = i; cond; next) body
  //
  // and rewrite it as follows.  Here we write {{ ... }} for init-blocks, ie.,
  // blocks whose ignore_completion_value_ flag is set.
  //
  //  {
  //    let/const x = i;
  //    temp_x = x;
  //    first = 1;
  //    undefined;
  //    outer: for (;;) {
  //      let/const x = temp_x;
  //      {{ if (first == 1) {
  //           first = 0;
  //         } else {
  //           next;
  //         }
  //         flag = 1;
  //         if (!cond) break;
  //      }}
  //      labels: for (; flag == 1; flag = 0, temp_x = x) {
  //        body
  //      }
  //      {{ if (flag == 1)  // Body used break.
  //           break;
  //      }}
  //    }
  //  }

  DCHECK_GT(for_info.bound_names.length(), 0);
  ScopedPtrList<Variable> temps(pointer_buffer());

  Block* outer_block =
      factory()->NewBlock(for_info.bound_names.length() + 4, false);

  // Add statement: let/const x = i.
  outer_block->statements()->Add(init, zone());

  const AstRawString* temp_name = ast_value_factory()->dot_for_string();

  // For each lexical variable x:
  //   make statement: temp_x = x.
  for (const AstRawString* bound_name : for_info.bound_names) {
    VariableProxy* proxy = NewUnresolved(bound_name);
    Variable* temp = NewTemporary(temp_name);
    VariableProxy* temp_proxy = factory()->NewVariableProxy(temp);
    Assignment* assignment = factory()->NewAssignment(
        Token::kAssign, temp_proxy, proxy, kNoSourcePosition);
    Statement* assignment_statement =
        factory()->NewExpressionStatement(assignment, kNoSourcePosition);
    outer_block->statements()->Add(assignment_statement, zone());
    temps.Add(temp);
  }

  Variable* first = nullptr;
  // Make statement: first = 1.
  if (next) {
    first = NewTemporary(temp_name);
    VariableProxy* first_proxy = factory()->NewVariableProxy(first);
    Expression* const1 = factory()->NewSmiLiteral(1, kNoSourcePosition);
    Assignment* assignment = factory()->NewAssignment(
        Token::kAssign, first_proxy, const1, kNoSourcePosition);
    Statement* assignment_statement =
        factory()->NewExpressionStatement(assignment, kNoSourcePosition);
    outer_block->statements()->Add(assignment_statement, zone());
  }

  // make statement: undefined;
  outer_block->statements()->Add(
      factory()->NewExpressionStatement(
          factory()->NewUndefinedLiteral(kNoSourcePosition), kNoSourcePosition),
      zone());

  // Make statement: outer: for (;;)
  // Note that we don't actually create the label, or set this loop up as an
  // explicit break target, instead handing it directly to those nodes that
  // need to know about it. This should be safe because we don't run any code
  // in this function that looks up break targets.
  ForStatement* outer_loop = factory()->NewForStatement(kNoSourcePosition);
  outer_block->statements()->Add(outer_loop, zone());
  outer_block->set_scope(scope());

  Block* inner_block = factory()->NewBlock(3, false);
  {
    BlockState block_state(&scope_, inner_scope);

    Block* ignore_completion_block =
        factory()->NewBlock(for_info.bound_names.length() + 3, true);
    ScopedPtrList<Variable> inner_vars(pointer_buffer());
    // For each let variable x:
    //    make statement: let/const x = temp_x.
    for (int i = 0; i < for_info.bound_names.length(); i++) {
      VariableProxy* proxy = DeclareBoundVariable(
          for_info.bound_names[i], for_info.parsing_result.descriptor.mode,
          kNoSourcePosition);
      inner_vars.Add(proxy->var());
      VariableProxy* temp_proxy = factory()->NewVariableProxy(temps.at(i));
      Assignment* assignment = factory()->NewAssignment(
          Token::kInit, proxy, temp_proxy, kNoSourcePosition);
      Statement* assignment_statement =
          factory()->NewExpressionStatement(assignment, kNoSourcePosition);
      int declaration_pos = for_info.parsing_result.descriptor.declaration_pos;
      DCHECK_NE(declaration_pos, kNoSourcePosition);
      proxy->var()->set_initializer_position(declaration_pos);
      ignore_completion_block->statements()->Add(assignment_statement, zone());
    }

    // Make statement: if (first == 1) { first = 0; } else { next; }
    if (next) {
      DCHECK(first);
      Expression* compare = nullptr;
      // Make compare expression: first == 1.
      {
        Expression* const1 = factory()->NewSmiLiteral(1, kNoSourcePosition);
        VariableProxy* first_proxy = factory()->NewVariableProxy(first);
        compare = factory()->NewCompareOperation(Token::kEq, first_proxy,
                                                 const1, kNoSourcePosition);
      }
      Statement* clear_first = nullptr;
      // Make statement: first = 0.
      {
        VariableProxy* first_proxy = factory()->NewVariableProxy(first);
        Expression* const0 = factory()->NewSmiLiteral(0, kNoSourcePosition);
        Assignment* assignment = factory()->NewAssignment(
            Token::kAssign, first_proxy, const0, kNoSourcePosition);
        clear_first =
            factory()->NewExpressionStatement(assignment, kNoSourcePosition);
      }
      Statement* clear_first_or_next = factory()->NewIfStatement(
          compare, clear_first, next, kNoSourcePosition);
      ignore_completion_block->statements()->Add(clear_first_or_next, zone());
    }

    Variable* flag = NewTemporary(temp_name);
    // Make statement: flag = 1.
    {
      VariableProxy* flag_proxy = factory()->NewVariableProxy(flag);
      Expression* const1 = factory()->NewSmiLiteral(1, kNoSourcePosition);
      Assignment* assignment = factory()->NewAssignment(
          Token::kAssign, flag_proxy, const1, kNoSourcePosition);
      Statement* assignment_statement =
          factory()->NewExpressionStatement(assignment, kNoSourcePosition);
      ignore_completion_block->statements()->Add(assignment_statement, zone());
    }

    // Make statement: if (!cond) break.
    if (cond) {
      Statement* stop =
          factory()->NewBreakStatement(outer_loop, kNoSourcePosition);
      Statement* noop = factory()->EmptyStatement();
      ignore_completion_block->statements()->Add(
          factory()->NewIfStatement(cond, noop, stop, cond->position()),
          zone());
    }

    inner_block->statements()->Add(ignore_completion_block, zone());
    // Make cond expression for main loop: flag == 1.
    Expression* flag_cond = nullptr;
    {
      Expression* const1 = factory()->NewSmiLiteral(1, kNoSourcePosition);
      VariableProxy* flag_proxy = factory()->NewVariableProxy(flag);
      flag_cond = factory()->NewCompareOperation(Token::kEq, flag_proxy, const1,
                                                 kNoSourcePosition);
    }

    // Create chain of expressions "flag = 0, temp_x = x, ..."
    Statement* compound_next_statement = nullptr;
    {
      Expression* compound_next = nullptr;
      // Make expression: flag = 0.
      {
        VariableProxy* flag_proxy = factory()->NewVariableProxy(flag);
        Expression* const0 = factory()->NewSmiLiteral(0, kNoSourcePosition);
        compound_next = factory()->NewAssignment(Token::kAssign, flag_proxy,
                                                 const0, kNoSourcePosition);
      }

      // Make the comma-separated list of temp_x = x assignments.
      int inner_var_proxy_pos = scanner()->location().beg_pos;
      for (int i = 0; i < for_info.bound_names.length(); i++) {
        VariableProxy* temp_proxy = factory()->NewVariableProxy(temps.at(i));
        VariableProxy* proxy =
            factory()->NewVariableProxy(inner_vars.at(i), inner_var_proxy_pos);
        Assignment* assignment = factory()->NewAssignment(
            Token::kAssign, temp_proxy, proxy, kNoSourcePosition);
        compound_next = factory()->NewBinaryOperation(
            Token::kComma, compound_next, assignment, kNoSourcePosition);
      }

      compound_next_statement =
          factory()->NewExpressionStatement(compound_next, kNoSourcePosition);
    }

    // Make statement: labels: for (; flag == 1; flag = 0, temp_x = x)
    // Note that we re-use the original loop node, which retains its labels
    // and ensures that any break or continue statements in body point to
    // the right place.
    loop->Initialize(nullptr, flag_cond, compound_next_statement, body);
    inner_block->statements()->Add(loop, zone());

    // Make statement: {{if (flag == 1) break;}}
    {
      Expression* compare = nullptr;
      // Make compare expresion: flag == 1.
      {
        Expression* const1 = factory()->NewSmiLiteral(1, kNoSourcePosition);
        VariableProxy* flag_proxy = factory()->NewVariableProxy(flag);
        compare = factory()->NewCompareOperation(Token::kEq, flag_proxy, const1,
                                                 kNoSourcePosition);
      }
      Statement* stop =
          factory()->NewBreakStatement(outer_loop, kNoSourcePosition);
      Statement* empty = factory()->EmptyStatement();
      Statement* if_flag_break =
          factory()->NewIfStatement(compare, stop, empty, kNoSourcePosition);
      inner_block->statements()->Add(IgnoreCompletion(if_flag_break), zone());
    }

    inner_block->set_scope(inner_scope);
  }

  outer_loop->Initialize(nullptr, nullptr, nullptr, inner_block);

  return outer_block;
}

void ParserFormalParameters::ValidateDuplicate(Parser* parser) const {
  if (has_duplicate()) {
    parser->ReportMessageAt(duplicate_loc, MessageTemplate::kParamDupe);
  }
}
void ParserFormalParameters::ValidateStrictMode(Parser* parser) const {
  if (strict_error_loc.IsValid()) {
    parser->ReportMessageAt(strict_error_loc, strict_error_message);
  }
}

void Parser::AddArrowFunctionFormalParameters(
    ParserFormalParameters* parameters, Expression* expr, int end_pos) {
  // ArrowFunctionFormals ::
  //    Nary(Token::kComma, VariableProxy*, Tail)
  //    Binary(Token::kComma, NonTailArrowFunctionFormals, Tail)
  //    Tail
  // NonTailArrowFunctionFormals ::
  //    Binary(Token::kComma, NonTailArrowFunctionFormals, VariableProxy)
  //    VariableProxy
  // Tail ::
  //    VariableProxy
  //    Spread(VariableProxy)
  //
  // We need to visit the parameters in left-to-right order
  //

  // For the Nary case, we simply visit the parameters in a loop.
  if (expr->IsNaryOperation()) {
    NaryOperation* nary = expr->AsNaryOperation();
    // The classifier has already run, so we know that the expression is a valid
    // arrow function formals production.
    DCHECK_EQ(nary->op(), Token::kComma);
    // Each op position is the end position of the *previous* expr, with the
    // second (i.e. first "subsequent") op position being the end position of
    // the first child expression.
    Expression* next = nary->first();
    for (size_t i = 0; i < nary->subsequent_length(); ++i) {
      AddArrowFunctionFormalParameters(parameters, next,
                                       nary->subsequent_op_position(i));
      next = nary->subsequent(i);
    }
    AddArrowFunctionFormalParameters(parameters, next, end_pos);
    return;
  }

  // For the binary case, we recurse on the left-hand side of binary comma
  // expressions.
  if (expr->IsBinaryOperation()) {
    BinaryOperation* binop = expr->AsBinaryOperation();
    // The classifier has already run, so we know that the expression is a valid
    // arrow function formals production.
    DCHECK_EQ(binop->op(), Token::kComma);
    Expression* left = binop->left();
    Expression* right = binop->right();
    int comma_pos = binop->position();
    AddArrowFunctionFormalParameters(parameters, left, comma_pos);
    // LHS of comma expression should be unparenthesized.
    expr = right;
  }

  // Only the right-most expression may be a rest parameter.
  DCHECK(!parameters->has_rest);

  bool is_rest = expr->IsSpread();
  if (is_rest) {
    expr = expr->AsSpread()->expression();
    parameters->has_rest = true;
  }
  DCHECK_IMPLIES(parameters->is_simple, !is_rest);
  DCHECK_IMPLIES(parameters->is_simple, expr->IsVariableProxy());

  Expression* initializer = nullptr;
  if (expr->IsAssignment()) {
    Assignment* assignment = expr->AsAssignment();
    DCHECK(!assignment->IsCompoundAssignment());
    initializer = assignment->value();
    expr = assignment->target();
  }

  AddFormalParameter(parameters, expr, initializer, end_pos, is_rest);
}

void Parser::DeclareArrowFunctionFormalParameters(
    ParserFormalParameters* parameters, Expression* expr,
    const Scanner::Location& params_loc) {
  if (expr->IsEmptyParentheses() || has_error()) return;

  AddArrowFunctionFormalParameters(parameters, expr, params_loc.end_pos);

  if (parameters->arity > Code::kMaxArguments) {
    ReportMessageAt(params_loc, MessageTemplate::kMalformedArrowFunParamList);
    return;
  }

  DeclareFormalParameters(parameters);
  DCHECK_IMPLIES(parameters->is_simple,
                 parameters->scope->has_simple_parameters());
}

void Parser::ReindexArrowFunctionFormalParameters(
    ParserFormalParameters* parameters) {
  // Make space for the arrow function above the formal parameters.
  AstFunctionLiteralIdReindexer reindexer(stack_limit_, 1);
  for (auto p : parameters->params) {
    if (p->pattern != nullptr) reindexer.Reindex(p->pattern);
    if (p->initializer() != nullptr) {
      reindexer.Reindex(p->initializer());
    }
    if (reindexer.HasStackOverflow()) {
      set_stack_overflow();
      return;
    }
  }
}

void Parser::ReindexComputedMemberName(Expression* computed_name) {
  // Make space for the member initializer function above the computed property
  // name.
  AstFunctionLiteralIdReindexer reindexer(stack_limit_, 1);
  reindexer.Reindex(computed_name);
}

void Parser::PrepareGeneratorVariables() {
  // Calling a generator returns a generator object.  That object is stored
  // in a temporary variable, a definition that is used by "yield"
  // expressions.
  function_state_->scope()->DeclareGeneratorObjectVar(
      ast_value_factory()->dot_generator_object_string());
}

FunctionLiteral* Parser::ParseFunctionLiteral(
    const AstRawString* function_name, Scanner::Location function_name_location,
    FunctionNameValidity function_name_validity, FunctionKind kind,
    int function_token_pos, FunctionSyntaxKind function_syntax_kind,
    LanguageMode language_mode,
    ZonePtrList<const AstRawString>* arguments_for_wrapped_function) {
  // Function ::
  //   '(' FormalParameterList? ')' '{' FunctionBody '}'
  //
  // Getter ::
  //   '(' ')' '{' FunctionBody '}'
  //
  // Setter ::
  //   '(' PropertySetParameterList ')' '{' FunctionBody '}'

  bool is_wrapped = function_syntax_kind == FunctionSyntaxKind::kWrapped;
  DCHECK_EQ(is_wrapped, arguments_for_wrapped_function != nullptr);

  int pos = function_token_pos == kNoSourcePosition ? peek_position()
                                                    : function_token_pos;
  DCHECK_NE(kNoSourcePosition, pos);

  // Anonymous functions were passed either the empty symbol or a null
  // handle as the function name.  Remember if we were passed a non-empty
  // handle to decide whether to invoke function name inference.
  bool should_infer_name = function_name == nullptr;

  // We want a non-null handle as the function name by default. We will handle
  // the "function does not have a shared name" case later.
  if (should_infer_name) {
    function_name = ast_value_factory()->empty_string();
  }

  // This is true if we get here through CreateDynamicFunction.
  bool params_need_validation = parameters_end_pos_ != kNoSourcePosition;

  FunctionLiteral::EagerCompileHint eager_compile_hint =
      function_state_->next_function_is_likely_called() || is_wrapped ||
              params_need_validation ||
              (info()->flags().compile_hints_magic_enabled() &&
               scanner()->SawMagicCommentCompileHintsAll())
          ? FunctionLiteral::kShouldEagerCompile
          : default_eager_compile_hint();

  // Determine if the function can be parsed lazily. Lazy parsing is
  // different from lazy compilation; we need to parse more eagerly than we
  // compile.

  // We can only parse lazily if we also compile lazily. The heuristics for lazy
  // compilation are:
  // - It must not have been prohibited by the caller to Parse (some callers
  //   need a full AST).
  // - The outer scope must allow lazy compilation of inner functions.
  // - The function mustn't be a function expression with an open parenthesis
  //   before; we consider that a hint that the function will be called
  //   immediately, and it would be a waste of time to make it lazily
  //   compiled.
  // These are all things we can know at this point, without looking at the
  // function itself.

  // We separate between lazy parsing top level functions and lazy parsing inner
  // functions, because the latter needs to do more work. In particular, we need
  // to track unresolved variables to distinguish between these cases:
  // (function foo() {
  //   bar = function() { return 1; }
  //  })();
  // and
  // (function foo() {
  //   var a = 1;
  //   bar = function() { return a; }
  //  })();

  // Now foo will be parsed eagerly and compiled eagerly (optimization: assume
  // parenthesis before the function means that it will be called
  // immediately). bar can be parsed lazily, but we need to parse it in a mode
  // that tracks unresolved variables.
  DCHECK_IMPLIES(parse_lazily(), info()->flags().allow_lazy_compile());
  DCHECK_IMPLIES(parse_lazily(), has_error() || allow_lazy_);
  DCHECK_IMPLIES(parse_lazily(), extension() == nullptr);

  int compile_hint_position = peek_position();
  eager_compile_hint =
      GetEmbedderCompileHint(eager_compile_hint, compile_hint_position);

  const bool is_lazy =
      eager_compile_hint == FunctionLiteral::kShouldLazyCompile;
  const bool is_top_level = AllowsLazyParsingWithoutUnresolvedVariables();
  const bool is_eager_top_level_function = !is_lazy && is_top_level;

  RCS_SCOPE(runtime_call_stats_, RuntimeCallCounterId::kParseFunctionLiteral,
            RuntimeCallStats::kThreadSpecific);
  base::ElapsedTimer timer;
  if (V8_UNLIKELY(v8_flags.log_function_events)) timer.Start();

  // Determine whether we can lazy parse the inner function. Lazy compilation
  // has to be enabled, which is either forced by overall parse flags or via a
  // ParsingModeScope.
  const bool can_preparse = parse_lazily();

  // Determine whether we can post any parallel compile tasks. Preparsing must
  // be possible, there has to be a dispatcher, and the character stream must be
  // cloneable.
  const bool can_post_parallel_task =
      can_preparse && info()->dispatcher() &&
      scanner()->stream()->can_be_cloned_for_parallel_access();

  // If parallel compile tasks are enabled, and this isn't a re-parse, enable
  // parallel compile for the subset of functions as defined by flags.
  bool should_post_parallel_task =
      can_post_parallel_task && !flags().is_reparse() &&
      ((is_eager_top_level_function &&
        flags().post_parallel_compile_tasks_for_eager_toplevel()) ||
       (is_lazy && flags().post_parallel_compile_tasks_for_lazy()));

  // Determine whether we should lazy parse the inner function. This will be
  // when either the function is lazy by inspection, or when we force it to be
  // preparsed now so that we can then post a parallel full parse & compile task
  // for it.
  const bool should_preparse =
      can_preparse && (is_lazy || should_post_parallel_task);

  ScopedPtrList<Statement> body(pointer_buffer());
  int expected_property_count = 0;
  int suspend_count = -1;
  int num_parameters = -1;
  int function_length = -1;
  bool has_duplicate_parameters = false;
  int function_literal_id = GetNextInfoId();
  ProducedPreparseData* produced_preparse_data = nullptr;

  // Inner functions will be parsed using a temporary Zone. After parsing, we
  // will migrate unresolved variable into a Scope in the main Zone.
  Zone* parse_zone = should_preparse ? &preparser_zone_ : zone();
  // This Scope lives in the main zone. We'll migrate data into that zone later.
  DeclarationScope* scope = NewFunctionScope(kind, parse_zone);
  SetLanguageMode(scope, language_mode);
  if (is_wrapped) {
    scope->set_is_wrapped_function();
  }
#ifdef DEBUG
  scope->SetScopeName(function_name);
#endif

  if (!is_wrapped && V8_UNLIKELY(!Check(Token::kLeftParen))) {
    ReportUnexpectedToken(Next());
    return nullptr;
  }
  scope->set_start_position(position());

  // Eager or lazy parse? If is_lazy_top_level_function, we'll parse
  // lazily. We'll call SkipFunction, which may decide to
  // abort lazy parsing if it suspects that wasn't a good idea. If so (in
  // which case the parser is expected to have backtracked), or if we didn't
  // try to lazy parse in the first place, we'll have to parse eagerly.
  bool did_preparse_successfully =
      should_preparse &&
      SkipFunction(function_name, kind, function_syntax_kind, scope,
                   &num_parameters, &function_length, &produced_preparse_data);

  if (!did_preparse_successfully) {
    // If skipping aborted, it rewound the scanner until before the lparen.
    // Consume it in that case.
    if (should_preparse) Consume(Token::kLeftParen);
    should_post_parallel_task = false;
    ParseFunction(&body, function_name, pos, kind, function_syntax_kind, scope,
                  &num_parameters, &function_length, &has_duplicate_parameters,
                  &expected_property_count, &suspend_count,
                  arguments_for_wrapped_function);
  }

  if (V8_UNLIKELY(v8_flags.log_function_events)) {
    double ms = timer.Elapsed().InMillisecondsF();
    const char* event_name =
        should_preparse
            ? (is_top_level ? "preparse-no-resolution" : "preparse-resolution")
            : "full-parse";
    v8_file_logger_->FunctionEvent(
        event_name, flags().script_id(), ms, scope->start_position(),
        scope->end_position(),
        reinterpret_cast<const char*>(function_name->raw_data()),
        function_name->byte_length(), function_name->is_one_byte());
  }
#ifdef V8_RUNTIME_CALL_STATS
  if (did_preparse_successfully && runtime_call_stats_ &&
      V8_UNLIKELY(TracingFlags::is_runtime_stats_enabled())) {
    runtime_call_stats_->CorrectCurrentCounterId(
        RuntimeCallCounterId::kPreParseWithVariableResolution,
        RuntimeCallStats::kThreadSpecific);
  }
#endif  // V8_RUNTIME_CALL_STATS

  // Validate function name. We can do this only after parsing the function,
  // since the function can declare itself strict.
  language_mode = scope->language_mode();
  CheckFunctionName(language_mode, function_name, function_name_validity,
                    function_name_location);

  if (is_strict(language_mode)) {
    CheckStrictOctalLiteral(scope->start_position(), scope->end_position());
  }

  FunctionLiteral::ParameterFlag duplicate_parameters =
      has_duplicate_parameters ? FunctionLiteral::kHasDuplicateParameters
                               : FunctionLiteral::kNoDuplicateParameters;

  // Note that the FunctionLiteral needs to be created in the main Zone again.
  FunctionLiteral* function_literal = factory()->NewFunctionLiteral(
      function_name, scope, body, expected_property_count, num_parameters,
      function_length, duplicate_parameters, function_syntax_kind,
      eager_compile_hint, pos, true, function_literal_id,
      produced_preparse_data);
  function_literal->set_function_token_position(function_token_pos);
  function_literal->set_suspend_count(suspend_count);

  RecordFunctionLiteralSourceRange(function_literal);

  if (should_post_parallel_task && !has_error()) {
    function_literal->set_should_parallel_compile();
  }

  if (should_infer_name) {
    fni_.AddFunction(function_literal);
  }
  return function_literal;
}

bool Parser::SkipFunction(const AstRawString* function_name, FunctionKind kind,
                          FunctionSyntaxKind function_syntax_kind,
                          DeclarationScope* function_scope, int* num_parameters,
                          int* function_length,
                          ProducedPreparseData** produced_preparse_data) {
  FunctionState function_state(&function_state_, &scope_, function_scope);
  function_scope->set_zone(&preparser_zone_);

  DCHECK_NE(kNoSourcePosition, function_scope->start_position());
  DCHECK_EQ(kNoSourcePosition, parameters_end_pos_);

  DCHECK_IMPLIES(IsArrowFunction(kind),
                 scanner()->current_token() == Token::kArrow);

  // FIXME(marja): There are 2 ways to skip functions now. Unify them.
  if (consumed_preparse_data_) {
    int end_position;
    LanguageMode language_mode;
    int num_inner_infos;
    bool uses_super_property;
    if (stack_overflow()) return true;
    {
      UnparkedScopeIfOnBackground unparked_scope(local_isolate_);
      *produced_preparse_data =
          consumed_preparse_data_->GetDataForSkippableFunction(
              main_zone(), function_scope->start_position(), &end_position,
              num_parameters, function_length, &num_inner_infos,
              &uses_super_property, &language_mode);
    }

    function_scope->outer_scope()->SetMustUsePreparseData();
    function_scope->set_is_skipped_function(true);
    function_scope->set_end_position(end_position);
    scanner()->SeekForward(end_position - 1);
    Expect(Token::kRightBrace);
    SetLanguageMode(function_scope, language_mode);
    if (uses_super_property) {
      function_scope->RecordSuperPropertyUsage();
    }
    SkipInfos(num_inner_infos);
    function_scope->ResetAfterPreparsing(ast_value_factory_, false);
    return true;
  }

  Scanner::BookmarkScope bookmark(scanner());
  bookmark.Set(function_scope->start_position());

  UnresolvedList::Iterator unresolved_private_tail;
  PrivateNameScopeIterator private_name_scope_iter(function_scope);
  if (!private_name_scope_iter.Done()) {
    unresolved_private_tail =
        private_name_scope_iter.GetScope()->GetUnresolvedPrivateNameTail();
  }

  // With no cached data, we partially parse the function, without building an
  // AST. This gathers the data needed to build a lazy function.
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.compile"), "V8.PreParse");

  PreParser::PreParseResult result = reusable_preparser()->PreParseFunction(
      function_name, kind, function_syntax_kind, function_scope, use_counts_,
      produced_preparse_data);

  if (result == PreParser::kPreParseStackOverflow) {
    // Propagate stack overflow.
    set_stack_overflow();
  } else if (pending_error_handler()->has_error_unidentifiable_by_preparser()) {
    // Make sure we don't re-preparse inner functions of the aborted function.
    // The error might be in an inner function.
    allow_lazy_ = false;
    mode_ = PARSE_EAGERLY;
    DCHECK(!pending_error_handler()->stack_overflow());
    // If we encounter an error that the preparser can not identify we reset to
    // the state before preparsing. The caller may then fully parse the function
    // to identify the actual error.
    bookmark.Apply();
    if (!private_name_scope_iter.Done()) {
      private_name_scope_iter.GetScope()->ResetUnresolvedPrivateNameTail(
          unresolved_private_tail);
    }
    function_scope->ResetAfterPreparsing(ast_value_factory_, true);
    pending_error_handler()->clear_unidentifiable_error();
    return false;
  } else if (pending_error_handler()->has_pending_error()) {
    DCHECK(!pending_error_handler()->stack_overflow());
    DCHECK(has_error());
  } else {
    DCHECK(!pending_error_handler()->stack_overflow());
    set_allow_eval_cache(reusable_preparser()->allow_eval_cache());

    PreParserLogger* logger = reusable_preparser()->logger();
    function_scope->set_end_position(logger->end());
    Expect(Token::kRightBrace);
    total_preparse_skipped_ +=
        function_scope->end_position() - function_scope->start_position();
    *num_parameters = logger->num_parameters();
    *function_length = logger->function_length();
    SkipInfos(logger->num_inner_infos());
    if (!private_name_scope_iter.Done()) {
      private_name_scope_iter.GetScope()->MigrateUnresolvedPrivateNameTail(
          factory(), unresolved_private_tail);
    }
    function_scope->AnalyzePartially(this, factory(), MaybeParsingArrowhead());
  }

  return true;
}

Block* Parser::BuildParameterInitializationBlock(
    const ParserFormalParameters& parameters) {
  DCHECK(!parameters.is_simple);
  DCHECK(scope()->is_function_scope());
  DCHECK_EQ(scope(), parameters.scope);
  ScopedPtrList<Statement> init_statements(pointer_buffer());
  int index = 0;
  for (auto parameter : parameters.params) {
    Expression* initial_value =
        factory()->NewVariableProxy(parameters.scope->parameter(index));
    if (parameter->initializer() != nullptr) {
      // IS_UNDEFINED($param) ? initializer : $param

      auto condition = factory()->NewCompareOperation(
          Token::kEqStrict,
          factory()->NewVariableProxy(parameters.scope->parameter(index)),
          factory()->NewUndefinedLiteral(kNoSourcePosition), kNoSourcePosition);
      initial_value =
          factory()->NewConditional(condition, parameter->initializer(),
                                    initial_value, kNoSourcePosition);
    }

    BlockState block_state(&scope_, scope()->AsDeclarationScope());
    DeclarationParsingResult::Declaration decl(parameter->pattern,
                                               initial_value);
    InitializeVariables(&init_statements, PARAMETER_VARIABLE, &decl);

    ++index;
  }
  return factory()->NewParameterInitializationBlock(init_statements);
}

Expression* Parser::BuildInitialYield(int pos, FunctionKind kind) {
  Expression* yield_result = factory()->NewVariableProxy(
      function_state_->scope()->generator_object_var());
  // The position of the yield is important for reporting the exception
  // caused by calling the .throw method on a generator suspended at the
  // initial yield (i.e. right after generator instantiation).
  function_state_->AddSuspend();
  return factory()->NewYield(yield_result, scope()->start_position(),
                             Suspend::kOnExceptionThrow);
}

void Parser::ParseFunction(
    ScopedPtrList<Statement>* body, const AstRawString* function_name, int pos,
    FunctionKind kind, FunctionSyntaxKind function_syntax_kind,
    DeclarationScope* function_scope, int* num_parameters, int* function_length,
    bool* has_duplicate_parameters, int* expected_property_count,
    int* suspend_count,
    ZonePtrList<const AstRawString>* arguments_for_wrapped_function) {
  FunctionParsingScope function_parsing_scope(this);
  ParsingModeScope mode(this, allow_lazy_ ? PARSE_LAZILY : PARSE_EAGERLY);

  FunctionState function_state(&function_state_, &scope_, function_scope);

  bool is_wrapped = function_syntax_kind == FunctionSyntaxKind::kWrapped;

  int expected_parameters_end_pos = parameters_end_pos_;
  if (expected_parameters_end_pos != kNoSourcePosition) {
    // This is the first function encountered in a CreateDynamicFunction eval.
    parameters_end_pos_ = kNoSourcePosition;
    // The function name should have been ignored, giving us the empty string
    // here.
    DCHECK_EQ(function_name, ast_value_factory()->empty_string());
  }

  ParserFormalParameters formals(function_scope);

  {
    ParameterDeclarationParsingScope formals_scope(this);
    if (is_wrapped) {
      // For a function implicitly wrapped in function header and footer, the
      // function arguments are provided separately to the source, and are
      // declared directly here.
      for (const AstRawString* arg : *arguments_for_wrapped_function) {
        const bool is_rest = false;
        Expression* argument = ExpressionFromIdentifier(arg, kNoSourcePosition);
        AddFormalParameter(&formals, argument, NullExpression(),
                           kNoSourcePosition, is_rest);
      }
      DCHECK_EQ(arguments_for_wrapped_function->length(),
                formals.num_parameters());
      DeclareFormalParameters(&formals);
    } else {
      // For a regular function, the function arguments are parsed from source.
      DCHECK_NULL(arguments_for_wrapped_function);
      ParseFormalParameterList(&formals);
      if (expected_parameters_end_pos != kNoSourcePosition) {
        // Check for '(' or ')' shenanigans in the parameter string for dynamic
        // functions.
        int position = peek_position();
        if (position < expected_parameters_end_pos) {
          ReportMessageAt(Scanner::Location(position, position + 1),
                          MessageTemplate::kArgStringTerminatesParametersEarly);
          return;
        } else if (position > expected_parameters_end_pos) {
          ReportMessageAt(Scanner::Location(expected_parameters_end_pos - 2,
                                            expected_parameters_end_pos),
                          MessageTemplate::kUnexpectedEndOfArgString);
          return;
        }
      }
      Expect(Token::kRightParen);
      int formals_end_position = end_position();

      CheckArityRestrictions(formals.arity, kind, formals.has_rest,
                             function_scope->start_position(),
                             formals_end_position);
      Expect(Token::kLeftBrace);
    }
    formals.duplicate_loc = formals_scope.duplicate_location();
  }

  *num_parameters = formals.num_parameters();
  *function_length = formals.function_length;

  AcceptINScope scope(this, true);
  ParseFunctionBody(body, function_name, pos, formals, kind,
                    function_syntax_kind, FunctionBodyType::kBlock);

  *has_duplicate_parameters = formals.has_duplicate();

  *expected_property_count = function_state.expected_property_count();
  *suspend_count = function_state.suspend_count();
}

void Parser::DeclareClassVariable(ClassScope* scope, const AstRawString* name,
                                  ClassInfo* class_info, int class_token_pos) {
#ifdef DEBUG
  scope->SetScopeName(name);
#endif

  DCHECK_IMPLIES(IsEmptyIdentifier(name), class_info->is_anonymous);
  // Declare a special class variable for anonymous classes with the dot
  // if we need to save it for static private method access.
  Variable* class_variable =
      scope->DeclareClassVariable(ast_value_factory(), name, class_token_pos);
  Declaration* declaration = factory()->NewVariableDeclaration(class_token_pos);
  scope->declarations()->Add(declaration);
  declaration->set_var(class_variable);
}

VariableProxy* Parser::CreateSyntheticContextVariableProxy(
    ClassScope* scope, ClassInfo* class_info, const AstRawString* name,
    bool is_static) {
  if (scope->is_reparsed()) {
    DeclarationScope* declaration_scope =
        is_static ? class_info->static_elements_scope
                  : class_info->instance_members_scope;
    return declaration_scope->NewUnresolved(factory()->ast_node_factory(), name,
                                            position());
  }
  VariableProxy* proxy =
      DeclareBoundVariable(name, VariableMode::kConst, kNoSourcePosition);
  proxy->var()->ForceContextAllocation();
  return proxy;
}

VariableProxy* Parser::CreatePrivateNameVariable(ClassScope* scope,
                                                 VariableMode mode,
                                                 IsStaticFlag is_static_flag,
                                                 const AstRawString* name) {
  DCHECK_NOT_NULL(name);
  int begin = position();
  int end = end_position();
  bool was_added = false;
  DCHECK(IsImmutableLexicalOrPrivateVariableMode(mode));
  Variable* var =
      scope->DeclarePrivateName(name, mode, is_static_flag, &was_added);
  if (!was_added) {
    Scanner::Location loc(begin, end);
    ReportMessageAt(loc, MessageTemplate::kVarRedeclaration, var->raw_name());
  }
  return factory()->NewVariableProxy(var, begin);
}

void Parser::AddInstanceFieldOrStaticElement(ClassLiteralProperty* property,
                                             ClassInfo* class_info,
                                             bool is_static) {
  if (is_static) {
    class_info->static_elements->Add(
        factory()->NewClassLiteralStaticElement(property), zone());
    return;
  }
  class_info->instance_fields->Add(property, zone());
}

void Parser::DeclarePublicClassField(ClassScope* scope,
                                     ClassLiteralProperty* property,
                                     bool is_static, bool is_computed_name,
                                     ClassInfo* class_info) {
  AddInstanceFieldOrStaticElement(property, class_info, is_static);

  if (is_computed_name) {
    // We create a synthetic variable name here so that scope
    // analysis doesn't dedupe the vars.
    const AstRawString* name = ClassFieldVariableName(
        ast_value_factory(), class_info->computed_field_count);
    VariableProxy* proxy =
        CreateSyntheticContextVariableProxy(scope, class_info, name, is_static);
    property->set_computed_name_proxy(proxy);
    class_info->public_members->Add(property, zone());
  }
}

void Parser::DeclarePrivateClassMember(ClassScope* scope,
                                       const AstRawString* property_name,
                                       ClassLiteralProperty* property,
                                       ClassLiteralProperty::Kind kind,
                                       bool is_static, ClassInfo* class_info) {
  if (kind == ClassLiteralProperty::Kind::FIELD ||
      kind == ClassLiteralProperty::Kind::AUTO_ACCESSOR) {
    AddInstanceFieldOrStaticElement(property, class_info, is_static);
  }
  class_info->private_members->Add(property, zone());

  VariableProxy* proxy;
  if (scope->is_reparsed()) {
    PrivateNameScopeIterator private_name_scope_iter(scope);
    proxy = ExpressionFromPrivateName(&private_name_scope_iter, property_name,
                                      position());
  } else {
    proxy = CreatePrivateNameVariable(
        scope, GetVariableMode(kind),
        is_static ? IsStaticFlag::kStatic : IsStaticFlag::kNotStatic,
        property_name);
    int pos = property->value()->position();
    if (pos == kNoSourcePosition) {
      pos = property->key()->position();
    }
    proxy->var()->set_initializer_position(pos);
  }
  property->SetPrivateNameProxy(proxy);
}

// This method declares a property of the given class.  It updates the
// following fields of class_info, as appropriate:
//   - constructor
//   - properties
void Parser::DeclarePublicClassMethod(const AstRawString* class_name,
                                      ClassLiteralProperty* property,
                                      bool is_constructor,
                                      ClassInfo* class_info) {
  if (is_constructor) {
    DCHECK(!class_info->constructor);
    class_info->constructor = property->value()->AsFunctionLiteral();
    DCHECK_NOT_NULL(class_info->constructor);
    class_info->constructor->set_raw_name(
        class_name != nullptr ? ast_value_factory()->NewConsString(class_name)
                              : nullptr);
    return;
  }

  class_info->public_members->Add(property, zone());
}

void Parser::AddClassStaticBlock(Block* block, ClassInfo* class_info) {
  DCHECK(class_info->has_static_elements());
  class_info->static_elements->Add(
      factory()->NewClassLiteralStaticElement(block), zone());
}

FunctionLiteral* Parser::CreateInitializerFunction(
    const AstRawString* class_name, DeclarationScope* scope,
    int function_literal_id, Statement* initializer_stmt) {
  DCHECK(IsClassMembersInitializerFunction(scope->function_kind()));
  // function() { .. class fields initializer .. }
  ScopedPtrList<Statement> statements(pointer_buffer());
  statements.Add(initializer_stmt);
  FunctionLiteral* result = factory()->NewFunctionLiteral(
      class_name, scope, statements, 0, 0, 0,
      FunctionLiteral::kNoDuplicateParameters,
      FunctionSyntaxKind::kAccessorOrMethod,
      FunctionLiteral::kShouldEagerCompile, scope->start_position(), false,
      function_literal_id);
#ifdef DEBUG
  scope->SetScopeName(class_name);
#endif
  RecordFunctionLiteralSourceRange(result);

  return result;
}

FunctionLiteral* Parser::CreateStaticElementsInitializer(
    const AstRawString* name, ClassInfo* class_info) {
  return CreateInitializerFunction(
      name, class_info->static_elements_scope,
      class_info->static_elements_function_id,
      factory()->NewInitializeClassStaticElementsStatement(
          class_info->static_elements, kNoSourcePosition));
}

FunctionLiteral* Parser::CreateInstanceMembersInitializer(
    const AstRawString* name, ClassInfo* class_info) {
  return CreateInitializerFunction(
      name, class_info->instance_members_scope,
      class_info->instance_members_function_id,
      factory()->NewInitializeClassMembersStatement(class_info->instance_fields,
                                                    kNoSourcePosition));
}

// This method generates a ClassLiteral AST node.
// It uses the following fields of class_info:
//   - constructor (if missing, it updates it with a default constructor)
//   - proxy
//   - extends
//   - properties
//   - has_static_computed_names
Expression* Parser::RewriteClassLiteral(ClassScope* block_scope,
                                        const AstRawString* name,
                                        ClassInfo* class_info, int pos) {
  DCHECK_NOT_NULL(block_scope);
  DCHECK_EQ(block_scope->scope_type(), CLASS_SCOPE);
  DCHECK_EQ(block_scope->language_mode(), LanguageMode::kStrict);

  bool has_extends = class_info->extends != nullptr;
  bool has_default_constructor = class_info->constructor == nullptr;
  int end_pos = block_scope->end_position();
  if (has_default_constructor) {
    class_info->constructor = DefaultConstructor(name, has_extends, pos);
  }

  if (!IsEmptyIdentifier(name)) {
    DCHECK_NOT_NULL(block_scope->class_variable());
    block_scope->class_variable()->set_initializer_position(end_pos);
  }

  FunctionLiteral* static_initializer = nullptr;
  if (class_info->has_static_elements()) {
    st
```