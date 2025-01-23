Response:
The user wants a summary of the functionalities present in the provided C++ code snippet from `v8/src/parsing/parser.cc`. The request includes specific considerations: whether the file would be a Torque source if it had a `.tq` extension, its relationship to JavaScript (illustrated with examples), code logic with input/output scenarios, common user errors, and a final overall summary of the functionality within this part of the parser.

Here's a breakdown of the thought process:

1. **Identify the Core Functionality:**  The code primarily deals with parsing `export` statements in JavaScript. This includes different forms of exports like `export *`, `export { ... }`, and named exports of declarations (functions, classes, variables).

2. **Address the Torque Question:** The user is asking if a `.tq` extension would indicate a Torque source. Since this is V8 code and `.tq` is the extension for V8's Torque language, the answer is yes.

3. **Illustrate with JavaScript Examples:** For each significant parsing function, provide a corresponding JavaScript example to clarify its purpose. This will help bridge the gap between the C++ parser and the JavaScript it processes.

4. **Analyze Code Logic and Provide Input/Output:**  For key functions like `ParseExportStar` and `ParseExportDeclaration`, describe the expected input (tokens) and the resulting changes to the `module()` state (adding exports/imports). Focus on the different branches within the logic.

5. **Identify Common User Errors:**  Consider what mistakes developers might make when writing `export` statements that this parser would catch. Examples include exporting reserved words without a `from` clause and using string literals as local names without a `from` clause.

6. **Synthesize the Overall Functionality:**  Combine the individual function summaries into a cohesive description of the parser's role in handling exports. Emphasize its responsibility in understanding and representing the structure of export declarations for later stages of the V8 pipeline.

7. **Structure the Response:** Organize the information clearly, addressing each of the user's requirements systematically. Use headings and bullet points to enhance readability.

**Pre-computation/Analysis of the Code Snippet:**

* **`ParseExportStar()`:** This handles `export * from '...'` and `export * as name from '...'`. The latter involves desugaring into an import and a local export.
* **`ParseExportDeclaration()`:** This is the main entry point for parsing various `export` statement forms. It uses a switch statement to differentiate between different export types.
* **Export Clause Parsing (`ParseExportClause`)**: Although not directly shown in this snippet, it's referenced and crucial for handling `export { a, b as c }`.
* **Declaration Handling (`DeclareUnboundVariable`, `DeclareBoundVariable`, `DeclareVariable`, `Declare`):** These functions are responsible for managing variables and their scopes, a fundamental part of parsing any declaration, including exported ones.
* **Rewriting and Desugaring:** Functions like `RewriteSwitchStatement`, `RewriteTryStatement`, and the various `RewriteFor...` functions illustrate the parser's role in transforming complex language features into simpler, equivalent forms. The for-loop desugaring with lexical bindings is particularly involved.

**Self-Correction during Thought Process:**

* **Initial thought:** Focus heavily on the AST node creation.
* **Correction:** Shift focus to the *purpose* of these nodes and how they represent the JavaScript `export` concept. The user wants to understand the *what*, not just the *how*.
* **Initial thought:**  Provide very low-level details about token consumption.
* **Correction:**  Abstract to a higher level, describing the overall parsing flow and the different export statement structures being recognized. Token details are less relevant for a functional summary.
* **Initial thought:** Treat each function in isolation.
* **Correction:** Emphasize the relationships between the functions, particularly how `ParseExportDeclaration` orchestrates the parsing of different export forms by calling other functions.

By following these steps, the response aims to be comprehensive, accurate, and tailored to the user's specific requirements, bridging the gap between the C++ implementation and the JavaScript language it parses.
这是 V8 源代码文件 `v8/src/parsing/parser.cc` 的一部分，主要负责解析 JavaScript 的 `export` 声明以及相关的语法结构。以下是对这段代码的功能归纳：

**主要功能：解析 JavaScript 的 `export` 声明**

这段代码的核心任务是理解和分析 JavaScript 代码中的 `export` 语句，将其转化为 V8 内部的抽象语法树 (AST) 表示形式，以便后续的编译和执行。具体来说，它处理以下几种 `export` 的语法结构：

* **`export * from 'module'`:**  导出指定模块的所有绑定 (变量、函数、类等)。
* **`export * as name from 'module'`:** 导出指定模块的所有绑定，并用新的名称进行别名导出。
* **`export { name1, name2 as alias }`:** 导出当前模块中已声明的特定绑定。
* **`export { name1, name2 as alias } from 'module'`:** 导出指定模块的特定绑定，并可以选择性地进行别名。
* **`export var/let/const declaration`:** 导出变量声明。
* **`export function declaration`:** 导出函数声明。
* **`export class declaration`:** 导出类声明。
* **`export default expression`:** 导出默认值。 (虽然这段代码中没有 `ParseExportDefault` 的完整实现，但可以看到 `ParseExportDeclaration` 中有针对 `Token::kDefault` 的处理，表明它负责分发给 `ParseExportDefault`)

**功能分解与代码逻辑推理：**

1. **`ParseExportStar()`**:
   - **功能:** 解析 `export * from 'module'` 和 `export * as name from 'module'` 两种形式。
   - **假设输入 (Token 流):**
     - 对于 `export * from 'mod';`: `Token::kExport`, `Token::kMul`, `ContextualKeyword("from")`, `StringLiteral("mod")`, `Token::kSemicolon`
     - 对于 `export * as alias from 'mod';`: `Token::kExport`, `Token::kMul`, `ContextualKeyword("as")`, `IdentifierName("alias")`, `ContextualKeyword("from")`, `StringLiteral("mod")`, `Token::kSemicolon`
   - **输出 (对 `module()` 的操作):**
     - 对于 `export * from 'mod';`: 调用 `module()->AddStarExport(...)`，将模块说明符添加到星号导出列表中。
     - 对于 `export * as alias from 'mod';`:
       - 调用 `module()->AddStarImport(...)`，引入一个内部命名空间的导入。
       - 调用 `module()->AddExport(...)`，将内部导入的名称别名为指定的导出名称。
   - **代码逻辑推理:**  代码通过检查下一个 token 是否为 `as` 来区分两种 `export *` 的形式。对于 `export * as ...` 形式，它会创建一个临时的内部变量名 (`NextInternalNamespaceExportName`)，先将模块导入到这个内部变量，然后再将这个内部变量以指定的别名导出。这种方式避免了导出名称与本地变量冲突。

2. **`ParseExportDeclaration()`**:
   - **功能:**  作为解析各种 `export` 声明的入口点，根据不同的 token 类型分发到相应的解析函数。
   - **假设输入 (Token 流):**  可以是各种 `export` 语句的 token 流，例如：
     - `export function foo() {}`
     - `export class Bar {}`
     - `export { a, b as c };`
     - `export { d } from './other';`
   - **输出 (创建 AST 节点):**  根据不同的 `export` 形式，创建不同的 AST 节点，例如 `FunctionDeclaration`, `ClassDeclaration`, `EmptyStatement` (对于导出说明符)。同时，还会调用 `module()->AddExport(...)` 或 `module()->AddStarExport/Import(...)` 来记录导出的信息。
   - **代码逻辑推理:** 使用 `switch (peek())` 语句来判断下一个 token 的类型，从而确定当前的 `export` 声明是哪种形式，然后调用相应的解析函数进行处理。例如，如果遇到 `Token::kFunction`，则调用 `ParseHoistableDeclaration` 解析函数声明。

3. **变量声明和绑定 (`DeclareUnboundVariable`, `DeclareBoundVariable`, `DeclareVariable`, `Declare`)**:
   - **功能:**  这些函数用于声明变量，并将其绑定到当前的作用域中。它们处理变量的类型 (var, let, const)、初始化状态以及可能存在的重声明错误。
   - **假设输入:** 变量名、变量模式 (var, let, const)、初始化标志、作用域等信息。
   - **输出:** 创建 `Variable` 对象，并将其添加到作用域的声明列表中。如果存在重声明错误，则报告错误。
   - **代码逻辑推理:** `DeclareVariable` 函数会根据变量的模式和作用域判断是否需要创建 `NestedVariableDeclaration`。`Declare` 函数负责将声明添加到作用域，并检查是否存在重声明。

**与 JavaScript 功能的关系 (示例):**

```javascript
// 假设 parser.cc 解析以下 JavaScript 代码

// 对应 ParseExportStar
export * from './utils';
export * as helpers from './helpers';

// 对应 ParseExportDeclaration 的不同分支
export function add(a, b) { return a + b; }
export class Calculator { constructor() {} }
export const PI = 3.14;
let counter = 0;
export { counter };
export { subtract as sub } from './math';
```

**用户常见的编程错误 (示例):**

* **导出保留字，但没有 `from` 子句:**
  ```javascript
  export let function; // 错误：'function' 是保留字
  ```
  代码中的 `if (reserved_loc.IsValid()) { ... ReportMessageAt(reserved_loc, MessageTemplate::kUnexpectedReserved); ... }`  会捕获这类错误。

* **在没有 `from` 子句的情况下，使用字符串字面量作为本地名称:**
  ```javascript
  export { "string" }; // 错误：模块导出名称不能是字符串字面量，除非有 from 子句
  ```
  代码中的 `else if (string_literal_local_name_loc.IsValid()) { ... ReportMessageAt(string_literal_local_name_loc, MessageTemplate::kModuleExportNameWithoutFromClause); ... }` 会捕获这类错误。

* **重复导出相同的名称:** 虽然这段代码没有直接展示错误报告逻辑，但在 `module()->AddExport` 内部应该会有相应的检查，防止重复导出。

**如果 `v8/src/parsing/parser.cc` 以 `.tq` 结尾：**

如果 `v8/src/parsing/parser.cc` 以 `.tq` 结尾，那么它就是一个 **V8 Torque 源代码**。Torque 是 V8 用来定义其内部运行时函数的领域特定语言。Torque 代码会被编译成 C++ 代码。

**总结 (第 3 部分的功能):**

这部分 `parser.cc` 的代码主要负责 **解析 JavaScript 的 `export` 声明**。它能够识别和处理各种不同的 `export` 语法结构，并将这些结构转换为 V8 内部的表示形式，以便进行进一步的编译和代码生成。此外，它还负责在解析过程中进行一些基本的语法检查，例如防止导出保留字或在不恰当的地方使用字符串字面量作为导出名称。 这部分的功能是理解模块化 JavaScript 代码的关键一步。

### 提示词
```
这是目录为v8/src/parsing/parser.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/parsing/parser.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
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

  return outer_block
```