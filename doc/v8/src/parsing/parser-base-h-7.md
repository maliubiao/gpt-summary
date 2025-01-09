Response:
The user wants a summary of the C++ code provided, focusing on its functionality within the V8 JavaScript engine.

Here's a breakdown of the thought process to generate the response:

1. **Identify the core class:** The code snippet is part of the `ParserBase` class template in `v8/src/parsing/parser-base.h`. This immediately tells us it's related to parsing JavaScript code.

2. **Analyze the methods:**  The provided code contains implementations for parsing various JavaScript statements. List them out: `ParseIfStatement`, `ParseContinueStatement`, `ParseBreakStatement`, `ParseReturnStatement`, `ParseWithStatement`, `ParseDoWhileStatement`, `ParseWhileStatement`, `ParseThrowStatement`, `ParseSwitchStatement`, `ParseTryStatement`, `ParseForStatement`, `ParseForEachStatementWithDeclarations`, `ParseForEachStatementWithoutDeclarations`, `ParseStandardForLoopWithLexicalDeclarations`, `ParseStandardForLoop`, and `ParseForAwaitStatement`.

3. **Group by functionality:** These methods clearly correspond to the different types of statements in JavaScript. Grouping them helps organize the explanation:
    * **Conditional:** `ParseIfStatement`
    * **Loop Control:** `ParseContinueStatement`, `ParseBreakStatement`
    * **Function Control:** `ParseReturnStatement`
    * **Scope Manipulation:** `ParseWithStatement`
    * **Loops:** `ParseDoWhileStatement`, `ParseWhileStatement`, `ParseForStatement`, `ParseForEachStatementWithDeclarations`, `ParseForEachStatementWithoutDeclarations`, `ParseStandardForLoopWithLexicalDeclarations`, `ParseStandardForLoop`, `ParseForAwaitStatement`
    * **Exception Handling:** `ParseThrowStatement`, `ParseSwitchStatement`, `ParseTryStatement`

4. **Describe the purpose of each method:** Briefly explain what each parsing method does in terms of recognizing and processing the corresponding JavaScript statement. Focus on the actions taken by the parser, such as consuming tokens, building AST nodes, and handling errors.

5. **Address the `.tq` question:** Explain that the `.h` extension indicates a C++ header file, not a Torque file.

6. **Connect to JavaScript functionality with examples:** For each group of statements, provide a simple JavaScript code snippet demonstrating the feature being parsed. This is crucial for understanding the code's purpose from a JavaScript perspective.

7. **Illustrate code logic with input/output assumptions:** For methods involving more complex logic (like `ParseIfStatement` or loop parsing), create simple hypothetical input (tokens) and the expected output (an abstract representation of the parsed statement). This clarifies the parsing process.

8. **Provide examples of common programming errors:**  For relevant statements, point out common mistakes developers make when writing JavaScript code and how the parser might handle or flag these errors (e.g., illegal `continue`, `break`, `return`, strict mode `with`).

9. **Summarize the overall functionality:**  Combine the individual functionalities into a concise overview of the header file's role in the parsing process. Emphasize its responsibility for recognizing and building the Abstract Syntax Tree (AST) for JavaScript statements.

10. **Review and refine:**  Read through the generated explanation to ensure clarity, accuracy, and completeness. Check for any inconsistencies or areas where more detail might be helpful. For example, initially, I might not have explicitly mentioned AST building, but it's a core function of a parser, so it should be included. Also, ensure the examples are simple and easy to understand.

This structured approach ensures all aspects of the prompt are addressed in a logical and informative manner.
This是 `v8/src/parsing/parser-base.h` 的一部分代码，它定义了 `ParserBase` 模板类中用于解析各种 JavaScript 语句的方法。以下是这些方法的功能归纳：

**核心功能：解析 JavaScript 语句**

这部分代码的核心功能是 **识别和解析各种 JavaScript 语句，并将它们转换为抽象语法树 (AST) 中的相应节点**。`ParserBase` 类是 V8 引擎中语法分析器的基础，它定义了通用的解析逻辑和接口，具体的解析实现由模板参数 `Impl` 提供。

**各个语句解析方法的功能：**

* **`ParseIfStatement()`:** 解析 `if` 语句。它会识别 `if` 关键字，解析条件表达式，然后解析 `then` 代码块。如果存在 `else` 分支，也会解析 `else` 代码块。
    * **JavaScript 例子:** `if (x > 0) { console.log("positive"); } else { console.log("non-positive"); }`
    * **代码逻辑推理 (假设输入和输出):**
        * **假设输入 (Token 流):** `Token::kIf`, `Token::kLeftParen`, Identifier("x"), `Token::kGreaterThan`, Number(0), `Token::kRightParen`, `Token::kLeftBrace`, Identifier("console"), Dot, Identifier("log"), `Token::kLeftParen`, String("positive"), `Token::kRightParen`, `Token::kSemicolon`, `Token::kRightBrace`, `Token::kElse`, `Token::kLeftBrace`, ...
        * **假设输出 (AST 节点):**  一个表示 `IfStatement` 的节点，包含条件表达式 `(x > 0)`，一个表示 `then` 代码块的 `BlockStatement` 节点，以及一个表示 `else` 代码块的 `BlockStatement` 节点。

* **`ParseContinueStatement()`:** 解析 `continue` 语句。它会识别 `continue` 关键字，并查找可选的标签，以确定要继续执行哪个循环。
    * **JavaScript 例子:** `for (let i = 0; i < 10; i++) { if (i % 2 === 0) continue; console.log(i); }`
    * **用户常见的编程错误:** 在循环外部使用 `continue` 语句会导致语法错误。

* **`ParseBreakStatement()`:** 解析 `break` 语句。它会识别 `break` 关键字，并查找可选的标签，以确定要跳出哪个循环或 `switch` 语句。
    * **JavaScript 例子:** `for (let i = 0; i < 10; i++) { if (i > 5) break; console.log(i); }`
    * **用户常见的编程错误:** 在循环或 `switch` 外部使用 `break` 语句会导致语法错误。

* **`ParseReturnStatement()`:** 解析 `return` 语句。它会识别 `return` 关键字，并解析可选的返回值表达式。
    * **JavaScript 例子:** `function add(a, b) { return a + b; }`
    * **用户常见的编程错误:** 在没有返回值的函数中使用 `return value;` 或者在不允许返回值的上下文中（如全局作用域）使用 `return`。V8 会在解析阶段报告 `kIllegalReturn` 错误。

* **`ParseWithStatement()`:** 解析 `with` 语句。它会识别 `with` 关键字，解析对象表达式和语句块。**请注意，`with` 语句在严格模式下是被禁止的**。
    * **JavaScript 例子:** `with (console) { log("Hello"); }`
    * **用户常见的编程错误:** 在严格模式下使用 `with` 语句。V8 会报告 `kStrictWith` 错误。

* **`ParseDoWhileStatement()`:** 解析 `do...while` 循环。它会识别 `do` 关键字，解析循环体，然后识别 `while` 关键字并解析循环条件。
    * **JavaScript 例子:** `let i = 0; do { console.log(i++); } while (i < 5);`

* **`ParseWhileStatement()`:** 解析 `while` 循环。它会识别 `while` 关键字，解析循环条件，然后解析循环体。
    * **JavaScript 例子:** `let i = 0; while (i < 5) { console.log(i++); }`

* **`ParseThrowStatement()`:** 解析 `throw` 语句。它会识别 `throw` 关键字，并解析要抛出的异常表达式。
    * **JavaScript 例子:** `throw new Error("Something went wrong!");`
    * **用户常见的编程错误:** `throw` 关键字后紧跟换行符会导致语法错误 (`kNewlineAfterThrow`)。

* **`ParseSwitchStatement()`:** 解析 `switch` 语句。它会识别 `switch` 关键字，解析匹配表达式，然后解析各个 `case` 和 `default` 子句。
    * **JavaScript 例子:**
    ```javascript
    switch (fruit) {
      case "apple":
        console.log("It's an apple.");
        break;
      case "banana":
        console.log("It's a banana.");
        break;
      default:
        console.log("It's something else.");
    }
    ```
    * **用户常见的编程错误:** 在 `switch` 语句中出现多个 `default` 子句 (`kMultipleDefaultsInSwitch`)。

* **`ParseTryStatement()`:** 解析 `try...catch...finally` 语句。它会识别 `try` 关键字，解析 `try` 代码块，然后解析可选的 `catch` 和 `finally` 代码块。
    * **JavaScript 例子:**
    ```javascript
    try {
      // Some code that might throw an error
      throw new Error("Test error");
    } catch (error) {
      console.error("Caught an error:", error);
    } finally {
      console.log("Finally block executed.");
    }
    ```
    * **用户常见的编程错误:**  `try` 语句后面既没有 `catch` 也没有 `finally` 块 (`kNoCatchOrFinally`)。

* **`ParseForStatement()`:** 解析 `for` 循环，包括标准的 `for` 循环和 `for...in` 以及 `for...of` 循环。它会处理循环的初始化、条件和更新部分。
    * **JavaScript 例子:**
        * `for (let i = 0; i < 10; i++) { console.log(i); }`
        * `for (let key in object) { console.log(key); }`
        * `for (let value of array) { console.log(value); }`
    * **用户常见的编程错误:** 在 `for...in` 或 `for...of` 循环中使用多个变量声明 (`kForInOfLoopMultiBindings`)，或者在这些循环的初始化部分使用赋值语句 (`kForInOfLoopInitializer`)。

* **`ParseForEachStatementWithDeclarations()`:**  专门处理带有变量声明的 `for...in` 和 `for...of` 循环的解析。

* **`ParseForEachStatementWithoutDeclarations()`:** 专门处理不带变量声明的 `for...in` 和 `for...of` 循环的解析。

* **`ParseStandardForLoopWithLexicalDeclarations()`:** 处理带有词法声明（`let`, `const`) 的标准 `for` 循环。

* **`ParseStandardForLoop()`:** 解析标准的 `for` 循环的条件和更新部分。

* **`ParseForAwaitStatement()`:** 解析 `for await...of` 循环，用于异步迭代器。
    * **JavaScript 例子:**
    ```javascript
    async function processStream(stream) {
      for await (const chunk of stream) {
        console.log("Received chunk:", chunk);
      }
    }
    ```
    * **用户常见的编程错误:** 在 `for await...of` 循环中使用多个变量声明 (`kForInOfLoopMultiBindings`)，或者在初始化部分使用赋值语句 (`kForInOfLoopInitializer`)。

**关于 `.tq` 扩展名:**

如果 `v8/src/parsing/parser-base.h` 以 `.tq` 结尾，那它确实是一个 V8 Torque 源代码文件。 **然而，根据您提供的信息，文件名是 `.h`，这表明它是一个 C++ 头文件**，而不是 Torque 文件。 Torque 文件通常用于定义 V8 内部的运行时函数和类型。

**总结 `v8/src/parsing/parser-base.h` 的功能 (针对提供的代码片段):**

这部分 `v8/src/parsing/parser-base.h` 代码定义了 `ParserBase` 类中用于 **解析各种 JavaScript 语句** 的方法。它负责识别不同的语句类型，提取关键组成部分（例如，条件表达式、循环体、变量声明等），并构建代表这些语句的 AST 节点。 这些方法是 V8 引擎将 JavaScript 源代码转换为可执行代码的关键步骤。

Prompt: 
```
这是目录为v8/src/parsing/parser-base.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/parsing/parser-base.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第8部分，共9部分，请归纳一下它的功能

"""
seScopedStatement(labels);
    else_range = SourceRange::ContinuationOf(then_range, end_position());
  } else {
    else_statement = factory()->EmptyStatement();
  }
  StatementT stmt =
      factory()->NewIfStatement(condition, then_statement, else_statement, pos);
  impl()->RecordIfStatementSourceRange(stmt, then_range, else_range);
  return stmt;
}

template <typename Impl>
typename ParserBase<Impl>::StatementT
ParserBase<Impl>::ParseContinueStatement() {
  // ContinueStatement ::
  //   'continue' Identifier? ';'

  int pos = peek_position();
  Consume(Token::kContinue);
  IdentifierT label = impl()->NullIdentifier();
  Token::Value tok = peek();
  if (!scanner()->HasLineTerminatorBeforeNext() &&
      !Token::IsAutoSemicolon(tok)) {
    // ECMA allows "eval" or "arguments" as labels even in strict mode.
    label = ParseIdentifier();
  }
  IterationStatementT target = LookupContinueTarget(label);
  if (impl()->IsNull(target)) {
    // Illegal continue statement.
    MessageTemplate message = MessageTemplate::kIllegalContinue;
    BreakableStatementT breakable_target = LookupBreakTarget(label);
    if (impl()->IsNull(label)) {
      message = MessageTemplate::kNoIterationStatement;
    } else if (impl()->IsNull(breakable_target)) {
      message = MessageTemplate::kUnknownLabel;
    }
    ReportMessage(message, label);
    return impl()->NullStatement();
  }
  ExpectSemicolon();
  StatementT stmt = factory()->NewContinueStatement(target, pos);
  impl()->RecordJumpStatementSourceRange(stmt, end_position());
  return stmt;
}

template <typename Impl>
typename ParserBase<Impl>::StatementT ParserBase<Impl>::ParseBreakStatement(
    ZonePtrList<const AstRawString>* labels) {
  // BreakStatement ::
  //   'break' Identifier? ';'

  int pos = peek_position();
  Consume(Token::kBreak);
  IdentifierT label = impl()->NullIdentifier();
  Token::Value tok = peek();
  if (!scanner()->HasLineTerminatorBeforeNext() &&
      !Token::IsAutoSemicolon(tok)) {
    // ECMA allows "eval" or "arguments" as labels even in strict mode.
    label = ParseIdentifier();
  }
  // Parse labeled break statements that target themselves into
  // empty statements, e.g. 'l1: l2: l3: break l2;'
  if (!impl()->IsNull(label) &&
      impl()->ContainsLabel(labels, impl()->GetRawNameFromIdentifier(label))) {
    ExpectSemicolon();
    return factory()->EmptyStatement();
  }
  BreakableStatementT target = LookupBreakTarget(label);
  if (impl()->IsNull(target)) {
    // Illegal break statement.
    MessageTemplate message = MessageTemplate::kIllegalBreak;
    if (!impl()->IsNull(label)) {
      message = MessageTemplate::kUnknownLabel;
    }
    ReportMessage(message, label);
    return impl()->NullStatement();
  }
  ExpectSemicolon();
  StatementT stmt = factory()->NewBreakStatement(target, pos);
  impl()->RecordJumpStatementSourceRange(stmt, end_position());
  return stmt;
}

template <typename Impl>
typename ParserBase<Impl>::StatementT ParserBase<Impl>::ParseReturnStatement() {
  // ReturnStatement ::
  //   'return' [no line terminator] Expression? ';'

  // Consume the return token. It is necessary to do that before
  // reporting any errors on it, because of the way errors are
  // reported (underlining).
  Consume(Token::kReturn);
  Scanner::Location loc = scanner()->location();

  switch (GetDeclarationScope()->scope_type()) {
    case SCRIPT_SCOPE:
    case REPL_MODE_SCOPE:
    case EVAL_SCOPE:
    case MODULE_SCOPE:
      impl()->ReportMessageAt(loc, MessageTemplate::kIllegalReturn);
      return impl()->NullStatement();
    case BLOCK_SCOPE:
      // Class static blocks disallow return. They are their own var scopes and
      // have a varblock scope.
      if (function_state_->kind() ==
          FunctionKind::kClassStaticInitializerFunction) {
        impl()->ReportMessageAt(loc, MessageTemplate::kIllegalReturn);
        return impl()->NullStatement();
      }
      break;
    default:
      break;
  }

  Token::Value tok = peek();
  ExpressionT return_value = impl()->NullExpression();
  if (!scanner()->HasLineTerminatorBeforeNext() &&
      !Token::IsAutoSemicolon(tok)) {
    return_value = ParseExpression();
  }
  ExpectSemicolon();

  int continuation_pos = end_position();
  StatementT stmt =
      BuildReturnStatement(return_value, loc.beg_pos, continuation_pos);
  impl()->RecordJumpStatementSourceRange(stmt, end_position());
  return stmt;
}

template <typename Impl>
typename ParserBase<Impl>::StatementT ParserBase<Impl>::ParseWithStatement(
    ZonePtrList<const AstRawString>* labels) {
  // WithStatement ::
  //   'with' '(' Expression ')' Statement

  Consume(Token::kWith);
  int pos = position();

  if (is_strict(language_mode())) {
    ReportMessage(MessageTemplate::kStrictWith);
    return impl()->NullStatement();
  }

  Expect(Token::kLeftParen);
  ExpressionT expr = ParseExpression();
  Expect(Token::kRightParen);

  Scope* with_scope = NewScope(WITH_SCOPE);
  StatementT body = impl()->NullStatement();
  {
    BlockState block_state(&scope_, with_scope);
    with_scope->set_start_position(position());
    body = ParseStatement(labels, nullptr);
    with_scope->set_end_position(end_position());
  }
  return factory()->NewWithStatement(with_scope, expr, body, pos);
}

template <typename Impl>
typename ParserBase<Impl>::StatementT ParserBase<Impl>::ParseDoWhileStatement(
    ZonePtrList<const AstRawString>* labels,
    ZonePtrList<const AstRawString>* own_labels) {
  // DoStatement ::
  //   'do' Statement 'while' '(' Expression ')' ';'
  typename FunctionState::LoopScope loop_scope(function_state_);

  auto loop = factory()->NewDoWhileStatement(peek_position());
  Target target(this, loop, labels, own_labels, Target::TARGET_FOR_ANONYMOUS);

  SourceRange body_range;
  StatementT body = impl()->NullStatement();

  Consume(Token::kDo);

  CheckStackOverflow();
  {
    SourceRangeScope range_scope(scanner(), &body_range);
    body = ParseStatement(nullptr, nullptr);
  }
  Expect(Token::kWhile);
  Expect(Token::kLeftParen);

  ExpressionT cond = ParseExpression();
  Expect(Token::kRightParen);

  // Allow do-statements to be terminated with and without
  // semi-colons. This allows code such as 'do;while(0)return' to
  // parse, which would not be the case if we had used the
  // ExpectSemicolon() functionality here.
  Check(Token::kSemicolon);

  loop->Initialize(cond, body);
  impl()->RecordIterationStatementSourceRange(loop, body_range);

  return loop;
}

template <typename Impl>
typename ParserBase<Impl>::StatementT ParserBase<Impl>::ParseWhileStatement(
    ZonePtrList<const AstRawString>* labels,
    ZonePtrList<const AstRawString>* own_labels) {
  // WhileStatement ::
  //   'while' '(' Expression ')' Statement
  typename FunctionState::LoopScope loop_scope(function_state_);

  auto loop = factory()->NewWhileStatement(peek_position());
  Target target(this, loop, labels, own_labels, Target::TARGET_FOR_ANONYMOUS);

  SourceRange body_range;
  StatementT body = impl()->NullStatement();

  Consume(Token::kWhile);
  Expect(Token::kLeftParen);
  ExpressionT cond = ParseExpression();
  Expect(Token::kRightParen);
  {
    SourceRangeScope range_scope(scanner(), &body_range);
    body = ParseStatement(nullptr, nullptr);
  }

  loop->Initialize(cond, body);
  impl()->RecordIterationStatementSourceRange(loop, body_range);

  return loop;
}

template <typename Impl>
typename ParserBase<Impl>::StatementT ParserBase<Impl>::ParseThrowStatement() {
  // ThrowStatement ::
  //   'throw' Expression ';'

  Consume(Token::kThrow);
  int pos = position();
  if (scanner()->HasLineTerminatorBeforeNext()) {
    ReportMessage(MessageTemplate::kNewlineAfterThrow);
    return impl()->NullStatement();
  }
  ExpressionT exception = ParseExpression();
  ExpectSemicolon();

  StatementT stmt = impl()->NewThrowStatement(exception, pos);
  impl()->RecordThrowSourceRange(stmt, end_position());

  return stmt;
}

template <typename Impl>
typename ParserBase<Impl>::StatementT ParserBase<Impl>::ParseSwitchStatement(
    ZonePtrList<const AstRawString>* labels) {
  // SwitchStatement ::
  //   'switch' '(' Expression ')' '{' CaseClause* '}'
  // CaseClause ::
  //   'case' Expression ':' StatementList
  //   'default' ':' StatementList
  int switch_pos = peek_position();

  Consume(Token::kSwitch);
  Expect(Token::kLeftParen);
  ExpressionT tag = ParseExpression();
  Expect(Token::kRightParen);

  auto switch_statement = factory()->NewSwitchStatement(tag, switch_pos);

  {
    BlockState cases_block_state(zone(), &scope_);
    scope()->set_start_position(switch_pos);
    scope()->SetNonlinear();
    Target target(this, switch_statement, labels, nullptr,
                  Target::TARGET_FOR_ANONYMOUS);

    bool default_seen = false;
    Expect(Token::kLeftBrace);
    while (peek() != Token::kRightBrace) {
      // An empty label indicates the default case.
      ExpressionT label = impl()->NullExpression();
      StatementListT statements(pointer_buffer());
      SourceRange clause_range;
      {
        SourceRangeScope range_scope(scanner(), &clause_range);
        if (Check(Token::kCase)) {
          label = ParseExpression();
        } else {
          Expect(Token::kDefault);
          if (default_seen) {
            ReportMessage(MessageTemplate::kMultipleDefaultsInSwitch);
            return impl()->NullStatement();
          }
          default_seen = true;
        }
        Expect(Token::kColon);
        while (peek() != Token::kCase && peek() != Token::kDefault &&
               peek() != Token::kRightBrace) {
          StatementT stat = ParseStatementListItem();
          if (impl()->IsNull(stat)) return stat;
          if (stat->IsEmptyStatement()) continue;
          statements.Add(stat);
        }
      }
      auto clause = factory()->NewCaseClause(label, statements);
      impl()->RecordCaseClauseSourceRange(clause, clause_range);
      switch_statement->cases()->Add(clause, zone());
    }
    Expect(Token::kRightBrace);

    int end_pos = end_position();
    scope()->set_end_position(end_pos);
    impl()->RecordSwitchStatementSourceRange(switch_statement, end_pos);
    Scope* switch_scope = scope()->FinalizeBlockScope();
    function_state_ =
        AddOneSuspendPointIfBlockContainsAwaitUsing(scope(), function_state_);
    if (switch_scope != nullptr) {
      return impl()->RewriteSwitchStatement(switch_statement, switch_scope);
    }
    return switch_statement;
  }
}

template <typename Impl>
typename ParserBase<Impl>::StatementT ParserBase<Impl>::ParseTryStatement() {
  // TryStatement ::
  //   'try' Block Catch
  //   'try' Block Finally
  //   'try' Block Catch Finally
  //
  // Catch ::
  //   'catch' '(' Identifier ')' Block
  //
  // Finally ::
  //   'finally' Block

  Consume(Token::kTry);
  int pos = position();

  BlockT try_block = ParseBlock(nullptr);

  CatchInfo catch_info(this);

  if (peek() != Token::kCatch && peek() != Token::kFinally) {
    ReportMessage(MessageTemplate::kNoCatchOrFinally);
    return impl()->NullStatement();
  }

  SourceRange catch_range, finally_range;

  BlockT catch_block = impl()->NullBlock();
  {
    SourceRangeScope catch_range_scope(scanner(), &catch_range);
    if (Check(Token::kCatch)) {
      bool has_binding;
      has_binding = Check(Token::kLeftParen);

      if (has_binding) {
        catch_info.scope = NewScope(CATCH_SCOPE);
        catch_info.scope->set_start_position(position());

        {
          BlockState catch_block_state(&scope_, catch_info.scope);
          StatementListT catch_statements(pointer_buffer());

          // Create a block scope to hold any lexical declarations created
          // as part of destructuring the catch parameter.
          {
            BlockState catch_variable_block_state(zone(), &scope_);
            scope()->set_start_position(peek_position());

            if (peek_any_identifier()) {
              IdentifierT identifier = ParseNonRestrictedIdentifier();
              RETURN_IF_PARSE_ERROR;
              catch_info.variable = impl()->DeclareCatchVariableName(
                  catch_info.scope, identifier);
            } else {
              catch_info.variable = catch_info.scope->DeclareCatchVariableName(
                  ast_value_factory()->dot_catch_string());

              auto declaration_it = scope()->declarations()->end();

              VariableDeclarationParsingScope destructuring(
                  impl(), VariableMode::kLet, nullptr);
              catch_info.pattern = ParseBindingPattern();

              int initializer_position = end_position();
              auto declaration_end = scope()->declarations()->end();
              for (; declaration_it != declaration_end; ++declaration_it) {
                declaration_it->var()->set_initializer_position(
                    initializer_position);
              }

              RETURN_IF_PARSE_ERROR;
              catch_statements.Add(impl()->RewriteCatchPattern(&catch_info));
            }

            Expect(Token::kRightParen);

            BlockT inner_block = ParseBlock(nullptr);
            catch_statements.Add(inner_block);

            // Check for `catch(e) { let e; }` and similar errors.
            if (!impl()->HasCheckedSyntax()) {
              Scope* inner_scope = inner_block->scope();
              if (inner_scope != nullptr) {
                const AstRawString* conflict = nullptr;
                if (impl()->IsNull(catch_info.pattern)) {
                  const AstRawString* name = catch_info.variable->raw_name();
                  if (inner_scope->LookupLocal(name)) conflict = name;
                } else {
                  conflict = inner_scope->FindVariableDeclaredIn(
                      scope(), VariableMode::kVar);
                }
                if (conflict != nullptr) {
                  impl()->ReportVarRedeclarationIn(conflict, inner_scope);
                }
              }
            }

            scope()->set_end_position(end_position());
            catch_block = factory()->NewBlock(false, catch_statements);
            catch_block->set_scope(scope()->FinalizeBlockScope());
          }
        }

        catch_info.scope->set_end_position(end_position());
      } else {
        catch_block = ParseBlock(nullptr);
      }
    }
  }

  BlockT finally_block = impl()->NullBlock();
  DCHECK(has_error() || peek() == Token::kFinally ||
         !impl()->IsNull(catch_block));
  {
    SourceRangeScope range_scope(scanner(), &finally_range);
    if (Check(Token::kFinally)) {
      finally_block = ParseBlock(nullptr);
    }
  }

  RETURN_IF_PARSE_ERROR;
  return impl()->RewriteTryStatement(try_block, catch_block, catch_range,
                                     finally_block, finally_range, catch_info,
                                     pos);
}

template <typename Impl>
typename ParserBase<Impl>::StatementT ParserBase<Impl>::ParseForStatement(
    ZonePtrList<const AstRawString>* labels,
    ZonePtrList<const AstRawString>* own_labels) {
  // Either a standard for loop
  //   for (<init>; <cond>; <next>) { ... }
  // or a for-each loop
  //   for (<each> of|in <iterable>) { ... }
  //
  // We parse a declaration/expression after the 'for (' and then read the first
  // expression/declaration before we know if this is a for or a for-each.
  typename FunctionState::LoopScope loop_scope(function_state_);

  int stmt_pos = peek_position();
  ForInfo for_info(this);

  Consume(Token::kFor);
  Expect(Token::kLeftParen);

  bool starts_with_let = peek() == Token::kLet;
  bool starts_with_using_keyword = IfStartsWithUsingKeyword();
  if (peek() == Token::kConst || (starts_with_let && IsNextLetKeyword()) ||
      starts_with_using_keyword) {
    // The initializer contains lexical declarations,
    // so create an in-between scope.
    BlockState for_state(zone(), &scope_);
    scope()->set_start_position(position());

    // Also record whether inner functions or evals are found inside
    // this loop, as this information is used to simplify the desugaring
    // if none are found.
    typename FunctionState::FunctionOrEvalRecordingScope recording_scope(
        function_state_);

    // Create an inner block scope which will be the parent scope of scopes
    // possibly created by ParseVariableDeclarations.
    Scope* inner_block_scope = NewScope(BLOCK_SCOPE);
    inner_block_scope->set_start_position(end_position());
    {
      BlockState inner_state(&scope_, inner_block_scope);
      ParseVariableDeclarations(kForStatement, &for_info.parsing_result,
                                &for_info.bound_names);
    }
    DCHECK(IsLexicalVariableMode(for_info.parsing_result.descriptor.mode));
    for_info.position = position();

    if (CheckInOrOf(&for_info.mode)) {
      scope()->set_is_hidden();
      if (starts_with_using_keyword &&
          for_info.mode == ForEachStatement::ENUMERATE) {
        impl()->ReportMessageAt(scanner()->location(),
                                MessageTemplate::kInvalidUsingInForInLoop);
      }
      return ParseForEachStatementWithDeclarations(
          stmt_pos, &for_info, labels, own_labels, inner_block_scope);
    }

    Expect(Token::kSemicolon);

    // Parse the remaining code in the inner block scope since the declaration
    // above was parsed there. We'll finalize the unnecessary outer block scope
    // after parsing the rest of the loop.
    StatementT result = impl()->NullStatement();
    {
      BlockState inner_state(&scope_, inner_block_scope);
      StatementT init =
          impl()->BuildInitializationBlock(&for_info.parsing_result);

      result = ParseStandardForLoopWithLexicalDeclarations(
          stmt_pos, init, &for_info, labels, own_labels);
    }
    Scope* finalized = scope()->FinalizeBlockScope();
    DCHECK_NULL(finalized);
    USE(finalized);
    return result;
  }

  StatementT init = impl()->NullStatement();
  if (peek() == Token::kVar) {
    ParseVariableDeclarations(kForStatement, &for_info.parsing_result,
                              &for_info.bound_names);
    DCHECK_EQ(for_info.parsing_result.descriptor.mode, VariableMode::kVar);
    for_info.position = position();

    if (CheckInOrOf(&for_info.mode)) {
      return ParseForEachStatementWithDeclarations(stmt_pos, &for_info, labels,
                                                   own_labels, scope());
    }

    init = impl()->BuildInitializationBlock(&for_info.parsing_result);
  } else if (peek() != Token::kSemicolon) {
    // The initializer does not contain declarations.
    Scanner::Location next_loc = scanner()->peek_location();
    int lhs_beg_pos = next_loc.beg_pos;
    int lhs_end_pos;
    bool is_for_each;
    ExpressionT expression;

    {
      ExpressionParsingScope parsing_scope(impl());
      AcceptINScope scope(this, false);
      expression = ParseExpressionCoverGrammar();
      // `for (async of` is disallowed but `for (async.x of` is allowed, so
      // check if the token is kAsync after parsing the expression.
      bool expression_is_async = scanner()->current_token() == Token::kAsync &&
                                 !scanner()->literal_contains_escapes();
      // Initializer is reference followed by in/of.
      lhs_end_pos = end_position();
      is_for_each = CheckInOrOf(&for_info.mode);
      if (is_for_each) {
        if ((starts_with_let || expression_is_async) &&
            for_info.mode == ForEachStatement::ITERATE) {
          impl()->ReportMessageAt(next_loc, starts_with_let
                                                ? MessageTemplate::kForOfLet
                                                : MessageTemplate::kForOfAsync);
          return impl()->NullStatement();
        }
        if (expression->IsPattern()) {
          parsing_scope.ValidatePattern(expression, lhs_beg_pos, lhs_end_pos);
        } else {
          expression = parsing_scope.ValidateAndRewriteReference(
              expression, lhs_beg_pos, lhs_end_pos);
        }
      } else {
        parsing_scope.ValidateExpression();
      }
    }

    if (is_for_each) {
      return ParseForEachStatementWithoutDeclarations(
          stmt_pos, expression, lhs_beg_pos, lhs_end_pos, &for_info, labels,
          own_labels);
    }
    // Initializer is just an expression.
    init = factory()->NewExpressionStatement(expression, lhs_beg_pos);
  }

  Expect(Token::kSemicolon);

  // Standard 'for' loop, we have parsed the initializer at this point.
  ExpressionT cond = impl()->NullExpression();
  StatementT next = impl()->NullStatement();
  StatementT body = impl()->NullStatement();
  ForStatementT loop =
      ParseStandardForLoop(stmt_pos, labels, own_labels, &cond, &next, &body);
  RETURN_IF_PARSE_ERROR;
  loop->Initialize(init, cond, next, body);
  return loop;
}

template <typename Impl>
typename ParserBase<Impl>::StatementT
ParserBase<Impl>::ParseForEachStatementWithDeclarations(
    int stmt_pos, ForInfo* for_info, ZonePtrList<const AstRawString>* labels,
    ZonePtrList<const AstRawString>* own_labels, Scope* inner_block_scope) {
  // Just one declaration followed by in/of.
  if (for_info->parsing_result.declarations.size() != 1) {
    impl()->ReportMessageAt(for_info->parsing_result.bindings_loc,
                            MessageTemplate::kForInOfLoopMultiBindings,
                            ForEachStatement::VisitModeString(for_info->mode));
    return impl()->NullStatement();
  }
  if (for_info->parsing_result.first_initializer_loc.IsValid() &&
      (is_strict(language_mode()) ||
       for_info->mode == ForEachStatement::ITERATE ||
       IsLexicalVariableMode(for_info->parsing_result.descriptor.mode) ||
       !impl()->IsIdentifier(
           for_info->parsing_result.declarations[0].pattern))) {
    impl()->ReportMessageAt(for_info->parsing_result.first_initializer_loc,
                            MessageTemplate::kForInOfLoopInitializer,
                            ForEachStatement::VisitModeString(for_info->mode));
    return impl()->NullStatement();
  }

  BlockT init_block = impl()->RewriteForVarInLegacy(*for_info);

  auto loop = factory()->NewForEachStatement(for_info->mode, stmt_pos);
  Target target(this, loop, labels, own_labels, Target::TARGET_FOR_ANONYMOUS);

  ExpressionT enumerable = impl()->NullExpression();
  if (for_info->mode == ForEachStatement::ITERATE) {
    AcceptINScope scope(this, true);
    enumerable = ParseAssignmentExpression();
  } else {
    enumerable = ParseExpression();
  }

  Expect(Token::kRightParen);

  ExpressionT each_variable = impl()->NullExpression();
  BlockT body_block = impl()->NullBlock();
  {
    BlockState block_state(&scope_, inner_block_scope);

    SourceRange body_range;
    StatementT body = impl()->NullStatement();
    {
      SourceRangeScope range_scope(scanner(), &body_range);
      body = ParseStatement(nullptr, nullptr);
    }
    impl()->RecordIterationStatementSourceRange(loop, body_range);

    impl()->DesugarBindingInForEachStatement(for_info, &body_block,
                                             &each_variable);
    body_block->statements()->Add(body, zone());

    if (IsLexicalVariableMode(for_info->parsing_result.descriptor.mode)) {
      scope()->set_end_position(end_position());
      body_block->set_scope(scope()->FinalizeBlockScope());
    }
  }

  loop->Initialize(each_variable, enumerable, body_block);

  init_block = impl()->CreateForEachStatementTDZ(init_block, *for_info);

  // Parsed for-in loop w/ variable declarations.
  if (!impl()->IsNull(init_block)) {
    init_block->statements()->Add(loop, zone());
    if (IsLexicalVariableMode(for_info->parsing_result.descriptor.mode)) {
      scope()->set_end_position(end_position());
      init_block->set_scope(scope()->FinalizeBlockScope());
    }
    return init_block;
  }

  return loop;
}

template <typename Impl>
typename ParserBase<Impl>::StatementT
ParserBase<Impl>::ParseForEachStatementWithoutDeclarations(
    int stmt_pos, ExpressionT expression, int lhs_beg_pos, int lhs_end_pos,
    ForInfo* for_info, ZonePtrList<const AstRawString>* labels,
    ZonePtrList<const AstRawString>* own_labels) {
  auto loop = factory()->NewForEachStatement(for_info->mode, stmt_pos);
  Target target(this, loop, labels, own_labels, Target::TARGET_FOR_ANONYMOUS);

  ExpressionT enumerable = impl()->NullExpression();
  if (for_info->mode == ForEachStatement::ITERATE) {
    AcceptINScope scope(this, true);
    enumerable = ParseAssignmentExpression();
  } else {
    enumerable = ParseExpression();
  }

  Expect(Token::kRightParen);

  StatementT body = impl()->NullStatement();
  SourceRange body_range;
  {
    SourceRangeScope range_scope(scanner(), &body_range);
    body = ParseStatement(nullptr, nullptr);
  }
  impl()->RecordIterationStatementSourceRange(loop, body_range);
  RETURN_IF_PARSE_ERROR;
  loop->Initialize(expression, enumerable, body);
  return loop;
}

template <typename Impl>
typename ParserBase<Impl>::StatementT
ParserBase<Impl>::ParseStandardForLoopWithLexicalDeclarations(
    int stmt_pos, StatementT init, ForInfo* for_info,
    ZonePtrList<const AstRawString>* labels,
    ZonePtrList<const AstRawString>* own_labels) {
  // The condition and the next statement of the for loop must be parsed
  // in a new scope.
  Scope* inner_scope = NewScope(BLOCK_SCOPE);
  ForStatementT loop = impl()->NullStatement();
  ExpressionT cond = impl()->NullExpression();
  StatementT next = impl()->NullStatement();
  StatementT body = impl()->NullStatement();
  {
    BlockState block_state(&scope_, inner_scope);
    scope()->set_start_position(scanner()->location().beg_pos);
    loop =
        ParseStandardForLoop(stmt_pos, labels, own_labels, &cond, &next, &body);
    RETURN_IF_PARSE_ERROR;
    scope()->set_end_position(end_position());
  }

  scope()->set_end_position(end_position());
  if (for_info->bound_names.length() > 0 &&
      function_state_->contains_function_or_eval()) {
    scope()->set_is_hidden();
    return impl()->DesugarLexicalBindingsInForStatement(
        loop, init, cond, next, body, inner_scope, *for_info);
  } else {
    inner_scope = inner_scope->FinalizeBlockScope();
    DCHECK_NULL(inner_scope);
    USE(inner_scope);
  }

  Scope* for_scope = scope()->FinalizeBlockScope();
  if (for_scope != nullptr) {
    // Rewrite a for statement of the form
    //   for (const x = i; c; n) b
    //
    // into
    //
    //   {
    //     const x = i;
    //     for (; c; n) b
    //   }
    //
    DCHECK(!impl()->IsNull(init));
    BlockT block = factory()->NewBlock(2, false);
    block->statements()->Add(init, zone());
    block->statements()->Add(loop, zone());
    block->set_scope(for_scope);
    loop->Initialize(impl()->NullStatement(), cond, next, body);
    return block;
  }

  loop->Initialize(init, cond, next, body);
  return loop;
}

template <typename Impl>
typename ParserBase<Impl>::ForStatementT ParserBase<Impl>::ParseStandardForLoop(
    int stmt_pos, ZonePtrList<const AstRawString>* labels,
    ZonePtrList<const AstRawString>* own_labels, ExpressionT* cond,
    StatementT* next, StatementT* body) {
  CheckStackOverflow();
  ForStatementT loop = factory()->NewForStatement(stmt_pos);
  Target target(this, loop, labels, own_labels, Target::TARGET_FOR_ANONYMOUS);

  if (peek() != Token::kSemicolon) {
    *cond = ParseExpression();
  }
  Expect(Token::kSemicolon);

  if (peek() != Token::kRightParen) {
    ExpressionT exp = ParseExpression();
    *next = factory()->NewExpressionStatement(exp, exp->position());
  }
  Expect(Token::kRightParen);

  SourceRange body_range;
  {
    SourceRangeScope range_scope(scanner(), &body_range);
    *body = ParseStatement(nullptr, nullptr);
  }
  impl()->RecordIterationStatementSourceRange(loop, body_range);

  return loop;
}

template <typename Impl>
typename ParserBase<Impl>::StatementT ParserBase<Impl>::ParseForAwaitStatement(
    ZonePtrList<const AstRawString>* labels,
    ZonePtrList<const AstRawString>* own_labels) {
  // for await '(' ForDeclaration of AssignmentExpression ')'
  DCHECK(is_await_allowed());
  typename FunctionState::LoopScope loop_scope(function_state_);

  int stmt_pos = peek_position();

  ForInfo for_info(this);
  for_info.mode = ForEachStatement::ITERATE;

  // Create an in-between scope for let-bound iteration variables.
  BlockState for_state(zone(), &scope_);
  Expect(Token::kFor);
  Expect(Token::kAwait);
  Expect(Token::kLeftParen);
  scope()->set_start_position(position());
  scope()->set_is_hidden();

  auto loop = factory()->NewForOfStatement(stmt_pos, IteratorType::kAsync);
  // Two suspends: one for next() and one for return()
  function_state_->AddSuspend();
  function_state_->AddSuspend();

  Target target(this, loop, labels, own_labels, Target::TARGET_FOR_ANONYMOUS);

  ExpressionT each_variable = impl()->NullExpression();

  bool has_declarations = false;
  Scope* inner_block_scope = NewScope(BLOCK_SCOPE);
  inner_block_scope->set_start_position(peek_position());

  bool starts_with_let = peek() == Token::kLet;
  if (peek() == Token::kVar || peek() == Token::kConst ||
      (starts_with_let && IsNextLetKeyword()) || IfStartsWithUsingKeyword()) {
    // The initializer contains declarations
    // 'for' 'await' '(' ForDeclaration 'of' AssignmentExpression ')'
    //     Statement
    // 'for' 'await' '(' 'var' ForBinding 'of' AssignmentExpression ')'
    //     Statement
    has_declarations = true;

    {
      BlockState inner_state(&scope_, inner_block_scope);
      ParseVariableDeclarations(kForStatement, &for_info.parsing_result,
                                &for_info.bound_names);
    }
    for_info.position = position();

    // Only a single declaration is allowed in for-await-of loops
    if (for_info.parsing_result.declarations.size() != 1) {
      impl()->ReportMessageAt(for_info.parsing_result.bindings_loc,
                              MessageTemplate::kForInOfLoopMultiBindings,
                              "for-await-of");
      return impl()->NullStatement();
    }

    // for-await-of's declarations do not permit initializers.
    if (for_info.parsing_result.first_initializer_loc.IsValid()) {
      impl()->ReportMessageAt(for_info.parsing_result.first_initializer_loc,
                              MessageTemplate::kForInOfLoopInitializer,
                              "for-await-of");
      return impl()->NullStatement();
    }
  } else {
    // The initializer does not contain declarations.
    // 'for' 'await' '(' LeftHandSideExpression 'of' AssignmentExpression ')'
    //     Statement
    if (starts_with_let) {
      impl()->ReportMessageAt(scanner()->peek_location(),
                              MessageTemplate::kForOfLet);
      return impl()->NullStatement();
    }
    int lhs_beg_pos = peek_position();
    BlockState inner_state(&scope_, inner_block_scope);
    ExpressionParsingScope parsing_scope(impl());
    ExpressionT lhs = each_variable = ParseLeftHandSideExpression();
    int lhs_end_pos = end_position();

    if (lhs->IsPattern()) {
      parsing_scope.ValidatePattern(lhs, lhs_beg_pos, lhs_end_pos);
    } else {
      each_variable = parsing_scope.ValidateAndRewriteReference(
          lhs, lhs_beg_pos, lhs_end_pos);
    }
  }

  ExpectContextualKeyword(Token::kOf);

  const bool kAllowIn = true;
  ExpressionT iterable = impl()->NullExpression();

  {
    AcceptINScope scope(this, kAllowIn);
    iterable = ParseAssignmentExpression();
  }

  Expect(Token::kRightParen);

  StatementT body = impl()->NullStatement();
  {
    BlockState block_state(&scope_, inner_block_scope);

    SourceRange body_range;
    {
      SourceRangeScope range_scope(scanner(), &body_range);
      body = ParseStatement(nullptr, nullptr);
      scope()->set_end_position(end_position());
    }
    impl()->RecordIterationStatementSourceRange(loop, body_range);

    if (has_declarations) {
      BlockT body_block = impl()->NullBlock();
      impl()->DesugarBindingInForEachStatement(&for_info, &body_block,
                                               &each_variable);
      body_block->statements()->Add(body, zone());
      body_block->set_scope(scope()->FinalizeBlockScope());
      body = body_block;
    } else {
      Scope* block_scope = scope()->FinalizeBlockScope();
      DCHECK_NULL(block_scope);
      USE(block_scope);
    }
  }

  loop->Initialize(each_variable, iterable, body);

  if (!has_declarations) {
    Scope* for_scope = scope()->FinalizeBlockScope();
    DCHECK_NULL(for_scope);
    USE(for_scope);
    return loop;
  }

  BlockT init_block =
      impl()->CreateForEachStatementTDZ(impl()->NullBlock(), for_info);

  scope()->set_end_position(end_position());
  Scope* for_scope = scope()->FinalizeBlockScope();
  // Parsed for-in loop w/ variable declarations.
  if (!impl()->IsNull(init_block)) {
    init_block->state
"""


```