Response: The user wants a summary of the C++ code provided, specifically the `v8/src/torque/torque-parser.cc` file (part 2 of 2). The summary should focus on the functionalities implemented in this code snippet and its relationship with JavaScript.

**Plan:**

1. **Identify the main structures and functions:** Look for function definitions prefixed with `Make...` which are likely responsible for parsing and creating intermediate representation (AST) nodes.
2. **Categorize the functionalities:** Group the `Make...` functions based on the language constructs they handle (e.g., statements, expressions, declarations).
3. **Analyze the logic within `MakeTypeswitchStatement`:**  This function seems important and has a clear desugaring example.
4. **Examine the relationship with JavaScript:** Look for keywords or concepts that are similar to JavaScript. The desugaring of `typeswitch` into nested `try...catch` suggests a connection to exception handling, which exists in JavaScript.
5. **Provide a JavaScript example:**  Illustrate the `typeswitch` functionality with a corresponding JavaScript example demonstrating similar type checking and branching.
这是 `v8/src/torque/torque-parser.cc` 文件的第二部分，延续了第一部分的功能，主要负责将 Torque 语言的文本解析成抽象语法树 (AST)。

**归纳其功能：**

这部分代码主要定义了用于创建各种 Torque 语言 AST 节点的函数。这些函数通常以 `Make` 开头，并对应于 Torque 语法中的不同结构，例如：

* **语句 (Statements):**  定义了如何创建 `if`、`typeswitch`、`while`、`return`、`tailcall`、`var` 声明、`break`、`continue`、`goto`、`block`、`try...label`、`for` 等语句的 AST 节点。
* **表达式 (Expressions):**  定义了如何创建标识符、字段访问、元素访问、解引用、结构体字面量、赋值、字面量（浮点数、整数、字符串）、自增自减、逻辑运算、条件表达式等表达式的 AST 节点。
* **声明 (Declarations):** 虽然大部分声明相关的逻辑可能在第一部分，但这里仍然涉及一些辅助类型或结构体的创建，例如 `EnumEntry`、`ClassFieldExpression`、`StructFieldExpression`、`BitFieldDeclaration`。
* **辅助结构体和类型:** 定义了诸如 `TypeswitchCase`、`LabelAndTypes`、`NameAndType`、`NameAndExpression`、`Annotation` 等辅助结构体，用于中间表示和解析过程。
* **语法规则 (Grammar Rules):** 定义了 Torque 语言的语法规则，使用类似 BNF 的形式描述了各种语法结构的组成。这些规则定义了如何将词法单元组合成更大的语法结构，并最终调用相应的 `Make` 函数创建 AST 节点。
* **错误处理和约定检查:**  代码中包含了一些错误报告机制（例如 `ReportError`，`Error`）和命名约定检查（例如 `IsLowerCamelCase`，`IsUpperCamelCase`），用于在解析过程中发现并报告错误。
* **辅助函数:**  定义了一些辅助函数，例如用于处理注解 (`AnnotationSet`)，以及用于从解析结果中提取特定信息的函数（例如 `ExtractAssignmentOperator`）。

**与 JavaScript 的关系及示例：**

Torque 是一种用于定义 V8 引擎内部实现的语言。它用于生成高效的 C++ 代码，这些代码实现了 JavaScript 语言的各种特性和内置函数。

这部分代码中，与 JavaScript 功能最直接相关的例子是 **`MakeTypeswitchStatement` 函数**。它实现了 Torque 的 `typeswitch` 语句，该语句的功能类似于 JavaScript 中的根据变量类型执行不同代码块的模式。

**Torque 的 `typeswitch` 语句会被“脱糖” (desugared) 成一系列嵌套的 `try...label` 语句**，这实际上是在模拟一种基于类型判断的控制流。

让我们用一个简单的例子来说明：

**Torque 代码 (假设的语法):**

```torque
typeswitch (value) {
  case (str : String) {
    Print("It's a string: " + str);
  }
  case (num : Number) {
    Print("It's a number: " + num);
  }
  default {
    Print("It's something else.");
  }
}
```

**`MakeTypeswitchStatement` 函数会将上述 Torque 代码转换成类似以下的结构 (简化版):**

```c++
{
  const _value = value;
  try {
    const str : String = Cast<String>(_value) otherwise _NextCase1;
    // ... 处理字符串的情况
  } label _NextCase1 {
    try {
      const num : Number = Cast<Number>(AssumeTypeImpossible<String>(_value));
      // ... 处理数字的情况
    } label _NextCase2 {
      // ... 处理默认情况
    }
  }
}
```

**在 JavaScript 中，虽然没有直接的 `typeswitch` 语句，但可以使用 `typeof` 运算符和 `if...else if...else` 结构来实现类似的功能：**

```javascript
let value = /* ... 某个值 */;

if (typeof value === 'string') {
  console.log("It's a string: " + value);
} else if (typeof value === 'number') {
  console.log("It's a number: " + value);
} else {
  console.log("It's something else.");
}
```

**或者使用更现代的模式匹配 (虽然 JavaScript 目前还没有原生的模式匹配，但可以通过一些库或提案实现):**

```javascript
let value = /* ... 某个值 */;

switch (true) {
  case typeof value === 'string':
    console.log("It's a string: " + value);
    break;
  case typeof value === 'number':
    console.log("It's a number: " + value);
    break;
  default:
    console.log("It's something else.");
}
```

**总结：**

这部分 `torque-parser.cc` 代码是 Torque 语言解析器的核心组成部分，它定义了如何将 Torque 代码转换成内部的 AST 表示。 `MakeTypeswitchStatement` 函数就是一个很好的例子，展示了 Torque 如何提供类似于 JavaScript 中类型检查和分支的功能，并通过脱糖转换成更底层的控制流结构。 总体来说，这个文件是 V8 引擎使用 Torque 语言进行内部开发的关键部分。

Prompt: 
```
这是目录为v8/src/torque/torque-parser.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
TypeswitchCase>>();
  CurrentSourcePosition::Scope matched_input_current_source_position(
      child_results->matched_input().pos);

  // typeswitch (expression) case (x1 : T1) {
  //   ...b1
  // } case (x2 : T2) {
  //   ...b2
  // } case (x3 : T3) {
  //   ...b3
  // }
  //
  // desugars to
  //
  // {
  //   const _value = expression;
  //   try {
  //     const x1 : T1 = cast<T1>(_value) otherwise _NextCase;
  //     ...b1
  //   } label _NextCase {
  //     try {
  //       const x2 : T2 = cast<T2>(%assume_impossible<T1>(_value));
  //       ...b2
  //     } label _NextCase {
  //       const x3 : T3 = %assume_impossible<T1|T2>(_value);
  //       ...b3
  //     }
  //   }
  // }

  BlockStatement* current_block = MakeNode<BlockStatement>();
  Statement* result = current_block;
  {
    CurrentSourcePosition::Scope current_source_position(expression->pos);
    current_block->statements.push_back(MakeNode<VarDeclarationStatement>(
        true, MakeNode<Identifier>("__value"), std::nullopt, expression));
  }

  TypeExpression* accumulated_types;
  for (size_t i = 0; i < cases.size(); ++i) {
    CurrentSourcePosition::Scope current_source_position(cases[i].pos);
    Expression* value =
        MakeNode<IdentifierExpression>(MakeNode<Identifier>("__value"));
    if (i >= 1) {
      value =
          MakeNode<AssumeTypeImpossibleExpression>(accumulated_types, value);
    }
    BlockStatement* case_block;
    if (i < cases.size() - 1) {
      value = MakeCall(MakeNode<Identifier>("Cast"),
                       std::vector<TypeExpression*>{cases[i].type},
                       std::vector<Expression*>{value},
                       std::vector<Statement*>{MakeNode<ExpressionStatement>(
                           MakeNode<IdentifierExpression>(
                               MakeNode<Identifier>(kNextCaseLabelName)))});
      case_block = MakeNode<BlockStatement>();
    } else {
      case_block = current_block;
    }
    Identifier* name =
        cases[i].name ? *cases[i].name : MakeNode<Identifier>("__case_value");
    if (cases[i].name) name = *cases[i].name;
    case_block->statements.push_back(
        MakeNode<VarDeclarationStatement>(true, name, cases[i].type, value));
    case_block->statements.push_back(cases[i].block);
    if (i < cases.size() - 1) {
      BlockStatement* next_block = MakeNode<BlockStatement>();
      current_block->statements.push_back(
          MakeNode<ExpressionStatement>(MakeNode<TryLabelExpression>(
              MakeNode<StatementExpression>(case_block),
              MakeNode<TryHandler>(TryHandler::HandlerKind::kLabel,
                                   MakeNode<Identifier>(kNextCaseLabelName),
                                   ParameterList::Empty(), next_block))));
      current_block = next_block;
    }
    accumulated_types =
        i > 0 ? MakeNode<UnionTypeExpression>(accumulated_types, cases[i].type)
              : cases[i].type;
  }
  return ParseResult{result};
}

std::optional<ParseResult> MakeTypeswitchCase(
    ParseResultIterator* child_results) {
  auto name = child_results->NextAs<std::optional<Identifier*>>();
  auto type = child_results->NextAs<TypeExpression*>();
  auto block = child_results->NextAs<Statement*>();
  return ParseResult{
      TypeswitchCase{child_results->matched_input().pos, name, type, block}};
}

std::optional<ParseResult> MakeWhileStatement(
    ParseResultIterator* child_results) {
  auto condition = child_results->NextAs<Expression*>();
  auto body = child_results->NextAs<Statement*>();
  Statement* result = MakeNode<WhileStatement>(condition, body);
  CheckNotDeferredStatement(result);
  return ParseResult{result};
}

std::optional<ParseResult> MakeReturnStatement(
    ParseResultIterator* child_results) {
  auto value = child_results->NextAs<std::optional<Expression*>>();
  Statement* result = MakeNode<ReturnStatement>(value);
  return ParseResult{result};
}

std::optional<ParseResult> MakeTailCallStatement(
    ParseResultIterator* child_results) {
  auto value = child_results->NextAs<Expression*>();
  Statement* result = MakeNode<TailCallStatement>(CallExpression::cast(value));
  return ParseResult{result};
}

std::optional<ParseResult> MakeVarDeclarationStatement(
    ParseResultIterator* child_results) {
  auto kind = child_results->NextAs<Identifier*>();
  bool const_qualified = kind->value == "const";
  if (!const_qualified) DCHECK_EQ("let", kind->value);
  auto name = child_results->NextAs<Identifier*>();
  if (!IsLowerCamelCase(name->value)) {
    NamingConventionError("Variable", name, "lowerCamelCase");
  }

  auto type = child_results->NextAs<std::optional<TypeExpression*>>();
  std::optional<Expression*> initializer;
  if (child_results->HasNext())
    initializer = child_results->NextAs<Expression*>();
  if (!initializer && !type) {
    ReportError("Declaration is missing a type.");
  }
  Statement* result = MakeNode<VarDeclarationStatement>(const_qualified, name,
                                                        type, initializer);
  return ParseResult{result};
}

std::optional<ParseResult> MakeBreakStatement(
    ParseResultIterator* child_results) {
  Statement* result = MakeNode<BreakStatement>();
  return ParseResult{result};
}

std::optional<ParseResult> MakeContinueStatement(
    ParseResultIterator* child_results) {
  Statement* result = MakeNode<ContinueStatement>();
  return ParseResult{result};
}

std::optional<ParseResult> MakeGotoStatement(
    ParseResultIterator* child_results) {
  auto label = child_results->NextAs<Identifier*>();
  auto arguments = child_results->NextAs<std::vector<Expression*>>();
  Statement* result = MakeNode<GotoStatement>(label, std::move(arguments));
  return ParseResult{result};
}

std::optional<ParseResult> MakeBlockStatement(
    ParseResultIterator* child_results) {
  auto deferred = child_results->NextAs<bool>();
  auto statements = child_results->NextAs<std::vector<Statement*>>();
  for (Statement* statement : statements) {
    CheckNotDeferredStatement(statement);
  }
  Statement* result = MakeNode<BlockStatement>(deferred, std::move(statements));
  return ParseResult{result};
}

std::optional<ParseResult> MakeTryLabelExpression(
    ParseResultIterator* child_results) {
  auto try_block = child_results->NextAs<Statement*>();
  CheckNotDeferredStatement(try_block);
  Statement* result = try_block;
  auto handlers = child_results->NextAs<std::vector<TryHandler*>>();
  if (handlers.empty()) {
    Error("Try blocks without catch or label don't make sense.");
  }
  for (size_t i = 0; i < handlers.size(); ++i) {
    if (i != 0 &&
        handlers[i]->handler_kind == TryHandler::HandlerKind::kCatch) {
      Error(
          "A catch handler always has to be first, before any label handler, "
          "to avoid ambiguity about whether it catches exceptions from "
          "preceding handlers or not.")
          .Position(handlers[i]->pos);
    }
    result = MakeNode<ExpressionStatement>(MakeNode<TryLabelExpression>(
        MakeNode<StatementExpression>(result), handlers[i]));
  }
  return ParseResult{result};
}

std::optional<ParseResult> MakeForLoopStatement(
    ParseResultIterator* child_results) {
  auto var_decl = child_results->NextAs<std::optional<Statement*>>();
  auto test = child_results->NextAs<std::optional<Expression*>>();
  auto action = child_results->NextAs<std::optional<Expression*>>();
  std::optional<Statement*> action_stmt;
  if (action) action_stmt = MakeNode<ExpressionStatement>(*action);
  auto body = child_results->NextAs<Statement*>();
  CheckNotDeferredStatement(body);
  Statement* result =
      MakeNode<ForLoopStatement>(var_decl, test, action_stmt, body);
  return ParseResult{result};
}

std::optional<ParseResult> MakeLabelBlock(ParseResultIterator* child_results) {
  auto label = child_results->NextAs<Identifier*>();
  if (!IsUpperCamelCase(label->value)) {
    NamingConventionError("Label", label, "UpperCamelCase");
  }
  auto parameters = child_results->NextAs<ParameterList>();
  auto body = child_results->NextAs<Statement*>();
  TryHandler* result = MakeNode<TryHandler>(TryHandler::HandlerKind::kLabel,
                                            label, std::move(parameters), body);
  return ParseResult{result};
}

std::optional<ParseResult> MakeCatchBlock(ParseResultIterator* child_results) {
  auto parameter_names = child_results->NextAs<std::vector<std::string>>();
  auto body = child_results->NextAs<Statement*>();
  for (const std::string& variable : parameter_names) {
    if (!IsLowerCamelCase(variable)) {
      NamingConventionError("Exception", variable, "lowerCamelCase");
    }
  }
  if (parameter_names.size() != 2) {
    ReportError(
        "A catch clause needs to have exactly two parameters: The exception "
        "and the message. How about: \"catch (exception, message) { ...\".");
  }
  ParameterList parameters;

  parameters.names.push_back(MakeNode<Identifier>(parameter_names[0]));
  parameters.types.push_back(MakeNode<BasicTypeExpression>(
      std::vector<std::string>{}, MakeNode<Identifier>("JSAny"),
      std::vector<TypeExpression*>{}));
  parameters.names.push_back(MakeNode<Identifier>(parameter_names[1]));
  parameters.types.push_back(MakeNode<UnionTypeExpression>(
      MakeNode<BasicTypeExpression>(std::vector<std::string>{},
                                    MakeNode<Identifier>("JSMessageObject"),
                                    std::vector<TypeExpression*>{}),
      MakeNode<BasicTypeExpression>(std::vector<std::string>{},
                                    MakeNode<Identifier>("TheHole"),
                                    std::vector<TypeExpression*>{})));
  parameters.has_varargs = false;
  TryHandler* result = MakeNode<TryHandler>(
      TryHandler::HandlerKind::kCatch, MakeNode<Identifier>(kCatchLabelName),
      std::move(parameters), body);
  return ParseResult{result};
}

std::optional<ParseResult> MakeExpressionWithSource(
    ParseResultIterator* child_results) {
  auto e = child_results->NextAs<Expression*>();
  return ParseResult{
      ExpressionWithSource{e, child_results->matched_input().ToString()}};
}

std::optional<ParseResult> MakeIdentifier(ParseResultIterator* child_results) {
  auto name = child_results->NextAs<std::string>();
  Identifier* result = MakeNode<Identifier>(std::move(name));
  return ParseResult{result};
}

std::optional<ParseResult> MakeIdentifierFromMatchedInput(
    ParseResultIterator* child_results) {
  return ParseResult{
      MakeNode<Identifier>(child_results->matched_input().ToString())};
}

std::optional<ParseResult> MakeRightShiftIdentifier(
    ParseResultIterator* child_results) {
  std::string str = child_results->matched_input().ToString();
  for (auto character : str) {
    if (character != '>') {
      ReportError("right-shift operators may not contain any whitespace");
    }
  }
  return ParseResult{MakeNode<Identifier>(str)};
}

std::optional<ParseResult> MakeNamespaceQualification(
    ParseResultIterator* child_results) {
  bool global_namespace = child_results->NextAs<bool>();
  auto namespace_qualification =
      child_results->NextAs<std::vector<std::string>>();
  if (global_namespace) {
    namespace_qualification.insert(namespace_qualification.begin(), "");
  }
  return ParseResult(std::move(namespace_qualification));
}

std::optional<ParseResult> MakeIdentifierExpression(
    ParseResultIterator* child_results) {
  auto namespace_qualification =
      child_results->NextAs<std::vector<std::string>>();
  auto name = child_results->NextAs<Identifier*>();
  auto generic_arguments =
      child_results->NextAs<std::vector<TypeExpression*>>();
  Expression* result = MakeNode<IdentifierExpression>(
      std::move(namespace_qualification), name, std::move(generic_arguments));
  return ParseResult{result};
}

std::optional<ParseResult> MakeFieldAccessExpression(
    ParseResultIterator* child_results) {
  auto object = child_results->NextAs<Expression*>();
  auto field = child_results->NextAs<Identifier*>();
  Expression* result = MakeNode<FieldAccessExpression>(object, field);
  return ParseResult{result};
}

std::optional<ParseResult> MakeReferenceFieldAccessExpression(
    ParseResultIterator* child_results) {
  auto object = child_results->NextAs<Expression*>();
  auto field = child_results->NextAs<Identifier*>();
  // `a->b` is equivalent to `(*a).b`.
  Expression* deref = MakeNode<DereferenceExpression>(object);
  Expression* result = MakeNode<FieldAccessExpression>(deref, field);
  return ParseResult{result};
}

std::optional<ParseResult> MakeElementAccessExpression(
    ParseResultIterator* child_results) {
  auto object = child_results->NextAs<Expression*>();
  auto field = child_results->NextAs<Expression*>();
  Expression* result = MakeNode<ElementAccessExpression>(object, field);
  return ParseResult{result};
}

std::optional<ParseResult> MakeDereferenceExpression(
    ParseResultIterator* child_results) {
  auto reference = child_results->NextAs<Expression*>();
  Expression* result = MakeNode<DereferenceExpression>(reference);
  return ParseResult{result};
}

std::optional<ParseResult> MakeStructExpression(
    ParseResultIterator* child_results) {
  auto type = child_results->NextAs<TypeExpression*>();
  auto initializers = child_results->NextAs<std::vector<NameAndExpression>>();
  Expression* result =
      MakeNode<StructExpression>(type, std::move(initializers));
  return ParseResult{result};
}

std::optional<ParseResult> MakeAssignmentExpression(
    ParseResultIterator* child_results) {
  auto location = child_results->NextAs<Expression*>();
  auto op = child_results->NextAs<std::optional<std::string>>();
  auto value = child_results->NextAs<Expression*>();
  Expression* result =
      MakeNode<AssignmentExpression>(location, std::move(op), value);
  return ParseResult{result};
}

std::optional<ParseResult> MakeFloatingPointLiteralExpression(
    ParseResultIterator* child_results) {
  auto value = child_results->NextAs<double>();
  Expression* result = MakeNode<FloatingPointLiteralExpression>(value);
  return ParseResult{result};
}

std::optional<ParseResult> MakeIntegerLiteralExpression(
    ParseResultIterator* child_results) {
  auto value = child_results->NextAs<IntegerLiteral>();
  Expression* result = MakeNode<IntegerLiteralExpression>(std::move(value));
  return ParseResult{result};
}

std::optional<ParseResult> MakeStringLiteralExpression(
    ParseResultIterator* child_results) {
  auto literal = child_results->NextAs<std::string>();
  Expression* result = MakeNode<StringLiteralExpression>(std::move(literal));
  return ParseResult{result};
}

std::optional<ParseResult> MakeIncrementDecrementExpressionPostfix(
    ParseResultIterator* child_results) {
  auto location = child_results->NextAs<Expression*>();
  auto op = child_results->NextAs<IncrementDecrementOperator>();
  Expression* result =
      MakeNode<IncrementDecrementExpression>(location, op, true);
  return ParseResult{result};
}

std::optional<ParseResult> MakeIncrementDecrementExpressionPrefix(
    ParseResultIterator* child_results) {
  auto op = child_results->NextAs<IncrementDecrementOperator>();
  auto location = child_results->NextAs<Expression*>();
  Expression* result =
      MakeNode<IncrementDecrementExpression>(location, op, false);
  return ParseResult{result};
}

std::optional<ParseResult> MakeLogicalOrExpression(
    ParseResultIterator* child_results) {
  auto left = child_results->NextAs<Expression*>();
  auto right = child_results->NextAs<Expression*>();
  Expression* result = MakeNode<LogicalOrExpression>(left, right);
  return ParseResult{result};
}

std::optional<ParseResult> MakeLogicalAndExpression(
    ParseResultIterator* child_results) {
  auto left = child_results->NextAs<Expression*>();
  auto right = child_results->NextAs<Expression*>();
  Expression* result = MakeNode<LogicalAndExpression>(left, right);
  return ParseResult{result};
}

std::optional<ParseResult> MakeConditionalExpression(
    ParseResultIterator* child_results) {
  auto condition = child_results->NextAs<Expression*>();
  auto if_true = child_results->NextAs<Expression*>();
  auto if_false = child_results->NextAs<Expression*>();
  Expression* result =
      MakeNode<ConditionalExpression>(condition, if_true, if_false);
  return ParseResult{result};
}

std::optional<ParseResult> MakeLabelAndTypes(
    ParseResultIterator* child_results) {
  auto name = child_results->NextAs<Identifier*>();
  if (!IsUpperCamelCase(name->value)) {
    NamingConventionError("Label", name, "UpperCamelCase");
  }
  auto types = child_results->NextAs<std::vector<TypeExpression*>>();
  return ParseResult{LabelAndTypes{name, std::move(types)}};
}

std::optional<ParseResult> MakeNameAndType(ParseResultIterator* child_results) {
  auto name = child_results->NextAs<Identifier*>();
  auto type = child_results->NextAs<TypeExpression*>();
  return ParseResult{NameAndTypeExpression{name, type}};
}

std::optional<ParseResult> MakeEnumEntry(ParseResultIterator* child_results) {
  AnnotationSet annotations(child_results, {}, {ANNOTATION_SAME_ENUM_VALUE_AS});
  std::vector<ConditionalAnnotation> conditions;
  std::optional<std::string> alias_entry =
      annotations.GetStringParam(ANNOTATION_SAME_ENUM_VALUE_AS);

  auto name = child_results->NextAs<Identifier*>();
  auto type = child_results->NextAs<std::optional<TypeExpression*>>();
  return ParseResult{EnumEntry{name, type, alias_entry}};
}

std::optional<ParseResult> MakeNameAndExpression(
    ParseResultIterator* child_results) {
  auto name = child_results->NextAs<Identifier*>();
  auto expression = child_results->NextAs<Expression*>();
  return ParseResult{NameAndExpression{name, expression}};
}

std::optional<ParseResult> MakeNameAndExpressionFromExpression(
    ParseResultIterator* child_results) {
  auto expression = child_results->NextAs<Expression*>();
  if (auto* id = IdentifierExpression::DynamicCast(expression)) {
    if (!id->generic_arguments.empty() ||
        !id->namespace_qualification.empty()) {
      ReportError("expected a plain identifier without qualification");
    }
    return ParseResult{NameAndExpression{id->name, id}};
  }
  ReportError("Constructor parameters need to be named.");
}

std::optional<ParseResult> MakeAnnotation(ParseResultIterator* child_results) {
  return ParseResult{
      Annotation{child_results->NextAs<Identifier*>(),
                 child_results->NextAs<std::optional<AnnotationParameter>>()}};
}

std::optional<ParseResult> MakeClassField(ParseResultIterator* child_results) {
  AnnotationSet annotations(
      child_results,
      {ANNOTATION_CPP_RELAXED_STORE, ANNOTATION_CPP_RELAXED_LOAD,
       ANNOTATION_CPP_RELEASE_STORE, ANNOTATION_CPP_ACQUIRE_LOAD,
       ANNOTATION_CUSTOM_WEAK_MARKING},
      {ANNOTATION_IF, ANNOTATION_IFNOT});
  FieldSynchronization synchronization = FieldSynchronization::kNone;
  if (annotations.Contains(ANNOTATION_CPP_RELEASE_STORE)) {
    synchronization = FieldSynchronization::kAcquireRelease;
  } else if (annotations.Contains(ANNOTATION_CPP_RELAXED_STORE)) {
    synchronization = FieldSynchronization::kRelaxed;
  }
  {
    FieldSynchronization read_synchronization = FieldSynchronization::kNone;
    if (annotations.Contains(ANNOTATION_CPP_ACQUIRE_LOAD)) {
      read_synchronization = FieldSynchronization::kAcquireRelease;
    } else if (annotations.Contains(ANNOTATION_CPP_RELAXED_LOAD)) {
      read_synchronization = FieldSynchronization::kRelaxed;
    }
    if (read_synchronization != synchronization) {
      Error("Incompatible read/write synchronization annotations for a field.");
    }
  }
  std::vector<ConditionalAnnotation> conditions;
  std::optional<std::string> if_condition =
      annotations.GetStringParam(ANNOTATION_IF);
  std::optional<std::string> ifnot_condition =
      annotations.GetStringParam(ANNOTATION_IFNOT);
  if (if_condition.has_value()) {
    conditions.push_back({*if_condition, ConditionalAnnotationType::kPositive});
  }
  if (ifnot_condition.has_value()) {
    conditions.push_back(
        {*ifnot_condition, ConditionalAnnotationType::kNegative});
  }
  bool custom_weak_marking =
      annotations.Contains(ANNOTATION_CUSTOM_WEAK_MARKING);
  auto deprecated_weak = child_results->NextAs<bool>();
  if (deprecated_weak) {
    Error(
        "The keyword 'weak' is deprecated. For a field that can contain a "
        "normal weak pointer, use type Weak<T>. For a field that should be "
        "marked in some custom way, use @customWeakMarking.");
    custom_weak_marking = true;
  }
  auto const_qualified = child_results->NextAs<bool>();
  auto name = child_results->NextAs<Identifier*>();
  auto optional = child_results->NextAs<bool>();
  auto index = child_results->NextAs<std::optional<Expression*>>();
  if (optional && !index) {
    Error(
        "Fields using optional specifier must also provide an expression "
        "indicating the condition for whether the field is present");
  }
  std::optional<ClassFieldIndexInfo> index_info;
  if (index) {
    if (optional) {
      // Internally, an optional field is just an indexed field where the count
      // is zero or one.
      index = MakeNode<ConditionalExpression>(
          *index,
          MakeCall(
              MakeNode<Identifier>("FromConstexpr"),
              {MakeNode<BasicTypeExpression>(std::vector<std::string>{},
                                             MakeNode<Identifier>("intptr"),
                                             std::vector<TypeExpression*>{})},
              {MakeNode<IntegerLiteralExpression>(IntegerLiteral(1))}, {}),
          MakeCall(
              MakeNode<Identifier>("FromConstexpr"),
              {MakeNode<BasicTypeExpression>(std::vector<std::string>{},
                                             MakeNode<Identifier>("intptr"),
                                             std::vector<TypeExpression*>{})},
              {MakeNode<IntegerLiteralExpression>(IntegerLiteral(0))}, {}));
    }
    index_info = ClassFieldIndexInfo{*index, optional};
  }
  auto type = child_results->NextAs<TypeExpression*>();
  return ParseResult{ClassFieldExpression{{name, type},
                                          index_info,
                                          std::move(conditions),
                                          custom_weak_marking,
                                          const_qualified,
                                          synchronization}};
}

std::optional<ParseResult> MakeStructField(ParseResultIterator* child_results) {
  auto const_qualified = child_results->NextAs<bool>();
  auto name = child_results->NextAs<Identifier*>();
  auto type = child_results->NextAs<TypeExpression*>();
  return ParseResult{StructFieldExpression{{name, type}, const_qualified}};
}

std::optional<ParseResult> MakeBitFieldDeclaration(
    ParseResultIterator* child_results) {
  auto name = child_results->NextAs<Identifier*>();
  auto type = child_results->NextAs<TypeExpression*>();
  auto num_bits = child_results->NextAs<int32_t>();
  return ParseResult{BitFieldDeclaration{{name, type}, num_bits}};
}

std::optional<ParseResult> ExtractAssignmentOperator(
    ParseResultIterator* child_results) {
  auto op = child_results->NextAs<Identifier*>();
  std::optional<std::string> result =
      std::string(op->value.begin(), op->value.end() - 1);
  return ParseResult(std::move(result));
}

struct TorqueGrammar : Grammar {
  static bool MatchWhitespace(InputPosition* pos) {
    while (true) {
      if (MatchChar(std::isspace, pos)) continue;
      if (MatchString("//", pos)) {
        while (MatchChar([](char c) { return c != '\n'; }, pos)) {
        }
        continue;
      }
      if (MatchString("/*", pos)) {
        while (!MatchString("*/", pos)) ++*pos;
        continue;
      }
      return true;
    }
  }

  static bool MatchIdentifier(InputPosition* pos) {
    InputPosition current = *pos;
    MatchString("_", &current);
    if (!MatchChar(std::isalpha, &current)) return false;
    while (MatchChar(std::isalnum, &current) || MatchString("_", &current)) {
    }
    *pos = current;
    return true;
  }

  static bool MatchAnnotation(InputPosition* pos) {
    InputPosition current = *pos;
    if (!MatchString("@", &current)) return false;
    if (!MatchIdentifier(&current)) return false;
    *pos = current;
    return true;
  }

  static bool MatchIntrinsicName(InputPosition* pos) {
    InputPosition current = *pos;
    if (!MatchString("%", &current)) return false;
    if (!MatchIdentifier(&current)) return false;
    *pos = current;
    return true;
  }

  static bool MatchStringLiteral(InputPosition* pos) {
    InputPosition current = *pos;
    if (MatchString("\"", &current)) {
      while (
          (MatchString("\\", &current) && MatchAnyChar(&current)) ||
          MatchChar([](char c) { return c != '"' && c != '\n'; }, &current)) {
      }
      if (MatchString("\"", &current)) {
        *pos = current;
        return true;
      }
    }
    current = *pos;
    if (MatchString("'", &current)) {
      while (
          (MatchString("\\", &current) && MatchAnyChar(&current)) ||
          MatchChar([](char c) { return c != '\'' && c != '\n'; }, &current)) {
      }
      if (MatchString("'", &current)) {
        *pos = current;
        return true;
      }
    }
    return false;
  }

  static bool MatchHexLiteral(InputPosition* pos) {
    InputPosition current = *pos;
    MatchString("-", &current);
    if (MatchString("0x", &current) && MatchChar(std::isxdigit, &current)) {
      while (MatchChar(std::isxdigit, &current)) {
      }
      *pos = current;
      return true;
    }
    return false;
  }

  static bool MatchIntegerLiteral(InputPosition* pos) {
    InputPosition current = *pos;
    bool found_digit = false;
    MatchString("-", &current);
    while (MatchChar(std::isdigit, &current)) found_digit = true;
    if (found_digit) {
      *pos = current;
      return true;
    }
    return false;
  }

  static bool MatchFloatingPointLiteral(InputPosition* pos) {
    InputPosition current = *pos;
    bool found_digit = false;
    MatchString("-", &current);
    while (MatchChar(std::isdigit, &current)) found_digit = true;
    if (!MatchString(".", &current)) return false;
    while (MatchChar(std::isdigit, &current)) found_digit = true;
    if (!found_digit) return false;
    *pos = current;
    if ((MatchString("e", &current) || MatchString("E", &current)) &&
        (MatchString("+", &current) || MatchString("-", &current) || true) &&
        MatchChar(std::isdigit, &current)) {
      while (MatchChar(std::isdigit, &current)) {
      }
      *pos = current;
      return true;
    }
    return true;
  }

  template <class T, bool first>
  static std::optional<ParseResult> MakeExtendedVectorIfAnnotation(
      ParseResultIterator* child_results) {
    std::vector<T> l = {};
    if (!first) l = child_results->NextAs<std::vector<T>>();
    bool enabled = ProcessIfAnnotation(child_results);
    T x = child_results->NextAs<T>();

    if (enabled) l.push_back(std::move(x));
    return ParseResult{std::move(l)};
  }

  template <class T>
  Symbol* NonemptyListAllowIfAnnotation(Symbol* element,
                                        std::optional<Symbol*> separator = {}) {
    Symbol* list = NewSymbol();
    *list = {
        Rule({annotations, element}, MakeExtendedVectorIfAnnotation<T, true>),
        separator ? Rule({list, annotations, *separator, element},
                         MakeExtendedVectorIfAnnotation<T, false>)
                  : Rule({list, annotations, element},
                         MakeExtendedVectorIfAnnotation<T, false>)};
    return list;
  }

  template <class T>
  Symbol* ListAllowIfAnnotation(Symbol* element,
                                std::optional<Symbol*> separator = {}) {
    return TryOrDefault<std::vector<T>>(
        NonemptyListAllowIfAnnotation<T>(element, separator));
  }

  TorqueGrammar() : Grammar(&file) { SetWhitespace(MatchWhitespace); }

  // Result: Expression*
  Symbol* expression = &assignmentExpression;

  // Result: std::string
  Symbol identifier = {Rule({Pattern(MatchIdentifier)}, YieldMatchedInput),
                       Rule({Token("runtime")}, YieldMatchedInput)};

  // Result: Identifier*
  Symbol name = {Rule({&identifier}, MakeIdentifier)};

  // Result: Identifier*
  Symbol annotationName = {
      Rule({Pattern(MatchAnnotation)}, MakeIdentifierFromMatchedInput)};

  // Result: std::string
  Symbol intrinsicName = {
      Rule({Pattern(MatchIntrinsicName)}, MakeIdentifierFromMatchedInput)};

  // Result: std::string
  Symbol stringLiteral = {
      Rule({Pattern(MatchStringLiteral)}, YieldMatchedInput)};

  // Result: std::string
  Symbol externalString = {Rule({&stringLiteral}, StringLiteralUnquoteAction)};

  // Result: IntegerLiteral
  Symbol integerLiteral = {
      Rule({Pattern(MatchIntegerLiteral)}, YieldIntegerLiteral),
      Rule({Pattern(MatchHexLiteral)}, YieldIntegerLiteral)};

  // Result: double
  Symbol floatingPointLiteral = {
      Rule({Pattern(MatchFloatingPointLiteral)}, YieldDouble)};

  // Result: int32_t
  Symbol int32Literal = {Rule({Pattern(MatchIntegerLiteral)}, YieldInt32),
                         Rule({Pattern(MatchHexLiteral)}, YieldInt32)};

  // Result: AnnotationParameter
  Symbol annotationParameter = {
      Rule({&identifier}, MakeStringAnnotationParameter),
      Rule({&int32Literal}, MakeIntAnnotationParameter),
      Rule({&externalString}, MakeStringAnnotationParameter)};

  // Result: AnnotationParameter
  Symbol annotationParameters = {
      Rule({Token("("), &annotationParameter, Token(")")})};

  // Result: Annotation
  Symbol annotation = {Rule(
      {&annotationName, Optional<AnnotationParameter>(&annotationParameters)},
      MakeAnnotation)};

  // Result: std::vector<Annotation>
  Symbol* annotations = List<Annotation>(&annotation);

  // Result: std::vector<std::string>
  Symbol namespaceQualification = {
      Rule({CheckIf(Token("::")),
            List<std::string>(Sequence({&identifier, Token("::")}))},
           MakeNamespaceQualification)};

  // Result: TypeList
  Symbol* typeList = List<TypeExpression*>(&type, Token(","));

  // Result: TypeExpression*
  Symbol simpleType = {
      Rule({Token("("), &type, Token(")")}),
      Rule({&namespaceQualification, CheckIf(Token("constexpr")), &identifier,
            TryOrDefault<std::vector<TypeExpression*>>(
                &genericSpecializationTypeList)},
           MakeBasicTypeExpression),
      Rule({Token("builtin"), Token("("), typeList, Token(")"), Token("=>"),
            &simpleType},
           MakeFunctionTypeExpression),
      Rule({CheckIf(Token("const")), Token("&"), &simpleType},
           MakeReferenceTypeExpression)};

  // Result: TypeExpression*
  Symbol type = {Rule({&simpleType}), Rule({&type, Token("|"), &simpleType},
                                           MakeUnionTypeExpression)};

  // Result: GenericParameter
  Symbol genericParameter = {
      Rule({&name, Token(":"), Token("type"),
            Optional<TypeExpression*>(Sequence({Token("extends"), &type}))},
           MakeGenericParameter)};

  // Result: GenericParameters
  Symbol genericParameters = {
      Rule({Token("<"), List<GenericParameter>(&genericParameter, Token(",")),
            Token(">")})};

  // Result: TypeList
  Symbol genericSpecializationTypeList = {
      Rule({Token("<"), typeList, Token(">")})};

  // Result: std::optional<GenericParameters>
  Symbol* optionalGenericParameters = Optional<TypeList>(&genericParameters);

  Symbol implicitParameterList{
      Rule({Token("("), OneOf({"implicit", "js-implicit"}),
            List<NameAndTypeExpression>(&nameAndType, Token(",")), Token(")")},
           MakeImplicitParameterList)};

  Symbol* optionalImplicitParameterList{
      Optional<ImplicitParameters>(&implicitParameterList)};

  // Result: ParameterList
  Symbol typeListMaybeVarArgs = {
      Rule({optionalImplicitParameterList, Token("("),
            List<TypeExpression*>(Sequence({&type, Token(",")})), Token("..."),
            Token(")")},
           MakeParameterList<true, false>),
      Rule({optionalImplicitParameterList, Token("("), typeList, Token(")")},
           MakeParameterList<false, false>)};

  // Result: LabelAndTypes
  Symbol labelParameter = {Rule(
      {&name,
       TryOrDefault<TypeList>(Sequence({Token("("), typeList, Token(")")}))},
      MakeLabelAndTypes)};

  // Result: TypeExpression*
  Symbol returnType = {Rule({Token(":"), &type}),
                       Rule({}, DeprecatedMakeVoidType)};

  // Result: LabelAndTypesVector
  Symbol* optionalLabelList{TryOrDefault<LabelAndTypesVector>(
      Sequence({Token("labels"),
                NonemptyList<LabelAndTypes>(&labelParameter, Token(","))}))};

  // Result: std::vector<Statement*>
  Symbol* optionalOtherwise{TryOrDefault<std::vector<Statement*>>(
      Sequence({Token("otherwise"),
                NonemptyList<Statement*>(&atomarStatement, Token(","))}))};

  // Result: NameAndTypeExpression
  Symbol nameAndType = {Rule({&name, Token(":"), &type}, MakeNameAndType)};

  // Result: std::optional<Expression*>
  Symbol* optionalArraySpecifier =
      Optional<Expression*>(Sequence({Token("["), expression, Token("]")}));

  // Result: ClassFieldExpression
  Symbol classField = {
      Rule({annotations, CheckIf(Token("weak")), CheckIf(Token("const")), &name,
            CheckIf(Token("?")), optionalArraySpecifier, Token(":"), &type,
            Token(";")},
           MakeClassField)};

  // Result: StructFieldExpression
  Symbol structField = {
      Rule({CheckIf(Token("const")), &name, Token(":"), &type, Token(";")},
           MakeStructField)};

  // Result: BitFieldDeclaration
  Symbol bitFieldDeclaration = {Rule({&name, Token(":"), &type, Token(":"),
                                      &int32Literal, Token("bit"), Token(";")},
                                     MakeBitFieldDeclaration)};

  // Result: ParameterList
  Symbol parameterListNoVararg = {
      Rule({optionalImplicitParameterList, Token("("),
            List<NameAndTypeExpression>(&nameAndType, Token(",")), Token(")")},
           MakeParameterList<false, true>)};

  // Result: ParameterList
  Symbol parameterListAllowVararg = {
      Rule({&parameterListNoVararg}),
      Rule({optionalImplicitParameterList, Token("("),
            List<NameAndTypeExpression>(Sequence({&nameAndType, Token(",")})),
            Token("..."), &identifier, Token(")")},
           MakeParameterList<true, true>)};

  // Result: Identifier*
  Symbol* OneOf(const std::vector<std::string>& alternatives) {
    Symbol* result = NewSymbol();
    for (const std::string& s : alternatives) {
      result->AddRule(Rule({Token(s)}, MakeIdentifierFromMatchedInput));
    }
    return result;
  }

  // Result: Expression*
  Symbol* BinaryOperator(Symbol* nextLevel, Symbol* op) {
    Symbol* result = NewSymbol();
    *result = {Rule({nextLevel}),
               Rule({result, op, nextLevel}, MakeBinaryOperator)};
    return result;
  }

  // Result: IncrementDecrementOperator
  Symbol incrementDecrementOperator = {
      Rule({Token("++")},
           YieldIntegralConstant<IncrementDecrementOperator,
                                 IncrementDecrementOperator::kIncrement>),
      Rule({Token("--")},
           YieldIntegralConstant<IncrementDecrementOperator,
                                 IncrementDecrementOperator::kDecrement>)};

  // Result: Expression*
  Symbol identifierExpression = {
      Rule({&namespaceQualification, &name,
            TryOrDefault<TypeList>(&genericSpecializationTypeList)},
           MakeIdentifierExpression),
  };

  // Result: std::vector<Expression*>
  Symbol argumentList = {Rule(
      {Token("("), List<Expression*>(expression, Token(",")), Token(")")})};

  // Result: Expression*
  Symbol callExpression = {Rule(
      {&identifierExpression, &argumentList, optionalOtherwise}, MakeCall)};

  // Result: Expression*
  Symbol callMethodExpression = {Rule(
      {&primaryExpression, Token("."), &name, &argumentList, optionalOtherwise},
      MakeMethodCall)};

  // Result: NameAndExpression
  Symbol namedExpression = {
      Rule({&name, Token(":"), expression}, MakeNameAndExpression),
      Rule({expression}, MakeNameAndExpressionFromExpression)};

  // Result: std::vector<NameAndExpression>
  Symbol initializerList = {
      Rule({Token("{"), List<NameAndExpression>(&namedExpression, Token(",")),
            Token("}")})};

  // Result: Expression*
  Symbol intrinsicCallExpression = {Rule(
      {&intrinsicName, TryOrDefault<TypeList>(&genericSpecializationTypeList),
       &argumentList},
      MakeIntrinsicCallExpression)};

  // Result: Expression*
  Symbol newExpression = {
      Rule({Token("new"),
            CheckIf(Sequence({Token("("), Token("Pretenured"), Token(")")})),
            CheckIf(Sequence({Token("("), Token("ClearPadding"), Token(")")})),
            &simpleType, &initializerList},
           MakeNewExpression)};

  // Result: Expression*
  Symbol primaryExpression = {
      Rule({&callExpression}),
      Rule({&callMethodExpression}),
      Rule({&intrinsicCallExpression}),
      Rule({&identifierExpression}),
      Rule({&primaryExpression, Token("."), &name}, MakeFieldAccessExpression),
      Rule({&primaryExpression, Token("->"), &name},
           MakeReferenceFieldAccessExpression),
      Rule({&primaryExpression, Token("["), expression, Token("]")},
           MakeElementAccessExpression),
      Rule({&integerLiteral}, MakeIntegerLiteralExpression),
      Rule({&floatingPointLiteral}, MakeFloatingPointLiteralExpression),
      Rule({&stringLiteral}, MakeStringLiteralExpression),
      Rule({&simpleType, &initializerList}, MakeStructExpression),
      Rule({&newExpression}),
      Rule({Token("("), expression, Token(")")})};

  // Result: Expression*
  Symbol unaryExpression = {
      Rule({&primaryExpression}),
      Rule({OneOf({"+", "-", "!", "~", "&"}), &unaryExpression},
           MakeUnaryOperator),
      Rule({Token("*"), &unaryExpression}, MakeDereferenceExpression),
      Rule({Token("..."), &unaryExpression}, MakeSpreadExpression),
      Rule({&incrementDecrementOperator, &unaryExpression},
           MakeIncrementDecrementExpressionPrefix),
      Rule({&unaryExpression, &incrementDecrementOperator},
           MakeIncrementDecrementExpressionPostfix)};

  // Result: Expression*
  Symbol* multiplicativeExpression =
      BinaryOperator(&unaryExpression, OneOf({"*", "/", "%"}));

  // Result: Expression*
  Symbol* additiveExpression =
      BinaryOperator(multiplicativeExpression, OneOf({"+", "-"}));

  // Result: Identifier*
  Symbol shiftOperator = {
      Rule({Token("<<")}, MakeIdentifierFromMatchedInput),
      Rule({Token(">"), Token(">")}, MakeRightShiftIdentifier),
      Rule({Token(">"), Token(">"), Token(">")}, MakeRightShiftIdentifier)};

  // Result: Expression*
  Symbol* shiftExpression = BinaryOperator(additiveExpression, &shiftOperator);

  // Do not allow expressions like a < b > c because this is never
  // useful and ambiguous with template parameters.
  // Result: Expression*
  Symbol relationalExpression = {
      Rule({shiftExpression}),
      Rule({shiftExpression, OneOf({"<", ">", "<=", ">="}), shiftExpression},
           MakeBinaryOperator)};

  // Result: Expression*
  Symbol* equalityExpression =
      BinaryOperator(&relationalExpression, OneOf({"==", "!="}));

  // Result: Expression*
  Symbol* bitwiseExpression =
      BinaryOperator(equalityExpression, OneOf({"&", "|"}));

  // Result: Expression*
  Symbol logicalAndExpression = {
      Rule({bitwiseExpression}),
      Rule({&logicalAndExpression, Token("&&"), bitwiseExpression},
           MakeLogicalAndExpression)};

  // Result: Expression*
  Symbol logicalOrExpression = {
      Rule({&logicalAndExpression}),
      Rule({&logicalOrExpression, Token("||"), &logicalAndExpression},
           MakeLogicalOrExpression)};

  // Result: Expression*
  Symbol conditionalExpression = {
      Rule({&logicalOrExpression}),
      Rule({&logicalOrExpression, Token("?"), expression, Token(":"),
            &conditionalExpression},
           MakeConditionalExpression)};

  // Result: std::optional<std::string>
  Symbol assignmentOperator = {
      Rule({Token("=")}, YieldDefaultValue<std::optional<std::string>>),
      Rule({OneOf({"*=", "/=", "%=", "+=", "-=", "<<=", ">>=", ">>>=", "&=",
                   "^=", "|="})},
           ExtractAssignmentOperator)};

  // Result: Expression*
  Symbol assignmentExpression = {
      Rule({&conditionalExpression}),
      Rule({&conditionalExpression, &assignmentOperator, &assignmentExpression},
           MakeAssignmentExpression)};

  // Result: Statement*
  Symbol block = {
      Rule({CheckIf(Token("deferred")), Token("{"),
            ListAllowIfAnnotation<Statement*>(&statement), Token("}")},
           MakeBlockStatement)};

  // Result: TryHandler*
  Symbol tryHandler = {
      Rule({Token("label"), &name,
            TryOrDefault<ParameterList>(&parameterListNoVararg), &block},
           MakeLabelBlock),
      Rule({Token("catch"), Token("("),
            List<std::string>(&identifier, Token(",")), Token(")"), &block},
           MakeCatchBlock)};

  // Result: ExpressionWithSource
  Symbol expressionWithSource = {Rule({expression}, MakeExpressionWithSource)};

  Symbol* optionalTypeSpecifier =
      Optional<TypeExpression*>(Sequence({Token(":"), &type}));

  // Result: EnumEntry
  Symbol enumEntry = {
      Rule({annotations, &name, optionalTypeSpecifier}, MakeEnumEntry)};

  // Result: Statement*
  Symbol varDeclaration = {
      Rule({OneOf({"let", "const"}), &name, optionalTypeSpecifier},
           MakeVarDeclarationStatement)};

  // Result: Statement*
  Symbol varDeclarationWithInitialization = {
      Rule({OneOf({"let", "const"}), &name, optionalTypeSpecifier, Token("="),
            expression},
           MakeVarDeclarationStatement)};

  // Result: Statement*
  Symbol atomarStatement = {
      Rule({expression}, MakeExpressionStatement),
      Rule({Token("return"), Optional<Expression*>(expression)},
           MakeReturnStatement),
      Rule({Token("tail"), &callExpression}, MakeTailCallStatement),
      Rule({Token("break")}, MakeBreakStatement),
      Rule({Token("continue")}, MakeContinueStatement),
      Rule({Token("goto"), &name,
            TryOrDefault<std::vector<Expression*>>(&argumentList)},
           MakeGotoStatement),
      Rule({OneOf({"debug", "unreachable"})}, MakeDebugStatement)};

  // Result: Statement*
  Symbol statement = {
      Rule({&block}),
      Rule({&atomarStatement, Token(";")}),
      Rule({&varDeclaration, Token(";")}),
      Rule({&varDeclarationWithInitialization, Token(";")}),
      Rule({Token("if"), CheckIf(Token("constexpr")), Token("("), expression,
            Token(")"), &statement,
            Optional<Statement*>(Sequence({Token("else"), &statement}))},
           MakeIfStatement),
      Rule(
          {
              Token("typeswitch"),
              Token("("),
              expression,
              Token(")"),
              Token("{"),
              NonemptyListAllowIfAnnotation<TypeswitchCase>(&typeswitchCase),
              Token("}"),
          },
          MakeTypeswitchStatement),
      Rule({Token("try"), &block, List<TryHandler*>(&tryHandler)},
           MakeTryLabelExpression),
      Rule({OneOf({"dcheck", "check", "sbxcheck", "static_assert"}), Token("("),
            &expressionWithSource, Token(")"), Token(";")},
           MakeAssertStatement),
      Rule({Token("while"), Token("("), expression, Token(")"), &statement},
           MakeWhileStatement),
      Rule({Token("for"), Token("("),
            Optional<Statement*>(&varDeclarationWithInitialization), Token(";"),
            Optional<Expression*>(expression), Token(";"),
            Optional<Expression*>(expression), Token(")"), &statement},
           MakeForLoopStatement)};

  // Result: TypeswitchCase
  Symbol typeswitchCase = {
      Rule({Token("case"), Token("("),
            Optional<Identifier*>(Sequence({&name, Token(":")})), &type,
            Token(")"), Token(":"), &block},
           MakeTypeswitchCase)};

  // Result: std::optional<Statement*>
  Symbol optionalBody = {
      Rule({&block}, CastParseResult<Statement*, std::optional<Statement*>>),
      Rule({Token(";")}, YieldDefaultValue<std::optional<Statement*>>)};

  // Result: Declaration*
  Symbol method = {Rule(
      {CheckIf(Token("transitioning")),
       Optional<std::string>(Sequence({Token("operator"), &externalString})),
       Token("macro"), &name, &parameterListNoVararg, &returnType,
       optionalLabelList, &block},
      MakeMethodDeclaration)};

  // Result: std::optional<ClassBody*>
  Symbol optionalClassBody = {
      Rule({Token("{"), List<Declaration*>(&method),
            List<ClassFieldExpression>(&classField), Token("}")},
           MakeClassBody),
      Rule({Token(";")}, YieldDefaultValue<std::optional<ClassBody*>>)};

  // Result: std::vector<Declaration*>
  Symbol declaration = {
      Rule({Token("const"), &name, Token(":"), &type, Token("="), expression,
            Token(";")},
           AsSingletonVector<Declaration*, MakeConstDeclaration>()),
      Rule({Token("const"), &name, Token(":"), &type, Token("generates"),
            &externalString, Token(";")},
           AsSingletonVector<Declaration*, MakeExternConstDeclaration>()),
      Rule({annotations, CheckIf(Token("extern")), CheckIf(Token("transient")),
            OneOf({"class", "shape"}), &name, Token("extends"), &type,
            Optional<std::string>(
                Sequence({Token("generates"), &externalString})),
            &optionalClassBody},
           MakeClassDeclaration),
      Rule({annotations, Token("struct"), &name,
            TryOrDefault<GenericParameters>(&genericParameters), Token("{"),
            ListAllowIfAnnotation<Declaration*>(&method),
            ListAllowIfAnnotation<StructFieldExpression>(&structField),
            Token("}")},
           AsSingletonVector<Declaration*, MakeStructDeclaration>()),
      Rule({Token("bitfield"), Token("struct"), &name, Token("extends"), &type,
            Token("{"),
            ListAllowIfAnnotation<BitFieldDeclaration>(&bitFieldDeclaration),
            Token("}")},
           AsSingletonVector<Declaration*, MakeBitFieldStructDeclaration>()),
      Rule({annotations, CheckIf(Token("transient")), Token("type"), &name,
            TryOrDefault<GenericParameters>(&genericParameters),
            Optional<TypeExpression*>(Sequence({Token("extends"), &type})),
            Optional<std::string>(
                Sequence({Token("generates"), &externalString})),
            Optional<std::string>(
                Sequence({Token("constexpr"), &externalString})),
            Token(";")},
           MakeAbstractTypeDeclaration),
      Rule({annotations, Token("type"), &name, Token("="), &type, Token(";")},
           MakeTypeAliasDeclaration),
      Rule({Token("intrinsic"), &intrinsicName,
            TryOrDefault<GenericParameters>(&genericParameters),
            &parameterListNoVararg, &returnType, &optionalBody},
           AsSingletonVector<Declaration*, MakeIntrinsicDeclaration>()),
      Rule({Token("extern"), CheckIf(Token("transitioning")),
            Optional<std::string>(
                Sequence({Token("operator"), &externalString})),
            Token("macro"),
            Optional<std::string>(Sequence({&identifier, Token("::")})), &name,
            TryOrDefault<GenericParameters>(&genericParameters),
            &typeListMaybeVarArgs, &returnType, optionalLabelList, Token(";")},
           AsSingletonVector<Declaration*, MakeExternalMacro>()),
      Rule({Token("extern"), CheckIf(Token("transitioning")),
            CheckIf(Token("javascript")), Token("builtin"), &name,
            TryOrDefault<GenericParameters>(&genericParameters),
            &typeListMaybeVarArgs, &returnType, Token(";")},
           AsSingletonVector<Declaration*, MakeExternalBuiltin>()),
      Rule({Token("extern"), CheckIf(Token("transitioning")), Token("runtime"),
            &name, &typeListMaybeVarArgs, &returnType, Token(";")},
           AsSingletonVector<Declaration*, MakeExternalRuntime>()),
      Rule({annotations, CheckIf(Token("transitioning")),
            Optional<std::string>(
                Sequence({Token("operator"), &externalString})),
            Token("macro"), &name,
            TryOrDefault<GenericParameters>(&genericParameters),
            &parameterListNoVararg, &returnType, optionalLabelList,
            &optionalBody},
           AsSingletonVector<Declaration*, MakeTorqueMacroDeclaration>()),
      Rule({annotations, CheckIf(Token("transitioning")),
            CheckIf(Token("javascript")), Token("builtin"), &name,
            TryOrDefault<GenericParameters>(&genericParameters),
            &parameterListAllowVararg, &returnType, &optionalBody},
           MakeTorqueBuiltinDeclaration),
      Rule({CheckIf(Token("transitioning")), &name,
            &genericSpecializationTypeList, &parameterListAllowVararg,
            &returnType, optionalLabelList, &block},
           AsSingletonVector<Declaration*, MakeSpecializationDeclaration>()),
      Rule({Token("#include"), &externalString},
           AsSingletonVector<Declaration*, MakeCppIncludeDeclaration>()),
      Rule({CheckIf(Token("extern")), Token("enum"), &name,
            Optional<TypeExpression*>(Sequence({Token("extends"), &type})),
            Optional<std::string>(
                Sequence({Token("constexpr"), &externalString})),
            Token("{"),
            NonemptyListAllowIfAnnotation<EnumEntry>(&enumEntry, Token(",")),
            CheckIf(Sequence({Token(","), Token("...")})), Token("}")},
           MakeEnumDeclaration),
      Rule({Token("namespace"), &identifier, Token("{"), &declarationList,
            Token("}")},
           AsSingletonVector<Declaration*, MakeNamespaceDeclaration>())};

  // Result: std::vector<Declaration*>
  Symbol declarationList = {
      Rule({List<std::vector<Declaration*>>(&declaration)}, ConcatList)};

  Symbol file = {Rule({&file, Token("import"), &externalString},
                      ProcessTorqueImportDeclaration),
                 Rule({&file, &declaration}, AddGlobalDeclarations), Rule({})};
};

}  // namespace

void ParseTorque(const std::string& input) {
  BuildFlags::Scope build_flags_scope;
  TorqueGrammar().Parse(input);
}

}  // namespace v8::internal::torque

"""


```