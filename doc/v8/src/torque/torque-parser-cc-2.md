Response:
The user is asking for a summary of the functionalities present in the provided C++ code snippet from `v8/src/torque/torque-parser.cc`. This is part 3 of a 4-part series, implying previous parts likely covered earlier sections of the file.

Here's a breakdown of the thought process to achieve the desired summary:

1. **Identify the Core Task:** The primary function of this code is parsing Torque source code. This involves taking textual input and converting it into an Abstract Syntax Tree (AST) representation.

2. **Analyze the Code Structure:** The code consists of numerous functions named `Make...`, suggesting they are factory or builder functions for creating AST nodes. The `ParseResultIterator` parameter in these functions indicates they are processing results from a parsing process.

3. **Focus on Key Data Structures:** The code deals with various grammatical constructs: statements (`WhileStatement`, `ReturnStatement`, `VarDeclarationStatement`, etc.), expressions (`IdentifierExpression`, `FieldAccessExpression`, `AssignmentExpression`, etc.), and types (`BasicTypeExpression`, `UnionTypeExpression`, etc.). The `ParseResult` structure likely encapsulates these parsed elements.

4. **Examine Specific Functionalities:**  Go through each `Make...` function and understand what grammatical construct it handles. Pay attention to the logic within each function, especially how they desugar more complex constructs (like `typeswitch`).

5. **Look for Connections to JavaScript:** The presence of types like `JSAny` and `JSMessageObject` hints at interaction with JavaScript concepts. The desugaring of `typeswitch` also seems related to JavaScript's type-checking mechanisms.

6. **Identify Potential Programming Errors:**  The code includes checks for naming conventions (`IsLowerCamelCase`, `IsUpperCamelCase`) and type consistency, which can be sources of programming errors.

7. **Consider Input and Output:** For code logic (like the `typeswitch` desugaring), think about a simple input and what the resulting AST structure would represent.

8. **Address the `.tq` File Extension:**  The prompt explicitly mentions `.tq` files, which reinforces the idea that this parser is for the Torque language.

9. **Structure the Summary:** Organize the findings into clear categories:
    * Core functionality (parsing Torque).
    * Handling of various statements and expressions.
    * Desugaring of complex constructs.
    * Connection to JavaScript (with examples).
    * Code logic examples (input/output for `typeswitch`).
    * Common programming errors.

10. **Refine and Elaborate:**  Expand on the initial points with more details. For instance, instead of just saying "handles statements," list some of the specific statement types. For the JavaScript connection, provide a concrete JavaScript example that relates to the `typeswitch` functionality.

11. **Self-Correction/Refinement during thought process:**
    * Initially, I might just think of this as "parsing." But it's more specific: parsing *Torque*.
    * When seeing the `typeswitch` desugaring, I should actively try to understand *why* it's being desugared that way and what the resulting structure represents. This leads to the connection with JavaScript's type checking.
    * The naming convention checks are a good indicator of common programming errors that the parser is designed to catch.

By following these steps, I can generate a comprehensive and accurate summary of the provided code snippet.
```cpp
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
  for (size_t i = 0;i < handlers.size(); ++i) {
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
        Rule({annotations, element}, MakeExtendedVectorIfAnnotation<T
### 提示词
```
这是目录为v8/src/torque/torque-parser.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/torque/torque-parser.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
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
                NonemptyList<LabelAndTypes>(&labelP
```