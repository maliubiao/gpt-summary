Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/parsing/parser-base.h`. The request also includes specific constraints and questions to address:

1. **List functionalities:** Identify the main actions performed by the code.
2. **Torque source:** Check if the file ends with `.tq` to determine if it's a Torque source file.
3. **JavaScript relationship:**  If there's a connection to JavaScript features, illustrate with JavaScript examples.
4. **Code logic inference:** Present hypothetical inputs and outputs for code logic sections.
5. **Common programming errors:**  Point out potential user errors related to the code.
6. **Part of a series:** Acknowledge this is part 7 of 9 and provide a high-level summary.

Let's break down the code snippet and address each point:

* **Overall Structure:** The code defines template methods within the `ParserBase` class, suggesting this class provides foundational parsing logic. The `<typename Impl>` indicates a Curiously Recurring Template Pattern (CRTP), where `Impl` provides concrete parsing implementations.

* **Key Methods:** The snippet focuses on parsing class literals, async functions, template literals, error handling for invalid references, parameter classification, and statement parsing.

* **Class Literal Parsing (`ParseClassLiteral`, `ParseClassLiteralBody`):** This section handles the parsing of `class` declarations in JavaScript, including inheritance (`extends`), static blocks, and property definitions.

* **Async Function Parsing (`ParseAsyncFunctionLiteral`):**  This method parses JavaScript `async function` declarations.

* **Template Literal Parsing (`ParseTemplateLiteral`):**  Handles the parsing of template literals (backticks).

* **Error Handling (`RewriteInvalidReferenceExpression`):**  Deals with cases where an expression isn't a valid reference (e.g., on the left-hand side of an assignment).

* **Parameter Classification (`ClassifyParameter`, `ClassifyArrowParameter`):**  Checks for invalid parameter names in strict mode (like `eval` or `arguments`).

* **Statement Parsing (`ParseStatementList`, `ParseStatementListItem`, `ParseStatement`, `ParseBlock`, `ParseVariableStatement`, etc.):**  This large section handles parsing various JavaScript statements, including blocks, variable declarations, if statements, loops, try-catch, etc.

* **Torque Check:** The filename ends in `.h`, not `.tq`.

* **JavaScript Relationship:**  The code directly parses JavaScript syntax. The functionalities map almost one-to-one with JavaScript language constructs.

* **Code Logic Inference:**  The class literal parsing has clear steps. The statement parsing uses a switch statement to dispatch to specific parsers.

* **Common Errors:**  Misusing `eval` or `arguments` in strict mode parameters is a classic error. Incorrect syntax in class literals or template literals would also be caught.

* **Part 7 of 9:**  This likely represents a significant portion of the core parsing logic, focusing on expressions and statements.

**Plan:**

1. Start with the general functionalities of the code.
2. Confirm it's not Torque.
3. Provide JavaScript examples for the parsed constructs.
4. Create a simple input and expected output scenario for class literal parsing.
5. Give an example of the `eval`/`arguments` error.
6. Summarize the overall role within the larger parsing process.
```cpp
template <typename Impl>
typename ParserBase<Impl>::ExpressionT ParserBase<Impl>::ParseClassLiteral(
    IdentifierT name, int pos, bool is_anonymous) {
  // ClassDeclaration[Yield, Await, Default] :
  //   class BindingIdentifier[?Yield, ?Await] ClassTail[?Yield, ?Await]
  // ClassExpression[Yield, Await] :
  //   class BindingIdentifier[?Yield, ?Await]? ClassTail[?Yield, ?Await]
  // ClassTail[Yield, Await] :
  //   [Heritage[?Yield, ?Await]]opt { ClassBody[?Yield, ?Await]opt }

  int class_token_pos = pos;
  ClassScope class_scope(this, scope(), name);
  ClassScope::ScopeTracer tr(&class_scope);

  ClassInfo class_info(this);
  class_info.is_anonymous = is_anonymous;

  scope()->set_start_position(class_token_pos);
  if (Check(Token::kExtends)) {
    ClassScope::HeritageParsingScope heritage(class_scope);
    FuncNameInferrerState fni_state(&fni_);
    ExpressionParsingScope scope(impl());
    class_info.extends = ParseLeftHandSideExpression();
    scope.ValidateExpression();
  }

  Expect(Token::kLeftBrace);

  ParseClassLiteralBody(class_info, name, class_token_pos, Token::kRightBrace);

  VariableProxy* unresolvable = class_scope->ResolvePrivateNamesPartially();
  if (unresolvable != nullptr) {
    impl()->ReportMessageAt(Scanner::Location(unresolvable->position(),
                                              unresolvable->position() + 1),
                            MessageTemplate::kInvalidPrivateFieldResolution,
                            unresolvable->raw_name());
    return impl()->FailureExpression();
  }

  if (class_info.requires_brand) {
    class_scope->DeclareBrandVariable(
        ast_value_factory(), IsStaticFlag::kNotStatic, kNoSourcePosition);
  }

  if (class_scope->needs_home_object()) {
    class_info.home_object_variable =
        class_scope->DeclareHomeObjectVariable(ast_value_factory());
    class_info.static_home_object_variable =
        class_scope->DeclareStaticHomeObjectVariable(ast_value_factory());
  }

  bool should_save_class_variable_index =
      class_scope->should_save_class_variable_index();
  if (!class_info.is_anonymous || should_save_class_variable_index) {
    impl()->DeclareClassVariable(class_scope, name, &class_info,
                                 class_token_pos);
    if (should_save_class_variable_index) {
      class_scope->class_variable()->set_is_used();
      class_scope->class_variable()->ForceContextAllocation();
    }
  }

  return impl()->RewriteClassLiteral(class_scope, name, &class_info,
                                     class_token_pos);
}

template <typename Impl>
void ParserBase<Impl>::ParseClassLiteralBody(ClassInfo& class_info,
                                             IdentifierT name,
                                             int class_token_pos,
                                             Token::Value end_token) {
  bool has_extends = !impl()->IsNull(class_info.extends);

  while (peek() != end_token) {
    if (Check(Token::kSemicolon)) continue;

    // Either we're parsing a `static { }` initialization block or a property.
    if (peek() == Token::kStatic && PeekAhead() == Token::kLeftBrace) {
      BlockT static_block = ParseClassStaticBlock(&class_info);
      impl()->AddClassStaticBlock(static_block, &class_info);
      continue;
    }

    FuncNameInferrerState fni_state(&fni_);
    // If we haven't seen the constructor yet, it potentially is the next
    // property.
    bool is_constructor = !class_info.has_seen_constructor;
    ParsePropertyInfo prop_info(this);
    prop_info.position = PropertyPosition::kClassLiteral;

    ClassLiteralPropertyT property =
        ParseClassPropertyDefinition(&class_info, &prop_info, has_extends);

    if (has_error()) return;

    ClassLiteralProperty::Kind property_kind =
        ClassPropertyKindFor(prop_info.kind);

    if (!class_info.has_static_computed_names && prop_info.is_static &&
        prop_info.is_computed_name) {
      class_info.has_static_computed_names = true;
    }
    is_constructor &= class_info.has_seen_constructor;

    bool is_field = property_kind == ClassLiteralProperty::FIELD;

    if (V8_UNLIKELY(prop_info.is_private)) {
      DCHECK(!is_constructor);
      class_info.requires_brand |= (!is_field && !prop_info.is_static);
      class_info.has_static_private_methods_or_accessors |=
          (prop_info.is_static && !is_field);

      impl()->DeclarePrivateClassMember(scope()->AsClassScope(), prop_info.name,
                                        property, property_kind,
                                        prop_info.is_static, &class_info);
      impl()->InferFunctionName();
      continue;
    }

    if (V8_UNLIKELY(is_field)) {
      DCHECK(!prop_info.is_private);
      // If we're reparsing, we might not have a class scope. We only need a
      // class scope if we have a computed name though, and in that case we're
      // certain that the current scope must be a class scope.
      ClassScope* class_scope = nullptr;
      if (prop_info.is_computed_name) {
        class_info.computed_field_count++;
        class_scope = scope()->AsClassScope();
      }

      impl()->DeclarePublicClassField(class_scope, property,
                                      prop_info.is_static,
                                      prop_info.is_computed_name, &class_info);
      impl()->InferFunctionName();
      continue;
    }

    if (property_kind == ClassLiteralProperty::Kind::AUTO_ACCESSOR) {
      // Private auto-accessors are handled above with the other private
      // properties.
      DCHECK(!prop_info.is_private);
      impl()->AddInstanceFieldOrStaticElement(property, &class_info,
                                              prop_info.is_static);
    }

    impl()->DeclarePublicClassMethod(name, property, is_constructor,
                                     &class_info);
    impl()->InferFunctionName();
  }

  Expect(end_token);
  scope()->set_end_position(end_position());
}

template <typename Impl>
typename ParserBase<Impl>::ExpressionT
ParserBase<Impl>::ParseAsyncFunctionLiteral() {
  // AsyncFunctionLiteral ::
  //   async [no LineTerminator here] function ( FormalParameters[Await] )
  //       { AsyncFunctionBody }
  //
  //   async [no LineTerminator here] function BindingIdentifier[Await]
  //       ( FormalParameters[Await] ) { AsyncFunctionBody }
  DCHECK_EQ(scanner()->current_token(), Token::kAsync);
  if (V8_UNLIKELY(scanner()->literal_contains_escapes())) {
    impl()->ReportUnexpectedToken(Token::kEscapedKeyword);
  }
  int pos = position();
  Consume(Token::kFunction);
  IdentifierT name = impl()->NullIdentifier();
  FunctionSyntaxKind syntax_kind = FunctionSyntaxKind::kAnonymousExpression;

  ParseFunctionFlags flags = ParseFunctionFlag::kIsAsync;
  if (Check(Token::kMul)) flags |= ParseFunctionFlag::kIsGenerator;
  const FunctionKind kind = FunctionKindFor(flags);
  bool is_strict_reserved = Token::IsStrictReservedWord(peek());

  if (impl()->ParsingDynamicFunctionDeclaration()) {
    // We don't want dynamic functions to actually declare their name
    // "anonymous". We just want that name in the toString().

    // Consuming token we did not peek yet, which could lead to a kIllegal token
    // in the case of a stackoverflow.
    Consume(Token::kIdentifier);
    DCHECK_IMPLIES(!has_error(),
                   scanner()->CurrentSymbol(ast_value_factory()) ==
                       ast_value_factory()->anonymous_string());
  } else if (peek_any_identifier()) {
    syntax_kind = FunctionSyntaxKind::kNamedExpression;
    name = ParseIdentifier(kind);
  }
  FunctionLiteralT result = impl()->ParseFunctionLiteral(
      name, scanner()->location(),
      is_strict_reserved ? kFunctionNameIsStrictReserved
                         : kFunctionNameValidityUnknown,
      kind, pos, syntax_kind, language_mode(), nullptr);
  if (impl()->IsNull(result)) return impl()->FailureExpression();
  return result;
}

template <typename Impl>
typename ParserBase<Impl>::ExpressionT ParserBase<Impl>::ParseTemplateLiteral(
    ExpressionT tag, int start, bool tagged) {
  // A TemplateLiteral is made up of 0 or more kTemplateSpan tokens (literal
  // text followed by a substitution expression), finalized by a single
  // kTemplateTail.
  //
  // In terms of draft language, kTemplateSpan may be either the TemplateHead or
  // TemplateMiddle productions, while kTemplateTail is either TemplateTail, or
  // NoSubstitutionTemplate.
  //
  // When parsing a TemplateLiteral, we must have scanned either an initial
  // kTemplateSpan, or a kTemplateTail.
  DCHECK(peek() == Token::kTemplateSpan || peek() == Token::kTemplateTail);

  if (tagged) {
    // TaggedTemplate expressions prevent the eval compilation cache from being
    // used. This flag is only used if an eval is being parsed.
    set_allow_eval_cache(false);
  }

  bool forbid_illegal_escapes = !tagged;

  // If we reach a kTemplateTail first, we are parsing a NoSubstitutionTemplate.
  // In this case we may simply consume the token and build a template with a
  // single kTemplateSpan and no expressions.
  if (peek() == Token::kTemplateTail) {
    Consume(Token::kTemplateTail);
    int pos = position();
    typename Impl::TemplateLiteralState ts = impl()->OpenTemplateLiteral(pos);
    bool is_valid = CheckTemplateEscapes(forbid_illegal_escapes);
    impl()->AddTemplateSpan(&ts, is_valid, true);
    return impl()->CloseTemplateLiteral(&ts, start, tag);
  }

  Consume(Token::kTemplateSpan);
  int pos = position();
  typename Impl::TemplateLiteralState ts = impl()->OpenTemplateLiteral(pos);
  bool is_valid = CheckTemplateEscapes(forbid_illegal_escapes);
  impl()->AddTemplateSpan(&ts, is_valid, false);
  Token::Value next;

  // If we open with a kTemplateSpan, we must scan the subsequent expression,
  // and repeat if the following token is a kTemplateSpan as well (in this
  // case, representing a TemplateMiddle).

  do {
    next = peek();

    int expr_pos = peek_position();
    AcceptINScope scope(this, true);
    ExpressionT expression = ParseExpressionCoverGrammar();
    impl()->AddTemplateExpression(&ts, expression);

    if (peek() != Token::kRightBrace) {
      impl()->ReportMessageAt(Scanner::Location(expr_pos, peek_position()),
                              MessageTemplate::kUnterminatedTemplateExpr);
      return impl()->FailureExpression();
    }

    // If we didn't die parsing that expression, our next token should be a
    // kTemplateSpan or kTemplateTail.
    next = scanner()->ScanTemplateContinuation();
    Next();
    pos = position();

    is_valid = CheckTemplateEscapes(forbid_illegal_escapes);
    impl()->AddTemplateSpan(&ts, is_valid, next == Token::kTemplateTail);
  } while (next == Token::kTemplateSpan);

  DCHECK_IMPLIES(!has_error(), next == Token::kTemplateTail);
  // Once we've reached a kTemplateTail, we can close the TemplateLiteral.
  return impl()->CloseTemplateLiteral(&ts, start, tag);
}

template <typename Impl>
typename ParserBase<Impl>::ExpressionT
ParserBase<Impl>::RewriteInvalidReferenceExpression(ExpressionT expression,
                                                    int beg_pos, int end_pos,
                                                    MessageTemplate message,
                                                    bool early_error) {
  DCHECK(!IsValidReferenceExpression(expression));
  if (impl()->IsIdentifier(expression)) {
    DCHECK(is_strict(language_mode()));
    DCHECK(impl()->IsEvalOrArguments(impl()->AsIdentifier(expression)));

    ReportMessageAt(Scanner::Location(beg_pos, end_pos),
                    MessageTemplate::kStrictEvalArguments);
    return impl()->FailureExpression();
  }
  if (expression->IsCall() && !expression->AsCall()->is_tagged_template() &&
      !early_error) {
    expression_scope()->RecordPatternError(
        Scanner::Location(beg_pos, end_pos),
        MessageTemplate::kInvalidDestructuringTarget);
    // If it is a call, make it a runtime error for legacy web compatibility.
    // Bug: https://bugs.chromium.org/p/v8/issues/detail?id=4480
    // Rewrite `expr' to `expr[throw ReferenceError]'.
    impl()->CountUsage(
        is_strict(language_mode())
            ? v8::Isolate::kAssigmentExpressionLHSIsCallInStrict
            : v8::Isolate::kAssigmentExpressionLHSIsCallInSloppy);
    ExpressionT error = impl()->NewThrowReferenceError(message, beg_pos);
    return factory()->NewProperty(expression, error, beg_pos);
  }
  // Tagged templates and other modern language features (which pass early_error
  // = true) are exempt from the web compatibility hack. Throw a regular early
  // error.
  ReportMessageAt(Scanner::Location(beg_pos, end_pos), message);
  return impl()->FailureExpression();
}

template <typename Impl>
void ParserBase<Impl>::ClassifyParameter(IdentifierT parameter, int begin,
                                         int end) {
  if (impl()->IsEvalOrArguments(parameter)) {
    expression_scope()->RecordStrictModeParameterError(
        Scanner::Location(begin, end), MessageTemplate::kStrictEvalArguments);
  }
}

template <typename Impl>
void ParserBase<Impl>::ClassifyArrowParameter(
    AccumulationScope* accumulation_scope, int position,
    ExpressionT parameter) {
  accumulation_scope->Accumulate();
  if (parameter->is_parenthesized() ||
      !(impl()->IsIdentifier(parameter) || parameter->IsPattern() ||
        parameter->IsAssignment())) {
    expression_scope()->RecordDeclarationError(
        Scanner::Location(position, end_position()),
        MessageTemplate::kInvalidDestructuringTarget);
  } else if (impl()->IsIdentifier(parameter)) {
    ClassifyParameter(impl()->AsIdentifier(parameter), position,
                      end_position());
  } else {
    expression_scope()->RecordNonSimpleParameter();
  }
}

template <typename Impl>
bool ParserBase<Impl>::IsValidReferenceExpression(ExpressionT expression) {
  return IsAssignableIdentifier(expression) || expression->IsProperty();
}

template <typename Impl>
typename ParserBase<Impl>::ExpressionT
ParserBase<Impl>::ParsePossibleDestructuringSubPattern(
    AccumulationScope* scope) {
  if (scope) scope->Accumulate();
  int begin = peek_position();
  ExpressionT result = ParseAssignmentExpressionCoverGrammar();

  if (IsValidReferenceExpression(result)) {
    // Parenthesized identifiers and property references are allowed as part of
    // a larger assignment pattern, even though parenthesized patterns
    // themselves are not allowed, e.g., "[(x)] = []". Only accumulate
    // assignment pattern errors if the parsed expression is more complex.
    if (impl()->IsIdentifier(result)) {
      if (result->is_parenthesized()) {
        expression_scope()->RecordDeclarationError(
            Scanner::Location(begin, end_position()),
            MessageTemplate::kInvalidDestructuringTarget);
      }
      IdentifierT identifier = impl()->AsIdentifier(result);
      ClassifyParameter(identifier, begin, end_position());
    } else {
      DCHECK(result->IsProperty());
      expression_scope()->RecordDeclarationError(
          Scanner::Location(begin, end_position()),
          MessageTemplate::kInvalidPropertyBindingPattern);
      if (scope != nullptr) scope->ValidateExpression();
    }
  } else if (result->is_parenthesized() ||
             (!result->IsPattern() && !result->IsAssignment())) {
    expression_scope()->RecordPatternError(
        Scanner::Location(begin, end_position()),
        MessageTemplate::kInvalidDestructuringTarget);
  }

  return result;
}

template <typename Impl>
typename ParserBase<Impl>::ExpressionT ParserBase<Impl>::ParseV8Intrinsic() {
  // CallRuntime ::
  //   '%' Identifier Arguments

  int pos = peek_position();
  Consume(Token::kMod);
  // Allow "eval" or "arguments" for backward compatibility.
  IdentifierT name = ParseIdentifier();
  if (peek() != Token::kLeftParen) {
    impl()->ReportUnexpectedToken(peek());
    return impl()->FailureExpression();
  }
  bool has_spread;
  ExpressionListT args(pointer_buffer());
  ParseArguments(&args, &has_spread);

  if (has_spread) {
    ReportMessageAt(Scanner::Location(pos, position()),
                    MessageTemplate::kIntrinsicWithSpread);
    return impl()->FailureExpression();
  }

  return impl()->NewV8Intrinsic(name, args, pos);
}

template <typename Impl>
void ParserBase<Impl>::ParseStatementList(StatementListT* body,
                                          Token::Value end_token) {
  // StatementList ::
  //   (StatementListItem)* <end_token>
  DCHECK_NOT_NULL(body);

  while (peek() == Token::kString) {
    bool use_strict = false;
#if V8_ENABLE_WEBASSEMBLY
    bool use_asm = false;
#endif  // V8_ENABLE_WEBASSEMBLY

    Scanner::Location token_loc = scanner()->peek_location();

    if (scanner()->NextLiteralExactlyEquals("use strict")) {
      use_strict = true;
#if V8_ENABLE_WEBASSEMBLY
    } else if (scanner()->NextLiteralExactlyEquals("use asm")) {
      use_asm = true;
#endif  // V8_ENABLE_WEBASSEMBLY
    }

    StatementT stat = ParseStatementListItem();
    if (impl()->IsNull(stat)) return;

    body->Add(stat);

    if (!impl()->IsStringLiteral(stat)) break;

    if (use_strict) {
      // Directive "use strict" (ES5 14.1).
      RaiseLanguageMode(LanguageMode::kStrict);
      if (!scope()->HasSimpleParameters()) {
        // TC39 deemed "use strict" directives to be an error when occurring
        // in the body of a function with non-simple parameter list, on
        // 29/7/2015. https://goo.gl/ueA7Ln
        impl()->ReportMessageAt(token_loc,
                                MessageTemplate::kIllegalLanguageModeDirective,
                                "use strict");
        return;
      }
#if V8_ENABLE_WEBASSEMBLY
    } else if (use_asm) {
      // Directive "use asm".
      impl()->SetAsmModule();
#endif  // V8_ENABLE_WEBASSEMBLY
    } else {
      // Possibly an unknown directive.
      // Should not change mode, but will increment usage counters
      // as appropriate. Ditto usages below.
      RaiseLanguageMode(LanguageMode::kSloppy);
    }
  }

  while (peek() != end_token) {
    StatementT stat = ParseStatementListItem();
    if (impl()->IsNull(stat)) return;
    if (stat->IsEmptyStatement()) continue;
    body->Add(stat);
  }
  function_state_ =
      AddOneSuspendPointIfBlockContainsAwaitUsing(scope(), function_state_);
}

template <typename Impl>
typename ParserBase<Impl>::StatementT
ParserBase<Impl>::ParseStatementListItem() {
  // ECMA 262 6th Edition
  // StatementListItem[Yield, Return] :
  //   Statement[?Yield, ?Return]
  //   Declaration[?Yield]
  //
  // Declaration[Yield] :
  //   HoistableDeclaration[?Yield]
  //   ClassDeclaration[?Yield]
  //   LexicalDeclaration[In, ?Yield]
  //
  // HoistableDeclaration[Yield, Default] :
  //   FunctionDeclaration[?Yield, ?Default]
  //   GeneratorDeclaration[?Yield, ?Default]
  //
  // LexicalDeclaration[In, Yield, Await] :
  //   LetOrConst BindingList[?In, ?Yield, ?Await, +Pattern] ;
  //   UsingDeclaration[?In, ?Yield, ?Await, ~Pattern];
  //   [+Await] AwaitUsingDeclaration[?In, ?Yield];

  switch (peek()) {
    case Token::kFunction:
      return ParseHoistableDeclaration(nullptr, false);
    case Token::kClass:
      Consume(Token::kClass);
      return ParseClassDeclaration(nullptr, false);
    case Token::kVar:
    case Token::kConst:
      return ParseVariableStatement(kStatementListItem, nullptr);
    case Token::kLet:
      if (IsNextLetKeyword()) {
        return ParseVariableStatement(kStatementListItem, nullptr);
      }
      break;
    case Token::kUsing:
      if (!v8_flags.js_explicit_resource_management) break;
      if (!is_using_allowed()) break;
      if (!(scanner()->HasLineTerminatorAfterNext()) &&
          PeekAhead() != Token::kAwait && PeekAhead() != Token::kLeftBracket &&
          PeekAhead() != Token::kLeftBrace) {
        return ParseVariableStatement(kStatementListItem, nullptr);
      }
      break;
    case Token::kAwait:
      if (!v8_flags.js_explicit_resource_management) break;
      if (!is_await_allowed()) break;
      if (!is_using_allowed()) break;
      if (!(scanner()->HasLineTerminatorAfterNext()) &&
          PeekAhead() == Token::kUsing &&
          !(scanner()->HasLineTerminatorAfterNextNext()) &&
          PeekAheadAhead() != Token::kLeftBracket &&
          PeekAheadAhead() != Token::kLeftBrace &&
          Token::IsAnyIdentifier(PeekAheadAhead())) {
        return ParseVariableStatement(kStatementListItem, nullptr);
      }
      break;
    case Token::kAsync:
      if (PeekAhead() == Token::kFunction &&
          !scanner()->HasLineTerminatorAfterNext()) {
        Consume(Token::kAsync);
        return ParseAsyncFunctionDeclaration(nullptr, false);
      }
      break;
    default:
      break;
  }
  return ParseStatement(nullptr, nullptr, kAllowLabelledFunctionStatement);
}

template <typename Impl>
typename ParserBase<Impl>::StatementT ParserBase<Impl>::ParseStatement(
    ZonePtrList<const AstRawString>* labels,
    ZonePtrList<const AstRawString>* own_labels,
    AllowLabelledFunctionStatement allow_function) {
  // Statement ::
  //   Block
  //   VariableStatement
  //   EmptyStatement
  //   ExpressionStatement
  //   IfStatement
  //   IterationStatement
  //   ContinueStatement
  //   BreakStatement
  //   ReturnStatement
  //   WithStatement
  //   LabelledStatement
  //   SwitchStatement
  //   ThrowStatement
  //   TryStatement
  //   DebuggerStatement

  // {own_labels} is always a subset of {labels}.
  DCHECK_IMPLIES(labels == nullptr, own_labels == nullptr);

  // Note: Since labels can only be used by 'break' and 'continue'
  // statements, which themselves are only valid within blocks,
  // iterations or 'switch' statements (i.e., BreakableStatements),
  // labels can be simply ignored in all other cases; except for
  // trivial labeled break statements 'label: break label' which is
  // parsed into an empty statement.
  switch (peek()) {
    case Token::kLeftBrace:
      return ParseBlock(labels);
    case Token::kSemicolon:
      Next();
      return factory()->EmptyStatement();
    case Token::kIf:
      return ParseIfStatement(labels);
    case Token::kDo:
      return ParseDoWhileStatement(labels, own_labels);
    case Token::kWhile:
      return ParseWhileStatement(labels, own_labels);
    case Token::kFor:
      if (V8_UNLIKELY(is_await_allowed() && PeekAhead() == Token::kAwait)) {
        return ParseForAwaitStatement(labels, own_labels);
      }
      return ParseForStatement(labels, own_labels);
    case Token::kContinue:
      return ParseContinueStatement();
    case Token::kBreak:
      return ParseBreakStatement(labels);
    case Token::kReturn:
      return ParseReturnStatement();
    case Token::kThrow:
      return ParseThrowStatement();
    case Token::kTry: {
      // It is somewhat complicated to have labels on try-statements.
      // When breaking out of a try-finally statement, one must take
      // great care not to treat it as a fall-through. It is much easier
      // just to wrap the entire try-statement in a statement block and
      // put the labels there.
      if (labels == nullptr) return ParseTryStatement();
      StatementListT statements(pointer_buffer());
      BlockT result = factory()->NewBlock(false, true);
      Target target(this, result, labels, nullptr,
                    Target::TARGET_FOR_NAMED_ONLY);
      StatementT statement = ParseTryStatement();
      statements.Add(statement);
      result->InitializeStatements(statements, zone());
      return result;
    }
    case Token::kWith:
      return ParseWithStatement(labels);
    case Token::kSwitch:
      return ParseSwitchStatement(labels);
    case Token::kFunction:
      // FunctionDeclaration only allowed as a StatementListItem, not in
      // an arbitrary Statement position. Exceptions such as
      // ES#sec-functiondeclarations-in-ifstatement-statement-clauses
      // are handled by calling ParseScopedStatement rather than
      // ParseStatement directly.
      impl()->ReportMessageAt(scanner()->peek_location(),
                              is_strict(language_mode())
                                  ? MessageTemplate::kStrictFunction
                                  : MessageTemplate::kSloppyFunction);
      return impl()->NullStatement();
    case Token::kDebugger:
      // return ParseDebuggerStatement();
      Next();
      return factory()->EmptyStatement();
    case Token::kVar:
      return ParseVariableStatement(kStatement, nullptr);
    case Token::kAsync:
      if (!impl()->HasCheckedSyntax() &&
          !scanner()->HasLineTerminatorAfterNext() &&
          PeekAhead() == Token::kFunction) {
        impl()->ReportMessageAt(
            scanner()->peek_location(),
            MessageTemplate::kAsyncFunctionInSingleStatementContext);
        return impl()->NullStatement();
      }
      [[fallthrough]];
    default:
      return ParseExpressionOrLabelledStatement(labels, own_labels,
                                                allow_function);
  }
}

template <typename Impl>
typename ParserBase<Impl>::BlockT ParserBase<Impl>::ParseBlock(
    ZonePtrList<const AstRawString>* labels, Scope* block_scope) {
  // Block ::
  //   '{' StatementList '}'

  // Parse the statements and collect escaping labels.
  BlockT body = factory()->NewBlock(false, labels != nullptr);
  StatementListT statements(pointer_buffer());

  CheckStackOverflow();

  {
    BlockState block_state(&scope_, block_scope);
    scope()->set_start_position(peek_position());
    Target target(this, body, labels, nullptr, Target::TARGET_FOR_NAMED_ONLY);

    Expect(Token::kLeftBrace);

    while (peek() != Token::kRightBrace) {
      StatementT stat = ParseStatementListItem();
      if (impl()->IsNull(stat)) return body;
      if (stat->IsEmptyStatement()) continue;
      statements.Add(stat);
    }

    Expect(Token::kRightBrace);

    int end_pos = end_position();
    scope()->set_end_position(end_pos);

    impl()->RecordBlockSourceRange(body, end_pos);
    body->set_scope(scope()->FinalizeBlockScope());
    function_state_ =
        AddOneSuspendPointIfBlockContainsAwaitUsing(scope(), function_state_);
  }

  body->InitializeStatements(statements, zone());
  return body;
}

template <typename Impl>
typename ParserBase<Impl>::BlockT ParserBase<Impl>::ParseBlock(
    ZonePtrList<const AstRawString>* labels) {
  return ParseBlock(labels, NewScope(BLOCK_SCOPE));
}

template <typename Impl>
typename ParserBase<Impl>::StatementT ParserBase<Impl>::ParseScopedStatement(
    ZonePtrList<const AstRawString>* labels) {
  if (is_strict(language_mode()) || peek() != Token::kFunction) {
    return ParseStatement(labels, nullptr);
  } else {
    // Make a block around the statement for a lexical binding
    // is introduced by a FunctionDeclaration.
    BlockState block_state(zone(), &scope_);
    scope()->set_start_position(scanner()->location().beg_pos);
    BlockT block = factory()->NewBlock(1, false);
    StatementT body = ParseFunctionDeclaration();
    block->statements()->Add(body, zone());
    scope()->set_end_position(end_position());
    block->set_scope(scope()->FinalizeBlockScope());
    return block;
  }
}

template <typename Impl>
typename ParserBase<Impl>::StatementT ParserBase<Impl>::ParseVariableStatement(
    VariableDeclarationContext var_context,
    ZonePtrList<const AstRawString>* names) {
  // VariableStatement ::
  //   VariableDeclarations ';'

  // The scope of a var declared variable anywhere inside a function
  // is the entire function (ECMA-262, 3rd, 10.1.3, and 12.2). Thus we can
  // transform a source-level var declaration into a (Function) Scope
  // declaration, and rewrite the source-level initialization into an assignment
  // statement. We use a block to collect multiple assignments.
  //
  // We mark the block as initializer block because we don't want the
  // rewriter to add a '.result' assignment to such a block (to get compliant
  // behavior for code such as print(eval('var x = 7')), and for cosmetic
  // reasons when pretty-printing. Also, unless an assignment (initialization)
  // is inside an initializer block, it is ignored.

  DeclarationParsingResult
Prompt: 
```
这是目录为v8/src/parsing/parser-base.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/parsing/parser-base.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第7部分，共9部分，请归纳一下它的功能

"""
tr);

  ClassInfo class_info(this);
  class_info.is_anonymous = is_anonymous;

  scope()->set_start_position(class_token_pos);
  if (Check(Token::kExtends)) {
    ClassScope::HeritageParsingScope heritage(class_scope);
    FuncNameInferrerState fni_state(&fni_);
    ExpressionParsingScope scope(impl());
    class_info.extends = ParseLeftHandSideExpression();
    scope.ValidateExpression();
  }

  Expect(Token::kLeftBrace);

  ParseClassLiteralBody(class_info, name, class_token_pos, Token::kRightBrace);

  VariableProxy* unresolvable = class_scope->ResolvePrivateNamesPartially();
  if (unresolvable != nullptr) {
    impl()->ReportMessageAt(Scanner::Location(unresolvable->position(),
                                              unresolvable->position() + 1),
                            MessageTemplate::kInvalidPrivateFieldResolution,
                            unresolvable->raw_name());
    return impl()->FailureExpression();
  }

  if (class_info.requires_brand) {
    class_scope->DeclareBrandVariable(
        ast_value_factory(), IsStaticFlag::kNotStatic, kNoSourcePosition);
  }

  if (class_scope->needs_home_object()) {
    class_info.home_object_variable =
        class_scope->DeclareHomeObjectVariable(ast_value_factory());
    class_info.static_home_object_variable =
        class_scope->DeclareStaticHomeObjectVariable(ast_value_factory());
  }

  bool should_save_class_variable_index =
      class_scope->should_save_class_variable_index();
  if (!class_info.is_anonymous || should_save_class_variable_index) {
    impl()->DeclareClassVariable(class_scope, name, &class_info,
                                 class_token_pos);
    if (should_save_class_variable_index) {
      class_scope->class_variable()->set_is_used();
      class_scope->class_variable()->ForceContextAllocation();
    }
  }

  return impl()->RewriteClassLiteral(class_scope, name, &class_info,
                                     class_token_pos);
}

template <typename Impl>
void ParserBase<Impl>::ParseClassLiteralBody(ClassInfo& class_info,
                                             IdentifierT name,
                                             int class_token_pos,
                                             Token::Value end_token) {
  bool has_extends = !impl()->IsNull(class_info.extends);

  while (peek() != end_token) {
    if (Check(Token::kSemicolon)) continue;

    // Either we're parsing a `static { }` initialization block or a property.
    if (peek() == Token::kStatic && PeekAhead() == Token::kLeftBrace) {
      BlockT static_block = ParseClassStaticBlock(&class_info);
      impl()->AddClassStaticBlock(static_block, &class_info);
      continue;
    }

    FuncNameInferrerState fni_state(&fni_);
    // If we haven't seen the constructor yet, it potentially is the next
    // property.
    bool is_constructor = !class_info.has_seen_constructor;
    ParsePropertyInfo prop_info(this);
    prop_info.position = PropertyPosition::kClassLiteral;

    ClassLiteralPropertyT property =
        ParseClassPropertyDefinition(&class_info, &prop_info, has_extends);

    if (has_error()) return;

    ClassLiteralProperty::Kind property_kind =
        ClassPropertyKindFor(prop_info.kind);

    if (!class_info.has_static_computed_names && prop_info.is_static &&
        prop_info.is_computed_name) {
      class_info.has_static_computed_names = true;
    }
    is_constructor &= class_info.has_seen_constructor;

    bool is_field = property_kind == ClassLiteralProperty::FIELD;

    if (V8_UNLIKELY(prop_info.is_private)) {
      DCHECK(!is_constructor);
      class_info.requires_brand |= (!is_field && !prop_info.is_static);
      class_info.has_static_private_methods_or_accessors |=
          (prop_info.is_static && !is_field);

      impl()->DeclarePrivateClassMember(scope()->AsClassScope(), prop_info.name,
                                        property, property_kind,
                                        prop_info.is_static, &class_info);
      impl()->InferFunctionName();
      continue;
    }

    if (V8_UNLIKELY(is_field)) {
      DCHECK(!prop_info.is_private);
      // If we're reparsing, we might not have a class scope. We only need a
      // class scope if we have a computed name though, and in that case we're
      // certain that the current scope must be a class scope.
      ClassScope* class_scope = nullptr;
      if (prop_info.is_computed_name) {
        class_info.computed_field_count++;
        class_scope = scope()->AsClassScope();
      }

      impl()->DeclarePublicClassField(class_scope, property,
                                      prop_info.is_static,
                                      prop_info.is_computed_name, &class_info);
      impl()->InferFunctionName();
      continue;
    }

    if (property_kind == ClassLiteralProperty::Kind::AUTO_ACCESSOR) {
      // Private auto-accessors are handled above with the other private
      // properties.
      DCHECK(!prop_info.is_private);
      impl()->AddInstanceFieldOrStaticElement(property, &class_info,
                                              prop_info.is_static);
    }

    impl()->DeclarePublicClassMethod(name, property, is_constructor,
                                     &class_info);
    impl()->InferFunctionName();
  }

  Expect(end_token);
  scope()->set_end_position(end_position());
}

template <typename Impl>
typename ParserBase<Impl>::ExpressionT
ParserBase<Impl>::ParseAsyncFunctionLiteral() {
  // AsyncFunctionLiteral ::
  //   async [no LineTerminator here] function ( FormalParameters[Await] )
  //       { AsyncFunctionBody }
  //
  //   async [no LineTerminator here] function BindingIdentifier[Await]
  //       ( FormalParameters[Await] ) { AsyncFunctionBody }
  DCHECK_EQ(scanner()->current_token(), Token::kAsync);
  if (V8_UNLIKELY(scanner()->literal_contains_escapes())) {
    impl()->ReportUnexpectedToken(Token::kEscapedKeyword);
  }
  int pos = position();
  Consume(Token::kFunction);
  IdentifierT name = impl()->NullIdentifier();
  FunctionSyntaxKind syntax_kind = FunctionSyntaxKind::kAnonymousExpression;

  ParseFunctionFlags flags = ParseFunctionFlag::kIsAsync;
  if (Check(Token::kMul)) flags |= ParseFunctionFlag::kIsGenerator;
  const FunctionKind kind = FunctionKindFor(flags);
  bool is_strict_reserved = Token::IsStrictReservedWord(peek());

  if (impl()->ParsingDynamicFunctionDeclaration()) {
    // We don't want dynamic functions to actually declare their name
    // "anonymous". We just want that name in the toString().

    // Consuming token we did not peek yet, which could lead to a kIllegal token
    // in the case of a stackoverflow.
    Consume(Token::kIdentifier);
    DCHECK_IMPLIES(!has_error(),
                   scanner()->CurrentSymbol(ast_value_factory()) ==
                       ast_value_factory()->anonymous_string());
  } else if (peek_any_identifier()) {
    syntax_kind = FunctionSyntaxKind::kNamedExpression;
    name = ParseIdentifier(kind);
  }
  FunctionLiteralT result = impl()->ParseFunctionLiteral(
      name, scanner()->location(),
      is_strict_reserved ? kFunctionNameIsStrictReserved
                         : kFunctionNameValidityUnknown,
      kind, pos, syntax_kind, language_mode(), nullptr);
  if (impl()->IsNull(result)) return impl()->FailureExpression();
  return result;
}

template <typename Impl>
typename ParserBase<Impl>::ExpressionT ParserBase<Impl>::ParseTemplateLiteral(
    ExpressionT tag, int start, bool tagged) {
  // A TemplateLiteral is made up of 0 or more kTemplateSpan tokens (literal
  // text followed by a substitution expression), finalized by a single
  // kTemplateTail.
  //
  // In terms of draft language, kTemplateSpan may be either the TemplateHead or
  // TemplateMiddle productions, while kTemplateTail is either TemplateTail, or
  // NoSubstitutionTemplate.
  //
  // When parsing a TemplateLiteral, we must have scanned either an initial
  // kTemplateSpan, or a kTemplateTail.
  DCHECK(peek() == Token::kTemplateSpan || peek() == Token::kTemplateTail);

  if (tagged) {
    // TaggedTemplate expressions prevent the eval compilation cache from being
    // used. This flag is only used if an eval is being parsed.
    set_allow_eval_cache(false);
  }

  bool forbid_illegal_escapes = !tagged;

  // If we reach a kTemplateTail first, we are parsing a NoSubstitutionTemplate.
  // In this case we may simply consume the token and build a template with a
  // single kTemplateSpan and no expressions.
  if (peek() == Token::kTemplateTail) {
    Consume(Token::kTemplateTail);
    int pos = position();
    typename Impl::TemplateLiteralState ts = impl()->OpenTemplateLiteral(pos);
    bool is_valid = CheckTemplateEscapes(forbid_illegal_escapes);
    impl()->AddTemplateSpan(&ts, is_valid, true);
    return impl()->CloseTemplateLiteral(&ts, start, tag);
  }

  Consume(Token::kTemplateSpan);
  int pos = position();
  typename Impl::TemplateLiteralState ts = impl()->OpenTemplateLiteral(pos);
  bool is_valid = CheckTemplateEscapes(forbid_illegal_escapes);
  impl()->AddTemplateSpan(&ts, is_valid, false);
  Token::Value next;

  // If we open with a kTemplateSpan, we must scan the subsequent expression,
  // and repeat if the following token is a kTemplateSpan as well (in this
  // case, representing a TemplateMiddle).

  do {
    next = peek();

    int expr_pos = peek_position();
    AcceptINScope scope(this, true);
    ExpressionT expression = ParseExpressionCoverGrammar();
    impl()->AddTemplateExpression(&ts, expression);

    if (peek() != Token::kRightBrace) {
      impl()->ReportMessageAt(Scanner::Location(expr_pos, peek_position()),
                              MessageTemplate::kUnterminatedTemplateExpr);
      return impl()->FailureExpression();
    }

    // If we didn't die parsing that expression, our next token should be a
    // kTemplateSpan or kTemplateTail.
    next = scanner()->ScanTemplateContinuation();
    Next();
    pos = position();

    is_valid = CheckTemplateEscapes(forbid_illegal_escapes);
    impl()->AddTemplateSpan(&ts, is_valid, next == Token::kTemplateTail);
  } while (next == Token::kTemplateSpan);

  DCHECK_IMPLIES(!has_error(), next == Token::kTemplateTail);
  // Once we've reached a kTemplateTail, we can close the TemplateLiteral.
  return impl()->CloseTemplateLiteral(&ts, start, tag);
}

template <typename Impl>
typename ParserBase<Impl>::ExpressionT
ParserBase<Impl>::RewriteInvalidReferenceExpression(ExpressionT expression,
                                                    int beg_pos, int end_pos,
                                                    MessageTemplate message,
                                                    bool early_error) {
  DCHECK(!IsValidReferenceExpression(expression));
  if (impl()->IsIdentifier(expression)) {
    DCHECK(is_strict(language_mode()));
    DCHECK(impl()->IsEvalOrArguments(impl()->AsIdentifier(expression)));

    ReportMessageAt(Scanner::Location(beg_pos, end_pos),
                    MessageTemplate::kStrictEvalArguments);
    return impl()->FailureExpression();
  }
  if (expression->IsCall() && !expression->AsCall()->is_tagged_template() &&
      !early_error) {
    expression_scope()->RecordPatternError(
        Scanner::Location(beg_pos, end_pos),
        MessageTemplate::kInvalidDestructuringTarget);
    // If it is a call, make it a runtime error for legacy web compatibility.
    // Bug: https://bugs.chromium.org/p/v8/issues/detail?id=4480
    // Rewrite `expr' to `expr[throw ReferenceError]'.
    impl()->CountUsage(
        is_strict(language_mode())
            ? v8::Isolate::kAssigmentExpressionLHSIsCallInStrict
            : v8::Isolate::kAssigmentExpressionLHSIsCallInSloppy);
    ExpressionT error = impl()->NewThrowReferenceError(message, beg_pos);
    return factory()->NewProperty(expression, error, beg_pos);
  }
  // Tagged templates and other modern language features (which pass early_error
  // = true) are exempt from the web compatibility hack. Throw a regular early
  // error.
  ReportMessageAt(Scanner::Location(beg_pos, end_pos), message);
  return impl()->FailureExpression();
}

template <typename Impl>
void ParserBase<Impl>::ClassifyParameter(IdentifierT parameter, int begin,
                                         int end) {
  if (impl()->IsEvalOrArguments(parameter)) {
    expression_scope()->RecordStrictModeParameterError(
        Scanner::Location(begin, end), MessageTemplate::kStrictEvalArguments);
  }
}

template <typename Impl>
void ParserBase<Impl>::ClassifyArrowParameter(
    AccumulationScope* accumulation_scope, int position,
    ExpressionT parameter) {
  accumulation_scope->Accumulate();
  if (parameter->is_parenthesized() ||
      !(impl()->IsIdentifier(parameter) || parameter->IsPattern() ||
        parameter->IsAssignment())) {
    expression_scope()->RecordDeclarationError(
        Scanner::Location(position, end_position()),
        MessageTemplate::kInvalidDestructuringTarget);
  } else if (impl()->IsIdentifier(parameter)) {
    ClassifyParameter(impl()->AsIdentifier(parameter), position,
                      end_position());
  } else {
    expression_scope()->RecordNonSimpleParameter();
  }
}

template <typename Impl>
bool ParserBase<Impl>::IsValidReferenceExpression(ExpressionT expression) {
  return IsAssignableIdentifier(expression) || expression->IsProperty();
}

template <typename Impl>
typename ParserBase<Impl>::ExpressionT
ParserBase<Impl>::ParsePossibleDestructuringSubPattern(
    AccumulationScope* scope) {
  if (scope) scope->Accumulate();
  int begin = peek_position();
  ExpressionT result = ParseAssignmentExpressionCoverGrammar();

  if (IsValidReferenceExpression(result)) {
    // Parenthesized identifiers and property references are allowed as part of
    // a larger assignment pattern, even though parenthesized patterns
    // themselves are not allowed, e.g., "[(x)] = []". Only accumulate
    // assignment pattern errors if the parsed expression is more complex.
    if (impl()->IsIdentifier(result)) {
      if (result->is_parenthesized()) {
        expression_scope()->RecordDeclarationError(
            Scanner::Location(begin, end_position()),
            MessageTemplate::kInvalidDestructuringTarget);
      }
      IdentifierT identifier = impl()->AsIdentifier(result);
      ClassifyParameter(identifier, begin, end_position());
    } else {
      DCHECK(result->IsProperty());
      expression_scope()->RecordDeclarationError(
          Scanner::Location(begin, end_position()),
          MessageTemplate::kInvalidPropertyBindingPattern);
      if (scope != nullptr) scope->ValidateExpression();
    }
  } else if (result->is_parenthesized() ||
             (!result->IsPattern() && !result->IsAssignment())) {
    expression_scope()->RecordPatternError(
        Scanner::Location(begin, end_position()),
        MessageTemplate::kInvalidDestructuringTarget);
  }

  return result;
}

template <typename Impl>
typename ParserBase<Impl>::ExpressionT ParserBase<Impl>::ParseV8Intrinsic() {
  // CallRuntime ::
  //   '%' Identifier Arguments

  int pos = peek_position();
  Consume(Token::kMod);
  // Allow "eval" or "arguments" for backward compatibility.
  IdentifierT name = ParseIdentifier();
  if (peek() != Token::kLeftParen) {
    impl()->ReportUnexpectedToken(peek());
    return impl()->FailureExpression();
  }
  bool has_spread;
  ExpressionListT args(pointer_buffer());
  ParseArguments(&args, &has_spread);

  if (has_spread) {
    ReportMessageAt(Scanner::Location(pos, position()),
                    MessageTemplate::kIntrinsicWithSpread);
    return impl()->FailureExpression();
  }

  return impl()->NewV8Intrinsic(name, args, pos);
}

template <typename Impl>
void ParserBase<Impl>::ParseStatementList(StatementListT* body,
                                          Token::Value end_token) {
  // StatementList ::
  //   (StatementListItem)* <end_token>
  DCHECK_NOT_NULL(body);

  while (peek() == Token::kString) {
    bool use_strict = false;
#if V8_ENABLE_WEBASSEMBLY
    bool use_asm = false;
#endif  // V8_ENABLE_WEBASSEMBLY

    Scanner::Location token_loc = scanner()->peek_location();

    if (scanner()->NextLiteralExactlyEquals("use strict")) {
      use_strict = true;
#if V8_ENABLE_WEBASSEMBLY
    } else if (scanner()->NextLiteralExactlyEquals("use asm")) {
      use_asm = true;
#endif  // V8_ENABLE_WEBASSEMBLY
    }

    StatementT stat = ParseStatementListItem();
    if (impl()->IsNull(stat)) return;

    body->Add(stat);

    if (!impl()->IsStringLiteral(stat)) break;

    if (use_strict) {
      // Directive "use strict" (ES5 14.1).
      RaiseLanguageMode(LanguageMode::kStrict);
      if (!scope()->HasSimpleParameters()) {
        // TC39 deemed "use strict" directives to be an error when occurring
        // in the body of a function with non-simple parameter list, on
        // 29/7/2015. https://goo.gl/ueA7Ln
        impl()->ReportMessageAt(token_loc,
                                MessageTemplate::kIllegalLanguageModeDirective,
                                "use strict");
        return;
      }
#if V8_ENABLE_WEBASSEMBLY
    } else if (use_asm) {
      // Directive "use asm".
      impl()->SetAsmModule();
#endif  // V8_ENABLE_WEBASSEMBLY
    } else {
      // Possibly an unknown directive.
      // Should not change mode, but will increment usage counters
      // as appropriate. Ditto usages below.
      RaiseLanguageMode(LanguageMode::kSloppy);
    }
  }

  while (peek() != end_token) {
    StatementT stat = ParseStatementListItem();
    if (impl()->IsNull(stat)) return;
    if (stat->IsEmptyStatement()) continue;
    body->Add(stat);
  }
  function_state_ =
      AddOneSuspendPointIfBlockContainsAwaitUsing(scope(), function_state_);
}

template <typename Impl>
typename ParserBase<Impl>::StatementT
ParserBase<Impl>::ParseStatementListItem() {
  // ECMA 262 6th Edition
  // StatementListItem[Yield, Return] :
  //   Statement[?Yield, ?Return]
  //   Declaration[?Yield]
  //
  // Declaration[Yield] :
  //   HoistableDeclaration[?Yield]
  //   ClassDeclaration[?Yield]
  //   LexicalDeclaration[In, ?Yield]
  //
  // HoistableDeclaration[Yield, Default] :
  //   FunctionDeclaration[?Yield, ?Default]
  //   GeneratorDeclaration[?Yield, ?Default]
  //
  // LexicalDeclaration[In, Yield, Await] :
  //   LetOrConst BindingList[?In, ?Yield, ?Await, +Pattern] ;
  //   UsingDeclaration[?In, ?Yield, ?Await, ~Pattern];
  //   [+Await] AwaitUsingDeclaration[?In, ?Yield];

  switch (peek()) {
    case Token::kFunction:
      return ParseHoistableDeclaration(nullptr, false);
    case Token::kClass:
      Consume(Token::kClass);
      return ParseClassDeclaration(nullptr, false);
    case Token::kVar:
    case Token::kConst:
      return ParseVariableStatement(kStatementListItem, nullptr);
    case Token::kLet:
      if (IsNextLetKeyword()) {
        return ParseVariableStatement(kStatementListItem, nullptr);
      }
      break;
    case Token::kUsing:
      if (!v8_flags.js_explicit_resource_management) break;
      if (!is_using_allowed()) break;
      if (!(scanner()->HasLineTerminatorAfterNext()) &&
          PeekAhead() != Token::kAwait && PeekAhead() != Token::kLeftBracket &&
          PeekAhead() != Token::kLeftBrace) {
        return ParseVariableStatement(kStatementListItem, nullptr);
      }
      break;
    case Token::kAwait:
      if (!v8_flags.js_explicit_resource_management) break;
      if (!is_await_allowed()) break;
      if (!is_using_allowed()) break;
      if (!(scanner()->HasLineTerminatorAfterNext()) &&
          PeekAhead() == Token::kUsing &&
          !(scanner()->HasLineTerminatorAfterNextNext()) &&
          PeekAheadAhead() != Token::kLeftBracket &&
          PeekAheadAhead() != Token::kLeftBrace &&
          Token::IsAnyIdentifier(PeekAheadAhead())) {
        return ParseVariableStatement(kStatementListItem, nullptr);
      }
      break;
    case Token::kAsync:
      if (PeekAhead() == Token::kFunction &&
          !scanner()->HasLineTerminatorAfterNext()) {
        Consume(Token::kAsync);
        return ParseAsyncFunctionDeclaration(nullptr, false);
      }
      break;
    default:
      break;
  }
  return ParseStatement(nullptr, nullptr, kAllowLabelledFunctionStatement);
}

template <typename Impl>
typename ParserBase<Impl>::StatementT ParserBase<Impl>::ParseStatement(
    ZonePtrList<const AstRawString>* labels,
    ZonePtrList<const AstRawString>* own_labels,
    AllowLabelledFunctionStatement allow_function) {
  // Statement ::
  //   Block
  //   VariableStatement
  //   EmptyStatement
  //   ExpressionStatement
  //   IfStatement
  //   IterationStatement
  //   ContinueStatement
  //   BreakStatement
  //   ReturnStatement
  //   WithStatement
  //   LabelledStatement
  //   SwitchStatement
  //   ThrowStatement
  //   TryStatement
  //   DebuggerStatement

  // {own_labels} is always a subset of {labels}.
  DCHECK_IMPLIES(labels == nullptr, own_labels == nullptr);

  // Note: Since labels can only be used by 'break' and 'continue'
  // statements, which themselves are only valid within blocks,
  // iterations or 'switch' statements (i.e., BreakableStatements),
  // labels can be simply ignored in all other cases; except for
  // trivial labeled break statements 'label: break label' which is
  // parsed into an empty statement.
  switch (peek()) {
    case Token::kLeftBrace:
      return ParseBlock(labels);
    case Token::kSemicolon:
      Next();
      return factory()->EmptyStatement();
    case Token::kIf:
      return ParseIfStatement(labels);
    case Token::kDo:
      return ParseDoWhileStatement(labels, own_labels);
    case Token::kWhile:
      return ParseWhileStatement(labels, own_labels);
    case Token::kFor:
      if (V8_UNLIKELY(is_await_allowed() && PeekAhead() == Token::kAwait)) {
        return ParseForAwaitStatement(labels, own_labels);
      }
      return ParseForStatement(labels, own_labels);
    case Token::kContinue:
      return ParseContinueStatement();
    case Token::kBreak:
      return ParseBreakStatement(labels);
    case Token::kReturn:
      return ParseReturnStatement();
    case Token::kThrow:
      return ParseThrowStatement();
    case Token::kTry: {
      // It is somewhat complicated to have labels on try-statements.
      // When breaking out of a try-finally statement, one must take
      // great care not to treat it as a fall-through. It is much easier
      // just to wrap the entire try-statement in a statement block and
      // put the labels there.
      if (labels == nullptr) return ParseTryStatement();
      StatementListT statements(pointer_buffer());
      BlockT result = factory()->NewBlock(false, true);
      Target target(this, result, labels, nullptr,
                    Target::TARGET_FOR_NAMED_ONLY);
      StatementT statement = ParseTryStatement();
      statements.Add(statement);
      result->InitializeStatements(statements, zone());
      return result;
    }
    case Token::kWith:
      return ParseWithStatement(labels);
    case Token::kSwitch:
      return ParseSwitchStatement(labels);
    case Token::kFunction:
      // FunctionDeclaration only allowed as a StatementListItem, not in
      // an arbitrary Statement position. Exceptions such as
      // ES#sec-functiondeclarations-in-ifstatement-statement-clauses
      // are handled by calling ParseScopedStatement rather than
      // ParseStatement directly.
      impl()->ReportMessageAt(scanner()->peek_location(),
                              is_strict(language_mode())
                                  ? MessageTemplate::kStrictFunction
                                  : MessageTemplate::kSloppyFunction);
      return impl()->NullStatement();
    case Token::kDebugger:
      // return ParseDebuggerStatement();
      Next();
      return factory()->EmptyStatement();
    case Token::kVar:
      return ParseVariableStatement(kStatement, nullptr);
    case Token::kAsync:
      if (!impl()->HasCheckedSyntax() &&
          !scanner()->HasLineTerminatorAfterNext() &&
          PeekAhead() == Token::kFunction) {
        impl()->ReportMessageAt(
            scanner()->peek_location(),
            MessageTemplate::kAsyncFunctionInSingleStatementContext);
        return impl()->NullStatement();
      }
      [[fallthrough]];
    default:
      return ParseExpressionOrLabelledStatement(labels, own_labels,
                                                allow_function);
  }
}

template <typename Impl>
typename ParserBase<Impl>::BlockT ParserBase<Impl>::ParseBlock(
    ZonePtrList<const AstRawString>* labels, Scope* block_scope) {
  // Block ::
  //   '{' StatementList '}'

  // Parse the statements and collect escaping labels.
  BlockT body = factory()->NewBlock(false, labels != nullptr);
  StatementListT statements(pointer_buffer());

  CheckStackOverflow();

  {
    BlockState block_state(&scope_, block_scope);
    scope()->set_start_position(peek_position());
    Target target(this, body, labels, nullptr, Target::TARGET_FOR_NAMED_ONLY);

    Expect(Token::kLeftBrace);

    while (peek() != Token::kRightBrace) {
      StatementT stat = ParseStatementListItem();
      if (impl()->IsNull(stat)) return body;
      if (stat->IsEmptyStatement()) continue;
      statements.Add(stat);
    }

    Expect(Token::kRightBrace);

    int end_pos = end_position();
    scope()->set_end_position(end_pos);

    impl()->RecordBlockSourceRange(body, end_pos);
    body->set_scope(scope()->FinalizeBlockScope());
    function_state_ =
        AddOneSuspendPointIfBlockContainsAwaitUsing(scope(), function_state_);
  }

  body->InitializeStatements(statements, zone());
  return body;
}

template <typename Impl>
typename ParserBase<Impl>::BlockT ParserBase<Impl>::ParseBlock(
    ZonePtrList<const AstRawString>* labels) {
  return ParseBlock(labels, NewScope(BLOCK_SCOPE));
}

template <typename Impl>
typename ParserBase<Impl>::StatementT ParserBase<Impl>::ParseScopedStatement(
    ZonePtrList<const AstRawString>* labels) {
  if (is_strict(language_mode()) || peek() != Token::kFunction) {
    return ParseStatement(labels, nullptr);
  } else {
    // Make a block around the statement for a lexical binding
    // is introduced by a FunctionDeclaration.
    BlockState block_state(zone(), &scope_);
    scope()->set_start_position(scanner()->location().beg_pos);
    BlockT block = factory()->NewBlock(1, false);
    StatementT body = ParseFunctionDeclaration();
    block->statements()->Add(body, zone());
    scope()->set_end_position(end_position());
    block->set_scope(scope()->FinalizeBlockScope());
    return block;
  }
}

template <typename Impl>
typename ParserBase<Impl>::StatementT ParserBase<Impl>::ParseVariableStatement(
    VariableDeclarationContext var_context,
    ZonePtrList<const AstRawString>* names) {
  // VariableStatement ::
  //   VariableDeclarations ';'

  // The scope of a var declared variable anywhere inside a function
  // is the entire function (ECMA-262, 3rd, 10.1.3, and 12.2). Thus we can
  // transform a source-level var declaration into a (Function) Scope
  // declaration, and rewrite the source-level initialization into an assignment
  // statement. We use a block to collect multiple assignments.
  //
  // We mark the block as initializer block because we don't want the
  // rewriter to add a '.result' assignment to such a block (to get compliant
  // behavior for code such as print(eval('var x = 7')), and for cosmetic
  // reasons when pretty-printing. Also, unless an assignment (initialization)
  // is inside an initializer block, it is ignored.

  DeclarationParsingResult parsing_result;
  ParseVariableDeclarations(var_context, &parsing_result, names);
  ExpectSemicolon();
  return impl()->BuildInitializationBlock(&parsing_result);
}

template <typename Impl>
typename ParserBase<Impl>::StatementT
ParserBase<Impl>::ParseDebuggerStatement() {
  // In ECMA-262 'debugger' is defined as a reserved keyword. In some browser
  // contexts this is used as a statement which invokes the debugger as i a
  // break point is present.
  // DebuggerStatement ::
  //   'debugger' ';'

  int pos = peek_position();
  Consume(Token::kDebugger);
  ExpectSemicolon();
  return factory()->NewDebuggerStatement(pos);
}

template <typename Impl>
typename ParserBase<Impl>::StatementT
ParserBase<Impl>::ParseExpressionOrLabelledStatement(
    ZonePtrList<const AstRawString>* labels,
    ZonePtrList<const AstRawString>* own_labels,
    AllowLabelledFunctionStatement allow_function) {
  // ExpressionStatement | LabelledStatement ::
  //   Expression ';'
  //   Identifier ':' Statement
  //
  // ExpressionStatement[Yield] :
  //   [lookahead notin {{, function, class, let [}] Expression[In, ?Yield] ;

  int pos = peek_position();

  switch (peek()) {
    case Token::kFunction:
    case Token::kLeftBrace:
      UNREACHABLE();  // Always handled by the callers.
    case Token::kClass:
      ReportUnexpectedToken(Next());
      return impl()->NullStatement();
    case Token::kLet: {
      Token::Value next_next = PeekAhead();
      // "let" followed by either "[", "{" or an identifier means a lexical
      // declaration, which should not appear here.
      // However, ASI may insert a line break before an identifier or a brace.
      if (next_next != Token::kLeftBracket &&
          ((next_next != Token::kLeftBrace &&
            next_next != Token::kIdentifier) ||
           scanner_->HasLineTerminatorAfterNext())) {
        break;
      }
      impl()->ReportMessageAt(scanner()->peek_location(),
                              MessageTemplate::kUnexpectedLexicalDeclaration);
      return impl()->NullStatement();
    }
    default:
      break;
  }

  bool starts_with_identifier = peek_any_identifier();

  ExpressionT expr;
  {
    // Effectively inlines ParseExpression, so potential labels can be extracted
    // from expression_scope.
    ExpressionParsingScope expression_scope(impl());
    AcceptINScope scope(this, true);
    expr = ParseExpressionCoverGrammar();
    expression_scope.ValidateExpression();

    if (peek() == Token::kColon && starts_with_identifier &&
        impl()->IsIdentifier(expr)) {
      // The whole expression was a single identifier, and not, e.g.,
      // something starting with an identifier or a parenthesized identifier.
      DCHECK_EQ(expression_scope.variable_list()->length(), 1);
      VariableProxy* label = expression_scope.variable_list()->at(0).first;
      impl()->DeclareLabel(&labels, &own_labels, label->raw_name());

      // Remove the "ghost" variable that turned out to be a label from the top
      // scope. This way, we don't try to resolve it during the scope
      // processing.
      this->scope()->DeleteUnresolved(label);

      Consume(Token::kColon);
      // ES#sec-labelled-function-declarations Labelled Function Declarations
      if (peek() == Token::kFunction && is_sloppy(language_mode()) &&
          allow_function == kAllowLabelledFunctionStatement) {
        return ParseFunctionDeclaration();
      }
      return ParseStatement(labels, own_labels, allow_function);
    }
  }

  // We allow a native function declaration if we're parsing the source for an
  // extension. A native function declaration starts with "native function"
  // with no line-terminator between the two words.
  if (impl()->ParsingExtension() && peek() == Token::kFunction &&
      !scanner()->HasLineTerminatorBeforeNext() && impl()->IsNative(expr) &&
      !scanner()->literal_contains_escapes()) {
    return ParseNativeDeclaration();
  }

  // Parsed expression statement, followed by semicolon.
  ExpectSemicolon();
  if (expr->IsFailureExpression()) return impl()->NullStatement();
  return factory()->NewExpressionStatement(expr, pos);
}

template <typename Impl>
typename ParserBase<Impl>::StatementT ParserBase<Impl>::ParseIfStatement(
    ZonePtrList<const AstRawString>* labels) {
  // IfStatement ::
  //   'if' '(' Expression ')' Statement ('else' Statement)?

  int pos = peek_position();
  Consume(Token::kIf);
  Expect(Token::kLeftParen);
  ExpressionT condition = ParseExpression();
  Expect(Token::kRightParen);

  SourceRange then_range, else_range;
  StatementT then_statement = impl()->NullStatement();
  {
    SourceRangeScope range_scope(scanner(), &then_range);
    // Make a copy of {labels} to avoid conflicts with any
    // labels that may be applied to the else clause below.
    auto labels_copy =
        labels == nullptr
            ? labels
            : zone()->template New<ZonePtrList<const AstRawString>>(*labels,
                                                                    zone());
    then_statement = ParseScopedStatement(labels_copy);
  }

  StatementT else_statement = impl()->NullStatement();
  if (Check(Token::kElse)) {
    else_statement = Par
"""


```