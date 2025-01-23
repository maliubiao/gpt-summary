Response:
The user wants a summary of the provided C++ header file `v8/src/parsing/parser-base.h`.

Here's a breakdown of how to approach this:

1. **Identify the Core Purpose:** The filename strongly suggests this file defines a base class for parsing JavaScript code.

2. **Analyze Key Methods:**  Skim through the provided code snippet, looking for method names that reveal functionality. Methods like `ParseFormalParameter`, `ParseVariableDeclarations`, `ParseFunctionDeclaration`, `ParseClassDeclaration`, `ParseArrowFunctionLiteral`, `ParseStatementList`, etc., are strong indicators of parsing-related activities.

3. **Recognize Data Structures:** Notice the use of `ZonePtrList`, `AstRawString`, `FormalParametersT`, `StatementListT`, `FunctionLiteralT`, `Scope`, etc. These point to the internal representation of the parsed JavaScript code.

4. **Look for Error Handling:** The presence of `ReportMessage` and `Check` suggests mechanisms for detecting and reporting syntax errors.

5. **Consider Language Features:**  The code handles features like `var`, `const`, `let`, `using`, async/await, generators, classes, and arrow functions, indicating its role in parsing modern JavaScript syntax.

6. **Address Specific Instructions:**
    * **`.tq` extension:** Check if the filename ends with `.tq`. It doesn't.
    * **JavaScript relation:** Explain how the parsing relates to JavaScript code execution. Provide a simple JavaScript example and explain how the parser would process it.
    * **Code logic推理 (Inference):** Select a simple code snippet (like parsing function parameters) and illustrate the expected input and output.
    * **User errors:** Identify common JavaScript programming errors the parser would detect (e.g., too many parameters, missing initializers).
    * **Part of a larger series:** Acknowledge that this is part of a larger parsing system.

7. **Synthesize a Summary:** Combine the observations into a concise description of the file's role.

**Pre-computation/Pre-analysis (Internal thought process during the scan):**

* **Focus on the `ParserBase` template:**  The code is heavily templated, indicating it's a base class intended to be used by specific parser implementations. The `Impl` template parameter likely provides the concrete AST node creation and other implementation details.
* **Notice the state management:**  The use of `Scope`, `FunctionState`, `BlockState`, and `ExpressionParsingScope` highlights the parser's need to maintain context during the parsing process.
* **Identify parsing phases:** The method names suggest different stages of parsing, such as handling declarations, expressions, and statements.
* **Recognize ES6+ features:**  Keywords like `const`, `let`, `class`, `async`, and `await` indicate support for modern JavaScript syntax.
* **Infer error reporting:** The `ReportMessage` calls are crucial for providing feedback to developers about syntax errors.

By following these steps, we can construct a comprehensive and accurate summary of the provided code snippet.
```cpp
template <typename Impl>
void ParserBase<Impl>::ParseFormalParameter(FormalParametersT* parameters) {
  // FormalParameter [Yield, Await] :
  //   BindingElement [Yield, Await]
  //   ... BindingIdentifier [Yield, Await]

  // BindingElement [Yield, Await] :
  //   SingleNameBinding [Yield, Await]
  //   BindingPattern [Yield, Await] Initializer [In, ?Yield, ?Await]opt

  // SingleNameBinding [Yield, Await] :
  //   BindingIdentifier [Yield, Await] Initializer [In, ?Yield, ?Await]opt

  int parameter_start_position = peek_position();
  IdentifierT name;
  ExpressionT pattern;

  if (V8_LIKELY(Token::IsIdentifier(peek()) || peek() == Token::kLet)) {
    // SingleNameBinding or starting a BindingPattern with an identifier.
    name = ParseBindingIdentifier();
    if (V8_UNLIKELY(is_strict(language_mode()) &&
                    impl()->IsEvalOrArguments(name))) {
      impl()->ReportMessageAt(scanner()->location(),
                              MessageTemplate::kStrictEvalArguments);
      return;
    }
    pattern = impl()->ExpressionFromIdentifier(name, parameter_start_position);
    if (peek() == Token::kLeftParen || peek() == Token::kLeftBracket) {
      // We have parsed an identifier but it is the start of a more complex
      // destructuring pattern. Rewind and parse the full pattern.
      Rewind(parameter_start_position);
      pattern = ParseBindingPattern();
      name = impl()->NullIdentifier();
    }
  } else {
    pattern = ParseBindingPattern();
    name = impl()->NullIdentifier();
  }

  ExpressionT initializer;
  if (Check(Token::kAssign)) {
    initializer = ParseAssignmentExpression();
    impl()->SetFunctionNameFromIdentifierRef(initializer, pattern);
  } else {
    initializer = impl()->NullExpression();
  }

  parameters->Add(name, pattern, initializer, parameter_start_position,
                  end_position());
}

template <typename Impl>
void ParserBase<Impl>::ParseFormalParameters(FormalParametersT* parameters) {
  parameters->scope = NewScope(scope(), FunctionScope::FORMAL_PARAMETERS_SCOPE);
  parameters->scope->set_start_position(position());

  // FormalParameters [Yield, Await] :
  //   [empty]
  //   FunctionRestParameter [Yield, Await]
  //   FormalParameterList [Yield, Await]
  //   FormalParameterList [Yield, Await] , FunctionRestParameter [Yield, Await]

  // FormalParameterList [Yield, Await] :
  //   FormalParameter [?Yield, ?Await]
  //   FormalParameterList [?Yield, ?Await] , FormalParameter [?Yield, ?Await]

  Consume(Token::kLeftParen);

  if (!Check(Token::kRightParen)) {
    DeclarationScope* scope = parameters->scope;
    PushScope(scope);
    do {
      if (parameters->meters->arity + 1 > Code::kMaxArguments) {
        ReportMessage(MessageTemplate::kTooManyParameters);
        return;
      }
      parameters->has_rest = Check(Token::kEllipsis);
      ParseFormalParameter(parameters);

      if (parameters->has_rest) {
        parameters->is_simple = false;
        if (peek() == Token::kComma) {
          impl()->ReportMessageAt(scanner()->peek_location(),
                                  MessageTemplate::kParamAfterRest);
          return;
        }
        break;
      }
      if (!Check(Token::kComma)) break;
      if (peek() == Token::kRightParen) {
        // allow the trailing comma
        break;
      }
    } while (true);
    PopScope();
  }

  Expect(Token::kRightParen);
  parameters->scope->set_end_position(position());

  impl()->DeclareFormalParameters(parameters);
}

template <typename Impl>
void ParserBase<Impl>::ParseVariableDeclarations(
    VariableDeclarationContext var_context,
    DeclarationParsingResult* parsing_result,
    ZonePtrList<const AstRawString>* names) {
  // VariableDeclarations ::
  //   ('var' | 'const' | 'let' | 'using' | 'await using') (Identifier ('='
  //   AssignmentExpression)?)+[',']
  //
  // ES6:
  // FIXME(marja, nikolaos): Add an up-to-date comment about ES6 variable
  // declaration syntax.

  DCHECK_NOT_NULL(parsing_result);
  parsing_result->descriptor.kind = NORMAL_VARIABLE;
  parsing_result->descriptor.declaration_pos = peek_position();
  parsing_result->descriptor.initialization_pos = peek_position();

  switch (peek()) {
    case Token::kVar:
      parsing_result->descriptor.mode = VariableMode::kVar;
      Consume(Token::kVar);
      break;
    case Token::kConst:
      Consume(Token::kConst);
      DCHECK_NE(var_context, kStatement);
      parsing_result->descriptor.mode = VariableMode::kConst;
      break;
    case Token::kLet:
      Consume(Token::kLet);
      DCHECK_NE(var_context, kStatement);
      parsing_result->descriptor.mode = VariableMode::kLet;
      break;
    case Token::kUsing:
      // using [no LineTerminator here] [lookahead ≠ await] BindingList[?In,
      // ?Yield, ?Await, ~Pattern] ;
      Consume(Token::kUsing);
      DCHECK(v8_flags.js_explicit_resource_management);
      DCHECK_NE(var_context, kStatement);
      DCHECK(is_using_allowed());
      DCHECK(peek() != Token::kAwait);
      DCHECK(!scanner()->HasLineTerminatorBeforeNext());
      DCHECK(peek() != Token::kLeftBracket && peek() != Token::kLeftBrace);
      parsing_result->descriptor.mode = VariableMode::kUsing;
      break;
    case Token::kAwait:
      // CoverAwaitExpressionAndAwaitUsingDeclarationHead[?Yield] [no
      // LineTerminator here] BindingList[?In, ?Yield, +Await, ~Pattern];
      Consume(Token::kAwait);
      DCHECK(v8_flags.js_explicit_resource_management);
      DCHECK_NE(var_context, kStatement);
      DCHECK(is_using_allowed());
      DCHECK(is_await_allowed());
      Consume(Token::kUsing);
      DCHECK(!scanner()->HasLineTerminatorBeforeNext());
      DCHECK(peek() != Token::kLeftBracket && peek() != Token::kLeftBrace);
      parsing_result->descriptor.mode = VariableMode::kAwaitUsing;
      break;
    default:
      UNREACHABLE();  // by current callers
      break;
  }

  VariableDeclarationParsingScope declaration(
      impl(), parsing_result->descriptor.mode, names);
  Scope* target_scope = IsLexicalVariableMode(parsing_result->descriptor.mode)
                            ? scope()
                            : scope()->GetDeclarationScope();

  auto declaration_it = target_scope->declarations()->end();

  int bindings_start = peek_position();
  do {
    // Parse binding pattern.
    FuncNameInferrerState fni_state(&fni_);

    int decl_pos = peek_position();

    IdentifierT name;
    ExpressionT pattern;
    // Check for an identifier first, so that we can elide the pattern in cases
    // where there is no initializer (and so no proxy needs to be created).
    if (V8_LIKELY(Token::IsAnyIdentifier(peek()))) {
      name = ParseAndClassifyIdentifier(Next());
      if (V8_UNLIKELY(is_strict(language_mode()) &&
                      impl()->IsEvalOrArguments(name))) {
        impl()->ReportMessageAt(scanner()->location(),
                                MessageTemplate::kStrictEvalArguments);
        return;
      }
      if (peek() == Token::kAssign ||
          (var_context == kForStatement && PeekInOrOf()) ||
          parsing_result->descriptor.mode == VariableMode::kLet) {
        // Assignments need the variable expression for the assignment LHS, and
        // for of/in will need it later, so create the expression now.
        pattern = impl()->ExpressionFromIdentifier(name, decl_pos);
      } else {
        // Otherwise, elide the variable expression and just declare it.
        impl()->DeclareIdentifier(name, decl_pos);
        pattern = impl()->NullExpression();
      }
    } else if (parsing_result->descriptor.mode != VariableMode::kUsing &&
               parsing_result->descriptor.mode != VariableMode::kAwaitUsing) {
      name = impl()->NullIdentifier();
      pattern = ParseBindingPattern();
      DCHECK(!impl()->IsIdentifier(pattern));
    } else {
      // `using` declarations should have an identifier.
      impl()->ReportMessageAt(Scanner::Location(decl_pos, end_position()),
                              MessageTemplate::kDeclarationMissingInitializer,
                              "using");
      return;
    }

    Scanner::Location variable_loc = scanner()->location();

    ExpressionT value = impl()->NullExpression();
    int value_beg_pos = kNoSourcePosition;
    if (Check(Token::kAssign)) {
      DCHECK(!impl()->IsNull(pattern));
      {
        value_beg_pos = peek_position();
        AcceptINScope scope(this, var_context != kForStatement);
        value = ParseAssignmentExpression();
      }
      variable_loc.end_pos = end_position();

      if (!parsing_result->first_initializer_loc.IsValid()) {
        parsing_result->first_initializer_loc = variable_loc;
      }

      // Don't infer if it is "a = function(){...}();"-like expression.
      if (impl()->IsIdentifier(pattern)) {
        if (!value->IsCall() && !value->IsCallNew()) {
          fni_.Infer();
        } else {
          fni_.RemoveLastFunction();
        }
      }

      impl()->SetFunctionNameFromIdentifierRef(value, pattern);
    } else {
#ifdef DEBUG
      // We can fall through into here on error paths, so don't DCHECK those.
      if (!has_error()) {
        // We should never get identifier patterns for the non-initializer path,
        // as those expressions should be elided.
        DCHECK_EQ(!impl()->IsNull(name),
                  Token::IsAnyIdentifier(scanner()->current_token()));
        DCHECK_IMPLIES(impl()->IsNull(pattern), !impl()->IsNull(name));
        // The only times we have a non-null pattern are:
        //   1. This is a destructuring declaration (with no initializer, which
        //      is immediately an error),
        //   2. This is a declaration in a for in/of loop, or
        //   3. This is a let (which has an implicit undefined initializer)
        DCHECK_IMPLIES(
            !impl()->IsNull(pattern),
            !impl()->IsIdentifier(pattern) ||
                (var_context == kForStatement && PeekInOrOf()) ||
                parsing_result->descriptor.mode == VariableMode::kLet);
      }
#endif

      if (var_context != kForStatement || !PeekInOrOf()) {
        // ES6 'const' and binding patterns require initializers.
        if (parsing_result->descriptor.mode == VariableMode::kConst ||
            impl()->IsNull(name)) {
          impl()->ReportMessageAt(
              Scanner::Location(decl_pos, end_position()),
              MessageTemplate::kDeclarationMissingInitializer,
              impl()->IsNull(name) ? "destructuring" : "const");
          return;
        }
        // 'let x' initializes 'x' to undefined.
        if (parsing_result->descriptor.mode == VariableMode::kLet) {
          value = factory()->NewUndefinedLiteral(position());
        }
      }
    }

    int initializer_position = end_position();
    auto declaration_end = target_scope->declarations()->end();
    for (; declaration_it != declaration_end; ++declaration_it) {
      declaration_it->var()->set_initializer_position(initializer_position);
    }

    // Patterns should be elided iff. they don't have an initializer.
    DCHECK_IMPLIES(impl()->IsNull(pattern),
                   impl()->IsNull(value) ||
                       (var_context == kForStatement && PeekInOrOf()));

    typename DeclarationParsingResult::Declaration decl(pattern, value);
    decl.value_beg_pos = value_beg_pos;

    parsing_result->declarations.push_back(decl);
  } while (Check(Token::kComma));

  parsing_result->bindings_loc =
      Scanner::Location(bindings_start, end_position());
}

template <typename Impl>
typename ParserBase<Impl>::StatementT
ParserBase<Impl>::ParseFunctionDeclaration() {
  Consume(Token::kFunction);

  int pos = position();
  ParseFunctionFlags flags = ParseFunctionFlag::kIsNormal;
  if (Check(Token::kMul)) {
    impl()->ReportMessageAt(
        scanner()->location(),
        MessageTemplate::kGeneratorInSingleStatementContext);
    return impl()->NullStatement();
  }
  return ParseHoistableDeclaration(pos, flags, nullptr, false);
}

template <typename Impl>
typename ParserBase<Impl>::StatementT
ParserBase<Impl>::ParseHoistableDeclaration(
    ZonePtrList<const AstRawString>* names, bool default_export) {
  Consume(Token::kFunction);

  int pos = position();
  ParseFunctionFlags flags = ParseFunctionFlag::kIsNormal;
  if (Check(Token::kMul)) {
    flags |= ParseFunctionFlag::kIsGenerator;
  }
  return ParseHoistableDeclaration(pos, flags, names, default_export);
}

template <typename Impl>
typename ParserBase<Impl>::StatementT
ParserBase<Impl>::ParseHoistableDeclaration(
    int pos, ParseFunctionFlags flags, ZonePtrList<const AstRawString>* names,
    bool default_export) {
  CheckStackOverflow();

  // FunctionDeclaration ::
  //   'function' Identifier '(' FormalParameters ')' '{' FunctionBody '}'
  //   'function' '(' FormalParameters ')' '{' FunctionBody '}'
  // GeneratorDeclaration ::
  //   'function' '*' Identifier '(' FormalParameters ')' '{' FunctionBody '}'
  //   'function' '*' '(' FormalParameters ')' '{' FunctionBody '}'
  //
  // The anonymous forms are allowed iff [default_export] is true.
  //
  // 'function' and '*' (if present) have been consumed by the caller.

  DCHECK_IMPLIES((flags & ParseFunctionFlag::kIsAsync) != 0,
                 (flags & ParseFunctionFlag::kIsGenerator) == 0);

  if ((flags & ParseFunctionFlag::kIsAsync) != 0 && Check(Token::kMul)) {
    // Async generator
    flags |= ParseFunctionFlag::kIsGenerator;
  }

  IdentifierT name;
  FunctionNameValidity name_validity;
  IdentifierT variable_name;
  if (peek() == Token::kLeftParen) {
    if (default_export) {
      impl()->GetDefaultStrings(&name, &variable_name);
      name_validity = kSkipFunctionNameCheck;
    } else {
      ReportMessage(MessageTemplate::kMissingFunctionName);
      return impl()->NullStatement();
    }
  } else {
    bool is_strict_reserved = Token::IsStrictReservedWord(peek());
    name = ParseIdentifier();
    name_validity = is_strict_reserved ? kFunctionNameIsStrictReserved
                                       : kFunctionNameValidityUnknown;
    variable_name = name;
  }

  FuncNameInferrerState fni_state(&fni_);
  impl()->PushEnclosingName(name);

  FunctionKind function_kind = FunctionKindFor(flags);

  FunctionLiteralT function = impl()->ParseFunctionLiteral(
      name, scanner()->location(), name_validity, function_kind, pos,
      FunctionSyntaxKind::kDeclaration, language_mode(), nullptr);

  // In ES6, a function behaves as a lexical binding, except in
  // a script scope, or the initial scope of eval or another function.
  VariableMode mode =
      (!scope()->is_declaration_scope() || scope()->is_module_scope())
          ? VariableMode::kLet
          : VariableMode::kVar;
  // Async functions don't undergo sloppy mode block scoped hoisting, and don't
  // allow duplicates in a block. Both are represented by the
  // sloppy_block_functions_. Don't add them to the map for async functions.
  // Generators are also supposed to be prohibited; currently doing this behind
  // a flag and UseCounting violations to assess web compatibility.
  VariableKind kind = is_sloppy(language_mode()) &&
                              !scope()->is_declaration_scope() &&
                              flags == ParseFunctionFlag::kIsNormal
                          ? SLOPPY_BLOCK_FUNCTION_VARIABLE
                          : NORMAL_VARIABLE;

  return impl()->DeclareFunction(variable_name, function, mode, kind, pos,
                                 end_position(), names);
}

template <typename Impl>
typename ParserBase<Impl>::StatementT ParserBase<Impl>::ParseClassDeclaration(
    ZonePtrList<const AstRawString>* names, bool default_export) {
  // ClassDeclaration ::
  //   'class' Identifier ('extends' LeftHandExpression)? '{' ClassBody '}'
  //   'class' ('extends' LeftHandExpression)? '{' ClassBody '}'
  //
  // The anonymous form is allowed iff [default_export] is true.
  //
  // 'class' is expected to be consumed by the caller.
  //
  // A ClassDeclaration
  //
  //   class C { ... }
  //
  // has the same semantics as:
  //
  //   let C = class C { ... };
  //
  // so rewrite it as such.

  int class_token_pos = position();
  IdentifierT name = impl()->EmptyIdentifierString();
  bool is_strict_reserved = Token::IsStrictReservedWord(peek());
  IdentifierT variable_name = impl()->NullIdentifier();
  if (default_export &&
      (peek() == Token::kExtends || peek() == Token::kLeftBrace)) {
    impl()->GetDefaultStrings(&name, &variable_name);
  } else {
    name = ParseIdentifier();
    variable_name = name;
  }

  ExpressionParsingScope no_expression_scope(impl());
  ExpressionT value = ParseClassLiteral(scope(), name, scanner()->location(),
                                        is_strict_reserved, class_token_pos);
  no_expression_scope.ValidateExpression();
  int end_pos = position();
  return impl()->DeclareClass(variable_name, value, names, class_token_pos,
                              end_pos);
}

// Language extension which is only enabled for source files loaded
// through the API's extension mechanism. A native function
// declaration is resolved by looking up the function through a
// callback provided by the extension.
template <typename Impl>
typename ParserBase<Impl>::StatementT
ParserBase<Impl>::ParseNativeDeclaration() {
  function_state_->DisableOptimization(BailoutReason::kNativeFunctionLiteral);

  int pos = peek_position();
  Consume(Token::kFunction);
  // Allow "eval" or "arguments" for backward compatibility.
  IdentifierT name = ParseIdentifier();
  Expect(Token::kLeftParen);
  if (peek() != Token::kRightParen) {
    do {
      ParseIdentifier();
    } while (Check(Token::kComma));
  }
  Expect(Token::kRightParen);
  Expect(Token::kSemicolon);
  return impl()->DeclareNative(name, pos);
}

template <typename Impl>
typename ParserBase<Impl>::StatementT
ParserBase<Impl>::ParseAsyncFunctionDeclaration(
    ZonePtrList<const AstRawString>* names, bool default_export) {
  // AsyncFunctionDeclaration ::
  //   async [no LineTerminator here] function BindingIdentifier[Await]
  //       ( FormalParameters[Await] ) { AsyncFunctionBody }
  DCHECK_EQ(scanner()->current_token(), Token::kAsync);
  if (V8_UNLIKELY(scanner()->literal_contains_escapes())) {
    impl()->ReportUnexpectedToken(Token::kEscapedKeyword);
  }
  int pos = position();
  DCHECK(!scanner()->HasLineTerminatorBeforeNext());
  Consume(Token::kFunction);
  ParseFunctionFlags flags = ParseFunctionFlag::kIsAsync;
  return ParseHoistableDeclaration(pos, flags, names, default_export);
}

template <typename Impl>
void ParserBase<Impl>::ParseFunctionBody(
    StatementListT* body, IdentifierT function_name, int pos,
    const FormalParametersT& parameters, FunctionKind kind,
    FunctionSyntaxKind function_syntax_kind, FunctionBodyType body_type) {
  CheckStackOverflow();

  if (IsResumableFunction(kind)) impl()->PrepareGeneratorVariables();

  DeclarationScope* function_scope = parameters.scope;
  DeclarationScope* inner_scope = function_scope;

  // Building the parameter initialization block declares the parameters.
  // TODO(verwaest): Rely on ArrowHeadParsingScope instead.
  if (V8_UNLIKELY(!parameters.is_simple)) {
    if (has_error()) return;
    body->Add(impl()->BuildParameterInitializationBlock(parameters));
    if (has_error()) return;

    inner_scope = NewVarblockScope();
    inner_scope->set_start_position(position());
  }

  StatementListT inner_body(pointer_buffer());

  {
    BlockState block_state(&scope_, inner_scope);

    if (body_type == FunctionBodyType::kExpression) {
      ExpressionT expression = ParseAssignmentExpression();
      inner_body.Add(BuildReturnStatement(expression, expression->position()));
    } else {
      DCHECK(accept_IN_);
      DCHECK_EQ(FunctionBodyType::kBlock, body_type);
      // If we are parsing the source as if it is wrapped in a function, the
      // source ends without a closing brace.
      Token::Value closing_token =
          function_syntax_kind == FunctionSyntaxKind::kWrapped
              ? Token::kEos
              : Token::kRightBrace;

      if (IsAsyncGeneratorFunction(kind)) {
        impl()->ParseAsyncGeneratorFunctionBody(pos, kind, &inner_body);
      } else if (IsGeneratorFunction(kind)) {
        impl()->ParseGeneratorFunctionBody(pos, kind, &inner_body);
      } else {
        ParseStatementList(&inner_body, closing_token);
        if (IsAsyncFunction(kind)) {
          inner_scope->set_end_position(end_position());
          function_state_ = AddOneSuspendPointIfBlockContainsAwaitUsing(
              inner_scope, function_state_);
        }
      }
      if (IsDerivedConstructor(kind)) {
        // Derived constructors are implemented by returning `this` when the
        // original return value is undefined, so always use `this`.
        ExpressionParsingScope expression_scope(impl());
        UseThis();
        expression_scope.ValidateExpression();
      }
      Expect(closing_token);
    }
  }

  scope()->set_end_position(end_position());

  bool allow_duplicate_parameters = false;

  CheckConflictingVarDeclarations(inner_scope);

  if (V8_LIKELY(parameters.is_simple)) {
    DCHECK_EQ(inner_scope, function_scope);
    if (is_sloppy(function_scope->language_mode())) {
      impl()->InsertSloppyBlockFunctionVarBindings(function_scope);
    }
    allow_duplicate_parameters =
        is_sloppy(function_scope->language_mode()) && !IsConciseMethod(kind);
  } else {
    DCHECK_NOT_NULL(inner_scope);
    DCHECK_EQ(function_scope, scope());
    DCHECK_EQ(function_scope, inner_scope->outer_scope());
    impl()->SetLanguageMode(function_scope, inner_scope->language_mode());

    if (is_sloppy(inner_scope->language_mode())) {
      impl()->InsertSloppyBlockFunctionVarBindings(inner_scope);
    }

    inner_scope->set_end_position(end_position());
    if (inner_scope->FinalizeBlockScope() != nullptr) {
      BlockT inner_block = factory()->NewBlock(true, inner_body);
      inner_body.Rewind();
      inner_body.Add(inner_block);
      inner_block->set_scope(inner_scope);
      impl()->RecordBlockSourceRange(inner_block, scope()->end_position());
      if (!impl()->HasCheckedSyntax()) {
        const AstRawString* conflict = inner_scope->FindVariableDeclaredIn(
            function_scope, VariableMode::kLastLexicalVariableMode);
        if (conflict != nullptr) {
          impl()->ReportVarRedeclarationIn(conflict, inner_scope);
        }
      }

      // According to ES#sec-functiondeclarationinstantiation step 27,28
      // when hasParameterExpressions is true, we need bind var declared
      // arguments to "arguments exotic object", so we here first declare
      // "arguments exotic object", then var declared arguments will be
      // initialized with "arguments exotic object"
      if (!IsArrowFunction(kind)) {
        function_scope->DeclareArguments(ast_value_factory());
      }

      impl()->InsertShadowingVarBindingInitializers(inner_block);
    }
  }

  ValidateFormalParameters(language_mode(), parameters,
                           allow_duplicate_parameters);

  if (!IsArrowFunction(kind)) {
    function_scope->DeclareArguments(ast_value_factory());
  }

  impl()->DeclareFunctionNameVar(function_name, function_syntax_kind,
                                 function_scope);

  inner_body.MergeInto(body);
}

template <typename Impl>
void ParserBase<Impl>::CheckArityRestrictions(int param_count,
                                              FunctionKind function_kind,
                                              bool has_rest,
                                              int formals_start_pos,
                                              int formals_end_pos) {
  if (impl()->HasCheckedSyntax()) return;
  if (IsGetterFunction(function_kind)) {
    if (param_count != 0) {
      impl()->ReportMessageAt(
          Scanner::Location(formals_start_pos, formals_end_pos),
          MessageTemplate::kBadGetterArity);
    }
  } else if (IsSetterFunction(function_kind)) {
    if (param_count != 1) {
      impl()->ReportMessageAt(
          Scanner::Location(formals_start_pos, formals_end_pos),
          MessageTemplate::kBadSetterArity);
    }
    if (has_rest) {
      impl()->ReportMessageAt(
          Scanner::Location(formals_start_pos, formals_end_pos),
          MessageTemplate::kBadSetterRestParameter);
    }
  }
}

template <typename Impl>
bool ParserBase<Impl>::IsNextLetKeyword() {
  DCHECK_EQ(Token::kLet, peek());
  Token::Value next_next = PeekAhead();
  switch (next_next) {
    case Token::kLeftBrace:
    case Token::kLeftBracket:
    case Token::kIdentifier:
    case Token::kStatic:
    case Token::kLet:  // `let let;` is disallowed by static semantics, but the
                       // token must be first interpreted as a keyword in order
                       // for those semantics to apply. This ensures that ASI is
                       // not honored when a LineTerminator separates the
                       // tokens.
    case Token::kYield:
    case Token::kAwait:
    case Token::kGet:
    case Token::kSet:
    case Token::kOf:
    case Token::kUsing:
    case Token::kAccessor:
    case Token::kAsync:
      return true;
    case Token::kFutureStrictReservedWord:
    case Token::kEscapedStrictReservedWord:
      // The early error rule for future reserved keywords
      // (ES#sec-identifiers-static-semantics-early-errors) uses the static
      // semantics StringValue of IdentifierName, which normalizes escape
      // sequences. So, both escaped and unescaped future reserved keywords are
      // allowed as identifiers in sloppy mode.
      return is_sloppy(language_mode());
    default:
      return false;
  }
}

template <typename Impl>
typename ParserBase<Impl>::ExpressionT
ParserBase<Impl>::ParseArrowFunctionLiteral(
    const FormalParametersT& formal_parameters, int function_literal_id,
    bool could_be_immediately_invoked) {
  RCS_SCOPE(runtime_call_stats_,
            Impl::IsPreParser()
                ? RuntimeCallCounterId::kPreParseArrowFunctionLiteral
                : RuntimeCallCounterId::kParseArrowFunctionLiteral,
            RuntimeCallStats::kThreadSpecific);
  base::ElapsedTimer timer;
  if (V8_UNLIKELY(v8_flags.log_function_events)) timer.Start();

  DCHECK_IMPLIES(!has_error(), peek() == Token::kArrow);
  if (!impl()->HasCheckedSyntax() && scanner_->HasLineTerminatorBeforeNext()) {
    // No line terminator allowed between the parameters and the arrow:
    // ArrowFunction[In, Yield, Await] :
    //   ArrowParameters[?Yield, ?Await] [no LineTerminator here] =>
    //   ConciseBody[?In]
    // If the next token is not `=>`, it's a syntax error anyway.
    impl()->ReportUnexpectedTokenAt(scanner_->peek_location(), Token::kArrow);
    return impl()->FailureExpression();
  }

  int expected_property_count = 0;
  int suspend_count = 0;

  FunctionKind kind = formal_parameters.scope->function_kind();
  FunctionLiteral::EagerCompileHint eager_compile_hint =
      could_be_immediately_invoked ||
              (compile_hints_magic_enabled_ &&
               scanner_->SawMagicCommentCompileHintsAll())
          ? FunctionLiteral::kShouldEagerCompile
          : default_eager_compile_hint_;

  int compile_hint_position = formal_parameters.scope->start_position();
  eager_compile_hint =
      impl()->GetEmbedderCompileHint(eager_compile_hint, compile_hint_position);

  bool can_preparse = impl()->parse_lazily() &&
                      eager_compile_hint == FunctionLiteral::kShouldLazyCompile;
  // TODO(marja): consider lazy-parsing inner arrow functions too. is_this
  // handling in Scope::ResolveVariable needs to change.
  bool is_lazy_top_level_function =
      can_preparse && impl()->AllowsLazyParsingWithoutUnresolvedVariables();
  bool has_braces = true;
  ProducedPreparseData* produced_preparse_data = nullptr;
  StatementListT body(pointer_buffer());
  {
    FunctionState function_state(&function_state_, &scope_,
                                 formal_parameters.scope);

    Consume(Token::kArrow);

    if (peek() == Token::kLeftBrace) {
      // Multiple statement body
      DCHECK_EQ(scope(), formal_parameters.scope);

      if (is_lazy_top_level_function) {
        // FIXME(marja): Arrow function parameters will be parsed even
### 提示词
```
这是目录为v8/src/parsing/parser-base.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/parsing/parser-base.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第6部分，共9部分，请归纳一下它的功能
```

### 源代码
```c
meters->arity + 1 > Code::kMaxArguments) {
        ReportMessage(MessageTemplate::kTooManyParameters);
        return;
      }
      parameters->has_rest = Check(Token::kEllipsis);
      ParseFormalParameter(parameters);

      if (parameters->has_rest) {
        parameters->is_simple = false;
        if (peek() == Token::kComma) {
          impl()->ReportMessageAt(scanner()->peek_location(),
                                  MessageTemplate::kParamAfterRest);
          return;
        }
        break;
      }
      if (!Check(Token::kComma)) break;
      if (peek() == Token::kRightParen) {
        // allow the trailing comma
        break;
      }
    }
  }

  impl()->DeclareFormalParameters(parameters);
}

template <typename Impl>
void ParserBase<Impl>::ParseVariableDeclarations(
    VariableDeclarationContext var_context,
    DeclarationParsingResult* parsing_result,
    ZonePtrList<const AstRawString>* names) {
  // VariableDeclarations ::
  //   ('var' | 'const' | 'let' | 'using' | 'await using') (Identifier ('='
  //   AssignmentExpression)?)+[',']
  //
  // ES6:
  // FIXME(marja, nikolaos): Add an up-to-date comment about ES6 variable
  // declaration syntax.

  DCHECK_NOT_NULL(parsing_result);
  parsing_result->descriptor.kind = NORMAL_VARIABLE;
  parsing_result->descriptor.declaration_pos = peek_position();
  parsing_result->descriptor.initialization_pos = peek_position();

  switch (peek()) {
    case Token::kVar:
      parsing_result->descriptor.mode = VariableMode::kVar;
      Consume(Token::kVar);
      break;
    case Token::kConst:
      Consume(Token::kConst);
      DCHECK_NE(var_context, kStatement);
      parsing_result->descriptor.mode = VariableMode::kConst;
      break;
    case Token::kLet:
      Consume(Token::kLet);
      DCHECK_NE(var_context, kStatement);
      parsing_result->descriptor.mode = VariableMode::kLet;
      break;
    case Token::kUsing:
      // using [no LineTerminator here] [lookahead ≠ await] BindingList[?In,
      // ?Yield, ?Await, ~Pattern] ;
      Consume(Token::kUsing);
      DCHECK(v8_flags.js_explicit_resource_management);
      DCHECK_NE(var_context, kStatement);
      DCHECK(is_using_allowed());
      DCHECK(peek() != Token::kAwait);
      DCHECK(!scanner()->HasLineTerminatorBeforeNext());
      DCHECK(peek() != Token::kLeftBracket && peek() != Token::kLeftBrace);
      parsing_result->descriptor.mode = VariableMode::kUsing;
      break;
    case Token::kAwait:
      // CoverAwaitExpressionAndAwaitUsingDeclarationHead[?Yield] [no
      // LineTerminator here] BindingList[?In, ?Yield, +Await, ~Pattern];
      Consume(Token::kAwait);
      DCHECK(v8_flags.js_explicit_resource_management);
      DCHECK_NE(var_context, kStatement);
      DCHECK(is_using_allowed());
      DCHECK(is_await_allowed());
      Consume(Token::kUsing);
      DCHECK(!scanner()->HasLineTerminatorBeforeNext());
      DCHECK(peek() != Token::kLeftBracket && peek() != Token::kLeftBrace);
      parsing_result->descriptor.mode = VariableMode::kAwaitUsing;
      break;
    default:
      UNREACHABLE();  // by current callers
      break;
  }

  VariableDeclarationParsingScope declaration(
      impl(), parsing_result->descriptor.mode, names);
  Scope* target_scope = IsLexicalVariableMode(parsing_result->descriptor.mode)
                            ? scope()
                            : scope()->GetDeclarationScope();

  auto declaration_it = target_scope->declarations()->end();

  int bindings_start = peek_position();
  do {
    // Parse binding pattern.
    FuncNameInferrerState fni_state(&fni_);

    int decl_pos = peek_position();

    IdentifierT name;
    ExpressionT pattern;
    // Check for an identifier first, so that we can elide the pattern in cases
    // where there is no initializer (and so no proxy needs to be created).
    if (V8_LIKELY(Token::IsAnyIdentifier(peek()))) {
      name = ParseAndClassifyIdentifier(Next());
      if (V8_UNLIKELY(is_strict(language_mode()) &&
                      impl()->IsEvalOrArguments(name))) {
        impl()->ReportMessageAt(scanner()->location(),
                                MessageTemplate::kStrictEvalArguments);
        return;
      }
      if (peek() == Token::kAssign ||
          (var_context == kForStatement && PeekInOrOf()) ||
          parsing_result->descriptor.mode == VariableMode::kLet) {
        // Assignments need the variable expression for the assignment LHS, and
        // for of/in will need it later, so create the expression now.
        pattern = impl()->ExpressionFromIdentifier(name, decl_pos);
      } else {
        // Otherwise, elide the variable expression and just declare it.
        impl()->DeclareIdentifier(name, decl_pos);
        pattern = impl()->NullExpression();
      }
    } else if (parsing_result->descriptor.mode != VariableMode::kUsing &&
               parsing_result->descriptor.mode != VariableMode::kAwaitUsing) {
      name = impl()->NullIdentifier();
      pattern = ParseBindingPattern();
      DCHECK(!impl()->IsIdentifier(pattern));
    } else {
      // `using` declarations should have an identifier.
      impl()->ReportMessageAt(Scanner::Location(decl_pos, end_position()),
                              MessageTemplate::kDeclarationMissingInitializer,
                              "using");
      return;
    }

    Scanner::Location variable_loc = scanner()->location();

    ExpressionT value = impl()->NullExpression();
    int value_beg_pos = kNoSourcePosition;
    if (Check(Token::kAssign)) {
      DCHECK(!impl()->IsNull(pattern));
      {
        value_beg_pos = peek_position();
        AcceptINScope scope(this, var_context != kForStatement);
        value = ParseAssignmentExpression();
      }
      variable_loc.end_pos = end_position();

      if (!parsing_result->first_initializer_loc.IsValid()) {
        parsing_result->first_initializer_loc = variable_loc;
      }

      // Don't infer if it is "a = function(){...}();"-like expression.
      if (impl()->IsIdentifier(pattern)) {
        if (!value->IsCall() && !value->IsCallNew()) {
          fni_.Infer();
        } else {
          fni_.RemoveLastFunction();
        }
      }

      impl()->SetFunctionNameFromIdentifierRef(value, pattern);
    } else {
#ifdef DEBUG
      // We can fall through into here on error paths, so don't DCHECK those.
      if (!has_error()) {
        // We should never get identifier patterns for the non-initializer path,
        // as those expressions should be elided.
        DCHECK_EQ(!impl()->IsNull(name),
                  Token::IsAnyIdentifier(scanner()->current_token()));
        DCHECK_IMPLIES(impl()->IsNull(pattern), !impl()->IsNull(name));
        // The only times we have a non-null pattern are:
        //   1. This is a destructuring declaration (with no initializer, which
        //      is immediately an error),
        //   2. This is a declaration in a for in/of loop, or
        //   3. This is a let (which has an implicit undefined initializer)
        DCHECK_IMPLIES(
            !impl()->IsNull(pattern),
            !impl()->IsIdentifier(pattern) ||
                (var_context == kForStatement && PeekInOrOf()) ||
                parsing_result->descriptor.mode == VariableMode::kLet);
      }
#endif

      if (var_context != kForStatement || !PeekInOrOf()) {
        // ES6 'const' and binding patterns require initializers.
        if (parsing_result->descriptor.mode == VariableMode::kConst ||
            impl()->IsNull(name)) {
          impl()->ReportMessageAt(
              Scanner::Location(decl_pos, end_position()),
              MessageTemplate::kDeclarationMissingInitializer,
              impl()->IsNull(name) ? "destructuring" : "const");
          return;
        }
        // 'let x' initializes 'x' to undefined.
        if (parsing_result->descriptor.mode == VariableMode::kLet) {
          value = factory()->NewUndefinedLiteral(position());
        }
      }
    }

    int initializer_position = end_position();
    auto declaration_end = target_scope->declarations()->end();
    for (; declaration_it != declaration_end; ++declaration_it) {
      declaration_it->var()->set_initializer_position(initializer_position);
    }

    // Patterns should be elided iff. they don't have an initializer.
    DCHECK_IMPLIES(impl()->IsNull(pattern),
                   impl()->IsNull(value) ||
                       (var_context == kForStatement && PeekInOrOf()));

    typename DeclarationParsingResult::Declaration decl(pattern, value);
    decl.value_beg_pos = value_beg_pos;

    parsing_result->declarations.push_back(decl);
  } while (Check(Token::kComma));

  parsing_result->bindings_loc =
      Scanner::Location(bindings_start, end_position());
}

template <typename Impl>
typename ParserBase<Impl>::StatementT
ParserBase<Impl>::ParseFunctionDeclaration() {
  Consume(Token::kFunction);

  int pos = position();
  ParseFunctionFlags flags = ParseFunctionFlag::kIsNormal;
  if (Check(Token::kMul)) {
    impl()->ReportMessageAt(
        scanner()->location(),
        MessageTemplate::kGeneratorInSingleStatementContext);
    return impl()->NullStatement();
  }
  return ParseHoistableDeclaration(pos, flags, nullptr, false);
}

template <typename Impl>
typename ParserBase<Impl>::StatementT
ParserBase<Impl>::ParseHoistableDeclaration(
    ZonePtrList<const AstRawString>* names, bool default_export) {
  Consume(Token::kFunction);

  int pos = position();
  ParseFunctionFlags flags = ParseFunctionFlag::kIsNormal;
  if (Check(Token::kMul)) {
    flags |= ParseFunctionFlag::kIsGenerator;
  }
  return ParseHoistableDeclaration(pos, flags, names, default_export);
}

template <typename Impl>
typename ParserBase<Impl>::StatementT
ParserBase<Impl>::ParseHoistableDeclaration(
    int pos, ParseFunctionFlags flags, ZonePtrList<const AstRawString>* names,
    bool default_export) {
  CheckStackOverflow();

  // FunctionDeclaration ::
  //   'function' Identifier '(' FormalParameters ')' '{' FunctionBody '}'
  //   'function' '(' FormalParameters ')' '{' FunctionBody '}'
  // GeneratorDeclaration ::
  //   'function' '*' Identifier '(' FormalParameters ')' '{' FunctionBody '}'
  //   'function' '*' '(' FormalParameters ')' '{' FunctionBody '}'
  //
  // The anonymous forms are allowed iff [default_export] is true.
  //
  // 'function' and '*' (if present) have been consumed by the caller.

  DCHECK_IMPLIES((flags & ParseFunctionFlag::kIsAsync) != 0,
                 (flags & ParseFunctionFlag::kIsGenerator) == 0);

  if ((flags & ParseFunctionFlag::kIsAsync) != 0 && Check(Token::kMul)) {
    // Async generator
    flags |= ParseFunctionFlag::kIsGenerator;
  }

  IdentifierT name;
  FunctionNameValidity name_validity;
  IdentifierT variable_name;
  if (peek() == Token::kLeftParen) {
    if (default_export) {
      impl()->GetDefaultStrings(&name, &variable_name);
      name_validity = kSkipFunctionNameCheck;
    } else {
      ReportMessage(MessageTemplate::kMissingFunctionName);
      return impl()->NullStatement();
    }
  } else {
    bool is_strict_reserved = Token::IsStrictReservedWord(peek());
    name = ParseIdentifier();
    name_validity = is_strict_reserved ? kFunctionNameIsStrictReserved
                                       : kFunctionNameValidityUnknown;
    variable_name = name;
  }

  FuncNameInferrerState fni_state(&fni_);
  impl()->PushEnclosingName(name);

  FunctionKind function_kind = FunctionKindFor(flags);

  FunctionLiteralT function = impl()->ParseFunctionLiteral(
      name, scanner()->location(), name_validity, function_kind, pos,
      FunctionSyntaxKind::kDeclaration, language_mode(), nullptr);

  // In ES6, a function behaves as a lexical binding, except in
  // a script scope, or the initial scope of eval or another function.
  VariableMode mode =
      (!scope()->is_declaration_scope() || scope()->is_module_scope())
          ? VariableMode::kLet
          : VariableMode::kVar;
  // Async functions don't undergo sloppy mode block scoped hoisting, and don't
  // allow duplicates in a block. Both are represented by the
  // sloppy_block_functions_. Don't add them to the map for async functions.
  // Generators are also supposed to be prohibited; currently doing this behind
  // a flag and UseCounting violations to assess web compatibility.
  VariableKind kind = is_sloppy(language_mode()) &&
                              !scope()->is_declaration_scope() &&
                              flags == ParseFunctionFlag::kIsNormal
                          ? SLOPPY_BLOCK_FUNCTION_VARIABLE
                          : NORMAL_VARIABLE;

  return impl()->DeclareFunction(variable_name, function, mode, kind, pos,
                                 end_position(), names);
}

template <typename Impl>
typename ParserBase<Impl>::StatementT ParserBase<Impl>::ParseClassDeclaration(
    ZonePtrList<const AstRawString>* names, bool default_export) {
  // ClassDeclaration ::
  //   'class' Identifier ('extends' LeftHandExpression)? '{' ClassBody '}'
  //   'class' ('extends' LeftHandExpression)? '{' ClassBody '}'
  //
  // The anonymous form is allowed iff [default_export] is true.
  //
  // 'class' is expected to be consumed by the caller.
  //
  // A ClassDeclaration
  //
  //   class C { ... }
  //
  // has the same semantics as:
  //
  //   let C = class C { ... };
  //
  // so rewrite it as such.

  int class_token_pos = position();
  IdentifierT name = impl()->EmptyIdentifierString();
  bool is_strict_reserved = Token::IsStrictReservedWord(peek());
  IdentifierT variable_name = impl()->NullIdentifier();
  if (default_export &&
      (peek() == Token::kExtends || peek() == Token::kLeftBrace)) {
    impl()->GetDefaultStrings(&name, &variable_name);
  } else {
    name = ParseIdentifier();
    variable_name = name;
  }

  ExpressionParsingScope no_expression_scope(impl());
  ExpressionT value = ParseClassLiteral(scope(), name, scanner()->location(),
                                        is_strict_reserved, class_token_pos);
  no_expression_scope.ValidateExpression();
  int end_pos = position();
  return impl()->DeclareClass(variable_name, value, names, class_token_pos,
                              end_pos);
}

// Language extension which is only enabled for source files loaded
// through the API's extension mechanism.  A native function
// declaration is resolved by looking up the function through a
// callback provided by the extension.
template <typename Impl>
typename ParserBase<Impl>::StatementT
ParserBase<Impl>::ParseNativeDeclaration() {
  function_state_->DisableOptimization(BailoutReason::kNativeFunctionLiteral);

  int pos = peek_position();
  Consume(Token::kFunction);
  // Allow "eval" or "arguments" for backward compatibility.
  IdentifierT name = ParseIdentifier();
  Expect(Token::kLeftParen);
  if (peek() != Token::kRightParen) {
    do {
      ParseIdentifier();
    } while (Check(Token::kComma));
  }
  Expect(Token::kRightParen);
  Expect(Token::kSemicolon);
  return impl()->DeclareNative(name, pos);
}

template <typename Impl>
typename ParserBase<Impl>::StatementT
ParserBase<Impl>::ParseAsyncFunctionDeclaration(
    ZonePtrList<const AstRawString>* names, bool default_export) {
  // AsyncFunctionDeclaration ::
  //   async [no LineTerminator here] function BindingIdentifier[Await]
  //       ( FormalParameters[Await] ) { AsyncFunctionBody }
  DCHECK_EQ(scanner()->current_token(), Token::kAsync);
  if (V8_UNLIKELY(scanner()->literal_contains_escapes())) {
    impl()->ReportUnexpectedToken(Token::kEscapedKeyword);
  }
  int pos = position();
  DCHECK(!scanner()->HasLineTerminatorBeforeNext());
  Consume(Token::kFunction);
  ParseFunctionFlags flags = ParseFunctionFlag::kIsAsync;
  return ParseHoistableDeclaration(pos, flags, names, default_export);
}

template <typename Impl>
void ParserBase<Impl>::ParseFunctionBody(
    StatementListT* body, IdentifierT function_name, int pos,
    const FormalParametersT& parameters, FunctionKind kind,
    FunctionSyntaxKind function_syntax_kind, FunctionBodyType body_type) {
  CheckStackOverflow();

  if (IsResumableFunction(kind)) impl()->PrepareGeneratorVariables();

  DeclarationScope* function_scope = parameters.scope;
  DeclarationScope* inner_scope = function_scope;

  // Building the parameter initialization block declares the parameters.
  // TODO(verwaest): Rely on ArrowHeadParsingScope instead.
  if (V8_UNLIKELY(!parameters.is_simple)) {
    if (has_error()) return;
    body->Add(impl()->BuildParameterInitializationBlock(parameters));
    if (has_error()) return;

    inner_scope = NewVarblockScope();
    inner_scope->set_start_position(position());
  }

  StatementListT inner_body(pointer_buffer());

  {
    BlockState block_state(&scope_, inner_scope);

    if (body_type == FunctionBodyType::kExpression) {
      ExpressionT expression = ParseAssignmentExpression();
      inner_body.Add(BuildReturnStatement(expression, expression->position()));
    } else {
      DCHECK(accept_IN_);
      DCHECK_EQ(FunctionBodyType::kBlock, body_type);
      // If we are parsing the source as if it is wrapped in a function, the
      // source ends without a closing brace.
      Token::Value closing_token =
          function_syntax_kind == FunctionSyntaxKind::kWrapped
              ? Token::kEos
              : Token::kRightBrace;

      if (IsAsyncGeneratorFunction(kind)) {
        impl()->ParseAsyncGeneratorFunctionBody(pos, kind, &inner_body);
      } else if (IsGeneratorFunction(kind)) {
        impl()->ParseGeneratorFunctionBody(pos, kind, &inner_body);
      } else {
        ParseStatementList(&inner_body, closing_token);
        if (IsAsyncFunction(kind)) {
          inner_scope->set_end_position(end_position());
          function_state_ = AddOneSuspendPointIfBlockContainsAwaitUsing(
              inner_scope, function_state_);
        }
      }
      if (IsDerivedConstructor(kind)) {
        // Derived constructors are implemented by returning `this` when the
        // original return value is undefined, so always use `this`.
        ExpressionParsingScope expression_scope(impl());
        UseThis();
        expression_scope.ValidateExpression();
      }
      Expect(closing_token);
    }
  }

  scope()->set_end_position(end_position());

  bool allow_duplicate_parameters = false;

  CheckConflictingVarDeclarations(inner_scope);

  if (V8_LIKELY(parameters.is_simple)) {
    DCHECK_EQ(inner_scope, function_scope);
    if (is_sloppy(function_scope->language_mode())) {
      impl()->InsertSloppyBlockFunctionVarBindings(function_scope);
    }
    allow_duplicate_parameters =
        is_sloppy(function_scope->language_mode()) && !IsConciseMethod(kind);
  } else {
    DCHECK_NOT_NULL(inner_scope);
    DCHECK_EQ(function_scope, scope());
    DCHECK_EQ(function_scope, inner_scope->outer_scope());
    impl()->SetLanguageMode(function_scope, inner_scope->language_mode());

    if (is_sloppy(inner_scope->language_mode())) {
      impl()->InsertSloppyBlockFunctionVarBindings(inner_scope);
    }

    inner_scope->set_end_position(end_position());
    if (inner_scope->FinalizeBlockScope() != nullptr) {
      BlockT inner_block = factory()->NewBlock(true, inner_body);
      inner_body.Rewind();
      inner_body.Add(inner_block);
      inner_block->set_scope(inner_scope);
      impl()->RecordBlockSourceRange(inner_block, scope()->end_position());
      if (!impl()->HasCheckedSyntax()) {
        const AstRawString* conflict = inner_scope->FindVariableDeclaredIn(
            function_scope, VariableMode::kLastLexicalVariableMode);
        if (conflict != nullptr) {
          impl()->ReportVarRedeclarationIn(conflict, inner_scope);
        }
      }

      // According to ES#sec-functiondeclarationinstantiation step 27,28
      // when hasParameterExpressions is true, we need bind var declared
      // arguments to "arguments exotic object", so we here first declare
      // "arguments exotic object", then var declared arguments will be
      // initialized with "arguments exotic object"
      if (!IsArrowFunction(kind)) {
        function_scope->DeclareArguments(ast_value_factory());
      }

      impl()->InsertShadowingVarBindingInitializers(inner_block);
    }
  }

  ValidateFormalParameters(language_mode(), parameters,
                           allow_duplicate_parameters);

  if (!IsArrowFunction(kind)) {
    function_scope->DeclareArguments(ast_value_factory());
  }

  impl()->DeclareFunctionNameVar(function_name, function_syntax_kind,
                                 function_scope);

  inner_body.MergeInto(body);
}

template <typename Impl>
void ParserBase<Impl>::CheckArityRestrictions(int param_count,
                                              FunctionKind function_kind,
                                              bool has_rest,
                                              int formals_start_pos,
                                              int formals_end_pos) {
  if (impl()->HasCheckedSyntax()) return;
  if (IsGetterFunction(function_kind)) {
    if (param_count != 0) {
      impl()->ReportMessageAt(
          Scanner::Location(formals_start_pos, formals_end_pos),
          MessageTemplate::kBadGetterArity);
    }
  } else if (IsSetterFunction(function_kind)) {
    if (param_count != 1) {
      impl()->ReportMessageAt(
          Scanner::Location(formals_start_pos, formals_end_pos),
          MessageTemplate::kBadSetterArity);
    }
    if (has_rest) {
      impl()->ReportMessageAt(
          Scanner::Location(formals_start_pos, formals_end_pos),
          MessageTemplate::kBadSetterRestParameter);
    }
  }
}

template <typename Impl>
bool ParserBase<Impl>::IsNextLetKeyword() {
  DCHECK_EQ(Token::kLet, peek());
  Token::Value next_next = PeekAhead();
  switch (next_next) {
    case Token::kLeftBrace:
    case Token::kLeftBracket:
    case Token::kIdentifier:
    case Token::kStatic:
    case Token::kLet:  // `let let;` is disallowed by static semantics, but the
                       // token must be first interpreted as a keyword in order
                       // for those semantics to apply. This ensures that ASI is
                       // not honored when a LineTerminator separates the
                       // tokens.
    case Token::kYield:
    case Token::kAwait:
    case Token::kGet:
    case Token::kSet:
    case Token::kOf:
    case Token::kUsing:
    case Token::kAccessor:
    case Token::kAsync:
      return true;
    case Token::kFutureStrictReservedWord:
    case Token::kEscapedStrictReservedWord:
      // The early error rule for future reserved keywords
      // (ES#sec-identifiers-static-semantics-early-errors) uses the static
      // semantics StringValue of IdentifierName, which normalizes escape
      // sequences. So, both escaped and unescaped future reserved keywords are
      // allowed as identifiers in sloppy mode.
      return is_sloppy(language_mode());
    default:
      return false;
  }
}

template <typename Impl>
typename ParserBase<Impl>::ExpressionT
ParserBase<Impl>::ParseArrowFunctionLiteral(
    const FormalParametersT& formal_parameters, int function_literal_id,
    bool could_be_immediately_invoked) {
  RCS_SCOPE(runtime_call_stats_,
            Impl::IsPreParser()
                ? RuntimeCallCounterId::kPreParseArrowFunctionLiteral
                : RuntimeCallCounterId::kParseArrowFunctionLiteral,
            RuntimeCallStats::kThreadSpecific);
  base::ElapsedTimer timer;
  if (V8_UNLIKELY(v8_flags.log_function_events)) timer.Start();

  DCHECK_IMPLIES(!has_error(), peek() == Token::kArrow);
  if (!impl()->HasCheckedSyntax() && scanner_->HasLineTerminatorBeforeNext()) {
    // No line terminator allowed between the parameters and the arrow:
    // ArrowFunction[In, Yield, Await] :
    //   ArrowParameters[?Yield, ?Await] [no LineTerminator here] =>
    //   ConciseBody[?In]
    // If the next token is not `=>`, it's a syntax error anyway.
    impl()->ReportUnexpectedTokenAt(scanner_->peek_location(), Token::kArrow);
    return impl()->FailureExpression();
  }

  int expected_property_count = 0;
  int suspend_count = 0;

  FunctionKind kind = formal_parameters.scope->function_kind();
  FunctionLiteral::EagerCompileHint eager_compile_hint =
      could_be_immediately_invoked ||
              (compile_hints_magic_enabled_ &&
               scanner_->SawMagicCommentCompileHintsAll())
          ? FunctionLiteral::kShouldEagerCompile
          : default_eager_compile_hint_;

  int compile_hint_position = formal_parameters.scope->start_position();
  eager_compile_hint =
      impl()->GetEmbedderCompileHint(eager_compile_hint, compile_hint_position);

  bool can_preparse = impl()->parse_lazily() &&
                      eager_compile_hint == FunctionLiteral::kShouldLazyCompile;
  // TODO(marja): consider lazy-parsing inner arrow functions too. is_this
  // handling in Scope::ResolveVariable needs to change.
  bool is_lazy_top_level_function =
      can_preparse && impl()->AllowsLazyParsingWithoutUnresolvedVariables();
  bool has_braces = true;
  ProducedPreparseData* produced_preparse_data = nullptr;
  StatementListT body(pointer_buffer());
  {
    FunctionState function_state(&function_state_, &scope_,
                                 formal_parameters.scope);

    Consume(Token::kArrow);

    if (peek() == Token::kLeftBrace) {
      // Multiple statement body
      DCHECK_EQ(scope(), formal_parameters.scope);

      if (is_lazy_top_level_function) {
        // FIXME(marja): Arrow function parameters will be parsed even if the
        // body is preparsed; move relevant parts of parameter handling to
        // simulate consistent parameter handling.

        // Building the parameter initialization block declares the parameters.
        // TODO(verwaest): Rely on ArrowHeadParsingScope instead.
        if (!formal_parameters.is_simple) {
          impl()->BuildParameterInitializationBlock(formal_parameters);
          if (has_error()) return impl()->FailureExpression();
        }

        // For arrow functions, we don't need to retrieve data about function
        // parameters.
        int dummy_num_parameters = -1;
        int dummy_function_length = -1;
        DCHECK(IsArrowFunction(kind));
        bool did_preparse_successfully = impl()->SkipFunction(
            nullptr, kind, FunctionSyntaxKind::kAnonymousExpression,
            formal_parameters.scope, &dummy_num_parameters,
            &dummy_function_length, &produced_preparse_data);

        DCHECK_NULL(produced_preparse_data);

        if (did_preparse_successfully) {
          // Validate parameter names. We can do this only after preparsing the
          // function, since the function can declare itself strict.
          ValidateFormalParameters(language_mode(), formal_parameters, false);
        } else {
          // In case we did not sucessfully preparse the function because of an
          // unidentified error we do a full reparse to return the error.
          // Parse again in the outer scope, since the language mode may change.
          BlockState block_state(&scope_, scope()->outer_scope());
          ExpressionT expression = ParseConditionalExpression();
          // Reparsing the head may have caused a stack overflow.
          if (has_error()) return impl()->FailureExpression();

          DeclarationScope* function_scope = next_arrow_function_info_.scope;
          FunctionState inner_function_state(&function_state_, &scope_,
                                             function_scope);
          Scanner::Location loc(function_scope->start_position(),
                                end_position());
          FormalParametersT parameters(function_scope);
          parameters.is_simple = function_scope->has_simple_parameters();
          impl()->DeclareArrowFunctionFormalParameters(&parameters, expression,
                                                       loc);
          next_arrow_function_info_.Reset();

          Consume(Token::kArrow);
          Consume(Token::kLeftBrace);

          AcceptINScope scope(this, true);
          FunctionParsingScope body_parsing_scope(impl());
          ParseFunctionBody(&body, impl()->NullIdentifier(), kNoSourcePosition,
                            parameters, kind,
                            FunctionSyntaxKind::kAnonymousExpression,
                            FunctionBodyType::kBlock);
          CHECK(has_error());
          return impl()->FailureExpression();
        }
      } else {
        Consume(Token::kLeftBrace);
        AcceptINScope scope(this, true);
        FunctionParsingScope body_parsing_scope(impl());
        ParseFunctionBody(&body, impl()->NullIdentifier(), kNoSourcePosition,
                          formal_parameters, kind,
                          FunctionSyntaxKind::kAnonymousExpression,
                          FunctionBodyType::kBlock);
        expected_property_count = function_state.expected_property_count();
      }
    } else {
      // Single-expression body
      has_braces = false;
      FunctionParsingScope body_parsing_scope(impl());
      ParseFunctionBody(&body, impl()->NullIdentifier(), kNoSourcePosition,
                        formal_parameters, kind,
                        FunctionSyntaxKind::kAnonymousExpression,
                        FunctionBodyType::kExpression);
      expected_property_count = function_state.expected_property_count();
    }

    formal_parameters.scope->set_end_position(end_position());

    // Validate strict mode.
    if (is_strict(language_mode())) {
      CheckStrictOctalLiteral(formal_parameters.scope->start_position(),
                              end_position());
    }
    suspend_count = function_state.suspend_count();
  }

  FunctionLiteralT function_literal = factory()->NewFunctionLiteral(
      impl()->EmptyIdentifierString(), formal_parameters.scope, body,
      expected_property_count, formal_parameters.num_parameters(),
      formal_parameters.function_length,
      FunctionLiteral::kNoDuplicateParameters,
      FunctionSyntaxKind::kAnonymousExpression, eager_compile_hint,
      formal_parameters.scope->start_position(), has_braces,
      function_literal_id, produced_preparse_data);

  function_literal->set_suspend_count(suspend_count);
  function_literal->set_function_token_position(
      formal_parameters.scope->start_position());

  impl()->RecordFunctionLiteralSourceRange(function_literal);
  impl()->AddFunctionForNameInference(function_literal);

  if (V8_UNLIKELY(v8_flags.log_function_events)) {
    Scope* scope = formal_parameters.scope;
    double ms = timer.Elapsed().InMillisecondsF();
    const char* event_name =
        is_lazy_top_level_function ? "preparse-no-resolution" : "parse";
    const char* name = "arrow function";
    v8_file_logger_->FunctionEvent(event_name, flags().script_id(), ms,
                                   scope->start_position(),
                                   scope->end_position(), name, strlen(name));
  }

  return function_literal;
}

template <typename Impl>
typename ParserBase<Impl>::ExpressionT ParserBase<Impl>::ParseClassExpression(
    Scope* outer_scope) {
  Consume(Token::kClass);
  int class_token_pos = position();
  IdentifierT name = impl()->EmptyIdentifierString();
  bool is_strict_reserved_name = false;
  Scanner::Location class_name_location = Scanner::Location::invalid();
  if (peek_any_identifier()) {
    name = ParseAndClassifyIdentifier(Next());
    class_name_location = scanner()->location();
    is_strict_reserved_name =
        Token::IsStrictReservedWord(scanner()->current_token());
  }
  return ParseClassLiteral(outer_scope, name, class_name_location,
                           is_strict_reserved_name, class_token_pos);
}

template <typename Impl>
typename ParserBase<Impl>::ExpressionT ParserBase<Impl>::ParseClassLiteral(
    Scope* outer_scope, IdentifierT name, Scanner::Location class_name_location,
    bool name_is_strict_reserved, int class_token_pos) {
  bool is_anonymous = impl()->IsEmptyIdentifier(name);

  // All parts of a ClassDeclaration and ClassExpression are strict code.
  if (!impl()->HasCheckedSyntax() && !is_anonymous) {
    if (name_is_strict_reserved) {
      impl()->ReportMessageAt(class_name_location,
                              MessageTemplate::kUnexpectedStrictReserved);
      return impl()->FailureExpression();
    }
    if (impl()->IsEvalOrArguments(name)) {
      impl()->ReportMessageAt(class_name_location,
                              MessageTemplate::kStrictEvalArguments);
      return impl()->FailureExpression();
    }
  }

  ClassScope* class_scope = NewClassScope(outer_scope, is_anonymous);
  BlockState block_state(&scope_, class_scope);
  RaiseLanguageMode(LanguageMode::kStrict);

  BlockState object_literal_scope_state(&object_literal_scope_, nullp
```