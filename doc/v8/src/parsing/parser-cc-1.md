Response:
The user wants a summary of the functionalities present in the provided C++ code snippet from `v8/src/parsing/parser.cc`. The request also includes conditions for identifying Torque code and relating the code to JavaScript. I need to carefully analyze the code, identify its key functionalities, and present them concisely. Since this is part 2 of 5, I should focus on the features evident in this specific snippet and avoid speculating about functionalities that might appear in other parts.

Here's a breakdown of the code's functionalities:

1. **Post-processing Parse Results:** The `PostProcessParseResult` function template handles tasks after parsing, such as rewriting and declaration scope analysis. This suggests actions taken after the initial syntactic analysis.

2. **Handling Wrapped Arguments:** The `PrepareWrappedArguments` function deals with arguments for wrapped functions. This is likely related to how V8 handles code evaluated in a specific context (e.g., `eval`).

3. **Parsing Wrapped Code:**  The `ParseWrapped` function parses code that's been "wrapped" as a function. This is another indicator of handling `eval`-like scenarios.

4. **Parsing REPL Programs:** The `ParseREPLProgram` function handles the parsing of code entered in a REPL (Read-Eval-Print Loop) environment. It includes special handling for the completion value.

5. **Wrapping REPL Results:** The `WrapREPLResult` function wraps the result of a REPL evaluation in a specific object structure. This is to provide the REPL with the final computed value.

6. **Parsing Functions:** The `ParseFunction` function is a core parsing function, responsible for parsing function definitions. It handles various aspects like scope, source positions, and different function kinds.

7. **Detailed Function Parsing (`DoParseFunction`):** This function contains the detailed logic for parsing various types of functions, including arrow functions and default constructors.

8. **Parsing for Class Member Initialization:** The `ParseClassForMemberInitialization` function handles the specific case of parsing functions that initialize class members. This indicates special handling for class syntax.

9. **Parsing Module Items:** The `ParseModuleItem` function deals with individual items within a JavaScript module (e.g., imports, exports, statements).

10. **Parsing Module Item Lists:** The `ParseModuleItemList` function parses a sequence of module items, essentially parsing the body of a module.

11. **Parsing Module Specifiers:** The `ParseModuleSpecifier` function extracts the module name from an import/export statement.

12. **Parsing Export Clauses:** The `ParseExportClause` function parses the list of exported members in an `export` statement.

13. **Parsing Export Specifier Names:** The `ParseExportSpecifierName` extracts the name of a specific export.

14. **Parsing Named Imports:** The `ParseNamedImports` function parses the list of imported members in an `import` statement with specific names.

15. **Parsing Import Attributes (`ParseImportWithOrAssertClause`):** This function handles the parsing of optional attributes associated with an `import` statement.

16. **Parsing Import Declarations:** The `ParseImportDeclaration` function is responsible for parsing the complete `import` statement.

17. **Parsing Export Default:** The `ParseExportDefault` function handles the parsing of `export default` statements, which can export functions, classes, or expressions.

18. **Generating Internal Namespace Export Names:** The `NextInternalNamespaceExportName` function likely generates unique names for internal use when dealing with namespace exports in modules.

Considering the request's constraints:

* **Torque Source:** The code does not end with `.tq`, so it's not Torque code.
* **JavaScript Relation:** Many functionalities are directly related to JavaScript syntax and features like functions, classes, modules, imports, exports, `eval`, and REPL. I can provide JavaScript examples for these.
* **Code Logic Inference:** I can infer the purpose of functions based on their names and the operations they perform (e.g., `ParseFunctionLiteral` likely parses function literals).
* **Common Programming Errors:**  Parsing is often where syntax errors are caught. I can illustrate common JavaScript syntax errors that this parser would handle.
Based on the provided code snippet from `v8/src/parsing/parser.cc`, here's a summary of its functionalities:

**Core Parsing Tasks:**

* **Post-Processing Parse Results:**  It performs actions after the initial parsing, such as rewriting the Abstract Syntax Tree (AST) and analyzing the declaration scope of variables. This ensures the parsed code is semantically correct and ready for further processing.
* **Parsing Wrapped Code (`ParseWrapped`):** This function handles parsing code that is wrapped within a function, which is typical for `eval()` calls. It sets up the appropriate parsing context and creates a function literal representing the wrapped code.
* **Parsing REPL (Read-Eval-Print Loop) Programs (`ParseREPLProgram`):**  This function is responsible for parsing code entered in an interactive REPL environment. It treats REPL input similarly to an async function, capturing the completion value of the script.
* **Wrapping REPL Results (`WrapREPLResult`):**  It takes the result of a REPL execution and wraps it in a specific object structure (with a `.repl_result` property) before returning it. This allows the REPL to consistently handle the output.
* **Parsing Functions (`ParseFunction`, `DoParseFunction`):**  These are core functions for parsing function definitions, including regular functions, arrow functions, async functions, and default constructors. They handle the extraction of parameters, the function body, and various function properties.
* **Parsing Class Member Initialization (`ParseClassForMemberInitialization`):**  This function specifically handles the parsing of functions that initialize class members, which can be complex and require re-parsing parts of the class definition.
* **Parsing Module Items (`ParseModuleItem`):**  It identifies and parses individual elements within a JavaScript module, such as import and export declarations, and regular statements.
* **Parsing Module Item Lists (`ParseModuleItemList`):**  This function parses a sequence of module items, effectively parsing the entire body of a JavaScript module.
* **Parsing Module Specifiers (`ParseModuleSpecifier`):**  It extracts the string literal that specifies the module being imported or exported from.
* **Parsing Export Clauses (`ParseExportClause`):**  This function parses the list of items being exported within an `export` statement (e.g., `{ a, b as c }`).
* **Parsing Export Specifier Names (`ParseExportSpecifierName`):** It extracts the individual names being exported, handling both identifiers and string literals.
* **Parsing Named Imports (`ParseNamedImports`):** This function parses the list of specific members being imported in an `import` statement (e.g., `{ a, b as c }`).
* **Parsing Import Attributes (`ParseImportWithOrAssertClause`):** It parses the optional `with` or `assert` clause in import statements, which allows specifying attributes about the module.
* **Parsing Import Declarations (`ParseImportDeclaration`):** This function handles the parsing of complete `import` statements, including different forms like named imports, namespace imports, and default imports.
* **Parsing Export Default (`ParseExportDefault`):**  It handles the parsing of `export default` statements, which can export a function, class, or an expression.
* **Generating Internal Namespace Export Names (`NextInternalNamespaceExportName`):** This likely generates unique, internal names for handling namespace exports within modules.

**Handling Wrapped Arguments:**

* **Preparing Wrapped Arguments (`PrepareWrappedArguments`):** This function extracts and prepares the arguments that were passed to a wrapped function (like in `eval()`).

**Relation to JavaScript and Examples:**

Yes, `v8/src/parsing/parser.cc` is deeply related to JavaScript functionality. It's responsible for understanding the syntax of JavaScript code. Here are some examples:

**1. Parsing Functions:**

```javascript
function add(a, b) {
  return a + b;
}

const multiply = (a, b) => a * b;

async function fetchData() {
  return await fetch('/data');
}
```

The `ParseFunction`, `DoParseFunction` would be involved in parsing these different function declarations and expressions, extracting the function name, parameters, and body.

**2. Parsing `eval()` (Wrapped Code):**

```javascript
eval("console.log('Hello from eval');");
```

The `ParseWrapped` function would handle the parsing of the string `"console.log('Hello from eval');"` as if it were a function body.

**3. Parsing REPL Input:**

If you type `1 + 2` in a Node.js REPL, the `ParseREPLProgram` function would parse this expression. The `WrapREPLResult` would then wrap the result `3` in an object like `{ __proto__: null, .repl_result: 3 }`.

**4. Parsing Modules (Imports and Exports):**

```javascript
// moduleA.js
export const message = "Hello";
export function greet(name) {
  console.log(`Hello, ${name}!`);
}

// moduleB.js
import { message, greet } from './moduleA.js';
console.log(message);
greet("World");

export default class MyClass {
  constructor() {
    console.log("MyClass instantiated");
  }
}
```

Functions like `ParseModuleItem`, `ParseImportDeclaration`, `ParseExportDeclaration`, `ParseNamedImports`, and `ParseExportDefault` would be crucial in understanding the structure and dependencies of these modules.

**Common Programming Errors:**

The parser is responsible for detecting syntax errors. Here are some examples of JavaScript errors this code would likely catch:

* **Missing Semicolon:**

```javascript
console.log("Hello") // Missing semicolon
```

* **Unmatched Braces/Parentheses:**

```javascript
function foo( { // Unmatched opening brace
  console.log("Error");
}
```

* **Invalid Import/Export Syntax:**

```javascript
import  from './moduleA.js'; // Missing curly braces or *
export const; // Missing variable name
```

* **Using Reserved Keywords as Identifiers (in strict mode or modules):**

```javascript
const let = 5; // 'let' is a reserved keyword
```

**Code Logic Inference (Example):**

**Assumption:** The `PrepareWrappedArguments` function is called when parsing code within an `eval()` call that might have captured arguments from the surrounding scope.

**Input:** JavaScript code like this:

```javascript
function outer() {
  let x = 10;
  eval("console.log(x);");
}
outer();
```

**Output of `PrepareWrappedArguments`:** A data structure (likely a `ZonePtrList<const AstRawString>`) containing the string representation of the captured variable names, in this case, likely containing `"x"`. This allows the `eval`'d code to access variables from its surrounding scope.

**Conclusion for Part 2:**

This part of `parser.cc` focuses on the core logic for dissecting and understanding various JavaScript syntactic constructs, including functions, `eval()` calls, REPL input, and the fundamental building blocks of JavaScript modules (imports and exports). It handles the initial stage of converting raw JavaScript text into a structured representation (AST) that the V8 engine can then process further. It also plays a crucial role in detecting and reporting syntax errors.

Prompt: 
```
这是目录为v8/src/parsing/parser.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/parsing/parser.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共5部分，请归纳一下它的功能

"""
ThreadSpecific);
    if (!Rewriter::Rewrite(info) || !DeclarationScope::Analyze(info)) {
      // Null out the literal to indicate that something failed.
      info->set_literal(nullptr);
      return;
    }
  }
}

template void Parser::PostProcessParseResult(Isolate* isolate, ParseInfo* info,
                                             FunctionLiteral* literal);
template void Parser::PostProcessParseResult(LocalIsolate* isolate,
                                             ParseInfo* info,
                                             FunctionLiteral* literal);

ZonePtrList<const AstRawString>* Parser::PrepareWrappedArguments(
    Isolate* isolate, ParseInfo* info, Zone* zone) {
  DCHECK(parsing_on_main_thread_);
  DCHECK_NOT_NULL(isolate);
  DirectHandle<FixedArray> arguments =
      maybe_wrapped_arguments_.ToHandleChecked();
  int arguments_length = arguments->length();
  ZonePtrList<const AstRawString>* arguments_for_wrapped_function =
      zone->New<ZonePtrList<const AstRawString>>(arguments_length, zone);
  for (int i = 0; i < arguments_length; i++) {
    const AstRawString* argument_string = ast_value_factory()->GetString(
        Cast<String>(arguments->get(i)),
        SharedStringAccessGuardIfNeeded(isolate));
    arguments_for_wrapped_function->Add(argument_string, zone);
  }
  return arguments_for_wrapped_function;
}

void Parser::ParseWrapped(Isolate* isolate, ParseInfo* info,
                          ScopedPtrList<Statement>* body,
                          DeclarationScope* outer_scope, Zone* zone) {
  DCHECK(parsing_on_main_thread_);
  DCHECK(info->is_wrapped_as_function());
  ParsingModeScope parsing_mode(this, PARSE_EAGERLY);

  // Set function and block state for the outer eval scope.
  DCHECK(outer_scope->is_eval_scope());
  FunctionState function_state(&function_state_, &scope_, outer_scope);

  const AstRawString* function_name = nullptr;
  Scanner::Location location(0, 0);

  ZonePtrList<const AstRawString>* arguments_for_wrapped_function =
      PrepareWrappedArguments(isolate, info, zone);

  FunctionLiteral* function_literal =
      ParseFunctionLiteral(function_name, location, kSkipFunctionNameCheck,
                           FunctionKind::kNormalFunction, kNoSourcePosition,
                           FunctionSyntaxKind::kWrapped, LanguageMode::kSloppy,
                           arguments_for_wrapped_function);

  Statement* return_statement =
      factory()->NewReturnStatement(function_literal, kNoSourcePosition);
  body->Add(return_statement);
}

void Parser::ParseREPLProgram(ParseInfo* info, ScopedPtrList<Statement>* body,
                              DeclarationScope* scope) {
  // REPL scripts are handled nearly the same way as the body of an async
  // function. The difference is the value used to resolve the async
  // promise.
  // For a REPL script this is the completion value of the
  // script instead of the expression of some "return" statement. The
  // completion value of the script is obtained by manually invoking
  // the {Rewriter} which will return a VariableProxy referencing the
  // result.
  DCHECK(flags().is_repl_mode());
  this->scope()->SetLanguageMode(info->language_mode());
  PrepareGeneratorVariables();

  BlockT block = impl()->NullBlock();
  {
    StatementListT statements(pointer_buffer());
    ParseStatementList(&statements, Token::kEos);
    block = factory()->NewBlock(true, statements);
  }

  if (has_error()) return;

  std::optional<VariableProxy*> maybe_result =
      Rewriter::RewriteBody(info, scope, block->statements());
  Expression* result_value =
      (maybe_result && *maybe_result)
          ? static_cast<Expression*>(*maybe_result)
          : factory()->NewUndefinedLiteral(kNoSourcePosition);
  Expression* wrapped_result_value = WrapREPLResult(result_value);
  block->statements()->Add(factory()->NewAsyncReturnStatement(
                               wrapped_result_value, kNoSourcePosition),
                           zone());
  body->Add(block);
}

Expression* Parser::WrapREPLResult(Expression* value) {
  // REPL scripts additionally wrap the ".result" variable in an
  // object literal:
  //
  //     return %_AsyncFunctionResolve(
  //               .generator_object, {__proto__: null, .repl_result: .result});
  //
  // Should ".result" be a resolved promise itself, the async return
  // would chain the promises and return the resolve value instead of
  // the promise.

  Literal* property_name = factory()->NewStringLiteral(
      ast_value_factory()->dot_repl_result_string(), kNoSourcePosition);
  ObjectLiteralProperty* property =
      factory()->NewObjectLiteralProperty(property_name, value, true);

  Literal* proto_name = factory()->NewStringLiteral(
      ast_value_factory()->proto_string(), kNoSourcePosition);
  ObjectLiteralProperty* prototype = factory()->NewObjectLiteralProperty(
      proto_name, factory()->NewNullLiteral(kNoSourcePosition), false);

  ScopedPtrList<ObjectLiteralProperty> properties(pointer_buffer());
  properties.Add(property);
  properties.Add(prototype);
  return factory()->NewObjectLiteral(properties, false, kNoSourcePosition,
                                     false);
}

void Parser::ParseFunction(Isolate* isolate, ParseInfo* info,
                           DirectHandle<SharedFunctionInfo> shared_info) {
  // It's OK to use the Isolate & counters here, since this function is only
  // called in the main thread.
  DCHECK(parsing_on_main_thread_);
  RCS_SCOPE(runtime_call_stats_, RuntimeCallCounterId::kParseFunction);
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.compile"), "V8.ParseFunction");
  base::ElapsedTimer timer;
  if (V8_UNLIKELY(v8_flags.log_function_events)) timer.Start();

  MaybeHandle<ScopeInfo> maybe_outer_scope_info;
  if (shared_info->HasOuterScopeInfo()) {
    maybe_outer_scope_info = handle(shared_info->GetOuterScopeInfo(), isolate);
  }
  int start_position = shared_info->StartPosition();
  int end_position = shared_info->EndPosition();

  DeserializeScopeChain(isolate, info, maybe_outer_scope_info,
                        Scope::DeserializationMode::kIncludingVariables);
  DCHECK_EQ(factory()->zone(), info->zone());

  DirectHandle<Script> script(Cast<Script>(shared_info->script()), isolate);
  if (shared_info->is_wrapped()) {
    maybe_wrapped_arguments_ = handle(script->wrapped_arguments(), isolate);
  }

  int function_literal_id = shared_info->function_literal_id();

  // Initialize parser state.
  info->set_function_name(ast_value_factory()->GetString(
      shared_info->Name(), SharedStringAccessGuardIfNeeded(isolate)));
  scanner_.Initialize();

  FunctionKind function_kind = flags().function_kind();
  FunctionLiteral* result;
  if (V8_UNLIKELY(IsClassMembersInitializerFunction(function_kind))) {
    // Reparsing of class member initializer functions has to be handled
    // specially because they require reparsing of the whole class body,
    // function start/end positions correspond to the class literal body
    // positions.
    result = ParseClassForMemberInitialization(
        function_kind, start_position, function_literal_id, end_position,
        info->function_name());
    info->set_max_info_id(GetLastInfoId());
  } else if (V8_UNLIKELY(shared_info->private_name_lookup_skips_outer_class() &&
                         original_scope_->is_class_scope())) {
    // If the function skips the outer class and the outer scope is a class, the
    // function is in heritage position. Otherwise the function scope's skip bit
    // will be correctly inherited from the outer scope.
    ClassScope::HeritageParsingScope heritage(original_scope_->AsClassScope());
    result = DoParseFunction(isolate, info, start_position, end_position,
                             function_literal_id, info->function_name());
  } else {
    result = DoParseFunction(isolate, info, start_position, end_position,
                             function_literal_id, info->function_name());
  }
  if (result == nullptr) return;
  MaybeProcessSourceRanges(info, result, stack_limit_);
  PostProcessParseResult(isolate, info, result);
  if (V8_UNLIKELY(v8_flags.log_function_events)) {
    double ms = timer.Elapsed().InMillisecondsF();
    // We should already be internalized by now, so the debug name will be
    // available.
    DeclarationScope* function_scope = result->scope();
    std::unique_ptr<char[]> function_name = shared_info->DebugNameCStr();
    LOG(isolate,
        FunctionEvent("parse-function", flags().script_id(), ms,
                      function_scope->start_position(),
                      function_scope->end_position(), function_name.get(),
                      strlen(function_name.get())));
  }
}

FunctionLiteral* Parser::DoParseFunction(Isolate* isolate, ParseInfo* info,
                                         int start_position, int end_position,
                                         int function_literal_id,
                                         const AstRawString* raw_name) {
  DCHECK_EQ(parsing_on_main_thread_, isolate != nullptr);
  DCHECK_NOT_NULL(raw_name);
  DCHECK_NULL(scope_);

  DCHECK(ast_value_factory());
  fni_.PushEnclosingName(raw_name);

  ResetInfoId();
  DCHECK_LT(0, function_literal_id);
  SkipInfos(function_literal_id - 1);

  ParsingModeScope parsing_mode(this, PARSE_EAGERLY);

  // Place holder for the result.
  FunctionLiteral* result = nullptr;

  {
    // Parse the function literal.
    Scope* outer = original_scope_;
    DeclarationScope* outer_function = outer->GetClosureScope();
    DCHECK(outer);
    FunctionState function_state(&function_state_, &scope_, outer_function);
    BlockState block_state(&scope_, outer);
    DCHECK(is_sloppy(outer->language_mode()) ||
           is_strict(info->language_mode()));
    FunctionKind kind = flags().function_kind();
    DCHECK_IMPLIES(IsConciseMethod(kind) || IsAccessorFunction(kind),
                   flags().function_syntax_kind() ==
                       FunctionSyntaxKind::kAccessorOrMethod);

    if (IsArrowFunction(kind)) {
      if (IsAsyncFunction(kind)) {
        DCHECK(!scanner()->HasLineTerminatorAfterNext());
        if (!Check(Token::kAsync)) {
          CHECK(stack_overflow());
          return nullptr;
        }
        if (!(peek_any_identifier() || peek() == Token::kLeftParen)) {
          CHECK(stack_overflow());
          return nullptr;
        }
      }

      CHECK_EQ(function_literal_id, GetNextInfoId());

      // TODO(adamk): We should construct this scope from the ScopeInfo.
      DeclarationScope* scope = NewFunctionScope(kind);
      scope->set_has_checked_syntax(true);

      // This bit only needs to be explicitly set because we're
      // not passing the ScopeInfo to the Scope constructor.
      SetLanguageMode(scope, info->language_mode());

      scope->set_start_position(start_position);
      ParserFormalParameters formals(scope);
      {
        ParameterDeclarationParsingScope formals_scope(this);
        // Parsing patterns as variable reference expression creates
        // NewUnresolved references in current scope. Enter arrow function
        // scope for formal parameter parsing.
        BlockState inner_block_state(&scope_, scope);
        if (Check(Token::kLeftParen)) {
          // '(' StrictFormalParameters ')'
          ParseFormalParameterList(&formals);
          Expect(Token::kRightParen);
        } else {
          // BindingIdentifier
          ParameterParsingScope parameter_parsing_scope(impl(), &formals);
          ParseFormalParameter(&formals);
          DeclareFormalParameters(&formals);
        }
        formals.duplicate_loc = formals_scope.duplicate_location();
      }

      // It doesn't really matter what value we pass here for
      // could_be_immediately_invoked since we already introduced an eager
      // compilation scope above.
      bool could_be_immediately_invoked = false;
      Expression* expression = ParseArrowFunctionLiteral(
          formals, function_literal_id, could_be_immediately_invoked);
      // Scanning must end at the same position that was recorded
      // previously. If not, parsing has been interrupted due to a stack
      // overflow, at which point the partially parsed arrow function
      // concise body happens to be a valid expression. This is a problem
      // only for arrow functions with single expression bodies, since there
      // is no end token such as "}" for normal functions.
      if (scanner()->location().end_pos == end_position) {
        // The pre-parser saw an arrow function here, so the full parser
        // must produce a FunctionLiteral.
        DCHECK(expression->IsFunctionLiteral());
        result = expression->AsFunctionLiteral();
      }
    } else if (IsDefaultConstructor(kind)) {
      DCHECK_EQ(scope(), outer);
      result = DefaultConstructor(raw_name, IsDerivedConstructor(kind),
                                  start_position);
    } else {
      ZonePtrList<const AstRawString>* arguments_for_wrapped_function =
          info->is_wrapped_as_function()
              ? PrepareWrappedArguments(isolate, info, zone())
              : nullptr;
      result = ParseFunctionLiteral(
          raw_name, Scanner::Location::invalid(), kSkipFunctionNameCheck, kind,
          kNoSourcePosition, flags().function_syntax_kind(),
          info->language_mode(), arguments_for_wrapped_function);
    }

    if (has_error()) return nullptr;
    result->set_requires_instance_members_initializer(
        flags().requires_instance_members_initializer());
    result->set_class_scope_has_private_brand(
        flags().class_scope_has_private_brand());
    result->set_has_static_private_methods_or_accessors(
        flags().has_static_private_methods_or_accessors());
  }

  info->set_max_info_id(GetLastInfoId());

  DCHECK_IMPLIES(result, function_literal_id == result->function_literal_id());
  return result;
}

FunctionLiteral* Parser::ParseClassForMemberInitialization(
    FunctionKind initalizer_kind, int initializer_pos, int initializer_id,
    int initializer_end_pos, const AstRawString* class_name) {
  // When the function is a class members initializer function, we record the
  // source range of the entire class body as its positions in its SFI, so at
  // this point the scanner should be rewound to the position of the class
  // token.
  DCHECK_EQ(peek_position(), initializer_pos);
  // Insert a FunctionState with the closest outer Declaration scope
  DeclarationScope* nearest_decl_scope = original_scope_->GetDeclarationScope();
  DCHECK_NOT_NULL(nearest_decl_scope);
  FunctionState function_state(&function_state_, &scope_, nearest_decl_scope);

  // We will reindex the function literals later.
  ResetInfoId();
  SkipInfos(initializer_id - 1);

  // We preparse the class members that are not fields with initializers
  // in order to collect the function literal ids.
  ParsingModeScope mode(this, PARSE_LAZILY);

  ExpressionParsingScope no_expression_scope(impl());

  // Reparse the whole class body to build member initializer functions.
  FunctionLiteral* initializer;
  {
    bool is_anonymous = IsEmptyIdentifier(class_name);
    BlockState block_state(&scope_, original_scope_);
    RaiseLanguageMode(LanguageMode::kStrict);

    BlockState object_literal_scope_state(&object_literal_scope_, nullptr);

    ClassInfo class_info(this);
    class_info.is_anonymous = is_anonymous;

    // Create an arbitrary non-Null expression to indicate that the class
    // extends something. Doing so unconditionally is fine because:
    //  - the fact whether the class extends something affects parsing of
    //    'super' expressions which cause parse-time SyntaxError if the class
    //    is not a derived one. However, all such errors must have been
    //    reported during initial parse of the class declaration.
    //  - "extends" clause affects class constructor's FunctionKind, but here
    //    we are interested only in the member initializer functions and thus
    //    we can ignore the constructor function details.
    //
    // Given all the above we can simplify things and for the purpose of class
    // member initializers reparsing don't bother propagating the existence of
    // the "extends" clause through scope serialization/deserialization.
    class_info.extends = factory()->NewNullLiteral(kNoSourcePosition);

    // Note that we don't recheck class_name for strict-reserved words or eval
    // because all such checks have already been done during initial paring and
    // respective SyntaxErrors must have been thrown if necessary.

    // Class initializers don't care about position of the class token.
    int class_token_pos = kNoSourcePosition;

#ifdef DEBUG
    scope()->MarkReparsingForClassInitializer();
#endif

    ParseClassLiteralBody(class_info, class_name, class_token_pos, Token::kEos);

    if (initalizer_kind == FunctionKind::kClassMembersInitializerFunction) {
      DCHECK_EQ(class_info.instance_members_function_id, initializer_id);
      initializer = CreateInstanceMembersInitializer(class_name, &class_info);
    } else {
      DCHECK_EQ(class_info.static_elements_function_id, initializer_id);
      initializer = CreateStaticElementsInitializer(class_name, &class_info);
    }
    initializer->scope()->TakeUnresolvedReferencesFromParent();
  }

  if (has_error()) return nullptr;

  DCHECK(IsClassMembersInitializerFunction(initalizer_kind));

  no_expression_scope.ValidateExpression();

  DCHECK_EQ(initializer->kind(), initalizer_kind);
  DCHECK_EQ(initializer->function_literal_id(), initializer_id);
  DCHECK_EQ(initializer->end_position(), initializer_end_pos);

  return initializer;
}

Statement* Parser::ParseModuleItem() {
  // ecma262/#prod-ModuleItem
  // ModuleItem :
  //    ImportDeclaration
  //    ExportDeclaration
  //    StatementListItem

  Token::Value next = peek();

  if (next == Token::kExport) {
    return ParseExportDeclaration();
  }

  if (next == Token::kImport) {
    // We must be careful not to parse a dynamic import expression as an import
    // declaration. Same for import.meta expressions.
    Token::Value peek_ahead = PeekAhead();
    if (peek_ahead != Token::kLeftParen && peek_ahead != Token::kPeriod) {
      ParseImportDeclaration();
      return factory()->EmptyStatement();
    }
  }

  return ParseStatementListItem();
}

void Parser::ParseModuleItemList(ScopedPtrList<Statement>* body) {
  // ecma262/#prod-Module
  // Module :
  //    ModuleBody?
  //
  // ecma262/#prod-ModuleItemList
  // ModuleBody :
  //    ModuleItem*

  DCHECK(scope()->is_module_scope());
  while (peek() != Token::kEos) {
    Statement* stat = ParseModuleItem();
    if (stat == nullptr) return;
    if (stat->IsEmptyStatement()) continue;
    body->Add(stat);
  }
}

const AstRawString* Parser::ParseModuleSpecifier() {
  // ModuleSpecifier :
  //    StringLiteral

  Expect(Token::kString);
  return GetSymbol();
}

ZoneChunkList<Parser::ExportClauseData>* Parser::ParseExportClause(
    Scanner::Location* reserved_loc,
    Scanner::Location* string_literal_local_name_loc) {
  // ExportClause :
  //   '{' '}'
  //   '{' ExportsList '}'
  //   '{' ExportsList ',' '}'
  //
  // ExportsList :
  //   ExportSpecifier
  //   ExportsList ',' ExportSpecifier
  //
  // ExportSpecifier :
  //   IdentifierName
  //   IdentifierName 'as' IdentifierName
  //   IdentifierName 'as' ModuleExportName
  //   ModuleExportName
  //   ModuleExportName 'as' ModuleExportName
  //
  // ModuleExportName :
  //   StringLiteral
  ZoneChunkList<ExportClauseData>* export_data =
      zone()->New<ZoneChunkList<ExportClauseData>>(zone());

  Expect(Token::kLeftBrace);

  Token::Value name_tok;
  while ((name_tok = peek()) != Token::kRightBrace) {
    const AstRawString* local_name = ParseExportSpecifierName();
    if (!string_literal_local_name_loc->IsValid() &&
        name_tok == Token::kString) {
      // Keep track of the first string literal local name exported for error
      // reporting. These must be followed by a 'from' clause.
      *string_literal_local_name_loc = scanner()->location();
    } else if (!reserved_loc->IsValid() &&
               !Token::IsValidIdentifier(name_tok, LanguageMode::kStrict, false,
                                         flags().is_module())) {
      // Keep track of the first reserved word encountered in case our
      // caller needs to report an error.
      *reserved_loc = scanner()->location();
    }
    const AstRawString* export_name;
    Scanner::Location location = scanner()->location();
    if (CheckContextualKeyword(ast_value_factory()->as_string())) {
      export_name = ParseExportSpecifierName();
      // Set the location to the whole "a as b" string, so that it makes sense
      // both for errors due to "a" and for errors due to "b".
      location.end_pos = scanner()->location().end_pos;
    } else {
      export_name = local_name;
    }
    export_data->push_back({export_name, local_name, location});
    if (peek() == Token::kRightBrace) break;
    if (V8_UNLIKELY(!Check(Token::kComma))) {
      ReportUnexpectedToken(Next());
      break;
    }
  }

  Expect(Token::kRightBrace);
  return export_data;
}

const AstRawString* Parser::ParseExportSpecifierName() {
  Token::Value next = Next();

  // IdentifierName
  if (V8_LIKELY(Token::IsPropertyName(next))) {
    return GetSymbol();
  }

  // ModuleExportName
  if (next == Token::kString) {
    const AstRawString* export_name = GetSymbol();
    if (V8_LIKELY(export_name->is_one_byte())) return export_name;
    if (!unibrow::Utf16::HasUnpairedSurrogate(
            reinterpret_cast<const uint16_t*>(export_name->raw_data()),
            export_name->length())) {
      return export_name;
    }
    ReportMessage(MessageTemplate::kInvalidModuleExportName);
    return EmptyIdentifierString();
  }

  ReportUnexpectedToken(next);
  return EmptyIdentifierString();
}

ZonePtrList<const Parser::NamedImport>* Parser::ParseNamedImports(int pos) {
  // NamedImports :
  //   '{' '}'
  //   '{' ImportsList '}'
  //   '{' ImportsList ',' '}'
  //
  // ImportsList :
  //   ImportSpecifier
  //   ImportsList ',' ImportSpecifier
  //
  // ImportSpecifier :
  //   BindingIdentifier
  //   IdentifierName 'as' BindingIdentifier
  //   ModuleExportName 'as' BindingIdentifier

  Expect(Token::kLeftBrace);

  auto result = zone()->New<ZonePtrList<const NamedImport>>(1, zone());
  while (peek() != Token::kRightBrace) {
    const AstRawString* import_name = ParseExportSpecifierName();
    const AstRawString* local_name = import_name;
    Scanner::Location location = scanner()->location();
    // In the presence of 'as', the left-side of the 'as' can
    // be any IdentifierName. But without 'as', it must be a valid
    // BindingIdentifier.
    if (CheckContextualKeyword(ast_value_factory()->as_string())) {
      local_name = ParsePropertyName();
    }
    if (!Token::IsValidIdentifier(scanner()->current_token(),
                                  LanguageMode::kStrict, false,
                                  flags().is_module())) {
      ReportMessage(MessageTemplate::kUnexpectedReserved);
      return nullptr;
    } else if (IsEvalOrArguments(local_name)) {
      ReportMessage(MessageTemplate::kStrictEvalArguments);
      return nullptr;
    }

    DeclareUnboundVariable(local_name, VariableMode::kConst,
                           kNeedsInitialization, position());

    NamedImport* import =
        zone()->New<NamedImport>(import_name, local_name, location);
    result->Add(import, zone());

    if (peek() == Token::kRightBrace) break;
    Expect(Token::kComma);
  }

  Expect(Token::kRightBrace);
  return result;
}

ImportAttributes* Parser::ParseImportWithOrAssertClause() {
  // WithClause :
  //    with '{' '}'
  //    with '{' WithEntries ','? '}'

  // WithEntries :
  //    LiteralPropertyName
  //    LiteralPropertyName ':' StringLiteral , WithEntries

  auto import_attributes = zone()->New<ImportAttributes>(zone());

  if (v8_flags.harmony_import_attributes && Check(Token::kWith)) {
    // 'with' keyword consumed
  } else {
    return import_attributes;
  }

  Expect(Token::kLeftBrace);

  while (peek() != Token::kRightBrace) {
    const AstRawString* attribute_key =
        Check(Token::kString) ? GetSymbol() : ParsePropertyName();

    Scanner::Location location = scanner()->location();

    Expect(Token::kColon);
    Expect(Token::kString);

    const AstRawString* attribute_value = GetSymbol();

    // Set the location to the whole "key: 'value'"" string, so that it makes
    // sense both for errors due to the key and errors due to the value.
    location.end_pos = scanner()->location().end_pos;

    auto result = import_attributes->insert(std::make_pair(
        attribute_key, std::make_pair(attribute_value, location)));
    if (!result.second) {
      // It is a syntax error if two WithEntries have the same key.
      ReportMessageAt(location, MessageTemplate::kImportAttributesDuplicateKey,
                      attribute_key);
      break;
    }

    if (peek() == Token::kRightBrace) break;
    if (V8_UNLIKELY(!Check(Token::kComma))) {
      ReportUnexpectedToken(Next());
      break;
    }
  }

  Expect(Token::kRightBrace);

  return import_attributes;
}

void Parser::ParseImportDeclaration() {
  // ImportDeclaration :
  //   'import' ImportClause 'from' ModuleSpecifier ';'
  //   'import' ModuleSpecifier ';'
  //   'import' ImportClause 'from' ModuleSpecifier [no LineTerminator here]
  //       AssertClause ';'
  //   'import' ModuleSpecifier [no LineTerminator here] AssertClause';'
  //   'import' 'source' ImportedBinding 'from' ModuleSpecifier ';'
  //
  // ImportClause :
  //   ImportedDefaultBinding
  //   NameSpaceImport
  //   NamedImports
  //   ImportedDefaultBinding ',' NameSpaceImport
  //   ImportedDefaultBinding ',' NamedImports
  //
  // NameSpaceImport :
  //   '*' 'as' ImportedBinding

  int pos = peek_position();
  Expect(Token::kImport);

  Token::Value tok = peek();

  // 'import' ModuleSpecifier ';'
  if (tok == Token::kString) {
    Scanner::Location specifier_loc = scanner()->peek_location();
    const AstRawString* module_specifier = ParseModuleSpecifier();
    const ImportAttributes* import_attributes = ParseImportWithOrAssertClause();
    ExpectSemicolon();
    module()->AddEmptyImport(module_specifier, import_attributes, specifier_loc,
                             zone());
    return;
  }

  // Parse ImportedDefaultBinding or 'source' ImportedBinding if present.
  const AstRawString* import_default_binding = nullptr;
  Scanner::Location import_default_binding_loc;
  ModuleImportPhase import_phase = ModuleImportPhase::kEvaluation;
  if (tok != Token::kMul && tok != Token::kLeftBrace) {
    if (v8_flags.js_source_phase_imports &&
        PeekContextualKeyword(ast_value_factory()->source_string()) &&
        PeekAhead() == Token::kIdentifier &&
        PeekAheadAhead() == Token::kIdentifier) {
      Consume(Token::kIdentifier);
      import_phase = ModuleImportPhase::kSource;
    }
    import_default_binding = ParseNonRestrictedIdentifier();
    import_default_binding_loc = scanner()->location();
    DeclareUnboundVariable(import_default_binding, VariableMode::kConst,
                           kNeedsInitialization, pos);
  }

  // Parse NameSpaceImport or NamedImports if present.
  const AstRawString* module_namespace_binding = nullptr;
  Scanner::Location module_namespace_binding_loc;
  const ZonePtrList<const NamedImport>* named_imports = nullptr;
  if (import_phase == ModuleImportPhase::kEvaluation &&
      (import_default_binding == nullptr || Check(Token::kComma))) {
    switch (peek()) {
      case Token::kMul: {
        Consume(Token::kMul);
        ExpectContextualKeyword(ast_value_factory()->as_string());
        module_namespace_binding = ParseNonRestrictedIdentifier();
        module_namespace_binding_loc = scanner()->location();
        DeclareUnboundVariable(module_namespace_binding, VariableMode::kConst,
                               kCreatedInitialized, pos);
        break;
      }

      case Token::kLeftBrace:
        named_imports = ParseNamedImports(pos);
        break;

      default:
        ReportUnexpectedToken(scanner()->current_token());
        return;
    }
  }

  ExpectContextualKeyword(ast_value_factory()->from_string());
  Scanner::Location specifier_loc = scanner()->peek_location();
  const AstRawString* module_specifier = ParseModuleSpecifier();
  // TODO(42204365): Enable import attributes with source phase import once
  // specified.
  const ImportAttributes* import_attributes =
      import_phase == ModuleImportPhase::kEvaluation
          ? ParseImportWithOrAssertClause()
          : zone()->New<ImportAttributes>(zone());
  ExpectSemicolon();

  // Now that we have all the information, we can make the appropriate
  // declarations.

  // TODO(neis): Would prefer to call DeclareVariable for each case below rather
  // than above and in ParseNamedImports, but then a possible error message
  // would point to the wrong location.  Maybe have a DeclareAt version of
  // Declare that takes a location?

  if (module_namespace_binding != nullptr) {
    DCHECK_EQ(ModuleImportPhase::kEvaluation, import_phase);
    module()->AddStarImport(module_namespace_binding, module_specifier,
                            import_attributes, module_namespace_binding_loc,
                            specifier_loc, zone());
  }

  if (import_default_binding != nullptr) {
    DCHECK_IMPLIES(import_phase == ModuleImportPhase::kSource,
                   v8_flags.js_source_phase_imports);
    module()->AddImport(ast_value_factory()->default_string(),
                        import_default_binding, module_specifier, import_phase,
                        import_attributes, import_default_binding_loc,
                        specifier_loc, zone());
  }

  if (named_imports != nullptr) {
    DCHECK_EQ(ModuleImportPhase::kEvaluation, import_phase);
    if (named_imports->length() == 0) {
      module()->AddEmptyImport(module_specifier, import_attributes,
                               specifier_loc, zone());
    } else {
      for (const NamedImport* import : *named_imports) {
        module()->AddImport(import->import_name, import->local_name,
                            module_specifier, import_phase, import_attributes,
                            import->location, specifier_loc, zone());
      }
    }
  }
}

Statement* Parser::ParseExportDefault() {
  //  Supports the following productions, starting after the 'default' token:
  //    'export' 'default' HoistableDeclaration
  //    'export' 'default' ClassDeclaration
  //    'export' 'default' AssignmentExpression[In] ';'

  Expect(Token::kDefault);
  Scanner::Location default_loc = scanner()->location();

  ZonePtrList<const AstRawString> local_names(1, zone());
  Statement* result = nullptr;
  switch (peek()) {
    case Token::kFunction:
      result = ParseHoistableDeclaration(&local_names, true);
      break;

    case Token::kClass:
      Consume(Token::kClass);
      result = ParseClassDeclaration(&local_names, true);
      break;

    case Token::kAsync:
      if (PeekAhead() == Token::kFunction &&
          !scanner()->HasLineTerminatorAfterNext()) {
        Consume(Token::kAsync);
        result = ParseAsyncFunctionDeclaration(&local_names, true);
        break;
      }
      [[fallthrough]];

    default: {
      int pos = position();
      AcceptINScope scope(this, true);
      Expression* value = ParseAssignmentExpression();
      SetFunctionName(value, ast_value_factory()->default_string());

      const AstRawString* local_name =
          ast_value_factory()->dot_default_string();
      local_names.Add(local_name, zone());

      // It's fine to declare this as VariableMode::kConst because the user has
      // no way of writing to it.
      VariableProxy* proxy =
          DeclareBoundVariable(local_name, VariableMode::kConst, pos);
      proxy->var()->set_initializer_position(position());

      Assignment* assignment = factory()->NewAssignment(
          Token::kInit, proxy, value, kNoSourcePosition);
      result = IgnoreCompletion(
          factory()->NewExpressionStatement(assignment, kNoSourcePosition));

      ExpectSemicolon();
      break;
    }
  }

  if (result != nullptr) {
    DCHECK_EQ(local_names.length(), 1);
    module()->AddExport(local_names.first(),
                        ast_value_factory()->default_string(), default_loc,
                        zone());
  }

  return result;
}

const AstRawString* Parser::NextInternalNamespaceExportName() {
  const char* prefix = ".ns-export";
  std::string s(prefix);
  s.append(std::to_string(number_of_named_namespace_exports_++));
  return ast_value_factory()->GetOneByteString(s.c_str()
"""


```