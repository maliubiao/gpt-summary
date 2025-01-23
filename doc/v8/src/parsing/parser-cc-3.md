Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/parsing/parser.cc`. I need to:

1. **Identify the core functionalities** demonstrated in the code. This involves looking at the methods and their actions.
2. **Relate to JavaScript functionality** if applicable and provide examples.
3. **Identify potential user errors** that these parsing mechanisms are designed to catch.
4. **Provide a summary** of the overall purpose of this part of the parser.

Based on the code, I see functionalities related to:

- **Handling function parameters**, specifically for arrow functions (parsing, declaration, reindexing).
- **Parsing function literals**, including handling lazy parsing and parallel compilation.
- **Skipping function bodies** during pre-parsing for optimization.
- **Building parameter initialization blocks** for complex parameter patterns.
- **Parsing and declaring class elements** (fields, methods, static blocks, private members).
- **Creating initializer functions** for class members.
- **Rewriting class literals** into their final AST representation.

Let's break down each of these and think about the JavaScript connections and potential errors.
这是 `v8/src/parsing/parser.cc` 源代码的第 4 部分，主要负责处理函数和类的语法分析和声明。以下是其功能的归纳：

**核心功能:**

1. **处理箭头函数的形式参数 (Formal Parameters):**
    *   **`AddArrowFunctionFormalParameters`:**  递归地解析箭头函数的参数列表，处理逗号分隔的参数，并识别剩余参数 (`...rest`).
    *   **`DeclareArrowFunctionFormalParameters`:** 声明箭头函数的参数，并检查参数数量是否超过限制。
    *   **`ReindexArrowFunctionFormalParameters`:**  为箭头函数的形式参数进行重新索引，这可能涉及到内存管理和 AST 节点的重新排序。

    **JavaScript 示例:**

    ```javascript
    // 箭头函数参数
    const arrowFunc1 = (a, b) => a + b;
    const arrowFunc2 = (c, ...rest) => rest.reduce((sum, num) => sum + num, c);
    const arrowFunc3 = (d = 10, e) => d * e; // 带有默认值的参数
    ```

2. **解析函数字面量 (Function Literal):**
    *   **`ParseFunctionLiteral`:**  解析 `function` 关键字定义的函数，包括函数名、参数列表和函数体。它还处理延迟解析 (lazy parsing) 和并行编译的逻辑，以提高性能。

    **JavaScript 示例:**

    ```javascript
    function regularFunction(x, y) {
      return x * y;
    }

    const anonymousFunction = function(z) {
      return z * z;
    };
    ```

3. **跳过函数体 (Skipping Function):**
    *   **`SkipFunction`:**  在预解析 (pre-parsing) 阶段跳过函数体的内容，以加速初始解析过程。这对于延迟编译的函数非常有用。

4. **构建参数初始化块 (Parameter Initialization Block):**
    *   **`BuildParameterInitializationBlock`:**  为具有默认值或解构赋值的参数创建初始化代码块。

    **JavaScript 示例:**

    ```javascript
    function funcWithDefaults(a = 1, { b = 2 } = {}) {
      console.log(a, b);
    }
    ```
    假设输入 `parameters` 描述了 `funcWithDefaults` 的参数，输出的 `Block` 将包含类似以下逻辑的语句：
    `a === undefined ? 1 : a;`
    `b === undefined ? 2 : b;`

5. **处理生成器函数 (Generator Functions):**
    *   **`PrepareGeneratorVariables`:**  为生成器函数声明必要的临时变量，例如用于存储生成器对象的变量。
    *   **`BuildInitialYield`:**  为生成器函数创建初始的 `yield` 表达式。

    **JavaScript 示例:**

    ```javascript
    function* generatorFunc() {
      yield 1;
      yield 2;
    }
    ```

6. **解析函数体 (Parsing Function Body):**
    *   **`ParseFunction`:**  协调函数参数列表和函数体的解析。

7. **处理类 (Class):**
    *   **`DeclareClassVariable`:** 声明类变量。
    *   **`CreateSyntheticContextVariableProxy`:** 为类成员创建合成的上下文变量代理。
    *   **`CreatePrivateNameVariable`:** 创建私有类成员的变量。
    *   **`AddInstanceFieldOrStaticElement`:** 将类字段或静态元素添加到类的元数据中。
    *   **`DeclarePublicClassField`:** 声明公共类字段。
    *   **`DeclarePrivateClassMember`:** 声明私有类成员。
    *   **`DeclarePublicClassMethod`:** 声明公共类方法。
    *   **`AddClassStaticBlock`:** 添加类的静态代码块。
    *   **`CreateInitializerFunction`:** 创建用于初始化类成员的函数。
    *   **`CreateStaticElementsInitializer`:** 创建用于初始化静态类成员的函数。
    *   **`CreateInstanceMembersInitializer`:** 创建用于初始化实例类成员的函数。
    *   **`RewriteClassLiteral`:** 将类字面量转换为最终的 AST 节点。

    **JavaScript 示例:**

    ```javascript
    class MyClass {
      constructor(name) {
        this.name = name;
      }
      static staticMethod() {
        console.log("Static method");
      }
      myMethod() {
        console.log("Instance method");
      }
      myField = 10;
      #privateField = 20;
      get myAccessor() { return this.#privateField; }
      set myAccessor(value) { this.#privateField = value; }
      static {
        console.log("Static block");
      }
    }
    ```

**代码逻辑推理示例:**

假设输入一个箭头函数表达式 `(a, b) => a + b;`，`AddArrowFunctionFormalParameters` 会遍历 `a` 和 `b` 两个标识符，并将它们添加到 `ParserFormalParameters` 对象中。`DeclareArrowFunctionFormalParameters` 最终会将 `a` 和 `b` 声明为当前作用域内的变量。

**用户常见的编程错误:**

*   **函数参数重复:**  在非严格模式下，重复的参数名会被忽略，但在严格模式下会报错。`ValidateDuplicate` 方法用于检测这种情况。

    ```javascript
    function nonStrict(a, a) { console.log(a); } // 合法 (非严格模式)
    function strictFunc(b, b) { "use strict"; console.log(b); } // 报错 (严格模式)

    const arrowDupe = (c, c) => c * 2; // 报错
    ```

*   **在严格模式下使用 `arguments` 或 `eval` 作为参数名:**  `ValidateStrictMode` 方法会检查这些错误。

    ```javascript
    function strictArgs(arguments) { "use strict"; } // 报错
    function strictEval(eval) { "use strict"; } // 报错

    const arrowArgs = (arguments) => arguments; // 报错
    ```

*   **箭头函数参数列表格式错误:**  例如，在箭头函数参数列表中使用 `new` 关键字。

    ```javascript
    // 假设解析器遇到类似下面的错误结构
    const invalidArrow = new a => a; // 语法错误，但解析器需要识别并报告
    ```
    对于这种情况，解析器可能会抛出 `kMalformedArrowFunParamList` 错误。

**归纳其功能:**

这部分 `parser.cc` 代码主要负责解析和处理 JavaScript 中函数的定义（包括普通函数、箭头函数和生成器函数）以及类的定义。它涵盖了：

*   **识别和提取函数及类的各种组成部分**，如参数列表、函数体、类成员等。
*   **进行语法验证**，例如检查重复的参数名、严格模式下的非法标识符等。
*   **为后续的编译和执行阶段准备数据结构**，例如创建作用域、声明变量、构建抽象语法树 (AST) 节点等。
*   **支持性能优化**，例如通过延迟解析来减少初始解析时间。

总而言之，这是 V8 引擎中负责将 JavaScript 函数和类源代码转换为内部表示的关键部分。

### 提示词
```
这是目录为v8/src/parsing/parser.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/parsing/parser.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
;
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