Response:
The user wants a summary of the functionality of the provided C++ header file `v8/src/parsing/parser-base.h`. I need to identify the key roles and responsibilities of this header.

Here's a breakdown of the content and my plan:

1. **Identify Core Classes:** The header defines the `ParserBase` class template, and several nested classes like `ParameterParsingScope`, `FunctionParsingScope`, and `FunctionState`. These are central.

2. **Analyze Member Variables:**  The member variables of `ParserBase` reveal its state and dependencies. Look for things like:
    - Scope management (`scope_`, `object_literal_scope_`, `original_scope_`)
    - Function context (`function_state_`)
    - AST construction (`ast_value_factory_`, `ast_node_factory_`)
    - Lexical analysis (`scanner_`)
    - Error handling (`pending_error_handler_`)
    - Configuration (`flags_`)
    - Buffers (`pointer_buffer_`, `variable_buffer_`)

3. **Analyze Member Functions:** The member functions define the actions the parser can perform. Look for functions related to:
    - Token consumption (`Next()`, `Consume()`, `Check()`, `Expect()`)
    - Identifier parsing (`ParseIdentifier()`, `ParseAndClassifyIdentifier()`, `ParsePropertyName()`)
    - Expression parsing (`ParsePrimaryExpression()`, `ParseExpression()`, `ParseArrayLiteral()`, `ParseObjectLiteral()`, `ParseRegExpLiteral()`)
    - Scope management (the scope classes, `NewFunctionScope()`)
    - Error reporting (`ReportUnexpectedToken()`, `ReportMessage()`)
    - Specific language features (arrow functions, class expressions, etc.)

4. **Identify Core Functionalities:**  Based on the members, I can infer the main responsibilities of `ParserBase`:
    - Managing the parsing process.
    - Maintaining the current parsing state (scope, function context).
    - Consuming tokens from the scanner.
    - Building the Abstract Syntax Tree (AST).
    - Handling parsing errors.
    - Supporting various JavaScript syntax constructs.

5. **Address Specific Questions:**
    - **.tq extension:** Check if the file name indicates a Torque file. In this case, it doesn't.
    - **Relationship to JavaScript:**  The parsing of various JavaScript expressions and literals clearly demonstrates the connection. I can use a simple JavaScript example to illustrate.
    - **Code Logic Reasoning:** I can find a simple logic example within the provided code (e.g., `ParameterParsingScope`). Define example inputs and expected outputs based on the code.
    - **Common Programming Errors:** Identify areas where typical programming mistakes could lead to parsing errors (e.g., unexpected tokens, syntax errors).
    - **Part 3 of 9:** Acknowledge the context provided by the user.

6. **Synthesize the Summary:** Combine the identified functionalities into a concise summary, addressing all aspects of the user's prompt.

**Self-Correction/Refinement:**

- Ensure the JavaScript example is relevant and easy to understand.
- The code logic reasoning example should be straightforward and directly tied to the provided snippet.
- For common programming errors, focus on syntax issues that the parser would catch.
- Emphasize the role of `ParserBase` as a foundational component in the V8 parsing pipeline.

By following this plan, I should be able to generate a comprehensive and accurate answer to the user's request.
这是 `v8/src/parsing/parser-base.h` 文件的第三部分，它定义了 `ParserBase` 模板类的一些辅助结构、成员变量和方法，这些是构建 JavaScript 解析器的基础。

**功能归纳：**

这部分 `ParserBase` 的主要功能集中在以下几个方面：

1. **作用域管理 (Scope Management):**
   - 定义了 `ParameterParsingScope` 和 `FunctionParsingScope` 两个 RAII 风格的类，用于在解析函数参数和函数体时临时修改和恢复解析器的相关状态（例如，函数参数列表和表达式作用域）。
   - 维护了多个作用域相关的成员变量：
     - `scope_`: 当前的作用域栈。
     - `object_literal_scope_`: 用于跟踪正在解析的对象字面量的作用域。
     - `original_scope_`: 当前解析项的顶级作用域。

2. **函数状态管理 (Function State Management):**
   - 声明了 `FunctionState` 嵌套类，用于存储解析函数时的状态信息，例如期望的属性数量、暂停计数等。这是一个栈式结构，用于处理嵌套函数。

3. **辅助数据结构 (Helper Data Structures):**
   - `pointer_buffer_`: 一个 `void*` 指针的缓冲区，用途可能是在解析过程中临时存储指针。
   - `variable_buffer_`: 一个存储 `VariableProxy*` 和 `int` 对的缓冲区，可能用于跟踪变量信息。

4. **解析器配置和上下文 (Parser Configuration and Context):**
   - 存储了解析器的一些配置和上下文信息：
     - `function_state_`: 指向当前函数状态的指针。
     - `fni_`: `FuncNameInferrer` 实例，用于推断函数名。
     - `ast_value_factory_`: 指向 `AstValueFactory` 的指针，用于创建 AST 节点的值。
     - `ast_node_factory_`: `Types::Factory` 实例，用于创建 AST 节点。
     - `runtime_call_stats_`: 用于收集运行时调用统计信息。
     - `v8_file_logger_`: 用于日志记录。
     - `parsing_on_main_thread_`: 标识是否在主线程上解析。
     - `stack_limit_`: 堆栈限制。
     - `pending_error_handler_`: 用于处理待处理的编译错误。
     - `flags_`: 存储了解析器的编译标志。
     - `info_id_`:  标识当前解析项的 ID。

5. **Token 流管理 (Token Stream Management):**
   - 包含了指向 `Scanner` 的指针 `scanner_`，负责词法分析。

6. **箭头函数处理 (Arrow Function Handling):**
   - 定义了 `NextArrowFunctionInfo` 结构体，用于在解析箭头函数时传递参数信息，例如严格模式参数错误的位置和消息、作用域和函数字面量 ID。

7. **语法约束 (Grammar Constraints):**
   - `accept_IN_`: 一个布尔值，用于控制是否接受 `in` 运算符（在某些语法上下文中不允许）。
   - `allow_eval_cache_`: 一个布尔值，可能与 `eval` 函数的缓存有关。

**关于文件类型和 JavaScript 关系：**

- **`.tq` 结尾：**  `v8/src/parsing/parser-base.h` 以 `.h` 结尾，因此它不是 V8 Torque 源代码。Torque 文件通常以 `.tq` 结尾。
- **与 JavaScript 的关系：**  `v8/src/parsing/parser-base.h` 是 V8 JavaScript 引擎解析器的核心组成部分。它定义了用于解析 JavaScript 语法的基础结构和方法。

**JavaScript 举例说明：**

这部分代码主要处理解析过程中的状态管理和辅助功能，不容易直接用一个简单的 JavaScript 例子完全对应。但是，`ParameterParsingScope` 的概念可以与 JavaScript 函数参数的解析过程联系起来。

```javascript
function foo(a, b = 1, ...rest) {
  console.log(a, b, rest);
}
```

当 V8 解析这个函数定义时，`ParameterParsingScope`  可能被用来管理 `a`, `b = 1`, `...rest` 这些参数的解析过程，例如记录参数名、默认值以及剩余参数的标识。

**代码逻辑推理 (ParameterParsingScope):**

**假设输入：**

1. 解析器实例 `parser`，其 `parameters_` 成员指向一个表示当前参数列表的 `FormalParametersT` 对象（假设为空）。
2. 一个新的 `FormalParametersT` 对象 `new_parameters`，表示待解析的函数参数列表。

**执行 `ParameterParsingScope`：**

```c++
ParameterParsingScope scope(parser, new_parameters);
// 在 scope 内，parser->parameters_ 指向 new_parameters
```

**执行 `ParameterParsingScope` 的析构函数：**

```c++
// scope 析构时
// parser->parameters_ 恢复为原始的 parent_parameters_ (在构造函数中保存)
```

**输出：**

- 在 `ParameterParsingScope` 对象存在期间，`parser->parameters_` 将指向 `new_parameters`。
- 当 `scope` 对象超出作用域时，`parser->parameters_` 将被恢复为其原始值。

**用户常见的编程错误：**

虽然这部分代码是 V8 内部的，但其设计旨在处理各种可能的 JavaScript 语法。用户常见的编程错误会导致解析器抛出错误，例如：

1. **语法错误：**
   ```javascript
   function foo(a, , b) { // 逗号之间缺少参数
       console.log(a, b);
   }
   ```
   解析器会报告 "Unexpected token ','"。

2. **重复的参数名（在严格模式下）：**
   ```javascript
   "use strict";
   function bar(a, a) { // 严格模式下不允许重复参数名
       console.log(a);
   }
   ```
   解析器会报告 "Duplicate parameter name not allowed in this context"。

3. **在不允许的上下文中使用 `arguments` 或 `eval`（在严格模式下）：**
   ```javascript
   "use strict";
   function baz() {
       console.log(arguments); // 严格模式下不允许访问 arguments
   }
   ```
   解析器会根据具体情况报告错误。

**总结：**

这部分 `v8/src/parsing/parser-base.h` 代码定义了 `ParserBase` 类在解析 JavaScript 代码时用于管理作用域、函数状态以及其他辅助信息的基础结构。它为后续的语法分析和抽象语法树 (AST) 构建提供了必要的支持。虽然不是直接的 JavaScript 代码，但它深刻地影响着 V8 如何理解和执行 JavaScript 代码。

### 提示词
```
这是目录为v8/src/parsing/parser-base.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/parsing/parser-base.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共9部分，请归纳一下它的功能
```

### 源代码
```c
rsingScope(Impl* parser, FormalParametersT* parameters)
        : parser_(parser), parent_parameters_(parser_->parameters_) {
      parser_->parameters_ = parameters;
    }

    ~ParameterParsingScope() { parser_->parameters_ = parent_parameters_; }

   private:
    Impl* parser_;
    FormalParametersT* parent_parameters_;
  };

  class V8_NODISCARD FunctionParsingScope {
   public:
    explicit FunctionParsingScope(Impl* parser)
        : parser_(parser), expression_scope_(parser_->expression_scope_) {
      parser_->expression_scope_ = nullptr;
    }

    ~FunctionParsingScope() { parser_->expression_scope_ = expression_scope_; }

   private:
    Impl* parser_;
    ExpressionScope* expression_scope_;
  };

  std::vector<void*>* pointer_buffer() { return &pointer_buffer_; }
  std::vector<std::pair<VariableProxy*, int>>* variable_buffer() {
    return &variable_buffer_;
  }

  // Parser base's protected field members.

  Scope* scope_;                   // Scope stack.
  // Stack of scopes for object literals we're currently parsing.
  Scope* object_literal_scope_ = nullptr;
  Scope* original_scope_;  // The top scope for the current parsing item.
  FunctionState* function_state_;  // Function state stack.
  FuncNameInferrer fni_;
  AstValueFactory* ast_value_factory_;  // Not owned.
  typename Types::Factory ast_node_factory_;
  RuntimeCallStats* runtime_call_stats_;
  internal::V8FileLogger* v8_file_logger_;
  bool parsing_on_main_thread_;
  uintptr_t stack_limit_;
  PendingCompilationErrorHandler* pending_error_handler_;

  // Parser base's private field members.
  void set_has_module_in_scope_chain() { has_module_in_scope_chain_ = true; }

 private:
  Zone* zone_;
  ExpressionScope* expression_scope_;

  std::vector<void*> pointer_buffer_;
  std::vector<std::pair<VariableProxy*, int>> variable_buffer_;

  Scanner* scanner_;

  const UnoptimizedCompileFlags flags_;
  int info_id_;

  bool has_module_in_scope_chain_ : 1;

  FunctionLiteral::EagerCompileHint default_eager_compile_hint_;
  bool compile_hints_magic_enabled_;

  // This struct is used to move information about the next arrow function from
  // the place where the arrow head was parsed to where the body will be parsed.
  // Nothing can be parsed between the head and the body, so it will be consumed
  // immediately after it's produced.
  // Preallocating the struct as part of the parser minimizes the cost of
  // supporting arrow functions on non-arrow expressions.
  struct NextArrowFunctionInfo {
    Scanner::Location strict_parameter_error_location =
        Scanner::Location::invalid();
    MessageTemplate strict_parameter_error_message = MessageTemplate::kNone;
    DeclarationScope* scope = nullptr;
    int function_literal_id = -1;
    bool could_be_immediately_invoked = false;

    bool HasInitialState() const { return scope == nullptr; }

    void Reset() {
      scope = nullptr;
      function_literal_id = -1;
      ClearStrictParameterError();
      could_be_immediately_invoked = false;
      DCHECK(HasInitialState());
    }

    // Tracks strict-mode parameter violations of sloppy-mode arrow heads in
    // case the function ends up becoming strict mode. Only one global place to
    // track this is necessary since arrow functions with none-simple parameters
    // cannot become strict-mode later on.
    void ClearStrictParameterError() {
      strict_parameter_error_location = Scanner::Location::invalid();
      strict_parameter_error_message = MessageTemplate::kNone;
    }
  };

  FormalParametersT* parameters_;
  NextArrowFunctionInfo next_arrow_function_info_;

  // The position of the token following the start parenthesis in the production
  // PrimaryExpression :: '(' Expression ')'
  int position_after_last_primary_expression_open_parenthesis_ = -1;

  bool accept_IN_ = true;
  bool allow_eval_cache_ = true;
};

template <typename Impl>
ParserBase<Impl>::FunctionState::FunctionState(
    FunctionState** function_state_stack, Scope** scope_stack,
    DeclarationScope* scope)
    : BlockState(scope_stack, scope),
      expected_property_count_(0),
      suspend_count_(0),
      function_state_stack_(function_state_stack),
      outer_function_state_(*function_state_stack),
      scope_(scope),
      dont_optimize_reason_(BailoutReason::kNoReason),
      next_function_is_likely_called_(false),
      previous_function_was_likely_called_(false),
      contains_function_or_eval_(false) {
  *function_state_stack = this;
  if (outer_function_state_) {
    outer_function_state_->previous_function_was_likely_called_ =
        outer_function_state_->next_function_is_likely_called_;
    outer_function_state_->next_function_is_likely_called_ = false;
  }
}

template <typename Impl>
ParserBase<Impl>::FunctionState::~FunctionState() {
  *function_state_stack_ = outer_function_state_;
}

template <typename Impl>
void ParserBase<Impl>::ReportUnexpectedToken(Token::Value token) {
  return impl()->ReportUnexpectedTokenAt(scanner_->location(), token);
}

template <typename Impl>
bool ParserBase<Impl>::ClassifyPropertyIdentifier(
    Token::Value next, ParsePropertyInfo* prop_info) {
  // Updates made here must be reflected on ParseAndClassifyIdentifier.
  if (V8_LIKELY(base::IsInRange(next, Token::kIdentifier, Token::kAsync))) {
    if (V8_UNLIKELY(impl()->IsArguments(prop_info->name) &&
                    scope()->ShouldBanArguments())) {
      ReportMessage(
          MessageTemplate::kArgumentsDisallowedInInitializerAndStaticBlock);
      return false;
    }
    return true;
  }

  if (!Token::IsValidIdentifier(next, language_mode(), is_generator(),
                                is_await_as_identifier_disallowed())) {
    ReportUnexpectedToken(next);
    return false;
  }

  DCHECK(!prop_info->is_computed_name);

  if (next == Token::kAwait) {
    DCHECK(!is_async_function());
    expression_scope()->RecordAsyncArrowParametersError(
        scanner()->peek_location(), MessageTemplate::kAwaitBindingIdentifier);
  }
  return true;
}

template <typename Impl>
typename ParserBase<Impl>::IdentifierT
ParserBase<Impl>::ParseAndClassifyIdentifier(Token::Value next) {
  // Updates made here must be reflected on ClassifyPropertyIdentifier.
  DCHECK_EQ(scanner()->current_token(), next);
  if (V8_LIKELY(base::IsInRange(next, Token::kIdentifier, Token::kAsync))) {
    IdentifierT name = impl()->GetIdentifier();
    if (V8_UNLIKELY(impl()->IsArguments(name) &&
                    scope()->ShouldBanArguments())) {
      ReportMessage(
          MessageTemplate::kArgumentsDisallowedInInitializerAndStaticBlock);
      return impl()->EmptyIdentifierString();
    }
    return name;
  }

  if (!Token::IsValidIdentifier(next, language_mode(), is_generator(),
                                is_await_as_identifier_disallowed())) {
    ReportUnexpectedToken(next);
    return impl()->EmptyIdentifierString();
  }

  if (next == Token::kAwait) {
    expression_scope()->RecordAsyncArrowParametersError(
        scanner()->location(), MessageTemplate::kAwaitBindingIdentifier);
    return impl()->GetIdentifier();
  }

  DCHECK(Token::IsStrictReservedWord(next));
  expression_scope()->RecordStrictModeParameterError(
      scanner()->location(), MessageTemplate::kUnexpectedStrictReserved);
  return impl()->GetIdentifier();
}

template <class Impl>
typename ParserBase<Impl>::IdentifierT ParserBase<Impl>::ParseIdentifier(
    FunctionKind function_kind) {
  Token::Value next = Next();

  if (!Token::IsValidIdentifier(
          next, language_mode(), IsGeneratorFunction(function_kind),
          flags().is_module() ||
              IsAwaitAsIdentifierDisallowed(function_kind))) {
    ReportUnexpectedToken(next);
    return impl()->EmptyIdentifierString();
  }

  return impl()->GetIdentifier();
}

template <typename Impl>
typename ParserBase<Impl>::IdentifierT
ParserBase<Impl>::ParseNonRestrictedIdentifier() {
  IdentifierT result = ParseIdentifier();

  if (is_strict(language_mode()) &&
      V8_UNLIKELY(impl()->IsEvalOrArguments(result))) {
    impl()->ReportMessageAt(scanner()->location(),
                            MessageTemplate::kStrictEvalArguments);
  }

  return result;
}

template <typename Impl>
typename ParserBase<Impl>::IdentifierT ParserBase<Impl>::ParsePropertyName() {
  Token::Value next = Next();
  if (V8_LIKELY(Token::IsPropertyName(next))) {
    if (peek() == Token::kColon) return impl()->GetSymbol();
    return impl()->GetIdentifier();
  }

  ReportUnexpectedToken(next);
  return impl()->EmptyIdentifierString();
}

template <typename Impl>
bool ParserBase<Impl>::IsExtraordinaryPrivateNameAccessAllowed() const {
  if (flags().parsing_while_debugging() != ParsingWhileDebugging::kYes &&
      !flags().is_repl_mode()) {
    return false;
  }
  Scope* current_scope = scope();
  while (current_scope != nullptr) {
    switch (current_scope->scope_type()) {
      case CLASS_SCOPE:
      case CATCH_SCOPE:
      case BLOCK_SCOPE:
      case WITH_SCOPE:
      case SHADOW_REALM_SCOPE:
        return false;
      // Top-level scopes.
      case REPL_MODE_SCOPE:
      case SCRIPT_SCOPE:
      case MODULE_SCOPE:
        return true;
      // Top-level wrapper function scopes.
      case FUNCTION_SCOPE:
        return info_id_ == kFunctionLiteralIdTopLevel;
      // Used by debug-evaluate. If the outer scope is top-level,
      // extraordinary private name access is allowed.
      case EVAL_SCOPE:
        current_scope = current_scope->outer_scope();
        DCHECK_NOT_NULL(current_scope);
        break;
    }
  }
  UNREACHABLE();
}

template <typename Impl>
typename ParserBase<Impl>::ExpressionT
ParserBase<Impl>::ParsePropertyOrPrivatePropertyName() {
  int pos = position();
  IdentifierT name;
  ExpressionT key;
  Token::Value next = Next();
  if (V8_LIKELY(Token::IsPropertyName(next))) {
    name = impl()->GetSymbol();
    key = factory()->NewStringLiteral(name, pos);
  } else if (next == Token::kPrivateName) {
    // In the case of a top level function, we completely skip
    // analysing it's scope, meaning, we don't have a chance to
    // resolve private names and find that they are not enclosed in a
    // class body.
    //
    // Here, we check if this is a new private name reference in a top
    // level function and throw an error if so.
    PrivateNameScopeIterator private_name_scope_iter(scope());
    // Parse the identifier so that we can display it in the error message
    name = impl()->GetIdentifier();
    // In debug-evaluate, we relax the private name resolution to enable
    // evaluation of obj.#member outside the class bodies in top-level scopes.
    if (private_name_scope_iter.Done() &&
        !IsExtraordinaryPrivateNameAccessAllowed()) {
      impl()->ReportMessageAt(Scanner::Location(pos, pos + 1),
                              MessageTemplate::kInvalidPrivateFieldResolution,
                              impl()->GetRawNameFromIdentifier(name));
      return impl()->FailureExpression();
    }
    key =
        impl()->ExpressionFromPrivateName(&private_name_scope_iter, name, pos);
  } else {
    ReportUnexpectedToken(next);
    return impl()->FailureExpression();
  }
  impl()->PushLiteralName(name);
  return key;
}

template <typename Impl>
bool ParserBase<Impl>::ValidateRegExpFlags(RegExpFlags flags) {
  return RegExp::VerifyFlags(flags);
}

template <typename Impl>
bool ParserBase<Impl>::ValidateRegExpLiteral(const AstRawString* pattern,
                                             RegExpFlags flags,
                                             RegExpError* regexp_error) {
  // TODO(jgruber): If already validated in the preparser, skip validation in
  // the parser.
  DisallowGarbageCollection no_gc;
  ZoneScope zone_scope(zone());  // Free regexp parser memory after use.
  const unsigned char* d = pattern->raw_data();
  if (pattern->is_one_byte()) {
    return RegExp::VerifySyntax(zone(), stack_limit(),
                                static_cast<const uint8_t*>(d),
                                pattern->length(), flags, regexp_error, no_gc);
  } else {
    return RegExp::VerifySyntax(zone(), stack_limit(),
                                reinterpret_cast<const uint16_t*>(d),
                                pattern->length(), flags, regexp_error, no_gc);
  }
}

template <typename Impl>
typename ParserBase<Impl>::ExpressionT ParserBase<Impl>::ParseRegExpLiteral() {
  int pos = peek_position();
  if (!scanner()->ScanRegExpPattern()) {
    Next();
    ReportMessage(MessageTemplate::kUnterminatedRegExp);
    return impl()->FailureExpression();
  }

  const AstRawString* pattern = GetNextSymbolForRegExpLiteral();
  std::optional<RegExpFlags> flags = scanner()->ScanRegExpFlags();
  const AstRawString* flags_as_ast_raw_string = GetNextSymbolForRegExpLiteral();
  if (!flags.has_value() || !ValidateRegExpFlags(flags.value())) {
    Next();
    ReportMessage(MessageTemplate::kMalformedRegExpFlags);
    return impl()->FailureExpression();
  }
  Next();
  RegExpError regexp_error;
  if (!ValidateRegExpLiteral(pattern, flags.value(), &regexp_error)) {
    if (RegExpErrorIsStackOverflow(regexp_error)) set_stack_overflow();
    ReportMessage(MessageTemplate::kMalformedRegExp, pattern,
                  flags_as_ast_raw_string, RegExpErrorString(regexp_error));
    return impl()->FailureExpression();
  }
  return factory()->NewRegExpLiteral(pattern, flags.value(), pos);
}

template <typename Impl>
typename ParserBase<Impl>::ExpressionT ParserBase<Impl>::ParseBindingPattern() {
  // Pattern ::
  //   Identifier
  //   ArrayLiteral
  //   ObjectLiteral

  int beg_pos = peek_position();
  Token::Value token = peek();
  ExpressionT result;

  if (Token::IsAnyIdentifier(token)) {
    IdentifierT name = ParseAndClassifyIdentifier(Next());
    if (V8_UNLIKELY(is_strict(language_mode()) &&
                    impl()->IsEvalOrArguments(name))) {
      impl()->ReportMessageAt(scanner()->location(),
                              MessageTemplate::kStrictEvalArguments);
      return impl()->FailureExpression();
    }
    return impl()->ExpressionFromIdentifier(name, beg_pos);
  }

  CheckStackOverflow();

  if (token == Token::kLeftBracket) {
    result = ParseArrayLiteral();
  } else if (token == Token::kLeftBrace) {
    result = ParseObjectLiteral();
  } else {
    ReportUnexpectedToken(Next());
    return impl()->FailureExpression();
  }

  return result;
}

template <typename Impl>
typename ParserBase<Impl>::ExpressionT
ParserBase<Impl>::ParsePrimaryExpression() {
  CheckStackOverflow();

  // PrimaryExpression ::
  //   'this'
  //   'null'
  //   'true'
  //   'false'
  //   Identifier
  //   Number
  //   String
  //   ArrayLiteral
  //   ObjectLiteral
  //   RegExpLiteral
  //   ClassLiteral
  //   '(' Expression ')'
  //   TemplateLiteral
  //   do Block
  //   AsyncFunctionLiteral

  int beg_pos = peek_position();
  Token::Value token = peek();

  if (Token::IsAnyIdentifier(token)) {
    Consume(token);

    FunctionKind kind = FunctionKind::kArrowFunction;

    if (V8_UNLIKELY(token == Token::kAsync &&
                    !scanner()->HasLineTerminatorBeforeNext() &&
                    !scanner()->literal_contains_escapes())) {
      // async function ...
      if (peek() == Token::kFunction) return ParseAsyncFunctionLiteral();

      // async Identifier => ...
      if (peek_any_identifier() && PeekAhead() == Token::kArrow) {
        token = Next();
        beg_pos = position();
        kind = FunctionKind::kAsyncArrowFunction;
      }
    }

    if (V8_UNLIKELY(peek() == Token::kArrow)) {
      ArrowHeadParsingScope parsing_scope(impl(), kind, PeekNextInfoId());
      IdentifierT name = ParseAndClassifyIdentifier(token);
      ClassifyParameter(name, beg_pos, end_position());
      ExpressionT result =
          impl()->ExpressionFromIdentifier(name, beg_pos, InferName::kNo);
      parsing_scope.SetInitializers(0, peek_position());
      next_arrow_function_info_.scope = parsing_scope.ValidateAndCreateScope();
      next_arrow_function_info_.function_literal_id =
          parsing_scope.function_literal_id();
      next_arrow_function_info_.could_be_immediately_invoked =
          position_after_last_primary_expression_open_parenthesis_ == beg_pos;
      return result;
    }

    IdentifierT name = ParseAndClassifyIdentifier(token);
    return impl()->ExpressionFromIdentifier(name, beg_pos);
  }

  if (Token::IsLiteral(token)) {
    return impl()->ExpressionFromLiteral(Next(), beg_pos);
  }

  switch (token) {
    case Token::kNew:
      return ParseMemberWithPresentNewPrefixesExpression();

    case Token::kThis: {
      Consume(Token::kThis);
      // Not necessary for this.x, this.x(), this?.x and this?.x() to
      // store the source position for ThisExpression.
      if (peek() == Token::kPeriod || peek() == Token::kQuestionPeriod) {
        return impl()->ThisExpression();
      }
      return impl()->NewThisExpression(beg_pos);
    }

    case Token::kAssignDiv:
    case Token::kDiv:
      return ParseRegExpLiteral();

    case Token::kFunction:
      return ParseFunctionExpression();

    case Token::kSuper: {
      return ParseSuperExpression();
    }
    case Token::kImport:
      return ParseImportExpressions();

    case Token::kLeftBracket:
      return ParseArrayLiteral();

    case Token::kLeftBrace:
      return ParseObjectLiteral();

    case Token::kLeftParen: {
      Consume(Token::kLeftParen);

      if (Check(Token::kRightParen)) {
        // clear last next_arrow_function_info tracked strict parameters error.
        next_arrow_function_info_.ClearStrictParameterError();

        // ()=>x.  The continuation that consumes the => is in
        // ParseAssignmentExpressionCoverGrammar.
        if (peek() != Token::kArrow) ReportUnexpectedToken(Token::kRightParen);
        next_arrow_function_info_.scope =
            NewFunctionScope(FunctionKind::kArrowFunction);
        next_arrow_function_info_.function_literal_id = PeekNextInfoId();
        next_arrow_function_info_.could_be_immediately_invoked =
            position_after_last_primary_expression_open_parenthesis_ == beg_pos;
        return factory()->NewEmptyParentheses(beg_pos);
      }
      Scope::Snapshot scope_snapshot(scope());
      bool could_be_immediately_invoked_arrow_function =
          position_after_last_primary_expression_open_parenthesis_ == beg_pos;
      ArrowHeadParsingScope maybe_arrow(impl(), FunctionKind::kArrowFunction,
                                        PeekNextInfoId());
      position_after_last_primary_expression_open_parenthesis_ =
          peek_position();
      // Heuristically try to detect immediately called functions before
      // seeing the call parentheses.
      if (peek() == Token::kFunction ||
          (peek() == Token::kAsync && PeekAhead() == Token::kFunction)) {
        function_state_->set_next_function_is_likely_called();
      }
      AcceptINScope scope(this, true);
      ExpressionT expr = ParseExpressionCoverGrammar();
      expr->mark_parenthesized();
      Expect(Token::kRightParen);

      if (peek() == Token::kArrow) {
        next_arrow_function_info_.scope = maybe_arrow.ValidateAndCreateScope();
        next_arrow_function_info_.function_literal_id =
            maybe_arrow.function_literal_id();
        next_arrow_function_info_.could_be_immediately_invoked =
            could_be_immediately_invoked_arrow_function;
        scope_snapshot.Reparent(next_arrow_function_info_.scope);
      } else {
        maybe_arrow.ValidateExpression();
      }

      return expr;
    }

    case Token::kClass: {
      return ParseClassExpression(scope());
    }

    case Token::kTemplateSpan:
    case Token::kTemplateTail:
      return ParseTemplateLiteral(impl()->NullExpression(), beg_pos, false);

    case Token::kMod:
      if (flags().allow_natives_syntax() || impl()->ParsingExtension()) {
        return ParseV8Intrinsic();
      }
      break;

    default:
      break;
  }

  ReportUnexpectedToken(Next());
  return impl()->FailureExpression();
}

template <typename Impl>
typename ParserBase<Impl>::ExpressionT ParserBase<Impl>::ParseExpression() {
  ExpressionParsingScope expression_scope(impl());
  AcceptINScope scope(this, true);
  ExpressionT result = ParseExpressionCoverGrammar();
  expression_scope.ValidateExpression();
  return result;
}

template <typename Impl>
typename ParserBase<Impl>::ExpressionT
ParserBase<Impl>::ParseConditionalChainAssignmentExpression() {
  ExpressionParsingScope expression_scope(impl());
  ExpressionT result = ParseConditionalChainAssignmentExpressionCoverGrammar();
  expression_scope.ValidateExpression();
  return result;
}

template <typename Impl>
typename ParserBase<Impl>::ExpressionT
ParserBase<Impl>::ParseAssignmentExpression() {
  ExpressionParsingScope expression_scope(impl());
  ExpressionT result = ParseAssignmentExpressionCoverGrammar();
  expression_scope.ValidateExpression();
  return result;
}

template <typename Impl>
typename ParserBase<Impl>::ExpressionT
ParserBase<Impl>::ParseExpressionCoverGrammar() {
  // Expression ::
  //   AssignmentExpression
  //   Expression ',' AssignmentExpression

  ExpressionListT list(pointer_buffer());
  ExpressionT expression;
  AccumulationScope accumulation_scope(expression_scope());
  int variable_index = 0;
  while (true) {
    if (V8_UNLIKELY(peek() == Token::kEllipsis)) {
      return ParseArrowParametersWithRest(&list, &accumulation_scope,
                                          variable_index);
    }

    int expr_pos = peek_position();
    expression = ParseAssignmentExpressionCoverGrammar();

    ClassifyArrowParameter(&accumulation_scope, expr_pos, expression);
    list.Add(expression);

    variable_index =
        expression_scope()->SetInitializers(variable_index, peek_position());

    if (!Check(Token::kComma)) break;

    if (peek() == Token::kRightParen && PeekAhead() == Token::kArrow) {
      // a trailing comma is allowed at the end of an arrow parameter list
      break;
    }

    // Pass on the 'set_next_function_is_likely_called' flag if we have
    // several function literals separated by comma.
    if (peek() == Token::kFunction &&
        function_state_->previous_function_was_likely_called()) {
      function_state_->set_next_function_is_likely_called();
    }
  }

  // Return the single element if the list is empty. We need to do this because
  // callers of this function care about the type of the result if there was
  // only a single assignment expression. The preparser would lose this
  // information otherwise.
  if (list.length() == 1) return expression;
  return impl()->ExpressionListToExpression(list);
}

template <typename Impl>
typename ParserBase<Impl>::ExpressionT
ParserBase<Impl>::ParseArrowParametersWithRest(
    typename ParserBase<Impl>::ExpressionListT* list,
    AccumulationScope* accumulation_scope, int seen_variables) {
  Consume(Token::kEllipsis);

  Scanner::Location ellipsis = scanner()->location();
  int pattern_pos = peek_position();
  ExpressionT pattern = ParseBindingPattern();
  ClassifyArrowParameter(accumulation_scope, pattern_pos, pattern);

  expression_scope()->RecordNonSimpleParameter();

  if (V8_UNLIKELY(peek() == Token::kAssign)) {
    ReportMessage(MessageTemplate::kRestDefaultInitializer);
    return impl()->FailureExpression();
  }

  ExpressionT spread =
      factory()->NewSpread(pattern, ellipsis.beg_pos, pattern_pos);
  if (V8_UNLIKELY(peek() == Token::kComma)) {
    ReportMessage(MessageTemplate::kParamAfterRest);
    return impl()->FailureExpression();
  }

  expression_scope()->SetInitializers(seen_variables, peek_position());

  // 'x, y, ...z' in CoverParenthesizedExpressionAndArrowParameterList only
  // as the formal parameters of'(x, y, ...z) => foo', and is not itself a
  // valid expression.
  if (peek() != Token::kRightParen || PeekAhead() != Token::kArrow) {
    impl()->ReportUnexpectedTokenAt(ellipsis, Token::kEllipsis);
    return impl()->FailureExpression();
  }

  list->Add(spread);
  return impl()->ExpressionListToExpression(*list);
}

template <typename Impl>
typename ParserBase<Impl>::ExpressionT ParserBase<Impl>::ParseArrayLiteral() {
  // ArrayLiteral ::
  //   '[' Expression? (',' Expression?)* ']'

  int pos = peek_position();
  ExpressionListT values(pointer_buffer());
  int first_spread_index = -1;
  Consume(Token::kLeftBracket);

  AccumulationScope accumulation_scope(expression_scope());

  while (!Check(Token::kRightBracket)) {
    ExpressionT elem;
    if (peek() == Token::kComma) {
      elem = factory()->NewTheHoleLiteral();
    } else if (Check(Token::kEllipsis)) {
      int start_pos = position();
      int expr_pos = peek_position();
      AcceptINScope scope(this, true);
      ExpressionT argument =
          ParsePossibleDestructuringSubPattern(&accumulation_scope);
      elem = factory()->NewSpread(argument, start_pos, expr_pos);

      if (first_spread_index < 0) {
        first_spread_index = values.length();
      }

      if (argument->IsAssignment()) {
        expression_scope()->RecordPatternError(
            Scanner::Location(start_pos, end_position()),
            MessageTemplate::kInvalidDestructuringTarget);
      }

      if (peek() == Token::kComma) {
        expression_scope()->RecordPatternError(
            Scanner::Location(start_pos, end_position()),
            MessageTemplate::kElementAfterRest);
      }
    } else {
      AcceptINScope scope(this, true);
      elem = ParsePossibleDestructuringSubPattern(&accumulation_scope);
    }
    values.Add(elem);
    if (peek() != Token::kRightBracket) {
      Expect(Token::kComma);
      if (elem->IsFailureExpression()) return elem;
    }
  }

  return factory()->NewArrayLiteral(values, first_spread_index, pos);
}

template <class Impl>
typename ParserBase<Impl>::ExpressionT ParserBase<Impl>::ParseProperty(
    ParsePropertyInfo* prop_info) {
  DCHECK_EQ(prop_info->kind, ParsePropertyKind::kNotSet);
  DCHECK_EQ(prop_info->function_flags, ParseFunctionFlag::kIsNormal);
  DCHECK(!prop_info->is_computed_name);

  if (Check(Token::kAsync)) {
    Token::Value token = peek();
    if ((token != Token::kMul &&
         prop_info->ParsePropertyKindFromToken(token)) ||
        scanner()->HasLineTerminatorBeforeNext()) {
      prop_info->name = impl()->GetIdentifier();
      impl()->PushLiteralName(prop_info->name);
      return factory()->NewStringLiteral(prop_info->name, position());
    }
    if (V8_UNLIKELY(scanner()->literal_contains_escapes())) {
      impl()->ReportUnexpectedToken(Token::kEscapedKeyword);
    }
    prop_info->function_flags = ParseFunctionFlag::kIsAsync;
    prop_info->kind = ParsePropertyKind::kMethod;
  }

  if (Check(Token::kMul)) {
    prop_info->function_flags |= ParseFunctionFlag::kIsGenerator;
    prop_info->kind = ParsePropertyKind::kMethod;
  }

  if (prop_info->kind == ParsePropertyKind::kNotSet &&
      base::IsInRange(peek(), Token::kGet, Token::kSet)) {
    Token::Value token = Next();
    if (prop_info->ParsePropertyKindFromToken(peek())) {
      prop_info->name = impl()->GetIdentifier();
      impl()->PushLiteralName(prop_info->name);
      return factory()->NewStringLiteral(prop_info->name, position());
    }
    if (V8_UNLIKELY(scanner()->literal_contains_escapes())) {
      impl()->ReportUnexpectedToken(Token::kEscapedKeyword);
    }
    if (token == Token::kGet) {
      prop_info->kind = ParsePropertyKind::kAccessorGetter;
    } else if (token == Token::kSet) {
      prop_info->kind = ParsePropertyKind::kAccessorSetter;
    }
  }

  int pos = peek_position();

  // For non computed property names we normalize the name a bit:
  //
  //   "12" -> 12
  //   12.3 -> "12.3"
  //   12.30 -> "12.3"
  //   identifier -> "identifier"
  //
  // This is important because we use the property name as a key in a hash
  // table when we compute constant properties.
  bool is_array_index;
  uint32_t index;
  switch (peek()) {
    case Token::kPrivateName:
      prop_info->is_private = true;
      is_array_index = false;
      Consume(Token::kPrivateName);
      if (prop_info->kind == ParsePropertyKind::kNotSet) {
        prop_info->ParsePropertyKindFromToken(peek());
      }
      prop_info->name = impl()->GetIdentifier();
      if (V8_UNLIKELY(prop_info->position ==
                      PropertyPosition::kObjectLiteral)) {
        ReportUnexpectedToken(Token::kPrivateName);
        prop_info->kind = ParsePropertyKind::kNotSet;
        return impl()->FailureExpression();
      }
      break;

    case Token::kString:
      Consume(Token::kString);
      prop_info->name = peek() == Token::kColon ? impl()->GetSymbol()
                                                : impl()->GetIdentifier();
      is_array_index = impl()->IsArrayIndex(prop_info->name, &index);
      break;

    case Token::kSmi:
      Consume(Token::kSmi);
      index = scanner()->smi_value();
      is_array_index = true;
      // Token::kSmi were scanned from their canonical representation.
      prop_info->name = impl()->GetSymbol();
      break;

    case Token::kNumber: {
      Consume(Token::kNumber);
      prop_info->name = impl()->GetNumberAsSymbol();
      is_array_index = impl()->IsArrayIndex(prop_info->name, &index);
      break;
    }

    case Token::kBigInt: {
      Consume(Token::kBigInt);
      prop_info->name = impl()->GetBigIntAsSymbol();
      is_array_index = impl()->IsArrayIndex(prop_info->name, &index);
      break;
    }

    case Token::kLeftBracket: {
      prop_info->name = impl()->NullIdentifier();
      prop_info->is_computed_name = true;
      Consume(Token::kLeftBracket);
      AcceptINScope scope(this, true);
      ExpressionT expression = ParseAssignmentExpression();
      Expect(Token::kRightBracket);
      if (prop_info->kind == ParsePropertyKind::kNotSet) {
        prop_info->ParsePropertyKindFromToken(peek());
      }
      return expression;
    }

    case Token::kEllipsis:
      if (prop_info->kind == ParsePropertyKind::kNotSet) {
        prop_info->name = impl()->NullIdentifier();
        Consume(Token::kEllipsis);
        AcceptINScope scope(this, true);
        int start_pos = peek_position();
        ExpressionT expression =
            ParsePossibleDestructuringSubPattern(prop_info->accumulation_scope);
        prop_info->kind = ParsePropertyKind::kSpread;

        if (!IsValidReferenceExpression(expression)) {
          expression_scope()->RecordDeclarationError(
              Scanner::Location(start_pos, end_position()),
              MessageTemplate::kInvalidRestBindingPattern);
          expression_scope()->RecordPatternError(
              Scanner::Location(start_pos, end_position()),
              MessageTemplate::kInvalidRestAssignmentPattern);
        }

        if (peek() != Token::kRightBrace) {
          expression_scope()->RecordPatternError(
              scanner()->location(), MessageTemplate::kElementAfterRest);
        }
        return expression;
      }
      [[fallthrough]];

    default:
      prop_info->name = ParsePropertyName();
      is_array_index = false;
      break;
  }

  if (prop_info->kind == ParsePropertyKind::kNotSet) {
    prop_info->ParsePropertyKindFromToken(peek());
  }
  impl()->PushLiteralName(prop_info->name);
  return is_array_index ? factory()->NewNumberLiteral(index, pos)
                        : factory()->NewStringLiteral(prop_info->name, pos);
}

template <typename Impl>
bool ParserBase<Impl>::VerifyCanHaveAutoAccessorOrThrow(
    ParsePropertyInfo* prop_info, ExpressionT name_expression,
    int name_token_position) {
  switch (prop_info->kind) {
    case ParsePropertyKind::kAssign:
    case ParsePropertyKind::kClassField:
    case ParsePropertyKind::kShorthandOrClassField:
    case ParsePropertyKind::kNotSet:
      prop_info->kind = ParsePropertyKind::kAutoAccessorClassField;
      return true;
    default:
      impl()->ReportUnexpectedTokenAt(
          Scanner::Location(name_token_position, name_expression->position()),
          Token::kAccessor);
      return false;
  }
}

template <typename Impl>
bool ParserBase<Impl>::ParseCurrentSymbolAsClassFieldOrMethod(
    ParsePropertyInfo* prop_info, ExpressionT* name_expression) {
  if (peek() == Token::kLeftParen) {
    prop_info->kind = ParsePropertyKind::kMethod;
    prop_info->name = impl()->GetIdentifier();
    *name_expression = factory()->NewStringLiteral(prop_info->name, position());
    return true;
  }
  if (peek() == Token::kAssign || peek() == Token::kSemicolon ||
      peek() == Token::kRightBrace) {
    prop_info->name = impl()->GetIdentifier();
    *name_expression = factory()->NewStringLiteral(prop_info->name, position());
    return true;
  }
  return false;
}

template <typename Impl>
bool ParserBase<Impl>::ParseAccessorPropertyOrAutoAccessors(
    ParsePropert
```