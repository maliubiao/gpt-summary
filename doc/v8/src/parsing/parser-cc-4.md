Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/parsing/parser.cc`. I need to analyze the code and identify its main responsibilities within the V8 JavaScript engine's parsing process.

Here's a breakdown of the code's functionalities:

1. **Class Literal Creation:** The `ParseClassLiteral` function deals with creating the AST (Abstract Syntax Tree) node for a JavaScript class definition. This involves handling static and instance members, private fields, and the class constructor.

2. **Shadowing Variable Initializers:**  The `InsertShadowingVarBindingInitializers` function handles the specific case where a `var` declaration inside a block shadows a parameter of the enclosing function. It inserts an assignment to initialize the variable with the parameter's value.

3. **Sloppy Block Function Hoisting:** `InsertSloppyBlockFunctionVarBindings` addresses function declarations within blocks in sloppy mode. It ensures these functions are hoisted correctly, especially in `eval` scopes.

4. **Source URL and Mapping URL Handling:** The `HandleSourceURLComments` function extracts and sets the source URL and source mapping URL from special comments within the JavaScript source code.

5. **Usage Statistics:**  The `UpdateStatistics` functions track various language features and parsing events to gather usage data. This includes things like HTML comments, magic comments for compile hints, and source mapping URL comments.

6. **Background Parsing:** The `ParseOnBackground` function allows parsing to be performed on a background thread to improve performance. It handles the parsing of both top-level programs and individual functions.

7. **Template Literal Processing:** The `OpenTemplateLiteral`, `AddTemplateSpan`, `AddTemplateExpression`, and `CloseTemplateLiteral` functions work together to parse and construct the AST node for template literals (template strings). This includes handling tagged templates.

8. **Language Mode Setting:** The `SetLanguageMode` function records and sets the language mode (strict or sloppy) for a given scope.

9. **Asm.js Module Handling:** The `SetAsmModule` function detects and marks a script as an asm.js module.

10. **Expression List Conversion:** `ExpressionListToExpression` converts a list of expressions into a single expression using the comma operator.

11. **Function Name Inference:** The `SetFunctionNameFromPropertyName` and `SetFunctionNameFromIdentifierRef` functions are responsible for inferring and setting the names of functions, especially for anonymous function expressions within object literals or assignments. The `SetFunctionName` does the actual setting of the function's name in the AST.

Based on these points, I can now formulate a comprehensive summary and address the other points of the user's request.
`v8/src/parsing/parser.cc` 的代码片段主要负责 **解析 JavaScript 类 (class) 声明以及一些与作用域、源信息和统计相关的辅助功能**。

**功能列表:**

1. **解析类声明 (`ParseClassLiteral`)**:
   - 创建 `ClassLiteral` AST 节点，表示一个 JavaScript 类。
   - 处理类的名称、继承关系 (`extends`)、构造函数、公共成员、私有成员、静态初始化器和实例成员初始化器。
   - 为类构造函数设置必要的属性，例如是否需要实例成员初始化器、是否具有私有 brand、是否具有静态私有方法或访问器。
   - 处理匿名类和带有 home object 变量的类。
   - 将构造函数添加到名称推断机制中。

2. **插入变量绑定初始化器 (`InsertShadowingVarBindingInitializers`)**:
   - 当一个 `var` 声明在一个块级作用域内，并且该变量名与外部函数作用域的参数名相同时，插入一个赋值语句，将参数的值赋给该变量。
   - 这确保了在执行块级代码之前，被 `var` 声明的变量被正确初始化。
   - 考虑了变量名与函数声明冲突的情况，在这种情况下，不会创建变量绑定。

3. **插入松散模式块级函数变量绑定 (`InsertSloppyBlockFunctionVarBindings`)**:
   - 在松散模式下，将块级作用域中的函数声明提升到其封闭的作用域。
   - 对于最外层的 `eval` 作用域，提升操作会在稍后的 `DeclarationScope::Analyze` 阶段进行。

4. **处理源 URL 注释 (`HandleSourceURLComments`)**:
   - 从 JavaScript 源代码中的特殊注释（`//# sourceURL=` 和 `//# sourceMappingURL=`）提取源文件的 URL 和源映射文件的 URL。
   - 将这些 URL 设置到 `Script` 对象中，用于调试和错误报告。

5. **更新统计信息 (`UpdateStatistics`)**:
   - 收集解析过程中的各种统计信息，例如使用了哪些语言特性（通过 `use_counts_` 数组）。
   - 记录是否发现了 HTML 注释 (`<!-- ... -->`) 和特殊的魔术注释（例如用于编译提示和源映射 URL）。
   - 将这些统计信息传递给 `Isolate` 对象，用于性能分析和特性使用情况跟踪。

6. **后台解析 (`ParseOnBackground`)**:
   - 允许在后台线程上执行解析操作，提高主线程的响应性。
   - 用于解析顶层程序或单独的函数。

7. **处理模板字面量 (`OpenTemplateLiteral`, `AddTemplateSpan`, `AddTemplateExpression`, `CloseTemplateLiteral`)**:
   - 用于解析模板字符串（template literals）。
   - `OpenTemplateLiteral` 创建一个 `TemplateLiteral` 对象来存储模板字面量的各个部分。
   - `AddTemplateSpan` 添加静态的字符串部分。
   - `AddTemplateExpression` 添加嵌入的表达式。
   - `CloseTemplateLiteral` 完成模板字面量的解析，并根据是否带有标签（tagged template）创建不同的 AST 节点。

8. **设置语言模式 (`SetLanguageMode`)**:
   - 设置当前作用域的语言模式（严格模式或松散模式）。
   - 同时更新相应的统计信息。

9. **标记为 Asm.js 模块 (`SetAsmModule`)**:
   - 如果解析器遇到 Asm.js 模块的语法，则将其标记为 Asm.js 模块。

10. **将表达式列表转换为表达式 (`ExpressionListToExpression`)**:
    - 将一个包含多个表达式的列表，用逗号运算符连接起来，形成一个单一的表达式。

11. **根据属性名设置函数名 (`SetFunctionNameFromPropertyName`)**:
    - 当在对象字面量中定义函数时，根据属性名推断并设置函数的名称。这有助于调试和错误堆栈。
    - 区分了普通属性和原型属性 (`__proto__`)。

12. **根据标识符引用设置函数名 (`SetFunctionNameFromIdentifierRef`)**:
    - 当将一个标识符引用的值赋给一个变量时，如果该值是一个匿名函数，则使用标识符的名称作为该函数的名称。

13. **设置函数名 (`SetFunctionName`)**:
    - 实际设置函数字面量的名称。可以设置一个简单的名称，也可以设置带有前缀的名称（例如，对于方法）。

**如果 `v8/src/parsing/parser.cc` 以 `.tq` 结尾，那它是个 v8 Torque 源代码。**  但根据用户提供的信息，文件名为 `parser.cc`，所以它是 C++ 源代码。 Torque 是一种 V8 内部使用的类型安全的 DSL (Domain Specific Language)，用于生成 C++ 代码。

**与 JavaScript 功能的关系及 JavaScript 示例:**

这些代码片段直接对应 JavaScript 的语法结构和行为：

1. **类声明:**

   ```javascript
   class MyClass {
     constructor(value) {
       this.value = value;
     }

     static staticMethod() {
       console.log("Static method");
     }

     instanceMethod() {
       console.log("Instance method:", this.value);
     }

     get myProperty() {
       return this.value * 2;
     }

     set myProperty(newValue) {
       this.value = newValue / 2;
     }

     #privateField = 0;

     #privateMethod() {
       console.log("Private method");
     }
   }
   ```
   `ParseClassLiteral` 函数负责解析上面这样的 JavaScript 类声明，提取类名、构造函数、方法、属性、静态成员和私有成员等信息。

2. **变量绑定初始化器:**

   ```javascript
   function example(a) {
     {
       var a = 10; // 这里的 'a' 会 shadow 函数参数 'a'
       console.log(a); // 输出 10
     }
     console.log(a); // 输出 undefined (在 ES5 中，var 是函数作用域)
   }
   example(5);
   ```
   `InsertShadowingVarBindingInitializers` 处理的就是类似这样的情况，在块级作用域开始时，将参数 `a` 的值赋给块内的 `var a`。  **注意：在 ES6 及之后，使用 `let` 或 `const` 会产生不同的行为，因为它们是块级作用域。**

3. **松散模式块级函数变量绑定:**

   ```javascript
   function example() {
     if (true) {
       function foo() { // 在非严格模式下，这个函数会被提升
         console.log("foo");
       }
     }
     foo(); // 可以调用
   }
   example();
   ```
   `InsertSloppyBlockFunctionVarBindings` 确保了在松散模式下，块内的函数声明 `foo` 可以被外部访问。

4. **源 URL 注释:**

   ```javascript
   //# sourceURL=my-script.js
   console.log("This is my script.");
   ```
   `HandleSourceURLComments` 会解析 `//# sourceURL=` 注释，并将 `my-script.js` 设置为该脚本的源 URL，方便调试时在开发者工具中看到正确的文件名。

5. **模板字面量:**

   ```javascript
   const name = "World";
   const greeting = `Hello, ${name}!`; // 解析模板字面量
   const tagged = String.raw`Hello,\n${name}!`; // 解析带标签的模板字面量
   ```
   `OpenTemplateLiteral` 等函数负责解析和构建模板字符串的 AST。

6. **函数名推断:**

   ```javascript
   const obj = {
     myFunction() { // 函数名被推断为 'myFunction'
       console.log("Hello");
     },
     anonymous: function() { // 函数名被推断为 'anonymous' (取决于上下文)
       console.log("Anonymous");
     }
   };

   const myFunc = function namedFunction() { // 显式命名
     console.log("Named");
   };

   const anotherFunc = function() { // 匿名函数
     console.log("Another");
   };
   ```
   `SetFunctionNameFromPropertyName` 等函数负责在解析对象字面量和赋值表达式时，尽可能地推断和设置函数的名称，即使是匿名函数。

**代码逻辑推理 (假设输入与输出):**

**假设输入:** 包含以下 JavaScript 类声明的代码片段：

```javascript
class MyClass {
  constructor(a) {
    this.x = a;
  }
  getX() {
    return this.x;
  }
  static staticMethod() {
    return 10;
  }
}
```

**输出:** `ParseClassLiteral` 函数会返回一个 `ClassLiteral` AST 节点，该节点包含以下信息：

- `name`:  指向 "MyClass" 字符串的 `AstRawString`。
- `extends`:  `nullptr` (因为没有 `extends` 子句)。
- `constructor`: 一个 `FunctionLiteral` 节点，表示构造函数，其参数为 "a"，函数体为 `this.x = a;`。
- `public_members`: 一个列表，包含一个表示 `getX` 方法的 `ObjectLiteralProperty` 节点和一个表示构造函数的 `ObjectLiteralProperty` 节点。
- `private_members`: 空列表。
- `static_initializer`:  `nullptr` (没有静态字段需要初始化)。
- `instance_members_initializer_function`:  `nullptr` (没有实例字段需要初始化，只有构造函数中的赋值)。

**涉及用户常见的编程错误 (举例说明):**

1. **在 `var` 声明前访问变量 (由于作用域混淆):**

   ```javascript
   function example(arg) {
     console.log(x); // 错误：在初始化之前无法访问 'x' (如果使用了 let/const) 或输出 undefined (如果使用了 var)
     if (arg > 0) {
       var x = 10;
     }
   }
   example(1);
   ```
   虽然 `var` 有提升特性，但在其声明语句执行之前，访问 `x` 会导致 `undefined`。`InsertShadowingVarBindingInitializers` 可以在某些情况下影响这种行为，尤其是在块级作用域中。

2. **在严格模式下意外使用 `arguments` 或 `eval` 作为变量名:**

   ```javascript
   "use strict";
   var arguments = 10; // 语法错误：严格模式下不允许使用 'arguments' 作为变量名
   ```
   虽然这个代码片段本身不直接处理这类错误，但解析器在解析过程中会检查这些语法错误，并且会影响作用域的创建和变量的绑定。

3. **在类声明之前访问类名:**

   ```javascript
   const instance = new MyClass(); // 错误：在声明之前无法访问 'MyClass'
   class MyClass {}
   ```
   `ParseClassLiteral` 确保了类在声明完成后才能被访问。

**归纳 `v8/src/parsing/parser.cc` 的功能 (针对第 5 部分):**

总的来说，这部分代码主要关注 **JavaScript 类语法的解析和处理，以及一些与作用域管理、源代码信息处理和性能统计相关的辅助功能。** 它确保了 V8 能够正确理解和表示 JavaScript 中的类声明，并为后续的编译和执行阶段提供必要的元数据。  此外，它还处理了一些与脚本上下文（如源 URL）和性能监控相关的任务。 这部分功能是 V8 解析器将 JavaScript 源代码转换为可执行的抽象语法树的关键组成部分。

### 提示词
```
这是目录为v8/src/parsing/parser.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/parsing/parser.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
atic_initializer = CreateStaticElementsInitializer(name, class_info);
  }

  FunctionLiteral* instance_members_initializer_function = nullptr;
  if (class_info->has_instance_members()) {
    instance_members_initializer_function =
        CreateInstanceMembersInitializer(name, class_info);
    class_info->constructor->set_requires_instance_members_initializer(true);
    class_info->constructor->add_expected_properties(
        class_info->instance_fields->length());
  }

  if (class_info->requires_brand) {
    class_info->constructor->set_class_scope_has_private_brand(true);
  }
  if (class_info->has_static_private_methods_or_accessors) {
    class_info->constructor->set_has_static_private_methods_or_accessors(true);
  }
  ClassLiteral* class_literal = factory()->NewClassLiteral(
      block_scope, class_info->extends, class_info->constructor,
      class_info->public_members, class_info->private_members,
      static_initializer, instance_members_initializer_function, pos, end_pos,
      class_info->has_static_computed_names, class_info->is_anonymous,
      class_info->home_object_variable,
      class_info->static_home_object_variable);

  AddFunctionForNameInference(class_info->constructor);
  return class_literal;
}

void Parser::InsertShadowingVarBindingInitializers(Block* inner_block) {
  // For each var-binding that shadows a parameter, insert an assignment
  // initializing the variable with the parameter.
  Scope* inner_scope = inner_block->scope();
  DCHECK(inner_scope->is_declaration_scope());
  Scope* function_scope = inner_scope->outer_scope();
  DCHECK(function_scope->is_function_scope());
  BlockState block_state(&scope_, inner_scope);
  // According to https://tc39.es/ecma262/#sec-functiondeclarationinstantiation
  // If a variable's name conflicts with the names of both parameters and
  // functions, no bindings should be created for it. A set is used here
  // to record such variables.
  std::set<Variable*> hoisted_func_vars;
  std::vector<std::pair<Variable*, Variable*>> var_param_bindings;
  for (Declaration* decl : *inner_scope->declarations()) {
    if (!decl->IsVariableDeclaration()) {
      hoisted_func_vars.insert(decl->var());
      continue;
    } else if (decl->var()->mode() != VariableMode::kVar) {
      continue;
    }
    const AstRawString* name = decl->var()->raw_name();
    Variable* parameter = function_scope->LookupLocal(name);
    if (parameter == nullptr) continue;
    var_param_bindings.push_back(std::pair(decl->var(), parameter));
  }

  for (auto decl : var_param_bindings) {
    if (hoisted_func_vars.find(decl.first) != hoisted_func_vars.end()) {
      continue;
    }
    const AstRawString* name = decl.first->raw_name();
    VariableProxy* to = NewUnresolved(name);
    VariableProxy* from = factory()->NewVariableProxy(decl.second);
    Expression* assignment =
        factory()->NewAssignment(Token::kAssign, to, from, kNoSourcePosition);
    Statement* statement =
        factory()->NewExpressionStatement(assignment, kNoSourcePosition);
    inner_block->statements()->InsertAt(0, statement, zone());
  }
}

void Parser::InsertSloppyBlockFunctionVarBindings(DeclarationScope* scope) {
  // For the outermost eval scope, we cannot hoist during parsing: let
  // declarations in the surrounding scope may prevent hoisting, but the
  // information is unaccessible during parsing. In this case, we hoist later in
  // DeclarationScope::Analyze.
  if (scope->is_eval_scope() && scope->outer_scope() == original_scope_) {
    return;
  }
  scope->HoistSloppyBlockFunctions(factory());
}

// ----------------------------------------------------------------------------
// Parser support

template <typename IsolateT>
void Parser::HandleSourceURLComments(IsolateT* isolate,
                                     DirectHandle<Script> script) {
  Handle<String> source_url = scanner_.SourceUrl(isolate);
  if (!source_url.is_null()) {
    script->set_source_url(*source_url);
  }
  Handle<String> source_mapping_url = scanner_.SourceMappingUrl(isolate);
  // The API can provide a source map URL and the API should take precedence.
  // Let's make sure we do not override the API with the magic comment.
  if (!source_mapping_url.is_null() &&
      IsUndefined(script->source_mapping_url(isolate), isolate)) {
    script->set_source_mapping_url(*source_mapping_url);
  }
}

template void Parser::HandleSourceURLComments(Isolate* isolate,
                                              DirectHandle<Script> script);
template void Parser::HandleSourceURLComments(LocalIsolate* isolate,
                                              DirectHandle<Script> script);

void Parser::UpdateStatistics(Isolate* isolate, DirectHandle<Script> script) {
  CHECK_NOT_NULL(isolate);

  // Move statistics to Isolate.
  for (int feature = 0; feature < v8::Isolate::kUseCounterFeatureCount;
       ++feature) {
    if (use_counts_[feature] > 0) {
      isolate->CountUsage(v8::Isolate::UseCounterFeature(feature));
    }
  }
  if (scanner_.FoundHtmlComment()) {
    isolate->CountUsage(v8::Isolate::kHtmlComment);
    if (script->line_offset() == 0 && script->column_offset() == 0) {
      isolate->CountUsage(v8::Isolate::kHtmlCommentInExternalScript);
    }
  }
  if (scanner_.SawMagicCommentCompileHintsAll()) {
    isolate->CountUsage(v8::Isolate::kCompileHintsMagicAll);
  }
  if (scanner_.SawSourceMappingUrlMagicCommentAtSign()) {
    isolate->CountUsage(v8::Isolate::kSourceMappingUrlMagicCommentAtSign);
  }
}

void Parser::UpdateStatistics(
    DirectHandle<Script> script,
    base::SmallVector<v8::Isolate::UseCounterFeature, 8>* use_counts,
    int* preparse_skipped) {
  // Move statistics to Isolate.
  for (int feature = 0; feature < v8::Isolate::kUseCounterFeatureCount;
       ++feature) {
    if (use_counts_[feature] > 0) {
      use_counts->emplace_back(v8::Isolate::UseCounterFeature(feature));
    }
  }
  if (scanner_.FoundHtmlComment()) {
    use_counts->emplace_back(v8::Isolate::kHtmlComment);
    if (script->line_offset() == 0 && script->column_offset() == 0) {
      use_counts->emplace_back(v8::Isolate::kHtmlCommentInExternalScript);
    }
  }
  if (scanner_.SawMagicCommentCompileHintsAll()) {
    use_counts->emplace_back(v8::Isolate::kCompileHintsMagicAll);
  }
  if (scanner_.SawSourceMappingUrlMagicCommentAtSign()) {
    use_counts->emplace_back(v8::Isolate::kSourceMappingUrlMagicCommentAtSign);
  }

  *preparse_skipped = total_preparse_skipped_;
}

void Parser::ParseOnBackground(LocalIsolate* isolate, ParseInfo* info,
                               DirectHandle<Script> script, int start_position,
                               int end_position, int function_literal_id) {
  RCS_SCOPE(isolate, RuntimeCallCounterId::kParseProgram,
            RuntimeCallStats::CounterMode::kThreadSpecific);
  parsing_on_main_thread_ = false;

  DCHECK_NULL(info->literal());
  FunctionLiteral* result = nullptr;

  // We can park the isolate while parsing, it doesn't need to allocate or
  // access the main thread.
  isolate->ParkIfOnBackgroundAndExecute([this, start_position, end_position,
                                         function_literal_id, info, &result]() {
    scanner_.Initialize();

    DCHECK(original_scope_);

    // When streaming, we don't know the length of the source until we have
    // parsed it. The raw data can be UTF-8, so we wouldn't know the source
    // length until we have decoded it anyway even if we knew the raw data
    // length (which we don't). We work around this by storing all the scopes
    // which need their end position set at the end of the script (the top scope
    // and possible eval scopes) and set their end position after we know the
    // script length.
    if (flags().is_toplevel()) {
      DCHECK_EQ(start_position, 0);
      DCHECK_EQ(end_position, 0);
      DCHECK_EQ(function_literal_id, kFunctionLiteralIdTopLevel);
      result = DoParseProgram(/* isolate = */ nullptr, info);
    } else {
      std::optional<ClassScope::HeritageParsingScope> heritage;
      if (V8_UNLIKELY(flags().private_name_lookup_skips_outer_class() &&
                      original_scope_->is_class_scope())) {
        // If the function skips the outer class and the outer scope is a class,
        // the function is in heritage position. Otherwise the function scope's
        // skip bit will be correctly inherited from the outer scope.
        heritage.emplace(original_scope_->AsClassScope());
      }
      result = DoParseFunction(/* isolate = */ nullptr, info, start_position,
                               end_position, function_literal_id,
                               info->function_name());
    }
    if (result == nullptr) return;
    MaybeProcessSourceRanges(info, result, stack_limit_);
  });
  // We need to unpark by now though, to be able to internalize.
  if (flags().is_toplevel()) {
    HandleSourceURLComments(isolate, script);
  }
  if (result == nullptr) return;
  PostProcessParseResult(isolate, info, result);
}

Parser::TemplateLiteralState Parser::OpenTemplateLiteral(int pos) {
  return zone()->New<TemplateLiteral>(zone(), pos);
}

void Parser::AddTemplateSpan(TemplateLiteralState* state, bool should_cook,
                             bool tail) {
  int end = scanner()->location().end_pos - (tail ? 1 : 2);
  const AstRawString* raw = scanner()->CurrentRawSymbol(ast_value_factory());
  if (should_cook) {
    const AstRawString* cooked = scanner()->CurrentSymbol(ast_value_factory());
    (*state)->AddTemplateSpan(cooked, raw, end, zone());
  } else {
    (*state)->AddTemplateSpan(nullptr, raw, end, zone());
  }
}

void Parser::AddTemplateExpression(TemplateLiteralState* state,
                                   Expression* expression) {
  (*state)->AddExpression(expression, zone());
}

Expression* Parser::CloseTemplateLiteral(TemplateLiteralState* state, int start,
                                         Expression* tag) {
  TemplateLiteral* lit = *state;
  int pos = lit->position();
  const ZonePtrList<const AstRawString>* cooked_strings = lit->cooked();
  const ZonePtrList<const AstRawString>* raw_strings = lit->raw();
  const ZonePtrList<Expression>* expressions = lit->expressions();
  DCHECK_EQ(cooked_strings->length(), raw_strings->length());
  DCHECK_EQ(cooked_strings->length(), expressions->length() + 1);

  if (!tag) {
    if (cooked_strings->length() == 1) {
      return factory()->NewStringLiteral(cooked_strings->first(), pos);
    }
    return factory()->NewTemplateLiteral(cooked_strings, expressions, pos);
  } else {
    // GetTemplateObject
    Expression* template_object =
        factory()->NewGetTemplateObject(cooked_strings, raw_strings, pos);

    // Call TagFn
    ScopedPtrList<Expression> call_args(pointer_buffer());
    call_args.Add(template_object);
    call_args.AddAll(expressions->ToConstVector());
    return factory()->NewTaggedTemplate(tag, call_args, pos);
  }
}

void Parser::SetLanguageMode(Scope* scope, LanguageMode mode) {
  v8::Isolate::UseCounterFeature feature;
  if (is_sloppy(mode))
    feature = v8::Isolate::kSloppyMode;
  else if (is_strict(mode))
    feature = v8::Isolate::kStrictMode;
  else
    UNREACHABLE();
  ++use_counts_[feature];
  scope->SetLanguageMode(mode);
}

#if V8_ENABLE_WEBASSEMBLY
void Parser::SetAsmModule() {
  // Store the usage count; The actual use counter on the isolate is
  // incremented after parsing is done.
  ++use_counts_[v8::Isolate::kUseAsm];
  DCHECK(scope()->is_declaration_scope());
  scope()->AsDeclarationScope()->set_is_asm_module();
  info_->set_contains_asm_module(true);
}
#endif  // V8_ENABLE_WEBASSEMBLY

Expression* Parser::ExpressionListToExpression(
    const ScopedPtrList<Expression>& args) {
  Expression* expr = args.at(0);
  if (args.length() == 1) return expr;
  if (args.length() == 2) {
    return factory()->NewBinaryOperation(Token::kComma, expr, args.at(1),
                                         args.at(1)->position());
  }
  NaryOperation* result =
      factory()->NewNaryOperation(Token::kComma, expr, args.length() - 1);
  for (int i = 1; i < args.length(); i++) {
    result->AddSubsequent(args.at(i), args.at(i)->position());
  }
  return result;
}

void Parser::SetFunctionNameFromPropertyName(LiteralProperty* property,
                                             const AstRawString* name,
                                             const AstRawString* prefix) {
  if (has_error()) return;
  // Ensure that the function we are going to create has shared name iff
  // we are not going to set it later.
  if (property->NeedsSetFunctionName()) {
    name = nullptr;
    prefix = nullptr;
  } else {
    // If the property value is an anonymous function or an anonymous class or
    // a concise method or an accessor function which doesn't require the name
    // to be set then the shared name must be provided.
    DCHECK_IMPLIES(property->value()->IsAnonymousFunctionDefinition() ||
                       property->value()->IsConciseMethodDefinition() ||
                       property->value()->IsAccessorFunctionDefinition(),
                   name != nullptr);
  }

  Expression* value = property->value();
  SetFunctionName(value, name, prefix);
}

void Parser::SetFunctionNameFromPropertyName(ObjectLiteralProperty* property,
                                             const AstRawString* name,
                                             const AstRawString* prefix) {
  // Ignore "__proto__" as a name when it's being used to set the [[Prototype]]
  // of an object literal.
  // See ES #sec-__proto__-property-names-in-object-initializers.
  if (property->IsPrototype() || has_error()) return;

  DCHECK(!property->value()->IsAnonymousFunctionDefinition() ||
         property->kind() == ObjectLiteralProperty::COMPUTED);

  SetFunctionNameFromPropertyName(static_cast<LiteralProperty*>(property), name,
                                  prefix);
}

void Parser::SetFunctionNameFromIdentifierRef(Expression* value,
                                              Expression* identifier) {
  if (!identifier->IsVariableProxy()) return;
  // IsIdentifierRef of parenthesized expressions is false.
  if (identifier->is_parenthesized()) return;
  SetFunctionName(value, identifier->AsVariableProxy()->raw_name());
}

void Parser::SetFunctionName(Expression* value, const AstRawString* name,
                             const AstRawString* prefix) {
  if (!value->IsAnonymousFunctionDefinition() &&
      !value->IsConciseMethodDefinition() &&
      !value->IsAccessorFunctionDefinition()) {
    return;
  }
  auto function = value->AsFunctionLiteral();
  if (value->IsClassLiteral()) {
    function = value->AsClassLiteral()->constructor();
  }
  if (function != nullptr) {
    AstConsString* cons_name = nullptr;
    if (name != nullptr) {
      if (prefix != nullptr) {
        cons_name = ast_value_factory()->NewConsString(prefix, name);
      } else {
        cons_name = ast_value_factory()->NewConsString(name);
      }
    } else {
      DCHECK_NULL(prefix);
    }
    function->set_raw_name(cons_name);
  }
}

}  // namespace v8::internal
```