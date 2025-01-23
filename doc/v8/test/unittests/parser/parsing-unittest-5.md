Response: The user wants to understand the functionality of the C++ code file `v8/test/unittests/parser/parsing-unittest.cc`. They've specified this is part 6 of an 8-part series, suggesting they are progressively analyzing the file.

To answer this, I need to:

1. **Identify the core purpose of the file:** Based on the path and filename, it's likely related to testing the V8 JavaScript engine's parser. The "unittests" part suggests it contains isolated tests for different parsing scenarios.

2. **Analyze the provided code snippets:** The code consists of several `TEST_F` blocks, each representing a specific test case. These tests seem to focus on:
    * **Module parsing:**  Verifying the correct parsing of `import` statements, including those with `with` clauses for import attributes.
    * **Error handling:** Testing scenarios that should result in parsing errors (e.g., duplicate `__proto__` properties, declarations in single-statement contexts).
    * **Language features:** Testing the parsing of various JavaScript language features (e.g., strict mode directives, object spread, template literals, destructuring, `new.target`, `import.meta`, source phase imports).

3. **Summarize the file's function:** The file serves as a collection of unit tests specifically designed to validate the correctness of the V8 JavaScript parser. It checks if the parser correctly identifies valid and invalid JavaScript syntax.

4. **Explain the relation to JavaScript:** The tests directly exercise the parsing logic for JavaScript code. If the parser fails on any of these tests, it indicates a bug in the parser that needs to be fixed.

5. **Provide JavaScript examples:**  To illustrate the connection, I should provide JavaScript code snippets similar to those being tested in the C++ file and explain what the parser is supposed to do with them. For example, an `import` statement with attributes or a destructuring assignment.
这个C++源代码文件 `v8/test/unittests/parser/parsing-unittest.cc` 的第6部分，主要功能是**测试 V8 JavaScript 引擎的解析器 (parser) 在处理各种 JavaScript 语法结构时的正确性**。

具体来说，这部分侧重于以下几个方面的解析测试：

* **模块 (Modules) 的解析:**  尤其是 `import` 语句的解析，包括：
    * `import` 语句中 `with` 子句引入的 **Import Attributes (导入属性)** 的解析，测试了属性的顺序和键的排序。
    * 确保模块请求 (module requests) 是按照源代码中出现的顺序进行解析的。
* **错误处理 (Error Handling):** 测试解析器是否能正确识别并报告各种语法错误，例如：
    * 对象字面量中重复的 `__proto__` 属性。
    * 在单语句上下文中声明 (declarations)（例如 `if`, `while`, `for` 等语句的控制体中）。
* **语言特性 (Language Features) 的解析:** 测试解析器对各种 ECMAScript 语言特性的解析，包括：
    * **指令 (Directives):**  例如 "use strict" 指令。
    * **属性名 `eval` 和 `arguments`:** 在严格模式下的限制。
    * **函数字面量的重复参数:** 在严格模式和非严格模式下的处理。
    * **箭头函数 (Arrow Functions) 的自动分号插入 (ASI) 错误。**
    * **对象展开 (Object Spread) 语法。**
    * **模板字面量 (Template Literals) 中的转义序列。**
    * **解构 (Destructuring) 赋值和声明。**  测试了各种解构的语法，包括成功和失败的情况，以及在不同上下文中的使用（例如变量声明、函数参数、赋值）。
    * **`new.target` 元属性。**
    * **`import.meta` 元属性。**
    * **Source Phase Imports (源阶段导入，实验性特性)。**
    * **`import()` 动态导入。**
    * **`const` 和 `let` 声明在非严格模式下的行为。**
    * **在非简单参数列表中使用 "use strict" 指令的错误。**
    * **保留字 (Keywords) 的转义形式。**

**与 JavaScript 功能的关系以及 JavaScript 示例:**

这个 C++ 文件中的测试直接关系到 V8 引擎如何理解和执行 JavaScript 代码。  每个 `TEST_F` 都会解析一段 JavaScript 代码片段，并断言解析结果是否符合预期。

以下是一些与代码中测试相关的 JavaScript 示例：

**1. Import Attributes:**

```javascript
// 对应 `ModuleParsingImportAttributes` 测试
import 'module.js' with { type: 'JSON' };
import 'other.js' with { foo: 'bar', "hello": "world" };
```

**2. 模块请求排序:**

```javascript
// 对应 `ModuleParsingModuleRequestOrdering` 测试
import 'foo' with { };
import 'baaaaaar' with { };
import 'aa' with { };
// ... 等等
```

**3. 重复的 `__proto__` 属性错误:**

```javascript
// 对应 `DuplicateProtoError` 测试
let obj1 = { __proto__: null, __proto__: {} }; // 应该报错
let obj2 = { __proto__: null, "__proto__": {} }; // 应该报错
```

**4. 单语句上下文中的声明错误:**

```javascript
// 对应 `DeclarationsError` 测试
'use strict';
if (true) let x = 1; // 应该报错
'use strict';
while (false) const y = 2; // 应该报错
```

**5. 对象展开语法:**

```javascript
// 对应 `ObjectSpreadPositiveTests` 和 `ObjectSpreadNegativeTests`
let obj = { a: 1, b: 2 };
let newObj = { ...obj, c: 3 }; // 合法
let invalidObj = { ...var x = 1 }; // 应该报错
```

**6. 解构赋值:**

```javascript
// 对应 `DestructuringAssignmentPositiveTests` 和 `DestructuringAssignmentNegativeTests`
let a, b;
[a, b] = [1, 2]; // 合法
({ x: a, y: b } = { x: 3, y: 4 }); // 合法

let c;
c++ = 5; // 应该报错，解构赋值目标不能是自增/自减表达式
```

**7. `new.target`:**

```javascript
// 对应 `NewTarget` 测试
function MyClass() {
  if (!new.target) {
    throw new Error('必须使用 new 调用');
  }
  console.log('使用了 new 调用');
}

new MyClass(); // 合法
MyClass(); // 应该报错
```

**8. `import.meta`:**

```javascript
// 对应 `ImportMetaSuccess` 和 `ImportMetaFailure` 测试
// 只能在模块中使用
console.log(import.meta.url);
```

**总结:**

这个 C++ 文件是 V8 引擎测试套件的关键组成部分，它通过大量的单元测试来确保 JavaScript 语言的各种语法特性能够被正确地解析，并且在出现语法错误时能够被准确地识别和报告。 这对于保证 V8 引擎的稳定性和符合 ECMAScript 标准至关重要。

### 提示词
```
这是目录为v8/test/unittests/parser/parsing-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第6部分，共8部分，请归纳一下它的功能
```

### 源代码
```
CHECK_EQ(155, elem->position());
      CHECK(elem->import_attributes()
                ->at(foo_string)
                .first->IsOneByteEqualTo("bar2"));
      CHECK_EQ(169, elem->import_attributes()->at(foo_string).second.beg_pos);
    } else if (elem->index() == 4) {
      CHECK(elem->specifier()->IsOneByteEqualTo("m.js"));
      CHECK_EQ(2, elem->import_attributes()->size());
      CHECK_EQ(206, elem->position());
      CHECK(elem->import_attributes()
                ->at(foo_string)
                .first->IsOneByteEqualTo("bar"));
      CHECK_EQ(220, elem->import_attributes()->at(foo_string).second.beg_pos);
      CHECK(elem->import_attributes()
                ->at(foo2_string)
                .first->IsOneByteEqualTo("bar"));
      CHECK_EQ(232, elem->import_attributes()->at(foo2_string).second.beg_pos);
    } else if (elem->index() == 5) {
      CHECK(elem->specifier()->IsOneByteEqualTo("n.js"));
      CHECK_EQ(1, elem->import_attributes()->size());
      CHECK_EQ(269, elem->position());
      CHECK(elem->import_attributes()
                ->at(foo_string)
                .first->IsOneByteEqualTo("bar"));
      CHECK_EQ(283, elem->import_attributes()->at(foo_string).second.beg_pos);
    } else {
      UNREACHABLE();
    }
  }
}

TEST_F(ParsingTest, ModuleParsingModuleRequestOrdering) {
  i::v8_flags.harmony_import_attributes = true;
  i::Isolate* isolate = i_isolate();
  i::Factory* factory = isolate->factory();
  isolate->stack_guard()->SetStackLimit(base::Stack::GetCurrentStackPosition() -
                                        128 * 1024);

  static const char kSource[] =
      "import 'foo' with { };"
      "import 'baaaaaar' with { };"
      "import 'aa' with { };"
      "import 'a' with { a: 'b' };"
      "import 'b' with { };"
      "import 'd' with { a: 'b' };"
      "import 'c' with { };"
      "import 'f' with { };"
      "import 'f' with { a: 'b'};"
      "import 'g' with { a: 'b' };"
      "import 'g' with { };"
      "import 'h' with { a: 'd' };"
      "import 'h' with { b: 'c' };"
      "import 'i' with { b: 'c' };"
      "import 'i' with { a: 'd' };"
      "import 'j' with { a: 'b' };"
      "import 'j' with { a: 'c' };"
      "import 'k' with { a: 'c' };"
      "import 'k' with { a: 'b' };"
      "import 'l' with { a: 'b', e: 'f' };"
      "import 'l' with { a: 'c', d: 'g' };"
      "import 'm' with { a: 'c', d: 'g' };"
      "import 'm' with { a: 'b', e: 'f' };"
      "import 'n' with { 'd': '' };"
      "import 'n' with { 'a': 'b' };"
      "import 'o' with { 'a': 'b' };"
      "import 'o' with { 'd': '' };"
      "import 'p' with { 'z': 'c' };"
      "import 'p' with { 'a': 'c', 'b': 'c' };";
  i::DirectHandle<i::String> source =
      factory->NewStringFromAsciiChecked(kSource);
  i::Handle<i::Script> script = factory->NewScript(source);
  i::UnoptimizedCompileState compile_state;
  i::ReusableUnoptimizedCompileState reusable_state(isolate);
  i::UnoptimizedCompileFlags flags =
      i::UnoptimizedCompileFlags::ForScriptCompile(isolate, *script);
  flags.set_is_module(true);
  i::ParseInfo info(isolate, flags, &compile_state, &reusable_state);
  CHECK_PARSE_PROGRAM(&info, script, isolate);

  i::FunctionLiteral* func = info.literal();
  i::ModuleScope* module_scope = func->scope()->AsModuleScope();
  CHECK(module_scope->is_module_scope());

  i::SourceTextModuleDescriptor* descriptor = module_scope->module();
  CHECK_NOT_NULL(descriptor);

  const i::AstRawString* a_string =
      info.ast_value_factory()->GetOneByteString("a");
  const i::AstRawString* b_string =
      info.ast_value_factory()->GetOneByteString("b");
  const i::AstRawString* d_string =
      info.ast_value_factory()->GetOneByteString("d");
  const i::AstRawString* e_string =
      info.ast_value_factory()->GetOneByteString("e");
  const i::AstRawString* z_string =
      info.ast_value_factory()->GetOneByteString("z");
  CHECK_EQ(29u, descriptor->module_requests().size());
  auto request_iterator = descriptor->module_requests().cbegin();

  CHECK((*request_iterator)->specifier()->IsOneByteEqualTo("a"));
  ++request_iterator;

  CHECK((*request_iterator)->specifier()->IsOneByteEqualTo("aa"));
  ++request_iterator;

  CHECK((*request_iterator)->specifier()->IsOneByteEqualTo("b"));
  ++request_iterator;

  CHECK((*request_iterator)->specifier()->IsOneByteEqualTo("baaaaaar"));
  ++request_iterator;

  CHECK((*request_iterator)->specifier()->IsOneByteEqualTo("c"));
  ++request_iterator;

  CHECK((*request_iterator)->specifier()->IsOneByteEqualTo("d"));
  ++request_iterator;

  CHECK((*request_iterator)->specifier()->IsOneByteEqualTo("f"));
  CHECK_EQ(0, (*request_iterator)->import_attributes()->size());
  ++request_iterator;

  CHECK((*request_iterator)->specifier()->IsOneByteEqualTo("f"));
  CHECK_EQ(1, (*request_iterator)->import_attributes()->size());
  ++request_iterator;

  CHECK((*request_iterator)->specifier()->IsOneByteEqualTo("foo"));
  ++request_iterator;

  CHECK((*request_iterator)->specifier()->IsOneByteEqualTo("g"));
  CHECK_EQ(0, (*request_iterator)->import_attributes()->size());
  ++request_iterator;

  CHECK((*request_iterator)->specifier()->IsOneByteEqualTo("g"));
  CHECK_EQ(1, (*request_iterator)->import_attributes()->size());
  ++request_iterator;

  CHECK((*request_iterator)->specifier()->IsOneByteEqualTo("h"));
  CHECK_EQ(1, (*request_iterator)->import_attributes()->size());
  CHECK((*request_iterator)
            ->import_attributes()
            ->at(a_string)
            .first->IsOneByteEqualTo("d"));
  ++request_iterator;

  CHECK((*request_iterator)->specifier()->IsOneByteEqualTo("h"));
  CHECK_EQ(1, (*request_iterator)->import_attributes()->size());
  CHECK((*request_iterator)
            ->import_attributes()
            ->at(b_string)
            .first->IsOneByteEqualTo("c"));
  ++request_iterator;

  CHECK((*request_iterator)->specifier()->IsOneByteEqualTo("i"));
  CHECK_EQ(1, (*request_iterator)->import_attributes()->size());
  CHECK((*request_iterator)
            ->import_attributes()
            ->at(a_string)
            .first->IsOneByteEqualTo("d"));
  ++request_iterator;

  CHECK((*request_iterator)->specifier()->IsOneByteEqualTo("i"));
  CHECK_EQ(1, (*request_iterator)->import_attributes()->size());
  CHECK((*request_iterator)
            ->import_attributes()
            ->at(b_string)
            .first->IsOneByteEqualTo("c"));
  ++request_iterator;

  CHECK((*request_iterator)->specifier()->IsOneByteEqualTo("j"));
  CHECK_EQ(1, (*request_iterator)->import_attributes()->size());
  CHECK((*request_iterator)
            ->import_attributes()
            ->at(a_string)
            .first->IsOneByteEqualTo("b"));
  ++request_iterator;

  CHECK((*request_iterator)->specifier()->IsOneByteEqualTo("j"));
  CHECK_EQ(1, (*request_iterator)->import_attributes()->size());
  CHECK((*request_iterator)
            ->import_attributes()
            ->at(a_string)
            .first->IsOneByteEqualTo("c"));
  ++request_iterator;

  CHECK((*request_iterator)->specifier()->IsOneByteEqualTo("k"));
  CHECK_EQ(1, (*request_iterator)->import_attributes()->size());
  CHECK((*request_iterator)
            ->import_attributes()
            ->at(a_string)
            .first->IsOneByteEqualTo("b"));
  ++request_iterator;

  CHECK((*request_iterator)->specifier()->IsOneByteEqualTo("k"));
  CHECK_EQ(1, (*request_iterator)->import_attributes()->size());
  CHECK((*request_iterator)
            ->import_attributes()
            ->at(a_string)
            .first->IsOneByteEqualTo("c"));
  ++request_iterator;

  CHECK((*request_iterator)->specifier()->IsOneByteEqualTo("l"));
  CHECK_EQ(2, (*request_iterator)->import_attributes()->size());
  CHECK((*request_iterator)
            ->import_attributes()
            ->at(a_string)
            .first->IsOneByteEqualTo("b"));
  CHECK((*request_iterator)
            ->import_attributes()
            ->at(e_string)
            .first->IsOneByteEqualTo("f"));
  ++request_iterator;

  CHECK((*request_iterator)->specifier()->IsOneByteEqualTo("l"));
  CHECK_EQ(2, (*request_iterator)->import_attributes()->size());
  CHECK((*request_iterator)
            ->import_attributes()
            ->at(a_string)
            .first->IsOneByteEqualTo("c"));
  CHECK((*request_iterator)
            ->import_attributes()
            ->at(d_string)
            .first->IsOneByteEqualTo("g"));
  ++request_iterator;

  CHECK((*request_iterator)->specifier()->IsOneByteEqualTo("m"));
  CHECK_EQ(2, (*request_iterator)->import_attributes()->size());
  CHECK((*request_iterator)
            ->import_attributes()
            ->at(a_string)
            .first->IsOneByteEqualTo("b"));
  CHECK((*request_iterator)
            ->import_attributes()
            ->at(e_string)
            .first->IsOneByteEqualTo("f"));
  ++request_iterator;

  CHECK((*request_iterator)->specifier()->IsOneByteEqualTo("m"));
  CHECK_EQ(2, (*request_iterator)->import_attributes()->size());
  CHECK((*request_iterator)
            ->import_attributes()
            ->at(a_string)
            .first->IsOneByteEqualTo("c"));
  CHECK((*request_iterator)
            ->import_attributes()
            ->at(d_string)
            .first->IsOneByteEqualTo("g"));
  ++request_iterator;

  CHECK((*request_iterator)->specifier()->IsOneByteEqualTo("n"));
  CHECK_EQ(1, (*request_iterator)->import_attributes()->size());
  CHECK((*request_iterator)
            ->import_attributes()
            ->at(a_string)
            .first->IsOneByteEqualTo("b"));
  ++request_iterator;

  CHECK((*request_iterator)->specifier()->IsOneByteEqualTo("n"));
  CHECK_EQ(1, (*request_iterator)->import_attributes()->size());
  CHECK((*request_iterator)
            ->import_attributes()
            ->at(d_string)
            .first->IsOneByteEqualTo(""));
  ++request_iterator;

  CHECK((*request_iterator)->specifier()->IsOneByteEqualTo("o"));
  CHECK_EQ(1, (*request_iterator)->import_attributes()->size());
  CHECK((*request_iterator)
            ->import_attributes()
            ->at(a_string)
            .first->IsOneByteEqualTo("b"));
  ++request_iterator;

  CHECK((*request_iterator)->specifier()->IsOneByteEqualTo("o"));
  CHECK_EQ(1, (*request_iterator)->import_attributes()->size());
  CHECK((*request_iterator)
            ->import_attributes()
            ->at(d_string)
            .first->IsOneByteEqualTo(""));
  ++request_iterator;

  CHECK((*request_iterator)->specifier()->IsOneByteEqualTo("p"));
  CHECK_EQ(2, (*request_iterator)->import_attributes()->size());
  CHECK((*request_iterator)
            ->import_attributes()
            ->at(a_string)
            .first->IsOneByteEqualTo("c"));
  CHECK((*request_iterator)
            ->import_attributes()
            ->at(b_string)
            .first->IsOneByteEqualTo("c"));
  ++request_iterator;

  CHECK((*request_iterator)->specifier()->IsOneByteEqualTo("p"));
  CHECK_EQ(1, (*request_iterator)->import_attributes()->size());
  CHECK((*request_iterator)
            ->import_attributes()
            ->at(z_string)
            .first->IsOneByteEqualTo("c"));
}

TEST_F(ParsingTest, ModuleParsingImportAttributesKeySorting) {
  i::v8_flags.harmony_import_attributes = true;
  i::Isolate* isolate = i_isolate();
  i::Factory* factory = isolate->factory();
  isolate->stack_guard()->SetStackLimit(base::Stack::GetCurrentStackPosition() -
                                        128 * 1024);

  static const char kSource[] =
      "import 'a' with { 'b':'z', 'a': 'c' };"
      "import 'b' with { 'aaaaaa': 'c', 'b': 'z' };"
      "import 'c' with { '': 'c', 'b': 'z' };"
      "import 'd' with { 'aabbbb': 'c', 'aaabbb': 'z' };"
      // zzzz\u0005 is a one-byte string, yyyy\u0100 is a two-byte string.
      "import 'e' with { 'zzzz\\u0005': 'second', 'yyyy\\u0100': 'first' };"
      // Both keys are two-byte strings.
      "import 'f' with { 'xxxx\\u0005\\u0101': 'first', "
      "'xxxx\\u0100\\u0101': 'second' };";
  i::DirectHandle<i::String> source =
      factory->NewStringFromAsciiChecked(kSource);
  i::Handle<i::Script> script = factory->NewScript(source);
  i::UnoptimizedCompileState compile_state;
  i::ReusableUnoptimizedCompileState reusable_state(isolate);
  i::UnoptimizedCompileFlags flags =
      i::UnoptimizedCompileFlags::ForScriptCompile(isolate, *script);
  flags.set_is_module(true);
  i::ParseInfo info(isolate, flags, &compile_state, &reusable_state);
  CHECK_PARSE_PROGRAM(&info, script, isolate);

  i::FunctionLiteral* func = info.literal();
  i::ModuleScope* module_scope = func->scope()->AsModuleScope();
  CHECK(module_scope->is_module_scope());

  i::SourceTextModuleDescriptor* descriptor = module_scope->module();
  CHECK_NOT_NULL(descriptor);

  CHECK_EQ(6u, descriptor->module_requests().size());
  auto request_iterator = descriptor->module_requests().cbegin();

  CHECK((*request_iterator)->specifier()->IsOneByteEqualTo("a"));
  CHECK_EQ(2, (*request_iterator)->import_attributes()->size());
  auto attributes_iterator = (*request_iterator)->import_attributes()->cbegin();
  CHECK(attributes_iterator->first->IsOneByteEqualTo("a"));
  CHECK(attributes_iterator->second.first->IsOneByteEqualTo("c"));
  ++attributes_iterator;
  CHECK(attributes_iterator->first->IsOneByteEqualTo("b"));
  CHECK(attributes_iterator->second.first->IsOneByteEqualTo("z"));
  ++request_iterator;

  CHECK((*request_iterator)->specifier()->IsOneByteEqualTo("b"));
  CHECK_EQ(2, (*request_iterator)->import_attributes()->size());
  attributes_iterator = (*request_iterator)->import_attributes()->cbegin();
  CHECK(attributes_iterator->first->IsOneByteEqualTo("aaaaaa"));
  CHECK(attributes_iterator->second.first->IsOneByteEqualTo("c"));
  ++attributes_iterator;
  CHECK(attributes_iterator->first->IsOneByteEqualTo("b"));
  CHECK(attributes_iterator->second.first->IsOneByteEqualTo("z"));
  ++request_iterator;

  CHECK((*request_iterator)->specifier()->IsOneByteEqualTo("c"));
  CHECK_EQ(2, (*request_iterator)->import_attributes()->size());
  attributes_iterator = (*request_iterator)->import_attributes()->cbegin();
  CHECK(attributes_iterator->first->IsOneByteEqualTo(""));
  CHECK(attributes_iterator->second.first->IsOneByteEqualTo("c"));
  ++attributes_iterator;
  CHECK(attributes_iterator->first->IsOneByteEqualTo("b"));
  CHECK(attributes_iterator->second.first->IsOneByteEqualTo("z"));
  ++request_iterator;

  CHECK((*request_iterator)->specifier()->IsOneByteEqualTo("d"));
  CHECK_EQ(2, (*request_iterator)->import_attributes()->size());
  attributes_iterator = (*request_iterator)->import_attributes()->cbegin();
  CHECK(attributes_iterator->first->IsOneByteEqualTo("aaabbb"));
  CHECK(attributes_iterator->second.first->IsOneByteEqualTo("z"));
  ++attributes_iterator;
  CHECK(attributes_iterator->first->IsOneByteEqualTo("aabbbb"));
  CHECK(attributes_iterator->second.first->IsOneByteEqualTo("c"));
  ++request_iterator;

  CHECK((*request_iterator)->specifier()->IsOneByteEqualTo("e"));
  CHECK_EQ(2, (*request_iterator)->import_attributes()->size());
  attributes_iterator = (*request_iterator)->import_attributes()->cbegin();
  CHECK(attributes_iterator->second.first->IsOneByteEqualTo("first"));
  ++attributes_iterator;
  CHECK(attributes_iterator->second.first->IsOneByteEqualTo("second"));
  ++request_iterator;

  CHECK((*request_iterator)->specifier()->IsOneByteEqualTo("f"));
  CHECK_EQ(2, (*request_iterator)->import_attributes()->size());
  attributes_iterator = (*request_iterator)->import_attributes()->cbegin();
  CHECK(attributes_iterator->second.first->IsOneByteEqualTo("first"));
  ++attributes_iterator;
  CHECK(attributes_iterator->second.first->IsOneByteEqualTo("second"));
}

TEST_F(ParsingTest, DuplicateProtoError) {
  const char* context_data[][2] = {
      {"({", "});"}, {"'use strict'; ({", "});"}, {nullptr, nullptr}};
  const char* error_data[] = {"__proto__: {}, __proto__: {}",
                              "__proto__: {}, \"__proto__\": {}",
                              "__proto__: {}, \"__\x70roto__\": {}",
                              "__proto__: {}, a: 1, __proto__: {}", nullptr};

  RunParserSyncTest(context_data, error_data, kError);
}

TEST_F(ParsingTest, DuplicateProtoNoError) {
  const char* context_data[][2] = {
      {"({", "});"}, {"'use strict'; ({", "});"}, {nullptr, nullptr}};
  const char* error_data[] = {
      "__proto__: {}, ['__proto__']: {}",  "__proto__: {}, __proto__() {}",
      "__proto__: {}, get __proto__() {}", "__proto__: {}, set __proto__(v) {}",
      "__proto__: {}, __proto__",          nullptr};

  RunParserSyncTest(context_data, error_data, kSuccess);
}

TEST_F(ParsingTest, DeclarationsError) {
  const char* context_data[][2] = {{"'use strict'; if (true)", ""},
                                   {"'use strict'; if (false) {} else", ""},
                                   {"'use strict'; while (false)", ""},
                                   {"'use strict'; for (;;)", ""},
                                   {"'use strict'; for (x in y)", ""},
                                   {"'use strict'; do ", " while (false)"},
                                   {nullptr, nullptr}};

  const char* statement_data[] = {"let x = 1;", "const x = 1;", "class C {}",
                                  nullptr};

  RunParserSyncTest(context_data, statement_data, kError);
}

TEST_F(ParsingTest, LanguageModeDirectives) {
  TestLanguageMode("\"use nothing\"", i::LanguageMode::kSloppy);
  TestLanguageMode("\"use strict\"", i::LanguageMode::kStrict);

  TestLanguageMode("var x = 1; \"use strict\"", i::LanguageMode::kSloppy);

  TestLanguageMode("\"use some future directive\"; \"use strict\";",
                   i::LanguageMode::kStrict);
}

TEST_F(ParsingTest, PropertyNameEvalArguments) {
  const char* context_data[][2] = {{"'use strict';", ""}, {nullptr, nullptr}};

  const char* statement_data[] = {"({eval: 1})",
                                  "({arguments: 1})",
                                  "({eval() {}})",
                                  "({arguments() {}})",
                                  "({*eval() {}})",
                                  "({*arguments() {}})",
                                  "({get eval() {}})",
                                  "({get arguments() {}})",
                                  "({set eval(_) {}})",
                                  "({set arguments(_) {}})",

                                  "class C {eval() {}}",
                                  "class C {arguments() {}}",
                                  "class C {*eval() {}}",
                                  "class C {*arguments() {}}",
                                  "class C {get eval() {}}",
                                  "class C {get arguments() {}}",
                                  "class C {set eval(_) {}}",
                                  "class C {set arguments(_) {}}",

                                  "class C {static eval() {}}",
                                  "class C {static arguments() {}}",
                                  "class C {static *eval() {}}",
                                  "class C {static *arguments() {}}",
                                  "class C {static get eval() {}}",
                                  "class C {static get arguments() {}}",
                                  "class C {static set eval(_) {}}",
                                  "class C {static set arguments(_) {}}",

                                  nullptr};

  RunParserSyncTest(context_data, statement_data, kSuccess);
}

TEST_F(ParsingTest, FunctionLiteralDuplicateParameters) {
  const char* strict_context_data[][2] = {
      {"'use strict';(function(", "){})();"},
      {"(function(", ") { 'use strict'; })();"},
      {"'use strict'; function fn(", ") {}; fn();"},
      {"function fn(", ") { 'use strict'; }; fn();"},
      {nullptr, nullptr}};

  const char* sloppy_context_data[][2] = {{"(function(", "){})();"},
                                          {"(function(", ") {})();"},
                                          {"function fn(", ") {}; fn();"},
                                          {"function fn(", ") {}; fn();"},
                                          {nullptr, nullptr}};

  const char* data[] = {
      "a, a",
      "a, a, a",
      "b, a, a",
      "a, b, c, c",
      "a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, w",
      nullptr};

  RunParserSyncTest(strict_context_data, data, kError);
  RunParserSyncTest(sloppy_context_data, data, kSuccess);
}

TEST_F(ParsingTest, ArrowFunctionASIErrors) {
  const char* context_data[][2] = {
      {"'use strict';", ""}, {"", ""}, {nullptr, nullptr}};

  const char* data[] = {"(a\n=> a)(1)",
                        "(a/*\n*/=> a)(1)",
                        "((a)\n=> a)(1)",
                        "((a)/*\n*/=> a)(1)",
                        "((a, b)\n=> a + b)(1, 2)",
                        "((a, b)/*\n*/=> a + b)(1, 2)",
                        nullptr};
  RunParserSyncTest(context_data, data, kError);
}

TEST_F(ParsingTest, ObjectSpreadPositiveTests) {
  // clang-format off
  const char* context_data[][2] = {
    {"x = ", ""},
    {"'use strict'; x = ", ""},
    {nullptr, nullptr}};

  // clang-format off
  const char* data[] = {
    "{ ...y }",
    "{ a: 1, ...y }",
    "{ b: 1, ...y }",
    "{ y, ...y}",
    "{ ...z = y}",
    "{ ...y, y }",
    "{ ...y, ...y}",
    "{ a: 1, ...y, b: 1}",
    "{ ...y, b: 1}",
    "{ ...1}",
    "{ ...null}",
    "{ ...undefined}",
    "{ ...1 in {}}",
    "{ ...[]}",
    "{ ...async function() { }}",
    "{ ...async () => { }}",
    "{ ...new Foo()}",
    nullptr};
  // clang-format on

  RunParserSyncTest(context_data, data, kSuccess);
}

TEST_F(ParsingTest, ObjectSpreadNegativeTests) {
  const char* context_data[][2] = {
      {"x = ", ""}, {"'use strict'; x = ", ""}, {nullptr, nullptr}};

  // clang-format off
  const char* data[] = {
    "{ ...var z = y}",
    "{ ...var}",
    "{ ...foo bar}",
    "{* ...foo}",
    "{get ...foo}",
    "{set ...foo}",
    "{async ...foo}",
    nullptr};

  RunParserSyncTest(context_data, data, kError);
}

TEST_F(ParsingTest, TemplateEscapesPositiveTests) {
  // clang-format off
  const char* context_data[][2] = {
    {"", ""},
    {"'use strict';", ""},
    {nullptr, nullptr}};

  // clang-format off
  const char* data[] = {
    "tag`\\08`",
    "tag`\\01`",
    "tag`\\01${0}right`",
    "tag`left${0}\\01`",
    "tag`left${0}\\01${1}right`",
    "tag`\\1`",
    "tag`\\1${0}right`",
    "tag`left${0}\\1`",
    "tag`left${0}\\1${1}right`",
    "tag`\\xg`",
    "tag`\\xg${0}right`",
    "tag`left${0}\\xg`",
    "tag`left${0}\\xg${1}right`",
    "tag`\\xAg`",
    "tag`\\xAg${0}right`",
    "tag`left${0}\\xAg`",
    "tag`left${0}\\xAg${1}right`",
    "tag`\\u0`",
    "tag`\\u0${0}right`",
    "tag`left${0}\\u0`",
    "tag`left${0}\\u0${1}right`",
    "tag`\\u0g`",
    "tag`\\u0g${0}right`",
    "tag`left${0}\\u0g`",
    "tag`left${0}\\u0g${1}right`",
    "tag`\\u00g`",
    "tag`\\u00g${0}right`",
    "tag`left${0}\\u00g`",
    "tag`left${0}\\u00g${1}right`",
    "tag`\\u000g`",
    "tag`\\u000g${0}right`",
    "tag`left${0}\\u000g`",
    "tag`left${0}\\u000g${1}right`",
    "tag`\\u{}`",
    "tag`\\u{}${0}right`",
    "tag`left${0}\\u{}`",
    "tag`left${0}\\u{}${1}right`",
    "tag`\\u{-0}`",
    "tag`\\u{-0}${0}right`",
    "tag`left${0}\\u{-0}`",
    "tag`left${0}\\u{-0}${1}right`",
    "tag`\\u{g}`",
    "tag`\\u{g}${0}right`",
    "tag`left${0}\\u{g}`",
    "tag`left${0}\\u{g}${1}right`",
    "tag`\\u{0`",
    "tag`\\u{0${0}right`",
    "tag`left${0}\\u{0`",
    "tag`left${0}\\u{0${1}right`",
    "tag`\\u{\\u{0}`",
    "tag`\\u{\\u{0}${0}right`",
    "tag`left${0}\\u{\\u{0}`",
    "tag`left${0}\\u{\\u{0}${1}right`",
    "tag`\\u{110000}`",
    "tag`\\u{110000}${0}right`",
    "tag`left${0}\\u{110000}`",
    "tag`left${0}\\u{110000}${1}right`",
    "tag` ${tag`\\u`}`",
    "tag` ``\\u`",
    "tag`\\u`` `",
    "tag`\\u``\\u`",
    "` ${tag`\\u`}`",
    "` ``\\u`",
    nullptr};
  // clang-format on

  RunParserSyncTest(context_data, data, kSuccess);
}

TEST_F(ParsingTest, TemplateEscapesNegativeTests) {
  // clang-format off
  const char* context_data[][2] = {
    {"", ""},
    {"'use strict';", ""},
    {nullptr, nullptr}};

  // clang-format off
  const char* data[] = {
    "`\\08`",
    "`\\01`",
    "`\\01${0}right`",
    "`left${0}\\01`",
    "`left${0}\\01${1}right`",
    "`\\1`",
    "`\\1${0}right`",
    "`left${0}\\1`",
    "`left${0}\\1${1}right`",
    "`\\xg`",
    "`\\xg${0}right`",
    "`left${0}\\xg`",
    "`left${0}\\xg${1}right`",
    "`\\xAg`",
    "`\\xAg${0}right`",
    "`left${0}\\xAg`",
    "`left${0}\\xAg${1}right`",
    "`\\u0`",
    "`\\u0${0}right`",
    "`left${0}\\u0`",
    "`left${0}\\u0${1}right`",
    "`\\u0g`",
    "`\\u0g${0}right`",
    "`left${0}\\u0g`",
    "`left${0}\\u0g${1}right`",
    "`\\u00g`",
    "`\\u00g${0}right`",
    "`left${0}\\u00g`",
    "`left${0}\\u00g${1}right`",
    "`\\u000g`",
    "`\\u000g${0}right`",
    "`left${0}\\u000g`",
    "`left${0}\\u000g${1}right`",
    "`\\u{}`",
    "`\\u{}${0}right`",
    "`left${0}\\u{}`",
    "`left${0}\\u{}${1}right`",
    "`\\u{-0}`",
    "`\\u{-0}${0}right`",
    "`left${0}\\u{-0}`",
    "`left${0}\\u{-0}${1}right`",
    "`\\u{g}`",
    "`\\u{g}${0}right`",
    "`left${0}\\u{g}`",
    "`left${0}\\u{g}${1}right`",
    "`\\u{0`",
    "`\\u{0${0}right`",
    "`left${0}\\u{0`",
    "`left${0}\\u{0${1}right`",
    "`\\u{\\u{0}`",
    "`\\u{\\u{0}${0}right`",
    "`left${0}\\u{\\u{0}`",
    "`left${0}\\u{\\u{0}${1}right`",
    "`\\u{110000}`",
    "`\\u{110000}${0}right`",
    "`left${0}\\u{110000}`",
    "`left${0}\\u{110000}${1}right`",
    "`\\1``\\2`",
    "tag` ${`\\u`}`",
    "`\\u```",
    nullptr};
  // clang-format on

  RunParserSyncTest(context_data, data, kError);
}

TEST_F(ParsingTest, DestructuringPositiveTests) {
  const char* context_data[][2] = {{"'use strict'; let ", " = {};"},
                                   {"var ", " = {};"},
                                   {"'use strict'; const ", " = {};"},
                                   {"function f(", ") {}"},
                                   {"function f(argument1, ", ") {}"},
                                   {"var f = (", ") => {};"},
                                   {"var f = (argument1,", ") => {};"},
                                   {"try {} catch(", ") {}"},
                                   {nullptr, nullptr}};

  // clang-format off
  const char* data[] = {
    "a",
    "{ x : y }",
    "{ x : y = 1 }",
    "{ get, set }",
    "{ get = 1, set = 2 }",
    "[a]",
    "[a = 1]",
    "[a,b,c]",
    "[a, b = 42, c]",
    "{ x : x, y : y }",
    "{ x : x = 1, y : y }",
    "{ x : x, y : y = 42 }",
    "[]",
    "{}",
    "[{x:x, y:y}, [a,b,c]]",
    "[{x:x = 1, y:y = 2}, [a = 3, b = 4, c = 5]]",
    "{x}",
    "{x, y}",
    "{x = 42, y = 15}",
    "[a,,b]",
    "{42 : x}",
    "{42 : x = 42}",
    "{42e-2 : x}",
    "{42e-2 : x = 42}",
    "{x : y, x : z}",
    "{'hi' : x}",
    "{'hi' : x = 42}",
    "{var: x}",
    "{var: x = 42}",
    "{[x] : z}",
    "{[1+1] : z}",
    "{[foo()] : z}",
    "{}",
    "[...rest]",
    "[a,b,...rest]",
    "[a,,...rest]",
    "{ __proto__: x, __proto__: y}",
    "{arguments: x}",
    "{eval: x}",
    "{ x : y, ...z }",
    "{ x : y = 1, ...z }",
    "{ x : x, y : y, ...z }",
    "{ x : x = 1, y : y, ...z }",
    "{ x : x, y : y = 42, ...z }",
    "[{x:x, y:y, ...z}, [a,b,c]]",
    "[{x:x = 1, y:y = 2, ...z}, [a = 3, b = 4, c = 5]]",
    "{...x}",
    "{x, ...y}",
    "{x = 42, y = 15, ...z}",
    "{42 : x = 42, ...y}",
    "{'hi' : x, ...z}",
    "{'hi' : x = 42, ...z}",
    "{var: x = 42, ...z}",
    "{[x] : z, ...y}",
    "{[1+1] : z, ...x}",
    "{arguments: x, ...z}",
    "{ __proto__: x, __proto__: y, ...z}",
    nullptr
  };

  // clang-format on
  RunParserSyncTest(context_data, data, kSuccess);
}

// v8:5201
TEST_F(ParsingTest, SloppyContextDestructuringPositiveTests) {
  // clang-format off
  const char* sloppy_context_data[][2] = {
    {"var ", " = {};"},
    {"function f(", ") {}"},
    {"function f(argument1, ", ") {}"},
    {"var f = (", ") => {};"},
    {"var f = (argument1,", ") => {};"},
    {"try {} catch(", ") {}"},
    {nullptr, nullptr}
  };

  const char* data[] = {
    "{arguments}",
    "{eval}",
    "{x: arguments}",
    "{x: eval}",
    "{arguments = false}",
    "{eval = false}",
    "{...arguments}",
    "{...eval}",
    nullptr
  };
  // clang-format on
  RunParserSyncTest(sloppy_context_data, data, kSuccess);
}

TEST_F(ParsingTest, DestructuringNegativeTests) {
  {  // All modes.
    const char* context_data[][2] = {{"'use strict'; let ", " = {};"},
                                     {"var ", " = {};"},
                                     {"'use strict'; const ", " = {};"},
                                     {"function f(", ") {}"},
                                     {"function f(argument1, ", ") {}"},
                                     {"var f = (", ") => {};"},
                                     {"var f = ", " => {};"},
                                     {"var f = (argument1,", ") => {};"},
                                     {"try {} catch(", ") {}"},
                                     {nullptr, nullptr}};

    // clang-format off
    const char* data[] = {
        "a++",
        "++a",
        "delete a",
        "void a",
        "typeof a",
        "--a",
        "+a",
        "-a",
        "~a",
        "!a",
        "{ x : y++ }",
        "[a++]",
        "(x => y)",
        "(async x => y)",
        "((x, z) => y)",
        "(async (x, z) => y)",
        "a[i]", "a()",
        "a.b",
        "new a",
        "a + a",
        "a - a",
        "a * a",
        "a / a",
        "a == a",
        "a != a",
        "a > a",
        "a < a",
        "a <<< a",
        "a >>> a",
        "function a() {}",
        "function* a() {}",
        "async function a() {}",
        "a`bcd`",
        "this",
        "null",
        "true",
        "false",
        "1",
        "'abc'",
        "/abc/",
        "`abc`",
        "class {}",
        "{+2 : x}",
        "{-2 : x}",
        "var",
        "[var]",
        "{x : {y : var}}",
        "{x : x = a+}",
        "{x : x = (a+)}",
        "{x : x += a}",
        "{m() {} = 0}",
        "{[1+1]}",
        "[...rest, x]",
        "[a,b,...rest, x]",
        "[a,,...rest, x]",
        "[...rest,]",
        "[a,b,...rest,]",
        "[a,,...rest,]",
        "[...rest,...rest1]",
        "[a,b,...rest,...rest1]",
        "[a,,..rest,...rest1]",
        "[x, y, ...z = 1]",
        "[...z = 1]",
        "[x, y, ...[z] = [1]]",
        "[...[z] = [1]]",
        "{ x : 3 }",
        "{ x : 'foo' }",
        "{ x : /foo/ }",
        "{ x : `foo` }",
        "{ get a() {} }",
        "{ set a() {} }",
        "{ method() {} }",
        "{ *method() {} }",
        "...a++",
        "...++a",
        "...typeof a",
        "...[a++]",
        "...(x => y)",
        "{ ...x, }",
        "{ ...x, y }",
        "{ y, ...x, y }",
        "{ ...x, ...y }",
        "{ ...x, ...x }",
        "{ ...x, ...x = {} }",
        "{ ...x, ...x = ...x }",
        "{ ...x, ...x = ...{ x } }",
        "{ ,, ...x }",
        "{ ...get a() {} }",
        "{ ...set a() {} }",
        "{ ...method() {} }",
        "{ ...function() {} }",
        "{ ...*method() {} }",
        "{...{x} }",
        "{...[x] }",
        "{...{ x = 5 } }",
        "{...[ x = 5 ] }",
        "{...x.f }",
        "{...x[0] }",
        "async function* a() {}",
        nullptr
    };

    // clang-format on
    RunParserSyncTest(context_data, data, kError);
  }

  {  // All modes.
    const char* context_data[][2] = {
        {"'use strict'; let ", " = {};"},    {"var ", " = {};"},
        {"'use strict'; const ", " = {};"},  {"function f(", ") {}"},
        {"function f(argument1, ", ") {}"},  {"var f = (", ") => {};"},
        {"var f = (argument1,", ") => {};"}, {nullptr, nullptr}};

    // clang-format off
    const char* data[] = {
        "x => x",
        "() => x",
        nullptr};
    // clang-format on
    RunParserSyncTest(context_data, data, kError);
  }

  {  // Strict mode.
    const char* context_data[][2] = {
        {"'use strict'; var ", " = {};"},
        {"'use strict'; let ", " = {};"},
        {"'use strict'; const ", " = {};"},
        {"'use strict'; function f(", ") {}"},
        {"'use strict'; function f(argument1, ", ") {}"},
        {nullptr, nullptr}};

    // clang-format off
    const char* data[] = {
      "[arguments]",
      "[eval]",
      "{ a : arguments }",
      "{ a : eval }",
      "[public]",
      "{ x : private }",
      "{ x : arguments }",
      "{ x : eval }",
      "{ arguments }",
      "{ eval }",
      "{ arguments = false }"
      "{ eval = false }",
      "{ ...eval }",
      "{ ...arguments }",
      nullptr};

    // clang-format on
    RunParserSyncTest(context_data, data, kError);
  }

  {  // 'yield' in generators.
    const char* context_data[][2] = {
        {"function*() { var ", " = {};"},
        {"function*() { 'use strict'; let ", " = {};"},
        {"function*() { 'use strict'; const ", " = {};"},
        {nullptr, nullptr}};

    // clang-format off
    const char* data[] = {
      "yield",
      "[yield]",
      "{ x : yield }",
      nullptr};
    // clang-format on
    RunParserSyncTest(context_data, data, kError);
  }

  {  // Declaration-specific errors
    const char* context_data[][2] = {{"'use strict'; var ", ""},
                                     {"'use strict'; let ", ""},
                                     {"'use strict'; const ", ""},
                                     {"'use strict'; for (var ", ";;) {}"},
                                     {"'use strict'; for (let ", ";;) {}"},
                                     {"'use strict'; for (const ", ";;) {}"},
                                     {"var ", ""},
                                     {"let ", ""},
                                     {"const ", ""},
                                     {"for (var ", ";;) {}"},
                                     {"for (let ", ";;) {}"},
                                     {"for (const ", ";;) {}"},
                                     {nullptr, nullptr}};

    // clang-format off
    const char* data[] = {
      "{ a }",
      "[ a ]",
      "{ ...a }",
      nullptr
    };
    // clang-format on
    RunParserSyncTest(context_data, data, kError);
  }
}

TEST_F(ParsingTest, ObjectRestNegativeTestSlow) {
  // clang-format off
  const char* context_data[][2] = {
    {"var { ", " } = { a: 1};"},
    { nullptr, nullptr }
  };

  using v8::internal::InstructionStream;
  std::string statement;
  for (int i = 0; i < Code::kMaxArguments; ++i) {
    statement += std::to_string(i) + " : " + "x, ";
  }
  statement += "...y";

  const char* statement_data[] = {
    statement.c_str(),
    nullptr
  };

  // clang-format on
  // The test is quite slow, so run it with a reduced set of flags.
  static const ParserFlag flags[] = {kAllowLazy};
  RunParserSyncTest(context_data, statement_data, kError, nullptr, 0, flags,
                    arraysize(flags));
}

TEST_F(ParsingTest, DestructuringAssignmentPositiveTests) {
  const char* context_data[][2] = {
      {"'use strict'; let x, y, z; (", " = {});"},
      {"var x, y, z; (", " = {});"},
      {"'use strict'; let x, y, z; for (x in ", " = {});"},
      {"'use strict'; let x, y, z; for (x of ", " = {});"},
      {"var x, y, z; for (x in ", " = {});"},
      {"var x, y, z; for (x of ", " = {});"},
      {"var x, y, z; for (", " in {});"},
      {"var x, y, z; for (", " of {});"},
      {"'use strict'; var x, y, z; for (", " in {});"},
      {"'use strict'; var x, y, z; for (", " of {});"},
      {"var x, y, z; m(['a']) ? ", " = {} : rhs"},
      {"var x, y, z; m(['b']) ? lhs : ", " = {}"},
      {"'use strict'; var x, y, z; m(['a']) ? ", " = {} : rhs"},
      {"'use strict'; var x, y, z; m(['b']) ? lhs : ", " = {}"},
      {nullptr, nullptr}};

  const char* mixed_assignments_context_data[][2] = {
      {"'use strict'; let x, y, z; (", " = z = {});"},
      {"var x, y, z; (", " = z = {});"},
      {"'use strict'; let x, y, z; (x = ", " = z = {});"},
      {"var x, y, z; (x = ", " = z = {});"},
      {"'use strict'; let x, y, z; for (x in ", " = z = {});"},
      {"'use strict'; let x, y, z; for (x in x = ", " = z = {});"},
      {"'use strict'; let x, y, z; for (x of ", " = z = {});"},
      {"'use strict'; let x, y, z; for (x of x = ", " = z = {});"},
      {"var x, y, z; for (x in ", " = z = {});"},
      {"var x, y, z; for (x in x = ", " = z = {});"},
      {"var x, y, z; for (x of ", " = z = {});"},
      {"var x, y, z; for (x of x = ", " = z = {});"},
      {nullptr, nullptr}};

  // clang-format off
  const char* data[] = {
    "x",

    "{ x : y }",
    "{ x : foo().y }",
    "{ x : foo()[y] }",
    "{ x : y.z }",
    "{ x : y[z] }",
    "{ x : { y } }",
    "{ x : { foo: y } }",
    "{ x : { foo: foo().y } }",
    "{ x : { foo: foo()[y] } }",
    "{ x : { foo: y.z } }",
    "{ x : { foo: y[z] } }",
    "{ x : [ y ] }",
    "{ x : [ foo().y ] }",
    "{ x : [ foo()[y] ] }",
    "{ x : [ y.z ] }",
    "{ x : [ y[z] ] }",

    "{ x : y = 10 }",
    "{ x : foo().y = 10 }",
    "{ x : foo()[y] = 10 }",
    "{ x : y.z = 10 }",
    "{ x : y[z] = 10 }",
    "{ x : { y = 10 } = {} }",
    "{ x : { foo: y = 10 } = {} }",
    "{ x : { foo: foo().y = 10 } = {} }",
    "{ x : { foo: foo()[y] = 10 } = {} }",
    "{ x : { foo: y.z = 10 } = {} }",
    "{ x : { foo: y[z] = 10 } = {} }",
    "{ x : [ y = 10 ] = {} }",
    "{ x : [ foo().y = 10 ] = {} }",
    "{ x : [ foo()[y] = 10 ] = {} }",
    "{ x : [ y.z = 10 ] = {} }",
    "{ x : [ y[z] = 10 ] = {} }",
    "{ z : { __proto__: x, __proto__: y } = z }"

    "[ x ]",
    "[ foo().x ]",
    "[ foo()[x] ]",
    "[ x.y ]",
    "[ x[y] ]",
    "[ { x } ]",
    "[ { x : y } ]",
    "[ { x : foo().y } ]",
    "[ { x : foo()[y] } ]",
    "[ { x : x.y } ]",
    "[ { x : x[y] } ]",
    "[ [ x ] ]",
    "[ [ foo().x ] ]",
    "[ [ foo()[x] ] ]",
    "[ [ x.y ] ]",
    "[ [ x[y] ] ]",

    "[ x = 10 ]",
    "[ foo().x = 10 ]",
    "[ foo()[x] = 10 ]",
    "[ x.y = 10 ]",
    "[ x[y] = 10 ]",
    "[ { x = 10 } = {} ]",
    "[ { x : y = 10 } = {} ]",
    "[ { x : foo().y = 10 } = {} ]",
    "[ { x : foo()[y] = 10 } = {} ]",
    "[ { x : x.y = 10 } = {} ]",
    "[ { x : x[y] = 10 } = {} ]",
    "[ [ x = 10 ] = {} ]",
    "[ [ foo().x = 10 ] = {} ]",
    "[ [ foo()[x] = 10 ] = {} ]",
    "[ [ x.y = 10 ] = {} ]",
    "[ [ x[y] = 10 ] = {} ]",
    "{ x : y = 1 }",
    "{ x }",
    "{ x, y, z }",
    "{ x = 1, y: z, z: y }",
    "{x = 42, y = 15}",
    "[x]",
    "[x = 1]",
    "[x,y,z]",
    "[x, y = 42, z]",
    "{ x : x, y : y }",
    "{ x : x = 1, y : y }",
    "{ x : x, y : y = 42 }",
    "[]",
    "{}",
    "[{x:x, y:y}, [,x,z,]]",
    "[{x:x = 1, y:y = 2}, [z = 3, z = 4, z = 5]]",
    "[x,,y]",
    "[(x),,(y)]",
    "[(x)]",
    "{42 : x}",
    "{42 : x = 42}",
    "{42e-2 : x}",
    "{42e-2 : x = 42}",
    "{'hi' : x}",
    "{'hi' : x = 42}",
    "{var: x}",
    "{var: x = 42}",
    "{var: (x) = 42}",
    "{[x] : z}",
    "{[1+1] : z}",
    "{[1+1] : (z)}",
    "{[foo()] : z}",
    "{[foo()] : (z)}",
    "{[foo()] : foo().bar}",
    "{[foo()] : foo()['bar']}",
    "{[foo()] : this.bar}",
    "{[foo()] : this['bar']}",
    "{[foo()] : 'foo'.bar}",
    "{[foo()] : 'foo'['bar']}",
    "[...x]",
    "[x,y,...z]",
    "[x,,...z]",
    "{ x: y }",
    "[x, y]",
    "[((x, y) => z).x]",
    "{x: ((y, z) => z).x}",
    "[((x, y) => z)['x']]",
    "{x: ((y, z) => z)['x']}",

    "{x: { y = 10 } }",
    "[(({ x } = { x: 1 }) => x).a]",

    "{ ...d.x }",
    "{ ...c[0]}",

    // v8:4662
    "{ x: (y) }",
    "{ x: (y) = [] }",
    "{ x: (foo.bar) }",
    "{ x: (foo['bar']) }",
    "[ ...(a) ]",
    "[ ...(foo['bar']) ]",
    "[ ...(foo.bar) ]",
    "[ (y) ]",
    "[ (foo.bar) ]",
    "[ (foo['bar']) ]",

    nullptr};
  // clang-format on
  RunParserSyncTest(context_data, data, kSuccess);

  RunParserSyncTest(mixed_assignments_context_data, data, kSuccess);

  const char* empty_context_data[][2] = {
      {"'use strict';", ""}, {"", ""}, {nullptr, nullptr}};

  // CoverInitializedName ambiguity handling in various contexts
  const char* ambiguity_data[] = {
      "var foo = { x = 10 } = {};",
      "var foo = { q } = { x = 10 } = {};",
      "var foo; foo = { x = 10 } = {};",
      "var foo; foo = { q } = { x = 10 } = {};",
      "var x; ({ x = 10 } = {});",
      "var q, x; ({ q } = { x = 10 } = {});",
      "var x; [{ x = 10 } = {}]",
      "var x; (true ? { x = true } = {} : { x = false } = {})",
      "var q, x; (q, { x = 10 } = {});",
      "var { x = 10 } = { x = 20 } = {};",
      "var { __proto__: x, __proto__: y } = {}",
      "({ __proto__: x, __proto__: y } = {})",
      "var { x = 10 } = (o = { x = 20 } = {});",
      "var x; (({ x = 10 } = { x = 20 } = {}) => x)({})",
      nullptr,
  };
  RunParserSyncTest(empty_context_data, ambiguity_data, kSuccess);
}

TEST_F(ParsingTest, DestructuringAssignmentNegativeTests) {
  const char* context_data[][2] = {
      {"'use strict'; let x, y, z; (", " = {});"},
      {"var x, y, z; (", " = {});"},
      {"'use strict'; let x, y, z; for (x in ", " = {});"},
      {"'use strict'; let x, y, z; for (x of ", " = {});"},
      {"var x, y, z; for (x in ", " = {});"},
      {"var x, y, z; for (x of ", " = {});"},
      {nullptr, nullptr}};

  // clang-format off
  const char* data[] = {
    "{ x : ++y }",
    "{ x : y * 2 }",
    "{ get x() {} }",
    "{ set x() {} }",
    "{ x: y() }",
    "{ this }",
    "{ x: this }",
    "{ x: this = 1 }",
    "{ super }",
    "{ x: super }",
    "{ x: super = 1 }",
    "{ new.target }",
    "{ x: new.target }",
    "{ x: new.target = 1 }",
    "{ import.meta }",
    "{ x: import.meta }",
    "{ x: import.meta = 1 }",
    "[x--]",
    "[--x = 1]",
    "[x()]",
    "[this]",
    "[this = 1]",
    "[new.target]",
    "[new.target = 1]",
    "[import.meta]",
    "[import.meta = 1]",
    "[super]",
    "[super = 1]",
    "[function f() {}]",
    "[async function f() {}]",
    "[function* f() {}]",
    "[50]",
    "[(50)]",
    "[(function() {})]",
    "[(async function() {})]",
    "[(function*() {})]",
    "[(foo())]",
    "{ x: 50 }",
    "{ x: (50) }",
    "['str']",
    "{ x: 'str' }",
    "{ x: ('str') }",
    "{ x: (foo()) }",
    "{ x: function() {} }",
    "{ x: async function() {} }",
    "{ x: function*() {} }",
    "{ x: (function() {}) }",
    "{ x: (async function() {}) }",
    "{ x: (function*() {}) }",
    "{ x: y } = 'str'",
    "[x, y] = 'str'",
    "[(x,y) => z]",
    "[async(x,y) => z]",
    "[async x => z]",
    "{x: (y) => z}",
    "{x: (y,w) => z}",
    "{x: async (y) => z}",
    "{x: async (y,w) => z}",
    "[x, ...y, z]",
    "[...x,]",
    "[x, y, ...z = 1]",
    "[...z = 1]",
    "[x, y, ...[z] = [1]]",
    "[...[z] = [1]]",

    "[...++x]",
    "[...x--]",
    "[...!x]",
    "[...x + y]",

    // v8:4657
    "({ x: x4, x: (x+=1e4) })",
    "(({ x: x4, x: (x+=1e4) }))",
    "({ x: x4, x: (x+=1e4) } = {})",
    "(({ x: x4, x: (x+=1e4) } = {}))",
    "(({ x: x4, x: (x+=1e4) }) = {})",
    "({ x: y } = {})",
    "(({ x: y } = {}))",
    "(({ x: y }) = {})",
    "([a])",
    "(([a]))",
    "([a] = [])",
    "(([a] = []))",
    "(([a]) = [])",

    // v8:4662
    "{ x: ([y]) }",
    "{ x: ([y] = []) }",
    "{ x: ({y}) }",
    "{ x: ({y} = {}) }",
    "{ x: (++y) }",
    "[ (...[a]) ]",
    "[ ...([a]) ]",
    "[ ...([a] = [])",
    "[ ...[ ( [ a ] ) ] ]",
    "[ ([a]) ]",
    "[ (...[a]) ]",
    "[ ([a] = []) ]",
    "[ (++y) ]",
    "[ ...(++y) ]",

    "[ x += x ]",
    "{ foo: x += x }",

    nullptr};
  // clang-format on
  RunParserSyncTest(context_data, data, kError);

  {
    i::FlagScope<bool> f(&v8_flags.js_source_phase_imports, true);
    // clang-format off
    const char* data[] = {
      "{ import.source }",
      "{ x: import.source }",
      "{ x: import.source = 1 }",
      "[import.source]",
      "[import.source = 1]",
      nullptr};
    // clang-format on
    RunParserSyncTest(context_data, data, kError);
  }

  const char* empty_context_data[][2] = {
      {"'use strict';", ""}, {"", ""}, {nullptr, nullptr}};

  // CoverInitializedName ambiguity handling in various contexts
  const char* ambiguity_data[] = {
      "var foo = { x = 10 };",
      "var foo = { q } = { x = 10 };",
      "var foo; foo = { x = 10 };",
      "var foo; foo = { q } = { x = 10 };",
      "var x; ({ x = 10 });",
      "var q, x; ({ q } = { x = 10 });",
      "var x; [{ x = 10 }]",
      "var x; (true ? { x = true } : { x = false })",
      "var q, x; (q, { x = 10 });",
      "var { x = 10 } = { x = 20 };",
      "var { x = 10 } = (o = { x = 20 });",
      "var x; (({ x = 10 } = { x = 20 }) => x)({})",

      // Not ambiguous, but uses same context data
      "switch([window %= []] = []) { default: }",

      nullptr,
  };
  RunParserSyncTest(empty_context_data, ambiguity_data, kError);

  // Strict mode errors
  const char* strict_context_data[][2] = {{"'use strict'; (", " = {})"},
                                          {"'use strict'; for (", " of {}) {}"},
                                          {"'use strict'; for (", " in {}) {}"},
                                          {nullptr, nullptr}};
  const char* strict_data[] = {
      "{ eval }", "{ arguments }", "{ foo: eval }", "{ foo: arguments }",
      "{ eval = 0 }", "{ arguments = 0 }", "{ foo: eval = 0 }",
      "{ foo: arguments = 0 }", "[ eval ]", "[ arguments ]", "[ eval = 0 ]",
      "[ arguments = 0 ]",

      // v8:4662
      "{ x: (eval) }", "{ x: (arguments) }", "{ x: (eval = 0) }",
      "{ x: (arguments = 0) }", "{ x: (eval) = 0 }", "{ x: (arguments) = 0 }",
      "[ (eval) ]", "[ (arguments) ]", "[ (eval = 0) ]", "[ (arguments = 0) ]",
      "[ (eval) = 0 ]", "[ (arguments) = 0 ]", "[ ...(eval) ]",
      "[ ...(arguments) ]", "[ ...(eval = 0) ]", "[ ...(arguments = 0) ]",
      "[ ...(eval) = 0 ]", "[ ...(arguments) = 0 ]",

      nullptr};
  RunParserSyncTest(strict_context_data, strict_data, kError);
}

TEST_F(ParsingTest, DestructuringDisallowPatternsInForVarIn) {
  const char* context_data[][2] = {
      {"", ""}, {"function f() {", "}"}, {nullptr, nullptr}};
  // clang-format off
  const char* error_data[] = {
    "for (let x = {} in null);",
    "for (let x = {} of null);",
    nullptr};
  // clang-format on
  RunParserSyncTest(context_data, error_data, kError);

  // clang-format off
  const char* success_data[] = {
    "for (var x = {} in null);",
    nullptr};
  // clang-format on
  RunParserSyncTest(context_data, success_data, kSuccess);
}

TEST_F(ParsingTest, DestructuringDuplicateParams) {
  const char* context_data[][2] = {{"'use strict';", ""},
                                   {"function outer() { 'use strict';", "}"},
                                   {nullptr, nullptr}};

  // clang-format off
  const char* error_data[] = {
    "function f(x,x){}",
    "function f(x, {x : x}){}",
    "function f(x, {x}){}",
    "function f({x,x}) {}",
    "function f([x,x]) {}",
    "function f(x, [y,{z:x}]) {}",
    "function f([x,{y:x}]) {}",
    // non-simple parameter list causes duplicates to be errors in sloppy mode.
    "function f(x, x, {a}) {}",
    nullptr};
  // clang-format on
  RunParserSyncTest(context_data, error_data, kError);
}

TEST_F(ParsingTest, DestructuringDuplicateParamsSloppy) {
  const char* context_data[][2] = {
      {"", ""}, {"function outer() {", "}"}, {nullptr, nullptr}};

  // clang-format off
  const char* error_data[] = {
    // non-simple parameter list causes duplicates to be errors in sloppy mode.
    "function f(x, {x : x}){}",
    "function f(x, {x}){}",
    "function f({x,x}) {}",
    "function f(x, x, {a}) {}",
    nullptr};
  // clang-format on
  RunParserSyncTest(context_data, error_data, kError);
}

TEST_F(ParsingTest, DestructuringDisallowPatternsInSingleParamArrows) {
  const char* context_data[][2] = {{"'use strict';", ""},
                                   {"function outer() { 'use strict';", "}"},
                                   {"", ""},
                                   {"function outer() { ", "}"},
                                   {nullptr, nullptr}};

  // clang-format off
  const char* error_data[] = {
    "var f = {x} => {};",
    "var f = {x,y} => {};",
    nullptr};
  // clang-format on
  RunParserSyncTest(context_data, error_data, kError);
}

TEST_F(ParsingTest, DefaultParametersYieldInInitializers) {
  // clang-format off
  const char* sloppy_function_context_data[][2] = {
    {"(function f(", ") { });"},
    {nullptr, nullptr}
  };

  const char* strict_function_context_data[][2] = {
    {"'use strict'; (function f(", ") { });"},
    {nullptr, nullptr}
  };

  const char* sloppy_arrow_context_data[][2] = {
    {"((", ")=>{});"},
    {nullptr, nullptr}
  };

  const char* strict_arrow_context_data[][2] = {
    {"'use strict'; ((", ")=>{});"},
    {nullptr, nullptr}
  };

  const char* generator_context_data[][2] = {
    {"'use strict'; (function *g(", ") { });"},
    {"(function *g(", ") { });"},
    // Arrow function within generator has the same rules.
    {"'use strict'; (function *g() { (", ") => {} });"},
    {"(function *g() { (", ") => {} });"},
    // And similarly for arrow functions in the parameter list.
    {"'use strict'; (function *g(z = (", ") => {}) { });"},
    {"(function *g(z = (", ") => {}) { });"},
    {nullptr, nullptr}
  };

  const char* parameter_data[] = {
    "x=yield",
    "x, y=yield",
    "{x=yield}",
    "[x=yield]",

    "x=(yield)",
    "x, y=(yield)",
    "{x=(yield)}",
    "[x=(yield)]",

    "x=f(yield)",
    "x, y=f(yield)",
    "{x=f(yield)}",
    "[x=f(yield)]",

    "{x}=yield",
    "[x]=yield",

    "{x}=(yield)",
    "[x]=(yield)",

    "{x}=f(yield)",
    "[x]=f(yield)",
    nullptr
  };

  // Because classes are always in strict mode, these are always errors.
  const char* always_error_param_data[] = {
    "x = class extends (yield) { }",
    "x = class extends f(yield) { }",
    "x = class extends (null, yield) { }",
    "x = class extends (a ? null : yield) { }",
    "[x] = [class extends (a ? null : yield) { }]",
    "[x = class extends (a ? null : yield) { }]",
    "[x = class extends (a ? null : yield) { }] = [null]",
    "x = class { [yield]() { } }",
    "x = class { static [yield]() { } }",
    "x = class { [(yield, 1)]() { } }",
    "x = class { [y = (yield, 1)]() { } }",
    nullptr
  };
  // clang-format on

  RunParserSyncTest(sloppy_function_context_data, parameter_data, kSuccess);
  RunParserSyncTest(sloppy_arrow_context_data, parameter_data, kSuccess);

  RunParserSyncTest(strict_function_context_data, parameter_data, kError);
  RunParserSyncTest(strict_arrow_context_data, parameter_data, kError);

  RunParserSyncTest(generator_context_data, parameter_data, kError);
  RunParserSyncTest(generator_context_data, always_error_param_data, kError);
}

TEST_F(ParsingTest, SpreadArray) {
  const char* context_data[][2] = {
      {"'use strict';", ""}, {"", ""}, {nullptr, nullptr}};

  // clang-format off
  const char* data[] = {
    "[...a]",
    "[a, ...b]",
    "[...a,]",
    "[...a, ,]",
    "[, ...a]",
    "[...a, ...b]",
    "[...a, , ...b]",
    "[...[...a]]",
    "[, ...a]",
    "[, , ...a]",
    nullptr};
  // clang-format on
  RunParserSyncTest(context_data, data, kSuccess);
}

TEST_F(ParsingTest, SpreadArrayError) {
  const char* context_data[][2] = {
      {"'use strict';", ""}, {"", ""}, {nullptr, nullptr}};

  // clang-format off
  const char* data[] = {
    "[...]",
    "[a, ...]",
    "[..., ]",
    "[..., ...]",
    "[ (...a)]",
    nullptr};
  // clang-format on
  RunParserSyncTest(context_data, data, kError);
}

TEST_F(ParsingTest, NewTarget) {
  // clang-format off
  const char* good_context_data[][2] = {
    {"function f() {", "}"},
    {"'use strict'; function f() {", "}"},
    {"var f = function() {", "}"},
    {"'use strict'; var f = function() {", "}"},
    {"({m: function() {", "}})"},
    {"'use strict'; ({m: function() {", "}})"},
    {"({m() {", "}})"},
    {"'use strict'; ({m() {", "}})"},
    {"({get x() {", "}})"},
    {"'use strict'; ({get x() {", "}})"},
    {"({set x(_) {", "}})"},
    {"'use strict'; ({set x(_) {", "}})"},
    {"class C {m() {", "}}"},
    {"class C {get x() {", "}}"},
    {"class C {set x(_) {", "}}"},
    {nullptr}
  };

  const char* bad_context_data[][2] = {
    {"", ""},
    {"'use strict';", ""},
    {nullptr}
  };

  const char* data[] = {
    "new.target",
    "{ new.target }",
    "() => { new.target }",
    "() => new.target",
    "if (1) { new.target }",
    "if (1) {} else { new.target }",
    "while (0) { new.target }",
    "do { new.target } while (0)",
    nullptr
  };

  // clang-format on

  RunParserSyncTest(good_context_data, data, kSuccess);
  RunParserSyncTest(bad_context_data, data, kError);
}

TEST_F(ParsingTest, ImportMetaSuccess) {
  // clang-format off
  const char* context_data[][2] = {
    {"", ""},
    {"'use strict';", ""},
    {"function f() {", "}"},
    {"'use strict'; function f() {", "}"},
    {"var f = function() {", "}"},
    {"'use strict'; var f = function() {", "}"},
    {"({m: function() {", "}})"},
    {"'use strict'; ({m: function() {", "}})"},
    {"({m() {", "}})"},
    {"'use strict'; ({m() {", "}})"},
    {"({get x() {", "}})"},
    {"'use strict'; ({get x() {", "}})"},
    {"({set x(_) {", "}})"},
    {"'use strict'; ({set x(_) {", "}})"},
    {"class C {m() {", "}}"},
    {"class C {get x() {", "}}"},
    {"class C {set x(_) {", "}}"},
    {nullptr}
  };

  const char* data[] = {
    "import.meta",
    "() => { import.meta }",
    "() => import.meta",
    "if (1) { import.meta }",
    "if (1) {} else { import.meta }",
    "while (0) { import.meta }",
    "do { import.meta } while (0)",
    "import.meta.url",
    "import.meta[0]",
    "import.meta.couldBeMutable = true",
    "import.meta()",
    "new import.meta.MagicClass",
    "new import.meta",
    "t = [...import.meta]",
    "f = {...import.meta}",
    "delete import.meta",
    nullptr
  };

  // clang-format on

  // 2.1.1 Static Semantics: Early Errors
  // ImportMeta
  // * It is an early Syntax Error if Module is not the syntactic goal symbol.
  RunParserSyncTest(context_data, data, kError);

  RunModuleParserSyncTest(context_data, data, kSuccess);
}

TEST_F(ParsingTest, ImportMetaFailure) {
  // clang-format off
  const char* context_data[][2] = {
    {"var ", ""},
    {"let ", ""},
    {"const ", ""},
    {"var [", "] = [1]"},
    {"([", "] = [1])"},
    {"({", "} = {1})"},
    {"var {", " = 1} = 1"},
    {"for (var ", " of [1]) {}"},
    {"(", ") => {}"},
    {"let f = ", " => {}"},
    {nullptr}
  };

  const char* data[] = {
    "import.meta",
    nullptr
  };

  // clang-format on

  RunParserSyncTest(context_data, data, kError);
  RunModuleParserSyncTest(context_data, data, kError);
}

TEST_F(ParsingTest, ImportSourceSuccess) {
  i::FlagScope<bool> f(&v8_flags.js_source_phase_imports, true);
  // clang-format off
  const char* context_data[][2] = {
    {"", ""},
    {"'use strict';", ""},
    {nullptr}
  };

  const char* data[] = {
    // Basic import declarations, not a source phase import
    "import source from ''",
    "import from from ''",
    // Source phase imports
    "import source source from ''",
    "import source from from ''",
    "import source x from ''",
    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, data, kError);
  // Skip preparser
  RunModuleParserSyncTest(context_data, data, kSuccess, nullptr, 0, nullptr, 0,
                          nullptr, 0, false);
}

TEST_F(ParsingTest, ImportSourceFailure) {
  i::FlagScope<bool> f(&v8_flags.js_source_phase_imports, true);
  // clang-format off
  const char* context_data[][2] = {
    {"", ""},
    {"'use strict';", ""},
    {"function f() {", "}"},
    {"'use strict'; function f() {", "}"},
    {"var f = function() {", "}"},
    {"'use strict'; var f = function() {", "}"},
    {"({m: function() {", "}})"},
    {"'use strict'; ({m: function() {", "}})"},
    {"({m() {", "}})"},
    {"'use strict'; ({m() {", "}})"},
    {"({get x() {", "}})"},
    {"'use strict'; ({get x() {", "}})"},
    {"({set x(_) {", "}})"},
    {"'use strict'; ({set x(_) {", "}})"},
    {"class C {m() {", "}}"},
    {"class C {get x() {", "}}"},
    {"class C {set x(_) {", "}}"},
    {nullptr}
  };

  const char* data[] = {
    "import source source source from ''",
    "import source from from from ''",
    "import source default from ''",
    "import source * from from ''",
    "import * source from from ''",
    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, data, kError);
  RunModuleParserSyncTest(context_data, data, kError);
}

TEST_F(ParsingTest, ImportSourceAttributesNotAllowed) {
  i::FlagScope<bool> f_js_source_phase_imports(
      &v8_flags.js_source_phase_imports, true);
  i::FlagScope<bool> f_harmony_import_attributes(
      &v8_flags.harmony_import_attributes, true);
  // clang-format off
  const char* context_data[][2] = {
    {"", ""},
    {"'use strict';", ""},
    {nullptr}
  };

  const char* data[] = {
    "import source x from '' with {}",
    "import source x from '' assert {}",
    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, data, kError);
  RunModuleParserSyncTest(context_data, data, kError);
}

TEST_F(ParsingTest, ImportCallSourceSuccess) {
  i::FlagScope<bool> f(&v8_flags.js_source_phase_imports, true);
  // clang-format off
  const char* context_data[][2] = {
    {"", ""},
    {"'use strict';", ""},
    {"function f() {", "}"},
    {"'use strict'; function f() {", "}"},
    {"var f = function() {", "}"},
    {"'use strict'; var f = function() {", "}"},
    {"({m: function() {", "}})"},
    {"'use strict'; ({m: function() {", "}})"},
    {"({m() {", "}})"},
    {"'use strict'; ({m() {", "}})"},
    {"({get x() {", "}})"},
    {"'use strict'; ({get x() {", "}})"},
    {"({set x(_) {", "}})"},
    {"'use strict'; ({set x(_) {", "}})"},
    {"class C {m() {", "}}"},
    {"class C {get x() {", "}}"},
    {"class C {set x(_) {", "}}"},
    {nullptr}
  };

  const char* data[] = {
    "import.source('')",
    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, data, kSuccess);
  RunModuleParserSyncTest(context_data, data, kSuccess);
}

TEST_F(ParsingTest, ImportCallSourceFailure) {
  i::FlagScope<bool> f(&v8_flags.js_source_phase_imports, true);
  // clang-format off
  const char* context_data[][2] = {
    {"", ""},
    {"var ", ""},
    {"let ", ""},
    {"const ", ""},
    {"var [", "] = [1]"},
    {"([", "] = [1])"},
    {"({", "} = {1})"},
    {"var {", " = 1} = 1"},
    {"for (var ", " of [1]) {}"},
    {"(", ") => {}"},
    {"let f = ", " => {}"},
    {nullptr}
  };

  const char* data[] = {
    "import.source",
    "import.source.url",
    "import.source[0]",
    "import.source.couldBeMutable = true",
    "import.source()",
    "new import.source.MagicClass",
    "new import.source",
    "t = [...import.source]",
    "f = {...import.source}",
    "delete import.source",
    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, data, kError);
  RunModuleParserSyncTest(context_data, data, kError);
}

TEST_F(ParsingTest, ImportCallSourceAttributesNotAllowed) {
  i::FlagScope<bool> f_js_source_phase_imports(
      &v8_flags.js_source_phase_imports, true);
  i::FlagScope<bool> f_harmony_import_attributes(
      &v8_flags.harmony_import_attributes, true);

  // clang-format off
  const char* context_data[][2] = {
    {"", ""},
    {"'use strict';", ""},
    {"function f() {", "}"},
    {"'use strict'; function f() {", "}"},
    {"var f = function() {", "}"},
    {"'use strict'; var f = function() {", "}"},
    {"({m: function() {", "}})"},
    {"'use strict'; ({m: function() {", "}})"},
    {"({m() {", "}})"},
    {"'use strict'; ({m() {", "}})"},
    {"({get x() {", "}})"},
    {"'use strict'; ({get x() {", "}})"},
    {"({set x(_) {", "}})"},
    {"'use strict'; ({set x(_) {", "}})"},
    {"class C {m() {", "}}"},
    {"class C {get x() {", "}}"},
    {"class C {set x(_) {", "}}"},
    {nullptr}
  };

  const char* data[] = {
    "import.source('', )",
    "import.source('', {})",
    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, data, kError);
  RunModuleParserSyncTest(context_data, data, kError);
}

TEST_F(ParsingTest, ConstSloppy) {
  // clang-format off
  const char* context_data[][2] = {
    {"", ""},
    {"{", "}"},
    {nullptr, nullptr}
  };

  const char* data[] = {
    "const x = 1",
    "for (const x = 1; x < 1; x++) {}",
    "for (const x in {}) {}",
    "for (const x of []) {}",
    nullptr
  };
  // clang-format on
  RunParserSyncTest(context_data, data, kSuccess);
}

TEST_F(ParsingTest, LetSloppy) {
  // clang-format off
  const char* context_data[][2] = {
    {"", ""},
    {"'use strict';", ""},
    {"{", "}"},
    {nullptr, nullptr}
  };

  const char* data[] = {
    "let x",
    "let x = 1",
    "for (let x = 1; x < 1; x++) {}",
    "for (let x in {}) {}",
    "for (let x of []) {}",
    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, data, kSuccess);
}

TEST_F(ParsingTest, LanguageModeDirectivesNonSimpleParameterListErrors) {
  // TC39 deemed "use strict" directives to be an error when occurring in the
  // body of a function with non-simple parameter list, on 29/7/2015.
  // https://goo.gl/ueA7Ln
  const char* context_data[][2] = {
      {"function f(", ") { 'use strict'; }"},
      {"function* g(", ") { 'use strict'; }"},
      {"class c { foo(", ") { 'use strict' }"},
      {"var a = (", ") => { 'use strict'; }"},
      {"var o = { m(", ") { 'use strict'; }"},
      {"var o = { *gm(", ") { 'use strict'; }"},
      {"var c = { m(", ") { 'use strict'; }"},
      {"var c = { *gm(", ") { 'use strict'; }"},

      {"'use strict'; function f(", ") { 'use strict'; }"},
      {"'use strict'; function* g(", ") { 'use strict'; }"},
      {"'use strict'; class c { foo(", ") { 'use strict' }"},
      {"'use strict'; var a = (", ") => { 'use strict'; }"},
      {"'use strict'; var o = { m(", ") { 'use strict'; }"},
      {"'use strict'; var o = { *gm(", ") { 'use strict'; }"},
      {"'use strict'; var c = { m(", ") { 'use strict'; }"},
      {"'use strict'; var c = { *gm(", ") { 'use strict'; }"},

      {nullptr, nullptr}};

  const char* data[] = {
      // TODO(@caitp): support formal parameter initializers
      "{}",
      "[]",
      "[{}]",
      "{a}",
      "a, {b}",
      "a, b, {c, d, e}",
      "initializer = true",
      "a, b, c = 1",
      "...args",
      "a, b, ...rest",
      "[a, b, ...rest]",
      "{ bindingPattern = {} }",
      "{ initializedBindingPattern } = { initializedBindingPattern: true }",
      nullptr};

  RunParserSyncTest(context_data, data, kError);
}

TEST_F(ParsingTest, LetSloppyOnly) {
  // clang-format off
  const char* context_data[][2] = {
    {"", ""},
    {"{", "}"},
    {"(function() {", "})()"},
    {nullptr, nullptr}
  };

  const char* data[] = {
    "let",
    "let = 1",
    "for (let = 1; let < 1; let++) {}",
    "for (let in {}) {}",
    "for (var let = 1; let < 1; let++) {}",
    "for (var let in {}) {}",
    "for (var [let] = 1; let < 1; let++) {}",
    "for (var [let] in {}) {}",
    "var let",
    "var [let] = []",
    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, data, kSuccess);

  // Some things should be rejected even in sloppy mode
  // This addresses BUG(v8:4403).

  // clang-format off
  const char* fail_data[] = {
    "let let = 1",
    "for (let let = 1; let < 1; let++) {}",
    "for (let let in {}) {}",
    "for (let let of []) {}",
    "const let = 1",
    "for (const let = 1; let < 1; let++) {}",
    "for (const let in {}) {}",
    "for (const let of []) {}",
    "let [let] = 1",
    "for (let [let] = 1; let < 1; let++) {}",
    "for (let [let] in {}) {}",
    "for (let [let] of []) {}",
    "const [let] = 1",
    "for (const [let] = 1; let < 1; let++) {}",
    "for (const [let] in {}) {}",
    "for (const [let] of []) {}",

    // Sprinkle in the escaped version too.
    "let l\\u0065t = 1",
    "const l\\u0065t = 1",
    "let [l\\u0065t] = 1",
    "const [l\\u0065t] = 1",
    "for (let l\\u0065t in {}) {}",
    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, fail_data, kError);
}

TEST_F(ParsingTest, EscapedKeywords) {
  // clang-format off
  const char* sloppy_context_data[][2] = {
    {"", ""},
    {nullptr, nullptr}
  };

  const char* strict_context_data[][2] = {
    {"'use strict';", ""},
    {nullptr, nullptr}
  };

  const char* fail_data[] = {
    "for (var i = 0; i < 100; ++i) { br\\u0065ak; }",
    "cl\\u0061ss Foo {}",
    "var x = cl\\u0061ss {}",
    "\\u0063onst foo = 1;",
    "while (i < 10) { if (i++ & 1) c\\u006fntinue; this.x++; }",
    "d\\u0065bugger;",
    "d\\u0065lete this.a;",
    "\\u0063o { } while(0)",
    "if (d\\u006f { true }) {}",
    "if (false) { this.a = 1; } \\u0065lse { this.b = 1; }",
    "e\\u0078port var foo;",
    "try { } catch (e) {} f\\u0069nally { }",
    "f\\u006fr (var i = 0; i < 10; ++i);",
    "f\\u0075nction fn() {}",
    "var f = f\\u0075nction() {}",
    "\\u0069f (true) { }",
    "\\u0069mport blah from './foo.js';",
    "n\\u0065w function f() {}",
    "(function() { r\\u0065turn; })()",
    "class C
```