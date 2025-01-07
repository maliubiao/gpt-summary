Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/test/unittests/parser/parsing-unittest.cc`. The snippet contains several test cases within the `ParsingTest` fixture.

Here's a breakdown of how to analyze the code and generate the response:

1. **Identify the core purpose:** The filename `parsing-unittest.cc` strongly suggests that this file contains unit tests for the V8 parser. The `TEST_F(ParsingTest, ...)` macros confirm this.

2. **Examine individual test cases:**  Each `TEST_F` block represents a specific test. Analyze what each test is checking.

3. **Look for patterns and common themes:**  Many tests involve parsing specific JavaScript syntax and verifying the parser's behavior. Keywords like "ModuleParsing," "ImportAttributes," "DuplicateProto," "DeclarationsError," "LanguageMode," "PropertyName," "DuplicateParameters," "ArrowFunction," "ObjectSpread," "TemplateEscapes," and "Destructuring" point to the specific language features being tested.

4. **Relate to JavaScript functionality:** For each test, understand the corresponding JavaScript feature and how the parser should handle it.

5. **Consider the specific checks within each test:**  The `CHECK_EQ`, `CHECK`, `CHECK_NOT_NULL`, and `UNREACHABLE` macros are used for assertions. These tell us what conditions are being verified.

6. **Address the specific instructions:**
    * **Functionality listing:**  List the identified JavaScript features being tested.
    * **`.tq` check:**  Confirm it's not a Torque file based on the extension.
    * **JavaScript examples:** Provide simple JavaScript code demonstrating the features being tested.
    * **Logic inference:**  For tests involving parsing and specific outcomes, describe the input and expected output.
    * **Common programming errors:** Identify potential errors that the parser tests might be preventing or detecting.
    * **Part number:** Acknowledge the part number.
    * **Overall summarization:**  Provide a concise summary of the file's purpose.

**Pre-computation/Analysis of the Snippet:**

* **`ModuleParsingModuleRequestOrdering`:** Tests the order in which module import requests are parsed and stored, especially when import attributes are present. It also checks the sorting of attributes.
* **`ModuleParsingImportAttributesKeySorting`:**  Specifically tests the sorting of keys within import attributes. It considers different string encodings (one-byte vs. two-byte).
* **`DuplicateProtoError` and `DuplicateProtoNoError`:**  Test the parser's handling of duplicate `__proto__` properties in object literals in strict mode. It verifies that some forms are errors, while others are not.
* **`DeclarationsError`:** Tests that certain declarations (like `let`, `const`, `class`) are not allowed in specific statement positions (e.g., after `if`, `while`, `for`).
* **`LanguageModeDirectives`:** Checks that the parser correctly identifies and sets the language mode (strict or sloppy) based on "use strict" directives.
* **`PropertyNameEvalArguments`:** Tests that using `eval` or `arguments` as property names is allowed in non-strict mode but might have restrictions in strict mode (though this test seems to allow it).
* **`FunctionLiteralDuplicateParameters`:** Checks that duplicate parameter names in function declarations are errors in strict mode but allowed in sloppy mode.
* **`ArrowFunctionASIErrors`:**  Tests that automatic semicolon insertion (ASI) does *not* happen in certain cases involving arrow functions, leading to syntax errors.
* **`ObjectSpreadPositiveTests` and `ObjectSpreadNegativeTests`:** Test valid and invalid uses of the object spread syntax (`...`).
* **`TemplateEscapesPositiveTests` and `TemplateEscapesNegativeTests`:**  Test valid and invalid escape sequences within template literals, distinguishing between tagged templates and regular template literals.
* **`DestructuringPositiveTests` and `DestructuringNegativeTests`:** Test valid and invalid syntax for destructuring assignments and declarations.
* **`SloppyContextDestructuringPositiveTests`:** Specifically tests destructuring in sloppy mode involving `arguments` and `eval`.

**Drafting the response (incorporating the analysis):** The process would involve structuring the answer based on the user's requests, explaining each test's purpose, providing illustrative JavaScript examples, and highlighting potential errors.```cpp
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
    
Prompt: 
```
这是目录为v8/test/unittests/parser/parsing-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/parser/parsing-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第11部分，共15部分，请归纳一下它的功能

"""

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

"""


```