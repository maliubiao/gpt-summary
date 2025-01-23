Response:
The user wants a summary of the functionality of the C++ source code file `v8/test/unittests/parser/parsing-unittest.cc`.

Here's a breakdown of how to address the request:

1. **Identify the core purpose:** The filename strongly suggests this file contains unit tests for the V8 JavaScript parser.

2. **Examine the test structure:**  Look for patterns in the `TEST_F` macros. These indicate individual test cases. Notice the use of `RunParserSyncTest`.

3. **Analyze the test case categories:** Group the tests based on the topics they cover. Keywords like "ObjectRestNegativeTest", "DestructuringAssignmentPositiveTests", "DestructuringAssignmentNegativeTests", "SpreadArray", "NewTarget", "ImportMeta", "ConstSloppy", "LetSloppy", etc., reveal specific JavaScript language features being tested.

4. **Address specific instructions:**
    * **".tq" extension:** Explain that this file is C++ and not Torque.
    * **Relation to JavaScript:**  Provide JavaScript examples corresponding to the tested features (destructuring, spread syntax, `new.target`, `import.meta`, etc.).
    * **Code logic inference:** For tests involving parsing errors (negative tests), formulate a hypothesis about the expected input and output (an error).
    * **Common programming errors:** Relate the negative tests to common mistakes developers might make (e.g., invalid destructuring patterns, using `eval` or `arguments` as identifiers in strict mode).
    * **归纳一下它的功能 (Summarize its functionality):**  Provide a concise overall summary of the file's purpose.

5. **Iterate and refine:** Go through each code block provided in the prompt and categorize the tests. Pay attention to the context data and the expected outcome (`kSuccess` or `kError`).

6. **Structure the response:** Organize the information logically, addressing each point in the user's request. Start with the basic functionality, then delve into specifics, and finally provide a concluding summary.
```cpp
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
      "[ (eval) ]", "[ (arguments) ]", "[ (eval = 0) ]", "[ (arguments) = 0 ]",
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
    {"'
### 提示词
```
这是目录为v8/test/unittests/parser/parsing-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/parser/parsing-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第12部分，共15部分，请归纳一下它的功能
```

### 源代码
```cpp
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