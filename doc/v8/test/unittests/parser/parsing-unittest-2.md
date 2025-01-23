Response: The user wants a summary of the C++ source code file `v8/test/unittests/parser/parsing-unittest.cc`, specifically the third part of the file. They also want to know if it's related to JavaScript and see an example if it is.

The code contains a series of C++ unit tests for the V8 JavaScript engine's parser. These tests verify the parser's behavior for various JavaScript syntax, especially focusing on:

1. **`MaybeAssigned` analysis**:  This likely refers to determining if a variable might be assigned a value during execution. This is important for optimization and error detection.
2. **Control flow statements**:  The tests cover `for`, `while`, and `do-while` loops, and how variable assignments within these loops affect the `MaybeAssigned` status.
3. **Arrow functions**:  The tests check the parsing of both valid and invalid arrow function syntax, including parameter lists and bodies.
4. **`super` keyword**:  The tests validate the correct usage of the `super` keyword within classes.
5. **`import()` expressions**:  The tests cover the parsing of dynamic `import()` expressions, including variations with options.
6. **Import Attributes (`with`)**:  The tests verify the parsing of import statements with `with` clauses, a feature for specifying module attributes.
7. **Use Counters**: Tests related to tracking the usage of JavaScript features like strict mode and asm.js.
8. **Line Terminators**: Tests for how the parser handles specific Unicode line separator characters.

The code directly interacts with the V8 parsing infrastructure to perform these tests. It creates `ParseInfo` objects, compiles JavaScript code snippets, and checks the resulting Abstract Syntax Tree (AST) and scope information.

**Relation to JavaScript and Examples:**

The entire file is dedicated to testing the parsing of JavaScript code. The C++ code constructs JavaScript code snippets as strings and then uses V8's internal APIs to parse them.

Here are some examples based on the tests in the provided code:

**`MaybeAssigned`:**

```javascript
function test() {
  let x;
  if (someCondition) {
    x = 5;
  }
  console.log(x); // V8's parser needs to know if 'x' might be unassigned here.
}

function loopTest() {
  let y;
  for (let i = 0; i < 10; i++) {
    y = i;
  }
  console.log(y); // 'y' is definitely assigned here.

  let z;
  for (let j of [1, 2, 3]) {
    z = j;
  }
  console.log(z); // 'z' is definitely assigned here.
}
```

**Arrow Functions:**

```javascript
// Valid arrow functions
const add = (a, b) => a + b;
const square = x => x * x;
const greet = () => console.log("Hello");

// Invalid arrow functions (examples from the test)
// () =>  // Missing body
// => 0   // Missing parameter list
// (a,) => {} // Trailing comma in parameter list
```

**`super` keyword:**

```javascript
class Parent {
  constructor(name) {
    this.name = name;
  }
  greet() {
    console.log(`Hello, I am ${this.name}`);
  }
}

class Child extends Parent {
  constructor(name, age) {
    super(name); // Calling the parent class's constructor
    this.age = age;
  }
  introduce() {
    super.greet(); // Calling the parent class's method
    console.log(`I am also ${this.age} years old.`);
  }
}
```

**`import()` expressions:**

```javascript
async function loadModule() {
  const module = await import('./my-module.js');
  module.doSomething();
}

// With options (this is a newer feature)
// async function loadModuleWithOptions() {
//   const module = await import('./my-module.json', { with: { type: "json" } });
//   console.log(module);
// }
```

**Import Attributes (`with`):**

```javascript
// This is a proposal and might not be supported in all environments yet.
// import data from './data.json' with { type: 'json' };
// console.log(data);
```
这是 `v8/test/unittests/parser/parsing-unittest.cc` 文件的一部分，主要包含了一系列的 C++ 单元测试，用于测试 V8 JavaScript 引擎的 **解析器 (parser)** 的功能。 这部分测试着重于以下几个方面：

1. **`MaybeAssigned` 分析**: 这部分测试验证了解析器在处理变量赋值时，能否正确地分析出变量是否可能被赋值。这对于代码优化和静态分析非常重要。测试用例涵盖了函数参数、循环语句内部的变量赋值等场景。

2. **`MaybeAssignedParameters` 测试**: 这部分专门测试了函数参数是否可能被赋值的情况。例如，在函数体内直接给参数赋值，或者通过 `eval`、`arguments` 对象等间接方式修改参数的值。

3. **`MaybeAssignedInsideLoop` 测试**:  这部分测试了在不同类型的循环（`for`、`for...of`、`for...in`、`while`、`do...while`）中，变量是否可能被赋值的情况。它涵盖了各种变量声明方式 (`var`, `let`, `const`) 和赋值操作。

**与 JavaScript 的关系以及 JavaScript 示例:**

这个 C++ 文件是 V8 引擎的一部分，V8 是 Google Chrome 和 Node.js 使用的 JavaScript 引擎。 因此，这个文件中的单元测试直接关系到 **JavaScript 语言的语法解析**。

**`MaybeAssigned` 的 JavaScript 例子:**

```javascript
function testMaybeAssigned(condition) {
  let x;
  if (condition) {
    x = 10;
  }
  console.log(x); // 在这里，x 可能被赋值，也可能没有被赋值
}

function testDefinitelyAssigned() {
  let y = 20;
  console.log(y); // 在这里，y 肯定被赋值了
}

function testLoopAssignment() {
  let z;
  for (let i = 0; i < 5; i++) {
    z = i;
  }
  console.log(z); // 在循环结束后，z 肯定被赋值了
}
```

**`MaybeAssignedParameters` 的 JavaScript 例子:**

```javascript
function testParameterAssignment(arg) {
  console.log(arg);
  arg = 5; // 直接给参数赋值
  console.log(arg);
}

function testArgumentsAssignment(arg) {
  console.log(arg);
  arguments[0] = 10; // 通过 arguments 对象修改参数
  console.log(arg);
}

function testEvalAssignment(arg) {
  console.log(arg);
  eval('arg = 15;'); // 通过 eval 修改参数
  console.log(arg);
}
```

**`MaybeAssignedInsideLoop` 的 JavaScript 例子:**

```javascript
function testForLoop(arr) {
  let value;
  for (let i = 0; i < arr.length; i++) {
    value = arr[i];
    console.log(value);
  }
}

function testForOfLoop(arr) {
  let item;
  for (const item of arr) {
    console.log(item);
  }
}

function testForInLoop(obj) {
  let key;
  for (const key in obj) {
    console.log(key, obj[key]);
  }
}

function testWhileLoop(count) {
  let counter = 0;
  while (counter < count) {
    console.log(counter);
    counter++;
  }
}

function testDoWhileLoop(count) {
  let counter = 0;
  do {
    console.log(counter);
    counter++;
  } while (counter < count);
}
```

总而言之，这部分 C++ 代码是 V8 引擎解析器功能的核心测试，确保了引擎能够正确理解和处理各种复杂的 JavaScript 语法，尤其是在变量赋值和控制流方面。 这些测试直接影响了 JavaScript 代码在 V8 引擎中的执行方式和性能。

### 提示词
```
这是目录为v8/test/unittests/parser/parsing-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共8部分，请归纳一下它的功能
```

### 源代码
```
eval(''); }", true, false, false},
      {"function x() { eval(''); }", true, false, false},
      {"(function(x) { eval(''); })", true, false, false},
  };

  int prefix_len = Utf8LengthHelper(prefix);
  int midfix_len = Utf8LengthHelper(midfix);
  int suffix_len = Utf8LengthHelper(suffix);
  for (unsigned i = 0; i < arraysize(outers); ++i) {
    const char* outer = outers[i].source;
    int outer_len = Utf8LengthHelper(outer);
    for (unsigned j = 0; j < arraysize(inners); ++j) {
      for (unsigned lazy = 0; lazy < 2; ++lazy) {
        if (outers[i].strict && inners[j].with) continue;
        const char* inner = inners[j].source;
        int inner_len = Utf8LengthHelper(inner);

        int len = prefix_len + outer_len + midfix_len + inner_len + suffix_len;
        base::ScopedVector<char> program(len + 1);

        base::SNPrintF(program, "%s%s%s%s%s", prefix, outer, midfix, inner,
                       suffix);

        UnoptimizedCompileState compile_state;
        ReusableUnoptimizedCompileState reusable_state(isolate);
        std::unique_ptr<i::ParseInfo> info;
        if (lazy) {
          printf("%s\n", program.begin());
          v8::Local<v8::Value> v = RunJS(program.begin());
          i::DirectHandle<i::Object> o = v8::Utils::OpenDirectHandle(*v);
          i::DirectHandle<i::JSFunction> f = i::Cast<i::JSFunction>(o);
          i::Handle<i::SharedFunctionInfo> shared(f->shared(), isolate);
          i::UnoptimizedCompileFlags flags =
              i::UnoptimizedCompileFlags::ForFunctionCompile(isolate, *shared);
          info = std::make_unique<i::ParseInfo>(isolate, flags, &compile_state,
                                                &reusable_state);
          CHECK_PARSE_FUNCTION(info.get(), shared, isolate);
        } else {
          i::DirectHandle<i::String> source =
              factory->InternalizeUtf8String(program.begin());
          source->PrintOn(stdout);
          printf("\n");
          i::Handle<i::Script> script = factory->NewScript(source);
          i::UnoptimizedCompileFlags flags =
              i::UnoptimizedCompileFlags::ForScriptCompile(isolate, *script);
          flags.set_allow_lazy_parsing(false);
          info = std::make_unique<i::ParseInfo>(isolate, flags, &compile_state,
                                                &reusable_state);
          CHECK_PARSE_PROGRAM(info.get(), script, isolate);
        }

        i::Scope* scope = info->literal()->scope();
        if (!lazy) {
          scope = scope->inner_scope();
        }
        DCHECK_NOT_NULL(scope);
        DCHECK_NULL(scope->sibling());
        DCHECK(scope->is_function_scope());
        const i::AstRawString* var_name =
            info->ast_value_factory()->GetOneByteString("x");
        i::Variable* var = scope->LookupForTesting(var_name);
        bool expected = outers[i].assigned || inners[j].assigned;
        CHECK_NOT_NULL(var);
        bool is_maybe_assigned = var->maybe_assigned() == i::kMaybeAssigned;
        CHECK(is_maybe_assigned == expected ||
              (is_maybe_assigned && inners[j].allow_error_in_inner_function));
      }
    }
  }
}

TEST_F(ParsingTest, MaybeAssignedParameters) {
  i::Isolate* isolate = i_isolate();

  struct {
    bool arg_assigned;
    const char* source;
  } tests[] = {
      {false, "function f(arg) {}"},
      {false, "function f(arg) {g(arg)}"},
      {false, "function f(arg) {function h() { g(arg) }; h()}"},
      {false, "function f(arg) {function h() { g(arg) }; return h}"},
      {false, "function f(arg=1) {}"},
      {false, "function f(arg=1) {g(arg)}"},
      {false, "function f(arg, arguments) {g(arg); arguments[0] = 42; g(arg)}"},
      {false,
       "function f(arg, ...arguments) {g(arg); arguments[0] = 42; g(arg)}"},
      {false,
       "function f(arg, arguments=[]) {g(arg); arguments[0] = 42; g(arg)}"},
      {false, "function f(...arg) {g(arg); arguments[0] = 42; g(arg)}"},
      {false,
       "function f(arg) {g(arg); g(function() {arguments[0] = 42}); g(arg)}"},

      // strict arguments object
      {false, "function f(arg, x=1) {g(arg); arguments[0] = 42; g(arg)}"},
      {false, "function f(arg, ...x) {g(arg); arguments[0] = 42; g(arg)}"},
      {false, "function f(arg=1) {g(arg); arguments[0] = 42; g(arg)}"},
      {false,
       "function f(arg) {'use strict'; g(arg); arguments[0] = 42; g(arg)}"},
      {false, "function f(arg) {g(arg); f.arguments[0] = 42; g(arg)}"},
      {false, "function f(arg, args=arguments) {g(arg); args[0] = 42; g(arg)}"},

      {true, "function f(arg) {g(arg); arg = 42; g(arg)}"},
      {true, "function f(arg) {g(arg); eval('arg = 42'); g(arg)}"},
      {true, "function f(arg) {g(arg); var arg = 42; g(arg)}"},
      {true, "function f(arg, x=1) {g(arg); arg = 42; g(arg)}"},
      {true, "function f(arg, ...x) {g(arg); arg = 42; g(arg)}"},
      {true, "function f(arg=1) {g(arg); arg = 42; g(arg)}"},
      {true, "function f(arg) {'use strict'; g(arg); arg = 42; g(arg)}"},
      {true, "function f(arg, {a=(g(arg), arg=42)}) {g(arg)}"},
      {true, "function f(arg) {g(arg); g(function() {arg = 42}); g(arg)}"},
      {true,
       "function f(arg) {g(arg); g(function() {eval('arg = 42')}); g(arg)}"},
      {true, "function f(arg) {g(arg); g(() => arg = 42); g(arg)}"},
      {true, "function f(arg) {g(arg); g(() => eval('arg = 42')); g(arg)}"},
      {true, "function f(...arg) {g(arg); eval('arg = 42'); g(arg)}"},

      // sloppy arguments object
      {true, "function f(arg) {g(arg); arguments[0] = 42; g(arg)}"},
      {true, "function f(arg) {g(arg); h(arguments); g(arg)}"},
      {true,
       "function f(arg) {((args) => {arguments[0] = 42})(arguments); "
       "g(arg)}"},
      {true, "function f(arg) {g(arg); eval('arguments[0] = 42'); g(arg)}"},
      {true, "function f(arg) {g(arg); g(() => arguments[0] = 42); g(arg)}"},

      // default values
      {false, "function f({x:arg = 1}) {}"},
      {true, "function f({x:arg = 1}, {y:b=(arg=2)}) {}"},
      {true, "function f({x:arg = (arg = 2)}) {}"},
      {false, "var f = ({x:arg = 1}) => {}"},
      {true, "var f = ({x:arg = 1}, {y:b=(arg=2)}) => {}"},
      {true, "var f = ({x:arg = (arg = 2)}) => {}"},
  };

  const char* suffix = "; f";

  for (unsigned i = 0; i < arraysize(tests); ++i) {
    bool assigned = tests[i].arg_assigned;
    const char* source = tests[i].source;
    for (unsigned allow_lazy = 0; allow_lazy < 2; ++allow_lazy) {
      base::ScopedVector<char> program(Utf8LengthHelper(source) +
                                       Utf8LengthHelper(suffix) + 1);
      base::SNPrintF(program, "%s%s", source, suffix);
      printf("%s\n", program.begin());
      v8::Local<v8::Value> v = RunJS(program.begin());
      i::DirectHandle<i::Object> o = v8::Utils::OpenDirectHandle(*v);
      i::DirectHandle<i::JSFunction> f = i::Cast<i::JSFunction>(o);
      i::Handle<i::SharedFunctionInfo> shared = i::handle(f->shared(), isolate);
      i::UnoptimizedCompileState state;
      i::ReusableUnoptimizedCompileState reusable_state(isolate);
      i::UnoptimizedCompileFlags flags =
          i::UnoptimizedCompileFlags::ForFunctionCompile(isolate, *shared);
      flags.set_allow_lazy_parsing(allow_lazy);
      i::ParseInfo info(isolate, flags, &state, &reusable_state);
      CHECK_PARSE_FUNCTION(&info, shared, isolate);

      i::Scope* scope = info.literal()->scope();
      CHECK(!scope->AsDeclarationScope()->was_lazily_parsed());
      CHECK_NULL(scope->sibling());
      CHECK(scope->is_function_scope());
      const i::AstRawString* var_name =
          info.ast_value_factory()->GetOneByteString("arg");
      i::Variable* var = scope->LookupForTesting(var_name);
      CHECK(var->is_used() || !assigned);
      bool is_maybe_assigned = var->maybe_assigned() == i::kMaybeAssigned;
      CHECK_EQ(is_maybe_assigned, assigned);
    }
  }
}

static Input wrap(Input input) {
  Input result;
  result.assigned = input.assigned;
  result.source = "function WRAPPED() { " + input.source + " }";
  result.location.push_back(0);
  for (auto n : input.location) {
    result.location.push_back(n);
  }
  return result;
}

TEST_F(ParsingTest, MaybeAssignedInsideLoop) {
  std::vector<unsigned> top;  // Can't use {} in initializers below.

  Input module_and_script_tests[] = {
      {true, "for (j=x; j<10; ++j) { foo = j }", top},
      {true, "for (j=x; j<10; ++j) { [foo] = [j] }", top},
      {true, "for (j=x; j<10; ++j) { [[foo]=[42]] = [] }", top},
      {true, "for (j=x; j<10; ++j) { var foo = j }", top},
      {true, "for (j=x; j<10; ++j) { var [foo] = [j] }", top},
      {true, "for (j=x; j<10; ++j) { var [[foo]=[42]] = [] }", top},
      {true, "for (j=x; j<10; ++j) { var foo; foo = j }", top},
      {true, "for (j=x; j<10; ++j) { var foo; [foo] = [j] }", top},
      {true, "for (j=x; j<10; ++j) { var foo; [[foo]=[42]] = [] }", top},
      {true, "for (j=x; j<10; ++j) { let foo; foo = j }", {0}},
      {true, "for (j=x; j<10; ++j) { let foo; [foo] = [j] }", {0}},
      {true, "for (j=x; j<10; ++j) { let foo; [[foo]=[42]] = [] }", {0}},
      {false, "for (j=x; j<10; ++j) { let foo = j }", {0}},
      {false, "for (j=x; j<10; ++j) { let [foo] = [j] }", {0}},
      {false, "for (j=x; j<10; ++j) { const foo = j }", {0}},
      {false, "for (j=x; j<10; ++j) { const [foo] = [j] }", {0}},
      {false, "for (j=x; j<10; ++j) { function foo() {return j} }", {0}},

      {true, "for ({j}=x; j<10; ++j) { foo = j }", top},
      {true, "for ({j}=x; j<10; ++j) { [foo] = [j] }", top},
      {true, "for ({j}=x; j<10; ++j) { [[foo]=[42]] = [] }", top},
      {true, "for ({j}=x; j<10; ++j) { var foo = j }", top},
      {true, "for ({j}=x; j<10; ++j) { var [foo] = [j] }", top},
      {true, "for ({j}=x; j<10; ++j) { var [[foo]=[42]] = [] }", top},
      {true, "for ({j}=x; j<10; ++j) { var foo; foo = j }", top},
      {true, "for ({j}=x; j<10; ++j) { var foo; [foo] = [j] }", top},
      {true, "for ({j}=x; j<10; ++j) { var foo; [[foo]=[42]] = [] }", top},
      {true, "for ({j}=x; j<10; ++j) { let foo; foo = j }", {0}},
      {true, "for ({j}=x; j<10; ++j) { let foo; [foo] = [j] }", {0}},
      {true, "for ({j}=x; j<10; ++j) { let foo; [[foo]=[42]] = [] }", {0}},
      {false, "for ({j}=x; j<10; ++j) { let foo = j }", {0}},
      {false, "for ({j}=x; j<10; ++j) { let [foo] = [j] }", {0}},
      {false, "for ({j}=x; j<10; ++j) { const foo = j }", {0}},
      {false, "for ({j}=x; j<10; ++j) { const [foo] = [j] }", {0}},
      {false, "for ({j}=x; j<10; ++j) { function foo() {return j} }", {0}},

      {true, "for (var j=x; j<10; ++j) { foo = j }", top},
      {true, "for (var j=x; j<10; ++j) { [foo] = [j] }", top},
      {true, "for (var j=x; j<10; ++j) { [[foo]=[42]] = [] }", top},
      {true, "for (var j=x; j<10; ++j) { var foo = j }", top},
      {true, "for (var j=x; j<10; ++j) { var [foo] = [j] }", top},
      {true, "for (var j=x; j<10; ++j) { var [[foo]=[42]] = [] }", top},
      {true, "for (var j=x; j<10; ++j) { var foo; foo = j }", top},
      {true, "for (var j=x; j<10; ++j) { var foo; [foo] = [j] }", top},
      {true, "for (var j=x; j<10; ++j) { var foo; [[foo]=[42]] = [] }", top},
      {true, "for (var j=x; j<10; ++j) { let foo; foo = j }", {0}},
      {true, "for (var j=x; j<10; ++j) { let foo; [foo] = [j] }", {0}},
      {true, "for (var j=x; j<10; ++j) { let foo; [[foo]=[42]] = [] }", {0}},
      {false, "for (var j=x; j<10; ++j) { let foo = j }", {0}},
      {false, "for (var j=x; j<10; ++j) { let [foo] = [j] }", {0}},
      {false, "for (var j=x; j<10; ++j) { const foo = j }", {0}},
      {false, "for (var j=x; j<10; ++j) { const [foo] = [j] }", {0}},
      {false, "for (var j=x; j<10; ++j) { function foo() {return j} }", {0}},

      {true, "for (var {j}=x; j<10; ++j) { foo = j }", top},
      {true, "for (var {j}=x; j<10; ++j) { [foo] = [j] }", top},
      {true, "for (var {j}=x; j<10; ++j) { [[foo]=[42]] = [] }", top},
      {true, "for (var {j}=x; j<10; ++j) { var foo = j }", top},
      {true, "for (var {j}=x; j<10; ++j) { var [foo] = [j] }", top},
      {true, "for (var {j}=x; j<10; ++j) { var [[foo]=[42]] = [] }", top},
      {true, "for (var {j}=x; j<10; ++j) { var foo; foo = j }", top},
      {true, "for (var {j}=x; j<10; ++j) { var foo; [foo] = [j] }", top},
      {true, "for (var {j}=x; j<10; ++j) { var foo; [[foo]=[42]] = [] }", top},
      {true, "for (var {j}=x; j<10; ++j) { let foo; foo = j }", {0}},
      {true, "for (var {j}=x; j<10; ++j) { let foo; [foo] = [j] }", {0}},
      {true, "for (var {j}=x; j<10; ++j) { let foo; [[foo]=[42]] = [] }", {0}},
      {false, "for (var {j}=x; j<10; ++j) { let foo = j }", {0}},
      {false, "for (var {j}=x; j<10; ++j) { let [foo] = [j] }", {0}},
      {false, "for (var {j}=x; j<10; ++j) { const foo = j }", {0}},
      {false, "for (var {j}=x; j<10; ++j) { const [foo] = [j] }", {0}},
      {false, "for (var {j}=x; j<10; ++j) { function foo() {return j} }", {0}},

      {true, "for (let j=x; j<10; ++j) { foo = j }", top},
      {true, "for (let j=x; j<10; ++j) { [foo] = [j] }", top},
      {true, "for (let j=x; j<10; ++j) { [[foo]=[42]] = [] }", top},
      {true, "for (let j=x; j<10; ++j) { var foo = j }", top},
      {true, "for (let j=x; j<10; ++j) { var [foo] = [j] }", top},
      {true, "for (let j=x; j<10; ++j) { var [[foo]=[42]] = [] }", top},
      {true, "for (let j=x; j<10; ++j) { var foo; foo = j }", top},
      {true, "for (let j=x; j<10; ++j) { var foo; [foo] = [j] }", top},
      {true, "for (let j=x; j<10; ++j) { var foo; [[foo]=[42]] = [] }", top},
      {true, "for (let j=x; j<10; ++j) { let foo; foo = j }", {0, 0}},
      {true, "for (let j=x; j<10; ++j) { let foo; [foo] = [j] }", {0, 0}},
      {true, "for (let j=x; j<10; ++j) { let foo; [[foo]=[42]] = [] }", {0, 0}},
      {false, "for (let j=x; j<10; ++j) { let foo = j }", {0, 0}},
      {false, "for (let j=x; j<10; ++j) { let [foo] = [j] }", {0, 0}},
      {false, "for (let j=x; j<10; ++j) { const foo = j }", {0, 0}},
      {false, "for (let j=x; j<10; ++j) { const [foo] = [j] }", {0, 0}},
      {false,
       "for (let j=x; j<10; ++j) { function foo() {return j} }",
       {0, 0, 0}},

      {true, "for (let {j}=x; j<10; ++j) { foo = j }", top},
      {true, "for (let {j}=x; j<10; ++j) { [foo] = [j] }", top},
      {true, "for (let {j}=x; j<10; ++j) { [[foo]=[42]] = [] }", top},
      {true, "for (let {j}=x; j<10; ++j) { var foo = j }", top},
      {true, "for (let {j}=x; j<10; ++j) { var [foo] = [j] }", top},
      {true, "for (let {j}=x; j<10; ++j) { var [[foo]=[42]] = [] }", top},
      {true, "for (let {j}=x; j<10; ++j) { var foo; foo = j }", top},
      {true, "for (let {j}=x; j<10; ++j) { var foo; [foo] = [j] }", top},
      {true, "for (let {j}=x; j<10; ++j) { var foo; [[foo]=[42]] = [] }", top},
      {true, "for (let {j}=x; j<10; ++j) { let foo; foo = j }", {0, 0}},
      {true, "for (let {j}=x; j<10; ++j) { let foo; [foo] = [j] }", {0, 0}},
      {true,
       "for (let {j}=x; j<10; ++j) { let foo; [[foo]=[42]] = [] }",
       {0, 0}},
      {false, "for (let {j}=x; j<10; ++j) { let foo = j }", {0, 0}},
      {false, "for (let {j}=x; j<10; ++j) { let [foo] = [j] }", {0, 0}},
      {false, "for (let {j}=x; j<10; ++j) { const foo = j }", {0, 0}},
      {false, "for (let {j}=x; j<10; ++j) { const [foo] = [j] }", {0, 0}},
      {false,
       "for (let {j}=x; j<10; ++j) { function foo(){return j} }",
       {0, 0, 0}},

      {true, "for (j of x) { foo = j }", top},
      {true, "for (j of x) { [foo] = [j] }", top},
      {true, "for (j of x) { [[foo]=[42]] = [] }", top},
      {true, "for (j of x) { var foo = j }", top},
      {true, "for (j of x) { var [foo] = [j] }", top},
      {true, "for (j of x) { var [[foo]=[42]] = [] }", top},
      {true, "for (j of x) { var foo; foo = j }", top},
      {true, "for (j of x) { var foo; [foo] = [j] }", top},
      {true, "for (j of x) { var foo; [[foo]=[42]] = [] }", top},
      {true, "for (j of x) { let foo; foo = j }", {0}},
      {true, "for (j of x) { let foo; [foo] = [j] }", {0}},
      {true, "for (j of x) { let foo; [[foo]=[42]] = [] }", {0}},
      {false, "for (j of x) { let foo = j }", {0}},
      {false, "for (j of x) { let [foo] = [j] }", {0}},
      {false, "for (j of x) { const foo = j }", {0}},
      {false, "for (j of x) { const [foo] = [j] }", {0}},
      {false, "for (j of x) { function foo() {return j} }", {0}},

      {true, "for ({j} of x) { foo = j }", top},
      {true, "for ({j} of x) { [foo] = [j] }", top},
      {true, "for ({j} of x) { [[foo]=[42]] = [] }", top},
      {true, "for ({j} of x) { var foo = j }", top},
      {true, "for ({j} of x) { var [foo] = [j] }", top},
      {true, "for ({j} of x) { var [[foo]=[42]] = [] }", top},
      {true, "for ({j} of x) { var foo; foo = j }", top},
      {true, "for ({j} of x) { var foo; [foo] = [j] }", top},
      {true, "for ({j} of x) { var foo; [[foo]=[42]] = [] }", top},
      {true, "for ({j} of x) { let foo; foo = j }", {0}},
      {true, "for ({j} of x) { let foo; [foo] = [j] }", {0}},
      {true, "for ({j} of x) { let foo; [[foo]=[42]] = [] }", {0}},
      {false, "for ({j} of x) { let foo = j }", {0}},
      {false, "for ({j} of x) { let [foo] = [j] }", {0}},
      {false, "for ({j} of x) { const foo = j }", {0}},
      {false, "for ({j} of x) { const [foo] = [j] }", {0}},
      {false, "for ({j} of x) { function foo() {return j} }", {0}},

      {true, "for (var j of x) { foo = j }", top},
      {true, "for (var j of x) { [foo] = [j] }", top},
      {true, "for (var j of x) { [[foo]=[42]] = [] }", top},
      {true, "for (var j of x) { var foo = j }", top},
      {true, "for (var j of x) { var [foo] = [j] }", top},
      {true, "for (var j of x) { var [[foo]=[42]] = [] }", top},
      {true, "for (var j of x) { var foo; foo = j }", top},
      {true, "for (var j of x) { var foo; [foo] = [j] }", top},
      {true, "for (var j of x) { var foo; [[foo]=[42]] = [] }", top},
      {true, "for (var j of x) { let foo; foo = j }", {0}},
      {true, "for (var j of x) { let foo; [foo] = [j] }", {0}},
      {true, "for (var j of x) { let foo; [[foo]=[42]] = [] }", {0}},
      {false, "for (var j of x) { let foo = j }", {0}},
      {false, "for (var j of x) { let [foo] = [j] }", {0}},
      {false, "for (var j of x) { const foo = j }", {0}},
      {false, "for (var j of x) { const [foo] = [j] }", {0}},
      {false, "for (var j of x) { function foo() {return j} }", {0}},

      {true, "for (var {j} of x) { foo = j }", top},
      {true, "for (var {j} of x) { [foo] = [j] }", top},
      {true, "for (var {j} of x) { [[foo]=[42]] = [] }", top},
      {true, "for (var {j} of x) { var foo = j }", top},
      {true, "for (var {j} of x) { var [foo] = [j] }", top},
      {true, "for (var {j} of x) { var [[foo]=[42]] = [] }", top},
      {true, "for (var {j} of x) { var foo; foo = j }", top},
      {true, "for (var {j} of x) { var foo; [foo] = [j] }", top},
      {true, "for (var {j} of x) { var foo; [[foo]=[42]] = [] }", top},
      {true, "for (var {j} of x) { let foo; foo = j }", {0}},
      {true, "for (var {j} of x) { let foo; [foo] = [j] }", {0}},
      {true, "for (var {j} of x) { let foo; [[foo]=[42]] = [] }", {0}},
      {false, "for (var {j} of x) { let foo = j }", {0}},
      {false, "for (var {j} of x) { let [foo] = [j] }", {0}},
      {false, "for (var {j} of x) { const foo = j }", {0}},
      {false, "for (var {j} of x) { const [foo] = [j] }", {0}},
      {false, "for (var {j} of x) { function foo() {return j} }", {0}},

      {true, "for (let j of x) { foo = j }", top},
      {true, "for (let j of x) { [foo] = [j] }", top},
      {true, "for (let j of x) { [[foo]=[42]] = [] }", top},
      {true, "for (let j of x) { var foo = j }", top},
      {true, "for (let j of x) { var [foo] = [j] }", top},
      {true, "for (let j of x) { var [[foo]=[42]] = [] }", top},
      {true, "for (let j of x) { var foo; foo = j }", top},
      {true, "for (let j of x) { var foo; [foo] = [j] }", top},
      {true, "for (let j of x) { var foo; [[foo]=[42]] = [] }", top},
      {true, "for (let j of x) { let foo; foo = j }", {0, 0, 0}},
      {true, "for (let j of x) { let foo; [foo] = [j] }", {0, 0, 0}},
      {true, "for (let j of x) { let foo; [[foo]=[42]] = [] }", {0, 0, 0}},
      {false, "for (let j of x) { let foo = j }", {0, 0, 0}},
      {false, "for (let j of x) { let [foo] = [j] }", {0, 0, 0}},
      {false, "for (let j of x) { const foo = j }", {0, 0, 0}},
      {false, "for (let j of x) { const [foo] = [j] }", {0, 0, 0}},
      {false, "for (let j of x) { function foo() {return j} }", {0, 0, 0}},

      {true, "for (let {j} of x) { foo = j }", top},
      {true, "for (let {j} of x) { [foo] = [j] }", top},
      {true, "for (let {j} of x) { [[foo]=[42]] = [] }", top},
      {true, "for (let {j} of x) { var foo = j }", top},
      {true, "for (let {j} of x) { var [foo] = [j] }", top},
      {true, "for (let {j} of x) { var [[foo]=[42]] = [] }", top},
      {true, "for (let {j} of x) { var foo; foo = j }", top},
      {true, "for (let {j} of x) { var foo; [foo] = [j] }", top},
      {true, "for (let {j} of x) { var foo; [[foo]=[42]] = [] }", top},
      {true, "for (let {j} of x) { let foo; foo = j }", {0, 0, 0}},
      {true, "for (let {j} of x) { let foo; [foo] = [j] }", {0, 0, 0}},
      {true, "for (let {j} of x) { let foo; [[foo]=[42]] = [] }", {0, 0, 0}},
      {false, "for (let {j} of x) { let foo = j }", {0, 0, 0}},
      {false, "for (let {j} of x) { let [foo] = [j] }", {0, 0, 0}},
      {false, "for (let {j} of x) { const foo = j }", {0, 0, 0}},
      {false, "for (let {j} of x) { const [foo] = [j] }", {0, 0, 0}},
      {false, "for (let {j} of x) { function foo() {return j} }", {0, 0, 0}},

      {true, "for (const j of x) { foo = j }", top},
      {true, "for (const j of x) { [foo] = [j] }", top},
      {true, "for (const j of x) { [[foo]=[42]] = [] }", top},
      {true, "for (const j of x) { var foo = j }", top},
      {true, "for (const j of x) { var [foo] = [j] }", top},
      {true, "for (const j of x) { var [[foo]=[42]] = [] }", top},
      {true, "for (const j of x) { var foo; foo = j }", top},
      {true, "for (const j of x) { var foo; [foo] = [j] }", top},
      {true, "for (const j of x) { var foo; [[foo]=[42]] = [] }", top},
      {true, "for (const j of x) { let foo; foo = j }", {0, 0, 0}},
      {true, "for (const j of x) { let foo; [foo] = [j] }", {0, 0, 0}},
      {true, "for (const j of x) { let foo; [[foo]=[42]] = [] }", {0, 0, 0}},
      {false, "for (const j of x) { let foo = j }", {0, 0, 0}},
      {false, "for (const j of x) { let [foo] = [j] }", {0, 0, 0}},
      {false, "for (const j of x) { const foo = j }", {0, 0, 0}},
      {false, "for (const j of x) { const [foo] = [j] }", {0, 0, 0}},
      {false, "for (const j of x) { function foo() {return j} }", {0, 0, 0}},

      {true, "for (const {j} of x) { foo = j }", top},
      {true, "for (const {j} of x) { [foo] = [j] }", top},
      {true, "for (const {j} of x) { [[foo]=[42]] = [] }", top},
      {true, "for (const {j} of x) { var foo = j }", top},
      {true, "for (const {j} of x) { var [foo] = [j] }", top},
      {true, "for (const {j} of x) { var [[foo]=[42]] = [] }", top},
      {true, "for (const {j} of x) { var foo; foo = j }", top},
      {true, "for (const {j} of x) { var foo; [foo] = [j] }", top},
      {true, "for (const {j} of x) { var foo; [[foo]=[42]] = [] }", top},
      {true, "for (const {j} of x) { let foo; foo = j }", {0, 0, 0}},
      {true, "for (const {j} of x) { let foo; [foo] = [j] }", {0, 0, 0}},
      {true, "for (const {j} of x) { let foo; [[foo]=[42]] = [] }", {0, 0, 0}},
      {false, "for (const {j} of x) { let foo = j }", {0, 0, 0}},
      {false, "for (const {j} of x) { let [foo] = [j] }", {0, 0, 0}},
      {false, "for (const {j} of x) { const foo = j }", {0, 0, 0}},
      {false, "for (const {j} of x) { const [foo] = [j] }", {0, 0, 0}},
      {false, "for (const {j} of x) { function foo() {return j} }", {0, 0, 0}},

      {true, "for (j in x) { foo = j }", top},
      {true, "for (j in x) { [foo] = [j] }", top},
      {true, "for (j in x) { [[foo]=[42]] = [] }", top},
      {true, "for (j in x) { var foo = j }", top},
      {true, "for (j in x) { var [foo] = [j] }", top},
      {true, "for (j in x) { var [[foo]=[42]] = [] }", top},
      {true, "for (j in x) { var foo; foo = j }", top},
      {true, "for (j in x) { var foo; [foo] = [j] }", top},
      {true, "for (j in x) { var foo; [[foo]=[42]] = [] }", top},
      {true, "for (j in x) { let foo; foo = j }", {0}},
      {true, "for (j in x) { let foo; [foo] = [j] }", {0}},
      {true, "for (j in x) { let foo; [[foo]=[42]] = [] }", {0}},
      {false, "for (j in x) { let foo = j }", {0}},
      {false, "for (j in x) { let [foo] = [j] }", {0}},
      {false, "for (j in x) { const foo = j }", {0}},
      {false, "for (j in x) { const [foo] = [j] }", {0}},
      {false, "for (j in x) { function foo() {return j} }", {0}},

      {true, "for ({j} in x) { foo = j }", top},
      {true, "for ({j} in x) { [foo] = [j] }", top},
      {true, "for ({j} in x) { [[foo]=[42]] = [] }", top},
      {true, "for ({j} in x) { var foo = j }", top},
      {true, "for ({j} in x) { var [foo] = [j] }", top},
      {true, "for ({j} in x) { var [[foo]=[42]] = [] }", top},
      {true, "for ({j} in x) { var foo; foo = j }", top},
      {true, "for ({j} in x) { var foo; [foo] = [j] }", top},
      {true, "for ({j} in x) { var foo; [[foo]=[42]] = [] }", top},
      {true, "for ({j} in x) { let foo; foo = j }", {0}},
      {true, "for ({j} in x) { let foo; [foo] = [j] }", {0}},
      {true, "for ({j} in x) { let foo; [[foo]=[42]] = [] }", {0}},
      {false, "for ({j} in x) { let foo = j }", {0}},
      {false, "for ({j} in x) { let [foo] = [j] }", {0}},
      {false, "for ({j} in x) { const foo = j }", {0}},
      {false, "for ({j} in x) { const [foo] = [j] }", {0}},
      {false, "for ({j} in x) { function foo() {return j} }", {0}},

      {true, "for (var j in x) { foo = j }", top},
      {true, "for (var j in x) { [foo] = [j] }", top},
      {true, "for (var j in x) { [[foo]=[42]] = [] }", top},
      {true, "for (var j in x) { var foo = j }", top},
      {true, "for (var j in x) { var [foo] = [j] }", top},
      {true, "for (var j in x) { var [[foo]=[42]] = [] }", top},
      {true, "for (var j in x) { var foo; foo = j }", top},
      {true, "for (var j in x) { var foo; [foo] = [j] }", top},
      {true, "for (var j in x) { var foo; [[foo]=[42]] = [] }", top},
      {true, "for (var j in x) { let foo; foo = j }", {0}},
      {true, "for (var j in x) { let foo; [foo] = [j] }", {0}},
      {true, "for (var j in x) { let foo; [[foo]=[42]] = [] }", {0}},
      {false, "for (var j in x) { let foo = j }", {0}},
      {false, "for (var j in x) { let [foo] = [j] }", {0}},
      {false, "for (var j in x) { const foo = j }", {0}},
      {false, "for (var j in x) { const [foo] = [j] }", {0}},
      {false, "for (var j in x) { function foo() {return j} }", {0}},

      {true, "for (var {j} in x) { foo = j }", top},
      {true, "for (var {j} in x) { [foo] = [j] }", top},
      {true, "for (var {j} in x) { [[foo]=[42]] = [] }", top},
      {true, "for (var {j} in x) { var foo = j }", top},
      {true, "for (var {j} in x) { var [foo] = [j] }", top},
      {true, "for (var {j} in x) { var [[foo]=[42]] = [] }", top},
      {true, "for (var {j} in x) { var foo; foo = j }", top},
      {true, "for (var {j} in x) { var foo; [foo] = [j] }", top},
      {true, "for (var {j} in x) { var foo; [[foo]=[42]] = [] }", top},
      {true, "for (var {j} in x) { let foo; foo = j }", {0}},
      {true, "for (var {j} in x) { let foo; [foo] = [j] }", {0}},
      {true, "for (var {j} in x) { let foo; [[foo]=[42]] = [] }", {0}},
      {false, "for (var {j} in x) { let foo = j }", {0}},
      {false, "for (var {j} in x) { let [foo] = [j] }", {0}},
      {false, "for (var {j} in x) { const foo = j }", {0}},
      {false, "for (var {j} in x) { const [foo] = [j] }", {0}},
      {false, "for (var {j} in x) { function foo() {return j} }", {0}},

      {true, "for (let j in x) { foo = j }", top},
      {true, "for (let j in x) { [foo] = [j] }", top},
      {true, "for (let j in x) { [[foo]=[42]] = [] }", top},
      {true, "for (let j in x) { var foo = j }", top},
      {true, "for (let j in x) { var [foo] = [j] }", top},
      {true, "for (let j in x) { var [[foo]=[42]] = [] }", top},
      {true, "for (let j in x) { var foo; foo = j }", top},
      {true, "for (let j in x) { var foo; [foo] = [j] }", top},
      {true, "for (let j in x) { var foo; [[foo]=[42]] = [] }", top},
      {true, "for (let j in x) { let foo; foo = j }", {0, 0, 0}},
      {true, "for (let j in x) { let foo; [foo] = [j] }", {0, 0, 0}},
      {true, "for (let j in x) { let foo; [[foo]=[42]] = [] }", {0, 0, 0}},
      {false, "for (let j in x) { let foo = j }", {0, 0, 0}},
      {false, "for (let j in x) { let [foo] = [j] }", {0, 0, 0}},
      {false, "for (let j in x) { const foo = j }", {0, 0, 0}},
      {false, "for (let j in x) { const [foo] = [j] }", {0, 0, 0}},
      {false, "for (let j in x) { function foo() {return j} }", {0, 0, 0}},

      {true, "for (let {j} in x) { foo = j }", top},
      {true, "for (let {j} in x) { [foo] = [j] }", top},
      {true, "for (let {j} in x) { [[foo]=[42]] = [] }", top},
      {true, "for (let {j} in x) { var foo = j }", top},
      {true, "for (let {j} in x) { var [foo] = [j] }", top},
      {true, "for (let {j} in x) { var [[foo]=[42]] = [] }", top},
      {true, "for (let {j} in x) { var foo; foo = j }", top},
      {true, "for (let {j} in x) { var foo; [foo] = [j] }", top},
      {true, "for (let {j} in x) { var foo; [[foo]=[42]] = [] }", top},
      {true, "for (let {j} in x) { let foo; foo = j }", {0, 0, 0}},
      {true, "for (let {j} in x) { let foo; [foo] = [j] }", {0, 0, 0}},
      {true, "for (let {j} in x) { let foo; [[foo]=[42]] = [] }", {0, 0, 0}},
      {false, "for (let {j} in x) { let foo = j }", {0, 0, 0}},
      {false, "for (let {j} in x) { let [foo] = [j] }", {0, 0, 0}},
      {false, "for (let {j} in x) { const foo = j }", {0, 0, 0}},
      {false, "for (let {j} in x) { const [foo] = [j] }", {0, 0, 0}},
      {false, "for (let {j} in x) { function foo() {return j} }", {0, 0, 0}},

      {true, "for (const j in x) { foo = j }", top},
      {true, "for (const j in x) { [foo] = [j] }", top},
      {true, "for (const j in x) { [[foo]=[42]] = [] }", top},
      {true, "for (const j in x) { var foo = j }", top},
      {true, "for (const j in x) { var [foo] = [j] }", top},
      {true, "for (const j in x) { var [[foo]=[42]] = [] }", top},
      {true, "for (const j in x) { var foo; foo = j }", top},
      {true, "for (const j in x) { var foo; [foo] = [j] }", top},
      {true, "for (const j in x) { var foo; [[foo]=[42]] = [] }", top},
      {true, "for (const j in x) { let foo; foo = j }", {0, 0, 0}},
      {true, "for (const j in x) { let foo; [foo] = [j] }", {0, 0, 0}},
      {true, "for (const j in x) { let foo; [[foo]=[42]] = [] }", {0, 0, 0}},
      {false, "for (const j in x) { let foo = j }", {0, 0, 0}},
      {false, "for (const j in x) { let [foo] = [j] }", {0, 0, 0}},
      {false, "for (const j in x) { const foo = j }", {0, 0, 0}},
      {false, "for (const j in x) { const [foo] = [j] }", {0, 0, 0}},
      {false, "for (const j in x) { function foo() {return j} }", {0, 0, 0}},

      {true, "for (const {j} in x) { foo = j }", top},
      {true, "for (const {j} in x) { [foo] = [j] }", top},
      {true, "for (const {j} in x) { [[foo]=[42]] = [] }", top},
      {true, "for (const {j} in x) { var foo = j }", top},
      {true, "for (const {j} in x) { var [foo] = [j] }", top},
      {true, "for (const {j} in x) { var [[foo]=[42]] = [] }", top},
      {true, "for (const {j} in x) { var foo; foo = j }", top},
      {true, "for (const {j} in x) { var foo; [foo] = [j] }", top},
      {true, "for (const {j} in x) { var foo; [[foo]=[42]] = [] }", top},
      {true, "for (const {j} in x) { let foo; foo = j }", {0, 0, 0}},
      {true, "for (const {j} in x) { let foo; [foo] = [j] }", {0, 0, 0}},
      {true, "for (const {j} in x) { let foo; [[foo]=[42]] = [] }", {0, 0, 0}},
      {false, "for (const {j} in x) { let foo = j }", {0, 0, 0}},
      {false, "for (const {j} in x) { let [foo] = [j] }", {0, 0, 0}},
      {false, "for (const {j} in x) { const foo = j }", {0, 0, 0}},
      {false, "for (const {j} in x) { const [foo] = [j] }", {0, 0, 0}},
      {false, "for (const {j} in x) { function foo() {return j} }", {0, 0, 0}},

      {true, "while (j) { foo = j }", top},
      {true, "while (j) { [foo] = [j] }", top},
      {true, "while (j) { [[foo]=[42]] = [] }", top},
      {true, "while (j) { var foo = j }", top},
      {true, "while (j) { var [foo] = [j] }", top},
      {true, "while (j) { var [[foo]=[42]] = [] }", top},
      {true, "while (j) { var foo; foo = j }", top},
      {true, "while (j) { var foo; [foo] = [j] }", top},
      {true, "while (j) { var foo; [[foo]=[42]] = [] }", top},
      {true, "while (j) { let foo; foo = j }", {0}},
      {true, "while (j) { let foo; [foo] = [j] }", {0}},
      {true, "while (j) { let foo; [[foo]=[42]] = [] }", {0}},
      {false, "while (j) { let foo = j }", {0}},
      {false, "while (j) { let [foo] = [j] }", {0}},
      {false, "while (j) { const foo = j }", {0}},
      {false, "while (j) { const [foo] = [j] }", {0}},
      {false, "while (j) { function foo() {return j} }", {0}},

      {true, "do { foo = j } while (j)", top},
      {true, "do { [foo] = [j] } while (j)", top},
      {true, "do { [[foo]=[42]] = [] } while (j)", top},
      {true, "do { var foo = j } while (j)", top},
      {true, "do { var [foo] = [j] } while (j)", top},
      {true, "do { var [[foo]=[42]] = [] } while (j)", top},
      {true, "do { var foo; foo = j } while (j)", top},
      {true, "do { var foo; [foo] = [j] } while (j)", top},
      {true, "do { var foo; [[foo]=[42]] = [] } while (j)", top},
      {true, "do { let foo; foo = j } while (j)", {0}},
      {true, "do { let foo; [foo] = [j] } while (j)", {0}},
      {true, "do { let foo; [[foo]=[42]] = [] } while (j)", {0}},
      {false, "do { let foo = j } while (j)", {0}},
      {false, "do { let [foo] = [j] } while (j)", {0}},
      {false, "do { const foo = j } while (j)", {0}},
      {false, "do { const [foo] = [j] } while (j)", {0}},
      {false, "do { function foo() {return j} } while (j)", {0}},
  };

  Input script_only_tests[] = {
      {true, "for (j=x; j<10; ++j) { function foo() {return j} }", top},
      {true, "for ({j}=x; j<10; ++j) { function foo() {return j} }", top},
      {true, "for (var j=x; j<10; ++j) { function foo() {return j} }", top},
      {true, "for (var {j}=x; j<10; ++j) { function foo() {return j} }", top},
      {true, "for (let j=x; j<10; ++j) { function foo() {return j} }", top},
      {true, "for (let {j}=x; j<10; ++j) { function foo() {return j} }", top},
      {true, "for (j of x) { function foo() {return j} }", top},
      {true, "for ({j} of x) { function foo() {return j} }", top},
      {true, "for (var j of x) { function foo() {return j} }", top},
      {true, "for (var {j} of x) { function foo() {return j} }", top},
      {true, "for (let j of x) { function foo() {return j} }", top},
      {true, "for (let {j} of x) { function foo() {return j} }", top},
      {true, "for (const j of x) { function foo() {return j} }", top},
      {true, "for (const {j} of x) { function foo() {return j} }", top},
      {true, "for (j in x) { function foo() {return j} }", top},
      {true, "for ({j} in x) { function foo() {return j} }", top},
      {true, "for (var j in x) { function foo() {return j} }", top},
      {true, "for (var {j} in x) { function foo() {return j} }", top},
      {true, "for (let j in x) { function foo() {return j} }", top},
      {true, "for (let {j} in x) { function foo() {return j} }", top},
      {true, "for (const j in x) { function foo() {return j} }", top},
      {true, "for (const {j} in x) { function foo() {return j} }", top},
      {true, "while (j) { function foo() {return j} }", top},
      {true, "do { function foo() {return j} } while (j)", top},
  };

  for (unsigned i = 0; i < arraysize(module_and_script_tests); ++i) {
    Input input = module_and_script_tests[i];
    for (unsigned module = 0; module <= 1; ++module) {
      for (unsigned allow_lazy_parsing = 0; allow_lazy_parsing <= 1;
           ++allow_lazy_parsing) {
        TestMaybeAssigned(input, "foo", module, allow_lazy_parsing);
      }
      TestMaybeAssigned(wrap(input), "foo", module, false);
    }
  }

  for (unsigned i = 0; i < arraysize(script_only_tests); ++i) {
    Input input = script_only_tests[i];
    for (unsigned allow_lazy_parsing = 0; allow_lazy_parsing <= 1;
         ++allow_lazy_parsing) {
      TestMaybeAssigned(input, "foo", false, allow_lazy_parsing);
    }
    TestMaybeAssigned(wrap(input), "foo", false, false);
  }
}

TEST_F(ParsingTest, MaybeAssignedTopLevel) {
  const char* prefixes[] = {
      "let foo; ",
      "let foo = 0; ",
      "let [foo] = [1]; ",
      "let {foo} = {foo: 2}; ",
      "let {foo=3} = {}; ",
      "var foo; ",
      "var foo = 0; ",
      "var [foo] = [1]; ",
      "var {foo} = {foo: 2}; ",
      "var {foo=3} = {}; ",
      "{ var foo; }; ",
      "{ var foo = 0; }; ",
      "{ var [foo] = [1]; }; ",
      "{ var {foo} = {foo: 2}; }; ",
      "{ var {foo=3} = {}; }; ",
      "function foo() {}; ",
      "function* foo() {}; ",
      "async function foo() {}; ",
      "class foo {}; ",
      "class foo extends null {}; ",
  };

  const char* module_and_script_tests[] = {
      "function bar() {foo = 42}; ext(bar); ext(foo)",
      "ext(function() {foo++}); ext(foo)",
      "bar = () => --foo; ext(bar); ext(foo)",
      "function* bar() {eval(ext)}; ext(bar); ext(foo)",
  };

  const char* script_only_tests[] = {
      "",
      "{ function foo() {}; }; ",
      "{ function* foo() {}; }; ",
      "{ async function foo() {}; }; ",
  };

  for (unsigned i = 0; i < arraysize(prefixes); ++i) {
    for (unsigned j = 0; j < arraysize(module_and_script_tests); ++j) {
      std::string source(prefixes[i]);
      source += module_and_script_tests[j];
      std::vector<unsigned> top;
      Input input({true, source, top});
      for (unsigned module = 0; module <= 1; ++module) {
        for (unsigned allow_lazy_parsing = 0; allow_lazy_parsing <= 1;
             ++allow_lazy_parsing) {
          TestMaybeAssigned(input, "foo", module, allow_lazy_parsing);
        }
      }
    }
  }

  for (unsigned i = 0; i < arraysize(prefixes); ++i) {
    for (unsigned j = 0; j < arraysize(script_only_tests); ++j) {
      std::string source(prefixes[i]);
      source += script_only_tests[j];
      std::vector<unsigned> top;
      Input input({true, source, top});
      for (unsigned allow_lazy_parsing = 0; allow_lazy_parsing <= 1;
           ++allow_lazy_parsing) {
        TestMaybeAssigned(input, "foo", false, allow_lazy_parsing);
      }
    }
  }
}

#if V8_ENABLE_WEBASSEMBLY
namespace {

i::Scope* DeserializeFunctionScope(i::Isolate* isolate, i::Zone* zone,
                                   i::Handle<i::JSObject> m, const char* name) {
  i::AstValueFactory avf(zone, isolate->ast_string_constants(),
                         HashSeed(isolate));
  i::DirectHandle<i::JSFunction> f = i::Cast<i::JSFunction>(
      i::JSReceiver::GetProperty(isolate, m, name).ToHandleChecked());
  i::DeclarationScope* script_scope =
      zone->New<i::DeclarationScope>(zone, &avf);
  i::Scope* s = i::Scope::DeserializeScopeChain(
      isolate, zone, f->context()->scope_info(), script_scope, &avf,
      i::Scope::DeserializationMode::kIncludingVariables);
  return s;
}

}  // namespace

TEST_F(ParsingTest, AsmModuleFlag) {
  i::v8_flags.validate_asm = false;
  i::Isolate* isolate = i_isolate();

  const char* src =
      "function m() {"
      "  'use asm';"
      "  function f() { return 0 };"
      "  return { f:f };"
      "}"
      "m();";

  v8::Local<v8::Value> v = RunJS(src);
  i::Handle<i::Object> o = v8::Utils::OpenHandle(*v);
  i::Handle<i::JSObject> m = i::Cast<i::JSObject>(o);

  // The asm.js module should be marked as such.
  i::Scope* s = DeserializeFunctionScope(isolate, zone(), m, "f");
  CHECK(s->IsAsmModule() && s->AsDeclarationScope()->is_asm_module());
}

TEST_F(ParsingTest, UseAsmUseCount) {
  int use_counts[v8::Isolate::kUseCounterFeatureCount] = {};
  global_use_counts = use_counts;
  v8_isolate()->SetUseCounterCallback(MockUseCounterCallback);
  RunJS(
      "\"use asm\";\n"
      "var foo = 1;\n"
      "function bar() { \"use asm\"; var baz = 1; }");
  CHECK_LT(0, use_counts[v8::Isolate::kUseAsm]);
}
#endif  // V8_ENABLE_WEBASSEMBLY

TEST_F(ParsingTest, StrictModeUseCount) {
  int use_counts[v8::Isolate::kUseCounterFeatureCount] = {};
  global_use_counts = use_counts;
  v8_isolate()->SetUseCounterCallback(MockUseCounterCallback);
  RunJS(
      "\"use strict\";\n"
      "function bar() { var baz = 1; }");  // strict mode inherits
  CHECK_LT(0, use_counts[v8::Isolate::kStrictMode]);
  CHECK_EQ(0, use_counts[v8::Isolate::kSloppyMode]);
}

TEST_F(ParsingTest, SloppyModeUseCount) {
  int use_counts[v8::Isolate::kUseCounterFeatureCount] = {};
  global_use_counts = use_counts;
  // Force eager parsing (preparser doesn't update use counts).
  i::v8_flags.lazy = false;
  i::v8_flags.lazy_streaming = false;
  v8_isolate()->SetUseCounterCallback(MockUseCounterCallback);
  RunJS("function bar() { var baz = 1; }");
  CHECK_LT(0, use_counts[v8::Isolate::kSloppyMode]);
  CHECK_EQ(0, use_counts[v8::Isolate::kStrictMode]);
}

TEST_F(ParsingTest, BothModesUseCount) {
  int use_counts[v8::Isolate::kUseCounterFeatureCount] = {};
  global_use_counts = use_counts;
  i::v8_flags.lazy = false;
  i::v8_flags.lazy_streaming = false;
  v8_isolate()->SetUseCounterCallback(MockUseCounterCallback);
  RunJS("function bar() { 'use strict'; var baz = 1; }");
  CHECK_LT(0, use_counts[v8::Isolate::kSloppyMode]);
  CHECK_LT(0, use_counts[v8::Isolate::kStrictMode]);
}

TEST_F(ParsingTest, LineOrParagraphSeparatorAsLineTerminator) {
  // Tests that both preparsing and parsing accept U+2028 LINE SEPARATOR and
  // U+2029 PARAGRAPH SEPARATOR as LineTerminator symbols outside of string
  // literals.
  const char* context_data[][2] = {{"", ""}, {nullptr, nullptr}};
  const char* statement_data[] = {"\x31\xE2\x80\xA8\x32",  // 1<U+2028>2
                                  "\x31\xE2\x80\xA9\x32",  // 1<U+2029>2
                                  nullptr};

  RunParserSyncTest(context_data, statement_data, kSuccess);
}

TEST_F(ParsingTest, LineOrParagraphSeparatorInStringLiteral) {
  // Tests that both preparsing and parsing don't treat U+2028 LINE SEPARATOR
  // and U+2029 PARAGRAPH SEPARATOR as line terminators within string literals.
  // https://github.com/tc39/proposal-json-superset
  const char* context_data[][2] = {
      {"\"", "\""}, {"'", "'"}, {nullptr, nullptr}};
  const char* statement_data[] = {"\x31\xE2\x80\xA8\x32",  // 1<U+2028>2
                                  "\x31\xE2\x80\xA9\x32",  // 1<U+2029>2
                                  nullptr};

  RunParserSyncTest(context_data, statement_data, kSuccess);
}

TEST_F(ParsingTest, ErrorsArrowFormalParameters) {
  const char* context_data[][2] = {{"()", "=>{}"},
                                   {"()", "=>{};"},
                                   {"var x = ()", "=>{}"},
                                   {"var x = ()", "=>{};"},

                                   {"a", "=>{}"},
                                   {"a", "=>{};"},
                                   {"var x = a", "=>{}"},
                                   {"var x = a", "=>{};"},

                                   {"(a)", "=>{}"},
                                   {"(a)", "=>{};"},
                                   {"var x = (a)", "=>{}"},
                                   {"var x = (a)", "=>{};"},

                                   {"(...a)", "=>{}"},
                                   {"(...a)", "=>{};"},
                                   {"var x = (...a)", "=>{}"},
                                   {"var x = (...a)", "=>{};"},

                                   {"(a,b)", "=>{}"},
                                   {"(a,b)", "=>{};"},
                                   {"var x = (a,b)", "=>{}"},
                                   {"var x = (a,b)", "=>{};"},

                                   {"(a,...b)", "=>{}"},
                                   {"(a,...b)", "=>{};"},
                                   {"var x = (a,...b)", "=>{}"},
                                   {"var x = (a,...b)", "=>{};"},

                                   {nullptr, nullptr}};
  const char* assignment_expression_suffix_data[] = {
      "?c:d=>{}",
      "=c=>{}",
      "()",
      "(c)",
      "[1]",
      "[c]",
      ".c",
      "-c",
      "+c",
      "c++",
      "`c`",
      "`${c}`",
      "`template-head${c}`",
      "`${c}template-tail`",
      "`template-head${c}template-tail`",
      "`${c}template-tail`",
      nullptr};

  RunParserSyncTest(context_data, assignment_expression_suffix_data, kError);
}

TEST_F(ParsingTest, ErrorsArrowFunctions) {
  // Tests that parser and preparser generate the same kind of errors
  // on invalid arrow function syntax.

  // clang-format off
  const char* context_data[][2] = {
    {"", ";"},
    {"v = ", ";"},
    {"bar ? (", ") : baz;"},
    {"bar ? baz : (", ");"},
    {"bar[", "];"},
    {"bar, ", ";"},
    {"", ", bar;"},
    {nullptr, nullptr}
  };

  const char* statement_data[] = {
    "=> 0",
    "=>",
    "() =>",
    "=> {}",
    ") => {}",
    ", => {}",
    "(,) => {}",
    "return => {}",
    "() => {'value': 42}",

    // Check that the early return introduced in ParsePrimaryExpression
    // does not accept stray closing parentheses.
    ")",
    ") => 0",
    "foo[()]",
    "()",

    // Parameter lists with extra parens should be recognized as errors.
    "(()) => 0",
    "((x)) => 0",
    "((x, y)) => 0",
    "(x, (y)) => 0",
    "((x, y, z)) => 0",
    "(x, (y, z)) => 0",
    "((x, y), z) => 0",

    // Arrow function formal parameters are parsed as StrictFormalParameters,
    // which confusingly only implies that there are no duplicates.  Words
    // reserved in strict mode, and eval or arguments, are indeed valid in
    // sloppy mode.
    "eval => { 'use strict'; 0 }",
    "arguments => { 'use strict'; 0 }",
    "yield => { 'use strict'; 0 }",
    "interface => { 'use strict'; 0 }",
    "(eval) => { 'use strict'; 0 }",
    "(arguments) => { 'use strict'; 0 }",
    "(yield) => { 'use strict'; 0 }",
    "(interface) => { 'use strict'; 0 }",
    "(eval, bar) => { 'use strict'; 0 }",
    "(bar, eval) => { 'use strict'; 0 }",
    "(bar, arguments) => { 'use strict'; 0 }",
    "(bar, yield) => { 'use strict'; 0 }",
    "(bar, interface) => { 'use strict'; 0 }",
    // TODO(aperez): Detecting duplicates does not work in PreParser.
    // "(bar, bar) => {}",

    // The parameter list is parsed as an expression, but only
    // a comma-separated list of identifier is valid.
    "32 => {}",
    "(32) => {}",
    "(a, 32) => {}",
    "if => {}",
    "(if) => {}",
    "(a, if) => {}",
    "a + b => {}",
    "(a + b) => {}",
    "(a + b, c) => {}",
    "(a, b - c) => {}",
    "\"a\" => {}",
    "(\"a\") => {}",
    "(\"a\", b) => {}",
    "(a, \"b\") => {}",
    "-a => {}",
    "(-a) => {}",
    "(-a, b) => {}",
    "(a, -b) => {}",
    "{} => {}",
    "a++ => {}",
    "(a++) => {}",
    "(a++, b) => {}",
    "(a, b++) => {}",
    "[] => {}",
    "(foo ? bar : baz) => {}",
    "(a, foo ? bar : baz) => {}",
    "(foo ? bar : baz, a) => {}",
    "(a.b, c) => {}",
    "(c, a.b) => {}",
    "(a['b'], c) => {}",
    "(c, a['b']) => {}",
    "(...a = b) => b",

    // crbug.com/582626
    "(...rest - a) => b",
    "(a, ...b - 10) => b",

    nullptr
  };
  // clang-format on

  // The test is quite slow, so run it with a reduced set of flags.
  static const ParserFlag flags[] = {kAllowLazy};
  RunParserSyncTest(context_data, statement_data, kError, flags,
                    arraysize(flags));

  // In a context where a concise arrow body is parsed with [~In] variant,
  // ensure that an error is reported in both full parser and preparser.
  const char* loop_context_data[][2] = {{"for (", "; 0;);"},
                                        {nullptr, nullptr}};
  const char* loop_expr_data[] = {"f => 'key' in {}", nullptr};
  RunParserSyncTest(loop_context_data, loop_expr_data, kError, flags,
                    arraysize(flags));
}

TEST_F(ParsingTest, NoErrorsArrowFunctions) {
  // Tests that parser and preparser accept valid arrow functions syntax.
  // clang-format off
  const char* context_data[][2] = {
    {"", ";"},
    {"bar ? (", ") : baz;"},
    {"bar ? baz : (", ");"},
    {"bar, ", ";"},
    {"", ", bar;"},
    {nullptr, nullptr}
  };

  const char* statement_data[] = {
    "() => {}",
    "() => { return 42 }",
    "x => { return x; }",
    "(x) => { return x; }",
    "(x, y) => { return x + y; }",
    "(x, y, z) => { return x + y + z; }",
    "(x, y) => { x.a = y; }",
    "() => 42",
    "x => x",
    "x => x * x",
    "(x) => x",
    "(x) => x * x",
    "(x, y) => x + y",
    "(x, y, z) => x, y, z",
    "(x, y) => x.a = y",
    "() => ({'value': 42})",
    "x => y => x + y",
    "(x, y) => (u, v) => x*u + y*v",
    "(x, y) => z => z * (x + y)",
    "x => (y, z) => z * (x + y)",

    // Those are comma-separated expressions, with arrow functions as items.
    // They stress the code for validating arrow function parameter lists.
    "a, b => 0",
    "a, b, (c, d) => 0",
    "(a, b, (c, d) => 0)",
    "(a, b) => 0, (c, d) => 1",
    "(a, b => {}, a => a + 1)",
    "((a, b) => {}, (a => a + 1))",
    "(a, (a, (b, c) => 0))",

    // Arrow has more precedence, this is the same as: foo ? bar : (baz = {})
    "foo ? bar : baz => {}",

    // Arrows with non-simple parameters.
    "({}) => {}",
    "(a, {}) => {}",
    "({}, a) => {}",
    "([]) => {}",
    "(a, []) => {}",
    "([], a) => {}",
    "(a = b) => {}",
    "(a = b, c) => {}",
    "(a, b = c) => {}",
    "({a}) => {}",
    "(x = 9) => {}",
    "(x, y = 9) => {}",
    "(x = 9, y) => {}",
    "(x, y = 9, z) => {}",
    "(x, y = 9, z = 8) => {}",
    "(...a) => {}",
    "(x, ...a) => {}",
    "(x = 9, ...a) => {}",
    "(x, y = 9, ...a) => {}",
    "(x, y = 9, {b}, z = 8, ...a) => {}",
    "({a} = {}) => {}",
    "([x] = []) => {}",
    "({a = 42}) => {}",
    "([x = 0]) => {}",
    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, statement_data, kSuccess);

  static const ParserFlag flags[] = {kAllowLazy};
  // In a context where a concise arrow body is parsed with [~In] variant,
  // ensure that nested expressions can still use the 'in' operator,
  const char* loop_context_data[][2] = {{"for (", "; 0;);"},
                                        {nullptr, nullptr}};
  const char* loop_expr_data[] = {"f => ('key' in {})", nullptr};
  RunParserSyncTest(loop_context_data, loop_expr_data, kSuccess, flags,
                    arraysize(flags));
}

TEST_F(ParsingTest, ArrowFunctionsSloppyParameterNames) {
  const char* strict_context_data[][2] = {{"'use strict'; ", ";"},
                                          {"'use strict'; bar ? (", ") : baz;"},
                                          {"'use strict'; bar ? baz : (", ");"},
                                          {"'use strict'; bar, ", ";"},
                                          {"'use strict'; ", ", bar;"},
                                          {nullptr, nullptr}};

  const char* sloppy_context_data[][2] = {
      {"", ";"},      {"bar ? (", ") : baz;"}, {"bar ? baz : (", ");"},
      {"bar, ", ";"}, {"", ", bar;"},          {nullptr, nullptr}};

  const char* statement_data[] = {"eval => {}",
                                  "arguments => {}",
                                  "yield => {}",
                                  "interface => {}",
                                  "(eval) => {}",
                                  "(arguments) => {}",
                                  "(yield) => {}",
                                  "(interface) => {}",
                                  "(eval, bar) => {}",
                                  "(bar, eval) => {}",
                                  "(bar, arguments) => {}",
                                  "(bar, yield) => {}",
                                  "(bar, interface) => {}",
                                  "(interface, eval) => {}",
                                  "(interface, arguments) => {}",
                                  "(eval, interface) => {}",
                                  "(arguments, interface) => {}",
                                  nullptr};

  RunParserSyncTest(strict_context_data, statement_data, kError);
  RunParserSyncTest(sloppy_context_data, statement_data, kSuccess);
}

TEST_F(ParsingTest, ArrowFunctionsYieldParameterNameInGenerator) {
  const char* sloppy_function_context_data[][2] = {
      {"(function f() { (", "); });"}, {nullptr, nullptr}};

  const char* strict_function_context_data[][2] = {
      {"(function f() {'use strict'; (", "); });"}, {nullptr, nullptr}};

  const char* generator_context_data[][2] = {
      {"(function *g() {'use strict'; (", "); });"},
      {"(function *g() { (", "); });"},
      {nullptr, nullptr}};

  const char* arrow_data[] = {
      "yield => {}",      "(yield) => {}",       "(a, yield) => {}",
      "(yield, a) => {}", "(yield, ...a) => {}", "(a, ...yield) => {}",
      "({yield}) => {}",  "([yield]) => {}",     nullptr};

  RunParserSyncTest(sloppy_function_context_data, arrow_data, kSuccess);
  RunParserSyncTest(strict_function_context_data, arrow_data, kError);
  RunParserSyncTest(generator_context_data, arrow_data, kError);
}

TEST_F(ParsingTest, SuperNoErrors) {
  // Tests that parser and preparser accept 'super' keyword in right places.
  const char* context_data[][2] = {{"class C { m() { ", "; } }"},
                                   {"class C { m() { k = ", "; } }"},
                                   {"class C { m() { foo(", "); } }"},
                                   {"class C { m() { () => ", "; } }"},
                                   {nullptr, nullptr}};

  const char* statement_data[] = {"super.x",       "super[27]",
                                  "new super.x",   "new super.x()",
                                  "new super[27]", "new super[27]()",
                                  "z.super",  // Ok, property lookup.
                                  nullptr};

  RunParserSyncTest(context_data, statement_data, kSuccess);
}

TEST_F(ParsingTest, SuperErrors) {
  const char* context_data[][2] = {{"class C { m() { ", "; } }"},
                                   {"class C { m() { k = ", "; } }"},
                                   {"class C { m() { foo(", "); } }"},
                                   {"class C { m() { () => ", "; } }"},
                                   {nullptr, nullptr}};

  const char* expression_data[] = {"super",
                                   "super = x",
                                   "y = super",
                                   "f(super)",
                                   "new super",
                                   "new super()",
                                   "new super(12, 45)",
                                   "new new super",
                                   "new new super()",
                                   "new new super()()",
                                   nullptr};

  RunParserSyncTest(context_data, expression_data, kError);
}

TEST_F(ParsingTest, ImportExpressionSuccess) {
  // clang-format off
  const char* context_data[][2] = {
    {"", ""},
    {nullptr, nullptr}
  };

  const char* data[] = {
    "import(1)",
    "import(y=x)",
    "f(...[import(y=x)])",
    "x = {[import(y=x)]: 1}",
    "var {[import(y=x)]: x} = {}",
    "({[import(y=x)]: x} = {})",
    "async () => { await import(x) }",
    "() => { import(x) }",
    "(import(y=x))",
    "{import(y=x)}",
    "import(import(x))",
    "x = import(x)",
    "var x = import(x)",
    "let x = import(x)",
    "for(x of import(x)) {}",
    "import(x).then()",
    nullptr
  };

  // clang-format on

  RunParserSyncTest(context_data, data, kSuccess);
  RunModuleParserSyncTest(context_data, data, kSuccess);
}

TEST_F(ParsingTest, ImportExpressionWithOptionsSuccess) {
  i::v8_flags.harmony_import_attributes = true;

  // clang-format off
  const char* context_data[][2] = {
    {"", ""},
    {nullptr, nullptr}
  };

  const char* data[] = {
    "import(x,)",
    "import(x,1)",
    "import(x,y)",
    "import(x,y,)",
    "import(x, { 'a': 'b' })",
    "import(x, { a: 'b', 'c': 'd' },)",
    "import(x, { 'a': { b: 'c' }, 'd': 'e' },)",
    "import(x,import(y))",
    "import(x,y=z)",
    "import(x,[y, z])",
    "import(x,undefined)",
    nullptr
  };

  // clang-format on
  RunParserSyncTest(context_data, data, kSuccess);
  RunModuleParserSyncTest(context_data, data, kSuccess);
}

TEST_F(ParsingTest, ImportExpressionErrors) {
  {
    // clang-format off
    const char* context_data[][2] = {
      {"", ""},
      {"var ", ""},
      {"let ", ""},
      {"new ", ""},
      {nullptr, nullptr}
    };

    const char* data[] = {
      "import(",
      "import)",
      "import()",
      "import('x",
      "import('x']",
      "import['x')",
      "import = x",
      "import[",
      "import[]",
      "import]",
      "import[x]",
      "import{",
      "import{x",
      "import{x}",
      "import(x, y, z)",
      "import(...y)",
      "import(,)",
      "import(,y)",
      "import(;)",
      "[import]",
      "{import}",
      "import+",
      "import = 1",
      "import.wat",
      "new import(x)",
      nullptr
    };

    // clang-format on
    RunParserSyncTest(context_data, data, kError);

    // We ignore test error messages because the error message from
    // the parser/preparser is different for the same data depending
    // on the context.  For example, a top level "import{" is parsed
    // as an import declaration. The parser parses the import token
    // correctly and then shows an "Unexpected end of input" error
    // message because of the '{'. The preparser shows an "Unexpected
    // token '{'" because it's not a valid token in a CallExpression.
    RunModuleParserSyncTest(context_data, data, kError, nullptr, 0, nullptr, 0,
                            nullptr, 0, true, true);
  }

  {
    // clang-format off
    const char* context_data[][2] = {
      {"var ", ""},
      {"let ", ""},
      {nullptr, nullptr}
    };

    const char* data[] = {
      "import('x')",
      nullptr
    };

    // clang-format on
    RunParserSyncTest(context_data, data, kError);
    RunModuleParserSyncTest(context_data, data, kError);
  }

  // Import statements as arrow function params and destructuring targets.
  {
    // clang-format off
    const char* context_data[][2] = {
      {"(", ") => {}"},
      {"(a, ", ") => {}"},
      {"(1, ", ") => {}"},
      {"let f = ", " => {}"},
      {"[", "] = [1];"},
      {"{", "} = {'a': 1};"},
      {nullptr, nullptr}
    };

    const char* data[] = {
      "import(foo)",
      "import(1)",
      "import(y=x)",
      "import(import(x))",
      "import(x).then()",
      nullptr
    };

    // clang-format on
    RunParserSyncTest(context_data, data, kError);
    RunModuleParserSyncTest(context_data, data, kError);
  }
}

TEST_F(ParsingTest, ImportExpressionWithOptionsErrors) {
  {
    i::v8_flags.harmony_import_attributes = true;

    // clang-format off
    const char* context_data[][2] = {
      {"", ""},
      {"var ", ""},
      {"let ", ""},
      {"new ", ""},
      {nullptr, nullptr}
    };

    const char* data[] = {
      "import(x,,)",
      "import(x))",
      "import(x,))",
      "import(x,())",
      "import(x,y,,)",
      "import(x,y,z)",
      "import(x,y",
      "import(x,y,",
      "import(x,y(",
      nullptr
    };

    // clang-format on
    RunParserSyncTest(context_data, data, kError);
    RunModuleParserSyncTest(context_data, data, kError);
  }

  {
    // clang-format off
    const char* context_data[][2] = {
      {"var ", ""},
      {"let ", ""},
      {nullptr, nullptr}
    };

    const char* data[] = {
      "import('x',y)",
      nullptr
    };

    // clang-format on
    RunParserSyncTest(context_data, data, kError);
    RunModuleParserSyncTest(context_data, data, kError);
  }

  // Import statements as arrow function params and destructuring targets.
  {
    // clang-format off
    const char* context_data[][2] = {
      {"(", ") => {}"},
      {"(a, ", ") => {}"},
      {"(1, ", ") => {}"},
      {"let f = ", " => {}"},
      {"[", "] = [1];"},
      {"{", "} = {'a': 1};"},
      {nullptr, nullptr}
    };

    const char* data[] = {
      "import(foo,y)",
      "import(1,y)",
      "import(y=x,z)",
      "import(import(x),y)",
      "import(x,y).then()",
      nullptr
    };

    // clang-format on
    RunParserSyncTest(context_data, data, kError);
    RunModuleParserSyncTest(context_data, data, kError);
  }
}

TEST_F(ParsingTest, BasicImportAttributesParsing) {
  // clang-format off
  const char* kSources[] = {
    "import { a as b } from 'm.js' with { };",
    "import n from 'n.js' with { };",
    "export { a as b } from 'm.js' with { };",
    "export * from 'm.js' with { };",
    "import 'm.js' with { };",
    "import * as foo from 'bar.js' with { };",

    "import { a as b } from 'm.js' with { a: 'b' };",
    "import { a as b } from 'm.js' with { c: 'd' };",
    "import { a as b } from 'm.js' with { 'c': 'd' };",
    "import { a as b } from 'm.js' with { a: 'b', 'c': 'd', e: 'f' };",
    "import { a as b } from 'm.js' with { 'c': 'd', };",
    "import n from 'n.js' with { 'c': 'd' };",
    "export { a as b } from 'm.js' with { 'c': 'd' };",
    "export * from 'm.js' with { 'c': 'd' };",
    "import 'm.js' with { 'c': 'd' };",
    "import * as foo from 'bar.js' with { 'c': 'd' };",

    "import { a as b } from 'm.js' with { \nc: 'd'};",
    "import { a as b } from 'm.js' with { c:\n 'd'};",
    "import { a as b } from 'm.js' with { c:'d'\n};",

    "import { a as b } from 'm.js' with { '0': 'b', };",

    "import 'm.js'\n with { };",
    "import 'm.js' \nwith { };",
    "import { a } from 'm.js'\n with { };",
    "export * from 'm.js'\n with { };"
  };
  // clang-format on

  i::v8_flags.harmony_import_attributes = true;
  i::Isolate* isolate = i_isolate();
  i::Factory* factory = isolate->factory();

  isolate->stack_guard()->SetStackLimit(i::GetCurrentStackPosition() -
                                        128 * 1024);

  for (unsigned i = 0; i < arraysize(kSources); ++i) {
    i::DirectHandle<i::String> source =
        factory->NewStringFromAsciiChecked(kSources[i]);

    // Show that parsing as a module works
    {
      i::Handle<i::Script> script = factory->NewScript(source);
      i::UnoptimizedCompileState compile_state;
      i::ReusableUnoptimizedCompileState reusable_state(isolate);
      i::UnoptimizedCompileFlags flags =
          i::UnoptimizedCompileFlags::ForScriptCompile(isolate, *script);
      flags.set_is_module(true);
      i::ParseInfo info(isolate, flags, &compile_state, &reusable_state);
      CHECK_PARSE_PROGRAM(&info, script, isolate);
    }

    // And that parsing a script does not.
    {
      i::UnoptimizedCompileState compile_state;
      i::ReusableUnoptimizedCompileState reusable_state(isolate);
      i::DirectHandle<i::Script> script = factory->NewScript(source);
      i::UnoptimizedCompileFlags flags =
          i::UnoptimizedCompileFlags::ForScriptCompile(isolate, *script);
      i::ParseInfo info(isolate, flags, &compile_state, &reusable_state);
      CHECK(!i::parsing::ParseProgram(&info, script, isolate,
                                      parsing::ReportStatisticsMode::kYes));
      CHECK(info.pending_error_handler()->has_pending_error());
    }
  }
}

TEST_F(ParsingTest, ImportAttributesParsingErrors) {
  // clang-format off
  const char* kErrorSources[] = {
    "import { a } from 'm.js' with {;",
    "import { a } from 'm.js' with };",
    "import { a } from 'm.js' , with { };",
    "import { a } from 'm.js' with , { };",
    "import { a } from 'm.js' with { , };",
    "import { a } from 'm.js' with { b };",
    "import { a } from 'm.js' with { 'b' };",
    "import { a } from 'm.js' with { for };",
    "import { a } from 'm.js' with { with };",
    "export { a } with { };",
    "export * with { };",

    "import { a } from 'm.js' with { x: 2 };",
    "import { a } from 'm.js' with { b: c };",
    "import { a } from 'm.js' with { 'b': c };",
    "import { a } from 'm.js' with { , b: c };",
    "import { a } from 'm.js' with { a: 'b', a: 'c' };",
    "import { a } from 'm.js' with { a: 'b', 'a': 'c' };",

    "import 'm.js' assert { a: 'b' };"
  };
  // clang-format on

  i::v8_flags.harmony_import_attributes = true;
  i::Isolate* isolate = i_isolate();
  i::Factory* factory = isolate->factory();

  isolate->stack_guard()->SetStackLimit(i::GetCurrentStackPosition() -
                                        128 * 1024);

  for (unsigned i = 0; i < arraysize(kErrorSources); ++i) {
    i::DirectHandle<i::String> source =
        factory->NewStringFromAsciiChecked(kErrorSources[i]);

    i::DirectHandle<i::Script> script = factory->NewScript(source);
    i::UnoptimizedCompileState c
```