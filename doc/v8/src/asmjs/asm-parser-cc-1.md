Response:
The user wants me to analyze the provided C++ code snippet from `v8/src/asmjs/asm-parser.cc`. Specifically, they want me to:

1. **Determine the function of the code.** I need to understand what this part of the parser is doing.
2. **Check if it's a Torque file.**  This is a simple check based on the file extension.
3. **Relate it to JavaScript functionality.** If applicable, I need to provide a JavaScript example.
4. **Illustrate code logic with input/output.**  This requires identifying a logical flow and simulating it.
5. **Point out common programming errors.** Based on the code, I need to identify potential mistakes a user might make.
6. **Summarize the functionality of the provided code.** This is the main goal.

Let's break down the code snippet to understand its purpose. It seems to be handling the parsing and validation of variable declarations and various statement types within an asm.js module.

- The `ParseVarDeclaration` function deals with declaring variables, potentially initializing them with constant values or global variables. It also handles the `fround()` coercion.
- The `ValidateStatement` function acts as a dispatcher, calling different functions based on the type of statement encountered (block, empty statement, if, return, loops, break, continue, switch, or expression).
- Subsequent functions like `Block`, `ExpressionStatement`, `IfStatement`, `ReturnStatement`, and the various loop structures (`WhileStatement`, `DoStatement`, `ForStatement`) are responsible for parsing and validating the specific syntax and semantics of those statements.
- `BreakStatement`, `ContinueStatement`, `LabelledStatement`, and `SwitchStatement` handle control flow constructs.

It's clear that this code is responsible for parsing and validating the syntax of asm.js code, ensuring it adheres to the asm.js specification, and potentially generating intermediate representations (like the WASM instructions being emitted by `current_function_builder_`).

Now, let's address each of the user's points:

1. **Functionality:**  This code parses and validates variable declarations and various control flow statements within an asm.js module. It checks the syntax and semantics of the code and potentially generates WebAssembly instructions.

2. **Torque:** The filename ends in `.cc`, not `.tq`, so it's not a Torque file.

3. **JavaScript Relationship:**  asm.js is a strict subset of JavaScript that can be optimized by JavaScript engines. The functionality here relates to how JavaScript engines parse and validate asm.js modules.

4. **Code Logic (Hypothetical):**
   - **Input:** An asm.js code snippet like `var x = 10; if (x > 5) return x;`
   - **Processing:** The `ParseVarDeclaration` would parse `var x = 10;`, recognizing `x` as a local variable of type int, initializing it with the value 10, and emitting a `set_local` WASM instruction. Then, `ValidateStatement` would handle the `if` statement, parsing the condition `x > 5` and the `return x` statement.
   - **Output:** (Simplified view) WASM instructions for setting a local variable, comparing it to 5, and conditionally returning the value.

5. **Common Programming Errors:**
   - Declaring a variable without initialization when the context expects one (e.g., `var x;` inside a function where it's immediately used). The parser would likely expect an initial value.
   - Using incorrect types in assignments or operations (e.g., trying to assign a double to an int variable without explicit coercion, or using non-integer values in bitwise operations). The parser would detect type mismatches.
   - Incorrectly using `break` or `continue` statements outside of loops or `switch` statements. The parser would identify illegal control flow.

6. **Summary of Functionality:** This part of the `asm-parser.cc` file is responsible for parsing and validating variable declarations and various control flow statements (like `if`, `return`, `while`, `for`, `break`, `continue`, and `switch`) in asm.js code. It checks the syntax and type correctness of these constructs and potentially emits corresponding WebAssembly instructions. It handles variable initialization, type checking in assignments and expressions, and validation of control flow logic.
这是V8源代码文件 `v8/src/asmjs/asm-parser.cc` 的一部分，主要负责 **解析和验证 asm.js 代码中的变量声明和各种语句**。

以下是针对您提出的问题的详细解答：

**1. 功能列举:**

从提供的代码片段来看，`asm-parser.cc` 的这部分功能包括：

* **解析变量声明 (`ParseVarDeclaration`)**:
    * 识别变量的类型（int, float, double）。
    * 处理变量的初始化，包括常量值和全局变量的引用。
    * 特殊处理 `fround()`，用于将 double 类型的值转换为 float 类型。
    * 将本地变量添加到本地作用域。
    * 生成相应的 WebAssembly 指令来初始化本地变量 (`kExprGlobalGet`, `kExprSetLocal`, `kExprF32Const`, `kExprF64Const`, `kExprI32Const`)。
* **验证语句 (`ValidateStatement`)**:
    * 这是一个分发函数，根据遇到的 token 类型，将控制权交给相应的语句处理函数。
    * 支持多种语句类型：
        * 代码块 (`Block`)
        * 空语句 (`EmptyStatement`)
        * `if` 语句 (`IfStatement`)
        * `return` 语句 (`ReturnStatement`)
        * 循环语句 (`IterationStatement`，包括 `while`, `do`, `for`)
        * `break` 语句 (`BreakStatement`)
        * `continue` 语句 (`ContinueStatement`)
        * `switch` 语句 (`SwitchStatement`)
        * 表达式语句 (`ExpressionStatement`)
        * 标记语句 (`LabelledStatement`)
* **解析和验证各种语句的具体实现 (`Block`, `ExpressionStatement`, `IfStatement`, `ReturnStatement`, `WhileStatement`, `DoStatement`, `ForStatement`, `BreakStatement`, `ContinueStatement`, `LabelledStatement`, `SwitchStatement`)**:
    * 检查语句的语法是否正确。
    * 递归调用自身以处理嵌套的语句。
    * 生成相应的 WebAssembly 指令来表示这些语句的语义 (`kExprBlock`, `kExprIf`, `kExprElse`, `kExprEnd`, `kExprReturn`, `kExprBr`, `kExprBrIf`, `kExprI32Eqz`, 等等)。
* **处理 `switch` 语句的 `case` 和 `default` (`ValidateCase`, `ValidateDefault`)**:
    * 解析 `case` 语句中的常量值。
    * 确保 `case` 语句的值是数字字面量。
    * 处理 `default` 语句。

**2. 是否为 Torque 源代码:**

`v8/src/asmjs/asm-parser.cc` 以 `.cc` 结尾，因此它是一个 **C++ 源代码文件**，而不是 v8 Torque 源代码。Torque 源代码文件通常以 `.tq` 结尾。

**3. 与 Javascript 的功能关系及举例:**

asm.js 是 JavaScript 的一个严格子集，旨在可以被 JavaScript 引擎高效优化。`asm-parser.cc` 的功能直接关系到 JavaScript 引擎如何理解和处理 asm.js 代码。

**Javascript 示例:**

```javascript
function asmModule(stdlib, foreign, heap) {
  "use asm";
  var x = 0;
  function add(a, b) {
    a = a | 0;
    b = b | 0;
    x = (a + b) | 0;
    return x;
  }
  return { add: add };
}
```

在这个 asm.js 模块中：

* `var x = 0;`  会由 `ParseVarDeclaration` 处理，识别 `x` 是一个本地变量，类型为 int，并初始化为 0。
* `function add(a, b) { ... }` 内部的语句会被 `ValidateStatement` 及其子函数处理：
    * `a = a | 0;` 和 `b = b | 0;` 是表达式语句，会被解析并验证类型。
    * `x = (a + b) | 0;` 是一个赋值语句，也会被解析和验证。
    * `return x;` 是一个 `return` 语句，会被 `ReturnStatement` 处理。

**4. 代码逻辑推理 (假设输入与输出):**

**假设输入 (asm.js 代码片段):**

```javascript
function f(i) {
  "use asm";
  var x = 10.5;
  var y = stdlib.Math.fround(2.7);
  if (i | 0) {
    return x;
  } else {
    return y;
  }
}
```

**处理过程和输出 (简化的 WebAssembly 指令):**

1. **`ParseVarDeclaration` 处理 `var x = 10.5;`**:
   * 识别 `x` 为本地变量。
   * 推断类型为 `double`。
   * 生成 WASM 指令 `f64.const 10.5` 和 `local.set <index_of_x>`.
2. **`ParseVarDeclaration` 处理 `var y = stdlib.Math.fround(2.7);`**:
   * 识别 `y` 为本地变量。
   * 识别 `stdlib.Math.fround`，类型为 `fround`。
   * 解析参数 `2.7`。
   * 生成 WASM 指令 `f32.const 2.7` 和 `local.set <index_of_y>`.
3. **`ValidateStatement` 处理 `if (i | 0) { ... } else { ... }`**:
   * **解析条件 `i | 0`**:
     * 生成 WASM 指令获取参数 `i` (`local.get <index_of_i>`) 和进行 `i32.or` 运算。
   * **处理 `if` 代码块**:
     * 生成 WASM 指令 `if`.
     * **处理 `return x;`**:
       * 生成 WASM 指令获取 `x` 的值 (`local.get <index_of_x>`) 和 `return`.
   * **处理 `else` 代码块**:
     * 生成 WASM 指令 `else`.
     * **处理 `return y;`**:
       * 生成 WASM 指令获取 `y` 的值 (`local.get <index_of_y>`) 和 `return`.
   * 生成 WASM 指令 `end`.

**5. 涉及用户常见的编程错误:**

* **类型不匹配:**
    ```javascript
    function f() {
      "use asm";
      var x = 10;
      x = 2.5; // 错误：尝试将 double 类型赋值给 int 类型变量
      return x;
    }
    ```
    `asm-parser.cc` 会在验证赋值语句时检测到类型不匹配并报错。
* **未声明的变量赋值:**
    ```javascript
    function f() {
      "use asm";
      y = 5; // 错误：y 未声明
      return y;
    }
    ```
    `asm-parser.cc` 会在验证赋值语句时发现 `y` 未声明并报错。
* **在需要常量的地方使用变量:**
    ```javascript
    function f(n) {
      "use asm";
      switch (n | 0) {
        case n: // 错误：case 语句需要常量值
          return 1;
      }
      return 0;
    }
    ```
    `asm-parser.cc` 在解析 `switch` 语句的 `case` 时会检查是否为常量表达式。
* **不正确的 `fround` 用法:**
    ```javascript
    function f() {
      "use asm";
      var x = stdlib.Math.fround(true); // 错误：fround 期望数字类型
      return x;
    }
    ```
    `asm-parser.cc` 在解析 `fround` 调用时会检查参数的类型。

**6. 功能归纳 (针对提供的代码片段):**

这部分 `v8/src/asmjs/asm-parser.cc` 代码的核心功能是 **解析和验证 asm.js 代码中的变量声明和控制流语句**。它负责识别变量的类型、处理变量的初始化、检查语句的语法结构是否符合 asm.js 规范，并生成相应的 WebAssembly 指令。这部分代码是 asm.js 到 WebAssembly 转换的关键步骤，确保了 asm.js 代码的正确性和可执行性。

Prompt: 
```
这是目录为v8/src/asmjs/asm-parser.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/asmjs/asm-parser.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
nt + locals->size());
          if (sinfo->type->IsA(AsmType::Int())) {
            locals->push_back(kWasmI32);
          } else if (sinfo->type->IsA(AsmType::Float())) {
            locals->push_back(kWasmF32);
          } else if (sinfo->type->IsA(AsmType::Double())) {
            locals->push_back(kWasmF64);
          } else {
            FAIL("Bad local variable definition");
          }
          current_function_builder_->EmitWithU32V(kExprGlobalGet,
                                                  VarIndex(sinfo));
          current_function_builder_->EmitSetLocal(info->index);
        } else if (sinfo->type->IsA(stdlib_fround_)) {
          EXPECT_TOKEN('(');
          bool negate = false;
          if (Check('-')) {
            negate = true;
          }
          if (CheckForDouble(&dvalue)) {
            info->kind = VarKind::kLocal;
            info->type = AsmType::Float();
            info->index = static_cast<uint32_t>(param_count + locals->size());
            locals->push_back(kWasmF32);
            if (negate) {
              dvalue = -dvalue;
            }
            float fvalue = DoubleToFloat32(dvalue);
            current_function_builder_->EmitF32Const(fvalue);
            current_function_builder_->EmitSetLocal(info->index);
          } else if (CheckForUnsigned(&uvalue)) {
            if (uvalue > 0x7FFFFFFF) {
              FAIL("Numeric literal out of range");
            }
            info->kind = VarKind::kLocal;
            info->type = AsmType::Float();
            info->index = static_cast<uint32_t>(param_count + locals->size());
            locals->push_back(kWasmF32);
            int32_t value = static_cast<int32_t>(uvalue);
            if (negate) {
              value = -value;
            }
            float fvalue = static_cast<float>(value);
            current_function_builder_->EmitF32Const(fvalue);
            current_function_builder_->EmitSetLocal(info->index);
          } else {
            FAIL("Expected variable initial value");
          }
          EXPECT_TOKEN(')');
        } else {
          FAIL("expected fround or const global");
        }
      } else if (CheckForDouble(&dvalue)) {
        info->kind = VarKind::kLocal;
        info->type = AsmType::Double();
        info->index = static_cast<uint32_t>(param_count + locals->size());
        locals->push_back(kWasmF64);
        current_function_builder_->EmitF64Const(dvalue);
        current_function_builder_->EmitSetLocal(info->index);
      } else if (CheckForUnsigned(&uvalue)) {
        info->kind = VarKind::kLocal;
        info->type = AsmType::Int();
        info->index = static_cast<uint32_t>(param_count + locals->size());
        locals->push_back(kWasmI32);
        int32_t value = static_cast<int32_t>(uvalue);
        current_function_builder_->EmitI32Const(value);
        current_function_builder_->EmitSetLocal(info->index);
      } else {
        FAIL("Expected variable initial value");
      }
      if (!Peek(',')) {
        break;
      }
      scanner_.EnterLocalScope();
      EXPECT_TOKEN(',');
      scanner_.EnterGlobalScope();
    }
    SkipSemicolon();
  }
}

// 6.5 ValidateStatement
void AsmJsParser::ValidateStatement() {
  call_coercion_ = nullptr;
  if (Peek('{')) {
    RECURSE(Block());
  } else if (Peek(';')) {
    RECURSE(EmptyStatement());
  } else if (Peek(TOK(if))) {
    RECURSE(IfStatement());
    // clang-format off
  } else if (Peek(TOK(return))) {
    // clang-format on
    RECURSE(ReturnStatement());
  } else if (IterationStatement()) {
    // Handled in IterationStatement.
  } else if (Peek(TOK(break))) {
    RECURSE(BreakStatement());
  } else if (Peek(TOK(continue))) {
    RECURSE(ContinueStatement());
  } else if (Peek(TOK(switch))) {
    RECURSE(SwitchStatement());
  } else {
    RECURSE(ExpressionStatement());
  }
}

// 6.5.1 Block
void AsmJsParser::Block() {
  bool can_break_to_block = pending_label_ != 0;
  if (can_break_to_block) {
    BareBegin(BlockKind::kNamed, pending_label_);
    current_function_builder_->EmitWithU8(kExprBlock, kVoidCode);
  }
  pending_label_ = 0;
  EXPECT_TOKEN('{');
  while (!failed_ && !Peek('}')) {
    RECURSE(ValidateStatement());
  }
  EXPECT_TOKEN('}');
  if (can_break_to_block) {
    End();
  }
}

// 6.5.2 ExpressionStatement
void AsmJsParser::ExpressionStatement() {
  if (scanner_.IsGlobal() || scanner_.IsLocal()) {
    // NOTE: Both global or local identifiers can also be used as labels.
    scanner_.Next();
    if (Peek(':')) {
      scanner_.Rewind();
      RECURSE(LabelledStatement());
      return;
    }
    scanner_.Rewind();
  }
  AsmType* ret;
  RECURSE(ret = ValidateExpression());
  if (!ret->IsA(AsmType::Void())) {
    current_function_builder_->Emit(kExprDrop);
  }
  SkipSemicolon();
}

// 6.5.3 EmptyStatement
void AsmJsParser::EmptyStatement() { EXPECT_TOKEN(';'); }

// 6.5.4 IfStatement
void AsmJsParser::IfStatement() {
  EXPECT_TOKEN(TOK(if));
  EXPECT_TOKEN('(');
  RECURSE(Expression(AsmType::Int()));
  EXPECT_TOKEN(')');
  BareBegin(BlockKind::kOther);
  current_function_builder_->EmitWithU8(kExprIf, kVoidCode);
  RECURSE(ValidateStatement());
  if (Check(TOK(else))) {
    current_function_builder_->Emit(kExprElse);
    RECURSE(ValidateStatement());
  }
  current_function_builder_->Emit(kExprEnd);
  BareEnd();
}

// 6.5.5 ReturnStatement
void AsmJsParser::ReturnStatement() {
  // clang-format off
  EXPECT_TOKEN(TOK(return));
  // clang-format on
  if (!Peek(';') && !Peek('}')) {
    // TODO(bradnelson): See if this can be factored out.
    AsmType* ret;
    RECURSE(ret = Expression(return_type_));
    if (ret->IsA(AsmType::Double())) {
      return_type_ = AsmType::Double();
    } else if (ret->IsA(AsmType::Float())) {
      return_type_ = AsmType::Float();
    } else if (ret->IsA(AsmType::Signed())) {
      return_type_ = AsmType::Signed();
    } else {
      FAIL("Invalid return type");
    }
  } else if (return_type_ == nullptr) {
    return_type_ = AsmType::Void();
  } else if (!return_type_->IsA(AsmType::Void())) {
    FAIL("Invalid void return type");
  }
  current_function_builder_->Emit(kExprReturn);
  SkipSemicolon();
}

// 6.5.6 IterationStatement
bool AsmJsParser::IterationStatement() {
  if (Peek(TOK(while))) {
    WhileStatement();
  } else if (Peek(TOK(do))) {
    DoStatement();
  } else if (Peek(TOK(for))) {
    ForStatement();
  } else {
    return false;
  }
  return true;
}

// 6.5.6 IterationStatement - while
void AsmJsParser::WhileStatement() {
  // a: block {
  Begin(pending_label_);
  //   b: loop {
  Loop(pending_label_);
  pending_label_ = 0;
  EXPECT_TOKEN(TOK(while));
  EXPECT_TOKEN('(');
  RECURSE(Expression(AsmType::Int()));
  EXPECT_TOKEN(')');
  //     if (!CONDITION) break a;
  current_function_builder_->Emit(kExprI32Eqz);
  current_function_builder_->EmitWithU8(kExprBrIf, 1);
  //     BODY
  RECURSE(ValidateStatement());
  //     continue b;
  current_function_builder_->EmitWithU8(kExprBr, 0);
  End();
  //   }
  // }
  End();
}

// 6.5.6 IterationStatement - do
void AsmJsParser::DoStatement() {
  // a: block {
  Begin(pending_label_);
  //   b: loop {
  Loop();
  //     c: block {  // but treated like loop so continue works
  BareBegin(BlockKind::kLoop, pending_label_);
  current_function_builder_->EmitWithU8(kExprBlock, kVoidCode);
  pending_label_ = 0;
  EXPECT_TOKEN(TOK(do));
  //       BODY
  RECURSE(ValidateStatement());
  EXPECT_TOKEN(TOK(while));
  End();
  //     }  // end c
  EXPECT_TOKEN('(');
  RECURSE(Expression(AsmType::Int()));
  //     if (!CONDITION) break a;
  current_function_builder_->Emit(kExprI32Eqz);
  current_function_builder_->EmitWithU8(kExprBrIf, 1);
  //     continue b;
  current_function_builder_->EmitWithU8(kExprBr, 0);
  EXPECT_TOKEN(')');
  //   }  // end b
  End();
  // }  // end a
  End();
  SkipSemicolon();
}

// 6.5.6 IterationStatement - for
void AsmJsParser::ForStatement() {
  EXPECT_TOKEN(TOK(for));
  EXPECT_TOKEN('(');
  if (!Peek(';')) {
    AsmType* ret;
    RECURSE(ret = Expression(nullptr));
    if (!ret->IsA(AsmType::Void())) {
      current_function_builder_->Emit(kExprDrop);
    }
  }
  EXPECT_TOKEN(';');
  // a: block {
  Begin(pending_label_);
  //   b: loop {
  Loop();
  //     c: block {  // but treated like loop so continue works
  BareBegin(BlockKind::kLoop, pending_label_);
  current_function_builder_->EmitWithU8(kExprBlock, kVoidCode);
  pending_label_ = 0;
  if (!Peek(';')) {
    //       if (!CONDITION) break a;
    RECURSE(Expression(AsmType::Int()));
    current_function_builder_->Emit(kExprI32Eqz);
    current_function_builder_->EmitWithU8(kExprBrIf, 2);
  }
  EXPECT_TOKEN(';');
  // Race past INCREMENT
  size_t increment_position = scanner_.Position();
  ScanToClosingParenthesis();
  EXPECT_TOKEN(')');
  //       BODY
  RECURSE(ValidateStatement());
  //     }  // end c
  End();
  //     INCREMENT
  size_t end_position = scanner_.Position();
  scanner_.Seek(increment_position);
  if (!Peek(')')) {
    RECURSE(Expression(nullptr));
    // NOTE: No explicit drop because below break is an implicit drop.
  }
  //     continue b;
  current_function_builder_->EmitWithU8(kExprBr, 0);
  scanner_.Seek(end_position);
  //   }  // end b
  End();
  // }  // end a
  End();
}

// 6.5.7 BreakStatement
void AsmJsParser::BreakStatement() {
  EXPECT_TOKEN(TOK(break));
  AsmJsScanner::token_t label_name = kTokenNone;
  if (scanner_.IsGlobal() || scanner_.IsLocal()) {
    // NOTE: Currently using globals/locals for labels too.
    label_name = Consume();
  }
  int depth = FindBreakLabelDepth(label_name);
  if (depth < 0) {
    FAIL("Illegal break");
  }
  current_function_builder_->EmitWithU32V(kExprBr, depth);
  SkipSemicolon();
}

// 6.5.8 ContinueStatement
void AsmJsParser::ContinueStatement() {
  EXPECT_TOKEN(TOK(continue));
  AsmJsScanner::token_t label_name = kTokenNone;
  if (scanner_.IsGlobal() || scanner_.IsLocal()) {
    // NOTE: Currently using globals/locals for labels too.
    label_name = Consume();
  }
  int depth = FindContinueLabelDepth(label_name);
  if (depth < 0) {
    FAIL("Illegal continue");
  }
  current_function_builder_->EmitWithU32V(kExprBr, depth);
  SkipSemicolon();
}

// 6.5.9 LabelledStatement
void AsmJsParser::LabelledStatement() {
  DCHECK(scanner_.IsGlobal() || scanner_.IsLocal());
  // NOTE: Currently using globals/locals for labels too.
  if (pending_label_ != 0) {
    FAIL("Double label unsupported");
  }
  pending_label_ = scanner_.Token();
  scanner_.Next();
  EXPECT_TOKEN(':');
  RECURSE(ValidateStatement());
}

// 6.5.10 SwitchStatement
void AsmJsParser::SwitchStatement() {
  EXPECT_TOKEN(TOK(switch));
  EXPECT_TOKEN('(');
  AsmType* test;
  RECURSE(test = Expression(nullptr));
  if (!test->IsA(AsmType::Signed())) {
    FAIL("Expected signed for switch value");
  }
  EXPECT_TOKEN(')');
  uint32_t tmp = TempVariable(0);
  current_function_builder_->EmitSetLocal(tmp);
  Begin(pending_label_);
  pending_label_ = 0;
  // TODO(bradnelson): Make less weird.
  CachedVector<int32_t> cases(&cached_int_vectors_);
  GatherCases(&cases);
  EXPECT_TOKEN('{');
  size_t count = cases.size() + 1;
  for (size_t i = 0; i < count; ++i) {
    BareBegin(BlockKind::kOther);
    current_function_builder_->EmitWithU8(kExprBlock, kVoidCode);
  }
  int table_pos = 0;
  for (auto c : cases) {
    current_function_builder_->EmitGetLocal(tmp);
    current_function_builder_->EmitI32Const(c);
    current_function_builder_->Emit(kExprI32Eq);
    current_function_builder_->EmitWithU32V(kExprBrIf, table_pos++);
  }
  current_function_builder_->EmitWithU32V(kExprBr, table_pos++);
  while (!failed_ && Peek(TOK(case))) {
    current_function_builder_->Emit(kExprEnd);
    BareEnd();
    RECURSE(ValidateCase());
  }
  current_function_builder_->Emit(kExprEnd);
  BareEnd();
  if (Peek(TOK(default))) {
    RECURSE(ValidateDefault());
  }
  EXPECT_TOKEN('}');
  End();
}

// 6.6. ValidateCase
void AsmJsParser::ValidateCase() {
  EXPECT_TOKEN(TOK(case));
  bool negate = false;
  if (Check('-')) {
    negate = true;
  }
  uint32_t uvalue;
  if (!CheckForUnsigned(&uvalue)) {
    FAIL("Expected numeric literal");
  }
  // TODO(bradnelson): Share negation plumbing.
  if ((negate && uvalue > 0x80000000) || (!negate && uvalue > 0x7FFFFFFF)) {
    FAIL("Numeric literal out of range");
  }
  int32_t value = static_cast<int32_t>(uvalue);
  DCHECK_IMPLIES(negate && uvalue == 0x80000000, value == kMinInt);
  if (negate && value != kMinInt) {
    value = -value;
  }
  EXPECT_TOKEN(':');
  while (!failed_ && !Peek('}') && !Peek(TOK(case)) && !Peek(TOK(default))) {
    RECURSE(ValidateStatement());
  }
}

// 6.7 ValidateDefault
void AsmJsParser::ValidateDefault() {
  EXPECT_TOKEN(TOK(default));
  EXPECT_TOKEN(':');
  while (!failed_ && !Peek('}')) {
    RECURSE(ValidateStatement());
  }
}

// 6.8 ValidateExpression
AsmType* AsmJsParser::ValidateExpression() {
  AsmType* ret;
  RECURSEn(ret = Expression(nullptr));
  return ret;
}

// 6.8.1 Expression
AsmType* AsmJsParser::Expression(AsmType* expected) {
  AsmType* a;
  for (;;) {
    RECURSEn(a = AssignmentExpression());
    if (Peek(',')) {
      if (a->IsA(AsmType::None())) {
        FAILn("Expected actual type");
      }
      if (!a->IsA(AsmType::Void())) {
        current_function_builder_->Emit(kExprDrop);
      }
      EXPECT_TOKENn(',');
      continue;
    }
    break;
  }
  if (expected != nullptr && !a->IsA(expected)) {
    FAILn("Unexpected type");
  }
  return a;
}

// 6.8.2 NumericLiteral
AsmType* AsmJsParser::NumericLiteral() {
  call_coercion_ = nullptr;
  double dvalue = 0.0;
  uint32_t uvalue = 0;
  if (CheckForDouble(&dvalue)) {
    current_function_builder_->EmitF64Const(dvalue);
    return AsmType::Double();
  } else if (CheckForUnsigned(&uvalue)) {
    if (uvalue <= 0x7FFFFFFF) {
      current_function_builder_->EmitI32Const(static_cast<int32_t>(uvalue));
      return AsmType::FixNum();
    } else {
      current_function_builder_->EmitI32Const(static_cast<int32_t>(uvalue));
      return AsmType::Unsigned();
    }
  } else {
    FAILn("Expected numeric literal.");
  }
}

// 6.8.3 Identifier
AsmType* AsmJsParser::Identifier() {
  call_coercion_ = nullptr;
  if (scanner_.IsLocal()) {
    VarInfo* info = GetVarInfo(Consume());
    if (info->kind != VarKind::kLocal) {
      FAILn("Undefined local variable");
    }
    current_function_builder_->EmitGetLocal(info->index);
    return info->type;
  } else if (scanner_.IsGlobal()) {
    VarInfo* info = GetVarInfo(Consume());
    if (info->kind != VarKind::kGlobal) {
      FAILn("Undefined global variable");
    }
    current_function_builder_->EmitWithU32V(kExprGlobalGet, VarIndex(info));
    return info->type;
  }
  UNREACHABLE();
}

// 6.8.4 CallExpression
AsmType* AsmJsParser::CallExpression() {
  AsmType* ret;
  if (scanner_.IsGlobal() &&
      GetVarInfo(scanner_.Token())->type->IsA(stdlib_fround_)) {
    ValidateFloatCoercion();
    return AsmType::Float();
  } else if (scanner_.IsGlobal() &&
             GetVarInfo(scanner_.Token())->type->IsA(AsmType::Heap())) {
    RECURSEn(ret = MemberExpression());
  } else if (Peek('(')) {
    RECURSEn(ret = ParenthesizedExpression());
  } else if (PeekCall()) {
    RECURSEn(ret = ValidateCall());
  } else if (scanner_.IsLocal() || scanner_.IsGlobal()) {
    RECURSEn(ret = Identifier());
  } else {
    RECURSEn(ret = NumericLiteral());
  }
  return ret;
}

// 6.8.5 MemberExpression
AsmType* AsmJsParser::MemberExpression() {
  call_coercion_ = nullptr;
  RECURSEn(ValidateHeapAccess());
  DCHECK_NOT_NULL(heap_access_type_);
  if (Peek('=')) {
    inside_heap_assignment_ = true;
    return heap_access_type_->StoreType();
  } else {
#define V(array_type, wasmload, wasmstore, type)                       \
  if (heap_access_type_->IsA(AsmType::array_type())) {                 \
    current_function_builder_->Emit(kExpr##type##AsmjsLoad##wasmload); \
    return heap_access_type_->LoadType();                              \
  }
    STDLIB_ARRAY_TYPE_LIST(V)
#undef V
    FAILn("Expected valid heap load");
  }
}

// 6.8.6 AssignmentExpression
AsmType* AsmJsParser::AssignmentExpression() {
  AsmType* ret;
  if (scanner_.IsGlobal() &&
      GetVarInfo(scanner_.Token())->type->IsA(AsmType::Heap())) {
    RECURSEn(ret = ConditionalExpression());
    if (Peek('=')) {
      if (!inside_heap_assignment_) {
        FAILn("Invalid assignment target");
      }
      inside_heap_assignment_ = false;
      DCHECK_NOT_NULL(heap_access_type_);
      AsmType* heap_type = heap_access_type_;
      EXPECT_TOKENn('=');
      AsmType* value;
      RECURSEn(value = AssignmentExpression());
      if (!value->IsA(ret)) {
        FAILn("Illegal type stored to heap view");
      }
      ret = value;
      if (heap_type->IsA(AsmType::Float32Array()) &&
          value->IsA(AsmType::DoubleQ())) {
        // Assignment to a float32 heap can be used to convert doubles.
        current_function_builder_->Emit(kExprF32ConvertF64);
        ret = AsmType::FloatQ();
      }
      if (heap_type->IsA(AsmType::Float64Array()) &&
          value->IsA(AsmType::FloatQ())) {
        // Assignment to a float64 heap can be used to convert floats.
        current_function_builder_->Emit(kExprF64ConvertF32);
        ret = AsmType::DoubleQ();
      }
#define V(array_type, wasmload, wasmstore, type)                         \
  if (heap_type->IsA(AsmType::array_type())) {                           \
    current_function_builder_->Emit(kExpr##type##AsmjsStore##wasmstore); \
    return ret;                                                          \
  }
      STDLIB_ARRAY_TYPE_LIST(V)
#undef V
    }
  } else if (scanner_.IsLocal() || scanner_.IsGlobal()) {
    bool is_local = scanner_.IsLocal();
    VarInfo* info = GetVarInfo(scanner_.Token());
    USE(is_local);
    ret = info->type;
    scanner_.Next();
    if (Check('=')) {
      // NOTE: Before this point, this might have been VarKind::kUnused even in
      // valid code, as it might be a label.
      if (info->kind == VarKind::kUnused) {
        FAILn("Undeclared assignment target");
      }
      if (!info->mutable_variable) {
        FAILn("Expected mutable variable in assignment");
      }
      DCHECK(is_local ? info->kind == VarKind::kLocal
                      : info->kind == VarKind::kGlobal);
      AsmType* value;
      RECURSEn(value = AssignmentExpression());
      if (!value->IsA(ret)) {
        FAILn("Type mismatch in assignment");
      }
      if (info->kind == VarKind::kLocal) {
        current_function_builder_->EmitTeeLocal(info->index);
      } else if (info->kind == VarKind::kGlobal) {
        current_function_builder_->EmitWithU32V(kExprGlobalSet, VarIndex(info));
        current_function_builder_->EmitWithU32V(kExprGlobalGet, VarIndex(info));
      } else {
        UNREACHABLE();
      }
      return ret;
    }
    scanner_.Rewind();
    RECURSEn(ret = ConditionalExpression());
  } else {
    RECURSEn(ret = ConditionalExpression());
  }
  return ret;
}

// 6.8.7 UnaryExpression
AsmType* AsmJsParser::UnaryExpression() {
  AsmType* ret;
  if (Check('-')) {
    uint32_t uvalue;
    if (CheckForUnsigned(&uvalue)) {
      if (uvalue == 0) {
        current_function_builder_->EmitF64Const(-0.0);
        ret = AsmType::Double();
      } else if (uvalue <= 0x80000000) {
        // TODO(bradnelson): was supposed to be 0x7FFFFFFF, check errata.
        current_function_builder_->EmitI32Const(
            base::NegateWithWraparound(static_cast<int32_t>(uvalue)));
        ret = AsmType::Signed();
      } else {
        FAILn("Integer numeric literal out of range.");
      }
    } else {
      RECURSEn(ret = UnaryExpression());
      if (ret->IsA(AsmType::Int())) {
        TemporaryVariableScope tmp(this);
        current_function_builder_->EmitSetLocal(tmp.get());
        current_function_builder_->EmitI32Const(0);
        current_function_builder_->EmitGetLocal(tmp.get());
        current_function_builder_->Emit(kExprI32Sub);
        ret = AsmType::Intish();
      } else if (ret->IsA(AsmType::DoubleQ())) {
        current_function_builder_->Emit(kExprF64Neg);
        ret = AsmType::Double();
      } else if (ret->IsA(AsmType::FloatQ())) {
        current_function_builder_->Emit(kExprF32Neg);
        ret = AsmType::Floatish();
      } else {
        FAILn("expected int/double?/float?");
      }
    }
  } else if (Peek('+')) {
    call_coercion_ = AsmType::Double();
    call_coercion_position_ = scanner_.Position();
    scanner_.Next();  // Done late for correct position.
    RECURSEn(ret = UnaryExpression());
    // TODO(bradnelson): Generalize.
    if (ret->IsA(AsmType::Signed())) {
      current_function_builder_->Emit(kExprF64SConvertI32);
      ret = AsmType::Double();
    } else if (ret->IsA(AsmType::Unsigned())) {
      current_function_builder_->Emit(kExprF64UConvertI32);
      ret = AsmType::Double();
    } else if (ret->IsA(AsmType::DoubleQ())) {
      ret = AsmType::Double();
    } else if (ret->IsA(AsmType::FloatQ())) {
      current_function_builder_->Emit(kExprF64ConvertF32);
      ret = AsmType::Double();
    } else {
      FAILn("expected signed/unsigned/double?/float?");
    }
  } else if (Check('!')) {
    RECURSEn(ret = UnaryExpression());
    if (!ret->IsA(AsmType::Int())) {
      FAILn("expected int");
    }
    current_function_builder_->Emit(kExprI32Eqz);
  } else if (Check('~')) {
    if (Check('~')) {
      RECURSEn(ret = UnaryExpression());
      if (ret->IsA(AsmType::Double())) {
        current_function_builder_->Emit(kExprI32AsmjsSConvertF64);
      } else if (ret->IsA(AsmType::FloatQ())) {
        current_function_builder_->Emit(kExprI32AsmjsSConvertF32);
      } else {
        FAILn("expected double or float?");
      }
      ret = AsmType::Signed();
    } else {
      RECURSEn(ret = UnaryExpression());
      if (!ret->IsA(AsmType::Intish())) {
        FAILn("operator ~ expects intish");
      }
      current_function_builder_->EmitI32Const(0xFFFFFFFF);
      current_function_builder_->Emit(kExprI32Xor);
      ret = AsmType::Signed();
    }
  } else {
    RECURSEn(ret = CallExpression());
  }
  return ret;
}

// 6.8.8 MultiplicativeExpression
AsmType* AsmJsParser::MultiplicativeExpression() {
  AsmType* a;
  uint32_t uvalue;
  if (CheckForUnsignedBelow(0x100000, &uvalue)) {
    if (Check('*')) {
      AsmType* type;
      RECURSEn(type = UnaryExpression());
      if (!type->IsA(AsmType::Int())) {
        FAILn("Expected int");
      }
      int32_t value = static_cast<int32_t>(uvalue);
      current_function_builder_->EmitI32Const(value);
      current_function_builder_->Emit(kExprI32Mul);
      return AsmType::Intish();
    } else {
      scanner_.Rewind();
      RECURSEn(a = UnaryExpression());
    }
  } else if (Check('-')) {
    if (!PeekForZero() && CheckForUnsignedBelow(0x100000, &uvalue)) {
      int32_t value = -static_cast<int32_t>(uvalue);
      current_function_builder_->EmitI32Const(value);
      if (Check('*')) {
        AsmType* type;
        RECURSEn(type = UnaryExpression());
        if (!type->IsA(AsmType::Int())) {
          FAILn("Expected int");
        }
        current_function_builder_->Emit(kExprI32Mul);
        return AsmType::Intish();
      }
      a = AsmType::Signed();
    } else {
      scanner_.Rewind();
      RECURSEn(a = UnaryExpression());
    }
  } else {
    RECURSEn(a = UnaryExpression());
  }
  for (;;) {
    if (Check('*')) {
      if (Check('-')) {
        if (!PeekForZero() && CheckForUnsigned(&uvalue)) {
          if (uvalue >= 0x100000) {
            FAILn("Constant multiple out of range");
          }
          if (!a->IsA(AsmType::Int())) {
            FAILn("Integer multiply of expects int");
          }
          int32_t value = -static_cast<int32_t>(uvalue);
          current_function_builder_->EmitI32Const(value);
          current_function_builder_->Emit(kExprI32Mul);
          return AsmType::Intish();
        }
        scanner_.Rewind();
      } else if (CheckForUnsigned(&uvalue)) {
        if (uvalue >= 0x100000) {
          FAILn("Constant multiple out of range");
        }
        if (!a->IsA(AsmType::Int())) {
          FAILn("Integer multiply of expects int");
        }
        int32_t value = static_cast<int32_t>(uvalue);
        current_function_builder_->EmitI32Const(value);
        current_function_builder_->Emit(kExprI32Mul);
        return AsmType::Intish();
      }
      AsmType* b;
      RECURSEn(b = UnaryExpression());
      if (a->IsA(AsmType::DoubleQ()) && b->IsA(AsmType::DoubleQ())) {
        current_function_builder_->Emit(kExprF64Mul);
        a = AsmType::Double();
      } else if (a->IsA(AsmType::FloatQ()) && b->IsA(AsmType::FloatQ())) {
        current_function_builder_->Emit(kExprF32Mul);
        a = AsmType::Floatish();
      } else {
        FAILn("expected doubles or floats");
      }
    } else if (Check('/')) {
      AsmType* b;
      RECURSEn(b = UnaryExpression());
      if (a->IsA(AsmType::DoubleQ()) && b->IsA(AsmType::DoubleQ())) {
        current_function_builder_->Emit(kExprF64Div);
        a = AsmType::Double();
      } else if (a->IsA(AsmType::FloatQ()) && b->IsA(AsmType::FloatQ())) {
        current_function_builder_->Emit(kExprF32Div);
        a = AsmType::Floatish();
      } else if (a->IsA(AsmType::Signed()) && b->IsA(AsmType::Signed())) {
        current_function_builder_->Emit(kExprI32AsmjsDivS);
        a = AsmType::Intish();
      } else if (a->IsA(AsmType::Unsigned()) && b->IsA(AsmType::Unsigned())) {
        current_function_builder_->Emit(kExprI32AsmjsDivU);
        a = AsmType::Intish();
      } else {
        FAILn("expected doubles or floats");
      }
    } else if (Check('%')) {
      AsmType* b;
      RECURSEn(b = UnaryExpression());
      if (a->IsA(AsmType::DoubleQ()) && b->IsA(AsmType::DoubleQ())) {
        current_function_builder_->Emit(kExprF64Mod);
        a = AsmType::Double();
      } else if (a->IsA(AsmType::Signed()) && b->IsA(AsmType::Signed())) {
        current_function_builder_->Emit(kExprI32AsmjsRemS);
        a = AsmType::Intish();
      } else if (a->IsA(AsmType::Unsigned()) && b->IsA(AsmType::Unsigned())) {
        current_function_builder_->Emit(kExprI32AsmjsRemU);
        a = AsmType::Intish();
      } else {
        FAILn("expected doubles or floats");
      }
    } else {
      break;
    }
  }
  return a;
}

// 6.8.9 AdditiveExpression
AsmType* AsmJsParser::AdditiveExpression() {
  AsmType* a;
  RECURSEn(a = MultiplicativeExpression());
  int n = 0;
  for (;;) {
    if (Check('+')) {
      AsmType* b;
      RECURSEn(b = MultiplicativeExpression());
      if (a->IsA(AsmType::Double()) && b->IsA(AsmType::Double())) {
        current_function_builder_->Emit(kExprF64Add);
        a = AsmType::Double();
      } else if (a->IsA(AsmType::FloatQ()) && b->IsA(AsmType::FloatQ())) {
        current_function_builder_->Emit(kExprF32Add);
        a = AsmType::Floatish();
      } else if (a->IsA(AsmType::Int()) && b->IsA(AsmType::Int())) {
        current_function_builder_->Emit(kExprI32Add);
        a = AsmType::Intish();
        n = 2;
      } else if (a->IsA(AsmType::Intish()) && b->IsA(AsmType::Intish())) {
        // TODO(bradnelson): b should really only be Int.
        // specialize intish to capture count.
        ++n;
        if (n > (1 << 20)) {
          FAILn("more than 2^20 additive values");
        }
        current_function_builder_->Emit(kExprI32Add);
      } else {
        FAILn("illegal types for +");
      }
    } else if (Check('-')) {
      AsmType* b;
      RECURSEn(b = MultiplicativeExpression());
      if (a->IsA(AsmType::Double()) && b->IsA(AsmType::Double())) {
        current_function_builder_->Emit(kExprF64Sub);
        a = AsmType::Double();
      } else if (a->IsA(AsmType::FloatQ()) && b->IsA(AsmType::FloatQ())) {
        current_function_builder_->Emit(kExprF32Sub);
        a = AsmType::Floatish();
      } else if (a->IsA(AsmType::Int()) && b->IsA(AsmType::Int())) {
        current_function_builder_->Emit(kExprI32Sub);
        a = AsmType::Intish();
        n = 2;
      } else if (a->IsA(AsmType::Intish()) && b->IsA(AsmType::Intish())) {
        // TODO(bradnelson): b should really only be Int.
        // specialize intish to capture count.
        ++n;
        if (n > (1 << 20)) {
          FAILn("more than 2^20 additive values");
        }
        current_function_builder_->Emit(kExprI32Sub);
      } else {
        FAILn("illegal types for +");
      }
    } else {
      break;
    }
  }
  return a;
}

// 6.8.10 ShiftExpression
AsmType* AsmJsParser::ShiftExpression() {
  AsmType* a = nullptr;
  RECURSEn(a = AdditiveExpression());
  heap_access_shift_position_ = kNoHeapAccessShift;
  // TODO(bradnelson): Implement backtracking to avoid emitting code
  // for the x >>> 0 case (similar to what's there for |0).
  for (;;) {
    switch (scanner_.Token()) {
      case TOK(SAR): {
        EXPECT_TOKENn(TOK(SAR));
        heap_access_shift_position_ = kNoHeapAccessShift;
        // Remember position allowing this shift-expression to be used as part
        // of a heap access operation expecting `a >> n:NumericLiteral`.
        bool imm = false;
        size_t old_pos;
        size_t old_code;
        uint32_t shift_imm;
        if (a->IsA(AsmType::Intish()) && CheckForUnsigned(&shift_imm)) {
          old_pos = scanner_.Position();
          old_code = current_function_builder_->GetPosition();
          scanner_.Rewind();
          imm = true;
        }
        AsmType* b = nullptr;
        RECURSEn(b = AdditiveExpression());
        // Check for `a >> n:NumericLiteral` pattern.
        if (imm && old_pos == scanner_.Position()) {
          heap_access_shift_position_ = old_code;
          heap_access_shift_value_ = shift_imm;
        }
        if (!(a->IsA(AsmType::Intish()) && b->IsA(AsmType::Intish()))) {
          FAILn("Expected intish for operator >>.");
        }
        current_function_builder_->Emit(kExprI32ShrS);
        a = AsmType::Signed();
        continue;
      }
#define HANDLE_CASE(op, opcode, name, result)                        \
  case TOK(op): {                                                    \
    EXPECT_TOKENn(TOK(op));                                          \
    heap_access_shift_position_ = kNoHeapAccessShift;                \
    AsmType* b = nullptr;                                            \
    RECURSEn(b = AdditiveExpression());                              \
    if (!(a->IsA(AsmType::Intish()) && b->IsA(AsmType::Intish()))) { \
      FAILn("Expected intish for operator " #name ".");              \
    }                                                                \
    current_function_builder_->Emit(kExpr##opcode);                  \
    a = AsmType::result();                                           \
    continue;                                                        \
  }
        HANDLE_CASE(SHL, I32Shl, "<<", Signed);
        HANDLE_CASE(SHR, I32ShrU, ">>>", Unsigned);
#undef HANDLE_CASE
      default:
        return a;
    }
  }
}

// 6.8.11 RelationalExpression
AsmType* AsmJsParser::RelationalExpression() {
  AsmType* a = nullptr;
  RECURSEn(a = ShiftExpression());
  for (;;) {
    switch (scanner_.Token()) {
#define HANDLE_CASE(op, sop, uop, dop, fop, name)                             \
  case op: {                                                                  \
    EXPECT_TOKENn(op);                                                        \
    AsmType* b = nullptr;                                                     \
    RECURSEn(b = ShiftExpression());                                          \
    if (a->IsA(AsmType::Signed()) && b->IsA(AsmType::Signed())) {             \
      current_function_builder_->Emit(kExpr##sop);                            \
    } else if (a->IsA(AsmType::Unsigned()) && b->IsA(AsmType::Unsigned())) {  \
      current_function_builder_->Emit(kExpr##uop);                            \
    } else if (a->IsA(AsmType::Double()) && b->IsA(AsmType::Double())) {      \
      current_function_builder_->Emit(kExpr##dop);                            \
    } else if (a->IsA(AsmType::Float()) && b->IsA(AsmType::Float())) {        \
      current_function_builder_->Emit(kExpr##fop);                            \
    } else {                                                                  \
      FAILn("Expected signed, unsigned, double, or float for operator " #name \
            ".");                                                             \
    }                                                                         \
    a = AsmType::Int();                                                       \
    continue;                                                                 \
  }
      HANDLE_CASE('<', I32LtS, I32LtU, F64Lt, F32Lt, "<");
      HANDLE_CASE(TOK(LE), I32LeS, I32LeU, 
"""


```