Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/asmjs/asm-parser.cc`. The request has several parts:

1. **List the functionalities:** I need to analyze the code and identify its purpose and the operations it performs.
2. **Check for Torque source:** I need to determine if the file extension was `.tq`. Based on the prompt, it's not, so this is a simple check.
3. **Relate to Javascript with examples:** If the C++ code is related to Javascript functionality, I need to provide Javascript examples demonstrating that relationship.
4. **Code logic reasoning (input/output):**  For specific code blocks, I need to provide hypothetical inputs and the expected outputs or behavior.
5. **Common programming errors:** If the code handles or prevents common programming errors, I need to provide examples of those errors.
6. **Summarize the functionality:** Provide a concise overview of the code's purpose.

**Analysis of the Code:**

The code snippet defines a class `AsmJsParser` with several methods that seem to correspond to different parts of the asm.js grammar. The methods like `RelationalExpression`, `EqualityExpression`, `BitwiseANDExpression`, etc., strongly suggest that this code is responsible for parsing and validating asm.js code.

Key observations:

* **Parsing:** The code uses a `scanner_` object to tokenize the input. The `EXPECT_TOKENn` and `Check` macros indicate parsing logic.
* **Type Checking:**  The code heavily relies on `AsmType` to represent and check the types of expressions. It distinguishes between signed integers, unsigned integers, floats, and doubles.
* **Code Generation:** The `current_function_builder_` object suggests that the parser is also involved in generating some kind of intermediate representation or bytecode (indicated by `Emit` calls like `Emit(kExprI32Add)`).
* **Function Calls:** The `ValidateCall` method handles the parsing and validation of function calls, including both regular function calls and calls to function tables.
* **Heap Access:** The `ValidateHeapAccess` method handles accesses to the asm.js heap.
* **Coercions:** The `ValidateFloatCoercion` method deals with explicit type conversions, particularly to floats.
* **Error Handling:** The `FAILn` macro indicates error reporting during parsing.

**Plan:**

1. **Functionality List:** I will list the core functionalities based on the identified methods and their actions (parsing, type checking, code generation, validation of specific asm.js features).
2. **Torque Check:**  State that the file is not a Torque source based on the `.cc` extension.
3. **Javascript Relation and Examples:** Focus on how the parsing and validation in this C++ code ensure the correct execution of asm.js code in a JavaScript environment. I will provide examples of asm.js constructs and how this parser would handle them.
4. **Code Logic Reasoning:** For simpler methods like `RelationalExpression` and `EqualityExpression`, I can provide examples of asm.js expressions and how the parser determines their type and generates corresponding intermediate code.
5. **Common Errors:**  Focus on type errors and syntax errors that this parser would catch, providing corresponding asm.js code snippets that would trigger these errors.
6. **Summary:**  Provide a concise overview of the role of `asm-parser.cc` in the V8 compilation pipeline for asm.js code.
当然，让我们来分析一下 `v8/src/asmjs/asm-parser.cc` 代码的功能。

**功能列举:**

这段代码是 V8 引擎中用于解析和验证 asm.js 代码的解析器的一部分。它的主要功能包括：

1. **语法分析 (Parsing):**  代码中的各种 `Expression` 方法（如 `RelationalExpression`, `EqualityExpression`, `BitwiseANDExpression` 等）负责根据 asm.js 的语法规则，将输入的 token 流转换成抽象语法树 (AST) 的概念表示，并进行结构化的分析。
2. **类型检查 (Type Checking):**  代码会检查 asm.js 代码中变量和表达式的类型是否符合规范。例如，在二元运算中，会检查操作数的类型是否一致或可以进行合法的类型转换。`AsmType` 类用于表示和比较类型。
3. **代码生成 (Code Generation):**  `current_function_builder_` 对象用于生成 WebAssembly (Wasm) 的指令。当解析器识别出合法的 asm.js 结构时，它会调用 `Emit` 方法来生成相应的 Wasm 指令。例如，`current_function_builder_->Emit(kExprI32Add)` 会生成一个 32 位整数加法指令。
4. **函数调用验证 (Function Call Validation):** `ValidateCall` 方法负责处理函数调用，包括：
    - 识别函数是本地定义的、导入的还是标准库函数。
    - 检查函数参数的类型是否与函数签名匹配。
    - 为函数调用生成相应的 Wasm `call` 或 `call_indirect` 指令。
5. **堆访问验证 (Heap Access Validation):** `ValidateHeapAccess` 方法用于验证对 asm.js 堆的访问，确保访问是合法的，并且索引和偏移量在有效范围内。
6. **浮点数类型转换验证 (Float Coercion Validation):** `ValidateFloatCoercion` 方法处理 `Math.fround()` 调用，确保它用于将表达式转换为 32 位浮点数。
7. **错误处理 (Error Handling):**  代码中使用了 `FAILn` 和 `FAIL` 宏来报告解析过程中遇到的语法错误或类型错误。

**关于文件扩展名和 Torque:**

根据您的描述，`v8/src/asmjs/asm-parser.cc` 的扩展名是 `.cc`，这意味着它是一个 C++ 源代码文件，而不是以 `.tq` 结尾的 V8 Torque 源代码。

**与 JavaScript 的关系及示例:**

asm.js 是 JavaScript 的一个严格子集，旨在提供接近原生性能的执行。`asm-parser.cc` 的作用是将这段特殊的 JavaScript 代码解析并转换为更底层的 WebAssembly，以便高效执行。

**JavaScript 示例：**

```javascript
function asmModule(stdlib, foreign, heap) {
  "use asm";

  var i = 0;
  var f = 0.0;
  var d = 0.0;

  function add(x, y) {
    x = x | 0; // 类型注解，表示 x 是一个 32 位有符号整数
    y = y | 0; // 类型注解，表示 y 是一个 32 位有符号整数
    return (x + y) | 0; // 返回值也是一个 32 位有符号整数
  }

  function multiply(x, y) {
    x = +x; // 类型注解，表示 x 是一个双精度浮点数
    y = +y; // 类型注解，表示 y 是一个双精度浮点数
    return +(x * y); // 返回值也是一个双精度浮点数
  }

  function accessHeap(index) {
    index = index | 0;
    heap[index] = 123;
  }

  return {
    add: add,
    multiply: multiply,
    accessHeap: accessHeap
  };
}

const stdlib = {};
const foreign = {};
const heap = new ArrayBuffer(256);
const moduleInstance = asmModule(stdlib, foreign, new Uint8Array(heap));

console.log(moduleInstance.add(10, 20)); // 输出 30
console.log(moduleInstance.multiply(2.5, 3.5)); // 输出 8.75
moduleInstance.accessHeap(0);
console.log(new Uint8Array(heap)[0]); // 输出 123
```

在这个例子中，`asm-parser.cc` 的代码会解析 `asmModule` 函数内部的 asm.js 代码，进行类型检查（例如，确保 `x` 和 `y` 在 `add` 函数中被强制转换为整数），并生成相应的 WebAssembly 指令来实现加法和乘法运算，以及堆访问。

**代码逻辑推理 (假设输入与输出):**

假设解析器当前正在处理以下 asm.js 代码片段：

```javascript
  function add(x, y) {
    x = x | 0;
    y = y | 0;
    return (x + y) | 0;
  }
```

当解析器执行到 `EqualityExpression()` 方法时，并且遇到了 `+` 运算符，根据代码：

```c++
// 6.8.10 AdditiveExpression
AsmType* AsmJsParser::AdditiveExpression() {
  AsmType* a = nullptr;
  RECURSEn(a = MultiplicativeExpression());
  for (;;) {
    switch (scanner_.Token()) {
      case '+': {
        EXPECT_TOKENn('+');
        AsmType* b = nullptr;
        RECURSEn(b = MultiplicativeExpression());
        if (a->IsA(AsmType::Intish()) && b->IsA(AsmType::Intish())) {
          current_function_builder_->Emit(kExprI32Add);
          a = AsmType::Signed();
        } else if (a->IsA(AsmType::Double()) && b->IsA(AsmType::Double())) {
          current_function_builder_->Emit(kExprF64Add);
          a = AsmType::Double();
        } else if (a->IsA(AsmType::Float()) && b->IsA(AsmType::Float())) {
          current_function_builder_->Emit(kExprF32Add);
          a = AsmType::Float();
        } else {
          FAILn("Expected intish, double, or float for operator +.");
        }
        continue;
      }
      // ... 其他 case ...
      default:
        return a;
    }
  }
}
```

**假设输入:**

- `scanner_.Token()` 返回 `'+'`。
- 之前的 `MultiplicativeExpression()` 解析出的 `x` 和 `y` 的类型 `a` 和 `b` 都是 `AsmType::Int()` (表示 32 位有符号整数)。

**预期输出:**

- `EXPECT_TOKENn('+')` 会消耗 `'+'` token。
- `RECURSEn(b = MultiplicativeExpression())` 会继续解析 `y`。
- `a->IsA(AsmType::Intish())` 和 `b->IsA(AsmType::Intish())` 都会返回 true。
- `current_function_builder_->Emit(kExprI32Add)` 会生成一个 WebAssembly 的 `i32.add` 指令。
- `a` 的类型会被更新为 `AsmType::Signed()`。
- 函数返回 `AsmType::Signed()`。

**用户常见的编程错误及示例:**

`asm-parser.cc` 可以捕获多种用户在编写 asm.js 代码时可能犯的错误：

1. **类型不匹配的运算:**

   ```javascript
   function incorrectAdd(x, y) {
     x = x | 0;
     return x + y; // 错误：y 没有进行类型注解，可能不是整数
   }
   ```

   `asm-parser.cc` 会在解析到 `x + y` 时，由于 `y` 的类型不明确（没有通过 `| 0` 等进行类型注解），会抛出一个类型错误。

2. **使用了非法的 asm.js 语法:**

   ```javascript
   function invalidAsm() {
     "use asm";
     let a = 10; // 错误：asm.js 不支持 let 声明
     return a;
   }
   ```

   解析器会识别出 `let` 关键字在 asm.js 中是非法的，并报告语法错误。

3. **堆访问越界或使用了错误的索引类型:**

   ```javascript
   function badHeapAccess(heap, index) {
     "use asm";
     var HEAP8 = new Uint8Array(heap);
     index = +index; // 错误：堆索引必须是整数
     HEAP8[index] = 123;
   }
   ```

   `ValidateHeapAccess` 方法会检查 `index` 的类型，如果不是整数类型，则会报告错误。

**功能归纳 (第三部分):**

作为第三部分，这段代码主要负责 **处理表达式和语句的解析、类型检查以及相应的 WebAssembly 代码生成**。它涵盖了算术运算、位运算、比较运算、逻辑运算、条件表达式以及函数调用等关键的 asm.js 语言特性。通过这些功能，`asm-parser.cc` 确保了输入的 asm.js 代码符合规范，并且能够被正确地转换为高效的 WebAssembly 代码执行。

总而言之，`v8/src/asmjs/asm-parser.cc` 是 V8 引擎中至关重要的一个组件，它负责将 asm.js 代码转换为可执行的 WebAssembly，并在转换过程中进行严格的语法和类型检查，从而保证了 asm.js 代码的性能和安全性。

Prompt: 
```
这是目录为v8/src/asmjs/asm-parser.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/asmjs/asm-parser.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共3部分，请归纳一下它的功能

"""
F64Le, F32Le, "<=");
      HANDLE_CASE('>', I32GtS, I32GtU, F64Gt, F32Gt, ">");
      HANDLE_CASE(TOK(GE), I32GeS, I32GeU, F64Ge, F32Ge, ">=");
#undef HANDLE_CASE
      default:
        return a;
    }
  }
}

// 6.8.12 EqualityExpression
AsmType* AsmJsParser::EqualityExpression() {
  AsmType* a = nullptr;
  RECURSEn(a = RelationalExpression());
  for (;;) {
    switch (scanner_.Token()) {
#define HANDLE_CASE(op, sop, uop, dop, fop, name)                             \
  case op: {                                                                  \
    EXPECT_TOKENn(op);                                                        \
    AsmType* b = nullptr;                                                     \
    RECURSEn(b = RelationalExpression());                                     \
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
      HANDLE_CASE(TOK(EQ), I32Eq, I32Eq, F64Eq, F32Eq, "==");
      HANDLE_CASE(TOK(NE), I32Ne, I32Ne, F64Ne, F32Ne, "!=");
#undef HANDLE_CASE
      default:
        return a;
    }
  }
}

// 6.8.13 BitwiseANDExpression
AsmType* AsmJsParser::BitwiseANDExpression() {
  AsmType* a = nullptr;
  RECURSEn(a = EqualityExpression());
  while (Check('&')) {
    AsmType* b = nullptr;
    RECURSEn(b = EqualityExpression());
    if (a->IsA(AsmType::Intish()) && b->IsA(AsmType::Intish())) {
      current_function_builder_->Emit(kExprI32And);
      a = AsmType::Signed();
    } else {
      FAILn("Expected intish for operator &.");
    }
  }
  return a;
}

// 6.8.14 BitwiseXORExpression
AsmType* AsmJsParser::BitwiseXORExpression() {
  AsmType* a = nullptr;
  RECURSEn(a = BitwiseANDExpression());
  while (Check('^')) {
    AsmType* b = nullptr;
    RECURSEn(b = BitwiseANDExpression());
    if (a->IsA(AsmType::Intish()) && b->IsA(AsmType::Intish())) {
      current_function_builder_->Emit(kExprI32Xor);
      a = AsmType::Signed();
    } else {
      FAILn("Expected intish for operator &.");
    }
  }
  return a;
}

// 6.8.15 BitwiseORExpression
AsmType* AsmJsParser::BitwiseORExpression() {
  AsmType* a = nullptr;
  call_coercion_deferred_position_ = scanner_.Position();
  RECURSEn(a = BitwiseXORExpression());
  while (Check('|')) {
    AsmType* b = nullptr;
    // Remember whether the first operand to this OR-expression has requested
    // deferred validation of the |0 annotation.
    // NOTE: This has to happen here to work recursively.
    bool requires_zero =
        AsmType::IsExactly(call_coercion_deferred_, AsmType::Signed());
    call_coercion_deferred_ = nullptr;
    // TODO(bradnelson): Make it prettier.
    bool zero = false;
    size_t old_pos;
    size_t old_code;
    if (a->IsA(AsmType::Intish()) && CheckForZero()) {
      old_pos = scanner_.Position();
      old_code = current_function_builder_->GetPosition();
      scanner_.Rewind();
      zero = true;
    }
    RECURSEn(b = BitwiseXORExpression());
    // Handle |0 specially.
    if (zero && old_pos == scanner_.Position()) {
      current_function_builder_->DeleteCodeAfter(old_code);
      a = AsmType::Signed();
      continue;
    }
    // Anything not matching |0 breaks the lookahead in {ValidateCall}.
    if (requires_zero) {
      FAILn("Expected |0 type annotation for call");
    }
    if (a->IsA(AsmType::Intish()) && b->IsA(AsmType::Intish())) {
      current_function_builder_->Emit(kExprI32Ior);
      a = AsmType::Signed();
    } else {
      FAILn("Expected intish for operator |.");
    }
  }
  DCHECK_NULL(call_coercion_deferred_);
  return a;
}

// 6.8.16 ConditionalExpression
AsmType* AsmJsParser::ConditionalExpression() {
  AsmType* test = nullptr;
  RECURSEn(test = BitwiseORExpression());
  if (Check('?')) {
    if (!test->IsA(AsmType::Int())) {
      FAILn("Expected int in condition of ternary operator.");
    }
    current_function_builder_->EmitWithU8(kExprIf, kI32Code);
    size_t fixup = current_function_builder_->GetPosition() -
                   1;  // Assumes encoding knowledge.
    AsmType* cons = nullptr;
    RECURSEn(cons = AssignmentExpression());
    current_function_builder_->Emit(kExprElse);
    EXPECT_TOKENn(':');
    AsmType* alt = nullptr;
    RECURSEn(alt = AssignmentExpression());
    current_function_builder_->Emit(kExprEnd);
    if (cons->IsA(AsmType::Int()) && alt->IsA(AsmType::Int())) {
      current_function_builder_->FixupByte(fixup, kI32Code);
      return AsmType::Int();
    } else if (cons->IsA(AsmType::Double()) && alt->IsA(AsmType::Double())) {
      current_function_builder_->FixupByte(fixup, kF64Code);
      return AsmType::Double();
    } else if (cons->IsA(AsmType::Float()) && alt->IsA(AsmType::Float())) {
      current_function_builder_->FixupByte(fixup, kF32Code);
      return AsmType::Float();
    } else {
      FAILn("Type mismatch in ternary operator.");
    }
  } else {
    return test;
  }
}

// 6.8.17 ParenthesiedExpression
AsmType* AsmJsParser::ParenthesizedExpression() {
  call_coercion_ = nullptr;
  AsmType* ret;
  EXPECT_TOKENn('(');
  RECURSEn(ret = Expression(nullptr));
  EXPECT_TOKENn(')');
  return ret;
}

// 6.9 ValidateCall
AsmType* AsmJsParser::ValidateCall() {
  AsmType* return_type = call_coercion_;
  call_coercion_ = nullptr;
  size_t call_pos = scanner_.Position();
  size_t to_number_pos = call_coercion_position_;
  bool allow_peek = (call_coercion_deferred_position_ == scanner_.Position());
  AsmJsScanner::token_t function_name = Consume();

  // Distinguish between ordinary function calls and function table calls. In
  // both cases we might be seeing the {function_name} for the first time and
  // hence allocate a {VarInfo} here, all subsequent uses of the same name then
  // need to match the information stored at this point.
  std::optional<TemporaryVariableScope> tmp_scope;
  if (Check('[')) {
    AsmType* index = nullptr;
    RECURSEn(index = EqualityExpression());
    if (!index->IsA(AsmType::Intish())) {
      FAILn("Expected intish index");
    }
    EXPECT_TOKENn('&');
    uint32_t mask = 0;
    if (!CheckForUnsigned(&mask)) {
      FAILn("Expected mask literal");
    }
    if (!base::bits::IsPowerOfTwo(mask + 1)) {
      FAILn("Expected power of 2 mask");
    }
    current_function_builder_->EmitI32Const(mask);
    current_function_builder_->Emit(kExprI32And);
    EXPECT_TOKENn(']');
    VarInfo* function_info = GetVarInfo(function_name);
    if (function_info->kind == VarKind::kUnused) {
      if (module_builder_->NumTables() == 0) {
        module_builder_->AddTable(kWasmFuncRef, 0);
      }
      uint32_t func_index = module_builder_->IncreaseTableMinSize(0, mask + 1);
      if (func_index == std::numeric_limits<uint32_t>::max()) {
        FAILn("Exceeded maximum function table size");
      }
      function_info->kind = VarKind::kTable;
      function_info->mask = mask;
      function_info->index = func_index;
      function_info->mutable_variable = false;
    } else {
      if (function_info->kind != VarKind::kTable) {
        FAILn("Expected call table");
      }
      if (function_info->mask != mask) {
        FAILn("Mask size mismatch");
      }
    }
    current_function_builder_->EmitI32Const(function_info->index);
    current_function_builder_->Emit(kExprI32Add);
    // We have to use a temporary for the correct order of evaluation.
    tmp_scope.emplace(this);
    current_function_builder_->EmitSetLocal(tmp_scope->get());
    // The position of function table calls is after the table lookup.
    call_pos = scanner_.Position();
  } else {
    VarInfo* function_info = GetVarInfo(function_name);
    if (function_info->kind == VarKind::kUnused) {
      function_info->kind = VarKind::kFunction;
      function_info->function_builder = module_builder_->AddFunction();
      function_info->index = function_info->function_builder->func_index();
      function_info->mutable_variable = false;
    } else {
      if (function_info->kind != VarKind::kFunction &&
          function_info->kind < VarKind::kImportedFunction) {
        FAILn("Expected function as call target");
      }
    }
  }

  // Parse argument list and gather types.
  CachedVector<AsmType*> param_types(&cached_asm_type_p_vectors_);
  CachedVector<AsmType*> param_specific_types(&cached_asm_type_p_vectors_);
  EXPECT_TOKENn('(');
  while (!failed_ && !Peek(')')) {
    AsmType* t;
    RECURSEn(t = AssignmentExpression());
    param_specific_types.push_back(t);
    if (t->IsA(AsmType::Int())) {
      param_types.push_back(AsmType::Int());
    } else if (t->IsA(AsmType::Float())) {
      param_types.push_back(AsmType::Float());
    } else if (t->IsA(AsmType::Double())) {
      param_types.push_back(AsmType::Double());
    } else {
      FAILn("Bad function argument type");
    }
    if (!Peek(')')) {
      EXPECT_TOKENn(',');
    }
  }
  EXPECT_TOKENn(')');

  // Reload {VarInfo} after parsing arguments as table might have grown.
  VarInfo* function_info = GetVarInfo(function_name);

  // We potentially use lookahead in order to determine the return type in case
  // it is not yet clear from the call context. Special care has to be taken to
  // ensure the non-contextual lookahead is valid. The following restrictions
  // substantiate the validity of the lookahead implemented below:
  //  - All calls (except stdlib calls) require some sort of type annotation.
  //  - The coercion to "signed" is part of the {BitwiseORExpression}, any
  //    intermittent expressions like parenthesis in `(callsite(..))|0` are
  //    syntactically not considered coercions.
  //  - The coercion to "double" as part of the {UnaryExpression} has higher
  //    precedence and wins in `+callsite(..)|0` cases. Only "float" return
  //    types are overridden in `fround(callsite(..)|0)` expressions.
  //  - Expected coercions to "signed" are flagged via {call_coercion_deferred}
  //    and later on validated as part of {BitwiseORExpression} to ensure they
  //    indeed apply to the current call expression.
  //  - The deferred validation is only allowed if {BitwiseORExpression} did
  //    promise to fulfill the request via {call_coercion_deferred_position}.
  if (allow_peek && Peek('|') &&
      function_info->kind <= VarKind::kImportedFunction &&
      (return_type == nullptr || return_type->IsA(AsmType::Float()))) {
    DCHECK_NULL(call_coercion_deferred_);
    call_coercion_deferred_ = AsmType::Signed();
    to_number_pos = scanner_.Position();
    return_type = AsmType::Signed();
  } else if (return_type == nullptr) {
    to_number_pos = call_pos;  // No conversion.
    return_type = AsmType::Void();
  }

  // Compute function type and signature based on gathered types.
  AsmType* function_type = AsmType::Function(zone(), return_type);
  for (auto t : param_types) {
    function_type->AsFunctionType()->AddArgument(t);
  }
  FunctionSig* sig = ConvertSignature(return_type, param_types);
  ModuleTypeIndex signature_index = module_builder_->AddSignature(sig, true);

  // Emit actual function invocation depending on the kind. At this point we
  // also determined the complete function type and can perform checking against
  // the expected type or update the expected type in case of first occurrence.
  if (function_info->kind == VarKind::kImportedFunction) {
    if (param_types.size() > kV8MaxWasmFunctionParams) {
      FAILn("Number of parameters exceeds internal limit");
    }
    for (auto t : param_specific_types) {
      if (!t->IsA(AsmType::Extern())) {
        FAILn("Imported function args must be type extern");
      }
    }
    if (return_type->IsA(AsmType::Float())) {
      FAILn("Imported function can't be called as float");
    }
    DCHECK_NOT_NULL(function_info->import);
    // TODO(bradnelson): Factor out.
    uint32_t index;
    auto it = function_info->import->cache.find(*sig);
    if (it != function_info->import->cache.end()) {
      index = it->second;
      DCHECK(function_info->function_defined);
    } else {
      index =
          module_builder_->AddImport(function_info->import->function_name, sig);
      function_info->import->cache[*sig] = index;
      function_info->function_defined = true;
    }
    current_function_builder_->AddAsmWasmOffset(call_pos, to_number_pos);
    current_function_builder_->EmitWithU32V(kExprCallFunction, index);
  } else if (function_info->kind > VarKind::kImportedFunction) {
    AsmCallableType* callable = function_info->type->AsCallableType();
    if (!callable) {
      FAILn("Expected callable function");
    }
    // TODO(bradnelson): Refactor AsmType to not need this.
    if (callable->CanBeInvokedWith(return_type, param_specific_types)) {
      // Return type ok.
    } else if (callable->CanBeInvokedWith(AsmType::Float(),
                                          param_specific_types)) {
      return_type = AsmType::Float();
    } else if (callable->CanBeInvokedWith(AsmType::Floatish(),
                                          param_specific_types)) {
      return_type = AsmType::Floatish();
    } else if (callable->CanBeInvokedWith(AsmType::Double(),
                                          param_specific_types)) {
      return_type = AsmType::Double();
    } else if (callable->CanBeInvokedWith(AsmType::Signed(),
                                          param_specific_types)) {
      return_type = AsmType::Signed();
    } else if (callable->CanBeInvokedWith(AsmType::Unsigned(),
                                          param_specific_types)) {
      return_type = AsmType::Unsigned();
    } else {
      FAILn("Function use doesn't match definition");
    }
    switch (function_info->kind) {
#define V(name, Name, op, sig)           \
  case VarKind::kMath##Name:             \
    current_function_builder_->Emit(op); \
    break;
      STDLIB_MATH_FUNCTION_MONOMORPHIC_LIST(V)
#undef V
#define V(name, Name, op, sig)                                    \
  case VarKind::kMath##Name:                                      \
    if (param_specific_types[0]->IsA(AsmType::DoubleQ())) {       \
      current_function_builder_->Emit(kExprF64##Name);            \
    } else if (param_specific_types[0]->IsA(AsmType::FloatQ())) { \
      current_function_builder_->Emit(kExprF32##Name);            \
    } else {                                                      \
      UNREACHABLE();                                              \
    }                                                             \
    break;
      STDLIB_MATH_FUNCTION_CEIL_LIKE_LIST(V)
#undef V
      case VarKind::kMathMin:
      case VarKind::kMathMax:
        if (param_specific_types[0]->IsA(AsmType::Double())) {
          for (size_t i = 1; i < param_specific_types.size(); ++i) {
            if (function_info->kind == VarKind::kMathMin) {
              current_function_builder_->Emit(kExprF64Min);
            } else {
              current_function_builder_->Emit(kExprF64Max);
            }
          }
        } else if (param_specific_types[0]->IsA(AsmType::Float())) {
          // NOTE: Not technically part of the asm.js spec, but Firefox
          // accepts it.
          for (size_t i = 1; i < param_specific_types.size(); ++i) {
            if (function_info->kind == VarKind::kMathMin) {
              current_function_builder_->Emit(kExprF32Min);
            } else {
              current_function_builder_->Emit(kExprF32Max);
            }
          }
        } else if (param_specific_types[0]->IsA(AsmType::Signed())) {
          TemporaryVariableScope tmp_x(this);
          TemporaryVariableScope tmp_y(this);
          for (size_t i = 1; i < param_specific_types.size(); ++i) {
            current_function_builder_->EmitSetLocal(tmp_x.get());
            current_function_builder_->EmitTeeLocal(tmp_y.get());
            current_function_builder_->EmitGetLocal(tmp_x.get());
            if (function_info->kind == VarKind::kMathMin) {
              current_function_builder_->Emit(kExprI32GeS);
            } else {
              current_function_builder_->Emit(kExprI32LeS);
            }
            current_function_builder_->EmitWithU8(kExprIf, kI32Code);
            current_function_builder_->EmitGetLocal(tmp_x.get());
            current_function_builder_->Emit(kExprElse);
            current_function_builder_->EmitGetLocal(tmp_y.get());
            current_function_builder_->Emit(kExprEnd);
          }
        } else {
          UNREACHABLE();
        }
        break;

      case VarKind::kMathAbs:
        if (param_specific_types[0]->IsA(AsmType::Signed())) {
          TemporaryVariableScope tmp(this);
          current_function_builder_->EmitTeeLocal(tmp.get());
          current_function_builder_->EmitGetLocal(tmp.get());
          current_function_builder_->EmitI32Const(31);
          current_function_builder_->Emit(kExprI32ShrS);
          current_function_builder_->EmitTeeLocal(tmp.get());
          current_function_builder_->Emit(kExprI32Xor);
          current_function_builder_->EmitGetLocal(tmp.get());
          current_function_builder_->Emit(kExprI32Sub);
        } else if (param_specific_types[0]->IsA(AsmType::DoubleQ())) {
          current_function_builder_->Emit(kExprF64Abs);
        } else if (param_specific_types[0]->IsA(AsmType::FloatQ())) {
          current_function_builder_->Emit(kExprF32Abs);
        } else {
          UNREACHABLE();
        }
        break;

      case VarKind::kMathFround:
        // NOTE: Handled in {AsmJsParser::CallExpression} specially and treated
        // as a coercion to "float" type. Cannot be reached as a call here.
        UNREACHABLE();

      default:
        UNREACHABLE();
    }
  } else {
    DCHECK(function_info->kind == VarKind::kFunction ||
           function_info->kind == VarKind::kTable);
    if (function_info->type->IsA(AsmType::None())) {
      function_info->type = function_type;
    } else {
      AsmCallableType* callable = function_info->type->AsCallableType();
      if (!callable ||
          !callable->CanBeInvokedWith(return_type, param_specific_types)) {
        FAILn("Function use doesn't match definition");
      }
    }
    if (function_info->kind == VarKind::kTable) {
      current_function_builder_->EmitGetLocal(tmp_scope->get());
      current_function_builder_->AddAsmWasmOffset(call_pos, to_number_pos);
      current_function_builder_->Emit(kExprCallIndirect);
      current_function_builder_->EmitU32V(signature_index);
      current_function_builder_->EmitU32V(0);  // table index
    } else {
      current_function_builder_->AddAsmWasmOffset(call_pos, to_number_pos);
      current_function_builder_->Emit(kExprCallFunction);
      current_function_builder_->EmitDirectCallIndex(function_info->index);
    }
  }

  return return_type;
}

// 6.9 ValidateCall - helper
bool AsmJsParser::PeekCall() {
  if (!scanner_.IsGlobal()) {
    return false;
  }
  if (GetVarInfo(scanner_.Token())->kind == VarKind::kFunction) {
    return true;
  }
  if (GetVarInfo(scanner_.Token())->kind >= VarKind::kImportedFunction) {
    return true;
  }
  if (GetVarInfo(scanner_.Token())->kind == VarKind::kUnused ||
      GetVarInfo(scanner_.Token())->kind == VarKind::kTable) {
    scanner_.Next();
    if (Peek('(') || Peek('[')) {
      scanner_.Rewind();
      return true;
    }
    scanner_.Rewind();
  }
  return false;
}

// 6.10 ValidateHeapAccess
void AsmJsParser::ValidateHeapAccess() {
  VarInfo* info = GetVarInfo(Consume());
  int32_t size = info->type->ElementSizeInBytes();
  EXPECT_TOKEN('[');
  uint32_t offset;
  if (CheckForUnsigned(&offset)) {
    // TODO(bradnelson): Check more things.
    // TODO(asmjs): Clarify and explain where this limit is coming from,
    // as it is not mandated by the spec directly.
    if (offset > 0x7FFFFFFF ||
        static_cast<uint64_t>(offset) * static_cast<uint64_t>(size) >
            0x7FFFFFFF) {
      FAIL("Heap access out of range");
    }
    if (Check(']')) {
      current_function_builder_->EmitI32Const(
          static_cast<uint32_t>(offset * size));
      // NOTE: This has to happen here to work recursively.
      heap_access_type_ = info->type;
      return;
    } else {
      scanner_.Rewind();
    }
  }
  AsmType* index_type;
  if (info->type->IsA(AsmType::Int8Array()) ||
      info->type->IsA(AsmType::Uint8Array())) {
    RECURSE(index_type = Expression(nullptr));
  } else {
    RECURSE(index_type = ShiftExpression());
    if (heap_access_shift_position_ == kNoHeapAccessShift) {
      FAIL("Expected shift of word size");
    }
    if (heap_access_shift_value_ > 3) {
      FAIL("Expected valid heap access shift");
    }
    if ((1 << heap_access_shift_value_) != size) {
      FAIL("Expected heap access shift to match heap view");
    }
    // Delete the code of the actual shift operation.
    current_function_builder_->DeleteCodeAfter(heap_access_shift_position_);
    // Mask bottom bits to match asm.js behavior.
    current_function_builder_->EmitI32Const(~(size - 1));
    current_function_builder_->Emit(kExprI32And);
  }
  if (!index_type->IsA(AsmType::Intish())) {
    FAIL("Expected intish index");
  }
  EXPECT_TOKEN(']');
  // NOTE: This has to happen here to work recursively.
  heap_access_type_ = info->type;
}

// 6.11 ValidateFloatCoercion
void AsmJsParser::ValidateFloatCoercion() {
  if (!scanner_.IsGlobal() ||
      !GetVarInfo(scanner_.Token())->type->IsA(stdlib_fround_)) {
    FAIL("Expected fround");
  }
  scanner_.Next();
  EXPECT_TOKEN('(');
  call_coercion_ = AsmType::Float();
  // NOTE: The coercion position to float is not observable from JavaScript,
  // because imported functions are not allowed to have float return type.
  call_coercion_position_ = scanner_.Position();
  AsmType* ret;
  RECURSE(ret = AssignmentExpression());
  if (ret->IsA(AsmType::Floatish())) {
    // Do nothing, as already a float.
  } else if (ret->IsA(AsmType::DoubleQ())) {
    current_function_builder_->Emit(kExprF32ConvertF64);
  } else if (ret->IsA(AsmType::Signed())) {
    current_function_builder_->Emit(kExprF32SConvertI32);
  } else if (ret->IsA(AsmType::Unsigned())) {
    current_function_builder_->Emit(kExprF32UConvertI32);
  } else {
    FAIL("Illegal conversion to float");
  }
  EXPECT_TOKEN(')');
}

void AsmJsParser::ScanToClosingParenthesis() {
  int depth = 0;
  for (;;) {
    if (Peek('(')) {
      ++depth;
    } else if (Peek(')')) {
      --depth;
      if (depth < 0) {
        break;
      }
    } else if (Peek(AsmJsScanner::kEndOfInput)) {
      break;
    }
    scanner_.Next();
  }
}

void AsmJsParser::GatherCases(ZoneVector<int32_t>* cases) {
  size_t start = scanner_.Position();
  int depth = 0;
  for (;;) {
    if (Peek('{')) {
      ++depth;
    } else if (Peek('}')) {
      --depth;
      if (depth <= 0) {
        break;
      }
    } else if (depth == 1 && Peek(TOK(case))) {
      scanner_.Next();
      uint32_t uvalue;
      bool negate = false;
      if (Check('-')) negate = true;
      if (!CheckForUnsigned(&uvalue)) {
        break;
      }
      int32_t value = static_cast<int32_t>(uvalue);
      DCHECK_IMPLIES(negate && uvalue == 0x80000000, value == kMinInt);
      if (negate && value != kMinInt) {
        value = -value;
      }
      cases->push_back(value);
    } else if (Peek(AsmJsScanner::kEndOfInput) ||
               Peek(AsmJsScanner::kParseError)) {
      break;
    }
    scanner_.Next();
  }
  scanner_.Seek(start);
}

#undef TOK
#undef RECURSEn
#undef RECURSE
#undef RECURSE_OR_RETURN
#undef EXPECT_TOKENn
#undef EXPECT_TOKEN
#undef EXPECT_TOKEN_OR_RETURN
#undef FAILn
#undef FAIL
#undef FAIL_AND_RETURN
#undef TRACE_ASM_PARSER

}  // namespace wasm
}  // namespace internal
}  // namespace v8

"""


```