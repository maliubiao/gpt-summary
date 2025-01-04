Response: The user wants me to summarize the functionality of the provided C++ code snippet, which is part 2 of a larger file. I need to focus on the code in this specific part and how it relates to JavaScript, providing a JavaScript example if a connection exists.

The code seems to be parsing and validating expressions within an asm.js module. It handles various JavaScript operators like comparisons, equality checks, bitwise operations, and conditional expressions. It also deals with function calls and heap access, which are key aspects of asm.js.

Here's a breakdown of the code sections:

1. **RelationalExpression:** Handles relational operators (`<`, `>`, `<=`, `>=`).
2. **EqualityExpression:** Handles equality operators (`==`, `!=`).
3. **BitwiseANDExpression, BitwiseXORExpression, BitwiseORExpression:** Handles bitwise operators (`&`, `^`, `|`). The `BitwiseORExpression` has special handling for the `|0` coercion.
4. **ConditionalExpression:** Handles the ternary operator (`? :`).
5. **ParenthesizedExpression:** Handles expressions enclosed in parentheses.
6. **ValidateCall:**  Deals with parsing and validating function calls, including both regular function calls and calls to function table entries. It also handles type checking and potential coercions.
7. **PeekCall:** A helper function to check if the current token represents a function call.
8. **ValidateHeapAccess:** Handles accessing memory in the heap, ensuring proper indexing and bounds.
9. **ValidateFloatCoercion:**  Handles the `fround()` function call, which coerces a value to a 32-bit float.
10. **ScanToClosingParenthesis, GatherCases:** These seem like utility functions, likely for handling switch statements (though the switch statement parsing itself isn't in this part).

The connection to JavaScript is strong, as asm.js is a strict subset of JavaScript. The parser is essentially enforcing the asm.js rules on JavaScript code.
这个C++源代码文件（`asm-parser.cc` 的第 2 部分）的主要功能是**解析和验证 asm.js 规范中的各种表达式**。它负责将 asm.js 代码解析成内部表示，并在解析过程中进行类型检查和语义验证，以确保代码符合 asm.js 的规范。

具体来说，这部分代码处理以下类型的表达式：

*   **关系表达式 (RelationalExpression):**  解析和验证诸如 `<`，`>`，`<=`，`>=` 等关系运算符。
*   **相等表达式 (EqualityExpression):** 解析和验证诸如 `==`，`!=` 等相等运算符。
*   **位与表达式 (BitwiseANDExpression):** 解析和验证位与运算符 `&`。
*   **位异或表达式 (BitwiseXORExpression):** 解析和验证位异或运算符 `^`。
*   **位或表达式 (BitwiseORExpression):** 解析和验证位或运算符 `|`，并特别处理 `|0` 这种将数值强制转换为 32 位有符号整数的操作。
*   **条件表达式 (ConditionalExpression):** 解析和验证三元条件运算符 `? :`。
*   **带括号的表达式 (ParenthesizedExpression):** 处理用括号括起来的表达式。
*   **函数调用验证 (ValidateCall):**  验证函数调用，包括检查参数类型、返回值类型，以及处理标准库函数（如 `Math` 对象上的函数）的调用。
*   **检查是否是函数调用 (PeekCall):**  辅助函数，用于判断当前 token 是否表示一个函数调用。
*   **堆访问验证 (ValidateHeapAccess):** 验证对 asm.js 内存堆的访问，包括数组的索引和偏移量计算。
*   **浮点数强制转换验证 (ValidateFloatCoercion):** 验证 `fround()` 函数调用，该函数将数值强制转换为 32 位浮点数。
*   **扫描到右括号 (ScanToClosingParenthesis) 和 收集 case 语句 (GatherCases):** 这两个函数看起来像是辅助函数，可能用于处理控制流语句，例如 `switch` 语句（虽然这部分代码没有直接展示 `switch` 的解析）。

**与 JavaScript 的关系和示例：**

asm.js 是 JavaScript 的一个严格子集，可以被优化器高效地编译成机器码。这个 C++ 文件中的代码正是 V8 引擎中负责解析和验证 asm.js 代码的部分。它确保了 JavaScript 代码符合 asm.js 的规范，以便进行后续的优化。

以下是一些 JavaScript 示例，展示了这些表达式在 asm.js 中的用法，以及 `asm-parser.cc` 如何处理它们：

**1. 关系表达式和相等表达式：**

```javascript
function f(x, y) {
  "use asm";
  function compare(a, b) {
    a = +a;
    b = +b;
    return (a < b) | 0; // '<' 关系表达式
  }
  function isEqual(a, b) {
    a = a | 0;
    b = b | 0;
    return (a == b) | 0; // '==' 相等表达式
  }
  return { compare: compare, isEqual: isEqual };
}
```

`asm-parser.cc` 会解析 `a < b` 和 `a == b` 这两个表达式，并检查操作数的类型是否符合 asm.js 的要求（例如，对于浮点数比较，操作数需要是双精度浮点数）。

**2. 位运算表达式：**

```javascript
function f(x) {
  "use asm";
  function bitwise(a, b) {
    a = a | 0;
    b = b | 0;
    return (a & b) ^ (a | b); // '&', '^', '|' 位运算表达式
  }
  return { bitwise: bitwise };
}
```

`asm-parser.cc` 会解析 `a & b`，`a ^ b`，和 `a | b`，并确保操作数是 32 位整数。

**3. 条件表达式：**

```javascript
function f(x) {
  "use asm";
  function ternary(a) {
    a = a | 0;
    return (a > 0 ? 1 : 0) | 0; // '?' 条件表达式
  }
  return { ternary: ternary };
}
```

`asm-parser.cc` 会解析 `a > 0 ? 1 : 0`，检查条件 `a > 0` 的结果是否为整数，以及两个分支的返回值类型是否一致。

**4. 函数调用：**

```javascript
function f(stdlib, foreign, heap) {
  "use asm";
  var sin = stdlib.Math.sin;
  var log = foreign.log;
  function call_funcs(x) {
    x = +x;
    return +sin(x) + +log(x); // 函数调用
  }
  return { call_funcs: call_funcs };
}
```

`asm-parser.cc` 的 `ValidateCall` 函数会处理 `sin(x)` 和 `log(x)` 的调用。它会查找 `sin` 在 `stdlib` 中，`log` 在 `foreign` 中，并验证它们的参数类型和返回值类型。

**5. 堆访问：**

```javascript
function f(stdlib, foreign, heap) {
  "use asm";
  var i32 = new stdlib.Int32Array(heap);
  function load(index) {
    index = index | 0;
    return i32[index] | 0; // 堆访问
  }
  return { load: load };
}
```

`asm-parser.cc` 的 `ValidateHeapAccess` 函数会验证 `i32[index]` 的访问。它会检查 `index` 的类型，并确保访问在堆的范围内。

**6. 浮点数强制转换：**

```javascript
function f(stdlib, foreign, heap) {
  "use asm";
  var fround = stdlib.Math.fround;
  function float_conversion(x) {
    x = +x;
    return fround(x); // 浮点数强制转换
  }
  return { float_conversion: float_conversion };
}
```

`asm-parser.cc` 的 `ValidateFloatCoercion` 函数会处理 `fround(x)` 的调用，确保 `x` 可以被转换为 32 位浮点数。

总而言之，`asm-parser.cc` 的这部分代码是 V8 引擎中实现 asm.js 功能的关键部分，它通过解析和验证表达式，确保了 asm.js 代码的正确性和可优化性，从而提高了 JavaScript 在特定场景下的性能。

Prompt: 
```
这是目录为v8/src/asmjs/asm-parser.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共2部分，请归纳一下它的功能

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