Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of the V8 JavaScript engine and resides in the `v8/src/asmjs` directory.

Here's a breakdown of the request and how to approach it:

1. **Identify the Core Functionality:** The filename `asm-parser.cc` strongly suggests this code is responsible for parsing asm.js code. The presence of `#include "src/asmjs/asm-parser.h"` and references to `AsmJsParser`, `AsmType`, `WasmModuleBuilder`, and `AsmJsScanner` confirm this.

2. **Analyze Key Classes and Methods:**
    - `AsmJsParser`: This is the main class. Its constructor takes a `Zone` (memory management), `stack_limit`, and `Utf16CharacterStream` (input source). It initializes a `WasmModuleBuilder` and sets up standard library types. The `Run()` method likely orchestrates the parsing process.
    - `WasmModuleBuilder`: This class is used to construct the WebAssembly module representation from the parsed asm.js code.
    - `AsmJsScanner`: This handles tokenizing the input stream.
    - Methods like `ValidateModule`, `ValidateFunction`, `ValidateStatement`, etc., clearly indicate the steps involved in parsing and validating the asm.js code structure.

3. **Look for Javascript Relevance:** The code is in `v8/src/`, indicating its role in the V8 engine, which executes Javascript. Asm.js is a strict subset of Javascript designed for near-native performance through compilation to WebAssembly. Therefore, the connection to Javascript is inherent. We need to illustrate how asm.js code, which this parser processes, relates to Javascript.

4. **Code Logic Inference:**  The code uses macros like `FAIL_AND_RETURN`, `EXPECT_TOKEN`, `RECURSE_OR_RETURN` to manage the parsing process. It maintains a `block_stack_` to handle control flow structures. We can infer the parsing logic by examining how these macros and the validation methods are used.

5. **Common Programming Errors:** The parser aims to enforce the rules of asm.js. Violations of these rules would be common programming errors. Examples include incorrect type annotations, using features outside the asm.js subset, or violating module structure.

6. **Handle the ".tq" Check:** The question specifically asks about the `.tq` extension, indicating Torque source. We need to confirm that `.cc` signifies C++ and not Torque.

7. **Structure the Response:** The response needs to cover the functionalities, the Javascript relation (with an example), potential logic flow, common errors, and the `.tq` clarification.

**Pre-computation/Analysis:**

- **`.tq` vs. `.cc`:**  A quick check confirms that `.cc` is the standard extension for C++ source files, while `.tq` is used for Torque files within the V8 project.
- **Asm.js to Javascript Connection:**  A simple asm.js code snippet can be used to demonstrate the relationship, showing its Javascript syntax and the added type annotations.
- **Parsing Logic:** The nested `Validate` methods (e.g., `ValidateModule` calling `ValidateFunction`) suggest a recursive descent parser. The `block_stack_` indicates handling of nested blocks.
- **Common Errors:**  Thinking about the constraints of asm.js (explicit typing, restricted features) helps identify likely errors.

By following these steps, a comprehensive and accurate answer can be generated.这是 V8 引擎中用于解析 asm.js 代码的 C++ 源代码文件。以下是它的功能归纳：

**主要功能：解析 asm.js 代码并生成 WebAssembly 模块**

`v8/src/asmjs/asm-parser.cc` 的主要职责是将输入的 asm.js 代码解析成 V8 可以理解的内部表示，最终生成一个 WebAssembly (Wasm) 模块。 这个过程包括词法分析、语法分析和语义验证，以确保输入的代码符合 asm.js 的规范。

**详细功能分解：**

1. **词法分析 (通过 `AsmJsScanner`)：**  将输入的字符流分解成一个个的词法单元（tokens），例如关键字、标识符、运算符、常量等。`AsmJsScanner` 类负责执行这项任务。

2. **语法分析：**  根据 asm.js 的语法规则，将词法单元组织成语法树或类似的结构。`AsmJsParser` 类中的各种 `Validate...` 方法实现了语法分析，例如：
   - `ValidateModule()`:  验证整个 asm.js 模块的结构。
   - `ValidateModuleParameters()`: 验证模块的参数（stdlib, foreign, heap）。
   - `ValidateModuleVars()`: 验证模块级别的变量声明。
   - `ValidateFunction()`: 验证函数定义。
   - `ValidateStatement()`: 验证函数体内的语句。
   - `ValidateExport()`: 验证模块的导出部分。
   - `ValidateFunctionTable()`: 验证函数表定义。

3. **语义验证：**  检查代码的语义是否正确，例如类型匹配、变量是否已声明、函数调用是否合法等。  `AsmJsParser` 会跟踪变量的类型 (`AsmType`)，并进行类型检查。

4. **生成 WebAssembly 模块 (`WasmModuleBuilder`)：**  如果 asm.js 代码通过了语法和语义验证，`AsmJsParser` 会使用 `WasmModuleBuilder` 类来构建相应的 WebAssembly 模块。这包括：
   - 添加内存 (memory)。
   - 定义全局变量 (globals)。
   - 定义函数 (functions)。
   - 定义导出 (exports)。
   - 定义函数表 (function tables)。
   - 生成初始化代码。

5. **处理标准库 (stdlib)、外部 (foreign) 和堆 (heap)：**  asm.js 代码通常依赖于标准库函数、外部导入的对象以及用于模拟堆的 ArrayBuffer。 `AsmJsParser` 会识别并处理这些依赖。

6. **错误处理：**  如果解析过程中发现任何不符合 asm.js 规范的地方，`AsmJsParser` 会记录错误信息 (`failed_`, `failure_message_`, `failure_location_`) 并停止解析。  宏如 `FAIL_AND_RETURN` 用于方便地报告错误。

7. **管理作用域：** 使用 `scanner_.EnterLocalScope()` 和 `scanner_.EnterGlobalScope()` 来管理变量的作用域。

8. **跟踪临时变量：**  使用 `TemporaryVariableScope` 来管理函数内部的临时变量。

**关于 .tq 结尾的文件：**

你说得对，如果 `v8/src/asmjs/asm-parser.cc` 以 `.tq` 结尾，那么它将是一个 V8 Torque 源代码文件。 然而，根据你提供的信息，它以 `.cc` 结尾，所以它是 **C++ 源代码**。 Torque 是一种 V8 特有的语言，用于定义 V8 内部的运行时代码和内置函数。

**与 JavaScript 的关系及示例：**

asm.js 是 JavaScript 的一个严格子集，它的设计目标是通过静态类型和一些限制，使得 JavaScript 引擎可以对其进行优化，甚至提前编译成机器码或类似 WebAssembly 的中间表示，从而提高性能。

**JavaScript 示例 (asm.js 代码):**

```javascript
function AsmModule(stdlib, foreign, heap) {
  "use asm";

  var imul = stdlib.Math.imul;
  var buffer = new stdlib.Int32Array(heap);

  function add(x, y) {
    x = x | 0;
    y = y | 0;
    return (x + y) | 0;
  }

  function multiply(a, b) {
    a = a | 0;
    b = b | 0;
    return imul(a, b);
  }

  return {
    add: add,
    multiply: multiply
  };
}
```

**功能说明：**

-  `"use asm";` 指示这是一个 asm.js 模块。
-  `stdlib`, `foreign`, `heap` 是模块的导入，分别对应标准库、外部对象和堆。
-  变量 `imul` 从 `stdlib.Math` 中导入。
-  `buffer` 是一个 `Int32Array`，用于操作堆内存。
-  函数 `add` 和 `multiply` 使用 `| 0` 来进行类型标注，表明参数和返回值都是 32 位整数。

`v8/src/asmjs/asm-parser.cc` 的作用就是解析像上面这样的 JavaScript 代码（当它被当作 asm.js 处理时），并将其转换为更底层的 WebAssembly 表示，以便更高效地执行。

**代码逻辑推理（假设输入与输出）：**

**假设输入 (部分 asm.js 函数定义):**

```javascript
function f(x, y) {
  x = x | 0;
  y = y | 0;
  var z = 10;
  z = (x * y) | 0;
  return z | 0;
}
```

**推测的输出 (简化的 WebAssembly 指令序列，仅为说明概念):**

```wasm
;; 函数 f 的定义
func $f (param $x i32) (param $y i32) (result i32)
  ;; 局部变量 z
  local $z i32

  ;; 初始化 z = 10
  i32.const 10
  local.set $z

  ;; 计算 z = x * y
  local.get $x
  local.get $y
  i32.mul
  local.set $z

  ;; 返回 z
  local.get $z
  return
```

**说明：**  `AsmJsParser` 会识别出参数 `x` 和 `y` 的类型为 int32，局部变量 `z` 的类型为 int32，并将乘法和赋值操作转换为相应的 WebAssembly 指令。

**涉及用户常见的编程错误及示例：**

由于 asm.js 是一个受限的 JavaScript 子集，常见的编程错误包括违反这些限制：

1. **缺少或错误的类型标注：**

   ```javascript
   function add(x, y) { // 缺少类型标注
     return x + y;
   }
   ```

   **错误：** asm.js 要求对变量和函数参数进行显式的类型标注 (例如 `x = x | 0` 表示 `x` 是一个 32 位整数)。

2. **使用了 asm.js 不支持的 JavaScript 特性：**

   ```javascript
   function createObject() {
     return { value: 10 }; // asm.js 不支持创建普通对象
   }
   ```

   **错误：** asm.js 主要关注数值计算，不支持动态对象创建等复杂特性。

3. **类型不匹配：**

   ```javascript
   function multiply(x, y) {
     x = +x; // 标注为 double
     y = y | 0; // 标注为 int
     return x * y; // 混合类型运算可能导致错误
   }
   ```

   **错误：**  asm.js 强调类型的一致性，混合类型的运算需要小心处理。

4. **访问未定义的变量：**

   ```javascript
   function calculate() {
     var a = 10;
     return a + b; // b 未定义
   }
   ```

   **错误：**  在严格模式下的 asm.js 中，访问未定义的变量会导致错误。

**归纳一下它的功能 (第 1 部分):**

总而言之，`v8/src/asmjs/asm-parser.cc` 的核心功能是作为 V8 引擎中 **asm.js 代码的解析器**。 它负责接收 asm.js 源代码，进行词法分析、语法分析和语义验证，最终将其转换为可以被 V8 执行的 WebAssembly 模块。  它确保输入的代码符合 asm.js 的规范，并处理标准库、外部导入和堆内存相关的操作。

Prompt: 
```
这是目录为v8/src/asmjs/asm-parser.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/asmjs/asm-parser.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/asmjs/asm-parser.h"

#include <math.h>
#include <string.h>

#include <algorithm>
#include <optional>

#include "src/asmjs/asm-js.h"
#include "src/asmjs/asm-types.h"
#include "src/base/overflowing-math.h"
#include "src/flags/flags.h"
#include "src/numbers/conversions-inl.h"
#include "src/parsing/scanner.h"
#include "src/wasm/wasm-limits.h"
#include "src/wasm/wasm-opcodes.h"

namespace v8 {
namespace internal {
namespace wasm {

#ifdef DEBUG
#define TRACE_ASM_PARSER(...)      \
  if (v8_flags.trace_asm_parser) { \
    PrintF(__VA_ARGS__);           \
  }
#else
#define TRACE_ASM_PARSER(...)
#endif

#define FAIL_AND_RETURN(ret, msg)                                          \
  failed_ = true;                                                          \
  failure_message_ = msg;                                                  \
  failure_location_ = static_cast<int>(scanner_.Position());               \
  TRACE_ASM_PARSER("[asm.js failure: %s, token: '%s', see: %s:%d]\n", msg, \
                   scanner_.Name(scanner_.Token()).c_str(), __FILE__,      \
                   __LINE__);                                              \
  return ret;

#define FAIL(msg) FAIL_AND_RETURN(, msg)
#define FAILn(msg) FAIL_AND_RETURN(nullptr, msg)

#define EXPECT_TOKEN_OR_RETURN(ret, token)      \
  do {                                          \
    if (scanner_.Token() != token) {            \
      FAIL_AND_RETURN(ret, "Unexpected token"); \
    }                                           \
    scanner_.Next();                            \
  } while (false)

#define EXPECT_TOKEN(token) EXPECT_TOKEN_OR_RETURN(, token)
#define EXPECT_TOKENn(token) EXPECT_TOKEN_OR_RETURN(nullptr, token)

#define RECURSE_OR_RETURN(ret, call)                                       \
  do {                                                                     \
    DCHECK(!failed_);                                                      \
    if (GetCurrentStackPosition() < stack_limit_) {                        \
      FAIL_AND_RETURN(ret, "Stack overflow while parsing asm.js module."); \
    }                                                                      \
    call;                                                                  \
    if (failed_) return ret;                                               \
  } while (false)

#define RECURSE(call) RECURSE_OR_RETURN(, call)
#define RECURSEn(call) RECURSE_OR_RETURN(nullptr, call)

#define TOK(name) AsmJsScanner::kToken_##name

AsmJsParser::AsmJsParser(Zone* zone, uintptr_t stack_limit,
                         Utf16CharacterStream* stream)
    : zone_(zone),
      scanner_(stream),
      module_builder_(zone->New<WasmModuleBuilder>(zone)),
      stack_limit_(stack_limit),
      block_stack_(zone),
      global_imports_(zone) {
  module_builder_->AddMemory(0);
  InitializeStdlibTypes();
}

void AsmJsParser::InitializeStdlibTypes() {
  auto* d = AsmType::Double();
  auto* dq = AsmType::DoubleQ();
  stdlib_dq2d_ = AsmType::Function(zone(), d);
  stdlib_dq2d_->AsFunctionType()->AddArgument(dq);

  stdlib_dqdq2d_ = AsmType::Function(zone(), d);
  stdlib_dqdq2d_->AsFunctionType()->AddArgument(dq);
  stdlib_dqdq2d_->AsFunctionType()->AddArgument(dq);

  auto* f = AsmType::Float();
  auto* fh = AsmType::Floatish();
  auto* fq = AsmType::FloatQ();
  auto* fq2fh = AsmType::Function(zone(), fh);
  fq2fh->AsFunctionType()->AddArgument(fq);

  auto* s = AsmType::Signed();
  auto* u = AsmType::Unsigned();
  auto* s2u = AsmType::Function(zone(), u);
  s2u->AsFunctionType()->AddArgument(s);

  auto* i = AsmType::Int();
  stdlib_i2s_ = AsmType::Function(zone_, s);
  stdlib_i2s_->AsFunctionType()->AddArgument(i);

  stdlib_ii2s_ = AsmType::Function(zone(), s);
  stdlib_ii2s_->AsFunctionType()->AddArgument(i);
  stdlib_ii2s_->AsFunctionType()->AddArgument(i);

  // The signatures in "9 Standard Library" of the spec draft are outdated and
  // have been superseded with the following by an errata:
  //  - Math.min/max : (signed, signed...) -> signed
  //                   (double, double...) -> double
  //                   (float, float...) -> float
  auto* minmax_d = AsmType::MinMaxType(zone(), d, d);
  auto* minmax_f = AsmType::MinMaxType(zone(), f, f);
  auto* minmax_s = AsmType::MinMaxType(zone(), s, s);
  stdlib_minmax_ = AsmType::OverloadedFunction(zone());
  stdlib_minmax_->AsOverloadedFunctionType()->AddOverload(minmax_s);
  stdlib_minmax_->AsOverloadedFunctionType()->AddOverload(minmax_f);
  stdlib_minmax_->AsOverloadedFunctionType()->AddOverload(minmax_d);

  // The signatures in "9 Standard Library" of the spec draft are outdated and
  // have been superseded with the following by an errata:
  //  - Math.abs : (signed) -> unsigned
  //               (double?) -> double
  //               (float?) -> floatish
  stdlib_abs_ = AsmType::OverloadedFunction(zone());
  stdlib_abs_->AsOverloadedFunctionType()->AddOverload(s2u);
  stdlib_abs_->AsOverloadedFunctionType()->AddOverload(stdlib_dq2d_);
  stdlib_abs_->AsOverloadedFunctionType()->AddOverload(fq2fh);

  // The signatures in "9 Standard Library" of the spec draft are outdated and
  // have been superseded with the following by an errata:
  //  - Math.ceil/floor/sqrt : (double?) -> double
  //                           (float?) -> floatish
  stdlib_ceil_like_ = AsmType::OverloadedFunction(zone());
  stdlib_ceil_like_->AsOverloadedFunctionType()->AddOverload(stdlib_dq2d_);
  stdlib_ceil_like_->AsOverloadedFunctionType()->AddOverload(fq2fh);

  stdlib_fround_ = AsmType::FroundType(zone());
}

FunctionSig* AsmJsParser::ConvertSignature(AsmType* return_type,
                                           const ZoneVector<AsmType*>& params) {
  FunctionSig::Builder sig_builder(
      zone(), !return_type->IsA(AsmType::Void()) ? 1 : 0, params.size());
  for (auto param : params) {
    if (param->IsA(AsmType::Double())) {
      sig_builder.AddParam(kWasmF64);
    } else if (param->IsA(AsmType::Float())) {
      sig_builder.AddParam(kWasmF32);
    } else if (param->IsA(AsmType::Int())) {
      sig_builder.AddParam(kWasmI32);
    } else {
      UNREACHABLE();
    }
  }
  if (!return_type->IsA(AsmType::Void())) {
    if (return_type->IsA(AsmType::Double())) {
      sig_builder.AddReturn(kWasmF64);
    } else if (return_type->IsA(AsmType::Float())) {
      sig_builder.AddReturn(kWasmF32);
    } else if (return_type->IsA(AsmType::Signed())) {
      sig_builder.AddReturn(kWasmI32);
    } else {
      UNREACHABLE();
    }
  }
  return sig_builder.Get();
}

bool AsmJsParser::Run() {
  ValidateModule();
  return !failed_;
}

class V8_NODISCARD AsmJsParser::TemporaryVariableScope {
 public:
  explicit TemporaryVariableScope(AsmJsParser* parser) : parser_(parser) {
    local_depth_ = parser_->function_temp_locals_depth_;
    parser_->function_temp_locals_depth_++;
  }
  ~TemporaryVariableScope() {
    DCHECK_EQ(local_depth_, parser_->function_temp_locals_depth_ - 1);
    parser_->function_temp_locals_depth_--;
  }
  uint32_t get() const { return parser_->TempVariable(local_depth_); }

 private:
  AsmJsParser* parser_;
  int local_depth_;
};

wasm::AsmJsParser::VarInfo* AsmJsParser::GetVarInfo(
    AsmJsScanner::token_t token) {
  const bool is_global = AsmJsScanner::IsGlobal(token);
  DCHECK(is_global || AsmJsScanner::IsLocal(token));
  base::Vector<VarInfo>& var_info =
      is_global ? global_var_info_ : local_var_info_;
  size_t old_capacity = var_info.size();
  size_t index = is_global ? AsmJsScanner::GlobalIndex(token)
                           : AsmJsScanner::LocalIndex(token);
  if (is_global && index + 1 > num_globals_) num_globals_ = index + 1;
  if (index + 1 > old_capacity) {
    size_t new_size = std::max(2 * old_capacity, index + 1);
    base::Vector<VarInfo> new_info = zone_->NewVector<VarInfo>(new_size);
    std::copy(var_info.begin(), var_info.end(), new_info.begin());
    var_info = new_info;
  }
  return &var_info[index];
}

uint32_t AsmJsParser::VarIndex(VarInfo* info) {
  DCHECK_EQ(info->kind, VarKind::kGlobal);
  return info->index + static_cast<uint32_t>(global_imports_.size());
}

void AsmJsParser::AddGlobalImport(base::Vector<const char> name, AsmType* type,
                                  ValueType vtype, bool mutable_variable,
                                  VarInfo* info) {
  // Allocate a separate variable for the import.
  // TODO(asmjs): Consider using the imported global directly instead of
  // allocating a separate global variable for immutable (i.e. const) imports.
  DeclareGlobal(info, mutable_variable, type, vtype,
                WasmInitExpr::DefaultValue(vtype));

  // Record the need to initialize the global from the import.
  global_imports_.push_back({name, vtype, info});
}

void AsmJsParser::DeclareGlobal(VarInfo* info, bool mutable_variable,
                                AsmType* type, ValueType vtype,
                                WasmInitExpr init) {
  info->kind = VarKind::kGlobal;
  info->type = type;
  info->index = module_builder_->AddGlobal(vtype, true, init);
  info->mutable_variable = mutable_variable;
}

void AsmJsParser::DeclareStdlibFunc(VarInfo* info, VarKind kind,
                                    AsmType* type) {
  info->kind = kind;
  info->type = type;
  info->index = 0;  // unused
  info->mutable_variable = false;
}

uint32_t AsmJsParser::TempVariable(int index) {
  if (index + 1 > function_temp_locals_used_) {
    function_temp_locals_used_ = index + 1;
  }
  return function_temp_locals_offset_ + index;
}

base::Vector<const char> AsmJsParser::CopyCurrentIdentifierString() {
  return zone()->CloneVector(base::VectorOf(scanner_.GetIdentifierString()));
}

void AsmJsParser::SkipSemicolon() {
  if (Check(';')) {
    // Had a semicolon.
  } else if (!Peek('}') && !scanner_.IsPrecededByNewline()) {
    FAIL("Expected ;");
  }
}

void AsmJsParser::Begin(AsmJsScanner::token_t label) {
  BareBegin(BlockKind::kRegular, label);
  current_function_builder_->EmitWithU8(kExprBlock, kVoidCode);
}

void AsmJsParser::Loop(AsmJsScanner::token_t label) {
  BareBegin(BlockKind::kLoop, label);
  size_t position = scanner_.Position();
  current_function_builder_->AddAsmWasmOffset(position, position);
  current_function_builder_->EmitWithU8(kExprLoop, kVoidCode);
}

void AsmJsParser::End() {
  BareEnd();
  current_function_builder_->Emit(kExprEnd);
}

void AsmJsParser::BareBegin(BlockKind kind, AsmJsScanner::token_t label) {
  BlockInfo info;
  info.kind = kind;
  info.label = label;
  block_stack_.push_back(info);
}

void AsmJsParser::BareEnd() {
  DCHECK_GT(block_stack_.size(), 0);
  block_stack_.pop_back();
}

int AsmJsParser::FindContinueLabelDepth(AsmJsScanner::token_t label) {
  int count = 0;
  for (auto it = block_stack_.rbegin(); it != block_stack_.rend();
       ++it, ++count) {
    // A 'continue' statement targets ...
    //  - The innermost {kLoop} block if no label is given.
    //  - The matching {kLoop} block (when a label is provided).
    if (it->kind == BlockKind::kLoop &&
        (label == kTokenNone || it->label == label)) {
      return count;
    }
  }
  return -1;
}

int AsmJsParser::FindBreakLabelDepth(AsmJsScanner::token_t label) {
  int count = 0;
  for (auto it = block_stack_.rbegin(); it != block_stack_.rend();
       ++it, ++count) {
    // A 'break' statement targets ...
    //  - The innermost {kRegular} block if no label is given.
    //  - The matching {kRegular} or {kNamed} block (when a label is provided).
    if ((it->kind == BlockKind::kRegular &&
         (label == kTokenNone || it->label == label)) ||
        (it->kind == BlockKind::kNamed && it->label == label)) {
      return count;
    }
  }
  return -1;
}

// 6.1 ValidateModule
void AsmJsParser::ValidateModule() {
  RECURSE(ValidateModuleParameters());
  EXPECT_TOKEN('{');
  EXPECT_TOKEN(TOK(UseAsm));
  RECURSE(SkipSemicolon());
  RECURSE(ValidateModuleVars());
  while (Peek(TOK(function))) {
    RECURSE(ValidateFunction());
  }
  while (Peek(TOK(var))) {
    RECURSE(ValidateFunctionTable());
  }
  RECURSE(ValidateExport());
  RECURSE(SkipSemicolon());
  EXPECT_TOKEN('}');

  // Check that all functions were eventually defined.
  for (auto& info : global_var_info_.SubVector(0, num_globals_)) {
    if (info.kind == VarKind::kFunction && !info.function_defined) {
      FAIL("Undefined function");
    }
    if (info.kind == VarKind::kTable && !info.function_defined) {
      FAIL("Undefined function table");
    }
    if (info.kind == VarKind::kImportedFunction && !info.function_defined) {
      // For imported functions without a single call site, we insert a dummy
      // import here to preserve the fact that there actually was an import.
      FunctionSig* void_void_sig = FunctionSig::Builder(zone(), 0, 0).Get();
      module_builder_->AddImport(info.import->function_name, void_void_sig);
    }
  }

  // Add start function to initialize things.
  WasmFunctionBuilder* start = module_builder_->AddFunction();
  module_builder_->MarkStartFunction(start);
  for (auto& global_import : global_imports_) {
    uint32_t import_index = module_builder_->AddGlobalImport(
        global_import.import_name, global_import.value_type,
        false /* mutability */);
    start->EmitWithU32V(kExprGlobalGet, import_index);
    start->EmitWithU32V(kExprGlobalSet, VarIndex(global_import.var_info));
  }
  start->Emit(kExprEnd);
  FunctionSig::Builder b(zone(), 0, 0);
  start->SetSignature(b.Get());
}

// 6.1 ValidateModule - parameters
void AsmJsParser::ValidateModuleParameters() {
  EXPECT_TOKEN('(');
  stdlib_name_ = 0;
  foreign_name_ = 0;
  heap_name_ = 0;
  if (!Peek(')')) {
    if (!scanner_.IsGlobal()) {
      FAIL("Expected stdlib parameter");
    }
    stdlib_name_ = Consume();
    if (!Peek(')')) {
      EXPECT_TOKEN(',');
      if (!scanner_.IsGlobal()) {
        FAIL("Expected foreign parameter");
      }
      foreign_name_ = Consume();
      if (stdlib_name_ == foreign_name_) {
        FAIL("Duplicate parameter name");
      }
      if (!Peek(')')) {
        EXPECT_TOKEN(',');
        if (!scanner_.IsGlobal()) {
          FAIL("Expected heap parameter");
        }
        heap_name_ = Consume();
        if (heap_name_ == stdlib_name_ || heap_name_ == foreign_name_) {
          FAIL("Duplicate parameter name");
        }
      }
    }
  }
  EXPECT_TOKEN(')');
}

// 6.1 ValidateModule - variables
void AsmJsParser::ValidateModuleVars() {
  while (Peek(TOK(var)) || Peek(TOK(const))) {
    bool mutable_variable = true;
    if (Check(TOK(var))) {
      // Had a var.
    } else {
      EXPECT_TOKEN(TOK(const));
      mutable_variable = false;
    }
    for (;;) {
      RECURSE(ValidateModuleVar(mutable_variable));
      if (Check(',')) {
        continue;
      }
      break;
    }
    SkipSemicolon();
  }
}

// 6.1 ValidateModule - one variable
void AsmJsParser::ValidateModuleVar(bool mutable_variable) {
  if (!scanner_.IsGlobal()) {
    FAIL("Expected identifier");
  }
  AsmJsScanner::token_t identifier = Consume();
  if (identifier == stdlib_name_ || identifier == foreign_name_ ||
      identifier == heap_name_) {
    FAIL("Cannot shadow parameters");
  }
  VarInfo* info = GetVarInfo(identifier);
  if (info->kind != VarKind::kUnused) {
    FAIL("Redefinition of variable");
  }
  EXPECT_TOKEN('=');
  double dvalue = 0.0;
  uint32_t uvalue = 0;
  if (CheckForDouble(&dvalue)) {
    DeclareGlobal(info, mutable_variable, AsmType::Double(), kWasmF64,
                  WasmInitExpr(dvalue));
  } else if (CheckForUnsigned(&uvalue)) {
    if (uvalue > 0x7FFFFFFF) {
      FAIL("Numeric literal out of range");
    }
    DeclareGlobal(info, mutable_variable,
                  mutable_variable ? AsmType::Int() : AsmType::Signed(),
                  kWasmI32, WasmInitExpr(static_cast<int32_t>(uvalue)));
  } else if (Check('-')) {
    if (CheckForDouble(&dvalue)) {
      DeclareGlobal(info, mutable_variable, AsmType::Double(), kWasmF64,
                    WasmInitExpr(-dvalue));
    } else if (CheckForUnsigned(&uvalue)) {
      if (uvalue > 0x7FFFFFFF) {
        FAIL("Numeric literal out of range");
      }
      if (uvalue == 0) {
        // '-0' is treated as float.
        DeclareGlobal(info, mutable_variable, AsmType::Float(), kWasmF32,
                      WasmInitExpr(-0.f));
      } else {
        DeclareGlobal(info, mutable_variable,
                      mutable_variable ? AsmType::Int() : AsmType::Signed(),
                      kWasmI32, WasmInitExpr(-static_cast<int32_t>(uvalue)));
      }
    } else {
      FAIL("Expected numeric literal");
    }
  } else if (Check(TOK(new))) {
    RECURSE(ValidateModuleVarNewStdlib(info));
  } else if (Check(stdlib_name_)) {
    EXPECT_TOKEN('.');
    RECURSE(ValidateModuleVarStdlib(info));
  } else if (Peek(foreign_name_) || Peek('+')) {
    RECURSE(ValidateModuleVarImport(info, mutable_variable));
  } else if (scanner_.IsGlobal()) {
    RECURSE(ValidateModuleVarFromGlobal(info, mutable_variable));
  } else {
    FAIL("Bad variable declaration");
  }
}

// 6.1 ValidateModule - global float declaration
void AsmJsParser::ValidateModuleVarFromGlobal(VarInfo* info,
                                              bool mutable_variable) {
  VarInfo* src_info = GetVarInfo(Consume());
  if (!src_info->type->IsA(stdlib_fround_)) {
    if (src_info->mutable_variable) {
      FAIL("Can only use immutable variables in global definition");
    }
    if (mutable_variable) {
      FAIL("Can only define immutable variables with other immutables");
    }
    if (!src_info->type->IsA(AsmType::Int()) &&
        !src_info->type->IsA(AsmType::Float()) &&
        !src_info->type->IsA(AsmType::Double())) {
      FAIL("Expected int, float, double, or fround for global definition");
    }
    info->kind = VarKind::kGlobal;
    info->type = src_info->type;
    info->index = src_info->index;
    info->mutable_variable = false;
    return;
  }
  EXPECT_TOKEN('(');
  bool negate = false;
  if (Check('-')) {
    negate = true;
  }
  double dvalue = 0.0;
  uint32_t uvalue = 0;
  if (CheckForDouble(&dvalue)) {
    if (negate) {
      dvalue = -dvalue;
    }
    DeclareGlobal(info, mutable_variable, AsmType::Float(), kWasmF32,
                  WasmInitExpr(DoubleToFloat32(dvalue)));
  } else if (CheckForUnsigned(&uvalue)) {
    dvalue = uvalue;
    if (negate) {
      dvalue = -dvalue;
    }
    DeclareGlobal(info, mutable_variable, AsmType::Float(), kWasmF32,
                  WasmInitExpr(static_cast<float>(dvalue)));
  } else {
    FAIL("Expected numeric literal");
  }
  EXPECT_TOKEN(')');
}

// 6.1 ValidateModule - foreign imports
void AsmJsParser::ValidateModuleVarImport(VarInfo* info,
                                          bool mutable_variable) {
  if (Check('+')) {
    EXPECT_TOKEN(foreign_name_);
    EXPECT_TOKEN('.');
    base::Vector<const char> name = CopyCurrentIdentifierString();
    AddGlobalImport(name, AsmType::Double(), kWasmF64, mutable_variable, info);
    scanner_.Next();
  } else {
    EXPECT_TOKEN(foreign_name_);
    EXPECT_TOKEN('.');
    base::Vector<const char> name = CopyCurrentIdentifierString();
    scanner_.Next();
    if (Check('|')) {
      if (!CheckForZero()) {
        FAIL("Expected |0 type annotation for foreign integer import");
      }
      AddGlobalImport(name, AsmType::Int(), kWasmI32, mutable_variable, info);
    } else {
      info->kind = VarKind::kImportedFunction;
      info->import = zone()->New<FunctionImportInfo>(name, zone());
      info->mutable_variable = false;
    }
  }
}

// 6.1 ValidateModule - one variable
// 9 - Standard Library - heap types
void AsmJsParser::ValidateModuleVarNewStdlib(VarInfo* info) {
  EXPECT_TOKEN(stdlib_name_);
  EXPECT_TOKEN('.');
  switch (Consume()) {
#define V(name, _junk1, _junk2, _junk3)                          \
  case TOK(name):                                                \
    DeclareStdlibFunc(info, VarKind::kSpecial, AsmType::name()); \
    stdlib_uses_.Add(StandardMember::k##name);                   \
    break;
    STDLIB_ARRAY_TYPE_LIST(V)
#undef V
    default:
      FAIL("Expected ArrayBuffer view");
  }
  EXPECT_TOKEN('(');
  EXPECT_TOKEN(heap_name_);
  EXPECT_TOKEN(')');
}

// 6.1 ValidateModule - one variable
// 9 - Standard Library
void AsmJsParser::ValidateModuleVarStdlib(VarInfo* info) {
  if (Check(TOK(Math))) {
    EXPECT_TOKEN('.');
    switch (Consume()) {
#define V(name, const_value)                                \
  case TOK(name):                                           \
    DeclareGlobal(info, false, AsmType::Double(), kWasmF64, \
                  WasmInitExpr(const_value));               \
    stdlib_uses_.Add(StandardMember::kMath##name);          \
    break;
      STDLIB_MATH_VALUE_LIST(V)
#undef V
#define V(name, Name, op, sig)                                      \
  case TOK(name):                                                   \
    DeclareStdlibFunc(info, VarKind::kMath##Name, stdlib_##sig##_); \
    stdlib_uses_.Add(StandardMember::kMath##Name);                  \
    break;
      STDLIB_MATH_FUNCTION_LIST(V)
#undef V
      default:
        FAIL("Invalid member of stdlib.Math");
    }
  } else if (Check(TOK(Infinity))) {
    DeclareGlobal(info, false, AsmType::Double(), kWasmF64,
                  WasmInitExpr(std::numeric_limits<double>::infinity()));
    stdlib_uses_.Add(StandardMember::kInfinity);
  } else if (Check(TOK(NaN))) {
    DeclareGlobal(info, false, AsmType::Double(), kWasmF64,
                  WasmInitExpr(std::numeric_limits<double>::quiet_NaN()));
    stdlib_uses_.Add(StandardMember::kNaN);
  } else {
    FAIL("Invalid member of stdlib");
  }
}

// 6.2 ValidateExport
void AsmJsParser::ValidateExport() {
  // clang-format off
  EXPECT_TOKEN(TOK(return));
  // clang-format on
  if (Check('{')) {
    for (;;) {
      base::Vector<const char> name = CopyCurrentIdentifierString();
      if (!scanner_.IsGlobal() && !scanner_.IsLocal()) {
        FAIL("Illegal export name");
      }
      Consume();
      EXPECT_TOKEN(':');
      if (!scanner_.IsGlobal()) {
        FAIL("Expected function name");
      }
      VarInfo* info = GetVarInfo(Consume());
      if (info->kind != VarKind::kFunction) {
        FAIL("Expected function");
      }
      module_builder_->AddExport(name, info->function_builder);
      if (Check(',')) {
        if (!Peek('}')) {
          continue;
        }
      }
      break;
    }
    EXPECT_TOKEN('}');
  } else {
    if (!scanner_.IsGlobal()) {
      FAIL("Single function export must be a function name");
    }
    VarInfo* info = GetVarInfo(Consume());
    if (info->kind != VarKind::kFunction) {
      FAIL("Single function export must be a function");
    }
    module_builder_->AddExport(base::CStrVector(AsmJs::kSingleFunctionName),
                               info->function_builder);
  }
}

// 6.3 ValidateFunctionTable
void AsmJsParser::ValidateFunctionTable() {
  EXPECT_TOKEN(TOK(var));
  if (!scanner_.IsGlobal()) {
    FAIL("Expected table name");
  }
  VarInfo* table_info = GetVarInfo(Consume());
  if (table_info->kind == VarKind::kTable) {
    if (table_info->function_defined) {
      FAIL("Function table redefined");
    }
    table_info->function_defined = true;
  } else if (table_info->kind != VarKind::kUnused) {
    FAIL("Function table name collides");
  }
  EXPECT_TOKEN('=');
  EXPECT_TOKEN('[');
  uint64_t count = 0;
  for (;;) {
    if (!scanner_.IsGlobal()) {
      FAIL("Expected function name");
    }
    VarInfo* info = GetVarInfo(Consume());
    if (info->kind != VarKind::kFunction) {
      FAIL("Expected function");
    }
    // Only store the function into a table if we used the table somewhere
    // (i.e. tables are first seen at their use sites and allocated there).
    if (table_info->kind == VarKind::kTable) {
      if (count >= static_cast<uint64_t>(table_info->mask) + 1) {
        FAIL("Exceeded function table size");
      }
      if (!info->type->IsA(table_info->type)) {
        FAIL("Function table definition doesn't match use");
      }
      module_builder_->SetIndirectFunction(
          0, static_cast<uint32_t>(table_info->index + count), info->index,
          WasmModuleBuilder::WasmElemSegment::kRelativeToDeclaredFunctions);
    }
    ++count;
    if (Check(',')) {
      if (!Peek(']')) {
        continue;
      }
    }
    break;
  }
  EXPECT_TOKEN(']');
  if (table_info->kind == VarKind::kTable &&
      count != static_cast<uint64_t>(table_info->mask) + 1) {
    FAIL("Function table size does not match uses");
  }
  SkipSemicolon();
}

// 6.4 ValidateFunction
void AsmJsParser::ValidateFunction() {
  // Remember position of the 'function' token as start position.
  size_t function_start_position = scanner_.Position();

  EXPECT_TOKEN(TOK(function));
  if (!scanner_.IsGlobal()) {
    FAIL("Expected function name");
  }

  base::Vector<const char> function_name_str = CopyCurrentIdentifierString();
  AsmJsScanner::token_t function_name = Consume();
  VarInfo* function_info = GetVarInfo(function_name);
  if (function_info->kind == VarKind::kUnused) {
    function_info->kind = VarKind::kFunction;
    function_info->function_builder = module_builder_->AddFunction();
    function_info->index = function_info->function_builder->func_index();
    function_info->mutable_variable = false;
  } else if (function_info->kind != VarKind::kFunction) {
    FAIL("Function name collides with variable");
  } else if (function_info->function_defined) {
    FAIL("Function redefined");
  }

  function_info->function_defined = true;
  function_info->function_builder->SetName(function_name_str);
  current_function_builder_ = function_info->function_builder;
  return_type_ = nullptr;

  // Record start of the function, used as position for the stack check.
  current_function_builder_->SetAsmFunctionStartPosition(
      function_start_position);

  CachedVector<AsmType*> params(&cached_asm_type_p_vectors_);
  ValidateFunctionParams(&params);

  // Check against limit on number of parameters.
  if (params.size() > kV8MaxWasmFunctionParams) {
    FAIL("Number of parameters exceeds internal limit");
  }

  CachedVector<ValueType> locals(&cached_valuetype_vectors_);
  ValidateFunctionLocals(params.size(), &locals);

  function_temp_locals_offset_ = static_cast<uint32_t>(
      params.size() + locals.size());
  function_temp_locals_used_ = 0;
  function_temp_locals_depth_ = 0;

  bool last_statement_is_return = false;
  while (!failed_ && !Peek('}')) {
    // clang-format off
    last_statement_is_return = Peek(TOK(return));
    // clang-format on
    RECURSE(ValidateStatement());
  }

  size_t function_end_position = scanner_.Position() + 1;

  EXPECT_TOKEN('}');

  if (!last_statement_is_return) {
    if (return_type_ == nullptr) {
      return_type_ = AsmType::Void();
    } else if (!return_type_->IsA(AsmType::Void())) {
      FAIL("Expected return at end of non-void function");
    }
  }
  DCHECK_NOT_NULL(return_type_);

  // TODO(bradnelson): WasmModuleBuilder can't take this in the right order.
  //                   We should fix that so we can use it instead.
  FunctionSig* sig = ConvertSignature(return_type_, params);
  current_function_builder_->SetSignature(sig);
  for (auto local : locals) {
    current_function_builder_->AddLocal(local);
  }
  // Add bonus temps.
  for (int i = 0; i < function_temp_locals_used_; ++i) {
    current_function_builder_->AddLocal(kWasmI32);
  }

  // Check against limit on number of local variables.
  if (locals.size() + function_temp_locals_used_ > kV8MaxWasmFunctionLocals) {
    FAIL("Number of local variables exceeds internal limit");
  }

  // End function
  current_function_builder_->Emit(kExprEnd);

  // Emit function end position as the last position for this function.
  current_function_builder_->AddAsmWasmOffset(function_end_position,
                                              function_end_position);

  if (current_function_builder_->GetPosition() > kV8MaxWasmFunctionSize) {
    FAIL("Size of function body exceeds internal limit");
  }
  // Record (or validate) function type.
  AsmType* function_type = AsmType::Function(zone(), return_type_);
  for (auto t : params) {
    function_type->AsFunctionType()->AddArgument(t);
  }
  function_info = GetVarInfo(function_name);
  if (function_info->type->IsA(AsmType::None())) {
    DCHECK_EQ(function_info->kind, VarKind::kFunction);
    function_info->type = function_type;
  } else if (!function_type->IsA(function_info->type)) {
    // TODO(bradnelson): Should IsExactly be used here?
    FAIL("Function definition doesn't match use");
  }

  scanner_.ResetLocals();
  std::fill(local_var_info_.begin(), local_var_info_.end(), VarInfo{});
}

// 6.4 ValidateFunction
void AsmJsParser::ValidateFunctionParams(ZoneVector<AsmType*>* params) {
  // TODO(bradnelson): Do this differently so that the scanner doesn't need to
  // have a state transition that needs knowledge of how the scanner works
  // inside.
  scanner_.EnterLocalScope();
  EXPECT_TOKEN('(');
  CachedVector<AsmJsScanner::token_t> function_parameters(
      &cached_token_t_vectors_);
  while (!failed_ && !Peek(')')) {
    if (!scanner_.IsLocal()) {
      FAIL("Expected parameter name");
    }
    function_parameters.push_back(Consume());
    if (!Peek(')')) {
      EXPECT_TOKEN(',');
    }
  }
  EXPECT_TOKEN(')');
  scanner_.EnterGlobalScope();
  EXPECT_TOKEN('{');
  // 5.1 Parameter Type Annotations
  for (auto p : function_parameters) {
    EXPECT_TOKEN(p);
    EXPECT_TOKEN('=');
    VarInfo* info = GetVarInfo(p);
    if (info->kind != VarKind::kUnused) {
      FAIL("Duplicate parameter name");
    }
    if (Check(p)) {
      EXPECT_TOKEN('|');
      if (!CheckForZero()) {
        FAIL("Bad integer parameter annotation.");
      }
      info->kind = VarKind::kLocal;
      info->type = AsmType::Int();
      info->index = static_cast<uint32_t>(params->size());
      params->push_back(AsmType::Int());
    } else if (Check('+')) {
      EXPECT_TOKEN(p);
      info->kind = VarKind::kLocal;
      info->type = AsmType::Double();
      info->index = static_cast<uint32_t>(params->size());
      params->push_back(AsmType::Double());
    } else {
      if (!scanner_.IsGlobal() ||
          !GetVarInfo(Consume())->type->IsA(stdlib_fround_)) {
        FAIL("Expected fround");
      }
      EXPECT_TOKEN('(');
      EXPECT_TOKEN(p);
      EXPECT_TOKEN(')');
      info->kind = VarKind::kLocal;
      info->type = AsmType::Float();
      info->index = static_cast<uint32_t>(params->size());
      params->push_back(AsmType::Float());
    }
    SkipSemicolon();
  }
}

// 6.4 ValidateFunction - locals
void AsmJsParser::ValidateFunctionLocals(size_t param_count,
                                         ZoneVector<ValueType>* locals) {
  DCHECK(locals->empty());
  // Local Variables.
  while (Peek(TOK(var))) {
    scanner_.EnterLocalScope();
    EXPECT_TOKEN(TOK(var));
    scanner_.EnterGlobalScope();
    for (;;) {
      if (!scanner_.IsLocal()) {
        FAIL("Expected local variable identifier");
      }
      VarInfo* info = GetVarInfo(Consume());
      if (info->kind != VarKind::kUnused) {
        FAIL("Duplicate local variable name");
      }
      // Store types.
      EXPECT_TOKEN('=');
      double dvalue = 0.0;
      uint32_t uvalue = 0;
      if (Check('-')) {
        if (CheckForDouble(&dvalue)) {
          info->kind = VarKind::kLocal;
          info->type = AsmType::Double();
          info->index = static_cast<uint32_t>(param_count + locals->size());
          locals->push_back(kWasmF64);
          current_function_builder_->EmitF64Const(-dvalue);
          current_function_builder_->EmitSetLocal(info->index);
        } else if (CheckForUnsigned(&uvalue)) {
          if (uvalue > 0x7FFFFFFF) {
            FAIL("Numeric literal out of range");
          }
          info->kind = VarKind::kLocal;
          info->type = AsmType::Int();
          info->index = static_cast<uint32_t>(param_count + locals->size());
          locals->push_back(kWasmI32);
          int32_t value = -static_cast<int32_t>(uvalue);
          current_function_builder_->EmitI32Const(value);
          current_function_builder_->EmitSetLocal(info->index);
        } else {
          FAIL("Expected variable initial value");
        }
      } else if (scanner_.IsGlobal()) {
        VarInfo* sinfo = GetVarInfo(Consume());
        if (sinfo->kind == VarKind::kGlobal) {
          if (sinfo->mutable_variable) {
            FAIL("Initializing from global requires const variable");
          }
          info->kind = VarKind::kLocal;
          info->type = sinfo->type;
          info->index = static_cast<uint32_t>(param_cou
"""


```