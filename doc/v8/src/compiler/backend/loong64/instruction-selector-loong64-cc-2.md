Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/compiler/backend/loong64/instruction-selector-loong64.cc`. The request asks for:

1. **Functionality Summary:** A description of what the code does.
2. **Torque Source Check:** Whether the file would be a Torque source if it ended in `.tq`.
3. **JavaScript Relation:** If it's related to JavaScript, provide an example.
4. **Code Logic Inference:** Provide an example of input and output based on the code.
5. **Common Programming Errors:**  Illustrate potential errors the code helps avoid or might encounter.
6. **Overall Function Summary:** A concise summary of the code's purpose.

Let's break down the code:

* **Template Instantiations:** The code uses C++ templates (`template <typename Adapter>`) indicating it's designed to work with different "adapters". These adapters likely represent different phases or configurations within the V8 compilation pipeline (e.g., Turbofan, Turboshaft).
* **`InstructionSelectorT` Class:**  This suggests the code is responsible for selecting machine instructions based on higher-level operations.
* **`Visit...` Methods:**  Methods like `VisitInt32Mul`, `VisitFloat64Add`, etc., imply that this code processes different types of operations (integer multiplication, floating-point addition, etc.).
* **Instruction Emission:**  Calls to `Emit(...)` indicate that the code generates specific LoongArch64 assembly instructions. The `kLoong64...` prefixes denote LoongArch64 instruction mnemonics.
* **Operand Generation:**  The `Loong64OperandGeneratorT` class seems responsible for creating operands (registers, immediate values) for the generated instructions.
* **Matcher Classes:** Classes like `Int32BinopMatcher` are used to extract information about the operands of specific operations.
* **Optimization Logic:** The code contains conditional logic to optimize certain operations. For example, in `VisitInt64Mul`, it checks for multiplication by powers of two to use shift instructions instead of a full multiplication.
* **Type Conversions:**  Methods like `VisitChangeInt32ToFloat64` handle conversions between different data types.
* **Truncation Handling:**  Methods related to truncation (e.g., `VisitTruncateFloat64ToInt32`) often have logic to handle potential overflow conditions.
* **Calling Conventions:** The `EmitMoveParamToFPR` and `EmitMoveFPRToParam` methods suggest dealing with function call parameters.

**Plan:**

1. Summarize the core function: instruction selection for LoongArch64.
2. Address the Torque question.
3. Connect the operations to JavaScript equivalents.
4. Provide an example of integer multiplication optimization.
5. Think about common errors in manual instruction selection that this code prevents.
6. Reiterate the main functionality.
This part of the `v8/src/compiler/backend/loong64/instruction-selector-loong64.cc` file focuses on selecting and emitting LoongArch64 instructions for various arithmetic and type conversion operations. Specifically, it handles:

**Functionality Summary of This Part:**

* **Integer Arithmetic Operations:**
    * Multiplication (`VisitInt32Mul`, `VisitInt64Mul`, `VisitUint32MulHigh`, etc.) including optimizations for multiplication by powers of two.
    * Division (`VisitInt32Div`, `VisitUint32Div`, `VisitInt64Div`, `VisitUint64Div`).
    * Modulo (`VisitInt32Mod`, `VisitUint32Mod`, `VisitInt64Mod`, `VisitUint64Mod`).
* **Floating-Point Conversions:**
    * Conversions between different floating-point precisions (e.g., `VisitChangeFloat32ToFloat64`, `VisitTruncateFloat64ToFloat32`).
    * Conversions between integers and floating-point numbers (e.g., `VisitRoundInt32ToFloat32`, `VisitChangeFloat64ToInt32`, `VisitTruncateFloat32ToInt32`).
    * "Try" versions of truncation operations that handle potential overflows and have separate success outputs (e.g., `VisitTryTruncateFloat32ToInt64`).
* **Bitwise Operations (Implicit):** The `VisitBitcast...` functions handle reinterpreting the bits of a value as a different type.
* **Integer Type Conversions:**
    * Conversions between different integer sizes (e.g., `VisitChangeInt32ToInt64`, `VisitChangeUint32ToUint64`, `VisitTruncateInt64ToInt32`). It includes optimizations for sign-extending and zero-extending loads.
* **Floating-Point Arithmetic Operations:**
    * Addition, subtraction, multiplication, division, modulo (`VisitFloat32Add`, `VisitFloat64Sub`, etc.).
    * Maximum, minimum, absolute value, square root (`VisitFloat32Max`, `VisitFloat64Abs`, `VisitFloat64Sqrt`).
    * Rounding operations (`VisitFloat32RoundDown`, `VisitFloat64RoundTiesEven`, etc.).
    * Negation (`VisitFloat32Neg`, `VisitFloat64Neg`).
* **Handling of Different Compilation Pipelines:** The use of templates (`template <typename Adapter>`) and conditional compilation (`if constexpr (Adapter::IsTurboshaft)`) indicates that the code adapts its instruction selection based on the specific V8 compilation pipeline being used (e.g., Turbofan or Turboshaft).
* **Optimization of Instruction Sequences:**  The code attempts to identify patterns in the intermediate representation (IR) to emit more efficient instruction sequences. For example, combining shifts with multiplication or division, and optimizing multiplication by constants.
* **Function Call Parameter Handling:**  The `EmitMoveParamToFPR` and `EmitMoveFPRToParam` functions deal with moving parameters to and from floating-point registers during function calls.

**Torque Source Check:**

Yes, if `v8/src/compiler/backend/loong64/instruction-selector-loong64.cc` ended with `.tq`, it would be a V8 Torque source file. Torque is V8's domain-specific language for generating C++ code, often used for implementing built-in functions and parts of the compiler.

**Relationship with JavaScript and Example:**

This code directly translates JavaScript's arithmetic and type conversion operations into low-level machine instructions for the LoongArch64 architecture.

**JavaScript Example:**

```javascript
let a = 10;
let b = 5;
let sum = a + b;        // Would involve code similar to VisitInt32Add
let product = a * b;    // Would involve code similar to VisitInt32Mul
let quotient = a / b;   // Would involve code similar to VisitInt32Div
let floatNum = 3.14;
let intFromFloat = Math.trunc(floatNum); // Would involve code similar to VisitTruncateFloat64ToInt32
let floatFromInt = a + 0.0;              // Would involve code similar to VisitChangeInt32ToFloat64
```

When V8 compiles this JavaScript code, the intermediate representation (IR) nodes for these operations will be processed by the `InstructionSelectorT` class, and the methods in this file will be responsible for choosing the appropriate LoongArch64 instructions to perform these calculations.

**Code Logic Inference with Input and Output:**

Let's consider the `VisitInt64Mul` function (Turbofan adapter) with the power-of-two optimization:

**Hypothetical Input (IR Node):** An `Int64Mul` node where the right input is a constant value of 8.

**Code Logic:** The code checks if the right operand is a power of two. 8 is 2<sup>3</sup>.

**Output (Emitted Instruction):**  The code will emit a left shift instruction (`kLoong64Sll_d`) instead of a full multiplication. The emitted instruction would conceptually be:

```assembly
sll.d destination_register, source_register, 3
```

Where `destination_register` is the register where the result of the multiplication will be stored, `source_register` holds the left operand, and `3` is the shift amount (log base 2 of 8).

**Common Programming Errors:**

This code helps avoid common errors that would arise from manually writing assembly code, such as:

* **Incorrect Instruction Selection:** Choosing the wrong instruction for a specific operation (e.g., using an unsigned multiply for signed numbers).
* **Register Allocation Errors:**  Incorrectly assigning registers, leading to data corruption. The `OperandGenerator` helps manage register allocation.
* **Incorrect Operand Ordering:**  Assembly instructions often have specific ordering for source and destination operands. This code ensures the correct order for LoongArch64.
* **Missing Type Conversions:**  Forgetting to perform necessary type conversions before arithmetic operations. The `VisitChange...` functions handle these conversions.
* **Inefficient Code Generation:**  Manually written assembly might miss opportunities for optimization, like the power-of-two multiplication example. This code implements these optimizations.

**Overall Function Summary of This Part:**

This section of `instruction-selector-loong64.cc` is responsible for the core task of **translating high-level intermediate representation (IR) nodes representing arithmetic and type conversion operations into concrete LoongArch64 machine instructions**. It incorporates architecture-specific knowledge and optimizations to generate efficient code for the LoongArch64 platform within the V8 JavaScript engine. It also adapts its behavior based on the specific compilation pipeline being used.

Prompt: 
```
这是目录为v8/src/compiler/backend/loong64/instruction-selector-loong64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/loong64/instruction-selector-loong64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共6部分，请归纳一下它的功能

"""
atcher leftInput(left), rightInput(right);
      if (leftInput.right().Is(32) && rightInput.right().Is(32)) {
        // Combine untagging shifts with Mulh_d.
        Emit(kLoong64Mulh_d, g.DefineSameAsFirst(node),
             g.UseRegister(leftInput.left().node()),
             g.UseRegister(rightInput.left().node()));
        return;
      }
    }
  }
  VisitRRR(this, kLoong64Mul_w, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32MulHigh(node_t node) {
  VisitRRR(this, kLoong64Mulh_w, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64MulHigh(node_t node) {
  VisitRRR(this, kLoong64Mulh_d, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint32MulHigh(node_t node) {
  VisitRRR(this, kLoong64Mulh_wu, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint64MulHigh(node_t node) {
  VisitRRR(this, kLoong64Mulh_du, node);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitInt64Mul(node_t node) {
  // TODO(LOONG_dev): May could be optimized like in Turbofan.
  VisitBinop(this, node, kLoong64Mul_d, true, kLoong64Mul_d);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitInt64Mul(Node* node) {
  Loong64OperandGeneratorT<TurbofanAdapter> g(this);
  Int64BinopMatcher m(node);
  if (m.right().HasResolvedValue() && m.right().ResolvedValue() > 0) {
    uint64_t value = static_cast<uint64_t>(m.right().ResolvedValue());
    if (base::bits::IsPowerOfTwo(value)) {
      Emit(kLoong64Sll_d | AddressingModeField::encode(kMode_None),
           g.DefineAsRegister(node), g.UseRegister(m.left().node()),
           g.TempImmediate(base::bits::WhichPowerOfTwo(value)));
      return;
    }
    if (base::bits::IsPowerOfTwo(value - 1) && value - 1 > 0) {
      // Alsl_d macro will handle the shifting value out of bound cases.
      Emit(kLoong64Alsl_d, g.DefineAsRegister(node),
           g.UseRegister(m.left().node()), g.UseRegister(m.left().node()),
           g.TempImmediate(base::bits::WhichPowerOfTwo(value - 1)));
      return;
    }
    if (base::bits::IsPowerOfTwo(value + 1)) {
      InstructionOperand temp = g.TempRegister();
      Emit(kLoong64Sll_d | AddressingModeField::encode(kMode_None), temp,
           g.UseRegister(m.left().node()),
           g.TempImmediate(base::bits::WhichPowerOfTwo(value + 1)));
      Emit(kLoong64Sub_d | AddressingModeField::encode(kMode_None),
           g.DefineAsRegister(node), temp, g.UseRegister(m.left().node()));
      return;
    }
  }
  Emit(kLoong64Mul_d, g.DefineAsRegister(node), g.UseRegister(m.left().node()),
       g.UseRegister(m.right().node()));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32Div(node_t node) {
  Loong64OperandGeneratorT<Adapter> g(this);

  if constexpr (Adapter::IsTurboshaft) {
    auto binop = this->word_binop_view(node);
    Emit(kLoong64Div_w, g.DefineSameAsFirst(node), g.UseRegister(binop.left()),
         g.UseRegister(binop.right()));
  } else {
    Int32BinopMatcher m(node);
    Node* left = node->InputAt(0);
    Node* right = node->InputAt(1);
    if (CanCover(node, left) && CanCover(node, right)) {
      if (left->opcode() == IrOpcode::kWord64Sar &&
          right->opcode() == IrOpcode::kWord64Sar) {
        Int64BinopMatcher rightInput(right), leftInput(left);
        if (rightInput.right().Is(32) && leftInput.right().Is(32)) {
          // Combine both shifted operands with Div_d.
          Emit(kLoong64Div_d, g.DefineSameAsFirst(node),
               g.UseRegister(leftInput.left().node()),
               g.UseRegister(rightInput.left().node()));
          return;
        }
      }
    }
    Emit(kLoong64Div_w, g.DefineSameAsFirst(node),
         g.UseRegister(m.left().node()), g.UseRegister(m.right().node()));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint32Div(node_t node) {
  Loong64OperandGeneratorT<Adapter> g(this);
  auto binop = this->word_binop_view(node);
  Emit(kLoong64Div_wu, g.DefineSameAsFirst(node), g.UseRegister(binop.left()),
       g.UseRegister(binop.right()));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32Mod(node_t node) {
  Loong64OperandGeneratorT<Adapter> g(this);

  if constexpr (Adapter::IsTurboshaft) {
    auto binop = this->word_binop_view(node);
    Emit(kLoong64Mod_w, g.DefineSameAsFirst(node), g.UseRegister(binop.left()),
         g.UseRegister(binop.right()));
  } else {
    Int32BinopMatcher m(node);
    Node* left = node->InputAt(0);
    Node* right = node->InputAt(1);
    if (CanCover(node, left) && CanCover(node, right)) {
      if (left->opcode() == IrOpcode::kWord64Sar &&
          right->opcode() == IrOpcode::kWord64Sar) {
        Int64BinopMatcher rightInput(right), leftInput(left);
        if (rightInput.right().Is(32) && leftInput.right().Is(32)) {
          // Combine both shifted operands with Mod_d.
          Emit(kLoong64Mod_d, g.DefineSameAsFirst(node),
               g.UseRegister(leftInput.left().node()),
               g.UseRegister(rightInput.left().node()));
          return;
        }
      }
    }
    Emit(kLoong64Mod_w, g.DefineAsRegister(node),
         g.UseRegister(m.left().node()), g.UseRegister(m.right().node()));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint32Mod(node_t node) {
  VisitRRR(this, kLoong64Mod_wu, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64Div(node_t node) {
  Loong64OperandGeneratorT<Adapter> g(this);
  auto binop = this->word_binop_view(node);
  Emit(kLoong64Div_d, g.DefineSameAsFirst(node), g.UseRegister(binop.left()),
       g.UseRegister(binop.right()));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint64Div(node_t node) {
  Loong64OperandGeneratorT<Adapter> g(this);
  auto binop = this->word_binop_view(node);
  Emit(kLoong64Div_du, g.DefineSameAsFirst(node), g.UseRegister(binop.left()),
       g.UseRegister(binop.right()));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64Mod(node_t node) {
  VisitRRR(this, kLoong64Mod_d, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint64Mod(node_t node) {
  VisitRRR(this, kLoong64Mod_du, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeFloat32ToFloat64(node_t node) {
  VisitRR(this, kLoong64Float32ToFloat64, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitRoundInt32ToFloat32(node_t node) {
  VisitRR(this, kLoong64Int32ToFloat32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitRoundUint32ToFloat32(node_t node) {
  VisitRR(this, kLoong64Uint32ToFloat32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeInt32ToFloat64(node_t node) {
  VisitRR(this, kLoong64Int32ToFloat64, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeInt64ToFloat64(node_t node) {
  VisitRR(this, kLoong64Int64ToFloat64, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeUint32ToFloat64(node_t node) {
  VisitRR(this, kLoong64Uint32ToFloat64, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateFloat32ToInt32(node_t node) {
  Loong64OperandGeneratorT<Adapter> g(this);

  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const Operation& op = this->Get(node);
    InstructionCode opcode = kLoong64Float32ToInt32;
    opcode |= MiscField::encode(
        op.Is<Opmask::kTruncateFloat32ToInt32OverflowToMin>());
    Emit(opcode, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)));
  } else {
    InstructionCode opcode = kLoong64Float32ToInt32;
    TruncateKind kind = OpParameter<TruncateKind>(node->op());
    if (kind == TruncateKind::kSetOverflowToMin) {
      opcode |= MiscField::encode(true);
    }
    Emit(opcode, g.DefineAsRegister(node), g.UseRegister(node->InputAt(0)));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateFloat32ToUint32(node_t node) {
  Loong64OperandGeneratorT<Adapter> g(this);

  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const Operation& op = this->Get(node);
    InstructionCode opcode = kLoong64Float32ToUint32;
    if (op.Is<Opmask::kTruncateFloat32ToUint32OverflowToMin>()) {
      opcode |= MiscField::encode(true);
    }

    Emit(opcode, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)));
  } else {
    InstructionCode opcode = kLoong64Float32ToUint32;
    TruncateKind kind = OpParameter<TruncateKind>(node->op());
    if (kind == TruncateKind::kSetOverflowToMin) {
      opcode |= MiscField::encode(true);
    }
    Emit(opcode, g.DefineAsRegister(node), g.UseRegister(node->InputAt(0)));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeFloat64ToInt32(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    // TODO(loong64): Check if could be optimized like turbofan here.
  } else {
    Loong64OperandGeneratorT<Adapter> g(this);
    Node* value = node->InputAt(0);
    // TODO(LOONG_dev): LOONG64 Match ChangeFloat64ToInt32(Float64Round##OP) to
    // corresponding instruction which does rounding and conversion to
    // integer format.
    if (CanCover(node, value)) {
      if (value->opcode() == IrOpcode::kChangeFloat32ToFloat64) {
        Node* next = value->InputAt(0);
        if (!CanCover(value, next)) {
          // Match float32 -> float64 -> int32 representation change path.
          Emit(kLoong64Float32ToInt32, g.DefineAsRegister(node),
               g.UseRegister(value->InputAt(0)));
          return;
        }
      }
    }
  }

  VisitRR(this, kLoong64Float64ToInt32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeFloat64ToInt64(node_t node) {
  VisitRR(this, kLoong64Float64ToInt64, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeFloat64ToUint32(node_t node) {
  VisitRR(this, kLoong64Float64ToUint32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeFloat64ToUint64(node_t node) {
  VisitRR(this, kLoong64Float64ToUint64, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateFloat64ToUint32(node_t node) {
  VisitRR(this, kLoong64Float64ToUint32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateFloat64ToInt64(node_t node) {
  Loong64OperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    InstructionCode opcode = kLoong64Float64ToInt64;
    const Operation& op = this->Get(node);
    if (op.Is<Opmask::kTruncateFloat64ToInt64OverflowToMin>()) {
      opcode |= MiscField::encode(true);
    }

    Emit(opcode, g.DefineAsRegister(node), g.UseRegister(op.input(0)));
  } else {
    InstructionCode opcode = kLoong64Float64ToInt64;
    TruncateKind kind = OpParameter<TruncateKind>(node->op());
    if (kind == TruncateKind::kSetOverflowToMin) {
      opcode |= MiscField::encode(true);
    }
    Emit(opcode, g.DefineAsRegister(node), g.UseRegister(node->InputAt(0)));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateFloat64ToFloat16RawBits(
    node_t node) {
  UNIMPLEMENTED();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTryTruncateFloat32ToInt64(
    node_t node) {
  Loong64OperandGeneratorT<Adapter> g(this);

  InstructionOperand inputs[] = {g.UseRegister(this->input_at(node, 0))};
  InstructionOperand outputs[2];
  size_t output_count = 0;
  outputs[output_count++] = g.DefineAsRegister(node);

  node_t success_output = FindProjection(node, 1);
  if (this->valid(success_output)) {
    outputs[output_count++] = g.DefineAsRegister(success_output);
  }

  Emit(kLoong64Float32ToInt64, output_count, outputs, 1, inputs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTryTruncateFloat64ToInt64(
    node_t node) {
  Loong64OperandGeneratorT<Adapter> g(this);

  InstructionOperand inputs[] = {g.UseRegister(this->input_at(node, 0))};
  InstructionOperand outputs[2];
  size_t output_count = 0;
  outputs[output_count++] = g.DefineAsRegister(node);

  node_t success_output = FindProjection(node, 1);
  if (this->valid(success_output)) {
    outputs[output_count++] = g.DefineAsRegister(success_output);
  }

  Emit(kLoong64Float64ToInt64, output_count, outputs, 1, inputs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTryTruncateFloat32ToUint64(
    node_t node) {
  Loong64OperandGeneratorT<Adapter> g(this);

  InstructionOperand inputs[] = {g.UseRegister(this->input_at(node, 0))};
  InstructionOperand outputs[2];
  size_t output_count = 0;
  outputs[output_count++] = g.DefineAsRegister(node);

  node_t success_output = FindProjection(node, 1);
  if (this->valid(success_output)) {
    outputs[output_count++] = g.DefineAsRegister(success_output);
  }

  Emit(kLoong64Float32ToUint64, output_count, outputs, 1, inputs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTryTruncateFloat64ToUint64(
    node_t node) {
  Loong64OperandGeneratorT<Adapter> g(this);

  InstructionOperand inputs[] = {g.UseRegister(this->input_at(node, 0))};
  InstructionOperand outputs[2];
  size_t output_count = 0;
  outputs[output_count++] = g.DefineAsRegister(node);

  node_t success_output = FindProjection(node, 1);
  if (this->valid(success_output)) {
    outputs[output_count++] = g.DefineAsRegister(success_output);
  }

  Emit(kLoong64Float64ToUint64, output_count, outputs, 1, inputs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTryTruncateFloat64ToInt32(
    node_t node) {
  Loong64OperandGeneratorT<Adapter> g(this);

  InstructionOperand inputs[] = {g.UseRegister(this->input_at(node, 0))};
  InstructionOperand outputs[2];
  size_t output_count = 0;
  outputs[output_count++] = g.DefineAsRegister(node);

  node_t success_output = FindProjection(node, 1);
  if (this->valid(success_output)) {
    outputs[output_count++] = g.DefineAsRegister(success_output);
  }

  Emit(kLoong64Float64ToInt32, output_count, outputs, 1, inputs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTryTruncateFloat64ToUint32(
    node_t node) {
  Loong64OperandGeneratorT<Adapter> g(this);

  InstructionOperand inputs[] = {g.UseRegister(this->input_at(node, 0))};
  InstructionOperand outputs[2];
  size_t output_count = 0;
  outputs[output_count++] = g.DefineAsRegister(node);

  node_t success_output = FindProjection(node, 1);
  if (this->valid(success_output)) {
    outputs[output_count++] = g.DefineAsRegister(success_output);
  }

  Emit(kLoong64Float64ToUint32, output_count, outputs, 1, inputs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitBitcastWord32ToWord64(node_t node) {
  DCHECK(SmiValuesAre31Bits());
  DCHECK(COMPRESS_POINTERS_BOOL);
  EmitIdentity(node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeInt32ToInt64(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    Loong64OperandGeneratorT<Adapter> g(this);
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const ChangeOp& change_op = this->Get(node).template Cast<ChangeOp>();
    const Operation& input_op = this->Get(change_op.input());
    if (input_op.Is<LoadOp>() && CanCover(node, change_op.input())) {
      // Generate sign-extending load.
      LoadRepresentation load_rep =
          this->load_view(change_op.input()).loaded_rep();
      MachineRepresentation rep = load_rep.representation();
      InstructionCode opcode = kArchNop;
      switch (rep) {
        case MachineRepresentation::kBit:  // Fall through.
        case MachineRepresentation::kWord8:
          opcode = load_rep.IsUnsigned() ? kLoong64Ld_bu : kLoong64Ld_b;
          break;
        case MachineRepresentation::kWord16:
          opcode = load_rep.IsUnsigned() ? kLoong64Ld_hu : kLoong64Ld_h;
          break;
        case MachineRepresentation::kWord32:
        case MachineRepresentation::kTaggedSigned:
        case MachineRepresentation::kTagged:
        case MachineRepresentation::kTaggedPointer:
          opcode = kLoong64Ld_w;
          break;
        default:
          UNREACHABLE();
      }
      EmitLoad(this, change_op.input(), opcode, node);
      return;
    } else if (input_op.Is<Opmask::kWord32ShiftRightArithmetic>() &&
               CanCover(node, change_op.input())) {
      // TODO(LOONG_dev): May also optimize 'TruncateInt64ToInt32' here.
      EmitIdentity(node);
    }
    Emit(kLoong64Sll_w, g.DefineAsRegister(node),
         g.UseRegister(change_op.input()), g.TempImmediate(0));
  } else {
    Loong64OperandGeneratorT<Adapter> g(this);
    Node* value = node->InputAt(0);
    if ((value->opcode() == IrOpcode::kLoad ||
         value->opcode() == IrOpcode::kLoadImmutable) &&
        CanCover(node, value)) {
      // Generate sign-extending load.
      LoadRepresentation load_rep = LoadRepresentationOf(value->op());
      InstructionCode opcode = kArchNop;
      switch (load_rep.representation()) {
        case MachineRepresentation::kBit:  // Fall through.
        case MachineRepresentation::kWord8:
          opcode = load_rep.IsUnsigned() ? kLoong64Ld_bu : kLoong64Ld_b;
          break;
        case MachineRepresentation::kWord16:
          opcode = load_rep.IsUnsigned() ? kLoong64Ld_hu : kLoong64Ld_h;
          break;
        case MachineRepresentation::kWord32:
        case MachineRepresentation::kTaggedSigned:
        case MachineRepresentation::kTagged:
        case MachineRepresentation::kTaggedPointer:
          opcode = kLoong64Ld_w;
          break;
        default:
          UNREACHABLE();
      }
      EmitLoad(this, value, opcode, node);
      return;
    } else if (value->opcode() == IrOpcode::kTruncateInt64ToInt32) {
      EmitIdentity(node);
      return;
    }
    Emit(kLoong64Sll_w, g.DefineAsRegister(node),
         g.UseRegister(node->InputAt(0)), g.TempImmediate(0));
  }
}

template <>
bool InstructionSelectorT<TurboshaftAdapter>::ZeroExtendsWord32ToWord64NoPhis(
    node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  DCHECK(!this->Get(node).Is<PhiOp>());
  const Operation& op = this->Get(node);
  switch (op.opcode) {
    // Comparisons only emit 0/1, so the upper 32 bits must be zero.
    case Opcode::kComparison:
      return op.Cast<ComparisonOp>().rep == RegisterRepresentation::Word32();
    case Opcode::kOverflowCheckedBinop:
      return op.Cast<OverflowCheckedBinopOp>().rep ==
             WordRepresentation::Word32();
    case Opcode::kLoad: {
      auto load = this->load_view(node);
      LoadRepresentation load_rep = load.loaded_rep();
      if (load_rep.IsUnsigned()) {
        switch (load_rep.representation()) {
          case MachineRepresentation::kBit:    // Fall through.
          case MachineRepresentation::kWord8:  // Fall through.
          case MachineRepresentation::kWord16:
            return true;
          default:
            return false;
        }
      }
      return false;
    }
    default:
      return false;
  }
}

template <>
bool InstructionSelectorT<TurbofanAdapter>::ZeroExtendsWord32ToWord64NoPhis(
    Node* node) {
  DCHECK_NE(node->opcode(), IrOpcode::kPhi);
  switch (node->opcode()) {
    // Comparisons only emit 0/1, so the upper 32 bits must be zero.
    case IrOpcode::kWord32Equal:
    case IrOpcode::kInt32LessThan:
    case IrOpcode::kInt32LessThanOrEqual:
    case IrOpcode::kUint32LessThan:
    case IrOpcode::kUint32LessThanOrEqual:
      return true;
    case IrOpcode::kWord32And: {
      Int32BinopMatcher m(node);
      if (m.right().HasResolvedValue()) {
        uint32_t mask = m.right().ResolvedValue();
        return is_uint31(mask);
      }
      return false;
    }
    case IrOpcode::kWord32Shr: {
      Int32BinopMatcher m(node);
      if (m.right().HasResolvedValue()) {
        uint8_t sa = m.right().ResolvedValue() & 0x1f;
        return sa > 0;
      }
      return false;
    }
    case IrOpcode::kLoad:
    case IrOpcode::kLoadImmutable: {
      LoadRepresentation load_rep = LoadRepresentationOf(node->op());
      if (load_rep.IsUnsigned()) {
        switch (load_rep.representation()) {
          case MachineRepresentation::kBit:    // Fall through.
          case MachineRepresentation::kWord8:  // Fall through.
          case MachineRepresentation::kWord16:
            return true;
          default:
            return false;
        }
      }
      return false;
    }
    default:
      return false;
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeUint32ToUint64(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    Loong64OperandGeneratorT<Adapter> g(this);
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const ChangeOp& change_op = this->Get(node).template Cast<ChangeOp>();
    node_t input = change_op.input();
    const Operation& input_op = this->Get(input);

    if (input_op.Is<LoadOp>() && CanCover(node, input)) {
      // Generate zero-extending load.
      LoadRepresentation load_rep = this->load_view(input).loaded_rep();
      if (load_rep.IsUnsigned() &&
          load_rep.representation() == MachineRepresentation::kWord32) {
        EmitLoad(this, input, kLoong64Ld_wu, node);
        return;
      }
    }
    if (ZeroExtendsWord32ToWord64(input)) {
      EmitIdentity(node);
      return;
    }
    Emit(kLoong64Bstrpick_d, g.DefineAsRegister(node), g.UseRegister(input),
         g.TempImmediate(0), g.TempImmediate(32));
  } else {
    Loong64OperandGeneratorT<Adapter> g(this);
    Node* value = node->InputAt(0);

    if (value->opcode() == IrOpcode::kLoad) {
      LoadRepresentation load_rep = LoadRepresentationOf(value->op());
      if (load_rep.IsUnsigned() &&
          load_rep.representation() == MachineRepresentation::kWord32) {
        EmitLoad(this, value, kLoong64Ld_wu, node);
        return;
      }
    }
    if (ZeroExtendsWord32ToWord64(value)) {
      EmitIdentity(node);
      return;
    }
    Emit(kLoong64Bstrpick_d, g.DefineAsRegister(node),
         g.UseRegister(node->InputAt(0)), g.TempImmediate(0),
         g.TempImmediate(32));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateInt64ToInt32(node_t node) {
    Loong64OperandGeneratorT<Adapter> g(this);
    Node* value = node->InputAt(0);
    if (CanCover(node, value)) {
      switch (value->opcode()) {
        case IrOpcode::kWord64Sar: {
          if (CanCover(value, value->InputAt(0)) &&
              TryEmitExtendingLoad(this, value, node)) {
            return;
          } else {
            Int64BinopMatcher m(value);
            if (m.right().IsInRange(32, 63)) {
              // After smi untagging no need for truncate. Combine sequence.
              Emit(kLoong64Sra_d, g.DefineAsRegister(node),
                   g.UseRegister(m.left().node()),
                   g.UseImmediate(m.right().node()));
              return;
            }
          }
          break;
        }
        default:
          break;
      }
    }
    Emit(kLoong64Sll_w, g.DefineAsRegister(node),
         g.UseRegister(node->InputAt(0)), g.TempImmediate(0));
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitTruncateInt64ToInt32(
    node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  Loong64OperandGeneratorT<TurboshaftAdapter> g(this);
  auto value = input_at(node, 0);
  if (CanCover(node, value)) {
    if (Get(value).Is<Opmask::kWord64ShiftRightArithmetic>()) {
      auto shift_value = input_at(value, 1);
      if (CanCover(value, input_at(value, 0)) &&
          TryEmitExtendingLoad(this, value, node)) {
        return;
      } else if (g.IsIntegerConstant(shift_value)) {
        auto constant = g.GetIntegerConstantValue(constant_view(shift_value));

        if (constant >= 32 && constant <= 63) {
          // After smi untagging no need for truncate. Combine sequence.
          Emit(kLoong64Sra_d, g.DefineAsRegister(node),
               g.UseRegister(input_at(value, 0)), g.UseImmediate(constant));
          return;
        }
      }
    }
  }
  Emit(kLoong64Sll_w, g.DefineAsRegister(node), g.UseRegister(value),
       g.TempImmediate(0));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateFloat64ToFloat32(node_t node) {
  Loong64OperandGeneratorT<Adapter> g(this);

  if constexpr (Adapter::IsTurboshaft) {
    // TODO(loong64): Check if could be optimized like turbofan here.
  } else {
    Node* value = node->InputAt(0);
    // Match TruncateFloat64ToFloat32(ChangeInt32ToFloat64) to corresponding
    // instruction.
    if (CanCover(node, value) &&
        value->opcode() == IrOpcode::kChangeInt32ToFloat64) {
      Emit(kLoong64Int32ToFloat32, g.DefineAsRegister(node),
           g.UseRegister(value->InputAt(0)));
      return;
    }
  }

  VisitRR(this, kLoong64Float64ToFloat32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateFloat64ToWord32(node_t node) {
  VisitRR(this, kArchTruncateDoubleToI, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitRoundFloat64ToInt32(node_t node) {
  VisitRR(this, kLoong64Float64ToInt32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitRoundInt64ToFloat32(node_t node) {
  VisitRR(this, kLoong64Int64ToFloat32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitRoundInt64ToFloat64(node_t node) {
  VisitRR(this, kLoong64Int64ToFloat64, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitRoundUint64ToFloat32(node_t node) {
  VisitRR(this, kLoong64Uint64ToFloat32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitRoundUint64ToFloat64(node_t node) {
  VisitRR(this, kLoong64Uint64ToFloat64, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitBitcastFloat32ToInt32(node_t node) {
  VisitRR(this, kLoong64Float64ExtractLowWord32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitBitcastFloat64ToInt64(node_t node) {
  VisitRR(this, kLoong64BitcastDL, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitBitcastInt32ToFloat32(node_t node) {
  // when move lower 32 bits of general registers to 64-bit fpu registers on
  // LoongArch64, the upper 32 bits of the fpu register is undefined. So we
  // could just move the whole 64 bits to fpu registers.
  VisitRR(this, kLoong64BitcastLD, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitBitcastInt64ToFloat64(node_t node) {
  VisitRR(this, kLoong64BitcastLD, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Add(node_t node) {
  VisitRRR(this, kLoong64Float32Add, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Add(node_t node) {
  VisitRRR(this, kLoong64Float64Add, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Sub(node_t node) {
  VisitRRR(this, kLoong64Float32Sub, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Sub(node_t node) {
  VisitRRR(this, kLoong64Float64Sub, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Mul(node_t node) {
  VisitRRR(this, kLoong64Float32Mul, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Mul(node_t node) {
  VisitRRR(this, kLoong64Float64Mul, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Div(node_t node) {
  VisitRRR(this, kLoong64Float32Div, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Div(node_t node) {
  VisitRRR(this, kLoong64Float64Div, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Mod(node_t node) {
  Loong64OperandGeneratorT<Adapter> g(this);
  Emit(kLoong64Float64Mod, g.DefineAsFixed(node, f0),
       g.UseFixed(this->input_at(node, 0), f0),
       g.UseFixed(this->input_at(node, 1), f1))
      ->MarkAsCall();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Max(node_t node) {
  VisitRRR(this, kLoong64Float32Max, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Max(node_t node) {
  VisitRRR(this, kLoong64Float64Max, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Min(node_t node) {
  VisitRRR(this, kLoong64Float32Min, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Min(node_t node) {
  VisitRRR(this, kLoong64Float64Min, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Abs(node_t node) {
  VisitRR(this, kLoong64Float32Abs, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Abs(node_t node) {
  VisitRR(this, kLoong64Float64Abs, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Sqrt(node_t node) {
  VisitRR(this, kLoong64Float32Sqrt, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Sqrt(node_t node) {
  VisitRR(this, kLoong64Float64Sqrt, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32RoundDown(node_t node) {
  VisitRR(this, kLoong64Float32RoundDown, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64RoundDown(node_t node) {
  VisitRR(this, kLoong64Float64RoundDown, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32RoundUp(node_t node) {
  VisitRR(this, kLoong64Float32RoundUp, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64RoundUp(node_t node) {
  VisitRR(this, kLoong64Float64RoundUp, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32RoundTruncate(node_t node) {
  VisitRR(this, kLoong64Float32RoundTruncate, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64RoundTruncate(node_t node) {
  VisitRR(this, kLoong64Float64RoundTruncate, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64RoundTiesAway(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32RoundTiesEven(node_t node) {
  VisitRR(this, kLoong64Float32RoundTiesEven, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64RoundTiesEven(node_t node) {
  VisitRR(this, kLoong64Float64RoundTiesEven, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Neg(node_t node) {
  VisitRR(this, kLoong64Float32Neg, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Neg(node_t node) {
  VisitRR(this, kLoong64Float64Neg, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Ieee754Binop(
    node_t node, InstructionCode opcode) {
  Loong64OperandGeneratorT<Adapter> g(this);
  Emit(opcode, g.DefineAsFixed(node, f0),
       g.UseFixed(this->input_at(node, 0), f0),
       g.UseFixed(this->input_at(node, 1), f1))
      ->MarkAsCall();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Ieee754Unop(
    node_t node, InstructionCode opcode) {
  Loong64OperandGeneratorT<Adapter> g(this);
  Emit(opcode, g.DefineAsFixed(node, f0),
       g.UseFixed(this->input_at(node, 0), f0))
      ->MarkAsCall();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::EmitMoveParamToFPR(node_t node,
                                                       int32_t index) {
  if constexpr (Adapter::IsTurboshaft) {
    UNIMPLEMENTED();
  } else {
    OperandGenerator g(this);
    int count = linkage()->GetParameterLocation(index).GetLocation();
    InstructionOperand out_op = g.TempRegister(-count);
    Emit(kArchNop, out_op);
    Emit(kLoong64BitcastLD, g.DefineAsRegister(node), out_op);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::EmitMoveFPRToParam(
    InstructionOperand* op, LinkageLocation location) {
  OperandGenerator g(this);
  int count = location.GetLocation();
  InstructionOperand new_op = g.TempRegister(-count);
  Emit(kLoong64BitcastDL, new_op, *op);
  *op = new_op;
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::EmitPrepareArguments(
    ZoneVector<
"""


```