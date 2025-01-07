Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/compiler/wasm-compiler.cc`. The prompt also includes several constraints and questions about the code:

1. **List Functionality:** Describe what the code does.
2. **Torque Source:** Check if the filename ends with `.tq`. This is a quick check; the code snippet is C++, so this will be false.
3. **JavaScript Relationship:** If the code relates to JavaScript, provide an example. This code deals with WebAssembly compilation, which is closely tied to JavaScript.
4. **Code Logic Inference:** Provide input and output examples if there's any logic to infer. This code is about building a graph representation of WebAssembly operations.
5. **Common Programming Errors:** Point out potential user programming errors related to the functionality. This is about how WebAssembly developers might make mistakes that this code helps handle.
6. **Part of a Whole:**  Acknowledge that this is part 2 of 12.
7. **Summarize Functionality:** Provide a concise summary of the code's role.

**Plan:**

1. **High-Level Overview:**  Recognize that this code snippet is part of the `WasmGraphBuilder` class, responsible for translating WebAssembly operations into a graph-based Intermediate Representation (IR) used by V8's optimizing compiler (Turbofan).
2. **Focus on the `EmitUnop` Method:** The provided code is primarily within the `EmitUnop` method, which handles unary WebAssembly operations.
3. **Identify Key Operations:**  List the different WebAssembly unary operations handled in the `switch` statement (conversions, bitwise operations, floating-point functions).
4. **Explain the Graph Building Process:** Explain how each case in the `switch` statement translates a WebAssembly operation into corresponding V8 IR nodes (using `mcgraph()->machine()` and `graph()->NewNode()`).
5. **Address the Constraints:**
    * `.tq` check:  State that the file doesn't end in `.tq`.
    * JavaScript Relation: Provide a simple JavaScript example that would lead to these operations being executed during WebAssembly execution.
    * Logic Inference:  Give a simple example of a WebAssembly unary operation and how it might be translated into a V8 IR node.
    * Common Errors: Discuss common WebAssembly developer errors related to type conversions and potential overflows.
    * Acknowledge part 2/12.
6. **Summarize:**  Provide a concise summary of the code's role in the compilation process.
```cpp
:
      return BuildI32AsmjsSConvertF64(input);
    case wasm::kExprI32AsmjsUConvertF64:
      return BuildI32AsmjsUConvertF64(input);
    case wasm::kExprF32ConvertF64:
      op = m->TruncateFloat64ToFloat32();
      break;
    case wasm::kExprF64SConvertI32:
      op = m->ChangeInt32ToFloat64();
      break;
    case wasm::kExprF64UConvertI32:
      op = m->ChangeUint32ToFloat64();
      break;
    case wasm::kExprF32SConvertI32:
      op = m->RoundInt32ToFloat32();
      break;
    case wasm::kExprF32UConvertI32:
      op = m->RoundUint32ToFloat32();
      break;
    case wasm::kExprI32AsmjsSConvertF32:
      return BuildI32AsmjsSConvertF32(input);
    case wasm::kExprI32AsmjsUConvertF32:
      return BuildI32AsmjsUConvertF32(input);
    case wasm::kExprF64ConvertF32:
      op = m->ChangeFloat32ToFloat64();
      break;
    case wasm::kExprF32ReinterpretI32:
      op = m->BitcastInt32ToFloat32();
      break;
    case wasm::kExprI32ReinterpretF32:
      op = m->BitcastFloat32ToInt32();
      break;
    case wasm::kExprI32Clz:
      op = m->Word32Clz();
      break;
    case wasm::kExprI32Ctz: {
      if (m->Word32Ctz().IsSupported()) {
        op = m->Word32Ctz().op();
        break;
      } else if (m->Word32ReverseBits().IsSupported()) {
        Node* reversed = graph()->NewNode(m->Word32ReverseBits().op(), input);
        Node* result = graph()->NewNode(m->Word32Clz(), reversed);
        return result;
      } else {
        return BuildI32Ctz(input);
      }
    }
    case wasm::kExprI32Popcnt: {
      if (m->Word32Popcnt().IsSupported()) {
        op = m->Word32Popcnt().op();
        break;
      } else {
        return BuildI32Popcnt(input);
      }
    }
    case wasm::kExprF32Floor: {
      if (!m->Float32RoundDown().IsSupported()) return BuildF32Floor(input);
      op = m->Float32RoundDown().op();
      break;
    }
    case wasm::kExprF32Ceil: {
      if (!m->Float32RoundUp().IsSupported()) return BuildF32Ceil(input);
      op = m->Float32RoundUp().op();
      break;
    }
    case wasm::kExprF32Trunc: {
      if (!m->Float32RoundTruncate().IsSupported()) return BuildF32Trunc(input);
      op = m->Float32RoundTruncate().op();
      break;
    }
    case wasm::kExprF32NearestInt: {
      if (!m->Float32RoundTiesEven().IsSupported())
        return BuildF32NearestInt(input);
      op = m->Float32RoundTiesEven().op();
      break;
    }
    case wasm::kExprF64Floor: {
      if (!m->Float64RoundDown().IsSupported()) return BuildF64Floor(input);
      op = m->Float64RoundDown().op();
      break;
    }
    case wasm::kExprF64Ceil: {
      if (!m->Float64RoundUp().IsSupported()) return BuildF64Ceil(input);
      op = m->Float64RoundUp().op();
      break;
    }
    case wasm::kExprF64Trunc: {
      if (!m->Float64RoundTruncate().IsSupported()) return BuildF64Trunc(input);
      op = m->Float64RoundTruncate().op();
      break;
    }
    case wasm::kExprF64NearestInt: {
      if (!m->Float64RoundTiesEven().IsSupported())
        return BuildF64NearestInt(input);
      op = m->Float64RoundTiesEven().op();
      break;
    }
    case wasm::kExprF64Acos: {
      return BuildF64Acos(input);
    }
    case wasm::kExprF64Asin: {
      return BuildF64Asin(input);
    }
    case wasm::kExprF64Atan:
      op = m->Float64Atan();
      break;
    case wasm::kExprF64Cos: {
      op = m->Float64Cos();
      break;
    }
    case wasm::kExprF64Sin: {
      op = m->Float64Sin();
      break;
    }
    case wasm::kExprF64Tan: {
      op = m->Float64Tan();
      break;
    }
    case wasm::kExprF64Exp: {
      op = m->Float64Exp();
      break;
    }
    case wasm::kExprF64Log:
      op = m->Float64Log();
      break;
    case wasm::kExprI32ConvertI64:
      op = m->TruncateInt64ToInt32();
      break;
    case wasm::kExprI64SConvertI32:
      op = m->ChangeInt32ToInt64();
      break;
    case wasm::kExprI64UConvertI32:
      op = m->ChangeUint32ToUint64();
      break;
    case wasm::kExprF64ReinterpretI64:
      op = m->BitcastInt64ToFloat64();
      break;
    case wasm::kExprI64ReinterpretF64:
      op = m->BitcastFloat64ToInt64();
      break;
    case wasm::kExprI64Clz:
      return m->Is64()
                 ? graph()->NewNode(m->Word64Clz(), input)
                 : graph()->NewNode(m->Word64ClzLowerable(), input, control());
    case wasm::kExprI64Ctz: {
      if (m->Word64Ctz().IsSupported()) {
        return m->Is64() ? graph()->NewNode(m->Word64Ctz().op(), input)
                         : graph()->NewNode(m->Word64CtzLowerable().op(), input,
                                            control());
      } else if (m->Is32() && m->Word32Ctz().IsSupported()) {
        return graph()->NewNode(m->Word64CtzLowerable().placeholder(), input,
                                control());
      } else if (m->Word64ReverseBits().IsSupported()) {
        Node* reversed = graph()->NewNode(m->Word64ReverseBits().op(), input);
        Node* result = m->Is64() ? graph()->NewNode(m->Word64Clz(), reversed)
                                 : graph()->NewNode(m->Word64ClzLowerable(),
                                                    reversed, control());
        return result;
      } else {
        return BuildI64Ctz(input);
      }
    }
    case wasm::kExprI64Popcnt: {
      OptionalOperator popcnt64 = m->Word64Popcnt();
      if (popcnt64.IsSupported()) {
        op = popcnt64.op();
      } else if (m->Is32() && m->Word32Popcnt().IsSupported()) {
        op = popcnt64.placeholder();
      } else {
        return BuildI64Popcnt(input);
      }
      break;
    }
    case wasm::kExprI64Eqz:
      return gasm_->Word64Equal(input, Int64Constant(0));
    case wasm::kExprF32SConvertI64:
      if (m->Is32()) {
        return BuildF32SConvertI64(input);
      }
      op = m->RoundInt64ToFloat32();
      break;
    case wasm::kExprF32UConvertI64:
      if (m->Is32()) {
        return BuildF32UConvertI64(input);
      }
      op = m->RoundUint64ToFloat32();
      break;
    case wasm::kExprF64SConvertI64:
      if (m->Is32()) {
        return BuildF64SConvertI64(input);
      }
      op = m->RoundInt64ToFloat64();
      break;
    case wasm::kExprF64UConvertI64:
      if (m->Is32()) {
        return BuildF64UConvertI64(input);
      }
      op = m->RoundUint64ToFloat64();
      break;
    case wasm::kExprI32SExtendI8:
      op = m->SignExtendWord8ToInt32();
      break;
    case wasm::kExprI32SExtendI16:
      op = m->SignExtendWord16ToInt32();
      break;
    case wasm::kExprI64SExtendI8:
      op = m->SignExtendWord8ToInt64();
      break;
    case wasm::kExprI64SExtendI16:
      op = m->SignExtendWord16ToInt64();
      break;
    case wasm::kExprI64SExtendI32:
      op = m->SignExtendWord32ToInt64();
      break;
    case wasm::kExprI64SConvertF32:
    case wasm::kExprI64UConvertF32:
    case wasm::kExprI64SConvertF64:
    case wasm::kExprI64UConvertF64:
    case wasm::kExprI64SConvertSatF32:
    case wasm::kExprI64UConvertSatF32:
    case wasm::kExprI64SConvertSatF64:
    case wasm::kExprI64UConvertSatF64:
      return mcgraph()->machine()->Is32()
                 ? BuildCcallConvertFloat(input, position, opcode)
                 : BuildIntConvertFloat(input, position, opcode);
    case wasm::kExprRefIsNull:
      return IsNull(input, type);
    // We abuse ref.as_non_null, which isn't otherwise used in this switch, as
    // a sentinel for the negation of ref.is_null.
    case wasm::kExprRefAsNonNull:
      return gasm_->Word32Equal(gasm_->Int32Constant(0), IsNull(input, type));
    case wasm::kExprI32AsmjsLoadMem8S:
      return BuildAsmjsLoadMem(MachineType::Int8(), input);
    case wasm::kExprI32AsmjsLoadMem8U:
      return BuildAsmjsLoadMem(MachineType::Uint8(), input);
    case wasm::kExprI32AsmjsLoadMem16S:
      return BuildAsmjsLoadMem(MachineType::Int16(), input);
    case wasm::kExprI32AsmjsLoadMem16U:
      return BuildAsmjsLoadMem(MachineType::Uint16(), input);
    case wasm::kExprI32AsmjsLoadMem:
      return BuildAsmjsLoadMem(MachineType::Int32(), input);
    case wasm::kExprF32AsmjsLoadMem:
      return BuildAsmjsLoadMem(MachineType::Float32(), input);
    case wasm::kExprF64AsmjsLoadMem:
      return BuildAsmjsLoadMem(MachineType::Float64(), input);
    case wasm::kExprAnyConvertExtern: {
      return gasm_->WasmAnyConvertExtern(input);
    }
    case wasm::kExprExternConvertAny:
      return gasm_->WasmExternConvertAny(input);
    default:
      FATAL_UNSUPPORTED_OPCODE(opcode);
  }
  return graph()->NewNode(op, input);
}

Node* WasmGraphBuilder::Float32Constant(float value) {
  return mcgraph()->Float32Constant(value);
}

Node* WasmGraphBuilder::Float64Constant(double value) {
  return mcgraph()->Float64Constant(value);
}

Node* WasmGraphBuilder::Simd128Constant(const uint8_t value[16]) {
  has_simd_ = true;
  return graph()->NewNode(mcgraph()->machine()->S128Const(value));
}

std::tuple<Node*, Node*> WasmGraphBuilder::BranchNoHint(Node* cond) {
  Node* true_node;
  Node* false_node;
  gasm_->Branch(cond, &true_node, &false_node, BranchHint::kNone);
  return {true_node, false_node};
}

std::tuple<Node*, Node*> WasmGraphBuilder::BranchExpectFalse(Node* cond) {
  Node* true_node;
  Node* false_node;
  gasm_->Branch(cond, &true_node, &false_node, BranchHint::kFalse);
  return {true_node, false_node};
}

std::tuple<Node*, Node*> WasmGraphBuilder::BranchExpectTrue(Node* cond) {
  Node* true_node;
  Node* false_node;
  gasm_->Branch(cond, &true_node, &false_node, BranchHint::kTrue);
  return {true_node, false_node};
}

Node* WasmGraphBuilder::Select(Node *cond, Node* true_node,
                               Node* false_node, wasm::ValueType type) {
  MachineOperatorBuilder* m = mcgraph()->machine();
  wasm::ValueKind kind = type.kind();
  // Lower to select if supported.
  if (kind == wasm::kF32 && m->Float32Select().IsSupported()) {
    return mcgraph()->graph()->NewNode(m->Float32Select().op(), cond,
                                       true_node, false_node);
  }
  if (kind == wasm::kF64 && m->Float64Select().IsSupported()) {
    return mcgraph()->graph()->NewNode(m->Float64Select().op(), cond,
                                       true_node, false_node);
  }
  if (kind == wasm::kI32 && m->Word32Select().IsSupported()) {
    return mcgraph()->graph()->NewNode(m->Word32Select().op(), cond, true_node,
                                       false_node);
  }
  if (kind == wasm::kI64 && m->Word64Select().IsSupported()) {
    return mcgraph()->graph()->NewNode(m->Word64Select().op(), cond, true_node,
                                       false_node);
  }
  // Default to control-flow.

  auto [if_true, if_false] = BranchNoHint(cond);
  Node* merge = Merge(if_true, if_false);
  SetControl(merge);
  Node* inputs[] = {true_node, false_node, merge};
  return Phi(type, 2, inputs);
}

// TODO(ahaas): Merge TrapId with TrapReason.
TrapId WasmGraphBuilder::GetTrapIdForTrap(wasm::TrapReason reason) {
  switch (reason) {
#define TRAPREASON_TO_TRAPID(name)                                 \
  case wasm::k##name:                                              \
    static_assert(static_cast<int>(TrapId::k##name) ==             \
                      static_cast<int>(Builtin::kThrowWasm##name), \
                  "trap id mismatch");                             \
    return TrapId::k##name;
    FOREACH_WASM_TRAPREASON(TRAPREASON_TO_TRAPID)
#undef TRAPREASON_TO_TRAPID
    default:
      UNREACHABLE();
  }
}

void WasmGraphBuilder::TrapIfTrue(wasm::TrapReason reason, Node* cond,
                                  wasm::WasmCodePosition position) {
  TrapId trap_id = GetTrapIdForTrap(reason);
  gasm_->TrapIf(cond, trap_id);
  SetSourcePosition(effect(), position);
}

void WasmGraphBuilder::TrapIfFalse(wasm::TrapReason reason, Node* cond,
                                   wasm::WasmCodePosition position) {
  TrapId trap_id = GetTrapIdForTrap(reason);
  gasm_->TrapUnless(cond, trap_id);
  SetSourcePosition(effect(), position);
}

Node* WasmGraphBuilder::AssertNotNull(Node* object, wasm::ValueType type,
                                      wasm::WasmCodePosition position,
                                      wasm::TrapReason reason) {
  TrapId trap_id = GetTrapIdForTrap(reason);
  Node* result = gasm_->AssertNotNull(object, type, trap_id);
  SetSourcePosition(result, position);
  return result;
}

// Add a check that traps if {node} is equal to {val}.
void WasmGraphBuilder::TrapIfEq32(wasm::TrapReason reason, Node* node,
                                  int32_t val,
                                  wasm::WasmCodePosition position) {
  if (val == 0) {
    TrapIfFalse(reason, node, position);
  } else {
    TrapIfTrue(reason, gasm_->Word32Equal(node, Int32Constant(val)), position);
  }
}

// Add a check that traps if {node} is zero.
void WasmGraphBuilder::ZeroCheck32(wasm::TrapReason reason, Node* node,
                                   wasm::WasmCodePosition position) {
  TrapIfEq32(reason, node, 0, position);
}

// Add a check that traps if {node} is equal to {val}.
void WasmGraphBuilder::TrapIfEq64(wasm::TrapReason reason, Node* node,
                                  int64_t val,
                                  wasm::WasmCodePosition position) {
  TrapIfTrue(reason, gasm_->Word64Equal(node, Int64Constant(val)), position);
}

// Add a check that traps if {node} is zero.
void WasmGraphBuilder::ZeroCheck64(wasm::TrapReason reason, Node* node,
                                   wasm::WasmCodePosition position) {
  TrapIfEq64(reason, node, 0, position);
}

Node* WasmGraphBuilder::Switch(unsigned count, Node* key) {
  // The instruction selector will use {kArchTableSwitch} for large switches,
  // which has limited input count, see {InstructionSelector::EmitTableSwitch}.
  DCHECK_LE(count, Instruction::kMaxInputCount - 2);          // value_range + 2
  DCHECK_LE(count, wasm::kV8MaxWasmFunctionBrTableSize + 1);  // plus IfDefault
  return graph()->NewNode(mcgraph()->common()->Switch(count), key, control());
}

Node* WasmGraphBuilder::IfValue(int32_t value, Node* sw) {
  DCHECK_EQ(IrOpcode::kSwitch, sw->opcode());
  return graph()->NewNode(mcgraph()->common()->IfValue(value), sw);
}

Node* WasmGraphBuilder::IfDefault(Node* sw) {
  DCHECK_EQ(IrOpcode::kSwitch, sw->opcode());
  return graph()->NewNode(mcgraph()->common()->IfDefault(), sw);
}

Node* WasmGraphBuilder::Return(base::Vector<Node*> vals) {
  unsigned count = static_cast<unsigned>(vals.size());
  base::SmallVector<Node*, 8> buf(count + 3);

  // TODOC: What is the meaning of the 0-constant?
  buf[0] = Int32Constant(0);
  if (count > 0) {
    memcpy(buf.data() + 1, vals.begin(), sizeof(void*) * count);
  }
  buf[count + 1] = effect();
  buf[count + 2] = control();
  Node* ret = graph()->NewNode(mcgraph()->common()->Return(count), count + 3,
                               buf.data());

  gasm_->MergeControlToEnd(ret);
  return ret;
}

void WasmGraphBuilder::Trap(wasm::TrapReason reason,
                            wasm::WasmCodePosition position) {
  TrapIfFalse(reason, Int32Constant(0), position);
  // Connect control to end via a Throw() node.
  TerminateThrow(effect(), control());
}

Node* WasmGraphBuilder::MaskShiftCount32(Node* node) {
  static const int32_t kMask32 = 0x1F;
  if (!mcgraph()->machine()->Word32ShiftIsSafe()) {
    // Shifts by constants are so common we pattern-match them here.
    Int32Matcher match(node);
    if (match.HasResolvedValue()) {
      int32_t masked = (match.ResolvedValue() & kMask32);
      if (match.ResolvedValue() != masked) node = Int32Constant(masked);
    } else {
      node = gasm_->Word32And(node, Int32Constant(kMask32));
    }
  }
  return node;
}

Node* WasmGraphBuilder::MaskShiftCount64(Node* node) {
  static const int64_t kMask64 = 0x3F;
  if (!mcgraph()->machine()->Word32ShiftIsSafe()) {
    // Shifts by constants are so common we pattern-match them here.
    Int64Matcher match(node);
    if (match.HasResolvedValue()) {
      int64_t masked = (match.ResolvedValue() & kMask64);
      if (match.ResolvedValue() != masked) node = Int64Constant(masked);
    } else {
      node = gasm_->Word64And(node, Int64Constant(kMask64));
    }
  }
  return node;
}

namespace {

bool ReverseBytesSupported(MachineOperatorBuilder* m, size_t size_in_bytes) {
  switch (size_in_bytes) {
    case 4:
    case 16:
      return true;
    case 8:
      return m->Is64();
    default:
      break;
  }
  return false;
}

}  // namespace

Node* WasmGraphBuilder::BuildChangeEndiannessStore(
    Node* node, MachineRepresentation mem_rep, wasm::ValueType wasmtype) {
  Node* result;
  Node* value = node;
  MachineOperatorBuilder* m = mcgraph()->machine();
  int valueSizeInBytes = wasmtype.value_kind_size();
  int valueSizeInBits = 8 * valueSizeInBytes;
  bool isFloat = false;

  switch (wasmtype.kind()) {
    case wasm::kF64:
      value = gasm_->BitcastFloat64ToInt64(node);
      isFloat = true;
      [[fallthrough]];
    case wasm::kI64:
      result = Int64Constant(0);
      break;
    case wasm::kF32:
      value = gasm_->BitcastFloat32ToInt32(node);
      isFloat = true;
      [[fallthrough]];
    case wasm::kI32:
      result = Int32Constant(0);
      break;
    case wasm::kS128:
      DCHECK(ReverseBytesSupported(m, valueSizeInBytes));
      break;
    default:
      UNREACHABLE();
  }

  if (mem_rep == MachineRepresentation::kWord8) {
    // No need to change endianness for byte size, return original node
    return node;
  }
  if (wasmtype == wasm::kWasmI64 && mem_rep < MachineRepresentation::kWord64) {
    // In case we store lower part of WasmI64 expression, we can truncate
    // upper 32bits
    value = gasm_->TruncateInt64ToInt32(value);
    valueSizeInBytes = wasm::kWasmI32.value_kind_size();
    valueSizeInBits = 8 * valueSizeInBytes;
    if (mem_rep == MachineRepresentation::kWord16) {
      value = gasm_->Word32Shl(value, Int32Constant(16));
    }
  } else if (wasmtype == wasm::kWasmI32 &&
             mem_rep == MachineRepresentation::kWord16) {
    value = gasm_->Word32Shl(value, Int32Constant(16));
  }

  int i;
  uint32_t shiftCount;

  if (ReverseBytesSupported(m, valueSizeInBytes)) {
    switch (valueSizeInBytes) {
      case 4:
        result = gasm_->Word32ReverseBytes(value);
        break;
      case 8:
        result = gasm_->Word64ReverseBytes(value);
        break;
      case 16:
        result = graph()->NewNode(m->Simd128ReverseBytes(), value);
        break;
      default:
        UNREACHABLE();
    }
  } else {
    for (i = 0, shiftCount = valueSizeInBits - 8; i < valueSizeInBits / 2;
         i += 8, shiftCount -= 16) {
      Node* shiftLower;
      Node* shiftHigher;
      Node* lowerByte;
      Node* higherByte;

      DCHECK_LT(0, shiftCount);
      DCHECK_EQ(0, (shiftCount + 8) % 16);

      if (valueSizeInBits > 32) {
        shiftLower = gasm_->Word64Shl(value, Int64Constant(shiftCount));
        shiftHigher = gasm_->Word64Shr(value, Int64Constant(shiftCount));
        lowerByte = gasm_->Word64And(
            shiftLower, Int64Constant(static_cast<uint64_t>(0xFF)
                                      << (valueSizeInBits - 8 - i)));
        higherByte = gasm_->Word64And(
            shiftHigher, Int64Constant(static_cast<uint64_t>(0xFF) << i));
        result = gasm_->Word64Or(result, lowerByte);
        result = gasm_->Word64Or(result, higherByte);
      } else {
        shiftLower = gasm_->Word32Shl(value, Int32Constant(shiftCount));
        shiftHigher = gasm_->Word32Shr(value, Int32Constant(shiftCount));
        lowerByte = gasm_->Word32And(
            shiftLower, Int32Constant(static_cast<uint32_t>(0xFF)
                                      << (valueSizeInBits - 8 - i)));
        higherByte = gasm_->Word32And(
            shiftHigher, Int32Constant(static_cast<uint32_t>(0xFF) << i));
        result = gasm_->Word32Or(result, lowerByte);
        result = gasm_->Word32Or(result, higherByte);
      }
    }
  }

  if (isFloat) {
    switch (wasmtype.kind()) {
      case wasm::kF64:
        result = gasm_->BitcastInt64ToFloat64(result);
        break;
      case wasm::kF32:
        result = gasm_->BitcastInt32ToFloat32(result);
        break;
      default:
        UNREACHABLE();
    }
  }

  return result;
}

Node* WasmGraphBuilder::BuildChangeEndiannessLoad(Node* node,
                                                  MachineType memtype,
                                                  wasm::ValueType wasmtype) {
  Node* result;
  Node* value = node;
  MachineOperatorBuilder* m = mcgraph()->machine();
  int valueSizeInBytes = ElementSizeInBytes(memtype.representation());
  int valueSizeInBits = 8 * valueSizeInBytes;
  bool isFloat = false;

  switch (memtype.representation()) {
    case MachineRepresentation::kFloat64:
      value = gasm_->BitcastFloat64ToInt64(node);
      isFloat = true;
      [[fallthrough]];
    case MachineRepresentation::kWord64:
      result = Int64Constant(0);
      break;
    case MachineRepresentation::kFloat32:
      value = gasm_->BitcastFloat32ToInt32(node);
      isFloat = true;
      [[fallthrough]];
    case MachineRepresentation::kWord32:
    case MachineRepresentation::kWord16:
      result = Int32Constant(0);
      break;
    case MachineRepresentation::kWord8:
      // No need to change endianness for byte size, return original node
      return node;
    case MachineRepresentation::kSimd128:
      DCHECK(ReverseBytesSupported(m, valueSizeInBytes));
      break;
    default:
      UNREACHABLE();
  }

  int i;
  uint32_t shiftCount;

  if (ReverseBytesSupported(m, valueSizeInBytes < 4 ? 4 : valueSizeInBytes)) {
    switch (valueSizeInBytes) {
      case 2:
        result = gasm_->Word32ReverseBytes(
            gasm_->Word32Shl(value, Int32Constant(16)));
        break;
      case 4:
        result = gasm_->Word32ReverseBytes(value);
        break;
      case 8:
        result = gasm_->Word64ReverseBytes(value);
        break;
      case 16:
        result = graph()->NewNode(m->Simd128ReverseBytes(), value);
        break;
      default:
        UNREACHABLE();
    }
  } else {
    for (i = 0, shiftCount = valueSizeInBits - 8; i < valueSizeInBits / 2;
         i += 8, shiftCount -= 16) {
      Node* shiftLower;
      Node* shiftHigher;
      Node* lowerByte;
      Node* higherByte;

      DCHECK_LT(0, shiftCount);
      DCHECK_EQ(0, (shiftCount + 8) % 16);

      if (valueSizeInBits > 32) {
        shiftLower = gasm_->Word64Shl(value, Int64Constant(shiftCount));
        shiftHigher = gasm_->Word64Shr(value, Int64Constant(shiftCount));
        lowerByte = gasm_->Word64And(
            shiftLower, Int64
Prompt: 
```
这是目录为v8/src/compiler/wasm-compiler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/wasm-compiler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共12部分，请归纳一下它的功能

"""
:
      return BuildI32AsmjsSConvertF64(input);
    case wasm::kExprI32AsmjsUConvertF64:
      return BuildI32AsmjsUConvertF64(input);
    case wasm::kExprF32ConvertF64:
      op = m->TruncateFloat64ToFloat32();
      break;
    case wasm::kExprF64SConvertI32:
      op = m->ChangeInt32ToFloat64();
      break;
    case wasm::kExprF64UConvertI32:
      op = m->ChangeUint32ToFloat64();
      break;
    case wasm::kExprF32SConvertI32:
      op = m->RoundInt32ToFloat32();
      break;
    case wasm::kExprF32UConvertI32:
      op = m->RoundUint32ToFloat32();
      break;
    case wasm::kExprI32AsmjsSConvertF32:
      return BuildI32AsmjsSConvertF32(input);
    case wasm::kExprI32AsmjsUConvertF32:
      return BuildI32AsmjsUConvertF32(input);
    case wasm::kExprF64ConvertF32:
      op = m->ChangeFloat32ToFloat64();
      break;
    case wasm::kExprF32ReinterpretI32:
      op = m->BitcastInt32ToFloat32();
      break;
    case wasm::kExprI32ReinterpretF32:
      op = m->BitcastFloat32ToInt32();
      break;
    case wasm::kExprI32Clz:
      op = m->Word32Clz();
      break;
    case wasm::kExprI32Ctz: {
      if (m->Word32Ctz().IsSupported()) {
        op = m->Word32Ctz().op();
        break;
      } else if (m->Word32ReverseBits().IsSupported()) {
        Node* reversed = graph()->NewNode(m->Word32ReverseBits().op(), input);
        Node* result = graph()->NewNode(m->Word32Clz(), reversed);
        return result;
      } else {
        return BuildI32Ctz(input);
      }
    }
    case wasm::kExprI32Popcnt: {
      if (m->Word32Popcnt().IsSupported()) {
        op = m->Word32Popcnt().op();
        break;
      } else {
        return BuildI32Popcnt(input);
      }
    }
    case wasm::kExprF32Floor: {
      if (!m->Float32RoundDown().IsSupported()) return BuildF32Floor(input);
      op = m->Float32RoundDown().op();
      break;
    }
    case wasm::kExprF32Ceil: {
      if (!m->Float32RoundUp().IsSupported()) return BuildF32Ceil(input);
      op = m->Float32RoundUp().op();
      break;
    }
    case wasm::kExprF32Trunc: {
      if (!m->Float32RoundTruncate().IsSupported()) return BuildF32Trunc(input);
      op = m->Float32RoundTruncate().op();
      break;
    }
    case wasm::kExprF32NearestInt: {
      if (!m->Float32RoundTiesEven().IsSupported())
        return BuildF32NearestInt(input);
      op = m->Float32RoundTiesEven().op();
      break;
    }
    case wasm::kExprF64Floor: {
      if (!m->Float64RoundDown().IsSupported()) return BuildF64Floor(input);
      op = m->Float64RoundDown().op();
      break;
    }
    case wasm::kExprF64Ceil: {
      if (!m->Float64RoundUp().IsSupported()) return BuildF64Ceil(input);
      op = m->Float64RoundUp().op();
      break;
    }
    case wasm::kExprF64Trunc: {
      if (!m->Float64RoundTruncate().IsSupported()) return BuildF64Trunc(input);
      op = m->Float64RoundTruncate().op();
      break;
    }
    case wasm::kExprF64NearestInt: {
      if (!m->Float64RoundTiesEven().IsSupported())
        return BuildF64NearestInt(input);
      op = m->Float64RoundTiesEven().op();
      break;
    }
    case wasm::kExprF64Acos: {
      return BuildF64Acos(input);
    }
    case wasm::kExprF64Asin: {
      return BuildF64Asin(input);
    }
    case wasm::kExprF64Atan:
      op = m->Float64Atan();
      break;
    case wasm::kExprF64Cos: {
      op = m->Float64Cos();
      break;
    }
    case wasm::kExprF64Sin: {
      op = m->Float64Sin();
      break;
    }
    case wasm::kExprF64Tan: {
      op = m->Float64Tan();
      break;
    }
    case wasm::kExprF64Exp: {
      op = m->Float64Exp();
      break;
    }
    case wasm::kExprF64Log:
      op = m->Float64Log();
      break;
    case wasm::kExprI32ConvertI64:
      op = m->TruncateInt64ToInt32();
      break;
    case wasm::kExprI64SConvertI32:
      op = m->ChangeInt32ToInt64();
      break;
    case wasm::kExprI64UConvertI32:
      op = m->ChangeUint32ToUint64();
      break;
    case wasm::kExprF64ReinterpretI64:
      op = m->BitcastInt64ToFloat64();
      break;
    case wasm::kExprI64ReinterpretF64:
      op = m->BitcastFloat64ToInt64();
      break;
    case wasm::kExprI64Clz:
      return m->Is64()
                 ? graph()->NewNode(m->Word64Clz(), input)
                 : graph()->NewNode(m->Word64ClzLowerable(), input, control());
    case wasm::kExprI64Ctz: {
      if (m->Word64Ctz().IsSupported()) {
        return m->Is64() ? graph()->NewNode(m->Word64Ctz().op(), input)
                         : graph()->NewNode(m->Word64CtzLowerable().op(), input,
                                            control());
      } else if (m->Is32() && m->Word32Ctz().IsSupported()) {
        return graph()->NewNode(m->Word64CtzLowerable().placeholder(), input,
                                control());
      } else if (m->Word64ReverseBits().IsSupported()) {
        Node* reversed = graph()->NewNode(m->Word64ReverseBits().op(), input);
        Node* result = m->Is64() ? graph()->NewNode(m->Word64Clz(), reversed)
                                 : graph()->NewNode(m->Word64ClzLowerable(),
                                                    reversed, control());
        return result;
      } else {
        return BuildI64Ctz(input);
      }
    }
    case wasm::kExprI64Popcnt: {
      OptionalOperator popcnt64 = m->Word64Popcnt();
      if (popcnt64.IsSupported()) {
        op = popcnt64.op();
      } else if (m->Is32() && m->Word32Popcnt().IsSupported()) {
        op = popcnt64.placeholder();
      } else {
        return BuildI64Popcnt(input);
      }
      break;
    }
    case wasm::kExprI64Eqz:
      return gasm_->Word64Equal(input, Int64Constant(0));
    case wasm::kExprF32SConvertI64:
      if (m->Is32()) {
        return BuildF32SConvertI64(input);
      }
      op = m->RoundInt64ToFloat32();
      break;
    case wasm::kExprF32UConvertI64:
      if (m->Is32()) {
        return BuildF32UConvertI64(input);
      }
      op = m->RoundUint64ToFloat32();
      break;
    case wasm::kExprF64SConvertI64:
      if (m->Is32()) {
        return BuildF64SConvertI64(input);
      }
      op = m->RoundInt64ToFloat64();
      break;
    case wasm::kExprF64UConvertI64:
      if (m->Is32()) {
        return BuildF64UConvertI64(input);
      }
      op = m->RoundUint64ToFloat64();
      break;
    case wasm::kExprI32SExtendI8:
      op = m->SignExtendWord8ToInt32();
      break;
    case wasm::kExprI32SExtendI16:
      op = m->SignExtendWord16ToInt32();
      break;
    case wasm::kExprI64SExtendI8:
      op = m->SignExtendWord8ToInt64();
      break;
    case wasm::kExprI64SExtendI16:
      op = m->SignExtendWord16ToInt64();
      break;
    case wasm::kExprI64SExtendI32:
      op = m->SignExtendWord32ToInt64();
      break;
    case wasm::kExprI64SConvertF32:
    case wasm::kExprI64UConvertF32:
    case wasm::kExprI64SConvertF64:
    case wasm::kExprI64UConvertF64:
    case wasm::kExprI64SConvertSatF32:
    case wasm::kExprI64UConvertSatF32:
    case wasm::kExprI64SConvertSatF64:
    case wasm::kExprI64UConvertSatF64:
      return mcgraph()->machine()->Is32()
                 ? BuildCcallConvertFloat(input, position, opcode)
                 : BuildIntConvertFloat(input, position, opcode);
    case wasm::kExprRefIsNull:
      return IsNull(input, type);
    // We abuse ref.as_non_null, which isn't otherwise used in this switch, as
    // a sentinel for the negation of ref.is_null.
    case wasm::kExprRefAsNonNull:
      return gasm_->Word32Equal(gasm_->Int32Constant(0), IsNull(input, type));
    case wasm::kExprI32AsmjsLoadMem8S:
      return BuildAsmjsLoadMem(MachineType::Int8(), input);
    case wasm::kExprI32AsmjsLoadMem8U:
      return BuildAsmjsLoadMem(MachineType::Uint8(), input);
    case wasm::kExprI32AsmjsLoadMem16S:
      return BuildAsmjsLoadMem(MachineType::Int16(), input);
    case wasm::kExprI32AsmjsLoadMem16U:
      return BuildAsmjsLoadMem(MachineType::Uint16(), input);
    case wasm::kExprI32AsmjsLoadMem:
      return BuildAsmjsLoadMem(MachineType::Int32(), input);
    case wasm::kExprF32AsmjsLoadMem:
      return BuildAsmjsLoadMem(MachineType::Float32(), input);
    case wasm::kExprF64AsmjsLoadMem:
      return BuildAsmjsLoadMem(MachineType::Float64(), input);
    case wasm::kExprAnyConvertExtern: {
      return gasm_->WasmAnyConvertExtern(input);
    }
    case wasm::kExprExternConvertAny:
      return gasm_->WasmExternConvertAny(input);
    default:
      FATAL_UNSUPPORTED_OPCODE(opcode);
  }
  return graph()->NewNode(op, input);
}

Node* WasmGraphBuilder::Float32Constant(float value) {
  return mcgraph()->Float32Constant(value);
}

Node* WasmGraphBuilder::Float64Constant(double value) {
  return mcgraph()->Float64Constant(value);
}

Node* WasmGraphBuilder::Simd128Constant(const uint8_t value[16]) {
  has_simd_ = true;
  return graph()->NewNode(mcgraph()->machine()->S128Const(value));
}

std::tuple<Node*, Node*> WasmGraphBuilder::BranchNoHint(Node* cond) {
  Node* true_node;
  Node* false_node;
  gasm_->Branch(cond, &true_node, &false_node, BranchHint::kNone);
  return {true_node, false_node};
}

std::tuple<Node*, Node*> WasmGraphBuilder::BranchExpectFalse(Node* cond) {
  Node* true_node;
  Node* false_node;
  gasm_->Branch(cond, &true_node, &false_node, BranchHint::kFalse);
  return {true_node, false_node};
}

std::tuple<Node*, Node*> WasmGraphBuilder::BranchExpectTrue(Node* cond) {
  Node* true_node;
  Node* false_node;
  gasm_->Branch(cond, &true_node, &false_node, BranchHint::kTrue);
  return {true_node, false_node};
}

Node* WasmGraphBuilder::Select(Node *cond, Node* true_node,
                               Node* false_node, wasm::ValueType type) {
  MachineOperatorBuilder* m = mcgraph()->machine();
  wasm::ValueKind kind = type.kind();
  // Lower to select if supported.
  if (kind == wasm::kF32 && m->Float32Select().IsSupported()) {
    return mcgraph()->graph()->NewNode(m->Float32Select().op(), cond,
                                       true_node, false_node);
  }
  if (kind == wasm::kF64 && m->Float64Select().IsSupported()) {
    return mcgraph()->graph()->NewNode(m->Float64Select().op(), cond,
                                       true_node, false_node);
  }
  if (kind == wasm::kI32 && m->Word32Select().IsSupported()) {
    return mcgraph()->graph()->NewNode(m->Word32Select().op(), cond, true_node,
                                       false_node);
  }
  if (kind == wasm::kI64 && m->Word64Select().IsSupported()) {
    return mcgraph()->graph()->NewNode(m->Word64Select().op(), cond, true_node,
                                       false_node);
  }
  // Default to control-flow.

  auto [if_true, if_false] = BranchNoHint(cond);
  Node* merge = Merge(if_true, if_false);
  SetControl(merge);
  Node* inputs[] = {true_node, false_node, merge};
  return Phi(type, 2, inputs);
}

// TODO(ahaas): Merge TrapId with TrapReason.
TrapId WasmGraphBuilder::GetTrapIdForTrap(wasm::TrapReason reason) {
  switch (reason) {
#define TRAPREASON_TO_TRAPID(name)                                 \
  case wasm::k##name:                                              \
    static_assert(static_cast<int>(TrapId::k##name) ==             \
                      static_cast<int>(Builtin::kThrowWasm##name), \
                  "trap id mismatch");                             \
    return TrapId::k##name;
    FOREACH_WASM_TRAPREASON(TRAPREASON_TO_TRAPID)
#undef TRAPREASON_TO_TRAPID
    default:
      UNREACHABLE();
  }
}

void WasmGraphBuilder::TrapIfTrue(wasm::TrapReason reason, Node* cond,
                                  wasm::WasmCodePosition position) {
  TrapId trap_id = GetTrapIdForTrap(reason);
  gasm_->TrapIf(cond, trap_id);
  SetSourcePosition(effect(), position);
}

void WasmGraphBuilder::TrapIfFalse(wasm::TrapReason reason, Node* cond,
                                   wasm::WasmCodePosition position) {
  TrapId trap_id = GetTrapIdForTrap(reason);
  gasm_->TrapUnless(cond, trap_id);
  SetSourcePosition(effect(), position);
}

Node* WasmGraphBuilder::AssertNotNull(Node* object, wasm::ValueType type,
                                      wasm::WasmCodePosition position,
                                      wasm::TrapReason reason) {
  TrapId trap_id = GetTrapIdForTrap(reason);
  Node* result = gasm_->AssertNotNull(object, type, trap_id);
  SetSourcePosition(result, position);
  return result;
}

// Add a check that traps if {node} is equal to {val}.
void WasmGraphBuilder::TrapIfEq32(wasm::TrapReason reason, Node* node,
                                  int32_t val,
                                  wasm::WasmCodePosition position) {
  if (val == 0) {
    TrapIfFalse(reason, node, position);
  } else {
    TrapIfTrue(reason, gasm_->Word32Equal(node, Int32Constant(val)), position);
  }
}

// Add a check that traps if {node} is zero.
void WasmGraphBuilder::ZeroCheck32(wasm::TrapReason reason, Node* node,
                                   wasm::WasmCodePosition position) {
  TrapIfEq32(reason, node, 0, position);
}

// Add a check that traps if {node} is equal to {val}.
void WasmGraphBuilder::TrapIfEq64(wasm::TrapReason reason, Node* node,
                                  int64_t val,
                                  wasm::WasmCodePosition position) {
  TrapIfTrue(reason, gasm_->Word64Equal(node, Int64Constant(val)), position);
}

// Add a check that traps if {node} is zero.
void WasmGraphBuilder::ZeroCheck64(wasm::TrapReason reason, Node* node,
                                   wasm::WasmCodePosition position) {
  TrapIfEq64(reason, node, 0, position);
}

Node* WasmGraphBuilder::Switch(unsigned count, Node* key) {
  // The instruction selector will use {kArchTableSwitch} for large switches,
  // which has limited input count, see {InstructionSelector::EmitTableSwitch}.
  DCHECK_LE(count, Instruction::kMaxInputCount - 2);          // value_range + 2
  DCHECK_LE(count, wasm::kV8MaxWasmFunctionBrTableSize + 1);  // plus IfDefault
  return graph()->NewNode(mcgraph()->common()->Switch(count), key, control());
}

Node* WasmGraphBuilder::IfValue(int32_t value, Node* sw) {
  DCHECK_EQ(IrOpcode::kSwitch, sw->opcode());
  return graph()->NewNode(mcgraph()->common()->IfValue(value), sw);
}

Node* WasmGraphBuilder::IfDefault(Node* sw) {
  DCHECK_EQ(IrOpcode::kSwitch, sw->opcode());
  return graph()->NewNode(mcgraph()->common()->IfDefault(), sw);
}

Node* WasmGraphBuilder::Return(base::Vector<Node*> vals) {
  unsigned count = static_cast<unsigned>(vals.size());
  base::SmallVector<Node*, 8> buf(count + 3);

  // TODOC: What is the meaning of the 0-constant?
  buf[0] = Int32Constant(0);
  if (count > 0) {
    memcpy(buf.data() + 1, vals.begin(), sizeof(void*) * count);
  }
  buf[count + 1] = effect();
  buf[count + 2] = control();
  Node* ret = graph()->NewNode(mcgraph()->common()->Return(count), count + 3,
                               buf.data());

  gasm_->MergeControlToEnd(ret);
  return ret;
}

void WasmGraphBuilder::Trap(wasm::TrapReason reason,
                            wasm::WasmCodePosition position) {
  TrapIfFalse(reason, Int32Constant(0), position);
  // Connect control to end via a Throw() node.
  TerminateThrow(effect(), control());
}

Node* WasmGraphBuilder::MaskShiftCount32(Node* node) {
  static const int32_t kMask32 = 0x1F;
  if (!mcgraph()->machine()->Word32ShiftIsSafe()) {
    // Shifts by constants are so common we pattern-match them here.
    Int32Matcher match(node);
    if (match.HasResolvedValue()) {
      int32_t masked = (match.ResolvedValue() & kMask32);
      if (match.ResolvedValue() != masked) node = Int32Constant(masked);
    } else {
      node = gasm_->Word32And(node, Int32Constant(kMask32));
    }
  }
  return node;
}

Node* WasmGraphBuilder::MaskShiftCount64(Node* node) {
  static const int64_t kMask64 = 0x3F;
  if (!mcgraph()->machine()->Word32ShiftIsSafe()) {
    // Shifts by constants are so common we pattern-match them here.
    Int64Matcher match(node);
    if (match.HasResolvedValue()) {
      int64_t masked = (match.ResolvedValue() & kMask64);
      if (match.ResolvedValue() != masked) node = Int64Constant(masked);
    } else {
      node = gasm_->Word64And(node, Int64Constant(kMask64));
    }
  }
  return node;
}

namespace {

bool ReverseBytesSupported(MachineOperatorBuilder* m, size_t size_in_bytes) {
  switch (size_in_bytes) {
    case 4:
    case 16:
      return true;
    case 8:
      return m->Is64();
    default:
      break;
  }
  return false;
}

}  // namespace

Node* WasmGraphBuilder::BuildChangeEndiannessStore(
    Node* node, MachineRepresentation mem_rep, wasm::ValueType wasmtype) {
  Node* result;
  Node* value = node;
  MachineOperatorBuilder* m = mcgraph()->machine();
  int valueSizeInBytes = wasmtype.value_kind_size();
  int valueSizeInBits = 8 * valueSizeInBytes;
  bool isFloat = false;

  switch (wasmtype.kind()) {
    case wasm::kF64:
      value = gasm_->BitcastFloat64ToInt64(node);
      isFloat = true;
      [[fallthrough]];
    case wasm::kI64:
      result = Int64Constant(0);
      break;
    case wasm::kF32:
      value = gasm_->BitcastFloat32ToInt32(node);
      isFloat = true;
      [[fallthrough]];
    case wasm::kI32:
      result = Int32Constant(0);
      break;
    case wasm::kS128:
      DCHECK(ReverseBytesSupported(m, valueSizeInBytes));
      break;
    default:
      UNREACHABLE();
  }

  if (mem_rep == MachineRepresentation::kWord8) {
    // No need to change endianness for byte size, return original node
    return node;
  }
  if (wasmtype == wasm::kWasmI64 && mem_rep < MachineRepresentation::kWord64) {
    // In case we store lower part of WasmI64 expression, we can truncate
    // upper 32bits
    value = gasm_->TruncateInt64ToInt32(value);
    valueSizeInBytes = wasm::kWasmI32.value_kind_size();
    valueSizeInBits = 8 * valueSizeInBytes;
    if (mem_rep == MachineRepresentation::kWord16) {
      value = gasm_->Word32Shl(value, Int32Constant(16));
    }
  } else if (wasmtype == wasm::kWasmI32 &&
             mem_rep == MachineRepresentation::kWord16) {
    value = gasm_->Word32Shl(value, Int32Constant(16));
  }

  int i;
  uint32_t shiftCount;

  if (ReverseBytesSupported(m, valueSizeInBytes)) {
    switch (valueSizeInBytes) {
      case 4:
        result = gasm_->Word32ReverseBytes(value);
        break;
      case 8:
        result = gasm_->Word64ReverseBytes(value);
        break;
      case 16:
        result = graph()->NewNode(m->Simd128ReverseBytes(), value);
        break;
      default:
        UNREACHABLE();
    }
  } else {
    for (i = 0, shiftCount = valueSizeInBits - 8; i < valueSizeInBits / 2;
         i += 8, shiftCount -= 16) {
      Node* shiftLower;
      Node* shiftHigher;
      Node* lowerByte;
      Node* higherByte;

      DCHECK_LT(0, shiftCount);
      DCHECK_EQ(0, (shiftCount + 8) % 16);

      if (valueSizeInBits > 32) {
        shiftLower = gasm_->Word64Shl(value, Int64Constant(shiftCount));
        shiftHigher = gasm_->Word64Shr(value, Int64Constant(shiftCount));
        lowerByte = gasm_->Word64And(
            shiftLower, Int64Constant(static_cast<uint64_t>(0xFF)
                                      << (valueSizeInBits - 8 - i)));
        higherByte = gasm_->Word64And(
            shiftHigher, Int64Constant(static_cast<uint64_t>(0xFF) << i));
        result = gasm_->Word64Or(result, lowerByte);
        result = gasm_->Word64Or(result, higherByte);
      } else {
        shiftLower = gasm_->Word32Shl(value, Int32Constant(shiftCount));
        shiftHigher = gasm_->Word32Shr(value, Int32Constant(shiftCount));
        lowerByte = gasm_->Word32And(
            shiftLower, Int32Constant(static_cast<uint32_t>(0xFF)
                                      << (valueSizeInBits - 8 - i)));
        higherByte = gasm_->Word32And(
            shiftHigher, Int32Constant(static_cast<uint32_t>(0xFF) << i));
        result = gasm_->Word32Or(result, lowerByte);
        result = gasm_->Word32Or(result, higherByte);
      }
    }
  }

  if (isFloat) {
    switch (wasmtype.kind()) {
      case wasm::kF64:
        result = gasm_->BitcastInt64ToFloat64(result);
        break;
      case wasm::kF32:
        result = gasm_->BitcastInt32ToFloat32(result);
        break;
      default:
        UNREACHABLE();
    }
  }

  return result;
}

Node* WasmGraphBuilder::BuildChangeEndiannessLoad(Node* node,
                                                  MachineType memtype,
                                                  wasm::ValueType wasmtype) {
  Node* result;
  Node* value = node;
  MachineOperatorBuilder* m = mcgraph()->machine();
  int valueSizeInBytes = ElementSizeInBytes(memtype.representation());
  int valueSizeInBits = 8 * valueSizeInBytes;
  bool isFloat = false;

  switch (memtype.representation()) {
    case MachineRepresentation::kFloat64:
      value = gasm_->BitcastFloat64ToInt64(node);
      isFloat = true;
      [[fallthrough]];
    case MachineRepresentation::kWord64:
      result = Int64Constant(0);
      break;
    case MachineRepresentation::kFloat32:
      value = gasm_->BitcastFloat32ToInt32(node);
      isFloat = true;
      [[fallthrough]];
    case MachineRepresentation::kWord32:
    case MachineRepresentation::kWord16:
      result = Int32Constant(0);
      break;
    case MachineRepresentation::kWord8:
      // No need to change endianness for byte size, return original node
      return node;
    case MachineRepresentation::kSimd128:
      DCHECK(ReverseBytesSupported(m, valueSizeInBytes));
      break;
    default:
      UNREACHABLE();
  }

  int i;
  uint32_t shiftCount;

  if (ReverseBytesSupported(m, valueSizeInBytes < 4 ? 4 : valueSizeInBytes)) {
    switch (valueSizeInBytes) {
      case 2:
        result = gasm_->Word32ReverseBytes(
            gasm_->Word32Shl(value, Int32Constant(16)));
        break;
      case 4:
        result = gasm_->Word32ReverseBytes(value);
        break;
      case 8:
        result = gasm_->Word64ReverseBytes(value);
        break;
      case 16:
        result = graph()->NewNode(m->Simd128ReverseBytes(), value);
        break;
      default:
        UNREACHABLE();
    }
  } else {
    for (i = 0, shiftCount = valueSizeInBits - 8; i < valueSizeInBits / 2;
         i += 8, shiftCount -= 16) {
      Node* shiftLower;
      Node* shiftHigher;
      Node* lowerByte;
      Node* higherByte;

      DCHECK_LT(0, shiftCount);
      DCHECK_EQ(0, (shiftCount + 8) % 16);

      if (valueSizeInBits > 32) {
        shiftLower = gasm_->Word64Shl(value, Int64Constant(shiftCount));
        shiftHigher = gasm_->Word64Shr(value, Int64Constant(shiftCount));
        lowerByte = gasm_->Word64And(
            shiftLower, Int64Constant(static_cast<uint64_t>(0xFF)
                                      << (valueSizeInBits - 8 - i)));
        higherByte = gasm_->Word64And(
            shiftHigher, Int64Constant(static_cast<uint64_t>(0xFF) << i));
        result = gasm_->Word64Or(result, lowerByte);
        result = gasm_->Word64Or(result, higherByte);
      } else {
        shiftLower = gasm_->Word32Shl(value, Int32Constant(shiftCount));
        shiftHigher = gasm_->Word32Shr(value, Int32Constant(shiftCount));
        lowerByte = gasm_->Word32And(
            shiftLower, Int32Constant(static_cast<uint32_t>(0xFF)
                                      << (valueSizeInBits - 8 - i)));
        higherByte = gasm_->Word32And(
            shiftHigher, Int32Constant(static_cast<uint32_t>(0xFF) << i));
        result = gasm_->Word32Or(result, lowerByte);
        result = gasm_->Word32Or(result, higherByte);
      }
    }
  }

  if (isFloat) {
    switch (memtype.representation()) {
      case MachineRepresentation::kFloat64:
        result = gasm_->BitcastInt64ToFloat64(result);
        break;
      case MachineRepresentation::kFloat32:
        result = gasm_->BitcastInt32ToFloat32(result);
        break;
      default:
        UNREACHABLE();
    }
  }

  // We need to sign or zero extend the value
  if (memtype.IsSigned()) {
    DCHECK(!isFloat);
    if (valueSizeInBits < 32) {
      Node* shiftBitCount;
      // Perform sign extension using following trick
      // result = (x << machine_width - type_width) >> (machine_width -
      // type_width)
      if (wasmtype == wasm::kWasmI64) {
        shiftBitCount = Int32Constant(64 - valueSizeInBits);
        result = gasm_->Word64Sar(
            gasm_->Word64Shl(gasm_->ChangeInt32ToInt64(result), shiftBitCount),
            shiftBitCount);
      } else if (wasmtype == wasm::kWasmI32) {
        shiftBitCount = Int32Constant(32 - valueSizeInBits);
        result = gasm_->Word32Sar(gasm_->Word32Shl(result, shiftBitCount),
                                  shiftBitCount);
      }
    }
  } else if (wasmtype == wasm::kWasmI64 && valueSizeInBits < 64) {
    result = gasm_->ChangeUint32ToUint64(result);
  }

  return result;
}

Node* WasmGraphBuilder::BuildF32CopySign(Node* left, Node* right) {
  Node* result = Unop(
      wasm::kExprF32ReinterpretI32,
      Binop(wasm::kExprI32Ior,
            Binop(wasm::kExprI32And, Unop(wasm::kExprI32ReinterpretF32, left),
                  Int32Constant(0x7FFFFFFF)),
            Binop(wasm::kExprI32And, Unop(wasm::kExprI32ReinterpretF32, right),
                  Int32Constant(0x80000000))));

  return result;
}

Node* WasmGraphBuilder::BuildF64CopySign(Node* left, Node* right) {
  if (mcgraph()->machine()->Is64()) {
    return gasm_->BitcastInt64ToFloat64(
        gasm_->Word64Or(gasm_->Word64And(gasm_->BitcastFloat64ToInt64(left),
                                         Int64Constant(0x7FFFFFFFFFFFFFFF)),
                        gasm_->Word64And(gasm_->BitcastFloat64ToInt64(right),
                                         Int64Constant(0x8000000000000000))));
  }

  DCHECK(mcgraph()->machine()->Is32());

  Node* high_word_left = gasm_->Float64ExtractHighWord32(left);
  Node* high_word_right = gasm_->Float64ExtractHighWord32(right);

  Node* new_high_word = gasm_->Word32Or(
      gasm_->Word32And(high_word_left, Int32Constant(0x7FFFFFFF)),
      gasm_->Word32And(high_word_right, Int32Constant(0x80000000)));

  return gasm_->Float64InsertHighWord32(left, new_high_word);
}

namespace {

MachineType IntConvertType(wasm::WasmOpcode opcode) {
  switch (opcode) {
    case wasm::kExprI32SConvertF32:
    case wasm::kExprI32SConvertF64:
    case wasm::kExprI32SConvertSatF32:
    case wasm::kExprI32SConvertSatF64:
      return MachineType::Int32();
    case wasm::kExprI32UConvertF32:
    case wasm::kExprI32UConvertF64:
    case wasm::kExprI32UConvertSatF32:
    case wasm::kExprI32UConvertSatF64:
      return MachineType::Uint32();
    case wasm::kExprI64SConvertF32:
    case wasm::kExprI64SConvertF64:
    case wasm::kExprI64SConvertSatF32:
    case wasm::kExprI64SConvertSatF64:
      return MachineType::Int64();
    case wasm::kExprI64UConvertF32:
    case wasm::kExprI64UConvertF64:
    case wasm::kExprI64UConvertSatF32:
    case wasm::kExprI64UConvertSatF64:
      return MachineType::Uint64();
    default:
      UNREACHABLE();
  }
}

MachineType FloatConvertType(wasm::WasmOpcode opcode) {
  switch (opcode) {
    case wasm::kExprI32SConvertF32:
    case wasm::kExprI32UConvertF32:
    case wasm::kExprI32SConvertSatF32:
    case wasm::kExprI64SConvertF32:
    case wasm::kExprI64UConvertF32:
    case wasm::kExprI32UConvertSatF32:
    case wasm::kExprI64SConvertSatF32:
    case wasm::kExprI64UConvertSatF32:
      return MachineType::Float32();
    case wasm::kExprI32SConvertF64:
    case wasm::kExprI32UConvertF64:
    case wasm::kExprI64SConvertF64:
    case wasm::kExprI64UConvertF64:
    case wasm::kExprI32SConvertSatF64:
    case wasm::kExprI32UConvertSatF64:
    case wasm::kExprI64SConvertSatF64:
    case wasm::kExprI64UConvertSatF64:
      return MachineType::Float64();
    default:
      UNREACHABLE();
  }
}

const Operator* ConvertOp(WasmGraphBuilder* builder, wasm::WasmOpcode opcode) {
  switch (opcode) {
    case wasm::kExprI32SConvertF32:
      return builder->mcgraph()->machine()->TruncateFloat32ToInt32(
          TruncateKind::kSetOverflowToMin);
    case wasm::kExprI32SConvertSatF32:
      return builder->mcgraph()->machine()->TruncateFloat32ToInt32(
          TruncateKind::kArchitectureDefault);
    case wasm::kExprI32UConvertF32:
      return builder->mcgraph()->machine()->TruncateFloat32ToUint32(
          TruncateKind::kSetOverflowToMin);
    case wasm::kExprI32UConvertSatF32:
      return builder->mcgraph()->machine()->TruncateFloat32ToUint32(
          TruncateKind::kArchitectureDefault);
    case wasm::kExprI32SConvertF64:
    case wasm::kExprI32SConvertSatF64:
      return builder->mcgraph()->machine()->ChangeFloat64ToInt32();
    case wasm::kExprI32UConvertF64:
    case wasm::kExprI32UConvertSatF64:
      return builder->mcgraph()->machine()->TruncateFloat64ToUint32();
    case wasm::kExprI64SConvertF32:
    case wasm::kExprI64SConvertSatF32:
      return builder->mcgraph()->machine()->TryTruncateFloat32ToInt64();
    case wasm::kExprI64UConvertF32:
    case wasm::kExprI64UConvertSatF32:
      return builder->mcgraph()->machine()->TryTruncateFloat32ToUint64();
    case wasm::kExprI64SConvertF64:
    case wasm::kExprI64SConvertSatF64:
      return builder->mcgraph()->machine()->TryTruncateFloat64ToInt64();
    case wasm::kExprI64UConvertF64:
    case wasm::kExprI64UConvertSatF64:
      return builder->mcgraph()->machine()->TryTruncateFloat64ToUint64();
    default:
      UNREACHABLE();
  }
}

wasm::WasmOpcode ConvertBackOp(wasm::WasmOpcode opcode) {
  switch (opcode) {
    case wasm::kExprI32SConvertF32:
    case wasm::kExprI32SConvertSatF32:
      return wasm::kExprF32SConvertI32;
    case wasm::kExprI32UConvertF32:
    case wasm::kExprI32UConvertSatF32:
      return wasm::kExprF32UConvertI32;
    case wasm::kExprI32SConvertF64:
    case wasm::kExprI32SConvertSatF64:
      return wasm::kExprF64SConvertI32;
    case wasm::kExprI32UConvertF64:
    case wasm::kExprI32UConvertSatF64:
      return wasm::kExprF64UConvertI32;
    default:
      UNREACHABLE();
  }
}

bool IsTrappingConvertOp(wasm::WasmOpcode opcode) {
  switch (opcode) {
    case wasm::kExprI32SConvertF32:
    case wasm::kExprI32UConvertF32:
    case wasm::kExprI32SConvertF64:
    case wasm::kExprI32UConvertF64:
    case wasm::kExprI64SConvertF32:
    case wasm::kExprI64UConvertF32:
    case wasm::kExprI64SConvertF64:
    case wasm::kExprI64UConvertF64:
      return true;
    case wasm::kExprI32SConvertSatF64:
    case wasm::kExprI32UConvertSatF64:
    case wasm::kExprI32SConvertSatF32:
    case wasm::kExprI32UConvertSatF32:
    case wasm::kExprI64SConvertSatF32:
    case wasm::kExprI64UConvertSatF32:
    case wasm::kExprI64SConvertSatF64:
    case wasm::kExprI64UConvertSatF64:
      return false;
    default:
      UNREACHABLE();
  }
}

Node* Zero(WasmGraphBuilder* builder, const MachineType& ty) {
  switch (ty.representation()) {
    case MachineRepresentation::kWord32:
      return builder->Int32Constant(0);
    case MachineRepresentation::kWord64:
      return builder->Int64Constant(0);
    case MachineRepresentation::kFloat32:
      return builder->Float32Constant(0.0);
    case MachineRepresentation::kFloat64:
      return builder->Float64Constant(0.0);
    default:
      UNREACHABLE();
  }
}

Node* Min(WasmGraphBuilder* builder, const MachineType& ty) {
  switch (ty.semantic()) {
    case MachineSemantic::kInt32:
      return builder->Int32Constant(std::numeric_limits<int32_t>::min());
    case MachineSemantic::kUint32:
      return builder->Int32Constant(std::numeric_limits<uint32_t>::min());
    case MachineSemantic::kInt64:
      return builder->Int64Constant(std::numeric_limits<int64_t>::min());
    case MachineSemantic::kUint64:
      return builder->Int64Constant(std::numeric_limits<uint64_t>::min());
    default:
      UNREACHABLE();
  }
}

Node* Max(WasmGraphBuilder* builder, const MachineType& ty) {
  switch (ty.semantic()) {
    case MachineSemantic::kInt32:
      return builder->Int32Constant(std::numeric_limits<int32_t>::max());
    case MachineSemantic::kUint32:
      return builder->Int32Constant(std::numeric_limits<uint32_t>::max());
    case MachineSemantic::kInt64:
      return builder->Int64Constant(std::numeric_limits<int64_t>::max());
    case MachineSemantic::kUint64:
      return builder->Int64Constant(std::numeric_limits<uint64_t>::max());
    default:
      UNREACHABLE();
  }
}

wasm::WasmOpcode TruncOp(const MachineType& ty) {
  switch (ty.representation()) {
    case MachineRepresentation::kFloat32:
      return wasm::kExprF32Trunc;
    case MachineRepresentation::kFloat64:
      return wasm::kExprF64Trunc;
    default:
      UNREACHABLE();
  }
}

wasm::WasmOpcode NeOp(const MachineType& ty) {
  switch (ty.representation()) {
    case MachineRepresentation::kFloat32:
      return wasm::kExprF32Ne;
    case MachineRepresentation::kFloat64:
      return wasm::kExprF6
"""


```