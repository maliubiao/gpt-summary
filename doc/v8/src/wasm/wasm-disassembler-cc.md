Response:
My thinking process to arrive at the summary of `v8/src/wasm/wasm-disassembler.cc`'s functionality goes like this:

1. **Identify the core purpose:** The file name "wasm-disassembler.cc" immediately suggests its primary function is to take WebAssembly code and convert it into a human-readable format. The presence of "disassemble" in function names like `Disassemble` and `DisassembleFunction` reinforces this.

2. **Analyze the main `Disassemble` functions:** There are two `Disassemble` functions. The first takes a `WasmModule` and wire bytes, implying it works with already decoded WebAssembly modules. The second takes only wire bytes, indicating it handles the decoding process itself. This tells me the disassembler can operate on both pre-processed and raw WASM bytecode.

3. **Look for output mechanisms:** The `v8::debug::DisassemblyCollector* collector` parameter in both `Disassemble` functions clearly points to how the disassembled output is collected. The `MultiLineStringBuilder` class seems to be an internal helper for building this output. The `ToDisassemblyCollector` method confirms this.

4. **Examine function-level disassembly:** The `DisassembleFunction` functions and `DisassembleFunctionImpl` are dedicated to disassembling individual WebAssembly functions. This indicates the tool can dissect the module at a granular level. The `std::ostream& os` parameter suggests another output mechanism, likely for direct printing.

5. **Understand the role of `NamesProvider`:**  The `NamesProvider` class is used extensively for printing names of functions, locals, globals, etc. This signifies that the disassembler aims to provide symbolic information, making the output more understandable than raw bytecode.

6. **Investigate `FunctionBodyDisassembler`:** This class appears central to the process of disassembling the instructions within a function. The `DecodeAsWat` method name strongly suggests it generates the WebAssembly Text Format (WAT).

7. **Trace the flow of disassembly within `DecodeAsWat`:**  The code iterates through opcodes, prints the opcode name, and then prints "immediates." This is the standard structure of disassembled code. The handling of indentation and labels (using `label_stack_`) reveals the disassembler's ability to represent control flow structures.

8. **Consider the "immediates":** The `ImmediatesPrinter` template is responsible for formatting the operands of each opcode. The various `Print...` methods within this class show how different immediate types (constants, indices, memory access info, etc.) are represented in the disassembled output.

9. **Recognize the need for metadata:** The `OffsetsProvider` class is used to collect offsets of various sections within the WASM module. This metadata is essential for accurate disassembly, especially when dealing with labels and references.

10. **Synthesize the functionality of `ModuleDisassembler`:** This class orchestrates the overall module disassembly process. It uses the `FunctionBodyDisassembler` to handle individual functions and iterates through the module's structure (types, imports, tables, etc.) to generate the complete disassembled output.

11. **Address the ".tq" question:** The code explicitly checks if the filename ends with ".tq" to determine if it's a Torque file. Since it doesn't, I can conclude it's a regular C++ source file.

12. **Consider JavaScript relationships:** The disassembler is a developer tool, so its relation to JavaScript is indirect. It helps developers understand how JavaScript code compiles down to WebAssembly, which can be useful for debugging and optimization. A simple JavaScript example demonstrating the interaction with WebAssembly is appropriate here.

13. **Look for code logic/inference:**  The `GetDefaultAlignment` function provides a clear example of logic. By examining the input (opcode) and the `switch` statement, I can deduce the output (default memory alignment). Providing specific input/output examples clarifies this.

14. **Identify potential user errors:**  A common mistake is incorrect memory access, such as out-of-bounds access or misaligned access. Relating this back to the disassembler's output (showing `offset` and `align`) helps illustrate how the tool can aid in identifying these issues.

15. **Organize the information into a structured summary:** Finally, I organize the findings into a clear and concise summary covering the key functionalities, addressing the specific questions raised in the prompt. I focus on the "what" and "why" of the code, explaining its purpose and how it achieves it.
```cpp
// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/wasm/wasm-disassembler.h"

#include <iomanip>

#include "src/debug/debug-interface.h"
#include "src/numbers/conversions.h"
#include "src/wasm/module-decoder-impl.h"
#include "src/wasm/names-provider.h"
#include "src/wasm/wasm-disassembler-impl.h"
#include "src/wasm/wasm-opcodes-inl.h"

namespace v8 {
namespace internal {
namespace wasm {

////////////////////////////////////////////////////////////////////////////////
// Public interface.

void Disassemble(const WasmModule* module, ModuleWireBytes wire_bytes,
                 NamesProvider* names,
                 v8::debug::DisassemblyCollector* collector,
                 std::vector<int>* function_body_offsets) {
  MultiLineStringBuilder out;
  AccountingAllocator allocator;
  ModuleDisassembler md(out, module, names, wire_bytes, &allocator,
                        /* no offsets yet */ {}, function_body_offsets);
  md.PrintModule({0, 2}, v8_flags.wasm_disassembly_max_mb);
  out.ToDisassemblyCollector(collector);
}

void Disassemble(base::Vector<const uint8_t> wire_bytes,
                 v8::debug::DisassemblyCollector* collector,
                 std::vector<int>* function_body_offsets) {
  std::unique_ptr<OffsetsProvider> offsets = AllocateOffsetsProvider();
  ModuleResult result =
      DecodeWasmModuleForDisassembler(wire_bytes, offsets.get());
  MultiLineStringBuilder out;
  AccountingAllocator allocator;
  if (result.failed()) {
    WasmError error = result.error();
    out << "Decoding error: " << error.message() << " at offset "
        << error.offset();
    out.ToDisassemblyCollector(collector);
    return;
  }
  const WasmModule* module = result.value().get();
  NamesProvider names(module, wire_bytes);
  ModuleWireBytes module_bytes(wire_bytes);
  ModuleDisassembler md(out, module, &names, module_bytes, &allocator,
                        std::move(offsets), function_body_offsets);
  md.PrintModule({0, 2}, v8_flags.wasm_disassembly_max_mb);
  out.ToDisassemblyCollector(collector);
}

void MultiLineStringBuilder::ToDisassemblyCollector(
    v8::debug::DisassemblyCollector* collector) {
  if (length() != 0) NextLine(0);  // Finalize last line.
  collector->ReserveLineCount(lines_.size());
  for (const Line& l : lines_) {
    // Don't include trailing '\n'.
    collector->AddLine(l.data, l.len - 1, l.bytecode_offset);
  }
}

void DisassembleFunctionImpl(const WasmModule* module, int func_index,
                             base::Vector<const uint8_t> function_body,
                             ModuleWireBytes module_bytes, NamesProvider* names,
                             std::ostream& os, std::vector<uint32_t>* offsets) {
  MultiLineStringBuilder sb;
  const wasm::WasmFunction& func = module->functions[func_index];
  AccountingAllocator allocator;
  Zone zone(&allocator, "Wasm disassembler");
  bool shared = module->type(func.sig_index).is_shared;
  WasmDetectedFeatures detected;
  FunctionBodyDisassembler d(&zone, module, func_index, shared, &detected,
                             func.sig, function_body.begin(),
                             function_body.end(), func.code.offset(),
                             module_bytes, names);
  d.DecodeAsWat(sb, {0, 2}, FunctionBodyDisassembler::kPrintHeader);
  const bool print_offsets = false;
  sb.WriteTo(os, print_offsets, offsets);
}

void DisassembleFunction(const WasmModule* module, int func_index,
                         base::Vector<const uint8_t> wire_bytes,
                         NamesProvider* names, std::ostream& os) {
  DCHECK(func_index < static_cast<int>(module->functions.size()) &&
         func_index >= static_cast<int>(module->num_imported_functions));
  ModuleWireBytes module_bytes(wire_bytes);
  base::Vector<const uint8_t> code =
      module_bytes.GetFunctionBytes(&module->functions[func_index]);
  std::vector<uint32_t>* collect_offsets = nullptr;
  DisassembleFunctionImpl(module, func_index, code, module_bytes, names, os,
                          collect_offsets);
}

void DisassembleFunction(const WasmModule* module, int func_index,
                         base::Vector<const uint8_t> function_body,
                         base::Vector<const uint8_t> maybe_wire_bytes,
                         uint32_t function_body_offset, std::ostream& os,
                         std::vector<uint32_t>* offsets) {
  DCHECK(func_index < static_cast<int>(module->functions.size()) &&
         func_index >= static_cast<int>(module->num_imported_functions));
  NamesProvider fake_names(module, maybe_wire_bytes);
  DisassembleFunctionImpl(module, func_index, function_body,
                          ModuleWireBytes{nullptr, 0}, &fake_names, os,
                          offsets);
}

////////////////////////////////////////////////////////////////////////////////
// Helpers.

static constexpr char kHexChars[] = "0123456789abcdef";
static constexpr char kUpperHexChars[] = "0123456789ABCDEF";

// Returns the log2 of the alignment, e.g. "4" means 2<<4 == 16 bytes.
// This is the same format as used in .wasm binary modules.
uint32_t GetDefaultAlignment(WasmOpcode opcode) {
  switch (opcode) {
    case kExprS128LoadMem:
    case kExprS128StoreMem:
      return 4;
    case kExprS128Load8x8S:
    case kExprS128Load8x8U:
    case kExprS128Load16x4S:
    case kExprS128Load16x4U:
    case kExprS128Load32x2S:
    case kExprS128Load32x2U:
    case kExprS128Load64Splat:
    case kExprS128Load64Zero:
    case kExprS128Load64Lane:
    case kExprS128Store64Lane:
      return 3;
    case kExprS128Load32Splat:
    case kExprS128Load32Zero:
    case kExprS128Load32Lane:
    case kExprS128Store32Lane:
      return 2;
    case kExprS128Load16Splat:
    case kExprS128Load16Lane:
    case kExprS128Store16Lane:
      return 1;
    case kExprS128Load8Splat:
    case kExprS128Load8Lane:
    case kExprS128Store8Lane:
      return 0;

#define CASE(Opcode, ...) \
  case kExpr##Opcode:     \
    return GetLoadType(kExpr##Opcode).size_log_2();
      FOREACH_LOAD_MEM_OPCODE(CASE)
#undef CASE
#define CASE(Opcode, ...) \
  case kExpr##Opcode:     \
    return GetStoreType(kExpr##Opcode).size_log_2();
      FOREACH_STORE_MEM_OPCODE(CASE)
#undef CASE

#define CASE(Opcode, Type) \
  case kExpr##Opcode:      \
    return ElementSizeLog2Of(MachineType::Type().representation());
      ATOMIC_OP_LIST(CASE)
      ATOMIC_STORE_OP_LIST(CASE)
#undef CASE

    default:
      UNREACHABLE();
  }
}

void PrintSignatureOneLine(StringBuilder& out, const FunctionSig* sig,
                           uint32_t func_index, NamesProvider* names,
                           bool param_names,
                           IndexAsComment indices_as_comments) {
  if (param_names) {
    for (uint32_t i = 0; i < sig->parameter_count(); i++) {
      out << " (param ";
      names->PrintLocalName(out, func_index, i, indices_as_comments);
      out << ' ';
      names->PrintValueType(out, sig->GetParam(i));
      out << ")";
    }
  } else if (sig->parameter_count() > 0) {
    out << " (param";
    for (uint32_t i = 0; i < sig->parameter_count(); i++) {
      out << " ";
      names->PrintValueType(out, sig->GetParam(i));
    }
    out << ")";
  }
  for (size_t i = 0; i < sig->return_count(); i++) {
    out << " (result ";
    names->PrintValueType(out, sig->GetReturn(i));
    out << ")";
  }
}

void PrintStringRaw(StringBuilder& out, const uint8_t* start,
                    const uint8_t* end) {
  for (const uint8_t* ptr = start; ptr < end; ptr++) {
    uint8_t b = *ptr;
    if (b < 32 || b >= 127 || b == '"' || b == '\\') {
      out << '\\' << kHexChars[b >> 4] << kHexChars[b & 0xF];
    } else {
      out << static_cast<char>(b);
    }
  }
}

////////////////////////////////////////////////////////////////////////////////
// FunctionBodyDisassembler.

void FunctionBodyDisassembler::DecodeAsWat(MultiLineStringBuilder& out,
                                           Indentation indentation,
                                           FunctionHeader include_header,
                                           uint32_t* first_instruction_offset) {
  out_ = &out;
  int base_indentation = indentation.current();
  // Print header.
  if (include_header == kPrintHeader) {
    out << indentation << "(func ";
    names_->PrintFunctionName(out, func_index_, NamesProvider::kDevTools);
    PrintSignatureOneLine(out, sig_, func_index_, names_, true,
                          kIndicesAsComments);
    out.NextLine(pc_offset());
  } else {
    out.set_current_line_bytecode_offset(pc_offset());
  }
  indentation.increase();

  // Decode and print locals.
  uint32_t locals_length = DecodeLocals(pc_);
  if (failed()) {
    // TODO(jkummerow): Improve error handling.
    out << "Failed to decode locals\n";
    return;
  }
  for (uint32_t i = static_cast<uint32_t>(sig_->parameter_count());
       i < num_locals_; i++) {
    out << indentation << "(local ";
    names_->PrintLocalName(out, func_index_, i);
    out << " ";
    names_->PrintValueType(out, local_type(i));
    out << ")";
    out.NextLine(pc_offset());
  }
  consume_bytes(locals_length);
  out.set_current_line_bytecode_offset(pc_offset());
  if (first_instruction_offset) *first_instruction_offset = pc_offset();

  // Main loop.
  while (pc_ < end_ && ok()) {
    WasmOpcode opcode = GetOpcode();
    current_opcode_ = opcode;  // Some immediates need to know this.

    // Deal with indentation.
    if (opcode == kExprEnd || opcode == kExprElse || opcode == kExprCatch ||
        opcode == kExprCatchAll || opcode == kExprDelegate) {
      if (indentation.current() >= base_indentation) {
        indentation.decrease();
      }
    }
    out << indentation;
    if (opcode == kExprElse || opcode == kExprCatch ||
        opcode == kExprCatchAll || opcode == kExprBlock || opcode == kExprIf ||
        opcode == kExprLoop || opcode == kExprTry || opcode == kExprTryTable) {
      indentation.increase();
    }

    // Print the opcode and its immediates.
    if (opcode == kExprEnd) {
      if (indentation.current() < base_indentation) {
        out << ";; Unexpected end byte";
      } else if (indentation.current() == base_indentation) {
        out << ")";  // End of the function.
      } else {
        out << "end";
        const LabelInfo& label = label_stack_.back();
        if (label.start != nullptr) {
          out << " ";
          out.write(label.start, label.length);
        }
        label_stack_.pop_back();
      }
    } else {
      out << WasmOpcodes::OpcodeName(opcode);
    }
    if (opcode == kExprBlock || opcode == kExprIf || opcode == kExprLoop ||
        opcode == kExprTry || opcode == kExprTryTable) {
      // Create the LabelInfo now to get the correct offset, but only push it
      // after printing the immediates because the immediates don't see the new
      // label yet.
      LabelInfo label(out.line_number(), out.length(),
                      label_occurrence_index_++);
      pc_ += PrintImmediatesAndGetLength(out);
      label_stack_.push_back(label);
    } else {
      pc_ += PrintImmediatesAndGetLength(out);
    }

    out.NextLine(pc_offset());
  }

  if (pc_ != end_) {
    // TODO(jkummerow): Improve error handling.
    out << "Beyond end of code";
  }
}

void FunctionBodyDisassembler::DecodeGlobalInitializer(StringBuilder& out) {
  while (pc_ < end_) {
    WasmOpcode opcode = GetOpcode();
    current_opcode_ = opcode;  // Some immediates need to know this.
    // Don't print the final "end".
    if (opcode == kExprEnd && pc_ + 1 == end_) break;
    uint32_t length;
    out << " (" << WasmOpcodes::OpcodeName(opcode);
    length = PrintImmediatesAndGetLength(out);
    out << ")";
    pc_ += length;
  }
}

WasmOpcode FunctionBodyDisassembler::GetOpcode() {
  WasmOpcode opcode = static_cast<WasmOpcode>(*pc_);
  if (!WasmOpcodes::IsPrefixOpcode(opcode)) return opcode;
  return read_prefixed_opcode<ValidationTag>(pc_).first;
}

void FunctionBodyDisassembler::PrintHexNumber(StringBuilder& out,
                                              uint64_t number) {
  constexpr size_t kBufferSize = sizeof(number) * 2 + 2;  // +2 for "0x".
  char buffer[kBufferSize];
  char* end = buffer + kBufferSize;
  char* ptr = end;
  do {
    *(--ptr) = kHexChars[number & 0xF];
    number >>= 4;
  } while (number > 0);
  *(--ptr) = 'x';
  *(--ptr) = '0';
  size_t length = static_cast<size_t>(end - ptr);
  char* output = out.allocate(length);
  memcpy(output, ptr, length);
}

////////////////////////////////////////////////////////////////////////////////
// ImmediatesPrinter.

template <typename ValidationTag>
class ImmediatesPrinter {
 public:
  ImmediatesPrinter(StringBuilder& out, FunctionBodyDisassembler* owner)
      : out_(out), owner_(owner) {}

  void PrintDepthAsLabel(int imm_depth) {
    out_ << " ";
    size_t label_start_position = out_.length();
    int depth = imm_depth;
    if (owner_->current_opcode_ == kExprDelegate) depth++;
    // Be robust: if the module is invalid, print what we got.
    if (depth < 0 || depth >= static_cast<int>(owner_->label_stack_.size())) {
      out_ << imm_depth;
      return;
    }
    // If the label's name has already been determined and backpatched, just
    // copy it here.
    LabelInfo& label_info = owner_->label_info(depth);
    if (label_info.start != nullptr) {
      out_.write(label_info.start, label_info.length);
      return;
    }
    // Determine the label's name and backpatch the line that opened the block.
    names()->PrintLabelName(out_, owner_->func_index_,
                            label_info.name_section_index,
                            owner_->label_generation_index_++);
    label_info.length = out_.length() - label_start_position;
    owner_->out_->PatchLabel(label_info, out_.start() + label_start_position);
  }

  void PrintSignature(ModuleTypeIndex sig_index) {
    if (owner_->module_->has_signature(sig_index)) {
      const FunctionSig* sig = owner_->module_->signature(sig_index);
      PrintSignatureOneLine(out_, sig, 0 /* ignored */, names(), false);
    } else {
      out_ << " (signature: " << sig_index << " INVALID)";
    }
  }

  void BlockType(BlockTypeImmediate& imm) {
    if (imm.sig.all().begin() == nullptr) {
      PrintSignature(imm.sig_index);
    } else {
      PrintSignatureOneLine(out_, &imm.sig, 0 /* ignored */, names(), false);
    }
  }

  void HeapType(HeapTypeImmediate& imm) {
    out_ << " ";
    names()->PrintHeapType(out_, imm.type);
    if (imm.type.is_index()) use_type(imm.type.ref_index());
  }

  void ValueType(HeapTypeImmediate& imm, bool is_nullable) {
    out_ << " ";
    names()->PrintValueType(
        out_, ValueType::RefMaybeNull(imm.type,
                                      is_nullable ? kNullable : kNonNullable));
    if (imm.type.is_index()) use_type(imm.type.ref_index());
  }

  void BrOnCastFlags(BrOnCastImmediate& flags) {
    // Ignored here. For printing text format, we do all the work via the
    // two calls to {ValueType()} that we get for a br_on_cast.
  }

  void BranchDepth(BranchDepthImmediate& imm) { PrintDepthAsLabel(imm.depth); }

  void BranchTable(BranchTableImmediate& imm) {
    const uint8_t* pc = imm.table;
    for (uint32_t i = 0; i <= imm.table_count; i++) {
      auto [target, length] = owner_->read_u32v<ValidationTag>(pc);
      PrintDepthAsLabel(target);
      pc += length;
    }
  }

  const char* CatchKindToString(CatchKind kind) {
    switch (kind) {
      case kCatch:
        return "catch";
      case kCatchRef:
        return "catch_ref";
      case kCatchAll:
        return "catch_all";
      case kCatchAllRef:
        return "catch_all_ref";
      default:
        return "<invalid>";
    }
  }

  void TryTable(TryTableImmediate& imm) {
    const uint8_t* pc = imm.table;
    for (uint32_t i = 0; i < imm.table_count; i++) {
      uint8_t kind = owner_->read_u8<ValidationTag>(pc);
      pc += 1;
      out_ << " " << CatchKindToString(static_cast<CatchKind>(kind));
      if (kind == kCatch || kind == kCatchRef) {
        auto [tag, length] = owner_->read_u32v<ValidationTag>(pc);
        out_ << " ";
        names()->PrintTagName(out_, tag);
        pc += length;
      }
      auto [target, length] = owner_->read_u32v<ValidationTag>(pc);
      PrintDepthAsLabel(target);
      pc += length;
    }
  }

  void CallIndirect(CallIndirectImmediate& imm) {
    PrintSignature(imm.sig_imm.index);
    if (imm.table_imm.index != 0) TableIndex(imm.table_imm);
  }

  void SelectType(SelectTypeImmediate& imm) {
    out_ << " ";
    names()->PrintValueType(out_, imm.type);
  }

  void MemoryAccess(MemoryAccessImmediate& imm) {
    if (imm.offset != 0) out_ << " offset=" << imm.offset;
    if (imm.alignment != GetDefaultAlignment(owner_->current_opcode_)) {
      out_ << " align=" << (1u << imm.alignment);
    }
  }

  void SimdLane(SimdLaneImmediate& imm) { out_ << " " << uint32_t{imm.lane}; }

  void Field(FieldImmediate& imm) {
    TypeIndex(imm.struct_imm);
    out_ << " ";
    names()->PrintFieldName(out_, imm.struct_imm.index.index,
                            imm.field_imm.index);
  }

  void Length(IndexImmediate& imm) {
    out_ << " " << imm.index;  // --
  }

  void TagIndex(TagIndexImmediate& imm) {
    out_ << " ";
    names()->PrintTagName(out_, imm.index);
  }

  void FunctionIndex(IndexImmediate& imm) {
    out_ << " ";
    names()->PrintFunctionName(out_, imm.index, NamesProvider::kDevTools);
  }

  void TypeIndex(TypeIndexImmediate& imm) {
    out_ << " ";
    names()->PrintTypeName(out_, imm.index);
    use_type(imm.index);
  }

  void LocalIndex(IndexImmediate& imm) {
    out_ << " ";
    names()->PrintLocalName(out_, func_index(), imm.index);
  }

  void GlobalIndex(IndexImmediate& imm) {
    out_ << " ";
    names()->PrintGlobalName(out_, imm.index);
  }

  void TableIndex(TableIndexImmediate& imm) {
    out_ << " ";
    names()->PrintTableName(out_, imm.index);
  }

  void MemoryIndex(MemoryIndexImmediate& imm) {
    if (imm.index == 0) return;
    out_ << " " << imm.index;
  }

  void DataSegmentIndex(IndexImmediate& imm) {
    if (kSkipDataSegmentNames) {
      out_ << " " << imm.index;
    } else {
      out_ << " ";
      names()->PrintDataSegmentName(out_, imm.index);
    }
  }

  void ElemSegmentIndex(IndexImmediate& imm) {
    out_ << " ";
    names()->PrintElementSegmentName(out_, imm.index);
  }

  void I32Const(ImmI32Immediate& imm) {
    out_ << " " << imm.value;  // --
  }

  void I64Const(ImmI64Immediate& imm) {
    if (imm.value >= 0) {
      out_ << " " << static_cast<uint64_t>(imm.value);
    } else {
      out_ << " -" << ((~static_cast<uint64_t>(imm.value)) + 1);
    }
  }

  void F32Const(ImmF32Immediate& imm) {
    float f = imm.value;
    if (f == 0) {
      out_ << (1 / f < 0 ? " -0.0" : " 0.0");
    } else if (std::isinf(f)) {
      out_ << (f > 0 ? " inf" : " -inf");
    } else if (std::isnan(f)) {
      uint32_t bits = base::bit_cast<uint32_t>(f);
      uint32_t payload = bits & 0x7F'FFFFu;
      uint32_t signbit = bits >> 31;
      if (payload == 0x40'0000u) {
        out_ << (signbit == 1 ? " -nan" : " nan");
      } else {
        out_ << (signbit == 1 ? " -nan:" : " +nan:");
        owner_->PrintHexNumber(out_, payload);
      }
    } else {
      std::ostringstream o;
      // TODO(dlehmann): Change to `std::format` (C++20) or to `std::to_chars`
      // (C++17) once available, so that `0.1` isn't printed as `0.100000001`
      // any more.
      o << std::setprecision(std::numeric_limits<float>::max_digits10) << f;
      out_ << " " << o.str();
    }
  }

  void F64Const(ImmF64Immediate& imm) {
    double d = imm.value;
    if (d == 0) {
      out_ << (1 / d < 0 ? " -0.0" : " 0.0");
    } else if (std::isinf(d)) {
      out_ << (d > 0 ? " inf" : " -inf");
    } else if (std::isnan(d)) {
      uint64_t bits = base::bit_cast<uint64_t>(d);
      uint64_t payload = bits & 0xF'FFFF'FFFF'FFFFull;
      uint64_t signbit = bits >> 63;
      if (payload == 0x8'0000'0000'0000ull) {
        out_ << (signbit == 1 ? " -nan" : " nan");
      } else {
        out_ << (signbit == 1 ? " -nan:" : " +nan:");
        owner_->PrintHexNumber(out_, payload);
      }
    } else {
      char buffer[100];
      const char* str = DoubleToCString(d, base::VectorOf(buffer, 100u));
      out_ << " " << str;
    }
  }

  void S128Const(Simd128Immediate& imm) {
    if (owner_->current_opcode_ == kExprI8x16Shuffle) {
      for (int i = 0; i < 16; i++) {
        out_ << " " << uint32_t{imm.value[i]};
      }
    } else {
      DCHECK_EQ(owner_->current_opcode_, kExprS128Const);
      out_ << " i32x4";
      for (int i = 0; i < 4; i++) {
        out_ << " 0x";
        for (int j = 3; j >= 0; j--) {  // Little endian.
          uint8_t b = imm.value[i * 4 + j];
          out_ << kUpperHexChars[b >> 4];
          out_ << kUpperHexChars[b & 0xF];
        }
      }
    }
  }

  void StringConst(StringConstImmediate& imm) {
    if (imm.index >= owner_->module_->stringref_literals.size()) {
      out_ << " " << imm.index << " INVALID";
      return;
    }
    if (owner_->wire_bytes_.start() == nullptr) {
      out_ << " " << imm.index;
      return;
    }
    out_ << " \"";
    const WasmStringRefLiteral& lit =
        owner_->module_->stringref_literals[imm.index];
    const uint8_t* start = owner_->wire_bytes_.start() + lit.source.offset();
    static constexpr uint32_t kMaxCharsPrinted = 40;
    if (lit.source.length() <= kMaxCharsPrinted) {
      const uint8_t* end =
          owner_->wire_bytes_.start() + lit.source.end_offset();
      PrintStringRaw(out_, start, end);
    } else {
      const uint8_t* end = start + kMaxCharsPrinted - 1;
      PrintStringRaw(out_, start, end);
      out_ << "…";
    }
    out_ << '"';
    if (kIndicesAsComments) out_ << " (;" << imm.index << ";)";
  }

  void MemoryInit(MemoryInitImmediate& imm) {
    DataSegmentIndex(imm.data_segment);
    if (imm.memory.index != 0) out_ << " " << uint32_t{imm.memory.index};
  }

  void MemoryCopy(MemoryCopyImmediate& imm) {
    if (imm.memory_dst.index == 0 && imm.memory_src.index == 0) return;
    out_ << " " << uint32_t{imm.memory_dst.index};
    out_ << " " << uint32_t{imm.memory_src.index};
  }

  void TableInit(
Prompt: 
```
这是目录为v8/src/wasm/wasm-disassembler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/wasm-disassembler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/wasm/wasm-disassembler.h"

#include <iomanip>

#include "src/debug/debug-interface.h"
#include "src/numbers/conversions.h"
#include "src/wasm/module-decoder-impl.h"
#include "src/wasm/names-provider.h"
#include "src/wasm/wasm-disassembler-impl.h"
#include "src/wasm/wasm-opcodes-inl.h"

namespace v8 {
namespace internal {
namespace wasm {

////////////////////////////////////////////////////////////////////////////////
// Public interface.

void Disassemble(const WasmModule* module, ModuleWireBytes wire_bytes,
                 NamesProvider* names,
                 v8::debug::DisassemblyCollector* collector,
                 std::vector<int>* function_body_offsets) {
  MultiLineStringBuilder out;
  AccountingAllocator allocator;
  ModuleDisassembler md(out, module, names, wire_bytes, &allocator,
                        /* no offsets yet */ {}, function_body_offsets);
  md.PrintModule({0, 2}, v8_flags.wasm_disassembly_max_mb);
  out.ToDisassemblyCollector(collector);
}

void Disassemble(base::Vector<const uint8_t> wire_bytes,
                 v8::debug::DisassemblyCollector* collector,
                 std::vector<int>* function_body_offsets) {
  std::unique_ptr<OffsetsProvider> offsets = AllocateOffsetsProvider();
  ModuleResult result =
      DecodeWasmModuleForDisassembler(wire_bytes, offsets.get());
  MultiLineStringBuilder out;
  AccountingAllocator allocator;
  if (result.failed()) {
    WasmError error = result.error();
    out << "Decoding error: " << error.message() << " at offset "
        << error.offset();
    out.ToDisassemblyCollector(collector);
    return;
  }
  const WasmModule* module = result.value().get();
  NamesProvider names(module, wire_bytes);
  ModuleWireBytes module_bytes(wire_bytes);
  ModuleDisassembler md(out, module, &names, module_bytes, &allocator,
                        std::move(offsets), function_body_offsets);
  md.PrintModule({0, 2}, v8_flags.wasm_disassembly_max_mb);
  out.ToDisassemblyCollector(collector);
}

void MultiLineStringBuilder::ToDisassemblyCollector(
    v8::debug::DisassemblyCollector* collector) {
  if (length() != 0) NextLine(0);  // Finalize last line.
  collector->ReserveLineCount(lines_.size());
  for (const Line& l : lines_) {
    // Don't include trailing '\n'.
    collector->AddLine(l.data, l.len - 1, l.bytecode_offset);
  }
}

void DisassembleFunctionImpl(const WasmModule* module, int func_index,
                             base::Vector<const uint8_t> function_body,
                             ModuleWireBytes module_bytes, NamesProvider* names,
                             std::ostream& os, std::vector<uint32_t>* offsets) {
  MultiLineStringBuilder sb;
  const wasm::WasmFunction& func = module->functions[func_index];
  AccountingAllocator allocator;
  Zone zone(&allocator, "Wasm disassembler");
  bool shared = module->type(func.sig_index).is_shared;
  WasmDetectedFeatures detected;
  FunctionBodyDisassembler d(&zone, module, func_index, shared, &detected,
                             func.sig, function_body.begin(),
                             function_body.end(), func.code.offset(),
                             module_bytes, names);
  d.DecodeAsWat(sb, {0, 2}, FunctionBodyDisassembler::kPrintHeader);
  const bool print_offsets = false;
  sb.WriteTo(os, print_offsets, offsets);
}

void DisassembleFunction(const WasmModule* module, int func_index,
                         base::Vector<const uint8_t> wire_bytes,
                         NamesProvider* names, std::ostream& os) {
  DCHECK(func_index < static_cast<int>(module->functions.size()) &&
         func_index >= static_cast<int>(module->num_imported_functions));
  ModuleWireBytes module_bytes(wire_bytes);
  base::Vector<const uint8_t> code =
      module_bytes.GetFunctionBytes(&module->functions[func_index]);
  std::vector<uint32_t>* collect_offsets = nullptr;
  DisassembleFunctionImpl(module, func_index, code, module_bytes, names, os,
                          collect_offsets);
}

void DisassembleFunction(const WasmModule* module, int func_index,
                         base::Vector<const uint8_t> function_body,
                         base::Vector<const uint8_t> maybe_wire_bytes,
                         uint32_t function_body_offset, std::ostream& os,
                         std::vector<uint32_t>* offsets) {
  DCHECK(func_index < static_cast<int>(module->functions.size()) &&
         func_index >= static_cast<int>(module->num_imported_functions));
  NamesProvider fake_names(module, maybe_wire_bytes);
  DisassembleFunctionImpl(module, func_index, function_body,
                          ModuleWireBytes{nullptr, 0}, &fake_names, os,
                          offsets);
}

////////////////////////////////////////////////////////////////////////////////
// Helpers.

static constexpr char kHexChars[] = "0123456789abcdef";
static constexpr char kUpperHexChars[] = "0123456789ABCDEF";

// Returns the log2 of the alignment, e.g. "4" means 2<<4 == 16 bytes.
// This is the same format as used in .wasm binary modules.
uint32_t GetDefaultAlignment(WasmOpcode opcode) {
  switch (opcode) {
    case kExprS128LoadMem:
    case kExprS128StoreMem:
      return 4;
    case kExprS128Load8x8S:
    case kExprS128Load8x8U:
    case kExprS128Load16x4S:
    case kExprS128Load16x4U:
    case kExprS128Load32x2S:
    case kExprS128Load32x2U:
    case kExprS128Load64Splat:
    case kExprS128Load64Zero:
    case kExprS128Load64Lane:
    case kExprS128Store64Lane:
      return 3;
    case kExprS128Load32Splat:
    case kExprS128Load32Zero:
    case kExprS128Load32Lane:
    case kExprS128Store32Lane:
      return 2;
    case kExprS128Load16Splat:
    case kExprS128Load16Lane:
    case kExprS128Store16Lane:
      return 1;
    case kExprS128Load8Splat:
    case kExprS128Load8Lane:
    case kExprS128Store8Lane:
      return 0;

#define CASE(Opcode, ...) \
  case kExpr##Opcode:     \
    return GetLoadType(kExpr##Opcode).size_log_2();
      FOREACH_LOAD_MEM_OPCODE(CASE)
#undef CASE
#define CASE(Opcode, ...) \
  case kExpr##Opcode:     \
    return GetStoreType(kExpr##Opcode).size_log_2();
      FOREACH_STORE_MEM_OPCODE(CASE)
#undef CASE

#define CASE(Opcode, Type) \
  case kExpr##Opcode:      \
    return ElementSizeLog2Of(MachineType::Type().representation());
      ATOMIC_OP_LIST(CASE)
      ATOMIC_STORE_OP_LIST(CASE)
#undef CASE

    default:
      UNREACHABLE();
  }
}

void PrintSignatureOneLine(StringBuilder& out, const FunctionSig* sig,
                           uint32_t func_index, NamesProvider* names,
                           bool param_names,
                           IndexAsComment indices_as_comments) {
  if (param_names) {
    for (uint32_t i = 0; i < sig->parameter_count(); i++) {
      out << " (param ";
      names->PrintLocalName(out, func_index, i, indices_as_comments);
      out << ' ';
      names->PrintValueType(out, sig->GetParam(i));
      out << ")";
    }
  } else if (sig->parameter_count() > 0) {
    out << " (param";
    for (uint32_t i = 0; i < sig->parameter_count(); i++) {
      out << " ";
      names->PrintValueType(out, sig->GetParam(i));
    }
    out << ")";
  }
  for (size_t i = 0; i < sig->return_count(); i++) {
    out << " (result ";
    names->PrintValueType(out, sig->GetReturn(i));
    out << ")";
  }
}

void PrintStringRaw(StringBuilder& out, const uint8_t* start,
                    const uint8_t* end) {
  for (const uint8_t* ptr = start; ptr < end; ptr++) {
    uint8_t b = *ptr;
    if (b < 32 || b >= 127 || b == '"' || b == '\\') {
      out << '\\' << kHexChars[b >> 4] << kHexChars[b & 0xF];
    } else {
      out << static_cast<char>(b);
    }
  }
}

////////////////////////////////////////////////////////////////////////////////
// FunctionBodyDisassembler.

void FunctionBodyDisassembler::DecodeAsWat(MultiLineStringBuilder& out,
                                           Indentation indentation,
                                           FunctionHeader include_header,
                                           uint32_t* first_instruction_offset) {
  out_ = &out;
  int base_indentation = indentation.current();
  // Print header.
  if (include_header == kPrintHeader) {
    out << indentation << "(func ";
    names_->PrintFunctionName(out, func_index_, NamesProvider::kDevTools);
    PrintSignatureOneLine(out, sig_, func_index_, names_, true,
                          kIndicesAsComments);
    out.NextLine(pc_offset());
  } else {
    out.set_current_line_bytecode_offset(pc_offset());
  }
  indentation.increase();

  // Decode and print locals.
  uint32_t locals_length = DecodeLocals(pc_);
  if (failed()) {
    // TODO(jkummerow): Improve error handling.
    out << "Failed to decode locals\n";
    return;
  }
  for (uint32_t i = static_cast<uint32_t>(sig_->parameter_count());
       i < num_locals_; i++) {
    out << indentation << "(local ";
    names_->PrintLocalName(out, func_index_, i);
    out << " ";
    names_->PrintValueType(out, local_type(i));
    out << ")";
    out.NextLine(pc_offset());
  }
  consume_bytes(locals_length);
  out.set_current_line_bytecode_offset(pc_offset());
  if (first_instruction_offset) *first_instruction_offset = pc_offset();

  // Main loop.
  while (pc_ < end_ && ok()) {
    WasmOpcode opcode = GetOpcode();
    current_opcode_ = opcode;  // Some immediates need to know this.

    // Deal with indentation.
    if (opcode == kExprEnd || opcode == kExprElse || opcode == kExprCatch ||
        opcode == kExprCatchAll || opcode == kExprDelegate) {
      if (indentation.current() >= base_indentation) {
        indentation.decrease();
      }
    }
    out << indentation;
    if (opcode == kExprElse || opcode == kExprCatch ||
        opcode == kExprCatchAll || opcode == kExprBlock || opcode == kExprIf ||
        opcode == kExprLoop || opcode == kExprTry || opcode == kExprTryTable) {
      indentation.increase();
    }

    // Print the opcode and its immediates.
    if (opcode == kExprEnd) {
      if (indentation.current() < base_indentation) {
        out << ";; Unexpected end byte";
      } else if (indentation.current() == base_indentation) {
        out << ")";  // End of the function.
      } else {
        out << "end";
        const LabelInfo& label = label_stack_.back();
        if (label.start != nullptr) {
          out << " ";
          out.write(label.start, label.length);
        }
        label_stack_.pop_back();
      }
    } else {
      out << WasmOpcodes::OpcodeName(opcode);
    }
    if (opcode == kExprBlock || opcode == kExprIf || opcode == kExprLoop ||
        opcode == kExprTry || opcode == kExprTryTable) {
      // Create the LabelInfo now to get the correct offset, but only push it
      // after printing the immediates because the immediates don't see the new
      // label yet.
      LabelInfo label(out.line_number(), out.length(),
                      label_occurrence_index_++);
      pc_ += PrintImmediatesAndGetLength(out);
      label_stack_.push_back(label);
    } else {
      pc_ += PrintImmediatesAndGetLength(out);
    }

    out.NextLine(pc_offset());
  }

  if (pc_ != end_) {
    // TODO(jkummerow): Improve error handling.
    out << "Beyond end of code";
  }
}

void FunctionBodyDisassembler::DecodeGlobalInitializer(StringBuilder& out) {
  while (pc_ < end_) {
    WasmOpcode opcode = GetOpcode();
    current_opcode_ = opcode;  // Some immediates need to know this.
    // Don't print the final "end".
    if (opcode == kExprEnd && pc_ + 1 == end_) break;
    uint32_t length;
    out << " (" << WasmOpcodes::OpcodeName(opcode);
    length = PrintImmediatesAndGetLength(out);
    out << ")";
    pc_ += length;
  }
}

WasmOpcode FunctionBodyDisassembler::GetOpcode() {
  WasmOpcode opcode = static_cast<WasmOpcode>(*pc_);
  if (!WasmOpcodes::IsPrefixOpcode(opcode)) return opcode;
  return read_prefixed_opcode<ValidationTag>(pc_).first;
}

void FunctionBodyDisassembler::PrintHexNumber(StringBuilder& out,
                                              uint64_t number) {
  constexpr size_t kBufferSize = sizeof(number) * 2 + 2;  // +2 for "0x".
  char buffer[kBufferSize];
  char* end = buffer + kBufferSize;
  char* ptr = end;
  do {
    *(--ptr) = kHexChars[number & 0xF];
    number >>= 4;
  } while (number > 0);
  *(--ptr) = 'x';
  *(--ptr) = '0';
  size_t length = static_cast<size_t>(end - ptr);
  char* output = out.allocate(length);
  memcpy(output, ptr, length);
}

////////////////////////////////////////////////////////////////////////////////
// ImmediatesPrinter.

template <typename ValidationTag>
class ImmediatesPrinter {
 public:
  ImmediatesPrinter(StringBuilder& out, FunctionBodyDisassembler* owner)
      : out_(out), owner_(owner) {}

  void PrintDepthAsLabel(int imm_depth) {
    out_ << " ";
    size_t label_start_position = out_.length();
    int depth = imm_depth;
    if (owner_->current_opcode_ == kExprDelegate) depth++;
    // Be robust: if the module is invalid, print what we got.
    if (depth < 0 || depth >= static_cast<int>(owner_->label_stack_.size())) {
      out_ << imm_depth;
      return;
    }
    // If the label's name has already been determined and backpatched, just
    // copy it here.
    LabelInfo& label_info = owner_->label_info(depth);
    if (label_info.start != nullptr) {
      out_.write(label_info.start, label_info.length);
      return;
    }
    // Determine the label's name and backpatch the line that opened the block.
    names()->PrintLabelName(out_, owner_->func_index_,
                            label_info.name_section_index,
                            owner_->label_generation_index_++);
    label_info.length = out_.length() - label_start_position;
    owner_->out_->PatchLabel(label_info, out_.start() + label_start_position);
  }

  void PrintSignature(ModuleTypeIndex sig_index) {
    if (owner_->module_->has_signature(sig_index)) {
      const FunctionSig* sig = owner_->module_->signature(sig_index);
      PrintSignatureOneLine(out_, sig, 0 /* ignored */, names(), false);
    } else {
      out_ << " (signature: " << sig_index << " INVALID)";
    }
  }

  void BlockType(BlockTypeImmediate& imm) {
    if (imm.sig.all().begin() == nullptr) {
      PrintSignature(imm.sig_index);
    } else {
      PrintSignatureOneLine(out_, &imm.sig, 0 /* ignored */, names(), false);
    }
  }

  void HeapType(HeapTypeImmediate& imm) {
    out_ << " ";
    names()->PrintHeapType(out_, imm.type);
    if (imm.type.is_index()) use_type(imm.type.ref_index());
  }

  void ValueType(HeapTypeImmediate& imm, bool is_nullable) {
    out_ << " ";
    names()->PrintValueType(
        out_, ValueType::RefMaybeNull(imm.type,
                                      is_nullable ? kNullable : kNonNullable));
    if (imm.type.is_index()) use_type(imm.type.ref_index());
  }

  void BrOnCastFlags(BrOnCastImmediate& flags) {
    // Ignored here. For printing text format, we do all the work via the
    // two calls to {ValueType()} that we get for a br_on_cast.
  }

  void BranchDepth(BranchDepthImmediate& imm) { PrintDepthAsLabel(imm.depth); }

  void BranchTable(BranchTableImmediate& imm) {
    const uint8_t* pc = imm.table;
    for (uint32_t i = 0; i <= imm.table_count; i++) {
      auto [target, length] = owner_->read_u32v<ValidationTag>(pc);
      PrintDepthAsLabel(target);
      pc += length;
    }
  }

  const char* CatchKindToString(CatchKind kind) {
    switch (kind) {
      case kCatch:
        return "catch";
      case kCatchRef:
        return "catch_ref";
      case kCatchAll:
        return "catch_all";
      case kCatchAllRef:
        return "catch_all_ref";
      default:
        return "<invalid>";
    }
  }

  void TryTable(TryTableImmediate& imm) {
    const uint8_t* pc = imm.table;
    for (uint32_t i = 0; i < imm.table_count; i++) {
      uint8_t kind = owner_->read_u8<ValidationTag>(pc);
      pc += 1;
      out_ << " " << CatchKindToString(static_cast<CatchKind>(kind));
      if (kind == kCatch || kind == kCatchRef) {
        auto [tag, length] = owner_->read_u32v<ValidationTag>(pc);
        out_ << " ";
        names()->PrintTagName(out_, tag);
        pc += length;
      }
      auto [target, length] = owner_->read_u32v<ValidationTag>(pc);
      PrintDepthAsLabel(target);
      pc += length;
    }
  }

  void CallIndirect(CallIndirectImmediate& imm) {
    PrintSignature(imm.sig_imm.index);
    if (imm.table_imm.index != 0) TableIndex(imm.table_imm);
  }

  void SelectType(SelectTypeImmediate& imm) {
    out_ << " ";
    names()->PrintValueType(out_, imm.type);
  }

  void MemoryAccess(MemoryAccessImmediate& imm) {
    if (imm.offset != 0) out_ << " offset=" << imm.offset;
    if (imm.alignment != GetDefaultAlignment(owner_->current_opcode_)) {
      out_ << " align=" << (1u << imm.alignment);
    }
  }

  void SimdLane(SimdLaneImmediate& imm) { out_ << " " << uint32_t{imm.lane}; }

  void Field(FieldImmediate& imm) {
    TypeIndex(imm.struct_imm);
    out_ << " ";
    names()->PrintFieldName(out_, imm.struct_imm.index.index,
                            imm.field_imm.index);
  }

  void Length(IndexImmediate& imm) {
    out_ << " " << imm.index;  // --
  }

  void TagIndex(TagIndexImmediate& imm) {
    out_ << " ";
    names()->PrintTagName(out_, imm.index);
  }

  void FunctionIndex(IndexImmediate& imm) {
    out_ << " ";
    names()->PrintFunctionName(out_, imm.index, NamesProvider::kDevTools);
  }

  void TypeIndex(TypeIndexImmediate& imm) {
    out_ << " ";
    names()->PrintTypeName(out_, imm.index);
    use_type(imm.index);
  }

  void LocalIndex(IndexImmediate& imm) {
    out_ << " ";
    names()->PrintLocalName(out_, func_index(), imm.index);
  }

  void GlobalIndex(IndexImmediate& imm) {
    out_ << " ";
    names()->PrintGlobalName(out_, imm.index);
  }

  void TableIndex(TableIndexImmediate& imm) {
    out_ << " ";
    names()->PrintTableName(out_, imm.index);
  }

  void MemoryIndex(MemoryIndexImmediate& imm) {
    if (imm.index == 0) return;
    out_ << " " << imm.index;
  }

  void DataSegmentIndex(IndexImmediate& imm) {
    if (kSkipDataSegmentNames) {
      out_ << " " << imm.index;
    } else {
      out_ << " ";
      names()->PrintDataSegmentName(out_, imm.index);
    }
  }

  void ElemSegmentIndex(IndexImmediate& imm) {
    out_ << " ";
    names()->PrintElementSegmentName(out_, imm.index);
  }

  void I32Const(ImmI32Immediate& imm) {
    out_ << " " << imm.value;  // --
  }

  void I64Const(ImmI64Immediate& imm) {
    if (imm.value >= 0) {
      out_ << " " << static_cast<uint64_t>(imm.value);
    } else {
      out_ << " -" << ((~static_cast<uint64_t>(imm.value)) + 1);
    }
  }

  void F32Const(ImmF32Immediate& imm) {
    float f = imm.value;
    if (f == 0) {
      out_ << (1 / f < 0 ? " -0.0" : " 0.0");
    } else if (std::isinf(f)) {
      out_ << (f > 0 ? " inf" : " -inf");
    } else if (std::isnan(f)) {
      uint32_t bits = base::bit_cast<uint32_t>(f);
      uint32_t payload = bits & 0x7F'FFFFu;
      uint32_t signbit = bits >> 31;
      if (payload == 0x40'0000u) {
        out_ << (signbit == 1 ? " -nan" : " nan");
      } else {
        out_ << (signbit == 1 ? " -nan:" : " +nan:");
        owner_->PrintHexNumber(out_, payload);
      }
    } else {
      std::ostringstream o;
      // TODO(dlehmann): Change to `std::format` (C++20) or to `std::to_chars`
      // (C++17) once available, so that `0.1` isn't printed as `0.100000001`
      // any more.
      o << std::setprecision(std::numeric_limits<float>::max_digits10) << f;
      out_ << " " << o.str();
    }
  }

  void F64Const(ImmF64Immediate& imm) {
    double d = imm.value;
    if (d == 0) {
      out_ << (1 / d < 0 ? " -0.0" : " 0.0");
    } else if (std::isinf(d)) {
      out_ << (d > 0 ? " inf" : " -inf");
    } else if (std::isnan(d)) {
      uint64_t bits = base::bit_cast<uint64_t>(d);
      uint64_t payload = bits & 0xF'FFFF'FFFF'FFFFull;
      uint64_t signbit = bits >> 63;
      if (payload == 0x8'0000'0000'0000ull) {
        out_ << (signbit == 1 ? " -nan" : " nan");
      } else {
        out_ << (signbit == 1 ? " -nan:" : " +nan:");
        owner_->PrintHexNumber(out_, payload);
      }
    } else {
      char buffer[100];
      const char* str = DoubleToCString(d, base::VectorOf(buffer, 100u));
      out_ << " " << str;
    }
  }

  void S128Const(Simd128Immediate& imm) {
    if (owner_->current_opcode_ == kExprI8x16Shuffle) {
      for (int i = 0; i < 16; i++) {
        out_ << " " << uint32_t{imm.value[i]};
      }
    } else {
      DCHECK_EQ(owner_->current_opcode_, kExprS128Const);
      out_ << " i32x4";
      for (int i = 0; i < 4; i++) {
        out_ << " 0x";
        for (int j = 3; j >= 0; j--) {  // Little endian.
          uint8_t b = imm.value[i * 4 + j];
          out_ << kUpperHexChars[b >> 4];
          out_ << kUpperHexChars[b & 0xF];
        }
      }
    }
  }

  void StringConst(StringConstImmediate& imm) {
    if (imm.index >= owner_->module_->stringref_literals.size()) {
      out_ << " " << imm.index << " INVALID";
      return;
    }
    if (owner_->wire_bytes_.start() == nullptr) {
      out_ << " " << imm.index;
      return;
    }
    out_ << " \"";
    const WasmStringRefLiteral& lit =
        owner_->module_->stringref_literals[imm.index];
    const uint8_t* start = owner_->wire_bytes_.start() + lit.source.offset();
    static constexpr uint32_t kMaxCharsPrinted = 40;
    if (lit.source.length() <= kMaxCharsPrinted) {
      const uint8_t* end =
          owner_->wire_bytes_.start() + lit.source.end_offset();
      PrintStringRaw(out_, start, end);
    } else {
      const uint8_t* end = start + kMaxCharsPrinted - 1;
      PrintStringRaw(out_, start, end);
      out_ << "…";
    }
    out_ << '"';
    if (kIndicesAsComments) out_ << " (;" << imm.index << ";)";
  }

  void MemoryInit(MemoryInitImmediate& imm) {
    DataSegmentIndex(imm.data_segment);
    if (imm.memory.index != 0) out_ << " " << uint32_t{imm.memory.index};
  }

  void MemoryCopy(MemoryCopyImmediate& imm) {
    if (imm.memory_dst.index == 0 && imm.memory_src.index == 0) return;
    out_ << " " << uint32_t{imm.memory_dst.index};
    out_ << " " << uint32_t{imm.memory_src.index};
  }

  void TableInit(TableInitImmediate& imm) {
    if (imm.table.index != 0) TableIndex(imm.table);
    ElemSegmentIndex(imm.element_segment);
  }

  void TableCopy(TableCopyImmediate& imm) {
    if (imm.table_dst.index == 0 && imm.table_src.index == 0) return;
    out_ << " ";
    names()->PrintTableName(out_, imm.table_dst.index);
    out_ << " ";
    names()->PrintTableName(out_, imm.table_src.index);
  }

  void ArrayCopy(TypeIndexImmediate& dst, TypeIndexImmediate& src) {
    out_ << " ";
    names()->PrintTypeName(out_, dst.index);
    out_ << " ";
    names()->PrintTypeName(out_, src.index);
    use_type(dst.index);
    use_type(src.index);
  }

 private:
  void use_type(ModuleTypeIndex type_index) {
    owner_->used_types_.insert(type_index.index);
  }

  NamesProvider* names() { return owner_->names_; }

  uint32_t func_index() { return owner_->func_index_; }

  StringBuilder& out_;
  FunctionBodyDisassembler* owner_;
};

uint32_t FunctionBodyDisassembler::PrintImmediatesAndGetLength(
    StringBuilder& out) {
  using Printer = ImmediatesPrinter<ValidationTag>;
  Printer imm_printer(out, this);
  return WasmDecoder::OpcodeLength<Printer>(this, this->pc_, imm_printer);
}

////////////////////////////////////////////////////////////////////////////////
// OffsetsProvider.

void OffsetsProvider::CollectOffsets(const WasmModule* module,
                                     base::Vector<const uint8_t> wire_bytes) {
  num_imported_tables_ = module->num_imported_tables;
  num_imported_globals_ = module->num_imported_globals;
  num_imported_tags_ = module->num_imported_tags;
  type_offsets_.reserve(module->types.size());
  import_offsets_.reserve(module->import_table.size());
  table_offsets_.reserve(module->tables.size() - num_imported_tables_);
  tag_offsets_.reserve(module->tags.size() - num_imported_tags_);
  global_offsets_.reserve(module->globals.size() - num_imported_globals_);
  element_offsets_.reserve(module->elem_segments.size());
  data_offsets_.reserve(module->data_segments.size());
  recgroups_.reserve(4);  // We can't know, so this is just a guess.

  WasmDetectedFeatures unused_detected_features;
  ModuleDecoderImpl decoder{WasmEnabledFeatures::All(), wire_bytes, kWasmOrigin,
                            &unused_detected_features, this};
  constexpr bool kNoVerifyFunctions = false;
  decoder.DecodeModule(kNoVerifyFunctions);
}

////////////////////////////////////////////////////////////////////////////////
// ModuleDisassembler.

ModuleDisassembler::ModuleDisassembler(
    MultiLineStringBuilder& out, const WasmModule* module, NamesProvider* names,
    const ModuleWireBytes wire_bytes, AccountingAllocator* allocator,
    std::unique_ptr<OffsetsProvider> offsets_provider,
    std::vector<int>* function_body_offsets)
    : out_(out),
      module_(module),
      names_(names),
      wire_bytes_(wire_bytes),
      start_(wire_bytes_.start()),
      zone_(allocator, "disassembler zone"),
      offsets_(offsets_provider.release()),
      function_body_offsets_(function_body_offsets) {
  if (!offsets_) {
    offsets_ = std::make_unique<OffsetsProvider>();
    offsets_->CollectOffsets(module, wire_bytes_.module_bytes());
  }
}

ModuleDisassembler::~ModuleDisassembler() = default;

void ModuleDisassembler::PrintTypeDefinition(uint32_t type_index,
                                             Indentation indentation,
                                             IndexAsComment index_as_comment) {
  uint32_t offset = offsets_->type_offset(type_index);
  out_.NextLine(offset);
  out_ << indentation << "(type ";
  names_->PrintTypeName(out_, type_index, index_as_comment);
  const TypeDefinition& type = module_->types[type_index];
  bool has_super = type.supertype != kNoSuperType;
  if (has_super) {
    out_ << " (sub ";
    if (type.is_final) out_ << "final ";
    names_->PrintHeapType(out_, HeapType(type.supertype));
  }
  if (type.kind == TypeDefinition::kArray) {
    const ArrayType* atype = type.array_type;
    out_ << " (array";
    if (type.is_shared) out_ << " shared";
    out_ << " (field ";
    PrintMutableType(atype->mutability(), atype->element_type());
    out_ << ")";  // Closes "(field ...".
  } else if (type.kind == TypeDefinition::kStruct) {
    const StructType* stype = type.struct_type;
    out_ << " (struct";
    if (type.is_shared) out_ << " shared";
    bool break_lines = stype->field_count() > 2;
    for (uint32_t i = 0; i < stype->field_count(); i++) {
      LineBreakOrSpace(break_lines, indentation, offset);
      out_ << "(field ";
      names_->PrintFieldName(out_, type_index, i);
      out_ << " ";
      PrintMutableType(stype->mutability(i), stype->field(i));
      out_ << ")";
    }
  } else if (type.kind == TypeDefinition::kFunction) {
    const FunctionSig* sig = type.function_sig;
    out_ << " (func";
    if (type.is_shared) out_ << " shared";
    bool break_lines = sig->parameter_count() + sig->return_count() > 2;
    for (uint32_t i = 0; i < sig->parameter_count(); i++) {
      LineBreakOrSpace(break_lines, indentation, offset);
      out_ << "(param ";
      names_->PrintLocalName(out_, type_index, i);
      out_ << " ";
      names_->PrintValueType(out_, sig->GetParam(i));
      out_ << ")";
    }
    for (uint32_t i = 0; i < sig->return_count(); i++) {
      LineBreakOrSpace(break_lines, indentation, offset);
      out_ << "(result ";
      names_->PrintValueType(out_, sig->GetReturn(i));
      out_ << ")";
    }
  }
  // Closes "(type", "(sub", and "(array" / "(struct" / "(func".
  out_ << (has_super ? ")))" : "))");
}

void ModuleDisassembler::PrintModule(Indentation indentation, size_t max_mb) {
  // 0. General infrastructure.
  // We don't store import/export information on {WasmTag} currently.
  size_t num_tags = module_->tags.size();
  std::vector<bool> exported_tags(num_tags, false);
  for (const WasmExport& ex : module_->export_table) {
    if (ex.kind == kExternalTag) exported_tags[ex.index] = true;
  }

  // I. Module name.
  out_ << indentation << "(module";
  if (module_->name.is_set()) {
    out_ << " $";
    const uint8_t* name_start = start_ + module_->name.offset();
    out_.write(name_start, module_->name.length());
  }
  indentation.increase();

  // II. Types
  uint32_t recgroup_index = 0;
  OffsetsProvider::RecGroup recgroup = offsets_->recgroup(recgroup_index++);
  bool in_explicit_recgroup = false;
  for (uint32_t i = 0; i < module_->types.size(); i++) {
    // No need to check {recgroup.valid()}, as the comparison will simply
    // never be true otherwise.
    while (i == recgroup.start_type_index) {
      out_.NextLine(recgroup.offset);
      out_ << indentation << "(rec";
      if V8_UNLIKELY (recgroup.end_type_index == i) {
        // Empty recgroup.
        out_ << ")";
        DCHECK(!in_explicit_recgroup);
        recgroup = offsets_->recgroup(recgroup_index++);
        continue;
      } else {
        in_explicit_recgroup = true;
        indentation.increase();
        break;
      }
    }
    if (kSkipFunctionTypesInTypeSection &&
        module_->has_signature(ModuleTypeIndex{i}) && !in_explicit_recgroup) {
      continue;
    }
    PrintTypeDefinition(i, indentation, kIndicesAsComments);
    if (in_explicit_recgroup && i == recgroup.end_type_index - 1) {
      in_explicit_recgroup = false;
      indentation.decrease();
      // The end of a recgroup is implicit in the wire bytes, so repeat the
      // previous line's offset for it.
      uint32_t offset = out_.current_line_bytecode_offset();
      out_.NextLine(offset);
      out_ << indentation << ")";
      recgroup = offsets_->recgroup(recgroup_index++);
    }
  }
  while (recgroup.valid()) {
    // There could be empty recgroups at the end of the type section.
    DCHECK_GE(recgroup.start_type_index, module_->types.size());
    DCHECK_EQ(recgroup.start_type_index, recgroup.end_type_index);
    out_.NextLine(recgroup.offset);
    out_ << indentation << "(rec)";
    recgroup = offsets_->recgroup(recgroup_index++);
  }

  // III. Imports
  for (uint32_t i = 0; i < module_->import_table.size(); i++) {
    const WasmImport& import = module_->import_table[i];
    out_.NextLine(offsets_->import_offset(i));
    out_ << indentation;
    switch (import.kind) {
      case kExternalTable: {
        out_ << "(table ";
        names_->PrintTableName(out_, import.index, kIndicesAsComments);
        const WasmTable& table = module_->tables[import.index];
        if (table.exported) PrintExportName(kExternalTable, import.index);
        PrintImportName(import);
        PrintTable(table);
        break;
      }
      case kExternalFunction: {
        out_ << "(func ";
        names_->PrintFunctionName(out_, import.index, NamesProvider::kDevTools,
                                  kIndicesAsComments);
        const WasmFunction& func = module_->functions[import.index];
        if (func.exported) PrintExportName(kExternalFunction, import.index);
        PrintImportName(import);
        PrintSignatureOneLine(out_, func.sig, import.index, names_, false);
        break;
      }
      case kExternalGlobal: {
        out_ << "(global ";
        names_->PrintGlobalName(out_, import.index, kIndicesAsComments);
        const WasmGlobal& global = module_->globals[import.index];
        if (global.exported) PrintExportName(kExternalGlobal, import.index);
        PrintImportName(import);
        PrintGlobal(global);
        break;
      }
      case kExternalMemory:
        out_ << "(memory ";
        names_->PrintMemoryName(out_, import.index, kIndicesAsComments);
        if (module_->memories[import.index].exported) {
          PrintExportName(kExternalMemory, 0);
        }
        PrintImportName(import);
        PrintMemory(module_->memories[import.index]);
        break;
      case kExternalTag:
        out_ << "(tag ";
        names_->PrintTagName(out_, import.index, kIndicesAsComments);
        PrintImportName(import);
        if (exported_tags[import.index]) {
          PrintExportName(kExternalTag, import.index);
        }
        PrintTagSignature(module_->tags[import.index].sig);
        break;
    }
    out_ << ")";
  }

  // IV. Tables
  for (uint32_t i = module_->num_imported_tables; i < module_->tables.size();
       i++) {
    const WasmTable& table = module_->tables[i];
    DCHECK(!table.imported);
    out_.NextLine(offsets_->table_offset(i));
    out_ << indentation << "(table ";
    names_->PrintTableName(out_, i, kIndicesAsComments);
    if (table.exported) Pr
"""


```