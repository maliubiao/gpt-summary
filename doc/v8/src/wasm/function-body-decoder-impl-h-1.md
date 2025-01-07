Response:
The user wants a summary of the provided C++ code snippet. The code defines several structs related to decoding WebAssembly function bodies.

Here's a breakdown of the thinking process:

1. **Identify the core purpose:** The code defines structures used during the decoding of a WebAssembly function body. This is hinted at by the file path and the `Decoder` class usage.

2. **Analyze individual structs:**
    * **`Simd128Immediate`:**  Represents an immediate value of 128 bits, likely used for SIMD instructions.
    * **`MemoryInitImmediate`:**  Holds information for a `memory.init` instruction, including data segment index and memory index.
    * **`MemoryCopyImmediate`:**  Holds information for a `memory.copy` instruction, specifying source and destination memory.
    * **`TableInitImmediate`:**  Similar to `MemoryInitImmediate`, but for table initialization.
    * **`TableCopyImmediate`:** Similar to `MemoryCopyImmediate`, but for table copying.
    * **`HeapTypeImmediate`:** Represents an immediate value specifying a heap type.
    * **`StringConstImmediate`:** Represents an immediate value referring to a string literal.
    * **`PcForErrors`:** A utility struct to store the program counter for error reporting during validation.
    * **`ValueBase`:**  Represents a value on the stack during decoding, along with its type.
    * **`Merge`:** Represents a merge point in the control flow, holding either a single value or an array of values.
    * **`ControlKind` enum:** Defines the different types of control flow structures (if, block, loop, try).
    * **`Reachability` enum:** Indicates the reachability of code during validation.
    * **`ControlBase`:** Represents an entry on the control stack, managing the state of control flow structures.
    * **`INTERFACE_FUNCTIONS` macros:** Define a set of callback functions that a `WasmFullDecoder` needs to implement. These functions handle different WebAssembly instructions.
    * **`invalid_instruction_trace`:** A constant used for error handling.
    * **`FastZoneVector`:** A custom vector implementation for efficient memory management within a `Zone`.
    * **`WasmDecoder`:** The main decoder class, providing methods for reading bytes, decoding immediates, and managing local variables. It also handles instruction tracing.

3. **Identify relationships between structs:**  Note how the "Immediate" structs are often used to store parameters for instructions, and how `ControlBase` uses `Merge` to manage values at control flow boundaries.

4. **Infer functionality based on names and members:**  The names of the structs and their members are quite descriptive (e.g., `MemoryInitImmediate` has `data_segment` and `memory`).

5. **Consider the context:** The code is part of V8's WebAssembly implementation, specifically the function body decoding process. This helps in understanding the purpose of these structures.

6. **Address specific user requests:**
    * **Functionality listing:**  List the purpose of each struct and key elements.
    * **`.tq` extension:** Confirm that this file is `.h` and therefore not a Torque source.
    * **JavaScript relation:** Explain the connection to JavaScript by describing how this code helps execute WebAssembly loaded in a JavaScript environment. Provide a simple JavaScript example of loading and running WASM.
    * **Code logic inference:** Select a simple struct (like `Simd128Immediate`) and demonstrate how it reads data, showing a hypothetical input and output.
    * **Common programming errors:** Think about potential errors during WebAssembly compilation or hand-written WASM that this decoder might encounter and try to handle (e.g., incorrect index, type mismatch).
    * **Part 2 of 9:** Acknowledge the context and reiterate the focus on the current section.

7. **Structure the answer:** Organize the information logically, starting with a general overview and then detailing each struct. Use clear headings and bullet points.

8. **Refine the language:**  Use precise technical terms while keeping the explanation understandable. Avoid jargon where possible or explain it. Ensure the JavaScript example is clear and functional.

By following these steps, a comprehensive and accurate summary of the provided code snippet can be generated, addressing all aspects of the user's request.
```cpp
struct Simd128Immediate {
  uint8_t value[kSimd128Size] = {0};

  template <typename ValidationTag>
  Simd128Immediate(Decoder* decoder, const uint8_t* pc, ValidationTag = {}) {
    for (uint32_t i = 0; i < kSimd128Size; ++i) {
      value[i] = decoder->read_u8<ValidationTag>(pc + i, "value");
    }
  }
};

struct MemoryInitImmediate {
  IndexImmediate data_segment;
  MemoryIndexImmediate memory;
  uint32_t length;

  template <typename ValidationTag>
  MemoryInitImmediate(Decoder* decoder, const uint8_t* pc,
                      ValidationTag validate = {})
      : data_segment(decoder, pc, "data segment index", validate),
        memory(decoder, pc + data_segment.length, validate),
        length(data_segment.length + memory.length) {}
};

struct MemoryCopyImmediate {
  MemoryIndexImmediate memory_dst;
  MemoryIndexImmediate memory_src;
  uint32_t length;

  template <typename ValidationTag>
  MemoryCopyImmediate(Decoder* decoder, const uint8_t* pc,
                      ValidationTag validate = {})
      : memory_dst(decoder, pc, validate),
        memory_src(decoder, pc + memory_dst.length, validate),
        length(memory_src.length + memory_dst.length) {}
};

struct TableInitImmediate {
  IndexImmediate element_segment;
  TableIndexImmediate table;
  uint32_t length;

  template <typename ValidationTag>
  TableInitImmediate(Decoder* decoder, const uint8_t* pc,
                     ValidationTag validate = {})
      : element_segment(decoder, pc, "element segment index", validate),
        table(decoder, pc + element_segment.length, validate),
        length(element_segment.length + table.length) {}
};

struct TableCopyImmediate {
  TableIndexImmediate table_dst;
  TableIndexImmediate table_src;
  uint32_t length;

  template <typename ValidationTag>
  TableCopyImmediate(Decoder* decoder, const uint8_t* pc,
                     ValidationTag validate = {})
      : table_dst(decoder, pc, validate),
        table_src(decoder, pc + table_dst.length, validate),
        length(table_src.length + table_dst.length) {}
};

struct HeapTypeImmediate {
  uint32_t length;
  HeapType type{HeapType::kBottom};

  template <typename ValidationTag>
  HeapTypeImmediate(WasmEnabledFeatures enabled, Decoder* decoder,
                    const uint8_t* pc, ValidationTag = {}) {
    std::tie(type, length) =
        value_type_reader::read_heap_type<ValidationTag>(decoder, pc, enabled);
  }
};

struct StringConstImmediate {
  uint32_t index;
  uint32_t length;

  template <typename ValidationTag>
  StringConstImmediate(Decoder* decoder, const uint8_t* pc,
                       ValidationTag = {}) {
    std::tie(index, length) =
        decoder->read_u32v<ValidationTag>(pc, "stringref literal index");
  }
};

template <bool validate>
struct PcForErrors {
  static_assert(validate == false);
  explicit PcForErrors(const uint8_t* /* pc */) {}

  const uint8_t* pc() const { return nullptr; }
};

template <>
struct PcForErrors<true> {
  const uint8_t* pc_for_errors = nullptr;

  explicit PcForErrors(const uint8_t* pc) : pc_for_errors(pc) {}

  const uint8_t* pc() const { return pc_for_errors; }
};

// An entry on the value stack.
template <typename ValidationTag>
struct ValueBase : public PcForErrors<ValidationTag::validate> {
  ValueType type = kWasmVoid;

  ValueBase(const uint8_t* pc, ValueType type)
      : PcForErrors<ValidationTag::validate>(pc), type(type) {}
};

template <typename Value>
struct Merge {
  uint32_t arity = 0;
  union {  // Either multiple values or a single value.
    Value* array;
    Value first;
  } vals = {nullptr};  // Initialize {array} with {nullptr}.

  // Tracks whether this merge was ever reached. Uses precise reachability, like
  // Reachability::kReachable.
  bool reached;

  explicit Merge(bool reached = false) : reached(reached) {}

  Value& operator[](uint32_t i) {
    DCHECK_GT(arity, i);
    return arity == 1 ? vals.first : vals.array[i];
  }
};

enum ControlKind : uint8_t {
  kControlIf,
  kControlIfElse,
  kControlBlock,
  kControlLoop,
  kControlTry,
  kControlTryTable,
  kControlTryCatch,
  kControlTryCatchAll,
};

enum Reachability : uint8_t {
  // reachable code.
  kReachable,
  // reachable code in unreachable block (implies normal validation).
  kSpecOnlyReachable,
  // code unreachable in its own block (implies polymorphic validation).
  kUnreachable
};

// An entry on the control stack (i.e. if, block, loop, or try).
template <typename Value, typename ValidationTag>
struct ControlBase : public PcForErrors<ValidationTag::validate> {
  ControlKind kind = kControlBlock;
  Reachability reachability = kReachable;

  // For try-table.
  base::Vector<CatchCase> catch_cases;

  uint32_t stack_depth = 0;  // Stack height at the beginning of the construct.
  uint32_t init_stack_depth = 0;  // Height of "locals initialization" stack
                                  // at the beginning of the construct.
  int32_t previous_catch = -1;  // Depth of the innermost catch containing this
                                // 'try'.

  // Values merged into the start or end of this control construct.
  Merge<Value> start_merge;
  Merge<Value> end_merge;

  bool might_throw = false;

  MOVE_ONLY_NO_DEFAULT_CONSTRUCTOR(ControlBase);

  ControlBase(Zone* zone, ControlKind kind, uint32_t stack_depth,
              uint32_t init_stack_depth, const uint8_t* pc,
              Reachability reachability)
      : PcForErrors<ValidationTag::validate>(pc),
        kind(kind),
        reachability(reachability),
        stack_depth(stack_depth),
        init_stack_depth(init_stack_depth),
        start_merge(reachability == kReachable) {}

  // Check whether the current block is reachable.
  bool reachable() const { return reachability == kReachable; }

  // Check whether the rest of the block is unreachable.
  // Note that this is different from {!reachable()}, as there is also the
  // "indirect unreachable state", for which both {reachable()} and
  // {unreachable()} return false.
  bool unreachable() const { return reachability == kUnreachable; }

  // Return the reachability of new control structs started in this block.
  Reachability innerReachability() const {
    return reachability == kReachable ? kReachable : kSpecOnlyReachable;
  }

  bool is_if() const { return is_onearmed_if() || is_if_else(); }
  bool is_onearmed_if() const { return kind == kControlIf; }
  bool is_if_else() const { return kind == kControlIfElse; }
  bool is_block() const { return kind == kControlBlock; }
  bool is_loop() const { return kind == kControlLoop; }
  bool is_incomplete_try() const { return kind == kControlTry; }
  bool is_try_catch() const { return kind == kControlTryCatch; }
  bool is_try_catchall() const { return kind == kControlTryCatchAll; }
  bool is_try() const {
    return is_incomplete_try() || is_try_catch() || is_try_catchall();
  }
  bool is_try_table() { return kind == kControlTryTable; }

  Merge<Value>* br_merge() {
    return is_loop() ? &this->start_merge : &this->end_merge;
  }
};

// This is the list of callback functions that an interface for the
// WasmFullDecoder should implement.
// F(Name, args...)
#define INTERFACE_FUNCTIONS(F)    \
  INTERFACE_META_FUNCTIONS(F)     \
  INTERFACE_CONSTANT_FUNCTIONS(F) \
  INTERFACE_NON_CONSTANT_FUNCTIONS(F)

#define INTERFACE_META_FUNCTIONS(F)    \
  F(TraceInstruction, uint32_t value)  \
  F(StartFunction)                     \
  F(StartFunctionBody, Control* block) \
  F(FinishFunction)                    \
  F(OnFirstError)                      \
  F(NextInstruction, WasmOpcode)

#define INTERFACE_CONSTANT_FUNCTIONS(F) /*       force 80 columns           */ \
  F(I32Const, Value* result, int32_t value)                                    \
  F(I64Const, Value* result, int64_t value)                                    \
  F(F32Const, Value* result, float value)                                      \
  F(F64Const, Value* result, double value)                                     \
  F(S128Const, const Simd128Immediate& imm, Value* result)                     \
  F(GlobalGet, Value* result, const GlobalIndexImmediate& imm)                 \
  F(DoReturn, uint32_t drop_values)                                            \
  F(UnOp, WasmOpcode opcode, const Value& value, Value* result)                \
  F(BinOp, WasmOpcode opcode, const Value& lhs, const Value& rhs,              \
    Value* result)                                                             \
  F(RefNull, ValueType type, Value* result)                                    \
  F(RefFunc, uint32_t function_index, Value* result)                           \
  F(StructNew, const StructIndexImmediate& imm, const Value args[],            \
    Value* result)                                                             \
  F(StructNewDefault, const StructIndexImmediate& imm, Value* result)          \
  F(ArrayNew, const ArrayIndexImmediate& imm, const Value& length,             \
    const Value& initial_value, Value* result)                                 \
  F(ArrayNewDefault, const ArrayIndexImmediate& imm, const Value& length,      \
    Value* result)                                                             \
  F(ArrayNewFixed, const ArrayIndexImmediate& imm,                             \
    const IndexImmediate& length_imm, const Value elements[], Value* result)   \
  F(ArrayNewSegment, const ArrayIndexImmediate& array_imm,                     \
    const IndexImmediate& data_segment, const Value& offset,                   \
    const Value& length, Value* result)                                        \
  F(RefI31, const Value& input, Value* result)                                 \
  F(StringConst, const StringConstImmediate& imm, Value* result)

#define INTERFACE_NON_CONSTANT_FUNCTIONS(F) /*       force 80 columns       */ \
  /* Control: */                                                               \
  F(Block, Control* block)                                                     \
  F(Loop, Control* block)                                                      \
  F(Try, Control* block)                                                       \
  F(TryTable, Control* block)                                                  \
  F(CatchCase, Control* block, const CatchCase& catch_case,                    \
    base::Vector<Value> caught_values)                                         \
  F(If, const Value& cond, Control* if_block)                                  \
  F(FallThruTo, Control* c)                                                    \
  F(PopControl, Control* block)                                                \
  /* Instructions: */                                                          \
  F(RefAsNonNull, const Value& arg, Value* result)                             \
  F(Drop)                                                                      \
  F(LocalGet, Value* result, const IndexImmediate& imm)                        \
  F(LocalSet, const Value& value, const IndexImmediate& imm)                   \
  F(LocalTee, const Value& value, Value* result, const IndexImmediate& imm)    \
  F(GlobalSet, const Value& value, const GlobalIndexImmediate& imm)            \
  F(TableGet, const Value& index, Value* result, const IndexImmediate& imm)    \
  F(TableSet, const Value& index, const Value& value,                          \
    const IndexImmediate& imm)                                                 \
  F(Trap, TrapReason reason)                                                   \
  F(NopForTestingUnsupportedInLiftoff)                                         \
  F(Forward, const Value& from, Value* to)                                     \
  F(Select, const Value& cond, const Value& fval, const Value& tval,           \
    Value* result)                                                             \
  F(BrOrRet, uint32_t depth)                                                   \
  F(BrIf, const Value& cond, uint32_t depth)                                   \
  F(BrTable, const BranchTableImmediate& imm, const Value& key)                \
  F(Else, Control* if_block)                                                   \
  F(LoadMem, LoadType type, const MemoryAccessImmediate& imm,                  \
    const Value& index, Value* result)                                         \
  F(LoadTransform, LoadType type, LoadTransformationKind transform,            \
    const MemoryAccessImmediate& imm, const Value& index, Value* result)       \
  F(LoadLane, LoadType type, const Value& value, const Value& index,           \
    const MemoryAccessImmediate& imm, const uint8_t laneidx, Value* result)    \
  F(StoreMem, StoreType type, const MemoryAccessImmediate& imm,                \
    const Value& index, const Value& value)                                    \
  F(StoreLane, StoreType type, const MemoryAccessImmediate& imm,               \
    const Value& index, const Value& value, const uint8_t laneidx)             \
  F(CurrentMemoryPages, const MemoryIndexImmediate& imm, Value* result)        \
  F(MemoryGrow, const MemoryIndexImmediate& imm, const Value& value,           \
    Value* result)                                                             \
  F(CallDirect, const CallFunctionImmediate& imm, const Value args[],          \
    Value returns[])                                                           \
  F(CallIndirect, const Value& index, const CallIndirectImmediate& imm,        \
    const Value args[], Value returns[])                                       \
  F(CallRef, const Value& func_ref, const FunctionSig* sig,                    \
    const Value args[], const Value returns[])                                 \
  F(ReturnCallRef, const Value& func_ref, const FunctionSig* sig,              \
    const Value args[])                                                        \
  F(ReturnCall, const CallFunctionImmediate& imm, const Value args[])          \
  F(ReturnCallIndirect, const Value& index, const CallIndirectImmediate& imm,  \
    const Value args[])                                                        \
  F(BrOnNull, const Value& ref_object, uint32_t depth,                         \
    bool pass_null_along_branch, Value* result_on_fallthrough)                 \
  F(BrOnNonNull, const Value& ref_object, Value* result, uint32_t depth,       \
    bool drop_null_on_fallthrough)                                             \
  F(SimdOp, WasmOpcode opcode, const Value args[], Value* result)              \
  F(SimdLaneOp, WasmOpcode opcode, const SimdLaneImmediate& imm,               \
    base::Vector<const Value> inputs, Value* result)                           \
  F(Simd8x16ShuffleOp, const Simd128Immediate& imm, const Value& input0,       \
    const Value& input1, Value* result)                                        \
  F(Throw, const TagIndexImmediate& imm, const Value args[])                   \
  F(ThrowRef, Value* value)                                                    \
  F(Rethrow, Control* block)                                                   \
  F(CatchException, const TagIndexImmediate& imm, Control* block,              \
    base::Vector<Value> caught_values)                                         \
  F(Delegate, uint32_t depth, Control* block)                                  \
  F(CatchAll, Control* block)                                                  \
  F(AtomicOp, WasmOpcode opcode, const Value args[], const size_t argc,        \
    const MemoryAccessImmediate& imm, Value* result)                           \
  F(AtomicFence)                                                               \
  F(MemoryInit, const MemoryInitImmediate& imm, const Value& dst,              \
    const Value& src, const Value& size)                                       \
  F(DataDrop, const IndexImmediate& imm)                                       \
  F(MemoryCopy, const MemoryCopyImmediate& imm, const Value& dst,              \
    const Value& src, const Value& size)                                       \
  F(MemoryFill, const MemoryIndexImmediate& imm, const Value& dst,             \
    const Value& value, const Value& size)                                     \
  F(TableInit, const TableInitImmediate& imm, const Value& dst,                \
    const Value& src, const Value& size)                                       \
  F(ElemDrop, const IndexImmediate& imm)                                       \
  F(TableCopy, const TableCopyImmediate& imm, const Value& dst,                \
    const Value& src, const Value& size)                                       \
  F(TableGrow, const IndexImmediate& imm, const Value& value,                  \
    const Value& delta, Value* result)                                         \
  F(TableSize, const IndexImmediate& imm, Value* result)                       \
  F(TableFill, const IndexImmediate& imm, const Value& start,                  \
    const Value& value, const Value& count)                                    \
  F(StructGet, const Value& struct_object, const FieldImmediate& field,        \
    bool is_signed, Value* result)                                             \
  F(StructSet, const Value& struct_object, const FieldImmediate& field,        \
    const Value& field_value)                                                  \
  F(ArrayGet, const Value& array_obj, const ArrayIndexImmediate& imm,          \
    const Value& index, bool is_signed, Value* result)                         \
  F(ArraySet, const Value& array_obj, const ArrayIndexImmediate& imm,          \
    const Value& index, const Value& value)                                    \
  F(ArrayLen, const Value& array_obj, Value* result)                           \
  F(ArrayCopy, const Value& dst, const Value& dst_index, const Value& src,     \
    const Value& src_index, const ArrayIndexImmediate& src_imm,                \
    const Value& length)                                                       \
  F(ArrayFill, const ArrayIndexImmediate& imm, const Value& array,             \
    const Value& index, const Value& value, const Value& length)               \
  F(ArrayInitSegment, const ArrayIndexImmediate& array_imm,                    \
    const IndexImmediate& segment_imm, const Value& array,                     \
    const Value& array_index, const Value& segment_offset,                     \
    const Value& length)                                                       \
  F(I31GetS, const Value& input, Value* result)                                \
  F(I31GetU, const Value& input, Value* result)                                \
  F(RefTest, ModuleTypeIndex ref_index, const Value& obj, Value* result,       \
    bool null_succeeds)                                                        \
  F(RefTestAbstract, const Value& obj, HeapType type, Value* result,           \
    bool null_succeeds)                                                        \
  F(RefCast, ModuleTypeIndex ref_index, const Value& obj, Value* result,       \
    bool null_succeeds)                                                        \
  F(RefCastAbstract, const Value& obj, HeapType type, Value* result,           \
    bool null_succeeds)                                                        \
  F(AssertNullTypecheck, const Value& obj, Value* result)                      \
  F(AssertNotNullTypecheck, const Value& obj, Value* result)                   \
  F(BrOnCast, ModuleTypeIndex ref_index, const Value& obj,                     \
    Value* result_on_branch, uint32_t depth, bool null_succeeds)               \
  F(BrOnCastFail, ModuleTypeIndex ref_index, const Value& obj,                 \
    Value* result_on_fallthrough, uint32_t depth, bool null_succeeds)          \
  F(BrOnCastAbstract, const Value& obj, HeapType type,                         \
    Value* result_on_branch, uint32_t depth, bool null_succeeds)               \
  F(BrOnCastFailAbstract, const Value& obj, HeapType type,                     \
    Value* result_on_fallthrough, uint32_t depth, bool null_succeeds)          \
  F(StringNewWtf8, const MemoryIndexImmediate& memory,                         \
    const unibrow::Utf8Variant variant, const Value& offset,                   \
    const Value& size, Value* result)                                          \
  F(StringNewWtf8Array, const unibrow::Utf8Variant variant,                    \
    const Value& array, const Value& start, const Value& end, Value* result)   \
  F(StringNewWtf16, const MemoryIndexImmediate& memory, const Value& offset,   \
    const Value& size, Value* result)                                          \
  F(StringNewWtf16Array, const Value& array, const Value& start,               \
    const Value& end, Value* result)                                           \
  F(StringMeasureWtf8, const unibrow::Utf8Variant variant, const Value& str,   \
    Value* result)                                                             \
  F(StringMeasureWtf16, const Value& str, Value* result)                       \
  F(StringEncodeWtf8, const MemoryIndexImmediate& memory,                      \
    const unibrow::Utf8Variant variant, const Value& str,                      \
    const Value& address, Value* result)                                       \
  F(StringEncodeWtf8Array, const unibrow::Utf8Variant variant,                 \
    const Value& str, const Value& array, const Value& start, Value* result)   \
  F(StringEncodeWtf16, const MemoryIndexImmediate& memory, const Value& str,   \
    const Value& address, Value* result)                                       \
  F(StringEncodeWtf16Array, const Value& str, const Value& array,              \
    const Value& start, Value* result)                                         \
  F(StringConcat, const Value& head, const Value& tail, Value* result)         \
  F(StringEq, const Value& a, const Value& b, Value* result)                   \
  F(StringIsUSVSequence, const Value& str, Value* result)                      \
  F(StringAsWtf8, const Value& str, Value* result)                             \
  F(StringViewWtf8Advance, const Value& view, const Value& pos,                \
    const Value& bytes, Value* result)                                         \
  F(StringViewWtf8Encode, const MemoryIndexImmediate& memory,                  \
    const unibrow::Utf8Variant variant, const Value& view, const Value& addr,  \
    const Value& pos, const Value& bytes, Value* next_pos,                     \
    Value* bytes_written)                                                      \
  F(StringViewWtf8Slice, const Value& view, const Value& start,                \
    const Value& end, Value* result)                                           \
  F(StringAsWtf16, const Value& str, Value* result)                            \
  F(StringViewWtf16GetCodeUnit, const Value& view, const Value& pos,           \
    Value* result)                                                             \
  F(StringViewWtf16Encode, const MemoryIndexImmediate& memory,                 \
    const Value& view, const Value& addr, const Value& pos,                    \
    const Value& codeunits, Value* result)                                     \
  F(StringViewWtf16Slice, const Value& view, const Value& start,               \
    const Value& end, Value* result)                                           \
  F(StringAsIter, const Value& str, Value* result)                             \
  F(StringViewIterNext, const Value& view, Value* result)                      \
  F(StringViewIterAdvance, const Value& view, const Value& codepoints,         \
    Value* result)                                                             \
  F(StringViewIterRewind, const Value& view, const Value& codepoints,          \
    Value* result)                                                             \
  F(StringViewIterSlice, const Value& view, const Value& codepoints,           \
    Value* result)                                                             \
  F(StringCompare, const Value& lhs, const Value& rhs, Value* result)          \
  F(StringFromCodePoint, const Value& code_point, Value* result)               \
  F(StringHash, const Value& string, Value* result)

// This is a global constant invalid instruction trace, to be pointed at by
// the current instruction trace pointer in the default case
const std::pair<uint32_t, uint32_t> invalid_instruction_trace = {0, 0};

// A fast vector implementation, without implicit bounds checks (see
// https://crbug.com/1358853).
template <typename T>
class FastZoneVector {
 public:
  FastZoneVector() = default;
  explicit FastZoneVector(int initial_size, Zone* zone) {
    Grow(initial_size, zone);
  }

#ifdef DEBUG
  ~FastZoneVector() {
    // Check that {Reset} was called on this vector.
    DCHECK_NULL(begin_);
  }
#endif

  void Reset(Zone* zone) {
    if (begin_ == nullptr) return;
    if constexpr (!std::is_trivially_destructible_v<T>) {
      for (T* ptr = begin_; ptr != end_; ++ptr) {
        ptr->~T();
      }
    }
    zone->DeleteArray(begin_, capacity_end_ - begin_);
    begin_ = nullptr;
    end_ = nullptr;
    capacity_end_ = nullptr;
  }

  T* begin() const { return begin_; }
  T* end() const { return end_; }

  T& front() {
    DCHECK(!empty());
    return begin_[0];
  }

  T& back() {
    DCHECK(!empty());
    return end_[-1];
  }

  uint32_t size() const { return static_cast<uint32_t>(end_ - begin_); }

  bool empty() const { return begin_ == end_; }

  T& operator[](uint32_t index) {
    DCHECK_GE(size(), index);
    return begin_[index];
  }

  void shrink_to(uint32_t new_size) {
    static_assert(std::is_trivially_destructible_v<T>);
    DCHECK_GE(size(), new_size);
    end_ = begin_ + new_size;
  }

  void pop(uint32_t num = 1) {
    DCHECK_GE(size(), num);
    for (T* new_end = end_ - num; end_ != new_end;) {
      --end_;
      end_->~T();
    }
  }

  void push(T value) {
    DCHECK_GT(capacity_end_, end_);
    *end_ = std::move(value);
    ++end_;
  }

  template <typename... Args>
  void emplace_back(Args&&... args) {
    DCHECK_GT(capacity_end_, end_);
    new (end_) T{std::forward<Args>(args)...};
    ++end_;
  }

  V8_INLINE void EnsureMoreCapacity(int slots_needed, Zone* zone) {
    if (V8_LIKELY(capacity_end_ - end_ >= slots_needed)) return;
    Grow(slots_needed, zone);
  }

 private:
  V8_NOINLINE V8_PRESERVE_MOST void Grow(int slots_needed, Zone* zone) {
    size_t new_capacity = std::max(
        size_t{8}, base::bits::RoundUpToPowerOfTwo(size() + slots_needed));
    CHECK_GE(kMaxUInt32, new_capacity);
    DCHECK_LT(capacity_end_ - begin_, new_capacity);
    T* new_begin = zone->template AllocateArray<T>(new_capacity);
    if (begin_) {
      for (T *ptr = begin_, *new_ptr = new_begin; ptr != end_;
           ++ptr, ++new_ptr) {
        new (new_ptr) T{std::move(*ptr)};
        ptr->~T();
      }
      zone->DeleteArray(begin_, capacity_end_ - begin_);
    }
    end_ = new_begin + (end_ - begin_);
    begin_ = new_begin;
    capacity_end_ = new_begin + new_capacity;
  }

  // The array is zone-allocated inside {EnsureMoreCapacity}.
  T* begin_ = nullptr;
  T* end_ = nullptr;
  T* capacity_end_ = nullptr;
};

// Generic Wasm bytecode decoder with utilities for decoding immediates,
// lengths, etc.
template <typename ValidationTag, DecodingMode decoding_mode = kFunctionBody>
class WasmDecoder : public Decoder {
 public:
  WasmDecoder(Zone* zone, const WasmModule* module, WasmEnabledFeatures enabled,
              WasmDetectedFeatures* detected, const FunctionSig* sig,
              bool is_shared, const uint8_t* start, const uint8_t* end,
              uint32_t buffer_offset = 0)
      : Decoder(start, end, buffer_offset),
        zone_(zone),
        
Prompt: 
```
这是目录为v8/src/wasm/function-body-decoder-impl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/function-body-decoder-impl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共9部分，请归纳一下它的功能

"""
e {
  uint8_t value[kSimd128Size] = {0};

  template <typename ValidationTag>
  Simd128Immediate(Decoder* decoder, const uint8_t* pc, ValidationTag = {}) {
    for (uint32_t i = 0; i < kSimd128Size; ++i) {
      value[i] = decoder->read_u8<ValidationTag>(pc + i, "value");
    }
  }
};

struct MemoryInitImmediate {
  IndexImmediate data_segment;
  MemoryIndexImmediate memory;
  uint32_t length;

  template <typename ValidationTag>
  MemoryInitImmediate(Decoder* decoder, const uint8_t* pc,
                      ValidationTag validate = {})
      : data_segment(decoder, pc, "data segment index", validate),
        memory(decoder, pc + data_segment.length, validate),
        length(data_segment.length + memory.length) {}
};

struct MemoryCopyImmediate {
  MemoryIndexImmediate memory_dst;
  MemoryIndexImmediate memory_src;
  uint32_t length;

  template <typename ValidationTag>
  MemoryCopyImmediate(Decoder* decoder, const uint8_t* pc,
                      ValidationTag validate = {})
      : memory_dst(decoder, pc, validate),
        memory_src(decoder, pc + memory_dst.length, validate),
        length(memory_src.length + memory_dst.length) {}
};

struct TableInitImmediate {
  IndexImmediate element_segment;
  TableIndexImmediate table;
  uint32_t length;

  template <typename ValidationTag>
  TableInitImmediate(Decoder* decoder, const uint8_t* pc,
                     ValidationTag validate = {})
      : element_segment(decoder, pc, "element segment index", validate),
        table(decoder, pc + element_segment.length, validate),
        length(element_segment.length + table.length) {}
};

struct TableCopyImmediate {
  TableIndexImmediate table_dst;
  TableIndexImmediate table_src;
  uint32_t length;

  template <typename ValidationTag>
  TableCopyImmediate(Decoder* decoder, const uint8_t* pc,
                     ValidationTag validate = {})
      : table_dst(decoder, pc, validate),
        table_src(decoder, pc + table_dst.length, validate),
        length(table_src.length + table_dst.length) {}
};

struct HeapTypeImmediate {
  uint32_t length;
  HeapType type{HeapType::kBottom};

  template <typename ValidationTag>
  HeapTypeImmediate(WasmEnabledFeatures enabled, Decoder* decoder,
                    const uint8_t* pc, ValidationTag = {}) {
    std::tie(type, length) =
        value_type_reader::read_heap_type<ValidationTag>(decoder, pc, enabled);
  }
};

struct StringConstImmediate {
  uint32_t index;
  uint32_t length;

  template <typename ValidationTag>
  StringConstImmediate(Decoder* decoder, const uint8_t* pc,
                       ValidationTag = {}) {
    std::tie(index, length) =
        decoder->read_u32v<ValidationTag>(pc, "stringref literal index");
  }
};

template <bool validate>
struct PcForErrors {
  static_assert(validate == false);
  explicit PcForErrors(const uint8_t* /* pc */) {}

  const uint8_t* pc() const { return nullptr; }
};

template <>
struct PcForErrors<true> {
  const uint8_t* pc_for_errors = nullptr;

  explicit PcForErrors(const uint8_t* pc) : pc_for_errors(pc) {}

  const uint8_t* pc() const { return pc_for_errors; }
};

// An entry on the value stack.
template <typename ValidationTag>
struct ValueBase : public PcForErrors<ValidationTag::validate> {
  ValueType type = kWasmVoid;

  ValueBase(const uint8_t* pc, ValueType type)
      : PcForErrors<ValidationTag::validate>(pc), type(type) {}
};

template <typename Value>
struct Merge {
  uint32_t arity = 0;
  union {  // Either multiple values or a single value.
    Value* array;
    Value first;
  } vals = {nullptr};  // Initialize {array} with {nullptr}.

  // Tracks whether this merge was ever reached. Uses precise reachability, like
  // Reachability::kReachable.
  bool reached;

  explicit Merge(bool reached = false) : reached(reached) {}

  Value& operator[](uint32_t i) {
    DCHECK_GT(arity, i);
    return arity == 1 ? vals.first : vals.array[i];
  }
};

enum ControlKind : uint8_t {
  kControlIf,
  kControlIfElse,
  kControlBlock,
  kControlLoop,
  kControlTry,
  kControlTryTable,
  kControlTryCatch,
  kControlTryCatchAll,
};

enum Reachability : uint8_t {
  // reachable code.
  kReachable,
  // reachable code in unreachable block (implies normal validation).
  kSpecOnlyReachable,
  // code unreachable in its own block (implies polymorphic validation).
  kUnreachable
};

// An entry on the control stack (i.e. if, block, loop, or try).
template <typename Value, typename ValidationTag>
struct ControlBase : public PcForErrors<ValidationTag::validate> {
  ControlKind kind = kControlBlock;
  Reachability reachability = kReachable;

  // For try-table.
  base::Vector<CatchCase> catch_cases;

  uint32_t stack_depth = 0;  // Stack height at the beginning of the construct.
  uint32_t init_stack_depth = 0;  // Height of "locals initialization" stack
                                  // at the beginning of the construct.
  int32_t previous_catch = -1;  // Depth of the innermost catch containing this
                                // 'try'.

  // Values merged into the start or end of this control construct.
  Merge<Value> start_merge;
  Merge<Value> end_merge;

  bool might_throw = false;

  MOVE_ONLY_NO_DEFAULT_CONSTRUCTOR(ControlBase);

  ControlBase(Zone* zone, ControlKind kind, uint32_t stack_depth,
              uint32_t init_stack_depth, const uint8_t* pc,
              Reachability reachability)
      : PcForErrors<ValidationTag::validate>(pc),
        kind(kind),
        reachability(reachability),
        stack_depth(stack_depth),
        init_stack_depth(init_stack_depth),
        start_merge(reachability == kReachable) {}

  // Check whether the current block is reachable.
  bool reachable() const { return reachability == kReachable; }

  // Check whether the rest of the block is unreachable.
  // Note that this is different from {!reachable()}, as there is also the
  // "indirect unreachable state", for which both {reachable()} and
  // {unreachable()} return false.
  bool unreachable() const { return reachability == kUnreachable; }

  // Return the reachability of new control structs started in this block.
  Reachability innerReachability() const {
    return reachability == kReachable ? kReachable : kSpecOnlyReachable;
  }

  bool is_if() const { return is_onearmed_if() || is_if_else(); }
  bool is_onearmed_if() const { return kind == kControlIf; }
  bool is_if_else() const { return kind == kControlIfElse; }
  bool is_block() const { return kind == kControlBlock; }
  bool is_loop() const { return kind == kControlLoop; }
  bool is_incomplete_try() const { return kind == kControlTry; }
  bool is_try_catch() const { return kind == kControlTryCatch; }
  bool is_try_catchall() const { return kind == kControlTryCatchAll; }
  bool is_try() const {
    return is_incomplete_try() || is_try_catch() || is_try_catchall();
  }
  bool is_try_table() { return kind == kControlTryTable; }

  Merge<Value>* br_merge() {
    return is_loop() ? &this->start_merge : &this->end_merge;
  }
};

// This is the list of callback functions that an interface for the
// WasmFullDecoder should implement.
// F(Name, args...)
#define INTERFACE_FUNCTIONS(F)    \
  INTERFACE_META_FUNCTIONS(F)     \
  INTERFACE_CONSTANT_FUNCTIONS(F) \
  INTERFACE_NON_CONSTANT_FUNCTIONS(F)

#define INTERFACE_META_FUNCTIONS(F)    \
  F(TraceInstruction, uint32_t value)  \
  F(StartFunction)                     \
  F(StartFunctionBody, Control* block) \
  F(FinishFunction)                    \
  F(OnFirstError)                      \
  F(NextInstruction, WasmOpcode)

#define INTERFACE_CONSTANT_FUNCTIONS(F) /*       force 80 columns           */ \
  F(I32Const, Value* result, int32_t value)                                    \
  F(I64Const, Value* result, int64_t value)                                    \
  F(F32Const, Value* result, float value)                                      \
  F(F64Const, Value* result, double value)                                     \
  F(S128Const, const Simd128Immediate& imm, Value* result)                     \
  F(GlobalGet, Value* result, const GlobalIndexImmediate& imm)                 \
  F(DoReturn, uint32_t drop_values)                                            \
  F(UnOp, WasmOpcode opcode, const Value& value, Value* result)                \
  F(BinOp, WasmOpcode opcode, const Value& lhs, const Value& rhs,              \
    Value* result)                                                             \
  F(RefNull, ValueType type, Value* result)                                    \
  F(RefFunc, uint32_t function_index, Value* result)                           \
  F(StructNew, const StructIndexImmediate& imm, const Value args[],            \
    Value* result)                                                             \
  F(StructNewDefault, const StructIndexImmediate& imm, Value* result)          \
  F(ArrayNew, const ArrayIndexImmediate& imm, const Value& length,             \
    const Value& initial_value, Value* result)                                 \
  F(ArrayNewDefault, const ArrayIndexImmediate& imm, const Value& length,      \
    Value* result)                                                             \
  F(ArrayNewFixed, const ArrayIndexImmediate& imm,                             \
    const IndexImmediate& length_imm, const Value elements[], Value* result)   \
  F(ArrayNewSegment, const ArrayIndexImmediate& array_imm,                     \
    const IndexImmediate& data_segment, const Value& offset,                   \
    const Value& length, Value* result)                                        \
  F(RefI31, const Value& input, Value* result)                                 \
  F(StringConst, const StringConstImmediate& imm, Value* result)

#define INTERFACE_NON_CONSTANT_FUNCTIONS(F) /*       force 80 columns       */ \
  /* Control: */                                                               \
  F(Block, Control* block)                                                     \
  F(Loop, Control* block)                                                      \
  F(Try, Control* block)                                                       \
  F(TryTable, Control* block)                                                  \
  F(CatchCase, Control* block, const CatchCase& catch_case,                    \
    base::Vector<Value> caught_values)                                         \
  F(If, const Value& cond, Control* if_block)                                  \
  F(FallThruTo, Control* c)                                                    \
  F(PopControl, Control* block)                                                \
  /* Instructions: */                                                          \
  F(RefAsNonNull, const Value& arg, Value* result)                             \
  F(Drop)                                                                      \
  F(LocalGet, Value* result, const IndexImmediate& imm)                        \
  F(LocalSet, const Value& value, const IndexImmediate& imm)                   \
  F(LocalTee, const Value& value, Value* result, const IndexImmediate& imm)    \
  F(GlobalSet, const Value& value, const GlobalIndexImmediate& imm)            \
  F(TableGet, const Value& index, Value* result, const IndexImmediate& imm)    \
  F(TableSet, const Value& index, const Value& value,                          \
    const IndexImmediate& imm)                                                 \
  F(Trap, TrapReason reason)                                                   \
  F(NopForTestingUnsupportedInLiftoff)                                         \
  F(Forward, const Value& from, Value* to)                                     \
  F(Select, const Value& cond, const Value& fval, const Value& tval,           \
    Value* result)                                                             \
  F(BrOrRet, uint32_t depth)                                                   \
  F(BrIf, const Value& cond, uint32_t depth)                                   \
  F(BrTable, const BranchTableImmediate& imm, const Value& key)                \
  F(Else, Control* if_block)                                                   \
  F(LoadMem, LoadType type, const MemoryAccessImmediate& imm,                  \
    const Value& index, Value* result)                                         \
  F(LoadTransform, LoadType type, LoadTransformationKind transform,            \
    const MemoryAccessImmediate& imm, const Value& index, Value* result)       \
  F(LoadLane, LoadType type, const Value& value, const Value& index,           \
    const MemoryAccessImmediate& imm, const uint8_t laneidx, Value* result)    \
  F(StoreMem, StoreType type, const MemoryAccessImmediate& imm,                \
    const Value& index, const Value& value)                                    \
  F(StoreLane, StoreType type, const MemoryAccessImmediate& imm,               \
    const Value& index, const Value& value, const uint8_t laneidx)             \
  F(CurrentMemoryPages, const MemoryIndexImmediate& imm, Value* result)        \
  F(MemoryGrow, const MemoryIndexImmediate& imm, const Value& value,           \
    Value* result)                                                             \
  F(CallDirect, const CallFunctionImmediate& imm, const Value args[],          \
    Value returns[])                                                           \
  F(CallIndirect, const Value& index, const CallIndirectImmediate& imm,        \
    const Value args[], Value returns[])                                       \
  F(CallRef, const Value& func_ref, const FunctionSig* sig,                    \
    const Value args[], const Value returns[])                                 \
  F(ReturnCallRef, const Value& func_ref, const FunctionSig* sig,              \
    const Value args[])                                                        \
  F(ReturnCall, const CallFunctionImmediate& imm, const Value args[])          \
  F(ReturnCallIndirect, const Value& index, const CallIndirectImmediate& imm,  \
    const Value args[])                                                        \
  F(BrOnNull, const Value& ref_object, uint32_t depth,                         \
    bool pass_null_along_branch, Value* result_on_fallthrough)                 \
  F(BrOnNonNull, const Value& ref_object, Value* result, uint32_t depth,       \
    bool drop_null_on_fallthrough)                                             \
  F(SimdOp, WasmOpcode opcode, const Value args[], Value* result)              \
  F(SimdLaneOp, WasmOpcode opcode, const SimdLaneImmediate& imm,               \
    base::Vector<const Value> inputs, Value* result)                           \
  F(Simd8x16ShuffleOp, const Simd128Immediate& imm, const Value& input0,       \
    const Value& input1, Value* result)                                        \
  F(Throw, const TagIndexImmediate& imm, const Value args[])                   \
  F(ThrowRef, Value* value)                                                    \
  F(Rethrow, Control* block)                                                   \
  F(CatchException, const TagIndexImmediate& imm, Control* block,              \
    base::Vector<Value> caught_values)                                         \
  F(Delegate, uint32_t depth, Control* block)                                  \
  F(CatchAll, Control* block)                                                  \
  F(AtomicOp, WasmOpcode opcode, const Value args[], const size_t argc,        \
    const MemoryAccessImmediate& imm, Value* result)                           \
  F(AtomicFence)                                                               \
  F(MemoryInit, const MemoryInitImmediate& imm, const Value& dst,              \
    const Value& src, const Value& size)                                       \
  F(DataDrop, const IndexImmediate& imm)                                       \
  F(MemoryCopy, const MemoryCopyImmediate& imm, const Value& dst,              \
    const Value& src, const Value& size)                                       \
  F(MemoryFill, const MemoryIndexImmediate& imm, const Value& dst,             \
    const Value& value, const Value& size)                                     \
  F(TableInit, const TableInitImmediate& imm, const Value& dst,                \
    const Value& src, const Value& size)                                       \
  F(ElemDrop, const IndexImmediate& imm)                                       \
  F(TableCopy, const TableCopyImmediate& imm, const Value& dst,                \
    const Value& src, const Value& size)                                       \
  F(TableGrow, const IndexImmediate& imm, const Value& value,                  \
    const Value& delta, Value* result)                                         \
  F(TableSize, const IndexImmediate& imm, Value* result)                       \
  F(TableFill, const IndexImmediate& imm, const Value& start,                  \
    const Value& value, const Value& count)                                    \
  F(StructGet, const Value& struct_object, const FieldImmediate& field,        \
    bool is_signed, Value* result)                                             \
  F(StructSet, const Value& struct_object, const FieldImmediate& field,        \
    const Value& field_value)                                                  \
  F(ArrayGet, const Value& array_obj, const ArrayIndexImmediate& imm,          \
    const Value& index, bool is_signed, Value* result)                         \
  F(ArraySet, const Value& array_obj, const ArrayIndexImmediate& imm,          \
    const Value& index, const Value& value)                                    \
  F(ArrayLen, const Value& array_obj, Value* result)                           \
  F(ArrayCopy, const Value& dst, const Value& dst_index, const Value& src,     \
    const Value& src_index, const ArrayIndexImmediate& src_imm,                \
    const Value& length)                                                       \
  F(ArrayFill, const ArrayIndexImmediate& imm, const Value& array,             \
    const Value& index, const Value& value, const Value& length)               \
  F(ArrayInitSegment, const ArrayIndexImmediate& array_imm,                    \
    const IndexImmediate& segment_imm, const Value& array,                     \
    const Value& array_index, const Value& segment_offset,                     \
    const Value& length)                                                       \
  F(I31GetS, const Value& input, Value* result)                                \
  F(I31GetU, const Value& input, Value* result)                                \
  F(RefTest, ModuleTypeIndex ref_index, const Value& obj, Value* result,       \
    bool null_succeeds)                                                        \
  F(RefTestAbstract, const Value& obj, HeapType type, Value* result,           \
    bool null_succeeds)                                                        \
  F(RefCast, ModuleTypeIndex ref_index, const Value& obj, Value* result,       \
    bool null_succeeds)                                                        \
  F(RefCastAbstract, const Value& obj, HeapType type, Value* result,           \
    bool null_succeeds)                                                        \
  F(AssertNullTypecheck, const Value& obj, Value* result)                      \
  F(AssertNotNullTypecheck, const Value& obj, Value* result)                   \
  F(BrOnCast, ModuleTypeIndex ref_index, const Value& obj,                     \
    Value* result_on_branch, uint32_t depth, bool null_succeeds)               \
  F(BrOnCastFail, ModuleTypeIndex ref_index, const Value& obj,                 \
    Value* result_on_fallthrough, uint32_t depth, bool null_succeeds)          \
  F(BrOnCastAbstract, const Value& obj, HeapType type,                         \
    Value* result_on_branch, uint32_t depth, bool null_succeeds)               \
  F(BrOnCastFailAbstract, const Value& obj, HeapType type,                     \
    Value* result_on_fallthrough, uint32_t depth, bool null_succeeds)          \
  F(StringNewWtf8, const MemoryIndexImmediate& memory,                         \
    const unibrow::Utf8Variant variant, const Value& offset,                   \
    const Value& size, Value* result)                                          \
  F(StringNewWtf8Array, const unibrow::Utf8Variant variant,                    \
    const Value& array, const Value& start, const Value& end, Value* result)   \
  F(StringNewWtf16, const MemoryIndexImmediate& memory, const Value& offset,   \
    const Value& size, Value* result)                                          \
  F(StringNewWtf16Array, const Value& array, const Value& start,               \
    const Value& end, Value* result)                                           \
  F(StringMeasureWtf8, const unibrow::Utf8Variant variant, const Value& str,   \
    Value* result)                                                             \
  F(StringMeasureWtf16, const Value& str, Value* result)                       \
  F(StringEncodeWtf8, const MemoryIndexImmediate& memory,                      \
    const unibrow::Utf8Variant variant, const Value& str,                      \
    const Value& address, Value* result)                                       \
  F(StringEncodeWtf8Array, const unibrow::Utf8Variant variant,                 \
    const Value& str, const Value& array, const Value& start, Value* result)   \
  F(StringEncodeWtf16, const MemoryIndexImmediate& memory, const Value& str,   \
    const Value& address, Value* result)                                       \
  F(StringEncodeWtf16Array, const Value& str, const Value& array,              \
    const Value& start, Value* result)                                         \
  F(StringConcat, const Value& head, const Value& tail, Value* result)         \
  F(StringEq, const Value& a, const Value& b, Value* result)                   \
  F(StringIsUSVSequence, const Value& str, Value* result)                      \
  F(StringAsWtf8, const Value& str, Value* result)                             \
  F(StringViewWtf8Advance, const Value& view, const Value& pos,                \
    const Value& bytes, Value* result)                                         \
  F(StringViewWtf8Encode, const MemoryIndexImmediate& memory,                  \
    const unibrow::Utf8Variant variant, const Value& view, const Value& addr,  \
    const Value& pos, const Value& bytes, Value* next_pos,                     \
    Value* bytes_written)                                                      \
  F(StringViewWtf8Slice, const Value& view, const Value& start,                \
    const Value& end, Value* result)                                           \
  F(StringAsWtf16, const Value& str, Value* result)                            \
  F(StringViewWtf16GetCodeUnit, const Value& view, const Value& pos,           \
    Value* result)                                                             \
  F(StringViewWtf16Encode, const MemoryIndexImmediate& memory,                 \
    const Value& view, const Value& addr, const Value& pos,                    \
    const Value& codeunits, Value* result)                                     \
  F(StringViewWtf16Slice, const Value& view, const Value& start,               \
    const Value& end, Value* result)                                           \
  F(StringAsIter, const Value& str, Value* result)                             \
  F(StringViewIterNext, const Value& view, Value* result)                      \
  F(StringViewIterAdvance, const Value& view, const Value& codepoints,         \
    Value* result)                                                             \
  F(StringViewIterRewind, const Value& view, const Value& codepoints,          \
    Value* result)                                                             \
  F(StringViewIterSlice, const Value& view, const Value& codepoints,           \
    Value* result)                                                             \
  F(StringCompare, const Value& lhs, const Value& rhs, Value* result)          \
  F(StringFromCodePoint, const Value& code_point, Value* result)               \
  F(StringHash, const Value& string, Value* result)

// This is a global constant invalid instruction trace, to be pointed at by
// the current instruction trace pointer in the default case
const std::pair<uint32_t, uint32_t> invalid_instruction_trace = {0, 0};

// A fast vector implementation, without implicit bounds checks (see
// https://crbug.com/1358853).
template <typename T>
class FastZoneVector {
 public:
  FastZoneVector() = default;
  explicit FastZoneVector(int initial_size, Zone* zone) {
    Grow(initial_size, zone);
  }

#ifdef DEBUG
  ~FastZoneVector() {
    // Check that {Reset} was called on this vector.
    DCHECK_NULL(begin_);
  }
#endif

  void Reset(Zone* zone) {
    if (begin_ == nullptr) return;
    if constexpr (!std::is_trivially_destructible_v<T>) {
      for (T* ptr = begin_; ptr != end_; ++ptr) {
        ptr->~T();
      }
    }
    zone->DeleteArray(begin_, capacity_end_ - begin_);
    begin_ = nullptr;
    end_ = nullptr;
    capacity_end_ = nullptr;
  }

  T* begin() const { return begin_; }
  T* end() const { return end_; }

  T& front() {
    DCHECK(!empty());
    return begin_[0];
  }

  T& back() {
    DCHECK(!empty());
    return end_[-1];
  }

  uint32_t size() const { return static_cast<uint32_t>(end_ - begin_); }

  bool empty() const { return begin_ == end_; }

  T& operator[](uint32_t index) {
    DCHECK_GE(size(), index);
    return begin_[index];
  }

  void shrink_to(uint32_t new_size) {
    static_assert(std::is_trivially_destructible_v<T>);
    DCHECK_GE(size(), new_size);
    end_ = begin_ + new_size;
  }

  void pop(uint32_t num = 1) {
    DCHECK_GE(size(), num);
    for (T* new_end = end_ - num; end_ != new_end;) {
      --end_;
      end_->~T();
    }
  }

  void push(T value) {
    DCHECK_GT(capacity_end_, end_);
    *end_ = std::move(value);
    ++end_;
  }

  template <typename... Args>
  void emplace_back(Args&&... args) {
    DCHECK_GT(capacity_end_, end_);
    new (end_) T{std::forward<Args>(args)...};
    ++end_;
  }

  V8_INLINE void EnsureMoreCapacity(int slots_needed, Zone* zone) {
    if (V8_LIKELY(capacity_end_ - end_ >= slots_needed)) return;
    Grow(slots_needed, zone);
  }

 private:
  V8_NOINLINE V8_PRESERVE_MOST void Grow(int slots_needed, Zone* zone) {
    size_t new_capacity = std::max(
        size_t{8}, base::bits::RoundUpToPowerOfTwo(size() + slots_needed));
    CHECK_GE(kMaxUInt32, new_capacity);
    DCHECK_LT(capacity_end_ - begin_, new_capacity);
    T* new_begin = zone->template AllocateArray<T>(new_capacity);
    if (begin_) {
      for (T *ptr = begin_, *new_ptr = new_begin; ptr != end_;
           ++ptr, ++new_ptr) {
        new (new_ptr) T{std::move(*ptr)};
        ptr->~T();
      }
      zone->DeleteArray(begin_, capacity_end_ - begin_);
    }
    end_ = new_begin + (end_ - begin_);
    begin_ = new_begin;
    capacity_end_ = new_begin + new_capacity;
  }

  // The array is zone-allocated inside {EnsureMoreCapacity}.
  T* begin_ = nullptr;
  T* end_ = nullptr;
  T* capacity_end_ = nullptr;
};

// Generic Wasm bytecode decoder with utilities for decoding immediates,
// lengths, etc.
template <typename ValidationTag, DecodingMode decoding_mode = kFunctionBody>
class WasmDecoder : public Decoder {
 public:
  WasmDecoder(Zone* zone, const WasmModule* module, WasmEnabledFeatures enabled,
              WasmDetectedFeatures* detected, const FunctionSig* sig,
              bool is_shared, const uint8_t* start, const uint8_t* end,
              uint32_t buffer_offset = 0)
      : Decoder(start, end, buffer_offset),
        zone_(zone),
        module_(module),
        enabled_(enabled),
        detected_(detected),
        sig_(sig),
        is_shared_(is_shared) {
    current_inst_trace_ = &invalid_instruction_trace;
    if (V8_UNLIKELY(module_ && !module_->inst_traces.empty())) {
      auto last_trace = module_->inst_traces.end() - 1;
      auto first_inst_trace =
          std::lower_bound(module_->inst_traces.begin(), last_trace,
                           std::make_pair(buffer_offset, 0),
                           [](const std::pair<uint32_t, uint32_t>& a,
                              const std::pair<uint32_t, uint32_t>& b) {
                             return a.first < b.first;
                           });
      if (V8_UNLIKELY(first_inst_trace != last_trace)) {
        current_inst_trace_ = &*first_inst_trace;
      }
    }
  }

  Zone* zone() const { return zone_; }

  uint32_t num_locals() const { return num_locals_; }

  base::Vector<ValueType> local_types() const {
    return base::VectorOf(local_types_, num_locals_);
  }
  ValueType local_type(uint32_t index) const {
    DCHECK_GE(num_locals_, index);
    return local_types_[index];
  }

  // Decodes local definitions in the current decoder.
  // The decoded locals will be appended to {this->local_types_}.
  // The decoder's pc is not advanced.
  // The total length of decoded locals is returned.
  uint32_t DecodeLocals(const uint8_t* pc) {
    DCHECK_NULL(local_types_);
    DCHECK_EQ(0, num_locals_);

    // In a first step, count the number of locals and store the decoded
    // entries.
    num_locals_ = static_cast<uint32_t>(this->sig_->parameter_count());

    // Decode local declarations, if any.
    auto [entries, entries_length] =
        read_u32v<ValidationTag>(pc, "local decls count");

    if (!VALIDATE(ok())) {
      DecodeError(pc, "invalid local decls count");
      return 0;
    }
    TRACE("local decls count: %u\n", entries);

    // Do an early validity check, to avoid allocating too much memory below.
    // Every entry needs at least two bytes (count plus type); if that many are
    // not available any more, flag that as an error.
    if (available_bytes() / 2 < entries) {
      DecodeError(pc, "local decls count bigger than remaining function size");
      return 0;
    }

    struct DecodedLocalEntry {
      uint32_t count;
      ValueType type;
    };
    base::SmallVector<DecodedLocalEntry, 8> decoded_locals(entries);
    uint32_t total_length = entries_length;
    for (uint32_t entry = 0; entry < entries; ++entry) {
      if (!VALIDATE(more())) {
        DecodeError(end(),
                    "expected more local decls but reached end of input");
        return 0;
      }

      auto [count, count_length] =
          read_u32v<ValidationTag>(pc + total_length, "local count");
      if (!VALIDATE(ok())) {
        DecodeError(pc + total_length, "invalid local count");
        return 0;
      }
      DCHECK_LE(num_locals_, kV8MaxWasmFunctionLocals);
      if (!VALIDATE(count <= kV8MaxWasmFunctionLocals - num_locals_)) {
        DecodeError(pc + total_length, "local count too large");
        return 0;
      }
      total_length += count_length;

      auto [type, type_length] =
          value_type_reader::read_value_type<ValidationTag>(
              this, pc + total_length, enabled_);
      ValidateValueType(pc + total_length, type);
      if (!VALIDATE(!is_shared_ || IsShared(type, module_))) {
        DecodeError(pc + total_length, "local must have shared type");
        return 0;
      }
      if (!VALIDATE(ok())) return 0;
      total_length += type_length;

      num_locals_ += count;
      decoded_locals[entry] = DecodedLocalEntry{count, type};
    }
    DCHECK(ok());

    if (num_locals_ > 0) {
      // Now build the array of local types from the parsed entries.
      local_types_ = zone_->AllocateArray<ValueType>(num_locals_);
      ValueType* locals_ptr = local_types_;

      if (sig_->parameter_count() > 0) {
        std::copy(sig_->parameters().begin(), sig_->parameters().end(),
                  locals_ptr);
        locals_ptr += sig_->parameter_count();
      }

      for (auto& entry : decoded_locals) {
        std::fill_n(locals_ptr, entry.count, entry.type);
        locals_ptr += entry.count;
      }
      DCHECK_EQ(locals_ptr, local_types_ + num_locals_);
    }
    return total_length;
  }

  // Shorthand that forwards to the {DecodeError} functions above, passing our
  // {ValidationTag}.
  template <typename... Args>
  V8_INLINE void DecodeError(Args... args) {
    wasm::DecodeError<ValidationTag>(this, std::forward<Args>(args)...);
  }

  // Returns a BitVector of length {locals_count + 1} representing the set of
  // variables that are assigned in the loop starting at {pc}. The additional
  // position at the end of the vector represents possible assignments to
  // the instance cache.
  static BitVector* AnalyzeLoopAssignment(WasmDecoder* decoder,
                                          const uint8_t*
"""


```