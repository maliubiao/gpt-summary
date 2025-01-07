Response:
Let's break down the thought process for analyzing the `wasm-compiler.h` header file.

1. **Understand the Goal:** The request asks for a functional summary of the C++ header file `v8/src/compiler/wasm-compiler.h`. It also includes specific questions about Torque, JavaScript interaction, logic, common errors, and finally a general summary for part 1.

2. **Initial Scan and Keyword Identification:**  Read through the header, looking for key terms and patterns. Immediately, "WebAssembly," "compiler," "Turbofan," "Graph," "Node," "Wasm," "JS," "import," "export," "memory," "table," "global," "struct," "array," "string," and "exception" stand out. The `#ifndef` and `#define` guard are standard header file practices and can be noted but aren't core functionality. The `#error` directive confirms this header is specifically for WebAssembly.

3. **Categorize Functionality:**  Based on the initial scan, start grouping the functions and data structures into logical categories. This is crucial for a structured summary.

    * **Core Compilation:** Functions like `ExecuteTurbofanWasmCompilation`, `CompileWasmImportCallWrapper`, `CompileWasmCapiCallWrapper`, `CompileWasmJSFastCallWrapper`, and `NewJSToWasmCompilationJob` clearly deal with the compilation process.
    * **Graph Building:** The `WasmGraphBuilder` class is central here. Its methods (like `Start`, `Param`, `Binop`, `LoadMem`, `StoreMem`, `CallDirect`, etc.) are the building blocks for creating the compiler's internal representation (the graph).
    * **Data Structures:**  Structures like `WasmCompilationData`, `WasmInstanceCacheNodes`, `WasmLoopInfo` hold important information during compilation.
    * **Interoperability:**  Functions involving "import," "JS," and wrappers (`CompileWasmImportCallWrapper`, `CompileWasmJSFastCallWrapper`, `NewJSToWasmCompilationJob`, `CompileCWasmEntry`) highlight the interaction between WebAssembly and JavaScript.
    * **WebAssembly Features:**  Methods related to memory (`MemoryGrow`, `LoadMem`, `StoreMem`), tables (`TableGet`, `TableSet`), globals (`GlobalGet`, `GlobalSet`), and more complex features like threads (atomic operations), GC types (structs, arrays), and strings show the file's support for various WebAssembly functionalities.
    * **Error Handling:**  Functions like `TrapIfTrue`, `TrapIfFalse`, `Throw`, `Rethrow` deal with WebAssembly's trap (exception) mechanism.

4. **Analyze Specific Questions:**  Address each specific point in the request:

    * **`.tq` extension:** The header ends with `.h`, not `.tq`, so it's C++, not Torque.
    * **JavaScript Relation:** Identify functions that explicitly bridge the gap between Wasm and JS (import/export wrappers). Think about how JavaScript code might invoke WebAssembly functions and vice-versa. The example of calling a Wasm function from JS is a good illustration.
    * **Logic Inference:** Look for functions that perform conditional operations or data manipulation. The `Branch` family of functions and `Select` are good candidates. Create a simple, concrete example with inputs and expected outputs.
    * **Common Programming Errors:** Consider typical errors in WebAssembly or low-level programming that this compiler might need to handle or that developers might encounter. Out-of-bounds memory access is a classic example.

5. **Deep Dive into `WasmGraphBuilder`:** This class is the heart of the file. Go through its public methods and group them based on their purpose:

    * **Basic Graph Construction:**  `Start`, `Param`, `Loop`, `Merge`, `Phi`, constants.
    * **Control Flow:** `Branch`, `Switch`, `Return`, `Trap`.
    * **Function Calls:** `CallDirect`, `CallIndirect`, `CallRef`, `ReturnCall`, etc.
    * **Memory Operations:** `LoadMem`, `StoreMem`, `MemoryGrow`, `MemoryCopy`, etc.
    * **Table Operations:** `TableGet`, `TableSet`, `TableGrow`, etc.
    * **Global Operations:** `GlobalGet`, `GlobalSet`.
    * **Exception Handling:** `Throw`, `Rethrow`.
    * **Advanced Features:** Structs, Arrays, Strings, SIMD, Atomics, GC.
    * **Utilities:**  Methods for managing the instance cache, setting source positions, etc.

6. **Synthesize the Summary:** Combine the categorized functionalities into a concise summary. Focus on the "what" and "why" of the file. Emphasize its role in the WebAssembly compilation pipeline within V8. Mention the key components like the `WasmGraphBuilder` and its purpose.

7. **Review and Refine:** Read through the summary and ensure it's accurate, well-organized, and addresses all parts of the initial request. Check for clarity and conciseness. Make sure the examples are appropriate and easy to understand. For instance, initially, I might have just listed functions. But realizing the request asks for *functionality*, I refined it to explain *what* those functions enable. Similarly, for the common error, just stating "memory access errors" isn't as helpful as providing a concrete Wasm example and its JavaScript equivalent.

This systematic approach, moving from a broad overview to detailed analysis and then back to a synthesized summary, is crucial for understanding complex code like this header file. The process involves identifying key components, categorizing their roles, and then explaining their interactions and purposes.
```cpp
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if !V8_ENABLE_WEBASSEMBLY
#error This header should only be included if WebAssembly is enabled.
#endif  // !V8_ENABLE_WEBASSEMBLY

#ifndef V8_COMPILER_WASM_COMPILER_H_
#define V8_COMPILER_WASM_COMPILER_H_

#include <memory>
#include <utility>

// Clients of this interface shouldn't depend on lots of compiler internals.
// Do not include anything else from src/compiler here!
#include "src/base/small-vector.h"
#include "src/codegen/compiler.h"
#include "src/compiler/wasm-compiler-definitions.h"
#include "src/runtime/runtime.h"
#include "src/wasm/function-body-decoder.h"
#include "src/wasm/function-compiler.h"
#include "src/wasm/module-instantiate.h"
#include "src/wasm/wasm-features.h"
#include "src/wasm/wasm-module.h"
#include "src/wasm/wasm-opcodes.h"
#include "src/wasm/wasm-result.h"
#include "src/zone/zone.h"

namespace v8 {

class CFunctionInfo;

namespace internal {
enum class AbortReason : uint8_t;
struct AssemblerOptions;
enum class BranchHint : uint8_t;
class TurbofanCompilationJob;

namespace compiler {
// Forward declarations for some compiler data structures.
class CallDescriptor;
class Graph;
class MachineGraph;
class Node;
class NodeOriginTable;
class Operator;
class SourcePositionTable;
struct WasmCompilationData;
class WasmDecorator;
class WasmGraphAssembler;
enum class TrapId : int32_t;
struct Int64LoweringSpecialCase;
template <size_t VarCount>
class GraphAssemblerLabel;
struct WasmTypeCheckConfig;
}  // namespace compiler

namespace wasm {
struct DecodeStruct;
class WasmCode;
class WireBytesStorage;
enum class LoadTransformationKind : uint8_t;
enum Suspend : int;
enum CallOrigin { kCalledFromWasm, kCalledFromJS };
}  // namespace wasm

namespace compiler {

wasm::WasmCompilationResult ExecuteTurbofanWasmCompilation(
    wasm::CompilationEnv*, WasmCompilationData& compilation_data, Counters*,
    wasm::WasmDetectedFeatures* detected);

// Compiles an import call wrapper, which allows Wasm to call imports.
V8_EXPORT_PRIVATE wasm::WasmCompilationResult CompileWasmImportCallWrapper(
    wasm::ImportCallKind, const wasm::CanonicalSig*, bool source_positions,
    int expected_arity, wasm::Suspend);

// Compiles a host call wrapper, which allows Wasm to call host functions.
wasm::WasmCompilationResult CompileWasmCapiCallWrapper(
    const wasm::CanonicalSig*);

bool IsFastCallSupportedSignature(const v8::CFunctionInfo*);
// Compiles a wrapper to call a Fast API function from Wasm.
wasm::WasmCompilationResult CompileWasmJSFastCallWrapper(
    const wasm::CanonicalSig*, Handle<JSReceiver> callable);

// Returns an TurbofanCompilationJob or TurboshaftCompilationJob object
// (depending on the --turboshaft-wasm-wrappers flag) for a JS to Wasm wrapper.
std::unique_ptr<OptimizedCompilationJob> NewJSToWasmCompilationJob(
    Isolate* isolate, const wasm::CanonicalSig* sig);

enum CWasmEntryParameters {
  kCodeEntry,
  kObjectRef,
  kArgumentsBuffer,
  kCEntryFp,
  // marker:
  kNumParameters
};

// Compiles a stub with C++ linkage, to be called from Execution::CallWasm,
// which knows how to feed it its parameters.
V8_EXPORT_PRIVATE Handle<Code> CompileCWasmEntry(Isolate*,
                                                 const wasm::CanonicalSig*);

// Values from the instance object are cached between Wasm-level function calls.
// This struct allows the SSA environment handling this cache to be defined
// and manipulated in wasm-compiler.{h,cc} instead of inside the Wasm decoder.
// (Note that currently, the globals base is immutable, so not cached here.)
struct WasmInstanceCacheNodes {
  // Cache the memory start and size of one fixed memory per function. Which one
  // is determined by {WasmGraphBuilder::cached_memory_index}.
  Node* mem_start = nullptr;
  Node* mem_size = nullptr;

  // For iteration support. Defined outside the class for MSVC compatibility.
  using FieldPtr = Node* WasmInstanceCacheNodes::*;
  static const FieldPtr kFields[2];
};
inline constexpr WasmInstanceCacheNodes::FieldPtr
    WasmInstanceCacheNodes::kFields[] = {&WasmInstanceCacheNodes::mem_start,
                                         &WasmInstanceCacheNodes::mem_size};

struct WasmLoopInfo {
  Node* header;
  uint32_t nesting_depth;
  // This loop has, to our best knowledge, no other loops nested within it. A
  // loop can obtain inner loops despite this after inlining.
  bool can_be_innermost;

  WasmLoopInfo(Node* header, uint32_t nesting_depth, bool can_be_innermost)
      : header(header),
        nesting_depth(nesting_depth),
        can_be_innermost(can_be_innermost) {}
};

struct WasmCompilationData {
  explicit WasmCompilationData(const wasm::FunctionBody& func_body)
      : func_body(func_body) {}

  size_t body_size() { return func_body.end - func_body.start; }

  const wasm::FunctionBody& func_body;
  const wasm::WireBytesStorage* wire_bytes_storage;
  NodeOriginTable* node_origins{nullptr};
  std::vector<WasmLoopInfo>* loop_infos{nullptr};
  wasm::AssumptionsJournal* assumptions{nullptr};
  SourcePositionTable* source_positions{nullptr};
  int func_index;
};

// Abstracts details of building TurboFan graph nodes for wasm to separate
// the wasm decoder from the internal details of TurboFan.
class WasmGraphBuilder {
 public:
  // ParameterMode specifies how the instance is passed.
  enum ParameterMode {
    // Normal wasm functions pass the instance as an implicit first parameter.
    kInstanceParameterMode,
    // For Wasm-to-JS and C-API wrappers, a {WasmImportData} object is
    // passed as first parameter.
    kWasmImportDataMode,
    // For JS-to-Wasm wrappers (which are JS functions), we load the Wasm
    // instance from the JS function data. The generated code objects live on
    // the JS heap, so those compilation pass an isolate.
    kJSFunctionAbiMode,
    // The JS-to-JS wrapper does not have an associated instance.
    // The C-entry stub uses a custom ABI (see {CWasmEntryParameters}).
    kNoSpecialParameterMode
  };

  V8_EXPORT_PRIVATE WasmGraphBuilder(
      wasm::CompilationEnv* env, Zone* zone, MachineGraph* mcgraph,
      const wasm::FunctionSig* sig, compiler::SourcePositionTable* spt,
      ParameterMode parameter_mode, Isolate* isolate,
      wasm::WasmEnabledFeatures enabled_features,
      const wasm::CanonicalSig* wrapper_sig = nullptr);

  V8_EXPORT_PRIVATE ~WasmGraphBuilder();

  bool TryWasmInlining(int fct_index, wasm::NativeModule* native_module,
                       int inlining_id);

  //-----------------------------------------------------------------------
  // Operations independent of {control} or {effect}.
  //-----------------------------------------------------------------------
  void Start(unsigned params);
  Node* Param(int index, const char* debug_name = nullptr);
  Node* Loop(Node* entry);
  void TerminateLoop(Node* effect, Node* control);
  Node* LoopExit(Node* loop_node);
  // Assumes current control() is the corresponding loop exit.
  Node* LoopExitValue(Node* value, MachineRepresentation representation);
  void TerminateThrow(Node* effect, Node* control);
  Node* Merge(unsigned count, Node** controls);
  template <typename... Nodes>
  Node* Merge(Node* fst, Nodes*... args);
  Node* Phi(wasm::ValueType type, unsigned count, Node** vals_and_control);
  Node* CreateOrMergeIntoPhi(MachineRepresentation rep, Node* merge,
                             Node* tnode, Node* fnode);
  Node* CreateOrMergeIntoEffectPhi(Node* merge, Node* tnode, Node* fnode);
  Node* EffectPhi(unsigned count, Node** effects_and_control);
  Node* RefNull(wasm::ValueType type);
  Node* RefFunc(uint32_t function_index);
  Node* AssertNotNull(
      Node* object, wasm::ValueType type, wasm::WasmCodePosition position,
      wasm::TrapReason reason = wasm::TrapReason::kTrapNullDereference);
  Node* TraceInstruction(uint32_t mark_id);
  Node* Int32Constant(int32_t value);
  Node* Int64Constant(int64_t value);
  Node* Float32Constant(float value);
  Node* Float64Constant(double value);
  Node* Simd128Constant(const uint8_t value[16]);
  Node* Binop(wasm::WasmOpcode opcode, Node* left, Node* right,
              wasm::WasmCodePosition position = wasm::kNoCodePosition);
  // The {type} argument is only required for null-checking operations.
  Node* Unop(wasm::WasmOpcode opcode, Node* input,
             wasm::ValueType type = wasm::kWasmBottom,
             wasm::WasmCodePosition position = wasm::kNoCodePosition);
  Node* MemoryGrow(const wasm::WasmMemory* memory, Node* input);
  Node* Throw(uint32_t tag_index, const wasm::WasmTag* tag,
              const base::Vector<Node*> values,
              wasm::WasmCodePosition position);
  Node* Rethrow(Node* except_obj);
  Node* ThrowRef(Node* except_obj);
  Node* IsExceptionTagUndefined(Node* tag);
  Node* LoadJSTag();
  Node* ExceptionTagEqual(Node* caught_tag, Node* expected_tag);
  Node* LoadTagFromTable(uint32_t tag_index);
  Node* GetExceptionTag(Node* except_obj);
  Node* GetExceptionValues(Node* except_obj, const wasm::WasmTag* tag,
                           base::Vector<Node*> values_out);
  bool IsPhiWithMerge(Node* phi, Node* merge);
  bool ThrowsException(Node* node, Node** if_success, Node** if_exception);
  void AppendToMerge(Node* merge, Node* from);
  void AppendToPhi(Node* phi, Node* from);

  void StackCheck(WasmInstanceCacheNodes* shared_memory_instance_cache,
                  wasm::WasmCodePosition);

  void PatchInStackCheckIfNeeded();

  //-----------------------------------------------------------------------
  // Operations that read and/or write {control} and {effect}.
  //-----------------------------------------------------------------------

  // Branch nodes return the true and false projection.
  std::tuple<Node*, Node*> BranchNoHint(Node* cond);
  std::tuple<Node*, Node*> BranchExpectFalse(Node* cond);
  std::tuple<Node*, Node*> BranchExpectTrue(Node* cond);

  void TrapIfTrue(wasm::TrapReason reason, Node* cond,
                  wasm::WasmCodePosition position);
  void TrapIfFalse(wasm::TrapReason reason, Node* cond,
                   wasm::WasmCodePosition position);
  Node* Select(Node *cond, Node* true_node, Node* false_node,
               wasm::ValueType type);

  void TrapIfEq32(wasm::TrapReason reason, Node* node, int32_t val,
                  wasm::WasmCodePosition position);
  void ZeroCheck32(wasm::TrapReason reason, Node* node,
                   wasm::WasmCodePosition position);
  void TrapIfEq64(wasm::TrapReason reason, Node* node, int64_t val,
                  wasm::WasmCodePosition position);
  void ZeroCheck64(wasm::TrapReason reason, Node* node,
                   wasm::WasmCodePosition position);

  Node* Switch(unsigned count, Node* key);
  Node* IfValue(int32_t value, Node* sw);
  Node* IfDefault(Node* sw);
  Node* Return(base::Vector<Node*> nodes);
  template <typename... Nodes>
  Node* Return(Node* fst, Nodes*... more) {
    Node* arr[] = {fst, more...};
    return Return(base::ArrayVector(arr));
  }

  void TraceFunctionEntry(wasm::WasmCodePosition position);
  void TraceFunctionExit(base::Vector<Node*> vals,
                         wasm::WasmCodePosition position);

  void Trap(wasm::TrapReason reason, wasm::WasmCodePosition position);

  // In all six call-related public functions, we pass a signature based on the
  // real arguments for this call. This signature gets stored in the Call node
  // and will later help us generate better code if this call gets inlined.
  Node* CallDirect(uint32_t index, base::Vector<Node*> args,
                   base::Vector<Node*> rets, wasm::WasmCodePosition position);
  Node* CallIndirect(uint32_t table_index, wasm::ModuleTypeIndex sig_index,
                     base::Vector<Node*> args, base::Vector<Node*> rets,
                     wasm::WasmCodePosition position);
  Node* CallRef(const wasm::FunctionSig* sig, base::Vector<Node*> args,
                base::Vector<Node*> rets, CheckForNull null_check,
                wasm::WasmCodePosition position);

  Node* ReturnCall(uint32_t index, base::Vector<Node*> args,
                   wasm::WasmCodePosition position);
  Node* ReturnCallIndirect(uint32_t table_index,
                           wasm::ModuleTypeIndex sig_index,
                           base::Vector<Node*> args,
                           wasm::WasmCodePosition position);
  Node* ReturnCallRef(const wasm::FunctionSig* sig, base::Vector<Node*> args,
                      CheckForNull null_check, wasm::WasmCodePosition position);

  void CompareToFuncRefAtIndex(Node* func_ref, uint32_t function_index,
                               Node** success_control, Node** failure_control,
                               bool is_last_case);

  // BrOnNull returns the control for the null and non-null case.
  std::tuple<Node*, Node*> BrOnNull(Node* ref_object, wasm::ValueType type);

  Node* Invert(Node* node);

  Node* GlobalGet(uint32_t index);
  void GlobalSet(uint32_t index, Node* val);
  Node* TableGet(uint32_t table_index, Node* index,
                 wasm::WasmCodePosition position);
  void TableSet(uint32_t table_index, Node* index, Node* val,
                wasm::WasmCodePosition position);
  //-----------------------------------------------------------------------
  // Operations that concern the linear memory.
  //-----------------------------------------------------------------------
  Node* CurrentMemoryPages(const wasm::WasmMemory* memory);
  void TraceMemoryOperation(bool is_store, MachineRepresentation, Node* index,
                            uintptr_t offset, wasm::WasmCodePosition);
  Node* LoadMem(const wasm::WasmMemory* memory, wasm::ValueType type,
                MachineType memtype, Node* index, uintptr_t offset,
                uint32_t alignment, wasm::WasmCodePosition position);
  Node* LoadTransform(const wasm::WasmMemory* memory, wasm::ValueType type,
                      MachineType memtype,
                      wasm::LoadTransformationKind transform, Node* index,
                      uintptr_t offset, uint32_t alignment,
                      wasm::WasmCodePosition position);
  Node* LoadLane(const wasm::WasmMemory* memory, wasm::ValueType type,
                 MachineType memtype, Node* value, Node* index,
                 uintptr_t offset, uint32_t alignment, uint8_t laneidx,
                 wasm::WasmCodePosition position);
  void StoreMem(const wasm::WasmMemory* memory, MachineRepresentation mem_rep,
                Node* index, uintptr_t offset, uint32_t alignment, Node* val,
                wasm::WasmCodePosition position, wasm::ValueType type);
  void StoreLane(const wasm::WasmMemory* memory, MachineRepresentation mem_rep,
                 Node* index, uintptr_t offset, uint32_t alignment, Node* val,
                 uint8_t laneidx, wasm::WasmCodePosition position,
                 wasm::ValueType type);
  static void PrintDebugName(Node* node);

  Node* effect();
  Node* control();
  Node* SetEffect(Node* node);
  Node* SetControl(Node* node);
  void SetEffectControl(Node* effect, Node* control);
  Node* SetEffectControl(Node* effect_and_control) {
    SetEffectControl(effect_and_control, effect_and_control);
    return effect_and_control;
  }

  Node* SetType(Node* node, wasm::ValueType type);

  // Utilities to manipulate sets of instance cache nodes.
  void InitInstanceCache(WasmInstanceCacheNodes* instance_cache);
  void PrepareInstanceCacheForLoop(WasmInstanceCacheNodes* instance_cache,
                                   Node* control);
  void NewInstanceCacheMerge(WasmInstanceCacheNodes* to,
                             WasmInstanceCacheNodes* from, Node* merge);
  void MergeInstanceCacheInto(WasmInstanceCacheNodes* to,
                              WasmInstanceCacheNodes* from, Node* merge);

  void set_instance_cache(WasmInstanceCacheNodes* instance_cache) {
    this->instance_cache_ = instance_cache;
  }

  // Overload for when we want to provide a specific signature, rather than
  // build one using sig_, for example after scalar lowering.
  V8_EXPORT_PRIVATE void LowerInt64(Signature<MachineRepresentation>* sig);
  V8_EXPORT_PRIVATE void LowerInt64(wasm::CallOrigin origin);

  void SetSourcePosition(Node* node, wasm::WasmCodePosition position);

  Node* S128Zero();
  Node* S1x4Zero();
  Node* S1x8Zero();
  Node* S1x16Zero();

  Node* SimdOp(wasm::WasmOpcode opcode, Node* const* inputs);

  Node* SimdLaneOp(wasm::WasmOpcode opcode, uint8_t lane, Node* const* inputs);

  Node* Simd8x16ShuffleOp(const uint8_t shuffle[16], Node* const* inputs);

  Node* AtomicOp(const wasm::WasmMemory* memory, wasm::WasmOpcode opcode,
                 Node* const* inputs, uint32_t alignment, uintptr_t offset,
                 wasm::WasmCodePosition position);
  void AtomicFence();

  void MemoryInit(const wasm::WasmMemory* memory, uint32_t data_segment_index,
                  Node* dst, Node* src, Node* size,
                  wasm::WasmCodePosition position);
  void MemoryCopy(const wasm::WasmMemory* dst_memory,
                  const wasm::WasmMemory* src_memory, Node* dst, Node* src,
                  Node* size, wasm::WasmCodePosition position);
  void DataDrop(uint32_t data_segment_index, wasm::WasmCodePosition position);
  void MemoryFill(const wasm::WasmMemory* memory, Node* dst, Node* fill,
                  Node* size, wasm::WasmCodePosition position);

  void TableInit(uint32_t table_index, uint32_t elem_segment_index, Node* dst,
                 Node* src, Node* size, wasm::WasmCodePosition position);
  void ElemDrop(uint32_t elem_segment_index, wasm::WasmCodePosition position);
  void TableCopy(uint32_t table_dst_index, uint32_t table_src_index, Node* dst,
                 Node* src, Node* size, wasm::WasmCodePosition position);
  Node* TableGrow(uint32_t table_index, Node* value, Node* delta,
                  wasm::WasmCodePosition position);
  Node* TableSize(uint32_t table_index);
  void TableFill(uint32_t table_index, Node* start, Node* value, Node* count,
                 wasm::WasmCodePosition position);

  Node* StructNew(wasm::ModuleTypeIndex struct_index,
                  const wasm::StructType* type, Node* rtt,
                  base::Vector<Node*> fields);
  Node* StructGet(Node* struct_object, const wasm::StructType* struct_type,
                  uint32_t field_index, CheckForNull null_check, bool is_signed,
                  wasm::WasmCodePosition position);
  void StructSet(Node* struct_object, const wasm::StructType* struct_type,
                 uint32_t field_index, Node* value, CheckForNull null_check,
                 wasm::WasmCodePosition position);
  Node* ArrayNew(wasm::ModuleTypeIndex array_index, const wasm::ArrayType* type,
                 Node* length, Node* initial_value, Node* rtt,
                 wasm::WasmCodePosition position);
  Node* ArrayGet(Node* array_object, const wasm::ArrayType* type, Node* index,
                 CheckForNull null_check, bool is_signed,
                 wasm::WasmCodePosition position);
  void ArraySet(Node* array_object, const wasm::ArrayType* type, Node* index,
                Node* value, CheckForNull null_check,
                wasm::WasmCodePosition position);
  Node* ArrayLen(Node* array_object, CheckForNull null_check,
                 wasm::WasmCodePosition position);
  void ArrayCopy(Node* dst_array, Node* dst_index, CheckForNull dst_null_check,
                 Node* src_array, Node* src_index, CheckForNull src_null_check,
                 Node* length, const wasm::ArrayType* type,
                 wasm::WasmCodePosition position);
  void ArrayFill(Node* array, Node* index, Node* value, Node* length,
                 const wasm::ArrayType* type, CheckForNull null_check,
                 wasm::WasmCodePosition position);
  Node* ArrayNewFixed(const wasm::ArrayType* type, Node* rtt,
                      base::Vector<Node*> elements);
  Node* ArrayNewSegment(uint32_t segment_index, Node* offset, Node* length,
                        Node* rtt, bool is_element,
                        wasm::WasmCodePosition position);
  void ArrayInitSegment(uint32_t segment_index, Node* array, Node* array_index,
                        Node* segment_offset, Node* length, bool is_element,
                        wasm::WasmCodePosition position);
  Node* RefI31(Node* input);
  Node* I31GetS(Node* input, CheckForNull null_check,
                wasm::WasmCodePosition position);
  Node* I31GetU(Node* input, CheckForNull null_check,
                wasm::WasmCodePosition position);
  Node* RttCanon(wasm::ModuleTypeIndex type_index);

  Node* RefTest(Node* object, Node* rtt, WasmTypeCheckConfig config);
  Node* RefTestAbstract(Node* object, WasmTypeCheckConfig config);
  Node* RefCast(Node* object, Node* rtt, WasmTypeCheckConfig config,
                wasm::WasmCodePosition position);
  Node* RefCastAbstract(Node* object, WasmTypeCheckConfig config,
                        wasm::WasmCodePosition position);
  struct ResultNodesOfBr {
    Node* control_on_match;
    Node* effect_on_match;
    Node* control_on_no_match;
    Node* effect_on_no_match;
  };
  ResultNodesOfBr BrOnCast(Node* object, Node* rtt, WasmTypeCheckConfig config);
  ResultNodesOfBr BrOnEq(Node* object, Node* rtt, WasmTypeCheckConfig config);
  ResultNodesOfBr BrOnStruct(Node* object, Node* rtt,
                             WasmTypeCheckConfig config);
  ResultNodesOfBr BrOnArray(Node* object, Node* rtt,
                            WasmTypeCheckConfig config);
  ResultNodesOfBr BrOnI31(Node* object, Node* rtt, WasmTypeCheckConfig config);
  ResultNodesOfBr BrOnString(Node* object, Node* rtt,
                             WasmTypeCheckConfig config);

  Node* StringNewWtf8(const wasm::WasmMemory* memory,
                      unibrow::Utf8Variant variant, Node* offset, Node* size,
                      wasm::WasmCodePosition position);
  Node* StringNewWtf8Array(unibrow::Utf8Variant variant, Node* array,
                           CheckForNull null_check, Node* start, Node* end,
                           wasm::WasmCodePosition position);
  Node* StringNewWtf16(const wasm::WasmMemory* memory, Node* offset, Node* size,
                       wasm::WasmCodePosition position);
  Node* StringNewWtf16Array(Node* array, CheckForNull null_check, Node* start,
                            Node* end, wasm::WasmCodePosition position);
  Node* StringAsWtf16(Node* string, CheckForNull null_check,
                      wasm::WasmCodePosition position);
  Node* StringConst(uint32_t index);
  Node* StringMeasureUtf8(Node* string, CheckForNull null_check,
                          wasm::WasmCodePosition position);
  Node* StringMeasureWtf8(Node* string, CheckForNull null_check,
                          wasm::WasmCodePosition position);
  Node* StringMeasureWtf16(Node* string, CheckForNull null_check,
                           wasm::WasmCodePosition position);
  Node* StringEncodeWtf8(const wasm::WasmMemory* memory,
                         unibrow::Utf8Variant variant, Node* string,
                         CheckForNull null_check, Node* offset,
                         wasm::WasmCodePosition position);
  Node* StringEncodeWtf8Array(unibrow::Utf8Variant variant, Node* string,
                              CheckForNull string_null_check, Node* array,
                              CheckForNull array_null_check, Node* start,
                              wasm::WasmCodePosition position);
  Node* StringToUtf8Array(Node* string, CheckForNull null_check,
                          wasm::WasmCodePosition position);
  Node* StringEncodeWtf16(const wasm::WasmMemory* memory, Node* string,
                          CheckForNull null_check, Node* offset,
                          wasm::WasmCodePosition position);
  Node* StringEncodeWtf16Array(Node* string, CheckForNull string_null_check,
                               Node* array, CheckForNull array_null_check,
                               Node* start, wasm::WasmCodePosition position);
  Node* StringConcat(Node* head, CheckForNull head_null_check, Node* tail,
                     CheckForNull tail_null_check,
                     wasm::WasmCodePosition position);
  Node* StringEqual(Node* a, wasm::ValueType a_type, Node* b,
                    wasm::ValueType b_type, wasm::WasmCodePosition position);
  Node* StringIsUSVSequence(Node* str, CheckForNull null_check,
                            wasm::WasmCodePosition position);
  Node* StringAsWtf8(Node* str, CheckForNull null_check,
                     wasm::WasmCodePosition position);
  Node* StringViewWtf8Advance(Node* view, CheckForNull null_check, Node* pos,
                              Node* bytes, wasm::WasmCodePosition position);
  void StringViewWtf8Encode(const wasm::WasmMemory* memory,
                            unibrow::Utf8Variant variant, Node* view,
                            CheckForNull null_check, Node* addr, Node* pos,
                            Node* bytes, Node** next_pos, Node** bytes_written,
                            wasm::WasmCodePosition position);
  Node* StringViewWtf8Slice(Node* view, CheckForNull null_check, Node* pos,
                            Node* bytes, wasm::W
Prompt: 
```
这是目录为v8/src/compiler/wasm-compiler.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/wasm-compiler.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if !V8_ENABLE_WEBASSEMBLY
#error This header should only be included if WebAssembly is enabled.
#endif  // !V8_ENABLE_WEBASSEMBLY

#ifndef V8_COMPILER_WASM_COMPILER_H_
#define V8_COMPILER_WASM_COMPILER_H_

#include <memory>
#include <utility>

// Clients of this interface shouldn't depend on lots of compiler internals.
// Do not include anything else from src/compiler here!
#include "src/base/small-vector.h"
#include "src/codegen/compiler.h"
#include "src/compiler/wasm-compiler-definitions.h"
#include "src/runtime/runtime.h"
#include "src/wasm/function-body-decoder.h"
#include "src/wasm/function-compiler.h"
#include "src/wasm/module-instantiate.h"
#include "src/wasm/wasm-features.h"
#include "src/wasm/wasm-module.h"
#include "src/wasm/wasm-opcodes.h"
#include "src/wasm/wasm-result.h"
#include "src/zone/zone.h"

namespace v8 {

class CFunctionInfo;

namespace internal {
enum class AbortReason : uint8_t;
struct AssemblerOptions;
enum class BranchHint : uint8_t;
class TurbofanCompilationJob;

namespace compiler {
// Forward declarations for some compiler data structures.
class CallDescriptor;
class Graph;
class MachineGraph;
class Node;
class NodeOriginTable;
class Operator;
class SourcePositionTable;
struct WasmCompilationData;
class WasmDecorator;
class WasmGraphAssembler;
enum class TrapId : int32_t;
struct Int64LoweringSpecialCase;
template <size_t VarCount>
class GraphAssemblerLabel;
struct WasmTypeCheckConfig;
}  // namespace compiler

namespace wasm {
struct DecodeStruct;
class WasmCode;
class WireBytesStorage;
enum class LoadTransformationKind : uint8_t;
enum Suspend : int;
enum CallOrigin { kCalledFromWasm, kCalledFromJS };
}  // namespace wasm

namespace compiler {

wasm::WasmCompilationResult ExecuteTurbofanWasmCompilation(
    wasm::CompilationEnv*, WasmCompilationData& compilation_data, Counters*,
    wasm::WasmDetectedFeatures* detected);

// Compiles an import call wrapper, which allows Wasm to call imports.
V8_EXPORT_PRIVATE wasm::WasmCompilationResult CompileWasmImportCallWrapper(
    wasm::ImportCallKind, const wasm::CanonicalSig*, bool source_positions,
    int expected_arity, wasm::Suspend);

// Compiles a host call wrapper, which allows Wasm to call host functions.
wasm::WasmCompilationResult CompileWasmCapiCallWrapper(
    const wasm::CanonicalSig*);

bool IsFastCallSupportedSignature(const v8::CFunctionInfo*);
// Compiles a wrapper to call a Fast API function from Wasm.
wasm::WasmCompilationResult CompileWasmJSFastCallWrapper(
    const wasm::CanonicalSig*, Handle<JSReceiver> callable);

// Returns an TurbofanCompilationJob or TurboshaftCompilationJob object
// (depending on the --turboshaft-wasm-wrappers flag) for a JS to Wasm wrapper.
std::unique_ptr<OptimizedCompilationJob> NewJSToWasmCompilationJob(
    Isolate* isolate, const wasm::CanonicalSig* sig);

enum CWasmEntryParameters {
  kCodeEntry,
  kObjectRef,
  kArgumentsBuffer,
  kCEntryFp,
  // marker:
  kNumParameters
};

// Compiles a stub with C++ linkage, to be called from Execution::CallWasm,
// which knows how to feed it its parameters.
V8_EXPORT_PRIVATE Handle<Code> CompileCWasmEntry(Isolate*,
                                                 const wasm::CanonicalSig*);

// Values from the instance object are cached between Wasm-level function calls.
// This struct allows the SSA environment handling this cache to be defined
// and manipulated in wasm-compiler.{h,cc} instead of inside the Wasm decoder.
// (Note that currently, the globals base is immutable, so not cached here.)
struct WasmInstanceCacheNodes {
  // Cache the memory start and size of one fixed memory per function. Which one
  // is determined by {WasmGraphBuilder::cached_memory_index}.
  Node* mem_start = nullptr;
  Node* mem_size = nullptr;

  // For iteration support. Defined outside the class for MSVC compatibility.
  using FieldPtr = Node* WasmInstanceCacheNodes::*;
  static const FieldPtr kFields[2];
};
inline constexpr WasmInstanceCacheNodes::FieldPtr
    WasmInstanceCacheNodes::kFields[] = {&WasmInstanceCacheNodes::mem_start,
                                         &WasmInstanceCacheNodes::mem_size};

struct WasmLoopInfo {
  Node* header;
  uint32_t nesting_depth;
  // This loop has, to our best knowledge, no other loops nested within it. A
  // loop can obtain inner loops despite this after inlining.
  bool can_be_innermost;

  WasmLoopInfo(Node* header, uint32_t nesting_depth, bool can_be_innermost)
      : header(header),
        nesting_depth(nesting_depth),
        can_be_innermost(can_be_innermost) {}
};

struct WasmCompilationData {
  explicit WasmCompilationData(const wasm::FunctionBody& func_body)
      : func_body(func_body) {}

  size_t body_size() { return func_body.end - func_body.start; }

  const wasm::FunctionBody& func_body;
  const wasm::WireBytesStorage* wire_bytes_storage;
  NodeOriginTable* node_origins{nullptr};
  std::vector<WasmLoopInfo>* loop_infos{nullptr};
  wasm::AssumptionsJournal* assumptions{nullptr};
  SourcePositionTable* source_positions{nullptr};
  int func_index;
};

// Abstracts details of building TurboFan graph nodes for wasm to separate
// the wasm decoder from the internal details of TurboFan.
class WasmGraphBuilder {
 public:
  // ParameterMode specifies how the instance is passed.
  enum ParameterMode {
    // Normal wasm functions pass the instance as an implicit first parameter.
    kInstanceParameterMode,
    // For Wasm-to-JS and C-API wrappers, a {WasmImportData} object is
    // passed as first parameter.
    kWasmImportDataMode,
    // For JS-to-Wasm wrappers (which are JS functions), we load the Wasm
    // instance from the JS function data. The generated code objects live on
    // the JS heap, so those compilation pass an isolate.
    kJSFunctionAbiMode,
    // The JS-to-JS wrapper does not have an associated instance.
    // The C-entry stub uses a custom ABI (see {CWasmEntryParameters}).
    kNoSpecialParameterMode
  };

  V8_EXPORT_PRIVATE WasmGraphBuilder(
      wasm::CompilationEnv* env, Zone* zone, MachineGraph* mcgraph,
      const wasm::FunctionSig* sig, compiler::SourcePositionTable* spt,
      ParameterMode parameter_mode, Isolate* isolate,
      wasm::WasmEnabledFeatures enabled_features,
      const wasm::CanonicalSig* wrapper_sig = nullptr);

  V8_EXPORT_PRIVATE ~WasmGraphBuilder();

  bool TryWasmInlining(int fct_index, wasm::NativeModule* native_module,
                       int inlining_id);

  //-----------------------------------------------------------------------
  // Operations independent of {control} or {effect}.
  //-----------------------------------------------------------------------
  void Start(unsigned params);
  Node* Param(int index, const char* debug_name = nullptr);
  Node* Loop(Node* entry);
  void TerminateLoop(Node* effect, Node* control);
  Node* LoopExit(Node* loop_node);
  // Assumes current control() is the corresponding loop exit.
  Node* LoopExitValue(Node* value, MachineRepresentation representation);
  void TerminateThrow(Node* effect, Node* control);
  Node* Merge(unsigned count, Node** controls);
  template <typename... Nodes>
  Node* Merge(Node* fst, Nodes*... args);
  Node* Phi(wasm::ValueType type, unsigned count, Node** vals_and_control);
  Node* CreateOrMergeIntoPhi(MachineRepresentation rep, Node* merge,
                             Node* tnode, Node* fnode);
  Node* CreateOrMergeIntoEffectPhi(Node* merge, Node* tnode, Node* fnode);
  Node* EffectPhi(unsigned count, Node** effects_and_control);
  Node* RefNull(wasm::ValueType type);
  Node* RefFunc(uint32_t function_index);
  Node* AssertNotNull(
      Node* object, wasm::ValueType type, wasm::WasmCodePosition position,
      wasm::TrapReason reason = wasm::TrapReason::kTrapNullDereference);
  Node* TraceInstruction(uint32_t mark_id);
  Node* Int32Constant(int32_t value);
  Node* Int64Constant(int64_t value);
  Node* Float32Constant(float value);
  Node* Float64Constant(double value);
  Node* Simd128Constant(const uint8_t value[16]);
  Node* Binop(wasm::WasmOpcode opcode, Node* left, Node* right,
              wasm::WasmCodePosition position = wasm::kNoCodePosition);
  // The {type} argument is only required for null-checking operations.
  Node* Unop(wasm::WasmOpcode opcode, Node* input,
             wasm::ValueType type = wasm::kWasmBottom,
             wasm::WasmCodePosition position = wasm::kNoCodePosition);
  Node* MemoryGrow(const wasm::WasmMemory* memory, Node* input);
  Node* Throw(uint32_t tag_index, const wasm::WasmTag* tag,
              const base::Vector<Node*> values,
              wasm::WasmCodePosition position);
  Node* Rethrow(Node* except_obj);
  Node* ThrowRef(Node* except_obj);
  Node* IsExceptionTagUndefined(Node* tag);
  Node* LoadJSTag();
  Node* ExceptionTagEqual(Node* caught_tag, Node* expected_tag);
  Node* LoadTagFromTable(uint32_t tag_index);
  Node* GetExceptionTag(Node* except_obj);
  Node* GetExceptionValues(Node* except_obj, const wasm::WasmTag* tag,
                           base::Vector<Node*> values_out);
  bool IsPhiWithMerge(Node* phi, Node* merge);
  bool ThrowsException(Node* node, Node** if_success, Node** if_exception);
  void AppendToMerge(Node* merge, Node* from);
  void AppendToPhi(Node* phi, Node* from);

  void StackCheck(WasmInstanceCacheNodes* shared_memory_instance_cache,
                  wasm::WasmCodePosition);

  void PatchInStackCheckIfNeeded();

  //-----------------------------------------------------------------------
  // Operations that read and/or write {control} and {effect}.
  //-----------------------------------------------------------------------

  // Branch nodes return the true and false projection.
  std::tuple<Node*, Node*> BranchNoHint(Node* cond);
  std::tuple<Node*, Node*> BranchExpectFalse(Node* cond);
  std::tuple<Node*, Node*> BranchExpectTrue(Node* cond);

  void TrapIfTrue(wasm::TrapReason reason, Node* cond,
                  wasm::WasmCodePosition position);
  void TrapIfFalse(wasm::TrapReason reason, Node* cond,
                   wasm::WasmCodePosition position);
  Node* Select(Node *cond, Node* true_node, Node* false_node,
               wasm::ValueType type);

  void TrapIfEq32(wasm::TrapReason reason, Node* node, int32_t val,
                  wasm::WasmCodePosition position);
  void ZeroCheck32(wasm::TrapReason reason, Node* node,
                   wasm::WasmCodePosition position);
  void TrapIfEq64(wasm::TrapReason reason, Node* node, int64_t val,
                  wasm::WasmCodePosition position);
  void ZeroCheck64(wasm::TrapReason reason, Node* node,
                   wasm::WasmCodePosition position);

  Node* Switch(unsigned count, Node* key);
  Node* IfValue(int32_t value, Node* sw);
  Node* IfDefault(Node* sw);
  Node* Return(base::Vector<Node*> nodes);
  template <typename... Nodes>
  Node* Return(Node* fst, Nodes*... more) {
    Node* arr[] = {fst, more...};
    return Return(base::ArrayVector(arr));
  }

  void TraceFunctionEntry(wasm::WasmCodePosition position);
  void TraceFunctionExit(base::Vector<Node*> vals,
                         wasm::WasmCodePosition position);

  void Trap(wasm::TrapReason reason, wasm::WasmCodePosition position);

  // In all six call-related public functions, we pass a signature based on the
  // real arguments for this call. This signature gets stored in the Call node
  // and will later help us generate better code if this call gets inlined.
  Node* CallDirect(uint32_t index, base::Vector<Node*> args,
                   base::Vector<Node*> rets, wasm::WasmCodePosition position);
  Node* CallIndirect(uint32_t table_index, wasm::ModuleTypeIndex sig_index,
                     base::Vector<Node*> args, base::Vector<Node*> rets,
                     wasm::WasmCodePosition position);
  Node* CallRef(const wasm::FunctionSig* sig, base::Vector<Node*> args,
                base::Vector<Node*> rets, CheckForNull null_check,
                wasm::WasmCodePosition position);

  Node* ReturnCall(uint32_t index, base::Vector<Node*> args,
                   wasm::WasmCodePosition position);
  Node* ReturnCallIndirect(uint32_t table_index,
                           wasm::ModuleTypeIndex sig_index,
                           base::Vector<Node*> args,
                           wasm::WasmCodePosition position);
  Node* ReturnCallRef(const wasm::FunctionSig* sig, base::Vector<Node*> args,
                      CheckForNull null_check, wasm::WasmCodePosition position);

  void CompareToFuncRefAtIndex(Node* func_ref, uint32_t function_index,
                               Node** success_control, Node** failure_control,
                               bool is_last_case);

  // BrOnNull returns the control for the null and non-null case.
  std::tuple<Node*, Node*> BrOnNull(Node* ref_object, wasm::ValueType type);

  Node* Invert(Node* node);

  Node* GlobalGet(uint32_t index);
  void GlobalSet(uint32_t index, Node* val);
  Node* TableGet(uint32_t table_index, Node* index,
                 wasm::WasmCodePosition position);
  void TableSet(uint32_t table_index, Node* index, Node* val,
                wasm::WasmCodePosition position);
  //-----------------------------------------------------------------------
  // Operations that concern the linear memory.
  //-----------------------------------------------------------------------
  Node* CurrentMemoryPages(const wasm::WasmMemory* memory);
  void TraceMemoryOperation(bool is_store, MachineRepresentation, Node* index,
                            uintptr_t offset, wasm::WasmCodePosition);
  Node* LoadMem(const wasm::WasmMemory* memory, wasm::ValueType type,
                MachineType memtype, Node* index, uintptr_t offset,
                uint32_t alignment, wasm::WasmCodePosition position);
  Node* LoadTransform(const wasm::WasmMemory* memory, wasm::ValueType type,
                      MachineType memtype,
                      wasm::LoadTransformationKind transform, Node* index,
                      uintptr_t offset, uint32_t alignment,
                      wasm::WasmCodePosition position);
  Node* LoadLane(const wasm::WasmMemory* memory, wasm::ValueType type,
                 MachineType memtype, Node* value, Node* index,
                 uintptr_t offset, uint32_t alignment, uint8_t laneidx,
                 wasm::WasmCodePosition position);
  void StoreMem(const wasm::WasmMemory* memory, MachineRepresentation mem_rep,
                Node* index, uintptr_t offset, uint32_t alignment, Node* val,
                wasm::WasmCodePosition position, wasm::ValueType type);
  void StoreLane(const wasm::WasmMemory* memory, MachineRepresentation mem_rep,
                 Node* index, uintptr_t offset, uint32_t alignment, Node* val,
                 uint8_t laneidx, wasm::WasmCodePosition position,
                 wasm::ValueType type);
  static void PrintDebugName(Node* node);

  Node* effect();
  Node* control();
  Node* SetEffect(Node* node);
  Node* SetControl(Node* node);
  void SetEffectControl(Node* effect, Node* control);
  Node* SetEffectControl(Node* effect_and_control) {
    SetEffectControl(effect_and_control, effect_and_control);
    return effect_and_control;
  }

  Node* SetType(Node* node, wasm::ValueType type);

  // Utilities to manipulate sets of instance cache nodes.
  void InitInstanceCache(WasmInstanceCacheNodes* instance_cache);
  void PrepareInstanceCacheForLoop(WasmInstanceCacheNodes* instance_cache,
                                   Node* control);
  void NewInstanceCacheMerge(WasmInstanceCacheNodes* to,
                             WasmInstanceCacheNodes* from, Node* merge);
  void MergeInstanceCacheInto(WasmInstanceCacheNodes* to,
                              WasmInstanceCacheNodes* from, Node* merge);

  void set_instance_cache(WasmInstanceCacheNodes* instance_cache) {
    this->instance_cache_ = instance_cache;
  }

  // Overload for when we want to provide a specific signature, rather than
  // build one using sig_, for example after scalar lowering.
  V8_EXPORT_PRIVATE void LowerInt64(Signature<MachineRepresentation>* sig);
  V8_EXPORT_PRIVATE void LowerInt64(wasm::CallOrigin origin);

  void SetSourcePosition(Node* node, wasm::WasmCodePosition position);

  Node* S128Zero();
  Node* S1x4Zero();
  Node* S1x8Zero();
  Node* S1x16Zero();

  Node* SimdOp(wasm::WasmOpcode opcode, Node* const* inputs);

  Node* SimdLaneOp(wasm::WasmOpcode opcode, uint8_t lane, Node* const* inputs);

  Node* Simd8x16ShuffleOp(const uint8_t shuffle[16], Node* const* inputs);

  Node* AtomicOp(const wasm::WasmMemory* memory, wasm::WasmOpcode opcode,
                 Node* const* inputs, uint32_t alignment, uintptr_t offset,
                 wasm::WasmCodePosition position);
  void AtomicFence();

  void MemoryInit(const wasm::WasmMemory* memory, uint32_t data_segment_index,
                  Node* dst, Node* src, Node* size,
                  wasm::WasmCodePosition position);
  void MemoryCopy(const wasm::WasmMemory* dst_memory,
                  const wasm::WasmMemory* src_memory, Node* dst, Node* src,
                  Node* size, wasm::WasmCodePosition position);
  void DataDrop(uint32_t data_segment_index, wasm::WasmCodePosition position);
  void MemoryFill(const wasm::WasmMemory* memory, Node* dst, Node* fill,
                  Node* size, wasm::WasmCodePosition position);

  void TableInit(uint32_t table_index, uint32_t elem_segment_index, Node* dst,
                 Node* src, Node* size, wasm::WasmCodePosition position);
  void ElemDrop(uint32_t elem_segment_index, wasm::WasmCodePosition position);
  void TableCopy(uint32_t table_dst_index, uint32_t table_src_index, Node* dst,
                 Node* src, Node* size, wasm::WasmCodePosition position);
  Node* TableGrow(uint32_t table_index, Node* value, Node* delta,
                  wasm::WasmCodePosition position);
  Node* TableSize(uint32_t table_index);
  void TableFill(uint32_t table_index, Node* start, Node* value, Node* count,
                 wasm::WasmCodePosition position);

  Node* StructNew(wasm::ModuleTypeIndex struct_index,
                  const wasm::StructType* type, Node* rtt,
                  base::Vector<Node*> fields);
  Node* StructGet(Node* struct_object, const wasm::StructType* struct_type,
                  uint32_t field_index, CheckForNull null_check, bool is_signed,
                  wasm::WasmCodePosition position);
  void StructSet(Node* struct_object, const wasm::StructType* struct_type,
                 uint32_t field_index, Node* value, CheckForNull null_check,
                 wasm::WasmCodePosition position);
  Node* ArrayNew(wasm::ModuleTypeIndex array_index, const wasm::ArrayType* type,
                 Node* length, Node* initial_value, Node* rtt,
                 wasm::WasmCodePosition position);
  Node* ArrayGet(Node* array_object, const wasm::ArrayType* type, Node* index,
                 CheckForNull null_check, bool is_signed,
                 wasm::WasmCodePosition position);
  void ArraySet(Node* array_object, const wasm::ArrayType* type, Node* index,
                Node* value, CheckForNull null_check,
                wasm::WasmCodePosition position);
  Node* ArrayLen(Node* array_object, CheckForNull null_check,
                 wasm::WasmCodePosition position);
  void ArrayCopy(Node* dst_array, Node* dst_index, CheckForNull dst_null_check,
                 Node* src_array, Node* src_index, CheckForNull src_null_check,
                 Node* length, const wasm::ArrayType* type,
                 wasm::WasmCodePosition position);
  void ArrayFill(Node* array, Node* index, Node* value, Node* length,
                 const wasm::ArrayType* type, CheckForNull null_check,
                 wasm::WasmCodePosition position);
  Node* ArrayNewFixed(const wasm::ArrayType* type, Node* rtt,
                      base::Vector<Node*> elements);
  Node* ArrayNewSegment(uint32_t segment_index, Node* offset, Node* length,
                        Node* rtt, bool is_element,
                        wasm::WasmCodePosition position);
  void ArrayInitSegment(uint32_t segment_index, Node* array, Node* array_index,
                        Node* segment_offset, Node* length, bool is_element,
                        wasm::WasmCodePosition position);
  Node* RefI31(Node* input);
  Node* I31GetS(Node* input, CheckForNull null_check,
                wasm::WasmCodePosition position);
  Node* I31GetU(Node* input, CheckForNull null_check,
                wasm::WasmCodePosition position);
  Node* RttCanon(wasm::ModuleTypeIndex type_index);

  Node* RefTest(Node* object, Node* rtt, WasmTypeCheckConfig config);
  Node* RefTestAbstract(Node* object, WasmTypeCheckConfig config);
  Node* RefCast(Node* object, Node* rtt, WasmTypeCheckConfig config,
                wasm::WasmCodePosition position);
  Node* RefCastAbstract(Node* object, WasmTypeCheckConfig config,
                        wasm::WasmCodePosition position);
  struct ResultNodesOfBr {
    Node* control_on_match;
    Node* effect_on_match;
    Node* control_on_no_match;
    Node* effect_on_no_match;
  };
  ResultNodesOfBr BrOnCast(Node* object, Node* rtt, WasmTypeCheckConfig config);
  ResultNodesOfBr BrOnEq(Node* object, Node* rtt, WasmTypeCheckConfig config);
  ResultNodesOfBr BrOnStruct(Node* object, Node* rtt,
                             WasmTypeCheckConfig config);
  ResultNodesOfBr BrOnArray(Node* object, Node* rtt,
                            WasmTypeCheckConfig config);
  ResultNodesOfBr BrOnI31(Node* object, Node* rtt, WasmTypeCheckConfig config);
  ResultNodesOfBr BrOnString(Node* object, Node* rtt,
                             WasmTypeCheckConfig config);

  Node* StringNewWtf8(const wasm::WasmMemory* memory,
                      unibrow::Utf8Variant variant, Node* offset, Node* size,
                      wasm::WasmCodePosition position);
  Node* StringNewWtf8Array(unibrow::Utf8Variant variant, Node* array,
                           CheckForNull null_check, Node* start, Node* end,
                           wasm::WasmCodePosition position);
  Node* StringNewWtf16(const wasm::WasmMemory* memory, Node* offset, Node* size,
                       wasm::WasmCodePosition position);
  Node* StringNewWtf16Array(Node* array, CheckForNull null_check, Node* start,
                            Node* end, wasm::WasmCodePosition position);
  Node* StringAsWtf16(Node* string, CheckForNull null_check,
                      wasm::WasmCodePosition position);
  Node* StringConst(uint32_t index);
  Node* StringMeasureUtf8(Node* string, CheckForNull null_check,
                          wasm::WasmCodePosition position);
  Node* StringMeasureWtf8(Node* string, CheckForNull null_check,
                          wasm::WasmCodePosition position);
  Node* StringMeasureWtf16(Node* string, CheckForNull null_check,
                           wasm::WasmCodePosition position);
  Node* StringEncodeWtf8(const wasm::WasmMemory* memory,
                         unibrow::Utf8Variant variant, Node* string,
                         CheckForNull null_check, Node* offset,
                         wasm::WasmCodePosition position);
  Node* StringEncodeWtf8Array(unibrow::Utf8Variant variant, Node* string,
                              CheckForNull string_null_check, Node* array,
                              CheckForNull array_null_check, Node* start,
                              wasm::WasmCodePosition position);
  Node* StringToUtf8Array(Node* string, CheckForNull null_check,
                          wasm::WasmCodePosition position);
  Node* StringEncodeWtf16(const wasm::WasmMemory* memory, Node* string,
                          CheckForNull null_check, Node* offset,
                          wasm::WasmCodePosition position);
  Node* StringEncodeWtf16Array(Node* string, CheckForNull string_null_check,
                               Node* array, CheckForNull array_null_check,
                               Node* start, wasm::WasmCodePosition position);
  Node* StringConcat(Node* head, CheckForNull head_null_check, Node* tail,
                     CheckForNull tail_null_check,
                     wasm::WasmCodePosition position);
  Node* StringEqual(Node* a, wasm::ValueType a_type, Node* b,
                    wasm::ValueType b_type, wasm::WasmCodePosition position);
  Node* StringIsUSVSequence(Node* str, CheckForNull null_check,
                            wasm::WasmCodePosition position);
  Node* StringAsWtf8(Node* str, CheckForNull null_check,
                     wasm::WasmCodePosition position);
  Node* StringViewWtf8Advance(Node* view, CheckForNull null_check, Node* pos,
                              Node* bytes, wasm::WasmCodePosition position);
  void StringViewWtf8Encode(const wasm::WasmMemory* memory,
                            unibrow::Utf8Variant variant, Node* view,
                            CheckForNull null_check, Node* addr, Node* pos,
                            Node* bytes, Node** next_pos, Node** bytes_written,
                            wasm::WasmCodePosition position);
  Node* StringViewWtf8Slice(Node* view, CheckForNull null_check, Node* pos,
                            Node* bytes, wasm::WasmCodePosition position);
  Node* StringViewWtf16GetCodeUnit(Node* string, CheckForNull null_check,
                                   Node* offset,
                                   wasm::WasmCodePosition position);
  Node* StringCodePointAt(Node* string, CheckForNull null_check, Node* offset,
                          wasm::WasmCodePosition position);
  Node* StringViewWtf16Encode(const wasm::WasmMemory* memory, Node* string,
                              CheckForNull null_check, Node* offset,
                              Node* start, Node* length,
                              wasm::WasmCodePosition position);
  Node* StringViewWtf16Slice(Node* string, CheckForNull null_check, Node* start,
                             Node* end, wasm::WasmCodePosition position);
  Node* StringAsIter(Node* str, CheckForNull null_check,
                     wasm::WasmCodePosition position);
  Node* StringViewIterNext(Node* view, CheckForNull null_check,
                           wasm::WasmCodePosition position);
  Node* StringViewIterAdvance(Node* view, CheckForNull null_check,
                              Node* codepoints,
                              wasm::WasmCodePosition position);
  Node* StringViewIterRewind(Node* view, CheckForNull null_check,
                             Node* codepoints, wasm::WasmCodePosition position);
  Node* StringViewIterSlice(Node* view, CheckForNull null_check,
                            Node* codepoints, wasm::WasmCodePosition position);
  Node* StringCompare(Node* lhs, CheckForNull null_check_lhs, Node* rhs,
                      CheckForNull null_check_rhs,
                      wasm::WasmCodePosition position);
  Node* StringFromCharCode(Node* char_code);
  Node* StringFromCodePoint(Node* code_point);
  Node* StringHash(Node* string, CheckForNull null_check,
                   wasm::WasmCodePosition position);
  Node* IsNull(Node* object, wasm::ValueType type);
  Node* TypeGuard(Node* value, wasm::ValueType type);

  // Support for well-known imports.
  // See {CheckWellKnownImport} for signature and builtin ID definitions.
  Node* WellKnown_StringIndexOf(Node* string, Node* search, Node* start,
                                CheckForNull string_null_check,
                                CheckForNull search_null_check);
  Node* WellKnown_StringToLocaleLowerCaseStringref(
      int func_index, Node* string, Node* locale,
      CheckForNull string_null_check);
  Node* WellKnown_StringToLowerCaseStringref(Node* string,
                                             CheckForNull null_check);
  Node* WellKnown_ParseFloat(Node* string, CheckForNull null_check);
  Node* WellKnown_DoubleToString(Node* n);
  Node* WellKnown_IntToString(Node* n, Node* radix);

  bool has_simd() const { return has_simd_; }

  Node* DefaultValue(wasm::ValueType type);

  MachineGraph* mcgraph() { return mcgraph_; }
  Graph* graph();
  Zone* graph_zone();

  void AddBytecodePositionDecorator(NodeOriginTable* node_origins,
                                    wasm::Decoder* decoder);

  void RemoveBytecodePositionDecorator();

  void StoreCallCount(Node* call, int count);
  void ReserveCallCounts(size_t num_call_instructions);

  void set_inlining_id(int inlining_id) {
    DCHECK_NE(inlining_id, -1);
    inlining_id_ = inlining_id;
  }

  bool has_cached_memory() const {
    return cached_memory_index_ != kNoCachedMemoryIndex;
  }
  int cached_memory_index() const {
    DCHECK(has_cached_memory());
    return cached_memory_index_;
  }
  void set_cached_memory_index(int cached_memory_index) {
    DCHECK_LE(0, cached_memory_index);
    DCHECK(!has_cached_memory());
    cached_memory_index_ = cached_memory_index;
  }

 protected:
  Node* NoContextConstant();

  Node* GetInstanceData();
  Node* BuildLoadIsolateRoot();
  Node* UndefinedValue();

  // Get a memory start or size, using the cached SSA value if available.
  Node* MemStart(uint32_t mem_index);
  Node* MemSize(uint32_t mem_index);

  // Load a memory start or size (without using the cache).
  Node* LoadMemStart(uint32_t mem_index);
  Node* LoadMemSize(uint32_t mem_index);

  // MemBuffer is only called with valid offsets (after bounds checking), so the
  // offset fits in a platform-dependent uintptr_t.
  Node* MemBuffer(uint32_t mem_index, uintptr_t offset);

  // BoundsCheckMem receives a 32/64-bit index (depending on
  // {memory->is_memory64}) and returns a ptrsize index and information about
  // the kind of bounds check performed (or why none was needed).
  std::pair<Node*, BoundsCheckResult> BoundsCheckMem(
      const wasm::WasmMemory* memory, uint8_t access_size, Node* index,
      uintptr_t offset, wasm::WasmCodePosition, EnforceBoundsCheck,
      AlignmentCheck alignment_check);

  std::pair<Node*, BoundsCheckResult> CheckBoundsAndAlignment(
      const wasm::WasmMemory* memory, int8_t access_size, Node* index,
      uintptr_t offset, wasm::WasmCodePosition, EnforceBoundsCheck);

  const Operator* GetSafeLoadOperator(int offset, wasm::ValueTypeBase type);
  const Operator* GetSafeStoreOperator(int offset, wasm::ValueTypeBase type);
  Node* BuildChangeEndiannessStore(Node* node, MachineRepresentation rep,
                                   wasm::ValueType wasmtype = wasm::kWasmVoid);
  Node* BuildChangeEndiannessLoad(Node* node, MachineType type,
                                  wasm::ValueType wasmtype = wasm::kWasmVoid);

  Node* MaskShiftCount32(Node* node);
  Node* MaskShiftCount64(Node* node);

  enum IsReturnCall : bool { kReturnCall = true, kCallContinues = false };

  template <typename... Args>
  Node* BuildCCall(MachineSignature* sig, Node* function, Args... args);
  Node* BuildCallNode(size_t param_count, base::Vector<Node*> args,
                      wasm::WasmCodePosition position, Node* instance_node,
                      const Operator* op, Node* frame_state = nullptr);
  // Helper function for {BuildIndirectCall}.
  void LoadIndirectFunctionTable(uint32_t table_index, Node** ift_size,
                                 Node** ift_sig_ids, Node** ift_targets,
                                 Node** ift_instances);
  Node* BuildIndirectCall(uint32_t table_index, wasm::ModuleTypeIndex sig_index,
                          base::Vector<Node*> args, base::Vector<Node*> rets,
                          wasm::WasmCodePosition position,
                          IsReturnCall continuation);
  template <typename T>
  Node* BuildWasmCall(const Signature<T>* sig, base::Vector<Node*> args,
                      base::Vector<Node*> rets, wasm::WasmCodePosition position,
                      Node* implicit_first_arg, Node* frame_state = nullptr);
  Node* BuildWasmReturnCall(const wasm::FunctionSig* sig,
                            base::Vector<Node*> args,
                            wasm::WasmCodePosition position,
                            Node* implicit_first_arg);
  Node* BuildImportCall(const wasm::FunctionSig* sig, base::Vector<Node*> args,
                        base::Vector<Node*> rets,
                        wasm::WasmCodePosition position, int func_index,
                        IsReturnCall continuation);
  Node* BuildImportCall(const wasm::FunctionSig* sig, base::Vector<Node*> args,
                        base::Vector<Node*> rets,
                        wasm::WasmCodePosition position, Node* func_index,
                        IsReturnCall continuation, Node* frame_state = nullptr);
  Node* BuildCallRef(const wasm::FunctionSig* sig, base::Vector<Node*> args,
                     base::Vector<Node*> rets, Che
"""


```