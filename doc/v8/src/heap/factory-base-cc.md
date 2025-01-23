Response:
The user wants to understand the functionality of the provided C++ code snippet, which is a part of the V8 JavaScript engine source code.

Here's a breakdown of the thinking process to address the user's request:

1. **Identify the core component:** The code is located in `v8/src/heap/factory-base.cc` and defines a template class `FactoryBase`. The name suggests it's related to object creation within the V8 heap.

2. **Analyze the template parameter:** The `template <typename Impl>` indicates that `FactoryBase` is a base class intended to be used with different implementations. This suggests a pattern like the Strategy pattern where the specific allocation and initialization logic might vary.

3. **Examine included headers:** The `#include` directives provide crucial context. They point to various parts of the V8 codebase related to:
    * Abstract Syntax Tree (`src/ast/*`)
    * Assertions and Globals (`src/common/*`)
    * Execution Context (`src/execution/*`)
    * Handles (`src/handles/*`)
    * Heap management (`src/heap/*`)
    * Logging (`src/logging/*`)
    * JavaScript objects (`src/objects/*`)
    * Roots (pre-allocated, fundamental objects) (`src/roots/*`)

4. **Focus on the methods:** The core functionality lies within the template methods of `FactoryBase`. Each method seems responsible for creating and initializing a specific type of V8 object. Examples include:
    * `NewHeapNumber`: Creates a `HeapNumber` object.
    * `NewStruct`: Creates a generic `Struct`.
    * `NewCode`: Creates a `Code` object (representing compiled JavaScript).
    * `NewFixedArray`: Creates a `FixedArray` (a dynamically sized array in V8).
    * `NewString`: Creates various string types.
    * `NewSharedFunctionInfo`: Creates metadata about JavaScript functions.

5. **Look for patterns in object creation:**  Notice the common steps in object creation methods:
    * Get the appropriate `Map` (metadata describing the object's structure).
    * Allocate raw memory for the object.
    * Initialize the object's fields.
    * Return a `Handle` to the newly created object.

6. **Consider the `.tq` extension:** The prompt mentions `.tq`. This refers to Torque, V8's domain-specific language for low-level builtins. The code *is* C++, not Torque, so this part of the prompt needs to be addressed.

7. **Connect to JavaScript:**  The object types being created directly correspond to JavaScript concepts (numbers, functions, arrays, strings). This is the crucial link to demonstrate with JavaScript examples.

8. **Think about potential errors:**  Since this code deals with memory allocation and object initialization, potential errors relate to incorrect sizes, types, or memory management. Examples like exceeding array limits or type mismatches are relevant.

9. **Address the "code logic reasoning" part:** While the code *is* logic, the request seems to ask for a specific example with inputs and outputs. A simple case, like creating a `HeapNumber`, can illustrate this.

10. **Structure the response:** Organize the findings into logical sections as requested by the prompt:
    * Overall Functionality
    * Torque Clarification
    * Relationship to JavaScript (with examples)
    * Code Logic Reasoning (with example)
    * Common Programming Errors (with examples)
    * Summary of Functionality (for part 1)

11. **Refine and elaborate:**  Add details and explanations to make the response clear and comprehensive. For example, explain what `Handles` are, the role of `Maps`, and the different allocation types. Explain the concept of internalization for strings.

**(Self-Correction during the process):**

* Initially, I might have focused too much on the individual methods without recognizing the overarching pattern of object creation. Stepping back and seeing the common steps is important.
* The `.tq` mention is a potential point of confusion. It's crucial to clarify that this particular file is C++, even though the `FactoryBase` might be used by Torque-generated code.
* Ensuring the JavaScript examples are clear and directly relate to the C++ code is vital. Vague examples wouldn't be helpful.
* For the code logic example, choosing a simple case like `NewHeapNumber` is better than trying to explain a more complex object creation.
```cpp
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/heap/factory-base.h"

#include "src/ast/ast-source-ranges.h"
#include "src/ast/ast.h"
#include "src/common/assert-scope.h"
#include "src/common/globals.h"
#include "src/execution/local-isolate.h"
#include "src/handles/handles-inl.h"
#include "src/heap/factory.h"
#include "src/heap/heap-inl.h"
#include "src/heap/large-page-metadata-inl.h"
#include "src/heap/local-factory-inl.h"
#include "src/heap/mutable-page-metadata.h"
#include "src/heap/read-only-heap.h"
#include "src/logging/local-logger.h"
#include "src/logging/log.h"
#include "src/objects/arguments-inl.h"
#include "src/objects/instance-type.h"
#include "src/objects/js-regexp-inl.h"
#include "src/objects/literal-objects-inl.h"
#include "src/objects/module-inl.h"
#include "src/objects/oddball.h"
#include "src/objects/shared-function-info-inl.h"
#include "src/objects/shared-function-info.h"
#include "src/objects/source-text-module.h"
#include "src/objects/string-inl.h"
#include "src/objects/string.h"
#include "src/objects/swiss-name-dictionary-inl.h"
#include "src/objects/template-objects-inl.h"
#include "src/roots/roots.h"

namespace v8 {
namespace internal {

template <typename Impl>
template <AllocationType allocation>
Handle<HeapNumber> FactoryBase<Impl>::NewHeapNumber() {
  static_assert(sizeof(HeapNumber) <= kMaxRegularHeapObjectSize);
  Tagged<Map> map = read_only_roots().heap_number_map();
  Tagged<HeapObject> result = AllocateRawWithImmortalMap(
      sizeof(HeapNumber), allocation, map, kDoubleUnaligned);
  return handle(Cast<HeapNumber>(result), isolate());
}

template V8_EXPORT_PRIVATE Handle<HeapNumber>
FactoryBase<Factory>::NewHeapNumber<AllocationType::kYoung>();
template V8_EXPORT_PRIVATE Handle<HeapNumber>
FactoryBase<Factory>::NewHeapNumber<AllocationType::kOld>();
template V8_EXPORT_PRIVATE Handle<HeapNumber>
FactoryBase<Factory>::NewHeapNumber<AllocationType::kReadOnly>();
template V8_EXPORT_PRIVATE Handle<HeapNumber>
FactoryBase<Factory>::NewHeapNumber<AllocationType::kSharedOld>();

template V8_EXPORT_PRIVATE Handle<HeapNumber>
FactoryBase<LocalFactory>::NewHeapNumber<AllocationType::kOld>();

template <typename Impl>
Handle<Struct> FactoryBase<Impl>::NewStruct(InstanceType type,
                                            AllocationType allocation) {
  ReadOnlyRoots roots = read_only_roots();
  Tagged<Map> map = Map::GetMapFor(roots, type);
  int size = map->instance_size();
  return handle(NewStructInternal(roots, map, size, allocation), isolate());
}

template <typename Impl>
Handle<AccessorPair> FactoryBase<Impl>::NewAccessorPair() {
  auto accessors =
      NewStructInternal<AccessorPair>(ACCESSOR_PAIR_TYPE, AllocationType::kOld);
  DisallowGarbageCollection no_gc;
  accessors->set_getter(read_only_roots().null_value(), SKIP_WRITE_BARRIER);
  accessors->set_setter(read_only_roots().null_value(), SKIP_WRITE_BARRIER);
  return handle(accessors, isolate());
}

template <typename Impl>
Handle<Code> FactoryBase<Impl>::NewCode(const NewCodeOptions& options) {
  DirectHandle<CodeWrapper> wrapper = NewCodeWrapper();
  Tagged<Map> map = read_only_roots().code_map();
  int size = map->instance_size();
  Tagged<Code> code = Cast<Code>(
      AllocateRawWithImmortalMap(size, AllocationType::kTrusted, map));
  DisallowGarbageCollection no_gc;
  code->init_self_indirect_pointer(isolate());
  code->initialize_flags(options.kind, options.is_context_specialized,
                         options.is_turbofanned);
  code->set_builtin_id(options.builtin);
  code->set_instruction_size(options.instruction_size);
  code->set_metadata_size(options.metadata_size);
  code->set_inlined_bytecode_size(options.inlined_bytecode_size);
  code->set_osr_offset(options.osr_offset);
  code->set_handler_table_offset(options.handler_table_offset);
  code->set_constant_pool_offset(options.constant_pool_offset);
  code->set_code_comments_offset(options.code_comments_offset);
  code->set_builtin_jump_table_info_offset(
      options.builtin_jump_table_info_offset);
  code->set_unwinding_info_offset(options.unwinding_info_offset);
  code->set_parameter_count(options.parameter_count);

  // Set bytecode/interpreter data or deoptimization data.
  if (CodeKindUsesBytecodeOrInterpreterData(options.kind)) {
    DCHECK(options.deoptimization_data.is_null());
    Tagged<TrustedObject> data =
        *options.bytecode_or_interpreter_data.ToHandleChecked();
    DCHECK(IsBytecodeArray(data) || IsInterpreterData(data));
    code->set_bytecode_or_interpreter_data(data);
  } else if (CodeKindUsesDeoptimizationData(options.kind)) {
    DCHECK(options.bytecode_or_interpreter_data.is_null());
    code->set_deoptimization_data(
        *options.deoptimization_data.ToHandleChecked());
  } else {
    DCHECK(options.deoptimization_data.is_null());
    DCHECK(options.bytecode_or_interpreter_data.is_null());
    code->clear_deoptimization_data_and_interpreter_data();
  }

  // Set bytecode offset table or source position table.
  if (CodeKindUsesBytecodeOffsetTable(options.kind)) {
    DCHECK(options.source_position_table.is_null());
    code->set_bytecode_offset_table(
        *options.bytecode_offset_table.ToHandleChecked());
  } else if (CodeKindMayLackSourcePositionTable(options.kind)) {
    DCHECK(options.bytecode_offset_table.is_null());
    Handle<TrustedByteArray> table;
    if (options.source_position_table.ToHandle(&table)) {
      code->set_source_position_table(*table);
    } else {
      code->clear_source_position_table_and_bytecode_offset_table();
    }
  } else {
    DCHECK(options.bytecode_offset_table.is_null());
    code->set_source_position_table(
        *options.source_position_table.ToHandleChecked());
  }

  // Set instruction stream and entrypoint.
  Handle<InstructionStream> istream;
  if (options.instruction_stream.ToHandle(&istream)) {
    DCHECK_EQ(options.instruction_start, kNullAddress);
    code->SetInstructionStreamAndInstructionStart(isolate(), *istream);
  } else {
    DCHECK_NE(options.instruction_start, kNullAddress);
    code->set_raw_instruction_stream(Smi::zero(), SKIP_WRITE_BARRIER);
    code->SetInstructionStartForOffHeapBuiltin(isolate(),
                                               options.instruction_start);
  }

  wrapper->set_code(code);
  code->set_wrapper(*wrapper);

  code->clear_padding();
  return handle(code, isolate());
}

template <typename Impl>
Handle<CodeWrapper> FactoryBase<Impl>::NewCodeWrapper() {
  Handle<CodeWrapper> wrapper(
      Cast<CodeWrapper>(NewWithImmortalMap(read_only_roots().code_wrapper_map(),
                                           AllocationType::kOld)),
      isolate());
  // The CodeWrapper is typically created before the Code object it wraps, so
  // the code field cannot yet be set. However, as a heap verifier might see
  // the wrapper before the field can be set, we need to clear the field here.
  wrapper->clear_code();
  return wrapper;
}

template <typename Impl>
Handle<FixedArray> FactoryBase<Impl>::NewFixedArray(int length,
                                                    AllocationType allocation) {
  return FixedArray::New(isolate(), length, allocation);
}

template <typename Impl>
Handle<TrustedFixedArray> FactoryBase<Impl>::NewTrustedFixedArray(
    int length, AllocationType allocation) {
  DCHECK(allocation == AllocationType::kTrusted ||
         allocation == AllocationType::kSharedTrusted);

  // TODO(saelo): Move this check to TrustedFixedArray::New once we have a RO
  // trusted space.
  if (length == 0) return empty_trusted_fixed_array();
  return TrustedFixedArray::New(isolate(), length, allocation);
}

template <typename Impl>
Handle<ProtectedFixedArray> FactoryBase<Impl>::NewProtectedFixedArray(
    int length) {
  if (length == 0) return empty_protected_fixed_array();
  return ProtectedFixedArray::New(isolate(), length);
}

template <typename Impl>
Handle<FixedArray> FactoryBase<Impl>::NewFixedArrayWithMap(
    DirectHandle<Map> map, int length, AllocationType allocation) {
  // Zero-length case must be handled outside, where the knowledge about
  // the map is.
  DCHECK_LT(0, length);
  return NewFixedArrayWithFiller(
      map, length, read_only_roots().undefined_value_handle(), allocation);
}

template <typename Impl>
Handle<FixedArray> FactoryBase<Impl>::NewFixedArrayWithHoles(
    int length, AllocationType allocation) {
  DCHECK_LE(0, length);
  if (length == 0) return impl()->empty_fixed_array();
  return NewFixedArrayWithFiller(
      read_only_roots().fixed_array_map_handle(), length,
      read_only_roots().the_hole_value_handle(), allocation);
}

template <typename Impl>
Handle<FixedArray> FactoryBase<Impl>::NewFixedArrayWithFiller(
    DirectHandle<Map> map, int length, DirectHandle<HeapObject> filler,
    AllocationType allocation) {
  Tagged<HeapObject> result = AllocateRawFixedArray(length, allocation);
  DisallowGarbageCollection no_gc;
  DCHECK(ReadOnlyHeap::Contains(*map));
  DCHECK(ReadOnlyHeap::Contains(*filler));
  result->set_map_after_allocation(isolate(), *map, SKIP_WRITE_BARRIER);
  Tagged<FixedArray> array = Cast<FixedArray>(result);
  array->set_length(length);
  MemsetTagged(array->RawFieldOfFirstElement(), *filler, length);
  return handle(array, isolate());
}

template <typename Impl>
Handle<FixedArray> FactoryBase<Impl>::NewFixedArrayWithZeroes(
    int length, AllocationType allocation) {
  DCHECK_LE(0, length);
  if (length == 0) return impl()->empty_fixed_array();
  if (length > FixedArray::kMaxLength) {
    FATAL("Invalid FixedArray size %d", length);
  }
  Tagged<HeapObject> result = AllocateRawFixedArray(length, allocation);
  DisallowGarbageCollection no_gc;
  result->set_map_after_allocation(
      isolate(), read_only_roots().fixed_array_map(), SKIP_WRITE_BARRIER);
  Tagged<FixedArray> array = Cast<FixedArray>(result);
  array->set_length(length);
  MemsetTagged(array->RawFieldOfFirstElement(), Smi::zero(), length);
  return handle(array, isolate());
}

template <typename Impl>
Handle<FixedArrayBase> FactoryBase<Impl>::NewFixedDoubleArray(
    int length, AllocationType allocation) {
  return FixedDoubleArray::New(isolate(), length, allocation);
}

template <typename Impl>
Handle<WeakFixedArray> FactoryBase<Impl>::NewWeakFixedArrayWithMap(
    Tagged<Map> map, int length, AllocationType allocation) {
  // Zero-length case must be handled outside.
  DCHECK_LT(0, length);
  DCHECK(ReadOnlyHeap::Contains(map));

  Tagged<HeapObject> result =
      AllocateRawArray(WeakFixedArray::SizeFor(length), allocation);
  result->set_map_after_allocation(isolate(), map, SKIP_WRITE_BARRIER);
  DisallowGarbageCollection no_gc;
  Tagged<WeakFixedArray> array = Cast<WeakFixedArray>(result);
  array->set_length(length);
  MemsetTagged(ObjectSlot(array->RawFieldOfFirstElement()),
               read_only_roots().undefined_value(), length);

  return handle(array, isolate());
}

template <typename Impl>
Handle<WeakFixedArray> FactoryBase<Impl>::NewWeakFixedArray(
    int length, AllocationType allocation) {
  return WeakFixedArray::New(isolate(), length, allocation);
}

template <typename Impl>
Handle<TrustedWeakFixedArray> FactoryBase<Impl>::NewTrustedWeakFixedArray(
    int length) {
  // TODO(saelo): Move this check to TrustedWeakFixedArray::New once we have a
  // RO trusted space.
  if (length == 0) return empty_trusted_weak_fixed_array();
  return TrustedWeakFixedArray::New(isolate(), length);
}

template <typename Impl>
Handle<ByteArray> FactoryBase<Impl>::NewByteArray(int length,
                                                  AllocationType allocation) {
  return ByteArray::New(isolate(), length, allocation);
}

template <typename Impl>
Handle<TrustedByteArray> FactoryBase<Impl>::NewTrustedByteArray(
    int length, AllocationType allocation_type) {
  if (length == 0) return empty_trusted_byte_array();
  return TrustedByteArray::New(isolate(), length, allocation_type);
}

template <typename Impl>
Handle<DeoptimizationLiteralArray>
FactoryBase<Impl>::NewDeoptimizationLiteralArray(int length) {
  return Cast<DeoptimizationLiteralArray>(NewTrustedWeakFixedArray(length));
}

template <typename Impl>
Handle<DeoptimizationFrameTranslation>
FactoryBase<Impl>::NewDeoptimizationFrameTranslation(int length) {
  return Cast<DeoptimizationFrameTranslation>(NewTrustedByteArray(length));
}

template <typename Impl>
Handle<BytecodeArray> FactoryBase<Impl>::NewBytecodeArray(
    int length, const uint8_t* raw_bytecodes, int frame_size,
    uint16_t parameter_count, uint16_t max_arguments,
    DirectHandle<TrustedFixedArray> constant_pool,
    DirectHandle<TrustedByteArray> handler_table, AllocationType allocation) {
  DCHECK(allocation == AllocationType::kTrusted ||
         allocation == AllocationType::kSharedTrusted);
  if (length < 0 || length > BytecodeArray::kMaxLength) {
    FATAL("Fatal JavaScript invalid size error %d", length);
    UNREACHABLE();
  }
  DirectHandle<BytecodeWrapper> wrapper = NewBytecodeWrapper();
  int size = BytecodeArray::SizeFor(length);
  Tagged<HeapObject> result = AllocateRawWithImmortalMap(
      size, allocation, read_only_roots().bytecode_array_map());
  DisallowGarbageCollection no_gc;
  Tagged<BytecodeArray> instance = Cast<BytecodeArray>(result);
  instance->init_self_indirect_pointer(isolate());
  instance->set_length(length);
  instance->set_frame_size(frame_size);
  instance->set_parameter_count(parameter_count);
  instance->set_max_arguments(max_arguments);
  instance->set_incoming_new_target_or_generator_register(
      interpreter::Register::invalid_value());
  instance->set_constant_pool(*constant_pool);
  instance->set_handler_table(*handler_table);
  instance->clear_source_position_table(kReleaseStore);
  instance->set_wrapper(*wrapper);
  CopyBytes(reinterpret_cast<uint8_t*>(instance->GetFirstBytecodeAddress()),
            raw_bytecodes, length);
  instance->clear_padding();
  wrapper->set_bytecode(instance);
  return handle(instance, isolate());
}

template <typename Impl>
Handle<BytecodeWrapper> FactoryBase<Impl>::NewBytecodeWrapper(
    AllocationType allocation) {
  DCHECK(allocation == AllocationType::kOld ||
         allocation == AllocationType::kSharedOld);

  Handle<BytecodeWrapper> wrapper(
      Cast<BytecodeWrapper>(NewWithImmortalMap(
          read_only_roots().bytecode_wrapper_map(), allocation)),
      isolate());
  // The BytecodeWrapper is typically created before the BytecodeArray it
  // wraps, so the bytecode field cannot yet be set. However, as a heap
  // verifier might see the wrapper before the field can be set, we need to
  // clear the field here.
  wrapper->clear_bytecode();
  return wrapper;
}

template <typename Impl>
Handle<Script> FactoryBase<Impl>::NewScript(
    DirectHandle<UnionOf<String, Undefined>> source,
    ScriptEventType script_event_type) {
  return NewScriptWithId(source, isolate()->GetNextScriptId(),
                         script_event_type);
}

template <typename Impl>
Handle<Script> FactoryBase<Impl>::NewScriptWithId(
    DirectHandle<UnionOf<String, Undefined>> source, int script_id,
    ScriptEventType script_event_type) {
  DCHECK(IsString(*source) || IsUndefined(*source));
  // Create and initialize script object.
  ReadOnlyRoots roots = read_only_roots();
  Handle<Script> script = handle(
      NewStructInternal<Script>(SCRIPT_TYPE, AllocationType::kOld), isolate());
  {
    DisallowGarbageCollection no_gc;
    Tagged<Script> raw = *script;
    raw->set_source(*source);
    raw->set_name(roots.undefined_value(), SKIP_WRITE_BARRIER);
    raw->set_id(script_id);
    raw->set_line_offset(0);
    raw->set_column_offset(0);
    raw->set_context_data(roots.undefined_value(), SKIP_WRITE_BARRIER);
    raw->set_type(Script::Type::kNormal);
    raw->set_line_ends(Smi::zero());
    raw->set_eval_from_shared_or_wrapped_arguments(roots.undefined_value(),
                                                   SKIP_WRITE_BARRIER);
    raw->set_eval_from_position(0);
    raw->set_infos(roots.empty_weak_fixed_array(), SKIP_WRITE_BARRIER);
    raw->set_flags(0);
    raw->set_host_defined_options(roots.empty_fixed_array(),
                                  SKIP_WRITE_BARRIER);
    raw->set_source_hash(roots.undefined_value(), SKIP_WRITE_BARRIER);
    raw->set_compiled_lazy_function_positions(roots.undefined_value(),
                                              SKIP_WRITE_BARRIER);
#ifdef V8_SCRIPTORMODULE_LEGACY_LIFETIME
    raw->set_script_or_modules(roots.empty_array_list());
#endif
  }
  impl()->ProcessNewScript(script, script_event_type);
  return script;
}

template <typename Impl>
Handle<SloppyArgumentsElements> FactoryBase<Impl>::NewSloppyArgumentsElements(
    int length, DirectHandle<Context> context,
    DirectHandle<FixedArray> arguments, AllocationType allocation) {
  Tagged<SloppyArgumentsElements> result =
      Cast<SloppyArgumentsElements>(AllocateRawWithImmortalMap(
          SloppyArgumentsElements::SizeFor(length), allocation,
          read_only_roots().sloppy_arguments_elements_map()));

  DisallowGarbageCollection no_gc;
  WriteBarrierMode write_barrier_mode = allocation == AllocationType::kYoung
                                            ? SKIP_WRITE_BARRIER
                                            : UPDATE_WRITE_BARRIER;
  result->set_length(length);
  result->set_context(*context, write_barrier_mode);
  result->set_arguments(*arguments, write_barrier_mode);
  return handle(result, isolate());
}

template <typename Impl>
Handle<ArrayList> FactoryBase<Impl>::NewArrayList(int size,
                                                  AllocationType allocation) {
  return ArrayList::New(isolate(), size, allocation);
}

template <typename Impl>
Handle<SharedFunctionInfo> FactoryBase<Impl>::NewSharedFunctionInfoForLiteral(
    FunctionLiteral* literal, DirectHandle<Script> script, bool is_toplevel) {
  FunctionKind kind = literal->kind();
  Handle<SharedFunctionInfo> shared =
      NewSharedFunctionInfo(literal->GetName(isolate()), {},
                            Builtin::kCompileLazy, 0, kDontAdapt, kind);
  shared->set_function_literal_id(literal->function_literal_id());
  literal->set_shared_function_info(shared);
  SharedFunctionInfo::InitFromFunctionLiteral(isolate(), literal, is_toplevel);
  shared->SetScript(isolate(), read_only_roots(), *script,
                    literal->function_literal_id(), false);
  return shared;
}

template <typename Impl>
Handle<SharedFunctionInfo> FactoryBase<Impl>::CloneSharedFunctionInfo(
    DirectHandle<SharedFunctionInfo> other) {
  Tagged<Map> map = read_only_roots().shared_function_info_map();

  Tagged<SharedFunctionInfo> shared =
      Cast<SharedFunctionInfo>(NewWithImmortalMap(map, AllocationType::kOld));
  DisallowGarbageCollection no_gc;

  shared->clear_padding();
  shared->CopyFrom(*other, isolate());

  return handle(shared, isolate());
}

template <typename Impl>
Handle<SharedFunctionInfoWrapper>
FactoryBase<Impl>::NewSharedFunctionInfoWrapper(
    DirectHandle<SharedFunctionInfo> sfi) {
  Tagged<Map> map = read_only_roots().shared_function_info_wrapper_map();
  Tagged<SharedFunctionInfoWrapper> wrapper = Cast<SharedFunctionInfoWrapper>(
      NewWithImmortalMap(map, AllocationType::kTrusted));

  wrapper->set_shared_info(*sfi);

  return handle(wrapper, isolate());
}

template <typename Impl>
Handle<PreparseData> FactoryBase<Impl>::NewPreparseData(int data_length,
                                                        int children_length) {
  int size = PreparseData::SizeFor(data_length, children_length);
  Tagged<PreparseData> result = Cast<PreparseData>(AllocateRawWithImmortalMap(
      size, AllocationType::kOld, read_only_roots().preparse_data_map()));
  DisallowGarbageCollection no_gc;
  result->set_data_length(data_length);
  result->set_children_length(children_length);
  MemsetTagged(result->inner_data_start(), read_only_roots().null_value(),
               children_length);
  result->clear_padding();
  return handle(result, isolate());
}

template <typename Impl>
Handle<UncompiledDataWithoutPreparseData>
FactoryBase<Impl>::NewUncompiledDataWithoutPreparseData(
    Handle<String> inferred_name, int32_t start_position,
    int32_t end_position) {
  return TorqueGeneratedFactory<Impl>::NewUncompiledDataWithoutPreparseData(
      inferred_name, start_position, end_position, AllocationType::kTrusted);
}

template <typename Impl>
Handle<UncompiledDataWithPreparseData>
FactoryBase<Impl>::NewUncompiledDataWithPreparseData(
    Handle<String> inferred_name, int32_t start_position, int32_t end_position,
    Handle<PreparseData> preparse_data) {
  return TorqueGeneratedFactory<Impl>::NewUncompiledDataWithPreparseData(
      inferred_name, start_position, end_position, preparse_data,
      AllocationType::kTrusted);
}

template <typename Impl>
Handle<UncompiledDataWithoutPreparseDataWithJob>
FactoryBase<Impl>::NewUncompiledDataWithoutPreparseDataWithJob(
    Handle<String> inferred_name, int32_t start_position,
    int32_t end_position) {
  return TorqueGeneratedFactory<Impl>::
      NewUncompiledDataWithoutPreparseDataWithJob(inferred_name, start_position,
                                                  end_position, kNullAddress,
                                                  AllocationType::kTrusted);
}

template <typename Impl>
Handle<UncompiledDataWithPreparseDataAndJob>
FactoryBase<Impl>::NewUncompiledDataWithPreparseDataAndJob(
    Handle<String> inferred_name, int32_t start_position, int32_t end_position,
    Handle<PreparseData> preparse_data) {
  return TorqueGeneratedFactory<Impl>::NewUncompiledDataWithPreparseDataAndJob(
      inferred_name, start_position, end_position, preparse_data, kNullAddress,
      AllocationType::kTrusted);
}

template <typename Impl>
Handle<SharedFunctionInfo> FactoryBase<Impl>::NewSharedFunctionInfo(
    MaybeDirectHandle<String> maybe_name,
    MaybeDirectHandle<HeapObject> maybe_function_data, Builtin builtin, int len,
    AdaptArguments adapt, FunctionKind kind) {
  Handle<SharedFunctionInfo> shared =
      NewSharedFunctionInfo(AllocationType::kOld);
  DisallowGarbageCollection no_gc;
  Tagged<SharedFunctionInfo> raw = *shared;
  // Function names are assumed to be flat elsewhere.
  DirectHandle<String> shared_name;
  bool has_shared_name = maybe_name.ToHandle(&shared_name);
  if (has_shared_name) {
    DCHECK(shared_name->IsFlat());
    raw->set_name_or_scope_info(*shared_name, kReleaseStore);
  } else {
    DCHECK_EQ(raw->name_or_scope_info(kAcquireLoad),
              SharedFunctionInfo::kNoSharedNameSentinel);
  }

  DirectHandle<HeapObject> function_data;
  if (maybe_function_data.ToHandle(&function_data)) {
    // If we pass function_data then we shouldn't pass a builtin index, and
    // the function_data should not be code with a builtin.
    DCHECK(!Builtins::IsBuiltinId(builtin));
    DCHECK(!IsInstructionStream(*function_data));
    DCHECK(!IsCode(*function_data));
    if (IsExposedTrustedObject(*function_data)) {
      raw->SetTrustedData(Cast<ExposedTrustedObject>(*function_data));
    } else {
      raw->SetUntrustedData(*function_data);
    }
  } else if (Builtins::IsBuiltinId(builtin)) {
    raw->set_builtin_id(builtin);
  } else {
    DCHECK(raw->HasBuiltinId());
    DCHECK_EQ(Builtin::kIllegal, raw->builtin_id());
  }

  raw->CalculateConstructAsBuiltin();
  raw->set_kind(kind);

  switch (adapt) {
    case AdaptArguments::kYes:
      raw->set_formal_parameter_count(JSParameterCount(len));
      break;
    case AdaptArguments::kNo:
      raw->DontAdaptArguments();
      break;
  }
  raw->set_length(len);

  DCHECK_IMPLIES(raw->HasBuiltinId(),
                 Builtins::CheckFormalParameterCount(
                     raw->builtin_id(), raw->length(),
                     raw->internal_formal_parameter_count_with_receiver()));
#ifdef VERIFY_HEAP
  if (v8_flags.verify_heap) raw->SharedFunctionInfoVerify(isolate());
#endif  // VERIFY_HEAP
  return shared;
}

template <typename Impl>
Handle<ObjectBoilerplateDescription>
FactoryBase<Impl>::NewObjectBoilerplateDescription(int boilerplate,
                                                   int all_properties,
                                                   int index_keys,
                                                   bool has_seen_proto) {
  return ObjectBoilerplateDescription::New(
      isolate(), boilerplate, all_properties, index_keys, has_seen_proto,
      AllocationType::kOld);
}

template <typename Impl>
Handle<ArrayBoilerplateDescription>
FactoryBase<Impl>::NewArrayBoilerplateDescription(
    ElementsKind elements_kind, DirectHandle<FixedArrayBase> constant_values) {
  auto result = NewStructInternal<ArrayBoilerplateDescription>(
      ARRAY_BOILERPLATE_DESCRIPTION_TYPE, AllocationType::kOld);
  DisallowGarbageCollection no_gc;
  result->set_elements_kind(elements_kind);
  result->set_constant_elements(*constant_values);
  return handle(result, isolate());
}

template <typename Impl>
Handle<RegExpDataWrapper> FactoryBase<Impl>::NewRegExpDataWrapper() {
  Handle<RegExpDataWrapper> wrapper(
      Cast<RegExpDataWrapper>(NewWithImmortalMap(
          read_only_roots().regexp_data_wrapper_map(), AllocationType::kOld)),
      isolate());
  wrapper->clear_data();
  return wrapper;
}

template <typename Impl>
Handle<RegExpBoilerplateDescription>
FactoryBase<Impl>::NewRegExpBoilerplateDescription(
    DirectHandle<RegExpData> data, DirectHandle<String> source
### 提示词
```
这是目录为v8/src/heap/factory-base.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/factory-base.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/heap/factory-base.h"

#include "src/ast/ast-source-ranges.h"
#include "src/ast/ast.h"
#include "src/common/assert-scope.h"
#include "src/common/globals.h"
#include "src/execution/local-isolate.h"
#include "src/handles/handles-inl.h"
#include "src/heap/factory.h"
#include "src/heap/heap-inl.h"
#include "src/heap/large-page-metadata-inl.h"
#include "src/heap/local-factory-inl.h"
#include "src/heap/mutable-page-metadata.h"
#include "src/heap/read-only-heap.h"
#include "src/logging/local-logger.h"
#include "src/logging/log.h"
#include "src/objects/arguments-inl.h"
#include "src/objects/instance-type.h"
#include "src/objects/js-regexp-inl.h"
#include "src/objects/literal-objects-inl.h"
#include "src/objects/module-inl.h"
#include "src/objects/oddball.h"
#include "src/objects/shared-function-info-inl.h"
#include "src/objects/shared-function-info.h"
#include "src/objects/source-text-module.h"
#include "src/objects/string-inl.h"
#include "src/objects/string.h"
#include "src/objects/swiss-name-dictionary-inl.h"
#include "src/objects/template-objects-inl.h"
#include "src/roots/roots.h"

namespace v8 {
namespace internal {

template <typename Impl>
template <AllocationType allocation>
Handle<HeapNumber> FactoryBase<Impl>::NewHeapNumber() {
  static_assert(sizeof(HeapNumber) <= kMaxRegularHeapObjectSize);
  Tagged<Map> map = read_only_roots().heap_number_map();
  Tagged<HeapObject> result = AllocateRawWithImmortalMap(
      sizeof(HeapNumber), allocation, map, kDoubleUnaligned);
  return handle(Cast<HeapNumber>(result), isolate());
}

template V8_EXPORT_PRIVATE Handle<HeapNumber>
FactoryBase<Factory>::NewHeapNumber<AllocationType::kYoung>();
template V8_EXPORT_PRIVATE Handle<HeapNumber>
FactoryBase<Factory>::NewHeapNumber<AllocationType::kOld>();
template V8_EXPORT_PRIVATE Handle<HeapNumber>
FactoryBase<Factory>::NewHeapNumber<AllocationType::kReadOnly>();
template V8_EXPORT_PRIVATE Handle<HeapNumber>
FactoryBase<Factory>::NewHeapNumber<AllocationType::kSharedOld>();

template V8_EXPORT_PRIVATE Handle<HeapNumber>
FactoryBase<LocalFactory>::NewHeapNumber<AllocationType::kOld>();

template <typename Impl>
Handle<Struct> FactoryBase<Impl>::NewStruct(InstanceType type,
                                            AllocationType allocation) {
  ReadOnlyRoots roots = read_only_roots();
  Tagged<Map> map = Map::GetMapFor(roots, type);
  int size = map->instance_size();
  return handle(NewStructInternal(roots, map, size, allocation), isolate());
}

template <typename Impl>
Handle<AccessorPair> FactoryBase<Impl>::NewAccessorPair() {
  auto accessors =
      NewStructInternal<AccessorPair>(ACCESSOR_PAIR_TYPE, AllocationType::kOld);
  DisallowGarbageCollection no_gc;
  accessors->set_getter(read_only_roots().null_value(), SKIP_WRITE_BARRIER);
  accessors->set_setter(read_only_roots().null_value(), SKIP_WRITE_BARRIER);
  return handle(accessors, isolate());
}

template <typename Impl>
Handle<Code> FactoryBase<Impl>::NewCode(const NewCodeOptions& options) {
  DirectHandle<CodeWrapper> wrapper = NewCodeWrapper();
  Tagged<Map> map = read_only_roots().code_map();
  int size = map->instance_size();
  Tagged<Code> code = Cast<Code>(
      AllocateRawWithImmortalMap(size, AllocationType::kTrusted, map));
  DisallowGarbageCollection no_gc;
  code->init_self_indirect_pointer(isolate());
  code->initialize_flags(options.kind, options.is_context_specialized,
                         options.is_turbofanned);
  code->set_builtin_id(options.builtin);
  code->set_instruction_size(options.instruction_size);
  code->set_metadata_size(options.metadata_size);
  code->set_inlined_bytecode_size(options.inlined_bytecode_size);
  code->set_osr_offset(options.osr_offset);
  code->set_handler_table_offset(options.handler_table_offset);
  code->set_constant_pool_offset(options.constant_pool_offset);
  code->set_code_comments_offset(options.code_comments_offset);
  code->set_builtin_jump_table_info_offset(
      options.builtin_jump_table_info_offset);
  code->set_unwinding_info_offset(options.unwinding_info_offset);
  code->set_parameter_count(options.parameter_count);

  // Set bytecode/interpreter data or deoptimization data.
  if (CodeKindUsesBytecodeOrInterpreterData(options.kind)) {
    DCHECK(options.deoptimization_data.is_null());
    Tagged<TrustedObject> data =
        *options.bytecode_or_interpreter_data.ToHandleChecked();
    DCHECK(IsBytecodeArray(data) || IsInterpreterData(data));
    code->set_bytecode_or_interpreter_data(data);
  } else if (CodeKindUsesDeoptimizationData(options.kind)) {
    DCHECK(options.bytecode_or_interpreter_data.is_null());
    code->set_deoptimization_data(
        *options.deoptimization_data.ToHandleChecked());
  } else {
    DCHECK(options.deoptimization_data.is_null());
    DCHECK(options.bytecode_or_interpreter_data.is_null());
    code->clear_deoptimization_data_and_interpreter_data();
  }

  // Set bytecode offset table or source position table.
  if (CodeKindUsesBytecodeOffsetTable(options.kind)) {
    DCHECK(options.source_position_table.is_null());
    code->set_bytecode_offset_table(
        *options.bytecode_offset_table.ToHandleChecked());
  } else if (CodeKindMayLackSourcePositionTable(options.kind)) {
    DCHECK(options.bytecode_offset_table.is_null());
    Handle<TrustedByteArray> table;
    if (options.source_position_table.ToHandle(&table)) {
      code->set_source_position_table(*table);
    } else {
      code->clear_source_position_table_and_bytecode_offset_table();
    }
  } else {
    DCHECK(options.bytecode_offset_table.is_null());
    code->set_source_position_table(
        *options.source_position_table.ToHandleChecked());
  }

  // Set instruction stream and entrypoint.
  Handle<InstructionStream> istream;
  if (options.instruction_stream.ToHandle(&istream)) {
    DCHECK_EQ(options.instruction_start, kNullAddress);
    code->SetInstructionStreamAndInstructionStart(isolate(), *istream);
  } else {
    DCHECK_NE(options.instruction_start, kNullAddress);
    code->set_raw_instruction_stream(Smi::zero(), SKIP_WRITE_BARRIER);
    code->SetInstructionStartForOffHeapBuiltin(isolate(),
                                               options.instruction_start);
  }

  wrapper->set_code(code);
  code->set_wrapper(*wrapper);

  code->clear_padding();
  return handle(code, isolate());
}

template <typename Impl>
Handle<CodeWrapper> FactoryBase<Impl>::NewCodeWrapper() {
  Handle<CodeWrapper> wrapper(
      Cast<CodeWrapper>(NewWithImmortalMap(read_only_roots().code_wrapper_map(),
                                           AllocationType::kOld)),
      isolate());
  // The CodeWrapper is typically created before the Code object it wraps, so
  // the code field cannot yet be set. However, as a heap verifier might see
  // the wrapper before the field can be set, we need to clear the field here.
  wrapper->clear_code();
  return wrapper;
}

template <typename Impl>
Handle<FixedArray> FactoryBase<Impl>::NewFixedArray(int length,
                                                    AllocationType allocation) {
  return FixedArray::New(isolate(), length, allocation);
}

template <typename Impl>
Handle<TrustedFixedArray> FactoryBase<Impl>::NewTrustedFixedArray(
    int length, AllocationType allocation) {
  DCHECK(allocation == AllocationType::kTrusted ||
         allocation == AllocationType::kSharedTrusted);

  // TODO(saelo): Move this check to TrustedFixedArray::New once we have a RO
  // trusted space.
  if (length == 0) return empty_trusted_fixed_array();
  return TrustedFixedArray::New(isolate(), length, allocation);
}

template <typename Impl>
Handle<ProtectedFixedArray> FactoryBase<Impl>::NewProtectedFixedArray(
    int length) {
  if (length == 0) return empty_protected_fixed_array();
  return ProtectedFixedArray::New(isolate(), length);
}

template <typename Impl>
Handle<FixedArray> FactoryBase<Impl>::NewFixedArrayWithMap(
    DirectHandle<Map> map, int length, AllocationType allocation) {
  // Zero-length case must be handled outside, where the knowledge about
  // the map is.
  DCHECK_LT(0, length);
  return NewFixedArrayWithFiller(
      map, length, read_only_roots().undefined_value_handle(), allocation);
}

template <typename Impl>
Handle<FixedArray> FactoryBase<Impl>::NewFixedArrayWithHoles(
    int length, AllocationType allocation) {
  DCHECK_LE(0, length);
  if (length == 0) return impl()->empty_fixed_array();
  return NewFixedArrayWithFiller(
      read_only_roots().fixed_array_map_handle(), length,
      read_only_roots().the_hole_value_handle(), allocation);
}

template <typename Impl>
Handle<FixedArray> FactoryBase<Impl>::NewFixedArrayWithFiller(
    DirectHandle<Map> map, int length, DirectHandle<HeapObject> filler,
    AllocationType allocation) {
  Tagged<HeapObject> result = AllocateRawFixedArray(length, allocation);
  DisallowGarbageCollection no_gc;
  DCHECK(ReadOnlyHeap::Contains(*map));
  DCHECK(ReadOnlyHeap::Contains(*filler));
  result->set_map_after_allocation(isolate(), *map, SKIP_WRITE_BARRIER);
  Tagged<FixedArray> array = Cast<FixedArray>(result);
  array->set_length(length);
  MemsetTagged(array->RawFieldOfFirstElement(), *filler, length);
  return handle(array, isolate());
}

template <typename Impl>
Handle<FixedArray> FactoryBase<Impl>::NewFixedArrayWithZeroes(
    int length, AllocationType allocation) {
  DCHECK_LE(0, length);
  if (length == 0) return impl()->empty_fixed_array();
  if (length > FixedArray::kMaxLength) {
    FATAL("Invalid FixedArray size %d", length);
  }
  Tagged<HeapObject> result = AllocateRawFixedArray(length, allocation);
  DisallowGarbageCollection no_gc;
  result->set_map_after_allocation(
      isolate(), read_only_roots().fixed_array_map(), SKIP_WRITE_BARRIER);
  Tagged<FixedArray> array = Cast<FixedArray>(result);
  array->set_length(length);
  MemsetTagged(array->RawFieldOfFirstElement(), Smi::zero(), length);
  return handle(array, isolate());
}

template <typename Impl>
Handle<FixedArrayBase> FactoryBase<Impl>::NewFixedDoubleArray(
    int length, AllocationType allocation) {
  return FixedDoubleArray::New(isolate(), length, allocation);
}

template <typename Impl>
Handle<WeakFixedArray> FactoryBase<Impl>::NewWeakFixedArrayWithMap(
    Tagged<Map> map, int length, AllocationType allocation) {
  // Zero-length case must be handled outside.
  DCHECK_LT(0, length);
  DCHECK(ReadOnlyHeap::Contains(map));

  Tagged<HeapObject> result =
      AllocateRawArray(WeakFixedArray::SizeFor(length), allocation);
  result->set_map_after_allocation(isolate(), map, SKIP_WRITE_BARRIER);
  DisallowGarbageCollection no_gc;
  Tagged<WeakFixedArray> array = Cast<WeakFixedArray>(result);
  array->set_length(length);
  MemsetTagged(ObjectSlot(array->RawFieldOfFirstElement()),
               read_only_roots().undefined_value(), length);

  return handle(array, isolate());
}

template <typename Impl>
Handle<WeakFixedArray> FactoryBase<Impl>::NewWeakFixedArray(
    int length, AllocationType allocation) {
  return WeakFixedArray::New(isolate(), length, allocation);
}

template <typename Impl>
Handle<TrustedWeakFixedArray> FactoryBase<Impl>::NewTrustedWeakFixedArray(
    int length) {
  // TODO(saelo): Move this check to TrustedWeakFixedArray::New once we have a
  // RO trusted space.
  if (length == 0) return empty_trusted_weak_fixed_array();
  return TrustedWeakFixedArray::New(isolate(), length);
}

template <typename Impl>
Handle<ByteArray> FactoryBase<Impl>::NewByteArray(int length,
                                                  AllocationType allocation) {
  return ByteArray::New(isolate(), length, allocation);
}

template <typename Impl>
Handle<TrustedByteArray> FactoryBase<Impl>::NewTrustedByteArray(
    int length, AllocationType allocation_type) {
  if (length == 0) return empty_trusted_byte_array();
  return TrustedByteArray::New(isolate(), length, allocation_type);
}

template <typename Impl>
Handle<DeoptimizationLiteralArray>
FactoryBase<Impl>::NewDeoptimizationLiteralArray(int length) {
  return Cast<DeoptimizationLiteralArray>(NewTrustedWeakFixedArray(length));
}

template <typename Impl>
Handle<DeoptimizationFrameTranslation>
FactoryBase<Impl>::NewDeoptimizationFrameTranslation(int length) {
  return Cast<DeoptimizationFrameTranslation>(NewTrustedByteArray(length));
}

template <typename Impl>
Handle<BytecodeArray> FactoryBase<Impl>::NewBytecodeArray(
    int length, const uint8_t* raw_bytecodes, int frame_size,
    uint16_t parameter_count, uint16_t max_arguments,
    DirectHandle<TrustedFixedArray> constant_pool,
    DirectHandle<TrustedByteArray> handler_table, AllocationType allocation) {
  DCHECK(allocation == AllocationType::kTrusted ||
         allocation == AllocationType::kSharedTrusted);
  if (length < 0 || length > BytecodeArray::kMaxLength) {
    FATAL("Fatal JavaScript invalid size error %d", length);
    UNREACHABLE();
  }
  DirectHandle<BytecodeWrapper> wrapper = NewBytecodeWrapper();
  int size = BytecodeArray::SizeFor(length);
  Tagged<HeapObject> result = AllocateRawWithImmortalMap(
      size, allocation, read_only_roots().bytecode_array_map());
  DisallowGarbageCollection no_gc;
  Tagged<BytecodeArray> instance = Cast<BytecodeArray>(result);
  instance->init_self_indirect_pointer(isolate());
  instance->set_length(length);
  instance->set_frame_size(frame_size);
  instance->set_parameter_count(parameter_count);
  instance->set_max_arguments(max_arguments);
  instance->set_incoming_new_target_or_generator_register(
      interpreter::Register::invalid_value());
  instance->set_constant_pool(*constant_pool);
  instance->set_handler_table(*handler_table);
  instance->clear_source_position_table(kReleaseStore);
  instance->set_wrapper(*wrapper);
  CopyBytes(reinterpret_cast<uint8_t*>(instance->GetFirstBytecodeAddress()),
            raw_bytecodes, length);
  instance->clear_padding();
  wrapper->set_bytecode(instance);
  return handle(instance, isolate());
}

template <typename Impl>
Handle<BytecodeWrapper> FactoryBase<Impl>::NewBytecodeWrapper(
    AllocationType allocation) {
  DCHECK(allocation == AllocationType::kOld ||
         allocation == AllocationType::kSharedOld);

  Handle<BytecodeWrapper> wrapper(
      Cast<BytecodeWrapper>(NewWithImmortalMap(
          read_only_roots().bytecode_wrapper_map(), allocation)),
      isolate());
  // The BytecodeWrapper is typically created before the BytecodeArray it
  // wraps, so the bytecode field cannot yet be set. However, as a heap
  // verifier might see the wrapper before the field can be set, we need to
  // clear the field here.
  wrapper->clear_bytecode();
  return wrapper;
}

template <typename Impl>
Handle<Script> FactoryBase<Impl>::NewScript(
    DirectHandle<UnionOf<String, Undefined>> source,
    ScriptEventType script_event_type) {
  return NewScriptWithId(source, isolate()->GetNextScriptId(),
                         script_event_type);
}

template <typename Impl>
Handle<Script> FactoryBase<Impl>::NewScriptWithId(
    DirectHandle<UnionOf<String, Undefined>> source, int script_id,
    ScriptEventType script_event_type) {
  DCHECK(IsString(*source) || IsUndefined(*source));
  // Create and initialize script object.
  ReadOnlyRoots roots = read_only_roots();
  Handle<Script> script = handle(
      NewStructInternal<Script>(SCRIPT_TYPE, AllocationType::kOld), isolate());
  {
    DisallowGarbageCollection no_gc;
    Tagged<Script> raw = *script;
    raw->set_source(*source);
    raw->set_name(roots.undefined_value(), SKIP_WRITE_BARRIER);
    raw->set_id(script_id);
    raw->set_line_offset(0);
    raw->set_column_offset(0);
    raw->set_context_data(roots.undefined_value(), SKIP_WRITE_BARRIER);
    raw->set_type(Script::Type::kNormal);
    raw->set_line_ends(Smi::zero());
    raw->set_eval_from_shared_or_wrapped_arguments(roots.undefined_value(),
                                                   SKIP_WRITE_BARRIER);
    raw->set_eval_from_position(0);
    raw->set_infos(roots.empty_weak_fixed_array(), SKIP_WRITE_BARRIER);
    raw->set_flags(0);
    raw->set_host_defined_options(roots.empty_fixed_array(),
                                  SKIP_WRITE_BARRIER);
    raw->set_source_hash(roots.undefined_value(), SKIP_WRITE_BARRIER);
    raw->set_compiled_lazy_function_positions(roots.undefined_value(),
                                              SKIP_WRITE_BARRIER);
#ifdef V8_SCRIPTORMODULE_LEGACY_LIFETIME
    raw->set_script_or_modules(roots.empty_array_list());
#endif
  }
  impl()->ProcessNewScript(script, script_event_type);
  return script;
}

template <typename Impl>
Handle<SloppyArgumentsElements> FactoryBase<Impl>::NewSloppyArgumentsElements(
    int length, DirectHandle<Context> context,
    DirectHandle<FixedArray> arguments, AllocationType allocation) {
  Tagged<SloppyArgumentsElements> result =
      Cast<SloppyArgumentsElements>(AllocateRawWithImmortalMap(
          SloppyArgumentsElements::SizeFor(length), allocation,
          read_only_roots().sloppy_arguments_elements_map()));

  DisallowGarbageCollection no_gc;
  WriteBarrierMode write_barrier_mode = allocation == AllocationType::kYoung
                                            ? SKIP_WRITE_BARRIER
                                            : UPDATE_WRITE_BARRIER;
  result->set_length(length);
  result->set_context(*context, write_barrier_mode);
  result->set_arguments(*arguments, write_barrier_mode);
  return handle(result, isolate());
}

template <typename Impl>
Handle<ArrayList> FactoryBase<Impl>::NewArrayList(int size,
                                                  AllocationType allocation) {
  return ArrayList::New(isolate(), size, allocation);
}

template <typename Impl>
Handle<SharedFunctionInfo> FactoryBase<Impl>::NewSharedFunctionInfoForLiteral(
    FunctionLiteral* literal, DirectHandle<Script> script, bool is_toplevel) {
  FunctionKind kind = literal->kind();
  Handle<SharedFunctionInfo> shared =
      NewSharedFunctionInfo(literal->GetName(isolate()), {},
                            Builtin::kCompileLazy, 0, kDontAdapt, kind);
  shared->set_function_literal_id(literal->function_literal_id());
  literal->set_shared_function_info(shared);
  SharedFunctionInfo::InitFromFunctionLiteral(isolate(), literal, is_toplevel);
  shared->SetScript(isolate(), read_only_roots(), *script,
                    literal->function_literal_id(), false);
  return shared;
}

template <typename Impl>
Handle<SharedFunctionInfo> FactoryBase<Impl>::CloneSharedFunctionInfo(
    DirectHandle<SharedFunctionInfo> other) {
  Tagged<Map> map = read_only_roots().shared_function_info_map();

  Tagged<SharedFunctionInfo> shared =
      Cast<SharedFunctionInfo>(NewWithImmortalMap(map, AllocationType::kOld));
  DisallowGarbageCollection no_gc;

  shared->clear_padding();
  shared->CopyFrom(*other, isolate());

  return handle(shared, isolate());
}

template <typename Impl>
Handle<SharedFunctionInfoWrapper>
FactoryBase<Impl>::NewSharedFunctionInfoWrapper(
    DirectHandle<SharedFunctionInfo> sfi) {
  Tagged<Map> map = read_only_roots().shared_function_info_wrapper_map();
  Tagged<SharedFunctionInfoWrapper> wrapper = Cast<SharedFunctionInfoWrapper>(
      NewWithImmortalMap(map, AllocationType::kTrusted));

  wrapper->set_shared_info(*sfi);

  return handle(wrapper, isolate());
}

template <typename Impl>
Handle<PreparseData> FactoryBase<Impl>::NewPreparseData(int data_length,
                                                        int children_length) {
  int size = PreparseData::SizeFor(data_length, children_length);
  Tagged<PreparseData> result = Cast<PreparseData>(AllocateRawWithImmortalMap(
      size, AllocationType::kOld, read_only_roots().preparse_data_map()));
  DisallowGarbageCollection no_gc;
  result->set_data_length(data_length);
  result->set_children_length(children_length);
  MemsetTagged(result->inner_data_start(), read_only_roots().null_value(),
               children_length);
  result->clear_padding();
  return handle(result, isolate());
}

template <typename Impl>
Handle<UncompiledDataWithoutPreparseData>
FactoryBase<Impl>::NewUncompiledDataWithoutPreparseData(
    Handle<String> inferred_name, int32_t start_position,
    int32_t end_position) {
  return TorqueGeneratedFactory<Impl>::NewUncompiledDataWithoutPreparseData(
      inferred_name, start_position, end_position, AllocationType::kTrusted);
}

template <typename Impl>
Handle<UncompiledDataWithPreparseData>
FactoryBase<Impl>::NewUncompiledDataWithPreparseData(
    Handle<String> inferred_name, int32_t start_position, int32_t end_position,
    Handle<PreparseData> preparse_data) {
  return TorqueGeneratedFactory<Impl>::NewUncompiledDataWithPreparseData(
      inferred_name, start_position, end_position, preparse_data,
      AllocationType::kTrusted);
}

template <typename Impl>
Handle<UncompiledDataWithoutPreparseDataWithJob>
FactoryBase<Impl>::NewUncompiledDataWithoutPreparseDataWithJob(
    Handle<String> inferred_name, int32_t start_position,
    int32_t end_position) {
  return TorqueGeneratedFactory<Impl>::
      NewUncompiledDataWithoutPreparseDataWithJob(inferred_name, start_position,
                                                  end_position, kNullAddress,
                                                  AllocationType::kTrusted);
}

template <typename Impl>
Handle<UncompiledDataWithPreparseDataAndJob>
FactoryBase<Impl>::NewUncompiledDataWithPreparseDataAndJob(
    Handle<String> inferred_name, int32_t start_position, int32_t end_position,
    Handle<PreparseData> preparse_data) {
  return TorqueGeneratedFactory<Impl>::NewUncompiledDataWithPreparseDataAndJob(
      inferred_name, start_position, end_position, preparse_data, kNullAddress,
      AllocationType::kTrusted);
}

template <typename Impl>
Handle<SharedFunctionInfo> FactoryBase<Impl>::NewSharedFunctionInfo(
    MaybeDirectHandle<String> maybe_name,
    MaybeDirectHandle<HeapObject> maybe_function_data, Builtin builtin, int len,
    AdaptArguments adapt, FunctionKind kind) {
  Handle<SharedFunctionInfo> shared =
      NewSharedFunctionInfo(AllocationType::kOld);
  DisallowGarbageCollection no_gc;
  Tagged<SharedFunctionInfo> raw = *shared;
  // Function names are assumed to be flat elsewhere.
  DirectHandle<String> shared_name;
  bool has_shared_name = maybe_name.ToHandle(&shared_name);
  if (has_shared_name) {
    DCHECK(shared_name->IsFlat());
    raw->set_name_or_scope_info(*shared_name, kReleaseStore);
  } else {
    DCHECK_EQ(raw->name_or_scope_info(kAcquireLoad),
              SharedFunctionInfo::kNoSharedNameSentinel);
  }

  DirectHandle<HeapObject> function_data;
  if (maybe_function_data.ToHandle(&function_data)) {
    // If we pass function_data then we shouldn't pass a builtin index, and
    // the function_data should not be code with a builtin.
    DCHECK(!Builtins::IsBuiltinId(builtin));
    DCHECK(!IsInstructionStream(*function_data));
    DCHECK(!IsCode(*function_data));
    if (IsExposedTrustedObject(*function_data)) {
      raw->SetTrustedData(Cast<ExposedTrustedObject>(*function_data));
    } else {
      raw->SetUntrustedData(*function_data);
    }
  } else if (Builtins::IsBuiltinId(builtin)) {
    raw->set_builtin_id(builtin);
  } else {
    DCHECK(raw->HasBuiltinId());
    DCHECK_EQ(Builtin::kIllegal, raw->builtin_id());
  }

  raw->CalculateConstructAsBuiltin();
  raw->set_kind(kind);

  switch (adapt) {
    case AdaptArguments::kYes:
      raw->set_formal_parameter_count(JSParameterCount(len));
      break;
    case AdaptArguments::kNo:
      raw->DontAdaptArguments();
      break;
  }
  raw->set_length(len);

  DCHECK_IMPLIES(raw->HasBuiltinId(),
                 Builtins::CheckFormalParameterCount(
                     raw->builtin_id(), raw->length(),
                     raw->internal_formal_parameter_count_with_receiver()));
#ifdef VERIFY_HEAP
  if (v8_flags.verify_heap) raw->SharedFunctionInfoVerify(isolate());
#endif  // VERIFY_HEAP
  return shared;
}

template <typename Impl>
Handle<ObjectBoilerplateDescription>
FactoryBase<Impl>::NewObjectBoilerplateDescription(int boilerplate,
                                                   int all_properties,
                                                   int index_keys,
                                                   bool has_seen_proto) {
  return ObjectBoilerplateDescription::New(
      isolate(), boilerplate, all_properties, index_keys, has_seen_proto,
      AllocationType::kOld);
}

template <typename Impl>
Handle<ArrayBoilerplateDescription>
FactoryBase<Impl>::NewArrayBoilerplateDescription(
    ElementsKind elements_kind, DirectHandle<FixedArrayBase> constant_values) {
  auto result = NewStructInternal<ArrayBoilerplateDescription>(
      ARRAY_BOILERPLATE_DESCRIPTION_TYPE, AllocationType::kOld);
  DisallowGarbageCollection no_gc;
  result->set_elements_kind(elements_kind);
  result->set_constant_elements(*constant_values);
  return handle(result, isolate());
}

template <typename Impl>
Handle<RegExpDataWrapper> FactoryBase<Impl>::NewRegExpDataWrapper() {
  Handle<RegExpDataWrapper> wrapper(
      Cast<RegExpDataWrapper>(NewWithImmortalMap(
          read_only_roots().regexp_data_wrapper_map(), AllocationType::kOld)),
      isolate());
  wrapper->clear_data();
  return wrapper;
}

template <typename Impl>
Handle<RegExpBoilerplateDescription>
FactoryBase<Impl>::NewRegExpBoilerplateDescription(
    DirectHandle<RegExpData> data, DirectHandle<String> source,
    Tagged<Smi> flags) {
  auto result = NewStructInternal<RegExpBoilerplateDescription>(
      REG_EXP_BOILERPLATE_DESCRIPTION_TYPE, AllocationType::kOld);
  DisallowGarbageCollection no_gc;
  result->set_data(*data);
  result->set_source(*source);
  result->set_flags(flags.value());
  return handle(result, isolate());
}

template <typename Impl>
Handle<TemplateObjectDescription>
FactoryBase<Impl>::NewTemplateObjectDescription(
    DirectHandle<FixedArray> raw_strings,
    DirectHandle<FixedArray> cooked_strings) {
  DCHECK_EQ(raw_strings->length(), cooked_strings->length());
  DCHECK_LT(0, raw_strings->length());
  auto result = NewStructInternal<TemplateObjectDescription>(
      TEMPLATE_OBJECT_DESCRIPTION_TYPE, AllocationType::kOld);
  DisallowGarbageCollection no_gc;
  result->set_raw_strings(*raw_strings);
  result->set_cooked_strings(*cooked_strings);
  return handle(result, isolate());
}

template <typename Impl>
Handle<FeedbackMetadata> FactoryBase<Impl>::NewFeedbackMetadata(
    int slot_count, int create_closure_slot_count, AllocationType allocation) {
  DCHECK_LE(0, slot_count);
  int size = FeedbackMetadata::SizeFor(slot_count, create_closure_slot_count);
  Tagged<FeedbackMetadata> result =
      Cast<FeedbackMetadata>(AllocateRawWithImmortalMap(
          size, allocation, read_only_roots().feedback_metadata_map()));
  result->set_slot_count(slot_count);
  result->set_create_closure_slot_count(create_closure_slot_count);

  // Initialize the data section to 0.
  int data_size = size - FeedbackMetadata::kHeaderSize;
  Address data_start = result->address() + FeedbackMetadata::kHeaderSize;
  memset(reinterpret_cast<uint8_t*>(data_start), 0, data_size);
  // Fields have been zeroed out but not initialized, so this object will not
  // pass object verification at this point.
  return handle(result, isolate());
}

template <typename Impl>
Handle<CoverageInfo> FactoryBase<Impl>::NewCoverageInfo(
    const ZoneVector<SourceRange>& slots) {
  const int slot_count = static_cast<int>(slots.size());

  int size = CoverageInfo::SizeFor(slot_count);
  Tagged<Map> map = read_only_roots().coverage_info_map();
  Tagged<CoverageInfo> info = Cast<CoverageInfo>(
      AllocateRawWithImmortalMap(size, AllocationType::kOld, map));
  info->set_slot_count(slot_count);
  for (int i = 0; i < slot_count; i++) {
    SourceRange range = slots[i];
    info->InitializeSlot(i, range.start, range.end);
  }
  return handle(info, isolate());
}

template <typename Impl>
Handle<String> FactoryBase<Impl>::MakeOrFindTwoCharacterString(uint16_t c1,
                                                               uint16_t c2) {
  if ((c1 | c2) <= unibrow::Latin1::kMaxChar) {
    uint8_t buffer[] = {static_cast<uint8_t>(c1), static_cast<uint8_t>(c2)};
    return InternalizeString(base::Vector<const uint8_t>(buffer, 2));
  }
  uint16_t buffer[] = {c1, c2};
  return InternalizeString(base::Vector<const uint16_t>(buffer, 2));
}

template <typename Impl>
template <class StringTableKey>
Handle<String> FactoryBase<Impl>::InternalizeStringWithKey(
    StringTableKey* key) {
  return indirect_handle(isolate()->string_table()->LookupKey(isolate(), key),
                         isolate());
}

template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)
    Handle<String> FactoryBase<Factory>::InternalizeStringWithKey(
        OneByteStringKey* key);
template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)
    Handle<String> FactoryBase<Factory>::InternalizeStringWithKey(
        TwoByteStringKey* key);
template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)
    Handle<String> FactoryBase<Factory>::InternalizeStringWithKey(
        SeqOneByteSubStringKey* key);
template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)
    Handle<String> FactoryBase<Factory>::InternalizeStringWithKey(
        SeqTwoByteSubStringKey* key);

template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)
    Handle<String> FactoryBase<LocalFactory>::InternalizeStringWithKey(
        OneByteStringKey* key);
template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)
    Handle<String> FactoryBase<LocalFactory>::InternalizeStringWithKey(
        TwoByteStringKey* key);

template <typename Impl>
Handle<String> FactoryBase<Impl>::InternalizeString(
    base::Vector<const uint8_t> string, bool convert_encoding) {
  SequentialStringKey<uint8_t> key(string, HashSeed(read_only_roots()),
                                   convert_encoding);
  return InternalizeStringWithKey(&key);
}

template <typename Impl>
Handle<String> FactoryBase<Impl>::InternalizeString(
    base::Vector<const uint16_t> string, bool convert_encoding) {
  SequentialStringKey<uint16_t> key(string, HashSeed(read_only_roots()),
                                    convert_encoding);
  return InternalizeStringWithKey(&key);
}

template <typename Impl>
Handle<SeqOneByteString> FactoryBase<Impl>::NewOneByteInternalizedString(
    base::Vector<const uint8_t> str, uint32_t raw_hash_field) {
  Handle<SeqOneByteString> result =
      AllocateRawOneByteInternalizedString(str.length(), raw_hash_field);
  // No synchronization is needed since the shared string hasn't yet escaped to
  // script.
  DisallowGarbageCollection no_gc;
  MemCopy(result->GetChars(no_gc, SharedStringAccessGuardIfNeeded::NotNeeded()),
          str.begin(), str.length());
  return result;
}

template <typename Impl>
Handle<SeqTwoByteString> FactoryBase<Impl>::NewTwoByteInternalizedString(
    base::Vector<const base::uc16> str, uint32_t raw_hash_field) {
  Handle<SeqTwoByteString> result =
      AllocateRawTwoByteInternalizedString(str.length(), raw_hash_field);
  // No synchronization is needed since the shared string hasn't yet escaped to
  // script.
  DisallowGarbageCollection no_gc;
  MemCopy(result->GetChars(no_gc, SharedStringAccessGuardIfNeeded::NotNeeded()),
          str.begin(), str.length() * base::kUC16Size);
  return result;
}

template <typename Impl>
Handle<SeqOneByteString>
FactoryBase<Impl>::NewOneByteInternalizedStringFromTwoByte(
    base::Vector<const base::uc16> str, uint32_t raw_hash_field) {
  Handle<SeqOneByteString> result =
      AllocateRawOneByteInternalizedString(str.length(), raw_hash_field);
  DisallowGarbageCollection no_gc;
  CopyChars(
      result->GetChars(no_gc, SharedStringAccessGuardIfNeeded::NotNeeded()),
      str.begin(), str.length());
  return result;
}

template <typename Impl>
template <typename SeqStringT>
MaybeHandle<SeqStringT> FactoryBase<Impl>::NewRawStringWithMap(
    int length, Tagged<Map> map, AllocationType allocation) {
  DCHECK(SeqStringT::IsCompatibleMap(map, read_only_roots()));
  DCHECK_IMPLIES(!StringShape(map).IsShared(),
                 RefineAllocationTypeForInPlaceInternalizableString(
                     allocation, map) == allocation);
  if (length < 0 || static_cast<uint32_t>(length) > String::kMaxLength) {
    THROW_NEW_ERROR(isolate(), NewInvalidStringLengthError());
  }
  DCHECK_GT(length, 0);  // Use Factory::empty_string() instead.
  int size = SeqStringT::SizeFor(length);
  DCHECK_GE(ObjectTraits<SeqStringT>::kMaxSize, size);

  Tagged<SeqStringT> string =
      Cast<SeqStringT>(AllocateRawWithImmortalMap(size, allocation, map));
  DisallowGarbageCollection no_gc;
  string->clear_padding_destructively
```