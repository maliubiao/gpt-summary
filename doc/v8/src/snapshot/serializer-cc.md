Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/snapshot/serializer.cc`. They also have specific questions based on file extension, relationship to JavaScript, code logic, and potential programming errors.

Here's a breakdown of the thought process to address each point:

1. **Identify the core purpose:** The file name `serializer.cc` and the presence of classes like `Serializer` and `ObjectSerializer` strongly suggest this code is responsible for serializing V8 objects. The comments like "Encoding heap object" and the use of a `sink_` (likely for output) confirm this.

2. **Analyze the `Serializer` class:**  Look at the constructor and member functions. Key elements that stand out are:
    * `isolate_`:  Indicates interaction with the V8 isolate.
    * `hot_objects_`, `reference_map_`: These seem to be for handling object references and preventing duplication/cycles.
    * `deferred_objects_`: Suggests handling objects that can't be serialized immediately.
    * `SerializeObject`, `SerializeDeferredObjects`: Core serialization methods.
    * `PutRoot`, `PutBackReference`:  Mechanisms for encoding references.
    * `OutputStatistics`:  For debugging and understanding serialization.

3. **Analyze the `ObjectSerializer` class:**  This appears to handle the serialization of individual objects. Key methods are:
    * `SerializePrologue`:  Handles the initial steps for serializing an object, including checking for meta maps and handling deferred native contexts.
    * `SerializeBackingStore`:  Deals with serializing off-heap memory buffers (likely for `ArrayBuffer`).
    * `SerializeJSTypedArray`, `SerializeJSArrayBuffer`, `SerializeExternalString`: Specialized serialization for different JavaScript object types.
    * `Serialize`: The main entry point for serializing an object, with logic for deferral and recursion.

4. **Address the `.tq` question:** The prompt explicitly states the implication of a `.tq` extension. This is a simple check.

5. **Consider the JavaScript connection:**  Serialization is crucial for snapshots, which are used to speed up V8 startup. Think about how snapshots relate to JavaScript: they store the initial state of the heap, including built-in objects and code. This leads to considering how specific JavaScript types (like strings, arrays, functions) are handled during serialization. The specialized `Serialize` methods in `ObjectSerializer` provide concrete examples.

6. **Think about code logic and examples:**  Consider the flow of serialization. An object is encountered, its type is checked, and specific serialization logic is applied. The handling of deferred objects and back references is a key logical aspect. For examples, focus on simple scenarios like serializing a basic JavaScript object or a string.

7. **Identify potential programming errors:**  Consider common issues related to serialization, such as:
    * **Circular references:** The deferral and back-reference mechanisms are likely in place to prevent issues with circular dependencies. Failing to handle these can lead to infinite loops or stack overflows.
    * **Incorrect handling of external resources:**  Serializing pointers to external data needs careful handling to ensure those resources are available during deserialization. The code related to `ExternalString` and `ArrayBuffer` highlights this.
    * **State inconsistencies:** If the state of an object is modified during serialization in a way that isn't correctly restored during deserialization, it can lead to errors.

8. **Synthesize the functionality summary:** Combine the observations from the code analysis into a concise description of the file's purpose. Emphasize the key responsibilities of the `Serializer` and `ObjectSerializer` classes.

9. **Structure the answer:** Organize the information logically, addressing each part of the user's request (functionality, `.tq` extension, JavaScript relation, code logic, errors). Use clear and concise language. Use code blocks for JavaScript examples and format the assumptions and outputs for the code logic clearly.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Focus heavily on low-level details of the serialization format.
* **Correction:** Realize the user needs a higher-level understanding of the *purpose* of the code. Focus on the core functionality and how the different parts contribute to that.
* **Initial thought:**  Provide very technical C++ examples of how serialization works.
* **Correction:** The user requested JavaScript examples where relevant. Provide those to bridge the gap between the C++ code and the user's perspective.
* **Initial thought:**  Overcomplicate the code logic explanation.
* **Correction:**  Simplify the scenario with basic inputs and outputs to illustrate the core concepts like object type handling.
```cpp
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/snapshot/serializer.h"

#include "include/v8-internal.h"
#include "src/codegen/assembler-inl.h"
#include "src/common/globals.h"
#include "src/handles/global-handles-inl.h"
#include "src/heap/heap-inl.h"  // For Space::identity().
#include "src/heap/mutable-page-metadata-inl.h"
#include "src/heap/read-only-heap.h"
#include "src/heap/visit-object.h"
#include "src/objects/code.h"
#include "src/objects/descriptor-array.h"
#include "src/objects/instance-type-checker.h"
#include "src/objects/instance-type.h"
#include "src/objects/js-array-buffer-inl.h"
#include "src/objects/map.h"
#include "src/objects/objects-body-descriptors-inl.h"
#include "src/objects/slots-inl.h"
#include "src/objects/slots.h"
#include "src/objects/smi.h"
#include "src/sandbox/js-dispatch-table-inl.h"
#include "src/snapshot/embedded/embedded-data.h"
#include "src/snapshot/serializer-deserializer.h"
#include "src/snapshot/serializer-inl.h"

namespace v8 {
namespace internal {

Serializer::Serializer(Isolate* isolate, Snapshot::SerializerFlags flags)
    : isolate_(isolate),
#if V8_COMPRESS_POINTERS
      cage_base_(isolate),
#endif  // V8_COMPRESS_POINTERS
      hot_objects_(isolate->heap()),
      reference_map_(isolate),
      external_reference_encoder_(isolate),
      root_index_map_(isolate),
      deferred_objects_(isolate->heap()),
      forward_refs_per_pending_object_(isolate->heap()),
      flags_(flags)
#ifdef DEBUG
      ,
      back_refs_(isolate->heap()),
      stack_(isolate->heap())
#endif
{
#ifdef VERBOSE_SERIALIZATION_STATISTICS
  if (v8_flags.serialization_statistics) {
    for (int space = 0; space < kNumberOfSnapshotSpaces; ++space) {
      // Value-initialized to 0.
      instance_type_count_[space] = std::make_unique<int[]>(kInstanceTypes);
      instance_type_size_[space] = std::make_unique<size_t[]>(kInstanceTypes);
    }
  }
#endif  // VERBOSE_SERIALIZATION_STATISTICS
}

#ifdef DEBUG
void Serializer::PopStack() { stack_.Pop(); }
#endif

void Serializer::CountAllocation(Tagged<Map> map, int size,
                                 SnapshotSpace space) {
  DCHECK(v8_flags.serialization_statistics);

  const int space_number = static_cast<int>(space);
  allocation_size_[space_number] += size;
#ifdef VERBOSE_SERIALIZATION_STATISTICS
  int instance_type = map->instance_type();
  instance_type_count_[space_number][instance_type]++;
  instance_type_size_[space_number][instance_type] += size;
#endif  // VERBOSE_SERIALIZATION_STATISTICS
}

int Serializer::TotalAllocationSize() const {
  int sum = 0;
  for (int space = 0; space < kNumberOfSnapshotSpaces; space++) {
    sum += allocation_size_[space];
  }
  return sum;
}

namespace {

const char* ToString(SnapshotSpace space) {
  switch (space) {
    case SnapshotSpace::kReadOnlyHeap:
      return "ReadOnlyHeap";
    case SnapshotSpace::kOld:
      return "Old";
    case SnapshotSpace::kCode:
      return "Code";
    case SnapshotSpace::kTrusted:
      return "Trusted";
  }
}

}  // namespace

void Serializer::OutputStatistics(const char* name) {
  if (!v8_flags.serialization_statistics) return;

  PrintF("%s:\n", name);
  if (!serializer_tracks_serialization_statistics()) {
    PrintF("  <serialization statistics are not tracked>\n");
    return;
  }

  PrintF("  Spaces (bytes):\n");

  static constexpr SnapshotSpace kAllSnapshotSpaces[] = {
      SnapshotSpace::kReadOnlyHeap,
      SnapshotSpace::kOld,
      SnapshotSpace::kCode,
  };

  for (SnapshotSpace space : kAllSnapshotSpaces) {
    PrintF("%16s", ToString(space));
  }
  PrintF("\n");

  for (SnapshotSpace space : kAllSnapshotSpaces) {
    PrintF("%16zu", allocation_size_[static_cast<int>(space)]);
  }
  PrintF("\n");

#ifdef VERBOSE_SERIALIZATION_STATISTICS
  PrintF("  Instance types (count and bytes):\n");
#define PRINT_INSTANCE_TYPE(Name)                                           \
  for (SnapshotSpace space : kAllSnapshotSpaces) {                          \
    const int space_i = static_cast<int>(space);                            \
    if (instance_type_count_[space_i][Name]) {                              \
      PrintF("%10d %10zu  %-10s %s\n", instance_type_count_[space_i][Name], \
             instance_type_size_[space_i][Name], ToString(space), #Name);   \
    }                                                                       \
  }
  INSTANCE_TYPE_LIST(PRINT_INSTANCE_TYPE)
#undef PRINT_INSTANCE_TYPE
  PrintF("\n");
#endif  // VERBOSE_SERIALIZATION_STATISTICS
}

void Serializer::SerializeDeferredObjects() {
  if (v8_flags.trace_serializer) {
    PrintF("Serializing deferred objects\n");
  }
  WHILE_WITH_HANDLE_SCOPE(isolate(), !deferred_objects_.empty(), {
    Handle<HeapObject> obj = handle(deferred_objects_.Pop(), isolate());

    ObjectSerializer obj_serializer(this, obj, &sink_);
    obj_serializer.SerializeDeferred();
  });
  sink_.Put(kSynchronize, "Finished with deferred objects");
}

void Serializer::SerializeObject(Handle<HeapObject> obj, SlotType slot_type) {
  // ThinStrings are just an indirection to an internalized string, so elide the
  // indirection and serialize the actual string directly.
  if (IsThinString(*obj, isolate())) {
    obj = handle(Cast<ThinString>(*obj)->actual(), isolate());
  } else if (IsCode(*obj, isolate())) {
    Tagged<Code> code = Cast<Code>(*obj);
    // The only expected Code objects here are baseline code and builtins.
    if (code->kind() == CodeKind::BASELINE) {
      // For now just serialize the BytecodeArray instead of baseline code.
      // TODO(v8:11429,pthier): Handle Baseline code in cases we want to
      // serialize it.
      obj = handle(code->bytecode_or_interpreter_data(), isolate());
    } else {
      CHECK(code->is_builtin());
    }
  }
  SerializeObjectImpl(obj, slot_type);
}

bool Serializer::MustBeDeferred(Tagged<HeapObject> object) { return false; }

void Serializer::VisitRootPointers(Root root, const char* description,
                                   FullObjectSlot start, FullObjectSlot end) {
  for (FullObjectSlot current = start; current < end; ++current) {
    SerializeRootObject(current);
  }
}

void Serializer::SerializeRootObject(FullObjectSlot slot) {
  Tagged<Object> o = *slot;
  if (IsSmi(o)) {
    PutSmiRoot(slot);
  } else {
    SerializeObject(Handle<HeapObject>(slot.location()), SlotType::kAnySlot);
  }
}

#ifdef DEBUG
void Serializer::PrintStack() { PrintStack(std::cout); }

void Serializer::PrintStack(std::ostream& out) {
  for (const auto o : stack_) {
    Print(*o, out);
    out << "\n";
  }
}
#endif  // DEBUG

bool Serializer::SerializeRoot(Tagged<HeapObject> obj) {
  RootIndex root_index;
  // Derived serializers are responsible for determining if the root has
  // actually been serialized before calling this.
  if (root_index_map()->Lookup(obj, &root_index)) {
    PutRoot(root_index);
    return true;
  }
  return false;
}

bool Serializer::SerializeHotObject(Tagged<HeapObject> obj) {
  DisallowGarbageCollection no_gc;
  // Encode a reference to a hot object by its index in the working set.
  int index = hot_objects_.Find(obj);
  if (index == HotObjectsList::kNotFound) return false;
  DCHECK(index >= 0 && index < kHotObjectCount);
  if (v8_flags.trace_serializer) {
    PrintF(" Encoding hot object %d:", index);
    ShortPrint(obj);
    PrintF("\n");
  }
  sink_.Put(HotObject::Encode(index), "HotObject");
  return true;
}

bool Serializer::SerializeBackReference(Tagged<HeapObject> obj) {
  DisallowGarbageCollection no_gc;
  const SerializerReference* reference = reference_map_.LookupReference(obj);
  if (reference == nullptr) return false;
  // Encode the location of an already deserialized object in order to write
  // its location into a later object. We can encode the location as an
  // offset fromthe start of the deserialized objects or as an offset
  // backwards from the current allocation pointer.
  if (reference->is_attached_reference()) {
    if (v8_flags.trace_serializer) {
      PrintF(" Encoding attached reference %d\n",
             reference->attached_reference_index());
    }
    PutAttachedReference(*reference);
  } else {
    DCHECK(reference->is_back_reference());
    if (v8_flags.trace_serializer) {
      PrintF(" Encoding back reference to: ");
      ShortPrint(obj);
      PrintF("\n");
    }

    sink_.Put(kBackref, "Backref");
    PutBackReference(obj, *reference);
  }
  return true;
}

bool Serializer::SerializePendingObject(Tagged<HeapObject> obj) {
  PendingObjectReferences* refs_to_object =
      forward_refs_per_pending_object_.Find(obj);
  if (refs_to_object == nullptr) {
    return false;
  }
  PutPendingForwardReference(*refs_to_object);
  return true;
}

bool Serializer::ObjectIsBytecodeHandler(Tagged<HeapObject> obj) const {
  if (!IsCode(obj)) return false;
  return (Cast<Code>(obj)->kind() == CodeKind::BYTECODE_HANDLER);
}

void Serializer::PutRoot(RootIndex root) {
  DisallowGarbageCollection no_gc;
  int root_index = static_cast<int>(root);
  Tagged<HeapObject> object = Cast<HeapObject>(isolate()->root(root));
  if (v8_flags.trace_serializer) {
    PrintF(" Encoding root %d:", root_index);
    ShortPrint(object);
    PrintF("\n");
  }

  // Assert that the first 32 root array items are a conscious choice. They are
  // chosen so that the most common ones can be encoded more efficiently.
  static_assert(static_cast<int>(RootIndex::kArgumentsMarker) ==
                kRootArrayConstantsCount - 1);

  // TODO(ulan): Check that it works with young large objects.
  if (root_index < kRootArrayConstantsCount &&
      !HeapLayout::InYoungGeneration(object)) {
    sink_.Put(RootArrayConstant::Encode(root), "RootConstant");
  } else {
    sink_.Put(kRootArray, "RootSerialization");
    sink_.PutUint30(root_index, "root_index");
    hot_objects_.Add(object);
  }
}

void Serializer::PutSmiRoot(FullObjectSlot slot) {
  // Serializing a smi root in compressed pointer builds will serialize the
  // full object slot (of kSystemPointerSize) to avoid complications during
  // deserialization (endianness or smi sequences).
  static_assert(decltype(slot)::kSlotDataSize == sizeof(Address));
  static_assert(decltype(slot)::kSlotDataSize == kSystemPointerSize);
  static constexpr int bytes_to_output = decltype(slot)::kSlotDataSize;
  static constexpr int size_in_tagged = bytes_to_output >> kTaggedSizeLog2;
  sink_.Put(FixedRawDataWithSize::Encode(size_in_tagged), "Smi");

  Address raw_value = Cast<Smi>(*slot).ptr();
  const uint8_t* raw_value_as_bytes =
      reinterpret_cast<const uint8_t*>(&raw_value);
  sink_.PutRaw(raw_value_as_bytes, bytes_to_output, "Bytes");
}

void Serializer::PutBackReference(Tagged<HeapObject> object,
                                  SerializerReference reference) {
  DCHECK_EQ(object, *back_refs_[reference.back_ref_index()]);
  sink_.PutUint30(reference.back_ref_index(), "BackRefIndex");
  hot_objects_.Add(object);
}

void Serializer::PutAttachedReference(SerializerReference reference) {
  DCHECK(reference.is_attached_reference());
  sink_.Put(kAttachedReference, "AttachedRef");
  sink_.PutUint30(reference.attached_reference_index(), "AttachedRefIndex");
}

void Serializer::PutRepeatRoot(int repeat_count, RootIndex root_index) {
  if (repeat_count <= kLastEncodableFixedRepeatRootCount) {
    sink_.Put(FixedRepeatRootWithCount::Encode(repeat_count),
              "FixedRepeatRoot");
  } else {
    sink_.Put(kVariableRepeatRoot, "VariableRepeatRoot");
    sink_.PutUint30(VariableRepeatRootCount::Encode(repeat_count),
                    "repeat count");
  }
  DCHECK_LE(static_cast<uint32_t>(root_index), UINT8_MAX);
  sink_.Put(static_cast<uint8_t>(root_index), "root index");
}

void Serializer::PutPendingForwardReference(PendingObjectReferences& refs) {
  sink_.Put(kRegisterPendingForwardRef, "RegisterPendingForwardRef");
  unresolved_forward_refs_++;
  // Register the current slot with the pending object.
  int forward_ref_id = next_forward_ref_id_++;
  if (refs == nullptr) {
    // The IdentityMap holding the pending object reference vectors does not
    // support non-trivial types; in particular it doesn't support destructors
    // on values. So, we manually allocate a vector with new, and delete it when
    // resolving the pending object.
    refs = new std::vector<int>();
  }
  refs->push_back(forward_ref_id);
}

void Serializer::ResolvePendingForwardReference(int forward_reference_id) {
  sink_.Put(kResolvePendingForwardRef, "ResolvePendingForwardRef");
  sink_.PutUint30(forward_reference_id, "with this index");
  unresolved_forward_refs_--;

  // If there are no more unresolved forward refs, reset the forward ref id to
  // zero so that future forward refs compress better.
  if (unresolved_forward_refs_ == 0) {
    next_forward_ref_id_ = 0;
  }
}

ExternalReferenceEncoder::Value Serializer::EncodeExternalReference(
    Address addr) {
  Maybe<ExternalReferenceEncoder::Value> result =
      external_reference_encoder_.TryEncode(addr);
  if (result.IsNothing()) {
#ifdef DEBUG
    PrintStack(std::cerr);
#endif
    void* addr_ptr = reinterpret_cast<void*>(addr);
    v8::base::OS::PrintError("Unknown external reference %p.\n", addr_ptr);
    v8::base::OS::PrintError("%s\n",
                             ExternalReferenceTable::ResolveSymbol(addr_ptr));
    v8::base::OS::Abort();
  }
  return result.FromJust();
}

void Serializer::RegisterObjectIsPending(Tagged<HeapObject> obj) {
  DisallowGarbageCollection no_gc;
  if (IsNotMappedSymbol(obj)) return;

  // Add the given object to the pending objects -> forward refs map.
  auto find_result = forward_refs_per_pending_object_.FindOrInsert(obj);
  USE(find_result);

  // If the above emplace didn't actually add the object, then the object must
  // already have been registered pending by deferring. It might not be in the
  // deferred objects queue though, since it may be the very object we just
  // popped off that queue, so just check that it can be deferred.
  DCHECK_IMPLIES(find_result.already_exists, *find_result.entry != nullptr);
  DCHECK_IMPLIES(find_result.already_exists,
                 CanBeDeferred(obj, SlotType::kAnySlot));
}

void Serializer::ResolvePendingObject(Tagged<HeapObject> obj) {
  DisallowGarbageCollection no_gc;
  if (IsNotMappedSymbol(obj)) return;

  std::vector<int>* refs;
  CHECK(forward_refs_per_pending_object_.Delete(obj, &refs));
  if (refs) {
    for (int index : *refs) {
      ResolvePendingForwardReference(index);
    }
    // See PutPendingForwardReference -- we have to manually manage the memory
    // of non-trivial IdentityMap values.
    delete refs;
  }
}

void Serializer::Pad(int padding_offset) {
  // The non-branching GetInt will read up to 3 bytes too far, so we need
  // to pad the snapshot to make sure we don't read over the end.
  for (unsigned i = 0; i < sizeof(int32_t) - 1; i++) {
    sink_.Put(kNop, "Padding");
  }
  // Pad up to pointer size for checksum.
  while (!IsAligned(sink_.Position() + padding_offset, kPointerAlignment)) {
    sink_.Put(kNop, "Padding");
  }
}

void Serializer::InitializeCodeAddressMap() {
  isolate_->InitializeLoggingAndCounters();
  code_address_map_ = std::make_unique<CodeAddressMap>(isolate_);
}

Tagged<InstructionStream> Serializer::CopyCode(
    Tagged<InstructionStream> istream) {
  code_buffer_.clear();  // Clear buffer without deleting backing store.
  // Add InstructionStream padding which is usually added by the allocator.
  // While this doesn't guarantee the exact same alignment, it's enough to
  // fulfill the alignment requirements of writes during relocation.
  code_buffer_.resize(InstructionStream::kCodeAlignmentMinusCodeHeader);
  int size = istream->Size();
  code_buffer_.insert(code_buffer_.end(),
                      reinterpret_cast<uint8_t*>(istream.address()),
                      reinterpret_cast<uint8_t*>(istream.address() + size));
  // When pointer compression is enabled the checked cast will try to
  // decompress map field of off-heap InstructionStream object.
  return UncheckedCast<InstructionStream>(
      HeapObject::FromAddress(reinterpret_cast<Address>(
          &code_buffer_[InstructionStream::kCodeAlignmentMinusCodeHeader])));
}

void Serializer::ObjectSerializer::SerializePrologue(SnapshotSpace space,
                                                     int size,
                                                     Tagged<Map> map) {
  if (serializer_->code_address_map_) {
    const char* code_name =
        serializer_->code_address_map_->Lookup(object_->address());
    LOG(serializer_->isolate_,
        CodeNameEvent(object_->address(), sink_->Position(), code_name));
  }

  if (map.SafeEquals(*object_)) {
    if (map == ReadOnlyRoots(isolate()).meta_map()) {
      DCHECK_EQ(space, SnapshotSpace::kReadOnlyHeap);
      sink_->Put(kNewContextlessMetaMap, "NewContextlessMetaMap");
    } else {
      DCHECK_EQ(space, SnapshotSpace::kOld);
      DCHECK(IsContext(map->native_context_or_null()));
      sink_->Put(kNewContextfulMetaMap, "NewContextfulMetaMap");

      // Defer serialization of the native context in order to break
      // a potential cycle through the map slot:
      //   MAP -> meta map -> NativeContext -> ... -> MAP
      // Otherwise it'll be a "forward ref to a map" problem: deserializer
      // will not be able to create {obj} because {MAP} is not deserialized yet.
      Tagged<NativeContext> native_context = map->native_context();

      // Sanity check - the native context must not be serialized yet since
      // it has a contextful map and thus the respective meta map must be
      // serialized first. So we don't have to search the native context
      // among the back refs before adding it to the deferred queue.
      DCHECK_NULL(
          serializer_->reference_map()->LookupReference(native_context));

      if (!serializer_->forward_refs_per_pending_object_.Find(native_context)) {
        serializer_->RegisterObjectIsPending(native_context);
        serializer_->QueueDeferredObject(native_context);
      }
    }
    DCHECK_EQ(size, Map::kSize);
  } else {
    sink_->Put(NewObject::Encode(space), "NewObject");

    // TODO(leszeks): Skip this when the map has a fixed size.
    sink_->PutUint30(size >> kObjectAlignmentBits, "ObjectSizeInWords");

    // Until the space for the object is allocated, it is considered "pending".
    serializer_->RegisterObjectIsPending(*object_);

    // Serialize map (first word of the object) before anything else, so that
    // the deserializer can access it when allocating. Make sure that the map
    // is known to be being serialized for the map slot, so that it is not
    // deferred.
    DCHECK(IsMap(map));
    serializer_->SerializeObject(handle(map, isolate()), SlotType::kMapSlot);

    // Make sure the map serialization didn't accidentally recursively serialize
    // this object.
    DCHECK_IMPLIES(
        !serializer_->IsNotMappedSymbol(*object_),
        serializer_->reference_map()->LookupReference(object_) == nullptr);

    // To support deserializing pending objects referenced through indirect
    // pointers, we need to make sure that the 'self' indirect pointer is
    // initialized before the pending reference is resolved. Otherwise, the
    // object cannot be referenced.
    if (V8_ENABLE_SANDBOX_BOOL && IsExposedTrustedObject(*object_)) {
      sink_->Put(kInitializeSelfIndirectPointer,
                 "InitializeSelfIndirectPointer");
    }

    // Now that the object is allocated, we can resolve pending references to
    // it.
    serializer_->ResolvePendingObject(*object_);
  }

  if (v8_flags.serialization_statistics) {
    serializer_->CountAllocation(object_->map(), size, space);
  }

  // The snapshot should only contain internalized strings (since these end up
  // in RO space). If this DCHECK fails, allocate the object_ String through
  // Factory::InternalizeString instead.
  // TODO(jgruber,v8:13789): Try to enable this DCHECK once custom snapshots
  // can extend RO space. We may have to do a pass over the heap prior to
  // serialization that in-place converts all strings to internalized strings.
  // DCHECK_IMPLIES(object_->IsString(), object_->IsInternalizedString());

  // Mark this object as already serialized, and add it to the reference map so
  // that it can be accessed by backreference by future objects.
  serializer_->num_back_refs_++;
#ifdef DEBUG
  serializer_->back_refs_.Push(*object_);
  DCHECK_EQ(serializer_->back_refs_.size(), serializer_->num_back_refs_);
#endif
  if (!serializer_->IsNotMappedSymbol(*object_)) {
    // Only add the object to the map if it's not not_mapped_symbol, else
    // the reference IdentityMap has issues. We don't expect to have back
    // references to the not_mapped_symbol anyway, so it's fine.
    SerializerReference back_reference =
        SerializerReference::BackReference(serializer_->num_back_refs_ - 1);
    serializer_->reference_map()->Add(*object_, back_reference);
    DCHECK_EQ(*object_,
              *serializer_->back_refs_[back_reference.back_ref_index()]);
    DCHECK_EQ(back_reference.back_ref_index(), serializer_->reference_map()
                                                   ->LookupReference(object_)
                                                   ->back_ref_index());
  }
}

uint32_t Serializer::ObjectSerializer::SerializeBackingStore(
    void* backing_store, uint32_t byte_length,
    Maybe<uint32_t> max_byte_length) {
  DisallowGarbageCollection no_gc;
  const SerializerReference* reference_ptr =
      serializer_->reference_map()->LookupBackingStore(backing_store);

  // Serialize the off-heap backing store.
  if (reference_ptr) {
    return reference_ptr->off_heap_backing_store_index();
  }
  if (max_byte_length.IsJust()) {
    sink_->Put(kOffHeapResizableBackingStore,
               "Off-heap resizable backing store");
  } else {
    sink_->Put(kOffHeapBackingStore, "Off-heap backing store");
  }
  sink_->PutUint32(byte_length, "length");
  if (max_byte_length.IsJust()) {
    sink_->PutUint32(max_byte_length.FromJust(), "max length");
  }
  sink_->PutRaw(static_cast<uint8_t*>(backing_store), byte_length,
                "BackingStore");
  DCHECK_NE(0, serializer_->seen_backing_stores_index_);
  SerializerReference reference =
      SerializerReference::OffHeapBackingStoreReference(
          serializer_->seen_backing_stores_index_++);
  // Mark this backing store as already serialized.
  serializer_->reference_map()->AddBackingStore(backing_store, reference);
  return reference.off_heap_backing_store_index();
}

void Serializer::ObjectSerializer::SerializeJSTypedArray() {
  {
    DisallowGarbageCollection no_gc;
    Tagged<JSTypedArray> typed_array = Cast<JSTypedArray>(*object_);
    if (typed_array->is_on_heap()) {
      typed_array->RemoveExternalPointerCompensationForSerialization(isolate());
    } else {
      if (!typed_array->IsDetachedOrOutOfBounds()) {
        // Explicitly serialize the backing store now.
        Tagged<JSArrayBuffer> buffer =
            Cast<JSArrayBuffer>(typed_array->buffer());
        // We cannot store byte_length or max_byte_length larger than uint32
        // range in the snapshot.
        size_t byte_length_size = buffer->GetByteLength();
        CHECK_LE(byte_length_size,
                 size_t{std::numeric_limits<uint32_t>::max()});
        uint32_t byte_length = static_cast<uint32_t>(byte_length_size);
        Maybe<uint32_t> max_byte_length = Nothing<uint32_t>();
        if (buffer->is_resizable_by_js()) {
          CHECK_LE(buffer->max_byte_length(),
                   std::numeric_limits<uint32_t>::max());
          max_byte_length =
              Just(static_cast<uint32_t>(buffer->max_byte_length()));
        }
        size_t byte_offset = typed_array->byte_offset();

        // We need to calculate the backing store from the data pointer
        // because the ArrayBuffer may already have been serialized.
        void* backing_store = reinterpret_cast<void*>(
            reinterpret_cast<Address>(typed_array->DataPtr()) - byte_offset);

        uint32_t ref =
            SerializeBackingStore(backing_store, byte_length, max_byte_length);
        typed_array->SetExternalBackingStoreRefForSerialization(ref);
      } else {
        typed_array->SetExternalBackingStoreRefForSerialization(0);
      }
    }
  }
  SerializeObject();
}

void Serializer::ObjectSerializer::SerializeJSArrayBuffer() {
  ArrayBufferExtension* extension;
  void* backing_store;
  {
    DisallowGarbageCollection no_gc;
    Tagged<JSArrayBuffer> buffer = Cast<JSArrayBuffer>(*object_);
    backing_store = buffer->backing_store();
    // We cannot store byte_length or max_byte_length larger than uint32 range
    // in the snapshot.
    CHECK_LE(buffer->byte_length(), std::numeric_limits<uint32_t>::max());
    uint32_t byte_length = static_cast<uint32_t>(buffer->byte_length());
    Maybe<uint32_t> max_byte_length = Nothing<uint32_t>();
    if (buffer->is_resizable_by_js()) {
      CHECK_LE(buffer->max_byte_length(), std::numeric_limits<uint32_t>::max());
      
### 提示词
```
这是目录为v8/src/snapshot/serializer.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/snapshot/serializer.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/snapshot/serializer.h"

#include "include/v8-internal.h"
#include "src/codegen/assembler-inl.h"
#include "src/common/globals.h"
#include "src/handles/global-handles-inl.h"
#include "src/heap/heap-inl.h"  // For Space::identity().
#include "src/heap/mutable-page-metadata-inl.h"
#include "src/heap/read-only-heap.h"
#include "src/heap/visit-object.h"
#include "src/objects/code.h"
#include "src/objects/descriptor-array.h"
#include "src/objects/instance-type-checker.h"
#include "src/objects/instance-type.h"
#include "src/objects/js-array-buffer-inl.h"
#include "src/objects/map.h"
#include "src/objects/objects-body-descriptors-inl.h"
#include "src/objects/slots-inl.h"
#include "src/objects/slots.h"
#include "src/objects/smi.h"
#include "src/sandbox/js-dispatch-table-inl.h"
#include "src/snapshot/embedded/embedded-data.h"
#include "src/snapshot/serializer-deserializer.h"
#include "src/snapshot/serializer-inl.h"

namespace v8 {
namespace internal {

Serializer::Serializer(Isolate* isolate, Snapshot::SerializerFlags flags)
    : isolate_(isolate),
#if V8_COMPRESS_POINTERS
      cage_base_(isolate),
#endif  // V8_COMPRESS_POINTERS
      hot_objects_(isolate->heap()),
      reference_map_(isolate),
      external_reference_encoder_(isolate),
      root_index_map_(isolate),
      deferred_objects_(isolate->heap()),
      forward_refs_per_pending_object_(isolate->heap()),
      flags_(flags)
#ifdef DEBUG
      ,
      back_refs_(isolate->heap()),
      stack_(isolate->heap())
#endif
{
#ifdef VERBOSE_SERIALIZATION_STATISTICS
  if (v8_flags.serialization_statistics) {
    for (int space = 0; space < kNumberOfSnapshotSpaces; ++space) {
      // Value-initialized to 0.
      instance_type_count_[space] = std::make_unique<int[]>(kInstanceTypes);
      instance_type_size_[space] = std::make_unique<size_t[]>(kInstanceTypes);
    }
  }
#endif  // VERBOSE_SERIALIZATION_STATISTICS
}

#ifdef DEBUG
void Serializer::PopStack() { stack_.Pop(); }
#endif

void Serializer::CountAllocation(Tagged<Map> map, int size,
                                 SnapshotSpace space) {
  DCHECK(v8_flags.serialization_statistics);

  const int space_number = static_cast<int>(space);
  allocation_size_[space_number] += size;
#ifdef VERBOSE_SERIALIZATION_STATISTICS
  int instance_type = map->instance_type();
  instance_type_count_[space_number][instance_type]++;
  instance_type_size_[space_number][instance_type] += size;
#endif  // VERBOSE_SERIALIZATION_STATISTICS
}

int Serializer::TotalAllocationSize() const {
  int sum = 0;
  for (int space = 0; space < kNumberOfSnapshotSpaces; space++) {
    sum += allocation_size_[space];
  }
  return sum;
}

namespace {

const char* ToString(SnapshotSpace space) {
  switch (space) {
    case SnapshotSpace::kReadOnlyHeap:
      return "ReadOnlyHeap";
    case SnapshotSpace::kOld:
      return "Old";
    case SnapshotSpace::kCode:
      return "Code";
    case SnapshotSpace::kTrusted:
      return "Trusted";
  }
}

}  // namespace

void Serializer::OutputStatistics(const char* name) {
  if (!v8_flags.serialization_statistics) return;

  PrintF("%s:\n", name);
  if (!serializer_tracks_serialization_statistics()) {
    PrintF("  <serialization statistics are not tracked>\n");
    return;
  }

  PrintF("  Spaces (bytes):\n");

  static constexpr SnapshotSpace kAllSnapshotSpaces[] = {
      SnapshotSpace::kReadOnlyHeap,
      SnapshotSpace::kOld,
      SnapshotSpace::kCode,
  };

  for (SnapshotSpace space : kAllSnapshotSpaces) {
    PrintF("%16s", ToString(space));
  }
  PrintF("\n");

  for (SnapshotSpace space : kAllSnapshotSpaces) {
    PrintF("%16zu", allocation_size_[static_cast<int>(space)]);
  }
  PrintF("\n");

#ifdef VERBOSE_SERIALIZATION_STATISTICS
  PrintF("  Instance types (count and bytes):\n");
#define PRINT_INSTANCE_TYPE(Name)                                           \
  for (SnapshotSpace space : kAllSnapshotSpaces) {                          \
    const int space_i = static_cast<int>(space);                            \
    if (instance_type_count_[space_i][Name]) {                              \
      PrintF("%10d %10zu  %-10s %s\n", instance_type_count_[space_i][Name], \
             instance_type_size_[space_i][Name], ToString(space), #Name);   \
    }                                                                       \
  }
  INSTANCE_TYPE_LIST(PRINT_INSTANCE_TYPE)
#undef PRINT_INSTANCE_TYPE
  PrintF("\n");
#endif  // VERBOSE_SERIALIZATION_STATISTICS
}

void Serializer::SerializeDeferredObjects() {
  if (v8_flags.trace_serializer) {
    PrintF("Serializing deferred objects\n");
  }
  WHILE_WITH_HANDLE_SCOPE(isolate(), !deferred_objects_.empty(), {
    Handle<HeapObject> obj = handle(deferred_objects_.Pop(), isolate());

    ObjectSerializer obj_serializer(this, obj, &sink_);
    obj_serializer.SerializeDeferred();
  });
  sink_.Put(kSynchronize, "Finished with deferred objects");
}

void Serializer::SerializeObject(Handle<HeapObject> obj, SlotType slot_type) {
  // ThinStrings are just an indirection to an internalized string, so elide the
  // indirection and serialize the actual string directly.
  if (IsThinString(*obj, isolate())) {
    obj = handle(Cast<ThinString>(*obj)->actual(), isolate());
  } else if (IsCode(*obj, isolate())) {
    Tagged<Code> code = Cast<Code>(*obj);
    // The only expected Code objects here are baseline code and builtins.
    if (code->kind() == CodeKind::BASELINE) {
      // For now just serialize the BytecodeArray instead of baseline code.
      // TODO(v8:11429,pthier): Handle Baseline code in cases we want to
      // serialize it.
      obj = handle(code->bytecode_or_interpreter_data(), isolate());
    } else {
      CHECK(code->is_builtin());
    }
  }
  SerializeObjectImpl(obj, slot_type);
}

bool Serializer::MustBeDeferred(Tagged<HeapObject> object) { return false; }

void Serializer::VisitRootPointers(Root root, const char* description,
                                   FullObjectSlot start, FullObjectSlot end) {
  for (FullObjectSlot current = start; current < end; ++current) {
    SerializeRootObject(current);
  }
}

void Serializer::SerializeRootObject(FullObjectSlot slot) {
  Tagged<Object> o = *slot;
  if (IsSmi(o)) {
    PutSmiRoot(slot);
  } else {
    SerializeObject(Handle<HeapObject>(slot.location()), SlotType::kAnySlot);
  }
}

#ifdef DEBUG
void Serializer::PrintStack() { PrintStack(std::cout); }

void Serializer::PrintStack(std::ostream& out) {
  for (const auto o : stack_) {
    Print(*o, out);
    out << "\n";
  }
}
#endif  // DEBUG

bool Serializer::SerializeRoot(Tagged<HeapObject> obj) {
  RootIndex root_index;
  // Derived serializers are responsible for determining if the root has
  // actually been serialized before calling this.
  if (root_index_map()->Lookup(obj, &root_index)) {
    PutRoot(root_index);
    return true;
  }
  return false;
}

bool Serializer::SerializeHotObject(Tagged<HeapObject> obj) {
  DisallowGarbageCollection no_gc;
  // Encode a reference to a hot object by its index in the working set.
  int index = hot_objects_.Find(obj);
  if (index == HotObjectsList::kNotFound) return false;
  DCHECK(index >= 0 && index < kHotObjectCount);
  if (v8_flags.trace_serializer) {
    PrintF(" Encoding hot object %d:", index);
    ShortPrint(obj);
    PrintF("\n");
  }
  sink_.Put(HotObject::Encode(index), "HotObject");
  return true;
}

bool Serializer::SerializeBackReference(Tagged<HeapObject> obj) {
  DisallowGarbageCollection no_gc;
  const SerializerReference* reference = reference_map_.LookupReference(obj);
  if (reference == nullptr) return false;
  // Encode the location of an already deserialized object in order to write
  // its location into a later object.  We can encode the location as an
  // offset fromthe start of the deserialized objects or as an offset
  // backwards from the current allocation pointer.
  if (reference->is_attached_reference()) {
    if (v8_flags.trace_serializer) {
      PrintF(" Encoding attached reference %d\n",
             reference->attached_reference_index());
    }
    PutAttachedReference(*reference);
  } else {
    DCHECK(reference->is_back_reference());
    if (v8_flags.trace_serializer) {
      PrintF(" Encoding back reference to: ");
      ShortPrint(obj);
      PrintF("\n");
    }

    sink_.Put(kBackref, "Backref");
    PutBackReference(obj, *reference);
  }
  return true;
}

bool Serializer::SerializePendingObject(Tagged<HeapObject> obj) {
  PendingObjectReferences* refs_to_object =
      forward_refs_per_pending_object_.Find(obj);
  if (refs_to_object == nullptr) {
    return false;
  }
  PutPendingForwardReference(*refs_to_object);
  return true;
}

bool Serializer::ObjectIsBytecodeHandler(Tagged<HeapObject> obj) const {
  if (!IsCode(obj)) return false;
  return (Cast<Code>(obj)->kind() == CodeKind::BYTECODE_HANDLER);
}

void Serializer::PutRoot(RootIndex root) {
  DisallowGarbageCollection no_gc;
  int root_index = static_cast<int>(root);
  Tagged<HeapObject> object = Cast<HeapObject>(isolate()->root(root));
  if (v8_flags.trace_serializer) {
    PrintF(" Encoding root %d:", root_index);
    ShortPrint(object);
    PrintF("\n");
  }

  // Assert that the first 32 root array items are a conscious choice. They are
  // chosen so that the most common ones can be encoded more efficiently.
  static_assert(static_cast<int>(RootIndex::kArgumentsMarker) ==
                kRootArrayConstantsCount - 1);

  // TODO(ulan): Check that it works with young large objects.
  if (root_index < kRootArrayConstantsCount &&
      !HeapLayout::InYoungGeneration(object)) {
    sink_.Put(RootArrayConstant::Encode(root), "RootConstant");
  } else {
    sink_.Put(kRootArray, "RootSerialization");
    sink_.PutUint30(root_index, "root_index");
    hot_objects_.Add(object);
  }
}

void Serializer::PutSmiRoot(FullObjectSlot slot) {
  // Serializing a smi root in compressed pointer builds will serialize the
  // full object slot (of kSystemPointerSize) to avoid complications during
  // deserialization (endianness or smi sequences).
  static_assert(decltype(slot)::kSlotDataSize == sizeof(Address));
  static_assert(decltype(slot)::kSlotDataSize == kSystemPointerSize);
  static constexpr int bytes_to_output = decltype(slot)::kSlotDataSize;
  static constexpr int size_in_tagged = bytes_to_output >> kTaggedSizeLog2;
  sink_.Put(FixedRawDataWithSize::Encode(size_in_tagged), "Smi");

  Address raw_value = Cast<Smi>(*slot).ptr();
  const uint8_t* raw_value_as_bytes =
      reinterpret_cast<const uint8_t*>(&raw_value);
  sink_.PutRaw(raw_value_as_bytes, bytes_to_output, "Bytes");
}

void Serializer::PutBackReference(Tagged<HeapObject> object,
                                  SerializerReference reference) {
  DCHECK_EQ(object, *back_refs_[reference.back_ref_index()]);
  sink_.PutUint30(reference.back_ref_index(), "BackRefIndex");
  hot_objects_.Add(object);
}

void Serializer::PutAttachedReference(SerializerReference reference) {
  DCHECK(reference.is_attached_reference());
  sink_.Put(kAttachedReference, "AttachedRef");
  sink_.PutUint30(reference.attached_reference_index(), "AttachedRefIndex");
}

void Serializer::PutRepeatRoot(int repeat_count, RootIndex root_index) {
  if (repeat_count <= kLastEncodableFixedRepeatRootCount) {
    sink_.Put(FixedRepeatRootWithCount::Encode(repeat_count),
              "FixedRepeatRoot");
  } else {
    sink_.Put(kVariableRepeatRoot, "VariableRepeatRoot");
    sink_.PutUint30(VariableRepeatRootCount::Encode(repeat_count),
                    "repeat count");
  }
  DCHECK_LE(static_cast<uint32_t>(root_index), UINT8_MAX);
  sink_.Put(static_cast<uint8_t>(root_index), "root index");
}

void Serializer::PutPendingForwardReference(PendingObjectReferences& refs) {
  sink_.Put(kRegisterPendingForwardRef, "RegisterPendingForwardRef");
  unresolved_forward_refs_++;
  // Register the current slot with the pending object.
  int forward_ref_id = next_forward_ref_id_++;
  if (refs == nullptr) {
    // The IdentityMap holding the pending object reference vectors does not
    // support non-trivial types; in particular it doesn't support destructors
    // on values. So, we manually allocate a vector with new, and delete it when
    // resolving the pending object.
    refs = new std::vector<int>();
  }
  refs->push_back(forward_ref_id);
}

void Serializer::ResolvePendingForwardReference(int forward_reference_id) {
  sink_.Put(kResolvePendingForwardRef, "ResolvePendingForwardRef");
  sink_.PutUint30(forward_reference_id, "with this index");
  unresolved_forward_refs_--;

  // If there are no more unresolved forward refs, reset the forward ref id to
  // zero so that future forward refs compress better.
  if (unresolved_forward_refs_ == 0) {
    next_forward_ref_id_ = 0;
  }
}

ExternalReferenceEncoder::Value Serializer::EncodeExternalReference(
    Address addr) {
  Maybe<ExternalReferenceEncoder::Value> result =
      external_reference_encoder_.TryEncode(addr);
  if (result.IsNothing()) {
#ifdef DEBUG
    PrintStack(std::cerr);
#endif
    void* addr_ptr = reinterpret_cast<void*>(addr);
    v8::base::OS::PrintError("Unknown external reference %p.\n", addr_ptr);
    v8::base::OS::PrintError("%s\n",
                             ExternalReferenceTable::ResolveSymbol(addr_ptr));
    v8::base::OS::Abort();
  }
  return result.FromJust();
}

void Serializer::RegisterObjectIsPending(Tagged<HeapObject> obj) {
  DisallowGarbageCollection no_gc;
  if (IsNotMappedSymbol(obj)) return;

  // Add the given object to the pending objects -> forward refs map.
  auto find_result = forward_refs_per_pending_object_.FindOrInsert(obj);
  USE(find_result);

  // If the above emplace didn't actually add the object, then the object must
  // already have been registered pending by deferring. It might not be in the
  // deferred objects queue though, since it may be the very object we just
  // popped off that queue, so just check that it can be deferred.
  DCHECK_IMPLIES(find_result.already_exists, *find_result.entry != nullptr);
  DCHECK_IMPLIES(find_result.already_exists,
                 CanBeDeferred(obj, SlotType::kAnySlot));
}

void Serializer::ResolvePendingObject(Tagged<HeapObject> obj) {
  DisallowGarbageCollection no_gc;
  if (IsNotMappedSymbol(obj)) return;

  std::vector<int>* refs;
  CHECK(forward_refs_per_pending_object_.Delete(obj, &refs));
  if (refs) {
    for (int index : *refs) {
      ResolvePendingForwardReference(index);
    }
    // See PutPendingForwardReference -- we have to manually manage the memory
    // of non-trivial IdentityMap values.
    delete refs;
  }
}

void Serializer::Pad(int padding_offset) {
  // The non-branching GetInt will read up to 3 bytes too far, so we need
  // to pad the snapshot to make sure we don't read over the end.
  for (unsigned i = 0; i < sizeof(int32_t) - 1; i++) {
    sink_.Put(kNop, "Padding");
  }
  // Pad up to pointer size for checksum.
  while (!IsAligned(sink_.Position() + padding_offset, kPointerAlignment)) {
    sink_.Put(kNop, "Padding");
  }
}

void Serializer::InitializeCodeAddressMap() {
  isolate_->InitializeLoggingAndCounters();
  code_address_map_ = std::make_unique<CodeAddressMap>(isolate_);
}

Tagged<InstructionStream> Serializer::CopyCode(
    Tagged<InstructionStream> istream) {
  code_buffer_.clear();  // Clear buffer without deleting backing store.
  // Add InstructionStream padding which is usually added by the allocator.
  // While this doesn't guarantee the exact same alignment, it's enough to
  // fulfill the alignment requirements of writes during relocation.
  code_buffer_.resize(InstructionStream::kCodeAlignmentMinusCodeHeader);
  int size = istream->Size();
  code_buffer_.insert(code_buffer_.end(),
                      reinterpret_cast<uint8_t*>(istream.address()),
                      reinterpret_cast<uint8_t*>(istream.address() + size));
  // When pointer compression is enabled the checked cast will try to
  // decompress map field of off-heap InstructionStream object.
  return UncheckedCast<InstructionStream>(
      HeapObject::FromAddress(reinterpret_cast<Address>(
          &code_buffer_[InstructionStream::kCodeAlignmentMinusCodeHeader])));
}

void Serializer::ObjectSerializer::SerializePrologue(SnapshotSpace space,
                                                     int size,
                                                     Tagged<Map> map) {
  if (serializer_->code_address_map_) {
    const char* code_name =
        serializer_->code_address_map_->Lookup(object_->address());
    LOG(serializer_->isolate_,
        CodeNameEvent(object_->address(), sink_->Position(), code_name));
  }

  if (map.SafeEquals(*object_)) {
    if (map == ReadOnlyRoots(isolate()).meta_map()) {
      DCHECK_EQ(space, SnapshotSpace::kReadOnlyHeap);
      sink_->Put(kNewContextlessMetaMap, "NewContextlessMetaMap");
    } else {
      DCHECK_EQ(space, SnapshotSpace::kOld);
      DCHECK(IsContext(map->native_context_or_null()));
      sink_->Put(kNewContextfulMetaMap, "NewContextfulMetaMap");

      // Defer serialization of the native context in order to break
      // a potential cycle through the map slot:
      //   MAP -> meta map -> NativeContext -> ... -> MAP
      // Otherwise it'll be a "forward ref to a map" problem: deserializer
      // will not be able to create {obj} because {MAP} is not deserialized yet.
      Tagged<NativeContext> native_context = map->native_context();

      // Sanity check - the native context must not be serialized yet since
      // it has a contextful map and thus the respective meta map must be
      // serialized first. So we don't have to search the native context
      // among the back refs before adding it to the deferred queue.
      DCHECK_NULL(
          serializer_->reference_map()->LookupReference(native_context));

      if (!serializer_->forward_refs_per_pending_object_.Find(native_context)) {
        serializer_->RegisterObjectIsPending(native_context);
        serializer_->QueueDeferredObject(native_context);
      }
    }
    DCHECK_EQ(size, Map::kSize);
  } else {
    sink_->Put(NewObject::Encode(space), "NewObject");

    // TODO(leszeks): Skip this when the map has a fixed size.
    sink_->PutUint30(size >> kObjectAlignmentBits, "ObjectSizeInWords");

    // Until the space for the object is allocated, it is considered "pending".
    serializer_->RegisterObjectIsPending(*object_);

    // Serialize map (first word of the object) before anything else, so that
    // the deserializer can access it when allocating. Make sure that the map
    // is known to be being serialized for the map slot, so that it is not
    // deferred.
    DCHECK(IsMap(map));
    serializer_->SerializeObject(handle(map, isolate()), SlotType::kMapSlot);

    // Make sure the map serialization didn't accidentally recursively serialize
    // this object.
    DCHECK_IMPLIES(
        !serializer_->IsNotMappedSymbol(*object_),
        serializer_->reference_map()->LookupReference(object_) == nullptr);

    // To support deserializing pending objects referenced through indirect
    // pointers, we need to make sure that the 'self' indirect pointer is
    // initialized before the pending reference is resolved. Otherwise, the
    // object cannot be referenced.
    if (V8_ENABLE_SANDBOX_BOOL && IsExposedTrustedObject(*object_)) {
      sink_->Put(kInitializeSelfIndirectPointer,
                 "InitializeSelfIndirectPointer");
    }

    // Now that the object is allocated, we can resolve pending references to
    // it.
    serializer_->ResolvePendingObject(*object_);
  }

  if (v8_flags.serialization_statistics) {
    serializer_->CountAllocation(object_->map(), size, space);
  }

  // The snapshot should only contain internalized strings (since these end up
  // in RO space). If this DCHECK fails, allocate the object_ String through
  // Factory::InternalizeString instead.
  // TODO(jgruber,v8:13789): Try to enable this DCHECK once custom snapshots
  // can extend RO space. We may have to do a pass over the heap prior to
  // serialization that in-place converts all strings to internalized strings.
  // DCHECK_IMPLIES(object_->IsString(), object_->IsInternalizedString());

  // Mark this object as already serialized, and add it to the reference map so
  // that it can be accessed by backreference by future objects.
  serializer_->num_back_refs_++;
#ifdef DEBUG
  serializer_->back_refs_.Push(*object_);
  DCHECK_EQ(serializer_->back_refs_.size(), serializer_->num_back_refs_);
#endif
  if (!serializer_->IsNotMappedSymbol(*object_)) {
    // Only add the object to the map if it's not not_mapped_symbol, else
    // the reference IdentityMap has issues. We don't expect to have back
    // references to the not_mapped_symbol anyway, so it's fine.
    SerializerReference back_reference =
        SerializerReference::BackReference(serializer_->num_back_refs_ - 1);
    serializer_->reference_map()->Add(*object_, back_reference);
    DCHECK_EQ(*object_,
              *serializer_->back_refs_[back_reference.back_ref_index()]);
    DCHECK_EQ(back_reference.back_ref_index(), serializer_->reference_map()
                                                   ->LookupReference(object_)
                                                   ->back_ref_index());
  }
}

uint32_t Serializer::ObjectSerializer::SerializeBackingStore(
    void* backing_store, uint32_t byte_length,
    Maybe<uint32_t> max_byte_length) {
  DisallowGarbageCollection no_gc;
  const SerializerReference* reference_ptr =
      serializer_->reference_map()->LookupBackingStore(backing_store);

  // Serialize the off-heap backing store.
  if (reference_ptr) {
    return reference_ptr->off_heap_backing_store_index();
  }
  if (max_byte_length.IsJust()) {
    sink_->Put(kOffHeapResizableBackingStore,
               "Off-heap resizable backing store");
  } else {
    sink_->Put(kOffHeapBackingStore, "Off-heap backing store");
  }
  sink_->PutUint32(byte_length, "length");
  if (max_byte_length.IsJust()) {
    sink_->PutUint32(max_byte_length.FromJust(), "max length");
  }
  sink_->PutRaw(static_cast<uint8_t*>(backing_store), byte_length,
                "BackingStore");
  DCHECK_NE(0, serializer_->seen_backing_stores_index_);
  SerializerReference reference =
      SerializerReference::OffHeapBackingStoreReference(
          serializer_->seen_backing_stores_index_++);
  // Mark this backing store as already serialized.
  serializer_->reference_map()->AddBackingStore(backing_store, reference);
  return reference.off_heap_backing_store_index();
}

void Serializer::ObjectSerializer::SerializeJSTypedArray() {
  {
    DisallowGarbageCollection no_gc;
    Tagged<JSTypedArray> typed_array = Cast<JSTypedArray>(*object_);
    if (typed_array->is_on_heap()) {
      typed_array->RemoveExternalPointerCompensationForSerialization(isolate());
    } else {
      if (!typed_array->IsDetachedOrOutOfBounds()) {
        // Explicitly serialize the backing store now.
        Tagged<JSArrayBuffer> buffer =
            Cast<JSArrayBuffer>(typed_array->buffer());
        // We cannot store byte_length or max_byte_length larger than uint32
        // range in the snapshot.
        size_t byte_length_size = buffer->GetByteLength();
        CHECK_LE(byte_length_size,
                 size_t{std::numeric_limits<uint32_t>::max()});
        uint32_t byte_length = static_cast<uint32_t>(byte_length_size);
        Maybe<uint32_t> max_byte_length = Nothing<uint32_t>();
        if (buffer->is_resizable_by_js()) {
          CHECK_LE(buffer->max_byte_length(),
                   std::numeric_limits<uint32_t>::max());
          max_byte_length =
              Just(static_cast<uint32_t>(buffer->max_byte_length()));
        }
        size_t byte_offset = typed_array->byte_offset();

        // We need to calculate the backing store from the data pointer
        // because the ArrayBuffer may already have been serialized.
        void* backing_store = reinterpret_cast<void*>(
            reinterpret_cast<Address>(typed_array->DataPtr()) - byte_offset);

        uint32_t ref =
            SerializeBackingStore(backing_store, byte_length, max_byte_length);
        typed_array->SetExternalBackingStoreRefForSerialization(ref);
      } else {
        typed_array->SetExternalBackingStoreRefForSerialization(0);
      }
    }
  }
  SerializeObject();
}

void Serializer::ObjectSerializer::SerializeJSArrayBuffer() {
  ArrayBufferExtension* extension;
  void* backing_store;
  {
    DisallowGarbageCollection no_gc;
    Tagged<JSArrayBuffer> buffer = Cast<JSArrayBuffer>(*object_);
    backing_store = buffer->backing_store();
    // We cannot store byte_length or max_byte_length larger than uint32 range
    // in the snapshot.
    CHECK_LE(buffer->byte_length(), std::numeric_limits<uint32_t>::max());
    uint32_t byte_length = static_cast<uint32_t>(buffer->byte_length());
    Maybe<uint32_t> max_byte_length = Nothing<uint32_t>();
    if (buffer->is_resizable_by_js()) {
      CHECK_LE(buffer->max_byte_length(), std::numeric_limits<uint32_t>::max());
      max_byte_length = Just(static_cast<uint32_t>(buffer->max_byte_length()));
    }
    extension = buffer->extension();

    // Only serialize non-empty backing stores.
    if (buffer->IsEmpty()) {
      buffer->SetBackingStoreRefForSerialization(kEmptyBackingStoreRefSentinel);
    } else {
      uint32_t ref =
          SerializeBackingStore(backing_store, byte_length, max_byte_length);
      buffer->SetBackingStoreRefForSerialization(ref);
    }

    // Ensure deterministic output by setting extension to null during
    // serialization.
    buffer->set_extension(nullptr);
  }
  SerializeObject();
  {
    Tagged<JSArrayBuffer> buffer = Cast<JSArrayBuffer>(*object_);
    buffer->set_backing_store(isolate(), backing_store);
    buffer->set_extension(extension);
  }
}

void Serializer::ObjectSerializer::SerializeExternalString() {
  // For external strings with known resources, we replace the resource field
  // with the encoded external reference, which we restore upon deserialize.
  // For the rest we serialize them to look like ordinary sequential strings.
  auto string = Cast<ExternalString>(object_);
  Address resource = string->resource_as_address();
  ExternalReferenceEncoder::Value reference;
  if (serializer_->external_reference_encoder_.TryEncode(resource).To(
          &reference)) {
    DCHECK(reference.is_from_api());
#ifdef V8_ENABLE_SANDBOX
    uint32_t external_pointer_entry =
        string->GetResourceRefForDeserialization();
#endif
    string->SetResourceRefForSerialization(reference.index());
    SerializeObject();
#ifdef V8_ENABLE_SANDBOX
    string->SetResourceRefForSerialization(external_pointer_entry);
#else
    string->set_address_as_resource(isolate(), resource);
#endif
  } else {
    SerializeExternalStringAsSequentialString();
  }
}

void Serializer::ObjectSerializer::SerializeExternalStringAsSequentialString() {
  // Instead of serializing this as an external string, we serialize
  // an imaginary sequential string with the same content.
  ReadOnlyRoots roots(isolate());
  PtrComprCageBase cage_base(isolate());
  DCHECK(IsExternalString(*object_, cage_base));
  Handle<ExternalString> string = Cast<ExternalString>(object_);
  uint32_t length = string->length();
  Tagged<Map> map;
  int content_size;
  int allocation_size;
  const uint8_t* resource;
  // Find the map and size for the imaginary sequential string.
  bool internalized = IsInternalizedString(*object_, cage_base);
  if (IsExternalOneByteString(*object_, cage_base)) {
    map = internalized ? roots.internalized_one_byte_string_map()
                       : roots.seq_one_byte_string_map();
    allocation_size = SeqOneByteString::SizeFor(length);
    content_size = length * kCharSize;
    resource = reinterpret_cast<const uint8_t*>(
        Cast<ExternalOneByteString>(string)->resource()->data());
  } else {
    map = internalized ? roots.internalized_two_byte_string_map()
                       : roots.seq_two_byte_string_map();
    allocation_size = SeqTwoByteString::SizeFor(length);
    content_size = length * kShortSize;
    resource = reinterpret_cast<const uint8_t*>(
        Cast<ExternalTwoByteString>(string)->resource()->data());
  }

  SnapshotSpace space = SnapshotSpace::kOld;
  SerializePrologue(space, allocation_size, map);

  // Output the rest of the imaginary string.
  int bytes_to_output = allocation_size - HeapObject::kHeaderSize;
  DCHECK(IsAligned(bytes_to_output, kTaggedSize));
  int slots_to_output = bytes_to_output >> kTaggedSizeLog2;

  // Output raw data header. Do not bother with common raw length cases here.
  sink_->Put(kVariableRawData, "RawDataForString");
  sink_->PutUint30(slots_to_output, "length");

  // Serialize string header (except for map).
  uint8_t* string_start = reinterpret_cast<uint8_t*>(string->address());
  for (size_t i = sizeof(HeapObjectLayout); i < sizeof(SeqString); i++) {
    sink_->Put(string_start[i], "StringHeader");
  }

  // Serialize string content.
  sink_->PutRaw(resource, content_size, "StringContent");

  // Since the allocation size is rounded up to object alignment, there
  // maybe left-over bytes that need to be padded.
  size_t padding_size = allocation_size - sizeof(SeqString) - content_size;
  DCHECK(0 <= padding_size && padding_size < kObjectAlignment);
  for (size_t i = 0; i < padding_size; i++) {
    sink_->Put(static_cast<uint8_t>(0), "StringPadding");
  }
}

// Clear and later restore the next link in the weak cell or allocation site.
// TODO(all): replace this with proper iteration of weak slots in serializer.
class V8_NODISCARD UnlinkWeakNextScope {
 public:
  explicit UnlinkWeakNextScope(Heap* heap, Tagged<HeapObject> object) {
    Isolate* isolate = heap->isolate();
    if (IsAllocationSite(object, isolate) &&
        Cast<AllocationSite>(object)->HasWeakNext()) {
      object_ = object;
      next_ = Cast<AllocationSite>(object)->weak_next();
      Cast<AllocationSite>(object)->set_weak_next(
          ReadOnlyRoots(isolate).undefined_value());
    }
  }

  ~UnlinkWeakNextScope() {
    if (next_ == Smi::zero()) return;
    Cast<AllocationSite>(object_)->set_weak_next(next_, UPDATE_WRITE_BARRIER);
  }

 private:
  Tagged<HeapObject> object_;
  Tagged<Object> next_ = Smi::zero();
  DISALLOW_GARBAGE_COLLECTION(no_gc_)
};

void Serializer::ObjectSerializer::Serialize(SlotType slot_type) {
  RecursionScope recursion(serializer_);

  {
    DisallowGarbageCollection no_gc;
    Tagged<HeapObject> raw = *object_;
    // Defer objects as "pending" if they cannot be serialized now, or if we
    // exceed a certain recursion depth. Some objects cannot be deferred.
    bool should_defer =
        recursion.ExceedsMaximum() || serializer_->MustBeDeferred(raw);
    if (should_defer && CanBeDeferred(raw, slot_type)) {
      if (v8_flags.trace_serializer) {
        PrintF(" Deferring heap object: ");
        ShortPrint(*object_);
        PrintF("\n");
      }
      // Deferred objects are considered "pending".
      serializer_->RegisterObjectIsPending(raw);
      serializer_->PutPendingForwardReference(
          *serializer_->forward_refs_per_pending_object_.Find(raw));
      serializer_->QueueDeferredObject(raw);
      return;
    } else {
      if (v8_flags.trace_serializer && recursion.ExceedsMaximum()) {
        PrintF(" Exceeding max recursion depth by %d for: ",
               recursion.ExceedsMaximumBy());
        ShortPrint(*object_);
        PrintF("\n");
      }
    }

    if (v8_flags.trace_serializer) {
      PrintF(" Encoding heap object: ");
      ShortPrint(*object_);
      PrintF("\n");
    }
  }

  PtrComprCageBase cage_base(isolate());
  InstanceType instance_type = object_->map(cage_base)->instance_type();
  if (InstanceTypeChecker::IsExternalString(instance_type)) {
    SerializeExternalString();
    return;
  }
  if (InstanceTypeChecker::IsJSTypedArray(instance_type)) {
    SerializeJSTypedArray();
    return;
  }
  if (InstanceTypeChecker::IsJSArrayBuffer(instance_type)) {
    SerializeJSArrayBuffer();
    return;
  }
  if (InstanceTypeChecker::IsScript(instance_type)) {
    // Clear cached line ends & compiled lazy function positions.
    Cast<Script>(object_)->set_line_ends(Smi::zero());
    Cast<Script>(object_)->set_compiled_lazy_function_positions(
        ReadOnlyRoots(isolate()).undefined_value());
  }

#if V8_ENABLE_WEBASSEMBLY
  // The padding for wasm null is a free space filler. We put it into the roots
  // table to be able to skip its payload when serializing the read only heap
  // in the ReadOnlyHeapImageSerializer.
  DCHECK_IMPLIES(
      !object_
```