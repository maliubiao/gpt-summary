Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/debug/debug.cc`. The request has several specific constraints:

1. **List Functionality:** Describe what the code does.
2. **Torque Check:** Determine if the file would be a Torque file based on the `.tq` extension (it's not).
3. **JavaScript Relationship:** If the C++ code relates to JavaScript features, provide a JavaScript example.
4. **Logic Inference:** If there's logical reasoning in the code, provide example inputs and outputs.
5. **Common Programming Errors:** If the code helps prevent or handle common errors, give examples.
6. **Part 1 Summary:**  Specifically summarize the functionality of this first part of the code.

**Plan:**

1. **High-Level Overview:** Read through the code to understand its primary purpose. It seems to be related to debugging functionality within the V8 engine.
2. **Detailed Analysis:** Go through the code section by section, focusing on:
    * **Includes:** Identify the core V8 components this file interacts with (e.g., `api`, `builtins`, `codegen`, `execution`, `objects`).
    * **`TemporaryObjectsTracker`:**  Understand its role in tracking temporary objects for debugging purposes.
    * **`Debug` Class:** Analyze the member variables and methods, paying attention to those related to breakpoints, stepping, and debugging states.
    * **`BreakLocation` Class:** Figure out how it represents locations where execution can break.
    * **`BreakIterator` Class:** Understand how it iterates through potential break locations within a function.
    * **Threading:**  Note the thread-local storage used for debugging state.
    * **`DebugInfoCollection`:**  Determine its purpose in managing debug information for functions.
    * **`Break` Method:**  This seems like a central function for handling breakpoints.
    * **`CheckBreakPoints`:** Analyze how breakpoints are checked and evaluated.
    * **Muting:** Understand the concept of "muting" breakpoints.
3. **Address Specific Constraints:**
    * **Torque:** Confirm that the file extension is `.cc` and not `.tq`.
    * **JavaScript Relationship:**  Identify areas where the debugging features directly interact with JavaScript concepts like functions, execution, and bytecode. Construct JavaScript examples illustrating these relationships (e.g., setting breakpoints, stepping through code).
    * **Logic Inference:**  Consider the `TemporaryObjectsTracker`'s logic for adding and removing regions and how this impacts determining if an object is temporary. Create hypothetical scenarios.
    * **Common Errors:**  Think about how the debugger helps users identify errors like unexpected behavior, incorrect variable values, or control flow issues.
    * **Part 1 Summary:**  Synthesize the information gathered into a concise summary of the functionality covered in this portion of the code.

**Self-Correction/Refinement:**

* Ensure the JavaScript examples are clear and relevant to the C++ code's functionality.
*  Focus on the *functionality* of the code, not just a line-by-line description.
*  Keep the explanations at a reasonably high level, avoiding overly technical V8 internals unless absolutely necessary.
*  Structure the answer logically to address all parts of the user's request.

**(Proceeding with detailed analysis and response generation)**
```cpp
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/debug/debug.h"

#include <memory>
#include <optional>

#include "src/api/api-inl.h"
#include "src/base/platform/mutex.h"
#include "src/builtins/builtins.h"
#include "src/codegen/compilation-cache.h"
#include "src/codegen/compiler.h"
#include "src/common/assert-scope.h"
#include "src/common/globals.h"
#include "src/common/message-template.h"
#include "src/debug/debug-evaluate.h"
#include "src/debug/liveedit.h"
#include "src/deoptimizer/deoptimizer.h"
#include "src/execution/execution.h"
#include "src/execution/frames-inl.h"
#include "src/execution/isolate-inl.h"
#include "src/execution/protectors-inl.h"
#include "src/execution/v8threads.h"
#include "src/handles/global-handles-inl.h"
#include "src/heap/heap-inl.h"  // For NextDebuggingId.
#include "src/init/bootstrapper.h"
#include "src/interpreter/bytecode-array-iterator.h"
#include "src/logging/counters.h"
#include "src/logging/runtime-call-stats-scope.h"
#include "src/objects/api-callbacks-inl.h"
#include "src/objects/debug-objects-inl.h"
#include "src/objects/js-generator-inl.h"
#include "src/objects/js-promise-inl.h"
#include "src/objects/slots.h"
#include "src/snapshot/embedded/embedded-data.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/wasm-debug.h"
#include "src/wasm/wasm-objects-inl.h"
#endif  // V8_ENABLE_WEBASSEMBLY

namespace v8 {
namespace internal {

class Debug::TemporaryObjectsTracker : public HeapObjectAllocationTracker {
 public:
  TemporaryObjectsTracker() = default;
  ~TemporaryObjectsTracker() override = default;
  TemporaryObjectsTracker(const TemporaryObjectsTracker&) = delete;
  TemporaryObjectsTracker& operator=(const TemporaryObjectsTracker&) = delete;

  void AllocationEvent(Address addr, int size) override {
    if (disabled) return;
    AddRegion(addr, addr + size);
  }

  void MoveEvent(Address from, Address to, int size) override {
    if (from == to) return;
    base::MutexGuard guard(&mutex_);
    if (RemoveFromRegions(from, from + size)) {
      // We had the object tracked as temporary, so we will track the
      // new location as temporary, too.
      AddRegion(to, to + size);
    } else {
      // The object we moved is a non-temporary, so the new location is also
      // non-temporary. Thus we remove everything we track there (because it
      // must have become dead).
      RemoveFromRegions(to, to + size);
    }
  }

  bool HasObject(Handle<HeapObject> obj) {
    if (IsJSObject(*obj) && Cast<JSObject>(obj)->GetEmbedderFieldCount()) {
      // Embedder may store any pointers using embedder fields and implements
      // non trivial logic, e.g. create wrappers lazily and store pointer to
      // native object inside embedder field. We should consider all objects
      // with embedder fields as non temporary.
      return false;
    }
    Address addr = obj->address();
    return HasRegionContainingObject(addr, addr + obj->Size());
  }

  bool disabled = false;

 private:
  bool HasRegionContainingObject(Address start, Address end) {
    // Check if there is a region that contains (overlaps) this object's space.
    auto it = FindOverlappingRegion(start, end, false);
    // If there is, we expect the region to contain the entire object.
    DCHECK_IMPLIES(it != regions_.end(),
                   it->second <= start && end <= it->first);
    return it != regions_.end();
  }

  // This function returns any one of the overlapping regions (there might be
  // multiple). If {include_adjacent} is true, it will also consider regions
  // that have no overlap but are directly connected.
  std::map<Address, Address>::iterator FindOverlappingRegion(
      Address start, Address end, bool include_adjacent) {
    // Region A = [start, end) overlaps with an existing region [existing_start,
    // existing_end) iff (start <= existing_end) && (existing_start <= end).
    // Since we index {regions_} by end address, we can find a candidate that
    // satisfies the first condition using lower_bound.
    if (include_adjacent) {
      auto it = regions_.lower_bound(start);
      if (it == regions_.end()) return regions_.end();
      if (it->second <= end) return it;
    } else {
      auto it = regions_.upper_bound(start);
      if (it == regions_.end()) return regions_.end();
      if (it->second < end) return it;
    }
    return regions_.end();
  }

  void AddRegion(Address start, Address end) {
    DCHECK_LT(start, end);

    // Region [start, end) can be combined with an existing region if they
    // overlap.
    while (true) {
      auto it = FindOverlappingRegion(start, end, true);
      // If there is no such region, we don't need to merge anything.
      if (it == regions_.end()) break;

      // Otherwise, we found an overlapping region. We remove the old one and
      // add the new region recursively (to handle cases where the new region
      // overlaps multiple existing ones).
      start = std::min(start, it->second);
      end = std::max(end, it->first);
      regions_.erase(it);
    }

    // Add the new (possibly combined) region.
    regions_.emplace(end, start);
  }

  bool RemoveFromRegions(Address start, Address end) {
    // Check if we have anything that overlaps with [start, end).
    auto it = FindOverlappingRegion(start, end, false);
    if (it == regions_.end()) return false;

    // We need to update all overlapping regions.
    for (; it != regions_.end();
         it = FindOverlappingRegion(start, end, false)) {
      Address existing_start = it->second;
      Address existing_end = it->first;
      // If we remove the region [start, end) from an existing region
      // [existing_start, existing_end), there can be at most 2 regions left:
      regions_.erase(it);
      // The one before {start} is: [existing_start, start)
      if (existing_start < start) AddRegion(existing_start, start);
      // And the one after {end} is: [end, existing_end)
      if (end < existing_end) AddRegion(end, existing_end);
    }
    return true;
  }

  // Tracking addresses is not enough, because a single allocation may combine
  // multiple objects due to allocation folding. We track both start and end
  // (exclusive) address of regions. We index by end address for faster lookup.
  // Map: end address => start address
  std::map<Address, Address> regions_;
  base::Mutex mutex_;
};

Debug::Debug(Isolate* isolate)
    : is_active_(false),
      hook_on_function_call_(false),
      is_suppressed_(false),
      break_disabled_(false),
      break_points_active_(true),
      break_on_caught_exception_(false),
      break_on_uncaught_exception_(false),
      side_effect_check_failed_(false),
      debug_infos_(isolate) {
  ThreadInit();
}

Debug::~Debug() { DCHECK_NULL(debug_delegate_); }

BreakLocation BreakLocation::FromFrame(Handle<DebugInfo> debug_info,
                                       JavaScriptFrame* frame) {
  if (debug_info->CanBreakAtEntry()) {
    return BreakLocation(Debug::kBreakAtEntryPosition, DEBUG_BREAK_AT_ENTRY);
  }
  auto summary = FrameSummary::GetTop(frame).AsJavaScript();
  int offset = summary.code_offset();
  DirectHandle<AbstractCode> abstract_code = summary.abstract_code();
  BreakIterator it(debug_info);
  it.SkipTo(BreakIndexFromCodeOffset(debug_info, abstract_code, offset));
  return it.GetBreakLocation();
}

bool BreakLocation::IsPausedInJsFunctionEntry(JavaScriptFrame* frame) {
  auto summary = FrameSummary::GetTop(frame);
  return summary.code_offset() == kFunctionEntryBytecodeOffset;
}

MaybeHandle<FixedArray> Debug::CheckBreakPointsForLocations(
    Handle<DebugInfo> debug_info, std::vector<BreakLocation>& break_locations,
    bool* has_break_points) {
  Handle<FixedArray> break_points_hit = isolate_->factory()->NewFixedArray(
      debug_info->GetBreakPointCount(isolate_));
  int break_points_hit_count = 0;
  bool has_break_points_at_all = false;
  for (size_t i = 0; i < break_locations.size(); i++) {
    bool location_has_break_points;
    MaybeHandle<FixedArray> check_result = CheckBreakPoints(
        debug_info, &break_locations[i], &location_has_break_points);
    has_break_points_at_all |= location_has_break_points;
    if (!check_result.is_null()) {
      DirectHandle<FixedArray> break_points_current_hit =
          check_result.ToHandleChecked();
      int num_objects = break_points_current_hit->length();
      for (int j = 0; j < num_objects; ++j) {
        break_points_hit->set(break_points_hit_count++,
                              break_points_current_hit->get(j));
      }
    }
  }
  *has_break_points = has_break_points_at_all;
  if (break_points_hit_count == 0) return {};

  break_points_hit->RightTrim(isolate_, break_points_hit_count);
  return break_points_hit;
}

void BreakLocation::AllAtCurrentStatement(
    Handle<DebugInfo> debug_info, JavaScriptFrame* frame,
    std::vector<BreakLocation>* result_out) {
  DCHECK(!debug_info->CanBreakAtEntry());
  auto summary = FrameSummary::GetTop(frame).AsJavaScript();
  int offset = summary.code_offset();
  DirectHandle<AbstractCode> abstract_code = summary.abstract_code();
  PtrComprCageBase cage_base = GetPtrComprCageBase(*debug_info);
  if (IsCode(*abstract_code, cage_base)) offset = offset - 1;
  int statement_position;
  {
    BreakIterator it(debug_info);
    it.SkipTo(BreakIndexFromCodeOffset(debug_info, abstract_code, offset));
    statement_position = it.statement_position();
  }
  for (BreakIterator it(debug_info); !it.Done(); it.Next()) {
    if (it.statement_position() == statement_position) {
      result_out->push_back(it.GetBreakLocation());
    }
  }
}

Tagged<JSGeneratorObject> BreakLocation::GetGeneratorObjectForSuspendedFrame(
    JavaScriptFrame* frame) const {
  DCHECK(IsSuspend());
  DCHECK_GE(generator_obj_reg_index_, 0);

  Tagged<Object> generator_obj =
      UnoptimizedJSFrame::cast(frame)->ReadInterpreterRegister(
          generator_obj_reg_index_);

  return Cast<JSGeneratorObject>(generator_obj);
}

int BreakLocation::BreakIndexFromCodeOffset(
    Handle<DebugInfo> debug_info, DirectHandle<AbstractCode> abstract_code,
    int offset) {
  // Run through all break points to locate the one closest to the address.
  int closest_break = 0;
  int distance = kMaxInt;
  DCHECK(kFunctionEntryBytecodeOffset <= offset &&
         offset < abstract_code->Size());
  for (BreakIterator it(debug_info); !it.Done(); it.Next()) {
    // Check if this break point is closer that what was previously found.
    if (it.code_offset() <= offset && offset - it.code_offset() < distance) {
      closest_break = it.break_index();
      distance = offset - it.code_offset();
      // Check whether we can't get any closer.
      if (distance == 0) break;
    }
  }
  return closest_break;
}

bool BreakLocation::HasBreakPoint(Isolate* isolate,
                                  Handle<DebugInfo> debug_info) const {
  // First check whether there is a break point with the same source position.
  if (!debug_info->HasBreakInfo() ||
      !debug_info->HasBreakPoint(isolate, position_)) {
    return false;
  }
  if (debug_info->CanBreakAtEntry()) {
    DCHECK_EQ(Debug::kBreakAtEntryPosition, position_);
    return debug_info->BreakAtEntry();
  } else {
    // Then check whether a break point at that source position would have
    // the same code offset. Otherwise it's just a break location that we can
    // step to, but not actually a location where we can put a break point.
    DCHECK(IsBytecodeArray(*abstract_code_, isolate));
    BreakIterator it(debug_info);
    it.SkipToPosition(position_);
    return it.code_offset() == code_offset_;
  }
}

debug::BreakLocationType BreakLocation::type() const {
  switch (type_) {
    case DEBUGGER_STATEMENT:
      return debug::kDebuggerStatementBreakLocation;
    case DEBUG_BREAK_SLOT_AT_CALL:
      return debug::kCallBreakLocation;
    case DEBUG_BREAK_SLOT_AT_RETURN:
      return debug::kReturnBreakLocation;

    // Externally, suspend breaks should look like normal breaks.
    case DEBUG_BREAK_SLOT_AT_SUSPEND:
    default:
      return debug::kCommonBreakLocation;
  }
}

BreakIterator::BreakIterator(Handle<DebugInfo> debug_info)
    : debug_info_(debug_info),
      break_index_(-1),
      source_position_iterator_(
          debug_info->DebugBytecodeArray(isolate())->SourcePositionTable()) {
  position_ = debug_info->shared()->StartPosition();
  statement_position_ = position_;
  // There is at least one break location.
  DCHECK(!Done());
  Next();
}

int BreakIterator::BreakIndexFromPosition(int source_position) {
  for (; !Done(); Next()) {
    if (GetDebugBreakType() == DEBUG_BREAK_SLOT_AT_SUSPEND) continue;
    if (source_position <= position()) {
      int first_break = break_index();
      for (; !Done(); Next()) {
        if (GetDebugBreakType() == DEBUG_BREAK_SLOT_AT_SUSPEND) continue;
        if (source_position == position()) return break_index();
      }
      return first_break;
    }
  }
  return break_index();
}

void BreakIterator::Next() {
  DisallowGarbageCollection no_gc;
  DCHECK(!Done());
  bool first = break_index_ == -1;
  while (!Done()) {
    if (!first) source_position_iterator_.Advance();
    first = false;
    if (Done()) return;
    position_ = source_position_iterator_.source_position().ScriptOffset();
    if (source_position_iterator_.is_statement()) {
      statement_position_ = position_;
    }
    DCHECK_LE(0, position_);
    DCHECK_LE(0, statement_position_);

    DebugBreakType type = GetDebugBreakType();
    if (type != NOT_DEBUG_BREAK) break;
  }
  break_index_++;
}

DebugBreakType BreakIterator::GetDebugBreakType() {
  Tagged<BytecodeArray> bytecode_array =
      debug_info_->OriginalBytecodeArray(isolate());
  interpreter::Bytecode bytecode =
      interpreter::Bytecodes::FromByte(bytecode_array->get(code_offset()));

  // Make sure we read the actual bytecode, not a prefix scaling bytecode.
  if (interpreter::Bytecodes::IsPrefixScalingBytecode(bytecode)) {
    bytecode = interpreter::Bytecodes::FromByte(
        bytecode_array->get(code_offset() + 1));
  }

  if (bytecode == interpreter::Bytecode::kDebugger) {
    return DEBUGGER_STATEMENT;
  } else if (bytecode == interpreter::Bytecode::kReturn) {
    return DEBUG_BREAK_SLOT_AT_RETURN;
  } else if (bytecode == interpreter::Bytecode::kSuspendGenerator) {
    // SuspendGenerator should always only carry an expression position that
    // is used in stack trace construction, but should never be a breakable
    // position reported to the debugger front-end.
    DCHECK(!source_position_iterator_.is_statement());
    return DEBUG_BREAK_SLOT_AT_SUSPEND;
  } else if (interpreter::Bytecodes::IsCallOrConstruct(bytecode)) {
    return DEBUG_BREAK_SLOT_AT_CALL;
  } else if (source_position_iterator_.is_statement()) {
    return DEBUG_BREAK_SLOT;
  } else {
    return NOT_DEBUG_BREAK;
  }
}

void BreakIterator::SkipToPosition(int position) {
  BreakIterator it(debug_info_);
  SkipTo(it.BreakIndexFromPosition(position));
}

void BreakIterator::SetDebugBreak() {
  DCHECK(GetDebugBreakType() >= DEBUGGER_STATEMENT);
  HandleScope scope(isolate());
  Handle<BytecodeArray> bytecode_array(
      debug_info_->DebugBytecodeArray(isolate()), isolate());
  interpreter::BytecodeArrayIterator(bytecode_array, code_offset())
      .ApplyDebugBreak();
}

void BreakIterator::ClearDebugBreak() {
  DCHECK(GetDebugBreakType() >= DEBUGGER_STATEMENT);
  Tagged<BytecodeArray> bytecode_array =
      debug_info_->DebugBytecodeArray(isolate());
  Tagged<BytecodeArray> original =
      debug_info_->OriginalBytecodeArray(isolate());
  bytecode_array->set(code_offset(), original->get(code_offset()));
}

BreakLocation BreakIterator::GetBreakLocation() {
  Handle<AbstractCode> code(
      Cast<AbstractCode>(debug_info_->DebugBytecodeArray(isolate())),
      isolate());
  DebugBreakType type = GetDebugBreakType();
  int generator_object_reg_index = -1;
  int generator_suspend_id = -1;
  if (type == DEBUG_BREAK_SLOT_AT_SUSPEND) {
    // For suspend break, we'll need the generator object to be able to step
    // over the suspend as if it didn't return. We get the interpreter register
    // index that holds the generator object by reading it directly off the
    // bytecode array, and we'll read the actual generator object off the
    // interpreter stack frame in GetGeneratorObjectForSuspendedFrame.
    Tagged<BytecodeArray> bytecode_array =
        debug_info_->OriginalBytecodeArray(isolate());
    interpreter::BytecodeArrayIterator iterator(
        handle(bytecode_array, isolate()), code_offset());

    DCHECK_EQ(iterator.current_bytecode(),
              interpreter::Bytecode::kSuspendGenerator);
    interpreter::Register generator_obj_reg = iterator.GetRegisterOperand(0);
    generator_object_reg_index = generator_obj_reg.index();

    // Also memorize the suspend ID, to be able to decide whether
    // we are paused on the implicit initial yield later.
    generator_suspend_id = iterator.GetUnsignedImmediateOperand(3);
  }
  return BreakLocation(code, type, code_offset(), position_,
                       generator_object_reg_index, generator_suspend_id);
}

Isolate* BreakIterator::isolate() { return debug_info_->GetIsolate(); }

// Threading support.
void Debug::ThreadInit() {
  thread_local_.break_frame_id_ = StackFrameId::NO_ID;
  thread_local_.last_step_action_ = StepNone;
  thread_local_.last_statement_position_ = kNoSourcePosition;
  thread_local_.last_bytecode_offset_ = kFunctionEntryBytecodeOffset;
  thread_local_.last_frame_count_ = -1;
  thread_local_.fast_forward_to_return_ = false;
  thread_local_.ignore_step_into_function_ = Smi::zero();
  thread_local_.target_frame_count_ = -1;
  thread_local_.return_value_ = Smi::zero();
  thread_local_.last_breakpoint_id_ = 0;
  clear_restart_frame();
  clear_suspended_generator();
  base::Relaxed_Store(&thread_local_.current_debug_scope_,
                      static_cast<base::AtomicWord>(0));
  thread_local_.break_on_next_function_call_ = false;
  thread_local_.scheduled_break_on_next_function_call_ = false;
  UpdateHookOnFunctionCall();
  thread_local_.muted_function_ = Smi::zero();
  thread_local_.muted_position_ = -1;
}

char* Debug::ArchiveDebug(char* storage) {
  MemCopy(storage, reinterpret_cast<char*>(&thread_local_),
          ArchiveSpacePerThread());
  return storage + ArchiveSpacePerThread();
}

char* Debug::RestoreDebug(char* storage) {
  MemCopy(reinterpret_cast<char*>(&thread_local_), storage,
          ArchiveSpacePerThread());

  // Enter the isolate.
  v8::Isolate::Scope isolate_scope(reinterpret_cast<v8::Isolate*>(isolate_));
  // Enter the debugger.
  DebugScope debug_scope(this);

  // Clear any one-shot breakpoints that may have been set by the other
  // thread, and reapply breakpoints for this thread.
  ClearOneShot();

  if (thread_local_.last_step_action_ != StepNone) {
    int current_frame_count = CurrentFrameCount();
    int target_frame_count = thread_local_.target_frame_count_;
    DCHECK(current_frame_count >= target_frame_count);
    DebuggableStackFrameIterator frames_it(isolate_);
    while (current_frame_count > target_frame_count) {
      current_frame_count -= frames_it.FrameFunctionCount();
      frames_it.Advance();
    }
    DCHECK(current_frame_count == target_frame_count);
    // Set frame to what it was at Step break
    thread_local_.break_frame_id_ = frames_it.frame()->id();

    // Reset the previous step action for this thread.
    PrepareStep(thread_local_.last_step_action_);
  }

  return storage + ArchiveSpacePerThread();
}

int Debug::ArchiveSpacePerThread() { return sizeof(ThreadLocal); }

void Debug::Iterate(RootVisitor* v) { Iterate(v, &thread_local_); }

char* Debug::Iterate(RootVisitor* v, char* thread_storage) {
  ThreadLocal* thread_local_data =
      reinterpret_cast<ThreadLocal*>(thread_storage);
  Iterate(v, thread_local_data);
  return thread_storage + ArchiveSpacePerThread();
}

void Debug::Iterate(RootVisitor* v, ThreadLocal* thread_local_data) {
  v->VisitRootPointer(Root::kDebug, nullptr,
                      FullObjectSlot(&thread_local_data->return_value_));
  v->VisitRootPointer(Root::kDebug, nullptr,
                      FullObjectSlot(&thread_local_data->suspended_generator_));
  v->VisitRootPointer(
      Root::kDebug, nullptr,
      FullObjectSlot(&thread_local_data->ignore_step_into_function_));
  v->VisitRootPointer(Root::kDebug, nullptr,
                      FullObjectSlot(&thread_local_data->muted_function_));
}

void DebugInfoCollection::Insert(Tagged<SharedFunctionInfo> sfi,
                                 Tagged<DebugInfo> debug_info) {
  DisallowGarbageCollection no_gc;
  base::SharedMutexGuard<base::kExclusive> mutex_guard(
      isolate_->shared_function_info_access());

  DCHECK_EQ(sfi, debug_info->shared());
  DCHECK(!Contains(sfi));
  HandleLocation location =
      isolate_->global_handles()->Create(debug_info).location();
  list_.push_back(location);
  map_.emplace(sfi->unique_id(), location);
  DCHECK(Contains(sfi));
  DCHECK_EQ(list_.size(), map_.size());
}

bool DebugInfoCollection::Contains(Tagged<SharedFunctionInfo> sfi) const {
  auto it = map_.find(sfi->unique_id());
  if (it == map_.end()) return false;
  DCHECK_EQ(Cast<DebugInfo>(Tagged<Object>(*it->second))->shared(), sfi);
  return true;
}

std::optional<Tagged<DebugInfo>> DebugInfoCollection::Find(
    Tagged<SharedFunctionInfo> sfi) const {
  auto it = map_.find(sfi->unique_id());
  if (it == map_.end()) return {};
  Tagged<DebugInfo> di = Cast<DebugInfo>(Tagged<Object>(*it->second));
  DCHECK_EQ(di->shared(), sfi);
  return di;
}

void DebugInfoCollection::DeleteSlow(Tagged<SharedFunctionInfo> sfi) {
  DebugInfoCollection::Iterator it(this);
  for (; it.HasNext(); it.Advance()) {
    Tagged<DebugInfo> debug_info = it.Next();
    if (debug_info->shared() != sfi) continue;
    it.DeleteNext();
    return;
  }
  UNREACHABLE();
}

Tagged<DebugInfo> DebugInfoCollection::EntryAsDebugInfo(size_t index) const {
  DCHECK_LT(index, list_.size());
  return Cast<DebugInfo>(Tagged<Object>(*list_[index]));
}

void DebugInfoCollection::DeleteIndex(size_t index) {
  base::SharedMutexGuard<base::kExclusive> mutex_guard(
      isolate_->shared_function_info_access());

  Tagged<DebugInfo> debug_info = EntryAsDebugInfo(index);
  Tagged<SharedFunctionInfo> sfi = debug_info->shared();
  DCHECK(Contains(sfi));

  auto it = map_.find(sfi->unique_id());
  HandleLocation location = it->second;
  DCHECK_EQ(location, list_[index]);
  map_.erase(it);

  list_[index] = list_.back();
  list_.pop_back();

  GlobalHandles::Destroy(location);
  DCHECK(!Contains(sfi));
  DCHECK_EQ(list_.size(), map_.size());
}

void Debug::Unload() {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  ClearAllBreakPoints();
  ClearStepping();
  RemoveAllCoverageInfos();
  ClearAllDebuggerHints();
  debug_delegate_ = nullptr;
}

debug::DebugDelegate::ActionAfterInstrumentation
Debug::OnInstrumentationBreak() {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  if (!debug_delegate_) {
    return debug::DebugDelegate::ActionAfterInstrumentation::
        kPauseIfBreakpointsHit;
  }
  DCHECK(in_debug_scope());
  HandleScope scope(isolate_);
  DisableBreak no_recursive_break(this);

  return debug_delegate_->BreakOnInstrumentation(
      v8::Utils::ToLocal(isolate_->native_context()), kInstrumentationId);
}

void Debug::Break(JavaScriptFrame* frame,
                  DirectHandle<JSFunction> break_target) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  // Just continue if breaks are disabled or debugger cannot be loaded.
  if (break_disabled()) return;

  // Enter the debugger.
  DebugScope debug_scope(this);
  DisableBreak no_recursive_break(this);

  // Return if we fail to retrieve debug info.
  Handle<SharedFunctionInfo> shared(break_target->shared(), isolate_);
  if (!EnsureBreakInfo(shared)) return;
  PrepareFunctionForDebugExecution(shared);

  Handle<DebugInfo> debug_info(TryGetDebugInfo(*shared).value(), isolate_);

  // Find the break location where execution has stopped.
  BreakLocation location = BreakLocation::FromFrame(debug_info, frame);
  const bool hitInstrumentationBreak =
      IsBreakOnInstrumentation(debug_info, location);
  bool shouldPauseAfterInstrumentation = false;
  if (hitInstrumentationBreak) {
    debug::DebugDelegate::ActionAfterInstrumentation action =
        OnInstrumentationBreak();
    switch (action) {
      case debug::DebugDelegate::ActionAfterInstrumentation::kPause:
        shouldPauseAfterInstrumentation = true;
        break;
      case debug::DebugDelegate::ActionAfterInstrumentation::
          kPauseIfBreakpointsHit:
        shouldPauseAfterInstrumentation = false;
        break;
      case debug::DebugDelegate::ActionAfterInstrumentation::kContinue:
        return;
    }
  }

  // Find actual break points, if any, and trigger debug break event.
  ClearMutedLocation();
  bool has_break_points;
  bool scheduled_break =
      scheduled_break_on_function_call() || shouldPauseAfterInstrumentation;
  MaybeHandle<FixedArray> break_points_hit =
      CheckBreakPoints(debug_info, &location, &has_break_points);
  if (!break_points_hit.is_null() || break_on_next_function_call() ||
      scheduled_break) {
    StepAction lastStepAction = last_step_action();
    debug::BreakReasons break_reasons;
    if (scheduled_break) {
      break_reasons.Add(debug::BreakReason::kScheduled);
    }
    // If it's a debugger statement, add the reason and then mute the location
    // so we don't stop a second time.
    bool is_debugger_statement = IsBreakOnDebuggerStatement(shared, location);
    if (is_debugger_statement) {
      break_reasons.Add(debug::BreakReason::kDebuggerStatement);
    }

    // Clear all current stepping setup.
    ClearStepping();
    // Notify the debug event listeners.
    OnDebugBreak(!break_
### 提示词
```
这是目录为v8/src/debug/debug.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/debug/debug.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/debug/debug.h"

#include <memory>
#include <optional>

#include "src/api/api-inl.h"
#include "src/base/platform/mutex.h"
#include "src/builtins/builtins.h"
#include "src/codegen/compilation-cache.h"
#include "src/codegen/compiler.h"
#include "src/common/assert-scope.h"
#include "src/common/globals.h"
#include "src/common/message-template.h"
#include "src/debug/debug-evaluate.h"
#include "src/debug/liveedit.h"
#include "src/deoptimizer/deoptimizer.h"
#include "src/execution/execution.h"
#include "src/execution/frames-inl.h"
#include "src/execution/isolate-inl.h"
#include "src/execution/protectors-inl.h"
#include "src/execution/v8threads.h"
#include "src/handles/global-handles-inl.h"
#include "src/heap/heap-inl.h"  // For NextDebuggingId.
#include "src/init/bootstrapper.h"
#include "src/interpreter/bytecode-array-iterator.h"
#include "src/logging/counters.h"
#include "src/logging/runtime-call-stats-scope.h"
#include "src/objects/api-callbacks-inl.h"
#include "src/objects/debug-objects-inl.h"
#include "src/objects/js-generator-inl.h"
#include "src/objects/js-promise-inl.h"
#include "src/objects/slots.h"
#include "src/snapshot/embedded/embedded-data.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/wasm-debug.h"
#include "src/wasm/wasm-objects-inl.h"
#endif  // V8_ENABLE_WEBASSEMBLY

namespace v8 {
namespace internal {

class Debug::TemporaryObjectsTracker : public HeapObjectAllocationTracker {
 public:
  TemporaryObjectsTracker() = default;
  ~TemporaryObjectsTracker() override = default;
  TemporaryObjectsTracker(const TemporaryObjectsTracker&) = delete;
  TemporaryObjectsTracker& operator=(const TemporaryObjectsTracker&) = delete;

  void AllocationEvent(Address addr, int size) override {
    if (disabled) return;
    AddRegion(addr, addr + size);
  }

  void MoveEvent(Address from, Address to, int size) override {
    if (from == to) return;
    base::MutexGuard guard(&mutex_);
    if (RemoveFromRegions(from, from + size)) {
      // We had the object tracked as temporary, so we will track the
      // new location as temporary, too.
      AddRegion(to, to + size);
    } else {
      // The object we moved is a non-temporary, so the new location is also
      // non-temporary. Thus we remove everything we track there (because it
      // must have become dead).
      RemoveFromRegions(to, to + size);
    }
  }

  bool HasObject(Handle<HeapObject> obj) {
    if (IsJSObject(*obj) && Cast<JSObject>(obj)->GetEmbedderFieldCount()) {
      // Embedder may store any pointers using embedder fields and implements
      // non trivial logic, e.g. create wrappers lazily and store pointer to
      // native object inside embedder field. We should consider all objects
      // with embedder fields as non temporary.
      return false;
    }
    Address addr = obj->address();
    return HasRegionContainingObject(addr, addr + obj->Size());
  }

  bool disabled = false;

 private:
  bool HasRegionContainingObject(Address start, Address end) {
    // Check if there is a region that contains (overlaps) this object's space.
    auto it = FindOverlappingRegion(start, end, false);
    // If there is, we expect the region to contain the entire object.
    DCHECK_IMPLIES(it != regions_.end(),
                   it->second <= start && end <= it->first);
    return it != regions_.end();
  }

  // This function returns any one of the overlapping regions (there might be
  // multiple). If {include_adjacent} is true, it will also consider regions
  // that have no overlap but are directly connected.
  std::map<Address, Address>::iterator FindOverlappingRegion(
      Address start, Address end, bool include_adjacent) {
    // Region A = [start, end) overlaps with an existing region [existing_start,
    // existing_end) iff (start <= existing_end) && (existing_start <= end).
    // Since we index {regions_} by end address, we can find a candidate that
    // satisfies the first condition using lower_bound.
    if (include_adjacent) {
      auto it = regions_.lower_bound(start);
      if (it == regions_.end()) return regions_.end();
      if (it->second <= end) return it;
    } else {
      auto it = regions_.upper_bound(start);
      if (it == regions_.end()) return regions_.end();
      if (it->second < end) return it;
    }
    return regions_.end();
  }

  void AddRegion(Address start, Address end) {
    DCHECK_LT(start, end);

    // Region [start, end) can be combined with an existing region if they
    // overlap.
    while (true) {
      auto it = FindOverlappingRegion(start, end, true);
      // If there is no such region, we don't need to merge anything.
      if (it == regions_.end()) break;

      // Otherwise, we found an overlapping region. We remove the old one and
      // add the new region recursively (to handle cases where the new region
      // overlaps multiple existing ones).
      start = std::min(start, it->second);
      end = std::max(end, it->first);
      regions_.erase(it);
    }

    // Add the new (possibly combined) region.
    regions_.emplace(end, start);
  }

  bool RemoveFromRegions(Address start, Address end) {
    // Check if we have anything that overlaps with [start, end).
    auto it = FindOverlappingRegion(start, end, false);
    if (it == regions_.end()) return false;

    // We need to update all overlapping regions.
    for (; it != regions_.end();
         it = FindOverlappingRegion(start, end, false)) {
      Address existing_start = it->second;
      Address existing_end = it->first;
      // If we remove the region [start, end) from an existing region
      // [existing_start, existing_end), there can be at most 2 regions left:
      regions_.erase(it);
      // The one before {start} is: [existing_start, start)
      if (existing_start < start) AddRegion(existing_start, start);
      // And the one after {end} is: [end, existing_end)
      if (end < existing_end) AddRegion(end, existing_end);
    }
    return true;
  }

  // Tracking addresses is not enough, because a single allocation may combine
  // multiple objects due to allocation folding. We track both start and end
  // (exclusive) address of regions. We index by end address for faster lookup.
  // Map: end address => start address
  std::map<Address, Address> regions_;
  base::Mutex mutex_;
};

Debug::Debug(Isolate* isolate)
    : is_active_(false),
      hook_on_function_call_(false),
      is_suppressed_(false),
      break_disabled_(false),
      break_points_active_(true),
      break_on_caught_exception_(false),
      break_on_uncaught_exception_(false),
      side_effect_check_failed_(false),
      debug_infos_(isolate),
      isolate_(isolate) {
  ThreadInit();
}

Debug::~Debug() { DCHECK_NULL(debug_delegate_); }

BreakLocation BreakLocation::FromFrame(Handle<DebugInfo> debug_info,
                                       JavaScriptFrame* frame) {
  if (debug_info->CanBreakAtEntry()) {
    return BreakLocation(Debug::kBreakAtEntryPosition, DEBUG_BREAK_AT_ENTRY);
  }
  auto summary = FrameSummary::GetTop(frame).AsJavaScript();
  int offset = summary.code_offset();
  DirectHandle<AbstractCode> abstract_code = summary.abstract_code();
  BreakIterator it(debug_info);
  it.SkipTo(BreakIndexFromCodeOffset(debug_info, abstract_code, offset));
  return it.GetBreakLocation();
}

bool BreakLocation::IsPausedInJsFunctionEntry(JavaScriptFrame* frame) {
  auto summary = FrameSummary::GetTop(frame);
  return summary.code_offset() == kFunctionEntryBytecodeOffset;
}

MaybeHandle<FixedArray> Debug::CheckBreakPointsForLocations(
    Handle<DebugInfo> debug_info, std::vector<BreakLocation>& break_locations,
    bool* has_break_points) {
  Handle<FixedArray> break_points_hit = isolate_->factory()->NewFixedArray(
      debug_info->GetBreakPointCount(isolate_));
  int break_points_hit_count = 0;
  bool has_break_points_at_all = false;
  for (size_t i = 0; i < break_locations.size(); i++) {
    bool location_has_break_points;
    MaybeHandle<FixedArray> check_result = CheckBreakPoints(
        debug_info, &break_locations[i], &location_has_break_points);
    has_break_points_at_all |= location_has_break_points;
    if (!check_result.is_null()) {
      DirectHandle<FixedArray> break_points_current_hit =
          check_result.ToHandleChecked();
      int num_objects = break_points_current_hit->length();
      for (int j = 0; j < num_objects; ++j) {
        break_points_hit->set(break_points_hit_count++,
                              break_points_current_hit->get(j));
      }
    }
  }
  *has_break_points = has_break_points_at_all;
  if (break_points_hit_count == 0) return {};

  break_points_hit->RightTrim(isolate_, break_points_hit_count);
  return break_points_hit;
}

void BreakLocation::AllAtCurrentStatement(
    Handle<DebugInfo> debug_info, JavaScriptFrame* frame,
    std::vector<BreakLocation>* result_out) {
  DCHECK(!debug_info->CanBreakAtEntry());
  auto summary = FrameSummary::GetTop(frame).AsJavaScript();
  int offset = summary.code_offset();
  DirectHandle<AbstractCode> abstract_code = summary.abstract_code();
  PtrComprCageBase cage_base = GetPtrComprCageBase(*debug_info);
  if (IsCode(*abstract_code, cage_base)) offset = offset - 1;
  int statement_position;
  {
    BreakIterator it(debug_info);
    it.SkipTo(BreakIndexFromCodeOffset(debug_info, abstract_code, offset));
    statement_position = it.statement_position();
  }
  for (BreakIterator it(debug_info); !it.Done(); it.Next()) {
    if (it.statement_position() == statement_position) {
      result_out->push_back(it.GetBreakLocation());
    }
  }
}

Tagged<JSGeneratorObject> BreakLocation::GetGeneratorObjectForSuspendedFrame(
    JavaScriptFrame* frame) const {
  DCHECK(IsSuspend());
  DCHECK_GE(generator_obj_reg_index_, 0);

  Tagged<Object> generator_obj =
      UnoptimizedJSFrame::cast(frame)->ReadInterpreterRegister(
          generator_obj_reg_index_);

  return Cast<JSGeneratorObject>(generator_obj);
}

int BreakLocation::BreakIndexFromCodeOffset(
    Handle<DebugInfo> debug_info, DirectHandle<AbstractCode> abstract_code,
    int offset) {
  // Run through all break points to locate the one closest to the address.
  int closest_break = 0;
  int distance = kMaxInt;
  DCHECK(kFunctionEntryBytecodeOffset <= offset &&
         offset < abstract_code->Size());
  for (BreakIterator it(debug_info); !it.Done(); it.Next()) {
    // Check if this break point is closer that what was previously found.
    if (it.code_offset() <= offset && offset - it.code_offset() < distance) {
      closest_break = it.break_index();
      distance = offset - it.code_offset();
      // Check whether we can't get any closer.
      if (distance == 0) break;
    }
  }
  return closest_break;
}

bool BreakLocation::HasBreakPoint(Isolate* isolate,
                                  Handle<DebugInfo> debug_info) const {
  // First check whether there is a break point with the same source position.
  if (!debug_info->HasBreakInfo() ||
      !debug_info->HasBreakPoint(isolate, position_)) {
    return false;
  }
  if (debug_info->CanBreakAtEntry()) {
    DCHECK_EQ(Debug::kBreakAtEntryPosition, position_);
    return debug_info->BreakAtEntry();
  } else {
    // Then check whether a break point at that source position would have
    // the same code offset. Otherwise it's just a break location that we can
    // step to, but not actually a location where we can put a break point.
    DCHECK(IsBytecodeArray(*abstract_code_, isolate));
    BreakIterator it(debug_info);
    it.SkipToPosition(position_);
    return it.code_offset() == code_offset_;
  }
}

debug::BreakLocationType BreakLocation::type() const {
  switch (type_) {
    case DEBUGGER_STATEMENT:
      return debug::kDebuggerStatementBreakLocation;
    case DEBUG_BREAK_SLOT_AT_CALL:
      return debug::kCallBreakLocation;
    case DEBUG_BREAK_SLOT_AT_RETURN:
      return debug::kReturnBreakLocation;

    // Externally, suspend breaks should look like normal breaks.
    case DEBUG_BREAK_SLOT_AT_SUSPEND:
    default:
      return debug::kCommonBreakLocation;
  }
}

BreakIterator::BreakIterator(Handle<DebugInfo> debug_info)
    : debug_info_(debug_info),
      break_index_(-1),
      source_position_iterator_(
          debug_info->DebugBytecodeArray(isolate())->SourcePositionTable()) {
  position_ = debug_info->shared()->StartPosition();
  statement_position_ = position_;
  // There is at least one break location.
  DCHECK(!Done());
  Next();
}

int BreakIterator::BreakIndexFromPosition(int source_position) {
  for (; !Done(); Next()) {
    if (GetDebugBreakType() == DEBUG_BREAK_SLOT_AT_SUSPEND) continue;
    if (source_position <= position()) {
      int first_break = break_index();
      for (; !Done(); Next()) {
        if (GetDebugBreakType() == DEBUG_BREAK_SLOT_AT_SUSPEND) continue;
        if (source_position == position()) return break_index();
      }
      return first_break;
    }
  }
  return break_index();
}

void BreakIterator::Next() {
  DisallowGarbageCollection no_gc;
  DCHECK(!Done());
  bool first = break_index_ == -1;
  while (!Done()) {
    if (!first) source_position_iterator_.Advance();
    first = false;
    if (Done()) return;
    position_ = source_position_iterator_.source_position().ScriptOffset();
    if (source_position_iterator_.is_statement()) {
      statement_position_ = position_;
    }
    DCHECK_LE(0, position_);
    DCHECK_LE(0, statement_position_);

    DebugBreakType type = GetDebugBreakType();
    if (type != NOT_DEBUG_BREAK) break;
  }
  break_index_++;
}

DebugBreakType BreakIterator::GetDebugBreakType() {
  Tagged<BytecodeArray> bytecode_array =
      debug_info_->OriginalBytecodeArray(isolate());
  interpreter::Bytecode bytecode =
      interpreter::Bytecodes::FromByte(bytecode_array->get(code_offset()));

  // Make sure we read the actual bytecode, not a prefix scaling bytecode.
  if (interpreter::Bytecodes::IsPrefixScalingBytecode(bytecode)) {
    bytecode = interpreter::Bytecodes::FromByte(
        bytecode_array->get(code_offset() + 1));
  }

  if (bytecode == interpreter::Bytecode::kDebugger) {
    return DEBUGGER_STATEMENT;
  } else if (bytecode == interpreter::Bytecode::kReturn) {
    return DEBUG_BREAK_SLOT_AT_RETURN;
  } else if (bytecode == interpreter::Bytecode::kSuspendGenerator) {
    // SuspendGenerator should always only carry an expression position that
    // is used in stack trace construction, but should never be a breakable
    // position reported to the debugger front-end.
    DCHECK(!source_position_iterator_.is_statement());
    return DEBUG_BREAK_SLOT_AT_SUSPEND;
  } else if (interpreter::Bytecodes::IsCallOrConstruct(bytecode)) {
    return DEBUG_BREAK_SLOT_AT_CALL;
  } else if (source_position_iterator_.is_statement()) {
    return DEBUG_BREAK_SLOT;
  } else {
    return NOT_DEBUG_BREAK;
  }
}

void BreakIterator::SkipToPosition(int position) {
  BreakIterator it(debug_info_);
  SkipTo(it.BreakIndexFromPosition(position));
}

void BreakIterator::SetDebugBreak() {
  DCHECK(GetDebugBreakType() >= DEBUGGER_STATEMENT);
  HandleScope scope(isolate());
  Handle<BytecodeArray> bytecode_array(
      debug_info_->DebugBytecodeArray(isolate()), isolate());
  interpreter::BytecodeArrayIterator(bytecode_array, code_offset())
      .ApplyDebugBreak();
}

void BreakIterator::ClearDebugBreak() {
  DCHECK(GetDebugBreakType() >= DEBUGGER_STATEMENT);
  Tagged<BytecodeArray> bytecode_array =
      debug_info_->DebugBytecodeArray(isolate());
  Tagged<BytecodeArray> original =
      debug_info_->OriginalBytecodeArray(isolate());
  bytecode_array->set(code_offset(), original->get(code_offset()));
}

BreakLocation BreakIterator::GetBreakLocation() {
  Handle<AbstractCode> code(
      Cast<AbstractCode>(debug_info_->DebugBytecodeArray(isolate())),
      isolate());
  DebugBreakType type = GetDebugBreakType();
  int generator_object_reg_index = -1;
  int generator_suspend_id = -1;
  if (type == DEBUG_BREAK_SLOT_AT_SUSPEND) {
    // For suspend break, we'll need the generator object to be able to step
    // over the suspend as if it didn't return. We get the interpreter register
    // index that holds the generator object by reading it directly off the
    // bytecode array, and we'll read the actual generator object off the
    // interpreter stack frame in GetGeneratorObjectForSuspendedFrame.
    Tagged<BytecodeArray> bytecode_array =
        debug_info_->OriginalBytecodeArray(isolate());
    interpreter::BytecodeArrayIterator iterator(
        handle(bytecode_array, isolate()), code_offset());

    DCHECK_EQ(iterator.current_bytecode(),
              interpreter::Bytecode::kSuspendGenerator);
    interpreter::Register generator_obj_reg = iterator.GetRegisterOperand(0);
    generator_object_reg_index = generator_obj_reg.index();

    // Also memorize the suspend ID, to be able to decide whether
    // we are paused on the implicit initial yield later.
    generator_suspend_id = iterator.GetUnsignedImmediateOperand(3);
  }
  return BreakLocation(code, type, code_offset(), position_,
                       generator_object_reg_index, generator_suspend_id);
}

Isolate* BreakIterator::isolate() { return debug_info_->GetIsolate(); }

// Threading support.
void Debug::ThreadInit() {
  thread_local_.break_frame_id_ = StackFrameId::NO_ID;
  thread_local_.last_step_action_ = StepNone;
  thread_local_.last_statement_position_ = kNoSourcePosition;
  thread_local_.last_bytecode_offset_ = kFunctionEntryBytecodeOffset;
  thread_local_.last_frame_count_ = -1;
  thread_local_.fast_forward_to_return_ = false;
  thread_local_.ignore_step_into_function_ = Smi::zero();
  thread_local_.target_frame_count_ = -1;
  thread_local_.return_value_ = Smi::zero();
  thread_local_.last_breakpoint_id_ = 0;
  clear_restart_frame();
  clear_suspended_generator();
  base::Relaxed_Store(&thread_local_.current_debug_scope_,
                      static_cast<base::AtomicWord>(0));
  thread_local_.break_on_next_function_call_ = false;
  thread_local_.scheduled_break_on_next_function_call_ = false;
  UpdateHookOnFunctionCall();
  thread_local_.muted_function_ = Smi::zero();
  thread_local_.muted_position_ = -1;
}

char* Debug::ArchiveDebug(char* storage) {
  MemCopy(storage, reinterpret_cast<char*>(&thread_local_),
          ArchiveSpacePerThread());
  return storage + ArchiveSpacePerThread();
}

char* Debug::RestoreDebug(char* storage) {
  MemCopy(reinterpret_cast<char*>(&thread_local_), storage,
          ArchiveSpacePerThread());

  // Enter the isolate.
  v8::Isolate::Scope isolate_scope(reinterpret_cast<v8::Isolate*>(isolate_));
  // Enter the debugger.
  DebugScope debug_scope(this);

  // Clear any one-shot breakpoints that may have been set by the other
  // thread, and reapply breakpoints for this thread.
  ClearOneShot();

  if (thread_local_.last_step_action_ != StepNone) {
    int current_frame_count = CurrentFrameCount();
    int target_frame_count = thread_local_.target_frame_count_;
    DCHECK(current_frame_count >= target_frame_count);
    DebuggableStackFrameIterator frames_it(isolate_);
    while (current_frame_count > target_frame_count) {
      current_frame_count -= frames_it.FrameFunctionCount();
      frames_it.Advance();
    }
    DCHECK(current_frame_count == target_frame_count);
    // Set frame to what it was at Step break
    thread_local_.break_frame_id_ = frames_it.frame()->id();

    // Reset the previous step action for this thread.
    PrepareStep(thread_local_.last_step_action_);
  }

  return storage + ArchiveSpacePerThread();
}

int Debug::ArchiveSpacePerThread() { return sizeof(ThreadLocal); }

void Debug::Iterate(RootVisitor* v) { Iterate(v, &thread_local_); }

char* Debug::Iterate(RootVisitor* v, char* thread_storage) {
  ThreadLocal* thread_local_data =
      reinterpret_cast<ThreadLocal*>(thread_storage);
  Iterate(v, thread_local_data);
  return thread_storage + ArchiveSpacePerThread();
}

void Debug::Iterate(RootVisitor* v, ThreadLocal* thread_local_data) {
  v->VisitRootPointer(Root::kDebug, nullptr,
                      FullObjectSlot(&thread_local_data->return_value_));
  v->VisitRootPointer(Root::kDebug, nullptr,
                      FullObjectSlot(&thread_local_data->suspended_generator_));
  v->VisitRootPointer(
      Root::kDebug, nullptr,
      FullObjectSlot(&thread_local_data->ignore_step_into_function_));
  v->VisitRootPointer(Root::kDebug, nullptr,
                      FullObjectSlot(&thread_local_data->muted_function_));
}

void DebugInfoCollection::Insert(Tagged<SharedFunctionInfo> sfi,
                                 Tagged<DebugInfo> debug_info) {
  DisallowGarbageCollection no_gc;
  base::SharedMutexGuard<base::kExclusive> mutex_guard(
      isolate_->shared_function_info_access());

  DCHECK_EQ(sfi, debug_info->shared());
  DCHECK(!Contains(sfi));
  HandleLocation location =
      isolate_->global_handles()->Create(debug_info).location();
  list_.push_back(location);
  map_.emplace(sfi->unique_id(), location);
  DCHECK(Contains(sfi));
  DCHECK_EQ(list_.size(), map_.size());
}

bool DebugInfoCollection::Contains(Tagged<SharedFunctionInfo> sfi) const {
  auto it = map_.find(sfi->unique_id());
  if (it == map_.end()) return false;
  DCHECK_EQ(Cast<DebugInfo>(Tagged<Object>(*it->second))->shared(), sfi);
  return true;
}

std::optional<Tagged<DebugInfo>> DebugInfoCollection::Find(
    Tagged<SharedFunctionInfo> sfi) const {
  auto it = map_.find(sfi->unique_id());
  if (it == map_.end()) return {};
  Tagged<DebugInfo> di = Cast<DebugInfo>(Tagged<Object>(*it->second));
  DCHECK_EQ(di->shared(), sfi);
  return di;
}

void DebugInfoCollection::DeleteSlow(Tagged<SharedFunctionInfo> sfi) {
  DebugInfoCollection::Iterator it(this);
  for (; it.HasNext(); it.Advance()) {
    Tagged<DebugInfo> debug_info = it.Next();
    if (debug_info->shared() != sfi) continue;
    it.DeleteNext();
    return;
  }
  UNREACHABLE();
}

Tagged<DebugInfo> DebugInfoCollection::EntryAsDebugInfo(size_t index) const {
  DCHECK_LT(index, list_.size());
  return Cast<DebugInfo>(Tagged<Object>(*list_[index]));
}

void DebugInfoCollection::DeleteIndex(size_t index) {
  base::SharedMutexGuard<base::kExclusive> mutex_guard(
      isolate_->shared_function_info_access());

  Tagged<DebugInfo> debug_info = EntryAsDebugInfo(index);
  Tagged<SharedFunctionInfo> sfi = debug_info->shared();
  DCHECK(Contains(sfi));

  auto it = map_.find(sfi->unique_id());
  HandleLocation location = it->second;
  DCHECK_EQ(location, list_[index]);
  map_.erase(it);

  list_[index] = list_.back();
  list_.pop_back();

  GlobalHandles::Destroy(location);
  DCHECK(!Contains(sfi));
  DCHECK_EQ(list_.size(), map_.size());
}

void Debug::Unload() {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  ClearAllBreakPoints();
  ClearStepping();
  RemoveAllCoverageInfos();
  ClearAllDebuggerHints();
  debug_delegate_ = nullptr;
}

debug::DebugDelegate::ActionAfterInstrumentation
Debug::OnInstrumentationBreak() {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  if (!debug_delegate_) {
    return debug::DebugDelegate::ActionAfterInstrumentation::
        kPauseIfBreakpointsHit;
  }
  DCHECK(in_debug_scope());
  HandleScope scope(isolate_);
  DisableBreak no_recursive_break(this);

  return debug_delegate_->BreakOnInstrumentation(
      v8::Utils::ToLocal(isolate_->native_context()), kInstrumentationId);
}

void Debug::Break(JavaScriptFrame* frame,
                  DirectHandle<JSFunction> break_target) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  // Just continue if breaks are disabled or debugger cannot be loaded.
  if (break_disabled()) return;

  // Enter the debugger.
  DebugScope debug_scope(this);
  DisableBreak no_recursive_break(this);

  // Return if we fail to retrieve debug info.
  Handle<SharedFunctionInfo> shared(break_target->shared(), isolate_);
  if (!EnsureBreakInfo(shared)) return;
  PrepareFunctionForDebugExecution(shared);

  Handle<DebugInfo> debug_info(TryGetDebugInfo(*shared).value(), isolate_);

  // Find the break location where execution has stopped.
  BreakLocation location = BreakLocation::FromFrame(debug_info, frame);
  const bool hitInstrumentationBreak =
      IsBreakOnInstrumentation(debug_info, location);
  bool shouldPauseAfterInstrumentation = false;
  if (hitInstrumentationBreak) {
    debug::DebugDelegate::ActionAfterInstrumentation action =
        OnInstrumentationBreak();
    switch (action) {
      case debug::DebugDelegate::ActionAfterInstrumentation::kPause:
        shouldPauseAfterInstrumentation = true;
        break;
      case debug::DebugDelegate::ActionAfterInstrumentation::
          kPauseIfBreakpointsHit:
        shouldPauseAfterInstrumentation = false;
        break;
      case debug::DebugDelegate::ActionAfterInstrumentation::kContinue:
        return;
    }
  }

  // Find actual break points, if any, and trigger debug break event.
  ClearMutedLocation();
  bool has_break_points;
  bool scheduled_break =
      scheduled_break_on_function_call() || shouldPauseAfterInstrumentation;
  MaybeHandle<FixedArray> break_points_hit =
      CheckBreakPoints(debug_info, &location, &has_break_points);
  if (!break_points_hit.is_null() || break_on_next_function_call() ||
      scheduled_break) {
    StepAction lastStepAction = last_step_action();
    debug::BreakReasons break_reasons;
    if (scheduled_break) {
      break_reasons.Add(debug::BreakReason::kScheduled);
    }
    // If it's a debugger statement, add the reason and then mute the location
    // so we don't stop a second time.
    bool is_debugger_statement = IsBreakOnDebuggerStatement(shared, location);
    if (is_debugger_statement) {
      break_reasons.Add(debug::BreakReason::kDebuggerStatement);
    }

    // Clear all current stepping setup.
    ClearStepping();
    // Notify the debug event listeners.
    OnDebugBreak(!break_points_hit.is_null()
                     ? break_points_hit.ToHandleChecked()
                     : isolate_->factory()->empty_fixed_array(),
                 lastStepAction, break_reasons);

    if (is_debugger_statement) {
      // Don't pause here a second time
      SetMutedLocation(shared, location);
    }
    return;
  }

  // Debug break at function entry, do not worry about stepping.
  if (location.IsDebugBreakAtEntry()) {
    DCHECK(debug_info->BreakAtEntry());
    return;
  }

  DCHECK_NOT_NULL(frame);

  // No break point. Check for stepping.
  StepAction step_action = last_step_action();
  int current_frame_count = CurrentFrameCount();
  int target_frame_count = thread_local_.target_frame_count_;
  int last_frame_count = thread_local_.last_frame_count_;

  // StepOut at not return position was requested and return break locations
  // were flooded with one shots.
  if (thread_local_.fast_forward_to_return_) {
    // We might hit an instrumentation breakpoint before running into a
    // return/suspend location.
    DCHECK(location.IsReturnOrSuspend() || hitInstrumentationBreak);
    // We have to ignore recursive calls to function.
    if (current_frame_count > target_frame_count) return;
    ClearStepping();
    PrepareStep(StepOut);
    return;
  }

  bool step_break = false;
  switch (step_action) {
    case StepNone:
      if (has_break_points) {
        SetMutedLocation(shared, location);
      }
      return;
    case StepOut:
      // StepOut should not break in a deeper frame than target frame.
      if (current_frame_count > target_frame_count) return;
      step_break = true;
      break;
    case StepOver:
      // StepOver should not break in a deeper frame than target frame.
      if (current_frame_count > target_frame_count) return;
      [[fallthrough]];
    case StepInto: {
      // StepInto and StepOver should enter "generator stepping" mode, except
      // for the implicit initial yield in generators, where it should simply
      // step out of the generator function.
      if (location.IsSuspend()) {
        DCHECK(!has_suspended_generator());
        ClearStepping();
        if (!IsGeneratorFunction(shared->kind()) ||
            location.generator_suspend_id() > 0) {
          thread_local_.suspended_generator_ =
              location.GetGeneratorObjectForSuspendedFrame(frame);
        } else {
          PrepareStep(StepOut);
        }
        return;
      }
      FrameSummary summary = FrameSummary::GetTop(frame);
      const bool frame_or_statement_changed =
          current_frame_count != last_frame_count ||
          thread_local_.last_statement_position_ !=
              summary.SourceStatementPosition();
      // If we stayed on the same frame and reached the same bytecode offset
      // since the last step, we are in a loop and should pause. Otherwise
      // we keep "stepping" through the loop without ever acutally pausing.
      const bool potential_single_statement_loop =
          current_frame_count == last_frame_count &&
          thread_local_.last_bytecode_offset_ == summary.code_offset();
      step_break = step_break || location.IsReturn() ||
                   potential_single_statement_loop ||
                   frame_or_statement_changed;
      break;
    }
  }

  StepAction lastStepAction = last_step_action();
  // Clear all current stepping setup.
  ClearStepping();

  if (step_break) {
    // If it's a debugger statement, add the reason and then mute the location
    // so we don't stop a second time.
    debug::BreakReasons break_reasons;
    bool is_debugger_statement = IsBreakOnDebuggerStatement(shared, location);
    if (is_debugger_statement) {
      break_reasons.Add(debug::BreakReason::kDebuggerStatement);
    }
    // Notify the debug event listeners.
    OnDebugBreak(isolate_->factory()->empty_fixed_array(), lastStepAction,
                 break_reasons);

    if (is_debugger_statement) {
      // Don't pause here a second time
      SetMutedLocation(shared, location);
    }
  } else {
    // Re-prepare to continue.
    PrepareStep(step_action);
  }
}

bool Debug::IsBreakOnInstrumentation(Handle<DebugInfo> debug_info,
                                     const BreakLocation& location) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  bool has_break_points_to_check =
      break_points_active_ && location.HasBreakPoint(isolate_, debug_info);
  if (!has_break_points_to_check) return {};

  DirectHandle<Object> break_points =
      debug_info->GetBreakPoints(isolate_, location.position());
  DCHECK(!IsUndefined(*break_points, isolate_));
  if (!IsFixedArray(*break_points)) {
    const auto break_point = Cast<BreakPoint>(break_points);
    return break_point->id() == kInstrumentationId;
  }

  DirectHandle<FixedArray> array(Cast<FixedArray>(*break_points), isolate_);
  for (int i = 0; i < array->length(); ++i) {
    const auto break_point =
        Cast<BreakPoint>(direct_handle(array->get(i), isolate_));
    if (break_point->id() == kInstrumentationId) {
      return true;
    }
  }
  return false;
}

bool Debug::IsBreakOnDebuggerStatement(
    DirectHandle<SharedFunctionInfo> function, const BreakLocation& location) {
  if (!function->HasBytecodeArray()) {
    return false;
  }
  Tagged<BytecodeArray> original_bytecode =
      function->GetBytecodeArray(isolate_);
  interpreter::Bytecode bytecode = interpreter::Bytecodes::FromByte(
      original_bytecode->get(location.code_offset()));
  return bytecode == interpreter::Bytecode::kDebugger;
}

// Find break point objects for this location, if any, and evaluate them.
// Return an array of break point objects that evaluated true, or an empty
// handle if none evaluated true.
// has_break_points will be true, if there is any (non-instrumentation)
// breakpoint.
MaybeHandle<FixedArray> Debug::CheckBreakPoints(Handle<DebugInfo> debug_info,
                                                BreakLocation* location,
                                                bool* has_break_points) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  bool has_break_points_to_check =
      break_points_active_ && location->HasBreakPoint(isolate_, debug_info);
  if (!has_break_points_to_check) {
    *has_break_points = false;
    return {};
  }

  return Debug::GetHitBreakPoints(debug_info, location->position(),
                                  has_break_points);
}

bool Debug::IsMutedAtAnyBreakLocation(
    DirectHandle<SharedFunctionInfo> function,
    const std::vector<BreakLocation>& locations) {
  // A break location is considered muted if break locations on the current
  // statement have at least one break point, and all of these break points
  // evaluate to false. Aside from not triggering a debug break event at the
  // brea
```