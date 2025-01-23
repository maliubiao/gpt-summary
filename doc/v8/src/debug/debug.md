Response: The user wants me to summarize the functionality of the C++ code provided in `v8/src/debug/debug.cc`. I also need to illustrate the connection to JavaScript using JavaScript examples.

**Plan:**

1. **High-level overview:**  Identify the core purpose of this file within the V8 project. Keywords like "debug", "breakpoints", "stepping" are prominent.
2. **Key components:**  Break down the code into logical sections based on the classes and functions. Focus on:
    * `Debug` class:  Central class, managing debug state.
    * Breakpoint handling: Setting, clearing, checking breakpoints.
    * Stepping:  Implementing step-in, step-out, step-over.
    * Exception handling: Breaking on exceptions.
    * Threading support:  How debugging interacts with multiple threads.
    * `BreakLocation` and `BreakIterator`: Data structures and logic for managing breakable points.
    * `DebugInfoCollection`:  Managing debug information for functions.
3. **Relationship to JavaScript:** Explain how the C++ code enables debugging features accessible in JavaScript. This will involve concepts like:
    * `debugger` statement.
    * Developer tools (breakpoints, stepping).
    * Error handling (try/catch).
4. **JavaScript examples:**  Provide concise JavaScript code snippets that demonstrate the functionality implemented in the C++ code. Connect specific C++ features to their JavaScript counterparts.
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
    
### 提示词
```
这是目录为v8/src/debug/debug.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```
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
  // break location, we also do not trigger one for debugger statements, nor
  // an exception event on exception at this location.
  // This should have been computed at last break, and we should just
  // check that we are not at that location.

  if (IsSmi(thread_local_.muted_function_) ||
      *function != thread_local_.muted_function_) {
    return false;
  }

  for (const BreakLocation& location : locations) {
    if (location.position() == thread_local_.muted_position_) {
      return true;
    }
  }

  return false;
}

#if V8_ENABLE_WEBASSEMBLY
void Debug::SetMutedWasmLocation(DirectHandle<Script> script, int position) {
  thread_local_.muted_function_ = *script;
  thread_local_.muted_position_ = position;
}

bool Debug::IsMutedAtWasmLocation(Tagged<Script> script, int position) {
  return script == thread_local_.muted_function_ &&
         position == thread_local_.muted_position_;
}
#endif  // V8_ENABLE_WEBASSEMBLY

namespace {

// Convenience helper for easier std::optional translation.
bool ToHandle(Isolate* isolate, std::optional<Tagged<DebugInfo>> debug_info,
              Handle<DebugInfo>* out) {
  if (!debug_info.has_value()) return false;
  *out = handle(debug_info.value(), isolate);
  return true;
}

}  // namespace

// Check whether a single break point object is triggered.
bool Debug::CheckBreakPoint(DirectHandle<BreakPoint> break_point,
                            bool is_break_at_entry) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  HandleScope scope(isolate_);

  // Instrumentation breakpoints are handled separately.
  if (break_point->id() == kInstrumentationId) {
    return false;
  }

  if (!break_point->condition()->length()) return true;
  Handle<String> condition(break_point->condition(), isolate_);
  MaybeHandle<Object> maybe_result;
  Handle<Object> result;

  if (is_break_at_entry) {
    maybe_result = DebugEvaluate::WithTopmostArguments(isolate_, condition);
  } else {
    // Since we call CheckBreakpoint only for deoptimized frame on top of stack,
    // we can use 0 as index of inlined frame.
    const int inlined_jsframe_index = 0;
    const bool throw_on_side_effect = false;
    maybe_result =
        DebugEvaluate::Local(isolate_, break_frame_id(), inlined_jsframe_index,
                             condition, throw_on_side_effect);
  }

  Handle<Object> maybe_exception;
  bool exception_thrown = true;
  if (maybe_result.ToHandle(&result)) {
    exception_thrown = false;
  } else if (isolate_->has_exception()) {
    maybe_exception = handle(isolate_->exception(), isolate_);
    isolate_->clear_exception();
  }

  CHECK(in_debug_scope());
  DisableBreak no_recursive_break(this);

  {
    RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebuggerCallback);
    debug_delegate_->BreakpointConditionEvaluated(
        v8::Utils::ToLocal(isolate_->native_context()), break_point->id(),
        exception_thrown, v8::Utils::ToLocal(maybe_exception));
  }

  return !result.is_null() ? Object::BooleanValue(*result, isolate_) : false;
}

bool Debug::SetBreakpoint(Handle<SharedFunctionInfo> shared,
                          DirectHandle<BreakPoint> break_point,
                          int* source_position) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  HandleScope scope(isolate_);

  // Make sure the function is compiled and has set up the debug info.
  if (!EnsureBreakInfo(shared)) return false;
  PrepareFunctionForDebugExecution(shared);

  Handle<DebugInfo> debug_info(TryGetDebugInfo(*shared).value(), isolate_);
  // Source positions starts with zero.
  DCHECK_LE(0, *source_position);

  // Find the break point and change it.
  *source_position = FindBreakablePosition(debug_info, *source_position);
  DebugInfo::SetBreakPoint(isolate_, debug_info, *source_position, break_point);
  // At least one active break point now.
  DCHECK_LT(0, debug_info->GetBreakPointCount(isolate_));

  ClearBreakPoints(debug_info);
  ApplyBreakPoints(debug_info);
  return true;
}

bool Debug::SetBreakPointForScript(Handle<Script> script,
                                   DirectHandle<String> condition,
                                   int* source_position, int* id) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  *id = ++thread_local_.last_breakpoint_id_;
  DirectHandle<BreakPoint> break_point =
      isolate_->factory()->NewBreakPoint(*id, condition);
#if V8_ENABLE_WEBASSEMBLY
  if (script->type() == Script::Type::kWasm) {
    RecordWasmScriptWithBreakpoints(script);
    return WasmScript::SetBreakPoint(script, source_position, break_point);
  }
#endif  //  V8_ENABLE_WEBASSEMBLY

  HandleScope scope(isolate_);

  // Obtain shared function info for the innermost function containing this
  // position.
  Handle<Object> result =
      FindInnermostContainingFunctionInfo(script, *source_position);
  if (IsUndefined(*result, isolate_)) return false;

  auto shared = Cast<SharedFunctionInfo>(result);
  if (!EnsureBreakInfo(shared)) return false;
  PrepareFunctionForDebugExecution(shared);

  // Find the nested shared function info that is closest to the position within
  // the containing function.
  shared = FindClosestSharedFunctionInfoFromPosition(*source_position, script,
                                                     shared);

  // Set the breakpoint in the function.
  return SetBreakpoint(shared, break_point, source_position);
}

int Debug::FindBreakablePosition(Handle<DebugInfo> debug_info,
                                 int source_position) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  if (debug_info->CanBreakAtEntry()) {
    return kBreakAtEntryPosition;
  } else {
    DCHECK(debug_info->HasInstrumentedBytecodeArray());
    BreakIterator it(debug_info);
    it.SkipToPosition(source_position);
    return it.position();
  }
}

void Debug::ApplyBreakPoints(Handle<DebugInfo> debug_info) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  DisallowGarbageCollection no_gc;
  if (debug_info->CanBreakAtEntry()) {
    debug_info->SetBreakAtEntry();
  } else {
    if (!debug_info->HasInstrumentedBytecodeArray()) return;
    Tagged<FixedArray> break_points = debug_info->break_points();
    for (int i = 0; i < break_points->length(); i++) {
      if (IsUndefined(break_points->get(i), isolate_)) continue;
      Tagged<BreakPointInfo> info = Cast<BreakPointInfo>(break_points->get(i));
      if (info->GetBreakPointCount(isolate_) == 0) continue;
      DCHECK(debug_info->HasInstrumentedBytecodeArray());
      BreakIterator it(debug_info);
      it.SkipToPosition(info->source_position());
      it.SetDebugBreak();
    }
  }
  debug_info->SetDebugExecutionMode(DebugInfo::kBreakpoints);
}

void Debug::ClearBreakPoints(Handle<DebugInfo> debug_info) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  if (debug_info->CanBreakAtEntry()) {
    debug_info->ClearBreakAtEntry();
  } else {
    // If we attempt to clear breakpoints but none exist, simply return. This
    // can happen e.g. CoverageInfos exist but no breakpoints are set.
    if (!debug_info->HasInstrumentedBytecodeArray() ||
        !debug_info->HasBreakInfo()) {
      return;
    }

    DisallowGarbageCollection no_gc;
    for (BreakIterator it(debug_info); !it.Done(); it.Next()) {
      it.ClearDebugBreak();
    }
  }
}

void Debug::ClearBreakPoint(DirectHandle<BreakPoint> break_point) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  HandleScope scope(isolate_);

  DebugInfoCollection::Iterator it(&debug_infos_);
  for (; it.HasNext(); it.Advance()) {
    Handle<DebugInfo> debug_info(it.Next(), isolate_);
    if (!debug_info->HasBreakInfo()) continue;

    DirectHandle<Object> result =
        DebugInfo::FindBreakPointInfo(isolate_, debug_info, break_point);
    if (IsUndefined(*result, isolate_)) continue;

    if (DebugInfo::ClearBreakPoint(isolate_, debug_info, break_point)) {
      ClearBreakPoints(debug_info);
      if (debug_info->GetBreakPointCount(isolate_) == 0) {
        debug_info->ClearBreakInfo(isolate_);
        if (debug_info->IsEmpty()) it.DeleteNext();
      } else {
        ApplyBreakPoints(debug_info);
      }
      return;
    }
  }
}

int Debug::GetFunctionDebuggingId(DirectHandle<JSFunction> function) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  DirectHandle<SharedFunctionInfo> shared(function->shared(), isolate_);
  DirectHandle<DebugInfo> debug_info = GetOrCreateDebugInfo(shared);
  int id = debug_info->debugging_id();
  if (id == DebugInfo::kNoDebuggingId) {
    id = isolate_->heap()->NextDebuggingId();
    debug_info->set_debugging_id(id);
  }
  return id;
}

bool Debug::SetBreakpointForFunction(Handle<SharedFunctionInfo> shared,
                                     DirectHandle<String> condition, int* id,
                                     BreakPointKind kind) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  if (kind == kInstrumentation) {
    *id = kInstrumentationId;
  } else {
    *id = ++thread_local_.last_breakpoint_id_;
  }
  DirectHandle<BreakPoint> breakpoint =
      isolate_->factory()->NewBreakPoint(*id, condition);
  int source_position = 0;
#if V8_ENABLE_WEBASSEMBLY
  if (shared->HasWasmExportedFunctionData()) {
    Tagged<WasmExportedFunctionData> function_data =
        shared->wasm_exported_function_data();
    int func_index = function_data->function_index();
    // TODO(42204563): Avoid crashing if the instance object is not available.
    CHECK(function_data->instance_data()->has_instance_object());
    Tagged<WasmModuleObject> module_obj =
        function_data->instance_data()->instance_object()->module_object();
    DirectHandle<Script> script(module_obj->script(), isolate_);
    return WasmScript::SetBreakPointOnFirstBreakableForFunction(
        script, func_index, breakpoint);
  }
#endif  // V8_ENABLE_WEBASSEMBLY
  return SetBreakpoint(shared, breakpoint, &source_position);
}

void Debug::RemoveBreakpoint(int id) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  DirectHandle<BreakPoint> breakpoint = isolate_->factory()->NewBreakPoint(
      id, isolate_->factory()->empty_string());
  ClearBreakPoint(breakpoint);
}

#if V8_ENABLE_WEBASSEMBLY
void Debug::SetInstrumentationBreakpointForWasmScript(Handle<Script> script,
                                                      int* id) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  DCHECK_EQ(Script::Type::kWasm, script->type());
  *id = kInstrumentationId;

  DirectHandle<BreakPoint> break_point = isolate_->factory()->NewBreakPoint(
      *id, isolate_->factory()->empty_string());
  RecordWasmScriptWithBreakpoints(script);
  WasmScript::SetInstrumentationBreakpoint(script, break_point);
}

void Debug::RemoveBreakpointForWasmScript(DirectHandle<Script> script, int id) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  if (script->type() == Script::Type::kWasm) {
    WasmScript::ClearBreakPointById(script, id);
  }
}

void Debug::RecordWasmScriptWithBreakpoints(Handle<Script> script) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  if (wasm_scripts_with_break_points_.is_null()) {
    DirectHandle<WeakArrayList> new_list =
        isolate_->factory()->NewWeakArrayList(4);
    wasm_scripts_with_break_points_ =
        isolate_->global_handles()->Create(*new_list);
  }
  {
    DisallowGarbageCollection no_gc;
    for (int idx = wasm_scripts_with_break_points_->length() - 1; idx >= 0;
         --idx) {
      Tagged<HeapObject> wasm_script;
      if (wasm_scripts_with_break_points_->Get(idx).GetHeapObject(
              &wasm_script) &&
          wasm_script == *script) {
        return;
      }
    }
  }
  DirectHandle<WeakArrayList> new_list =
      WeakArrayList::Append(isolate_, wasm_scripts_with_break_points_,
                            MaybeObjectDirectHandle{script});
  if (*new_list != *wasm_scripts_with_break_points_) {
    isolate_->global_handles()->Destroy(
        wasm_scripts_with_break_points_.location());
    wasm_scripts_with_break_points_ =
        isolate_->global_handles()->Create(*new_list);
  }
}
#endif  // V8_ENABLE_WEBASSEMBLY

// Clear out all the debug break code.
void Debug::ClearAllBreakPoints() {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  ClearAllDebugInfos([=, this](Handle<DebugInfo> info) {
    ClearBreakPoints(info);
    info->ClearBreakInfo(isolate_);
  });
#if V8_ENABLE_WEBASSEMBLY
  // Clear all wasm breakpoints.
  if (!wasm_scripts_with_break_points_.is_null()) {
    DisallowGarbageCollection no_gc;
    for (int idx = wasm_scripts_with_break_points_->length() - 1; idx >= 0;
         --idx) {
      Tagged<HeapObject> raw_wasm_script;
      if (wasm_scripts_with_break_points_->Get(idx).GetHeapObject(
              &raw_wasm_script)) {
        Tagged<Script> wasm_script = Cast<Script>(raw_wasm_script);
        WasmScript::ClearAllBreakpoints(wasm_script);
        wasm_script->wasm_native_module()->GetDebugInfo()->RemoveIsolate(
            isolate_);
      }
    }
    wasm_scripts_with_break_points_ = Handle<WeakArrayList>{};
  }
#endif  // V8_ENABLE_WEBASSEMBLY
}

void Debug::FloodWithOneShot(Handle<SharedFunctionInfo> shared,
                             bool returns_only) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  if (IsBlackboxed(shared)) return;
  // Make sure the function is compiled and has set up the debug info.
  if (!EnsureBreakInfo(shared)) return;
  PrepareFunctionForDebugExecution(shared);

  Handle<DebugInfo> debug_info(TryGetDebugInfo(*shared).value(), isolate_);
  // Flood the function with break points.
  DCHECK(debug_info->HasInstrumentedBytecodeArray());
  for (BreakIterator it(debug_info); !it.Done(); it.Next()) {
    if (returns_only && !it.GetBreakLocation().IsReturnOrSuspend()) continue;
    it.SetDebugBreak();
  }
}

void Debug::ChangeBreakOnException(ExceptionBreakType type, bool enable) {
  if (type == BreakUncaughtException) {
    break_on_uncaught_exception_ = enable;
  } else {
    break_on_caught_exception_ = enable;
  }
}

bool Debug::IsBreakOnException(ExceptionBreakType type) {
  if (type == BreakUncaughtException) {
    return break_on_uncaught_exception_;
  } else {
    return break_on_caught_exception_;
  }
}

MaybeHandle<FixedArray> Debug::GetHitBreakPoints(
    DirectHandle<DebugInfo> debug_info, int position, bool* has_break_points) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  DirectHandle<Object> break_points =
      debug_info->GetBreakPoints(isolate_, position);
  bool is_break_at_entry = debug_info->BreakAtEntry();
  DCHECK(!IsUndefined(*break_points, isolate_));
  if (!IsFixedArray(*break_points)) {
    const auto break_point = Cast<BreakPoint>(break_points);
    *has_break_points = break_point->id() != kInstrumentationId;
    if (!CheckBreakPoint(break_point, is_break_at_entry)) {
      return {};
    }
    Handle<FixedArray> break_points_hit = isolate_->factory()->NewFixedArray(1);
    break_points_hit->set(0, *break_points);
    return break_points_hit;
  }

  DirectHandle<FixedArray> array(Cast<FixedArray>(*break_points), isolate_);
  int num_objects = array->length();
  Handle<FixedArray> break_points_hit =
      isolate_->factory()->NewFixedArray(num_objects);
  int break_points_hit_count = 0;
  *has_break_points = false;
  for (int i = 0; i < num_objects; ++i) {
    const auto break_point =
        Cast<BreakPoint>(direct_handle(array->get(i), isolate_));
    *has_break_points |= break_point->id() != kInstrumentationId;
    if (CheckBreakPoint(break_point, is_break_at_entry)) {
      break_points_hit->set(break_points_hit_count++, *break_point);
    }
  }
  if (break_points_hit_count == 0) return {};
  break_points_hit->RightTrim(isolate_, break_points_hit_count);
  return break_points_hit;
}

void Debug::SetBreakOnNextFunctionCall() {
  // This method forces V8 to break on next function call regardless current
  // last_step_action_. If any break happens between SetBreakOnNextFunctionCall
  // and ClearBreakOnNextFunctionCall, we will clear this flag and stepping. If
  // break does not happen, e.g. all called functions are blackboxed or no
  // function is called, then we will clear this flag and let stepping continue
  // its normal business.
  thread_local_.break_on_next_function_call_ = true;
  UpdateHookOnFunctionCall();
}

void Debug::ClearBreakOnNextFunctionCall() {
  thread_local_.break_on_next_function_call_ = false;
  UpdateHookOnFunctionCall();
}

void Debug::PrepareStepIn(DirectHandle<JSFunction> function) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  CHECK(last_step_action() >= StepInto || break_on_next_function_call() ||
        scheduled_break_on_function_call());
  if (ignore_events()) return;
  if (in_debug_scope()) return;
  if (break_disabled()) return;
  Handle<SharedFunctionInfo> shared(function->shared(), isolate_);
  if (IsBlackboxed(shared)) return;
  if (*function == thread_local_.ignore_step_into_function_) return;
  thread_local_.ignore_step_into_function_ = Smi::zero();
  FloodWithOneShot(shared);
}

void Debug::PrepareStepInSuspendedGenerator() {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  CHECK(has_suspended_generator());
  if (ignore_events()) return;
  if (in_debug_scope()) return;
  if (break_disabled()) return;
  thread_local_.last_step_action_ = StepInto;
  UpdateHookOnFunctionCall();
  DirectHandle<JSFunction> function(
      Cast<JSGeneratorObject>(thread_local_.suspended_generator_)->function(),
      isolate_);
  FloodWithOneShot(handle(function->shared(), isolate_));
  clear_suspended_generator();
}

void Debug::PrepareStepOnThrow() {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  if (last_step_action() == StepNone) return;
  if (ignore_events()) return;
  if (in_debug_scope()) return;
  if (break_disabled()) return;

  ClearOneShot();

  int current_frame_count = CurrentFrameCount();

  // Iterate through the JavaScript stack looking for handlers.
  JavaScriptStackFrameIterator it(isolate_);
  while (!it.done()) {
    JavaScriptFrame* frame = it.frame();
    if (frame->LookupExceptionHandlerInTable(nullptr, nullptr) > 0) break;
    std::vector<Tagged<SharedFunctionInfo>> infos;
    frame->GetFunctions(&infos);
    current_frame_count -= infos.size();
    it.Advance();
  }

  // No handler found. Nothing to instrument.
  if (it.done()) return;

  bool found_handler = false;
  // Iterate frames, including inlined frames. First, find the handler frame.
  // Then skip to the frame we want to break in, then instrument for stepping.
  for (; !it.done(); it.Advance()) {
    JavaScriptFrame* frame = JavaScriptFrame::cast(it.frame());
    if (last_step_action() == StepInto) {
      // Deoptimize frame to ensure calls are checked for step-in.
      Deoptimizer::DeoptimizeFunction(frame->function());
    }
    std::vector<FrameSummary> summaries;
    frame->Summarize(&summaries);
    for (size_t i = summaries.size(); i != 0; i--, current_frame_count--) {
      const FrameSummary& summary = summaries[i - 1];
      if (!found_handler) {
        // We have yet to find the handler. If the frame inlines multiple
        // functions, we have to check each one for the handler.
        // If it only contains one function, we already found the handler.
        if (summaries.size() > 1) {
          DirectHandle<AbstractCode> code =
              summary.AsJavaScript().abstract_code();
          CHECK_EQ(CodeKind::INTERPRETED_FUNCTION, code->kind(isolate_));
          HandlerTable table(code->GetBytecodeArray());
          int code_offset = summary.code_offset();
          found_handler = table.LookupHandlerIndexForRange(code_offset) !=
                          HandlerTable::kNoHandlerFound;
        } else {
          found_handler = true;
        }
      }

      if (found_handler) {
        // We found the handler. If we are stepping next or out, we need to
        // iterate until we found the suitable target frame to break in.
        if ((last_step_action() == StepOver || last_step_action() == StepOut) &&
            current_frame_count > thread_local_.target_frame_count_) {
          continue;
        }
        Handle<SharedFunctionInfo> info(
            summary.AsJavaScript().function()->shared(), isolate_);
        if (IsBlackboxed(info)) continue;
        FloodWithOneShot(info);
        return;
      }
    }
  }
}

void Debug::PrepareStep(StepAction step_action) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  HandleScope scope(isolate_);

  DCHECK(in_debug_scope());

  // Get the frame where the execution has stopped and skip the debug frame if
  // any. The debug frame will only be present if execution was stopped due to
  // hitting a break point. In other situations (e.g. unhandled exception) the
  // debug frame is not present.
  StackFrameId frame_id = break_frame_id();
  // If there is no JavaScript stack don't do anything.
  if (frame_id == StackFrameId::NO_ID) return;

  thread_local_.last_step_action_ = step_action;

  DebuggableStackFrameIterator frames_it(isolate_, frame_id);
  CommonFrame* frame = frames_it.frame();

  BreakLocation location = BreakLocation::Invalid();
  Handle<SharedFunctionInfo> shared;
  int current_frame_count = CurrentFrameCount();

  if (frame->is_javascript()) {
    JavaScriptFrame* js_frame = JavaScriptFrame::cast(frame);
    DCHECK(IsJSFunction(js_frame->function()));

    // Get the debug info (create it if it does not exist).
    auto summary = FrameSummary::GetTop(frame).AsJavaScript();
    DirectHandle<JSFunction> function(summary.function());
    shared = Handle<SharedFunctionInfo>(function->shared(), isolate_);
    if (!EnsureBreakInfo(shared)) return;
    PrepareFunctionForDebugExecution(shared);

    // PrepareFunctionForDebugExecution can invalidate Baseline frames
    js_frame = JavaScriptFrame::cast(frames_it.Reframe());

    Handle<DebugInfo> debug_info(TryGetDebugInfo(*shared).value(), isolate_);
    location = BreakLocation::FromFrame(debug_info, js_frame);

    // Any step at a return is a step-out, and a step-out at a suspend behaves
    // like a return.
    if (location.IsReturn() ||
        (location.IsSuspend() && step_action == StepOut)) {
      // On StepOut we'll ignore our further calls to current function in
      // PrepareStepIn callback.
      if (last_step_action() == StepOut) {
        thread_local_.ignore_step_into_function_ = *function;
      }
      step_action = StepOut;
      thread_local_.last_step_action_ = StepInto;
    }

    // We need to schedule DebugOnFunction call callback
    UpdateHookOnFunctionCall();

    // A step-next in blackboxed function is a step-out.
    if (step_action == StepOver && IsBlackboxed(shared)) step_action = StepOut;

    thread_local_.last_statement_position_ = summary.SourceStatementPosition();
    thread_local_.last_bytecode_offset_ = summary.code_offset();
    thread_local_.last_frame_count_ = current_frame_count;
    // No longer perform the current async step.
    clear_suspended_generator();
#if V8_ENABLE_WEBASSEMBLY
  } else if (frame->is_wasm() && step_action != StepOut) {
#if V8_ENABLE_DRUMBRAKE
    // TODO(paolosev@microsoft.com) - If we are running with the interpreter, we
    // cannot step.
    if (frame->is_wasm_interpreter_entry()) return;
#endif  // V8_ENABLE_DRUMBRAKE
    // Handle stepping in wasm.
    WasmFrame* wasm_frame = WasmFrame::cast(frame);
    auto* debug_info = wasm_frame->native_module()->GetDebugInfo();
    if (debug_info->PrepareStep(wasm_frame)) {
      UpdateHookOnFunctionCall();
      return;
    }
    // If the wasm code is not debuggable or will return after this step
    // (indicated by {PrepareStep} returning false), then step out of that frame
    // instead.
    step_action = StepOut;
    UpdateHookOnFunctionCall();
#endif  // V8_ENABLE_WEBASSEMBLY
  }

  switch (step_action) {
    case StepNone:
      UNREACHABLE();
    case StepOut: {
      // Clear last position info. For stepping out it does not matter.
      thread_local_.last_statement_position_ = kNoSourcePosition;
      thread_local_.last_bytecode_offset_ = kFunctionEntryBytecodeOffset;
      thread_local_.last_frame_count_ = -1;
      if (!shared.is_null()) {
        if (!location.IsReturnOrSuspend() && !IsBlackboxed(shared)) {
          // At not return position we flood return positions with one shots and
          // will repeat StepOut automatically at next break.
          thread_local_.target_frame_count_ = current_frame_count;
          thread_local_.fast_forward_to_return_ = true;
          FloodWithOneShot(shared, true);
          return;
        }
        if (IsAsyncFunction(shared->kind())) {
          // Stepping out of an async function whose implicit promise is awaited
          // by some other async function, should resume the latter. The return
          // value here is either a JSPromise or a JSGeneratorObject (for the
          // initial yield of async generators).
          Handle<JSReceiver> return_value(
              Cast<JSReceiver>(thread_local_.return_value_), isolate_);
          DirectHandle<Object> awaited_by_holder = JSReceiver::GetDataProperty(
              isolate_, return_value,
              isolate_->factory()->promise_awaited_by_symbol());
          if (IsWeakFixedArray(*awaited_by_holder, isolate_)) {
            auto weak_fixed_array = Cast<WeakFixedArray>(awaited_by_holder);
            if (weak_fixed_array->length() == 1 &&
                weak_fixed_array->get(0).IsWeak()) {
              DirectHandle<HeapObject> awaited_by(
                  weak_fixed_array->get(0).GetHeapObjectAssumeWeak(isolate_),
                  isolate_);
              if (IsJSGeneratorObject(*awaited_by)) {
                DCHECK(!has_suspended_generator());
                thread_local_.suspended_generator_ = *awaited_by;
                ClearStepping();
                return;
              }
            }
          }
        }
      }
      // Skip the current frame, find the first frame we want to step out to
      // and deoptimize every frame along the way.
      bool in_current_frame = true;
      for (; !frames_it.done(); frames_it.Advance()) {
#if V8_ENABLE_WEBASSEMBLY
#if V8_ENABLE_DRUMBRAKE
        // TODO(paolosev@microsoft.com): Implement stepping out from JS to wasm
        // interpreter.
        if (frame->is_wasm_interpreter_entry()) continue;
#endif  // V8_ENABLE_DRUMBRAKE
        if (frames_it.frame()->is_wasm()) {
          if (in_current_frame) {
            in_current_frame = false;
            continue;
          }
          // Handle stepping out into Wasm.
          WasmFrame* wasm_frame = WasmFrame::cast(frames_it.frame());
          auto* debug_info = wasm_frame->native_module()->GetDebugInfo();
          if (debug_info->IsFrameBlackboxed(wasm_frame)) continue;
          debug_info->PrepareStepOutTo(wasm_frame);
          return;
        }
#endif  // V8_ENABLE_WEBASSEMBLY
        JavaScriptFrame* js_frame = JavaScriptFrame::cast(frames_it.frame());
        if (last_step_action() == StepInto) {
          // Deoptimize frame to ensure calls are checked for step-in.
          Deoptimizer::DeoptimizeFunction(js_frame->function());
        }
        HandleScope inner_scope(isolate_);
        std::vector<Handle<SharedFunctionInfo>> infos;
        js_frame->GetFunctions(&infos);
        for (; !infos.empty(); current_frame_count--) {
          Handle<SharedFunctionInfo> info = infos.back();
          infos.pop_back();
          if (in_current_frame) {
            // We want to step out, so skip the current frame.
            in_current_frame = false;
            continue;
          }
          if (IsBlackboxed(info)) continue;
          FloodWithOneShot(info);
          thread_local_.target_frame_count_ = current_frame_count;
          return;
        }
      }
      break;
    }
    case StepOver:
      thread_local_.target_frame_count_ = current_frame_count;
      [[fallthrough]];
    case StepInto:
      FloodWithOneShot(shared);
      break;
  }
}

// Simple function for returning the source positions for active break points.
// static
Handle<Object> Debug::GetSourceBreakLocations(
    Isolate* isolate, DirectHandle<SharedFunctionInfo> shared) {
  RCS_SCOPE(isolate, RuntimeCallCounterId::kDebugger);
  if (!shared->HasBreakInfo(isolate)) {
    return isolate->factory()->undefined_value();
  }

  DirectHandle<DebugInfo> debug_info(
      isolate->debug()->TryGetDebugInfo(*shared).value(), isolate);
  if (debug_info->GetBreakPointCount(isolate) == 0) {
    return isolate->factory()->undefined_value();
  }
  Handle<FixedArray> locations = isolate->factory()->NewFixedArray(
      debug_info->GetBreakPointCount(isolate));
  int count = 0;
  for (int i = 0; i < debug_info->break_points()->length(); ++i) {
    if (!IsUndefined(debug_info->break_points()->get(i), isolate)) {
      Tagged<BreakPointInfo> break_point_info =
          Cast<BreakPointInfo>(debug_info->break_points()->get(i));
      int break_points = break_point_info->GetBreakPointCount(isolate);
      if (break_points == 0) continue;
      for (int j = 0; j < break_points; ++j) {
        locations->set(count++,
                       Smi::FromInt(break_point_info->source_position()));
      }
    }
  }
  return locations;
}

void Debug::ClearStepping() {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  // Clear the various stepping setup.
  ClearOneShot();
  ClearMutedLocation();

  thread_local_.last_step_action_ = StepNone;
  thread_local_.last_statement_position_ = kNoSourcePosition;
  thread_local_.last_bytecode_offset_ = kFunctionEntryBytecodeOffset;
  thread_local_.ignore_step_into_function_ = Smi::zero();
  thread_local_.fast_forward_to_return_ = false;
  thread_local_.last_frame_count_ = -1;
  thread_local_.target_frame_count_ = -1;
  thread_local_.break_on_next_function_call_ = false;
  thread_local_.scheduled_break_on_next_function_call_ = false;
  clear_restart_frame();
  UpdateHookOnFunctionCall();
}

// Clears all the one-shot break points that are currently set. Normally this
// function is called each time a break point is hit as one shot break points
// are used to support stepping.
void Debug::ClearOneShot() {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  // The current implementation just runs through all the breakpoints. When the
  // last break point for a function is removed that function is automatically
  // removed from the list.
  HandleScope scope(isolate_);
  DebugInfoCollection::Iterator it(&debug_infos_);
  for (; it.HasNext(); it.Advance()) {
    Handle<DebugInfo> debug_info(it.Next(), isolate_);
    ClearBreakPoints(debug_info);
    ApplyBreakPoints(debug_info);
  }
}

void Debug::ClearMutedLocation() {
  thread_local_.muted_function_ = Smi::zero();
  thread_local_.muted_position_ = -1;
}

void Debug::SetMutedLocation(DirectHandle<SharedFunctionInfo> function,
                             const BreakLocation& location) {
  thread_local_.muted_function_ = *function;
  thread_local_.muted_position_ = location.position();
}

namespace {
class DiscardBaselineCodeVisitor : public ThreadVisitor {
 public:
  explicit DiscardBaselineCodeVisitor(Tagged<SharedFunctionInfo> shared)
      : shared_(shared) {}
  DiscardBaselineCodeVisitor() : shared_(SharedFunctionInfo()) {}

  void VisitThread(Isolate* isolate, ThreadLocalTop* top) override {
    DisallowGarbageCollection diallow_gc;
    bool deopt_all = shared_ == SharedFunctionInfo();
    for (JavaScriptStackFrameIterator it(isolate, top); !it.done();
         it.Advance()) {
      if (!deopt_all && it.frame()->function()->shared() != shared_) continue;
      if (it.frame()->type() == StackFrame::BASELINE) {
        BaselineFrame* frame = BaselineFrame::cast(it.frame());
        int bytecode_offset = frame->GetBytecodeOffset();
        Address* pc_addr = frame->pc_address();
        Address advance;
        if (bytecode_offset == kFunctionEntryBytecodeOffset) {
          advance = BUILTIN_CODE(isolate, BaselineOutOfLinePrologueDeopt)
                        ->instruction_start();
        } else {
          advance = BUILTIN_CODE(isolate, InterpreterEnterAtNextBytecode)
                        ->instruction_start();
        }
        PointerAuthentication::ReplacePC(pc_addr, advance, kSystemPointerSize);
        InterpretedFrame::cast(it.Reframe())
            ->PatchBytecodeOffset(bytecode_offset);
      } else if (it.frame()->type() == StackFrame::INTERPRETED) {
        // Check if the PC is a baseline entry trampoline. If it is, replace it
        // with the corresponding interpreter entry trampoline.
        // This is the case if a baseline function was inlined into a function
        // we deoptimized in the debugger and are stepping into it.
        JavaScriptFrame* frame = it.frame();
        Address pc = frame->pc();
        Builtin builtin =
```