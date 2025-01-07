Response:
The user wants a summary of the provided C++ code snippet, focusing on the functionality of `v8/src/objects/js-function.cc`. I need to identify the key operations and concepts related to JavaScript functions within the V8 engine.

Here's a breakdown of the thought process to analyze the code:

1. **Identify the Core Subject:** The filename `js-function.cc` and the class name `JSFunction` clearly indicate the primary focus is the representation and management of JavaScript functions within V8.

2. **Look for Key Data Structures:** The code mentions several important data structures:
    * `Code`: Represents compiled code (various tiers like interpreted, baseline, optimized).
    * `SharedFunctionInfo`: Contains information shared across instances of the same function.
    * `FeedbackVector`: Stores feedback about function execution for optimization.
    * `ClosureFeedbackCellArray`:  Manages feedback cells for closures.
    * `Map`:  Describes the structure and properties of objects created by the function (as a constructor).

3. **Analyze Functionality by Grouping Related Methods:**  The code contains various methods. It's helpful to group them based on their purpose:
    * **Code Management:** `GetAttachedCodeKinds`, `GetAvailableCodeKinds`, `HasAttachedOptimizedCode`, `HasAvailableHigherTierCodeThan`, `HasAvailableOptimizedCode`, `HasAttachedCodeKind`, `HasAvailableCodeKind`, `GetActiveTier`, `CanDiscardCompiled`. These methods deal with querying the different tiers of compiled code associated with a function.
    * **Optimization & Tiering:** `RequestOptimization`, `SetInterruptBudget`, `EnsureFeedbackVector`, `CreateAndAttachFeedbackVector`, `InitializeFeedbackCell`. These relate to triggering and managing the optimization process of JavaScript functions.
    * **Function Properties (Name, Length):** `CopyNameAndLength`, `GetName` (for `JSBoundFunction`, `JSWrappedFunction`, `JSFunction`), `GetLength` (for `JSBoundFunction`, `JSWrappedFunction`). These methods handle the creation and retrieval of the `name` and `length` properties of functions, including bound and wrapped functions.
    * **Function Binding and Wrapping:** Methods related to `JSBoundFunction` and `JSWrappedFunction` suggest the implementation of `bind()` and function wrapping.
    * **Prototypes:** `SetPrototype`, `SetInstancePrototype`. These methods handle setting the prototype of a function and the initial map for objects created by the function.
    * **Internal State Management:** `EnsureClosureFeedbackCellArray`. This manages the internal structures used for closure feedback.

4. **Relate to JavaScript Concepts:** Connect the identified functionalities to familiar JavaScript concepts:
    * **Function execution:** The different code kinds (interpreted, baseline, optimized) relate to how JavaScript code is executed.
    * **Optimization:**  The tiering system (Ignition, Baseline, Maglev, Turbofan) is V8's mechanism for optimizing frequently executed code. Feedback is crucial for this.
    * **`bind()`:**  `JSBoundFunction` directly corresponds to the functionality of `bind()`.
    * **Function wrapping:** `JSWrappedFunction` is related to how native functions or other non-JS callables are integrated into the JavaScript environment.
    * **Prototypes and Constructors:** The `SetPrototype` and related methods are fundamental to JavaScript's prototypal inheritance.

5. **Consider Edge Cases and Error Handling:**  The code includes checks for `HasAsmWasmData` and uses `Maybe` and `MaybeHandle` for potential failures, indicating consideration for WebAssembly functions and error handling during property access.

6. **Formulate the Summary:** Based on the above analysis, construct a concise summary that covers the key functionalities and their relevance to JavaScript. Mention the data structures involved and the overall purpose of the code. Address the specific points raised in the prompt (Torque, JavaScript examples, logic, common errors).

7. **Self-Correction/Refinement:** Review the summary to ensure accuracy and completeness. For example, initially, I might focus too much on individual methods. Refining the summary involves grouping related functionalities and explaining the higher-level purpose. Make sure to directly address all parts of the prompt. For instance, the prompt specifically asks about `.tq` files – even if the current snippet isn't one, explicitly address that point. Similarly, proactively mention common programming errors related to function properties or prototypes, even if the code doesn't directly *handle* those errors.
```cpp
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/objects/js-function.h"

#include <optional>

#include "src/baseline/baseline-batch-compiler.h"
#include "src/codegen/compiler.h"
#include "src/common/globals.h"
#include "src/diagnostics/code-tracer.h"
#include "src/execution/frames-inl.h"
#include "src/execution/isolate.h"
#include "src/execution/tiering-manager.h"
#include "src/heap/heap-inl.h"
#include "src/ic/ic.h"
#include "src/init/bootstrapper.h"
#include "src/objects/feedback-cell-inl.h"
#include "src/strings/string-builder-inl.h"

// Has to be the last include (doesn't have include guards):
#include "src/objects/object-macros.h"

namespace v8::internal {

CodeKinds JSFunction::GetAttachedCodeKinds(IsolateForSandbox isolate) const {
  const CodeKind kind = code(isolate)->kind();
  if (!CodeKindIsJSFunction(kind)) return {};
  if (CodeKindIsOptimizedJSFunction(kind) &&
      code(isolate)->marked_for_deoptimization()) {
    return {};
  }
  return CodeKindToCodeKindFlag(kind);
}

CodeKinds JSFunction::GetAvailableCodeKinds(IsolateForSandbox isolate) const {
  CodeKinds result = GetAttachedCodeKinds(isolate);

  if ((result & CodeKindFlag::INTERPRETED_FUNCTION) == 0) {
    // The SharedFunctionInfo could have attached bytecode.
    if (shared()->HasBytecodeArray()) {
      result |= CodeKindFlag::INTERPRETED_FUNCTION;
    }
  }

  if ((result & CodeKindFlag::BASELINE) == 0) {
    // The SharedFunctionInfo could have attached baseline code.
    if (shared()->HasBaselineCode()) {
      result |= CodeKindFlag::BASELINE;
    }
  }

#ifndef V8_ENABLE_LEAPTIERING
  // Check the optimized code cache.
  if (has_feedback_vector() && feedback_vector()->has_optimized_code() &&
      !feedback_vector()
           ->optimized_code(isolate)
           ->marked_for_deoptimization()) {
    Tagged<Code> code = feedback_vector()->optimized_code(isolate);
    DCHECK(CodeKindIsOptimizedJSFunction(code->kind()));
    result |= CodeKindToCodeKindFlag(code->kind());
  }
#endif  // !V8_ENABLE_LEAPTIERING

  DCHECK_EQ((result & ~kJSFunctionCodeKindsMask), 0);
  return result;
}

bool JSFunction::HasAttachedOptimizedCode(IsolateForSandbox isolate) const {
  CodeKinds result = GetAttachedCodeKinds(isolate);
  return (result & kOptimizedJSFunctionCodeKindsMask) != 0;
}

bool JSFunction::HasAvailableHigherTierCodeThan(IsolateForSandbox isolate,
                                                CodeKind kind) const {
  return HasAvailableHigherTierCodeThanWithFilter(isolate, kind,
                                                  kJSFunctionCodeKindsMask);
}

bool JSFunction::HasAvailableHigherTierCodeThanWithFilter(
    IsolateForSandbox isolate, CodeKind kind, CodeKinds filter_mask) const {
  const int kind_as_int_flag = static_cast<int>(CodeKindToCodeKindFlag(kind));
  DCHECK(base::bits::IsPowerOfTwo(kind_as_int_flag));
  // Smear right - any higher present bit means we have a higher tier available.
  const int mask = kind_as_int_flag | (kind_as_int_flag - 1);
  const CodeKinds masked_available_kinds =
      GetAvailableCodeKinds(isolate) & filter_mask;
  return (masked_available_kinds & static_cast<CodeKinds>(~mask)) != 0;
}

bool JSFunction::HasAvailableOptimizedCode(IsolateForSandbox isolate) const {
  CodeKinds result = GetAvailableCodeKinds(isolate);
  return (result & kOptimizedJSFunctionCodeKindsMask) != 0;
}

bool JSFunction::HasAttachedCodeKind(IsolateForSandbox isolate,
                                     CodeKind kind) const {
  CodeKinds result = GetAttachedCodeKinds(isolate);
  return (result & CodeKindToCodeKindFlag(kind)) != 0;
}

bool JSFunction::HasAvailableCodeKind(IsolateForSandbox isolate,
                                      CodeKind kind) const {
  CodeKinds result = GetAvailableCodeKinds(isolate);
  return (result & CodeKindToCodeKindFlag(kind)) != 0;
}

namespace {

// Returns false if no highest tier exists (i.e. the function is not compiled),
// otherwise returns true and sets highest_tier.
V8_WARN_UNUSED_RESULT bool HighestTierOf(CodeKinds kinds,
                                         CodeKind* highest_tier) {
  DCHECK_EQ((kinds & ~kJSFunctionCodeKindsMask), 0);
  // Higher tiers > lower tiers.
  static_assert(CodeKind::TURBOFAN_JS > CodeKind::INTERPRETED_FUNCTION);
  if (kinds == 0) return false;
  const int highest_tier_log2 =
      31 - base::bits::CountLeadingZeros(static_cast<uint32_t>(kinds));
  DCHECK(CodeKindIsJSFunction(static_cast<CodeKind>(highest_tier_log2)));
  *highest_tier = static_cast<CodeKind>(highest_tier_log2);
  return true;
}

}  // namespace

std::optional<CodeKind> JSFunction::GetActiveTier(
    IsolateForSandbox isolate) const {
#if V8_ENABLE_WEBASSEMBLY
  // Asm/Wasm functions are currently not supported. For simplicity, this
  // includes invalid asm.js functions whose code hasn't yet been updated to
  // CompileLazy but is still the InstantiateAsmJs builtin.
  if (shared()->HasAsmWasmData() ||
      code(isolate)->builtin_id() == Builtin::kInstantiateAsmJs) {
    return {};
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  CodeKind highest_tier;
  if (!HighestTierOf(GetAvailableCodeKinds(isolate), &highest_tier)) return {};

#ifdef DEBUG
  CHECK(highest_tier == CodeKind::TURBOFAN_JS ||
        highest_tier == CodeKind::BASELINE ||
        highest_tier == CodeKind::MAGLEV ||
        highest_tier == CodeKind::INTERPRETED_FUNCTION);

  if (highest_tier == CodeKind::INTERPRETED_FUNCTION) {
    CHECK(code(isolate)->is_interpreter_trampoline_builtin() ||
          (CodeKindIsOptimizedJSFunction(code(isolate)->kind()) &&
           code(isolate)->marked_for_deoptimization()) ||
          (code(isolate)->builtin_id() == Builtin::kCompileLazy &&
           shared()->HasBytecodeArray() && !shared()->HasBaselineCode()));
  }
#endif  // DEBUG

  return highest_tier;
}

bool JSFunction::ActiveTierIsIgnition(IsolateForSandbox isolate) const {
  return GetActiveTier(isolate) == CodeKind::INTERPRETED_FUNCTION;
}

bool JSFunction::ActiveTierIsBaseline(IsolateForSandbox isolate) const {
  return GetActiveTier(isolate) == CodeKind::BASELINE;
}

bool JSFunction::ActiveTierIsMaglev(IsolateForSandbox isolate) const {
  return GetActiveTier(isolate) == CodeKind::MAGLEV;
}

bool JSFunction::ActiveTierIsTurbofan(IsolateForSandbox isolate) const {
  return GetActiveTier(isolate) == CodeKind::TURBOFAN_JS;
}

bool JSFunction::CanDiscardCompiled(IsolateForSandbox isolate) const {
  // Essentially, what we are asking here is, has this function been compiled
  // from JS code? We can currently tell only indirectly, by looking at
  // available code kinds. If any JS code kind exists, we can discard.
  //
  // Attached optimized code that is marked for deoptimization will not show up
  // in the list of available code kinds, thus we must check for it manually.
  //
  // Note that when the function has not yet been compiled we also return
  // false; that's fine, since nothing must be discarded in that case.
  if (CodeKindIsOptimizedJSFunction(code(isolate)->kind())) return true;
  CodeKinds result = GetAvailableCodeKinds(isolate);
  return (result & kJSFunctionCodeKindsMask) != 0;
}

namespace {

#ifndef V8_ENABLE_LEAPTIERING
constexpr TieringState TieringStateFor(CodeKind target_kind,
                                       ConcurrencyMode mode) {
  DCHECK(target_kind == CodeKind::MAGLEV ||
         target_kind == CodeKind::TURBOFAN_JS);
  return target_kind == CodeKind::MAGLEV
             ? (IsConcurrent(mode) ? TieringState::kRequestMaglev_Concurrent
                                   : TieringState::kRequestMaglev_Synchronous)
             : (IsConcurrent(mode)
                    ? TieringState::kRequestTurbofan_Concurrent
                    : TieringState::kRequestTurbofan_Synchronous);
}
#endif  // !V8_ENABLE_LEAPTIERING

}  // namespace

void JSFunction::RequestOptimization(Isolate* isolate, CodeKind target_kind,
                                     ConcurrencyMode mode) {
  if (!isolate->concurrent_recompilation_enabled() ||
      isolate->bootstrapper()->IsActive()) {
    mode = ConcurrencyMode::kSynchronous;
  }

  DCHECK(CodeKindIsOptimizedJSFunction(target_kind));
  DCHECK(!is_compiled(isolate) || ActiveTierIsIgnition(isolate) ||
         ActiveTierIsBaseline(isolate) || ActiveTierIsMaglev(isolate));
  DCHECK(!ActiveTierIsTurbofan(isolate));
  DCHECK(shared()->HasBytecodeArray());
  DCHECK(shared()->allows_lazy_compilation() ||
         !shared()->optimization_disabled());

  if (IsConcurrent(mode)) {
    if (tiering_in_progress()) {
      if (v8_flags.trace_concurrent_recompilation) {
        PrintF("  ** Not marking ");
        ShortPrint(*this);
        PrintF(" -- already in optimization queue.\n");
      }
      return;
    }
    if (v8_flags.trace_concurrent_recompilation) {
      PrintF("  ** Marking ");
      ShortPrint(*this);
      PrintF(" for concurrent %s recompilation.\n",
             CodeKindToString(target_kind));
    }
  }

#ifdef V8_ENABLE_LEAPTIERING
  JSDispatchTable* jdt = GetProcessWideJSDispatchTable();
  switch (target_kind) {
    case CodeKind::MAGLEV:
      switch (mode) {
        case ConcurrencyMode::kConcurrent:
          DCHECK(!HasAvailableCodeKind(isolate, CodeKind::MAGLEV));
          DCHECK(!HasAvailableCodeKind(isolate, CodeKind::TURBOFAN_JS));
          DCHECK(!IsOptimizationRequested(isolate));
          jdt->SetTieringRequest(dispatch_handle(),
                                 TieringBuiltin::kStartMaglevOptimizationJob,
                                 isolate);
          break;
        case ConcurrencyMode::kSynchronous:
          jdt->SetTieringRequest(dispatch_handle(),
                                 TieringBuiltin::kOptimizeMaglevEager, isolate);
          break;
      }
      break;
    case CodeKind::TURBOFAN_JS:
      switch (mode) {
        case ConcurrencyMode::kConcurrent:
          DCHECK(!IsOptimizationRequested(isolate));
          DCHECK(!HasAvailableCodeKind(isolate, CodeKind::TURBOFAN_JS));
          jdt->SetTieringRequest(dispatch_handle(),
                                 TieringBuiltin::kStartTurbofanOptimizationJob,
                                 isolate);
          break;
        case ConcurrencyMode::kSynchronous:
          jdt->SetTieringRequest(dispatch_handle(),
                                 TieringBuiltin::kOptimizeTurbofanEager,
                                 isolate);
          break;
      }
      break;
    default:
      UNREACHABLE();
  }
#else
  set_tiering_state(isolate, TieringStateFor(target_kind, mode));
#endif  // V8_ENABLE_LEAPTIERING
}

void JSFunction::SetInterruptBudget(
    Isolate* isolate, std::optional<CodeKind> override_active_tier) {
  raw_feedback_cell()->set_interrupt_budget(
      TieringManager::InterruptBudgetFor(isolate, *this, override_active_tier));
}

// static
Maybe<bool> JSFunctionOrBoundFunctionOrWrappedFunction::CopyNameAndLength(
    Isolate* isolate,
    Handle<JSFunctionOrBoundFunctionOrWrappedFunction> function,
    Handle<JSReceiver> target, Handle<String> prefix, int arg_count) {
  // Setup the "length" property based on the "length" of the {target}.
  // If the targets length is the default JSFunction accessor, we can keep the
  // accessor that's installed by default on the
  // JSBoundFunction/JSWrappedFunction. It lazily computes the value from the
  // underlying internal length.
  Handle<AccessorInfo> function_length_accessor =
      isolate->factory()->function_length_accessor();
  LookupIterator length_lookup(isolate, target,
                               isolate->factory()->length_string(), target,
                               LookupIterator::OWN);
  if (!IsJSFunction(*target) ||
      length_lookup.state() != LookupIterator::ACCESSOR ||
      !length_lookup.GetAccessors().is_identical_to(function_length_accessor)) {
    Handle<Object> length(Smi::zero(), isolate);
    Maybe<PropertyAttributes> attributes =
        JSReceiver::GetPropertyAttributes(&length_lookup);
    if (attributes.IsNothing()) return Nothing<bool>();
    if (attributes.FromJust() != ABSENT) {
      Handle<Object> target_length;
      ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, target_length,
                                       Object::GetProperty(&length_lookup),
                                       Nothing<bool>());
      if (IsNumber(*target_length)) {
        length = isolate->factory()->NewNumber(std::max(
            0.0,
            DoubleToInteger(Object::NumberValue(*target_length)) - arg_count));
      }
    }
    LookupIterator it(isolate, function, isolate->factory()->length_string(),
                      function);
    DCHECK_EQ(LookupIterator::ACCESSOR, it.state());
    RETURN_ON_EXCEPTION_VALUE(isolate,
                              JSObject::DefineOwnPropertyIgnoreAttributes(
                                  &it, length, it.property_attributes()),
                              Nothing<bool>());
  }

  // Setup the "name" property based on the "name" of the {target}.
  // If the target's name is the default JSFunction accessor, we can keep the
  // accessor that's installed by default on the
  // JSBoundFunction/JSWrappedFunction. It lazily computes the value from the
  // underlying internal name.
  Handle<AccessorInfo> function_name_accessor =
      isolate->factory()->function_name_accessor();
  LookupIterator name_lookup(isolate, target, isolate->factory()->name_string(),
                             target);
  if (!IsJSFunction(*target) ||
      name_lookup.state() != LookupIterator::ACCESSOR ||
      !name_lookup.GetAccessors().is_identical_to(function_name_accessor) ||
      (name_lookup.IsFound() && !name_lookup.HolderIsReceiver())) {
    Handle<Object> target_name;
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, target_name,
                                     Object::GetProperty(&name_lookup),
                                     Nothing<bool>());
    Handle<String> name;
    if (IsString(*target_name)) {
      ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate, name,
          Name::ToFunctionName(isolate, Cast<String>(target_name)),
          Nothing<bool>());
      if (!prefix.is_null()) {
        ASSIGN_RETURN_ON_EXCEPTION_VALUE(
            isolate, name, isolate->factory()->NewConsString(prefix, name),
            Nothing<bool>());
      }
    } else if (prefix.is_null()) {
      name = isolate->factory()->empty_string();
    } else {
      name = prefix;
    }
    LookupIterator it(isolate, function, isolate->factory()->name_string());
    DCHECK_EQ(LookupIterator::ACCESSOR, it.state());
    RETURN_ON_EXCEPTION_VALUE(isolate,
                              JSObject::DefineOwnPropertyIgnoreAttributes(
                                  &it, name, it.property_attributes()),
                              Nothing<bool>());
  }

  return Just(true);
}

// static
MaybeHandle<String> JSBoundFunction::GetName(
    Isolate* isolate, DirectHandle<JSBoundFunction> function) {
  Handle<String> prefix = isolate->factory()->bound__string();
  Handle<String> target_name = prefix;
  Factory* factory = isolate->factory();
  // Concatenate the "bound " up to the last non-bound target.
  while (IsJSBoundFunction(function->bound_target_function())) {
    ASSIGN_RETURN_ON_EXCEPTION(isolate, target_name,
                               factory->NewConsString(prefix, target_name));
    function = handle(Cast<JSBoundFunction>(function->bound_target_function()),
                      isolate);
  }
  if (IsJSWrappedFunction(function->bound_target_function())) {
    DirectHandle<JSWrappedFunction> target(
        Cast<JSWrappedFunction>(function->bound_target_function()), isolate);
    Handle<String> name;
    ASSIGN_RETURN_ON_EXCEPTION(isolate, name,
                               JSWrappedFunction::GetName(isolate, target));
    return factory->NewConsString(target_name, name);
  }
  if (IsJSFunction(function->bound_target_function())) {
    DirectHandle<JSFunction> target(
        Cast<JSFunction>(function->bound_target_function()), isolate);
    Handle<String> name = JSFunction::GetName(isolate, target);
    return factory->NewConsString(target_name, name);
  }
  // This will omit the proper target name for bound JSProxies.
  return target_name;
}

// static
Maybe<int> JSBoundFunction::GetLength(Isolate* isolate,
                                      DirectHandle<JSBoundFunction> function) {
  int nof_bound_arguments = function->bound_arguments()->length();
  while (IsJSBoundFunction(function->bound_target_function())) {
    function = handle(Cast<JSBoundFunction>(function->bound_target_function()),
                      isolate);
    // Make sure we never overflow {nof_bound_arguments}, the number of
    // arguments of a function is strictly limited by the max length of an
    // JSAarray, Smi::kMaxValue is thus a reasonably good overestimate.
    int length = function->bound_arguments()->length();
    if (V8_LIKELY(Smi::kMaxValue - nof_bound_arguments > length)) {
      nof_bound_arguments += length;
    } else {
      nof_bound_arguments = Smi::kMaxValue;
    }
  }
  if (IsJSWrappedFunction(function->bound_target_function())) {
    DirectHandle<JSWrappedFunction> target(
        Cast<JSWrappedFunction>(function->bound_target_function()), isolate);
    int target_length = 0;
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, target_length, JSWrappedFunction::GetLength(isolate, target),
        Nothing<int>());
    int length = std::max(0, target_length - nof_bound_arguments);
    return Just(length);
  }
  // All non JSFunction targets get a direct property and don't use this
  // accessor.
  DirectHandle<JSFunction> target(
      Cast<JSFunction>(function->bound_target_function()), isolate);
  int target_length = target->length();

  int length = std::max(0, target_length - nof_bound_arguments);
  return Just(length);
}

// static
Handle<String> JSBoundFunction::ToString(
    DirectHandle<JSBoundFunction> function) {
  Isolate* const isolate = function->GetIsolate();
  return isolate->factory()->function_native_code_string();
}

// static
MaybeHandle<String> JSWrappedFunction::GetName(
    Isolate* isolate, DirectHandle<JSWrappedFunction> function) {
  STACK_CHECK(isolate, MaybeHandle<String>());
  Factory* factory = isolate->factory();
  Handle<String> target_name = factory->empty_string();
  DirectHandle<JSReceiver> target(function->wrapped_target_function(), isolate);
  if (IsJSBoundFunction(*target)) {
    return JSBoundFunction::GetName(
        isolate,
        handle(Cast<JSBoundFunction>(function->wrapped_target_function()),
               isolate));
  } else if (IsJSFunction(*target)) {
    return JSFunction::GetName(
        isolate,
        handle(Cast<JSFunction>(function->wrapped_target_function()), isolate));
  }
  // This will omit the proper target name for bound JSProxies.
  return target_name;
}

// static
Maybe<int> JSWrappedFunction::GetLength(
    Isolate* isolate, DirectHandle<JSWrappedFunction> function) {
  STACK_CHECK(isolate, Nothing<int>());
  Handle<JSReceiver> target =
      handle(function->wrapped_target_function(), isolate);
  if (IsJSBoundFunction(*target)) {
    return JSBoundFunction::GetLength(
        isolate,
        handle(Cast<JSBoundFunction>(function->wrapped_target_function()),
               isolate));
  }
  // All non JSFunction targets get a direct property and don't use this
  // accessor.
  return Just(Cast<JSFunction>(target)->length());
}

// static
Handle<String> JSWrappedFunction::ToString(
    DirectHandle<JSWrappedFunction> function) {
  Isolate* const isolate = function->GetIsolate();
  return isolate->factory()->function_native_code_string();
}

// static
MaybeHandle<Object> JSWrappedFunction::Create(
    Isolate* isolate, DirectHandle<NativeContext> creation_context,
    Handle<JSReceiver> value) {
  // The value must be a callable according to the specification.
  DCHECK(IsCallable(*value));
  // The intermediate wrapped functions are not user-visible. And calling a
  // wrapped function won't cause a side effect in the creation realm.
  // Unwrap here to avoid nested unwrapping at the call site.
  if (IsJSWrappedFunction(*value)) {
    auto target_wrapped = Cast<JSWrappedFunction>(value);
    value =
        Handle<JSReceiver>(target_wrapped->wrapped_target_function(), isolate);
  }

  // 1. Let internalSlotsList be the internal slots listed in Table 2, plus
  // [[Prototype]] and [[Extensible]].
  // 2. Let wrapped be ! MakeBasicObject(internalSlotsList).
  // 3. Set wrapped.[[Prototype]] to
  // callerRealm.[[Intrinsics]].[[%Function.prototype%]].
  // 4. Set wrapped.[[Call]] as described in 2.1.
  // 5. Set wrapped.[[WrappedTargetFunction]] to Target.
  // 6. Set wrapped.[[Realm]] to callerRealm.
  Handle<JSWrappedFunction> wrapped =
      isolate->factory()->NewJSWrappedFunction(creation_context, value);

  // 7. Let result be CopyNameAndLength(wrapped, Target, "wrapped").
  Maybe<bool> is_abrupt =
      JSFunctionOrBoundFunctionOrWrappedFunction::CopyNameAndLength(
          isolate, wrapped, value, Handle<String>(), 0);

  // 8. If result is an Abrupt Completion, throw a TypeError exception.
  if (is_abrupt.IsNothing()) {
    DCHECK(isolate->has_exception());
    DirectHandle<Object> exception(isolate->exception(), isolate);
    isolate->clear_exception();

    // The TypeError thrown is created with creation Realm's TypeError
    // constructor instead of the executing Realm's.
    Handle<JSFunction> type_error_function =
        Handle<JSFunction>(creation_context->type_error_function(), isolate);
    DirectHandle<String> string =
        Object::NoSideEffectsToString(isolate, exception);
    THROW_NEW_ERROR_RETURN_VALUE(
        isolate,
        NewError(type_error_function, MessageTemplate::kCannotWrap, string),
        {});
  }
  DCHECK(is_abrupt.FromJust());

  // 9. Return wrapped.
  return wrapped;
}

// static
Handle<String> JSFunction::GetName(Isolate* isolate,
                                   DirectHandle<JSFunction
Prompt: 
```
这是目录为v8/src/objects/js-function.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/js-function.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/objects/js-function.h"

#include <optional>

#include "src/baseline/baseline-batch-compiler.h"
#include "src/codegen/compiler.h"
#include "src/common/globals.h"
#include "src/diagnostics/code-tracer.h"
#include "src/execution/frames-inl.h"
#include "src/execution/isolate.h"
#include "src/execution/tiering-manager.h"
#include "src/heap/heap-inl.h"
#include "src/ic/ic.h"
#include "src/init/bootstrapper.h"
#include "src/objects/feedback-cell-inl.h"
#include "src/strings/string-builder-inl.h"

// Has to be the last include (doesn't have include guards):
#include "src/objects/object-macros.h"

namespace v8::internal {

CodeKinds JSFunction::GetAttachedCodeKinds(IsolateForSandbox isolate) const {
  const CodeKind kind = code(isolate)->kind();
  if (!CodeKindIsJSFunction(kind)) return {};
  if (CodeKindIsOptimizedJSFunction(kind) &&
      code(isolate)->marked_for_deoptimization()) {
    return {};
  }
  return CodeKindToCodeKindFlag(kind);
}

CodeKinds JSFunction::GetAvailableCodeKinds(IsolateForSandbox isolate) const {
  CodeKinds result = GetAttachedCodeKinds(isolate);

  if ((result & CodeKindFlag::INTERPRETED_FUNCTION) == 0) {
    // The SharedFunctionInfo could have attached bytecode.
    if (shared()->HasBytecodeArray()) {
      result |= CodeKindFlag::INTERPRETED_FUNCTION;
    }
  }

  if ((result & CodeKindFlag::BASELINE) == 0) {
    // The SharedFunctionInfo could have attached baseline code.
    if (shared()->HasBaselineCode()) {
      result |= CodeKindFlag::BASELINE;
    }
  }

#ifndef V8_ENABLE_LEAPTIERING
  // Check the optimized code cache.
  if (has_feedback_vector() && feedback_vector()->has_optimized_code() &&
      !feedback_vector()
           ->optimized_code(isolate)
           ->marked_for_deoptimization()) {
    Tagged<Code> code = feedback_vector()->optimized_code(isolate);
    DCHECK(CodeKindIsOptimizedJSFunction(code->kind()));
    result |= CodeKindToCodeKindFlag(code->kind());
  }
#endif  // !V8_ENABLE_LEAPTIERING

  DCHECK_EQ((result & ~kJSFunctionCodeKindsMask), 0);
  return result;
}

bool JSFunction::HasAttachedOptimizedCode(IsolateForSandbox isolate) const {
  CodeKinds result = GetAttachedCodeKinds(isolate);
  return (result & kOptimizedJSFunctionCodeKindsMask) != 0;
}

bool JSFunction::HasAvailableHigherTierCodeThan(IsolateForSandbox isolate,
                                                CodeKind kind) const {
  return HasAvailableHigherTierCodeThanWithFilter(isolate, kind,
                                                  kJSFunctionCodeKindsMask);
}

bool JSFunction::HasAvailableHigherTierCodeThanWithFilter(
    IsolateForSandbox isolate, CodeKind kind, CodeKinds filter_mask) const {
  const int kind_as_int_flag = static_cast<int>(CodeKindToCodeKindFlag(kind));
  DCHECK(base::bits::IsPowerOfTwo(kind_as_int_flag));
  // Smear right - any higher present bit means we have a higher tier available.
  const int mask = kind_as_int_flag | (kind_as_int_flag - 1);
  const CodeKinds masked_available_kinds =
      GetAvailableCodeKinds(isolate) & filter_mask;
  return (masked_available_kinds & static_cast<CodeKinds>(~mask)) != 0;
}

bool JSFunction::HasAvailableOptimizedCode(IsolateForSandbox isolate) const {
  CodeKinds result = GetAvailableCodeKinds(isolate);
  return (result & kOptimizedJSFunctionCodeKindsMask) != 0;
}

bool JSFunction::HasAttachedCodeKind(IsolateForSandbox isolate,
                                     CodeKind kind) const {
  CodeKinds result = GetAttachedCodeKinds(isolate);
  return (result & CodeKindToCodeKindFlag(kind)) != 0;
}

bool JSFunction::HasAvailableCodeKind(IsolateForSandbox isolate,
                                      CodeKind kind) const {
  CodeKinds result = GetAvailableCodeKinds(isolate);
  return (result & CodeKindToCodeKindFlag(kind)) != 0;
}

namespace {

// Returns false if no highest tier exists (i.e. the function is not compiled),
// otherwise returns true and sets highest_tier.
V8_WARN_UNUSED_RESULT bool HighestTierOf(CodeKinds kinds,
                                         CodeKind* highest_tier) {
  DCHECK_EQ((kinds & ~kJSFunctionCodeKindsMask), 0);
  // Higher tiers > lower tiers.
  static_assert(CodeKind::TURBOFAN_JS > CodeKind::INTERPRETED_FUNCTION);
  if (kinds == 0) return false;
  const int highest_tier_log2 =
      31 - base::bits::CountLeadingZeros(static_cast<uint32_t>(kinds));
  DCHECK(CodeKindIsJSFunction(static_cast<CodeKind>(highest_tier_log2)));
  *highest_tier = static_cast<CodeKind>(highest_tier_log2);
  return true;
}

}  // namespace

std::optional<CodeKind> JSFunction::GetActiveTier(
    IsolateForSandbox isolate) const {
#if V8_ENABLE_WEBASSEMBLY
  // Asm/Wasm functions are currently not supported. For simplicity, this
  // includes invalid asm.js functions whose code hasn't yet been updated to
  // CompileLazy but is still the InstantiateAsmJs builtin.
  if (shared()->HasAsmWasmData() ||
      code(isolate)->builtin_id() == Builtin::kInstantiateAsmJs) {
    return {};
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  CodeKind highest_tier;
  if (!HighestTierOf(GetAvailableCodeKinds(isolate), &highest_tier)) return {};

#ifdef DEBUG
  CHECK(highest_tier == CodeKind::TURBOFAN_JS ||
        highest_tier == CodeKind::BASELINE ||
        highest_tier == CodeKind::MAGLEV ||
        highest_tier == CodeKind::INTERPRETED_FUNCTION);

  if (highest_tier == CodeKind::INTERPRETED_FUNCTION) {
    CHECK(code(isolate)->is_interpreter_trampoline_builtin() ||
          (CodeKindIsOptimizedJSFunction(code(isolate)->kind()) &&
           code(isolate)->marked_for_deoptimization()) ||
          (code(isolate)->builtin_id() == Builtin::kCompileLazy &&
           shared()->HasBytecodeArray() && !shared()->HasBaselineCode()));
  }
#endif  // DEBUG

  return highest_tier;
}

bool JSFunction::ActiveTierIsIgnition(IsolateForSandbox isolate) const {
  return GetActiveTier(isolate) == CodeKind::INTERPRETED_FUNCTION;
}

bool JSFunction::ActiveTierIsBaseline(IsolateForSandbox isolate) const {
  return GetActiveTier(isolate) == CodeKind::BASELINE;
}

bool JSFunction::ActiveTierIsMaglev(IsolateForSandbox isolate) const {
  return GetActiveTier(isolate) == CodeKind::MAGLEV;
}

bool JSFunction::ActiveTierIsTurbofan(IsolateForSandbox isolate) const {
  return GetActiveTier(isolate) == CodeKind::TURBOFAN_JS;
}

bool JSFunction::CanDiscardCompiled(IsolateForSandbox isolate) const {
  // Essentially, what we are asking here is, has this function been compiled
  // from JS code? We can currently tell only indirectly, by looking at
  // available code kinds. If any JS code kind exists, we can discard.
  //
  // Attached optimized code that is marked for deoptimization will not show up
  // in the list of available code kinds, thus we must check for it manually.
  //
  // Note that when the function has not yet been compiled we also return
  // false; that's fine, since nothing must be discarded in that case.
  if (CodeKindIsOptimizedJSFunction(code(isolate)->kind())) return true;
  CodeKinds result = GetAvailableCodeKinds(isolate);
  return (result & kJSFunctionCodeKindsMask) != 0;
}

namespace {

#ifndef V8_ENABLE_LEAPTIERING
constexpr TieringState TieringStateFor(CodeKind target_kind,
                                       ConcurrencyMode mode) {
  DCHECK(target_kind == CodeKind::MAGLEV ||
         target_kind == CodeKind::TURBOFAN_JS);
  return target_kind == CodeKind::MAGLEV
             ? (IsConcurrent(mode) ? TieringState::kRequestMaglev_Concurrent
                                   : TieringState::kRequestMaglev_Synchronous)
             : (IsConcurrent(mode)
                    ? TieringState::kRequestTurbofan_Concurrent
                    : TieringState::kRequestTurbofan_Synchronous);
}
#endif  // !V8_ENABLE_LEAPTIERING

}  // namespace

void JSFunction::RequestOptimization(Isolate* isolate, CodeKind target_kind,
                                     ConcurrencyMode mode) {
  if (!isolate->concurrent_recompilation_enabled() ||
      isolate->bootstrapper()->IsActive()) {
    mode = ConcurrencyMode::kSynchronous;
  }

  DCHECK(CodeKindIsOptimizedJSFunction(target_kind));
  DCHECK(!is_compiled(isolate) || ActiveTierIsIgnition(isolate) ||
         ActiveTierIsBaseline(isolate) || ActiveTierIsMaglev(isolate));
  DCHECK(!ActiveTierIsTurbofan(isolate));
  DCHECK(shared()->HasBytecodeArray());
  DCHECK(shared()->allows_lazy_compilation() ||
         !shared()->optimization_disabled());

  if (IsConcurrent(mode)) {
    if (tiering_in_progress()) {
      if (v8_flags.trace_concurrent_recompilation) {
        PrintF("  ** Not marking ");
        ShortPrint(*this);
        PrintF(" -- already in optimization queue.\n");
      }
      return;
    }
    if (v8_flags.trace_concurrent_recompilation) {
      PrintF("  ** Marking ");
      ShortPrint(*this);
      PrintF(" for concurrent %s recompilation.\n",
             CodeKindToString(target_kind));
    }
  }

#ifdef V8_ENABLE_LEAPTIERING
  JSDispatchTable* jdt = GetProcessWideJSDispatchTable();
  switch (target_kind) {
    case CodeKind::MAGLEV:
      switch (mode) {
        case ConcurrencyMode::kConcurrent:
          DCHECK(!HasAvailableCodeKind(isolate, CodeKind::MAGLEV));
          DCHECK(!HasAvailableCodeKind(isolate, CodeKind::TURBOFAN_JS));
          DCHECK(!IsOptimizationRequested(isolate));
          jdt->SetTieringRequest(dispatch_handle(),
                                 TieringBuiltin::kStartMaglevOptimizationJob,
                                 isolate);
          break;
        case ConcurrencyMode::kSynchronous:
          jdt->SetTieringRequest(dispatch_handle(),
                                 TieringBuiltin::kOptimizeMaglevEager, isolate);
          break;
      }
      break;
    case CodeKind::TURBOFAN_JS:
      switch (mode) {
        case ConcurrencyMode::kConcurrent:
          DCHECK(!IsOptimizationRequested(isolate));
          DCHECK(!HasAvailableCodeKind(isolate, CodeKind::TURBOFAN_JS));
          jdt->SetTieringRequest(dispatch_handle(),
                                 TieringBuiltin::kStartTurbofanOptimizationJob,
                                 isolate);
          break;
        case ConcurrencyMode::kSynchronous:
          jdt->SetTieringRequest(dispatch_handle(),
                                 TieringBuiltin::kOptimizeTurbofanEager,
                                 isolate);
          break;
      }
      break;
    default:
      UNREACHABLE();
  }
#else
  set_tiering_state(isolate, TieringStateFor(target_kind, mode));
#endif  // V8_ENABLE_LEAPTIERING
}

void JSFunction::SetInterruptBudget(
    Isolate* isolate, std::optional<CodeKind> override_active_tier) {
  raw_feedback_cell()->set_interrupt_budget(
      TieringManager::InterruptBudgetFor(isolate, *this, override_active_tier));
}

// static
Maybe<bool> JSFunctionOrBoundFunctionOrWrappedFunction::CopyNameAndLength(
    Isolate* isolate,
    Handle<JSFunctionOrBoundFunctionOrWrappedFunction> function,
    Handle<JSReceiver> target, Handle<String> prefix, int arg_count) {
  // Setup the "length" property based on the "length" of the {target}.
  // If the targets length is the default JSFunction accessor, we can keep the
  // accessor that's installed by default on the
  // JSBoundFunction/JSWrappedFunction. It lazily computes the value from the
  // underlying internal length.
  Handle<AccessorInfo> function_length_accessor =
      isolate->factory()->function_length_accessor();
  LookupIterator length_lookup(isolate, target,
                               isolate->factory()->length_string(), target,
                               LookupIterator::OWN);
  if (!IsJSFunction(*target) ||
      length_lookup.state() != LookupIterator::ACCESSOR ||
      !length_lookup.GetAccessors().is_identical_to(function_length_accessor)) {
    Handle<Object> length(Smi::zero(), isolate);
    Maybe<PropertyAttributes> attributes =
        JSReceiver::GetPropertyAttributes(&length_lookup);
    if (attributes.IsNothing()) return Nothing<bool>();
    if (attributes.FromJust() != ABSENT) {
      Handle<Object> target_length;
      ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, target_length,
                                       Object::GetProperty(&length_lookup),
                                       Nothing<bool>());
      if (IsNumber(*target_length)) {
        length = isolate->factory()->NewNumber(std::max(
            0.0,
            DoubleToInteger(Object::NumberValue(*target_length)) - arg_count));
      }
    }
    LookupIterator it(isolate, function, isolate->factory()->length_string(),
                      function);
    DCHECK_EQ(LookupIterator::ACCESSOR, it.state());
    RETURN_ON_EXCEPTION_VALUE(isolate,
                              JSObject::DefineOwnPropertyIgnoreAttributes(
                                  &it, length, it.property_attributes()),
                              Nothing<bool>());
  }

  // Setup the "name" property based on the "name" of the {target}.
  // If the target's name is the default JSFunction accessor, we can keep the
  // accessor that's installed by default on the
  // JSBoundFunction/JSWrappedFunction. It lazily computes the value from the
  // underlying internal name.
  Handle<AccessorInfo> function_name_accessor =
      isolate->factory()->function_name_accessor();
  LookupIterator name_lookup(isolate, target, isolate->factory()->name_string(),
                             target);
  if (!IsJSFunction(*target) ||
      name_lookup.state() != LookupIterator::ACCESSOR ||
      !name_lookup.GetAccessors().is_identical_to(function_name_accessor) ||
      (name_lookup.IsFound() && !name_lookup.HolderIsReceiver())) {
    Handle<Object> target_name;
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, target_name,
                                     Object::GetProperty(&name_lookup),
                                     Nothing<bool>());
    Handle<String> name;
    if (IsString(*target_name)) {
      ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate, name,
          Name::ToFunctionName(isolate, Cast<String>(target_name)),
          Nothing<bool>());
      if (!prefix.is_null()) {
        ASSIGN_RETURN_ON_EXCEPTION_VALUE(
            isolate, name, isolate->factory()->NewConsString(prefix, name),
            Nothing<bool>());
      }
    } else if (prefix.is_null()) {
      name = isolate->factory()->empty_string();
    } else {
      name = prefix;
    }
    LookupIterator it(isolate, function, isolate->factory()->name_string());
    DCHECK_EQ(LookupIterator::ACCESSOR, it.state());
    RETURN_ON_EXCEPTION_VALUE(isolate,
                              JSObject::DefineOwnPropertyIgnoreAttributes(
                                  &it, name, it.property_attributes()),
                              Nothing<bool>());
  }

  return Just(true);
}

// static
MaybeHandle<String> JSBoundFunction::GetName(
    Isolate* isolate, DirectHandle<JSBoundFunction> function) {
  Handle<String> prefix = isolate->factory()->bound__string();
  Handle<String> target_name = prefix;
  Factory* factory = isolate->factory();
  // Concatenate the "bound " up to the last non-bound target.
  while (IsJSBoundFunction(function->bound_target_function())) {
    ASSIGN_RETURN_ON_EXCEPTION(isolate, target_name,
                               factory->NewConsString(prefix, target_name));
    function = handle(Cast<JSBoundFunction>(function->bound_target_function()),
                      isolate);
  }
  if (IsJSWrappedFunction(function->bound_target_function())) {
    DirectHandle<JSWrappedFunction> target(
        Cast<JSWrappedFunction>(function->bound_target_function()), isolate);
    Handle<String> name;
    ASSIGN_RETURN_ON_EXCEPTION(isolate, name,
                               JSWrappedFunction::GetName(isolate, target));
    return factory->NewConsString(target_name, name);
  }
  if (IsJSFunction(function->bound_target_function())) {
    DirectHandle<JSFunction> target(
        Cast<JSFunction>(function->bound_target_function()), isolate);
    Handle<String> name = JSFunction::GetName(isolate, target);
    return factory->NewConsString(target_name, name);
  }
  // This will omit the proper target name for bound JSProxies.
  return target_name;
}

// static
Maybe<int> JSBoundFunction::GetLength(Isolate* isolate,
                                      DirectHandle<JSBoundFunction> function) {
  int nof_bound_arguments = function->bound_arguments()->length();
  while (IsJSBoundFunction(function->bound_target_function())) {
    function = handle(Cast<JSBoundFunction>(function->bound_target_function()),
                      isolate);
    // Make sure we never overflow {nof_bound_arguments}, the number of
    // arguments of a function is strictly limited by the max length of an
    // JSAarray, Smi::kMaxValue is thus a reasonably good overestimate.
    int length = function->bound_arguments()->length();
    if (V8_LIKELY(Smi::kMaxValue - nof_bound_arguments > length)) {
      nof_bound_arguments += length;
    } else {
      nof_bound_arguments = Smi::kMaxValue;
    }
  }
  if (IsJSWrappedFunction(function->bound_target_function())) {
    DirectHandle<JSWrappedFunction> target(
        Cast<JSWrappedFunction>(function->bound_target_function()), isolate);
    int target_length = 0;
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, target_length, JSWrappedFunction::GetLength(isolate, target),
        Nothing<int>());
    int length = std::max(0, target_length - nof_bound_arguments);
    return Just(length);
  }
  // All non JSFunction targets get a direct property and don't use this
  // accessor.
  DirectHandle<JSFunction> target(
      Cast<JSFunction>(function->bound_target_function()), isolate);
  int target_length = target->length();

  int length = std::max(0, target_length - nof_bound_arguments);
  return Just(length);
}

// static
Handle<String> JSBoundFunction::ToString(
    DirectHandle<JSBoundFunction> function) {
  Isolate* const isolate = function->GetIsolate();
  return isolate->factory()->function_native_code_string();
}

// static
MaybeHandle<String> JSWrappedFunction::GetName(
    Isolate* isolate, DirectHandle<JSWrappedFunction> function) {
  STACK_CHECK(isolate, MaybeHandle<String>());
  Factory* factory = isolate->factory();
  Handle<String> target_name = factory->empty_string();
  DirectHandle<JSReceiver> target(function->wrapped_target_function(), isolate);
  if (IsJSBoundFunction(*target)) {
    return JSBoundFunction::GetName(
        isolate,
        handle(Cast<JSBoundFunction>(function->wrapped_target_function()),
               isolate));
  } else if (IsJSFunction(*target)) {
    return JSFunction::GetName(
        isolate,
        handle(Cast<JSFunction>(function->wrapped_target_function()), isolate));
  }
  // This will omit the proper target name for bound JSProxies.
  return target_name;
}

// static
Maybe<int> JSWrappedFunction::GetLength(
    Isolate* isolate, DirectHandle<JSWrappedFunction> function) {
  STACK_CHECK(isolate, Nothing<int>());
  Handle<JSReceiver> target =
      handle(function->wrapped_target_function(), isolate);
  if (IsJSBoundFunction(*target)) {
    return JSBoundFunction::GetLength(
        isolate,
        handle(Cast<JSBoundFunction>(function->wrapped_target_function()),
               isolate));
  }
  // All non JSFunction targets get a direct property and don't use this
  // accessor.
  return Just(Cast<JSFunction>(target)->length());
}

// static
Handle<String> JSWrappedFunction::ToString(
    DirectHandle<JSWrappedFunction> function) {
  Isolate* const isolate = function->GetIsolate();
  return isolate->factory()->function_native_code_string();
}

// static
MaybeHandle<Object> JSWrappedFunction::Create(
    Isolate* isolate, DirectHandle<NativeContext> creation_context,
    Handle<JSReceiver> value) {
  // The value must be a callable according to the specification.
  DCHECK(IsCallable(*value));
  // The intermediate wrapped functions are not user-visible. And calling a
  // wrapped function won't cause a side effect in the creation realm.
  // Unwrap here to avoid nested unwrapping at the call site.
  if (IsJSWrappedFunction(*value)) {
    auto target_wrapped = Cast<JSWrappedFunction>(value);
    value =
        Handle<JSReceiver>(target_wrapped->wrapped_target_function(), isolate);
  }

  // 1. Let internalSlotsList be the internal slots listed in Table 2, plus
  // [[Prototype]] and [[Extensible]].
  // 2. Let wrapped be ! MakeBasicObject(internalSlotsList).
  // 3. Set wrapped.[[Prototype]] to
  // callerRealm.[[Intrinsics]].[[%Function.prototype%]].
  // 4. Set wrapped.[[Call]] as described in 2.1.
  // 5. Set wrapped.[[WrappedTargetFunction]] to Target.
  // 6. Set wrapped.[[Realm]] to callerRealm.
  Handle<JSWrappedFunction> wrapped =
      isolate->factory()->NewJSWrappedFunction(creation_context, value);

  // 7. Let result be CopyNameAndLength(wrapped, Target, "wrapped").
  Maybe<bool> is_abrupt =
      JSFunctionOrBoundFunctionOrWrappedFunction::CopyNameAndLength(
          isolate, wrapped, value, Handle<String>(), 0);

  // 8. If result is an Abrupt Completion, throw a TypeError exception.
  if (is_abrupt.IsNothing()) {
    DCHECK(isolate->has_exception());
    DirectHandle<Object> exception(isolate->exception(), isolate);
    isolate->clear_exception();

    // The TypeError thrown is created with creation Realm's TypeError
    // constructor instead of the executing Realm's.
    Handle<JSFunction> type_error_function =
        Handle<JSFunction>(creation_context->type_error_function(), isolate);
    DirectHandle<String> string =
        Object::NoSideEffectsToString(isolate, exception);
    THROW_NEW_ERROR_RETURN_VALUE(
        isolate,
        NewError(type_error_function, MessageTemplate::kCannotWrap, string),
        {});
  }
  DCHECK(is_abrupt.FromJust());

  // 9. Return wrapped.
  return wrapped;
}

// static
Handle<String> JSFunction::GetName(Isolate* isolate,
                                   DirectHandle<JSFunction> function) {
  if (function->shared()->name_should_print_as_anonymous()) {
    return isolate->factory()->anonymous_string();
  }
  return handle(function->shared()->Name(), isolate);
}

// static
void JSFunction::EnsureClosureFeedbackCellArray(
    DirectHandle<JSFunction> function,
    bool reset_budget_for_feedback_allocation) {
  Isolate* const isolate = function->GetIsolate();
  DCHECK(function->shared()->is_compiled());
  DCHECK(function->shared()->HasFeedbackMetadata());
#if V8_ENABLE_WEBASSEMBLY
  if (function->shared()->HasAsmWasmData()) return;
#endif  // V8_ENABLE_WEBASSEMBLY

  DirectHandle<SharedFunctionInfo> shared(function->shared(), isolate);
  DCHECK(shared->HasBytecodeArray());

  const bool has_closure_feedback_cell_array =
      (function->has_closure_feedback_cell_array() ||
       function->has_feedback_vector());
  // Initialize the interrupt budget to the feedback vector allocation budget
  // when initializing the feedback cell for the first time or after a bytecode
  // flush. We retain the closure feedback cell array on bytecode flush, so
  // reset_budget_for_feedback_allocation is used to reset the budget in these
  // cases.
  if (reset_budget_for_feedback_allocation ||
      !has_closure_feedback_cell_array) {
    function->SetInterruptBudget(isolate);
  }

  if (has_closure_feedback_cell_array) {
    return;
  }

  DirectHandle<ClosureFeedbackCellArray> feedback_cell_array =
      ClosureFeedbackCellArray::New(isolate, shared);
  // Many closure cell is used as a way to specify that there is no
  // feedback cell for this function and a new feedback cell has to be
  // allocated for this function. For ex: for eval functions, we have to create
  // a feedback cell and cache it along with the code. It is safe to use
  // many_closure_cell to indicate this because in regular cases, it should
  // already have a feedback_vector / feedback cell array allocated.
  if (function->raw_feedback_cell() == isolate->heap()->many_closures_cell()) {
    DirectHandle<FeedbackCell> feedback_cell =
        isolate->factory()->NewOneClosureCell(feedback_cell_array);
#ifdef V8_ENABLE_LEAPTIERING
    // This is a rare case where we copy the dispatch entry from a JSFunction
    // to its FeedbackCell instead of the other way around.
    // TODO(42204201): investigate whether this can be avoided so that we only
    // ever copy a dispatch handle from a FeedbackCell to a JSFunction. That
    // would probably require refactoring the way JSFunctions are built so that
    // we always allocate a FeedbackCell up front (if needed).
    DCHECK_NE(function->dispatch_handle(), kNullJSDispatchHandle);
    // The feedback cell should never contain context specialized code.
    DCHECK(!function->code(isolate)->is_context_specialized());
    feedback_cell->set_dispatch_handle(function->dispatch_handle());
#endif  // V8_ENABLE_LEAPTIERING
    function->set_raw_feedback_cell(*feedback_cell, kReleaseStore);
    function->SetInterruptBudget(isolate);
  } else {
    function->raw_feedback_cell()->set_value(*feedback_cell_array,
                                             kReleaseStore);
  }
}

// static
void JSFunction::EnsureFeedbackVector(Isolate* isolate,
                                      DirectHandle<JSFunction> function,
                                      IsCompiledScope* compiled_scope) {
  CHECK(compiled_scope->is_compiled());
  DCHECK(function->shared()->HasFeedbackMetadata());
  if (function->has_feedback_vector()) return;
#if V8_ENABLE_WEBASSEMBLY
  if (function->shared()->HasAsmWasmData()) return;
#endif  // V8_ENABLE_WEBASSEMBLY

  CreateAndAttachFeedbackVector(isolate, function, compiled_scope);
}

// static
void JSFunction::CreateAndAttachFeedbackVector(
    Isolate* isolate, DirectHandle<JSFunction> function,
    IsCompiledScope* compiled_scope) {
  CHECK(compiled_scope->is_compiled());
  DCHECK(function->shared()->HasFeedbackMetadata());
  DCHECK(!function->has_feedback_vector());
#if V8_ENABLE_WEBASSEMBLY
  DCHECK(!function->shared()->HasAsmWasmData());
#endif  // V8_ENABLE_WEBASSEMBLY

  DirectHandle<SharedFunctionInfo> shared(function->shared(), isolate);
  DCHECK(function->shared()->HasBytecodeArray());

  EnsureClosureFeedbackCellArray(function, false);
  DirectHandle<ClosureFeedbackCellArray> closure_feedback_cell_array(
      function->closure_feedback_cell_array(), isolate);
  DirectHandle<FeedbackVector> feedback_vector = FeedbackVector::New(
      isolate, shared, closure_feedback_cell_array,
      direct_handle(function->raw_feedback_cell(isolate), isolate),
      compiled_scope);
  USE(feedback_vector);
  // EnsureClosureFeedbackCellArray should handle the special case where we need
  // to allocate a new feedback cell. Please look at comment in that function
  // for more details.
  DCHECK(function->raw_feedback_cell() !=
         isolate->heap()->many_closures_cell());
  DCHECK_EQ(function->raw_feedback_cell()->value(), *feedback_vector);
  function->SetInterruptBudget(isolate);

#ifndef V8_ENABLE_LEAPTIERING
  DCHECK_EQ(v8_flags.log_function_events,
            feedback_vector->log_next_execution());
#endif

  if (v8_flags.profile_guided_optimization &&
      v8_flags.profile_guided_optimization_for_empty_feedback_vector &&
      function->feedback_vector()->length() == 0) {
    if (function->shared()->cached_tiering_decision() ==
        CachedTieringDecision::kEarlyMaglev) {
      function->RequestOptimization(isolate, CodeKind::MAGLEV,
                                    ConcurrencyMode::kConcurrent);
    } else if (function->shared()->cached_tiering_decision() ==
               CachedTieringDecision::kEarlyTurbofan) {
      function->RequestOptimization(isolate, CodeKind::TURBOFAN_JS,
                                    ConcurrencyMode::kConcurrent);
    }
  }
}

// static
void JSFunction::InitializeFeedbackCell(
    DirectHandle<JSFunction> function, IsCompiledScope* is_compiled_scope,
    bool reset_budget_for_feedback_allocation) {
  Isolate* const isolate = function->GetIsolate();
#if V8_ENABLE_WEBASSEMBLY
  // The following checks ensure that the feedback vectors are compatible with
  // the feedback metadata. For Asm / Wasm functions we never allocate / use
  // feedback vectors, so a mismatch between the metadata and feedback vector is
  // harmless. The checks could fail for functions that has has_asm_wasm_broken
  // set at runtime (for ex: failed instantiation).
  if (function->shared()->HasAsmWasmData()) return;
#endif  // V8_ENABLE_WEBASSEMBLY

  if (function->has_feedback_vector()) {
    CHECK_EQ(function->feedback_vector()->length(),
             function->feedback_vector()->metadata()->slot_count());
    return;
  }

  if (function->has_closure_feedback_cell_array()) {
    CHECK_EQ(
        function->closure_feedback_cell_array()->length(),
        function->shared()->feedback_metadata()->create_closure_slot_count());
  }

  const bool needs_feedback_vector =
      !v8_flags.lazy_feedback_allocation || v8_flags.always_turbofan ||
      // We also need a feedback vector for certain log events, collecting type
      // profile and more precise code coverage.
      v8_flags.log_function_events ||
      !isolate->is_best_effort_code_coverage() ||
      function->shared()->cached_tiering_decision() !=
          CachedTieringDecision::kPending;

  if (needs_feedback_vector) {
    CreateAndAttachFeedbackVector(isolate, function, is_compiled_scope);
  } else {
    EnsureClosureFeedbackCellArray(function,
                                   reset_budget_for_feedback_allocation);
  }
#ifdef V8_ENABLE_SPARKPLUG
  // TODO(jgruber): Unduplicate these conditions from tiering-manager.cc.
  if (function->shared()->cached_tiering_decision() !=
          CachedTieringDecision::kPending &&
      CanCompileWithBaseline(isolate, function->shared()) &&
      function->ActiveTierIsIgnition(isolate)) {
    if (v8_flags.baseline_batch_compilation) {
      isolate->baseline_batch_compiler()->EnqueueFunction(function);
    } else {
      IsCompiledScope is_compiled_scope(
          function->shared()->is_compiled_scope(isolate));
      Compiler::CompileBaseline(isolate, function, Compiler::CLEAR_EXCEPTION,
                                &is_compiled_scope);
    }
  }
#endif  // V8_ENABLE_SPARKPLUG
}

namespace {

void SetInstancePrototype(Isolate* isolate, DirectHandle<JSFunction> function,
                          Handle<JSReceiver> value) {
  // Now some logic for the maps of the objects that are created by using this
  // function as a constructor.
  if (function->has_initial_map()) {
    // If the function has allocated the initial map replace it with a
    // copy containing the new prototype.  Also complete any in-object
    // slack tracking that is in progress at this point because it is
    // still tracking the old copy.
    function->CompleteInobjectSlackTrackingIfActive();

    Handle<Map> initial_map(function->initial_map(), isolate);

    if (!isolate->bootstrapper()->IsActive() &&
        initial_map->instance_type() == JS_OBJECT_TYPE) {
      // Put the value in the initial map field until an initial map is needed.
      // At that point, a new initial map is created and the prototype is put
      // into the initial map where it belongs.
      function->set_prototype_or_initial_map(*value, kReleaseStore);
      if (IsJSObjectThatCanBeTrackedAsPrototype(*value)) {
        // Optimize as prototype to detach it from its transition tree.
        JSObject::OptimizeAsPrototype(Cast<JSObject>(value));
      }
    } else {
      Handle<Map> new_map =
          Map::Copy(isolate, initial_map, "SetInstancePrototype");
      JSFunction::SetInitialMap(isolate, function, new_map, value);
      DCHECK_IMPLIES(!isolate->bootstrapper()->IsActive(),
                     *function != function->native_context()->array_function());
    }

    // Deoptimize all code that embeds the previous initial map.
    DependentCode::DeoptimizeDependencyGroups(
        isolate, *initial_map, DependentCode::kInitialMapChangedGroup);
  } else {
    // Put the value in the initial map field until an initial map is
    // needed.  At that point, a new initial map is created and the
    // prototype is put into the initial map where it belongs.
    function->set_prototype_or_initial_map(*value, kReleaseStore);
    if (IsJSObjectThatCanBeTrackedAsPrototype(*value)) {
      // Optimize as prototype to detach it from its transition tree.
      JSObject::OptimizeAsPrototype(Cast<JSObject>(value));
    }
  }
}

}  // anonymous namespace

void JSFunction::SetPrototype(DirectHandle<JSFunction> function,
                              Handle<Object> value) {
  DCHECK(IsConstructor(*function) ||
"""


```