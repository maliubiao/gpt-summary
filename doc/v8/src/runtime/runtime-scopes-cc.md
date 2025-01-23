Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/runtime/runtime-scopes.cc`. The request asks for:

1. **List of functionalities:**  What does this code do?
2. **Torque source check:** Is it a Torque file (`.tq`)?
3. **JavaScript relation:** If related to JavaScript features, provide examples.
4. **Logic inference:** Provide hypothetical inputs and outputs for code logic.
5. **Common errors:** Illustrate common programming mistakes related to the code.
6. **Overall summary:** A concise description of its purpose.

Let's break down the code section by section and identify its main functions:

* **Error Handling (ThrowConstAssignError, ThrowUsingAssignError):** These functions throw specific `TypeError` exceptions related to assigning to constants or `using` declarations.
* **Redeclaration Handling (ThrowRedeclarationError, DeclareGlobal):**  These functions deal with scenarios where variables are redeclared, enforcing JavaScript's scoping rules and throwing `SyntaxError` or `TypeError` as needed. The `DeclareGlobal` function is crucial for managing global variable declarations.
* **Module Exports (Runtime_DeclareModuleExports):** This function appears to handle the declaration of exports within JavaScript modules.
* **Global Declarations (Runtime_DeclareGlobals):** This function manages the declaration of global variables in the JavaScript environment.
* **Disposable Stacks (Runtime_InitializeDisposableStack, Runtime_AddDisposableValue, Runtime_AddAsyncDisposableValue, Runtime_DisposeDisposableStack, Runtime_HandleExceptionsInDisposeDisposableStack):** This set of functions implements a mechanism for managing resources that need to be disposed of, potentially asynchronously, likely related to the `using` statement and resource management in JavaScript.
* **Eval Declarations (DeclareEvalHelper, Runtime_DeclareEvalFunction, Runtime_DeclareEvalVar):** These functions handle variable and function declarations within the context of `eval()` calls, which have special scoping rules.
* **Arguments Objects (GetCallerArguments, NewSloppyArguments, Runtime_NewSloppyArguments, Runtime_NewStrictArguments, Runtime_NewRestParameter):**  These functions are responsible for creating and managing the `arguments` object available inside JavaScript functions, including handling sloppy mode arguments, strict mode arguments, and rest parameters.
* **Closures (Runtime_NewClosure, Runtime_NewClosure_Tenured):** These functions create JavaScript closures, which capture their surrounding lexical environment.
* **Context Management (Runtime_NewFunctionContext, Runtime_PushWithContext, Runtime_PushCatchContext, Runtime_PushBlockContext):**  These functions manage the creation and manipulation of different types of execution contexts in V8, like function contexts, `with` contexts, `catch` contexts, and block contexts.
* **Variable Deletion (Runtime_DeleteLookupSlot):** This function implements the `delete` operator's behavior when applied to variables in different scopes.
* **Variable Lookup (LoadLookupSlot):** This function is responsible for finding the value of a variable by looking it up in the current scope chain.

Based on this analysis, the primary function of `runtime-scopes.cc` is to **implement the runtime semantics of JavaScript's scoping rules and variable management**.

Now, let's address the other parts of the prompt:

* **`.tq` extension:** The code is standard C++, not Torque, so it would not end in `.tq`.
* **JavaScript examples:**  We can illustrate the functionality with JavaScript code snippets.
* **Logic inference:** We can create simple scenarios to show how some functions behave.
* **Common errors:** We can point out typical mistakes developers make that these runtime functions handle.
```cpp
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>

#include "src/builtins/accessors.h"
#include "src/common/message-template.h"
#include "src/deoptimizer/deoptimizer.h"
#include "src/execution/arguments-inl.h"
#include "src/execution/frames-inl.h"
#include "src/execution/isolate-inl.h"
#include "src/execution/isolate.h"
#include "src/handles/handles.h"
#include "src/heap/heap-inl.h"  // For ToBoolean. TODO(jkummerow): Drop.
#include "src/interpreter/bytecode-flags-and-tokens.h"
#include "src/objects/arguments-inl.h"
#include "src/objects/fixed-array.h"
#include "src/objects/heap-object.h"
#include "src/objects/js-disposable-stack-inl.h"
#include "src/objects/js-disposable-stack.h"
#include "src/objects/objects.h"
#include "src/objects/oddball.h"
#include "src/objects/smi.h"
#include "src/objects/tagged.h"
#include "src/runtime/runtime-utils.h"

namespace v8 {
namespace internal {

RUNTIME_FUNCTION(Runtime_ThrowConstAssignError) {
  HandleScope scope(isolate);
  THROW_NEW_ERROR_RETURN_FAILURE(isolate,
                                 NewTypeError(MessageTemplate::kConstAssign));
}

RUNTIME_FUNCTION(Runtime_ThrowUsingAssignError) {
  HandleScope scope(isolate);
  THROW_NEW_ERROR_RETURN_FAILURE(isolate,
                                 NewTypeError(MessageTemplate::kUsingAssign));
}

namespace {

enum class RedeclarationType { kSyntaxError = 0, kTypeError = 1 };

Tagged<Object> ThrowRedeclarationError(Isolate* isolate, Handle<String> name,
                                       RedeclarationType redeclaration_type) {
  HandleScope scope(isolate);
  if (redeclaration_type == RedeclarationType::kSyntaxError) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewSyntaxError(MessageTemplate::kVarRedeclaration, name));
  } else {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kVarRedeclaration, name));
  }
}

// May throw a RedeclarationError.
Tagged<Object> DeclareGlobal(Isolate* isolate, Handle<JSGlobalObject> global,
                             Handle<String> name, Handle<Object> value,
                             PropertyAttributes attr, bool is_var,
                             RedeclarationType redeclaration_type) {
  DirectHandle<ScriptContextTable> script_contexts(
      global->native_context()->script_context_table(), isolate);
  VariableLookupResult lookup;
  if (script_contexts->Lookup(name, &lookup) &&
      IsLexicalVariableMode(lookup.mode)) {
    // ES#sec-globaldeclarationinstantiation 6.a:
    // If envRec.HasLexicalDeclaration(name) is true, throw a SyntaxError
    // exception.
    return ThrowRedeclarationError(isolate, name,
                                   RedeclarationType::kSyntaxError);
  }

  // Do the lookup own properties only, see ES5 erratum.
  LookupIterator::Configuration lookup_config(
      LookupIterator::Configuration::OWN_SKIP_INTERCEPTOR);
  if (!is_var) {
    // For function declarations, use the interceptor on the declaration. For
    // non-functions, use it only on initialization.
    lookup_config = LookupIterator::Configuration::OWN;
  }
  LookupIterator it(isolate, global, name, global, lookup_config);
  Maybe<PropertyAttributes> maybe = JSReceiver::GetPropertyAttributes(&it);
  if (maybe.IsNothing()) return ReadOnlyRoots(isolate).exception();

  if (it.IsFound()) {
    PropertyAttributes old_attributes = maybe.FromJust();
    // The name was declared before; check for conflicting re-declarations.

    // Skip var re-declarations.
    if (is_var) return ReadOnlyRoots(isolate).undefined_value();

    if ((old_attributes & DONT_DELETE) != 0) {
      // Only allow reconfiguring globals to functions in user code (no
      // natives, which are marked as read-only).
      DCHECK_EQ(attr & READ_ONLY, 0);

      // Check whether we can reconfigure the existing property into a
      // function.
      if (old_attributes & READ_ONLY || old_attributes & DONT_ENUM ||
          (it.state() == LookupIterator::ACCESSOR)) {
        // ECMA-262 section 15.1.11 GlobalDeclarationInstantiation 5.d:
        // If hasRestrictedGlobal is true, throw a SyntaxError exception.
        // ECMA-262 section 18.2.1.3 EvalDeclarationInstantiation 8.a.iv.1.b:
        // If fnDefinable is false, throw a TypeError exception.
        return ThrowRedeclarationError(isolate, name, redeclaration_type);
      }
      // If the existing property is not configurable, keep its attributes. Do
      attr = old_attributes;
    }

    // If the current state is ACCESSOR, this could mean it's an AccessorInfo
    // type property. We are not allowed to call into such setters during global
    // function declaration since this would break e.g., onload. Meaning
    // 'function onload() {}' would invalidly register that function as the
    // onload callback. To avoid this situation, we first delete the property
    // before readding it as a regular data property below.
    if (it.state() == LookupIterator::ACCESSOR) it.Delete();
  }

  if (!is_var) it.Restart();

  // Define or redefine own property.
  RETURN_FAILURE_ON_EXCEPTION(
      isolate, JSObject::DefineOwnPropertyIgnoreAttributes(&it, value, attr));

  return ReadOnlyRoots(isolate).undefined_value();
}

}  // namespace

RUNTIME_FUNCTION(Runtime_DeclareModuleExports) {
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());

  DirectHandle<FixedArray> declarations = args.at<FixedArray>(0);
  DirectHandle<JSFunction> closure = args.at<JSFunction>(1);

  DirectHandle<ClosureFeedbackCellArray> closure_feedback_cell_array(
      closure->has_feedback_vector()
          ? closure->feedback_vector()->closure_feedback_cell_array()
          : closure->closure_feedback_cell_array(),
      isolate);

  Handle<Context> context(isolate->context(), isolate);
  DCHECK(context->IsModuleContext());
  DirectHandle<FixedArray> exports(
      Cast<SourceTextModule>(context->extension())->regular_exports(), isolate);

  int length = declarations->length();
  FOR_WITH_HANDLE_SCOPE(isolate, int, i = 0, i, i < length, i++, {
    Tagged<Object> decl = declarations->get(i);
    int index;
    Tagged<Object> value;
    if (IsSmi(decl)) {
      index = Smi::ToInt(decl);
      value = ReadOnlyRoots(isolate).the_hole_value();
    } else {
      Handle<SharedFunctionInfo> sfi(
          Cast<SharedFunctionInfo>(declarations->get(i)), isolate);
      int feedback_index = Smi::ToInt(declarations->get(++i));
      index = Smi::ToInt(declarations->get(++i));
      Handle<FeedbackCell> feedback_cell(
          closure_feedback_cell_array->get(feedback_index), isolate);
      value = *Factory::JSFunctionBuilder(isolate, sfi, context)
                   .set_feedback_cell(feedback_cell)
                   .Build();
    }

    Cast<Cell>(exports->get(index - 1))->set_value(value);
  });

  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_DeclareGlobals) {
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());

  DirectHandle<FixedArray> declarations = args.at<FixedArray>(0);
  DirectHandle<JSFunction> closure = args.at<JSFunction>(1);

  Handle<JSGlobalObject> global(isolate->global_object());
  Handle<Context> context(isolate->context(), isolate);

  DirectHandle<ClosureFeedbackCellArray> closure_feedback_cell_array(
      closure->has_feedback_vector()
          ? closure->feedback_vector()->closure_feedback_cell_array()
          : closure->closure_feedback_cell_array(),
      isolate);

  // Traverse the name/value pairs and set the properties.
  int length = declarations->length();
  FOR_WITH_HANDLE_SCOPE(isolate, int, i = 0, i, i < length, i++, {
    Handle<Object> decl(declarations->get(i), isolate);
    Handle<String> name;
    Handle<Object> value;
    bool is_var = IsString(*decl);

    if (is_var) {
      name = Cast<String>(decl);
      value = isolate->factory()->undefined_value();
    } else {
      Handle<SharedFunctionInfo> sfi = Cast<SharedFunctionInfo>(decl);
      name = handle(sfi->Name(), isolate);
      int index = Smi::ToInt(declarations->get(++i));
      Handle<FeedbackCell> feedback_cell(
          closure_feedback_cell_array->get(index), isolate);
      value = Factory::JSFunctionBuilder(isolate, sfi, context)
                  .set_feedback_cell(feedback_cell)
                  .Build();
    }

    // Compute the property attributes. According to ECMA-262,
    // the property must be non-configurable except in eval.
    Tagged<Script> script = Cast<Script>(closure->shared()->script());
    PropertyAttributes attr =
        script->compilation_type() == Script::CompilationType::kEval
            ? NONE
            : DONT_DELETE;

    // ES#sec-globaldeclarationinstantiation 5.d:
    // If hasRestrictedGlobal is true, throw a SyntaxError exception.
    Tagged<Object> result =
        DeclareGlobal(isolate, global, name, value, attr, is_var,
                      RedeclarationType::kSyntaxError);
    if (IsException(result)) return result;
  });

  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_InitializeDisposableStack) {
  HandleScope scope(isolate);
  DCHECK_EQ(0, args.length());

  DirectHandle<JSDisposableStackBase> disposable_stack =
      isolate->factory()->NewJSDisposableStackBase();
  JSDisposableStackBase::InitializeJSDisposableStackBase(isolate,
                                                         disposable_stack);
  return *disposable_stack;
}

Tagged<Object> AddToDisposableStack(Isolate* isolate,
                                    DirectHandle<JSDisposableStackBase> stack,
                                    Handle<JSAny> value,
                                    DisposeMethodCallType type,
                                    DisposeMethodHint hint) {
  // a. If V is either null or undefined and hint is sync-dispose, return
  // unused.
  if (IsNullOrUndefined(*value) && hint == DisposeMethodHint::kSyncDispose) {
    return *value;
  } else if (IsNullOrUndefined(*value) &&
             hint == DisposeMethodHint::kAsyncDispose) {
    value = ReadOnlyRoots(isolate).undefined_value_handle();
  }

  Handle<Object> method;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, method,
      JSDisposableStackBase::CheckValueAndGetDisposeMethod(isolate, value,
                                                           hint));

  // Return the DisposableResource Record { [[ResourceValue]]: V, [[Hint]]:
  // hint, [[DisposeMethod]]: method }.
  JSDisposableStackBase::Add(isolate, stack, value, method, type, hint);
  return *value;
}

RUNTIME_FUNCTION(Runtime_AddDisposableValue) {
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());

  DirectHandle<JSDisposableStackBase> stack = args.at<JSDisposableStackBase>(0);
  Handle<JSAny> value = args.at<JSAny>(1);

  // Return the DisposableResource Record { [[ResourceValue]]: V, [[Hint]]:
  // hint, [[DisposeMethod]]: method }.
  return AddToDisposableStack(isolate, stack, value,
                              DisposeMethodCallType::kValueIsReceiver,
                              DisposeMethodHint::kSyncDispose);
}

RUNTIME_FUNCTION(Runtime_AddAsyncDisposableValue) {
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());

  DirectHandle<JSDisposableStackBase> stack = args.at<JSDisposableStackBase>(0);
  Handle<JSAny> value = args.at<JSAny>(1);

  // Return the DisposableResource Record { [[ResourceValue]]: V, [[Hint]]:
  // hint, [[DisposeMethod]]: method }.
  return AddToDisposableStack(isolate, stack, value,
                              DisposeMethodCallType::kValueIsReceiver,
                              DisposeMethodHint::kAsyncDispose);
}

RUNTIME_FUNCTION(Runtime_DisposeDisposableStack) {
  HandleScope scope(isolate);
  DCHECK_EQ(4, args.length());

  DirectHandle<JSDisposableStackBase> disposable_stack =
      args.at<JSDisposableStackBase>(0);
  DirectHandle<Smi> continuation_token = args.at<Smi>(1);
  Handle<Object> continuation_error = args.at<Object>(2);
  DirectHandle<Smi> has_await_using = args.at<Smi>(3);

  Handle<Object> result;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, result,
      JSDisposableStackBase::DisposeResources(
          isolate, disposable_stack,
          (*continuation_token !=
           Smi::FromInt(static_cast<int>(
               interpreter::TryFinallyContinuationToken::kRethrowToken)))
              ? MaybeHandle<Object>()
              : continuation_error,
          static_cast<DisposableStackResourcesType>(
              Smi::ToInt(*has_await_using))));
  return *result;
}

RUNTIME_FUNCTION(Runtime_HandleExceptionsInDisposeDisposableStack) {
  HandleScope scope(isolate);
  DCHECK_EQ(3, args.length());

  DirectHandle<JSDisposableStackBase> disposable_stack =
      args.at<JSDisposableStackBase>(0);
  Handle<Object> exception = args.at<Object>(1);
  Handle<Object> message = args.at<Object>(2);

  if (!isolate->is_catchable_by_javascript(*exception)) {
    return isolate->Throw(*exception);
  }

  JSDisposableStackBase::HandleErrorInDisposal(isolate, disposable_stack,
                                               exception, message);
  return *disposable_stack;
}

namespace {

Tagged<Object> DeclareEvalHelper(Isolate* isolate, Handle<String> name,
                                 Handle<Object> value) {
  // Declarations are always made in a function, native, eval, or script
  // context, or a declaration block scope. Since this is called from eval, the
  // context passed is the context of the caller, which may be some nested
  // context and not the declaration context.
  Handle<Context> context(isolate->context()->declaration_context(), isolate);

  // For debug-evaluate we always use sloppy eval, in which case context could
  // also be a module context. As module contexts re-use the extension slot
  // we need to check for this.
  const bool is_debug_evaluate_in_module =
      isolate->context()->IsDebugEvaluateContext() &&
      context->IsModuleContext();

  DCHECK(context->IsFunctionContext() || IsNativeContext(*context) ||
         context->IsScriptContext() || context->IsEvalContext() ||
         (context->IsBlockContext() &&
          context->scope_info()->is_declaration_scope()) ||
         is_debug_evaluate_in_module);

  bool is_var = IsUndefined(*value, isolate);
  DCHECK_IMPLIES(!is_var, IsJSFunction(*value));

  int index;
  PropertyAttributes attributes;
  InitializationFlag init_flag;
  VariableMode mode;

  Handle<Object> holder =
      Context::Lookup(context, name, DONT_FOLLOW_CHAINS, &index, &attributes,
                      &init_flag, &mode);
  DCHECK(holder.is_null() || !IsSourceTextModule(*holder));
  DCHECK(!isolate->has_exception());

  Handle<JSObject> object;

  if (attributes != ABSENT && IsJSGlobalObject(*holder)) {
    // ES#sec-evaldeclarationinstantiation 8.a.iv.1.b:
    // If fnDefinable is false, throw a TypeError exception.
    return DeclareGlobal(isolate, Cast<JSGlobalObject>(holder), name, value,
                         NONE, is_var, RedeclarationType::kTypeError);
  }
  if (context->has_extension() && IsJSGlobalObject(context->extension())) {
    Handle<JSGlobalObject> global(Cast<JSGlobalObject>(context->extension()),
                                  isolate);
    return DeclareGlobal(isolate, global, name, value, NONE, is_var,
                         RedeclarationType::kTypeError);
  } else if (context->IsScriptContext()) {
    DCHECK(IsJSGlobalObject(context->global_object()));
    Handle<JSGlobalObject> global(
        Cast<JSGlobalObject>(context->global_object()), isolate);
    return DeclareGlobal(isolate, global, name, value, NONE, is_var,
                         RedeclarationType::kTypeError);
  }

  if (attributes != ABSENT) {
    DCHECK_EQ(NONE, attributes);

    // Skip var re-declarations.
    if (is_var) return ReadOnlyRoots(isolate).undefined_value();

    if (index != Context::kNotFound) {
      DCHECK(holder.is_identical_to(context));
      context->set(index, *value);
      return ReadOnlyRoots(isolate).undefined_value();
    }

    object = Cast<JSObject>(holder);

  } else if (context->has_extension() && !is_debug_evaluate_in_module) {
    object = handle(context->extension_object(), isolate);
    DCHECK(IsJSContextExtensionObject(*object));
  } else if (context->scope_info()->HasContextExtensionSlot() &&
             !is_debug_evaluate_in_module) {
    // Sloppy varblock and function contexts might not have an extension object
    // yet. Sloppy eval will never have an extension object, as vars are hoisted
    // out, and lets are known statically.
    DCHECK((context->IsBlockContext() &&
            context->scope_info()->is_declaration_scope()) ||
           context->IsFunctionContext());
    DCHECK(context->scope_info()->SloppyEvalCanExtendVars());
    object =
        isolate->factory()->NewJSObject(isolate->context_extension_function());
    context->set_extension(*object);
    {
      Tagged<ScopeInfo> scope_info = context->scope_info();
      if (!scope_info->SomeContextHasExtension()) {
        scope_info->mark_some_context_has_extension();
        DependentCode::DeoptimizeDependencyGroups(
            isolate, scope_info, DependentCode::kEmptyContextExtensionGroup);
      }
    }
  } else {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate,
        NewEvalError(MessageTemplate::kVarNotAllowedInEvalScope, name));
  }

  RETURN_FAILURE_ON_EXCEPTION(isolate, JSObject::SetOwnPropertyIgnoreAttributes(
                                           object, name, value, NONE));

  return ReadOnlyRoots(isolate).undefined_value();
}

}  // namespace

RUNTIME_FUNCTION(Runtime_DeclareEvalFunction) {
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());
  Handle<String> name = args.at<String>(0);
  Handle<Object> value = args.at(1);
  return DeclareEvalHelper(isolate, name, value);
}

RUNTIME_FUNCTION(Runtime_DeclareEvalVar) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  Handle<String> name = args.at<String>(0);
  return DeclareEvalHelper(isolate, name,
                           isolate->factory()->undefined_value());
}

namespace {

// Find the arguments of the JavaScript function invocation that called
// into C++ code. Collect these in a newly allocated array of handles.
DirectHandleVector<Object> GetCallerArguments(Isolate* isolate) {
  // Find frame containing arguments passed to the caller.
  JavaScriptStackFrameIterator it(isolate);
  JavaScriptFrame* frame = it.frame();
  std::vector<Tagged<SharedFunctionInfo>> functions;
  frame->GetFunctions(&functions);
  if (functions.size() > 1) {
    int inlined_jsframe_index = static_cast<int>(functions.size()) - 1;
    TranslatedState translated_values(frame);
    translated_values.Prepare(frame->fp());

    int argument_count = 0;
    TranslatedFrame* translated_frame =
        translated_values.GetArgumentsInfoFromJSFrameIndex(
            inlined_jsframe_index, &argument_count);
    TranslatedFrame::iterator iter = translated_frame->begin();

    // Skip the function.
    iter++;

    // Skip the receiver.
    iter++;
    argument_count--;

    DirectHandleVector<Object> param_data(isolate, argument_count);
    bool should_deoptimize = false;
    for (int i = 0; i < argument_count; i++) {
      // If we materialize any object, we should deoptimize the frame because we
      // might alias an object that was eliminated by escape analysis.
      should_deoptimize = should_deoptimize || iter->IsMaterializedObject();
      Handle<Object> value = iter->GetValue();
      param_data[i] = value;
      iter++;
    }

    if (should_deoptimize) {
      translated_values.StoreMaterializedValuesAndDeopt(frame);
    }

    return param_data;
  } else {
    int args_count = frame->GetActualArgumentCount();
    DirectHandleVector<Object> param_data(isolate, args_count);
    for (int i = 0; i < args_count; i++) {
      Handle<Object> val = Handle<Object>(frame->GetParameter(i), isolate);
      param_data[i] = val;
    }
    return param_data;
  }
}

template <typename T>
Handle<JSObject> NewSloppyArguments(Isolate* isolate, Handle<JSFunction> callee,
                                    T parameters, int argument_count) {
  CHECK(!IsDerivedConstructor(callee->shared()->kind()));
  DCHECK(callee->shared()->has_simple_parameters());
  Handle<JSObject> result =
      isolate->factory()->NewArgumentsObject(callee, argument_count);

  // Allocate the elements if needed.
  int parameter_count =
      callee->shared()->internal_formal_parameter_count_without_receiver();
  if (argument_count > 0) {
    if (parameter_count > 0) {
      int mapped_count = std::min(argument_count, parameter_count);

      // Store the context and the arguments array at the beginning of the
      // parameter map.
      DirectHandle<Context> context(isolate->context(), isolate);
      DirectHandle<FixedArray> arguments = isolate->factory()->NewFixedArray(
          argument_count, AllocationType::kYoung);

      DirectHandle<SloppyArgumentsElements> parameter_map =
          isolate->factory()->NewSloppyArgumentsElements(
              mapped_count, context, arguments, AllocationType::kYoung);

      result->set_map(isolate,
                      isolate->native_context()->fast_aliased_arguments_map());
      result->set_elements(*parameter_map);

      // Loop over the actual parameters backwards.
      int index = argument_count - 1;
      while (index >= mapped_count) {
        // These go directly in the arguments array and have no
        // corresponding slot in the parameter map.
        arguments->set(index, parameters[index]);
        --index;
      }

      DirectHandle<ScopeInfo> scope_info(callee->shared()->scope_info(),
                                         isolate);

      // First mark all mappable slots as unmapped and copy the values into the
      // arguments object.
      for (int i = 0; i < mapped_count; i++) {
        arguments->set(i, parameters[i]);
        parameter_map->set_mapped_entries(
            i, *isolate->factory()->the_hole_value());
      }

      // Walk all context slots to find context allocated parameters. Mark each
      // found parameter as mapped.
      ReadOnlyRoots roots{isolate};
      for (int i = 0; i < scope_info->ContextLocalCount(); i++) {
        if (!scope_info->ContextLocalIsParameter(i)) continue;
        int parameter = scope_info->ContextLocalParameterNumber(i);
        if (parameter >= mapped_count) continue;
        arguments->set_the_hole(roots, parameter);
        Tagged<Smi> slot = Smi::FromInt(scope_info->ContextHeaderLength() + i);
        parameter_map->set_mapped_entries(parameter, slot);
      }
    } else {
      // If there is no aliasing, the arguments object elements are not
      // special in any way.
      DirectHandle<FixedArray> elements = isolate->factory()->NewFixedArray(
          argument_count, AllocationType::kYoung);
      result->set_elements(*elements);
      for (int i = 0; i < argument_count; ++i) {
        elements->set(i, parameters[i]);
      }
    }
  }
  return result;
}

class HandleArguments {
 public:
  // If direct handles are enabled, it is the responsibility of the caller to
  // ensure that the memory pointed to by `array` is scanned during CSS, e.g.,
  // it comes from a `DirectHandleVector<Object>`.
  explicit HandleArguments(base::Vector<const DirectHandle<Object>> array)
      : array_(array) {}
  Tagged<Object> operator[](int index) { return *array_[index]; }

 private:
  base::Vector<const DirectHandle<Object>> array_;
};

class ParameterArguments {
 public:
  explicit ParameterArguments(Address parameters) : parameters_(parameters) {}
  Tagged<Object> operator[](int index) {
    return *FullObjectSlot(parameters_ - (index + 1) * kSystemPointerSize);
  }

 private:
  Address parameters_;
};

}  // namespace

RUNTIME_FUNCTION(Runtime_NewSloppyArguments) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  Handle<JSFunction> callee = args.at<JSFunction>(0);
  // This generic runtime function can also be used when the caller has been
  // inlined, we use the slow but accurate {GetCallerArguments}.
  auto arguments = GetCallerArguments(isolate);
  HandleArguments argument_getter({arguments.data(), arguments.size()});
  return *NewSloppyArguments(isolate, callee, argument_getter,
                             static_cast<int>(arguments.size()));
}

RUNTIME_FUNCTION(Runtime_NewStrictArguments) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  Handle<JSFunction> callee = args.at<JSFunction>(0);
  // This generic runtime function can also be used when the caller has been
  // inlined, we use the slow but accurate {GetCallerArguments}.
  auto arguments = GetCallerArguments(isolate);
  int argument_count = static_cast<int>(arguments.size());
  DirectHandle<JSObject> result =
      isolate->factory()->NewArgumentsObject(callee, argument_count);
  if (argument_count) {
    DirectHandle<FixedArray> array =
        isolate->factory()->NewFixedArray(argument_count);
    DisallowGarbageCollection no_gc;
    WriteBarrierMode mode = array->GetWriteBarrierMode(no_gc);
    for (int i = 0; i < argument_count; i++) {
      array->set(i, *arguments[i], mode);
    }
    result->set_elements(*array);
  }
  return *result;
}

RUNTIME_FUNCTION(Runtime_NewRestParameter) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  DirectHandle<JSFunction> callee = args.at<JSFunction>(0);
  int start_index =
      callee->shared()->internal_formal_parameter_count_without_receiver();
  // This generic runtime function can also be used when the caller has been
  // inlined, we use the slow but accurate {GetCallerArguments}.
  auto arguments = GetCallerArguments(isolate);
  int argument_count = static_cast<int>(arguments.size());
  int num_elements = std::max(0, argument_count - start_index);
  DirectHandle<JSObject> result = isolate->factory()->NewJSArray(
      PACKED_ELEMENTS, num_elements, num_elements,
      ArrayStorageAllocationMode::DONT_INITIALIZE_ARRAY_ELEMENTS);
  if (num_elements == 0) return *result;
  {
    DisallowGarbageCollection no_gc;
    Tagged<FixedArray> elements = Cast<FixedArray>(result->elements());
    WriteBarrierMode mode = elements->GetWriteBarrierMode(no_gc);
    for (int i = 0; i < num_elements; i++) {
      elements->set(i, *arguments[i + start_index], mode);
    }
  }
  return *result;
}

RUNTIME_FUNCTION(Runtime_NewClosure) {
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());
  Handle<SharedFunctionInfo> shared = args.at<SharedFunctionInfo>(0);
  Handle<FeedbackCell> feedback_cell = args.at<FeedbackCell>(1);
  Handle<Context> context(isolate->context(), isolate);
  return *Factory::JSFunctionBuilder{isolate, shared, context}
              .set_feedback_cell(feedback_cell)
              .set_allocation_type(AllocationType::kYoung)
              .Build();
}

RUNTIME_FUNCTION(Runtime_NewClosure_Tenured) {
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());
  Handle<SharedFunctionInfo> shared = args.at<SharedFunctionInfo>(0);
  Handle<FeedbackCell> feedback_cell = args.at<FeedbackCell>(1);
  Handle<Context> context(isolate->context(), isolate);
  // The caller ensures that we preten
### 提示词
```
这是目录为v8/src/runtime/runtime-scopes.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/runtime/runtime-scopes.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>

#include "src/builtins/accessors.h"
#include "src/common/message-template.h"
#include "src/deoptimizer/deoptimizer.h"
#include "src/execution/arguments-inl.h"
#include "src/execution/frames-inl.h"
#include "src/execution/isolate-inl.h"
#include "src/execution/isolate.h"
#include "src/handles/handles.h"
#include "src/heap/heap-inl.h"  // For ToBoolean. TODO(jkummerow): Drop.
#include "src/interpreter/bytecode-flags-and-tokens.h"
#include "src/objects/arguments-inl.h"
#include "src/objects/fixed-array.h"
#include "src/objects/heap-object.h"
#include "src/objects/js-disposable-stack-inl.h"
#include "src/objects/js-disposable-stack.h"
#include "src/objects/objects.h"
#include "src/objects/oddball.h"
#include "src/objects/smi.h"
#include "src/objects/tagged.h"
#include "src/runtime/runtime-utils.h"

namespace v8 {
namespace internal {

RUNTIME_FUNCTION(Runtime_ThrowConstAssignError) {
  HandleScope scope(isolate);
  THROW_NEW_ERROR_RETURN_FAILURE(isolate,
                                 NewTypeError(MessageTemplate::kConstAssign));
}

RUNTIME_FUNCTION(Runtime_ThrowUsingAssignError) {
  HandleScope scope(isolate);
  THROW_NEW_ERROR_RETURN_FAILURE(isolate,
                                 NewTypeError(MessageTemplate::kUsingAssign));
}

namespace {

enum class RedeclarationType { kSyntaxError = 0, kTypeError = 1 };

Tagged<Object> ThrowRedeclarationError(Isolate* isolate, Handle<String> name,
                                       RedeclarationType redeclaration_type) {
  HandleScope scope(isolate);
  if (redeclaration_type == RedeclarationType::kSyntaxError) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewSyntaxError(MessageTemplate::kVarRedeclaration, name));
  } else {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kVarRedeclaration, name));
  }
}

// May throw a RedeclarationError.
Tagged<Object> DeclareGlobal(Isolate* isolate, Handle<JSGlobalObject> global,
                             Handle<String> name, Handle<Object> value,
                             PropertyAttributes attr, bool is_var,
                             RedeclarationType redeclaration_type) {
  DirectHandle<ScriptContextTable> script_contexts(
      global->native_context()->script_context_table(), isolate);
  VariableLookupResult lookup;
  if (script_contexts->Lookup(name, &lookup) &&
      IsLexicalVariableMode(lookup.mode)) {
    // ES#sec-globaldeclarationinstantiation 6.a:
    // If envRec.HasLexicalDeclaration(name) is true, throw a SyntaxError
    // exception.
    return ThrowRedeclarationError(isolate, name,
                                   RedeclarationType::kSyntaxError);
  }

  // Do the lookup own properties only, see ES5 erratum.
  LookupIterator::Configuration lookup_config(
      LookupIterator::Configuration::OWN_SKIP_INTERCEPTOR);
  if (!is_var) {
    // For function declarations, use the interceptor on the declaration. For
    // non-functions, use it only on initialization.
    lookup_config = LookupIterator::Configuration::OWN;
  }
  LookupIterator it(isolate, global, name, global, lookup_config);
  Maybe<PropertyAttributes> maybe = JSReceiver::GetPropertyAttributes(&it);
  if (maybe.IsNothing()) return ReadOnlyRoots(isolate).exception();

  if (it.IsFound()) {
    PropertyAttributes old_attributes = maybe.FromJust();
    // The name was declared before; check for conflicting re-declarations.

    // Skip var re-declarations.
    if (is_var) return ReadOnlyRoots(isolate).undefined_value();

    if ((old_attributes & DONT_DELETE) != 0) {
      // Only allow reconfiguring globals to functions in user code (no
      // natives, which are marked as read-only).
      DCHECK_EQ(attr & READ_ONLY, 0);

      // Check whether we can reconfigure the existing property into a
      // function.
      if (old_attributes & READ_ONLY || old_attributes & DONT_ENUM ||
          (it.state() == LookupIterator::ACCESSOR)) {
        // ECMA-262 section 15.1.11 GlobalDeclarationInstantiation 5.d:
        // If hasRestrictedGlobal is true, throw a SyntaxError exception.
        // ECMA-262 section 18.2.1.3 EvalDeclarationInstantiation 8.a.iv.1.b:
        // If fnDefinable is false, throw a TypeError exception.
        return ThrowRedeclarationError(isolate, name, redeclaration_type);
      }
      // If the existing property is not configurable, keep its attributes. Do
      attr = old_attributes;
    }

    // If the current state is ACCESSOR, this could mean it's an AccessorInfo
    // type property. We are not allowed to call into such setters during global
    // function declaration since this would break e.g., onload. Meaning
    // 'function onload() {}' would invalidly register that function as the
    // onload callback. To avoid this situation, we first delete the property
    // before readding it as a regular data property below.
    if (it.state() == LookupIterator::ACCESSOR) it.Delete();
  }

  if (!is_var) it.Restart();

  // Define or redefine own property.
  RETURN_FAILURE_ON_EXCEPTION(
      isolate, JSObject::DefineOwnPropertyIgnoreAttributes(&it, value, attr));

  return ReadOnlyRoots(isolate).undefined_value();
}

}  // namespace

RUNTIME_FUNCTION(Runtime_DeclareModuleExports) {
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());

  DirectHandle<FixedArray> declarations = args.at<FixedArray>(0);
  DirectHandle<JSFunction> closure = args.at<JSFunction>(1);

  DirectHandle<ClosureFeedbackCellArray> closure_feedback_cell_array(
      closure->has_feedback_vector()
          ? closure->feedback_vector()->closure_feedback_cell_array()
          : closure->closure_feedback_cell_array(),
      isolate);

  Handle<Context> context(isolate->context(), isolate);
  DCHECK(context->IsModuleContext());
  DirectHandle<FixedArray> exports(
      Cast<SourceTextModule>(context->extension())->regular_exports(), isolate);

  int length = declarations->length();
  FOR_WITH_HANDLE_SCOPE(isolate, int, i = 0, i, i < length, i++, {
    Tagged<Object> decl = declarations->get(i);
    int index;
    Tagged<Object> value;
    if (IsSmi(decl)) {
      index = Smi::ToInt(decl);
      value = ReadOnlyRoots(isolate).the_hole_value();
    } else {
      Handle<SharedFunctionInfo> sfi(
          Cast<SharedFunctionInfo>(declarations->get(i)), isolate);
      int feedback_index = Smi::ToInt(declarations->get(++i));
      index = Smi::ToInt(declarations->get(++i));
      Handle<FeedbackCell> feedback_cell(
          closure_feedback_cell_array->get(feedback_index), isolate);
      value = *Factory::JSFunctionBuilder(isolate, sfi, context)
                   .set_feedback_cell(feedback_cell)
                   .Build();
    }

    Cast<Cell>(exports->get(index - 1))->set_value(value);
  });

  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_DeclareGlobals) {
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());

  DirectHandle<FixedArray> declarations = args.at<FixedArray>(0);
  DirectHandle<JSFunction> closure = args.at<JSFunction>(1);

  Handle<JSGlobalObject> global(isolate->global_object());
  Handle<Context> context(isolate->context(), isolate);

  DirectHandle<ClosureFeedbackCellArray> closure_feedback_cell_array(
      closure->has_feedback_vector()
          ? closure->feedback_vector()->closure_feedback_cell_array()
          : closure->closure_feedback_cell_array(),
      isolate);

  // Traverse the name/value pairs and set the properties.
  int length = declarations->length();
  FOR_WITH_HANDLE_SCOPE(isolate, int, i = 0, i, i < length, i++, {
    Handle<Object> decl(declarations->get(i), isolate);
    Handle<String> name;
    Handle<Object> value;
    bool is_var = IsString(*decl);

    if (is_var) {
      name = Cast<String>(decl);
      value = isolate->factory()->undefined_value();
    } else {
      Handle<SharedFunctionInfo> sfi = Cast<SharedFunctionInfo>(decl);
      name = handle(sfi->Name(), isolate);
      int index = Smi::ToInt(declarations->get(++i));
      Handle<FeedbackCell> feedback_cell(
          closure_feedback_cell_array->get(index), isolate);
      value = Factory::JSFunctionBuilder(isolate, sfi, context)
                  .set_feedback_cell(feedback_cell)
                  .Build();
    }

    // Compute the property attributes. According to ECMA-262,
    // the property must be non-configurable except in eval.
    Tagged<Script> script = Cast<Script>(closure->shared()->script());
    PropertyAttributes attr =
        script->compilation_type() == Script::CompilationType::kEval
            ? NONE
            : DONT_DELETE;

    // ES#sec-globaldeclarationinstantiation 5.d:
    // If hasRestrictedGlobal is true, throw a SyntaxError exception.
    Tagged<Object> result =
        DeclareGlobal(isolate, global, name, value, attr, is_var,
                      RedeclarationType::kSyntaxError);
    if (IsException(result)) return result;
  });

  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_InitializeDisposableStack) {
  HandleScope scope(isolate);
  DCHECK_EQ(0, args.length());

  DirectHandle<JSDisposableStackBase> disposable_stack =
      isolate->factory()->NewJSDisposableStackBase();
  JSDisposableStackBase::InitializeJSDisposableStackBase(isolate,
                                                         disposable_stack);
  return *disposable_stack;
}

Tagged<Object> AddToDisposableStack(Isolate* isolate,
                                    DirectHandle<JSDisposableStackBase> stack,
                                    Handle<JSAny> value,
                                    DisposeMethodCallType type,
                                    DisposeMethodHint hint) {
  // a. If V is either null or undefined and hint is sync-dispose, return
  // unused.
  if (IsNullOrUndefined(*value) && hint == DisposeMethodHint::kSyncDispose) {
    return *value;
  } else if (IsNullOrUndefined(*value) &&
             hint == DisposeMethodHint::kAsyncDispose) {
    value = ReadOnlyRoots(isolate).undefined_value_handle();
  }

  Handle<Object> method;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, method,
      JSDisposableStackBase::CheckValueAndGetDisposeMethod(isolate, value,
                                                           hint));

  // Return the DisposableResource Record { [[ResourceValue]]: V, [[Hint]]:
  // hint, [[DisposeMethod]]: method }.
  JSDisposableStackBase::Add(isolate, stack, value, method, type, hint);
  return *value;
}

RUNTIME_FUNCTION(Runtime_AddDisposableValue) {
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());

  DirectHandle<JSDisposableStackBase> stack = args.at<JSDisposableStackBase>(0);
  Handle<JSAny> value = args.at<JSAny>(1);

  // Return the DisposableResource Record { [[ResourceValue]]: V, [[Hint]]:
  // hint, [[DisposeMethod]]: method }.
  return AddToDisposableStack(isolate, stack, value,
                              DisposeMethodCallType::kValueIsReceiver,
                              DisposeMethodHint::kSyncDispose);
}

RUNTIME_FUNCTION(Runtime_AddAsyncDisposableValue) {
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());

  DirectHandle<JSDisposableStackBase> stack = args.at<JSDisposableStackBase>(0);
  Handle<JSAny> value = args.at<JSAny>(1);

  // Return the DisposableResource Record { [[ResourceValue]]: V, [[Hint]]:
  // hint, [[DisposeMethod]]: method }.
  return AddToDisposableStack(isolate, stack, value,
                              DisposeMethodCallType::kValueIsReceiver,
                              DisposeMethodHint::kAsyncDispose);
}

RUNTIME_FUNCTION(Runtime_DisposeDisposableStack) {
  HandleScope scope(isolate);
  DCHECK_EQ(4, args.length());

  DirectHandle<JSDisposableStackBase> disposable_stack =
      args.at<JSDisposableStackBase>(0);
  DirectHandle<Smi> continuation_token = args.at<Smi>(1);
  Handle<Object> continuation_error = args.at<Object>(2);
  DirectHandle<Smi> has_await_using = args.at<Smi>(3);

  Handle<Object> result;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, result,
      JSDisposableStackBase::DisposeResources(
          isolate, disposable_stack,
          (*continuation_token !=
           Smi::FromInt(static_cast<int>(
               interpreter::TryFinallyContinuationToken::kRethrowToken)))
              ? MaybeHandle<Object>()
              : continuation_error,
          static_cast<DisposableStackResourcesType>(
              Smi::ToInt(*has_await_using))));
  return *result;
}

RUNTIME_FUNCTION(Runtime_HandleExceptionsInDisposeDisposableStack) {
  HandleScope scope(isolate);
  DCHECK_EQ(3, args.length());

  DirectHandle<JSDisposableStackBase> disposable_stack =
      args.at<JSDisposableStackBase>(0);
  Handle<Object> exception = args.at<Object>(1);
  Handle<Object> message = args.at<Object>(2);

  if (!isolate->is_catchable_by_javascript(*exception)) {
    return isolate->Throw(*exception);
  }

  JSDisposableStackBase::HandleErrorInDisposal(isolate, disposable_stack,
                                               exception, message);
  return *disposable_stack;
}

namespace {

Tagged<Object> DeclareEvalHelper(Isolate* isolate, Handle<String> name,
                                 Handle<Object> value) {
  // Declarations are always made in a function, native, eval, or script
  // context, or a declaration block scope. Since this is called from eval, the
  // context passed is the context of the caller, which may be some nested
  // context and not the declaration context.
  Handle<Context> context(isolate->context()->declaration_context(), isolate);

  // For debug-evaluate we always use sloppy eval, in which case context could
  // also be a module context. As module contexts re-use the extension slot
  // we need to check for this.
  const bool is_debug_evaluate_in_module =
      isolate->context()->IsDebugEvaluateContext() &&
      context->IsModuleContext();

  DCHECK(context->IsFunctionContext() || IsNativeContext(*context) ||
         context->IsScriptContext() || context->IsEvalContext() ||
         (context->IsBlockContext() &&
          context->scope_info()->is_declaration_scope()) ||
         is_debug_evaluate_in_module);

  bool is_var = IsUndefined(*value, isolate);
  DCHECK_IMPLIES(!is_var, IsJSFunction(*value));

  int index;
  PropertyAttributes attributes;
  InitializationFlag init_flag;
  VariableMode mode;

  Handle<Object> holder =
      Context::Lookup(context, name, DONT_FOLLOW_CHAINS, &index, &attributes,
                      &init_flag, &mode);
  DCHECK(holder.is_null() || !IsSourceTextModule(*holder));
  DCHECK(!isolate->has_exception());

  Handle<JSObject> object;

  if (attributes != ABSENT && IsJSGlobalObject(*holder)) {
    // ES#sec-evaldeclarationinstantiation 8.a.iv.1.b:
    // If fnDefinable is false, throw a TypeError exception.
    return DeclareGlobal(isolate, Cast<JSGlobalObject>(holder), name, value,
                         NONE, is_var, RedeclarationType::kTypeError);
  }
  if (context->has_extension() && IsJSGlobalObject(context->extension())) {
    Handle<JSGlobalObject> global(Cast<JSGlobalObject>(context->extension()),
                                  isolate);
    return DeclareGlobal(isolate, global, name, value, NONE, is_var,
                         RedeclarationType::kTypeError);
  } else if (context->IsScriptContext()) {
    DCHECK(IsJSGlobalObject(context->global_object()));
    Handle<JSGlobalObject> global(
        Cast<JSGlobalObject>(context->global_object()), isolate);
    return DeclareGlobal(isolate, global, name, value, NONE, is_var,
                         RedeclarationType::kTypeError);
  }

  if (attributes != ABSENT) {
    DCHECK_EQ(NONE, attributes);

    // Skip var re-declarations.
    if (is_var) return ReadOnlyRoots(isolate).undefined_value();

    if (index != Context::kNotFound) {
      DCHECK(holder.is_identical_to(context));
      context->set(index, *value);
      return ReadOnlyRoots(isolate).undefined_value();
    }

    object = Cast<JSObject>(holder);

  } else if (context->has_extension() && !is_debug_evaluate_in_module) {
    object = handle(context->extension_object(), isolate);
    DCHECK(IsJSContextExtensionObject(*object));
  } else if (context->scope_info()->HasContextExtensionSlot() &&
             !is_debug_evaluate_in_module) {
    // Sloppy varblock and function contexts might not have an extension object
    // yet. Sloppy eval will never have an extension object, as vars are hoisted
    // out, and lets are known statically.
    DCHECK((context->IsBlockContext() &&
            context->scope_info()->is_declaration_scope()) ||
           context->IsFunctionContext());
    DCHECK(context->scope_info()->SloppyEvalCanExtendVars());
    object =
        isolate->factory()->NewJSObject(isolate->context_extension_function());
    context->set_extension(*object);
    {
      Tagged<ScopeInfo> scope_info = context->scope_info();
      if (!scope_info->SomeContextHasExtension()) {
        scope_info->mark_some_context_has_extension();
        DependentCode::DeoptimizeDependencyGroups(
            isolate, scope_info, DependentCode::kEmptyContextExtensionGroup);
      }
    }
  } else {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate,
        NewEvalError(MessageTemplate::kVarNotAllowedInEvalScope, name));
  }

  RETURN_FAILURE_ON_EXCEPTION(isolate, JSObject::SetOwnPropertyIgnoreAttributes(
                                           object, name, value, NONE));

  return ReadOnlyRoots(isolate).undefined_value();
}

}  // namespace

RUNTIME_FUNCTION(Runtime_DeclareEvalFunction) {
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());
  Handle<String> name = args.at<String>(0);
  Handle<Object> value = args.at(1);
  return DeclareEvalHelper(isolate, name, value);
}

RUNTIME_FUNCTION(Runtime_DeclareEvalVar) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  Handle<String> name = args.at<String>(0);
  return DeclareEvalHelper(isolate, name,
                           isolate->factory()->undefined_value());
}

namespace {

// Find the arguments of the JavaScript function invocation that called
// into C++ code. Collect these in a newly allocated array of handles.
DirectHandleVector<Object> GetCallerArguments(Isolate* isolate) {
  // Find frame containing arguments passed to the caller.
  JavaScriptStackFrameIterator it(isolate);
  JavaScriptFrame* frame = it.frame();
  std::vector<Tagged<SharedFunctionInfo>> functions;
  frame->GetFunctions(&functions);
  if (functions.size() > 1) {
    int inlined_jsframe_index = static_cast<int>(functions.size()) - 1;
    TranslatedState translated_values(frame);
    translated_values.Prepare(frame->fp());

    int argument_count = 0;
    TranslatedFrame* translated_frame =
        translated_values.GetArgumentsInfoFromJSFrameIndex(
            inlined_jsframe_index, &argument_count);
    TranslatedFrame::iterator iter = translated_frame->begin();

    // Skip the function.
    iter++;

    // Skip the receiver.
    iter++;
    argument_count--;

    DirectHandleVector<Object> param_data(isolate, argument_count);
    bool should_deoptimize = false;
    for (int i = 0; i < argument_count; i++) {
      // If we materialize any object, we should deoptimize the frame because we
      // might alias an object that was eliminated by escape analysis.
      should_deoptimize = should_deoptimize || iter->IsMaterializedObject();
      Handle<Object> value = iter->GetValue();
      param_data[i] = value;
      iter++;
    }

    if (should_deoptimize) {
      translated_values.StoreMaterializedValuesAndDeopt(frame);
    }

    return param_data;
  } else {
    int args_count = frame->GetActualArgumentCount();
    DirectHandleVector<Object> param_data(isolate, args_count);
    for (int i = 0; i < args_count; i++) {
      Handle<Object> val = Handle<Object>(frame->GetParameter(i), isolate);
      param_data[i] = val;
    }
    return param_data;
  }
}

template <typename T>
Handle<JSObject> NewSloppyArguments(Isolate* isolate, Handle<JSFunction> callee,
                                    T parameters, int argument_count) {
  CHECK(!IsDerivedConstructor(callee->shared()->kind()));
  DCHECK(callee->shared()->has_simple_parameters());
  Handle<JSObject> result =
      isolate->factory()->NewArgumentsObject(callee, argument_count);

  // Allocate the elements if needed.
  int parameter_count =
      callee->shared()->internal_formal_parameter_count_without_receiver();
  if (argument_count > 0) {
    if (parameter_count > 0) {
      int mapped_count = std::min(argument_count, parameter_count);

      // Store the context and the arguments array at the beginning of the
      // parameter map.
      DirectHandle<Context> context(isolate->context(), isolate);
      DirectHandle<FixedArray> arguments = isolate->factory()->NewFixedArray(
          argument_count, AllocationType::kYoung);

      DirectHandle<SloppyArgumentsElements> parameter_map =
          isolate->factory()->NewSloppyArgumentsElements(
              mapped_count, context, arguments, AllocationType::kYoung);

      result->set_map(isolate,
                      isolate->native_context()->fast_aliased_arguments_map());
      result->set_elements(*parameter_map);

      // Loop over the actual parameters backwards.
      int index = argument_count - 1;
      while (index >= mapped_count) {
        // These go directly in the arguments array and have no
        // corresponding slot in the parameter map.
        arguments->set(index, parameters[index]);
        --index;
      }

      DirectHandle<ScopeInfo> scope_info(callee->shared()->scope_info(),
                                         isolate);

      // First mark all mappable slots as unmapped and copy the values into the
      // arguments object.
      for (int i = 0; i < mapped_count; i++) {
        arguments->set(i, parameters[i]);
        parameter_map->set_mapped_entries(
            i, *isolate->factory()->the_hole_value());
      }

      // Walk all context slots to find context allocated parameters. Mark each
      // found parameter as mapped.
      ReadOnlyRoots roots{isolate};
      for (int i = 0; i < scope_info->ContextLocalCount(); i++) {
        if (!scope_info->ContextLocalIsParameter(i)) continue;
        int parameter = scope_info->ContextLocalParameterNumber(i);
        if (parameter >= mapped_count) continue;
        arguments->set_the_hole(roots, parameter);
        Tagged<Smi> slot = Smi::FromInt(scope_info->ContextHeaderLength() + i);
        parameter_map->set_mapped_entries(parameter, slot);
      }
    } else {
      // If there is no aliasing, the arguments object elements are not
      // special in any way.
      DirectHandle<FixedArray> elements = isolate->factory()->NewFixedArray(
          argument_count, AllocationType::kYoung);
      result->set_elements(*elements);
      for (int i = 0; i < argument_count; ++i) {
        elements->set(i, parameters[i]);
      }
    }
  }
  return result;
}

class HandleArguments {
 public:
  // If direct handles are enabled, it is the responsibility of the caller to
  // ensure that the memory pointed to by `array` is scanned during CSS, e.g.,
  // it comes from a `DirectHandleVector<Object>`.
  explicit HandleArguments(base::Vector<const DirectHandle<Object>> array)
      : array_(array) {}
  Tagged<Object> operator[](int index) { return *array_[index]; }

 private:
  base::Vector<const DirectHandle<Object>> array_;
};

class ParameterArguments {
 public:
  explicit ParameterArguments(Address parameters) : parameters_(parameters) {}
  Tagged<Object> operator[](int index) {
    return *FullObjectSlot(parameters_ - (index + 1) * kSystemPointerSize);
  }

 private:
  Address parameters_;
};

}  // namespace

RUNTIME_FUNCTION(Runtime_NewSloppyArguments) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  Handle<JSFunction> callee = args.at<JSFunction>(0);
  // This generic runtime function can also be used when the caller has been
  // inlined, we use the slow but accurate {GetCallerArguments}.
  auto arguments = GetCallerArguments(isolate);
  HandleArguments argument_getter({arguments.data(), arguments.size()});
  return *NewSloppyArguments(isolate, callee, argument_getter,
                             static_cast<int>(arguments.size()));
}

RUNTIME_FUNCTION(Runtime_NewStrictArguments) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  Handle<JSFunction> callee = args.at<JSFunction>(0);
  // This generic runtime function can also be used when the caller has been
  // inlined, we use the slow but accurate {GetCallerArguments}.
  auto arguments = GetCallerArguments(isolate);
  int argument_count = static_cast<int>(arguments.size());
  DirectHandle<JSObject> result =
      isolate->factory()->NewArgumentsObject(callee, argument_count);
  if (argument_count) {
    DirectHandle<FixedArray> array =
        isolate->factory()->NewFixedArray(argument_count);
    DisallowGarbageCollection no_gc;
    WriteBarrierMode mode = array->GetWriteBarrierMode(no_gc);
    for (int i = 0; i < argument_count; i++) {
      array->set(i, *arguments[i], mode);
    }
    result->set_elements(*array);
  }
  return *result;
}

RUNTIME_FUNCTION(Runtime_NewRestParameter) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  DirectHandle<JSFunction> callee = args.at<JSFunction>(0);
  int start_index =
      callee->shared()->internal_formal_parameter_count_without_receiver();
  // This generic runtime function can also be used when the caller has been
  // inlined, we use the slow but accurate {GetCallerArguments}.
  auto arguments = GetCallerArguments(isolate);
  int argument_count = static_cast<int>(arguments.size());
  int num_elements = std::max(0, argument_count - start_index);
  DirectHandle<JSObject> result = isolate->factory()->NewJSArray(
      PACKED_ELEMENTS, num_elements, num_elements,
      ArrayStorageAllocationMode::DONT_INITIALIZE_ARRAY_ELEMENTS);
  if (num_elements == 0) return *result;
  {
    DisallowGarbageCollection no_gc;
    Tagged<FixedArray> elements = Cast<FixedArray>(result->elements());
    WriteBarrierMode mode = elements->GetWriteBarrierMode(no_gc);
    for (int i = 0; i < num_elements; i++) {
      elements->set(i, *arguments[i + start_index], mode);
    }
  }
  return *result;
}

RUNTIME_FUNCTION(Runtime_NewClosure) {
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());
  Handle<SharedFunctionInfo> shared = args.at<SharedFunctionInfo>(0);
  Handle<FeedbackCell> feedback_cell = args.at<FeedbackCell>(1);
  Handle<Context> context(isolate->context(), isolate);
  return *Factory::JSFunctionBuilder{isolate, shared, context}
              .set_feedback_cell(feedback_cell)
              .set_allocation_type(AllocationType::kYoung)
              .Build();
}

RUNTIME_FUNCTION(Runtime_NewClosure_Tenured) {
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());
  Handle<SharedFunctionInfo> shared = args.at<SharedFunctionInfo>(0);
  Handle<FeedbackCell> feedback_cell = args.at<FeedbackCell>(1);
  Handle<Context> context(isolate->context(), isolate);
  // The caller ensures that we pretenure closures that are assigned
  // directly to properties.
  return *Factory::JSFunctionBuilder{isolate, shared, context}
              .set_feedback_cell(feedback_cell)
              .set_allocation_type(AllocationType::kOld)
              .Build();
}

RUNTIME_FUNCTION(Runtime_NewFunctionContext) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());

  DirectHandle<ScopeInfo> scope_info = args.at<ScopeInfo>(0);

  DirectHandle<Context> outer(isolate->context(), isolate);
  return *isolate->factory()->NewFunctionContext(outer, scope_info);
}

// TODO(jgruber): Rename these functions to 'New...Context'.
RUNTIME_FUNCTION(Runtime_PushWithContext) {
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());
  DirectHandle<JSReceiver> extension_object = args.at<JSReceiver>(0);
  DirectHandle<ScopeInfo> scope_info = args.at<ScopeInfo>(1);
  DirectHandle<Context> current(isolate->context(), isolate);
  return *isolate->factory()->NewWithContext(current, scope_info,
                                             extension_object);
}

// TODO(jgruber): Rename these functions to 'New...Context'.
RUNTIME_FUNCTION(Runtime_PushCatchContext) {
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());
  DirectHandle<Object> thrown_object = args.at(0);
  DirectHandle<ScopeInfo> scope_info = args.at<ScopeInfo>(1);
  DirectHandle<Context> current(isolate->context(), isolate);
  return *isolate->factory()->NewCatchContext(current, scope_info,
                                              thrown_object);
}

// TODO(jgruber): Rename these functions to 'New...Context'.
RUNTIME_FUNCTION(Runtime_PushBlockContext) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  DirectHandle<ScopeInfo> scope_info = args.at<ScopeInfo>(0);
  DirectHandle<Context> current(isolate->context(), isolate);
  return *isolate->factory()->NewBlockContext(current, scope_info);
}


RUNTIME_FUNCTION(Runtime_DeleteLookupSlot) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  Handle<String> name = args.at<String>(0);

  int index;
  PropertyAttributes attributes;
  InitializationFlag flag;
  VariableMode mode;
  Handle<Context> context(isolate->context(), isolate);
  Handle<Object> holder = Context::Lookup(context, name, FOLLOW_CHAINS, &index,
                                          &attributes, &flag, &mode);

  // If the slot was not found the result is true.
  if (holder.is_null()) {
    // In case of JSProxy, an exception might have been thrown.
    if (isolate->has_exception()) return ReadOnlyRoots(isolate).exception();
    return ReadOnlyRoots(isolate).true_value();
  }

  // If the slot was found in a context or in module imports and exports it
  // should be DONT_DELETE.
  if (IsContext(*holder) || IsSourceTextModule(*holder)) {
    return ReadOnlyRoots(isolate).false_value();
  }

  // The slot was found in a JSReceiver, either a context extension object,
  // the global object, or the subject of a with.  Try to delete it
  // (respecting DONT_DELETE).
  Handle<JSReceiver> object = Cast<JSReceiver>(holder);
  Maybe<bool> result = JSReceiver::DeleteProperty(isolate, object, name);
  MAYBE_RETURN(result, ReadOnlyRoots(isolate).exception());
  return isolate->heap()->ToBoolean(result.FromJust());
}


namespace {

MaybeHandle<Object> LoadLookupSlot(Isolate* isolate, Handle<String> name,
                                   ShouldThrow should_throw,
                                   Handle<Object>* receiver_return = nullptr) {
  int index;
  PropertyAttributes attributes;
  InitializationFlag flag;
  VariableMode mode;
  Handle<Context> context(isolate->context(), isolate);
  Handle<Object> holder = Context::Lookup(context, name, FOLLOW_CHAINS, &index,
                                          &attributes, &flag, &mode);
  if (isolate->has_exception()) return MaybeHandle<Object>();

  if (!holder.is_null() && IsSourceTextModule(*holder)) {
    Handle<Object> receiver = isolate->factory()->undefined_value();
    if (receiver_return) *receiver_return = receiver;
    return SourceTextModule::LoadVariable(
        isolate, Cast<SourceTextModule>(holder), index);
  }
  if (index != Context::kNotFound) {
    DCHECK(IsContext(*holder));
    Handle<Context> holder_context = Cast<Context>(holder);
    // If the "property" we were looking for is a local variable, the
    // receiver is the global object; see ECMA-262, 3rd., 10.1.6 and 10.2.3.
    Handle<Object> receiver = isolate->factory()->undefined_value();
    Handle<Object> value = handle(holder_context->get(index), isolate);
    // Check for uninitialized bindings.
    if (flag == kNeedsInitialization && IsTheHole(*value, isolate)) {
      THROW_NEW_ERROR(isolate,
                      NewReferenceError(MessageTemplate::kNotDefined, name));
    }
    DCHECK(!IsTheHole(*value, isolate));
    if (receiver_return) *receiver_return = receiver;
    if (v8_flags.script_context_mutable_heap_number &&
        holder_context->IsScriptContext()) {
      return handle(*Context::LoadScriptContextElement(holder_context, index,
                                                       value, isolate),
                    isolate);
    }
    return value;
  }

  // Otherwise, if the slot was found the holder is a context extension
  // object, subject of a with, or a global object.  We read the named
  // property from it.
  if (!holder.is_null()) {
    // No need to unhole the value here.  This is taken care of by the
    // GetProperty function.
    Handle<Object> value;
    ASSIGN_RET
```