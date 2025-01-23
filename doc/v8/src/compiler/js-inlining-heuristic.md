Response: Let's break down the thought process for analyzing this C++ code and summarizing its functionality in relation to JavaScript inlining.

**1. Initial Understanding of the File Path and Namespace:**

* The path `v8/src/compiler/js-inlining-heuristic.cc` immediately tells us this file is part of the V8 JavaScript engine's compiler and deals with *inlining*, specifically as a *heuristic*. This means it's about making smart guesses about which function calls are good candidates for inlining.
* The namespaces `v8::internal::compiler` further confirm this context.

**2. Identifying Key Data Structures and Classes:**

* **`JSInliningHeuristic`:** This is clearly the central class. It's responsible for the overall logic of deciding what to inline.
* **`Candidate`:**  This struct represents a potential function call site for inlining. It holds information about the call site (the `Node`), the function(s) being called, their bytecode, and other relevant details.
* **`JSHeapBroker`:**  This is a crucial V8 component that provides access to JavaScript heap objects (functions, bytecode arrays, etc.) in a compiler-friendly way.
* **`FeedbackCellRef`, `FeedbackVectorRef`, `SharedFunctionInfoRef`, `BytecodeArrayRef`, `JSFunctionRef`:** These are references to V8 internal objects that hold metadata about functions and their execution. The presence of "Feedback" strongly suggests that runtime performance data influences inlining decisions.
* **`Node`:** This likely refers to nodes in the compiler's intermediate representation (IR) graph. Inlining involves manipulating this graph.
* **`Reduction`:** This return type suggests that the `Reduce` method modifies the IR graph.

**3. Analyzing the `Reduce` Method (Core Logic):**

* The `Reduce` method is the primary entry point for the heuristic during the compiler's optimization pipeline. It's called on individual nodes in the IR graph.
* **Filtering:** The first checks (`IsInlineeOpcode`, `total_inlined_bytecode_size_`, `seen_`) indicate that the heuristic avoids inlining non-callable nodes, respects a budget, and prevents redundant processing.
* **`CollectFunctions`:** This method identifies the function(s) being called at the current node. It handles different call scenarios (direct calls, calls through phis, closure creations).
* **`CanConsiderForInlining`:** This function performs checks to see if a function *can* be inlined (has bytecode, is marked as inlineable, etc.). Feedback data is consulted here.
* **Polymorphism:** The code considers polymorphic calls (calls to multiple different functions at the same call site) and respects a flag (`v8_flags.polymorphic_inlining`).
* **Recursion Check:** It avoids direct recursive inlining.
* **Size Check (`IsSmall`):** Small functions are prioritized for immediate inlining.
* **Frequency Check (`candidate.frequency`):**  Inlining decisions are influenced by how often a call site is executed.
* **Candidate Storage (`candidates_`):**  If a call site isn't immediately inlined, it's added to a list of potential candidates for later consideration.

**4. Analyzing the `Finalize` Method:**

* This method is called after the main `Reduce` phase.
* It iterates through the collected `candidates_`.
* It checks if the candidates are still valid and if there's enough inlining budget remaining.
* It calls `InlineCandidate` to perform the actual inlining.

**5. Analyzing the `InlineCandidate` Method:**

* This method performs the actual graph transformations for inlining.
* **Monomorphic vs. Polymorphic Inlining:** It handles both cases. For polymorphic calls, it might generate a dispatch structure.
* **Dispatch Logic (`CreateOrReuseDispatch`, `TryReuseDispatch`):**  This is interesting. It deals with how to handle calls where the target function might vary at runtime. It tries to reuse existing dispatch logic or creates new branches in the control flow.
* **Graph Manipulation:**  It uses methods like `graph()->NewNode`, `ReplaceWithValue`, `ReplaceInput`, `Kill` to modify the IR graph.

**6. Connecting to JavaScript:**

* **Concept of Functions:**  Inlining is a core optimization for function calls in JavaScript.
* **Bytecode:** The code explicitly deals with JavaScript bytecode, which is the intermediate representation of JavaScript code executed by V8's interpreter.
* **Performance Feedback:**  The use of `FeedbackCell`, `FeedbackVector` directly links to V8's runtime feedback collection mechanism. The engine observes how code executes and uses this information to guide optimizations like inlining.
* **Polymorphism:**  JavaScript's dynamic nature leads to polymorphic calls. The code's handling of this is crucial.
* **Recursion:** The decision to avoid direct recursion inlining is a deliberate choice related to potential performance trade-offs.

**7. Constructing the JavaScript Examples:**

The goal here is to illustrate the *effects* of the inlining heuristic from a JavaScript developer's perspective, *without* needing to understand the C++ implementation details deeply.

* **Small Function Example:**  Show a very simple function that would likely be considered "small" and thus a prime candidate for inlining.
* **Polymorphic Call Example:** Demonstrate a scenario where a function might be called with different types of arguments, leading to different underlying function calls. This highlights the heuristic's need to handle polymorphism.
* **Frequency/Hot Code Example:** Illustrate how calling a function repeatedly makes it a better candidate for inlining.

**Self-Correction/Refinement During Analysis:**

* **Initial Focus on `Reduce`:**  Realizing that `Reduce` is the main driver of the heuristic.
* **Understanding `Candidate`:** Recognizing that this structure holds key information for inlining decisions.
* **Importance of Feedback:**  Noting the recurring mentions of "Feedback" and connecting it to runtime performance data.
* **Polymorphic Dispatch:**  Paying attention to the logic for handling calls with multiple potential targets.
* **JavaScript Abstraction:**  Focusing the JavaScript examples on observable behavior rather than internal implementation details.

By following this structured analysis, we can effectively understand the functionality of the C++ code and its relationship to JavaScript performance.
This C++ source code file, `js-inlining-heuristic.cc`, is a crucial part of the V8 JavaScript engine's **TurboFan optimizing compiler**. Its primary function is to **determine which JavaScript function calls are good candidates for inlining**.

Inlining is a compiler optimization technique where the code of a called function is directly inserted into the caller function's code. This can improve performance by:

* **Reducing function call overhead:**  Eliminating the cost of setting up and tearing down the call stack.
* **Enabling further optimizations:**  After inlining, the compiler has a larger block of code to analyze and optimize.

Here's a breakdown of the key functionalities:

**1. Candidate Selection:**

* **`CollectFunctions(Node* node, int functions_size)`:** This method analyzes a given node in the compiler's intermediate representation graph (likely representing a function call). It tries to identify the function being called. It handles different call scenarios, including:
    * Direct function calls.
    * Calls through `Phi` nodes (used in control flow merges where the called function might vary).
    * Calls to closures (functions that capture their surrounding scope).
* **`CanConsiderForInlining(JSHeapBroker* broker, ...)`:** This set of overloaded functions performs checks to determine if a function is a *viable* candidate for inlining. These checks include:
    * **Availability of Bytecode:** The function must have bytecode available for inlining.
    * **Inlineability:** The function's metadata (stored in `SharedFunctionInfo`) must indicate that it's generally inlineable.
    * **Feedback Vector:** The presence and stability of the function's feedback vector. The feedback vector stores runtime information about how the function is used (e.g., argument types), which helps the compiler make informed inlining decisions.
    * **Recursion Check:**  It avoids directly inlining recursive calls to prevent excessive code growth.

**2. Inlining Heuristic Logic (`Reduce(Node* node)`):**

* The `Reduce` method is the core of the heuristic. It's called by the compiler to process each node in the graph.
* **Budgeting:** It keeps track of the total amount of bytecode that has been inlined (`total_inlined_bytecode_size_`) and respects limits (`max_inlined_bytecode_size_absolute_`, `max_inlined_bytecode_size_cumulative_`) to prevent excessive code growth.
* **Frequency Analysis:** It considers the execution frequency of the call site (`candidate.frequency`). Frequently called functions are generally better candidates for inlining.
* **Size Considerations:** It prioritizes inlining small functions (`IsSmall`).
* **Polymorphism Handling:** It can handle polymorphic call sites (where the same call site might invoke different functions). There are flags to control polymorphic inlining (`v8_flags.polymorphic_inlining`).
* **Candidate Storage:**  If a function isn't immediately inlined, it might be added to a set of potential candidates (`candidates_`) for later consideration.

**3. Performing Inlining (`InlineCandidate(Candidate const& candidate, bool small_function)`):**

* This method takes a selected candidate and performs the actual inlining operation.
* **Graph Transformation:** It manipulates the compiler's intermediate representation graph to insert the inlined code.
* **Handling Polymorphism:** If it's a polymorphic call, it might generate code to dispatch to the correct inlined function based on runtime conditions.

**4. Finalization (`Finalize()`):**

* After the main optimization passes, this method processes any remaining inlining candidates.

**Relationship to JavaScript and Examples:**

This code directly impacts the performance of JavaScript code. The decisions made by this heuristic determine which function calls are inlined, which can significantly affect execution speed.

Here are some JavaScript examples to illustrate how this heuristic might work:

**Example 1: Small Function Inlining**

```javascript
function add(a, b) {
  return a + b;
}

function calculate(x) {
  const result = add(x, 5); // Potential inlining opportunity
  return result * 2;
}

console.log(calculate(10));
```

In this case, the `add` function is small and likely to be inlined into the `calculate` function. The compiler might transform the `calculate` function conceptually (not literally in the source code) to something like:

```javascript
function calculate(x) {
  const result = x + 5; // 'add' function inlined
  return result * 2;
}
```

**Example 2: Hot Function Inlining**

```javascript
function processItem(item) {
  // ... some complex logic ...
  return item.value * 2;
}

function mainLoop(items) {
  for (let i = 0; i < items.length; i++) {
    const processed = processItem(items[i]); // Potential inlining if 'processItem' is called frequently
    console.log(processed);
  }
}

const data = [{ value: 1 }, { value: 2 }, { value: 3 }];
mainLoop(data); // 'processItem' is called multiple times
```

If `processItem` is called frequently within `mainLoop`, the inlining heuristic might decide to inline it to avoid the overhead of repeated function calls.

**Example 3: Polymorphic Call and Heuristic Decisions**

```javascript
function process(input) {
  return input.getValue();
}

const obj1 = { getValue: () => 10 };
const obj2 = { getValue: () => "hello" };

console.log(process(obj1)); // Calls obj1.getValue()
console.log(process(obj2)); // Calls obj2.getValue()
```

Here, the `process` function makes a polymorphic call to `getValue`. The inlining heuristic might:

* **Not inline initially:** If the compiler doesn't have enough information about the types of `input`.
* **Inline speculatively:** If feedback suggests that most calls are to a specific type (e.g., objects like `obj1`), it might inline the code for that specific case and have a fallback mechanism for other types.
* **Create a dispatch:**  If the polymorphism is common, it might create a small dispatch mechanism within `process` to call the appropriate `getValue` implementation.

**In summary, `js-inlining-heuristic.cc` is responsible for making intelligent decisions about when and how to inline JavaScript function calls within the TurboFan compiler. It considers factors like function size, call frequency, runtime feedback, and polymorphism to optimize JavaScript code for better performance.**

### 提示词
```
这是目录为v8/src/compiler/js-inlining-heuristic.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/js-inlining-heuristic.h"

#include "src/compiler/common-operator.h"
#include "src/compiler/compiler-source-position-table.h"
#include "src/compiler/js-heap-broker.h"
#include "src/compiler/node-matchers.h"
#include "src/compiler/simplified-operator.h"

namespace v8 {
namespace internal {
namespace compiler {

#define TRACE(...)                                \
  do {                                            \
    if (v8_flags.trace_turbo_inlining)            \
      StdoutStream{} << __VA_ARGS__ << std::endl; \
  } while (false)

namespace {
bool IsSmall(int const size) {
  return size <= v8_flags.max_inlined_bytecode_size_small;
}

bool CanConsiderForInlining(JSHeapBroker* broker,
                            FeedbackCellRef feedback_cell) {
  OptionalFeedbackVectorRef feedback_vector =
      feedback_cell.feedback_vector(broker);
  if (!feedback_vector.has_value()) {
    TRACE("Cannot consider " << feedback_cell
                             << " for inlining (no feedback vector)");
    return false;
  }
  SharedFunctionInfoRef shared = feedback_vector->shared_function_info(broker);

  if (!shared.HasBytecodeArray()) {
    TRACE("Cannot consider " << shared << " for inlining (no bytecode)");
    return false;
  }
  // Ensure we have a persistent handle to the bytecode in order to avoid
  // flushing it during the remaining compilation.
  shared.GetBytecodeArray(broker);

  // Read feedback vector again in case it got flushed before we were able to
  // prevent flushing above.
  OptionalFeedbackVectorRef feedback_vector_again =
      feedback_cell.feedback_vector(broker);
  if (!feedback_vector_again.has_value()) {
    TRACE("Cannot consider " << shared << " for inlining (no feedback vector)");
    return false;
  }
  if (!feedback_vector_again->equals(*feedback_vector)) {
    // The new feedback vector likely contains lots of uninitialized slots, so
    // it doesn't make much sense to inline this function now.
    TRACE("Not considering " << shared
                             << " for inlining (feedback vector changed)");
    return false;
  }

  SharedFunctionInfo::Inlineability inlineability =
      shared.GetInlineability(broker);
  if (inlineability != SharedFunctionInfo::kIsInlineable) {
    TRACE("Cannot consider "
          << shared << " for inlining (reason: " << inlineability << ")");
    return false;
  }

  TRACE("Considering " << shared << " for inlining with " << *feedback_vector);
  return true;
}

bool CanConsiderForInlining(JSHeapBroker* broker, JSFunctionRef function) {
  FeedbackCellRef feedback_cell = function.raw_feedback_cell(broker);
  bool const result = CanConsiderForInlining(broker, feedback_cell);
  if (result) {
    CHECK(function.shared(broker).equals(
        feedback_cell.shared_function_info(broker).value()));
  }
  return result;
}

}  // namespace

JSInliningHeuristic::Candidate JSInliningHeuristic::CollectFunctions(
    Node* node, int functions_size) {
  DCHECK_NE(0, functions_size);
  Node* callee = node->InputAt(0);
  Candidate out;
  out.node = node;

  HeapObjectMatcher m(callee);
  if (m.HasResolvedValue() && m.Ref(broker()).IsJSFunction()) {
    JSFunctionRef function = m.Ref(broker()).AsJSFunction();
    out.functions[0] = function;
    if (CanConsiderForInlining(broker(), function)) {
      out.bytecode[0] = function.shared(broker()).GetBytecodeArray(broker());
      out.num_functions = 1;
      return out;
    }
  }
  if (m.IsPhi()) {
    int const value_input_count = m.node()->op()->ValueInputCount();
    if (value_input_count > functions_size) {
      out.num_functions = 0;
      return out;
    }
    for (int n = 0; n < value_input_count; ++n) {
      HeapObjectMatcher m2(callee->InputAt(n));
      if (!m2.HasResolvedValue() || !m2.Ref(broker()).IsJSFunction()) {
        out.num_functions = 0;
        return out;
      }

      out.functions[n] = m2.Ref(broker()).AsJSFunction();
      JSFunctionRef function = out.functions[n].value();
      if (CanConsiderForInlining(broker(), function)) {
        out.bytecode[n] = function.shared(broker()).GetBytecodeArray(broker());
      }
    }
    out.num_functions = value_input_count;
    return out;
  }
  if (m.IsCheckClosure()) {
    DCHECK(!out.functions[0].has_value());
    FeedbackCellRef feedback_cell = MakeRef(broker(), FeedbackCellOf(m.op()));
    if (CanConsiderForInlining(broker(), feedback_cell)) {
      out.shared_info = feedback_cell.shared_function_info(broker()).value();
      out.bytecode[0] = out.shared_info->GetBytecodeArray(broker());
    }
    out.num_functions = 1;
    return out;
  }
  if (m.IsJSCreateClosure()) {
    DCHECK(!out.functions[0].has_value());
    JSCreateClosureNode n(callee);
    FeedbackCellRef feedback_cell = n.GetFeedbackCellRefChecked(broker());
    if (CanConsiderForInlining(broker(), feedback_cell)) {
      out.shared_info = feedback_cell.shared_function_info(broker()).value();
      out.bytecode[0] = out.shared_info->GetBytecodeArray(broker());
      CHECK(out.shared_info->equals(n.Parameters().shared_info()));
    }
    out.num_functions = 1;
    return out;
  }
  out.num_functions = 0;
  return out;
}

Reduction JSInliningHeuristic::Reduce(Node* node) {
#if V8_ENABLE_WEBASSEMBLY
  if (mode() == kWasmWrappersOnly || mode() == kWasmFullInlining) {
    if (node->opcode() == IrOpcode::kJSWasmCall) {
      return inliner_.ReduceJSWasmCall(node);
    }
    return NoChange();
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  DCHECK_EQ(mode(), kJSOnly);
  if (!IrOpcode::IsInlineeOpcode(node->opcode())) return NoChange();

  if (total_inlined_bytecode_size_ >= max_inlined_bytecode_size_absolute_) {
    return NoChange();
  }

  // Check if we already saw that {node} before, and if so, just skip it.
  if (seen_.find(node->id()) != seen_.end()) return NoChange();

  // Check if the {node} is an appropriate candidate for inlining.
  Candidate candidate = CollectFunctions(node, kMaxCallPolymorphism);
  if (candidate.num_functions == 0) {
    return NoChange();
  } else if (candidate.num_functions > 1 && !v8_flags.polymorphic_inlining) {
    TRACE("Not considering call site #"
          << node->id() << ":" << node->op()->mnemonic()
          << ", because polymorphic inlining is disabled");
    return NoChange();
  }

  bool can_inline_candidate = false, candidate_is_small = true;
  candidate.total_size = 0;
  FrameState frame_state{NodeProperties::GetFrameStateInput(node)};
  FrameStateInfo const& frame_info = frame_state.frame_state_info();
  Handle<SharedFunctionInfo> frame_shared_info;
  for (int i = 0; i < candidate.num_functions; ++i) {
    if (!candidate.bytecode[i].has_value()) {
      candidate.can_inline_function[i] = false;
      continue;
    }

    SharedFunctionInfoRef shared =
        candidate.functions[i].has_value()
            ? candidate.functions[i].value().shared(broker())
            : candidate.shared_info.value();
    candidate.can_inline_function[i] = candidate.bytecode[i].has_value();
    // Because of concurrent optimization, optimization of the inlining
    // candidate could have been disabled meanwhile.
    // JSInliner will check this again and not actually inline the function in
    // this case.
    CHECK_IMPLIES(candidate.can_inline_function[i],
                  shared.IsInlineable(broker()) ||
                      shared.GetInlineability(broker()) ==
                          SharedFunctionInfo::kHasOptimizationDisabled);
    // Do not allow direct recursion i.e. f() -> f(). We still allow indirect
    // recursion like f() -> g() -> f(). The indirect recursion is helpful in
    // cases where f() is a small dispatch function that calls the appropriate
    // function. In the case of direct recursion, we only have some static
    // information for the first level of inlining and it may not be that useful
    // to just inline one level in recursive calls. In some cases like tail
    // recursion we may benefit from recursive inlining, if we have additional
    // analysis that converts them to iterative implementations. Though it is
    // not obvious if such an analysis is needed.
    if (frame_info.shared_info().ToHandle(&frame_shared_info) &&
        frame_shared_info.equals(shared.object())) {
      TRACE("Not considering call site #" << node->id() << ":"
                                          << node->op()->mnemonic()
                                          << ", because of recursive inlining");
      candidate.can_inline_function[i] = false;
    }
    if (candidate.can_inline_function[i]) {
      can_inline_candidate = true;
      BytecodeArrayRef bytecode = candidate.bytecode[i].value();
      candidate.total_size += bytecode.length();
      unsigned inlined_bytecode_size = 0;
      if (OptionalJSFunctionRef function = candidate.functions[i]) {
        if (OptionalCodeRef code = function->code(broker())) {
          inlined_bytecode_size = code->GetInlinedBytecodeSize();
          candidate.total_size += inlined_bytecode_size;
        }
      }
      candidate_is_small = candidate_is_small &&
                           IsSmall(bytecode.length() + inlined_bytecode_size);
    }
  }
  if (!can_inline_candidate) return NoChange();

  // Gather feedback on how often this call site has been hit before.
  if (node->opcode() == IrOpcode::kJSCall) {
    CallParameters const p = CallParametersOf(node->op());
    candidate.frequency = p.frequency();
  } else {
    ConstructParameters const p = ConstructParametersOf(node->op());
    candidate.frequency = p.frequency();
  }

  // Don't consider a {candidate} whose frequency is below the
  // threshold, i.e. a call site that is only hit once every N
  // invocations of the caller.
  if (candidate.frequency.IsKnown() &&
      candidate.frequency.value() < v8_flags.min_inlining_frequency) {
    return NoChange();
  }

  // Found a candidate. Insert it into the set of seen nodes s.t. we don't
  // revisit in the future. Note this insertion happens here and not earlier in
  // order to make inlining decisions order-independent. A node may not be a
  // candidate when first seen, but later reductions may turn it into a valid
  // candidate. In that case, the node should be revisited by
  // JSInliningHeuristic.
  seen_.insert(node->id());

  // Forcibly inline small functions here. In the case of polymorphic inlining
  // candidate_is_small is set only when all functions are small.
  if (candidate_is_small) {
    TRACE("Inlining small function(s) at call site #"
          << node->id() << ":" << node->op()->mnemonic());
    return InlineCandidate(candidate, true);
  }

  // In the general case we remember the candidate for later.
  candidates_.insert(candidate);
  return NoChange();
}

void JSInliningHeuristic::Finalize() {
  if (candidates_.empty()) return;  // Nothing to do without candidates.
  if (v8_flags.trace_turbo_inlining) PrintCandidates();

  // We inline at most one candidate in every iteration of the fixpoint.
  // This is to ensure that we don't consume the full inlining budget
  // on things that aren't called very often.
  // TODO(bmeurer): Use std::priority_queue instead of std::set here.
  while (!candidates_.empty()) {
    auto i = candidates_.begin();
    Candidate candidate = *i;
    candidates_.erase(i);

    // Ignore this candidate if it's no longer valid.
    if (!IrOpcode::IsInlineeOpcode(candidate.node->opcode())) continue;
    if (candidate.node->IsDead()) continue;

    // Make sure we have some extra budget left, so that any small functions
    // exposed by this function would be given a chance to inline.
    double size_of_candidate =
        candidate.total_size * v8_flags.reserve_inline_budget_scale_factor;
    int total_size =
        total_inlined_bytecode_size_ + static_cast<int>(size_of_candidate);
    if (total_size > max_inlined_bytecode_size_cumulative_) {
      info_->set_could_not_inline_all_candidates();
      // Try if any smaller functions are available to inline.
      continue;
    }

    Reduction const reduction = InlineCandidate(candidate, false);
    if (reduction.Changed()) return;
  }
}

namespace {

struct NodeAndIndex {
  Node* node;
  int index;
};

bool CollectStateValuesOwnedUses(Node* node, Node* state_values,
                                 NodeAndIndex* uses_buffer, size_t* use_count,
                                 size_t max_uses) {
  // Only accumulate states that are not shared with other users.
  if (state_values->UseCount() > 1) return true;
  for (int i = 0; i < state_values->InputCount(); i++) {
    Node* input = state_values->InputAt(i);
    if (input->opcode() == IrOpcode::kStateValues) {
      if (!CollectStateValuesOwnedUses(node, input, uses_buffer, use_count,
                                       max_uses)) {
        return false;
      }
    } else if (input == node) {
      if (*use_count >= max_uses) return false;
      uses_buffer[*use_count] = {state_values, i};
      (*use_count)++;
    }
  }
  return true;
}

}  // namespace

Node* JSInliningHeuristic::DuplicateStateValuesAndRename(Node* state_values,
                                                         Node* from, Node* to,
                                                         StateCloneMode mode) {
  // Only rename in states that are not shared with other users. This needs to
  // be in sync with the condition in {CollectStateValuesOwnedUses}.
  if (state_values->UseCount() > 1) return state_values;
  Node* copy = mode == kChangeInPlace ? state_values : nullptr;
  for (int i = 0; i < state_values->InputCount(); i++) {
    Node* input = state_values->InputAt(i);
    Node* processed;
    if (input->opcode() == IrOpcode::kStateValues) {
      processed = DuplicateStateValuesAndRename(input, from, to, mode);
    } else if (input == from) {
      processed = to;
    } else {
      processed = input;
    }
    if (processed != input) {
      if (!copy) {
        copy = graph()->CloneNode(state_values);
      }
      copy->ReplaceInput(i, processed);
    }
  }
  return copy ? copy : state_values;
}

namespace {

bool CollectFrameStateUniqueUses(Node* node, FrameState frame_state,
                                 NodeAndIndex* uses_buffer, size_t* use_count,
                                 size_t max_uses) {
  // Only accumulate states that are not shared with other users.
  if (frame_state->UseCount() > 1) return true;
  if (frame_state.stack() == node) {
    if (*use_count >= max_uses) return false;
    uses_buffer[*use_count] = {frame_state, FrameState::kFrameStateStackInput};
    (*use_count)++;
  }
  if (!CollectStateValuesOwnedUses(node, frame_state.locals(), uses_buffer,
                                   use_count, max_uses)) {
    return false;
  }
  return true;
}

}  // namespace

FrameState JSInliningHeuristic::DuplicateFrameStateAndRename(
    FrameState frame_state, Node* from, Node* to, StateCloneMode mode) {
  // Only rename in states that are not shared with other users. This needs to
  // be in sync with the condition in {DuplicateFrameStateAndRename}.
  if (frame_state->UseCount() > 1) return frame_state;
  Node* copy =
      mode == kChangeInPlace ? static_cast<Node*>(frame_state) : nullptr;
  if (frame_state.stack() == from) {
    if (!copy) {
      copy = graph()->CloneNode(frame_state);
    }
    copy->ReplaceInput(FrameState::kFrameStateStackInput, to);
  }
  Node* locals = frame_state.locals();
  Node* new_locals = DuplicateStateValuesAndRename(locals, from, to, mode);
  if (new_locals != locals) {
    if (!copy) {
      copy = graph()->CloneNode(frame_state);
    }
    copy->ReplaceInput(FrameState::kFrameStateLocalsInput, new_locals);
  }
  return copy != nullptr ? FrameState{copy} : frame_state;
}

bool JSInliningHeuristic::TryReuseDispatch(Node* node, Node* callee,
                                           Node** if_successes, Node** calls,
                                           Node** inputs, int input_count,
                                           int* num_calls) {
  // We will try to reuse the control flow branch created for computing
  // the {callee} target of the call. We only reuse the branch if there
  // is no side-effect between the call and the branch, and if the callee is
  // only used as the target (and possibly also in the related frame states).

  // We are trying to match the following pattern:
  //
  //         C1     C2
  //          .     .
  //          |     |
  //         Merge(merge)  <-----------------+
  //           ^    ^                        |
  //  V1  V2   |    |         E1  E2         |
  //   .  .    |    +----+     .  .          |
  //   |  |    |         |     |  |          |
  //  Phi(callee)      EffectPhi(effect_phi) |
  //     ^                    ^              |
  //     |                    |              |
  //     +----+               |              |
  //     |    |               |              |
  //     |   StateValues      |              |
  //     |       ^            |              |
  //     +----+  |            |              |
  //     |    |  |            |              |
  //     |    FrameState      |              |
  //     |           ^        |              |
  //     |           |        |          +---+
  //     |           |        |          |   |
  //     +----+     Checkpoint(checkpoint)   |
  //     |    |           ^                  |
  //     |    StateValues |    +-------------+
  //     |        |       |    |
  //     +-----+  |       |    |
  //     |     |  |       |    |
  //     |     FrameState |    |
  //     |             ^  |    |
  //     +-----------+ |  |    |
  //                  Call(node)
  //                   |
  //                   |
  //                   .
  //
  // The {callee} here is a phi that merges the possible call targets, {node}
  // is the actual call that we will try to duplicate and connect to the
  // control that comes into {merge}. There can be a {checkpoint} between
  // the call and the calle phi.
  //
  // The idea is to get rid of the merge, effect phi and phi, then duplicate
  // the call (with all the frame states and such), and connect the duplicated
  // calls and states directly to the inputs of the ex-phi, ex-effect-phi and
  // ex-merge. The tricky part is to make sure that there is no interference
  // from the outside. In particular, there should not be any unaccounted uses
  // of the  phi, effect-phi and merge because we will remove them from
  // the graph.
  //
  //     V1              E1   C1  V2   E2               C2
  //     .                .    .  .    .                .
  //     |                |    |  |    |                |
  //     +----+           |    |  +----+                |
  //     |    |           |    |  |    |                |
  //     |   StateValues  |    |  |   StateValues       |
  //     |       ^        |    |  |       ^             |
  //     +----+  |        |    |  +----+  |             |
  //     |    |  |        |    |  |    |  |             |
  //     |    FrameState  |    |  |    FrameState       |
  //     |           ^    |    |  |           ^         |
  //     |           |    |    |  |           |         |
  //     |           |    |    |  |           |         |
  //     +----+     Checkpoint |  +----+     Checkpoint |
  //     |    |           ^    |  |    |           ^    |
  //     |    StateValues |    |  |    StateValues |    |
  //     |        |       |    |  |        |       |    |
  //     +-----+  |       |    |  +-----+  |       |    |
  //     |     |  |       |    |  |     |  |       |    |
  //     |     FrameState |    |  |     FrameState |    |
  //     |              ^ |    |  |              ^ |    |
  //     +-------------+| |    |  +-------------+| |    |
  //                   Call----+                Call----+
  //                     |                       |
  //                     +-------+  +------------+
  //                             |  |
  //                             Merge
  //                             EffectPhi
  //                             Phi
  //                              |
  //                             ...

  // Bailout if the call is not polymorphic anymore (other reducers might
  // have replaced the callee phi with a constant).
  if (callee->opcode() != IrOpcode::kPhi) return false;

  // If there is a control node between the callee computation
  // and the call, bail out.
  Node* merge = NodeProperties::GetControlInput(callee);
  if (NodeProperties::GetControlInput(node) != merge) return false;

  // If there is a non-checkpoint effect node between the callee computation
  // and the call, bail out. We will drop any checkpoint between the call and
  // the callee phi because the callee computation should have its own
  // checkpoint that the call can fall back to.
  Node* checkpoint = nullptr;
  Node* effect = NodeProperties::GetEffectInput(node);
  if (effect->opcode() == IrOpcode::kCheckpoint) {
    checkpoint = effect;
    if (NodeProperties::GetControlInput(checkpoint) != merge) return false;
    effect = NodeProperties::GetEffectInput(effect);
  }
  if (effect->opcode() != IrOpcode::kEffectPhi) return false;
  if (NodeProperties::GetControlInput(effect) != merge) return false;
  Node* effect_phi = effect;

  // The effect phi, the callee, the call and the checkpoint must be the only
  // users of the merge.
  for (Node* merge_use : merge->uses()) {
    if (merge_use != effect_phi && merge_use != callee && merge_use != node &&
        merge_use != checkpoint) {
      return false;
    }
  }

  // The effect phi must be only used by the checkpoint or the call.
  for (Node* effect_phi_use : effect_phi->uses()) {
    if (effect_phi_use != node && effect_phi_use != checkpoint) return false;
  }

  // We must replace the callee phi with the appropriate constant in
  // the entire subgraph reachable by inputs from the call (terminating
  // at phis and merges). Since we do not want to walk (and later duplicate)
  // the subgraph here, we limit the possible uses to this set:
  //
  // 1. In the call (as a target).
  // 2. The checkpoint between the call and the callee computation merge.
  // 3. The lazy deoptimization frame state.
  //
  // This corresponds to the most common pattern, where the function is
  // called with only local variables or constants as arguments.
  //
  // To check the uses, we first collect all the occurrences of callee in 1, 2
  // and 3, and then we check that all uses of callee are in the collected
  // occurrences. If there is an unaccounted use, we do not try to rewire
  // the control flow.
  //
  // Note: With CFG, this would be much easier and more robust - we would just
  // duplicate all the nodes between the merge and the call, replacing all
  // occurrences of the {callee} phi with the appropriate constant.

  // First compute the set of uses that are only reachable from 2 and 3.
  const size_t kMaxUses = 8;
  NodeAndIndex replaceable_uses[kMaxUses];
  size_t replaceable_uses_count = 0;

  // Collect the uses to check case 2.
  Node* checkpoint_state = nullptr;
  if (checkpoint) {
    checkpoint_state = checkpoint->InputAt(0);
    if (!CollectFrameStateUniqueUses(callee, FrameState{checkpoint_state},
                                     replaceable_uses, &replaceable_uses_count,
                                     kMaxUses)) {
      return false;
    }
  }

  // Collect the uses to check case 3.
  FrameState frame_state{NodeProperties::GetFrameStateInput(node)};
  if (!CollectFrameStateUniqueUses(callee, frame_state, replaceable_uses,
                                   &replaceable_uses_count, kMaxUses)) {
    return false;
  }

  // Bail out if there is a use of {callee} that is not reachable from 1, 2
  // and 3.
  for (Edge edge : callee->use_edges()) {
    // Case 1 (use by the call as a target).
    if (edge.from() == node && edge.index() == 0) continue;
    // Case 2 and 3 - used in checkpoint and/or lazy deopt frame states.
    bool found = false;
    for (size_t i = 0; i < replaceable_uses_count; i++) {
      if (replaceable_uses[i].node == edge.from() &&
          replaceable_uses[i].index == edge.index()) {
        found = true;
        break;
      }
    }
    if (!found) return false;
  }

  *num_calls = callee->op()->ValueInputCount();

  // Clone the call and the framestate, including the uniquely reachable
  // state values, making sure that we replace the phi with the constant.
  for (int i = 0; i < *num_calls; ++i) {
    // Clone the calls for each branch.
    // We need to specialize the calls to the correct target, effect, and
    // control. We also need to duplicate the checkpoint and the lazy
    // frame state, and change all the uses of the callee to the constant
    // callee.
    Node* target = callee->InputAt(i);
    Node* effect_phi_effect = effect_phi->InputAt(i);
    Node* control = merge->InputAt(i);

    if (checkpoint) {
      // Duplicate the checkpoint.
      FrameState new_checkpoint_state = DuplicateFrameStateAndRename(
          FrameState{checkpoint_state}, callee, target,
          (i == *num_calls - 1) ? kChangeInPlace : kCloneState);
      effect_phi_effect = graph()->NewNode(
          checkpoint->op(), new_checkpoint_state, effect_phi_effect, control);
    }

    // Duplicate the call.
    FrameState new_lazy_frame_state = DuplicateFrameStateAndRename(
        frame_state, callee, target,
        (i == *num_calls - 1) ? kChangeInPlace : kCloneState);
    inputs[0] = target;
    inputs[input_count - 3] = new_lazy_frame_state;
    inputs[input_count - 2] = effect_phi_effect;
    inputs[input_count - 1] = control;
    calls[i] = if_successes[i] =
        graph()->NewNode(node->op(), input_count, inputs);
  }

  // Mark the control inputs dead, so that we can kill the merge.
  node->ReplaceInput(input_count - 1, jsgraph()->Dead());
  callee->ReplaceInput(*num_calls, jsgraph()->Dead());
  effect_phi->ReplaceInput(*num_calls, jsgraph()->Dead());
  if (checkpoint) {
    checkpoint->ReplaceInput(2, jsgraph()->Dead());
  }

  merge->Kill();
  return true;
}

void JSInliningHeuristic::CreateOrReuseDispatch(
    Node* node, Node* callee, Candidate const& candidate, Node** if_successes,
    Node** calls, Node** inputs, int input_count, int* num_calls) {
  SourcePositionTable::Scope position(
      source_positions_, source_positions_->GetSourcePosition(node));
  if (TryReuseDispatch(node, callee, if_successes, calls, inputs, input_count,
                       num_calls)) {
    return;
  }

  static_assert(JSCallOrConstructNode::kHaveIdenticalLayouts);

  Node* fallthrough_control = NodeProperties::GetControlInput(node);
  *num_calls = candidate.num_functions;

  // Create the appropriate control flow to dispatch to the cloned calls.
  for (int i = 0; i < *num_calls; ++i) {
    // TODO(2206): Make comparison be based on underlying SharedFunctionInfo
    // instead of the target JSFunction reference directly.
    Node* target =
        jsgraph()->ConstantNoHole(candidate.functions[i].value(), broker());
    if (i != (*num_calls - 1)) {
      Node* check =
          graph()->NewNode(simplified()->ReferenceEqual(), callee, target);
      Node* branch =
          graph()->NewNode(common()->Branch(), check, fallthrough_control);
      fallthrough_control = graph()->NewNode(common()->IfFalse(), branch);
      if_successes[i] = graph()->NewNode(common()->IfTrue(), branch);
    } else {
      if_successes[i] = fallthrough_control;
    }

    // Clone the calls for each branch.
    // The first input to the call is the actual target (which we specialize
    // to the known {target}); the last input is the control dependency.
    // We also specialize the new.target of JSConstruct {node}s if it refers
    // to the same node as the {node}'s target input, so that we can later
    // properly inline the JSCreate operations.
    if (node->opcode() == IrOpcode::kJSConstruct) {
      // TODO(jgruber, v8:10675): This branch seems unreachable.
      JSConstructNode n(node);
      if (inputs[n.TargetIndex()] == inputs[n.NewTargetIndex()]) {
        inputs[n.NewTargetIndex()] = target;
      }
    }
    inputs[JSCallOrConstructNode::TargetIndex()] = target;
    inputs[input_count - 1] = if_successes[i];
    calls[i] = if_successes[i] =
        graph()->NewNode(node->op(), input_count, inputs);
  }
}

Reduction JSInliningHeuristic::InlineCandidate(Candidate const& candidate,
                                               bool small_function) {
  int num_calls = candidate.num_functions;
  Node* const node = candidate.node;
#if V8_ENABLE_WEBASSEMBLY
  DCHECK_NE(node->opcode(), IrOpcode::kJSWasmCall);
#endif  // V8_ENABLE_WEBASSEMBLY
  if (num_calls == 1) {
    Reduction const reduction = inliner_.ReduceJSCall(node);
    if (reduction.Changed()) {
      total_inlined_bytecode_size_ += candidate.bytecode[0].value().length();
    }
    return reduction;
  }

  // Expand the JSCall/JSConstruct node to a subgraph first if
  // we have multiple known target functions.
  DCHECK_LT(1, num_calls);
  Node* calls[kMaxCallPolymorphism + 1];
  Node* if_successes[kMaxCallPolymorphism];
  Node* callee = NodeProperties::GetValueInput(node, 0);

  // Setup the inputs for the cloned call nodes.
  int const input_count = node->InputCount();
  Node** inputs = graph()->zone()->AllocateArray<Node*>(input_count);
  for (int i = 0; i < input_count; ++i) {
    inputs[i] = node->InputAt(i);
  }

  // Create the appropriate control flow to dispatch to the cloned calls.
  CreateOrReuseDispatch(node, callee, candidate, if_successes, calls, inputs,
                        input_count, &num_calls);

  // Check if we have an exception projection for the call {node}.
  Node* if_exception = nullptr;
  if (NodeProperties::IsExceptionalCall(node, &if_exception)) {
    Node* if_exceptions[kMaxCallPolymorphism + 1];
    for (int i = 0; i < num_calls; ++i) {
      if_successes[i] = graph()->NewNode(common()->IfSuccess(), calls[i]);
      if_exceptions[i] =
          graph()->NewNode(common()->IfException(), calls[i], calls[i]);
    }

    // Morph the {if_exception} projection into a join.
    Node* exception_control =
        graph()->NewNode(common()->Merge(num_calls), num_calls, if_exceptions);
    if_exceptions[num_calls] = exception_control;
    Node* exception_effect = graph()->NewNode(common()->EffectPhi(num_calls),
                                              num_calls + 1, if_exceptions);
    Node* exception_value = graph()->NewNode(
        common()->Phi(MachineRepresentation::kTagged, num_calls), num_calls + 1,
        if_exceptions);
    ReplaceWithValue(if_exception, exception_value, exception_effect,
                     exception_control);
  }

  // Morph the original call site into a join of the dispatched call sites.
  Node* control =
      graph()->NewNode(common()->Merge(num_calls), num_calls, if_successes);
  calls[num_calls] = control;
  Node* effect =
      graph()->NewNode(common()->EffectPhi(num_calls), num_calls + 1, calls);
  Node* value =
      graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, num_calls),
                       num_calls + 1, calls);
  ReplaceWithValue(node, value, effect, control);

  // Inline the individual, cloned call sites.
  for (int i = 0; i < num_calls && total_inlined_bytecode_size_ <
                                       max_inlined_bytecode_size_absolute_;
       ++i) {
    if (candidate.can_inline_function[i] &&
        (small_function || total_inlined_bytecode_size_ <
                               max_inlined_bytecode_size_cumulative_)) {
      Node* call = calls[i];
      Reduction const reduction = inliner_.ReduceJSCall(call);
      if (reduction.Changed()) {
        total_inlined_bytecode_size_ += candidate.bytecode[i]->length();
        // Killing the call node is not strictly necessary, but it is safer to
        // make sure we do not resurrect the node.
        call->Kill();
      }
    }
  }

  return Replace(value);
}

bool JSInliningHeuristic::CandidateCompare::operator()(
    const Candidate& left, const Candidate& right) const {
  constexpr bool kInlineLeftFirst = true, kInlineRightFirst = false;
  if (right.frequency.IsUnknown()) {
    if (left.frequency.IsUnknown()) {
      // If left and right are both unknown then the ordering is indeterminate,
      // which breaks strict weak ordering requirements, so we fall back to the
      // node id as a tie breaker.
      if (left.total_size < right.total_size) {
        return kInlineLeftFirst;
      } else if (left.total_size > right.total_size) {
        return kInlineRightFirst;
      } else {
        return left.node->id() > right.node->id();
      }
    } else {
      return kInlineLeftFirst;
    }
  } else if (left.frequency.IsUnknown()) {
    return kInlineRightFirst;
  }

  int left_score = left.frequency.value() / left.total_size;
  int right_score = right.frequency.value() / right.total_size;

  if (left_score > right_score) {
    return kInlineLeftFirst;
  } else if (left_score < right_score) {
    return kInlineRightFirst;
  } else {
    return left.node->id() > right.node->id();
  }
}

void JSInliningHeuristic::PrintCandidates() {
  StdoutStream os;
  os << candidates_.size() << " candidate(s) for inlining:" << std::endl;
  for (const Candidate& candidate : candidates_) {
    os << "- candidate: " << candidate.node->op()->mnemonic() << " node #"
       << candidate.node->id() << " with frequency " << candidate.frequency
       << ", " << candidate.num_functions << " target(s):" << std::endl;
    for (int i = 0; i < candidate.num_functions; ++i) {
      SharedFunctionInfoRef shared =
          candidate.functions[i].has_value()
              ? candidate.functions[i]->shared(broker())
              : candidate.shared_info.value();
      os << "  - target: " << shared;
      if (candidate.bytecode[i].has_value()) {
        os << ", bytecode size: " << candidate.bytecode[i]->length();
        if (OptionalJSFunctionRef function = candidate.functions[i]) {
          if (OptionalCodeRef code = function->code(broker())) {
            unsigned inlined_bytecode_size = code->GetInlinedBytecodeSize();
            if (inlined_bytecode_size > 0) {
              os << ", existing opt code's inlined bytecode size: "
                 << inlined_bytecode_size;
            }
          }
        }
      } else {
        os << ", no bytecode";
      }
      os << std::endl;
    }
  }
}

Graph* JSInliningHeuristic::graph() const { return jsgraph()->graph(); }

CompilationDependencies* JSInliningHeuristic::dependencies() const {
  return broker()->dependencies();
}

CommonOperatorBuilder* JSInliningHeuristic::common() const {
  return jsgraph()->common();
}

SimplifiedOperatorBuilder* JSInliningHeuristic::simplified() const {
  return jsgraph()->simplified();
}

#undef TRACE

}  // namespace compiler
}  // namespace internal
}  // namespace v8
```