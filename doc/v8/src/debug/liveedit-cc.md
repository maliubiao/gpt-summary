Response:
Let's break down the thought process for analyzing the provided C++ code snippet and generating the desired summary.

1. **Understanding the Request:** The core request is to analyze a V8 source file (`liveedit.cc`) and describe its functionality. Specific constraints are given: check for `.tq` extension (Torque), relate to JavaScript, provide examples, discuss logic with assumptions, mention common errors, and summarize the functionality. This is part 1 of 2, indicating a larger scope and the need to focus on the provided section.

2. **Initial Scan and Keywords:** I'll quickly scan the code for recognizable keywords and patterns related to compilation, debugging, and JavaScript:
    * `#include`: Includes related headers like `debug.h`, `ast.h`, `codegen.h`, `parsing.h`, `objects.h`. This immediately suggests a connection to the compilation and debugging process of JavaScript code within V8.
    * `namespace v8::internal`: Confirms this is internal V8 implementation.
    * `LiveEdit`: The file name itself is a strong indicator of its purpose. "Live editing" implies the ability to modify and update code while the program is running.
    * `CompareStrings`, `CalculateDifference`:  Likely involved in diffing the old and new versions of the script.
    * `FunctionLiteral`, `Scope`, `SharedFunctionInfo`, `JSFunction`, `JSGeneratorObject`: These are core V8 concepts representing JavaScript code structures and execution contexts.
    * `PatchScript`, `ParseScript`, `CompileForLiveEdit`: Functions directly related to the live editing process.
    * `SourceChangeRange`:  Represents the differences found between the old and new code.
    * `ThreadVisitor`: Suggests interaction with V8's threading model, likely for finding active functions.

3. **Checking for Torque:** The prompt explicitly asks about `.tq` files. The filename is `liveedit.cc`, so it's C++, *not* Torque. This is a direct answer.

4. **Relating to JavaScript Functionality:** The presence of `FunctionLiteral`, `JSFunction`, etc., strongly indicates a relationship with JavaScript. Live editing *is* a feature relevant to JavaScript developers. To provide a JavaScript example, I need to think about what live editing means in a practical sense: changing code and seeing the effects without a full restart. A simple function and modification scenario will suffice.

5. **Inferring Functionality - Core Logic:** Now, let's delve deeper into the code's structure and logic.

    * **Diffing:** The `CompareStrings` function (not fully shown, but implied) and the `Comparator` classes suggest the core functionality involves finding differences between the old and new script source code. The `NarrowDownInput` function aims to optimize the diffing process by ignoring common prefixes and suffixes.
    * **Line-Level and Token-Level Comparison:**  The `LineArrayCompareInput` and `TokensCompareInput` classes indicate a two-tiered approach to comparison. First, compare lines, and if lines are different, potentially do a more granular token-level comparison.
    * **Tracking Function Changes:** The `CalculateFunctionLiteralChanges` function and related structures (`SourcePositionEvent`, `FunctionLiteralChange`) are crucial. They aim to identify which JavaScript functions have been affected by the changes. This is essential for selectively updating the runtime. The logic involving `SourcePositionEvent` and sorting by position is interesting – it seems like a way to process changes and function boundaries in a coordinated manner. The stack usage indicates handling nested function definitions.
    * **Mapping Old and New Literals:** `MapLiterals` tries to associate old function literals with their corresponding new versions. It considers factors like scope changes to determine if a function can be safely updated.
    * **Parsing and Compilation:** `ParseScript` handles parsing the new script. The call to `Compiler::CompileForLiveEdit` is the key step in preparing the new code.
    * **Identifying Active Functions:** The `FunctionDataMap` and `ThreadVisitor` classes are responsible for tracking active JavaScript functions on the stack. This is important to prevent live editing of functions that are currently being executed.
    * **Patching:** `PatchScript` orchestrates the entire process: diffing, parsing, identifying changes, and (presumably in the later part) updating the V8 runtime with the new code.
    * **Updating Source Position Tables:** `TranslateSourcePositionTable` is important for maintaining accurate debugging information after code modifications.

6. **Logic Reasoning with Assumptions:** For `CalculateFunctionLiteralChanges`, I can make assumptions about the input (`literals` and `diffs`) and trace the logic. For instance, assume a small function is modified. I can then walk through how the `events` vector is populated and sorted, and how the `literal_stack` and `delta` are used to determine the new positions of the function literal.

7. **Common Programming Errors:**  Live editing scenarios can reveal common errors like syntax errors in the updated code, or introducing logic errors that only manifest at runtime. I can provide simple JavaScript examples of these.

8. **Functionality Summary (Part 1):** Based on the analysis of the included section, the core functionality revolves around:
    * Diffing the old and new source code.
    * Identifying which JavaScript functions have been changed or are affected by the changes.
    * Preparing the new code through parsing and potentially compilation.
    * Identifying functions that *cannot* be live-edited due to being active on the stack.

9. **Structuring the Output:**  I need to organize the information clearly, following the structure requested in the prompt (functionality, Torque check, JavaScript relation, logic reasoning, common errors, summary). Using headings and code blocks will improve readability.

10. **Refinement and Review:**  Finally, I'll review my generated summary to ensure accuracy, clarity, and completeness, addressing all parts of the original request. I'll double-check the JavaScript examples and the assumptions made in the logic reasoning.

This detailed thought process, starting from a high-level understanding and progressively diving into the code's details, allows for a comprehensive and accurate analysis of the provided V8 source code snippet.
```cpp
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/debug/liveedit.h"

#include <optional>

#include "src/api/api-inl.h"
#include "src/ast/ast-traversal-visitor.h"
#include "src/ast/ast.h"
#include "src/ast/scopes.h"
#include "src/codegen/compilation-cache.h"
#include "src/codegen/compiler.h"
#include "src/codegen/source-position-table.h"
#include "src/common/globals.h"
#include "src/debug/debug-interface.h"
#include "src/debug/debug-stack-trace-iterator.h"
#include "src/debug/debug.h"
#include "src/debug/liveedit-diff.h"
#include "src/execution/frames-inl.h"
#include "src/execution/v8threads.h"
#include "src/logging/log.h"
#include "src/objects/js-generator-inl.h"
#include "src/objects/js-objects.h"
#include "src/objects/objects-inl.h"
#include "src/parsing/parse-info.h"
#include "src/parsing/parsing.h"

namespace v8 {
namespace internal {
namespace {

bool CompareSubstrings(DirectHandle<String> s1, int pos1,
                       DirectHandle<String> s2, int pos2, int len) {
  for (int i = 0; i < len; i++) {
    if (s1->Get(i + pos1) != s2->Get(i + pos2)) return false;
  }
  return true;
}

// Additional to Input interface. Lets switch Input range to subrange.
// More elegant way would be to wrap one Input as another Input object
// and translate positions there, but that would cost us additional virtual
// call per comparison.
class SubrangableInput : public Comparator::Input {
 public:
  virtual void SetSubrange1(int offset, int len) = 0;
  virtual void SetSubrange2(int offset, int len) = 0;
};

class SubrangableOutput : public Comparator::Output {
 public:
  virtual void SetSubrange1(int offset, int len) = 0;
  virtual void SetSubrange2(int offset, int len) = 0;
};

// Finds common prefix and suffix in input. This parts shouldn't take space in
// linear programming table. Enable subranging in input and output.
void NarrowDownInput(SubrangableInput* input, SubrangableOutput* output) {
  const int len1 = input->GetLength1();
  const int len2 = input->GetLength2();

  int common_prefix_len;
  int common_suffix_len;

  {
    common_prefix_len = 0;
    int prefix_limit = std::min(len1, len2);
    while (common_prefix_len < prefix_limit &&
        input->Equals(common_prefix_len, common_prefix_len)) {
      common_prefix_len++;
    }

    common_suffix_len = 0;
    int suffix_limit =
        std::min(len1 - common_prefix_len, len2 - common_prefix_len);

    while (common_suffix_len < suffix_limit &&
        input->Equals(len1 - common_suffix_len - 1,
        len2 - common_suffix_len - 1)) {
      common_suffix_len++;
    }
  }

  if (common_prefix_len > 0 || common_suffix_len > 0) {
    int new_len1 = len1 - common_suffix_len - common_prefix_len;
    int new_len2 = len2 - common_suffix_len - common_prefix_len;

    input->SetSubrange1(common_prefix_len, new_len1);
    input->SetSubrange2(common_prefix_len, new_len2);

    output->SetSubrange1(common_prefix_len, new_len1);
    output->SetSubrange2(common_prefix_len, new_len2);
  }
}

// Represents 2 strings as 2 arrays of tokens.
// TODO(LiveEdit): Currently it's actually an array of charactres.
//     Make array of tokens instead.
class TokensCompareInput : public Comparator::Input {
 public:
  TokensCompareInput(Handle<String> s1, int offset1, int len1,
                       Handle<String> s2, int offset2, int len2)
      : s1_(s1), offset1_(offset1), len1_(len1),
        s2_(s2), offset2_(offset2), len2_(len2) {
  }
  int GetLength1() override { return len1_; }
  int GetLength2() override { return len2_; }
  bool Equals(int index1, int index2) override {
    return s1_->Get(offset1_ + index1) == s2_->Get(offset2_ + index2);
  }

 private:
  Handle<String> s1_;
  int offset1_;
  int len1_;
  Handle<String> s2_;
  int offset2_;
  int len2_;
};

// Stores compare result in std::vector. Converts substring positions
// to absolute positions.
class TokensCompareOutput : public Comparator::Output {
 public:
  TokensCompareOutput(int offset1, int offset2,
                      std::vector<SourceChangeRange>* output)
      : output_(output), offset1_(offset1), offset2_(offset2) {}

  void AddChunk(int pos1, int pos2, int len1, int len2) override {
    output_->emplace_back(
        SourceChangeRange{pos1 + offset1_, pos1 + len1 + offset1_,
                          pos2 + offset2_, pos2 + offset2_ + len2});
  }

 private:
  std::vector<SourceChangeRange>* output_;
  int offset1_;
  int offset2_;
};

// Wraps raw n-elements line_ends array as a list of n+1 lines. The last line
// never has terminating new line character.
class LineEndsWrapper {
 public:
  explicit LineEndsWrapper(Isolate* isolate, Handle<String> string)
      : ends_array_(String::CalculateLineEnds(isolate, string, false)),
        string_len_(string->length()) {}
  int length() {
    return ends_array_->length() + 1;
  }
  // Returns start for any line including start of the imaginary line after
  // the last line.
  int GetLineStart(int index) { return index == 0 ? 0 : GetLineEnd(index - 1); }
  int GetLineEnd(int index) {
    if (index == ends_array_->length()) {
      // End of the last line is always an end of the whole string.
      // If the string ends with a new line character, the last line is an
      // empty string after this character.
      return string_len_;
    } else {
      return GetPosAfterNewLine(index);
    }
  }

 private:
  Handle<FixedArray> ends_array_;
  int string_len_;

  int GetPosAfterNewLine(int index) {
    return Smi::ToInt(ends_array_->get(index)) + 1;
  }
};

// Represents 2 strings as 2 arrays of lines.
class LineArrayCompareInput : public SubrangableInput {
 public:
  LineArrayCompareInput(Handle<String> s1, Handle<String> s2,
                        LineEndsWrapper line_ends1, LineEndsWrapper line_ends2)
      : s1_(s1), s2_(s2), line_ends1_(line_ends1),
        line_ends2_(line_ends2),
        subrange_offset1_(0), subrange_offset2_(0),
        subrange_len1_(line_ends1_.length()),
        subrange_len2_(line_ends2_.length()) {
  }
  int GetLength1() override { return subrange_len1_; }
  int GetLength2() override { return subrange_len2_; }
  bool Equals(int index1, int index2) override {
    index1 += subrange_offset1_;
    index2 += subrange_offset2_;

    int line_start1 = line_ends1_.GetLineStart(index1);
    int line_start2 = line_ends2_.GetLineStart(index2);
    int line_end1 = line_ends1_.GetLineEnd(index1);
    int line_end2 = line_ends2_.GetLineEnd(index2);
    int len1 = line_end1 - line_start1;
    int len2 = line_end2 - line_start2;
    if (len1 != len2) {
      return false;
    }
    return CompareSubstrings(s1_, line_start1, s2_, line_start2,
                             len1);
  }
  void SetSubrange1(int offset, int len) override {
    subrange_offset1_ = offset;
    subrange_len1_ = len;
  }
  void SetSubrange2(int offset, int len) override {
    subrange_offset2_ = offset;
    subrange_len2_ = len;
  }

 private:
  Handle<String> s1_;
  Handle<String> s2_;
  LineEndsWrapper line_ends1_;
  LineEndsWrapper line_ends2_;
  int subrange_offset1_;
  int subrange_offset2_;
  int subrange_len1_;
  int subrange_len2_;
};

// Stores compare result in std::vector. For each chunk tries to conduct
// a fine-grained nested diff token-wise.
class TokenizingLineArrayCompareOutput : public SubrangableOutput {
 public:
  TokenizingLineArrayCompareOutput(Isolate* isolate, LineEndsWrapper line_ends1,
                                   LineEndsWrapper line_ends2,
                                   Handle<String> s1, Handle<String> s2,
                                   std::vector<SourceChangeRange>* output)
      : isolate_(isolate),
        line_ends1_(line_ends1),
        line_ends2_(line_ends2),
        s1_(s1),
        s2_(s2),
        subrange_offset1_(0),
        subrange_offset2_(0),
        output_(output) {}

  void AddChunk(int line_pos1, int line_pos2, int line_len1,
                int line_len2) override {
    line_pos1 += subrange_offset1_;
    line_pos2 += subrange_offset2_;

    int char_pos1 = line_ends1_.GetLineStart(line_pos1);
    int char_pos2 = line_ends2_.GetLineStart(line_pos2);
    int char_len1 = line_ends1_.GetLineStart(line_pos1 + line_len1) - char_pos1;
    int char_len2 = line_ends2_.GetLineStart(line_pos2 + line_len2) - char_pos2;

    if (char_len1 < CHUNK_LEN_LIMIT && char_len2 < CHUNK_LEN_LIMIT) {
      // Chunk is small enough to conduct a nested token-level diff.
      HandleScope subTaskScope(isolate_);

      TokensCompareInput tokens_input(s1_, char_pos1, char_len1,
                                      s2_, char_pos2, char_len2);
      TokensCompareOutput tokens_output(char_pos1, char_pos2, output_);

      Comparator::CalculateDifference(&tokens_input, &tokens_output);
    } else {
      output_->emplace_back(SourceChangeRange{
          char_pos1, char_pos1 + char_len1, char_pos2, char_pos2 + char_len2});
    }
  }
  void SetSubrange1(int offset, int len) override {
    subrange_offset1_ = offset;
  }
  void SetSubrange2(int offset, int len) override {
    subrange_offset2_ = offset;
  }

 private:
  static const int CHUNK_LEN_LIMIT = 800;

  Isolate* isolate_;
  LineEndsWrapper line_ends1_;
  LineEndsWrapper line_ends2_;
  Handle<String> s1_;
  Handle<String> s2_;
  int subrange_offset1_;
  int subrange_offset2_;
  std::vector<SourceChangeRange>* output_;
};

struct SourcePositionEvent {
  enum Type { LITERAL_STARTS, LITERAL_ENDS, DIFF_STARTS, DIFF_ENDS };

  int position;
  Type type;

  union {
    FunctionLiteral* literal;
    int pos_diff;
  };

  SourcePositionEvent(FunctionLiteral* literal, bool is_start)
      : position(is_start ? literal->start_position()
                          : literal->end_position()),
        type(is_start ? LITERAL_STARTS : LITERAL_ENDS),
        literal(literal) {}
  SourcePositionEvent(const SourceChangeRange& change, bool is_start)
      : position(is_start ? change.start_position : change.end_position),
        type(is_start ? DIFF_STARTS : DIFF_ENDS),
        pos_diff((change.new_end_position - change.new_start_position) -
                 (change.end_position - change.start_position)) {}

  static bool LessThan(const SourcePositionEvent& a,
                       const SourcePositionEvent& b) {
    if (a.position != b.position) return a.position < b.position;
    if (a.type != b.type) return a.type < b.type;
    if (a.type == LITERAL_STARTS && b.type == LITERAL_STARTS) {
      // If the literals start in the same position, we want the one with the
      // furthest (i.e. largest) end position to be first.
      if (a.literal->end_position() != b.literal->end_position()) {
        return a.literal->end_position() > b.literal->end_position();
      }
      // If they also end in the same position, we want the first in order of
      // literal ids to be first.
      return a.literal->function_literal_id() <
             b.literal->function_literal_id();
    } else if (a.type == LITERAL_ENDS && b.type == LITERAL_ENDS) {
      // If the literals end in the same position, we want the one with the
      // nearest (i.e. largest) start position to be first.
      if (a.literal->start_position() != b.literal->start_position()) {
        return a.literal->start_position() > b.literal->start_position();
      }
      // If they also end in the same position, we want the last in order of
      // literal ids to be first.
      return a.literal->function_literal_id() >
             b.literal->function_literal_id();
    } else {
      return a.pos_diff < b.pos_diff;
    }
  }
};

struct FunctionLiteralChange {
  // If any of start/end position is kNoSourcePosition, this literal is
  // considered damaged and will not be mapped and edited at all.
  int new_start_position;
  int new_end_position;
  bool has_changes;
  FunctionLiteral* outer_literal;

  explicit FunctionLiteralChange(int new_start_position, FunctionLiteral* outer)
      : new_start_position(new_start_position),
        new_end_position(kNoSourcePosition),
        has_changes(false),
        outer_literal(outer) {}
};

using FunctionLiteralChanges =
    std::unordered_map<FunctionLiteral*, FunctionLiteralChange>;
void CalculateFunctionLiteralChanges(
    const std::vector<FunctionLiteral*>& literals,
    const std::vector<SourceChangeRange>& diffs,
    FunctionLiteralChanges* result) {
  std::vector<SourcePositionEvent> events;
  events.reserve(literals.size() * 2 + diffs.size() * 2);
  for (FunctionLiteral* literal : literals) {
    events.emplace_back(literal, true);
    events.emplace_back(literal, false);
  }
  for (const SourceChangeRange& diff : diffs) {
    events.emplace_back(diff, true);
    events.emplace_back(diff, false);
  }
  std::sort(events.begin(), events.end(), SourcePositionEvent::LessThan);
  bool inside_diff = false;
  int delta = 0;
  std::stack<std::pair<FunctionLiteral*, FunctionLiteralChange>> literal_stack;
  for (const SourcePositionEvent& event : events) {
    switch (event.type) {
      case SourcePositionEvent::DIFF_ENDS:
        DCHECK(inside_diff);
        inside_diff = false;
        delta += event.pos_diff;
        break;
      case SourcePositionEvent::LITERAL_ENDS: {
        DCHECK_EQ(literal_stack.top().first, event.literal);
        FunctionLiteralChange& change = literal_stack.top().second;
        change.new_end_position = inside_diff
                                      ? kNoSourcePosition
                                      : event.literal->end_position() + delta;
        result->insert(literal_stack.top());
        literal_stack.pop();
        break;
      }
      case SourcePositionEvent::LITERAL_STARTS:
        literal_stack.push(std::make_pair(
            event.literal,
            FunctionLiteralChange(
                inside_diff ? kNoSourcePosition
                            : event.literal->start_position() + delta,
                literal_stack.empty() ? nullptr : literal_stack.top().first)));
        break;
      case SourcePositionEvent::DIFF_STARTS:
        DCHECK(!inside_diff);
        inside_diff = true;
        if (!literal_stack.empty()) {
          // Note that outer literal has not necessarily changed, unless the
          // diff goes past the end of this literal. In this case, we'll mark
          // this function as damaged and parent as changed later in
          // MapLiterals.
          literal_stack.top().second.has_changes = true;
        }
        break;
    }
  }
}

// Function which has not changed itself, but if any variable in its
// outer context has been added/removed, we must consider this function
// as damaged and not update references to it.
// This is because old compiled function has hardcoded references to
// it's outer context.
bool HasChangedScope(FunctionLiteral* a, FunctionLiteral* b) {
  Scope* scope_a = a->scope()->outer_scope();
  Scope* scope_b = b->scope()->outer_scope();
  while (scope_a && scope_b) {
    std::unordered_map<int, Handle<String>> vars;
    for (Variable* var : *scope_a->locals()) {
      if (!var->IsContextSlot()) continue;
      vars[var->index()] = var->name();
    }
    for (Variable* var : *scope_b->locals()) {
      if (!var->IsContextSlot()) continue;
      auto it = vars.find(var->index());
      if (it == vars.end()) return true;
      if (*it->second != *var->name()) return true;
    }
    scope_a = scope_a->outer_scope();
    scope_b = scope_b->outer_scope();
  }
  return scope_a != scope_b;
}

enum ChangeState { UNCHANGED, CHANGED, DAMAGED };

using LiteralMap = std::unordered_map<FunctionLiteral*, FunctionLiteral*>;
void MapLiterals(const FunctionLiteralChanges& changes,
                 const std::vector<FunctionLiteral*>& new_literals,
                 LiteralMap* unchanged, LiteralMap* changed) {
  // Track the top-level script function separately as it can overlap fully with
  // another function, e.g. the script "()=>42".
  const std::pair<int, int> kTopLevelMarker = std::make_pair(-1, -1);
  std::map<std::pair<int, int>, FunctionLiteral*> position_to_new_literal;
  for (FunctionLiteral* literal : new_literals) {
    DCHECK(literal->start_position() != kNoSourcePosition);
    DCHECK(literal->end_position() != kNoSourcePosition);
    std::pair<int, int> key =
        literal->function_literal_id() == kFunctionLiteralIdTopLevel
            ? kTopLevelMarker
            : std::make_pair(literal->start_position(),
                             literal->end_position());
    // Make sure there are no duplicate keys.
    DCHECK_EQ(position_to_new_literal.find(key), position_to_new_literal.end());
    position_to_new_literal[key] = literal;
  }
  LiteralMap mappings;
  std::unordered_map<FunctionLiteral*, ChangeState> change_state;
  for (const auto& change_pair : changes) {
    FunctionLiteral* literal = change_pair.first;
    const FunctionLiteralChange& change = change_pair.second;
    std::pair<int, int> key =
        literal->function_literal_id() == kFunctionLiteralIdTopLevel
            ? kTopLevelMarker
            : std::make_pair(change.new_start_position,
                             change.new_end_position);
    auto it = position_to_new_literal.find(key);
    if (it == position_to_new_literal.end() ||
        HasChangedScope(literal, it->second)) {
      change_state[literal] = ChangeState::DAMAGED;
      if (!change.outer_literal) continue;
      if (change_state[change.outer_literal] != ChangeState::DAMAGED) {
        change_state[change.outer_literal] = ChangeState::CHANGED;
      }
    } else {
      mappings[literal] = it->second;
      if (change_state.find(literal) == change_state.end()) {
        change_state[literal] =
            change.has_changes ? ChangeState::CHANGED : ChangeState::UNCHANGED;
      }
    }
  }
  for (const auto& mapping : mappings) {
    if (change_state[mapping.first] == ChangeState::UNCHANGED) {
      (*unchanged)[mapping.first] = mapping.second;
    } else if (change_state[mapping.first] == ChangeState::CHANGED) {
      (*changed)[mapping.first] = mapping.second;
    }
  }
}

class CollectFunctionLiterals final
    : public AstTraversalVisitor<CollectFunctionLiterals> {
 public:
  CollectFunctionLiterals(Isolate* isolate, AstNode* root)
      : AstTraversalVisitor<CollectFunctionLiterals>(isolate, root) {}
  void VisitFunctionLiteral(FunctionLiteral* lit) {
    AstTraversalVisitor::VisitFunctionLiteral(lit);
    literals_->push_back(lit);
  }
  void Run(std::vector<FunctionLiteral*>* literals) {
    literals_ = literals;
    AstTraversalVisitor::Run();
    literals_ = nullptr;
  }

 private:
  std::vector<FunctionLiteral*>* literals_;
};

bool ParseScript(Isolate* isolate, Handle<Script> script, ParseInfo* parse_info,
                 MaybeHandle<ScopeInfo> outer_scope_info, bool compile_as_well,
                 std::vector<FunctionLiteral*>* literals,
                 debug::LiveEditResult* result) {
  v8::TryCatch try_catch(reinterpret_cast<v8::Isolate*>(isolate));
  Handle<SharedFunctionInfo> shared;
  bool success = false;
  if (compile_as_well) {
    success = Compiler::CompileForLiveEdit(parse_info, script, outer_scope_info,
                                           isolate)
                  .ToHandle(&shared);
  } else {
    success =
        parsing::ParseProgram(parse_info, script, outer_scope_info, isolate,
                              parsing::ReportStatisticsMode::kYes);
    if (!success) {
      // Throw the parser error.
      parse_info->pending_error_handler()->PrepareErrors(
          isolate, parse_info->ast_value_factory());
      parse_info->pending_error_handler()->ReportErrors(isolate, script);
    }
  }
  if (!success) {
    DCHECK(try_catch.HasCaught());
    result->message = try_catch.Message()->Get();
    i::DirectHandle<i::JSMessageObject> msg =
        Utils::OpenDirectHandle(*try_catch.Message());
    i::JSMessageObject::EnsureSourcePositionsAvailable(isolate, msg);
    result->line_number = msg->GetLineNumber();
    result->column_number = msg->GetColumnNumber();
    result->status = debug::LiveEditResult::COMPILE_ERROR;
    return false;
  }
  CollectFunctionLiterals(isolate, parse_info->literal()).Run(literals);
  return true;
}

struct FunctionData {
  explicit FunctionData(FunctionLiteral* literal)
      : literal(literal), stack_position(NOT_ON_STACK) {}

  FunctionLiteral* literal;
  MaybeHandle<SharedFunctionInfo> shared;
  std::vector<Handle<JSFunction>> js_functions;
  std::vector<Handle<JSGeneratorObject>> running_generators;
  // In case of multiple functions with different stack position, the latest
  // one (in the order below) is used, since it is the most restrictive.
  // This is important only for functions to be restarted.
  enum StackPosition { NOT_ON_STACK, ON_TOP_ONLY, ON_STACK };
  StackPosition stack_position;
};

class FunctionDataMap : public ThreadVisitor {
 public:
  void AddInterestingLiteral(int script_id, FunctionLiteral* literal) {
    map_.emplace(GetFuncId(script_id, literal), FunctionData{literal});
  }

  bool Lookup(Tagged<SharedFunctionInfo> sfi, FunctionData** data) {
    int start_position = sfi->StartPosition();
    if (!IsScript(sfi->script()) || start_position == -1) {
      return false;
    }
    Tagged<Script> script = Cast<Script>(sfi->script());
    return Lookup(GetFuncId(script->id(), sfi), data);
  }

  bool Lookup(DirectHandle<Script> script, FunctionLiteral* literal,
              FunctionData** data) {
    return Lookup(GetFuncId(script->id(), literal), data);
  }

  void Fill(Isolate* isolate) {
    {
      HeapObjectIterator iterator(isolate->heap(),
                                  HeapObjectIterator::kFilterUnreachable);
      for (Tagged<HeapObject> obj = iterator.Next(); !obj.is_null();
           obj = iterator.Next()) {
        if (IsSharedFunctionInfo(obj)) {
          Tagged<SharedFunctionInfo> sfi = Cast<SharedFunctionInfo>(obj);
          FunctionData* data = nullptr;
          if (!Lookup(sfi, &data)) continue;
          data->shared = handle(sfi, isolate);
        } else if (IsJSFunction(obj)) {
          Tagged<JSFunction> js_function = Cast<JSFunction>(obj);
          Tagged<SharedFunctionInfo> sfi = js_function->shared();
          FunctionData* data = nullptr;
          if (!Lookup(sfi, &data)) continue;
          data->js_functions.emplace_back(js_function, isolate);
        } else if (IsJSGeneratorObject(obj)) {
          Tagged<JSGeneratorObject> gen = Cast<JSGeneratorObject>(obj);
          if (gen->is_closed()) continue;
          Tagged<SharedFunctionInfo> sfi = gen->function()->shared();
          FunctionData* data = nullptr;
          if (!Lookup(sfi, &data)) continue;
          data->running_generators.emplace_back(gen, isolate);
        }
      }
    }

    // Visit the current thread stack.
    VisitCurrentThread(isolate);

    // Visit the stacks of all archived threads.
    isolate->thread_manager()->IterateArchivedThreads(this);
  }

 private:
  // Unique id for a function: script_id + start_position, where start_position
  // is special cased to -1 for top-level so that it does not overlap with a
  // function whose
### 提示词
```
这是目录为v8/src/debug/liveedit.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/debug/liveedit.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/debug/liveedit.h"

#include <optional>

#include "src/api/api-inl.h"
#include "src/ast/ast-traversal-visitor.h"
#include "src/ast/ast.h"
#include "src/ast/scopes.h"
#include "src/codegen/compilation-cache.h"
#include "src/codegen/compiler.h"
#include "src/codegen/source-position-table.h"
#include "src/common/globals.h"
#include "src/debug/debug-interface.h"
#include "src/debug/debug-stack-trace-iterator.h"
#include "src/debug/debug.h"
#include "src/debug/liveedit-diff.h"
#include "src/execution/frames-inl.h"
#include "src/execution/v8threads.h"
#include "src/logging/log.h"
#include "src/objects/js-generator-inl.h"
#include "src/objects/js-objects.h"
#include "src/objects/objects-inl.h"
#include "src/parsing/parse-info.h"
#include "src/parsing/parsing.h"

namespace v8 {
namespace internal {
namespace {

bool CompareSubstrings(DirectHandle<String> s1, int pos1,
                       DirectHandle<String> s2, int pos2, int len) {
  for (int i = 0; i < len; i++) {
    if (s1->Get(i + pos1) != s2->Get(i + pos2)) return false;
  }
  return true;
}

// Additional to Input interface. Lets switch Input range to subrange.
// More elegant way would be to wrap one Input as another Input object
// and translate positions there, but that would cost us additional virtual
// call per comparison.
class SubrangableInput : public Comparator::Input {
 public:
  virtual void SetSubrange1(int offset, int len) = 0;
  virtual void SetSubrange2(int offset, int len) = 0;
};


class SubrangableOutput : public Comparator::Output {
 public:
  virtual void SetSubrange1(int offset, int len) = 0;
  virtual void SetSubrange2(int offset, int len) = 0;
};

// Finds common prefix and suffix in input. This parts shouldn't take space in
// linear programming table. Enable subranging in input and output.
void NarrowDownInput(SubrangableInput* input, SubrangableOutput* output) {
  const int len1 = input->GetLength1();
  const int len2 = input->GetLength2();

  int common_prefix_len;
  int common_suffix_len;

  {
    common_prefix_len = 0;
    int prefix_limit = std::min(len1, len2);
    while (common_prefix_len < prefix_limit &&
        input->Equals(common_prefix_len, common_prefix_len)) {
      common_prefix_len++;
    }

    common_suffix_len = 0;
    int suffix_limit =
        std::min(len1 - common_prefix_len, len2 - common_prefix_len);

    while (common_suffix_len < suffix_limit &&
        input->Equals(len1 - common_suffix_len - 1,
        len2 - common_suffix_len - 1)) {
      common_suffix_len++;
    }
  }

  if (common_prefix_len > 0 || common_suffix_len > 0) {
    int new_len1 = len1 - common_suffix_len - common_prefix_len;
    int new_len2 = len2 - common_suffix_len - common_prefix_len;

    input->SetSubrange1(common_prefix_len, new_len1);
    input->SetSubrange2(common_prefix_len, new_len2);

    output->SetSubrange1(common_prefix_len, new_len1);
    output->SetSubrange2(common_prefix_len, new_len2);
  }
}

// Represents 2 strings as 2 arrays of tokens.
// TODO(LiveEdit): Currently it's actually an array of charactres.
//     Make array of tokens instead.
class TokensCompareInput : public Comparator::Input {
 public:
  TokensCompareInput(Handle<String> s1, int offset1, int len1,
                       Handle<String> s2, int offset2, int len2)
      : s1_(s1), offset1_(offset1), len1_(len1),
        s2_(s2), offset2_(offset2), len2_(len2) {
  }
  int GetLength1() override { return len1_; }
  int GetLength2() override { return len2_; }
  bool Equals(int index1, int index2) override {
    return s1_->Get(offset1_ + index1) == s2_->Get(offset2_ + index2);
  }

 private:
  Handle<String> s1_;
  int offset1_;
  int len1_;
  Handle<String> s2_;
  int offset2_;
  int len2_;
};

// Stores compare result in std::vector. Converts substring positions
// to absolute positions.
class TokensCompareOutput : public Comparator::Output {
 public:
  TokensCompareOutput(int offset1, int offset2,
                      std::vector<SourceChangeRange>* output)
      : output_(output), offset1_(offset1), offset2_(offset2) {}

  void AddChunk(int pos1, int pos2, int len1, int len2) override {
    output_->emplace_back(
        SourceChangeRange{pos1 + offset1_, pos1 + len1 + offset1_,
                          pos2 + offset2_, pos2 + offset2_ + len2});
  }

 private:
  std::vector<SourceChangeRange>* output_;
  int offset1_;
  int offset2_;
};

// Wraps raw n-elements line_ends array as a list of n+1 lines. The last line
// never has terminating new line character.
class LineEndsWrapper {
 public:
  explicit LineEndsWrapper(Isolate* isolate, Handle<String> string)
      : ends_array_(String::CalculateLineEnds(isolate, string, false)),
        string_len_(string->length()) {}
  int length() {
    return ends_array_->length() + 1;
  }
  // Returns start for any line including start of the imaginary line after
  // the last line.
  int GetLineStart(int index) { return index == 0 ? 0 : GetLineEnd(index - 1); }
  int GetLineEnd(int index) {
    if (index == ends_array_->length()) {
      // End of the last line is always an end of the whole string.
      // If the string ends with a new line character, the last line is an
      // empty string after this character.
      return string_len_;
    } else {
      return GetPosAfterNewLine(index);
    }
  }

 private:
  Handle<FixedArray> ends_array_;
  int string_len_;

  int GetPosAfterNewLine(int index) {
    return Smi::ToInt(ends_array_->get(index)) + 1;
  }
};

// Represents 2 strings as 2 arrays of lines.
class LineArrayCompareInput : public SubrangableInput {
 public:
  LineArrayCompareInput(Handle<String> s1, Handle<String> s2,
                        LineEndsWrapper line_ends1, LineEndsWrapper line_ends2)
      : s1_(s1), s2_(s2), line_ends1_(line_ends1),
        line_ends2_(line_ends2),
        subrange_offset1_(0), subrange_offset2_(0),
        subrange_len1_(line_ends1_.length()),
        subrange_len2_(line_ends2_.length()) {
  }
  int GetLength1() override { return subrange_len1_; }
  int GetLength2() override { return subrange_len2_; }
  bool Equals(int index1, int index2) override {
    index1 += subrange_offset1_;
    index2 += subrange_offset2_;

    int line_start1 = line_ends1_.GetLineStart(index1);
    int line_start2 = line_ends2_.GetLineStart(index2);
    int line_end1 = line_ends1_.GetLineEnd(index1);
    int line_end2 = line_ends2_.GetLineEnd(index2);
    int len1 = line_end1 - line_start1;
    int len2 = line_end2 - line_start2;
    if (len1 != len2) {
      return false;
    }
    return CompareSubstrings(s1_, line_start1, s2_, line_start2,
                             len1);
  }
  void SetSubrange1(int offset, int len) override {
    subrange_offset1_ = offset;
    subrange_len1_ = len;
  }
  void SetSubrange2(int offset, int len) override {
    subrange_offset2_ = offset;
    subrange_len2_ = len;
  }

 private:
  Handle<String> s1_;
  Handle<String> s2_;
  LineEndsWrapper line_ends1_;
  LineEndsWrapper line_ends2_;
  int subrange_offset1_;
  int subrange_offset2_;
  int subrange_len1_;
  int subrange_len2_;
};

// Stores compare result in std::vector. For each chunk tries to conduct
// a fine-grained nested diff token-wise.
class TokenizingLineArrayCompareOutput : public SubrangableOutput {
 public:
  TokenizingLineArrayCompareOutput(Isolate* isolate, LineEndsWrapper line_ends1,
                                   LineEndsWrapper line_ends2,
                                   Handle<String> s1, Handle<String> s2,
                                   std::vector<SourceChangeRange>* output)
      : isolate_(isolate),
        line_ends1_(line_ends1),
        line_ends2_(line_ends2),
        s1_(s1),
        s2_(s2),
        subrange_offset1_(0),
        subrange_offset2_(0),
        output_(output) {}

  void AddChunk(int line_pos1, int line_pos2, int line_len1,
                int line_len2) override {
    line_pos1 += subrange_offset1_;
    line_pos2 += subrange_offset2_;

    int char_pos1 = line_ends1_.GetLineStart(line_pos1);
    int char_pos2 = line_ends2_.GetLineStart(line_pos2);
    int char_len1 = line_ends1_.GetLineStart(line_pos1 + line_len1) - char_pos1;
    int char_len2 = line_ends2_.GetLineStart(line_pos2 + line_len2) - char_pos2;

    if (char_len1 < CHUNK_LEN_LIMIT && char_len2 < CHUNK_LEN_LIMIT) {
      // Chunk is small enough to conduct a nested token-level diff.
      HandleScope subTaskScope(isolate_);

      TokensCompareInput tokens_input(s1_, char_pos1, char_len1,
                                      s2_, char_pos2, char_len2);
      TokensCompareOutput tokens_output(char_pos1, char_pos2, output_);

      Comparator::CalculateDifference(&tokens_input, &tokens_output);
    } else {
      output_->emplace_back(SourceChangeRange{
          char_pos1, char_pos1 + char_len1, char_pos2, char_pos2 + char_len2});
    }
  }
  void SetSubrange1(int offset, int len) override {
    subrange_offset1_ = offset;
  }
  void SetSubrange2(int offset, int len) override {
    subrange_offset2_ = offset;
  }

 private:
  static const int CHUNK_LEN_LIMIT = 800;

  Isolate* isolate_;
  LineEndsWrapper line_ends1_;
  LineEndsWrapper line_ends2_;
  Handle<String> s1_;
  Handle<String> s2_;
  int subrange_offset1_;
  int subrange_offset2_;
  std::vector<SourceChangeRange>* output_;
};

struct SourcePositionEvent {
  enum Type { LITERAL_STARTS, LITERAL_ENDS, DIFF_STARTS, DIFF_ENDS };

  int position;
  Type type;

  union {
    FunctionLiteral* literal;
    int pos_diff;
  };

  SourcePositionEvent(FunctionLiteral* literal, bool is_start)
      : position(is_start ? literal->start_position()
                          : literal->end_position()),
        type(is_start ? LITERAL_STARTS : LITERAL_ENDS),
        literal(literal) {}
  SourcePositionEvent(const SourceChangeRange& change, bool is_start)
      : position(is_start ? change.start_position : change.end_position),
        type(is_start ? DIFF_STARTS : DIFF_ENDS),
        pos_diff((change.new_end_position - change.new_start_position) -
                 (change.end_position - change.start_position)) {}

  static bool LessThan(const SourcePositionEvent& a,
                       const SourcePositionEvent& b) {
    if (a.position != b.position) return a.position < b.position;
    if (a.type != b.type) return a.type < b.type;
    if (a.type == LITERAL_STARTS && b.type == LITERAL_STARTS) {
      // If the literals start in the same position, we want the one with the
      // furthest (i.e. largest) end position to be first.
      if (a.literal->end_position() != b.literal->end_position()) {
        return a.literal->end_position() > b.literal->end_position();
      }
      // If they also end in the same position, we want the first in order of
      // literal ids to be first.
      return a.literal->function_literal_id() <
             b.literal->function_literal_id();
    } else if (a.type == LITERAL_ENDS && b.type == LITERAL_ENDS) {
      // If the literals end in the same position, we want the one with the
      // nearest (i.e. largest) start position to be first.
      if (a.literal->start_position() != b.literal->start_position()) {
        return a.literal->start_position() > b.literal->start_position();
      }
      // If they also end in the same position, we want the last in order of
      // literal ids to be first.
      return a.literal->function_literal_id() >
             b.literal->function_literal_id();
    } else {
      return a.pos_diff < b.pos_diff;
    }
  }
};

struct FunctionLiteralChange {
  // If any of start/end position is kNoSourcePosition, this literal is
  // considered damaged and will not be mapped and edited at all.
  int new_start_position;
  int new_end_position;
  bool has_changes;
  FunctionLiteral* outer_literal;

  explicit FunctionLiteralChange(int new_start_position, FunctionLiteral* outer)
      : new_start_position(new_start_position),
        new_end_position(kNoSourcePosition),
        has_changes(false),
        outer_literal(outer) {}
};

using FunctionLiteralChanges =
    std::unordered_map<FunctionLiteral*, FunctionLiteralChange>;
void CalculateFunctionLiteralChanges(
    const std::vector<FunctionLiteral*>& literals,
    const std::vector<SourceChangeRange>& diffs,
    FunctionLiteralChanges* result) {
  std::vector<SourcePositionEvent> events;
  events.reserve(literals.size() * 2 + diffs.size() * 2);
  for (FunctionLiteral* literal : literals) {
    events.emplace_back(literal, true);
    events.emplace_back(literal, false);
  }
  for (const SourceChangeRange& diff : diffs) {
    events.emplace_back(diff, true);
    events.emplace_back(diff, false);
  }
  std::sort(events.begin(), events.end(), SourcePositionEvent::LessThan);
  bool inside_diff = false;
  int delta = 0;
  std::stack<std::pair<FunctionLiteral*, FunctionLiteralChange>> literal_stack;
  for (const SourcePositionEvent& event : events) {
    switch (event.type) {
      case SourcePositionEvent::DIFF_ENDS:
        DCHECK(inside_diff);
        inside_diff = false;
        delta += event.pos_diff;
        break;
      case SourcePositionEvent::LITERAL_ENDS: {
        DCHECK_EQ(literal_stack.top().first, event.literal);
        FunctionLiteralChange& change = literal_stack.top().second;
        change.new_end_position = inside_diff
                                      ? kNoSourcePosition
                                      : event.literal->end_position() + delta;
        result->insert(literal_stack.top());
        literal_stack.pop();
        break;
      }
      case SourcePositionEvent::LITERAL_STARTS:
        literal_stack.push(std::make_pair(
            event.literal,
            FunctionLiteralChange(
                inside_diff ? kNoSourcePosition
                            : event.literal->start_position() + delta,
                literal_stack.empty() ? nullptr : literal_stack.top().first)));
        break;
      case SourcePositionEvent::DIFF_STARTS:
        DCHECK(!inside_diff);
        inside_diff = true;
        if (!literal_stack.empty()) {
          // Note that outer literal has not necessarily changed, unless the
          // diff goes past the end of this literal. In this case, we'll mark
          // this function as damaged and parent as changed later in
          // MapLiterals.
          literal_stack.top().second.has_changes = true;
        }
        break;
    }
  }
}

// Function which has not changed itself, but if any variable in its
// outer context has been added/removed, we must consider this function
// as damaged and not update references to it.
// This is because old compiled function has hardcoded references to
// it's outer context.
bool HasChangedScope(FunctionLiteral* a, FunctionLiteral* b) {
  Scope* scope_a = a->scope()->outer_scope();
  Scope* scope_b = b->scope()->outer_scope();
  while (scope_a && scope_b) {
    std::unordered_map<int, Handle<String>> vars;
    for (Variable* var : *scope_a->locals()) {
      if (!var->IsContextSlot()) continue;
      vars[var->index()] = var->name();
    }
    for (Variable* var : *scope_b->locals()) {
      if (!var->IsContextSlot()) continue;
      auto it = vars.find(var->index());
      if (it == vars.end()) return true;
      if (*it->second != *var->name()) return true;
    }
    scope_a = scope_a->outer_scope();
    scope_b = scope_b->outer_scope();
  }
  return scope_a != scope_b;
}

enum ChangeState { UNCHANGED, CHANGED, DAMAGED };

using LiteralMap = std::unordered_map<FunctionLiteral*, FunctionLiteral*>;
void MapLiterals(const FunctionLiteralChanges& changes,
                 const std::vector<FunctionLiteral*>& new_literals,
                 LiteralMap* unchanged, LiteralMap* changed) {
  // Track the top-level script function separately as it can overlap fully with
  // another function, e.g. the script "()=>42".
  const std::pair<int, int> kTopLevelMarker = std::make_pair(-1, -1);
  std::map<std::pair<int, int>, FunctionLiteral*> position_to_new_literal;
  for (FunctionLiteral* literal : new_literals) {
    DCHECK(literal->start_position() != kNoSourcePosition);
    DCHECK(literal->end_position() != kNoSourcePosition);
    std::pair<int, int> key =
        literal->function_literal_id() == kFunctionLiteralIdTopLevel
            ? kTopLevelMarker
            : std::make_pair(literal->start_position(),
                             literal->end_position());
    // Make sure there are no duplicate keys.
    DCHECK_EQ(position_to_new_literal.find(key), position_to_new_literal.end());
    position_to_new_literal[key] = literal;
  }
  LiteralMap mappings;
  std::unordered_map<FunctionLiteral*, ChangeState> change_state;
  for (const auto& change_pair : changes) {
    FunctionLiteral* literal = change_pair.first;
    const FunctionLiteralChange& change = change_pair.second;
    std::pair<int, int> key =
        literal->function_literal_id() == kFunctionLiteralIdTopLevel
            ? kTopLevelMarker
            : std::make_pair(change.new_start_position,
                             change.new_end_position);
    auto it = position_to_new_literal.find(key);
    if (it == position_to_new_literal.end() ||
        HasChangedScope(literal, it->second)) {
      change_state[literal] = ChangeState::DAMAGED;
      if (!change.outer_literal) continue;
      if (change_state[change.outer_literal] != ChangeState::DAMAGED) {
        change_state[change.outer_literal] = ChangeState::CHANGED;
      }
    } else {
      mappings[literal] = it->second;
      if (change_state.find(literal) == change_state.end()) {
        change_state[literal] =
            change.has_changes ? ChangeState::CHANGED : ChangeState::UNCHANGED;
      }
    }
  }
  for (const auto& mapping : mappings) {
    if (change_state[mapping.first] == ChangeState::UNCHANGED) {
      (*unchanged)[mapping.first] = mapping.second;
    } else if (change_state[mapping.first] == ChangeState::CHANGED) {
      (*changed)[mapping.first] = mapping.second;
    }
  }
}

class CollectFunctionLiterals final
    : public AstTraversalVisitor<CollectFunctionLiterals> {
 public:
  CollectFunctionLiterals(Isolate* isolate, AstNode* root)
      : AstTraversalVisitor<CollectFunctionLiterals>(isolate, root) {}
  void VisitFunctionLiteral(FunctionLiteral* lit) {
    AstTraversalVisitor::VisitFunctionLiteral(lit);
    literals_->push_back(lit);
  }
  void Run(std::vector<FunctionLiteral*>* literals) {
    literals_ = literals;
    AstTraversalVisitor::Run();
    literals_ = nullptr;
  }

 private:
  std::vector<FunctionLiteral*>* literals_;
};

bool ParseScript(Isolate* isolate, Handle<Script> script, ParseInfo* parse_info,
                 MaybeHandle<ScopeInfo> outer_scope_info, bool compile_as_well,
                 std::vector<FunctionLiteral*>* literals,
                 debug::LiveEditResult* result) {
  v8::TryCatch try_catch(reinterpret_cast<v8::Isolate*>(isolate));
  Handle<SharedFunctionInfo> shared;
  bool success = false;
  if (compile_as_well) {
    success = Compiler::CompileForLiveEdit(parse_info, script, outer_scope_info,
                                           isolate)
                  .ToHandle(&shared);
  } else {
    success =
        parsing::ParseProgram(parse_info, script, outer_scope_info, isolate,
                              parsing::ReportStatisticsMode::kYes);
    if (!success) {
      // Throw the parser error.
      parse_info->pending_error_handler()->PrepareErrors(
          isolate, parse_info->ast_value_factory());
      parse_info->pending_error_handler()->ReportErrors(isolate, script);
    }
  }
  if (!success) {
    DCHECK(try_catch.HasCaught());
    result->message = try_catch.Message()->Get();
    i::DirectHandle<i::JSMessageObject> msg =
        Utils::OpenDirectHandle(*try_catch.Message());
    i::JSMessageObject::EnsureSourcePositionsAvailable(isolate, msg);
    result->line_number = msg->GetLineNumber();
    result->column_number = msg->GetColumnNumber();
    result->status = debug::LiveEditResult::COMPILE_ERROR;
    return false;
  }
  CollectFunctionLiterals(isolate, parse_info->literal()).Run(literals);
  return true;
}

struct FunctionData {
  explicit FunctionData(FunctionLiteral* literal)
      : literal(literal), stack_position(NOT_ON_STACK) {}

  FunctionLiteral* literal;
  MaybeHandle<SharedFunctionInfo> shared;
  std::vector<Handle<JSFunction>> js_functions;
  std::vector<Handle<JSGeneratorObject>> running_generators;
  // In case of multiple functions with different stack position, the latest
  // one (in the order below) is used, since it is the most restrictive.
  // This is important only for functions to be restarted.
  enum StackPosition { NOT_ON_STACK, ON_TOP_ONLY, ON_STACK };
  StackPosition stack_position;
};

class FunctionDataMap : public ThreadVisitor {
 public:
  void AddInterestingLiteral(int script_id, FunctionLiteral* literal) {
    map_.emplace(GetFuncId(script_id, literal), FunctionData{literal});
  }

  bool Lookup(Tagged<SharedFunctionInfo> sfi, FunctionData** data) {
    int start_position = sfi->StartPosition();
    if (!IsScript(sfi->script()) || start_position == -1) {
      return false;
    }
    Tagged<Script> script = Cast<Script>(sfi->script());
    return Lookup(GetFuncId(script->id(), sfi), data);
  }

  bool Lookup(DirectHandle<Script> script, FunctionLiteral* literal,
              FunctionData** data) {
    return Lookup(GetFuncId(script->id(), literal), data);
  }

  void Fill(Isolate* isolate) {
    {
      HeapObjectIterator iterator(isolate->heap(),
                                  HeapObjectIterator::kFilterUnreachable);
      for (Tagged<HeapObject> obj = iterator.Next(); !obj.is_null();
           obj = iterator.Next()) {
        if (IsSharedFunctionInfo(obj)) {
          Tagged<SharedFunctionInfo> sfi = Cast<SharedFunctionInfo>(obj);
          FunctionData* data = nullptr;
          if (!Lookup(sfi, &data)) continue;
          data->shared = handle(sfi, isolate);
        } else if (IsJSFunction(obj)) {
          Tagged<JSFunction> js_function = Cast<JSFunction>(obj);
          Tagged<SharedFunctionInfo> sfi = js_function->shared();
          FunctionData* data = nullptr;
          if (!Lookup(sfi, &data)) continue;
          data->js_functions.emplace_back(js_function, isolate);
        } else if (IsJSGeneratorObject(obj)) {
          Tagged<JSGeneratorObject> gen = Cast<JSGeneratorObject>(obj);
          if (gen->is_closed()) continue;
          Tagged<SharedFunctionInfo> sfi = gen->function()->shared();
          FunctionData* data = nullptr;
          if (!Lookup(sfi, &data)) continue;
          data->running_generators.emplace_back(gen, isolate);
        }
      }
    }

    // Visit the current thread stack.
    VisitCurrentThread(isolate);

    // Visit the stacks of all archived threads.
    isolate->thread_manager()->IterateArchivedThreads(this);
  }

 private:
  // Unique id for a function: script_id + start_position, where start_position
  // is special cased to -1 for top-level so that it does not overlap with a
  // function whose start position is 0.
  using FuncId = std::pair<int, int>;

  FuncId GetFuncId(int script_id, FunctionLiteral* literal) {
    int start_position = literal->start_position();
    if (literal->function_literal_id() == 0) {
      // This is the top-level script function literal, so special case its
      // start position
      DCHECK_EQ(start_position, 0);
      start_position = -1;
    }
    return FuncId(script_id, start_position);
  }

  FuncId GetFuncId(int script_id, Tagged<SharedFunctionInfo> sfi) {
    DCHECK_EQ(script_id, Cast<Script>(sfi->script())->id());
    int start_position = sfi->StartPosition();
    DCHECK_NE(start_position, -1);
    if (sfi->is_toplevel()) {
      // This is the top-level function, so special case its start position
      DCHECK_EQ(start_position, 0);
      start_position = -1;
    }
    return FuncId(script_id, start_position);
  }

  bool Lookup(FuncId id, FunctionData** data) {
    auto it = map_.find(id);
    if (it == map_.end()) return false;
    *data = &it->second;
    return true;
  }

  void VisitThread(Isolate* isolate, ThreadLocalTop* top) override {
    for (JavaScriptStackFrameIterator it(isolate, top); !it.done();
         it.Advance()) {
      std::vector<Handle<SharedFunctionInfo>> sfis;
      it.frame()->GetFunctions(&sfis);
      for (auto& sfi : sfis) {
        FunctionData* data = nullptr;
        if (!Lookup(*sfi, &data)) continue;
        data->stack_position = FunctionData::ON_STACK;
      }
    }
  }

  void VisitCurrentThread(Isolate* isolate) {
    // We allow live editing the function that's currently top-of-stack. But
    // only if no activation of that function is anywhere else on the stack.
    bool is_top = true;
    for (DebugStackTraceIterator it(isolate, /* index */ 0); !it.Done();
         it.Advance(), is_top = false) {
      auto sfi = it.GetSharedFunctionInfo();
      if (sfi.is_null()) continue;
      FunctionData* data = nullptr;
      if (!Lookup(*sfi, &data)) continue;

      // ON_TOP_ONLY will only be set on the first iteration (and if the frame
      // can be restarted). Further activations will change the ON_TOP_ONLY to
      // ON_STACK and prevent the live edit from happening.
      data->stack_position = is_top && it.CanBeRestarted()
                                 ? FunctionData::ON_TOP_ONLY
                                 : FunctionData::ON_STACK;
    }
  }

  std::map<FuncId, FunctionData> map_;
};

bool CanPatchScript(const LiteralMap& changed, DirectHandle<Script> script,
                    DirectHandle<Script> new_script,
                    FunctionDataMap& function_data_map,
                    bool allow_top_frame_live_editing,
                    debug::LiveEditResult* result) {
  for (const auto& mapping : changed) {
    FunctionData* data = nullptr;
    function_data_map.Lookup(script, mapping.first, &data);
    FunctionData* new_data = nullptr;
    function_data_map.Lookup(new_script, mapping.second, &new_data);
    Handle<SharedFunctionInfo> sfi;
    if (!data->shared.ToHandle(&sfi)) {
      continue;
    } else if (IsModule(sfi->kind())) {
      DCHECK(script->origin_options().IsModule() && sfi->is_toplevel());
      result->status =
          debug::LiveEditResult::BLOCKED_BY_TOP_LEVEL_ES_MODULE_CHANGE;
      return false;
    } else if (data->stack_position == FunctionData::ON_STACK) {
      result->status = debug::LiveEditResult::BLOCKED_BY_ACTIVE_FUNCTION;
      return false;
    } else if (!data->running_generators.empty()) {
      result->status = debug::LiveEditResult::BLOCKED_BY_RUNNING_GENERATOR;
      return false;
    } else if (data->stack_position == FunctionData::ON_TOP_ONLY) {
      if (!allow_top_frame_live_editing) {
        result->status = debug::LiveEditResult::BLOCKED_BY_ACTIVE_FUNCTION;
        return false;
      }
      result->restart_top_frame_required = true;
    }
  }
  return true;
}

void TranslateSourcePositionTable(Isolate* isolate,
                                  DirectHandle<BytecodeArray> code,
                                  const std::vector<SourceChangeRange>& diffs) {
  Zone zone(isolate->allocator(), ZONE_NAME);
  SourcePositionTableBuilder builder(&zone);

  DirectHandle<TrustedByteArray> source_position_table(
      code->SourcePositionTable(), isolate);
  for (SourcePositionTableIterator iterator(*source_position_table);
       !iterator.done(); iterator.Advance()) {
    SourcePosition position = iterator.source_position();
    position.SetScriptOffset(
        LiveEdit::TranslatePosition(diffs, position.ScriptOffset()));
    builder.AddPosition(iterator.code_offset(), position,
                        iterator.is_statement());
  }

  DirectHandle<TrustedByteArray> new_source_position_table(
      builder.ToSourcePositionTable(isolate));
  code->set_source_position_table(*new_source_position_table, kReleaseStore);
  LOG_CODE_EVENT(isolate,
                 CodeLinePosInfoRecordEvent(code->GetFirstBytecodeAddress(),
                                            *new_source_position_table,
                                            JitCodeEvent::BYTE_CODE));
}

void UpdatePositions(Isolate* isolate, DirectHandle<SharedFunctionInfo> sfi,
                     FunctionLiteral* new_function,
                     const std::vector<SourceChangeRange>& diffs) {
  sfi->UpdateFromFunctionLiteralForLiveEdit(isolate, new_function);
  if (sfi->HasBytecodeArray()) {
    TranslateSourcePositionTable(
        isolate, direct_handle(sfi->GetBytecodeArray(isolate), isolate), diffs);
  }
}

#ifdef DEBUG
Tagged<ScopeInfo> FindOuterScopeInfoFromScriptSfi(Isolate* isolate,
                                                  DirectHandle<Script> script) {
  // We take some SFI from the script and walk outwards until we find the
  // EVAL_SCOPE. Then we do the same search as `DetermineOuterScopeInfo` and
  // check that we found the same ScopeInfo.
  SharedFunctionInfo::ScriptIterator it(isolate, *script);
  Tagged<ScopeInfo> other_scope_info;
  for (Tagged<SharedFunctionInfo> sfi = it.Next(); !sfi.is_null();
       sfi = it.Next()) {
    if (!sfi->scope_info()->IsEmpty()) {
      other_scope_info = sfi->scope_info();
      break;
    }
  }
  if (other_scope_info.is_null()) return other_scope_info;

  while (!other_scope_info->IsEmpty() &&
         other_scope_info->scope_type() != EVAL_SCOPE &&
         other_scope_info->HasOuterScopeInfo()) {
    other_scope_info = other_scope_info->OuterScopeInfo();
  }

  // This function is only called when we found a ScopeInfo candidate, so
  // technically the EVAL_SCOPE must have an outer_scope_info. But, the GC can
  // clean up some ScopeInfos it thinks are no longer needed. Abort the check
  // in that case.
  if (!other_scope_info->HasOuterScopeInfo()) return ScopeInfo();

  DCHECK_EQ(other_scope_info->scope_type(), EVAL_SCOPE);
  other_scope_info = other_scope_info->OuterScopeInfo();

  while (!other_scope_info->IsEmpty() && !other_scope_info->HasContext() &&
         other_scope_info->HasOuterScopeInfo()) {
    other_scope_info = other_scope_info->OuterScopeInfo();
  }
  return other_scope_info;
}
#endif

// For sloppy eval we need to know the ScopeInfo the eval was compiled in and
// re-use it when we compile the new version of the script.
MaybeHandle<ScopeInfo> DetermineOuterScopeInfo(Isolate* isolate,
                                               DirectHandle<Script> script) {
  if (!script->has_eval_from_shared()) return kNullMaybeHandle;
  DCHECK_EQ(script->compilation_type(), Script::CompilationType::kEval);
  Tagged<ScopeInfo> scope_info = script->eval_from_shared()->scope_info();
  // Sloppy eval compiles use the ScopeInfo of the context. Let's find it.
  while (!scope_info->IsEmpty()) {
    if (scope_info->HasContext()) {
#ifdef DEBUG
      Tagged<ScopeInfo> other_scope_info =
          FindOuterScopeInfoFromScriptSfi(isolate, script);
      DCHECK_IMPLIES(!other_scope_info.is_null(),
                     scope_info == other_scope_info);
#endif
      return handle(scope_info, isolate);
    } else if (!scope_info->HasOuterScopeInfo()) {
      break;
    }
    scope_info = scope_info->OuterScopeInfo();
  }

  return kNullMaybeHandle;
}

}  // anonymous namespace

void LiveEdit::PatchScript(Isolate* isolate, Handle<Script> script,
                           Handle<String> new_source, bool preview,
                           bool allow_top_frame_live_editing,
                           debug::LiveEditResult* result) {
  std::vector<SourceChangeRange> diffs;
  LiveEdit::CompareStrings(isolate,
                           handle(Cast<String>(script->source()), isolate),
                           new_source, &diffs);
  if (diffs.empty()) {
    result->status = debug::LiveEditResult::OK;
    return;
  }

  ReusableUnoptimizedCompileState reusable_state(isolate);

  UnoptimizedCompileState compile_state;
  UnoptimizedCompileFlags flags =
      UnoptimizedCompileFlags::ForScriptCompile(isolate, *script);
  flags.set_is_eager(true);
  flags.set_is_reparse(true);
  ParseInfo parse_info(isolate, flags, &compile_state, &reusable_state);
  MaybeHandle<ScopeInfo> outer_scope_info =
      DetermineOuterScopeInfo(isolate, script);
  std::vector<FunctionLiteral*> literals;
  if (!ParseScript(isolate, script, &parse_info, outer_scope_info, false,
                   &literals, result))
    return;

  Handle<Script> new_script =
      isolate->factory()->CloneScript(script, new_source);
  UnoptimizedCompileState new_compile_state;
  UnoptimizedCompileFlags new_flags =
      UnoptimizedCompileFlags::ForScriptCompile(isolate, *new_script);
  new_flags.set_is_eager(true);
  Pa
```