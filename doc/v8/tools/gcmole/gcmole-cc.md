Response:
Let's break down the thought process for analyzing this C++ code snippet.

**1. Initial Scan and Keyword Recognition:**

The first step is a quick skim of the code, looking for obvious keywords and patterns. I see:

* `#include`:  Indicates standard C++ and Clang libraries are being used. Specific headers like `<fstream>`, `<iostream>`, `<map>`, `<set>`, and Clang headers like `"clang/AST/...`", `"clang/Frontend/..."` immediately suggest interaction with the Clang compiler's abstract syntax tree (AST).
* `namespace`:  The `namespace { ... }` block indicates local definitions.
* Macros like `TRACE`, `TRACE_LLVM_TYPE`, `TRACE_LLVM_DECL`: These are debugging/logging aids, suggesting the code might be complex and needs tracing. The `g_tracing_enabled` flag confirms this.
* Type definitions like `MangledName`, `CalleesSet`, `CalleesMap`: These suggest the code is working with function names, likely in their mangled form (used by compilers for overloading and namespaces).
* Function definitions with `Visit...`: This strongly points towards a visitor pattern, common for traversing tree-like structures (like the AST).
* Class definitions like `CalleesPrinter`, `FunctionDeclarationFinder`, `Environment`, `ExprEffect`, `FunctionAnalyzer`:  These suggest a structured approach to the analysis.
* Global variables like `gc_suspects_loaded`, `gc_suspects`, `gc_functions`: These hint at loading data from external files. The names suggest these files contain information about functions that might cause garbage collection.
* Comments mentioning "gcmole": The very first comment and the plugin description confirm this is part of the `gcmole` tool.
* Terms like "GC", "Garbage Collection", "VMState", "HeapObject", "Smi", "TaggedIndex": These are strong indicators that the code is related to garbage collection and memory management within a virtual machine (likely V8).

**2. Understanding the Core Purpose (Deduction from Keywords and Structure):**

Based on the above, I can formulate an initial hypothesis:  This C++ code is a Clang plugin (`gcmole`) designed to analyze C++ code (specifically V8's C++) related to garbage collection. It likely examines function calls and data flow to identify potential issues or areas of interest related to GC.

**3. Deeper Dive into Key Components:**

Now, I look closer at the main classes and their responsibilities:

* **`CalleesPrinter`:**  The name and the `VisitCallExpr` method strongly suggest this class builds a call graph. It tracks which functions call which other functions. The use of mangled names confirms it's dealing with the compiled representation of functions.
* **`FunctionDeclarationFinder`:**  This class seems to be the entry point of the plugin. It uses `CalleesPrinter` to build the call graph. The `HandleTranslationUnit` method confirms it processes the entire compilation unit.
* **Loading `gcsuspects`, `gccauses`, `suspects.allowlist`:**  The functions `LoadGCSuspects`, `LoadGCCauses`, and `LoadSuspectsAllowList` clearly indicate that the tool uses external data files to identify functions known or suspected to cause garbage collection and to have an allowlist for ignoring certain suspects.
* **`Environment` and `ExprEffect`:** These classes seem crucial for tracking the state of variables and the effects of expressions, particularly in relation to garbage collection. The `IsAlive` method in `Environment` is a key piece of evidence for this. `ExprEffect` tracks whether an expression might trigger GC (`hasGC`).
* **`FunctionAnalyzer`:** This class appears to be the core logic for analyzing the functions. Its `VisitExpr` methods (using the visitor pattern) and the handling of different expression types strongly indicate a detailed analysis of the code's semantics. The interaction with `Environment` and `ExprEffect` suggests it's trying to reason about how GC might affect the execution of code.

**4. Connecting the Dots and Inferring Functionality:**

By understanding the individual components, I can now start to connect the dots and refine my understanding of the overall functionality:

* **Call Graph Generation:** `CalleesPrinter` creates a call graph of V8 functions.
* **Identifying GC Suspects:** The tool uses lists of known and suspected GC-causing functions.
* **Data Flow Analysis:**  `Environment` and `ExprEffect` are used to track the "liveness" of variables and the potential for GC to occur within expressions. This helps identify situations where a variable might become stale due to a GC.
* **Detecting Unsafe GC Interactions:** The checks in `FunctionAnalyzer` for `IsSafe` and the reporting of `BAD_EXPR_MSG` and `DEAD_VAR_MSG` suggest the tool is trying to find coding patterns that are problematic in the presence of garbage collection.

**5. Addressing the Specific Questions:**

Now I can directly address the questions in the prompt:

* **Functionality:** Summarize the above deductions.
* **`.tq` extension:** The code clearly uses `.cc` and includes C++ headers, so it's C++, not Torque.
* **Relationship to JavaScript:**  The mentions of "v8" and garbage collection strongly tie this to the V8 JavaScript engine. I can provide JavaScript examples where garbage collection is relevant (e.g., object creation and disposal).
* **Code Logic Inference:** I can create simple examples to illustrate how the `Environment` and `ExprEffect` might track variable liveness and GC effects.
* **Common Programming Errors:** I can identify typical errors related to manual memory management (although V8 is garbage-collected) or potential issues with object lifetimes and GC interference.

**6. Iteration and Refinement (Self-Correction):**

During the process, I might encounter details that require adjusting my understanding. For example, initially, I might focus too much on manual memory management, but realizing it's V8, I need to shift the focus to how GC interacts with object references and potential "stale" variable issues. The comments within the code itself provide valuable clues and can help correct initial assumptions.

By following these steps, combining keyword recognition, structural analysis, and logical deduction, I can arrive at a comprehensive understanding of the `gcmole.cc` code and accurately answer the questions in the prompt.
`v8/tools/gcmole/gcmole.cc` 是一个 V8 源代码文件，它是一个 Clang 插件，用于 `gcmole` 工具。这个工具的主要目的是分析 V8 的 C++ 代码，特别是与垃圾回收（Garbage Collection，GC）相关的部分，并帮助开发者识别潜在的 GC 安全问题。

根据代码内容，我们可以归纳出 `gcmole.cc` 的以下功能：

**核心功能：静态分析 V8 C++ 代码，识别潜在的 GC 安全问题。**

**详细功能点：**

1. **构建函数调用图 (Call Graph)：**
   - 通过 `CalleesPrinter` 类，遍历抽象语法树 (AST)，识别函数调用关系。
   - 记录哪些函数调用了其他函数，并将这些调用关系存储在 `callgraph_` 中。
   - 使用 mangled name (编译后的函数名) 来唯一标识函数。

2. **识别已知的 GC 触发函数 (GC Suspects)：**
   - 加载外部文件 `gcsuspects`，其中包含了已知会触发 GC 的函数的 mangled name。
   - `IsKnownToCauseGC` 函数会检查当前分析的函数是否在这些已知列表中。

3. **识别疑似的 GC 触发函数 (Suspected GC Functions)：**
   - 加载外部文件 `gcsuspects`，其中也包含了函数的名字。
   - `IsSuspectedToCauseGC` 函数会检查当前分析的函数的名字是否在这些疑似列表中。

4. **识别 GC 触发链 (GC Causes)：**
   - 加载外部文件 `gccauses`，其中定义了函数调用链，这些调用链最终会导致 GC。

5. **跟踪变量的“活跃”状态 (Variable Liveness Tracking)：**
   - 使用 `Environment` 类来维护一个符号表，记录变量是否“活跃”。
   - “活跃”意味着变量在 GC 发生后仍然有效。
   - `ExprEffect` 类表示表达式的副作用，包括是否可能触发 GC，以及是否读写了变量。

6. **分析表达式的 GC 副作用：**
   - `FunctionAnalyzer` 类使用 Visitor 模式遍历表达式。
   - 对于不同的表达式类型（如函数调用、变量引用、运算符等），分析其是否可能触发 GC，以及对变量的影响。

7. **检测潜在的 GC 不安全代码：**
   - **乱序求值 (Out-of-order Evaluation)：**  当表达式的子表达式求值顺序不确定，且其中一些表达式可能触发 GC 时，可能会导致问题。`Parallel` 函数用于处理这种情况，并使用 `CallProps` 类来跟踪参数的 GC 副作用。
   - **悬垂指针/失效变量 (Stale Variables)：** 如果一个变量指向堆上的对象，而在 GC 发生后，该对象可能被移动或回收，导致变量指向无效的内存。`Use` 函数会检查变量的活跃状态，如果变量不再活跃，则可能报告一个警告。

8. **处理特定的 V8 类型：**
   - 特别关注 V8 的内部类型，例如 `HeapObject`，`Smi` (Small Integer)，`TaggedIndex` 和 `Tagged`。

**如果 `v8/tools/gcmole/gcmole.cc` 以 `.tq` 结尾，那它是个 v8 torque 源代码：**

当前给出的代码片段是 C++ 代码 (`.cc`)，而不是 Torque 代码 (`.tq`)。Torque 是 V8 用于定义运行时函数的领域特定语言。

**如果它与 javascript 的功能有关系，请用 javascript 举例说明：**

`gcmole.cc` 分析的是 V8 的 **C++** 源代码，而 V8 是执行 JavaScript 的引擎。因此，`gcmole.cc` 的功能直接关系到 JavaScript 的内存管理和性能。

例如，在 JavaScript 中创建对象：

```javascript
let obj = {};
```

当 JavaScript 引擎执行这段代码时，V8 会在堆上分配内存来存储这个对象。垃圾回收器负责周期性地回收不再使用的对象所占用的内存。

`gcmole.cc` 旨在帮助 V8 开发者确保在 V8 的 C++ 代码中，与垃圾回收器交互的部分是安全的，不会导致程序崩溃或出现未定义的行为。例如，如果一个 C++ 函数在 GC 发生后仍然持有指向已回收对象的指针，这就是一个潜在的 GC 安全问题，`gcmole` 可能会检测到。

**如果有代码逻辑推理，请给出假设输入与输出：**

假设有以下 V8 C++ 代码片段（简化）：

```c++
namespace v8::internal {

class HeapObject {};

HeapObject* global_object;

void AllocateObject() {
  global_object = new HeapObject();
}

HeapObject* GetGlobalObject() {
  return global_object;
}

void MaybeTriggerGC() {
  // 模拟可能触发 GC 的操作
  printf("Maybe triggering GC...\n");
}

void UseGlobalObject() {
  HeapObject* obj = GetGlobalObject();
  MaybeTriggerGC(); // GC 可能在这里发生
  printf("Using global object: %p\n", obj);
}

} // namespace v8::internal
```

**假设输入：**  `gcmole` 插件分析包含以上代码的 V8 源代码文件。

**可能的输出（`gcmole` 可能会报告的警告）：**

```
[Warning] Potential GC safety issue in v8::internal::UseGlobalObject:
  Possibly stale variable due to GCs. (DEAD_VAR_MSG)
```

**推理过程：**

1. `gcmole` 会分析 `UseGlobalObject` 函数。
2. 它会识别 `GetGlobalObject()` 的返回值被赋给了局部变量 `obj`。
3. `gcmole` 会注意到 `MaybeTriggerGC()` 函数可能触发垃圾回收。
4. 如果 `HeapObject` 是一个需要 GC 管理的类型，那么在 `MaybeTriggerGC()` 执行期间，如果 `global_object` 指向的对象不再被其他强引用持有，GC 可能回收它。
5. 在 `MaybeTriggerGC()` 执行完毕后，`obj` 仍然持有之前获取的指针。如果 GC 确实发生了并且回收了 `global_object` 指向的对象，那么 `obj` 就变成了一个悬垂指针。
6. 随后的 `printf` 语句访问 `obj` 可能会导致问题。
7. `gcmole` 通过跟踪变量的活跃状态，可能会检测到在调用 `MaybeTriggerGC()` 之后，`obj` 所指向的对象可能不再安全访问，并发出警告。

**如果涉及用户常见的编程错误，请举例说明：**

用户在编写 V8 的 C++ 代码时，常见的与 GC 相关的编程错误包括：

1. **在可能发生 GC 的操作后，继续使用本地持有的指向堆对象的原始指针。**

   ```c++
   void ProcessObject(v8::internal::HeapObject* obj) {
     // ... 一些操作 ...
     v8::internal::MaybeGarbageCollect(); // 可能触发 GC
     // ... 错误地继续使用 obj，如果 GC 发生了，obj 可能失效 ...
     obj->Print();
   }
   ```

2. **在回调函数或闭包中捕获指向堆对象的原始指针，并在 GC 发生后使用。**

   ```c++
   v8::internal::HeapObject* my_object;

   void SetCallback(std::function<void()> callback) {
     callback(); // 错误：my_object 可能在 callback 执行时已经失效
   }

   void Setup() {
     my_object = new v8::internal::HeapObject();
     SetCallback([my_object]() {
       // ... 尝试使用 my_object ...
       my_object->Print();
     });
     v8::internal::MaybeGarbageCollect(); // my_object 可能在这里被回收
   }
   ```

3. **在数据结构中存储指向堆对象的原始指针，而没有适当的生命周期管理。**

   ```c++
   std::vector<v8::internal::HeapObject*> object_list;

   void AddObject(v8::internal::HeapObject* obj) {
     object_list.push_back(obj);
   }

   void ProcessList() {
     v8::internal::MaybeGarbageCollect();
     for (auto obj : object_list) {
       // ... 如果某些 obj 指向的对象已被回收，这里会出错 ...
       obj->Print();
     }
   }
   ```

`gcmole` 旨在帮助开发者避免这些常见的错误，通过静态分析提前发现潜在的 GC 安全隐患。

**总结一下它的功能 (第 1 部分)：**

`v8/tools/gcmole/gcmole.cc` 的主要功能是作为一个 Clang 插件，对 V8 的 C++ 源代码进行静态分析，特别是关注与垃圾回收相关的代码。它通过构建函数调用图、识别已知的和疑似的 GC 触发函数、跟踪变量的活跃状态以及分析表达式的 GC 副作用，来检测潜在的 GC 安全问题，例如在可能发生 GC 的操作后继续使用本地持有的指向堆对象的原始指针，从而帮助 V8 开发者编写更健壮和可靠的代码。

Prompt: 
```
这是目录为v8/tools/gcmole/gcmole.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/tools/gcmole/gcmole.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2011 the V8 project authors. All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
//       copyright notice, this list of conditions and the following
//       disclaimer in the documentation and/or other materials provided
//       with the distribution.
//     * Neither the name of Google Inc. nor the names of its
//       contributors may be used to endorse or promote products derived
//       from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// This is clang plugin used by gcmole tool. See README for more details.

#include <bitset>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <stack>

#include "clang/AST/APValue.h"
#include "clang/AST/AST.h"
#include "clang/AST/ASTConsumer.h"
#include "clang/AST/DeclCXX.h"
#include "clang/AST/DeclTemplate.h"
#include "clang/AST/Mangle.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/StmtVisitor.h"
#include "clang/AST/TemplateBase.h"
#include "clang/Basic/FileManager.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendPluginRegistry.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/LineIterator.h"
#include "llvm/Support/raw_ostream.h"

namespace {

bool g_tracing_enabled = false;
bool g_dead_vars_analysis = false;
bool g_verbose = false;
bool g_print_gc_call_chain = false;

#define TRACE(str)                   \
  do {                               \
    if (g_tracing_enabled) {         \
      std::cout << str << std::endl; \
    }                                \
  } while (false)

#define TRACE_LLVM_TYPE(str, type)                                \
  do {                                                            \
    if (g_tracing_enabled) {                                      \
      std::cout << str << " " << type.getAsString() << std::endl; \
    }                                                             \
  } while (false)

// Node: The following is used when tracing --dead-vars
// to provide extra info for the GC suspect.
#define TRACE_LLVM_DECL(str, decl)                   \
  do {                                               \
    if (g_tracing_enabled && g_dead_vars_analysis) { \
      std::cout << str << std::endl;                 \
      decl->dump();                                  \
    }                                                \
  } while (false)

typedef std::string MangledName;
typedef std::set<MangledName> CalleesSet;
typedef std::map<MangledName, MangledName> CalleesMap;

static bool GetMangledName(clang::MangleContext* ctx,
                           const clang::NamedDecl* decl, MangledName* result) {
  if (llvm::isa<clang::CXXConstructorDecl>(decl)) return false;
  if (llvm::isa<clang::CXXDestructorDecl>(decl)) return false;
  if (llvm::isa<clang::CXXDeductionGuideDecl>(decl)) return false;
  llvm::SmallVector<char, 512> output;
  llvm::raw_svector_ostream out(output);
  ctx->mangleName(decl, out);
  *result = out.str().str();
  return true;
}

static bool InV8Namespace(const clang::NamedDecl* decl) {
  return decl->getQualifiedNameAsString().compare(0, 4, "v8::") == 0;
}

static std::string EXTERNAL("EXTERNAL");
static std::string STATE_TAG("enum v8::internal::StateTag");

static bool IsExternalVMState(const clang::ValueDecl* var) {
  const clang::EnumConstantDecl* enum_constant =
      llvm::dyn_cast<clang::EnumConstantDecl>(var);
  if (enum_constant != nullptr &&
      enum_constant->getNameAsString() == EXTERNAL) {
    clang::QualType type = enum_constant->getType();
    return (type.getAsString() == STATE_TAG);
  }

  return false;
}

struct Resolver {
  explicit Resolver(clang::ASTContext& ctx)
      : ctx_(ctx), decl_ctx_(ctx.getTranslationUnitDecl()) {}

  Resolver(clang::ASTContext& ctx, clang::DeclContext* decl_ctx)
      : ctx_(ctx), decl_ctx_(decl_ctx) {}

  clang::DeclarationName ResolveName(const char* n) {
    clang::IdentifierInfo* ident = &ctx_.Idents.get(n);
    return ctx_.DeclarationNames.getIdentifier(ident);
  }

  Resolver ResolveNamespace(const char* n) {
    return Resolver(ctx_, Resolve<clang::NamespaceDecl>(n));
  }

  template <typename T>
  T* Resolve(const char* n) {
    if (decl_ctx_ == nullptr) return nullptr;

    clang::DeclContext::lookup_result result =
        decl_ctx_->lookup(ResolveName(n));

    clang::DeclContext::lookup_iterator end = result.end();
    for (clang::DeclContext::lookup_iterator i = result.begin(); i != end;
         i++) {
      clang::NamedDecl* decl = *i;

      // Try to strip off any type aliases.
      const clang::TypeAliasDecl* type_alias_decl =
          llvm::dyn_cast_or_null<clang::TypeAliasDecl>(decl);
      if (type_alias_decl) {
        clang::QualType underlying_type = type_alias_decl->getUnderlyingType();
        clang::QualType desugared_type = underlying_type.getDesugaredType(ctx_);
        clang::TagDecl* tag_decl = desugared_type->getAsTagDecl();
        if (!tag_decl) {
          llvm::errs() << "Couldn't resolve target decl of type alias "
                       << decl->getNameAsString() << "\n";
          decl->dump();
          return nullptr;
        }
        decl = tag_decl;
      }

      if (llvm::isa<T>(decl)) {
        return llvm::cast<T>(decl);
      }

      llvm::errs() << "Didn't match declaration template for " << n
                   << " against " << decl->getNameAsString() << "\n";
      decl->dump();
    }

    return nullptr;
  }

 private:
  clang::ASTContext& ctx_;
  clang::DeclContext* decl_ctx_;
};

class CalleesPrinter : public clang::RecursiveASTVisitor<CalleesPrinter> {
 public:
  explicit CalleesPrinter(clang::MangleContext* ctx) : ctx_(ctx) {}

  virtual bool VisitCallExpr(clang::CallExpr* expr) {
    const clang::FunctionDecl* callee = expr->getDirectCallee();
    if (callee != nullptr) AnalyzeFunction(callee);
    return true;
  }

  virtual bool VisitDeclRefExpr(clang::DeclRefExpr* expr) {
    // If function mentions EXTERNAL VMState add artificial garbage collection
    // mark.
    if (IsExternalVMState(expr->getDecl())) {
      AddCallee("CollectGarbage", "CollectGarbage");
    }
    return true;
  }

  void AnalyzeFunction(const clang::FunctionDecl* f) {
    if (!InV8Namespace(f)) return;
    MangledName name;
    if (!GetMangledName(ctx_, f, &name)) return;
    const std::string& function = f->getNameAsString();
    AddCallee(name, function);

    const clang::FunctionDecl* body = nullptr;
    if (f->hasBody(body) && !Analyzed(name)) {
      EnterScope(name);
      TraverseStmt(body->getBody());
      LeaveScope();
    }
  }

  typedef std::map<MangledName, CalleesSet*> Callgraph;

  bool Analyzed(const MangledName& name) { return callgraph_[name] != nullptr; }

  void EnterScope(const MangledName& name) {
    CalleesSet* callees = callgraph_[name];

    if (callees == nullptr) {
      callgraph_[name] = callees = new CalleesSet();
    }

    scopes_.push(callees);
  }

  void LeaveScope() { scopes_.pop(); }

  void AddCallee(const MangledName& name, const MangledName& function) {
    if (!scopes_.empty()) scopes_.top()->insert(name);
    mangled_to_function_[name] = function;
  }

  void PrintCallGraph() {
    for (Callgraph::const_iterator i = callgraph_.begin(), e = callgraph_.end();
         i != e; ++i) {
      std::cout << i->first << "," << mangled_to_function_[i->first] << "\n";

      CalleesSet* callees = i->second;
      for (CalleesSet::const_iterator j = callees->begin(), e = callees->end();
           j != e; ++j) {
        std::cout << "\t" << *j << "," << mangled_to_function_[*j] << "\n";
      }
    }
  }

 private:
  clang::MangleContext* ctx_;

  std::stack<CalleesSet*> scopes_;
  Callgraph callgraph_;
  CalleesMap mangled_to_function_;
};

class FunctionDeclarationFinder
    : public clang::ASTConsumer,
      public clang::RecursiveASTVisitor<FunctionDeclarationFinder> {
 public:
  explicit FunctionDeclarationFinder(
      clang::DiagnosticsEngine& diagnostics_engine,
      clang::SourceManager& source_manager,
      const std::vector<std::string>& args)
      : diagnostics_engine_(diagnostics_engine),
        source_manager_(source_manager) {}

  void HandleTranslationUnit(clang::ASTContext& ctx) override {
    mangle_context_ =
        clang::ItaniumMangleContext::create(ctx, diagnostics_engine_);
    callees_printer_ = new CalleesPrinter(mangle_context_);
    TraverseDecl(ctx.getTranslationUnitDecl());
    callees_printer_->PrintCallGraph();
  }

  virtual bool VisitFunctionDecl(clang::FunctionDecl* decl) {
    callees_printer_->AnalyzeFunction(decl);
    return true;
  }

 private:
  clang::DiagnosticsEngine& diagnostics_engine_;
  clang::SourceManager& source_manager_;
  clang::MangleContext* mangle_context_;

  CalleesPrinter* callees_printer_;
};

static bool gc_suspects_loaded = false;
static CalleesSet gc_suspects;
static CalleesSet gc_functions;

static bool allowlist_loaded = false;
static CalleesSet suspects_allowlist;

static bool gc_causes_loaded = false;
static std::map<MangledName, std::vector<MangledName>> gc_causes;

static void LoadGCCauses() {
  if (gc_causes_loaded) return;
  std::ifstream fin("gccauses");
  std::string mangled, function;
  while (!fin.eof()) {
    std::getline(fin, mangled, ',');
    std::getline(fin, function);
    if (mangled.empty()) break;
    std::string parent = mangled;
    // start,nested
    std::getline(fin, mangled, ',');
    assert(mangled.compare("start") == 0);
    std::getline(fin, function);
    assert(function.compare("nested") == 0);
    while (true) {
      std::getline(fin, mangled, ',');
      std::getline(fin, function);
      if (mangled.compare("end") == 0) {
        assert(function.compare("nested") == 0);
        break;
      }
      gc_causes[parent].push_back(mangled);
    }
  }
  gc_causes_loaded = true;
}

static void LoadGCSuspects() {
  if (gc_suspects_loaded) return;

  std::ifstream fin("gcsuspects");
  std::string mangled, function;

  while (!fin.eof()) {
    std::getline(fin, mangled, ',');
    gc_suspects.insert(mangled);
    std::getline(fin, function);
    gc_functions.insert(function);
  }

  gc_suspects_loaded = true;
}

static void LoadSuspectsAllowList() {
  if (allowlist_loaded) return;

  // TODO(cbruni): clean up once fully migrated
  std::ifstream fin("tools/gcmole/suspects.allowlist");
  std::string s;

  while (fin >> s) suspects_allowlist.insert(s);

  allowlist_loaded = true;
}

// Looks for exact match of the mangled name.
static bool IsKnownToCauseGC(clang::MangleContext* ctx,
                             const clang::FunctionDecl* decl) {
  LoadGCSuspects();
  if (!InV8Namespace(decl)) return false;
  if (suspects_allowlist.find(decl->getNameAsString()) !=
      suspects_allowlist.end()) {
    return false;
  }
  MangledName name;
  if (GetMangledName(ctx, decl, &name)) {
    return gc_suspects.find(name) != gc_suspects.end();
  }
  return false;
}

// Looks for partial match of only the function name.
static bool IsSuspectedToCauseGC(clang::MangleContext* ctx,
                                 const clang::FunctionDecl* decl) {
  LoadGCSuspects();
  if (!InV8Namespace(decl)) return false;
  LoadSuspectsAllowList();
  if (suspects_allowlist.find(decl->getNameAsString()) !=
      suspects_allowlist.end()) {
    return false;
  }
  if (gc_functions.find(decl->getNameAsString()) != gc_functions.end()) {
    TRACE_LLVM_DECL("Suspected by ", decl);
    return true;
  }
  return false;
}

static const int kNoEffect = 0;
static const int kCausesGC = 1;
static const int kRawDef = 2;
static const int kRawUse = 4;
static const int kAllEffects = kCausesGC | kRawDef | kRawUse;

class Environment;

class ExprEffect {
 public:
  bool hasGC() { return (effect_ & kCausesGC) != 0; }
  void setGC() { effect_ |= kCausesGC; }

  bool hasRawDef() { return (effect_ & kRawDef) != 0; }
  void setRawDef() { effect_ |= kRawDef; }

  bool hasRawUse() { return (effect_ & kRawUse) != 0; }
  void setRawUse() { effect_ |= kRawUse; }

  static ExprEffect None() { return ExprEffect(kNoEffect, nullptr); }
  static ExprEffect NoneWithEnv(Environment* env) {
    return ExprEffect(kNoEffect, env);
  }
  static ExprEffect RawUse() { return ExprEffect(kRawUse, nullptr); }

  static ExprEffect Merge(ExprEffect a, ExprEffect b);
  static ExprEffect MergeSeq(ExprEffect a, ExprEffect b);
  ExprEffect Define(const std::string& name);

  Environment* env() {
    return reinterpret_cast<Environment*>(effect_ & ~kAllEffects);
  }

  static ExprEffect GC() { return ExprEffect(kCausesGC, nullptr); }

 private:
  ExprEffect(int effect, Environment* env)
      : effect_((effect & kAllEffects) | reinterpret_cast<intptr_t>(env)) {}

  intptr_t effect_;
};

const std::string BAD_EXPR_MSG(
    "Possible problem with evaluation order with interleaved GCs.");
const std::string DEAD_VAR_MSG("Possibly stale variable due to GCs.");

class Environment {
 public:
  Environment() = default;

  static Environment Unreachable() {
    Environment env;
    env.unreachable_ = true;
    return env;
  }

  static Environment Merge(const Environment& l, const Environment& r) {
    Environment out(l);
    out &= r;
    return out;
  }

  Environment ApplyEffect(ExprEffect effect) const {
    Environment out = effect.hasGC() ? Environment() : Environment(*this);
    if (effect.env()) out |= *effect.env();
    return out;
  }

  typedef std::map<std::string, int> SymbolTable;

  bool IsAlive(const std::string& name) const {
    SymbolTable::iterator code = symbol_table_.find(name);
    if (code == symbol_table_.end()) return false;
    return is_live(code->second);
  }

  bool Equal(const Environment& env) {
    if (unreachable_ && env.unreachable_) return true;
    size_t size = std::max(live_.size(), env.live_.size());
    for (size_t i = 0; i < size; ++i) {
      if (is_live(i) != env.is_live(i)) return false;
    }
    return true;
  }

  Environment Define(const std::string& name) const {
    return Environment(*this, SymbolToCode(name));
  }

  void MDefine(const std::string& name) { set_live(SymbolToCode(name)); }

  static int SymbolToCode(const std::string& name) {
    SymbolTable::iterator code = symbol_table_.find(name);

    if (code == symbol_table_.end()) {
      int new_code = symbol_table_.size();
      symbol_table_.insert(std::make_pair(name, new_code));
      return new_code;
    }

    return code->second;
  }

  static void ClearSymbolTable() {
    for (Environment* e : envs_) delete e;
    envs_.clear();
    symbol_table_.clear();
  }

  void Print() const {
    bool comma = false;
    std::cout << "{";
    for (auto& e : symbol_table_) {
      if (!is_live(e.second)) continue;
      if (comma) std::cout << ", ";
      std::cout << e.first;
      comma = true;
    }
    std::cout << "}" << std::endl;
  }

  static Environment* Allocate(const Environment& env) {
    Environment* allocated_env = new Environment(env);
    envs_.push_back(allocated_env);
    return allocated_env;
  }

 private:
  Environment(const Environment& l, int code) : live_(l.live_) {
    set_live(code);
  }

  void set_live(size_t pos) {
    if (unreachable_) return;
    if (pos >= live_.size()) live_.resize(pos + 1);
    live_[pos] = true;
  }

  bool is_live(size_t pos) const {
    return unreachable_ || (live_.size() > pos && live_[pos]);
  }

  Environment& operator|=(const Environment& o) {
    if (o.unreachable_) {
      unreachable_ = true;
      live_.clear();
    } else if (!unreachable_) {
      for (size_t i = 0, e = o.live_.size(); i < e; ++i) {
        if (o.live_[i]) set_live(i);
      }
    }
    return *this;
  }

  Environment& operator&=(const Environment& o) {
    if (o.unreachable_) return *this;
    if (unreachable_) return *this = o;

    // Carry over false bits from the tail of o.live_, and reset all bits that
    // are not set in o.live_.
    size_t size = std::max(live_.size(), o.live_.size());
    if (size > live_.size()) live_.resize(size);
    for (size_t i = 0; i < size; ++i) {
      if (live_[i] && (i >= o.live_.size() || !o.live_[i])) live_[i] = false;
    }
    return *this;
  }

  static SymbolTable symbol_table_;
  static std::vector<Environment*> envs_;

  std::vector<bool> live_;
  // unreachable_ == true implies live_.empty(), but still is_live(i) returns
  // true for all i.
  bool unreachable_ = false;

  friend class ExprEffect;
  friend class CallProps;
};

class CallProps {
 public:
  CallProps() : env_(nullptr) {}

  void SetEffect(int arg, ExprEffect in) {
    if (in.hasGC()) {
      gc_.set(arg);
    }
    if (in.hasRawDef()) raw_def_.set(arg);
    if (in.hasRawUse()) raw_use_.set(arg);
    if (in.env() != nullptr) {
      if (env_ == nullptr) {
        env_ = in.env();
      } else {
        *env_ |= *in.env();
      }
    }
  }

  ExprEffect ComputeCumulativeEffect(bool result_is_raw) {
    ExprEffect out = ExprEffect::NoneWithEnv(env_);
    if (gc_.any()) out.setGC();
    if (raw_use_.any()) out.setRawUse();
    if (result_is_raw) out.setRawDef();
    return out;
  }

  bool IsSafe() {
    if (!gc_.any()) return true;
    std::bitset<kMaxNumberOfArguments> raw = (raw_def_ | raw_use_);
    if (!raw.any()) return true;
    bool result = gc_.count() == 1 && !((raw ^ gc_).any());
    return result;
  }

 private:
  static const int kMaxNumberOfArguments = 64;
  std::bitset<kMaxNumberOfArguments> raw_def_;
  std::bitset<kMaxNumberOfArguments> raw_use_;
  std::bitset<kMaxNumberOfArguments> gc_;
  Environment* env_;
};

Environment::SymbolTable Environment::symbol_table_;
std::vector<Environment*> Environment::envs_;

ExprEffect ExprEffect::Merge(ExprEffect a, ExprEffect b) {
  Environment* a_env = a.env();
  Environment* b_env = b.env();
  Environment* out = nullptr;
  if (a_env != nullptr && b_env != nullptr) {
    out = Environment::Allocate(*a_env);
    *out &= *b_env;
  }
  return ExprEffect(a.effect_ | b.effect_, out);
}

ExprEffect ExprEffect::MergeSeq(ExprEffect a, ExprEffect b) {
  Environment* a_env = b.hasGC() ? nullptr : a.env();
  Environment* b_env = b.env();
  Environment* out = (b_env == nullptr) ? a_env : b_env;
  if (a_env != nullptr && b_env != nullptr) {
    out = Environment::Allocate(*b_env);
    *out |= *a_env;
  }
  return ExprEffect(a.effect_ | b.effect_, out);
}

ExprEffect ExprEffect::Define(const std::string& name) {
  Environment* e = env();
  if (e == nullptr) {
    e = Environment::Allocate(Environment());
  }
  e->MDefine(name);
  return ExprEffect(effect_, e);
}

static std::string THIS("this");

class FunctionAnalyzer {
 public:
  FunctionAnalyzer(clang::MangleContext* ctx,
                   clang::CXXRecordDecl* heap_object_decl,
                   clang::CXXRecordDecl* smi_decl,
                   clang::CXXRecordDecl* tagged_index_decl,
                   clang::ClassTemplateDecl* tagged_decl,
                   clang::CXXRecordDecl* no_gc_mole_decl,
                   clang::DiagnosticsEngine& d, clang::SourceManager& sm)
      : ctx_(ctx),
        heap_object_decl_(heap_object_decl),
        smi_decl_(smi_decl),
        tagged_index_decl_(tagged_index_decl),
        tagged_decl_(tagged_decl),
        no_gc_mole_decl_(no_gc_mole_decl),
        d_(d),
        sm_(sm),
        block_(nullptr) {}

  // --------------------------------------------------------------------------
  // Expressions
  // --------------------------------------------------------------------------

  ExprEffect VisitExpr(clang::Expr* expr, const Environment& env) {
#define VISIT(type)                                                         \
  do {                                                                      \
    clang::type* concrete_expr = llvm::dyn_cast_or_null<clang::type>(expr); \
    if (concrete_expr != nullptr) {                                         \
      return Visit##type(concrete_expr, env);                               \
    }                                                                       \
  } while (0);

    VISIT(AbstractConditionalOperator);
    VISIT(AddrLabelExpr);
    VISIT(ArraySubscriptExpr);
    VISIT(BinaryOperator);
    VISIT(BlockExpr);
    VISIT(CallExpr);
    VISIT(CastExpr);
    VISIT(CharacterLiteral);
    VISIT(ChooseExpr);
    VISIT(CompoundLiteralExpr);
    VISIT(ConstantExpr);
    VISIT(CXXBindTemporaryExpr);
    VISIT(CXXBoolLiteralExpr);
    VISIT(CXXConstructExpr);
    VISIT(CXXDefaultArgExpr);
    VISIT(CXXDeleteExpr);
    VISIT(CXXDependentScopeMemberExpr);
    VISIT(CXXNewExpr);
    VISIT(CXXNoexceptExpr);
    VISIT(CXXNullPtrLiteralExpr);
    VISIT(CXXPseudoDestructorExpr);
    VISIT(CXXScalarValueInitExpr);
    VISIT(CXXThisExpr);
    VISIT(CXXThrowExpr);
    VISIT(CXXTypeidExpr);
    VISIT(CXXUnresolvedConstructExpr);
    VISIT(CXXUuidofExpr);
    VISIT(DeclRefExpr);
    VISIT(DependentScopeDeclRefExpr);
    VISIT(DesignatedInitExpr);
    VISIT(ExprWithCleanups);
    VISIT(ExtVectorElementExpr);
    VISIT(FloatingLiteral);
    VISIT(GNUNullExpr);
    VISIT(ImaginaryLiteral);
    VISIT(ImplicitCastExpr);
    VISIT(ImplicitValueInitExpr);
    VISIT(InitListExpr);
    VISIT(IntegerLiteral);
    VISIT(MaterializeTemporaryExpr);
    VISIT(MemberExpr);
    VISIT(OffsetOfExpr);
    VISIT(OpaqueValueExpr);
    VISIT(OverloadExpr);
    VISIT(PackExpansionExpr);
    VISIT(ParenExpr);
    VISIT(ParenListExpr);
    VISIT(PredefinedExpr);
    VISIT(ShuffleVectorExpr);
    VISIT(SizeOfPackExpr);
    VISIT(StmtExpr);
    VISIT(StringLiteral);
    VISIT(SubstNonTypeTemplateParmPackExpr);
    VISIT(TypeTraitExpr);
    VISIT(UnaryOperator);
    VISIT(UnaryExprOrTypeTraitExpr);
    VISIT(VAArgExpr);
#undef VISIT

    return ExprEffect::None();
  }

#define DECL_VISIT_EXPR(type) \
  ExprEffect Visit##type(clang::type* expr, const Environment& env)

#define IGNORE_EXPR(type)                                             \
  ExprEffect Visit##type(clang::type* expr, const Environment& env) { \
    return ExprEffect::None();                                        \
  }

  IGNORE_EXPR(AddrLabelExpr);
  IGNORE_EXPR(BlockExpr);
  IGNORE_EXPR(CharacterLiteral);
  IGNORE_EXPR(ChooseExpr);
  IGNORE_EXPR(CompoundLiteralExpr);
  IGNORE_EXPR(CXXBoolLiteralExpr);
  IGNORE_EXPR(CXXDependentScopeMemberExpr);
  IGNORE_EXPR(CXXNullPtrLiteralExpr);
  IGNORE_EXPR(CXXPseudoDestructorExpr);
  IGNORE_EXPR(CXXScalarValueInitExpr);
  IGNORE_EXPR(CXXNoexceptExpr);
  IGNORE_EXPR(CXXTypeidExpr);
  IGNORE_EXPR(CXXUnresolvedConstructExpr);
  IGNORE_EXPR(CXXUuidofExpr);
  IGNORE_EXPR(DependentScopeDeclRefExpr);
  IGNORE_EXPR(DesignatedInitExpr);
  IGNORE_EXPR(ExtVectorElementExpr);
  IGNORE_EXPR(FloatingLiteral);
  IGNORE_EXPR(ImaginaryLiteral);
  IGNORE_EXPR(IntegerLiteral);
  IGNORE_EXPR(OffsetOfExpr);
  IGNORE_EXPR(ImplicitValueInitExpr);
  IGNORE_EXPR(PackExpansionExpr);
  IGNORE_EXPR(PredefinedExpr);
  IGNORE_EXPR(ShuffleVectorExpr);
  IGNORE_EXPR(SizeOfPackExpr);
  IGNORE_EXPR(StmtExpr);
  IGNORE_EXPR(StringLiteral);
  IGNORE_EXPR(SubstNonTypeTemplateParmPackExpr);
  IGNORE_EXPR(TypeTraitExpr);
  IGNORE_EXPR(VAArgExpr);
  IGNORE_EXPR(GNUNullExpr);
  IGNORE_EXPR(OverloadExpr);

  DECL_VISIT_EXPR(CXXThisExpr) { return Use(expr, expr->getType(), THIS, env); }

  DECL_VISIT_EXPR(AbstractConditionalOperator) {
    Environment after_cond = env.ApplyEffect(VisitExpr(expr->getCond(), env));
    return ExprEffect::Merge(VisitExpr(expr->getTrueExpr(), after_cond),
                             VisitExpr(expr->getFalseExpr(), after_cond));
  }

  DECL_VISIT_EXPR(ArraySubscriptExpr) {
    clang::Expr* exprs[2] = {expr->getBase(), expr->getIdx()};
    return Parallel(expr, 2, exprs, env);
  }

  bool IsRawPointerVar(clang::Expr* expr, std::string* var_name) {
    if (llvm::isa<clang::DeclRefExpr>(expr)) {
      *var_name =
          llvm::cast<clang::DeclRefExpr>(expr)->getDecl()->getNameAsString();
      return true;
    }

    return false;
  }

  DECL_VISIT_EXPR(BinaryOperator) {
    clang::Expr* lhs = expr->getLHS();
    clang::Expr* rhs = expr->getRHS();
    clang::Expr* exprs[2] = {lhs, rhs};

    switch (expr->getOpcode()) {
      case clang::BO_Comma:
        return Sequential(expr, 2, exprs, env);

      case clang::BO_LAnd:
      case clang::BO_LOr:
        return ExprEffect::Merge(VisitExpr(lhs, env), VisitExpr(rhs, env));

      default:
        return Parallel(expr, 2, exprs, env);
    }
  }

  DECL_VISIT_EXPR(CXXBindTemporaryExpr) {
    return VisitExpr(expr->getSubExpr(), env);
  }

  DECL_VISIT_EXPR(MaterializeTemporaryExpr) {
    return VisitExpr(expr->getSubExpr(), env);
  }

  DECL_VISIT_EXPR(CXXConstructExpr) { return VisitArguments<>(expr, env); }

  DECL_VISIT_EXPR(CXXDefaultArgExpr) { return VisitExpr(expr->getExpr(), env); }

  DECL_VISIT_EXPR(CXXDeleteExpr) { return VisitExpr(expr->getArgument(), env); }

  DECL_VISIT_EXPR(CXXNewExpr) { return VisitExpr(expr->getInitializer(), env); }

  DECL_VISIT_EXPR(ExprWithCleanups) {
    return VisitExpr(expr->getSubExpr(), env);
  }

  DECL_VISIT_EXPR(CXXThrowExpr) { return VisitExpr(expr->getSubExpr(), env); }

  DECL_VISIT_EXPR(ImplicitCastExpr) {
    return VisitExpr(expr->getSubExpr(), env);
  }

  DECL_VISIT_EXPR(ConstantExpr) { return VisitExpr(expr->getSubExpr(), env); }

  DECL_VISIT_EXPR(InitListExpr) {
    return Sequential(expr, expr->getNumInits(), expr->getInits(), env);
  }

  DECL_VISIT_EXPR(MemberExpr) { return VisitExpr(expr->getBase(), env); }

  DECL_VISIT_EXPR(OpaqueValueExpr) {
    return VisitExpr(expr->getSourceExpr(), env);
  }

  DECL_VISIT_EXPR(ParenExpr) { return VisitExpr(expr->getSubExpr(), env); }

  DECL_VISIT_EXPR(ParenListExpr) {
    return Parallel(expr, expr->getNumExprs(), expr->getExprs(), env);
  }

  DECL_VISIT_EXPR(UnaryOperator) {
    // TODO(gcmole): We are treating all expressions that look like
    // {&raw_pointer_var} as definitions of {raw_pointer_var}. This should be
    // changed to recognize less generic pattern:
    //
    //   if (maybe_object->ToObject(&obj)) return maybe_object;
    //
    if (expr->getOpcode() == clang::UO_AddrOf) {
      std::string var_name;
      if (IsRawPointerVar(expr->getSubExpr(), &var_name)) {
        return ExprEffect::None().Define(var_name);
      }
    }
    return VisitExpr(expr->getSubExpr(), env);
  }

  DECL_VISIT_EXPR(UnaryExprOrTypeTraitExpr) {
    if (expr->isArgumentType()) {
      return ExprEffect::None();
    }

    return VisitExpr(expr->getArgumentExpr(), env);
  }

  DECL_VISIT_EXPR(CastExpr) { return VisitExpr(expr->getSubExpr(), env); }

  DECL_VISIT_EXPR(DeclRefExpr) { return Use(expr, expr->getDecl(), env); }

  // Represents a node in the AST {parent} whose children {exprs} have
  // undefined order of evaluation, e.g. array subscript or a binary operator.
  ExprEffect Parallel(clang::Expr* parent, int n, clang::Expr** exprs,
                      const Environment& env) {
    CallProps props;
    for (int i = 0; i < n; ++i) {
      props.SetEffect(i, VisitExpr(exprs[i], env));
    }
    if (!props.IsSafe()) ReportUnsafe(parent, BAD_EXPR_MSG);
    return props.ComputeCumulativeEffect(
        RepresentsRawPointerType(parent->getType()));
  }

  // Represents a node in the AST {parent} whose children {exprs} are
  // executed in sequence, e.g. a switch statement or an initializer list.
  ExprEffect Sequential(clang::Stmt* parent, int n, clang::Expr** exprs,
                        const Environment& env) {
    ExprEffect out = ExprEffect::None();
    Environment out_env = env;
    for (int i = 0; i < n; ++i) {
      out = ExprEffect::MergeSeq(out, VisitExpr(exprs[i], out_env));
      out_env = out_env.ApplyEffect(out);
    }
    return out;
  }

  // Represents a node in the AST {parent} which uses the variable {var_name},
  // e.g. this expression or operator&.
  // Here we observe the type in {var_type} of a previously declared variable
  // and if it's a raw heap object type, we do the following:
  // 1. If it got stale due to GC since its declaration, we report it as such.
  // 2. Mark its raw usage in the ExprEffect returned by this function.
  ExprEffect Use(const clang::Expr* parent, const clang::QualType& var_type,
                 const std::string& var_name, const Environment& env) {
    if (!g_dead_vars_analysis) return ExprEffect::None();
    if (!RepresentsRawPointerType(var_type)) return ExprEffect::None();
    // We currently care only about our internal pointer types and not about
    // raw C++ pointers, because normally special care is taken when storing
    // raw pointers to the managed heap. Furthermore, checking for raw
    // pointers produces too many false positives in the dead variable
    // analysis.
    if (!IsInternalPointerType(var_type)) return ExprEffect::None();
    if (env.IsAlive(var_name)) return ExprEffect::None();
    if (HasActiveGuard()) return ExprEffect::None();
    ReportUnsafe(parent, DEAD_VAR_MSG);
    return ExprEffect::RawUse();
  }

  ExprEffect Use(const clang::Expr* parent, const clang::ValueDecl* var,
                 const Environment& env) {
    if (IsExternalVMState(var)) return ExprEffect::GC();
    return Use(parent, var->getType(), var->getNameAsString(), env);
  }

  template <typename ExprType>
  ExprEffect VisitArguments(ExprType* call, const Environment& env) {
    CallProps props;
    VisitArguments<>(call, &props, env);
    if (!props.IsSafe()) ReportUnsafe(call, BAD_EXPR_MSG);
    return props.ComputeCumulativeEffect(
        RepresentsRawPointerType(call->getType()));
  }

  template <typename ExprType>
  void VisitArguments(ExprType* call, CallProps* props,
                      const Environment& env) {
    for (unsigned arg = 0; arg < call->getNumArgs(); arg++) {
      props->SetEffect(arg + 1, VisitExpr(call->getArg(arg), env));
    }
  }

  // After visiting the receiver and the arguments of the {call} node, this
  // function might report a GC-unsafe usage (due to the undefined evaluation
  // order of the receiver and the rest of the arguments).
  ExprEffect VisitCallExpr(clang::CallExpr* call, const Environment& env) {
    CallProps props;

    clang::CXXMemberCallExpr* memcall =
        llvm::dyn_cast_or_null<clang::CXXMemberCallExpr>(call);
    if (memcall != nullptr) {
      clang::Expr* receiver = memcall->getImplicitObjectArgument();
      props.SetEffect(0, VisitExpr(receiver, env));
    }

    std::string var_name;
    clang::CXXOperatorCallExpr* opcall =
        llvm::dyn_cast_or_null<clang::CXXOperatorCallExpr>(call);
    if (opcall != nullptr && opcall->isAssignmentOp() &&
        IsRawPointerVar(opcall->getArg(0), &var_name)) {
      // TODO(gcmole): We are treating all assignment operator calls with
      // the left hand side looking like {raw_pointer_var} as safe independent
      // of the concrete assignment operator implementation. This should be
      // changed to be more narrow only if the assignment operator of the base
      // {Object} or {HeapObject} class was used, which we know to be safe.
      props.SetEffect(1, VisitExpr(call->getArg(1), env).Define(var_name));
    } else {
      VisitArguments<>(call, &props, env);
    }

    if (!props.IsSafe()) ReportUnsafe(call, BAD_EXPR_MSG);

    ExprEffect out = props.ComputeCumulativeEffect(
        RepresentsRawPointerType(call->getType()));

    clang::FunctionDecl* callee = call->getDirectCallee();
    if (callee == nullptr) return out;

    if (IsKnownToCauseGC(ctx_, callee)) {
      out.setGC();
      scopes_.back().SetGCCauseLocation(
          clang::FullSourceLoc(call->getExprLoc(), sm_), callee);
    }

    // Support for virtual methods that might be GC suspects.
    if (memcall == nullptr) return out;
    clang::CXXMethodDecl* method =
        llvm::dyn_cast_or_null<clang::CXXMethodDecl>(callee);
    if (method == nullptr) r
"""


```