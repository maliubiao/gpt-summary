Response:
The user wants to understand the functionality of the provided C++ code snippet, which is part of the `gcmole.cc` file in the V8 JavaScript engine's source code.

Here's a breakdown of the thought process to address the user's request:

1. **Identify the core purpose:** The code heavily uses Clang's AST (Abstract Syntax Tree) to analyze C++ code. The names of classes and methods like `VisitStmt`, `VisitExpr`, `AnalyzeFunction`, and the presence of a `ProblemsFinder` class strongly suggest a static analysis tool. The name `gcmole` itself hints at garbage collection.

2. **Analyze the `FunctionAnalyzer` class:** This class seems central to the analysis. It has methods to visit statements and expressions, manage scopes, and track potential GC-causing calls. The `Environment` class, and its methods like `Merge`, `Define`, and `ApplyEffect`, likely represent the state of the program at different points during analysis, possibly tracking variables and their potential to be affected by GC.

3. **Focus on GC-related aspects:**  Look for code that explicitly mentions GC. The `IsKnownToCauseGC` and `IsSuspectedToCauseGC` functions are key. The `GCScope` struct and its members (`guard_location`, `gccause_location`, `gccause_decl`) confirm that the tool is tracking where and why garbage collection might occur. The `ReportUnsafe` method indicates that the tool identifies potentially problematic code related to GC.

4. **Infer functionality from names and structure:**
    * `IsDerivedFromInternalPointer`: Checks if a type represents a V8 internal pointer that the GC manages.
    * `RepresentsRawPointerType`:  Identifies types that are either raw pointers or wrappers around them (like `Object` and `MaybeObject` in V8).
    * `IsGCGuard`: Checks if a variable is marked as a "GC guard," which likely prevents the GC from collecting the referenced object.
    * The various `Visit...` methods handle different C++ language constructs (expressions, statements, declarations) and analyze their interaction with GC.
    * The `Block` class and its `Loop` and `Sequential` methods suggest a form of control-flow analysis to track how GC effects propagate through the code.

5. **Address specific user questions:**
    * **Functionality:** Combine the observations to describe the overall purpose: analyzing C++ code to find potential issues related to garbage collection, such as using pointers to GC-managed objects after a GC might have occurred.
    * **`.tq` extension:**  Recognize the association of `.tq` with Torque in V8 and state that the given code isn't Torque.
    * **Relationship to JavaScript:** Explain that this C++ code analyzes the *implementation* of the JavaScript engine, so direct JavaScript equivalents of the analysis logic don't exist. Provide an *example* of a potential problem this tool could detect (using a detached DOM node) and how it relates to GC.
    * **Code logic inference:**  Create a simplified example of a function call that might trigger a GC and how the tool could track that. Provide hypothetical input (the function call) and the expected output (the `setGC()` flag being set).
    * **Common programming errors:** Give a classic example of a use-after-free vulnerability, which is a type of error this tool aims to help prevent in the context of GC.
    * **Summarize functionality (Part 2):**  Focus on the parts of the code snippet in the second part: statement analysis, control flow (loops, conditionals), declaration handling, and the reporting of unsafe operations.

6. **Refine and structure the answer:** Organize the information logically, using headings and bullet points for clarity. Use precise language to describe the technical concepts. Make sure to clearly separate the different aspects of the user's request.

7. **Review and self-correct:** Read through the generated answer to ensure accuracy and completeness. Check if all parts of the user's query have been addressed adequately. For instance, double-check the interpretation of `GCGuard` and its role.
好的，这是代码的第二部分。让我们继续分析 `v8/tools/gcmole/gcmole.cc` 的功能。

**归纳其功能**

综合第一部分和第二部分的代码，`v8/tools/gcmole/gcmole.cc` 的主要功能是：

**静态分析 C++ 代码以检测潜在的与垃圾回收 (GC) 相关的安全问题。**

更具体地说，它执行以下操作：

1. **解析 C++ 代码:** 使用 Clang 库解析 V8 源代码的 C++ 文件，构建抽象语法树 (AST)。

2. **识别 GC 相关的类型和函数:**  它会查找 V8 内部中与垃圾回收相关的特定类（例如 `HeapObject`, `Smi`, `Tagged`）和可能触发 GC 的函数。

3. **跟踪代码执行路径:**  通过遍历 AST，它模拟代码的执行流程，包括处理各种语句（如循环、条件语句、返回语句等）。

4. **分析变量生命周期:** 它试图跟踪指向 GC 管理的对象的指针，并确定这些指针在可能发生 GC 的点是否仍然有效。

5. **检测潜在的 Use-After-GC 错误:**  这是该工具的核心目标。它会标记出在可能发生 GC 之后，仍然访问指向 GC 管理的对象的指针的情况，这可能导致程序崩溃或未定义的行为。

6. **支持 GC Guard:** 它识别并处理 "GC Guard" 机制，这些机制用于在执行可能触发 GC 的代码之前，临时阻止对象的回收。

7. **报告潜在问题:** 当检测到潜在的 GC 安全问题时，它会生成警告信息，指出问题发生的源代码位置以及可能导致 GC 的调用。

8. **可选的死变量分析:**  通过命令行参数，它可以执行死变量分析，这可能有助于识别不再使用的指针，这些指针虽然不会直接导致 Use-After-GC，但也可能表明代码存在问题。

9. **可配置的忽略列表:** 允许指定要忽略的文件，以减少噪音并专注于关键代码。

**总结来说，`gcmole.cc` 是一个静态分析工具，用于帮助 V8 开发人员在 C++ 代码中尽早发现与垃圾回收相关的潜在错误，从而提高代码的稳定性和安全性。**

**与 JavaScript 功能的关系**

虽然 `gcmole.cc` 是 C++ 代码，它直接分析的是 V8 引擎的 *内部实现*，但它的目标是确保 V8 能够正确且安全地执行 JavaScript 代码。  GC 是 JavaScript 引擎的核心组成部分，负责管理 JavaScript 对象的内存。  如果 V8 的 C++ 代码中存在与 GC 相关的错误，可能会导致 JavaScript 程序的崩溃或产生意外的行为。

例如，考虑以下 JavaScript 代码：

```javascript
let obj = { data: 'some data' };
let ref = obj;
// ... 某些可能触发垃圾回收的操作 ...
console.log(ref.data); // 如果在 "..." 期间 obj 被 GC 回收，这里可能会出错
```

`gcmole.cc` 试图在 V8 的 C++ 源码中找到类似于这种情景的错误，即使在 C++ 代码层面，对象的生命周期管理更加复杂。

**用户常见的编程错误 (C++ 角度)**

在 V8 的 C++ 代码中，与 GC 相关的常见编程错误可能包括：

1. **未正确使用 `Tagged` 指针:**  V8 使用 `Tagged` 模板类来包装指向堆上分配的 JavaScript 对象的指针。  直接使用原始指针而没有正确标记，可能导致 GC 无法识别对象的引用，从而过早回收。

2. **在可能发生 GC 的调用后访问未受保护的指针:**  如果在调用可能触发 GC 的函数后，继续访问指向可能被回收的对象的指针，而没有使用 GC Guard 或其他机制来确保对象的存活，就会发生 Use-After-GC 错误。

   ```c++
   v8::internal::HeapObject* obj = GetSomeHeapObject();
   // ... 调用可能触发 GC 的函数 ...
   Use(obj); // 如果 obj 在上面的调用中被回收，这里会出错
   ```

3. **在回调函数中持有指向堆对象的裸指针:** 当注册一个在未来执行的回调函数时，如果回调函数持有一个指向堆对象的裸指针，而该对象在回调执行之前被 GC 回收，就会出现问题。

4. **在多线程环境中不正确地共享 GC 管理的对象:**  在多线程环境中，需要仔细考虑如何安全地共享和访问 GC 管理的对象，避免竞争条件和 Use-After-GC。

**总结**

第二部分的代码主要关注于：

* **各种 C++ 语句的访问和分析:**  定义了如何处理不同类型的语句，例如 `if`, `while`, `for`, `return` 等。
* **控制流分析:** 通过 `Block` 类和 `Merge` 操作，尝试理解代码的执行路径和状态变化。
* **变量声明和作用域管理:**  跟踪变量的声明和其作用域，以便后续分析其生命周期。
* **识别 GC Guard 机制:** 识别并记录 GC Guard 的位置，以便在分析中考虑其影响。
* **报告潜在的 GC 安全问题:**  `ReportUnsafe` 函数用于报告检测到的问题。

总而言之，`gcmole.cc` 是一个复杂的静态分析工具，旨在提高 V8 引擎的健壮性和安全性，它通过深入分析 C++ 源代码来预防与垃圾回收相关的错误。

### 提示词
```
这是目录为v8/tools/gcmole/gcmole.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/tools/gcmole/gcmole.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
eturn out;
    if (!method->isVirtual()) return out;

    clang::CXXMethodDecl* target = method->getDevirtualizedMethod(
        memcall->getImplicitObjectArgument(), false);
    if (target != nullptr) {
      if (IsKnownToCauseGC(ctx_, target)) {
        out.setGC();
        scopes_.back().SetGCCauseLocation(
            clang::FullSourceLoc(call->getExprLoc(), sm_), target);
      }
    } else {
      // According to the documentation, {getDevirtualizedMethod} might
      // return nullptr, in which case we still want to use the partial
      // match of the {method}'s name against the GC suspects in order
      // to increase coverage.
      if (IsSuspectedToCauseGC(ctx_, method)) {
        out.setGC();
        scopes_.back().SetGCCauseLocation(
            clang::FullSourceLoc(call->getExprLoc(), sm_), method);
      }
    }
    return out;
  }

  // --------------------------------------------------------------------------
  // Statements
  // --------------------------------------------------------------------------

  Environment VisitStmt(clang::Stmt* stmt, const Environment& env) {
#define VISIT(type)                                                         \
  do {                                                                      \
    clang::type* concrete_stmt = llvm::dyn_cast_or_null<clang::type>(stmt); \
    if (concrete_stmt != nullptr) {                                         \
      return Visit##type(concrete_stmt, env);                               \
    }                                                                       \
  } while (0);

    if (clang::Expr* expr = llvm::dyn_cast_or_null<clang::Expr>(stmt)) {
      return env.ApplyEffect(VisitExpr(expr, env));
    }

    VISIT(AsmStmt);
    VISIT(BreakStmt);
    VISIT(CompoundStmt);
    VISIT(ContinueStmt);
    VISIT(CXXCatchStmt);
    VISIT(CXXTryStmt);
    VISIT(DeclStmt);
    VISIT(DoStmt);
    VISIT(ForStmt);
    VISIT(GotoStmt);
    VISIT(IfStmt);
    VISIT(IndirectGotoStmt);
    VISIT(LabelStmt);
    VISIT(NullStmt);
    VISIT(ReturnStmt);
    VISIT(CaseStmt);
    VISIT(DefaultStmt);
    VISIT(SwitchStmt);
    VISIT(WhileStmt);
#undef VISIT

    return env;
  }

#define DECL_VISIT_STMT(type) \
  Environment Visit##type(clang::type* stmt, const Environment& env)

#define IGNORE_STMT(type)                                              \
  Environment Visit##type(clang::type* stmt, const Environment& env) { \
    return env;                                                        \
  }

  IGNORE_STMT(IndirectGotoStmt);
  IGNORE_STMT(NullStmt);
  IGNORE_STMT(AsmStmt);

  // We are ignoring control flow for simplicity.
  IGNORE_STMT(GotoStmt);
  IGNORE_STMT(LabelStmt);

  // We are ignoring try/catch because V8 does not use them.
  IGNORE_STMT(CXXCatchStmt);
  IGNORE_STMT(CXXTryStmt);

  class Block {
   public:
    Block(const Environment& in, FunctionAnalyzer* owner)
        : in_(in),
          out_(Environment::Unreachable()),
          changed_(false),
          owner_(owner) {
      parent_ = owner_->EnterBlock(this);
    }

    ~Block() { owner_->LeaveBlock(parent_); }

    void MergeIn(const Environment& env) {
      Environment old_in = in_;
      in_ = Environment::Merge(in_, env);
      changed_ = !old_in.Equal(in_);
    }

    bool changed() {
      if (!changed_) return false;
      changed_ = false;
      return true;
    }

    const Environment& in() { return in_; }

    const Environment& out() { return out_; }

    void MergeOut(const Environment& env) {
      out_ = Environment::Merge(out_, env);
    }

    void Sequential(clang::Stmt* a, clang::Stmt* b, clang::Stmt* c) {
      Environment a_out = owner_->VisitStmt(a, in());
      Environment b_out = owner_->VisitStmt(b, a_out);
      Environment c_out = owner_->VisitStmt(c, b_out);
      MergeOut(c_out);
    }

    void Sequential(clang::Stmt* a, clang::Stmt* b) {
      Environment a_out = owner_->VisitStmt(a, in());
      Environment b_out = owner_->VisitStmt(b, a_out);
      MergeOut(b_out);
    }

    void Loop(clang::Stmt* a, clang::Stmt* b, clang::Stmt* c) {
      Sequential(a, b, c);
      MergeIn(out());
    }

    void Loop(clang::Stmt* a, clang::Stmt* b) {
      Sequential(a, b);
      MergeIn(out());
    }

   private:
    Environment in_;
    Environment out_;
    bool changed_;
    FunctionAnalyzer* owner_;
    Block* parent_;
  };

  DECL_VISIT_STMT(BreakStmt) {
    block_->MergeOut(env);
    return Environment::Unreachable();
  }

  DECL_VISIT_STMT(ContinueStmt) {
    block_->MergeIn(env);
    return Environment::Unreachable();
  }

  DECL_VISIT_STMT(CompoundStmt) {
    scopes_.push_back(GCScope());
    Environment out = env;
    clang::CompoundStmt::body_iterator end = stmt->body_end();
    for (clang::CompoundStmt::body_iterator s = stmt->body_begin(); s != end;
         ++s) {
      out = VisitStmt(*s, out);
    }
    scopes_.pop_back();
    return out;
  }

  DECL_VISIT_STMT(WhileStmt) {
    Block block(env, this);
    do {
      block.Loop(stmt->getCond(), stmt->getBody());
    } while (block.changed());
    return block.out();
  }

  DECL_VISIT_STMT(DoStmt) {
    Block block(env, this);

    // Special case `do { ... } while (false);`, which is known to only run
    // once, and is used in our (D)CHECK macros.
    if (auto* literal_cond =
            llvm::dyn_cast<clang::CXXBoolLiteralExpr>(stmt->getCond())) {
      if (literal_cond->getValue() == false) {
        block.Loop(stmt->getBody(), stmt->getCond());
        return block.out();
      }
    }

    do {
      block.Loop(stmt->getBody(), stmt->getCond());
    } while (block.changed());
    return block.out();
  }

  DECL_VISIT_STMT(ForStmt) {
    Block block(VisitStmt(stmt->getInit(), env), this);
    do {
      block.Loop(stmt->getCond(), stmt->getBody(), stmt->getInc());
    } while (block.changed());
    return block.out();
  }

  DECL_VISIT_STMT(IfStmt) {
    Environment init_out = VisitStmt(stmt->getInit(), env);
    Environment cond_out = VisitStmt(stmt->getCond(), init_out);
    Environment then_out = VisitStmt(stmt->getThen(), cond_out);
    Environment else_out = VisitStmt(stmt->getElse(), cond_out);
    return Environment::Merge(then_out, else_out);
  }

  DECL_VISIT_STMT(SwitchStmt) {
    Block block(env, this);
    block.Sequential(stmt->getCond(), stmt->getBody());
    return block.out();
  }

  DECL_VISIT_STMT(CaseStmt) {
    Environment in = Environment::Merge(env, block_->in());
    Environment after_lhs = VisitStmt(stmt->getLHS(), in);
    return VisitStmt(stmt->getSubStmt(), after_lhs);
  }

  DECL_VISIT_STMT(DefaultStmt) {
    Environment in = Environment::Merge(env, block_->in());
    return VisitStmt(stmt->getSubStmt(), in);
  }

  DECL_VISIT_STMT(ReturnStmt) {
    VisitExpr(stmt->getRetValue(), env);
    return Environment::Unreachable();
  }

  const clang::TagType* ToTagType(const clang::Type* t) {
    if (t == nullptr) {
      return nullptr;
    } else if (llvm::isa<clang::TagType>(t)) {
      return llvm::cast<clang::TagType>(t);
    } else if (llvm::isa<clang::SubstTemplateTypeParmType>(t)) {
      return ToTagType(llvm::cast<clang::SubstTemplateTypeParmType>(t)
                           ->getReplacementType()
                           .getTypePtr());
    } else {
      return nullptr;
    }
  }

  bool IsDerivedFrom(const clang::CXXRecordDecl* record,
                     const clang::CXXRecordDecl* base) {
    return (record == base) || record->isDerivedFrom(base);
  }

  const clang::CXXRecordDecl* GetDefinitionOrNull(
      const clang::CXXRecordDecl* record) {
    if (record == nullptr) return nullptr;
    if (!InV8Namespace(record)) return nullptr;
    if (!record->hasDefinition()) return nullptr;
    return record->getDefinition();
  }

  bool IsDerivedFromInternalPointer(const clang::CXXRecordDecl* record) {
    if (record == nullptr) return false;
    if (!InV8Namespace(record)) return false;
    auto* specialization =
        llvm::dyn_cast<clang::ClassTemplateSpecializationDecl>(record);
    if (specialization) {
      auto* template_decl =
          specialization->getSpecializedTemplate()->getCanonicalDecl();
      if (template_decl == tagged_decl_) {
        auto& template_args = specialization->getTemplateArgs();
        if (template_args.size() != 1) {
          llvm::errs() << "v8::internal::Tagged<T> should have exactly one "
                          "template argument\n";
          specialization->dump(llvm::errs());
          return false;
        }
        if (template_args[0].getKind() != clang::TemplateArgument::Type) {
          llvm::errs()
              << "v8::internal::Tagged<T>, T should be a type argument\n";
          specialization->dump(llvm::errs());
          return false;
        }

        auto* tagged_type_record =
            template_args[0].getAsType()->getAsCXXRecordDecl();
        return tagged_type_record != smi_decl_ &&
               tagged_type_record != tagged_index_decl_;
      }
    }

    const clang::CXXRecordDecl* definition = GetDefinitionOrNull(record);
    if (!definition) return false;
    if (IsDerivedFrom(record, heap_object_decl_)) {
      return true;
    }
    return false;
  }

  bool IsRawPointerType(const clang::PointerType* type) {
    const clang::CXXRecordDecl* record = type->getPointeeCXXRecordDecl();
    bool result = IsDerivedFromInternalPointer(record);
    TRACE("is raw " << result << " "
                    << (record ? record->getNameAsString() : "nullptr"));
    return result;
  }

  bool IsInternalPointerType(clang::QualType qtype) {
    const clang::CXXRecordDecl* record = qtype->getAsCXXRecordDecl();
    bool result = IsDerivedFromInternalPointer(record);
    TRACE_LLVM_TYPE("is internal " << result, qtype);
    return result;
  }

  // Returns weather the given type is a raw pointer or a wrapper around
  // such. For V8 that means Object and MaybeObject instances.
  bool RepresentsRawPointerType(clang::QualType qtype) {
    // Not yet assigned pointers can't get moved by the GC.
    if (qtype.isNull()) return false;
    // nullptr can't get moved by the GC.
    if (qtype->isNullPtrType()) return false;

    const clang::PointerType* pointer_type =
        llvm::dyn_cast_or_null<clang::PointerType>(qtype.getTypePtrOrNull());
    if (pointer_type != nullptr) {
      return IsRawPointerType(pointer_type);
    } else {
      return IsInternalPointerType(qtype);
    }
  }

  bool IsGCGuard(clang::QualType qtype) {
    if (!no_gc_mole_decl_) return false;
    if (qtype.isNull()) return false;
    if (qtype->isNullPtrType()) return false;

    const clang::CXXRecordDecl* record = qtype->getAsCXXRecordDecl();
    const clang::CXXRecordDecl* definition = GetDefinitionOrNull(record);

    if (!definition) return false;
    return no_gc_mole_decl_ == definition;
  }

  Environment VisitDecl(clang::Decl* decl, Environment& env) {
    if (clang::VarDecl* var = llvm::dyn_cast<clang::VarDecl>(decl)) {
      Environment out = var->hasInit() ? VisitStmt(var->getInit(), env) : env;

      if (RepresentsRawPointerType(var->getType())) {
        out = out.Define(var->getNameAsString());
      }
      if (IsGCGuard(var->getType())) {
        scopes_.back().guard_location =
            clang::FullSourceLoc(decl->getLocation(), sm_);
      }

      return out;
    }
    // TODO(gcmole): handle other declarations?
    return env;
  }

  DECL_VISIT_STMT(DeclStmt) {
    Environment out = env;
    clang::DeclStmt::decl_iterator end = stmt->decl_end();
    for (clang::DeclStmt::decl_iterator decl = stmt->decl_begin(); decl != end;
         ++decl) {
      out = VisitDecl(*decl, out);
    }
    return out;
  }

  void DefineParameters(const clang::FunctionDecl* f, Environment* env) {
    env->MDefine(THIS);
    clang::FunctionDecl::param_const_iterator end = f->param_end();
    for (clang::FunctionDecl::param_const_iterator p = f->param_begin();
         p != end; ++p) {
      env->MDefine((*p)->getNameAsString());
    }
  }

  void AnalyzeFunction(const clang::FunctionDecl* f) {
    const clang::FunctionDecl* body = nullptr;
    if (f->hasBody(body)) {
      Environment env;
      DefineParameters(body, &env);
      VisitStmt(body->getBody(), env);
      Environment::ClearSymbolTable();
    }
  }

  Block* EnterBlock(Block* block) {
    Block* parent = block_;
    block_ = block;
    return parent;
  }

  void LeaveBlock(Block* block) { block_ = block; }

  bool HasActiveGuard() {
    for (const auto& s : scopes_) {
      if (s.IsBeforeGCCause()) return true;
    }
    return false;
  }

 private:
  void ReportUnsafe(const clang::Expr* expr, const std::string& msg) {
    clang::SourceLocation error_loc =
        clang::FullSourceLoc(expr->getExprLoc(), sm_);
    d_.Report(error_loc,
              d_.getCustomDiagID(clang::DiagnosticsEngine::Warning, "%0"))
        << msg;
    // Find the relevant GC scope (see HasActiveGuard).
    const GCScope* pscope = nullptr;
    for (const auto& s : scopes_) {
      if (!s.IsBeforeGCCause() && s.gccause_location.isValid()) {
        pscope = &s;
        break;
      }
    }
    if (!pscope) {
      d_.Report(error_loc,
                d_.getCustomDiagID(clang::DiagnosticsEngine::Note,
                                   "Could not find GC source location."));
      return;
    }
    const GCScope& scope = *pscope;
    d_.Report(scope.gccause_location,
              d_.getCustomDiagID(clang::DiagnosticsEngine::Note,
                                 "Call might cause unexpected GC."));
    clang::FunctionDecl* gccause_decl = scope.gccause_decl;
    d_.Report(
        clang::FullSourceLoc(gccause_decl->getBeginLoc(), sm_),
        d_.getCustomDiagID(clang::DiagnosticsEngine::Note, "GC call here."));

    if (!g_print_gc_call_chain) return;
    // TODO(cbruni, v8::10009): print call-chain to gc with proper source
    // positions.
    LoadGCCauses();
    MangledName name;
    if (!GetMangledName(ctx_, gccause_decl, &name)) return;
    std::cout << "Potential GC call chain:\n";
    std::set<MangledName> stack;
    while (true) {
      if (!stack.insert(name).second) break;
      std::cout << "\t" << name << "\n";
      auto next = gc_causes.find(name);
      if (next == gc_causes.end()) break;
      std::vector<MangledName> calls = next->second;
      for (MangledName call : calls) {
        name = call;
        if (stack.find(call) != stack.end()) break;
      }
    }
  }

  clang::MangleContext* ctx_;
  clang::CXXRecordDecl* heap_object_decl_;
  clang::CXXRecordDecl* smi_decl_;
  clang::CXXRecordDecl* tagged_index_decl_;
  clang::ClassTemplateDecl* tagged_decl_;
  clang::CXXRecordDecl* no_gc_mole_decl_;

  clang::DiagnosticsEngine& d_;
  clang::SourceManager& sm_;

  Block* block_;

  struct GCScope {
    clang::FullSourceLoc guard_location;
    clang::FullSourceLoc gccause_location;
    clang::FunctionDecl* gccause_decl;

    // We're only interested in guards that are declared before any further GC
    // causing calls (see TestGuardedDeadVarAnalysisMidFunction for example).
    bool IsBeforeGCCause() const {
      if (!guard_location.isValid()) return false;
      if (!gccause_location.isValid()) return true;
      return guard_location.isBeforeInTranslationUnitThan(gccause_location);
    }

    // After we set the first GC cause in the scope, we don't need the later
    // ones.
    void SetGCCauseLocation(clang::FullSourceLoc gccause_location_,
                            clang::FunctionDecl* decl) {
      if (gccause_location.isValid()) return;
      gccause_location = gccause_location_;
      gccause_decl = decl;
    }
  };
  std::vector<GCScope> scopes_;
};

class ProblemsFinder : public clang::ASTConsumer,
                       public clang::RecursiveASTVisitor<ProblemsFinder> {
 public:
  ProblemsFinder(clang::DiagnosticsEngine& d, clang::SourceManager& sm,
                 const std::vector<std::string>& args)
      : d_(d), sm_(sm) {
    for (unsigned i = 0; i < args.size(); ++i) {
      if (args[i] == "--dead-vars") {
        g_dead_vars_analysis = true;
      }
      if (args[i] == "--verbose-trace") g_tracing_enabled = true;
      if (args[i] == "--verbose") g_verbose = true;
    }
  }

  bool TranslationUnitIgnored() {
    if (!ignored_files_loaded_) {
      auto fileOrError =
          llvm::MemoryBuffer::getFile("tools/gcmole/ignored_files");
      if (auto error = fileOrError.getError()) {
        llvm::errs() << "Failed to open ignored_files file\n";
        std::terminate();
      }
      for (llvm::line_iterator it(*fileOrError->get()); !it.is_at_end(); ++it) {
        ignored_files_.insert(*it);
      }
      ignored_files_loaded_ = true;
    }

    clang::FileID main_file_id = sm_.getMainFileID();
    llvm::StringRef filename =
        sm_.getFileEntryForID(main_file_id)->tryGetRealPathName();

    bool result = ignored_files_.contains(filename);
    if (result) {
      llvm::outs() << "Ignoring file " << filename << "\n";
    }
    return result;
  }

  void HandleTranslationUnit(clang::ASTContext& ctx) override {
    if (TranslationUnitIgnored()) return;

    Resolver r(ctx);

    // It is a valid situation that no_gc_mole_decl == nullptr when
    // DisableGCMole is not included and can't be resolved. This is gracefully
    // handled in the FunctionAnalyzer later.
    auto v8_internal = r.ResolveNamespace("v8").ResolveNamespace("internal");
    clang::CXXRecordDecl* no_gc_mole_decl =
        v8_internal.Resolve<clang::CXXRecordDecl>("DisableGCMole");

    clang::CXXRecordDecl* heap_object_decl =
        v8_internal.Resolve<clang::CXXRecordDecl>("HeapObject");

    clang::CXXRecordDecl* smi_decl =
        v8_internal.Resolve<clang::CXXRecordDecl>("Smi");

    clang::CXXRecordDecl* tagged_index_decl =
        v8_internal.Resolve<clang::CXXRecordDecl>("TaggedIndex");

    clang::ClassTemplateDecl* tagged_decl =
        v8_internal.Resolve<clang::ClassTemplateDecl>("Tagged");

    if (heap_object_decl != nullptr) {
      heap_object_decl = heap_object_decl->getDefinition();
    }

    if (smi_decl != nullptr) {
      smi_decl = smi_decl->getDefinition();
    }

    if (tagged_index_decl != nullptr) {
      tagged_index_decl = tagged_index_decl->getDefinition();
    }

    if (tagged_decl != nullptr) {
      tagged_decl = tagged_decl->getCanonicalDecl();
    }

    if (heap_object_decl != nullptr && smi_decl != nullptr &&
        tagged_index_decl != nullptr && tagged_decl != nullptr) {
      function_analyzer_ = new FunctionAnalyzer(
          clang::ItaniumMangleContext::create(ctx, d_), heap_object_decl,
          smi_decl, tagged_index_decl, tagged_decl, no_gc_mole_decl, d_, sm_);
      TraverseDecl(ctx.getTranslationUnitDecl());
    } else if (g_verbose) {
      if (heap_object_decl == nullptr) {
        llvm::errs() << "Failed to resolve v8::internal::HeapObject\n";
      }
      if (smi_decl == nullptr) {
        llvm::errs() << "Failed to resolve v8::internal::Smi\n";
      }
      if (tagged_index_decl == nullptr) {
        llvm::errs() << "Failed to resolve v8::internal::TaggedIndex\n";
      }
      if (tagged_decl == nullptr) {
        llvm::errs() << "Failed to resolve v8::internal::Tagged<T>\n";
      }
    }
  }

  virtual bool VisitFunctionDecl(clang::FunctionDecl* decl) {
    // Don't print tracing from includes, otherwise the output is too big.
    bool tracing = g_tracing_enabled;
    const auto& fileID = sm_.getFileID(decl->getLocation());
    if (fileID != sm_.getMainFileID()) {
      g_tracing_enabled = false;
    }

    TRACE("Visiting function " << decl->getNameAsString());
    function_analyzer_->AnalyzeFunction(decl);

    g_tracing_enabled = tracing;
    return true;
  }

 private:
  clang::DiagnosticsEngine& d_;
  clang::SourceManager& sm_;

  bool ignored_files_loaded_ = false;
  llvm::StringSet<> ignored_files_;

  FunctionAnalyzer* function_analyzer_;
};

template <typename ConsumerType>
class Action : public clang::PluginASTAction {
 protected:
  std::unique_ptr<clang::ASTConsumer> CreateASTConsumer(
      clang::CompilerInstance& CI, llvm::StringRef InFile) override {
    return std::unique_ptr<clang::ASTConsumer>(
        new ConsumerType(CI.getDiagnostics(), CI.getSourceManager(), args_));
  }

  bool ParseArgs(const clang::CompilerInstance& CI,
                 const std::vector<std::string>& args) override {
    args_ = args;
    return true;
  }

  void PrintHelp(llvm::raw_ostream& ros) {}

 private:
  std::vector<std::string> args_;
};

}  // namespace

static clang::FrontendPluginRegistry::Add<Action<ProblemsFinder>> FindProblems(
    "find-problems", "Find GC-unsafe places.");

static clang::FrontendPluginRegistry::Add<Action<FunctionDeclarationFinder>>
    DumpCallees("dump-callees", "Dump callees for each function.");

#undef TRACE
#undef TRACE_LLVM_TYPE
#undef TRACE_LLVM_DECL
#undef DECL_VISIT_EXPR
#undef IGNORE_EXPR
#undef DECL_VISIT_STMT
#undef IGNORE_STMT
```