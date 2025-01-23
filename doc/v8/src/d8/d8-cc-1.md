Response:
The user wants a summary of the functionalities of the provided C++ code snippet, which is part of `v8/src/d8/d8.cc`.

Here's a breakdown of the code's responsibilities:

1. **JavaScript Execution:** The `Shell::ExecuteString` function handles the execution of JavaScript code. It covers parsing, compilation, and running the code within a V8 context. It also deals with code caching.

2. **Module Handling:**  The code implements logic for resolving, fetching, and executing JavaScript modules, including both standard JavaScript modules and JSON modules. Key functions are `ResolveModuleCallback`, `ResolveModuleSourceCallback`, `FetchModuleSource`, `FetchModuleTree`, and `ExecuteModule`.

3. **Dynamic Imports:**  The code supports dynamic imports using `HostImportModuleDynamically` and `DoHostImportModuleDynamically`. This involves fetching and evaluating modules asynchronously.

4. **Module Meta Object:**  The `HostInitializeImportMetaObject` function provides access to module metadata, specifically the module's URL.

5. **Shadow Realms:** The `HostCreateShadowRealmContext` function supports the creation of isolated JavaScript realms (Shadow Realms).

6. **Wasm Integration:** There's a mention of WebAssembly module handling within `FetchModuleSource`.

7. **Path Normalization:**  Utility functions like `IsAbsolutePath`, `GetWorkingDirectory`, `DirName`, and `NormalizePath` are used to manage file paths for module resolution.

8. **Error Handling:** The code uses `TryCatch` to handle exceptions during script execution and module loading.

9. **Code Caching:**  The `Shell::ExecuteString` function includes logic for producing and consuming code cache.

I will now formulate the summary based on these points.
这是 `v8/src/d8/d8.cc` 的一部分代码，主要负责 **执行 JavaScript 代码和模块**，特别是涉及到 ES 模块的加载和执行，以及动态 import 的处理。

**功能归纳：**

1. **执行字符串形式的 JavaScript 代码 (`Shell::ExecuteString`)**:
   - 接收一段 JavaScript 代码字符串，并将其在 V8 环境中执行。
   - 可以选择是否报告执行过程中出现的异常。
   - 支持 `parse_only` 模式，只进行语法解析而不执行。
   - 实现了代码的编译和运行流程。
   - 支持代码缓存的生成和使用，以提高后续执行效率。
   - 可以重复编译代码多次。

2. **ES 模块的解析和加载**:
   - 提供了 `ResolveModuleCallback` 和 `ResolveModuleSourceCallback` 用于解析模块的路径。
   - `FetchModuleSource` 用于获取特定类型（目前只看到 WebAssembly）模块的源代码。
   - `FetchModuleTree` 负责递归地加载和解析模块依赖树，包括 JavaScript 和 JSON 模块。
   - 支持 data URL 形式的模块加载。
   - 处理模块的类型（JavaScript, JSON, WebAssembly）。
   - 记录已加载的模块，避免重复加载。

3. **动态 `import()` 的处理 (`HostImportModuleDynamically`, `DoHostImportModuleDynamically`)**:
   - 实现了 `import()` 语法的宿主环境回调。
   - 异步地加载和执行动态导入的模块。
   - 使用微任务队列来处理异步加载过程。
   - 提供了成功和失败的回调 (`ModuleResolutionSuccessCallback`, `ModuleResolutionFailureCallback`) 来处理模块加载的结果。

4. **模块元数据 (`HostInitializeImportMetaObject`)**:
   - 提供了获取模块元数据的机制，目前只看到设置了 `url` 属性。

5. **Shadow Realms (`HostCreateShadowRealmContext`)**:
   - 提供了创建隔离的 JavaScript 执行上下文 (Shadow Realms) 的能力。

6. **路径规范化**:
   - 提供了一系列函数 (`IsAbsolutePath`, `GetWorkingDirectory`, `DirName`, `NormalizePath`, `NormalizeModuleSpecifier`) 用于处理和规范化模块的路径，以便正确地加载模块。

**与 JavaScript 的关系及示例：**

这段 C++ 代码是 V8 引擎内部实现的一部分，负责支持 JavaScript 中的模块化功能。

**示例 (JavaScript):**

```javascript
// 假设 d8 运行在某个目录下，并且有一个文件 my_module.js

// my_module.js
export function greet(name) {
  return `Hello, ${name}!`;
}

// main.js
import { greet } from './my_module.js';
console.log(greet('World'));

// 或者使用动态 import
async function loadModule() {
  const module = await import('./my_module.js');
  console.log(module.greet('Dynamic World'));
}
loadModule();
```

当 d8 运行 `main.js` 时，这段 C++ 代码中的 `FetchModuleTree` 会负责找到并加载 `my_module.js` 的内容。对于动态 `import()`，`HostImportModuleDynamically` 和 `DoHostImportModuleDynamically` 会处理异步加载 `my_module.js` 的过程。

**代码逻辑推理与假设输入输出：**

**场景：执行一个包含静态导入的 JavaScript 模块**

**假设输入：**

- 文件 `main.js` 内容： `import { value } from './module.js'; console.log(value);`
- 文件 `module.js` 内容： `export const value = 42;`
- 使用 d8 命令执行 `d8 main.js`

**代码逻辑推理：**

1. `Shell::ExecuteModule` 被调用，接收 `main.js` 的文件名。
2. `NormalizeModuleSpecifier` 将 `./module.js` 转换为绝对路径（例如 `/path/to/module.js`）。
3. `FetchModuleTree` 会读取 `main.js` 的内容，并解析其中的 `import` 语句。
4. 再次调用 `FetchModuleTree` 读取 `module.js` 的内容。
5. `InstantiateModule` 负责将两个模块连接起来。
6. `Evaluate` 执行模块的代码，先执行 `module.js`，然后执行 `main.js`。

**预期输出：**

```
42
```

**用户常见的编程错误举例：**

1. **模块路径错误：** 在 `import` 语句中使用了错误的相对或绝对路径，导致 `FetchModuleTree` 找不到模块文件。

   ```javascript
   // main.js
   import { value } from 'modul.js'; // 拼写错误
   ```

   **d8 的报错信息可能包含：** "d8: Error reading module from ..."

2. **循环依赖：** 模块之间存在循环依赖关系，可能导致 `InstantiateModule` 失败。

   ```javascript
   // a.js
   import './b.js';
   export const a = 1;

   // b.js
   import './a.js';
   export const b = 2;
   ```

   **d8 的报错信息可能与模块实例化失败有关。**

3. **动态 `import()` 中使用了无法解析的模块标识符：**

   ```javascript
   async function load() {
     await import('non-existent-module');
   }
   load();
   ```

   **d8 的报错信息会提示无法读取模块。**

**功能总结（基于提供的第 2 部分代码）：**

这段代码的核心功能是 **支持 V8 执行 JavaScript 代码，特别是 ES 模块的加载、解析和动态导入**。它实现了 V8 引擎在宿主环境（d8）中处理模块化 JavaScript 代码的关键逻辑，包括查找模块文件、解析模块依赖关系、实例化模块以及执行模块代码。此外，它还支持 Shadow Realms 的创建，为隔离的 JavaScript 执行环境提供了基础。路径规范化的功能确保了模块加载的正确性，而代码缓存的机制则提升了性能。

### 提示词
```
这是目录为v8/src/d8/d8.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/d8/d8.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
ext> context,
    v8::Local<v8::Promise::Resolver> resolver, v8::Local<v8::Value> result,
    WasmAsyncSuccess success) {
  // We have to resolve the promise in a separate task which is not a cancelable
  // task, to avoid a deadlock when {quit()} is called in the then-handler of
  // the result promise.
  g_platform->GetForegroundTaskRunner(isolate)->PostTask(
      std::make_unique<D8WasmAsyncResolvePromiseTask>(
          isolate, context, resolver, result, success));
}

}  // namespace

// Executes a string within the current v8 context.
bool Shell::ExecuteString(Isolate* isolate, Local<String> source,
                          Local<String> name,
                          ReportExceptions report_exceptions,
                          Global<Value>* out_result) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  if (i_isolate->is_execution_terminating()) return true;
  if (i::v8_flags.parse_only) {
    i::VMState<PARSER> state(i_isolate);
    i::Handle<i::String> str = Utils::OpenHandle(*(source));

    // Set up ParseInfo.
    i::UnoptimizedCompileState compile_state;
    i::ReusableUnoptimizedCompileState reusable_state(i_isolate);

    i::UnoptimizedCompileFlags flags =
        i::UnoptimizedCompileFlags::ForToplevelCompile(
            i_isolate, true, i::construct_language_mode(i::v8_flags.use_strict),
            i::REPLMode::kNo, ScriptType::kClassic, i::v8_flags.lazy);

    if (options.compile_options & v8::ScriptCompiler::kEagerCompile) {
      flags.set_is_eager(true);
    }

    i::ParseInfo parse_info(i_isolate, flags, &compile_state, &reusable_state);

    i::Handle<i::Script> script = parse_info.CreateScript(
        i_isolate, str, i::kNullMaybeHandle, ScriptOriginOptions());
    if (!i::parsing::ParseProgram(&parse_info, script, i_isolate,
                                  i::parsing::ReportStatisticsMode::kYes)) {
      parse_info.pending_error_handler()->PrepareErrors(
          i_isolate, parse_info.ast_value_factory());
      parse_info.pending_error_handler()->ReportErrors(i_isolate, script);

      fprintf(stderr, "Failed parsing\n");
      return false;
    }
    return true;
  }

  HandleScope handle_scope(isolate);
  TryCatch try_catch(isolate);
  try_catch.SetVerbose(report_exceptions == kReportExceptions);

  // Explicitly check for stack overflows. This method can be called
  // recursively, and since we consume quite some stack space for the C++
  // frames, the stack check in the called frame might be too late.
  if (i::StackLimitCheck{i_isolate}.HasOverflowed()) {
    i_isolate->StackOverflow();
    return false;
  }

  PerIsolateData* data = PerIsolateData::Get(isolate);
  Local<Context> realm =
      Local<Context>::New(isolate, data->realms_[data->realm_current_]);
  Context::Scope context_scope(realm);
  Local<Context> context(isolate->GetCurrentContext());
  ScriptOrigin origin = CreateScriptOrigin(isolate, name, ScriptType::kClassic);

  std::shared_ptr<ModuleEmbedderData> module_data =
      GetModuleDataFromContext(realm);
  module_data->origin = ToSTLString(isolate, name);

  for (int i = 1; i < options.repeat_compile; ++i) {
    HandleScope handle_scope_for_compiling(isolate);
    if (CompileString<Script>(isolate, context, source, origin).IsEmpty()) {
      return false;
    }
  }
  Local<Script> script;
  if (!CompileString<Script>(isolate, context, source, origin)
           .ToLocal(&script)) {
    return false;
  }

  if (options.code_cache_options ==
      ShellOptions::CodeCacheOptions::kProduceCache) {
    // Serialize and store it in memory for the next execution.
    ScriptCompiler::CachedData* cached_data =
        ScriptCompiler::CreateCodeCache(script->GetUnboundScript());
    StoreInCodeCache(isolate, source, cached_data);
    delete cached_data;
  }
  if (options.compile_only) return true;
  if (options.compile_options & ScriptCompiler::kConsumeCodeCache) {
    i::DirectHandle<i::Script> i_script(
        i::Cast<i::Script>(
            Utils::OpenDirectHandle(*script)->shared()->script()),
        i_isolate);
    // TODO(cbruni, chromium:1244145): remove once context-allocated.
    i_script->set_host_defined_options(i::Cast<i::FixedArray>(
        *Utils::OpenDirectHandle(*(origin.GetHostDefinedOptions()))));
  }

  MaybeLocal<Value> maybe_result = script->Run(realm);

  if (options.code_cache_options ==
      ShellOptions::CodeCacheOptions::kProduceCacheAfterExecute) {
    // Serialize and store it in memory for the next execution.
    ScriptCompiler::CachedData* cached_data =
        ScriptCompiler::CreateCodeCache(script->GetUnboundScript());
    StoreInCodeCache(isolate, source, cached_data);
    delete cached_data;
  }
  data->realm_current_ = data->realm_switch_;

  Local<Value> result;
  if (!maybe_result.ToLocal(&result)) {
    if (try_catch.HasTerminated()) return true;
    DCHECK(try_catch.HasCaught());
    return false;
  } else if (out_result != nullptr) {
    out_result->Reset(isolate, result);
  }

  // It's possible that a FinalizationRegistry cleanup task threw an error.
  return !try_catch.HasCaught();
}

namespace {

bool IsAbsolutePath(const std::string& path) {
#if defined(V8_OS_WIN)
  // This is an incorrect approximation, but should
  // work for all our test-running cases.
  return path.find(':') != std::string::npos;
#else
  return path[0] == '/';
#endif
}

std::string GetWorkingDirectory() {
#if defined(V8_OS_WIN)
  char system_buffer[MAX_PATH];
  // Unicode paths are unsupported, which is fine as long as
  // the test directory doesn't include any such paths.
  DWORD len = GetCurrentDirectoryA(MAX_PATH, system_buffer);
  CHECK_GT(len, 0);
  return system_buffer;
#else
  char curdir[PATH_MAX];
  CHECK_NOT_NULL(getcwd(curdir, PATH_MAX));
  return curdir;
#endif
}

// Returns the directory part of path, without the trailing '/'.
std::string DirName(const std::string& path) {
  DCHECK(IsAbsolutePath(path));
  size_t last_slash = path.find_last_of('/');
  DCHECK(last_slash != std::string::npos);
  return path.substr(0, last_slash);
}

// Resolves path to an absolute path if necessary, and does some
// normalization (eliding references to the current directory
// and replacing backslashes with slashes).
std::string NormalizePath(const std::string& path,
                          const std::string& dir_name) {
  std::string absolute_path;
  if (IsAbsolutePath(path)) {
    absolute_path = path;
  } else {
    absolute_path = dir_name + '/' + path;
  }
  std::replace(absolute_path.begin(), absolute_path.end(), '\\', '/');
  std::vector<std::string> segments;
  std::istringstream segment_stream(absolute_path);
  std::string segment;
  while (std::getline(segment_stream, segment, '/')) {
    if (segment == "..") {
      if (!segments.empty()) segments.pop_back();
    } else if (segment != ".") {
      segments.push_back(segment);
    }
  }
  // Join path segments.
  std::ostringstream os;
  if (segments.size() > 1) {
    std::copy(segments.begin(), segments.end() - 1,
              std::ostream_iterator<std::string>(os, "/"));
    os << *segments.rbegin();
  } else {
    os << "/";
    if (!segments.empty()) os << segments[0];
  }
  return os.str();
}

// Resolves specifier to an absolute path if necessary, and does some
// normalization (eliding references to the current directory
// and replacing backslashes with slashes).
//
// If specifier is a data url, returns it unchanged.
std::string NormalizeModuleSpecifier(const std::string& specifier,
                                     const std::string& dir_name) {
  if (specifier.starts_with(kDataURLPrefix)) return specifier;
  return NormalizePath(specifier, dir_name);
}

MaybeLocal<Module> ResolveModuleCallback(Local<Context> context,
                                         Local<String> specifier,
                                         Local<FixedArray> import_attributes,
                                         Local<Module> referrer) {
  Isolate* isolate = context->GetIsolate();
  std::shared_ptr<ModuleEmbedderData> module_data =
      GetModuleDataFromContext(context);
  std::string referrer_specifier = module_data->GetModuleSpecifier(referrer);

  std::string stl_specifier = ToSTLString(isolate, specifier);
  std::string absolute_path =
      NormalizeModuleSpecifier(stl_specifier, DirName(referrer_specifier));
  ModuleType module_type =
      ModuleEmbedderData::ModuleTypeFromImportSpecifierAndAttributes(
          context, stl_specifier, import_attributes, true);
  return module_data->GetModule(std::make_pair(absolute_path, module_type));
}

MaybeLocal<Object> ResolveModuleSourceCallback(
    Local<Context> context, Local<String> specifier,
    Local<FixedArray> import_attributes, Local<Module> referrer) {
  Isolate* isolate = context->GetIsolate();
  std::shared_ptr<ModuleEmbedderData> module_data =
      GetModuleDataFromContext(context);
  std::string referrer_specifier = module_data->GetModuleSpecifier(referrer);

  std::string stl_specifier = ToSTLString(isolate, specifier);
  std::string absolute_path =
      NormalizeModuleSpecifier(stl_specifier, DirName(referrer_specifier));
  ModuleType module_type =
      ModuleEmbedderData::ModuleTypeFromImportSpecifierAndAttributes(
          context, stl_specifier, import_attributes, true);

  return module_data->GetModuleSource(
      std::make_pair(absolute_path, module_type));
}

}  // anonymous namespace

MaybeLocal<Object> Shell::FetchModuleSource(Local<Module> referrer,
                                            Local<Context> context,
                                            const std::string& module_specifier,
                                            ModuleType module_type) {
  Isolate* isolate = context->GetIsolate();
  DCHECK(IsAbsolutePath(module_specifier));
  auto file = ReadFileData(isolate, module_specifier.c_str());

  std::shared_ptr<ModuleEmbedderData> module_data =
      GetModuleDataFromContext(context);
  if (!file) {
    std::string msg = "d8: Error reading module from " + module_specifier;
    if (!referrer.IsEmpty()) {
      std::string referrer_specifier =
          module_data->GetModuleSpecifier(referrer);
      msg += "\n    imported by " + referrer_specifier;
    }
    ThrowError(isolate,
               v8::String::NewFromUtf8(isolate, msg.c_str()).ToLocalChecked());
    return MaybeLocal<Object>();
  }

  Local<Object> module_source;
  switch (module_type) {
    case ModuleType::kWebAssembly: {
      if (!v8::WasmModuleObject::Compile(
               isolate,
               MemorySpan<const uint8_t>(static_cast<uint8_t*>(file->memory()),
                                         file->size()))
               .ToLocal(&module_source)) {
        return MaybeLocal<Object>();
      }
      break;
    }
    default:
      // https://tc39.es/proposal-source-phase-imports/#table-abstract-methods-of-module-records
      // For Module Records that do not have a source representation,
      // GetModuleSource() must always return a throw completion whose [[Value]]
      // is a ReferenceError.
      ThrowException(
          isolate, v8::Exception::SyntaxError(String::NewFromUtf8Literal(
                       isolate, "Module source can not be imported for type")));
      return MaybeLocal<Object>();
  }

  CHECK(
      module_data->module_source_map
          .insert(std::make_pair(std::make_pair(module_specifier, module_type),
                                 Global<Object>(isolate, module_source)))
          .second);
  return module_source;
}

// file_name must be either an absolute path to the filesystem or a data URL.
MaybeLocal<Module> Shell::FetchModuleTree(Local<Module> referrer,
                                          Local<Context> context,
                                          const std::string& module_specifier,
                                          ModuleType module_type) {
  Isolate* isolate = context->GetIsolate();
  const bool is_data_url = module_specifier.starts_with(kDataURLPrefix);
  MaybeLocal<String> source_text;
  if (is_data_url) {
    source_text = String::NewFromUtf8(
        isolate, module_specifier.c_str() + strlen(kDataURLPrefix));
  } else {
    DCHECK(IsAbsolutePath(module_specifier));
    source_text = ReadFile(isolate, module_specifier.c_str(), false);
    if (source_text.IsEmpty() && options.fuzzy_module_file_extensions) {
      std::string fallback_file_name = module_specifier + ".js";
      source_text = ReadFile(isolate, fallback_file_name.c_str(), false);
      if (source_text.IsEmpty()) {
        fallback_file_name = module_specifier + ".mjs";
        source_text = ReadFile(isolate, fallback_file_name.c_str());
      }
    }
  }

  std::shared_ptr<ModuleEmbedderData> module_data =
      GetModuleDataFromContext(context);
  if (source_text.IsEmpty()) {
    std::string msg = "d8: Error reading module from " + module_specifier;
    if (!referrer.IsEmpty()) {
      std::string referrer_specifier =
          module_data->GetModuleSpecifier(referrer);
      msg += "\n    imported by " + referrer_specifier;
    }
    ThrowError(isolate,
               v8::String::NewFromUtf8(isolate, msg.c_str()).ToLocalChecked());
    return MaybeLocal<Module>();
  }

  Local<String> resource_name =
      String::NewFromUtf8(isolate, module_specifier.c_str()).ToLocalChecked();
  ScriptOrigin origin =
      CreateScriptOrigin(isolate, resource_name, ScriptType::kModule);

  Local<Module> module;
  if (module_type == ModuleType::kJavaScript) {
    ScriptCompiler::Source source(source_text.ToLocalChecked(), origin);
    if (!CompileString<Module>(isolate, context, source_text.ToLocalChecked(),
                               origin)
             .ToLocal(&module)) {
      return MaybeLocal<Module>();
    }
  } else if (module_type == ModuleType::kJSON) {
    Local<Value> parsed_json;
    if (!v8::JSON::Parse(context, source_text.ToLocalChecked())
             .ToLocal(&parsed_json)) {
      return MaybeLocal<Module>();
    }

    auto export_names = v8::to_array<Local<String>>(
        {String::NewFromUtf8(isolate, "default").ToLocalChecked()});

    module = v8::Module::CreateSyntheticModule(
        isolate,
        String::NewFromUtf8(isolate, module_specifier.c_str()).ToLocalChecked(),
        export_names, Shell::JSONModuleEvaluationSteps);

    CHECK(module_data->json_module_to_parsed_json_map
              .insert(std::make_pair(Global<Module>(isolate, module),
                                     Global<Value>(isolate, parsed_json)))
              .second);
  } else {
    UNREACHABLE();
  }

  CHECK(
      module_data->module_map
          .insert(std::make_pair(std::make_pair(module_specifier, module_type),
                                 Global<Module>(isolate, module)))
          .second);
  CHECK(module_data->module_to_specifier_map
            .insert(std::make_pair(Global<Module>(isolate, module),
                                   module_specifier))
            .second);

  // data URLs don't support further imports, so we're done.
  if (is_data_url) return module;

  std::string dir_name = DirName(module_specifier);

  Local<FixedArray> module_requests = module->GetModuleRequests();
  for (int i = 0, length = module_requests->Length(); i < length; ++i) {
    Local<ModuleRequest> module_request =
        module_requests->Get(context, i).As<ModuleRequest>();
    std::string specifier =
        ToSTLString(isolate, module_request->GetSpecifier());
    std::string normalized_specifier =
        NormalizeModuleSpecifier(specifier, dir_name);
    Local<FixedArray> import_attributes = module_request->GetImportAttributes();
    ModuleType request_module_type =
        ModuleEmbedderData::ModuleTypeFromImportSpecifierAndAttributes(
            context, normalized_specifier, import_attributes, true);

    if (request_module_type == ModuleType::kInvalid) {
      ThrowError(isolate, "Invalid module type was asserted");
      return MaybeLocal<Module>();
    }

    if (module_request->GetPhase() == ModuleImportPhase::kSource) {
      if (module_data->module_source_map.count(
              std::make_pair(normalized_specifier, request_module_type))) {
        continue;
      }

      if (FetchModuleSource(module, context, normalized_specifier,
                            request_module_type)
              .IsEmpty()) {
        return MaybeLocal<Module>();
      }
    } else {
      if (module_data->module_map.count(
              std::make_pair(normalized_specifier, request_module_type))) {
        continue;
      }

      if (FetchModuleTree(module, context, normalized_specifier,
                          request_module_type)
              .IsEmpty()) {
        return MaybeLocal<Module>();
      }
    }
  }

  return module;
}

MaybeLocal<Value> Shell::JSONModuleEvaluationSteps(Local<Context> context,
                                                   Local<Module> module) {
  Isolate* isolate = context->GetIsolate();

  std::shared_ptr<ModuleEmbedderData> module_data =
      GetModuleDataFromContext(context);
  Local<Value> json_value = module_data->GetJsonModuleValue(module);

  TryCatch try_catch(isolate);
  Maybe<bool> result = module->SetSyntheticModuleExport(
      isolate,
      String::NewFromUtf8Literal(isolate, "default",
                                 NewStringType::kInternalized),
      json_value);

  // Setting the default export should never fail.
  CHECK(!try_catch.HasCaught());
  CHECK(!result.IsNothing() && result.FromJust());

  Local<Promise::Resolver> resolver =
      Promise::Resolver::New(context).ToLocalChecked();
  resolver->Resolve(context, Undefined(isolate)).ToChecked();
  return resolver->GetPromise();
}

struct DynamicImportData {
  DynamicImportData(Isolate* isolate_, Local<Context> context_,
                    Local<Value> referrer_, Local<String> specifier_,
                    ModuleImportPhase phase_,
                    Local<FixedArray> import_attributes_,
                    Local<Promise::Resolver> resolver_)
      : isolate(isolate_), phase(phase_) {
    context.Reset(isolate, context_);
    referrer.Reset(isolate, referrer_);
    specifier.Reset(isolate, specifier_);
    import_attributes.Reset(isolate, import_attributes_);
    resolver.Reset(isolate, resolver_);
  }

  Isolate* isolate;
  // The initiating context. It can be the Realm created by d8, or the context
  // created by ShadowRealm built-in.
  Global<Context> context;
  Global<Value> referrer;
  Global<String> specifier;
  ModuleImportPhase phase;
  Global<FixedArray> import_attributes;
  Global<Promise::Resolver> resolver;
};

namespace {

enum ModuleResolutionDataIndex : uint32_t {
  kResolver = 0,
  kNamespaceOrSource = 1,
};

}  // namespace

void Shell::ModuleResolutionSuccessCallback(
    const FunctionCallbackInfo<Value>& info) {
  DCHECK(i::ValidateCallbackInfo(info));
  Isolate* isolate(info.GetIsolate());
  HandleScope handle_scope(isolate);
  Local<Array> module_resolution_data(info.Data().As<Array>());
  Local<Context> context(isolate->GetCurrentContext());

  Local<Promise::Resolver> resolver(
      module_resolution_data->Get(context, ModuleResolutionDataIndex::kResolver)
          .ToLocalChecked()
          .As<Promise::Resolver>());
  Local<Value> namespace_or_source(
      module_resolution_data
          ->Get(context, ModuleResolutionDataIndex::kNamespaceOrSource)
          .ToLocalChecked());

  PerIsolateData* data = PerIsolateData::Get(isolate);
  Local<Context> realm = data->realms_[data->realm_current_].Get(isolate);
  Context::Scope context_scope(realm);

  resolver->Resolve(realm, namespace_or_source).ToChecked();
}

void Shell::ModuleResolutionFailureCallback(
    const FunctionCallbackInfo<Value>& info) {
  DCHECK(i::ValidateCallbackInfo(info));
  Isolate* isolate(info.GetIsolate());
  HandleScope handle_scope(isolate);
  Local<Array> module_resolution_data(info.Data().As<Array>());
  Local<Context> context(isolate->GetCurrentContext());

  Local<Promise::Resolver> resolver(
      module_resolution_data->Get(context, ModuleResolutionDataIndex::kResolver)
          .ToLocalChecked()
          .As<Promise::Resolver>());

  PerIsolateData* data = PerIsolateData::Get(isolate);
  Local<Context> realm = data->realms_[data->realm_current_].Get(isolate);
  Context::Scope context_scope(realm);

  DCHECK_EQ(info.Length(), 1);
  resolver->Reject(realm, info[0]).ToChecked();
}

MaybeLocal<Promise> Shell::HostImportModuleDynamically(
    Local<Context> context, Local<Data> host_defined_options,
    Local<Value> resource_name, Local<String> specifier,
    Local<FixedArray> import_attributes) {
  return HostImportModuleWithPhaseDynamically(
      context, host_defined_options, resource_name, specifier,
      ModuleImportPhase::kEvaluation, import_attributes);
}

MaybeLocal<Promise> Shell::HostImportModuleWithPhaseDynamically(
    Local<Context> context, Local<Data> host_defined_options,
    Local<Value> resource_name, Local<String> specifier,
    ModuleImportPhase phase, Local<FixedArray> import_attributes) {
  Isolate* isolate = context->GetIsolate();

  MaybeLocal<Promise::Resolver> maybe_resolver =
      Promise::Resolver::New(context);
  Local<Promise::Resolver> resolver;
  if (!maybe_resolver.ToLocal(&resolver)) return MaybeLocal<Promise>();

  if (!resource_name->IsNull() &&
      !IsValidHostDefinedOptions(context, host_defined_options,
                                 resource_name)) {
    resolver
        ->Reject(context, v8::Exception::TypeError(String::NewFromUtf8Literal(
                              isolate, "Invalid host defined options")))
        .ToChecked();
  } else {
    DynamicImportData* data =
        new DynamicImportData(isolate, context, resource_name, specifier, phase,
                              import_attributes, resolver);
    PerIsolateData::Get(isolate)->AddDynamicImportData(data);
    isolate->EnqueueMicrotask(Shell::DoHostImportModuleDynamically, data);
  }
  return resolver->GetPromise();
}

void Shell::HostInitializeImportMetaObject(Local<Context> context,
                                           Local<Module> module,
                                           Local<Object> meta) {
  Isolate* isolate = context->GetIsolate();
  HandleScope handle_scope(isolate);

  std::shared_ptr<ModuleEmbedderData> module_data =
      GetModuleDataFromContext(context);
  std::string specifier = module_data->GetModuleSpecifier(module);

  Local<String> url_key =
      String::NewFromUtf8Literal(isolate, "url", NewStringType::kInternalized);
  Local<String> url =
      String::NewFromUtf8(isolate, specifier.c_str()).ToLocalChecked();
  meta->CreateDataProperty(context, url_key, url).ToChecked();
}

MaybeLocal<Context> Shell::HostCreateShadowRealmContext(
    Local<Context> initiator_context) {
  Local<Context> context = v8::Context::New(initiator_context->GetIsolate());
  std::shared_ptr<ModuleEmbedderData> shadow_realm_data =
      InitializeModuleEmbedderData(context);
  std::shared_ptr<ModuleEmbedderData> initiator_data =
      GetModuleDataFromContext(initiator_context);

  // ShadowRealms are synchronously accessible and are always in the same origin
  // as the initiator context.
  context->SetSecurityToken(initiator_context->GetSecurityToken());
  shadow_realm_data->origin = initiator_data->origin;

  return context;
}

void Shell::DoHostImportModuleDynamically(void* import_data) {
  DynamicImportData* import_data_ =
      static_cast<DynamicImportData*>(import_data);

  Isolate* isolate(import_data_->isolate);
  Global<Context> global_realm;
  Global<Promise::Resolver> global_resolver;
  Global<Promise> global_result_promise;
  Global<Value> global_namespace_or_source;

  TryCatch try_catch(isolate);
  try_catch.SetVerbose(true);

  {
    HandleScope handle_scope(isolate);
    Local<Context> realm = import_data_->context.Get(isolate);
    Local<Value> referrer = import_data_->referrer.Get(isolate);
    Local<String> v8_specifier = import_data_->specifier.Get(isolate);
    ModuleImportPhase phase = import_data_->phase;
    Local<FixedArray> import_attributes =
        import_data_->import_attributes.Get(isolate);
    Local<Promise::Resolver> resolver = import_data_->resolver.Get(isolate);

    global_realm.Reset(isolate, realm);
    global_resolver.Reset(isolate, resolver);

    PerIsolateData* data = PerIsolateData::Get(isolate);
    data->DeleteDynamicImportData(import_data_);

    Context::Scope context_scope(realm);
    std::string specifier = ToSTLString(isolate, v8_specifier);

    ModuleType module_type =
        ModuleEmbedderData::ModuleTypeFromImportSpecifierAndAttributes(
            realm, specifier, import_attributes, false);

    if (module_type == ModuleType::kInvalid) {
      ThrowError(isolate, "Invalid module type was asserted");
      CHECK(try_catch.HasCaught());
      resolver->Reject(realm, try_catch.Exception()).ToChecked();
      return;
    }

    std::shared_ptr<ModuleEmbedderData> module_data =
        GetModuleDataFromContext(realm);

    std::string source_url = referrer->IsNull()
                                 ? module_data->origin
                                 : ToSTLString(isolate, referrer.As<String>());
    std::string dir_name =
        DirName(NormalizePath(source_url, GetWorkingDirectory()));
    std::string absolute_path = NormalizeModuleSpecifier(specifier, dir_name);

    switch (phase) {
      case ModuleImportPhase::kSource: {
        Local<Object> module_source;
        auto module_it = module_data->module_source_map.find(
            std::make_pair(absolute_path, module_type));
        if (module_it != module_data->module_source_map.end()) {
          module_source = module_it->second.Get(isolate);
        } else if (!FetchModuleSource(Local<Module>(), realm, absolute_path,
                                      module_type)
                        .ToLocal(&module_source)) {
          CHECK(try_catch.HasCaught());
          if (isolate->IsExecutionTerminating()) {
            Shell::ReportException(isolate, try_catch);
          } else {
            resolver->Reject(realm, try_catch.Exception()).ToChecked();
          }
          return;
        }
        Local<Promise::Resolver> module_resolver =
            Promise::Resolver::New(realm).ToLocalChecked();
        module_resolver->Resolve(realm, module_source).ToChecked();

        global_namespace_or_source.Reset(isolate, module_source);
        global_result_promise.Reset(isolate, module_resolver->GetPromise());
        break;
      }
      case v8::ModuleImportPhase::kEvaluation: {
        Local<Module> root_module;
        auto module_it = module_data->module_map.find(
            std::make_pair(absolute_path, module_type));
        if (module_it != module_data->module_map.end()) {
          root_module = module_it->second.Get(isolate);
        } else if (!FetchModuleTree(Local<Module>(), realm, absolute_path,
                                    module_type)
                        .ToLocal(&root_module)) {
          CHECK(try_catch.HasCaught());
          if (isolate->IsExecutionTerminating()) {
            Shell::ReportException(isolate, try_catch);
          } else {
            resolver->Reject(realm, try_catch.Exception()).ToChecked();
          }
          return;
        }

        if (root_module
                ->InstantiateModule(realm, ResolveModuleCallback,
                                    ResolveModuleSourceCallback)
                .FromMaybe(false)) {
          MaybeLocal<Value> maybe_result = root_module->Evaluate(realm);
          CHECK(!maybe_result.IsEmpty());
          global_result_promise.Reset(
              isolate, maybe_result.ToLocalChecked().As<Promise>());
          global_namespace_or_source.Reset(isolate,
                                           root_module->GetModuleNamespace());
        }
        break;
      }
      default: {
        UNREACHABLE();
      }
    }
  }

  if (global_result_promise.IsEmpty()) {
    DCHECK(try_catch.HasCaught());
    HandleScope handle_scope(isolate);
    Local<Context> realm = global_realm.Get(isolate);
    Local<Promise::Resolver> resolver = global_resolver.Get(isolate);
    resolver->Reject(realm, try_catch.Exception()).ToChecked();
    return;
  }

  {
    // This method is invoked from a microtask, where in general we may have
    // an non-trivial stack. Emptying the message queue below may trigger the
    // execution of a stackless GC. We need to override the embedder stack
    // state, to force scanning the stack, if this happens.
    i::Heap* heap = reinterpret_cast<i::Isolate*>(isolate)->heap();
    i::EmbedderStackStateScope scope(
        heap, i::EmbedderStackStateOrigin::kExplicitInvocation,
        StackState::kMayContainHeapPointers);
    EmptyMessageQueues(isolate);
  }

  // Setup callbacks, and then chain them to the result promise.
  HandleScope handle_scope(isolate);
  Local<Context> realm = global_realm.Get(isolate);
  Local<Promise::Resolver> resolver = global_resolver.Get(isolate);
  Local<Promise> result_promise = global_result_promise.Get(isolate);
  Local<Value> namespace_or_source = global_namespace_or_source.Get(isolate);

  Local<Array> module_resolution_data = v8::Array::New(isolate);
  module_resolution_data->SetPrototypeV2(realm, v8::Null(isolate)).ToChecked();
  module_resolution_data
      ->Set(realm, ModuleResolutionDataIndex::kResolver, resolver)
      .ToChecked();
  module_resolution_data
      ->Set(realm, ModuleResolutionDataIndex::kNamespaceOrSource,
            namespace_or_source)
      .ToChecked();
  Local<Function> callback_success;
  CHECK(Function::New(realm, ModuleResolutionSuccessCallback,
                      module_resolution_data)
            .ToLocal(&callback_success));
  Local<Function> callback_failure;
  CHECK(Function::New(realm, ModuleResolutionFailureCallback,
                      module_resolution_data)
            .ToLocal(&callback_failure));
  result_promise->Then(realm, callback_success, callback_failure)
      .ToLocalChecked();
}

bool Shell::ExecuteModule(Isolate* isolate, const char* file_name) {
  HandleScope handle_scope(isolate);
  Global<Module> global_root_module;
  Global<Promise> global_result_promise;

  // Use a non-verbose TryCatch and report exceptions manually using
  // Shell::ReportException, because some errors (such as file errors) are
  // thrown without entering JS and thus do not trigger
  // isolate->ReportPendingMessages().
  TryCatch try_catch(isolate);

  {
    PerIsolateData* data = PerIsolateData::Get(isolate);
    Local<Context> realm = data->realms_[data->realm_current_].Get(isolate);
    Context::Scope context_scope(realm);

    std::string absolute_path =
        NormalizeModuleSpecifier(file_name, GetWorkingDirectory());

    std::shared_ptr<ModuleEmbedderData> module_data =
        GetModuleDataFromContext(realm);
    Local<Module> root_module;
    auto module_it = module_data->module_map.find(
        std::make_pair(absolute_path, ModuleType::kJavaScript));
    if (module_it != module_data->module_map.end()) {
      root_module = module_it->second.Get(isolate);
    } else if (!FetchModuleTree(Local<Module>(), realm, absolute_path,
                                ModuleType::kJavaScript)
                    .ToLocal(&root_module)) {
      CHECK(try_catch.HasCaught());
      ReportException(isolate, try_catch);
      return false;
    }
    global_root_module.Reset(isolate, root_module);

    module_data->origin = absolute_path;

    MaybeLocal<Value> maybe_result;
    if (root_module
            ->InstantiateModule(realm, ResolveModuleCallback,
                                ResolveModuleSourceCallback)
            .FromMaybe(false)) {
      maybe_result = root_module->Evaluate(realm);
      CHECK(!maybe_result.IsEmpty());
      global_result_promise.Reset(isolate,
                                  maybe_result.ToLocalChecked().As<Promise>());
    }
  }

  if (!global_result_promise.IsEmpty()) {
    EmptyMessageQueues(isolate);
  } else {
    DCHECK(try_catch.HasCaught());
    ReportException(isolate, try_catch);
    return false;
  }

  // Loop until module execution finishes
  while (isolate->HasPendingBackgroundTasks() ||
         (i::ValueHelper::HandleAsValue(global_result_promise)->State() ==
              Promise::kPending &&
          reinterpret_cast<i::Isolate*>(isolate)
                  ->default_microtask_queue()
                  ->size() > 0)) {
    Shell::CompleteMessageLoop(isolate);
  }

  {
    Local<Promise> result_promise = global_result_promise.Get(isolate);
    Local<Module> root_module = global_root_module.Get(isolate);

    if (result_promise->State() == Promise::kRejected) {
      // If the exception has been caught by the promise pipeline, we rethrow
      // here in order to ReportException.
      // TODO(cbruni): Clean this up a
```