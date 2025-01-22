Response:
### 功能归纳

`jvm.js` 是 Frida 工具中用于与 Java 虚拟机（JVM）交互的模块，主要功能包括：

1. **JVM 方法替换与恢复**：
   - 通过 `JvmMethodMangler` 类，可以实现对 JVM 方法的动态替换和恢复。具体来说，它允许用户替换某个 Java 方法的实现，并在需要时恢复原始方法。
   - 例如，`replace` 方法用于替换方法的实现，而 `revert` 方法用于恢复原始方法。

2. **JVM 方法信息获取与操作**：
   - 通过 `fetchJvmMethod` 和 `readJvmMethod` 函数，可以获取 JVM 方法的详细信息，包括方法的大小、常量池、访问标志、vtable 索引等。
   - `installJvmMethod` 函数用于将新的方法实现安装到 JVM 中，并更新相关数据结构（如 vtable、方法数组等）。

3. **JVM 线程管理**：
   - `withJvmThread` 函数用于在 JVM 线程上下文中执行代码，确保操作在正确的线程环境中进行。
   - `makeThreadFromJniHelper` 函数用于从 JNI 环境中获取当前线程的指针。

4. **JVM 内部 API 调用**：
   - 通过 `getApi` 函数，获取 JVM 内部 API 的地址，并封装为可调用的函数。这些 API 包括 `JNI_GetCreatedJavaVMs`、`JVM_Sleep`、`VMThread::execute` 等。
   - 这些 API 允许 Frida 直接与 JVM 内部进行交互，执行诸如方法替换、线程管理等操作。

5. **JVM 方法清理与优化**：
   - `forceSweep` 函数用于强制清理 JVM 的代码缓存，确保替换后的方法能够立即生效。
   - `nativeJvmMethod` 函数用于将方法标记为本地方法，并清除相关的 JIT 编译代码。

6. **JVM 内部数据结构解析**：
   - 通过 `_getJvmMethodSpec` 和 `_getJvmInstanceKlassSpec` 函数，解析 JVM 内部的数据结构，如方法表、vtable、常量池等。
   - 这些信息对于动态替换方法和操作 JVM 内部数据结构至关重要。

### 涉及二进制底层与 Linux 内核的示例

1. **方法替换与 vtable 操作**：
   - 在 JVM 中，方法的调用通常通过 vtable（虚函数表）来实现。`jvm.js` 通过直接操作 vtable 来实现方法的动态替换。
   - 例如，`installJvmMethod` 函数会更新 vtable 中的方法指针，使其指向新的方法实现。

2. **JVM 内部 API 调用**：
   - `getApi` 函数通过解析 JVM 的动态链接库（如 `libjvm.so`）中的符号，获取内部 API 的地址。这些 API 通常用于管理 JVM 的内部状态，如线程、方法、类加载器等。
   - 例如，`JNI_GetCreatedJavaVMs` 用于获取当前 JVM 实例的指针，`VMThread::execute` 用于在 JVM 线程中执行操作。

### 使用 LLDB 复刻调试功能的示例

假设我们想要复刻 `forceSweep` 函数的功能，强制清理 JVM 的代码缓存。我们可以使用 LLDB 脚本来实现类似的功能。

#### LLDB Python 脚本示例

```python
import lldb

def force_sweep(debugger, command, result, internal_dict):
    # 获取当前进程
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    
    # 获取 NMethodSweeper::sweep_code_cache 函数的地址
    sweep_code_cache_addr = target.FindSymbols("NMethodSweeper::sweep_code_cache")[0].GetStartAddress().GetLoadAddress(target)
    
    # 调用 sweep_code_cache 函数
    process.ExecuteExpression(f"(void (*)()){sweep_code_cache_addr}()")

# 注册命令
def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f lldb_script.force_sweep force_sweep')
```

#### 使用 LLDB 命令

```bash
lldb -p <pid>
(lldb) force_sweep
```

### 假设输入与输出

1. **输入**：
   - 用户调用 `forceSweep` 函数，传入 JNI 环境指针 `env`。
   
2. **输出**：
   - JVM 的代码缓存被强制清理，替换后的方法立即生效。

### 用户常见错误示例

1. **方法替换失败**：
   - 用户可能尝试替换一个不存在的方法，或者方法的签名不匹配，导致替换失败。
   - 例如，用户尝试替换一个非本地方法为本地方法，但没有正确设置方法的访问标志。

2. **线程上下文错误**：
   - 用户可能在没有正确获取 JVM 线程上下文的情况下执行操作，导致操作失败或 JVM 崩溃。
   - 例如，用户在没有调用 `withJvmThread` 的情况下直接操作 JVM 内部数据结构。

### 用户操作步骤

1. **启动 Frida**：
   - 用户启动 Frida 并附加到目标 JVM 进程。

2. **加载 `jvm.js` 模块**：
   - 用户加载 `jvm.js` 模块，获取与 JVM 交互的 API。

3. **替换方法**：
   - 用户调用 `JvmMethodMangler` 的 `replace` 方法，替换目标方法的实现。

4. **执行操作**：
   - 用户执行一些操作，触发替换后的方法。

5. **恢复方法**：
   - 用户调用 `revert` 方法，恢复原始方法的实现。

6. **清理缓存**：
   - 用户调用 `forceSweep` 函数，确保替换后的方法立即生效。

通过这些步骤，用户可以动态地替换和恢复 JVM 中的方法，实现调试和监控的目的。
Prompt: 
```
这是目录为frida/subprojects/frida-java-bridge/lib/jvm.js的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
这是第1部分，共2部分，请归纳一下它的功能

"""
const {
  jvmtiVersion,
  jvmtiCapabilities,
  EnvJvmti
} = require('./jvmti');
const { parseInstructionsAt } = require('./machine-code');
const memoize = require('./memoize');
const { checkJniResult } = require('./result');
const VM = require('./vm');

const jsizeSize = 4;
const { pointerSize } = Process;

const JVM_ACC_NATIVE = 0x0100;
const JVM_ACC_IS_OLD = 0x00010000;
const JVM_ACC_IS_OBSOLETE = 0x00020000;
const JVM_ACC_NOT_C2_COMPILABLE = 0x02000000;
const JVM_ACC_NOT_C1_COMPILABLE = 0x04000000;
const JVM_ACC_NOT_C2_OSR_COMPILABLE = 0x08000000;

const nativeFunctionOptions = {
  exceptions: 'propagate'
};

const getJvmMethodSpec = memoize(_getJvmMethodSpec);
const getJvmInstanceKlassSpec = memoize(_getJvmInstanceKlassSpec);
const getJvmThreadSpec = memoize(_getJvmThreadSpec);

let cachedApi = null;
let manglersScheduled = false;
const replaceManglers = new Map();
const revertManglers = new Map();

function getApi () {
  if (cachedApi === null) {
    cachedApi = _getApi();
  }
  return cachedApi;
}

function _getApi () {
  const vmModules = Process.enumerateModules()
    .filter(m => /jvm.(dll|dylib|so)$/.test(m.name));
  if (vmModules.length === 0) {
    return null;
  }

  const vmModule = vmModules[0];

  const temporaryApi = {
    flavor: 'jvm'
  };

  const pending = Process.platform === 'windows'
    ? [{
        module: vmModule.path,
        functions: {
          JNI_GetCreatedJavaVMs: ['JNI_GetCreatedJavaVMs', 'int', ['pointer', 'int', 'pointer']],
          JVM_Sleep: ['JVM_Sleep', 'void', ['pointer', 'pointer', 'long']],
          'VMThread::execute': ['VMThread::execute', 'void', ['pointer']],
          'Method::size': ['Method::size', 'int', ['int']],
          'Method::set_native_function': ['Method::set_native_function', 'void', ['pointer', 'pointer', 'int']],
          'Method::clear_native_function': ['Method::clear_native_function', 'void', ['pointer']],
          'Method::jmethod_id': ['Method::jmethod_id', 'pointer', ['pointer']],
          'ClassLoaderDataGraph::classes_do': ['ClassLoaderDataGraph::classes_do', 'void', ['pointer']],
          'NMethodSweeper::sweep_code_cache': ['NMethodSweeper::sweep_code_cache', 'void', []],
          'OopMapCache::flush_obsolete_entries': ['OopMapCache::flush_obsolete_entries', 'void', ['pointer']]
        },
        variables: {
          'VM_RedefineClasses::`vftable\'': function (address) {
            this.vtableRedefineClasses = address;
          },
          'VM_RedefineClasses::doit': function (address) {
            this.redefineClassesDoIt = address;
          },
          'VM_RedefineClasses::doit_prologue': function (address) {
            this.redefineClassesDoItPrologue = address;
          },
          'VM_RedefineClasses::doit_epilogue': function (address) {
            this.redefineClassesDoItEpilogue = address;
          },
          'VM_RedefineClasses::allow_nested_vm_operations': function (address) {
            this.redefineClassesAllow = address;
          },
          'NMethodSweeper::_traversals': function (address) {
            this.traversals = address;
          },
          'NMethodSweeper::_should_sweep': function (address) {
            this.shouldSweep = address;
          }
        },
        optionals: [
        ]
      }]
  // If platform is not Windows
    : [{
        module: vmModule.path,
        functions: {
          JNI_GetCreatedJavaVMs: ['JNI_GetCreatedJavaVMs', 'int', ['pointer', 'int', 'pointer']],

          _ZN6Method4sizeEb: ['Method::size', 'int', ['int']],
          _ZN6Method19set_native_functionEPhb: ['Method::set_native_function', 'void', ['pointer', 'pointer', 'int']],
          _ZN6Method21clear_native_functionEv: ['Method::clear_native_function', 'void', ['pointer']],
          // JDK >= 17
          _ZN6Method24restore_unshareable_infoEP10JavaThread: ['Method::restore_unshareable_info', 'void', ['pointer', 'pointer']],
          // JDK < 17
          _ZN6Method24restore_unshareable_infoEP6Thread: ['Method::restore_unshareable_info', 'void', ['pointer', 'pointer']],
          _ZN6Method10jmethod_idEv: ['Method::jmethod_id', 'pointer', ['pointer']],
          _ZN6Method10clear_codeEv: function (address) {
            const clearCode = new NativeFunction(address, 'void', ['pointer'], nativeFunctionOptions);
            this['Method::clear_code'] = function (thisPtr) {
              clearCode(thisPtr);
            };
          },
          _ZN6Method10clear_codeEb: function (address) {
            const clearCode = new NativeFunction(address, 'void', ['pointer', 'int'], nativeFunctionOptions);
            const lock = 0;
            this['Method::clear_code'] = function (thisPtr) {
              clearCode(thisPtr, lock);
            };
          },

          // JDK >= 13
          _ZN18VM_RedefineClasses19mark_dependent_codeEP13InstanceKlass: ['VM_RedefineClasses::mark_dependent_code', 'void', ['pointer', 'pointer']],
          _ZN18VM_RedefineClasses20flush_dependent_codeEv: ['VM_RedefineClasses::flush_dependent_code', 'void', []],
          // JDK < 13
          _ZN18VM_RedefineClasses20flush_dependent_codeEP13InstanceKlassP6Thread: ['VM_RedefineClasses::flush_dependent_code', 'void', ['pointer', 'pointer', 'pointer']],
          // JDK < 10
          _ZN18VM_RedefineClasses20flush_dependent_codeE19instanceKlassHandleP6Thread: ['VM_RedefineClasses::flush_dependent_code', 'void', ['pointer', 'pointer', 'pointer']],

          _ZN19ResolvedMethodTable21adjust_method_entriesEPb: ['ResolvedMethodTable::adjust_method_entries', 'void', ['pointer']],
          // JDK < 10
          _ZN15MemberNameTable21adjust_method_entriesEP13InstanceKlassPb: ['MemberNameTable::adjust_method_entries', 'void', ['pointer', 'pointer', 'pointer']],

          _ZN17ConstantPoolCache21adjust_method_entriesEPb: function (address) {
            const adjustMethod = new NativeFunction(address, 'void', ['pointer', 'pointer'], nativeFunctionOptions);
            this['ConstantPoolCache::adjust_method_entries'] = function (thisPtr, holderPtr, tracePtr) {
              adjustMethod(thisPtr, tracePtr);
            };
          },
          // JDK < 13
          _ZN17ConstantPoolCache21adjust_method_entriesEP13InstanceKlassPb: function (address) {
            const adjustMethod = new NativeFunction(address, 'void', ['pointer', 'pointer', 'pointer'], nativeFunctionOptions);
            this['ConstantPoolCache::adjust_method_entries'] = function (thisPtr, holderPtr, tracePtr) {
              adjustMethod(thisPtr, holderPtr, tracePtr);
            };
          },

          _ZN20ClassLoaderDataGraph10classes_doEP12KlassClosure: ['ClassLoaderDataGraph::classes_do', 'void', ['pointer']],
          _ZN20ClassLoaderDataGraph22clean_deallocate_listsEb: ['ClassLoaderDataGraph::clean_deallocate_lists', 'void', ['int']],

          _ZN10JavaThread27thread_from_jni_environmentEP7JNIEnv_: ['JavaThread::thread_from_jni_environment', 'pointer', ['pointer']],

          _ZN8VMThread7executeEP12VM_Operation: ['VMThread::execute', 'void', ['pointer']],

          _ZN11OopMapCache22flush_obsolete_entriesEv: ['OopMapCache::flush_obsolete_entries', 'void', ['pointer']],

          _ZN14NMethodSweeper11force_sweepEv: ['NMethodSweeper::force_sweep', 'void', []],
          _ZN14NMethodSweeper16sweep_code_cacheEv: ['NMethodSweeper::sweep_code_cache', 'void', []],
          _ZN14NMethodSweeper17sweep_in_progressEv: ['NMethodSweeper::sweep_in_progress', 'bool', []],

          JVM_Sleep: ['JVM_Sleep', 'void', ['pointer', 'pointer', 'long']]
        },
        variables: {
          // JDK <= 9
          _ZN18VM_RedefineClasses14_the_class_oopE: function (address) {
            this.redefineClass = address;
          },
          // 9 < JDK < 13
          _ZN18VM_RedefineClasses10_the_classE: function (address) {
            this.redefineClass = address;
          },
          // JDK < 13
          _ZN18VM_RedefineClasses25AdjustCpoolCacheAndVtable8do_klassEP5Klass: function (address) {
            this.doKlass = address;
          },
          // JDK >= 13
          _ZN18VM_RedefineClasses22AdjustAndCleanMetadata8do_klassEP5Klass: function (address) {
            this.doKlass = address;
          },
          _ZTV18VM_RedefineClasses: function (address) {
            this.vtableRedefineClasses = address;
          },
          _ZN18VM_RedefineClasses4doitEv: function (address) {
            this.redefineClassesDoIt = address;
          },
          _ZN18VM_RedefineClasses13doit_prologueEv: function (address) {
            this.redefineClassesDoItPrologue = address;
          },
          _ZN18VM_RedefineClasses13doit_epilogueEv: function (address) {
            this.redefineClassesDoItEpilogue = address;
          },
          _ZN18VM_RedefineClassesD0Ev: function (address) {
            this.redefineClassesDispose0 = address;
          },
          _ZN18VM_RedefineClassesD1Ev: function (address) {
            this.redefineClassesDispose1 = address;
          },
          _ZNK18VM_RedefineClasses26allow_nested_vm_operationsEv: function (address) {
            this.redefineClassesAllow = address;
          },
          _ZNK18VM_RedefineClasses14print_on_errorEP12outputStream: function (address) {
            this.redefineClassesOnError = address;
          },

          // JDK >= 17
          _ZN13InstanceKlass33create_new_default_vtable_indicesEiP10JavaThread: function (address) {
            this.createNewDefaultVtableIndices = address;
          },
          // JDK < 17
          _ZN13InstanceKlass33create_new_default_vtable_indicesEiP6Thread: function (address) {
            this.createNewDefaultVtableIndices = address;
          },

          _ZN19Abstract_VM_Version19jre_release_versionEv: function (address) {
            const getVersion = new NativeFunction(address, 'pointer', [], nativeFunctionOptions);
            const versionS = getVersion().readCString();
            this.version = versionS.startsWith('1.8')
              ? 8
              : versionS.startsWith('9.')
                ? 9
                : parseInt(versionS.slice(0, 2), 10);
            this.versionS = versionS;
          },

          _ZN14NMethodSweeper11_traversalsE: function (address) {
            this.traversals = address;
          },
          _ZN14NMethodSweeper21_sweep_fractions_leftE: function (address) {
            this.fractions = address;
          },
          _ZN14NMethodSweeper13_should_sweepE: function (address) {
            this.shouldSweep = address;
          }
        },
        optionals: [
          '_ZN6Method24restore_unshareable_infoEP10JavaThread',
          '_ZN6Method24restore_unshareable_infoEP6Thread',
          '_ZN6Method10clear_codeEv',
          '_ZN6Method10clear_codeEb',

          '_ZN18VM_RedefineClasses19mark_dependent_codeEP13InstanceKlass',
          '_ZN18VM_RedefineClasses20flush_dependent_codeEv',
          '_ZN18VM_RedefineClasses20flush_dependent_codeEP13InstanceKlassP6Thread',
          '_ZN18VM_RedefineClasses20flush_dependent_codeE19instanceKlassHandleP6Thread',

          '_ZN19ResolvedMethodTable21adjust_method_entriesEPb',
          '_ZN15MemberNameTable21adjust_method_entriesEP13InstanceKlassPb',

          '_ZN17ConstantPoolCache21adjust_method_entriesEPb',
          '_ZN17ConstantPoolCache21adjust_method_entriesEP13InstanceKlassPb',

          '_ZN20ClassLoaderDataGraph22clean_deallocate_listsEb',

          '_ZN10JavaThread27thread_from_jni_environmentEP7JNIEnv_',

          '_ZN14NMethodSweeper11force_sweepEv',
          '_ZN14NMethodSweeper17sweep_in_progressEv',

          '_ZN18VM_RedefineClasses14_the_class_oopE',
          '_ZN18VM_RedefineClasses10_the_classE',
          '_ZN18VM_RedefineClasses25AdjustCpoolCacheAndVtable8do_klassEP5Klass',
          '_ZN18VM_RedefineClasses22AdjustAndCleanMetadata8do_klassEP5Klass',
          '_ZN18VM_RedefineClassesD0Ev',
          '_ZN18VM_RedefineClassesD1Ev',
          '_ZNK18VM_RedefineClasses14print_on_errorEP12outputStream',

          '_ZN13InstanceKlass33create_new_default_vtable_indicesEiP10JavaThread',
          '_ZN13InstanceKlass33create_new_default_vtable_indicesEiP6Thread',

          '_ZN14NMethodSweeper21_sweep_fractions_leftE'
        ]
      }];

  const missing = [];

  pending.forEach(function (api) {
    const functions = api.functions || {};
    const variables = api.variables || {};
    const optionals = new Set(api.optionals || []);

    const tmp = Module
      .enumerateExports(api.module)
      .reduce(function (result, exp) {
        result[exp.name] = exp;
        return result;
      }, {});

    const exportByName = Module
      .enumerateSymbols(api.module)
      .reduce(function (result, exp) {
        result[exp.name] = exp;
        return result;
      }, tmp);

    Object.keys(functions)
      .forEach(function (name) {
        const exp = exportByName[name];
        if (exp !== undefined) {
          const signature = functions[name];
          if (typeof signature === 'function') {
            signature.call(temporaryApi, exp.address);
          } else {
            temporaryApi[signature[0]] = new NativeFunction(exp.address, signature[1], signature[2], nativeFunctionOptions);
          }
        } else {
          if (!optionals.has(name)) {
            missing.push(name);
          }
        }
      });

    Object.keys(variables)
      .forEach(function (name) {
        const exp = exportByName[name];
        if (exp !== undefined) {
          const handler = variables[name];
          handler.call(temporaryApi, exp.address);
        } else {
          if (!optionals.has(name)) {
            missing.push(name);
          }
        }
      });
  });

  if (missing.length > 0) {
    throw new Error('Java API only partially available; please file a bug. Missing: ' + missing.join(', '));
  }

  const vms = Memory.alloc(pointerSize);
  const vmCount = Memory.alloc(jsizeSize);
  checkJniResult('JNI_GetCreatedJavaVMs', temporaryApi.JNI_GetCreatedJavaVMs(vms, 1, vmCount));
  if (vmCount.readInt() === 0) {
    return null;
  }
  temporaryApi.vm = vms.readPointer();

  const allocatorFunctions = Process.platform === 'windows'
    ? {
        $new: ['??2@YAPEAX_K@Z', 'pointer', ['ulong']],
        $delete: ['??3@YAXPEAX@Z', 'void', ['pointer']]
      }
  // If platform is not Windows
    : {
        $new: ['_Znwm', 'pointer', ['ulong']],
        $delete: ['_ZdlPv', 'void', ['pointer']]
      };

  for (const [name, [rawName, retType, argTypes]] of Object.entries(allocatorFunctions)) {
    let address = Module.findExportByName(null, rawName);
    if (address === null) {
      address = DebugSymbol.fromName(rawName).address;
      if (address.isNull()) {
        throw new Error(`unable to find C++ allocator API, missing: '${rawName}'`);
      }
    }
    temporaryApi[name] = new NativeFunction(address, retType, argTypes, nativeFunctionOptions);
  }

  temporaryApi.jvmti = getEnvJvmti(temporaryApi);

  if (temporaryApi['JavaThread::thread_from_jni_environment'] === undefined) {
    temporaryApi['JavaThread::thread_from_jni_environment'] = makeThreadFromJniHelper(temporaryApi);
  }

  return temporaryApi;
}

function getEnvJvmti (api) {
  const vm = new VM(api);

  let env;
  vm.perform(() => {
    const handle = vm.tryGetEnvHandle(jvmtiVersion.v1_0);
    if (handle === null) {
      throw new Error('JVMTI not available');
    }
    env = new EnvJvmti(handle, vm);

    const capaBuf = Memory.alloc(8);
    capaBuf.writeU64(jvmtiCapabilities.canTagObjects);
    const result = env.addCapabilities(capaBuf);
    checkJniResult('getEnvJvmti::AddCapabilities', result);
  });

  return env;
}

const threadOffsetParsers = {
  x64: parseX64ThreadOffset
};

function makeThreadFromJniHelper (api) {
  let offset = null;

  const tryParse = threadOffsetParsers[Process.arch];
  if (tryParse !== undefined) {
    const vm = new VM(api);
    const findClassImpl = vm.perform(env => env.handle.readPointer().add(6 * pointerSize).readPointer());
    offset = parseInstructionsAt(findClassImpl, tryParse, { limit: 10 });
  }

  if (offset === null) {
    return () => {
      throw new Error('Unable to make thread_from_jni_environment() helper for the current architecture');
    };
  }

  return env => {
    return env.add(offset);
  };
}

function parseX64ThreadOffset (insn) {
  if (insn.mnemonic !== 'lea') {
    return null;
  }

  const { base, disp } = insn.operands[1].value;
  if (!(base === 'rdi' && disp < 0)) {
    return null;
  }

  return disp;
}

function ensureClassInitialized (env, classRef) {
}

class JvmMethodMangler {
  constructor (methodId) {
    this.methodId = methodId;
    this.method = methodId.readPointer();
    this.originalMethod = null;
    this.newMethod = null;
    this.resolved = null;
    this.impl = null;
    this.key = methodId.toString(16);
  }

  replace (impl, isInstanceMethod, argTypes, vm, api) {
    const { key } = this;
    const mangler = revertManglers.get(key);
    if (mangler !== undefined) {
      revertManglers.delete(key);
      this.method = mangler.method;
      this.originalMethod = mangler.originalMethod;
      this.newMethod = mangler.newMethod;
      this.resolved = mangler.resolved;
    }
    this.impl = impl;
    replaceManglers.set(key, this);
    ensureManglersScheduled(vm);
  }

  revert (vm) {
    const { key } = this;
    replaceManglers.delete(key);
    revertManglers.set(key, this);
    ensureManglersScheduled(vm);
  }

  resolveTarget (wrapper, isInstanceMethod, env, api) {
    const { resolved, originalMethod, methodId } = this;
    if (resolved !== null) {
      return resolved;
    }

    if (originalMethod === null) {
      return methodId;
    }

    const vip = originalMethod.oldMethod.vtableIndexPtr;

    // Make old method final with nonvirtual_vtable_index = -2
    // so that we don't need a vtable entry when calling old method.
    vip.writeS32(-2);

    const jmethodID = Memory.alloc(pointerSize);
    jmethodID.writePointer(this.method);
    this.resolved = jmethodID;

    return jmethodID;
  }
}

function ensureManglersScheduled (vm) {
  if (!manglersScheduled) {
    manglersScheduled = true;
    Script.nextTick(doManglers, vm);
  }
}

function doManglers (vm) {
  const localReplaceManglers = new Map(replaceManglers);
  const localRevertManglers = new Map(revertManglers);
  replaceManglers.clear();
  revertManglers.clear();
  manglersScheduled = false;

  vm.perform(env => {
    const api = getApi();

    const thread = api['JavaThread::thread_from_jni_environment'](env.handle);

    let force = false;

    withJvmThread(() => {
      localReplaceManglers.forEach(mangler => {
        const { method, originalMethod, impl, methodId, newMethod } = mangler;
        if (originalMethod === null) {
          mangler.originalMethod = fetchJvmMethod(method);
          mangler.newMethod = nativeJvmMethod(method, impl, thread);
          installJvmMethod(mangler.newMethod, methodId, thread);
        } else {
          api['Method::set_native_function'](newMethod.method, impl, 0);
        }
      });

      localRevertManglers.forEach(mangler => {
        const { originalMethod, methodId, newMethod } = mangler;
        if (originalMethod !== null) {
          revertJvmMethod(originalMethod);
          const revert = originalMethod.oldMethod;
          revert.oldMethod = newMethod;
          installJvmMethod(revert, methodId, thread);
          force = true;
        }
      });
    });

    if (force) {
      forceSweep(env.handle);
    }
  });
}

function forceSweep (env) {
  const {
    fractions,
    shouldSweep,
    traversals,
    'NMethodSweeper::sweep_code_cache': sweep,
    'NMethodSweeper::sweep_in_progress': inProgress,
    'NMethodSweeper::force_sweep': force,
    JVM_Sleep: sleep
  } = getApi();

  if (force !== undefined) {
    Thread.sleep(0.05);
    force();
    Thread.sleep(0.05);
    force();
  } else {
    let trav = traversals.readS64();
    const endTrav = trav + 2;

    while (endTrav > trav) {
      // Force a full sweep if already in progress.
      fractions.writeS32(1);
      sleep(env, NULL, 50);

      // Check if current nmethod is set.
      if (!inProgress()) {
        // Force mark_active_nmethods on exit from safepoint.
        withJvmThread(() => {
          Thread.sleep(0.05);
        });
      }

      const sweepNotAlreadyInProgress = shouldSweep.readU8() === 0;
      if (sweepNotAlreadyInProgress) {
        // Sanity check to not divide by 0.
        fractions.writeS32(1);
        sweep();
      }

      trav = traversals.readS64();
    }
  }
}

function withJvmThread (fn, fnPrologue, fnEpilogue) {
  const {
    execute,
    vtable,
    vtableSize,
    doItOffset,
    prologueOffset,
    epilogueOffset
  } = getJvmThreadSpec();

  const vtableDup = Memory.dup(vtable, vtableSize);

  const vmOperation = Memory.alloc(pointerSize * 25);
  vmOperation.writePointer(vtableDup);

  const doIt = new NativeCallback(fn, 'void', ['pointer']);
  vtableDup.add(doItOffset).writePointer(doIt);

  let prologue = null;
  if (fnPrologue !== undefined) {
    prologue = new NativeCallback(fnPrologue, 'int', ['pointer']);
    vtableDup.add(prologueOffset).writePointer(prologue);
  }

  let epilogue = null;
  if (fnEpilogue !== undefined) {
    epilogue = new NativeCallback(fnEpilogue, 'void', ['pointer']);
    vtableDup.add(epilogueOffset).writePointer(epilogue);
  }

  execute(vmOperation);
}

function _getJvmThreadSpec () {
  const {
    vtableRedefineClasses,
    redefineClassesDoIt,
    redefineClassesDoItPrologue,
    redefineClassesDoItEpilogue,
    redefineClassesOnError,
    redefineClassesAllow,
    redefineClassesDispose0,
    redefineClassesDispose1,
    'VMThread::execute': execute
  } = getApi();

  const vtablePtr = vtableRedefineClasses.add(2 * pointerSize);
  const vtableSize = 15 * pointerSize;
  const vtable = Memory.dup(vtablePtr, vtableSize);

  const emptyCallback = new NativeCallback(() => {}, 'void', ['pointer']);

  let doItOffset, prologueOffset, epilogueOffset;
  for (let offset = 0; offset !== vtableSize; offset += pointerSize) {
    const element = vtable.add(offset);
    const value = element.readPointer();
    if ((redefineClassesOnError !== undefined && value.equals(redefineClassesOnError)) ||
        (redefineClassesDispose0 !== undefined && value.equals(redefineClassesDispose0)) ||
        (redefineClassesDispose1 !== undefined && value.equals(redefineClassesDispose1))) {
      element.writePointer(emptyCallback);
    } else if (value.equals(redefineClassesDoIt)) {
      doItOffset = offset;
    } else if (value.equals(redefineClassesDoItPrologue)) {
      prologueOffset = offset;
      element.writePointer(redefineClassesAllow);
    } else if (value.equals(redefineClassesDoItEpilogue)) {
      epilogueOffset = offset;
      element.writePointer(emptyCallback);
    }
  }

  return {
    execute,
    emptyCallback,
    vtable,
    vtableSize,
    doItOffset,
    prologueOffset,
    epilogueOffset
  };
}

function makeMethodMangler (methodId) {
  return new JvmMethodMangler(methodId);
}

function installJvmMethod (method, methodId, thread) {
  const { method: handle, oldMethod: old } = method;
  const api = getApi();

  // Replace position in methodsArray with new method.
  method.methodsArray.add(method.methodIndex * pointerSize).writePointer(handle);

  // Replace method handle in vtable
  if (method.vtableIndex >= 0) {
    method.vtable.add(method.vtableIndex * pointerSize).writePointer(handle);
  }

  // Replace jmethodID with new method.
  methodId.writePointer(handle);

  old.accessFlagsPtr.writeU32((old.accessFlags | JVM_ACC_IS_OLD | JVM_ACC_IS_OBSOLETE) >>> 0);

  // Deoptimize dependent code.
  const flushObs = api['OopMapCache::flush_obsolete_entries'];
  if (flushObs !== undefined) {
    const { oopMapCache } = method;
    if (!oopMapCache.isNull()) {
      flushObs(oopMapCache);
    }
  }

  const mark = api['VM_RedefineClasses::mark_dependent_code'];
  const flush = api['VM_RedefineClasses::flush_dependent_code'];
  if (mark !== undefined) {
    mark(NULL, method.instanceKlass);
    flush();
  } else {
    flush(NULL, method.instanceKlass, thread);
  }

  const traceNamePrinted = Memory.alloc(1);
  traceNamePrinted.writeU8(1);
  api['ConstantPoolCache::adjust_method_entries'](method.cache, method.instanceKlass, traceNamePrinted);

  const klassClosure = Memory.alloc(3 * pointerSize);
  const doKlassPtr = Memory.alloc(pointerSize);
  doKlassPtr.writePointer(api.doKlass);
  klassClosure.writePointer(doKlassPtr);
  klassClosure.add(pointerSize).writePointer(thread);
  klassClosure.add(2 * pointerSize).writePointer(thread);
  if (api.redefineClass !== undefined) {
    api.redefineClass.writePointer(method.instanceKlass);
  }
  api['ClassLoaderDataGraph::classes_do'](klassClosure);

  const rmtAdjustMethodEntries = api['ResolvedMethodTable::adjust_method_entries'];
  if (rmtAdjustMethodEntries !== undefined) {
    rmtAdjustMethodEntries(traceNamePrinted);
  } else {
    const { memberNames } = method;
    if (!memberNames.isNull()) {
      const mntAdjustMethodEntries = api['MemberNameTable::adjust_method_entries'];
      if (mntAdjustMethodEntries !== undefined) {
        mntAdjustMethodEntries(memberNames, method.instanceKlass, traceNamePrinted);
      }
    }
  }
  const clean = api['ClassLoaderDataGraph::clean_deallocate_lists'];
  if (clean !== undefined) {
    clean(0);
  }
}

function nativeJvmMethod (method, impl, thread) {
  const api = getApi();

  const newMethod = fetchJvmMethod(method);
  newMethod.constPtr.writePointer(newMethod.const);
  const flags = (newMethod.accessFlags | JVM_ACC_NATIVE |
    JVM_ACC_NOT_C2_COMPILABLE | JVM_ACC_NOT_C1_COMPILABLE |
    JVM_ACC_NOT_C2_OSR_COMPILABLE) >>> 0;
  newMethod.accessFlagsPtr.writeU32(flags);
  newMethod.signatureHandler.writePointer(NULL);
  newMethod.adapter.writePointer(NULL);
  newMethod.i2iEntry.writePointer(NULL);
  api['Method::clear_code'](newMethod.method);

  newMethod.dataPtr.writePointer(NULL);
  newMethod.countersPtr.writePointer(NULL);
  newMethod.stackmapPtr.writePointer(NULL);

  api['Method::clear_native_function'](newMethod.method);
  api['Method::set_native_function'](newMethod.method, impl, 0);

  api['Method::restore_unshareable_info'](newMethod.method, thread);

  return newMethod;
}

function fetchJvmMethod (method) {
  const spec = getJvmMethodSpec();
  const constMethod = method.add(spec.method.constMethodOffset).readPointer();
  const constMethodSize = constMethod.add(spec.constMethod.sizeOffset).readS32() * pointerSize;

  const newConstMethod = Memory.alloc(constMethodSize + spec.method.size);
  Memory.copy(newConstMethod, constMethod, constMethodSize);

  const newMethod = newConstMethod.add(constMethodSize);
  Memory.copy(newMethod, method, spec.method.size);

  const result = readJvmMethod(newMethod, newConstMethod, constMethodSize);

  const oldMethod = readJvmMethod(method, constMethod, constMethodSize);
  result.oldMethod = oldMethod;

  return result;
}

function readJvmMethod (method, constMethod, constMethodSize) {
  const api = getApi();
  const spec = getJvmMethodSpec();

  const constPtr = method.add(spec.method.constMethodOffset);
  const dataPtr = method.add(spec.method.methodDataOffset);
  const countersPtr = method.add(spec.method.methodCountersOffset);
  const accessFlagsPtr = method.add(spec.method.accessFlagsOffset);
  const accessFlags = accessFlagsPtr.readU32();
  const adapter = spec.getAdapterPointer(method, constMethod);
  const i2iEntry = method.add(spec.method.i2iEntryOffset);
  const signatureHandler = method.add(spec.method.signatureHandlerOffset);

  const constantPool = constMethod.add(spec.constMethod.constantPoolOffset).readPointer();
  const stackmapPtr = constMethod.add(spec.constMethod.stackmapDataOffset);
  const instanceKlass = constantPool.add(spec.constantPool.instanceKlassOffset).readPointer();
  const cache = constantPool.add(spec.constantPool.cacheOffset).readPointer();

  const instanceKlassSpec = getJvmInstanceKlassSpec();

  const methods = instanceKlass.add(instanceKlassSpec.methodsOffset).readPointer();
  const methodsCount = methods.readS32();
  const methodsArray = methods.add(pointerSize);
  const methodIndex = constMethod.add(spec.constMethod.methodIdnumOffset).readU16();
  const vtableIndexPtr = method.add(spec.method.vtableIndexOffset);
  const vtableIndex = vtableIndexPtr.readS32();
  const vtable = instanceKlass.add(instanceKlassSpec.vtableOffset);
  const oopMapCache = instanceKlass.add(instanceKlassSpec.oopMapCacheOffset).readPointer();

  const memberNames = (api.version >= 10)
    ? instanceKlass.add(instanceKlassSpec.memberNamesOffset).readPointer()
    : NULL;

  return {
    method,
    methodSize: spec.method.size,
    const: constMethod,
    constSize: constMethodSize,
    constPtr,
    dataPtr,
    countersPtr,
    stackmapPtr,
    instanceKlass,
    methodsArray,
    methodsCount,
    methodIndex,
    vtableIndex,
    vtableIndexPtr,
    vtable,
    accessFlags,
    accessFlagsPtr,
    adapter,
    i2iEntry,
    signatureHandler,
    memberNames,
    cache,
    oopMapCache
  };
}

function revertJvmMethod (method) {
  const { oldMethod: old } = method;
  old.accessFlagsPtr.writeU32(old.accessFlags);
  old.vtableIndexPtr.writeS32(old.vtableIndex);
}

function _getJvmMethodSpec () {
  const api = getApi();
  const { version } = api;

  let adapterHandlerLocation;
  if (version >= 17) {
    adapterHandlerLocation = 'method:early';
  } else if (version >= 9 && version <= 16) {
    adapterHandlerLocation = 'const-method';
  } else {
    adapterHandlerLocation = 'method:late';
  }

  const isNative = 1;
  const methodSize = api['Method::size'](isNative) * pointerSize;
  const constMethodOffset = pointerSize;
  const methodDataOffset = 2 * pointerSize;
  const methodCountersOffset = 3 * pointerSize;
  const adapterInMethodEarlyOffset = 4 * pointerSize;
  const adapterInMethodEarlySize = (adapterHandlerLocation === 'method:early') ? pointerSize : 0;
  const accessFlagsOffset = adapterInMethodEarlyOffset + adapterInMethodEarlySize;
  const vtableIndexOffset = accessFlagsOffset + 4;
  const i2iEntryOffset = vtableIndexOffset + 4 + 8;
  const adapterInMethodLateOffset = i2iEntryOffset + pointerSize;
  const adapterInMethodOffset = (adapterInMethodEarlySize !== 0) ? adapterInMethodEarlyOffset : adapterInMethodLateOffset;
  const nativeFunctionOffset = methodSize - 2 * pointerSize;
  const signatureHandlerOffset = methodSize - pointerSize;

  const constantPoolOffset = 8;
  const stackmapDataOffset = constantPoolOffset + pointerSize;
  const adapterInConstMethodOffset = stackmapDataOffset + pointerSize;
  const adapterInConstMethodSize = (adapterHandlerLocation === 'const-method') ? pointerSize : 0;
  const constMethodSizeOffset = adapterInConstMethodOffset + adapterInConstMethodSize;
  const methodIdnumOffset = constMethodSizeOffset + 0xe;

  const cacheOffset = 2 * pointerSize;
  const instanceKlassOffset = 3 * pointerSize;

  const getAdapterPointer = (adapterInConstMethodSize !== 0)
    ? function (method, constMethod) {
      return constMethod.add(adapterInConstMethodOffset);
    }
    : function (method, constMethod) {
      return method.add(adapterInMethodOffset);
    };

  return {
    getAdapterPointer,
    method: {
      size: methodSize,
      constMethodOffset,
      methodDataOffset,
      methodCountersOffset,
      accessFlagsOffset,
      vtableIndexOffset,
      i2iEntryOffset,
      nativeFunctionOffset,
      signatureHandlerOffset
    },
    constMethod: {
      constantPoolOffset,
      stackmapDataOffset,
      sizeOffset: constMethodSizeOffset,
      methodIdnumOffset
    },
    constantPool: {
      cacheOffset,
      instanceKlassOffset
    }
  };
}

const vtableOffsetParsers = {
  x64: parseX64VTableOffset
};

function _getJvmInstanceKlassSpec () {
  const { version: jvmVersion, createNewDefaultVtableIndices } = getApi();

  const tryParse = vtableOffsetParsers[Process.arch];
  if (tryParse === undefined) {
    throw new Error(`Missing vtable offset parser for ${Process.arch}`);
  }

  const vtableOffset = parseInstructionsAt(createNewDefaultVtableIndices, tryParse, { limit: 32 });
  if (vtableOffset === null) {
    throw new Error('Unable to deduce vtable offset');
  }

  const oopMultiplier = ((jvmVersion >= 10 && jvmVersion <= 11) || jvmVersion >= 15) ? 17 : 18;

  const methodsOffset = vtableOffset - (7 * pointerSize);
  const memberNamesOffset = vtableOffset - (17 * pointerSize);
  const oopMapCacheOffset = vtableOffset - (oopMultiplier * pointerSize);

  return {
    vtableOffset,
    methodsOffset,
    memberNamesOffset,
    oopMapCacheOffset
  };
}

function parseX64VTableOffset (insn) {
  if (insn.mnemonic !
"""


```