Response:
### 第1部分：功能归纳

#### **核心功能**：
1. **ART/Dalvik 运行时交互**  
   - 访问 JVM 内部结构（类、方法、线程）
   - 解析 ART 关键结构（`ArtMethod`, `ClassLinker`, `ThreadList`）
   - 动态修改方法实现（插桩、Hook）

2. **JNI 与 JVM TI 集成**  
   - 管理 JNI 全局引用 (`AddGlobalRef`, `DecodeGlobal`)
   - 使用 JVM TI 能力（如对象标记、类重定义）

3. **线程控制与堆栈遍历**  
   - 挂起/恢复所有线程 (`SuspendAll`, `ResumeAll`)
   - 遍历线程堆栈 (`StackVisitor`)，获取调用上下文

4. **内存与代码管理**  
   - 分配可执行内存 (`makeCodeAllocator`)
   - 生成跳转指令（ARM/X86 架构适配）
   - 处理去优化（Deoptimization）

5. **调试与反射支持**  
   - 启动 JDWP 调试会话
   - 反射访问类/方法元数据 (`GetDescriptor`, `PrettyMethod`)

6. **快速 JNI 处理**  
   - 识别 `kAccFastNative`/`kAccCriticalNative` 方法
   - 绕过 JNI 检查优化性能

7. **跨版本兼容性**  
   - 适配 Android 5~14 的 ART 内部结构差异
   - 动态计算字段偏移（如 `Runtime.classLinker_`）

---

#### **关键代码段解析**：
- **`_getApi()`**  
  动态绑定 ART/Dalvik 符号，处理不同 Android 版本差异。

- **`tryGetEnvJvmti()`**  
  加载 `libopenjdkjvmti.so`，获取 JVM TI 环境句柄。

- **`makeAddGlobalRefFallbackForAndroid5`**  
  为旧版本实现全局引用兼容逻辑。

- **`getArtQuickEntrypointFromTrampoline`**  
  解析 ART 快速执行入口点（如 `art_quick_generic_jni_trampoline`）。

---

#### **假设输入与输出**：
- **输入**：Hook `java.lang.String.length()`  
  **输出**：修改 `ArtMethod` 的入口指针，跳转到 Frida 的代理代码。

- **输入**：调用 `Java.perform()`  
  **输出**：挂起所有线程，遍历类加载器，注入钩子后恢复。

---

#### **用户常见错误示例**：
1. **线程状态未同步**  
   ```javascript
   Java.perform(() => {
     // 错误：未处理挂起状态直接修改方法
     let method = getTargetMethod();
     method.implementation = ...;
   });
   ```
   **后果**：并发修改导致崩溃。

2. **JNI 引用泄漏**  
   ```c
   jobject globalRef = (*env)->NewGlobalRef(env, localRef);
   // 错误：未调用 DeleteGlobalRef
   ```
   **后果**：内存泄漏，最终 JVM 崩溃。

---

#### **调试线索（调用链）**：
1. `Java.perform()` 触发初始化  
2. 调用 `getApi()` 绑定 ART 符号  
3. 挂起线程 (`SuspendAll`)  
4. 遍历 `ClassLinker` 加载的类  
5. 找到目标 `ArtMethod` 结构体  
6. 修改 `access_flags` 和 `entry_point`  
7. 生成跳转代码到 Frida 分配的内存  
8. 处理去优化请求 (`DeoptimizeEverything`)  
9. 恢复线程 (`ResumeAll`)  
10. 注册 JDWP 回调处理调试事件  

---

**下一部分将深入执行顺序与 LLDB 调试示例**。
### 提示词
```
这是目录为frida/subprojects/frida-java-bridge/lib/android.js的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
请列举一下它的功能, 给出执行顺序(不是行号顺序), 建议分10步,
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明调用链如何一步步的到达这里，作为调试线索，建议10步，
请用中文回复。
这是第1部分，共5部分，请归纳一下它的功能
```

### 源代码
```javascript
const makeCodeAllocator = require('./alloc');
const {
  jvmtiVersion,
  jvmtiCapabilities,
  EnvJvmti
} = require('./jvmti');
const { parseInstructionsAt } = require('./machine-code');
const memoize = require('./memoize');
const { checkJniResult, JNI_OK } = require('./result');
const VM = require('./vm');

const jsizeSize = 4;
const pointerSize = Process.pointerSize;

const {
  readU32,
  readPointer,
  writeU32,
  writePointer
} = NativePointer.prototype;

const kAccPublic = 0x0001;
const kAccStatic = 0x0008;
const kAccFinal = 0x0010;
const kAccNative = 0x0100;
const kAccFastNative = 0x00080000;
const kAccCriticalNative = 0x00200000;
const kAccFastInterpreterToInterpreterInvoke = 0x40000000;
const kAccSkipAccessChecks = 0x00080000;
const kAccSingleImplementation = 0x08000000;
const kAccNterpEntryPointFastPathFlag = 0x00100000;
const kAccNterpInvokeFastPathFlag = 0x00200000;
const kAccPublicApi = 0x10000000;
const kAccXposedHookedMethod = 0x10000000;

const kPointer = 0x0;

const kFullDeoptimization = 3;
const kSelectiveDeoptimization = 5;

const THUMB_BIT_REMOVAL_MASK = ptr(1).not();

const X86_JMP_MAX_DISTANCE = 0x7fffbfff;
const ARM64_ADRP_MAX_DISTANCE = 0xfffff000;

const ENV_VTABLE_OFFSET_EXCEPTION_CLEAR = 17 * pointerSize;
const ENV_VTABLE_OFFSET_FATAL_ERROR = 18 * pointerSize;

const DVM_JNI_ENV_OFFSET_SELF = 12;

const DVM_CLASS_OBJECT_OFFSET_VTABLE_COUNT = 112;
const DVM_CLASS_OBJECT_OFFSET_VTABLE = 116;

const DVM_OBJECT_OFFSET_CLAZZ = 0;

const DVM_METHOD_SIZE = 56;
const DVM_METHOD_OFFSET_ACCESS_FLAGS = 4;
const DVM_METHOD_OFFSET_METHOD_INDEX = 8;
const DVM_METHOD_OFFSET_REGISTERS_SIZE = 10;
const DVM_METHOD_OFFSET_OUTS_SIZE = 12;
const DVM_METHOD_OFFSET_INS_SIZE = 14;
const DVM_METHOD_OFFSET_SHORTY = 28;
const DVM_METHOD_OFFSET_JNI_ARG_INFO = 36;

const DALVIK_JNI_RETURN_VOID = 0;
const DALVIK_JNI_RETURN_FLOAT = 1;
const DALVIK_JNI_RETURN_DOUBLE = 2;
const DALVIK_JNI_RETURN_S8 = 3;
const DALVIK_JNI_RETURN_S4 = 4;
const DALVIK_JNI_RETURN_S2 = 5;
const DALVIK_JNI_RETURN_U2 = 6;
const DALVIK_JNI_RETURN_S1 = 7;
const DALVIK_JNI_NO_ARG_INFO = 0x80000000;
const DALVIK_JNI_RETURN_SHIFT = 28;

const STD_STRING_SIZE = 3 * pointerSize;
const STD_VECTOR_SIZE = 3 * pointerSize;

const AF_UNIX = 1;
const SOCK_STREAM = 1;

const getArtRuntimeSpec = memoize(_getArtRuntimeSpec);
const getArtInstrumentationSpec = memoize(_getArtInstrumentationSpec);
const getArtMethodSpec = memoize(_getArtMethodSpec);
const getArtThreadSpec = memoize(_getArtThreadSpec);
const getArtManagedStackSpec = memoize(_getArtManagedStackSpec);
const getArtThreadStateTransitionImpl = memoize(_getArtThreadStateTransitionImpl);
const getAndroidVersion = memoize(_getAndroidVersion);
const getAndroidCodename = memoize(_getAndroidCodename);
const getAndroidApiLevel = memoize(_getAndroidApiLevel);
const getArtQuickFrameInfoGetterThunk = memoize(_getArtQuickFrameInfoGetterThunk);

const makeCxxMethodWrapperReturningPointerByValue =
    (Process.arch === 'ia32')
      ? makeCxxMethodWrapperReturningPointerByValueInFirstArg
      : makeCxxMethodWrapperReturningPointerByValueGeneric;

const nativeFunctionOptions = {
  exceptions: 'propagate'
};

const artThreadStateTransitions = {};

let cachedApi = null;
let cachedArtClassLinkerSpec = null;
let MethodMangler = null;
let artController = null;
const inlineHooks = [];
const patchedClasses = new Map();
const artQuickInterceptors = [];
let thunkPage = null;
let thunkOffset = 0;
let taughtArtAboutReplacementMethods = false;
let taughtArtAboutMethodInstrumentation = false;
let backtraceModule = null;
const jdwpSessions = [];
let socketpair = null;

let trampolineAllocator = null;

function getApi () {
  if (cachedApi === null) {
    cachedApi = _getApi();
  }
  return cachedApi;
}

function _getApi () {
  const vmModules = Process.enumerateModules()
    .filter(m => /^lib(art|dvm).so$/.test(m.name))
    .filter(m => !/\/system\/fake-libs/.test(m.path));
  if (vmModules.length === 0) {
    return null;
  }
  const vmModule = vmModules[0];

  const flavor = (vmModule.name.indexOf('art') !== -1) ? 'art' : 'dalvik';
  const isArt = flavor === 'art';

  const temporaryApi = {
    module: vmModule,
    flavor,
    addLocalReference: null
  };

  const pending = isArt
    ? [{
        module: vmModule.path,
        functions: {
          JNI_GetCreatedJavaVMs: ['JNI_GetCreatedJavaVMs', 'int', ['pointer', 'int', 'pointer']],

          // Android < 7
          artInterpreterToCompiledCodeBridge: function (address) {
            this.artInterpreterToCompiledCodeBridge = address;
          },

          // Android >= 8
          _ZN3art9JavaVMExt12AddGlobalRefEPNS_6ThreadENS_6ObjPtrINS_6mirror6ObjectEEE: ['art::JavaVMExt::AddGlobalRef', 'pointer', ['pointer', 'pointer', 'pointer']],
          // Android >= 6
          _ZN3art9JavaVMExt12AddGlobalRefEPNS_6ThreadEPNS_6mirror6ObjectE: ['art::JavaVMExt::AddGlobalRef', 'pointer', ['pointer', 'pointer', 'pointer']],
          // Android < 6: makeAddGlobalRefFallbackForAndroid5() needs these:
          _ZN3art17ReaderWriterMutex13ExclusiveLockEPNS_6ThreadE: ['art::ReaderWriterMutex::ExclusiveLock', 'void', ['pointer', 'pointer']],
          _ZN3art17ReaderWriterMutex15ExclusiveUnlockEPNS_6ThreadE: ['art::ReaderWriterMutex::ExclusiveUnlock', 'void', ['pointer', 'pointer']],

          // Android <= 7
          _ZN3art22IndirectReferenceTable3AddEjPNS_6mirror6ObjectE: function (address) {
            this['art::IndirectReferenceTable::Add'] = new NativeFunction(address, 'pointer', ['pointer', 'uint', 'pointer'], nativeFunctionOptions);
          },
          // Android > 7
          _ZN3art22IndirectReferenceTable3AddENS_15IRTSegmentStateENS_6ObjPtrINS_6mirror6ObjectEEE: function (address) {
            this['art::IndirectReferenceTable::Add'] = new NativeFunction(address, 'pointer', ['pointer', 'uint', 'pointer'], nativeFunctionOptions);
          },

          // Android >= 7
          _ZN3art9JavaVMExt12DecodeGlobalEPv: function (address) {
            let decodeGlobal;
            if (getAndroidApiLevel() >= 26) {
              // Returns ObjPtr<mirror::Object>
              decodeGlobal = makeCxxMethodWrapperReturningPointerByValue(address, ['pointer', 'pointer']);
            } else {
              // Returns mirror::Object *
              decodeGlobal = new NativeFunction(address, 'pointer', ['pointer', 'pointer'], nativeFunctionOptions);
            }
            this['art::JavaVMExt::DecodeGlobal'] = function (vm, thread, ref) {
              return decodeGlobal(vm, ref);
            };
          },
          // Android >= 6
          _ZN3art9JavaVMExt12DecodeGlobalEPNS_6ThreadEPv: ['art::JavaVMExt::DecodeGlobal', 'pointer', ['pointer', 'pointer', 'pointer']],

          // makeDecodeGlobalFallback() uses:
          // Android >= 15
          _ZNK3art6Thread19DecodeGlobalJObjectEP8_jobject: ['art::Thread::DecodeJObject', 'pointer', ['pointer', 'pointer']],
          // Android < 6
          _ZNK3art6Thread13DecodeJObjectEP8_jobject: ['art::Thread::DecodeJObject', 'pointer', ['pointer', 'pointer']],

          // Android >= 6
          _ZN3art10ThreadList10SuspendAllEPKcb: ['art::ThreadList::SuspendAll', 'void', ['pointer', 'pointer', 'bool']],
          // or fallback:
          _ZN3art10ThreadList10SuspendAllEv: function (address) {
            const suspendAll = new NativeFunction(address, 'void', ['pointer'], nativeFunctionOptions);
            this['art::ThreadList::SuspendAll'] = function (threadList, cause, longSuspend) {
              return suspendAll(threadList);
            };
          },

          _ZN3art10ThreadList9ResumeAllEv: ['art::ThreadList::ResumeAll', 'void', ['pointer']],

          // Android >= 7
          _ZN3art11ClassLinker12VisitClassesEPNS_12ClassVisitorE: ['art::ClassLinker::VisitClasses', 'void', ['pointer', 'pointer']],
          // Android < 7
          _ZN3art11ClassLinker12VisitClassesEPFbPNS_6mirror5ClassEPvES4_: function (address) {
            const visitClasses = new NativeFunction(address, 'void', ['pointer', 'pointer', 'pointer'], nativeFunctionOptions);
            this['art::ClassLinker::VisitClasses'] = function (classLinker, visitor) {
              visitClasses(classLinker, visitor, NULL);
            };
          },

          _ZNK3art11ClassLinker17VisitClassLoadersEPNS_18ClassLoaderVisitorE: ['art::ClassLinker::VisitClassLoaders', 'void', ['pointer', 'pointer']],

          _ZN3art2gc4Heap12VisitObjectsEPFvPNS_6mirror6ObjectEPvES5_: ['art::gc::Heap::VisitObjects', 'void', ['pointer', 'pointer', 'pointer']],
          _ZN3art2gc4Heap12GetInstancesERNS_24VariableSizedHandleScopeENS_6HandleINS_6mirror5ClassEEEiRNSt3__16vectorINS4_INS5_6ObjectEEENS8_9allocatorISB_EEEE: ['art::gc::Heap::GetInstances', 'void', ['pointer', 'pointer', 'pointer', 'int', 'pointer']],

          // Android >= 9
          _ZN3art2gc4Heap12GetInstancesERNS_24VariableSizedHandleScopeENS_6HandleINS_6mirror5ClassEEEbiRNSt3__16vectorINS4_INS5_6ObjectEEENS8_9allocatorISB_EEEE: function (address) {
            const getInstances = new NativeFunction(address, 'void', ['pointer', 'pointer', 'pointer', 'bool', 'int', 'pointer'], nativeFunctionOptions);
            this['art::gc::Heap::GetInstances'] = function (instance, scope, hClass, maxCount, instances) {
              const useIsAssignableFrom = 0;
              getInstances(instance, scope, hClass, useIsAssignableFrom, maxCount, instances);
            };
          },

          _ZN3art12StackVisitorC2EPNS_6ThreadEPNS_7ContextENS0_13StackWalkKindEjb: ['art::StackVisitor::StackVisitor', 'void', ['pointer', 'pointer', 'pointer', 'uint', 'uint', 'bool']],
          _ZN3art12StackVisitorC2EPNS_6ThreadEPNS_7ContextENS0_13StackWalkKindEmb: ['art::StackVisitor::StackVisitor', 'void', ['pointer', 'pointer', 'pointer', 'uint', 'size_t', 'bool']],
          _ZN3art12StackVisitor9WalkStackILNS0_16CountTransitionsE0EEEvb: ['art::StackVisitor::WalkStack', 'void', ['pointer', 'bool']],
          _ZNK3art12StackVisitor9GetMethodEv: ['art::StackVisitor::GetMethod', 'pointer', ['pointer']],
          _ZNK3art12StackVisitor16DescribeLocationEv: function (address) {
            this['art::StackVisitor::DescribeLocation'] = makeCxxMethodWrapperReturningStdStringByValue(address, ['pointer']);
          },
          _ZNK3art12StackVisitor24GetCurrentQuickFrameInfoEv: function (address) {
            this['art::StackVisitor::GetCurrentQuickFrameInfo'] = makeArtQuickFrameInfoGetter(address);
          },

          _ZN3art6Thread18GetLongJumpContextEv: ['art::Thread::GetLongJumpContext', 'pointer', ['pointer']],

          _ZN3art6mirror5Class13GetDescriptorEPNSt3__112basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEE: function (address) {
            this['art::mirror::Class::GetDescriptor'] = address;
          },
          _ZN3art6mirror5Class11GetLocationEv: function (address) {
            this['art::mirror::Class::GetLocation'] = makeCxxMethodWrapperReturningStdStringByValue(address, ['pointer']);
          },

          _ZN3art9ArtMethod12PrettyMethodEb: function (address) {
            this['art::ArtMethod::PrettyMethod'] = makeCxxMethodWrapperReturningStdStringByValue(address, ['pointer', 'bool']);
          },
          _ZN3art12PrettyMethodEPNS_9ArtMethodEb: function (address) {
            this['art::ArtMethod::PrettyMethodNullSafe'] = makeCxxMethodWrapperReturningStdStringByValue(address, ['pointer', 'bool']);
          },

          // Android < 6 for cloneArtMethod()
          _ZN3art6Thread14CurrentFromGdbEv: ['art::Thread::CurrentFromGdb', 'pointer', []],
          _ZN3art6mirror6Object5CloneEPNS_6ThreadE: function (address) {
            this['art::mirror::Object::Clone'] = new NativeFunction(address, 'pointer', ['pointer', 'pointer'], nativeFunctionOptions);
          },
          _ZN3art6mirror6Object5CloneEPNS_6ThreadEm: function (address) {
            const clone = new NativeFunction(address, 'pointer', ['pointer', 'pointer', 'pointer'], nativeFunctionOptions);
            this['art::mirror::Object::Clone'] = function (thisPtr, threadPtr) {
              const numTargetBytes = NULL;
              return clone(thisPtr, threadPtr, numTargetBytes);
            };
          },
          _ZN3art6mirror6Object5CloneEPNS_6ThreadEj: function (address) {
            const clone = new NativeFunction(address, 'pointer', ['pointer', 'pointer', 'uint'], nativeFunctionOptions);
            this['art::mirror::Object::Clone'] = function (thisPtr, threadPtr) {
              const numTargetBytes = 0;
              return clone(thisPtr, threadPtr, numTargetBytes);
            };
          },

          _ZN3art3Dbg14SetJdwpAllowedEb: ['art::Dbg::SetJdwpAllowed', 'void', ['bool']],
          _ZN3art3Dbg13ConfigureJdwpERKNS_4JDWP11JdwpOptionsE: ['art::Dbg::ConfigureJdwp', 'void', ['pointer']],
          _ZN3art31InternalDebuggerControlCallback13StartDebuggerEv: ['art::InternalDebuggerControlCallback::StartDebugger', 'void', ['pointer']],
          _ZN3art3Dbg9StartJdwpEv: ['art::Dbg::StartJdwp', 'void', []],
          _ZN3art3Dbg8GoActiveEv: ['art::Dbg::GoActive', 'void', []],
          _ZN3art3Dbg21RequestDeoptimizationERKNS_21DeoptimizationRequestE: ['art::Dbg::RequestDeoptimization', 'void', ['pointer']],
          _ZN3art3Dbg20ManageDeoptimizationEv: ['art::Dbg::ManageDeoptimization', 'void', []],

          _ZN3art15instrumentation15Instrumentation20EnableDeoptimizationEv: ['art::Instrumentation::EnableDeoptimization', 'void', ['pointer']],
          // Android >= 6
          _ZN3art15instrumentation15Instrumentation20DeoptimizeEverythingEPKc: ['art::Instrumentation::DeoptimizeEverything', 'void', ['pointer', 'pointer']],
          // Android < 6
          _ZN3art15instrumentation15Instrumentation20DeoptimizeEverythingEv: function (address) {
            const deoptimize = new NativeFunction(address, 'void', ['pointer'], nativeFunctionOptions);
            this['art::Instrumentation::DeoptimizeEverything'] = function (instrumentation, key) {
              deoptimize(instrumentation);
            };
          },
          _ZN3art7Runtime19DeoptimizeBootImageEv: ['art::Runtime::DeoptimizeBootImage', 'void', ['pointer']],
          _ZN3art15instrumentation15Instrumentation10DeoptimizeEPNS_9ArtMethodE: ['art::Instrumentation::Deoptimize', 'void', ['pointer', 'pointer']],

          // Android >= 11
          _ZN3art3jni12JniIdManager14DecodeMethodIdEP10_jmethodID: ['art::jni::JniIdManager::DecodeMethodId', 'pointer', ['pointer', 'pointer']],
          _ZN3art11interpreter18GetNterpEntryPointEv: ['art::interpreter::GetNterpEntryPoint', 'pointer', []],

          _ZN3art7Monitor17TranslateLocationEPNS_9ArtMethodEjPPKcPi: ['art::Monitor::TranslateLocation', 'void', ['pointer', 'uint32', 'pointer', 'pointer']]
        },
        variables: {
          _ZN3art3Dbg9gRegistryE: function (address) {
            this.isJdwpStarted = () => !address.readPointer().isNull();
          },
          _ZN3art3Dbg15gDebuggerActiveE: function (address) {
            this.isDebuggerActive = () => !!address.readU8();
          }
        },
        optionals: [
          'artInterpreterToCompiledCodeBridge',
          '_ZN3art9JavaVMExt12AddGlobalRefEPNS_6ThreadENS_6ObjPtrINS_6mirror6ObjectEEE',
          '_ZN3art9JavaVMExt12AddGlobalRefEPNS_6ThreadEPNS_6mirror6ObjectE',
          '_ZN3art9JavaVMExt12DecodeGlobalEPv',
          '_ZN3art9JavaVMExt12DecodeGlobalEPNS_6ThreadEPv',
          '_ZNK3art6Thread19DecodeGlobalJObjectEP8_jobject',
          '_ZNK3art6Thread13DecodeJObjectEP8_jobject',
          '_ZN3art10ThreadList10SuspendAllEPKcb',
          '_ZN3art10ThreadList10SuspendAllEv',
          '_ZN3art11ClassLinker12VisitClassesEPNS_12ClassVisitorE',
          '_ZN3art11ClassLinker12VisitClassesEPFbPNS_6mirror5ClassEPvES4_',
          '_ZNK3art11ClassLinker17VisitClassLoadersEPNS_18ClassLoaderVisitorE',
          '_ZN3art6mirror6Object5CloneEPNS_6ThreadE',
          '_ZN3art6mirror6Object5CloneEPNS_6ThreadEm',
          '_ZN3art6mirror6Object5CloneEPNS_6ThreadEj',
          '_ZN3art22IndirectReferenceTable3AddEjPNS_6mirror6ObjectE',
          '_ZN3art22IndirectReferenceTable3AddENS_15IRTSegmentStateENS_6ObjPtrINS_6mirror6ObjectEEE',
          '_ZN3art2gc4Heap12VisitObjectsEPFvPNS_6mirror6ObjectEPvES5_',
          '_ZN3art2gc4Heap12GetInstancesERNS_24VariableSizedHandleScopeENS_6HandleINS_6mirror5ClassEEEiRNSt3__16vectorINS4_INS5_6ObjectEEENS8_9allocatorISB_EEEE',
          '_ZN3art2gc4Heap12GetInstancesERNS_24VariableSizedHandleScopeENS_6HandleINS_6mirror5ClassEEEbiRNSt3__16vectorINS4_INS5_6ObjectEEENS8_9allocatorISB_EEEE',
          '_ZN3art12StackVisitorC2EPNS_6ThreadEPNS_7ContextENS0_13StackWalkKindEjb',
          '_ZN3art12StackVisitorC2EPNS_6ThreadEPNS_7ContextENS0_13StackWalkKindEmb',
          '_ZN3art12StackVisitor9WalkStackILNS0_16CountTransitionsE0EEEvb',
          '_ZNK3art12StackVisitor9GetMethodEv',
          '_ZNK3art12StackVisitor16DescribeLocationEv',
          '_ZNK3art12StackVisitor24GetCurrentQuickFrameInfoEv',
          '_ZN3art6Thread18GetLongJumpContextEv',
          '_ZN3art6mirror5Class13GetDescriptorEPNSt3__112basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEE',
          '_ZN3art6mirror5Class11GetLocationEv',
          '_ZN3art9ArtMethod12PrettyMethodEb',
          '_ZN3art12PrettyMethodEPNS_9ArtMethodEb',
          '_ZN3art3Dbg13ConfigureJdwpERKNS_4JDWP11JdwpOptionsE',
          '_ZN3art31InternalDebuggerControlCallback13StartDebuggerEv',
          '_ZN3art3Dbg15gDebuggerActiveE',
          '_ZN3art15instrumentation15Instrumentation20EnableDeoptimizationEv',
          '_ZN3art15instrumentation15Instrumentation20DeoptimizeEverythingEPKc',
          '_ZN3art15instrumentation15Instrumentation20DeoptimizeEverythingEv',
          '_ZN3art7Runtime19DeoptimizeBootImageEv',
          '_ZN3art15instrumentation15Instrumentation10DeoptimizeEPNS_9ArtMethodE',
          '_ZN3art3Dbg9StartJdwpEv',
          '_ZN3art3Dbg8GoActiveEv',
          '_ZN3art3Dbg21RequestDeoptimizationERKNS_21DeoptimizationRequestE',
          '_ZN3art3Dbg20ManageDeoptimizationEv',
          '_ZN3art3Dbg9gRegistryE',
          '_ZN3art3jni12JniIdManager14DecodeMethodIdEP10_jmethodID',
          '_ZN3art11interpreter18GetNterpEntryPointEv',
          '_ZN3art7Monitor17TranslateLocationEPNS_9ArtMethodEjPPKcPi'
        ]
      }]
    : [{
        module: vmModule.path,
        functions: {
          _Z20dvmDecodeIndirectRefP6ThreadP8_jobject: ['dvmDecodeIndirectRef', 'pointer', ['pointer', 'pointer']],
          _Z15dvmUseJNIBridgeP6MethodPv: ['dvmUseJNIBridge', 'void', ['pointer', 'pointer']],
          _Z20dvmHeapSourceGetBasev: ['dvmHeapSourceGetBase', 'pointer', []],
          _Z21dvmHeapSourceGetLimitv: ['dvmHeapSourceGetLimit', 'pointer', []],
          _Z16dvmIsValidObjectPK6Object: ['dvmIsValidObject', 'uint8', ['pointer']],
          JNI_GetCreatedJavaVMs: ['JNI_GetCreatedJavaVMs', 'int', ['pointer', 'int', 'pointer']]
        },
        variables: {
          gDvmJni: function (address) {
            this.gDvmJni = address;
          },
          gDvm: function (address) {
            this.gDvm = address;
          }
        }
      }];

  const missing = [];

  pending.forEach(function (api) {
    const functions = api.functions || {};
    const variables = api.variables || {};
    const optionals = new Set(api.optionals || []);

    const exportByName = Module
      .enumerateExports(api.module)
      .reduce(function (result, exp) {
        result[exp.name] = exp;
        return result;
      }, {});

    Object.keys(functions)
      .forEach(function (name) {
        const exp = exportByName[name];
        if (exp !== undefined && exp.type === 'function') {
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
        if (exp !== undefined && exp.type === 'variable') {
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

  if (isArt) {
    const apiLevel = getAndroidApiLevel();

    let kAccCompileDontBother;
    if (apiLevel >= 27) {
      kAccCompileDontBother = 0x02000000;
    } else if (apiLevel >= 24) {
      kAccCompileDontBother = 0x01000000;
    } else {
      kAccCompileDontBother = 0;
    }
    temporaryApi.kAccCompileDontBother = kAccCompileDontBother;

    const artRuntime = temporaryApi.vm.add(pointerSize).readPointer();
    temporaryApi.artRuntime = artRuntime;
    const runtimeSpec = getArtRuntimeSpec(temporaryApi);
    const runtimeOffset = runtimeSpec.offset;
    const instrumentationOffset = runtimeOffset.instrumentation;
    temporaryApi.artInstrumentation = (instrumentationOffset !== null) ? artRuntime.add(instrumentationOffset) : null;

    temporaryApi.artHeap = artRuntime.add(runtimeOffset.heap).readPointer();
    temporaryApi.artThreadList = artRuntime.add(runtimeOffset.threadList).readPointer();

    /*
     * We must use the *correct* copy (or address) of art_quick_generic_jni_trampoline
     * in order for the stack trace to recognize the JNI stub quick frame.
     *
     * For ARTs for Android 6.x we can just use the JNI trampoline built into ART.
     */
    const classLinker = artRuntime.add(runtimeOffset.classLinker).readPointer();

    const classLinkerOffsets = getArtClassLinkerSpec(artRuntime, runtimeSpec).offset;
    const quickResolutionTrampoline = classLinker.add(classLinkerOffsets.quickResolutionTrampoline).readPointer();
    const quickImtConflictTrampoline = classLinker.add(classLinkerOffsets.quickImtConflictTrampoline).readPointer();
    const quickGenericJniTrampoline = classLinker.add(classLinkerOffsets.quickGenericJniTrampoline).readPointer();
    const quickToInterpreterBridgeTrampoline = classLinker.add(classLinkerOffsets.quickToInterpreterBridgeTrampoline).readPointer();

    temporaryApi.artClassLinker = {
      address: classLinker,
      quickResolutionTrampoline,
      quickImtConflictTrampoline,
      quickGenericJniTrampoline,
      quickToInterpreterBridgeTrampoline
    };

    const vm = new VM(temporaryApi);

    temporaryApi.artQuickGenericJniTrampoline = getArtQuickEntrypointFromTrampoline(quickGenericJniTrampoline, vm);
    temporaryApi.artQuickToInterpreterBridge = getArtQuickEntrypointFromTrampoline(quickToInterpreterBridgeTrampoline, vm);
    temporaryApi.artQuickResolutionTrampoline = getArtQuickEntrypointFromTrampoline(quickResolutionTrampoline, vm);

    if (temporaryApi['art::JavaVMExt::AddGlobalRef'] === undefined) {
      temporaryApi['art::JavaVMExt::AddGlobalRef'] = makeAddGlobalRefFallbackForAndroid5(temporaryApi);
    }
    if (temporaryApi['art::JavaVMExt::DecodeGlobal'] === undefined) {
      temporaryApi['art::JavaVMExt::DecodeGlobal'] = makeDecodeGlobalFallback(temporaryApi);
    }
    if (temporaryApi['art::ArtMethod::PrettyMethod'] === undefined) {
      temporaryApi['art::ArtMethod::PrettyMethod'] = temporaryApi['art::ArtMethod::PrettyMethodNullSafe'];
    }
    if (temporaryApi['art::interpreter::GetNterpEntryPoint'] !== undefined) {
      temporaryApi.artNterpEntryPoint = temporaryApi['art::interpreter::GetNterpEntryPoint']();
    }

    artController = makeArtController(vm);

    fixupArtQuickDeliverExceptionBug(temporaryApi);

    let cachedJvmti = null;
    Object.defineProperty(temporaryApi, 'jvmti', {
      get () {
        if (cachedJvmti === null) {
          cachedJvmti = [tryGetEnvJvmti(vm, this.artRuntime)];
        }
        return cachedJvmti[0];
      }
    });
  }

  const cxxImports = Module.enumerateImports(vmModule.path)
    .filter(imp => imp.name.indexOf('_Z') === 0)
    .reduce((result, imp) => {
      result[imp.name] = imp.address;
      return result;
    }, {});
  temporaryApi.$new = new NativeFunction(cxxImports._Znwm || cxxImports._Znwj, 'pointer', ['ulong'], nativeFunctionOptions);
  temporaryApi.$delete = new NativeFunction(cxxImports._ZdlPv, 'void', ['pointer'], nativeFunctionOptions);

  MethodMangler = isArt ? ArtMethodMangler : DalvikMethodMangler;

  return temporaryApi;
}

function tryGetEnvJvmti (vm, runtime) {
  let env = null;

  vm.perform(() => {
    const ensurePluginLoaded = new NativeFunction(
      Module.getExportByName('libart.so', '_ZN3art7Runtime18EnsurePluginLoadedEPKcPNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEE'),
      'bool',
      ['pointer', 'pointer', 'pointer']);
    const errorPtr = Memory.alloc(pointerSize);
    const success = ensurePluginLoaded(runtime, Memory.allocUtf8String('libopenjdkjvmti.so'), errorPtr);
    if (!success) {
      // FIXME: Avoid leaking error
      return;
    }

    const kArtTiVersion = jvmtiVersion.v1_2 | 0x40000000;
    const handle = vm.tryGetEnvHandle(kArtTiVersion);
    if (handle === null) {
      return;
    }
    env = new EnvJvmti(handle, vm);

    const capaBuf = Memory.alloc(8);
    capaBuf.writeU64(jvmtiCapabilities.canTagObjects);
    const result = env.addCapabilities(capaBuf);
    if (result !== JNI_OK) {
      env = null;
    }
  });

  return env;
}

function ensureClassInitialized (env, classRef) {
  const api = getApi();
  if (api.flavor !== 'art') {
    return;
  }

  env.getFieldId(classRef, 'x', 'Z');
  env.exceptionClear();
}

function getArtVMSpec (api) {
  return {
    offset: (pointerSize === 4)
      ? {
          globalsLock: 32,
          globals: 72
        }
      : {
          globalsLock: 64,
          globals: 112
        }
  };
}

function _getArtRuntimeSpec (api) {
  /*
   * class Runtime {
   * ...
   * gc::Heap* heap_;                <-- we need to find this
   * std::unique_ptr<ArenaPool> jit_arena_pool_;     <----- API level >= 24
   * std::unique_ptr<ArenaPool> arena_pool_;             __
   * std::unique_ptr<ArenaPool> low_4gb_arena_pool_/linear_alloc_arena_pool_; <--|__ API level >= 23
   * std::unique_ptr<LinearAlloc> linear_alloc_;         \_
   * std::atomic<LinearAlloc*> startup_linear_alloc_;<----- API level >= 34
   * size_t max_spins_before_thin_lock_inflation_;
   * MonitorList* monitor_list_;
   * MonitorPool* monitor_pool_;
   * ThreadList* thread_list_;        <--- and these
   * InternTable* intern_table_;      <--/
   * ClassLinker* class_linker_;      <-/
   * SignalCatcher* signal_catcher_;
   * SmallIrtAllocator* small_irt_allocator_; <------------ API level >= 33 or Android Tiramisu Developer Preview
   * std::unique_ptr<jni::JniIdManager> jni_id_manager_; <- API level >= 30 or Android R Developer Preview
   * bool use_tombstoned_traces_;     <-------------------- API level 27/28
   * std::string stack_trace_file_;   <-------------------- API level <= 28
   * JavaVMExt* java_vm_;             <-- so we find this then calculate our way backwards
   * ...
   * }
   */

  const vm = api.vm;
  const runtime = api.artRuntime;

  const startOffset = (pointerSize === 4) ? 200 : 384;
  const endOffset = startOffset + (100 * pointerSize);

  const apiLevel = getAndroidApiLevel();
  const codename = getAndroidCodename();
  const isApiLevel34OrApexEquivalent = Module.findExportByName('libart.so', '_ZN3art7AppInfo29GetPrimaryApkReferenceProfileEv') !== null;

  let spec = null;

  for (let offset = startOffset; offset !== endOffset; offset += pointerSize) {
    const value = runtime.add(offset).readPointer();
    if (value.equals(vm)) {
      let classLinkerOffsets;
      let jniIdManagerOffset = null;
      if (apiLevel >= 33 || codename === 'Tiramisu') {
        classLinkerOffsets = [offset - (4 * pointerSize)];
        jniIdManagerOffset = offset - pointerSize;
      } else if (apiLevel >= 30 || codename === 'R') {
        classLinkerOffsets = [offset - (3 * pointerSize), offset - (4 * pointerSize)];
        jniIdManagerOffset = offset - pointerSize;
      } else if (apiLevel >= 29) {
        classLinkerOffsets = [offset - (2 * pointerSize)];
      } else if (apiLevel >= 27) {
        classLinkerOffsets = [offset - STD_STRING_SIZE - (3 * pointerSize)];
      } else {
        classLinkerOffsets = [offset - STD_STRING_SIZE - (2 * pointerSize)];
      }

      for (const classLinkerOffset of classLinkerOffsets) {
        const internTableOffset = classLinkerOffset - pointerSize;
        const threadListOffset = internTableOffset - pointerSize;

        let heapOffset;
        if (isApiLevel34OrApexEquivalent) {
          heapOffset = threadListOffset - (9 * pointerSize);
        } else if (apiLevel >= 24) {
          heapOffset = threadListOffset - (8 * pointerSize);
        } else if (apiLevel >= 23) {
          heapOffset = threadListOffset - (7 * pointerSize);
        } else {
          heapOffset = threadListOffset - (4 * pointerSize);
        }

        const candidate = {
          offset: {
            heap: heapOffset,
            threadList: threadListOffset,
            internTable: internTableOffset,
            classLinker: classLinkerOffset,
            jniIdManager: jniIdManagerOffset
          }
        };
        if (tryGetArtClassLinkerSpec(runtime, candidate) !== null) {
          spec = candidate;
          break;
        }
      }

      break;
    }
  }

  if (spec === null) {
    throw new Error('Unable to determine Runtime field offsets');
  }

  spec.offset.instrumentation = tryDetectInstrumentationOffset(api);
  spec.offset.jniIdsIndirection = tryDetectJniIdsIndirectionOffset();

  return spec;
}

const instrumentationOffsetParsers = {
  ia32: parsex86InstrumentationOffset,
  x64: parsex86InstrumentationOffset,
  arm: parseArmInstrumentationOffset,
  arm64: parseArm64InstrumentationOffset
};

function tryDetectInstrumentationOffset (api) {
  const impl = api['art::Runtime::DeoptimizeBootImage'];
  if (impl === undefined) {
    return null;
  }

  return parseInstructionsAt(impl, instrumentationOffsetParsers[Process.arch], { limit: 30 });
}

function parsex86InstrumentationOffset (insn) {
  if (insn.mnemonic !== 'lea') {
    return null;
  }

  const offset = insn.operands[1].value.disp;
  if (offset < 0x100 || offset > 0x400) {
    return null;
  }

  return offset;
}

function parseArmInstrumentationOffset (insn) {
  if (insn.mnemonic !== 'add.w') {
    return null;
  }

  const ops = insn.operands;
  if (ops.length !== 3) {
    return null;
  }

  const op2 = ops[2];
  if (op2.type !== 'imm') {
    return null;
  }

  return op2.value;
}

function parseArm64InstrumentationOffset (insn) {
  if (insn.mnemonic !== 'add') {
    return null;
  }

  const ops = insn.operands;
  if (ops.length !== 3) {
    return null;
  }

  if (ops[0].value === 'sp' || ops[1].value === 'sp') {
    return null;
  }

  const op2 = ops[2];
  if (op2.type !== 'imm') {
    return null;
  }

  const offset = op2.value.valueOf();
  if (offset < 0x100 || offset > 0x400) {
    return null;
  }

  return offset;
}

const jniIdsIndirectionOffsetParsers = {
  ia32: parsex86JniIdsIndirectionOffset,
  x64: parsex86JniIdsIndirectionOffset,
  arm: parseArmJniIdsIndirectionOffset,
  arm64: parseArm64JniIdsIndirectionOffset
};

function tryDetectJniIdsIndirectionOffset () {
  const impl = Module.findExportByName('libart.so', '_ZN3art7Runtime12SetJniIdTypeENS_9JniIdTypeE');
  if (impl === null) {
    return null;
  }

  const offset = parseInstructionsAt(impl, jniIdsIndirectionOffsetParsers[Process.arch], { limit: 20 });
  if (offset === null) {
    throw new Error('Unable to determine Runtime.jni_ids_indirection_ offset');
  }

  return offset;
}

function parsex86JniIdsIndirectionOffset (insn) {
  if (insn.mnemonic === 'cmp') {
    return insn.operands[0].value.disp;
  }

  return null;
}

function parseArmJniIdsIndirectionOffset (insn) {
  if (insn.mnemonic === 'ldr.w') {
    return insn.operands[1].value.disp;
  }

  return null;
}

function parseArm64JniIdsIndirectionOffset (insn, prevInsn) {
  if (prevInsn === null) {
    return null;
  }

  const { mnemonic } = insn;
  const { mnemonic: prevMnemonic
```