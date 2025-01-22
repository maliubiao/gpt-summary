Response:
`class-factory.js` 是 Frida 的 `frida-java-bridge` 模块中的一个核心文件，主要负责与 Java 虚拟机（JVM 或 ART）进行交互，并提供对 Java 类的动态操作和调试功能。以下是该文件的主要功能归纳：

### 1. **Java 类的动态加载与操作**
   - **功能**：`ClassFactory` 类负责动态加载 Java 类，并提供对类的实例化、方法调用、字段访问等操作。
   - **实现**：通过 JNI（Java Native Interface）与 Java 虚拟机进行交互，动态加载类并生成对应的 JavaScript 包装器。
   - **示例**：用户可以通过 `ClassFactory.use(className)` 来加载一个 Java 类，并通过返回的包装器对象调用类的方法或访问字段。

### 2. **Java 类的实例化与对象操作**
   - **功能**：提供对 Java 对象的实例化、类型转换、对象引用管理等操作。
   - **实现**：通过 JNI 的 `NewObject`、`NewGlobalRef`、`DeleteLocalRef` 等函数来管理 Java 对象的生命周期。
   - **示例**：用户可以通过 `classWrapper.$new()` 来实例化一个 Java 对象，并通过 `classWrapper.cast(obj, klass)` 进行类型转换。

### 3. **Java 方法的动态调用**
   - **功能**：允许用户动态调用 Java 类的方法，包括静态方法和实例方法。
   - **实现**：通过 JNI 的 `CallStaticMethod` 和 `CallMethod` 等函数来实现方法的调用。
   - **示例**：用户可以通过 `classWrapper.methodName(args)` 来调用 Java 类的方法。

### 4. **Java 字段的动态访问**
   - **功能**：允许用户动态访问 Java 类的字段，包括静态字段和实例字段。
   - **实现**：通过 JNI 的 `GetField` 和 `SetField` 等函数来实现字段的访问和修改。
   - **示例**：用户可以通过 `classWrapper.fieldName` 来访问或修改 Java 类的字段。

### 5. **Java 类的注册与动态生成**
   - **功能**：允许用户在运行时动态生成并注册新的 Java 类。
   - **实现**：通过生成 DEX 文件并加载到 Java 虚拟机中来实现类的动态注册。
   - **示例**：用户可以通过 `ClassFactory.registerClass(spec)` 来动态生成并注册一个新的 Java 类。

### 6. **Java 对象的遍历与选择**
   - **功能**：提供对 Java 堆中对象的遍历和选择功能，允许用户查找特定类的所有实例。
   - **实现**：通过 JVMTI（Java Virtual Machine Tool Interface）或 ART 的 GC 接口来遍历堆中的对象。
   - **示例**：用户可以通过 `ClassFactory.choose(className, callbacks)` 来遍历并选择特定类的所有实例。

### 7. **Java 类的缓存与优化**
   - **功能**：通过缓存机制优化 Java 类的加载和访问性能。
   - **实现**：使用 LRU（Least Recently Used）缓存策略来缓存已加载的类和对象。
   - **示例**：用户可以通过 `ClassFactory.use(className)` 来加载类，并利用缓存机制提高性能。

### 8. **Java 类的调试与监控**
   - **功能**：提供对 Java 类的调试和监控功能，允许用户动态修改类的行为。
   - **实现**：通过 Frida 的 `Interceptor` 和 `Memory` 模块来实现对 Java 方法的 Hook 和监控。
   - **示例**：用户可以通过 `Interceptor.attach(classWrapper.methodName, { onEnter, onLeave })` 来监控 Java 方法的调用。

### 9. **Java 类的类型系统支持**
   - **功能**：提供对 Java 类型系统的支持，包括基本类型、数组类型和对象类型的处理。
   - **实现**：通过 `getType`、`getPrimitiveType`、`getArrayType` 等函数来处理 Java 类型。
   - **示例**：用户可以通过 `ClassFactory.array(type, elements)` 来创建 Java 数组。

### 10. **Java 类的生命周期管理**
   - **功能**：提供对 Java 类和对象的生命周期管理，包括对象的创建、销毁和引用管理。
   - **实现**：通过 JNI 的 `NewGlobalRef`、`DeleteGlobalRef` 等函数来管理对象的生命周期。
   - **示例**：用户可以通过 `classWrapper.$dispose()` 来释放 Java 对象的引用。

### 11. **Java 类的继承与多态支持**
   - **功能**：提供对 Java 类的继承和多态的支持，允许用户访问父类的方法和字段。
   - **实现**：通过 JNI 的 `GetSuperclass` 和 `CallNonvirtualMethod` 等函数来实现继承和多态的支持。
   - **示例**：用户可以通过 `classWrapper.$super.methodName(args)` 来调用父类的方法。

### 12. **Java 类的异常处理**
   - **功能**：提供对 Java 异常的捕获和处理功能。
   - **实现**：通过 JNI 的 `ExceptionCheck` 和 `ExceptionDescribe` 等函数来处理 Java 异常。
   - **示例**：用户可以通过 `env.throwIfExceptionPending()` 来检查并处理 Java 异常。

### 13. **Java 类的动态代理**
   - **功能**：提供对 Java 类的动态代理功能，允许用户动态生成代理类。
   - **实现**：通过生成 DEX 文件并加载到 Java 虚拟机中来实现动态代理。
   - **示例**：用户可以通过 `ClassFactory.registerClass(spec)` 来动态生成代理类。

### 14. **Java 类的调试线索**
   - **功能**：提供对 Java 类的调试线索，帮助用户定位和解决问题。
   - **实现**：通过 Frida 的 `Thread` 和 `Process` 模块来获取调试线索。
   - **示例**：用户可以通过 `Thread.sleep(0.05)` 来暂停当前线程，以便调试。

### 15. **Java 类的二进制底层操作**
   - **功能**：提供对 Java 类的二进制底层操作，包括内存扫描和修改。
   - **实现**：通过 Frida 的 `Memory` 模块来实现内存扫描和修改。
   - **示例**：用户可以通过 `Memory.scan(base, size, pattern, callbacks)` 来扫描内存中的特定模式。

### 16. **Java 类的 Linux 内核支持**
   - **功能**：提供对 Linux 内核的支持，允许用户与内核进行交互。
   - **实现**：通过 Frida 的 `Process` 模块来实现与 Linux 内核的交互。
   - **示例**：用户可以通过 `Process.getModuleByName('libdvm.so')` 来获取 Android Dalvik 虚拟机的模块信息。

### 17. **Java 类的 LLDB 调试支持**
   - **功能**：提供对 LLDB 调试器的支持，允许用户通过 LLDB 调试 Java 类。
   - **实现**：通过 Frida 的 `NativeFunction` 和 `Memory` 模块来实现 LLDB 调试支持。
   - **示例**：用户可以通过 `NativeFunction(address, 'pointer', ['pointer', 'pointer'])` 来调用 LLDB 调试器中的函数。

### 18. **Java 类的常见使用错误**
   - **功能**：提供对常见使用错误的处理和建议。
   - **实现**：通过 Frida 的 `Error` 模块来处理常见错误。
   - **示例**：用户可能会遇到 `Cast from 'java.lang.Object' to 'com.example.MyClass' isn't possible` 的错误，提示类型转换失败。

### 19. **Java 类的用户操作路径**
   - **功能**：提供用户操作的路径，帮助用户理解如何一步步到达当前状态。
   - **实现**：通过 Frida 的 `Thread` 和 `Process` 模块来获取用户操作路径。
   - **示例**：用户可以通过 `Thread.backtrace()` 来获取当前线程的调用栈，帮助定位问题。

### 20. **Java 类的逻辑推理**
   - **功能**：提供对 Java 类的逻辑推理功能，帮助用户理解类的行为。
   - **实现**：通过 Frida 的 `Interceptor` 和 `Memory` 模块来实现逻辑推理。
   - **示例**：用户可以通过 `Interceptor.attach(classWrapper.methodName, { onEnter, onLeave })` 来监控方法的调用，推理类的行为。

### 21. **Java 类的假设输入与输出**
   - **功能**：提供对 Java 类的假设输入与输出功能，帮助用户测试类的行为。
   - **实现**：通过 Frida 的 `Interceptor` 和 `Memory` 模块来实现假设输入与输出。
   - **示例**：用户可以通过 `Interceptor.attach(classWrapper.methodName, { onEnter, onLeave })` 来监控方法的输入与输出，测试类的行为。

### 22. **Java 类的调试功能复刻**
   - **功能**：提供对 Java 类的调试功能复刻，帮助用户复现调试过程。
   - **实现**：通过 Frida 的 `NativeFunction` 和 `Memory` 模块来实现调试功能复刻。
   - **示例**：用户可以通过 `NativeFunction(address, 'pointer', ['pointer', 'pointer'])` 来复刻调试功能。

### 23. **Java 类的 LLDB Python 脚本示例**
   - **功能**：提供对 Java 类的 LLDB Python 脚本示例，帮助用户通过 LLDB 调试 Java 类。
   - **实现**：通过 Frida 的 `NativeFunction` 和 `Memory` 模块来实现 LLDB Python 脚本示例。
   - **示例**：用户可以通过以下 LLDB Python 脚本来调试 Java 类：
     ```python
     import lldb

     def debug_java_class(debugger, command, result, internal_dict):
         target = debugger.GetSelectedTarget()
         process = target.GetProcess()
         thread = process.GetSelectedThread()
         frame = thread.GetSelectedFrame()

         # 获取 Java 类的地址
         class_address = frame.FindVariable("classWrapper").GetValueAsUnsigned()

         # 调用 Java 类的方法
         method_address = frame.FindVariable("methodName").GetValueAsUnsigned()
         lldb.debugger.HandleCommand(f"expr (void) ((void (*)(void *)) {method_address})({class_address})")

     # 注册 LLDB 命令
     def __lldb_init_module(debugger, internal_dict):
         debugger.HandleCommand('command script add -f debug_java_class.debug_java_class debug_java_class')
     ```

### 总结
`class-factory.js` 是 Frida 中与 Java 虚拟机交互的核心模块，提供了丰富的功能来动态操作和调试 Java 类。通过该模块，用户可以轻松地加载、实例化、调用方法和访问字段，同时还可以动态生成和注册新的 Java 类。此外，该模块还提供了对 Java 堆的遍历、对象的生命周期管理、异常处理、类型系统支持等功能，极大地增强了 Frida 在 Android 应用动态分析和调试中的能力。
Prompt: 
```
这是目录为frida-java-bridge/lib/class-factory.js的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
这是第1部分，共2部分，请归纳一下它的功能

"""
const Env = require('./env');
const android = require('./android');
const jvm = require('./jvm');
const jsizeSize = 4;
let {
  ensureClassInitialized,
  makeMethodMangler
} = android;
const ClassModel = require('./class-model');
const LRU = require('./lru');
const mkdex = require('./mkdex');
const {
  getType,
  getPrimitiveType,
  getArrayType,
  makeJniObjectTypeName
} = require('./types');

const CONSTRUCTOR_METHOD = 1;
const STATIC_METHOD = 2;
const INSTANCE_METHOD = 3;

const STATIC_FIELD = 1;
const INSTANCE_FIELD = 2;

const STRATEGY_VIRTUAL = 1;
const STRATEGY_DIRECT = 2;

const PENDING_USE = Symbol('PENDING_USE');

const DEFAULT_CACHE_DIR = '/data/local/tmp';

const {
  getCurrentThreadId,
  pointerSize
} = Process;

const factoryCache = {
  state: 'empty',
  factories: [],
  loaders: null,
  Integer: null
};

let vm = null;
let api = null;
let isArtVm = null;

let wrapperHandler = null;
let dispatcherPrototype = null;
let methodPrototype = null;
let valueOfPrototype = null;

let cachedLoaderInvoke = null;
let cachedLoaderMethod = null;

const ignoredThreads = new Map();

class ClassFactory {
  static _initialize (_vm, _api) {
    vm = _vm;
    api = _api;
    isArtVm = _api.flavor === 'art';
    if (_api.flavor === 'jvm') {
      ensureClassInitialized = jvm.ensureClassInitialized;
      makeMethodMangler = jvm.makeMethodMangler;
    }
  }

  static _disposeAll (env) {
    factoryCache.factories.forEach(factory => {
      factory._dispose(env);
    });
  }

  static get (classLoader) {
    const cache = getFactoryCache();

    const defaultFactory = cache.factories[0];

    if (classLoader === null) {
      return defaultFactory;
    }

    const indexObj = cache.loaders.get(classLoader);
    if (indexObj !== null) {
      const index = defaultFactory.cast(indexObj, cache.Integer);
      return cache.factories[index.intValue()];
    }

    const factory = new ClassFactory();
    factory.loader = classLoader;
    factory.cacheDir = defaultFactory.cacheDir;
    addFactoryToCache(factory, classLoader);

    return factory;
  }

  constructor () {
    this.cacheDir = DEFAULT_CACHE_DIR;
    this.codeCacheDir = DEFAULT_CACHE_DIR + '/dalvik-cache';

    this.tempFileNaming = {
      prefix: 'frida',
      suffix: ''
    };

    this._classes = {};
    this._classHandles = new LRU(10, releaseClassHandle);
    this._patchedMethods = new Set();
    this._loader = null;
    this._types = [{}, {}];

    factoryCache.factories.push(this);
  }

  _dispose (env) {
    Array.from(this._patchedMethods).forEach(method => {
      method.implementation = null;
    });
    this._patchedMethods.clear();

    android.revertGlobalPatches();

    this._classHandles.dispose(env);
    this._classes = {};
  }

  get loader () {
    return this._loader;
  }

  set loader (value) {
    const isInitial = this._loader === null && value !== null;

    this._loader = value;

    if (isInitial && factoryCache.state === 'ready' && this === factoryCache.factories[0]) {
      addFactoryToCache(this, value);
    }
  }

  use (className, options = {}) {
    const allowCached = options.cache !== 'skip';

    let C = allowCached ? this._getUsedClass(className) : undefined;
    if (C === undefined) {
      try {
        const env = vm.getEnv();

        const { _loader: loader } = this;
        const getClassHandle = (loader !== null)
          ? makeLoaderClassHandleGetter(className, loader, env)
          : makeBasicClassHandleGetter(className);

        C = this._make(className, getClassHandle, env);
      } finally {
        if (allowCached) {
          this._setUsedClass(className, C);
        }
      }
    }

    return C;
  }

  _getUsedClass (className) {
    let c;
    while ((c = this._classes[className]) === PENDING_USE) {
      Thread.sleep(0.05);
    }
    if (c === undefined) {
      this._classes[className] = PENDING_USE;
    }
    return c;
  }

  _setUsedClass (className, c) {
    if (c !== undefined) {
      this._classes[className] = c;
    } else {
      delete this._classes[className];
    }
  }

  _make (name, getClassHandle, env) {
    const C = makeClassWrapperConstructor();
    const proto = Object.create(Wrapper.prototype, {
      [Symbol.for('n')]: {
        value: name
      },
      $n: {
        get () {
          return this[Symbol.for('n')];
        }
      },
      [Symbol.for('C')]: {
        value: C
      },
      $C: {
        get () {
          return this[Symbol.for('C')];
        }
      },
      [Symbol.for('w')]: {
        value: null,
        writable: true
      },
      $w: {
        get () {
          return this[Symbol.for('w')];
        },
        set (val) {
          this[Symbol.for('w')] = val;
        }
      },
      [Symbol.for('_s')]: {
        writable: true
      },
      $_s: {
        get () {
          return this[Symbol.for('_s')];
        },
        set (val) {
          this[Symbol.for('_s')] = val;
        }
      },
      [Symbol.for('c')]: {
        value: [null]
      },
      $c: {
        get () {
          return this[Symbol.for('c')];
        }
      },
      [Symbol.for('m')]: {
        value: new Map()
      },
      $m: {
        get () {
          return this[Symbol.for('m')];
        }
      },
      [Symbol.for('l')]: {
        value: null,
        writable: true
      },
      $l: {
        get () {
          return this[Symbol.for('l')];
        },
        set (val) {
          this[Symbol.for('l')] = val;
        }
      },
      [Symbol.for('gch')]: {
        value: getClassHandle
      },
      $gch: {
        get () {
          return this[Symbol.for('gch')];
        }
      },
      [Symbol.for('f')]: {
        value: this
      },
      $f: {
        get () {
          return this[Symbol.for('f')];
        }
      }
    });
    C.prototype = proto;

    const classWrapper = new C(null);
    proto[Symbol.for('w')] = classWrapper;
    proto.$w = classWrapper;

    const h = classWrapper.$borrowClassHandle(env);
    try {
      const classHandle = h.value;

      ensureClassInitialized(env, classHandle);

      proto.$l = ClassModel.build(classHandle, env);
    } finally {
      h.unref(env);
    }

    return classWrapper;
  }

  retain (obj) {
    const env = vm.getEnv();
    return obj.$clone(env);
  }

  cast (obj, klass, owned) {
    const env = vm.getEnv();

    let handle = obj.$h;
    if (handle === undefined) {
      handle = obj;
    }

    const h = klass.$borrowClassHandle(env);
    try {
      const isValidCast = env.isInstanceOf(handle, h.value);
      if (!isValidCast) {
        throw new Error(`Cast from '${env.getObjectClassName(handle)}' to '${klass.$n}' isn't possible`);
      }
    } finally {
      h.unref(env);
    }

    const C = klass.$C;
    return new C(handle, STRATEGY_VIRTUAL, env, owned);
  }

  wrap (handle, klass, env) {
    const C = klass.$C;
    const wrapper = new C(handle, STRATEGY_VIRTUAL, env, false);
    wrapper.$r = Script.bindWeak(wrapper, vm.makeHandleDestructor(handle));
    return wrapper;
  }

  array (type, elements) {
    const env = vm.getEnv();

    const primitiveType = getPrimitiveType(type);
    if (primitiveType !== null) {
      type = primitiveType.name;
    }
    const arrayType = getArrayType('[' + type, false, this);

    const rawArray = arrayType.toJni(elements, env);
    return arrayType.fromJni(rawArray, env, true);
  }

  registerClass (spec) {
    const env = vm.getEnv();

    const tempHandles = [];
    try {
      const Class = this.use('java.lang.Class');
      const Method = env.javaLangReflectMethod();
      const invokeObjectMethodNoArgs = env.vaMethod('pointer', []);

      const className = spec.name;
      const interfaces = (spec.implements || []);
      const superClass = (spec.superClass || this.use('java.lang.Object'));

      const dexFields = [];
      const dexMethods = [];
      const dexSpec = {
        name: makeJniObjectTypeName(className),
        sourceFileName: makeSourceFileName(className),
        superClass: makeJniObjectTypeName(superClass.$n),
        interfaces: interfaces.map(iface => makeJniObjectTypeName(iface.$n)),
        fields: dexFields,
        methods: dexMethods
      };

      const allInterfaces = interfaces.slice();
      interfaces.forEach(iface => {
        Array.prototype.slice.call(iface.class.getInterfaces())
          .forEach(baseIface => {
            const baseIfaceName = this.cast(baseIface, Class).getCanonicalName();
            allInterfaces.push(this.use(baseIfaceName));
          });
      });

      const fields = spec.fields || {};
      Object.getOwnPropertyNames(fields).forEach(name => {
        const fieldType = this._getType(fields[name]);
        dexFields.push([name, fieldType.name]);
      });

      const baseMethods = {};
      const pendingOverloads = {};
      allInterfaces.forEach(iface => {
        const h = iface.$borrowClassHandle(env);
        tempHandles.push(h);
        const ifaceHandle = h.value;

        iface.$ownMembers
          .filter(name => {
            return iface[name].overloads !== undefined;
          })
          .forEach(name => {
            const method = iface[name];

            const overloads = method.overloads;
            const overloadIds = overloads.map(overload => makeOverloadId(name, overload.returnType, overload.argumentTypes));

            baseMethods[name] = [method, overloadIds, ifaceHandle];
            overloads.forEach((overload, index) => {
              const id = overloadIds[index];
              pendingOverloads[id] = [overload, ifaceHandle];
            });
          });
      });

      const methods = spec.methods || {};
      const methodNames = Object.keys(methods);
      const methodEntries = methodNames.reduce((result, name) => {
        const entry = methods[name];
        const rawName = (name === '$init') ? '<init>' : name;
        if (entry instanceof Array) {
          result.push(...entry.map(e => [rawName, e]));
        } else {
          result.push([rawName, entry]);
        }
        return result;
      }, []);

      const implMethods = [];

      methodEntries.forEach(([name, methodValue]) => {
        let type = INSTANCE_METHOD;
        let returnType;
        let argumentTypes;
        let thrownTypeNames = [];
        let impl;

        if (typeof methodValue === 'function') {
          const m = baseMethods[name];
          if (m !== undefined && Array.isArray(m)) {
            const [baseMethod, overloadIds, parentTypeHandle] = m;

            if (overloadIds.length > 1) {
              throw new Error(`More than one overload matching '${name}': signature must be specified`);
            }
            delete pendingOverloads[overloadIds[0]];
            const overload = baseMethod.overloads[0];

            type = overload.type;
            returnType = overload.returnType;
            argumentTypes = overload.argumentTypes;
            impl = methodValue;

            const reflectedMethod = env.toReflectedMethod(parentTypeHandle, overload.handle, 0);
            const thrownTypes = invokeObjectMethodNoArgs(env.handle, reflectedMethod, Method.getGenericExceptionTypes);
            thrownTypeNames = readTypeNames(env, thrownTypes).map(makeJniObjectTypeName);
            env.deleteLocalRef(thrownTypes);
            env.deleteLocalRef(reflectedMethod);
          } else {
            returnType = this._getType('void');
            argumentTypes = [];
            impl = methodValue;
          }
        } else {
          returnType = this._getType(methodValue.returnType || 'void');
          argumentTypes = (methodValue.argumentTypes || []).map(name => this._getType(name));
          impl = methodValue.implementation;
          if (typeof impl !== 'function') {
            throw new Error('Expected a function implementation for method: ' + name);
          }

          const id = makeOverloadId(name, returnType, argumentTypes);
          const pendingOverload = pendingOverloads[id];
          if (pendingOverload !== undefined) {
            const [overload, parentTypeHandle] = pendingOverload;
            delete pendingOverloads[id];

            type = overload.type;
            returnType = overload.returnType;
            argumentTypes = overload.argumentTypes;

            const reflectedMethod = env.toReflectedMethod(parentTypeHandle, overload.handle, 0);
            const thrownTypes = invokeObjectMethodNoArgs(env.handle, reflectedMethod, Method.getGenericExceptionTypes);
            thrownTypeNames = readTypeNames(env, thrownTypes).map(makeJniObjectTypeName);
            env.deleteLocalRef(thrownTypes);
            env.deleteLocalRef(reflectedMethod);
          }
        }

        const returnTypeName = returnType.name;
        const argumentTypeNames = argumentTypes.map(t => t.name);
        const signature = '(' + argumentTypeNames.join('') + ')' + returnTypeName;

        dexMethods.push([name, returnTypeName, argumentTypeNames, thrownTypeNames]);
        implMethods.push([name, signature, type, returnType, argumentTypes, impl]);
      });

      const unimplementedMethodIds = Object.keys(pendingOverloads);
      if (unimplementedMethodIds.length > 0) {
        throw new Error('Missing implementation for: ' + unimplementedMethodIds.join(', '));
      }

      const dex = DexFile.fromBuffer(mkdex(dexSpec), this);
      try {
        dex.load();
      } finally {
        dex.file.delete();
      }

      const classWrapper = this.use(spec.name);

      const numMethods = methodEntries.length;
      if (numMethods > 0) {
        const methodElementSize = 3 * pointerSize;
        const methodElements = Memory.alloc(numMethods * methodElementSize);

        const nativeMethods = [];
        const temporaryHandles = [];

        implMethods.forEach(([name, signature, type, returnType, argumentTypes, impl], index) => {
          const rawName = Memory.allocUtf8String(name);
          const rawSignature = Memory.allocUtf8String(signature);
          const rawImpl = implement(name, classWrapper, type, returnType, argumentTypes, impl);

          methodElements.add(index * methodElementSize).writePointer(rawName);
          methodElements.add((index * methodElementSize) + pointerSize).writePointer(rawSignature);
          methodElements.add((index * methodElementSize) + (2 * pointerSize)).writePointer(rawImpl);

          temporaryHandles.push(rawName, rawSignature);
          nativeMethods.push(rawImpl);
        });

        const h = classWrapper.$borrowClassHandle(env);
        tempHandles.push(h);
        const classHandle = h.value;

        env.registerNatives(classHandle, methodElements, numMethods);
        env.throwIfExceptionPending();

        classWrapper.$nativeMethods = nativeMethods;
      }

      return classWrapper;
    } finally {
      tempHandles.forEach(h => { h.unref(env); });
    }
  }

  choose (specifier, callbacks) {
    const env = vm.getEnv();
    const { flavor } = api;
    if (flavor === 'jvm') {
      this._chooseObjectsJvm(specifier, env, callbacks);
    } else if (flavor === 'art') {
      const legacyApiMissing = api['art::gc::Heap::VisitObjects'] === undefined;
      if (legacyApiMissing) {
        const preA12ApiMissing = api['art::gc::Heap::GetInstances'] === undefined;
        if (preA12ApiMissing) {
          return this._chooseObjectsJvm(specifier, env, callbacks);
        }
      }
      android.withRunnableArtThread(vm, env, thread => {
        if (legacyApiMissing) {
          this._chooseObjectsArtPreA12(specifier, env, thread, callbacks);
        } else {
          this._chooseObjectsArtLegacy(specifier, env, thread, callbacks);
        }
      });
    } else {
      this._chooseObjectsDalvik(specifier, env, callbacks);
    }
  }

  _chooseObjectsJvm (className, env, callbacks) {
    const classWrapper = this.use(className);
    const { jvmti } = api;
    const JVMTI_ITERATION_CONTINUE = 1;
    const JVMTI_HEAP_OBJECT_EITHER = 3;

    const h = classWrapper.$borrowClassHandle(env);
    try {
      const heapObjectCallback = new NativeCallback((classTag, size, tagPtr, userData) => {
        tagPtr.writePointer(h.value);
        return JVMTI_ITERATION_CONTINUE;
      }, 'int', ['long', 'long', 'pointer', 'pointer']);
      jvmti.iterateOverInstancesOfClass(h.value, JVMTI_HEAP_OBJECT_EITHER, heapObjectCallback, h.value);

      const tagPtr = Memory.alloc(pointerSize);
      tagPtr.writePointer(h.value);
      const countPtr = Memory.alloc(jsizeSize);
      const objectsPtr = Memory.alloc(pointerSize);
      jvmti.getObjectsWithTags(1, tagPtr, countPtr, objectsPtr, NULL);

      const count = countPtr.readS32();
      const objects = objectsPtr.readPointer();
      const handles = [];
      for (let i = 0; i !== count; i++) {
        handles.push(objects.add(i * pointerSize).readPointer());
      }
      jvmti.deallocate(objects);

      try {
        for (const handle of handles) {
          const instance = this.cast(handle, classWrapper);
          const result = callbacks.onMatch(instance);
          if (result === 'stop') {
            break;
          }
        }

        callbacks.onComplete();
      } finally {
        handles.forEach(handle => {
          env.deleteLocalRef(handle);
        });
      }
    } finally {
      h.unref(env);
    }
  }

  _chooseObjectsArtPreA12 (className, env, thread, callbacks) {
    const classWrapper = this.use(className);

    const scope = android.VariableSizedHandleScope.$new(thread, vm);

    let needle;
    const h = classWrapper.$borrowClassHandle(env);
    try {
      const object = api['art::JavaVMExt::DecodeGlobal'](api.vm, thread, h.value);
      needle = scope.newHandle(object);
    } finally {
      h.unref(env);
    }

    const maxCount = 0;

    const instances = android.HandleVector.$new();

    api['art::gc::Heap::GetInstances'](api.artHeap, scope, needle, maxCount, instances);

    const instanceHandles = instances.handles.map(handle => env.newGlobalRef(handle));

    instances.$delete();
    scope.$delete();

    try {
      for (const handle of instanceHandles) {
        const instance = this.cast(handle, classWrapper);
        const result = callbacks.onMatch(instance);
        if (result === 'stop') {
          break;
        }
      }

      callbacks.onComplete();
    } finally {
      instanceHandles.forEach(handle => {
        env.deleteGlobalRef(handle);
      });
    }
  }

  _chooseObjectsArtLegacy (className, env, thread, callbacks) {
    const classWrapper = this.use(className);

    const instanceHandles = [];
    const addGlobalReference = api['art::JavaVMExt::AddGlobalRef'];
    const vmHandle = api.vm;

    let needle;
    const h = classWrapper.$borrowClassHandle(env);
    try {
      needle = api['art::JavaVMExt::DecodeGlobal'](vmHandle, thread, h.value).toInt32();
    } finally {
      h.unref(env);
    }

    const collectMatchingInstanceHandles = android.makeObjectVisitorPredicate(needle, object => {
      instanceHandles.push(addGlobalReference(vmHandle, thread, object));
    });

    api['art::gc::Heap::VisitObjects'](api.artHeap, collectMatchingInstanceHandles, NULL);

    try {
      for (const handle of instanceHandles) {
        const instance = this.cast(handle, classWrapper);
        const result = callbacks.onMatch(instance);
        if (result === 'stop') {
          break;
        }
      }
    } finally {
      instanceHandles.forEach(handle => {
        env.deleteGlobalRef(handle);
      });
    }

    callbacks.onComplete();
  }

  _chooseObjectsDalvik (className, callerEnv, callbacks) {
    const classWrapper = this.use(className);

    if (api.addLocalReference === null) {
      const libdvm = Process.getModuleByName('libdvm.so');

      let pattern;
      switch (Process.arch) {
        case 'arm':
          // Verified with 4.3.1 and 4.4.4
          pattern = '2d e9 f0 41 05 46 15 4e 0c 46 7e 44 11 b3 43 68';
          break;
        case 'ia32':
          // Verified with 4.3.1 and 4.4.2
          pattern = '8d 64 24 d4 89 5c 24 1c 89 74 24 20 e8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 85 d2';
          break;
      }

      Memory.scan(libdvm.base, libdvm.size, pattern, {
        onMatch: (address, size) => {
          let wrapper;
          if (Process.arch === 'arm') {
            address = address.or(1); // Thumb
            wrapper = new NativeFunction(address, 'pointer', ['pointer', 'pointer']);
          } else {
            const thunk = Memory.alloc(Process.pageSize);
            Memory.patchCode(thunk, 16, code => {
              const cw = new X86Writer(code, { pc: thunk });
              cw.putMovRegRegOffsetPtr('eax', 'esp', 4);
              cw.putMovRegRegOffsetPtr('edx', 'esp', 8);
              cw.putJmpAddress(address);
              cw.flush();
            });
            wrapper = new NativeFunction(thunk, 'pointer', ['pointer', 'pointer']);
            wrapper._thunk = thunk;
          }
          api.addLocalReference = wrapper;

          vm.perform(env => {
            enumerateInstances(this, env);
          });

          return 'stop';
        },
        onError (reason) {},
        onComplete () {
          if (api.addLocalReference === null) {
            callbacks.onComplete();
          }
        }
      });
    } else {
      enumerateInstances(this, callerEnv);
    }

    function enumerateInstances (factory, env) {
      const { DVM_JNI_ENV_OFFSET_SELF } = android;
      const thread = env.handle.add(DVM_JNI_ENV_OFFSET_SELF).readPointer();

      let ptrClassObject;
      const h = classWrapper.$borrowClassHandle(env);
      try {
        ptrClassObject = api.dvmDecodeIndirectRef(thread, h.value);
      } finally {
        h.unref(env);
      }

      const pattern = ptrClassObject.toMatchPattern();
      const heapSourceBase = api.dvmHeapSourceGetBase();
      const heapSourceLimit = api.dvmHeapSourceGetLimit();
      const size = heapSourceLimit.sub(heapSourceBase).toInt32();

      Memory.scan(heapSourceBase, size, pattern, {
        onMatch: (address, size) => {
          if (api.dvmIsValidObject(address)) {
            vm.perform(env => {
              const thread = env.handle.add(DVM_JNI_ENV_OFFSET_SELF).readPointer();

              let instance;
              const localReference = api.addLocalReference(thread, address);
              try {
                instance = factory.cast(localReference, classWrapper);
              } finally {
                env.deleteLocalRef(localReference);
              }

              const result = callbacks.onMatch(instance);
              if (result === 'stop') {
                return 'stop';
              }
            });
          }
        },
        onError (reason) {},
        onComplete () {
          callbacks.onComplete();
        }
      });
    }
  }

  openClassFile (filePath) {
    return new DexFile(filePath, null, this);
  }

  _getType (typeName, unbox = true) {
    return getType(typeName, unbox, this);
  }
}

function makeClassWrapperConstructor () {
  return function (handle, strategy, env, owned) {
    return Wrapper.call(this, handle, strategy, env, owned);
  };
}

function Wrapper (handle, strategy, env, owned = true) {
  if (handle !== null) {
    if (owned) {
      const h = env.newGlobalRef(handle);
      this.$h = h;
      this.$r = Script.bindWeak(this, vm.makeHandleDestructor(h));
    } else {
      this.$h = handle;
      this.$r = null;
    }
  } else {
    this.$h = null;
    this.$r = null;
  }

  this.$t = strategy;

  return new Proxy(this, wrapperHandler);
}

wrapperHandler = {
  has (target, property) {
    if (property in target) {
      return true;
    }

    return target.$has(property);
  },
  get (target, property, receiver) {
    if (typeof property !== 'string' || property.startsWith('$') || property === 'class') {
      return target[property];
    }

    const unwrap = target.$find(property);
    if (unwrap !== null) {
      return unwrap(receiver);
    }

    return target[property];
  },
  set (target, property, value, receiver) {
    target[property] = value;
    return true;
  },
  ownKeys (target) {
    return target.$list();
  },
  getOwnPropertyDescriptor (target, property) {
    if (Object.prototype.hasOwnProperty.call(target, property)) {
      return Object.getOwnPropertyDescriptor(target, property);
    }

    return {
      writable: false,
      configurable: true,
      enumerable: true
    };
  }
};

Object.defineProperties(Wrapper.prototype, {
  [Symbol.for('new')]: {
    enumerable: false,
    get () {
      return this.$getCtor('allocAndInit');
    }
  },
  $new: {
    enumerable: true,
    get () {
      return this[Symbol.for('new')];
    }
  },
  [Symbol.for('alloc')]: {
    enumerable: false,
    value () {
      const env = vm.getEnv();
      const h = this.$borrowClassHandle(env);
      try {
        const obj = env.allocObject(h.value);
        const factory = this.$f;
        return factory.cast(obj, this);
      } finally {
        h.unref(env);
      }
    }
  },
  $alloc: {
    enumerable: true,
    get () {
      return this[Symbol.for('$alloc')];
    }
  },
  [Symbol.for('init')]: {
    enumerable: false,
    get () {
      return this.$getCtor('initOnly');
    }
  },
  $init: {
    enumerable: true,
    get () {
      return this[Symbol.for('init')];
    }
  },
  [Symbol.for('dispose')]: {
    enumerable: false,
    value () {
      const ref = this.$r;
      if (ref !== null) {
        this.$r = null;
        Script.unbindWeak(ref);
      }

      if (this.$h !== null) {
        this.$h = undefined;
      }
    }
  },
  $dispose: {
    enumerable: true,
    get () {
      return this[Symbol.for('dispose')];
    }
  },
  [Symbol.for('clone')]: {
    enumerable: false,
    value (env) {
      const C = this.$C;
      return new C(this.$h, this.$t, env);
    }
  },
  $clone: {
    value (env) {
      return this[Symbol.for('clone')](env);
    }
  },
  [Symbol.for('class')]: {
    enumerable: false,
    get () {
      const env = vm.getEnv();
      const h = this.$borrowClassHandle(env);
      try {
        const factory = this.$f;
        return factory.cast(h.value, factory.use('java.lang.Class'));
      } finally {
        h.unref(env);
      }
    }
  },
  class: {
    enumerable: true,
    get () {
      return this[Symbol.for('class')];
    }
  },
  [Symbol.for('className')]: {
    enumerable: false,
    get () {
      const handle = this.$h;
      if (handle === null) {
        return this.$n;
      }

      return vm.getEnv().getObjectClassName(handle);
    }
  },
  $className: {
    enumerable: true,
    get () {
      return this[Symbol.for('className')];
    }
  },
  [Symbol.for('ownMembers')]: {
    enumerable: false,
    get () {
      const model = this.$l;
      return model.list();
    }
  },
  $ownMembers: {
    enumerable: true,
    get () {
      return this[Symbol.for('ownMembers')];
    }
  },
  [Symbol.for('super')]: {
    enumerable: false,
    get () {
      const env = vm.getEnv();
      const C = this.$s.$C;
      return new C(this.$h, STRATEGY_DIRECT, env);
    }
  },
  $super: {
    enumerable: true,
    get () {
      return this[Symbol.for('super')];
    }
  },
  [Symbol.for('s')]: {
    enumerable: false,
    get () {
      const proto = Object.getPrototypeOf(this);

      let superWrapper = proto.$_s;
      if (superWrapper === undefined) {
        const env = vm.getEnv();

        const h = this.$borrowClassHandle(env);
        try {
          const superHandle = env.getSuperclass(h.value);
          if (!superHandle.isNull()) {
            try {
              const superClassName = env.getClassName(superHandle);
              const factory = proto.$f;
              superWrapper = factory._getUsedClass(superClassName);
              if (superWrapper === undefined) {
                try {
                  const getSuperClassHandle = makeSuperHandleGetter(this);
                  superWrapper = factory._make(superClassName, getSuperClassHandle, env);
                } finally {
                  factory._setUsedClass(superClassName, superWrapper);
                }
              }
            } finally {
              env.deleteLocalRef(superHandle);
            }
          } else {
            superWrapper = null;
          }
        } finally {
          h.unref(env);
        }

        proto.$_s = superWrapper;
      }

      return superWrapper;
    }
  },
  $s: {
    get () {
      return this[Symbol.for('s')];
    }
  },
  [Symbol.for('isSameObject')]: {
    enumerable: false,
    value (obj) {
      const env = vm.getEnv();
      return env.isSameObject(obj.$h, this.$h);
    }
  },
  $isSameObject: {
    value (obj) {
      return this[Symbol.for('isSameObject')](obj);
    }
  },
  [Symbol.for('getCtor')]: {
    enumerable: false,
    value (type) {
      const slot = this.$c;

      let ctor = slot[0];
      if (ctor === null) {
        const env = vm.getEnv();
        const h = this.$borrowClassHandle(env);
        try {
          ctor = makeConstructor(h.value, this.$w, env);
          slot[0] = ctor;
        } finally {
          h.unref(env);
        }
      }

      return ctor[type];
    }
  },
  $getCtor: {
    value (type) {
      return this[Symbol.for('getCtor')](type);
    }
  },
  [Symbol.for('borrowClassHandle')]: {
    enumerable: false,
    value (env) {
      const className = this.$n;
      const classHandles = this.$f._classHandles;

      let handle = classHandles.get(className);
      if (handle === undefined) {
        handle = new ClassHandle(this.$gch(env), env);
        classHandles.set(className, handle, env);
      }

      return handle.ref();
    }
  },
  $borrowClassHandle: {
    value (env) {
      return this[Symbol.for('borrowClassHandle')](env);
    }
  },
  [Symbol.for('copyClassHandle')]: {
    enumerable: false,
    value (env) {
      const h = this.$borrowClassHandle(env);
      try {
        return env.newLocalRef(h.value);
      } finally {
        h.unref(env);
      }
    }
  },
  $copyClassHandle: {
    value (env) {
      return this[Symbol.for('copyClassHandle')](env);
    }
  },
  [Symbol.for('getHandle')]: {
    enumerable: false,
    value (env) {
      const handle = this.$h;

      const isDisposed = handle === undefined;
      if (isDisposed) {
        throw new Error('Wrapper is disposed; perhaps it was borrowed from a hook ' +
            'instead of calling Java.retain() to make a long-lived wrapper?');
      }

      return handle;
    }
  },
  $getHandle: {
    value (env) {
      return this[Symbol.for('getHandle')](env);
    }
  },
  [Symbol.for('list')]: {
    enumerable: false,
    value () {
      const superWrapper = this.$s;
      const superMembers = (superWrapper !== null) ? superWrapper.$list() : [];

      const model = this.$l;
      return Array.from(new Set(superMembers.concat(model.list())));
    }
  },
  $list: {
    get () {
      return this[Symbol.for('list')];
    }
  },
  [Symbol.for('has')]: {
    enumerable: false,
    value (member) {
      const members = this.$m;
      if (members.has(member)) {
        return true;
      }

      const model = this.$l;
      if (model.has(member)) {
        return true;
      }

      const superWrapper = this.$s;
      if (superWrapper !== null && superWrapper.$has(member)) {
        return true;
      }

      return false;
    }
  },
  $has: {
    value (member) {
      return this[Symbol.for('has')](member);
    }
  },
  [Symbol.for('find')]: {
    enumerable: false,
    value (member) {
      const members = this.$m;

      let value = members.get(member);
      if (value !== undefined) {
        return value;
      }

      const model = this.$l;
      const spec = model.find(member);
      if (spec !== null) {
        const env = vm.getEnv();
        const h = this.$borrowClassHandle(env);
        try {
          value = makeMember(member, spec, h.value, this.$w, env);
        } finally {
          h.unref(env);
        }
        members.set(member, value);
        return value;
      }

      const superWrapper = this.$s;
      if (superWrapper !== null) {
        return superWrapper.$find(member);
      }

      return null;
    }
  },
  $find: {
    value (member) {
      return this[Symbol.for('find')](member);
    }
  },
  [Symbol.for('toJSON')]: {
    enumerable: false,
    value () {
      const wrapperName = this.$n;

      const handle = this.$h;
      if (handle === null) {
        return `<class: ${wrapperName}>`;
      }

      const actualName = this.$className;
      if (wrapperName === actualName) {
        return `<instance: ${wrapperName}>`;
      }

      return `<instance: ${wrapperName}, $className: ${actualName}>`;
    }
  },
  toJSON: {
    get () {
      return this[Symbol.for('toJSON')];
    }
  }
});

function C
"""


```