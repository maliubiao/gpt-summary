Response:
### 功能归纳（第2部分）

#### **1. 类句柄管理**
- **功能**：`ClassHandle` 管理 JNI 类引用，通过引用计数（`ref/unref`）防止内存泄漏。`releaseClassHandle` 释放全局引用。
- **常见错误**：未正确调用 `unref` 导致内存泄漏；在多线程中误删引用导致崩溃。
- **调用链示例**：`Java.use()` → 获取类句柄 → `ClassHandle.ref()` → 使用后调用 `releaseClassHandle()`。

#### **2. 类加载与查找**
- **功能**：`makeBasicClassHandleGetter` 通过类名查找类；`makeLoaderClassHandleGetter` 通过类加载器动态加载类。
- **假设输入**：`makeLoaderClassHandleGetter("com.example.MyClass", loader)` → 返回类句柄。
- **调试示例**：`lldb -p [PID] -o "br set -n JNI_FindClass"` 断点跟踪类查找。

#### **3. 方法构造与重载处理**
- **功能**：`makeMethod` 解析方法签名，生成方法实例；`makeMethodDispatcher` 处理重载方法选择。
- **执行顺序**：解析参数类型 → 匹配重载 → 调用 `jniCall`。
- **常见错误**：参数类型不匹配导致 `throwOverloadError`；未处理 `VarArgs`。

#### **4. 字段访问**
- **功能**：`makeFieldFromSpec` 生成字段访问器，支持静态/实例字段的读写。
- **示例错误**：访问实例字段未提供对象实例 → 抛出 `Cannot access instance field`。

#### **5. Dex 文件动态加载**
- **功能**：`DexFile` 类支持从缓冲区加载 Dex 文件，注入新类到当前类加载器。
- **调用链**：`DexFile.fromBuffer()` → 创建临时文件 → `load()` 使用 `DexClassLoader` 加载。
- **调试指令**：`lldb -o "watch set var dalvik.system.DexClassLoader"` 监控类加载。

#### **6. 方法替换与Hook**
- **功能**：`methodPrototype.implementation` 支持替换方法实现，通过 `NativeCallback` 注入。
- **示例**：`targetMethod.implementation = function() {...}` → 生成桩代码并替换 JNI 方法ID。
- **错误**：替换构造函数未调用 `$init` → 导致实例化失败。

#### **7. 线程安全管理**
- **功能**：`ignore/unignore` 防止线程冲突（如死锁），通过线程ID管理忽略状态。
- **执行顺序**：调用 JNI 前 `ignore(tid)` → 执行操作 → `unignore(tid)`。
- **错误**：未配对调用导致线程永久忽略或提前唤醒。

#### **8. 工厂缓存管理**
- **功能**：`getFactoryCache` 缓存类加载器与工厂的映射，避免重复初始化。
- **逻辑推理**：新类加载器触发 `addFactoryToCache` → 更新 `HashMap` 映射。

#### **9. 类型转换与JNI交互**
- **功能**：`toJni/fromJni` 处理 JS 与 Java 类型转换（如对象、基本类型）。
- **假设输入**：JS 字符串 → `env.newStringUtf()` → 转为 `jstring`。

#### **10. 异常处理**
- **功能**：`env.throwIfExceptionPending()` 检查 JNI 异常，转换为 JS 异常。
- **调试示例**：`lldb -o "expr *(void**)env->exception"` 查看当前异常对象。

---

### **执行顺序示例（10步）**
1. **初始化类工厂**：`ClassFactory` 创建，初始化缓存（`getFactoryCache`）。
2. **加载目标类**：`Java.use("MyClass")` 调用 `makeBasicClassHandleGetter` 获取类句柄。
3. **解析方法签名**：`makeMethodFromSpec` 解析 `spec` 参数，提取方法ID和类型。
4. **生成方法分发器**：`makeMethodDispatcher` 收集重载方法，生成调用逻辑。
5. **处理构造函数**：`makeConstructor` 收集所有构造函数，生成 `$init` 和 `$new`。
6. **Hook方法替换**：用户设置 `implementation` → 生成桩代码并替换方法指针。
7. **字段访问**：`MyClass.field.value = 42` → 调用 `setValue` JNI 函数。
8. **Dex加载**：`DexFile.fromBuffer()` 写入临时文件 → 调用 `load()` 加载类。
9. **线程安全操作**：JNI 调用前 `ignore(tid)`，完成后 `unignore(tid)`。
10. **资源释放**：`ClassHandle.unref()` 引用计数归零 → 删除全局引用。

---

### **调试线索（调用链示例）**
1. **用户调用**：`Java.perform(() => { ... })` 触发类工厂初始化。
2. **类查找**：`Java.use("com.example.Target")` → `findClass` JNI 调用。
3. **方法构造**：解析 `Target.method` 的签名 → `makeMethodFromSpec`。
4. **重载选择**：用户调用 `method.overload('int').implement(...)` → `overload()` 匹配。
5. **JNI调用**：`jniCall` 调用 `CallObjectMethodV`，传递参数和返回值。
6. **异常检查**：`env.throwIfExceptionPending()` 发现异常 → 抛出 JS 错误。
7. **Dex注入**：`DexFile.load()` 调用 `DexClassLoader.loadClass` → 类加载事件。
8. **线程忽略**：在 JNI 回调中 `ignore(tid)`，避免重入。
9. **缓存管理**：新类加载器触发 `addFactoryToCache`，更新工厂映射。
10. **资源回收**：`Script.unload()` 触发 `releaseClassHandle` 释放所有引用。

---

### **总结**
该模块是 Frida 的 Java 层动态插桩核心，负责 Java 类的加载、方法/字段的动态访问、Dex 注入、线程安全及资源管理。通过 JNI 与 JS 类型转换，实现 Java 与 JS 的无缝交互，并提供了方法替换、重载处理等高级调试功能。
### 提示词
```
这是目录为frida/subprojects/frida-java-bridge/lib/class-factory.js的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
请列举一下它的功能, 给出执行顺序(不是行号顺序), 建议分10步,
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明调用链如何一步步的到达这里，作为调试线索，建议10步，
请用中文回复。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```javascript
lassHandle (value, env) {
  this.value = env.newGlobalRef(value);
  env.deleteLocalRef(value);

  this.refs = 1;
}

ClassHandle.prototype.ref = function () {
  this.refs++;
  return this;
};

ClassHandle.prototype.unref = function (env) {
  if (--this.refs === 0) {
    env.deleteGlobalRef(this.value);
  }
};

function releaseClassHandle (handle, env) {
  handle.unref(env);
}

function makeBasicClassHandleGetter (className) {
  const canonicalClassName = className.replace(/\./g, '/');

  return function (env) {
    const tid = getCurrentThreadId();
    ignore(tid);
    try {
      return env.findClass(canonicalClassName);
    } finally {
      unignore(tid);
    }
  };
}

function makeLoaderClassHandleGetter (className, usedLoader, callerEnv) {
  if (cachedLoaderMethod === null) {
    cachedLoaderInvoke = callerEnv.vaMethod('pointer', ['pointer']);
    cachedLoaderMethod = usedLoader.loadClass.overload('java.lang.String').handle;
  }

  callerEnv = null;

  return function (env) {
    const classNameValue = env.newStringUtf(className);

    const tid = getCurrentThreadId();
    ignore(tid);
    try {
      const result = cachedLoaderInvoke(env.handle, usedLoader.$h, cachedLoaderMethod, classNameValue);
      env.throwIfExceptionPending();
      return result;
    } finally {
      unignore(tid);
      env.deleteLocalRef(classNameValue);
    }
  };
}

function makeSuperHandleGetter (classWrapper) {
  return function (env) {
    const h = classWrapper.$borrowClassHandle(env);
    try {
      return env.getSuperclass(h.value);
    } finally {
      h.unref(env);
    }
  };
}

function makeConstructor (classHandle, classWrapper, env) {
  const { $n: className, $f: factory } = classWrapper;
  const methodName = basename(className);
  const Class = env.javaLangClass();
  const Constructor = env.javaLangReflectConstructor();
  const invokeObjectMethodNoArgs = env.vaMethod('pointer', []);
  const invokeUInt8MethodNoArgs = env.vaMethod('uint8', []);

  const jsCtorMethods = [];
  const jsInitMethods = [];
  const jsRetType = factory._getType(className, false);
  const jsVoidType = factory._getType('void', false);

  const constructors = invokeObjectMethodNoArgs(env.handle, classHandle, Class.getDeclaredConstructors);
  try {
    const n = env.getArrayLength(constructors);

    if (n !== 0) {
      for (let i = 0; i !== n; i++) {
        let methodId, types;
        const constructor = env.getObjectArrayElement(constructors, i);
        try {
          methodId = env.fromReflectedMethod(constructor);
          types = invokeObjectMethodNoArgs(env.handle, constructor, Constructor.getGenericParameterTypes);
        } finally {
          env.deleteLocalRef(constructor);
        }

        let jsArgTypes;
        try {
          jsArgTypes = readTypeNames(env, types).map(name => factory._getType(name));
        } finally {
          env.deleteLocalRef(types);
        }

        jsCtorMethods.push(makeMethod(methodName, classWrapper, CONSTRUCTOR_METHOD, methodId, jsRetType, jsArgTypes, env));
        jsInitMethods.push(makeMethod(methodName, classWrapper, INSTANCE_METHOD, methodId, jsVoidType, jsArgTypes, env));
      }
    } else {
      const isInterface = invokeUInt8MethodNoArgs(env.handle, classHandle, Class.isInterface);
      if (isInterface) {
        throw new Error('cannot instantiate an interface');
      }

      const defaultClass = env.javaLangObject();
      const defaultConstructor = env.getMethodId(defaultClass, '<init>', '()V');

      jsCtorMethods.push(makeMethod(methodName, classWrapper, CONSTRUCTOR_METHOD, defaultConstructor, jsRetType, [], env));
      jsInitMethods.push(makeMethod(methodName, classWrapper, INSTANCE_METHOD, defaultConstructor, jsVoidType, [], env));
    }
  } finally {
    env.deleteLocalRef(constructors);
  }

  if (jsInitMethods.length === 0) {
    throw new Error('no supported overloads');
  }

  return {
    allocAndInit: makeMethodDispatcher(jsCtorMethods),
    initOnly: makeMethodDispatcher(jsInitMethods)
  };
}

function makeMember (name, spec, classHandle, classWrapper, env) {
  if (spec.startsWith('m')) {
    return makeMethodFromSpec(name, spec, classHandle, classWrapper, env);
  }

  return makeFieldFromSpec(name, spec, classHandle, classWrapper, env);
}

function makeMethodFromSpec (name, spec, classHandle, classWrapper, env) {
  const { $f: factory } = classWrapper;
  const overloads = spec.split(':').slice(1);

  const Method = env.javaLangReflectMethod();
  const invokeObjectMethodNoArgs = env.vaMethod('pointer', []);
  const invokeUInt8MethodNoArgs = env.vaMethod('uint8', []);

  const methods = overloads.map(params => {
    const type = (params[0] === 's') ? STATIC_METHOD : INSTANCE_METHOD;
    const methodId = ptr(params.substr(1));

    let jsRetType;
    const jsArgTypes = [];
    const handle = env.toReflectedMethod(classHandle, methodId, (type === STATIC_METHOD) ? 1 : 0);
    try {
      const isVarArgs = !!invokeUInt8MethodNoArgs(env.handle, handle, Method.isVarArgs);

      const retType = invokeObjectMethodNoArgs(env.handle, handle, Method.getGenericReturnType);
      env.throwIfExceptionPending();
      try {
        jsRetType = factory._getType(env.getTypeName(retType));
      } finally {
        env.deleteLocalRef(retType);
      }

      const argTypes = invokeObjectMethodNoArgs(env.handle, handle, Method.getParameterTypes);
      try {
        const n = env.getArrayLength(argTypes);

        for (let i = 0; i !== n; i++) {
          const t = env.getObjectArrayElement(argTypes, i);

          let argClassName;
          try {
            argClassName = (isVarArgs && i === n - 1) ? env.getArrayTypeName(t) : env.getTypeName(t);
          } finally {
            env.deleteLocalRef(t);
          }

          const argType = factory._getType(argClassName);
          jsArgTypes.push(argType);
        }
      } finally {
        env.deleteLocalRef(argTypes);
      }
    } catch (e) {
      return null;
    } finally {
      env.deleteLocalRef(handle);
    }

    return makeMethod(name, classWrapper, type, methodId, jsRetType, jsArgTypes, env);
  })
    .filter(m => m !== null);

  if (methods.length === 0) {
    throw new Error('No supported overloads');
  }

  if (name === 'valueOf') {
    ensureDefaultValueOfImplemented(methods);
  }

  const result = makeMethodDispatcher(methods);

  return function (receiver) {
    return result;
  };
}

function makeMethodDispatcher (overloads) {
  const m = makeMethodDispatcherCallable();
  Object.setPrototypeOf(m, dispatcherPrototype);
  m._o = overloads;
  return m;
}

function makeMethodDispatcherCallable () {
  const m = function () {
    return m.invoke(this, arguments);
  };
  return m;
}

dispatcherPrototype = Object.create(Function.prototype, {
  overloads: {
    enumerable: true,
    get () {
      return this._o;
    }
  },
  overload: {
    value (...args) {
      const overloads = this._o;

      const numArgs = args.length;
      const signature = args.join(':');

      for (let i = 0; i !== overloads.length; i++) {
        const method = overloads[i];
        const { argumentTypes } = method;

        if (argumentTypes.length !== numArgs) {
          continue;
        }

        const s = argumentTypes.map(t => t.className).join(':');
        if (s === signature) {
          return method;
        }
      }

      throwOverloadError(this.methodName, this.overloads, 'specified argument types do not match any of:');
    }
  },
  methodName: {
    enumerable: true,
    get () {
      return this._o[0].methodName;
    }
  },
  holder: {
    enumerable: true,
    get () {
      return this._o[0].holder;
    }
  },
  type: {
    enumerable: true,
    get () {
      return this._o[0].type;
    }
  },
  handle: {
    enumerable: true,
    get () {
      throwIfDispatcherAmbiguous(this);
      return this._o[0].handle;
    }
  },
  implementation: {
    enumerable: true,
    get () {
      throwIfDispatcherAmbiguous(this);
      return this._o[0].implementation;
    },
    set (fn) {
      throwIfDispatcherAmbiguous(this);
      this._o[0].implementation = fn;
    }
  },
  returnType: {
    enumerable: true,
    get () {
      throwIfDispatcherAmbiguous(this);
      return this._o[0].returnType;
    }
  },
  argumentTypes: {
    enumerable: true,
    get () {
      throwIfDispatcherAmbiguous(this);
      return this._o[0].argumentTypes;
    }
  },
  canInvokeWith: {
    enumerable: true,
    get (args) {
      throwIfDispatcherAmbiguous(this);
      return this._o[0].canInvokeWith;
    }
  },
  clone: {
    enumerable: true,
    value (options) {
      throwIfDispatcherAmbiguous(this);
      return this._o[0].clone(options);
    }
  },
  invoke: {
    value (receiver, args) {
      const overloads = this._o;

      const isInstance = receiver.$h !== null;

      for (let i = 0; i !== overloads.length; i++) {
        const method = overloads[i];

        if (!method.canInvokeWith(args)) {
          continue;
        }

        if (method.type === INSTANCE_METHOD && !isInstance) {
          const name = this.methodName;

          if (name === 'toString') {
            return `<class: ${receiver.$n}>`;
          }

          throw new Error(name + ': cannot call instance method without an instance');
        }

        return method.apply(receiver, args);
      }

      if (this.methodName === 'toString') {
        return `<class: ${receiver.$n}>`;
      }

      throwOverloadError(this.methodName, this.overloads, 'argument types do not match any of:');
    }
  }
});

function makeOverloadId (name, returnType, argumentTypes) {
  return `${returnType.className} ${name}(${argumentTypes.map(t => t.className).join(', ')})`;
}

function throwIfDispatcherAmbiguous (dispatcher) {
  const methods = dispatcher._o;
  if (methods.length > 1) {
    throwOverloadError(methods[0].methodName, methods, 'has more than one overload, use .overload(<signature>) to choose from:');
  }
}

function throwOverloadError (name, methods, message) {
  const methodsSortedByArity = methods.slice().sort((a, b) => a.argumentTypes.length - b.argumentTypes.length);
  const overloads = methodsSortedByArity.map(m => {
    const argTypes = m.argumentTypes;
    if (argTypes.length > 0) {
      return '.overload(\'' + m.argumentTypes.map(t => t.className).join('\', \'') + '\')';
    } else {
      return '.overload()';
    }
  });
  throw new Error(`${name}(): ${message}\n\t${overloads.join('\n\t')}`);
}

function makeMethod (methodName, classWrapper, type, methodId, retType, argTypes, env, invocationOptions) {
  const rawRetType = retType.type;
  const rawArgTypes = argTypes.map((t) => t.type);

  if (env === null) {
    env = vm.getEnv();
  }

  let callVirtually, callDirectly;
  if (type === INSTANCE_METHOD) {
    callVirtually = env.vaMethod(rawRetType, rawArgTypes, invocationOptions);
    callDirectly = env.nonvirtualVaMethod(rawRetType, rawArgTypes, invocationOptions);
  } else if (type === STATIC_METHOD) {
    callVirtually = env.staticVaMethod(rawRetType, rawArgTypes, invocationOptions);
    callDirectly = callVirtually;
  } else {
    callVirtually = env.constructor(rawArgTypes, invocationOptions);
    callDirectly = callVirtually;
  }

  return makeMethodInstance([methodName, classWrapper, type, methodId, retType, argTypes, callVirtually, callDirectly]);
}

function makeMethodInstance (params) {
  const m = makeMethodCallable();
  Object.setPrototypeOf(m, methodPrototype);
  m._p = params;
  return m;
}

function makeMethodCallable () {
  const m = function () {
    return m.invoke(this, arguments);
  };
  return m;
}

methodPrototype = Object.create(Function.prototype, {
  methodName: {
    enumerable: true,
    get () {
      return this._p[0];
    }
  },
  holder: {
    enumerable: true,
    get () {
      return this._p[1];
    }
  },
  type: {
    enumerable: true,
    get () {
      return this._p[2];
    }
  },
  handle: {
    enumerable: true,
    get () {
      return this._p[3];
    }
  },
  implementation: {
    enumerable: true,
    get () {
      const replacement = this._r;
      return (replacement !== undefined) ? replacement : null;
    },
    set (fn) {
      const params = this._p;
      const holder = params[1];
      const type = params[2];

      if (type === CONSTRUCTOR_METHOD) {
        throw new Error('Reimplementing $new is not possible; replace implementation of $init instead');
      }

      const existingReplacement = this._r;
      if (existingReplacement !== undefined) {
        holder.$f._patchedMethods.delete(this);

        const mangler = existingReplacement._m;
        mangler.revert(vm);

        this._r = undefined;
      }

      if (fn !== null) {
        const [methodName, classWrapper, type, methodId, retType, argTypes] = params;

        const replacement = implement(methodName, classWrapper, type, retType, argTypes, fn, this);
        const mangler = makeMethodMangler(methodId);
        replacement._m = mangler;
        this._r = replacement;

        mangler.replace(replacement, type === INSTANCE_METHOD, argTypes, vm, api);

        holder.$f._patchedMethods.add(this);
      }
    }
  },
  returnType: {
    enumerable: true,
    get () {
      return this._p[4];
    }
  },
  argumentTypes: {
    enumerable: true,
    get () {
      return this._p[5];
    }
  },
  canInvokeWith: {
    enumerable: true,
    value (args) {
      const argTypes = this._p[5];

      if (args.length !== argTypes.length) {
        return false;
      }

      return argTypes.every((t, i) => {
        return t.isCompatible(args[i]);
      });
    }
  },
  clone: {
    enumerable: true,
    value (options) {
      const params = this._p.slice(0, 6);
      return makeMethod(...params, null, options);
    }
  },
  invoke: {
    value (receiver, args) {
      const env = vm.getEnv();

      const params = this._p;
      const type = params[2];
      const retType = params[4];
      const argTypes = params[5];

      const replacement = this._r;

      const isInstanceMethod = type === INSTANCE_METHOD;
      const numArgs = args.length;

      const frameCapacity = 2 + numArgs;
      env.pushLocalFrame(frameCapacity);

      let borrowedHandle = null;
      try {
        let jniThis;
        if (isInstanceMethod) {
          jniThis = receiver.$getHandle();
        } else {
          borrowedHandle = receiver.$borrowClassHandle(env);
          jniThis = borrowedHandle.value;
        }

        let methodId;
        let strategy = receiver.$t;
        if (replacement === undefined) {
          methodId = params[3];
        } else {
          const mangler = replacement._m;
          methodId = mangler.resolveTarget(receiver, isInstanceMethod, env, api);

          if (isArtVm) {
            const pendingCalls = replacement._c;
            if (pendingCalls.has(getCurrentThreadId())) {
              strategy = STRATEGY_DIRECT;
            }
          }
        }

        const jniArgs = [
          env.handle,
          jniThis,
          methodId
        ];
        for (let i = 0; i !== numArgs; i++) {
          jniArgs.push(argTypes[i].toJni(args[i], env));
        }

        let jniCall;
        if (strategy === STRATEGY_VIRTUAL) {
          jniCall = params[6];
        } else {
          jniCall = params[7];

          if (isInstanceMethod) {
            jniArgs.splice(2, 0, receiver.$copyClassHandle(env));
          }
        }

        const jniRetval = jniCall.apply(null, jniArgs);
        env.throwIfExceptionPending();

        return retType.fromJni(jniRetval, env, true);
      } finally {
        if (borrowedHandle !== null) {
          borrowedHandle.unref(env);
        }

        env.popLocalFrame(NULL);
      }
    }
  },
  toString: {
    enumerable: true,
    value () {
      return `function ${this.methodName}(${this.argumentTypes.map(t => t.className).join(', ')}): ${this.returnType.className}`;
    }
  }
});

function implement (methodName, classWrapper, type, retType, argTypes, handler, fallback = null) {
  const pendingCalls = new Set();

  const f = makeMethodImplementation([methodName, classWrapper, type, retType, argTypes, handler, fallback, pendingCalls]);

  const impl = new NativeCallback(f, retType.type, ['pointer', 'pointer'].concat(argTypes.map(t => t.type)));
  impl._c = pendingCalls;

  return impl;
}

function makeMethodImplementation (params) {
  return function () {
    return handleMethodInvocation(arguments, params);
  };
}

function handleMethodInvocation (jniArgs, params) {
  const env = new Env(jniArgs[0], vm);

  const [methodName, classWrapper, type, retType, argTypes, handler, fallback, pendingCalls] = params;

  const ownedObjects = [];

  let self;
  if (type === INSTANCE_METHOD) {
    const C = classWrapper.$C;
    self = new C(jniArgs[1], STRATEGY_VIRTUAL, env, false);
  } else {
    self = classWrapper;
  }

  const tid = getCurrentThreadId();

  env.pushLocalFrame(3);
  let haveFrame = true;

  vm.link(tid, env);

  try {
    pendingCalls.add(tid);

    let fn;
    if (fallback === null || !ignoredThreads.has(tid)) {
      fn = handler;
    } else {
      fn = fallback;
    }

    const args = [];
    const numArgs = jniArgs.length - 2;
    for (let i = 0; i !== numArgs; i++) {
      const t = argTypes[i];

      const value = t.fromJni(jniArgs[2 + i], env, false);
      args.push(value);

      ownedObjects.push(value);
    }

    const retval = fn.apply(self, args);

    if (!retType.isCompatible(retval)) {
      throw new Error(`Implementation for ${methodName} expected return value compatible with ${retType.className}`);
    }

    let jniRetval = retType.toJni(retval, env);

    if (retType.type === 'pointer') {
      jniRetval = env.popLocalFrame(jniRetval);
      haveFrame = false;

      ownedObjects.push(retval);
    }

    return jniRetval;
  } catch (e) {
    const jniException = e.$h;
    if (jniException !== undefined) {
      env.throw(jniException);
    } else {
      Script.nextTick(() => { throw e; });
    }

    return retType.defaultValue;
  } finally {
    vm.unlink(tid);

    if (haveFrame) {
      env.popLocalFrame(NULL);
    }

    pendingCalls.delete(tid);

    ownedObjects.forEach(obj => {
      if (obj === null) {
        return;
      }

      const dispose = obj.$dispose;
      if (dispose !== undefined) {
        dispose.call(obj);
      }
    });
  }
}

function ensureDefaultValueOfImplemented (methods) {
  const { holder, type } = methods[0];

  const hasDefaultValueOf = methods.some(m => m.type === type && m.argumentTypes.length === 0);
  if (hasDefaultValueOf) {
    return;
  }

  methods.push(makeValueOfMethod([holder, type]));
}

function makeValueOfMethod (params) {
  const m = makeValueOfCallable();
  Object.setPrototypeOf(m, valueOfPrototype);
  m._p = params;
  return m;
}

function makeValueOfCallable () {
  const m = function () {
    return this;
  };
  return m;
}

valueOfPrototype = Object.create(Function.prototype, {
  methodName: {
    enumerable: true,
    get () {
      return 'valueOf';
    }
  },
  holder: {
    enumerable: true,
    get () {
      return this._p[0];
    }
  },
  type: {
    enumerable: true,
    get () {
      return this._p[1];
    }
  },
  handle: {
    enumerable: true,
    get () {
      return NULL;
    }
  },
  implementation: {
    enumerable: true,
    get () {
      return null;
    },
    set (fn) {
    }
  },
  returnType: {
    enumerable: true,
    get () {
      const classWrapper = this.holder;
      return classWrapper.$f.use(classWrapper.$n);
    }
  },
  argumentTypes: {
    enumerable: true,
    get () {
      return [];
    }
  },
  canInvokeWith: {
    enumerable: true,
    value (args) {
      return args.length === 0;
    }
  },
  clone: {
    enumerable: true,
    value (options) {
      throw new Error('Invalid operation');
    }
  }
});

function makeFieldFromSpec (name, spec, classHandle, classWrapper, env) {
  const type = (spec[2] === 's') ? STATIC_FIELD : INSTANCE_FIELD;
  const id = ptr(spec.substr(3));
  const { $f: factory } = classWrapper;

  let fieldType;
  const field = env.toReflectedField(classHandle, id, (type === STATIC_FIELD) ? 1 : 0);
  try {
    fieldType = env.vaMethod('pointer', [])(env.handle, field, env.javaLangReflectField().getGenericType);
    env.throwIfExceptionPending();
  } finally {
    env.deleteLocalRef(field);
  }

  let rtype;
  try {
    rtype = factory._getType(env.getTypeName(fieldType));
  } finally {
    env.deleteLocalRef(fieldType);
  }

  let getValue, setValue;
  const rtypeJni = rtype.type;
  if (type === STATIC_FIELD) {
    getValue = env.getStaticField(rtypeJni);
    setValue = env.setStaticField(rtypeJni);
  } else {
    getValue = env.getField(rtypeJni);
    setValue = env.setField(rtypeJni);
  }

  return makeFieldFromParams([type, rtype, id, getValue, setValue]);
}

function makeFieldFromParams (params) {
  return function (receiver) {
    return new Field([receiver].concat(params));
  };
}

function Field (params) {
  this._p = params;
}

Object.defineProperties(Field.prototype, {
  value: {
    enumerable: true,
    get () {
      const [holder, type, rtype, id, getValue] = this._p;

      const env = vm.getEnv();
      env.pushLocalFrame(4);

      let borrowedHandle = null;
      try {
        let jniThis;
        if (type === INSTANCE_FIELD) {
          jniThis = holder.$getHandle();
          if (jniThis === null) {
            throw new Error('Cannot access an instance field without an instance');
          }
        } else {
          borrowedHandle = holder.$borrowClassHandle(env);
          jniThis = borrowedHandle.value;
        }

        const jniRetval = getValue(env.handle, jniThis, id);
        env.throwIfExceptionPending();

        return rtype.fromJni(jniRetval, env, true);
      } finally {
        if (borrowedHandle !== null) {
          borrowedHandle.unref(env);
        }

        env.popLocalFrame(NULL);
      }
    },
    set (value) {
      const [holder, type, rtype, id, , setValue] = this._p;

      const env = vm.getEnv();
      env.pushLocalFrame(4);

      let borrowedHandle = null;
      try {
        let jniThis;
        if (type === INSTANCE_FIELD) {
          jniThis = holder.$getHandle();
          if (jniThis === null) {
            throw new Error('Cannot access an instance field without an instance');
          }
        } else {
          borrowedHandle = holder.$borrowClassHandle(env);
          jniThis = borrowedHandle.value;
        }

        if (!rtype.isCompatible(value)) {
          throw new Error(`Expected value compatible with ${rtype.className}`);
        }
        const jniValue = rtype.toJni(value, env);

        setValue(env.handle, jniThis, id, jniValue);
        env.throwIfExceptionPending();
      } finally {
        if (borrowedHandle !== null) {
          borrowedHandle.unref(env);
        }

        env.popLocalFrame(NULL);
      }
    }
  },
  holder: {
    enumerable: true,
    get () {
      return this._p[0];
    }
  },
  fieldType: {
    enumerable: true,
    get () {
      return this._p[1];
    }
  },
  fieldReturnType: {
    enumerable: true,
    get () {
      return this._p[2];
    }
  },
  toString: {
    enumerable: true,
    value () {
      const inlineString = `Java.Field{holder: ${this.holder}, fieldType: ${this.fieldType}, fieldReturnType: ${this.fieldReturnType}, value: ${this.value}}`;
      if (inlineString.length < 200) {
        return inlineString;
      }
      const multilineString = `Java.Field{
\tholder: ${this.holder},
\tfieldType: ${this.fieldType},
\tfieldReturnType: ${this.fieldReturnType},
\tvalue: ${this.value},
}`;
      return multilineString.split('\n').map(l => l.length > 200 ? l.slice(0, l.indexOf(' ') + 1) + '...,' : l).join('\n');
    }
  }
});

class DexFile {
  static fromBuffer (buffer, factory) {
    const fileValue = createTemporaryDex(factory);
    const filePath = fileValue.getCanonicalPath().toString();

    const file = new File(filePath, 'w');
    file.write(buffer.buffer);
    file.close();
    setReadOnlyDex(filePath, factory);

    return new DexFile(filePath, fileValue, factory);
  }

  constructor (path, file, factory) {
    this.path = path;
    this.file = file;

    this._factory = factory;
  }

  load () {
    const { _factory: factory } = this;
    const { codeCacheDir } = factory;
    const DexClassLoader = factory.use('dalvik.system.DexClassLoader');
    const JFile = factory.use('java.io.File');

    let file = this.file;
    if (file === null) {
      file = factory.use('java.io.File').$new(this.path);
    }
    if (!file.exists()) {
      throw new Error('File not found');
    }

    JFile.$new(codeCacheDir).mkdirs();

    factory.loader = DexClassLoader.$new(file.getCanonicalPath(), codeCacheDir, null, factory.loader);

    vm.preventDetachDueToClassLoader();
  }

  getClassNames () {
    const { _factory: factory } = this;
    const DexFile = factory.use('dalvik.system.DexFile');

    const optimizedDex = createTemporaryDex(factory);
    const dx = DexFile.loadDex(this.path, optimizedDex.getCanonicalPath(), 0);

    const classNames = [];
    const enumeratorClassNames = dx.entries();
    while (enumeratorClassNames.hasMoreElements()) {
      classNames.push(enumeratorClassNames.nextElement().toString());
    }
    return classNames;
  }
}

function createTemporaryDex (factory) {
  const { cacheDir, tempFileNaming } = factory;
  const JFile = factory.use('java.io.File');

  const cacheDirValue = JFile.$new(cacheDir);
  cacheDirValue.mkdirs();

  return JFile.createTempFile(tempFileNaming.prefix, tempFileNaming.suffix + '.dex', cacheDirValue);
}

function setReadOnlyDex (filePath, factory) {
  const JFile = factory.use('java.io.File');
  const file = JFile.$new(filePath);
  file.setWritable(false, false);
}

function getFactoryCache () {
  switch (factoryCache.state) {
    case 'empty': {
      factoryCache.state = 'pending';

      const defaultFactory = factoryCache.factories[0];

      const HashMap = defaultFactory.use('java.util.HashMap');
      const Integer = defaultFactory.use('java.lang.Integer');

      factoryCache.loaders = HashMap.$new();
      factoryCache.Integer = Integer;

      const loader = defaultFactory.loader;
      if (loader !== null) {
        addFactoryToCache(defaultFactory, loader);
      }

      factoryCache.state = 'ready';

      return factoryCache;
    }
    case 'pending':
      do {
        Thread.sleep(0.05);
      } while (factoryCache.state === 'pending');
      return factoryCache;
    case 'ready':
      return factoryCache;
  }
}

function addFactoryToCache (factory, loader) {
  const { factories, loaders, Integer } = factoryCache;

  const index = Integer.$new(factories.indexOf(factory));
  loaders.put(loader, index);

  for (let l = loader.getParent(); l !== null; l = l.getParent()) {
    if (loaders.containsKey(l)) {
      break;
    }

    loaders.put(l, index);
  }
}

function ignore (threadId) {
  let count = ignoredThreads.get(threadId);
  if (count === undefined) {
    count = 0;
  }
  count++;
  ignoredThreads.set(threadId, count);
}

function unignore (threadId) {
  let count = ignoredThreads.get(threadId);
  if (count === undefined) {
    throw new Error(`Thread ${threadId} is not ignored`);
  }
  count--;
  if (count === 0) {
    ignoredThreads.delete(threadId);
  } else {
    ignoredThreads.set(threadId, count);
  }
}

function basename (className) {
  return className.slice(className.lastIndexOf('.') + 1);
}

function readTypeNames (env, types) {
  const names = [];

  const n = env.getArrayLength(types);
  for (let i = 0; i !== n; i++) {
    const t = env.getObjectArrayElement(types, i);
    try {
      names.push(env.getTypeName(t));
    } finally {
      env.deleteLocalRef(t);
    }
  }

  return names;
}

function makeSourceFileName (className) {
  const tokens = className.split('.');
  return tokens[tokens.length - 1] + '.java';
}

module.exports = ClassFactory;
```