Response:
Let's break down the thought process to analyze the provided JavaScript code for Frida.

**1. Initial Understanding - Context and Purpose:**

The first step is to recognize this is a JavaScript file intended for use with Frida, a dynamic instrumentation toolkit. The file path `frida/subprojects/frida-core/src/linux/agent/system-server.js` strongly suggests this code interacts with the Android system server, likely to gather information and control applications.

**2. High-Level Functionality Identification (Scanning for `rpc.exports`):**

A quick scan for `rpc.exports` is crucial. This immediately reveals the primary entry points and intended functionalities of the script, as these are the functions Frida will expose for interaction. Listing these out provides a good overview:

* `getFrontmostApplication`:  Get information about the app currently in the foreground.
* `enumerateApplications`: List installed applications.
* `getProcessName`: Get the process name of an application.
* `getProcessParameters`: Get detailed information about processes.
* `startActivity`: Launch an application or a specific activity.
* `sendBroadcast`: Send an Android broadcast intent.
* `stopPackage`: Force stop an application.
* `tryStopPackageByPid`: Attempt to stop an application based on its process ID.

**3. Decompiling Each `rpc.exports` Function:**

For each exposed function, the next step is to understand *what it does*. This involves examining the code within each function. Look for:

* **Java API Calls:**  The code heavily uses `Java.use()`, `Java.cast()`, and accesses static fields (e.g., `Intent.ACTION_MAIN.value`). This immediately signals interaction with the Android runtime environment and Java APIs. Identify key classes like `ActivityManager`, `PackageManager`, `Intent`, `ApplicationInfo`, etc.
* **Parameters and Return Values:**  Understand what input the function expects and what kind of data it returns.
* **Logic and Data Flow:**  Trace how data is retrieved, manipulated, and returned. For instance, in `getFrontmostApplication`, the code gets running tasks, extracts the top activity, and then fetches application information.

**4. Identifying Core Concepts and Techniques:**

As you analyze the individual functions, patterns and common themes will emerge. For instance:

* **Package Management:** Several functions revolve around getting information about applications (listing, details, starting). This points to the use of `PackageManager`.
* **Activity Management:**  Functions like `getFrontmostApplication`, `startActivity`, and `stopPackage` clearly interact with the `ActivityManager`.
* **Intents:** The `startActivity` and `sendBroadcast` functions use `Intent` objects, which are fundamental to inter-component communication in Android.
* **Process Information:**  Functions dealing with PIDs and process names indicate interaction with the operating system's process management.
* **User Handling:**  The presence of `uid` parameters and calls like `createPackageContextAsUser` and `getInstalledApplicationsAsUser` highlight support for multi-user environments.
* **Frida Specifics:** Recognize the use of `performOnJavaVM` for safely executing code within the Android runtime.

**5. Connecting to Reverse Engineering Concepts:**

Now, think about how these functionalities are relevant to reverse engineering:

* **Application Enumeration/Inspection:**  Tools like this allow an analyst to get a detailed view of installed apps, their components, and their running state.
* **Identifying Entry Points:**  `startActivity` helps in understanding how an app can be launched and which activities are available.
* **Inter-Process Communication (IPC) Analysis:** `sendBroadcast` is directly related to analyzing how applications communicate through broadcast intents.
* **Dynamic Analysis:** The ability to start and stop packages facilitates controlled experiments and observation of app behavior.
* **Identifying Potential Attack Surfaces:** Understanding the structure and components of an application can reveal potential vulnerabilities.

**6. Linking to Low-Level Concepts (Linux, Android Kernel/Framework):**

Consider the underlying technologies:

* **Linux Processes:** The concept of PIDs, process names, and stopping processes are all fundamental Linux concepts.
* **Android Framework APIs:**  The script heavily relies on the Android framework APIs (e.g., `ActivityManager`, `PackageManager`), which are Java interfaces to the underlying system services.
* **Android Application Model:** The script works with concepts like packages, activities, intents, and application information, which are core to the Android application model.
* **Permissions and Security:** Although not explicitly manipulated in this script, the functions provide insights into how Android manages applications and their permissions.

**7. Logical Reasoning and Examples:**

Think about hypothetical scenarios:

* **Input/Output:**  For `getFrontmostApplication`, imagine the user interface is currently showing the Chrome browser. The output would be the package name of Chrome, its label, its PID, and potentially more details.
* **User Errors:**  Consider what could go wrong. A common mistake would be providing an incorrect package name or activity name to `startActivity`.

**8. Tracing User Operations:**

Imagine the user's interaction with Frida:

1. The user runs a Frida script that includes this code.
2. The script calls one of the `rpc.exports` functions (e.g., `enumerateApplications`).
3. Frida, through its agent mechanism, executes the corresponding JavaScript code within the target Android process (likely `system_server`).
4. The JavaScript code uses the Android APIs to gather the requested information.
5. The information is returned to the Frida script and then back to the user.

**Self-Correction/Refinement:**

During this process, it's important to be critical and refine your understanding. For example, initially, you might just say "it gets app info." But digging deeper, you realize *how* it gets that info (using `PackageManager`) and *what kind* of info (name, label, PID, version, etc.). Similarly, understanding the `performLaunchOperation` function and its timeout mechanism adds another layer of comprehension.

By following these steps, you can systematically analyze the code and address all the requirements of the prompt. The key is to break down the problem into smaller, manageable parts and connect the code to the broader context of Android development and reverse engineering.
这个Frida脚本 `system-server.js` 的主要功能是**获取和操作Android系统中的应用程序信息和状态**。它通过与Android的 `system_server` 进程交互，利用Android的Java API来完成这些任务。

以下是其功能的详细列表，并结合你提出的要求进行说明：

**1. 获取应用程序信息:**

* **`getFrontmostApplication(scope)`:** 获取当前前台运行的应用程序的信息，包括包名、应用标签、进程ID（PID）以及可选的详细参数（如版本、构建号、数据目录等）。
    * **与逆向方法的关系:** 在逆向分析时，了解当前运行的应用程序是第一步，可以确定攻击目标或分析对象。例如，逆向工程师可以使用此功能来确认恶意软件是否正在前台运行。
    * **二进制底层/Linux/Android内核及框架知识:**  此功能依赖于Android框架提供的 `ActivityManager` 服务来获取前台任务信息。`ActivityManager` 本身与Linux的进程管理相关，并构建在Android内核之上。
    * **逻辑推理:**  假设前台运行的是微信，输入 `frida> rpc.exports.getFrontmostApplication()`，输出可能类似于 `["com.tencent.mm", "微信", 1234, {version: "8.0.30", ...}]`。
* **`enumerateApplications(identifiers, scope)`:**  列出所有或指定的已安装应用程序的信息，包括包名、应用标签、进程ID（PID）以及可选的详细参数。
    * **与逆向方法的关系:**  可以用于枚举设备上安装的所有应用，为进一步分析提供目标列表。例如，可以列出所有带有 `debuggable` 标志的应用，方便调试。
    * **二进制底层/Linux/Android内核及框架知识:**  依赖 `PackageManager` 服务来获取已安装的应用列表和应用信息。
    * **逻辑推理:**  假设输入 `frida> rpc.exports.enumerateApplications(['com.tencent.mm', 'com.android.settings'])`，将返回微信和设置两个应用的相关信息。
* **`getProcessName(pkgName, uid)`:**  根据包名和可选的用户ID（UID）获取应用程序的进程名称。
    * **与逆向方法的关系:**  在分析涉及多个进程的应用时，可以根据包名快速定位其进程名称。
    * **二进制底层/Linux/Android内核及框架知识:**  涉及Android的用户和进程模型。
    * **逻辑推理:**  假设输入 `frida> rpc.exports.getProcessName('com.tencent.mm')`，输出可能是 `"com.tencent.mm"` 或 `"com.tencent.mm:push"` 等。
* **`getProcessParameters(pids, scope)`:**  根据进程ID（PID）列表获取进程的详细参数，包括应用名称、图标（可选）、包名列表等。
    * **与逆向方法的关系:**  可以根据进程ID反查应用信息，或者了解特定进程所关联的包名。
    * **二进制底层/Linux/Android内核及框架知识:**  需要访问Android的进程信息。
    * **逻辑推理:**  假设输入 `frida> rpc.exports.getProcessParameters([1234])`，其中 `1234` 是微信的PID，输出将包含微信的应用名称和可能的图标数据。

**2. 操作应用程序:**

* **`startActivity(pkgName, activity, uid)`:** 启动指定包名的应用程序或特定的Activity。
    * **与逆向方法的关系:**  可以用于启动目标应用的特定组件进行测试或分析。例如，可以跳过主界面直接启动某个特定的Activity。
    * **二进制底层/Linux/Android内核及框架知识:**  依赖于 `ActivityManager` 服务来启动Activity，涉及到Android的Intent机制。
    * **逻辑推理:**  假设输入 `frida> rpc.exports.startActivity('com.tencent.mm', '.ui.LauncherUI')`，将尝试启动微信的主界面。
    * **用户/编程常见的使用错误:** 如果提供的 `activity` 名称不存在，或者包名错误，Frida会抛出异常。
* **`sendBroadcast(pkgName, receiver, action, uid)`:** 向指定包名的应用程序发送广播Intent。
    * **与逆向方法的关系:**  可以用于触发目标应用的特定功能或观察其对特定广播的响应。
    * **二进制底层/Linux/Android内核及框架知识:**  依赖于Android的广播机制。
    * **逻辑推理:**  假设输入 `frida> rpc.exports.sendBroadcast('com.example.app', 'com.example.app.MyReceiver', 'MY_CUSTOM_ACTION')`，将向 `com.example.app` 发送一个自定义的广播。
    * **用户/编程常见的使用错误:**  如果 `receiver` 或 `action` 不正确，广播可能无法被目标应用接收。
* **`stopPackage(pkgName, uid)`:** 强制停止指定包名的应用程序。
    * **与逆向方法的关系:**  可以用于停止目标应用，以便进行代码注入或观察其重启行为。
    * **二进制底层/Linux/Android内核及框架知识:**  依赖于 `ActivityManager` 服务的强制停止功能，会影响应用的进程。
    * **逻辑推理:**  假设输入 `frida> rpc.exports.stopPackage('com.tencent.mm')`，将强制停止微信应用。
    * **用户/编程常见的使用错误:**  强制停止应用可能会导致数据丢失或不稳定。
* **`tryStopPackageByPid(pid)`:** 尝试根据进程ID（PID）停止应用程序。
    * **与逆向方法的关系:**  在已知进程ID的情况下停止应用。
    * **二进制底层/Linux/Android内核及框架知识:**  需要查找与PID关联的包名，然后调用 `stopPackage`。
    * **逻辑推理:**  假设输入 `frida> rpc.exports.tryStopPackageByPid(1234)`，如果 `1234` 是微信的PID，将尝试停止微信。

**3. 其他辅助功能:**

* **`init()`:** 初始化函数，在脚本加载时执行，用于获取Android的Java类和常量。
    * **二进制底层/Linux/Android内核及框架知识:**  涉及加载和使用Android的Java类。
* **`getFrontmostPackageName()`:** 获取当前前台应用程序的包名。
* **`getLauncherApplications()`:** 获取所有启动器应用的 `ApplicationInfo` 对象。
* **`getAppInfo(pkgName, uid)`:** 获取指定包名和用户ID的应用信息。
* **`fetchAppParameters(pkgName, appInfo, scope)`:** 获取应用的详细参数，如版本、构建号、安装路径等。
* **`fetchAppIcon(appInfo)`:** 获取应用的图标并将其转换为Base64编码的字符串。
* **`getAppProcesses()`:** 获取当前运行的所有应用程序进程信息。
* **`computeAppPids(processes)`:** 从进程信息中提取包名和对应的进程ID。
* **`detectLauncherPackageName()`:** 检测当前设备的启动器应用包名。
* **`checkUidOptionSupported(uid)`:** 检查当前Android版本是否支持用户ID选项。
* **`installLaunchTimeoutRemovalInstrumentation()`:**  一个 Hook 机制，用于移除启动应用时的超时限制，可能用于调试目的。它 Hook 了 `android.os.Process.start` 和 `android.os.Handler.sendMessageDelayed`。
    * **二进制底层/Linux/Android内核及框架知识:** 涉及到 Android 的进程启动机制和消息处理机制。Hook 技术本身是逆向工程中常用的方法。
* **`performLaunchOperation(pkgName, uid, operation)`:**  执行启动操作，并处理可能的超时情况。
* **`tryFinishLaunch(processName)`:**  尝试完成启动操作，清除定时器等。
* **`performOnJavaVM(task)`:**  确保代码在 Android 的 Java 虚拟机中执行。

**用户操作如何一步步的到达这里，作为调试线索：**

1. **编写 Frida 脚本:**  用户编写了一个 Frida 脚本，其中 `rpc.exports` 定义了可以被外部调用的函数。这个 `system-server.js` 文件就是这样的一个脚本。
2. **连接到 Android 设备/模拟器:** 用户使用 Frida CLI 或其他 Frida 客户端连接到目标 Android 设备或模拟器。
3. **指定目标进程:** 用户指定 Frida Agent 需要注入的进程。由于这个脚本涉及到系统级别的操作，通常会注入到 `system_server` 进程。
    ```bash
    frida -U -n system_server -l system-server.js
    ```
    或者，如果目标是特定的应用，可以注入到该应用的进程。
4. **调用 `rpc.exports` 中的函数:** 用户在 Frida 控制台或通过 Frida 客户端调用 `system-server.js` 中 `rpc.exports` 暴露的函数。例如：
    ```javascript
    rpc.exports.getFrontmostApplication();
    rpc.exports.startActivity('com.example.app', '.MainActivity');
    ```
5. **Frida Agent 执行代码:** Frida Agent 会将用户的调用传递给注入到目标进程的 JavaScript 代码（即 `system-server.js`）。
6. **脚本内部逻辑执行:**  脚本中的函数会使用 Android 的 Java API（通过 `Java.use` 等）来获取或操作系统信息。例如，调用 `ActivityManager` 或 `PackageManager` 的方法。
7. **结果返回:**  脚本执行的结果会通过 Frida Agent 返回给用户。

**涉及用户或编程常见的使用错误举例说明:**

* **错误的包名或Activity名称:**  在使用 `startActivity` 时，如果提供的包名或 Activity 名称不正确，会导致启动失败并抛出异常。例如：`rpc.exports.startActivity('com.example.notexist', '.MainActivity')`。
* **权限不足:** 某些操作可能需要特定的系统权限，如果 Frida 注入的进程没有相应的权限，操作可能会失败。
* **UID 使用错误:** 在不支持多用户的 Android 版本上使用 `uid` 参数会导致错误。
* **假设前台应用存在:**  在调用 `getFrontmostApplication` 之前，没有判断是否有前台应用，可能返回 `null`。
* **广播接收器未注册:**  在使用 `sendBroadcast` 时，如果目标应用没有注册相应的广播接收器，广播将不会被处理。
* **误用 `stopPackage`:**  频繁或不必要地使用 `stopPackage` 可能会导致应用数据丢失或用户体验下降。

总而言之，`system-server.js` 是一个强大的 Frida 脚本，它允许用户在运行时动态地检查和操作 Android 系统的应用程序，这对于安全分析、逆向工程和调试都非常有价值。

### 提示词
```
这是目录为frida/subprojects/frida-core/src/linux/agent/system-server.js的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```javascript
let ApplicationInfo, Base64OutputStream, Bitmap, ByteArrayOutputStream, Canvas, ComponentName, ContextWrapper, Intent, ResolveInfo,
  RunningAppProcessInfo, RunningTaskInfo, UserHandle;
let ACTION_MAIN, ARGB_8888, CATEGORY_HOME, CATEGORY_LAUNCHER, GET_ACTIVITIES, FLAG_ACTIVITY_NEW_TASK, FLAG_DEBUGGABLE, NO_WRAP, PNG;
let context, packageManager, activityManager, loadAppLabel, loadResolveInfoLabel;

let multiUserSupported;
let launcherPkgName;
const pendingLaunches = new Map();

function init() {
  const ActivityManager = Java.use('android.app.ActivityManager');
  const ActivityThread = Java.use('android.app.ActivityThread');
  ApplicationInfo = Java.use('android.content.pm.ApplicationInfo');
  const Base64 = Java.use('android.util.Base64');
  Base64OutputStream = Java.use('android.util.Base64OutputStream');
  Bitmap = Java.use('android.graphics.Bitmap');
  const BitmapCompressFormat = Java.use('android.graphics.Bitmap$CompressFormat');
  const BitmapConfig = Java.use('android.graphics.Bitmap$Config');
  ByteArrayOutputStream = Java.use('java.io.ByteArrayOutputStream');
  Canvas = Java.use('android.graphics.Canvas');
  ComponentName = Java.use('android.content.ComponentName');
  ContextWrapper = Java.use('android.content.ContextWrapper');
  Intent = Java.use('android.content.Intent');
  const Context = Java.use('android.content.Context');
  const PackageManager = Java.use('android.content.pm.PackageManager');
  ResolveInfo = Java.use('android.content.pm.ResolveInfo');
  RunningAppProcessInfo = Java.use('android.app.ActivityManager$RunningAppProcessInfo');
  RunningTaskInfo = Java.use('android.app.ActivityManager$RunningTaskInfo');
  UserHandle = Java.use('android.os.UserHandle');
  const ACTIVITY_SERVICE = Context.ACTIVITY_SERVICE.value;
  ACTION_MAIN = Intent.ACTION_MAIN.value;
  ARGB_8888 = BitmapConfig.ARGB_8888.value;
  CATEGORY_HOME = Intent.CATEGORY_HOME.value;
  CATEGORY_LAUNCHER = Intent.CATEGORY_LAUNCHER.value;
  GET_ACTIVITIES = PackageManager.GET_ACTIVITIES.value;
  FLAG_ACTIVITY_NEW_TASK = Intent.FLAG_ACTIVITY_NEW_TASK.value;
  FLAG_DEBUGGABLE = ApplicationInfo.FLAG_DEBUGGABLE.value;
  NO_WRAP = Base64.NO_WRAP.value;
  PNG = BitmapCompressFormat.PNG.value;

  context = ActivityThread.currentApplication();

  packageManager = context.getPackageManager();
  activityManager = Java.cast(context.getSystemService(ACTIVITY_SERVICE), ActivityManager);

  loadAppLabel = ApplicationInfo.loadUnsafeLabel ?? ApplicationInfo.loadLabel;

  multiUserSupported = 'getApplicationInfoAsUser' in PackageManager;
  launcherPkgName = detectLauncherPackageName();

  installLaunchTimeoutRemovalInstrumentation();
}

rpc.exports = {
  getFrontmostApplication(scope) {
    return performOnJavaVM(() => {
      const pkgName = getFrontmostPackageName();
      if (pkgName === null)
        return null;

      const appInfo = packageManager.getApplicationInfo(pkgName, 0);

      const appLabel = loadAppLabel.call(appInfo, packageManager).toString();
      const pid = computeAppPids(getAppProcesses()).get(pkgName) ?? 0;
      const parameters = (scope !== 'minimal') ? fetchAppParameters(pkgName, appInfo, scope) : null;

      return [pkgName, appLabel, pid, parameters];
    });
  },
  enumerateApplications(identifiers, scope) {
    return performOnJavaVM(() => {
      const apps = [];
      if (identifiers.length > 0) {
        for (const pkgName of identifiers) {
          try {
            apps.push([pkgName, packageManager.getApplicationInfo(pkgName, 0)]);
          } catch (e) {
          }
        }
      } else {
        for (const appInfo of getLauncherApplications()) {
          apps.push([appInfo.packageName.value, appInfo]);
        }
      }

      const result = [];

      const pids = computeAppPids(getAppProcesses());
      const includeParameters = scope !== 'minimal';
      const frontmostPkgName = includeParameters ? getFrontmostPackageName() : null;

      for (const [pkgName, appInfo] of apps) {
        const appLabel = loadAppLabel.call(appInfo, packageManager).toString();
        const pid = pids.get(pkgName) ?? 0;
        let parameters = null;

        if (includeParameters) {
          parameters = fetchAppParameters(pkgName, appInfo, scope);

          if (pkgName === frontmostPkgName)
            parameters.frontmost = true;
        }

        result.push([pkgName, appLabel, pid, parameters]);
      }

      return result;
    });
  },
  getProcessName(pkgName, uid) {
    checkUidOptionSupported(uid);

    return performOnJavaVM(() => {
      try {
        return getAppInfo(pkgName, uid).processName.value;
      } catch (e) {
        throw new Error(`Unable to find application with identifier '${pkgName}'${(uid !== 0) ? ' belonging to uid ' + uid : ''}`);
      }
    });
  },
  getProcessParameters(pids, scope) {
    const result = {};

    const appProcesses = getAppProcesses();

    const appPidByPkgName = computeAppPids(appProcesses);

    const appProcessByPid = new Map();
    for (const process of appProcesses)
      appProcessByPid.set(process.pid, process);

    const appInfoByPkgName = new Map();
    for (const appInfo of getLauncherApplications())
      appInfoByPkgName.set(appInfo.packageName.value, appInfo);

    const appInfoByPid = new Map();
    for (const [pkgName, appPid] of appPidByPkgName.entries()) {
      const appInfo = appInfoByPkgName.get(pkgName);
      if (appInfo !== undefined)
        appInfoByPid.set(appPid, appInfo);
    }

    let frontmostPid = -1;
    const frontmostPkgName = getFrontmostPackageName();
    if (frontmostPkgName !== null) {
      frontmostPid = appPidByPkgName.get(frontmostPkgName) ?? -1;
    }

    const includeParameters = scope !== 'minimal';
    const includeIcons = scope === 'full';

    for (const pid of pids) {
      const parameters = {};

      const appInfo = appInfoByPid.get(pid);
      if (appInfo !== undefined) {
        parameters.$name = loadAppLabel.call(appInfo, packageManager).toString()

        if (includeIcons)
          parameters.$icon = fetchAppIcon(appInfo);
      }

      if (includeParameters) {
        const appProcess = appProcessByPid.get(pid);
        if (appProcess !== undefined) {
          parameters.applications = appProcess.pkgList;
        }

        if (pid === frontmostPid) {
          parameters.frontmost = true;
        }
      }

      if (Object.keys(parameters).length !== 0) {
        result[pid] = parameters;
      }
    }

    return result;
  },
  startActivity(pkgName, activity, uid) {
    checkUidOptionSupported(uid);

    return performOnJavaVM(() => {
      let user, ctx, pm;
      if (uid !== 0) {
        user = UserHandle.of(uid);
        ctx = context.createPackageContextAsUser(pkgName, 0, user);
        pm = ctx.getPackageManager();
      } else {
        user = null;
        ctx = context;
        pm = packageManager;
      }

      let appInstalled = false;
      const apps = (uid !== 0)
          ? pm.getInstalledApplicationsAsUser(0, uid)
          : pm.getInstalledApplications(0);
      const numApps = apps.size();
      for (let i = 0; i !== numApps; i++) {
        const appInfo = Java.cast(apps.get(i), ApplicationInfo);
        if (appInfo.packageName.value === pkgName) {
          appInstalled = true;
          break;
        }
      }
      if (!appInstalled)
        throw new Error("Unable to find application with identifier '" + pkgName + "'");

      let intent = pm.getLaunchIntentForPackage(pkgName);
      if (intent === null && 'getLeanbackLaunchIntentForPackage' in pm)
        intent = pm.getLeanbackLaunchIntentForPackage(pkgName);
      if (intent === null && activity === null)
        throw new Error('Unable to find a front-door activity');

      if (intent === null) {
        intent = Intent.$new();
        intent.setFlags(FLAG_ACTIVITY_NEW_TASK);
      }

      if (activity !== null) {
        const pkgInfo = (uid !== 0)
            ? pm.getPackageInfoAsUser(pkgName, GET_ACTIVITIES, uid)
            : pm.getPackageInfo(pkgName, GET_ACTIVITIES);
        const activities = pkgInfo.activities.value.map(activityInfo => activityInfo.name.value);
        if (!activities.includes(activity))
          throw new Error("Unable to find activity with identifier '" + activity + "'");

        intent.setClassName(pkgName, activity);
      }

      performLaunchOperation(pkgName, uid, () => {
        if (user !== null)
          ContextWrapper.$new(ctx).startActivityAsUser(intent, user);
        else
          ctx.startActivity(intent);
      });
    });
  },
  sendBroadcast(pkgName, receiver, action, uid) {
    checkUidOptionSupported(uid);

    return performOnJavaVM(() => {
      const intent = Intent.$new();
      intent.setComponent(ComponentName.$new(pkgName, receiver));
      intent.setAction(action);

      performLaunchOperation(pkgName, uid, () => {
        if (uid !== 0)
          ContextWrapper.$new(context).sendBroadcastAsUser(intent, UserHandle.of(uid));
        else
          context.sendBroadcast(intent);
      });
    });
  },
  stopPackage(pkgName, uid) {
    checkUidOptionSupported(uid);

    return performOnJavaVM(() => {
      if (uid !== 0)
        activityManager.forceStopPackageAsUser(pkgName, uid);
      else
        activityManager.forceStopPackage(pkgName);
    });
  },
  tryStopPackageByPid(pid) {
    return performOnJavaVM(() => {
      const processes = activityManager.getRunningAppProcesses();

      const numProcesses = processes.size();
      for (let i = 0; i !== numProcesses; i++) {
        const process = Java.cast(processes.get(i), RunningAppProcessInfo);
        if (process.pid.value === pid) {
          for (const pkgName of process.pkgList.value) {
            activityManager.forceStopPackage(pkgName);
          }
          return true;
        }
      }

      return false;
    });
  },
};

function getFrontmostPackageName() {
  const tasks = activityManager.getRunningTasks(1);
  if (tasks.isEmpty())
    return null;

  const task = Java.cast(tasks.get(0), RunningTaskInfo);
  if (task.topActivity === undefined)
    return null;

  const name = task.topActivity.value.getPackageName();
  if (name === launcherPkgName)
    return null;

  return name;
}

function getLauncherApplications() {
  const intent = Intent.$new(ACTION_MAIN);
  intent.addCategory(CATEGORY_LAUNCHER);

  const activities = packageManager.queryIntentActivities(intent, 0);

  const result = [];
  const n = activities.size();
  for (let i = 0; i !== n; i++) {
    const resolveInfo = Java.cast(activities.get(i), ResolveInfo);
    result.push(resolveInfo.activityInfo.value.applicationInfo.value);
  }
  return result;
}

function getAppInfo(pkgName, uid) {
  return (uid !== 0)
      ? packageManager.getApplicationInfoAsUser(pkgName, 0, uid)
      : packageManager.getApplicationInfo(pkgName, 0);
}

function fetchAppParameters(pkgName, appInfo, scope) {
  const pkgInfo = packageManager.getPackageInfo(pkgName, 0);

  const parameters = {
    'version': pkgInfo.versionName.value,
    'build': pkgInfo.versionCode.value.toString(),
    'sources': [appInfo.publicSourceDir.value].concat(appInfo.splitPublicSourceDirs?.value ?? []),
    'data-dir': appInfo.dataDir.value,
    'target-sdk': appInfo.targetSdkVersion.value,
  };

  if ((appInfo.flags.value & FLAG_DEBUGGABLE) !== 0)
    parameters.debuggable = true;

  if (scope === 'full')
    parameters.$icon = fetchAppIcon(appInfo);

  return parameters;
}

function fetchAppIcon(appInfo) {
  const icon = packageManager.getApplicationIcon(appInfo);

  const width = icon.getIntrinsicWidth();
  const height = icon.getIntrinsicHeight();

  const bitmap = Bitmap.createBitmap(width, height, ARGB_8888);
  const canvas = Canvas.$new(bitmap);
  icon.setBounds(0, 0, width, height);
  icon.draw(canvas);

  const output = ByteArrayOutputStream.$new();
  bitmap.compress(PNG, 100, Base64OutputStream.$new(output, NO_WRAP));

  return output.toString('US-ASCII');
}

function getAppProcesses() {
  const result = [];

  const processes = activityManager.getRunningAppProcesses();
  const n = processes.size();
  for (let i = 0; i !== n; i++) {
    const process = Java.cast(processes.get(i), RunningAppProcessInfo);

    result.push({
      pid: process.pid.value,
      importance: process.importance.value,
      pkgList: process.pkgList.value
    });
  }

  return result;
}

function computeAppPids(processes) {
  const pids = new Map();

  for (const { pid, importance, pkgList } of processes) {
    for (const pkgName of pkgList) {
      let entries = pids.get(pkgName);
      if (entries === undefined) {
        entries = [];
        pids.set(pkgName, entries);
      }
      entries.push([ pid, importance ]);
      if (entries.length > 1) {
        entries.sort((a, b) => a[1] - b[1]);
      }
    }
  }

  return new Map(Array.from(pids.entries()).map(([k, v]) => [k, v[0][0]]));
}

function detectLauncherPackageName() {
  const intent = Intent.$new(ACTION_MAIN);
  intent.addCategory(CATEGORY_HOME);

  const launchers = packageManager.queryIntentActivities(intent, 0);
  if (launchers.isEmpty())
    return null;

  const launcher = Java.cast(launchers.get(0), ResolveInfo);

  return launcher.activityInfo.value.packageName.value;
}

function checkUidOptionSupported(uid) {
  if (uid !== 0 && !multiUserSupported)
    throw new Error('The “uid” option is not supported on the current Android OS version');
}

function installLaunchTimeoutRemovalInstrumentation() {
  const Handler = Java.use('android.os.Handler');
  const OSProcess = Java.use('android.os.Process');

  const pendingStartRequests = new Set();

  const start = OSProcess.start;
  start.implementation = function (processClass, niceName) {
    const result = start.apply(this, arguments);

    if (tryFinishLaunch(niceName)) {
      pendingStartRequests.add(Process.getCurrentThreadId());
    }

    return result;
  };

  const sendMessageDelayed = Handler.sendMessageDelayed;
  sendMessageDelayed.implementation = function (msg, delayMillis) {
    const tid = Process.getCurrentThreadId();
    if (pendingStartRequests.has(tid)) {
      pendingStartRequests.delete(tid);
      msg.recycle();
      return true;
    }

    return sendMessageDelayed.call(this, msg, delayMillis);
  };
}

function performLaunchOperation(pkgName, uid, operation) {
  const processName = getAppInfo(pkgName, uid).processName.value;

  tryFinishLaunch(processName);

  const timer = setTimeout(() => {
    if (pendingLaunches.get(processName) === timer)
      tryFinishLaunch(processName);
  }, 10000);
  pendingLaunches.set(processName, timer);

  try {
    return operation();
  } catch (e) {
    tryFinishLaunch(processName);
    throw e;
  }
}

function tryFinishLaunch(processName) {
  const timer = pendingLaunches.get(processName);
  if (timer === undefined)
    return false;

  pendingLaunches.delete(processName);
  clearTimeout(timer);
  return true;
}

function performOnJavaVM(task) {
  return new Promise((resolve, reject) => {
    Java.perform(() => {
      try {
        const result = task();

        resolve(result);
      } catch (e) {
        reject(e);
      }
    });
  });
}

Java.perform(init);
```