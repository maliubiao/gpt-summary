响应:

```
好的，我现在需要分析这个Kotlin代码文件的功能，并按照用户的要求回答问题。首先，这个文件是APatch项目中PatchesViewModel.kt的一部分，用于处理Android内核和系统的修补。用户要求列举功能执行顺序，可能的shell示例，文件系统访问细节，以及易错点。

首先，我需要理解这个类的主要职责。看起来这是一个ViewModel，负责管理补丁的应用、卸载以及相关操作。里面有很多方法，比如准备环境、解析引导镜像、嵌入KPM模块、执行补丁或卸载等。

接下来，按照执行顺序来排列功能。可能用户选择一个操作模式（比如打补丁、安装到下一个槽位等），然后进行准备步骤，包括创建目录、设置符号链接、提取脚本等。然后根据模式的不同，可能提取当前boot镜像并解析，或者处理用户上传的boot镜像。之后可能会嵌入额外的KPM模块，最后执行实际的补丁或卸载操作，并处理输出结果。

关于Shell代码示例，可能需要展示如何调用kptools或magiskboot工具，例如解析kpimg信息或解包boot镜像。例如，用户可能执行类似`./kptools -l -k kpimg`的命令来获取版本信息。

文件系统访问方面，代码中使用了patchDir作为工作目录，处理临时文件，复制上传的boot.img，以及生成修补后的镜像。需要注意权限问题，尤其是在需要root权限的情况下操作/system分区或boot设备。

易错点可能包括：用户没有正确授予root权限导致命令执行失败；上传的KPM模块格式不正确导致解析错误；在Android高版本中写入文件需要MediaStore API，否则可能无法保存修补后的镜像；处理A/B分区时切换槽位失败可能导致启动问题；Super Key不符合复杂度要求导致补丁失败。

需要验证这些推测是否正确。例如，在doPatch方法中，构建patchCommand时考虑了旧版本的兼容性，如果用户使用的工具版本过旧，可能导致参数顺序错误。此外，处理A/B分区时，如果bootctl命令不可用，可能导致切换槽位失败，需要手动处理。

总结功能执行顺序大致为：准备环境 -> 解析当前系统信息 -> 处理用户输入（如boot镜像或KPM文件） -> 执行补丁/卸载 -> 处理输出结果（保存文件或设置重启）。Shell示例可能涉及工具的使用，而文件系统操作需要特别注意权限和路径。
```
### 功能执行顺序推理
1. **环境准备阶段**  
   - 创建临时工作目录 `patchDir`
   - 通过符号链接动态加载二进制工具（`libkptools.so`等）
   - 从 Assets 提取核心脚本（`boot_patch.sh`等）

2. **信息解析阶段**  
   - 调用 `kptools -l -k kpimg` 解析内核补丁元数据（版本/编译时间）
   - 用 `magiskboot unpack` 解包 boot.img 并解析内核信息（是否已修补）
   - 提取当前系统的 A/B 分区信息（`bootctl`相关）

3. **用户交互阶段**  
   - 处理用户上传的 boot.img 或 KPM 模块文件（通过 Uri）
   - 验证 Super Key 的复杂度（字母+数字组合）

4. **核心操作阶段**  
   - **打补丁**：调用 `boot_patch.sh` 嵌入 Super Key 和 KPM 模块
   - **卸载补丁**：删除相关文件并还原原始 boot 分区
   - **多分区处理**：通过 `bootctl` 切换 A/B 槽位

5. **结果处理阶段**  
   - 将修补后的 boot.img 保存到 Downloads 目录（兼容 Android Q+）
   - 写入 post-fs-data 脚本确保 OTA 后标记启动状态
   - 设置全局重启标记

---

### Shell 代码示例（功能推理）
#### 1. 解析内核补丁信息
```bash
# 假设在 patchDir 工作目录
./kptools -l -k kpimg
```
**输入**：已修补的 boot.img  
**输出**：
```ini
[kpimg]
version = 1.2.3
compile_time = 2023-04-01
config = arm64
```

#### 2. 解包 boot 镜像
```bash
./magiskboot unpack boot.img
./kptools -l -i kernel
```
**输出**：
```ini
[kernel]
banner = Linux version 5.10.0
patched = true
```

---

### 文件系统访问细节
1. **敏感路径**：
   - `/data/adb/post-fs-data.d/`：写入启动后脚本
   - `BOOTIMAGE` 环境变量：指向当前 boot 分区设备（如 `/dev/block/sde22`）

2. **关键操作**：
   - 通过 `ExtendedFile` 抽象进行 root 权限文件操作
   - Android Q+ 使用 MediaStore API 写入 Downloads
   - 通过 `FileProvider` 安全共享文件

---

### 使用者易错点示例
1. **Super Key 复杂度不足**  
   ```kotlin
   checkSuperKeyValidation("weakkey") // 失败：需要至少1数字+1字母
   ```

2. **KPM 模块格式错误**  
   ```bash
   # 无效的 KPM 会导致：
   ./kptools -M invalid.kpm // 返回非0退出码
   ```

3. **A/B 分区处理失败**  
   ```log
   [X] Failed to connect to boot hal // 需要手动切换槽位
   ```

4. **Android Q 文件写入权限**  
   未申请 `WRITE_EXTERNAL_STORAGE` 权限时，`MediaStore` 写入会失败

---

### 架构设计亮点
1. **分层命令执行**  
   通过 `Shell.newJob()` 封装 root 命令，区分同步/异步执行

2. **多版本兼容**  
   检测 `isSuExecutable()` 处理旧版 Magisk 环境

3. **安全文件传输**  
   使用 `FileProvider` 避免 `file://` URI 暴露风险
提示器:

这是路径为APatch/app/src/main/java/me/tool/passkey/ui/viewmodel/PatchesViewModel.kt的apatch `The patching of Android kernel and Android system`实现的一部分， 
请按照最可能的执行顺序(非行号)列举一下它的功能, 　
如果你能推理出它是什么功能的实现，请用shell代码举例, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，涉及到对文件系统的访问，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

```kotlin
package me.tool.passkey.ui.viewmodel

import android.content.ContentValues
import android.content.Context
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import android.system.Os
import android.util.Log
import androidx.annotation.RequiresApi
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.core.content.FileProvider
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.topjohnwu.superuser.CallbackList
import com.topjohnwu.superuser.Shell
import com.topjohnwu.superuser.nio.ExtendedFile
import com.topjohnwu.superuser.nio.FileSystemManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import me.tool.passkey.APApplication
import me.tool.passkey.BuildConfig
import me.tool.passkey.R
import me.tool.passkey.apApp
import me.tool.passkey.util.Version
import me.tool.passkey.util.copyAndClose
import me.tool.passkey.util.copyAndCloseOut
import me.tool.passkey.util.createRootShell
import me.tool.passkey.util.inputStream
import me.tool.passkey.util.shellForResult
import me.tool.passkey.util.writeTo
import org.ini4j.Ini
import java.io.BufferedReader
import java.io.File
import java.io.FileNotFoundException
import java.io.IOException
import java.io.InputStreamReader
import java.io.StringReader

private const val TAG = "PatchViewModel"

class PatchesViewModel : ViewModel() {

    enum class PatchMode(val sId: Int) {
        PATCH_ONLY(R.string.patch_mode_bootimg_patch),
        PATCH_AND_INSTALL(R.string.patch_mode_patch_and_install),
        INSTALL_TO_NEXT_SLOT(R.string.patch_mode_install_to_next_slot),
        UNPATCH(R.string.patch_mode_uninstall_patch)
    }

    var bootSlot by mutableStateOf("")
    var bootDev by mutableStateOf("")
    var kimgInfo by mutableStateOf(KPModel.KImgInfo("", false))
    var kpimgInfo by mutableStateOf(KPModel.KPImgInfo("", "", "", "", ""))
    var superkey by mutableStateOf(APApplication.superKey)
    var existedExtras = mutableStateListOf<KPModel.IExtraInfo>()
    var newExtras = mutableStateListOf<KPModel.IExtraInfo>()
    var newExtrasFileName = mutableListOf<String>()

    var running by mutableStateOf(false)
    var patching by mutableStateOf(false)
    var patchdone by mutableStateOf(false)
    var needReboot by mutableStateOf(false)

    var error by mutableStateOf("")
    var patchLog by mutableStateOf("")

    private val patchDir: ExtendedFile = FileSystemManager.getLocal().getFile(apApp.filesDir.parent, "patch")
    private var srcBoot: ExtendedFile = patchDir.getChildFile("boot.img")
    private var shell: Shell = createRootShell()
    private var prepared: Boolean = false

    private fun prepare() {
        patchDir.deleteRecursively()
        patchDir.mkdirs()
        val execs = listOf(
            "libkptools.so", "libmagiskboot.so", "libbusybox.so", "libkpatch.so", "libbootctl.so"
        )
        error = ""

        val info = apApp.applicationInfo
        val libs = File(info.nativeLibraryDir).listFiles { _, name ->
            execs.contains(name)
        } ?: emptyArray()

        for (lib in libs) {
            val name = lib.name.substring(3, lib.name.length - 3)
            Os.symlink(lib.path, "$patchDir/$name")
        }

        // Extract scripts
        for (script in listOf(
            "boot_patch.sh", "boot_unpatch.sh", "boot_extract.sh", "util_functions.sh", "kpimg"
        )) {
            val dest = File(patchDir, script)
            apApp.assets.open(script).writeTo(dest)
        }

    }

    private fun parseKpimg() {
        val result = shellForResult(
            shell, "cd $patchDir", "./kptools -l -k kpimg"
        )

        if (result.isSuccess) {
            val ini = Ini(StringReader(result.out.joinToString("\n")))
            val kpimg = ini["kpimg"]
            if (kpimg != null) {
                kpimgInfo = KPModel.KPImgInfo(
                    kpimg["version"].toString(),
                    kpimg["compile_time"].toString(),
                    kpimg["config"].toString(),
                    APApplication.superKey,     // current key
                    kpimg["root_superkey"].toString(),   // empty
                )
            } else {
                error += "parse kpimg error\n"
            }
        } else {
            error = result.err.joinToString("\n")
        }
    }

    private fun parseBootimg(bootimg: String) {
        val result = shellForResult(
            shell,
            "cd $patchDir",
            "./magiskboot unpack $bootimg",
            "./kptools -l -i kernel",
        )
        if (result.isSuccess) {
            val ini = Ini(StringReader(result.out.joinToString("\n")))
            Log.d(TAG, "kernel image info: $ini")

            val kernel = ini["kernel"]
            if (kernel == null) {
                error += "empty kernel section"
                Log.d(TAG, error)
                return
            }
            kimgInfo = KPModel.KImgInfo(kernel["banner"].toString(), kernel["patched"].toBoolean())
            if (kimgInfo.patched) {
                val superkey = ini["kpimg"]?.getOrDefault("superkey", "") ?: ""
                kpimgInfo.superKey = superkey
                if (checkSuperKeyValidation(superkey)) {
                    this.superkey = superkey
                }
                var kpmNum = kernel["extra_num"]?.toInt()
                if (kpmNum == null) {
                    val extras = ini["extras"]
                    kpmNum = extras?.get("num")?.toInt()
                }
                if (kpmNum != null && kpmNum > 0) {
                    for (i in 0..<kpmNum) {
                        val extra = ini["extra $i"]
                        if (extra == null) {
                            error += "empty extra section"
                            break
                        }
                        val type = KPModel.ExtraType.valueOf(extra["type"]!!.uppercase())
                        val name = extra["name"].toString()
                        val args = extra["args"].toString()
                        var event = extra["event"].toString()
                        if (event.isEmpty()) {
                            event = KPModel.TriggerEvent.PRE_KERNEL_INIT.event
                        }
                        if (type == KPModel.ExtraType.KPM) {
                            val kpmInfo = KPModel.KPMInfo(
                                type, name, event, args,
                                extra["version"].toString(),
                                extra["license"].toString(),
                                extra["author"].toString(),
                                extra["description"].toString(),
                            )
                            existedExtras.add(kpmInfo)
                        }
                    }

                }
            }
        } else {
            error += result.err.joinToString("\n")
        }
    }

    val checkSuperKeyValidation: (superKey: String) -> Boolean = { superKey ->
        superKey.length in 8..63 && superKey.any { it.isDigit() } && superKey.any { it.isLetter() }
    }

    fun copyAndParseBootimg(uri: Uri) {
        viewModelScope.launch(Dispatchers.IO) {
            if (running) return@launch
            running = true
            try {
                uri.inputStream().buffered().use { src ->
                    srcBoot.also {
                        src.copyAndCloseOut(it.newOutputStream())
                    }
                }
            } catch (e: IOException) {
                Log.e(TAG, "copy boot image error: $e")
            }
            parseBootimg(srcBoot.path)
            running = false
        }
    }

    private fun extractAndParseBootimg(mode: PatchMode) {
        var cmdBuilder = "./boot_extract.sh"

        if (mode == PatchMode.INSTALL_TO_NEXT_SLOT) {
            cmdBuilder += " true"
        }

        val result = shellForResult(
            shell,
            "export ASH_STANDALONE=1",
            "cd $patchDir",
            "./busybox sh $cmdBuilder",
        )

        if (result.isSuccess) {
            bootSlot = if (!result.out.toString().contains("SLOT=")) {
                ""
            } else {
                result.out.filter { it.startsWith("SLOT=") }[0].removePrefix("SLOT=")
            }
            bootDev =
                result.out.filter { it.startsWith("BOOTIMAGE=") }[0].removePrefix("BOOTIMAGE=")
            Log.i(TAG, "current slot: $bootSlot")
            Log.i(TAG, "current bootimg: $bootDev")
            srcBoot = FileSystemManager.getLocal().getFile(bootDev)
            parseBootimg(bootDev)
        } else {
            error = result.err.joinToString("\n")
        }
        running = false
    }

    fun prepare(mode: PatchMode) {
        viewModelScope.launch(Dispatchers.IO) {
            if (prepared) return@launch
            prepared = true

            running = true
            prepare()
            if (mode != PatchMode.UNPATCH) {
                parseKpimg()
            }
            if (mode == PatchMode.PATCH_AND_INSTALL || mode == PatchMode.UNPATCH || mode == PatchMode.INSTALL_TO_NEXT_SLOT) {
                extractAndParseBootimg(mode)
            }
            running = false
        }
    }

    fun embedKPM(uri: Uri) {
        viewModelScope.launch(Dispatchers.IO) {
            if (running) return@launch
            running = true
            error = ""

            val rand = (1..4).map { ('a'..'z').random() }.joinToString("")
            val kpmFileName = "${rand}.kpm"
            val kpmFile: ExtendedFile = patchDir.getChildFile(kpmFileName)

            Log.i(TAG, "copy kpm to: " + kpmFile.path)
            try {
                uri.inputStream().buffered().use { src ->
                    kpmFile.also {
                        src.copyAndCloseOut(it.newOutputStream())
                    }
                }
            } catch (e: IOException) {
                Log.e(TAG, "Copy kpm error: $e")
            }

            val result = shellForResult(
                shell, "cd $patchDir", "./kptools -l -M ${kpmFile.path}"
            )

            if (result.isSuccess) {
                val ini = Ini(StringReader(result.out.joinToString("\n")))
                val kpm = ini["kpm"]
                if (kpm != null) {
                    val kpmInfo = KPModel.KPMInfo(
                        KPModel.ExtraType.KPM,
                        kpm["name"].toString(),
                        KPModel.TriggerEvent.PRE_KERNEL_INIT.event,
                        "",
                        kpm["version"].toString(),
                        kpm["license"].toString(),
                        kpm["author"].toString(),
                        kpm["description"].toString(),
                    )
                    newExtras.add(kpmInfo)
                    newExtrasFileName.add(kpmFileName)
                }
            } else {
                error = "Invalid KPM\n"
            }
            running = false
        }
    }

    fun doUnpatch() {
        viewModelScope.launch(Dispatchers.IO) {
            patching = true
            patchLog = ""
            Log.i(TAG, "starting unpatching...")

            val logs = object : CallbackList<String>() {
                override fun onAddElement(e: String?) {
                    patchLog += e
                    Log.i(TAG, "" + e)
                    patchLog += "\n"
                }
            }

            val result = shell.newJob().add(
                "export ASH_STANDALONE=1",
                "rm -f ${APApplication.APD_PATH}",
                "rm -rf ${APApplication.APATCH_FOLDER}",
                "cd $patchDir",
                "./busybox sh ./boot_unpatch.sh $bootDev",
            ).to(logs, logs).exec()

            if (result.isSuccess) {
                logs.add(" Unpatch successful")
                needReboot = true
                APApplication.markNeedReboot()
            } else {
                logs.add(" Unpatched failed")
                error = result.err.joinToString("\n")
            }
            logs.add("****************************")

            patchdone = true
            patching = false
        }
    }
    fun isSuExecutable(): Boolean {
        val suFile = File("/system/bin/su")
        return suFile.exists() && suFile.canExecute()
    }
    fun doPatch(mode: PatchMode) {
        viewModelScope.launch(Dispatchers.IO) {
            patching = true
            Log.d(TAG, "starting patching...")

            val apVer = Version.getManagerVersion().second
            val rand = (1..4).map { ('a'..'z').random() }.joinToString("")
            val outFilename = "apatch_patched_${apVer}_${BuildConfig.buildKPV}_${rand}.img"

            val logs = object : CallbackList<String>() {
                override fun onAddElement(e: String?) {
                    patchLog += e
                    Log.d(TAG, "" + e)
                    patchLog += "\n"
                }
            }
            logs.add("****************************")

            var patchCommand = mutableListOf("./busybox sh boot_patch.sh \"$0\" \"$@\"")

            // adapt for 0.10.7 and lower KP
            var isKpOld = false

            if (mode == PatchMode.PATCH_AND_INSTALL || mode == PatchMode.INSTALL_TO_NEXT_SLOT) {

                val KPCheck = shell.newJob().add("truncate $superkey -Z u:r:magisk:s0 -c whoami").exec()

                if (KPCheck.isSuccess && !isSuExecutable()) {
                    patchCommand.addAll(0, listOf("truncate", APApplication.superKey, "-Z", APApplication.MAGISK_SCONTEXT, "-c"))
                    patchCommand.addAll(listOf(superkey, srcBoot.path, "true"))
                } else {
                    patchCommand = mutableListOf("./busybox", "sh", "boot_patch.sh")
                    patchCommand.addAll(listOf(superkey, srcBoot.path, "true"))
                    isKpOld = true
                }

            } else {
                patchCommand.addAll(0, listOf("sh", "-c"))
                patchCommand.addAll(listOf(superkey, srcBoot.path))
            }

            for (i in 0..<newExtrasFileName.size) {
                patchCommand.addAll(listOf("-M", newExtrasFileName[i]))
                val extra = newExtras[i]
                if (extra.args.isNotEmpty()) {
                    patchCommand.addAll(listOf("-A", extra.args))
                }
                if (extra.event.isNotEmpty()) {
                    patchCommand.addAll(listOf("-V", extra.event))
                }
                patchCommand.addAll(listOf("-T", extra.type.desc))
            }
            for (i in 0..<existedExtras.size) {
                val extra = existedExtras[i]
                patchCommand.addAll(listOf("-E", extra.name))
                if (extra.args.isNotEmpty()) {
                    patchCommand.addAll(listOf("-A", extra.args))
                }
                if (extra.event.isNotEmpty()) {
                    patchCommand.addAll(listOf("-V", extra.event))
                }
                patchCommand.addAll(listOf("-T", extra.type.desc))
            }

            val builder = ProcessBuilder(patchCommand)

            Log.i(TAG, "patchCommand: $patchCommand")

            var succ = false

            if (isKpOld) {
                val resultString = "\"" + patchCommand.joinToString(separator = "\" \"") + "\""
                val result = shell.newJob().add(
                    "export ASH_STANDALONE=1",
                    "cd $patchDir",
                    resultString,
                ).to(logs, logs).exec()
                succ = result.isSuccess
            } else {
                builder.environment().put("ASH_STANDALONE", "1")
                builder.directory(patchDir)
                builder.redirectErrorStream(true)

                val process = builder.start()

                Thread {
                    BufferedReader(InputStreamReader(process.inputStream)).use { reader ->
                        var line: String?
                        while (reader.readLine().also { line = it } != null) {
                            patchLog += line
                            Log.i(TAG, "" + line)
                            patchLog += "\n"
                        }
                    }
                }.start()
                succ = process.waitFor() == 0
            }

            if (!succ) {
                val msg = " Patch failed."
                error = msg
//                error += result.err.joinToString("\n")
                logs.add(error)
                logs.add("****************************")
                patching = false
                return@launch
            }

            if (mode == PatchMode.PATCH_AND_INSTALL) {
                logs.add("- Reboot to finish the installation...")
                needReboot = true
                APApplication.markNeedReboot()
            } else if (mode == PatchMode.INSTALL_TO_NEXT_SLOT) {
                logs.add("- Connecting boot hal...")
                val bootctlStatus = shell.newJob().add(
                    "cd $patchDir", "chmod 0777 $patchDir/bootctl", "./bootctl hal-info"
                ).to(logs, logs).exec()
                if (!bootctlStatus.isSuccess) {
                    logs.add("[X] Failed to connect to boot hal, you may need switch slot manually")
                } else {
                    val currSlot = shellForResult(
                        shell, "cd $patchDir", "./bootctl get-current-slot"
                    ).out.toString()
                    val targetSlot = if (currSlot.contains("0")) {
                        1
                    } else {
                        0
                    }
                    logs.add("- Switching to next slot: $targetSlot...")
                    val setNextActiveSlot = shell.newJob().add(
                        "cd $patchDir", "./bootctl set-active-boot-slot $targetSlot"
                    ).exec()
                    if (setNextActiveSlot.isSuccess) {
                        logs.add("- Switch done")
                        logs.add("- Writing boot marker script...")
                        val markBootableScript = shell.newJob().add(
                            "mkdir -p /data/adb/post-fs-data.d && rm -rf /data/adb/post-fs-data.d/post_ota.sh && touch /data/adb/post-fs-data.d/post_ota.sh",
                            "echo \"chmod 0777 $patchDir/bootctl\" > /data/adb/post-fs-data.d/post_ota.sh",
                            "echo \"chown root:root 0777 $patchDir/bootctl\" > /data/adb/post-fs-data.d/post_ota.sh",
                            "echo \"$patchDir/bootctl mark-boot-successful\" > /data/adb/post-fs-data.d/post_ota.sh",
                            "echo >> /data/adb/post-fs-data.d/post_ota.sh",
                            "echo \"rm -rf $patchDir\" >> /data/adb/post-fs-data.d/post_ota.sh",
                            "echo >> /data/adb/post-fs-data.d/post_ota.sh",
                            "echo \"rm -f /data/adb/post-fs-data.d/post_ota.sh\" >> /data/adb/post-fs-data.d/post_ota.sh",
                            "chmod 0777 /data/adb/post-fs-data.d/post_ota.sh",
                            "chown root:root /data/adb/post-fs-data.d/post_ota.sh",
                        ).to(logs, logs).exec()
                        if (markBootableScript.isSuccess) {
                            logs.add("- Boot marker script write done")
                        } else {
                            logs.add("[X] Boot marker scripts write failed")
                        }
                    }
                }
                logs.add("- Reboot to finish the installation...")
                needReboot = true
                APApplication.markNeedReboot()
            } else if (mode == PatchMode.PATCH_ONLY) {
                val newBootFile = patchDir.getChildFile("new-boot.img")
                val outDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
                if (!outDir.exists()) outDir.mkdirs()
                val outPath = File(outDir, outFilename)
                val inputUri = newBootFile.getUri(apApp)

                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    val outUri = createDownloadUri(apApp, outFilename)
                    succ = insertDownload(apApp, outUri, inputUri)
                } else {
                    newBootFile.inputStream().copyAndClose(outPath.outputStream())
                }
                if (succ) {
                    logs.add(" Output file is written to ")
                    logs.add(" ${outPath.path}")
                } else {
                    logs.add(" Write patched boot.img failed")
                }
            }
            logs.add("****************************")
            patchdone = true
            patching = false
        }
    }

    @RequiresApi(Build.VERSION_CODES.Q)
    fun createDownloadUri(context: Context, outFilename: String): Uri? {
        val contentValues = ContentValues().apply {
            put(MediaStore.Downloads.DISPLAY_NAME, outFilename)
            put(MediaStore.Downloads.MIME_TYPE, "application/octet-stream")
            put(MediaStore.Downloads.IS_PENDING, 1)
        }

        val resolver = context.contentResolver
        return resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, contentValues)
    }

    @RequiresApi(Build.VERSION_CODES.Q)
    fun insertDownload(context: Context, outUri: Uri?, inputUri: Uri): Boolean {
        if (outUri == null) return false

        try {
            val resolver = context.contentResolver
            resolver.openInputStream(inputUri)?.use { inputStream ->
                resolver.openOutputStream(outUri)?.use { outputStream ->
                    inputStream.copyTo(outputStream)
                }
            }
            val contentValues = ContentValues().apply {
                put(MediaStore.Downloads.IS_PENDING, 0)
            }
            resolver.update(outUri, contentValues, null, null)

            return true
        } catch (_: FileNotFoundException) {
            return false
        }
    }

    fun File.getUri(context: Context): Uri {
        val authority = "${context.packageName}.fileprovider"
        return FileProvider.getUriForFile(context, authority, this)
    }

}

"""



