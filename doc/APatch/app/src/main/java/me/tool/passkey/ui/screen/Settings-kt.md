响应:

```
嗯，我现在需要分析这个Kotlin代码文件，看看它是做什么的。首先，这个文件路径是APatch/app/src/main/java/me/tool/passkey/ui/screen/Settings.kt，属于APatch项目的一部分，而APatch是一个类似Magisk的Android root解决方案，支持内核模块和系统补丁。

首先，我注意到这个文件是一个Compose组件，属于设置界面。用户界面通常会有各种选项和开关，所以这里可能包含APatch的各种配置选项。让我先看一下主要的函数，SettingScreen()函数，里面用了Scaffold布局，顶部有个TopAppBar，标题是“settings”，所以这是一个典型的设置页面结构。

接下来看里面有哪些组件。首先有几个状态变量，比如kPatchReady和aPatchReady，这些可能表示内核补丁和Android补丁的状态。然后有关于全局命名空间（Global Namespace）的开关，这让我联想到Magisk的挂载命名空间隔离功能。代码里用到了setGlobalNamespaceEnabled函数，可能用来控制是否启用全局命名空间模式。

然后看到SwitchItem组件，用于各种开关选项，比如是否存储超级密钥（super key）。这里有一个bSkipStoreSuperKey的状态，通过APatchKeyHelper来设置，可能涉及安全相关的功能，比如不将密钥存储在本地，增加安全性。

接下来是WebView调试的开关，这可能允许开发者启用WebView的调试功能，对于开发模块有用。检查更新、夜间模式跟随系统、动态颜色主题等选项，这些都是常见的应用设置，属于用户界面定制的部分。

关于语言设置的对话框，使用AppCompatDelegate设置应用的语言，支持多语言切换。还有重置su路径的对话框，这里调用了Natives.resetSuPath，可能修改su命令的位置，需要root权限执行相关命令，比如写入到某个文件。

日志功能部分，用户可以选择保存或分享日志文件。导出日志使用了ActivityResultContracts.CreateDocument，生成.tar.gz文件，路径包含时间戳，便于追踪问题。这里可能调用系统工具生成bugreport，然后处理文件分享。

隐藏APatch管理器的部分被注释掉了，但看起来是允许用户更改包名来避免检测，类似Magisk Hide的功能。这部分可能涉及APK的重打包和重新安装，需要处理文件系统和包管理器。

动态主题选择对话框列出了多种颜色主题，用户选择后保存到SharedPreferences，并刷新主题。这里用到了颜色名称和对应的资源ID，实现主题切换。

在代码中还看到很多与root权限相关的操作，比如rootShellForResult执行命令，修改系统文件。这些操作可能会在设备上留下痕迹，比如修改su路径的文件，或者安装隐藏的APK。

可能的执行步骤大致如下：用户打开设置界面，看到各种开关和选项。调整超级密钥存储设置，切换全局命名空间，启用WebView调试，管理主题和语言，重置su路径，导出日志等。每个操作都会触发相应的函数，修改SharedPreferences或执行底层命令。

对于外部痕迹，比如修改su路径会写入特定文件，生成bugreport日志文件，可能还有隐藏APK的新包名安装。这些都可以通过检查文件系统或已安装应用列表来发现。

比如，重置su路径的shell命令可能是这样的：
```bash
echo "/new/su/path" > /path/to/su_path_file
```
而生成bugreport可能调用Android的dumpstate工具，保存为tar.gz文件。

总之，这个设置界面管理APatch的核心功能，包括安全设置、模块管理、调试选项和界面定制，涉及大量系统级操作和文件处理，需要root权限来执行关键步骤。
```
以下是该Settings.kt文件功能的10步执行顺序分析及关键功能归纳：

---
**功能执行顺序分析：**
1. 初始化应用状态检测（kPatchReady/aPatchReady）
2. 加载超级密钥存储选项（bSkipStoreSuperKey）
3. 检测全局命名空间状态（isGlobalNamespaceEnabled）
4. 渲染WebView调试开关（enableWebDebugging）
5. 处理自动更新设置（checkUpdate）
6. 配置夜间模式相关选项（nightFollowSystem/nightThemeEnabled）
7. 管理动态颜色主题（useSystemDynamicColor/custom_color）
8. 处理SU路径重置对话框（showResetSuPathDialog）
9. 实现多语言选择功能（showLanguageDialog）
10. 处理日志导出与分享（showLogBottomSheet）

---
**核心功能推理及Shell示例：**

**1. 重置SU路径功能**（对应ResetSUPathDialog）：
```bash
# 假设原始su路径：/system/xbin/su
# 用户输入新路径：/data/local/tmp/su
echo "/data/local/tmp/su" > /data/adb/apatch/su_path
chmod 0755 /data/local/tmp/su
```

输入：用户输入有效路径 `/data/local/tmp/su`
输出：Toast显示成功消息，`/data/adb/apatch/su_path` 文件被修改

**2. 生成调试日志**（对应getBugreportFile）：
```bash
# 实际执行的底层命令可能包含：
dumpstate -o /data/user/0/me.tool.passkey/files/bugreport.zip
tar -czvf APatch_bugreport_2024-02-22_14-30.tar.gz /data/user/0/me.tool.passkey/files/
```

**3. 全局命名空间控制**（setGlobalNamespaceEnabled）：
```bash
# 修改内核参数文件
echo 1 > /sys/module/apatch/parameters/global_namespace
```

---
**文件系统访问痕迹：**
1. SU路径配置文件：`/data/adb/apatch/su_path`
2. 调试日志文件：`/data/user/0/[包名]/files/APatch_bugreport_*.tar.gz`
3. 共享偏好设置：`/data/data/[包名]/shared_prefs/*.xml`
4. 隐藏APK安装包：`/data/app/[随机包名]-*`

---
**Android系统可见痕迹：**
1. 通过`ps -A | grep apatch`可见后台进程
2. 通过`ls -l /system/xbin/su`查看修改后的SU路径
3. 通过`settings list global`可查看WebView调试标记
4. 通过`pm list packages`可能发现隐藏包名

---
**功能总结（第1部分）：**
该文件实现了APatch的核心配置界面，主要功能包括：
- 安全控制：超级密钥存储管理、SU路径修改
- 内核模块：全局命名空间模式切换
- 开发支持：WebView调试启用、日志收集系统
- 界面定制：动态颜色主题、多语言切换、夜间模式
- 系统集成：通过rootShellForResult执行特权命令
- 隐蔽功能：被注释的包名随机化代码（疑似防检测）
提示器:

这是路径为APatch/app/src/main/java/me/tool/passkey/ui/screen/Settings.kt的apatch `The patching of Android kernel and Android system`实现的一部分，
它的项目描述如下`
A new kernel-based root solution for Android devices.
APM: Support for modules similar to Magisk.
KPM: Support for modules that allow you to inject any code into the kernel (Provides kernel function inline-hook and syscall-table-hook).
APatch relies on KernelPatch.
The APatch UI and the APModule source code have been derived and modified from KernelSU.
` 
请按照最可能的执行顺序(非行号)列举一下它的功能, 建议10步，　
如果你能推理出它是什么功能的实现，请用shell代码举例, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，涉及到对文件系统的访问，请详细介绍一下，
如果这个程序生成了哪些android外部进程可以看到的痕迹，请提示一下，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能

```kotlin
package me.tool.passkey.ui.screen

import android.content.Intent
import android.net.Uri
import android.os.Build
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.annotation.StringRes
import androidx.appcompat.app.AppCompatDelegate
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.wrapContentHeight
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.ColorLens
import androidx.compose.material.icons.filled.Commit
import androidx.compose.material.icons.filled.DarkMode
import androidx.compose.material.icons.filled.DeveloperMode
import androidx.compose.material.icons.filled.Engineering
import androidx.compose.material.icons.filled.FormatColorFill
import androidx.compose.material.icons.filled.InvertColors
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Save
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Translate
import androidx.compose.material.icons.filled.Update
import androidx.compose.material3.AlertDialogDefaults
import androidx.compose.material3.BasicAlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.livedata.observeAsState
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.res.stringArrayResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.LineHeightStyle
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.window.DialogWindowProvider
import androidx.core.content.FileProvider
import androidx.core.os.LocaleListCompat
import com.ramcosta.composedestinations.annotation.Destination
import com.ramcosta.composedestinations.annotation.RootGraph
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import me.tool.passkey.APApplication
import me.tool.passkey.BuildConfig
import me.tool.passkey.Natives
import me.tool.passkey.R
import me.tool.passkey.ui.component.SwitchItem
import me.tool.passkey.ui.component.rememberConfirmDialog
import me.tool.passkey.ui.component.rememberLoadingDialog
import me.tool.passkey.ui.theme.refreshTheme
import me.tool.passkey.util.APatchKeyHelper
import me.tool.passkey.util.getBugreportFile
import me.tool.passkey.util.hideapk.HideAPK
import me.tool.passkey.util.isGlobalNamespaceEnabled
import me.tool.passkey.util.outputStream
import me.tool.passkey.util.rootShellForResult
import me.tool.passkey.util.setGlobalNamespaceEnabled
import me.tool.passkey.util.ui.APDialogBlurBehindUtils
import me.tool.passkey.util.ui.LocalSnackbarHost
import me.tool.passkey.util.ui.NavigationBarsSpacer
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter
import java.util.Locale

@Destination<RootGraph>
@Composable
@OptIn(ExperimentalMaterial3Api::class)
fun SettingScreen() {
    val state by APApplication.apStateLiveData.observeAsState(APApplication.State.UNKNOWN_STATE)
    val kPatchReady = state != APApplication.State.UNKNOWN_STATE
    val aPatchReady =
        (state == APApplication.State.ANDROIDPATCH_INSTALLING || state == APApplication.State.ANDROIDPATCH_INSTALLED || state == APApplication.State.ANDROIDPATCH_NEED_UPDATE)
    //val bIsManagerHide = AppUtils.getPackageName() != APPLICATION_ID
    var isGlobalNamespaceEnabled by rememberSaveable {
        mutableStateOf(false)
    }
    var bSkipStoreSuperKey by rememberSaveable {
        mutableStateOf(APatchKeyHelper.shouldSkipStoreSuperKey())
    }
    if (kPatchReady && aPatchReady) {
        isGlobalNamespaceEnabled = isGlobalNamespaceEnabled()
    }

    val snackBarHost = LocalSnackbarHost.current

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.settings)) },
            )
        },
        snackbarHost = { SnackbarHost(snackBarHost) }
    ) { paddingValues ->

        val loadingDialog = rememberLoadingDialog()
        val clearKeyDialog = rememberConfirmDialog(
            onConfirm = {
                APatchKeyHelper.clearConfigKey()
                APApplication.superKey = ""
            }
        )

        val showLanguageDialog = rememberSaveable { mutableStateOf(false) }
        LanguageDialog(showLanguageDialog)

        /*val showRandomizePkgNameDialog = rememberSaveable { mutableStateOf(false) }
        if (showRandomizePkgNameDialog.value) {
            RandomizePkgNameDialog(showDialog = showRandomizePkgNameDialog)
        }*/

        val showResetSuPathDialog = remember { mutableStateOf(false) }
        if (showResetSuPathDialog.value) {
            ResetSUPathDialog(showResetSuPathDialog)
        }

        val showThemeChooseDialog = remember { mutableStateOf(false) }
        if (showThemeChooseDialog.value) {
            ThemeChooseDialog(showThemeChooseDialog)
        }

        var showLogBottomSheet by remember { mutableStateOf(false) }

        val scope = rememberCoroutineScope()
        val context = LocalContext.current
        val logSavedMessage = stringResource(R.string.log_saved)
        val exportBugreportLauncher = rememberLauncherForActivityResult(
            ActivityResultContracts.CreateDocument("application/gzip")
        ) { uri: Uri? ->
            if (uri != null) {
                scope.launch(Dispatchers.IO) {
                    loadingDialog.show()
                    uri.outputStream().use { output ->
                        getBugreportFile(context).inputStream().use {
                            it.copyTo(output)
                        }
                    }
                    loadingDialog.hide()
                    snackBarHost.showSnackbar(message = logSavedMessage)
                }
            }
        }

        Column(
            modifier = Modifier
                .padding(paddingValues)
                .fillMaxWidth()
                .verticalScroll(rememberScrollState()),
        ) {

            val context = LocalContext.current
            val scope = rememberCoroutineScope()
            val prefs = APApplication.sharedPreferences

            // clear key
            if (kPatchReady) {
                val clearKeyDialogTitle = stringResource(id = R.string.clear_super_key)
                val clearKeyDialogContent =
                    stringResource(id = R.string.settings_clear_super_key_dialog)
                ListItem(leadingContent = {
                    Icon(
                        Icons.Filled.Key, stringResource(id = R.string.super_key)
                    )
                },
                    headlineContent = { Text(stringResource(id = R.string.clear_super_key)) },
                    modifier = Modifier.clickable {
                        clearKeyDialog.showConfirm(
                            title = clearKeyDialogTitle,
                            content = clearKeyDialogContent,
                            markdown = false,
                        )

                    })
            }

            // store key local?
            SwitchItem(icon = Icons.Filled.Key,
                title = stringResource(id = R.string.settings_donot_store_superkey),
                summary = stringResource(id = R.string.settings_donot_store_superkey_summary),
                checked = bSkipStoreSuperKey,
                onCheckedChange = {
                    bSkipStoreSuperKey = it
                    APatchKeyHelper.setShouldSkipStoreSuperKey(bSkipStoreSuperKey)
                })

            // Global mount
            if (kPatchReady && aPatchReady) {
                SwitchItem(icon = Icons.Filled.Engineering,
                    title = stringResource(id = R.string.settings_global_namespace_mode),
                    summary = stringResource(id = R.string.settings_global_namespace_mode_summary),
                    checked = isGlobalNamespaceEnabled,
                    onCheckedChange = {
                        setGlobalNamespaceEnabled(
                            if (isGlobalNamespaceEnabled) {
                                "0"
                            } else {
                                "1"
                            }
                        )
                        isGlobalNamespaceEnabled = it
                    })
            }

            // WebView Debug
            if (aPatchReady) {
                var enableWebDebugging by rememberSaveable {
                    mutableStateOf(
                        prefs.getBoolean("enable_web_debugging", false)
                    )
                }
                SwitchItem(
                    icon = Icons.Filled.DeveloperMode,
                    title = stringResource(id = R.string.enable_web_debugging),
                    summary = stringResource(id = R.string.enable_web_debugging_summary),
                    checked = enableWebDebugging
                ) {
                    APApplication.sharedPreferences.edit().putBoolean("enable_web_debugging", it)
                        .apply()
                    enableWebDebugging = it
                }
            }

            // Check Update
            var checkUpdate by rememberSaveable {
                mutableStateOf(
                    prefs.getBoolean("check_update", true)
                )
            }

            SwitchItem(
                icon = Icons.Filled.Update,
                title = stringResource(id = R.string.settings_check_update),
                summary = stringResource(id = R.string.settings_check_update_summary),
                checked = checkUpdate
            ) {
                prefs.edit().putBoolean("check_update", it).apply()
                checkUpdate = it
            }

            // Night Mode Follow System
            var nightFollowSystem by rememberSaveable {
                mutableStateOf(
                    prefs.getBoolean("night_mode_follow_sys", true)
                )
            }
            SwitchItem(
                icon = Icons.Filled.InvertColors,
                title = stringResource(id = R.string.settings_night_mode_follow_sys),
                summary = stringResource(id = R.string.settings_night_mode_follow_sys_summary),
                checked = nightFollowSystem
            ) {
                prefs.edit().putBoolean("night_mode_follow_sys", it).apply()
                nightFollowSystem = it
                refreshTheme.value = true
            }

            // Custom Night Theme Switch
            if (!nightFollowSystem) {
                var nightThemeEnabled by rememberSaveable {
                    mutableStateOf(
                        prefs.getBoolean("night_mode_enabled", false)
                    )
                }
                SwitchItem(
                    icon = Icons.Filled.DarkMode,
                    title = stringResource(id = R.string.settings_night_theme_enabled),
                    checked = nightThemeEnabled
                ) {
                    prefs.edit().putBoolean("night_mode_enabled", it).apply()
                    nightThemeEnabled = it
                    refreshTheme.value = true
                }
            }

            // System dynamic color theme
            val isDynamicColorSupport = Build.VERSION.SDK_INT >= Build.VERSION_CODES.S
            if (isDynamicColorSupport) {
                var useSystemDynamicColor by rememberSaveable {
                    mutableStateOf(
                        prefs.getBoolean("use_system_color_theme", true)
                    )
                }
                SwitchItem(
                    icon = Icons.Filled.ColorLens,
                    title = stringResource(id = R.string.settings_use_system_color_theme),
                    summary = stringResource(id = R.string.settings_use_system_color_theme_summary),
                    checked = useSystemDynamicColor
                ) {
                    prefs.edit().putBoolean("use_system_color_theme", it).apply()
                    useSystemDynamicColor = it
                    refreshTheme.value = true
                }

                if (!useSystemDynamicColor) {
                    ListItem(headlineContent = {
                        Text(text = stringResource(id = R.string.settings_custom_color_theme))
                    }, modifier = Modifier.clickable {
                        showThemeChooseDialog.value = true
                    }, supportingContent = {
                        val colorMode = prefs.getString("custom_color", "blue")
                        Text(
                            text = stringResource(colorNameToString(colorMode.toString())),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.outline
                        )
                    }, leadingContent = { Icon(Icons.Filled.FormatColorFill, null) })

                }
            } else {
                ListItem(headlineContent = {
                    Text(text = stringResource(id = R.string.settings_custom_color_theme))
                }, modifier = Modifier.clickable {
                    showThemeChooseDialog.value = true
                }, supportingContent = {
                    val colorMode = prefs.getString("custom_color", "blue")
                    Text(
                        text = stringResource(colorNameToString(colorMode.toString())),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.outline
                    )
                }, leadingContent = { Icon(Icons.Filled.FormatColorFill, null) })
            }

            /*
            // hide manager
            if (kPatchReady && !bIsManagerHide) {
                ListItem(
                    leadingContent = {
                        Icon(
                            Icons.Filled.Masks,
                            stringResource(id = R.string.hide_apatch_manager)
                        )
                    },
                    supportingContent = {
                        Text(text = stringResource(id = R.string.hide_apatch_manager_summary))
                    },
                    headlineContent = {
                        Text(
                            stringResource(id = R.string.hide_apatch_manager),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.outline
                        )
                    },
                    modifier = Modifier.clickable {
                        showRandomizePkgNameDialog.value = true
                    }
                )
            }*/

            // su path
            if (kPatchReady) {
                ListItem(leadingContent = {
                    Icon(
                        Icons.Filled.Commit, stringResource(id = R.string.setting_reset_su_path)
                    )
                },
                    supportingContent = {},
                    headlineContent = { Text(stringResource(id = R.string.setting_reset_su_path)) },
                    modifier = Modifier.clickable {
                        showResetSuPathDialog.value = true
                    })
            }

            // language
            ListItem(headlineContent = {
                Text(text = stringResource(id = R.string.settings_app_language))
            }, modifier = Modifier.clickable {
                showLanguageDialog.value = true
            }, supportingContent = {
                Text(text = AppCompatDelegate.getApplicationLocales()[0]?.displayLanguage?.replaceFirstChar {
                    if (it.isLowerCase()) it.titlecase(
                        Locale.getDefault()
                    ) else it.toString()
                } ?: stringResource(id = R.string.system_default),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.outline)
            }, leadingContent = { Icon(Icons.Filled.Translate, null) })

            // log
            ListItem(leadingContent = {
                Icon(
                    Icons.Filled.BugReport, stringResource(id = R.string.send_log)
                )
            },
                headlineContent = { Text(stringResource(id = R.string.send_log)) },
                modifier = Modifier.clickable {
                    showLogBottomSheet = true
                })
            if (showLogBottomSheet) {
                ModalBottomSheet(
                    onDismissRequest = { showLogBottomSheet = false },
                    contentWindowInsets = { WindowInsets(0, 0, 0, 0) },
                    content = {
                        Row(
                            modifier = Modifier
                                .padding(10.dp)
                                .align(Alignment.CenterHorizontally)

                        ) {
                            Box {
                                Column(modifier = Modifier
                                    .padding(16.dp)
                                    .clickable {
                                        scope.launch {
                                            val formatter =
                                                DateTimeFormatter.ofPattern("yyyy-MM-dd_HH_mm")
                                            val current = LocalDateTime.now().format(formatter)
                                            exportBugreportLauncher.launch("APatch_bugreport_${current}.tar.gz")
                                            showLogBottomSheet = false
                                        }
                                    }
                                ) {
                                    Icon(
                                        Icons.Filled.Save,
                                        contentDescription = null,
                                        modifier = Modifier.align(Alignment.CenterHorizontally)
                                    )
                                    Text(text = stringResource(id = R.string.save_log),
                                        modifier = Modifier.padding(top = 16.dp),
                                        textAlign = TextAlign.Center.also {
                                            LineHeightStyle(
                                                alignment = LineHeightStyle.Alignment.Center,
                                                trim = LineHeightStyle.Trim.None
                                            )
                                        }

                                    )
                                }

                            }
                            Box {
                                Column(modifier = Modifier
                                    .padding(16.dp)
                                    .clickable {
                                        scope.launch {
                                            val bugreport = loadingDialog.withLoading {
                                                withContext(Dispatchers.IO) {
                                                    getBugreportFile(context)
                                                }
                                            }

                                            val uri: Uri = FileProvider.getUriForFile(
                                                context,
                                                "${BuildConfig.APPLICATION_ID}.fileprovider",
                                                bugreport
                                            )

                                            val shareIntent = Intent(Intent.ACTION_SEND).apply {
                                                putExtra(Intent.EXTRA_STREAM, uri)
                                                setDataAndType(uri, "application/gzip")
                                                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                                            }

                                            context.startActivity(
                                                Intent.createChooser(
                                                    shareIntent,
                                                    context.getString(R.string.send_log)
                                                )
                                            )
                                            showLogBottomSheet = false
                                        }
                                    }) {
                                    Icon(
                                        Icons.Filled.Share,
                                        contentDescription = null,
                                        modifier = Modifier.align(Alignment.CenterHorizontally)
                                    )
                                    Text(text = stringResource(id = R.string.send_log),
                                        modifier = Modifier.padding(top = 16.dp),
                                        textAlign = TextAlign.Center.also {
                                            LineHeightStyle(
                                                alignment = LineHeightStyle.Alignment.Center,
                                                trim = LineHeightStyle.Trim.None
                                            )
                                        }

                                    )
                                }

                            }
                        }
                        NavigationBarsSpacer()
                    })
            }


        }

    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ThemeChooseDialog(showDialog: MutableState<Boolean>) {
    val prefs = APApplication.sharedPreferences

    BasicAlertDialog(
        onDismissRequest = { showDialog.value = false }, properties = DialogProperties(
            decorFitsSystemWindows = true,
            usePlatformDefaultWidth = false,
        )
    ) {
        Surface(
            modifier = Modifier
                .width(310.dp)
                .wrapContentHeight(),
            shape = RoundedCornerShape(30.dp),
            tonalElevation = AlertDialogDefaults.TonalElevation,
            color = AlertDialogDefaults.containerColor,
        ) {
            LazyColumn {
                items(colorsList()) {
                    ListItem(headlineContent = { Text(text = stringResource(it.nameId)) },
                        modifier = Modifier.clickable {
                            showDialog.value = false
                            prefs.edit().putString("custom_color", it.name).apply()
                            refreshTheme.value = true
                        })
                }

            }

            val dialogWindowProvider = LocalView.current.parent as DialogWindowProvider
            APDialogBlurBehindUtils.setupWindowBlurListener(dialogWindowProvider.window)
        }
    }

}

private data class APColor(
    val name: String, @StringRes val nameId: Int
)

private fun colorsList(): List<APColor> {
    return listOf(
        APColor("amber", R.string.amber_theme),
        APColor("blue_grey", R.string.blue_grey_theme),
        APColor("blue", R.string.blue_theme),
        APColor("brown", R.string.brown_theme),
        APColor("cyan", R.string.cyan_theme),
        APColor("deep_orange", R.string.deep_orange_theme),
        APColor("deep_purple", R.string.deep_purple_theme),
        APColor("green", R.string.green_theme),
        APColor("indigo", R.string.indigo_theme),
        APColor("light_blue", R.string.light_blue_theme),
        APColor("light_green", R.string.light_green_theme),
        APColor("lime", R.string.lime_theme),
        APColor("orange", R.string.orange_theme),
        APColor("pink", R.string.pink_theme),
        APColor("purple", R.string.purple_theme),
        APColor("red", R.string.red_theme),
        APColor("sakura", R.string.sakura_theme),
        APColor("teal", R.string.teal_theme),
        APColor("yellow", R.string.yellow_theme),
    )
}

@Composable
private fun colorNameToString(colorName: String): Int {
    return colorsList().find { it.name == colorName }?.nameId ?: R.string.blue_theme
}

val suPathChecked: (path: String) -> Boolean = {
    it.startsWith("/") && it.trim().length > 1
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ResetSUPathDialog(showDialog: MutableState<Boolean>) {
    val context = LocalContext.current
    var suPath by remember { mutableStateOf(Natives.suPath()) }
    BasicAlertDialog(
        onDismissRequest = { showDialog.value = false }, properties = DialogProperties(
            decorFitsSystemWindows = true,
            usePlatformDefaultWidth = false,
        )
    ) {
        Surface(
            modifier = Modifier
                .width(310.dp)
                .wrapContentHeight(),
            shape = RoundedCornerShape(30.dp),
            tonalElevation = AlertDialogDefaults.TonalElevation,
            color = AlertDialogDefaults.containerColor,
        ) {
            Column(modifier = Modifier.padding(PaddingValues(all = 24.dp))) {
                Box(
                    Modifier
                        .padding(PaddingValues(bottom = 16.dp))
                        .align(Alignment.Start)
                ) {
                    Text(
                        text = stringResource(id = R.string.setting_reset_su_path),
                        style = MaterialTheme.typography.headlineSmall
                    )
                }
                Box(
                    Modifier
                        .weight(weight = 1f, fill = false)
                        .padding(PaddingValues(bottom = 12.dp))
                        .align(Alignment.Start)
                ) {
                    OutlinedTextField(
                        value = suPath,
                        onValueChange = {
                            suPath = it
                        },
                        label = { Text(stringResource(id = R.string.setting_reset_su_new_path)) },
                        visualTransformation = VisualTransformation.None,
                    )
                }

                Row(
                    modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End
                ) {
                    TextButton(onClick = { showDialog.value = false }) {

                        Text(stringResource(id = android.R.string.cancel))
                    }

                    Button(enabled = suPathChecked(suPath), onClick = {
                        showDialog.value = false
                        val success = Natives.resetSuPath(suPath)
                        Toast.makeText(
                            context,
                            if (success) R.string.success else R.string.failure,
                            Toast.LENGTH_SHORT
                        ).show()
                        rootShellForResult("echo $suPath > ${APApplication.SU_PATH_FILE}")
                    }) {
                        Text(stringResource(id = android.R.string.ok))
                    }
                }
            }
            val dialogWindowProvider = LocalView.current.parent as DialogWindowProvider
            APDialogBlurBehindUtils.setupWindowBlurListener(dialogWindowProvider.window)
        }
    }
}


@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RandomizePkgNameDialog(showDialog: MutableState<Boolean>) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    var newPackageName by remember { mutableStateOf("") }
    var enable by remember { mutableStateOf(false) }
    BasicAlertDialog(
        onDismissRequest = { showDialog.value = false }, properties = DialogProperties(
            decorFitsSystemWindows = true,
            usePlatformDefaultWidth = false,

            )
    ) {
        Surface(
            modifier = Modifier
                .width(310.dp)
                .wrapContentHeight(),
            shape = RoundedCornerShape(30.dp),
            tonalElevation = AlertDialogDefaults.TonalElevation,
            color = AlertDialogDefaults.containerColor,
        ) {
            Column(modifier = Modifier.padding(PaddingValues(all = 24.dp))) {

                Box(
                    Modifier
                        .padding(PaddingValues(bottom = 16.dp))
                        .align(Alignment.Start)
                ) {
                    Text(
                        text = stringResource(id = R.string.hide_apatch_manager),
                        style = MaterialTheme.typography.headlineSmall
                    )
                }

                Box(
                    Modifier
                        .weight(weight = 1f, fill = false)
                        .padding(PaddingValues(bottom = 12.dp))
                        .align(Alignment.Start)
                ) {
                    Text(
                        text = stringResource(id = R.string.hide_apatch_dialog_summary),
                        style = MaterialTheme.typography.bodyMedium
                    )
                }

                Box(
                    Modifier
                        .weight(weight = 1f, fill = false)
                        .padding(PaddingValues(bottom = 12.dp))
                        .align(Alignment.Start)
                ) {
                    OutlinedTextField(
                        value = newPackageName,
                        onValueChange = {
                            newPackageName = it
                            enable = newPackageName.isNotEmpty()
                        },
                        label = { Text(stringResource(id = R.string.hide_apatch_dialog_new_manager_name)) },
                        visualTransformation = VisualTransformation.None,
                    )
                }

                // Buttons
                Row(
                    modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End
                ) {
                    TextButton(onClick = { showDialog.value = false }) {
                        Text(stringResource(id = android.R.string.cancel))
                    }

                    Button(onClick = {
                        showDialog.value = false
                        scope.launch { HideAPK.hide(context, newPackageName) }
                    }) {
                        Text(stringResource(id = android.R.string.ok))
                    }
                }
            }
            val dialogWindowProvider = LocalView.current.parent as DialogWindowProvider
            APDialogBlurBehindUtils.setup
"""




