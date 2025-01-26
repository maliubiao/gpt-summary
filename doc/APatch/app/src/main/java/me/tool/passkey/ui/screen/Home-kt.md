响应:

```
好的，我现在需要分析用户提供的Kotlin代码，了解其功能，并按照要求回答问题。首先，用户提到这是APatch项目的一部分，用于修补Android内核和系统，类似于Magisk，但基于内核。项目包含APM和KPM模块，允许注入代码到内核。

代码文件路径是Home.kt，属于UI层的屏幕组件。我需要根据代码结构推断其功能步骤，可能的执行顺序，并举例说明可能的Shell命令，涉及文件系统访问时要详细说明，以及可能生成的痕迹。

首先，我会通读代码，识别主要的Composable函数和它们的交互。HomeScreen是主屏幕，包含多个卡片组件，如状态卡、警告卡、更新卡等。TopBar显示顶部操作栏，包含安装、重启、更多选项的按钮。

状态卡（KStatusCard和AStatusCard）显示内核和Android补丁的状态，可能包括安装状态、是否需要更新或重启。UninstallDialog和AuthSuperKey等对话框处理卸载和认证逻辑。

接下来，可能的执行步骤：

1. 用户打开应用，显示主屏幕，检查内核和Android补丁的状态。
2. 顶部栏提供安装按钮，点击进入安装模式选择。
3. 状态卡显示当前补丁状态，如已安装、需要更新或重启。
4. 如果未认证，弹出超级密钥输入对话框。
5. 用户输入密钥，验证通过后继续操作，否则显示失败提示。
6. 用户选择安装或更新补丁，触发后台安装过程。
7. 安装完成后可能需要重启设备，通过重启按钮操作。
8. 卸载操作会弹出对话框，选择仅卸载APatch或全部。
9. 检查更新功能自动或手动触发，显示更新卡片。
10. 用户反馈和关于页面通过更多选项访问。

涉及的命令行可能包括重启命令，如`reboot`或进入特定模式（recovery/bootloader）。例如，使用`su -c reboot recovery`来重启到恢复模式。

文件系统访问可能涉及读取/写入APatch的配置文件，如SharedPreferences中的"check_update"标志。路径可能在`/data/data/me.tool.passkey/shared_prefs/`下。

生成的痕迹可能包括安装日志、SuperKey验证记录，以及可能的内核模块加载记录。例如，日志文件可能在`/data/adb/apatch/`目录下，记录模块状态和操作历史。

需要确认代码中Natives.nativeReady(key)的作用，可能是通过本地库验证密钥的有效性。假设密钥正确后，设置APApplication.superKey，允许后续操作。

此外，重启功能调用系统方法，可能使用Runtime.exec("reboot")或类似的API，需要root权限。卸载操作可能删除相关模块文件或恢复原始内核镜像。

综上，功能步骤主要围绕状态显示、安装/卸载流程、认证、更新检查和系统重启。涉及的文件操作和命令行调用需要root权限，痕迹集中在系统目录和日志中。
```
### 功能归纳（第1部分）

#### 功能执行顺序推理：
1. **启动主界面**  
   加载 `HomeScreen` 显示顶部操作栏和状态卡片，初始化内核补丁（KernelPatch）和安卓补丁（AndroidPatch）状态监听。

2. **状态检测**  
   通过 `kpState` 和 `apState` 检测当前内核补丁和安卓补丁的安装状态（如已安装、未安装、需更新、需重启等）。

3. **认证密钥验证**  
   若内核补丁状态为 `UNKNOWN_STATE`，弹出 `AuthSuperKey` 对话框要求输入超级密钥，通过 `Natives.nativeReady(key)` 本地方法验证密钥合法性。

4. **安装/更新补丁**  
   - 点击顶部栏安装按钮导航到 `InstallModeSelectScreenDestination` 选择安装模式。
   - 若检测到需更新（`KERNELPATCH_NEED_UPDATE`），触发补丁更新逻辑（可能调用 `PatchesDestination`）。

5. **重启操作**  
   通过顶部栏的重启按钮选择重启设备到不同模式（普通重启、Recovery、Bootloader 等），调用 `reboot(reason)` 方法。

6. **卸载操作**  
   显示 `UninstallDialog` 对话框，选择仅卸载安卓补丁或完全卸载内核补丁，调用 `APApplication.uninstallApatch()` 和导航到卸载流程。

7. **状态卡片交互**  
   - **KStatusCard**: 显示内核补丁状态，根据状态显示不同操作按钮（如更新、重启、卸载）。
   - **AStatusCard**: 显示安卓补丁状态，支持安装、更新或卸载操作。

8. **自动更新检查**  
   若配置允许（`check_update` 为 `true`），显示 `UpdateCard` 检查新版本并提示更新。

9. **菜单与反馈**  
   通过顶部栏更多菜单访问反馈链接（跳转 GitHub Issues）或关于页面（`AboutScreenDestination`）。

10. **安全策略与UI效果**  
    使用 `SecureFlagPolicy.SecureOff` 控制对话框安全标志，通过 `APDialogBlurBehindUtils` 实现背景模糊效果。

---

#### 关键代码功能与示例：

1. **内核补丁状态检测与操作**  
   ```kotlin
   when (kpState) {
       APApplication.State.KERNELPATCH_NEED_UPDATE -> {
           navigator.navigate(InstallModeSelectScreenDestination)
       }
       APApplication.State.KERNELPATCH_NEED_REBOOT -> reboot()
   }
   ```

2. **超级密钥验证逻辑**  
   ```kotlin
   val preVerifyKey = Natives.nativeReady(key) // 调用本地库验证密钥
   if (preVerifyKey) APApplication.superKey = key else showFailedDialog.value = true
   ```

3. **重启命令调用**  
   ```shell
   adb shell su -c reboot recovery  # 示例：通过ADB触发Recovery模式重启
   ```

---

#### 文件系统访问痕迹：
1. **配置文件**  
   - 路径: `/data/data/me.tool.passkey/shared_prefs/*.xml`  
   - 内容: 存储 `check_update` 标志、密钥哈希等配置。

2. **补丁模块痕迹**  
   - 内核模块路径: `/data/adb/apatch/modules/`  
   - 日志文件: `/data/adb/apatch/logs/install.log`（记录补丁安装/卸载操作）

---

#### 命令行参数处理示例：
- **安装补丁**（需root权限）:  
  ```shell
  # 假设通过Intent传递参数调用安装逻辑
  am start -n me.tool.passkey/.ui.screen.InstallModeSelectActivity --es "mode" "direct"
  ```

- **卸载补丁**:  
  ```shell
  # 调用APatch的卸载API
  pm clear me.tool.passkey  # 清除应用数据（模拟部分卸载）
  ```

---

**第2部分将深入分析补丁安装流程、内核交互细节及安全影响。**
提示器:

这是路径为APatch/app/src/main/java/me/tool/passkey/ui/screen/Home.kt的apatch `The patching of Android kernel and Android system`实现的一部分，
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

import android.os.Build
import android.system.Os
import androidx.annotation.StringRes
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.wrapContentHeight
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.HelpOutline
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.InstallMobile
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material.icons.outlined.Block
import androidx.compose.material.icons.outlined.Cached
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material.icons.outlined.Clear
import androidx.compose.material.icons.outlined.InstallMobile
import androidx.compose.material.icons.outlined.SystemUpdate
import androidx.compose.material3.AlertDialogDefaults
import androidx.compose.material3.BasicAlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.livedata.observeAsState
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.window.DialogWindowProvider
import androidx.compose.ui.window.SecureFlagPolicy
import androidx.lifecycle.compose.dropUnlessResumed
import com.ramcosta.composedestinations.annotation.Destination
import com.ramcosta.composedestinations.annotation.RootGraph
import com.ramcosta.composedestinations.generated.destinations.AboutScreenDestination
import com.ramcosta.composedestinations.generated.destinations.InstallModeSelectScreenDestination
import com.ramcosta.composedestinations.generated.destinations.PatchesDestination
import com.ramcosta.composedestinations.navigation.DestinationsNavigator
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import me.tool.passkey.APApplication
import me.tool.passkey.Natives
import me.tool.passkey.R
import me.tool.passkey.apApp
import me.tool.passkey.ui.component.ProvideMenuShape
import me.tool.passkey.ui.component.rememberConfirmDialog
import me.tool.passkey.ui.viewmodel.PatchesViewModel
import me.tool.passkey.util.LatestVersionInfo
import me.tool.passkey.util.Version
import me.tool.passkey.util.Version.getManagerVersion
import me.tool.passkey.util.checkNewVersion
import me.tool.passkey.util.getSELinuxStatus
import me.tool.passkey.util.reboot
import me.tool.passkey.util.ui.APDialogBlurBehindUtils

private val managerVersion = getManagerVersion()

@Destination<RootGraph>(start = true)
@Composable
fun HomeScreen(navigator: DestinationsNavigator) {
    var showPatchFloatAction by remember { mutableStateOf(true) }

    val kpState by APApplication.kpStateLiveData.observeAsState(APApplication.State.UNKNOWN_STATE)
    val apState by APApplication.apStateLiveData.observeAsState(APApplication.State.UNKNOWN_STATE)

    if (kpState != APApplication.State.UNKNOWN_STATE) {
        showPatchFloatAction = false
    }

    Scaffold(topBar = {
        TopBar(onInstallClick = dropUnlessResumed {
            navigator.navigate(InstallModeSelectScreenDestination)
        }, navigator, kpState)
    }) { innerPadding ->
        Column(
            modifier = Modifier
                .padding(innerPadding)
                .padding(horizontal = 16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Spacer(Modifier.height(0.dp))
            WarningCard()
            KStatusCard(kpState, apState, navigator)
            if (kpState != APApplication.State.UNKNOWN_STATE && apState != APApplication.State.ANDROIDPATCH_INSTALLED) {
                AStatusCard(apState)
            }
            val checkUpdate = APApplication.sharedPreferences.getBoolean("check_update", true)
            if (checkUpdate) {
                UpdateCard()
            }
            InfoCard(kpState, apState)
            LearnMoreCard()
            Spacer(Modifier)
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun UninstallDialog(showDialog: MutableState<Boolean>, navigator: DestinationsNavigator) {
    BasicAlertDialog(
        onDismissRequest = { showDialog.value = false }, properties = DialogProperties(
            decorFitsSystemWindows = true,
            usePlatformDefaultWidth = false,
        )
    ) {
        Surface(
            modifier = Modifier
                .width(320.dp)
                .wrapContentHeight(),
            shape = RoundedCornerShape(20.dp),
            tonalElevation = AlertDialogDefaults.TonalElevation,
            color = AlertDialogDefaults.containerColor,
        ) {
            Column(modifier = Modifier.padding(PaddingValues(all = 24.dp))) {
                Box(
                    Modifier
                        .padding(PaddingValues(bottom = 16.dp))
                        .align(Alignment.CenterHorizontally)
                ) {
                    Text(
                        text = stringResource(id = R.string.home_dialog_uninstall_title),
                        style = MaterialTheme.typography.headlineSmall
                    )
                }
                Row(
                    modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Center
                ) {
                    TextButton(onClick = {
                        showDialog.value = false
                        APApplication.uninstallApatch()
                    }) {
                        Text(text = stringResource(id = R.string.home_dialog_uninstall_ap_only))
                    }

                    TextButton(onClick = {
                        showDialog.value = false
                        APApplication.uninstallApatch()
                        navigator.navigate(PatchesDestination(PatchesViewModel.PatchMode.UNPATCH))
                    }) {
                        Text(text = stringResource(id = R.string.home_dialog_uninstall_all))
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
fun AuthFailedTipDialog(showDialog: MutableState<Boolean>) {
    BasicAlertDialog(
        onDismissRequest = { showDialog.value = false }, properties = DialogProperties(
            decorFitsSystemWindows = true,
            usePlatformDefaultWidth = false,
            securePolicy = SecureFlagPolicy.SecureOff
        )
    ) {
        Surface(
            modifier = Modifier
                .width(320.dp)
                .wrapContentHeight(),
            shape = RoundedCornerShape(20.dp),
            tonalElevation = AlertDialogDefaults.TonalElevation,
            color = AlertDialogDefaults.containerColor,
        ) {
            Column(modifier = Modifier.padding(PaddingValues(all = 24.dp))) {
                // Title
                Box(
                    Modifier
                        .padding(PaddingValues(bottom = 16.dp))
                        .align(Alignment.Start)
                ) {
                    Text(
                        text = stringResource(id = R.string.home_dialog_auth_fail_title),
                        style = MaterialTheme.typography.headlineSmall
                    )
                }

                // Content
                Box(
                    Modifier
                        .weight(weight = 1f, fill = false)
                        .padding(PaddingValues(bottom = 24.dp))
                        .align(Alignment.Start)
                ) {
                    Text(
                        text = stringResource(id = R.string.home_dialog_auth_fail_content),
                        style = MaterialTheme.typography.bodyMedium
                    )
                }

                // Buttons
                Row(
                    modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End
                ) {
                    TextButton(onClick = { showDialog.value = false }) {
                        Text(text = stringResource(id = android.R.string.ok))
                    }
                }
            }
            val dialogWindowProvider = LocalView.current.parent as DialogWindowProvider
            APDialogBlurBehindUtils.setupWindowBlurListener(dialogWindowProvider.window)
        }
    }

}

val checkSuperKeyValidation: (superKey: String) -> Boolean = { superKey ->
    superKey.length in 8..63 && superKey.any { it.isDigit() } && superKey.any { it.isLetter() }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AuthSuperKey(showDialog: MutableState<Boolean>, showFailedDialog: MutableState<Boolean>) {
    var key by remember { mutableStateOf("") }
    var keyVisible by remember { mutableStateOf(false) }
    var enable by remember { mutableStateOf(false) }

    BasicAlertDialog(
        onDismissRequest = { showDialog.value = false }, properties = DialogProperties(
            decorFitsSystemWindows = true,
            usePlatformDefaultWidth = false,
            securePolicy = SecureFlagPolicy.SecureOff
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
                // Title
                Box(
                    Modifier
                        .padding(PaddingValues(bottom = 16.dp))
                        .align(Alignment.Start)
                ) {
                    Text(
                        text = stringResource(id = R.string.home_auth_key_title),
                        style = MaterialTheme.typography.headlineSmall
                    )
                }

                // Content
                Box(
                    Modifier
                        .weight(weight = 1f, fill = false)
                        .align(Alignment.Start)
                ) {
                    Text(
                        text = stringResource(id = R.string.home_auth_key_desc),
                        style = MaterialTheme.typography.bodyMedium
                    )
                }

                // Content2
                Box(
                    contentAlignment = Alignment.CenterEnd,
                ) {
                    OutlinedTextField(
                        value = key,
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(top = 6.dp),
                        onValueChange = {
                            key = it
                            enable = checkSuperKeyValidation(key)
                        },
                        shape = RoundedCornerShape(50.0f),
                        label = { Text(stringResource(id = R.string.super_key)) },
                        visualTransformation = if (keyVisible) VisualTransformation.None else PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password)
                    )
                    IconButton(modifier = Modifier
                        .size(40.dp)
                        .padding(top = 15.dp, end = 5.dp),
                        onClick = { keyVisible = !keyVisible }) {
                        Icon(
                            imageVector = if (keyVisible) Icons.Default.Visibility else Icons.Default.VisibilityOff,
                            contentDescription = null,
                            tint = Color.Gray
                        )
                    }
                }

                Spacer(modifier = Modifier.height(12.dp))
                // Buttons
                Row(
                    modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End
                ) {
                    TextButton(onClick = { showDialog.value = false }) {
                        Text(stringResource(id = android.R.string.cancel))
                    }

                    Button(onClick = {
                        showDialog.value = false

                        val preVerifyKey = Natives.nativeReady(key)
                        if (preVerifyKey) {
                            APApplication.superKey = key
                        } else {
                            showFailedDialog.value = true
                        }

                    }, enabled = enable) {
                        Text(stringResource(id = android.R.string.ok))
                    }
                }
            }
        }
        val dialogWindowProvider = LocalView.current.parent as DialogWindowProvider
        APDialogBlurBehindUtils.setupWindowBlurListener(dialogWindowProvider.window)
    }
}

@Composable
fun RebootDropdownItem(@StringRes id: Int, reason: String = "") {
    DropdownMenuItem(text = {
        Text(stringResource(id))
    }, onClick = {
        reboot(reason)
    })
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun TopBar(
    onInstallClick: () -> Unit, navigator: DestinationsNavigator, kpState: APApplication.State
) {
    val uriHandler = LocalUriHandler.current
    var showDropdownMoreOptions by remember { mutableStateOf(false) }
    var showDropdownReboot by remember { mutableStateOf(false) }

    TopAppBar(title = {
        Text(stringResource(R.string.app_name))
    }, actions = {
        IconButton(onClick = onInstallClick) {
            Icon(
                imageVector = Icons.Filled.InstallMobile,
                contentDescription = stringResource(id = R.string.mode_select_page_title)
            )
        }

        if (kpState != APApplication.State.UNKNOWN_STATE) {
            IconButton(onClick = {
                showDropdownReboot = true
            }) {
                Icon(
                    imageVector = Icons.Filled.Refresh,
                    contentDescription = stringResource(id = R.string.reboot)
                )

                ProvideMenuShape(RoundedCornerShape(10.dp)) {
                    DropdownMenu(expanded = showDropdownReboot, onDismissRequest = {
                        showDropdownReboot = false
                    }) {
                        RebootDropdownItem(id = R.string.reboot)
                        RebootDropdownItem(id = R.string.reboot_recovery, reason = "recovery")
                        RebootDropdownItem(id = R.string.reboot_bootloader, reason = "bootloader")
                        RebootDropdownItem(id = R.string.reboot_download, reason = "download")
                        RebootDropdownItem(id = R.string.reboot_edl, reason = "edl")
                    }
                }
            }
        }

        Box {
            IconButton(onClick = { showDropdownMoreOptions = true }) {
                Icon(
                    imageVector = Icons.Filled.MoreVert,
                    contentDescription = stringResource(id = R.string.settings)
                )
                ProvideMenuShape(RoundedCornerShape(10.dp)) {
                    DropdownMenu(expanded = showDropdownMoreOptions, onDismissRequest = {
                        showDropdownMoreOptions = false
                    }) {
                        DropdownMenuItem(text = {
                            Text(stringResource(R.string.home_more_menu_feedback_or_suggestion))
                        }, onClick = {
                            showDropdownMoreOptions = false
                            uriHandler.openUri("https://github.com/bmax121/APatch/issues/new/choose")
                        })
                        DropdownMenuItem(text = {
                            Text(stringResource(R.string.home_more_menu_about))
                        }, onClick = {
                            navigator.navigate(AboutScreenDestination)
                            showDropdownMoreOptions = false
                        })
                    }
                }
            }
        }
    })
}

@Composable
private fun KStatusCard(
    kpState: APApplication.State, apState: APApplication.State, navigator: DestinationsNavigator
) {

    val showAuthFailedTipDialog = remember { mutableStateOf(false) }
    if (showAuthFailedTipDialog.value) {
        AuthFailedTipDialog(showDialog = showAuthFailedTipDialog)
    }

    val showAuthKeyDialog = remember { mutableStateOf(false) }
    if (showAuthKeyDialog.value) {
        AuthSuperKey(showDialog = showAuthKeyDialog, showFailedDialog = showAuthFailedTipDialog)
    }

    val showUninstallDialog = remember { mutableStateOf(false) }
    if (showUninstallDialog.value) {
        UninstallDialog(showDialog = showUninstallDialog, navigator)
    }

    val cardBackgroundColor = when (kpState) {
        APApplication.State.KERNELPATCH_INSTALLED -> {
            MaterialTheme.colorScheme.primary
        }

        APApplication.State.KERNELPATCH_NEED_UPDATE, APApplication.State.KERNELPATCH_NEED_REBOOT -> {
            MaterialTheme.colorScheme.secondary
        }

        else -> {
            MaterialTheme.colorScheme.secondaryContainer
        }
    }

    ElevatedCard(
        onClick = {
            if (kpState != APApplication.State.KERNELPATCH_INSTALLED) {
                navigator.navigate(InstallModeSelectScreenDestination)
            }
        },
        colors = CardDefaults.elevatedCardColors(containerColor = cardBackgroundColor),
        elevation = CardDefaults.cardElevation(
            defaultElevation = if (kpState == APApplication.State.UNKNOWN_STATE) 0.dp else 6.dp
        )
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            if (kpState == APApplication.State.KERNELPATCH_NEED_UPDATE) {
                Row {
                    Text(
                        text = stringResource(R.string.kernel_patch),
                        style = MaterialTheme.typography.titleMedium
                    )
                }
            }
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(10.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                when (kpState) {
                    APApplication.State.KERNELPATCH_INSTALLED -> {
                        Icon(Icons.Filled.CheckCircle, stringResource(R.string.home_working))
                    }

                    APApplication.State.KERNELPATCH_NEED_UPDATE, APApplication.State.KERNELPATCH_NEED_REBOOT -> {
                        Icon(Icons.Outlined.SystemUpdate, stringResource(R.string.home_need_update))
                    }

                    else -> {
                        Icon(Icons.AutoMirrored.Outlined.HelpOutline, "Unknown")
                    }
                }
                Column(
                    Modifier
                        .weight(2f)
                        .padding(start = 16.dp)
                ) {
                    when (kpState) {
                        APApplication.State.KERNELPATCH_INSTALLED -> {
                            Text(
                                text = stringResource(R.string.home_working),
                                style = MaterialTheme.typography.titleMedium
                            )
                        }

                        APApplication.State.KERNELPATCH_NEED_UPDATE, APApplication.State.KERNELPATCH_NEED_REBOOT -> {
                            Text(
                                text = stringResource(R.string.home_need_update),
                                style = MaterialTheme.typography.titleMedium
                            )
                            Spacer(Modifier.height(6.dp))
                            Text(
                                text = stringResource(
                                    R.string.kpatch_version_update,
                                    Version.installedKPVString(),
                                    Version.buildKPVString()
                                ), style = MaterialTheme.typography.bodyMedium
                            )
                        }

                        else -> {
                            Text(
                                text = stringResource(R.string.home_install_unknown),
                                style = MaterialTheme.typography.titleMedium
                            )
                            Text(
                                text = stringResource(R.string.home_install_unknown_summary),
                                style = MaterialTheme.typography.bodyMedium
                            )
                        }
                    }
                    if (kpState != APApplication.State.UNKNOWN_STATE && kpState != APApplication.State.KERNELPATCH_NEED_UPDATE && kpState != APApplication.State.KERNELPATCH_NEED_REBOOT) {
                        Spacer(Modifier.height(4.dp))
                        Text(
                            text = "${Version.installedKPVString()} (${managerVersion.second}) - " + if (apState != APApplication.State.ANDROIDPATCH_NOT_INSTALLED) "Full" else "KernelPatch",
                            style = MaterialTheme.typography.bodyMedium
                        )
                    }
                }

                Column(
                    modifier = Modifier.align(Alignment.CenterVertically)
                ) {
                    Button(onClick = {
                        when (kpState) {
                            APApplication.State.UNKNOWN_STATE -> {
                                showAuthKeyDialog.value = true
                            }

                            APApplication.State.KERNELPATCH_NEED_UPDATE -> {
                                // todo: remove legacy compact for kp < 0.9.0
                                if (Version.installedKPVUInt() < 0x900u) {
                                    navigator.navigate(PatchesDestination(PatchesViewModel.PatchMode.PATCH_ONLY))
                                } else {
                                    navigator.navigate(InstallModeSelectScreenDestination)
                                }
                            }

                            APApplication.State.KERNELPATCH_NEED_REBOOT -> {
                                reboot()
                            }

                            APApplication.State.KERNELPATCH_UNINSTALLING -> {
                                // Do nothing
                            }

                            else -> {
                                if (apState == APApplication.State.ANDROIDPATCH_INSTALLED || apState == APApplication.State.ANDROIDPATCH_NEED_UPDATE) {
                                    showUninstallDialog.value = true
                                } else {
                                    navigator.navigate(PatchesDestination(PatchesViewModel.PatchMode.UNPATCH))
                                }
                            }
                        }
                    }, content = {
                        when (kpState) {
                            APApplication.State.UNKNOWN_STATE -> {
                                Text(text = stringResource(id = R.string.super_key))
                            }

                            APApplication.State.KERNELPATCH_NEED_UPDATE -> {
                                Text(text = stringResource(id = R.string.home_ap_cando_update))
                            }

                            APApplication.State.KERNELPATCH_NEED_REBOOT -> {
                                Text(text = stringResource(id = R.string.home_ap_cando_reboot))
                            }

                            APApplication.State.KERNELPATCH_UNINSTALLING -> {
                                Icon(Icons.Outlined.Cached, contentDescription = "busy")
                            }

                            else -> {
                                Text(text = stringResource(id = R.string.home_ap_cando_uninstall))
                            }
                        }
                    })
                }
            }
        }
    }
}

@Composable
private fun AStatusCard(apState: APApplication.State) {
    ElevatedCard(
        colors = CardDefaults.elevatedCardColors(containerColor = run {
            MaterialTheme.colorScheme.secondaryContainer
        })
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Row {
                Text(
                    text = stringResource(R.string.android_patch),
                    style = MaterialTheme.typography.titleMedium
                )
            }
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(10.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                when (apState) {
                    APApplication.State.ANDROIDPATCH_NOT_INSTALLED -> {
                        Icon(Icons.Outlined.Block, stringResource(R.string.home_not_installed))
                    }

                    APApplication.State.ANDROIDPATCH_INSTALLING -> {
                        Icon(Icons.Outlined.InstallMobile, stringResource(R.string.home_installing))
                    }

                    APApplication.State.ANDROIDPATCH_INSTALLED -> {
                        Icon(Icons.Outlined.CheckCircle, stringResource(R.string.home_working))
                    }

                    APApplication.State.ANDROIDPATCH_NEED_UPDATE -> {
                        Icon(Icons.Outlined.SystemUpdate, stringResource(R.string.home_need_update))
                    }

                    else -> {
                        Icon(
                            Icons.AutoMirrored.Outlined.HelpOutline,
                            stringResource(R.string.home_install_unknown)
                        )
                    }
                }
                Column(
                    Modifier
                        .weight(2f)
                        .padding(start = 16.dp)
                ) {

                    when (apState) {
                        APApplication.State.ANDROIDPATCH_NOT_INSTALLED -> {
                            Text(
                                text = stringResource(R.string.home_not_installed),
                                style = MaterialTheme.typography.titleMedium
                            )
                        }

                        APApplication.State.ANDROIDPATCH_INSTALLING -> {
                            Text(
                                text = stringResource(R.string.home_installing),
                                style = MaterialTheme.typography.titleMedium
                            )
                        }

                        APApplication.State.ANDROIDPATCH_INSTALLED -> {
                            Text(
                                text = stringResource(R.string.home_working),
                                style = MaterialTheme.typography.titleMedium
                            )
                        }

                        APApplication.State.ANDROIDPATCH_NEED_UPDATE -> {
                            Text(
                                text = stringResource(R.string.home_need_update),
                                style = MaterialTheme.typography.titleMedium
                            )
                            Spacer(Modifier.height(6.dp))
                            Text(
                                text = stringResource(
                                    R.string.apatch_version_update,
                                    Version.installedApdVString,
                                    managerVersion.second
                                ), style = MaterialTheme.typography.bodyMedium
                            )
                        }

                        else -> {
                            Text(
                                text = stringResource(R.string.home_install_unknown),
                                style = MaterialTheme.typography.titleMedium
                            )
                        }
                    }
                }
                if (apState != APApplication.State.UNKNOWN_STATE) {
                    Column(
                        modifier = Modifier.align(Alignment.CenterVertically)
                    ) {
                        Button(onClick = {
                            when (apState) {
                                APApplication.State.ANDROIDPATCH_NOT_INSTALLED, APApplication.State.ANDROIDPATCH_NEED_UPDATE -> {
                                    APApplication.installApatch()
                                }

                                APApplication.State.ANDROIDPATCH_UNINSTALLING -> {
                                    // Do nothing
                                }

                                else -> {
                                    APApplication.uninstallApatch()
                                }
                            }
                        }, content = {
                            when (apState) {
                                APApplication.State.ANDROIDPATCH_NOT_INSTALLED -> {
                                    Text(text = stringResource(id = R.string.home_ap_cando_install))
                                }

                                APApplication.State.ANDROIDPATCH_NEED_UPDATE -> {
                                    Text(text = stringResource(id = R.string.home_ap_cando_update))
                                }

                                APApplication.State.ANDROIDPATCH_UNINSTALLING -> {
                                    Icon(Icons.Outlined.Cached, contentDescript
"""




