响应:

```
好的，我现在需要分析用户提供的Kotlin代码，了解它的功能，并按照要求回答问题。首先，用户提到这段代码是APatch项目的一部分，属于KPM模块的UI实现。APatch是一个类似Magisk的Android内核和系统补丁工具，支持内核模块的加载和管理。

首先，我会通读代码，理解它的结构和主要组成部分。代码中定义了一个名为KPModuleScreen的Composable函数，这应该是主界面，用于显示和管理内核模块。里面包含了一些UI组件，比如顶部应用栏（TopAppBar）、下拉菜单（DropdownMenu）、模块列表（LazyColumn）以及对话框（如KPMControlDialog）。

接下来，我需要理清代码的执行流程。用户要求按执行顺序列举功能步骤，所以需要从界面初始化开始，逐步分析各个交互点。例如，当用户打开这个界面时，会检查APatch的状态，加载模块列表，然后用户可以通过FAB（浮动操作按钮）添加、安装或加载模块。每个按钮点击后可能触发不同的操作，比如选择文件、调用本地方法加载模块等。

然后，涉及到的功能点可能包括：模块的加载、卸载、控制参数设置，以及通过Natives类调用底层C/C++函数（如Natives.loadKernelPatchModule）。此外，文件操作部分，比如从URI读取文件内容，保存到应用的私有目录，这些都是需要关注的。

关于Shell代码示例，假设用户想通过命令行加载或卸载模块，可能需要调用类似apatch kpm load/unload的命令，但需要查看Natives类中的具体实现。不过根据代码中的Natives方法，可以推断可能的底层操作，比如加载模块可能涉及将.kpm文件复制到特定目录，并通过系统调用或内核模块加载机制来实现。

文件系统访问方面，代码中使用了FileSystemManager来处理文件，将临时模块保存到应用目录下的kpm文件夹。例如，在loadModule函数中，会删除旧目录，创建新目录，并将选择的文件写入其中，然后调用本地方法加载。这涉及到对应用私有目录的读写，外部进程可能无法直接访问，但生成的文件可能在/data/data/应用包名/files/kpm下，需要root权限才能查看。

痕迹方面，加载或卸载模块可能会在系统日志中留下痕迹，例如通过Log.d或Log.e输出的日志标签“KernelPatchModule”。此外，成功或失败会有Toast提示，但这些属于用户界面反馈，不会在系统层面留下持久记录。生成的.kpm文件可能残留在应用目录中，卸载应用后可能被清除。

需要验证的部分包括Natives类中的方法如何与底层交互，例如loadKernelPatchModule和unloadKernelPatchModule的具体实现，这可能需要查看项目的其他部分或文档。假设这些方法通过JNI调用C++代码，进而操作内核模块，那么实际效果取决于这些底层实现是否正确处理模块的加载和卸载。

最后，总结功能步骤时，应该从界面初始化、加载模块列表、用户操作（加载、安装、控制、卸载）到具体的文件操作和底层调用，按流程排列。同时注意可能涉及的用户权限，例如需要root权限执行某些操作，或者文件选择时的URI权限处理。
```
以下是基于代码推理的功能步骤分析：

1. **界面初始化**  
- 检查APatch状态，若未安装显示提示
- 初始化ViewModel并获取内核模块列表
- 创建可滚动模块列表界面(LazyColumn)

2. **模块加载准备**  
- 用户点击FAB按钮展开下拉菜单
- 提供三个选项：嵌入/安装/加载模块（当前安装功能未开放）

3. **选择模块文件**  
```shell
# 假设通过adb模拟文件选择
adb push example.kpm /sdcard/
am start -a android.intent.action.GET_CONTENT -t "*/*"
```

4. **文件处理流程**  
- 创建临时目录：/data/data/me.tool.passkey/files/kpm
- 生成随机文件名（如abcd.kpm）
- 将选定文件内容复制到临时文件

5. **内核模块加载**  
```kotlin
Natives.loadKernelPatchModule(path, args) // 实际调用native方法
```
假设输入：/data/.../abcd.kpm 输出：返回0表示成功

6. **模块管理操作**  
- 显示模块名称/版本/作者/参数信息
- 支持通过参数控制模块行为（需内核支持）
```shell
# 假设控制命令
echo "debug_mode=1" > /sys/kernel/kpm_control
```

7. **模块卸载流程**  
```kotlin
Natives.unloadKernelPatchModule(name) // 调用native卸载
```
假设输入：example_module 输出：返回0表示成功

8. **文件系统痕迹**  
生成路径示例：
```
/data/data/me.tool.passkey/files/kpm/abcd.kpm
/data/data/me.tool.passkey/shared_prefs/*.xml # 配置存储
```

9. **日志痕迹分析**  
通过logcat可观察：
```shell
adb logcat -s KernelPatchModule:D
# 示例输出
D/KernelPatchModule: save tmp kpm: /data/.../abcd.kpm
D/KernelPatchModule: load /data/.../abcd.kpm rc: 0
```

10. **系统层影响**  
- 通过内核模块修改syscall表
- 注入的代码可能影响/proc/kallsyms
- 可能生成内核线程（ps -TZ | grep kpm）

关键命令行参数处理特征：
1. 文件URI处理使用Android SAF框架
2. 临时文件使用随机4字母命名避免冲突
3. 所有文件操作在应用私有目录进行
4. 通过JNI调用底层Natives方法实现特权操作

注意事项：
1. 需要ROOT权限执行核心操作
2. 模块加载失败会保留临时文件供调试
3. 控制参数直接传递给内核模块，无内容验证
4. 成功操作通过Toast提示，失败保留错误日志
提示器:

这是路径为APatch/app/src/main/java/me/tool/passkey/ui/screen/KPM.kt的apatch `The patching of Android kernel and Android system`实现的一部分，
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

```kotlin
package me.tool.passkey.ui.screen

import android.app.Activity.RESULT_OK
import android.content.Intent
import android.net.Uri
import android.util.Log
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.wrapContentHeight
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.ExperimentalMaterialApi
import androidx.compose.material3.AlertDialogDefaults
import androidx.compose.material3.BasicAlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.livedata.observeAsState
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.window.DialogWindowProvider
import androidx.compose.ui.window.PopupProperties
import androidx.lifecycle.viewmodel.compose.viewModel
import com.ramcosta.composedestinations.annotation.Destination
import com.ramcosta.composedestinations.annotation.RootGraph
import com.ramcosta.composedestinations.generated.destinations.InstallScreenDestination
import com.ramcosta.composedestinations.generated.destinations.PatchesDestination
import com.ramcosta.composedestinations.navigation.DestinationsNavigator
import com.topjohnwu.superuser.nio.ExtendedFile
import com.topjohnwu.superuser.nio.FileSystemManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import me.tool.passkey.APApplication
import me.tool.passkey.Natives
import me.tool.passkey.R
import me.tool.passkey.apApp
import me.tool.passkey.ui.component.ConfirmResult
import me.tool.passkey.ui.component.KPModuleRemoveButton
import me.tool.passkey.ui.component.LoadingDialogHandle
import me.tool.passkey.ui.component.ProvideMenuShape
import me.tool.passkey.ui.component.rememberConfirmDialog
import me.tool.passkey.ui.component.rememberLoadingDialog
import me.tool.passkey.ui.viewmodel.KPModel
import me.tool.passkey.ui.viewmodel.KPModuleViewModel
import me.tool.passkey.ui.viewmodel.PatchesViewModel
import me.tool.passkey.util.inputStream
import me.tool.passkey.util.ui.APDialogBlurBehindUtils
import me.tool.passkey.util.writeTo
import java.io.IOException

private const val TAG = "KernelPatchModule"
private lateinit var targetKPMToControl: KPModel.KPMInfo

@Destination<RootGraph>
@Composable
fun KPModuleScreen(navigator: DestinationsNavigator) {
    val state by APApplication.apStateLiveData.observeAsState(APApplication.State.UNKNOWN_STATE)
    if (state == APApplication.State.UNKNOWN_STATE) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(12.dp),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Row {
                Text(
                    text = stringResource(id = R.string.kpm_kp_not_installed),
                    style = MaterialTheme.typography.titleMedium
                )
            }
        }
        return
    }

    val viewModel = viewModel<KPModuleViewModel>()

    LaunchedEffect(Unit) {
        if (viewModel.moduleList.isEmpty() || viewModel.isNeedRefresh) {
            viewModel.fetchModuleList()
        }
    }

    val kpModuleListState = rememberLazyListState()

    Scaffold(topBar = {
        TopBar()
    }, floatingActionButton = run {
        {
            val scope = rememberCoroutineScope()
            val context = LocalContext.current

            val moduleLoad = stringResource(id = R.string.kpm_load)
            val moduleInstall = stringResource(id = R.string.kpm_install)
            val moduleEmbed = stringResource(id = R.string.kpm_embed)
            val successToastText = stringResource(id = R.string.kpm_load_toast_succ)
            val failToastText = stringResource(id = R.string.kpm_load_toast_failed)
            val loadingDialog = rememberLoadingDialog()

            val selectZipLauncher = rememberLauncherForActivityResult(
                contract = ActivityResultContracts.StartActivityForResult()
            ) {
                if (it.resultCode != RESULT_OK) {
                    return@rememberLauncherForActivityResult
                }
                val data = it.data ?: return@rememberLauncherForActivityResult
                val uri = data.data ?: return@rememberLauncherForActivityResult

                Log.i(TAG, "select zip result: $uri")

                navigator.navigate(InstallScreenDestination(uri, MODULE_TYPE.KPM))
            }

            val selectKpmLauncher = rememberLauncherForActivityResult(
                contract = ActivityResultContracts.StartActivityForResult()
            ) {
                if (it.resultCode != RESULT_OK) {
                    return@rememberLauncherForActivityResult
                }
                val data = it.data ?: return@rememberLauncherForActivityResult
                val uri = data.data ?: return@rememberLauncherForActivityResult

                // todo: args
                scope.launch {
                    val rc = loadModule(loadingDialog, uri, "") == 0
                    val toastText = if (rc) successToastText else failToastText
                    withContext(Dispatchers.Main) {
                        Toast.makeText(
                            context, toastText, Toast.LENGTH_SHORT
                        ).show()
                    }
                    viewModel.markNeedRefresh()
                    viewModel.fetchModuleList()
                }
            }

            var expanded by remember { mutableStateOf(false) }
            val options = listOf(moduleEmbed, moduleInstall, moduleLoad)

            Column {
                FloatingActionButton(
                    onClick = {
                        expanded = !expanded
                    },
                    contentColor = MaterialTheme.colorScheme.onPrimary,
                    containerColor = MaterialTheme.colorScheme.primary,
                ) {
                    Icon(
                        painter = painterResource(id = R.drawable.package_import),
                        contentDescription = null
                    )
                }

                ProvideMenuShape(RoundedCornerShape(10.dp)) {
                    DropdownMenu(
                        expanded = expanded,
                        onDismissRequest = { expanded = false },
                        properties = PopupProperties(focusable = true)
                    ) {
                        options.forEach { label ->
                            DropdownMenuItem(text = { Text(label) }, onClick = {
                                expanded = false
                                when (label) {
                                    moduleEmbed -> {
                                        navigator.navigate(PatchesDestination(PatchesViewModel.PatchMode.PATCH_AND_INSTALL))
                                    }

                                    moduleInstall -> {
//                                        val intent = Intent(Intent.ACTION_GET_CONTENT)
//                                        intent.type = "application/zip"
//                                        selectZipLauncher.launch(intent)
                                        Toast.makeText(context, "Under development", Toast.LENGTH_SHORT).show()
                                    }

                                    moduleLoad -> {
                                        val intent = Intent(Intent.ACTION_GET_CONTENT)
                                        intent.type = "*/*"
                                        selectKpmLauncher.launch(intent)
                                    }
                                }
                            })
                        }
                    }
                }
            }
        }
    }) { innerPadding ->

        KPModuleList(
            viewModel = viewModel,
            modifier = Modifier
                .padding(innerPadding)
                .fillMaxSize(),
            state = kpModuleListState
        )
    }
}

suspend fun loadModule(loadingDialog: LoadingDialogHandle, uri: Uri, args: String): Int {
    val rc = loadingDialog.withLoading {
        withContext(Dispatchers.IO) {
            run {
                val kpmDir: ExtendedFile =
                    FileSystemManager.getLocal().getFile(apApp.filesDir.parent, "kpm")
                kpmDir.deleteRecursively()
                kpmDir.mkdirs()
                val rand = (1..4).map { ('a'..'z').random() }.joinToString("")
                val kpm = kpmDir.getChildFile("${rand}.kpm")
                Log.d(TAG, "save tmp kpm: ${kpm.path}")
                var rc = -1
                try {
                    uri.inputStream().buffered().writeTo(kpm)
                    rc = Natives.loadKernelPatchModule(kpm.path, args).toInt()
                } catch (e: IOException) {
                    Log.e(TAG, "Copy kpm error: $e")
                }
                Log.d(TAG, "load ${kpm.path} rc: $rc")
                rc
            }
        }
    }
    return rc
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun KPMControlDialog(showDialog: MutableState<Boolean>) {
    var controlParam by remember { mutableStateOf("") }
    var enable by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    val loadingDialog = rememberLoadingDialog()
    val context = LocalContext.current
    val outMsgStringRes = stringResource(id = R.string.kpm_control_outMsg)
    val okStringRes = stringResource(id = R.string.kpm_control_ok)
    val failedStringRes = stringResource(id = R.string.kpm_control_failed)

    lateinit var controlResult: Natives.KPMCtlRes

    suspend fun onModuleControl(module: KPModel.KPMInfo) {
        loadingDialog.withLoading {
            withContext(Dispatchers.IO) {
                controlResult = Natives.kernelPatchModuleControl(module.name, controlParam)
            }
        }

        if (controlResult.rc >= 0) {
            Toast.makeText(
                context,
                "$okStringRes\n${outMsgStringRes}: ${controlResult.outMsg}",
                Toast.LENGTH_SHORT
            ).show()
        } else {
            Toast.makeText(
                context,
                "$failedStringRes\n${outMsgStringRes}: ${controlResult.outMsg}",
                Toast.LENGTH_SHORT
            ).show()
        }
    }

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
                        text = stringResource(id = R.string.kpm_control_dialog_title),
                        style = MaterialTheme.typography.headlineSmall
                    )
                }

                Box(
                    Modifier
                        .weight(weight = 1f, fill = false)
                        .align(Alignment.Start)
                ) {
                    Text(
                        text = stringResource(id = R.string.kpm_control_dialog_content),
                        style = MaterialTheme.typography.bodyMedium
                    )
                }

                Box(
                    contentAlignment = Alignment.CenterEnd,
                ) {
                    OutlinedTextField(
                        value = controlParam,
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(top = 6.dp),
                        onValueChange = {
                            controlParam = it
                            enable = controlParam.isNotBlank()
                        },
                        shape = RoundedCornerShape(50.0f),
                        label = { Text(stringResource(id = R.string.kpm_control_paramters)) },
                        visualTransformation = VisualTransformation.None,
                    )
                }

                Spacer(modifier = Modifier.height(12.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End
                ) {
                    TextButton(onClick = { showDialog.value = false }) {
                        Text(stringResource(id = android.R.string.cancel))
                    }

                    Button(onClick = {
                        showDialog.value = false

                        scope.launch { onModuleControl(targetKPMToControl) }

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

@OptIn(ExperimentalMaterialApi::class, ExperimentalMaterial3Api::class)
@Composable
private fun KPModuleList(
    viewModel: KPModuleViewModel, modifier: Modifier = Modifier, state: LazyListState
) {
    val moduleStr = stringResource(id = R.string.kpm)
    val moduleUninstallConfirm = stringResource(id = R.string.kpm_unload_confirm)
    val uninstall = stringResource(id = R.string.kpm_unload)
    val cancel = stringResource(id = android.R.string.cancel)

    val confirmDialog = rememberConfirmDialog()
    val loadingDialog = rememberLoadingDialog()

    val showKPMControlDialog = remember { mutableStateOf(false) }
    if (showKPMControlDialog.value) {
        KPMControlDialog(showDialog = showKPMControlDialog)
    }

    suspend fun onModuleUninstall(module: KPModel.KPMInfo) {
        val confirmResult = confirmDialog.awaitConfirm(
            moduleStr,
            content = moduleUninstallConfirm.format(module.name),
            confirm = uninstall,
            dismiss = cancel
        )
        if (confirmResult != ConfirmResult.Confirmed) {
            return
        }

        val success = loadingDialog.withLoading {
            withContext(Dispatchers.IO) {
                Natives.unloadKernelPatchModule(module.name) == 0L
            }
        }

        if (success) {
            viewModel.fetchModuleList()
        }
    }

    PullToRefreshBox(
        modifier = modifier,
        onRefresh = { viewModel.fetchModuleList() },
        isRefreshing = viewModel.isRefreshing
    ) {
        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            state = state,
            verticalArrangement = Arrangement.spacedBy(16.dp),
            contentPadding = remember {
                PaddingValues(
                    start = 16.dp,
                    top = 16.dp,
                    end = 16.dp,
                    bottom = 16.dp + 16.dp + 56.dp /*  Scaffold Fab Spacing + Fab container height */
                )
            },
        ) {
            when {
                viewModel.moduleList.isEmpty() -> {
                    item {
                        Box(
                            modifier = Modifier.fillParentMaxSize(),
                            contentAlignment = Alignment.Center
                        ) {
                            Text(
                                stringResource(R.string.kpm_apm_empty), textAlign = TextAlign.Center
                            )
                        }
                    }
                }
                else -> {
                    items(viewModel.moduleList) { module ->
                        val scope = rememberCoroutineScope()
                        KPModuleItem(
                            module,
                            onUninstall = {
                                scope.launch { onModuleUninstall(module) }
                            },
                            onControl = {
                                targetKPMToControl = module
                                showKPMControlDialog.value = true
                            },
                        )

                        // fix last item shadow incomplete in LazyColumn
                        Spacer(Modifier.height(1.dp))
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun TopBar() {
    TopAppBar(title = { Text(stringResource(R.string.kpm)) })
}

@Composable
private fun KPModuleItem(
    module: KPModel.KPMInfo,
    onUninstall: (KPModel.KPMInfo) -> Unit,
    onControl: (KPModel.KPMInfo) -> Unit,
    modifier: Modifier = Modifier,
    alpha: Float = 1f,
) {
    val moduleAuthor = stringResource(id = R.string.kpm_author)
    val moduleArgs = stringResource(id = R.string.kpm_args)
    val decoration = TextDecoration.None

    Surface(
        modifier = modifier,
        color = MaterialTheme.colorScheme.surface,
        tonalElevation = 1.dp,
        shape = RoundedCornerShape(20.dp)
    ) {

        Box(
            modifier = Modifier.fillMaxWidth(), contentAlignment = Alignment.Center
        ) {
            Column(
                modifier = Modifier.fillMaxWidth()
            ) {
                Row(
                    modifier = Modifier.padding(all = 16.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(
                        modifier = Modifier
                            .alpha(alpha = alpha)
                            .weight(1f),
                        verticalArrangement = Arrangement.spacedBy(2.dp)
                    ) {
                        Text(
                            text = module.name,
                            style = MaterialTheme.typography.titleSmall.copy(fontWeight = FontWeight.Bold),
                            maxLines = 2,
                            textDecoration = decoration,
                            overflow = TextOverflow.Ellipsis
                        )

                        Text(
                            text = "${module.version}, $moduleAuthor ${module.author}",
                            style = MaterialTheme.typography.bodySmall,
                            textDecoration = decoration,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )

                        Text(
                            text = "$moduleArgs: ${module.args}",
                            style = MaterialTheme.typography.bodySmall,
                            textDecoration = decoration,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }

                }

                Text(
                    modifier = Modifier
                        .alpha(alpha = alpha)
                        .padding(horizontal = 16.dp),
                    text = module.description,
                    style = MaterialTheme.typography.bodySmall,
                    textDecoration = decoration,
                    color = MaterialTheme.colorScheme.outline
                )

                HorizontalDivider(
                    thickness = 1.5.dp,
                    color = MaterialTheme.colorScheme.surface,
                    modifier = Modifier.padding(top = 8.dp)
                )

                Row(
                    modifier = Modifier
                        .padding(horizontal = 16.dp, vertical = 8.dp)
                        .fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Spacer(modifier = Modifier.weight(1f))

                    FilledTonalButton(
                        onClick = { onControl(module) },
                        enabled = true,
                        contentPadding = PaddingValues(horizontal = 12.dp)
                    ) {
                        Icon(
                            modifier = Modifier.size(20.dp),
                            painter = painterResource(id = R.drawable.settings),
                            contentDescription = null
                        )

                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            text = stringResource(id = R.string.kpm_control),
                            maxLines = 1,
                            overflow = TextOverflow.Visible,
                            softWrap = false
                        )
                    }

                    Spacer(modifier = Modifier.width(12.dp))

                    KPModuleRemoveButton(enabled = true, onClick = { onUninstall(module) })
                }
            }

        }
    }
}

"""



