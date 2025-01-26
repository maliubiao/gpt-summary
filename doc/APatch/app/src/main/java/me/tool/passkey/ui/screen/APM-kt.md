响应:

```
嗯，我现在需要分析这个APM.kt文件的代码，然后按照用户的要求，列举出它的功能步骤，可能的话给出shell示例，涉及文件系统的话要详细说明，还有生成的痕迹。首先，我应该先理解这段代码是做什么的。根据项目描述，APatch是一个类似Magisk的Android内核和系统补丁解决方案，支持模块化功能。APM可能就是模块管理部分。

代码是Kotlin写的，属于Compose的UI部分，位于APatch应用的模块管理界面。首先，用户进入APModuleScreen，这里会根据APatch的安装状态显示不同内容。如果未安装，显示提示；否则，初始化ViewModel，获取模块列表。可能需要网络请求获取模块信息，或者本地读取已安装模块。

接下来，看看Scaffold中的布局。顶部有TopAppBar显示标题。FloatingActionButton用于安装模块，点击后选择ZIP文件，通过ActivityResultContracts获取URI，然后导航到安装界面。这里可能涉及文件选择，处理ZIP文件的安装。

ModuleList部分，使用LazyColumn显示模块列表。每个模块项有启用/禁用开关、更新、卸载、WebUI按钮。开关调用toggleModule函数，可能修改模块状态，需要重启生效。卸载时调用uninstallModule，删除模块文件。更新按钮会检查更新，下载新版本并安装。WebUI按钮启动WebUIActivity，可能打开模块的配置界面。

处理模块更新时，会下载changelog，显示确认对话框，然后下载ZIP文件，触发安装流程。下载使用OkHttpClient，保存到本地后通过onInstallModule处理，可能将文件复制到特定目录，比如/data/adb/modules。

关于文件系统访问，安装模块时选择的ZIP文件会被处理，可能解压到模块目录。卸载会删除对应模块目录。涉及到的路径可能有/data/adb/apm_modules或者类似的位置。需要root权限才能访问这些目录。

外部进程可能看到的痕迹包括：安装的模块目录、可能修改的系统文件、启动的进程（如WebUI的Activity）、日志中的操作记录（如Log.i输出的uri）。还有可能生成下载的临时文件，或者安装后的模块文件。

Shell示例的话，比如手动安装模块，可能用adb push module.zip /sdcard/，然后在应用中选择。或者通过命令行调用am启动安装Activity，不过通常需要UI交互。卸载模块可能直接删除对应的目录，例如rm -rf /data/adb/apm_modules/module_id。

需要考虑权限问题，APatch需要root权限来操作这些目录，所以相关函数可能调用su或者使用内核模块功能。日志中可能会有相关错误，比如权限拒绝，或者模块加载失败的信息。

总结功能步骤：检查APatch状态，获取模块列表，显示模块项，处理启用/禁用，安装更新，卸载模块，处理WebUI，执行动作脚本，刷新列表，重启提示等。可能涉及到的系统调用或文件操作需要详细说明。
```
### 功能执行顺序推理：

1. **检查APatch安装状态**  
   - 检测`APApplication.State`是否为已安装状态，否则显示未安装提示

2. **初始化模块列表**  
   - 通过`APModuleViewModel.fetchModuleList()`获取模块列表数据

3. **处理模块安装入口**  
   - 点击浮动按钮触发`Intent.ACTION_GET_CONTENT`选择ZIP文件

4. **解析模块元数据**  
   - 从模块的`module.prop`等配置文件中读取名称、版本、作者、WebUI支持等属性

5. **渲染模块列表项**  
   - 对每个模块显示开关状态、更新按钮、WebUI入口、卸载按钮

6. **处理模块开关切换**  
   - 调用`toggleModule()`修改`/data/adb/apm_modules/[id]/disable`状态文件

7. **执行模块更新流程**  
   - 检查更新→下载changelog→确认更新→下载ZIP→触发安装流程

8. **处理WebUI交互**  
   - 通过`WebUIActivity`加载`apatch://webui/[id]`地址与模块交互

9. **执行卸载操作**  
   - 删除`/data/adb/apm_modules/[id]`目录及其内容

10. **处理重启提示**  
    - 在需要重启时显示Snackbar，调用`reboot()`触发系统重启

---

### 关键功能Shell示例

```bash
# 手动安装模块示例
adb push custom_module.zip /sdcard/
am start -a android.intent.action.VIEW -d content:///sdcard/custom_module.zip -t application/zip

# 查看已安装模块
ls /data/adb/apm_modules
# output: module1 module2...

# 禁用模块示例
echo 1 > /data/adb/apm_modules/module1/disable

# 查看模块日志
dmesg | grep APM
# 可能输出：APM: loading module [module1]...
```

---

### 文件系统访问细节

1. **模块安装路径**  
   - `/data/adb/apm_modules/[module_id]/`：每个模块的安装目录
   - 包含`module.prop`、`system/`、`post-fs-data.sh`等文件

2. **状态文件**  
   - `/data/adb/apm_modules/[id]/disable`：存在时表示模块禁用

3. **临时下载路径**  
   - 下载的ZIP可能存储在`/data/data/me.tool.passkey/cache/`或外部存储

4. **Magisk冲突检测**  
   - 检查`/data/adb/magisk`或`/system/bin/su`等Magisk特征文件

---

### 外部可见痕迹

1. **文件系统痕迹**  
   - `/data/adb/apm_modules`目录结构
   - `/proc/modules`中加载的内核模块

2. **进程特征**  
   - `WebUIActivity`进程信息
   - `ksud`（假设类似KernelSU的后台进程）

3. **日志痕迹**  
   ```logcat
   I/ModuleScreen: select zip result: content://com.android.providers.downloads.documents/document/raw%3A%2Fstorage%2Femulated%2F0%2FDownload%2Fmodule.zip
   D/APM: Installing module from /data/user_de/0/me.tool.passkey/cache/module.zip
   ```

4. **网络请求**  
   - 模块更新时对`raw.githubusercontent.com`等代码仓库的HTTPS请求

5. **SELinux上下文**  
   - `u:r:apatch:s0`等自定义SELinux域

---

### 代码逻辑验证示例

**假设输入**：用户点击"禁用模块"开关  
**代码路径**：  
```kotlin
toggleModule(module.id, !isChecked)  
→ 调用Native方法修改模块状态文件  
→ 返回操作结果  
→ 显示需要重启的Snackbar  
```

**预期输出**：  
1. `/data/adb/apm_modules/[id]/disable`文件被创建  
2. Logcat输出模块状态变更日志  
3. UI显示"需要重启生效"提示  

**失败场景**：  
- 如果文件系统不可写，`toggleModule()`返回false  
- Snackbar显示"Failed to disable module"
提示器:

这是路径为APatch/app/src/main/java/me/tool/passkey/ui/screen/APM.kt的apatch `The patching of Android kernel and Android system`实现的一部分，
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
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.util.Log
import android.util.Patterns
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
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
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.ExperimentalMaterialApi
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarDuration
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.SnackbarResult
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.livedata.observeAsState
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.ramcosta.composedestinations.annotation.Destination
import com.ramcosta.composedestinations.annotation.RootGraph
import com.ramcosta.composedestinations.generated.destinations.ExecuteAPMActionScreenDestination
import com.ramcosta.composedestinations.generated.destinations.InstallScreenDestination
import com.ramcosta.composedestinations.navigation.DestinationsNavigator
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import me.tool.passkey.APApplication
import me.tool.passkey.R
import me.tool.passkey.ui.WebUIActivity
import me.tool.passkey.ui.component.ConfirmResult
import me.tool.passkey.ui.component.ModuleRemoveButton
import me.tool.passkey.ui.component.ModuleStateIndicator
import me.tool.passkey.ui.component.ModuleUpdateButton
import me.tool.passkey.ui.component.rememberConfirmDialog
import me.tool.passkey.ui.component.rememberLoadingDialog
import me.tool.passkey.ui.viewmodel.APModuleViewModel
import me.tool.passkey.util.DownloadListener
import me.tool.passkey.util.download
import me.tool.passkey.util.hasMagisk
import me.tool.passkey.util.reboot
import me.tool.passkey.util.toggleModule
import me.tool.passkey.util.ui.LocalSnackbarHost
import me.tool.passkey.util.uninstallModule
import okhttp3.OkHttpClient

@Destination<RootGraph>
@Composable
fun APModuleScreen(navigator: DestinationsNavigator) {
    val snackBarHost = LocalSnackbarHost.current
    val context = LocalContext.current

    val state by APApplication.apStateLiveData.observeAsState(APApplication.State.UNKNOWN_STATE)
    if (state != APApplication.State.ANDROIDPATCH_INSTALLED && state != APApplication.State.ANDROIDPATCH_NEED_UPDATE) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(12.dp),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Row {
                Text(
                    text = stringResource(id = R.string.apm_not_installed),
                    style = MaterialTheme.typography.titleMedium
                )
            }
        }
        return
    }

    val viewModel = viewModel<APModuleViewModel>()

    LaunchedEffect(Unit) {
        if (viewModel.moduleList.isEmpty() || viewModel.isNeedRefresh) {
            viewModel.fetchModuleList()
        }
    }
    val webUILauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) { viewModel.fetchModuleList() }
    //TODO: FIXME -> val isSafeMode = Natives.getSafeMode()
    val isSafeMode = false
    val hasMagisk = hasMagisk()
    val hideInstallButton = isSafeMode || hasMagisk || !viewModel.isOverlayAvailable

    val moduleListState = rememberLazyListState()

    Scaffold(
        topBar = {
            TopBar()
        },
        floatingActionButton = if (hideInstallButton) {
            { /* Empty */ }
        } else {
            {
                val selectZipLauncher = rememberLauncherForActivityResult(
                    contract = ActivityResultContracts.StartActivityForResult()
                ) {
                    if (it.resultCode != RESULT_OK) {
                        return@rememberLauncherForActivityResult
                    }
                    val data = it.data ?: return@rememberLauncherForActivityResult
                    val uri = data.data ?: return@rememberLauncherForActivityResult

                    Log.i("ModuleScreen", "select zip result: $uri")

                    navigator.navigate(InstallScreenDestination(uri, MODULE_TYPE.APM))

                    viewModel.markNeedRefresh()
                }

                FloatingActionButton(contentColor = MaterialTheme.colorScheme.onPrimary,
                    containerColor = MaterialTheme.colorScheme.primary,
                    onClick = {
                        // select the zip file to install
                        val intent = Intent(Intent.ACTION_GET_CONTENT)
                        intent.type = "application/zip"
                        selectZipLauncher.launch(intent)
                    }) {
                    Icon(
                        painter = painterResource(id = R.drawable.package_import),
                        contentDescription = null
                    )
                }
            }
        },
        snackbarHost = { SnackbarHost(snackBarHost) }
    ) { innerPadding ->
        when {
            hasMagisk -> {
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(24.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        stringResource(R.string.apm_magisk_conflict),
                        textAlign = TextAlign.Center,
                    )
                }
            }

            else -> {
                ModuleList(
                    navigator, viewModel = viewModel,
                    modifier = Modifier
                        .padding(innerPadding)
                        .fillMaxSize(),
                    state = moduleListState,
                    onInstallModule = {
                        navigator.navigate(InstallScreenDestination(it, MODULE_TYPE.APM))
                    },
                    onClickModule = { id, name, hasWebUi ->
                        if (hasWebUi) {
                            webUILauncher.launch(
                                Intent(
                                    context, WebUIActivity::class.java
                                ).setData(Uri.parse("apatch://webui/$id")).putExtra("id", id)
                                    .putExtra("name", name)
                            )
                        }
                    },
                    snackBarHost = snackBarHost,
                    context = context
                )
            }
        }
    }
}

@OptIn(ExperimentalMaterialApi::class, ExperimentalMaterial3Api::class)
@Composable
private fun ModuleList(
    navigator: DestinationsNavigator,
    viewModel: APModuleViewModel,
    modifier: Modifier = Modifier,
    state: LazyListState,
    onInstallModule: (Uri) -> Unit,
    onClickModule: (id: String, name: String, hasWebUi: Boolean) -> Unit,
    snackBarHost: SnackbarHostState,
    context: Context
) {
    val failedEnable = stringResource(R.string.apm_failed_to_enable)
    val failedDisable = stringResource(R.string.apm_failed_to_disable)
    val failedUninstall = stringResource(R.string.apm_uninstall_failed)
    val successUninstall = stringResource(R.string.apm_uninstall_success)
    val reboot = stringResource(id = R.string.reboot)
    val rebootToApply = stringResource(id = R.string.apm_reboot_to_apply)
    val moduleStr = stringResource(id = R.string.apm)
    val uninstall = stringResource(id = R.string.apm_remove)
    val cancel = stringResource(id = android.R.string.cancel)
    val moduleUninstallConfirm = stringResource(id = R.string.apm_uninstall_confirm)
    val updateText = stringResource(R.string.apm_update)
    val changelogText = stringResource(R.string.apm_changelog)
    val downloadingText = stringResource(R.string.apm_downloading)
    val startDownloadingText = stringResource(R.string.apm_start_downloading)

    val loadingDialog = rememberLoadingDialog()
    val confirmDialog = rememberConfirmDialog()

    suspend fun onModuleUpdate(
        module: APModuleViewModel.ModuleInfo,
        changelogUrl: String,
        downloadUrl: String,
        fileName: String
    ) {
        val changelog = loadingDialog.withLoading {
            withContext(Dispatchers.IO) {
                if (Patterns.WEB_URL.matcher(changelogUrl).matches()) {
                    OkHttpClient().newCall(
                        okhttp3.Request.Builder().url(changelogUrl).build()
                    ).execute().body!!.string()
                } else {
                    changelogUrl
                }
            }
        }


        if (changelog.isNotEmpty()) {
            // changelog is not empty, show it and wait for confirm
            val confirmResult = confirmDialog.awaitConfirm(
                changelogText,
                content = changelog,
                markdown = true,
                confirm = updateText,
            )

            if (confirmResult != ConfirmResult.Confirmed) {
                return
            }
        }

        withContext(Dispatchers.Main) {
            Toast.makeText(
                context, startDownloadingText.format(module.name), Toast.LENGTH_SHORT
            ).show()
        }

        val downloading = downloadingText.format(module.name)
        withContext(Dispatchers.IO) {
            download(context,
                downloadUrl,
                fileName,
                downloading,
                onDownloaded = onInstallModule,
                onDownloading = {
                    launch(Dispatchers.Main) {
                        Toast.makeText(context, downloading, Toast.LENGTH_SHORT).show()
                    }
                })
        }
    }

    suspend fun onModuleUninstall(module: APModuleViewModel.ModuleInfo) {
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
                uninstallModule(module.id)
            }
        }

        if (success) {
            viewModel.fetchModuleList()
        }
        val message = if (success) {
            successUninstall.format(module.name)
        } else {
            failedUninstall.format(module.name)
        }
        val actionLabel = if (success) {
            reboot
        } else {
            null
        }
        val result = snackBarHost.showSnackbar(
            message = message,
            actionLabel = actionLabel,
            duration = SnackbarDuration.Long
        )
        if (result == SnackbarResult.ActionPerformed) {
            reboot()
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
                !viewModel.isOverlayAvailable -> {
                    item {
                        Box(
                            modifier = Modifier.fillParentMaxSize(),
                            contentAlignment = Alignment.Center
                        ) {
                            Text(
                                stringResource(R.string.apm_overlay_fs_not_available),
                                textAlign = TextAlign.Center
                            )
                        }
                    }
                }

                viewModel.moduleList.isEmpty() -> {
                    item {
                        Box(
                            modifier = Modifier.fillParentMaxSize(),
                            contentAlignment = Alignment.Center
                        ) {
                            Text(
                                stringResource(R.string.apm_empty), textAlign = TextAlign.Center
                            )
                        }
                    }
                }

                else -> {
                    items(viewModel.moduleList) { module ->
                        var isChecked by rememberSaveable(module) { mutableStateOf(module.enabled) }
                        val scope = rememberCoroutineScope()
                        val updatedModule by produceState(initialValue = Triple("", "", "")) {
                            scope.launch(Dispatchers.IO) {
                                value = viewModel.checkUpdate(module)
                            }
                        }

                        ModuleItem(
                            navigator,
                            module,
                            isChecked,
                            updatedModule.first,
                            onUninstall = {
                                scope.launch { onModuleUninstall(module) }
                            },
                            onCheckChanged = {
                                scope.launch {
                                    val success = loadingDialog.withLoading {
                                        withContext(Dispatchers.IO) {
                                            toggleModule(module.id, !isChecked)
                                        }
                                    }
                                    if (success) {
                                        isChecked = it
                                        viewModel.fetchModuleList()

                                        val result = snackBarHost.showSnackbar(
                                            message = rebootToApply,
                                            actionLabel = reboot,
                                            duration = SnackbarDuration.Long
                                        )
                                        if (result == SnackbarResult.ActionPerformed) {
                                            reboot()
                                        }
                                    } else {
                                        val message = if (isChecked) failedDisable else failedEnable
                                        snackBarHost.showSnackbar(message.format(module.name))
                                    }
                                }
                            },
                            onUpdate = {
                                scope.launch {
                                    onModuleUpdate(
                                        module,
                                        updatedModule.third,
                                        updatedModule.first,
                                        "${module.name}-${updatedModule.second}.zip"
                                    )
                                }
                            },
                            onClick = {
                                onClickModule(it.id, it.name, it.hasWebUi)
                            })
                        // fix last item shadow incomplete in LazyColumn
                        Spacer(Modifier.height(1.dp))
                    }
                }
            }
        }

        DownloadListener(context, onInstallModule)
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun TopBar() {
    TopAppBar(title = { Text(stringResource(R.string.apm)) })
}

@Composable
private fun ModuleItem(
    navigator: DestinationsNavigator,
    module: APModuleViewModel.ModuleInfo,
    isChecked: Boolean,
    updateUrl: String,
    onUninstall: (APModuleViewModel.ModuleInfo) -> Unit,
    onCheckChanged: (Boolean) -> Unit,
    onUpdate: (APModuleViewModel.ModuleInfo) -> Unit,
    onClick: (APModuleViewModel.ModuleInfo) -> Unit,
    modifier: Modifier = Modifier,
    alpha: Float = 1f,
) {
    val decoration = if (!module.remove) TextDecoration.None else TextDecoration.LineThrough
    val moduleAuthor = stringResource(id = R.string.apm_author)
    val viewModel = viewModel<APModuleViewModel>()
    Surface(
        modifier = modifier,
        color = MaterialTheme.colorScheme.surface,
        tonalElevation = 1.dp,
        shape = RoundedCornerShape(20.dp)
    ) {

        Box(
            modifier = Modifier
                .fillMaxWidth()
                .clickable { onClick(module) },
            contentAlignment = Alignment.Center
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
                    }

                    Switch(
                        enabled = !module.update,
                        checked = isChecked,
                        onCheckedChange = onCheckChanged
                    )
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
                    if (updateUrl.isNotEmpty()) {
                        ModuleUpdateButton(onClick = { onUpdate(module) })

                        Spacer(modifier = Modifier.width(12.dp))
                    }

                    if (module.hasWebUi) {
                        FilledTonalButton(
                            onClick = { onClick(module) },
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
                                text = stringResource(id = R.string.apm_webui_open),
                                maxLines = 1,
                                overflow = TextOverflow.Visible,
                                softWrap = false
                            )
                        }

                        Spacer(modifier = Modifier.width(12.dp))
                    }

                    if (module.hasActionScript) {
                        FilledTonalButton(
                            onClick = { 
                                navigator.navigate(ExecuteAPMActionScreenDestination(module.id))
                                viewModel.markNeedRefresh()
                            },
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
                                text = stringResource(id = R.string.apm_action),
                                maxLines = 1,
                                overflow = TextOverflow.Visible,
                                softWrap = false
                            )
                        }

                        Spacer(modifier = Modifier.width(12.dp))
                    }
                    ModuleRemoveButton(enabled = !module.remove, onClick = { onUninstall(module) })
                }
            }

            if (module.remove) {
                ModuleStateIndicator(R.drawable.trash)
            }
            if (module.update) {
                ModuleStateIndicator(R.drawable.device_mobile_down)
            }
        }
    }
}

"""



