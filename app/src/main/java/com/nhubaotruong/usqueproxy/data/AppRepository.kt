package com.nhubaotruong.usqueproxy.data

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.drawable.Drawable

data class AppInfo(
    val packageName: String,
    val label: String,
    val icon: Drawable,
)

class AppRepository(private val context: Context) {

    fun getInstalledApps(): List<AppInfo> {
        val pm = context.packageManager
        return pm.getInstalledApplications(PackageManager.GET_META_DATA)
            .filter { it.packageName != context.packageName }
            .filter { it.flags and ApplicationInfo.FLAG_SYSTEM == 0 || pm.getLaunchIntentForPackage(it.packageName) != null }
            .map { info ->
                AppInfo(
                    packageName = info.packageName,
                    label = info.loadLabel(pm).toString(),
                    icon = info.loadIcon(pm),
                )
            }
            .sortedBy { it.label.lowercase() }
    }
}
