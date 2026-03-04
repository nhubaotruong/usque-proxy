# Add project specific ProGuard rules here.
# You can control the set of applied configuration files using the
# proguardFiles setting in build.gradle.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

# Keep gomobile-generated usquebind bindings (native JNI + interface impls)
-keep class usquebind.** { *; }
-keep interface usquebind.** { *; }

# Keep VPN service (referenced from AndroidManifest.xml)
-keep class com.nhubaotruong.usqueproxy.vpn.UsqueVpnService { *; }

# Keep classes implementing native interfaces (VpnProtector callback)
-keepclassmembers class * implements usquebind.VpnProtector {
    *;
}
