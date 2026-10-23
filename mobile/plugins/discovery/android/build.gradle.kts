import org.jetbrains.kotlin.gradle.dsl.JvmTarget
plugins { id("com.android.library"); id("org.jetbrains.kotlin.android") }
android {
    namespace = "com.ecojust.ohmypassword.discovery"
    compileSdk = 36
    defaultConfig { minSdk = 24; consumerProguardFiles("consumer-rules.pro") }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_1_8; targetCompatibility = JavaVersion.VERSION_1_8 }
}
kotlin { compilerOptions { jvmTarget = JvmTarget.JVM_1_8 } }
dependencies { implementation("androidx.appcompat:appcompat:1.6.0"); implementation(project(":tauri-android")) }
