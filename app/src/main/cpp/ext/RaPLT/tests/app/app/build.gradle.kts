plugins {
    id("com.android.application")
}

android {
    namespace = "com.raplt.test"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.raplt.test"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "1.0"
        ndk {
            abiFilters += listOf("x86_64", "arm64-v8a")
            version = "25.1.8937393"
        }
        externalNativeBuild {
            cmake { arguments += "-DANDROID_STL=none" }
        }
    }
    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }
}
