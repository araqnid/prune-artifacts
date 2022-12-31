plugins {
    kotlin("js") version "1.6.21"
    kotlin("plugin.serialization") version "1.8.0" apply false
    id("package-github-action")
}

repositories {
    mavenCentral()
}

kotlin {
    js(IR) {
        nodejs()
        useCommonJs()
        binaries.executable()
        compilations["main"].packageJson {
        }
        compilations.all {
            compileKotlinTask.kotlinOptions.freeCompilerArgs += listOf("-opt-in=kotlin.RequiresOptIn")
        }
    }
}

dependencies {
    api(kotlin("stdlib-js"))
    implementation(project(":github-client"))
    implementation(project(":actions-toolkit"))
    implementation(platform("org.jetbrains.kotlinx:kotlinx-coroutines-bom:1.6.1"))
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core")

    testImplementation(kotlin("test-js"))
    testImplementation("org.araqnid.kotlin.assert-that:assert-that:0.1.1")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test")
}

actionPackaging {
    nodeVersion.set("16.15.0")
    minify.set(false)
}
