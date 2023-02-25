plugins {
    kotlin("js") version "1.8.10"
    kotlin("plugin.serialization") version "1.8.10" apply false
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
    }
}

dependencies {
    api(kotlin("stdlib-js"))
    implementation(project(":github-client"))
    implementation(platform("org.jetbrains.kotlinx:kotlinx-coroutines-bom:1.6.4"))
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core")
    implementation(platform("org.jetbrains.kotlin-wrappers:kotlin-wrappers-bom:1.0.0-pre.504"))
    implementation("org.jetbrains.kotlin-wrappers:kotlin-node")
    implementation("org.jetbrains.kotlin-wrappers:kotlin-actions-toolkit")

    testImplementation(kotlin("test-js"))
    testImplementation("org.araqnid.kotlin.assert-that:assert-that:0.1.1")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test")
}

actionPackaging {
    val nccVersionValue = properties["ncc.version"]
    if (nccVersionValue is String) {
        nccVersion.set(nccVersionValue)
    }
}

node {
    val nodeVersionFile = rootProject.projectDir.resolve(".nvmrc")
    if (nodeVersionFile.exists()) {
        version.set(nodeVersionFile.readText().trim())
        download.set(true)
    }
}
