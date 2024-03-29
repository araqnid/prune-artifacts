plugins {
    kotlin("js") version "1.8.20"
    kotlin("plugin.serialization") version "1.8.20" apply false
    id("org.araqnid.kotlin-github-action") version "0.0.4"
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
    implementation(platform("org.jetbrains.kotlin-wrappers:kotlin-wrappers-bom:1.0.0-pre.507"))
    implementation("org.jetbrains.kotlin-wrappers:kotlin-node")
    implementation("org.jetbrains.kotlin-wrappers:kotlin-actions-toolkit")

    testImplementation(kotlin("test-js"))
    testImplementation("org.araqnid.kotlin.assert-that:assert-that:0.1.1")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test")
}

actionPackaging {
    nccVersion.set(providers.gradleProperty("ncc.version").orElse("latest"))
}

node {
    val nvmrc = providers.fileContents(layout.projectDirectory.file(".nvmrc")).asText.map { it.trim() }.orElse("")
    version.set(nvmrc)
    download.set(nvmrc.map { it.isNotEmpty() })
}
