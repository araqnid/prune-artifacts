val actionModule = project.name

val extension = extensions.create<PackageGithubActionExtension>("nodeJsApplication")

val packageExplodedTask = tasks.register("packageDistributableExploded") {
    group = "package"
    description = "Package action using a node_modules directory"
    dependsOn("productionExecutableCompileSync")
    val distDir = file("dist")
    inputs.dir("build/js/node_modules")
    outputs.dir(distDir)

    doLast {
        copy {
            from(file("build/js/node_modules"))
            into(distDir.resolve("node_modules"))
        }
        file(distDir.resolve("index.js")).printWriter().use { pw ->
            pw.println("require('$actionModule')")
        }
    }
}

val installNccTask = tasks.register("installNCC") {
    doNotTrackState("Running NCC updates cache files and defeats output tracking")
    val toolDir = buildDir.resolve(name)
    val nccScript = toolDir.resolve("node_modules/@vercel/ncc/dist/ncc/cli.js")

    doLast {
        if (!nccScript.exists()) {
            exec {
                workingDir = toolDir
                commandLine("npm", "install", "@vercel/ncc")
            }
        }
        check(nccScript.exists()) { "npm install did not produce a @vercel/ncc executable" }
    }
}

val packageWithNccTask = tasks.register("packageDistributableWithNCC") {
    group = "package"
    description = "Package action as a single file using BCC"

    dependsOn(installNccTask)
    dependsOn("productionExecutableCompileSync")

    val toolDir = buildDir.resolve(installNccTask.name)
    val distDir = file("dist")
    val jsBuildOutput = buildDir.resolve("js")
    val jsBuildFile = jsBuildOutput.resolve("packages/$actionModule/kotlin/$actionModule.js")

    inputs.file(jsBuildFile)
    outputs.dir(distDir)

    doLast {
        delete {
            delete(distDir)
        }
        exec {
            val params = mutableListOf(
                "node",
                toolDir.resolve("node_modules/@vercel/ncc/dist/ncc/cli.js"),
                "build",
                jsBuildFile,
                "-o",
                distDir,
            )
            if (extension.minify.get()) {
                params += listOf("-m", "--license", "LICENSE.txt")
            }
            if (extension.v8cache.get()) {
                params += listOf("--v8-cache")
            }
            if (extension.target.isPresent) {
                params += listOf("--target", extension.target.get())
            }
            commandLine(params)
        }
    }
}

tasks.register("package") {
    group = "package"
    description = "Produce dist directory with all dependencies for GitHub Actions"

    dependsOn(
        when (val packageStyle = rootProject.properties["githubAction.package"] ?: "ncc") {
            "ncc" -> packageWithNccTask
            "exploded" -> packageExplodedTask
            else -> error("Unhandled githubAction.package value: $packageStyle")
        }
    )
}
