val actionModule = project.name

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
    val toolDir = file("build").resolve(name)
    outputs.upToDateWhen {
        toolDir.resolve("package.json").exists()
    }

    doLast {
        exec {
            workingDir = toolDir
            commandLine("npm", "install", "@vercel/ncc")
        }
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
        exec {
            commandLine(
                "node",
                toolDir.resolve("node_modules/@vercel/ncc/dist/ncc/cli.js"),
                "build",
                jsBuildFile
            )
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
