import org.gradle.api.provider.Property

abstract class PackageGithubActionExtension {
    abstract val minify: Property<Boolean>
    abstract val v8cache: Property<Boolean>
    abstract val target: Property<String>

    init {
        minify.convention(true)
        v8cache.convention(true)
    }
}
