package pruneArtifacts

import actions.core.info
import github.useGithub
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.filter
import kotlinx.coroutines.flow.onEach
import kotlin.js.Date

fun main() {
    runAction {
        val minSize = getInputOrNull("min-size")?.let { parseSize(it) } ?: 1048576
        val minAge = getInputOrNull("min-age")?.let { parseAge(it) } ?: (3 * 24 * 3600 * 1000)
        val names = getInput("name", required = false).split(Regex(""",\s*""")).filter { it.isNotBlank() }.toSet()

        debug("min size in bytes: $minSize")
        debug("min age in millis: $minAge")
        debug(if (names.isNotEmpty()) "name filter: $names" else "no name filter")

        useGithub { github ->
            var deletedCount = 0
            var deletedBytes = 0L

            val repo = run {
                val (ownerName, repoName) = GITHUB_REPOSITORY.split("/", limit = 2)
                github.getRepo(ownerName, repoName)
            }

            github.getRepoArtifacts(repo)
                .let { upstream ->
                    if (names.isEmpty())
                        upstream
                    else
                        upstream.filter { artifact -> artifact.name in names }
                }
                .onEach { artifact ->
                    debug(artifact, "$artifact")
                }
                .filter { artifact ->
                    val age = Date() - artifact.createdAt
                    !artifact.isExpired && artifact.sizeInBytes > minSize && age > minAge
                }
                .collect { artifact ->
                    try {
                        github.deleteRepoArtifact(repo, artifact)
                        info(artifact, "Deleted")
                        deletedCount++
                        deletedBytes += artifact.sizeInBytes
                    } catch (ex: Throwable) {
                        error(artifact, "Failed to delete: $ex")
                    }
                }

            info(
                "Deleted $deletedCount artifacts (total Mbytes: ${deletedBytes / 1048576})"
            )
        }
    }
}

private operator fun Date.minus(other: Date) = getTime() - other.getTime()

