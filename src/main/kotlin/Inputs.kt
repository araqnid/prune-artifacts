package pruneArtifacts

private val MB_PATTERN = Regex("""(\d+)MB?""", RegexOption.IGNORE_CASE)
private val KB_PATTERN = Regex("""(\d+)KB?""", RegexOption.IGNORE_CASE)
private val B_PATTERN = Regex("""(\d+)B?""", RegexOption.IGNORE_CASE)

fun parseSize(input: String): Long {
    MB_PATTERN.matchEntire(input)?.let { matchResult ->
        return matchResult.groupValues[1].toLong() * 1048576
    }
    KB_PATTERN.matchEntire(input)?.let { matchResult ->
        return matchResult.groupValues[1].toLong() * 1024
    }
    B_PATTERN.matchEntire(input)?.let { matchResult ->
        return matchResult.groupValues[1].toLong()
    }
    kotlin.error("Invalid size: $input")
}

private val DAYS_PATTERN = Regex("""(\d+)\s*d(ays?)?""", RegexOption.IGNORE_CASE)
private val HOURS_PATTERN = Regex("""(\d+)\s*h((ou)?rs?)?""", RegexOption.IGNORE_CASE)

fun parseAge(input: String): Long {
    DAYS_PATTERN.matchEntire(input)?.let { matchResult ->
        return matchResult.groupValues[1].toLong() * 24 * 3600 * 1000
    }
    HOURS_PATTERN.matchEntire(input)?.let { matchResult ->
        return matchResult.groupValues[1].toLong() * 3600 * 1000
    }
    kotlin.error("Invalid age: $input")
}
