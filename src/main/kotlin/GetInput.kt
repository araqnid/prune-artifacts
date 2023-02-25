package pruneArtifacts

import js.core.jso

/**
 * Gets the value of an input.
 *
 * Returns an empty string if the value is not defined and [required] is false.
 *
 * @param name name of the input to get
 * @param required throw error if input not specified
 * @param trimWhitespace trim whitespace from start and end of value
 * @see actions.core.getInput
 */
fun getInput(name: String, required: Boolean = false, trimWhitespace: Boolean = true): String {
    return actions.core.getInput(name, jso {
        this.required = required
        this.trimWhitespace = trimWhitespace
    })
}

/**
 * Gets the value of an input, or `null` if it is not supplied.
 *
 * @param name name of the input to get
 * @param trimWhitespace trim whitespace from start and end of value
 * @see actions.core.getInput
 */
fun getInputOrNull(name: String, trimWhitespace: Boolean = true): String? {
    return getInput(name, required = false, trimWhitespace = trimWhitespace).takeIf { it != "" }
}
