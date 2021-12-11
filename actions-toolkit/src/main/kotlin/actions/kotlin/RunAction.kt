package actions.kotlin

import actions.core.setFailed
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlin.coroutines.Continuation
import kotlin.coroutines.CoroutineContext
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.coroutines.startCoroutine

/**
 * Launches a suspending body of code for the action, and calls [setFailed] if it throws an exception.
 *
 * This is intended to be used as the top level entry point, analagous to `runBlocking` in a JVM
 * context.
 *
 * @param context Coroutine context (a [Job] will be added)
 * @param body Body of action
 */
fun runAction(
    context: CoroutineContext = EmptyCoroutineContext, body: suspend CoroutineScope.() -> Unit
) {
    // if callers want to register completion handlers on the job, that should work
    val job = Job()
    val scope = CoroutineScope(context + job)

    val completion = object : Continuation<Unit> {
        override val context: CoroutineContext
            get() = context

        override fun resumeWith(result: Result<Unit>) {
            result.fold({
                job.complete()
            }, { ex ->
                job.completeExceptionally(ex)
                setFailed(ex)
            })
        }
    }

    body.startCoroutine(scope, completion)
}
