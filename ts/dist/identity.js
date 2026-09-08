/** Where every adapter in this family answers. */
export const whoamiPath = "/.access/whoami";
/** Ask the application who the caller is.
 *
 * Resolves rather than throws, because every outcome is something a
 * console has to render: signed in, signed out, or unable to say. The
 * distinction between the last two is the whole reason this returns a
 * status rather than an identity or null. */
export async function fetchIdentity(options = {}) {
    const path = options.path ?? whoamiPath;
    try {
        const response = await fetch(path, {
            credentials: "same-origin",
            headers: { Accept: "application/json" },
            ...(options.signal ? { signal: options.signal } : {}),
        });
        // A 401 is an answer: the application knows, and the answer is nobody.
        if (response.status === 401 || response.status === 403) {
            return { status: "signed-out" };
        }
        if (!response.ok) {
            return { status: "unknown", error: `${path} answered ${response.status}` };
        }
        const body = (await response.json());
        if (body.status === "signed-in") {
            return { ...body, status: "signed-in" };
        }
        return { ...body, status: "signed-out" };
    }
    catch (cause) {
        if (cause instanceof DOMException && cause.name === "AbortError") {
            // The caller went away. Not an answer, and not an error to show.
            return { status: "loading" };
        }
        return { status: "unknown", error: cause instanceof Error ? cause.message : String(cause) };
    }
}
//# sourceMappingURL=identity.js.map