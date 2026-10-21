package dev.tessera.iam.domain.client;

/**
 * A redirect URI that {@link RedirectUriPolicy} refuses to register. Carries the RFC 7591 §3.2.2
 * error code {@code invalid_redirect_uri} and the offending URI, so a registration path can
 * report the refusal in protocol terms.
 */
public final class InvalidRedirectUriException extends IllegalArgumentException {

    /** The RFC 7591 §3.2.2 error code for every refusal. */
    public static final String ERROR = "invalid_redirect_uri";

    private static final long serialVersionUID = 1L;

    private final String redirectUri;

    InvalidRedirectUriException(String redirectUri, String reason) {
        super(ERROR + ": " + redirectUri + " (" + reason + ")");
        this.redirectUri = redirectUri;
    }

    /** @return {@value #ERROR} */
    public String error() {
        return ERROR;
    }

    /** @return the refused redirect URI, verbatim */
    public String redirectUri() {
        return redirectUri;
    }
}
