package dev.tessera.iam.launcher.config;

import dev.tessera.iam.adapter.persistence.signingkey.SigningKeyConfig;
import dev.tessera.iam.adapter.rest.config.OidcDiscoveryConfig;
import io.quarkus.runtime.StartupEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

/**
 * Fails startup when the two issuer settings disagree.
 *
 * <p>{@code iam.oidc.issuer} is the issuer discovery advertises and tokens carry;
 * {@code iam.keys.issuer} is stamped on every signing key the rotation service mints. They
 * are separate properties in separate modules, and nothing used to tie them together: a
 * deployment that set one and not the other booted happily, signing under one issuer
 * identity while advertising another. Nothing logged it, and the mismatch surfaced only at
 * a relying party, as an issuer mismatch with no local signal.
 *
 * <p>{@link SigningKeyConfig#issuer()} now defaults to {@code ${iam.oidc.issuer}}, so the
 * common case — set {@code TESSERA_OIDC_ISSUER}, set nothing else — wires both. This check
 * closes the remaining hole: an explicit {@code iam.keys.issuer} that contradicts
 * {@code iam.oidc.issuer} aborts the boot with a message naming both values, rather than
 * being accepted because each value is individually valid.
 *
 * <p>This lives in the launcher because it is the only module that sees both configs; the
 * REST and persistence modules each own one half and neither can compare them.
 *
 * <p>Comparison is exact. An issuer identifier is compared character-for-character by every
 * relying party (OIDC Core §3.1.3.7), so {@code https://iam.example.com} and
 * {@code https://iam.example.com/} are two different issuers, and treating them as equal
 * here would hide exactly the class of defect this check exists to catch.
 */
@ApplicationScoped
public class IssuerConsistencyCheck {

    private static final Logger LOG = Logger.getLogger(IssuerConsistencyCheck.class);

    private final OidcDiscoveryConfig oidc;
    private final SigningKeyConfig keys;

    @Inject
    public IssuerConsistencyCheck(OidcDiscoveryConfig oidc, SigningKeyConfig keys) {
        this.oidc = oidc;
        this.keys = keys;
    }

    void onStart(@Observes StartupEvent event) {
        verify(oidc.issuer(), keys.issuer());
        LOG.debugf("Issuer settings agree: iam.oidc.issuer = iam.keys.issuer = %s", oidc.issuer());
    }

    /**
     * Compares the two configured issuers.
     *
     * @param oidcIssuer the value of {@code iam.oidc.issuer}
     * @param keysIssuer the value of {@code iam.keys.issuer}
     * @throws IllegalStateException if they differ, naming both values
     */
    static void verify(String oidcIssuer, String keysIssuer) {
        if (!java.util.Objects.equals(oidcIssuer, keysIssuer)) {
            throw new IllegalStateException(
                    "Issuer configuration is inconsistent: iam.oidc.issuer = '" + oidcIssuer
                            + "' but iam.keys.issuer = '" + keysIssuer + "'. Discovery would"
                            + " advertise one issuer while signing keys are stamped with another."
                            + " Set iam.keys.issuer to the same value, or leave it unset so it"
                            + " derives from iam.oidc.issuer.");
        }
    }
}
