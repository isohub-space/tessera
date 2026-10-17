package dev.tessera.iam.adapter.persistence.rls;

import static org.assertj.core.api.Assertions.assertThat;

import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.domain.JavaMethodCall;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import java.util.Set;
import java.util.TreeSet;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Pins which operations may use the retrying read path ({@link TenantScopedSession#inTenantRead}).
 *
 * <p>A retried unit of work runs twice when its first connection fails, so only pure reads may use
 * it. The list below is the reviewed set of read-only call sites: moving a write there (refresh-token
 * creation, rotation or revocation, a persist or a state update) fails this test, and so does adding a
 * new read, which then has to be reviewed and listed. Writes go through {@link TenantScopedSession#inTenant},
 * which never retries.
 */
@DisplayName("IAM Persistence — only reviewed read-only operations use the retrying read path (ArchUnit)")
class ReadRetryScopeArchTest {

    private static final Set<String> REVIEWED_READS = Set.of(
            "AuthSessionRepository.findById",
            "ConsentRepository.findByUserAndClient",
            "CredentialRepository.findByUser",
            "OAuthClientRepository.findByClientKey",
            "OAuthClientRepository.findById",
            "UserRepository.findBySubject",
            "UserRepository.findById",
            "UserRepository.findByUsername",
            "DbRefreshTokenStore.find",
            "DbKeyProviderAdapter.sign",
            "DbKeyProviderAdapter.publishedJwks",
            "DbKeyProviderAdapter.currentSigningKey");

    private static final Set<String> WRITES = Set.of(
            "DbRefreshTokenStore.createFamily",
            "DbRefreshTokenStore.consumeAndRotate",
            "DbRefreshTokenStore.revokeFamily",
            "AuthSessionRepository.persist",
            "AuthSessionRepository.updateState",
            "ConsentRepository.persist",
            "CredentialRepository.persist",
            "OAuthClientRepository.persist",
            "UserRepository.persist");

    private static JavaClasses persistenceClasses;

    @BeforeAll
    static void importClasses() {
        persistenceClasses = new ClassFileImporter()
                .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
                .importPackages("dev.tessera.iam.adapter.persistence");
    }

    private static Set<String> callersOf(String methodName) {
        Set<String> callers = new TreeSet<>();
        for (JavaMethodCall call : persistenceClasses.get(TenantScopedSession.class).getMethodCallsToSelf()) {
            if (call.getTarget().getName().equals(methodName)
                    && !call.getOriginOwner().isEquivalentTo(TenantScopedSession.class)) {
                callers.add(call.getOriginOwner().getSimpleName() + "." + enclosingMethod(call.getOrigin().getName()));
            }
        }
        return callers;
    }

    // A call inside a lambda is attributed to the synthetic lambda$<method>$<n>.
    private static String enclosingMethod(String name) {
        return name.startsWith("lambda$") ? name.substring(7, name.indexOf('$', 7)) : name;
    }

    @Test
    @DisplayName("the retrying read path is used by exactly the reviewed read-only operations")
    void onlyReviewedReadsRetry() {
        assertThat(callersOf("inTenantRead")).containsExactlyInAnyOrderElementsOf(REVIEWED_READS);
    }

    @Test
    @DisplayName("refresh-token creation, rotation and revocation and every persist or update stay on the non-retrying path")
    void writesNeverRetry() {
        assertThat(callersOf("inTenantRead")).doesNotContainAnyElementsOf(WRITES);
        assertThat(callersOf("inTenant")).containsAll(WRITES);
    }
}
