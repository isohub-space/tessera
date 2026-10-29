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
 * Pins which operations use which path of {@link TenantScopedSession}.
 *
 * <p>Both paths attempt a unit of work again only when it failed before its work function was
 * called (the transaction began, the tenant was bound, or no connection was handed over): nothing of
 * the unit had been sent, so nothing can be applied twice. {@link TenantScopedSession#inTenantRead}
 * is for the reviewed read-only operations, {@link TenantScopedSession#inTenant} for everything that
 * writes; each has its own retry budget. Both lists below are exact: moving an operation from one
 * path to the other, or adding a caller of either, fails this test until it is reviewed and listed.
 *
 * <p>Every write below uses the pre-work retry for the same reason: the retry happens only while its
 * own statements have not been sent, which does not depend on what those statements are. A failure
 * after the work started is never retried; {@code ConnectionResetRecoveryIT} checks that for
 * refresh-token creation, rotation and revocation and for a session update.
 */
@DisplayName("IAM Persistence — the read and write paths are used by exactly the reviewed operations (ArchUnit)")
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

    private static final Set<String> REVIEWED_WRITES = Set.of(
            "DbRefreshTokenStore.createFamily",
            "DbRefreshTokenStore.consumeAndRotate",
            "DbRefreshTokenStore.revokeFamily",
            "DbRefreshTokenStore.revokeFamiliesOf",
            "AuthSessionRepository.persist",
            "AuthSessionRepository.updateState",
            "ConsentRepository.persist",
            "CredentialRepository.persist",
            "OAuthClientRepository.persist",
            "UserRepository.persist",
            "KeyRotationService.mintPending",
            "KeyRotationService.promoteToActive",
            "FirstBootProvisioner.ensureSigningKey");

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
    @DisplayName("the read path is used by exactly the reviewed read-only operations")
    void onlyReviewedReads() {
        assertThat(callersOf("inTenantRead")).containsExactlyInAnyOrderElementsOf(REVIEWED_READS);
    }

    @Test
    @DisplayName("the write path is used by exactly the reviewed writes, refresh-token creation, rotation and revocation among them")
    void onlyReviewedWrites() {
        assertThat(callersOf("inTenant")).containsExactlyInAnyOrderElementsOf(REVIEWED_WRITES);
    }
}
