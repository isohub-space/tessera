package dev.tessera.iam.adapter.persistence;

import static org.assertj.core.api.Assertions.assertThat;

import com.tngtech.archunit.core.domain.JavaClass;
import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.domain.JavaMethodCall;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Structural timing defence: every place a presented credential or token secret is compared with
 * a stored value compares in constant time. This is deliberately not a statistical timing test,
 * which would be flaky in CI; it pins the code shape that makes the comparison constant-time.
 *
 * <p>The sites are listed exactly. Each of them must not compare with {@code String.equals},
 * {@code Objects.equals} or {@code Arrays.equals}, which return at the first differing byte, and the
 * sites that compare raw values must call {@code MessageDigest.isEqual}. Client secrets and user
 * passwords are compared by password4j's Argon2 check, whose own comparison is pinned too, so a
 * dependency upgrade that dropped it would fail here.
 *
 * <p>At the sites that compare raw secret values the rule is stricter: no call or method reference
 * named like an equality or ordering at all, whatever its owner, so {@code Object.equals}, a
 * record's generated {@code equals} wrapping the hash, or {@code Arrays.mismatch} are caught too.
 *
 * <p>The list is closed on purpose: a new place that compares a presented secret with a stored one
 * must be added to {@link #COMPARISON_SITES} (and, if it compares raw values, to
 * {@link #RAW_COMPARATORS}) in the same change.
 */
@DisplayName("Credential and token comparisons are constant-time (ArchUnit, structural)")
class ConstantTimeComparisonArchTest {

    /** The classes holding a secret comparison; none may use an early-exit equality. */
    private static final List<String> COMPARISON_SITES = List.of(
            "dev.tessera.iam.domain.authcode.PkceVerifier",
            "dev.tessera.iam.domain.refresh.RefreshReuseDetection",
            "dev.tessera.iam.application.refresh.RefreshTokenCodec",
            "dev.tessera.iam.application.IntrospectService",
            "dev.tessera.iam.application.RefreshService",
            "dev.tessera.iam.adapter.persistence.client.Argon2ClientSecretVerifier",
            "dev.tessera.iam.adapter.persistence.credential.Argon2PasswordCredentialVerifier");

    /** The sites that compare raw bytes themselves, and so must call {@code MessageDigest.isEqual}. */
    private static final List<String> RAW_COMPARATORS = List.of(
            "dev.tessera.iam.domain.authcode.PkceVerifier",
            "dev.tessera.iam.domain.refresh.RefreshReuseDetection",
            "dev.tessera.iam.application.refresh.RefreshTokenCodec");

    /** The sites that delegate the refresh-token hash comparison to the codec. */
    private static final List<String> CODEC_DELEGATES = List.of(
            "dev.tessera.iam.application.IntrospectService",
            "dev.tessera.iam.application.RefreshService");

    private static final List<String> ARGON2_VERIFIERS = List.of(
            "dev.tessera.iam.adapter.persistence.client.Argon2ClientSecretVerifier",
            "dev.tessera.iam.adapter.persistence.credential.Argon2PasswordCredentialVerifier");

    private static final Set<String> EARLY_EXIT_EQUALITY = Set.of(
            "java.lang.String.equals",
            "java.lang.String.equalsIgnoreCase",
            "java.lang.String.contentEquals",
            "java.util.Objects.equals",
            "java.util.Arrays.equals");

    /** Method names that compare by early exit, whichever class declares them. */
    private static final Set<String> EARLY_EXIT_NAMES = Set.of(
            "equals", "equalsIgnoreCase", "contentEquals", "compareTo", "compare", "mismatch");

    private static JavaClasses classes;

    @BeforeAll
    static void importClasses() {
        classes = new ClassFileImporter()
                .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
                .importPackages("dev.tessera.iam", "com.password4j");
    }

    @Test
    @DisplayName("no comparison site uses an early-exit equality")
    void noEarlyExitEquality() {
        for (String site : COMPARISON_SITES) {
            assertThat(calls(site).filter(EARLY_EXIT_EQUALITY::contains).toList())
                    .as("early-exit equality in %s", site)
                    .isEmpty();
        }
    }

    @Test
    @DisplayName("raw secret comparisons call no method named equals, compare or mismatch, on any owner")
    void rawComparatorsCallNoEqualityByName() {
        for (String site : RAW_COMPARATORS) {
            JavaClass owner = classes.get(site);
            Stream<String> called = Stream.concat(
                    owner.getMethodCallsFromSelf().stream().map(call -> call.getTarget().getName()),
                    owner.getMethodReferencesFromSelf().stream().map(ref -> ref.getTarget().getName()));
            assertThat(called.filter(EARLY_EXIT_NAMES::contains).toList())
                    .as("early-exit equality by name in %s", site)
                    .isEmpty();
        }
    }

    @Test
    @DisplayName("PKCE and refresh-token hashes are compared with MessageDigest.isEqual")
    void rawComparisonsUseMessageDigestIsEqual() {
        for (String site : RAW_COMPARATORS) {
            assertThat(calls(site)).as("comparison in %s", site)
                    .contains("java.security.MessageDigest.isEqual");
        }
        for (String site : CODEC_DELEGATES) {
            assertThat(calls(site)).as("refresh-token hash comparison in %s", site)
                    .contains("dev.tessera.iam.application.refresh.RefreshTokenCodec.matches");
        }
    }

    @Test
    @DisplayName("client secrets and passwords go through password4j's Argon2 check, itself constant-time")
    void argon2ChecksAreConstantTime() {
        for (String site : ARGON2_VERIFIERS) {
            assertThat(calls(site)).as("credential check in %s", site)
                    .contains("com.password4j.Password.check", "com.password4j.HashChecker.with");
        }
        // slowEquals is inherited from AbstractHashingFunction; the call names the subclass.
        assertThat(calls("com.password4j.Argon2Function"))
                .as("password4j's Argon2 comparison")
                .anyMatch(call -> call.endsWith(".slowEquals"))
                .doesNotContain("java.util.Arrays.equals", "java.lang.String.equals");
    }

    /** Every method called from {@code className}, lambdas included, as {@code owner.name}. */
    private static Stream<String> calls(String className) {
        JavaClass owner = classes.get(className);
        return owner.getMethodCallsFromSelf().stream()
                .map(JavaMethodCall::getTarget)
                .map(target -> target.getOwner().getName() + "." + target.getName());
    }
}
