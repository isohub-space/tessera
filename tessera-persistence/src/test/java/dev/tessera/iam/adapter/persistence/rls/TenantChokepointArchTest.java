package dev.tessera.iam.adapter.persistence.rls;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.lang.ArchRule;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Machine-enforces the tenant-scoped chokepoint: repositories must reach the database
 * through {@code TenantScopedSession}, which binds {@code app.tenant_id} so the
 * row-level-security policies apply, never through the raw reactive
 * {@code Mutiny.SessionFactory}. A repository that injected the factory directly could
 * open a session with no tenant bound and either see nothing (fail-closed) or, worse,
 * leave the GUC set by a previous transaction in place — the chokepoint removes both
 * footguns by being the single place a session is obtained.
 */
@DisplayName("IAM Persistence — repositories go through the tenant-scoped chokepoint (ArchUnit)")
class TenantChokepointArchTest {

    private static JavaClasses persistenceClasses;

    @BeforeAll
    static void importClasses() {
        persistenceClasses = new ClassFileImporter()
                .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
                .importPackages("dev.tessera.iam.adapter.persistence");
    }

    @Test
    @DisplayName("repositories never touch Mutiny.SessionFactory directly — only TenantScopedSession")
    void repositories_routeThrough_tenantScopedSession() {
        ArchRule rule = noClasses()
                .that().resideInAPackage("dev.tessera.iam.adapter.persistence.repository..")
                .should().dependOnClassesThat()
                .haveFullyQualifiedName("org.hibernate.reactive.mutiny.Mutiny$SessionFactory")
                .as("Repositories must obtain sessions via TenantScopedSession so app.tenant_id "
                        + "is always bound — never the raw reactive Mutiny.SessionFactory")
                .allowEmptyShould(true);
        rule.check(persistenceClasses);
    }
}
