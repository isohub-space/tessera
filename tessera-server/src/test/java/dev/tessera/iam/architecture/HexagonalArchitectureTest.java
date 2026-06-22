package dev.tessera.iam.architecture;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.classes;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;
import static com.tngtech.archunit.library.dependencies.SlicesRuleDefinition.slices;

import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.lang.ArchRule;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Machine-enforces the hexagonal module boundaries of the IAM service on every
 * {@code mvn verify}. Extend this catalogue as the service grows.
 */
@DisplayName("IAM Hexagonal Architecture — ArchUnit boundary rules")
class HexagonalArchitectureTest {

    private static JavaClasses allClasses;

    @BeforeAll
    static void importClasses() {
        allClasses = new ClassFileImporter()
                .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
                .importPackages("dev.tessera.iam");
    }

    @Test
    @DisplayName("Domain has no Quarkus / jakarta / Hibernate dependencies")
    void domain_isFrameworkFree() {
        ArchRule rule = noClasses()
                .that().resideInAPackage("dev.tessera.iam.domain..")
                .should().dependOnClassesThat()
                .resideInAnyPackage("io.quarkus..", "jakarta..", "org.hibernate..")
                .as("Domain must be a pure-Java module — compile and test without Quarkus boot")
                .allowEmptyShould(true);
        rule.check(allClasses);
    }

    @Test
    @DisplayName("Application ports have no Jakarta / Quarkus framework imports")
    void applicationPorts_areFrameworkFree() {
        ArchRule rule = noClasses()
                .that().resideInAPackage("dev.tessera.iam.application..")
                .should().dependOnClassesThat()
                .resideInAnyPackage(
                        "jakarta.enterprise..", "jakarta.ws.rs..", "jakarta.inject..", "io.quarkus..")
                .as("Application ports must be implementable by any adapter without the Quarkus runtime")
                .allowEmptyShould(true);
        rule.check(allClasses);
    }

    @Test
    @DisplayName("REST does not depend on persistence")
    void rest_doesNot_dependOn_persistence() {
        ArchRule rule = noClasses()
                .that().resideInAPackage("dev.tessera.iam.adapter.rest..")
                .should().dependOnClassesThat()
                .resideInAPackage("dev.tessera.iam.adapter.persistence..")
                .as("Adapters must not cross-import — route through application ports only")
                .allowEmptyShould(true);
        rule.check(allClasses);
    }

    @Test
    @DisplayName("Persistence does not depend on REST")
    void persistence_doesNot_dependOn_rest() {
        ArchRule rule = noClasses()
                .that().resideInAPackage("dev.tessera.iam.adapter.persistence..")
                .should().dependOnClassesThat()
                .resideInAPackage("dev.tessera.iam.adapter.rest..")
                .as("Persistence is an outbound adapter — it never reaches back into REST")
                .allowEmptyShould(true);
        rule.check(allClasses);
    }

    @Test
    @DisplayName("Only REST classes carry @Path")
    void onlyRestClasses_carry_path() {
        ArchRule rule = classes()
                .that().areAnnotatedWith(jakarta.ws.rs.Path.class)
                .should().resideInAPackage("dev.tessera.iam.adapter.rest..")
                .as("JAX-RS resource classes belong only in the REST adapter")
                .allowEmptyShould(true);
        rule.check(allClasses);
    }

    @Test
    @DisplayName("No cyclic dependencies between module slices")
    void modules_haveNo_cyclicDependencies() {
        ArchRule rule = slices()
                .matching("dev.tessera.iam.(*)..")
                .should().beFreeOfCycles()
                .as("Cyclic module dependencies break incremental builds and ArchUnit reasoning");
        rule.check(allClasses);
    }
}
