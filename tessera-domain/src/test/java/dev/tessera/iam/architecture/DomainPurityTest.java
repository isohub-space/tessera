package dev.tessera.iam.architecture;

import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.lang.ArchRule;
import com.tngtech.archunit.lang.syntax.ArchRuleDefinition;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Tessera domain purity — ArchUnit rules guarding the framework-free domain. */
@DisplayName("Tessera Domain Purity — ArchUnit rules")
class DomainPurityTest {

    private static JavaClasses domainClasses;

    @BeforeAll
    static void importClasses() {
        domainClasses = new ClassFileImporter()
                .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
                .importPackages("dev.tessera.iam.domain");
    }

    @Test
    @DisplayName("Domain classes have no framework imports")
    void domainClasses_haveNoFrameworkImports() {
        ArchRule rule = ArchRuleDefinition.noClasses()
                .should().dependOnClassesThat()
                .resideInAnyPackage("jakarta..", "io.quarkus..", "org.hibernate..")
                .as("Domain layer must be framework-free — no jakarta, quarkus or hibernate imports");

        rule.allowEmptyShould(false).check(domainClasses);
    }

    @Test
    @DisplayName("Domain classes have no java.sql imports")
    void domainClasses_haveNoJavaSqlImports() {
        ArchRule rule = ArchRuleDefinition.noClasses()
                .should().dependOnClassesThat()
                .resideInAPackage("java.sql..")
                .as("Domain layer must not use java.sql — keep persistence concerns out of the domain");

        rule.allowEmptyShould(false).check(domainClasses);
    }
}
