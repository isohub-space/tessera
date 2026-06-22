/**
 * Quarkus assembly module for the IAM service.
 *
 * <p>Holds {@code application.properties}, the wired-together runtime, the
 * {@code @QuarkusTest} end-to-end test and the ArchUnit boundary catalogue.
 * Beans (the persistence adapter, the REST resource and the use-case producer)
 * are discovered across modules via the Jandex indices produced on each build.
 */
package dev.tessera.iam.launcher;
