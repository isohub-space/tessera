package dev.tessera.iam.adapter.persistence.db;

import io.quarkus.test.junit.QuarkusTestProfile;
import java.util.List;

/** Runs a test against {@link ResettingProxyPostgresResource} instead of the shared database resource. */
public class ResettingProxyProfile implements QuarkusTestProfile {

    @Override
    public List<TestResourceEntry> testResources() {
        return List.of(new TestResourceEntry(ResettingProxyPostgresResource.class));
    }

    @Override
    public boolean disableGlobalTestResources() {
        return true;
    }
}
