package dev.tessera.iam.domain.token;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * An immutable set of JWT claims.
 *
 * <p>A thin wrapper over {@code Map<String, Object>} that the domain uses as the
 * <em>unsigned</em> payload of a {@link Token}. The map is defensively copied on
 * construction and exposed only through unmodifiable accessors, so a
 * {@code ClaimSet} cannot be mutated after creation. Signing/serialisation of
 * these claims is an adapter effect — no JOSE or crypto here.
 *
 * <p>Claim <em>values</em> are arbitrary JSON-shaped objects ({@code String},
 * {@code Number}, {@code Boolean}, nested {@code Map}/{@code List}); the domain
 * does not interpret them, so it stores them opaquely. Callers must not place
 * mutable collections inside and then mutate them externally — the wrapper guards
 * the top-level map, not deeply nested structures.
 */
public record ClaimSet(Map<String, Object> claims) {

    public ClaimSet {
        if (claims == null) {
            throw new IllegalArgumentException("ClaimSet claims must not be null");
        }
        // Defensive copy + unmodifiable view keeps the claim set immutable.
        claims = Collections.unmodifiableMap(new HashMap<>(claims));
    }

    /** @return an empty claim set. */
    public static ClaimSet empty() {
        return new ClaimSet(Map.of());
    }

    /**
     * Looks up a single claim by name.
     *
     * @param name the claim name
     * @return the claim value if present
     */
    public Optional<Object> claim(String name) {
        return Optional.ofNullable(claims.get(name));
    }
}
