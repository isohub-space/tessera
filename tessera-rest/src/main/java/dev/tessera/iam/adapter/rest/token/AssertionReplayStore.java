// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.adapter.rest.token;

import dev.tessera.iam.domain.tenancy.RealmKey;
import java.time.Instant;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;
import java.util.PriorityQueue;

/**
 * The spent {@code jti}s of accepted client assertions, each kept until its assertion expires.
 *
 * <p>Two bounds, so that exhaustion stays with whoever causes it: each client, a realm and an
 * issuer, holds at most {@code maxPerClient} live entries, and a client at its cap refuses only its
 * own new assertions; the whole store holds at most {@code maxTotal}, a backstop set well above
 * what the per-client caps add up to in practice. Expired entries leave in expiry order from a
 * priority queue, so no request scans the store.
 *
 * <p>Per instance: see {@link NimbusClientAssertionVerifier} for what that means with several.
 */
final class AssertionReplayStore {

    private final int maxPerClient;
    private final int maxTotal;
    private final Map<Spent, Instant> live = new HashMap<>();
    private final Map<Owner, Integer> perClient = new HashMap<>();
    private final PriorityQueue<Expiry> expiries = new PriorityQueue<>(Comparator.comparing(Expiry::until));

    AssertionReplayStore(int maxPerClient, int maxTotal) {
        if (maxPerClient < 1 || maxTotal < maxPerClient) {
            throw new IllegalArgumentException("need 1 <= maxPerClient <= maxTotal");
        }
        this.maxPerClient = maxPerClient;
        this.maxTotal = maxTotal;
    }

    /**
     * Records a {@code jti} until {@code until}.
     *
     * @return {@code true} when it was not live, and neither its client nor the store is full
     */
    synchronized boolean firstUse(RealmKey realm, String issuer, String jti, Instant until, Instant now) {
        evictExpired(now);
        Spent spent = new Spent(new Owner(realm, issuer), jti);
        if (live.containsKey(spent)
                || perClient.getOrDefault(spent.owner(), 0) >= maxPerClient
                || live.size() >= maxTotal) {
            return false;
        }
        live.put(spent, until);
        perClient.merge(spent.owner(), 1, Integer::sum);
        expiries.add(new Expiry(until, spent));
        return true;
    }

    private void evictExpired(Instant now) {
        for (Expiry head = expiries.peek(); head != null && head.until().isBefore(now); head = expiries.peek()) {
            expiries.poll();
            live.remove(head.spent());
            perClient.computeIfPresent(head.spent().owner(), (owner, count) -> count == 1 ? null : count - 1);
        }
    }

    private record Owner(RealmKey realm, String issuer) {
    }

    private record Spent(Owner owner, String jti) {
    }

    private record Expiry(Instant until, Spent spent) {
    }
}
