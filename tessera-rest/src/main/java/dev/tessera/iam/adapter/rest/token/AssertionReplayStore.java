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
 * <p>Three nested bounds, so that exhaustion stays with whoever causes it: each client, a realm, an
 * issuer and a subject (so the clients of one shared external issuer do not share one cap), holds
 * at most {@code maxPerClient} live entries, and a client at its cap refuses only its own new
 * assertions; each realm holds at most {@code maxPerRealm}, so a tenant with many busy
 * clients refuses only its own; and the whole store holds at most {@code maxTotal}, which bounds
 * the memory all realms together can take. Expired entries leave in expiry order from a priority
 * queue, so no request scans the store.
 *
 * <p>Per instance: see {@link NimbusClientAssertionVerifier} for what that means with several.
 */
final class AssertionReplayStore {

    private final int maxPerClient;
    private final int maxPerRealm;
    private final int maxTotal;
    private final Map<Spent, Instant> live = new HashMap<>();
    private final Map<Owner, Integer> perClient = new HashMap<>();
    private final Map<RealmKey, Integer> perRealm = new HashMap<>();
    private final PriorityQueue<Expiry> expiries = new PriorityQueue<>(Comparator.comparing(Expiry::until));

    AssertionReplayStore(int maxPerClient, int maxPerRealm, int maxTotal) {
        if (maxPerClient < 1 || maxPerRealm < maxPerClient || maxTotal < maxPerRealm) {
            throw new IllegalArgumentException("iam.client-assertion replay caps must satisfy 1 <= "
                    + "replay-cache-max-entries-per-client (" + maxPerClient + ") <= "
                    + "replay-cache-max-entries-per-realm (" + maxPerRealm + ") <= "
                    + "replay-cache-max-entries (" + maxTotal + ")");
        }
        this.maxPerClient = maxPerClient;
        this.maxPerRealm = maxPerRealm;
        this.maxTotal = maxTotal;
    }

    /**
     * Records a {@code jti} until {@code until}.
     *
     * @return {@code true} when it was not live, and neither its client, its realm nor the store is full
     */
    synchronized boolean firstUse(RealmKey realm, String issuer, String subject, String jti, Instant until,
            Instant now) {
        evictExpired(now);
        Spent spent = new Spent(new Owner(realm, issuer, subject), jti);
        if (live.containsKey(spent)
                || perClient.getOrDefault(spent.owner(), 0) >= maxPerClient
                || perRealm.getOrDefault(realm, 0) >= maxPerRealm
                || live.size() >= maxTotal) {
            return false;
        }
        live.put(spent, until);
        perClient.merge(spent.owner(), 1, Integer::sum);
        perRealm.merge(realm, 1, Integer::sum);
        expiries.add(new Expiry(until, spent));
        return true;
    }

    private void evictExpired(Instant now) {
        for (Expiry head = expiries.peek(); head != null && head.until().isBefore(now); head = expiries.peek()) {
            expiries.poll();
            live.remove(head.spent());
            perClient.computeIfPresent(head.spent().owner(), (owner, count) -> count == 1 ? null : count - 1);
            perRealm.computeIfPresent(head.spent().owner().realm(), (realm, count) -> count == 1 ? null : count - 1);
        }
    }

    private record Owner(RealmKey realm, String issuer, String subject) {
    }

    private record Spent(Owner owner, String jti) {
    }

    private record Expiry(Instant until, Spent spent) {
    }
}
