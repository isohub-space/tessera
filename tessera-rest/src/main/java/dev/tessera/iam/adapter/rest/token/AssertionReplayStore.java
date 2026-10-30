// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.adapter.rest.token;

import dev.tessera.iam.application.port.out.ClientAssertionVerifierPort.ReplayBudget;
import dev.tessera.iam.domain.tenancy.RealmKey;
import java.time.Instant;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.Map;
import java.util.PriorityQueue;

/**
 * The spent {@code jti}s of accepted client assertions, each kept until its assertion expires.
 *
 * <p><strong>One namespace, two budgets.</strong> A {@code jti} is spent for every endpoint alike:
 * an assertion accepted at {@code /token} is refused at {@code /introspect} and {@code /revoke}, and
 * the other way round. What a newly spent {@code jti} counts against depends on the endpoint
 * ({@link ReplayBudget}): {@code /token} and the two token-management endpoints have separate caps,
 * so a resource server whose introspection calls (driven by the tokens its own callers present)
 * fill its budget is refused at {@code /introspect} and {@code /revoke} only, and still obtains its
 * tokens at {@code /token}.
 *
 * <p>Within each budget, three nested bounds, so that exhaustion stays with whoever causes it: each
 * client, a realm, an issuer and a subject (so the clients of one shared external issuer do not
 * share one cap), holds at most its per-client cap of live entries ({@code maxPerClient} at
 * {@code /token}, {@code maxPerClientIntrospection} at {@code /introspect} and {@code /revoke}), and
 * a client at its cap refuses only its own new assertions; each realm holds at most
 * {@code maxPerRealm}, so a tenant with many busy clients refuses only its own; and the whole budget
 * holds at most {@code maxTotal}. The store therefore holds at most twice {@code maxTotal} entries.
 * Expired entries leave in expiry order from a priority queue, so no request scans the store. Every
 * check and update happens under one lock, so the namespace and the counters never disagree.
 *
 * <p>Per instance: see {@link NimbusClientAssertionVerifier} for what that means with several.
 */
final class AssertionReplayStore {

    private final Map<ReplayBudget, Integer> maxPerClient = new EnumMap<>(ReplayBudget.class);
    private final int maxPerRealm;
    private final int maxTotal;
    private final Map<Spent, Instant> live = new HashMap<>();
    private final Map<Owner, Integer> perClient = new HashMap<>();
    private final Map<RealmBudget, Integer> perRealm = new HashMap<>();
    private final Map<ReplayBudget, Integer> perBudget = new EnumMap<>(ReplayBudget.class);
    private final PriorityQueue<Expiry> expiries = new PriorityQueue<>(Comparator.comparing(Expiry::until));

    /** With the same per-client cap for both budgets. */
    AssertionReplayStore(int maxPerClient, int maxPerRealm, int maxTotal) {
        this(maxPerClient, maxPerClient, maxPerRealm, maxTotal);
    }

    AssertionReplayStore(int maxPerClient, int maxPerClientIntrospection, int maxPerRealm, int maxTotal) {
        if (maxPerClient < 1 || maxPerClientIntrospection < 1 || maxPerRealm < Math.max(maxPerClient,
                maxPerClientIntrospection) || maxTotal < maxPerRealm) {
            throw new IllegalArgumentException("iam.client-assertion replay caps must satisfy 1 <= "
                    + "replay-cache-max-entries-per-client (" + maxPerClient + ") and 1 <= "
                    + "introspection-replay-cache-max-entries-per-client (" + maxPerClientIntrospection
                    + "), each <= replay-cache-max-entries-per-realm (" + maxPerRealm + ") <= "
                    + "replay-cache-max-entries (" + maxTotal + ")");
        }
        this.maxPerClient.put(ReplayBudget.TOKEN, maxPerClient);
        this.maxPerClient.put(ReplayBudget.INTROSPECTION_AND_REVOCATION, maxPerClientIntrospection);
        this.maxPerRealm = maxPerRealm;
        this.maxTotal = maxTotal;
    }

    /**
     * Records a {@code jti} until {@code until}. Only distinct {@code jti}s count against the caps, so
     * a reusable one takes one slot however often, and at whichever endpoint, it is presented.
     *
     * @param singleUse whether a {@code jti} that is already live is refused ({@code true}) or
     *                  accepted again until it expires
     * @param global whether the {@code jti} is spent across realms: a trusted external issuer and
     *               subject name one workload wherever it is presented, while a {@code private_key_jwt}
     *               client's id names a client within its realm only
     * @param budget the caps a newly spent {@code jti} counts against; whether it is already live is
     *               answered across both budgets
     * @return {@code true} when it was not live at any endpoint, and neither its client, its realm
     *         nor the store is full in {@code budget}
     */
    synchronized boolean firstUse(RealmKey realm, String issuer, String subject, String jti, boolean singleUse,
            boolean global, Instant until, Instant now, ReplayBudget budget) {
        evictExpired(now);
        Spent spent = new Spent(global ? null : realm, issuer, subject, jti);
        if (live.containsKey(spent)) {
            return !singleUse;
        }
        Owner owner = new Owner(realm, issuer, subject, budget);
        RealmBudget realmBudget = new RealmBudget(realm, budget);
        if (perClient.getOrDefault(owner, 0) >= maxPerClient.get(budget)
                || perRealm.getOrDefault(realmBudget, 0) >= maxPerRealm
                || perBudget.getOrDefault(budget, 0) >= maxTotal) {
            return false;
        }
        live.put(spent, until);
        perClient.merge(owner, 1, Integer::sum);
        perRealm.merge(realmBudget, 1, Integer::sum);
        perBudget.merge(budget, 1, Integer::sum);
        expiries.add(new Expiry(until, spent, owner));
        return true;
    }

    private void evictExpired(Instant now) {
        for (Expiry head = expiries.peek(); head != null && head.until().isBefore(now); head = expiries.peek()) {
            expiries.poll();
            live.remove(head.spent());
            Owner owner = head.owner();
            perClient.computeIfPresent(owner, (key, count) -> count == 1 ? null : count - 1);
            perRealm.computeIfPresent(new RealmBudget(owner.realm(), owner.budget()),
                    (key, count) -> count == 1 ? null : count - 1);
            perBudget.computeIfPresent(owner.budget(), (key, count) -> count == 1 ? null : count - 1);
        }
    }

    /** Whose caps an entry counts against: a client, in one budget. */
    private record Owner(RealmKey realm, String issuer, String subject, ReplayBudget budget) {
    }

    private record RealmBudget(RealmKey realm, ReplayBudget budget) {
    }

    /**
     * The replay identity, the same at every endpoint: {@code scope} is the realm, or {@code null}
     * when it is spent across realms.
     */
    private record Spent(RealmKey scope, String issuer, String subject, String jti) {
    }

    /** One live entry, and the owner whose caps it counts against. */
    private record Expiry(Instant until, Spent spent, Owner owner) {
    }
}
