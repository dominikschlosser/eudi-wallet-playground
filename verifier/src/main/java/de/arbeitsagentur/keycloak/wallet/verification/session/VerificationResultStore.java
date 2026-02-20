/*
 * Copyright 2026 Bundesagentur für Arbeit
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.arbeitsagentur.keycloak.wallet.verification.session;

import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import de.arbeitsagentur.keycloak.wallet.verification.service.VerificationSteps;

@Component
public class VerificationResultStore {
    private static final Duration TTL = Duration.ofMinutes(15);
    private final Map<String, StoredResult> store = new ConcurrentHashMap<>();

    public void put(String state, VerificationResult result) {
        if (state == null || state.isBlank() || result == null) {
            return;
        }
        cleanupExpired();
        store.put(state, new StoredResult(result, Instant.now().plus(TTL)));
    }

    public VerificationResult get(String state) {
        if (state == null || state.isBlank()) {
            return null;
        }
        StoredResult stored = store.get(state);
        if (stored == null) {
            return null;
        }
        if (stored.expiresAt().isBefore(Instant.now())) {
            store.remove(state);
            return null;
        }
        return stored.result();
    }

    public void remove(String state) {
        if (state == null || state.isBlank()) {
            return;
        }
        store.remove(state);
    }

    private void cleanupExpired() {
        Instant now = Instant.now();
        store.entrySet().removeIf(entry -> entry.getValue().expiresAt().isBefore(now));
    }

    public record VerificationResult(String state,
                                      String message,
                                      boolean success,
                                      List<String> stepTitles,
                                      List<VerificationSteps.StepDetail> stepDetails,
                                      List<String> vpTokens,
                                      String vpTokenRaw,
                                      String idToken,
                                      Map<String, Object> payload) {
    }

    private record StoredResult(VerificationResult result, Instant expiresAt) {
    }
}
