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
package de.arbeitsagentur.keycloak.wallet.demo.oid4vp;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import de.arbeitsagentur.keycloak.wallet.common.storage.CredentialStore;
import de.arbeitsagentur.keycloak.wallet.common.util.ClaimDisplayFilter;
import de.arbeitsagentur.keycloak.wallet.common.util.JsonPathNormalizer;
import de.arbeitsagentur.keycloak.wallet.common.sdjwt.SdJwtParser;
import de.arbeitsagentur.keycloak.wallet.common.mdoc.MdocParser;
import de.arbeitsagentur.keycloak.wallet.common.mdoc.MdocSelectiveDiscloser;
import de.arbeitsagentur.keycloak.wallet.common.sdjwt.SdJwtSelectiveDiscloser;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.PathNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class PresentationService {
    private static final Logger LOG = LoggerFactory.getLogger(PresentationService.class);

    /** Known DCQL root-level fields per OID4VP 1.0 / DCQL specification */
    private static final Set<String> KNOWN_DCQL_ROOT_FIELDS = Set.of(
            "credentials", "credential_sets"
    );

    /** Known credential-level fields in DCQL */
    private static final Set<String> KNOWN_CREDENTIAL_FIELDS = Set.of(
            "id", "format", "claims", "credential_set", "claim_set", "meta", "vct"
    );

    /** Known claim-level fields in DCQL */
    private static final Set<String> KNOWN_CLAIM_FIELDS = Set.of(
            "path", "value", "values", "id"
    );

    private final CredentialStore credentialStore;
    private final ObjectMapper objectMapper;
    private final SdJwtParser sdJwtParser;
    private final MdocParser mdocParser;
    private final MdocSelectiveDiscloser mdocSelectiveDiscloser;
    private final SdJwtSelectiveDiscloser sdJwtSelectiveDiscloser;

    public PresentationService(CredentialStore credentialStore, ObjectMapper objectMapper) {
        this.credentialStore = credentialStore;
        this.objectMapper = objectMapper;
        this.sdJwtParser = new SdJwtParser(objectMapper);
        this.mdocParser = new MdocParser();
        this.mdocSelectiveDiscloser = new MdocSelectiveDiscloser();
        this.sdJwtSelectiveDiscloser = new SdJwtSelectiveDiscloser(sdJwtParser);
    }

    public Optional<Presentation> findPresentation(String userId, String dcqlQuery) {
        return findPresentation(userId != null ? List.of(userId) : List.of(), dcqlQuery);
    }

    public Optional<Presentation> findPresentation(List<String> userIds, String dcqlQuery) {
        return preparePresentations(userIds, dcqlQuery).map(bundle -> {
            String token;
            if (bundle.matches().size() == 1) {
                token = bundle.matches().get(0).vpToken();
            } else {
                List<String> tokens = bundle.matches().stream().map(DescriptorMatch::vpToken).toList();
                token = toJsonArray(tokens);
            }
            Map<String, Object> credential = bundle.matches().get(0).credential();
            return new Presentation(token, credential);
        });
    }

    public Optional<PresentationBundle> preparePresentations(String userId, String dcqlQuery) {
        return preparePresentations(userId != null ? List.of(userId) : List.of(), dcqlQuery);
    }

    public Optional<PresentationBundle> preparePresentations(List<String> userIds, String dcqlQuery) {
        Optional<PresentationOptions> options = preparePresentationOptions(userIds, dcqlQuery);
        if (options.isEmpty()) {
            return Optional.empty();
        }
        Optional<List<DescriptorMatch>> distinct = selectDistinctMatches(options.get());
        return distinct.map(PresentationBundle::new);
    }

    public Optional<PresentationOptions> preparePresentationOptions(String userId, String dcqlQuery) {
        return preparePresentationOptions(userId != null ? List.of(userId) : List.of(), dcqlQuery);
    }

    public Optional<PresentationOptions> preparePresentationOptions(List<String> userIds, String dcqlQuery) {
        List<CredentialStore.Entry> entries = listEntries(userIds);
        if (entries.isEmpty()) {
            return Optional.empty();
        }
        List<CredentialRequest> definitions = parseCredentialRequests(dcqlQuery);
        if (definitions.isEmpty()) {
            definitions = fallbackRequests(entries);
        }
        ensureUniqueDescriptorIds(definitions);

        Map<String, List<DescriptorMatch>> matchesByCredentialId = buildMatchesByCredentialId(definitions, entries);
        List<CredentialSetQuery> credentialSets = parseRootCredentialSets(dcqlQuery);

        LOG.debug("credential_sets parsed: {} sets, matchesByCredentialId keys: {}",
                credentialSets.size(), matchesByCredentialId.keySet());

        if (!credentialSets.isEmpty()) {
            return buildOptionsFromCredentialSets(credentialSets, matchesByCredentialId, definitions);
        }
        return buildOptionsRequiringAllCredentials(definitions, matchesByCredentialId);
    }

    private Map<String, List<DescriptorMatch>> buildMatchesByCredentialId(
            List<CredentialRequest> definitions, List<CredentialStore.Entry> entries) {
        Map<String, List<DescriptorMatch>> result = new LinkedHashMap<>();
        for (CredentialRequest definition : definitions) {
            List<MatchResult> candidates = findMatches(definition, entries);
            result.put(definition.id(), candidates.stream().map(MatchResult::match).toList());
        }
        return result;
    }

    private Optional<PresentationOptions> buildOptionsFromCredentialSets(
            List<CredentialSetQuery> credentialSets,
            Map<String, List<DescriptorMatch>> matchesByCredentialId,
            List<CredentialRequest> definitions) {
        Set<String> allRequiredCredIds = new HashSet<>();

        for (CredentialSetQuery credentialSet : credentialSets) {
            if (!credentialSet.required()) {
                LOG.debug("Skipping non-required credential_set");
                continue;
            }

            List<String> satisfiedOption = findFirstSatisfiedOption(credentialSet.options(), matchesByCredentialId);
            if (satisfiedOption == null) {
                LOG.debug("Required credential_set could not be satisfied");
                return Optional.empty();
            }
            allRequiredCredIds.addAll(satisfiedOption);
        }

        List<DescriptorOptions> options = allRequiredCredIds.stream()
                .map(credId -> definitions.stream().filter(d -> credId.equals(d.id())).findFirst().orElse(null))
                .filter(req -> req != null)
                .map(req -> new DescriptorOptions(req, matchesByCredentialId.get(req.id())))
                .toList();
        return Optional.of(new PresentationOptions(options));
    }

    private List<String> findFirstSatisfiedOption(List<List<String>> options,
                                                   Map<String, List<DescriptorMatch>> matchesByCredentialId) {
        for (List<String> option : options) {
            boolean allHaveMatches = option.stream()
                    .allMatch(credId -> {
                        List<DescriptorMatch> matches = matchesByCredentialId.get(credId);
                        return matches != null && !matches.isEmpty();
                    });
            if (allHaveMatches) {
                LOG.debug("credential_sets option satisfied: {}", option);
                return option;
            }
        }
        return null;
    }

    private Optional<PresentationOptions> buildOptionsRequiringAllCredentials(
            List<CredentialRequest> definitions, Map<String, List<DescriptorMatch>> matchesByCredentialId) {
        List<DescriptorOptions> options = new ArrayList<>();
        for (CredentialRequest definition : definitions) {
            List<DescriptorMatch> matches = matchesByCredentialId.get(definition.id());
            if (matches == null || matches.isEmpty()) {
                return Optional.empty();
            }
            options.add(new DescriptorOptions(definition, matches));
        }
        return Optional.of(new PresentationOptions(options));
    }

    /**
     * Credential Set Query per OID4VP 1.0 Section 6.2.
     * @param options Non-empty array of options, each option is a list of credential IDs
     * @param required Whether this set is required (defaults to true per spec)
     */
    private record CredentialSetQuery(List<List<String>> options, boolean required) {}

    private List<CredentialSetQuery> parseRootCredentialSets(String dcqlQuery) {
        if (dcqlQuery == null || dcqlQuery.isBlank()) {
            return List.of();
        }
        try {
            JsonNode root = objectMapper.readTree(dcqlQuery);
            JsonNode credentialSets = root.path("credential_sets");
            if (!credentialSets.isArray()) {
                return List.of();
            }
            List<CredentialSetQuery> result = new ArrayList<>();
            for (JsonNode setNode : credentialSets) {
                JsonNode optionsNode = setNode.path("options");
                if (!optionsNode.isArray()) {
                    continue;
                }
                List<List<String>> options = new ArrayList<>();
                for (JsonNode optionNode : optionsNode) {
                    if (!optionNode.isArray()) {
                        continue;
                    }
                    List<String> credIds = new ArrayList<>();
                    for (JsonNode idNode : optionNode) {
                        if (idNode.isTextual()) {
                            credIds.add(idNode.asText());
                        }
                    }
                    if (!credIds.isEmpty()) {
                        options.add(credIds);
                    }
                }
                if (!options.isEmpty()) {
                    // Per OID4VP 1.0: required defaults to true if omitted
                    boolean required = !setNode.has("required") || setNode.path("required").asBoolean(true);
                    result.add(new CredentialSetQuery(options, required));
                }
            }
            return result;
        } catch (Exception e) {
            LOG.debug("Failed to parse credential_sets: {}", e.getMessage());
            return List.of();
        }
    }

    private List<CredentialRequest> fallbackRequests(List<CredentialStore.Entry> entries) {
        List<CredentialRequest> fallback = new ArrayList<>();
        for (int i = 0; i < entries.size(); i++) {
            Map<String, Object> claims = extractClaims(objectMapper.convertValue(entries.get(i).credential(), Map.class));
            List<ClaimRequest> claimRequests = claims.keySet().stream()
                    .map(name -> new ClaimRequest(name, null))
                    .toList();
            fallback.add(new CredentialRequest("credential-%d".formatted(i + 1), List.of(), claimRequests, List.of(), List.of(), null));
        }
        return fallback;
    }

    private List<MatchResult> findMatches(CredentialRequest definition, List<CredentialStore.Entry> entries) {
        Map<String, MatchResult> matchesByFile = new LinkedHashMap<>();
        for (int i = 0; i < entries.size(); i++) {
            CredentialStore.Entry entry = entries.get(i);
            Map<String, Object> map = objectMapper.convertValue(entry.credential(), Map.class);
            String format = resolveFormat(map);
            String vct = extractVct(map);
            if (!matchesFormat(definition, format)) {
                continue;
            }
            // Check vct_values and doctype_value from meta section
            if (!matchesVctOrDoctype(definition, vct)) {
                continue;
            }
            if (!matchesCredentialSet(definition, map, vct, format)) {
                continue;
            }
            Map<String, Object> claims = extractClaims(map);
            if (!matchesClaimSetWithClaims(definition, claims)) {
                continue;
            }
            if (!matchesConstraints(definition, map)) {
                continue;
            }
            Map<String, Object> disclosed = filterClaims(claims, definition.claims());
            // Count claims with value constraints (these are REQUIRED)
            long constrainedClaimCount = definition.claims() != null
                    ? definition.claims().stream()
                        .filter(c -> c != null && c.name() != null && !c.name().isBlank()
                                && c.constValue() != null && !c.constValue().isBlank())
                        .count()
                    : 0;
            // Count all valid claim requests
            long totalClaimCount = definition.claims() != null
                    ? definition.claims().stream()
                        .filter(c -> c != null && c.name() != null && !c.name().isBlank())
                        .count()
                    : 0;
            boolean hasRequestedClaims = totalClaimCount > 0;
            // If there are constrained claims, credential must have at least those
            // If no constrained claims, at least one claim must match (to avoid showing completely irrelevant credentials)
            long requiredCount = constrainedClaimCount > 0 ? constrainedClaimCount : (hasRequestedClaims ? 1 : 0);
            if (hasRequestedClaims && (disclosed == null || disclosed.size() < requiredCount)) {
                LOG.debug("Credential {} rejected: has {} of {} required claims (total requested: {})",
                        entry.fileName(), disclosed != null ? disclosed.size() : 0, requiredCount, totalClaimCount);
                continue;
            }
            MatchResult candidate = new MatchResult(buildMatch(definition, entry, map, disclosed), i, disclosed.size());
            String key = entry.fileName() != null ? entry.fileName() : "entry-" + i;
            MatchResult existing = matchesByFile.get(key);
            if (existing == null || candidate.score() > existing.score()) {
                matchesByFile.put(key, candidate);
            }
        }
        // sort to keep deterministic order, higher score first
        List<MatchResult> matches = new ArrayList<>(matchesByFile.values());
        matches.sort((a, b) -> Integer.compare(b.score(), a.score()));
        return matches;
    }

    private void ensureUniqueDescriptorIds(List<CredentialRequest> definitions) {
        Set<String> seen = new HashSet<>();
        int counter = 1;
        for (int i = 0; i < definitions.size(); i++) {
            CredentialRequest def = definitions.get(i);
            String id = def.id();
            if (id == null || id.isBlank() || seen.contains(id)) {
                String newId;
                do {
                    newId = "credential-%d".formatted(counter++);
                } while (seen.contains(newId));
                def = new CredentialRequest(newId, def.constraints(), def.claims(), def.credentialSets(), def.claimSets(), def.format());
                definitions.set(i, def);
            }
            seen.add(def.id());
        }
    }

    private boolean requiresExactMatch(CredentialRequest definition) {
        boolean hasConstraints = definition.constraints() != null && !definition.constraints().isEmpty();
        boolean hasClaimSets = definition.claimSets() != null && !definition.claimSets().isEmpty();
        boolean hasCredentialSets = definition.credentialSets() != null && !definition.credentialSets().isEmpty();
        boolean hasFormat = definition.format() != null && !definition.format().isBlank();
        return hasConstraints || hasClaimSets || hasCredentialSets || hasFormat;
    }

    private List<CredentialStore.Entry> listEntries(List<String> userIds) {
        if (userIds == null || userIds.isEmpty()) {
            return List.of();
        }
        List<CredentialStore.Entry> entries = credentialStore.listCredentialEntries(userIds);
        return entries == null ? List.of() : entries;
    }

    private boolean matchesConstraints(CredentialRequest definition, Map<String, Object> map) {
        if (definition.constraints() == null || definition.constraints().isEmpty()) {
            return true;
        }
        Object credentialDocument = objectMapper.convertValue(map, Object.class);
        return definition.constraints().stream().allMatch(c -> c.matches(credentialDocument));
    }

    private boolean matchesFormat(CredentialRequest definition, String format) {
        if (definition.format() == null || definition.format().isBlank()
                || "all".equalsIgnoreCase(definition.format())) {
            return true;
        }
        if (format == null || format.isBlank()) {
            return false;
        }
        if (definition.format().equalsIgnoreCase(format)) {
            return true;
        }
        return isSdJwt(definition.format()) && isSdJwt(format);
    }

    private boolean isSdJwt(String format) {
        String normalized = format == null ? "" : format.toLowerCase();
        return normalized.contains("sd-jwt");
    }

    /**
     * Check if credential's vct matches the definition's vct_values or doctype_value.
     * Per DCQL spec, meta.vct_values is for SD-JWT VC, meta.doctype_value is for mDoc.
     */
    private boolean matchesVctOrDoctype(CredentialRequest definition, String credentialVct) {
        // If neither vct_values nor doctype_value is specified, match any
        boolean hasVctConstraint = definition.vctValues() != null && !definition.vctValues().isEmpty();
        boolean hasDoctypeConstraint = definition.doctypeValue() != null && !definition.doctypeValue().isBlank();

        if (!hasVctConstraint && !hasDoctypeConstraint) {
            return true;
        }

        if (credentialVct == null || credentialVct.isBlank()) {
            return false;
        }

        // Check vct_values (for SD-JWT)
        if (hasVctConstraint) {
            for (String allowedVct : definition.vctValues()) {
                if (credentialVct.equalsIgnoreCase(allowedVct)) {
                    return true;
                }
            }
        }

        // Check doctype_value (for mDoc)
        if (hasDoctypeConstraint) {
            if (credentialVct.equalsIgnoreCase(definition.doctypeValue())) {
                return true;
            }
        }

        return false;
    }

    private String normalizeFormat(String format) {
        if (format == null) {
            return null;
        }
        String trimmed = format.trim();
        if (trimmed.isBlank() || "all".equalsIgnoreCase(trimmed)) {
            return null;
        }
        return trimmed;
    }

    private DescriptorMatch buildMatch(CredentialRequest definition, CredentialStore.Entry entry, Map<String, Object> map) {
        Map<String, Object> disclosed = filterClaims(extractClaims(map), definition.claims());
        return buildMatch(definition, entry, map, disclosed);
    }

    private DescriptorMatch buildMatch(CredentialRequest definition, CredentialStore.Entry entry,
                                       Map<String, Object> map, Map<String, Object> disclosed) {
        String vct = extractVct(map);
        if (vct != null && !vct.isBlank() && !map.containsKey("vct")) {
            map.put("vct", vct);
        }
        Set<String> requestedClaims = definition.claims().stream()
                .flatMap(c -> {
                    List<String> names = new ArrayList<>();
                    if (c.name() != null && !c.name().isBlank()) {
                        names.add(c.name());
                    }
                    if (c.jsonPath() != null && !c.jsonPath().isBlank()) {
                        String normalized = JsonPathNormalizer.normalize(c.jsonPath());
                        if (normalized != null) {
                            names.add(normalized);
                            String first = JsonPathNormalizer.firstSegment(normalized);
                            if (first != null) {
                                names.add(first);
                            }
                        }
                    }
                    return names.stream();
                })
                .collect(Collectors.toSet());
        String vpToken = toVpToken(map, definition.claims(), requestedClaims);
        Map<String, Object> displayDisclosed = filterDisplayClaims(disclosed);
        return new DescriptorMatch(definition.id(), entry.fileName(), map, vpToken, definition.claims(), displayDisclosed,
                definition.credentialSets(), definition.claimSets());
    }

    private Map<String, Object> filterDisplayClaims(Map<String, Object> claims) {
        return ClaimDisplayFilter.filterForDisplay(claims);
    }

    private List<CredentialRequest> parseCredentialRequests(String dcqlQuery) {
        if (dcqlQuery == null || dcqlQuery.isBlank()) {
            return List.of();
        }
        try {
            JsonNode root = objectMapper.readTree(dcqlQuery);

            // Validate and log unknown root-level fields
            validateAndLogUnknownFields(root, KNOWN_DCQL_ROOT_FIELDS, "DCQL root");

            JsonNode credentials = root.path("credentials");
            if (!credentials.isArray()) {
                LOG.warn("DCQL query missing or invalid 'credentials' array");
                return List.of();
            }

            // Log unsupported features
            if (root.has("credential_sets") && !root.path("credential_sets").isMissingNode()) {
                LOG.debug("DCQL credential_sets feature detected - processing with best-effort matching");
            }

            List<CredentialRequest> result = new ArrayList<>();
            for (JsonNode credentialNode : credentials) {
                // Validate credential-level fields
                validateAndLogUnknownFields(credentialNode, KNOWN_CREDENTIAL_FIELDS, "DCQL credential");

                String id = textOrNull(credentialNode, "id");
                if (id == null || id.isBlank()) {
                    id = "credential-%d".formatted(result.size() + 1);
                }
                String format = normalizeFormat(textOrNull(credentialNode, "format"));

                // Validate claim-level fields
                JsonNode claimsNode = credentialNode.path("claims");
                if (claimsNode.isArray()) {
                    for (JsonNode claimNode : claimsNode) {
                        if (claimNode.isObject()) {
                            validateAndLogUnknownFields(claimNode, KNOWN_CLAIM_FIELDS, "DCQL claim in '" + id + "'");
                            // Log unsupported 'values' constraint
                            if (claimNode.has("values") && !claimNode.path("values").isMissingNode()) {
                                LOG.debug("DCQL claim 'values' constraint detected in '{}' - not fully supported, using first value", id);
                            }
                        }
                    }
                }

                List<ClaimRequest> claims = extractClaimRequestsFromDcql(claimsNode);
                List<FieldConstraint> constraints = buildConstraintsFromClaims(claims);
                List<CredentialSetFilter> credentialSets = parseCredentialSets(credentialNode.path("credential_set"));
                List<ClaimSet> claimSets = parseClaimSets(credentialNode.path("claim_set"));

                // Parse meta section for vct_values and doctype_value
                JsonNode metaNode = credentialNode.path("meta");
                List<String> vctValues = new ArrayList<>();
                String doctypeValue = null;
                if (!metaNode.isMissingNode() && metaNode.isObject()) {
                    JsonNode vctValuesNode = metaNode.path("vct_values");
                    if (vctValuesNode.isArray()) {
                        for (JsonNode v : vctValuesNode) {
                            if (v.isTextual()) {
                                vctValues.add(v.asText());
                            }
                        }
                    }
                    JsonNode doctypeNode = metaNode.path("doctype_value");
                    if (doctypeNode.isTextual()) {
                        doctypeValue = doctypeNode.asText();
                    }
                }

                result.add(new CredentialRequest(id, constraints, claims, credentialSets, claimSets, format, vctValues, doctypeValue));
            }
            return result;
        } catch (Exception e) {
            LOG.warn("Failed to parse DCQL query: {}", e.getMessage());
            LOG.debug("DCQL parse error details", e);
            return List.of();
        }
    }

    private void validateAndLogUnknownFields(JsonNode node, Set<String> knownFields, String context) {
        if (!node.isObject()) {
            return;
        }
        ((tools.jackson.databind.node.ObjectNode) node).properties().forEach(entry -> {
            String fieldName = entry.getKey();
            if (!knownFields.contains(fieldName)) {
                LOG.debug("Unknown/unsupported DCQL field '{}' in {} - ignoring", fieldName, context);
            }
        });
    }

    private List<CredentialSetFilter> parseCredentialSets(JsonNode node) {
        if (!node.isArray()) {
            return List.of();
        }
        List<CredentialSetFilter> filters = new ArrayList<>();
        for (JsonNode n : node) {
            String id = null;
            String vct = null;
            String format = null;
            if (n.isTextual()) {
                id = n.asText();
            } else if (n.isObject()) {
                id = textOrNull(n, "id");
                if (id == null) {
                    id = textOrNull(n, "type");
                }
                vct = textOrNull(n, "vct");
                format = normalizeFormat(textOrNull(n, "format"));
            }
            if ((id != null && !id.isBlank()) || (vct != null && !vct.isBlank()) || (format != null && !format.isBlank())) {
                filters.add(new CredentialSetFilter(id, vct, format));
            }
        }
        return filters;
    }

    private List<ClaimSet> parseClaimSets(JsonNode node) {
        if (!node.isArray()) {
            return List.of();
        }
        List<ClaimSet> claimSets = new ArrayList<>();
        for (JsonNode entry : node) {
            List<ClaimRequest> claims = new ArrayList<>();
            if (entry.isArray()) {
                for (JsonNode claimNode : entry) {
                    addClaimFromNode(claims, claimNode);
                }
            } else if (entry.isObject()) {
                JsonNode claimsNode = entry.has("claims") ? entry.get("claims") : entry;
                if (claimsNode.isArray()) {
                    for (JsonNode claimNode : claimsNode) {
                        addClaimFromNode(claims, claimNode);
                    }
                } else {
                    addClaimFromNode(claims, claimsNode);
                }
            } else if (entry.isTextual()) {
                claims.add(new ClaimRequest(entry.asText(), null));
            }
            if (!claims.isEmpty()) {
                claimSets.add(new ClaimSet(claims));
            }
        }
        return claimSets;
    }

    private void addClaimFromNode(List<ClaimRequest> target, JsonNode claimNode) {
        JsonNode pathNode = claimNode.path("path");
        String constValue = claimNode.path("value").asText(null);
        if (claimNode.isTextual() && (pathNode.isMissingNode() || !pathNode.isArray())) {
            target.add(new ClaimRequest(claimNode.asText(), constValue));
            return;
        }
        if (!pathNode.isArray() || pathNode.isEmpty()) {
            return;
        }
        String name = claimFromSegments(pathNode);
        if (name != null && !name.isBlank()) {
            target.add(new ClaimRequest(name, constValue, jsonPathFromSegments(pathNode)));
        }
    }

    private String textOrNull(JsonNode node, String field) {
        if (node.has(field) && node.get(field).isTextual()) {
            String value = node.get(field).asText();
            return value.isBlank() ? null : value;
        }
        return null;
    }

    public Optional<List<DescriptorMatch>> selectDistinctMatches(PresentationOptions options) {
        return selectDistinctMatches(options, Map.of());
    }

    public Optional<List<DescriptorMatch>> selectDistinctMatches(PresentationOptions options, Map<String, String> selections) {
        if (options == null || options.options() == null || options.options().isEmpty()) {
            return Optional.empty();
        }
        List<DescriptorMatch> ordered = new ArrayList<>();
        Set<String> used = new HashSet<>();
        boolean solved = backtrackMatches(options.options(), selections == null ? Map.of() : selections, 0, used, ordered);
        return solved ? Optional.of(ordered) : Optional.empty();
    }

    private boolean backtrackMatches(List<DescriptorOptions> options, Map<String, String> selections,
                                     int index, Set<String> usedFiles, List<DescriptorMatch> chosen) {
        if (index >= options.size()) {
            return true;
        }
        DescriptorOptions current = options.get(index);
        List<DescriptorMatch> candidates = new ArrayList<>();
        String selection = selections.get(current.request().id());
        if (selection != null) {
            DescriptorMatch selected = current.findByFileName(selection);
            if (selected != null) {
                candidates.add(selected);
            }
        }
        for (DescriptorMatch candidate : current.candidates()) {
            if (candidates.stream().noneMatch(existing -> existing.credentialFileName() != null
                    && existing.credentialFileName().equals(candidate.credentialFileName()))) {
                candidates.add(candidate);
            }
        }
        for (DescriptorMatch candidate : candidates) {
            String fileName = candidate.credentialFileName();
            if (fileName != null && usedFiles.contains(fileName)) {
                continue;
            }
            chosen.add(candidate);
            if (fileName != null) {
                usedFiles.add(fileName);
            }
            if (backtrackMatches(options, selections, index + 1, usedFiles, chosen)) {
                return true;
            }
            chosen.remove(chosen.size() - 1);
            if (fileName != null) {
                usedFiles.remove(fileName);
            }
        }
        return false;
    }

    private List<FieldConstraint> buildConstraintsFromClaims(List<ClaimRequest> claims) {
        List<FieldConstraint> constraints = new ArrayList<>();
        for (ClaimRequest claim : claims) {
            if (claim.name() == null || claim.name().isBlank()) {
                continue;
            }
            if (claim.constValue() == null || claim.constValue().isBlank()) {
                continue;
            }
            List<String> paths = new ArrayList<>();
            if (claim.jsonPath() != null && !claim.jsonPath().isBlank()) {
                paths.add(claim.jsonPath());
                String normalized = JsonPathNormalizer.normalize(claim.jsonPath());
                if (normalized != null && !normalized.startsWith("credentialSubject") && !normalized.startsWith("vc.")) {
                    paths.add(JsonPathNormalizer.toCredentialSubjectPath(normalized));
                    paths.add(JsonPathNormalizer.toVcCredentialSubjectPath(normalized));
                }
                // Allow dotted claim names (like address.country) to match stored flat structures.
                String flat = JsonPathNormalizer.normalize(claim.jsonPath());
                if (flat != null && flat.contains(".")) {
                    String bracketedFlat = "['" + flat.replace("'", "\\'") + "']";
                    paths.add("$.credentialSubject" + bracketedFlat);
                    paths.add("$.vc.credentialSubject" + bracketedFlat);
                }
            } else {
                paths.add(JsonPathNormalizer.toCredentialSubjectPath(claim.name()));
                paths.add(JsonPathNormalizer.toVcCredentialSubjectPath(claim.name()));
                if (claim.name().contains(".")) {
                    String bracketed = "['" + claim.name().replace("'", "\\'") + "']";
                    paths.add("$.credentialSubject" + bracketed);
                    paths.add("$.vc.credentialSubject" + bracketed);
                }
            }
            constraints.add(new FieldConstraint(paths, claim.constValue()));
        }
        return constraints;
    }

    private List<ClaimRequest> extractClaimRequestsFromDcql(JsonNode claimsNode) {
        if (!claimsNode.isArray()) {
            return List.of(new ClaimRequest("credentialSubject", null));
        }
        List<ClaimRequest> claims = new ArrayList<>();
        for (JsonNode claim : claimsNode) {
            JsonNode pathNode = claim.path("path");
            String constValue = claim.path("value").asText(null);
            if (!pathNode.isArray() || pathNode.isEmpty()) {
                continue;
            }
            String name = claimFromSegments(pathNode);
            if (name != null && !name.isBlank()) {
                claims.add(new ClaimRequest(name, constValue, jsonPathFromSegments(pathNode)));
            }
        }
        if (claims.isEmpty()) {
            claims.add(new ClaimRequest("credentialSubject", null));
        }
        return claims;
    }

    private String jsonPathFromSegments(JsonNode pathNode) {
        List<String> segments = new ArrayList<>();
        for (JsonNode p : pathNode) {
            if (p.isTextual()) {
                segments.add(p.asText());
            }
        }
        if (segments.isEmpty()) {
            return null;
        }
        return "$." + String.join(".", segments);
    }

    private String claimFromSegments(JsonNode pathNode) {
        List<String> segments = new ArrayList<>();
        for (JsonNode p : pathNode) {
            if (p.isTextual()) {
                segments.add(p.asText());
            }
        }
        if (segments.isEmpty()) {
            return null;
        }
        return segments.get(segments.size() - 1);
    }

    private String toVpToken(Map<String, Object> credential, List<ClaimRequest> requests, Set<String> requestedClaims) {
        Object raw = credential.get("rawCredential");
        if (!(raw instanceof String rawCredential) || rawCredential.isBlank()) {
            return credential.toString();
        }
        if (sdJwtParser.isSdJwt(rawCredential)) {
            return sdJwtSelectiveDiscloser.filter(rawCredential, toSdJwtRequests(requests), requestedClaims);
        }
        if (mdocParser.isMdoc(rawCredential)) {
            return mdocSelectiveDiscloser.filter(rawCredential, requestedClaims);
        }
        List<String> disclosures = sdJwtSelectiveDiscloser.filterDisclosures(
                filterDisclosuresFromCredential(credential), toSdJwtRequests(requests), requestedClaims);
        if (disclosures.isEmpty()) {
            return rawCredential;
        }
        return sdJwtParser.withDisclosures(rawCredential, disclosures);
    }

    public record Presentation(String vpToken, Map<String, Object> credential) {
    }

    public record PresentationBundle(List<DescriptorMatch> matches) {
    }

    public record PresentationOptions(List<DescriptorOptions> options) {
    }

    public record DescriptorOptions(CredentialRequest request, List<DescriptorMatch> candidates) {
        public DescriptorMatch findByFileName(String fileName) {
            if (fileName == null || fileName.isBlank() || candidates == null) {
                return null;
            }
            return candidates.stream()
                    .filter(c -> fileName.equals(c.credentialFileName()))
                    .findFirst()
                    .orElse(null);
        }
    }

    public record DescriptorMatch(String descriptorId,
                                  String credentialFileName,
                                  Map<String, Object> credential,
                                  String vpToken,
                                  List<ClaimRequest> requestedClaims,
                                  Map<String, Object> disclosedClaims,
                                  List<CredentialSetFilter> credentialSets,
                                  List<ClaimSet> claimSets) {
    }

    public record CredentialRequest(String id,
                                    List<FieldConstraint> constraints,
                                    List<ClaimRequest> claims,
                                    List<CredentialSetFilter> credentialSets,
                                    List<ClaimSet> claimSets,
                                    String format,
                                    List<String> vctValues,
                                    String doctypeValue) {
        // Convenience constructor for backward compatibility
        public CredentialRequest(String id, List<FieldConstraint> constraints, List<ClaimRequest> claims,
                                 List<CredentialSetFilter> credentialSets, List<ClaimSet> claimSets, String format) {
            this(id, constraints, claims, credentialSets, claimSets, format, List.of(), null);
        }
    }

    public record ClaimRequest(String name, String constValue, String jsonPath) {
        public ClaimRequest(String name, String constValue) {
            this(name, constValue, null);
        }
    }

    private List<String> filterDisclosuresFromCredential(Map<String, Object> credential) {
        Object disclosureValue = credential.get("disclosures");
        if (disclosureValue instanceof List<?> list) {
            List<String> result = new ArrayList<>();
            for (Object entry : list) {
                if (entry != null) {
                    result.add(entry.toString());
                }
            }
            return result;
        }
        return List.of();
    }

    private List<SdJwtSelectiveDiscloser.ClaimRequest> toSdJwtRequests(List<ClaimRequest> requests) {
        if (requests == null || requests.isEmpty()) {
            return List.of();
        }
        List<SdJwtSelectiveDiscloser.ClaimRequest> converted = new ArrayList<>();
        for (ClaimRequest req : requests) {
            if (req == null) {
                continue;
            }
            converted.add(new SdJwtSelectiveDiscloser.ClaimRequest(req.name(), req.jsonPath()));
        }
        return converted;
    }

    private boolean matchesCredentialSet(CredentialRequest definition, Map<String, Object> credential) {
        String vct = extractVct(credential);
        String format = resolveFormat(credential);
        return matchesCredentialSet(definition, credential, vct, format);
    }

    private boolean matchesCredentialSet(CredentialRequest definition, Map<String, Object> credential, String vct, String format) {
        if (definition.credentialSets() == null || definition.credentialSets().isEmpty()) {
            return true;
        }
        for (CredentialSetFilter filter : definition.credentialSets()) {
            boolean match = true;
            if (filter.vct() != null && !filter.vct().isBlank()) {
                match = vct != null && filter.vct().equalsIgnoreCase(vct);
            }
            if (match && filter.id() != null && !filter.id().isBlank()) {
                match = (vct != null && filter.id().equalsIgnoreCase(vct))
                        || filter.id().equalsIgnoreCase(String.valueOf(credential.get("id")));
            }
            if (match && filter.format() != null && !filter.format().isBlank()) {
                match = format != null && filter.format().equalsIgnoreCase(format);
            }
            if (match) {
                return true;
            }
        }
        return false;
    }

    private boolean matchesClaimSet(CredentialRequest definition, Map<String, Object> credential) {
        return matchesClaimSetWithClaims(definition, extractClaims(credential));
    }

    private boolean matchesClaimSetWithClaims(CredentialRequest definition, Map<String, Object> claims) {
        if (definition.claimSets() == null || definition.claimSets().isEmpty()) {
            return true;
        }
        if (claims == null || claims.isEmpty()) {
            return false;
        }
        for (ClaimSet set : definition.claimSets()) {
            boolean allMatch = true;
            for (ClaimRequest req : set.claims()) {
                Object value = claims.get(req.name());
                if (value == null) {
                    allMatch = false;
                    break;
                }
                if (req.constValue() != null && !req.constValue().equals(String.valueOf(value))) {
                    allMatch = false;
                    break;
                }
            }
            if (allMatch) {
                return true;
            }
        }
        return false;
    }

    private String extractVct(Map<String, Object> credential) {
        Object vct = credential.get("vct");
        if (vct instanceof String s && !s.isBlank()) {
            return s;
        }
        Object type = credential.get("type");
        if (type instanceof String s && !s.isBlank()) {
            return s;
        }
        if (type instanceof List<?> list) {
            return list.stream()
                    .filter(String.class::isInstance)
                    .map(String.class::cast)
                    .findFirst()
                    .orElse(null);
        }
        Object raw = credential.get("rawCredential");
        if (raw instanceof String rawCredential && !rawCredential.isBlank()) {
            try {
            if (sdJwtParser.isSdJwt(rawCredential)) {
                String vctFromSdJwt = sdJwtParser.extractVct(rawCredential);
                if (vctFromSdJwt != null) {
                    return vctFromSdJwt;
                }
            }
            if (mdocParser.isMdoc(rawCredential)) {
                String docType = mdocParser.extractDocType(rawCredential);
                if (docType != null) {
                    return docType;
                }
            }
            String signed = sdJwtParser.isSdJwt(rawCredential) ? sdJwtParser.signedJwt(rawCredential) : rawCredential;
            String[] parts = signed.split("\\.");
            if (parts.length >= 2) {
                    byte[] payload = Base64.getUrlDecoder().decode(parts[1]);
                    JsonNode node = objectMapper.readTree(payload);
                    if (node.has("vct") && node.get("vct").isTextual()) {
                        return node.get("vct").asText();
                    }
                    JsonNode vc = node.path("vc");
                    if (vc.has("type")) {
                        JsonNode vcType = vc.get("type");
                        if (vcType.isTextual()) {
                            return vcType.asText();
                        }
                        if (vcType.isArray() && vcType.size() > 0 && vcType.get(0).isTextual()) {
                            return vcType.get(0).asText();
                        }
                    }
                }
            } catch (Exception ignored) {
            }
        }
        return null;
    }

    private String resolveFormat(Map<String, Object> credential) {
        Object declared = credential.get("format");
        if (declared instanceof String s && !s.isBlank()) {
            return s;
        }
        Object disclosures = credential.get("disclosures");
        if (disclosures instanceof List<?> list && !list.isEmpty()) {
            return "dc+sd-jwt";
        }
        Object raw = credential.get("rawCredential");
        if (raw instanceof String rawCredential && !rawCredential.isBlank()) {
            if (sdJwtParser.isSdJwt(rawCredential)) {
                return "dc+sd-jwt";
            }
            if (mdocParser.isMdoc(rawCredential)) {
                return "mso_mdoc";
            }
            return "jwt_vc";
        }
        return null;
    }

    private Map<String, Object> extractClaims(Map<String, Object> map) {
        Object existing = map.get("credentialSubject");
        if (existing instanceof Map<?, ?> ready) {
            return (Map<String, Object>) ready;
        }
        Object raw = map.get("rawCredential");
        if (!(raw instanceof String rawCredential) || rawCredential.isBlank()) {
            return Map.of();
        }
        try {
            if (sdJwtParser.isSdJwt(rawCredential)) {
                return sdJwtParser.extractDisclosedClaims(rawCredential);
            }
            if (mdocParser.isMdoc(rawCredential)) {
                return mdocParser.extractClaims(rawCredential);
            }
            String[] parts = rawCredential.split("\\.");
            if (parts.length < 2) {
                return Map.of();
            }
            byte[] payload = Base64.getUrlDecoder().decode(parts[1]);
            JsonNode node = objectMapper.readTree(payload);
            JsonNode subject = node.path("vc").path("credentialSubject");
            if (subject.isMissingNode()) {
                subject = node.path("credentialSubject");
            }
            return objectMapper.convertValue(subject, Map.class);
        } catch (Exception e) {
            return Map.of();
        }
    }

    private static final Set<String> SUPPRESSED_CLAIMS = Set.of("type", "vct");

    private Map<String, Object> filterClaims(Map<String, Object> disclosed, List<ClaimRequest> requests) {
        if (disclosed == null || disclosed.isEmpty() || requests == null || requests.isEmpty()) {
            return Map.of();
        }
        Map<String, Object> filtered = new LinkedHashMap<>();
        for (ClaimRequest req : requests) {
            if (req == null || req.name() == null || req.name().isBlank() || SUPPRESSED_CLAIMS.contains(req.name())) {
                continue;
            }
            Object value = resolveClaimValue(disclosed, req);
            if (value != null) {
                filtered.put(req.name(), value);
            }
        }
        return filtered;
    }

    private Object resolveClaimValue(Map<String, Object> disclosed, ClaimRequest req) {
        Object value = disclosed.get(req.name());
        if (value != null) {
            return value;
        }

        if (req.jsonPath() != null) {
            String normalized = JsonPathNormalizer.normalize(req.jsonPath());
            if (normalized != null) {
                value = disclosed.get(normalized);
            }
            if (value == null) {
                value = tryJsonPath(disclosed, req.jsonPath());
            }
            if (value == null && normalized != null) {
                value = tryJsonPath(disclosed, "$." + normalized);
            }
        }

        // Support dotted claim names in flattened disclosures.
        if (value == null && req.name().contains(".")) {
            value = disclosed.get(req.name());
        }
        return value;
    }

    private Object tryJsonPath(Map<String, Object> data, String path) {
        try {
            return JsonPath.read(data, path);
        } catch (Exception ignored) {
            return null;
        }
    }

    private String toJsonArray(List<String> values) {
        try {
            return objectMapper.writeValueAsString(values);
        } catch (Exception e) {
            return String.join(",", values);
        }
    }

    private record FieldConstraint(List<String> paths, String constValue) {
        boolean matches(Object credential) {
            if (paths == null || paths.isEmpty()) {
                return true;
            }
            for (String path : paths) {
                if (path == null || path.isBlank()) {
                    continue;
                }
                try {
                    Object value = JsonPath.read(credential, path);
                    if (value == null) {
                        continue;
                    }
                    if (value instanceof List<?> list && list.isEmpty()) {
                        continue;
                    }
                    String text = value instanceof List<?> list && list.size() == 1
                            ? String.valueOf(list.get(0))
                            : String.valueOf(value);
                    if (constValue == null || constValue.equals(text)) {
                        return true;
                    }
                } catch (PathNotFoundException ignored) {
                }
            }
            return false;
        }
    }

    private record CredentialSetFilter(String id, String vct, String format) {
    }

    private record ClaimSet(List<ClaimRequest> claims) {
    }

    private record MatchResult(DescriptorMatch match, int entryIndex, int score) {
    }
}
