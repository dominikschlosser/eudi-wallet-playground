package de.arbeitsagentur.keycloak.wallet.demo.oid4vp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.authlete.sd.Disclosure;
import com.authlete.sd.SDJWT;
import de.arbeitsagentur.keycloak.wallet.common.sdjwt.SdJwtUtils;
import de.arbeitsagentur.keycloak.wallet.common.storage.CredentialStore;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.PathNotFoundException;
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
    private final CredentialStore credentialStore;
    private final ObjectMapper objectMapper;

    public PresentationService(CredentialStore credentialStore, ObjectMapper objectMapper) {
        this.credentialStore = credentialStore;
        this.objectMapper = objectMapper;
    }

    public Optional<Presentation> findPresentation(String userId, String dcqlQuery) {
        return preparePresentations(userId, dcqlQuery).map(bundle -> {
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
        Optional<PresentationOptions> options = preparePresentationOptions(userId, dcqlQuery);
        if (options.isEmpty()) {
            return Optional.empty();
        }
        Optional<List<DescriptorMatch>> distinct = selectDistinctMatches(options.get());
        return distinct.map(PresentationBundle::new);
    }

    public Optional<PresentationOptions> preparePresentationOptions(String userId, String dcqlQuery) {
        List<CredentialStore.Entry> entries = listEntries(userId);
        if (entries.isEmpty()) {
            return Optional.empty();
        }
        List<CredentialRequest> definitions = parseCredentialRequests(dcqlQuery);
        if (definitions.isEmpty()) {
            definitions = fallbackRequests(entries);
        }
        ensureUniqueDescriptorIds(definitions);
        List<DescriptorOptions> options = new ArrayList<>();
        for (CredentialRequest definition : definitions) {
            List<MatchResult> candidates = findMatches(definition, entries);
            if (candidates.isEmpty()) {
                return Optional.empty();
            }
            options.add(new DescriptorOptions(definition, candidates.stream().map(MatchResult::match).toList()));
        }
        return Optional.of(new PresentationOptions(options));
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
            boolean hasRequestedClaims = definition.claims() != null && definition.claims().stream()
                    .anyMatch(c -> c != null && c.name() != null && !c.name().isBlank());
            if (hasRequestedClaims && (disclosed == null || disclosed.isEmpty())) {
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

    private List<CredentialStore.Entry> listEntries(String userId) {
        List<CredentialStore.Entry> entries = credentialStore.listCredentialEntries(userId);
        if ((entries == null || entries.isEmpty()) && userId != null) {
            entries = credentialStore.listCredentialEntries(null);
        }
        if (entries == null) {
            return List.of();
        }
        return entries;
    }

    private boolean matchesConstraints(CredentialRequest definition, Map<String, Object> map) {
        if (definition.constraints() == null || definition.constraints().isEmpty()) {
            return true;
        }
        Object credentialDocument = objectMapper.convertValue(map, Object.class);
        return definition.constraints().stream().allMatch(c -> c.matches(credentialDocument));
    }

    private boolean matchesFormat(CredentialRequest definition, String format) {
        if (definition.format() == null || definition.format().isBlank()) {
            return true;
        }
        if (format == null || format.isBlank()) {
            return true;
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
                String normalized = c.jsonPath();
                if (normalized.startsWith("$.")) {
                    normalized = normalized.substring(2);
                }
                if (normalized.startsWith("credentialSubject.")) {
                    normalized = normalized.substring("credentialSubject.".length());
                } else if (normalized.startsWith("vc.credentialSubject.")) {
                    normalized = normalized.substring("vc.credentialSubject.".length());
                }
                names.add(normalized);
                int dot = normalized.indexOf('.');
                if (dot > 0) {
                    names.add(normalized.substring(0, dot));
                }
            }
            return names.stream();
        })
        .collect(Collectors.toSet());
        String vpToken = toVpToken(map, definition.claims(), requestedClaims);
        return new DescriptorMatch(definition.id(), entry.fileName(), map, vpToken, definition.claims(), disclosed,
                definition.credentialSets(), definition.claimSets());
    }

    private List<CredentialRequest> parseCredentialRequests(String dcqlQuery) {
        if (dcqlQuery == null || dcqlQuery.isBlank()) {
            return List.of();
        }
        try {
            JsonNode root = objectMapper.readTree(dcqlQuery);
            JsonNode credentials = root.path("credentials");
            if (!credentials.isArray()) {
                return List.of();
            }
            List<CredentialRequest> result = new ArrayList<>();
            for (JsonNode credentialNode : credentials) {
                String id = credentialNode.path("id").asText();
                if (id == null || id.isBlank()) {
                    id = "credential-%d".formatted(result.size() + 1);
                }
                String format = credentialNode.path("format").asText(null);
                List<ClaimRequest> claims = extractClaimRequestsFromDcql(credentialNode.path("claims"));
                List<FieldConstraint> constraints = buildConstraintsFromClaims(claims);
                List<CredentialSetFilter> credentialSets = parseCredentialSets(credentialNode.path("credential_set"));
                List<ClaimSet> claimSets = parseClaimSets(credentialNode.path("claim_set"));
                result.add(new CredentialRequest(id, constraints, claims, credentialSets, claimSets, format));
            }
            return result;
        } catch (Exception e) {
            return List.of();
        }
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
                format = textOrNull(n, "format");
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
                String normalized = claim.jsonPath().startsWith("$.")
                        ? claim.jsonPath().substring(2)
                        : claim.jsonPath();
                if (!normalized.startsWith("credentialSubject") && !normalized.startsWith("vc.")) {
                    paths.add("$.credentialSubject." + normalized);
                    paths.add("$.vc.credentialSubject." + normalized);
                }
                // Allow dotted claim names (like address.country) to match stored flat structures.
                if (normalized.contains(".")) {
                    String flat = normalized;
                    if (flat.startsWith("credentialSubject.")) {
                        flat = flat.substring("credentialSubject.".length());
                    } else if (flat.startsWith("vc.credentialSubject.")) {
                        flat = flat.substring("vc.credentialSubject.".length());
                    }
                    String bracketedFlat = "['" + flat.replace("'", "\\'") + "']";
                    paths.add("$.credentialSubject" + bracketedFlat);
                    paths.add("$.vc.credentialSubject" + bracketedFlat);
                }
            } else {
                paths.add("$.credentialSubject." + claim.name());
                paths.add("$.vc.credentialSubject." + claim.name());
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
        if (rawCredential.contains("~")) {
            return rebuildSdJwt(rawCredential, requests, requestedClaims);
        }
        List<String> disclosures = filterDisclosures(credential, requests, requestedClaims);
        if (disclosures.isEmpty()) {
            return rawCredential;
        }
        StringBuilder sb = new StringBuilder(rawCredential);
        for (String disclosure : disclosures) {
            if (disclosure != null && !disclosure.isBlank()) {
                sb.append('~').append(disclosure);
            }
        }
        return sb.toString();
    }

    private String rebuildSdJwt(String sdJwt, List<ClaimRequest> requests, Set<String> requestedClaims) {
        try {
            SDJWT parsed = SDJWT.parse(sdJwt);
            List<Disclosure> filtered = parsed.getDisclosures().stream()
                    .filter(d -> {
                        if (requestedClaims == null || requestedClaims.isEmpty()) {
                            return true;
                        }
                        String claimName = d.getClaimName();
                        if (claimName == null) {
                            return false;
                        }
                        return requestedClaims.contains(claimName)
                                || requests.stream().anyMatch(r -> matchesClaimName(r, claimName));
                    })
                    .toList();
            return new SDJWT(parsed.getCredentialJwt(), filtered, parsed.getBindingJwt()).toString();
        } catch (Exception e) {
            return sdJwt;
        }
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
                                    String format) {
    }

    public record ClaimRequest(String name, String constValue, String jsonPath) {
        public ClaimRequest(String name, String constValue) {
            this(name, constValue, null);
        }
    }

    private List<String> filterDisclosures(Map<String, Object> credential, List<ClaimRequest> requests, Set<String> requestedClaims) {
        Object disclosureValue = credential.get("disclosures");
        if (disclosureValue instanceof List<?> list) {
            List<String> result = new ArrayList<>();
            for (Object entry : list) {
                if (entry != null) {
                    result.add(entry.toString());
                }
            }
            return filterDisclosures(result, requests, requestedClaims);
        }
        return List.of();
    }

    private List<String> filterDisclosures(List<String> disclosures, List<ClaimRequest> requests, Set<String> requestedClaims) {
        if (disclosures.isEmpty() || requestedClaims.isEmpty()) {
            return disclosures;
        }
        List<String> filtered = new ArrayList<>();
        for (String disclosure : disclosures) {
            String claimName = claimNameFromDisclosure(disclosure);
            if (claimName != null && (requestedClaims.contains(claimName)
                    || requests.stream().anyMatch(r -> matchesClaimName(r, claimName)))) {
                filtered.add(disclosure);
            }
        }
        return filtered;
    }

    private boolean matchesClaimName(ClaimRequest request, String claimName) {
        if (request == null || claimName == null) {
            return false;
        }
        if (claimName.equals(request.name())) {
            return true;
        }
        if (request.jsonPath() != null && !request.jsonPath().isBlank()) {
            String normalized = request.jsonPath();
            if (normalized.startsWith("$.")) {
                normalized = normalized.substring(2);
            }
            if (normalized.startsWith("credentialSubject.")) {
                normalized = normalized.substring("credentialSubject.".length());
            } else if (normalized.startsWith("vc.credentialSubject.")) {
                normalized = normalized.substring("vc.credentialSubject.".length());
            }
            if (claimName.equals(normalized) || normalized.endsWith("." + claimName) || normalized.startsWith(claimName + ".")) {
                return true;
            }
        }
        return request.name() != null && (normalizedContains(claimName, request.name()) || (claimName != null && claimName.startsWith(request.name() + ".")));
    }

    private boolean normalizedContains(String full, String tail) {
        return full.equals(tail) || full.endsWith("." + tail);
    }

    private String claimNameFromDisclosure(String disclosure) {
        try {
            return Disclosure.parse(disclosure).getClaimName();
        } catch (Exception ignored) {
            return null;
        }
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
                String signed = rawCredential.contains("~") ? rawCredential.split("~")[0] : rawCredential;
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
            if (rawCredential.contains("~")) {
                return "dc+sd-jwt";
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
            if (rawCredential.contains("~")) {
                SdJwtUtils.SdJwtParts parts = SdJwtUtils.split(rawCredential);
                return SdJwtUtils.extractDisclosedClaims(parts, objectMapper);
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

    private Map<String, Object> filterClaims(Map<String, Object> disclosed, List<ClaimRequest> requests) {
        if (disclosed == null || disclosed.isEmpty() || requests == null || requests.isEmpty()) {
            return Map.of();
        }
        Set<String> suppressed = Set.of("type", "vct");
        Map<String, Object> filtered = new LinkedHashMap<>();
        for (ClaimRequest req : requests) {
            if (req == null || req.name() == null || req.name().isBlank()) {
                continue;
            }
            if (suppressed.contains(req.name())) {
                continue;
            }
            Object value = disclosed.get(req.name());
            if (value == null && req.jsonPath() != null) {
                String normalized = req.jsonPath();
                if (normalized.startsWith("$.")) {
                    normalized = normalized.substring(2);
                }
                value = disclosed.get(normalized);
                if (value == null && normalized.startsWith("credentialSubject.")) {
                    value = disclosed.get(normalized.substring("credentialSubject.".length()));
                } else if (value == null && normalized.startsWith("vc.credentialSubject.")) {
                    value = disclosed.get(normalized.substring("vc.credentialSubject.".length()));
                }
                if (value == null) {
                    try {
                        value = JsonPath.read(disclosed, req.jsonPath());
                    } catch (Exception ignored) {
                    }
                }
                if (value == null && !normalized.startsWith("$.")) {
                    try {
                        value = JsonPath.read(disclosed, "$." + normalized);
                    } catch (Exception ignored) {
                    }
                }
            }
            // Support dotted claim names in flattened disclosures.
            if (value == null && req.name().contains(".")) {
                value = disclosed.get(req.name());
            }
            if (value != null) {
                filtered.put(req.name(), value);
            }
        }
        return filtered;
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
