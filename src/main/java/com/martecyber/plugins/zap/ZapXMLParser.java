package com.martecyber.plugins.zap;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.martecyber.ares.assets.AssetLinkType;
import com.martecyber.ares.assets.AssetType;
import com.martecyber.ares.imports.ImportParser;
import com.martecyber.ares.imports.ParseResult;
import com.martecyber.ares.imports.ParsedAsset;
import com.martecyber.ares.imports.ParsedDetection;
import org.springframework.stereotype.Component;

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamReader;
import java.io.ByteArrayInputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Parses OWASP ZAP's XML report (Report > Generate Report... > "Traditional XML Report", or
 * {@code zap-cli report -f xml} / the automation framework's xml template).
 *
 * ZAP groups every URL matching the same vulnerability type under one &lt;alertitem&gt;, with
 * one &lt;instance&gt; per URL — the opposite nesting from Burp, which repeats the whole issue
 * per URL. One ParsedDetection is emitted per &lt;instance&gt;, reusing the parent alertitem's
 * name/severity/description/solution for all of them, mirroring how every other DAST-tool
 * parser here (Burp, Nuclei) treats one match as one detection.
 */
@Component
public class ZapXMLParser implements ImportParser {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Override public String getToolId() { return "zap"; }
    @Override public String getDisplayName() { return "OWASP ZAP XML"; }
    @Override public String[] getSupportedExtensions() { return new String[]{".xml"}; }

    @Override
    public boolean validate(byte[] content) {
        String s = new String(content, StandardCharsets.UTF_8);
        return s.contains("<OWASPZAPReport") && s.contains("<alertitem>");
    }

    @Override
    public ParseResult parse(byte[] content) throws Exception {
        ParseResult result = new ParseResult();
        XMLInputFactory factory = XMLInputFactory.newInstance();
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        XMLStreamReader r = factory.createXMLStreamReader(new ByteArrayInputStream(content));

        Set<String> seenAssets = new HashSet<>();
        Map<String, String> alert = null;              // fields shared by every instance of this alertitem
        List<Map<String, String>> instances = null;    // buffered — <instances> closes before the
                                                          // alertitem's trailing fields (solution,
                                                          // reference, cweid…), so instances can't be
                                                          // processed until </alertitem>
        Map<String, String> instance = null;            // fields of the <instance> currently open
        boolean inInstances = false;
        String currentField = null;
        StringBuilder currentText = new StringBuilder();

        while (r.hasNext()) {
            int ev = r.next();
            if (ev == XMLStreamConstants.START_ELEMENT) {
                String tag = r.getLocalName();
                if ("alertitem".equals(tag)) {
                    alert = new LinkedHashMap<>();
                    instances = new ArrayList<>();
                    currentField = null;
                } else if ("instances".equals(tag) && alert != null) {
                    inInstances = true;
                } else if ("instance".equals(tag) && inInstances) {
                    instance = new LinkedHashMap<>();
                    currentField = null;
                } else if (alert != null) {
                    currentField = tag;
                    currentText.setLength(0);
                }
            } else if (ev == XMLStreamConstants.CHARACTERS && currentField != null) {
                currentText.append(r.getText());
            } else if (ev == XMLStreamConstants.END_ELEMENT) {
                String tag = r.getLocalName();
                if ("instance".equals(tag) && instance != null) {
                    instances.add(instance);
                    instance = null;
                    currentField = null;
                } else if ("instances".equals(tag)) {
                    inInstances = false;
                    currentField = null;
                } else if ("alertitem".equals(tag) && alert != null) {
                    for (Map<String, String> inst : instances) {
                        processInstance(alert, inst, result, seenAssets);
                    }
                    alert = null;
                    instances = null;
                    currentField = null;
                } else if (currentField != null && currentField.equals(tag)) {
                    Map<String, String> target = instance != null ? instance : alert;
                    if (target != null) target.put(currentField, currentText.toString().trim());
                    currentField = null;
                    currentText.setLength(0);
                }
            }
        }
        r.close();
        return result;
    }

    private void processInstance(Map<String, String> alert, Map<String, String> instance,
                                  ParseResult result, Set<String> seenAssets) {
        String uri = instance.getOrDefault("uri", "");
        String name = firstNonBlank(alert.get("name"), alert.get("alert"), "Unknown vulnerability");
        String severity = mapRisk(alert.getOrDefault("riskcode", "0"));
        String desc = alert.getOrDefault("desc", "");
        String solution = alert.getOrDefault("solution", "");
        String reference = alert.getOrDefault("reference", "");
        String pluginId = alert.getOrDefault("pluginid", "");
        String param = instance.getOrDefault("param", "");

        String[] assets = resolveAssets(uri, seenAssets, result);
        String webAppId = assets != null ? assets[0] : null;
        String endpointId = assets != null ? assets[1] : null;

        StringBuilder fullDesc = new StringBuilder();
        if (!desc.isBlank()) fullDesc.append(desc).append("\n\n");
        if (!param.isBlank()) fullDesc.append("Parameter: ").append(param).append("\n\n");
        if (!solution.isBlank()) fullDesc.append("Solution: ").append(solution).append("\n\n");
        if (!reference.isBlank()) fullDesc.append("References: ").append(reference);

        // Every field the alertitem/instance elements carried (confidence, otherinfo, evidence,
        // attack, count, riskdesc, alertRef, ...), not the handful this parser's own title/
        // description logic reads — alert/instance are already generic tag→text captures (see
        // the walker above), so dumping them as-is is both complete and the simplest fix. The
        // request/response header+body fields are excluded: they already get their own
        // DetectionHttpSample storage below, so keeping them out of raw_data avoids silently
        // duplicating a full HTTP transcript into the JSON viewer.
        String raw;
        try {
            Map<String, Object> rawMap = new LinkedHashMap<>(alert);
            Map<String, String> instanceRaw = new LinkedHashMap<>(instance);
            instanceRaw.keySet().removeAll(List.of("requestheader", "requestbody", "responseheader", "responsebody"));
            rawMap.put("instance", instanceRaw);
            raw = MAPPER.writeValueAsString(rawMap);
        } catch (Exception e) { raw = "{}"; }

        String templateId = "zap-" + (pluginId.isBlank()
            ? name.toLowerCase().replaceAll("[^a-z0-9]+", "-")
            : pluginId);
        String path = pathOf(uri);
        String suffix = !param.isBlank() ? param
            : (path != null && !path.isBlank() && !"/".equals(path) ? path : null);
        String fullTitle = name + (suffix != null ? " [" + suffix + "]" : "");

        ParsedDetection pd = new ParsedDetection(fullTitle, severity, fullDesc.toString().trim(),
            endpointId, templateId, raw);
        // detected_at is the endpoint; affects the parent web application — same convention as
        // BurpXMLParser. Null when equal to endpointId (e.g. a root-path issue).
        if (webAppId != null && !webAppId.equals(endpointId)) pd.setAffectsIdentifier(webAppId);

        String request = joinHeaderBody(instance.get("requestheader"), instance.get("requestbody"));
        String response = joinHeaderBody(instance.get("responseheader"), instance.get("responsebody"));
        if ((request != null && !request.isBlank()) || (response != null && !response.isBlank())) {
            pd.setRequestContent(request);
            pd.setResponseContent(response);
        }
        result.addDetection(pd);
    }

    /** ZAP splits each captured exchange into separate header/body elements; joins them back
     *  into one HTTP message, the same shape HttpSamplesPanel already renders for Burp/Caido. */
    private static String joinHeaderBody(String header, String body) {
        if ((header == null || header.isBlank()) && (body == null || body.isBlank())) return null;
        StringBuilder sb = new StringBuilder();
        if (header != null) sb.append(header.strip());
        if (body != null && !body.isBlank()) {
            if (!sb.isEmpty()) sb.append("\n\n");
            sb.append(body);
        }
        return sb.toString();
    }

    /** Resolves (and, on first sight, emits) the WEB_APPLICATION + WEB_ENDPOINT pair for an
     *  instance's absolute URI. Returns null if the URI can't be parsed. */
    private String[] resolveAssets(String uriStr, Set<String> seenAssets, ParseResult result) {
        if (uriStr == null || uriStr.isBlank()) return null;
        URI uri;
        try { uri = new URI(uriStr.trim()); } catch (Exception e) { return null; }
        if (uri.getScheme() == null || uri.getHost() == null) return null;

        String webAppId = uri.getScheme() + "://" + uri.getHost()
            + (uri.getPort() == -1 ? "" : ":" + uri.getPort());
        if (seenAssets.add(webAppId)) {
            Map<String, Object> meta = new LinkedHashMap<>();
            meta.put("url", webAppId);
            if (uri.getPort() != -1) {
                meta.put("port", uri.getPort());
                meta.put("protocol", "https".equalsIgnoreCase(uri.getScheme()) ? "HTTPS" : "HTTP");
            }
            result.addAsset(new ParsedAsset(webAppId, AssetType.WEB_APPLICATION, meta));
        }

        String rawPath = uri.getRawPath();
        String cleanPath = rawPath == null ? "" : rawPath;
        String endpointId = cleanPath.isEmpty() || "/".equals(cleanPath) ? webAppId : webAppId + cleanPath;
        if (seenAssets.add("endpoint:" + endpointId)) {
            Map<String, Object> meta = new LinkedHashMap<>();
            meta.put("path", cleanPath.isEmpty() ? "/" : cleanPath);
            result.addAsset(new ParsedAsset(endpointId, AssetType.WEB_ENDPOINT, meta));
            result.addLink(webAppId, endpointId, AssetLinkType.WEBAPP_ENDPOINT);
        }
        return new String[]{webAppId, endpointId};
    }

    private static String pathOf(String uriStr) {
        try {
            return new URI(uriStr.trim()).getRawPath();
        } catch (Exception e) { return null; }
    }

    private static String firstNonBlank(String... values) {
        for (String v : values) if (v != null && !v.isBlank()) return v;
        return values.length > 0 ? values[values.length - 1] : null;
    }

    /** ZAP riskcode: 0=Informational, 1=Low, 2=Medium, 3=High — no "critical" tier. */
    private String mapRisk(String riskCode) {
        return switch (riskCode) {
            case "3" -> "high";
            case "2" -> "medium";
            case "1" -> "low";
            default -> "info";
        };
    }
}
