package com.martecyber.plugins.zap;

import com.martecyber.ares.assets.AssetType;
import com.martecyber.ares.imports.ParseResult;
import com.martecyber.ares.imports.ParsedDetection;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Regression coverage for {@link ZapXMLParser}, in particular the buffer-then-flush handling
 * of &lt;instances&gt; — ZAP closes that block BEFORE the alertitem's trailing fields
 * (solution/reference/cweid), so a naive "emit on </instance>" parser would silently produce
 * detections missing those fields. Also exercises two instances under the same alertitem
 * (one detection each, sharing the alert-level fields) and the header/body → request/response
 * join that feeds DetectionHttpSample.
 */
class ZapXMLParserTest {

    private static final String XML = """
        <?xml version="1.0"?>
        <OWASPZAPReport version="2.15.0" generated="Mon, 8 Sep 2026 10:00:00">
          <site name="http://example.com" host="example.com" port="80" ssl="false">
            <alerts>
              <alertitem>
                <pluginid>40012</pluginid>
                <alert>Cross Site Scripting (Reflected)</alert>
                <name>Cross Site Scripting (Reflected)</name>
                <riskcode>3</riskcode>
                <confidence>2</confidence>
                <riskdesc>High (Medium)</riskdesc>
                <desc>Reflected XSS description.</desc>
                <instances>
                  <instance>
                    <uri>http://example.com/search?q=test</uri>
                    <method>GET</method>
                    <param>q</param>
                    <evidence>&lt;script&gt;test&lt;/script&gt;</evidence>
                    <requestheader>GET /search?q=test HTTP/1.1
        Host: example.com</requestheader>
                    <requestbody></requestbody>
                    <responseheader>HTTP/1.1 200 OK
        Content-Type: text/html</responseheader>
                    <responsebody>&lt;html&gt;reflected&lt;/html&gt;</responsebody>
                  </instance>
                  <instance>
                    <uri>http://example.com/other?p=1</uri>
                    <method>GET</method>
                    <param>p</param>
                    <evidence>evidence2</evidence>
                  </instance>
                </instances>
                <count>2</count>
                <solution>Escape output.</solution>
                <otherinfo>extra info</otherinfo>
                <reference>https://owasp.org/xss</reference>
                <cweid>79</cweid>
                <wascid>8</wascid>
                <sourceid>1</sourceid>
              </alertitem>
              <alertitem>
                <pluginid>10202</pluginid>
                <alert>Absence of Anti-CSRF Tokens</alert>
                <name>Absence of Anti-CSRF Tokens</name>
                <riskcode>1</riskcode>
                <confidence>2</confidence>
                <desc>No CSRF token found.</desc>
                <instances>
                  <instance>
                    <uri>http://example.com/form</uri>
                    <method>POST</method>
                  </instance>
                </instances>
                <solution>Add CSRF tokens.</solution>
                <cweid>352</cweid>
              </alertitem>
            </alerts>
          </site>
        </OWASPZAPReport>
        """;

    @Test
    void validateAcceptsZapReport() {
        ZapXMLParser parser = new ZapXMLParser();
        assertTrue(parser.validate(XML.getBytes(StandardCharsets.UTF_8)));
        assertFalse(parser.validate("<not-zap/>".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void parsesOneDetectionPerInstance() throws Exception {
        ZapXMLParser parser = new ZapXMLParser();
        ParseResult result = parser.parse(XML.getBytes(StandardCharsets.UTF_8));

        // 2 instances under the first alertitem + 1 under the second = 3 detections total.
        List<ParsedDetection> detections = result.getDetections();
        assertEquals(3, detections.size());

        ParsedDetection xss = detections.get(0);
        assertEquals("Cross Site Scripting (Reflected) [q]", xss.getTitle());
        assertEquals("high", xss.getSeverity());
        assertTrue(xss.getDescription().contains("Reflected XSS description."));
        // Trailing alertitem fields (parsed AFTER </instances> closes) must still reach the
        // detection — this is exactly what buffering-until-</alertitem> is for.
        assertTrue(xss.getDescription().contains("Escape output."));
        assertTrue(xss.getDescription().contains("https://owasp.org/xss"));
        assertEquals("zap-40012", xss.getSourceTemplateId());

        ParsedDetection xssOther = detections.get(1);
        assertEquals("Cross Site Scripting (Reflected) [p]", xssOther.getTitle());
        assertTrue(xssOther.getDescription().contains("Escape output."));

        ParsedDetection csrf = detections.get(2);
        assertEquals("low", csrf.getSeverity());
        assertTrue(csrf.getDescription().contains("Add CSRF tokens."));
        assertEquals("zap-10202", csrf.getSourceTemplateId());
    }

    @Test
    void joinsRequestAndResponseHeaderBody() throws Exception {
        ZapXMLParser parser = new ZapXMLParser();
        ParseResult result = parser.parse(XML.getBytes(StandardCharsets.UTF_8));
        ParsedDetection xss = result.getDetections().get(0);

        assertNotNull(xss.getRequestContent());
        assertTrue(xss.getRequestContent().contains("GET /search?q=test HTTP/1.1"));
        assertNotNull(xss.getResponseContent());
        assertTrue(xss.getResponseContent().contains("HTTP/1.1 200 OK"));
        assertTrue(xss.getResponseContent().contains("<html>reflected</html>"));

        // Second instance under the same alertitem has no requestheader/responseheader at all —
        // must come back null, not an empty/garbage string.
        ParsedDetection xssOther = result.getDetections().get(1);
        assertNull(xssOther.getRequestContent());
        assertNull(xssOther.getResponseContent());
    }

    @Test
    void emitsWebApplicationAndEndpointAssets() throws Exception {
        ZapXMLParser parser = new ZapXMLParser();
        ParseResult result = parser.parse(XML.getBytes(StandardCharsets.UTF_8));

        assertTrue(result.getAssets().stream()
            .anyMatch(a -> a.getType().equals(AssetType.WEB_APPLICATION) && a.getIdentifier().equals("http://example.com")));
        assertTrue(result.getAssets().stream()
            .anyMatch(a -> a.getType().equals(AssetType.WEB_ENDPOINT) && a.getIdentifier().equals("http://example.com/search")));
        // detected_at is the endpoint; affects the parent web application.
        ParsedDetection xss = result.getDetections().get(0);
        assertEquals("http://example.com/search", xss.getAssetIdentifier());
        assertEquals("http://example.com", xss.getAffectsIdentifier());
    }
}
