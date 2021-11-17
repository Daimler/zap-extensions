/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.addon.reports;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;
import static org.zaproxy.addon.reports.TestAlertBuilder.newAlertBuilder;
import static org.zaproxy.addon.reports.TestAlertNodeBuilder.newAlertNodeBuilder;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;
import org.thymeleaf.templateresolver.FileTemplateResolver;
import org.zaproxy.addon.automation.jobs.PassiveScanJobResultData;
import org.zaproxy.addon.reports.sarif.SarifToolData;
import org.zaproxy.addon.reports.sarif.SarifToolData.SarifToolDataProvider;
import org.zaproxy.zap.extension.alert.AlertNode;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;
import org.zaproxy.zap.utils.I18N;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/** This integration test uses the real ZAP template engine to create a SARIF report output. */
class SarifReportIntegrationTest {

    private Template template;
    private TemplateEngine templateEngine;

    @BeforeEach
    void setUp() throws Exception {
        /* setup ZAP for testing - necessary dependencies for report data creation */
        Constant.messages = new I18N(Locale.ENGLISH);

        Model model = mock(Model.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        Model.setSingletonForTesting(model);
        ExtensionLoader extensionLoader = mock(ExtensionLoader.class, withSettings().lenient());
        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);
        Model.getSingleton().getOptionsParam().load(new ZapXmlConfiguration());

        Constant.PROGRAM_VERSION = "Dev Build";
    }

    void configureTemplateEngine(String templateName) throws Exception {
        /* configure template engine */
        templateEngine = new TemplateEngine();
        template = ExtensionReportsUnitTest.getTemplateFromYamlFile(templateName);

        FileTemplateResolver templateResolver = new FileTemplateResolver();
        templateResolver.setTemplateMode(template.getMode());
        templateEngine.setTemplateResolver(templateResolver);
        templateEngine.setMessageResolver(new ReportMessageResolver(template));
    }

    @Test
    void templateEngineCanProcessSarifJsonReportAndOutputIsAsExpected() throws Exception {
        /* prepare */
        configureTemplateEngine("sarif-json");

        ReportData reportData = createTestReportDataWithAlerts(template);
        Context context = createTestContext(reportData);
        StringWriter writer = new StringWriter();

        /* execute */
        templateEngine.process(template.getReportTemplateFile().getAbsolutePath(), context, writer);

        /* test */
        String sarifReportJSON = writer.getBuffer().toString();
        assertNotNull(sarifReportJSON);
        System.out.println(sarifReportJSON);

        JsonNode rootNode = assertValidJSON(sarifReportJSON);
        JsonNode firstRun = assertOneRunOnly(rootNode);
        assertResults(firstRun);
        assertTaxonomies(firstRun);
    }

    private JsonNode assertValidJSON(String sarifReportJSON)
            throws JsonProcessingException, JsonMappingException {
        ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.readTree(sarifReportJSON);
    }

    private void assertTaxonomies(JsonNode firstRun) {
        JsonNode taxonomies = firstRun.get("taxonomies");
        assertTrue(taxonomies.isArray());
        ArrayNode taxonomiesArray = (ArrayNode) taxonomies;

        // taxonomy: CWE
        assertEquals(1, taxonomiesArray.size()); // currently we provide only one: CWE
        JsonNode firstTaxonomy = taxonomiesArray.iterator().next();
        SarifToolDataProvider cwe = SarifToolData.INSTANCE.getCwe();
        assertEquals(cwe.getDownloadUri(), firstTaxonomy.get("downloadUri").asText());
        assertEquals(cwe.getInformationUri(), firstTaxonomy.get("informationUri").asText());

        // taxa
        JsonNode taxa = firstTaxonomy.get("taxa");
        assertTrue(taxa.isArray());
        ArrayNode taxaArray = (ArrayNode) taxa;
        assertEquals(2, taxaArray.size());
        Iterator<JsonNode> taxaIterator = taxaArray.iterator();
        JsonNode firstTaxa = taxaIterator.next();
        JsonNode secondTaxa = taxaIterator.next();

        assertEquals("79", firstTaxa.get("id").asText());
        assertEquals("693", secondTaxa.get("id").asText());
    }

    private void assertResults(JsonNode firstRun) {
        JsonNode results = firstRun.get("results");
        assertTrue(results.isArray());
        ArrayNode resultsArray = (ArrayNode) results;
        assertEquals(2, resultsArray.size());
        Iterator<JsonNode> resultiterator = resultsArray.iterator();
        JsonNode firstResult = resultiterator.next();
        JsonNode secondResult = resultiterator.next();

        assertEquals("error", firstResult.get("level").asText());
        assertEquals("40012", firstResult.get("ruleId").asText());

        assertEquals("warning", secondResult.get("level").asText());
        assertEquals("1", secondResult.get("ruleId").asText());

        assertWebRequest(firstResult);
        assertWebResponse(firstResult);
    }

    private void assertWebResponse(JsonNode firstResult) {
        JsonNode webResponse = firstResult.get("webResponse");
        assertEquals("HTTP", webResponse.get("protocol").asText());
        assertEquals("1.1", webResponse.get("version").asText());
        assertEquals("GET", webResponse.get("method").asText());
        assertEquals("200", webResponse.get("statusCode").asText());
    }

    private void assertWebRequest(JsonNode firstResult) {
        JsonNode webRequest = firstResult.get("webRequest");
        assertEquals(
                "https://127.0.0.1:8080/greeting?name=%3C%2Fp%3E%3Cscript%3Ealert%281%29%3B%3C%2Fscript%3E%3Cp%3E",
                webRequest.get("target").asText());
        assertEquals("HTTP", webRequest.get("protocol").asText());
        assertEquals("1.1", webRequest.get("version").asText());
        assertEquals("GET", webRequest.get("method").asText());
    }

    private JsonNode assertOneRunOnly(JsonNode rootNode) {
        JsonNode runs = rootNode.get("runs");
        assertTrue(runs.isArray());
        ArrayNode runsArray = (ArrayNode) runs;
        assertEquals(1, runsArray.size());
        JsonNode firstRun = runsArray.get(0);
        return firstRun;
    }

    private Context createTestContext(ReportData reportData) {
        Context context = new Context();
        context.setVariable("alertTree", reportData.getAlertTreeRootNode());
        context.setVariable("reportTitle", reportData.getTitle());
        context.setVariable("description", reportData.getDescription());
        context.setVariable("helper", new ReportHelper());
        context.setVariable("zapVersion", "99.9.9");
        context.setVariable("reportData", reportData);
        context.setVariable("report", reportData);
        return context;
    }

    private static ReportData createTestReportDataWithAlerts(Template template)
            throws URIException, HttpMalformedHeaderException {
        ReportData reportData = new ReportData();
        reportData.setTitle("Test Title");
        reportData.setDescription("Test Description");
        reportData.setIncludeAllConfidences(true);
        reportData.setSections(template.getSections());
        reportData.setIncludeAllRisks(true);

        List<PluginPassiveScanner> list = new ArrayList<>();
        PassiveScanJobResultData pscanData = new PassiveScanJobResultData("passiveScan-wait", list);
        reportData.addReportObjects(pscanData.getKey(), pscanData);

        AlertNode rootAlertNode =
                new AlertNode(0, "TestRootNode"); // represents root node at top of alert tree in UI
        reportData.setAlertTreeRootNode(rootAlertNode);
        /** @formatter:off */
        Alert cssAlert =
                newAlertBuilder()
                        .setName("Cross Site Scripting")
                        .setPluginId(40012)
                        .setDescription("CSS Description\nMultiple lines\n\nEnd")
                        .setUriString(
                                "https://127.0.0.1:8080/greeting?name=%3C%2Fp%3E%3Cscript%3Ealert%281%29%3B%3C%2Fscript%3E%3Cp%3")
                        .setAttack("</p><script>alert(1);</script><p>")
                        .setEvidence("</p><script>alert(1);</script><p>")
                        .setRequestHeader(
                                "GET https://127.0.0.1:8080/greeting?name=%3C%2Fp%3E%3Cscript%3Ealert%281%29%3B%3C%2Fscript%3E%3Cp%3E HTTP/1.1\n"
                                        + "Host: 127.0.0.1:8080\n"
                                        + "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:92.0) Gecko/20100101 Firefox/92.0\n"
                                        + "Pragma: no-cache\n"
                                        + "Cache-Control: no-cache\n"
                                        + "Referer: https://127.0.0.1:8080/hello\n"
                                        + "Cookie: JSESSIONID=38AA1F7A61982DF1073D7F43A3707798; locale=de\n"
                                        + "Content-Length: 0\n")
                        .setResponseHeader(
                                "HTTP/1.1 200\n"
                                        + "Set-Cookie: locale=de; HttpOnly; SameSite=strict\n"
                                        + "X-Content-Type-Options: nosniff\n"
                                        + "X-XSS-Protection: 1; mode=block\n"
                                        + "Cache-Control: no-cache, no-store, max-age=0, must-revalidate\n"
                                        + "Pragma: no-cache\n"
                                        + "Expires: 0\n"
                                        + "Strict-Transport-Security: max-age=31536000 ; includeSubDomains\n"
                                        + "X-Frame-Options: DENY\n"
                                        + "Content-Security-Policy: script-src 'self'\n"
                                        + "Referrer-Policy: no-referrer\n"
                                        + "Content-Type: text/html;charset=UTF-8\n"
                                        + "Content-Language: en-US\n"
                                        + "Date: Thu, 11 Nov 2021 09:56:20 GMT\n"
                                        + "")
                        .setResponseBody(
                                "<!DOCTYPE HTML>\n"
                                        + "<html>\n"
                                        + "<head>\n"
                                        + "    <title>Getting Started: Serving Web Content</title>\n"
                                        + "    <meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\" />\n"
                                        + "</head>\n"
                                        + "<body>\n"
                                        + "    <!-- unsecure text used (th:utext instead th:text)- to create vulnerability (XSS) -->\n"
                                        + "    <!-- simple usage: http://localhost:8080/greeting?name=Test2</p><script>;alert(\"hallo\")</script> -->\n"
                                        + "    <p >XSS attackable parameter output: </p><script>alert(1);</script><p>!</p>\n"
                                        + "</body>\n"
                                        + "</html>")
                        .setReference(
                                "http://projects.webappsec.org/Cross-Site-Scripting\n"
                                        + "http://cwe.mitre.org/data/definitions/79.html")
                        .setSolution("Phase: 1\n\nDo ....")
                        .setCweId(79)
                        .setWascId(8)
                        .setRisk(Alert.RISK_HIGH)
                        .build();

        rootAlertNode.add(
                newAlertNodeBuilder(cssAlert)
                        .newInstance()
                        .setRequestBody("request2")
                        .setResponseBody("response2")
                        .add()
                        .build());

        Alert cspAlert =
                newAlertBuilder()
                        .setName("CSP")
                        .setCweId(693)
                        .setUriString("https://127.0.0.1:8080")
                        .setDescription("CSP Description")
                        .setRisk(Alert.RISK_MEDIUM)
                        .build();

        rootAlertNode.add(newAlertNodeBuilder(cspAlert).build());

        reportData.setSites(Arrays.asList("https://127.0.0.1"));
        /** @formatter:on */
        return reportData;
    }
}
