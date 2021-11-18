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
package org.zaproxy.addon.reports.sarif;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpHeaderField;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpResponseHeader;

public class SarifResult {

    private SarifLevel level = SarifLevel.NONE;
    private SarifMessage message = new SarifMessage();
    private List<SarifResultLocation> locations = new ArrayList<>();
    private String ruleId = "0";
    private SarifWebRequest webRequest = new SarifWebRequest();
    private SarifWebResponse webResponse = new SarifWebResponse();

    public SarifWebRequest getWebRequest() {
        return webRequest;
    }

    public SarifWebResponse getWebResponse() {
        return webResponse;
    }

    public SarifResult(Alert alert) {
        /* base parts */
        level = SarifLevel.fromAlertRisk(alert.getRisk());
        ruleId = "" + alert.getPluginId();
        message.text = alert.getName();

        /* location */
        SarifResultLocation resultLocation = new SarifResultLocation();

        resultLocation.physicalLocation.artifactLocation.uri = alert.getUri();
        resultLocation.properties.attack = alert.getAttack();
        resultLocation.properties.evidence = alert.getEvidence();

        locations.add(resultLocation);

        HttpMessage httpMessage = alert.getMessage();

        /* ----------- */
        /* Web request */
        /* ----------- */
        /*
         * FIXME de-jcup: sarif supports two nodes: text +binary. we should have some
         * logic here to only set ONE...
         */
        webRequest.body.text = httpMessage.getRequestBody().toString();

        HttpRequestHeader requestHeader = httpMessage.getRequestHeader();
        List<HttpHeaderField> requestHeaders = requestHeader.getHeaders();
        for (HttpHeaderField headerField : requestHeaders) {
            webRequest.headers.put(headerField.getName(), headerField.getValue());
        }
        SarifProtocolData requestProtocolData =
                SarifProtocolData.parseProtocolAndVersion(requestHeader.getVersion());
        webRequest.protocol = requestProtocolData.getProtocol();
        webRequest.version = requestProtocolData.getVersion();
        webRequest.target = requestHeader.getURI().toString();
        webRequest.method = requestHeader.getMethod();
        /* ------------ */
        /* Web response */
        /* ------------ */
        /*
         * FIXME de-jcup: sarif supports two nodes: text +binary. we should have some
         * logic here to only set ONE...
         * 
         * responseHeader.isText() ?!?!??!?!? 
         * 
         */
        webResponse.body.text = httpMessage.getResponseBody().toString();
        httpMessage.getResponseHeader().getNormalisedContentTypeValue();

        HttpResponseHeader responseHeader = httpMessage.getResponseHeader();
        List<HttpHeaderField> responseHeaders = responseHeader.getHeaders();
        for (HttpHeaderField headerField : responseHeaders) {
            webResponse.headers.put(headerField.getName(), headerField.getValue());
        }
        webResponse.statusCode = responseHeader.getStatusCode();
        webResponse.reasonPhrase = responseHeader.getReasonPhrase();

        
        SarifProtocolData responseProtocolData =
                SarifProtocolData.parseProtocolAndVersion(responseHeader.getVersion());
        webResponse.protocol = responseProtocolData.getProtocol();
        webResponse.version = responseProtocolData.getVersion();
        
        webResponse.noResponseReceived=responseHeader.isConnectionClose();
        		
    }

    public String getRuleId() {
        return ruleId;
    }

    public SarifMessage getMessage() {
        return message;
    }

    public SarifLevel getLevel() {
        return level;
    }

    public List<SarifResultLocation> getLocations() {
        return locations;
    }

    public class SarifResultLocation {
        SarifPhysicalLocation physicalLocation = new SarifPhysicalLocation();
        SarifResultLocationProperties properties = new SarifResultLocationProperties();

        public SarifPhysicalLocation getPhysicalLocation() {
            return physicalLocation;
        }

        public SarifResultLocationProperties getProperties() {
            return properties;
        }
    }

    public class SarifResultLocationProperties {
        private String attack;
        private String evidence;

        public String getAttack() {
            return attack;
        }

        public String getEvidence() {
            return evidence;
        }
    }

    public class SarifPhysicalLocation {
        SarifArtifactLocation artifactLocation = new SarifArtifactLocation();

        public SarifArtifactLocation getArtifactLocation() {
            return artifactLocation;
        }
    }

    public class SarifArtifactLocation {
        private String uri;

        public String getUri() {
            return uri;
        }
    }

    public class SarifBody {

        private String text;
        private String binary;

        public String getText() {
            return text;
        }

        public String getBinary() {
            return binary;
        }
    }

    public class SarifWebRequest {
        private String protocol;
        private String version;
        private String target;
        private String method;
        private Map<String, String> headers = new TreeMap<>();
        private SarifBody body = new SarifBody();

        public String getProtocol() {
            return protocol;
        }

        public String getVersion() {
            return version;
        }

        public String getTarget() {
            return target;
        }

        public String getMethod() {
            return method;
        }

        public Map<String, String> getHeaders() {
            return headers;
        }

        public SarifBody getBody() {
            return body;
        }
    }

    public class SarifWebResponse {
        private String protocol;
        private String version;
        private Map<String, String> headers = new TreeMap<>();
        private SarifBody body = new SarifBody();

        private int statusCode;
        private String reasonPhrase;
        private boolean noResponseReceived;

        public String getProtocol() {
            return protocol;
        }

        public String getReasonPhrase() {
            return reasonPhrase;
        }

        public String getVersion() {
            return version;
        }

        public Map<String, String> getHeaders() {
            return headers;
        }

        public SarifBody getBody() {
            return body;
        }

        public int getStatusCode() {
            return statusCode;
        }

        public boolean isNoResponseReceived() {
            return noResponseReceived;
        }
    }
}
