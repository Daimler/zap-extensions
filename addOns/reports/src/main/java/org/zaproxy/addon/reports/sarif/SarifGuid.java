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

import java.util.UUID;
import org.parosproxy.paros.core.scanner.Alert;

/**
 * Represents a GUID for Sarif
 * https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317438
 */
public class SarifGuid {

    private String guid;

    public SarifGuid(Alert alert) {
        StringBuilder sb = new StringBuilder();
        sb.append("owasp-zap.sarif-guuid:");
        sb.append(alert.getPluginId());
        sb.append(":");
        sb.append(alert.getCweId());
        UUID nameBasedUUID = UUID.nameUUIDFromBytes(sb.toString().getBytes());
        this.guid = nameBasedUUID.toString();
    }

    /**
     * Creates a new Sarif GUID.
     *
     * @param guid
     */
    public SarifGuid(String guid) {
        this.guid = guid;
    }

    public String getGuid() {
        return guid;
    }
}
