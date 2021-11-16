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

import static org.junit.jupiter.api.Assertions.*;
import static org.zaproxy.addon.reports.TestAlertBuilder.newAlertBuilder;

import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.addon.reports.sarif.SarifResult.SarifArtifactLocation;
import org.zaproxy.addon.reports.sarif.SarifResult.SarifResultLocation;

class SarifResultTest {

    @Test
    void aHighRiskAlertWillBeConvertedToCorrespondingSarifResult() {
        // @formatter:off

        /* prepare */
        Alert alert =
                newAlertBuilder()
                        .setRisk(Alert.RISK_HIGH)
                        .setDescription("description1")
                        .setEvidence("evidence1")
                        .setAttack("attack1")
                        .setName("name1")
                        .setPluginId(12345)
                        .build();

        /* execute */
        SarifResult result = new SarifResult(alert);

        /* test */
        assertEquals(SarifLevel.ERROR.name(), result.getLevel());

        assertEquals(1, result.getLocations().size());
        SarifResultLocation firstLocation = result.getLocations().iterator().next();
        assertEquals("attack1", firstLocation.getProperties().getAttack());
        assertEquals("evidence1", firstLocation.getProperties().getEvidence());
        SarifArtifactLocation artifactLocation =
                firstLocation.getPhysicalLocation().getArtifactLocation();

        assertEquals("description1", result.getMessage());
        assertEquals("12345", result.getRuleId());
        assertEquals(79, artifactLocation.getUri());
        // @formatter:on
    }
}
