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

import java.util.Objects;
import java.util.UUID;
import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.addon.reports.sarif.SarifToolData.SarifToolDataProvider;

/**
 * Represents a GUID for Sarif
 * https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317438
 */
public class SarifGuid {

    private String guid;

    private SarifGuid() {
    	// force to use factory methods
    }
    
    public static SarifGuid createByAlert(Alert alert) {
        StringBuilder sb = new StringBuilder();
        sb.append("owasp-zap.sarif-guuid:");
        sb.append(alert.getPluginId());
        sb.append(":");
        sb.append(alert.getCweId());
        
        String string = sb.toString();

        SarifGuid sarifGuid = createByIdentifier(string);
        
        return sarifGuid;
    }

    /**
     * Creates a SARFI guid - by using only the given id
     * @param identifier
     * @return guid
     */
	public static SarifGuid createByIdentifier(String identifier) {
		SarifGuid sarifGuid = new SarifGuid();
		UUID nameBasedUUID = UUID.nameUUIDFromBytes(identifier.getBytes());
        sarifGuid.guid = nameBasedUUID.toString();
		return sarifGuid;
	}

	/**
	 * Creates a SARFI guid - by using data from provider (name, version) and the given id
	 * @param id
	 * @param provider
	 * @return guid
	 */
	public static SarifGuid createByProvider(String id, SarifToolDataProvider provider) {
		String identifier = "name:"+provider.getName()+":"+provider.getVersion()+":"+id;
		return createByIdentifier(identifier);
	}
	
    public String getGuid() {
        return guid;
    }

	@Override
	public int hashCode() {
		return Objects.hash(guid);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		SarifGuid other = (SarifGuid) obj;
		return Objects.equals(guid, other.guid);
	}
}
