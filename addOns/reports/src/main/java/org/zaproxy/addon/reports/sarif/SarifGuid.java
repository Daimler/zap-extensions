package org.zaproxy.addon.reports.sarif;

import java.util.UUID;

import org.parosproxy.paros.core.scanner.Alert;

/**
 * Represents a GUID for Sarif
 * https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317438
 *
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
