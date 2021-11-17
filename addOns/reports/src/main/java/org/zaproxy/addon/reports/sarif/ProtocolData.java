package org.zaproxy.addon.reports.sarif;

/**
 * Internal class to hold protocol and version separated. Provides also parse
 * functionality inside.
 *
 */
class ProtocolData {

	private String protocol;
	private String version;

	private ProtocolData() {
		// private constructor - so static method must be used
	}

	public static ProtocolData parseProtocolAndVersion(String versionString) {
		ProtocolData data = new ProtocolData();
		// assume it is something like HTTP/1.1 - so $protocol/$version
		if (versionString == null || versionString.length() < 3) {
			return data;
		}

		int slashIndex = versionString.indexOf('/');
		if (slashIndex < 1 || slashIndex == versionString.length() - 1) {
			return data;
		}
		data.protocol = versionString.substring(0, slashIndex);
		data.version = versionString.substring(slashIndex + 1);
		return data;
	}

	public String getVersion() {
		return version;
	}

	public String getProtocol() {
		return protocol;
	}

}