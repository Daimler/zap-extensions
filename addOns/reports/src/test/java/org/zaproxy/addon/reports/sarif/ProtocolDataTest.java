package org.zaproxy.addon.reports.sarif;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EmptySource;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

class ProtocolDataTest {

	@ParameterizedTest(name="A string containing \"{0}\" can be parsed, but result has version and protocol null")
	@ValueSource(strings={" ","/","HTTP/","/1.1","    /","/   "})
	@NullSource
	@EmptySource
	void parseProtocolAndVersionUnsupportedStrings(String data) {
		/* execute */
		ProtocolData result = ProtocolData.parseProtocolAndVersion(data);
		
		/* test */
		assertNotNull(result);
		assertNull(result.getVersion());
		assertNull(result.getProtocol());
	}
	
	@ParameterizedTest(name="A string containing \"{0}\" can be parsed, and version and protocol are set")
	@ValueSource(strings={"HTTP/1.1","HTTP/2.0","Something/Version"})
	void parseProtocolAndVersionSupportedStrings(String data) {
		/* execute */
		ProtocolData result = ProtocolData.parseProtocolAndVersion(data);
		
		/* test */
		assertNotNull(result);
		assertNotNull(result.getVersion());
		assertNotNull(result.getProtocol());
	}

	@Test
	void parseProtocolAndVersionResultContentAsExpected() {
		/* execute */
		ProtocolData result = ProtocolData.parseProtocolAndVersion("MyProtocol/MyVersion");
		
		/* test */
		assertNotNull(result);
		assertEquals("MyVersion",result.getVersion());
		assertEquals("MyProtocol",result.getProtocol());
	}
}
