package org.zaproxy.addon.reports.sarif;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.HashSet;
import java.util.Set;

import org.junit.jupiter.api.Test;

class SarifGuidTest {
	
	@Test
	void createByIdentifierResultsInGUIDStringWithExpectedLenghtOf36() {
		/* prepare */
		String identifier = "i.am.short";
		
		/* execute */
		SarifGuid result = SarifGuid.createByIdentifier(identifier);
		
		/* test */
		assertEquals(36, result.getGuid().length());
	}

	@Test
	void createByIdentifierCalledMultipletTimesResultsAlwaysInSameGUIDString() {
		/* prepare */
		String identifier = "this.is.my.test.name";
		Set<String> resultSet = new HashSet<>();
		
		/* execute */
		for (int i=0;i<10;i++) {
			SarifGuid result = SarifGuid.createByIdentifier(identifier);
			resultSet.add(result.getGuid());
		}
		
		/* test */
		assertEquals(1,resultSet.size());
		
	}

}
