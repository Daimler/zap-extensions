package org.zaproxy.addon.reports.sarif;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class SarifHTMLToStringListConverterTest {

	private SarifHTMLToStringListConverter toTest;

	@BeforeEach
	void beforeEach() {
		toTest = new SarifHTMLToStringListConverter();
	}
	
	@Test
	void convertToListNull() {
		assertConvertToPlainText(null, Collections.emptyList());
	}

	@Test
	void convertToListEmptyString() {
		assertConvertToPlainText("", Collections.emptyList());
	}

	@Test
	void convertToListNoPTags() {
		assertConvertToPlainText("<html><body>Some content</body></html>", Collections.emptyList());
	}

	
	@Test
	void convertToListContainsPtaggedEntriesOneLine() {
		assertConvertToPlainText("<p>entry1</p><p>entry2</p>", Arrays.asList("entry1","entry2"));
		assertConvertToPlainText("\"<p>http://projects.webappsec.org/Cross-Site-Scripting</p><p>http://cwe.mitre.org/data/definitions/79.html</p>\"", Arrays.asList("http://projects.webappsec.org/Cross-Site-Scripting","http://cwe.mitre.org/data/definitions/79.html"));
	}
	
	@Test
	void convertToListContainsPtaggedEntriesMultiLine() {
		assertConvertToPlainText("<p>entry1</p>\n<p>entry2</p>", Arrays.asList("entry1","entry2"));
		assertConvertToPlainText("\n\n<p>entry1</p>\n<p>entry2</p><p>entry3</p>", Arrays.asList("entry1","entry2","entry3"));
	}
	
	@Test
	void convertToListContainsPtaggedEntriesTrimmed() {
		assertConvertToPlainText("<p>entry1     </p>\n<p>     entry2</p>", Arrays.asList("entry1","entry2"));
	}
	
	@Test
	void convertToListContainsPtaggedEntriesWithOtherContentAround() {
		assertConvertToPlainText("<html><body>somethingelse<p>entry1</p><p>entry2</p>Followed by other things</body></html>", Arrays.asList("entry1","entry2"));
		assertConvertToPlainText("<html>\n<body>\nsomethingelse<p>entry1</p>\n<p>entry2</p>\nFollowed by other things\n</body>\n</html>", Arrays.asList("entry1","entry2"));
	}

	void assertConvertToPlainText(String html, List<String> expectedList) {
		/* execute */
		List<String> result = toTest.convertToList(html);

		/* test */
		assertEquals(expectedList, result);
	}

}
