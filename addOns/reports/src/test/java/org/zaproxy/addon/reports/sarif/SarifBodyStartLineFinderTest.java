package org.zaproxy.addon.reports.sarif;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.addon.reports.sarif.SarifResult.SarifBody;
import static org.mockito.Mockito.*;

class SarifBodyStartLineFinderTest {

	private SarifBodyStartLineFinder toTest;
	private SarifBody body;

	@BeforeEach
	void beforeEach() {
		toTest = new SarifBodyStartLineFinder();
		body = mock(SarifBody.class);
	}

	@Test
	void contentFoundInsideTextBodyResultsInCorrectLine() {
		/* prepare */
		String text = "Line1\nLine2\nLine3-Content\nLine4";
		when(body.getText()).thenReturn(text);

		/* execute */
		long found = toTest.findStartLine(body, "Line3-Content");

		/* test */
		assertEquals(3, found);
	}
	
	@Test
	void contentSubPartFoundInsideTextBodyResultsInCorrectLine() {
		/* prepare */
		String text = "Line1\nLine2-ContentXsubPartY\nLine3\nLine4";
		when(body.getText()).thenReturn(text);

		/* execute */
		long found = toTest.findStartLine(body, "subPart");

		/* test */
		assertEquals(2, found);
	}
	
	@Test
	void contentNotFoundInsideTextBodyResultsInLine0() {
		/* prepare */
		String text = "Line1\nLine2\nLine3-Content\nLine4";
		when(body.getText()).thenReturn(text);

		/* execute */
		long found = toTest.findStartLine(body, "Not found");

		/* test */
		assertEquals(0, found);
	}
	
	@Test
	void contentNullSoNotFoundInsideTextBodyResultsInLine0() {
		/* prepare */
		String text = null;
		when(body.getText()).thenReturn(text);

		/* execute */
		long found = toTest.findStartLine(body, "Not found");

		/* test */
		assertEquals(0, found);
	}
	
	@Test
	void contentSomethingNotFoundInsideNullBodyResultsInLine0() {
		/* prepare */
		String text = null;
		when(body.getText()).thenReturn(text);

		/* execute */
		long found = toTest.findStartLine(null, "Something");

		/* test */
		assertEquals(0, found);
	}

}
