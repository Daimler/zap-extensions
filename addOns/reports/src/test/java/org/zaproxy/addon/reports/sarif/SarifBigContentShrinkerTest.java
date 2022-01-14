package org.zaproxy.addon.reports.sarif;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class SarifBigContentShrinkerTest {

	private SarifBigContentShrinker shrinkerToTest;

	@BeforeEach
	void beforeEach() {
		shrinkerToTest = new SarifBigContentShrinker();
	}

	@Test
	void notShrinking12345678901234567890WhenMaxIs30andSnippetNotSet() {
		/* prepare */
		String content = "12345678901234567890";
		String snippet = null;
		int maxAllowedChars = 30;

		/* execute */
		String result = shrinkerToTest.shrinkTextContent(content, maxAllowedChars, snippet);

		/* test */
		assertEquals(content,result);
		
	}
	
	@Test
	void notShrinking12345678901234567890WhenMaxIs30andSnippetLikeContent() {
		/* prepare */
		String content = "12345678901234567890";
		String snippet = content;
		int maxAllowedChars = 30;

		/* execute */
		String result = shrinkerToTest.shrinkTextContent(content, maxAllowedChars, snippet);

		/* test */
		assertEquals(content,result);
		
	}
	
	@Test
	void shrinking12345678901234567890WhenMaxIs15andSnippetLikeContent() {
		/* prepare */
		String content = "12345678901234567890";
		String snippet = null;
		int maxAllowedChars = 15;

		/* execute */
		String result = shrinkerToTest.shrinkTextContent(content, maxAllowedChars, snippet);

		/* test */
		assertEquals("123456789012345[...]",result);
		
	}
	
	@Test
	void shrinking12345678901234567890WhenMaxIs15andSnippetSetButNotFound() {
		/* prepare */
		String content = "12345678901234567890";
		String snippet = "not-found";
		int maxAllowedChars = 15;

		/* execute */
		String result = shrinkerToTest.shrinkTextContent(content, maxAllowedChars, snippet);

		/* test */
		assertEquals("123456789012345[...]",result);
		
	}
	
	@Test
	void shrinking1234567890abcd1234567890WhenMaxIs2andSnippetSetAsABCD() {
		/* prepare */
		String content = "1234567890abcd1234567890";
		String snippet = "abcd";
		int maxAllowedChars = 2;

		/* execute */
		String result = shrinkerToTest.shrinkTextContent(content, maxAllowedChars, snippet);

		/* test */
		assertEquals("ab[...]",result); 
		
	}
	
	@Test
	void shrinking1234567890abcd1234567890WhenMaxIs14andSnippetSetAsABCD() {
		/* prepare */
		String content = "1234567890abcd1234567890";
		String snippet = "abcd";
		int maxAllowedChars = 14;

		/* execute */
		String result = shrinkerToTest.shrinkTextContent(content, maxAllowedChars, snippet);

		/* test */
		assertEquals("[...]67890abcd12345[...]",result);  // 5 before, 4 chars (abcd) and 5 chars after
		
	}
	
	@Test
	void shrinking12345678901234567890abcdWhenMaxIs14andSnippetSetAsABCD() {
		/* prepare */
		String content = "12345678901234567890abcd";
		String snippet = "abcd";
		int maxAllowedChars = 14;

		/* execute */
		String result = shrinkerToTest.shrinkTextContent(content, maxAllowedChars, snippet);

		/* test */
		assertEquals("[...]67890abcd",result);  // 5 before, 4 chars (abcd) and 5 chars after
		
	}
	
	@Test
	void shrinking12345678901234567890abc12345dWhenMaxIs14andSnippetSetAsABCD() {
		/* prepare */
		String content = "12345678901234567890abcd12345";
		String snippet = "abcd";
		int maxAllowedChars = 14;

		/* execute */
		String result = shrinkerToTest.shrinkTextContent(content, maxAllowedChars, snippet);

		/* test */
		assertEquals("[...]67890abcd12345",result);  // 5 before, 4 chars (abcd) and 5 chars after
		
	}

}
