/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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

import static org.junit.jupiter.api.Assertions.assertEquals;

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
        assertEquals(content, result);
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
        assertEquals(content, result);
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
        assertEquals("123456789012345[...]", result);
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
        assertEquals("123456789012345[...]", result);
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
        assertEquals("ab[...]", result);
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
        assertEquals(
                "[...]67890abcd12345[...]", result); // 5 before, 4 chars (abcd) and 5 chars after
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
        assertEquals("[...]67890abcd", result); // 5 before, 4 chars (abcd) and 5 chars after
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
        assertEquals("[...]67890abcd12345", result); // 5 before, 4 chars (abcd) and 5 chars after
    }
}
