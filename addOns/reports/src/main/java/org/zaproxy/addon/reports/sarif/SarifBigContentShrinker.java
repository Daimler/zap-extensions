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

public class SarifBigContentShrinker {

	private static final String SHRINK_MARKER = "[...]";

	public String shrinkTextContent(String content, int maxAllowedCharacters, String snippet) {
		if (content == null) {
			return null;
		}
		if (content.length() <= maxAllowedCharacters) {
			return content;
		}

		/* simple shrink when snippet not set or not found */
		int snippetIndex = -1;
		if (snippet != null) {
			snippetIndex = content.indexOf(snippet);
		}

		if (snippetIndex == -1) {
			return content.substring(0, maxAllowedCharacters) + SHRINK_MARKER;
		}

		return calculateSnippetWrappedWithBeforeAndAfter(content, maxAllowedCharacters, snippet, snippetIndex);
	}

	private String calculateSnippetWrappedWithBeforeAndAfter(String content, int maxAllowedCharacters, String snippet,
			int snippetIndex) {
		/* calculate before and after charsize */
		int remaining = maxAllowedCharacters - snippet.length();
		if (remaining == 0) {
			return snippet;
		} else if (remaining < 0) {
			return snippet.substring(0, maxAllowedCharacters) + SHRINK_MARKER;
		}
		int charsBefore = remaining / 2;
		int charsAfter = charsBefore;

		/* calculate beginning */
		boolean shrinkMarketAtBeginning = true;
		int calculatedIndexBefore = snippetIndex - charsBefore;
		if (calculatedIndexBefore == 0) {
			shrinkMarketAtBeginning = false;
		} else if (calculatedIndexBefore < 0) {
			charsAfter = charsAfter - calculatedIndexBefore;// e.g. calcIndexBefore=-4 and charsAfter=5 chars --> 5-(-4)
															// = 9
			calculatedIndexBefore = 0;
		}

		/* calculate end */
		boolean shrinkMarkerAtTheEnd = true;
		int calculatedIndexAfter = snippetIndex + snippet.length() + charsAfter;
		int contentLength = content.length();
		if (calculatedIndexAfter >= contentLength) {
			/* meeans not cut at all */
			shrinkMarkerAtTheEnd = false;
			calculatedIndexAfter = contentLength;
		}

		/* calculate snippet and before and end content */
		String buildContent = content.substring(calculatedIndexBefore, calculatedIndexAfter);

		StringBuilder sb = new StringBuilder();
		if (shrinkMarketAtBeginning) {
			sb.append(SHRINK_MARKER);
		}
		
		sb.append(buildContent);
		
		if (shrinkMarkerAtTheEnd) {
			sb.append(SHRINK_MARKER);
		}

		return sb.toString();
	}
}
