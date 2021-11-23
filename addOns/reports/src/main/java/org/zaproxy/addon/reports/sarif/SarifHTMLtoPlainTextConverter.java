package org.zaproxy.addon.reports.sarif;

import java.util.regex.Pattern;

public class SarifHTMLtoPlainTextConverter {

	private static final Pattern PATTERN_XML_START_OR_END_TAG = Pattern.compile("<[a-zA-Z-/]*>");
	private static final Pattern PATTERN_HTML_P_END = Pattern.compile("</p>");
	private static final Pattern PATTERN_HTML_BR = Pattern.compile("<br>|<br/>");

	/**
	 * Shared default instance
	 */
	public static final SarifHTMLtoPlainTextConverter DEFAULT = new SarifHTMLtoPlainTextConverter();

	/**
	 * Converts given HTML content to plain text. HTML Tags "br" and "p" will be
	 * changed to new lines, all other tags are just removed.
	 * 
	 * @param html
	 * @return plain text
	 */
	public String convertToPlainText(String html) {
		if (html == null) {
			return null;
		}
		String result = html;

		result = PATTERN_HTML_P_END.matcher(result).replaceAll("\n");
		result = PATTERN_HTML_BR.matcher(result).replaceAll("\n");
		result = PATTERN_XML_START_OR_END_TAG.matcher(result).replaceAll("");

		return result;
	}

}
