package org.zaproxy.addon.reports.sarif;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SarifHTMLToStringListConverter {

	/**
	 * Shared default instance
	 */
	public static final SarifHTMLToStringListConverter DEFAULT = new SarifHTMLToStringListConverter();
	
	private static final Pattern PATTERN_HTML_P_CONTENT = Pattern.compile("<p>([^<]+)<\\/p>");

	/**
	 * Converts given HTML content to a simple string list. Currently supported:
	 * <ul>
	 * <li>Element content inside &lt;p&gt; tags will be used as a trimmed string
	 * and added as a list element</li>
	 * </ul>
	 * All other content is just ignored!
	 * 
	 * @param html
	 * @return plain text
	 */
	public List<String> convertToList(String html) {
		if (html == null) {
			return Collections.emptyList();
		}

		List<String> list = new ArrayList<>();

		Matcher matcher = PATTERN_HTML_P_CONTENT.matcher(html);
		while (matcher.find()) {
			String group = matcher.group(1);
			list.add(group.trim());
		}

		return list;
	}
}
