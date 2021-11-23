package org.zaproxy.addon.reports.sarif;

import org.zaproxy.addon.reports.sarif.SarifResult.SarifBody;

public class SarifBodyStartLineFinder {

	public static final SarifBodyStartLineFinder DEFAULT = new SarifBodyStartLineFinder();

	/**
	 * SARIF supports a region information with a start line. (see
	 * https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317682
	 * ) This class does find the startline for text body content of given parameter
	 * 
	 * @param body
	 * @param toSearch
	 * @return 0 - when toSearch is not found inside text body, otherwise line number
	 */
	public long findStartLine(SarifBody body, String toSearch) {
		if (body == null) {
			return 0;
		}
		String text = body.getText();
		if (text == null) {
			return 0;
		}

		String[] lines = text.split("\n");
		for (int i = 0; i < lines.length; i++) {
			String content = lines[i];
			int indexOf = content.indexOf(toSearch);
			if (indexOf != -1) {
				return i + 1;
			}
		}
		return 0;
	}
}
