package org.zaproxy.addon.reports.sarif;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.SortedMap;
import java.util.TreeMap;

import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.addon.reports.ReportData;
import org.zaproxy.addon.reports.ReportHelper;

/**
 * The SARIF data structure needs GUIDs, has multiple references etc. inside
 * which are not available from standard OWASP Zap report data.<br>
 * <br>
 * So this class gives support to access SARIF related parts inside templates
 * easily.
 *
 */
public class SarifReportDataSupport {

	private ReportData reportData;
	private List<SarifResult> results = new ArrayList<>();
	
	// we use a sorted map here, so values set will always be sorted available - so
	// same report will produce same
	// ordering etc.
	private SortedMap<Integer, SarifRule> rulesMap;

	public SarifReportDataSupport(ReportData reportData) {
		this.reportData = reportData;
	}

	/* FIXME de-jcup: implement!*/
	public List<SarifResult> getResults(){
		return results;
	}

	/**
	 * 
	 * @return a sorted collection of SARIF rules
	 */
	public Collection<SarifRule> getRules() {
		if (rulesMap == null) {
			rulesMap = createRules();
		}
		return rulesMap.values();
	}

	private SortedMap<Integer, SarifRule> createRules() {
		SortedMap<Integer, SarifRule> registeredRules = new TreeMap<>();

		List<String> sites = reportData.getSites();

		for (String site : sites) {
			List<Alert> alerts = ReportHelper.getAlertsForSite(reportData.getAlertTreeRootNode(), site);
			for (Alert alert : alerts) {
				
				int pluginId = alert.getPluginId();
				if (registeredRules.containsKey(pluginId)) {
					continue;
				}
				// create and register the rule
				SarifRule rule = new SarifRule(alert);
				registeredRules.put(pluginId, rule);
			}

		}

		return registeredRules;
	}
}
