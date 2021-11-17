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

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.TreeSet;

import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.addon.reports.ReportData;
import org.zaproxy.addon.reports.ReportHelper;

/**
 * The SARIF data structure needs GUIDs, has multiple references etc. inside
 * which are not available from standard OWASP Zap report data.<br>
 * <br>
 * So this class gives support to access SARIF related parts inside templates
 * easily.
 */
public class SarifReportDataSupport {

	private ReportData reportData;
	private List<SarifResult> results;

	// we use a sorted map here, so values set will always be sorted available - so
	// same report will produce same
	// ordering etc.
	private SortedMap<Integer, SarifRule> rulesMap;
	private Collection<SarifTaxonomy> taxonomies;

	public SarifReportDataSupport(ReportData reportData) {
		this.reportData = reportData;
	}

	public SarifToolData getComponents() {
		return SarifToolData.INSTANCE;
	}

	public List<SarifResult> getResults() {
		if (results == null) {
			results = createResults();
		}
		return results;
	}

	private List<SarifResult> createResults() {
		List<SarifResult> results = new ArrayList<>();
		List<String> sites = reportData.getSites();

		for (String site : sites) {
			List<Alert> alertsForSite = ReportHelper.getAlertsForSite(reportData.getAlertTreeRootNode(), site);

			for (Alert alert : alertsForSite) {
				SarifResult sarifResult = new SarifResult(alert);
				results.add(sarifResult);
			}
		}

		return results;
	}

	public Collection<SarifTaxonomy> getTaxonomies() {
		if (taxonomies == null) {
			taxonomies = createTaxonomies();
		}
		return taxonomies;
	}

	private Collection<SarifTaxonomy> createTaxonomies() {
		List<SarifTaxonomy> list = new ArrayList<>();

		/* currently we provide only CWE */
		SarifTaxonomy taxonomy = new SarifTaxonomy(SarifToolData.INSTANCE.getCwe());

		Set<Integer> foundCWEIds = new TreeSet<>();
		for (String site : reportData.getSites()) {
			List<Alert> alertsForSite = ReportHelper.getAlertsForSite(reportData.getAlertTreeRootNode(), site);

			for (Alert alert : alertsForSite) {
				foundCWEIds.add(alert.getCweId());
			}
		}
		for (Integer foundCWEId : foundCWEIds) {
			taxonomy.addTaxa("" + foundCWEId);
		}

		list.add(taxonomy);

		return list;
	}

	/** @return a sorted collection of SARIF rules */
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
