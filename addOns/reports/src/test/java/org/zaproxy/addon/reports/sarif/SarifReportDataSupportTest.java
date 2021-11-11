package org.zaproxy.addon.reports.sarif;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.addon.reports.ReportData;
import org.zaproxy.zap.extension.alert.AlertNode;

import static org.zaproxy.addon.reports.TestAlertBuilder.*;
import static org.zaproxy.addon.reports.TestAlertNodeBuilder.*;

class SarifReportDataSupportTest {

	private ReportData reportData;

	@BeforeEach
	void beforeEach() {
	}

	@Test
	void threeAlertsTwoDifferentResultInTwoSarifRules() {
		/* prepare */
		reportData = new ReportData();
		AlertNode rootNode = new AlertNode(0, "root");
		reportData.setAlertTreeRootNode(rootNode);
		//  @formatter:off
		AlertNode plugin1NodeA = newAlertNodeBuilder(
				newAlertBuilder().
					setPluginId(1).
					setName("Name1").
					setUriString("https://example.com/test1").
					build())
				.build();
		
		AlertNode plugin1NodeB = newAlertNodeBuilder(
				newAlertBuilder().
					setPluginId(1).
					setName("Name1").
					setUriString("https://example.com/test2").
					build())
				.build();
		
		AlertNode plugin2Node = newAlertNodeBuilder(
				newAlertBuilder()
					.setPluginId(2)
					.setName("Name2")
					.setUriString("https://example.com/test3")
					.build())
				.build();
		
		rootNode.add(plugin1NodeA);
		rootNode.add(plugin1NodeB);
		rootNode.add(plugin2Node);
	    //  @formatter:on

		reportData.setSites(Arrays.asList("https://example.com"));
		SarifReportDataSupport toTest = new SarifReportDataSupport(reportData);

		/* execute */
		Collection<SarifRule> rules = toTest.getRules();

		/* test */
		assertEquals(2, rules.size());
		Iterator<SarifRule> it = rules.iterator();
		SarifRule rule1 = it.next();
		SarifRule rule2 = it.next();
		
		assertEquals("Name1",rule1.getName());
		assertEquals("1",rule1.getId());
		
		assertEquals("Name2",rule2.getName());
		assertEquals("2",rule2.getId());

	}

	@Test
	void rule_has_full_description() {
		/* prepare */
		reportData = new ReportData();
		AlertNode rootNode = new AlertNode(0, "root");
		reportData.setAlertTreeRootNode(rootNode);
		//  @formatter:off
		AlertNode plugin1NodeA = newAlertNodeBuilder(
				newAlertBuilder().
					setDescription("this is a description").
					setUriString("https://example.com/test1").
					build())
				.build();
		
		rootNode.add(plugin1NodeA);
	    //  @formatter:on

		reportData.setSites(Arrays.asList("https://example.com"));
		SarifReportDataSupport toTest = new SarifReportDataSupport(reportData);

		/* execute */
		Collection<SarifRule> rules = toTest.getRules();

		/* test */
		assertEquals(1, rules.size());
		Iterator<SarifRule> it = rules.iterator();
		SarifRule rule1 = it.next();
		assertEquals("this is a description",rule1.getFullDescription());
		
	}

}
