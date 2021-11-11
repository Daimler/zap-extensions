package org.zaproxy.addon.reports.sarif;

import static java.util.Objects.requireNonNull;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.parosproxy.paros.core.scanner.Alert;

public class SarifRule implements Comparable<SarifRule> {

	private Alert alert;
	private SarifRuleProperties ruleProperties;
	private List<SarifRuleRelationShip> relationShips;

	public SarifRule(Alert alert) {
		requireNonNull(alert, "alert parameter may not be null!");
		this.alert = alert;
		this.ruleProperties = new SarifRuleProperties();
	}

	public String getId() {
		return "" + alert.getPluginId();
	}

	public String getName() {
		return alert.getName();
	}

	public String getFullDescription() {
		return alert.getDescription();
	}

	public String getShortDescription() {
		return alert.getName();
	}

	public SarifRuleProperties getProperties() {
		return ruleProperties;
	}

	@Override
	public int compareTo(SarifRule o) {
		return alert.getPluginId() - o.alert.getPluginId();
	}

	public List<SarifRuleRelationShip> getRelationShips() {
		if (relationShips == null) {
			relationShips = createRelationShips();
		}
		return relationShips;
	}

	private List<SarifRuleRelationShip> createRelationShips() {
		List<SarifRuleRelationShip> list = new ArrayList<>();
		/* CWE relationship*/
		if (alert.getCweId()>0) {
			/* TODO de-jcup: update report.json and use sarif support for relations etc.*/
			SarifRuleRelationShip cweRelation = new SarifRuleRelationShip();
			cweRelation.kinds.add("superset");
			cweRelation.target.sarifGuid=new SarifGuid(alert);
			cweRelation.target.id=""+alert.getCweId();
			cweRelation.target.toolComponent=DefaultSarifToolComponents.CWE;
		}
		return list;
	}

	public class SarifRuleRelationShip {
		List<String> kinds = new ArrayList<>();
		SarifRuleRelationShipTarget target=new SarifRuleRelationShipTarget();

		public SarifRuleRelationShipTarget getTarget() {
			return target;
		}
		
		public List<String> getKinds() {
			return kinds;
		}
	}

	public class SarifRuleRelationShipTarget {
		SarifToolComponent toolComponent;
		SarifGuid sarifGuid;
		String id;
		
		public SarifToolComponent getToolComponent() {
			return toolComponent;
		}
		
		public String getGuid() {
			return sarifGuid.getGuid();
		}
		public String getId() {
			return id;
		}
	}

	public class SarifRuleProperties {
		public Collection<String> getReferences() {
			return Arrays.asList(alert.getReference());
		}

		public String getConfidence() {
			switch (alert.getConfidence()) {
			case Alert.CONFIDENCE_FALSE_POSITIVE:
				return "false-positive";
			case Alert.CONFIDENCE_MEDIUM:
				return "medium";
			case Alert.CONFIDENCE_HIGH:
				return "high";
			case Alert.CONFIDENCE_LOW:
				return "low";
			case Alert.CONFIDENCE_USER_CONFIRMED:
				return "confirmed";
			default:
				return "unknown";
			}
		}
	}

}
