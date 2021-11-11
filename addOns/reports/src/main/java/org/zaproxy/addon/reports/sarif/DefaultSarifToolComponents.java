package org.zaproxy.addon.reports.sarif;

public enum DefaultSarifToolComponents implements SarifToolComponent{
	
	OWASP_ZAP("OWASP ZAP",new SarifGuid("4d841334-0141-4e13-bdd0-53087266ebcd")),
	
	CWE("CWE",new SarifGuid("f2856fc0-85b7-373f-83e7-6f8582243547")),
	
	;

	private String name;
	private SarifGuid sarifGuid;

	DefaultSarifToolComponents(String name, SarifGuid sarifGuid) {
		this.name=name;
		this.sarifGuid=sarifGuid;
	}


	@Override
	public String getGuid() {
		return sarifGuid.getGuid();
	}

	@Override
	public String getName() {
		return name;
	}

}
