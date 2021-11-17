package org.zaproxy.addon.reports.sarif;

/**
 * A provider interface for SARIF taxonomy data
 *
 */
public interface SarifTaxonomyDataProvider {

    String getVersion();

	SarifMessage getShortDescription();

	String getName();

	String getGuid();

	String getDownloadUri();
	
	String getInformationUri();
	
	boolean isComprehensive();
	
	String getReleaseDateUtc();
	
	String getOrganization();
}
