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

public class SarifTaxonomy implements SarifTaxonomyDataProvider {

	private SarifTaxonomyDataProvider provider;
	private Collection<SarifTaxa> taxaCollection = new ArrayList<>();

	public SarifTaxonomy(SarifTaxonomyDataProvider provider) {
		this.provider = provider;
	}

	@Override
	public String getName() {
		return provider.getName();
	}

	@Override
	public SarifMessage getShortDescription() {
		return provider.getShortDescription();
	}

	@Override
	public String getDownloadUri() {
		return provider.getDownloadUri();
	}

	@Override
	public String getInformationUri() {
		return provider.getInformationUri();
	}

	@Override
	public boolean isComprehensive() {
		return provider.isComprehensive();
	}

	@Override
	public String getTaxonomyVersion() {
		return provider.getTaxonomyVersion();
	}

	/**
	 * Creates a taxa entry with dediced SARIF guid, add it to this taxonomy and
	 * return the created object
	 *
	 * @param taxonomyId
	 * @return taxa
	 */
	public SarifTaxa addTaxa(String taxonomyId) {
		SarifGuid taxaGUID = SarifGuid.createForTaxa(taxonomyId, this);
		SarifTaxa taxa = new SarifTaxa(taxaGUID, taxonomyId);
		taxaCollection.add(taxa);
		return taxa;
	}

	public Collection<SarifTaxa> getTaxa() {
		return taxaCollection;
	}

	@Override
	public String getGuid() {
		return provider.getGuid();
	}

	@Override
	public String getReleaseDateUtc() {
		return provider.getReleaseDateUtc();
	}

	@Override
	public String getOrganization() {
		return provider.getOrganization();
	}
}
