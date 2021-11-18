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

public class SarifToolData {

    public static final SarifToolData INSTANCE = new SarifToolData();

    // @formatter:off
    private static final SarifToolDataProvider OWASP_ZAP =
            builder()
                    .setName("OWASP ZAP")
                    .// we use 1.0 here - should normally not change
                    setTaxonomyVersion("1.0")
                    .setTaxonomyComprehensive(true)
                    .setShortDescription("OWASP ZED Attack proxy")
                    .setOrganization("OWASP")
                    .setTaxonomyInformationUri("https://www.zaproxy.org/")
                    .build();

    private static final SarifToolDataProvider CWE_WITH_4_4_TAXONOMY =
            builder()
                    .setName("CWE")
                    .setTaxonomyVersion("4.4")
                    .setTaxonomyComprehensive(true)
                    .setTaxonomyReleaseDateUtc("2021-03-15")
                    .setTaxonomyDownloadUri("https://cwe.mitre.org/data/xml/cwec_v4.4.xml.zip")
                    .setTaxonomyInformationUri("https://cwe.mitre.org/data/published/cwe_v4.4.pdf/")
                    .setShortDescription("The MITRE Common Weakness Enumeration")
                    .setOrganization("MITRE")
                    .build();
    // @formatter:on

    private SarifToolData() {
        // we only want the shared instance
    }

    public SarifToolDataProvider getOwaspZap() {
        return OWASP_ZAP;
    }

    public SarifToolDataProvider getCwe() {
        return CWE_WITH_4_4_TAXONOMY;
    }

    static SarifToolDataProviderBuilder builder() {
        return new SarifToolDataProviderBuilder();
    }

    static class SarifToolDataProviderBuilder {

        private String name;
        private String shortDescription;
        private String taxonomyVersion;
        private String taxonomyInformationUri;
        private String taxonomyDownloadUri;
        private String taxonomyReleaseDateUtc;
        private boolean comprehensive;
        private String organization;

        public SarifToolDataProvider build() {
            SarifToolDataProvider component = new SarifToolDataProvider();
            component.name = name;
            component.taxonomyShortDescription = new SarifMessage();
            component.taxonomyShortDescription = new SarifMessage();
            component.taxonomyShortDescription.text = shortDescription;
            component.taxonomyVersion = taxonomyVersion;
            component.taxonomyDownloadUri = taxonomyDownloadUri;
            component.taxonomyInformationUri = taxonomyInformationUri;
            component.taxonomyComprehensive = comprehensive;
            component.taxonomyReleaseDateUtc = taxonomyReleaseDateUtc;
            component.organization = organization;

            component.sarifGuid = SarifGuid.createToolcomponentGUID(component);

            return component;
        }

        public SarifToolDataProviderBuilder setTaxonomyReleaseDateUtc(String dateAsString) {
            this.taxonomyReleaseDateUtc = dateAsString;
            return this;
        }

        public SarifToolDataProviderBuilder setTaxonomyComprehensive(boolean comprehensive) {
            this.comprehensive = comprehensive;
            return this;
        }

        public SarifToolDataProviderBuilder setTaxonomyInformationUri(String uri) {
            this.taxonomyInformationUri = uri;
            return this;
        }

        public SarifToolDataProviderBuilder setTaxonomyDownloadUri(String uri) {
            this.taxonomyDownloadUri = uri;
            return this;
        }

        public SarifToolDataProviderBuilder setTaxonomyVersion(String taxonomyVersion) {
            this.taxonomyVersion = taxonomyVersion;
            return this;
        }

        public SarifToolDataProviderBuilder setName(String name) {
            this.name = name;
            return this;
        }

        public SarifToolDataProviderBuilder setOrganization(String organization) {
            this.organization = organization;
            return this;
        }

        public SarifToolDataProviderBuilder setShortDescription(String shortDescription) {
            this.shortDescription = shortDescription;
            return this;
        }
    }

    /**
     * Because SARIF tool component data often represents duplicated information and we do NOT want
     * to maintain same data on separate location this class was introduced. Data for SARIF tool
     * components as well as for taxonomy is provided by same provider, so can be easily reused.
     *
     * @author albert
     */
    public static class SarifToolDataProvider
            implements SarifToolComponent, SarifTaxonomyDataProvider {

        public String taxonomyReleaseDateUtc;
        public SarifMessage taxonomyShortDescription;
        private String name;
        private String organization;
        private SarifGuid sarifGuid;
        private String taxonomyVersion;
        private String taxonomyInformationUri;
        private String taxonomyDownloadUri;
        private boolean taxonomyComprehensive;

        @Override
        public String getOrganization() {
            return organization;
        }

        @Override
        public String getGuid() {
            return sarifGuid.getGuid();
        }

        @Override
        public String getName() {
            return name;
        }

        @Override
        public String getTaxonomyVersion() {
            return taxonomyVersion;
        }

        @Override
        public SarifMessage getShortDescription() {
            return taxonomyShortDescription;
        }

        @Override
        public String getDownloadUri() {
            return taxonomyDownloadUri;
        }

        @Override
        public String getInformationUri() {
            return taxonomyInformationUri;
        }

        @Override
        public boolean isComprehensive() {
            return taxonomyComprehensive;
        }

        @Override
        public String getReleaseDateUtc() {
            return taxonomyReleaseDateUtc;
        }
    }
}
