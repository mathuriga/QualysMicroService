/*
 *
 *   Copyright (c) 2019, WSO2 Inc., WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *   WSO2 Inc. licenses this file to you under the Apache License,
 *   Version 2.0 (the "License"); you may not use this file except
 *   in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.wso2.security.tools.scanner.config;

import java.util.ArrayList;
import java.util.List;

/**
 * This class represents the parameters related to Qualys Scanner.
 */
public class QualysScannerParam {

    // Qualys Scan Name (Mandatory)
    private String scanName;

    // Qualys Web Application Name (Mandatory which is retrieved from request)
    private String webAppName;

    // Qualys Web Application Id (Mandatory)
    private String webAppId;

    // Qualys Scan Type (Mandatory)
    private String type;

    // Scanner Appliance Type
    private String scannerApplianceType;

    //Scan profile Id (Mandatory)
    private String profileId;

    //ProgressiveScan (Optional)
    private String progressiveScanning;

    //Email to send notification regarding the Qualys Scan
    private String email;

    //List of WebAuthRecordIds (Authentication Scripts) (Mandatory)
    private List<String> listOfAuthenticationScripts = new ArrayList<String>();

    //List of Crawling Scripts (if required)
    private List<String> listOfCrawlingScripts = new ArrayList<String>();

    public String getScanName() {
        return scanName;
    }

    public void setScanName(String scanName) {
        this.scanName = scanName;
    }

    public String getWebAppId() {
        return webAppId;
    }

    public void setWebAppId(String webAppId) {
        this.webAppId = webAppId;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getScannerApplianceType() {
        return scannerApplianceType;
    }

    public void setScannerApplianceType(String scannerApplianceType) {
        this.scannerApplianceType = scannerApplianceType;
    }

    public List<String> getListOfAuthenticationScripts() {
        return listOfAuthenticationScripts;
    }

    public void setListOfAuthenticationScripts(List<String> listOfAuthenticationScripts) {
        this.listOfAuthenticationScripts = listOfAuthenticationScripts;
    }

    public List<String> getListOfCrawlingScripts() {
        return listOfCrawlingScripts;
    }

    public void setListOfCrawlingScripts(List<String> listOfCrawlingScripts) {
        this.listOfCrawlingScripts = listOfCrawlingScripts;
    }

    public String getProfileId() {
        return profileId;
    }

    public void setProfileId(String profileId) {
        this.profileId = profileId;
    }

    public String getProgressiveScanning() {
        return progressiveScanning;
    }

    public void setProgressiveScanning(String progressiveScanning) {
        this.progressiveScanning = progressiveScanning;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getWebAppName() {
        return webAppName;
    }

    public void setWebAppName(String webAppName) {
        this.webAppName = webAppName;
    }
}
