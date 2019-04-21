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
 * /
 */

package org.wso2.security.tools.scanner.config;

/**
 * TODO : Class level comment
 */
public class ScanContext {
    private String jobID;

    private String authId;

    private String scannerScanId;

    // Qualys Web Application Id (Mandatory)
    private String webAppId;

    // Qualys Web Application Id (Mandatory)
    private String webAppName;

    // Qualys Scan Type (Mandatory)
    private String type;

    // Scanner Appliance Type
    private String scannerApplianceType;

    //Scan profile Id (Mandatory)
    private String profileId;

    //ProgressiveScan (Optional)
    private String progressiveScanning;

    public String getJobID() {
        return jobID;
    }

    public void setJobID(String jobID) {
        this.jobID = jobID;
    }

    public String getAuthId() {
        return authId;
    }

    public void setAuthId(String authId) {
        this.authId = authId;
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

    public void setWebAppName(String webAppName) {
        this.webAppName = webAppName;
    }

    public String getWebAppName() {
        return webAppName;
    }

    public String getScannerScanId() {
        return scannerScanId;
    }

    public void setScannerScanId(String scannerScanId) {
        this.scannerScanId = scannerScanId;
    }
}
