/*
 *  Copyright (c) 2019, WSO2 Inc., WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 *
 */

package org.wso2.security.tools.scanner.utils;

/**
 * Model class to represent a Scan status request object coming from Scanner Side.
 */
public class ScanStatusUpdateRequest {

    private String jobId;

    private String scanStatus;

    private String actualScannerId;

    private String scanReportPath;

    public String getScanReportPath() {

        return scanReportPath;
    }

    public void setScanReportPath(String scanReportPath) {

        this.scanReportPath = scanReportPath;
    }

    public String getJobId() {

        return jobId;
    }

    public void setJobId(String jobId) {

        this.jobId = jobId;
    }

    public String getScanStatus() {

        return scanStatus;
    }

    public void setScanStatus(String scanStatus) {

        this.scanStatus = scanStatus;
    }

    public String getActualScannerId() {

        return actualScannerId;
    }

    public void setActualScannerId(String actualScannerId) {

        this.actualScannerId = actualScannerId;
    }
}
