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

package org.wso2.security.tools.scanner;

/**
 * Constants related to Qualys Scanner
 */
public class QualysScannerConstants {

    //Constants related to Qualys credentials
    public static final String USERNAME = "username";
    public static final String PASSWORD = "password";
    public static final String HOST = "host";

    //Qualys API Endpoint
    public static final String QUALYS_START_SCAN_API = "/qps/rest/3.0/launch/was/wasscan";
    //    public static final String QUALYS_CANCEL_SCAN_API = "/qps/rest/3.0/cancel/was/wasscan/";
    public static final String QUALYS_GET_STATUS_API = "/qps/rest/3.0/status/was/wasscan/";
    //    public static final String QUALYS_GET_REPORT_API = "/qps/rest/3.0/download/was/report/";
    public static final String QUALYS_GET_APPLICATION_API = "/qps/rest/3.0/search/was/webapp/";
    public static final String QUALYS_GET_AUTHENTICATION_SCRIPT_API = "/qps/rest/3.0/search/was/webappauthrecord/";
    public static final String QUALYS_GET_OPTIONAL_PROFILE_API = "/qps/rest/3.0/search/was/optionprofile/";
    public static final String QUALYS_ADD_AUTH_SCRIPT_API = "/qps/rest/3.0/create/was/webappauthrecord";
    public static final String QUALYS_WEB_UPDATE_API = "/qps/rest/3.0/update/was/webapp/";

    //Paths of the required files which are generated at Qualys Scanner initializing time
    public static final String QUALYS_WEB_APPLICATION_LIST_FILE_PATH = ScannerConstants.RESOURCE_FILE_PATH
            .concat("/qualysWebApplications.xml");
    public static final String QUALYS_AUTHENTICATION_LIST_FILE_PATH = ScannerConstants.RESOURCE_FILE_PATH
            .concat("/qualysAuthenticationScripts.xml");
    public static final String QUALYS_OPTIONAL_PROFILE_LIST_FILE_PATH = ScannerConstants.RESOURCE_FILE_PATH
            .concat("/qualysOptionalProfile.xml");
    //    public static final String QUALYS_CRAWLING_LIST_FILE_PATH = ScannerConstants.RESOURCE_FILE_PATH
    //            .concat("/qualysCrawlingScripts.xml");

    public static final String QUALYS_SCAN_NAME_PREFIX = "New Discovery scan launch from API : ";
    public static final long DELAY_BETWEEN_STATUS_CHECK_TASK = 15;

    //Qualys Tag Names
    public static final String QUALYS_WEBAPP_TAG_NAME = "WebApp";
    public static final String QUALYS_OPTIONAL_PROFILE_TAG_NAME = "OptionProfile";
    public static final String NAME_KEYWORD = "name";
    public static final String ID_KEYWORD = "id";

}
