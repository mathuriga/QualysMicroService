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

package org.wso2.security.tools.scanner.scanner;

import org.wso2.security.tools.scanner.exception.InvalidRequestException;
import org.wso2.security.tools.scanner.exception.ScannerException;
import org.wso2.security.tools.scanner.utils.ScannerRequest;
import org.wso2.security.tools.scanner.utils.ScannerResponse;

import java.io.FileNotFoundException;
import java.io.UnsupportedEncodingException;

/**
 * Interface for the scanner.
 */
public interface Scanner {

    /**
     * Initialise the Scanner.
     *
     * @throws ScannerException
     */
    void init() throws ScannerException, FileNotFoundException, UnsupportedEncodingException;

    /**
     * Run scan.
     *
     * @param scannerRequest Object that represent the required information for tha scanner operation
     * @throws ScannerException
     */
    ScannerResponse startScan(ScannerRequest scannerRequest) throws InvalidRequestException, ScannerException;

    /**
     * Controller method to stop the last scan for a given application.
     *
     * @param scannerRequest Object that represent the required information for tha scanner operation
     * @return whether delete scan operation success
     */
    ScannerResponse cancelScan(ScannerRequest scannerRequest) throws ScannerException;

}