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

package org.wso2.security.tools.scanner.config;

import org.wso2.security.tools.scanner.ScannerConstants;;
import org.yaml.snakeyaml.Yaml;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.util.Map;

/**
 * Class to get the configurations from the configuration file.
 */
public class ConfigurationReader {
    private static Map<String, Object> configObjectMap;

    private ConfigurationReader() {
    }

    /**
     * Load configuration into JVM.
     *
     * @throws FileNotFoundException
     */
    public static void loadConfiguration() throws FileNotFoundException {
        String configurationFile =
                ScannerConstants.RESOURCE_FILE_PATH + File.separator + ScannerConstants.CONFIGURTION_FILE_NAME;
        loadConfiguration(configurationFile);
    }

    /**
     * Load the properties from the property file.
     *
     * @param configFileLocation Path to configuration file
     * @throws FileNotFoundException
     */
    private static void loadConfiguration(String configFileLocation) throws FileNotFoundException {
        Yaml yaml = new Yaml();
        InputStream inputStream = null;
        inputStream = new FileInputStream(configFileLocation);

        configObjectMap = yaml.load(inputStream);
    }

    /**
     * Reads the required property from the property file using the given key and returns the corresponding value.
     *
     * @param key The key mapping to the required value of the property file.
     * @return returns the value corresponding to the given key value.
     */
    public static String getConfigProperty(String key) {
        return String.valueOf(configObjectMap.get(key));
    }

    /**
     * Reads the required property from the property file using the given key and returns the corresponding value.
     *
     * @return returns the config object.
     */
    public static Map getConfigs() {
        return configObjectMap;
    }
}
