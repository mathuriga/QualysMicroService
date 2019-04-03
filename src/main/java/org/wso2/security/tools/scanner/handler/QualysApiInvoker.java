package org.wso2.security.tools.scanner.handler;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.Consts;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClientBuilder;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.wso2.security.tools.scanner.QualysScannerConstants;
import org.wso2.security.tools.scanner.exception.InvalidRequestException;
import org.wso2.security.tools.scanner.exception.ScannerException;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringReader;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

/**
 * This class is responsible to invoke qualys api
 */
public class QualysApiInvoker {

    private static final Log log = LogFactory.getLog(QualysApiInvoker.class);

    private String basicAuth;

    public void setBasicAuth(String basicAuth) {
        this.basicAuth = basicAuth;
    }

    /**
     * Generate prerequisite files from qualys back end
     *
     * @param endPoint Qualys endpoint to get relevant files
     * @param filePath file path where the file should be created.
     * @throws ScannerException the error occurred while generating the file.
     */
    public void generatePrerequisiteFile(String endPoint, String filePath) throws ScannerException {
        String result;
        File tempFile = new File(filePath);
        boolean exists = tempFile.exists();
        try {
            if (!exists) {
                HttpPost postRequest = new HttpPost(endPoint);
                postRequest.addHeader("Authorization", "Basic " + basicAuth);
                postRequest.addHeader("Accept", "application/xml");
                HttpClient client = HttpClientBuilder.create().build();
                HttpResponse response = client.execute(postRequest);
                if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
                    BufferedReader br = new BufferedReader(
                            new InputStreamReader(response.getEntity().getContent(), "UTF-8"));
                    StringBuilder res = new StringBuilder();
                    while ((result = br.readLine()) != null) {
                        res.append(result);
                    }
                    BufferedWriter bwr = new BufferedWriter(new FileWriter(new File(filePath)));
                    bwr.write(res.toString());
                    bwr.flush();
                    bwr.close();
                    br.close();
                } else if (response.getStatusLine().getStatusCode() == HttpStatus.SC_UNAUTHORIZED) {
                    throw new ScannerException("The API request failed because of an authentication failure. ");
                } else {
                    throw new ScannerException("Error occurred while retrieving the list of Web APP, Profile list");
                }
            }
        } catch (IOException e) {
            throw new ScannerException("Error occurred while retrieving the list of Web APP, Profile list", e);
        }
    }

    /**
     * Call the Api to add authentication script in qualys end.
     *
     * @param host                  qualys endpoint
     * @param authScriptRequestBody addAuthentication script request body.
     * @return auth script id
     * @throws InvalidRequestException      Occurred due to Invalid request parameters.
     * @throws IOException                  Occurred IO exception while calling the api
     * @throws ParserConfigurationException Occurred while retrieving the script id.
     * @throws SAXException                 Occurred while retrieving the script id.
     */
    public String addAuthenticationScript(String host, String authScriptRequestBody)
            throws InvalidRequestException, IOException, ParserConfigurationException, SAXException {
        HttpPost postRequest = new HttpPost(host.concat(QualysScannerConstants.QUALYS_ADD_AUTH_SCRIPT_API));
        postRequest.addHeader("Authorization", "Basic " + basicAuth);
        HttpClient client = HttpClientBuilder.create().build();
        StringEntity entity = new StringEntity(authScriptRequestBody, ContentType.create("text/xml", Consts.UTF_8));
        HttpResponse response;
        postRequest.setEntity(entity);
        response = client.execute(postRequest);
        return getRequiredData(response, "id");
    }

    /**
     * Call the Api to add authentication script to web app.
     *
     * @param host                    qualys endpoint
     * @param updateWebAppRequestBody update web app request body.
     * @param webId                   web id
     * @return web id
     * @throws InvalidRequestException      Occurred due to Invalid request parameters.
     * @throws IOException                  Occurred IO exception while calling the api
     * @throws ParserConfigurationException Occurred while retrieving the web id.
     * @throws SAXException                 Occurred while retrieving the web id.
     */
    public String updateWebApp(String host, String updateWebAppRequestBody, String webId)
            throws InvalidRequestException, IOException, ParserConfigurationException, SAXException {
        HttpPost postRequest = new HttpPost(host.concat(QualysScannerConstants.QUALYS_WEB_UPDATE_API.concat(webId)));
        postRequest.addHeader("Authorization", "Basic " + basicAuth);
        HttpClient client = HttpClientBuilder.create().build();
        StringEntity entity = new StringEntity(updateWebAppRequestBody, ContentType.create("text/xml", Consts.UTF_8));
        HttpResponse response;
        postRequest.setEntity(entity);
        response = client.execute(postRequest);
        return getRequiredData(response, "id");
    }

    /**
     * Launch the scan.
     *
     * @param host                  qualys endpoint
     * @param launchScanRequestBody launch scan request body.
     * @return scannerScanId
     * @throws InvalidRequestException      Occurred due to Invalid request parameters.
     * @throws IOException                  Occurred IO exception while calling the api
     * @throws ParserConfigurationException Occurred while retrieving the web id.
     * @throws SAXException                 Occurred while retrieving the web id.
     */
    public String launchScan(String host, String launchScanRequestBody)
            throws InvalidRequestException, IOException, ParserConfigurationException, SAXException {
        HttpPost postRequest = new HttpPost(host.concat(QualysScannerConstants.QUALYS_START_SCAN_API));
        postRequest.addHeader("Authorization", "Basic " + basicAuth);
        HttpClient client = HttpClientBuilder.create().build();
        StringEntity entity = new StringEntity(launchScanRequestBody, ContentType.create("text/xml", Consts.UTF_8));
        HttpResponse response;
        postRequest.setEntity(entity);
        response = client.execute(postRequest);
        return getRequiredData(response, "id");
    }

    /**
     * Retrieve Scan Status
     *
     * @param host   qualys endpoint
     * @param scanId scan id
     * @return scan status
     * @throws InvalidRequestException      Occurred due to Invalid request parameters.
     * @throws IOException                  Occurred IO exception while calling the api
     * @throws ParserConfigurationException Occurred while retrieving the web id.
     * @throws SAXException                 Occurred while retrieving the web id.
     */
    public String retrieveStatus(String host, String scanId)
            throws IOException, InvalidRequestException, ParserConfigurationException, SAXException {
        HttpGet getRequest = new HttpGet(host.concat(QualysScannerConstants.QUALYS_GET_STATUS_API.concat(scanId)));
        getRequest.addHeader("Authorization", "Basic " + basicAuth);
        getRequest.addHeader("Accept", "application/xml");
        HttpClient client = HttpClientBuilder.create().build();
        HttpResponse response = client.execute(getRequest);
        return getRequiredData(response, "status");
    }

    /**
     * get the value of given tag name from http response.
     *
     * @param response http response
     * @param tagName  tag name
     * @return value
     * @throws InvalidRequestException      Occurred due to Invalid request parameters.
     * @throws IOException                  Occurred IO exception while calling the api
     * @throws ParserConfigurationException Occurred while retrieving the web id.
     * @throws SAXException                 Occurred while retrieving the web id.
     */
    private String getRequiredData(HttpResponse response, String tagName)
            throws InvalidRequestException, IOException, ParserConfigurationException, SAXException {
        String result;
        String requiredData = null;
        String responseCode;

        if (response.getStatusLine().getStatusCode() == 200) {
            BufferedReader br = new BufferedReader(new InputStreamReader(response.getEntity().getContent(), "UTF-8"));
            StringBuilder res = new StringBuilder();
            while ((result = br.readLine()) != null) {
                res.append(result);
            }
            Document doc = DocumentBuilderFactory.newInstance().newDocumentBuilder()
                    .parse(new InputSource(new StringReader(res.toString())));
            NodeList errNodes = doc.getElementsByTagName("ServiceResponse");
            if (errNodes.getLength() > 0) {
                Element err = (Element) errNodes.item(0);
                responseCode = err.getElementsByTagName("responseCode").item(0).getTextContent();
                if (responseCode != null) {
                    if (responseCode.equals("SUCCESS")) {
                        requiredData = err.getElementsByTagName(tagName).item(0).getTextContent();
                    }
                }
            }
        } else if (response.getStatusLine().getStatusCode() == 400) {
            log.error("Given parameters are not valid.");
            throw new InvalidRequestException("Given parameters are not valid.");
        }
        return requiredData;
    }
}
