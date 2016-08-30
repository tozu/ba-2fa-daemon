package managers;

import Utils.BTDiscovery;
import Utils.Encryption;
import models.BTToken;
import org.spongycastle.util.encoders.Base64;

import javax.bluetooth.RemoteDevice;
import javax.microedition.io.Connector;
import javax.microedition.io.StreamConnection;
import java.io.*;

/**
 * Created by Tobias on 21.04.2016.
 */
public class BluetoothManager {

    private BTDiscovery btDiscovery;
    private Encryption encManager;

    public enum REQUESTS {
        DAEMON_REQUEST_PUBLIC_KEY,
        DAEMON_REQUESTS_OTP,
        DAEMON_SENDS_OTP,
        DAEMON_REQUESTS_HMAC,
        BTCLIENT_CONFIRMATION,
        BTCLIENT_AWAITS_PROF,
        BTCLIENT_REFUESES
    }

    private static BluetoothManager mInstance;

    public static BluetoothManager getInstance() {
        if (mInstance == null) {
            mInstance = new BluetoothManager();
        }
        return mInstance;
    }

    private BluetoothManager() {
        btDiscovery = BTDiscovery.getInstance();
        encManager = Encryption.getInstance();
    }

    public boolean sendOTPToDevice(RemoteDevice device, String payload, BTToken.Token btToken) {
        System.out.println("---- /send OTP");
        boolean successful;

        StreamConnection streamConnection = null;
        OutputStream outStream = null;
        PrintWriter pWriter = null;
        InputStream inStream = null;
        BufferedReader bReader = null;

        try {
            btDiscovery.searchServiceForDevice(device);

            if (btDiscovery.getServiceFound().size() >= 1) {
                String connectionURL = btDiscovery.getServiceFound().elementAt(0);
                streamConnection = (StreamConnection) Connector.open(connectionURL, Connector.READ_WRITE, true);

                outStream = streamConnection.openOutputStream();
                pWriter = new PrintWriter(new OutputStreamWriter(outStream));

                byte[] signedRequest = encManager.signRSA(getRequest(REQUESTS.DAEMON_SENDS_OTP), encManager.getKeyPair().getPrivate());          // sign request with PR-D
                String request = Base64.toBase64String(signedRequest);                                                      // encode request

                System.out.println("sending: " + request);
                pWriter.write(request + "\r\n");                                                                           // send request
                pWriter.flush();

                inStream = streamConnection.openInputStream();
                bReader = new BufferedReader(new InputStreamReader(inStream));
                String received = bReader.readLine();                                                                              // receive response (encrypted [with PB-D] and encoded)

                byte[] decodedResponse = Base64.decode(received);                                                                  // decode response
                received = encManager.dectryptRSA(decodedResponse, encManager.getKeyPair().getPrivate());                          // decrypt response with PR-D

                if (received.equals(getRequest(REQUESTS.BTCLIENT_CONFIRMATION))) {                                                                       // BT Daemon expects OTP now
                    System.out.println("BT Client received OTP");

                    byte[] encryptedPayload = encManager.encryptRSA(payload, encManager.convertPublicKey(btToken.getPublicKey()));  // encrypt OTP with PB-BT
                    payload = Base64.toBase64String(encryptedPayload);                                                              // encode OTP

                    pWriter.write(payload + "\r\n");                                                                                // SEND OTP
                    pWriter.flush();

                    received = bReader.readLine();                                                                          // receive response (encrypted [with PB-D] and encoded)

                    decodedResponse = Base64.decode(received);                                                              // decode lineRead
                    String responseBT = encManager.dectryptRSA(decodedResponse, encManager.getKeyPair().getPrivate());      // decrypt (with PR-D) to check if it's confirmed

                    System.out.println("received (decrypted): " + responseBT);

                    if (responseBT.equals(getRequest(REQUESTS.BTCLIENT_AWAITS_PROF))) {                                                                                                                     // BT Daemon expects PROOF now
                        System.out.println("BT Client awaits proof now");

                        byte[] signedPayload = encManager.signRSA(encryptedPayload, encManager.getKeyPair().getPrivate());  // sign enc payload
                        payload = Base64.toBase64String(signedPayload);                                                     // encode it

                        pWriter.write(payload + "\r\n");                                                                    // send signature
                        pWriter.flush();

                        received = bReader.readLine();                                                                      // receive response (encrypted [with PB-D] and encoded)

                        decodedResponse = Base64.decode(received);                                                          // decode lineRead
                        responseBT = encManager.dectryptRSA(decodedResponse, encManager.getKeyPair().getPrivate());         // decrypt with PR-D
                        if (!responseBT.equals(getRequest(REQUESTS.BTCLIENT_CONFIRMATION))) {                                                                                                                      // check if it NOT confirmed
                            System.out.println("[ERROR] BT client couldn't save new OTP");
                            successful = false;
                        } else {
                            System.out.println("[SUCCESS] BT client COULD save new OTP");
                            successful = true;
                        }
                    } else {
                        System.out.println("[ERROR] BT client doesn't await proof of OTP");
                        successful = false;
                    }
                } else {
                    System.out.println("[ERROR] BT client doesn't expect OTP");
                    successful = false;
                }
            } else {
                System.out.println("[ERROR] finding url");
                successful = false;
            }
            if (bReader != null)
                bReader.close();
            if (inStream != null)
                inStream.close();
            if (pWriter != null)
                pWriter.close();
            if (outStream != null)
                outStream.close();
            if (streamConnection != null) {
                streamConnection.close();
            }
        } catch (IOException e) {
            e.printStackTrace();
            successful = false;
        }
        return successful;
    }

    public String requestFromDevice(RemoteDevice device, REQUESTS _request) {
        System.out.println("---- /REQUEST " + _request.name());

        try {
            btDiscovery.searchServiceForDevice(device);

            if (btDiscovery.getServiceFound().size() >= 1) {
                String connectionURL = btDiscovery.getServiceFound().elementAt(0);
                StreamConnection streamConnection = (StreamConnection) Connector.open(connectionURL, Connector.READ_WRITE, true);

                OutputStream outStream = streamConnection.openOutputStream();
                PrintWriter pWriter = new PrintWriter(new OutputStreamWriter(outStream));

                InputStream inStream = streamConnection.openInputStream();
                BufferedReader bReader = new BufferedReader(new InputStreamReader(inStream));

                byte[] signedPayload = encManager.signRSA(getRequest(_request), encManager.getKeyPair().getPrivate());     // sign request with PR-D
                String payload = Base64.toBase64String(signedPayload);                                                     // encode request

                System.out.println("sending: " + payload);
                pWriter.write(payload + "\r\n");                                                                           // send request
                pWriter.flush();

                String received = null;                                                                      // receive response (encrypted [with PB-D] and encoded)
                /* block until i receive sth */
                boolean receivedSth = false;
                while (!receivedSth) {
                    received = bReader.readLine();
                    if (received != null) {
                        receivedSth = true;
                        System.out.println("RECEIVED STH!");
                    }
                }

                byte[] decoded = Base64.decode(received);                                                                  // decode response

                if (_request == REQUESTS.DAEMON_REQUEST_PUBLIC_KEY) {
                    received = Base64.toBase64String(decoded);
                    System.out.println("\t\treceived (Public Key): " + received);
                } else {
                    received = encManager.dectryptRSA(decoded, encManager.getKeyPair().getPrivate());                      // decrypt response with PR-D
                    System.out.println("\t\treceived (decrypted): " + received);
                }

                bReader.close();
                inStream.close();
                pWriter.close();
                outStream.close();
                streamConnection.close();

                return received;
            } else {
                // error finding url -> problem to establish a connection
                return null;
            }
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    // Getter for REQUESTS
    private String getRequest(REQUESTS _request) {
        switch (_request) {
            case DAEMON_REQUEST_PUBLIC_KEY:
                return "0-";
            case DAEMON_REQUESTS_OTP:
                return "1-";
            case DAEMON_SENDS_OTP:
                return "2-";
            case DAEMON_REQUESTS_HMAC:
                return "3-";
            case BTCLIENT_CONFIRMATION:
                return "4-";
            case BTCLIENT_AWAITS_PROF:
                return "10-";
            case BTCLIENT_REFUESES:
                return "-7";
            default:
                return null;
        }
    }

}