import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.slf4j.LoggerFactory;
import threegpp.milenage.Milenage;
import threegpp.milenage.MilenageBufferFactory;
import threegpp.milenage.MilenageResult;
import threegpp.milenage.biginteger.BigIntegerBuffer;
import threegpp.milenage.biginteger.BigIntegerBufferFactory;
import threegpp.milenage.cipher.Ciphers;

import javax.crypto.Cipher;
import java.io.*;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.*;
import java.util.concurrent.Executors;

public class IMSAuth {

    HashMap<String, imsUsers> map = null;
    HashMap<String, String> users = null;
    String initdone="no";
    private static final org.slf4j.Logger LOG = LoggerFactory.getLogger(IMSAuth.class);

    private String sipURL="http://127.0.0.1/pcap/test.html";
    public  IMSAuth(){
        map=new HashMap<String, imsUsers>();
        users=new HashMap<String,String>();
        init_keys("/tmp/userkeys");
    }
    public imsUsers pushnewusers(String sipUsername, String sipnonce,String passwd){
        LOG.debug("pushing new user "+ sipUsername +" nonce "+sipnonce + " passwd "+ passwd);
        imsUsers imsUsersObj=new imsUsers(sipUsername,sipnonce,passwd);
        map.put(sipUsername,imsUsersObj);
        return imsUsersObj;
    }
    public imsUsers getuser(String sipUsername){
        imsUsers imsuser= map.get(sipUsername);
        LOG.debug("getting  new user "+ imsuser.sipUsername +" nonce "+imsuser.sipnonce + " passwd "+ imsuser.passwd);

        return imsuser;
    }
    public String getUserKeys(String sipUsername){
         String keys= users.get(sipUsername);
        LOG.debug("getting  new user "+ sipUsername +" K "+keys.split(",")[0] + " opc "+ keys.split(",")[1]);

        return keys;
    }

    public imsUsers getAuthParam(String username) throws URISyntaxException {
        LOG.debug("username = "+username);
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(new URI(sipURL+"?imsi="+username))
                .GET()
                .build();
        HttpResponse response = null;
        try {
            response = client.send(request, HttpResponse.BodyHandlers.ofString());
            LOG.debug("response from server  = "+response.body().toString());
//            System.out.println(response.body().toString());
        } catch (IOException | InterruptedException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        JSONObject obj = new JSONObject();
        JSONParser parser = new JSONParser();
        JSONObject json = null;
        try {
            json = (JSONObject) parser.parse(response.body().toString());
        } catch (ParseException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return null;
        }
        String nonce= (String) json.get("nonce");
        String passwd= (String) json.get("passwd");
        LOG.debug("Nonce "+nonce);
        LOG.debug("Passwd " + passwd);
        return this.pushnewusers(username,nonce,passwd);
    }
    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
    private static byte[] cat(byte[] a, byte[] b) {
        int len = a.length + b.length;
        byte[] c = new byte[len];
        System.arraycopy(a, 0, c, 0, a.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }
    public imsUsers generateauthparam(String username){

        String keys=getUserKeys(username);
        byte[] keyBytes=hexStringToByteArray(keys.split(",")[0]);
        byte[] OPcBytes=hexStringToByteArray(keys.split(",")[1]);

        byte [] rand=new byte[]{(byte)0x11,(byte)0x11,(byte)0x11,(byte)0x11,(byte)0x11,(byte)0x11,(byte)0x11,(byte)0x11,(byte)0x11,(byte)0x11,(byte)0x11,(byte)0x11,(byte)0x11,(byte)0x11,(byte)0x11,(byte)0x11,};
        byte [] sqn=new byte[]{(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x01};
        byte [] amf=new byte[]{(byte)0x80,(byte)0x00};
        MilenageBufferFactory<BigIntegerBuffer> bufferFactory = BigIntegerBufferFactory.getInstance();
        Cipher cipher = Ciphers.createRijndaelCipher(keyBytes);
//			byte [] OPc = Milenage.calculateOPc(opBytes, cipher, bufferFactory);
        Milenage<BigIntegerBuffer> milenage = new Milenage<>(OPcBytes, cipher, bufferFactory);
        Map<MilenageResult, byte []> result1=null;
        try{
            result1 = milenage.calculateAll(rand, sqn, amf, Executors.newCachedThreadPool());
        }catch (Exception e){
        }
        byte[] res=result1.get(MilenageResult.RES);
        byte[] ck=result1.get(MilenageResult.CK);
        byte[] ik=result1.get(MilenageResult.IK);
        byte[] ak=result1.get(MilenageResult.AK);
        byte[] mac_a=result1.get(MilenageResult.MAC_A);
        byte[] sqnxorak = new byte[6];
        int i = 0;
        for (byte b : sqn)
            sqnxorak[i] = (byte) (b ^ ak[i++]);
        System.out.println("ak Bytes are "+printbytes(ak));
        byte[] sqnxorak_amf=cat(sqnxorak,amf);
        byte[] autn=cat(sqnxorak_amf,mac_a);
        byte[] noncehex=cat(rand,autn);
        System.out.println("AUTN Bytes are "+printbytes(autn));
        String nonceb64 = Base64.getEncoder().encodeToString(noncehex);
        return this.pushnewusers(username,nonceb64,printbytes(res));
    }
    public static String printbytes(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
//        sb.append("[ ");
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
//        sb.append("]");
        return sb.toString();
    }
    private void init_keys(String config_file) {
        // InputStream inStreamLog4j =
        // mapScanner.class.getResourceAsStream("/SS7_Properties");
        try {
            File myObj = new File(config_file);
            Scanner myReader = new Scanner(myObj);
            while (myReader.hasNextLine()) {
                String data = myReader.nextLine();
                String[] userdata=data.split(",");
                users.put(userdata[0],userdata[1]+","+userdata[2]);
            }
            myReader.close();
        } catch (FileNotFoundException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
        }

    }
}
