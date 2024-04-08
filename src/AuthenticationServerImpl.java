/*
 * Copyright (C) 2005 Luca Veltri - University of Parma - Italy
 * 
 * This source code is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This source code is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this source code; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 * 
 * Author(s):
 * Luca Veltri (luca.veltri@unipr.it)
 */



import org.mjsip.sip.authentication.DigestAuthentication;
import org.mjsip.sip.header.AuthenticationHeader;
import org.mjsip.sip.header.AuthenticationInfoHeader;
import org.mjsip.sip.header.AuthorizationHeader;
import org.mjsip.sip.header.ProxyAuthenticateHeader;
import org.mjsip.sip.header.WwwAuthenticateHeader;
import org.mjsip.sip.message.SipMessage;
import org.mjsip.sip.message.SipResponses;
import org.mjsip.sip.provider.SipProvider;
import org.slf4j.LoggerFactory;
import org.zoolu.util.ByteUtils;
import org.zoolu.util.MD5;
import threegpp.milenage.Milenage;
import threegpp.milenage.MilenageBufferFactory;
import threegpp.milenage.MilenageResult;
import threegpp.milenage.biginteger.BigIntegerBuffer;
import threegpp.milenage.biginteger.BigIntegerBufferFactory;
import threegpp.milenage.cipher.Ciphers;

import javax.crypto.Cipher;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;

/** Class AuthenticationServerImpl implements an AuthenticationServer
  * for HTTP Digest authentication.
  */
public class AuthenticationServerImpl implements AuthenticationServer {
	
	private static final org.slf4j.Logger LOG = LoggerFactory.getLogger(AuthenticationServerImpl.class);

	/** Server authentication. */
	protected static final int SERVER_AUTHENTICATION=0;

	/** Proxy authentication. */
	protected static final int PROXY_AUTHENTICATION=1;

	/** The repository of users's authentication data. */
	protected AuthenticationService authentication_service;
	
	/** The authentication realm. */
	protected String realm;
	
	/** The authentication scheme. */
	protected String authentication_scheme="Digest";

	/** The authentication qop-options. */
	//protected String qop_options="auth,auth-int";
	protected String qop_options="auth,auth-int";

	/** The current random value. */
	protected byte[] rand;

	private SipProvider sip_provider;

	/** DIGEST */
	//public static final String DIGEST="Digest";
	/** AKA */
	//public static final String AKA="AKA";
	/** CHAP */
	//public static final String CHAP="CHAP";
	private IMSAuth imsAuth;

	/** Costructs a new AuthenticationServerImpl. */
	public AuthenticationServerImpl(SipProvider sip_provider, String realm, AuthenticationService authentication_service) {
		this.sip_provider = sip_provider;
		this.imsAuth=new IMSAuth();
		init(realm, authentication_service);
	}
 
	
	/** Inits the AuthenticationServerImpl. */
	private void init(String realm, AuthenticationService authentication_service) {
		this.realm=realm;
		this.authentication_service=authentication_service;
		this.rand=pickRandBytes();
	}

	/** Gets the realm. */
	/*public String getRealm() {
		return realm;
	}*/


	/** Gets the qop-options. */
	/*public String getQopOptions() {
		return qop_options;
	}*/


	/** Gets the current rand value. */
	/*public String getRand() {
		return HEX(rand);
	}*/

	int ctr=0;
	/** Authenticates a SIP request.
	  * @param msg is the SIP request to be authenticated
	  * @return it returns the error SipMessage in case of authentication failure,
	  * or null in case of authentication success. */
	@Override
	public SipMessage authenticateRequest(SipMessage msg) {
		final SipMessage[] msg2 = {null};
		System.out.println("going once " + ctr++);
		try {
			Thread.sleep(3000);
		} catch (InterruptedException e) {
			throw new RuntimeException(e);
		}

		return authenticateRequest(msg,SERVER_AUTHENTICATION);
	}


	/** Authenticates a proxying SIP request.
	  * @param msg is the SIP request to be authenticated
	  * @return it returns the error SipMessage in case of authentication failure,
	  * or null in case of authentication success. */
	@Override
	public SipMessage authenticateProxyRequest(SipMessage msg) {
		return authenticateRequest(msg,PROXY_AUTHENTICATION);
	}


	/** Authenticates a SIP request.
	  * @param msg the SIP request to be authenticated
	  * @param type the type of authentication ({@link AuthenticationServerImpl#SERVER_AUTHENTICATION} server authentication, for ({@link AuthenticationServerImpl#PROXY_AUTHENTICATION} for proxy authentication)
	  * @return the error SipMessage in case of authentication failure, or null in case of authentication success. */
	protected SipMessage authenticateRequest(SipMessage msg, int type) {
		SipMessage err_resp=null;

		//String username=msg.getFromHeader().getNameAddress().getAddress().getUserName();
		//String user=username+"@"+realm;

		AuthorizationHeader ah;
		if (type==SERVER_AUTHENTICATION) ah=msg.getAuthorizationHeader();
		else ah=msg.getProxyAuthorizationHeader();

		LOG.debug("AM HERE");
		if (ah.getNonceParam().length()!=0) {
			
			//String username=ah.getUsernameParam();
			String realm=ah.getRealmParam();
			String nonce=ah.getNonceParam();
			String username=ah.getUsernameParam();
			String scheme=ah.getAuthScheme();
			
//			String user=username+"@"+realm;


			LOG.debug("Params " + "realm " + realm + "nonce " + nonce + "username " + username + "scheme " + scheme );

			if (authentication_service.hasUser(username)) {
				imsUsers imsuserdata= this.imsAuth.getuser(username);
				LOG.debug("Here with user");
				if (authentication_scheme.equalsIgnoreCase(scheme)) {
					LOG.debug("Here with schema ");
					DigestAuthentication auth=new DigestAuthentication(msg.getRequestLine().getMethod(),ah,msg.getBody(),imsuserdata.passwd);

//					LOG.debug(" auth.toString " + auth.toString());
					// check user's authentication response
					boolean is_authorized=auth.checkResponse();

					rand=pickRandBytes();        
						
					if (!is_authorized) {
						err_resp=sip_provider.messageFactory().createResponse(msg,SipResponses.FORBIDDEN,null,null);
						LOG.info("Login error: Authentication of '" + username + "' failed");
					}
					else {
						// authentication/authorization successed
						LOG.info("Authentication of '"+username+"' successed");
					}
				}
				else {
					// authentication/authorization failed
					int result=400; // response code 400 ("Bad request")
					err_resp=sip_provider.messageFactory().createResponse(msg,result,null,null);
					LOG.info("Authentication method '"+scheme+"' not supported.");
				}
			}
			else {
				// no authentication credential found for this user
				int result=404; // response code 404 ("Not Found")
				err_resp=sip_provider.messageFactory().createResponse(msg,result,null,null);  
			}
		}
		else {
			// no Authorization header found
			LOG.info("No Authorization header found or nonce mismatching");
			String username=ah.getUsernameParam();
			imsUsers imsuserdata=null;
			try{
				imsuserdata=this.imsAuth.generateauthparam(username);
				if (imsuserdata==null){
					int result=404; // response code 404 ("Not Found")
					err_resp=sip_provider.messageFactory().createResponse(msg,result,null,null);
					return err_resp;
				}

			}catch (Exception e){
				e.printStackTrace();
			}
			int result;
			if (type==SERVER_AUTHENTICATION) result=401; // response code 401 ("Unauthorized")
			else result=407; // response code 407 ("Proxy Authentication Required")
			err_resp=sip_provider.messageFactory().createResponse(msg,result,"Unauthorized - Challenging the UE",null);
			AuthenticationHeader wah;
			if (type==SERVER_AUTHENTICATION) wah=new WwwAuthenticateHeader("Digest");
			else wah=new ProxyAuthenticateHeader("Digest");
			wah.addRealmParam(realm);
			wah.addAlgorithParam("AKAv1-MD5");
			wah.addQopOptionsParam(qop_options);
			wah.addNonceParam(imsuserdata.sipnonce);
			err_resp.setHeader(wah);

//			byte [] keyBytes=new byte[]{(byte)0x00};
//			byte [] opBytes=new byte[]{(byte)0x00};
//			byte [] rand=new byte[]{(byte)0x00};
//			byte [] sqn=new byte[]{(byte)0x00};
//			byte [] amf=new byte[]{(byte)0x00};
//			MilenageBufferFactory<BigIntegerBuffer> bufferFactory = BigIntegerBufferFactory.getInstance();
//			Cipher cipher = Ciphers.createRijndaelCipher(keyBytes);
//			byte [] OPc = Milenage.calculateOPc(opBytes, cipher, bufferFactory);
//			Milenage<BigIntegerBuffer> milenage = new Milenage<>(OPc, cipher, bufferFactory);
//			Map<MilenageResult, byte []> result1=null;
//			try{
//				 result1 = milenage.calculateAll(rand, sqn, amf, Executors.newCachedThreadPool());
//
//			}catch (Exception e){
//
//			}
//
//			result1.get(MilenageResult.RES);
//			result1.get(MilenageResult.CK);
//			result1.get(MilenageResult.IK);
//			result1.get(MilenageResult.AK);
//
//






		}
		return err_resp;
	}


	/** Gets AuthenticationInfoHeader. */
	@Override
	public AuthenticationInfoHeader getAuthenticationInfoHeader() {
		AuthenticationInfoHeader aih=new AuthenticationInfoHeader();
		aih.addRealmParam(realm);
		aih.addQopOptionsParam(qop_options);
		aih.addNextnonceParam(HEX(rand));
		return aih;
	}


	/** Picks a random array of 16 bytes. */
	private static byte[] pickRandBytes() {
		return MD5(Long.toHexString(org.zoolu.util.Random.nextLong()));
	}

	/** Converts the byte[] key in a String passwd. */
	private static String keyToPasswd(byte[] key) {
		return new String(key);
	}

	/** Calculates the MD5 of a String. */
	private static byte[] MD5(String str) {
		return MD5.digest(str);
	}

	/** Calculates the MD5 of an array of bytes. */
	private static byte[] MD5(byte[] bb) {
		return MD5.digest(bb);
	}

	/** Calculates the HEX of an array of bytes. */
	private static String HEX(byte[] bb) {
		return ByteUtils.asHex(bb);
	}

}
