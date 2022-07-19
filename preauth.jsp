<!--
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
-->

<!--

To configure:

1) Generate a preauth domain key for your domain using zmprov:

zmprov gdpak domain.com
preAuthKey:  ee0e096155314d474c8a8ba0c941e9382bb107cc035c7a24838b79271e32d7b0

Take that value, and set it below as the value of DOMAIN_KEY

2) restart server (only needed the first time you generate the domain pre-auth key)

3) redirect users to this (this, as in *this* file after you install it) JSP page:

http://server/zimbra/preauth.jsp

And it will construct the preauth URL

-->

<%@ page import="java.security.InvalidKeyException" %>
<%@ page import="java.security.NoSuchAlgorithmException" %>
<%@ page import="java.security.SecureRandom" %>
<%@ page import="java.util.HashMap" %>
<%@ page import="java.util.Map" %>
<%@ page import="java.util.Iterator" %>
<%@ page import="java.util.TreeSet" %>
<%@ page import="javax.crypto.Mac" %>
<%@ page import="javax.crypto.SecretKey" %>
<%!
	public static final String DOMAIN_KEY =
		"ee0e096155314d474c8a8ba0c941e9382bb107cc035c7a24838b79271e32d7b0";

	public static String generateRedirect(HttpServletRequest request, String name) {
		HashMap params = new HashMap();
		String ts = System.currentTimeMillis()+"";
		params.put("account", name);
		params.put("by", "name"); // needs to be part of hmac
		params.put("timestamp", ts);
		params.put("expires", "0"); // means use the default
		params.put("admin", "1");

		String preAuth = computePreAuth(params, DOMAIN_KEY);
		return request.getScheme()+"://"+request.getServerName()+":"+request.getServerPort()+"/service/preauth/?" +
			"account="+name+
			"&by=name"+
			"&timestamp="+ts+
			"&expires=0"+
			"&admin=1"+
			"&preauth="+preAuth;
	}

	public static String computePreAuth(Map params, String key) {
		TreeSet names = new TreeSet(params.keySet());
		StringBuffer sb = new StringBuffer();
		
		for (Iterator it=names.iterator(); it.hasNext();) {
			if (sb.length() > 0) sb.append('|');
			sb.append(params.get(it.next()));
		}
		return getHmac(sb.toString(), key.getBytes());        
	}

	private static String getHmac(String data, byte[] key) {
		try {
			ByteKey bk = new ByteKey(key);
			Mac mac = Mac.getInstance("HmacSHA1");
			mac.init(bk);
			return toHex(mac.doFinal(data.getBytes()));
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("fatal error", e);
		} catch (InvalidKeyException e) {
			throw new RuntimeException("fatal error", e);
		}
	}

	static class ByteKey implements SecretKey {
		private byte[] mKey;

		ByteKey(byte[] key) {
			mKey = (byte[]) key.clone();;
		}

		public byte[] getEncoded() {
			return mKey;
		}

		public String getAlgorithm() {
			return "HmacSHA1";
		}

		public String getFormat() {
			return "RAW";
		}
	}

	public static String toHex(byte[] data) {
		StringBuilder sb = new StringBuilder(data.length * 2);
		
		for (int i=0; i<data.length; i++ ) {
			sb.append(hex[(data[i] & 0xf0) >>> 4]);
			sb.append(hex[data[i] & 0x0f] );
		}
		return sb.toString();
	}

	private static final char[] hex =
		{'0' , '1' , '2' , '3' , '4' , '5' , '6' , '7' ,
		'8' , '9' , 'a' , 'b' , 'c' , 'd' , 'e' , 'f'};
%><%
	String casUser = request.getRemoteUser().toString().trim();
	String redirect = generateRedirect(request, casUser+"@yourdomain.com");
	response.sendRedirect(redirect);
%>
<html>
<head>
<title>Pre-auth redirect</title>
</head>
<body>You should never see this page!</body>
</html>