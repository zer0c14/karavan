import static javax.xml.bind.DatatypeConverter.printHexBinary;

import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;
import org.apache.camel.Exchange;
import org.apache.camel.builder.RouteBuilder;
import org.apache.camel.builder.RouteBuilderLifecycleStrategy;
import org.apache.camel.http.base.cookie.ExchangeCookieHandler;
import org.apache.camel.support.DefaultMessage;
import org.apache.camel.support.jsse.SSLContextParameters;
import org.apache.camel.support.jsse.TrustManagersParameters;

public class MyRouteBuilder extends RouteBuilder {
  private final ExchangeCookieHandler exchangeCookieHandler = new ExchangeCookieHandler();

  private final SSLContextParameters insecureSslParameters = getInsecureSslParameters();

  public MyRouteBuilder() {
    this.addLifecycleInterceptor(
        new RouteBuilderLifecycleStrategy() {
          @Override
          public void beforeConfigure(RouteBuilder builder) {
            builder.bindToRegistry("exchangeCookieHandler", exchangeCookieHandler);
            builder.bindToRegistry("insecureSslParameters", insecureSslParameters);
          }
        });
  }

  public void configure() {
    from("netty-http:http://0.0.0.0:12345/pt-af/v1/create-session")
        .process(exchange -> exchange.setMessage(new DefaultMessage(exchange)))
        .to(
            "netty-http:https://10.70.19.2:8443/login"
                + "?sslContextParameters=#insecureSslParameters"
                + "&cookieHandler=#exchangeCookieHandler")
        .unmarshal()
        .tidyMarkup()
        .setHeader("csrfToken", xpath("//input[@name='csrf_token']/@value").convertToString())
        .setHeader("modulus", xpath("//input[@name='public_key_n']/@value").convertToString())
        .setHeader("exponent", xpath("//input[@name='public_key_e']/@value").convertToString())
        .process(
            exchange -> {
              var modulus = exchange.getIn().getHeader("modulus", String.class);
              var exponent = exchange.getIn().getHeader("exponent", String.class);
              exchange.getIn().setHeader("password", getEncryptedPassword(modulus, exponent));
            })

        .setHeader(Exchange.HTTP_METHOD, constant(HttpMethod.POST))
        .setHeader(Exchange.CONTENT_TYPE, constant("application/x-www-form-urlencoded"))
        .setBody(
            simple(
                "login=orchestrator"
                    + "&password=${header.password}"
                    + "&csrf_token=${header.csrfToken}"
                    + "&public_key_n=${header.modulus}"
                    + "&public_key_e=${header.exponent}"
                    + "&lang=en"))
        .to(
            "netty-http:https://10.70.19.2:8443/login"
                + "?sslContextParameters=#insecureSslParameters"
                + "&cookieHandler=#exchangeCookieHandler"
                + "&okStatusCodeRange=200-399")
        .process(exchange -> exchange.setMessage(new DefaultMessage(exchange)))
        .setBody(
            exchange -> {
              var cookieStore = exchangeCookieHandler.getCookieStore(exchange);
              return cookieStore.getCookies().toString();
            });
  }

  private String getEncryptedPassword(String modulus, String exponent) throws Exception {
    return getEncryptedPassword(new BigInteger(modulus, 16), new BigInteger(exponent, 16));
  }

  private String getEncryptedPassword(BigInteger modulus, BigInteger exponent) throws Exception {
    var cipher = Cipher.getInstance("RSA");
    var keyFactory = KeyFactory.getInstance("RSA");

    var publicKeySpec = new RSAPublicKeySpec(modulus, exponent);
    var publicKey = keyFactory.generatePublic(publicKeySpec);
    var password = Base64.getEncoder().encode("NDu6%TZ7VD2s)5*+".getBytes());

    cipher.init(Cipher.ENCRYPT_MODE, publicKey);
    return printHexBinary(cipher.doFinal(password));
  }

  private static SSLContextParameters getInsecureSslParameters() {
    var trustManagersParameters = new TrustManagersParameters();
    trustManagersParameters.setTrustManager(
        InsecureTrustManagerFactory.INSTANCE.getTrustManagers()[0]);

    var sslContextParameters = new SSLContextParameters();
    sslContextParameters.setTrustManagers(trustManagersParameters);
    return sslContextParameters;
  }
}
