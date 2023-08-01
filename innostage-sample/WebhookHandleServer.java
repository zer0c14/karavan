import org.apache.camel.builder.RouteBuilder;

public class WebhookHandleServer extends RouteBuilder {
  @Override
  public void configure() throws Exception {
    from("platform-http:/hello?httpMethodRestrict=GET")
      .setBody(simple("Hello Innostage!!!"));
  }
}